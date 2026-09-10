#include "scanners.h"
#include <string.h>

static uint32_t rd32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void read_string(BinaryView* bv, uint32_t addr, char* buf, size_t n) {
    size_t avail;
    const uint8_t* p = bv_translate(bv, addr, &avail);
    if (!p) { buf[0] = 0; return; }
    size_t m = avail < n - 1 ? avail : n - 1;
    size_t i = 0;
    while (i < m && p[i]) { buf[i] = (char)p[i]; i++; }
    buf[i] = 0;
}

/* ".?AVName@@" -> "Name" */
static void demangle(const char* mangled, char* out, size_t n) {
    if ((strncmp(mangled, ".?AV", 4) == 0 || strncmp(mangled, ".?AU", 4) == 0)) {
        const char* end = strstr(mangled + 4, "@@");
        if (end) {
            size_t len = (size_t)(end - (mangled + 4));
            if (len > n - 1) len = n - 1;
            memcpy(out, mangled + 4, len);
            out[len] = 0;
            return;
        }
    }
    snprintf(out, n, "%s", mangled);
}

void vtscan_run(BinaryView* bv, VTableInfoVec* out) {
    memset(out, 0, sizeof *out);
    SectionView* rdata = bv_find_section_by_name(bv, ".rdata");
    if (!rdata) return;

    const uint8_t* d = rdata->data;
    uint32_t base = rdata->base_address;
    uint32_t size = rdata->size;

    for (uint32_t off = 0; off + 20 <= size; off += 4) {
        uint32_t signature = rd32(d + off);
        if (signature != 0) continue;
        uint32_t type_desc_ptr = rd32(d + off + 12);
        if (!bv_find_section(bv, type_desc_ptr)) continue;

        char type_name[128];
        read_string(bv, type_desc_ptr + 8, type_name, sizeof type_name);
        if (strncmp(type_name, ".?AV", 4) != 0 && strncmp(type_name, ".?AU", 4) != 0) continue;

        uint32_t col_addr = base + off;

        /* vtable = (dword in .rdata == col_addr) + 4 */
        uint32_t vtable_addr = 0;
        for (uint32_t o2 = 0; o2 + 4 <= size; o2 += 4)
            if (rd32(d + o2) == col_addr) { vtable_addr = base + o2 + 4; break; }
        if (!vtable_addr) continue;

        VTableInfo info;
        memset(&info, 0, sizeof info);
        info.vtable_address = vtable_addr;
        info.col_address = col_addr;
        demangle(type_name, info.class_name, sizeof info.class_name);

        uint32_t slot = vtable_addr;
        for (;;) {
            uint32_t fn;
            if (!bv_read_u32(bv, slot, &fn) || fn == 0) break;
            if (!bv_is_executable(bv, fn)) break;
            vec_push(&info.slots, fn);
            slot += 4;
        }
        if (info.slots.len == 0) { vec_free(&info.slots); continue; }
        vec_push(out, info);
    }
}

void vtscan_free(VTableInfoVec* v) {
    for (size_t i = 0; i < v->len; i++) vec_free(&v->data[i].slots);
    vec_free(v);
}

void sigscan(BinaryView* bv, const int* pattern, size_t plen, int entry_offset, U32Vec* out) {
    for (size_t s = 0; s < bv->sections.len; s++) {
        SectionView* sec = &bv->sections.data[s];
        if (!sec->executable || sec->size == 0 || bv_is_data_section_name(sec->name)) continue;
        if (sec->size < plen) continue;
        for (size_t i = 0; i + plen <= sec->size; i++) {
            int ok = 1;
            for (size_t j = 0; j < plen; j++)
                if (pattern[j] >= 0 && sec->data[i + j] != (uint8_t)pattern[j]) { ok = 0; break; }
            if (ok) vec_push(out, sec->base_address + (uint32_t)(i + entry_offset));
        }
    }
}

/* ---- data function-pointer scan ---------------------------------------- */

/* First byte(s) of a plausible function. Covers MSVC prologues, the tiny
 * `push imm; call rel; pop; ret` ctor stubs, and jump thunks. */
static int looks_like_prologue(const uint8_t* p, size_t avail) {
    if (avail < 3) return 0;
    switch (p[0]) {
        case 0x55:                       /* push ebp */
            return 1;
        case 0x53: case 0x56: case 0x57:  /* push ebx/esi/edi — usually part of a prologue run */
            return p[1] == 0x53 || p[1] == 0x56 || p[1] == 0x57 || p[1] == 0x55 ||
                   p[1] == 0x8B || (p[1] == 0x83 && p[2] == 0xEC) || (p[1] == 0x81 && p[2] == 0xEC);
        case 0x6A:                        /* push imm8 (ctor stub `push -1; push imm; ...`) */
            return p[1] == 0xFF && p[2] == 0x68;
        case 0x68:                        /* push imm32; call ... (ctor stub / SEH prolog) */
            return p[5] == 0xE8 || p[5] == 0x68 || p[5] == 0xFF;
        case 0xB8:                        /* mov eax, imm32; ... (SEH `mov eax, scopetable`) */
            return p[5] == 0xE8 || p[5] == 0x50 || p[5] == 0xC3;
        case 0xE9:                        /* jmp rel32 (thunk run) */
        case 0xEB:
            return 1;
        case 0x8B: return p[1] == 0xFF && (p[2] == 0x55 || p[2] == 0x56 || p[2] == 0x53 || p[2] == 0x8B); /* mov edi,edi hotpatch pad + real prologue */
        case 0x83: return p[1] == 0xEC;   /* sub esp, imm8 */
        case 0x81: return p[1] == 0xEC;   /* sub esp, imm32 */
        case 0xFF: return p[1] == 0x25;   /* jmp [mem] (import thunk) */
        default: return 0;
    }
}

/* Is `a` inside a section that primarily holds code (by name, not the XBE
 * flag — XBEs mark nearly everything executable). */
static int in_code_section(BinaryView* bv, uint32_t a) {
    SectionView* sec = bv_find_section(bv, a);
    return sec && !bv_is_data_section_name(sec->name);
}

void fnptrscan_run(BinaryView* bv, const CodeRegion* regions, size_t nregions, U32Vec* out) {
    (void)regions; (void)nregions;
    u32map seen; u32map_init(&seen, 8192);
    for (size_t s = 0; s < bv->sections.len; s++) {
        SectionView* sec = &bv->sections.data[s];
        if (sec->size < 4 || !bv_is_data_section_name(sec->name)) continue;
        for (uint32_t off = 0; off + 4 <= sec->size; off += 4) {
            uint32_t v = rd32(sec->data + off);
            if (v & 3) continue;                       /* code is 4-byte aligned here */
            if (!in_code_section(bv, v)) continue;
            if (u32map_has(&seen, v)) continue;
            size_t avail;
            const uint8_t* p = bv_translate(bv, v, &avail);
            if (!p || avail < 4 || !looks_like_prologue(p, avail)) continue;
            /* Require a table context: a neighbouring slot also points to code.
             * Kills isolated data bytes that happen to look like a prologue. */
            int nbr = 0;
            if (off >= 4) { uint32_t pv = rd32(sec->data + off - 4); nbr |= in_code_section(bv, pv); }
            if (off + 8 <= sec->size) { uint32_t nv = rd32(sec->data + off + 4); nbr |= in_code_section(bv, nv); }
            if (!nbr) continue;
            u32set_add(&seen, v);
            vec_push(out, v);
        }
    }
    u32map_free(&seen);
}
