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
