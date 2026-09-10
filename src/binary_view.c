#include "binary_view.h"
#include <string.h>
#ifndef _WIN32
#include <strings.h>
#endif

static const char* k_data_sections[] = {
    ".data", ".data1", ".rdata", ".idata", ".edata", ".reloc", ".tls", NULL
};

int bv_is_data_section_name(const char* name) {
    for (int i = 0; k_data_sections[i]; i++)
#ifdef _WIN32
        if (_stricmp(name, k_data_sections[i]) == 0) return 1;
#else
        if (strcasecmp(name, k_data_sections[i]) == 0) return 1;
#endif
    return 0;
}

void bv_from_xbe(const Xbe* xbe, BinaryView* out) {
    memset(out, 0, sizeof *out);
    out->base_address = xbe->base_address;
    out->image_size = xbe->image_size;
    out->entry_point = xbe->entry_point;
    out->kernel_thunk_table_start = xbe->kernel_thunk_addr;

    for (size_t i = 0; i < xbe->sections.len; i++) {
        const XbeSection* s = &xbe->sections.data[i];
        SectionView sv;
        memset(&sv, 0, sizeof sv);
        snprintf(sv.name, sizeof sv.name, "%s", s->name);
        sv.base_address = s->virtual_addr;
        sv.size = s->virtual_size;
        sv.executable = (s->flags & XBE_SEC_EXECUTABLE) != 0;
        sv.writable = (s->flags & XBE_SEC_WRITABLE) != 0;
        sv.data = calloc(1, s->virtual_size ? s->virtual_size : 1);
        uint32_t copy = s->raw_size < s->virtual_size ? s->raw_size : s->virtual_size;
        if (copy && (size_t)(s->raw_addr) + copy <= xbe->raw_len)
            memcpy(sv.data, xbe->raw + s->raw_addr, copy);
        vec_push(&out->sections, sv);
    }

    for (size_t i = 0; i < xbe->kernel_imports.len; i++) {
        const XbeKernelImport* k = &xbe->kernel_imports.data[i];
        ImportSymbol sym;
        memset(&sym, 0, sizeof sym);
        sym.address = k->thunk_addr;
        snprintf(sym.name, sizeof sym.name, "xboxkrnl@%d:%s", k->ordinal, k->name);
        vec_push(&out->imports, sym);
    }
}

void bv_free(BinaryView* v) {
    for (size_t i = 0; i < v->sections.len; i++) free(v->sections.data[i].data);
    vec_free(&v->sections);
    vec_free(&v->imports);
    memset(v, 0, sizeof *v);
}

SectionView* bv_find_section(BinaryView* v, uint32_t addr) {
    for (size_t i = 0; i < v->sections.len; i++) {
        SectionView* s = &v->sections.data[i];
        if (addr >= s->base_address && addr < s->base_address + s->size) return s;
    }
    return NULL;
}

SectionView* bv_find_section_by_name(BinaryView* v, const char* name) {
    for (size_t i = 0; i < v->sections.len; i++)
#ifdef _WIN32
        if (_stricmp(v->sections.data[i].name, name) == 0) return &v->sections.data[i];
#else
        if (strcasecmp(v->sections.data[i].name, name) == 0) return &v->sections.data[i];
#endif
    return NULL;
}

const uint8_t* bv_translate(BinaryView* v, uint32_t addr, size_t* avail) {
    SectionView* s = bv_find_section(v, addr);
    if (!s) { if (avail) *avail = 0; return NULL; }
    uint32_t off = addr - s->base_address;
    if (avail) *avail = s->size - off;
    return s->data + off;
}

int bv_read_u32(BinaryView* v, uint32_t addr, uint32_t* out) {
    size_t avail;
    const uint8_t* p = bv_translate(v, addr, &avail);
    if (!p || avail < 4) return 0;
    *out = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return 1;
}

int bv_is_executable(BinaryView* v, uint32_t addr) {
    SectionView* s = bv_find_section(v, addr);
    return s && s->executable;
}
