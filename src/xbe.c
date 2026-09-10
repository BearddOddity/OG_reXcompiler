#include "xbe.h"
#include "kernel_exports.h"

#include <stdio.h>
#include <string.h>

#define ENTRY_RETAIL_XOR 0xA8FC57ABu
#define ENTRY_DEBUG_XOR  0x94859D4Bu
#define THUNK_RETAIL_XOR 0x5B6D40B6u
#define THUNK_DEBUG_XOR  0xEFB1F152u

static uint32_t rd_u32(const uint8_t* p, size_t len, size_t off) {
    if (off + 4 > len) return 0;
    return (uint32_t)p[off] | ((uint32_t)p[off + 1] << 8) |
           ((uint32_t)p[off + 2] << 16) | ((uint32_t)p[off + 3] << 24);
}

int xbe_parse(const uint8_t* data, size_t len, Xbe* out) {
    memset(out, 0, sizeof *out);
    if (len < 0x180 || memcmp(data, "XBEH", 4) != 0) {
        fprintf(stderr, "not an XBE (bad 'XBEH' magic)\n");
        return 1;
    }

    out->raw = malloc(len);
    memcpy(out->raw, data, len);
    out->raw_len = len;
    const uint8_t* p = out->raw;

    uint32_t base_addr    = rd_u32(p, len, 0x0104);
    uint32_t headers_size = rd_u32(p, len, 0x0108);
    uint32_t image_size   = rd_u32(p, len, 0x010C);
    uint32_t num_sections = rd_u32(p, len, 0x011C);
    uint32_t sec_hdr_va   = rd_u32(p, len, 0x0120);
    uint32_t entry_raw    = rd_u32(p, len, 0x0128);
    uint32_t tls_va       = rd_u32(p, len, 0x012C);
    uint32_t thunk_raw    = rd_u32(p, len, 0x0158);

    uint32_t entry_retail = entry_raw ^ ENTRY_RETAIL_XOR;
    uint32_t entry_debug  = entry_raw ^ ENTRY_DEBUG_XOR;
    int is_debug; uint32_t entry;
    if (entry_retail >= base_addr && entry_retail < base_addr + image_size) {
        entry = entry_retail; is_debug = 0;
    } else if (entry_debug >= base_addr && entry_debug < base_addr + image_size) {
        entry = entry_debug; is_debug = 1;
    } else {
        entry = entry_retail; is_debug = 0;
    }
    uint32_t thunk = is_debug ? (thunk_raw ^ THUNK_DEBUG_XOR) : (thunk_raw ^ THUNK_RETAIL_XOR);

    out->base_address      = base_addr;
    out->image_size        = image_size;
    out->headers_size      = headers_size;
    out->entry_point       = entry;
    out->kernel_thunk_addr = thunk;
    out->tls_addr          = tls_va;
    out->is_debug          = is_debug;

    size_t sec_base = (size_t)(sec_hdr_va - base_addr);
    for (uint32_t i = 0; i < num_sections; i++) {
        size_t o = sec_base + (size_t)i * 56;
        if (o + 56 > len) break;
        XbeSection s;
        memset(&s, 0, sizeof s);
        s.flags        = rd_u32(p, len, o + 0);
        s.virtual_addr = rd_u32(p, len, o + 4);
        s.virtual_size = rd_u32(p, len, o + 8);
        s.raw_addr     = rd_u32(p, len, o + 12);
        s.raw_size     = rd_u32(p, len, o + 16);
        uint32_t name_va = rd_u32(p, len, o + 20);
        if (name_va != 0) {
            size_t no = (size_t)(name_va - base_addr);
            if (no < len) {
                size_t end = no;
                while (end < len && end < no + 32 && p[end] != 0) end++;
                size_t n = end - no;
                if (n > sizeof(s.name) - 1) n = sizeof(s.name) - 1;
                memcpy(s.name, p + no, n);
                s.name[n] = 0;
            }
        }
        vec_push(&out->sections, s);
    }

    /* kernel import thunk table: u32 array until 0; high bit => ordinal */
    if (thunk != 0) {
        long file_off = -1;
        for (size_t i = 0; i < out->sections.len; i++) {
            XbeSection* s = &out->sections.data[i];
            if (thunk >= s->virtual_addr && thunk < xbe_sec_end(s)) {
                file_off = (long)(s->raw_addr + (thunk - s->virtual_addr));
                break;
            }
        }
        if (file_off < 0) file_off = (long)thunk;
        for (size_t off = (size_t)file_off; off + 4 <= len; off += 4) {
            uint32_t val = rd_u32(p, len, off);
            if (val == 0) break;
            if (val & 0x80000000u) {
                XbeKernelImport imp;
                memset(&imp, 0, sizeof imp);
                imp.ordinal = (int)(val & 0x7FFFFFFF);
                xbox_kernel_export_name_buf(imp.ordinal, imp.name, sizeof imp.name);
                imp.thunk_addr = (uint32_t)(thunk + (off - (size_t)file_off));
                vec_push(&out->kernel_imports, imp);
            }
        }
    }
    return 0;
}

int xbe_load(const char* path, Xbe* out) {
    FILE* f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return 1; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); fprintf(stderr, "empty file %s\n", path); return 1; }
    uint8_t* buf = malloc((size_t)n);
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    if (got != (size_t)n) { free(buf); fprintf(stderr, "short read %s\n", path); return 1; }
    int rc = xbe_parse(buf, (size_t)n, out);
    free(buf);
    return rc;
}

void xbe_free(Xbe* x) {
    free(x->raw);
    vec_free(&x->sections);
    vec_free(&x->kernel_imports);
    memset(x, 0, sizeof *x);
}
