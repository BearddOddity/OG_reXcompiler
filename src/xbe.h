/* Minimal XBE parser — header, section table, kernel imports.
 * Ported from the C# branch (Binary/Xbe.cs). */
#ifndef OGX_XBE_H
#define OGX_XBE_H

#include <stdint.h>
#include <stddef.h>
#include "util.h"

enum {
    XBE_SEC_WRITABLE    = 0x01,
    XBE_SEC_PRELOAD     = 0x02,
    XBE_SEC_EXECUTABLE  = 0x04,
    XBE_SEC_INSERTED    = 0x08,
    XBE_SEC_HEAD_RO     = 0x10,
    XBE_SEC_TAIL_RO     = 0x20,
};

typedef struct {
    char     name[36];
    uint32_t virtual_addr;
    uint32_t virtual_size;
    uint32_t raw_addr;
    uint32_t raw_size;
    uint32_t flags;
} XbeSection;

typedef struct {
    int      ordinal;
    char     name[64];
    uint32_t thunk_addr;
} XbeKernelImport;

typedef struct {
    uint8_t*  raw;
    size_t    raw_len;
    uint32_t  base_address;
    uint32_t  image_size;
    uint32_t  headers_size;
    uint32_t  entry_point;
    uint32_t  kernel_thunk_addr;
    uint32_t  tls_addr;
    int       is_debug;

    VEC(XbeSection)      sections;
    VEC(XbeKernelImport) kernel_imports;
} Xbe;

/* Returns 0 on success, non-zero on error (message printed to stderr). */
int  xbe_load(const char* path, Xbe* out);
int  xbe_parse(const uint8_t* data, size_t len, Xbe* out);  /* takes ownership: copies */
void xbe_free(Xbe* x);

static inline uint32_t xbe_sec_end(const XbeSection* s) {
    return s->virtual_addr + s->virtual_size;
}

#endif
