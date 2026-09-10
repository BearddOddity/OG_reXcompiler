/* BinaryView — VA-addressable, owned view of a loaded binary.
 * Ported from the C# branch (Binary/BinaryView.cs). */
#ifndef OGX_BINARY_VIEW_H
#define OGX_BINARY_VIEW_H

#include <stdint.h>
#include "util.h"
#include "xbe.h"

typedef struct {
    char     name[36];
    uint32_t base_address;
    uint32_t size;          /* virtual size; data[] is this long, zero-padded past raw */
    uint8_t* data;
    int      executable;
    int      writable;
} SectionView;

typedef struct {
    uint32_t address;      /* thunk address a call targets */
    char     name[80];     /* "xboxkrnl@<ord>:<Name>" */
} ImportSymbol;

typedef struct {
    VEC(SectionView)  sections;
    VEC(ImportSymbol) imports;
    uint32_t base_address;
    uint32_t image_size;
    uint32_t entry_point;
    uint32_t kernel_thunk_table_start;
} BinaryView;

void         bv_from_xbe(const Xbe* xbe, BinaryView* out);
void         bv_free(BinaryView* v);

SectionView* bv_find_section(BinaryView* v, uint32_t addr);
SectionView* bv_find_section_by_name(BinaryView* v, const char* name);
const uint8_t* bv_translate(BinaryView* v, uint32_t addr, size_t* avail); /* NULL if unmapped */
int          bv_read_u32(BinaryView* v, uint32_t addr, uint32_t* out);
int          bv_is_executable(BinaryView* v, uint32_t addr);
int          bv_is_data_section_name(const char* name);   /* .data/.rdata/... */

#endif
