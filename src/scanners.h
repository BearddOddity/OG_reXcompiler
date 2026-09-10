/* VtableScanner (MSVC RTTI) + SigScanner (byte pattern).
 * Ported from Analysis/VtableScanner.cs + Analysis/SigScanner.cs. */
#ifndef OGX_SCANNERS_H
#define OGX_SCANNERS_H

#include "binary_view.h"
#include "util.h"
#include "func_types.h"

typedef struct {
    uint32_t vtable_address;
    uint32_t col_address;
    char     class_name[128];
    U32Vec   slots;
} VTableInfo;

typedef VEC(VTableInfo) VTableInfoVec;

/* Fills out with every recovered vtable. Free with vtscan_free. */
void vtscan_run(BinaryView* bv, VTableInfoVec* out);
void vtscan_free(VTableInfoVec* v);

/* SigScanner: pattern bytes with -1 meaning wildcard. Returns match addresses
 * (+ entry_offset) in out. */
void sigscan(BinaryView* bv, const int* pattern, size_t plen, int entry_offset, U32Vec* out);

/* Data function-pointer scan: every 4-byte-aligned u32 in a data section that
 * points at a plausible function prologue inside a known code region. Catches
 * MSVC _initterm ctor tables, dispatch tables, and callback arrays the
 * recursive scanner never reaches. Appends unique addresses to out. */
void fnptrscan_run(BinaryView* bv, const CodeRegion* regions, size_t nregions, U32Vec* out);

#endif
