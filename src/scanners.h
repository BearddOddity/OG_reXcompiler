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

#endif
