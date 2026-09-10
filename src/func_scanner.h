/* FunctionScanner — worklist block discovery + x86 jump-table detection.
 * Ported from Analysis/FunctionScanner.cs. */
#ifndef OGX_FUNC_SCANNER_H
#define OGX_FUNC_SCANNER_H

#include "decoded.h"
#include "func_types.h"

typedef struct { uint32_t site, target; int is_call, is_conditional; } UnresolvedBranch;

typedef struct {
    BlockVec          blocks;
    VEC(DecodedInsn)  instructions;
    U32Vec            labels;
    U32Vec            external_calls;
    U32Vec            tail_calls;
    VEC(UnresolvedBranch) unresolved_branches;
    VEC(JumpTable*)   jump_tables;
} BlockDiscoveryResult;

void bdr_free(BlockDiscoveryResult* r);

typedef struct {
    DecodedBinary* db;
    BinaryView*    bv;
    VEC(CodeRegion) code_regions;
} FunctionScanner;

void fs_init(FunctionScanner* fs, DecodedBinary* db, const CodeRegion* regions, size_t n);
void fs_free(FunctionScanner* fs);

CodeRegion* fs_region_containing(FunctionScanner* fs, uint32_t addr);

/* known_functions: a u32map used as a set. manual_tables: u32map addr->JumpTable* or NULL. */
void fs_discover_blocks(FunctionScanner* fs, uint32_t entry_point,
                        u32map* known_functions, u32map* manual_tables,
                        BlockDiscoveryResult* out);

JumpTable* fs_detect_jump_table(FunctionScanner* fs, uint32_t jmp_addr,
                                const CodeRegion* region, uint32_t func_start, uint32_t func_end);

#endif
