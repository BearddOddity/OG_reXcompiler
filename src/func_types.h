/* Shared function-graph types. Ported from FunctionTypes.cs. */
#ifndef OGX_FUNC_TYPES_H
#define OGX_FUNC_TYPES_H

#include <stdint.h>
#include "util.h"

/* Higher value wins at the same address; only GAP_FILL is absorbable.
 * PDATA is kept for lattice-shape parity — 32-bit x86 has no .pdata. */
typedef enum {
    AUTH_GAP_FILL   = 0,
    AUTH_DISCOVERED = 1,
    AUTH_VTABLE     = 2,
    AUTH_HELPER     = 3,
    AUTH_PDATA      = 4,
    AUTH_CONFIG     = 5,
    AUTH_IMPORT     = 6,
} FunctionAuthority;

typedef enum { ST_REGISTERED, ST_DISCOVERED, ST_SEALED } FunctionState;

typedef enum { TK_INTERNAL_LABEL, TK_FUNCTION, TK_IMPORT, TK_UNKNOWN } TargetKind;

const char* authority_name(FunctionAuthority a);

typedef struct { uint32_t base, size; } Block;
static inline uint32_t block_end(const Block* b) { return b->base + b->size; }
typedef VEC(Block) BlockVec;
typedef VEC(uint32_t) U32Vec;

typedef struct { uint32_t start, end; char section[36]; } CodeRegion;
static inline int cr_contains(const CodeRegion* r, uint32_t a) { return a >= r->start && a < r->end; }
static inline uint32_t cr_size(const CodeRegion* r) { return r->end - r->start; }

typedef struct {
    uint32_t jump_address;
    uint32_t table_address;
    uint8_t  index_register;
    VEC(uint32_t) targets;
} JumpTable;

struct FunctionNode;

typedef enum { CT_FUNCTION, CT_IMPORT, CT_UNRESOLVED } CallTargetKind;
typedef struct {
    CallTargetKind kind;
    struct FunctionNode* node;   /* CT_FUNCTION */
    uint32_t address;            /* CT_IMPORT / CT_UNRESOLVED */
    char name[80];               /* CT_IMPORT */
} CallTarget;

typedef struct { uint32_t site; CallTarget target; } CallEdge;
typedef struct { uint32_t site, target; int is_call, is_conditional; } UnresolvedJump;

/* --- exception info (x86 _EH4 SEH / C++ EH). Parsed lazily; kept minimal. --- */
typedef struct { uint32_t try_start, try_end, handler, filter; } SehScope;
typedef struct {
    uint32_t handler_thunk, scope_table_addr, frame_size, restore_helper;
    VEC(SehScope) scopes;
} SehExceptionInfo;
typedef struct { uint32_t action; int32_t to_state; } CxxUnwindEntry;
typedef struct {
    uint32_t handler_thunk, func_info_addr, max_state;
    VEC(CxxUnwindEntry) unwind_map;
    VEC(uint32_t) handler_addresses;   /* flattened catch handler addrs */
} CxxExceptionInfo;
typedef struct {
    int has_seh, has_cxx;
    SehExceptionInfo seh;
    CxxExceptionInfo cxx;
} ExceptionInfo;

#endif
