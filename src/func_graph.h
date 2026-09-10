/* FunctionNode + FunctionGraph. Ported from FunctionNode.cs + FunctionGraph.cs. */
#ifndef OGX_FUNC_GRAPH_H
#define OGX_FUNC_GRAPH_H

#include "func_types.h"
#include "decoded.h"

typedef struct FunctionNode {
    uint32_t base;
    uint32_t size;
    char     name[80];
    FunctionAuthority authority;
    FunctionState     state;
    int      has_exception_handler;
    int      shares_registers;
    int      has_exception_info;
    ExceptionInfo exception_info;

    BlockVec            blocks;
    VEC(DecodedInsn)    instructions;
    u32map             labels;         /* set */
    VEC(CallEdge)       calls;
    VEC(CallEdge)       tail_calls;
    VEC(JumpTable*)     jump_tables;
    VEC(UnresolvedJump) unresolved_jumps;
} FunctionNode;

int  fn_is_pending(const FunctionNode* n);
int  fn_is_import(const FunctionNode* n);
int  fn_end(const FunctionNode* n);
int  fn_contains_address(const FunctionNode* n, uint32_t addr);
int  fn_is_within_bounds(const FunctionNode* n, uint32_t addr);
int  fn_can_seal(const FunctionNode* n);

/* mutators (graph-internal, but exposed for the phases) */
void fn_discover(FunctionNode* n, Block* blocks, size_t nb,
                 DecodedInsn* insns, size_t ni, uint32_t* labels, size_t nl);
void fn_discover_as_import(FunctionNode* n);
void fn_seal(FunctionNode* n);
void fn_add_block(FunctionNode* n, Block b);
void fn_add_label(FunctionNode* n, uint32_t a);
void fn_add_call(FunctionNode* n, uint32_t site, CallTarget t);
void fn_add_tail_call(FunctionNode* n, uint32_t site, CallTarget t);
void fn_add_jump_table(FunctionNode* n, JumpTable* jt);
void fn_add_unresolved(FunctionNode* n, uint32_t site, uint32_t target, int is_call, int cond);
void fn_remove_unresolved(FunctionNode* n, uint32_t site);

typedef int (*MemoryReader)(void* ctx, uint32_t addr, uint32_t* out);

typedef struct {
    u32map functions;        /* addr -> FunctionNode* */
    u32map has_xrefs;        /* addr -> (void*)1 */
    u32map pending_unresolved; /* set: addrs of pending nodes with >=1 unresolved jump */
    u32map unresolved_by_target; /* target addr -> U32Vec* of node bases with an unresolved jump there */
    U32Vec sorted_bases;   /* kept sorted for interval lookup */
    int sorted_dirty;
    BlockVec chunks;
    MemoryReader mem_reader;
    void* mem_ctx;
} FunctionGraph;

void fg_init(FunctionGraph* g);
void fg_free(FunctionGraph* g);

FunctionNode* fg_add_function(FunctionGraph* g, uint32_t base, uint32_t size,
                              FunctionAuthority auth, const char* name, int has_xrefs);
FunctionNode* fg_add_import(FunctionGraph* g, uint32_t address, const char* resolved_name);
FunctionNode* fg_get(FunctionGraph* g, uint32_t entry);
int  fg_remove(FunctionGraph* g, uint32_t entry);
FunctionNode* fg_get_containing(FunctionGraph* g, uint32_t addr);
int  fg_is_entry_point(FunctionGraph* g, uint32_t addr);
int  fg_is_import(FunctionGraph* g, uint32_t addr);
size_t fg_count(FunctionGraph* g);
size_t fg_pending_count(FunctionGraph* g);
size_t fg_sealed_count(FunctionGraph* g);

void fg_set_function_name(FunctionGraph* g, uint32_t entry, const char* name);
void fg_set_exception_info(FunctionGraph* g, uint32_t entry, const ExceptionInfo* info);
void fg_add_jump_table_to(FunctionGraph* g, uint32_t entry, JumpTable* jt);
void fg_add_unresolved_jump_to(FunctionGraph* g, uint32_t entry, uint32_t site,
                               uint32_t target, int is_call, int cond);

int  fg_try_resolve_function(FunctionGraph* g, uint32_t entry);
int  fg_try_seal_function(FunctionGraph* g, uint32_t entry);
size_t fg_seal_all_ready(FunctionGraph* g);

void fg_set_memory_reader(FunctionGraph* g, MemoryReader r, void* ctx);
void fg_register_chunk(FunctionGraph* g, uint32_t base, uint32_t size);
int  fg_is_vacant(FunctionGraph* g, uint32_t from_addr, uint32_t target_addr);
int  fg_is_mergeable_entry_point(FunctionGraph* g, uint32_t addr);
size_t fg_mark_funclet_register_sharing(FunctionGraph* g);
TargetKind fg_classify_target(FunctionGraph* g, uint32_t target, uint32_t caller_addr, int is_call);

/* iterate every node: calls fn(node, ctx) */
void fg_each(FunctionGraph* g, void (*fn)(FunctionNode*, void*), void* ctx);

#endif
