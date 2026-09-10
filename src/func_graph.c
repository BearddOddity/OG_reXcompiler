#include "func_graph.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>

const char* authority_name(FunctionAuthority a) {
    switch (a) {
        case AUTH_GAP_FILL: return "gap_fill";
        case AUTH_DISCOVERED: return "discovered";
        case AUTH_VTABLE: return "vtable";
        case AUTH_HELPER: return "helper";
        case AUTH_PDATA: return "pdata";
        case AUTH_CONFIG: return "config";
        case AUTH_IMPORT: return "import";
    }
    return "unknown";
}

/*=========================================================================
 * FunctionNode
 *=======================================================================*/

static FunctionNode* fn_new(uint32_t base, uint32_t size, FunctionAuthority auth) {
    FunctionNode* n = calloc(1, sizeof *n);
    n->base = base;
    n->size = size;
    n->authority = auth;
    n->state = ST_REGISTERED;
    snprintf(n->name, sizeof n->name, "sub_%08X", base);
    u32map_init(&n->labels, 16);
    return n;
}

static void fn_dispose(FunctionNode* n) {
    vec_free(&n->blocks);
    vec_free(&n->instructions);
    u32map_free(&n->labels);
    vec_free(&n->calls);
    vec_free(&n->tail_calls);
    vec_free(&n->jump_tables);
    vec_free(&n->unresolved_jumps);
    free(n);
}

int fn_is_pending(const FunctionNode* n) { return n->state != ST_SEALED; }
int fn_is_import(const FunctionNode* n)  { return n->authority == AUTH_IMPORT; }
int fn_end(const FunctionNode* n)        { return n->base + n->size; }

int fn_is_within_bounds(const FunctionNode* n, uint32_t addr) {
    return addr >= n->base && addr < n->base + n->size;
}

int fn_contains_address(const FunctionNode* n, uint32_t addr) {
    if (addr < n->base || addr >= n->base + n->size) return 0;
    if (n->blocks.len == 0) return 1;
    for (size_t i = 0; i < n->blocks.len; i++) {
        Block* b = &n->blocks.data[i];
        if (addr >= b->base && addr < block_end(b)) return 1;
    }
    if (n->authority == AUTH_CONFIG || n->authority == AUTH_PDATA) return 1;
    return 0;
}

int fn_can_seal(const FunctionNode* n) {
    if (n->state != ST_DISCOVERED) return 0;
    if (fn_is_import(n)) return 1;
    if (n->blocks.len == 0) return 0;
    if (n->unresolved_jumps.len > 0) return 0;
    return 1;
}

void fn_add_block(FunctionNode* n, Block b) {
    vec_push(&n->blocks, b);
    if (block_end(&b) > n->base + n->size) n->size = block_end(&b) - n->base;
}
void fn_add_label(FunctionNode* n, uint32_t a) { u32set_add(&n->labels, a); }
void fn_add_call(FunctionNode* n, uint32_t site, CallTarget t) {
    CallEdge e = { site, t }; vec_push(&n->calls, e);
}
void fn_add_tail_call(FunctionNode* n, uint32_t site, CallTarget t) {
    CallEdge e = { site, t }; vec_push(&n->tail_calls, e);
}
void fn_add_jump_table(FunctionNode* n, JumpTable* jt) {
    for (size_t i = 0; i < jt->targets.len; i++) u32set_add(&n->labels, jt->targets.data[i]);
    vec_push(&n->jump_tables, jt);
}
void fn_add_unresolved(FunctionNode* n, uint32_t site, uint32_t target, int is_call, int cond) {
    UnresolvedJump j = { site, target, is_call, cond }; vec_push(&n->unresolved_jumps, j);
}
void fn_remove_unresolved(FunctionNode* n, uint32_t site) {
    size_t w = 0;
    for (size_t i = 0; i < n->unresolved_jumps.len; i++)
        if (n->unresolved_jumps.data[i].site != site)
            n->unresolved_jumps.data[w++] = n->unresolved_jumps.data[i];
    n->unresolved_jumps.len = w;
}

void fn_discover(FunctionNode* n, Block* blocks, size_t nb,
                 DecodedInsn* insns, size_t ni, uint32_t* labels, size_t nl) {
    assert(n->state == ST_REGISTERED);
    vec_clear(&n->blocks); vec_clear(&n->instructions);
    for (size_t i = 0; i < nb; i++) vec_push(&n->blocks, blocks[i]);
    for (size_t i = 0; i < ni; i++) vec_push(&n->instructions, insns[i]);
    for (size_t i = 0; i < nl; i++) u32set_add(&n->labels, labels[i]);
    if (!fn_is_import(n)) assert(n->blocks.len > 0);
    for (size_t i = 0; i < n->blocks.len; i++) {
        uint32_t e = block_end(&n->blocks.data[i]);
        if (e > n->base + n->size) n->size = e - n->base;
    }
    n->state = ST_DISCOVERED;
}

void fn_discover_as_import(FunctionNode* n) {
    assert(n->state == ST_REGISTERED && fn_is_import(n));
    n->state = ST_DISCOVERED;
}

static int cmp_block(const void* a, const void* b) {
    uint32_t x = ((const Block*)a)->base, y = ((const Block*)b)->base;
    return x < y ? -1 : x > y ? 1 : 0;
}

void fn_seal(FunctionNode* n) {
    assert(fn_can_seal(n));
    if (n->blocks.len > 1) {
        qsort(n->blocks.data, n->blocks.len, sizeof(Block), cmp_block);
        BlockVec merged = {0};
        vec_push(&merged, n->blocks.data[0]);
        for (size_t i = 1; i < n->blocks.len; i++) {
            Block* last = &merged.data[merged.len - 1];
            Block cur = n->blocks.data[i];
            if (cur.base <= block_end(last)) {
                uint32_t ne = block_end(last);
                uint32_t ce = block_end(&cur);
                if (ce > ne) ne = ce;
                last->size = ne - last->base;
            } else {
                vec_push(&merged, cur);
            }
        }
        vec_free(&n->blocks);
        n->blocks = merged;
    }
    n->state = ST_SEALED;
}

/* reactive: a new function entered — claim any jump targeting its entry */
static int fn_try_resolve_against(FunctionNode* n, FunctionNode* newf) {
    if (n->state == ST_SEALED || !newf) return 0;
    int any = 0;
    for (size_t i = n->unresolved_jumps.len; i-- > 0; ) {
        if (n->unresolved_jumps.data[i].target == newf->base) {
            CallTarget t = { CT_FUNCTION }; t.node = newf;
            fn_add_tail_call(n, n->unresolved_jumps.data[i].site, t);
            n->unresolved_jumps.data[i] = n->unresolved_jumps.data[--n->unresolved_jumps.len];
            any = 1;
        }
    }
    return any;
}

static int fn_try_resolve_internal_label(FunctionNode* n, uint32_t target) {
    if (!fn_contains_address(n, target)) return 0;
    fn_add_label(n, target);
    return 1;
}

/*=========================================================================
 * FunctionGraph
 *=======================================================================*/

void fg_init(FunctionGraph* g) {
    memset(g, 0, sizeof *g);
    u32map_init(&g->functions, 4096);
    u32map_init(&g->has_xrefs, 4096);
}

void fg_free(FunctionGraph* g) {
    for (size_t i = 0; i < g->functions.cap; i++)
        if (g->functions.used[i]) fn_dispose(g->functions.vals[i]);
    u32map_free(&g->functions);
    u32map_free(&g->has_xrefs);
    vec_free(&g->sorted_bases);
    vec_free(&g->chunks);
}

static int cmp_u32(const void* a, const void* b) {
    uint32_t x = *(const uint32_t*)a, y = *(const uint32_t*)b;
    return x < y ? -1 : x > y ? 1 : 0;
}
static void fg_resort(FunctionGraph* g) {
    vec_clear(&g->sorted_bases);
    for (size_t i = 0; i < g->functions.cap; i++)
        if (g->functions.used[i]) vec_push(&g->sorted_bases, g->functions.keys[i]);
    qsort(g->sorted_bases.data, g->sorted_bases.len, sizeof(uint32_t), cmp_u32);
    g->sorted_dirty = 0;
}

static void fg_notify_added(FunctionGraph* g, FunctionNode* newf) {
    for (size_t i = 0; i < g->functions.cap; i++) {
        if (!g->functions.used[i]) continue;
        FunctionNode* n = g->functions.vals[i];
        if (n != newf && fn_is_pending(n)) fn_try_resolve_against(n, newf);
    }
}

FunctionNode* fg_add_function(FunctionGraph* g, uint32_t base, uint32_t size,
                              FunctionAuthority auth, const char* name, int has_xrefs) {
    void* existing;
    if (u32map_get(&g->functions, base, &existing)) {
        FunctionNode* e = existing;
        if (e->authority >= auth) return e;
        /* replace: dispose the old, fall through to create */
        u32map_remove(&g->functions, base);
        fn_dispose(e);
    }
    FunctionNode* n = fn_new(base, size, auth);
    if (name && name[0]) snprintf(n->name, sizeof n->name, "%s", name);
    u32map_put(&g->functions, base, n);
    u32map_put(&g->has_xrefs, base, (void*)(uintptr_t)(has_xrefs ? 1 : 0));
    g->sorted_dirty = 1;
    fg_notify_added(g, n);
    return n;
}

FunctionNode* fg_add_import(FunctionGraph* g, uint32_t address, const char* resolved_name) {
    return fg_add_function(g, address, 4, AUTH_IMPORT, resolved_name, 1);
}

FunctionNode* fg_get(FunctionGraph* g, uint32_t entry) {
    void* v; return u32map_get(&g->functions, entry, &v) ? v : NULL;
}

int fg_remove(FunctionGraph* g, uint32_t entry) {
    void* v;
    if (!u32map_get(&g->functions, entry, &v)) return 0;
    u32map_remove(&g->functions, entry);
    u32map_remove(&g->has_xrefs, entry);
    fn_dispose(v);
    g->sorted_dirty = 1;
    return 1;
}

FunctionNode* fg_get_containing(FunctionGraph* g, uint32_t addr) {
    if (g->sorted_dirty) fg_resort(g);
    size_t lo = 0, hi = g->sorted_bases.len, found = (size_t)-1;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (g->sorted_bases.data[mid] <= addr) { found = mid; lo = mid + 1; }
        else hi = mid;
    }
    if (found == (size_t)-1) return NULL;
    FunctionNode* n = fg_get(g, g->sorted_bases.data[found]);
    return (n && fn_contains_address(n, addr)) ? n : NULL;
}

int fg_is_entry_point(FunctionGraph* g, uint32_t addr) { return u32map_has(&g->functions, addr); }
int fg_is_import(FunctionGraph* g, uint32_t addr) {
    FunctionNode* n = fg_get(g, addr);
    return n && n->authority == AUTH_IMPORT;
}
size_t fg_count(FunctionGraph* g) { return g->functions.len; }
size_t fg_pending_count(FunctionGraph* g) {
    size_t c = 0;
    for (size_t i = 0; i < g->functions.cap; i++)
        if (g->functions.used[i] && fn_is_pending(g->functions.vals[i])) c++;
    return c;
}
size_t fg_sealed_count(FunctionGraph* g) { return g->functions.len - fg_pending_count(g); }

void fg_set_function_name(FunctionGraph* g, uint32_t entry, const char* name) {
    FunctionNode* n = fg_get(g, entry);
    if (n) snprintf(n->name, sizeof n->name, "%s", name);
}
void fg_set_exception_info(FunctionGraph* g, uint32_t entry, const ExceptionInfo* info) {
    FunctionNode* n = fg_get(g, entry);
    if (n) { n->exception_info = *info; n->has_exception_info = info->has_seh || info->has_cxx; }
}
void fg_add_jump_table_to(FunctionGraph* g, uint32_t entry, JumpTable* jt) {
    FunctionNode* n = fg_get(g, entry);
    if (n) fn_add_jump_table(n, jt);
}

void fg_add_unresolved_jump_to(FunctionGraph* g, uint32_t entry, uint32_t site,
                               uint32_t target, int is_call, int cond) {
    FunctionNode* n = fg_get(g, entry);
    if (!n) return;
    FunctionNode* tf = fg_get(g, target);
    if (tf) {
        CallTarget t = { CT_FUNCTION }; t.node = tf;
        if (is_call) fn_add_call(n, site, t); else fn_add_tail_call(n, site, t);
        return;
    }
    if (fg_is_import(g, target)) {
        FunctionNode* imp = fg_get(g, target);
        CallTarget t = { CT_IMPORT }; t.address = target;
        snprintf(t.name, sizeof t.name, "%s", imp->name);
        if (is_call) fn_add_call(n, site, t); else fn_add_tail_call(n, site, t);
        return;
    }
    fn_add_unresolved(n, site, target, is_call, cond);
}

int fg_try_resolve_function(FunctionGraph* g, uint32_t entry) {
    FunctionNode* n = fg_get(g, entry);
    if (!n || n->state == ST_SEALED) return 0;
    int resolved = 0;
    /* snapshot */
    size_t count = n->unresolved_jumps.len;
    UnresolvedJump* snap = malloc(count * sizeof(UnresolvedJump));
    memcpy(snap, n->unresolved_jumps.data, count * sizeof(UnresolvedJump));
    for (size_t i = 0; i < count; i++) {
        UnresolvedJump j = snap[i];
        if (fn_try_resolve_internal_label(n, j.target)) {
            fn_remove_unresolved(n, j.site); resolved++; continue;
        }
        FunctionNode* tf = fg_get(g, j.target);
        if (tf) {
            CallTarget t = { CT_FUNCTION }; t.node = tf;
            if (j.is_call) fn_add_call(n, j.site, t); else fn_add_tail_call(n, j.site, t);
            fn_remove_unresolved(n, j.site); resolved++; continue;
        }
        if (fg_is_import(g, j.target)) {
            FunctionNode* imp = fg_get(g, j.target);
            CallTarget t = { CT_IMPORT }; t.address = j.target;
            snprintf(t.name, sizeof t.name, "%s", imp->name);
            if (j.is_call) fn_add_call(n, j.site, t); else fn_add_tail_call(n, j.site, t);
            fn_remove_unresolved(n, j.site); resolved++;
        }
    }
    free(snap);
    return resolved;
}

int fg_try_seal_function(FunctionGraph* g, uint32_t entry) {
    FunctionNode* n = fg_get(g, entry);
    if (!n || n->state == ST_SEALED || !fn_can_seal(n)) return 0;
    fn_seal(n);
    return 1;
}

size_t fg_seal_all_ready(FunctionGraph* g) {
    size_t sealed = 0;
    for (size_t i = 0; i < g->functions.cap; i++) {
        if (!g->functions.used[i]) continue;
        FunctionNode* n = g->functions.vals[i];
        if (fn_is_pending(n) && fn_can_seal(n)) { fn_seal(n); sealed++; }
    }
    return sealed;
}

void fg_set_memory_reader(FunctionGraph* g, MemoryReader r, void* ctx) {
    g->mem_reader = r; g->mem_ctx = ctx;
}
void fg_register_chunk(FunctionGraph* g, uint32_t base, uint32_t size) {
    Block b = { base, size }; vec_push(&g->chunks, b);
}

int fg_is_mergeable_entry_point(FunctionGraph* g, uint32_t addr) {
    FunctionNode* n = fg_get(g, addr);
    return n && n->authority == AUTH_GAP_FILL;
}

int fg_is_vacant(FunctionGraph* g, uint32_t from_addr, uint32_t target_addr) {
    if (g->mem_reader && target_addr > from_addr) {
        uint32_t v;
        if (g->mem_reader(g->mem_ctx, target_addr, &v) && v == 0) return 0;
    }
    for (size_t i = 0; i < g->chunks.len; i++) {
        Block* c = &g->chunks.data[i];
        if (target_addr >= c->base && target_addr < c->base + c->size) return 0;
    }
    for (size_t i = 0; i < g->functions.cap; i++) {
        if (!g->functions.used[i]) continue;
        FunctionNode* n = g->functions.vals[i];
        if (fn_contains_address(n, target_addr)) {
            if (fg_is_mergeable_entry_point(g, target_addr)) continue;
            return 0;
        }
    }
    return 1;
}

TargetKind fg_classify_target(FunctionGraph* g, uint32_t target, uint32_t caller_addr, int is_call) {
    FunctionNode* caller = fg_get_containing(g, caller_addr);
    if (fg_is_import(g, target)) return TK_IMPORT;
    if (caller && target == caller->base) return is_call ? TK_FUNCTION : TK_INTERNAL_LABEL;
    if (fg_is_entry_point(g, target)) return TK_FUNCTION;
    if (caller && fn_contains_address(caller, target)) return TK_INTERNAL_LABEL;
    return TK_UNKNOWN;
}

size_t fg_mark_funclet_register_sharing(FunctionGraph* g) {
    VEC(uint32_t) starts = {0};
    VEC(uint32_t) ends = {0};
    for (size_t i = 0; i < g->functions.cap; i++) {
        if (!g->functions.used[i]) continue;
        FunctionNode* n = g->functions.vals[i];
        if (!n->has_exception_info) continue;
        ExceptionInfo* e = &n->exception_info;
        if (e->has_seh) {
            for (size_t s = 0; s < e->seh.scopes.len; s++) {
                uint32_t hs[2] = { e->seh.scopes.data[s].handler, e->seh.scopes.data[s].filter };
                for (int k = 0; k < 2; k++) {
                    FunctionNode* f = hs[k] ? fg_get(g, hs[k]) : NULL;
                    if (f) { vec_push(&starts, f->base); vec_push(&ends, fn_end(f)); }
                }
            }
        }
        if (e->has_cxx) {
            for (size_t a = 0; a < e->cxx.handler_addresses.len; a++) {
                FunctionNode* f = fg_get(g, e->cxx.handler_addresses.data[a]);
                if (f) { vec_push(&starts, f->base); vec_push(&ends, fn_end(f)); }
            }
        }
    }
    size_t marked = 0;
    if (starts.len) {
        for (size_t i = 0; i < g->functions.cap; i++) {
            if (!g->functions.used[i]) continue;
            FunctionNode* n = g->functions.vals[i];
            if (n->shares_registers) continue;
            for (size_t r = 0; r < starts.len; r++)
                if (n->base >= starts.data[r] && n->base < ends.data[r]) {
                    n->shares_registers = 1; marked++; break;
                }
        }
    }
    vec_free(&starts); vec_free(&ends);
    return marked;
}

void fg_each(FunctionGraph* g, void (*fn)(FunctionNode*, void*), void* ctx) {
    for (size_t i = 0; i < g->functions.cap; i++)
        if (g->functions.used[i]) fn(g->functions.vals[i], ctx);
}
