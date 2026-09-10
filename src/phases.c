#include "phases.h"
#include "func_scanner.h"
#include "scanners.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/*=========================================================================
 * Scan phase — null-run code/data region carving (port of ScanPhase.cs)
 *=======================================================================*/

static void segment_code_regions(SectionView* sec, int min_null, const u32map* handlers,
                                 CodeRegionVec* out) {
    const uint8_t* d = sec->data;
    uint32_t n = sec->size, base = sec->base_address;
    long region_start = -1;
    uint32_t i = 0;

    while (i < n) {
        if (d[i] == 0) {
            uint32_t j = i;
            while (j < n && d[j] == 0) j++;
            uint32_t run = j - i;

            if (run >= 4 && i + 8 <= n) {
                uint32_t next_word = (uint32_t)d[i+4] | ((uint32_t)d[i+5] << 8) |
                                     ((uint32_t)d[i+6] << 16) | ((uint32_t)d[i+7] << 24);
                if (u32map_has(handlers, next_word)) {
                    if (region_start < 0) region_start = i;
                    i += 8;
                    continue;
                }
            }
            if ((int)run >= min_null) {
                if (region_start >= 0) {
                    CodeRegion r = { base + (uint32_t)region_start, base + i, {0} };
                    snprintf(r.section, sizeof r.section, "%s", sec->name);
                    vec_push(out, r);
                    region_start = -1;
                }
                i = j;
                continue;
            }
            if (region_start < 0) region_start = i;
            i = j;
            continue;
        }
        if (region_start < 0) region_start = i;
        i++;
    }
    if (region_start >= 0) {
        CodeRegion r = { base + (uint32_t)region_start, base + n, {0} };
        snprintf(r.section, sizeof r.section, "%s", sec->name);
        vec_push(out, r);
    }
}

static void detect_data_regions(SectionView* sec, int threshold, CodeRegionVec* out) {
    const uint8_t* d = sec->data;
    uint32_t n = sec->size & ~3u, base = sec->base_address;
    int invalid_run = 0; uint32_t run_start = 0;
    for (uint32_t off = 0; off < n; off += 4) {
        uint32_t w = (uint32_t)d[off] | ((uint32_t)d[off+1] << 8) |
                     ((uint32_t)d[off+2] << 16) | ((uint32_t)d[off+3] << 24);
        int inv = (w == 0x00000000u || w == 0xFFFFFFFFu);
        if (inv) { if (invalid_run == 0) run_start = off; invalid_run++; }
        else {
            if (invalid_run >= threshold) {
                CodeRegion r = { base + run_start, base + off, {0} };
                snprintf(r.section, sizeof r.section, "%s", sec->name);
                vec_push(out, r);
            }
            invalid_run = 0;
        }
    }
    if (invalid_run >= threshold) {
        CodeRegion r = { base + run_start, base + n, {0} };
        snprintf(r.section, sizeof r.section, "%s", sec->name);
        vec_push(out, r);
    }
}

void phase_scan(CodegenContext* ctx) {
    int min_null = (int)(ctx->config->min_null_run < 1 ? 1 : ctx->config->min_null_run);
    for (size_t i = 0; i < ctx->bv->sections.len; i++) {
        SectionView* s = &ctx->bv->sections.data[i];
        if (!s->executable || s->size == 0 || bv_is_data_section_name(s->name)) continue;
        segment_code_regions(s, min_null, &ctx->state.exception_handler_funcs, &ctx->scan.code_regions);
        detect_data_regions(s, (int)ctx->config->data_region_threshold, &ctx->scan.data_regions);
    }
}

/*=========================================================================
 * Register
 *=======================================================================*/

static const char* short_import_name(const char* full) {
    const char* colon = strrchr(full, ':');
    return colon ? colon + 1 : full;
}

void phase_register(CodegenContext* ctx) {
    FunctionGraph* g = &ctx->graph;
    RecompilerConfig* cfg = ctx->config;

    for (size_t i = 0; i < cfg->exception_handler_hints.cap; i++)
        if (cfg->exception_handler_hints.used[i])
            u32set_add(&ctx->state.exception_handler_funcs, cfg->exception_handler_hints.keys[i]);

    for (size_t i = 0; i < ctx->bv->imports.len; i++) {
        ImportSymbol* sym = &ctx->bv->imports.data[i];
        char name[96];
        snprintf(name, sizeof name, "__imp__%s", short_import_name(sym->name));
        FunctionNode* n = fg_add_import(g, sym->address, name);
        if (n->state == ST_REGISTERED) fn_discover_as_import(n);
        if (fn_can_seal(n)) fn_seal(n);
    }

    if (ctx->bv->entry_point != 0)
        fg_add_function(g, ctx->bv->entry_point, 0, AUTH_CONFIG, "xstart", 1);

    for (size_t i = 0; i < cfg->seed_functions.cap; i++)
        if (cfg->seed_functions.used[i])
            fg_add_function(g, cfg->seed_functions.keys[i], 0, AUTH_CONFIG, NULL, 1);

    for (size_t i = 0; i < cfg->functions.cap; i++) {
        if (!cfg->functions.used[i]) continue;
        uint32_t addr = cfg->functions.keys[i];
        FunctionConfig* fc = cfg->functions.vals[i];
        uint32_t size = fc->size ? fc->size : (fc->end > addr ? fc->end - addr : 0);
        FunctionNode* n = fg_add_function(g, addr, size, AUTH_CONFIG,
                                          fc->name[0] ? fc->name : NULL, 1);
        if (fc->share_registers) n->shares_registers = 1;
        if (size) fg_register_chunk(g, addr, size);
    }
}

/*=========================================================================
 * PhaseHelpers — known set + discover-pending
 *=======================================================================*/

static void build_known(FunctionGraph* g, int exclude_gapfill, u32map* out) {
    u32map_init(out, g->functions.len + 16);
    for (size_t i = 0; i < g->functions.cap; i++) {
        if (!g->functions.used[i]) continue;
        FunctionNode* n = g->functions.vals[i];
        if (exclude_gapfill && n->authority == AUTH_GAP_FILL) continue;
        u32set_add(out, g->functions.keys[i]);
    }
}

static void discover_one(CodegenContext* ctx, FunctionScanner* fs, uint32_t addr, u32map* known) {
    FunctionGraph* g = &ctx->graph;
    FunctionNode* node = fg_get(g, addr);
    if (!node || node->state != ST_REGISTERED) return;

    if (fn_is_import(node)) {
        fn_discover_as_import(node);
        if (fn_can_seal(node)) fn_seal(node);
        return;
    }

    uint32_t declared_size = node->authority == AUTH_CONFIG ? node->size : 0;

    BlockDiscoveryResult r;
    fs_discover_blocks(fs, addr, known, &ctx->config->switch_tables, &r);
    if (r.blocks.len == 0) { bdr_free(&r); return; }

    if (declared_size != 0) {
        uint32_t end = addr + declared_size;
        size_t w = 0;
        for (size_t i = 0; i < r.blocks.len; i++) {
            Block b = r.blocks.data[i];
            if (b.base >= end) continue;
            if (block_end(&b) > end) b.size = end - b.base;
            r.blocks.data[w++] = b;
        }
        r.blocks.len = w;
        if (r.blocks.len == 0) { bdr_free(&r); return; }
    }

    fn_discover(node, r.blocks.data, r.blocks.len, r.instructions.data, r.instructions.len,
                r.labels.data, r.labels.len);

    for (size_t i = 0; i < r.jump_tables.len; i++)
        fg_add_jump_table_to(g, addr, r.jump_tables.data[i]);

    for (size_t i = 0; i < r.external_calls.len; i++) {
        uint32_t t = r.external_calls.data[i];
        if (fg_is_entry_point(g, t) || fg_is_import(g, t)) continue;
        if (t == ctx->bv->kernel_thunk_table_start) continue;
        fg_add_function(g, t, 4, AUTH_DISCOVERED, NULL, 1);
    }

    for (size_t i = 0; i < r.unresolved_branches.len; i++) {
        UnresolvedBranch* b = &r.unresolved_branches.data[i];
        fg_add_unresolved_jump_to(g, addr, b->site, b->target, b->is_call, b->is_conditional);
    }

    /* transfer of jump_tables ownership done; free the rest */
    vec_free(&r.blocks); vec_free(&r.instructions); vec_free(&r.labels);
    vec_free(&r.external_calls); vec_free(&r.tail_calls);
    vec_free(&r.unresolved_branches); vec_free(&r.jump_tables);
}

static int discover_pending(CodegenContext* ctx, FunctionScanner* fs, u32map* known) {
    U32Vec pending = {0};
    for (size_t i = 0; i < ctx->graph.functions.cap; i++) {
        if (!ctx->graph.functions.used[i]) continue;
        FunctionNode* n = ctx->graph.functions.vals[i];
        if (n->state == ST_REGISTERED) vec_push(&pending, ctx->graph.functions.keys[i]);
    }
    for (size_t i = 0; i < pending.len; i++) discover_one(ctx, fs, pending.data[i], known);
    int c = (int)pending.len;
    vec_free(&pending);
    return c;
}

/*=========================================================================
 * Discover
 *=======================================================================*/

void phase_discover(CodegenContext* ctx) {
    FunctionGraph* g = &ctx->graph;
    FunctionScanner fs;
    fs_init(&fs, ctx->db, ctx->scan.code_regions.data, ctx->scan.code_regions.len);

    /* Function pointers stored in data sections — MSVC _initterm ctor tables,
     * callback arrays, dispatch tables the recursive scanner never reaches.
     * DISCOVERED authority: real extent detection and merge/gapfill win.
     * Skipped when the config supplies a full [functions] list (>1000): that
     * list is authoritative and fnptrscan's guesses would only add noise. */
    if (ctx->config->functions.len <= 1000) {
        U32Vec fps = {0};
        fnptrscan_run(ctx->bv, ctx->scan.code_regions.data, ctx->scan.code_regions.len, &fps);
        for (size_t i = 0; i < fps.len; i++)
            fg_add_function(g, fps.data[i], 0, AUTH_DISCOVERED, NULL, 1);
        fprintf(stderr, "  [fnptrscan] %zu data function pointers seeded\n", fps.len);
        vec_free(&fps);
    } else {
        fprintf(stderr, "  [fnptrscan] skipped — config supplies %zu functions\n",
                ctx->config->functions.len);
    }

    long last_count = -1;
    for (int iter = 0; iter < 64; iter++) {
        long count = (long)fg_count(g);
        if (count == last_count && iter > 0) break;
        last_count = count;
        u32map known; build_known(g, 0, &known);
        int n = discover_pending(ctx, &fs, &known);
        u32map_free(&known);
        if (n == 0) break;
    }

    VTableInfoVec vts;
    vtscan_run(ctx->bv, &vts);
    int new_fns = 0;
    for (size_t i = 0; i < vts.len; i++)
        for (size_t s = 0; s < vts.data[i].slots.len; s++) {
            uint32_t slot = vts.data[i].slots.data[s];
            if (fg_is_entry_point(g, slot)) continue;
            if (!fs_region_containing(&fs, slot)) continue;
            fg_add_function(g, slot, 4, AUTH_VTABLE, NULL, 1);
            new_fns++;
        }
    vtscan_free(&vts);

    if (new_fns > 0) {
        for (int iter = 0; iter < 64; iter++) {
            u32map known; build_known(g, 0, &known);
            int n = discover_pending(ctx, &fs, &known);
            u32map_free(&known);
            if (n == 0) break;
            if ((long)fg_count(g) == last_count) break;
            last_count = (long)fg_count(g);
        }
    }

    fs_free(&fs);
}

/*=========================================================================
 * GapFill
 *=======================================================================*/

static int looks_like_exception_data(CodegenContext* ctx, uint32_t addr) {
    uint32_t first, second;
    if (!bv_read_u32(ctx->bv, addr, &first) || !bv_read_u32(ctx->bv, addr + 4, &second)) return 0;
    if (!fg_is_entry_point(&ctx->graph, first)) return 0;
    SectionView* rd = bv_find_section_by_name(ctx->bv, ".rdata");
    if (!rd) return 0;
    return second >= rd->base_address && second < rd->base_address + rd->size;
}

void phase_gapfill(CodegenContext* ctx) {
    FunctionGraph* g = &ctx->graph;
    FunctionScanner fs;
    fs_init(&fs, ctx->db, ctx->scan.code_regions.data, ctx->scan.code_regions.len);

    u32map known_callables; u32map_init(&known_callables, g->functions.len + 16);
    for (size_t i = 0; i < g->functions.cap; i++)
        if (g->functions.used[i]) u32set_add(&known_callables, g->functions.keys[i]);

    for (size_t ri = 0; ri < ctx->scan.code_regions.len; ri++) {
        CodeRegion region = ctx->scan.code_regions.data[ri];
        uint32_t seg_start = region.start;
        uint32_t addr = region.start;
        while (addr < region.end) {
            DecodedInsn insn;
            if (!db_decode_at(ctx->db, addr, &insn) || insn.flow == FLOW_INVALID) { addr++; continue; }
            int split = 0;
            if (insn.flow == FLOW_RETURN) split = 1;
            else if (insn.flow == FLOW_UNCONDITIONAL_BR && insn.target != 0 &&
                     insn.target != seg_start && u32map_has(&known_callables, insn.target))
                split = 1;
            uint32_t next = di_end(&insn);
            if (split) {
                if (next > seg_start) {
                    uint32_t s = seg_start;
                    if (!fg_is_entry_point(g, s) && !fg_get_containing(g, s) && !looks_like_exception_data(ctx, s))
                        fg_add_function(g, s, next - s, AUTH_GAP_FILL, NULL, 0);
                }
                seg_start = next;
            }
            addr = next;
        }
        if (seg_start < region.end) {
            uint32_t s = seg_start;
            if (!fg_is_entry_point(g, s) && !fg_get_containing(g, s) && !looks_like_exception_data(ctx, s))
                fg_add_function(g, s, region.end - s, AUTH_GAP_FILL, NULL, 0);
        }
    }
    u32map_free(&known_callables);

    u32map known; build_known(g, 1, &known);
    discover_pending(ctx, &fs, &known);
    u32map_free(&known);

    /* cleanup absorbed gap-fills */
    U32Vec solid_start = {0}, solid_end = {0};
    for (size_t i = 0; i < g->functions.cap; i++) {
        if (!g->functions.used[i]) continue;
        FunctionNode* n = g->functions.vals[i];
        if (n->authority == AUTH_GAP_FILL) continue;
        vec_push(&solid_start, n->base);
        vec_push(&solid_end, fn_end(n));
    }
    U32Vec to_remove = {0};
    for (size_t i = 0; i < g->functions.cap; i++) {
        if (!g->functions.used[i]) continue;
        FunctionNode* n = g->functions.vals[i];
        if (n->authority != AUTH_GAP_FILL) continue;
        int inside = 0;
        for (size_t k = 0; k < solid_start.len; k++)
            if (n->base >= solid_start.data[k] && n->base < solid_end.data[k]) { inside = 1; break; }
        if (inside) { vec_push(&to_remove, n->base); continue; }
        FunctionNode* c = fg_get_containing(g, n->base);
        if (c && c->base < n->base && c->authority == AUTH_GAP_FILL) vec_push(&to_remove, n->base);
    }
    for (size_t i = 0; i < to_remove.len; i++) fg_remove(g, to_remove.data[i]);
    vec_free(&solid_start); vec_free(&solid_end); vec_free(&to_remove);

    fs_free(&fs);
}

/*=========================================================================
 * Merge
 *=======================================================================*/

static int graph_mem_reader(void* vctx, uint32_t addr, uint32_t* out) {
    return bv_read_u32(((CodegenContext*)vctx)->bv, addr, out);
}

void phase_merge(CodegenContext* ctx) {
    FunctionGraph* g = &ctx->graph;
    fg_set_memory_reader(g, graph_mem_reader, ctx);

    for (int iter = 0; iter < 32; iter++) {
        int changed = 0;
        U32Vec pend = {0};
        for (size_t i = 0; i < g->functions.cap; i++)
            if (g->functions.used[i] && fn_is_pending(g->functions.vals[i]))
                vec_push(&pend, g->functions.keys[i]);
        for (size_t i = 0; i < pend.len; i++) changed += fg_try_resolve_function(g, pend.data[i]);
        vec_free(&pend);
        if (changed == 0) break;
    }

    /* second chance: a branch into another function's body -> tail call to it */
    for (size_t i = 0; i < g->functions.cap; i++) {
        if (!g->functions.used[i]) continue;
        FunctionNode* n = g->functions.vals[i];
        if (!fn_is_pending(n)) continue;
        for (size_t j = n->unresolved_jumps.len; j-- > 0; ) {
            UnresolvedJump u = n->unresolved_jumps.data[j];
            FunctionNode* owner = fg_get_containing(g, u.target);
            if (!owner || owner == n) continue;
            CallTarget t = { CT_FUNCTION }; t.node = owner;
            fn_add_tail_call(n, u.site, t);
            fn_remove_unresolved(n, u.site);
        }
    }

    fg_mark_funclet_register_sharing(g);
    fg_seal_all_ready(g);
}

/*=========================================================================
 * Validate
 *=======================================================================*/

int phase_validate(CodegenContext* ctx) {
    FunctionGraph* g = &ctx->graph;
    for (size_t i = 0; i < g->functions.cap; i++) {
        if (!g->functions.used[i]) continue;
        FunctionNode* n = g->functions.vals[i];
        if (fn_is_import(n)) continue;
        for (size_t bi = 0; bi < n->blocks.len; bi++) {
            Block* block = &n->blocks.data[bi];
            uint32_t p = block->base;
            while (p < block_end(block)) {
                DecodedInsn insn;
                if (!db_decode_at(ctx->db, p, &insn)) break;
                if (insn.target != 0 &&
                    (insn.flow == FLOW_CALL || insn.flow == FLOW_UNCONDITIONAL_BR)) {
                    uint32_t t = insn.target;
                    int resolved = fn_contains_address(n, t) || fn_is_within_bounds(n, t) ||
                                   fg_is_entry_point(g, t) || fg_is_import(g, t) ||
                                   fg_get_containing(g, t) != NULL;
                    if (!resolved)
                        errors_add(&ctx->errors, ERR_UNRESOLVED_CALL, t, p,
                                   "%s target not in any function",
                                   insn.flow == FLOW_CALL ? "call" : "jmp");
                }
                uint32_t np = di_end(&insn);
                if (np <= p) break;
                p = np;
            }
        }
    }
    return ctx->errors.items.len == 0;
}

/*=========================================================================
 * Pipeline
 *=======================================================================*/

static double now_s(void) { return (double)clock() / CLOCKS_PER_SEC; }
#define TIMED(label, expr) do { double _t = now_s(); expr; \
    fprintf(stderr, "  [phase] %-9s %.1fs  (functions=%zu)\n", label, now_s() - _t, fg_count(&ctx->graph)); } while (0)

int analysis_pipeline_run(CodegenContext* ctx) {
    TIMED("register", phase_register(ctx));
    TIMED("scan",     phase_scan(ctx));
    TIMED("discover", phase_discover(ctx));
    TIMED("gapfill",  phase_gapfill(ctx));
    TIMED("merge",    phase_merge(ctx));
    int clean;
    TIMED("validate", clean = phase_validate(ctx));
    return clean;
}
