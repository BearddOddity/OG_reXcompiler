/*
 * ogxbox_trace.c — guest call-stack ring, active only under -DREX_TRACE.
 *
 * The recompiler drives HLE growth: run the title, see which guest address an
 * unresolved call wanted, implement that, repeat. rex_backtrace() answers
 * "where did the game want to go, and how did it get here".
 */
#include "ogxbox_runtime.h"

#ifdef REX_TRACE
#include <stdio.h>

#define REX_TRACE_DEPTH 256

static _Thread_local uint32_t t_stack[REX_TRACE_DEPTH];
static _Thread_local int      t_top;   /* next free slot */

void rex_enter(uint32_t guest_addr) {
    if (t_top < REX_TRACE_DEPTH) t_stack[t_top] = guest_addr;
    t_top++;
}

void rex_leave(void) {
    if (t_top > 0) t_top--;
}

/* recomp_dispatch.c — RexDispatchEntry is in ogxbox_runtime.h */
extern const RexDispatchEntry g_rex_dispatch[];
extern const unsigned int     g_rex_dispatch_count;

static int is_known(uint32_t a) {
    unsigned int lo = 0, hi = g_rex_dispatch_count;
    while (lo < hi) { unsigned int m = (lo + hi) >> 1;
        if (g_rex_dispatch[m].addr < a) lo = m + 1; else hi = m; }
    return lo < g_rex_dispatch_count && g_rex_dispatch[lo].addr == a;
}

void rex_backtrace(void) {
    fprintf(stderr, "[ogxbox] guest backtrace (%d frames, newest first):\n", t_top);
    int shown = 0;
    for (int i = t_top - 1; i >= 0 && shown < 32; i--, shown++) {
        if (i >= REX_TRACE_DEPTH) continue;
        uint32_t a = t_stack[i];
        fprintf(stderr, "  #%-2d sub_%08X%s\n", shown, a, is_known(a) ? "" : "  (?)");
    }
    if (t_top > 32) fprintf(stderr, "  ... %d more\n", t_top - 32);
}
#endif /* REX_TRACE */
