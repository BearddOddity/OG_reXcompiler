/*
 * xmen-legends-manual.c — X-Men Legends per-title function overrides.
 *
 * Copied over runtime/recomp_manual.c at emit time (config `manual_file`).
 *
 * The CRT thread-startup path lives in the statically-linked XAPI/CRT and is
 * only ever referenced as a *data value* (the routine pointers handed to
 * PsCreateSystemThreadEx), never as a direct call/jump target — nothing points
 * the scanner at it. The two entry points here are hand-written from the
 * disassembly.
 */
#include "ogxbox_runtime.h"

void rex_dispatch(RecompCtx* c, uint32_t target);

/* Call a generated function. Our `call` convention pushes a return-address
 * slot the callee's `ret` pops, so a manual caller must push one too. */
static void mcall(RecompCtx* c, uint32_t target) {
    PUSH32(c, 0);
    rex_dispatch(c, target);
}

/* __cdecl call with 3 args: push them, then the return slot; the callee's bare
 * `ret` pops the slot, we pop the args. */
static void mcall_cdecl3(RecompCtx* c, uint32_t target, uint32_t a0, uint32_t a1, uint32_t a2) {
    PUSH32(c, a2);
    PUSH32(c, a1);
    PUSH32(c, a0);
    PUSH32(c, 0);
    rex_dispatch(c, target);
    c->esp += 12u;
}

/* 0x0019F196 — CRT _threadstartex (the SystemRoutine passed to
 * PsCreateSystemThreadEx). The original sets up per-thread CRT/TLS state then
 * calls StartRoutine(StartContext); we skip the bookkeeping and just enter it.
 * At entry: [esp]=return slot, [esp+4]=StartRoutine, [esp+8]=StartContext. */
static void title_threadstart(RecompCtx* c) {
    uint32_t start_routine = MEM32(c->esp + 4u);
    uint32_t start_context = MEM32(c->esp + 8u);
    if (rex_has_fn(start_routine)) {
        PUSH32(c, start_context);
        PUSH32(c, 0);
        rex_dispatch(c, start_routine);
        c->esp += 4u;
    }
    c->esp += 4u;
}

/* 0x001A1C23 — the thread main the CRT trampoline calls: a fixed sequence of
 * init calls, then return 0. Replayed from the disassembly. */
static void title_thread_main(RecompCtx* c) {
    mcall(c, 0x001A3639u);
    mcall(c, 0x001A23F3u);
    mcall(c, 0x001A35ACu);
    mcall(c, 0x001A3554u);
    mcall_cdecl3(c, 0x00011E40u, 0, 0, 0);
    mcall_cdecl3(c, 0x001A237Du, 0, 1, 1);
    c->eax = 0;
    c->esp += 4u;
}

const RexDispatchEntry g_rex_manual[] = {
    { 0x0019F196u, title_threadstart },
    { 0x001A1C23u, title_thread_main },
};
const uint32_t g_rex_manual_count = sizeof g_rex_manual / sizeof g_rex_manual[0];
