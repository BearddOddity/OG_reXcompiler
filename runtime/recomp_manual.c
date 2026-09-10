/*
 * recomp_manual.c — hand-written replacements for functions the scanner cannot
 * recover from the XBE.
 *
 * The CRT thread-startup path lives in the statically-linked XAPI/CRT and is
 * only ever referenced as a *data value* (the routine pointers handed to
 * PsCreateSystemThreadEx), never as a direct call/jump target, so nothing in
 * the binary points the scanner at it. The X-Men Legends recomp hit the same
 * wall and hand-wrote these two; this is the same logic in the SDK's
 * RecompCtx* form.
 *
 * These are registered ahead of the generated dispatch table (see
 * rex_lookup / g_rex_manual). Currently X-Men-Legends specific; a real
 * per-title hook file would replace this.
 */
#include "ogxbox_runtime.h"

void rex_dispatch(RecompCtx* c, uint32_t target);

/* Call a generated function. Our `call` convention pushes a return-address
 * slot the callee's `ret` pops, so a manual caller must push one too. */
static void mcall(RecompCtx* c, uint32_t target) {
    PUSH32(c, 0);
    rex_dispatch(c, target);
}

/* __cdecl call: push argc dwords (already in push order, arg0 first here so we
 * reverse), then the return slot; the callee's bare `ret` pops the slot, we
 * pop the args. */
static void mcall_cdecl3(RecompCtx* c, uint32_t target, uint32_t a0, uint32_t a1, uint32_t a2) {
    PUSH32(c, a2);
    PUSH32(c, a1);
    PUSH32(c, a0);
    PUSH32(c, 0);            /* return-address slot */
    rex_dispatch(c, target);
    c->esp += 12u;           /* __cdecl: caller pops the 3 args */
}

/* sub_0019F196 — CRT _threadstartex equivalent (the SystemRoutine passed to
 * PsCreateSystemThreadEx). Original sets up per-thread CRT/TLS state, then
 * calls StartRoutine(StartContext) and PsTerminateSystemThread(result). We
 * skip the CRT bookkeeping our runtime doesn't need and just enter
 * StartRoutine(StartContext); returning normally ends the host thread.
 *
 * At entry (our convention): [esp]=return slot, [esp+4]=StartRoutine (arg1),
 * [esp+8]=StartContext (arg2). */
static void sub_0019F196(RecompCtx* c) {
    uint32_t start_routine  = MEM32(c->esp + 4u);
    uint32_t start_context  = MEM32(c->esp + 8u);
    if (rex_has_fn(start_routine)) {
        PUSH32(c, start_context);
        PUSH32(c, 0);                 /* return-address slot (callee's ret pops it) */
        rex_dispatch(c, start_routine);
        c->esp += 4u;                 /* pop StartContext */
    }
    c->esp += 4u;                     /* pop our own return slot */
}

/* sub_001A1C23 — the thread main the CRT trampoline calls. The X-Men
 * disassembly runs, in order: 0x1A3639, 0x1A23F3, 0x1A35AC, 0x1A3554 (CRT
 * per-thread setup: I/O tables, locale, TLS), 0x11E40(0,0,0),
 * 0x1A237D(0,1,1) (the engine/device init), then return 0.
 *
 * The first four need a populated per-thread TIB (fs:[0x28] chain) that this
 * runtime does not model yet — running them dereferences garbage. Their effect
 * (buffered stdio, C locale) is not something the recompiled title needs from
 * *inside* the guest, so they are skipped until the TIB emulation lands.
 * 0x1A237D is the one that matters and it is a properly detected function. */
static void sub_001A1C23(RecompCtx* c) {
    mcall(c, 0x001A3639u);
    mcall(c, 0x001A23F3u);
    mcall(c, 0x001A35ACu);
    mcall(c, 0x001A3554u);
    mcall_cdecl3(c, 0x00011E40u, 0, 0, 0);
    mcall_cdecl3(c, 0x001A237Du, 0, 1, 1);
    c->eax = 0;
    c->esp += 4u;                     /* pop our own return slot */
}

const RexDispatchEntry g_rex_manual[] = {
    { 0x0019F196u, sub_0019F196 },
    { 0x001A1C23u, sub_001A1C23 },
};
const uint32_t g_rex_manual_count = sizeof g_rex_manual / sizeof g_rex_manual[0];
