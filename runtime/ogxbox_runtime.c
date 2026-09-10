/*
 * ogxbox_runtime.c — the parts of the generated-code contract that need a
 * definition. Compiled alongside the generated recomp_*.c.
 *
 * A concrete port supplies: the XBE image load into g_guest_ram, real kernel
 * HLE (overriding the weak __imp__* stubs), and its own main() that calls
 * rex_boot().
 */
#include "ogxbox_runtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

uint8_t*  g_guest_ram = 0;
uint32_t  g_guest_ram_size = 0;
ptrdiff_t g_xbox_mem_offset = 0;   /* native = guest_va + this (== (uintptr_t)g_guest_ram) */

void ogxbox_thunkfix_run(void);    /* ogxbox_thunkfix.c */

/* A hard fault in generated code (bad guest pointer) never reaches
 * rex_unimplemented, so catch it here and dump the guest backtrace. */
static LONG WINAPI rex_seh_filter(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_ACCESS_VIOLATION) {
        ULONG_PTR at = ep->ExceptionRecord->ExceptionInformation[1];
        int write = (int)ep->ExceptionRecord->ExceptionInformation[0];
        uint32_t guest = (g_guest_ram && (uint8_t*)at >= g_guest_ram &&
                          (uint8_t*)at < g_guest_ram + 0x100000000ull)
                         ? (uint32_t)((uint8_t*)at - g_guest_ram) : 0xFFFFFFFFu;
        fprintf(stderr, "[ogxbox] ACCESS VIOLATION %s host 0x%p", write ? "write" : "read", (void*)at);
        if (guest != 0xFFFFFFFFu) fprintf(stderr, " (guest 0x%08X)", guest);
        fprintf(stderr, "\n");
        rex_backtrace();
        return EXCEPTION_EXECUTE_HANDLER;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void rex_run_guarded(void (*fn)(RecompCtx*), RecompCtx* c) {
    __try { fn(c); }
    __except (rex_seh_filter(GetExceptionInformation())) {
        fprintf(stderr, "[ogxbox] guest aborted\n");
    }
}

void rex_dispatch(RecompCtx* c, uint32_t target);

void rex_dispatch_guarded(RecompCtx* c, uint32_t target) {
    __try { rex_dispatch(c, target); }
    __except (rex_seh_filter(GetExceptionInformation())) {
        fprintf(stderr, "[ogxbox] guest thread aborted\n");
    }
}

/* The generated dispatch table (recomp_dispatch.c). Sorted by guest address. */
extern const RexDispatchEntry g_rex_dispatch[];   /* RexDispatchEntry: ogxbox_runtime.h */
extern const uint32_t         g_rex_dispatch_count;

/* Per-title hand-written overrides (recomp_manual.c) — checked before the
 * generated table, for functions the scanner can't recover (reachable only as
 * data values, misaligned entries, etc). */
extern const RexDispatchEntry g_rex_manual[];
extern const uint32_t         g_rex_manual_count;

void rex_unimplemented(const char* what, uint32_t addr) {
    fprintf(stderr, "[ogxbox] unimplemented '%s' at 0x%08X\n", what, addr);
    rex_backtrace();
}

static void (*rex_lookup(uint32_t target))(RecompCtx*) {
    for (uint32_t i = 0; i < g_rex_manual_count; i++)
        if (g_rex_manual[i].addr == target) return g_rex_manual[i].fn;
    uint32_t lo = 0, hi = g_rex_dispatch_count;
    while (lo < hi) {
        uint32_t mid = (lo + hi) >> 1;
        if (g_rex_dispatch[mid].addr < target) lo = mid + 1;
        else hi = mid;
    }
    if (lo < g_rex_dispatch_count && g_rex_dispatch[lo].addr == target)
        return g_rex_dispatch[lo].fn;
    return 0;
}

int rex_has_fn(uint32_t addr) { return rex_lookup(addr) != 0; }

void rex_kernel_dispatch(RecompCtx* c, unsigned int ordinal);  /* recomp_kthunks.c */

#ifdef REX_TRACE
/* Stack-balance check on direct guest->guest calls. After `call sub_X`, a
 * correct callee has left esp at _sp0 + N (N = its `ret N` arg bytes, i.e.
 * 0..~64). Anything outside a sane band means the callee (or its subtree)
 * leaked or over-popped the guest stack — the recurring recomp corruption. */
void rex_call_balance(uint32_t site, uint32_t target,
                      uint32_t sp0, uint32_t sp1, uint32_t bp0, uint32_t bp1) {
    /* _SEH_prolog4 (0x3432A8) / _SEH_epilog4 (0x3432E3) are the SEH frame
     * machinery: the prolog deliberately returns with esp below the call site
     * (it did `sub esp, localsize`), the epilog deliberately returns with esp
     * far above it (it tore the frame down). Neither balances at its own call
     * boundary by design — exempt them from both checks. */
    if (target == 0x003432A8u || target == 0x003432E3u) return;
    int32_t sd = (int32_t)(sp1 - sp0);
    int bad_sp = !(sd >= 0 && sd <= 64);               /* plausible ret N */
    int bad_bp = (bp1 != bp0);
    if (!bad_sp && !bad_bp) return;
    static uint64_t seen[2048]; static int nseen;
    uint64_t key = ((uint64_t)site << 32) | target;
    for (int i = 0; i < nseen; i++) if (seen[i] == key) return;
    if (nseen < 2048) seen[nseen++] = key;
    fprintf(stderr, "[ogxbox] STACK: call 0x%08X -> sub_%08X", site, target);
    if (bad_sp) fprintf(stderr, "  esp %+d (0x%08X->0x%08X)", sd, sp0, sp1);
    if (bad_bp) fprintf(stderr, "  ebp 0x%08X->0x%08X", bp0, bp1);
    fputc('\n', stderr);
}

/* Callee-saved register check across indirect calls (ebx/esi/edi/ebp are
 * callee-saved under cdecl/stdcall/thiscall). A lifted stub that doesn't
 * restore them silently corrupts its caller. Deduped per target. */
static void rex_abi_note(uint32_t target, const char* reg, uint32_t before, uint32_t after) {
    static uint32_t seen[512]; static int nseen;
    for (int i = 0; i < nseen; i++) if (seen[i] == target) return;
    if (nseen < 512) seen[nseen++] = target;
    fprintf(stderr, "[ogxbox] ABI: icall 0x%08X did not restore %s (0x%08X -> 0x%08X)\n",
            target, reg, before, after);
}
#endif

static void rex_dispatch_fn(RecompCtx* c, uint32_t target, void (*fn)(RecompCtx*)) {
#ifdef REX_TRACE
    uint32_t b = c->ebx, s = c->esi, d = c->edi, p = c->ebp;
    fn(c);
    if (c->ebx != b) rex_abi_note(target, "ebx", b, c->ebx);
    if (c->esi != s) rex_abi_note(target, "esi", s, c->esi);
    if (c->edi != d) rex_abi_note(target, "edi", d, c->edi);
    if (c->ebp != p) rex_abi_note(target, "ebp", p, c->ebp);
#else
    (void)target;
    fn(c);
#endif
}

/* Indirect CALL through a corrupt/uninitialised function pointer. The emitter
 * has already pushed a guest return-address slot; unwind past it so the call
 * site's frame stays balanced (a resolved callee's `ret` would have popped
 * it). Stack args a stdcall callee would also have popped still leak, but a
 * 4-byte slip is recoverable where an 8+-byte one corrupts the caller. */
void rex_icall(RecompCtx* c, uint32_t target) {
    if (target & 0x80000000u) { rex_kernel_dispatch(c, target & 0x7FFFFFFFu); return; }
    void (*fn)(RecompCtx*) = rex_lookup(target);
    if (fn) { rex_dispatch_fn(c, target, fn); return; }
    rex_unimplemented("indirect call", target);
    c->eax = 0;
    c->esp += 4u;   /* pop the return slot */
}

void rex_dispatch(RecompCtx* c, uint32_t target) {
    /* An unfixed-up kernel thunk still holds 0x80000000 | ordinal. */
    if (target & 0x80000000u) { rex_kernel_dispatch(c, target & 0x7FFFFFFFu); return; }

    void (*fn)(RecompCtx*) = rex_lookup(target);
    if (!fn) {
        /* Corrupted / uninitialised function pointer. Log and return rather
         * than dispatch to garbage — the caller usually copes (games are
         * resilient), and a hard fault here buries the real cause upstream. */
        rex_unimplemented("indirect target", target);
        c->eax = 0;
        return;
    }
#ifdef REX_TRACE
    uint32_t b = c->ebx, s = c->esi, d = c->edi, p = c->ebp;
    fn(c);
    if (c->ebx != b) rex_abi_note(target, "ebx", b, c->ebx);
    if (c->esi != s) rex_abi_note(target, "esi", s, c->esi);
    if (c->edi != d) rex_abi_note(target, "edi", d, c->edi);
    if (c->ebp != p) rex_abi_note(target, "ebp", p, c->ebp);
#else
    fn(c);
#endif
}

/* fs: base — per thread. The main thread's is set in rex_boot; each guest
 * thread's in the trampoline. */
static _Thread_local uint32_t t_fs_base;
void rex_set_fs_base(uint32_t va) { t_fs_base = va; }
uint32_t rex_seg(int seg, uint32_t off) { return (seg == FS ? t_fs_base : 0u) + off; }

/* Generated (recomp_image.c). */
extern const unsigned int g_rex_image_base, g_rex_ram_size, g_rex_entry_va, g_rex_initial_esp;
int rex_load_image(const char* bin_path);
uint32_t ogxbox_tib_setup(void);       /* ogxbox_tib.c — returns the fs base VA */
void     ogxbox_kernel_page_setup(void);

/* Allocate guest RAM, map the XBE image, run the entry point. */
int rex_boot(const char* image_bin_path) {
    /* Reserve a 2 GB window so kernel-space addresses (0x8001xxxx — the Xbox
     * kernel image RenderWare pokes for cache sizing) land inside it; commit
     * the 64 MB of RAM up front. Guest VA == host offset from the base. */
    const uint32_t KWIN = 0x80020000u;
    g_guest_ram = (uint8_t*)VirtualAlloc(NULL, KWIN, MEM_RESERVE, PAGE_NOACCESS);
    if (!g_guest_ram) return -1;
    /* Commit all 64 MB including the low page: Xbox code legitimately reads
     * KPCR fields near VA 0, and a NULL-derived read should see zero rather
     * than fault (X-Men's layout does the same — a soft write-watch is the
     * right null trap, not PAGE_NOACCESS). */
    if (!VirtualAlloc(g_guest_ram, g_rex_ram_size, MEM_COMMIT, PAGE_READWRITE))
        return -1;
    g_guest_ram_size = g_rex_ram_size;

    int rc = rex_load_image(image_bin_path);
    if (rc != 0) { fprintf(stderr, "[ogxbox] image load failed: %d\n", rc); return rc; }

    /* g_xbox_mem_offset: vendored kernel code translates guest VA -> native as
     * (va + offset); our guest RAM is a flat host buffer, so offset == base. */
    g_xbox_mem_offset = (ptrdiff_t)(uintptr_t)g_guest_ram;

    ogxbox_kernel_page_setup();
    rex_set_fs_base(ogxbox_tib_setup());
    ogxbox_thunkfix_run();

    void (*entry)(RecompCtx*) = rex_lookup(g_rex_entry_va);
    if (!entry) { fprintf(stderr, "[ogxbox] no generated fn for entry 0x%08X\n", g_rex_entry_va); return -5; }

    RecompCtx ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.esp = g_rex_initial_esp;
    ctx.fpu_cw = 0x037F;
    PUSH32(&ctx, 0);   /* return-address slot — the entry reads args at [esp+4] */

    rex_run_guarded(entry, &ctx);
    return (int)ctx.eax;
}
