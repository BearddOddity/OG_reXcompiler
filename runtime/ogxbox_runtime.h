/*
 * ogxbox_runtime.h — the contract every generated .c file compiles against.
 *
 * Generated functions are `void sub_XXXXXXXX(RecompCtx* c)`. Registers live in
 * the per-call context (no globals — this is the "per-call context struct"
 * model from the start). Guest memory is a flat host allocation; MEM* macros
 * translate. Flags are computed eagerly by the emitter after each flag-setting
 * instruction.
 *
 * This file is a template shipped by the SDK; the recompiler copies it into the
 * output tree. Hand-written parts of a port (kernel HLE, D3D shim) include it.
 */
#ifndef OGXBOX_RUNTIME_H
#define OGXBOX_RUNTIME_H

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Guest physical memory base. Set once at startup. */
extern uint8_t* g_guest_ram;
extern uint32_t g_guest_ram_size;

/* The Xbox memory controller has a 26-bit address bus, so every RAM access
 * wraps modulo 64 MB — code does `base + large_offset` and relies on it. Fold
 * anything below the kernel/MMIO window (0x40000000) into the 64 MB of RAM;
 * leave kernel space (0x80010000 fake xboxkrnl page) untouched. */
#define REX_WRAP(a) (((uint32_t)(a) < 0x40000000u) ? ((uint32_t)(a) & 0x03FFFFFFu) : (uint32_t)(a))
#define XBOX_PTR(addr) ((void*)(g_guest_ram + REX_WRAP(addr)))

#define MEM8(a)   (*(volatile uint8_t*)  XBOX_PTR(a))
#define MEM16(a)  (*(volatile uint16_t*) XBOX_PTR(a))
#define MEM32(a)  (*(volatile uint32_t*) XBOX_PTR(a))
#define SMEM8(a)  (*(volatile int8_t*)   XBOX_PTR(a))
#define SMEM16(a) (*(volatile int16_t*)  XBOX_PTR(a))
#define SMEM32(a) (*(volatile int32_t*)  XBOX_PTR(a))

typedef struct RecompCtx {
    uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi;
    uint32_t eip;               /* only meaningful at indirect-dispatch points */

    /* Eagerly-maintained EFLAGS bits (0/1). */
    uint8_t cf, pf, af, zf, sf, of, df;

    /* x87: a circular register stack + a status word for fcom/fnstsw. */
    double st[8];
    uint8_t fpu_top;
    uint16_t fpu_sw;
    uint16_t fpu_cw;
} RecompCtx;

/* x87 stack access, ST(i) relative to top. */
#define FPU_ST(c, i)   ((c)->st[((c)->fpu_top + (i)) & 7])
#define FPU_PUSH(c, v)  do { (c)->fpu_top = ((c)->fpu_top - 1) & 7; FPU_ST(c, 0) = (double)(v); } while (0)
#define FPU_POP(c)      do { (c)->fpu_top = ((c)->fpu_top + 1) & 7; } while (0)

/* fcom family: set C3/C2/C0 (status-word bits 14/10/8) from an ordered compare. */
static inline void rex_fcom(RecompCtx* c, double a, double b) {
    c->fpu_sw &= (uint16_t)~0x4500u;
    if (a > b)      { /* 000 */ }
    else if (a < b) { c->fpu_sw |= 0x0100u; }              /* C0 */
    else if (a == b){ c->fpu_sw |= 0x4000u; }              /* C3 */
    else            { c->fpu_sw |= 0x4500u; }              /* unordered */
}

/* ---- sub-register access ------------------------------------------------- */
#define LO8(r)   ((uint8_t)((r) & 0xFFu))
#define HI8(r)   ((uint8_t)(((r) >> 8) & 0xFFu))
#define LO16(r)  ((uint16_t)((r) & 0xFFFFu))

#define SET_LO8(r, v)  ((r) = ((r) & 0xFFFFFF00u) | (uint32_t)(uint8_t)(v))
#define SET_HI8(r, v)  ((r) = ((r) & 0xFFFF00FFu) | ((uint32_t)(uint8_t)(v) << 8))
#define SET_LO16(r, v) ((r) = ((r) & 0xFFFF0000u) | (uint32_t)(uint16_t)(v))

/* ---- stack ------------------------------------------------------------- */
#define PUSH32(c, val) do { (c)->esp -= 4; MEM32((c)->esp) = (uint32_t)(val); } while (0)
#define POP32(c, dst)  do { (dst) = MEM32((c)->esp); (c)->esp += 4; } while (0)

/* ---- flag helpers ---------------------------------------------------------
 * The emitter calls these right after an ALU op. `w` is the operand width in
 * bits (8/16/32). Values are the pre-truncation math in 64-bit.
 */
#if defined(_MSC_VER)
static inline int __builtin_parity(unsigned x) { x ^= x >> 16; x ^= x >> 8; x ^= x >> 4; x ^= x >> 2; x ^= x >> 1; return x & 1; }
#endif

/* fs:/gs: segment-relative access. fs points at the per-thread block (TIB);
 * rex_seg adds the calling thread's fs base (set by rex_boot / the thread
 * trampoline via rex_set_fs_base). gs is unused on the Xbox. */
uint32_t rex_seg(int seg, uint32_t off);
void     rex_set_fs_base(uint32_t va);
#define FS 0
#define GS 1

static inline uint32_t rex_mask(int w) { return w == 32 ? 0xFFFFFFFFu : ((1u << w) - 1u); }

/* rdtsc — a monotonically increasing cycle-ish counter for CRT/engine timing. */
#if defined(_MSC_VER)
#include <intrin.h>
static inline uint64_t rex_rdtsc(void) { return __rdtsc(); }
#elif defined(__i386__) || defined(__x86_64__)
static inline uint64_t rex_rdtsc(void) { return __builtin_ia32_rdtsc(); }
#else
static inline uint64_t rex_rdtsc(void) { static uint64_t t; return t += 1000; }
#endif

static inline void rex_flags_logic(RecompCtx* c, uint64_t r, int w) {
    uint32_t m = rex_mask(w); uint32_t v = (uint32_t)(r & m);
    c->cf = 0; c->of = 0;
    c->zf = (v == 0);
    c->sf = (v >> (w - 1)) & 1;
    c->pf = !(__builtin_parity(v & 0xFF));
}
static inline void rex_flags_add(RecompCtx* c, uint64_t a, uint64_t b, uint64_t r, int w) {
    uint32_t m = rex_mask(w); uint32_t v = (uint32_t)(r & m);
    c->cf = (r >> w) & 1;
    c->zf = (v == 0);
    c->sf = (v >> (w - 1)) & 1;
    c->of = (((a ^ r) & (b ^ r)) >> (w - 1)) & 1;
    c->af = ((a ^ b ^ r) >> 4) & 1;
    c->pf = !(__builtin_parity(v & 0xFF));
}
static inline void rex_flags_sub(RecompCtx* c, uint64_t a, uint64_t b, uint64_t r, int w) {
    uint32_t m = rex_mask(w); uint32_t v = (uint32_t)(r & m);
    c->cf = (a & m) < (b & m);
    c->zf = (v == 0);
    c->sf = (v >> (w - 1)) & 1;
    c->of = (((a ^ b) & (a ^ r)) >> (w - 1)) & 1;
    c->af = ((a ^ b ^ r) >> 4) & 1;
    c->pf = !(__builtin_parity(v & 0xFF));
}

/* Marker for an instruction the emitter could not lower. Links, so a port that
 * hits one fails loudly at run time rather than silently doing nothing. */
void rex_unimplemented(const char* what, uint32_t addr);
#define REX_UNIMPLEMENTED(what, addr) rex_unimplemented((what), (addr))

/* Indirect jump/tail dispatch — resolves a guest address to a generated fn. */
void rex_dispatch(RecompCtx* c, uint32_t target);
/* Indirect call — same, but a return slot is already pushed; an unresolved
 * target pops it so the caller's frame stays balanced. */
void rex_icall(RecompCtx* c, uint32_t target);

/* True if a generated (or manually overridden) function exists at addr. */
int rex_has_fn(uint32_t addr);

/* Guest bump allocator (ogxbox_kernel.c) — shared by the HLE and the vendored
 * kernel's xbox_Heap* shims. Returns a guest VA, 0 on exhaustion. */
uint32_t rex_pool_alloc(uint32_t size);
uint32_t rex_pool_alloc_aligned(uint32_t size, uint32_t align);
uint32_t rex_pool_highwater(void);

/* One generated function: guest entry address -> its C function.
 * recomp_manual.c defines g_rex_manual[] of these for hand-written overrides. */
typedef struct { uint32_t addr; void (*fn)(RecompCtx*); } RexDispatchEntry;

/* Boot: alloc guest RAM, map recomp_image.bin, run the XBE entry point.
 * Returns the guest's eax at exit, or a negative error. */
int rex_boot(const char* image_bin_path);

/* Run a guest function under a structured-exception guard that dumps the
 * backtrace on an access violation. Used for the entry point and each thread. */
void rex_run_guarded(void (*fn)(RecompCtx*), RecompCtx* c);
void rex_dispatch_guarded(RecompCtx* c, uint32_t target);

/* --- guest call trace (compile with -DREX_TRACE) -----------------------------
 * Every generated function calls REX_ENTER(its addr) on entry and REX_LEAVE()
 * before each return, maintaining a per-thread ring of guest addresses.
 * rex_backtrace() dumps it (newest first, resolved to sub_XXXXXXXX names) and
 * is called automatically from an unresolved dispatch / unimplemented import.
 */
#ifdef REX_TRACE
void rex_enter(uint32_t guest_addr);
void rex_leave(void);
void rex_backtrace(void);
void rex_call_balance(uint32_t site, uint32_t target,
                      uint32_t sp0, uint32_t sp1, uint32_t bp0, uint32_t bp1);
#define REX_ENTER(a) rex_enter((a))
#define REX_LEAVE()  rex_leave()
#else
#define REX_ENTER(a) ((void)0)
#define REX_LEAVE()  ((void)0)
static inline void rex_backtrace(void) {}
#endif

#ifdef __cplusplus
}
#endif
#endif /* OGXBOX_RUNTIME_H */
