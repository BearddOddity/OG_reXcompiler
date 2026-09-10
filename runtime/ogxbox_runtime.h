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

#define XBOX_PTR(addr) ((void*)(g_guest_ram + (uint32_t)(addr)))

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

    /* x87 top-of-stack scratch for the few float ops the emitter lowers. */
    double st[8];
    uint8_t fpu_top;
} RecompCtx;

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

/* fs:/gs: segment-relative access. On the Xbox fs points at the thread block;
 * a port wires this to its TIB emulation. Default: treat as flat. */
static inline uint32_t rex_seg(int seg, uint32_t off) { (void)seg; return off; }
#define FS 0
#define GS 1

static inline uint32_t rex_mask(int w) { return w == 32 ? 0xFFFFFFFFu : ((1u << w) - 1u); }

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

/* Indirect call/jump dispatch — resolves a guest address to a generated fn. */
void rex_dispatch(RecompCtx* c, uint32_t target);

#ifdef __cplusplus
}
#endif
#endif /* OGXBOX_RUNTIME_H */
