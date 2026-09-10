/*
 * xmen-legends-hooks.c — native replacements for guest functions the
 * recompiler can't lift faithfully. Copied to <out>/recomp_hooks.c (config
 * `hook_file`); a strong `sub_X` here wins over the weak REX_FN thunk.
 *
 * The Alchemy subsystem-registry pool bootstrap is a deep chain of virtual
 * allocators whose internal state the recompilation never reconstructs (see
 * docs/RUNTIME.md, the current-wall memory). Route the thin "alloc N bytes
 * from this pool" / "grow to N" vtable methods straight to the runtime bump
 * allocator so the registry finishes constructing instead of spinning.
 */
#include "ogxbox_runtime.h"
#include <string.h>

uint32_t rex_pool_alloc(uint32_t size);

/* Route the guest CRT heap onto the runtime bump allocator. The real impl
 * (sub_001A0B0C, an SEH-wrapped segregated-freelist allocator reached via
 * sub_003437F3 / sub_00343AD8 / ...) doesn't unwind cleanly — it leaks ebx on
 * an early-return path, which sends sub_00216210 into its switch and skips the
 * registry init. Every block carries a CRT-style 4-byte size header at [ptr-4].
 * free is a no-op (bump allocator); fine for boot. */
static uint32_t rex_heap_block(uint32_t size) {
    if (!size) size = 1u;
    uint32_t blk = rex_pool_alloc(size + 16u);
    if (!blk) return 0u;
    MEM32(blk + 12u) = size;      /* header at (ret - 4) */
    return blk + 16u;
}

/* sub_001A0B0C(heap, flags, size) — the heap-alloc core. stdcall, ret 0xC. */
void sub_001A0B0C(RecompCtx* c) {
    REX_ENTER(0x001A0B0Cu);
    c->eax = rex_heap_block(MEM32(c->esp + 12u));
    c->esp += 4u + 12u;
    REX_LEAVE();
}

/* sub_003437F3 — CRT malloc(size). __cdecl, arg at [esp+4], caller cleans. */
void sub_003437F3(RecompCtx* c) {
    REX_ENTER(0x003437F3u);
    c->eax = rex_heap_block(MEM32(c->esp + 4u));
    c->esp += 4u;
    REX_LEAVE();
}

/* All pool methods land on sub_00211530 via [vtable+0x1ac]; the thin wrappers
 * differ only in argument shape. `size` is [esp+8] in every wrapper. */

/* sub_001EC5E0 — pool alloc(size).  thiscall, ret 4, size at [esp+4]. */
void sub_001EC5E0(RecompCtx* c) {
    REX_ENTER(0x001EC5E0u);
    uint32_t size = MEM32(c->esp + 4u);
    c->eax = rex_pool_alloc(size ? size : 16u);
    c->esp += 4u + 4u;
    REX_LEAVE();
}

/* sub_001EC750 — pool alloc(size), variant that passes -1.  ret 4. */
void sub_001EC750(RecompCtx* c) {
    REX_ENTER(0x001EC750u);
    uint32_t size = MEM32(c->esp + 4u);
    c->eax = rex_pool_alloc(size ? size : 16u);
    c->esp += 4u + 4u;
    REX_LEAVE();
}

/* sub_001EC720 — pool realloc(old, newsize).  ret 8: [esp+4]=old, [esp+8]=newsize. */
void sub_001EC720(RecompCtx* c) {
    REX_ENTER(0x001EC720u);
    uint32_t oldp    = MEM32(c->esp + 4u);
    uint32_t newsize = MEM32(c->esp + 8u);
    uint32_t p = rex_pool_alloc(newsize ? newsize : 16u);
    if (p && oldp && newsize)
        memcpy(XBOX_PTR(p), XBOX_PTR(oldp), newsize);
    c->eax = p;
    c->esp += 4u + 8u;
    REX_LEAVE();
}

/* sub_001E9D10 — append a u32 to a growable array. thiscall: ecx=this,
 * [esp+4]=value; ret 4. Layout: [this]=data, [this+4]=count, [this+8]=capacity.
 * Bypasses the pool-vtable realloc dance the recompilation gets wrong. */
void sub_001E9D10(RecompCtx* c) {
    REX_ENTER(0x001E9D10u);
    uint32_t self  = c->ecx;
    uint32_t value = MEM32(c->esp + 4u);
    uint32_t count = MEM32(self + 4u);
    uint32_t cap   = MEM32(self + 8u);
    uint32_t data  = MEM32(self);
    if (!data || count >= cap) {
        uint32_t ncap = cap ? cap * 2u : 0x40u;
        uint32_t nd   = rex_pool_alloc(ncap * 4u);
        if (data && count) memcpy(XBOX_PTR(nd), XBOX_PTR(data), count * 4u);
        MEM32(self)      = nd;
        MEM32(self + 8u) = ncap;
        data = nd;
    }
    MEM32(data + count * 4u) = value;
    MEM32(self + 4u) = count + 1u;
    c->eax = self;
    c->esp += 4u + 4u;
    REX_LEAVE();
}

/* sub_001F5D60 — registers a type into the [0x5bc538]/[0x5bc53c] type registry.
 * Those singletons are read here before sub_001F6FB0 (later in the same
 * sub_00216210 iteration) creates them — a static-init ordering the
 * recompilation doesn't reproduce. Skip the registration during boot; the
 * type table is rebuilt lazily by the readers when a lookup misses.
 * thiscall-ish: [esp+4]=arg on entry, bare `ret` (caller cleans). */
void sub_001F5D60(RecompCtx* c) {
    REX_ENTER(0x001F5D60u);
    c->esp += 4u;
    REX_LEAVE();
}
