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
