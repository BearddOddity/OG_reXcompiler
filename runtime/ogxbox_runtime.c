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

uint8_t*  g_guest_ram = 0;
uint32_t  g_guest_ram_size = 0;

/* The generated dispatch table (recomp_dispatch.c). Sorted by guest address. */
typedef struct { uint32_t addr; void (*fn)(RecompCtx*); } RexDispatchEntry;
extern const RexDispatchEntry g_rex_dispatch[];
extern const uint32_t         g_rex_dispatch_count;

void rex_unimplemented(const char* what, uint32_t addr) {
    fprintf(stderr, "[ogxbox] unimplemented '%s' at 0x%08X\n", what, addr);
}

static void (*rex_lookup(uint32_t target))(RecompCtx*) {
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

void rex_dispatch(RecompCtx* c, uint32_t target) {
    void (*fn)(RecompCtx*) = rex_lookup(target);
    if (fn) { fn(c); return; }
    rex_unimplemented("indirect target", target);
}

/* Generated (recomp_image.c). */
extern const unsigned int g_rex_image_base, g_rex_ram_size, g_rex_entry_va, g_rex_initial_esp;
int rex_load_image(const char* bin_path);

/* Allocate guest RAM, map the XBE image, run the entry point. */
int rex_boot(const char* image_bin_path) {
    g_guest_ram = (uint8_t*)calloc(1, g_rex_ram_size);
    if (!g_guest_ram) return -1;
    g_guest_ram_size = g_rex_ram_size;

    int rc = rex_load_image(image_bin_path);
    if (rc != 0) { fprintf(stderr, "[ogxbox] image load failed: %d\n", rc); return rc; }

    void (*entry)(RecompCtx*) = rex_lookup(g_rex_entry_va);
    if (!entry) { fprintf(stderr, "[ogxbox] no generated fn for entry 0x%08X\n", g_rex_entry_va); return -5; }

    RecompCtx ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.esp = g_rex_initial_esp;
    ctx.fpu_cw = 0x037F;

    entry(&ctx);
    return (int)ctx.eax;
}
