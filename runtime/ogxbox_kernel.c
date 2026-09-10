/*
 * ogxbox_kernel.c — starter HLE for the xboxkrnl imports a title hits earliest.
 *
 * These override the weak stubs in the generated recomp_imports.c (link this
 * file before, or without, recomp_imports.c). A real port grows this into a
 * full kernel layer (object table, thread scheduler, VFS, ...).
 *
 * Calling convention: the emitter lowers `call __imp__X` to a plain `__imp__X(c)`
 * with no pushed return address, so the guest stack top IS the first argument.
 * A __stdcall HLE reads args from [esp], [esp+4], ... and pops 4*argc on the way
 * out; __cdecl leaves the pop to the (generated) caller. Return value -> eax.
 *
 * ReXGlue does this with a HostToGuestFunction<> template + an .inc export
 * table; here it is spelled out so a port can see the shape.
 */
#include "ogxbox_runtime.h"
#include <stdio.h>
#include <stdlib.h>

/* Nth dword argument, 1-based. */
static uint32_t arg(RecompCtx* c, int n) { return MEM32(c->esp + 4u * (uint32_t)(n - 1)); }
static void ret_stdcall(RecompCtx* c, uint32_t eax, int argc) {
    c->eax = eax;
    c->esp += 4u * (uint32_t)argc;
}

/* --- a bump allocator standing in for the pool / heap ------------------- */
static uint32_t g_pool_next = 0;
static uint32_t g_pool_end = 0;
static void pool_init(void) {
    /* carve the top 8 MB of guest RAM as a pool */
    g_pool_end = g_guest_ram_size;
    g_pool_next = g_pool_end - (8u << 20);
}
static uint32_t pool_alloc(uint32_t size) {
    if (!g_pool_next) pool_init();
    size = (size + 15u) & ~15u;
    if (g_pool_next + size > g_pool_end) return 0;
    uint32_t p = g_pool_next; g_pool_next += size; return p;
}

/* ExAllocatePool(SIZE_T NumberOfBytes) */
void __imp__ExAllocatePool(RecompCtx* c)        { ret_stdcall(c, pool_alloc(arg(c, 1)), 1); }
/* ExAllocatePoolWithTag(SIZE_T, ULONG Tag) */
void __imp__ExAllocatePoolWithTag(RecompCtx* c) { ret_stdcall(c, pool_alloc(arg(c, 1)), 2); }
/* ExFreePool(PVOID) — bump allocator never frees */
void __imp__ExFreePool(RecompCtx* c)            { ret_stdcall(c, 0, 1); }

/* MmAllocateContiguousMemory(SIZE_T NumberOfBytes) */
void __imp__MmAllocateContiguousMemory(RecompCtx* c) { ret_stdcall(c, pool_alloc(arg(c, 1)), 1); }

/* DbgPrint(PCSTR Format, ...) — dump the format string, ignore varargs */
void __imp__DbgPrint(RecompCtx* c) {
    uint32_t p = arg(c, 1);
    fputs("[guest] ", stderr);
    for (int i = 0; i < 512; i++) { char ch = (char)MEM8(p + i); if (!ch) break; fputc(ch, stderr); }
    fputc('\n', stderr);
    c->eax = 0;   /* __cdecl/varargs — caller cleans the stack */
}

/* KeBugCheck / HalReturnToFirmware — halt */
void __imp__KeBugCheck(RecompCtx* c)          { fprintf(stderr, "[ogxbox] KeBugCheck 0x%X\n", arg(c, 1)); exit(2); }
void __imp__HalReturnToFirmware(RecompCtx* c) { fprintf(stderr, "[ogxbox] HalReturnToFirmware\n"); exit(0); }

/* RtlInitAnsiString / RtlInitUnicodeString — no-op enough to not crash */
void __imp__RtlInitAnsiString(RecompCtx* c)    { ret_stdcall(c, 0, 2); }
void __imp__RtlInitUnicodeString(RecompCtx* c) { ret_stdcall(c, 0, 2); }
