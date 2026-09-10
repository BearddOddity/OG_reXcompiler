/*
 * ogxbox_kernel.c — starter HLE for the xboxkrnl imports a title hits earliest.
 *
 * Overrides the weak stubs in generated recomp_imports.c. Enough to get a title
 * through CRT + engine init and into its main loop. A real port replaces this
 * with a proper object table / scheduler / VFS (much of which exists as C in
 * the X-Men recomp repo).
 *
 * Calling convention: the emitter lowers `call __imp__X` to `__imp__X(c)` with
 * NO pushed return address, so the guest stack top IS arg 1. A __stdcall HLE
 * reads args from [esp], [esp+4], ... and pops 4*argc; __cdecl/varargs leave
 * the pop to the generated caller. Return value -> eax.
 */
#include "ogxbox_runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

void rex_dispatch(RecompCtx* c, uint32_t target);

static uint32_t arg(RecompCtx* c, int n) { return MEM32(c->esp + 4u * (uint32_t)(n - 1)); }
static void ret_stdcall(RecompCtx* c, uint32_t eax, int argc) { c->eax = eax; c->esp += 4u * (uint32_t)argc; }
static void wr32(uint32_t p, uint32_t v) { if (p) MEM32(p) = v; }

/* --- pool / heap: a single bump allocator over the top of guest RAM ------ */
static uint32_t g_pool_next, g_pool_end;
static CRITICAL_SECTION g_pool_lock;
static void pool_init(void) {
    InitializeCriticalSection(&g_pool_lock);
    g_pool_end  = g_guest_ram_size - (1u << 20);   /* leave 1 MB headroom */
    g_pool_next = g_pool_end - (16u << 20);         /* 16 MB pool */
}
static uint32_t pool_alloc(uint32_t size) {
    if (!g_pool_end) pool_init();
    EnterCriticalSection(&g_pool_lock);
    size = (size + 15u) & ~15u;
    uint32_t p = (g_pool_next + size <= g_pool_end) ? g_pool_next : 0;
    if (p) { g_pool_next += size; }
    LeaveCriticalSection(&g_pool_lock);
    return p;
}

/* --- memory ------------------------------------------------------------- */
void __imp__ExAllocatePool(RecompCtx* c)             { ret_stdcall(c, pool_alloc(arg(c,1)), 1); }
void __imp__ExAllocatePoolWithTag(RecompCtx* c)      { ret_stdcall(c, pool_alloc(arg(c,1)), 2); }
void __imp__ExFreePool(RecompCtx* c)                 { ret_stdcall(c, 0, 1); }
void __imp__MmAllocateContiguousMemory(RecompCtx* c) { ret_stdcall(c, pool_alloc(arg(c,1)), 1); }
void __imp__MmAllocateContiguousMemoryEx(RecompCtx* c){ ret_stdcall(c, pool_alloc(arg(c,1)), 5); }
void __imp__MmFreeContiguousMemory(RecompCtx* c)     { ret_stdcall(c, 0, 1); }
void __imp__MmPersistContiguousMemory(RecompCtx* c)  { ret_stdcall(c, 0, 2); }
void __imp__MmQueryAllocationSize(RecompCtx* c)      { ret_stdcall(c, 0x10000, 1); }
void __imp__MmGetPhysicalAddress(RecompCtx* c)       { ret_stdcall(c, arg(c,1), 1); }

/* NtAllocateVirtualMemory(&base, &size, type, protect) — honour the requested
 * base if any, else hand back a fresh pool block. */
void __imp__NtAllocateVirtualMemory(RecompCtx* c) {
    uint32_t pbase = arg(c,1), psize = arg(c,2);
    uint32_t want = pbase ? MEM32(pbase) : 0;
    uint32_t size = psize ? MEM32(psize) : 0x1000;
    uint32_t got  = want ? want : pool_alloc(size);
    wr32(pbase, got);
    ret_stdcall(c, 0 /* STATUS_SUCCESS */, 4);
}
void __imp__NtFreeVirtualMemory(RecompCtx* c)        { ret_stdcall(c, 0, 4); }

/* RtlAllocateHeap / RtlFreeHeap / RtlReAllocateHeap / RtlSizeHeap */
void __imp__RtlCreateHeap(RecompCtx* c)   { ret_stdcall(c, 0x00010000, 6); }  /* fake handle */
void __imp__RtlAllocateHeap(RecompCtx* c) {
    uint32_t flags = arg(c,2), size = arg(c,3);
    uint32_t p = pool_alloc(size);
    if (p && (flags & 8 /* HEAP_ZERO_MEMORY */)) memset(XBOX_PTR(p), 0, size);
    ret_stdcall(c, p, 3);
}
void __imp__RtlFreeHeap(RecompCtx* c)     { ret_stdcall(c, 1, 3); }
void __imp__RtlReAllocateHeap(RecompCtx* c){ ret_stdcall(c, pool_alloc(arg(c,4)), 4); }
void __imp__RtlSizeHeap(RecompCtx* c)     { ret_stdcall(c, 0x10000, 3); }

/* --- strings / misc RTL --------------------------------------------------- */
void __imp__RtlInitAnsiString(RecompCtx* c)    { ret_stdcall(c, 0, 2); }
void __imp__RtlInitUnicodeString(RecompCtx* c) { ret_stdcall(c, 0, 2); }
void __imp__RtlEnterCriticalSection(RecompCtx* c) { ret_stdcall(c, 0, 1); }
void __imp__RtlLeaveCriticalSection(RecompCtx* c) { ret_stdcall(c, 0, 1); }
void __imp__RtlInitializeCriticalSection(RecompCtx* c) { ret_stdcall(c, 0, 1); }
void __imp__RtlTryEnterCriticalSection(RecompCtx* c) { ret_stdcall(c, 1, 1); }

/* --- debug / bugcheck -------------------------------------------------- */
static void guest_string(uint32_t p) {
    for (int i = 0; i < 512; i++) { char ch = (char)MEM8(p + i); if (!ch) break; fputc(ch, stderr); }
}
void __imp__DbgPrint(RecompCtx* c) { fputs("[guest] ", stderr); guest_string(arg(c,1)); fputc('\n', stderr); c->eax = 0; }
void __imp__KeBugCheck(RecompCtx* c)    { fprintf(stderr, "[ogxbox] KeBugCheck 0x%X\n", arg(c,1)); exit(2); }
void __imp__KeBugCheckEx(RecompCtx* c)  { fprintf(stderr, "[ogxbox] KeBugCheckEx 0x%X\n", arg(c,1)); exit(2); }
void __imp__HalReturnToFirmware(RecompCtx* c) { fprintf(stderr, "[ogxbox] HalReturnToFirmware(%u)\n", arg(c,1)); exit(0); }
void __imp__RtlRaiseException(RecompCtx* c)   { fprintf(stderr, "[ogxbox] RtlRaiseException\n"); exit(3); }

/* --- time / scheduling ---------------------------------------------------- */
void __imp__KeQueryPerformanceCounter(RecompCtx* c) {
    LARGE_INTEGER li; QueryPerformanceCounter(&li);
    c->eax = (uint32_t)li.QuadPart; c->edx = (uint32_t)(li.QuadPart >> 32);
    /* returns LARGE_INTEGER by value in edx:eax — no stack args */
}
void __imp__KeQueryPerformanceFrequency(RecompCtx* c) {
    LARGE_INTEGER li; QueryPerformanceFrequency(&li);
    c->eax = (uint32_t)li.QuadPart; c->edx = (uint32_t)(li.QuadPart >> 32);
}
void __imp__KeQuerySystemTime(RecompCtx* c) {
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    uint32_t out = arg(c,1); if (out) { MEM32(out) = (uint32_t)t; MEM32(out+4) = (uint32_t)(t>>32); }
    ret_stdcall(c, 0, 1);
}
void __imp__KeDelayExecutionThread(RecompCtx* c) { Sleep(1); ret_stdcall(c, 0, 3); }
void __imp__NtYieldExecution(RecompCtx* c)       { SwitchToThread(); c->eax = 0; }

/* --- threads ----------------------------------------------------------- */
typedef struct { uint32_t start_routine, start_context, esp; } GuestThreadArg;

static DWORD WINAPI guest_thread_trampoline(LPVOID p) {
    GuestThreadArg a = *(GuestThreadArg*)p;
    free(p);
    RecompCtx ctx; memset(&ctx, 0, sizeof ctx);
    ctx.esp = a.esp;
    ctx.fpu_cw = 0x037F;
    /* push start_context as the routine's single arg, then dispatch */
    PUSH32(&ctx, a.start_context);
    rex_dispatch(&ctx, a.start_routine);
    return ctx.eax;
}

/* PsCreateSystemThreadEx(&handle, extSize, kStack, tlsSize, &tid, start,
 *                        context, suspended, dbgThread, systemRoutine) */
void __imp__PsCreateSystemThreadEx(RecompCtx* c) {
    uint32_t phandle = arg(c,1), ptid = arg(c,5);
    uint32_t start   = arg(c,6), context = arg(c,7);

    uint32_t stack_bytes = 0x40000;                 /* 256 KB guest stack */
    uint32_t stack_base  = pool_alloc(stack_bytes);
    GuestThreadArg* ga = (GuestThreadArg*)malloc(sizeof *ga);
    ga->start_routine = start; ga->start_context = context;
    ga->esp = stack_base + stack_bytes - 0x20;

    DWORD tid = 0;
    HANDLE h = CreateThread(NULL, 0, guest_thread_trampoline, ga, 0, &tid);
    wr32(phandle, (uint32_t)(uintptr_t)h);
    wr32(ptid, tid);
    ret_stdcall(c, h ? 0 : 0xC0000001u, 10);
}
void __imp__PsTerminateSystemThread(RecompCtx* c) { ExitThread(arg(c,1)); }

void __imp__NtClose(RecompCtx* c) {
    uint32_t h = arg(c,1);
    if (h > 0x10000) CloseHandle((HANDLE)(uintptr_t)h);
    ret_stdcall(c, 0, 1);
}

/* Events / semaphores — thin Win32 wrappers keyed by the guest's dispatcher
 * object address (good enough for one-title bring-up). */
void __imp__NtCreateEvent(RecompCtx* c) {
    uint32_t phandle = arg(c,1);
    HANDLE h = CreateEventA(NULL, arg(c,4) == 0 /* NotificationEvent */, 0, NULL);
    wr32(phandle, (uint32_t)(uintptr_t)h);
    ret_stdcall(c, 0, 5);
}
void __imp__NtSetEvent(RecompCtx* c)   { HANDLE h=(HANDLE)(uintptr_t)arg(c,1); if(h)SetEvent(h);   ret_stdcall(c, 0, 2); }
void __imp__NtClearEvent(RecompCtx* c) { HANDLE h=(HANDLE)(uintptr_t)arg(c,1); if(h)ResetEvent(h); ret_stdcall(c, 0, 1); }
void __imp__NtWaitForSingleObject(RecompCtx* c) {
    HANDLE h=(HANDLE)(uintptr_t)arg(c,1);
    if (h) WaitForSingleObject(h, 50);
    ret_stdcall(c, 0, 3);
}

/* --- XAPI process init ------------------------------------------------- */
void __imp__XapiInitProcess(RecompCtx* c) { c->eax = 0; }   /* __cdecl, no args */
