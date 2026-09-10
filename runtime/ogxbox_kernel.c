/*
 * ogxbox_kernel.c — starter HLE for the xboxkrnl imports a title hits earliest.
 *
 * Overrides the weak stubs in generated recomp_imports.c. Enough to get a title
 * through CRT + engine init and into its main loop. A real port replaces this
 * with a proper object table / scheduler / VFS (much of which exists as C in
 * the X-Men recomp repo).
 *
 * Calling convention: the emitter's `call` pushes a return-address slot, so at
 * HLE entry [esp] is the return slot and [esp+4] is arg 1 (see arg()). A
 * __stdcall HLE pops the slot + 4*argc (ret_stdcall); __cdecl/varargs pop only
 * the slot and leave args to the caller (ret_cdecl). Return value -> eax.
 */
#include "ogxbox_runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

void rex_dispatch(RecompCtx* c, uint32_t target);

/* The generated `call` pushes a return-address slot at [esp]; args follow. */
static uint32_t arg(RecompCtx* c, int n) { return MEM32(c->esp + 4u + 4u * (uint32_t)(n - 1)); }
/* __stdcall HLE: pop the return slot + argc arg dwords. */
static void ret_stdcall(RecompCtx* c, uint32_t eax, int argc) { c->eax = eax; c->esp += 4u + 4u * (uint32_t)argc; }
/* __cdecl / varargs HLE: pop only the return slot; caller cleans its args. */
static void ret_cdecl(RecompCtx* c, uint32_t eax) { c->eax = eax; c->esp += 4u; }
static void wr32(uint32_t p, uint32_t v) { if (p) MEM32(p) = v; }

/* --- pool / heap: one bump allocator, shared with the vendored kernel -----
 * Guest map: sections 0x10000-~0x600000, kernel data 0x700000, TIB
 * 0x740000-0x780000, [ THIS POOL 0x800000-0x2E00000 ], free, guest stack
 * grows down from ~0x3700000. */
#define REX_POOL_BASE  0x00800000u
#define REX_POOL_END   0x02E00000u
static uint32_t g_pool_next, g_pool_end;
static uint32_t g_pool_hi;
static CRITICAL_SECTION g_pool_lock;
static void pool_init(void) {
    InitializeCriticalSection(&g_pool_lock);
    g_pool_next = REX_POOL_BASE;
    g_pool_end  = REX_POOL_END;
}
uint32_t rex_pool_alloc(uint32_t size) { return rex_pool_alloc_aligned(size, 16u); }
uint32_t rex_pool_alloc_aligned(uint32_t size, uint32_t align) {
    if (!g_pool_end) pool_init();
    if (align < 16u) align = 16u;
    EnterCriticalSection(&g_pool_lock);
    uint32_t base = (g_pool_next + (align - 1u)) & ~(align - 1u);
    size = (size + 15u) & ~15u;
    uint32_t p = (base + size <= g_pool_end) ? base : 0;
    if (p) { g_pool_next = p + size; if (g_pool_next > g_pool_hi) g_pool_hi = g_pool_next; }
    LeaveCriticalSection(&g_pool_lock);
    return p;
}
uint32_t rex_pool_highwater(void) { return g_pool_hi; }
static uint32_t pool_alloc(uint32_t size) { return rex_pool_alloc(size); }

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
void __imp__DbgPrint(RecompCtx* c) { fputs("[guest] ", stderr); guest_string(arg(c,1)); fputc('\n', stderr); ret_cdecl(c, 0); }
void __imp__KeBugCheck(RecompCtx* c)    { fprintf(stderr, "[ogxbox] KeBugCheck 0x%X\n", arg(c,1)); exit(2); }
void __imp__KeBugCheckEx(RecompCtx* c)  { fprintf(stderr, "[ogxbox] KeBugCheckEx 0x%X\n", arg(c,1)); exit(2); }
void __imp__HalReturnToFirmware(RecompCtx* c) { fprintf(stderr, "[ogxbox] HalReturnToFirmware(%u)\n", arg(c,1)); exit(0); }
void __imp__RtlRaiseException(RecompCtx* c)   { fprintf(stderr, "[ogxbox] RtlRaiseException\n"); exit(3); }

/* --- time / scheduling ---------------------------------------------------- */
void __imp__KeQueryPerformanceCounter(RecompCtx* c) {
    LARGE_INTEGER li; QueryPerformanceCounter(&li);
    c->eax = (uint32_t)li.QuadPart; c->edx = (uint32_t)(li.QuadPart >> 32);
    c->esp += 4u;  /* stdcall, 0 args: pop the return slot */
}
void __imp__KeQueryPerformanceFrequency(RecompCtx* c) {
    LARGE_INTEGER li; QueryPerformanceFrequency(&li);
    c->eax = (uint32_t)li.QuadPart; c->edx = (uint32_t)(li.QuadPart >> 32);
    c->esp += 4u;
}
void __imp__KeQuerySystemTime(RecompCtx* c) {
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    uint32_t out = arg(c,1); if (out) { MEM32(out) = (uint32_t)t; MEM32(out+4) = (uint32_t)(t>>32); }
    ret_stdcall(c, 0, 1);
}
void __imp__KeDelayExecutionThread(RecompCtx* c) { Sleep(1); ret_stdcall(c, 0, 3); }
void __imp__NtYieldExecution(RecompCtx* c)       { SwitchToThread(); ret_stdcall(c, 0, 0); }

/* --- threads ----------------------------------------------------------- */
typedef struct { uint32_t entry, a0, a1, nargs, esp; } GuestThreadArg;

int rex_has_fn(uint32_t addr);   /* ogxbox_runtime.c */

static DWORD WINAPI guest_thread_trampoline(LPVOID p) {
    GuestThreadArg a = *(GuestThreadArg*)p;
    free(p);
    RecompCtx ctx; memset(&ctx, 0, sizeof ctx);
    ctx.esp = a.esp;
    ctx.fpu_cw = 0x037F;
    rex_set_fs_base(0x00770000u);   /* shared TIB — per-thread when real threads land */
    /* push args right-to-left, then a return-address slot — the generated
     * entry reads its args at [esp+4] like any function our `call` reaches. */
    if (a.nargs >= 2) PUSH32(&ctx, a.a1);
    if (a.nargs >= 1) PUSH32(&ctx, a.a0);
    PUSH32(&ctx, 0);
    rex_dispatch_guarded(&ctx, a.entry);
    return ctx.eax;
}

/* NTSTATUS PsCreateSystemThreadEx(PHANDLE ThreadHandle, ULONG ThreadExtraSize,
 *   ULONG KernelStackSize, ULONG TlsDataSize, PULONG ThreadId,
 *   PKSTART_ROUTINE StartRoutine, PVOID StartContext, BOOLEAN CreateSuspended,
 *   BOOLEAN DebugStack, PKSYSTEM_ROUTINE SystemRoutine)
 *
 * On Xbox the kernel enters SystemRoutine(StartRoutine, StartContext); the
 * SystemRoutine (usually the title's XapiThreadStartup) then calls
 * StartRoutine(StartContext). If SystemRoutine is absent or not in our
 * dispatch table, enter StartRoutine(StartContext) directly. */
void __imp__PsCreateSystemThreadEx(RecompCtx* c) {
    uint32_t phandle = arg(c,1), ptid = arg(c,5);
    uint32_t start_routine = arg(c,6), start_context = arg(c,7);
    uint32_t system_routine = arg(c,10);
    fprintf(stderr, "[ogxbox] PsCreateSystemThreadEx args:");
    for (int i = 1; i <= 10; i++) fprintf(stderr, " [%d]=0x%08X", i, arg(c,i));
    fprintf(stderr, "\n");
    fprintf(stderr, "[ogxbox] PsCreateSystemThreadEx: StartRoutine=0x%08X "
            "StartContext=0x%08X SystemRoutine=0x%08X\n",
            start_routine, start_context, system_routine);

    GuestThreadArg* ga = (GuestThreadArg*)malloc(sizeof *ga);
    if (system_routine && rex_has_fn(system_routine)) {
        ga->entry = system_routine; ga->a0 = start_routine; ga->a1 = start_context; ga->nargs = 2;
    } else if (start_routine && rex_has_fn(start_routine)) {
        ga->entry = start_routine; ga->a0 = start_context; ga->a1 = 0; ga->nargs = 1;
    } else {
        fprintf(stderr, "[ogxbox] PsCreateSystemThreadEx: neither routine is in "
                        "the dispatch table; skipping thread\n");
        rex_backtrace();
        free(ga);
        wr32(phandle, 0);
        ret_stdcall(c, 0xC0000001u, 10);
        return;
    }

    uint32_t stack_bytes = 0x40000;                 /* 256 KB guest stack */
    uint32_t stack_base  = pool_alloc(stack_bytes);
    ga->esp = stack_base + stack_bytes - 0x20;

    DWORD tid = 0;
    HANDLE h = CreateThread(NULL, 0, guest_thread_trampoline, ga, 0, &tid);
    fprintf(stderr, "[ogxbox] thread: entry=0x%08X -> tid %lu\n", ga->entry, tid);
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

/* --- DPC / timer / HAL (init-time, mostly no-ops) --------------------- */
void __imp__KeInitializeDpc(RecompCtx* c) {          /* (dpc, routine, context) */
    uint32_t dpc = arg(c,1);
    if (dpc) { memset(XBOX_PTR(dpc), 0, 32); MEM16(dpc) = 0x13;
               MEM32(dpc+12) = arg(c,2); MEM32(dpc+16) = arg(c,3); }
    ret_stdcall(c, 0, 3);
}
void __imp__KeInitializeTimerEx(RecompCtx* c) {      /* (timer, type) */
    uint32_t t = arg(c,1);
    if (t) { memset(XBOX_PTR(t), 0, 40); MEM16(t) = (uint16_t)(0x08 + (arg(c,2) & 1)); }
    ret_stdcall(c, 0, 2);
}
void __imp__KeSetTimer(RecompCtx* c)   { ret_stdcall(c, 0, 4); }   /* FALSE = not previously set */
void __imp__KeCancelTimer(RecompCtx* c){ ret_stdcall(c, 0, 1); }
void __imp__HalRegisterShutdownNotification(RecompCtx* c) { ret_stdcall(c, 0, 2); }
void __imp__RtlNtStatusToDosError(RecompCtx* c) {
    uint32_t s = arg(c,1), e;
    switch (s) { case 0: e = 0; break; case 0xC0000034u: e = 2; break;
                 case 0xC000003Au: e = 3; break; case 0xC0000022u: e = 5; break;
                 case 0xC0000008u: e = 6; break; case 0xC000000Du: e = 87; break;
                 default: e = 317; }
    ret_stdcall(c, e, 1);
}
/* ExQueryNonVolatileSetting(ValueIndex, Type*, Value*, Length, ResultLength*)
 * EEPROM settings. Hand back zeros (English, NTSC, default clock) so the
 * engine takes its defaults. */
void __imp__ExQueryNonVolatileSetting(RecompCtx* c) {
    uint32_t ptype = arg(c,2), pval = arg(c,3), presult = arg(c,5);
    if (ptype) MEM32(ptype) = 4;   /* REG_DWORD */
    if (pval)  MEM32(pval) = 0;
    if (presult) MEM32(presult) = 4;
    ret_stdcall(c, 0, 5);
}

/* --- files: stubbed until the VFS lands (Phase B) --------------------- */
void __imp__NtOpenFile(RecompCtx* c)  { wr32(arg(c,1), 0); ret_stdcall(c, 0xC0000034u /* NAME_NOT_FOUND */, 6); }
void __imp__NtCreateFile(RecompCtx* c){ wr32(arg(c,1), 0); ret_stdcall(c, 0xC0000034u, 11); }
void __imp__NtReadFile(RecompCtx* c)  { ret_stdcall(c, 0xC0000011u /* END_OF_FILE */, 8); }
void __imp__NtWriteFile(RecompCtx* c) { ret_stdcall(c, 0, 8); }
void __imp__NtQueryVolumeInformationFile(RecompCtx* c) { ret_stdcall(c, 0xC0000034u, 5); }
void __imp__NtQueryInformationFile(RecompCtx* c)       { ret_stdcall(c, 0xC0000034u, 5); }
void __imp__NtQueryFullAttributesFile(RecompCtx* c)    { ret_stdcall(c, 0xC0000034u, 2); }
void __imp__NtQueryDirectoryFile(RecompCtx* c)         { ret_stdcall(c, 0xC0000034u, 10); }
void __imp__NtSetInformationFile(RecompCtx* c)         { ret_stdcall(c, 0, 5); }
void __imp__NtDeviceIoControlFile(RecompCtx* c)        { ret_stdcall(c, 0xC0000034u, 10); }
void __imp__NtFsControlFile(RecompCtx* c)              { ret_stdcall(c, 0xC0000034u, 10); }
void __imp__NtDeleteFile(RecompCtx* c)                 { ret_stdcall(c, 0xC0000034u, 1); }
void __imp__NtFlushBuffersFile(RecompCtx* c)           { ret_stdcall(c, 0, 2); }
void __imp__IoCreateFile(RecompCtx* c)                 { wr32(arg(c,1), 0); ret_stdcall(c, 0xC0000034u, 10); }

/* --- object / symbolic link ------------------------------------------- */
/* NtOpenSymbolicLinkObject(PHANDLE, POBJECT_ATTRIBUTES) — the game resolves
 * device paths (\Device\CdRom0, \Device\Harddisk0\Partition1, ...) this way
 * during drive mounting. Hand back a fake handle; the query below answers it. */
void __imp__NtOpenSymbolicLinkObject(RecompCtx* c) {
    uint32_t phandle = arg(c,1);
    wr32(phandle, 0x5B10D000u | (arg(c,2) & 0xFFFu));   /* fake, carries a tag */
    ret_stdcall(c, 0 /* STATUS_SUCCESS */, 2);
}
/* NtQuerySymbolicLinkObject(HANDLE, PSTRING LinkTarget, PULONG ReturnedLength)
 * Write an empty target — enough for the mount logic to proceed without a
 * real device tree (the VFS layer, Phase B, replaces this). */
void __imp__NtQuerySymbolicLinkObject(RecompCtx* c) {
    uint32_t pstr = arg(c,2), plen = arg(c,3);
    if (pstr) {
        MEM16(pstr + 0) = 0;          /* Length */
        /* leave MaximumLength / Buffer as the caller set them */
    }
    wr32(plen, 0);
    ret_stdcall(c, 0, 3);
}

/* --- XAPI process init ------------------------------------------------- */
void __imp__XapiInitProcess(RecompCtx* c) { ret_cdecl(c, 0); }   /* __cdecl, no args */
