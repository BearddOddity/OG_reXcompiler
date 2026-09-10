/**
 * kernel_bridge.c - Bridge between translated game code and kernel functions
 *
 * Problem:
 *   Translated game code calls kernel functions via indirect calls through
 *   the kernel thunk table at VA 0x0036B7C0. In the XBE file, these entries
 *   contain unresolved ordinals (0x80000000 | ordinal). On real Xbox hardware,
 *   the kernel loader replaces these with actual function pointers before the
 *   game runs.
 *
 * Solution:
 *   1. After xbox_MemoryLayoutInit copies .rdata, call xbox_kernel_bridge_init()
 *   2. Replace each ordinal entry in Xbox memory with a synthetic VA
 *   3. When RECOMP_ICALL encounters a synthetic VA, route it to a per-ordinal
 *      bridge function that reads args from the simulated Xbox stack, translates
 *      pointer arguments from Xbox VA→native, and calls the kernel function.
 *
 * Synthetic VA scheme:
 *   Each thunk slot i gets VA 0xFE000000 + i*4
 *   The lookup function checks this range and dispatches appropriately.
 *
 * Why per-ordinal bridges instead of a generic trampoline:
 *   Kernel functions receive Xbox pointers (32-bit VAs) that must be translated
 *   to native pointers by adding g_xbox_mem_offset. Different functions have
 *   different parameter layouts (pointer vs value), so each needs its own bridge.
 */

#include "kernel.h"
#include "xbox_memory_layout.h"
#include <stdio.h>
#include <float.h>

/* Adapted from the X-Men Legends recomp's kernel_bridge.c: the global
 * register file (c->eax/c->esp/...) is replaced by the SDK's per-call
 * RecompCtx* c, threaded through every bridge_* handler. */
#include "ogxbox_runtime.h"
extern ptrdiff_t g_xbox_mem_offset;
typedef void (*recomp_func_t)(RecompCtx*);
static recomp_func_t recomp_lookup(uint32_t va);
static recomp_func_t recomp_lookup_manual(uint32_t va) { return recomp_lookup(va); }

/* Memory access - same as recomp_types.h MEM32 but without the #define guard */
#define BRIDGE_MEM32(addr) (*(volatile uint32_t *)((uintptr_t)(addr) + g_xbox_mem_offset))

/* Translate Xbox VA to native pointer (NULL-safe: 0 → NULL) */
#define XBOX_TO_NATIVE(va) ((va) ? (void*)((uintptr_t)(va) + g_xbox_mem_offset) : NULL)

/*
 * Is this guest value plausibly a writable address?
 *
 * `if (ptr)` is not a pointer check - it only rejects 0. Small integers that
 * are really flags sail through it and get written to. That destroyed the SEH
 * exception-list head: ordinal 47's second argument is the BOOLEAN 1, a
 * mis-wired handler treated it as an output pointer, and the resulting write
 * at Xbox VA 1 turned the chain head from 0xFFFFFFFF into 0x000000FF.
 *
 * The XBE image base is 0x00010000, so nothing below it is ever a valid target,
 * and nothing at or beyond the 64 MB of Xbox RAM is either. Use this in every
 * bridge handler that writes through a guest-supplied pointer.
 */
#define BRIDGE_PTR_OK(va) \
    ((uint32_t)(va) >= 0x00010000u && (uint32_t)(va) < XBOX_TOTAL_RAM)

/* ── Synthetic VA range (for function exports) ─────────── */

#define KERNEL_VA_BASE  0xFE000000u
#define KERNEL_VA_END   (KERNEL_VA_BASE + XBOX_KERNEL_THUNK_TABLE_SIZE * 4)

/* ── Kernel data exports ──────────────────────────────────
 *
 * Some kernel ordinals are DATA exports (structs/variables), not functions.
 * The game reads their thunk entries and dereferences the result to access
 * the data. These cannot use synthetic VAs — they must point to real,
 * dereferenceable addresses in the Xbox VA space.
 *
 * We allocate a "kernel data area" at XBOX_KERNEL_DATA_BASE and populate
 * it with the expected structures.
 */

#define BRIDGE_MEM16(addr) (*(volatile uint16_t *)((uintptr_t)(addr) + g_xbox_mem_offset))
#define BRIDGE_MEM8(addr)  (*(volatile uint8_t  *)((uintptr_t)(addr) + g_xbox_mem_offset))

/**
 * Get the Xbox VA of data for a kernel DATA export ordinal.
 * Returns 0 if the ordinal is not a data export (i.e., it's a function).
 */
static uint32_t kernel_data_va_for_ordinal(ULONG ordinal)
{
    switch (ordinal) {
    case  17: return XBOX_KERNEL_DATA_BASE + KDATA_EVENT_OBJ_TYPE;
    case  65: return XBOX_KERNEL_DATA_BASE + KDATA_IO_COMPLETION_TYPE;
    case  71: return XBOX_KERNEL_DATA_BASE + KDATA_IO_DEVICE_TYPE;
    case 156: return XBOX_KERNEL_DATA_BASE + KDATA_TICK_COUNT;
    case 164: return XBOX_KERNEL_DATA_BASE + KDATA_LAUNCH_DATA_PAGE;
    case 259: return XBOX_KERNEL_DATA_BASE + KDATA_THREAD_OBJ_TYPE;
    case 322: return XBOX_KERNEL_DATA_BASE + KDATA_HARDWARE_INFO;
    case 323: return XBOX_KERNEL_DATA_BASE + KDATA_HD_KEY;
    case 324: return XBOX_KERNEL_DATA_BASE + KDATA_KRNL_VERSION;
    case 325: return XBOX_KERNEL_DATA_BASE + KDATA_SIGNATURE_KEY;
    case 326: return XBOX_KERNEL_DATA_BASE + KDATA_LAN_KEY;
    case 327: return XBOX_KERNEL_DATA_BASE + KDATA_ALT_SIGNATURE_KEYS;
    case 328: return XBOX_KERNEL_DATA_BASE + KDATA_XE_IMAGE_FILENAME;
    case 355: return XBOX_KERNEL_DATA_BASE + KDATA_LAN_KEY;         /* alias */
    case 356: return XBOX_KERNEL_DATA_BASE + KDATA_ALT_SIGNATURE_KEYS; /* alias */
    case 357: return XBOX_KERNEL_DATA_BASE + KDATA_XE_PUBLIC_KEY;
    default:  return 0;  /* Not a data export */
    }
}

/**
 * Initialize kernel data export values at the kernel data area.
 * Called during bridge init, after Xbox memory is mapped.
 */
static void kernel_data_init(void)
{
    /* XboxHardwareInfo (ordinal 322) - XBOX_HARDWARE_INFO
     *   +0: ULONG Flags (0 = retail, 0x20 = devkit)
     *   +4: UCHAR GpuRevision
     *   +5: UCHAR McpRevision
     */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_HARDWARE_INFO + 0) = 0;   /* Retail */
    BRIDGE_MEM8(XBOX_KERNEL_DATA_BASE + KDATA_HARDWARE_INFO + 4) = 0xA1; /* NV2A A1 */
    BRIDGE_MEM8(XBOX_KERNEL_DATA_BASE + KDATA_HARDWARE_INFO + 5) = 0xB1; /* MCPX B1 */

    /* XboxKrnlVersion (ordinal 324) - XBOX_KRNL_VERSION
     *   +0: USHORT Major (1)
     *   +2: USHORT Minor (0)
     *   +4: USHORT Build (5849 = XDK version)
     *   +6: USHORT Qfe (0)
     */
    BRIDGE_MEM16(XBOX_KERNEL_DATA_BASE + KDATA_KRNL_VERSION + 0) = 1;
    BRIDGE_MEM16(XBOX_KERNEL_DATA_BASE + KDATA_KRNL_VERSION + 2) = 0;
    BRIDGE_MEM16(XBOX_KERNEL_DATA_BASE + KDATA_KRNL_VERSION + 4) = 5849;
    BRIDGE_MEM16(XBOX_KERNEL_DATA_BASE + KDATA_KRNL_VERSION + 6) = 0;

    /* KeTickCount (ordinal 156) - initialized to current tick count.
     * A background thread in main.c updates this every ~1ms. */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_TICK_COUNT) = GetTickCount();

    /* LaunchDataPage (ordinal 164) - NULL (no launch data) */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_LAUNCH_DATA_PAGE) = 0;

    /* PsThreadObjectType (ordinal 259) - type object (stub: 0) */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_THREAD_OBJ_TYPE) = 0;

    /* ExEventObjectType (ordinal 17) - type object (stub: 0) */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_EVENT_OBJ_TYPE) = 0;

    /* IoCompletionObjectType (ordinal 65) - type object (stub: 0) */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_IO_COMPLETION_TYPE) = 0;

    /* IoDeviceObjectType (ordinal 71) - type object (stub: 0) */
    BRIDGE_MEM32(XBOX_KERNEL_DATA_BASE + KDATA_IO_DEVICE_TYPE) = 0;

    /* XboxHDKey (ordinal 323) - 16 bytes of zeros (no key) */
    memset((void*)((uintptr_t)(XBOX_KERNEL_DATA_BASE + KDATA_HD_KEY) + g_xbox_mem_offset), 0, 16);

    /* XboxSignatureKey (ordinal 325) - 16 bytes of zeros */
    memset((void*)((uintptr_t)(XBOX_KERNEL_DATA_BASE + KDATA_SIGNATURE_KEY) + g_xbox_mem_offset), 0, 16);

    /* XboxLANKey (ordinals 326, 355) - 16 bytes of zeros */
    memset((void*)((uintptr_t)(XBOX_KERNEL_DATA_BASE + KDATA_LAN_KEY) + g_xbox_mem_offset), 0, 16);

    /* XboxAlternateSignatureKeys (ordinals 327, 356) - 256 bytes of zeros */
    memset((void*)((uintptr_t)(XBOX_KERNEL_DATA_BASE + KDATA_ALT_SIGNATURE_KEYS) + g_xbox_mem_offset), 0, 256);

    /* XePublicKeyData (ordinal 357) - 284 bytes of zeros */
    memset((void*)((uintptr_t)(XBOX_KERNEL_DATA_BASE + KDATA_XE_PUBLIC_KEY) + g_xbox_mem_offset), 0, 284);

    fprintf(stderr, "  Kernel data exports: initialized at Xbox VA 0x%08X\n",
            XBOX_KERNEL_DATA_BASE);
}

/* ── Per-slot ordinal and bridge function ────────────────── */

/* Ordinal for each slot (read from Xbox memory during init) */
static ULONG g_slot_ordinals[XBOX_KERNEL_THUNK_TABLE_SIZE];

/* Log counter - limit output to avoid flooding */
static int g_kernel_call_count = 0;

/* Read Xbox stack arg as uint32_t.
 * After kernel_thunk_dispatch pops the dummy return address (c->esp += 4),
 * arg0 is at c->esp+0, arg1 at c->esp+4, etc. */
#define STACK_ARG(n) ((uint32_t)BRIDGE_MEM32(c->esp + 4u + (n) * 4))

/* ── Per-ordinal bridge functions ─────────────────────────
 *
 * Each bridge reads args from the Xbox stack, translates pointer
 * args from Xbox VA→native, calls the kernel function, and stores
 * the result in c->eax.
 *
 * Xbox cdecl: args pushed right-to-left, caller cleans stack.
 * Xbox stdcall: args pushed right-to-left, callee cleans stack.
 * In our case the caller (translated code) does "PUSH32" for each arg
 * before calling, and the kernel function's ret-N is handled by the
 * translated code's own stack adjustment.
 */

/* ── PsCreateSystemThreadEx (ordinal 255) ────────────────
 * NTSTATUS PsCreateSystemThreadEx(
 *   PHANDLE ThreadHandle,      // arg0: Xbox VA → pointer
 *   ULONG ThreadExtraSize,     // arg1: value
 *   ULONG KernelStackSize,     // arg2: value
 *   ULONG TlsDataSize,         // arg3: value
 *   PULONG ThreadId,           // arg4: Xbox VA → pointer (can be NULL)
 *   PVOID StartContext1,       // arg5: Xbox VA → opaque
 *   PVOID StartContext2,       // arg6: Xbox VA → opaque
 *   BOOLEAN CreateSuspended,   // arg7: value
 *   BOOLEAN DebugStack,        // arg8: value
 *   PXBOX_SYSTEM_ROUTINE StartRoutine  // arg9: Xbox function pointer
 * )
 *
 * For static recompilation, we don't create a real thread.
 * Instead we call the StartRoutine synchronously via RECOMP_ICALL.
 * This is correct because on Xbox, the entry point creates a system
 * thread and returns, and the thread runs the actual game.
 */
static int g_thread_call_count = 0;

static void bridge_PsCreateSystemThreadEx(RecompCtx* c)
{
    uint32_t xbox_handle_ptr = STACK_ARG(0);
    uint32_t start_context1  = STACK_ARG(5);
    uint32_t start_context2  = STACK_ARG(6);
    uint32_t start_routine   = STACK_ARG(9);
    int is_first_call = (g_thread_call_count == 0);
    g_thread_call_count++;

    fprintf(stderr, "  [KERNEL] PsCreateSystemThreadEx #%d: routine=0x%08X ctx1=0x%08X ctx2=0x%08X\n",
            g_thread_call_count, start_routine, start_context1, start_context2);
    fflush(stderr);

    /* Write a fake handle to the output pointer */
    if (xbox_handle_ptr) {
        BRIDGE_MEM32(xbox_handle_ptr) = 0xBEEF0001;  /* fake handle */
    }

    /* Call the start routine synchronously through the recomp dispatch.
     * Xbox thread start routines receive two parameters:
     *   void ThreadRoutine(PVOID StartContext1, PVOID StartContext2)
     * We push both onto the simulated stack (right-to-left).
     *
     * First call: the game's main thread entry point. Must run synchronously
     * and inherit the current register state (this IS the game starting).
     *
     * Subsequent calls: worker threads. Must save/restore ALL global registers
     * because on real Xbox each thread has its own register set. Without this,
     * the worker clobbers the caller's c->esi, c->ebx, etc. */
    if (start_routine) {
        recomp_func_t fn = recomp_lookup(start_routine);
        if (!fn) fn = recomp_lookup_manual(start_routine);
        if (fn) {
            if (is_first_call) {
                /* Main game thread: run directly, inheriting register state */
                c->esp -= 4; BRIDGE_MEM32(c->esp) = start_context2;
                c->esp -= 4; BRIDGE_MEM32(c->esp) = start_context1;
                c->esp -= 4; BRIDGE_MEM32(c->esp) = 0;
                fn(c);
                c->esp += 12;
                fprintf(stderr, "  [KERNEL] PsCreateSystemThreadEx: main thread returned (c->eax=0x%08X)\n", c->eax);
                fflush(stderr);
            } else {
                /* Worker thread: run synchronously but save/restore all
                 * global registers (each Xbox thread has its own register set).
                 * The XIP file loader runs as a worker and must complete
                 * before the scene graph can be built. */
                uint32_t save_eax = c->eax, save_ecx = c->ecx, save_edx = c->edx;
                uint32_t save_ebx = c->ebx, save_esi = c->esi, save_edi = c->edi;
                uint32_t save_esp = c->esp, save_ebp = c->ebp;
                fprintf(stderr, "  [KERNEL] PsCreateSystemThreadEx: running worker 0x%08X (ctx=0x%08X)\n",
                        start_routine, start_context1);
                fflush(stderr);

                c->esp -= 4; BRIDGE_MEM32(c->esp) = start_context2;
                c->esp -= 4; BRIDGE_MEM32(c->esp) = start_context1;
                c->esp -= 4; BRIDGE_MEM32(c->esp) = 0;
                c->ebp = c->esp;
                fn(c);
                fprintf(stderr, "  [KERNEL] PsCreateSystemThreadEx: worker returned\n");
                fflush(stderr);

                /* Restore all registers */
                c->eax = save_eax; c->ecx = save_ecx; c->edx = save_edx;
                c->ebx = save_ebx; c->esi = save_esi; c->edi = save_edi;
                c->esp = save_esp; c->ebp = save_ebp;
            }
        } else {
            fprintf(stderr, "  [KERNEL] PsCreateSystemThreadEx: start routine 0x%08X not found in dispatch!\n",
                    start_routine);
        }
    }

    c->eax = 0; /* STATUS_SUCCESS */
}

/* ── NtClose (ordinal 187) ───────────────────────────────
 * NTSTATUS NtClose(HANDLE Handle)
 * Handle is a value (not a pointer), so safe for generic call.
 */
/* Handle-table helpers; defined further below. Xbox memory slots are 32-bit
 * but native HANDLEs are 64-bit pointers, so handles are kept in a table and
 * referenced by tagged 32-bit tokens. */
static void   bridge_write_handle(uint32_t handle_va, HANDLE h);
static HANDLE bridge_take_handle(uint32_t token);

static void bridge_NtClose(RecompCtx* c)
{
    uint32_t raw_handle = STACK_ARG(0);

    if (g_kernel_call_count <= 200) {
        fprintf(stderr, "  [KERNEL] NtClose: handle=0x%08X\n", raw_handle);
        fflush(stderr);
    }

    /* Close real handles but skip fake/synthetic ones */
    if (raw_handle && raw_handle != 0xDEAD0001u && raw_handle != 0xBEEF0010u) {
        HANDLE h = bridge_take_handle(raw_handle);
        if (h && h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }
    c->eax = 0; /* STATUS_SUCCESS */
}

/* ── MmAllocateContiguousMemory (ordinal 165) ─────────────
 * PVOID MmAllocateContiguousMemory(ULONG NumberOfBytes)
 */
static void bridge_MmAllocateContiguousMemory(RecompCtx* c)
{
    uint32_t size = STACK_ARG(0);

    /* Allocate from Xbox heap so MEM32(result) works correctly */
    uint32_t xbox_va = xbox_HeapAlloc(size, 4096);

    if (g_kernel_call_count <= 100) {
        fprintf(stderr, "  [KERNEL] MmAllocateContiguousMemory: size=%u → Xbox VA 0x%08X\n",
                size, xbox_va);
        fflush(stderr);
    }

    c->eax = xbox_va;
}

/* ── MmAllocateContiguousMemoryEx (ordinal 166) ───────────
 * PVOID MmAllocateContiguousMemoryEx(SIZE_T size, ULONG_PTR low, ULONG_PTR high,
 *                                     ULONG alignment, ULONG protect)
 */
static void bridge_MmAllocateContiguousMemoryEx(RecompCtx* c)
{
    uint32_t size = STACK_ARG(0);
    uint32_t low = STACK_ARG(1);
    uint32_t high = STACK_ARG(2);
    uint32_t align = STACK_ARG(3);
    uint32_t prot = STACK_ARG(4);

    /* Allocate from Xbox heap with requested alignment */
    if (align < 4096) align = 4096;
    uint32_t xbox_va = xbox_HeapAlloc(size, align);

    if (g_kernel_call_count <= 100) {
        fprintf(stderr, "  [KERNEL] MmAllocateContiguousMemoryEx: size=%u align=%u → Xbox VA 0x%08X\n",
                size, align, xbox_va);
        fflush(stderr);
    }

    c->eax = xbox_va;
}

/* ── MmFreeContiguousMemory (ordinal 171) ─────────────────
 * VOID MmFreeContiguousMemory(PVOID BaseAddress)
 */
static void bridge_MmFreeContiguousMemory(RecompCtx* c)
{
    uint32_t addr = STACK_ARG(0);
    xbox_HeapFree(addr);
    c->eax = 0;
}

/* ── NtAllocateVirtualMemory (ordinal 184) ────────────────
 * NTSTATUS NtAllocateVirtualMemory(PVOID *BaseAddress, ULONG ZeroBits,
 *     PULONG AllocationSize, ULONG AllocationType, ULONG Protect)
 */
static void bridge_NtAllocateVirtualMemory(RecompCtx* c)
{
    uint32_t base_ptr = STACK_ARG(0);  /* PVOID* in Xbox VA */
    uint32_t zero_bits = STACK_ARG(1);
    uint32_t size_ptr = STACK_ARG(2);  /* PULONG in Xbox VA */
    uint32_t alloc_type = STACK_ARG(3);
    uint32_t protect = STACK_ARG(4);

    /* Read the requested size from Xbox memory */
    uint32_t size = size_ptr ? BRIDGE_MEM32(size_ptr) : 0;
    /* Read the base address hint (0 = let kernel choose) */
    uint32_t base_hint = base_ptr ? BRIDGE_MEM32(base_ptr) : 0;

    if (g_kernel_call_count <= 200) {
        fprintf(stderr, "  [KERNEL] NtAllocateVirtualMemory: base=0x%08X size=%u type=0x%X prot=0x%X\n",
                base_hint, size, alloc_type, protect);
        fflush(stderr);
    }

    if (size == 0) {
        c->eax = 0xC0000045u; /* STATUS_INVALID_PAGE_PROTECTION */
        return;
    }

    /*
     * Xbox NtAllocateVirtualMemory supports two modes:
     * - MEM_RESERVE (0x2000): Reserve virtual address space
     * - MEM_COMMIT  (0x1000): Commit pages within a reserved region
     * - MEM_RESERVE|MEM_COMMIT (0x3000): Both in one call
     *
     * Our Xbox heap (bump allocator) always commits memory immediately,
     * so MEM_COMMIT on an already-reserved region is a no-op.
     * Only allocate new memory when MEM_RESERVE is requested.
     */
    if (base_hint != 0 && (alloc_type & 0x2000) == 0) {
        /* MEM_COMMIT only, on an already-reserved region.
         * The memory is already committed by our bump allocator.
         * Don't change the base address - just return success. */
        if (g_kernel_call_count <= 200) {
            fprintf(stderr, "  [KERNEL] → MEM_COMMIT on existing region 0x%08X, no-op\n", base_hint);
            fflush(stderr);
        }
        c->eax = 0; /* STATUS_SUCCESS */
        return;
    }

    /*
     * Allocate from Xbox heap (MEM_RESERVE or MEM_RESERVE|MEM_COMMIT).
     *
     * When the caller names a base address, HONOUR IT. The engine does not
     * treat this as a hint: sub_001FFDA1 scans with NtQueryVirtualMemory,
     * picks a MEM_FREE region itself, reserves at that exact base, and then
     * checks `if (returned != requested) fail` (loc_001FFF8E). Handing back
     * the bump pointer instead - 0x0108D000 for a request of 0x01090000 -
     * made it abandon the reservation, so no memory region was ever
     * registered and sub_001FE850's region gate refused every subsequent
     * allocation with -1. That was the whole "the pool refuses 16 bytes"
     * wall. See ledger #75.
     *
     * Safe by construction: since ledger #35 this bridge reports everything
     * from xbox_HeapHighWater() up as MEM_FREE, so a base the engine chose
     * from our own report is at or above the bump pointer.
     */
    uint32_t xbox_va = base_hint ? xbox_HeapAllocAt(base_hint, size)
                                 : xbox_HeapAlloc(size, 4096);
    if (!xbox_va) {
        c->eax = 0xC0000017u; /* STATUS_NO_MEMORY */
        return;
    }

    /* Write back the allocated address and actual size */
    if (base_ptr) BRIDGE_MEM32(base_ptr) = xbox_va;
    if (size_ptr) BRIDGE_MEM32(size_ptr) = size;

    c->eax = 0; /* STATUS_SUCCESS */
}

/* ── NtFreeVirtualMemory (ordinal 199) ────────────────────
 * NTSTATUS NtFreeVirtualMemory(PVOID *BaseAddress, PULONG FreeSize,
 *     ULONG FreeType)
 */
static void bridge_NtFreeVirtualMemory(RecompCtx* c)
{
    /* No-op, like xbox_HeapFree: our memory model is one big pre-mapped
     * region carved up by a bump allocator, not individual VirtualAlloc
     * calls, so the real VirtualFree() in xbox_NtFreeVirtualMemory is
     * guaranteed to fail here. */
    c->eax = 0; /* STATUS_SUCCESS */
}

/* ── ExAllocatePool / ExAllocatePoolWithTag (ordinals 15, 16) ─
 * Must allocate from Xbox heap so the returned pointer is an Xbox VA
 * that can be accessed via MEM32(). Native HeapAlloc returns 64-bit
 * pointers that get truncated and produce garbage Xbox VAs.
 */
static void bridge_ExAllocatePool(RecompCtx* c)
{
    uint32_t size = STACK_ARG(0);
    uint32_t xbox_va = xbox_HeapAlloc(size, 16);

    if (g_kernel_call_count <= 200) {
        fprintf(stderr, "  [KERNEL] ExAllocatePool: size=%u → Xbox VA 0x%08X\n",
                size, xbox_va);
        fflush(stderr);
    }

    c->eax = xbox_va;
}

static void bridge_ExAllocatePoolWithTag(RecompCtx* c)
{
    uint32_t size = STACK_ARG(0);
    uint32_t tag = STACK_ARG(1);
    uint32_t xbox_va = xbox_HeapAlloc(size, 16);

    if (g_kernel_call_count <= 200) {
        fprintf(stderr, "  [KERNEL] ExAllocatePoolWithTag: size=%u tag='%c%c%c%c' → Xbox VA 0x%08X\n",
                size,
                (char)(tag & 0xFF), (char)((tag >> 8) & 0xFF),
                (char)((tag >> 16) & 0xFF), (char)((tag >> 24) & 0xFF),
                xbox_va);
        fflush(stderr);
    }

    c->eax = xbox_va;
}

/* ── KfRaiseIrql / KfLowerIrql (ordinals 160, 161) ────── */
static void bridge_KfRaiseIrql(RecompCtx* c)
{
    uint32_t new_irql = STACK_ARG(0);
    c->eax = (uint32_t)xbox_KfRaiseIrql((UCHAR)new_irql);
}

static void bridge_KfLowerIrql(RecompCtx* c)
{
    uint32_t new_irql = STACK_ARG(0);
    xbox_KfLowerIrql((UCHAR)new_irql);
    c->eax = 0;
}

/* ── KeRaiseIrqlToDpcLevel (ordinal 129) ─────────────────── */
static void bridge_KeRaiseIrqlToDpcLevel(RecompCtx* c)
{
    c->eax = (uint32_t)xbox_KeRaiseIrqlToDpcLevel();
}

/* ── RtlInitializeCriticalSection / Enter / Leave (ordinals 291, 277, 294) ─ */
static void bridge_RtlInitializeCriticalSection(RecompCtx* c)
{
    uint32_t cs_va = STACK_ARG(0);
    xbox_RtlInitializeCriticalSection(XBOX_TO_NATIVE(cs_va));
    c->eax = 0;
}

static void bridge_RtlEnterCriticalSection(RecompCtx* c)
{
    uint32_t cs_va = STACK_ARG(0);
    xbox_RtlEnterCriticalSection(XBOX_TO_NATIVE(cs_va));
    c->eax = 0;
}

static void bridge_RtlLeaveCriticalSection(RecompCtx* c)
{
    uint32_t cs_va = STACK_ARG(0);
    xbox_RtlLeaveCriticalSection(XBOX_TO_NATIVE(cs_va));
    c->eax = 0;
}

/* ── KeQueryPerformanceCounter / Frequency (ordinals 126, 127) ─ */
static void bridge_KeQueryPerformanceCounter(RecompCtx* c)
{
    LARGE_INTEGER li = xbox_KeQueryPerformanceCounter();
    c->eax = (uint32_t)li.LowPart;
    c->edx = (uint32_t)li.HighPart;
}

static void bridge_KeQueryPerformanceFrequency(RecompCtx* c)
{
    LARGE_INTEGER li = xbox_KeQueryPerformanceFrequency();
    c->eax = (uint32_t)li.LowPart;
    c->edx = (uint32_t)li.HighPart;
}

/* ── KeQuerySystemTime (ordinal 128) ─────────────────────── */
static void bridge_KeQuerySystemTime(RecompCtx* c)
{
    uint32_t time_ptr = STACK_ARG(0);
    xbox_KeQuerySystemTime(XBOX_TO_NATIVE(time_ptr));
    c->eax = 0;
}

/* ── MmQueryStatistics (ordinal 181) ─────────────────────── */
static void bridge_MmQueryStatistics(RecompCtx* c)
{
    uint32_t stats_ptr = STACK_ARG(0);
    c->eax = (uint32_t)xbox_MmQueryStatistics(XBOX_TO_NATIVE(stats_ptr));
}

/* ── NtCreateEvent (ordinal 189) ─────────────────────────── */
static void bridge_NtCreateEvent(RecompCtx* c)
{
    uint32_t handle_ptr = STACK_ARG(0);
    uint32_t obj_attr_ptr = STACK_ARG(1);
    uint32_t event_type = STACK_ARG(2);
    uint32_t initial_state = STACK_ARG(3);

    /* Use local HANDLE to avoid 8-byte write to 4-byte Xbox memory slot.
     * On x64, HANDLE is 8 bytes but Xbox expects 4-byte handles. */
    HANDLE local_handle = NULL;
    NTSTATUS status = xbox_NtCreateEvent(
        &local_handle,
        XBOX_TO_NATIVE(obj_attr_ptr),
        event_type, initial_state);

    if (handle_ptr) {
        bridge_write_handle(handle_ptr, local_handle);
    }

    fprintf(stderr, "  [BRIDGE] NtCreateEvent: handle_ptr=0x%08X type=%u init=%u → status=0x%08X handle=0x%08X\n",
            handle_ptr, event_type, initial_state, (uint32_t)status,
            (uint32_t)(uintptr_t)local_handle);

    c->eax = (uint32_t)status;
}

/* ── KeSetEvent (ordinal 145) ────────────────────────────── */
static void bridge_KeSetEvent(RecompCtx* c)
{
    uint32_t event_ptr = STACK_ARG(0);
    uint32_t increment = STACK_ARG(1);
    uint32_t wait = STACK_ARG(2);

    c->eax = (uint32_t)xbox_KeSetEvent(XBOX_TO_NATIVE(event_ptr), increment, (BOOLEAN)wait);
}

/* ── KeWaitForSingleObject (ordinal 159) ─────────────────── */
static void bridge_KeWaitForSingleObject(RecompCtx* c)
{
    uint32_t object = STACK_ARG(0);
    uint32_t wait_reason = STACK_ARG(1);
    uint32_t wait_mode = STACK_ARG(2);
    uint32_t alertable = STACK_ARG(3);
    uint32_t timeout_ptr = STACK_ARG(4);

    c->eax = (uint32_t)xbox_KeWaitForSingleObject(
        XBOX_TO_NATIVE(object), wait_reason, wait_mode,
        (BOOLEAN)alertable, XBOX_TO_NATIVE(timeout_ptr));
}

/* ── NtYieldExecution (ordinal 238) ──────────────────────── */
static void bridge_NtYieldExecution(RecompCtx* c)
{
    c->eax = (uint32_t)xbox_NtYieldExecution();
}

/* ── MmGetPhysicalAddress (ordinal 173) ──────────────────── */
static void bridge_MmGetPhysicalAddress(RecompCtx* c)
{
    uint32_t addr = STACK_ARG(0);
    /* Xbox uses identity mapping (physical == virtual) for the lower 64MB.
     * Just return the Xbox VA as-is. Don't call xbox_MmGetPhysicalAddress
     * which would return a native pointer. */
    c->eax = addr;
}

/* ── MmSetAddressProtect (ordinal 182) ───────────────────── */
static void bridge_MmSetAddressProtect(RecompCtx* c)
{
    uint32_t addr = STACK_ARG(0);
    uint32_t size = STACK_ARG(1);
    uint32_t prot = STACK_ARG(2);

    xbox_MmSetAddressProtect(XBOX_TO_NATIVE(addr), size, prot);
    c->eax = 0;
}

/* ── AvSetDisplayMode (ordinal 3) ────────────────────────── */
static void bridge_AvSetDisplayMode(RecompCtx* c)
{
    uint32_t addr = STACK_ARG(0);
    uint32_t step = STACK_ARG(1);
    uint32_t mode = STACK_ARG(2);
    uint32_t format = STACK_ARG(3);
    uint32_t pitch = STACK_ARG(4);
    uint32_t fb = STACK_ARG(5);

    xbox_AvSetDisplayMode(XBOX_TO_NATIVE(addr), step, mode, format, pitch, fb);
    c->eax = 0;
}

/* ── PsTerminateSystemThread (ordinal 258) ───────────────
 * VOID PsTerminateSystemThread(NTSTATUS ExitStatus)
 *
 * On real Xbox, this terminates the calling thread (never returns).
 * In our recompiled version, threads run synchronously, so we just
 * return. The caller (sub_001D1818) handles this gracefully.
 */
static void bridge_PsTerminateSystemThread(RecompCtx* c)
{
    uint32_t exit_status = STACK_ARG(0);

    fprintf(stderr, "  [KERNEL] PsTerminateSystemThread: status=0x%08X\n", exit_status);
    fflush(stderr);

    c->eax = exit_status;
    /* Simply return - caller will clean up */
}

/* ── HalReadSMCTrayState (ordinal 47) ─────────────────────
 * VOID HalReadSMCTrayState(PDWORD TrayState, PDWORD TrayStateChangeCount)
 *
 * Returns DVD tray state. 0x10 = no disc, 0x14 = tray closed with disc.
 */
static void bridge_HalReadSMCTrayState(RecompCtx* c)
{
    uint32_t state_ptr = STACK_ARG(0);
    uint32_t count_ptr = STACK_ARG(1);

    /* `if (ptr)` only rejects 0. A guest pointer of 1 - or any other small
     * integer that is really a flag, not an address - passes it and gets
     * written through. That is how the SEH chain head at Xbox VA 0 was being
     * destroyed: this handler was wired to ordinal 47, whose second argument
     * is the BOOLEAN 1, so it wrote a zero dword at VA 1 and turned
     * 0xFFFFFFFF into 0x000000FF. Validate the address, not just its
     * truthiness - a kernel bridge must never write through an implausible
     * guest pointer. */
    if (BRIDGE_PTR_OK(state_ptr)) BRIDGE_MEM32(state_ptr) = 0x10;  /* No disc */
    if (BRIDGE_PTR_OK(count_ptr)) BRIDGE_MEM32(count_ptr) = 0;
    c->eax = 0;
}

/* ── HalRegisterShutdownNotification (ordinal 47) ─────────
 * VOID HalRegisterShutdownNotification(PHAL_SHUTDOWN_REGISTRATION Registration,
 *                                      BOOLEAN Register)
 *
 * Adds or removes a shutdown-notification callback. Both arguments are INPUT:
 * a registration structure and a boolean. Nothing is written back.
 *
 * This ordinal was previously mapped to bridge_HalReadSMCTrayState, which
 * treats its second argument as an output pointer. The game calls it as
 *
 *     push ebx            ; = 1  (Register = TRUE)
 *     push 0x461694       ; Registration
 *     call [0x3C6CD0]     ; thunk slot 76 -> ordinal 47
 *
 * so the handler wrote a zero dword through the address "1", clobbering the
 * SEH exception-list head at Xbox VA 0. Caught with the TIB write-watch in
 * main.c. kernel_thunks.c already had the correct name for this ordinal; only
 * the bridge handler table disagreed.
 *
 * The port never shuts down through this path, so registering is a no-op -
 * but it must not write to memory.
 */
static void bridge_HalRegisterShutdownNotification(RecompCtx* c)
{
    uint32_t registration = STACK_ARG(0);
    uint32_t do_register  = STACK_ARG(1);

    static int logged;
    if (!logged++) {
        fprintf(stderr, "  [KERNEL] HalRegisterShutdownNotification: "
                        "registration=0x%08X register=%u (no-op)\n",
                registration, do_register);
        fflush(stderr);
    }
    c->eax = 0;
}

/* ── KeInitializeDpc (ordinal 107) ────────────────────────
 * VOID KeInitializeDpc(PKDPC Dpc, PKDEFERRED_ROUTINE DeferredRoutine,
 *                       PVOID DeferredContext)
 *
 * Initializes a DPC object. The Xbox KDPC structure is 32 bytes.
 * We zero it and set the routine and context pointers.
 */
static void bridge_KeInitializeDpc(RecompCtx* c)
{
    uint32_t dpc_va = STACK_ARG(0);
    uint32_t routine = STACK_ARG(1);
    uint32_t context = STACK_ARG(2);

    /* Zero the structure (32 bytes) */
    memset(XBOX_TO_NATIVE(dpc_va), 0, 32);

    /* Set Type (0x13 = DpcObject) and fields */
    BRIDGE_MEM16(dpc_va + 0) = 0x13;   /* Type */
    BRIDGE_MEM32(dpc_va + 12) = routine; /* DeferredRoutine */
    BRIDGE_MEM32(dpc_va + 16) = context; /* DeferredContext */
    c->eax = 0;
}

/* ── KeInitializeTimerEx (ordinal 113) ────────────────────
 * VOID KeInitializeTimerEx(PKTIMER Timer, TIMER_TYPE Type)
 *
 * Initializes a timer object. Xbox KTIMER is 40 bytes.
 */
static void bridge_KeInitializeTimerEx(RecompCtx* c)
{
    uint32_t timer_va = STACK_ARG(0);
    uint32_t type = STACK_ARG(1);

    /* Zero the structure (40 bytes) */
    memset(XBOX_TO_NATIVE(timer_va), 0, 40);

    /* Set Type (0x08 = TimerNotificationObject, 0x09 = TimerSynchronizationObject) */
    BRIDGE_MEM16(timer_va + 0) = (uint16_t)(0x08 + (type & 1));
    c->eax = 0;
}

/* ── KeSetTimer / KeSetTimerEx (ordinal 149/150) ──────────
 * BOOLEAN KeSetTimer(PKTIMER Timer, LARGE_INTEGER DueTime, PKDPC Dpc)
 *
 * Sets a timer. We don't actually start timers - just record the state.
 * Returns FALSE (timer was not already set).
 */
static void bridge_KeSetTimer(RecompCtx* c)
{
    /* Timer functionality is not needed for basic execution.
     * Return FALSE = timer was not previously set. */
    c->eax = 0;
}

/* ── ExQueryPoolBlockSize (ordinal 24) ────────────────────
 * ULONG ExQueryPoolBlockSize(PVOID PoolBlock)
 *
 * Returns the size of a pool memory block.
 * Since we use HeapAlloc, we can query the Windows heap.
 */
static void bridge_ExQueryPoolBlockSize(RecompCtx* c)
{
    uint32_t block = STACK_ARG(0);
    /* Return a reasonable default size. Actual pool blocks are managed
     * by the kernel; for recompilation, returning 0 might be OK since
     * code usually uses this for debugging/stats. */
    c->eax = 0;
}

/* ── RtlNtStatusToDosError (ordinal 301) ─────────────────
 * ULONG RtlNtStatusToDosError(NTSTATUS Status)
 *
 * Converts an NTSTATUS to a Win32 error code.
 */
static void bridge_RtlNtStatusToDosError(RecompCtx* c)
{
    uint32_t status = STACK_ARG(0);

    /* Simple mapping of common status codes */
    switch (status) {
    case 0x00000000: c->eax = 0; break;          /* STATUS_SUCCESS → ERROR_SUCCESS */
    case 0xC0000034: c->eax = 2; break;          /* STATUS_OBJECT_NAME_NOT_FOUND → ERROR_FILE_NOT_FOUND */
    case 0xC000003A: c->eax = 3; break;          /* STATUS_OBJECT_PATH_NOT_FOUND → ERROR_PATH_NOT_FOUND */
    case 0xC0000022: c->eax = 5; break;          /* STATUS_ACCESS_DENIED → ERROR_ACCESS_DENIED */
    case 0xC0000008: c->eax = 6; break;          /* STATUS_INVALID_HANDLE → ERROR_INVALID_HANDLE */
    case 0xC0000017: c->eax = 8; break;          /* STATUS_NO_MEMORY → ERROR_NOT_ENOUGH_MEMORY */
    case 0xC000000D: c->eax = 87; break;         /* STATUS_INVALID_PARAMETER → ERROR_INVALID_PARAMETER */
    default:         c->eax = 317; break;         /* ERROR_MR_MID_NOT_FOUND (generic) */
    }
}

/* ── File I/O bridge helpers ─────────────────────────────── */

/*
 * Xbox structures use 32-bit pointers. On Win64, the C structs
 * (XBOX_OBJECT_ATTRIBUTES, etc.) have 64-bit pointers, so we can't
 * cast Xbox memory to them directly. Instead, parse the 32-bit
 * Xbox layout manually:
 *
 * XBOX_OBJECT_ATTRIBUTES (12 bytes):
 *   offset 0: RootDirectory  (uint32_t)
 *   offset 4: ObjectName     (uint32_t, Xbox VA to ANSI_STRING)
 *   offset 8: Attributes     (uint32_t)
 *
 * XBOX_ANSI_STRING (8 bytes):
 *   offset 0: Length          (uint16_t)
 *   offset 2: MaximumLength   (uint16_t)
 *   offset 4: Buffer          (uint32_t, Xbox VA to char[])
 *
 * XBOX_IO_STATUS_BLOCK (8 bytes):
 *   offset 0: Status          (uint32_t)
 *   offset 4: Information     (uint32_t)
 */

/* Extract the ANSI path string from an Xbox OBJECT_ATTRIBUTES */
static const char* bridge_get_xbox_path(uint32_t obj_attrs_va)
{
    uint32_t ansi_str_va, buf_va;
    if (!obj_attrs_va) return NULL;
    ansi_str_va = BRIDGE_MEM32(obj_attrs_va + 4);
    if (!ansi_str_va) return NULL;
    buf_va = BRIDGE_MEM32(ansi_str_va + 4);
    if (!buf_va) return NULL;
    return (const char*)XBOX_TO_NATIVE(buf_va);
}

/* Write NTSTATUS + Information into Xbox IO_STATUS_BLOCK */
static void bridge_write_iostatus(uint32_t ios_va, NTSTATUS status, uint32_t info)
{
    if (ios_va) {
        BRIDGE_MEM32(ios_va + 0) = (uint32_t)status;
        BRIDGE_MEM32(ios_va + 4) = info;
    }
}

/*
 * Handle table.
 *
 * Xbox memory only has 32-bit handle slots, but native HANDLEs are 64-bit
 * pointers (win32_compat objects, or real Win32 handles on Windows). Map
 * 32-bit tokens <-> native HANDLEs so a handle survives a round-trip through
 * Xbox memory. Tokens carry a tag in the high byte so they never collide
 * with the synthetic handles (0xDEAD0001 / 0xBEEF0010) used elsewhere.
 */
#define BRIDGE_HANDLE_TAG  0x48000000u
#define BRIDGE_HANDLE_MASK 0x00FFFFFFu
#define BRIDGE_HANDLE_MAX  16384
static HANDLE s_handle_table[BRIDGE_HANDLE_MAX];

static uint32_t bridge_handle_token(HANDLE h)
{
    int i;
    if (!h || h == INVALID_HANDLE_VALUE) return 0;
    for (i = 1; i < BRIDGE_HANDLE_MAX; i++)
        if (s_handle_table[i] == h) return BRIDGE_HANDLE_TAG | (uint32_t)i;
    for (i = 1; i < BRIDGE_HANDLE_MAX; i++)
        if (s_handle_table[i] == NULL) {
            s_handle_table[i] = h;
            return BRIDGE_HANDLE_TAG | (uint32_t)i;
        }
    fprintf(stderr, "  [BRIDGE] handle table full\n");
    return 0;
}

/* Store a native HANDLE into a 32-bit Xbox memory slot (as a token). */
static void bridge_write_handle(uint32_t handle_va, HANDLE h)
{
    if (handle_va)
        BRIDGE_MEM32(handle_va) = bridge_handle_token(h);
}

/* Resolve a 32-bit Xbox handle slot back to a native HANDLE. */
static HANDLE bridge_read_handle(uint32_t va)
{
    uint32_t token = BRIDGE_MEM32(va);
    if ((token & 0xFF000000u) == BRIDGE_HANDLE_TAG) {
        uint32_t i = token & BRIDGE_HANDLE_MASK;
        return (i > 0 && i < BRIDGE_HANDLE_MAX) ? s_handle_table[i] : NULL;
    }
    /* Untagged value: synthetic/dummy handle -- pass through unchanged. */
    return (HANDLE)(uintptr_t)token;
}

/* Resolve a token to a HANDLE and release its table slot (for NtClose). */
static HANDLE bridge_take_handle(uint32_t token)
{
    if ((token & 0xFF000000u) == BRIDGE_HANDLE_TAG) {
        uint32_t i = token & BRIDGE_HANDLE_MASK;
        if (i > 0 && i < BRIDGE_HANDLE_MAX) {
            HANDLE h = s_handle_table[i];
            s_handle_table[i] = NULL;
            return h;
        }
    }
    return NULL;   /* untagged -> not a table handle, do not close */
}

/* Build a native OBJECT_ATTRIBUTES wrapping the translated Xbox path. */
static void bridge_build_oa(uint32_t obj_attrs_va,
                            XBOX_OBJECT_ATTRIBUTES* oa, XBOX_ANSI_STRING* name)
{
    const char* path = bridge_get_xbox_path(obj_attrs_va);
    name->Buffer        = (PCHAR)path;
    name->Length        = path ? (USHORT)strlen(path) : 0;
    name->MaximumLength = (USHORT)(name->Length + 1);
    oa->RootDirectory = NULL;
    oa->ObjectName    = name;
    oa->Attributes    = 0;
}

/* Open a file by delegating to the ported xbox_NtCreateFile kernel HLE. */
static NTSTATUS bridge_create_file_impl(
    uint32_t handle_va, ACCESS_MASK access, uint32_t obj_attrs_va,
    uint32_t iostatus_va, ULONG file_attrs, ULONG share,
    ULONG disposition, ULONG options)
{
    XBOX_OBJECT_ATTRIBUTES oa;
    XBOX_ANSI_STRING       name;
    XBOX_IO_STATUS_BLOCK   ios;
    HANDLE   h  = NULL;
    NTSTATUS st;

    bridge_build_oa(obj_attrs_va, &oa, &name);
    if (!name.Buffer) {
        bridge_write_iostatus(iostatus_va, STATUS_OBJECT_PATH_NOT_FOUND, 0);
        return STATUS_OBJECT_PATH_NOT_FOUND;
    }
    memset(&ios, 0, sizeof(ios));

    st = xbox_NtCreateFile(&h, access, &oa, &ios, NULL,
                           file_attrs, share, disposition, options);

    if (NT_SUCCESS(st)) {
        bridge_write_handle(handle_va, h);
        bridge_write_iostatus(iostatus_va, ios.Status, (uint32_t)ios.Information);
    } else {
        bridge_write_iostatus(iostatus_va, st, 0);
    }
    return st;
}

/* ── NtCreateFile (ordinal 190, 9 args = 36 bytes) ─────── */
static void bridge_NtCreateFile(RecompCtx* c)
{
    uint32_t handle_va   = STACK_ARG(0);  /* PHANDLE */
    uint32_t access      = STACK_ARG(1);  /* ACCESS_MASK */
    uint32_t obj_attrs   = STACK_ARG(2);  /* POBJECT_ATTRIBUTES */
    uint32_t iostatus    = STACK_ARG(3);  /* PIO_STATUS_BLOCK */
    /* arg4: AllocationSize - ignored */
    uint32_t file_attrs  = STACK_ARG(5);  /* FileAttributes */
    uint32_t share       = STACK_ARG(6);  /* ShareAccess */
    uint32_t disposition = STACK_ARG(7);  /* CreateDisposition */
    uint32_t options     = STACK_ARG(8);  /* CreateOptions */

    c->eax = (uint32_t)bridge_create_file_impl(
        handle_va, access, obj_attrs, iostatus,
        file_attrs, share, disposition, options);
}

/* ── NtOpenFile (ordinal 202, 6 args = 24 bytes) ──────── */
static void bridge_NtOpenFile(RecompCtx* c)
{
    uint32_t handle_va = STACK_ARG(0);  /* PHANDLE */
    uint32_t access    = STACK_ARG(1);  /* ACCESS_MASK */
    uint32_t obj_attrs = STACK_ARG(2);  /* POBJECT_ATTRIBUTES */
    uint32_t iostatus  = STACK_ARG(3);  /* PIO_STATUS_BLOCK */
    uint32_t share     = STACK_ARG(4);  /* ShareAccess */
    uint32_t options   = STACK_ARG(5);  /* OpenOptions */

    /* NtOpenFile = NtCreateFile with FILE_OPEN disposition */
    c->eax = (uint32_t)bridge_create_file_impl(
        handle_va, access, obj_attrs, iostatus,
        0, share, 1 /* FILE_OPEN */, options);
}

/* ── NtReadFile (ordinal 219, 8 args = 32 bytes) ──────── */
static void bridge_NtReadFile(RecompCtx* c)
{
    HANDLE   handle    = bridge_read_handle(STACK_ARG(0));
    uint32_t iostatus  = STACK_ARG(4);
    uint32_t buffer_va = STACK_ARG(5);
    uint32_t length    = STACK_ARG(6);
    uint32_t offset_va = STACK_ARG(7);
    XBOX_IO_STATUS_BLOCK ios;
    LARGE_INTEGER  off;
    PLARGE_INTEGER poff = NULL;

    memset(&ios, 0, sizeof(ios));
    if (offset_va) {
        off.LowPart  = BRIDGE_MEM32(offset_va);
        off.HighPart = (LONG)BRIDGE_MEM32(offset_va + 4);
        poff = &off;
    }
    c->eax = (uint32_t)xbox_NtReadFile(handle, NULL, NULL, NULL, &ios,
                XBOX_TO_NATIVE(buffer_va), length, poff);
    bridge_write_iostatus(iostatus, ios.Status, (uint32_t)ios.Information);
}

/* ── NtWriteFile (ordinal 236, 8 args = 32 bytes) ─────── */
static void bridge_NtWriteFile(RecompCtx* c)
{
    HANDLE   handle    = bridge_read_handle(STACK_ARG(0));
    uint32_t iostatus  = STACK_ARG(4);
    uint32_t buffer_va = STACK_ARG(5);
    uint32_t length    = STACK_ARG(6);
    uint32_t offset_va = STACK_ARG(7);
    XBOX_IO_STATUS_BLOCK ios;
    LARGE_INTEGER  off;
    PLARGE_INTEGER poff = NULL;

    memset(&ios, 0, sizeof(ios));
    if (offset_va) {
        off.LowPart  = BRIDGE_MEM32(offset_va);
        off.HighPart = (LONG)BRIDGE_MEM32(offset_va + 4);
        poff = &off;
    }
    c->eax = (uint32_t)xbox_NtWriteFile(handle, NULL, NULL, NULL, &ios,
                XBOX_TO_NATIVE(buffer_va), length, poff);
    bridge_write_iostatus(iostatus, ios.Status, (uint32_t)ios.Information);
}

/* ── NtQueryInformationFile (ordinal 211, 5 args = 20 bytes) */
static void bridge_NtQueryInformationFile(RecompCtx* c)
{
    HANDLE   handle    = bridge_read_handle(STACK_ARG(0));
    uint32_t ios_va    = STACK_ARG(1);
    uint32_t info_va   = STACK_ARG(2);
    uint32_t length    = STACK_ARG(3);
    uint32_t infoclass = STACK_ARG(4);
    XBOX_IO_STATUS_BLOCK ios;

    memset(&ios, 0, sizeof(ios));
    c->eax = (uint32_t)xbox_NtQueryInformationFile(handle, &ios,
                XBOX_TO_NATIVE(info_va), length,
                (XBOX_FILE_INFORMATION_CLASS)infoclass);
    bridge_write_iostatus(ios_va, ios.Status, (uint32_t)ios.Information);
}

/* ── NtSetInformationFile (ordinal 226, 5 args = 20 bytes) ─ */
static void bridge_NtSetInformationFile(RecompCtx* c)
{
    HANDLE   handle    = bridge_read_handle(STACK_ARG(0));
    uint32_t ios_va    = STACK_ARG(1);
    uint32_t info_va   = STACK_ARG(2);
    uint32_t length    = STACK_ARG(3);
    uint32_t infoclass = STACK_ARG(4);
    XBOX_IO_STATUS_BLOCK ios;

    memset(&ios, 0, sizeof(ios));
    c->eax = (uint32_t)xbox_NtSetInformationFile(handle, &ios,
                XBOX_TO_NATIVE(info_va), length,
                (XBOX_FILE_INFORMATION_CLASS)infoclass);
    bridge_write_iostatus(ios_va, ios.Status, (uint32_t)ios.Information);
}

/* ── NtQueryVolumeInformationFile (ordinal 218, 5 args = 20 bytes) */
/*
 * NtQueryVirtualMemory (ordinal 217) - describe the region containing an address.
 *
 * This was missing entirely and it dominated the boot: 3,966 of 4,000 kernel
 * calls were this one ordinal hitting the "no bridge, returning 0" fallback.
 * Because the fallback leaves the caller's output buffer untouched, the caller
 * read whatever was already there and called again, which is why the count is
 * so enormous.
 *
 * TWO ARGUMENTS, not four. g_slot_arg_bytes said 16 and docs/formats/
 * kernel-exports.md documents a 4-parameter form, but the running program
 * disagrees: esp climbed by exactly 8 bytes on every one of those 3,966 calls
 * (kernel #108..#113 walk 0x00F7FFDC -> 0x00F80004 in +8 steps). The bridge
 * pops g_slot_arg_bytes after the call, so popping 16 when the caller pushed 8
 * leaks 8 per call - and after ~4,000 calls esp had walked clean off the top of
 * the 8 MB stack, which is the "STACK ESCAPE" triage_crash reports. Every
 * register being garbage at the final crash is downstream of that.
 *
 * The documented 4-parameter signature is the Windows NT one; the Xbox kernel
 * takes only (BaseAddress, MemoryInformation). Measured behaviour wins over the
 * doc here (project rule #5), and the doc should be corrected separately.
 *
 * The struct is the usual 32-bit MEMORY_BASIC_INFORMATION, 28 bytes:
 *   +0x00 BaseAddress   +0x04 AllocationBase   +0x08 AllocationProtect
 *   +0x0C RegionSize    +0x10 State            +0x14 Protect   +0x18 Type
 *
 * Answered from our own guest layout rather than by calling the host's
 * VirtualQuery: a guest VA is not a host address, so querying the host would
 * describe unrelated memory. Anything inside guest RAM is reported as one
 * committed, readable/writable private region, which is true of how this port
 * maps it.
 */
static void bridge_NtQueryVirtualMemory(RecompCtx* c)
{
    uint32_t base_address = STACK_ARG(0);
    uint32_t info_ptr     = STACK_ARG(1);

    if (info_ptr == 0) {
        c->eax = 0xC000000Du;            /* STATUS_INVALID_PARAMETER */
        return;
    }

    /*
     * SUSPECT-2 TEST (ledger #30). Real contiguous extents, but the above-RAM
     * case is BOUNDED rather than "to the top of the address space". The
     * reverted version reported 0xFFFFFFFF - base there, which is a hair from
     * overflow and may wrap in the caller's own arithmetic. Everything else
     * about the region table is identical to the change that regressed, so if
     * this run is healthy the overflow was the bug; if it regresses the same
     * way, the extents themselves are what the caller dislikes.
     */
    /*
     * The heap is split at the bump allocator's high-water mark. Below it is
     * committed; above it, all the way to the top of RAM, is genuinely free
     * and must be reported as MEM_FREE.
     *
     * Reporting the whole heap span as committed is what stranded the boot
     * (ledger #34). The engine's memory scan steps by exactly the RegionSize
     * we return, looking for a free run big enough to grow its pool. With all
     * four in-RAM regions marked committed it rejected the entire 64 MB,
     * walked off the top of RAM, and spun there forever. It has ~49 MB of
     * untouched heap sitting right in front of it.
     */
    const uint32_t heap_used_end = xbox_HeapHighWater();
    const struct { uint32_t base, end; int free; } k_regions[] = {
        { 0x00000000u,        XBOX_BASE_ADDRESS,                  0 },
        { XBOX_BASE_ADDRESS,  XBOX_STACK_BASE,                    0 },
        { XBOX_STACK_BASE,    XBOX_STACK_BASE + XBOX_STACK_SIZE,  0 },
        { XBOX_HEAP_BASE,     heap_used_end,                      0 },
        { heap_used_end,      XBOX_TOTAL_RAM,                     1 },
    };
    uint32_t region_base = 0, region_size = 0;
    uint32_t in_ram = 0, is_free = 0;
    for (unsigned i = 0; i < sizeof k_regions / sizeof k_regions[0]; i++) {
        if (k_regions[i].end <= k_regions[i].base) continue;  /* empty span */
        if (base_address >= k_regions[i].base && base_address < k_regions[i].end) {
            region_base = k_regions[i].base;
            region_size = k_regions[i].end - k_regions[i].base;
            in_ram = 1;
            is_free = (uint32_t)k_regions[i].free;
            break;
        }
    }
    if (!region_size) {
        /*
         * Above the top of RAM there is nothing to describe. The console has
         * 64 MB; the 4 GB above XBOX_TOTAL_RAM is not free memory, it is not
         * memory at all, and the real kernel fails the query rather than
         * describing it.
         *
         * Reporting it as a successful 64 KB FREE region is what caused the
         * hang (ledger #33): the caller advances by exactly the RegionSize we
         * hand back, so a flat 64 KB granule turned its search into a 65,536
         * step sweep of the whole address space that wrapped 335 times and
         * made 21.6 MILLION calls without ever accepting a region. It wants a
         * contiguous run larger than 64 KB and we never reported one.
         *
         * This is NOT ledger #30 being re-applied. That change kept returning
         * SUCCESS and only altered the extents, and its three untested
         * candidates (a)(b)(c) all still describe a region. Failing the query
         * outright is the one option none of them covered, and it is also the
         * faithful one.
         */
        c->eax = 0xC000000Du;            /* STATUS_INVALID_PARAMETER */
        return;
    }

    /* A free region has no AllocationBase, no protection and no type - that is
     * what tells a scanner it is available rather than merely readable. */
    BRIDGE_MEM32(info_ptr + 0x00) = region_base;
    BRIDGE_MEM32(info_ptr + 0x04) = is_free ? 0u : region_base;
    BRIDGE_MEM32(info_ptr + 0x08) = is_free ? 0u : 0x04u;        /* RW */
    BRIDGE_MEM32(info_ptr + 0x0C) = region_size;
    BRIDGE_MEM32(info_ptr + 0x10) = is_free ? 0x10000u : 0x1000u; /* FREE : COMMIT */
    BRIDGE_MEM32(info_ptr + 0x14) = is_free ? 0x01u : 0x04u;      /* NOACCESS : RW */
    BRIDGE_MEM32(info_ptr + 0x18) = is_free ? 0u : 0x20000u;      /* MEM_PRIVATE */

    if (g_kernel_call_count <= 200) {
        fprintf(stderr, "  [KERNEL] NtQueryVirtualMemory: addr=0x%08X -> base=0x%08X size=%u %s\n",
                base_address, region_base, region_size,
                is_free ? "FREE" : "COMMIT");
        fflush(stderr);
    }

    /* MEASUREMENT ONLY (2026-08-07): how far does the sweep actually travel?
     * The log shows a linear 64 KB walk from 0x04000000 (= XBOX_TOTAL_RAM)
     * upward, one step per call, because we report RegionSize = 0x10000 for
     * every address above RAM - the caller advances by exactly what we tell
     * it. Open question this answers: does the walk terminate at 0xFFFFFFFF,
     * WRAP to 0 and start over (a true infinite loop), or stop early?
     * Logs every 4096th call only, and deliberately does NOT emit a
     * "[KERNEL] #" line, so the kernel_calls signal stays comparable. */
    {
        static uint32_t qvm_calls = 0, qvm_wraps = 0, qvm_prev = 0;
        if (qvm_calls && base_address < qvm_prev) qvm_wraps++;
        qvm_prev = base_address;
        if ((++qvm_calls & 0xFFFu) == 0) {
            fprintf(stderr, "  [QVMSWEEP] call=%u addr=0x%08X %s backsteps=%u\n",
                    qvm_calls, base_address, in_ram ? "COMMIT" : "FREE", qvm_wraps);
            fflush(stderr);
        }
    }

    c->eax = 0;                          /* STATUS_SUCCESS */
}

static void bridge_NtQueryVolumeInformationFile(RecompCtx* c)
{
    HANDLE   handle    = bridge_read_handle(STACK_ARG(0));
    uint32_t ios_va    = STACK_ARG(1);
    uint32_t info_va   = STACK_ARG(2);
    uint32_t length    = STACK_ARG(3);
    uint32_t infoclass = STACK_ARG(4);
    XBOX_IO_STATUS_BLOCK ios;

    memset(&ios, 0, sizeof(ios));
    c->eax = (uint32_t)xbox_NtQueryVolumeInformationFile(handle, &ios,
                XBOX_TO_NATIVE(info_va), length,
                (XBOX_FS_INFORMATION_CLASS)infoclass);
    bridge_write_iostatus(ios_va, ios.Status, (uint32_t)ios.Information);
}

/* ── NtQueryFullAttributesFile (ordinal 210, 2 args = 8 bytes) */
static void bridge_NtQueryFullAttributesFile(RecompCtx* c)
{
    uint32_t obj_attrs = STACK_ARG(0);
    uint32_t info_va   = STACK_ARG(1);
    XBOX_OBJECT_ATTRIBUTES oa;
    XBOX_ANSI_STRING       name;

    bridge_build_oa(obj_attrs, &oa, &name);
    if (!name.Buffer) { c->eax = STATUS_OBJECT_PATH_NOT_FOUND; return; }
    c->eax = (uint32_t)xbox_NtQueryFullAttributesFile(&oa,
                (PXBOX_FILE_NETWORK_OPEN_INFORMATION)XBOX_TO_NATIVE(info_va));
}

/* ── NtFlushBuffersFile (ordinal 198, 2 args = 8 bytes) ─── */
static void bridge_NtFlushBuffersFile(RecompCtx* c)
{
    HANDLE   handle = bridge_read_handle(STACK_ARG(0));
    uint32_t ios_va = STACK_ARG(1);
    XBOX_IO_STATUS_BLOCK ios;

    memset(&ios, 0, sizeof(ios));
    c->eax = (uint32_t)xbox_NtFlushBuffersFile(handle, &ios);
    bridge_write_iostatus(ios_va, ios.Status, (uint32_t)ios.Information);
}

/* ── NtDeleteFile (ordinal 195, 1 arg = 4 bytes) ─────── */
static void bridge_NtDeleteFile(RecompCtx* c)
{
    XBOX_OBJECT_ATTRIBUTES oa;
    XBOX_ANSI_STRING       name;

    bridge_build_oa(STACK_ARG(0), &oa, &name);
    if (!name.Buffer) { c->eax = STATUS_OBJECT_PATH_NOT_FOUND; return; }
    c->eax = (uint32_t)xbox_NtDeleteFile(&oa);
}

/* ── NtQueryDirectoryFile (ordinal 207, 9 args = 36 bytes) ─ */
static void bridge_NtQueryDirectoryFile(RecompCtx* c)
{
    HANDLE   handle      = bridge_read_handle(STACK_ARG(0));
    uint32_t ios_va      = STACK_ARG(4);
    uint32_t info_va     = STACK_ARG(5);
    uint32_t length      = STACK_ARG(6);
    uint32_t filename_va = STACK_ARG(7);  /* PXBOX_ANSI_STRING */
    uint32_t restart     = STACK_ARG(8);  /* BOOLEAN */
    XBOX_IO_STATUS_BLOCK ios;
    XBOX_ANSI_STRING     fn;
    PXBOX_ANSI_STRING    pfn = NULL;

    memset(&ios, 0, sizeof(ios));
    if (filename_va) {
        /* Xbox ANSI_STRING: 0=Length(u16), 2=MaximumLength(u16), 4=Buffer(u32) */
        uint32_t fn_buf  = BRIDGE_MEM32(filename_va + 4);
        fn.Length        = BRIDGE_MEM16(filename_va);
        fn.MaximumLength = BRIDGE_MEM16(filename_va + 2);
        fn.Buffer        = fn_buf ? (PCHAR)XBOX_TO_NATIVE(fn_buf) : NULL;
        if (fn.Buffer) pfn = &fn;
    }
    c->eax = (uint32_t)xbox_NtQueryDirectoryFile(handle, NULL, NULL, NULL, &ios,
                XBOX_TO_NATIVE(info_va), length, pfn, (BOOLEAN)restart);
    bridge_write_iostatus(ios_va, ios.Status, (uint32_t)ios.Information);
}

/* ── NtOpenSymbolicLinkObject (ordinal 203, 2 args = 8 bytes) */
static void bridge_NtOpenSymbolicLinkObject(RecompCtx* c)
{
    uint32_t handle_va = STACK_ARG(0);
    /* arg1: POBJECT_ATTRIBUTES - ignored, we return a synthetic handle.
     * Written raw (untagged) so NtClose recognises it and skips it. */
    if (handle_va) BRIDGE_MEM32(handle_va) = 0xDEAD0001u;
    c->eax = STATUS_SUCCESS;
}

/* ── NtQuerySymbolicLinkObject (ordinal 215, 3 args = 12 bytes) */
static void bridge_NtQuerySymbolicLinkObject(RecompCtx* c)
{
    /* uint32_t handle = STACK_ARG(0); */
    uint32_t target_va = STACK_ARG(1);
    uint32_t retlen_va = STACK_ARG(2);
    const char* target = "\\Device\\CdRom0";
    USHORT len = (USHORT)strlen(target);

    if (target_va) {
        uint16_t max_len = BRIDGE_MEM16(target_va + 2);
        uint32_t buf_va  = BRIDGE_MEM32(target_va + 4);
        if (buf_va && len < max_len) {
            memcpy(XBOX_TO_NATIVE(buf_va), target, len + 1);
            BRIDGE_MEM16(target_va) = len;
        }
    }
    if (retlen_va) BRIDGE_MEM32(retlen_va) = (uint32_t)len;
    c->eax = STATUS_SUCCESS;
}

/* ── IoCreateFile (ordinal 67, 10 args = 40 bytes) ────── */
static void bridge_IoCreateFile(RecompCtx* c)
{
    /* Same as NtCreateFile with an extra Options arg at the end */
    uint32_t handle_va   = STACK_ARG(0);
    uint32_t access      = STACK_ARG(1);
    uint32_t obj_attrs   = STACK_ARG(2);
    uint32_t iostatus    = STACK_ARG(3);
    uint32_t file_attrs  = STACK_ARG(5);
    uint32_t share       = STACK_ARG(6);
    uint32_t disposition = STACK_ARG(7);
    uint32_t options     = STACK_ARG(8);

    c->eax = (uint32_t)bridge_create_file_impl(
        handle_va, access, obj_attrs, iostatus,
        file_attrs, share, disposition, options);
}

/* ── NtDeviceIoControlFile (ordinal 196, 10 args = 40 bytes) */
static void bridge_NtDeviceIoControlFile(RecompCtx* c)
{
    uint32_t ioctl = STACK_ARG(5);
    uint32_t ios_va = STACK_ARG(4);
    fprintf(stderr, "  [FILE] NtDeviceIoControlFile(0x%X) - stub\n", ioctl);
    bridge_write_iostatus(ios_va, 0xC00000BBu, 0);
    c->eax = 0xC00000BBu; /* STATUS_NOT_IMPLEMENTED */
}

/* ── NtFsControlFile (ordinal 200, 10 args = 40 bytes) ──── */
static void bridge_NtFsControlFile(RecompCtx* c)
{
    uint32_t fsctl = STACK_ARG(5);
    uint32_t ios_va = STACK_ARG(4);
    fprintf(stderr, "  [FILE] NtFsControlFile(0x%X) - stub\n", fsctl);
    bridge_write_iostatus(ios_va, 0xC00000BBu, 0);
    c->eax = 0xC00000BBu;
}

/* ── NtCreateDirectoryObject (ordinal 188) ──────────────── */
static void bridge_NtCreateDirectoryObject(RecompCtx* c)
{
    /* Return STATUS_SUCCESS with a fake handle */
    uint32_t handle_ptr = STACK_ARG(0);
    if (handle_ptr) BRIDGE_MEM32(handle_ptr) = 0xBEEF0010;
    c->eax = 0;  /* STATUS_SUCCESS */
}

/* ── IoCreateSymbolicLink (ordinal 63) ───────────────────── */
static void bridge_IoCreateSymbolicLink(RecompCtx* c)
{
    c->eax = 0;  /* STATUS_SUCCESS */
}

/* ── ObReferenceObjectByHandle (ordinal 246) ─────────────── */
static void bridge_ObReferenceObjectByHandle(RecompCtx* c)
{
    /* Xbox: NTSTATUS ObReferenceObjectByHandle(HANDLE Handle, PVOID ObjectType, PVOID* Object)
     * 3 args (not 6 like Windows NT) */
    uint32_t handle = STACK_ARG(0);
    uint32_t obj_type = STACK_ARG(1);
    uint32_t object_ptr = STACK_ARG(2);
    if (object_ptr) BRIDGE_MEM32(object_ptr) = 0;
    c->eax = 0;  /* STATUS_SUCCESS */
}

/* ── RtlRaiseException (ordinal 302) ─────────────────────
 * VOID RtlRaiseException(PEXCEPTION_RECORD ExceptionRecord)
 *
 * Called by CRT / SEH code to raise structured exceptions.
 * On Xbox this triggers the kernel exception dispatcher.
 * For recompilation, we log and continue (no real SEH dispatch yet).
 */
static void bridge_RtlRaiseException(RecompCtx* c)
{
    uint32_t record_ptr = STACK_ARG(0);
    uint32_t code = record_ptr ? BRIDGE_MEM32(record_ptr) : 0;

    static int raise_count = 0;
    raise_count++;
    if (raise_count <= 10) {
        fprintf(stderr, "  [KERNEL] RtlRaiseException: record=0x%08X code=0x%08X (#%d)\n",
                record_ptr, code, raise_count);
        fflush(stderr);
    }

    /* Handle float exceptions by clearing the FPU status.
     *
     * On the real Xbox, RtlRaiseException dispatches through the SEH chain.
     * For float exceptions (0xC0000090-0xC0000096), the CRT exception handler
     * clears the x87/SSE status word and continues execution. Without clearing,
     * the caller re-checks the FPU status, sees the exception still pending,
     * and re-raises in an infinite loop.
     *
     * _clearfp() clears both x87 and SSE exception flags on Windows x64.
     */
    if (code >= 0xC0000090u && code <= 0xC0000096u) {
        _clearfp();
    }

    c->eax = 0;
}

/* ── MmMapIoSpace (ordinal 177) ──────────────────────────
 * PVOID MmMapIoSpace(ULONG_PTR PhysicalAddress, ULONG NumberOfBytes, ULONG Protect)
 *
 * Maps physical I/O memory (GPU registers, etc.) into virtual address space.
 * Allocate from Xbox heap so the returned pointer is a valid Xbox VA.
 */
static void bridge_MmMapIoSpace(RecompCtx* c)
{
    uint32_t phys_addr = STACK_ARG(0);
    uint32_t num_bytes = STACK_ARG(1);
    uint32_t protect = STACK_ARG(2);
    uint32_t xbox_va = xbox_HeapAlloc(num_bytes, 4096);

    fprintf(stderr, "  [KERNEL] MmMapIoSpace: phys=0x%08X size=%u → Xbox VA 0x%08X\n",
            phys_addr, num_bytes, xbox_va);
    fflush(stderr);

    c->eax = xbox_va;
}

/* ── MmPersistContiguousMemory (ordinal 178) ─────────────
 * VOID MmPersistContiguousMemory(PVOID BaseAddress, ULONG NumberOfBytes, BOOLEAN Persist)
 *
 * Marks contiguous memory as persistent across reboots (for save data).
 * No-op for recompilation.
 */
static void bridge_MmPersistContiguousMemory(RecompCtx* c)
{
    /* No-op stub */
    c->eax = 0;
}

/* ── Generic fallback for simple value-only functions ────── */
static void bridge_generic_stub(RecompCtx* c)
{
    /* Success-returning stub for functions whose callers only check for 0.
     * Deliberately silent: the caller (kernel_thunk_dispatch) warns for
     * ordinals with no bridge at all, which is the case worth hearing about. */
    c->eax = 0;
}

/* ── Dispatch table: ordinal → bridge function + stack arg bytes ── */

typedef void (*bridge_func_t)(RecompCtx*);

/**
 * stdcall arg byte count for each kernel ordinal.
 * On x86 stdcall, the callee cleans (ret N). Our bridges must do the same
 * via c->esp += N after execution so the simulated stack stays balanced.
 *
 * Special cases:
 *   - KfRaiseIrql/KfLowerIrql: fastcall (arg in ecx), 0 stack bytes
 *   - KeSetTimer: DueTime is LARGE_INTEGER (8 bytes on stack) + Timer + Dpc
 */
static int stdcall_args_for_ordinal(ULONG ordinal)
{
    switch (ordinal) {
    /* ── Display / AV ── */
    case   1: return  0;  /* AvGetSavedDataAddress(void) */
    case   2: return 16;  /* AvSendTVEncoderOption(4) */
    case   3: return 24;  /* AvSetDisplayMode(6) */
    case   4: return  4;  /* AvSetSavedDataAddress(1) */

    /* ── Unknown stubs ── */
    case   8: return  0;  /* Unknown_8(void) */
    case  23: return  0;  /* Unknown_23(void) */
    case  42: return  0;  /* Unknown_42(void) */

    /* ── Pool Allocator ── */
    case  15: return  4;  /* ExAllocatePool(1) */
    case  16: return  8;  /* ExAllocatePoolWithTag(2) */
    /* case  17: DATA export - ExEventObjectType */
    case  24: return  4;  /* ExQueryPoolBlockSize(1) */

    /* ── HAL ── */
    case  40: return  4;  /* HalClearSoftwareInterrupt(1) */
    case  41: return  8;  /* HalDisableSystemInterrupt(2) */
    case  44: return  8;  /* HalGetInterruptVector(2) */
    case  46: return  8;  /* HalReadSMCTrayState(2) */
    /* Ordinal 47 takes TWO args (8 bytes), not six.
     *
     * This table previously said 24 (HalReadWritePCISpace), which contradicted
     * the handler table below - that maps ordinal 47 to
     * bridge_HalReadSMCTrayState, a 2-argument function. The disagreement was
     * live: the bridge popped 24 bytes of "arguments" when the caller had
     * pushed 8, so every call to ordinal 47 silently raised the simulated
     * stack by 16 bytes.
     *
     * Verified against the game's own call site (sub_001A23F3, 0x001A23FF):
     *
     *     push ebx            ; = 1
     *     push 0x461694       ; a .data pointer
     *     call dword ptr [0x3C6CD0]   ; thunk slot 76 -> ordinal 47
     *
     * Two pushes, so 8 bytes. The (pointer, TRUE) shape matches
     * HalRegisterShutdownNotification(Registration, Register) rather than
     * either name above; what matters here is the argument count.
     *
     * Symptom this caused: the 16-byte over-pop left the caller's esp above
     * its own locals, so the next `push` wrote INTO the 0x30-byte struct at
     * ebp-0x34 and the following `mov [ebp-0x34], 0x30` overwrote the pointer
     * that had just been passed - the callee then received 0x30 as an address.
     * See DEBUGGING_NOTES.md. */
    case  47: return  8;
    case  49: return  4;  /* HalRequestSoftwareInterrupt(1) */
    case 358: return  0;  /* HalIsResetOrShutdownPending(void) */

    /* ── I/O Manager ── */
    case  62: return 36;  /* IoBuildDeviceIoControlRequest(9) */
    /* case  65: DATA export - IoCompletionObjectType */
    case  67: return 40;  /* IoCreateFile(10) */
    case  69: return  4;  /* IoDeleteDevice(1) */
    /* case  71: DATA export - IoDeviceObjectType */
    case  74: return 12;  /* IoInitializeIrp(3) */
    case  81: return 20;  /* IoSetIoCompletion(5) */
    case  83: return  8;  /* IoStartNextPacket(2) */
    case  84: return 12;  /* IoStartNextPacketByKey(3) */
    case  85: return 16;  /* IoStartPacket(4) */
    case  86: return 32;  /* IoSynchronousDeviceIoControlRequest(8) */
    case  87: return 20;  /* IoSynchronousFsdRequest(5) */
    case 359: return  4;  /* IoMarkIrpMustComplete(1) */

    /* ── Kernel Synchronization ── */
    case  95: return  8;  /* KeAlertThread(2) */
    case  97: return  4;  /* KeBugCheck(1) */
    case  98: return 20;  /* KeBugCheckEx(5) */
    case  99: return  4;  /* KeCancelTimer(1) */
    case 100: return  4;  /* KeConnectInterrupt(1) */
    case 107: return 12;  /* KeInitializeDpc(3) */
    case 109: return 28;  /* KeInitializeInterrupt(7) */
    case 113: return  8;  /* KeInitializeTimerEx(2) */
    case 119: return 12;  /* KeInsertQueueDpc(3) */
    case 124: return  4;  /* KeQueryBasePriorityThread(1) */
    case 126: return  0;  /* KeQueryPerformanceCounter(void) */
    case 127: return  0;  /* KeQueryPerformanceFrequency(void) */
    case 128: return  4;  /* KeQuerySystemTime(1) */
    case 129: return  0;  /* KeRaiseIrqlToDpcLevel(void) */
    case 137: return  4;  /* KeRemoveQueueDpc(1) */
    case 139: return  4;  /* KeRestoreFloatingPointState(1) */
    case 142: return  4;  /* KeSaveFloatingPointState(1) */
    case 143: return  8;  /* KeSetBasePriorityThread(2) */
    case 145: return 12;  /* KeSetEvent(3) */
    case 149: return 16;  /* KeSetTimer(Timer+DueTime[8]+Dpc) */
    case 150: return 20;  /* KeSetTimerEx(Timer+DueTime[8]+Period+Dpc) */
    case 151: return  4;  /* KeStallExecutionProcessor(1) */
    case 153: return 12;  /* KeSynchronizeExecution(3) */
    /* case 156: DATA export - KeTickCount */
    case 158: return 32;  /* KeWaitForMultipleObjects(8) */
    case 159: return 20;  /* KeWaitForSingleObject(5) */
    case 160: return  0;  /* KfRaiseIrql (fastcall: arg in ecx) */
    case 161: return  0;  /* KfLowerIrql (fastcall: arg in ecx) */

    /* ── Launch Data ── */
    /* case 164: DATA export - LaunchDataPage */

    /* ── Memory Management ── */
    case 165: return  4;  /* MmAllocateContiguousMemory(1) */
    case 166: return 20;  /* MmAllocateContiguousMemoryEx(5) */
    case 168: return  8;  /* MmClaimGpuInstanceMemory(2) */
    case 169: return  8;  /* MmCreateKernelStack(2) */
    case 170: return  8;  /* MmDeleteKernelStack(2) */
    case 171: return  4;  /* MmFreeContiguousMemory(1) */
    case 173: return  4;  /* MmGetPhysicalAddress(1) */
    case 175: return 12;  /* MmLockUnlockBufferPages(3) */
    case 176: return  8;  /* MmLockUnlockPhysicalPage(2) */
    case 177: return 12;  /* MmMapIoSpace(3) */
    case 178: return 12;  /* MmPersistContiguousMemory(3) */
    case 179: return  4;  /* MmQueryAddressProtect(1) */
    case 180: return  4;  /* MmQueryAllocationSize(1) */
    case 181: return  4;  /* MmQueryStatistics(1) */
    case 182: return 12;  /* MmSetAddressProtect(3) */

    /* ── NT Virtual Memory ── */
    case 184: return 20;  /* NtAllocateVirtualMemory(5) */

    /* ── NT File I/O & Handle ── */
    case 187: return  4;  /* NtClose(1) */
    case 189: return 16;  /* NtCreateEvent(4) */
    case 190: return 36;  /* NtCreateFile(9) */
    case 193: return 16;  /* NtCreateSemaphore(4) */
    case 195: return  4;  /* NtDeleteFile(1) */
    case 196: return 40;  /* NtDeviceIoControlFile(10) */
    case 197: return 12;  /* NtDuplicateObject(3) */
    case 198: return  8;  /* NtFlushBuffersFile(2) */
    case 199: return 12;  /* NtFreeVirtualMemory(3) */
    case 200: return 40;  /* NtFsControlFile(10) */
    case 202: return 24;  /* NtOpenFile(6) */
    case 203: return  8;  /* NtOpenSymbolicLinkObject(2) */
    case 207: return 36;  /* NtQueryDirectoryFile(9) */
    case 210: return  8;  /* NtQueryFullAttributesFile(2) */
    case 211: return 20;  /* NtQueryInformationFile(5) */
    case 215: return 12;  /* NtQuerySymbolicLinkObject(3) */
    /* NtQueryVirtualMemory takes TWO args on Xbox, not the four the NT
     * signature in docs/formats/kernel-exports.md lists. Measured: with 16
     * here, esp climbed exactly 8 bytes on each of 3,966 calls and walked off
     * the top of the 8 MB stack. See bridge_NtQueryVirtualMemory. */
    case 217: return 8;   /* NtQueryVirtualMemory(2) */
    case 218: return 20;  /* NtQueryVolumeInformationFile(5) */
    case 219: return 32;  /* NtReadFile(8) */
    case 222: return 12;  /* NtReleaseSemaphore(3) */
    case 225: return  8;  /* NtSetEvent(2) */
    case 226: return 20;  /* NtSetInformationFile(5) */
    case 228: return  8;  /* NtSetSystemTime(2) */
    case 233: return 20;  /* NtWaitForMultipleObjectsEx(5) */
    case 234: return 12;  /* NtWaitForSingleObject(3) */
    case 236: return 32;  /* NtWriteFile(8) */
    case 238: return  0;  /* NtYieldExecution(void) */

    /* ── Object Manager ── */
    case 246: return 12;  /* ObReferenceObjectByHandle(3) - Xbox: Handle,Type,Object* */
    case 247: return 20;  /* ObReferenceObjectByName(5) */
    case 250: return  0;  /* ObfDereferenceObject (fastcall: arg in ecx) */

    /* ── Network / PHY ── */
    case 252: return  4;  /* PhyGetLinkState(1) */
    case 253: return  8;  /* PhyInitialize(2) */

    /* ── Threading ── */
    case 255: return 40;  /* PsCreateSystemThreadEx(10) */
    case 256: return 12;  /* KeDelayExecutionThread(3) */
    case 258: return  4;  /* PsTerminateSystemThread(1) */
    /* case 259: DATA export - PsThreadObjectType */

    /* ── Runtime Library ── */
    case 260: return 12;  /* RtlAnsiStringToUnicodeString(3) */
    case 269: return 12;  /* RtlCompareMemoryUlong(3) */
    case 277: return  4;  /* RtlEnterCriticalSection(1) */
    case 279: return 12;  /* RtlEqualString(3) */
    case 289: return  8;  /* RtlInitAnsiString(2) */
    case 291: return  4;  /* RtlInitializeCriticalSection(1) */
    case 294: return  4;  /* RtlLeaveCriticalSection(1) */
    case 301: return  4;  /* RtlNtStatusToDosError(1) */
    case 302: return  4;  /* RtlRaiseException(1) */
    case 304: return  8;  /* RtlTimeFieldsToTime(2) */
    case 305: return  8;  /* RtlTimeToTimeFields(2) */
    case 308: return 12;  /* RtlUnicodeStringToAnsiString(3) */
    case 312: return 16;  /* RtlUnwind(4) */
    case 354: return 12;  /* RtlRip(3) */

    /* ── Xbox Identity (data exports) ── */
    /* cases 322-328, 355-357: DATA exports */

    /* ── Port I/O ── */
    case 335: return 12;  /* WRITE_PORT_BUFFER_USHORT(3) */
    case 336: return 12;  /* WRITE_PORT_BUFFER_ULONG(3) */

    /* ── Crypto ── */
    case 337: return  4;  /* XcSHAInit(1) */
    case 338: return 12;  /* XcSHAUpdate(3) */
    case 339: return  8;  /* XcSHAFinal(2) */
    case 340: return 12;  /* XcRC4Key(3) */
    case 344: return 12;  /* XcPKDecPrivate(3) */
    case 345: return  4;  /* XcPKGetKeyLen(1) */
    case 346: return 12;  /* XcVerifyPKCS1Signature(3) */
    case 347: return 20;  /* XcModExp(5) */
    case 349: return 12;  /* XcKeyTable(3) */
    case 353: return  8;  /* XcUpdateCrypto(2) */

    default:  return  0;  /* DATA exports or truly unknown */
    }
}

static bridge_func_t bridge_for_ordinal(ULONG ordinal)
{
    switch (ordinal) {
    /* Threading */
    case 255: return bridge_PsCreateSystemThreadEx;
    case 258: return bridge_PsTerminateSystemThread;

    /* File/Handle */
    case 187: return bridge_NtClose;
    case 190: return bridge_NtCreateFile;
    case 195: return bridge_NtDeleteFile;
    case 196: return bridge_NtDeviceIoControlFile;
    case 198: return bridge_NtFlushBuffersFile;
    case 200: return bridge_NtFsControlFile;
    case 202: return bridge_NtOpenFile;
    case 203: return bridge_NtOpenSymbolicLinkObject;
    case 207: return bridge_NtQueryDirectoryFile;
    case 210: return bridge_NtQueryFullAttributesFile;
    case 211: return bridge_NtQueryInformationFile;
    case 217: return bridge_NtQueryVirtualMemory;
    case 218: return bridge_NtQueryVolumeInformationFile;
    case 219: return bridge_NtReadFile;
    case 226: return bridge_NtSetInformationFile;
    case 236: return bridge_NtWriteFile;

    /* Memory - contiguous */
    case 165: return bridge_MmAllocateContiguousMemory;
    case 166: return bridge_MmAllocateContiguousMemoryEx;
    case 171: return bridge_MmFreeContiguousMemory;
    case 173: return bridge_MmGetPhysicalAddress;
    case 181: return bridge_MmQueryStatistics;
    case 182: return bridge_MmSetAddressProtect;

    /* Memory - virtual */
    case 184: return bridge_NtAllocateVirtualMemory;
    case 199: return bridge_NtFreeVirtualMemory;

    /* Pool */
    case  15: return bridge_ExAllocatePool;
    case  16: return bridge_ExAllocatePoolWithTag;
    /* Ordinal 23 is ExQueryPoolBlockSize (1 arg); 24 is ExQueryNonVolatileSetting
     * (5 args). The upstream X-Men bridge had 24 mapped to the pool handler —
     * a 16-byte under-pop that corrupted the caller's frame. Route 24 to the
     * SDK's __imp__ExQueryNonVolatileSetting via the fallback (NULL here). */
    case  23: return bridge_ExQueryPoolBlockSize;

    /* IRQL */
    case 129: return bridge_KeRaiseIrqlToDpcLevel;
    case 160: return bridge_KfRaiseIrql;
    case 161: return bridge_KfLowerIrql;

    /* Critical sections */
    case 277: return bridge_RtlEnterCriticalSection;
    case 291: return bridge_RtlInitializeCriticalSection;
    case 294: return bridge_RtlLeaveCriticalSection;

    /* Timing */
    case 126: return bridge_KeQueryPerformanceCounter;
    case 127: return bridge_KeQueryPerformanceFrequency;
    case 128: return bridge_KeQuerySystemTime;
    case 149: return bridge_KeSetTimer;
    case 150: return bridge_KeSetTimer;  /* KeSetTimerEx */

    /* DPC / Timer init */
    case 107: return bridge_KeInitializeDpc;
    case 113: return bridge_KeInitializeTimerEx;

    /* Synchronization */
    case 145: return bridge_KeSetEvent;
    case 159: return bridge_KeWaitForSingleObject;
    case 189: return bridge_NtCreateEvent;
    case 238: return bridge_NtYieldExecution;

    /* Hardware */
    case  46: return bridge_HalReadSMCTrayState;          /* its real ordinal */
    case  47: return bridge_HalRegisterShutdownNotification;

    /* Display */
    case   3: return bridge_AvSetDisplayMode;

    /* I/O */
    case  63: return bridge_IoCreateSymbolicLink;
    case  67: return bridge_IoCreateFile;
    case 188: return bridge_NtCreateDirectoryObject;
    case 246: return bridge_ObReferenceObjectByHandle;

    /* Memory - I/O mapping */
    case 177: return bridge_MmMapIoSpace;
    case 178: return bridge_MmPersistContiguousMemory;

    /* RTL */
    case 301: return bridge_RtlNtStatusToDosError;
    case 302: return bridge_RtlRaiseException;

    default:  return NULL;
    }
}


/* ---- SDK glue: entry points the runtime calls -------------------------- */
bridge_func_t rex_bridge_for_ordinal(unsigned int ordinal) { return bridge_for_ordinal((ULONG)ordinal); }
int           rex_bridge_stdcall_bytes(unsigned int ordinal) { return stdcall_args_for_ordinal((ULONG)ordinal); }
void          rex_bridge_data_init(void) { kernel_data_init(); }
uint32_t      rex_bridge_data_va_for_ordinal(unsigned int o) { return kernel_data_va_for_ordinal((ULONG)o); }

static _Thread_local uint32_t s_lookup_target;
static void lookup_trampoline(RecompCtx* c) {
    extern void rex_dispatch(RecompCtx*, uint32_t);
    rex_dispatch(c, s_lookup_target);
}
static recomp_func_t recomp_lookup(uint32_t va) {
    extern int rex_has_fn(uint32_t);
    if (!rex_has_fn(va)) return 0;
    s_lookup_target = va;
    return lookup_trampoline;
}
