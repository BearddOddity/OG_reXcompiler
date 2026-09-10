/*
 * ogxbox_thunkfix.c — fix up the kernel-import thunk table after the image is
 * loaded.
 *
 * In the XBE, each kernel thunk slot holds 0x80000000 | ordinal. On real
 * hardware the loader rewrites each slot with a real pointer before the title
 * runs. We handle the two cases separately:
 *
 *   - FUNCTION exports stay as 0x80000000 | ordinal. The generated code reaches
 *     them via `call [slot]` -> rex_dispatch, which routes the high-bit value
 *     to rex_kernel_dispatch(ordinal) -> __imp__<Name>. No patch needed.
 *
 *   - DATA exports (type objects, XboxHardwareInfo, XboxKrnlVersion, keys, ...)
 *     are dereferenced by the game as pointers. Their slots must hold a real,
 *     readable guest address. We point them at a small kernel data area and
 *     populate it here.
 *
 * The data-area layout and values follow the X-Men Legends recomp's
 * kernel_bridge.c (same author).
 */
#include "ogxbox_runtime.h"
#include <stdio.h>
#include <windows.h>

/* Kernel data area — a gap above the XBE sections, below the guest stack.
 * Matches xbox_memory_layout.h (XBOX_KERNEL_DATA_BASE / KDATA_*). */
#define KDATA_BASE              0x00740000u
#define KDATA_HARDWARE_INFO     0x000u
#define KDATA_KRNL_VERSION      0x010u
#define KDATA_TICK_COUNT        0x020u
#define KDATA_LAUNCH_DATA_PAGE  0x030u
#define KDATA_THREAD_OBJ_TYPE   0x040u
#define KDATA_EVENT_OBJ_TYPE    0x050u
#define KDATA_XE_IMAGE_FILENAME 0x060u
#define KDATA_IO_COMPLETION_TYPE 0x070u
#define KDATA_IO_DEVICE_TYPE    0x080u
#define KDATA_HD_KEY            0x100u
#define KDATA_SIGNATURE_KEY     0x110u
#define KDATA_LAN_KEY           0x120u
#define KDATA_ALT_SIGNATURE_KEYS 0x130u
#define KDATA_XE_PUBLIC_KEY     0x300u

/* Generated (recomp_image.c): one entry per kernel import thunk slot. */
typedef struct { unsigned int slot_va, ordinal; } RexKThunk;
extern const RexKThunk       g_rex_kthunk[];
extern const unsigned int    g_rex_kthunk_count;

/* Xbox VA of the data for a DATA-export ordinal, or 0 if it is a function. */
static uint32_t kdata_va_for_ordinal(unsigned int ord) {
    switch (ord) {
    case  17: return KDATA_BASE + KDATA_EVENT_OBJ_TYPE;       /* ExEventObjectType */
    case  65: return KDATA_BASE + KDATA_IO_COMPLETION_TYPE;   /* IoCompletionObjectType */
    case  71: return KDATA_BASE + KDATA_IO_DEVICE_TYPE;       /* IoDeviceObjectType */
    case 156: return KDATA_BASE + KDATA_TICK_COUNT;           /* KeTickCount */
    case 164: return KDATA_BASE + KDATA_LAUNCH_DATA_PAGE;     /* LaunchDataPage */
    case 259: return KDATA_BASE + KDATA_THREAD_OBJ_TYPE;      /* PsThreadObjectType */
    case 322: return KDATA_BASE + KDATA_HARDWARE_INFO;        /* XboxHardwareInfo */
    case 323: return KDATA_BASE + KDATA_HD_KEY;               /* XboxHDKey */
    case 324: return KDATA_BASE + KDATA_KRNL_VERSION;         /* XboxKrnlVersion */
    case 325: return KDATA_BASE + KDATA_SIGNATURE_KEY;        /* XboxSignatureKey */
    case 326: return KDATA_BASE + KDATA_LAN_KEY;              /* XboxLANKey */
    case 327: return KDATA_BASE + KDATA_ALT_SIGNATURE_KEYS;   /* XboxAlternateSignatureKeys */
    case 328: return KDATA_BASE + KDATA_XE_IMAGE_FILENAME;    /* XeImageFileName */
    case 355: return KDATA_BASE + KDATA_LAN_KEY;              /* alias */
    case 356: return KDATA_BASE + KDATA_ALT_SIGNATURE_KEYS;   /* alias */
    case 357: return KDATA_BASE + KDATA_XE_PUBLIC_KEY;        /* XePublicKeyData */
    default:  return 0;
    }
}

static void kdata_init(void) {
    /* XBOX_HARDWARE_INFO: Flags (0 = retail), GpuRevision, McpRevision */
    MEM32(KDATA_BASE + KDATA_HARDWARE_INFO + 0) = 0;
    MEM8 (KDATA_BASE + KDATA_HARDWARE_INFO + 4) = 0xA1;   /* NV2A A1 */
    MEM8 (KDATA_BASE + KDATA_HARDWARE_INFO + 5) = 0xB1;   /* MCPX B1 */

    /* XBOX_KRNL_VERSION: Major.Minor.Build.Qfe */
    MEM16(KDATA_BASE + KDATA_KRNL_VERSION + 0) = 1;
    MEM16(KDATA_BASE + KDATA_KRNL_VERSION + 2) = 0;
    MEM16(KDATA_BASE + KDATA_KRNL_VERSION + 4) = 5849;
    MEM16(KDATA_BASE + KDATA_KRNL_VERSION + 6) = 0;

    MEM32(KDATA_BASE + KDATA_TICK_COUNT) = GetTickCount();
    MEM32(KDATA_BASE + KDATA_LAUNCH_DATA_PAGE) = 0;
    MEM32(KDATA_BASE + KDATA_THREAD_OBJ_TYPE) = 0;
    MEM32(KDATA_BASE + KDATA_EVENT_OBJ_TYPE) = 0;
    MEM32(KDATA_BASE + KDATA_IO_COMPLETION_TYPE) = 0;
    MEM32(KDATA_BASE + KDATA_IO_DEVICE_TYPE) = 0;

    memset(XBOX_PTR(KDATA_BASE + KDATA_HD_KEY), 0, 16);
    memset(XBOX_PTR(KDATA_BASE + KDATA_SIGNATURE_KEY), 0, 16);
    memset(XBOX_PTR(KDATA_BASE + KDATA_LAN_KEY), 0, 16);
    memset(XBOX_PTR(KDATA_BASE + KDATA_ALT_SIGNATURE_KEYS), 0, 256);
    memset(XBOX_PTR(KDATA_BASE + KDATA_XE_PUBLIC_KEY), 0, 284);
    /* XeImageFileName: an empty ANSI_STRING {Length=0, Max=0, Buffer=0} */
    MEM16(KDATA_BASE + KDATA_XE_IMAGE_FILENAME + 0) = 0;
    MEM16(KDATA_BASE + KDATA_XE_IMAGE_FILENAME + 2) = 0;
    MEM32(KDATA_BASE + KDATA_XE_IMAGE_FILENAME + 4) = 0;
}

/* KeTickCount ticker — the game polls it for timing. */
static DWORD WINAPI tick_thread(LPVOID p) {
    (void)p;
    for (;;) { MEM32(KDATA_BASE + KDATA_TICK_COUNT) = GetTickCount(); Sleep(1); }
}

void ogxbox_thunkfix_run(void) {
    kdata_init();

    unsigned int data_slots = 0, func_slots = 0;
    for (unsigned int i = 0; i < g_rex_kthunk_count; i++) {
        uint32_t slot = g_rex_kthunk[i].slot_va;
        uint32_t ord  = g_rex_kthunk[i].ordinal;
        uint32_t dva  = kdata_va_for_ordinal(ord);
        if (dva) { MEM32(slot) = dva; data_slots++; }
        else     { MEM32(slot) = 0x80000000u | ord; func_slots++; }
    }
    fprintf(stderr, "[ogxbox] thunkfix: %u data exports patched, %u function "
                    "slots left as ordinals\n", data_slots, func_slots);

    CloseHandle(CreateThread(NULL, 0, tick_thread, NULL, 0, NULL));
}
