/*
 * ogxbox_tib.c — the per-thread block the guest reaches through `fs:`, plus the
 * fake Xbox-kernel page RenderWare pokes for CPU-cache sizing.
 *
 * Field layout and the reasoning behind each value follow the X-Men Legends
 * recomp's xbox_memory_layout.c (same author):
 *
 *   fs:[0x00]  SEH exception-list head   (-1 = end of chain)
 *   fs:[0x04]  __tls_index array base    (NOT NT_TIB StackBase — every guest
 *                                         read here is idx=[__tls_index];
 *                                         array=[fs:4]; block=[array+idx*4])
 *   fs:[0x08]  stack limit (low)
 *   fs:[0x18]  self pointer
 *   fs:[0x20]  KPCR Prcb pointer  (0 -> [+0x250] D3D-cache init is skipped)
 *   fs:[0x28]  RW engine context  (-> struct whose +0x28 is the RW data area)
 */
#include "ogxbox_runtime.h"
#include <stdio.h>
#include <windows.h>

#define TIB_VA            0x00770000u
#define TLS_ARRAY_VA      0x00750000u
#define TLS_BLOCK_VA      0x00751000u
#define TLS_SLOTS         16u
#define TLS_BLOCK_SZ      0x100u
#define RW_CTX_VA         0x00760000u
#define RW_DATA_VA        0x00700000u

#define XBOX_STACK_BASE   0x00780000u   /* low address of the guest stack area */

uint32_t ogxbox_tib_setup(void) {
    MEM32(TIB_VA + 0x00) = 0xFFFFFFFFu;        /* SEH: end of chain */
    MEM32(TIB_VA + 0x04) = TLS_ARRAY_VA;       /* __tls_index array */
    MEM32(TIB_VA + 0x08) = XBOX_STACK_BASE;    /* stack limit */
    MEM32(TIB_VA + 0x18) = TIB_VA;             /* self */
    MEM32(TIB_VA + 0x20) = 0;                  /* KPCR Prcb -> null: skip D3D cache */
    MEM32(TIB_VA + 0x28) = RW_CTX_VA;          /* RW engine context */

    for (uint32_t i = 0; i < TLS_SLOTS; i++)
        MEM32(TLS_ARRAY_VA + i * 4) = TLS_BLOCK_VA + i * TLS_BLOCK_SZ;
    memset(XBOX_PTR(TLS_BLOCK_VA), 0, TLS_SLOTS * TLS_BLOCK_SZ);

    MEM32(RW_CTX_VA + 0x28) = RW_DATA_VA;      /* RW data area pointer */

    fprintf(stderr, "[ogxbox] TIB at VA 0x%08X (fs base); TLS array 0x%08X x%u; "
                    "fs[0x28] ctx 0x%08X\n", TIB_VA, TLS_ARRAY_VA, TLS_SLOTS, RW_CTX_VA);
    return TIB_VA;
}

/* Xbox kernel image page. RenderWare's xbcache.c reads MEM32(0x8001003C) — the
 * DOS header e_lfanew — walks to the PE header, and reads NumberOfSections to
 * size CPU cache lines. A zero-section PE header makes it skip that cleanly.
 * The reserve window in rex_boot already covers this address; commit it. */
void ogxbox_kernel_page_setup(void) {
    void* p = VirtualAlloc(XBOX_PTR(0x80010000u), 0x1000u, MEM_COMMIT, PAGE_READWRITE);
    if (!p) { fprintf(stderr, "[ogxbox] kernel page commit failed (err %lu)\n", GetLastError()); return; }
    memset(p, 0, 0x1000u);
    MEM16(0x80010000u) = 0x5A4D;               /* 'MZ' */
    MEM32(0x80010000u + 0x3C) = 0x80u;         /* e_lfanew -> PE header at +0x80 */
    MEM32(0x80010000u + 0x80) = 0x00004550u;   /* 'PE\0\0' */
    MEM16(0x80010000u + 0x80 + 4) = 0x014C;    /* Machine: i386 */
    MEM16(0x80010000u + 0x80 + 6) = 0;         /* NumberOfSections = 0 */
    fprintf(stderr, "[ogxbox] fake xboxkrnl page at VA 0x80010000 (0-section PE)\n");
}
