/*
 * ogxbox_kernel_glue.c — links the vendored X-Men kernel + ogxbox_bridge.c to
 * the SDK runtime.
 *
 *   - xbox_Heap* over the SDK bump allocator (the vendored xbox_memory_layout.c
 *     is NOT compiled; the SDK owns guest RAM).
 *   - a stub xbox_MemoryLayoutInit (same reason).
 *   - rex_kernel_dispatch: our PsCreateSystemThreadEx (real threads) wins for
 *     ordinal 255; otherwise the bridge's ~140 handlers; otherwise the
 *     generated per-ordinal fallback (hand-written __imp__ stubs / weak).
 */
#include "ogxbox_runtime.h"
#include <stdio.h>
#include <windows.h>

/* ---- memory-subsystem shims the vendored kernel expects ---------------- */
unsigned int g_xbox_total_ram = 0x04000000u;   /* retail 64 MB */

int xbox_MemoryLayoutInit(const void* xbe_data, size_t xbe_size) {
    (void)xbe_data; (void)xbe_size;
    return 1;   /* the SDK set memory up already (rex_boot) */
}

unsigned int xbox_HeapAlloc(unsigned int size, unsigned int alignment) {
    return rex_pool_alloc_aligned(size, alignment ? alignment : 16u);
}
unsigned int xbox_HeapAllocAt(unsigned int base, unsigned int size) {
    (void)size;
    return base;   /* honour the engine's chosen base (ledger #75) */
}
void xbox_HeapFree(unsigned int xbox_va) { (void)xbox_va; }   /* bump allocator */
unsigned int xbox_HeapHighWater(void) { return rex_pool_highwater(); }

/* ---- kernel ordinal dispatch ----------------------------------------- */
typedef void (*bridge_func_t)(RecompCtx*);
bridge_func_t rex_bridge_for_ordinal(unsigned int ordinal);
int           rex_bridge_stdcall_bytes(unsigned int ordinal);

void __imp__PsCreateSystemThreadEx(RecompCtx* c);       /* ogxbox_kernel.c */
void rex_kthunk_fallback(RecompCtx* c, unsigned int ordinal);  /* generated */

/* File-I/O ordinals: the bridge's handlers hit the host filesystem via the
 * vendored kernel and half-succeed (bad handles) without a mounted VFS. Route
 * them to the SDK's error-returning stubs until Phase B lands.
 *   190 NtCreateFile  202 NtOpenFile  219 NtReadFile  236 NtWriteFile
 *   207 NtQueryDirectoryFile  210 NtQueryFullAttributesFile
 *   211 NtQueryInformationFile  218 NtQueryVolumeInformationFile
 *   226 NtSetInformationFile  196 NtDeviceIoControlFile  200 NtFsControlFile
 *   195 NtDeleteFile  198 NtFlushBuffersFile  66/67 IoCreateFile */
static int prefer_fallback(unsigned int o) {
    switch (o) {
    /* file I/O — no VFS yet */
    case 190: case 202: case 219: case 236: case 207: case 210: case 211:
    case 218: case 226: case 196: case 200: case 195: case 198:
    case 66: case 67:
    /* virtual memory — the SDK stubs carve from the shared pool permissively;
     * the bridge's handlers reject some type flags and hand back 0 */
    case 184: case 199: case 217:
        return 1;
    default: return 0;
    }
}

void rex_kernel_dispatch(RecompCtx* c, unsigned int ordinal) {
    if (ordinal == 255) { __imp__PsCreateSystemThreadEx(c); return; }

    bridge_func_t b = prefer_fallback(ordinal) ? 0 : rex_bridge_for_ordinal(ordinal);
    if (b) {
        b(c);
        c->esp += 4u + (unsigned int)rex_bridge_stdcall_bytes(ordinal);  /* return slot + args */
        return;
    }
    rex_kthunk_fallback(c, ordinal);
}
