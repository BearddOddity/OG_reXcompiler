/*
 * ogxbox_main.c — minimal host entry point for a recompiled OG Xbox title.
 *
 * A real port replaces this with its own main() and a proper kernel / graphics
 * / audio / input layer. This one boots the guest, then keeps the process alive
 * so guest threads spawned during startup can run.
 */
#include "ogxbox_runtime.h"
#include <stdio.h>
#include <windows.h>

#ifdef REX_TRACE
/* OGX_WATCH=0xADDR — poll a guest dword and dump the guest call stack the
 * instant it changes. Finds the writer of a corrupted global. */
static DWORD WINAPI watch_thread(LPVOID p) {
    uint32_t va = (uint32_t)(uintptr_t)p;
    extern void rex_global_backtrace(void);
    uint32_t last = *(volatile uint32_t*)(g_guest_ram + va);
    for (;;) {
        uint32_t now = *(volatile uint32_t*)(g_guest_ram + va);
        if (now != last) {
            fprintf(stderr, "[ogxbox] WATCH 0x%08X: 0x%08X -> 0x%08X\n", va, last, now);
            rex_global_backtrace();
            last = now;
        }
    }
}
#endif

int main(int argc, char** argv) {
    const char* image = argc > 1 ? argv[1] : "recomp_image.bin";
    fprintf(stderr, "[ogxbox] booting %s\n", image);
    int rc = rex_boot(image);
#ifdef REX_TRACE
    { const char* w = getenv("OGX_WATCH");
      if (w && g_guest_ram) {
          uint32_t va = (uint32_t)strtoul(w, 0, 0);
          CloseHandle(CreateThread(0,0,watch_thread,(LPVOID)(uintptr_t)va,0,0));
      } }
#endif
    fprintf(stderr, "[ogxbox] entry returned %d; waiting on guest threads...\n", rc);

    /* The XBE entry point (CRT startup) typically spawns the game's main thread
     * and returns. Hold the process so those threads keep running, and sample
     * the guest-progress counters so we can tell running from stuck. */
    unsigned long last_count = 0;
    for (int i = 0; i < 30; i++) {
        Sleep(500);
#ifdef REX_TRACE
        extern volatile uint32_t g_rex_last_enter;
        extern volatile unsigned long g_rex_enter_count;
        extern void rex_global_backtrace(void);
        unsigned long n = g_rex_enter_count;
        fprintf(stderr, "[ogxbox] +%02.1fs  guest calls %lu (+%lu)  last @ 0x%08X\n",
                i * 0.5, n, n - last_count, g_rex_last_enter);
        if (n == last_count && i > 2 && (i % 6) == 0) rex_global_backtrace();
        last_count = n;
#endif
    }
    fprintf(stderr, "[ogxbox] host timeout, exiting\n");
    /* Guest threads are still running (usually spinning in engine init). A
     * normal `return` runs CRT teardown while they execute -> they fault on
     * memory being pulled out from under them. Kill the process outright. */
    fflush(stderr);
    ExitProcess((UINT)(rc < 0 ? 1 : 0));
}
