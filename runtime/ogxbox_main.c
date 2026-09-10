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

int main(int argc, char** argv) {
    const char* image = argc > 1 ? argv[1] : "recomp_image.bin";
    fprintf(stderr, "[ogxbox] booting %s\n", image);
    int rc = rex_boot(image);
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
        unsigned long n = g_rex_enter_count;
        fprintf(stderr, "[ogxbox] +%02.1fs  guest calls %lu (+%lu)  last @ 0x%08X\n",
                i * 0.5, n, n - last_count, g_rex_last_enter);
        last_count = n;
#endif
    }
    fprintf(stderr, "[ogxbox] host timeout, exiting\n");
    return rc < 0 ? 1 : 0;
}
