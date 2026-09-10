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
     * and returns. Hold the process so those threads keep running. */
    Sleep(15000);
    fprintf(stderr, "[ogxbox] host timeout, exiting\n");
    return rc < 0 ? 1 : 0;
}
