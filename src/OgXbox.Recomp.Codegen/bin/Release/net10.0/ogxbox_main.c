/*
 * ogxbox_main.c — minimal host entry point for a recompiled OG Xbox title.
 *
 * A real port replaces this with its own main() and wires in a proper kernel /
 * graphics / audio / input layer. This one just boots the guest and reports.
 */
#include "ogxbox_runtime.h"
#include <stdio.h>

int main(int argc, char** argv) {
    const char* image = argc > 1 ? argv[1] : "recomp_image.bin";
    fprintf(stderr, "[ogxbox] booting %s\n", image);
    int rc = rex_boot(image);
    fprintf(stderr, "[ogxbox] guest returned %d\n", rc);
    return rc < 0 ? 1 : 0;
}
