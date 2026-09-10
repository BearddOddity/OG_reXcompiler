/* ogxbox — the recompiler CLI (C).
 *
 *   ogxbox analyze <game.xbe> -o <dir> [--config t.toml] [--seed a,b,...]
 *   ogxbox emit    <game.xbe> -o <dir> [--config t.toml] [--seed a,b,...]
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "xbe.h"
#include "binary_view.h"
#include "decoded.h"

static int usage(void) {
    fprintf(stderr, "usage: ogxbox <analyze|emit> <file.xbe> -o <dir> [--config f.toml] [--seed a,b,...]\n");
    return 2;
}

int main(int argc, char** argv) {
    if (argc < 3) return usage();
    int do_emit;
    if      (strcmp(argv[1], "analyze") == 0) do_emit = 0;
    else if (strcmp(argv[1], "emit") == 0)    do_emit = 1;
    else return usage();

    const char* xbe_path = argv[2];
    const char* out_dir = "ogxbox-out";
    const char* config_path = NULL;
    const char* seed_arg = NULL;
    for (int i = 3; i + 1 < argc; i++) {
        if      (strcmp(argv[i], "-o") == 0)       out_dir = argv[++i];
        else if (strcmp(argv[i], "--config") == 0) config_path = argv[++i];
        else if (strcmp(argv[i], "--seed") == 0)   seed_arg = argv[++i];
    }
    (void)out_dir; (void)config_path; (void)seed_arg; (void)do_emit;

    Xbe xbe;
    if (xbe_load(xbe_path, &xbe) != 0) return 1;
    printf("XBE: base=0x%08X entry=0x%08X sections=%zu kernel-imports=%zu (%s)\n",
           xbe.base_address, xbe.entry_point, xbe.sections.len, xbe.kernel_imports.len,
           xbe.is_debug ? "debug" : "retail");

    BinaryView bv;
    bv_from_xbe(&xbe, &bv);

    DecodedBinary db;
    db_init(&db, &bv);

    /* smoke: decode the entry instruction */
    DecodedInsn di;
    if (db_decode_at(&db, bv.entry_point, &di))
        printf("entry insn: %s  (len %u, flow %d)\n", di.text, di.length, di.flow);

    db_free(&db);
    bv_free(&bv);
    xbe_free(&xbe);

    fprintf(stderr, "\n[ogxbox-c] analysis/emit pipeline not yet ported — foundation only.\n");
    return 0;
}
