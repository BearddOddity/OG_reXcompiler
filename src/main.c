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
#include "config.h"
#include "context.h"
#include "phases.h"

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

    RecompilerConfig cfg;
    config_init(&cfg);
    if (config_path) {
        if (config_load(&cfg, config_path) != 0) { fprintf(stderr, "config validation failed\n"); return 4; }
        printf("config: %s\n", config_path);
    }
    if (seed_arg) {
        for (char* s = strdup(seed_arg), *tok = strtok(s, ","); tok; tok = strtok(NULL, ","))
            u32set_add(&cfg.seed_functions, parse_hex_u32(tok));
    }

    CodegenContext ctx;
    ctx_init(&ctx, &bv, &db, &cfg);

    int clean = analysis_pipeline_run(&ctx);

    size_t total = fg_count(&ctx.graph), sealed = fg_sealed_count(&ctx.graph);
    size_t pending = fg_pending_count(&ctx.graph), imports = 0;
    for (size_t i = 0; i < ctx.graph.functions.cap; i++)
        if (ctx.graph.functions.used[i] && fn_is_import(ctx.graph.functions.vals[i])) imports++;
    printf("functions=%zu sealed=%zu pending=%zu imports=%zu\n", total, sealed, pending, imports);
    printf("code-regions=%zu data-regions=%zu\n",
           ctx.scan.code_regions.len, ctx.scan.data_regions.len);
    printf("validation: %s (%zu errors)\n", clean ? "clean" : "FAILED", ctx.errors.items.len);

    if (do_emit)
        fprintf(stderr, "[ogxbox-c] emitter not yet ported.\n");

    ctx_free(&ctx);
    config_free(&cfg);
    db_free(&db);
    bv_free(&bv);
    xbe_free(&xbe);
    return clean ? 0 : 3;
}
