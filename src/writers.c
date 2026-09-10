#include "writers.h"
#include "emit.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) _mkdir(p)
#else
#define MKDIR(p) mkdir((p), 0755)
#endif

static void ensure_dir(const char* d) { MKDIR(d); }

static FILE* open_out(const char* dir, const char* name) {
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    return fopen(path, "wb");
}

static uint32_t round_up(uint32_t v, uint32_t a) { return (v + a - 1) / a * a; }

/*=========================================================================
 * image
 *=======================================================================*/

void write_image(const Xbe* xbe, const char* out_dir) {
    ensure_dir(out_dir);

    /* loadable sections sorted by VA */
    size_t n = xbe->sections.len;
    const XbeSection** secs = malloc(n * sizeof *secs);
    size_t m = 0;
    for (size_t i = 0; i < n; i++) {
        const XbeSection* s = &xbe->sections.data[i];
        if (s->raw_size > 0 && (size_t)s->raw_addr + s->raw_size <= xbe->raw_len) secs[m++] = s;
    }
    for (size_t i = 1; i < m; i++) {
        const XbeSection* k = secs[i]; size_t j = i;
        while (j > 0 && secs[j - 1]->virtual_addr > k->virtual_addr) { secs[j] = secs[j - 1]; j--; }
        secs[j] = k;
    }

    FILE* blob = open_out(out_dir, "recomp_image.bin");
    for (size_t i = 0; i < m; i++)
        fwrite(xbe->raw + secs[i]->raw_addr, 1, secs[i]->raw_size, blob);
    fclose(blob);

    uint32_t ram = 64u * 1024 * 1024;
    uint32_t esp = 0x03700000;
    (void)round_up;

    FILE* f = open_out(out_dir, "recomp_image.c");
    fprintf(f, "/* generated — XBE image map. */\n");
    fprintf(f, "#define _CRT_SECURE_NO_WARNINGS 1\n#include \"ogxbox_runtime.h\"\n#include <stdio.h>\n\n");
    fprintf(f, "typedef struct { unsigned int va, file_off, size; } RexSection;\n");
    fprintf(f, "static const RexSection g_rex_sections[] = {\n");
    long off = 0;
    for (size_t i = 0; i < m; i++) {
        fprintf(f, "  { 0x%08Xu, %ldu, 0x%Xu },  /* %s */\n",
                secs[i]->virtual_addr, off, secs[i]->raw_size, secs[i]->name);
        off += secs[i]->raw_size;
    }
    fprintf(f, "};\nstatic const unsigned int g_rex_section_count = %zu;\n\n", m);

    /* kernel import thunk slots: {slot VA, ordinal} — the runtime's thunkfix
     * patches DATA-export slots to the kernel data area and leaves FUNCTION
     * slots holding 0x80000000|ordinal for rex_kernel_dispatch. */
    fprintf(f, "typedef struct { unsigned int slot_va, ordinal; } RexKThunk;\n");
    fprintf(f, "const RexKThunk g_rex_kthunk[] = {\n");
    for (size_t i = 0; i < xbe->kernel_imports.len; i++) {
        const XbeKernelImport* k = &xbe->kernel_imports.data[i];
        fprintf(f, "  { 0x%08Xu, %uu },\n", k->thunk_addr, (unsigned int)k->ordinal);
    }
    fprintf(f, "};\nconst unsigned int g_rex_kthunk_count = %zu;\n\n", xbe->kernel_imports.len);

    fprintf(f, "const unsigned int g_rex_image_base = 0x%08Xu;\n", xbe->base_address);
    fprintf(f, "const unsigned int g_rex_ram_size  = 0x%08Xu;\n", ram);
    fprintf(f, "const unsigned int g_rex_entry_va  = 0x%08Xu;\n", xbe->entry_point);
    fprintf(f, "const unsigned int g_rex_initial_esp = 0x%08Xu;\n\n", esp);
    fprintf(f,
        "int rex_load_image(const char* bin_path) {\n"
        "    FILE* f = fopen(bin_path, \"rb\");\n"
        "    if (!f) { fprintf(stderr, \"[ogxbox] cannot open %%s\\n\", bin_path); return -1; }\n"
        "    for (unsigned int i = 0; i < g_rex_section_count; i++) {\n"
        "        const RexSection* s = &g_rex_sections[i];\n"
        "        if (s->va + s->size > g_guest_ram_size) { fclose(f); return -2; }\n"
        "        if (fseek(f, s->file_off, SEEK_SET) != 0) { fclose(f); return -3; }\n"
        "        if (fread(g_guest_ram + s->va, 1, s->size, f) != s->size) { fclose(f); return -4; }\n"
        "    }\n"
        "    fclose(f);\n    return 0;\n}\n");
    fclose(f);
    free(secs);
}

/*=========================================================================
 * JSON export
 *=======================================================================*/

static void json_functions(CodegenContext* ctx, FILE* f) {
    fprintf(f, "[\n");
    int first = 1;
    /* iterate sorted by base */
    for (size_t si = 0; si < ctx->graph.sorted_bases.len; si++) {
        FunctionNode* n = fg_get(&ctx->graph, ctx->graph.sorted_bases.data[si]);
        if (!n || fn_is_import(n)) continue;
        SectionView* sec = bv_find_section(ctx->bv, n->base);
        if (!first) fprintf(f, ",\n");
        first = 0;
        fprintf(f, "  {\"start\":\"0x%08X\",\"end\":\"0x%08X\",\"size\":%u,\"name\":\"%s\","
                   "\"section\":\"%s\",\"authority\":\"%s\",\"state\":\"%s\",\"num_instructions\":%zu,\"blocks\":[",
                n->base, fn_end(n), n->size, n->name, sec ? sec->name : "",
                authority_name(n->authority),
                n->state == ST_SEALED ? "sealed" : n->state == ST_DISCOVERED ? "discovered" : "registered",
                n->instructions.len);
        for (size_t bi = 0; bi < n->blocks.len; bi++)
            fprintf(f, "%s[\"0x%08X\",\"0x%08X\"]", bi ? "," : "",
                    n->blocks.data[bi].base, block_end(&n->blocks.data[bi]));
        fprintf(f, "]}");
    }
    fprintf(f, "\n]\n");
}

void write_graph_json(CodegenContext* ctx, const char* out_dir) {
    ensure_dir(out_dir);
    FILE* f;

    f = open_out(out_dir, "functions.json"); json_functions(ctx, f); fclose(f);

    f = open_out(out_dir, "seeded_functions.json");
    {
        U32Vec addrs = {0};
        for (size_t i = 0; i < ctx->graph.functions.cap; i++)
            if (ctx->graph.functions.used[i] &&
                !fn_is_import(ctx->graph.functions.vals[i]))
                vec_push(&addrs, ctx->graph.functions.keys[i]);
        for (size_t i = 1; i < addrs.len; i++) {
            uint32_t k = addrs.data[i]; size_t j = i;
            while (j > 0 && addrs.data[j - 1] > k) { addrs.data[j] = addrs.data[j - 1]; j--; }
            addrs.data[j] = k;
        }
        fprintf(f, "{ \"count\": %zu, \"addresses\": [", addrs.len);
        for (size_t i = 0; i < addrs.len; i++) fprintf(f, "%s%u", i ? "," : "", addrs.data[i]);
        fprintf(f, "] }\n");
        vec_free(&addrs);
    }
    fclose(f);

    f = open_out(out_dir, "analysis_summary.json");
    fprintf(f, "{\n  \"base_address\": \"0x%08X\",\n  \"entry_point\": \"0x%08X\",\n"
               "  \"functions_total\": %zu,\n  \"functions_sealed\": %zu,\n  \"functions_pending\": %zu,\n"
               "  \"validation_errors\": %zu\n}\n",
            ctx->bv->base_address, ctx->bv->entry_point,
            fg_count(&ctx->graph), fg_sealed_count(&ctx->graph), fg_pending_count(&ctx->graph),
            ctx->errors.items.len);
    fclose(f);
}

/*=========================================================================
 * codegen writer
 *=======================================================================*/

typedef struct { CodegenContext* ctx; u32map* emittable; } NameCtx;

static const char* name_of_cb(void* vc, uint32_t addr) {
    NameCtx* nc = vc;
    if (u32map_has(nc->emittable, addr)) {
        FunctionNode* n = fg_get(&nc->ctx->graph, addr);
        return n ? n->name : NULL;
    }
    FunctionNode* n = fg_get(&nc->ctx->graph, addr);
    return (n && fn_is_import(n)) ? n->name : NULL;
}

static int copy_path(const char* src_path, const char* dst_path) {
    FILE* in = fopen(src_path, "rb");
    if (!in) return -1;
    FILE* out = fopen(dst_path, "wb");
    if (!out) { fclose(in); return -1; }
    char buf[8192]; size_t k;
    while ((k = fread(buf, 1, sizeof buf, in)) > 0) fwrite(buf, 1, k, out);
    fclose(in); fclose(out);
    return 0;
}

static void copy_file(const char* src_dir, const char* name, const char* dst_dir) {
    char sp[1024], dp[1024];
    snprintf(sp, sizeof sp, "%s/%s", src_dir, name);
    snprintf(dp, sizeof dp, "%s/%s", dst_dir, name);
    copy_path(sp, dp);
}

static const char* short_kimport(const char* full) {
    const char* c = strrchr(full, ':');
    return c ? c + 1 : full;
}

void write_codegen(CodegenContext* ctx, const Xbe* xbe, const char* out_dir,
                   const char* runtime_dir, CodegenStats* stats) {
    ensure_dir(out_dir);
    memset(stats, 0, sizeof *stats);

    /* emittable set = sealed non-import with blocks */
    u32map emittable; u32map_init(&emittable, fg_count(&ctx->graph) + 16);
    U32Vec order = {0};
    for (size_t si = 0; si < ctx->graph.sorted_bases.len; si++) {
        FunctionNode* n = fg_get(&ctx->graph, ctx->graph.sorted_bases.data[si]);
        if (n && n->state == ST_SEALED && !fn_is_import(n) && n->blocks.len > 0) {
            u32set_add(&emittable, n->base);
            vec_push(&order, n->base);
        }
    }
    NameCtx nc = { ctx, &emittable };

    /* runtime headers/sources */
    const char* rt[] = { "ogxbox_runtime.h", "ogxbox_runtime.c", "ogxbox_trace.c",
                         "ogxbox_kernel.c", "ogxbox_kernel_glue.c", "ogxbox_thunkfix.c",
                         "ogxbox_tib.c", "recomp_manual.c", "ogxbox_main.c", NULL };
    for (int i = 0; rt[i]; i++) copy_file(runtime_dir, rt[i], out_dir);

    /* per-title recomp_manual.c override (config `manual_file`, path relative to
     * the working directory) — copied over the empty default */
    if (ctx->config->manual_file[0]) {
        char dp[1024];
        snprintf(dp, sizeof dp, "%s/recomp_manual.c", out_dir);
        if (copy_path(ctx->config->manual_file, dp) != 0)
            fprintf(stderr, "[ogxbox] warning: manual_file '%s' not found\n",
                    ctx->config->manual_file);
        else
            fprintf(stderr, "[ogxbox] manual overrides: %s\n", ctx->config->manual_file);
    }

    /* vendored OG Xbox kernel replacement layer + its platform shim */
    char sub[1024];
    snprintf(sub, sizeof sub, "%s/kernel", out_dir);   ensure_dir(sub);
    snprintf(sub, sizeof sub, "%s/platform", out_dir); ensure_dir(sub);
    const char* kern[] = {
        "kernel/kernel.h", "kernel/kernel_ob.c", "kernel/kernel_thread.c",
        "kernel/kernel_sync.c", "kernel/kernel_rtl.c", "kernel/kernel_file.c",
        "kernel/kernel_io.c", "kernel/kernel_memory.c", "kernel/kernel_pool.c",
        "kernel/kernel_hal.c", "kernel/kernel_path.c", "kernel/kernel_crypto.c",
        "kernel/kernel_xbox.c", "kernel/kernel_thunks.c", "kernel/ogxbox_bridge.c",
        "kernel/xbox_memory_layout.h", "kernel/xbox_page_zero_trap.h", "kernel/xbox_watch.h",
        "platform/xbox_winnt.h", "platform/win32_compat.h", "platform/win32_compat.c",
        NULL };
    for (int i = 0; kern[i]; i++) copy_file(runtime_dir, kern[i], out_dir);

    /* decls header */
    strbuf decls = {0};
    sb_add(&decls, "/* generated */\n#pragma once\n#include \"ogxbox_runtime.h\"\n");

    /* partition */
    const size_t per_file = 500;
    int file_idx = 0;
    for (size_t i = 0; i < order.len; i += per_file, file_idx++) {
        char fname[64]; snprintf(fname, sizeof fname, "recomp_%04d.c", file_idx);
        FILE* cf = open_out(out_dir, fname);
        fprintf(cf, "/* generated by ogxbox */\n#include \"recomp_decls.h\"\n\n");
        size_t upto = i + per_file < order.len ? i + per_file : order.len;
        for (size_t k = i; k < upto; k++) {
            FunctionNode* n = fg_get(&ctx->graph, order.data[k]);
            /* config manual_functions: declared + in the dispatch table, but the
             * body comes from recomp_manual.c, not the emitter. */
            if (u32map_has(&ctx->config->manual_functions, n->base)) {
                sb_addf(&decls, "void %s(RecompCtx* c);\n", n->name);
                continue;
            }
            EmitResult er;
            emit_function(ctx->db, n, name_of_cb, &nc, &er);
            stats->functions++;
            stats->instructions += er.instructions;
            stats->unimplemented += er.unimplemented;
            sb_addf(&decls, "void %s(RecompCtx* c);\n", n->name);
            fputs(er.code, cf);
            fputc('\n', cf);
            emit_result_free(&er);
        }
        fclose(cf);
    }

    /* dispatch table */
    {
        FILE* d = open_out(out_dir, "recomp_dispatch.c");
        fprintf(d, "/* generated */\n#include \"recomp_decls.h\"\n");
        fprintf(d, "/* RexDispatchEntry: ogxbox_runtime.h (via recomp_decls.h) */\n");
        fprintf(d, "const RexDispatchEntry g_rex_dispatch[] = {\n");
        for (size_t k = 0; k < order.len; k++) {
            FunctionNode* n = fg_get(&ctx->graph, order.data[k]);
            fprintf(d, "  { 0x%08Xu, %s },\n", n->base, n->name);
        }
        fprintf(d, "};\nconst unsigned int g_rex_dispatch_count = %zu;\n", order.len);
        fclose(d);
    }

    /* import stubs + decls */
    {
        FILE* im = open_out(out_dir, "recomp_imports.c");
        fprintf(im, "/* generated — weak kernel-import stubs */\n#include \"ogxbox_runtime.h\"\n");
        for (size_t i = 0; i < ctx->graph.functions.cap; i++) {
            if (!ctx->graph.functions.used[i]) continue;
            FunctionNode* n = ctx->graph.functions.vals[i];
            if (!fn_is_import(n)) continue;
            fprintf(im, "#if defined(__GNUC__) || defined(__clang__)\n__attribute__((weak))\n#endif\n"
                        "void %s(RecompCtx* c) { rex_unimplemented(\"%s\", 0); c->esp += 4u; }\n",
                        n->name, n->name);
            sb_addf(&decls, "void %s(RecompCtx* c);\n", n->name);
        }
        fclose(im);
    }

    /* kernel thunk dispatch */
    {
        FILE* kt = open_out(out_dir, "recomp_kthunks.c");
        fprintf(kt, "/* generated — xboxkrnl ordinal -> __imp__ fallback (used by\n"
                    "   ogxbox_kernel_glue.c's rex_kernel_dispatch when the bridge lacks a\n"
                    "   handler for the ordinal). */\n#include \"recomp_decls.h\"\n");
        fprintf(kt, "void rex_unimplemented(const char*, unsigned int);\n\n");
        fprintf(kt, "void rex_kthunk_fallback(RecompCtx* c, unsigned int ordinal) {\n  switch (ordinal) {\n");
        for (size_t i = 0; i < xbe->kernel_imports.len; i++) {
            const XbeKernelImport* k = &xbe->kernel_imports.data[i];
            fprintf(kt, "  case %d: __imp__%s(c); return;\n", k->ordinal, k->name);
        }
        fprintf(kt, "  default: rex_unimplemented(\"kernel ordinal\", 0x80000000u | ordinal);\n"
                    "           c->esp += 4u; return;   /* pop the return slot even when unhandled */\n  }\n}\n");
        fclose(kt);
    }

    { FILE* dh = open_out(out_dir, "recomp_decls.h"); fputs(decls.data ? decls.data : "", dh); fclose(dh); }
    free(sb_take(&decls));

    /* CMakeLists.txt */
    {
        FILE* cm = open_out(out_dir, "CMakeLists.txt");
        fprintf(cm, "cmake_minimum_required(VERSION 3.16)\nproject(recomp C)\nset(CMAKE_C_STANDARD 11)\n");
        fprintf(cm, "if (MSVC)\n  add_compile_definitions(_CRT_SECURE_NO_WARNINGS WIN32)\n"
                    "  add_compile_options(/wd4005 /wd4013 /wd4133 /wd4267 /wd4244)\nendif()\n");
        fprintf(cm, "include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/kernel)\n");
        fprintf(cm, "add_executable(recomp\n"
                    "  ogxbox_main.c ogxbox_runtime.c ogxbox_trace.c ogxbox_kernel.c ogxbox_kernel_glue.c\n"
                    "  ogxbox_thunkfix.c ogxbox_tib.c recomp_manual.c\n"
                    "  recomp_dispatch.c recomp_imports.c recomp_image.c recomp_kthunks.c\n"
                    "  kernel/kernel_ob.c kernel/kernel_thread.c kernel/kernel_sync.c kernel/kernel_rtl.c\n"
                    "  kernel/kernel_file.c kernel/kernel_io.c kernel/kernel_memory.c kernel/kernel_pool.c\n"
                    "  kernel/kernel_hal.c kernel/kernel_path.c kernel/kernel_crypto.c kernel/kernel_xbox.c\n"
                    "  kernel/kernel_thunks.c kernel/ogxbox_bridge.c platform/win32_compat.c\n");
        for (int k = 0; k < file_idx; k++) fprintf(cm, "  recomp_%04d.c\n", k);
        fprintf(cm, ")\ntarget_link_libraries(recomp PRIVATE bcrypt)\n"
                    "# add -DREX_TRACE for a guest backtrace on unresolved calls\n"
                    "# recomp_image.bin must sit next to the executable at run time.\n");
        fclose(cm);
    }
    (void)short_kimport; (void)round_up;

    u32map_free(&emittable);
    vec_free(&order);
}
