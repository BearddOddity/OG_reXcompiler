#include "context.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

void ctx_init(CodegenContext* ctx, BinaryView* bv, DecodedBinary* db, RecompilerConfig* cfg) {
    memset(ctx, 0, sizeof *ctx);
    ctx->bv = bv;
    ctx->db = db;
    ctx->config = cfg;
    fg_init(&ctx->graph);
    u32map_init(&ctx->state.exception_handler_funcs, 64);
    u32map_init(&ctx->state.known_indirect_calls, 64);
    u32map_init(&ctx->state.invalid_instructions, 64);
}

void ctx_free(CodegenContext* ctx) {
    fg_free(&ctx->graph);
    u32map_free(&ctx->state.exception_handler_funcs);
    u32map_free(&ctx->state.known_indirect_calls);
    u32map_free(&ctx->state.invalid_instructions);
    vec_free(&ctx->scan.code_regions);
    vec_free(&ctx->scan.data_regions);
    vec_free(&ctx->errors.items);
}

void errors_add(AnalysisErrors* e, AnalysisErrorCategory cat, uint32_t target, uint32_t site,
                const char* fmt, ...) {
    AnalysisError err;
    err.category = cat; err.target = target; err.site = site;
    va_list ap; va_start(ap, fmt);
    vsnprintf(err.message, sizeof err.message, fmt, ap);
    va_end(ap);
    vec_push(&e->items, err);
}
