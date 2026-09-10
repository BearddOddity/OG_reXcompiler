/* CodegenContext + AnalysisState + ScanResult + AnalysisErrors.
 * Ported from Phases/CodegenContext.cs + AnalysisErrors.cs. */
#ifndef OGX_CONTEXT_H
#define OGX_CONTEXT_H

#include "binary_view.h"
#include "decoded.h"
#include "func_graph.h"
#include "config.h"

typedef VEC(CodeRegion) CodeRegionVec;

typedef struct {
    u32map exception_handler_funcs;  /* set */
    u32map known_indirect_calls;     /* set */
    u32map invalid_instructions;     /* addr -> (void*)size */
} AnalysisState;

typedef struct {
    CodeRegionVec code_regions;
    CodeRegionVec data_regions;
} ScanResult;

typedef enum {
    ERR_UNRESOLVED_CALL,
    ERR_MISSING_JUMP_TABLE,
    ERR_JUMP_TARGET_OOB,
    ERR_DISCONTINUOUS_FUNCTION,
    ERR_UNIMPLEMENTED_INSN,
} AnalysisErrorCategory;

typedef struct {
    AnalysisErrorCategory category;
    uint32_t target, site;
    char message[128];
} AnalysisError;

typedef struct { VEC(AnalysisError) items; } AnalysisErrors;

typedef struct {
    BinaryView*      bv;
    DecodedBinary*   db;
    RecompilerConfig* config;
    FunctionGraph    graph;
    AnalysisState    state;
    ScanResult       scan;
    AnalysisErrors   errors;
} CodegenContext;

void ctx_init(CodegenContext* ctx, BinaryView* bv, DecodedBinary* db, RecompilerConfig* cfg);
void ctx_free(CodegenContext* ctx);
void errors_add(AnalysisErrors* e, AnalysisErrorCategory cat, uint32_t target, uint32_t site,
                const char* fmt, ...);

#endif
