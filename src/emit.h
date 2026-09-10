/* CEmitter — lower a sealed FunctionNode to a C function body.
 * Ported from Emit/CEmitter.cs. */
#ifndef OGX_EMIT_H
#define OGX_EMIT_H

#include "func_graph.h"
#include "decoded.h"

typedef struct {
    char*  name;
    char*  code;          /* malloc'd; caller frees */
    int    instructions;
    int    unimplemented;
} EmitResult;

/* name_of: entry addr -> symbol name for a call/jump target, or NULL to route
 * through rex_dispatch. ctx is passed through. */
typedef const char* (*NameOfFn)(void* ctx, uint32_t addr);

void emit_function(DecodedBinary* db, FunctionNode* node,
                   NameOfFn name_of, void* name_ctx, EmitResult* out);
void emit_result_free(EmitResult* r);

#endif
