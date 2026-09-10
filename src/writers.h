/* Output writers: image blob, JSON graph export, partitioned C + build files.
 * Ported from Emit/ImageWriter.cs, Output/GraphExporter.cs, Emit/CodegenWriter.cs. */
#ifndef OGX_WRITERS_H
#define OGX_WRITERS_H

#include "context.h"
#include "xbe.h"

typedef struct {
    int functions;
    long instructions;
    long unimplemented;
} CodegenStats;

/* recomp_image.bin + recomp_image.c */
void write_image(const Xbe* xbe, const char* out_dir);

/* functions.json / labels.json / seeded_functions.json / analysis_summary.json */
void write_graph_json(CodegenContext* ctx, const char* out_dir);

/* recomp_NNNN.c + recomp_decls.h + recomp_dispatch.c + recomp_imports.c +
 * recomp_kthunks.c + CMakeLists.txt; copies runtime/*.{h,c} from runtime_dir. */
void write_codegen(CodegenContext* ctx, const Xbe* xbe, const char* out_dir,
                   const char* runtime_dir, CodegenStats* stats);

#endif
