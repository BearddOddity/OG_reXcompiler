/* The six analysis phases + the pipeline. Ported from Phases/Phases.cs,
 * ScanPhase.cs, PhaseHelpers.cs. */
#ifndef OGX_PHASES_H
#define OGX_PHASES_H

#include "context.h"

void phase_register(CodegenContext* ctx);
void phase_coalesce(CodegenContext* ctx);
void phase_scan(CodegenContext* ctx);
void phase_discover(CodegenContext* ctx);
void phase_gapfill(CodegenContext* ctx);
void phase_merge(CodegenContext* ctx);
int  phase_validate(CodegenContext* ctx);   /* 1 => clean */

/* Runs all six; returns 1 if Validate passed. */
int  analysis_pipeline_run(CodegenContext* ctx);

#endif
