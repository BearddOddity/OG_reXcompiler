/*
 * recomp_manual.c — per-title hand-written function overrides.
 *
 * This is the SDK's empty default. A title that needs overrides (for functions
 * the scanner cannot recover, or ones that must be reimplemented against the
 * host runtime) points `manual_file` in its config at a replacement copied over
 * this one at emit time. See configs/<title>-manual.c for an example.
 *
 * Entries in g_rex_manual are consulted by rex_lookup before the generated
 * dispatch table.
 */
#include "ogxbox_runtime.h"

const RexDispatchEntry g_rex_manual[] = { { 0, 0 } };
const uint32_t         g_rex_manual_count = 0;
