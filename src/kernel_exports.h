/* Xbox kernel export ordinal -> name. */
#ifndef OGX_KERNEL_EXPORTS_H
#define OGX_KERNEL_EXPORTS_H
#include <stddef.h>

/* Returns the export name for a retail xboxkrnl ordinal, or NULL if unknown. */
const char* xbox_kernel_export_name(int ordinal);

/* Writes the name (or "Ordinal_<n>" for unknown) into buf. Returns 1 if known. */
int xbox_kernel_export_name_buf(int ordinal, char* buf, size_t n);

#endif
