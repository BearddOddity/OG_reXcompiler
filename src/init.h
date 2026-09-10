/* `ogxbox init` — scaffold a per-title recompilation project (manifest +
 * CMake superbuild + smoke test), matching ReXGlue's `rexglue init` /
 * `cmake --preset` flow. See templates/title/ and docs/AUTOMATION.md. */
#ifndef OGX_INIT_H
#define OGX_INIT_H

typedef struct {
    const char* xbe_path;       /* required */
    const char* name;           /* NULL -> derived from the xbe path */
    const char* recomp_config;  /* NULL -> a stub is written */
    const char* titles_dir;     /* NULL -> "titles" */
    const char* sdk_root;       /* NULL -> derived from OGX_RUNTIME_DIR */
    int min_guest_calls;        /* smoke threshold; 0 -> 1 */
    int timeout_s;              /* smoke run timeout; 0 -> 25 */
    int force;                  /* overwrite an existing manifest */
} InitOptions;

/* 0 on success. */
int ogx_init_project(const InitOptions* o);

#endif
