/* RecompilerConfig + TOML loader. Ported from Phases/RecompilerConfig.cs +
 * RecompilerConfigLoader.cs. */
#ifndef OGX_CONFIG_H
#define OGX_CONFIG_H

#include <stdint.h>
#include "util.h"
#include "func_types.h"

typedef struct {
    uint32_t size;      /* 0 => unset */
    uint32_t end;       /* 0 => unset (mutually exclusive with size) */
    char     name[80];  /* empty => auto */
    uint32_t parent;    /* non-zero => chunk */
    int      share_registers;
} FunctionConfig;

typedef struct {
    char  name[80];
    U32Vec dummy;  /* reserved; register list not used by the C analysis phases */
    int   ret, return_on_true, return_on_false, after_instruction;
    uint32_t jump_address, jump_address_on_true, jump_address_on_false;
} MidAsmHook;

typedef struct {
    char project_name[64];
    char file_path[512];
    char out_directory_path[512];
    char manual_file[512];   /* per-title recomp_manual.c, path as written in the config */
    int  generate_exception_handlers;

    uint32_t max_jump_extension;
    uint32_t min_null_run;
    uint32_t data_region_threshold;
    uint32_t large_function_threshold;

    u32map functions;     /* addr -> FunctionConfig* */
    u32map switch_tables; /* addr -> JumpTable* */
    u32map midasm_hooks;  /* addr -> MidAsmHook* */
    u32map seed_functions;        /* set */
    u32map exception_handler_hints; /* set */
    u32map manual_functions;      /* set: addrs the emitter must NOT emit — recomp_manual.c defines them */
} RecompilerConfig;

void config_init(RecompilerConfig* c);
void config_free(RecompilerConfig* c);

/* Loads a TOML file (with recursive includes). Returns 0 on success; prints
 * validation warnings/errors to stderr; non-zero if validation fails. */
int  config_load(RecompilerConfig* c, const char* path);

#endif
