#include "config.h"
#include "toml.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void config_init(RecompilerConfig* c) {
    memset(c, 0, sizeof *c);
    snprintf(c->project_name, sizeof c->project_name, "ogxbox");
    c->max_jump_extension = 65536;
    c->min_null_run = 8;
    c->data_region_threshold = 16;
    c->large_function_threshold = 1u << 20;
    u32map_init(&c->functions, 64);
    u32map_init(&c->switch_tables, 64);
    u32map_init(&c->midasm_hooks, 64);
    u32map_init(&c->seed_functions, 256);
    u32map_init(&c->manual_functions, 32);
    u32map_init(&c->exception_handler_hints, 64);
}

void config_free(RecompilerConfig* c) {
    for (size_t i = 0; i < c->functions.cap; i++)
        if (c->functions.used[i]) free(c->functions.vals[i]);
    for (size_t i = 0; i < c->switch_tables.cap; i++)
        if (c->switch_tables.used[i]) {
            JumpTable* jt = c->switch_tables.vals[i];
            vec_free(&jt->targets); free(jt);
        }
    for (size_t i = 0; i < c->midasm_hooks.cap; i++)
        if (c->midasm_hooks.used[i]) free(c->midasm_hooks.vals[i]);
    u32map_free(&c->functions);
    u32map_free(&c->switch_tables);
    u32map_free(&c->midasm_hooks);
    u32map_free(&c->seed_functions);
    u32map_free(&c->manual_functions);
    u32map_free(&c->exception_handler_hints);
}

static uint32_t datum_u32(toml_datum_t d) {
    return d.ok ? (uint32_t)d.u.i : 0;
}
static long array_int(toml_array_t* a, int i) {
    toml_datum_t d = toml_int_at(a, i);
    return d.ok ? (long)d.u.i : 0;
}

static void apply_table(RecompilerConfig* c, toml_table_t* t) {
    toml_datum_t d;

    d = toml_string_in(t, "project_name");
    if (d.ok) { snprintf(c->project_name, sizeof c->project_name, "%s", d.u.s); free(d.u.s); }
    d = toml_string_in(t, "file_path");
    if (d.ok) { snprintf(c->file_path, sizeof c->file_path, "%s", d.u.s); free(d.u.s); }
    d = toml_string_in(t, "manual_file");
    if (d.ok) { snprintf(c->manual_file, sizeof c->manual_file, "%s", d.u.s); free(d.u.s); }
    d = toml_string_in(t, "out_directory_path");
    if (d.ok) { snprintf(c->out_directory_path, sizeof c->out_directory_path, "%s", d.u.s); free(d.u.s); }
    d = toml_bool_in(t, "generate_exception_handlers");
    if (d.ok) c->generate_exception_handlers = d.u.b;

    toml_table_t* an = toml_table_in(t, "analysis");
    if (an) {
        d = toml_int_in(an, "max_jump_extension");     if (d.ok) c->max_jump_extension = datum_u32(d);
        d = toml_int_in(an, "data_region_threshold");  if (d.ok) c->data_region_threshold = datum_u32(d);
        d = toml_int_in(an, "large_function_threshold");if (d.ok) c->large_function_threshold = datum_u32(d);
        d = toml_int_in(an, "min_null_run");           if (d.ok) c->min_null_run = datum_u32(d);
        toml_array_t* eh = toml_array_in(an, "exception_handler_funcs");
        if (eh) for (int i = 0; i < toml_array_nelem(eh); i++)
            u32set_add(&c->exception_handler_hints, (uint32_t)array_int(eh, i));
    }

    /* top-level arrays (must precede any [section] in the file) */
    toml_array_t* mf = toml_array_in(t, "manual_functions");
    if (mf) for (int i = 0; i < toml_array_nelem(mf); i++)
        u32set_add(&c->manual_functions, (uint32_t)array_int(mf, i));
    toml_array_t* seeds = toml_array_in(t, "seeds");
    if (seeds) for (int i = 0; i < toml_array_nelem(seeds); i++)
        u32set_add(&c->seed_functions, (uint32_t)array_int(seeds, i));
    toml_array_t* ic = toml_array_in(t, "indirect_calls");
    if (ic) for (int i = 0; i < toml_array_nelem(ic); i++)
        u32set_add(&c->exception_handler_hints, (uint32_t)array_int(ic, i));

    /* [functions] "0xADDR" = { size|end, name, parent, share_registers } */
    toml_table_t* fns = toml_table_in(t, "functions");
    if (fns) {
        for (int i = 0; ; i++) {
            const char* key = toml_key_in(fns, i);
            if (!key) break;
            toml_table_t* e = toml_table_in(fns, key);
            if (!e) continue;
            uint32_t addr = parse_hex_u32(key);
            FunctionConfig* fc = calloc(1, sizeof *fc);
            d = toml_int_in(e, "size");   if (d.ok) fc->size = datum_u32(d);
            d = toml_int_in(e, "end");    if (d.ok) fc->end = datum_u32(d);
            d = toml_int_in(e, "parent"); if (d.ok) fc->parent = datum_u32(d);
            d = toml_bool_in(e, "share_registers"); if (d.ok) fc->share_registers = d.u.b;
            d = toml_string_in(e, "name");
            if (d.ok) { snprintf(fc->name, sizeof fc->name, "%s", d.u.s); free(d.u.s); }
            void* old;
            if (u32map_get(&c->functions, addr, &old)) free(old);
            u32map_put(&c->functions, addr, fc);
        }
    }

    /* [[switch_tables]] address, register, labels = [ ... ] */
    toml_array_t* sw = toml_array_in(t, "switch_tables");
    if (sw) {
        for (int i = 0; i < toml_array_nelem(sw); i++) {
            toml_table_t* e = toml_table_at(sw, i);
            if (!e) continue;
            uint32_t addr = datum_u32(toml_int_in(e, "address"));
            JumpTable* jt = calloc(1, sizeof *jt);
            jt->jump_address = addr;
            jt->index_register = (uint8_t)datum_u32(toml_int_in(e, "register"));
            toml_array_t* labels = toml_array_in(e, "labels");
            if (labels) for (int k = 0; k < toml_array_nelem(labels); k++)
                vec_push(&jt->targets, (uint32_t)array_int(labels, k));
            if (jt->targets.len) u32map_put(&c->switch_tables, addr, jt);
            else { vec_free(&jt->targets); free(jt); }
        }
    }

    /* [[midasm_hook]] address, name, return*, jump_address*, after_instruction */
    toml_array_t* hooks = toml_array_in(t, "midasm_hook");
    if (hooks) {
        for (int i = 0; i < toml_array_nelem(hooks); i++) {
            toml_table_t* e = toml_table_at(hooks, i);
            if (!e) continue;
            uint32_t addr = datum_u32(toml_int_in(e, "address"));
            MidAsmHook* h = calloc(1, sizeof *h);
            d = toml_string_in(e, "name");
            if (d.ok) { snprintf(h->name, sizeof h->name, "%s", d.u.s); free(d.u.s); }
            else snprintf(h->name, sizeof h->name, "hook_%08X", addr);
            d = toml_bool_in(e, "return");          if (d.ok) h->ret = d.u.b;
            d = toml_bool_in(e, "return_on_true");  if (d.ok) h->return_on_true = d.u.b;
            d = toml_bool_in(e, "return_on_false"); if (d.ok) h->return_on_false = d.u.b;
            d = toml_bool_in(e, "after_instruction");if (d.ok) h->after_instruction = d.u.b;
            h->jump_address          = datum_u32(toml_int_in(e, "jump_address"));
            h->jump_address_on_true  = datum_u32(toml_int_in(e, "jump_address_on_true"));
            h->jump_address_on_false = datum_u32(toml_int_in(e, "jump_address_on_false"));
            void* old;
            if (u32map_get(&c->midasm_hooks, addr, &old)) free(old);
            u32map_put(&c->midasm_hooks, addr, h);
        }
    }
}

static int load_recursive(RecompilerConfig* c, const char* path, int depth) {
    if (depth > 32) { fprintf(stderr, "config include depth exceeded: %s\n", path); return 1; }
    FILE* f = fopen(path, "r");
    if (!f) { fprintf(stderr, "config not found: %s\n", path); return 1; }
    char err[256];
    toml_table_t* t = toml_parse_file(f, err, sizeof err);
    fclose(f);
    if (!t) { fprintf(stderr, "config parse error in %s: %s\n", path, err); return 1; }

    /* includes first, depth-first, so this file's values win */
    toml_array_t* inc = toml_array_in(t, "includes");
    if (inc) {
        /* resolve relative to this file's directory */
        char dir[512];
        snprintf(dir, sizeof dir, "%s", path);
        char* slash = strrchr(dir, '/');
        char* bslash = strrchr(dir, '\\');
        if (bslash && (!slash || bslash > slash)) slash = bslash;
        if (slash) slash[1] = 0; else dir[0] = 0;
        for (int i = 0; i < toml_array_nelem(inc); i++) {
            toml_datum_t d = toml_string_at(inc, i);
            if (!d.ok) continue;
            char full[1024];
            int absolute = d.u.s[0] == '/' || d.u.s[0] == '\\' ||
                           (d.u.s[0] && d.u.s[1] == ':');   /* /x  \\x  C:\x */
            if (absolute) snprintf(full, sizeof full, "%s", d.u.s);
            else          snprintf(full, sizeof full, "%s%s", dir, d.u.s);
            free(d.u.s);
            if (load_recursive(c, full, depth + 1) != 0) { toml_free(t); return 1; }
        }
    }

    apply_table(c, t);
    toml_free(t);
    return 0;
}

static int validate(RecompilerConfig* c) {
    int ok = 1;
    /* overlapping standalone functions */
    U32Vec addrs = {0};
    for (size_t i = 0; i < c->functions.cap; i++)
        if (c->functions.used[i]) {
            FunctionConfig* fc = c->functions.vals[i];
            if (fc->parent == 0) vec_push(&addrs, c->functions.keys[i]);
        }
    /* insertion sort */
    for (size_t i = 1; i < addrs.len; i++) {
        uint32_t k = addrs.data[i]; size_t j = i;
        while (j > 0 && addrs.data[j - 1] > k) { addrs.data[j] = addrs.data[j - 1]; j--; }
        addrs.data[j] = k;
    }
    for (size_t i = 1; i < addrs.len; i++) {
        void* v;
        u32map_get(&c->functions, addrs.data[i - 1], &v);
        FunctionConfig* p = v;
        uint32_t psz = p->size ? p->size : (p->end > addrs.data[i - 1] ? p->end - addrs.data[i - 1] : 0);
        if (addrs.data[i] < addrs.data[i - 1] + psz) {
            fprintf(stderr, "config error: overlapping function boundaries at 0x%08X / 0x%08X\n",
                    addrs.data[i - 1], addrs.data[i]);
            ok = 0;
        }
    }
    vec_free(&addrs);
    return ok ? 0 : 1;
}

int config_load(RecompilerConfig* c, const char* path) {
    if (load_recursive(c, path, 0) != 0) return 1;
    return validate(c);
}
