#include "init.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) _mkdir(p)
static char* abspath(const char* p, char* buf, size_t n) { return _fullpath(buf, p, n); }
#else
#include <sys/stat.h>
#include <limits.h>
#define MKDIR(p) mkdir((p), 0755)
static char* abspath(const char* p, char* buf, size_t n) {
    char tmp[PATH_MAX];
    if (realpath(p, tmp)) { snprintf(buf, n, "%s", tmp); return buf; }
    /* target may not exist yet — fall back to cwd-join */
    if (p[0] == '/') { snprintf(buf, n, "%s", p); return buf; }
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof cwd)) return NULL;
    snprintf(buf, n, "%s/%s", cwd, p);
    return buf;
}
#endif

#ifndef OGX_RUNTIME_DIR
#define OGX_RUNTIME_DIR "runtime"
#endif

static void slashes(char* s) { for (; *s; s++) if (*s == '\\') *s = '/'; }

static char* slurp(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char* buf = malloc((size_t)n + 1);
    size_t got = fread(buf, 1, (size_t)n, f);
    buf[got] = 0;
    fclose(f);
    return buf;
}

typedef struct { const char* key; const char* val; } Sub;

static int render(const char* tmpl, const char* out, const Sub* subs, int nsub) {
    char* src = slurp(tmpl);
    if (!src) { fprintf(stderr, "init: template missing: %s\n", tmpl); return -1; }
    strbuf b = {0};
    for (char* p = src; *p; ) {
        if (*p == '@') {
            char* end = strchr(p + 1, '@');
            if (end) {
                size_t klen = (size_t)(end - (p + 1));
                for (int i = 0; i < nsub; i++) {
                    if (strlen(subs[i].key) == klen && strncmp(subs[i].key, p + 1, klen) == 0) {
                        sb_add(&b, subs[i].val ? subs[i].val : "");
                        p = end + 1;
                        goto next;
                    }
                }
            }
        }
        { char c[2] = { *p++, 0 }; sb_add(&b, c); }
    next:;
    }
    free(src);
    FILE* f = fopen(out, "wb");
    if (!f) { free(sb_take(&b)); fprintf(stderr, "init: cannot write %s\n", out); return -1; }
    fputs(b.data ? b.data : "", f);
    fclose(f);
    free(sb_take(&b));
    printf("  wrote %s\n", out);
    return 0;
}

/* lowercase, non-alnum -> '-', collapse and trim '-' */
static void sanitize(const char* in, char* out, size_t n) {
    size_t w = 0; int prev_dash = 1;   /* prev_dash=1 trims leading */
    for (const char* p = in; *p && w + 1 < n; p++) {
        int c = (unsigned char)*p;
        if (isalnum(c)) { out[w++] = (char)tolower(c); prev_dash = 0; }
        else if (!prev_dash) { out[w++] = '-'; prev_dash = 1; }
    }
    while (w > 0 && out[w - 1] == '-') w--;
    out[w] = 0;
    if (w == 0) snprintf(out, n, "title");
}

static void derive_name(const char* xbe, char* out, size_t n) {
    char tmp[1024]; snprintf(tmp, sizeof tmp, "%s", xbe); slashes(tmp);
    /* parent directory name */
    char* last = strrchr(tmp, '/');
    char* parent = NULL;
    if (last) { *last = 0; parent = strrchr(tmp, '/'); parent = parent ? parent + 1 : tmp; }
    const char* base = (parent && *parent) ? parent : "title";
    /* strip a trailing .xiso / .iso */
    char clean[512]; snprintf(clean, sizeof clean, "%s", base);
    char* dot = strrchr(clean, '.');
    if (dot && (strcmp(dot, ".xiso") == 0 || strcmp(dot, ".iso") == 0)) *dot = 0;
    sanitize(clean, out, n);
}

int ogx_init_project(const InitOptions* o) {
    if (!o->xbe_path) { fprintf(stderr, "init: an XBE path is required\n"); return 2; }

    char xbe_abs[1024];
    if (!abspath(o->xbe_path, xbe_abs, sizeof xbe_abs)) {
        fprintf(stderr, "init: cannot resolve xbe: %s\n", o->xbe_path); return 1;
    }
    slashes(xbe_abs);
    { FILE* t = fopen(xbe_abs, "rb"); if (!t) { fprintf(stderr, "init: xbe not found: %s\n", xbe_abs); return 1; } fclose(t); }

    /* SDK root: OGX_RUNTIME_DIR is "<root>/runtime" */
    char sdk_root[1024];
    if (o->sdk_root) snprintf(sdk_root, sizeof sdk_root, "%s", o->sdk_root);
    else {
        snprintf(sdk_root, sizeof sdk_root, "%s", OGX_RUNTIME_DIR);
        slashes(sdk_root);
        char* tail = strrchr(sdk_root, '/');
        if (tail && strcmp(tail, "/runtime") == 0) *tail = 0;
    }
    { char b[1024]; if (abspath(sdk_root, b, sizeof b)) { slashes(b); snprintf(sdk_root, sizeof sdk_root, "%s", b); } }

    char name[256];
    if (o->name && o->name[0]) sanitize(o->name, name, sizeof name);
    else derive_name(xbe_abs, name, sizeof name);

    const char* titles = (o->titles_dir && o->titles_dir[0]) ? o->titles_dir : "titles";
    char proj[1024];
    snprintf(proj, sizeof proj, "%s/%s", titles, name);
    slashes(proj);

    char manifest_out[1100];
    snprintf(manifest_out, sizeof manifest_out, "%s/manifest.toml", proj);
    { FILE* e = fopen(manifest_out, "rb");
      if (e) { fclose(e);
        if (!o->force) { fprintf(stderr, "init: %s already exists (use --force)\n", manifest_out); return 1; }
      } }

    MKDIR(titles);
    if (MKDIR(proj) != 0) { /* may already exist — fine */ }

    char cfg_abs[1024] = "";
    if (o->recomp_config && o->recomp_config[0]) {
        if (!abspath(o->recomp_config, cfg_abs, sizeof cfg_abs)) {
            fprintf(stderr, "init: cannot resolve --config: %s\n", o->recomp_config); return 1;
        }
        slashes(cfg_abs);
        FILE* t = fopen(cfg_abs, "rb");
        if (!t) { fprintf(stderr, "init: --config not found: %s\n", cfg_abs); return 1; }
        fclose(t);
    } else {
        /* write a stub config next to the manifest and point at it */
        snprintf(cfg_abs, sizeof cfg_abs, "%s/%s.toml", proj, name);
        FILE* s = fopen(cfg_abs, "wb");
        if (s) {
            fprintf(s,
                "# %s recompiler config. Fill in as the port progresses.\n"
                "# manual_file = \"%s/%s-manual.c\"\n"
                "# includes    = [ \"%s-functions.toml\" ]   # authoritative extents\n"
                "seeds = [ ]\n\n[functions]\n", name, proj, name, name);
            fclose(s);
            printf("  wrote %s\n", cfg_abs);
        }
    }

    char tmpl_dir[1024];
    snprintf(tmpl_dir, sizeof tmpl_dir, "%s/templates/title", sdk_root);

    char smin[16], stmo[16];
    snprintf(smin, sizeof smin, "%d", o->min_guest_calls > 0 ? o->min_guest_calls : 1);
    snprintf(stmo, sizeof stmo, "%d", o->timeout_s > 0 ? o->timeout_s : 25);

    Sub subs[] = {
        { "NAME", name }, { "XBE", xbe_abs }, { "SDK_ROOT", sdk_root },
        { "RECOMP_CONFIG", cfg_abs }, { "MIN_CALLS", smin }, { "TIMEOUT", stmo },
    };
    const int ns = (int)(sizeof subs / sizeof subs[0]);

    struct { const char* in; const char* out; } files[] = {
        { "manifest.toml.in",     "manifest.toml" },
        { "CMakeLists.txt.in",    "CMakeLists.txt" },
        { "CMakePresets.json.in", "CMakePresets.json" },
        { "gitignore.in",         ".gitignore" },
    };
    for (size_t i = 0; i < sizeof files / sizeof files[0]; i++) {
        char in[1200], out[1200];
        snprintf(in, sizeof in, "%s/%s", tmpl_dir, files[i].in);
        snprintf(out, sizeof out, "%s/%s", proj, files[i].out);
        if (render(in, out, subs, ns) != 0) return 1;
    }

    printf("\nscaffolded '%s' -> %s\n", name, proj);
    printf("next:\n");
    printf("  cmake --preset %s        # configure + run Part 1 (emit)\n", name);
    printf("  cmake --build --preset %s   # Part 2: compile the recompiled title\n", name);
    printf("  ctest --preset %s        # smoke: boot it, assert >= %s guest calls\n", name, smin);
    return 0;
}
