/* Small shared helpers: growable arrays, a uint32 hash set/map, a string
 * builder, hex parsing. Header-only, C11. */
#ifndef OGX_UTIL_H
#define OGX_UTIL_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

/* ---- growable typed array -------------------------------------------------
 * VEC(T) declares a struct; the macros operate on a pointer to it.
 *   VEC(uint32_t) v = {0};
 *   vec_push(&v, 5);
 *   for (size_t i = 0; i < v.len; i++) use(v.data[i]);
 *   vec_free(&v);
 */
#define VEC(T) struct { T* data; size_t len, cap; }

#define vec_reserve(v, n) do {                                                 \
    if ((n) > (v)->cap) {                                                      \
        size_t _c = (v)->cap ? (v)->cap * 2 : 8;                               \
        while (_c < (n)) _c *= 2;                                              \
        (v)->data = realloc((v)->data, _c * sizeof(*(v)->data));               \
        (v)->cap = _c;                                                         \
    }                                                                         \
} while (0)

#define vec_push(v, x) do {                                                    \
    vec_reserve((v), (v)->len + 1);                                            \
    (v)->data[(v)->len++] = (x);                                               \
} while (0)

#define vec_free(v) do { free((v)->data); (v)->data = 0; (v)->len = (v)->cap = 0; } while (0)
#define vec_clear(v) ((v)->len = 0)

/* ---- uint32 -> void* open-addressing hash map (also a set: value = key) --- */
typedef struct {
    uint32_t* keys;
    void**    vals;
    uint8_t*  used;
    size_t    cap, len;
} u32map;

static inline void u32map_init(u32map* m, size_t cap0) {
    size_t c = 16;
    while (c < cap0) c <<= 1;          /* power of 2 — the probe masks require it */
    m->cap = c;
    m->keys = calloc(m->cap, sizeof(uint32_t));
    m->vals = calloc(m->cap, sizeof(void*));
    m->used = calloc(m->cap, 1);
    m->len = 0;
}
static inline void u32map_free(u32map* m) {
    free(m->keys); free(m->vals); free(m->used);
    memset(m, 0, sizeof *m);
}
static inline size_t u32_hash(uint32_t k) { k *= 2654435761u; return k; }

static inline void u32map_put(u32map* m, uint32_t key, void* val);
static inline void u32map_grow(u32map* m) {
    u32map n; u32map_init(&n, m->cap * 2);
    for (size_t i = 0; i < m->cap; i++)
        if (m->used[i]) u32map_put(&n, m->keys[i], m->vals[i]);
    u32map_free(m); *m = n;
}
static inline void u32map_put(u32map* m, uint32_t key, void* val) {
    if ((m->len + 1) * 4 >= m->cap * 3) u32map_grow(m);
    size_t i = u32_hash(key) & (m->cap - 1);
    while (m->used[i]) {
        if (m->keys[i] == key) { m->vals[i] = val; return; }
        i = (i + 1) & (m->cap - 1);
    }
    m->used[i] = 1; m->keys[i] = key; m->vals[i] = val; m->len++;
}
static inline int u32map_get(const u32map* m, uint32_t key, void** out) {
    size_t i = u32_hash(key) & (m->cap - 1);
    while (m->used[i]) {
        if (m->keys[i] == key) { if (out) *out = m->vals[i]; return 1; }
        i = (i + 1) & (m->cap - 1);
    }
    return 0;
}
static inline int u32map_has(const u32map* m, uint32_t key) { return u32map_get(m, key, 0); }
static inline int u32map_remove(u32map* m, uint32_t key) {
    size_t i = u32_hash(key) & (m->cap - 1);
    while (m->used[i]) {
        if (m->keys[i] == key) {
            m->used[i] = 0; m->len--;
            size_t j = (i + 1) & (m->cap - 1);
            while (m->used[j]) {
                uint32_t rk = m->keys[j]; void* rv = m->vals[j];
                m->used[j] = 0; m->len--;
                u32map_put(m, rk, rv);
                j = (j + 1) & (m->cap - 1);
            }
            return 1;
        }
        i = (i + 1) & (m->cap - 1);
    }
    return 0;
}

/* set convenience */
static inline void u32set_add(u32map* s, uint32_t k) { u32map_put(s, k, (void*)(uintptr_t)k); }

/* ---- string builder ---------------------------------------------------- */
typedef VEC(char) strbuf;
static inline void sb_add(strbuf* b, const char* s) {
    size_t n = strlen(s);
    vec_reserve(b, b->len + n + 1);
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = 0;
}
static inline void sb_addf(strbuf* b, const char* fmt, ...) {
    char tmp[512];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n < sizeof tmp) { sb_add(b, tmp); return; }
    char* big = malloc(n + 1);
    va_start(ap, fmt); vsnprintf(big, n + 1, fmt, ap); va_end(ap);
    sb_add(b, big); free(big);
}
static inline char* sb_take(strbuf* b) { char* p = b->data; memset(b, 0, sizeof *b); return p; }

/* ---- hex ---------------------------------------------------------------- */
static inline uint32_t parse_hex_u32(const char* s) {
    while (*s == ' ' || *s == '\t') s++;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    return (uint32_t)strtoul(s, NULL, 16);
}

#endif
