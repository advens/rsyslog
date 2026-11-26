/* thrt_tld.h
 * TLD identification table. Exact case-insensitive last-label lookup.
 * Table hit: common / suspicious. Miss with a present domain: uncommon.
 * Absent domain, IP, or empty is not uncommon. Not CTI.
 *
 * Copyright 2026 Advens.
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef THRT_TLD_H
#define THRT_TLD_H

#include <ctype.h>
#include <json.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TLD_KIND_NONE 0
#define TLD_KIND_UNCOMMON 1
#define TLD_KIND_TABLE 2

#define TLD_LOOKUP_MAX 64

typedef struct {
    char *tld;
    char *cls;
    char *label;
} tld_entry_t;

typedef struct {
    tld_entry_t *entries;
    uint32_t n;
    tld_entry_t **slot;
    uint32_t slots;
} tld_table_t;

typedef struct {
    int kind;
    const char *cls;
    const char *label;
} tld_class_t;

static __attribute__((unused)) uint32_t tld_hash_bytes(const char *s, size_t n) {
    uint32_t h = 2166136261u;
    size_t i;
    for (i = 0; i < n; i++) {
        h ^= (uint8_t)s[i];
        h *= 16777619u;
    }
    return h;
}

static inline __attribute__((always_inline)) void tld_ascii_lower(char *dst, const char *src, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) dst[i] = (char)tolower((unsigned char)src[i]);
    dst[n] = '\0';
}

static __attribute__((unused)) void tld_table_free(tld_table_t *t) {
    uint32_t i;
    if (!t) return;
    for (i = 0; i < t->n; i++) {
        free(t->entries[i].tld);
        free(t->entries[i].cls);
        free(t->entries[i].label);
    }
    free(t->entries);
    free(t->slot);
    free(t);
}

static __attribute__((unused)) int tld_table_insert(tld_table_t *t, tld_entry_t *e) {
    uint32_t h, i, mask;
    if (!t || !e || !e->tld || t->slots == 0) return -1;
    mask = t->slots - 1;
    h = tld_hash_bytes(e->tld, strlen(e->tld)) & mask;
    for (i = 0; i < t->slots; i++) {
        uint32_t idx = (h + i) & mask;
        if (t->slot[idx] == NULL) {
            t->slot[idx] = e;
            return 0;
        }
        if (strcmp(t->slot[idx]->tld, e->tld) == 0) {
            t->slot[idx] = e;
            return 0;
        }
    }
    return -1;
}

static __attribute__((unused)) const tld_entry_t *tld_table_find(const tld_table_t *t, const char *key, size_t n) {
    uint32_t h, i, mask;
    if (!t || !key || t->slots == 0) return NULL;
    mask = t->slots - 1;
    h = tld_hash_bytes(key, n) & mask;
    for (i = 0; i < t->slots; i++) {
        uint32_t idx = (h + i) & mask;
        const tld_entry_t *e = t->slot[idx];
        if (e == NULL) return NULL;
        if (strlen(e->tld) == n && memcmp(e->tld, key, n) == 0) return e;
    }
    return NULL;
}

static inline __attribute__((always_inline)) char *tld_strdup(const char *s) {
    size_t n;
    char *d;
    if (!s) return NULL;
    n = strlen(s);
    d = (char *)malloc(n + 1);
    if (!d) return NULL;
    memcpy(d, s, n + 1);
    return d;
}

/* Last DNS label of *domain*. 0 if absent, IP, or unusable. */
static inline __attribute__((always_inline)) size_t tld_extract(const char *domain, size_t n, char *out, size_t outsz) {
    size_t i, start, lab;
    int digits = 1;

    if (!domain || !out || outsz < 3) return 0;
    for (i = 0; i < n; i++) {
        if (domain[i] == ':') return 0;
    }
    while (n > 0 && domain[n - 1] == '.') n--;
    if (n == 0) return 0;
    i = n;
    while (i > 0 && domain[i - 1] != '.') i--;
    start = i;
    lab = n - start;
    if (lab < 2 || lab >= outsz || lab >= TLD_LOOKUP_MAX) return 0;
    for (i = 0; i < lab; i++) {
        unsigned char c = (unsigned char)domain[start + i];
        if (!isalnum(c)) return 0;
        if (!isdigit(c)) digits = 0;
    }
    if (digits) return 0;
    tld_ascii_lower(out, domain + start, lab);
    return lab;
}

static __attribute__((unused)) tld_table_t *tld_table_load_json(const char *text) {
    struct json_object *root, *entries, *item, *jtld, *jcls, *jlab;
    tld_table_t *t;
    size_t n, i;
    uint32_t slots;

    if (!text) return NULL;
    root = json_tokener_parse(text);
    if (!root) return NULL;
    if (!json_object_object_get_ex(root, "entries", &entries) || json_object_get_type(entries) != json_type_array) {
        json_object_put(root);
        return NULL;
    }
    n = (size_t)json_object_array_length(entries);
    t = (tld_table_t *)calloc(1, sizeof(*t));
    if (!t) {
        json_object_put(root);
        return NULL;
    }
    if (n > 0) {
        t->entries = (tld_entry_t *)calloc(n, sizeof(tld_entry_t));
        if (!t->entries) {
            free(t);
            json_object_put(root);
            return NULL;
        }
    }
    for (i = 0; i < n; i++) {
        const char *tld, *cls, *lab;
        size_t tlen;
        item = json_object_array_get_idx(entries, (int)i);
        if (!item || !json_object_object_get_ex(item, "tld", &jtld)) continue;
        tld = json_object_get_string(jtld);
        if (!tld || !*tld) continue;
        tlen = strlen(tld);
        if (tlen < 2 || tlen >= TLD_LOOKUP_MAX) continue;
        cls = "suspicious";
        if (json_object_object_get_ex(item, "class", &jcls)) {
            const char *c = json_object_get_string(jcls);
            if (c && *c) cls = c;
        }
        lab = "";
        if (json_object_object_get_ex(item, "label", &jlab)) {
            const char *l = json_object_get_string(jlab);
            if (l) lab = l;
        }
        t->entries[t->n].tld = (char *)malloc(tlen + 1);
        if (!t->entries[t->n].tld) continue;
        tld_ascii_lower(t->entries[t->n].tld, tld, tlen);
        t->entries[t->n].cls = tld_strdup(cls);
        t->entries[t->n].label = tld_strdup(lab);
        if (!t->entries[t->n].cls || !t->entries[t->n].label) {
            free(t->entries[t->n].tld);
            free(t->entries[t->n].cls);
            free(t->entries[t->n].label);
            t->entries[t->n].tld = NULL;
            continue;
        }
        t->n++;
    }
    json_object_put(root);
    slots = 16;
    while (slots < t->n * 2u) slots *= 2;
    t->slots = slots;
    t->slot = (tld_entry_t **)calloc(slots, sizeof(tld_entry_t *));
    if (!t->slot) {
        tld_table_free(t);
        return NULL;
    }
    for (i = 0; i < t->n; i++) {
        if (tld_table_insert(t, &t->entries[i]) != 0) {
            tld_table_free(t);
            return NULL;
        }
    }
    return t;
}

static __attribute__((unused)) tld_table_t *tld_table_load(const char *path) {
    FILE *fp;
    long sz;
    char *buf;
    tld_table_t *t;

    if (!path || !*path) return NULL;
    fp = fopen(path, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    sz = ftell(fp);
    if (sz <= 0 || sz > 8 * 1024 * 1024) {
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    buf[sz] = '\0';
    t = tld_table_load_json(buf);
    free(buf);
    return t;
}

static __attribute__((unused)) int tld_classify(const tld_table_t *t,
                                                const char *domain,
                                                size_t len,
                                                tld_class_t *out) {
    char label[TLD_LOOKUP_MAX];
    size_t n;
    const tld_entry_t *e;

    if (!out) return -1;
    out->kind = TLD_KIND_NONE;
    out->cls = NULL;
    out->label = NULL;
    if (domain == NULL || len == 0) return 0;
    n = tld_extract(domain, len, label, sizeof(label));
    if (n == 0) return 0;
    e = tld_table_find(t, label, n);
    if (e) {
        out->kind = TLD_KIND_TABLE;
        out->cls = e->cls;
        out->label = e->label;
        return 0;
    }
    if (!t) return 0;
    out->kind = TLD_KIND_UNCOMMON;
    out->cls = "uncommon";
    return 0;
}

#endif /* THRT_TLD_H */
