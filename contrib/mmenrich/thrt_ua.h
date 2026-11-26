/* thrt_ua.h
 * User-agent identification table. Exact case-insensitive lookup,
 * then a contains automaton and prefix and suffix compares. Empty and a
 * trailing '=' are classifiers. Not CTI: a hit does not fold into
 * threat.thrt scoring.
 *
 * Copyright 2026 Advens.
 * Author: Jeremie Jourdin <jeremie.jourdin@advens.fr>
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef THRT_UA_H
#define THRT_UA_H

#include <ctype.h>
#include <json.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UA_KIND_NONE 0
#define UA_KIND_EMPTY 1
#define UA_KIND_ENCODED 2
#define UA_KIND_TABLE 3

#define UA_LOOKUP_MAX 1024
#define UA_PART_MIN 5
#define UA_PART_MAX 1024
#define UA_AC_MAX_NODES 32768
#define UA_AC_MAX_EDGES 32768
#define UA_AC_NONE 0xFFFFu

/* A modifier needle that occurs here would stamp a normal browser. */
static const char UA_BROWSER[] =
    "mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 "
    "(khtml, like gecko) chrome/120.0.0.0 safari/537.36";

typedef struct {
    char *ua; /* lowercase key */
    char *cls; /* malware / suspicious */
    char *label;
    uint16_t len;
} ua_entry_t;

typedef struct ua_ac_edge {
    unsigned char ch;
    uint16_t to;
    uint16_t next;
} ua_ac_edge;

typedef struct ua_ac_node {
    uint16_t head;
    uint16_t fail;
    int32_t best; /* index into contains, or -1 */
} ua_ac_node;

typedef struct ua_ac {
    ua_ac_node *nodes;
    ua_ac_edge *edges;
    uint16_t node_n;
    uint16_t edge_n;
} ua_ac_t;

typedef struct {
    ua_entry_t *entries;
    uint32_t n;
    ua_entry_t **slot;
    uint32_t slots;
    ua_entry_t *contains;
    uint32_t n_contains;
    ua_entry_t *prefixes;
    uint32_t n_prefixes;
    ua_entry_t *suffixes;
    uint32_t n_suffixes;
    ua_ac_t *ac;
} ua_table_t;

typedef struct {
    int kind;
    const char *cls;
    const char *label;
} ua_class_t;

static __attribute__((unused)) uint32_t ua_hash_bytes(const char *s, size_t n) {
    uint32_t h = 2166136261u;
    size_t i;
    for (i = 0; i < n; i++) {
        h ^= (uint8_t)s[i];
        h *= 16777619u;
    }
    return h;
}

static inline __attribute__((always_inline)) void ua_ascii_lower(char *dst, const char *src, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) dst[i] = (char)tolower((unsigned char)src[i]);
    dst[n] = '\0';
}

static __attribute__((unused)) void ua_entries_free(ua_entry_t *entries, uint32_t n) {
    uint32_t i;
    if (!entries) return;
    for (i = 0; i < n; i++) {
        free(entries[i].ua);
        free(entries[i].cls);
        free(entries[i].label);
    }
    free(entries);
}

static __attribute__((unused)) void ua_table_free(ua_table_t *t) {
    if (!t) return;
    ua_entries_free(t->entries, t->n);
    ua_entries_free(t->contains, t->n_contains);
    ua_entries_free(t->prefixes, t->n_prefixes);
    ua_entries_free(t->suffixes, t->n_suffixes);
    if (t->ac) {
        free(t->ac->nodes);
        free(t->ac->edges);
        free(t->ac);
    }
    free(t->slot);
    free(t);
}

static __attribute__((unused)) int ua_table_insert(ua_table_t *t, ua_entry_t *e) {
    uint32_t h, i, mask;
    if (!t || !e || !e->ua || t->slots == 0) return -1;
    mask = t->slots - 1;
    h = ua_hash_bytes(e->ua, strlen(e->ua)) & mask;
    for (i = 0; i < t->slots; i++) {
        uint32_t idx = (h + i) & mask;
        if (t->slot[idx] == NULL) {
            t->slot[idx] = e;
            return 0;
        }
        if (strcmp(t->slot[idx]->ua, e->ua) == 0) {
            t->slot[idx] = e; /* later insert wins (caller merged) */
            return 0;
        }
    }
    return -1;
}

static __attribute__((unused)) const ua_entry_t *ua_table_find(const ua_table_t *t, const char *key, size_t n) {
    uint32_t h, i, mask;
    if (!t || !key || t->slots == 0) return NULL;
    mask = t->slots - 1;
    h = ua_hash_bytes(key, n) & mask;
    for (i = 0; i < t->slots; i++) {
        uint32_t idx = (h + i) & mask;
        const ua_entry_t *e = t->slot[idx];
        if (e == NULL) return NULL;
        if (e->len == n && memcmp(e->ua, key, n) == 0) return e;
    }
    return NULL;
}

static inline __attribute__((always_inline)) char *ua_strdup(const char *s) {
    size_t n;
    char *d;
    if (!s) return NULL;
    n = strlen(s);
    d = (char *)malloc(n + 1);
    if (!d) return NULL;
    memcpy(d, s, n + 1);
    return d;
}

static int ua_rank(const char *cls) {
    if (!cls) return 0;
    if (strcmp(cls, "malware") == 0) return 3;
    if (strcmp(cls, "suspicious") == 0) return 2;
    if (strcmp(cls, "tool") == 0) return 1;
    return 0;
}

/* 1 when a modifier needle would match a normal browser User-Agent. */
static int ua_part_rejected(const char *low, size_t n) {
    size_t i, refn;
    if (n < UA_PART_MIN || n >= UA_LOOKUP_MAX) return 1;
    refn = sizeof(UA_BROWSER) - 1;
    if (n > refn) return 0;
    for (i = 0; i + n <= refn; i++) {
        if (memcmp(UA_BROWSER + i, low, n) == 0) return 1;
    }
    return 0;
}

static int ua_store(ua_entry_t *e, const char *ua, size_t ualen, const char *cls, const char *lab) {
    memset(e, 0, sizeof(*e));
    e->ua = (char *)malloc(ualen + 1);
    if (!e->ua) return -1;
    ua_ascii_lower(e->ua, ua, ualen);
    e->len = (uint16_t)ualen;
    e->cls = ua_strdup(cls && cls[0] ? cls : "suspicious");
    e->label = ua_strdup(lab ? lab : "");
    if (!e->cls || !e->label) {
        free(e->ua);
        free(e->cls);
        free(e->label);
        memset(e, 0, sizeof(*e));
        return -1;
    }
    return 0;
}

/* Missing key: 0. Allocation failure: -1. A bad element is skipped. */
static int ua_load_array(struct json_object *root,
                         const char *key,
                         ua_entry_t **out,
                         uint32_t *out_n,
                         size_t cap,
                         size_t min_len,
                         int part) {
    struct json_object *arr, *item, *jua, *jcls, *jlab;
    size_t n, i, kept;

    *out = NULL;
    *out_n = 0;
    if (!json_object_object_get_ex(root, key, &arr) || json_object_get_type(arr) != json_type_array) return 0;
    n = (size_t)json_object_array_length(arr);
    if (n > cap) n = cap;
    if (n == 0) return 0;
    *out = (ua_entry_t *)calloc(n, sizeof(ua_entry_t));
    if (!*out) return -1;
    kept = 0;
    for (i = 0; i < n; i++) {
        const char *ua, *cls, *lab;
        size_t ualen;
        int rc;
        item = json_object_array_get_idx(arr, (int)i);
        if (!item || json_object_get_type(item) != json_type_object) continue;
        if (!json_object_object_get_ex(item, "ua", &jua)) continue;
        ua = json_object_get_string(jua);
        if (!ua || !ua[0]) continue;
        ualen = strlen(ua);
        if (ualen < min_len || ualen >= UA_LOOKUP_MAX) continue;
        cls = "suspicious";
        if (json_object_object_get_ex(item, "class", &jcls)) {
            const char *c = json_object_get_string(jcls);
            if (c && c[0]) cls = c;
        }
        lab = "";
        if (json_object_object_get_ex(item, "label", &jlab)) {
            const char *l = json_object_get_string(jlab);
            if (l) lab = l;
        }
        rc = ua_store(&(*out)[kept], ua, ualen, cls, lab);
        if (rc != 0) {
            ua_entries_free(*out, (uint32_t)kept);
            *out = NULL;
            return -1;
        }
        if (part && ua_part_rejected((*out)[kept].ua, (*out)[kept].len)) {
            free((*out)[kept].ua);
            free((*out)[kept].cls);
            free((*out)[kept].label);
            memset(&(*out)[kept], 0, sizeof(ua_entry_t));
            continue;
        }
        kept++;
    }
    *out_n = (uint32_t)kept;
    return 0;
}

static int ua_ac_child(const ua_ac_t *ac, uint16_t node, unsigned char ch, uint16_t *to) {
    uint16_t e = ac->nodes[node].head;
    while (e != UA_AC_NONE) {
        if (ac->edges[e].ch == ch) {
            *to = ac->edges[e].to;
            return 1;
        }
        e = ac->edges[e].next;
    }
    return 0;
}

static uint16_t ua_ac_step(const ua_ac_t *ac, uint16_t node, unsigned char ch) {
    uint16_t to;
    for (;;) {
        if (ua_ac_child(ac, node, ch, &to)) return to;
        if (node == 0) return 0;
        node = ac->nodes[node].fail;
    }
}

static void ua_ac_set_best(ua_ac_t *ac, uint16_t node, int32_t idx, const ua_entry_t *entries) {
    int32_t cur = ac->nodes[node].best;
    if (cur < 0 || ua_rank(entries[idx].cls) > ua_rank(entries[cur].cls)) ac->nodes[node].best = idx;
}

static int ua_ac_insert(ua_ac_t *ac, const ua_entry_t *e, int32_t idx, const ua_entry_t *entries) {
    uint16_t node = 0;
    size_t i;
    for (i = 0; i < e->len; i++) {
        unsigned char ch = (unsigned char)e->ua[i];
        uint16_t to, edge;
        if (!ua_ac_child(ac, node, ch, &to)) {
            if (ac->node_n >= UA_AC_MAX_NODES || ac->edge_n >= UA_AC_MAX_EDGES) return -1;
            to = ac->node_n++;
            ac->nodes[to].head = UA_AC_NONE;
            ac->nodes[to].fail = 0;
            ac->nodes[to].best = -1;
            edge = ac->edge_n++;
            ac->edges[edge].ch = ch;
            ac->edges[edge].to = to;
            ac->edges[edge].next = ac->nodes[node].head;
            ac->nodes[node].head = edge;
        }
        node = to;
    }
    ua_ac_set_best(ac, node, idx, entries);
    return 0;
}

static int ua_ac_fail(ua_ac_t *ac, const ua_entry_t *entries) {
    uint16_t *queue;
    uint32_t qh = 0, qt = 0;
    uint16_t e, node;

    queue = (uint16_t *)malloc((size_t)ac->node_n * sizeof(uint16_t));
    if (!queue) return -1;
    e = ac->nodes[0].head;
    while (e != UA_AC_NONE) {
        ac->nodes[ac->edges[e].to].fail = 0;
        if (qt >= ac->node_n) {
            free(queue);
            return -1;
        }
        queue[qt++] = ac->edges[e].to;
        e = ac->edges[e].next;
    }
    while (qh < qt) {
        uint16_t edge;
        int32_t inherited;
        node = queue[qh++];
        inherited = ac->nodes[ac->nodes[node].fail].best;
        if (inherited >= 0) ua_ac_set_best(ac, node, inherited, entries);
        edge = ac->nodes[node].head;
        while (edge != UA_AC_NONE) {
            unsigned char ch = ac->edges[edge].ch;
            uint16_t child = ac->edges[edge].to;
            uint16_t fail = ac->nodes[node].fail;
            uint16_t to;
            while (fail != 0 && !ua_ac_child(ac, fail, ch, &to)) fail = ac->nodes[fail].fail;
            if (ua_ac_child(ac, fail, ch, &to))
                ac->nodes[child].fail = to;
            else
                ac->nodes[child].fail = 0;
            if (qt >= ac->node_n) {
                free(queue);
                return -1;
            }
            queue[qt++] = child;
            edge = ac->edges[edge].next;
        }
    }
    free(queue);
    return 0;
}

static int ua_ac_build(ua_table_t *t) {
    ua_ac_t *ac;
    uint32_t i;
    if (t->n_contains == 0) return 0;
    ac = (ua_ac_t *)calloc(1, sizeof(*ac));
    if (!ac) return -1;
    ac->nodes = (ua_ac_node *)calloc(UA_AC_MAX_NODES, sizeof(*ac->nodes));
    ac->edges = (ua_ac_edge *)calloc(UA_AC_MAX_EDGES, sizeof(*ac->edges));
    if (!ac->nodes || !ac->edges) {
        free(ac->nodes);
        free(ac->edges);
        free(ac);
        return -1;
    }
    ac->node_n = 1;
    ac->nodes[0].head = UA_AC_NONE;
    ac->nodes[0].fail = 0;
    ac->nodes[0].best = -1;
    for (i = 0; i < t->n_contains; i++) {
        if (ua_ac_insert(ac, &t->contains[i], (int32_t)i, t->contains) != 0) break;
    }
    if (ua_ac_fail(ac, t->contains) != 0) {
        free(ac->nodes);
        free(ac->edges);
        free(ac);
        return -1;
    }
    t->ac = ac;
    return 0;
}

static __attribute__((unused)) ua_table_t *ua_table_load_json(const char *text) {
    struct json_object *root, *entries;
    ua_table_t *t;
    uint32_t slots, i;

    if (!text) return NULL;
    root = json_tokener_parse(text);
    if (!root) return NULL;
    if (!json_object_object_get_ex(root, "entries", &entries) || json_object_get_type(entries) != json_type_array) {
        json_object_put(root);
        return NULL;
    }
    t = (ua_table_t *)calloc(1, sizeof(*t));
    if (!t) {
        json_object_put(root);
        return NULL;
    }
    if (ua_load_array(root, "entries", &t->entries, &t->n, (size_t)-1, 3, 0) != 0 ||
        ua_load_array(root, "contains", &t->contains, &t->n_contains, UA_PART_MAX, UA_PART_MIN, 1) != 0 ||
        ua_load_array(root, "prefixes", &t->prefixes, &t->n_prefixes, UA_PART_MAX, UA_PART_MIN, 1) != 0 ||
        ua_load_array(root, "suffixes", &t->suffixes, &t->n_suffixes, UA_PART_MAX, UA_PART_MIN, 1) != 0) {
        json_object_put(root);
        ua_table_free(t);
        return NULL;
    }
    json_object_put(root);
    slots = 16;
    while (slots < t->n * 2u) slots *= 2;
    t->slots = slots;
    t->slot = (ua_entry_t **)calloc(slots, sizeof(ua_entry_t *));
    if (!t->slot || ua_ac_build(t) != 0) {
        ua_table_free(t);
        return NULL;
    }
    for (i = 0; i < t->n; i++) {
        if (ua_table_insert(t, &t->entries[i]) != 0) {
            ua_table_free(t);
            return NULL;
        }
    }
    return t;
}

static __attribute__((unused)) ua_table_t *ua_table_load(const char *path) {
    FILE *fp;
    long sz;
    char *buf;
    ua_table_t *t;

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
    t = ua_table_load_json(buf);
    free(buf);
    return t;
}

static void ua_consider(const ua_entry_t **best, int *rank, const ua_entry_t *e) {
    int r;
    if (!e) return;
    r = ua_rank(e->cls);
    if (r > *rank) {
        *best = e;
        *rank = r;
    }
}

static void ua_scan_edge(const ua_entry_t *list,
                         uint32_t n,
                         const char *folded,
                         size_t len,
                         int suffix,
                         const ua_entry_t **best,
                         int *rank) {
    uint32_t i;
    for (i = 0; i < n && *rank < 3; i++) {
        const ua_entry_t *e = &list[i];
        if (e->len == 0 || (size_t)e->len > len) continue;
        if (suffix) {
            if (memcmp(folded + (len - e->len), e->ua, e->len) == 0) ua_consider(best, rank, e);
        } else if (memcmp(folded, e->ua, e->len) == 0) {
            ua_consider(best, rank, e);
        }
    }
}

static void ua_scan_contains(
    const ua_ac_t *ac, const ua_entry_t *list, const char *folded, size_t len, const ua_entry_t **best, int *rank) {
    uint16_t node = 0;
    size_t i;
    if (!ac) return;
    for (i = 0; i < len && *rank < 3; i++) {
        int32_t idx;
        node = ua_ac_step(ac, node, (unsigned char)folded[i]);
        idx = ac->nodes[node].best;
        if (idx >= 0) ua_consider(best, rank, &list[idx]);
    }
}

/* Field absent (ua == NULL) is not empty: only a present zero-length value is.
 * An exact malware row is reported without scanning the modifier lists.
 * Any weaker exact row is kept only when no modifier row has a higher class.
 */
static __attribute__((unused)) int ua_classify(const ua_table_t *t, const char *ua, size_t len, ua_class_t *out) {
    char folded[UA_LOOKUP_MAX];
    const ua_entry_t *best = NULL;
    int rank = 0;

    if (!out) return -1;
    out->kind = UA_KIND_NONE;
    out->cls = NULL;
    out->label = NULL;
    if (ua == NULL) return 0;
    if (len == 0) {
        out->kind = UA_KIND_EMPTY;
        out->cls = "empty";
        return 0;
    }
    if (t && len < UA_LOOKUP_MAX) {
        ua_ascii_lower(folded, ua, len);
        best = ua_table_find(t, folded, len);
        if (best) rank = ua_rank(best->cls);
        if (rank < 3) {
            ua_scan_edge(t->prefixes, t->n_prefixes, folded, len, 0, &best, &rank);
            ua_scan_edge(t->suffixes, t->n_suffixes, folded, len, 1, &best, &rank);
            ua_scan_contains(t->ac, t->contains, folded, len, &best, &rank);
        }
        if (best) {
            out->kind = UA_KIND_TABLE;
            out->cls = best->cls;
            out->label = best->label;
            return 0;
        }
    }
    if (ua[len - 1] == '=') {
        out->kind = UA_KIND_ENCODED;
        out->cls = "encoded";
        return 0;
    }
    return 0;
}

#endif /* THRT_UA_H */
