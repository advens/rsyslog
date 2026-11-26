/* enrich_json.h
 * JSON for one libenrich lookup result: the per-field object and the party
 * scalars mmenrich writes into the message.
 *
 * Per field (the mapping target):
 *   { "cti":  { "confidence": 80, "categories": [...], "tlp": [...],
 *               "feeds": [...], "labels": [...] },
 *     "tags": [...] }
 * "cti" is present for a public CTI match. A restricted match only sets the
 * event-level flag: no feed, marking, category or label of it is written.
 * "labels" are what public CTI sources attached (MISP tags, STIX labels);
 * "tags" are the context layer (inventory, cartography).
 *
 * Party scalars (<party>.threat): a rule engine reads one leaf, and an array
 * leaf does not match, so the same facts are also strings. category, feed,
 * labels and tags are comma-joined; tlp is the strictest marking (red, then
 * amber, green, clear); confidence is the public CTI score. A name that does
 * not fit the join buffer is left out whole.
 *
 * Copyright 2026 Advens.
 * Author: Jeremie Jourdin <jeremie.jourdin@advens.fr>
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef ENRICH_JSON_H
#define ENRICH_JSON_H

#include <json.h>
#include <stdint.h>
#include <string.h>

#include "enrich.h"

/* Feed name for bit idx, or NULL. mmenrich passes enrich_feed_name(). */
typedef const char *(*enrich_json_feed_fn)(const void *ctx, unsigned idx);

#define ENRICH_JSON_JOIN_MAX 4608

static const struct {
    uint16_t bit;
    const char *name;
} enrich_json_categories[] = {
    {THRT_CAT_ATTACK, "attack"},         {THRT_CAT_MALWARE, "malware"}, {THRT_CAT_PHISHING, "phishing"},
    {THRT_CAT_BOTNET, "botnet"},         {THRT_CAT_C2, "c2"},           {THRT_CAT_EXPLOIT, "exploit"},
    {THRT_CAT_RANSOMWARE, "ransomware"}, {THRT_CAT_SPAM, "spam"},       {THRT_CAT_SCANNER, "scanner"},
    {THRT_CAT_TOR_EXIT, "tor_exit"},     {THRT_CAT_PROXY, "proxy"},
};

/* A JSON array of strings held in a snapshot (not NUL-terminated). NULL
 * when absent or not an array. */
static __attribute__((unused)) struct json_object *enrich_json_array(const char *text, uint32_t len) {
    struct json_tokener *tok;
    struct json_object *arr;
    if (text == NULL || len == 0) return NULL;
    tok = json_tokener_new();
    if (tok == NULL) return NULL;
    arr = json_tokener_parse_ex(tok, text, (int)len);
    json_tokener_free(tok);
    if (arr != NULL && !json_object_is_type(arr, json_type_array)) {
        json_object_put(arr);
        arr = NULL;
    }
    return arr;
}

static __attribute__((unused)) struct json_object *enrich_json_cti(const enrich_result_t *r,
                                                                   enrich_json_feed_fn feed_name,
                                                                   const void *ctx) {
    static const struct {
        uint8_t bit;
        const char *name;
    } tlps[] = {{THRT_TLP_CLEAR, "clear"}, {THRT_TLP_GREEN, "green"}, {THRT_TLP_AMBER, "amber"}, {THRT_TLP_RED, "red"}};
    struct json_object *cti = json_object_new_object();
    struct json_object *cats, *tlp, *feeds, *labels;
    if (cti == NULL) return NULL;
    json_object_object_add(cti, "confidence", json_object_new_int(r->confidence));
    cats = json_object_new_array();
    for (size_t i = 0; cats && i < sizeof enrich_json_categories / sizeof enrich_json_categories[0]; i++)
        if (r->category_mask & enrich_json_categories[i].bit)
            json_object_array_add(cats, json_object_new_string(enrich_json_categories[i].name));
    if (cats) json_object_object_add(cti, "categories", cats);
    tlp = json_object_new_array();
    for (size_t i = 0; tlp && i < sizeof tlps / sizeof tlps[0]; i++)
        if (r->tlp_mask & tlps[i].bit) json_object_array_add(tlp, json_object_new_string(tlps[i].name));
    if (tlp) json_object_object_add(cti, "tlp", tlp);
    feeds = json_object_new_array();
    for (unsigned i = 0; feeds && i < 64; i++) {
        const char *name;
        if (!(r->feed_mask & (1ULL << i))) continue;
        name = feed_name ? feed_name(ctx, i) : NULL;
        if (name != NULL) json_object_array_add(feeds, json_object_new_string(name));
    }
    if (feeds) json_object_object_add(cti, "feeds", feeds);
    labels = enrich_json_array(r->labels, r->labels_len);
    if (labels) json_object_object_add(cti, "labels", labels);
    return cti;
}

/* The mapping target object, or NULL when there is nothing to write. */
static __attribute__((unused)) struct json_object *enrich_json_field(const enrich_result_t *r,
                                                                     enrich_json_feed_fn feed_name,
                                                                     const void *ctx) {
    struct json_object *obj, *tags;
    int keys = 0;
    if (r == NULL) return NULL;
    obj = json_object_new_object();
    if (obj == NULL) return NULL;
    if (r->type_mask & THRT_TYPE_CTI) {
        struct json_object *cti = enrich_json_cti(r, feed_name, ctx);
        if (cti) {
            json_object_object_add(obj, "cti", cti);
            keys++;
        }
    }
    tags = enrich_json_array(r->tags, r->tags_len);
    if (tags) {
        json_object_object_add(obj, "tags", tags);
        keys++;
    }
    if (keys == 0) {
        json_object_put(obj);
        return NULL;
    }
    return obj;
}

static __attribute__((unused)) int enrich_json_append(
    char *buf, size_t cap, size_t *used, const char *name, size_t nlen) {
    size_t comma = (*used > 0) ? 1 : 0;
    if (name == NULL || nlen == 0) return 1;
    if (*used + comma + nlen + 1 > cap) return 0;
    if (comma) buf[(*used)++] = ',';
    memcpy(buf + *used, name, nlen);
    *used += nlen;
    buf[*used] = '\0';
    return 1;
}

/* Join a JSON string array into buf. */
static __attribute__((unused)) size_t enrich_json_join_array(const char *text, uint32_t len, char *buf, size_t cap) {
    struct json_object *arr = enrich_json_array(text, len);
    size_t used = 0;
    int n;
    buf[0] = '\0';
    if (arr == NULL) return 0;
    n = (int)json_object_array_length(arr);
    for (int i = 0; i < n; i++) {
        struct json_object *item = json_object_array_get_idx(arr, i);
        const char *s;
        if (item == NULL || !json_object_is_type(item, json_type_string)) continue;
        s = json_object_get_string(item);
        if (!enrich_json_append(buf, cap, &used, s, strlen(s))) break;
    }
    json_object_put(arr);
    return used;
}

static __attribute__((unused)) void enrich_json_add_joined(
    struct json_object *obj, const char *key, const char *buf, size_t used, int *keys) {
    if (used == 0) return;
    json_object_object_add(obj, key, json_object_new_string_len(buf, (int)used));
    (*keys)++;
}

/* The <party>.threat scalars, or NULL when there is nothing to write. */
static __attribute__((unused)) struct json_object *enrich_json_party(const enrich_result_t *r,
                                                                     enrich_json_feed_fn feed_name,
                                                                     const void *ctx) {
    struct json_object *obj;
    char joined[ENRICH_JSON_JOIN_MAX];
    size_t used;
    int keys = 0;
    if (r == NULL) return NULL;
    obj = json_object_new_object();
    if (obj == NULL) return NULL;

    if (r->type_mask & THRT_TYPE_CTI) {
        const char *tlp = (r->tlp_mask & THRT_TLP_RED)     ? "red"
                          : (r->tlp_mask & THRT_TLP_AMBER) ? "amber"
                          : (r->tlp_mask & THRT_TLP_GREEN) ? "green"
                          : (r->tlp_mask & THRT_TLP_CLEAR) ? "clear"
                                                           : NULL;
        json_object_object_add(obj, "confidence", json_object_new_int(r->confidence));
        keys++;
        used = 0;
        joined[0] = '\0';
        for (size_t i = 0; i < sizeof enrich_json_categories / sizeof enrich_json_categories[0]; i++) {
            const char *name = enrich_json_categories[i].name;
            if ((r->category_mask & enrich_json_categories[i].bit) &&
                !enrich_json_append(joined, sizeof joined, &used, name, strlen(name)))
                break;
        }
        enrich_json_add_joined(obj, "category", joined, used, &keys);
        used = 0;
        joined[0] = '\0';
        for (unsigned i = 0; i < 64; i++) {
            const char *name;
            if (!(r->feed_mask & (1ULL << i))) continue;
            name = feed_name ? feed_name(ctx, i) : NULL;
            if (name != NULL && !enrich_json_append(joined, sizeof joined, &used, name, strlen(name))) break;
        }
        enrich_json_add_joined(obj, "feed", joined, used, &keys);
        if (tlp != NULL) {
            json_object_object_add(obj, "tlp", json_object_new_string(tlp));
            keys++;
        }
        used = enrich_json_join_array(r->labels, r->labels_len, joined, sizeof joined);
        enrich_json_add_joined(obj, "labels", joined, used, &keys);
    }
    used = enrich_json_join_array(r->tags, r->tags_len, joined, sizeof joined);
    enrich_json_add_joined(obj, "tags", joined, used, &keys);

    if (keys == 0) {
        json_object_put(obj);
        return NULL;
    }
    return obj;
}

#endif /* ENRICH_JSON_H */
