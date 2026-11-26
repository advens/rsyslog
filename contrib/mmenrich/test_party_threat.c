/* SPDX-License-Identifier: Apache-2.0 */

/* Copyright 2026 Advens */

/* JSON written for one lookup result. Category words must not contain one
 * another, the strictest TLP word is the one a term comparison sees, a feed
 * join keeps every selected name so a contains test can see TOR, CTI labels
 * and context tags stay apart, and a restricted match writes nothing. */
#include "enrich_json.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check(int cond, const char* what) {
    if (cond) return;
    fprintf(stderr, "fail: %s\n", what);
    failures++;
}

static const char* leaf(struct json_object* obj, const char* key) {
    struct json_object* value = NULL;
    if (obj == NULL) return NULL;
    if (!json_object_object_get_ex(obj, key, &value) || value == NULL) return NULL;
    return json_object_get_string(value);
}

static const char* feeds3(const void* ctx, unsigned idx) {
    (void)ctx;
    if (idx == 0) return "emerging_threats";
    if (idx == 2) return "TOR_exit";
    return NULL;
}

static void check_words_do_not_nest(void) {
    size_t n = sizeof enrich_json_categories / sizeof enrich_json_categories[0];
    for (size_t i = 0; i < n; i++)
        for (size_t j = 0; j < n; j++)
            if (i != j)
                check(strstr(enrich_json_categories[i].name, enrich_json_categories[j].name) == NULL,
                      "category word contains another");
}

int main(void) {
    static const char tags[] = "[\"vip\",\"internal\"]";
    static const char labels[] = "[\"misp-event:x\"]";
    enrich_result_t r;
    struct json_object *obj, *cti = NULL, *v = NULL;
    const char* text;

    check_words_do_not_nest();

    memset(&r, 0, sizeof r);
    r.confidence = 90;
    r.type_mask = THRT_TYPE_CTI | THRT_TYPE_TAGS;
    r.tlp_mask = THRT_TLP_GREEN | THRT_TLP_RED;
    r.category_mask = THRT_CAT_ATTACK | THRT_CAT_MALWARE;
    r.feed_mask = (1ULL << 0) | (1ULL << 2);
    r.tags = tags;
    r.tags_len = (uint32_t)strlen(tags);
    r.labels = labels;
    r.labels_len = (uint32_t)strlen(labels);

    obj = enrich_json_party(&r, feeds3, NULL);
    check(obj != NULL, "public object");
    text = leaf(obj, "confidence");
    check(text != NULL && strcmp(text, "90") == 0, "confidence 90");
    text = leaf(obj, "category");
    check(text != NULL && strcmp(text, "attack,malware") == 0, "category join");
    text = leaf(obj, "feed");
    check(text != NULL && strcmp(text, "emerging_threats,TOR_exit") == 0, "feed join");
    text = leaf(obj, "tlp");
    check(text != NULL && strcmp(text, "red") == 0, "strictest tlp");
    text = leaf(obj, "tags");
    check(text != NULL && strcmp(text, "vip,internal") == 0, "tags join");
    text = leaf(obj, "labels");
    check(text != NULL && strcmp(text, "misp-event:x") == 0, "labels join");
    json_object_put(obj);

    obj = enrich_json_field(&r, feeds3, NULL);
    check(obj != NULL && json_object_object_get_ex(obj, "cti", &cti), "field cti");
    check(json_object_object_get_ex(cti, "labels", &v) && json_object_array_length(v) == 1, "cti labels");
    check(json_object_object_get_ex(cti, "feeds", &v) && json_object_array_length(v) == 2, "cti feeds");
    check(json_object_object_get_ex(obj, "tags", &v) && json_object_array_length(v) == 2, "field tags");
    json_object_put(obj);

    r.tlp_mask = THRT_TLP_CLEAR;
    r.category_mask = THRT_CAT_C2;
    r.feed_mask = 0;
    r.tags = NULL;
    r.tags_len = 0;
    obj = enrich_json_party(&r, feeds3, NULL);
    text = leaf(obj, "tlp");
    check(text != NULL && strcmp(text, "clear") == 0, "clear tlp");
    text = leaf(obj, "category");
    check(text != NULL && strcmp(text, "c2") == 0, "single category");
    check(leaf(obj, "feed") == NULL, "no feed");
    check(leaf(obj, "tags") == NULL, "no tags");
    json_object_put(obj);

    /* A skipped private address: no CTI part, tags only. */
    memset(&r, 0, sizeof r);
    r.tags = tags;
    r.tags_len = (uint32_t)strlen(tags);
    obj = enrich_json_party(&r, feeds3, NULL);
    check(obj != NULL, "tags only object");
    check(leaf(obj, "confidence") == NULL && leaf(obj, "category") == NULL && leaf(obj, "tlp") == NULL,
          "tags only has no CTI scalar");
    text = leaf(obj, "tags");
    check(text != NULL && strcmp(text, "vip,internal") == 0, "private tags");
    json_object_put(obj);

    /* Restricted only. */
    memset(&r, 0, sizeof r);
    r.type_mask = THRT_TYPE_CTI_R;
    r.confidence_r = 95;
    check(enrich_json_party(&r, feeds3, NULL) == NULL, "restricted match writes no scalar");
    check(enrich_json_field(&r, feeds3, NULL) == NULL, "restricted match writes no field");

    /* A malformed blob is ignored, not trusted. */
    memset(&r, 0, sizeof r);
    r.tags = "[\"open";
    r.tags_len = 6;
    check(enrich_json_field(&r, feeds3, NULL) == NULL, "malformed tags ignored");

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("test_party_threat: ok\n");
    return 0;
}
