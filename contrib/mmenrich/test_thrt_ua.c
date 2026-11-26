/* SPDX-License-Identifier: Apache-2.0 */

/* Copyright 2026 Advens */

/* test_thrt_ua.c: UA table and classifiers. */
#include "thrt_ua.h"
#include <stdio.h>
#include <string.h>

static int fails;

static void expect(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        fails++;
    }
}

int main(void) {
    const char *json =
        "{"
        "\"schema\":1,"
        "\"entries\":["
        "{\"ua\":\"HttpBrowser/1.0\",\"class\":\"malware\",\"label\":\"HTTPBrowser RAT\"},"
        "{\"ua\":\"sample\",\"class\":\"suspicious\",\"label\":\"Suspicious User Agent\"}"
        "]"
        "}";
    ua_table_t *t = ua_table_load_json(json);
    ua_class_t cl;
    expect(t != NULL, "load json");
    expect(t && t->n == 2, "two entries");

    expect(ua_classify(t, NULL, 0, &cl) == 0 && cl.kind == UA_KIND_NONE, "absent is not empty");
    expect(ua_classify(t, "", 0, &cl) == 0 && cl.kind == UA_KIND_EMPTY && strcmp(cl.cls, "empty") == 0,
           "present empty");
    expect(
        ua_classify(t, "HttpBrowser/1.0", 15, &cl) == 0 && cl.kind == UA_KIND_TABLE && strcmp(cl.cls, "malware") == 0,
        "exact malware");
    expect(ua_classify(t, "httpbrowser/1.0", 15, &cl) == 0 && cl.kind == UA_KIND_TABLE, "case fold");
    expect(ua_classify(t, "Mozilla/5.0", 11, &cl) == 0 && cl.kind == UA_KIND_NONE, "benign");
    expect(ua_classify(t, "Q2hyb21l=", 9, &cl) == 0 && cl.kind == UA_KIND_ENCODED && strcmp(cl.cls, "encoded") == 0,
           "trailing equals");
    expect(ua_classify(NULL, "", 0, &cl) == 0 && cl.kind == UA_KIND_EMPTY, "empty without table");
    expect(ua_classify(NULL, "Q2hyb21l=", 9, &cl) == 0 && cl.kind == UA_KIND_ENCODED, "encoded without table");

    ua_table_free(t);

    {
        const char *parts =
            "{"
            "\"entries\":["
            "{\"ua\":\"ExampleBot/1.0\",\"class\":\"suspicious\",\"label\":\"exact\"}"
            "],"
            "\"contains\":["
            "{\"ua\":\"Example\",\"class\":\"suspicious\",\"label\":\"short\"},"
            "{\"ua\":\"ExampleBot\",\"class\":\"malware\",\"label\":\"bot\"},"
            "{\"ua\":\"ampleBot\",\"class\":\"malware\",\"label\":\"overlap\"},"
            "{\"ua\":\"bot\",\"class\":\"malware\",\"label\":\"too short\"}"
            "],"
            "\"prefixes\":["
            "{\"ua\":\"Mozilla\",\"class\":\"malware\",\"label\":\"browser\"},"
            "{\"ua\":\"ExampleMine\",\"class\":\"suspicious\",\"label\":\"mine\"}"
            "],"
            "\"suffixes\":["
            "{\"ua\":\"ExampleEnd\",\"class\":\"suspicious\",\"label\":\"end\"}"
            "]"
            "}";
        const char *browser =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        t = ua_table_load_json(parts);
        expect(t != NULL, "load parts");
        expect(t && t->n == 1, "one exact");
        expect(t && t->n_contains == 3, "short contains dropped");
        expect(t && t->n_prefixes == 1, "mozilla prefix dropped");
        expect(t && t->n_suffixes == 1, "one suffix");
        expect(ua_classify(t, "zzExamplezz", 11, &cl) == 0 && cl.kind == UA_KIND_TABLE &&
                   strcmp(cl.cls, "suspicious") == 0 && strcmp(cl.label, "short") == 0,
               "contains short token");
        expect(ua_classify(t, "zzExampleBotzz", 14, &cl) == 0 && cl.kind == UA_KIND_TABLE &&
                   strcmp(cl.cls, "malware") == 0,
               "contains longer token wins");
        expect(ua_classify(t, "xxampleBotyy", 12, &cl) == 0 && cl.kind == UA_KIND_TABLE &&
                   strcmp(cl.label, "overlap") == 0,
               "overlap suffix pattern");
        expect(ua_classify(t, "mybot", 5, &cl) == 0 && cl.kind == UA_KIND_NONE, "3-byte contains ignored");
        expect(ua_classify(t, browser, strlen(browser), &cl) == 0 && cl.kind == UA_KIND_NONE,
               "reference browser is not a prefix hit");
        expect(
            ua_classify(t, "ExampleMine/1", 13, &cl) == 0 && cl.kind == UA_KIND_TABLE && strcmp(cl.label, "mine") == 0,
            "prefix");
        expect(ua_classify(t, "aaExampleEnd", 12, &cl) == 0 && cl.kind == UA_KIND_TABLE && strcmp(cl.label, "end") == 0,
               "suffix");
        expect(ua_classify(t, "ExampleBot/1.0", 14, &cl) == 0 && cl.kind == UA_KIND_TABLE &&
                   strcmp(cl.cls, "malware") == 0 && strcmp(cl.label, "bot") == 0,
               "contains upgrades a weaker exact row");
        expect(ua_classify(t, "aaExampleEnd=", 13, &cl) == 0 && cl.kind == UA_KIND_TABLE,
               "table hit wins over trailing equals");
        ua_table_free(t);
    }
    if (fails) {
        fprintf(stderr, "%d failure(s)\n", fails);
        return 1;
    }
    printf("test_thrt_ua: ok\n");
    return 0;
}
