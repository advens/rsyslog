/* test_thrt_tld.c: TLD table + uncommon classifier. */
#include "thrt_tld.h"
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
        "{\"tld\":\"com\",\"class\":\"common\",\"label\":\"allow\"},"
        "{\"tld\":\"xyz\",\"class\":\"suspicious\",\"label\":\"shady\"}"
        "]"
        "}";
    tld_table_t *t = tld_table_load_json(json);
    tld_class_t cl;
    char lab[64];

    expect(t != NULL, "load json");
    expect(t && t->n == 2, "two entries");
    expect(tld_extract("www.Example.COM.", 16, lab, sizeof(lab)) == 3 && strcmp(lab, "com") == 0, "extract com");
    expect(tld_extract("1.2.3.4", 7, lab, sizeof(lab)) == 0, "ipv4 skip");
    expect(tld_extract("2001:db8::1", 11, lab, sizeof(lab)) == 0, "ipv6 skip");

    expect(tld_classify(t, NULL, 0, &cl) == 0 && cl.kind == TLD_KIND_NONE, "absent");
    expect(tld_classify(t, "", 0, &cl) == 0 && cl.kind == TLD_KIND_NONE, "empty host");
    expect(tld_classify(t, "files.example.com", 17, &cl) == 0 && cl.kind == TLD_KIND_TABLE &&
               strcmp(cl.cls, "common") == 0,
           "common");
    expect(
        tld_classify(t, "dl.evil.xyz", 11, &cl) == 0 && cl.kind == TLD_KIND_TABLE && strcmp(cl.cls, "suspicious") == 0,
        "suspicious");
    expect(
        tld_classify(t, "dl.evil.top", 11, &cl) == 0 && cl.kind == TLD_KIND_UNCOMMON && strcmp(cl.cls, "uncommon") == 0,
        "uncommon miss");
    expect(tld_classify(NULL, "dl.evil.top", 11, &cl) == 0 && cl.kind == TLD_KIND_NONE, "no table is not uncommon");

    tld_table_free(t);
    if (fails) {
        fprintf(stderr, "%d failure(s)\n", fails);
        return 1;
    }
    printf("test_thrt_tld: ok\n");
    return 0;
}
