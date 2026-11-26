/* SPDX-License-Identifier: Apache-2.0 */

/* test_ecs_derive.c
 * Self-test for the shared ECS derived-field layer (runtime/ecs_derive.h):
 * the SLICE transforms (url.path), the COMPUTED DGA numeric features (Shannon
 * entropy x100, digit ratio, longest label), and the ecs_derive_lookup resolver
 * path (name -> table row -> source field via a callback -> transform). This is
 * the ONLY consumer of ecs_derive.h among the mmsigma standalone tools, on
 * purpose: the matcher/engine cores stay coupling-free (see Makefile.am), and a
 * dedicated header test carries the runtime include path. libc-only (+ -lm for
 * log2). Exits non-zero on any failure so `make check` fails the build.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ecs_derive.h"

static int g_fail = 0;
#define CK(cond, ...)            \
    do {                         \
        if (!(cond)) {           \
            printf("FAIL: ");    \
            printf(__VA_ARGS__); \
            printf("\n");        \
            g_fail++;            \
        }                        \
    } while (0)

/* apply one transform to a NUL-terminated string, return the integer output
 * (COMPUTED transforms) or -1 on error. */
static long apply_int(int xf, const char *s) {
    const char *out = NULL;
    size_t olen = 0;
    char buf[ECS_DERIVE_BUFSZ];
    char tmp[ECS_DERIVE_BUFSZ];
    if (!ecs_derive_apply(xf, s, strlen(s), &out, &olen, buf, sizeof buf)) return -1;
    if (olen >= sizeof tmp) return -1;
    memcpy(tmp, out, olen);
    tmp[olen] = '\0';
    return atol(tmp);
}

/* ---- ecs_src_get_fn mock: a tiny KV table for the resolver-path test ---- */
typedef struct {
    const char *k, *v;
} kv_t;
typedef struct {
    const kv_t *kv;
    int n;
} mockctx_t;

static int mock_get(void *ctx, const char *name, const char **val, size_t *vlen) {
    const mockctx_t *m = (const mockctx_t *)ctx;
    for (int i = 0; i < m->n; i++) {
        if (strcmp(m->kv[i].k, name) == 0) {
            *val = m->kv[i].v;
            *vlen = strlen(m->kv[i].v);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    long g;
    long dga;
    /* --- COMPUTED: Shannon entropy x100 --- */
    CK(apply_int(ECS_XF_DNS_ENTROPY, "aaaa") == 0, "entropy(aaaa) == 0");
    CK(apply_int(ECS_XF_DNS_ENTROPY, "abcd") == 200, "entropy(abcd) == 2.00 bits");
    g = apply_int(ECS_XF_DNS_ENTROPY, "google.com");
    CK(g > 200 && g < 380, "entropy(google.com) moderate, not DGA (got %ld)", g);
    dga = apply_int(ECS_XF_DNS_ENTROPY, "kq3v9x2z7wprmb4njhg8ftq2");
    CK(dga >= 400, "entropy(DGA-like) >= 4.00 bits (got %ld)", dga);

    /* --- COMPUTED: digit ratio x100 (rounded) --- */
    CK(apply_int(ECS_XF_DNS_DIGIT_RATIO, "abc123") == 50, "digit_ratio(abc123) == 50");
    CK(apply_int(ECS_XF_DNS_DIGIT_RATIO, "abcdef") == 0, "digit_ratio(abcdef) == 0");
    CK(apply_int(ECS_XF_DNS_DIGIT_RATIO, "123456") == 100, "digit_ratio(123456) == 100");

    /* --- COMPUTED: longest dot-separated label --- */
    CK(apply_int(ECS_XF_DNS_MAX_LABEL, "www.example.com") == 7, "max_label(example) == 7");
    CK(apply_int(ECS_XF_DNS_MAX_LABEL, "a.verylonglabelhere.io") == 17, "max_label == 17");
    CK(apply_int(ECS_XF_DNS_MAX_LABEL, "nodots") == 6, "max_label(nodots) == 6");
    CK(apply_int(ECS_XF_DNS_MAX_LABEL, "") == 0, "max_label(empty) == 0");

    /* --- COMPUTED: HTTP structural features --- */
    CK(apply_int(ECS_XF_URL_LENGTH, "abcd") == 4, "url length == 4");
    CK(apply_int(ECS_XF_URL_LENGTH, "") == 0, "url length(empty) == 0");
    CK(apply_int(ECS_XF_URL_PCT_COUNT, "a%20b%25c") == 2, "pct_count == 2");
    CK(apply_int(ECS_XF_URL_PCT_COUNT, "/plain/path") == 0, "pct_count(plain) == 0");
    CK(apply_int(ECS_XF_URL_SPECIAL_COUNT, "a'b\"c<d>e") == 4, "special_count == 4 (' \" < >)");
    CK(apply_int(ECS_XF_URL_SPECIAL_COUNT, "/api/v1/users?page=2") == 0, "special_count(benign) == 0");
    CK(apply_int(ECS_XF_URL_TRAVERSAL_COUNT, "../../x/..\\y") == 3, "traversal_count == 3 (../ ../ ..\\)");
    CK(apply_int(ECS_XF_URL_TRAVERSAL_COUNT, "/download?file=../../../../etc/passwd") == 4,
       "traversal_count(LFI) == 4");
    CK(apply_int(ECS_XF_URL_TRAVERSAL_COUNT, "/normal/path/file.js") == 0, "traversal_count(benign) == 0");

    /* --- SLICE: url.path truncates at query/fragment --- */
    {
        const char *o = NULL;
        size_t ol = 0;
        char b[ECS_DERIVE_BUFSZ];
        CK(ecs_derive_apply(ECS_XF_URL_PATH, "/a/b?q=1", 8, &o, &ol, b, sizeof b) && ol == 4 &&
               memcmp(o, "/a/b", 4) == 0,
           "url.path slice stops at '?'");
        CK(ecs_derive_apply(ECS_XF_IDENTITY, "verbatim", 8, &o, &ol, b, sizeof b) && ol == 8 &&
               memcmp(o, "verbatim", 8) == 0,
           "identity is verbatim");
    }

    /* --- RESOLVER PATH: ecs_derive_lookup(name -> source via get -> apply) --- */
    {
        const kv_t kv[] = {
            {"dns.question.name", "kq3v9x2z7wprmb4njhg8ftq2.example.com"},
            {"url.original", "/admin/panel?token=abc"},
        };
        mockctx_t m = {kv, (int)(sizeof kv / sizeof kv[0])};
        const char *out = NULL;
        size_t ol = 0;
        char buf[ECS_DERIVE_BUFSZ];
        char tmp[ECS_DERIVE_BUFSZ];
        const kv_t kv2[] = {{"url.original", "/x"}};
        mockctx_t m2 = {kv2, 1};

        /* derived numeric field resolves through its source */
        CK(ecs_derive_lookup("dns.question.name_entropy", mock_get, &m, &out, &ol, buf, sizeof buf),
           "lookup resolves dns.question.name_entropy");
        memcpy(tmp, out, ol);
        tmp[ol] = '\0';
        CK(atol(tmp) >= 400, "resolved entropy >= 400 (got %s)", tmp);

        /* derived slice field resolves + truncates at '?' */
        CK(ecs_derive_lookup("url.path", mock_get, &m, &out, &ol, buf, sizeof buf) && ol == 12 &&
               memcmp(out, "/admin/panel", 12) == 0,
           "lookup resolves url.path from url.original, truncated");

        /* a name that is not a derived field -> not resolved */
        CK(!ecs_derive_lookup("source.ip", mock_get, &m, &out, &ol, buf, sizeof buf),
           "lookup declines a non-derived field");

        /* derived field whose SOURCE is absent -> not resolved */
        CK(!ecs_derive_lookup("dns.question.name_entropy", mock_get, &m2, &out, &ol, buf, sizeof buf),
           "lookup declines when source field is absent");
    }

    if (g_fail) {
        printf("\n%d CHECK(S) FAILED\n", g_fail);
        return 1;
    }
    printf("ecs_derive: all checks passed\n");
    return 0;
}
