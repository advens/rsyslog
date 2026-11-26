/* SPDX-License-Identifier: Apache-2.0 */

/* test_ecs_derive.c: the ECS derive contract: transforms and table shape.
 *
 * Copyright 2026 Advens.
 * Licensed under the Apache License, Version 2.0.
 *
 * Two things are pinned here.
 *
 * TRANSFORMS. ECS_XF_LOWER writes into the caller's scratch buffer, so the
 * bound matters.
 *
 * TABLE SHAPE. mmenrich_emit_derived_ecs walks this table on EVERY event and
 * probes the source once per contiguous same-source group. That is what keeps
 * the table growable: a source carrying none of these fields costs one arena
 * lookup per group, not one per row. Splitting a group silently doubles its
 * cost, so the grouping is asserted, not just documented.
 *
 * Build: make -f Makefile.dev test-derive
 */

#include <stdio.h>
#include <string.h>

#include "ecs_derive.h"

static int failures;

static void check(int cond, const char* what) {
    if (!cond) {
        printf("  FAIL %s\n", what);
        failures++;
    }
}

/* Apply a transform and compare the result to `want`. */
static void xf_eq(int xf, const char* in, const char* want, const char* what) {
    const char* out = NULL;
    size_t olen = 0;
    char buf[ECS_DERIVE_BUFSZ];
    if (!ecs_derive_apply(xf, in, strlen(in), &out, &olen, buf, sizeof buf)) {
        printf("  FAIL %s: transform returned 0\n", what);
        failures++;
        return;
    }
    if (olen != strlen(want) || memcmp(out, want, olen) != 0) {
        printf("  FAIL %s: got '%.*s', want '%s'\n", what, (int)olen, out, want);
        failures++;
    }
}

/* A source reader over a fixed (name,value) table, standing in for the arena. */
typedef struct {
    const char* const (*rows)[2];
    size_t n;
} fake_src_t;

static int fake_get(void* ctx, const char* name, const char** val, size_t* vlen) {
    fake_src_t* f = (fake_src_t*)ctx;
    for (size_t i = 0; i < f->n; i++) {
        if (strcmp(f->rows[i][0], name) == 0) {
            *val = f->rows[i][1];
            *vlen = strlen(f->rows[i][1]);
            return 1; /* ecs_src_get_fn: non-zero = found */
        }
    }
    return 0;
}

int main(void) {
    printf("ecs_derive contract\n");

    printf("transforms\n");
    xf_eq(ECS_XF_IDENTITY, "203.0.113.9", "203.0.113.9", "IDENTITY is verbatim");
    xf_eq(ECS_XF_LOWER, "TCP", "tcp", "LOWER folds ASCII letters");
    xf_eq(ECS_XF_LOWER, "UDP", "udp", "LOWER folds UDP");
    xf_eq(ECS_XF_LOWER, "tls", "tls", "LOWER leaves lowercase alone");
    xf_eq(ECS_XF_LOWER, "IPv6-ICMP", "ipv6-icmp", "LOWER keeps non-alpha bytes");
    xf_eq(ECS_XF_URL_PATH, "/a/b?x=1", "/a/b", "URL_PATH truncates at query");
    xf_eq(ECS_XF_URL_PATH, "/a/b#f", "/a/b", "URL_PATH truncates at fragment");

    /* The vendor-verb normalization that makes one firewall rule cover every
     * firewall instead of only pf. */
    xf_eq(ECS_XF_FW_DISPOSITION, "pass", "allowed", "pf pass -> allowed");
    xf_eq(ECS_XF_FW_DISPOSITION, "ACCEPT", "allowed", "iptables ACCEPT -> allowed");
    xf_eq(ECS_XF_FW_DISPOSITION, "allow", "allowed", "haproxy allow -> allowed");
    xf_eq(ECS_XF_FW_DISPOSITION, "block", "denied", "pf block -> denied");
    xf_eq(ECS_XF_FW_DISPOSITION, "DROP", "denied", "iptables DROP -> denied");
    xf_eq(ECS_XF_FW_DISPOSITION, "reject", "denied", "reject -> denied");
    xf_eq(ECS_XF_FW_DISPOSITION, "Deny", "denied", "mixed case is folded");

    /* Translation verbs must NOT normalize: pf logs a nat record AND a pass
     * record for the same flow, so mapping both would double-fire every allow
     * rule. Unrelated action vocabularies must not be guessed at either. */
    {
        const char* out = NULL;
        size_t olen = 0;
        char buf[ECS_DERIVE_BUFSZ];
        const char* unmapped[] = {"nat", "rdr", "connection", "ids_alert", "start", "end", ""};
        for (size_t i = 0; i < sizeof unmapped / sizeof unmapped[0]; i++) {
            if (ecs_derive_apply(ECS_XF_FW_DISPOSITION, unmapped[i], strlen(unmapped[i]), &out, &olen, buf,
                                 sizeof buf)) {
                printf("  FAIL '%s' must not normalize to an event.type\n", unmapped[i]);
                failures++;
            }
        }
        const char* longverb = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        check(ecs_derive_apply(ECS_XF_FW_DISPOSITION, longverb, strlen(longverb), &out, &olen, buf, sizeof buf) == 0,
              "an over-long verb is rejected, not truncated");
    }

    /* LOWER must fail closed rather than truncate: a clipped protocol token
     * could match the wrong rule, an absent field simply does not match. */
    {
        char small[8];
        const char* out = NULL;
        size_t olen = 0;
        const char* longv = "AAAAAAAAAAAAAAAAAAAAAAAA";
        check(ecs_derive_apply(ECS_XF_LOWER, longv, strlen(longv), &out, &olen, small, sizeof small) == 0,
              "LOWER fails closed when the value exceeds the buffer");
        check(ecs_derive_apply(ECS_XF_LOWER, "", 0, &out, &olen, small, sizeof small) == 1 && olen == 0,
              "LOWER accepts an empty value");
    }

    /* An unknown transform id must not fabricate a value. */
    {
        const char* out = NULL;
        size_t olen = 0;
        char buf[ECS_DERIVE_BUFSZ];
        check(ecs_derive_apply(9999, "x", 1, &out, &olen, buf, sizeof buf) == 0, "unknown transform id is rejected");
    }

    printf("table shape\n");
    /* Rows sharing a source must be contiguous: the emitter probes once per
     * group, so a split group is a silent per-event regression. */
    {
        /* For each source, every row between its first and last occurrence must
         * carry that same source: otherwise the group is split and the emitter
         * probes it more than once per event. */
        int split = 0;
        for (size_t i = 0; i < ECS_DERIVE_COUNT; i++) {
            const char* src = ecs_derive_table[i].source;
            size_t first = i, last = i;
            for (size_t k = 0; k < ECS_DERIVE_COUNT; k++) {
                if (strcmp(ecs_derive_table[k].source, src) != 0) continue;
                if (k < first) first = k;
                if (k > last) last = k;
            }
            for (size_t k = first; k <= last; k++) {
                if (strcmp(ecs_derive_table[k].source, src) != 0) {
                    printf("  FAIL source '%s' is split: row %zu ('%s') sits inside it\n", src, k,
                           ecs_derive_table[k].source);
                    split = 1;
                }
            }
        }
        check(!split, "same-source rows are contiguous");
    }

    /* A derived field may appear only once: the Python mirror is a dict keyed by
     * the derived name, so a duplicate would silently collapse and break parity. */
    {
        int dup = 0;
        for (size_t i = 0; i < ECS_DERIVE_COUNT; i++)
            for (size_t j = i + 1; j < ECS_DERIVE_COUNT; j++)
                if (strcmp(ecs_derive_table[i].derived, ecs_derive_table[j].derived) == 0) {
                    printf("  FAIL duplicate derived field '%s'\n", ecs_derive_table[i].derived);
                    dup = 1;
                }
        check(!dup, "each derived field is declared once");
    }

    printf("lookup\n");
    {
        static const char* const rows[][2] = {
            {"dns.question.name", "example.test"},
            {"event.action", "ACCEPT"},
        };
        fake_src_t ctx = {rows, sizeof rows / sizeof rows[0]};
        const char* out = NULL;
        size_t olen = 0;
        char buf[ECS_DERIVE_BUFSZ];

        check(!ecs_derive_lookup("source.ip", fake_get, &ctx, &out, &olen, buf, sizeof buf),
              "source.ip misses when the field is absent");
        check(ecs_derive_lookup("dns.question.name_entropy", fake_get, &ctx, &out, &olen, buf, sizeof buf) && olen > 0,
              "dns entropy resolves from dns.question.name");
        check(ecs_derive_lookup("event.type", fake_get, &ctx, &out, &olen, buf, sizeof buf) &&
                  olen == strlen("allowed") && memcmp(out, "allowed", olen) == 0,
              "event.type normalizes an iptables ACCEPT");
        check(!ecs_derive_lookup("destination.ip", fake_get, &ctx, &out, &olen, buf, sizeof buf),
              "destination.ip is not a derived field");
        check(!ecs_derive_lookup("not.a.field", fake_get, &ctx, &out, &olen, buf, sizeof buf),
              "an unknown field name does not resolve");
    }

    printf("geo base\n");
    {
        char gbuf[32];
        check(ecs_geo_base("source.ip", gbuf, sizeof gbuf) && strcmp(gbuf, "!source") == 0, "source.ip stamps !source");
        check(ecs_geo_base("destination.ip", gbuf, sizeof gbuf) && strcmp(gbuf, "!destination") == 0,
              "destination.ip stamps !destination");
        check(ecs_geo_base("src_ip", gbuf, sizeof gbuf) && strcmp(gbuf, "!src_ip") == 0, "src_ip stamps !src_ip");
        check(ecs_geo_base("dest_ip", gbuf, sizeof gbuf) && strcmp(gbuf, "!dest_ip") == 0, "dest_ip stamps !dest_ip");
        check(ecs_geo_base("src", gbuf, sizeof gbuf) && strcmp(gbuf, "!source") == 0, "CEF src stamps !source");
        check(ecs_geo_base("dst", gbuf, sizeof gbuf) && strcmp(gbuf, "!destination") == 0,
              "CEF dst stamps !destination");
        check(ecs_geo_base("proto", gbuf, sizeof gbuf) && strcmp(gbuf, "!proto") == 0,
              "a non-ip scalar keeps its own name");
        check(ecs_geo_base("src_ip", gbuf, 3) == 0, "too-small buffer is rejected");
    }

    if (failures) {
        printf("\n%d check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nall checks passed\n");
    return 0;
}
