/* SPDX-License-Identifier: Apache-2.0 */

/* ecs_derive.h
 * ECS-native derived-field layer (header-only). Derives canonical Elastic
 * Common Schema sub-fields from a parsed primary field, the way an Elastic
 * ingest pipeline's URL and grok processors do, but inside the mmenrich C hot
 * path, once per event, with no liblognorm snapshot or ABI change.
 *
 * mmenrich emits the derived fields into $! so downstream consumers see the
 * same canonical field names. The transform set is declared by the X-macro
 * table in ecs_derive_table.def; keep the ECS_XF_* entries in sync there.
 *
 * Two transform kinds:
 *  - SLICE transforms (url.path, identity) return a zero-copy pointer INTO the
 *    borrowed source value, no allocation.
 *  - COMPUTED transforms (DGA numeric features: entropy, digit ratio, longest
 *    label) format a small integer into a caller-provided scratch buffer. Scaled
 *    to integers (e.g. entropy x100) so the integer numeric matcher can threshold
 *    them from Sigma rules. Still allocation-free (caller owns the buffer).
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
#ifndef ECS_DERIVE_H
#define ECS_DERIVE_H

#include <stddef.h>
#include <string.h>
#include <math.h> /* log2 for the DNS entropy feature */
#include <stdio.h> /* snprintf for computed-numeric transforms */

/* Scratch buffer a caller must provide for COMPUTED transforms. Longest output
 * is a small signed integer; 24 bytes is ample. */
#define ECS_DERIVE_BUFSZ 24

/* Transform ids. A row's transform decides how source -> derived is computed.
 * Names mirror the tokens used in ecs_derive_table.def. */
typedef enum {
    ECS_XF_IDENTITY = 0, /* derived == source verbatim (pure alias)               */
    ECS_XF_URL_PATH, /* path portion: source up to '?' (query) or '#' (frag)  */
    ECS_XF_LOWER, /* ASCII-lowercased copy (ECS mandates lowercase enums)  */
    ECS_XF_FW_DISPOSITION, /* vendor firewall verb -> ECS event.type allowed|denied */
    /* --- COMPUTED numeric DGA features (integer output into the caller buffer) --- */
    ECS_XF_DNS_ENTROPY, /* Shannon entropy of the name, bits/char x100            */
    ECS_XF_DNS_DIGIT_RATIO, /* digit fraction of the name x100 (0..100)            */
    ECS_XF_DNS_MAX_LABEL, /* length of the longest dot-separated label             */
    /* --- COMPUTED HTTP structural features (integer output into the buffer) ---- */
    ECS_XF_URL_LENGTH, /* total URL length in bytes                          */
    ECS_XF_URL_PCT_COUNT, /* count of '%' (percent-encoding / obfuscation)      */
    ECS_XF_URL_SPECIAL_COUNT, /* count of injection metacharacters '"<>;()|` + NUL  */
    ECS_XF_URL_TRAVERSAL_COUNT /* count of "../" and "..\\" path-traversal runs     */
} ecs_derive_transform_t;

/* Shannon entropy (bits per char) of a byte string, scaled x100 to an integer.
 * Single pass over the bytes + one log2 per DISTINCT byte (<= alphabet size, so
 * a few tens for a domain). Algorithmically-generated (DGA) names score high. */
static inline __attribute__((always_inline)) long ecs__shannon_x100(const char *s, size_t n) {
    unsigned cnt[256] = {0};
    double h;
    long v;
    if (n == 0) return 0;
    for (size_t i = 0; i < n; i++) cnt[(unsigned char)s[i]]++;
    h = 0.0;
    for (int i = 0; i < 256; i++) {
        if (cnt[i]) {
            double p = (double)cnt[i] / (double)n;
            h -= p * log2(p);
        }
    }
    v = (long)(h * 100.0 + 0.5);
    return v;
}

/* Injection metacharacters: chars that carry SQLi/XSS/command-injection syntax
 * yet are RARE, unencoded, in benign URLs. Deliberately EXCLUDES URL-structural
 * chars (& = + / . - _ % : ? #) so ordinary query strings score ~0. A raw NUL
 * in a URL is always an evasion/smuggling attempt, so it counts too. */
static inline __attribute__((always_inline)) int ecs__is_injection_char(unsigned char c) {
    switch (c) {
        case '\'':
        case '"':
        case '<':
        case '>':
        case ';':
        case '(':
        case ')':
        case '|':
        case '`':
        case '\0':
            return 1;
        default:
            return 0;
    }
}

typedef struct {
    const char *derived; /* ECS field produced, e.g. "url.path"     */
    const char *source; /* ECS field read,     e.g. "url.original" */
    int transform; /* ecs_derive_transform_t                  */
} ecs_derive_entry_t;

/* The table, materialized from the shared .def. */
static const ecs_derive_entry_t ecs_derive_table[] = {
#define ECS_DERIVE(d, s, t) {d, s, t},
#include "ecs_derive_table.def"
#undef ECS_DERIVE
};
#define ECS_DERIVE_COUNT (sizeof(ecs_derive_table) / sizeof(ecs_derive_table[0]))

/* Some DNS server debug logs write a query name in wire form: each label
 * is preceded by its length in parentheses, and (0) ends the name, as in
 * (3)www(7)example(3)com(0). The DNS features describe the name, not its
 * encoding. Measured on the wire form, the length markers add digits and
 * parentheses to every name, which raises its entropy and digit ratio, and
 * the longest label spans the whole name. ecs__dns_wire_decode writes the
 * dotted name (www.example.com) into dst and returns its length. It returns
 * 0 for a value that is not well-formed wire form, or that decodes to more
 * than a DNS name holds, and the caller then measures the value as written. */
#define ECS_DNS_NAME_MAX 255
#define ECS_DNS_LABEL_MAX 63
static inline size_t ecs__dns_wire_decode(const char *s, size_t n, char *dst, size_t cap) {
    size_t i = 0, o = 0;
    if (n < 3 || s[0] != '(') return 0;
    while (i < n) {
        size_t len = 0, digits = 0;
        if (s[i] != '(') return 0;
        i++;
        while (i < n && digits < 3 && s[i] >= '0' && s[i] <= '9') {
            len = len * 10 + (size_t)(s[i] - '0');
            i++;
            digits++;
        }
        if (digits == 0 || i >= n || s[i] != ')') return 0;
        i++;
        if (len == 0) return i == n ? o : 0; /* (0) ends the name */
        if (len > ECS_DNS_LABEL_MAX || len > n - i) return 0;
        if (o > 0) {
            if (o >= cap) return 0;
            dst[o++] = '.';
        }
        if (len > cap - o) return 0;
        memcpy(dst + o, s + i, len);
        o += len;
        i += len;
    }
    return o; /* the terminator was cut off: the labels are still whole */
}

/* Apply one transform to a borrowed source value (val,vlen). SLICE transforms
 * set (*out,*out_len) to a borrowed slice of `val`; COMPUTED transforms format
 * an integer into `buf` (>= ECS_DERIVE_BUFSZ) and point *out there. Returns 1 on
 * success, 0 for an unknown transform id. */
static inline __attribute__((always_inline)) int ecs_derive_apply(
    int xf, const char *val, size_t vlen, const char **out, size_t *out_len, char *buf, size_t bufcap) {
    switch (xf) {
        case ECS_XF_URL_PATH: {
            size_t n = vlen;
            for (size_t i = 0; i < vlen; i++) {
                if (val[i] == '?' || val[i] == '#') {
                    n = i;
                    break;
                }
            }
            *out = val;
            *out_len = n;
            return 1;
        }
        case ECS_XF_IDENTITY:
            *out = val;
            *out_len = vlen;
            return 1;
        case ECS_XF_FW_DISPOSITION: {
            /* Every firewall names the same two outcomes differently: pf says
             * pass/block, iptables ACCEPT/DROP, others allow/deny/reject. ECS
             * already has the normalized field for this (event.type), so map the
             * vendor verb once here rather than teaching every detection rule
             * every vendor's vocabulary.
             *
             * Translation verbs (nat, rdr) are deliberately NOT mapped: pf logs
             * a nat record AND a pass record for the same flow, so mapping both
             * to "allowed" would double-fire every allow rule. Anything
             * unrecognised returns 0: an absent event.type does not match,
             * whereas guessing could invert a rule's meaning. */
            static const struct {
                const char *verb;
                const char *type;
            } fwmap[] = {
                {"pass", "allowed"},    {"accept", "allowed"}, {"allow", "allowed"},  {"permit", "allowed"},
                {"allowed", "allowed"}, {"block", "denied"},   {"drop", "denied"},    {"deny", "denied"},
                {"reject", "denied"},   {"denied", "denied"},  {"blocked", "denied"},
            };
            char low[16];
            if (vlen == 0 || vlen >= sizeof low) return 0;
            for (size_t i = 0; i < vlen; i++) {
                unsigned char c = (unsigned char)val[i];
                low[i] = (char)((c >= 'A' && c <= 'Z') ? (c - 'A' + 'a') : c);
            }
            low[vlen] = '\0';
            for (size_t i = 0; i < sizeof fwmap / sizeof fwmap[0]; i++) {
                if (strcmp(low, fwmap[i].verb) == 0) {
                    /* static storage: borrowed like a SLICE, consumes no buf */
                    *out = fwmap[i].type;
                    *out_len = strlen(fwmap[i].type);
                    return 1;
                }
            }
            (void)buf;
            (void)bufcap;
            return 0;
        }
        case ECS_XF_LOWER: {
            /* ECS defines network.transport / network.protocol as lowercase
             * enums, and Suricata eve emits proto uppercase ("TCP"). Aliasing
             * verbatim would make `network.transport: tcp` miss every eve
             * event, so case-fold rather than copy. Fail closed on a value too
             * long for the scratch buffer: a truncated protocol token could
             * match the wrong rule, whereas an absent field simply does not
             * match. */
            if (vlen >= bufcap) return 0;
            for (size_t i = 0; i < vlen; i++) {
                unsigned char c = (unsigned char)val[i];
                buf[i] = (char)((c >= 'A' && c <= 'Z') ? (c - 'A' + 'a') : c);
            }
            buf[vlen] = '\0';
            *out = buf;
            *out_len = vlen;
            return 1;
        }
        case ECS_XF_DNS_ENTROPY: {
            /* The dotted name lives in this case's own buffer, which a
             * COMPUTED result never points into. */
            char dnsname[ECS_DNS_NAME_MAX];
            size_t dl = ecs__dns_wire_decode(val, vlen, dnsname, sizeof dnsname);
            long v = dl > 0 ? ecs__shannon_x100(dnsname, dl) : ecs__shannon_x100(val, vlen);
            int n = snprintf(buf, bufcap, "%ld", v);
            if (n < 0 || (size_t)n >= bufcap) return 0;
            *out = buf;
            *out_len = (size_t)n;
            return 1;
        }
        case ECS_XF_DNS_DIGIT_RATIO: {
            char dnsname[ECS_DNS_NAME_MAX];
            size_t dl = ecs__dns_wire_decode(val, vlen, dnsname, sizeof dnsname);
            const char *name = dl > 0 ? dnsname : val;
            size_t nlen = dl > 0 ? dl : vlen;
            size_t digits = 0;
            long v;
            int n;
            for (size_t i = 0; i < nlen; i++)
                if (name[i] >= '0' && name[i] <= '9') digits++;
            v = nlen ? (long)((digits * 100 + nlen / 2) / nlen) : 0;
            n = snprintf(buf, bufcap, "%ld", v);
            if (n < 0 || (size_t)n >= bufcap) return 0;
            *out = buf;
            *out_len = (size_t)n;
            return 1;
        }
        case ECS_XF_DNS_MAX_LABEL: {
            char dnsname[ECS_DNS_NAME_MAX];
            size_t dl = ecs__dns_wire_decode(val, vlen, dnsname, sizeof dnsname);
            const char *name = dl > 0 ? dnsname : val;
            size_t nlen = dl > 0 ? dl : vlen;
            size_t maxlen = 0, cur = 0;
            int n;
            for (size_t i = 0; i < nlen; i++) {
                if (name[i] == '.') {
                    cur = 0;
                } else if (++cur > maxlen) {
                    maxlen = cur;
                }
            }
            n = snprintf(buf, bufcap, "%zu", maxlen);
            if (n < 0 || (size_t)n >= bufcap) return 0;
            *out = buf;
            *out_len = (size_t)n;
            return 1;
        }
        case ECS_XF_URL_LENGTH: {
            int n = snprintf(buf, bufcap, "%zu", vlen);
            if (n < 0 || (size_t)n >= bufcap) return 0;
            *out = buf;
            *out_len = (size_t)n;
            return 1;
        }
        case ECS_XF_URL_PCT_COUNT: {
            size_t c = 0;
            int n;
            for (size_t i = 0; i < vlen; i++)
                if (val[i] == '%') c++;
            n = snprintf(buf, bufcap, "%zu", c);
            if (n < 0 || (size_t)n >= bufcap) return 0;
            *out = buf;
            *out_len = (size_t)n;
            return 1;
        }
        case ECS_XF_URL_SPECIAL_COUNT: {
            size_t c = 0;
            int n;
            for (size_t i = 0; i < vlen; i++)
                if (ecs__is_injection_char((unsigned char)val[i])) c++;
            n = snprintf(buf, bufcap, "%zu", c);
            if (n < 0 || (size_t)n >= bufcap) return 0;
            *out = buf;
            *out_len = (size_t)n;
            return 1;
        }
        case ECS_XF_URL_TRAVERSAL_COUNT: {
            size_t c = 0;
            int n;
            /* count "../" and "..\" runs; i+2 stays in-bounds since i+2 < vlen */
            for (size_t i = 0; i + 2 < vlen; i++) {
                if (val[i] == '.' && val[i + 1] == '.' && (val[i + 2] == '/' || val[i + 2] == '\\')) c++;
            }
            n = snprintf(buf, bufcap, "%zu", c);
            if (n < 0 || (size_t)n >= bufcap) return 0;
            *out = buf;
            *out_len = (size_t)n;
            return 1;
        }
        default:
            return 0;
    }
}

/* Source-field reader injected by each call site (wraps the turbo snapshot).
 * Must return 1 and set (*val,*vlen) when `name` is present, 0 otherwise. */
typedef int (*ecs_src_get_fn)(void *ctx, const char *name, const char **val, size_t *vlen);

/* Resolve a DERIVED field by name. If `name` is a table row whose source field
 * resolves via `get`, applies the transform and returns 1 with a borrowed
 * (*out,*out_len). Returns 0 if `name` is not derived or its source is absent. */
static inline __attribute__((always_inline)) int ecs_derive_lookup(
    const char *name, ecs_src_get_fn get, void *ctx, const char **out, size_t *out_len, char *buf, size_t bufcap) {
    for (size_t i = 0; i < ECS_DERIVE_COUNT; i++) {
        const ecs_derive_entry_t *e = &ecs_derive_table[i];
        const char *sval;
        size_t slen;
        if (strcmp(name, e->derived) != 0) continue;
        sval = NULL;
        slen = 0;
        if (!get(ctx, e->source, &sval, &slen) || sval == NULL) return 0;
        return ecs_derive_apply(e->transform, sval, slen, out, out_len, buf, bufcap);
    }
    return 0;
}

/* Bang-path of the ECS object GeoIP should stamp for a mapping turbo_key.
 *
 * ECS dotted keys: "source.ip" -> "!source".
 * CEF scalars: "src"/"dst" (Vectra) and "srcip"/"dstip". A key with no dot
 * and no CEF alias keeps its own name.
 *
 * Returns 1 on success, 0 if the output buffer is too small. */
static inline int ecs_geo_base(const char *turbo_key, char *out, size_t out_sz) {
    const char *last_dot;
    const char *base;
    size_t base_len;
    size_t j;
    if (turbo_key == NULL || out == NULL || out_sz < 3) return 0;
    last_dot = strrchr(turbo_key, '.');
    base = turbo_key;

    if (last_dot != NULL) {
        base_len = (size_t)(last_dot - turbo_key);
    } else if (strcmp(turbo_key, "src") == 0 || strcmp(turbo_key, "srcip") == 0) {
        /* CEF / ISA / vendor scalars (Vectra src=, Palo srcip=). */
        if (out_sz < 8) return 0;
        memcpy(out, "!source", 8);
        return 1;
    } else if (strcmp(turbo_key, "dst") == 0 || strcmp(turbo_key, "dstip") == 0) {
        if (out_sz < 13) return 0;
        memcpy(out, "!destination", 13);
        return 1;
    } else {
        base = NULL;
        base_len = 0;
        for (size_t i = 0; i < ECS_DERIVE_COUNT; i++) {
            const ecs_derive_entry_t *e = &ecs_derive_table[i];
            const char *ddot;
            if (strcmp(e->source, turbo_key) != 0) continue;
            ddot = strrchr(e->derived, '.');
            if (ddot == NULL || strcmp(ddot + 1, "ip") != 0) continue;
            base = e->derived;
            base_len = (size_t)(ddot - e->derived);
            break;
        }
        if (base == NULL) {
            base = turbo_key;
            base_len = strlen(turbo_key);
        }
    }

    if (base_len == 0 || base_len + 2 > out_sz) return 0;
    out[0] = '!';
    j = 1;
    for (size_t i = 0; i < base_len && j < out_sz - 1; i++) out[j++] = (base[i] == '.') ? '!' : base[i];
    out[j] = '\0';
    return 1;
}

#endif /* ECS_DERIVE_H */
