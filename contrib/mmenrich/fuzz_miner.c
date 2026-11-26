/* fuzz_miner.c
 * Differential fuzz harness proving the mmenrich SIMD IOC miner
 * (mine_iocs_simd) is bit-identical to the scalar reference
 * (mine_iocs_scalar) on the host arch (AVX2 on x86-64, NEON on aarch64).
 *
 * This is the anti-TurboVM soundness gate for the pattern-mode miner. The SIMD
 * tokenizer shipped a double-advance bug (a shared `i += t_len` applied on top
 * of the AVX2 tokenizer loop that had ALREADY advanced i) that silently dropped
 * IOCs by position - exactly the failure that hides when a vector path is never
 * differentially checked against a scalar oracle. Property under test:
 *
 *   for every input, mine_iocs_simd() and mine_iocs_scalar() produce the SAME
 *   ioc_report_t - identical per-type candidate counts AND identical extracted
 *   spans (offset + length), in the same order, with the same `dropped` count.
 *
 * The corpus mixes adversarial bytes (NUL, high non-ASCII) with planted IOCs
 * (IPv4, domain, email, hex hash) placed at random offsets AND deliberately
 * straddling 16/32-byte SIMD chunk boundaries - the exact class the double
 * advance corrupted. A fixed regression corpus pins the cases that first
 * exposed the bug. Deterministic (fixed-seed xorshift), so a failure reproduces
 * from the printed seed and it is CI-stable. No unit-test framework: exits
 * non-zero on divergence with the reproducing input.
 *
 * The miner only extracts (the caller does the lookups),
 * so the harness is self-contained and tests the tokenizer/extractor - the part
 * that diverged - without needing a database.
 *
 * Build: cc -std=c11 -O2 -march=native fuzz_miner.c -o fuzz_miner (see
 *        Makefile.dev). On x86-64+gcc/clang the AVX2 tokenizer is always
 *        compiled in (per-function target("avx2") attributes let it build
 *        regardless of the command line's baseline -march - see
 *        thrt_miner.h's SIMD Detection block) and mine_iocs_simd() picks it
 *        at runtime only on a CPU that actually reports AVX2 support,
 *        falling back to scalar token-skip otherwise; the printed ARCH line
 *        reports which path THIS run actually took. A pure-scalar,
 *        non-x86/non-aarch64 build has nothing to differentially check and
 *        reports "scalar-only".
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

#include "thrt_logic.h" /* Hash/Bloom/IP lookup decls required by thrt_miner.h */
#include "thrt_miner.h" /* mine_iocs_scalar, mine_iocs_simd, ioc_report_t */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(THRT_SIMD_AVX2)
    /* THRT_SIMD_AVX2 is a compile-time capability, not a runtime guarantee:
     * mine_iocs_simd() dispatches to AVX2 or scalar per-message based on
     * thrt_cpu_has_avx2(). Report which path this actual host will run. */
    #define ARCH (thrt_cpu_has_avx2() ? "x86-64 AVX2 (runtime-detected)" : "x86-64 scalar (host lacks AVX2)")
#elif defined(THRT_SIMD_NEON)
    #define ARCH "aarch64 NEON"
#else
    #define ARCH "scalar-only (no SIMD compiled - nothing to differentially check)"
#endif

/* Deterministic xorshift64 PRNG (no time / Math.random dependence). */
static uint64_t g_rng = 0x9E3779B97F4A7C15ULL;
static uint64_t xrand(void) {
    uint64_t x = g_rng;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    g_rng = x;
    return x;
}
static uint32_t xrange(uint32_t n) {
    return n ? (uint32_t)(xrand() % n) : 0;
}

static int g_fail = 0;

/* Fill buf[0..len) with bytes from a small IOC-ish alphabet plus, occasionally,
 * an adversarial byte (NUL or a high non-ASCII byte). The alphabet is dense in
 * the characters that make and break tokens (digits, dot, colon, @, letters,
 * spaces, slash) so real IOCs form often and token boundaries land in every
 * SIMD lane position. */
static void fill_bytes(char* buf, size_t len) {
    /* Dense in every byte TOKEN_SKIP_LUT classifies as a separator, not just
     * the ones that make IOCs: a byte this fuzz never emits can hide a real
     * SIMD/scalar divergence in that byte's classification indefinitely,
     * however many iterations run. */
    static const char alpha[] = "0123456789abcdef.:@-_/^!\"&'()+,;<=>?`[]{}~\\ ABChttps";
    for (size_t i = 0; i < len; i++) {
        uint32_t roll = xrange(100);
        if (roll < 3)
            buf[i] = 0x00; /* embedded NUL */
        else if (roll < 6)
            buf[i] = (char)(0x80 + xrange(0x80)); /* high, non-ASCII */
        else
            buf[i] = alpha[xrange(sizeof(alpha) - 1)];
    }
}

/* --- IOC planters: write a well-formed IOC at buf+off, return its length ---- */
static size_t plant_ipv4(char* buf, size_t off) {
    int n = snprintf(buf + off, 16, "%u.%u.%u.%u", xrange(256), xrange(256), xrange(256), xrange(256));
    return n > 0 ? (size_t)n : 0;
}
static size_t plant_domain(char* buf, size_t off) {
    static const char* labels[] = {"evil", "example", "com", "net", "bad", "c2host", "mal"};
    int n = snprintf(buf + off, 40, "%s.%s.%s", labels[xrange(7)], labels[xrange(7)], labels[xrange(7)]);
    return n > 0 ? (size_t)n : 0;
}
static size_t plant_email(char* buf, size_t off) {
    int n = snprintf(buf + off, 40, "user%u@evil.example.com", xrange(1000));
    return n > 0 ? (size_t)n : 0;
}
static size_t plant_hash(char* buf, size_t off) {
    static const char hexd[] = "0123456789abcdef";
    const size_t widths[] = {32, 40, 64}; /* md5 / sha1 / sha256 */
    size_t w = widths[xrange(3)];
    for (size_t i = 0; i < w; i++) buf[off + i] = hexd[xrange(16)];
    return w;
}

/* --- full-report equality (offset + length of every span, every type) ------ */
static int spans_eq(const char* buf, const ioc_span_t* a, size_t na, const ioc_span_t* b, size_t nb) {
    if (na != nb) return 0;
    for (size_t k = 0; k < na; k++) {
        if ((a[k].ptr - buf) != (b[k].ptr - buf)) return 0;
        if (a[k].len != b[k].len) return 0;
    }
    return 1;
}
static int reports_eq(const char* buf, const ioc_report_t* a, const ioc_report_t* b) {
    return a->dropped == b->dropped && spans_eq(buf, a->ips, a->ip_count, b->ips, b->ip_count) &&
           spans_eq(buf, a->domains, a->domain_count, b->domains, b->domain_count) &&
           spans_eq(buf, a->file_threats, a->threat_count, b->file_threats, b->threat_count) &&
           spans_eq(buf, a->emails, a->email_count, b->emails, b->email_count) &&
           spans_eq(buf, a->hashes, a->hash_count, b->hashes, b->hash_count) &&
           spans_eq(buf, a->shellcodes, a->shellcode_count, b->shellcodes, b->shellcode_count);
}

static void dump_hex(const char* buf, size_t len) {
    fputs("        input: \"", stderr);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c >= 0x20 && c < 0x7f && c != '"' && c != '\\')
            fputc(c, stderr);
        else
            fprintf(stderr, "\\x%02x", c);
    }
    fprintf(stderr, "\" (len=%zu)\n", len);
}

/* Run one differential case: scalar vs SIMD over the same buffer. */
static void check_case(const char* buf, size_t len, const char* origin, long it) {
#if defined(THRT_SIMD_AVX2) || defined(THRT_SIMD_NEON)
    ioc_report_t rs, rv;
    mine_iocs_scalar(buf, len, &rs);
    mine_iocs_simd(buf, len, &rv);
    if (!reports_eq(buf, &rs, &rv)) {
        g_fail++;
        fprintf(stderr,
                "[FAIL] %s @iter %ld: scalar(ip=%zu dom=%zu thr=%zu eml=%zu hsh=%zu drop=%zu) != "
                "simd(ip=%zu dom=%zu thr=%zu eml=%zu hsh=%zu drop=%zu)\n",
                origin, it, rs.ip_count, rs.domain_count, rs.threat_count, rs.email_count, rs.hash_count, rs.dropped,
                rv.ip_count, rv.domain_count, rv.threat_count, rv.email_count, rv.hash_count, rv.dropped);
        dump_hex(buf, len);
    }
#else
    (void)buf;
    (void)len;
    (void)origin;
    (void)it;
#endif
}

/* Direct scalar-vs-SIMD comparison of analyze_token's own output (dot/colon/
 * at counts, not_ipv4_mask, not_hex_mask) on a single already-extracted
 * token, bypassing mine_iocs_simd()/classify_and_store(). check_case() only
 * observes classify_and_store()'s DOWNSTREAM decision, so a stats
 * discrepancy that does not happen to cross one of its branch conditions
 * (e.g. dot_count off by a few, when the branch only cares about dot_count
 * == 3 or > 0) is invisible to it even though analyze_token itself diverged.
 * This checks the unit the two SIMD-vs-scalar bugs in this file actually
 * lived in. */
static int token_stats_eq(const token_stats_t* a, const token_stats_t* b) {
    return a->dot_count == b->dot_count && a->colon_count == b->colon_count && a->at_count == b->at_count &&
           a->not_ipv4_mask == b->not_ipv4_mask && a->not_hex_mask == b->not_hex_mask;
}
static void check_analyze_case(const char* tok, size_t len, const char* origin, long it) {
#if defined(THRT_SIMD_AVX2) || defined(THRT_SIMD_NEON)
    token_stats_t sa = {0}, sb = {0};
    analyze_token_scalar(tok, len, &sa);
    #if defined(THRT_SIMD_NEON)
    analyze_token_neon(tok, len, &sb);
    #else
    if (thrt_cpu_has_avx2())
        analyze_token_avx2(tok, len, &sb);
    else
        analyze_token_scalar(tok, len, &sb);
    #endif
    if (!token_stats_eq(&sa, &sb)) {
        g_fail++;
        fprintf(stderr,
                "[FAIL] %s @iter %ld: analyze_token scalar(dot=%d col=%d at=%d bad_ip=%u bad_hex=%u) != "
                "simd(dot=%d col=%d at=%d bad_ip=%u bad_hex=%u) len=%zu\n",
                origin, it, sa.dot_count, sa.colon_count, sa.at_count, sa.not_ipv4_mask, sa.not_hex_mask, sb.dot_count,
                sb.colon_count, sb.at_count, sb.not_ipv4_mask, sb.not_hex_mask, len);
        dump_hex(tok, len);
    }
#else
    (void)tok;
    (void)len;
    (void)origin;
    (void)it;
#endif
}

/* --- fixed regression corpus: the inputs that first exposed the bug + edges - */
static void run_corpus(void) {
    static const char* cases[] = {
        "connection from 192.0.2.66 to server", /* miss after 2 tokens */
        "src=10.20.30.40 dst=192.0.2.66 evil.example.com", /* second IP dropped */
        "user bob@evil.example.com hash d41d8cd98f00b204e9800998ecf8427e",
        "192.0.2.66", /* single token */
        "a 192.0.2.66 b",
        "", /* empty */
        "no iocs at all just words here and there",
        ".:.:.:.:.:.:.:.:.:.:.:.:.:.:.:.:.:.:.:.", /* pathological separators */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        check_case(cases[i], strlen(cases[i]), "corpus", (long)i);
}

/* --- long-token corpus: lengths the boundary/random fuzz below cannot reach -
 * their alphabet is separator-dense (fill_bytes()) and fuzz_boundaries()
 * additionally forces a separator every <=20 bytes, so neither can produce an
 * unbroken content run anywhere near the widths analyze_token_{neon,avx2}
 * process a token in: 16B (NEON) / 32B (AVX2) chunks, with an 8-bit valid-lane
 * mask and (pre-fix) an 8-bit accumulator. Dedicated large buffers, run once,
 * not randomized - these pin exact lengths, not a distribution. */
static void run_long_token_corpus(void) {
    static char tok[16384];
    static char framed[16400];
    long it = 0;
    size_t n;

    /* Exactly 256 bytes: 16 uppercase letters (definitely not-IPv4/not-hex)
     * followed by 240 digits with exactly 3 dots. The valid-lane mask used
     * to be built from `remaining` truncated into a single byte, and 256
     * wraps to 0 - zeroing the entire first 16-byte/32-byte chunk (the
     * letters) out of the classification, which would make not_ipv4_mask
     * read 0 (clean) instead of 1 (the letters are real, unmasked bytes). */
    n = 0;
    for (int i = 0; i < 16; i++) tok[n++] = (char)('A' + i);
    tok[n++] = '1';
    tok[n++] = '.';
    tok[n++] = '2';
    tok[n++] = '.';
    tok[n++] = '3';
    tok[n++] = '.';
    for (int i = 0; i < 234; i++) tok[n++] = (char)('0' + (i % 10));
    check_analyze_case(tok, n, "long-256B-letters+ipv4shape", it);
    framed[0] = ' ';
    memcpy(framed + 1, tok, n);
    framed[n + 1] = ' ';
    check_case(framed, n + 2, "long-256B-letters+ipv4shape", it++);

    /* 300 dots in one token: overflows an 8-bit dot-count accumulator or a
     * horizontal sum returned as uint8_t, regardless of chunk width. */
    n = 0;
    for (int i = 0; i < 300; i++) tok[n++] = '.';
    check_analyze_case(tok, n, "long-300-dots", it);
    framed[0] = ' ';
    memcpy(framed + 1, tok, n);
    framed[n + 1] = ' ';
    check_case(framed, n + 2, "long-300-dots", it++);

    /* >8KB unbroken hex run: beyond both vector paths' per-lane chunk-count
     * wrap threshold (255 chunks: 4080B at 16B/chunk, 8160B at 32B/chunk). */
    n = 0;
    for (int i = 0; i < 8300; i++) tok[n++] = "0123456789abcdef"[i % 16];
    check_analyze_case(tok, n, "long-8300B", it);
    framed[0] = ' ';
    memcpy(framed + 1, tok, n);
    framed[n + 1] = ' ';
    check_case(framed, n + 2, "long-8300B", it++);
}

/* --- boundary-straddling fuzz: plant one IOC so it crosses a 16/32B lane -----
 * The double-advance bug manifested when a token was skipped across a chunk
 * boundary, so explicitly place IOCs at boundary-1 / boundary / boundary+1. */
static void fuzz_boundaries(long iters) {
    char buf[512];
    for (long it = 0; it < iters; it++) {
        size_t len = 64 + xrange(320);
        fill_bytes(buf, len);
        /* guarantee a separator lattice so tokens are well-defined */
        for (size_t i = 0; i < len; i += 1 + xrange(20)) buf[i] = ' ';

        const uint32_t bases[] = {16, 32, 48, 64, 96, 128};
        uint32_t b = bases[xrange(6)];
        int skew = (int)xrange(3) - 1; /* -1, 0, +1 */
        long off = (long)b + skew;
        if (off < 1) off = 1;

        size_t iocLen = 0;
        switch (xrange(4)) {
            case 0:
                iocLen = plant_ipv4(buf, (size_t)off);
                break;
            case 1:
                iocLen = plant_domain(buf, (size_t)off);
                break;
            case 2:
                iocLen = plant_email(buf, (size_t)off);
                break;
            default:
                iocLen = plant_hash(buf, (size_t)off);
                break;
        }
        /* frame the IOC with separators so it is a clean token */
        if (off > 0) buf[off - 1] = ' ';
        if ((size_t)off + iocLen < len) buf[(size_t)off + iocLen] = ' ';

        check_case(buf, len, "boundary", it);
        if (g_fail > 8) return;
    }
}

/* --- broad random fuzz: many IOCs at random offsets among adversarial noise -- */
static void fuzz_random(long iters) {
    char buf[512];
    for (long it = 0; it < iters; it++) {
        size_t len = xrange(400);
        fill_bytes(buf, len);
        uint32_t plants = xrange(6);
        for (uint32_t p = 0; p < plants && len > 70; p++) {
            size_t off = xrange((uint32_t)(len - 70));
            size_t iocLen = 0;
            switch (xrange(4)) {
                case 0:
                    iocLen = plant_ipv4(buf, off);
                    break;
                case 1:
                    iocLen = plant_domain(buf, off);
                    break;
                case 2:
                    iocLen = plant_email(buf, off);
                    break;
                default:
                    iocLen = plant_hash(buf, off);
                    break;
            }
            if (off > 0) buf[off - 1] = ' ';
            if (off + iocLen < len) buf[off + iocLen] = ' ';
        }
        check_case(buf, len, "random", it);
        if (g_fail > 8) return;
    }
}

int main(int argc, char** argv) {
    long boundary_iters = 1000000, random_iters = 1000000;
    if (argc > 1) g_rng = strtoull(argv[1], NULL, 0) | 1ULL; /* optional seed */
    printf("mmenrich IOC miner SIMD differential fuzz on %s (seed=0x%llx)\n", ARCH, (unsigned long long)g_rng);

#if !defined(THRT_SIMD_AVX2) && !defined(THRT_SIMD_NEON)
    printf("SKIP: built without a SIMD path; recompile with -mavx2 (x86) or on aarch64 to exercise the gate.\n");
    return 0;
#endif

    run_corpus();
    run_long_token_corpus();
    fuzz_boundaries(boundary_iters);
    fuzz_random(random_iters);

    if (g_fail == 0)
        printf("PASSED: mine_iocs_simd == mine_iocs_scalar over corpus + %ld boundary + %ld random iters\n",
               boundary_iters, random_iters);
    else
        printf("FAILED: %d SIMD/scalar miner divergence(s)\n", g_fail);
    return g_fail ? 1 : 0;
}
