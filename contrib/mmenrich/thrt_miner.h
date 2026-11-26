/* SPDX-License-Identifier: Apache-2.0 */

/* thrt_miner.h
 * Pattern-based IOC miner for mmenrich: extracts IP, domain, email, hash,
 * file and escaped-payload tokens from raw message text. Zero-copy: each
 * candidate is a span into the message. The caller looks the candidates up,
 * so the same lookup rules apply as for a parsed field.
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


#ifndef THRT_MINER_H
#define THRT_MINER_H

#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>

/* thrt_logic.h: the IPv6 parser and the CPU feature macros.
 * thrt_payload.h: URL extension, escaped-payload, and file-type
 * classification, shared with other modules. */
#include "thrt_logic.h"
#include "thrt_payload.h"
#include "mmenrich_atomic.h"

/* --- SIMD Detection ---
 * NEON is part of the mandatory AArch64 base ISA (unlike x86's SSE4.2/AVX2
 * tiers), so once __aarch64__ is set the vectorized tokenizer below is
 * always safe to run at compile time - no runtime check needed, matching
 * thrt_logic.h's compile-time NEON-CRC gating.
 *
 * x86-64 has no equivalent guarantee: the shipped package floor is
 * x86-64-v2/SSE4.2 (Makefile.am's MMENRICH_ARCHFLAGS), so the compiler
 * cannot be told to freely emit AVX2 for the whole translation unit without
 * silently raising that floor on every host. Instead every AVX2 tokenizer
 * function below carries a per-function `target("avx2")` attribute - the
 * compiler is allowed to use AVX2 instructions INSIDE those functions only,
 * regardless of the TU's default -march - and mine_iocs_simd() picks between
 * them and the scalar fallback via a runtime CPU-feature check
 * (thrt_cpu_has_avx2(), cached after the first call). Harmless and redundant
 * on a TU that already opts into -mavx2 (e.g. -march=native local builds),
 * required for the shipped -march=x86-64-v2 package build. Same
 * multiversioning idiom glibc/simdjson/zlib-ng use for the same reason. */
#if defined(__AVX2__) || ((defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__)))
    #include <immintrin.h>
    #define THRT_SIMD_AVX2 1
    #define THRT_AVX2_FN static __attribute__((target("avx2")))
#elif defined(__ARM_NEON) || defined(__aarch64__)
    #include <arm_neon.h>
    #define THRT_SIMD_NEON 1
#endif

/* --- 1. Tokenizer LUT (16x16 = 256) --- */
static const uint8_t TOKEN_SKIP_LUT[256] = {
    /* 0x00 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* 0x10 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* 0x20 */ 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1,  // Spc ! " # $ % & ' ( ) * + , - . /
    /* 0x30 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1,  // 0-9 : ; < = > ?
    /* 0x40 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // @ A-O
    /* 0x50 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,  // P-Z [ \ ] ^ _
    /* 0x60 */ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // ` a-o
    /* 0x70 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1,  // p-z { | } ~ DEL
    /* 0x80 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* 0x90 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* 0xA0 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* 0xB0 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* 0xC0 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* 0xD0 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* 0xE0 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* 0xF0 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

/* --- 2. Char Attributes LUT --- */
static const uint8_t CHAR_ATTR_LUT[256] = {
    /* 00-2D */ 0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    /* 2E .  */ 0x04,
    /* 2F /  */ 0,
    /* 30-39 */ 0x03,
    0x03,
    0x03,
    0x03,
    0x03,
    0x03,
    0x03,
    0x03,
    0x03,
    0x03,
    /* 3A :  */ 0x08,
    /* 3B-3F */ 0,
    0,
    0,
    0,
    0,
    /* 40 @  */ 0x10,
    /* 41-46 */ 0x02,
    0x02,
    0x02,
    0x02,
    0x02,
    0x02,  // A-F
    /* 47-60 */ 0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    /* 61-66 */ 0x02,
    0x02,
    0x02,
    0x02,
    0x02,
    0x02,  // a-f
    /* Rest  */ 0};

/* --- Structures --- */

/* A candidate: a span into the message. */
typedef struct {
    const char* ptr;
    size_t len;
} ioc_span_t;

/* Per-message, per-type cap on extracted IOC candidates. The report is a
 * stack structure on the hot path, so this bounds its size. Candidates beyond
 * the cap are not silently lost: add_candidate() counts them in
 * ioc_report_t.dropped, which the caller surfaces via the "cti.iocs_dropped"
 * impstats counter so operators can see when a message hit the limit. */
#define MAX_CANDIDATES 256
typedef struct {
    ioc_span_t ips[MAX_CANDIDATES];
    size_t ip_count;
    ioc_span_t domains[MAX_CANDIDATES];
    size_t domain_count;
    ioc_span_t file_threats[MAX_CANDIDATES];
    size_t threat_count;
    ioc_span_t emails[MAX_CANDIDATES];
    size_t email_count;
    ioc_span_t hashes[MAX_CANDIDATES];
    size_t hash_count;
    ioc_span_t shellcodes[MAX_CANDIDATES];
    size_t shellcode_count;
    size_t dropped; /* candidates discarded because a per-type cap was hit */
} ioc_report_t;

typedef struct {
    int dot_count;
    int colon_count;
    int at_count;
    uint32_t not_ipv4_mask;
    uint32_t not_hex_mask;
} token_stats_t;

/* --- Helpers --- */
static inline __attribute__((always_inline)) void add_candidate(
    ioc_report_t* rpt, ioc_span_t* list, size_t* count, const char* s, size_t l) {
    if (*count < MAX_CANDIDATES) {
        list[*count] = (ioc_span_t){s, l};
        (*count)++;
    } else {
        rpt->dropped++; /* record the drop instead of silently discarding */
    }
}

/* --- CLASSIFICATION ENGINE --- */

static __attribute__((unused)) void classify_and_store(const char* start,
                                                       size_t len,
                                                       token_stats_t* s,
                                                       ioc_report_t* out) {
    // 1. EMAIL
    if (s->at_count == 1) {
        if (len > 3 && start[0] != '@' && start[len - 1] != '@')
            add_candidate(out, out->emails, &out->email_count, start, len);
    }
    // 2. IPv4
    else if (s->dot_count == 3 && s->not_ipv4_mask == 0) {
        if (len > 0 && start[len - 1] == '.') return;  // Reject 1.2.3.4.
        add_candidate(out, out->ips, &out->ip_count, start, len);
    }
    // 3. IPv6
    else if (s->colon_count >= 2 && s->not_hex_mask == 0) {
        uint8_t tmp_ipv6[16];
        if (thrt_parse_ipv6_fast(start, len, tmp_ipv6)) add_candidate(out, out->ips, &out->ip_count, start, len);
    }
    // 4. HASHES
    else if (s->not_hex_mask == 0 && s->colon_count == 0 && s->dot_count == 0) {
        // Only accept standard Hash lengths
        if (len == 32 || len == 40 || len == 64 || len == 128)
            add_candidate(out, out->hashes, &out->hash_count, start, len);
    }

    // 5. SHELLCODE DETECTOR (Escaped Patterns \x.. \u..)
    // This catches "\x90\x90\x41" but ignores "a3f4..."
    else if (memchr(start, '\\', len)) {
        if (is_escaped_payload(start, len)) add_candidate(out, out->shellcodes, &out->shellcode_count, start, len);
    }
    // 6. FILES / DOMAINS
    else if (s->dot_count > 0 && s->colon_count == 0 && s->at_count == 0) {
        if (len < 4 || start[len - 1] == '.') return;

        const char* tld = NULL;
        bool has_upper = false;
        bool has_lower = false;
        for (size_t i = 0; i < len; i++) {
            char c = start[i];
            if (c == '.')
                tld = start + i + 1;
            else if (c >= 'A' && c <= 'Z')
                has_upper = true;
            else if (c >= 'a' && c <= 'z')
                has_lower = true;
        }

        if (has_upper && has_lower) return;

        if (tld) {
            size_t tld_len = (start + len) - tld;
            if (tld_len < 2 || tld_len > 10) return;  // Strict TLD length
            for (size_t i = 0; i < tld_len; i++)
                if (isdigit((unsigned char)tld[i])) return;

            int ftype = get_file_type(tld, tld_len);

            if (ftype == FILE_TYPE_IGNORE) return;

            if (ftype == FILE_TYPE_THREAT) {
                add_candidate(out, out->file_threats, &out->threat_count, start, len);
                return;
            }
            // Fallback: Domain
            add_candidate(out, out->domains, &out->domain_count, start, len);
        }
    }
}

static inline void analyze_token_scalar(const char* start, size_t len, token_stats_t* s) {
    const char* p = start;
    const char* end = start + len;
    uint32_t bad_ip = s->not_ipv4_mask;
    uint32_t bad_hex = s->not_hex_mask;
    int dots = s->dot_count;
    int cols = s->colon_count;
    int ats = s->at_count;
    while (p < end) {
        uint8_t attr = CHAR_ATTR_LUT[(uint8_t)*p++];
        if (!(attr & 0x05)) bad_ip = 1;
        if (!(attr & 0x0A)) bad_hex = 1;
        if (attr & 0x04) dots++;
        if (attr & 0x08) cols++;
        if (attr & 0x10) ats++;
    }
    s->not_ipv4_mask = bad_ip;
    s->not_hex_mask = bad_hex;
    s->dot_count = dots;
    s->colon_count = cols;
    s->at_count = ats;
}

/* --- OPTIMIZED SIMD --- */
#if defined(THRT_SIMD_NEON)
static inline size_t skip_separators_simd(const char* p, size_t max_len) {
    size_t i = 0;
    // Explicit check for all Scalar LUT separators to ensure consistency
    const uint8x16_t c_ctrl = vdupq_n_u8(0x21);  // 00-20
    const uint8x16_t c_bang = vdupq_n_u8('!');  // 0x21
    const uint8x16_t c_quo = vdupq_n_u8('"');  // 0x22
    const uint8x16_t c_amp = vdupq_n_u8('&');  // 0x26
    const uint8x16_t c_apo = vdupq_n_u8('\'');  // 0x27
    const uint8x16_t c_lpar = vdupq_n_u8('(');  // 0x28
    const uint8x16_t c_rpar = vdupq_n_u8(')');  // 0x29
    const uint8x16_t c_plus = vdupq_n_u8('+');  // 0x2B
    const uint8x16_t c_com = vdupq_n_u8(',');  // 0x2C
    const uint8x16_t c_sla = vdupq_n_u8('/');  // 0x2F
    const uint8x16_t c_semi = vdupq_n_u8(';');  // 0x3B-0x3F range start
    const uint8x16_t c_ques = vdupq_n_u8('?');  // 0x3B-0x3F range end
    const uint8x16_t c_lbrk = vdupq_n_u8('[');  // 0x5B-0x5D range start
    const uint8x16_t c_caret = vdupq_n_u8('^');  //
    const uint8x16_t c_rbrk = vdupq_n_u8(']');  // 0x5B-0x5D range end
    const uint8x16_t c_lcur = vdupq_n_u8('{');  // 0x7B: start of the all-separator top run
    const uint8x16_t c_backt = vdupq_n_u8('`');

    while (i + 16 <= max_len) {
        uint8x16_t v = vld1q_u8((const uint8_t*)(p + i));
        uint8x16_t sep = vcltq_u8(v, c_ctrl);  // < 0x21
        sep = vorrq_u8(sep, vceqq_u8(v, c_bang));
        sep = vorrq_u8(sep, vceqq_u8(v, c_quo));
        sep = vorrq_u8(sep, vceqq_u8(v, c_amp));
        sep = vorrq_u8(sep, vceqq_u8(v, c_apo));
        sep = vorrq_u8(sep, vceqq_u8(v, c_lpar));
        sep = vorrq_u8(sep, vceqq_u8(v, c_rpar));
        sep = vorrq_u8(sep, vceqq_u8(v, c_plus));
        sep = vorrq_u8(sep, vceqq_u8(v, c_com));
        sep = vorrq_u8(sep, vceqq_u8(v, c_sla));
        sep = vorrq_u8(sep, vceqq_u8(v, c_backt));
        sep = vorrq_u8(sep, vceqq_u8(v, c_caret));

        // Ranges
        sep = vorrq_u8(sep, vandq_u8(vcgeq_u8(v, c_semi), vcleq_u8(v, c_ques)));  // 3B-3F (; < = > ?)
        sep = vorrq_u8(sep, vandq_u8(vcgeq_u8(v, c_lbrk), vcleq_u8(v, c_rbrk)));  // 5B-5D ([ \ ])
        sep = vorrq_u8(sep, vcgeq_u8(v, c_lcur));  // 7B-FF: { | } ~ DEL + all high bytes (LUT: >=0x7B is separator)

        uint8x16_t content = vmvnq_u8(sep);
        if (vmaxvq_u32((uint32x4_t)content)) break;
        i += 16;
    }
    while (i < max_len && TOKEN_SKIP_LUT[(unsigned char)p[i]] == 1) i++;
    return i;
}

static inline size_t find_token_end_simd(const char* p, size_t max_len) {
    size_t i = 0;
    // Same separator set as skip_separators
    const uint8x16_t c_ctrl = vdupq_n_u8(0x21);
    const uint8x16_t c_bang = vdupq_n_u8('!');
    const uint8x16_t c_quo = vdupq_n_u8('"');
    const uint8x16_t c_amp = vdupq_n_u8('&');
    const uint8x16_t c_apo = vdupq_n_u8('\'');
    const uint8x16_t c_lpar = vdupq_n_u8('(');
    const uint8x16_t c_rpar = vdupq_n_u8(')');
    const uint8x16_t c_plus = vdupq_n_u8('+');
    const uint8x16_t c_com = vdupq_n_u8(',');
    const uint8x16_t c_sla = vdupq_n_u8('/');
    const uint8x16_t c_semi = vdupq_n_u8(';');
    const uint8x16_t c_ques = vdupq_n_u8('?');
    const uint8x16_t c_lbrk = vdupq_n_u8('[');
    const uint8x16_t c_caret = vdupq_n_u8('^');
    const uint8x16_t c_rbrk = vdupq_n_u8(']');
    const uint8x16_t c_lcur = vdupq_n_u8('{');
    const uint8x16_t c_backt = vdupq_n_u8('`');

    while (i + 16 <= max_len) {
        uint8x16_t v = vld1q_u8((const uint8_t*)(p + i));
        uint8x16_t sep = vcltq_u8(v, c_ctrl);
        sep = vorrq_u8(sep, vceqq_u8(v, c_bang));
        sep = vorrq_u8(sep, vceqq_u8(v, c_quo));
        sep = vorrq_u8(sep, vceqq_u8(v, c_amp));
        sep = vorrq_u8(sep, vceqq_u8(v, c_apo));
        sep = vorrq_u8(sep, vceqq_u8(v, c_lpar));
        sep = vorrq_u8(sep, vceqq_u8(v, c_rpar));
        sep = vorrq_u8(sep, vceqq_u8(v, c_plus));
        sep = vorrq_u8(sep, vceqq_u8(v, c_com));
        sep = vorrq_u8(sep, vceqq_u8(v, c_sla));
        sep = vorrq_u8(sep, vceqq_u8(v, c_backt));
        sep = vorrq_u8(sep, vceqq_u8(v, c_caret));

        sep = vorrq_u8(sep, vandq_u8(vcgeq_u8(v, c_semi), vcleq_u8(v, c_ques)));
        sep = vorrq_u8(sep, vandq_u8(vcgeq_u8(v, c_lbrk), vcleq_u8(v, c_rbrk)));
        sep = vorrq_u8(sep, vcgeq_u8(v, c_lcur));  // 7B-FF: { | } ~ DEL + all high bytes (LUT: >=0x7B is separator)

        if (vmaxvq_u32((uint32x4_t)sep)) break;
        i += 16;
    }
    while (i < max_len && TOKEN_SKIP_LUT[(unsigned char)p[i]] == 0) i++;
    return i;
}

static inline void analyze_token_neon(const char* start, size_t len, token_stats_t* s) {
    const char* p = start;
    size_t remaining = len;
    uint8x16_t v_bad_ip = vdupq_n_u8(0);
    uint8x16_t v_bad_hex = vdupq_n_u8(0);
    const uint8x16_t c_dot = vdupq_n_u8('.');
    const uint8x16_t c_col = vdupq_n_u8(':');
    const uint8x16_t c_at = vdupq_n_u8('@');
    const uint8x16_t c_zero = vdupq_n_u8('0');
    const uint8x16_t c_nine = vdupq_n_u8('9');
    const uint8x16_t c_20 = vdupq_n_u8(0x20);
    const uint8x16_t c_a = vdupq_n_u8('a');
    const uint8x16_t c_f = vdupq_n_u8('f');
    const uint8x16_t c_one = vdupq_n_u8(1);
    const uint8_t idx_arr[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    const uint8x16_t v_indices = vld1q_u8(idx_arr);
    while (remaining > 0) {
        /* Full 16B chunks load directly; the final partial chunk (< 16B) is
         * zero-padded into a stack buffer so the 128-bit load never reads past
         * the token/message buffer (which could straddle an unmapped page and
         * fault on a crafted input). valid_mask already discards the padded
         * lanes, so the result is identical to a masked full-width load. */
        uint8x16_t chunk;
        if (remaining >= 16) {
            chunk = vld1q_u8((const uint8_t*)p);
        } else {
            uint8_t tmp[16] = {0};
            memcpy(tmp, p, remaining);
            chunk = vld1q_u8(tmp);
        }
        /* vdupq_n_u8() takes a uint8_t: clamp remaining to at most 16 (the
         * lane count) BEFORE the dup, or a token >= 256 bytes truncates
         * `remaining` mod 256 - e.g. a 256-byte first chunk computes
         * vdupq_n_u8(0), masking every lane as invalid and silently hiding
         * real token content from the classifier. */
        uint8_t rem8 = (uint8_t)(remaining > 16 ? 16 : remaining);
        uint8x16_t valid_mask = vcgtq_u8(vdupq_n_u8(rem8), v_indices);
        uint8x16_t is_dot = vceqq_u8(chunk, c_dot);
        uint8x16_t is_col = vceqq_u8(chunk, c_col);
        uint8x16_t is_at = vceqq_u8(chunk, c_at);
        /* Reduce THIS chunk to a scalar and add to the native-width `int`
         * counter immediately, rather than accumulating counts in an 8-bit
         * lane across the whole token: a persistent byte-lane accumulator
         * (or a single vaddvq_u8 taken once at the end) silently wraps mod
         * 256 for a token with enough matching chars - e.g. 256+ dots -
         * misclassifying it downstream (a wrapped dot_count of 3 reads as a
         * plausible IPv4 octet count). Each per-chunk sum is <= 16 (fits
         * uint8_t/int trivially); accumulating in `s->*_count` (int) has no
         * realistic overflow risk. */
        s->dot_count += vaddvq_u8(vandq_u8(vandq_u8(is_dot, valid_mask), c_one));
        s->colon_count += vaddvq_u8(vandq_u8(vandq_u8(is_col, valid_mask), c_one));
        s->at_count += vaddvq_u8(vandq_u8(vandq_u8(is_at, valid_mask), c_one));
        uint8x16_t is_digit = vandq_u8(vcgeq_u8(chunk, c_zero), vcleq_u8(chunk, c_nine));
        uint8x16_t lower = vorrq_u8(chunk, c_20);
        uint8x16_t is_alpha = vandq_u8(vcgeq_u8(lower, c_a), vcleq_u8(lower, c_f));
        uint8x16_t is_hex = vorrq_u8(is_digit, is_alpha);
        uint8x16_t is_ipv4 = vorrq_u8(is_digit, is_dot);
        v_bad_ip = vorrq_u8(v_bad_ip, vandq_u8(vmvnq_u8(is_ipv4), valid_mask));
        uint8x16_t is_hex_full = vorrq_u8(is_hex, is_col);
        v_bad_hex = vorrq_u8(v_bad_hex, vandq_u8(vmvnq_u8(is_hex_full), valid_mask));
        if (remaining <= 16) break;
        p += 16;
        remaining -= 16;
    }
    /* v_bad_ip/v_bad_hex are OR-accumulated booleans (any bad lane ever
     * seen), not counts - safe to accumulate across arbitrarily many chunks
     * with no truncation risk, unlike the per-chunk counters above. */
    if (vmaxvq_u32((uint32x4_t)v_bad_ip)) s->not_ipv4_mask = 1;
    if (vmaxvq_u32((uint32x4_t)v_bad_hex)) s->not_hex_mask = 1;
}
#endif

#if defined(THRT_SIMD_AVX2)
/* Cached runtime AVX2 check: __builtin_cpu_supports reads a feature bitmap
 * the compiler runtime initializes once at process start, so this is a
 * memory read + bit test, not a CPUID per call. Cached anyway (one call
 * site per translation unit, benign if raced by concurrent first callers -
 * they all converge on the same value) to keep it off the per-message path
 * entirely: mine_iocs_simd() calls this once per message, not per token. */
static int thrt_cpu_has_avx2(void) {
    static int cached = -1;
    int c = MMENRICH_ATOMIC_LOAD(&cached, __ATOMIC_RELAXED);
    if (c < 0) {
        __builtin_cpu_init();
        c = __builtin_cpu_supports("avx2") ? 1 : 0;
        MMENRICH_ATOMIC_STORE(&cached, c, __ATOMIC_RELAXED);
    }
    return c;
}

/* AVX2 has no native unsigned byte compare (only signed cmpgt/cmpeq for 8-bit
 * lanes) - XOR both operands with 0x80 remaps the unsigned range onto the
 * signed one, the standard idiom, letting a single cmpgt_epi8 implement an
 * unsigned '>' with >=/<=/< derived from it and cmpeq. */
THRT_AVX2_FN __m256i thrt_avx2_flip(__m256i v) {
    return _mm256_xor_si256(v, _mm256_set1_epi8((char)0x80));
}
THRT_AVX2_FN __m256i thrt_avx2_cmpgt_epu8(__m256i a, __m256i b) {
    return _mm256_cmpgt_epi8(thrt_avx2_flip(a), thrt_avx2_flip(b));
}
THRT_AVX2_FN __m256i thrt_avx2_cmplt_epu8(__m256i a, __m256i b) {
    return thrt_avx2_cmpgt_epu8(b, a);
}
THRT_AVX2_FN __m256i thrt_avx2_cmpge_epu8(__m256i a, __m256i b) {
    return _mm256_or_si256(thrt_avx2_cmpgt_epu8(a, b), _mm256_cmpeq_epi8(a, b));
}
THRT_AVX2_FN __m256i thrt_avx2_cmple_epu8(__m256i a, __m256i b) {
    return thrt_avx2_cmpge_epu8(b, a);
}

/* Horizontal sum of 32 unsigned byte lanes. psadbw against zero sums each
 * group of 8 bytes into the low 16 bits of one 64-bit lane (four such lanes
 * per 256-bit register); a couple of 64-bit adds combine them. Standard
 * reduction idiom - the AVX2 equivalent of NEON's vaddvq_u8. */
THRT_AVX2_FN uint32_t thrt_avx2_hsum_epu8(__m256i v) {
    __m256i sad = _mm256_sad_epu8(v, _mm256_setzero_si256());
    __m128i lo = _mm256_castsi256_si128(sad);
    __m128i hi = _mm256_extracti128_si256(sad, 1);
    __m128i sum = _mm_add_epi64(lo, hi);
    sum = _mm_add_epi64(sum, _mm_srli_si128(sum, 8));
    return (uint32_t)_mm_cvtsi128_si32(sum);
}

/* Must classify every byte identically to TOKEN_SKIP_LUT and to the NEON
 * skip_separators_simd/find_token_end_simd pair, 32 bytes/iteration instead
 * of 16 - the scalar table is the single source of truth all three vector
 * paths mirror. fuzz_miner.c's alphabet is deliberately dense in every byte
 * TOKEN_SKIP_LUT treats specially so a classification mismatch here cannot
 * hide behind a corpus that never exercises the differing byte. */
THRT_AVX2_FN size_t skip_separators_avx2(const char* p, size_t max_len) {
    size_t i = 0;
    const __m256i c_ctrl = _mm256_set1_epi8(0x21);
    const __m256i c_bang = _mm256_set1_epi8('!');
    const __m256i c_quo = _mm256_set1_epi8('"');
    const __m256i c_amp = _mm256_set1_epi8('&');
    const __m256i c_apo = _mm256_set1_epi8('\'');
    const __m256i c_lpar = _mm256_set1_epi8('(');
    const __m256i c_rpar = _mm256_set1_epi8(')');
    const __m256i c_plus = _mm256_set1_epi8('+');
    const __m256i c_com = _mm256_set1_epi8(',');
    const __m256i c_sla = _mm256_set1_epi8('/');
    const __m256i c_backt = _mm256_set1_epi8('`');
    const __m256i c_caret = _mm256_set1_epi8('^');
    const __m256i c_semi = _mm256_set1_epi8(';');
    const __m256i c_ques = _mm256_set1_epi8('?');
    const __m256i c_lbrk = _mm256_set1_epi8('[');
    const __m256i c_rbrk = _mm256_set1_epi8(']');
    const __m256i c_lcur = _mm256_set1_epi8('{');

    while (i + 32 <= max_len) {
        __m256i v = _mm256_loadu_si256((const __m256i*)(p + i));
        __m256i sep = thrt_avx2_cmplt_epu8(v, c_ctrl);
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_bang));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_quo));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_amp));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_apo));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_lpar));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_rpar));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_plus));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_com));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_sla));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_backt));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_caret));
        sep = _mm256_or_si256(sep, _mm256_and_si256(thrt_avx2_cmpge_epu8(v, c_semi), thrt_avx2_cmple_epu8(v, c_ques)));
        sep = _mm256_or_si256(sep, _mm256_and_si256(thrt_avx2_cmpge_epu8(v, c_lbrk), thrt_avx2_cmple_epu8(v, c_rbrk)));
        sep = _mm256_or_si256(sep, thrt_avx2_cmpge_epu8(v, c_lcur));

        /* Opposite polarity from find_token_end_avx2: this function is
         * SKIPPING separators, so the fast loop may only advance a whole 32B
         * block while EVERY byte in it is a separator - stop as soon as the
         * block contains even one content (non-separator) byte, or the skip
         * overruns into real token data. */
        __m256i content = _mm256_xor_si256(sep, _mm256_set1_epi8((char)0xFF));
        if (!_mm256_testz_si256(content, content)) break;
        i += 32;
    }
    while (i < max_len && TOKEN_SKIP_LUT[(unsigned char)p[i]] == 1) i++;
    return i;
}

THRT_AVX2_FN size_t find_token_end_avx2(const char* p, size_t max_len) {
    size_t i = 0;
    const __m256i c_ctrl = _mm256_set1_epi8(0x21);
    const __m256i c_bang = _mm256_set1_epi8('!');
    const __m256i c_quo = _mm256_set1_epi8('"');
    const __m256i c_amp = _mm256_set1_epi8('&');
    const __m256i c_apo = _mm256_set1_epi8('\'');
    const __m256i c_lpar = _mm256_set1_epi8('(');
    const __m256i c_rpar = _mm256_set1_epi8(')');
    const __m256i c_plus = _mm256_set1_epi8('+');
    const __m256i c_com = _mm256_set1_epi8(',');
    const __m256i c_sla = _mm256_set1_epi8('/');
    const __m256i c_backt = _mm256_set1_epi8('`');
    const __m256i c_caret = _mm256_set1_epi8('^');
    const __m256i c_semi = _mm256_set1_epi8(';');
    const __m256i c_ques = _mm256_set1_epi8('?');
    const __m256i c_lbrk = _mm256_set1_epi8('[');
    const __m256i c_rbrk = _mm256_set1_epi8(']');
    const __m256i c_lcur = _mm256_set1_epi8('{');

    while (i + 32 <= max_len) {
        __m256i v = _mm256_loadu_si256((const __m256i*)(p + i));
        __m256i sep = thrt_avx2_cmplt_epu8(v, c_ctrl);
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_bang));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_quo));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_amp));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_apo));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_lpar));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_rpar));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_plus));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_com));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_sla));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_backt));
        sep = _mm256_or_si256(sep, _mm256_cmpeq_epi8(v, c_caret));
        sep = _mm256_or_si256(sep, _mm256_and_si256(thrt_avx2_cmpge_epu8(v, c_semi), thrt_avx2_cmple_epu8(v, c_ques)));
        sep = _mm256_or_si256(sep, _mm256_and_si256(thrt_avx2_cmpge_epu8(v, c_lbrk), thrt_avx2_cmple_epu8(v, c_rbrk)));
        sep = _mm256_or_si256(sep, thrt_avx2_cmpge_epu8(v, c_lcur));

        if (!_mm256_testz_si256(sep, sep)) break;
        i += 32;
    }
    while (i < max_len && TOKEN_SKIP_LUT[(unsigned char)p[i]] == 0) i++;
    return i;
}

THRT_AVX2_FN void analyze_token_avx2(const char* start, size_t len, token_stats_t* s) {
    const char* p = start;
    size_t remaining = len;
    __m256i v_bad_ip = _mm256_setzero_si256();
    __m256i v_bad_hex = _mm256_setzero_si256();
    const __m256i c_dot = _mm256_set1_epi8('.');
    const __m256i c_col = _mm256_set1_epi8(':');
    const __m256i c_at = _mm256_set1_epi8('@');
    const __m256i c_zero = _mm256_set1_epi8('0');
    const __m256i c_nine = _mm256_set1_epi8('9');
    const __m256i c_20 = _mm256_set1_epi8(0x20);
    const __m256i c_a = _mm256_set1_epi8('a');
    const __m256i c_f = _mm256_set1_epi8('f');
    const __m256i c_one = _mm256_set1_epi8(1);
    const uint8_t idx_arr[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                                 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    const __m256i v_indices = _mm256_loadu_si256((const __m256i*)idx_arr);

    while (remaining > 0) {
        /* Full 32B chunks load directly; the final partial chunk (< 32B) is
         * zero-padded into a stack buffer so the load never reads past the
         * token/message buffer (which could straddle an unmapped page and
         * fault on a crafted input) - same guard as analyze_token_neon. */
        __m256i chunk;
        if (remaining >= 32) {
            chunk = _mm256_loadu_si256((const __m256i*)p);
        } else {
            uint8_t tmp[32] = {0};
            memcpy(tmp, p, remaining);
            chunk = _mm256_loadu_si256((const __m256i*)tmp);
        }
        size_t rem_clamped = remaining > 32 ? 32 : remaining;
        __m256i valid_mask = thrt_avx2_cmplt_epu8(v_indices, _mm256_set1_epi8((char)rem_clamped));
        __m256i is_dot = _mm256_cmpeq_epi8(chunk, c_dot);
        __m256i is_col = _mm256_cmpeq_epi8(chunk, c_col);
        __m256i is_at = _mm256_cmpeq_epi8(chunk, c_at);
        /* Reduce THIS chunk to a scalar and add to the native-width `int`
         * counter immediately, rather than accumulating counts in an 8-bit
         * lane across the whole token: a persistent byte-lane accumulator
         * wraps mod 256 for a token with enough matching chars spread across
         * many chunks, misclassifying it downstream (a wrapped count reads
         * as a small, plausible one). Each per-chunk sum is <= 32 (fits
         * uint8_t/int trivially); accumulating in `s->*_count` (int) has no
         * realistic overflow risk. */
        s->dot_count += (int)thrt_avx2_hsum_epu8(_mm256_and_si256(_mm256_and_si256(is_dot, valid_mask), c_one));
        s->colon_count += (int)thrt_avx2_hsum_epu8(_mm256_and_si256(_mm256_and_si256(is_col, valid_mask), c_one));
        s->at_count += (int)thrt_avx2_hsum_epu8(_mm256_and_si256(_mm256_and_si256(is_at, valid_mask), c_one));
        __m256i is_digit = _mm256_and_si256(thrt_avx2_cmpge_epu8(chunk, c_zero), thrt_avx2_cmple_epu8(chunk, c_nine));
        __m256i lower = _mm256_or_si256(chunk, c_20);
        __m256i is_alpha = _mm256_and_si256(thrt_avx2_cmpge_epu8(lower, c_a), thrt_avx2_cmple_epu8(lower, c_f));
        __m256i is_hex = _mm256_or_si256(is_digit, is_alpha);
        __m256i is_ipv4 = _mm256_or_si256(is_digit, is_dot);
        v_bad_ip = _mm256_or_si256(v_bad_ip, _mm256_andnot_si256(is_ipv4, valid_mask));
        __m256i is_hex_full = _mm256_or_si256(is_hex, is_col);
        v_bad_hex = _mm256_or_si256(v_bad_hex, _mm256_andnot_si256(is_hex_full, valid_mask));
        if (remaining <= 32) break;
        p += 32;
        remaining -= 32;
    }
    /* v_bad_ip/v_bad_hex are OR-accumulated booleans (any bad lane ever
     * seen), not counts - safe to accumulate across arbitrarily many chunks
     * with no truncation risk, unlike the per-chunk counters above. */
    if (!_mm256_testz_si256(v_bad_ip, v_bad_ip)) s->not_ipv4_mask = 1;
    if (!_mm256_testz_si256(v_bad_hex, v_bad_hex)) s->not_hex_mask = 1;
}
#endif

static void mine_iocs_scalar(const char* buf, size_t len, ioc_report_t* out) {
    memset(out, 0, sizeof(ioc_report_t));
    size_t i = 0;
    while (i < len) {
        while (i < len && TOKEN_SKIP_LUT[(unsigned char)buf[i]] == 1) i++;
        if (i == len) break;
        const char* start = buf + i;
        size_t t_len = 0;
        while (i < len && TOKEN_SKIP_LUT[(unsigned char)buf[i]] == 0) {
            i++;
            t_len++;
        }
        if (t_len >= 3) {
            token_stats_t s = {0};
            analyze_token_scalar(start, t_len, &s);
            classify_and_store(start, t_len, &s, out);
        }
    }
}

#if defined(THRT_SIMD_AVX2) || defined(THRT_SIMD_NEON)
static void mine_iocs_simd(const char* buf, size_t len, ioc_report_t* out) {
    memset(out, 0, sizeof(ioc_report_t));
    #if defined(THRT_SIMD_AVX2)
    /* One runtime check per message, not per token: this file's own build
     * floor (x86-64-v2/SSE4.2) does not guarantee AVX2, so a CPU without it
     * must fall back to the manual scalar skip below, same as a pure-scalar
     * build would. */
    const int use_avx2 = thrt_cpu_has_avx2();
    #endif
    size_t i = 0;
    while (i < len) {
    #if defined(THRT_SIMD_NEON)
        i += skip_separators_simd(buf + i, len - i);
        if (i >= len) break;
        const char* start = buf + i;
        size_t t_len = find_token_end_simd(buf + i, len - i);
        i += t_len; /* advance past the token: find_token_end_simd only measures
                     * it, it does not move i (unlike the scalar loop below) */
    #else
        const char* start;
        size_t t_len;
        if (use_avx2) {
            i += skip_separators_avx2(buf + i, len - i);
            if (i >= len) break;
            start = buf + i;
            t_len = find_token_end_avx2(buf + i, len - i);
            i += t_len; /* find_token_end_avx2 only measures the token */
        } else {
            while (i < len && TOKEN_SKIP_LUT[(unsigned char)buf[i]] == 1) i++;
            if (i == len) break;
            start = buf + i;
            t_len = 0;
            while (i < len && TOKEN_SKIP_LUT[(unsigned char)buf[i]] == 0) {
                i++;
                t_len++;
            }
            /* the loop above already advanced i past the token */
        }
    #endif

        if (t_len >= 3) {
            token_stats_t s = {0};
    #if defined(THRT_SIMD_NEON)
            if (t_len >= 4)
                analyze_token_neon(start, t_len, &s);
            else
                analyze_token_scalar(start, t_len, &s);
    #else
            if (use_avx2 && t_len >= 4)
                analyze_token_avx2(start, t_len, &s);
            else
                analyze_token_scalar(start, t_len, &s);
    #endif
            classify_and_store(start, t_len, &s, out);
        }
        /* i already points at the next separator/token for every path above
         * (each tokenizer loop advances i inline, or the manual scalar skip
         * does). A second `i += t_len` here would double-advance and silently
         * skip a token's worth of input, dropping IOCs and diverging from the
         * scalar miner. */
    }
}
#endif

static inline void mine_iocs_pattern(const char* buf, size_t len, ioc_report_t* out) {
#if defined(THRT_SIMD_AVX2) || defined(THRT_SIMD_NEON)
    mine_iocs_simd(buf, len, out);
#else
    mine_iocs_scalar(buf, len, out);
#endif
}

#endif  // THRT_MINER_H
