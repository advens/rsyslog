/* SPDX-License-Identifier: Apache-2.0 */

/* turbo_field.h: read a parsed field the way a template reads $!field.
 *
 * Modules such as mmenrich and mmsigma read fields by their dotted ECS name
 * ("source.ip"). msgGetJSONPropStr() in the rsyslog core answers from the
 * mmnormalize turbo snapshot, unless a $! write since the parse touched that
 * path (set $!source!ip = ..., unset $!source), in which case it answers
 * from the $! tree. So a module sees what the configuration wrote before it,
 * and what the modules before it wrote, exactly as a template does.
 *
 * The core copies the value while it holds the message mutex. The copy goes
 * into a per-worker store and stays valid until tf_store_reset(), which the
 * module calls at the start of each message. The store also remembers every
 * answer (absent included) until then, so a field read twice costs one read.
 * It keeps each name it has seen with the work that does not depend on the
 * message (the $! path, the core's msgJSONKey_t) for the worker's life.
 * tf_lock()/tf_unlock() take the mutex once for a batch of reads; between
 * them the module must not call anything that takes it (msgAddJSON()).
 * A module that reads a path it wrote itself since tf_store_reset() gets
 * the remembered answer from before the write.
 *
 * Copyright 2026 Advens.
 * Author: Jeremie Jourdin <jeremie.jourdin@advens.fr>
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
#ifndef TURBO_FIELD_H
#define TURBO_FIELD_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "msg.h"

#ifndef RS_HAVE_MSG_GET_JSON_PROP_STR
    #error "this rsyslog core has no msgGetJSONPropStr(): apply the rsyslog port msg.c patch"
#endif

/* The word copies below go through a call: inlined, a fortified memcpy()
 * into a buffer of known size at a variable offset becomes a checked call
 * per word. */
#if defined(__GNUC__)
    #define TF_NOINLINE __attribute__((noinline))
#else
    #define TF_NOINLINE
#endif

/* Longest dotted name read; a longer name is reported absent. */
#define TF_NAME_MAX 256
/* Size of the first store chunk. A message whose values do not fit gets
 * further chunks for that message only. */
#define TF_CHUNK 16384
/* Names seen by the worker, in an open-addressing table of TF_MEMO slots (a
 * power of two) filled to TF_MEMO_FILL at most, which keeps linear probes
 * short. A slot keeps its name for the worker's life and the answer for one
 * message. Names of TF_MEMO_NAME bytes or more, and names past the fill, are
 * read each time and not remembered. */
#define TF_MEMO 256
#define TF_MEMO_FILL 160
#define TF_MEMO_NAME 64

typedef struct tf_chunk {
    struct tf_chunk *next; /* older chunk, NULL for the first one */
    size_t cap;
    size_t used;
    char data[];
} tf_chunk_t;

typedef struct {
    uint32_t gen; /* the message found, val and len belong to */
    uint8_t nlen;
    uint8_t found;
    char name[TF_MEMO_NAME]; /* a copy: callers pass names in stack buffers */
    char path[TF_MEMO_NAME + 1]; /* "!source!ip", NUL-terminated */
    msgJSONKey_t key;
    const char *val;
    size_t len;
} tf_memo_t;

typedef struct {
    tf_chunk_t *head; /* chunk being filled; the first chunk is last in the list */
    uint32_t gen; /* bumped by tf_store_reset(): forgets every answer at once */
    unsigned n_memo; /* slots holding a name */
    /* 1 << 32 | hash of the dotted name in a slot holding a name, 0 in a
     * free one. Kept apart from the slots so that a probe reads one word per
     * slot. */
    uint64_t key[TF_MEMO];
    tf_memo_t memo[TF_MEMO];
} tf_store_t;

typedef struct {
    smsg_t *msg;
    tf_store_t *store;
    int locked; /* the caller holds the message mutex (tf_lock) */
} tf_ctx_t;

static inline void tf_lock(tf_ctx_t *const tf) {
    MsgLock(tf->msg);
    tf->locked = 1;
}

static inline void tf_unlock(tf_ctx_t *const tf) {
    tf->locked = 0;
    MsgUnlock(tf->msg);
}

static inline tf_chunk_t *tf_chunk_new(const size_t cap, tf_chunk_t *const next) {
    tf_chunk_t *const c = malloc(sizeof(*c) + cap);
    if (c == NULL) return NULL;
    c->next = next;
    c->cap = cap;
    c->used = 0;
    return c;
}

/* 0 on success, -1 when the first chunk cannot be allocated. */
static inline int tf_store_init(tf_store_t *const st) {
    memset(st->key, 0, sizeof(st->key));
    for (unsigned i = 0; i < TF_MEMO; ++i) st->memo[i].gen = 0;
    st->gen = 1;
    st->n_memo = 0;
    st->head = tf_chunk_new(TF_CHUNK, NULL);
    return st->head == NULL ? -1 : 0;
}

/* Forget every value read so far. Keeps the first chunk. */
static inline void tf_store_reset(tf_store_t *const st) {
    tf_chunk_t *c = st->head;
    if (c == NULL) return;
    while (c->next != NULL) {
        tf_chunk_t *const older = c->next;
        free(c);
        c = older;
    }
    c->used = 0;
    st->head = c;
    if (++st->gen == 0) { /* wrapped: no answer may look current */
        for (unsigned i = 0; i < TF_MEMO; ++i) st->memo[i].gen = 0;
        st->gen = 1;
    }
}

static inline void tf_store_free(tf_store_t *const st) {
    tf_chunk_t *c = st->head;
    while (c != NULL) {
        tf_chunk_t *const older = c->next;
        free(c);
        c = older;
    }
    st->head = NULL;
}

/* The name hash relies on unsigned wrap-around in its multiplies, which is
 * well defined; keep the CI sanitizer's unsigned-integer-overflow check out
 * of it. */
#if defined(__clang__)
    #define TF_HASH_WRAPS __attribute__((no_sanitize("unsigned-integer-overflow")))
#else
    #define TF_HASH_WRAPS
#endif

/* Hash of a dotted name from its length and its first and last 8 bytes:
 * enough to spread ECS names, and a collision only costs a compare. */
TF_HASH_WRAPS static inline uint32_t tf_name_hash(const char *const name, const size_t n) {
    uint64_t a = 0, b = 0;
    if (n >= 8) {
        memcpy(&a, name, 8);
        memcpy(&b, name + n - 8, 8);
    } else
        memcpy(&a, name, n);
    const uint64_t x = (a ^ (b * 0x9e3779b97f4a7c15ULL) ^ n) * 0xff51afd7ed558ccdULL;
    return (uint32_t)(x >> 32);
}

/* Copy n bytes of src to dst, turning each '.' into '!', eight bytes at a
 * time: one call per name instead of one per separator. */
TF_NOINLINE static void tf_path_from_name(char *const dst, const char *const src, const size_t n) {
    const uint64_t ones = 0x0101010101010101ULL, high = 0x8080808080808080ULL;
    if (n < 8) {
        for (size_t i = 0; i < n; ++i) dst[i] = src[i] == '.' ? '!' : src[i];
        return;
    }
    for (size_t i = 0;; i += 8) {
        const size_t at = i + 8 <= n ? i : n - 8; /* the last word overlaps */
        uint64_t w;
        memcpy(&w, src + at, 8);
        const uint64_t x = w ^ (ones * (uint8_t)'.');
        const uint64_t eq = ~(((x & ~high) + ~high) | x) & high;
        w ^= (eq >> 7) * (uint8_t)('.' ^ '!');
        memcpy(dst + at, &w, 8);
        if (at + 8 >= n) return;
    }
}

/* Copy n < TF_MEMO_NAME bytes with fixed-size moves. A plain memcpy() of a
 * bounded length compiles to rep movs on x86-64, whose startup cost exceeds
 * the copy of a short name. */
TF_NOINLINE static void tf_copy_name(char *const d, const char *const s, const size_t n) {
    if (n >= 8) {
        size_t i = 0;
        for (; i + 8 < n; i += 8) {
            uint64_t w;
            memcpy(&w, s + i, 8);
            memcpy(d + i, &w, 8);
        }
        uint64_t t;
        memcpy(&t, s + n - 8, 8);
        memcpy(d + n - 8, &t, 8);
    } else {
        for (size_t i = 0; i < n; ++i) d[i] = s[i];
    }
}

/* 1 when the n bytes at a and b are equal; a has TF_MEMO_NAME readable bytes. */
static inline int tf_name_eq(const char *const a, const char *const b, const size_t n) {
    uint64_t x, y;
    if (n < 8) {
        for (size_t i = 0; i < n; ++i)
            if (a[i] != b[i]) return 0;
        return 1;
    }
    for (size_t i = 0; i + 8 < n; i += 8) {
        memcpy(&x, a + i, 8);
        memcpy(&y, b + i, 8);
        if (x != y) return 0;
    }
    memcpy(&x, a + n - 8, 8);
    memcpy(&y, b + n - 8, 8);
    return x == y;
}

/* Read the text of the scalar field name ("source.ip"). On success *val
 * points to a NUL-terminated copy of *len bytes, valid until the next
 * tf_store_reset(). Returns 0, or -1 when the field is absent, null, an
 * object or an array, or cannot be copied. */
static int tf_get(const tf_ctx_t *const tf, const char *const name, const char **const val, size_t *const len) {
    char path[TF_NAME_MAX + 1];
    const size_t n = strlen(name);
    uint32_t h;
    tf_store_t *const st = tf->store;
    tf_chunk_t *c = st->head;
    size_t vlen = 0;
    rsRetVal r;

    if (n == 0 || n + 1 >= TF_NAME_MAX || c == NULL) return -1;
    h = tf_name_hash(name, n);
    tf_memo_t *m = NULL;
    if (n < TF_MEMO_NAME) {
        const uint64_t want = (uint64_t)1 << 32 | h;
        for (unsigned i = h & (TF_MEMO - 1), probes = 0; probes < TF_MEMO; i = (i + 1) & (TF_MEMO - 1), ++probes) {
            const uint64_t k = st->key[i];
            if (k == 0) { /* a name this worker has not read: keep it if there is room */
                if (st->n_memo < TF_MEMO_FILL) {
                    m = &st->memo[i];
                    m->gen = 0;
                    m->nlen = (uint8_t)n;
                    tf_copy_name(m->name, name, n);
                    m->path[0] = '!';
                    tf_path_from_name(m->path + 1, name, n);
                    m->path[n + 1] = '\0';
                    msgJSONKeyInit(&m->key, (const uchar *)m->path, n + 1);
                    st->key[i] = want;
                    st->n_memo++;
                }
                break;
            }
            if (k != want) continue;
            tf_memo_t *const s = &st->memo[i];
            if (s->nlen != n || !tf_name_eq(s->name, name, n)) continue;
            if (s->gen == st->gen) {
                if (!s->found) return -1;
                *val = s->val;
                *len = s->len;
                return 0;
            }
            m = s;
            break;
        }
    }

    const char *p = path;
    const msgJSONKey_t *key = NULL;
    if (m != NULL) {
        p = m->path;
        key = &m->key;
    } else {
        /* "source.ip" -> "!source!ip" */
        path[0] = '!';
        tf_path_from_name(path + 1, name, n);
        path[n + 1] = '\0';
    }

    if (c->cap - c->used < 2) {
        tf_chunk_t *const nc = tf_chunk_new(TF_CHUNK, c);
        if (nc == NULL) return -1;
        st->head = c = nc;
    }
    if (!tf->locked) MsgLock(tf->msg);
    r = msgGetJSONPropStrLocked(tf->msg, (const uchar *)p, n + 1, key, (uchar *)c->data + c->used, c->cap - c->used,
                                &vlen);
    if (r == RS_RET_PROVIDED_BUFFER_TOO_SMALL) {
        /* vlen is the length that did not fit */
        tf_chunk_t *nc = NULL;
        if (vlen < SIZE_MAX / 2) nc = tf_chunk_new(vlen + 1 > TF_CHUNK ? vlen + 1 : TF_CHUNK, c);
        if (nc == NULL) {
            r = RS_RET_OUT_OF_MEMORY;
        } else {
            st->head = c = nc;
            r = msgGetJSONPropStrLocked(tf->msg, (const uchar *)p, n + 1, key, (uchar *)c->data, c->cap, &vlen);
        }
    }
    if (!tf->locked) MsgUnlock(tf->msg);
    if (r != RS_RET_OK && r != RS_RET_NOT_FOUND) return -1; /* not remembered: may succeed later */
    if (m != NULL) {
        m->gen = st->gen;
        m->found = r == RS_RET_OK;
        m->val = r == RS_RET_OK ? c->data + c->used : NULL;
        m->len = r == RS_RET_OK ? vlen : 0;
    }
    if (r != RS_RET_OK) return -1;
    *val = c->data + c->used;
    *len = vlen;
    c->used += vlen + 1;
    return 0;
}

/* Read the fields in names[0, n) under one mutex hold, so later tf_get()
 * calls for them are answered from the store. */
static inline void tf_prefetch(tf_ctx_t *const tf, const char *const *const names, const size_t n) {
    const char *v;
    size_t l;
    tf_lock(tf);
    for (size_t i = 0; i < n; ++i)
        if (names[i] != NULL) (void)tf_get(tf, names[i], &v, &l);
    tf_unlock(tf);
}

/* 1 when the message carries a turbo snapshot. Read under the message mutex,
 * which mmnormalize holds when it attaches one. */
static inline int tf_has_snapshot(smsg_t *const pMsg) {
#ifdef HAVE_LOGNORM_TURBO
    int has;
    MsgLock(pMsg);
    has = pMsg->turbo_result != NULL;
    MsgUnlock(pMsg);
    return has;
#else
    (void)pMsg;
    return 0;
#endif
}

#endif /* TURBO_FIELD_H */
