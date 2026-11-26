/* thrt_file_cache.c: see thrt_file_cache.h.
 *
 * Mutex is taken only on acquire / refresh / release / drain (config + HUP).
 * doAction never calls this file.
 */
#include "thrt_file_cache.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define THRT_FILE_CACHE_MAX 64

typedef struct thrt_file_rec {
    void *payload;
    int refs;
    int is_current; /* 1 = live snap for this (dev,ino) */
    int in_use;
    dev_t dev;
    ino_t ino;
    time_t mtime;
    time_t retired_at; /* 0 while refs > 0 */
} thrt_file_rec_t;

struct thrt_file_cache {
    pthread_mutex_t mu;
    thrt_file_load_fn load;
    thrt_file_free_fn free_fn;
    thrt_file_now_fn now_fn;
    int grace_s;
    int load_count;
    thrt_file_rec_t recs[THRT_FILE_CACHE_MAX];
};

static time_t cache_now(const thrt_file_cache_t *c) {
    if (c->now_fn) return c->now_fn();
    return time(NULL);
}

thrt_file_cache_t *thrt_file_cache_create(thrt_file_load_fn load,
                                          thrt_file_free_fn free_fn,
                                          int grace_s,
                                          thrt_file_now_fn now_fn) {
    thrt_file_cache_t *c;

    if (load == NULL || free_fn == NULL) return NULL;
    c = calloc(1, sizeof(*c));
    if (c == NULL) return NULL;
    pthread_mutex_init(&c->mu, NULL);
    c->load = load;
    c->free_fn = free_fn;
    c->now_fn = now_fn;
    c->grace_s = grace_s < 0 ? 0 : grace_s;
    return c;
}

static void rec_free_payload(thrt_file_cache_t *c, thrt_file_rec_t *r) {
    if (r->payload != NULL) c->free_fn(r->payload);
    memset(r, 0, sizeof(*r));
}

static void drain_locked(thrt_file_cache_t *c) {
    time_t now = cache_now(c);
    int i;

    for (i = 0; i < THRT_FILE_CACHE_MAX; i++) {
        thrt_file_rec_t *r = &c->recs[i];
        if (!r->in_use || r->refs > 0) continue;
        if (c->grace_s > 0 && r->retired_at != 0 && (now - r->retired_at) < c->grace_s) continue;
        rec_free_payload(c, r);
    }
}

void thrt_file_cache_drain(thrt_file_cache_t *cache) {
    if (cache == NULL) return;
    pthread_mutex_lock(&cache->mu);
    drain_locked(cache);
    pthread_mutex_unlock(&cache->mu);
}

void thrt_file_cache_destroy(thrt_file_cache_t *cache) {
    int i;

    if (cache == NULL) return;
    pthread_mutex_lock(&cache->mu);
    for (i = 0; i < THRT_FILE_CACHE_MAX; i++) {
        if (cache->recs[i].in_use) rec_free_payload(cache, &cache->recs[i]);
    }
    pthread_mutex_unlock(&cache->mu);
    pthread_mutex_destroy(&cache->mu);
    free(cache);
}

static thrt_file_rec_t *find_by_payload_locked(thrt_file_cache_t *c, const void *p) {
    int i;

    if (p == NULL) return NULL;
    for (i = 0; i < THRT_FILE_CACHE_MAX; i++) {
        if (c->recs[i].in_use && c->recs[i].payload == p) return &c->recs[i];
    }
    return NULL;
}

static thrt_file_rec_t *find_current_locked(thrt_file_cache_t *c, dev_t dev, ino_t ino) {
    int i;

    for (i = 0; i < THRT_FILE_CACHE_MAX; i++) {
        if (c->recs[i].in_use && c->recs[i].is_current && c->recs[i].dev == dev && c->recs[i].ino == ino)
            return &c->recs[i];
    }
    return NULL;
}

static thrt_file_rec_t *alloc_rec_locked(thrt_file_cache_t *c) {
    int i;

    drain_locked(c);
    for (i = 0; i < THRT_FILE_CACHE_MAX; i++) {
        if (!c->recs[i].in_use) return &c->recs[i];
    }
    return NULL;
}

static void *acquire_locked(thrt_file_cache_t *c, const char *path) {
    struct stat st;
    thrt_file_rec_t *cur, *neu;
    void *payload;

    if (path == NULL || path[0] == '\0') return NULL;
    if (stat(path, &st) != 0) return NULL;

    cur = find_current_locked(c, st.st_dev, st.st_ino);
    if (cur != NULL && cur->mtime == st.st_mtime) {
        cur->refs++;
        return cur->payload;
    }

    payload = c->load(path);
    c->load_count++;
    if (payload == NULL) return NULL;

    neu = alloc_rec_locked(c);
    if (neu == NULL) {
        c->free_fn(payload);
        return NULL;
    }
    if (cur != NULL) cur->is_current = 0;

    memset(neu, 0, sizeof(*neu));
    neu->in_use = 1;
    neu->is_current = 1;
    neu->payload = payload;
    neu->refs = 1;
    neu->dev = st.st_dev;
    neu->ino = st.st_ino;
    neu->mtime = st.st_mtime;
    return payload;
}

void *thrt_file_cache_acquire(thrt_file_cache_t *cache, const char *path) {
    void *p;

    if (cache == NULL) return NULL;
    pthread_mutex_lock(&cache->mu);
    p = acquire_locked(cache, path);
    pthread_mutex_unlock(&cache->mu);
    return p;
}

void thrt_file_cache_release(thrt_file_cache_t *cache, void *payload) {
    thrt_file_rec_t *r;

    if (cache == NULL || payload == NULL) return;
    pthread_mutex_lock(&cache->mu);
    r = find_by_payload_locked(cache, payload);
    if (r != NULL && r->refs > 0) {
        r->refs--;
        if (r->refs == 0) {
            r->is_current = 0;
            r->retired_at = cache_now(cache);
        }
    }
    drain_locked(cache);
    pthread_mutex_unlock(&cache->mu);
}

void *thrt_file_cache_refresh(thrt_file_cache_t *cache, const char *path, void *held) {
    void *neu;

    if (cache == NULL) return held;
    pthread_mutex_lock(&cache->mu);
    neu = acquire_locked(cache, path);
    if (neu == NULL) {
        pthread_mutex_unlock(&cache->mu);
        return held;
    }
    if (neu == held) {
        thrt_file_rec_t *r = find_by_payload_locked(cache, neu);
        if (r != NULL && r->refs > 1) r->refs--;
        pthread_mutex_unlock(&cache->mu);
        return held;
    }
    /* Switch this holder from held -> neu. acquire_locked already +1 on neu. */
    if (held != NULL) {
        thrt_file_rec_t *old = find_by_payload_locked(cache, held);
        if (old != NULL && old->refs > 0) {
            old->refs--;
            if (old->refs == 0) {
                old->is_current = 0;
                old->retired_at = cache_now(cache);
            }
        }
    }
    drain_locked(cache);
    pthread_mutex_unlock(&cache->mu);
    return neu;
}

int thrt_file_cache_live_count(const thrt_file_cache_t *cache) {
    int i, n = 0;

    if (cache == NULL) return 0;
    for (i = 0; i < THRT_FILE_CACHE_MAX; i++) {
        if (cache->recs[i].in_use && cache->recs[i].is_current) n++;
    }
    return n;
}

int thrt_file_cache_refs(const thrt_file_cache_t *cache, const void *payload) {
    int i;

    if (cache == NULL || payload == NULL) return 0;
    for (i = 0; i < THRT_FILE_CACHE_MAX; i++) {
        if (cache->recs[i].in_use && cache->recs[i].payload == payload) return cache->recs[i].refs;
    }
    return 0;
}

int thrt_file_cache_load_count(const thrt_file_cache_t *cache) {
    if (cache == NULL) return 0;
    return cache->load_count;
}
