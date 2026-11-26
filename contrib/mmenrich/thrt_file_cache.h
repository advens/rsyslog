/* thrt_file_cache.h: process-wide inode-keyed snapshot cache.
 *
 * Several mmenrich actions on one rsyslog process typically name the same
 * GeoIP MMDB file. This cache shares one payload per (st_dev, st_ino) and
 * reloads only when mtime (or inode) changes. The .thrt, overlay and .prev
 * go through libenrich instead.
 *
 * The hot path never calls here. Callers store the returned payload on
 * instanceData and load it with __atomic_load_n in doAction.
 *
 * Distinct inodes stay distinct. Overlay / mappings / GeoIP caches are not
 * cached (those are per-action config).
 *
 * Copyright 2026 Advens. Licensed under the Apache License, Version 2.0.
 */
#ifndef THRT_FILE_CACHE_H_INCLUDED
#define THRT_FILE_CACHE_H_INCLUDED

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *(*thrt_file_load_fn)(const char *path);
typedef void (*thrt_file_free_fn)(void *payload);
typedef time_t (*thrt_file_now_fn)(void);

typedef struct thrt_file_cache thrt_file_cache_t;

/* grace_s: retired payloads (refcount 0) are freed after this many seconds.
 * 0 = free immediately on last release. now_fn NULL = time(NULL). */
thrt_file_cache_t *thrt_file_cache_create(thrt_file_load_fn load,
                                          thrt_file_free_fn free_fn,
                                          int grace_s,
                                          thrt_file_now_fn now_fn);

void thrt_file_cache_destroy(thrt_file_cache_t *cache);

/* +1 ref on the live payload for this path's inode. NULL if stat/load fails. */
void *thrt_file_cache_acquire(thrt_file_cache_t *cache, const char *path);

/* Make *held the current live payload for path. On load failure keep *held.
 * If the live snap changed, release the previous held pointer. */
void *thrt_file_cache_refresh(thrt_file_cache_t *cache, const char *path, void *held);

/* -1 ref. Last ref retires the payload (freed after grace_s). */
void thrt_file_cache_release(thrt_file_cache_t *cache, void *payload);

/* Free retired payloads whose grace has elapsed. */
void thrt_file_cache_drain(thrt_file_cache_t *cache);

/* Test helpers. */
int thrt_file_cache_live_count(const thrt_file_cache_t *cache);
int thrt_file_cache_refs(const thrt_file_cache_t *cache, const void *payload);
int thrt_file_cache_load_count(const thrt_file_cache_t *cache);

#ifdef __cplusplus
}
#endif

#endif /* THRT_FILE_CACHE_H_INCLUDED */
