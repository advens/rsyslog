/* SPDX-License-Identifier: Apache-2.0 */

/* test_file_cache.c: inode-keyed snapshot cache (process-wide CTI maps).
 *
 * Build: cc -O2 -pthread -I. thrt_file_cache.c test_file_cache.c -o test_file_cache
 *        && ./test_file_cache
 *
 * Copyright 2026 Advens. Licensed under the Apache License, Version 2.0.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <utime.h>

#include "thrt_file_cache.h"

static int g_fail = 0;
#define CHECK(cond, msg)                                                    \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            g_fail++;                                                       \
        }                                                                   \
    } while (0)

static int g_loads = 0;

static void *test_load(const char *path) {
    char *p;
    FILE *f;
    char buf[64];
    size_t n;

    g_loads++;
    f = fopen(path, "rb");
    if (f == NULL) return NULL;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    p = malloc(strlen(path) + n + 8);
    if (p == NULL) return NULL;
    snprintf(p, strlen(path) + n + 8, "%s:%s", path, buf);
    return p;
}

static void test_free(void *payload) {
    free(payload);
}

static char *write_temp(const char *tag, const char *body) {
    char *path = malloc(128);
    int fd;

    if (path == NULL) return NULL;
    snprintf(path, 128, "/tmp/thrt-cache-%s-XXXXXX", tag);
    fd = mkstemp(path);
    if (fd < 0) {
        free(path);
        return NULL;
    }
    if (write(fd, body, strlen(body)) < 0) {
        close(fd);
        unlink(path);
        free(path);
        return NULL;
    }
    close(fd);
    return path;
}

static void bump_mtime(const char *path) {
    struct stat st;
    struct utimbuf u;

    if (stat(path, &st) != 0) return;
    u.actime = st.st_atime;
    u.modtime = st.st_mtime + 2;
    utime(path, &u);
}

int main(void) {
    thrt_file_cache_t *c;
    char *a, *b, *linkpath;
    void *p1, *p2, *p3;

    c = thrt_file_cache_create(test_load, test_free, 0, NULL);
    CHECK(c != NULL, "create");

    a = write_temp("a", "one");
    b = write_temp("b", "two");
    CHECK(a && b, "temp files");

    /* 1. two acquires of the same file share the payload */
    p1 = thrt_file_cache_acquire(c, a);
    p2 = thrt_file_cache_acquire(c, a);
    CHECK(p1 != NULL && p1 == p2, "same file same payload");
    CHECK(thrt_file_cache_refs(c, p1) == 2, "refcount 2");
    CHECK(thrt_file_cache_live_count(c) == 1, "one live identity");
    CHECK(thrt_file_cache_load_count(c) == 1, "loaded once");

    /* 2. different files do not share */
    p3 = thrt_file_cache_acquire(c, b);
    CHECK(p3 != NULL && p3 != p1, "distinct files distinct payloads");
    CHECK(thrt_file_cache_live_count(c) == 2, "two live identities");

    thrt_file_cache_release(c, p3);
    thrt_file_cache_release(c, p2);
    CHECK(thrt_file_cache_refs(c, p1) == 1, "refcount 1 after one release");

    /* 3. symlink to the same inode shares */
    linkpath = malloc(128);
    snprintf(linkpath, 128, "%s-link", a);
    unlink(linkpath);
    CHECK(symlink(a, linkpath) == 0, "symlink");
    p2 = thrt_file_cache_acquire(c, linkpath);
    CHECK(p2 == p1, "symlink shares inode");
    CHECK(thrt_file_cache_load_count(c) == 2, "still one load for a (plus b)");
    thrt_file_cache_release(c, p2);
    unlink(linkpath);
    free(linkpath);

    /* 4. refresh unchanged mtime does not reload */
    p2 = thrt_file_cache_refresh(c, a, p1);
    CHECK(p2 == p1, "refresh same mtime keeps pointer");
    CHECK(thrt_file_cache_load_count(c) == 2, "no extra load");
    CHECK(thrt_file_cache_refs(c, p1) == 1, "refresh same does not leak a ref");

    /* 5. refresh after mtime bump loads once, both holders can swap */
    bump_mtime(a);
    p2 = thrt_file_cache_refresh(c, a, p1);
    CHECK(p2 != NULL && p2 != p1, "mtime change new payload");
    CHECK(thrt_file_cache_load_count(c) == 3, "one reload");
    /* p1 is retired (no holders). p2 is live. */
    CHECK(thrt_file_cache_refs(c, p2) == 1, "new snap ref 1");
    p1 = p2;

    /* second holder refresh converges on the same new snap without reload */
    p3 = thrt_file_cache_acquire(c, a);
    CHECK(p3 == p1, "second holder gets live snap");
    CHECK(thrt_file_cache_load_count(c) == 3, "no third load");
    thrt_file_cache_release(c, p3);

    /* 6. last release with grace 0 unmaps */
    thrt_file_cache_release(c, p1);
    CHECK(thrt_file_cache_live_count(c) == 0, "no live after last release");
    CHECK(thrt_file_cache_refs(c, p1) == 0, "gone");

    /* 7. missing file */
    p1 = thrt_file_cache_acquire(c, "/no/such/thrt-cache-file");
    CHECK(p1 == NULL, "missing file returns NULL");

    /* refresh failure keeps held */
    p1 = thrt_file_cache_acquire(c, a);
    CHECK(p1 != NULL, "re-acquire a");
    p2 = thrt_file_cache_refresh(c, "/no/such/thrt-cache-file", p1);
    CHECK(p2 == p1, "failed refresh keeps old");
    thrt_file_cache_release(c, p1);

    thrt_file_cache_destroy(c);
    unlink(a);
    unlink(b);
    free(a);
    free(b);

    if (g_fail) {
        fprintf(stderr, "%d checks failed\n", g_fail);
        return 1;
    }
    printf("test_file_cache: OK\n");
    return 0;
}
