/* SPDX-License-Identifier: Apache-2.0 */

/* Copyright 2026 Advens */

/* Standalone checks for the prevalence counter file and its publisher.
 * Compile beside prev_live.c; the image is read back with prev_lookup.
 */
#include "prev_live.h"
#include "prev_format.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define WINDOW_SEC (7u * 24u * 3600u)

static int g_fail;
static char g_dir[512];

/* Remove name under parent and, for a directory, everything below it.
 * Symlinks are unlinked, never followed. */
static int remove_tree_at(int parent, const char *name) {
    int dfd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0) {
        return errno == ENOTDIR || errno == ELOOP ? unlinkat(parent, name, 0) : -1;
    }
    DIR *d = fdopendir(dfd);
    if (d == NULL) {
        close(dfd);
        return -1;
    }
    int rc = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        if (remove_tree_at(dfd, ent->d_name) != 0) {
            rc = -1;
        }
    }
    closedir(d);
    if (unlinkat(parent, name, AT_REMOVEDIR) != 0) {
        rc = -1;
    }
    return rc;
}

/* The scratch directory holds several hundred MB of images. It is removed
 * on every exit after creation, so repeated runs do not fill a tmpfs.
 * PREV_LIVE_KEEP=1 keeps it for inspection. */
static int finish(int rc) {
    const char *keep = getenv("PREV_LIVE_KEEP");
    if (keep != NULL && keep[0] != '\0' && strcmp(keep, "0") != 0) {
        fprintf(stderr, "kept %s\n", g_dir);
        return rc;
    }
    if (remove_tree_at(AT_FDCWD, g_dir) != 0) {
        fprintf(stderr, "FAIL remove %s: %s\n", g_dir, strerror(errno));
        return 1;
    }
    return rc;
}

static void fail_msg(const char *msg) {
    fprintf(stderr, "FAIL %s\n", msg);
    g_fail++;
}

static void expect_u32(const char *msg, uint32_t got, uint32_t want) {
    if (got != want) {
        fprintf(stderr, "FAIL %s: got %u want %u\n", msg, got, want);
        g_fail++;
    }
}

static void expect_int(const char *msg, int got, int want) {
    if (got != want) {
        fprintf(stderr, "FAIL %s: got %d want %d\n", msg, got, want);
        g_fail++;
    }
}

#define TEST_K0 0x0706050403020100ULL
#define TEST_K1 0x0f0e0d0c0b0a0908ULL

static void join_path(char *out, size_t n, const char *name) {
    int wrote = snprintf(out, n, "%s/%s", g_dir, name);
    if (wrote < 0 || (size_t)wrote >= n) {
        fprintf(stderr, "path too long: %s\n", name);
        exit(1);
    }
}

static prev_live_t *open_live(const char *name) {
    char path[256];
    prev_live_t *live;

    /* Every counter file of the test shares the key of prev_write.py's
     * conformance fixture, so images seed and merge across them. */
    static const uint64_t key[2] = {TEST_K0, TEST_K1};

    join_path(path, sizeof(path), name);
    live = prev_live_open_keyed(path, key);
    if (live == NULL) {
        fprintf(stderr, "open %s failed: %s\n", path, strerror(errno));
        exit(1);
    }
    return live;
}

/* Map a published image. Caller munmaps *base_out. Returns the entry table. */
static const prev_entry_t *map_image(
    const char *path, void **base_out, size_t *len_out, uint32_t *slots_out, prev_header_t *hdr_out) {
    struct stat st;
    void *base;
    const prev_entry_t *table;
    int fd;

    *base_out = NULL;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        return NULL;
    }
    base = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) return NULL;
    table = prev_table_map(base, (size_t)st.st_size, slots_out);
    if (table == NULL) {
        munmap(base, (size_t)st.st_size);
        return NULL;
    }
    memcpy(hdr_out, base, sizeof(*hdr_out));
    *base_out = base;
    *len_out = (size_t)st.st_size;
    return table;
}

static void lookup_image(
    const char *path, const char *key, uint32_t *count, uint16_t *edges, uint16_t *sources, prev_header_t *hdr) {
    void *base = NULL;
    size_t len = 0;
    uint32_t slots = 0;
    const prev_entry_t *table;
    prev_header_t local;

    *count = 0;
    *edges = 0;
    *sources = 0;
    memset(&local, 0, sizeof(local));
    table = map_image(path, &base, &len, &slots, &local);
    if (hdr != NULL) *hdr = local;
    if (table == NULL) return;
    *count = prev_lookup((const prev_header_t *)base, table, slots, key, edges, sources);
    munmap(base, len);
}

static int read_all(const char *path, uint8_t **out, size_t *len) {
    struct stat st;
    uint8_t *buf;
    int fd;
    size_t off = 0;

    *out = NULL;
    *len = 0;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0 || st.st_size < 0) {
        close(fd);
        return -1;
    }
    buf = malloc((size_t)st.st_size + 1u);
    if (buf == NULL) {
        close(fd);
        return -1;
    }
    while (off < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + off, (size_t)st.st_size - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf);
            close(fd);
            return -1;
        }
        if (n == 0) break;
        off += (size_t)n;
    }
    close(fd);
    *out = buf;
    *len = off;
    return 0;
}

static void note_n(prev_live_t *live, const char *key, const char *src, int n) {
    int i;
    for (i = 0; i < n; i++) prev_live_note(live, key, src);
}

static void put_name(prev_live_t *live, const char *name, uint32_t count, uint16_t edges, uint16_t sources) {
    uint64_t key = prev_live_hash(live, name);
    if (prev_live_put(live, key, count, edges, sources) != 0) {
        fprintf(stderr, "put %s failed\n", name);
        exit(1);
    }
}

static void test_null_and_empty(void) {
    char image[256];
    prev_live_t *live;
    uint32_t n = 99;

    join_path(image, sizeof(image), "empty.prev");
    prev_live_note(NULL, "a.example", "10.0.0.1");
    prev_live_tick(NULL, 1);
    prev_live_set_window_start(NULL, 1);
    prev_live_close(NULL);
    expect_int("publish NULL live", prev_live_publish(NULL, image, 1, &n), -1);
    expect_int("seed NULL live", prev_live_seed(NULL, image), -1);
    expect_int("put NULL live", prev_live_put(NULL, 1, 1, 1, 1), -1);

    live = open_live("empty.live");
    prev_live_note(live, "", "10.0.0.1");
    prev_live_note(live, NULL, "10.0.0.1");
    expect_int("put count 0", prev_live_put(live, 1, 0, 1, 1), -1);
    expect_int("seed NULL path", prev_live_seed(live, NULL), -1);
    expect_int("seed empty path", prev_live_seed(live, ""), -1);
    expect_int("publish empty table", prev_live_publish(live, image, 1700000000u, &n), 0);
    expect_u32("empty publish row count", n, 0);
    if (access(image, F_OK) == 0) fail_msg("empty publish created an image");
    prev_live_close(live);
}

static void test_conformance(void) {
    static const struct {
        const char *name;
        uint32_t count;
        uint16_t edges;
        uint16_t sources;
    } rows[] = {
        {"www.google.com", 50000, 7, 120}, {"cdn.cloudflare.net", 41000, 7, 95}, {"one.one.one.one", 12000, 6, 60},
        {"internal.corp.lan", 800, 3, 12}, {"lonely-beacon.example", 2, 1, 1},
    };
    char image[256];
    prev_live_t *live;
    prev_header_t hdr;
    uint32_t n = 0;
    uint32_t count;
    uint16_t edges, sources;
    size_t i;

    join_path(image, sizeof(image), "conformance.prev");
    live = open_live("conformance.live");
    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
        put_name(live, rows[i].name, rows[i].count, rows[i].edges, rows[i].sources);
    /* 1700000000 is behind the open-time window, so this publish must not rotate. */
    expect_int("conformance publish", prev_live_publish(live, image, 1700000000u, &n), 1);
    expect_u32("conformance rows", n, 5);
    lookup_image(image, "www.google.com", &count, &edges, &sources, &hdr);
    expect_u32("google count", count, 50000);
    expect_u32("google edges", edges, 7);
    expect_u32("google sources", sources, 120);
    expect_u32("reporting_edges", hdr.reporting_edges, 1);
    expect_u32("epoch", hdr.epoch, 1700000000u);
    expect_u32("version", hdr.version, PREV_VERSION);
    expect_u32("slots", hdr.hash_slots, 16);
    expect_u32("count_max", hdr.count_max, 50000);
    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        char label[64];
        lookup_image(image, rows[i].name, &count, &edges, &sources, NULL);
        snprintf(label, sizeof(label), "%s count", rows[i].name);
        expect_u32(label, count, rows[i].count);
        snprintf(label, sizeof(label), "%s edges", rows[i].name);
        expect_u32(label, edges, rows[i].edges);
        snprintf(label, sizeof(label), "%s sources", rows[i].name);
        expect_u32(label, sources, rows[i].sources);
    }
    lookup_image(image, "missing.example", &count, &edges, &sources, NULL);
    expect_u32("missing count", count, 0);
    expect_u32("missing edges", edges, 0);
    expect_u32("missing sources", sources, 0);

    /* Same rows, newer epoch: the image bytes that matter did not change. */
    expect_int("quiet republish", prev_live_publish(live, image, 1700000001u, &n), 0);
    lookup_image(image, "www.google.com", &count, &edges, &sources, &hdr);
    expect_u32("epoch unchanged", hdr.epoch, 1700000000u);
    expect_u32("google still 50000", count, 50000);
    prev_live_close(live);
    printf("conformance %s\n", image);
}

static void test_sources_and_floor(void) {
    char image[256];
    prev_live_t *live;
    uint32_t n = 0;
    uint32_t count;
    uint16_t edges, sources;

    join_path(image, sizeof(image), "sources.prev");
    live = open_live("sources.live");
    prev_live_tick(live, 1700000000u);
    note_n(live, "multi.example", "10.0.0.1", 1);
    note_n(live, "multi.example", "10.0.0.2", 1);
    note_n(live, "multi.example", "10.0.0.3", 1);
    note_n(live, "multi.example", "10.0.0.1", 1);
    note_n(live, "one.example", "10.0.0.9", 3);
    prev_live_note(live, "nosrc.example", NULL);
    prev_live_note(live, "nosrc.example", "");
    put_name(live, "www.google.com", 50000, 7, 120);
    prev_live_note(live, "www.google.com", "10.2.2.2");

    expect_int("sources publish", prev_live_publish(live, image, 1700000000u, &n), 1);
    lookup_image(image, "multi.example", &count, &edges, &sources, NULL);
    expect_u32("three sources count", count, 4);
    expect_u32("three sources edges", edges, 1);
    expect_u32("three sources", sources, 3);
    lookup_image(image, "one.example", &count, &edges, &sources, NULL);
    expect_u32("one source count", count, 3);
    expect_u32("one source edges", edges, 1);
    expect_u32("one source", sources, 1);
    lookup_image(image, "nosrc.example", &count, &edges, &sources, NULL);
    expect_u32("no source count", count, 2);
    expect_u32("no source edges", edges, 1);
    expect_u32("no source", sources, 0);
    lookup_image(image, "www.google.com", &count, &edges, &sources, NULL);
    expect_u32("floor plus note count", count, 50001);
    expect_u32("floor edges held", edges, 7);
    expect_u32("floor sources held", sources, 120);
    prev_live_close(live);
}

static void test_stub(void) {
    char image[256];
    char key[32];
    prev_live_t *live;
    uint8_t *before = NULL;
    uint8_t *after = NULL;
    size_t before_len = 0;
    size_t after_len = 0;
    uint32_t n = 0;
    uint32_t count;
    uint16_t edges, sources;
    int i;

    join_path(image, sizeof(image), "stub.prev");
    live = open_live("stub20.live");
    prev_live_tick(live, 1700000000u);
    for (i = 0; i < 20; i++) {
        snprintf(key, sizeof(key), "a%02d.example", i);
        prev_live_note(live, key, "10.0.0.1");
    }
    expect_int("publish 20", prev_live_publish(live, image, 1700000000u, &n), 1);
    expect_u32("20 rows", n, 20);
    prev_live_close(live);
    if (read_all(image, &before, &before_len) != 0) {
        fail_msg("read 20-row image");
        return;
    }

    live = open_live("stub4.live");
    prev_live_tick(live, 1700000000u);
    for (i = 0; i < 4; i++) {
        snprintf(key, sizeof(key), "b%d.example", i);
        prev_live_note(live, key, "10.0.0.2");
    }
    expect_int("stub 4 skipped", prev_live_publish(live, image, 1700000000u, &n), 0);
    prev_live_close(live);

    live = open_live("stub9.live");
    prev_live_tick(live, 1700000000u);
    for (i = 0; i < 9; i++) {
        snprintf(key, sizeof(key), "c%d.example", i);
        prev_live_note(live, key, "10.0.0.3");
    }
    expect_int("stub 9 skipped", prev_live_publish(live, image, 1700000000u, &n), 0);
    prev_live_close(live);

    live = open_live("stub0.live");
    expect_int("stub empty skipped", prev_live_publish(live, image, 1700000000u, &n), 0);
    prev_live_close(live);

    if (read_all(image, &after, &after_len) != 0) fail_msg("re-read stub image");
    if (before_len != after_len || memcmp(before, after, before_len) != 0) fail_msg("stub publish replaced the image");
    free(after);
    after = NULL;

    live = open_live("stub10.live");
    prev_live_tick(live, 1700000000u);
    for (i = 0; i < 10; i++) {
        snprintf(key, sizeof(key), "d%02d.example", i);
        prev_live_note(live, key, "10.0.0.4");
    }
    expect_int("half replaces", prev_live_publish(live, image, 1700000000u, &n), 1);
    expect_u32("10 rows", n, 10);
    lookup_image(image, "d00.example", &count, &edges, &sources, NULL);
    expect_u32("replacement count", count, 1);
    expect_u32("replacement edges", edges, 1);
    lookup_image(image, "a00.example", &count, &edges, &sources, NULL);
    expect_u32("old row dropped", count, 0);
    prev_live_close(live);
    free(before);
}

static uint32_t image_epoch(const char *path) {
    uint8_t *buf = NULL;
    size_t len = 0;
    prev_header_t hdr;
    if (read_all(path, &buf, &len) != 0 || len < sizeof(hdr)) {
        free(buf);
        return 0;
    }
    memcpy(&hdr, buf, sizeof(hdr));
    free(buf);
    return hdr.epoch;
}

/* A small image still grows, a shrink is held back only for a while, and
 * an unchanged image is rewritten often enough to keep its epoch fresh. */
static void test_stub_hold(void) {
    char image[256];
    char key[32];
    prev_live_t *live;
    uint32_t n = 0;
    uint32_t count;
    uint16_t edges, sources;
    uint32_t t = 1700000000u;
    int i;

    join_path(image, sizeof(image), "small.prev");
    live = open_live("small.live");
    prev_live_tick(live, t);
    for (i = 0; i < 3; i++) {
        snprintf(key, sizeof(key), "s%d.example", i);
        prev_live_note(live, key, "10.0.0.5");
    }
    expect_int("publish 3", prev_live_publish(live, image, t, &n), 1);
    for (i = 3; i < 5; i++) {
        snprintf(key, sizeof(key), "s%d.example", i);
        prev_live_note(live, key, "10.0.0.5");
    }
    expect_int("3 grows to 5", prev_live_publish(live, image, t + 60, &n), 1);
    expect_u32("5 rows", n, 5);
    lookup_image(image, "s4.example", &count, &edges, &sources, NULL);
    expect_u32("new small row", count, 1);

    expect_int("unchanged skipped", prev_live_publish(live, image, t + 120, &n), 0);
    expect_u32("epoch kept", image_epoch(image), t + 60);
    expect_int("unchanged refreshed", prev_live_publish(live, image, t + 60 + 600, &n), 1);
    expect_u32("epoch refreshed", image_epoch(image), t + 660);
    prev_live_close(live);

    join_path(image, sizeof(image), "hold.prev");
    live = open_live("hold20.live");
    prev_live_tick(live, t);
    for (i = 0; i < 20; i++) {
        snprintf(key, sizeof(key), "h%02d.example", i);
        prev_live_note(live, key, "10.0.0.6");
    }
    expect_int("publish 20 to hold", prev_live_publish(live, image, t, &n), 1);
    prev_live_close(live);
    live = open_live("hold4.live");
    prev_live_tick(live, t);
    for (i = 0; i < 4; i++) {
        snprintf(key, sizeof(key), "k%d.example", i);
        prev_live_note(live, key, "10.0.0.7");
    }
    expect_int("shrink held", prev_live_publish(live, image, t + 60, &n), 0);
    expect_int("shrink still held", prev_live_publish(live, image, t + 3599, &n), 0);
    expect_int("shrink past the hold", prev_live_publish(live, image, t + 3600, &n), 1);
    expect_u32("4 rows", n, 4);
    lookup_image(image, "h00.example", &count, &edges, &sources, NULL);
    expect_u32("held rows gone", count, 0);
    prev_live_close(live);
}

static void test_rotate(void) {
    char image[256];
    prev_live_t *live;
    uint32_t n = 0;
    uint32_t count;
    uint16_t edges, sources;
    uint32_t start = 1700000000u;
    uint32_t later;

    join_path(image, sizeof(image), "rotate.prev");
    live = open_live("rotate.live");
    prev_live_tick(live, start);
    put_name(live, "keep.example", 9, 7, 40);
    note_n(live, "keep.example", "10.0.0.1", 3);
    put_name(live, "seeded.only", 50000, 7, 120);
    prev_live_set_window_start(live, start - WINDOW_SEC);
    expect_int("rotate publish", prev_live_publish(live, image, start, &n), 1);
    lookup_image(image, "keep.example", &count, &edges, &sources, NULL);
    expect_u32("rotated count is the live bucket", count, 3);
    expect_u32("rotated edges cleared", edges, 1);
    expect_u32("rotated live source kept", sources, 1);
    lookup_image(image, "seeded.only", &count, &edges, &sources, NULL);
    expect_u32("seeded-only dropped", count, 0);
    prev_live_close(live);

    join_path(image, sizeof(image), "expire.prev");
    live = open_live("expire.live");
    prev_live_tick(live, start);
    prev_live_note(live, "old.example", "10.9.9.9");
    later = start + 2u * WINDOW_SEC + 1u;
    prev_live_tick(live, later);
    prev_live_note(live, "fresh.example", "10.8.8.8");
    prev_live_set_window_start(live, start);
    expect_int("expire publish", prev_live_publish(live, image, later, &n), 1);
    lookup_image(image, "old.example", &count, &edges, &sources, NULL);
    expect_u32("old count kept", count, 1);
    expect_u32("old source dropped", sources, 0);
    lookup_image(image, "fresh.example", &count, &edges, &sources, NULL);
    expect_u32("fresh count", count, 1);
    expect_u32("fresh source kept", sources, 1);
    prev_live_close(live);
}

struct hammer_arg {
    prev_live_t *live;
    int n;
};

static void *hammer_fn(void *arg) {
    struct hammer_arg *a = arg;
    int i;
    for (i = 0; i < a->n; i++) prev_live_note(a->live, "hammer.example", "10.1.1.1");
    return NULL;
}

static void test_hammer(void) {
    char image[256];
    prev_live_t *live;
    pthread_t th[4];
    struct hammer_arg arg;
    uint32_t n = 0;
    uint32_t count;
    uint16_t edges, sources;
    int i;

    join_path(image, sizeof(image), "hammer.prev");
    live = open_live("hammer.live");
    prev_live_tick(live, 1700000000u);
    arg.live = live;
    arg.n = 1000;
    for (i = 0; i < 4; i++) {
        if (pthread_create(&th[i], NULL, hammer_fn, &arg) != 0) {
            perror("pthread_create");
            exit(1);
        }
    }
    for (i = 0; i < 4; i++) pthread_join(th[i], NULL);
    expect_int("hammer publish", prev_live_publish(live, image, 1700000000u, &n), 1);
    lookup_image(image, "hammer.example", &count, &edges, &sources, NULL);
    expect_u32("hammer count", count, 4000);
    expect_u32("hammer edges", edges, 1);
    expect_u32("hammer sources", sources, 1);
    prev_live_close(live);
}

static void test_reopen_and_seed(const char *py_image) {
    char image[256];
    char live_name[64];
    prev_live_t *live;
    prev_header_t hdr;
    uint32_t n = 0;
    uint32_t count;
    uint16_t edges, sources;

    join_path(image, sizeof(image), "reopen.prev");
    live = open_live("reopen.live");
    prev_live_tick(live, 1700000000u);
    expect_int("seed missing", prev_live_seed(live, image), 0);
    note_n(live, "reopen.example", "10.0.0.1", 5);
    expect_int("reopen first publish", prev_live_publish(live, image, 1700000000u, &n), 1);
    expect_u32("reopen rows", n, 1);
    prev_live_close(live);

    live = open_live("reopen.live");
    expect_int("seed after restart", prev_live_seed(live, image), 0);
    expect_int("republish after restart", prev_live_publish(live, image, 1700000002u, &n), 0);
    lookup_image(image, "reopen.example", &count, &edges, &sources, NULL);
    expect_u32("restart did not double", count, 5);
    prev_live_close(live);

    if (py_image == NULL || py_image[0] == '\0') return;
    snprintf(live_name, sizeof(live_name), "pyseed.live");
    live = open_live(live_name);
    expect_int("seed python image", prev_live_seed(live, py_image), 0);
    expect_int("seed python image again", prev_live_seed(live, py_image), 0);
    prev_live_note(live, "www.google.com", "10.4.4.4");
    join_path(image, sizeof(image), "from-python.prev");
    expect_int("publish seeded python image", prev_live_publish(live, image, 1700000000u, &n), 1);
    expect_u32("seeded rows", n, 5);
    lookup_image(image, "www.google.com", &count, &edges, &sources, &hdr);
    expect_u32("seeded google count", count, 50001);
    expect_u32("seeded google edges", edges, 7);
    expect_u32("seeded google sources", sources, 120);
    expect_u32("seeded reporting_edges", hdr.reporting_edges, 1);
    lookup_image(image, "lonely-beacon.example", &count, &edges, &sources, NULL);
    expect_u32("seeded beacon count", count, 2);
    expect_u32("seeded beacon edges", edges, 1);
    expect_u32("seeded beacon sources", sources, 1);
    lookup_image(image, "cdn.cloudflare.net", &count, &edges, &sources, NULL);
    expect_u32("seeded cdn", count, 41000);
    /* A second publish must not import the image back into the counters. */
    expect_int("seed after own publish", prev_live_seed(live, image), 0);
    expect_int("no double after own publish", prev_live_publish(live, image, 1700000003u, &n), 0);
    lookup_image(image, "www.google.com", &count, &edges, &sources, NULL);
    expect_u32("google not doubled", count, 50001);
    prev_live_close(live);
    printf("from-python %s\n", image);
}

struct merge_row {
    const char *name;
    uint32_t count;
    uint16_t edges;
    uint16_t sources;
};

static void publish_rows(
    const char *live_name, const char *image_path, uint32_t epoch, const struct merge_row *rows, size_t nrows) {
    prev_live_t *live;
    uint32_t n = 0;
    size_t i;
    int rc;

    live = open_live(live_name);
    for (i = 0; i < nrows; i++) put_name(live, rows[i].name, rows[i].count, rows[i].edges, rows[i].sources);
    rc = prev_live_publish(live, image_path, epoch, &n);
    prev_live_close(live);
    if (rc != 1 || n != (uint32_t)nrows) {
        fprintf(stderr, "FAIL publish %s: rc %d rows %u want %zu\n", image_path, rc, n, nrows);
        g_fail++;
    }
}

static void make_dir(const char *path) {
    if (mkdir(path, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir %s: %s\n", path, strerror(errno));
        exit(1);
    }
}

static void write_text(const char *path, const char *text) {
    int fd;
    size_t len;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);
    if (fd < 0) {
        perror(path);
        exit(1);
    }
    len = strlen(text);
    if (write(fd, text, len) != (ssize_t)len) {
        perror("write");
        exit(1);
    }
    close(fd);
}

/* Three fresh images, one name on a single image, a stored edge floor of 7
 * that must count as one edge, a snapshot older than 8 days, a hard link of
 * the local file, and a dotfile. */
static void test_merge(void) {
    const uint32_t now = 1700000000u;
    const uint32_t week_epoch = now - WINDOW_SEC;
    const uint32_t stale_epoch = now - 8u * 24u * 3600u;
    const struct merge_row local_rows[] = {
        {"only.example", 4, 7, 1},
        {"shared.example", 10, 7, 2},
        {"both.example", 3, 1, 1},
    };
    const struct merge_row box2_rows[] = {
        {"shared.example", 20, 4, 5},
        {"both.example", 8, 9, 3},
    };
    const struct merge_row box3_rows[] = {{"shared.example", 1, 1, 1}};
    const struct merge_row stale_rows[] = {
        {"stale.example", 100, 1, 9},
        {"shared.example", 1000, 1, 9},
    };
    const struct merge_row week_rows[] = {{"week.example", 6, 2, 2}};
    const struct merge_row hidden_rows[] = {{"hidden.example", 50, 1, 1}};
    const struct merge_row future_rows[] = {{"future.example", 2, 9, 1}};
    char peers[256], local[256], out[256], alone[256], nested[256];
    char p2[256], p3[256], stale[256], week[256], hidden[256], future[256], linkpath[256], garbage[256];
    prev_header_t hdr;
    uint32_t n = 99;
    uint32_t count;
    uint16_t edges, sources;
    int wrote;

    expect_int("merge NULL out", prev_merge_images("x", "y", NULL, now, &n), -1);
    expect_u32("merge NULL out rows", n, 0);
    n = 7;
    expect_int("merge empty out", prev_merge_images("x", "y", "", now, &n), -1);
    expect_u32("merge empty out rows", n, 0);

    wrote = snprintf(peers, sizeof(peers), "%s/peers", g_dir);
    if (wrote < 0 || (size_t)wrote >= sizeof(peers)) exit(1);
    make_dir(peers);
    wrote = snprintf(nested, sizeof(nested), "%s/nested", peers);
    if (wrote < 0 || (size_t)wrote >= sizeof(nested)) exit(1);
    make_dir(nested);
    join_path(local, sizeof(local), "local.prev");
    join_path(out, sizeof(out), "merged.prev");
    join_path(alone, sizeof(alone), "alone.prev");
    wrote = snprintf(p2, sizeof(p2), "%s/b.prev", peers);
    if (wrote < 0 || (size_t)wrote >= sizeof(p2)) exit(1);
    wrote = snprintf(p3, sizeof(p3), "%s/c.prev", peers);
    if (wrote < 0 || (size_t)wrote >= sizeof(p3)) exit(1);
    wrote = snprintf(stale, sizeof(stale), "%s/stale.prev", peers);
    if (wrote < 0 || (size_t)wrote >= sizeof(stale)) exit(1);
    wrote = snprintf(week, sizeof(week), "%s/week.prev", peers);
    if (wrote < 0 || (size_t)wrote >= sizeof(week)) exit(1);
    wrote = snprintf(hidden, sizeof(hidden), "%s/.secret.prev", peers);
    if (wrote < 0 || (size_t)wrote >= sizeof(hidden)) exit(1);
    wrote = snprintf(future, sizeof(future), "%s/future.prev", peers);
    if (wrote < 0 || (size_t)wrote >= sizeof(future)) exit(1);
    wrote = snprintf(linkpath, sizeof(linkpath), "%s/same.prev", peers);
    if (wrote < 0 || (size_t)wrote >= sizeof(linkpath)) exit(1);
    wrote = snprintf(garbage, sizeof(garbage), "%s/notes.txt", peers);
    if (wrote < 0 || (size_t)wrote >= sizeof(garbage)) exit(1);

    publish_rows("m-local.live", local, now, local_rows, sizeof(local_rows) / sizeof(local_rows[0]));
    publish_rows("m-b.live", p2, now, box2_rows, sizeof(box2_rows) / sizeof(box2_rows[0]));
    publish_rows("m-c.live", p3, now, box3_rows, sizeof(box3_rows) / sizeof(box3_rows[0]));
    publish_rows("m-stale.live", stale, stale_epoch, stale_rows, sizeof(stale_rows) / sizeof(stale_rows[0]));
    publish_rows("m-week.live", week, week_epoch, week_rows, sizeof(week_rows) / sizeof(week_rows[0]));
    publish_rows("m-hidden.live", hidden, now, hidden_rows, sizeof(hidden_rows) / sizeof(hidden_rows[0]));
    publish_rows("m-future.live", future, now + 3600u, future_rows, sizeof(future_rows) / sizeof(future_rows[0]));
    if (link(local, linkpath) != 0) {
        perror("link");
        exit(1);
    }
    write_text(garbage, "not an image\n");

    expect_int("merge three", prev_merge_images(local, peers, out, now, &n), 1);
    expect_u32("merge rows", n, 5);
    lookup_image(out, "only.example", &count, &edges, &sources, &hdr);
    expect_u32("only count", count, 4);
    expect_u32("only edges are presence", edges, 1);
    expect_u32("only sources", sources, 1);
    expect_u32("merged reporting_edges", hdr.reporting_edges, 5);
    expect_u32("merged count_max", hdr.count_max, 31);
    lookup_image(out, "shared.example", &count, &edges, &sources, NULL);
    expect_u32("shared count", count, 31);
    expect_u32("shared edges", edges, 3);
    expect_u32("shared sources", sources, 8);
    lookup_image(out, "both.example", &count, &edges, &sources, NULL);
    expect_u32("both count", count, 11);
    expect_u32("both edges", edges, 2);
    expect_u32("both sources", sources, 4);
    lookup_image(out, "week.example", &count, &edges, &sources, NULL);
    expect_u32("week count", count, 6);
    expect_u32("week edges", edges, 1);
    expect_u32("week sources", sources, 2);
    lookup_image(out, "future.example", &count, &edges, &sources, NULL);
    expect_u32("future count", count, 2);
    expect_u32("future edges", edges, 1);
    lookup_image(out, "stale.example", &count, &edges, &sources, NULL);
    expect_u32("stale dropped", count, 0);
    lookup_image(out, "hidden.example", &count, &edges, &sources, NULL);
    expect_u32("dotfile dropped", count, 0);
    lookup_image(local, "only.example", &count, &edges, &sources, &hdr);
    expect_u32("local floor kept", edges, 7);
    expect_u32("local reporting_edges", hdr.reporting_edges, 1);

    n = 99;
    expect_int("second merge", prev_merge_images(local, peers, out, now, &n), 0);
    expect_u32("second merge rows", n, 0);

    expect_int("merge without peers", prev_merge_images(local, "/no/such/prev.peers", alone, now, &n), 1);
    lookup_image(alone, "only.example", &count, &edges, &sources, &hdr);
    expect_u32("alone edges", edges, 1);
    expect_u32("alone count", count, 4);
    expect_u32("alone reporting_edges", hdr.reporting_edges, 1);
    lookup_image(alone, "shared.example", &count, &edges, &sources, NULL);
    expect_u32("alone shared is local only", count, 10);
    lookup_image(local, "only.example", &count, &edges, &sources, NULL);
    expect_u32("local floor still 7", edges, 7);
}

static void test_seed_own(void) {
    const uint32_t now = 1700000000u;
    const struct merge_row own_rows[] = {{"keep.example", 9, 7, 4}};
    const struct merge_row other_rows[] = {{"extra.example", 3, 1, 1}};
    char own[256], other[256], one[256], merged[256], seeded[256], absent[256], image[256];
    prev_live_t *live;
    prev_header_t hdr;
    uint32_t n = 0;
    uint32_t count;
    uint16_t edges, sources;

    expect_int("seed own NULL", prev_live_seed_own(NULL, "a", "b"), -1);
    join_path(own, sizeof(own), "own.prev");
    join_path(other, sizeof(other), "other.prev");
    join_path(one, sizeof(one), "one.prev");
    join_path(merged, sizeof(merged), "seed-merged.prev");
    join_path(seeded, sizeof(seeded), "seeded-from-own.prev");
    join_path(absent, sizeof(absent), "no-such-local.prev");
    join_path(image, sizeof(image), "seeded-from-prevalence.prev");
    publish_rows("s-own.live", own, now, own_rows, 1);
    publish_rows("s-other.live", other, now, other_rows, 1);
    expect_int("seed merge", prev_merge_images(own, NULL, one, now, &n), 1);
    /* One local image: the merge rewrites the floor, it does not sum it. */
    lookup_image(one, "keep.example", &count, &edges, &sources, &hdr);
    expect_u32("one-image edges", edges, 1);
    expect_u32("one-image reporting", hdr.reporting_edges, 1);
    expect_int("seed merge again", prev_merge_images(own, NULL, one, now, &n), 0);

    /* A second image makes reporting_edges 2, which must not be seeded.
     * Write it to a new path: the stub guard would keep a 1-row image. */
    n = 0;
    {
        char peers[256], peer_file[256];
        int wrote = snprintf(peers, sizeof(peers), "%s/seed-peers", g_dir);
        if (wrote < 0 || (size_t)wrote >= sizeof(peers)) exit(1);
        make_dir(peers);
        wrote = snprintf(peer_file, sizeof(peer_file), "%s/other.prev", peers);
        if (wrote < 0 || (size_t)wrote >= sizeof(peer_file)) exit(1);
        publish_rows("s-peer.live", peer_file, now, other_rows, 1);
        expect_int("two-image merge", prev_merge_images(own, peers, merged, now, &n), 1);
        lookup_image(merged, "extra.example", &count, &edges, &sources, &hdr);
        expect_u32("two-image extra", count, 3);
        expect_u32("two-image reporting", hdr.reporting_edges, 2);
    }

    live = open_live("s-from-own.live");
    expect_int("seed prefers local", prev_live_seed_own(live, own, merged), 0);
    prev_live_note(live, "keep.example", "10.0.0.1");
    expect_int("publish seeded local", prev_live_publish(live, seeded, now, &n), 1);
    lookup_image(seeded, "keep.example", &count, &edges, &sources, NULL);
    expect_u32("seeded keep count", count, 10);
    expect_u32("seeded keep edges", edges, 7);
    lookup_image(seeded, "extra.example", &count, &edges, &sources, NULL);
    expect_u32("merged name not seeded", count, 0);
    expect_int("seed own again", prev_live_seed_own(live, own, merged), 0);
    expect_int("no double seed", prev_live_publish(live, seeded, now + 1u, &n), 0);
    lookup_image(seeded, "keep.example", &count, &edges, &sources, NULL);
    expect_u32("keep not doubled", count, 10);
    prev_live_close(live);

    live = open_live("s-from-merged.live");
    expect_int("seed one-edge merged image", prev_live_seed_own(live, absent, own), 0);
    expect_int("publish from one-edge merged image", prev_live_publish(live, image, now, &n), 1);
    lookup_image(image, "keep.example", &count, &edges, &sources, &hdr);
    expect_u32("one-edge merged count", count, 9);
    expect_u32("one-edge merged edges", edges, 7);
    expect_u32("one-edge merged reporting", hdr.reporting_edges, 1);
    prev_live_close(live);

    live = open_live("s-skip-merged.live");
    expect_int("skip merged image", prev_live_seed_own(live, absent, merged), 0);
    prev_live_note(live, "fresh.example", "10.0.0.2");
    join_path(image, sizeof(image), "skipped-merge.prev");
    expect_int("publish without merged names", prev_live_publish(live, image, now, &n), 1);
    lookup_image(image, "fresh.example", &count, &edges, &sources, NULL);
    expect_u32("fresh count", count, 1);
    lookup_image(image, "keep.example", &count, &edges, &sources, NULL);
    expect_u32("merged keep not imported", count, 0);
    lookup_image(image, "extra.example", &count, &edges, &sources, NULL);
    expect_u32("merged extra not imported", count, 0);
    prev_live_close(live);
}

/* An image under another key names other observables: a seed copies none
 * of its rows and a merge leaves it out. */
static void test_foreign_key(void) {
    char mine[256], foreign[256], peers[256], out[256], fpeer[256];
    prev_live_t *a, *b;
    uint32_t n = 0, count;
    uint16_t edges, sources;
    prev_header_t hdr;
    int wrote;

    join_path(mine, sizeof(mine), "fk-mine.prev");
    join_path(foreign, sizeof(foreign), "fk-foreign.prev");
    join_path(out, sizeof(out), "fk-merged.prev");
    wrote = snprintf(peers, sizeof(peers), "%s/fk-peers", g_dir);
    if (wrote < 0 || (size_t)wrote >= sizeof(peers)) exit(1);
    make_dir(peers);
    wrote = snprintf(fpeer, sizeof(fpeer), "%s/other.prev", peers);
    if (wrote < 0 || (size_t)wrote >= sizeof(fpeer)) exit(1);

    b = open_live("fk-b.live");
    prev_live_set_key(b, 1, 2);
    note_n(b, "foreign.example", "10.9.9.9", 9);
    expect_int("foreign publish", prev_live_publish(b, foreign, 1700000000u, &n), 1);
    expect_int("foreign peer publish", prev_live_publish(b, fpeer, 1700000000u, &n), 1);
    prev_live_close(b);

    a = open_live("fk-a.live");
    expect_int("seed foreign", prev_live_seed(a, foreign), 0);
    note_n(a, "mine.example", "10.1.1.1", 3);
    expect_int("publish after foreign seed", prev_live_publish(a, mine, 1700000000u, &n), 1);
    expect_u32("foreign rows not seeded", n, 1);
    lookup_image(mine, "foreign.example", &count, &edges, &sources, NULL);
    expect_u32("foreign name absent", count, 0);
    prev_live_close(a);

    expect_int("merge with foreign peer", prev_merge_images(mine, peers, out, 1700000000u, &n), 1);
    lookup_image(out, "mine.example", &count, &edges, &sources, &hdr);
    expect_u32("merge keeps own", count, 3);
    expect_u32("foreign peer not counted", hdr.reporting_edges, 1);
    lookup_image(out, "foreign.example", &count, &edges, &sources, NULL);
    expect_u32("foreign peer rows absent", count, 0);
}

/* Count of name in the counter file, read through a published image. */
static uint32_t live_count(prev_live_t *live, const char *image_name, const char *name) {
    char image[256];
    uint32_t n = 0, count = 0;
    uint16_t edges = 0, sources = 0;

    join_path(image, sizeof(image), image_name);
    (void)unlink(image);
    if (prev_live_publish(live, image, 1700000000u, &n) < 0) return UINT32_MAX;
    lookup_image(image, name, &count, &edges, &sources, NULL);
    return count;
}

static void write_file(const char *path, const char *bytes, size_t len, mode_t mode) {
    int fd;
    (void)unlink(path);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || write(fd, bytes, len) != (ssize_t)len || fchmod(fd, mode) != 0) {
        fprintf(stderr, "write %s failed: %s\n", path, strerror(errno));
        exit(1);
    }
    close(fd);
}

static void test_keyed_open(void) {
    static const uint64_t k_a[2] = {TEST_K0, TEST_K1};
    static const uint64_t k_b[2] = {0x1111111111111111ULL, 0x2222222222222222ULL};
    char path[256];
    prev_live_t *one, *two;
    pid_t pid;
    int status = 0;

    printf("-- keyed open\n");
    join_path(path, sizeof(path), "keyed.live");
    (void)unlink(path);
    expect_int("keyed NULL path", prev_live_open_keyed(NULL, k_a) == NULL, 1);
    one = prev_live_open_keyed(path, k_a);
    if (one == NULL) {
        fail_msg("keyed create");
        return;
    }
    expect_int("new file takes the key", prev_live_hash(one, "a.example") == prev_hash(k_a, "a.example"), 1);

    /* A second process under the same key adds to the same rows. */
    pid = fork();
    if (pid == 0) {
        prev_live_t *child = prev_live_open_keyed(path, k_a);
        if (child == NULL) _exit(2);
        prev_live_note(child, "shared.example", "192.0.2.1");
        prev_live_note(child, "shared.example", "192.0.2.2");
        prev_live_close(child);
        _exit(0);
    }
    expect_int("fork", pid > 0, 1);
    if (pid > 0) {
        expect_int("child wait", waitpid(pid, &status, 0) == pid, 1);
        expect_int("child exit", WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
    }
    prev_live_note(one, "shared.example", "192.0.2.3");
    expect_u32("one table for two processes", live_count(one, "keyed-a.prev", "shared.example"), 3);

    /* The same key and a plain open keep the rows. */
    two = prev_live_open_keyed(path, k_a);
    expect_int("same key reopen", two != NULL, 1);
    if (two != NULL) prev_live_close(two);
    two = prev_live_open(path);
    expect_int("plain reopen", two != NULL, 1);
    if (two != NULL) {
        expect_int("plain open keeps the key", prev_live_hash(two, "a.example") == prev_hash(k_a, "a.example"), 1);
        prev_live_close(two);
    }
    expect_u32("rows kept", live_count(one, "keyed-b.prev", "shared.example"), 3);
    prev_live_close(one);

    /* Another key empties the file once, then counts under it. */
    two = prev_live_open_keyed(path, k_b);
    if (two == NULL) {
        fail_msg("rekey open");
        return;
    }
    expect_int("rekey installs the key", prev_live_hash(two, "a.example") == prev_hash(k_b, "a.example"), 1);
    expect_u32("rekey empties the rows", live_count(two, "keyed-c.prev", "shared.example"), 0);
    prev_live_note(two, "after.example", "192.0.2.4");
    prev_live_close(two);
    two = prev_live_open_keyed(path, k_b);
    expect_int("rekeyed reopen", two != NULL, 1);
    if (two != NULL) {
        expect_u32("rows under the new key kept", live_count(two, "keyed-d.prev", "after.example"), 1);
        prev_live_close(two);
    }
}

static void test_read_key(void) {
    static const char hex[] = "000102030405060708090a0b0c0d0e0f";
    char path[256], link_path[256], buf[64];
    uint64_t key[2];

    printf("-- key file\n");
    join_path(path, sizeof(path), "prevalence.key");
    join_path(link_path, sizeof(link_path), "prevalence.key.link");

    expect_int("key NULL path", prev_live_read_key(NULL, key), PREV_KEY_EOPEN);
    expect_int("key empty path", prev_live_read_key("", key), PREV_KEY_EOPEN);
    (void)unlink(path);
    expect_int("key missing", prev_live_read_key(path, key), PREV_KEY_EOPEN);

    write_file(path, hex, sizeof hex - 1, 0600);
    key[0] = key[1] = 0;
    expect_int("key bare", prev_live_read_key(path, key), 0);
    /* The byte order is fixed: the same file gives the same key on
     * every architecture, and the test key of the other tests. */
    expect_int("key k0", key[0] == TEST_K0, 1);
    expect_int("key k1", key[1] == TEST_K1, 1);

    snprintf(buf, sizeof buf, "%s\n", hex);
    write_file(path, buf, strlen(buf), 0640);
    expect_int("key newline, group read", prev_live_read_key(path, key), 0);
    snprintf(buf, sizeof buf, "%s\r\n", hex);
    write_file(path, buf, strlen(buf), 0400);
    expect_int("key crlf", prev_live_read_key(path, key), 0);
    write_file(path, "000102030405060708090A0B0C0D0E0F", 32, 0600);
    expect_int("key upper case", prev_live_read_key(path, key), 0);
    expect_int("key upper case k1", key[1] == TEST_K1, 1);

    key[0] = key[1] = 7;
    write_file(path, hex, sizeof hex - 1, 0644);
    expect_int("key world readable", prev_live_read_key(path, key), PREV_KEY_EMODE);
    write_file(path, hex, sizeof hex - 1, 0620);
    expect_int("key group writable", prev_live_read_key(path, key), PREV_KEY_EMODE);
    expect_int("refused key untouched", key[0] == 7 && key[1] == 7, 1);

    write_file(path, hex, 31, 0600);
    expect_int("key short", prev_live_read_key(path, key), PREV_KEY_EFORMAT);
    snprintf(buf, sizeof buf, "%s0", hex);
    write_file(path, buf, strlen(buf), 0600);
    expect_int("key long", prev_live_read_key(path, key), PREV_KEY_EFORMAT);
    snprintf(buf, sizeof buf, "%s\n\n", hex);
    write_file(path, buf, strlen(buf), 0600);
    expect_int("key two line ends", prev_live_read_key(path, key), PREV_KEY_EFORMAT);
    snprintf(buf, sizeof buf, " %s", hex);
    buf[32] = '\0';
    write_file(path, buf, 32, 0600);
    expect_int("key leading space", prev_live_read_key(path, key), PREV_KEY_EFORMAT);
    write_file(path, "000102030405060708090a0b0c0d0e0g", 32, 0600);
    expect_int("key not hex", prev_live_read_key(path, key), PREV_KEY_EFORMAT);
    write_file(path, "00000000000000000000000000000000", 32, 0600);
    expect_int("key all zero", prev_live_read_key(path, key), PREV_KEY_EFORMAT);
    expect_int("bad key untouched", key[0] == 7 && key[1] == 7, 1);

    write_file(path, hex, sizeof hex - 1, 0600);
    (void)unlink(link_path);
    expect_int("symlink made", symlink(path, link_path), 0);
    expect_int("key symlink", prev_live_read_key(link_path, key), PREV_KEY_EOPEN);
    expect_int("key directory", prev_live_read_key(g_dir, key), PREV_KEY_EOPEN);
}

/* The directory may be writable by a less privileged user: a planted
 * symlink or hard link must not make this process write another file. */
static void test_planted_links(void) {
    static const uint64_t k[2] = {TEST_K0, TEST_K1};
    char victim[256], live_path[256], image[256], tmp[300];
    struct stat st;
    prev_live_t *live;
    uint32_t n = 0;

    printf("-- planted links\n");
    join_path(victim, sizeof victim, "victim");
    join_path(live_path, sizeof live_path, "planted.live");
    join_path(image, sizeof image, "planted.prev");

    write_file(victim, "", 0, 0600);
    (void)unlink(live_path);
    expect_int("symlink to victim", symlink(victim, live_path), 0);
    expect_int("live open refuses a symlink", prev_live_open_keyed(live_path, k) == NULL, 1);
    (void)unlink(live_path);
    expect_int("hard link to victim", link(victim, live_path), 0);
    expect_int("live open refuses a hard link", prev_live_open_keyed(live_path, k) == NULL, 1);
    expect_int("victim stat", stat(victim, &st), 0);
    expect_int("victim not grown", st.st_size == 0, 1);
    (void)unlink(live_path);

    write_file(victim, "keep", 4, 0600);
    live = open_live("planted-src.live");
    prev_live_note(live, "planted.example", "192.0.2.9");
    snprintf(tmp, sizeof tmp, "%s.tmp.%d", image, (int)getpid());
    (void)unlink(tmp);
    (void)unlink(image);
    expect_int("planted tmp symlink", symlink(victim, tmp), 0);
    expect_int("publish past a planted tmp", prev_live_publish(live, image, 1700000000u, &n), 1);
    expect_int("victim stat after publish", stat(victim, &st), 0);
    expect_int("victim untouched by publish", st.st_size == 4, 1);
    expect_int("image is a regular file", lstat(image, &st) == 0 && S_ISREG(st.st_mode), 1);
    (void)unlink(image);
    expect_int("planted tmp hard link", link(victim, tmp), 0);
    prev_live_note(live, "planted2.example", "192.0.2.9");
    expect_int("publish past a planted hard link", prev_live_publish(live, image, 1700000001u, &n), 1);
    expect_int("victim stat after second publish", stat(victim, &st), 0);
    expect_int("victim untouched by second publish", st.st_size == 4, 1);
    prev_live_close(live);
}

int main(int argc, char **argv) {
    const char *tmp = getenv("TMPDIR");
    if (tmp == NULL || tmp[0] == '\0') {
        tmp = "/tmp";
    }
    int wrote = snprintf(g_dir, sizeof(g_dir), "%s/prev-live-XXXXXX", tmp);
    if (wrote < 0 || (size_t)wrote >= sizeof(g_dir)) {
        fprintf(stderr, "TMPDIR too long\n");
        return 1;
    }
    if (mkdtemp(g_dir) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    test_null_and_empty();
    test_conformance();
    test_sources_and_floor();
    test_stub();
    test_stub_hold();
    test_rotate();
    test_hammer();
    test_reopen_and_seed(argc > 1 ? argv[1] : NULL);
    test_merge();
    test_seed_own();
    test_foreign_key();
    test_keyed_open();
    test_read_key();
    test_planted_links();
    if (g_fail != 0) {
        fprintf(stderr, "%d failure%s\n", g_fail, g_fail == 1 ? "" : "s");
        return finish(1);
    }
    printf("ok %s\n", g_dir);
    return finish(0);
}
