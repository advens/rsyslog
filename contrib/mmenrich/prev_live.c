/* prev_live.c
 * Counter file plus the .prev publisher. See prev_live.h.
 *
 * A local image is one appliance. reporting_edges in that image is 1.
 * edge_count is 1 for a row this process has seen, unless a baseline
 * floor is still inside the current window. source_count is the distinct
 * source.ip values remembered for that row, capped, and never a substitute
 * for a second appliance.
 *
 * prev_merge_images combines local images. Each file contributes one edge
 * for a name it contains. The merged header's reporting_edges is the
 * number of files that were fresh enough to include.
 */
#include "prev_live.h"

#include "prev_format.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__) || defined(__linux__)
    #include <sys/random.h> /* getentropy */
#endif

#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    #error "the prevalence image is little-endian"
#endif

#define PREV_LIVE_MAGIC 0x5052564cu /* "PRVL" */
#define PREV_LIVE_VERSION 2u
#define PREV_LIVE_SLOTS (1u << 18) /* 262144 open-addressed rows */
#define PREV_LIVE_SRCS 8u
#define PREV_LIVE_PROBE 128
#define PREV_WINDOW_SEC (7u * 24u * 3600u)
#define PREV_PUBLISH_MAX 200000u
#define PREV_STUB_MIN 8u
#define PREV_MERGE_MAX_IMAGES 64u
#define PREV_MERGE_PATH 512
/* A full local image is about 8 MB (200k names). Larger files are not ours. */
#define PREV_MERGE_MAX_BYTES (16u * 1024u * 1024u)

typedef struct prev_live_slot {
    uint64_t key;
    uint32_t count_cur;
    uint32_t count_prev;
    uint32_t edge_floor; /* published as u16; 0 means "this appliance" */
    uint32_t src_floor; /* baseline distinct sources, cleared on rotate */
    uint32_t src_hash[PREV_LIVE_SRCS];
    uint32_t src_sec[PREV_LIVE_SRCS];
} prev_live_slot_t;

struct prev_live_hdr {
    uint32_t magic;
    uint32_t version;
    uint32_t slots;
    uint32_t window_sec;
    uint32_t window_start;
    uint32_t seeded;
    uint32_t now_sec;
    uint32_t _pad0;
    uint64_t notes;
    uint64_t drops;
    uint64_t sip_key[2]; /* key of every row; published images carry it */
};

typedef struct {
    uint64_t key;
    uint32_t count;
    uint16_t edges;
    uint16_t sources;
} prev_pub_item_t;

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct prev_live_hdr) == 64, "prevalence counter header is 64 bytes");
_Static_assert(sizeof(prev_live_slot_t) == 88, "prevalence counter row is 88 bytes");
_Static_assert(sizeof(prev_header_t) == 80, "published prevalence header");
_Static_assert(sizeof(prev_entry_t) == 16, "published prevalence row");
#endif

static size_t prev_live_bytes(void) {
    return sizeof(struct prev_live_hdr) + (size_t)PREV_LIVE_SLOTS * sizeof(prev_live_slot_t);
}

static prev_live_slot_t *prev_live_slots(prev_live_t *live) {
    return (prev_live_slot_t *)((uint8_t *)live + sizeof(struct prev_live_hdr));
}

static uint32_t prev_now(prev_live_t *live) {
    uint32_t now = __atomic_load_n(&live->now_sec, __ATOMIC_RELAXED);
    if (now == 0) now = (uint32_t)time(NULL);
    return now;
}

static uint64_t prev_key(const prev_live_t *live, const char *s) {
    return prev_hash(live->sip_key, s);
}

uint64_t prev_live_hash(const prev_live_t *live, const char *observable) {
    if (live == NULL || observable == NULL) return 0;
    return prev_key(live, observable);
}

static prev_live_slot_t *prev_live_probe(prev_live_t *live, uint64_t key, int create) {
    prev_live_slot_t *slots = prev_live_slots(live);
    uint32_t mask = PREV_LIVE_SLOTS - 1u;
    uint32_t idx = (uint32_t)key & mask;
    int n;

    for (n = 0; n < PREV_LIVE_PROBE; n++) {
        prev_live_slot_t *slot = &slots[idx];
        uint64_t cur = __atomic_load_n(&slot->key, __ATOMIC_ACQUIRE);
        if (cur == key) return slot;
        if (cur == 0) {
            if (!create) return NULL;
            if (__atomic_compare_exchange_n(&slot->key, &cur, key, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) return slot;
            continue; /* lost the empty row, look again */
        }
        idx = (idx + 1u) & mask;
    }
    return NULL;
}

static void prev_note_source(const prev_live_t *live, prev_live_slot_t *slot, const char *source, uint32_t now) {
    uint32_t sh;
    int attempt;

    if (source == NULL || source[0] == '\0' || now == 0) return;
    sh = (uint32_t)prev_key(live, source);
    if (sh == 0) sh = 1;
    for (attempt = 0; attempt < 2; attempt++) {
        int free_idx = -1;
        int i;
        for (i = 0; i < (int)PREV_LIVE_SRCS; i++) {
            uint32_t cur = __atomic_load_n(&slot->src_hash[i], __ATOMIC_ACQUIRE);
            if (cur == sh) {
                __atomic_store_n(&slot->src_sec[i], now, __ATOMIC_RELAXED);
                return;
            }
            if (cur == 0 && free_idx < 0) free_idx = i;
        }
        if (free_idx < 0) return; /* eight distinct sources: the lte-2 gate is already false */
        {
            uint32_t expected = 0;
            if (__atomic_compare_exchange_n(&slot->src_hash[free_idx], &expected, sh, 0, __ATOMIC_RELEASE,
                                            __ATOMIC_RELAXED)) {
                __atomic_store_n(&slot->src_sec[free_idx], now, __ATOMIC_RELAXED);
                return;
            }
        }
    }
}

static void prev_add_count(prev_live_slot_t *slot) {
    uint32_t c;
    do {
        c = __atomic_load_n(&slot->count_cur, __ATOMIC_RELAXED);
        if (c == UINT32_MAX) return;
    } while (!__atomic_compare_exchange_n(&slot->count_cur, &c, c + 1u, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED));
}

void prev_live_tick(prev_live_t *live, uint32_t now_sec) {
    if (live == NULL || now_sec == 0) return;
    __atomic_store_n(&live->now_sec, now_sec, __ATOMIC_RELAXED);
}

void prev_live_note(prev_live_t *live, const char *observable, const char *source_ip) {
    prev_live_slot_t *slot;
    uint64_t key;

    if (live == NULL || observable == NULL || observable[0] == '\0') return;
    key = prev_key(live, observable);
    slot = prev_live_probe(live, key, 1);
    if (slot == NULL) {
        __atomic_fetch_add(&live->drops, 1, __ATOMIC_RELAXED);
        return;
    }
    prev_add_count(slot);
    prev_note_source(live, slot, source_ip, prev_now(live));
    __atomic_fetch_add(&live->notes, 1, __ATOMIC_RELAXED);
}

int prev_live_put(prev_live_t *live, uint64_t key, uint32_t count, uint16_t edges, uint16_t sources) {
    prev_live_slot_t *slot;
    uint32_t prev;

    if (live == NULL || count == 0) return -1;
    if (key == 0) key = 1;
    slot = prev_live_probe(live, key, 1);
    if (slot == NULL) return -1;
    prev = 0;
    (void)__atomic_compare_exchange_n(&slot->count_prev, &prev, count, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
    {
        uint32_t z = 0;
        (void)__atomic_compare_exchange_n(&slot->edge_floor, &z, (uint32_t)edges, 0, __ATOMIC_RELAXED,
                                          __ATOMIC_RELAXED);
        z = 0;
        (void)__atomic_compare_exchange_n(&slot->src_floor, &z, (uint32_t)sources, 0, __ATOMIC_RELAXED,
                                          __ATOMIC_RELAXED);
    }
    return 0;
}

void prev_live_set_key(prev_live_t *live, uint64_t k0, uint64_t k1) {
    if (live == NULL || (live->sip_key[0] == k0 && live->sip_key[1] == k1)) return;
    memset(prev_live_slots(live), 0, (size_t)PREV_LIVE_SLOTS * sizeof(prev_live_slot_t));
    live->sip_key[0] = k0;
    live->sip_key[1] = k1;
    __atomic_store_n(&live->seeded, 0u, __ATOMIC_RELEASE);
}

void prev_live_set_window_start(prev_live_t *live, uint32_t start) {
    if (live == NULL) return;
    __atomic_store_n(&live->window_start, start, __ATOMIC_RELAXED);
}

/* A fresh header under key, or under a random key when key is NULL.
 * -1 when no randomness is available: a guessable key would let an
 * observable be chosen to collide. */
static int prev_live_init_header(prev_live_t *live, uint32_t now, const uint64_t key_in[2]) {
    uint64_t key[2];
    if (key_in != NULL) {
        key[0] = key_in[0];
        key[1] = key_in[1];
    } else if (getentropy(key, sizeof key) != 0) {
        return -1;
    }
    memset(live, 0, sizeof(*live));
    live->magic = PREV_LIVE_MAGIC;
    live->version = PREV_LIVE_VERSION;
    live->slots = PREV_LIVE_SLOTS;
    live->window_sec = PREV_WINDOW_SEC;
    live->window_start = now == 0 ? (uint32_t)time(NULL) : now;
    live->sip_key[0] = key[0];
    live->sip_key[1] = key[1];
    return 0;
}

prev_live_t *prev_live_open(const char *path) {
    return prev_live_open_keyed(path, NULL);
}

prev_live_t *prev_live_open_keyed(const char *path, const uint64_t key[2]) {
    struct stat st;
    prev_live_t *live;
    size_t bytes;
    int fd;

    if (path == NULL || path[0] == '\0') return NULL;
    bytes = prev_live_bytes();
    /* Not through a symlink, and not a hard link to another file: the
     * directory may be writable by a less privileged user, and this
     * process writes the file. */
    fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0640);
    if (fd < 0) return NULL;
    if (flock(fd, LOCK_EX) != 0) {
        close(fd);
        return NULL;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1) {
        flock(fd, LOCK_UN);
        close(fd);
        return NULL;
    }
    if (st.st_size == 0) {
        if (ftruncate(fd, (off_t)bytes) != 0) {
            flock(fd, LOCK_UN);
            close(fd);
            return NULL;
        }
    } else if ((size_t)st.st_size != bytes) {
        flock(fd, LOCK_UN);
        close(fd);
        return NULL;
    }
    live = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (live == MAP_FAILED) {
        flock(fd, LOCK_UN);
        close(fd);
        return NULL;
    }
    /* Header is written before the lock drops so a second opener never
     * observes a full-size file with a zero magic and rejects it. A zero
     * magic after a crash mid-create is adopted, not destroyed. */
    /* A counter file of an older version holds rows hashed another way:
     * start it over rather than misread it. The window is days, the loss
     * is that window. */
    if (live->magic == PREV_LIVE_MAGIC && live->version != PREV_LIVE_VERSION && live->slots == PREV_LIVE_SLOTS)
        memset(live, 0, bytes);
    /* Rows counted under another key hash other names. Under the lock,
     * before any caller of this mapping adds a row, the file starts over
     * with the given key. */
    if (key != NULL && live->magic == PREV_LIVE_MAGIC && live->version == PREV_LIVE_VERSION &&
        live->slots == PREV_LIVE_SLOTS && (live->sip_key[0] != key[0] || live->sip_key[1] != key[1]))
        memset(live, 0, bytes);
    if ((live->magic == 0 && live->version == 0 && prev_live_init_header(live, 0, key) != 0) ||
        live->magic != PREV_LIVE_MAGIC || live->version != PREV_LIVE_VERSION || live->slots != PREV_LIVE_SLOTS) {
        munmap(live, bytes);
        flock(fd, LOCK_UN);
        close(fd);
        return NULL;
    }
    flock(fd, LOCK_UN);
    close(fd);
    return live;
}

/* Overwrite secret bytes in a way the compiler keeps. */
static void prev_wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n-- > 0) *v++ = 0;
}

static int prev_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int prev_live_read_key(const char *path, uint64_t key[2]) {
    char buf[PREV_KEY_HEX_LEN + 3];
    uint8_t raw[16];
    struct stat st;
    size_t len = 0;
    size_t i;
    uint8_t any = 0;
    int rc = PREV_KEY_EFORMAT;
    int fd;

    if (path == NULL || path[0] == '\0' || key == NULL) return PREV_KEY_EOPEN;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return PREV_KEY_EOPEN;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return PREV_KEY_EOPEN;
    }
    /* Readable by the owner and its group at most, writable by the owner. */
    if ((st.st_mode & (S_IWGRP | S_IRWXO)) != 0) {
        close(fd);
        return PREV_KEY_EMODE;
    }
    while (len < sizeof(buf)) {
        ssize_t n = read(fd, buf + len, sizeof(buf) - len);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            close(fd);
            prev_wipe(buf, sizeof buf);
            return PREV_KEY_EOPEN;
        }
        if (n == 0) break;
        len += (size_t)n;
    }
    close(fd);
    /* 32 hex digits, then at most one line end. */
    if (len == PREV_KEY_HEX_LEN + 1 && buf[PREV_KEY_HEX_LEN] == '\n')
        len = PREV_KEY_HEX_LEN;
    else if (len == PREV_KEY_HEX_LEN + 2 && buf[PREV_KEY_HEX_LEN] == '\r' && buf[PREV_KEY_HEX_LEN + 1] == '\n')
        len = PREV_KEY_HEX_LEN;
    if (len == PREV_KEY_HEX_LEN) {
        rc = 0;
        for (i = 0; i < sizeof raw; i++) {
            int hi = prev_hex_nibble(buf[2 * i]);
            int lo = prev_hex_nibble(buf[2 * i + 1]);
            if (hi < 0 || lo < 0) {
                rc = PREV_KEY_EFORMAT;
                break;
            }
            raw[i] = (uint8_t)((hi << 4) | lo);
            any |= raw[i];
        }
        if (rc == 0 && any == 0) rc = PREV_KEY_EFORMAT;
        if (rc == 0) {
            /* Byte order is fixed so every edge derives the same key. */
            uint64_t k0 = 0, k1 = 0;
            for (i = 0; i < 8; i++) {
                k0 |= (uint64_t)raw[i] << (8 * i);
                k1 |= (uint64_t)raw[8 + i] << (8 * i);
            }
            key[0] = k0;
            key[1] = k1;
            prev_wipe(&k0, sizeof k0);
            prev_wipe(&k1, sizeof k1);
        }
    }
    prev_wipe(buf, sizeof buf);
    prev_wipe(raw, sizeof raw);
    return rc;
}

const char *prev_live_key_error(int rc) {
    switch (rc) {
        case 0:
            return "ok";
        case PREV_KEY_EMODE:
            return "other users can read it or its group can write it";
        case PREV_KEY_EFORMAT:
            return "not 32 hex digits, or all zero";
        default:
            return "missing, unreadable, or not a regular file";
    }
}

void prev_live_close(prev_live_t *live) {
    if (live == NULL) return;
    munmap(live, prev_live_bytes());
}

int prev_live_seed(prev_live_t *live, const char *prev_path) {
    struct stat st;
    const prev_entry_t *table;
    uint32_t slots = 0;
    uint32_t i;
    void *base;
    int fd;

    if (live == NULL || prev_path == NULL || prev_path[0] == '\0') return -1;
    if (__atomic_load_n(&live->seeded, __ATOMIC_ACQUIRE) != 0) return 0;
    fd = open(prev_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        __atomic_store_n(&live->seeded, 1u, __ATOMIC_RELEASE);
        return 0;
    }
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(prev_header_t)) {
        close(fd);
        __atomic_store_n(&live->seeded, 1u, __ATOMIC_RELEASE);
        return 0;
    }
    base = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) return -1;
    table = prev_table_map(base, (size_t)st.st_size, &slots);
    /* Rows hashed under another key would land on the wrong names. */
    if (table != NULL && memcmp(((const prev_header_t *)base)->sip_key, live->sip_key, sizeof live->sip_key) == 0) {
        for (i = 0; i < slots; i++) {
            if (table[i].hash_key == 0 || table[i].total_count == 0) continue;
            (void)prev_live_put(live, table[i].hash_key, table[i].total_count, table[i].edge_count,
                                table[i].source_count);
        }
    }
    munmap(base, (size_t)st.st_size);
    __atomic_store_n(&live->seeded, 1u, __ATOMIC_RELEASE);
    return 0;
}

static int prev_read_header(const char *path, prev_header_t *hdr) {
    int fd;
    ssize_t n;

    if (path == NULL || path[0] == '\0' || hdr == NULL) return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    n = read(fd, hdr, sizeof(*hdr));
    close(fd);
    if (n != (ssize_t)sizeof(*hdr)) return -1;
    if (hdr->magic != PREV_MAGIC || hdr->version != PREV_VERSION) return -1;
    return 0;
}

static int prev_image_one_edge(const char *path) {
    prev_header_t hdr;

    if (prev_read_header(path, &hdr) != 0) return 0;
    return hdr.reporting_edges == 1u;
}

int prev_live_seed_own(prev_live_t *live, const char *local_path, const char *merged_path) {
    if (live == NULL) return -1;
    if (__atomic_load_n(&live->seeded, __ATOMIC_ACQUIRE) != 0) return 0;
    if (prev_image_one_edge(local_path)) return prev_live_seed(live, local_path);
    if (prev_image_one_edge(merged_path)) return prev_live_seed(live, merged_path);
    /* Missing, or already a merged image. Mark seeded so the next
     * publish is not imported back into the counters. */
    __atomic_store_n(&live->seeded, 1u, __ATOMIC_RELEASE);
    return 0;
}

static uint32_t prev_sum(uint32_t cur, uint32_t prev) {
    uint64_t s = (uint64_t)cur + (uint64_t)prev;
    if (s > UINT32_MAX) return UINT32_MAX;
    return (uint32_t)s;
}

static uint16_t prev_sources(const prev_live_slot_t *slot) {
    uint32_t n = 0;
    uint32_t floor;
    int i;

    for (i = 0; i < (int)PREV_LIVE_SRCS; i++) {
        if (__atomic_load_n(&slot->src_hash[i], __ATOMIC_RELAXED) != 0) n++;
    }
    floor = __atomic_load_n(&slot->src_floor, __ATOMIC_RELAXED);
    if (floor > n) n = floor;
    if (n > 65535u) n = 65535u;
    return (uint16_t)n;
}

static void prev_live_rotate(prev_live_t *live, uint32_t now) {
    uint32_t start = __atomic_load_n(&live->window_start, __ATOMIC_RELAXED);
    uint32_t window = live->window_sec == 0 ? PREV_WINDOW_SEC : live->window_sec;
    prev_live_slot_t *slots;
    uint32_t i;

    if (now < start || now - start < window) return;
    __atomic_store_n(&live->window_start, now, __ATOMIC_RELAXED);
    slots = prev_live_slots(live);
    for (i = 0; i < PREV_LIVE_SLOTS; i++) {
        prev_live_slot_t *slot = &slots[i];
        uint32_t cur;
        int s;
        if (__atomic_load_n(&slot->key, __ATOMIC_RELAXED) == 0) continue;
        cur = __atomic_exchange_n(&slot->count_cur, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->count_prev, cur, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->edge_floor, 0u, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->src_floor, 0u, __ATOMIC_RELAXED);
        for (s = 0; s < (int)PREV_LIVE_SRCS; s++) {
            uint32_t sec = __atomic_load_n(&slot->src_sec[s], __ATOMIC_RELAXED);
            if (sec != 0 && now > sec && now - sec > 2u * window) {
                __atomic_store_n(&slot->src_hash[s], 0u, __ATOMIC_RELAXED);
                __atomic_store_n(&slot->src_sec[s], 0u, __ATOMIC_RELAXED);
            }
        }
    }
}

static int prev_cmp_item(const void *a, const void *b) {
    const prev_pub_item_t *x = a;
    const prev_pub_item_t *y = b;
    if (x->count < y->count) return 1;
    if (x->count > y->count) return -1;
    if (x->key < y->key) return -1;
    if (x->key > y->key) return 1;
    return 0;
}

static uint32_t prev_next_pow2(uint32_t n) {
    uint32_t p = 1;
    if (n == 0) return 1;
    while (p < n) {
        if (p > 0x80000000u) return 0x80000000u;
        p <<= 1;
    }
    return p;
}

static uint32_t prev_image_entries(const char *path) {
    prev_header_t hdr;
    int fd;
    ssize_t n;

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    n = read(fd, &hdr, sizeof(hdr));
    close(fd);
    if (n != (ssize_t)sizeof(hdr)) return 0;
    if (hdr.magic != PREV_MAGIC || hdr.version != PREV_VERSION) return 0;
    return hdr.entry_count;
}

/* 1 when the entry bytes and the header fields that describe them match.
 * The epoch word is ignored so a quiet minute does not rewrite the image. */
static int prev_image_same(const char *path, const uint8_t *neu, size_t nlen) {
    uint8_t *old;
    struct stat st;
    int fd;
    int same = 0;

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    if (fstat(fd, &st) != 0 || st.st_size < 0 || (size_t)st.st_size != nlen || nlen < 32) {
        close(fd);
        return 0;
    }
    old = mmap(NULL, nlen, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (old == MAP_FAILED) return 0;
    same = memcmp(old, neu, 28) == 0 && memcmp(old + 32, neu + 32, nlen - 32) == 0;
    munmap(old, nlen);
    return same;
}

static int prev_fsync_dir(const char *path) {
    char dir[4096];
    char *slash;
    size_t len;
    int dfd;
    int rc;

    len = strlen(path);
    if (len == 0 || len >= sizeof(dir)) return -1;
    memcpy(dir, path, len + 1);
    slash = strrchr(dir, '/');
    if (slash == NULL) return 0;
    if (slash == dir)
        slash[1] = '\0';
    else
        *slash = '\0';
    dfd = open(dir, O_RDONLY | O_CLOEXEC);
    if (dfd < 0) return -1;
    rc = fsync(dfd);
    close(dfd);
    return rc;
}

static uint8_t *prev_build_image(prev_pub_item_t *items,
                                 uint32_t n,
                                 uint32_t epoch,
                                 uint32_t reporting_edges,
                                 const uint64_t sip_key[2],
                                 size_t *out_len) {
    uint32_t need = n * 2u + 1u;
    uint32_t slots;
    uint32_t mask;
    uint32_t placed = 0;
    uint32_t count_max = 0;
    size_t total;
    uint8_t *buf;
    prev_header_t *hdr;
    prev_entry_t *table;
    uint32_t i;

    if (need < n) return NULL; /* overflow */
    slots = prev_next_pow2(need);
    if (slots < 8u) slots = 8u;
    total = sizeof(prev_header_t) + (size_t)slots * sizeof(prev_entry_t);
    buf = calloc(1, total);
    if (buf == NULL) return NULL;
    table = (prev_entry_t *)(buf + sizeof(prev_header_t));
    mask = slots - 1u;
    for (i = 0; i < n; i++) {
        uint64_t h = items[i].key == 0 ? 1 : items[i].key;
        uint32_t idx = (uint32_t)h & mask;
        uint32_t probe;
        for (probe = 0; probe < slots; probe++) {
            if (table[idx].hash_key == 0 || table[idx].hash_key == h) {
                if (table[idx].hash_key == 0) placed++;
                table[idx].hash_key = h;
                table[idx].total_count = items[i].count;
                table[idx].edge_count = items[i].edges;
                table[idx].source_count = items[i].sources;
                break;
            }
            idx = (idx + 1u) & mask;
        }
        if (items[i].count > count_max) count_max = items[i].count;
    }
    hdr = (prev_header_t *)buf;
    hdr->magic = PREV_MAGIC;
    hdr->version = PREV_VERSION;
    hdr->total_size = (uint64_t)total;
    hdr->hash_slots = slots;
    hdr->entry_count = placed;
    hdr->checksum = 0;
    hdr->epoch = epoch;
    hdr->offset_entries = sizeof(prev_header_t);
    hdr->count_max = count_max;
    hdr->reporting_edges = reporting_edges;
    hdr->sip_key[0] = sip_key[0];
    hdr->sip_key[1] = sip_key[1];
    *out_len = total;
    return buf;
}

/* Replace path by rename. 1 written, 0 unchanged, -1 error.
 * image stays owned by the caller. */
static int prev_commit_image(
    const char *path, const uint8_t *image, size_t image_len, uint32_t n_rows, uint32_t *n_out) {
    char tmp[4096];
    int fd = -1;
    int rc = -1;
    size_t off;

    if (n_out) *n_out = 0;
    if (path == NULL || path[0] == '\0' || image == NULL || image_len == 0) return -1;
    if (prev_image_same(path, image, image_len)) return 0;
    if (strlen(path) + 32 >= sizeof(tmp)) return -1;
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    /* The directory may be writable by a less privileged user. A name
     * planted there (a symlink, or a hard link to another file) is
     * removed, and the temporary file is created new, never opened. */
    (void)unlink(tmp);
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0640);
    if (fd < 0) return -1;
    off = 0;
    while (off < image_len) {
        ssize_t w = write(fd, image + off, image_len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            goto done;
        }
        off += (size_t)w;
    }
    if (fsync(fd) != 0) goto done;
    if (close(fd) != 0) {
        fd = -1;
        goto done;
    }
    fd = -1;
    if (rename(tmp, path) != 0) goto done;
    (void)prev_fsync_dir(path);
    if (n_out) *n_out = n_rows;
    rc = 1;

done:
    if (fd >= 0) close(fd);
    if (rc != 1) unlink(tmp);
    return rc;
}

static int prev_image_too_small(const char *path, uint32_t n) {
    uint32_t live_entries;
    uint32_t floor;

    live_entries = prev_image_entries(path);
    floor = live_entries / 2u;
    if (floor < PREV_STUB_MIN) floor = PREV_STUB_MIN;
    return live_entries > 0 && n < floor;
}

int prev_live_publish(prev_live_t *live, const char *prev_path, uint32_t now_sec, uint32_t *n_out) {
    prev_live_slot_t *slots;
    prev_pub_item_t *items;
    uint8_t *image = NULL;
    size_t image_len = 0;
    uint32_t n = 0;
    uint32_t i;
    int rc;

    if (n_out) *n_out = 0;
    if (live == NULL || prev_path == NULL || prev_path[0] == '\0') return -1;
    if (now_sec == 0) now_sec = (uint32_t)time(NULL);
    prev_live_tick(live, now_sec);
    prev_live_rotate(live, now_sec);

    items = calloc(PREV_LIVE_SLOTS, sizeof(*items));
    if (items == NULL) return -1;
    slots = prev_live_slots(live);
    for (i = 0; i < PREV_LIVE_SLOTS; i++) {
        prev_live_slot_t *slot = &slots[i];
        uint64_t key = __atomic_load_n(&slot->key, __ATOMIC_ACQUIRE);
        uint32_t cur, prev, sum;
        uint32_t edges;
        if (key == 0) continue;
        cur = __atomic_load_n(&slot->count_cur, __ATOMIC_RELAXED);
        prev = __atomic_load_n(&slot->count_prev, __ATOMIC_RELAXED);
        sum = prev_sum(cur, prev);
        if (sum == 0) continue;
        edges = __atomic_load_n(&slot->edge_floor, __ATOMIC_RELAXED);
        if (edges == 0) edges = 1;
        if (edges > 65535u) edges = 65535u;
        items[n].key = key;
        items[n].count = sum;
        items[n].edges = (uint16_t)edges;
        items[n].sources = prev_sources(slot);
        n++;
    }
    if (n == 0) {
        free(items);
        return 0;
    }
    if (n > PREV_PUBLISH_MAX) {
        qsort(items, n, sizeof(*items), prev_cmp_item);
        n = PREV_PUBLISH_MAX;
    }
    if (prev_image_too_small(prev_path, n)) {
        free(items);
        return 0;
    }
    image = prev_build_image(items, n, now_sec, 1u, live->sip_key, &image_len);
    free(items);
    if (image == NULL) return -1;
    rc = prev_commit_image(prev_path, image, image_len, n, n_out);
    free(image);
    return rc;
}

static int prev_epoch_fresh(uint32_t epoch, uint32_t now_sec) {
    if (epoch == 0) return 0;
    /* A peer clock ahead of ours is still a report. Only an old one drops. */
    if (now_sec > epoch && now_sec - epoch > PREV_WINDOW_SEC) return 0;
    return 1;
}

static int prev_image_fresh(const char *path, uint32_t now_sec, uint32_t *entries) {
    prev_header_t hdr;

    if (prev_read_header(path, &hdr) != 0) return 0;
    if (!prev_epoch_fresh(hdr.epoch, now_sec)) return 0;
    if (entries != NULL) {
        *entries = hdr.entry_count;
        if (*entries > PREV_PUBLISH_MAX) *entries = PREV_PUBLISH_MAX;
    }
    return 1;
}

/* One image contributes one edge, whatever edge_count it stored. */
static int prev_acc_add(prev_pub_item_t *table, uint32_t slots, uint64_t key, uint32_t count, uint16_t sources) {
    uint64_t sum;
    uint32_t mask;
    uint32_t idx;
    uint32_t probe;
    uint32_t src;

    if (slots == 0 || key == 0) return 0;
    mask = slots - 1u;
    idx = (uint32_t)key & mask;
    for (probe = 0; probe < slots; probe++) {
        if (table[idx].key == 0) {
            table[idx].key = key;
            table[idx].count = count;
            table[idx].edges = 1;
            table[idx].sources = sources;
            return 1;
        }
        if (table[idx].key == key) {
            sum = (uint64_t)table[idx].count + (uint64_t)count;
            table[idx].count = sum > UINT32_MAX ? UINT32_MAX : (uint32_t)sum;
            src = (uint32_t)table[idx].sources + (uint32_t)sources;
            if (src > 65535u) src = 65535u;
            table[idx].sources = (uint16_t)src;
            if (table[idx].edges != 65535u) table[idx].edges++;
            return 0;
        }
        idx = (idx + 1u) & mask;
    }
    return -1;
}

/* 1 folded, 0 skipped, -1 the accumulator filled. */
/* key is the merge key: the first image folded sets it, and an image under
 * another key is skipped, since its rows name other observables. */
static int prev_merge_fold(
    prev_pub_item_t *acc, uint32_t slots, const char *path, uint32_t now_sec, uint64_t key[2], int *have_key) {
    struct stat st;
    prev_header_t hdr;
    const prev_entry_t *table;
    uint32_t hash_slots = 0;
    uint32_t i;
    void *base;
    int fd;
    int add;

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 || (uint64_t)st.st_size > PREV_MERGE_MAX_BYTES ||
        (size_t)st.st_size < sizeof(hdr)) {
        close(fd);
        return 0;
    }
    base = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) return 0;
    memcpy(&hdr, base, sizeof(hdr));
    if (!prev_epoch_fresh(hdr.epoch, now_sec)) {
        munmap(base, (size_t)st.st_size);
        return 0;
    }
    table = prev_table_map(base, (size_t)st.st_size, &hash_slots);
    if (table == NULL || (*have_key && memcmp(hdr.sip_key, key, sizeof hdr.sip_key) != 0)) {
        munmap(base, (size_t)st.st_size);
        return 0;
    }
    if (!*have_key) {
        key[0] = hdr.sip_key[0];
        key[1] = hdr.sip_key[1];
        *have_key = 1;
    }
    for (i = 0; i < hash_slots; i++) {
        if (table[i].hash_key == 0 || table[i].total_count == 0) continue;
        add = prev_acc_add(acc, slots, table[i].hash_key, table[i].total_count, table[i].source_count);
        if (add < 0) {
            munmap(base, (size_t)st.st_size);
            return -1;
        }
    }
    munmap(base, (size_t)st.st_size);
    return 1;
}

static int prev_merge_push(char paths[][PREV_MERGE_PATH],
                           uint32_t *npaths,
                           uint32_t *entry_sum,
                           const char *path,
                           uint32_t now_sec,
                           const struct stat *skip_ino) {
    struct stat st;
    uint32_t entries = 0;
    uint32_t sum;
    size_t len;

    if (*npaths >= PREV_MERGE_MAX_IMAGES) return 0;
    if (path == NULL) return 0;
    len = strlen(path);
    if (len == 0 || len >= PREV_MERGE_PATH) return 0;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) return 0;
    if (skip_ino != NULL && st.st_dev == skip_ino->st_dev && st.st_ino == skip_ino->st_ino) return 0;
    if (st.st_size <= 0 || (uint64_t)st.st_size > PREV_MERGE_MAX_BYTES) return 0;
    if (!prev_image_fresh(path, now_sec, &entries)) return 0;
    memcpy(paths[*npaths], path, len + 1);
    sum = *entry_sum + entries;
    if (sum < *entry_sum) sum = UINT32_MAX;
    *entry_sum = sum;
    (*npaths)++;
    return 1;
}

static uint32_t prev_merge_collect(char paths[][PREV_MERGE_PATH],
                                   const char *local_path,
                                   const char *peers_dir,
                                   uint32_t now_sec,
                                   uint32_t *entry_sum) {
    struct stat local_st;
    struct dirent *ent;
    DIR *dir;
    uint32_t npaths = 0;
    int have_ino = 0;

    *entry_sum = 0;
    if (prev_merge_push(paths, &npaths, entry_sum, local_path, now_sec, NULL) && lstat(local_path, &local_st) == 0 &&
        S_ISREG(local_st.st_mode))
        have_ino = 1;
    if (peers_dir == NULL || peers_dir[0] == '\0') return npaths;
    dir = opendir(peers_dir);
    if (dir == NULL) return npaths;
    while ((ent = readdir(dir)) != NULL) {
        char full[PREV_MERGE_PATH];
        int wrote;

        if (ent->d_name[0] == '.') continue;
        if (npaths >= PREV_MERGE_MAX_IMAGES) break;
        wrote = snprintf(full, sizeof(full), "%s/%s", peers_dir, ent->d_name);
        if (wrote < 0 || (size_t)wrote >= sizeof(full)) continue;
        (void)prev_merge_push(paths, &npaths, entry_sum, full, now_sec, have_ino ? &local_st : NULL);
    }
    closedir(dir);
    return npaths;
}

int prev_merge_images(
    const char *local_path, const char *peers_dir, const char *out_path, uint32_t now_sec, uint32_t *n_out) {
    char paths[PREV_MERGE_MAX_IMAGES][PREV_MERGE_PATH];
    prev_pub_item_t *acc = NULL;
    prev_pub_item_t *items = NULL;
    uint8_t *image = NULL;
    size_t image_len = 0;
    uint32_t npaths;
    uint32_t entry_sum = 0;
    uint32_t included = 0;
    uint32_t slots;
    uint32_t need;
    uint32_t n = 0;
    uint32_t filled;
    uint32_t i;
    int rc;
    int folded;
    uint64_t key[2] = {0, 0};
    int have_key = 0;

    if (n_out) *n_out = 0;
    if (out_path == NULL || out_path[0] == '\0') return -1;
    if (now_sec == 0) now_sec = (uint32_t)time(NULL);

    npaths = prev_merge_collect(paths, local_path, peers_dir, now_sec, &entry_sum);
    if (npaths == 0) return 0;

    if (entry_sum > (UINT32_MAX / 2u) - 1u) entry_sum = (UINT32_MAX / 2u) - 1u;
    need = entry_sum * 2u + 1u;
    if (need < 8u) need = 8u;
    slots = prev_next_pow2(need);
    if (slots < 8u) slots = 8u;
    if (slots > (1u << 25)) slots = 1u << 25;

    acc = calloc(slots, sizeof(*acc));
    if (acc == NULL) return -1;
    for (i = 0; i < npaths; i++) {
        folded = prev_merge_fold(acc, slots, paths[i], now_sec, key, &have_key);
        if (folded < 0) {
            free(acc);
            return -1;
        }
        if (folded > 0) included++;
    }
    if (included == 0) {
        free(acc);
        return 0;
    }

    for (i = 0; i < slots; i++) {
        if (acc[i].key != 0) n++;
    }
    if (n == 0) {
        free(acc);
        if (prev_image_too_small(out_path, 0)) return 0;
        image = prev_build_image(NULL, 0, now_sec, included, key, &image_len);
        if (image == NULL) return -1;
        rc = prev_commit_image(out_path, image, image_len, 0, n_out);
        free(image);
        return rc;
    }
    items = calloc(n, sizeof(*items));
    if (items == NULL) {
        free(acc);
        return -1;
    }
    filled = 0;
    for (i = 0; i < slots; i++) {
        if (acc[i].key == 0) continue;
        items[filled++] = acc[i];
    }
    free(acc);
    if (filled > PREV_PUBLISH_MAX) {
        qsort(items, filled, sizeof(*items), prev_cmp_item);
        filled = PREV_PUBLISH_MAX;
    }
    if (prev_image_too_small(out_path, filled)) {
        free(items);
        return 0;
    }
    image = prev_build_image(items, filled, now_sec, included, key, &image_len);
    free(items);
    if (image == NULL) return -1;
    rc = prev_commit_image(out_path, image, image_len, filled, n_out);
    free(image);
    return rc;
}
