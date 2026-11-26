/* SPDX-License-Identifier: Apache-2.0 */

/* mmenrich.c
 * This is a message modification module providing line-rate log enrichment.
 * It emits enrichment facts (CTI indicator lookup, GeoIP/ASN geolocation, CTI
 * overlay, ECS-derived fields, IOC mining, structural content flags) as message
 * fields; it makes no detection decision. It requires liblognorm with TurboVM
 * support and has no slow fallback parser.
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

#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

/* Rsyslog Headers */
#include "conf.h"
#include "syslogd-types.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "cfsysline.h"
#include "dirty.h"
#include "statsobj.h"
#include "unicode-helper.h" /* UCHAR_CONSTANT for impstats counter names */
#include "mmenrich_atomic.h"

/* libenrich: the .thrt, overlay and .prev lookups, their policy and reload */
#include "enrich.h"
#include "enrich_json.h"
#include "thrt_miner.h"
#include "thrt_ua.h" /* UA identification table */
#include "thrt_tld.h" /* TLD identification table */

/* Max bytes of a mined IOC value copied into the pattern-mode JSON report. */
#define MMENRICH_IOC_VALUE_MAX 256

/* Turbo result direct access (zero-JSON hot path)
 * mmenrich REQUIRES liblognorm turbo mode - there is no slow fallback.
 * Build with: ./configure --enable-mmnormalize --enable-lognorm-turbo */
#ifndef HAVE_LOGNORM_TURBO
    #error "mmenrich requires liblognorm turbo support. Rebuild liblognorm with turbo enabled."
#endif
#include <lognorm-features.h>
/* Public, opaque Turbo API (liblognorm >= 2.1.0). The internal turbo*.h
 * headers are no longer installed; mmenrich only uses the opaque accessors
 * and snapshot lifecycle, all provided here. */
#include <lognorm-turbo.h>
#include "ecs_derive.h" /* ECS derived-field layer (url.path ...) */
#include "turbo_field.h" /* parsed fields as a template reads $! */
#include "prev_live.h" /* this host's counter file; another process publishes it */
#include "thrt_file_cache.h" /* process-wide inode-keyed MMDB cache */

#include <pthread.h>
#include <stdatomic.h>

/* Integrated GeoIP support (optional, via libmaxminddb) */
#ifdef HAVE_MMENRICH_GEOIP
    #include <maxminddb.h>
#endif

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("mmenrich")

DEF_OMOD_STATIC_DATA
DEFobjCurrIf(statsobj)

    /* impstats: per-stage funnel throughput - events processed by mmenrich (the
     * enrich stage). Lock-free atomic INC per event (same class as the atomic DB
     * load); resettable so an operator sees per-interval EPS. */
    static statsobj_t* mmenrichStats;
STATSCOUNTER_DEF(ctrEvents, mutCtrEvents)
/* cti.hits counts events with at least one confirmed CTI/IOC match (once per
 * event, never per IOC) - the matched leg of the enrich funnel. */
STATSCOUNTER_DEF(ctrCtiHits, mutCtrCtiHits)
/* cti.iocs_dropped counts IOC candidates discarded because a per-message,
 * per-type extraction cap (MAX_CANDIDATES) was hit: non-zero means a message
 * carried more indicators of one type than mmenrich extracted. */
STATSCOUNTER_DEF(ctrIocsDropped, mutCtrIocsDropped)

/* ============================================================================
 * OPERATIONAL MODES
 * ============================================================================ */
typedef enum {
    MODE_PATTERN = 0, /* Feature Extraction: Parse & Extract IOCs from raw text */
    MODE_LOOKUP = 1 /* Key Lookup: Check specific JSON keys (src_ip, dst_ip, etc.) */
} op_mode_t;

/* Grace period for the process-wide MMDB cache: a snapshot retired by the
 * last holder is unmapped only after this many seconds. */
#define THRT_RETIRE_GRACE_S 30

/* ============================================================================
 * KEY-TO-TARGET MAPPING (V4)
 * Maps parsed field keys to output target paths
 * ============================================================================ */
typedef struct {
    uchar* key; /* Source key, e.g., "!parsed!src_ip" */
    uchar* target; /* Target path, e.g., "!cti!source!ip" */
    uchar* turbo_key; /* Turbo key, e.g., "parsed.src_ip" (computed from key at config time) */
} key_mapping_t;

/* ============================================================================
 * INTEGRATED GEOIP (optional, via libmaxminddb)
 * ============================================================================ */
#ifdef HAVE_MMENRICH_GEOIP

    #define MMENRICH_MAX_GEOIP_FIELDS 16 /* Max GeoIP fields to extract per IP */
    #define MMENRICH_MAX_GEOIP_PATH 8 /* Max depth for MMDB path components */

/* GeoIP field specification (parsed at config time, immutable at runtime) */
typedef struct {
    char* display_name; /* JSON key: "continent_en" */
    const char* mmdb_path[MMENRICH_MAX_GEOIP_PATH + 1]; /* NULL-terminated for MMDB_aget_value */
    int path_depth; /* Number of path components */
} geoip_field_spec_t;

/* GeoIP database snapshot (lock-free reload through the MMDB file cache) */
typedef struct geoip_snapshot {
    MMDB_s mmdb;
    sbool is_open;
} geoip_snapshot_t;

/* ============================================================================
 * GeoIP Cache
 *
 * Caches geoip_lookup_ip() results (json_object*) keyed by IP string.
 * GeoIP MMDB traversal + JSON construction is ~100-500us per lookup.
 * In firewall logs, IP locality is extreme (80-95% reuse within minutes).
 * Cache hit avoids MMDB traversal entirely - returns a ref-counted json_object.
 *
 * Design:
 *   - Pre-allocated pool (zero malloc on hot path)
 *   - CLOCK (second-chance) eviction: a rotating hand gives a recently-read
 *     entry one reprieve before evicting it, O(1) amortized with a bounded
 *     O(capacity) worst case (only reachable if every entry was read since
 *     the hand last passed it) - never a mandatory full-pool scan the way a
 *     true LFU-by-scan policy would need on every write once the pool fills.
 *     Degrades to plain FIFO (first probe always evicts) when keys are never
 *     re-read - the one workload where a linear min-usage scan would instead
 *     cost the most.
 *   - pthread_rwlock: readers don't block each other
 *   - Flush on HUP (same as DB reload pattern)
 *   - Config: geoip_cache_size (default: 0 = disabled)
 * ============================================================================ */

    #define GEOIP_CACHE_IP_MAX 42 /* Max IP string length (IPv6 = 39 + scope) */

typedef struct geoip_cache_entry {
    char ip[GEOIP_CACHE_IP_MAX + 1]; /* Key: IP string, null-terminated */
    struct json_object* jGeo; /* Value: cached result (ref-counted) */
    int ref; /* CLOCK reference bit: set on read hit, cleared on eviction sweep */
    struct geoip_cache_entry* next; /* Hash chain */
    struct geoip_cache_entry* prev; /* Hash chain (doubly-linked for O(1) remove) */
} geoip_cache_entry_t;

typedef struct geoip_cache {
    geoip_cache_entry_t* pool; /* Pre-allocated entry pool */
    geoip_cache_entry_t** buckets; /* Hash table (open chaining) */
    size_t capacity; /* Pool size */
    size_t num_buckets; /* Hash table size */
    size_t size; /* Current entries in use */
    size_t pool_next; /* Next free slot in pool (before full) */
    size_t clockHand; /* CLOCK eviction cursor into pool[] */
    pthread_rwlock_t lock; /* RW-lock: readers don't block */
} geoip_cache_t;

/* DJB2 hash for IP strings - simple, fast, good distribution for IPs */
static inline size_t geoip_cache_hash(const char* ip, size_t num_buckets) {
    uint64_t h = 5381;
    for (const char* p = ip; *p; p++) h = 33 * h ^ (unsigned char)*p;
    return h % num_buckets;
}

static geoip_cache_t* geoip_cache_create(size_t capacity) {
    if (capacity < 2) return NULL;

    geoip_cache_t* c = calloc(1, sizeof(geoip_cache_t));
    if (!c) return NULL;

    c->capacity = capacity;
    c->num_buckets = capacity; /* 1:1 ratio - low collision rate */
    c->pool = calloc(capacity, sizeof(geoip_cache_entry_t));
    c->buckets = calloc(c->num_buckets, sizeof(geoip_cache_entry_t*));
    if (!c->pool || !c->buckets) {
        free(c->pool);
        free(c->buckets);
        free(c);
        return NULL;
    }
    pthread_rwlock_init(&c->lock, NULL);
    return c;
}

static void geoip_cache_destroy(geoip_cache_t* c) {
    if (!c) return;
    /* Release all cached json_objects */
    for (size_t i = 0; i < c->capacity; i++) {
        if (c->pool[i].jGeo) {
            json_object_put(c->pool[i].jGeo);
        }
    }
    pthread_rwlock_destroy(&c->lock);
    free(c->pool);
    free(c->buckets);
    free(c);
}

static void geoip_cache_flush(geoip_cache_t* c) {
    if (!c) return;
    pthread_rwlock_wrlock(&c->lock);
    /* Release all cached json_objects */
    for (size_t i = 0; i < c->capacity; i++) {
        if (c->pool[i].jGeo) {
            json_object_put(c->pool[i].jGeo);
        }
    }
    memset(c->pool, 0, c->capacity * sizeof(geoip_cache_entry_t));
    memset(c->buckets, 0, c->num_buckets * sizeof(geoip_cache_entry_t*));
    c->size = 0;
    c->pool_next = 0;
    c->clockHand = 0;
    pthread_rwlock_unlock(&c->lock);
}

/* Read from cache (RD-lock, readers don't block each other).
 * Returns a DEEP COPY of the cached json_object, or NULL on miss.
 * Caller owns the returned object (standard ownership, no shared refs).
 *
 * Deep copy avoids shared-reference hazards: msgAddJSON may merge/replace
 * and eventually json_object_put - sharing the same object between cache
 * and multiple messages would cause use-after-free. Deep copy of a ~5 field
 * GeoIP object costs ~1-2us vs 100-500us for MMDB traversal. */
static struct json_object* geoip_cache_read(geoip_cache_t* c, const char* ip) {
    pthread_rwlock_rdlock(&c->lock);
    size_t h = geoip_cache_hash(ip, c->num_buckets);
    geoip_cache_entry_t* e = c->buckets[h];
    while (e) {
        if (strncmp(ip, e->ip, GEOIP_CACHE_IP_MAX) == 0) {
            /* Hit - set the CLOCK reference bit (gives this entry a second
             * chance at eviction time). Concurrent readers of the same entry
             * can all take this branch under the shared RD-lock, so the
             * store itself must be atomic even though every writer stores
             * the same value 1; relaxed is enough since the evictor only
             * ever reads `ref` while holding the exclusive WR-lock (that
             * lock is the synchronization point, not this store's order). */
            MMENRICH_ATOMIC_STORE(&e->ref, 1, __ATOMIC_RELAXED);
            struct json_object* copy = jsonDeepCopy(e->jGeo);
            pthread_rwlock_unlock(&c->lock);
            return copy;
        }
        e = e->next;
    }
    pthread_rwlock_unlock(&c->lock);
    return NULL;
}

/* Evict one entry via CLOCK (second-chance). Must be called under WR-lock.
 * Returns the pool index of the evicted entry.
 *
 * O(1) amortized: the rotating hand clears one `ref` bit per skipped slot,
 * so the total work across a sequence of calls is bounded by the number of
 * hits that set those bits. Worst case is O(capacity) - reachable only if
 * every entry was read since the hand last passed it, i.e. right after a
 * burst that touched the whole pool - and even then the hand still holds
 * this same write lock for that one call, never more. Degrades to plain
 * FIFO (first probed slot always wins, one comparison) when keys are never
 * re-read: entries whose `ref` is never set cost nothing extra to evict. */
static size_t geoip_cache_evict_clock(geoip_cache_t* c) {
    geoip_cache_entry_t* victim;
    size_t idx;

    for (;;) {
        idx = c->clockHand;
        c->clockHand = (c->clockHand + 1) % c->capacity;
        victim = &c->pool[idx];
        if (victim->ref) {
            victim->ref = 0; /* second chance: skip once, then evictable */
            continue;
        }
        break;
    }

    /* Unlink from hash chain */
    size_t h = geoip_cache_hash(victim->ip, c->num_buckets);

    if (victim->prev)
        victim->prev->next = victim->next;
    else
        c->buckets[h] = victim->next; /* was head of chain */
    if (victim->next) victim->next->prev = victim->prev;

    /* Release cached json_object */
    if (victim->jGeo) {
        json_object_put(victim->jGeo);
        victim->jGeo = NULL;
    }

    victim->ip[0] = '\0';
    victim->ref = 0;
    victim->next = NULL;
    victim->prev = NULL;

    return idx;
}

/* Write to cache (WR-lock).
 * Takes ownership of jGeo refcount - caller should NOT json_object_put() the value passed here.
 * The cache holds one reference; readers get additional references via json_object_get(). */
static void geoip_cache_write(geoip_cache_t* c, const char* ip, struct json_object* jGeo) {
    if (!jGeo) return;

    pthread_rwlock_wrlock(&c->lock);

    /* Check for duplicate (race: another thread may have inserted while we did the lookup) */
    size_t h = geoip_cache_hash(ip, c->num_buckets);
    geoip_cache_entry_t* e = c->buckets[h];
    while (e) {
        if (strncmp(ip, e->ip, GEOIP_CACHE_IP_MAX) == 0) {
            /* Already cached - update value, drop the duplicate */
            json_object_put(e->jGeo);
            e->jGeo = jGeo; /* transfer ownership */
            pthread_rwlock_unlock(&c->lock);
            return;
        }
        e = e->next;
    }

    /* Allocate slot: from pool if not full, else evict via CLOCK */
    size_t idx;
    if (c->size < c->capacity) {
        idx = c->pool_next++;
        c->size++;
    } else {
        idx = geoip_cache_evict_clock(c);
    }

    /* Populate entry */
    geoip_cache_entry_t* slot = &c->pool[idx];
    strncpy(slot->ip, ip, GEOIP_CACHE_IP_MAX);
    slot->ip[GEOIP_CACHE_IP_MAX] = '\0';
    slot->jGeo = jGeo; /* transfer ownership */
    slot->ref = 0; /* fresh insert: no second chance until actually re-read */

    /* Insert at head of hash chain */
    slot->prev = NULL;
    slot->next = c->buckets[h];
    if (c->buckets[h]) c->buckets[h]->prev = slot;
    c->buckets[h] = slot;

    pthread_rwlock_unlock(&c->lock);
}

/* Forward declarations (definitions below, after database management section) */
static void geoip_free_snapshot(geoip_snapshot_t* snap);
static geoip_snapshot_t* geoip_open_snapshot(const char* path);
static void geoip_free_field_specs(geoip_field_spec_t* fields, int count);

#endif /* HAVE_MMENRICH_GEOIP */

/* ============================================================================
 * INSTANCE DATA
 * ============================================================================ */
typedef struct _instanceData {
    /* Config */
    uchar* filePath; /* Path to .thrt database */
    uchar* targetPath; /* JSON key where to inject results (legacy) */
    op_mode_t mode; /* Operational mode */
    int simdEnabled; /* SIMD acceleration flag (default: 1) */
    sbool reloadOnHup; /* Enable database reload on HUP signal (default: 1) */

    /* Key Lookup Mode: Array of JSON keys to check (legacy) */
    uchar** lookupKeys; /* NULL-terminated array of key names */
    int numKeys; /* Number of keys */

    /* V4 Mappings Mode: key->target mappings */
    key_mapping_t* mappings; /* Array of key-to-target mappings */
    int numMappings; /* Number of mappings */

    /* The .thrt, overlay and .prev, opened as one libenrich handle. Each
     * worker reads it through its own reader; enrich_reload() swaps the
     * snapshot without blocking them. */
    enrich_t* enrich;
    uint32_t enrichReloading; /* 1 while one worker runs the periodic reload */

    /* Reload state */
    pthread_mutex_t reloadMutex; /* Serialize GeoIP reload and teardown */

    /* Private IP skip: suppresses CTI/CTI_R output for RFC1918/loopback/ULA IPs.
     * TAGS are always preserved (e.g., a public/private asset classification).
     * GeoIP skip is controlled independently via geoip_skip_private. */
    sbool skipPrivate; /* Skip CTI/CTI_R for private IPs (default: 1, TAGS still emitted) */

    /* GeoIP enrichment (optional) */
#ifdef HAVE_MMENRICH_GEOIP
    uchar* geoipDbPath; /* Path to City .mmdb file (NULL = disabled) */
    geoip_field_spec_t* geoipFields; /* Array of field specs */
    int numGeoipFields; /* Number of field specs */
    uchar* geoipSuffix; /* Mappings mode: suffix for target, e.g. "!geo" */
    sbool geoipSkipPrivate; /* Skip private IPs for GeoIP (default: 1) */
    sbool geoipEnabled; /* true when geoip_db set + opened */
    geoip_snapshot_t* geoipDb; /* Atomic: current snapshot (file-cache handle) */
    time_t geoipDbMtime; /* Last loaded City MMDB mtime - skip re-mmap if unchanged */
    uint32_t geoipCacheSize; /* GeoIP cache capacity (0 = disabled) */
    geoip_cache_t* geoipCache; /* GeoIP result cache (NULL if disabled) */

    /* ASN database (optional, separate MMDB) */
    uchar* geoipAsnDbPath; /* Path to ASN .mmdb file (NULL = disabled) */
    geoip_field_spec_t* geoipAsnFields; /* Array of ASN field specs */
    int numGeoipAsnFields; /* Number of ASN field specs */
    sbool geoipAsnEnabled; /* true when geoip_asn_db set + opened */
    geoip_snapshot_t* geoipAsnDb; /* Atomic: current ASN snapshot (file-cache handle) */
    time_t geoipAsnDbMtime; /* Last loaded ASN MMDB mtime - skip re-mmap if unchanged */
    uint32_t geoipAsnCacheSize; /* ASN GeoIP cache capacity (0 = disabled) */
    geoip_cache_t* geoipAsnCache; /* ASN GeoIP result cache (NULL if disabled) */
#endif

    /* Custom CTI overlay (local IOC additions/whitelists), part of enrich */
    uchar* overlayPath; /* Path to overlay file (NULL = disabled) */

    /* Shellcode MIME pre-filter: file extensions that skip shellcode detection.
     * Built-in: get_file_type()==FILE_TYPE_IGNORE covers images/fonts/CSS/JS.
     * This config adds operator-defined extensions (e.g. ["pdf", "docx"]). */
    char** shellcodeSkipTypes; /* Lowercase extension strings */
    size_t* shellcodeSkipTypesLen; /* Pre-computed lengths */
    int nShellcodeSkipTypes; /* Number of entries */

    /* Prevalence image, part of enrich. The merge renames a new file over
     * this path; HUP and the per-100-message reload pick it up. */
    uchar* prevPath; /* Path to .prev (NULL = disabled) */

    /* UA identification table. Optional. Missing file is a warning. */
    uchar* uaPath;
    ua_table_t* uaTable; /* atomic load in hot path; held in g_uaCache */

    /* TLD identification table. Optional. Missing file is a warning. */
    uchar* tldPath;
    tld_table_t* tldTable; /* atomic load in hot path; held in g_tldCache */
} instanceData;

typedef struct wrkrInstanceData {
    instanceData* pData;
    enrich_reader_t* reader; /* this worker's view of pData->enrich */
    tf_store_t tf; /* field values read for the current message */
} wrkrInstanceData_t;

/* Process-wide table caches. doAction never touches these. A replaced
 * table is freed THRT_RETIRE_GRACE_S after its last holder lets it go,
 * so a worker still classifying against it keeps a valid table. */
static thrt_file_cache_t* g_uaCache = NULL;
static thrt_file_cache_t* g_tldCache = NULL;
#ifdef HAVE_MMENRICH_GEOIP
static thrt_file_cache_t* g_geoipCache = NULL;
static thrt_file_cache_t* g_geoipAsnCache = NULL;
#endif

/* ============================================================================
 * CONFIG PARAMETERS
 * ============================================================================ */
static struct cnfparamdescr actpdescr[] = {
    {"file", eCmdHdlrString, CNFPARAM_REQUIRED},
    {"target", eCmdHdlrString, 0}, /* Legacy: single target path */
    {"mode", eCmdHdlrGetWord, 0},
    {"simd", eCmdHdlrBinary, 0},
    {"keys", eCmdHdlrArray, 0}, /* Array of JSON keys for lookup mode (legacy) */
    {"mappings", eCmdHdlrArray, 0}, /* V4: Array of key:target mappings */
    {"reloadOnHup", eCmdHdlrBinary, 0}, /* Enable hot reload on HUP signal */

    /* Skip private/RFC1918 IPs for CTI and GeoIP lookups */
    {"skip_private", eCmdHdlrBinary, 0},

    /* Shellcode MIME pre-filter (content-fact enrichment) */
    {"shellcode_skip_types", eCmdHdlrArray, 0}, /* ["pdf", "docx", ...] extra skip */

    /* Custom CTI overlay (enrichment) */
    {"overlay_file", eCmdHdlrString, 0}, /* Path to custom CTI overlay (.ovly) */

    /* GeoIP parameters (require libmaxminddb at build time) */
    {"geoip_db", eCmdHdlrString, 0},
    {"geoip_fields", eCmdHdlrArray, 0},
    {"geoip_suffix", eCmdHdlrString, 0},
    {"geoip_skip_private", eCmdHdlrBinary, 0},
    {"geoip_cache_size", eCmdHdlrInt, 0},
    {"geoip_asn_db", eCmdHdlrString, 0},
    {"geoip_asn_fields", eCmdHdlrArray, 0},
    {"geoip_asn_cache_size", eCmdHdlrInt, 0},
    {"prevalence_db", eCmdHdlrString, 0}, /* prevalence .prev (rarity prior) */
    {"ua_file", eCmdHdlrString, 0}, /* UA identification table */
    {"tld_file", eCmdHdlrString, 0}}; /* TLD identification table */

static struct cnfparamblk actpblk = {CNFPARAMBLK_VERSION, sizeof(actpdescr) / sizeof(struct cnfparamdescr), actpdescr};

/* Module parameters. prevalence_live_file names the shared counter file
 * that every action of this process writes. Unset, nothing is counted.
 * prevalence_key_file holds the tenant key the counters hash with, the
 * same file the publisher of the image reads. Unset, the counter file
 * keeps its own random key. Set and refused, nothing is counted. */
static struct cnfparamdescr modpdescr[] = {{"prevalence_live_file", eCmdHdlrString, 0},
                                           {"prevalence_key_file", eCmdHdlrString, 0}};
static struct cnfparamblk modpblk = {CNFPARAMBLK_VERSION, sizeof(modpdescr) / sizeof(struct cnfparamdescr), modpdescr};

struct modConfData_s {
    rsconf_t* pConf;
    char* prevLivePath;
    char* prevKeyPath;
};
static modConfData_t* loadModConf = NULL;
static modConfData_t* runModConf = NULL;

/* Set once in activateCnf, before any worker runs; read-only afterwards. */
static char* g_prevLivePath;
static uint64_t g_prevKey[2];
static int g_prevKeySet;

/* ============================================================================
 * LIFECYCLE BOILERPLATE
 * ============================================================================ */
BEGINcreateInstance
    CODESTARTcreateInstance;
    pData->filePath = NULL;
    pData->targetPath = NULL;
    pData->mode = MODE_PATTERN; /* Default mode */
    pData->simdEnabled = 1; /* SIMD enabled by default */
    pData->reloadOnHup = 1; /* Hot reload enabled by default */
    pData->lookupKeys = NULL;
    pData->numKeys = 0;
    pData->mappings = NULL;
    pData->numMappings = 0;
    pData->enrich = NULL;
    pData->enrichReloading = 0;
    pthread_mutex_init(&pData->reloadMutex, NULL);
    pData->skipPrivate = 1; /* Skip private IPs by default */
    pData->overlayPath = NULL;
    pData->geoipDbMtime = 0;
    pData->geoipAsnDbMtime = 0;
    pData->shellcodeSkipTypes = NULL;
    pData->shellcodeSkipTypesLen = NULL;
    pData->nShellcodeSkipTypes = 0;
    pData->prevPath = NULL;
    pData->uaPath = NULL;
    pData->uaTable = NULL;
    pData->tldPath = NULL;
    pData->tldTable = NULL;
#ifdef HAVE_MMENRICH_GEOIP
    pData->geoipDbPath = NULL;
    pData->geoipFields = NULL;
    pData->numGeoipFields = 0;
    pData->geoipSuffix = NULL;
    pData->geoipSkipPrivate = 1; /* Skip private IPs by default */
    pData->geoipEnabled = 0;
    pData->geoipDb = NULL;
    pData->geoipCacheSize = 0; /* GeoIP cache disabled by default */
    pData->geoipCache = NULL;
    pData->geoipAsnDbPath = NULL;
    pData->geoipAsnFields = NULL;
    pData->numGeoipAsnFields = 0;
    pData->geoipAsnEnabled = 0;
    pData->geoipAsnDb = NULL;
    pData->geoipAsnCacheSize = 0;
    pData->geoipAsnCache = NULL;
#endif
ENDcreateInstance

BEGINcreateWrkrInstance
    CODESTARTcreateWrkrInstance;
    pWrkrData->reader = NULL;
    if (tf_store_init(&pWrkrData->tf) != 0) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    if (pWrkrData->pData->enrich != NULL) {
        pWrkrData->reader = enrich_reader_new(pWrkrData->pData->enrich);
        if (pWrkrData->reader == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
finalize_it:
ENDcreateWrkrInstance

static void thrt_caches_ensure(void);

BEGINfreeInstance
    CODESTARTfreeInstance;
    /* Hold reloadMutex across teardown: it also serialises the GeoIP pointer
     * swaps, so a shutdown racing an in-flight HUP reload cannot double-free
     * a deferred old snapshot. Workers, and their readers, are gone by now. */
    pthread_mutex_lock(&pData->reloadMutex);
    enrich_close(pData->enrich);
    pData->enrich = NULL;

    free(pData->filePath);
    free(pData->targetPath);

    /* Free lookup keys array */
    if (pData->lookupKeys) {
        for (int i = 0; i < pData->numKeys; i++) {
            free(pData->lookupKeys[i]);
        }
        free(pData->lookupKeys);
    }

    /* Free V4 mappings */
    if (pData->mappings) {
        for (int i = 0; i < pData->numMappings; i++) {
            free(pData->mappings[i].key);
            free(pData->mappings[i].target);
            free(pData->mappings[i].turbo_key);
        }
        free(pData->mappings);
    }

    if (pData->shellcodeSkipTypes) {
        for (int i = 0; i < pData->nShellcodeSkipTypes; i++) free(pData->shellcodeSkipTypes[i]);
        free(pData->shellcodeSkipTypes);
        free(pData->shellcodeSkipTypesLen);
    }

    free(pData->overlayPath);
    free(pData->prevPath);
    if (pData->uaTable) thrt_file_cache_release(g_uaCache, pData->uaTable);
    pData->uaTable = NULL;
    free(pData->uaPath);
    if (pData->tldTable) thrt_file_cache_release(g_tldCache, pData->tldTable);
    pData->tldTable = NULL;
    free(pData->tldPath);

    /* Free GeoIP resources (MMDB payloads live in the file cache). */
#ifdef HAVE_MMENRICH_GEOIP
    if (pData->geoipDb) {
        thrt_file_cache_release(g_geoipCache, pData->geoipDb);
        pData->geoipDb = NULL;
    }
    if (pData->geoipAsnDb) {
        thrt_file_cache_release(g_geoipAsnCache, pData->geoipAsnDb);
        pData->geoipAsnDb = NULL;
    }
    geoip_free_field_specs(pData->geoipFields, pData->numGeoipFields);
    geoip_free_field_specs(pData->geoipAsnFields, pData->numGeoipAsnFields);
    geoip_cache_destroy(pData->geoipCache);
    geoip_cache_destroy(pData->geoipAsnCache);
    free(pData->geoipDbPath);
    free(pData->geoipAsnDbPath);
    free(pData->geoipSuffix);
#endif
    pthread_mutex_unlock(&pData->reloadMutex);
    pthread_mutex_destroy(&pData->reloadMutex);
ENDfreeInstance

BEGINfreeWrkrInstance
    CODESTARTfreeWrkrInstance;
    enrich_reader_free(pWrkrData->reader);
    pWrkrData->reader = NULL;
    tf_store_free(&pWrkrData->tf);
ENDfreeWrkrInstance

BEGINdbgPrintInstInfo
    CODESTARTdbgPrintInstInfo;
    dbgprintf("mmenrich\n");
    dbgprintf("\tfile='%s'\n", pData->filePath);
    dbgprintf("\ttarget='%s'\n", pData->targetPath);
    dbgprintf("\tmode=%s\n", pData->mode == MODE_PATTERN ? "pattern" : "lookup");
    dbgprintf("\tsimd=%s\n", pData->simdEnabled ? "enabled" : "disabled");
    dbgprintf("\treloadOnHup=%s\n", pData->reloadOnHup ? "enabled" : "disabled");
    dbgprintf("\tskipPrivate=%s\n", pData->skipPrivate ? "enabled" : "disabled");
    if (pData->uaPath)
        dbgprintf("\tuaPath='%s' exact=%u contains=%u prefixes=%u suffixes=%u\n", pData->uaPath,
                  pData->uaTable ? pData->uaTable->n : 0, pData->uaTable ? pData->uaTable->n_contains : 0,
                  pData->uaTable ? pData->uaTable->n_prefixes : 0, pData->uaTable ? pData->uaTable->n_suffixes : 0);
    if (pData->tldPath)
        dbgprintf("\ttldPath='%s' entries=%u\n", pData->tldPath, pData->tldTable ? pData->tldTable->n : 0);
#ifdef HAVE_MMENRICH_GEOIP
    dbgprintf("\tgeoipEnabled=%s\n", pData->geoipEnabled ? "yes" : "no");
    if (pData->geoipDbPath) dbgprintf("\tgeoipDbPath='%s'\n", pData->geoipDbPath);
    if (pData->geoipSuffix) dbgprintf("\tgeoipSuffix='%s'\n", pData->geoipSuffix);
    dbgprintf("\tgeoipFields=%d\n", pData->numGeoipFields);
    dbgprintf("\tgeoipCacheSize=%u\n", pData->geoipCacheSize);
#endif
    if (pData->mode == MODE_LOOKUP && pData->lookupKeys) {
        dbgprintf("\tkeys=[");
        for (int i = 0; i < pData->numKeys; i++) {
            dbgprintf("%s%s", pData->lookupKeys[i], i < pData->numKeys - 1 ? ", " : "");
        }
        dbgprintf("]\n");
    }
ENDdbgPrintInstInfo

BEGINtryResume
    CODESTARTtryResume;
    /* MMAP persists, nothing to do */
ENDtryResume

BEGINisCompatibleWithFeature
    CODESTARTisCompatibleWithFeature;
    if (eFeat == sFEATURERepeatedMsgReduction) iRet = RS_RET_OK;
ENDisCompatibleWithFeature

/* ============================================================================
 * MMDB FILE CACHE
 * ============================================================================ */

#ifdef HAVE_MMENRICH_GEOIP
static void* geoip_cache_load(const char* path) {
    return geoip_open_snapshot(path);
}

static void geoip_cache_free_payload(void* payload) {
    geoip_free_snapshot((geoip_snapshot_t*)payload);
}
#endif

static void* ua_cache_load(const char* path) {
    return ua_table_load(path);
}

static void ua_cache_free_payload(void* payload) {
    ua_table_free((ua_table_t*)payload);
}

static void* tld_cache_load(const char* path) {
    return tld_table_load(path);
}

static void tld_cache_free_payload(void* payload) {
    tld_table_free((tld_table_t*)payload);
}

static void thrt_caches_ensure(void) {
    if (g_uaCache == NULL)
        g_uaCache = thrt_file_cache_create(ua_cache_load, ua_cache_free_payload, THRT_RETIRE_GRACE_S, NULL);
    if (g_tldCache == NULL)
        g_tldCache = thrt_file_cache_create(tld_cache_load, tld_cache_free_payload, THRT_RETIRE_GRACE_S, NULL);
#ifdef HAVE_MMENRICH_GEOIP
    if (g_geoipCache == NULL)
        g_geoipCache = thrt_file_cache_create(geoip_cache_load, geoip_cache_free_payload, THRT_RETIRE_GRACE_S, NULL);
    if (g_geoipAsnCache == NULL)
        g_geoipAsnCache = thrt_file_cache_create(geoip_cache_load, geoip_cache_free_payload, THRT_RETIRE_GRACE_S, NULL);
#endif
}

static void thrt_caches_destroy(void) {
    thrt_file_cache_destroy(g_uaCache);
    g_uaCache = NULL;
    thrt_file_cache_destroy(g_tldCache);
    g_tldCache = NULL;
#ifdef HAVE_MMENRICH_GEOIP
    thrt_file_cache_destroy(g_geoipCache);
    g_geoipCache = NULL;
    thrt_file_cache_destroy(g_geoipAsnCache);
    g_geoipAsnCache = NULL;
#endif
}

/* ============================================================================
 * INTEGRATED GEOIP - MMDB LIFECYCLE & LOOKUP
 * ============================================================================ */
#ifdef HAVE_MMENRICH_GEOIP

/* Parse geoip_fields config array.
 * Format: ["display_name:mmdb!path!components", ...]
 * Example: ["city_name:city!names!en", "country_iso_code:country!iso_code"]
 *
 * The display_name becomes the JSON key in the output.
 * The mmdb!path!components are split on '!' to form the MMDB_aget_value path.
 */
static rsRetVal geoip_parse_field_specs(struct cnfarray* arr, geoip_field_spec_t** ppFields, int* pnFields) {
    DEFiRet;

    int n = arr->nmemb;
    if (n > MMENRICH_MAX_GEOIP_FIELDS) n = MMENRICH_MAX_GEOIP_FIELDS;

    geoip_field_spec_t* fields = calloc(n, sizeof(geoip_field_spec_t));
    if (!fields) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);

    int valid = 0;
    for (int i = 0; i < n; i++) {
        char* spec = es_str2cstr(arr->arr[i], NULL);
        if (!spec) continue;

        /* Split on first ':' - display_name:mmdb_path */
        char* colon = strchr(spec, ':');
        if (!colon) {
            LogError(0, RS_RET_CONFIG_ERROR,
                     "mmenrich/geoip: invalid field spec '%s' (expected display_name:mmdb!path)", spec);
            free(spec);
            continue;
        }
        *colon = '\0';
        const char* display = spec;
        const char* path_str = colon + 1;

        geoip_field_spec_t* f = &fields[valid];
        f->display_name = strdup(display);

        /* Split mmdb path on '!' into components */
        /* "city!names!en" -> ["city", "names", "en", NULL] */
        char* path_copy = strdup(path_str);
        if (!path_copy) {
            free(spec);
            continue;
        }

        int depth = 0;
        char* saveptr = NULL;
        char* tok = strtok_r(path_copy, "!", &saveptr);
        while (tok && depth < MMENRICH_MAX_GEOIP_PATH) {
            f->mmdb_path[depth] = strdup(tok);
            depth++;
            tok = strtok_r(NULL, "!", &saveptr);
        }
        f->mmdb_path[depth] = NULL; /* NULL-terminate for MMDB_aget_value */
        f->path_depth = depth;
        free(path_copy);
        free(spec);

        DBGPRINTF("mmenrich/geoip: field[%d] display='%s' path_depth=%d\n", valid, f->display_name, depth);
        valid++;
    }

    *ppFields = fields;
    *pnFields = valid;

finalize_it:
    RETiRet;
}

/* Free GeoIP field specs */
/* English country name for the city database. Skip when the operator already
 * listed country_name, or when the field list is already full. The ASN
 * database does not use this helper. */
static void geoip_ensure_country_name(geoip_field_spec_t** ppFields, int* pnFields) {
    geoip_field_spec_t* grown;
    geoip_field_spec_t* field;
    int i;
    if (ppFields == NULL || *ppFields == NULL || pnFields == NULL) return;
    if (*pnFields <= 0 || *pnFields >= MMENRICH_MAX_GEOIP_FIELDS) return;
    for (i = 0; i < *pnFields; i++) {
        if ((*ppFields)[i].display_name != NULL && strcmp((*ppFields)[i].display_name, "country_name") == 0) return;
    }
    grown = realloc(*ppFields, (size_t)(*pnFields + 1) * sizeof(*grown));
    if (grown == NULL) return;
    *ppFields = grown;
    field = &grown[*pnFields];
    memset(field, 0, sizeof(*field));
    field->display_name = strdup("country_name");
    field->mmdb_path[0] = strdup("country");
    field->mmdb_path[1] = strdup("names");
    field->mmdb_path[2] = strdup("en");
    field->mmdb_path[3] = NULL;
    field->path_depth = 3;
    if (field->display_name == NULL || field->mmdb_path[0] == NULL || field->mmdb_path[1] == NULL ||
        field->mmdb_path[2] == NULL) {
        free(field->display_name);
        free((void*)field->mmdb_path[0]);
        free((void*)field->mmdb_path[1]);
        free((void*)field->mmdb_path[2]);
        memset(field, 0, sizeof(*field));
        return;
    }
    *pnFields += 1;
}

static void geoip_free_field_specs(geoip_field_spec_t* fields, int count) {
    if (!fields) return;
    for (int i = 0; i < count; i++) {
        free(fields[i].display_name);
        for (int j = 0; j < fields[i].path_depth; j++) {
            free((void*)fields[i].mmdb_path[j]);
        }
    }
    free(fields);
}

/* Open a GeoIP MMDB database, returning a new snapshot */
static geoip_snapshot_t* geoip_open_snapshot(const char* path) {
    geoip_snapshot_t* snap = calloc(1, sizeof(geoip_snapshot_t));
    if (!snap) {
        LogError(0, RS_RET_OUT_OF_MEMORY, "mmenrich/geoip: failed to allocate snapshot");
        return NULL;
    }
    snap->is_open = 0;

    int status = MMDB_open(path, MMDB_MODE_MMAP, &snap->mmdb);
    if (MMDB_SUCCESS != status) {
        LogError(0, RS_RET_ERR, "mmenrich/geoip: cannot open MMDB %s - %s", path, MMDB_strerror(status));
        if (MMDB_IO_ERROR == status) LogError(0, errno, "mmenrich/geoip: IO error detail");
        free(snap);
        return NULL;
    }
    snap->is_open = 1;
    return snap;
}

/* Close and free a GeoIP snapshot */
static void geoip_free_snapshot(geoip_snapshot_t* snap) {
    if (!snap) return;
    if (snap->is_open) {
        MMDB_close(&snap->mmdb);
        snap->is_open = 0;
    }
    free(snap);
}

/* GeoIP lookup for a single IP.
 * Uses MMDB_lookup_sockaddr to avoid redundant getaddrinfo - we already have
 * the parsed binary IP from inet_pton in the hot path.
 *
 * Returns a json_object with the requested fields, or NULL if no entry found.
 * Example output: {"city_name":"Paris","country_iso_code":"FR","location":{"latitude":48.8566,"longitude":2.3522}}
 */
static struct json_object* geoip_lookup_ip(const geoip_snapshot_t* snap,
                                           int af, /* AF_INET or AF_INET6 */
                                           const void* addr, /* struct in_addr* or struct in6_addr* */
                                           const geoip_field_spec_t* fields,
                                           int num_fields) {
    if (!snap || !snap->is_open || !addr || num_fields == 0) return NULL;

    /* Build sockaddr for MMDB_lookup_sockaddr (no getaddrinfo overhead) */
    union {
        struct sockaddr sa;
        struct sockaddr_in sa4;
        struct sockaddr_in6 sa6;
    } sa;
    memset(&sa, 0, sizeof(sa));

    if (af == AF_INET) {
        sa.sa4.sin_family = AF_INET;
        memcpy(&sa.sa4.sin_addr, addr, sizeof(struct in_addr));
    #ifdef __FreeBSD__
        sa.sa4.sin_len = sizeof(struct sockaddr_in);
    #endif
    } else {
        sa.sa6.sin6_family = AF_INET6;
        memcpy(&sa.sa6.sin6_addr, addr, sizeof(struct in6_addr));
    #ifdef __FreeBSD__
        sa.sa6.sin6_len = sizeof(struct sockaddr_in6);
    #endif
    }

    int mmdb_err = 0;
    MMDB_lookup_result_s result = MMDB_lookup_sockaddr((MMDB_s*)&snap->mmdb, &sa.sa, &mmdb_err);

    if (MMDB_SUCCESS != mmdb_err) {
        DBGPRINTF("mmenrich/geoip: lookup error - %s\n", MMDB_strerror(mmdb_err));
        return NULL;
    }
    if (!result.found_entry) return NULL;

    /* Extract requested fields */
    struct json_object* jGeo = NULL;

    for (int i = 0; i < num_fields; i++) {
        const geoip_field_spec_t* f = &fields[i];
        MMDB_entry_data_s entry_data;

        int status = MMDB_aget_value(&result.entry, &entry_data, f->mmdb_path);
        if (MMDB_SUCCESS != status || !entry_data.has_data) continue;

        struct json_object* jVal = NULL;

        switch (entry_data.type) {
            case MMDB_DATA_TYPE_UTF8_STRING:
                jVal = json_object_new_string_len(entry_data.utf8_string, entry_data.data_size);
                break;
            case MMDB_DATA_TYPE_UINT16:
                jVal = json_object_new_int(entry_data.uint16);
                break;
            case MMDB_DATA_TYPE_UINT32:
                jVal = json_object_new_int64(entry_data.uint32);
                break;
            case MMDB_DATA_TYPE_INT32:
                jVal = json_object_new_int(entry_data.int32);
                break;
            case MMDB_DATA_TYPE_DOUBLE:
                jVal = json_object_new_double(entry_data.double_value);
                break;
            case MMDB_DATA_TYPE_FLOAT:
                jVal = json_object_new_double(entry_data.float_value);
                break;
            case MMDB_DATA_TYPE_BOOLEAN:
                jVal = json_object_new_boolean(entry_data.boolean);
                break;
            case MMDB_DATA_TYPE_MAP: {
                /* For map types (e.g., "location"), dump the entire subtree:
                 * {"latitude":48.85,"longitude":2.35,"accuracy_radius":20}
                 * without requiring the operator to list each sub-field.
                 *
                 * entry_data (from the aget_value call above, same
                 * &result.entry + f->mmdb_path) already resolved this exact
                 * map node - has_data is true or we would not be in this
                 * switch - so its offset seeds the walk directly; no second
                 * aget_value call needed to re-derive the same thing. */
                MMDB_entry_s map_entry = result.entry;
                map_entry.offset = entry_data.offset;
                MMDB_entry_data_list_s* map_list = NULL;
                status = MMDB_get_entry_data_list(&map_entry, &map_list);
                if (map_list != NULL) {
                    if (MMDB_SUCCESS == status) {
                        /* Parse the map: {key:val, key:val, ...} */
                        jVal = json_object_new_object();
                        /* map_list points to the MAP node itself, skip it */
                        uint32_t map_size = map_list->entry_data.data_size;
                        MMDB_entry_data_list_s* cur = map_list->next;
                        for (uint32_t m = 0; m < map_size && cur; m++) {
                            /* Key (must be UTF8_STRING) */
                            if (cur->entry_data.type != MMDB_DATA_TYPE_UTF8_STRING) break;
                            char key_buf[128];
                            size_t klen = cur->entry_data.data_size;
                            if (klen >= sizeof(key_buf)) klen = sizeof(key_buf) - 1;
                            memcpy(key_buf, cur->entry_data.utf8_string, klen);
                            key_buf[klen] = '\0';
                            cur = cur->next;
                            if (!cur) break;

                            /* Value */
                            struct json_object* mVal = NULL;
                            switch (cur->entry_data.type) {
                                case MMDB_DATA_TYPE_DOUBLE:
                                    mVal = json_object_new_double(cur->entry_data.double_value);
                                    break;
                                case MMDB_DATA_TYPE_FLOAT:
                                    mVal = json_object_new_double(cur->entry_data.float_value);
                                    break;
                                case MMDB_DATA_TYPE_UINT16:
                                    mVal = json_object_new_int(cur->entry_data.uint16);
                                    break;
                                case MMDB_DATA_TYPE_UINT32:
                                    mVal = json_object_new_int64(cur->entry_data.uint32);
                                    break;
                                case MMDB_DATA_TYPE_INT32:
                                    mVal = json_object_new_int(cur->entry_data.int32);
                                    break;
                                case MMDB_DATA_TYPE_UTF8_STRING:
                                    mVal = json_object_new_string_len(cur->entry_data.utf8_string,
                                                                      cur->entry_data.data_size);
                                    break;
                                case MMDB_DATA_TYPE_BOOLEAN:
                                    mVal = json_object_new_boolean(cur->entry_data.boolean);
                                    break;
                                default:
                                    break;
                            }
                            if (mVal) json_object_object_add(jVal, key_buf, mVal);
                            cur = cur->next;
                        }
                    }
                    /* Free unconditionally: MMDB_get_entry_data_list() can
                     * allocate part of the list before reporting a non-SUCCESS
                     * status (e.g. on truncated/corrupt map data); freeing a
                     * NULL list is a documented no-op, so there is no reason
                     * to gate this on `status` and leak on the error path. */
                    MMDB_free_entry_data_list(map_list);
                }
                break;
            }
            default:
                DBGPRINTF("mmenrich/geoip: unsupported MMDB type %d for field '%s'\n", entry_data.type,
                          f->display_name);
                break;
        }

        if (jVal) {
            if (!jGeo) jGeo = json_object_new_object();
            json_object_object_add(jGeo, f->display_name, jVal);
        }
    }

    return jGeo;
}

/* Reload GeoIP database atomically (same pattern as threat DB reload) */
static rsRetVal reloadGeoipDatabase(instanceData* pData) {
    DEFiRet;

    if (!pData->geoipDbPath || !pData->geoipEnabled) FINALIZE;

    pthread_mutex_lock(&pData->reloadMutex); /* Reuse same mutex */

    geoip_snapshot_t* oldSnap = MMENRICH_ATOMIC_LOAD(&pData->geoipDb, __ATOMIC_ACQUIRE);
    thrt_caches_ensure();
    geoip_snapshot_t* newSnap = thrt_file_cache_refresh(g_geoipCache, (char*)pData->geoipDbPath, oldSnap);
    if (newSnap == oldSnap) {
        pthread_mutex_unlock(&pData->reloadMutex);
        FINALIZE;
    }
    if (newSnap == NULL) {
        LogError(0, RS_RET_ERR, "mmenrich/geoip: reload FAILED - keeping old MMDB");
        pthread_mutex_unlock(&pData->reloadMutex);
        ABORT_FINALIZE(RS_RET_ERR);
    }

    LogMsg(0, RS_RET_OK, LOG_INFO, "mmenrich/geoip: reloading %s", pData->geoipDbPath);

    MMENRICH_ATOMIC_STORE(&pData->geoipDb, newSnap, __ATOMIC_RELEASE);
    MMENRICH_ATOMIC_FENCE(__ATOMIC_SEQ_CST);
    geoip_cache_flush(pData->geoipCache);

    pthread_mutex_unlock(&pData->reloadMutex);

    LogMsg(0, RS_RET_OK, LOG_INFO, "mmenrich/geoip: MMDB reloaded successfully (cache flushed)");

finalize_it:
    RETiRet;
}

/* Reload ASN GeoIP database atomically */
static rsRetVal reloadGeoipAsnDatabase(instanceData* pData) {
    DEFiRet;

    if (!pData->geoipAsnDbPath || !pData->geoipAsnEnabled) FINALIZE;

    pthread_mutex_lock(&pData->reloadMutex);

    geoip_snapshot_t* oldSnap = MMENRICH_ATOMIC_LOAD(&pData->geoipAsnDb, __ATOMIC_ACQUIRE);
    thrt_caches_ensure();
    geoip_snapshot_t* newSnap = thrt_file_cache_refresh(g_geoipAsnCache, (char*)pData->geoipAsnDbPath, oldSnap);
    if (newSnap == oldSnap) {
        pthread_mutex_unlock(&pData->reloadMutex);
        FINALIZE;
    }
    if (newSnap == NULL) {
        LogError(0, RS_RET_ERR, "mmenrich/geoip-asn: reload FAILED - keeping old ASN MMDB");
        pthread_mutex_unlock(&pData->reloadMutex);
        ABORT_FINALIZE(RS_RET_ERR);
    }

    LogMsg(0, RS_RET_OK, LOG_INFO, "mmenrich/geoip-asn: reloading %s", pData->geoipAsnDbPath);

    MMENRICH_ATOMIC_STORE(&pData->geoipAsnDb, newSnap, __ATOMIC_RELEASE);
    MMENRICH_ATOMIC_FENCE(__ATOMIC_SEQ_CST);

    geoip_cache_flush(pData->geoipAsnCache);

    pthread_mutex_unlock(&pData->reloadMutex);

    LogMsg(0, RS_RET_OK, LOG_INFO, "mmenrich/geoip-asn: ASN MMDB reloaded successfully (cache flushed)");

finalize_it:
    RETiRet;
}

#endif /* HAVE_MMENRICH_GEOIP */

/* ============================================================================
 * HOT RELOAD
 * ============================================================================ */

/* ============================================================================
 * INITIALIZATION
 * ============================================================================ */
BEGINnewActInst
    struct cnfparamvals* pvals = NULL;
    int i;
    CODESTARTnewActInst;
    DBGPRINTF("mmenrich: newActInst\n");

    if ((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }

    CHKiRet(createInstance(&pData));

    /* Parse parameters */
    for (i = 0; i < actpblk.nParams; ++i) {
        if (!pvals[i].bUsed) continue;

        if (!strcmp(actpblk.descr[i].name, "file")) {
            pData->filePath = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);

        } else if (!strcmp(actpblk.descr[i].name, "target")) {
            pData->targetPath = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);

            /* Validate target path format
             * Must be: $X... where X is !, ., or /
             * Examples: $.threat_intel, $!threat, $/global
             */
            if (pData->targetPath == NULL || strlen((char*)pData->targetPath) < 2) {
                LogError(0, RS_RET_CONFIG_ERROR, "mmenrich: target parameter is empty or too short");
                ABORT_FINALIZE(RS_RET_CONFIG_ERROR);
            }

            if (pData->targetPath[0] != '$') {
                LogError(0, RS_RET_CONFIG_ERROR,
                         "mmenrich: target '%s' must start with $ (e.g., '$.threat_intel' or '$!threat_intel')",
                         pData->targetPath);
                ABORT_FINALIZE(RS_RET_CONFIG_ERROR);
            }

            if (pData->targetPath[1] != '!' && pData->targetPath[1] != '.' && pData->targetPath[1] != '/') {
                LogError(0, RS_RET_CONFIG_ERROR,
                         "mmenrich: target '%s' second character must be !, ., or / (e.g., '$!threat_intel' or "
                         "'$.threat_intel')",
                         pData->targetPath);
                ABORT_FINALIZE(RS_RET_CONFIG_ERROR);
            }
        } else if (!strcmp(actpblk.descr[i].name, "mode")) {
            char* modeStr = es_str2cstr(pvals[i].val.d.estr, NULL);
            if (!strcasecmp(modeStr, "pattern")) {
                pData->mode = MODE_PATTERN;
            } else if (!strcasecmp(modeStr, "lookup")) {
                pData->mode = MODE_LOOKUP;
            } else {
                LogError(0, RS_RET_ERR, "mmenrich: Invalid mode '%s' (must be 'pattern' or 'lookup')", modeStr);
                free(modeStr);
                ABORT_FINALIZE(RS_RET_ERR);
            }
            free(modeStr);

        } else if (!strcmp(actpblk.descr[i].name, "simd")) {
            pData->simdEnabled = pvals[i].val.d.n;

        } else if (!strcmp(actpblk.descr[i].name, "keys")) {
            /* Parse array of keys for lookup mode */
            struct cnfarray* arr = pvals[i].val.d.ar;
            pData->numKeys = arr->nmemb;
            pData->lookupKeys = calloc(pData->numKeys + 1, sizeof(uchar*));
            if (!pData->lookupKeys) {
                ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            }
            for (int j = 0; j < pData->numKeys; j++) {
                pData->lookupKeys[j] = (uchar*)es_str2cstr(arr->arr[j], NULL);
            }
            pData->lookupKeys[pData->numKeys] = NULL;

        } else if (!strcmp(actpblk.descr[i].name, "mappings")) {
            /* Parse array of key:target mappings for V4 mode
             * Format: ["!parsed!src_ip:!cti!source!ip", "!parsed!dst_ip:!cti!destination!ip"]
             */
            struct cnfarray* arr = pvals[i].val.d.ar;
            pData->numMappings = arr->nmemb;
            pData->mappings = calloc(pData->numMappings, sizeof(key_mapping_t));
            if (!pData->mappings) {
                ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            }
            for (int j = 0; j < pData->numMappings; j++) {
                char* mappingStr = es_str2cstr(arr->arr[j], NULL);
                if (!mappingStr) continue;

                /* Split on ':' */
                char* colon = strchr(mappingStr, ':');
                if (!colon) {
                    LogError(0, RS_RET_CONFIG_ERROR, "mmenrich: invalid mapping format '%s' (expected key:target)",
                             mappingStr);
                    free(mappingStr);
                    continue;
                }

                *colon = '\0';
                pData->mappings[j].key = (uchar*)strdup(mappingStr);
                pData->mappings[j].target = (uchar*)strdup(colon + 1);

                /* Compute turbo_key: convert "!parsed!src_ip" -> "parsed.src_ip"
                 * for the dotted field read (tf_get) in the hot path.
                 * Strip leading '!' then replace remaining '!' with '.' */
                {
                    const char* src = mappingStr;
                    if (src[0] == '!') src++; /* skip leading separator */
                    char* tk = strdup(src);
                    if (tk) {
                        for (char* p = tk; *p; p++) {
                            if (*p == '!') *p = '.';
                        }
                    }
                    pData->mappings[j].turbo_key = (uchar*)tk;
                }

                DBGPRINTF("mmenrich: mapping[%d] key='%s' target='%s' turbo_key='%s'\n", j, pData->mappings[j].key,
                          pData->mappings[j].target,
                          pData->mappings[j].turbo_key ? (char*)pData->mappings[j].turbo_key : "(null)");

                free(mappingStr);
            }
            /* Set mode to lookup when using mappings */
            pData->mode = MODE_LOOKUP;

        } else if (!strcmp(actpblk.descr[i].name, "shellcode_skip_types")) {
            /* Parse shellcode_skip_types=["pdf", "docx", ...] array.
             * Extensions in this list skip is_escaped_payload() shellcode detection
             * when the URL (url.original) matches. Supplements the built-in
             * FILE_TYPE_IGNORE list (images, fonts, CSS, JS). */
            struct cnfarray* arr = pvals[i].val.d.ar;
            int n = arr->nmemb;
            if (n <= 0) continue;
            pData->shellcodeSkipTypes = calloc(n, sizeof(char*));
            pData->shellcodeSkipTypesLen = calloc(n, sizeof(size_t));
            if (pData->shellcodeSkipTypes == NULL || pData->shellcodeSkipTypesLen == NULL) {
                free(pData->shellcodeSkipTypes);
                free(pData->shellcodeSkipTypesLen);
                pData->shellcodeSkipTypes = NULL;
                pData->shellcodeSkipTypesLen = NULL;
                ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            }
            /* The count is set first so the destructor frees every entry,
             * including a partial list after a failed es_str2cstr. */
            pData->nShellcodeSkipTypes = n;
            for (int j = 0; j < n; j++) {
                pData->shellcodeSkipTypes[j] = es_str2cstr(arr->arr[j], NULL);
                if (pData->shellcodeSkipTypes[j] == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
                /* Lowercase at config time - hot path compares pre-lowered */
                size_t slen = strlen(pData->shellcodeSkipTypes[j]);
                for (size_t k = 0; k < slen; k++)
                    pData->shellcodeSkipTypes[j][k] = (char)tolower((unsigned char)pData->shellcodeSkipTypes[j][k]);
                pData->shellcodeSkipTypesLen[j] = slen;
            }
            DBGPRINTF("mmenrich: shellcode_skip_types: %d entries\n", n);

        } else if (!strcmp(actpblk.descr[i].name, "overlay_file")) {
            pData->overlayPath = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);

        } else if (!strcmp(actpblk.descr[i].name, "ua_file")) {
            pData->uaPath = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);

        } else if (!strcmp(actpblk.descr[i].name, "tld_file")) {
            pData->tldPath = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);

        } else if (!strcmp(actpblk.descr[i].name, "reloadOnHup")) {
            pData->reloadOnHup = pvals[i].val.d.n;

        } else if (!strcmp(actpblk.descr[i].name, "skip_private")) {
            pData->skipPrivate = pvals[i].val.d.n;

        } else if (!strcmp(actpblk.descr[i].name, "prevalence_db")) {
            pData->prevPath = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);

#ifdef HAVE_MMENRICH_GEOIP
        } else if (!strcmp(actpblk.descr[i].name, "geoip_db")) {
            pData->geoipDbPath = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "geoip_fields")) {
            struct cnfarray* arr = pvals[i].val.d.ar;
            geoip_parse_field_specs(arr, &pData->geoipFields, &pData->numGeoipFields);
            geoip_ensure_country_name(&pData->geoipFields, &pData->numGeoipFields);
        } else if (!strcmp(actpblk.descr[i].name, "geoip_suffix")) {
            pData->geoipSuffix = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "geoip_skip_private")) {
            pData->geoipSkipPrivate = pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "geoip_cache_size")) {
            pData->geoipCacheSize = (uint32_t)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "geoip_asn_db")) {
            pData->geoipAsnDbPath = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "geoip_asn_fields")) {
            struct cnfarray* arr = pvals[i].val.d.ar;
            geoip_parse_field_specs(arr, &pData->geoipAsnFields, &pData->numGeoipAsnFields);
        } else if (!strcmp(actpblk.descr[i].name, "geoip_asn_cache_size")) {
            pData->geoipAsnCacheSize = (uint32_t)pvals[i].val.d.n;
#endif
        }
    }

    /* Validate required parameters:
     * - LOOKUP mode REQUIRES mappings (key->target pairs for per-field injection + GeoIP)
     * - PATTERN mode requires 'target' for the mined-IOC JSON report
     */
    if (pData->mode == MODE_LOOKUP) {
        if (pData->numMappings == 0) {
            LogError(0, RS_RET_CONFIG_ERROR,
                     "mmenrich: LOOKUP mode requires 'mappings' parameter "
                     "(e.g., mappings=[\"!parsed!src_ip:!cti!source!ip\", ...])");
            ABORT_FINALIZE(RS_RET_CONFIG_ERROR);
        }
        /* Mappings mode: target is optional (unused), keys are embedded in mappings */
        if (pData->targetPath == NULL) {
            pData->targetPath = (uchar*)strdup("$!_mmenrich_unused");
        }
    } else {
        /* PATTERN mode: requires target for the mined-IOC JSON report */
        if (pData->targetPath == NULL) {
            LogError(0, RS_RET_CONFIG_ERROR,
                     "mmenrich: 'target' parameter is required for PATTERN mode "
                     "(e.g., target=\"$!threat_intel\")");
            ABORT_FINALIZE(RS_RET_CONFIG_ERROR);
        }
    }

    /* The .thrt, overlay and .prev open as one libenrich handle. A file that
     * is missing or invalid is not fatal: the distribution may not have
     * delivered it yet, and the periodic reload (or a SIGHUP) loads it once
     * it is there. Every file is validated before it is used. */
    {
        enrich_options_t eo;
        char eerr[512];
        int erc;
        memset(&eo, 0, sizeof eo);
        eo.size = sizeof eo;
        eo.thrt_path = (const char*)pData->filePath;
        eo.overlay_path = (const char*)pData->overlayPath;
        eo.prev_path = (const char*)pData->prevPath;
        eo.flags = ENRICH_OPT_PARTIAL | (pData->skipPrivate ? ENRICH_OPT_SKIP_PRIVATE : 0);
        erc = enrich_open(&pData->enrich, &eo, eerr, sizeof eerr);
        if (pData->enrich == NULL) {
            LogError(0, erc == ENRICH_ENOMEM ? RS_RET_OUT_OF_MEMORY : RS_RET_CONFIG_ERROR,
                     "mmenrich: cannot open the lookup files: %s", eerr[0] ? eerr : enrich_strerror(erc));
            ABORT_FINALIZE(erc == ENRICH_ENOMEM ? RS_RET_OUT_OF_MEMORY : RS_RET_CONFIG_ERROR);
        }
        if (erc != ENRICH_OK)
            LogMsg(0, RS_RET_OK, LOG_WARNING, "mmenrich: %s - running without it until the next reload loads it", eerr);
    }
    thrt_caches_ensure();

    if (pData->uaPath) {
        pData->uaTable = thrt_file_cache_acquire(g_uaCache, (const char*)pData->uaPath);
        if (pData->uaTable) {
            LogMsg(0, RS_RET_OK, LOG_INFO,
                   "mmenrich/ua: loaded %u exact, %u contains, %u prefixes, %u suffixes from %s", pData->uaTable->n,
                   pData->uaTable->n_contains, pData->uaTable->n_prefixes, pData->uaTable->n_suffixes, pData->uaPath);
        } else {
            LogMsg(0, RS_RET_OK, LOG_WARNING,
                   "mmenrich/ua: table '%s' not available yet - "
                   "empty/encoded classifiers still run; table hits wait for SIGHUP.",
                   pData->uaPath);
        }
    }

    if (pData->tldPath) {
        pData->tldTable = thrt_file_cache_acquire(g_tldCache, (const char*)pData->tldPath);
        if (pData->tldTable) {
            LogMsg(0, RS_RET_OK, LOG_INFO, "mmenrich/tld: loaded %u entries from %s", pData->tldTable->n,
                   pData->tldPath);
        } else {
            LogMsg(0, RS_RET_OK, LOG_WARNING,
                   "mmenrich/tld: table '%s' not available yet - "
                   "uncommon classifier waits for SIGHUP.",
                   pData->tldPath);
        }
    }

    /* Initialize GeoIP if configured */
#ifdef HAVE_MMENRICH_GEOIP
    if (pData->geoipDbPath) {
        if (pData->numGeoipFields == 0) {
            LogError(0, RS_RET_CONFIG_ERROR, "mmenrich/geoip: geoip_db set but geoip_fields is empty - GeoIP disabled");
        } else {
            pData->geoipDb = thrt_file_cache_acquire(g_geoipCache, (char*)pData->geoipDbPath);
            if (!pData->geoipDb) {
                LogError(0, RS_RET_ERR, "mmenrich/geoip: failed to open MMDB - GeoIP disabled");
            } else {
                pData->geoipEnabled = 1;

                /* Create GeoIP result cache if configured */
                if (pData->geoipCacheSize >= 2) {
                    pData->geoipCache = geoip_cache_create(pData->geoipCacheSize);
                    if (!pData->geoipCache) {
                        LogError(0, RS_RET_ERR,
                                 "mmenrich/geoip: cache allocation failed (size=%u) - running without cache",
                                 pData->geoipCacheSize);
                    }
                }

                LogMsg(0, RS_RET_OK, LOG_INFO,
                       "mmenrich/geoip: enabled (%d fields, suffix='%s', skip_private=%s, cache=%u)",
                       pData->numGeoipFields, pData->geoipSuffix ? (char*)pData->geoipSuffix : "(none)",
                       pData->geoipSkipPrivate ? "on" : "off", pData->geoipCache ? pData->geoipCacheSize : 0);
            }
        }
    }

    /* Initialize ASN GeoIP if configured */
    if (pData->geoipAsnDbPath) {
        if (pData->numGeoipAsnFields == 0) {
            LogError(0, RS_RET_CONFIG_ERROR,
                     "mmenrich/geoip-asn: geoip_asn_db set but geoip_asn_fields is empty - ASN disabled");
        } else {
            pData->geoipAsnDb = thrt_file_cache_acquire(g_geoipAsnCache, (char*)pData->geoipAsnDbPath);
            if (!pData->geoipAsnDb) {
                LogError(0, RS_RET_ERR, "mmenrich/geoip-asn: failed to open ASN MMDB - ASN disabled");
            } else {
                pData->geoipAsnEnabled = 1;

                if (pData->geoipAsnCacheSize >= 2) {
                    pData->geoipAsnCache = geoip_cache_create(pData->geoipAsnCacheSize);
                    if (!pData->geoipAsnCache) {
                        LogError(0, RS_RET_ERR, "mmenrich/geoip-asn: cache allocation failed (size=%u)",
                                 pData->geoipAsnCacheSize);
                    }
                }

                LogMsg(0, RS_RET_OK, LOG_INFO, "mmenrich/geoip-asn: enabled (%d fields, cache=%u)",
                       pData->numGeoipAsnFields, pData->geoipAsnCache ? pData->geoipAsnCacheSize : 0);
            }
        }
    }
#endif

#if !THRT_HW_ACCEL
    /* Config load is single-threaded, so this static guard needs no locking.
     * Warn once that the binary was built without hardware CRC32C, which costs
     * throughput on the enrichment hot path. */
    {
        static sbool warnedNoHwCrc = 0;
        if (!warnedNoHwCrc) {
            warnedNoHwCrc = 1;
            LogMsg(0, NO_ERRCODE, LOG_WARNING,
                   "mmenrich: built without hardware CRC32C acceleration (scalar fallback); "
                   "enrichment throughput is reduced. Rebuild with -msse4.2 (x86-64) or "
                   "-march=armv8-a+crc (arm64) to enable it.");
        }
    }
#endif

    {
        enrich_info_t info;
        enrich_reader_t* rd = enrich_reader_new(pData->enrich);
        if (rd == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
        enrich_snap_info(enrich_reader_enter(rd), &info);
        enrich_reader_free(rd);
        LogMsg(0, RS_RET_OK, LOG_INFO,
               "mmenrich: threat db %s (%u records), overlay %s (%u entries), prevalence %s (%u entries); "
               "mode=%s, simd=%s, reloadOnHup=%s, skipPrivate=%s",
               (info.components & ENRICH_C_THRT) ? "loaded" : "absent", info.thrt_metadata,
               (info.components & ENRICH_C_OVERLAY) ? "loaded" : (pData->overlayPath ? "absent" : "off"),
               info.overlay_entries,
               (info.components & ENRICH_C_PREV) ? "loaded" : (pData->prevPath ? "absent" : "off"), info.prev_entries,
               pData->mode == MODE_PATTERN ? "pattern" : "lookup", pData->simdEnabled ? "on" : "off",
               pData->reloadOnHup ? "on" : "off", pData->skipPrivate ? "on" : "off");
    }

    /* Register */
    CODE_STD_STRING_REQUESTnewActInst(1);
    CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));

    CODE_STD_FINALIZERnewActInst;
    if (pvals != NULL) cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================ */
static const char* mmenrich_feed_name(const void* ctx, unsigned idx) {
    return enrich_feed_name((const enrich_snap_t*)ctx, idx);
}

/* source.ip lands on !source!threat. url.domain lands on !url!threat.
 * msgAddJSON takes ownership of the object. */
static void emit_party_threat(smsg_t* pMsg,
                              const uchar* turbo_key,
                              const enrich_snap_t* snap,
                              const enrich_result_t* res) {
    char ecsBase[128];
    char path[192];
    struct json_object* jThreat;
    int n;
    if (turbo_key == NULL || res == NULL) return;
    if (!ecs_geo_base((const char*)turbo_key, ecsBase, sizeof ecsBase)) return;
    jThreat = enrich_json_party(res, mmenrich_feed_name, snap);
    if (jThreat == NULL) return;
    n = snprintf(path, sizeof path, "%s!threat", ecsBase);
    if (n < 0 || n >= (int)sizeof path) {
        json_object_put(jThreat);
        return;
    }
    msgAddJSON(pMsg, (uchar*)path, jThreat, 0, 0);
}

/* ============================================================================
 * MODE: PATTERN (Feature Extraction)
 *
 * The miner only extracts candidate spans. Each category is then looked up
 * as one batch, under the same rules as a parsed field: overlay first,
 * then the database, then the private-address policy.
 * ============================================================================ */
static void pattern_category(const enrich_snap_t* snap,
                             uint32_t lflags,
                             const ioc_span_t* spans,
                             size_t count,
                             const char* json_key,
                             struct json_object** jFinalReport) {
    enrich_value_t vals[MAX_CANDIDATES];
    enrich_result_t res[MAX_CANDIDATES];
    int st[MAX_CANDIDATES];
    struct json_object* jArr = NULL;

    if (count == 0) return;
    for (size_t i = 0; i < count; i++) vals[i] = (enrich_value_t){spans[i].ptr, spans[i].len};
    (void)enrich_lookup_batch(snap, lflags, vals, count, res, st);
    for (size_t i = 0; i < count; i++) {
        struct json_object *jMeta, *jItem;
        size_t vlen;
        if (st[i] != 1 || (res[i].flags & ENRICH_R_SUPPRESSED)) continue;
        jMeta = enrich_json_field(&res[i], mmenrich_feed_name, snap);
        if (jMeta == NULL) continue;
        jItem = json_object_new_object();
        if (jArr == NULL) jArr = json_object_new_array();
        if (jItem == NULL || jArr == NULL) {
            json_object_put(jMeta);
            if (jItem) json_object_put(jItem);
            continue;
        }
        vlen = spans[i].len < MMENRICH_IOC_VALUE_MAX - 1 ? spans[i].len : MMENRICH_IOC_VALUE_MAX - 1;
        json_object_object_add(jItem, "value", json_object_new_string_len(spans[i].ptr, (int)vlen));
        json_object_object_add(jItem, "meta", jMeta);
        json_object_array_add(jArr, jItem);
    }
    if (jArr == NULL) return;
    if (*jFinalReport == NULL) *jFinalReport = json_object_new_object();
    if (*jFinalReport == NULL) {
        json_object_put(jArr);
        return;
    }
    json_object_object_add(*jFinalReport, json_key, jArr);
}

static rsRetVal process_pattern_mode(instanceData* pData,
                                     const enrich_snap_t* snap,
                                     const char* msgContent,
                                     size_t msgLen,
                                     struct json_object** jFinalReport) {
    DEFiRet;
    uint32_t lflags = enrich_lookup_flags(pData->enrich);
    ioc_report_t report;

    if (snap == NULL) FINALIZE;
    if (pData->simdEnabled) {
        mine_iocs_pattern(msgContent, msgLen, &report);
    } else {
        mine_iocs_scalar(msgContent, msgLen, &report);
    }
    if (report.dropped) STATSCOUNTER_ADD(ctrIocsDropped, mutCtrIocsDropped, report.dropped);

    /* Escaped payloads are not indicators; mmenrich_emit_shellcode reports
     * them from the parsed fields. */
    pattern_category(snap, lflags, report.ips, report.ip_count, "ips", jFinalReport);
    pattern_category(snap, lflags, report.domains, report.domain_count, "domains", jFinalReport);
    pattern_category(snap, lflags, report.hashes, report.hash_count, "hashes", jFinalReport);
    pattern_category(snap, lflags, report.file_threats, report.threat_count, "file_threats", jFinalReport);
    pattern_category(snap, lflags, report.emails, report.email_count, "emails", jFinalReport);

finalize_it:
    RETiRet;
}

/* ============================================================================
 * MODE: V4 MAPPINGS LOOKUP (turbo-accelerated)
 * Key-to-target mappings with an event-level summary + integrated GeoIP
 *
 * Hot path, for each mapping:
 *   1. Read the field value (tf_get: the turbo snapshot, or $! once written)
 *   2. enrich_lookup(): overlay, database and private-address policy
 *   3. Inject the per-field and party results at their target paths
 *   4. GeoIP for an address, unless it is private and geoip_skip_private
 * ============================================================================ */

#ifdef HAVE_MMENRICH_GEOIP
/* Derive ECS base path from turbo_key: "source.ip" -> "!source"
 * (ecs_geo_base). Used to inject GeoIP at ECS-standard paths
 * (!source!geo / !destination!geo) instead of appending to the
 * threat target path. */
static void build_ecs_base(const uchar* turbo_key, char* out, size_t out_sz) {
    if (!ecs_geo_base((const char*)turbo_key, out, out_sz)) out[0] = '\0';
}
#endif

static rsRetVal process_lookup_mode_v4_mappings(
    instanceData* pData, const enrich_snap_t* snap, smsg_t* pMsg, const tf_ctx_t* tf, enrich_event_t* ev) {
    DEFiRet;
    uint32_t lflags = enrich_lookup_flags(pData->enrich);

    memset(ev, 0, sizeof *ev);
    if (!pData->mappings || pData->numMappings == 0) FINALIZE;

#ifdef HAVE_MMENRICH_GEOIP
    /* Atomic load of current GeoIP snapshots (lock-free, ~1-2ns each) */
    geoip_snapshot_t* geoSnap = NULL;
    geoip_snapshot_t* asnSnap = NULL;
    if (pData->geoipEnabled) {
        geoSnap = MMENRICH_ATOMIC_LOAD(&pData->geoipDb, __ATOMIC_ACQUIRE);
    }
    if (pData->geoipAsnEnabled) {
        asnSnap = MMENRICH_ATOMIC_LOAD(&pData->geoipAsnDb, __ATOMIC_ACQUIRE);
    }
#endif

    for (int i = 0; i < pData->numMappings; i++) {
        key_mapping_t* mapping = &pData->mappings[i];
        const char* val = NULL;
        size_t vlen = 0;
        enrich_result_t res;

        if (!mapping->turbo_key || tf_get(tf, (const char*)mapping->turbo_key, &val, &vlen) != 0) {
            continue;
        }
        if (!val || vlen == 0) continue;

        /* A value too long or holding a NUL is not an indicator. */
        if (enrich_lookup(snap, lflags, val, vlen, &res) < 0) continue;
        /* A full whitelist hides the value: no CTI, no GeoIP. */
        if (res.flags & ENRICH_R_SUPPRESSED) continue;
        enrich_event_fold(ev, &res);

        /* Operator context tags from an overlay tag entry are not threat
         * intel: they go to the top-level ECS $!tags array. */
        if (res.overlay_tags != NULL) {
            struct json_object* jtags = enrich_json_array(res.overlay_tags, res.overlay_tags_len);
            if (jtags) msgAddJSON(pMsg, (uchar*)"!tags", jtags, 0, 0);
        }

        if (res.flags & ENRICH_R_THRT) {
            struct json_object* fieldResult = enrich_json_field(&res, mmenrich_feed_name, snap);
            if (fieldResult) {
                uchar* tgt = mapping->target;
                if (tgt[0] == '$') tgt++;
                msgAddJSON(pMsg, tgt, fieldResult, 0, 0);
            }
            emit_party_threat(pMsg, mapping->turbo_key, snap, &res);
        }

#ifdef HAVE_MMENRICH_GEOIP
        if ((geoSnap || asnSnap) && res.kind != ENRICH_KIND_STRING) {
            /* GeoIP takes the parsed address and a NUL-terminated key for its
             * cache; an address is short. */
            char vbuf[INET6_ADDRSTRLEN];
            struct in_addr addr4;
            struct in6_addr addr6;
            int ip_af = res.kind == ENRICH_KIND_IPV4 ? AF_INET : AF_INET6;
            sbool is_private = (res.flags & ENRICH_R_PRIVATE) != 0;
            const char* valStr = vbuf;
            if (vlen >= sizeof vbuf) continue;
            memcpy(vbuf, val, vlen);
            vbuf[vlen] = '\0';
            if (inet_pton(ip_af, vbuf, ip_af == AF_INET ? (void*)&addr4 : (void*)&addr6) != 1) continue;
            /* --- GeoIP enrichment - ECS-compliant injection --- */
            /* Derive ECS base from turbo_key: "source.ip" / eve "src_ip" -> "!source"
             * City goes to !source!geo, ASN goes to !source!as */
            if ((geoSnap || asnSnap) && ip_af && !(pData->geoipSkipPrivate && is_private)) {
                char ecsBase[128];
                build_ecs_base(mapping->turbo_key, ecsBase, sizeof(ecsBase));
                if (ecsBase[0] == '\0') continue;

                const void* addr_ptr = (ip_af == AF_INET) ? (const void*)&addr4 : (const void*)&addr6;

                /* --- City GeoIP -> !source!geo (or !destination!geo) --- */
                if (geoSnap) {
                    struct json_object* jGeo = NULL;

                    if (pData->geoipCache) {
                        jGeo = geoip_cache_read(pData->geoipCache, valStr);
                    }

                    if (!jGeo) {
                        jGeo = geoip_lookup_ip(geoSnap, ip_af, addr_ptr, pData->geoipFields, pData->numGeoipFields);

                        if (jGeo && pData->geoipCache) {
                            struct json_object* cacheRef = json_object_get(jGeo);
                            geoip_cache_write(pData->geoipCache, valStr, cacheRef);
                        }
                    }

                    if (jGeo) {
                        char geoPath[256];
                        snprintf(geoPath, sizeof(geoPath), "%s!geo", ecsBase);
                        msgAddJSON(pMsg, (uchar*)geoPath, jGeo, 0, 0);
                    }
                }

                /* --- ASN GeoIP -> !source!as (or !destination!as) --- */
                if (asnSnap) {
                    struct json_object* jAsn = NULL;

                    if (pData->geoipAsnCache) {
                        jAsn = geoip_cache_read(pData->geoipAsnCache, valStr);
                    }

                    if (!jAsn) {
                        jAsn =
                            geoip_lookup_ip(asnSnap, ip_af, addr_ptr, pData->geoipAsnFields, pData->numGeoipAsnFields);

                        if (jAsn && pData->geoipAsnCache) {
                            struct json_object* cacheRef = json_object_get(jAsn);
                            geoip_cache_write(pData->geoipAsnCache, valStr, cacheRef);
                        }
                    }

                    if (jAsn) {
                        char asnPath[256];
                        snprintf(asnPath, sizeof(asnPath), "%s!as", ecsBase);
                        msgAddJSON(pMsg, (uchar*)asnPath, jAsn, 0, 0);
                    }
                }
            }
        }
#endif
    }

finalize_it:
    RETiRet;
}

/* ============================================================================
 * MAIN RUNTIME LOGIC
 * ============================================================================ */
/* "url.path" -> "!url!path" for msgAddJSON. Returns 1 on success. Bounded. */
static int ecs_dotted_to_bang(const char* dotted, char* out, size_t out_sz) {
    size_t j = 0;
    if (out_sz < 2) return 0;
    out[j++] = '!';
    for (size_t i = 0; dotted[i] != '\0'; i++) {
        if (j >= out_sz - 1) return 0;
        out[j++] = (dotted[i] == '.') ? '!' : dotted[i];
    }
    out[j] = '\0';
    return 1;
}

/* emit ECS derived fields (e.g. url.path <- url.original) into $! so
 * downstream consumers see the SAME canonical fields mmenrich derives
 * (no liblognorm snapshot/ABI change). Derive-only-when-absent: never
 * clobber a field a rulebase already produced. */
/* Record dns.question.name and destination.ip into the counter file named
 * by prevalence_live_file. Another process publishes it, not this module. A missing
 * file is retried; a permanent failure backs off so the hot path does not
 * open() on every event. */
static prev_live_t* g_prevLive;
static pthread_mutex_t g_prevLiveMu = PTHREAD_MUTEX_INITIALIZER;
static uint32_t g_prevLiveBackoff;

static prev_live_t* mmenrich_prev_live(void) {
    prev_live_t* live;
    uint32_t back;
    if (g_prevLivePath == NULL) return NULL;
    live = MMENRICH_ATOMIC_LOAD(&g_prevLive, __ATOMIC_ACQUIRE);
    if (live != NULL) return live;
    back = MMENRICH_ATOMIC_LOAD(&g_prevLiveBackoff, __ATOMIC_RELAXED);
    if (back > 0) {
        (void)MMENRICH_ATOMIC_CAS(&g_prevLiveBackoff, &back, back - 1u, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
        return NULL;
    }
    pthread_mutex_lock(&g_prevLiveMu);
    if (g_prevLive == NULL) {
        g_prevLive = prev_live_open_keyed(g_prevLivePath, g_prevKeySet ? g_prevKey : NULL);
        if (g_prevLive == NULL) MMENRICH_ATOMIC_STORE(&g_prevLiveBackoff, 10000u, __ATOMIC_RELAXED);
    }
    live = g_prevLive;
    pthread_mutex_unlock(&g_prevLiveMu);
    return live;
}

static void mmenrich_note_prevalence(const tf_ctx_t* tf) {
    static const char* fields[] = {"dns.question.name", "destination.ip"};
    prev_live_t* live;
    const char* src = NULL;
    size_t slen = 0;
    char sbuf[256];
    size_t i;

    live = mmenrich_prev_live();
    if (live == NULL) return;
    sbuf[0] = '\0';
    if (tf_get(tf, "source.ip", &src, &slen) == 0 && slen > 0 && slen < sizeof(sbuf)) {
        memcpy(sbuf, src, slen);
        sbuf[slen] = '\0';
    }
    for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        const char* sval = NULL;
        char kbuf[256];
        if (tf_get(tf, fields[i], &sval, &slen) != 0) continue;
        if (slen == 0 || slen >= sizeof(kbuf)) continue;
        memcpy(kbuf, sval, slen);
        kbuf[slen] = '\0';
        prev_live_note(live, kbuf, sbuf[0] != '\0' ? sbuf : NULL);
    }
}

/* Emit prevalence facts: for each rarity-relevant observable present in
 * the parse, look up its count and inject <field>_prevalence into
 * $!. 0 = absent = rarest (the signal a Sigma rule thresholds, ideally ANDed
 * with entropy or beaconing). Skipped entirely while the table is unwarmed
 * (count_max == 0), so a cold table never flags every domain as rare. */
static void mmenrich_emit_prevalence(smsg_t* pMsg, const tf_ctx_t* tf, const enrich_snap_t* snap) {
    static const struct {
        const char* field;
        const char* count_path; /* _prevalence: occurrences on every edge (first-seen signal) */
        const char* edges_path; /* _prevalence_edges: DISTINCT edges (spread-rarity, self-inflation-proof) */
        const char* srcs_path; /* _prevalence_sources: DISTINCT internal sources (rarity that survives single-egress) */
    } obs[] = {
        {"dns.question.name", "!dns!question!name_prevalence", "!dns!question!name_prevalence_edges",
         "!dns!question!name_prevalence_sources"},
        {"destination.ip", "!destination!ip_prevalence", "!destination!ip_prevalence_edges",
         "!destination!ip_prevalence_sources"},
    };
    uint32_t edges_rep;
    if (snap == NULL) return;
    /* Number of edges the table merges. 0 = unknown, absent or an
     * unwarmed table; a rule treats a missing field as the gate applying. */
    edges_rep = enrich_prev_reporting_edges(snap);
    if (edges_rep > 0) {
        struct json_object* jn = json_object_new_int64((int64_t)edges_rep);
        if (jn) msgAddJSON(pMsg, (uchar*)"!event!prevalence_reporting_edges", jn, 0, 0);
    }
    for (size_t i = 0; i < sizeof(obs) / sizeof(obs[0]); i++) {
        const char* sval = NULL;
        size_t slen = 0;
        enrich_prev_t pv;
        int rc;
        if (tf_get(tf, obs[i].field, &sval, &slen) != 0) continue; /* field absent */
        if (slen == 0 || slen >= 256) continue; /* empty or implausibly long */
        /* One lookup yields the total count, the distinct-edge spread
         * and the distinct-internal-source count. 0 = no warmed table: a
         * cold table never flags every name as rare. */
        rc = enrich_prevalence(snap, sval, slen, &pv);
        if (rc == 0) return;
        if (rc < 0) continue;
        struct json_object* jc = json_object_new_int64((int64_t)pv.count);
        if (jc) msgAddJSON(pMsg, (uchar*)obs[i].count_path, jc, 0, 0);
        struct json_object* je = json_object_new_int64((int64_t)pv.edges);
        if (je) msgAddJSON(pMsg, (uchar*)obs[i].edges_path, je, 0, 0);
        struct json_object* js = json_object_new_int64((int64_t)pv.sources);
        if (js) msgAddJSON(pMsg, (uchar*)obs[i].srcs_path, js, 0, 0);
    }
}

static void mmenrich_emit_derived_ecs(smsg_t* pMsg, const tf_ctx_t* tf) {
    /* Source-first, memoized per contiguous group. The table is grouped by
     * source field (ecs_derive_table.def documents this as contract), so a
     * whole group costs ONE arena probe when its source is absent, instead of
     * one probe per row. That is what keeps the table growable: an event from a
     * source that carries none of these fields walks the rows but touches the
     * arena only once per group. Probing the source before the derived field
     * also puts the cheaper rejection first, since a foreign source misses the
     * whole group while the derived-present check would have to run per row. */
    const char* grp_src = NULL;
    const char* gval = NULL;
    size_t glen = 0;
    int ghit = 0;

    for (size_t di = 0; di < ECS_DERIVE_COUNT; di++) {
        const ecs_derive_entry_t* e = &ecs_derive_table[di];
        const char *sval = NULL, *dval = NULL;
        size_t slen = 0, dlen = 0;
        char dbuf[ECS_DERIVE_BUFSZ]; /* scratch for COMPUTED transforms (DGA numerics) */

        if (grp_src == NULL || strcmp(grp_src, e->source) != 0) {
            grp_src = e->source;
            ghit = (tf_get(tf, e->source, &gval, &glen) == 0);
        }
        if (!ghit) continue; /* source absent - nothing in this group to derive */
        sval = gval;
        slen = glen;

        if (tf_get(tf, e->derived, &dval, &dlen) == 0) continue; /* already produced by the parser - leave it */
        dval = NULL;
        dlen = 0;
        if (!ecs_derive_apply(e->transform, sval, slen, &dval, &dlen, dbuf, sizeof dbuf)) continue;

        char jpath[128];
        if (!ecs_dotted_to_bang(e->derived, jpath, sizeof jpath)) continue;
        /* dval is a borrowed slice (SLICE transforms) or points into dbuf
         * (COMPUTED); the _len variant copies exactly dlen bytes into the json. */
        struct json_object* jv = json_object_new_string_len(dval, (int)dlen);
        if (jv) msgAddJSON(pMsg, (uchar*)jpath, jv, 0, 0);
    }
}

/* Emit $!shellcode = true when the raw message carries an escaped payload
 * (thrt_payload.h). Runs in both modes, so a downstream module reads the
 * flag instead of scanning the message again. Without url.original (pattern
 * mode without mmnormalize) the URL pre-filter is skipped. Nothing is
 * emitted for a clean message. */
static void mmenrich_emit_shellcode(const instanceData* pData, smsg_t* pMsg, const tf_ctx_t* tf) {
    const char* url = NULL;
    size_t url_len = 0;
    const char* raw = (const char*)pMsg->pszRawMsg;
    size_t raw_len = pMsg->iLenRawMsg;

    if (tf_get(tf, "url.original", &url, &url_len) != 0) {
        url = NULL;
        url_len = 0;
    }
    if (raw == NULL) {
        raw = (const char*)getMSG(pMsg);
        raw_len = getMSGLen(pMsg);
    }
    if (!payload_has_shellcode(url, url_len, raw, raw_len, pData->shellcodeSkipTypes, pData->shellcodeSkipTypesLen,
                               pData->nShellcodeSkipTypes))
        return;
    struct json_object* jSc = json_object_new_boolean(1);
    if (jSc) msgAddJSON(pMsg, (uchar*)"!shellcode", jSc, 0, 0);
}

/* Log a reload: a change once, a failure once per distinct message (a file
 * that stays missing does not log every 100 messages). Callers hold the
 * reloading flag or run from HUP. */
static void mmenrich_log_reload(instanceData* pData, int rc, unsigned changed, const char* err) {
    static __thread char last[256];
    if (changed) {
        LogMsg(0, RS_RET_OK, LOG_INFO, "mmenrich: reloaded%s%s%s", (changed & ENRICH_C_THRT) ? " threat-db" : "",
               (changed & ENRICH_C_OVERLAY) ? " overlay" : "", (changed & ENRICH_C_PREV) ? " prevalence" : "");
    }
    if (rc == ENRICH_OK) {
        last[0] = '\0';
        return;
    }
    if (strncmp(last, err, sizeof last - 1) == 0) return;
    snprintf(last, sizeof last, "%s", err);
    LogMsg(0, RS_RET_OK, LOG_WARNING, "mmenrich: reload kept the previous file: %s (%s)", err,
           pData->filePath ? (const char*)pData->filePath : "-");
}

/* Every 100 messages one worker stats the files and reloads what changed.
 * The others go on: enrich_reload() never blocks readers. */
static void mmenrich_periodic_reload(instanceData* pData) {
    uint32_t idle = 0;
    unsigned changed = 0;
    char err[512];
    int rc;
    if (pData->enrich == NULL) return;
    if (!MMENRICH_ATOMIC_CAS(&pData->enrichReloading, &idle, 1u, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return;
    err[0] = '\0';
    rc = enrich_reload(pData->enrich, &changed, err, sizeof err);
    mmenrich_log_reload(pData, rc, changed, err);
    MMENRICH_ATOMIC_STORE(&pData->enrichReloading, 0u, __ATOMIC_RELEASE);
}

BEGINdoAction_NoStrings
    smsg_t** ppMsg = (smsg_t**)pMsgData;
    smsg_t* pMsg = ppMsg[0];
    instanceData* pData = pWrkrData->pData;
    struct json_object* jFinalReport = NULL;
    tf_ctx_t tfc = {pMsg, &pWrkrData->tf, 0};
    const tf_ctx_t* const tf = &tfc;
    CODESTARTdoAction;
    STATSCOUNTER_INC(ctrEvents, mutCtrEvents);
    tf_store_reset(&pWrkrData->tf);

    /* This worker's snapshot of the .thrt, overlay and .prev. Two loads when
     * nothing was reloaded since the last message. A missing file is a
     * missing part of the snapshot: those lookups miss, the rest runs. */
    const enrich_snap_t* esnap = pWrkrData->reader ? enrich_reader_enter(pWrkrData->reader) : NULL;

    if (pData->mode == MODE_PATTERN) {
        /* Pattern Extraction Mode */
        char* msgContent = NULL;
        size_t msgLen = 0;

        /* Try RawMsg first (best for performance) */
        if (pMsg->pszRawMsg != NULL) {
            msgContent = (char*)pMsg->pszRawMsg;
            msgLen = pMsg->iLenRawMsg;
        }
        /* Fallback to standard msg */
        else {
            msgContent = (char*)getMSG(pMsg);
            msgLen = getMSGLen(pMsg);
        }

        if (msgContent && msgLen > 0) {
            process_pattern_mode(pData, esnap, msgContent, msgLen, &jFinalReport);
        }

        /* mmnormalize is optional in pattern mode. When it ran, its
         * url.original drives the same static-asset pre-filter as lookup. */
        mmenrich_emit_shellcode(pData, pMsg, tf);

        /* process_pattern_mode only adds a category key to jFinalReport when a
         * mined IOC carried CTI meta (a confirmed threat); a report with >=1 key
         * means this event matched CTI. Clean-but-mined IOCs leave it empty and
         * are NOT counted. Once per event. */
        if (jFinalReport != NULL && json_object_object_length(jFinalReport) > 0)
            STATSCOUNTER_INC(ctrCtiHits, mutCtrCtiHits);

    } else {
        /* Lookup Mode - the turbo parse is REQUIRED. Fields are read through
         * tf, which also sees $! writes made after the parse. */
        if (!tf_has_snapshot(pMsg)) {
            LogError(0, RS_RET_ERR,
                     "mmenrich: turbo_result is NULL - mmnormalize must have turbo=\"on\" enabled. "
                     "Add turbo=\"on\" to your mmnormalize action.");
            ABORT_FINALIZE(RS_RET_ERR);
        }

        /* Every field this action reads, under one mutex hold; the reads
         * below are then answered from the store. A derived field is read
         * only when its source is present, as mmenrich_emit_derived_ecs()
         * does. */
        {
            static const char* const fixed[] = {"source.ip",           "dns.question.name", "destination.ip",
                                                "user_agent.original", "url.domain",        "url.original"};
            const char* v;
            size_t l;
            tf_lock(&tfc);
            for (size_t k = 0; k < sizeof(fixed) / sizeof(fixed[0]); k++) (void)tf_get(tf, fixed[k], &v, &l);
            for (int k = 0; k < pData->numMappings; k++)
                if (pData->mappings[k].turbo_key) (void)tf_get(tf, (const char*)pData->mappings[k].turbo_key, &v, &l);
            for (size_t di = 0; di < ECS_DERIVE_COUNT; di++)
                if (tf_get(tf, ecs_derive_table[di].source, &v, &l) == 0)
                    (void)tf_get(tf, ecs_derive_table[di].derived, &v, &l);
            tf_unlock(&tfc);
        }

        /* ECS derived fields into $! (log/consumer symmetry). */
        mmenrich_emit_derived_ecs(pMsg, tf);

        /* Count first, then emit. Counting runs while the image is still cold. */
        mmenrich_note_prevalence(tf);
        mmenrich_emit_prevalence(pMsg, tf, esnap);

        /* UA identification. Field absent is not empty. */
        if (pData->uaPath) {
            const char* ua = NULL;
            size_t ualen = 0;
            ua_class_t uacl;
            ua_table_t* uat = MMENRICH_ATOMIC_LOAD(&pData->uaTable, __ATOMIC_ACQUIRE);
            if (tf_get(tf, "user_agent.original", &ua, &ualen) == 0 && ua_classify(uat, ua, ualen, &uacl) == 0 &&
                uacl.kind != UA_KIND_NONE) {
                if (uacl.cls) {
                    struct json_object* jcls = json_object_new_string(uacl.cls);
                    if (jcls) msgAddJSON(pMsg, (uchar*)"!user_agent!threat", jcls, 0, 0);
                }
                if (uacl.label && uacl.label[0]) {
                    struct json_object* jlab = json_object_new_string(uacl.label);
                    if (jlab) msgAddJSON(pMsg, (uchar*)"!user_agent!threat_label", jlab, 0, 0);
                }
            }
        }

        if (pData->tldPath) {
            const char* host = NULL;
            size_t hostlen = 0;
            tld_class_t tldcl;
            tld_table_t* tldt = MMENRICH_ATOMIC_LOAD(&pData->tldTable, __ATOMIC_ACQUIRE);
            if (tf_get(tf, "url.domain", &host, &hostlen) == 0 && tld_classify(tldt, host, hostlen, &tldcl) == 0 &&
                tldcl.kind != TLD_KIND_NONE) {
                if (tldcl.cls) {
                    struct json_object* jcls = json_object_new_string(tldcl.cls);
                    if (jcls) msgAddJSON(pMsg, (uchar*)"!url!tld_class", jcls, 0, 0);
                }
            }
        }

        /* V4 MAPPINGS PATH: turbo-accelerated field extraction + direct target injection.
         * Mappings are mandatory for LOOKUP mode (validated at config time). */
        enrich_event_t ev;
        process_lookup_mode_v4_mappings(pData, esnap, pMsg, tf, &ev);

        /* ev.match is the OR of every mapping's CTI, CTI_R or overlay add
         * match - increment cti.hits exactly once per matching event. */
        if (ev.match) STATSCOUNTER_INC(ctrCtiHits, mutCtrCtiHits);

        /* NAMESPACE SPLIT: the emitted enrichment is split into proper
         * ECS-native namespaces:
         *
         *   $!threat  - CTI / threat-intel ONLY. mmenrich is the sole CTI
         *               lookup site and emits $!threat with a stable shape
         *               { matched, confidence, category, feed, tlp } that
         *               downstream consumers read. `$!threat!matched` is the
         *               bool.
         *   $!labels  - operator disposition (whitelisted -> "allowed").
         *   $!tags    - operator context tags (emitted in the overlay path above).
         *
         * Contract for $!threat: { matched:bool, confidence:int, category:int,
         *   feed:int, tlp:int }. Always emitted (even on no-match) so downstream
         *   consumers see a stable shape; feed is a uint64 rendered as a JSON int64. */
        {
            struct json_object* jthreat = json_object_new_object();
            if (jthreat) {
                json_object_object_add(jthreat, "matched", json_object_new_boolean(ev.match ? 1 : 0));
                json_object_object_add(jthreat, "confidence", json_object_new_int((int)ev.confidence));
                json_object_object_add(jthreat, "category", json_object_new_int((int)ev.category_mask));
                json_object_object_add(jthreat, "feed", json_object_new_int64((int64_t)ev.feed_mask));
                json_object_object_add(jthreat, "tlp", json_object_new_int((int)ev.tlp_mask));
                msgAddJSON(pMsg, (uchar*)"!threat", jthreat, 0, 0);
            }
        }

        /* Operator disposition: emit $!labels!disposition = "allowed" only when
         * the entry was whitelisted (overlay '-' / the old `whitelisted` flag).
         * Absent otherwise. */
        if (ev.whitelisted) {
            struct json_object* jlabels = json_object_new_object();
            if (jlabels) {
                json_object_object_add(jlabels, "disposition", json_object_new_string("allowed"));
                msgAddJSON(pMsg, (uchar*)"!labels", jlabels, 0, 0);
            }
        }

        mmenrich_emit_shellcode(pData, pMsg, tf);
    }

    /* Inject turbo lookup results into message */
    if (jFinalReport && pData->targetPath) {
        /* msgAddJSON expects path WITHOUT the leading $
         * Configuration: target="$!threat_intel" -> pass "!threat_intel"
         * Configuration: target="$.threat_intel" -> pass ".threat_intel"
         * Configuration: target="$/threat_intel" -> pass "/threat_intel"
         */
        uchar* jsonPath = pData->targetPath;
        if (jsonPath[0] == '$') {
            jsonPath++; /* Skip the $ prefix */
        }

        if (RS_RET_OK != msgAddJSON(pMsg, jsonPath, jFinalReport, 0, 0)) {
            LogError(0, RS_RET_ERR, "mmenrich: Failed to add threat intelligence to message at '%s'",
                     pData->targetPath);
            json_object_put(jFinalReport);
        }
    }

finalize_it:
    /* Piggyback: stat the .thrt, overlay and .prev every 100 messages and
     * reload what changed. Thread-local counter: no contention. */
    {
        static __thread uint32_t reload_counter = 0;
        if (++reload_counter % 100 == 0) mmenrich_periodic_reload(pData);
    }

ENDdoAction

/* ============================================================================
 * HUP HANDLER (Hot Reload)
 * ============================================================================ */
/* Instance-level HUP (NOT per-worker): rsyslog invokes doHUPWrkr once per
 * worker thread for a single SIGHUP, and one reload per HUP is enough.
 * libenrich frees a replaced snapshot only once every worker's reader has
 * moved past it, so a worker mid-message keeps a valid mapping. */
BEGINdoHUP
    CODESTARTdoHUP;
    DBGPRINTF("mmenrich: HUP received\n");
    if (pData->reloadOnHup && pData->enrich != NULL) {
        unsigned changed = 0;
        char err[512];
        int rc;
        err[0] = '\0';
        rc = enrich_reload(pData->enrich, &changed, err, sizeof err);
        if (changed)
            LogMsg(0, RS_RET_OK, LOG_INFO, "mmenrich: HUP reloaded%s%s%s",
                   (changed & ENRICH_C_THRT) ? " threat-db" : "", (changed & ENRICH_C_OVERLAY) ? " overlay" : "",
                   (changed & ENRICH_C_PREV) ? " prevalence" : "");
        if (rc != ENRICH_OK) LogMsg(0, RS_RET_OK, LOG_WARNING, "mmenrich: HUP kept the previous file: %s", err);
    }
    if (pData->reloadOnHup) {
        /* A table that did not change, or that failed to load, stays in
         * place. A replaced table stays allocated for the grace period of
         * the cache, so a worker that loaded it before the swap is safe. */
        thrt_caches_ensure();
        if (pData->uaPath) {
            ua_table_t* old = pData->uaTable;
            ua_table_t* neu = thrt_file_cache_refresh(g_uaCache, (const char*)pData->uaPath, old);
            if (neu != old) MMENRICH_ATOMIC_STORE(&pData->uaTable, neu, __ATOMIC_RELEASE);
            if (neu != old && neu) {
                LogMsg(0, RS_RET_OK, LOG_INFO,
                       "mmenrich/ua: reloaded %u exact, %u contains, %u prefixes, %u suffixes from %s", neu->n,
                       neu->n_contains, neu->n_prefixes, neu->n_suffixes, pData->uaPath);
            }
        }
        if (pData->tldPath) {
            tld_table_t* old = pData->tldTable;
            tld_table_t* neu = thrt_file_cache_refresh(g_tldCache, (const char*)pData->tldPath, old);
            if (neu != old) MMENRICH_ATOMIC_STORE(&pData->tldTable, neu, __ATOMIC_RELEASE);
            if (neu != old && neu) {
                LogMsg(0, RS_RET_OK, LOG_INFO, "mmenrich/tld: reloaded %u entries from %s", neu->n, pData->tldPath);
            }
        }
#ifdef HAVE_MMENRICH_GEOIP
        if (pData->geoipEnabled) {
            reloadGeoipDatabase(pData);
        }
        if (pData->geoipAsnEnabled) {
            reloadGeoipAsnDatabase(pData);
        }
#endif
    }
ENDdoHUP

/* ============================================================================
 * MODULE FOOTER
 * ============================================================================ */
BEGINparseSelectorAct
    CODESTARTparseSelectorAct;
    CODE_STD_STRING_REQUESTparseSelectorAct(1);
    if (strncmp((char*)p, ":mmenrich:", sizeof(":mmenrich:") - 1)) {
        ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
    }
    CODE_STD_FINALIZERparseSelectorAct;
ENDparseSelectorAct

BEGINbeginCnfLoad
    CODESTARTbeginCnfLoad;
    loadModConf = pModConf;
    pModConf->pConf = pConf;
    pModConf->prevLivePath = NULL;
ENDbeginCnfLoad

BEGINsetModCnf
    struct cnfparamvals* pvals = NULL;
    int i;
    CODESTARTsetModCnf;
    pvals = nvlstGetParams(lst, &modpblk, NULL);
    if (pvals == NULL) {
        LogError(0, RS_RET_MISSING_CNFPARAMS, "mmenrich: error processing module config parameters [module(...)]");
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }
    if (Debug) {
        dbgprintf("module (global) param blk for mmenrich:\n");
        cnfparamsPrint(&modpblk, pvals);
    }
    for (i = 0; i < modpblk.nParams; ++i) {
        if (!pvals[i].bUsed) continue;
        if (!strcmp(modpblk.descr[i].name, "prevalence_live_file")) {
            free(loadModConf->prevLivePath);
            loadModConf->prevLivePath = es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(modpblk.descr[i].name, "prevalence_key_file")) {
            free(loadModConf->prevKeyPath);
            loadModConf->prevKeyPath = es_str2cstr(pvals[i].val.d.estr, NULL);
        } else {
            dbgprintf("mmenrich: program error, non-handled param '%s' in setModCnf\n", modpblk.descr[i].name);
        }
    }
finalize_it:
    if (pvals != NULL) cnfparamvalsDestruct(pvals, &modpblk);
ENDsetModCnf

BEGINendCnfLoad
    CODESTARTendCnfLoad;
    loadModConf = NULL;
ENDendCnfLoad

BEGINcheckCnf
    CODESTARTcheckCnf;
    if (pModConf->prevLivePath != NULL && pModConf->prevLivePath[0] == '\0') {
        free(pModConf->prevLivePath);
        pModConf->prevLivePath = NULL;
    }
    if (pModConf->prevKeyPath != NULL && pModConf->prevKeyPath[0] == '\0') {
        free(pModConf->prevKeyPath);
        pModConf->prevKeyPath = NULL;
    }
ENDcheckCnf

BEGINactivateCnf
    CODESTARTactivateCnf;
    runModConf = pModConf;
    if (g_prevLivePath == NULL && pModConf->prevLivePath != NULL) {
        /* A key file that is set and refused stops the counting: counters
         * under a random key would not merge with the other edges. */
        if (pModConf->prevKeyPath != NULL) {
            int krc = prev_live_read_key(pModConf->prevKeyPath, g_prevKey);
            if (krc != 0) {
                LogError(0, RS_RET_CONFIG_ERROR, "mmenrich: prevalence key file %s refused (%s), nothing is counted",
                         pModConf->prevKeyPath, prev_live_key_error(krc));
                FINALIZE;
            }
            g_prevKeySet = 1;
        }
        g_prevLivePath = strdup(pModConf->prevLivePath);
        if (g_prevLivePath == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
finalize_it:
ENDactivateCnf

BEGINfreeCnf
    CODESTARTfreeCnf;
    free(pModConf->prevLivePath);
    free(pModConf->prevKeyPath);
ENDfreeCnf

BEGINmodExit
    CODESTARTmodExit;
    if (mmenrichStats != NULL) statsobj.Destruct(&mmenrichStats);
    objRelease(statsobj, CORE_COMPONENT);
    thrt_caches_destroy();
    free(g_prevLivePath);
    g_prevLivePath = NULL;
    memset(g_prevKey, 0, sizeof g_prevKey);
    g_prevKeySet = 0;
ENDmodExit

BEGINqueryEtryPt
    CODESTARTqueryEtryPt;
    CODEqueryEtryPt_STD_OMOD_QUERIES;
    CODEqueryEtryPt_STD_OMOD8_QUERIES;
    CODEqueryEtryPt_STD_CONF2_QUERIES;
    CODEqueryEtryPt_STD_CONF2_setModCnf_QUERIES;
    CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES;
    CODEqueryEtryPt_doHUP;
ENDqueryEtryPt

BEGINmodInit()
    CODESTARTmodInit;
    *ipIFVersProvided = CURR_MOD_IF_VERSION;
    CODEmodInit_QueryRegCFSLineHdlr;
    /* impstats: expose the enrich-stage throughput counter (statsobj "mmenrich"
     * -> counter "events") so the collector's funnel can read events/interval. */
    CHKiRet(objUse(statsobj, CORE_COMPONENT));
    CHKiRet(statsobj.Construct(&mmenrichStats));
    CHKiRet(statsobj.SetName(mmenrichStats, (uchar*)"mmenrich"));
    CHKiRet(statsobj.SetOrigin(mmenrichStats, (uchar*)"mmenrich"));
    STATSCOUNTER_INIT(ctrEvents, mutCtrEvents);
    CHKiRet(
        statsobj.AddCounter(mmenrichStats, UCHAR_CONSTANT("events"), ctrType_IntCtr, CTR_FLAG_RESETTABLE, &ctrEvents));
    STATSCOUNTER_INIT(ctrCtiHits, mutCtrCtiHits);
    CHKiRet(statsobj.AddCounter(mmenrichStats, UCHAR_CONSTANT("cti.hits"), ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &ctrCtiHits));
    STATSCOUNTER_INIT(ctrIocsDropped, mutCtrIocsDropped);
    CHKiRet(statsobj.AddCounter(mmenrichStats, UCHAR_CONSTANT("cti.iocs_dropped"), ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &ctrIocsDropped));
    CHKiRet(statsobj.ConstructFinalize(mmenrichStats));
    thrt_caches_ensure();
ENDmodInit
