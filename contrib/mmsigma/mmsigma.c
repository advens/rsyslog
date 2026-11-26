/* SPDX-License-Identifier: Apache-2.0 */

/* mmsigma.c
 * rsyslog message-modification module: evaluate compiled Sigma selection-match
 * rules (a `.sigmac` artifact) against each message's parsed fields and inject
 * the verdict under `$!sigma`.
 *
 * Input fields come from the liblognorm TurboVM result attached to the message
 * (pMsg->turbo_result, flat dotted keys, e.g. "source.ip"), so mmnormalize must
 * run with turbo="on" earlier in the pipeline. Selection match, correlation,
 * contrib JSON, and event-time live in libsigma. This file is the rsyslog glue.
 *
 * The `.sigmac` and `rules.corr.json` files are written by
 * pySigma-backend-libsigma. A deployment may filter the rule set first (the
 * fields its parsers produce, the log sources a host receives).
 * This module only loads them.
 *
 * Output (`$!sigma`), hot path LABELS only:
 *   { "matched": true, "count": N,
 *     "rules": [ {"id":..,"verdict":..,"severity":..,"score":..,
 *                 "mitre":"T1059.001"}, ... ] }
 * There is NO top-level "verdict"/"score": the hot path must not make the
 * terminal "this is an alert, cluster-wide" collapse.  Per-rule "score" is a HINT
 * (the baked score_x100/100).  A downstream scoring stage combines
 * these with the edge's coarse role under escalate-wins / benign-advisory /
 * DEMOTE-NOT-MUTE and emits the verdict authority + fidelity tier.
 * "mitre" (primary MITRE technique) is present only when the matched rule carries
 * one, it is a downstream correlation join-key.
 *
 * Hot reload: the .sigmac is reloaded on SIGHUP and via a piggyback mtime check
 * (atomic pointer swap, one old generation retained for in-flight workers).
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <math.h>
#include <pthread.h>

#include "conf.h"
#include "syslogd-types.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "cfsysline.h"
#include "dirty.h"
#include "statsobj.h"
#include "unicode-helper.h"

/* Parsed fields prefer the liblognorm TurboVM snapshot (pMsg->turbo_result)
 * when the module is built with HAVE_LOGNORM_TURBO. Without it, matching falls
 * back to the $! tree for every event (same path as a missing snapshot). */
#ifdef HAVE_LOGNORM_TURBO
    #include <lognorm-turbo.h> /* ln_fast_result_* + snapshot accessors */
#endif

#include <sigma/sigma_match.h>
#include <sigma/sigma_format.h>
#include "ecs_derive.h" /* ECS derived-field layer (url.path ...) */
#include "enrich.h" /* libenrich: the prevalence table (rarity prior) */
#include <sigma/classify_corr.h> /* libsigma correlator */
#include <sigma/corr_format.h> /* rules.corr.json loader (the only json-dep part) */
#include <sigma/contrib_wire.h> /* $!sigma_contribution JSON */
#include "mmsigma_contrib.h" /* what an emitted partial carries */
#include <json.h>
#include <sigma/event_time.h> /* event-time parse for correlation windows */

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("mmsigma")

DEF_OMOD_STATIC_DATA
DEFobjCurrIf(statsobj)

    /* Module-global impstats.  turbo.missing counts events evaluated WITHOUT the
     * zero-copy turbo arena (fallback to the $! tree), a steadily rising counter
     * means an upstream path is losing the parse snapshot and matching runs
     * degraded instead of silently not at all.  matched.events counts events with
     * at least one rule hit. */
    static statsobj_t* mmsigmaStats;
STATSCOUNTER_DEF(ctrTurboMissing, mutCtrTurboMissing)
/* events counts every message mmsigma actually evaluates (a ruleset is
 * loaded), the denominator for matched.events. */
STATSCOUNTER_DEF(ctrEvents, mutCtrEvents)
STATSCOUNTER_DEF(ctrMatchedEvents, mutCtrMatchedEvents)
/* regex.skipped is a GAUGE: RE predicates in the CURRENT artifact that even
 * PCRE2 could not compile (a malformed pattern), set on each (re)load, so a
 * non-zero value means some |re: rule is silently not matching. */
STATSCOUNTER_DEF(ctrReSkipped, mutCtrReSkipped)

/* hits.truncated: matcher rule-hits DROPPED because more than MMSIGMA_MAX_HITS
 * rules fired on one event (the $!sigma.count stays honest, but rules[] is
 * capped).  Incremented live by (fired - cap) per over-cap event. */
STATSCOUNTER_DEF(ctrHitsTruncated, mutCtrHitsTruncated)

/* corr.timestamp.fallback: with useLogTimestamp on, events with no usable
 * event time (absent, unparseable or not finite), so the correlation used the
 * receive time. Non-zero flags a broken parser or a bad timestamp at the source. */
STATSCOUNTER_DEF(ctrCorrTsFallback, mutCtrCorrTsFallback)
/* corr.timestamp.ahead / .behind: an event or contribution time more than
 * corrmaxahead after, or corrmaxbehind before, the receive time, clamped to
 * that bound. With event-time ordering, a future time raises its group's
 * watermark, so corrmaxahead bounds how long one event can hold later ones
 * out as late. */
STATSCOUNTER_DEF(ctrCorrTsAhead, mutCtrCorrTsAhead)
STATSCOUNTER_DEF(ctrCorrTsBehind, mutCtrCorrTsBehind)
/* corr.timestamp.syslog: no parseable field, used rsyslog's msg tTIMESTAMP
 * (syslog header or receive time). */
STATSCOUNTER_DEF(ctrCorrTsSyslog, mutCtrCorrTsSyslog)
STATSCOUNTER_DEF(ctrCorrContribEmit, mutCtrCorrContribEmit)
/* corr.contrib.emit.failed: a partial this peer does not own could not be
 * encoded (out of memory), so its owner never sees it. */
STATSCOUNTER_DEF(ctrCorrContribEmitFailed, mutCtrCorrContribEmitFailed)
STATSCOUNTER_DEF(ctrCorrContribIngest, mutCtrCorrContribIngest)
STATSCOUNTER_DEF(ctrCorrContribDrop, mutCtrCorrContribDrop)
/* corr.value.overflow: a correlation group-by or value field did not fit the
 * per-event copy arena, so it was treated as absent for this event. */
STATSCOUNTER_DEF(ctrCorrValOverflow, mutCtrCorrValOverflow)

/* ---- folded-correlation boundary counters --------------
 * Every silent cap in the correlation engine + its loader is observable.  The
 * engine (libsigma classify_corr.c) and loader (corr_format.c) keep plain uint64 tallies
 * (dep-free); these impstats counters are refreshed from those tallies as
 * `persistent-accumulator + current-generation snapshot` (the engine resets its
 * internal tallies when an artifact is (re)loaded, so mmsigma carries the
 * accumulated total across generations, see publish_corr_stats). */
STATSCOUNTER_DEF(ctrCorrGroupsEvicted, mutCorrGroupsEvicted)
STATSCOUNTER_DEF(ctrCorrDistinctEvicted, mutCorrDistinctEvicted)
STATSCOUNTER_DEF(ctrCorrEventsOverwritten, mutCorrEventsOverwritten)
STATSCOUNTER_DEF(ctrCorrFiresSuppressed, mutCorrFiresSuppressed)
STATSCOUNTER_DEF(ctrCorrFiresTruncated, mutCorrFiresTruncated)
STATSCOUNTER_DEF(ctrCorrRulesRejected, mutCorrRulesRejected)
STATSCOUNTER_DEF(ctrCorrEvtSkippedMissing, mutCorrEvtSkippedMissing)
STATSCOUNTER_DEF(ctrCorrSeenTruncated, mutCorrSeenTruncated)
STATSCOUNTER_DEF(ctrCorrHitsTruncated, mutCorrHitsTruncated)
STATSCOUNTER_DEF(ctrCorrGroupEvidenceDropped, mutCorrGroupEvidenceDropped)
STATSCOUNTER_DEF(ctrCorrOomDropped, mutCorrOomDropped)
STATSCOUNTER_DEF(ctrCorrValuesNonnumeric, mutCorrValuesNonnumeric)
STATSCOUNTER_DEF(ctrCorrCondOverArity, mutCorrCondOverArity)
STATSCOUNTER_DEF(ctrCorrWatermarkLate, mutCorrWatermarkLate)
STATSCOUNTER_DEF(ctrCorrHotkeyFallback, mutCorrHotkeyFallback)
STATSCOUNTER_DEF(ctrCorrGroupbyTruncated, mutCorrGroupbyTruncated)
STATSCOUNTER_DEF(ctrCorrBaserulesTruncated, mutCorrBaserulesTruncated)
STATSCOUNTER_DEF(ctrCorrRidsDropped, mutCorrRidsDropped)

static int bWarnedTurboMissing = 0;

#define MMSIGMA_RELOAD_EVERY 100 /* piggyback mtime check cadence */
#define MMSIGMA_MAX_HITS 64
#define MMSIGMA_MAX_FIRES 32 /* fired correlations captured per event */
#define MMSIGMA_DERIVE_SLOTS 16 /* distinct COMPUTED field values held per event */
#define MMSIGMA_CORR_VAL_ARENA 16384 /* terminated copies of correlation field values, per event */
#define MMSIGMA_CORR_VAL_MEMO 16 /* field names memoized per event in that arena */

/* The prevalence table (.prev) is opened through libenrich: mmenrich
 * emits the rarity fact into $! for the enriched output, and mmsigma resolves
 * it here from the same table, so a Sigma rule can threshold
 * <field>_prevalence inline without a cross-module $! ordering. */

/* A loaded artifact. gen, not the address, tells a worker its eval scratch
 * is stale: malloc can hand a freed db's address to the next one. */
typedef struct mmsigma_db {
    sigma_db_t db;
    uint64_t gen;
    uint64_t retire_tag; /* dbGp after this db was replaced */
    struct mmsigma_db* next; /* retired list */
} mmsigma_db_t;

/* One per worker. epoch is 0 outside doAction, else the dbGp value read on
 * entry. Alone on its cache line: only its worker writes it. */
typedef struct mmsigma_reader {
    _Alignas(64) uint64_t epoch;
    struct mmsigma_reader* next;
} mmsigma_reader_t;

typedef struct _instanceData {
    uchar* dbPath; /* path to the .sigmac artifact (required) */
    uchar* targetPath; /* output JSON path, default "!sigma" */
    sbool reloadOnHup; /* reload artifact on SIGHUP (default: yes) */
    /* Current artifact, swapped by db_publish_locked. A replaced db goes on
     * dbRetired and is freed once every reader that could hold it has left
     * doAction (the libenrich reader scheme). */
    mmsigma_db_t* dbCur;
    uint64_t dbGp; /* grace period counter, +1 per publish, starts at 1 */
    uint64_t dbGen; /* load counter for mmsigma_db_t.gen */
    mmsigma_db_t* dbRetired;
    mmsigma_reader_t* dbReaders;
    pthread_mutex_t reloadMutex; /* dbCur swap, dbRetired, dbReaders, dbMtime/dbIno */
    time_t dbMtime;
    ino_t dbIno;

    /* ---- folded warm-path correlation -----------------
     * The Sigma CORRELATION engine lives inside mmsigma.  It consumes the matched rule-ids NATIVELY
     * (the sigma_hit_t[] sigma_eval_run just produced), there is NO $!sigma
     * round-trip read.
     *
     * Concurrency: the engine is internally synchronised and SAFE for
     * concurrent workers (per-correlation locks inside classify_corr.c), so the
     * action needs no single-worker restriction.  corrRwlock guards only the
     * engine POINTER's lifetime across a hot reload: doAction takes it read-held
     * (many workers concurrently) while it calls corr_on_event and serialises
     * the fired activations (which reference the loaded artifact); reload takes
     * it write-held to swap in a new generation and free the old one.
     *
     * corrFile unset => correlation disabled, a full no-op (mmsigma behaves
     * exactly as before). */
    uchar* corrFile; /* path to rules.corr.json; NULL => disabled */
    corr_engine_t* corrEngine;
    corr_artifact_t* corrArtifact; /* backs corrEngine's string/array storage */
    pthread_rwlock_t corrRwlock; /* guards engine-pointer swap vs in-flight readers */
    time_t corrMtime;
    /* eviction caps (CONFIG params -> corr_caps_t) */
    int corrMaxGroups;
    int corrMaxDistinct;
    int corrMaxEventsPerGroup;
    /* event-time correlation clock (default on). When set, the correlation
     * window and temporal_ordered sequencing use the parsed event time from
     * tsField, bounded by the receive time, instead of the receive time. */
    sbool useLogTimestamp;
    uchar* tsField; /* parsed event-time field name; default "@timestamp" */
    /* Accepted event-time skew around the receive time, seconds. */
    int corrMaxAhead;
    int corrMaxBehind;
    int corrMode; /* 0 = match (default), 1 = contribution ingest */
    int peerIndex; /* this node's index in the owner ring */
    int peerCount; /* ring size; <=1 means local-only (no emit) */
    uchar* originId; /* optional origin string on emitted contribs */
    /* Input whose messages are contributions for this engine (the imtcp or
     * imrelp `name`). The receiving input sets it, the sender cannot. */
    uchar* contribInput;
    size_t contribInputLen;
    sbool contribAuthenticated; /* contribinput.authenticated="on" */

    /* Persistent accumulators for the correlation boundary counters (the engine
     * resets its internal tallies on (re)load; these carry the total across
     * generations).  corrStatsBase folds in each retired engine's final tally;
     * corrLoadAccum sums every successful load's loader tallies.  Mutated only
     * under corrRwlock write-held (or at single-threaded startup). */
    corr_stats_t corrStatsBase;
    corr_load_stats_t corrLoadAccum;

    /* Prevalence image, written by another process. HUP reloads it, and so does
     * the per-100-message stat: a rename changes inode, mtime, or size.
     * Unset => the field never resolves and a rule that references it is inert. */
    uchar* prevPath; /* Path to .prev (NULL = disabled) */
    enrich_t* prev; /* libenrich handle on prevPath; readers are per worker */
} instanceData;

typedef struct wrkrInstanceData {
    instanceData* pData;
    sigma_eval_t* eval; /* per-worker scratch, sized for db generation evalGen */
    uint64_t evalGen;
    mmsigma_reader_t* dbReader; /* registered on pData->dbReaders */
    /* per-worker scratch for corr_on_event fired-group value pointers, so no
     * fired-group storage is shared between concurrent workers. */
    const char* corrScratch[MMSIGMA_MAX_FIRES * CORR_MAX_GROUP_FIELDS];
    /* Terminated copies of the turbo values the correlator reads this event.
     * Per worker so the per-event field context stays small to initialise. */
    char corrVal[MMSIGMA_CORR_VAL_ARENA];
    enrich_reader_t* prevReader; /* this worker's view of pData->prev */
} wrkrInstanceData_t;

static const char* mmsigma_corr_field_fn(void* ctx, const char* name);
static const char* corr_type_str(corr_type_t t);

/* ---- config params (action level) ------------------------------------- */
static struct cnfparamdescr actpdescr[] = {
    {"database", eCmdHdlrString, 0},
    {"target", eCmdHdlrString, 0},
    {"reloadonhup", eCmdHdlrBinary, 0},
    /* folded correlation engine; all OPTIONAL, unset
     * corrfile => correlation disabled, full no-op. */
    {"corrfile", eCmdHdlrString, 0},
    {"corrmaxgroups", eCmdHdlrPositiveInt, 0},
    {"corrmaxdistinct", eCmdHdlrPositiveInt, 0},
    {"corrmaxeventspergroup", eCmdHdlrPositiveInt, 0},
    /* event-time correlation: order/window on the log's event time (default on).
     * timestampfield names the preferred parsed field (default "@timestamp");
     * the glue also tries time / timestamp / event.created and the syslog header. */
    {"uselogtimestamp", eCmdHdlrBinary, 0},
    {"timestampfield", eCmdHdlrString, 0},
    /* event time is clamped to [receive - corrmaxbehind, receive + corrmaxahead] */
    {"corrmaxahead", eCmdHdlrNonNegInt, 0},
    {"corrmaxbehind", eCmdHdlrNonNegInt, 0},
    /* prevalence rarity table; unset => rarity fields never resolve. */
    {"prevalence_db", eCmdHdlrString, 0},
    /* match (default) evaluates .sigmac + maybe emits
     * contributions; contribution ingests $!sigma_contribution / raw JSON. */
    {"mode", eCmdHdlrGetWord, 0},
    {"peerindex", eCmdHdlrInt, 0},
    {"peercount", eCmdHdlrInt, 0},
    {"origin", eCmdHdlrString, 0},
    /* name of the input that carries contributions into this engine */
    {"contribinput", eCmdHdlrString, 0},
    /* The operator states that every message that reaches this engine as
     * a contribution (the contribinput input, or every message under
     * mode="contribution") arrived over mutual TLS: StreamDriver.Mode="1",
     * StreamDriver.AuthMode="x509/name" and StreamDriver.PermittedPeers
     * naming the ring members. mmsigma cannot see how the input is set
     * up and does not start without this statement. Every peer that input
     * accepts is trusted to add to the correlation state. */
    {"contribinput.authenticated", eCmdHdlrBinary, 0},
};
static struct cnfparamblk actpblk = {CNFPARAMBLK_VERSION, sizeof(actpdescr) / sizeof(struct cnfparamdescr), actpdescr};

/* ---- artifact (re)loading --------------------------------------------- */
static mmsigma_db_t* load_sigmac(const char* path) {
    mmsigma_db_t* d = calloc(1, sizeof(*d));
    if (d == NULL) return NULL;
    if (sigma_db_load_file(path, &d->db) != SIGMA_OK) {
        free(d);
        return NULL;
    }
    return d;
}

static void free_sigmac(mmsigma_db_t* d) {
    if (d == NULL) return;
    sigma_db_free(&d->db);
    free(d);
}

/* Free the retired dbs every reader has passed: a db retired at tag t can
 * only be held by a reader whose epoch is below t. reloadMutex held. */
static void db_reclaim_locked(instanceData* pData) {
    uint64_t min = UINT64_MAX;
    for (mmsigma_reader_t* r = pData->dbReaders; r != NULL; r = r->next) {
        uint64_t ep = __atomic_load_n(&r->epoch, __ATOMIC_SEQ_CST);
        if (ep != 0 && ep < min) min = ep;
    }
    mmsigma_db_t** pp = &pData->dbRetired;
    while (*pp != NULL) {
        mmsigma_db_t* d = *pp;
        if (d->retire_tag <= min) {
            *pp = d->next;
            free_sigmac(d);
        } else {
            pp = &d->next;
        }
    }
}

/* Swap in d and retire the db it replaces. reloadMutex held. */
static void db_publish_locked(instanceData* pData, mmsigma_db_t* d) {
    d->gen = ++pData->dbGen;
    mmsigma_db_t* old = __atomic_exchange_n(&pData->dbCur, d, __ATOMIC_SEQ_CST);
    uint64_t tag = __atomic_add_fetch(&pData->dbGp, 1, __ATOMIC_SEQ_CST);
    if (old != NULL) {
        old->retire_tag = tag;
        old->next = pData->dbRetired;
        pData->dbRetired = old;
    }
    db_reclaim_locked(pData);
}

/* Publish the epoch before reading dbCur. The writer swaps dbCur before it
 * scans the epochs, so either it sees this epoch or this load sees the new
 * db. */
static const mmsigma_db_t* db_enter(instanceData* pData, mmsigma_reader_t* r) {
    __atomic_store_n(&r->epoch, __atomic_load_n(&pData->dbGp, __ATOMIC_ACQUIRE), __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    return __atomic_load_n(&pData->dbCur, __ATOMIC_ACQUIRE);
}

static void db_leave(mmsigma_reader_t* r) {
    __atomic_store_n(&r->epoch, 0, __ATOMIC_RELEASE);
}

/* Load the artifact and publish it. reloadMutex held. *sb is the stat taken
 * before the load: a write during the load leaves a newer mtime, and the
 * next check loads again. */
static rsRetVal reload_db_locked(instanceData* pData, const struct stat* sb) {
    DEFiRet;
    mmsigma_db_t* d = load_sigmac((const char*)pData->dbPath);
    if (d == NULL) {
        LogError(0, RS_RET_ERR, "mmsigma: reload FAILED, keeping current ruleset (%s)", pData->dbPath);
        ABORT_FINALIZE(RS_RET_ERR);
    }
    db_publish_locked(pData, d);
    if (sb != NULL) {
        pData->dbMtime = sb->st_mtime;
        pData->dbIno = sb->st_ino;
    }

    /* Gauge: RE predicates the current artifact could not compile (should be 0
     * with PCRE2, non-zero means a malformed |re: pattern is not matching). */
    ctrReSkipped = d->db.n_re_skipped;
    if (d->db.n_re_skipped > 0)
        LogMsg(0, RS_RET_OK, LOG_WARNING,
               "mmsigma: %u regex predicate(s) failed "
               "to compile and are disabled (impstats: regex.skipped)",
               d->db.n_re_skipped);
    LogMsg(0, RS_RET_OK, LOG_INFO, "mmsigma: ruleset reloaded (%u rules) from %s", d->db.n_rules, pData->dbPath);
finalize_it:
    RETiRet;
}

/* SIGHUP: reload unconditionally. */
static rsRetVal reloadSigmaDb(instanceData* pData) {
    struct stat sb;
    pthread_mutex_lock(&pData->reloadMutex);
    rsRetVal r = reload_db_locked(pData, stat((const char*)pData->dbPath, &sb) == 0 ? &sb : NULL);
    pthread_mutex_unlock(&pData->reloadMutex);
    return r;
}

/* Cheap mtime/inode check from the worker path. One worker checks at a time,
 * the others skip, so one change is one reload. The watermark advances only
 * on a successful load: a partial or truncated artifact is retried on the
 * next check. */
static void check_db_reload(instanceData* pData) {
    struct stat sb;
    if (pthread_mutex_trylock(&pData->reloadMutex) != 0) return;
    if (stat((const char*)pData->dbPath, &sb) == 0 && (sb.st_mtime != pData->dbMtime || sb.st_ino != pData->dbIno))
        (void)reload_db_locked(pData, &sb);
    db_reclaim_locked(pData);
    pthread_mutex_unlock(&pData->reloadMutex);
}

/* ---- folded correlation engine (re)loading ----------- */
static corr_caps_t corr_caps_from(const instanceData* pData) {
    corr_caps_t caps = corr_caps_default();
    if (pData->corrMaxGroups > 0) caps.max_groups = (uint32_t)pData->corrMaxGroups;
    if (pData->corrMaxDistinct > 0) caps.max_distinct = (uint32_t)pData->corrMaxDistinct;
    if (pData->corrMaxEventsPerGroup > 0) caps.max_events_per_group = (uint32_t)pData->corrMaxEventsPerGroup;
    caps.event_time_ordering = pData->useLogTimestamp ? 1 : 0;
    caps.watermark_s = pData->useLogTimestamp ? 2.0 : 0.0;
    return caps;
}

/* Receive time of the message this worker is evaluating, read by the engine
 * clock. Set around each corr_on_event_apply / corr_on_contribution call and
 * cleared after it. */
static __thread double mmsigma_clock_recv = 0.0;

/* Engine clock: the receive time rsyslog stamped on the current message, so
 * the sender cannot move it and a queued backlog keeps its own times. Wall
 * clock if a call path did not set it. */
static double mmsigma_corr_clock(void* ctx) {
    (void)ctx;
    if (mmsigma_clock_recv > 0.0) return mmsigma_clock_recv;
    struct timespec tsp;
    clock_gettime(CLOCK_REALTIME, &tsp);
    return (double)tsp.tv_sec + (double)tsp.tv_nsec / 1e9;
}

/* Event times come from outside rsyslog when they are parsed from the message
 * or carried by a peer's contribution. Then the engine sweeps on the receive
 * clock minus corrmaxbehind, so neither a sender nor a source that runs late
 * moves the sweep. Otherwise event time is the receive time and the engine
 * keeps sweeping on it, which keeps groups no longer than their window. */
static int corr_wants_clock(const instanceData* pData) {
    return pData->useLogTimestamp || pData->contribInput != NULL || pData->corrMode == 1;
}

/* Build a fresh (engine, artifact) pair from corrFile.  On success eOut/aOut
 * receive the new pair (the engine references the artifact's storage) and, when
 * lsOut is non-NULL, the loader's boundary tallies for this artifact. */
static int build_corr_engine(instanceData* pData,
                             corr_engine_t** eOut,
                             corr_artifact_t** aOut,
                             corr_load_stats_t* lsOut) {
    struct corr_artifact_view view;
    corr_artifact_t* art = corr_artifact_load_file((const char*)pData->corrFile, &view);
    if (art == NULL) return -1;
    corr_engine_t* eng = corr_engine_new(view.rules, view.n, corr_caps_from(pData));
    if (eng == NULL) {
        corr_artifact_free(art);
        return -1;
    }
    if (corr_wants_clock(pData) && corr_engine_set_clock(eng, mmsigma_corr_clock, NULL, (double)pData->corrMaxAhead,
                                                         (double)pData->corrMaxBehind) != 0) {
        corr_engine_free(eng);
        corr_artifact_free(art);
        return -1;
    }
    *eOut = eng;
    *aOut = art;
    if (lsOut != NULL) *lsOut = view.load;
    return 0;
}

/* acc += d for the engine boundary tallies (folded on engine retirement). */
static void corr_stats_accum(corr_stats_t* acc, const corr_stats_t* d) {
    acc->groups_evicted += d->groups_evicted;
    acc->distinct_evicted += d->distinct_evicted;
    acc->events_overwritten += d->events_overwritten;
    acc->fires_suppressed += d->fires_suppressed;
    acc->fires_truncated += d->fires_truncated;
    acc->rules_rejected += d->rules_rejected;
    acc->event_skipped_missing_field += d->event_skipped_missing_field;
    acc->seen_truncated += d->seen_truncated;
    acc->hits_truncated += d->hits_truncated;
    acc->group_evidence_dropped += d->group_evidence_dropped;
    acc->oom_dropped += d->oom_dropped;
    acc->values_nonnumeric += d->values_nonnumeric;
    acc->cond_over_arity += d->cond_over_arity;
    acc->watermark_late += d->watermark_late;
    acc->hotkey_fallback += d->hotkey_fallback;
}

/* Refresh the correlation impstats counters from `accumulated base + current
 * engine snapshot`.  Read-locks corrRwlock so the engine pointer stays valid
 * across the snapshot (the counters themselves are relaxed-atomic).  Cheap and
 * rare (called on reload + on the periodic reload-check cadence). */
static void publish_corr_stats(instanceData* pData) {
    corr_stats_t snap;
    memset(&snap, 0, sizeof(snap));
    pthread_rwlock_rdlock(&pData->corrRwlock);
    if (pData->corrEngine != NULL) corr_engine_stats(pData->corrEngine, &snap);
    const corr_stats_t* base = &pData->corrStatsBase;
    const corr_load_stats_t* ld = &pData->corrLoadAccum;
    ctrCorrGroupsEvicted = base->groups_evicted + snap.groups_evicted;
    ctrCorrDistinctEvicted = base->distinct_evicted + snap.distinct_evicted;
    ctrCorrEventsOverwritten = base->events_overwritten + snap.events_overwritten;
    ctrCorrFiresSuppressed = base->fires_suppressed + snap.fires_suppressed;
    ctrCorrFiresTruncated = base->fires_truncated + snap.fires_truncated;
    /* rules.rejected = engine admit-rejects (base+snap) + loader JSON-rejects. */
    ctrCorrRulesRejected = base->rules_rejected + snap.rules_rejected + ld->rules_rejected;
    ctrCorrEvtSkippedMissing = base->event_skipped_missing_field + snap.event_skipped_missing_field;
    ctrCorrSeenTruncated = base->seen_truncated + snap.seen_truncated;
    ctrCorrHitsTruncated = base->hits_truncated + snap.hits_truncated;
    ctrCorrGroupEvidenceDropped = base->group_evidence_dropped + snap.group_evidence_dropped;
    ctrCorrOomDropped = base->oom_dropped + snap.oom_dropped;
    ctrCorrValuesNonnumeric = base->values_nonnumeric + snap.values_nonnumeric;
    ctrCorrCondOverArity = base->cond_over_arity + snap.cond_over_arity;
    ctrCorrWatermarkLate = base->watermark_late + snap.watermark_late;
    ctrCorrHotkeyFallback = base->hotkey_fallback + snap.hotkey_fallback;
    ctrCorrGroupbyTruncated = ld->groupby_truncated;
    ctrCorrBaserulesTruncated = ld->baserules_truncated;
    ctrCorrRidsDropped = ld->rids_dropped;
    pthread_rwlock_unlock(&pData->corrRwlock);
}

static rsRetVal reloadCorrEngine(instanceData* pData) {
    DEFiRet;
    corr_engine_t* newEng = NULL;
    corr_artifact_t* newArt = NULL;
    corr_engine_t* oldEng;
    corr_artifact_t* oldArt;
    corr_load_stats_t ls;

    if (build_corr_engine(pData, &newEng, &newArt, &ls) != 0) {
        LogError(0, RS_RET_ERR, "mmsigma: correlation reload FAILED, keeping current (%s)", pData->corrFile);
        ABORT_FINALIZE(RS_RET_ERR);
    }

    pthread_rwlock_wrlock(&pData->corrRwlock);
    oldEng = pData->corrEngine;
    oldArt = pData->corrArtifact;
    /* Fold the retiring engine's final boundary tally into the persistent base
     * (its internal counters die with it), and add this load's loader tally,
     * before swapping, so the published impstats totals span all generations. */
    if (oldEng != NULL) {
        corr_stats_t s;
        corr_engine_stats(oldEng, &s);
        corr_stats_accum(&pData->corrStatsBase, &s);
    }
    pData->corrLoadAccum.rules_rejected += ls.rules_rejected;
    pData->corrLoadAccum.groupby_truncated += ls.groupby_truncated;
    pData->corrLoadAccum.baserules_truncated += ls.baserules_truncated;
    pData->corrLoadAccum.rids_dropped += ls.rids_dropped;
    pData->corrEngine = newEng;
    pData->corrArtifact = newArt;
    pthread_rwlock_unlock(&pData->corrRwlock);

    /* The write lock drained all in-flight readers before the swap, so no worker
     * can still hold the old engine once it is released; freeing it now is safe.
     * In-flight window state is dropped on reload (correlations re-accumulate
     * within their window, same semantics as the Python
     * SigmaCorrelationEngine.load()). */
    if (oldEng != NULL) corr_engine_free(oldEng);
    if (oldArt != NULL) corr_artifact_free(oldArt);

    publish_corr_stats(pData);
    LogMsg(0, RS_RET_OK, LOG_INFO, "mmsigma: correlations reloaded (%zu rules) from %s", corr_engine_rule_count(newEng),
           pData->corrFile);
finalize_it:
    RETiRet;
}

/* Cheap mtime check for the correlation artifact; same watermark-on-success
 * discipline as check_db_reload (a partial/truncated mid-transfer artifact is
 * retried on the next check rather than stranding the edge on stale state). */
static void check_corr_reload(instanceData* pData) {
    struct stat sb;
    if (stat((const char*)pData->corrFile, &sb) != 0) return;
    if (sb.st_mtime == pData->corrMtime) return;
    if (reloadCorrEngine(pData) == RS_RET_OK) pData->corrMtime = sb.st_mtime;
}

static int mmsigma_apply_owned(void* ctx, const corr_rule_t* r, const char* const* g, size_t n) {
    instanceData* p = (instanceData*)ctx;
    if (p->peerCount <= 1) return 1;
    if (corr_contrib_kind_for(r->type) < 0) return 1;
    return corr_owner_index(r->id, g, n, (size_t)p->peerCount) == (size_t)p->peerIndex;
}

static uint64_t mmsigma_seen_mask(const corr_rule_t* r, const uint32_t* rids, size_t n_rids) {
    uint64_t mask = 0;
    size_t nb = r->n_base_rule_ids < 64 ? r->n_base_rule_ids : 64;
    size_t b, k;
    for (b = 0; b < nb; b++) {
        for (k = 0; k < n_rids; k++)
            if (rids[k] == r->base_rule_ids[b]) {
                mask |= (1ull << b);
                break;
            }
    }
    return mask;
}

static void mmsigma_emit_contribs(
    instanceData* pData, corr_engine_t* eng, void* fc, const uint32_t* rids, size_t n_rids, double ts, smsg_t* pMsg) {
    struct json_object* jarr;
    size_t nr, i;
    if (pData->peerCount <= 1 || eng == NULL) return;
    jarr = json_object_new_array();
    if (!jarr) return;
    nr = corr_engine_rule_count(eng);
    for (i = 0; i < nr; i++) {
        const corr_rule_t* r = corr_engine_rule_at(eng, i);
        int kind;
        const char* const* gfields;
        const char* gvals[CORR_MAX_GROUP_FIELDS];
        size_t g;
        corr_contrib_t c;
        struct json_object* jo;
        if (!r || corr_rule_hits(r, rids, n_rids) == 0) continue;
        kind = corr_contrib_kind_for(r->type);
        if (kind < 0) continue;
        gfields = mmsigma_contrib_group_fields(r, rids, n_rids);
        for (g = 0; g < r->n_group_by && g < CORR_MAX_GROUP_FIELDS; g++) {
            gvals[g] = gfields != NULL ? mmsigma_corr_field_fn(fc, gfields[g]) : NULL;
            if (gvals[g] == NULL) break;
        }
        if (g < r->n_group_by) continue;
        if (corr_owner_index(r->id, gvals, r->n_group_by, (size_t)pData->peerCount) == (size_t)pData->peerIndex)
            continue;
        memset(&c, 0, sizeof(c));
        c.kind = (corr_contrib_kind_t)kind;
        c.corr_id = r->id;
        c.group_vals = gvals;
        c.n_group = r->n_group_by;
        c.ts = ts;
        if (kind == (int)CORR_CONTRIB_COUNT) c.count = 1;
        /* Send no value the owner's engine would skip on a local event. */
        if (kind == (int)CORR_CONTRIB_SUM) {
            const char* vs = r->value_field ? mmsigma_corr_field_fn(fc, r->value_field) : NULL;
            if (!mmsigma_contrib_number(vs, &c.numeric)) continue;
            c.count = 1;
        }
        if (kind == (int)CORR_CONTRIB_DISTINCT) {
            c.value = r->value_field ? mmsigma_corr_field_fn(fc, r->value_field) : NULL;
            if (c.value == NULL) continue;
        }
        if (kind == (int)CORR_CONTRIB_SEEN) c.seen_mask = mmsigma_seen_mask(r, rids, n_rids);
        jo = corr_contrib_to_json(&c, pData->originId ? (const char*)pData->originId : NULL);
        if (jo) {
            json_object_array_add(jarr, jo);
            STATSCOUNTER_INC(ctrCorrContribEmit, mutCtrCorrContribEmit);
        } else {
            STATSCOUNTER_INC(ctrCorrContribEmitFailed, mutCtrCorrContribEmitFailed);
        }
    }
    if (json_object_array_length(jarr) > 0) {
        if (msgAddJSON(pMsg, (uchar*)"!sigma_contribution", jarr, 0, 0) != RS_RET_OK) json_object_put(jarr);
    } else {
        json_object_put(jarr);
    }
}

/* The time this peer received the message: rsyslog stamps it, the sender
 * cannot set it. */
static double mmsigma_recv_time(const smsg_t* pMsg) {
    if (pMsg != NULL && pMsg->ttGenTime > 0) return (double)pMsg->ttGenTime;
    struct timespec tsp;
    clock_gettime(CLOCK_REALTIME, &tsp);
    return (double)tsp.tv_sec + (double)tsp.tv_nsec / 1e9;
}

/* Clamp a sender-supplied time to the accepted skew around the receive time.
 * The engine clock applies the same bounds; this copy keeps the live
 * corr.timestamp counters. ahead stays small: with event-time ordering it
 * bounds how far one event can raise its group's watermark. */
static double mmsigma_bound_time(const instanceData* pData, double ts, double recv) {
    if (!isfinite(ts)) {
        STATSCOUNTER_INC(ctrCorrTsFallback, mutCtrCorrTsFallback);
        return recv;
    }
    if (ts > recv + (double)pData->corrMaxAhead) {
        STATSCOUNTER_INC(ctrCorrTsAhead, mutCtrCorrTsAhead);
        return recv + (double)pData->corrMaxAhead;
    }
    if (ts < recv - (double)pData->corrMaxBehind) {
        STATSCOUNTER_INC(ctrCorrTsBehind, mutCtrCorrTsBehind);
        return recv - (double)pData->corrMaxBehind;
    }
    return ts;
}

static void mmsigma_ingest_one(
    instanceData* pData, wrkrInstanceData_t* pWrkrData, corr_engine_t* eng, json_object* j, smsg_t* pMsg) {
    corr_contrib_t c;
    const char* slots[CORR_MAX_GROUP_FIELDS];
    corr_fire_t fires[MMSIGMA_MAX_FIRES];
    int nf, k;
    if (corr_contrib_from_json(j, &c, slots, CORR_MAX_GROUP_FIELDS) != 0) {
        STATSCOUNTER_INC(ctrCorrContribDrop, mutCtrCorrContribDrop);
        return;
    }
    /* Static ring: refuse a contrib whose owner is not this peer.
     * omfwd linear-probe is transport, not ownership. Applying a
     * mis-routed partial would split-brain when the real owner
     * returns. peercount<=1 stays local-only (no check). */
    if (pData->peerCount > 1 &&
        corr_owner_index(c.corr_id, c.group_vals, c.n_group, (size_t)pData->peerCount) != (size_t)pData->peerIndex) {
        STATSCOUNTER_INC(ctrCorrContribDrop, mutCtrCorrContribDrop);
        return;
    }
    STATSCOUNTER_INC(ctrCorrContribIngest, mutCtrCorrContribIngest);
    const double recv = mmsigma_recv_time(pMsg);
    c.ts = mmsigma_bound_time(pData, c.ts, recv);
    mmsigma_clock_recv = recv;
    nf = corr_on_contribution(eng, &c, NULL, NULL, fires, MMSIGMA_MAX_FIRES, pWrkrData->corrScratch,
                              sizeof(pWrkrData->corrScratch) / sizeof(pWrkrData->corrScratch[0]));
    mmsigma_clock_recv = 0.0;
    if (nf <= 0) return;
    {
        int fcapped = (nf < MMSIGMA_MAX_FIRES) ? nf : MMSIGMA_MAX_FIRES;
        struct json_object* jOut = json_object_new_object();
        struct json_object* jArr = json_object_new_array();
        for (k = 0; k < fcapped; k++) {
            const corr_fire_t* f = &fires[k];
            struct json_object* jc = json_object_new_object();
            if (f->rule_id) json_object_object_add(jc, "rule_id", json_object_new_string(f->rule_id));
            if (f->title) json_object_object_add(jc, "title", json_object_new_string(f->title));
            json_object_object_add(jc, "type", json_object_new_string(corr_type_str(f->type)));
            json_object_object_add(jc, "remote", json_object_new_boolean(f->remote));
            json_object_object_add(jc, "observed", json_object_new_int64(f->observed));
            json_object_object_add(jc, "threshold", json_object_new_int64(f->threshold));
            json_object_object_add(jc, "fidelity_tier", json_object_new_string(corr_tier_name(f->tier)));
            json_object_array_add(jArr, jc);
        }
        json_object_object_add(jOut, "matched", json_object_new_boolean(1));
        json_object_object_add(jOut, "count", json_object_new_int(nf));
        json_object_object_add(jOut, "correlations", jArr);
        if (msgAddJSON(pMsg, (uchar*)"!sigma_correlation", jOut, 0, 0) != RS_RET_OK) json_object_put(jOut);
    }
}

static int mmsigma_do_contrib(instanceData* pData, wrkrInstanceData_t* pWrkrData, smsg_t* pMsg) {
    uchar* pRaw = NULL;
    int lenRaw = 0;
    struct json_object* root;
    corr_engine_t* eng;
    getRawMsg(pMsg, &pRaw, &lenRaw);
    if (pRaw == NULL || lenRaw <= 0) return 0;
    {
        char* tmp = malloc((size_t)lenRaw + 1);
        const char* brace;
        if (!tmp) return 0;
        memcpy(tmp, pRaw, (size_t)lenRaw);
        tmp[lenRaw] = '\0';
        root = json_tokener_parse(tmp);
        if (root == NULL) {
            brace = strchr(tmp, '{');
            if (brace) root = json_tokener_parse(brace);
        }
        free(tmp);
    }
    if (root == NULL) {
        STATSCOUNTER_INC(ctrCorrContribDrop, mutCtrCorrContribDrop);
        return 0;
    }
    pthread_rwlock_rdlock(&pData->corrRwlock);
    eng = pData->corrEngine;
    if (eng != NULL) {
        if (json_object_is_type(root, json_type_array)) {
            size_t n = (size_t)json_object_array_length(root);
            size_t i;
            for (i = 0; i < n; i++)
                mmsigma_ingest_one(pData, pWrkrData, eng, json_object_array_get_idx(root, (int)i), pMsg);
        } else {
            mmsigma_ingest_one(pData, pWrkrData, eng, root, pMsg);
        }
    }
    pthread_rwlock_unlock(&pData->corrRwlock);
    json_object_put(root);
    return 1;
}

/* Reload the prevalence image when the file's inode, size or mtime changed.
 * libenrich keeps a replaced table mapped until every worker's reader has
 * moved past it. A failed reload keeps the current table. */
static void reloadPrevalenceDb(instanceData* pData) {
    unsigned changed = 0;
    char err[512];
    int rc;
    if (pData->prev == NULL) return;
    err[0] = '\0';
    rc = enrich_reload(pData->prev, &changed, err, sizeof err);
    if (changed & ENRICH_C_PREV) {
        enrich_reader_t* rd = enrich_reader_new(pData->prev);
        enrich_info_t info;
        if (rd != NULL) {
            enrich_snap_info(enrich_reader_enter(rd), &info);
            enrich_reader_free(rd);
            LogMsg(0, RS_RET_OK, LOG_INFO, "mmsigma/prev: reloaded %u entries (count_max=%u)", info.prev_entries,
                   info.prev_count_max);
        }
    }
    if (rc != ENRICH_OK && rc != ENRICH_ENOENT) DBGPRINTF("mmsigma/prev: reload kept the current table: %s\n", err);
}

/* ---- field resolution: matcher callback over the turbo result ----------
 * Truly zero-copy: the .sigmac contract guarantees every field NAME in the
 * strpool is NUL-terminated (validated at load: a non-terminated artifact is
 * rejected).  The matcher therefore hands us `db->strpool + off`, already a
 * valid C string, so we pass it straight to ln_fast_result_get_string(), no
 * bounce buffer, no copy, no length guard.  `name_len` is unused here. */
/* Per-event field-resolution context: the zero-copy turbo arena
 * result PLUS the $! enrichment root.  geoip, cti and tls.ja4 fields are
 * produced by mmenrich into $! (NOT the turbo arena), so a rule referencing them
 * resolves on arena-miss against `enrich`.  `enrich` is the BORROWED pMsg->json
 * root (no deep copy): mmenrich's msgAddJSON already populated it, and the msg
 * is owned by this worker for the whole doAction, so the borrowed pointer stays
 * valid across the match.  NULL when the message carries no $! tree yet. */
typedef struct {
#ifdef HAVE_LOGNORM_TURBO
    const ln_fast_result_t* r; /* turbo arena (parsed fields, zero-copy) */
#else
    const void* r; /* unused; $! fallback only */
#endif
    struct json_object* enrich; /* borrowed $! root, or NULL */
    const char* rawmsg; /* pristine raw event line, event.original fallback; NULL if absent */
    size_t rawmsg_len;
    /* Bump arena for COMPUTED field values (ecs_derive numerics +
     * prevalence). resolve_field MEMOIZES the returned pointer, not a copy, so a
     * single shared scratch would let a later computed field overwrite an
     * earlier field's still-cached value (e.g. digit_ratio clobbering entropy),
     * silently failing any rule that reads the earlier field from the memo.
     * Each computed resolution instead gets its OWN slot here; reset per event.
     * SLICE derives (url.path) borrow the arena/$! and consume no slot. */
    char derive_arena[ECS_DERIVE_BUFSZ * MMSIGMA_DERIVE_SLOTS];
    size_t derive_off; /* next free byte in derive_arena */
    /* prevalence table for the event (borrowed from the loaded snapshot;
     * NULL => rarity fields do not resolve). */
    const enrich_snap_t* prev; /* .prev snapshot of this worker, or NULL */
    /* Correlation values: bump arena (the worker's corrVal) and a memo of the
     * names already copied this event, so a group-by shared by several
     * correlations is copied once. */
    char* corr_arena;
    size_t corr_cap;
    size_t corr_off;
    uint32_t corr_n;
    struct {
        const char* name;
        const char* val;
    } corr_memo[MMSIGMA_CORR_VAL_MEMO];
} mmsigma_fieldctx_t;

#ifdef HAVE_LOGNORM_TURBO
static int mmsigma_turbo_get(const ln_fast_result_t* r, const char* name, const char** val, size_t* vlen) {
    if (r == NULL) return 0;
    return ln_fast_result_get_string(r, name, val, vlen) == 0;
}
#else
static int mmsigma_turbo_get(const void* r, const char* name, const char** val, size_t* vlen) {
    (void)r;
    (void)name;
    (void)val;
    (void)vlen;
    return 0;
}
#endif

/* Next COMPUTED-value slot in the per-event arena; wraps to the start when a
 * full ECS_DERIVE_BUFSZ no longer fits (bounded reuse: a single event resolves
 * far fewer computed fields than MMSIGMA_DERIVE_SLOTS, so the wrap is dead code
 * in practice and only ever sacrifices the oldest cached computed value). */
static inline char* mmsigma_derive_slot(mmsigma_fieldctx_t* fc) {
    if (fc->derive_off + ECS_DERIVE_BUFSZ > sizeof(fc->derive_arena)) fc->derive_off = 0;
    return fc->derive_arena + fc->derive_off;
}

/* ECS event.original: the pristine raw log line. Fieldless Sigma keyword
 * (full-message) searches lower to ordinary predicates on this field, so the
 * resolver below guarantees it always resolves (parser value if present, else
 * the raw message). */
#define MMSIGMA_EVENT_ORIGINAL "event.original"
#define MMSIGMA_EVENT_ORIGINAL_LEN 14

static const char* mmsigma_enrich_lookup(struct json_object* root, const char* name, size_t* out_len);

/* ecs_derive source-reader: adapts ln_fast_result_get_string to ecs_src_get_fn
 * (1 on hit). Lets a derived field (e.g. url.path) read its source (url.original)
 * from the zero-copy snapshot, or from the $! tree when the arena is absent. */
static int mmsigma_src_get(void* ctx, const char* name, const char** val, size_t* vlen) {
    const mmsigma_fieldctx_t* fc = (const mmsigma_fieldctx_t*)ctx;
    if (mmsigma_turbo_get(fc->r, name, val, vlen)) return 1;
    if (fc->enrich != NULL) {
        size_t elen = 0;
        const char* ev = mmsigma_enrich_lookup(fc->enrich, name, &elen);
        if (ev != NULL) {
            *val = ev;
            *vlen = elen;
            return 1;
        }
    }
    return 0;
}

/* Resolve a dotted field name (e.g. "source.geo.country_name") against the
 * borrowed $! enrichment root, walking each '.'-segment as a nested-object key
 *, a couple of O(1) json_object_object_get_ex hash-gets, no per-field root
 * re-fetch.  Returns the leaf value as a C string (NUL-terminated; libfastjson
 * renders non-string leaves like ints) valid for this event, or NULL. */
static const char* mmsigma_enrich_lookup(struct json_object* root, const char* name, size_t* out_len) {
    if (root == NULL || name == NULL) return NULL;
    struct json_object* cur = root;
    const char* seg = name;
    for (;;) {
        const char* dot = strchr(seg, '.');
        size_t klen = dot ? (size_t)(dot - seg) : strlen(seg);
        if (klen == 0 || klen >= 128) return NULL;
        char key[128];
        memcpy(key, seg, klen);
        key[klen] = '\0';
        struct json_object* next = NULL;
        if (!json_object_object_get_ex(cur, key, &next)) return NULL;
        if (dot == NULL) { /* leaf segment */
            if (json_object_is_type(next, json_type_object) || json_object_is_type(next, json_type_array)) return NULL;
            const char* v = json_object_get_string(next);
            if (v == NULL) return NULL;
            *out_len = strlen(v);
            return v;
        }
        if (!json_object_is_type(next, json_type_object)) return NULL; /* more segments but not an object */
        cur = next;
        seg = dot + 1;
    }
}

static const char* mmsigma_field_fn(void* ctx, const char* name, uint32_t name_len, size_t* out_len) {
    mmsigma_fieldctx_t* fc = (mmsigma_fieldctx_t*)ctx; /* non-const: computed derives write derive_buf */
    const char* val = NULL;
    size_t vlen = 0;

    (void)name_len;
    *out_len = 0;
    if (fc == NULL) return NULL;
    /* Zero-copy arena first; fc->r may be NULL when the message lost its turbo
     * snapshot (duplicating queue boundary, disk-queue replay), every lookup
     * then falls through to the derive/$! chain below, which resolves against
     * the already-materialized $! tree with identical semantics. */
    if (mmsigma_turbo_get(fc->r, name, &val, &vlen)) {
        *out_len = vlen;
        return val;
    }
    /* Arena miss: try an ECS derivation. E.g. a rule on
     * url.path resolves against url.original when no rulebase emits the
     * path field directly. Zero-copy, the derived slice points into the
     * source value already in the arena (or the $! tree in fallback). */
    {
        const char* dval = NULL;
        size_t dlen = 0;
        char* slot = mmsigma_derive_slot(fc);
        if (ecs_derive_lookup(name, mmsigma_src_get, (void*)fc, &dval, &dlen, slot, ECS_DERIVE_BUFSZ)) {
            /* COMPUTED transforms write into slot (consume it so a later
             * computed field can't overwrite this one's memoized pointer);
             * SLICE transforms borrow the arena/$! and consume nothing. */
            if (dval == slot) fc->derive_off += dlen + 1;
            *out_len = dlen;
            return dval;
        }
    }
    /* Prevalence: resolve <field>_prevalence (total count) and
     * <field>_prevalence_edges (DISTINCT edges = spread-rarity) from the .prev table.
     * mmenrich emits the same facts into $! for the enriched output; resolving
     * them here from the parsed arena keeps rule matching on the fast path and
     * off any cross-module $! ordering (the same reason entropy is computed here
     * rather than read back from $!). Skipped while the table is unwarmed
     * (count_max==0) so a cold table never scores every value as rare. */
    if (fc->prev != NULL) {
        static const char SUF_COUNT[] = "_prevalence";
        static const char SUF_EDGES[] = "_prevalence_edges";
        static const char SUF_SRCS[] = "_prevalence_sources";
        const size_t lc = sizeof(SUF_COUNT) - 1, le = sizeof(SUF_EDGES) - 1, ls = sizeof(SUF_SRCS) - 1;
        int want = -1; /* 0 = total count, 1 = distinct-edge spread, 2 = distinct-source spread */
        size_t suflen = 0;
        if ((size_t)name_len > lc && memcmp(name + name_len - lc, SUF_COUNT, lc) == 0) {
            want = 0;
            suflen = lc;
        } else if ((size_t)name_len > le && memcmp(name + name_len - le, SUF_EDGES, le) == 0) {
            want = 1;
            suflen = le;
        } else if ((size_t)name_len > ls && memcmp(name + name_len - ls, SUF_SRCS, ls) == 0) {
            want = 2;
            suflen = ls;
        }
        if (want >= 0) {
            char base[256];
            size_t blen = (size_t)name_len - suflen;
            if (blen < sizeof(base)) {
                memcpy(base, name, blen);
                base[blen] = '\0';
                /* Resolve the base observable through the full chain (turbo arena
                 * when present, else the $! tree into which parser fields are
                 * materialized at a queue boundary) so rarity resolves on EVERY
                 * event, not only the arena-present minority. base carries no
                 * rarity suffix, so this never recurses into this block. */
                size_t bvlen = 0;
                const char* bv = mmsigma_field_fn(ctx, base, (uint32_t)blen, &bvlen);
                enrich_prev_t pv;
                /* 1 only for a warmed table: a cold table never scores
                 * every value as rare. */
                if (bv != NULL && bvlen > 0 && bvlen < 256 && enrich_prevalence(fc->prev, bv, bvlen, &pv) == 1) {
                    uint32_t metric = (want == 2) ? (uint32_t)pv.sources : (want == 1) ? (uint32_t)pv.edges : pv.count;
                    char* slot = mmsigma_derive_slot(fc);
                    int n = snprintf(slot, ECS_DERIVE_BUFSZ, "%u", metric);
                    if (n > 0) {
                        fc->derive_off += (size_t)n + 1;
                        *out_len = (size_t)n;
                        return slot;
                    }
                }
            }
        }
    }
    /* Still absent: try the $! enrichment root. geoip.*, cti.*,
     * tls.ja4 are emitted by mmenrich into $!, not the arena. Parsed-field
     * matching above stays zero-copy; only this enrichment minority pays the
     * cached-$! lookup. */
    if (fc->enrich != NULL) {
        size_t elen = 0;
        const char* ev = mmsigma_enrich_lookup(fc->enrich, name, &elen);
        if (ev != NULL) {
            *out_len = elen;
            return ev;
        }
    }
    /* event.original fallback: fieldless keyword rules resolve here. A parser
     * value (arena / $! above) wins; otherwise return the pristine raw line so a
     * keyword rule still matches the full message. The name[0]=='e' guard keeps
     * this off the hot path for every other absent field. */
    if (fc->rawmsg != NULL && name[0] == 'e' && name_len == MMSIGMA_EVENT_ORIGINAL_LEN &&
        memcmp(name, MMSIGMA_EVENT_ORIGINAL, MMSIGMA_EVENT_ORIGINAL_LEN) == 0) {
        *out_len = fc->rawmsg_len;
        return fc->rawmsg;
    }
    return NULL; /* field absent, not derivable, not enriched */
}

static const char* verdict_name(uint8_t v) {
    switch (v) {
        case SIGMA_VERDICT_BENIGN:
            return "benign";
        case SIGMA_VERDICT_ESCALATE:
            return "escalate";
        default:
            return "alert";
    }
}

/* Correlation group-by / value field resolver. The engine's callback returns
 * a C string: libsigma calls strlen, strcmp and strtod on it and keeps the
 * pointer as group evidence until the fires are serialised. It resolves over
 * the same field context as mmsigma_field_fn: the turbo arena first, then the
 * $! tree when the arena is absent.
 *
 * liblognorm keeps a turbo value of 48 bytes or more as a pointer and length
 * into the message, with no terminator, so the value is copied, terminated,
 * into the per-event arena. A value that does not fit is treated as absent
 * (corr.value.overflow) rather than cut, which would merge distinct groups.
 * $! values are json-c strings and already terminated. */
static const char* mmsigma_corr_field_fn(void* ctx, const char* name) {
    mmsigma_fieldctx_t* fc = (mmsigma_fieldctx_t*)ctx;
    const char* val = NULL;
    size_t vlen = 0;
    if (fc == NULL || name == NULL) return NULL;
    for (uint32_t i = 0; i < fc->corr_n; i++)
        if (fc->corr_memo[i].name == name || strcmp(fc->corr_memo[i].name, name) == 0) return fc->corr_memo[i].val;
    if (mmsigma_turbo_get(fc->r, name, &val, &vlen)) {
        if (fc->corr_arena == NULL || vlen >= fc->corr_cap - fc->corr_off) {
            STATSCOUNTER_INC(ctrCorrValOverflow, mutCtrCorrValOverflow);
            return NULL;
        }
        char* dst = fc->corr_arena + fc->corr_off;
        memcpy(dst, val, vlen);
        dst[vlen] = '\0';
        fc->corr_off += vlen + 1;
        if (fc->corr_n < MMSIGMA_CORR_VAL_MEMO) {
            fc->corr_memo[fc->corr_n].name = name;
            fc->corr_memo[fc->corr_n].val = dst;
            fc->corr_n++;
        }
        return dst;
    }
    if (fc->enrich != NULL) return mmsigma_enrich_lookup(fc->enrich, name, &vlen);
    return NULL;
}

/* Length-aware field lookup + parse. Turbo values are not always NUL-terminated
 * so we never strlen() a turbo pointer. */
static int mmsigma_parse_named_time(mmsigma_fieldctx_t* fc, const char* name, time_t now, double* out) {
    if (fc == NULL || name == NULL || name[0] == '\0') return 0;
    size_t vlen = 0;
    const char* v = mmsigma_field_fn((void*)fc, name, (uint32_t)strlen(name), &vlen);
    if (v == NULL || vlen == 0) return 0;
    return event_time_parse(v, vlen, now, out);
}

static int mmsigma_syslogtime_epoch(const struct syslogTime* st, double* out) {
    if (st == NULL || st->year < 1970 || st->month < 1 || st->month > 12 || st->day < 1) return 0;
    double se = (double)st->second;
    if (st->secfracPrecision > 0 && st->secfrac > 0) {
        double den = 1.0;
        int p = st->secfracPrecision;
        while (p-- > 0) den *= 10.0;
        se += (double)st->secfrac / den;
    }
    int off = (int)st->OffsetHour * 60 + (int)st->OffsetMinute;
    if (st->OffsetMode == '-')
        off = -off;
    else if (st->OffsetMode != '+')
        off = 0;
    return event_time_from_civil(st->year, st->month, st->day, st->hour, st->minute, se, off, out);
}

/* Resolve the correlation clock. Prefer a parsed event-time field (configured
 * name, then the well-known aliases our rulebases actually emit), then compose
 * nginx-error event.date+event.time, then rsyslog's msg timestamp (syslog
 * header). CLOCK_MONOTONIC is the last resort and is counted as fallback. */
static int mmsigma_resolve_event_time(instanceData* pData, mmsigma_fieldctx_t* fc, smsg_t* pMsg, double* ts) {
    time_t now = time(NULL);
    if (pData->tsField != NULL && mmsigma_parse_named_time(fc, (const char*)pData->tsField, now, ts)) return 1;
    static const char* alts[] = {"@timestamp", "time", "timestamp", "event.created", NULL};
    for (int i = 0; alts[i] != NULL; i++) {
        if (pData->tsField != NULL && strcmp((const char*)pData->tsField, alts[i]) == 0) continue;
        if (mmsigma_parse_named_time(fc, alts[i], now, ts)) return 1;
    }
    size_t dlen = 0, tlen = 0;
    const char* d = mmsigma_field_fn((void*)fc, "event.date", 10, &dlen);
    const char* t = mmsigma_field_fn((void*)fc, "event.time", 10, &tlen);
    if (d != NULL && t != NULL && dlen > 0 && tlen > 0 && dlen + tlen + 2 < 64) {
        char buf[64];
        memcpy(buf, d, dlen);
        buf[dlen] = ' ';
        memcpy(buf + dlen + 1, t, tlen);
        buf[dlen + 1 + tlen] = '\0';
        if (event_time_parse(buf, dlen + 1 + tlen, now, ts)) return 1;
    }
    if (pMsg != NULL && mmsigma_syslogtime_epoch(&pMsg->tTIMESTAMP, ts)) {
        STATSCOUNTER_INC(ctrCorrTsSyslog, mutCtrCorrTsSyslog);
        return 1;
    }
    return 0;
}

static const char* corr_type_str(corr_type_t t) {
    switch (t) {
        case CORR_EVENT_COUNT:
            return "event_count";
        case CORR_VALUE_COUNT:
            return "value_count";
        case CORR_TEMPORAL:
            return "temporal";
        case CORR_TEMPORAL_ORDERED:
            return "temporal_ordered";
        case CORR_VALUE_SUM:
            return "value_sum";
        case CORR_VALUE_AVG:
            return "value_avg";
        case CORR_BEACONING:
            return "beaconing";
        case CORR_VALUE_PERCENTILE:
            return "value_percentile";
        case CORR_VALUE_MEDIAN:
            return "value_median";
        case CORR_TYPE__MAX:
        default:
            return "unknown";
    }
}

/* ---- module plumbing --------------------------------------------------- */
BEGINcreateInstance
    CODESTARTcreateInstance;
    pData->dbPath = NULL;
    pData->targetPath = NULL;
    pData->reloadOnHup = 1;
    pData->dbCur = NULL;
    pData->dbGp = 1;
    pData->dbGen = 0;
    pData->dbRetired = NULL;
    pData->dbReaders = NULL;
    pData->dbMtime = 0;
    pData->dbIno = 0;
    pthread_mutex_init(&pData->reloadMutex, NULL);
    pData->corrFile = NULL;
    pData->corrEngine = NULL;
    pData->corrArtifact = NULL;
    pData->corrMtime = 0;
    pData->corrMaxGroups = 0;
    pData->corrMaxDistinct = 0;
    pData->corrMaxEventsPerGroup = 0;
    pData->corrMaxAhead = 5;
    pData->corrMaxBehind = 3600;
    pData->useLogTimestamp = 1; /* event-time windows; missing ts falls back */
    pData->tsField = NULL;
    pData->corrMode = 0;
    pData->peerIndex = 0;
    pData->peerCount = 1;
    pData->originId = NULL;
    pData->contribInput = NULL;
    pData->contribInputLen = 0;
    pData->prevPath = NULL;
    pData->prev = NULL;
    memset(&pData->corrStatsBase, 0, sizeof(pData->corrStatsBase));
    memset(&pData->corrLoadAccum, 0, sizeof(pData->corrLoadAccum));
    pthread_rwlock_init(&pData->corrRwlock, NULL);
ENDcreateInstance

BEGINcreateWrkrInstance
    CODESTARTcreateWrkrInstance;
    pWrkrData->eval = NULL;
    pWrkrData->evalGen = 0;
    pWrkrData->prevReader = NULL;
    {
        void* mem = NULL;
        if (posix_memalign(&mem, 64, sizeof(mmsigma_reader_t)) != 0) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
        pWrkrData->dbReader = (mmsigma_reader_t*)mem;
        pWrkrData->dbReader->epoch = 0;
        pthread_mutex_lock(&pWrkrData->pData->reloadMutex);
        pWrkrData->dbReader->next = pWrkrData->pData->dbReaders;
        pWrkrData->pData->dbReaders = pWrkrData->dbReader;
        pthread_mutex_unlock(&pWrkrData->pData->reloadMutex);
    }
    if (pWrkrData->pData->prev != NULL) {
        pWrkrData->prevReader = enrich_reader_new(pWrkrData->pData->prev);
        if (pWrkrData->prevReader == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
finalize_it:
ENDcreateWrkrInstance

BEGINfreeInstance
    CODESTARTfreeInstance;
    /* Hold both locks across teardown so a SIGTERM racing an in-flight HUP
     * reload cannot double-free the current or a retired db, the corr pair, or a deferred .prev
     * snapshot (same race mmenrich already serialises). Drain corr readers
     * with the write lock before freeing the engine. NULL after free so a
     * stray second pass is a no-op. */
    pthread_mutex_lock(&pData->reloadMutex);
    pthread_rwlock_wrlock(&pData->corrRwlock);
    free_sigmac(pData->dbCur);
    pData->dbCur = NULL;
    while (pData->dbRetired != NULL) {
        mmsigma_db_t* d = pData->dbRetired;
        pData->dbRetired = d->next;
        free_sigmac(d);
    }
    if (pData->corrEngine != NULL) {
        corr_engine_free(pData->corrEngine);
        pData->corrEngine = NULL;
    }
    if (pData->corrArtifact != NULL) {
        corr_artifact_free(pData->corrArtifact);
        pData->corrArtifact = NULL;
    }
    enrich_close(pData->prev);
    pData->prev = NULL;
    pthread_rwlock_unlock(&pData->corrRwlock);
    pthread_mutex_unlock(&pData->reloadMutex);
    pthread_rwlock_destroy(&pData->corrRwlock);
    pthread_mutex_destroy(&pData->reloadMutex);
    free(pData->corrFile);
    pData->corrFile = NULL;
    free(pData->dbPath);
    pData->dbPath = NULL;
    free(pData->targetPath);
    pData->targetPath = NULL;
    free(pData->tsField);
    pData->tsField = NULL;
    free(pData->originId);
    pData->originId = NULL;
    free(pData->contribInput);
    pData->contribInput = NULL;
    free(pData->prevPath);
    pData->prevPath = NULL;
ENDfreeInstance

BEGINfreeWrkrInstance
    CODESTARTfreeWrkrInstance;
    if (pWrkrData->eval != NULL) {
        sigma_eval_free(pWrkrData->eval);
        pWrkrData->eval = NULL;
    }
    if (pWrkrData->dbReader != NULL) {
        instanceData* pData = pWrkrData->pData;
        pthread_mutex_lock(&pData->reloadMutex);
        for (mmsigma_reader_t** pp = &pData->dbReaders; *pp != NULL; pp = &(*pp)->next) {
            if (*pp == pWrkrData->dbReader) {
                *pp = pWrkrData->dbReader->next;
                break;
            }
        }
        db_reclaim_locked(pData);
        pthread_mutex_unlock(&pData->reloadMutex);
        free(pWrkrData->dbReader);
        pWrkrData->dbReader = NULL;
    }
    enrich_reader_free(pWrkrData->prevReader);
    pWrkrData->prevReader = NULL;
ENDfreeWrkrInstance

BEGINnewActInst
    struct cnfparamvals* pvals = NULL;
    int i;
    CODESTARTnewActInst;
    if ((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);

    CHKiRet(createInstance(&pData));

    for (i = 0; i < actpblk.nParams; ++i) {
        if (!pvals[i].bUsed) continue;
        if (!strcmp(actpblk.descr[i].name, "database")) {
            pData->dbPath = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "target")) {
            pData->targetPath = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "reloadonhup")) {
            pData->reloadOnHup = (sbool)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "corrfile")) {
            pData->corrFile = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "corrmaxgroups")) {
            pData->corrMaxGroups = (int)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "corrmaxdistinct")) {
            pData->corrMaxDistinct = (int)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "corrmaxeventspergroup")) {
            pData->corrMaxEventsPerGroup = (int)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "uselogtimestamp")) {
            pData->useLogTimestamp = (sbool)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "corrmaxahead")) {
            pData->corrMaxAhead = (int)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "corrmaxbehind")) {
            pData->corrMaxBehind = (int)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "prevalence_db")) {
            pData->prevPath = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "timestampfield")) {
            pData->tsField = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "mode")) {
            uchar* m = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
            if (m && !strcasecmp((char*)m, "contribution")) pData->corrMode = 1;
            free(m);
        } else if (!strcmp(actpblk.descr[i].name, "peerindex")) {
            pData->peerIndex = (int)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "peercount")) {
            pData->peerCount = (int)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "origin")) {
            pData->originId = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "contribinput")) {
            pData->contribInput = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "contribinput.authenticated")) {
            pData->contribAuthenticated = (sbool)pvals[i].val.d.n;
        }
    }
    /* default the event-time field once the flag is known */
    if (pData->useLogTimestamp && pData->tsField == NULL) pData->tsField = (uchar*)strdup("@timestamp");
    if (pData->peerCount < 1) pData->peerCount = 1;
    if (pData->peerIndex < 0) pData->peerIndex = 0;
    if (pData->peerIndex >= pData->peerCount) pData->peerIndex = 0;

    if (pData->corrMode == 0 && pData->dbPath == NULL) {
        LogError(0, RS_RET_MISSING_CNFPARAMS, "mmsigma: parameter 'database' is required unless mode=\"contribution\"");
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }
    if (pData->corrMode == 1 && pData->corrFile == NULL) {
        LogError(0, RS_RET_MISSING_CNFPARAMS, "mmsigma: mode=\"contribution\" requires corrfile");
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }
    if (pData->contribInput != NULL) {
        pData->contribInputLen = strlen((const char*)pData->contribInput);
        if (pData->contribInputLen == 0 || pData->corrFile == NULL) {
            LogError(0, RS_RET_CONFIG_ERROR, "mmsigma: contribinput needs a non-empty input name and corrfile");
            ABORT_FINALIZE(RS_RET_CONFIG_ERROR);
        }
    } else if (pData->corrMode == 0 && pData->peerCount > 1) {
        LogMsg(0, RS_RET_OK, LOG_WARNING,
               "mmsigma: peercount=%d without contribinput: partials sent to this peer are not merged",
               pData->peerCount);
    }
    /* A contribution is merged into the correlation state as it is: the
     * input that receives it is the only authentication. */
    if (pData->contribInput != NULL || pData->corrMode == 1) {
        if (!pData->contribAuthenticated) {
            LogError(0, RS_RET_CONFIG_ERROR,
                     "mmsigma: %s merges contributions without authenticating them. Receive them over mutual "
                     "TLS (StreamDriver.Mode=\"1\", StreamDriver.AuthMode=\"x509/name\", "
                     "StreamDriver.PermittedPeers set to the ring members) and set "
                     "contribinput.authenticated=\"on\"",
                     pData->corrMode == 1 ? "mode=\"contribution\"" : "contribinput");
            ABORT_FINALIZE(RS_RET_CONFIG_ERROR);
        }
        LogMsg(0, RS_RET_OK, LOG_WARNING, "mmsigma: contributions on %s are trusted from every peer that input accepts",
               pData->corrMode == 1 ? "this action" : (const char*)pData->contribInput);
    }

    if (pData->targetPath == NULL) pData->targetPath = (uchar*)strdup("!sigma");

    /* Initial load. A missing/invalid artifact is non-fatal: the instance may
     * start before the ruleset file exists; a later SIGHUP/mtime check loads it. */
    if (pData->dbPath != NULL) {
        struct stat sb;
        const int have_sb = stat((const char*)pData->dbPath, &sb) == 0;
        mmsigma_db_t* db = load_sigmac((const char*)pData->dbPath);
        if (db != NULL) {
            /* single-threaded: no worker exists yet */
            db_publish_locked(pData, db);
            if (have_sb) {
                pData->dbMtime = sb.st_mtime;
                pData->dbIno = sb.st_ino;
            }
            ctrReSkipped = db->db.n_re_skipped;
            LogMsg(0, RS_RET_OK, LOG_INFO, "mmsigma: loaded %u rules from %s", db->db.n_rules, pData->dbPath);
        } else {
            LogMsg(0, RS_RET_OK, LOG_WARNING, "mmsigma: ruleset %s not loaded yet, matching disabled until present",
                   pData->dbPath);
        }
    }

    /* Folded correlation engine.  corrFile unset => fully
     * disabled (no-op).  A missing/invalid artifact is non-fatal: the instance
     * may start before the artifact exists; a later SIGHUP/mtime check loads it. */
    if (pData->corrFile != NULL) {
        struct stat sb;
        if (stat((const char*)pData->corrFile, &sb) == 0) pData->corrMtime = sb.st_mtime;
        corr_engine_t* eng = NULL;
        corr_artifact_t* art = NULL;
        corr_load_stats_t ls;
        if (build_corr_engine(pData, &eng, &art, &ls) == 0) {
            pData->corrEngine = eng;
            pData->corrArtifact = art;
            pData->corrLoadAccum.rules_rejected += ls.rules_rejected;
            pData->corrLoadAccum.groupby_truncated += ls.groupby_truncated;
            pData->corrLoadAccum.baserules_truncated += ls.baserules_truncated;
            pData->corrLoadAccum.rids_dropped += ls.rids_dropped;
            LogMsg(0, RS_RET_OK, LOG_INFO, "mmsigma: loaded %zu correlations from %s", corr_engine_rule_count(eng),
                   pData->corrFile);
        } else {
            LogMsg(0, RS_RET_OK, LOG_WARNING,
                   "mmsigma: correlation artifact %s not loaded yet, "
                   "correlation disabled until present",
                   pData->corrFile);
        }
    }

    /* prevalence table: optional, opened here if present. Not fatal when
     * absent, the collector may not have distributed the .prev yet; rarity
     * fields stay unresolved (rules inert) until it lands and a HUP reloads it. */
    if (pData->prevPath != NULL) {
        enrich_options_t eo;
        char eerr[512];
        int erc;
        memset(&eo, 0, sizeof eo);
        eo.size = sizeof eo;
        eo.prev_path = (const char*)pData->prevPath;
        eo.flags = ENRICH_OPT_PARTIAL;
        erc = enrich_open(&pData->prev, &eo, eerr, sizeof eerr);
        if (pData->prev == NULL) {
            LogError(0, RS_RET_OUT_OF_MEMORY, "mmsigma/prev: %s", eerr[0] ? eerr : enrich_strerror(erc));
            ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
        }
        if (erc == ENRICH_OK)
            LogMsg(0, RS_RET_OK, LOG_INFO, "mmsigma/prev: loaded %s", pData->prevPath);
        else
            LogMsg(0, RS_RET_OK, LOG_WARNING, "mmsigma/prev: %s, rarity fields inert until it is present", eerr);
    }

    /* Construct the output-module string request: a message-modification
     * module still MUST build the OMSR (rsyslog calls OMSRgetEntryCount on it
     * during action setup, a NULL OMSR segfaults the loader).  One entry,
     * the whole message (we read pMsg->turbo_result in doAction, not a
     * template string).  */
    CODE_STD_STRING_REQUESTnewActInst(1);
    CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));
    CODE_STD_FINALIZERnewActInst;
    if (pvals != NULL) cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst

BEGINdoAction_NoStrings
    smsg_t** ppMsg = (smsg_t**)pMsgData;
    smsg_t* pMsg = ppMsg[0];
    instanceData* pData = pWrkrData->pData;
    int dbEntered = 0;
    CODESTARTdoAction;
    {
        if (pData->corrMode == 1) {
            STATSCOUNTER_INC(ctrEvents, mutCtrEvents);
            (void)mmsigma_do_contrib(pData, pWrkrData, pMsg);
            FINALIZE;
        }
        /* Same-action ingest: partials for groups this node owns merge into
         * THIS engine, next to its local events. Which messages are partials
         * is decided by the input that received them, never by their text:
         * a log line that quotes contribution JSON is still a log line. */
        if (pData->contribInput != NULL) {
            uchar* in = NULL;
            int inlen = 0;
            getInputName(pMsg, &in, &inlen);
            if (in != NULL && inlen >= 0 && (size_t)inlen == pData->contribInputLen &&
                memcmp(in, pData->contribInput, pData->contribInputLen) == 0) {
                STATSCOUNTER_INC(ctrEvents, mutCtrEvents);
                (void)mmsigma_do_contrib(pData, pWrkrData, pMsg);
                FINALIZE;
            }
        }
        /* From here to finalize_it this worker may hold the current db; a
         * reload frees it only after db_leave. */
        const mmsigma_db_t* dbh = db_enter(pData, pWrkrData->dbReader);
        dbEntered = 1;
        const sigma_db_t* db = dbh != NULL ? &dbh->db : NULL;
        if (db == NULL || db->n_rules == 0) FINALIZE; /* no ruleset yet, pass through */
        STATSCOUNTER_INC(ctrEvents, mutCtrEvents);

#ifdef HAVE_LOGNORM_TURBO
        const ln_fast_result_t* r = NULL;
        if (pMsg->turbo_result != NULL) {
            const ln_fast_result_snapshot_t* snap = (const ln_fast_result_snapshot_t*)pMsg->turbo_result;
            r = ln_fast_result_snapshot_get(snap);
        }
        if (r == NULL) {
            /* The zero-copy arena is gone (the message crossed a duplicating
             * queue boundary or was replayed from a disk queue).  The parsed
             * fields were already materialized into $!, so matching falls back
             * to the $! tree, slower per field, identical semantics.  Counted
             * in impstats so a systematically degraded path is VISIBLE, never
             * a silent no-op. */
            if (pMsg->json == NULL) FINALIZE; /* nothing to match against */
            STATSCOUNTER_INC(ctrTurboMissing, mutCtrTurboMissing);
            if (!bWarnedTurboMissing) {
                bWarnedTurboMissing = 1;
                LogMsg(0, RS_RET_OK, LOG_INFO,
                       "mmsigma: turbo parse snapshot absent, matching from "
                       "the $! tree (impstats counter: turbo.missing)");
            }
        }
#else
        const void* r = NULL;
        if (pMsg->json == NULL) FINALIZE;
#endif

        /* (Re)bind the per-worker scratch to the current ruleset generation. */
        if (pWrkrData->eval == NULL || pWrkrData->evalGen != dbh->gen) {
            if (pWrkrData->eval != NULL) sigma_eval_free(pWrkrData->eval);
            pWrkrData->eval = sigma_eval_create(db);
            pWrkrData->evalGen = pWrkrData->eval != NULL ? dbh->gen : 0;
            if (pWrkrData->eval == NULL) FINALIZE;
        }

        /* Field-resolution ctx: turbo arena (parsed, zero-copy) + the BORROWED
         * $! root for enrichment fields. pMsg->json is mmenrich's
         * enrichment tree; NULL when no $! exists yet (enrichment fields then
         * simply miss, graceful). No deep copy: the msg is owned by this worker
         * for the whole doAction. */
        /* event.original fallback source: the pristine raw line, so fieldless
         * keyword rules match the full message even with no parser value. */
        uchar* pRawMsg = NULL;
        int lenRawMsg = 0;
        getRawMsg(pMsg, &pRawMsg, &lenRawMsg);
        /* This worker's .prev snapshot: valid until its next enter. */
        const enrich_snap_t* prevSnap = pWrkrData->prevReader ? enrich_reader_enter(pWrkrData->prevReader) : NULL;
        mmsigma_fieldctx_t fctx = {.r = r,
                                   .enrich = pMsg->json,
                                   .rawmsg = (const char*)pRawMsg,
                                   .rawmsg_len = (size_t)(lenRawMsg > 0 ? lenRawMsg : 0),
                                   .prev = prevSnap,
                                   .corr_arena = pWrkrData->corrVal,
                                   .corr_cap = sizeof(pWrkrData->corrVal)};
        sigma_hit_t hits[MMSIGMA_MAX_HITS];
        int n = sigma_eval_run(pWrkrData->eval, mmsigma_field_fn, (void*)&fctx, hits, MMSIGMA_MAX_HITS);
        if (n <= 0) FINALIZE; /* no match, no output */
        STATSCOUNTER_INC(ctrMatchedEvents, mutCtrMatchedEvents);

        int capped = (n < MMSIGMA_MAX_HITS) ? n : MMSIGMA_MAX_HITS;
        /* hits.truncated: rules[] is capped at MMSIGMA_MAX_HITS while $!sigma.count
         * carries the honest fired total.  Count the rule-hits dropped from the
         * emitted array so the truncation is observable, not silent. */
        if (n > MMSIGMA_MAX_HITS)
            STATSCOUNTER_ADD(ctrHitsTruncated, mutCtrHitsTruncated, (unsigned)(n - MMSIGMA_MAX_HITS));
        struct json_object* jSigma = json_object_new_object();
        struct json_object* jRules = json_object_new_array();
        for (int i = 0; i < capped; i++) {
            struct json_object* jr = json_object_new_object();
            json_object_object_add(jr, "id", json_object_new_int64(hits[i].rule_id));
            json_object_object_add(jr, "verdict", json_object_new_string(verdict_name(hits[i].verdict)));
            json_object_object_add(jr, "severity", json_object_new_int(hits[i].severity));
            /* Per-rule "score" is a HINT only, the baked score_x100 a downstream scoring stage reads as the
             * verdict-combine base. The hot path no longer collapses these into a top-level verdict/score: that
             * terminal "this is an alert, cluster-wide" decision is the WARM path's authority. */
            json_object_object_add(jr, "score", json_object_new_double(hits[i].score_x100 / 100.0));
            /* MITRE technique (T-id) when the rule carries one, the correlation node
             * join-key.  Omitted (not null) when
             * absent so the activation never asserts a bogus technique. */
            if (hits[i].mitre != NULL && hits[i].mitre_len > 0)
                json_object_object_add(jr, "mitre", json_object_new_string_len(hits[i].mitre, (int)hits[i].mitre_len));
            json_object_array_add(jRules, jr);
        }
        /* Hot path LABELS only: matched/count/rules.  The top-level
         * verdict/score were REMOVED, the hot path must NOT make the terminal
         * collapse; the warm path owns the verdict authority. */
        json_object_object_add(jSigma, "matched", json_object_new_boolean(1));
        json_object_object_add(jSigma, "count", json_object_new_int(n));
        json_object_object_add(jSigma, "rules", jRules);

        uchar* path = pData->targetPath;
        if (path[0] == '$') path++; /* msgAddJSON wants no leading $ */
        if (msgAddJSON(pMsg, path, jSigma, 0, 0) != RS_RET_OK) json_object_put(jSigma);

        /* ---- folded warm-path correlation --------------
         * Feed the matched rule-ids NATIVELY into the correlation engine -
         * straight from hits[].rule_id, NO $!sigma read-back.  Same field
         * context (zero-copy arena, $! fallback) for the group-by / value
         * fields via mmsigma_corr_field_fn.
         * The engine is STATEFUL (sliding windows) and internally synchronised;
         * corrRwlock is read-held here only to keep the engine pointer and its
         * backing artifact alive against a concurrent reload while we evaluate
         * and serialise.  Output JSON under $!sigma_correlation; the rule does
         * no field READS from $!. */
        pthread_rwlock_rdlock(&pData->corrRwlock);
        corr_engine_t* corrEng = pData->corrEngine;
        if (corrEng != NULL) {
            uint32_t rids[MMSIGMA_MAX_HITS];
            int n_rids = 0;
            for (int i = 0; i < capped; i++) rids[n_rids++] = (uint32_t)hits[i].rule_id;

            /* Correlation clock: parsed event time (configured field, then
             * well-known aliases), then rsyslog's syslog-header timestamp, all
             * bounded by the receive time; the receive time when none
             * resolves (counted as fallback) or useLogTimestamp is off. */
            const double recv = mmsigma_recv_time(pMsg);
            double ts = recv;
            if (pData->useLogTimestamp) {
                if (mmsigma_resolve_event_time(pData, &fctx, pMsg, &ts))
                    ts = mmsigma_bound_time(pData, ts, recv);
                else {
                    ts = recv;
                    STATSCOUNTER_INC(ctrCorrTsFallback, mutCtrCorrTsFallback);
                }
            }

            corr_fire_t fires[MMSIGMA_MAX_FIRES];
            mmsigma_clock_recv = recv;
            int nf = corr_on_event_apply(corrEng, rids, (size_t)n_rids, mmsigma_corr_field_fn, (void*)&fctx, ts, fires,
                                         MMSIGMA_MAX_FIRES, pWrkrData->corrScratch,
                                         sizeof(pWrkrData->corrScratch) / sizeof(pWrkrData->corrScratch[0]),
                                         mmsigma_apply_owned, (void*)pData);
            mmsigma_clock_recv = 0.0;
            mmsigma_emit_contribs(pData, corrEng, (void*)&fctx, rids, (size_t)n_rids, ts, pMsg);
            if (nf > 0) {
                int fcapped = (nf < MMSIGMA_MAX_FIRES) ? nf : MMSIGMA_MAX_FIRES;
                struct json_object* jOut = json_object_new_object();
                struct json_object* jArr = json_object_new_array();
                for (int k = 0; k < fcapped; k++) {
                    const corr_fire_t* f = &fires[k];
                    struct json_object* jc = json_object_new_object();
                    if (f->rule_id) json_object_object_add(jc, "rule_id", json_object_new_string(f->rule_id));
                    if (f->title) json_object_object_add(jc, "title", json_object_new_string(f->title));
                    json_object_object_add(jc, "type", json_object_new_string(corr_type_str(f->type)));
                    if (f->technique) json_object_object_add(jc, "technique", json_object_new_string(f->technique));
                    json_object_object_add(jc, "level", json_object_new_string(f->level ? f->level : "medium"));
                    json_object_object_add(jc, "fidelity_tier", json_object_new_string(corr_tier_name(f->tier)));
                    json_object_object_add(jc, "fidelity_weight", json_object_new_double(f->fidelity_weight));
                    json_object_object_add(jc, "remote", json_object_new_boolean(f->remote));
                    struct json_object* jgb = json_object_new_array();
                    struct json_object* jgrp = json_object_new_object();
                    for (size_t g = 0; g < f->n_group; g++) {
                        json_object_array_add(jgb, json_object_new_string(f->group_by[g]));
                        if (f->group && f->group[g])
                            json_object_object_add(jgrp, f->group_by[g], json_object_new_string(f->group[g]));
                    }
                    json_object_object_add(jc, "group_by", jgb);
                    json_object_object_add(jc, "group", jgrp);
                    json_object_object_add(jc, "observed", json_object_new_int64(f->observed));
                    json_object_object_add(jc, "threshold", json_object_new_int64(f->threshold));
                    if (f->value_field)
                        json_object_object_add(jc, "value_field", json_object_new_string(f->value_field));
                    struct json_object* jbr = json_object_new_array();
                    for (size_t b = 0; b < f->n_base_rule_ids; b++)
                        json_object_array_add(jbr, json_object_new_int64(f->base_rule_ids[b]));
                    json_object_object_add(jc, "base_rule_ids", jbr);
                    json_object_array_add(jArr, jc);
                }
                json_object_object_add(jOut, "matched", json_object_new_boolean(1));
                json_object_object_add(jOut, "count", json_object_new_int(nf));
                json_object_object_add(jOut, "correlations", jArr);

                if (msgAddJSON(pMsg, (uchar*)"!sigma_correlation", jOut, 0, 0) != RS_RET_OK) json_object_put(jOut);
            }
        }
        pthread_rwlock_unlock(&pData->corrRwlock);
    }
finalize_it: {
    if (dbEntered) db_leave(pWrkrData->dbReader);
    static __thread uint32_t reload_counter = 0;
    if (++reload_counter % MMSIGMA_RELOAD_EVERY == 0) {
        if (pData->dbPath != NULL) check_db_reload(pData);
        if (pData->prevPath != NULL) reloadPrevalenceDb(pData);
        if (pData->corrFile != NULL) {
            check_corr_reload(pData);
            /* Refresh the correlation boundary counters from the engine's
             * live tallies (cheap, off the per-event path, this cadence is
             * 1/MMSIGMA_RELOAD_EVERY events). */
            publish_corr_stats(pData);
        }
    }
}
ENDdoAction

/* Instance-level HUP (NOT per-worker), see the mmenrich doHUP comment: one
 * reload per SIGHUP. */
BEGINdoHUP
    CODESTARTdoHUP;
    if (pData->reloadOnHup && pData->dbPath != NULL) (void)reloadSigmaDb(pData);
    if (pData->reloadOnHup && pData->corrFile != NULL) (void)reloadCorrEngine(pData);
    if (pData->reloadOnHup && pData->prevPath != NULL) reloadPrevalenceDb(pData);
ENDdoHUP

BEGINisCompatibleWithFeature
    CODESTARTisCompatibleWithFeature;
    if (eFeat == sFEATURERepeatedMsgReduction) iRet = RS_RET_OK;
ENDisCompatibleWithFeature

BEGINtryResume
    CODESTARTtryResume;
ENDtryResume

BEGINdbgPrintInstInfo
    CODESTARTdbgPrintInstInfo;
    dbgprintf("mmsigma\n");
    dbgprintf("\tdatabase='%s'\n", pData->dbPath);
    dbgprintf("\ttarget='%s'\n", pData->targetPath);
    dbgprintf("\treloadOnHup=%s\n", pData->reloadOnHup ? "enabled" : "disabled");
    dbgprintf("\tcorrfile='%s'\n", pData->corrFile ? (char*)pData->corrFile : "(disabled)");
ENDdbgPrintInstInfo

BEGINparseSelectorAct
    CODESTARTparseSelectorAct;
    CODE_STD_STRING_REQUESTparseSelectorAct(1);
    if (strncmp((char*)p, ":mmsigma:", sizeof(":mmsigma:") - 1)) {
        ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
    }
    CODE_STD_FINALIZERparseSelectorAct;
ENDparseSelectorAct

BEGINmodExit
    CODESTARTmodExit;
    if (mmsigmaStats != NULL) {
        statsobj.Destruct(&mmsigmaStats);
        mmsigmaStats = NULL;
    }
    objRelease(statsobj, CORE_COMPONENT);
ENDmodExit

BEGINqueryEtryPt
    CODESTARTqueryEtryPt;
    CODEqueryEtryPt_STD_OMOD_QUERIES;
    CODEqueryEtryPt_STD_OMOD8_QUERIES;
    CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES;
    CODEqueryEtryPt_doHUP;
ENDqueryEtryPt

BEGINmodInit()
    CODESTARTmodInit;
    *ipIFVersProvided = CURR_MOD_IF_VERSION;
    CODEmodInit_QueryRegCFSLineHdlr;
    CHKiRet(objUse(statsobj, CORE_COMPONENT));
    CHKiRet(statsobj.Construct(&mmsigmaStats));
    CHKiRet(statsobj.SetName(mmsigmaStats, (uchar*)"mmsigma"));
    CHKiRet(statsobj.SetOrigin(mmsigmaStats, (uchar*)"mmsigma"));
    STATSCOUNTER_INIT(ctrTurboMissing, mutCtrTurboMissing);
    CHKiRet(statsobj.AddCounter(mmsigmaStats, UCHAR_CONSTANT("turbo.missing"), ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &ctrTurboMissing));
    STATSCOUNTER_INIT(ctrEvents, mutCtrEvents);
    CHKiRet(
        statsobj.AddCounter(mmsigmaStats, UCHAR_CONSTANT("events"), ctrType_IntCtr, CTR_FLAG_RESETTABLE, &ctrEvents));
    STATSCOUNTER_INIT(ctrMatchedEvents, mutCtrMatchedEvents);
    CHKiRet(statsobj.AddCounter(mmsigmaStats, UCHAR_CONSTANT("matched.events"), ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &ctrMatchedEvents));
    STATSCOUNTER_INIT(ctrReSkipped, mutCtrReSkipped);
    CHKiRet(statsobj.AddCounter(mmsigmaStats, UCHAR_CONSTANT("regex.skipped"), ctrType_IntCtr, CTR_FLAG_NONE,
                                &ctrReSkipped));
    /* hits.truncated: incremented live per over-cap event (resettable). */
    STATSCOUNTER_INIT(ctrHitsTruncated, mutCtrHitsTruncated);
    CHKiRet(statsobj.AddCounter(mmsigmaStats, UCHAR_CONSTANT("hits.truncated"), ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &ctrHitsTruncated));
    STATSCOUNTER_INIT(ctrCorrTsFallback, mutCtrCorrTsFallback);
    CHKiRet(statsobj.AddCounter(mmsigmaStats, UCHAR_CONSTANT("corr.timestamp.fallback"), ctrType_IntCtr,
                                CTR_FLAG_RESETTABLE, &ctrCorrTsFallback));
    STATSCOUNTER_INIT(ctrCorrTsAhead, mutCtrCorrTsAhead);
    CHKiRet(statsobj.AddCounter(mmsigmaStats, UCHAR_CONSTANT("corr.timestamp.ahead"), ctrType_IntCtr,
                                CTR_FLAG_RESETTABLE, &ctrCorrTsAhead));
    STATSCOUNTER_INIT(ctrCorrTsBehind, mutCtrCorrTsBehind);
    CHKiRet(statsobj.AddCounter(mmsigmaStats, UCHAR_CONSTANT("corr.timestamp.behind"), ctrType_IntCtr,
                                CTR_FLAG_RESETTABLE, &ctrCorrTsBehind));
    STATSCOUNTER_INIT(ctrCorrTsSyslog, mutCtrCorrTsSyslog);
    CHKiRet(statsobj.AddCounter(mmsigmaStats, UCHAR_CONSTANT("corr.timestamp.syslog"), ctrType_IntCtr,
                                CTR_FLAG_RESETTABLE, &ctrCorrTsSyslog));
    STATSCOUNTER_INIT(ctrCorrContribEmit, mutCtrCorrContribEmit);
    CHKiRet(statsobj.AddCounter(mmsigmaStats, UCHAR_CONSTANT("corr.contrib.emit"), ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &ctrCorrContribEmit));
    STATSCOUNTER_INIT(ctrCorrContribEmitFailed, mutCtrCorrContribEmitFailed);
    CHKiRet(statsobj.AddCounter(mmsigmaStats, UCHAR_CONSTANT("corr.contrib.emit.failed"), ctrType_IntCtr,
                                CTR_FLAG_RESETTABLE, &ctrCorrContribEmitFailed));
    STATSCOUNTER_INIT(ctrCorrContribIngest, mutCtrCorrContribIngest);
    CHKiRet(statsobj.AddCounter(mmsigmaStats, UCHAR_CONSTANT("corr.contrib.ingest"), ctrType_IntCtr,
                                CTR_FLAG_RESETTABLE, &ctrCorrContribIngest));
    STATSCOUNTER_INIT(ctrCorrValOverflow, mutCtrCorrValOverflow);
    CHKiRet(statsobj.AddCounter(mmsigmaStats, UCHAR_CONSTANT("corr.value.overflow"), ctrType_IntCtr,
                                CTR_FLAG_RESETTABLE, &ctrCorrValOverflow));
    STATSCOUNTER_INIT(ctrCorrContribDrop, mutCtrCorrContribDrop);
    CHKiRet(statsobj.AddCounter(mmsigmaStats, UCHAR_CONSTANT("corr.contrib.drop"), ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &ctrCorrContribDrop));
    /* Correlation boundary counters.  These are REFRESHED (set) from the engine
     * + loader tallies by publish_corr_stats, so they behave as monotonic gauges
     * (CTR_FLAG_NONE, like regex.skipped) rather than live-incremented counters
     * a reset could zero mid-generation. */
#define MMSIGMA_ADD_CORR_CTR(field, mut, name)                                                                   \
    do {                                                                                                         \
        STATSCOUNTER_INIT(field, mut);                                                                           \
        CHKiRet(statsobj.AddCounter(mmsigmaStats, UCHAR_CONSTANT(name), ctrType_IntCtr, CTR_FLAG_NONE, &field)); \
    } while (0)
    MMSIGMA_ADD_CORR_CTR(ctrCorrGroupsEvicted, mutCorrGroupsEvicted, "corr.groups.evicted");
    MMSIGMA_ADD_CORR_CTR(ctrCorrDistinctEvicted, mutCorrDistinctEvicted, "corr.distinct.evicted");
    MMSIGMA_ADD_CORR_CTR(ctrCorrEventsOverwritten, mutCorrEventsOverwritten, "corr.events.overwritten");
    MMSIGMA_ADD_CORR_CTR(ctrCorrFiresSuppressed, mutCorrFiresSuppressed, "corr.fires.suppressed");
    MMSIGMA_ADD_CORR_CTR(ctrCorrFiresTruncated, mutCorrFiresTruncated, "corr.fires.truncated");
    MMSIGMA_ADD_CORR_CTR(ctrCorrRulesRejected, mutCorrRulesRejected, "corr.rules.rejected");
    MMSIGMA_ADD_CORR_CTR(ctrCorrEvtSkippedMissing, mutCorrEvtSkippedMissing, "corr.event.skipped_missing_field");
    MMSIGMA_ADD_CORR_CTR(ctrCorrSeenTruncated, mutCorrSeenTruncated, "corr.seen.truncated");
    MMSIGMA_ADD_CORR_CTR(ctrCorrHitsTruncated, mutCorrHitsTruncated, "corr.hits.truncated");
    MMSIGMA_ADD_CORR_CTR(ctrCorrGroupEvidenceDropped, mutCorrGroupEvidenceDropped, "corr.group.evidence_dropped");
    MMSIGMA_ADD_CORR_CTR(ctrCorrOomDropped, mutCorrOomDropped, "corr.oom.dropped");
    MMSIGMA_ADD_CORR_CTR(ctrCorrValuesNonnumeric, mutCorrValuesNonnumeric, "corr.values.nonnumeric");
    MMSIGMA_ADD_CORR_CTR(ctrCorrWatermarkLate, mutCorrWatermarkLate, "corr.watermark.late");
    MMSIGMA_ADD_CORR_CTR(ctrCorrHotkeyFallback, mutCorrHotkeyFallback, "corr.hotkey.fallback");
    MMSIGMA_ADD_CORR_CTR(ctrCorrCondOverArity, mutCorrCondOverArity, "corr.condition.over_arity");
    MMSIGMA_ADD_CORR_CTR(ctrCorrGroupbyTruncated, mutCorrGroupbyTruncated, "corr.groupby.truncated");
    MMSIGMA_ADD_CORR_CTR(ctrCorrBaserulesTruncated, mutCorrBaserulesTruncated, "corr.baserules.truncated");
    MMSIGMA_ADD_CORR_CTR(ctrCorrRidsDropped, mutCorrRidsDropped, "corr.rids.dropped");
#undef MMSIGMA_ADD_CORR_CTR
    CHKiRet(statsobj.ConstructFinalize(mmsigmaStats));
ENDmodInit
