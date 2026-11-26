/* SPDX-License-Identifier: Apache-2.0 */

/* Copyright 2026 Advens
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* prev_live.h
 * Prevalence counters shared by every module of one process, and the
 * publisher that turns them into a local .prev image. A separate merge
 * writes the image mmenrich and mmsigma map.
 *
 * The hot path records one observable with a few atomics. One publisher
 * ages the window and replaces the local image, then may merge it with
 * peer snapshots into the image the lookup reads. Callers pass every
 * path; this header names none. A local image alone has
 * reporting_edges 1.
 *
 * The image layout is prev_format.h. This header is the private counter
 * file, not that image.
 */
#ifndef PREV_LIVE_H
#define PREV_LIVE_H

#include <stdint.h>

typedef struct prev_live_hdr prev_live_t;

/* Map the counter file, creating it if needed. NULL on error.
 * The mapping is shared by every module in this process. A new file
 * gets a random key; an existing file keeps its key. */
prev_live_t *prev_live_open(const char *path);

/* prev_live_open() under a given key, so edges that share it count the
 * same value in the same row. A new file gets key. A file under another
 * key is emptied and takes key, under the file lock that guards the
 * header, before the mapping is returned. A file under key is used as
 * it is. key NULL is prev_live_open(). Every module of the process
 * should open with the same key: a second key empties the table again. */
prev_live_t *prev_live_open_keyed(const char *path, const uint64_t key[2]);

/* The tenant key file: 32 hex digits (16 bytes, the first byte first),
 * then at most one line end. Bytes 0 to 7 are key[0] and bytes 8 to 15
 * key[1], least significant first. A symlink, a file other users can
 * read, or one the group can write is refused. An all-zero key is
 * refused. Returns 0, or one of the codes below. key is written only on
 * success. */
#define PREV_KEY_HEX_LEN 32u
#define PREV_KEY_EOPEN (-1) /* missing, unreadable, or not a regular file */
#define PREV_KEY_EMODE (-2) /* other users can read it, or the group can write it */
#define PREV_KEY_EFORMAT (-3) /* not 32 hex digits, or all zero */
int prev_live_read_key(const char *path, uint64_t key[2]);

/* A log phrase for a prev_live_read_key() result. Names no key byte. */
const char *prev_live_key_error(int rc);
void prev_live_close(prev_live_t *live);

/* Wall clock second the hot path stamps onto source rows.
 * The publisher stores it once per loop. */
void prev_live_tick(prev_live_t *live, uint32_t now_sec);

/* Record one sighting. observable is NUL-terminated. source_ip may be
 * NULL when the event has no source address. Safe for concurrent callers. */
void prev_live_note(prev_live_t *live, const char *observable, const char *source_ip);

/* Copy an existing .prev image into empty counter rows, once.
 * A missing image still marks the table seeded so a later publish is
 * not imported back into itself. Returns 0 when seeded, -1 when live
 * or the path is NULL, or when the image could not be mapped (that
 * call does not mark the table, so the next one retries). */
int prev_live_seed(prev_live_t *live, const char *prev_path);

/* Seed from this appliance's own image, once.
 * local_path is used when it is a one-edge image. merged_path is used
 * only when local_path is not, and only when merged_path itself still
 * says one reporting edge. A merged image is not copied into
 * the counters. Returns 0 when seeded, -1 when live is NULL or the
 * chosen image could not be mapped. */
int prev_live_seed_own(prev_live_t *live, const char *local_path, const char *merged_path);

/* Age the window if it is due, then atomically replace prev_path.
 * The image is this appliance only: reporting_edges is 1.
 * Returns 1 when a new image was written, 0 when the write was skipped,
 * -1 on error. *n_out receives the number of rows written (0 on skip). */
int prev_live_publish(prev_live_t *live, const char *prev_path, uint32_t now_sec, uint32_t *n_out);

/* Merge local_path with the regular files in peers_dir into out_path.
 * peers_dir may be NULL or missing. A snapshot older than the 7-day
 * window is ignored. reporting_edges is the number of snapshots used.
 * A name's edge_count is how many of those snapshots contain it, not the
 * sum of their stored edge counts. source_count and total_count are sums.
 * The first image folded sets the key of the result; an image under another
 * key is skipped, since its rows hash other names.
 * Returns 1 when out_path was replaced, 0 when the write was skipped,
 * -1 on error. *n_out receives the number of rows written (0 on skip). */
int prev_merge_images(
    const char *local_path, const char *peers_dir, const char *out_path, uint32_t now_sec, uint32_t *n_out);

/* The row key of an observable: SipHash-1-3 under this counter file's key,
 * which every image it publishes carries. */
uint64_t prev_live_hash(const prev_live_t *live, const char *observable);

/* Place a baseline row keyed by prev_live_hash() (0 is bumped to 1).
 * Fills count_prev and the floors only when that row has no baseline yet. */
int prev_live_put(prev_live_t *live, uint64_t key, uint32_t count, uint16_t edges, uint16_t sources);

/* Put the counters under a given key. A different key empties the rows:
 * they hashed other names. The same key is a no-op. The rows are cleared
 * without the file lock, while another module may be adding to them:
 * open with prev_live_open_keyed() instead. */
void prev_live_set_key(prev_live_t *live, uint64_t k0, uint64_t k1);

/* Test aid: the publisher rotates when now_sec is this far past the start. */
void prev_live_set_window_start(prev_live_t *live, uint32_t start);

#endif /* PREV_LIVE_H */
