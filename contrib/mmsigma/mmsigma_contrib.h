/* SPDX-License-Identifier: Apache-2.0 */

/* mmsigma_contrib.h
 * What a peer sends for an event it does not own. An emitted partial must
 * carry what the owner would have applied locally: the same group values,
 * and only a value the engine accepts. Header-only so test_mmsigma_contrib
 * can check it without the rsyslog runtime.
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
#ifndef MMSIGMA_CONTRIB_H
#define MMSIGMA_CONTRIB_H

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sigma/classify_corr.h>

/* The group-by field names the engine reads for this event: the alias list
 * of the first matched rid that is a base rule of r, else r->group_by. The
 * engine resolves the values it passes to the apply callback the same way,
 * so the ownership decision and the emitted partial see the same values. */
static inline const char* const* mmsigma_contrib_group_fields(const corr_rule_t* r,
                                                              const uint32_t* rids,
                                                              size_t n_rids) {
    const int aliased = r->alias_group_by != NULL && r->n_alias_group_by == r->n_base_rule_ids;
    for (size_t k = 0; k < n_rids; k++) {
        for (size_t i = 0; i < r->n_base_rule_ids; i++) {
            if (r->base_rule_ids[i] != rids[k]) continue;
            return (aliased && r->alias_group_by[i] != NULL) ? r->alias_group_by[i] : r->group_by;
        }
    }
    return r->group_by;
}

/* A SUM value as the engine reads it: a leading decimal, trailing text
 * ignored, finite. Returns 0 when the engine would skip the event, and the
 * partial is then not sent. */
static inline int mmsigma_contrib_number(const char* s, double* out) {
    char* end = NULL;
    double v;
    if (s == NULL || s[0] == '\0') return 0;
    v = strtod(s, &end);
    if (end == s || !isfinite(v)) return 0;
    *out = v;
    return 1;
}

#endif /* MMSIGMA_CONTRIB_H */
