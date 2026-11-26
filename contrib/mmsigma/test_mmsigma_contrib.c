/* SPDX-License-Identifier: Apache-2.0 */

/* test_mmsigma_contrib.c
 * Self-test for mmsigma_contrib.h: the group-by fields of an emitted partial
 * follow the correlation's aliases like the engine does, and a SUM value the
 * engine would skip is not sent. Exits non-zero on any failure.
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
#include <stdio.h>
#include <string.h>
#include "mmsigma_contrib.h"

static int failed;

#define CHECK(c, msg)                      \
    do {                                   \
        if (!(c)) {                        \
            printf("  FAIL: %s\n", (msg)); \
            failed++;                      \
        }                                  \
    } while (0)

int main(void) {
    static const uint32_t bases[] = {10, 20, 30};
    static const char* gb[] = {"source.ip"};
    static const char* gb_20[] = {"client.ip"};
    static const char* const* aliases[] = {NULL, gb_20, NULL};
    corr_rule_t r;
    double v = 0.0;

    memset(&r, 0, sizeof(r));
    r.base_rule_ids = bases;
    r.n_base_rule_ids = 3;
    r.group_by = gb;
    r.n_group_by = 1;

    const uint32_t hit_20[] = {20};
    const uint32_t hit_5_20_10[] = {5, 20, 10};
    const uint32_t hit_10_20[] = {10, 20};
    const uint32_t hit_none[] = {7};

    CHECK(mmsigma_contrib_group_fields(&r, hit_20, 1) == gb, "no aliases: group_by");
    r.alias_group_by = aliases;
    r.n_alias_group_by = 3;
    CHECK(mmsigma_contrib_group_fields(&r, hit_20, 1) == gb_20, "alias of the matched base");
    CHECK(mmsigma_contrib_group_fields(&r, hit_5_20_10, 3) == gb_20, "first matched base wins");
    CHECK(mmsigma_contrib_group_fields(&r, hit_10_20, 2) == gb, "first matched base has no alias");
    CHECK(mmsigma_contrib_group_fields(&r, hit_none, 1) == gb, "no base matched: group_by");
    r.n_alias_group_by = 2;
    CHECK(mmsigma_contrib_group_fields(&r, hit_20, 1) == gb, "alias list of the wrong length is ignored");

    CHECK(mmsigma_contrib_number("1500", &v) && v == 1500.0, "number");
    CHECK(mmsigma_contrib_number("1500/tcp", &v) && v == 1500.0, "trailing text ignored");
    CHECK(mmsigma_contrib_number("-2.5e3", &v) && v == -2500.0, "sign and exponent");
    v = 42.0;
    CHECK(!mmsigma_contrib_number("abc", &v) && v == 42.0, "non-numeric is not sent");
    CHECK(!mmsigma_contrib_number("", &v), "empty is not sent");
    CHECK(!mmsigma_contrib_number(NULL, &v), "missing is not sent");
    CHECK(!mmsigma_contrib_number("1e999", &v), "overflow to infinity is not sent");
    CHECK(!mmsigma_contrib_number("nan", &v), "NaN is not sent");
    CHECK(!mmsigma_contrib_number("-inf", &v), "infinity is not sent");

    printf("mmsigma contrib: %s\n", failed ? "FAILED" : "PASSED");
    return failed ? 1 : 0;
}
