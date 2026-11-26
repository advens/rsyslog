/* SPDX-License-Identifier: Apache-2.0 */

/* ua_lookup.c
 * Load a ua.json catalog and classify a User-Agent string.
 *
 * Usage:   ua_lookup <ua.json> <user-agent>
 *          ua_lookup <ua.json> --empty
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

#include "thrt_ua.h"

#include <stdio.h>
#include <string.h>

static const char *kind_name(int k) {
    switch (k) {
        case UA_KIND_NONE:
            return "none";
        case UA_KIND_EMPTY:
            return "empty";
        case UA_KIND_ENCODED:
            return "encoded";
        case UA_KIND_TABLE:
            return "table";
        default:
            return "?";
    }
}

int main(int argc, char **argv) {
    ua_table_t *t;
    ua_class_t cl;
    const char *ua;
    size_t n;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <ua.json> <user-agent>\n", argv[0]);
        fprintf(stderr, "       %s <ua.json> --empty\n", argv[0]);
        return 2;
    }
    t = ua_table_load(argv[1]);
    if (t == NULL) {
        fprintf(stderr, "failed to load %s\n", argv[1]);
        return 1;
    }
    if (strcmp(argv[2], "--empty") == 0) {
        ua = "";
        n = 0;
    } else {
        ua = argv[2];
        n = strlen(ua);
    }
    if (ua_classify(t, ua, n, &cl) != 0) {
        fprintf(stderr, "classify failed\n");
        ua_table_free(t);
        return 1;
    }
    printf("ua=%s\n", n ? ua : "(empty string)");
    printf("kind=%s  class=%s  label=%s\n", kind_name(cl.kind), cl.cls ? cl.cls : "-",
           cl.label && cl.label[0] ? cl.label : "-");
    ua_table_free(t);
    return 0;
}
