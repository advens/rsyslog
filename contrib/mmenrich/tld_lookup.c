/* SPDX-License-Identifier: Apache-2.0 */

/* tld_lookup.c
 * Load a tld.json catalog and classify a domain's last label.
 *
 * Usage:   tld_lookup <tld.json> <domain>
 *          tld_lookup <tld.json> --empty
 *
 * Table hit: common / suspicious. Miss with a present domain: uncommon.
 * Absent, empty, or IP is not uncommon.
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

#include "thrt_tld.h"

#include <stdio.h>
#include <string.h>

static const char *kind_name(int k) {
    switch (k) {
        case TLD_KIND_NONE:
            return "none";
        case TLD_KIND_UNCOMMON:
            return "uncommon";
        case TLD_KIND_TABLE:
            return "table";
        default:
            return "?";
    }
}

int main(int argc, char **argv) {
    tld_table_t *t;
    tld_class_t cl;
    const char *domain;
    size_t n;
    char label[TLD_LOOKUP_MAX];
    size_t labn;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <tld.json> <domain>\n", argv[0]);
        fprintf(stderr, "       %s <tld.json> --empty\n", argv[0]);
        return 2;
    }
    t = tld_table_load(argv[1]);
    if (t == NULL) {
        fprintf(stderr, "failed to load %s\n", argv[1]);
        return 1;
    }
    if (strcmp(argv[2], "--empty") == 0) {
        domain = "";
        n = 0;
    } else {
        domain = argv[2];
        n = strlen(domain);
    }
    if (tld_classify(t, domain, n, &cl) != 0) {
        fprintf(stderr, "classify failed\n");
        tld_table_free(t);
        return 1;
    }
    labn = tld_extract(domain, n, label, sizeof(label));
    printf("domain=%s\n", n ? domain : "(empty string)");
    printf("tld=%s\n", labn ? label : "-");
    printf("kind=%s  class=%s  label=%s\n", kind_name(cl.kind), cl.cls ? cl.cls : "-",
           cl.label && cl.label[0] ? cl.label : "-");
    tld_table_free(t);
    return 0;
}
