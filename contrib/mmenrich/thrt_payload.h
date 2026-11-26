/* SPDX-License-Identifier: Apache-2.0 */

/* thrt_payload.h
 * Payload classification helpers: URL extension extraction, escaped-payload
 * detection, and file-extension classification. The IOC miner and any other
 * module that inspects a payload include this one file, so every consumer
 * classifies a payload the same way.
 *
 * Copyright 2026 Advens.
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

#ifndef THRT_PAYLOAD_H
#define THRT_PAYLOAD_H

#include <ctype.h>
#include <stddef.h>
#include <string.h>

/* Extract file extension from a URL path (before query string '?' or fragment '#').
 * Returns pointer into the url buffer; caller must NOT free.
 * Sets *ext_len to extension length.  Returns NULL if no extension found. */
static __attribute__((unused)) const char* extract_url_extension(const char* url, size_t url_len, size_t* ext_len) {
    const char* end = url + url_len;
    /* Find end of path portion (before '?' or '#') */
    const char* path_end = end;
    for (const char* p = url; p < end; p++) {
        if (*p == '?' || *p == '#') {
            path_end = p;
            break;
        }
    }
    /* Find last '.' in the final path segment. The index walk stops at url
     * itself: decrementing a pointer below url is undefined behaviour. */
    const char* dot = NULL;
    for (size_t i = (size_t)(path_end - url); i > 0; i--) {
        const char* p = url + i - 1;
        if (*p == '.') {
            dot = p;
            break;
        }
        if (*p == '/') break; /* no extension in this segment */
    }
    if (!dot || dot + 1 >= path_end) return NULL;
    *ext_len = (size_t)(path_end - dot - 1);
    return dot + 1;
}

/* Return 1 when str holds at least two escaped byte sequences (\xNN or
 * \uNNNN), the shape of an encoded shellcode payload. One sequence alone
 * is common in benign text and does not count. */
static __attribute__((unused)) int is_escaped_payload(const char* str, size_t len) {
    size_t valid_sequences = 0;
    const char* end = str + len;
    const char* ptr = str;

    while (ptr < end) {
        if (*ptr == '\\') {
            // Check \xNN
            if (ptr + 3 < end && (ptr[1] == 'x') && isxdigit((unsigned char)ptr[2]) &&
                isxdigit((unsigned char)ptr[3])) {
                valid_sequences++;
                ptr += 3;  // Jump past \xNN
                continue;
            }
            // Check \uNNNN
            if (ptr + 5 < end && (ptr[1] == 'u') && isxdigit((unsigned char)ptr[2]) &&
                isxdigit((unsigned char)ptr[3]) && isxdigit((unsigned char)ptr[4]) && isxdigit((unsigned char)ptr[5])) {
                valid_sequences++;
                ptr += 5;  // Jump past \uNNNN
                continue;
            }
        }
        ptr++;
    }

    return (valid_sequences >= 2);
}

/* File extension classes returned by get_file_type(). */
#define FILE_TYPE_NONE 0
#define FILE_TYPE_THREAT 1
#define FILE_TYPE_IGNORE 2

/* Classify a lowercase file extension of len bytes. FILE_TYPE_THREAT is an
 * executable or script type, FILE_TYPE_IGNORE a static asset (image, font,
 * stylesheet, media) whose bytes trip the escaped-payload check by accident. */
static __attribute__((unused)) int get_file_type(const char* ext, size_t len) {
    if (len == 2) {
        if (memcmp(ext, "js", 2) == 0) return FILE_TYPE_IGNORE;
        if (memcmp(ext, "sh", 2) == 0 || memcmp(ext, "py", 2) == 0 || memcmp(ext, "vb", 2) == 0 ||
            memcmp(ext, "so", 2) == 0)
            return FILE_TYPE_THREAT;
    } else if (len == 3) {
        switch (ext[0]) {
            case 'b':
                if (memcmp(ext, "bmp", 3) == 0) {
                    return FILE_TYPE_IGNORE;
                }
                if (memcmp(ext, "bat", 3) == 0 || memcmp(ext, "bin", 3) == 0) {
                    return FILE_TYPE_THREAT;
                }
                break;
            case 'c':
                if (memcmp(ext, "css", 3) == 0) {
                    return FILE_TYPE_IGNORE;
                }
                if (memcmp(ext, "cmd", 3) == 0 || memcmp(ext, "cgi", 3) == 0 || memcmp(ext, "cpl", 3) == 0) {
                    return FILE_TYPE_THREAT;
                }
                break;
            case 'd':
                if (memcmp(ext, "dll", 3) == 0 || memcmp(ext, "dmg", 3) == 0) {
                    return FILE_TYPE_THREAT;
                }
                break;
            case 'e':
                if (memcmp(ext, "eot", 3) == 0) {
                    return FILE_TYPE_IGNORE;
                }
                if (memcmp(ext, "exe", 3) == 0 || memcmp(ext, "elf", 3) == 0 || memcmp(ext, "ear", 3) == 0) {
                    return FILE_TYPE_THREAT;
                }
                break;
            case 'g':
                if (memcmp(ext, "gif", 3) == 0) {
                    return FILE_TYPE_IGNORE;
                }
                break;
            case 'h':
                if (memcmp(ext, "hta", 3) == 0) {
                    return FILE_TYPE_THREAT;
                }
                break;
            case 'i':
                if (memcmp(ext, "ico", 3) == 0) {
                    return FILE_TYPE_IGNORE;
                }
                break;
            case 'j':
                if (memcmp(ext, "jpg", 3) == 0) {
                    return FILE_TYPE_IGNORE;
                }
                if (memcmp(ext, "jar", 3) == 0 || memcmp(ext, "jsp", 3) == 0) {
                    return FILE_TYPE_THREAT;
                }
                break;
            case 'm':
                if (memcmp(ext, "mp3", 3) == 0 || memcmp(ext, "mp4", 3) == 0) {
                    return FILE_TYPE_IGNORE;
                }
                if (memcmp(ext, "msi", 3) == 0 || memcmp(ext, "msp", 3) == 0) {
                    return FILE_TYPE_THREAT;
                }
                break;
            case 'p':
                if (memcmp(ext, "png", 3) == 0) {
                    return FILE_TYPE_IGNORE;
                }
                if (memcmp(ext, "php", 3) == 0 || memcmp(ext, "ps1", 3) == 0 || memcmp(ext, "pif", 3) == 0) {
                    return FILE_TYPE_THREAT;
                }
                break;
            case 's':
                if (memcmp(ext, "svg", 3) == 0) {
                    return FILE_TYPE_IGNORE;
                }
                if (memcmp(ext, "scr", 3) == 0 || memcmp(ext, "shs", 3) == 0 || memcmp(ext, "swf", 3) == 0) {
                    return FILE_TYPE_THREAT;
                }
                break;
            case 'o':
                if (memcmp(ext, "otf", 3) == 0 || memcmp(ext, "ogg", 3) == 0) {
                    return FILE_TYPE_IGNORE;
                }
                break;
            case 't':
                if (memcmp(ext, "ttf", 3) == 0 || memcmp(ext, "tif", 3) == 0) {
                    return FILE_TYPE_IGNORE;
                }
                break;
            case 'v':
                if (memcmp(ext, "vbs", 3) == 0 || memcmp(ext, "vbe", 3) == 0) {
                    return FILE_TYPE_THREAT;
                }
                break;
            case 'w':
                if (memcmp(ext, "war", 3) == 0 || memcmp(ext, "wsf", 3) == 0) {
                    return FILE_TYPE_THREAT;
                }
                break;
            case 'z':
                if (memcmp(ext, "zip", 3) == 0) {
                    return FILE_TYPE_THREAT;
                }
                break;
            default:
                break;
        }
    } else if (len == 4) {
        if (memcmp(ext, "jpeg", 4) == 0 || memcmp(ext, "woff", 4) == 0 || memcmp(ext, "webp", 4) == 0 ||
            memcmp(ext, "tiff", 4) == 0 || memcmp(ext, "avif", 4) == 0)
            return FILE_TYPE_IGNORE;
        if (memcmp(ext, "aspx", 4) == 0 || memcmp(ext, "php5", 4) == 0) return FILE_TYPE_THREAT;
    } else if (len == 5) {
        if (memcmp(ext, "woff2", 5) == 0) return FILE_TYPE_IGNORE;
    }
    return FILE_TYPE_NONE;
}

/* Longest URL extension the skip lists are matched against. A longer
 * extension is never skipped. */
#define PAYLOAD_SKIP_EXT_MAX 5

/* Return 1 when the raw message carries an escaped payload that should be
 * reported as shellcode.
 *
 * url (url_len bytes, may be NULL) is the request URL. When its extension is
 * a static asset (FILE_TYPE_IGNORE) or one of the n_skip operator types, the
 * raw bytes are not scanned: images, fonts, and documents carry \xNN runs
 * that are not payloads. skip[] holds lowercase extensions and skip_len[]
 * their lengths; an entry may be NULL with length 0. */
static __attribute__((unused)) int payload_has_shellcode(const char* url,
                                                         size_t url_len,
                                                         const char* raw,
                                                         size_t raw_len,
                                                         char* const* skip,
                                                         const size_t* skip_len,
                                                         int n_skip) {
    if (raw == NULL || raw_len == 0) return 0;
    if (url != NULL && url_len > 0) {
        size_t ext_len = 0;
        const char* ext = extract_url_extension(url, url_len, &ext_len);
        if (ext != NULL && ext_len > 0 && ext_len <= PAYLOAD_SKIP_EXT_MAX) {
            char lext[PAYLOAD_SKIP_EXT_MAX];
            for (size_t i = 0; i < ext_len; i++) lext[i] = (char)tolower((unsigned char)ext[i]);
            if (get_file_type(lext, ext_len) == FILE_TYPE_IGNORE) return 0;
            for (int k = 0; k < n_skip; k++) {
                if (skip_len[k] == ext_len && memcmp(lext, skip[k], ext_len) == 0) return 0;
            }
        }
    }
    return is_escaped_payload(raw, raw_len);
}

#endif /* THRT_PAYLOAD_H */
