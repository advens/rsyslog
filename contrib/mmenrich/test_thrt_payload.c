/* test_thrt_payload.c
 * Shared payload classification helpers (thrt_payload.h).
 *
 * Every input is copied into a heap buffer of exactly its length, with no
 * NUL terminator, because the callers pass turbo slices and raw message
 * bytes. Under ASan any read past the slice fails the run.
 *
 * Copyright 2026 Advens.
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
#include "thrt_payload.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
static int checks;

static void expect(int cond, const char* msg) {
    checks++;
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        fails++;
    }
}

/* Exact-length copy. malloc(0) may return NULL, so an empty slice gets one
 * byte that the helper is never allowed to read. */
static char* slice(const char* s, size_t len) {
    char* b = malloc(len ? len : 1);
    if (b == NULL) {
        fprintf(stderr, "FAIL: out of memory\n");
        exit(2);
    }
    if (len) memcpy(b, s, len);
    return b;
}

static void expect_ext(const char* url, const char* want, const char* msg) {
    size_t len = strlen(url);
    char* b = slice(url, len);
    size_t ext_len = 0;
    const char* ext = extract_url_extension(b, len, &ext_len);
    if (want == NULL) {
        expect(ext == NULL, msg);
    } else {
        expect(ext != NULL && ext_len == strlen(want) && memcmp(ext, want, ext_len) == 0, msg);
    }
    free(b);
}

static void expect_escaped(const char* s, int want, const char* msg) {
    size_t len = strlen(s);
    char* b = slice(s, len);
    expect(is_escaped_payload(b, len) == want, msg);
    free(b);
}

static void expect_type(const char* ext, int want, const char* msg) {
    size_t len = strlen(ext);
    char* b = slice(ext, len);
    expect(get_file_type(b, len) == want, msg);
    free(b);
}

/* Operator skip list as mmenrich stores it: lowercase, with lengths. The
 * NULL entry is what a failed copy would leave and must never be read. */
static char skip_pdf[] = "pdf";
static char skip_docx[] = "docx";
static char* const skip_types[] = {skip_pdf, NULL, skip_docx};
static const size_t skip_lens[] = {3, 0, 4};

static void expect_shellcode(const char* url, const char* raw, int want, const char* msg) {
    size_t url_len = url ? strlen(url) : 0;
    size_t raw_len = strlen(raw);
    char* u = url ? slice(url, url_len) : NULL;
    char* r = slice(raw, raw_len);
    expect(payload_has_shellcode(u, url_len, r, raw_len, skip_types, skip_lens, 3) == want, msg);
    free(u);
    free(r);
}

int main(void) {
    /* extract_url_extension */
    expect_ext("/a/b.php?x=1", "php", "ext before query");
    expect_ext("/f.tar.gz#frag", "gz", "last dot before fragment");
    expect_ext("/a/b", NULL, "no dot");
    expect_ext("/a.b/c", NULL, "dot in an earlier segment");
    expect_ext("/x.", NULL, "trailing dot");
    expect_ext("?a.b", NULL, "dot only in the query");
    expect_ext(".htaccess", "htaccess", "leading dot, no slash");
    expect_ext("b.js", "js", "dot reached at index 1");
    expect_ext("", NULL, "empty url");
    {
        /* A slice that stops inside a longer buffer: the bytes after the
         * slice must not be scanned. */
        const char buf[] = "/x.js EXTRA.exe";
        size_t ext_len = 0;
        const char* ext = extract_url_extension(buf, 5, &ext_len);
        expect(ext != NULL && ext_len == 2 && memcmp(ext, "js", 2) == 0, "slice bound respected");
    }

    /* is_escaped_payload */
    expect_escaped("plain text", 0, "no escapes");
    expect_escaped("\\x41", 0, "one \\x sequence is not enough");
    expect_escaped("\\x41\\x42", 1, "two \\x sequences at the slice end");
    expect_escaped("\\u0041\\x42", 1, "mixed \\u and \\x");
    expect_escaped("\\u004", 0, "truncated \\u");
    expect_escaped("\\x41\\x4", 0, "second \\x truncated at the end");
    expect_escaped("\\xZZ\\xZZ", 0, "non-hex digits");
    expect_escaped("\\\\x41", 0, "escaped backslash then one sequence");
    expect_escaped("", 0, "empty input");

    /* get_file_type */
    expect_type("php", FILE_TYPE_THREAT, "php");
    expect_type("exe", FILE_TYPE_THREAT, "exe");
    expect_type("aspx", FILE_TYPE_THREAT, "aspx");
    expect_type("sh", FILE_TYPE_THREAT, "sh");
    expect_type("png", FILE_TYPE_IGNORE, "png");
    expect_type("js", FILE_TYPE_IGNORE, "js");
    expect_type("woff2", FILE_TYPE_IGNORE, "woff2");
    expect_type("txt", FILE_TYPE_NONE, "txt");
    expect_type("pdf", FILE_TYPE_NONE, "pdf is left to shellcode_skip_types");
    expect_type("", FILE_TYPE_NONE, "empty extension");
    expect_type("phpx", FILE_TYPE_NONE, "length decides before content");

    /* payload_has_shellcode */
    {
        const char* esc = "GET /x?q=\\x90\\x90\\x31\\xc0";
        expect_shellcode(NULL, esc, 1, "no URL: raw scan decides");
        expect_shellcode("/run.php?a=1", esc, 1, "threat extension is scanned");
        expect_shellcode("/logo.png", esc, 0, "static asset skipped");
        expect_shellcode("/LOGO.PNG", esc, 0, "asset match is case-insensitive");
        expect_shellcode("/r.pdf", esc, 0, "operator type skipped");
        expect_shellcode("/R.Docx#p2", esc, 0, "operator type, mixed case, before fragment");
        expect_shellcode("/a.verylong", esc, 1, "extension over the cap is never skipped");
        expect_shellcode("/a/", esc, 1, "no extension is scanned");
        expect_shellcode("/run.php", "plain request", 0, "clean raw message");
        expect_shellcode("/run.php", "", 0, "empty raw message");
        expect(payload_has_shellcode(NULL, 0, esc, strlen(esc), NULL, NULL, 0) == 1, "no skip list");
    }

    if (fails) {
        fprintf(stderr, "test_thrt_payload: %d of %d checks failed\n", fails, checks);
        return 1;
    }
    printf("test_thrt_payload: %d checks ok\n", checks);
    return 0;
}
