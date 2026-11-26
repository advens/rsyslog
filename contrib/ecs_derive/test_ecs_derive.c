/* test_ecs_derive.c: standalone unit test for the ECS derive layer.
 * Builds with: cc -std=c11 -I. -o /tmp/t test_ecs_derive.c && /tmp/t
 * No rsyslog/liblognorm deps: pure logic test of ecs_derive.h. */
#include "ecs_derive.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
    else         { printf("ok  : %s\n", msg); } } while (0)

/* mock turbo snapshot: a tiny (name,value) table */
struct kv { const char *k, *v; };
static int mock_get(void *ctx, const char *name, const char **val, size_t *vlen)
{
    struct kv *t = (struct kv *)ctx;
    for (; t->k; t++) {
        if (strcmp(t->k, name) == 0) {
            *val = t->v; *vlen = strlen(t->v); return 1;
        }
    }
    return 0;
}

static int derive(struct kv *snap, const char *field, char *buf, size_t bufsz)
{
    const char *out = NULL; size_t olen = 0;
    if (!ecs_derive_lookup(field, mock_get, snap, &out, &olen, buf, bufsz)) return 0;
    size_t n = olen < bufsz - 1 ? olen : bufsz - 1;
    memcpy(buf, out, n); buf[n] = '\0';
    return 1;
}

int main(void)
{
    char buf[256];

    /* nginx $uri (path-only) -> url.path is the whole string */
    struct kv s1[] = { {"url.original", "/.git/config"}, {NULL,NULL} };
    CHECK(derive(s1, "url.path", buf, sizeof buf) && strcmp(buf, "/.git/config") == 0,
          "nginx path-only: url.path == url.original");

    /* full URL with query -> path truncated at '?' (future full-URL source) */
    struct kv s2[] = { {"url.original", "/search?q=/.env&x=1"}, {NULL,NULL} };
    CHECK(derive(s2, "url.path", buf, sizeof buf) && strcmp(buf, "/search") == 0,
          "query stripped at '?'");

    /* fragment truncation */
    struct kv s3[] = { {"url.original", "/page#frag"}, {NULL,NULL} };
    CHECK(derive(s3, "url.path", buf, sizeof buf) && strcmp(buf, "/page") == 0,
          "fragment stripped at '#'");

    /* the secrets-path the custom rule hunts, with a query tail */
    struct kv s4[] = { {"url.original", "/.env?a=b"}, {NULL,NULL} };
    CHECK(derive(s4, "url.path", buf, sizeof buf) && strcmp(buf, "/.env") == 0,
          "rule-7 target /.env survives query strip (still contains '/.env')");

    /* source absent -> not derivable */
    struct kv s5[] = { {"source.ip", "1.2.3.4"}, {NULL,NULL} };
    CHECK(!derive(s5, "url.path", buf, sizeof buf),
          "no url.original -> url.path not derivable");

    /* unknown derived field -> miss */
    struct kv s6[] = { {"url.original", "/x"}, {NULL,NULL} };
    CHECK(!derive(s6, "url.scheme", buf, sizeof buf),
          "undeclared derived field -> miss");

    /* table is non-empty and url.path is declared */
    int found = 0;
    for (size_t i = 0; i < ECS_DERIVE_COUNT; i++)
        if (strcmp(ecs_derive_table[i].derived, "url.path") == 0) found = 1;
    CHECK(found && ECS_DERIVE_COUNT >= 1, "url.path declared in shared .def table");

    CHECK(ecs_geo_base("source.ip", buf, sizeof buf) && strcmp(buf, "!source") == 0,
          "source.ip stamps !source");
    CHECK(ecs_geo_base("src_ip", buf, sizeof buf) && strcmp(buf, "!src_ip") == 0,
          "src_ip stamps !src_ip");
    CHECK(ecs_geo_base("dest_ip", buf, sizeof buf) && strcmp(buf, "!dest_ip") == 0,
          "dest_ip stamps !dest_ip");
    CHECK(ecs_geo_base("src", buf, sizeof buf) && strcmp(buf, "!source") == 0, "CEF src stamps !source");
    CHECK(ecs_geo_base("dst", buf, sizeof buf) && strcmp(buf, "!destination") == 0, "CEF dst stamps !destination");

    printf("\n%s (%zu table rows, %d failures)\n",
           fails ? "FAILED" : "PASSED", (size_t)ECS_DERIVE_COUNT, fails);
    return fails ? 1 : 0;
}
