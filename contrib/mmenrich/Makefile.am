# mmenrich: generic line-rate log-enrichment module.
#
# Emits enrichment facts (CTI IOC lookup, GeoIP/ASN, CTI overlay, ECS-derived
# fields, IOC mining, structural content flags) as message fields; it does not
# score. Requires liblognorm turbo. Links libfastjson and liblognorm, plus
# optional libmaxminddb for GeoIP.

pkglib_LTLIBRARIES = mmenrich.la

# The .thrt format and lookup headers (thrt_format.h, thrt_logic.h,
# thrt_overlay.h, thrt_ipparse.h, prev_format.h) are installed by libenrich
# and reached via LIBENRICH_CFLAGS (pkg-config enrich). thrt_payload.h holds
# the payload classification behind the $!shellcode flag.
mmenrich_la_SOURCES = mmenrich.c \
                      prev_live.c \
                      prev_live.h \
                      thrt_file_cache.c \
                      thrt_file_cache.h \
                      thrt_miner.h \
                      enrich_json.h \
                      thrt_payload.h \
                      thrt_ua.h \
                      thrt_tld.h

# Guarantee the hardware CRC32C path on the target CPUs (x86-64-v2 / ARMv8.2+),
# independent of how the port's CPUTYPE propagates into this automake sub-build.
# The code gates the hardware CRC on __SSE4_2__ / __ARM_FEATURE_CRC32
# (libenrich's thrt_logic.h); pin the matching -march here.
# host_cpu is substituted by AC_CANONICAL_HOST.
mmenrich_archflags_amd64   = -march=x86-64-v2 -msse4.2
mmenrich_archflags_x86_64  = -march=x86-64-v2 -msse4.2
mmenrich_archflags_aarch64 = -march=armv8-a+crc
mmenrich_archflags_arm64   = -march=armv8-a+crc
MMENRICH_ARCHFLAGS = $(mmenrich_archflags_@host_cpu@)

# liblognorm turbo is REQUIRED (mmenrich has no slow fallback path).
# ecs_derive.h (shared ECS derived-field layer, emitted into $!) is staged by
# the port into contrib/ecs_derive (post-extract) and reached via
# -I$(srcdir)/../ecs_derive, the same way mmsigma includes it. (The upstream
# fork keeps ecs_derive.h in runtime/ and reaches it via RSRT_CFLAGS; this port
# relocates it, so the include path differs here.)
mmenrich_la_CPPFLAGS = $(RSRT_CFLAGS) $(PTHREADS_CFLAGS) $(JSON_C_CFLAGS) $(LIBLOGNORM_CFLAGS) $(LIBENRICH_CFLAGS) -I$(srcdir)/../ecs_derive
mmenrich_la_CFLAGS = $(AM_CFLAGS) $(MMENRICH_ARCHFLAGS)
mmenrich_la_LDFLAGS = -module -avoid-version
# -lm: ecs_derive.h's DNS-entropy feature uses log2() in the derived-ECS emit.
mmenrich_la_LIBADD = $(JSON_C_LIBS) $(LIBLOGNORM_LIBS) $(LIBENRICH_LIBS) -lm
if MMENRICH_GEOIP_SUPPORTED
mmenrich_la_CPPFLAGS += -DHAVE_MMENRICH_GEOIP
mmenrich_la_LIBADD += -lmaxminddb
endif

# Standalone helpers, built HERE in contrib/mmenrich rather than under
# tools/ENABLE_USERTOOLS so a package can ship them without pulling in the
# whole usertools set (logctl/rscryutil):
#   thrtutil      builds and applies the .thrt this module reads
#   thrt_cli      lookup CLI for a .thrt
#   overlay_tool  build/query a .ovly overlay
#   prev_lookup   query a .prev prevalence table
#   ua_lookup     classify a User-Agent against ua.json
#   tld_lookup    classify a domain last-label against tld.json
bin_PROGRAMS = ua_lookup tld_lookup
# json.h lives in libfastjson. mmenrich.la finds it through RSRT_CFLAGS
# (which already folds in LIBFASTJSON_CFLAGS). JSON_C_CFLAGS is empty in
# this tree; using it alone left the helpers with no -I and failed the
# Linux package build (fatal error: json.h).
ua_lookup_SOURCES = ua_lookup.c thrt_ua.h
ua_lookup_CPPFLAGS = $(RSRT_CFLAGS)
ua_lookup_CFLAGS = -O3 -Wall -Wextra $(MMENRICH_ARCHFLAGS)
ua_lookup_LDADD = $(LIBFASTJSON_LIBS)
tld_lookup_SOURCES = tld_lookup.c thrt_tld.h
tld_lookup_CPPFLAGS = $(RSRT_CFLAGS)
tld_lookup_CFLAGS = -O3 -Wall -Wextra $(MMENRICH_ARCHFLAGS)
tld_lookup_LDADD = $(LIBFASTJSON_LIBS)

EXTRA_DIST = fuzz_miner.c \
             test_ecs_derive.c \
             test_file_cache.c \
             test_party_threat.c \
             test_prev_live.c \
             test_thrt_payload.c \
             test_thrt_tld.c \
             test_thrt_ua.c \
             tests/cti_fold_idempotency.py \
             prev_write.py \
             Makefile.dev
