# mmsigma: rsyslog glue on top of libsigma.
#
# Selection match, correlation, contrib JSON, and event-time live in
# libsigma (devel/libsigma). This directory is the rsyslog module only.
# An upstream rsyslog PR vendors libsigma sources into this directory
# (scripts/vendor-libsigma-into-rsyslog.sh) and compiles them in-tree.
#
# Products:
#  1. mmsigma.la, the rsyslog message-mod module.
#  2. test_ecs_derive, header-only ECS derive self-test (not libsigma).
#  3. test_mmsigma_contrib, self-test of the emitted-partial rules.
# Engine tests run in the libsigma port.

pkglib_LTLIBRARIES = mmsigma.la

mmsigma_la_SOURCES = mmsigma.c mmsigma_contrib.h mmsigma_atomic.h
# -I../ecs_derive: shared ECS derived-field layer. The prevalence table is
# read through libenrich (pkg-config enrich).
mmsigma_la_CPPFLAGS = $(RSRT_CFLAGS) $(PTHREADS_CFLAGS) $(JSON_C_CFLAGS) \
                      $(LIBLOGNORM_CFLAGS) $(LIBSIGMA_CFLAGS) $(LIBENRICH_CFLAGS) \
                      -I$(srcdir)/../ecs_derive
mmsigma_la_LDFLAGS = -module -avoid-version
# -lm: ecs_derive.h's DNS-entropy feature uses log2() in the module field
# resolver (mmnormalize/mmjsonparse declare -lm the same way).
mmsigma_la_LIBADD = $(JSON_C_LIBS) $(LIBLOGNORM_LIBS) $(LIBSIGMA_LIBS) $(LIBENRICH_LIBS) -lm

noinst_PROGRAMS = test_ecs_derive test_mmsigma_contrib

# ECS derived-field layer self-test (SLICE + COMPUTED DGA/HTTP transforms + the
# ecs_derive_lookup resolver). The only standalone tool that includes
# ecs_derive.h; still libc-only at link (header-only; -lm for log2).
test_ecs_derive_SOURCES = test_ecs_derive.c
test_ecs_derive_CPPFLAGS = -I$(srcdir)/../ecs_derive
test_ecs_derive_CFLAGS = -O2 -Wall -Wextra
test_ecs_derive_LDADD = -lm

# Emitted-partial rules (mmsigma_contrib.h). Uses libsigma's headers only.
test_mmsigma_contrib_SOURCES = test_mmsigma_contrib.c mmsigma_contrib.h
test_mmsigma_contrib_CPPFLAGS = $(LIBSIGMA_CFLAGS)
test_mmsigma_contrib_CFLAGS = -O2 -Wall -Wextra
test_mmsigma_contrib_LDADD = -lm

EXTRA_DIST = Makefile.dev
