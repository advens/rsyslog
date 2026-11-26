#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# statsName and statsTags reach impstats output and downstream metric names,
# so a value outside [A-Za-z0-9_.-] is refused, and so is statsTags without
# statsName. A refused action is not loaded: the config check reports it.
. ${srcdir:=.}/diag.sh init
require_plugin mmnormalize

check_refused() {
	generate_conf
	add_conf '
module(load="../plugins/mmnormalize/.libs/mmnormalize")
action(type="mmnormalize" rule="rule=:x %v:word%" '"$1"')
'
	../tools/rsyslogd -N1 -f "${TESTCONF_NM}.conf" -M"$RSYSLOG_MODDIR" > "$RSYSLOG_DYNNAME.out" 2>&1
	if ! grep -q "$2" "$RSYSLOG_DYNNAME.out"; then
		echo "FAIL: '$1' was not refused with '$2':"
		cat "$RSYSLOG_DYNNAME.out"
		error_exit 1
	fi
}
check_refused 'statsName="a(b)"' "statsName 'a(b)' must be"
check_refused 'statsName="a/b"' "statsName 'a/b' must be"
check_refused 'statsTags=["catchall"]' "'statsTags' requires 'statsName'"
check_refused 'statsName="ok" statsTags=["a", "a"]' "statsTags lists 'a' twice"
check_refused 'statsName="ok" statsTags=["a b"]' "statsTags entry 'a b' must be"
check_refused 'statsName="ok" statsTags=[""]' "statsTags entry '' must be"
check_refused 'statsName="ok" statsTags=["1","2","3","4","5","6","7","8","9"]' "statsTags accepts at most 8 tags"
exit_test
