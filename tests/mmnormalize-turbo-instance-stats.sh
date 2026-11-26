#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# statsName gives an mmnormalize action its own impstats object. It counts
# parsed and failed messages, the messages the Turbo result answered, and,
# for each tag listed in statsTags, the Turbo matches whose rule carries it.
#
# Three rules: one untagged, one tagged "catchall", one tagged "other". The
# input has two lines for the untagged rule, one for each tagged rule and two
# that match nothing. A second action without statsName must not appear.
. ${srcdir:=.}/diag.sh init
require_plugin imtcp
require_plugin mmnormalize
require_plugin impstats

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/mmnormalize/.libs/mmnormalize")
module(load="../plugins/impstats/.libs/impstats" interval="1"
	log.file="'$RSYSLOG_DYNNAME'.stats" log.syslog="off" format="json")
input(type="imtcp" port="0"
	listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port" ruleset="norm")

template(name="ok" type="string" string="%parsesuccess% %$!tags%\n")

ruleset(name="norm") {
	action(type="mmnormalize" useRawMsg="on" turbo="on"
		statsName="src-a" statsTags=["catchall", "unused"]
		rule=["rule=:alpha %v:word%",
		      "rule=catchall:beta %r:rest%",
		      "rule=other:gamma %v:word%"])
	action(type="mmnormalize" useRawMsg="on" turbo="on" path="$!second"
		rule="rule=:alpha %v:word%")
	action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="ok")
}
'
startup
tcpflood -m1 -M "\"alpha one\""
tcpflood -m1 -M "\"alpha two\""
tcpflood -m1 -M "\"beta anything at all\""
tcpflood -m1 -M "\"gamma three\""
tcpflood -m1 -M "\"delta nothing\""
tcpflood -m1 -M "\"epsilon\""
wait_file_lines "$RSYSLOG_OUT_LOG" 6
wait_content '"name": *"mmnormalize(src-a)".*"failed": *2' "$RSYSLOG_DYNNAME.stats"
shutdown_when_empty
wait_shutdown

stats_line() {
	grep '"mmnormalize(src-a)"' "$RSYSLOG_DYNNAME.stats" | tail -1
}
check_counter() {
	if ! stats_line | grep -qE "\"$1\": *$2[ ,}]"; then
		echo "FAIL: expected $1=$2 in: $(stats_line)"
		error_exit 1
	fi
}
check_counter parsed 4
check_counter failed 2
check_counter turbo.parsed 4
check_counter turbo.fallback.parsed 0
check_counter parsed.catchall 1
check_counter parsed.unused 0
if stats_line | grep -q 'parsed.other'; then
	echo "FAIL: a tag not listed in statsTags was counted: $(stats_line)"
	error_exit 1
fi
# exactly one per-action object: the second action did not ask for one
if grep -o '"name": *"mmnormalize([^"]*)"' "$RSYSLOG_DYNNAME.stats" | sort -u | grep -vq 'src-a'; then
	echo "FAIL: an action without statsName published an object"
	error_exit 1
fi
exit_test
