#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# tests/cluster/soak-report.sh -- read a soak, rather than remember to.
#
# The M12 soak item is "leave it running for a few days and re-read
# /var/log/messages for anything the suites cannot see: slow leaks, a raft node
# that stops contributing, an assertion that only fires under real uptime."
# That is a reading, not a test, and a reading done by hand is done differently
# every time and compared against nothing. This prints the same numbers in the
# same order on every run, so two runs a week apart are a diff.
#
# It asserts nothing and changes nothing: every line is an observation, and
# judging them is the operator's job. Exit status is 0 unless a node could not
# be reached, because "the soak looks wrong" is not something a script gets to
# decide.
#
# Usage:
#   sh tests/cluster/soak-report.sh                  # every node in the inventory
#   sh tests/cluster/soak-report.sh node1 node3      # only these
#   sh tests/cluster/soak-report.sh --host fralix@alpha.example.com
#                                                    # a host outside the inventory
#                                                    # (the single-node soak lives there)
#   SATL_SOAK_SINCE='Aug 25' sh tests/cluster/soak-report.sh
#                                                    # narrow the log window to a
#                                                    # syslog date prefix
#
# What each block is for:
#
#   uptime        satld's start time and elapsed run time. A soak whose daemon
#                 restarted is not a soak of that length, and this is the only
#                 line that can tell you.
#   memory        RSS and virtual size. One number means nothing; the same
#                 number a week later is the leak check the suites cannot do.
#   containers    jail ids with their start times. **The ids matter more than
#                 the count**: same id across two reports is a container that
#                 was never restarted, which is the property re-adoption
#                 promises (architecture 7.2). A changed id with an unchanged
#                 count is a silent restart, and reads as health.
#   raft          the last leadership line and the number of term changes in
#                 the window. A cluster that keeps re-electing is contributing
#                 less than its node count suggests.
#   loud lines    ERROR and WARN counts per tracing target, most frequent
#                 first. This is the shape of the log rather than its content:
#                 a target that was quiet last week and is now the top line is
#                 the finding.
#   crashes       panics, assertion failures and the daemon's own
#                 "start-up ordering bug" style self-accusations. Zero is the
#                 expected reading and any hit is the whole point of the soak.
#   leaks         epairs, DYING prisons and layer datasets with no @final: the
#                 three things that accumulate quietly on a host that has been
#                 up for days (CLAUDE.md's FreeBSD notes).
#
#                 The epair count is one per (task x network), not one per
#                 task: a task publishing a port sits on the node bridge, its
#                 own overlay and `ingress`, so it holds three. Five epairs for
#                 two containers is what a healthy node looks like, and reading
#                 it as a leak costs a diagnosis. `ifconfig <epair> | grep
#                 description` names the owning task, which is the check that
#                 settles it -- the ifconfig *group* does not survive a vnet
#                 move, the description does.

set -e

CLUSTER_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$CLUSTER_DIR/lib.sh"

MESSAGES=/var/log/messages
# A syslog date prefix ("Aug 25", "Aug 25 14") narrows every count below to
# that window. Unset means the whole file, which is what a first baseline
# wants.
SINCE=${SATL_SOAK_SINCE:-}

EXTRA_HOSTS=
while [ $# -gt 0 ]; do
	case $1 in
	--host)
		[ $# -ge 2 ] || die "--host needs an ssh target"
		EXTRA_HOSTS="$EXTRA_HOSTS $2"
		shift 2
		;;
	--host=*) EXTRA_HOSTS="$EXTRA_HOSTS ${1#--host=}"; shift ;;
	-h|--help) sed -n '3,/^set -e/p' "$0" | sed 's/^#//; s/^ //'; exit 0 ;;
	*) break ;;
	esac
done

# The remote half. Runs as the ssh user and uses sudo only where a reading
# genuinely needs it (jls, zfs list of the layers root), so a node where sudo
# asks for a password degrades to a partial report rather than hanging: every
# sudo here is `-n`.
remote_report() {
	cat <<'REMOTE'
set -u
messages=$1
since=$2

section() { printf '\n  -- %s\n' "$1"; }

# The log window, as a stream every count below reads. `grep -a` always:
# one non-ASCII byte makes grep call the file binary and print nothing, which
# looks exactly like a quiet daemon (CLAUDE.md).
logwin() {
	if [ -n "$since" ]; then
		grep -a "satld\[" "$messages" 2>/dev/null | grep -aF "$since" || true
	else
		grep -a "satld\[" "$messages" 2>/dev/null || true
	fi
}

section uptime
pid=$(pgrep -x satld 2>/dev/null | head -1 || true)
if [ -z "$pid" ]; then
	echo "     satld is NOT RUNNING"
else
	started=$(ps -o lstart= -p "$pid" 2>/dev/null | sed 's/^ *//')
	elapsed=$(ps -o etime= -p "$pid" 2>/dev/null | sed 's/^ *//')
	printf '     pid %s, started %s, up %s\n' "$pid" "$started" "$elapsed"
fi

section memory
if [ -n "$pid" ]; then
	# Two separate -o flags: FreeBSD's ps reads `-o rss=,vsz=` as "column rss
	# with the header ',vsz='", so the one-flag spelling silently prints the
	# header as a line and no vsz at all. Measured, on the first run of this
	# script.
	ps -o rss= -o vsz= -p "$pid" 2>/dev/null |
	    awk 'NF { printf "     rss %.1f MiB, vsz %.1f MiB\n", $1/1024, $2/1024 }'
fi

section containers
if sudo -n jls -h jid name path 2>/dev/null | tail -n +2 | grep -q .; then
	sudo -n jls -h jid name 2>/dev/null | tail -n +2 | while read -r jid name; do
		# The jail's init process start time is the container's real age,
		# and it is what proves re-adoption across a daemon restart.
		jpid=$(pgrep -j "$jid" 2>/dev/null | head -1 || true)
		if [ -n "$jpid" ]; then
			printf '     jid %-4s %s  since %s\n' "$jid" "$name" \
			    "$(ps -o lstart= -p "$jpid" 2>/dev/null | sed 's/^ *//')"
		else
			printf '     jid %-4s %s  (no process)\n' "$jid" "$name"
		fi
	done
else
	echo "     none"
fi

section raft
last=$(logwin | grep -a "cluster state ready\|is_leader" | tail -1 || true)
[ -n "$last" ] && printf '     %s\n' "$(printf '%s' "$last" | sed 's/.*satld\[[0-9]*\]: //' | cut -c1-200)"
terms=$(logwin | grep -ac "became leader\|leader changed\|vote request" || true)
printf '     leadership/vote lines in window: %s\n' "${terms:-0}"

section "loud lines (count, level, target)"
# awk rather than sed: the level is a *field*, so finding it by position needs
# no regex dialect at all. The sed spelling of this looked right, matched
# nothing on a real syslog line, and reported the month name as the top target
# -- which is the kind of wrong that reads as a result.
loud=$(logwin |
    awk '{
        for (i = 1; i <= NF; i++)
            if ($i == "ERROR" || $i == "WARN") {
                target = $(i + 1)
                sub(/[:{].*/, "", target)
                print $i, target
                break
            }
    }' | sort | uniq -c | sort -rn | head -12)
if [ -n "$loud" ]; then
	printf '%s\n' "$loud" | awk '{ printf "     %6d  %-5s %s\n", $1, $2, $3 }'
else
	echo "     none"
fi

section crashes
n=$(logwin | grep -acE "panicked at|assertion .* failed|internal error|ordering bug" || true)
printf '     panic/assertion/self-accusation lines: %s\n' "${n:-0}"
[ "${n:-0}" = 0 ] || logwin | grep -aE "panicked at|assertion .* failed|internal error|ordering bug" |
    tail -5 | sed 's/^/     /' | cut -c1-220

section leaks
# `grep -c` prints 0 **and exits 1** when it matches nothing, so a `|| echo 0`
# appends a second line to a substitution that already said 0. Count with awk,
# which has one exit status and one line.
nlines() { awk 'END { print NR + 0 }'; }
printf '     epair interfaces: %s\n' \
    "$(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^epair' | nlines)"
printf '     DYING prisons:    %s\n' \
    "$(sudo -n jls -d -h name dying 2>/dev/null | tail -n +2 | grep ' true$' | nlines)"
root=$(sudo -n zfs list -H -o name 2>/dev/null | grep -m1 '/layers$' || true)
if [ -n "$root" ]; then
	total=$(sudo -n zfs list -H -o name -r "$root" 2>/dev/null | tail -n +2 | nlines)
	final=$(sudo -n zfs list -H -t snapshot -o name -r "$root" 2>/dev/null |
	    grep '@final$' | nlines)
	printf '     layer datasets:   %s, of which complete (@final): %s\n' "$total" "$final"
	[ "$total" = "$final" ] ||
	    printf '     ^ a layer with no @final is an interrupted apply; the next apply reclaims it\n'
fi
REMOTE
}

run_one() {
	_label=$1
	_target=$2
	hdr "$_label"
	if ! remote_report | ssh $SSH_OPTS "$_target" "sh -s $MESSAGES '$SINCE'" 2>&1; then
		warn "$_label: could not be read"
		return 1
	fi
	return 0
}

hdr "soak report"
if [ -n "$SINCE" ]; then
	info "log window: lines matching '$SINCE'"
else
	info "log window: the whole of $MESSAGES"
fi
info "nothing here is an assertion; two reports a week apart are the finding"

RC=0
for _h in $EXTRA_HOSTS; do
	run_one "$_h (outside the inventory)" "$_h" || RC=1
done

if [ $# -gt 0 ] || [ -z "$EXTRA_HOSTS" ]; then
	for _n in $(resolve_nodes "$@"); do
		run_one "$_n ($(node_field "$_n" ssh_host))" "$(node_target "$_n")" || RC=1
	done
fi

printf '\n'
[ "$RC" = 0 ] || warn "at least one host could not be read"
exit $RC
