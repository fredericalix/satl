#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# tests/cluster/encrypted.sh — M6 live verification of overlay data-plane
# encryption (`--opt encrypted`), the cluster half of Task 5.
#
# Usage: tests/cluster/encrypted.sh [-h]
#
# Requires a formed cluster (run.sh init_and_join or a full run.sh pass) and
# seeded images (images.sh). The script deploys itself: once with production
# defaults, once with the keyring testing knobs for the rotation scenario,
# then back to production defaults. Set SATL_SKIP_DEPLOY=1 to skip the
# initial deploy when the branch is already installed (the two mid-run
# re-deploys always happen; they are cheap, SATL_SKIP_BUILD=1).
#
# The scenarios, in order, each with captured evidence on stdout:
#
#   preflight — the Task 4c concerns on an IPsec-naive node: setkey -D is
#               benign, enc0 exists without kldload.
#   create    — network create --opt encrypted; tasks RUNNING on two nodes;
#               inspect shows Options {"encrypted": "true"}; the VTEP is on a
#               port from the encrypted range 4790..=4999.
#   wire      — tasks exchange traffic; tcpdump on the underlay shows ESP
#               (proto 50) and ZERO cleartext UDP on the network's port;
#               setkey -D/-DP show the SAs and the [any]-source SP.
#   mtu       — in-jail epair and bridge MTU 1416 for the encrypted network,
#               1450 for an unencrypted control network; the two coexist
#               (ESP for one, cleartext 4789 for the other); DF-boundary
#               pings prove both MTUs exact across nodes.
#   guard     — satl/guard anchor rules on both nodes; a crafted cleartext
#               VXLAN probe from the peer node is dropped (block counter
#               increments, nothing decapsulates onto the overlay bridge).
#   rotation  — redeployed with keyring_rotate_after_secs = 120 /
#               keyring_phase_settle_secs = 10; a continuous ping across one
#               full rotation; the outbound SPI changes, loss stays a blip
#               (experiment measured ~1%), the ring settles back to at most
#               primary + previous; then production defaults are restored.
#   teardown  — service rm + network rm; SAD/SPD empty on every node,
#               satl/guard flushed, no 4790-4999 listeners, no
#               interface/jail leftovers.
#
# House rules are run.sh's: no hardcoded addresses (inventory.toml only),
# no fixed sleeps (bounded polls), assertions read host ground truth.
# Everything printed is bounded; the run is meant to be tee'd to a log.

set -e

CLUSTER_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$CLUSTER_DIR/lib.sh"

usage() {
	sed -n '2,/^$/p' "$0" | sed 's/^#//; s/^ //'
	exit "${1:-0}"
}

while [ "$#" -gt 0 ]; do
	case $1 in
	-h | --help) usage 0 ;;
	-*) die "unknown option: $1 (try -h)" ;;
	*) break ;;
	esac
done

# ---------------------------------------------------------------- settings ---

UNDERLAY_IF=$(cluster_setting underlay_if)
STATE_DIR=$(cluster_setting state_dir)
REG_PORT=$(cluster_setting registry_port)
REG_NS=$(cluster_setting registry_namespace)

IMAGE=${SATL_TEST_IMAGE:-"127.0.0.1:$REG_PORT/$REG_NS/freebsd-nginx:latest"}
BODY=${SATL_TEST_BODY:-satl-test-ok}

ENC=${SATL_TEST_ENC_NET:-encnet}
PLAIN=${SATL_TEST_PLAIN_NET:-plainnet}
ENC_A=${SATL_TEST_ENC_A:-enc-a}
ENC_B=${SATL_TEST_ENC_B:-enc-b}
PLAIN_A=${SATL_TEST_PLAIN_A:-plain-a}
PLAIN_B=${SATL_TEST_PLAIN_B:-plain-b}

# The rotation testing knobs, injected through deploy.sh's SATL_SATLD_EXTRA.
ROTATE_AFTER=${SATL_TEST_ROTATE_AFTER:-120}
PHASE_SETTLE=${SATL_TEST_PHASE_SETTLE:-10}
# The ping spans the rotation: the leader notices the overdue ring on its
# first pass, then append, two settles.
ROT_PING_COUNT=${SATL_TEST_ROT_PING_COUNT:-1800}
ROT_PING_INTERVAL=${SATL_TEST_ROT_PING_INTERVAL:-0.1}
# Loss ceiling across the rotation, percent. The experiment measured 1.2%
# (hack/experiments/esp/README.md Q6); five times that is still a blip, and
# anything worse contradicts the measured design.
ROT_LOSS_MAX=${SATL_TEST_ROT_LOSS_MAX:-6}

ENC_MTU=1416
PLAIN_MTU=1450

POLL=${SATL_POLL:-3}
T_CONVERGE=${SATL_T_CONVERGE:-300}
T_CLEAN=${SATL_T_CLEAN:-180}
T_QUICK=${SATL_T_QUICK:-60}
T_ROTATE=${SATL_T_ROTATE:-300}

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/satl-enc.XXXXXX") || die "mktemp -d failed"
CURRENT=""
SUMMARY="$TMPD/summary"
: >"$SUMMARY"

on_exit() {
	_rc=$?
	if [ "$_rc" -ne 0 ]; then
		hdr "summary"
		while read -r _line; do info "$_line"; done <"$SUMMARY"
		[ -n "$CURRENT" ] && info "FAIL     $CURRENT"
		log ""
		log "The daemon's tracing is in /var/log/messages on each node:"
		for _n in $(cluster_nodes); do
			log "    ssh $(node_target "$_n") 'sudo grep -a satld /var/log/messages | tail -200'"
		done
	fi
	rm -rf "$TMPD"
	exit "$_rc"
}
trap on_exit EXIT

fail() {
	set +e
	printf '\n  FAIL: %s\n' "$*" >&2
	exit 1
}

# ------------------------------------------------------------ table parsing --
# run.sh's TCOLS_AWK, verbatim: read satl tables by header name, because the
# CLI pads columns and a cell can contain spaces or be empty.
TCOLS_AWK='
NR == 1 {
	nw = split(want, w, ",")
	n = split($0, h, "  +")
	start = 1
	for (i = 1; i <= n; i++) {
		p = index(substr($0, start), h[i]) + start - 1
		pos[i] = p
		start = p + length(h[i])
		byname[h[i]] = i
	}
	ncol = n
	for (k = 1; k <= nw; k++) {
		if (!(w[k] in byname)) {
			printf "encrypted.sh: no column \"%s\" in table header: %s\n", w[k], $0 > "/dev/stderr"
			exit 2
		}
		col[k] = byname[w[k]]
	}
	next
}
/^[[:space:]]*$/ { next }
{
	out = ""
	for (k = 1; k <= nw; k++) {
		c = col[k]
		len = (c < ncol) ? pos[c + 1] - pos[c] : length($0) - pos[c] + 1
		cell = substr($0, pos[c], len)
		sub(/^[[:space:]]+/, "", cell)
		sub(/[[:space:]]+$/, "", cell)
		out = out (k > 1 ? "\t" : "") cell
	}
	print out
}
'
tcols() { awk -v want="$2" "$TCOLS_AWK" "$1"; }
countl() { awk 'END { print NR + 0 }'; }

show() { sed 's/^/    /' "$1"; }

# node_sudo <node> <command...> — a root one-liner on the node. For anything
# longer than one line, use node_root_sh with a heredoc instead.
node_sudo() {
	_ns=$1
	shift
	node_ssh "$_ns" "sudo -n $*"
}

# wait_until <seconds> <description> <shell test> — bounded poll.
wait_until() {
	_limit=$1
	_what=$2
	_cond=$3
	_t0=$(date +%s)
	printf '  %-58s' "wait: $_what"
	while :; do
		if eval "$_cond"; then
			printf ' ok %ss\n' "$(($(date +%s) - _t0))"
			return 0
		fi
		if [ "$(($(date +%s) - _t0))" -ge "$_limit" ]; then
			printf ' TIMEOUT %ss\n' "$_limit"
			fail "timed out after ${_limit}s waiting for: $_what"
		fi
		printf '.'
		sleep "$POLL"
	done
}

# --------------------------------------------------------- hostname mapping --

HOSTMAP="$TMPD/hostmap"

build_hostmap() {
	: >"$HOSTMAP"
	for _bh in $(cluster_nodes); do
		_hn=$(node_ssh "$_bh" hostname 2>/dev/null) ||
		    die "cannot read the hostname of $_bh over ssh"
		printf '%s %s\n' "$_hn" "$_bh" >>"$HOSTMAP"
	done
}

host_of() { awk -v n="$1" '$2 == n { print $1 }' "$HOSTMAP"; }

# ----------------------------------------------------------- cluster state ---

# swarm_ready_on <node> <count> — <node> answers and shows <count> Ready.
swarm_ready_on() {
	node_ssh "$1" "satl node ls 2>/dev/null" >"$TMPD/nodes" || return 1
	_ready=$(tcols "$TMPD/nodes" STATUS | awk '$0 == "Ready" { n++ } END { print n + 0 }')
	[ "$_ready" = "$2" ]
}

# require_swarm — the scenarios need the formed cluster the inventory
# describes, seen from its bootstrap node. Polls: a deploy has just
# restarted every daemon, and raft needs a moment to reform.
require_swarm() {
	BOOT=$(bootstrap_node)
	CTL=$BOOT
	_want=$(cluster_nodes | countl)
	node_ssh "$BOOT" "satl node ls" >/dev/null 2>&1 ||
	    fail "no formed swarm on $BOOT — run: sh tests/cluster/run.sh init_and_join"
	wait_until "$T_QUICK" "all $_want nodes Ready on $BOOT" \
	    'swarm_ready_on "$BOOT" "$_want"'
	info "formed swarm of $_want nodes, driving it through $CTL"
}

# swarm_ready — every node answers and reports all nodes Ready (a poll test).
swarm_ready() {
	_want=$(cluster_nodes | countl)
	for _n in $(cluster_nodes); do
		node_ssh "$_n" "satl node ls 2>/dev/null" >"$TMPD/nodes.$_n" || return 1
		_ready=$(tcols "$TMPD/nodes.$_n" STATUS | awk '$0 == "Ready" { n++ } END { print n + 0 }')
		[ "$_ready" = "$_want" ] || return 1
	done
}

# svc_running <service> — true when the service reports <n>/<n> with n > 0.
svc_running() {
	node_ssh "$CTL" "satl service ls 2>/dev/null" >"$TMPD/svc" || return 1
	_r=$(tcols "$TMPD/svc" 'NAME,REPLICAS' | awk -F'\t' -v s="$1" '$1 == s { print $2 }')
	[ -n "$_r" ] || return 1
	[ "${_r%/*}" = "${_r#*/}" ] && [ "${_r%/*}" != "0" ]
}

# ----------------------------------------------------- host ground truth -----

# node_jails <node> — one line per SatL jail: "<jid> <name> <processes>"
# (run.sh's helper, verbatim).
node_jails() {
	node_root_sh "$1" "$STATE_DIR" <<'REMOTE' 2>/dev/null
state_dir=$1
jls -N jid name path 2>/dev/null |
    awk -v d="$state_dir/" '$3 ~ "^" d { print $1, $2 }' |
while read -r jid name; do
	procs=$(ps -J "$jid" -o pid= 2>/dev/null | wc -l | tr -d ' ')
	printf '%s %s %s\n' "$jid" "$name" "$procs"
done
REMOTE
}

# task_jid <node> <service> — the jid of the service's running task on <node>.
task_jid() {
	_tj_task=$(node_ssh "$1" "satl service ps $2 --quiet --no-trunc 2>/dev/null" |
	    head -1 | tr -d '\r')
	[ -n "$_tj_task" ] || return 0
	node_jails "$1" | awk -v t="$_tj_task" '$2 == t && $3 > 0 { print $1 }'
}

# task_addr <node> <network> <service> — the task's overlay address on
# <network>, from network inspect (api-compat 62: Containers carries
# IPv4Address).
task_addr() {
	_ta_task=$(node_ssh "$1" "satl service ps $3 --quiet --no-trunc 2>/dev/null" |
	    head -1 | tr -d '\r')
	[ -n "$_ta_task" ] || return 0
	node_ssh "$1" "satl network inspect $2 2>/dev/null" |
	    tr ',' '\n' | grep -A 4 "$_ta_task" | sed -n 's/.*"IPv4Address"[^"]*"\([^"/]*\).*/\1/p' |
	    head -1
}

# in_jail <node> <jid> <command...> — run a command inside a task's jail.
# /rescue first: an OCI image has no /usr/bin (run.sh's ovl_in_jail).
in_jail() {
	_ij_node=$1
	_ij_jid=$2
	shift 2
	node_root_sh "$_ij_node" "$_ij_jid" "$*" <<'REMOTE' 2>&1
jid=$1
cmd=$2
jexec "$jid" /bin/sh -c "PATH=/rescue:/bin:/sbin:/usr/bin:/usr/sbin; $cmd"
REMOTE
}

# net_vni <network> — the allocated VNI, from inspect on $CTL.
net_vni() {
	node_ssh "$CTL" "satl network inspect $1 2>/dev/null" |
	    sed -n 's/.*"Vni": *\([0-9][0-9]*\).*/\1/p' | head -1
}

# iface_by_descr <node> <description> — the interface carrying exactly that
# satl: description (the ownership marker, docs/networking.md).
iface_by_descr() {
	node_ssh "$1" 'ifconfig -a 2>/dev/null' | awk -v d="$2" '
		/^[a-z]/ { i = $1; sub(/:$/, "", i) }
		/^[[:space:]]*description: / {
			line = $0
			sub(/^[[:space:]]*description: /, "", line)
			if (line == d) print i
		}
	'
}

# ------------------------------------------------------------- deploy --------

# deploy_all <extra|-> — deploy.sh on every node. "-" means production
# defaults. Only the first call may build; re-deploys ship the existing
# binaries (SATL_SKIP_BUILD=1). The initial deploy is skipped entirely under
# SATL_SKIP_DEPLOY=1.
deploy_all() {
	_extra=$1
	if [ "$_extra" != "-" ]; then
		SATL_SATLD_EXTRA=$_extra SATL_SKIP_BUILD=1 sh "$CLUSTER_DIR/deploy.sh" >"$TMPD/deploy" 2>&1
	elif [ "${_INITIAL_DEPLOY_DONE:-0}" = 0 ]; then
		if [ "${SATL_SKIP_DEPLOY:-0}" = 1 ]; then
			info "SATL_SKIP_DEPLOY=1 — keeping the installed binaries"
			_INITIAL_DEPLOY_DONE=1
			return 0
		fi
		sh "$CLUSTER_DIR/deploy.sh" >"$TMPD/deploy" 2>&1
	else
		SATL_SKIP_BUILD=1 sh "$CLUSTER_DIR/deploy.sh" >"$TMPD/deploy" 2>&1
	fi || {
		show "$TMPD/deploy"
		fail "deploy.sh failed"
	}
	_INITIAL_DEPLOY_DONE=1
}

# ===========================================================================
# Scenario preflight — the Task 4c concerns on an IPsec-naive node
#
# Before anything in this run touches IPsec: `setkey -D` must be a benign
# "No SAD entries." (concern #1) and enc0 must exist with no kldload
# (concern #2) — on every node, since any of them could have been the naive
# one.
# ===========================================================================
# networks_gone — both networks deleted; retries the rm through the 409s
# while a task still holds an attachment (api-compat). A task whose jail had
# an open TCP connection takes ~60s to drain (docs/jail-teardown.md), so
# this needs the full T_CLEAN budget, not a fixed retry count.
networks_gone() {
	for _net in "$ENC" "$PLAIN"; do
		node_ssh "$CTL" "satl network inspect $_net >/dev/null 2>&1" || continue
		node_ssh "$CTL" "satl network rm $_net >/dev/null 2>&1" || return 1
	done
}

# clean_previous_run — a previous run that failed mid-suite leaves the
# services and networks behind (with SAs, SPs and the guard programmed);
# remove them and wait for the node's own teardown to drain the IPsec
# state, so preflight sees an IPsec-naive node again.
clean_previous_run() {
	for _s in "$ENC_A" "$ENC_B" "$PLAIN_A" "$PLAIN_B"; do
		node_ssh "$CTL" "satl service rm $_s >/dev/null 2>&1" || true
	done
	wait_until "$T_CLEAN" "leftover networks of any previous run deleted" 'networks_gone'
	wait_until "$T_CLEAN" "leftovers of any previous run drained" 'teardown_clean'
}

scenario_preflight() {
	clean_previous_run
	for _n in $(cluster_nodes); do
		node_root_sh "$_n" <<'REMOTE' >"$TMPD/pf.$_n" 2>&1
echo "--- setkey -D:"
setkey -D 2>&1
echo "--- setkey -DP:"
setkey -DP 2>&1
echo "--- enc0:"
ifconfig enc0 2>&1
echo "--- ipsec_filter_mask: $(sysctl -n net.enc.in.ipsec_filter_mask 2>&1)"
REMOTE
		grep -q 'No SAD entries' "$TMPD/pf.$_n" ||
		    fail "$_n: setkey -D is not benign on an IPsec-naive node:
$(cat "$TMPD/pf.$_n")"
		grep -q 'No SPD entries' "$TMPD/pf.$_n" ||
		    fail "$_n: setkey -DP is not benign:
$(cat "$TMPD/pf.$_n")"
		grep -q '^enc0:' "$TMPD/pf.$_n" ||
		    fail "$_n: enc0 does not exist without a kldload:
$(cat "$TMPD/pf.$_n")"
	done
	info "setkey -D/-DP benign (No SAD/SPD entries), enc0 present on every node, no kldload"
	show "$TMPD/pf.$(cluster_nodes | sed -n 1p)"
}

# ===========================================================================
# Scenario create — create + schedule
# ===========================================================================
scenario_create() {
	NA=$(cluster_nodes | sed -n 1p)
	NB=$(cluster_nodes | sed -n 2p)
	[ -n "$NB" ] || fail "the encrypted scenarios need at least two nodes"
	HA=$(host_of "$NA")
	HB=$(host_of "$NB")
	info "encrypted pair: $ENC_A on $NA ($HA), $ENC_B on $NB ($HB); control: $PLAIN_A/$PLAIN_B"

	# `--opt encrypted=true`, not Docker's bare `--opt encrypted`: the bare
	# spelling sends an empty value, which the daemon 400s today (accepted
	# values are "true"/"false"; the ""-compat question is a deferred Task 1
	# review item, not something a test task patches around).
	node_ssh "$CTL" "satl network create -d overlay --opt encrypted=true $ENC" >"$TMPD/netenc" 2>&1 || {
		show "$TMPD/netenc"
		fail "satl network create --opt encrypted=true $ENC failed"
	}
	node_ssh "$CTL" "satl network create -d overlay $PLAIN" >/dev/null ||
	    fail "satl network create -d overlay $PLAIN failed"
	info "created encrypted network $ENC and unencrypted control $PLAIN"

	wait_until "$T_QUICK" "$ENC shows encrypted + VNI on every node" '
		_ok=1
		for _n in $(cluster_nodes); do
			_j=$(node_ssh "$_n" "satl network inspect $ENC 2>/dev/null") || _ok=0
			printf %s "$_j" | grep -q "\"encrypted\": *\"true\"" || _ok=0
			printf %s "$_j" | grep -q "\"Vni\"" || _ok=0
			printf %s "$_j" | grep -q "\"Scope\": *\"swarm\"" || _ok=0
		done
		[ "$_ok" = 1 ]'
	node_ssh "$CTL" "satl network inspect $ENC" >"$TMPD/inspect" 2>&1
	show "$TMPD/inspect"
	VNI=$(net_vni "$ENC")
	[ -n "$VNI" ] || fail "no VNI in the inspect output of $ENC"
	info "VNI $VNI allocated; inspect shows Options encrypted=true"

	for _pair in "$ENC_A $HA" "$ENC_B $HB" "$PLAIN_A $HA" "$PLAIN_B $HB"; do
		set -- $_pair
		_net=$ENC
		case $1 in "$PLAIN_A" | "$PLAIN_B") _net=$PLAIN ;; esac
		node_ssh "$CTL" "satl service create --name $1 --replicas 1 \
		    --network $_net --constraint node.hostname==$2 $IMAGE" >/dev/null ||
		    fail "satl service create $1 failed"
	done
	info "created $ENC_A, $ENC_B (on $ENC) and $PLAIN_A, $PLAIN_B (on $PLAIN), pinned"

	wait_until "$T_CONVERGE" "all four services Running" '
		svc_running "$ENC_A" && svc_running "$ENC_B" &&
		svc_running "$PLAIN_A" && svc_running "$PLAIN_B"'

	# Placement is an assertion, not an assumption.
	JEA=$(task_jid "$NA" "$ENC_A")
	JEB=$(task_jid "$NB" "$ENC_B")
	JPA=$(task_jid "$NA" "$PLAIN_A")
	JPB=$(task_jid "$NB" "$PLAIN_B")
	[ -n "$JEA" ] && [ -n "$JEB" ] && [ -n "$JPA" ] && [ -n "$JPB" ] ||
	    fail "a task did not land on its pinned node: JEA=$JEA JEB=$JEB JPA=$JPA JPB=$JPB"
	info "jails: $ENC_A=$JEA ($NA), $ENC_B=$JEB ($NB), $PLAIN_A=$JPA ($NA), $PLAIN_B=$JPB ($NB)"

	AEA=$(task_addr "$NA" "$ENC" "$ENC_A")
	AEB=$(task_addr "$NB" "$ENC" "$ENC_B")
	APA=$(task_addr "$NA" "$PLAIN" "$PLAIN_A")
	APB=$(task_addr "$NB" "$PLAIN" "$PLAIN_B")
	[ -n "$AEA" ] && [ -n "$AEB" ] && [ -n "$APA" ] && [ -n "$APB" ] ||
	    fail "could not read all four overlay addresses"
	info "overlay addresses: $ENC_A $AEA, $ENC_B $AEB, $PLAIN_A $APA, $PLAIN_B $APB"

	# The VTEP port, from host ground truth: the interface marked
	# satl:vxlan:<net> must listen on a port in the encrypted range.
	VXEA=$(iface_by_descr "$NA" "satl:vxlan:$ENC")
	VXEB=$(iface_by_descr "$NB" "satl:vxlan:$ENC")
	[ -n "$VXEA" ] && [ -n "$VXEB" ] || fail "no satl:vxlan:$ENC interface on $NA/$NB"
	node_ssh "$NA" "ifconfig $VXEA" >"$TMPD/vtep.a" 2>&1
	node_ssh "$NB" "ifconfig $VXEB" >"$TMPD/vtep.b" 2>&1
	grep 'vxlan vni' "$TMPD/vtep.a" | sed 's/^/    /'
	grep 'vxlan vni' "$TMPD/vtep.b" | sed 's/^/    /'
	ENC_PORT=$(sed -n 's/.*local [0-9.]*:\([0-9][0-9]*\).*/\1/p' "$TMPD/vtep.a" | head -1)
	[ -n "$ENC_PORT" ] || fail "could not read the VTEP port from $(cat "$TMPD/vtep.a")"
	[ "$ENC_PORT" -ge 4790 ] && [ "$ENC_PORT" -le 4999 ] ||
	    fail "VTEP port $ENC_PORT outside the encrypted range 4790..=4999"
	grep -q "remote [0-9.]*:$ENC_PORT" "$TMPD/vtep.a" ||
	    fail "the VTEP's remote port is not $ENC_PORT: $(cat "$TMPD/vtep.a")"
	info "VTEPs $VXEA ($NA) and $VXEB ($NB) on encrypted-range port $ENC_PORT"
}

# ===========================================================================
# Scenario wire — encryption on the wire
#
# The capture pattern, here and below: tcpdump in the background on the
# node, traffic, then pkill by interface name (tcpdump -c alone could wait
# forever for packets that never come, and an unbounded capture is a disk
# problem). The capture file lives in /tmp on the node and is removed after
# the read.
# ===========================================================================

# start_wire_capture <node> <file-stem> <tcpdump-filter> — background.
start_wire_capture() {
	node_root_sh "$1" "$UNDERLAY_IF" "$2" "$3" <<'REMOTE' >/dev/null 2>&1 &
iface=$1
stem=$2
filter=$3
tcpdump -l -n -i "$iface" -c 400 "$filter" >"/tmp/$stem.cap" 2>/dev/null
REMOTE
}

# stop_wire_capture <node> <file-stem> — kill, read back, remove.
stop_wire_capture() {
	node_ssh "$1" "sudo -n pkill -f 'tcpdump -l -n -i $UNDERLAY_IF'" >/dev/null 2>&1 || true
	sleep 1
	node_root_sh "$1" "$2" <<'REMOTE' 2>/dev/null
stem=$1
cat "/tmp/$stem.cap" 2>/dev/null
rm -f "/tmp/$stem.cap"
REMOTE
}

scenario_wire() {
	# Traffic between the tasks, by service name: DNS answer, overlay data
	# path and a real TCP conversation, exactly as overlay_dns proves it.
	_fetch=$(in_jail "$NA" "$JEA" "fetch -q -T 5 -o - http://$ENC_B/" || true)
	printf %s "$_fetch" | grep -q "$BODY" ||
	    fail "$ENC_B did not answer by name from the $ENC_A jail: $_fetch"
	info "fetch http://$ENC_B/ from the $ENC_A jail returned the baked body"

	start_wire_capture "$NB" satl-enc-wire "esp or (udp and port $ENC_PORT)"
	sleep 2
	in_jail "$NA" "$JEA" "ping -c 20 -i 0.1 -t 15 $AEB" >"$TMPD/ping" 2>&1 || true
	grep -q ' 0.0% packet loss' "$TMPD/ping" ||
	    fail "ping $ENC_A -> $ENC_B lost packets:
$(cat "$TMPD/ping")"
	sleep 2
	stop_wire_capture "$NB" satl-enc-wire >"$TMPD/wire.b"

	_esp=$(awk '/ESP\(spi=/' "$TMPD/wire.b" | countl)
	_clear=$(awk '/VXLAN|UDP/' "$TMPD/wire.b" | countl)
	[ "$_esp" -gt 0 ] ||
	    fail "no ESP (proto 50) on $NB's $UNDERLAY_IF during the ping:
$(cat "$TMPD/wire.b")"
	[ "$_clear" = 0 ] ||
	    fail "cleartext VXLAN on port $ENC_PORT on the wire:
$(cat "$TMPD/wire.b")"
	info "wire on $NB: $_esp ESP lines, $_clear cleartext UDP/$ENC_PORT lines"
	grep 'ESP(spi=' "$TMPD/wire.b" | head -3 | sed 's/^/    /'

	# The SAs, on both nodes: one outbound (emission, the primary) and the
	# inbound ring (reception).
	for _n in "$NA" "$NB"; do
		node_sudo "$_n" setkey -D >"$TMPD/sad.$_n" 2>/dev/null
		node_sudo "$_n" setkey -DP >"$TMPD/spd.$_n" 2>/dev/null
		_sas=$(awk '/^[0-9]/' "$TMPD/sad.$_n" | countl)
		[ "$_sas" -ge 2 ] ||
		    fail "$_n holds fewer than two SAs:
$(cat "$TMPD/sad.$_n")"
		grep -q "\[$ENC_PORT\]" "$TMPD/spd.$_n" ||
		    fail "$_n has no SP selecting port $ENC_PORT:
$(cat "$TMPD/spd.$_n")"
		grep -q '\[any\]' "$TMPD/spd.$_n" ||
		    fail "the SP on $_n does not use the [any] source selector:
$(cat "$TMPD/spd.$_n")"
		info "$_n: $_sas SAs (inbound ring + outbound primary), SP with [any] source selector"
		head -8 "$TMPD/sad.$_n" | sed 's/^/    /'
		head -4 "$TMPD/spd.$_n" | sed 's/^/    /'
	done
}

# ===========================================================================
# Scenario mtu — 1416 encrypted, 1450 control, coexisting
# ===========================================================================

# jail_mtu <node> <jid> <net> — the MTU of the jail's epair ON <net>. A task
# also has an epair on the node-local bridge (mtu 1500), so the right one is
# identified by its satl:overlay:<net>: description, not by order (lo0 sorts
# first, the node-local epair second — both are false reads).
jail_mtu() {
	in_jail "$1" "$2" "ifconfig" | awk -v d="description: satl:overlay:$3:" '
		/^[a-z]/ { iface = $1; sub(/:$/, "", iface) }
		iface && /mtu / {
			for (i = 1; i <= NF; i++) if ($i == "mtu") mtu[iface] = $(i + 1)
		}
		index($0, d) { mine = iface }
		END { print mtu[mine] }
	'
}

# bridge_mtu <node> <net> — the MTU of the network's bridge.
bridge_mtu() {
	_br=$(iface_by_descr "$1" "satl:overlay:$2")
	[ -n "$_br" ] || return 1
	node_ssh "$1" "ifconfig $_br" |
	    awk '/mtu / { for (i = 1; i <= NF; i++) if ($i == "mtu") { print $(i + 1); exit } }'
}

scenario_mtu() {
	# In-jail epairs and bridges: encrypted 1416, control 1450.
	for _spec in "$NA $JEA $ENC $ENC_MTU" "$NB $JEB $ENC $ENC_MTU" \
	    "$NA $JPA $PLAIN $PLAIN_MTU" "$NB $JPB $PLAIN $PLAIN_MTU"; do
		set -- $_spec
		_got=$(jail_mtu "$1" "$2" "$3")
		[ "$_got" = "$4" ] || fail "$2 on $1 ($3): in-jail epair MTU $_got, expected $4"
	done
	for _spec in "$NA $ENC $ENC_MTU" "$NB $ENC $ENC_MTU" \
	    "$NA $PLAIN $PLAIN_MTU" "$NB $PLAIN $PLAIN_MTU"; do
		set -- $_spec
		_got=$(bridge_mtu "$1" "$2") ||
		    fail "no satl:overlay:$2 bridge on $1"
		[ "$_got" = "$3" ] || fail "$1: $2 bridge MTU $_got, expected $3"
	done
	info "in-jail epairs and bridges: $ENC_MTU on $ENC, $PLAIN_MTU on $PLAIN (both nodes)"

	# The MTUs are exact at the DF boundary, across the underlay:
	# 1388 + 28 = 1416 crosses the encrypted net, 1389 is refused locally;
	# 1422 + 28 = 1450 crosses the control, 1423 is refused.
	_p=$(in_jail "$NA" "$JEA" "ping -c 3 -D -s 1388 -t 10 $AEB" || true)
	printf %s "$_p" | grep -q ' 0.0% packet loss' ||
	    fail "1388-byte DF ping across $ENC failed; the encrypted MTU is below $ENC_MTU:
$_p"
	_p=$(in_jail "$NA" "$JEA" "ping -c 1 -D -s 1389 -t 5 $AEB" || true)
	printf %s "$_p" | grep -qi 'Message too long' ||
	    fail "a 1389-byte DF ping was not refused; the encrypted MTU is above $ENC_MTU:
$_p"
	info "encrypted net: DF ping at 1388 crosses, 1389 refused — MTU exactly $ENC_MTU"

	_p=$(in_jail "$NA" "$JPA" "ping -c 3 -D -s 1422 -t 10 $APB" || true)
	printf %s "$_p" | grep -q ' 0.0% packet loss' ||
	    fail "1422-byte DF ping across $PLAIN failed:
$_p"
	_p=$(in_jail "$NA" "$JPA" "ping -c 1 -D -s 1423 -t 5 $APB" || true)
	printf %s "$_p" | grep -qi 'Message too long' ||
	    fail "a 1423-byte DF ping was not refused; the control MTU is above $PLAIN_MTU:
$_p"
	info "control net: DF ping at 1422 crosses, 1423 refused — MTU exactly $PLAIN_MTU"

	# Coexistence on the wire: ping both networks; the capture must show ESP
	# (encrypted) AND cleartext UDP/4789 (control), and still zero cleartext
	# on the encrypted port.
	start_wire_capture "$NB" satl-enc-mix "esp or (udp and port $ENC_PORT) or (udp and port 4789)"
	sleep 2
	in_jail "$NA" "$JEA" "ping -c 15 -i 0.1 -t 10 $AEB" >/dev/null 2>&1 || true
	in_jail "$NA" "$JPA" "ping -c 15 -i 0.1 -t 10 $APB" >/dev/null 2>&1 || true
	sleep 2
	stop_wire_capture "$NB" satl-enc-mix >"$TMPD/wire.mix"

	_esp=$(awk '/ESP\(spi=/' "$TMPD/wire.mix" | countl)
	_clear_enc=$(awk '/VXLAN|UDP/ && !/4789/' "$TMPD/wire.mix" | countl)
	_clear_plain=$(awk '/VXLAN|UDP/ && /4789/' "$TMPD/wire.mix" | countl)
	[ "$_esp" -gt 0 ] || fail "no ESP in the mixed capture:
$(cat "$TMPD/wire.mix")"
	[ "$_clear_plain" -gt 0 ] ||
	    fail "no cleartext UDP/4789 in the mixed capture — the control net did not cross:
$(cat "$TMPD/wire.mix")"
	[ "$_clear_enc" = 0 ] ||
	    fail "cleartext on the encrypted port $ENC_PORT in the mixed capture:
$(cat "$TMPD/wire.mix")"
	info "mixed capture: ESP x$_esp ($ENC), cleartext UDP/4789 x$_clear_plain ($PLAIN), cleartext/$ENC_PORT x0"
	grep '4789' "$TMPD/wire.mix" | head -2 | sed 's/^/    /'
	grep 'ESP(spi=' "$TMPD/wire.mix" | head -2 | sed 's/^/    /'
}

# ===========================================================================
# Scenario guard — the pf cleartext guard
# ===========================================================================

# guard_rules <node> — the satl/guard anchor with per-rule counters.
guard_rules() {
	node_sudo "$1" pfctl -a satl/guard -sr -vv 2>/dev/null
}

# guard_packets <node> <rule-fragment> — the Packets counter of the first
# matching guard rule (0 when absent). The FIRST Packets line after the
# match is that rule's; without the exit, a later rule's counter overwrites.
guard_packets() {
	guard_rules "$1" | awk -v f="$2" '
		$0 ~ f { found = 1 }
		found && /Packets:/ {
			for (i = 1; i <= NF; i++) if ($i == "Packets:") { print $(i + 1); exit }
		}
		END { if (!found) print 0 }
	'
}

scenario_guard() {
	# The anchor, on both nodes: block on the underlay, pass-no-state on
	# enc0. The rules cover the whole encrypted port RANGE 4790:4999, not
	# the one network's port — deliberate (satl-net::guard_rules): the
	# ruleset is static while >= 1 encrypted network exists, so a new
	# encrypted network needs no reload.
	for _n in "$NA" "$NB"; do
		guard_rules "$_n" >"$TMPD/guard.$_n"
		grep -q "block drop in log quick on $UNDERLAY_IF proto udp from any to any port 4790:4999" "$TMPD/guard.$_n" ||
		    fail "$_n: no guard block rule for the encrypted port range:
$(cat "$TMPD/guard.$_n")"
		grep -q "pass in quick on enc0 proto udp from any to any port 4790:4999 no state" "$TMPD/guard.$_n" ||
		    fail "$_n: no guard pass-no-state rule for the encrypted port range:
$(cat "$TMPD/guard.$_n")"
		info "$_n: satl/guard holds the block (underlay) and pass-no-state (enc0) rules"
		show "$TMPD/guard.$_n"
	done
	# The enc0 substrate the guard depends on (experiment §7).
	_mask=$(node_sudo "$NA" sysctl -n net.enc.in.ipsec_filter_mask)
	[ "$_mask" = 2 ] ||
	    fail "$NA: net.enc.in.ipsec_filter_mask is $_mask, the guard needs 2"
	info "net.enc.in.ipsec_filter_mask = 2 on $NA (decapsulated presentation on enc0)"

	# The third node is NOT a participant: no keys, no SAs, no guard — the
	# distribution-is-participants-only invariant, on host ground truth.
	NC=$(cluster_nodes | sed -n 3p)
	[ -n "$NC" ] || fail "the guard scenario wants a third, non-participant node"
	_sad_nc=$(node_sudo "$NC" setkey -D 2>/dev/null)
	printf %s "$_sad_nc" | grep -q 'No SAD entries' ||
	    fail "$NC (not a participant) holds SAs — key distribution leaked:
$_sad_nc"
	_guard_nc=$(guard_rules "$NC" | countl)
	[ "$_guard_nc" = 0 ] ||
	    fail "$NC (not a participant) has satl/guard rules"
	info "$NC (non-participant): SAD empty, no guard rules — distribution is participants-only"

	_block_before=$(guard_packets "$NB" 'block drop in log quick')
	_pass_before=$(guard_packets "$NB" 'pass in quick on enc0')

	# The probe: a *valid* cleartext VXLAN frame (right VNI, broadcast inner
	# destination, so the bridge would flood it to the task's epair — the
	# exact frame was live-verified to decapsulate when it arrives via the
	# legitimate ESP path), sent raw to the port from the NON-PARTICIPANT
	# node. It must come from there: a participant's own outbound SP
	# encrypts anything it sends to the port (experiment Q3d — outbound
	# fails closed), so a probe from $NA would arrive as ESP, not
	# cleartext. The payload is padded past the 60-byte Ethernet minimum:
	# the 42-byte runt of an earlier draft was dropped by if_vxlan after
	# decapsulation, which would have made "the bridge stays quiet" prove
	# nothing. Without the guard this frame decapsulates onto the overlay
	# bridge (experiment Q3b); with it, pflog and the block counter eat it
	# and the bridge stays quiet (G3). The octal escapes are built as text
	# and reinterpreted by the second printf, the POSIX way to emit binary
	# from sh.
	_vni_hex=$(printf '%06x' "$VNI")
	_v1=$((0x$(printf %s "$_vni_hex" | cut -c1-2)))
	_v2=$((0x$(printf %s "$_vni_hex" | cut -c3-4)))
	_v3=$((0x$(printf %s "$_vni_hex" | cut -c5-6)))
	_esc=$(printf '\\010\\000\\000\\000\\%03o\\%03o\\%03o\\000' "$_v1" "$_v2" "$_v3")
	_esc="$_esc\\377\\377\\377\\377\\377\\377\\002\\343\\000\\000\\000\\001\\010\\000"
	printf "$_esc"'satl-cleartext-probe-payload-padded-to-64-bytes-total-abcdefgh' >"$TMPD/probe"
	node_scp "$NC" /tmp "$TMPD/probe"

	_nbi=$(node_field "$NB" private_ip)
	BRE=$(iface_by_descr "$NB" "satl:overlay:$ENC")
	[ -n "$BRE" ] || fail "no satl:overlay:$ENC bridge on $NB"
	# The bridge capture spans the probes: anything decapsulated shows here.
	node_root_sh "$NB" "$BRE" <<'REMOTE' >/dev/null 2>&1 &
bridge=$1
tcpdump -l -n -i "$bridge" -c 20 >/tmp/satl-enc-bridge.cap 2>/dev/null
REMOTE
	sleep 2
	_i=0
	while [ "$_i" -lt 3 ]; do
		node_ssh "$NC" "nc -u -w 1 $_nbi $ENC_PORT < /tmp/probe" >/dev/null 2>&1 || true
		_i=$((_i + 1))
	done
	sleep 3
	node_ssh "$NB" "sudo -n pkill -f 'tcpdump -l -n -i $BRE'" >/dev/null 2>&1 || true
	sleep 1
	node_root_sh "$NB" <<'REMOTE' >"$TMPD/bridge.cap" 2>/dev/null
cat /tmp/satl-enc-bridge.cap 2>/dev/null
rm -f /tmp/satl-enc-bridge.cap
REMOTE
	node_ssh "$NC" 'rm -f /tmp/probe' >/dev/null 2>&1 || true

	_block_after=$(guard_packets "$NB" 'block drop in log quick')
	_pass_after=$(guard_packets "$NB" 'pass in quick on enc0')
	_blocked=$((_block_after - _block_before))
	_passed=$((_pass_after - _pass_before))
	[ "$_blocked" -ge 3 ] ||
	    fail "the guard block counter moved by $_blocked (< 3 probes): $_block_before -> $_block_after"
	[ "$_passed" = 0 ] ||
	    fail "the guard pass counter moved by $_passed while probing — the probe took the enc0 path?"
	# A tcpdump killed with zero packets leaves a one-blank-line file
	# (measured), so count content lines, not lines.
	_bridge_lines=$(awk 'NF { n++ } END { print n + 0 }' "$TMPD/bridge.cap")
	if [ "$_bridge_lines" != 0 ]; then
		log "  bridge capture ($_bridge_lines lines, sed -n l):"
		sed -n l "$TMPD/bridge.cap" | head -10 | sed 's/^/    /'
		fail "the cleartext probe decapsulated onto the overlay bridge"
	fi
	info "3 cleartext probes: block counter +$_blocked, pass counter +0, bridge quiet ($_bridge_lines packets)"
	guard_rules "$NB" | sed 's/^/    /'
}

# ===========================================================================
# Scenario rotation — a full key rotation, live
# ===========================================================================

# outbound_spis <node> <peer-node> — the SPIs (hex) of every SA
# <node-ip> -> <peer-ip>, one per line.
outbound_spis() {
	_peer_ip=$(node_field "$2" private_ip)
	node_sudo "$1" setkey -D 2>/dev/null | awk -v dst="$_peer_ip" '
		/^[0-9]/ { inb = ($2 == dst) }
		inb && /spi=/ {
			line = $0
			sub(/.*spi=[0-9]+\(/, "", line)
			sub(/\).*/, "", line)
			print line
		}
	'
}

scenario_rotation() {
	_old_spi=$(outbound_spis "$NA" "$NB" | head -1)
	[ -n "$_old_spi" ] || fail "no outbound SA on $NA towards $NB before the rotation"
	info "outbound SPI before the rotation: $_old_spi"

	hdr "redeploy with keyring_rotate_after_secs = $ROTATE_AFTER, keyring_phase_settle_secs = $PHASE_SETTLE"
	deploy_all "keyring_rotate_after_secs = $ROTATE_AFTER
keyring_phase_settle_secs = $PHASE_SETTLE"
	wait_until "$T_QUICK" "swarm back after the redeploy" 'swarm_ready'

	# The knobs landed: the startup warning is in the manager logs.
	_warn=$(node_ssh "$CTL" "sudo -n grep -a 'keyring cadence' /var/log/messages 2>/dev/null | tail -1" || true)
	if [ -n "$_warn" ]; then
		printf '%s\n' "$_warn" | sed 's/^/    /'
	else
		warn "no keyring-cadence startup warning in $CTL's log (rotation evidence weakened)"
	fi

	# The continuous ping spans the whole rotation. Jails survive a satld
	# restart by design, so the redeploy above already cost it nothing. The
	# PATH wrapper is in_jail's: /rescue is a host path, not an image path.
	node_root_sh "$NA" "$JEA" "$AEB" "$ROT_PING_COUNT" "$ROT_PING_INTERVAL" <<'REMOTE' >/dev/null 2>&1 &
jid=$1
peer=$2
count=$3
interval=$4
jexec "$jid" /bin/sh -c "PATH=/rescue:/bin:/sbin:/usr/bin:/usr/sbin; \
    ping -c $count -i $interval -t $((count / 5 + 60)) $peer" \
    >/tmp/satl-enc-rotping.out 2>&1
REMOTE
	_ping=$!

	# Rotation is the SPI switch: the new outbound SA appears and the old
	# one is deleted — the delete is the promoting step (experiment Q6).
	_new_spi=""
	wait_until "$T_ROTATE" "the ring advanced (outbound SPI changed on $NA)" '
		_spis=$(outbound_spis "$NA" "$NB")
		_new_spi=""
		for _s in $_spis; do
			[ "$_s" != "$_old_spi" ] && _new_spi=$_s
		done
		[ -n "$_new_spi" ] && ! printf %s "$_spis" | grep -q "$_old_spi"'
	info "outbound SPI after the rotation: $_new_spi (was $_old_spi)"

	# The keyring transitions, from the leader's own log (whichever node led
	# after the redeploy — not necessarily $CTL).
	for _n in $(cluster_nodes); do
		node_ssh "$_n" "sudo -n grep -a 'keyring transition' /var/log/messages 2>/dev/null | tail -4" |
		    sed "s/^/    $_n: /"
	done

	# The ring settled back: at most 2 inbound SAs (primary + previous) and
	# 1 outbound on this peer — 3 headers in total, never more.
	_sas=$(node_sudo "$NA" setkey -D 2>/dev/null | awk '/^[0-9]/ { n++ } END { print n + 0 }')
	[ "$_sas" -le 3 ] ||
	    fail "$NA holds $_sas SAs after the rotation — the ring did not prune back"
	info "SAD after the rotation: $_sas SAs (<= 2 inbound + 1 outbound: primary + previous)"

	# The ping's verdict.
	wait "$_ping" 2>/dev/null || true
	node_root_sh "$NA" <<'REMOTE' >"$TMPD/rotping" 2>/dev/null
tail -4 /tmp/satl-enc-rotping.out
rm -f /tmp/satl-enc-rotping.out
REMOTE
	show "$TMPD/rotping"
	_loss=$(sed -n 's/.*, \([0-9.]*\)% packet loss.*/\1/p' "$TMPD/rotping" | head -1)
	[ -n "$_loss" ] ||
	    fail "no loss figure in the rotation ping:
$(cat "$TMPD/rotping")"
	_ok=$(awk -v l="$_loss" -v m="$ROT_LOSS_MAX" 'BEGIN { print (l + 0 <= m + 0) ? 1 : 0 }')
	[ "$_ok" = 1 ] ||
	    fail "rotation loss $_loss% exceeds the $ROT_LOSS_MAX% blip ceiling — contradicts the measured ~1%"
	info "rotation loss: $_loss% across the SPI switch (ceiling $ROT_LOSS_MAX%)"

	# Back to production defaults for the remaining scenarios.
	hdr "redeploy with production defaults"
	deploy_all -
	wait_until "$T_QUICK" "swarm back on production cadence" 'swarm_ready'
	_p=$(in_jail "$NA" "$JEA" "ping -c 3 -t 10 $AEB" || true)
	printf %s "$_p" | grep -q ' 0.0% packet loss' ||
	    fail "the pair does not ping after the return to production defaults:
$_p"
	info "production defaults restored; the pair still pings"
}

# ===========================================================================
# Scenario teardown — service rm + network rm leaves nothing
# ===========================================================================

# teardown_clean — the poll test: SAD/SPD empty, guard flushed, no
# 4790-4999 listeners, no network interfaces left, on every node.
teardown_clean() {
	for _n in $(cluster_nodes); do
		node_sudo "$_n" setkey -D 2>/dev/null | grep -q 'No SAD entries' || return 1
		node_sudo "$_n" setkey -DP 2>/dev/null | grep -q 'No SPD entries' || return 1
		_guard=$(guard_rules "$_n" | countl)
		[ "$_guard" = 0 ] || return 1
		_listeners=$(node_ssh "$_n" "sockstat -46l 2>/dev/null" |
		    awk '{ p = $6; sub(/.*:/, "", p); p += 0;
		           if (p >= 4790 && p <= 4999) n++ } END { print n + 0 }')
		[ "$_listeners" = 0 ] || return 1
		_ifaces=$(iface_by_descr "$_n" "satl:overlay:$ENC")
		_ifaces="$_ifaces$(iface_by_descr "$_n" "satl:vxlan:$ENC")"
		_ifaces="$_ifaces$(iface_by_descr "$_n" "satl:overlay:$PLAIN")"
		_ifaces="$_ifaces$(iface_by_descr "$_n" "satl:vxlan:$PLAIN")"
		[ -z "$_ifaces" ] || return 1
	done
	return 0
}

scenario_teardown() {
	for _s in "$ENC_A" "$ENC_B" "$PLAIN_A" "$PLAIN_B"; do
		node_ssh "$CTL" "satl service rm $_s >/dev/null 2>&1" || true
	done
	wait_until "$T_CLEAN" "services and both networks removed" 'networks_gone'
	info "services and both networks removed"

	wait_until "$T_CLEAN" "SAD/SPD, guard, ports and interfaces clean on every node" \
	    'teardown_clean'
	info "SAD/SPD empty, satl/guard flushed, no 4790-4999 listeners, no interfaces left"

	for _n in $(cluster_nodes); do
		_jails=$(node_jails "$_n" | countl)
		[ "$_jails" = 0 ] || fail "$_n still has $_jails SatL jails"
	done
	info "no SatL jails left on any node"
}

# =================================================================== driver ==

log "SatL encrypted-overlay verification — inventory $INVENTORY"

hdr "deploy (production defaults)"
deploy_all -

require_swarm
build_hostmap
while read -r hn nn; do info "$nn is '$hn' (as its agent reports it)"; done <"$HOSTMAP"

for scenario in preflight create wire mtu guard rotation teardown; do
	hdr "scenario $scenario"
	CURRENT=$scenario
	t0=$(date +%s)
	"scenario_$scenario"
	elapsed=$(($(date +%s) - t0))
	printf '  PASS %s in %ss\n' "$scenario" "$elapsed"
	printf 'PASS     %-12s %ss\n' "$scenario" "$elapsed" >>"$SUMMARY"
	CURRENT=""
done

hdr "summary"
while read -r line; do info "$line"; done <"$SUMMARY"
log ""
log "All encrypted-overlay scenarios passed."
