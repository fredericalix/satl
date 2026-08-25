#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# tests/cluster/run.sh — the `make cluster-test` entry point.
#
# Usage: tests/cluster/run.sh [-h] [-l] [-r] [scenario ...]
#
#   With no argument: the readiness gate, then every scenario in order, then
#   the leftover audit —
#
#       init_and_join   worker_join   replicas_spread   node_kill
#       leader_kill     overlay_dns   overlay_dns_multinet
#       publish_port    rolling_update
#       global_service  global_update   global_node_loss
#       constraint_enforcer   restart_budget   demote_leader   ca_rotate
#       compose_stack   mesh_failed_start   build_push_run   stack_verbs
#       jobs_and_prefs  hot_resize   images_rm   compose_local
#       cleanup
#
#   With scenario names: the readiness gate (it always gates), then just
#   those, in the order given. `cleanup` is appended only in full-suite mode,
#   so a single scenario leaves the cluster inspectable.
#
#   -l, --list             list the scenarios and exit
#   -r, --readiness-only   run only the readiness gate; the remaining
#                          arguments are node names, not scenario names
#
# The readiness gate asserts that every node in inventory.toml is reachable,
# provisioned (provision.sh), deployed (deploy.sh) and seeded (images.sh).
# Running a scenario against a half-provisioned cluster produces failures that
# look like orchestration bugs and are not, which is why the gate exists and
# why it cannot be skipped.
#
# The scenarios are the M2 Definition of Done (docs/roadmap.md): init + 2
# joins, `--replicas 6` spreads, worker kill → reschedule, leader kill →
# re-election with the killed leader marked Down, its tasks evicted, and the
# API staying up (the eviction is the M4 upgrade). What each one asserts is
# written above its function, and summarised in tests/cluster/README.md.
#
# House rules, enforced throughout:
#   - no address is ever hardcoded: inventory.toml is the only source (CLAUDE.md);
#   - no join token is ever printed, and it travels to the joiners over ssh
#     stdin rather than in an argv a `ps` could show;
#   - no fixed sleeps. Every wait is `wait_until <seconds> <what> <test>`: it
#     polls, prints what it is waiting for and how long it took, and on a
#     timeout dumps the live cluster state plus the daemon log to look at;
#   - assertions read observable cluster state (`satl node ls`,
#     `satl service ls/ps`) and host ground truth (jails, epairs, datasets),
#     never the harness's own idea of what should have happened.
#
# Environment:
#   SATL_INVENTORY      alternate inventory.toml
#   SATL_TEST_IMAGE     image the scenarios run (default: the seeded nginx)
#   SATL_TEST_SERVICE   service name to create (default: web)
#   SATL_REPLICAS       replica count for the spread scenario (default: 6)
#   SATL_POLL           seconds between polls (default: 3)
#   SATL_T_JOIN         timeout: join, promotion, a node coming back (180)
#   SATL_T_CONVERGE     timeout: a service reaching its desired state (300)
#   SATL_T_DOWN         timeout: a stopped node reported Down (120)
#   SATL_T_ELECT        timeout: a new leader elected and serving (120)
#   SATL_T_CLEAN        timeout: leftovers gone after a service rm (180)
#   SATL_T_QUICK        timeout: a read-back or a spread, instant when it works (60)

set -e

CLUSTER_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$CLUSTER_DIR/lib.sh"

usage() {
	sed -n '2,/^$/p' "$0" | sed 's/^#//; s/^ //'
	exit "${1:-0}"
}

SCENARIOS="init_and_join worker_join replicas_spread node_kill leader_kill overlay_dns \
overlay_dns_multinet publish_port rolling_update global_service global_update \
global_node_loss constraint_enforcer restart_budget demote_leader ca_rotate compose_stack \
mesh_failed_start build_push_run stack_verbs jobs_and_prefs hot_resize images_rm compose_local cleanup"

READINESS_ONLY=0
while [ "$#" -gt 0 ]; do
	case $1 in
	-h | --help) usage 0 ;;
	-l | --list)
		for s in $SCENARIOS; do echo "$s"; done
		exit 0
		;;
	-r | --readiness-only) READINESS_ONLY=1; shift ;;
	-*) die "unknown option: $1 (try -h)" ;;
	*) break ;;
	esac
done

# ---------------------------------------------------------------- settings ---

PREFIX=$(cluster_setting prefix)
ZFS_ROOT=$(cluster_setting zfs_root)
STATE_DIR=$(cluster_setting state_dir)
UNDERLAY_IF=$(cluster_setting underlay_if)
REG_PORT=$(cluster_setting registry_port)
REG_NS=$(cluster_setting registry_namespace)
MGR_PORT=$(cluster_setting manager_port)
IMAGES=${SATL_IMAGES:-"freebsd-runtime:15.1 freebsd-nginx:latest freebsd-redis:latest alpine:latest debian:stable-slim"}

# The scenarios run one image, referenced exactly as the single-node
# integration tests reference it: every node has the same loopback registry
# with the same repository names (README, "Images on the VMs").
IMAGE=${SATL_TEST_IMAGE:-"127.0.0.1:$REG_PORT/$REG_NS/freebsd-nginx:latest"}
SERVICE=${SATL_TEST_SERVICE:-web}
REPLICAS=${SATL_REPLICAS:-6}

# worker_join (M4) forms the mixed-role cluster the rest of the suite never
# sees: node2 joins as a manager, node3 with the *worker* token. Its overlay
# pair mirrors overlay_dns on a smaller scale, pinned so that the task that
# must resolve and carry traffic is on the worker.
WJ_OVL=${SATL_TEST_WJ_OVERLAY:-wjnet}
WJ_A=${SATL_TEST_WJ_A:-wj-a}
WJ_B=${SATL_TEST_WJ_B:-wj-b}
# The exact sentence moby's errNoManager returns for a swarm-scoped call on an
# active worker (503; docs/api-compat.md #79). Matched as a substring of the
# CLI's "Error response from daemon: ..." rendering.
WJ_REFUSAL="This node is not a swarm manager. Worker nodes can't be used to view or modify cluster state."

# overlay_dns (M3 DoD) runs its own two single-replica services, pinned to two
# different nodes by constraint rather than left to the spread: "tasks on
# different VMs" is the whole point of the scenario, so it must be a fact and
# not a probability.
OVL=${SATL_TEST_OVERLAY:-ovl}
SVC_A=${SATL_TEST_SVC_A:-ovl-a}
SVC_B=${SATL_TEST_SVC_B:-ovl-b}
# The body hack/images/build-freebsd-nginx.sh bakes into the index page. Getting
# it back through a service name is what "reach each other by service name"
# means, end to end: DNS answer, overlay data path, and a real TCP conversation.
OVL_BODY=${SATL_TEST_BODY:-satl-test-ok}
# 1450 = 1500 underlay - 50 VXLAN. Payload 1422 + 8 ICMP + 20 IP = 1450 exactly,
# so 1422 must pass with DF set and 1423 must not (docs/vxlan.md 6).
OVL_MTU=${SATL_OVERLAY_MTU:-1450}
OVL_PAYLOAD=$((OVL_MTU - 28))

# overlay_dns_multinet (api-compat 73/74) needs two overlay networks and three
# services: one on each network, and one on both. overlay_dns cannot catch a
# scoping regression because with a single network every scope is the same
# scope.
OVL_X=${SATL_TEST_OVERLAY_X:-ovlx}
OVL_Y=${SATL_TEST_OVERLAY_Y:-ovly}
SVC_X=${SATL_TEST_SVC_X:-mn-x}
SVC_Y=${SATL_TEST_SVC_Y:-mn-y}
SVC_BOTH=${SATL_TEST_SVC_BOTH:-mn-both}

# publish_port (api-compat 75) runs its own service with an ingress-published
# port, asserted from *outside* the cluster (this dev host reaches the VMs on
# their public addresses, which is exactly the vantage point a published port
# exists for) and from each node's own loopback: api-compat 35 now records that
# a node reaches its own published ports through 127.0.0.1, via the lo0
# NAT-plus-route relay measured in hack/experiments/lo0rdr/.
#
# Two replicas over three nodes, deliberately: with fewer replicas than nodes at
# least one node runs no task, whatever the scheduler decides, and that node is
# the one assertion 2 needs. Which nodes get a task is then *read* rather than
# assumed, so the run is deterministic without pinning placement.
PUB=${SATL_TEST_PUB_SERVICE:-pub}
# 18080 rather than 8080 because the assertions read the pf anchor back, and
# `pfctl -s nat` prints its own normalisation of a ruleset: a port that has a
# name in /etc/services comes back as that name (8080 prints as `port =
# http-alt`, with or without -N), and 18080 has none. Measured on the VMs.
PUB_PORT=${SATL_TEST_PUB_PORT:-18080}
PUB_REPLICAS=2
# Enough replicas that some node must run two of them (pigeonhole again), which
# is what makes the round-robin pool of api-compat 76 observable. `wc -l` and
# not `countl`: this runs before the helpers below are defined.
PUB_CROWDED=$(($(cluster_nodes | wc -l | tr -d ' ') + 1))

# rolling_update (the M4 DoD) runs its own six-replica service with a published
# port, updated one slot at a time while this host generates traffic against it.
# Its own name and port so it can never collide with $SERVICE or with
# publish_port's, and its own image tags so the update is a real image change.
RU=${SATL_TEST_ROLL_SERVICE:-roll}
RU_PORT=${SATL_TEST_ROLL_PORT:-18082}
RU_REPLICAS=${SATL_TEST_ROLL_REPLICAS:-6}
# Two slots per node, so one slot at a time leaves every node serving. The
# scenario asserts this rather than assuming it.
RU_MIN_SERVING=$((RU_REPLICAS - 1))
# The failure-observation window, in whole seconds: how long each new task must
# be observed running before the batch moves on. Long enough that a node has
# re-derived its pf redirects (satld's port pass, every 5s) before the next slot
# is touched, which is what makes the traffic assertion about the update and not
# about a redirect that had not caught up yet.
RU_MONITOR=${SATL_TEST_ROLL_MONITOR:-8}
# The image the service starts on, the tag it is updated to (same content, so
# the body served never changes and one load generator can span the update), and
# a tag that is in no registry — what a mistyped or unpushed tag looks like from
# the daemon's side.
RU_TAG_A=${SATL_TEST_ROLL_TAG_A:-freebsd-nginx:latest}
RU_TAG_B=${SATL_TEST_ROLL_TAG_B:-freebsd-nginx:rolled}
RU_TAG_BROKEN=${SATL_TEST_ROLL_TAG_BROKEN:-freebsd-nginx:no-such-tag}
# Below this many requests, "no request was lost" says nothing: a load generator
# that died in its first second would prove a flawless update.
RU_MIN_REQUESTS=${SATL_TEST_ROLL_MIN_REQUESTS:-200}
# How long one node may keep answering wrong, and what counts as one window.
# Argued in full on ru_assert_first_attempts: satld re-derives its redirects
# every 5s, so a window closes within one pass; 8s is that plus the jitter of a
# per-second timestamp and a busy node. Failures more than 2s apart are separate
# windows.
RU_STALE_MAX=${SATL_TEST_ROLL_STALE_MAX:-8}
RU_STALE_GAP=${SATL_TEST_ROLL_STALE_GAP:-2}
# The M4 orchestration scenarios — global services, drain, the constraint
# enforcer and the restart budget (commit fb5190a). Each runs a service of its
# own so none can collide with $SERVICE or with the ones above, and each removes
# it again.
GS=${SATL_TEST_GLOBAL_SERVICE:-gagent}
# The monitor window of the global rolling update, in whole seconds: its pace is
# what is asserted (elapsed >= two windows), so it has to be long enough to
# measure and short enough not to dominate the run.
GS_MONITOR=${SATL_TEST_GLOBAL_MONITOR:-8}
# The replicated service a drain moves, and its deliberately long restart delay.
# The 30s is the whole point of the measurement: SWK §7.4 forces the delay to 0
# for a drain, so without a delay that would otherwise be paid, "the drain was
# fast" is not a measurement of anything.
DRS=${SATL_TEST_DRAIN_SERVICE:-drainee}
DRS_REPLICAS=${SATL_TEST_DRAIN_REPLICAS:-6}
DRS_DELAY=${SATL_TEST_DRAIN_DELAY:-30}
# The constrained service, the node label that places it, and its restart delay
# — which a constraint change pays in full, because a label edit is nobody
# waiting on a node. Asserted from the daemon's own `delay_ms` field, which is
# also why the delay is deliberately not the 5s default.
CE=${SATL_TEST_CONSTRAINT_SERVICE:-zoned}
CE_REPLICAS=${SATL_TEST_CONSTRAINT_REPLICAS:-3}
CE_DELAY=${SATL_TEST_CONSTRAINT_DELAY:-10}
CE_LABEL=${SATL_TEST_CONSTRAINT_LABEL:-zone}
CE_MATCH=keep
CE_OTHER=elsewhere
# The crash-looping service of the restart-budget scenario: a bounded number of
# attempts, an entrypoint that exits non-zero, and a delay long enough that the
# leader can be killed *between* two restarts.
RB=${SATL_TEST_BUDGET_SERVICE:-flapper}
RB_ATTEMPTS=${SATL_TEST_BUDGET_ATTEMPTS:-2}
RB_DELAY=${SATL_TEST_BUDGET_DELAY:-25}
RB_EXIT=9

# ca_rotate (M5) runs its own published service under the rolling_update load
# machinery (RU_* is rebound to these for its duration) while the cluster root
# CA is replaced live. Its own name and port so it can never collide with the
# others; the label below is the per-phase write probe and is removed at both
# ends of the scenario.
CR=${SATL_TEST_CA_SERVICE:-rotca}
CR_PORT=${SATL_TEST_CA_PORT:-18084}
CR_REPLICAS=${SATL_TEST_CA_REPLICAS:-6}
CR_LABEL=${SATL_TEST_CA_LABEL:-satl-rot}
# Below this many requests, "no request was lost across the rotation" says
# nothing; the load is held (pre-soak, rotation, post-soak) until it is met.
CR_MIN_REQUESTS=${SATL_TEST_CA_MIN_REQUESTS:-150}

# compose_stack (M5 DoD, driven through `satl stack` since M11a) deploys a
# three-service stack from a Compose file across the cluster; compose_local is
# the node-local half of the same split. The project name is *derived from the
# directory*, which is part of what the scenario tests, so the directory's base
# name is the project: keep the two in step. Its own port and service prefix so it cannot collide with the rest of
# the suite, and its own secret, created outside the file because compose never
# creates one (api-compat 120).
CS_PROJECT=${SATL_TEST_COMPOSE_PROJECT:-cstack}
CS_DIR=${SATL_TEST_COMPOSE_DIR:-/tmp/$CS_PROJECT}
CS_PORT=${SATL_TEST_COMPOSE_PORT:-18086}
CS_SECRET=${SATL_TEST_COMPOSE_SECRET:-cs_redis_auth}
CS_WEB_IMAGE=${SATL_TEST_COMPOSE_WEB_IMAGE:-"127.0.0.1:$REG_PORT/$REG_NS/freebsd-nginx:latest"}
CS_REDIS_IMAGE=${SATL_TEST_COMPOSE_REDIS_IMAGE:-"127.0.0.1:$REG_PORT/$REG_NS/freebsd-redis:latest"}

# mesh_failed_start (B1 non-regression): a crash-looping service whose tasks
# die before their first healthcheck, published to the ingress mesh, while a
# healthy published service is deployed into the storm and serves through it.
# Its own names, and its own ports continuing the suite's plan (18080 pub,
# 18082 roll, 18084 ca, 18086 compose). The restart delay is explicit and
# short: the default is 5s since 80e179f, and the storm wants several rounds a
# minute without ever waiting on one.
MF_FLAP=${SATL_TEST_FLAP_SERVICE:-flap}
MF_FLAP_PORT=${SATL_TEST_FLAP_PORT:-18088}
MF_GOOD=${SATL_TEST_GOOD_SERVICE:-good}
MF_GOOD_PORT=${SATL_TEST_GOOD_PORT:-18090}
MF_REPLICAS=3
MF_REQUESTS=${SATL_TEST_MESH_REQUESTS:-12}
MF_DELAY=${SATL_TEST_FLAP_DELAY:-2}

# build_push_run (M6f/M7b/M8a-c): a Satlfile build on the bootstrap node, a
# warm rebuild measured against it, then a push into a *joiner's* registry and
# a service pinned to that joiner running the pushed image. Every registry is
# loopback-only (images.sh), so the push crosses a two-hop ssh tunnel held by
# this host — see the scenario's own header. The tunnel ports are this host's
# and the build node's loopback, never the nodes' registries' own port.
BP_NAME=${SATL_TEST_BP_NAME:-satl-built}
BP_LOCAL=$BP_NAME:task6
BP_TAG=task6-pushed
BP_SVC=${SATL_TEST_BP_SERVICE:-bpushed}
BP_DIR=/tmp/satl-bp
BP_MARKER=satl-task6-build-ok
BP_BASE=${SATL_TEST_BP_BASE:-"127.0.0.1:$REG_PORT/$REG_NS/freebsd-runtime:15.1"}
BP_TUN_PORT=${SATL_BP_TUN_PORT:-15001}
BP_HOP_PORT=${SATL_BP_HOP_PORT:-15002}
# PIDs of the two ssh forwarders while they are up, so the EXIT trap can take
# them down even when the scenario fails underneath them.
BP_TUNNEL_PIDS=""

# stack_verbs (B3 non-regression): a two-service stack deployed, listed,
# inspected and removed through `satl stack` alone.
SV=${SATL_TEST_STACK:-svstack}
SV_DIR=/tmp/$SV
SV_REPLICAS=2

# jobs_and_prefs (M7d/M7e): the two job modes, and a spread placement
# preference over a node label. The label name is the suite's own, removed at
# both ends of the scenario.
JP_RJOB=${SATL_TEST_RJOB:-jobr}
JP_GJOB=${SATL_TEST_GJOB:-jobg}
JP_SPREAD=${SATL_TEST_SPREAD_SERVICE:-spreadsvc}
JP_ZONE=${SATL_TEST_ZONE_LABEL:-zone}
JP_REPLICAS=${SATL_TEST_SPREAD_REPLICAS:-4}

# hot_resize (M6g + N4): a memory-capped service resized live, then removed —
# and one deliberately orphaned rctl rule for the startup purge to reap.
# HR_ORPHAN is exactly the task-id shape (25 lowercase base36 characters,
# satl-core's Id validation): anything else the purge refuses to touch.
HR=${SATL_TEST_RESIZE_SERVICE:-resize}
HR_REPLICAS=2
HR_OLD_BYTES=$((64 * 1024 * 1024))
HR_NEW_BYTES=$((128 * 1024 * 1024))
HR_ORPHAN=deaddeaddeaddeaddeaddeadd

# What leader_kill scales to: the write that must commit through a follower.
# Half, so the scale-down is unambiguous whatever SATL_REPLICAS says.
SCALED=$((REPLICAS / 2))
# leader_kill writes twice, once from each survivor, with distinct values
# (REPLICAS - 1, then SCALED); below 3 replicas those collide.
[ "$REPLICAS" -ge 3 ] || die "SATL_REPLICAS=$REPLICAS is too small (3 is the minimum)"

POLL=${SATL_POLL:-3}
T_JOIN=${SATL_T_JOIN:-180}
T_CONVERGE=${SATL_T_CONVERGE:-300}
T_DOWN=${SATL_T_DOWN:-120}
T_ELECT=${SATL_T_ELECT:-120}
T_CLEAN=${SATL_T_CLEAN:-180}
# Things that are immediate when they work at all: a store read-back, a spread.
T_QUICK=${SATL_T_QUICK:-60}
# A published port coming back after its pf anchor was destroyed behind the
# daemon's back. Long on purpose: that repair is the *slow* level (satld
# re-asserts an unchanged ruleset once a minute, crates/satld/src/reconcile.rs),
# and shortening this would turn a deliberate design constant into a flake.
T_PUB_HEAL=${SATL_T_PUB_HEAL:-150}
# A rolling update of six replicas, one slot at a time, each watched for
# RU_MONITOR seconds after it starts: the pace is the point, so this is long by
# design rather than by accident.
T_UPDATE=${SATL_T_UPDATE:-480}
# How long "nothing changed" is watched before it counts as a fact (hold_for):
# no replacement for a global task the cluster gave up, no flap after a second
# label write, no fourth task once a restart budget is spent. Long enough to
# cover several of the orchestrator's own passes, since what is being asserted
# is that those passes decide nothing.
T_SETTLE=${SATL_T_SETTLE:-40}

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/satl-run.XXXXXX") || die "mktemp -d failed"

# Set while a scenario runs, so the exit trap can name it and print the one
# command that re-runs it.
CURRENT=""
PASSED=""
SUMMARY="$TMPD/summary"
: >"$SUMMARY"

on_exit() {
	_rc=$?
	# rolling_update leaves a load generator running in the background; it
	# writes into $TMPD, so it has to go before the directory does — including
	# when a scenario failed underneath it.
	if [ -n "${RU_LOAD_PID:-}" ]; then
		kill "$RU_LOAD_PID" 2>/dev/null || true
	fi
	# build_push_run's two-hop ssh tunnel, if the scenario failed while it was
	# up (it clears the variable itself on the success path).
	if [ -n "${BP_TUNNEL_PIDS:-}" ]; then
		# shellcheck disable=SC2086  # PID list must word-split
		kill $BP_TUNNEL_PIDS 2>/dev/null || true
	fi
	if [ "$_rc" -ne 0 ]; then
		hdr "summary"
		while read -r _line; do info "$_line"; done <"$SUMMARY"
		if [ -n "$CURRENT" ]; then
			info "FAIL     $CURRENT"
			log ""
			log "Scenario '$CURRENT' failed. Re-run just that one with:"
			log "    sh tests/cluster/run.sh $CURRENT"
		else
			log ""
			log "The run failed outside a scenario (readiness gate or setup)."
		fi
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

# ------------------------------------------------------------ table parsing --

# tcols <file> <header[,header...]> — print the named columns of every data row
# of a satl table, tab-separated.
#
# The CLI pads every column to its widest cell plus three spaces, so a cell can
# contain single spaces ("Running 4 minutes ago") and can be empty (a worker's
# MANAGER STATUS) without breaking field splitting: this reads by the byte
# offsets the header line fixes, not by whitespace. An unknown header is a
# harness bug and fails loudly rather than yielding an empty string.
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
			printf "run.sh: no column \"%s\" in table header: %s\n", w[k], $0 > "/dev/stderr"
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

# show <file> — echo captured command output, indented, with any join token
# redacted. `satl swarm init` prints the *worker* token in its success message,
# so no captured output may ever be echoed raw.
show() { sed 's/SATL-1-[A-Za-z0-9_-]*/SATL-1-<redacted>/g; s/^/    /' "$1"; }

# ------------------------------------------------- cluster state, as observed --

# state_fetch <node> — capture `satl node ls`, `satl service ls` and
# `satl service ps <service>` from one node in a single ssh round trip.
# Returns non-zero when that node cannot answer, which is what makes it usable
# straight inside a poll: a manager that is down simply is not converged yet.
state_fetch() {
	: >"$TMPD/nodes"
	: >"$TMPD/svc"
	: >"$TMPD/tasks"
	node_ssh "$1" "satl node ls || exit 1
echo '@@@svc'
satl service ls || exit 1
echo '@@@task'
satl service ps $SERVICE 2>/dev/null || true" >"$TMPD/raw" 2>/dev/null || return 1
	awk -v base="$TMPD" '
		/^@@@svc$/  { part = 2; next }
		/^@@@task$/ { part = 3; next }
		{ print >> (part == 3 ? base "/tasks" : (part == 2 ? base "/svc" : base "/nodes")) }
	' "$TMPD/raw"
}

nodes_rows()      { tcols "$TMPD/nodes" ID | countl; }
nodes_ready()     { tcols "$TMPD/nodes" STATUS | awk '$0 == "Ready" { n++ } END { print n + 0 }'; }
nodes_leader()    { tcols "$TMPD/nodes" 'MANAGER STATUS' | awk '$0 == "Leader" { n++ } END { print n + 0 }'; }
nodes_reachable() { tcols "$TMPD/nodes" 'MANAGER STATUS' | awk '$0 == "Reachable" { n++ } END { print n + 0 }'; }
leader_host()     { tcols "$TMPD/nodes" 'HOSTNAME,MANAGER STATUS' | awk -F'\t' '$2 == "Leader" { print $1 }'; }
reachable_hosts() { tcols "$TMPD/nodes" 'HOSTNAME,MANAGER STATUS' | awk -F'\t' '$2 == "Reachable" { print $1 }'; }
host_status()     { tcols "$TMPD/nodes" 'HOSTNAME,STATUS' | awk -F'\t' -v h="$1" '$1 == h { print $2 }'; }
table_hosts()     { tcols "$TMPD/nodes" HOSTNAME; }

svc_replicas() { tcols "$TMPD/svc" 'NAME,REPLICAS' | awk -F'\t' -v s="$SERVICE" '$1 == s { print $2 }'; }
svc_running()  { svc_replicas | awk -F/ '{ print $1 + 0 }'; }
svc_desired()  { svc_replicas | awk -F/ '{ print $2 + 0 }'; }

# The *live* tasks: desired Running and observed Running.
#
# Both halves matter. A task on a node that stopped answering keeps its last
# reported CURRENT STATE — Running — for as long as the node is away (nothing
# can report otherwise; the orphan timer is 24h), while the manager moves its
# DESIRED STATE to Shutdown and schedules a replacement. Counting observed
# Running alone therefore says "8 tasks running" for a 6-replica service with
# one node down, which is not what the DoD means by six running replicas.
live_tasks() {
	tcols "$TMPD/tasks" 'NODE,DESIRED STATE,CURRENT STATE' |
	    awk -F'\t' '$2 == "Running" && $3 ~ /^Running/ { print $1 }'
}
live_total()   { live_tasks | countl; }
live_on_host() { live_tasks | awk -v h="$1" '$0 == h { n++ } END { print n + 0 }'; }
# Live tasks per node, counts only, ascending: "2 2 2" is a 2/2/2 spread.
live_spread() {
	live_tasks | awk '{ c[$0]++ } END { for (k in c) print c[k] }' |
	    sort -n | tr '\n' ' ' | sed 's/ *$//'
}
# Task rows a healthy run must never produce (the layer-application race in
# db38347 showed up here as spurious Rejected tasks).
bad_tasks() {
	tcols "$TMPD/tasks" 'NAME,NODE,CURRENT STATE,ERROR' |
	    awk -F'\t' '$3 ~ /^(Rejected|Failed)/ { print "    " $1 "  " $2 "  " $3 "  " $4 }'
}

# --------------------------------------------------- host ground truth (ssh) --

# node_jails <node> — one line per SatL jail: "<jid> <name> <processes>".
# The jail name is the task ID; the path is under the state directory. A jail
# with 0 processes is a container that has been stopped but not yet reaped.
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

# Jails that still hold at least one process, cluster-wide: the honest count of
# containers actually running, independent of what the managers believe.
cluster_live_jails() {
	_total=0
	for _clj in $(cluster_nodes); do
		_n=$(node_jails "$_clj" | awk '$3 > 0' | countl)
		_total=$((_total + _n))
	done
	echo "$_total"
}

# node_audit <node> — "jails=<n> epairs=<n> datasets=<n> mounts=<n> rdr=<n>", the
# leftover audit.
#
# `satl0` is excluded from the epair count on purpose: it is the node's bridge
# (description satl:network:*), not a per-task interface, and it outlives any
# single container.
#
# `mounts` counts **orphaned** container mounts, not container mounts: a
# container that still exists as a record (stopped, not removed) legitimately
# holds its devfs, its fdescfs and its tmpfs /tmp, and counting those would make
# every audit fail for a working node. A mount under
# `<state_dir>/containers/<id>/…` with no `<zfs_root>/containers/<id>` dataset
# belongs to a task that is gone from everything except the mount table.
#
# `mount -p`, never plain `mount`: these mounts are MNT_IGNORE and mount(8) hides
# those without -v. That is exactly why 54, 54 and 56 of them accumulated on
# these three nodes while this audit kept reporting them clean — the audit was
# looking at jails, epairs and datasets, and the leak was in the one place none
# of the standard tools would show it.
node_audit() {
	node_root_sh "$1" "$STATE_DIR" "$ZFS_ROOT" <<'REMOTE' 2>/dev/null
state_dir=$1
zfs_root=$2
jails=$(jls -N jid path 2>/dev/null |
    awk -v d="$state_dir/" '$2 ~ "^" d { n++ } END { print n + 0 }')
epairs=$(ifconfig -a 2>/dev/null |
    awk '/^[a-z]/ { n = $1; sub(/:$/, "", n) }
         /^[[:space:]]*description: satl:/ {
             # Long-lived cluster objects are not per-service leftovers: the
             # node-local bridge (satl:network:*) and, since M6d, the ingress
             # segment (satl:overlay:ingress, satl:vxlan:ingress), created
             # lazily and kept after its publishers go away.
             if ($2 !~ /^satl:network:/ && $2 !~ /^satl:overlay:ingress$/ && $2 !~ /^satl:vxlan:ingress$/) c++
         }
         END { print c + 0 }')
datasets=$(zfs list -H -o name -r -d 1 "$zfs_root/containers" 2>/dev/null |
    awk -v r="$zfs_root/containers/" 'index($0, r) == 1 { n++ } END { print n + 0 }')
live=$(zfs list -H -o name -r -d 1 "$zfs_root/containers" 2>/dev/null |
    awk -v r="$zfs_root/containers/" 'index($0, r) == 1 { print substr($0, length(r) + 1) }')
mounts=$(mount -p |
    awk -F'[\t ]+' -v d="$state_dir/containers/" '
        index($2, d) == 1 {
                rest = substr($2, length(d) + 1)
                slash = index(rest, "/")
                if (slash > 1) print substr(rest, 1, slash - 1)
        }' |
    while read -r id; do
	printf '%s\n' "$live" | grep -qx "$id" || echo "$id"
    done | wc -l | tr -d ' ')
# Redirects left in the satl/rdr anchor. stderr is dropped on purpose: an
# anchor that was never loaded prints `DIOCGETRULES: Invalid argument` and
# still exits 0, so "no anchor" and "empty anchor" read the same -- which is
# what absence means here.
#
# Safe to demand zero alongside jails=0: with no container anywhere on the
# node, no redirect can legitimately point at one. Without this the audit was
# blind to pf entirely, so `leftovers_gone` and `cleanup` were green with dead
# redirects on every node -- and a missing satl/rdr anchor was only ever
# noticed by the one scenario that thought to look.
rdr=$(pfctl -a satl/rdr -s nat 2>/dev/null | grep -c '^rdr' || true)
printf 'jails=%s epairs=%s datasets=%s mounts=%s rdr=%s\n' \
    "$jails" "$epairs" "$datasets" "$mounts" "$rdr"
REMOTE
}

# node_satld <node> <verb> — stop / start / kill9 the daemon.
#
# `stop` is a plain SIGTERM through rc.d: satld's shutdown deliberately leaves
# running jails alone (crates/satld/src/main.rs), which is precisely what makes
# the node_kill scenario meaningful — the containers stay behind as strays that
# the returning agent has to reap.
node_satld() {
	node_root_sh "$1" "$2" <<'REMOTE'
verb=$1
case $verb in
stop)
	service satld stop >/dev/null 2>&1 || true
	;;
kill9)
	pid=$(cat /var/run/satld.pid 2>/dev/null || true)
	if [ -n "$pid" ]; then kill -9 "$pid" 2>/dev/null || true; fi
	;;
start)
	service satld start >/dev/null
	;;
*)
	echo "node_satld: unknown verb $verb"
	exit 1
	;;
esac

# Bounded wait for the daemon to have actually gone or actually answered:
# rc.d returns before either is true, and a scenario must never proceed on a
# half-dead daemon.
i=0
while [ "$i" -lt 30 ]; do
	if [ "$verb" = start ]; then
		satl version >/dev/null 2>&1 && break
	else
		pgrep -qx satld || break
	fi
	sleep 1
	i=$((i + 1))
done
if [ "$verb" = start ]; then
	satl version >/dev/null 2>&1 || { echo "satld does not answer after start"; exit 1; }
else
	if pgrep -qx satld; then echo "satld is still running after $verb"; exit 1; fi
fi
REMOTE
}

# node_satld_log <node> <lines> — the tail of the daemon's tracing.
#
# openraft's per-append replication warnings are dropped: while a peer is down
# they arrive twice a second and bury everything satld itself says, which is the
# part that explains a failure. `sudo tail /var/log/messages | grep -a satld` on
# the node still shows them, and the summary points there.
#
# `grep -a`, and it is not optional: one non-ASCII byte anywhere in
# /var/log/messages makes grep call the whole file binary and print nothing at
# all, so a failure dump reads as a silent daemon (CLAUDE.md). That is exactly
# what happened once here -- a rolling_update timeout whose "last 20 satld log
# lines" section was empty on all three nodes while the log was full.
node_satld_log() {
	node_root_sh "$1" "$2" <<'REMOTE' 2>/dev/null || true
n=$1
grep -a satld /var/log/messages 2>/dev/null |
    grep -av -e 'openraft::replication' -e 'replication_handler' |
    tail -n "$n"
REMOTE
}

# --------------------------------------------------------- hostname mapping --

# `satl node ls` and `satl service ps` name a node by the hostname its agent
# reported, which is the real hostname and deliberately not the satld.toml
# node_name label (fix 39c86c4). Assertions are written in inventory names, so
# the two have to be tied together once, from the nodes themselves.
HOSTMAP="$TMPD/hostmap"

build_hostmap() {
	: >"$HOSTMAP"
	for _bh in $(cluster_nodes); do
		_hn=$(node_ssh "$_bh" hostname 2>/dev/null) ||
		    die "cannot read the hostname of $_bh over ssh"
		[ -n "$_hn" ] || die "$_bh reports an empty hostname"
		printf '%s %s\n' "$_hn" "$_bh" >>"$HOSTMAP"
	done
	_dup=$(awk '{ print $1 }' "$HOSTMAP" | sort | uniq -d)
	[ -z "$_dup" ] ||
	    die "nodes share a hostname ($_dup): no assertion could name one of them"
}

host_of()      { awk -v n="$1" '$2 == n { print $1 }' "$HOSTMAP"; }
node_of_host() { awk -v h="$1" '$1 == h { print $2 }' "$HOSTMAP"; }

# ------------------------------------------------------- waiting and failing --

# fail <message> — how a scenario ends badly: says what was expected, dumps the
# cluster as it actually is, and leaves. The EXIT trap names the scenario and
# prints the command that re-runs just it, so failing is a one-liner
# everywhere: `fail "..."`, never `fail "..." ; return 1`.
fail() {
	set +e
	printf '\n  FAIL: %s\n' "$*" >&2
	dump_state
	exit 1
}

# bail <message...> — a precondition the harness cannot fix and that no cluster
# dump would explain (a missing swarm, an inventory that contradicts itself).
bail() {
	set +e
	printf '\n  FAIL: %s\n' "$1" >&2
	shift
	log ""
	for _bl in "$@"; do log "  $_bl"; done
	exit 1
}

dump_state() {
	log ""
	log "  --- cluster state at the moment of failure"
	_shown=""
	for _d in $(cluster_nodes); do
		if node_ssh "$_d" "satl node ls" >"$TMPD/dump" 2>&1; then
			log "  from $_d: satl node ls"
			show "$TMPD/dump"
			log "  from $_d: satl service ps $SERVICE"
			node_ssh "$_d" "satl service ps $SERVICE" 2>&1 | sed 's/^/    /'
			_shown=$_d
			break
		fi
	done
	[ -n "$_shown" ] || log "    no node could answer satl node ls"
	log ""
	log "  --- jails, epairs and container datasets per node"
	for _d in $(cluster_nodes); do
		printf '    %-8s %s\n' "$_d" "$(node_audit "$_d" || echo unreachable)"
		node_jails "$_d" | sed "s/^/      jail /"
	done
	log ""
	log "  --- last 20 satld log lines per node (/var/log/messages)"
	for _d in $(cluster_nodes); do
		log "    $_d:"
		node_satld_log "$_d" 20 | sed 's/^/      /'
	done
}

# wait_until <seconds> <description> <shell test> — bounded poll, no sleeps
# anywhere else in this file. The test is re-evaluated every $POLL seconds; it
# is expected to refetch state itself, so a manager that is briefly unreachable
# reads as "not converged yet" rather than as an error.
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

# ------------------------------------------------------- shared preconditions --

# ensure_daemons — start satld wherever it is not answering.
#
# The scenarios below stop and kill daemons; one that fails in between leaves a
# node stopped. The next run must repair that rather than fail the readiness
# gate or spend T_JOIN waiting for a node nobody is going to start — a botched
# run needs no manual recovery. Deliberately lenient: a node that cannot be
# reached or whose daemon will not start is reported by the gate and by the
# scenario assertions, each of which says more about it than this could.
ensure_daemons() {
	for _ed in $(cluster_nodes); do
		node_ssh "$_ed" true >/dev/null 2>&1 || continue
		if ! node_ssh "$_ed" "satl version" >/dev/null 2>&1; then
			info "satld is not answering on $_ed — starting it"
			node_satld "$_ed" start >/dev/null 2>&1 ||
			    warn "satld will not start on $_ed — see /var/log/messages there"
		fi
	done
}

# require_swarm — a scenario other than init_and_join needs a formed cluster.
require_swarm() {
	ensure_daemons
	_want=$(cluster_nodes | countl)
	for _rs in $(cluster_nodes); do
		if state_fetch "$_rs" && [ "$(nodes_rows)" = "$_want" ]; then
			CTL=$_rs
			return 0
		fi
	done
	bail "no formed swarm of $_want nodes — no node lists them all" \
	    "Form one first:  sh tests/cluster/run.sh init_and_join"
}

# live_manager [exclude] — a node that answers, other than the excluded one.
live_manager() {
	for _lm in $(cluster_nodes); do
		[ "$_lm" = "${1:-}" ] && continue
		if state_fetch "$_lm"; then
			echo "$_lm"
			return 0
		fi
	done
	return 1
}

service_present() { [ -n "$(svc_replicas)" ]; }

# service_rm — remove $SERVICE and wait for every node to be clean again.
#
# The full leftover audit, not just "no process left": a task driven to Shutdown
# keeps its jail, its epair and its container dataset (the task record still
# exists, with zero processes in it), and only removing the service moves those
# tasks to Remove and frees them. Waiting for the audit here is what makes every
# scenario boundary a clean one.
service_rm() {
	node_ssh "$CTL" "satl service rm $SERVICE" >/dev/null 2>&1 || true
	wait_until "$T_CLEAN" "$SERVICE removed, no jail/epair/dataset/mount left anywhere" \
	    'state_fetch "$CTL" && [ -z "$(svc_replicas)" ] && leftovers_gone'
}

# ensure_service — the precondition scenarios 3 and 4 share: $SERVICE exists,
# converged at $REPLICAS/$REPLICAS, spread evenly over all three nodes. Kept
# when it is already in that shape (so the suite does not rebuild it between
# scenarios), rebuilt when it is not (so node_kill's 3/3/0 leftover cannot
# quietly turn leader_kill into a test of an empty node).
ensure_service() {
	wait_until "$T_JOIN" "all nodes Ready before touching $SERVICE" \
	    'state_fetch "$CTL" && [ "$(nodes_ready)" = "$(cluster_nodes | countl)" ]'
	_even=$(even_spread "$REPLICAS")
	if service_present && [ "$(svc_replicas)" = "$REPLICAS/$REPLICAS" ] &&
	    [ "$(live_spread)" = "$_even" ]; then
		info "$SERVICE already at $REPLICAS/$REPLICAS spread $_even — reused"
		return 0
	fi
	if service_present; then service_rm; fi
	create_service
}

create_service() {
	info "satl service create --name $SERVICE --replicas $REPLICAS $IMAGE"
	node_ssh "$CTL" "satl service create --name $SERVICE --replicas $REPLICAS $IMAGE" \
	    >"$TMPD/create" 2>&1 || {
		show "$TMPD/create"
		fail "satl service create failed on $CTL"
	}
	wait_until "$T_CONVERGE" "$SERVICE reaches $REPLICAS/$REPLICAS" \
	    'state_fetch "$CTL" && [ "$(svc_replicas)" = "$REPLICAS/$REPLICAS" ]'
}

# even_spread <replicas> — the ascending per-node counts a perfect spread of
# $1 replicas over the inventory's nodes produces: 6 over 3 nodes is "2 2 2".
even_spread() { spread_over "$1" "$(cluster_nodes | countl)"; }

# spread_over <replicas> <nodes> — the same over a given number of nodes, which
# is what a drained or lost node leaves: 6 over 2 is "3 3". The M4 scenarios
# assert the spread *after* a node stops taking tasks, and "one node fewer" is
# not something even_spread can express.
spread_over() {
	awk -v r="$1" -v n="$2" 'BEGIN {
		base = int(r / n)
		extra = r % n
		for (i = 1; i <= n; i++) printf "%d%s", base + (i > n - extra ? 1 : 0), (i < n ? " " : "\n")
	}'
}

# ===========================================================================
# Scenario 1 — init_and_join
#
# M2 DoD #1. From a wiped cluster: `satl swarm init` on the inventory's
# bootstrap node, then `satl swarm join` with the manager token from the other
# two, all over the 10.2.0.0/16 underlay.
#
# On the advertise address, which is where this differs from what a docker
# operator would type: `satl swarm init --advertise-addr X` is *always* refused
# by satld ("this node is already initialized and advertises …"), because first
# boot is the init (architecture §1.2) and rebinding the internal listener is a
# restart, not a request. The address therefore has to be pinned in satld.toml,
# which deploy.sh does for every node — otherwise satld would advertise the
# default-route interface, the *public* NIC on these VMs. So the scenario runs
# `satl swarm init` bare and asserts the thing `--advertise-addr` was meant to
# guarantee: every node advertises its own 10.2.0.0/16 address from
# inventory.toml, port included. `satl swarm join --advertise-addr` on the
# joiners is accepted and is passed, exactly as an operator would.
#
# Asserts, and keeps asserting until it holds on *every* node (each manager
# has to converge on the same membership, not just the one that was asked):
#   - three nodes listed, all Ready;
#   - exactly one Leader and exactly two Reachable — a three-manager raft;
#   - each node's Manager Status address is its inventory private_ip:2377;
#   - every node's HOSTNAME cell is that node's real hostname, and no cell
#     shows the satld.toml node_name label. That column used to show the
#     config label (fixed in 39c86c4), which made every other node-named
#     assertion in this file lie convincingly.
# ===========================================================================
scenario_init_and_join() {
	BOOT=$(bootstrap_node)
	JOINERS=$(nodes_with_role joiner)
	[ -n "$JOINERS" ] || fail "inventory has no node with role = \"joiner\""

	info "wiping cluster state everywhere (tests/cluster/reset.sh)"
	if ! sh "$CLUSTER_DIR/reset.sh" >"$TMPD/reset" 2>&1; then
		show "$TMPD/reset"
		fail "reset.sh did not leave every node clean"
	fi
	info "reset: $(awk '/RESET_DONE/ { n++ } END { print n + 0 }' "$TMPD/reset") node(s) wiped, satld restarted"

	_baddr=$(node_field "$BOOT" private_ip)
	info "swarm init on $BOOT"
	if ! node_ssh "$BOOT" "satl swarm init" >"$TMPD/init" 2>&1; then
		show "$TMPD/init"
		fail "satl swarm init failed on $BOOT"
	fi
	grep -q 'is now a manager' "$TMPD/init" ||
	    fail "satl swarm init on $BOOT did not report the node as a manager"
	_got=$(node_manager_addr "$BOOT")
	[ "$_got" = "$_baddr:$MGR_PORT" ] ||
	    fail "$BOOT advertises '$_got', not its underlay address $_baddr:$MGR_PORT — check listen_addr/advertise_addr in satld.toml (deploy.sh writes them)"
	info "$BOOT is a one-node cluster advertising $_got"

	# The token is read into a variable and never printed, never logged, and
	# never passed as an argument: join_with_token feeds it to the remote
	# shell on stdin, so it does not appear in any process list either.
	_token=$(node_ssh "$BOOT" "satl swarm join-token -q manager" 2>/dev/null) ||
	    fail "could not read the manager join token from $BOOT"
	case $_token in
	"" | *[!A-Za-z0-9-]*)
		fail "the manager join token is not the expected shape (not printed here)"
		;;
	esac
	info "manager join token in hand (never printed; sent to joiners over ssh stdin)"

	for _j in $JOINERS; do
		_jaddr=$(node_field "$_j" private_ip)
		info "swarm join from $_j ($_jaddr:$MGR_PORT) to $BOOT ($_baddr:$MGR_PORT)"
		if ! join_with_token "$_j" "$_jaddr" "$_baddr" "$_token" >"$TMPD/join" 2>&1; then
			show "$TMPD/join"
			fail "satl swarm join failed on $_j"
		fi
	done
	_token=""
	unset _token

	wait_until "$T_JOIN" "3 Ready, 1 Leader, 2 Reachable — on every node" \
	    'membership_agreed'

	# The HOSTNAME regression guard, on the membership every node agreed on.
	for _n in $(cluster_nodes); do
		_hn=$(host_of "$_n")
		table_hosts | grep -qx "$_hn" ||
		    fail "node ls has no HOSTNAME row '$_hn' (the real hostname of $_n)"
		if [ "$_hn" != "$_n" ] && table_hosts | grep -qx "$_n"; then
			fail "node ls HOSTNAME shows the satld.toml node_name label '$_n' instead of a real hostname (regression of 39c86c4)"
		fi
	done
	info "HOSTNAME column: $(table_hosts | tr '\n' ' ')— real hostnames, no config labels"

	# Every manager on the underlay, port included — what --advertise-addr on
	# `swarm init` would have been asked to guarantee.
	for _n in $(cluster_nodes); do
		_want="$(node_field "$_n" private_ip):$MGR_PORT"
		_got=$(node_manager_addr "$_n")
		[ "$_got" = "$_want" ] ||
		    fail "$_n advertises '$_got', not its underlay address $_want"
	done
	info "all managers advertise their $UNDERLAY_IF address on port $MGR_PORT"
	info "leader: $(leader_host), reachable: $(reachable_hosts | tr '\n' ' ')"
}

# node_manager_addr <node> — the Manager Status address the node itself reports.
node_manager_addr() {
	node_ssh "$1" "satl node inspect self --pretty" 2>/dev/null |
	    awk '/^Manager Status:/ { m = 1; next } m && /^ Address:/ { print $2; exit }'
}

# membership_agreed — the same three-manager membership seen from every node.
membership_agreed() {
	_want=$(cluster_nodes | countl)
	for _ma in $(cluster_nodes); do
		state_fetch "$_ma" || return 1
		[ "$(nodes_rows)" = "$_want" ] || return 1
		[ "$(nodes_ready)" = "$_want" ] || return 1
		[ "$(nodes_leader)" = 1 ] || return 1
		[ "$(nodes_reachable)" = "$((_want - 1))" ] || return 1
	done
	return 0
}

# join_with_token <node> <self-ip> <peer-ip> <token> — the token travels in the
# script text on ssh's stdin, never in argv.
join_with_token() {
	_jw=$1
	{
		printf "token='%s'\n" "$4"
		cat <<'REMOTE'
self=$1
peer=$2
port=$3
satl swarm join --token "$token" --advertise-addr "$self:$port" "$peer:$port"
REMOTE
	} | node_sh "$_jw" "$2" "$3" "$MGR_PORT"
}

# ===========================================================================
# Scenario 2 — worker_join
#
# M4: the first mixed-role cluster this suite forms. node1 inits, node2 joins
# as a manager, node3 joins with the **worker** token — no raft, no store, no
# listener of its own (architecture §1.2). Asserts, in order:
#
#   - `node ls` from a manager shows the roles: 3 Ready, 1 Leader, 1 Reachable,
#     and node3 with an empty MANAGER STATUS; the join itself printed
#     "joined a swarm as a worker";
#   - the worker's REST surface splits exactly as Docker's does (api-compat
#     #79-#81): `service ls` / `node ls` / a container mutation answer moby's
#     errNoManager sentence, while `satl ps` serves the node's own containers;
#   - the worker runs tasks: $REPLICAS replicas spread over all three nodes
#     put at least one on node3 (pigeonhole at 3 replicas; asserted, not
#     assumed), and an overlay service pinned to node3 resolves a service
#     pinned to a manager *by name* from inside its jail and fetches the body
#     across the underlay — the M3 machinery running storeless;
#   - `satl node promote node3` applies **live**: Reachable with the same
#     daemon pid, and a write submitted through node3 commits;
#   - `satl node demote node3` applies live too: back to an empty MANAGER
#     STATUS and the Docker refusal, same pid, its containers untouched;
#   - a killed worker converges exactly like the M2 follower case: satld
#     stopped and jails left behind, Down on the managers, its tasks evicted
#     to the two survivors (quorum is intact — the worker never counted),
#     strays reaped when it returns — as a worker, restarted from its
#     persisted manager list;
#   - node3 is then promoted again, leaving the all-manager cluster every
#     other scenario expects.
# ===========================================================================

# host_mstatus <hostname> — the MANAGER STATUS cell of one node ls row (empty
# for a worker). Reads the tables state_fetch captured.
host_mstatus() {
	tcols "$TMPD/nodes" 'HOSTNAME,MANAGER STATUS' |
	    awk -F'\t' -v h="$1" '$1 == h { print $2 }'
}

# node_pid <node> — the daemon's pid, for the no-restart assertion. pgrep
# rather than the pid file: the file is root-owned and this must stay an
# unprivileged read.
node_pid() {
	node_ssh "$1" "pgrep -x satld 2>/dev/null" | head -1 | tr -d '[:space:]'
}

# wj_refused <node> <command...> — the command fails *and* says exactly what
# Docker says on a worker. Either half alone is not the behaviour: an exit
# code without the sentence could be any error, the sentence with exit 0
# would be a lie in a pipe.
wj_refused() {
	_wjr_node=$1
	shift
	if node_ssh "$_wjr_node" "$*" >"$TMPD/refusal" 2>&1; then
		show "$TMPD/refusal"
		fail "'$*' succeeded on the worker $_wjr_node; it must answer Docker's refusal"
	fi
	grep -qF "$WJ_REFUSAL" "$TMPD/refusal" || {
		show "$TMPD/refusal"
		fail "'$*' on $_wjr_node failed without moby's errNoManager sentence"
	}
}

# wj_task_jid <ctl> <node> <service> — like ovl_task_jid, but the task id is
# read from a manager: the node hosting the jail may be a worker, whose
# `service ps` is (correctly) refused.
wj_task_jid() {
	_wjt_task=$(node_ssh "$1" "satl service ps $3 --quiet --no-trunc 2>/dev/null" |
	    head -1 | tr -d '\r')
	[ -n "$_wjt_task" ] || return 0
	node_jails "$2" | awk -v t="$_wjt_task" '$2 == t && $3 > 0 { print $1 }'
}

# wj_ps_rows <node> — how many containers that node's own `satl ps` lists.
wj_ps_rows() {
	node_ssh "$1" "satl ps 2>/dev/null" >"$TMPD/wjps" || return 1
	tcols "$TMPD/wjps" 'CONTAINER ID' | countl
}

wj_rm_all() {
	for _s in "$WJ_A" "$WJ_B"; do
		node_ssh "$1" "satl service rm $_s >/dev/null 2>&1" || true
	done
	_wjr_i=0
	while [ "$_wjr_i" -lt 20 ]; do
		node_ssh "$1" "satl network rm $WJ_OVL >/dev/null 2>&1" && break
		node_ssh "$1" "satl network inspect $WJ_OVL >/dev/null 2>&1" || break
		sleep "$POLL"
		_wjr_i=$((_wjr_i + 1))
	done
}

scenario_worker_join() {
	BOOT=$(bootstrap_node)
	WJ_MGR=$(nodes_with_role joiner | sed -n 1p)
	WJ_WRK=$(nodes_with_role joiner | sed -n 2p)
	[ -n "$WJ_WRK" ] || fail "worker_join needs two joiner nodes in the inventory"
	CTL=$BOOT

	info "wiping cluster state everywhere (tests/cluster/reset.sh)"
	if ! sh "$CLUSTER_DIR/reset.sh" >"$TMPD/reset" 2>&1; then
		show "$TMPD/reset"
		fail "reset.sh did not leave every node clean"
	fi
	build_hostmap
	_baddr=$(node_field "$BOOT" private_ip)
	H1=$(host_of "$BOOT")
	H3=$(host_of "$WJ_WRK")

	info "swarm init on $BOOT"
	node_ssh "$BOOT" "satl swarm init" >"$TMPD/init" 2>&1 || {
		show "$TMPD/init"
		fail "satl swarm init failed on $BOOT"
	}
	_mtoken=$(node_ssh "$BOOT" "satl swarm join-token -q manager" 2>/dev/null) ||
	    fail "could not read the manager join token from $BOOT"
	_wtoken=$(node_ssh "$BOOT" "satl swarm join-token -q worker" 2>/dev/null) ||
	    fail "could not read the worker join token from $BOOT"
	info "both join tokens in hand (never printed; sent over ssh stdin)"

	info "swarm join from $WJ_MGR as a MANAGER"
	join_with_token "$WJ_MGR" "$(node_field "$WJ_MGR" private_ip)" "$_baddr" "$_mtoken" \
	    >"$TMPD/join" 2>&1 || {
		show "$TMPD/join"
		fail "manager join failed on $WJ_MGR"
	}
	info "swarm join from $WJ_WRK with the WORKER token"
	join_with_token "$WJ_WRK" "$(node_field "$WJ_WRK" private_ip)" "$_baddr" "$_wtoken" \
	    >"$TMPD/join" 2>&1 || {
		show "$TMPD/join"
		fail "worker join failed on $WJ_WRK"
	}
	grep -q "joined a swarm as a worker" "$TMPD/join" || {
		show "$TMPD/join"
		fail "the join on $WJ_WRK did not report the worker role"
	}
	_mtoken=""
	_wtoken=""

	# --- 1. node ls shows the roles ------------------------------------------
	wait_until "$T_JOIN" "3 Ready: 1 Leader, 1 Reachable, $WJ_WRK a worker" '
		state_fetch "$CTL" &&
		[ "$(nodes_rows)" = 3 ] && [ "$(nodes_ready)" = 3 ] &&
		[ "$(nodes_leader)" = 1 ] && [ "$(nodes_reachable)" = 1 ] &&
		[ -z "$(host_mstatus "$H3")" ]'
	info "roles as asked: leader $(leader_host), $H3 has no manager status"

	# --- 2. the worker's REST surface splits like Docker's -------------------
	wj_refused "$WJ_WRK" "satl service ls"
	wj_refused "$WJ_WRK" "satl node ls"
	wj_refused "$WJ_WRK" "satl network ls"
	info "service ls / node ls / network ls on $WJ_WRK answer moby's errNoManager sentence"

	# --- 3. the worker runs tasks --------------------------------------------
	ensure_service
	wait_until "$T_QUICK" "$H3 runs at least one replica of $SERVICE" \
	    'state_fetch "$CTL" && [ "$(live_on_host "$H3")" -ge 1 ]'
	info "spread over the mixed cluster: $(live_spread) ($H3 included)"

	# Local reads work on the worker while cluster reads are refused: its own
	# `satl ps` lists exactly the containers the managers place on it.
	WJ_EXPECT=$(live_on_host "$H3")
	wait_until "$T_QUICK" "satl ps on $WJ_WRK lists its $WJ_EXPECT container(s)" \
	    '[ "$(wj_ps_rows "$WJ_WRK")" = "$WJ_EXPECT" ]'
	_wjc=$(tcols "$TMPD/wjps" 'CONTAINER ID' | head -1)
	wj_refused "$WJ_WRK" "satl stop $_wjc"
	info "satl ps serves the worker's own containers; satl stop is refused (a store write)"

	# --- 4. overlay + DNS on the worker (the M3 machinery, storeless) --------
	wj_rm_all "$CTL"
	node_ssh "$CTL" "satl network create -d overlay $WJ_OVL" >/dev/null ||
	    fail "satl network create -d overlay $WJ_OVL failed on $CTL"
	node_ssh "$CTL" "satl service create --name $WJ_A --replicas 1 \
	    --network $WJ_OVL --constraint node.hostname==$H1 $IMAGE" >/dev/null ||
	    fail "satl service create $WJ_A failed"
	node_ssh "$CTL" "satl service create --name $WJ_B --replicas 1 \
	    --network $WJ_OVL --constraint node.hostname==$H3 $IMAGE" >/dev/null ||
	    fail "satl service create $WJ_B failed"
	wait_until "$T_CONVERGE" "$WJ_A and $WJ_B each reach 1/1" '
		node_ssh "$CTL" "satl service ls 2>/dev/null" >"$TMPD/wjsvc" || return 1
		_r=$(tcols "$TMPD/wjsvc" "NAME,REPLICAS" |
		    awk -F"\t" -v a="$WJ_A" -v b="$WJ_B" \
		        "(\$1 == a || \$1 == b) && \$2 == \"1/1\"" | countl)
		[ "$_r" = 2 ]'
	WJ_JID=$(wj_task_jid "$CTL" "$WJ_WRK" "$WJ_B")
	[ -n "$WJ_JID" ] ||
	    fail "$WJ_B has no running jail on $WJ_WRK ($H3) — the constraint did not hold"
	ovl_wait_fetch "$WJ_WRK" "$WJ_JID" "$WJ_A"
	info "the worker's task resolved $WJ_A by name and fetched the body across the underlay"

	scenario_worker_join_roles
}

# The promotion / demotion / kill / restore half of worker_join. A separate
# function only for readability; it inherits every variable the first half set
# ($CTL, $WJ_WRK, $H3, ...).
scenario_worker_join_roles() {
	# --- 5. promotion applies live -------------------------------------------
	WJ_PID=$(node_pid "$WJ_WRK")
	[ -n "$WJ_PID" ] || fail "cannot read satld's pid on $WJ_WRK"
	info "satl node promote $H3 (satld on $WJ_WRK is pid $WJ_PID)"
	node_ssh "$CTL" "satl node promote $H3" >"$TMPD/promote" 2>&1 || {
		show "$TMPD/promote"
		fail "satl node promote $H3 failed on $CTL"
	}
	wait_until "$T_JOIN" "$H3 Reachable: a raft voter, live, no restart" '
		state_fetch "$CTL" &&
		[ "$(host_mstatus "$H3")" = "Reachable" ] && [ "$(host_status "$H3")" = Ready ]'
	_pid_now=$(node_pid "$WJ_WRK")
	[ "$_pid_now" = "$WJ_PID" ] ||
	    fail "satld's pid on $WJ_WRK changed ($WJ_PID -> $_pid_now): the promotion restarted the daemon"
	info "$H3 is Reachable with the same daemon pid $WJ_PID: the promotion applied live"

	# The promoted node serves the manager surface, and a write submitted
	# through it commits (it is a follower, so this also exercises
	# follower -> leader forwarding).
	node_ssh "$WJ_WRK" "satl node ls" >/dev/null 2>&1 ||
	    fail "satl node ls on the promoted $WJ_WRK still fails"
	WJ_STEP=$((REPLICAS - 1))
	info "write through the promoted node: satl service scale $SERVICE=$WJ_STEP"
	node_ssh "$WJ_WRK" "satl service scale $SERVICE=$WJ_STEP" >"$TMPD/wjscale" 2>&1 || {
		show "$TMPD/wjscale"
		fail "the promoted $WJ_WRK refused a write"
	}
	wait_until "$T_QUICK" "the write through $WJ_WRK committed (desired $WJ_STEP)" \
	    'state_fetch "$CTL" && [ "$(svc_desired)" = "$WJ_STEP" ]'
	# The leader having committed it is not enough to write through $WJ_WRK
	# again. `satl service scale` is a read-modify-write, and reads are
	# answered from the node's **own** applied store (architecture section 7),
	# so scaling through a node that has not applied the previous scale yet
	# submits the stale object version and the leader refuses it:
	#
	#   store transaction rejected ... sequence conflict on service <id>:
	#   store has version 65, caller wrote from version 14
	#
	# Measured: the scale below failed exactly that way in a full-suite run
	# and the same scenario passed alone, which is the signature of a
	# precondition weaker than what it guards -- the same mistake this suite
	# already removed from `node_kill`, `leader_kill` and `demote_leader`,
	# where the observable being waited on was not the one the next step
	# depends on. Wait for the writer's own reading, not the leader's.
	wait_until "$T_QUICK" "$WJ_WRK has applied it too (its own read says $WJ_STEP)" \
	    'state_fetch "$WJ_WRK" && [ "$(svc_desired)" = "$WJ_STEP" ]'
	node_ssh "$WJ_WRK" "satl service scale $SERVICE=$REPLICAS" >"$TMPD/wjscale2" 2>&1 ||
	    {
		show "$TMPD/wjscale2"
		fail "scaling $SERVICE back through $WJ_WRK failed"
	}
	# Converged, not merely desired: the count below must not race a task that
	# is still starting (measured: the extra replica landed on $WJ_WRK and
	# started *during* the demote steps, reading as "3 after, 2 before").
	wait_until "$T_CONVERGE" "and back to $REPLICAS, all running" \
	    'state_fetch "$CTL" && [ "$(svc_replicas)" = "$REPLICAS/$REPLICAS" ]'

	# --- 6. demotion applies live too ----------------------------------------
	_jails_before=$(node_jails "$WJ_WRK" | awk '$3 > 0' | countl)
	info "satl node demote $H3"
	node_ssh "$CTL" "satl node demote $H3" >"$TMPD/demote" 2>&1 || {
		show "$TMPD/demote"
		fail "satl node demote $H3 failed on $CTL"
	}
	wait_until "$T_JOIN" "$H3 back to a Ready worker (no manager status)" '
		state_fetch "$CTL" &&
		[ -z "$(host_mstatus "$H3")" ] && [ "$(host_status "$H3")" = Ready ]'
	wait_until "$T_QUICK" "the demoted $H3 answers Docker's refusal again" '
		! node_ssh "$WJ_WRK" "satl service ls" >"$TMPD/refusal" 2>&1 &&
		grep -qF "$WJ_REFUSAL" "$TMPD/refusal"'
	_pid_now=$(node_pid "$WJ_WRK")
	[ "$_pid_now" = "$WJ_PID" ] ||
	    fail "satld's pid on $WJ_WRK changed ($WJ_PID -> $_pid_now): the demotion restarted the daemon"
	_jails_after=$(node_jails "$WJ_WRK" | awk '$3 > 0' | countl)
	[ "$_jails_after" = "$_jails_before" ] ||
	    fail "$WJ_WRK ran $_jails_before container(s) before the demotion and $_jails_after after: a live role change must not disturb running tasks"
	info "$H3 demoted live: same pid, refusal back, $_jails_after container(s) untouched"

	# --- 7. a killed worker converges like the M2 follower case --------------
	# The overlay pair goes first: $WJ_B is pinned to the worker by constraint,
	# so after the kill it could never be rescheduled and would muddy "all
	# tasks evicted" into "all tasks that could be". state_fetch feeds
	# jails_match_tasks.
	wj_rm_all "$CTL"
	wait_until "$T_CLEAN" "the overlay pair is gone and jails match tasks again" \
	    'state_fetch "$CTL" && jails_match_tasks'

	VICTIM=$WJ_WRK
	VHOST=$H3
	node_jails "$VICTIM" | awk '$3 > 0 { print $2 }' >"$TMPD/strays"
	NSTRAY=$(countl <"$TMPD/strays")
	[ "$NSTRAY" -ge 1 ] || fail "$VICTIM runs no container: there would be nothing to strand"
	info "stopping satld on the worker $VICTIM ($NSTRAY container(s) left running)"
	node_satld "$VICTIM" stop || fail "could not stop satld on $VICTIM"

	wait_until "$T_DOWN" "$VICTIM reported Down (quorum intact: a worker counts for none)" \
	    'state_fetch "$CTL" && [ "$(host_status "$VHOST")" = Down ]'
	_still=$(node_jails "$VICTIM" | awk '$3 > 0' | countl)
	[ "$_still" = "$NSTRAY" ] ||
	    fail "$VICTIM has $_still live container(s), expected $NSTRAY strays"

	wait_until "$T_CONVERGE" "$REPLICAS tasks Running, none on $VHOST" \
	    'state_fetch "$CTL" && [ "$(live_total)" = "$REPLICAS" ] && [ "$(live_on_host "$VHOST")" = 0 ]'
	info "evicted to the two managers: $(live_spread)"

	info "restarting satld on $VICTIM (it must come back as a worker, from managers.json)"
	node_satld "$VICTIM" start || fail "satld did not come back on $VICTIM"
	wait_until "$T_JOIN" "$VICTIM back to Ready, still a worker" '
		state_fetch "$CTL" &&
		[ "$(host_status "$VHOST")" = Ready ] && [ -z "$(host_mstatus "$VHOST")" ]'
	wait_until "$T_CONVERGE" "$SERVICE at $REPLICAS/$REPLICAS with the strays reaped" \
	    'state_fetch "$CTL" && [ "$(svc_replicas)" = "$REPLICAS/$REPLICAS" ] &&
	     [ "$(strays_alive)" = 0 ] && [ "$(cluster_live_jails)" = "$REPLICAS" ] &&
	     jails_match_tasks'
	info "the returning worker reaped its $NSTRAY stray container(s)"

	# --- 8. restore the all-manager shape the rest of the suite expects ------
	info "satl node promote $H3 (restoring the all-manager cluster)"
	node_ssh "$CTL" "satl node promote $H3" >/dev/null 2>&1 ||
	    fail "the restoring promotion of $H3 failed"
	wait_until "$T_JOIN" "3 Ready, 1 Leader, 2 Reachable — on every node" \
	    'membership_agreed'
	info "cluster restored to three managers: leader $(leader_host)"
}

# ===========================================================================
# Scenario 3 — replicas_spread
#
# M2 DoD #2. `satl service create --replicas 6` of the seeded nginx image.
#
# Asserts:
#   - the service reaches 6/6;
#   - the running tasks are spread 2/2/2 — the scheduler's spread ranking, not
#     six tasks on the node that happened to be leader;
#   - no task is in a Rejected or Failed state, at any point in the service's
#     task history. A layer-application race (fixed in db38347) used to reject
#     a task on the node that pulled the image second, and the service still
#     reached 6/6 afterwards, so 6/6 alone did not catch it.
# ===========================================================================
scenario_replicas_spread() {
	require_swarm
	wait_until "$T_JOIN" "all nodes Ready" \
	    'state_fetch "$CTL" && [ "$(nodes_ready)" = "$(cluster_nodes | countl)" ]'
	if service_present; then service_rm; fi
	create_service

	_even=$(even_spread "$REPLICAS")
	wait_until "$T_QUICK" "running tasks spread $_even over $(cluster_nodes | countl) nodes" \
	    'state_fetch "$CTL" && [ "$(live_spread)" = "$(even_spread "$REPLICAS")" ]'

	_bad=$(bad_tasks)
	if [ -n "$_bad" ]; then
		log "  tasks in a rejected/failed state:"
		printf '%s\n' "$_bad"
		fail "$SERVICE has rejected/failed tasks — a clean create must produce none"
	fi
	info "no rejected or failed task in $SERVICE's history"

	# The managers' view against the hosts': six containers, two per node.
	for _n in $(cluster_nodes); do
		_live=$(node_jails "$_n" | awk '$3 > 0' | countl)
		info "$_n: $_live container jail(s) with live processes"
	done
	_total=$(cluster_live_jails)
	[ "$_total" = "$REPLICAS" ] ||
	    fail "$_total live container jails cluster-wide, expected $REPLICAS"
}

# ===========================================================================
# Scenario 4 — node_kill
#
# M2 DoD #3, plus the regression guard for 18285de.
#
# Stops satld on a non-leader node and deliberately leaves its jails running:
# satld's shutdown does not touch them (crates/satld/src/main.rs), so the two
# containers become strays that outlive their tasks. That is the interesting
# case — killing the containers as well would make the reaping assertion below
# vacuous.
#
# Asserts:
#   - the node is reported Down once its session TTL expires;
#   - while it is down, its containers really are still running (otherwise the
#     last assertion proves nothing);
#   - six tasks are Running again with none of them on the dead node — the
#     orchestrator evicted and replaced them (db38347);
#   - after the node is restarted it comes back Ready, the service is back to
#     exactly 6/6, none of the stray jails holds a process any more, and
#     cluster-wide exactly six containers run. Before 18285de a returning node
#     kept its strays alive and the service sat at 7/6 or 8/6 with no error
#     anywhere in the log.
# ===========================================================================
scenario_node_kill() {
	require_swarm
	ensure_service

	state_fetch "$CTL"
	# The victim is chosen by RAFT role. `reachable_hosts` reads the
	# MANAGER STATUS column, which is written at cluster formation and never
	# refreshed on a leadership change (see the note in leader_kill) — so
	# "Reachable" there can be the real leader, and this scenario, whose whole
	# premise is "a non-leader dies", would silently become a second and
	# worse-asserted leader_kill.
	VICTIM=$(a_follower)
	[ -n "$VICTIM" ] || fail "no manager other than the leader to kill"
	assert_not_leader "$VICTIM"
	VHOST=$(host_of "$VICTIM")
	CTL=$(live_manager "$VICTIM") || fail "no other node can serve reads"

	node_jails "$VICTIM" | awk '$3 > 0 { print $2 }' >"$TMPD/strays"
	NSTRAY=$(countl <"$TMPD/strays")
	[ "$NSTRAY" -ge 1 ] ||
	    fail "$VICTIM runs no container: there would be nothing to strand"
	info "victim $VICTIM ($VHOST), non-leader, running $NSTRAY container(s)"
	info "reads and assertions from $CTL for the rest of this scenario"

	info "stopping satld on $VICTIM (its jails are left running on purpose)"
	node_satld "$VICTIM" stop || fail "could not stop satld on $VICTIM"

	wait_until "$T_DOWN" "$VICTIM reported Down" \
	    'state_fetch "$CTL" && [ "$(host_status "$VHOST")" = Down ]'

	_still=$(node_jails "$VICTIM" | awk '$3 > 0' | countl)
	[ "$_still" = "$NSTRAY" ] ||
	    fail "$VICTIM has $_still live container(s), expected the $NSTRAY strays to survive satld's stop — the reaping assertion below would be vacuous"
	info "$NSTRAY stray container(s) still running on the dead $VICTIM, as intended"

	wait_until "$T_CONVERGE" "$REPLICAS tasks Running, none on $VICTIM" \
	    'state_fetch "$CTL" && [ "$(live_total)" = "$REPLICAS" ] && [ "$(live_on_host "$VHOST")" = 0 ]'
	info "spread after eviction: $(live_spread)"

	info "restarting satld on $VICTIM"
	node_satld "$VICTIM" start || fail "satld did not come back on $VICTIM"

	wait_until "$T_JOIN" "$VICTIM back to Ready" \
	    'state_fetch "$CTL" && [ "$(host_status "$VHOST")" = Ready ]'

	wait_until "$T_CONVERGE" "$SERVICE back to $REPLICAS/$REPLICAS with the strays reaped" \
	    'state_fetch "$CTL" && [ "$(svc_replicas)" = "$REPLICAS/$REPLICAS" ] &&
	     [ "$(strays_alive)" = 0 ] && [ "$(cluster_live_jails)" = "$REPLICAS" ] &&
	     jails_match_tasks'
	info "the $NSTRAY stray container(s) were stopped by the returning agent"
	info "one jail per live task on every node, $REPLICAS containers cluster-wide"
}

# strays_alive — how many of the jails recorded before the kill still hold a
# process. `satl` is expected to drive them to shutdown, which leaves the jail
# in place with nothing in it until the task is removed, so a name that has
# disappeared counts as reaped too.
strays_alive() {
	node_jails "$VICTIM" | awk '$3 > 0 { print $2 }' >"$TMPD/now"
	awk 'NR == FNR { was[$0] = 1; next } ($0 in was) { n++ } END { print n + 0 }' \
	    "$TMPD/strays" "$TMPD/now"
}

# jails_match_tasks — on every node, the number of jails holding a process
# equals the number of live tasks the store places on that node.
#
# The invariant a container outliving its task breaks, checked against host
# ground truth rather than against the daemon's own count: 18285de left a jail
# running with nothing driving it and nothing in the log to grep for. Only true
# at rest — a task that is still preparing has no jail yet — which is why it is
# always used inside a bounded poll. Reads the tasks table, so a state_fetch
# must have run first.
jails_match_tasks() {
	for _jm in $(cluster_nodes); do
		_jmj=$(node_jails "$_jm" | awk '$3 > 0' | countl)
		_jmt=$(live_on_host "$(host_of "$_jm")")
		[ "$_jmj" = "$_jmt" ] || return 1
	done
	return 0
}

# ===========================================================================
# Scenario 5 — leader_kill
#
# M2 DoD #4, upgraded in M4 to assert eviction. `kill -9` on the leader's
# satld, which is a manager running tasks too (architecture §1.2): losing one
# of three keeps quorum at two.
#
# The M4 upgrade: a killed leader now converges to *Down*, exactly like a
# killed follower, and its tasks are evicted. The new leader's dispatcher never
# held a session for the dead node, so at leadership gain it seeds a
# registration expectation for every non-Down, non-drained node in the store
# (SWK 13.2; crates/satl-dispatcher/src/liveness.rs). A node whose agent lives
# re-registers well inside the grace period (2 x session TTL = 30 s; measured
# re-registration is 2.9-7.5 s); one that never shows up expires through the
# ordinary TTL sweep into Down, and the orchestrator's InvalidNode trigger
# evicts and replaces its tasks. Until M4 this scenario could only assert "no
# longer Ready": the dead leader sat in Unknown forever and its replicas ran
# nowhere, indefinitely.
#
# One column is still not to be trusted: `satl node ls`'s MANAGER STATUS is
# written when the cluster forms and never refreshed on a leadership change
# (known M2 gap, README), so after the kill every node still calls the dead
# node Leader. The re-election is asserted through effects only a leader with
# quorum can produce — store writes — never through that column.
#
# Asserts:
#   - both survivors keep answering reads (the API stays up);
#   - the store marks the killed ex-leader Down, on every survivor's view — a
#     store write, therefore proof that a new leader was elected and holds
#     quorum, and the observable form of the expectation expiring;
#   - the dead node's tasks are evicted and rescheduled: the service returns
#     to $REPLICAS live tasks with none on the dead node, spread over the two
#     survivors — the same convergence node_kill asserts for a follower;
#   - each survivor accepts a `satl service scale` and the new desired count
#     reads back. Exactly one of the two survivors is the new leader, so one of
#     those two writes necessarily travelled follower -> leader through
#     Control.ProposeActions; requiring both to succeed exercises that path
#     without needing to know which node is which;
#   - the killed node rejoins Ready; the stray containers the kill left behind
#     are reaped by the returning agent (their tasks were evicted, so nothing
#     legitimately runs on it until the scheduler places something new); the
#     daemon's own count reads $SCALED/$SCALED, exactly $SCALED containers run
#     cluster-wide, and every node has one jail with processes per live task.
# ===========================================================================
scenario_leader_kill() {
	require_swarm
	ensure_service

	state_fetch "$CTL"
	# From the daemons' own logs, not from the MANAGER STATUS column this
	# scenario's own header documents as never refreshed. Reading the column
	# here was the sharpest version of the problem: run standalone after any
	# scenario that moved leadership, it killed a FOLLOWER and then waited out
	# T_ELECT for an election that was never going to happen.
	LEADER=$(the_leader)
	OLD_LEADER_HOST=$(host_of "$LEADER")
	CTL=$(live_manager "$LEADER") || fail "no survivor can serve reads"

	node_jails "$LEADER" | awk '$3 > 0 { print $2 }' >"$TMPD/strays"
	NSTRAY=$(countl <"$TMPD/strays")
	VICTIM=$LEADER
	[ "$NSTRAY" -ge 1 ] ||
	    fail "the leader $LEADER runs no container: killing it would strand nothing"
	info "leader $LEADER ($OLD_LEADER_HOST) running $NSTRAY container(s)"

	info "kill -9 on satld on the leader $LEADER"
	node_satld "$LEADER" kill9 || fail "could not kill satld on $LEADER"

	wait_until "$T_ELECT" "survivors serve reads and the store moved $LEADER off Ready" \
	    'survivors_serve_reads'
	info "the store now calls $OLD_LEADER_HOST '$(host_status "$OLD_LEADER_HOST")': a write committed after the kill, so a new leader holds quorum"

	# The seeded expectation expiring is a Down transition identical to a
	# follower's: bounded by election time + the 30 s grace, both well under
	# T_DOWN. Read from every survivor, because a Down only one manager
	# believes is a projection bug, not a convergence.
	wait_until "$T_DOWN" "$OLD_LEADER_HOST reported Down on every survivor" \
	    'ex_leader_down_everywhere'
	info "$OLD_LEADER_HOST is Down: the registration expectation expired (grep 'leadership gained with no session' and 'node marked down' in the new leader's log)"

	# Eviction, the debt this scenario existed to hide: the replicas the dead
	# node ran come back on the survivors, none remain on it, and the service
	# is at full strength again before any scale is asked of it.
	wait_until "$T_CONVERGE" "$REPLICAS tasks Running, none on $OLD_LEADER_HOST" \
	    'state_fetch "$CTL" && [ "$(live_total)" = "$REPLICAS" ] && [ "$(live_on_host "$OLD_LEADER_HOST")" = 0 ]'
	info "spread after eviction: $(live_spread) over the survivors"

	# One write from each survivor. One of them is the new leader and one is a
	# follower; requiring both to be accepted is what proves the forwarding
	# path, since no surface reports which is which (see the header above).
	_step=$((REPLICAS - 1))
	for _w in $(cluster_nodes); do
		[ "$_w" = "$LEADER" ] && continue
		info "write through $_w: satl service scale $SERVICE=$_step"
		if ! node_ssh "$_w" "satl service scale $SERVICE=$_step" >"$TMPD/scale" 2>&1; then
			show "$TMPD/scale"
			fail "$_w refused the write after the leader was killed — a manager that is not the leader must forward the mutation (Control.ProposeActions)"
		fi
		show "$TMPD/scale"
		WSTEP=$_step
		wait_until "$T_QUICK" "the write from $_w committed (desired $_step)" \
		    'state_fetch "$CTL" && [ "$(svc_desired)" = "$WSTEP" ]'
		_step=$SCALED
	done

	# While the killed node is away, `service ls` cannot read 3/3: the evicted
	# tasks on the dead node keep their last reported CURRENT STATE — Running —
	# because nothing is left there to report otherwise, and the daemon's
	# running count reads observed state. The live task set is what converges
	# now; the daemon's own count is asserted below, once the node is back and
	# its strays are gone.
	wait_until "$T_CONVERGE" "$SCALED tasks left Running" \
	    'state_fetch "$CTL" && [ "$(live_total)" = "$SCALED" ]'
	info "live tasks: $(live_total), spread $(live_spread)"

	info "restarting satld on the killed $LEADER"
	node_satld "$LEADER" start || fail "satld did not come back on $LEADER"

	wait_until "$T_JOIN" "$LEADER rejoins Ready" \
	    'state_fetch "$CTL" && [ "$(host_status "$OLD_LEADER_HOST")" = Ready ]'
	# Mirror node_kill's return leg: the strays must die. Their tasks were
	# evicted while the node was Down, so the returning agent's snapshot tells
	# it to shut every one of them down — a jail it keeps alive is a container
	# outliving its task. Then the usual ground truth: one jail with processes
	# per live task on every node, $SCALED containers cluster-wide, and the
	# daemon's own count finally reading $SCALED/$SCALED.
	wait_until "$T_CONVERGE" "$SCALED/$SCALED with the strays reaped, $SCALED containers cluster-wide" \
	    'state_fetch "$CTL" && [ "$(svc_replicas)" = "$SCALED/$SCALED" ] &&
	     [ "$(strays_alive)" = 0 ] && [ "$(cluster_live_jails)" = "$SCALED" ] &&
	     jails_match_tasks'
	info "the $NSTRAY stray container(s) were stopped by the returning agent"
	info "$LEADER runs $(node_jails "$LEADER" | awk '$3 > 0' | countl) container(s) now — one per live task placed on it"
}

# survivors_serve_reads — every node but $LEADER answers `satl node ls`, and all
# of them see the store having moved $LEADER out of Ready. Only the leader can
# write the store, so this is the observable form of "a new leader was elected".
survivors_serve_reads() {
	for _sr in $(cluster_nodes); do
		[ "$_sr" = "$LEADER" ] && continue
		state_fetch "$_sr" || return 1
		_st=$(host_status "$OLD_LEADER_HOST")
		[ -n "$_st" ] && [ "$_st" != Ready ] || return 1
	done
	return 0
}

# ex_leader_down_everywhere — every survivor's view of the store says the
# killed ex-leader is Down. The store is replicated, so one answer would do;
# asking all of them costs one poll and rules out a survivor serving a stale
# read.
ex_leader_down_everywhere() {
	for _ed in $(cluster_nodes); do
		[ "$_ed" = "$LEADER" ] && continue
		state_fetch "$_ed" || return 1
		[ "$(host_status "$OLD_LEADER_HOST")" = Down ] || return 1
	done
	return 0
}

# ===========================================================================
# Scenario 6 — overlay_dns
#
# The M3 DoD: two services on one overlay network, their tasks on different
# VMs, reaching each other by service name; cross-node traffic at the correct
# MTU.
#
# Why it is built the way it is:
#
#   - The two services are pinned to two named nodes with `node.hostname`
#     constraints. Letting the spread decide would make the interesting case
#     (traffic that actually crosses the underlay) a coin toss, and a run where
#     both tasks landed on one node would pass while proving nothing.
#   - Reachability is asserted with `fetch` against the *service name*, not
#     against an address. That single command exercises the whole chain the DoD
#     is about — the resolver answers, the FDB entry carries the frame, the ARP
#     entry lets the peer answer, and a real TCP conversation completes. An
#     address-only ping would pass with DNS entirely broken.
#   - It runs `fetch` in *both* directions. One direction can succeed on a
#     half-programmed overlay: the FDB and ARP tables are per node, so A->B
#     proves A's tables and B's return path, not B's tables.
#   - The MTU is proven by the DF boundary (1422 passes, 1423 does not) rather
#     than by reading `ifconfig`. A wrong MTU on the overlay does not fail
#     functionally — `vxlan_encap4()` clears DF, so oversized frames are
#     fragmented, not dropped (docs/vxlan.md). Reading the configured value
#     back only proves we wrote what we meant to write; the DF boundary proves
#     the packet the container can actually send.
#   - Teardown is asserted too. An overlay leaves a VTEP, a bridge and epairs
#     on every participating node, and CLAUDE.md's VNET gotcha is that these
#     leak when teardown is interrupted. A scenario that creates an overlay and
#     does not check it disappears would hide exactly that.
#
# Tools: the image is built on freebsd-runtime, whose /rescue carries static
# `fetch` and `ping`. There is no `drill` or `host` in it, which is why DNS is
# asserted through `fetch` rather than by inspecting a DNS answer directly.
# ===========================================================================

# ovl_task_jid <node> <service> — the jail id on <node> of <service>'s single
# task, or empty. The jail's name is the task id (node_jails), and
# `satl service ps` names the task; joining them avoids assuming an ordering.
ovl_task_jid() {
	_ojt_task=$(node_ssh "$1" "satl service ps $2 --quiet --no-trunc 2>/dev/null" |
	    head -1 | tr -d '\r')
	[ -n "$_ojt_task" ] || return 0
	node_jails "$1" | awk -v t="$_ojt_task" '$2 == t && $3 > 0 { print $1 }'
}

# ovl_addr <node> <service> — that task's overlay address, without the prefix,
# read from `satl network inspect` (api-compat 62: Containers is keyed by task
# id and carries IPv4Address). Read on <node> so a stale manager cannot answer.
ovl_addr() {
	_ova_task=$(node_ssh "$1" "satl service ps $2 --quiet --no-trunc 2>/dev/null" |
	    head -1 | tr -d '\r')
	[ -n "$_ova_task" ] || return 0
	node_ssh "$1" "satl network inspect $OVL 2>/dev/null" |
	    tr ',' '\n' | grep -A 4 "$_ova_task" | sed -n 's/.*"IPv4Address"[^"]*"\([^"/]*\).*/\1/p' |
	    head -1
}

# ovl_in_jail <node> <jid> <command...> — run a command inside a task's jail.
# /rescue first: an OCI image has no /usr/bin, and the base image's own
# binaries are dynamically linked against a userland the jail may not carry.
ovl_in_jail() {
	_oij_node=$1
	_oij_jid=$2
	shift 2
	node_root_sh "$_oij_node" "$_oij_jid" "$*" <<'REMOTE' 2>&1
jid=$1
cmd=$2
jexec "$jid" /bin/sh -c "PATH=/rescue:/bin:/sbin:/usr/bin:/usr/sbin; $cmd"
REMOTE
}

# ovl_wait_fetch <node> <jid> <service> — poll `fetch` against a service name
# from inside a jail until it returns the expected body, and fail with the last
# output if it never does. A plain wait_until would report only "timed out",
# and the distinction that matters is in that output: a DNS failure says
# "hostname nor servname provided", a data-plane failure says "Operation timed
# out", and a wrong MTU says nothing at all until the body is truncated.
ovl_wait_fetch() {
	_owf_node=$1
	_owf_jid=$2
	_owf_svc=$3
	_owf_t0=$(date +%s)
	printf '  %-58s' "wait: http://$_owf_svc/ answers in the jail on $_owf_node"
	while :; do
		# `|| true` is load-bearing under `set -e`: a variable assignment takes
		# the exit status of its command substitution, so a failing `fetch` --
		# which is the entire point of polling -- aborted the whole run on the
		# first attempt, before a single dot, and the "last output from the
		# jail" diagnostic below could never fire. Found by deliberately
		# breaking DNS scoping to check this helper reports it: it did not.
		_owf_out=$(ovl_in_jail "$_owf_node" "$_owf_jid" \
		    "fetch -q -T 5 -o - http://$_owf_svc/" || true)
		if printf %s "$_owf_out" | grep -q "$OVL_BODY"; then
			printf ' ok %ss\n' "$(($(date +%s) - _owf_t0))"
			return 0
		fi
		if [ "$(($(date +%s) - _owf_t0))" -ge "$T_QUICK" ]; then
			printf ' TIMEOUT %ss\n' "$T_QUICK"
			log "  last output from the jail:"
			printf '%s\n' "$_owf_out" | sed 's/^/    /'
			fail "$_owf_svc never answered by name from $_owf_node: \
DNS, the overlay data path, or both"
		fi
		printf '.'
		sleep "$POLL"
	done
}

# ovl_count <node> <command> <pattern> — how many lines of <command>'s output on
# <node> match <pattern>.
#
# `grep -c` is deliberately not used: it exits 1 when the count is zero, which
# turns every "nothing left" check into a shell trap (the count is printed *and*
# the caller's `|| echo 0` fallback fires, so the value is two lines). awk counts
# and always exits 0, so zero is a value rather than a failure.
# ovl_non_ingress_vxlans <node> — vxlan interfaces on the node, the ingress
# network's VTEP excluded. The ingress segment is a long-lived cluster object
# (M6d: created lazily on the first ingress publisher, kept after they go
# away), so a raw `ifconfig -g vxlan` count reads it as a leftover forever.
# The description, not the name, identifies it: the VNI is allocated. The awk
# runs here, not on the node: a remote awk program goes through two shell
# parsings and the quoting breaks.
ovl_non_ingress_vxlans() {
	node_ssh "$1" 'ifconfig -a 2>/dev/null' | awk '
		/^[a-z]/ {
			if (vx && !ing) c++
			i = $1; sub(/:$/, "", i)
			vx = (i ~ /^vxlan[0-9]+$/ || i ~ /^satl-vx[0-9]+$/)
			ing = 0
		}
		/description: satl:vxlan:ingress$/ { ing = 1 }
		END { if (vx && !ing) c++; print c + 0 }
	'
}

# ovl_ingress_names <node> — the ingress segment's interface names (bridge and
# VTEP), space-separated; empty when the node has no ingress segment.
ovl_ingress_names() {
	node_ssh "$1" 'ifconfig -a 2>/dev/null' | awk '
		/^[a-z]/ { i = $1; sub(/:$/, "", i) }
		/description: satl:overlay:ingress$/ || /description: satl:vxlan:ingress$/ { print i }
	' | tr '\n' ' '
}

ovl_count() {
	node_ssh "$1" "$2 2>/dev/null" | awk -v p="$3" 'p == "." || $0 ~ p { n++ } END { print n + 0 }'
}

ovl_rm_all() {
	_orm_ctl=$1
	for _s in "$SVC_A" "$SVC_B"; do
		node_ssh "$_orm_ctl" "satl service rm $_s >/dev/null 2>&1" || true
	done
	# The network cannot go until its tasks have: remove_network answers 409
	# while a task still holds an attachment (api-compat), so the retry here
	# is the reconciliation delay, not flakiness.
	_orm_i=0
	while [ "$_orm_i" -lt 20 ]; do
		node_ssh "$_orm_ctl" "satl network rm $OVL >/dev/null 2>&1" && break
		node_ssh "$_orm_ctl" "satl network ls --quiet 2>/dev/null" |
		    grep -q . || break
		sleep "$POLL"
		_orm_i=$((_orm_i + 1))
	done
}

scenario_overlay_dns() {
	require_swarm
	build_hostmap
	wait_until "$T_JOIN" "all nodes Ready" \
	    'state_fetch "$CTL" && [ "$(nodes_ready)" = "$(cluster_nodes | countl)" ]'

	_ovl_a=$(cluster_nodes | sed -n 1p)
	_ovl_b=$(cluster_nodes | sed -n 2p)
	[ -n "$_ovl_b" ] || fail "overlay_dns needs at least two nodes in the inventory"
	_ha=$(host_of "$_ovl_a")
	_hb=$(host_of "$_ovl_b")

	ovl_rm_all "$CTL"

	# --- the network --------------------------------------------------------
	node_ssh "$CTL" "satl network create -d overlay $OVL" >/dev/null ||
	    fail "satl network create -d overlay $OVL failed on $CTL"
	info "created overlay network $OVL on $CTL"

	# Every node must see it, with an allocated subnet and VNI: the object is
	# raft state, and the allocator runs on the leader only (invariant #1).
	wait_until "$T_QUICK" "$OVL visible with a subnet and vni on every node" '
		_ok=1
		for _n in $(cluster_nodes); do
			_j=$(node_ssh "$_n" "satl network inspect $OVL 2>/dev/null") || _ok=0
			printf %s "$_j" | grep -q "\"Subnet\"" || _ok=0
			printf %s "$_j" | grep -q "\"Vni\"" || _ok=0
			printf %s "$_j" | grep -q "\"Scope\": *\"swarm\"" || _ok=0
		done
		[ "$_ok" = 1 ]'

	# --- two services, one per node -----------------------------------------
	for _pair in "$SVC_A $_ha" "$SVC_B $_hb"; do
		set -- $_pair
		node_ssh "$CTL" "satl service create --name $1 --replicas 1 \
		    --network $OVL --constraint node.hostname==$2 $IMAGE" >/dev/null ||
		    fail "satl service create $1 (pinned to $2) failed"
		info "created $1 pinned to $2"
	done

	# Columns come out by *header*, like svc_replicas does, not by position:
	# `satl service ls` puts ID first and NAME second, so an `$1 == <name>`
	# match can never succeed (found the hard way — this wait timed out for 300s
	# against two services the daemon was already reporting as 1/1).
	wait_until "$T_CONVERGE" "$SVC_A and $SVC_B each have one Running task" '
		node_ssh "$CTL" "satl service ls 2>/dev/null" >"$TMPD/ovlsvc" || return 1
		_a=$(tcols "$TMPD/ovlsvc" "NAME,REPLICAS" |
		    awk -F"\t" -v a="$SVC_A" -v b="$SVC_B" \
		        "(\$1 == a || \$1 == b) && \$2 == \"1/1\"" | countl)
		[ "$_a" = 2 ]'

	# Placement is an assertion, not an assumption: if the constraints were
	# ignored, everything below would still pass on a single node.
	_ja=$(ovl_task_jid "$_ovl_a" "$SVC_A")
	_jb=$(ovl_task_jid "$_ovl_b" "$SVC_B")
	[ -n "$_ja" ] || fail "$SVC_A has no running jail on $_ovl_a ($_ha) — the constraint did not hold"
	[ -n "$_jb" ] || fail "$SVC_B has no running jail on $_ovl_b ($_hb) — the constraint did not hold"
	info "$SVC_A in jail $_ja on $_ovl_a, $SVC_B in jail $_jb on $_ovl_b"

	_aa=$(ovl_addr "$_ovl_a" "$SVC_A")
	_ab=$(ovl_addr "$_ovl_b" "$SVC_B")
	[ -n "$_aa" ] && [ -n "$_ab" ] ||
	    fail "could not read both overlay addresses from network inspect (got '$_aa' and '$_ab')"
	[ "$_aa" != "$_ab" ] || fail "both tasks report the overlay address $_aa"
	info "overlay addresses: $SVC_A $_aa, $SVC_B $_ab"

	# --- by service name, both directions -----------------------------------
	ovl_wait_fetch "$_ovl_a" "$_ja" "$SVC_B"
	ovl_wait_fetch "$_ovl_b" "$_jb" "$SVC_A"

	# --- the MTU, at the DF boundary ----------------------------------------
	# `|| true` for the same reason as in ovl_wait_fetch: without it a failing
	# ping aborts the run under `set -e` and the diagnosis below never prints.
	_ping_ok=$(ovl_in_jail "$_ovl_a" "$_ja" "ping -c 3 -D -s $OVL_PAYLOAD -t 10 $_ab" || true)
	printf %s "$_ping_ok" | grep -q " 0.0% packet loss" ||
	    fail "$OVL_PAYLOAD-byte DF ping $_aa -> $_ab failed; the overlay MTU is below $OVL_MTU:
$_ping_ok"
	info "DF ping at $OVL_PAYLOAD bytes crosses the underlay with no loss"

	_ping_big=$(ovl_in_jail "$_ovl_a" "$_ja" "ping -c 1 -D -s $((OVL_PAYLOAD + 1)) -t 5 $_ab" || true)
	printf %s "$_ping_big" | grep -qE "Message too long|message too long" ||
	    fail "a $((OVL_PAYLOAD + 1))-byte DF ping was not refused, so the overlay MTU is above \
$OVL_MTU and full-size frames will be fragmented on the underlay:
$_ping_big"
	info "one byte more is refused locally — the overlay MTU is exactly $OVL_MTU"

	# --- teardown leaves nothing -------------------------------------------
	ovl_rm_all "$CTL"
	wait_until "$T_CLEAN" "the overlay left no interface on any node" '
		_left=""
		for _n in $(cluster_nodes); do
			# `grep -c` prints 0 and *exits 1* when it matches nothing, so a
			# trailing `|| echo 0` appends a second line and the comparison can
			# never hold — which made this assertion unsatisfiable in exactly the
			# case it is meant to accept. Count with awk, which always exits 0.
			_o=$(ovl_count "$_n" "ifconfig -a" "overlay:$OVL")
			_t=$(ovl_count "$_n" "ifconfig -a" "vxlan:$OVL")
			_v=$(ovl_non_ingress_vxlans "$_n")
			[ "$_o" = 0 ] && [ "$_t" = 0 ] && [ "$_v" = 0 ] || _left="$_left $_n"
		done
		[ -z "$_left" ]'
	info "no overlay bridge, epair or VTEP left on any node"
	# Names as well as markers: an interrupted create leaves a `vxlanN` clone
	# carrying no description at all, which no marker grep can see. `ifconfig -g
	# vxlan` above catches that one; these catch a renamed interface whose
	# description was lost.
	for _n in $(cluster_nodes); do
		# The ingress segment's bridge/VTEP names are excluded the same way:
		# they are a long-lived cluster object, not a leftover (M6d).
		_ing=" $(ovl_ingress_names "$_n")"
		_named=$(node_ssh "$_n" \
		    "ifconfig -l | tr ' ' '\n' | grep -E '^satl-(br|vx)[0-9]+\$' || true" |
		    while read -r _i; do case $_ing in *" $_i "*) ;; *) echo "$_i";; esac; done | countl)
		[ "$_named" = 0 ] ||
		    fail "$_n still has $_named satl-br*/satl-vx* interface(s) after teardown"
	done
	info "no satl-br<vni> or satl-vx<vni> interface left by name either"
}

# ===========================================================================
# Scenario 7 — overlay_dns_multinet
#
# A task attached to *two* overlay networks resolves service names on both of
# them, and only on the networks it is itself attached to (api-compat 73/74).
#
# Why this exists beside overlay_dns rather than inside it: with one network
# every task's resolution scope is the same scope, so overlay_dns passes
# whatever the responder scopes queries to — the socket, the node, the whole
# cluster. It cannot fail on a scoping bug, which is exactly why the bug this
# scenario covers survived the M3 DoD.
#
# The layout is three services over two networks, and each of the three
# assertions below fails on a different wrong implementation:
#
#     node A: mn-x  on ovlx          mn-both on ovlx + ovly
#     node B: mn-y  on ovly
#
#   1. mn-both -> mn-x. Same node, first attached network. Passes on almost
#      anything; it is the control, so that a failure in 2 means "the second
#      network", not "DNS is down".
#   2. mn-both -> mn-y. **The regression catcher.** Different network *and*
#      different node. Scoped to the socket, this is the defect: a stub
#      resolver asks one `nameserver` line, gets an authoritative NXDOMAIN for
#      a name that lives on the other network, caches it and never tries the
#      second line. It is asserted through `fetch` on the service name, like
#      overlay_dns, so a pass means the answer was right *and* the second
#      network's data path carried the frames across the underlay.
#   3. mn-x -> mn-y must NOT resolve. **The over-widening catcher.** Node A's
#      responder holds ovly's endpoints (mn-both is on it), so an
#      implementation that answered from every network the *node* holds — the
#      obvious wrong way to fix 2 — would let mn-x resolve mn-y and leak one
#      network's service names into another. Checked only after 2 has passed,
#      because before convergence "does not resolve" is true for the wrong
#      reason.
#
# The resolv.conf line count is asserted too: two networks must produce two
# `nameserver` lines. Without that check, an attachment silently dropped at
# create time would leave assertion 3 passing for the wrong reason.
# ===========================================================================

# ovl_nameservers <node> <jid> — how many `nameserver` lines the jail's
# /etc/resolv.conf carries. awk rather than grep -c: grep exits 1 on zero
# matches, which turns a legitimate "none" into a shell trap (see ovl_count).
ovl_nameservers() {
	ovl_in_jail "$1" "$2" "cat /etc/resolv.conf" |
	    awk '$1 == "nameserver" { n++ } END { print n + 0 }'
}

# ovl_unresolvable <node> <jid> <service> — assert <service> does not resolve
# from inside a jail.
#
# The output is checked, not just the exit status, and the accepted patterns are
# resolution failures only. A `fetch` that cannot resolve says so ("Host does not
# resolve" from its own resolver path, "hostname nor servname provided" from
# getaddrinfo — both are seen, so both are accepted); one that fails with a
# timeout or a refused connection means the name *did* resolve, which is the leak
# this asserts against and must be a loud failure rather than a quiet pass.
ovl_unresolvable() {
	_our_out=$(ovl_in_jail "$1" "$2" "fetch -q -T 5 -o - http://$3/" || true)
	if printf %s "$_our_out" | grep -q "$OVL_BODY"; then
		fail "$3 answered inside $2 on $1, but that jail is not on its network: \
the responder is leaking one network's names into another (api-compat 73)"
	fi
	printf %s "$_our_out" |
	    grep -qiE "does not resolve|hostname nor servname|not known|Unknown host" ||
	    fail "$3 did not resolve inside $2 on $1, but not for the expected reason \
(a resolution failure). The output was:
$_our_out"
}

ovl_rm_multinet() {
	_orn_ctl=$1
	for _s in "$SVC_X" "$SVC_Y" "$SVC_BOTH"; do
		node_ssh "$_orn_ctl" "satl service rm $_s >/dev/null 2>&1" || true
	done
	for _net in "$OVL_X" "$OVL_Y"; do
		_orn_i=0
		while [ "$_orn_i" -lt 20 ]; do
			node_ssh "$_orn_ctl" "satl network rm $_net >/dev/null 2>&1" && break
			node_ssh "$_orn_ctl" "satl network inspect $_net >/dev/null 2>&1" || break
			sleep "$POLL"
			_orn_i=$((_orn_i + 1))
		done
	done
}

scenario_overlay_dns_multinet() {
	require_swarm
	build_hostmap
	wait_until "$T_JOIN" "all nodes Ready" \
	    'state_fetch "$CTL" && [ "$(nodes_ready)" = "$(cluster_nodes | countl)" ]'

	_mn_a=$(cluster_nodes | sed -n 1p)
	_mn_b=$(cluster_nodes | sed -n 2p)
	[ -n "$_mn_b" ] || fail "overlay_dns_multinet needs at least two nodes in the inventory"
	_mha=$(host_of "$_mn_a")
	_mhb=$(host_of "$_mn_b")

	ovl_rm_multinet "$CTL"

	for _net in "$OVL_X" "$OVL_Y"; do
		node_ssh "$CTL" "satl network create -d overlay $_net" >/dev/null ||
		    fail "satl network create -d overlay $_net failed on $CTL"
	done
	info "created overlay networks $OVL_X and $OVL_Y on $CTL"
	wait_until "$T_QUICK" "both networks have a subnet and a vni on every node" '
		_ok=1
		for _n in $(cluster_nodes); do
			for _net in "$OVL_X" "$OVL_Y"; do
				_j=$(node_ssh "$_n" "satl network inspect $_net 2>/dev/null") || _ok=0
				printf %s "$_j" | grep -q "\"Subnet\"" || _ok=0
				printf %s "$_j" | grep -q "\"Vni\"" || _ok=0
			done
		done
		[ "$_ok" = 1 ]'

	# One service per network plus one on both, each pinned so that the
	# interesting case — a name on the second network, on the other node — is a
	# fact and not a coin toss (the same reasoning as overlay_dns).
	node_ssh "$CTL" "satl service create --name $SVC_X --replicas 1 \
	    --network $OVL_X --constraint node.hostname==$_mha $IMAGE" >/dev/null ||
	    fail "satl service create $SVC_X failed"
	node_ssh "$CTL" "satl service create --name $SVC_Y --replicas 1 \
	    --network $OVL_Y --constraint node.hostname==$_mhb $IMAGE" >/dev/null ||
	    fail "satl service create $SVC_Y failed"
	node_ssh "$CTL" "satl service create --name $SVC_BOTH --replicas 1 \
	    --network $OVL_X --network $OVL_Y --constraint node.hostname==$_mha $IMAGE" >/dev/null ||
	    fail "satl service create $SVC_BOTH (on both networks) failed"
	info "$SVC_X on $OVL_X ($_mha), $SVC_Y on $OVL_Y ($_mhb), $SVC_BOTH on both ($_mha)"

	wait_until "$T_CONVERGE" "all three services have one Running task" '
		node_ssh "$CTL" "satl service ls 2>/dev/null" >"$TMPD/mnsvc" || return 1
		_r=$(tcols "$TMPD/mnsvc" "NAME,REPLICAS" |
		    awk -F"\t" -v x="$SVC_X" -v y="$SVC_Y" -v b="$SVC_BOTH" \
		        "(\$1 == x || \$1 == y || \$1 == b) && \$2 == \"1/1\"" | countl)
		[ "$_r" = 3 ]'

	_jx=$(ovl_task_jid "$_mn_a" "$SVC_X")
	_jy=$(ovl_task_jid "$_mn_b" "$SVC_Y")
	_jboth=$(ovl_task_jid "$_mn_a" "$SVC_BOTH")
	[ -n "$_jx" ] || fail "$SVC_X has no running jail on $_mn_a ($_mha) — the constraint did not hold"
	[ -n "$_jy" ] || fail "$SVC_Y has no running jail on $_mn_b ($_mhb) — the constraint did not hold"
	[ -n "$_jboth" ] ||
	    fail "$SVC_BOTH has no running jail on $_mn_a ($_mha) — the constraint did not hold"
	info "$SVC_X jail $_jx, $SVC_BOTH jail $_jboth on $_mn_a; $SVC_Y jail $_jy on $_mn_b"

	# Two attachments must produce two resolvers. If the second `--network` had
	# been dropped anywhere between the CLI and the allocator, assertion 3
	# below would still pass and this scenario would prove nothing.
	_ns=$(ovl_nameservers "$_mn_a" "$_jboth")
	[ "$_ns" = 2 ] ||
	    fail "$SVC_BOTH's jail has $_ns nameserver line(s), not 2: it is not \
attached to both overlay networks, so nothing below tests two-network scoping"
	_ns1=$(ovl_nameservers "$_mn_a" "$_jx")
	[ "$_ns1" = 1 ] || fail "$SVC_X's jail has $_ns1 nameserver line(s), not 1"
	info "$SVC_BOTH resolves through 2 nameservers, $SVC_X through 1"

	# 1 and 2: both names, from the task on both networks.
	ovl_wait_fetch "$_mn_a" "$_jboth" "$SVC_X"
	ovl_wait_fetch "$_mn_a" "$_jboth" "$SVC_Y"
	info "$SVC_BOTH reached both networks by name, including across the underlay"

	# 3: and the task on one network reaches only that one. Node $_mn_a's
	# responder demonstrably knows $SVC_Y — the line above just resolved it
	# there — so a pass here is about scope, not about a missing endpoint.
	ovl_unresolvable "$_mn_a" "$_jx" "$SVC_Y"
	info "$SVC_Y does not resolve from $SVC_X's jail: scope is the task, not the node"

	# --- teardown leaves nothing -------------------------------------------
	ovl_rm_multinet "$CTL"
	wait_until "$T_CLEAN" "neither overlay left an interface on any node" '
		_left=""
		for _n in $(cluster_nodes); do
			_c=0
			for _net in "$OVL_X" "$OVL_Y"; do
				_c=$((_c + $(ovl_count "$_n" "ifconfig -a" "overlay:$_net")))
				_c=$((_c + $(ovl_count "$_n" "ifconfig -a" "vxlan:$_net")))
			done
			_c=$((_c + $(ovl_non_ingress_vxlans "$_n")))
			[ "$_c" = 0 ] || _left="$_left $_n"
		done
		[ -z "$_left" ]'
	info "no overlay bridge, epair or VTEP left on any node"
}

# ===========================================================================
# Scenario 8 — publish_port
#
# `satl service create --publish <port>:80` and what it is worth from outside
# the cluster and from the nodes themselves. The external assertions run from
# the dev host against the VMs' public addresses, because the routing-mesh
# question is by definition about which node answers. The host-local ones run
# over ssh on each node's own 127.0.0.1: api-compat 35 used to record that pf
# never redirects a host's own loopback traffic, but the mechanism was
# remeasured in hack/experiments/lo0rdr/ and satld now publishes to the host
# too, with a `nat on lo0` source rewrite to a routed dummy address so the
# reply traverses both pf states. #35 records the new behaviour; this scenario
# pins it.
#
# Until M3 this was accepted, allocated, documented — and published nowhere:
# ingress is the default publish mode and the node-side filter only ever looked
# at host mode. Nothing in this suite noticed, because nothing in this suite had
# ever asked a node for a port.
#
# Asserts, in an order where each step only runs once the previous one makes it
# meaningful:
#
#   1. every node running a task of the service answers on the published port,
#      with the body the image bakes in (DNS-free, straight at the port), from
#      outside the cluster and from its own 127.0.0.1, and its `satl/rdr`
#      anchor holds both the redirect and the `nat on lo0` marker of the
#      host-local relay;
#   2. a node running *no* task answers too, from outside and from its own
#      loopback: the M6d routing mesh, whose return-path SNAT the host-local
#      relay chains with. Both markers (the mesh SNAT and the lo0 NAT) are
#      asserted alongside the answer;
#   3. the redirect survives its anchor being destroyed behind the daemon's
#      back — first with satld running (the periodic level pass repairs it with
#      no event and no restart), then across a `satld` restart (the startup pass
#      does). An edge-triggered publisher passes neither;
#   4. several tasks of one service on one node are one pf rule with a
#      round-robin address pool, not two rules of which pf would only ever
#      evaluate the first (api-compat 76);
#   5. removing the service leaves nothing: no rule in any anchor, and no node
#      answering.
# ===========================================================================

# pub_get <node> — fetch the published port from *this* host over the node's
# public address. Never fails the script: an unreachable port is data here, not
# an error (assertion 2 is precisely a request that must not succeed).
pub_get() {
	curl -s --max-time 5 "http://$(node_field "$1" public_ip):$PUB_PORT/" 2>/dev/null || true
}

# pub_answers <node> — whether that node serves the service on the published
# port. The body is checked, not just the connection: anything else that happened
# to listen on that port would otherwise read as a pass.
pub_answers() {
	printf %s "$(pub_get "$1")" | grep -q "$OVL_BODY"
}

# pub_get_local <node> — fetch the published port from the node itself, over
# its own loopback (the lo0 relay of api-compat 35, hack/experiments/lo0rdr).
# Same contract as pub_get: an unreachable port is data here, not an error.
pub_get_local() {
	node_ssh "$1" "curl -s --max-time 5 http://127.0.0.1:$PUB_PORT/ 2>/dev/null" \
	    2>/dev/null || true
}

# pub_answers_local <node> — whether the node serves the service to itself on
# 127.0.0.1. The body is checked, exactly as in pub_answers.
pub_answers_local() {
	printf %s "$(pub_get_local "$1")" | grep -q "$OVL_BODY"
}

# pub_rdr <node> — the node's live satl/rdr rules, one per line. An anchor that
# was never loaded prints "pfctl: DIOCGETRULES: Invalid argument" on stderr and
# exits 0, so stderr is dropped and only `rdr` lines are kept: "no anchor" and
# "empty anchor" are the same observation, which is what the assertions mean.
pub_rdr() {
	node_root_sh "$1" <<'REMOTE' 2>/dev/null
pfctl -a satl/rdr -s nat 2>/dev/null | grep '^rdr' || true
REMOTE
}

# pub_rdr_count <node> — how many of those rules mention the published port.
pub_rdr_count() {
	pub_rdr "$1" | awk -v p="port = $PUB_PORT " '$0 ~ p { n++ } END { print n + 0 }'
}

# pub_lo0_nat <node> — the node's live `nat on lo0` rules in satl/rdr, one per
# line: the marker of the host-local relay (hack/experiments/lo0rdr), the way
# `nat pass` is the marker of the mesh SNAT. Same "no anchor and empty anchor
# are the same observation" contract as pub_rdr.
pub_lo0_nat() {
	node_root_sh "$1" <<'REMOTE' 2>/dev/null
pfctl -a satl/rdr -s nat 2>/dev/null | grep '^nat on lo0' || true
REMOTE
}

# pub_lo0_nat_count <node> — how many of those rules mention the published port.
pub_lo0_nat_count() {
	pub_lo0_nat "$1" | awk -v p="port = $PUB_PORT " '$0 ~ p { n++ } END { print n + 0 }'
}

# pub_hosts — hostnames running a live task of $PUB, one per line, read from
# $CTL. Same definition of "live" as live_tasks(): desired Running *and*
# observed Running, so a task on a node that stopped reporting does not count.
pub_hosts() {
	node_ssh "$CTL" "satl service ps $PUB 2>/dev/null" >"$TMPD/pubtasks" 2>/dev/null || return 1
	tcols "$TMPD/pubtasks" 'NODE,DESIRED STATE,CURRENT STATE' |
	    awk -F'\t' '$2 == "Running" && $3 ~ /^Running/ { print $1 }' | sort -u
}

# pub_live <node> — how many live tasks of $PUB run on that inventory node.
pub_live() {
	node_ssh "$CTL" "satl service ps $PUB 2>/dev/null" >"$TMPD/pubtasks" 2>/dev/null || return 1
	tcols "$TMPD/pubtasks" 'NODE,DESIRED STATE,CURRENT STATE' |
	    awk -F'\t' -v h="$(host_of "$1")" \
	        '$1 == h && $2 == "Running" && $3 ~ /^Running/ { n++ } END { print n + 0 }'
}

pub_replicas() {
	node_ssh "$CTL" "satl service ls 2>/dev/null" >"$TMPD/pubsvc" 2>/dev/null || return 1
	tcols "$TMPD/pubsvc" 'NAME,REPLICAS' | awk -F'\t' -v s="$PUB" '$1 == s { print $2 }'
}

pub_rm() {
	node_ssh "$CTL" "satl service rm $PUB >/dev/null 2>&1" || true
}

# pub_flush_anchor <node> — destroy the node's satl/rdr anchor behind satld's
# back. This is SatL's own anchor, so the test is not reaching outside what SatL
# owns; it stands in for every way the kernel and the daemon's idea of the
# kernel can drift apart.
pub_flush_anchor() {
	node_root_sh "$1" <<'REMOTE' >/dev/null 2>&1 || true
pfctl -a satl/rdr -F nat
REMOTE
}

scenario_publish_port() {
	require_swarm
	build_hostmap
	wait_until "$T_JOIN" "all nodes Ready" \
	    'state_fetch "$CTL" && [ "$(nodes_ready)" = "$(cluster_nodes | countl)" ]'

	# A previous run of this scenario alone may have left the service behind;
	# creating it again would then be a name conflict rather than a test.
	pub_rm
	wait_until "$T_CLEAN" "no leftover $PUB service" '[ -z "$(pub_replicas)" ]'
	info "satl service create --name $PUB --replicas $PUB_REPLICAS -p $PUB_PORT:80"
	node_ssh "$CTL" "satl service create --name $PUB --replicas $PUB_REPLICAS \
	    -p $PUB_PORT:80 $IMAGE" >"$TMPD/pubcreate" 2>&1 || {
		show "$TMPD/pubcreate"
		fail "satl service create --publish failed on $CTL"
	}
	wait_until "$T_CONVERGE" "$PUB reaches $PUB_REPLICAS/$PUB_REPLICAS" \
	    '[ "$(pub_replicas)" = "$PUB_REPLICAS/$PUB_REPLICAS" ]'

	# Which nodes host a task is read from the cluster, not assumed: with two
	# replicas over three nodes the split is the scheduler's business, and only
	# the pigeonhole ("at least one node has none") is guaranteed.
	PUB_WITH=""
	PUB_WITHOUT=""
	for _n in $(cluster_nodes); do
		if pub_hosts | grep -qx "$(host_of "$_n")"; then
			PUB_WITH="$PUB_WITH $_n"
		else
			PUB_WITHOUT="$PUB_WITHOUT $_n"
		fi
	done
	PUB_WITH=${PUB_WITH# }
	PUB_WITHOUT=${PUB_WITHOUT# }
	[ -n "$PUB_WITH" ] || fail "$PUB has no live task anywhere"
	[ -n "$PUB_WITHOUT" ] ||
	    fail "every node runs a task of $PUB, so assertion 2 would pass vacuously \
(SATL_TEST_PUB replicas must stay below the node count)"
	info "tasks on: $PUB_WITH — no task on: $PUB_WITHOUT"

	# --- 1. every node with a task answers, from outside and from itself ----
	for _n in $PUB_WITH; do
		PUB_NODE=$_n
		wait_until "$T_QUICK" \
		    "$_n answers http://$(node_field "$_n" public_ip):$PUB_PORT/" \
		    'pub_answers "$PUB_NODE"'
		_rules=$(pub_rdr_count "$_n")
		[ "$_rules" -ge 1 ] ||
		    fail "$_n answers on $PUB_PORT but its satl/rdr anchor has no rule for it"
		# The host-local relay (api-compat 35, hack/experiments/lo0rdr): the
		# node reaches its own published port over loopback, and carries the
		# `nat on lo0` rule that makes the reply traversable.
		wait_until "$T_QUICK" \
		    "$_n answers http://127.0.0.1:$PUB_PORT/ from itself" \
		    'pub_answers_local "$PUB_NODE"'
		[ "$(pub_lo0_nat_count "$_n")" -ge 1 ] ||
		    fail "$_n answers itself on $PUB_PORT without the lo0 NAT rule in satl/rdr"
	done
	info "every node running a task publishes the port, to the outside and to itself"

	# --- 2. and a node without a task answers too — the M6d mesh -----------
	# Only meaningful now that the nodes that *should* answer do: before
	# convergence, "answers" is true for the wrong reason. Every node in this
	# suite is a manager, so every node is a mesh member; the worker carve-out
	# of api-compat 75 cannot be observed here.
	for _n in $PUB_WITHOUT; do
		PUB_NODE=$_n
		wait_until "$T_QUICK" \
		    "$_n relays http://$(node_field "$_n" public_ip):$PUB_PORT/ though it runs no task" \
		    'pub_answers "$PUB_NODE"'
		_rules=$(pub_rdr_count "$_n")
		[ "$_rules" -ge 1 ] ||
		    fail "$_n relays on $PUB_PORT but its satl/rdr anchor has no rule for it"
		# The mesh marker: the return-path SNAT, whose target is this node's
		# ingress gateway. Without it the relay would be asymmetric (measured
		# in hack/experiments/mesh: the handshake never completes).
		_nat=$(node_root_sh "$_n" <<'REMOTE' 2>/dev/null
pfctl -a satl/rdr -s nat 2>/dev/null | grep '^nat pass' || true
REMOTE
)
		[ -n "$_nat" ] ||
		    fail "$_n relays on $PUB_PORT without the mesh SNAT rule in satl/rdr"
		# And the relay works from the node itself too: the lo0 redirect
		# chains with the mesh SNAT above (hack/experiments/lo0rdr), so even
		# a node running no task serves its own 127.0.0.1.
		wait_until "$T_QUICK" \
		    "$_n relays http://127.0.0.1:$PUB_PORT/ from itself" \
		    'pub_answers_local "$PUB_NODE"'
		[ "$(pub_lo0_nat_count "$_n")" -ge 1 ] ||
		    fail "$_n relays its own loopback on $PUB_PORT without the lo0 NAT rule in satl/rdr"
	done
	info "a node with no task of $PUB answers by relaying (the M6d mesh), even to itself"

	# --- 3a. the anchor is a level: destroy it and it comes back ------------
	PUB_NODE=$(echo "$PUB_WITH" | awk '{ print $1 }')
	pub_flush_anchor "$PUB_NODE"
	_gone=$(pub_rdr_count "$PUB_NODE")
	if [ "$_gone" = 0 ]; then
		info "destroyed $PUB_NODE's satl/rdr anchor behind satld's back (it is still running)"
	else
		# satld re-asserts its anchor about once a minute, so it can land in the
		# second between the flush above and this read. That is the behaviour
		# under test rather than a failure — but it is said out loud, because
		# the wait below then proves nothing it did not already prove.
		info "$PUB_NODE repaired its anchor before this read ($_gone rule(s)) — \
the level was faster than the check"
	fi
	wait_until "$T_PUB_HEAL" "$PUB_NODE republishes the port with no event at all" \
	    'pub_answers "$PUB_NODE"'

	# --- 3b. and it survives a restart of the daemon ------------------------
	# Flushed while satld is down, so the anchor cannot simply have been left
	# alone: the startup pass has to derive it again from the store.
	node_satld "$PUB_NODE" stop >/dev/null
	pub_flush_anchor "$PUB_NODE"
	node_satld "$PUB_NODE" start >/dev/null
	info "restarted satld on $PUB_NODE with its rdr anchor wiped while it was down"
	wait_until "$T_QUICK" "$PUB_NODE answers again after the restart" \
	    'pub_answers "$PUB_NODE"'

	# --- 4. two tasks on one node are one rule with a pool ------------------
	info "satl service scale $PUB=$PUB_CROWDED"
	node_ssh "$CTL" "satl service scale $PUB=$PUB_CROWDED" >"$TMPD/pubscale" 2>&1 || {
		show "$TMPD/pubscale"
		fail "satl service scale $PUB=$PUB_CROWDED failed"
	}
	wait_until "$T_CONVERGE" "$PUB reaches $PUB_CROWDED/$PUB_CROWDED" \
	    '[ "$(pub_replicas)" = "$PUB_CROWDED/$PUB_CROWDED" ]'
	PUB_CROWDED_NODE=""
	for _n in $(cluster_nodes); do
		if [ "$(pub_live "$_n")" -ge 2 ]; then PUB_CROWDED_NODE=$_n; fi
	done
	[ -n "$PUB_CROWDED_NODE" ] ||
	    fail "$PUB_CROWDED replicas over $(cluster_nodes | countl) nodes and no node \
has two: nothing here can test the round-robin pool"
	# One pool per published triple, whatever the member count: the two rdr
	# rules (the interface-less one and its lo0 twin, api-compat 35) are the
	# pool's constant text, membership lives in the table. Two tasks must not
	# grow the ruleset.
	wait_until "$T_QUICK" "$PUB_CROWDED_NODE pools its two tasks into one rdr pool" '
		[ "$(pub_rdr_count "$PUB_CROWDED_NODE")" = 2 ] &&
		[ "$(pub_rdr "$PUB_CROWDED_NODE" | grep -c "on lo0")" = 1 ] &&
		pub_rdr "$PUB_CROWDED_NODE" | grep -q "round-robin"'
	pub_rdr "$PUB_CROWDED_NODE" | sed 's/^/    /'
	wait_until "$T_QUICK" "and still answers" 'pub_answers "$PUB_CROWDED_NODE"'

	# --- 5. removing the service leaves nothing -----------------------------
	pub_rm
	wait_until "$T_CLEAN" "no satl/rdr rule anywhere and no node answering" '
		_left=""
		for _n in $(cluster_nodes); do
			[ "$(pub_rdr_count "$_n")" = 0 ] || _left="$_left $_n"
			[ "$(pub_lo0_nat_count "$_n")" = 0 ] || _left="$_left $_n"
			! pub_answers "$_n" || _left="$_left $_n"
			! pub_answers_local "$_n" || _left="$_left $_n"
		done
		[ -z "$_left" ]'
	info "the satl/rdr anchor is empty on every node and the port answers nowhere"
}

# ===========================================================================
# Scenario 9 — rolling_update
#
# The M4 Definition of Done, live: **six replicas over three nodes, updated
# one slot at a time with traffic on the published port throughout and no
# request lost**, then an update to an image that cannot start, which the
# manager rolls back **on its own**, ending on the working spec and serving.
#
# Three phases, one service, one load generator running across the first two.
# Phase 2 is not a second scenario because the interesting part of a rollback is
# that it starts from a service that is already serving: the working tasks are
# what it must not disturb, and they only exist because phase 1 put them there.
# Phase 3 needs a converged service for the same reason.
#
# **The updates go through `satl service update`**, not through the REST API.
# That is the surface an operator uses, and until the CLI grew Docker's
# `--update-*`/`--rollback-*` flags it could not express `failure_action:
# rollback` at all -- worse, it *erased* it, because `update` posts back the spec
# it read and its copy of `UpdateConfig` had only two of six fields. So the two
# updates below name nothing but `--image` and phase 2 still has to roll back on
# its own, which is the strongest available assertion that the policy survived a
# CLI round trip (api-compat 96). The **create** stays on the REST API, as the one
# place in the suite that posts a full `ServiceSpec` with an explicit
# `UpdateConfig` and pins the wire spelling of every field of it; every read-back
# is REST too.
#
# What each phase asserts:
#
#   1. a spec change that requires replacing every task (a new image tag with
#      the same content, so the body served is unchanged and the load
#      generator's own success test stays valid across the update):
#      - `UpdateStatus` walks `updating` -> `completed`, and every task ends on
#        the new image, in the same six slots;
#      - **no request is lost** (see ru_load_start for exactly what is counted);
#      - the update is *rolling*: at every sample, at least five of the six
#        slots are serving and every node still answers on the published port.
#        With `parallelism = 1` and two slots per node, one slot at a time is
#        the difference between a rolling update and a restart, and it is the
#        only reason the traffic assertion above can hold.
#   2. an update to an image tag that is not in any node's registry, which is
#      what a mistyped or unpushed tag looks like from the daemon's side:
#      - the pull fails, the task fails, and with `failure_action = rollback`
#        the manager swaps the spec back with no operator involved;
#      - `UpdateStatus` ends `rollback_completed`, `PreviousSpec` is cleared
#        (nothing can roll forward into the broken spec again), and the service
#        is back on the working image and serving;
#      - **no request is lost here either**, and that is not luck: `stop-first`
#        only stops a task once its replacement is prepared, and a replacement
#        that cannot pull is never prepared, so a broken rollout never takes a
#        serving task away.
#   3. the other failure action, `pause`, and getting out of it. Set through the
#      CLI (a policy change that must replace no task at all), then the broken
#      image again, which now pauses instead of rolling back, then the working
#      image:
#      - a paused update is what an operator meets after a typo, and the updater
#        does nothing more for a paused service by design, so pushing a corrected
#        spec has to clear that status or the service is stuck for good
#        (api-compat 92);
#      - asserted as its own wait, so a control API that left `UpdateStatus`
#        alone fails naming the defect rather than timing out on convergence.
#      No load generator here: a paused update leaves a slot empty on purpose and
#      a node with no task of the service does not answer at all (api-compat 75),
#      so counting requests would measure ingress-lite instead of resumability.
#
# Finally, and independently of the traffic: **no node re-published a stopped
# task's redirect** (ru_republished), read from the daemon's own log. That is the
# deterministic form of the first-attempt failures the load generator can only see
# by luck.
#
# Why the port and not the service name: a published port is reachable from
# this host (api-compat 35/75) and a service name is not, so this is the only
# vantage point from which the load can be generated the way a client would.
# ===========================================================================

# ru_api <node> <method> <path> [body] — talk to satld's REST API on the node
# itself, over its unix socket. Root, because the socket is (like docker's)
# root-owned; the body travels as an argument rather than on stdin, which
# node_root_sh already uses for the script.
ru_api() {
	_ra_n=$1
	_ra_m=$2
	_ra_p=$3
	_ra_b=${4:-}
	node_root_sh "$_ra_n" "$_ra_m" "$_ra_p" "$_ra_b" <<'REMOTE'
method=$1
path=$2
body=$3
sock=/var/run/satl.sock
if [ -n "$body" ]; then
	tmp=$(mktemp /tmp/satl-api.XXXXXX)
	printf '%s' "$body" >"$tmp"
	curl -s --unix-socket "$sock" -X "$method" \
	    -H 'Content-Type: application/json' --data-binary "@$tmp" \
	    "http://localhost$path"
	rm -f "$tmp"
else
	curl -s --unix-socket "$sock" -X "$method" "http://localhost$path"
fi
REMOTE
}

# ru_spec <image> — the service spec, as one line of JSON.
#
# The spec the service is **created** with, on the REST API. The updates go
# through the CLI and name one field each, so this is also the baseline every
# later assertion about the policy compares against: everything is spelled out
# rather than defaulted, because the update configuration *is* what this scenario
# tests, and a CLI round trip must bring all of it back unchanged.
#
#   parallelism 1   one slot at a time (the default, and the DoD's shape)
#   order           stop-first (the default): a task is stopped only once its
#                   replacement is prepared, and promoted only once the
#                   predecessor has actually stopped
#   monitor         RU_MONITOR: how long a new task must be observed running
#                   before the batch moves on. This is the health gate: a task
#                   with a healthcheck does not report Running until it is
#                   healthy, so waiting for Running plus the window is waiting
#                   for "serving".
#   failure_action  rollback, which phase 1 must never reach and phase 2 must
#   max_failure_ratio 0: one failed task is one too many
#   restart         bounded, so a broken image's replacements do not churn
#                   while the assertions run
ru_spec() {
	cat <<JSON | tr -d '\n\t'
{
	"Name": "$RU",
	"TaskTemplate": {
		"ContainerSpec": {"Image": "$1"},
		"RestartPolicy": {"Condition": "any", "Delay": 5000000000, "MaxAttempts": 2},
		"ForceUpdate": 0
	},
	"Mode": {"Replicated": {"Replicas": $RU_REPLICAS}},
	"UpdateConfig": {
		"Parallelism": 1,
		"Delay": 0,
		"FailureAction": "rollback",
		"Monitor": ${RU_MONITOR}000000000,
		"MaxFailureRatio": 0.0,
		"Order": "stop-first"
	},
	"EndpointSpec": {
		"Mode": "dnsrr",
		"Ports": [{
			"Name": "http", "Protocol": "tcp", "TargetPort": 80,
			"PublishedPort": $RU_PORT, "PublishMode": "ingress"
		}]
	}
}
JSON
}

# The service as the API renders it, and the three things read out of it.
# Compact JSON from the API (the pretty-printer is the CLI's), so a field is a
# `sed` away and no JSON parser has to be shipped to the nodes.
ru_get() { ru_api "$CTL" GET "/services/$RU" 2>/dev/null; }
ru_version() { ru_get | sed -n 's/.*"Version":{"Index":\([0-9]*\).*/\1/p'; }
ru_state() { ru_get | sed -n 's/.*"UpdateStatus":{"State":"\([a-z_]*\)".*/\1/p'; }
ru_message() { ru_get | sed -n 's/.*"UpdateStatus":{[^}]*"Message":"\([^"]*\)".*/\1/p'; }
# The *current* spec's image, and deliberately not by matching `"Spec":{`: a
# service that has a `PreviousSpec` contains that substring twice, `sed`'s `.*`
# is greedy, and the second match is the spec that was rolled *away* from —
# which is exactly the value that would make a broken rollback look successful.
# Document order decides instead: the renderer writes `Spec` before
# `PreviousSpec`, so the first image in the document is the live one.
ru_spec_image() {
	ru_get | tr '{,' '\n\n' | sed -n 's/^"Image":"\([^"]*\)".*/\1/p' | head -1
}
ru_has_previous() { ru_get | grep -q '"PreviousSpec"'; }

# ru_tasks — `satl service ps $RU` as a table file, and the columns read out of
# it. Same definition of "live" as live_tasks(): desired Running *and* observed
# Running, so a task on a node that stopped reporting does not count.
ru_tasks() {
	node_ssh "$CTL" "satl service ps $RU 2>/dev/null" >"$TMPD/rutasks" 2>/dev/null || return 1
	return 0
}
ru_live_images() {
	tcols "$TMPD/rutasks" 'IMAGE,DESIRED STATE,CURRENT STATE' |
	    awk -F'\t' '$2 == "Running" && $3 ~ /^Running/ { print $1 }'
}
ru_serving_slots() {
	tcols "$TMPD/rutasks" 'NAME,DESIRED STATE,CURRENT STATE' |
	    awk -F'\t' '$2 == "Running" && $3 ~ /^Running/ { split($1, p, "."); print p[2] }' |
	    sort -u
}
ru_serving_nodes() {
	tcols "$TMPD/rutasks" 'NODE,DESIRED STATE,CURRENT STATE' |
	    awk -F'\t' '$2 == "Running" && $3 ~ /^Running/ { print $1 }' | sort | uniq -c |
	    awk '{ print $2 "=" $1 }' | tr '\n' ' ' | sed 's/ *$//'
}
ru_replicas() {
	node_ssh "$CTL" "satl service ls 2>/dev/null" >"$TMPD/rusvc" 2>/dev/null || return 1
	tcols "$TMPD/rusvc" 'NAME,REPLICAS' | awk -F'\t' -v s="$RU" '$1 == s { print $2 }'
}
ru_failed() {
	tcols "$TMPD/rutasks" 'NAME,CURRENT STATE,ERROR' |
	    awk -F'\t' '$2 ~ /^(Failed|Rejected)/ { print "    " $1 "  " $2 "  " $3 }'
}

ru_rm() {
	node_ssh "$CTL" "satl service rm $RU >/dev/null 2>&1" || true
}

# ru_task_ids — every task id of $RU, live and historic. Read before the service
# is removed, because afterwards there is nothing left to ask.
ru_task_ids() {
	node_ssh "$CTL" "satl service ps $RU --quiet --no-trunc 2>/dev/null" | tr -d '\r'
}

# ru_leftovers <ids> — how many jails, container datasets, task epairs and
# leftover mounts those task ids still hold, summed over every node.
#
# A task id is the jail name, the dataset name under <zfs_root>/containers, the
# epair description (`satl:<task-id>`) and the path component every one of its
# mounts sits under — so one id is four things to look for and all four are named
# after it, which is what makes a per-task audit possible at all.
#
# The mount check uses `mount -p`: ocijail's per-task mounts are MNT_IGNORE, so
# plain `mount` shows none of them and this audit passed for years' worth of runs
# while they piled up (measured: 54, 54 and 56 stale tmpfs across the nodes).
ru_leftovers() {
	_rl_total=0
	for _rl_n in $(cluster_nodes); do
		_rl_c=$(node_root_sh "$_rl_n" "$STATE_DIR" "$ZFS_ROOT" "$1" <<'REMOTE' 2>/dev/null
state_dir=$1
zfs_root=$2
ids=$3
n=0
jails=$(jls -N jid name path 2>/dev/null | awk -v d="$state_dir/" '$3 ~ "^" d { print $2 }')
datasets=$(zfs list -H -o name -r -d 1 "$zfs_root/containers" 2>/dev/null)
epairs=$(ifconfig -a 2>/dev/null | awk '/^[[:space:]]*description: satl:/ { print $2 }')
mounted=$(mount -p |
    awk -F'[\t ]+' -v d="$state_dir/containers/" '
        index($2, d) == 1 {
                rest = substr($2, length(d) + 1)
                slash = index(rest, "/")
                if (slash > 1) print substr(rest, 1, slash - 1)
        }' | sort -u)
for id in $ids; do
	printf '%s\n' "$jails" | grep -qx "$id" && n=$((n + 1))
	printf '%s\n' "$datasets" | grep -qx "$zfs_root/containers/$id" && n=$((n + 1))
	printf '%s\n' "$epairs" | grep -qx "satl:$id" && n=$((n + 1))
	printf '%s\n' "$mounted" | grep -qx "$id" && n=$((n + 1))
done
echo "$n"
REMOTE
		) || return 1
		_rl_total=$((_rl_total + _rl_c))
	done
	echo "$_rl_total"
}

# ru_serving_only <image> <count> — whether exactly <count> tasks are serving
# and every one of them is on <image>. A poll body, so a manager that cannot
# answer reads as "not converged yet" rather than as an error.
ru_serving_only() {
	ru_tasks || return 1
	[ "$(ru_live_images | countl)" = "$2" ] || return 1
	[ "$(ru_live_images | sort -u)" = "$1" ]
}

# --- the load generator -----------------------------------------------------
#
# It runs here, on the dev host, so every request crosses exactly what a client
# crosses: the node's public address, its pf redirect, its own task. One
# request at a time per node, round robin, each on its own connection, so a
# redirect that has just changed is observed rather than hidden inside a pooled
# one.
#
# What is counted, and why it is counted that way:
#
#   - **every attempt**, including the failures. A request that was never sent
#     is not a request that succeeded, so the assertions check the total as
#     well: a load generator that died in the first second would otherwise
#     "prove" a flawless update.
#   - an attempt succeeds only if the body carries the marker the image bakes
#     in. A 200 from something else that happens to listen on the port is a
#     failure, and so is a connection refused, a timeout and an empty body.
#   - a failed attempt is **retried once, immediately**, and the two outcomes
#     are counted separately: `retried` (the second attempt served it) and
#     `lost` (nothing served it). That is what a load balancer does with an
#     idempotent GET, and it is the honest way to report "no request was lost"
#     without hiding that an attempt failed.
#   - **every attempt carries its node and the second it happened in**, so the
#     question an operator actually asks — "how long was this port answering
#     wrong?" — can be answered, and so can the question that makes the answer
#     trustworthy: "was I still asking?". A generator that stalls for five
#     seconds cannot see a five-second outage, and a measurement that cannot
#     detect its own blind spot is not a measurement (see
#     ru_assert_first_attempts, which asserts the sampling gap alongside the
#     failures).
#
# Each line of `attempts` is `<ok|fail> <ip> <epoch>`; each line of `failures`
# is `<retried|lost> <ip> <epoch>`.
ru_load_start() {
	RU_LOAD=$TMPD/load
	mkdir -p "$RU_LOAD"
	: >"$RU_LOAD/attempts"
	: >"$RU_LOAD/failures"
	rm -f "$RU_LOAD/stop"
	_ru_ips=""
	for _n in $(cluster_nodes); do
		_ru_ips="$_ru_ips $(node_field "$_n" public_ip)"
	done
	(
		while [ ! -f "$RU_LOAD/stop" ]; do
			# One clock reading per round trip through the nodes: the three
			# requests below take a few hundred milliseconds together, which is
			# inside the one-second granularity this is compared at, and it
			# keeps the generator to two forks per request.
			_ru_at=$(date +%s)
			for _ip in $_ru_ips; do
				if curl -s --max-time 5 "http://$_ip:$RU_PORT/" 2>/dev/null |
				    grep -q "$OVL_BODY"; then
					printf 'ok %s %s\n' "$_ip" "$_ru_at" >>"$RU_LOAD/attempts"
					continue
				fi
				printf 'fail %s %s\n' "$_ip" "$_ru_at" >>"$RU_LOAD/attempts"
				if curl -s --max-time 5 "http://$_ip:$RU_PORT/" 2>/dev/null |
				    grep -q "$OVL_BODY"; then
					printf 'retried %s %s\n' "$_ip" "$_ru_at" >>"$RU_LOAD/failures"
				else
					printf 'lost %s %s\n' "$_ip" "$_ru_at" >>"$RU_LOAD/failures"
				fi
			done
		done
	) &
	RU_LOAD_PID=$!
	info "load: one request at a time per node against :$RU_PORT (pid $RU_LOAD_PID)"
}

# ru_load_mark <phase> — remember the counts at a phase boundary, so each phase
# reports its own numbers rather than the run's total.
ru_load_mark() {
	eval "RU_MARK_$1=\$(countl <\"\$RU_LOAD/attempts\")"
	eval "RU_MARKF_$1=\$(countl <\"\$RU_LOAD/failures\")"
}

# ru_load_report <phase> <from-attempts> <from-failures> — the counts since a
# mark, printed and left in RU_TOTAL / RU_FAIL1 / RU_RETRIED / RU_LOST.
ru_load_report() {
	_rlr_phase=$1
	_rlr_a0=$2
	_rlr_f0=$3
	# Where this phase starts in the failure log, for ru_assert_first_attempts.
	RU_MARKF=$_rlr_f0
	RU_TOTAL=$(($(countl <"$RU_LOAD/attempts") - _rlr_a0))
	RU_FAIL1=$(awk -v skip="$_rlr_a0" 'NR > skip && $1 == "fail" { n++ } END { print n + 0 }' \
	    "$RU_LOAD/attempts")
	RU_RETRIED=$(awk -v skip="$_rlr_f0" 'NR > skip && $1 == "retried" { n++ } END { print n + 0 }' \
	    "$RU_LOAD/failures")
	RU_LOST=$(awk -v skip="$_rlr_f0" 'NR > skip && $1 == "lost" { n++ } END { print n + 0 }' \
	    "$RU_LOAD/failures")
	# How long the phase was measured for, and the longest the generator went
	# without asking a given node anything: the second number is what makes the
	# first mean something.
	RU_SPAN=$(awk -v skip="$_rlr_a0" 'NR > skip { if (!f) f = $3; l = $3 }
	    END { print (l > f ? l - f : 0) }' "$RU_LOAD/attempts")
	RU_GAP=$(awk -v skip="$_rlr_a0" 'NR > skip {
		if ($2 in last && $3 - last[$2] > worst) worst = $3 - last[$2]
		last[$2] = $3
	} END { print worst + 0 }' "$RU_LOAD/attempts")
	info "load ($_rlr_phase): $RU_TOTAL requests over ${RU_SPAN}s, \
$((RU_TOTAL - RU_FAIL1)) served first try, $RU_RETRIED served on one retry, \
$RU_LOST lost; longest gap between two requests to one node ${RU_GAP}s"
	# One line per *window* rather than per node: failures more than
	# RU_STALE_GAP seconds apart are separate events, and merging them would
	# report two one-second windows half a minute apart as a thirty-second
	# outage. The span of each is the diagnosis — a stale redirect lives for one
	# of satld's port passes (5s); anything longer is a different defect.
	if [ "$RU_FAIL1" != 0 ]; then
		awk -v skip="$_rlr_f0" -v gap="$RU_STALE_GAP" '
		NR <= skip { next }
		{
			node = $2; at = $3 + 0
			if (node in last && at - last[node] > gap) {
				printf "      %-16s %4d request(s) failing over %2ds from %s\n",
				    node, n[node], last[node] - start[node], strftime("%H:%M:%S", start[node])
				n[node] = 0
			}
			if (!(node in n) || n[node] == 0) start[node] = at
			n[node]++
			last[node] = at
		}
		END {
			for (node in n) if (n[node] > 0)
				printf "      %-16s %4d request(s) failing over %2ds from %s\n",
				    node, n[node], last[node] - start[node], strftime("%H:%M:%S", start[node])
		}' "$RU_LOAD/failures"
	fi
}

# ru_assert_first_attempts <phase> — the second half of the traffic assertion,
# and the one that is *not* about the updater.
#
# A first attempt can fail while a retry a millisecond later succeeds, and that
# combination has exactly one cause, measured on these VMs and left in the log
# on purpose (node2, 11:05:38, first run of this scenario):
#
#   38.837  unpublish_ports{task_id=2ipiebk0...}: published ports removed
#   38.977  published ports converged ... 2ipiebk0...->10.88.0.3:80
#   38.999  dispatcher.status apply{task_id=2ipiebk0... state=shutdown}
#   43.976  published ports converged ... (without it)
#
# The agent removed the stopped task's redirect on the spot; satld's periodic
# port pass fired 140 ms later, derived `wanted` from the **store**, which had
# not yet been told the task had stopped (22 ms behind), and put the redirect
# back — pointing at a container that was gone. pf then alternates the two
# addresses of the node's round-robin pool (api-compat 76), so every other
# connection to that node fails until the next pass, 5 s later. That is why the
# failures come in pairs of "first attempt fails, retry succeeds".
#
# It was a satld defect, not an updater one, and it is **fixed**:
# `running_task_ports` (crates/satld/src/reconcile.rs) filtered on the task's
# *observed* state alone, where a task the manager has ordered to stop
# (`desired_state >= SHUTDOWN`, written before the agent acts and therefore never
# late) has no business being published. Measured over seven pre-fix runs of this
# scenario: four saw first-attempt failures (0, 0, 1, 1, 64, 0, 63 of ~2300),
# three saw none. The deterministic form of the same fact is asserted separately
# and unconditionally by `ru_republished`, which reads the daemon's log instead of
# guessing from traffic.
#
# What is asserted here is still the *shape* rather than the volume, and stays
# that way now that the count should be zero: volume is the wrong measure — a
# 5-second window costs as many requests as the load generator happens to send in
# 5 seconds, so a count, or a percentage of a phase that lasted 10 s (what an
# earlier version of this assertion used, and what Suite A caught it on), says
# more about the harness than about the daemon. A zero here is reported as
# "nothing failed" and needs no bound; a non-zero has to satisfy three things,
# each of them about the daemon:
#
#   1. **no window outlives one port pass.** A redirect 5 s behind the store is
#      the known lag; one that stayed wrong for 30 s is a different defect.
#   2. **no more windows than task stops can explain.** Pre-M6d a stop could
#      strand one redirect on one node, and `stops` was the ceiling. With the
#      mesh the pool is cluster-wide: one stop strands the task's entry on
#      **every** node at once, and this counter windows per node, so the
#      ceiling is `stops x nodes`. A defect that produced a one-second window
#      after every request would pass (1) and fail this.
#   3. **the generator never went quiet for longer than a window.** This is not
#      about the daemon but about whether (1) and (2) can be believed: a
#      measurement that stalls for as long as the outage it looks for cannot see
#      it, and "no request failed" from a generator that sent nothing is the
#      emptiest possible pass.
#
# Usage: ru_assert_first_attempts <phase> <task stops in this phase>
ru_assert_first_attempts() {
	RU_PHASE=$1
	RU_STOPS=$2
	# (3) first: if the sampling is not trustworthy, nothing below is.
	[ "$RU_GAP" -le "$RU_STALE_MAX" ] ||
	    fail "during $RU_PHASE the load generator went ${RU_GAP}s without asking one node \
anything, which is longer than the ${RU_STALE_MAX}s window it exists to detect: this \
run cannot tell whether the port kept answering. Was this host or a node saturated?"
	if [ "$RU_FAIL1" = 0 ]; then
		return 0
	fi
	# One pass over the phase's failures: the longest window and how many.
	set -- $(awk -v skip="$RU_MARKF" -v gap="$RU_STALE_GAP" '
		NR <= skip { next }
		{
			node = $2; at = $3 + 0
			if (!(node in last) || at - last[node] > gap) { start[node] = at; windows++ }
			span = at - start[node]
			if (span > worst) worst = span
			last[node] = at
		}
		END { print worst + 0, windows + 0 }' "$RU_LOAD/failures")
	_ru_worst=$1
	_ru_windows=$2
	shift 2 2>/dev/null || true
	[ "$_ru_worst" -le "$RU_STALE_MAX" ] ||
	    fail "during $RU_PHASE, one node answered wrong for ${_ru_worst}s in a row \
($RU_FAIL1 of $RU_TOTAL first attempts failed). A stale redirect is bounded by one \
satld port pass (${RU_STALE_MAX}s at the outside): anything longer is a different \
defect -- read 'published ports converged' on that node and check which task ids \
it lists against the ones the agent has stopped."
	_ru_ceiling=$((RU_STOPS * $(cluster_nodes | countl)))
	[ "$_ru_windows" -le "$_ru_ceiling" ] ||
	    fail "during $RU_PHASE there were $_ru_windows separate windows of failing \
requests but only $RU_STOPS task(s) were stopped; with the cluster-wide pool one \
stop explains at most one window per node ($_ru_ceiling here). Something is making \
a node answer wrong without a task having gone away."
	info "$RU_FAIL1 first attempt(s) failed during $RU_PHASE: $_ru_windows window(s) \
for $RU_STOPS task stop(s), the longest ${_ru_worst}s, within one port pass, every \
request served by the immediate retry. Zero is the expectation since the \
stale-redirect fix (see this function's notes); a bounded non-zero passes, and \
ru_republished says whether a redirect really outlived its container"
}

ru_load_stop() {
	[ -n "${RU_LOAD:-}" ] || return 0
	touch "$RU_LOAD/stop"
	# The generator checks the flag between requests, so this is bounded by one
	# request; `wait` without a bound would hang if the subshell were gone.
	_ru_i=0
	while [ "$_ru_i" -lt 20 ] && kill -0 "$RU_LOAD_PID" 2>/dev/null; do
		sleep 1
		_ru_i=$((_ru_i + 1))
	done
	kill "$RU_LOAD_PID" 2>/dev/null || true
}

# ru_seed_tag <from-tag> <to-tag> — make a second working image on every node's
# registry, by copying the seeded one to another tag.
#
# A tag is all the update needs to be a real one: the spec's image string
# changes, so every task is dirty and must be replaced, while the content is
# byte-identical and the body served is the same before and after — which is
# what lets one load generator span the update and judge every response by the
# same rule. Local to each node's own registry, so no image crosses the network.
ru_seed_tag() {
	for _n in $(cluster_nodes); do
		_ru_tagged=0
		node_sh "$_n" "$REG_PORT" "$REG_NS" "$1" "$2" >/dev/null 2>&1 <<'REMOTE' && _ru_tagged=1
port=$1
ns=$2
from=$3
to=$4
skopeo copy --all --quiet --src-tls-verify=false --dest-tls-verify=false \
    "docker://127.0.0.1:$port/$ns/$from" "docker://127.0.0.1:$port/$ns/$to"
REMOTE
		[ "$_ru_tagged" = 1 ] ||
		    fail "could not tag $REG_NS/$1 as $REG_NS/$2 in $_n's registry"
	done
	info "tagged $REG_NS/$2 on every node (same content as $1)"
}

# ru_cli_update <arg>... — `satl service update <args> $RU` on the control node.
#
# The operator's surface, and the reason the updates below no longer go through
# `curl --unix-socket`. `satl service update` is a read-edit-write of the
# *stored* spec: it reads the service, changes what the flags name, and posts the
# whole thing back. Every field the CLI fails to carry across that round trip is
# a field it silently deletes -- which is why an update naming nothing but
# `--image` is also the assertion that the service's failure action survives it.
# Until the CLI grew the `--update-*`/`--rollback-*` flags it could not express
# `failure_action: rollback` at all, and this scenario had to bypass it.
ru_cli_update() {
	node_sh "$CTL" "$RU" "$@" <<'REMOTE'
svc=$1
shift
satl service update "$@" "$svc"
REMOTE
}

# The *live* spec's rolling-update policy as the API renders it, brace contents
# only: the read-back that makes "the CLI did not reset it" an assertion rather
# than an inference from the rollback having fired.
#
# `PreviousSpec` is cut off first, for the reason ru_spec_image spells out: a
# service that has one contains `"UpdateConfig":{` twice, `sed`'s `.*` is greedy,
# and the second match is the policy of the spec that was updated *away* from --
# which is precisely the value that would make a reset policy look preserved.
ru_update_config() {
	ru_get | sed 's/"PreviousSpec".*//' |
	    sed -n 's/.*"UpdateConfig":{\([^}]*\)}.*/\1/p'
}

# ru_republished <task ids> — every `<node> <task id>` pair where a node put a
# redirect back *after* its own agent had removed it.
#
# The defect measured during the rolling-update proof, read from the daemon's own
# log instead of from the load generator: `running_task_ports` derived the wanted
# set from the store, which lags this node's agent by a round trip through the
# leader, so a periodic port pass firing in the ~150 ms between "the agent
# stopped the container" and "the store was told" re-created the redirect --
# pointing at a container that was gone, for a whole 5 s pass.
#
# This is here because the traffic measurement can only see it when the generator
# happens to ask during that window. Over seven pre-fix runs of this scenario
# four saw failing requests and three saw none, while every one of the four left
# this trace; a probabilistic detector cannot carry an assertion, and this one
# can.
#
# Bounded to the ids of *this* run's tasks: /var/log/messages outlives the run,
# and a pre-fix run's evidence must not fail a post-fix one. Within those ids the
# reading is unambiguous -- an id is unique, a task is one-shot, and its agent
# removes the redirect when the container stops, so a later "converged" naming it
# is the store's stale copy speaking. Every stop in this scenario is one the
# manager ordered (nginx does not exit on its own), which is the case desired
# state settles; a container that exits by itself is a narrower window the store
# alone cannot close, and it is not what this service does.
ru_republished() {
	for _rr_n in $(cluster_nodes); do
		node_root_sh "$_rr_n" "$1" <<'REMOTE' 2>/dev/null | sed "s/^/$_rr_n /"
ids=$1
grep -a satld /var/log/messages 2>/dev/null | awk -v ids="$ids" '
	BEGIN { n = split(ids, a, " "); for (i = 1; i <= n; i++) mine[a[i]] = 1 }
	/published ports removed/ {
		if (match($0, /task_id=[0-9A-Za-z]+/)) {
			id = substr($0, RSTART + 8, RLENGTH - 8)
			if (id in mine) removed[id] = 1
		}
		next
	}
	/published ports converged/ {
		for (id in removed) if (index($0, id) > 0) bad[id] = 1
	}
	END { for (id in bad) print id }
'
REMOTE
	done
}

# ru_watch_rolling — the poll body of the update wait: it samples the property
# that makes an update "rolling" and fails the moment it does not hold.
#
# One slot at a time means at most one of the six is not serving, so five is the
# floor. Sampling is the only way to assert this from outside — and the load
# generator is asserting the consequence continuously in parallel, which is the
# assertion that matters. Failing here rather than returning false is deliberate:
# a violation is not "not converged yet".
ru_watch_rolling() {
	ru_tasks || return 1
	_rwr_serving=$(ru_serving_slots | countl)
	if [ "$_rwr_serving" -lt "$RU_MIN_SERVING" ]; then
		fail "only $_rwr_serving of $RU_REPLICAS slots serving during the update, \
which is fewer than the $RU_MIN_SERVING a parallelism of 1 allows: the update is \
replacing more than one slot at a time"
	fi
	[ "$(ru_state)" = "completed" ]
}

scenario_rolling_update() {
	require_swarm
	build_hostmap
	wait_until "$T_JOIN" "all nodes Ready" \
	    'state_fetch "$CTL" && [ "$(nodes_ready)" = "$(cluster_nodes | countl)" ]'

	ru_seed_tag "$RU_TAG_A" "$RU_TAG_B"
	_ru_a="127.0.0.1:$REG_PORT/$REG_NS/$RU_TAG_A"
	_ru_b="127.0.0.1:$REG_PORT/$REG_NS/$RU_TAG_B"
	_ru_broken="127.0.0.1:$REG_PORT/$REG_NS/$RU_TAG_BROKEN"

	# A previous run of this scenario alone may have left the service behind.
	ru_rm
	wait_until "$T_CLEAN" "no leftover $RU service" '[ -z "$(ru_replicas)" ]'

	# --- the service, six replicas, published --------------------------------
	info "POST /services/create: $RU, $RU_REPLICAS replicas of $RU_TAG_A, -p $RU_PORT:80"
	ru_api "$CTL" POST "/services/create" "$(ru_spec "$_ru_a")" >"$TMPD/rucreate" 2>&1 || true
	grep -q '"ID"' "$TMPD/rucreate" || {
		show "$TMPD/rucreate"
		fail "the API refused the service spec"
	}
	wait_until "$T_CONVERGE" "$RU reaches $RU_REPLICAS/$RU_REPLICAS" \
	    '[ "$(ru_replicas)" = "$RU_REPLICAS/$RU_REPLICAS" ]'
	ru_tasks
	_ru_spread=$(ru_serving_nodes)
	info "spread before the update: $_ru_spread"
	for _n in $(cluster_nodes); do
		printf %s "$_ru_spread" | grep -q "$(host_of "$_n")=" ||
		    fail "$_n runs no task of $RU, so it publishes no port and the load \
generator would count its share of the requests as lost through the routing-mesh \
gap (api-compat 75) rather than through anything this scenario is testing. \
Spread: $_ru_spread"
	done
	[ -z "$(ru_state)" ] ||
	    fail "$RU has an UpdateStatus of '$(ru_state)' before any update: creating \
a service is not an update"

	# Every node answers before a single request is counted, so that a failure
	# below is the update's and not the port's.
	for _n in $(cluster_nodes); do
		RU_NODE=$_n
		wait_until "$T_QUICK" "$_n answers http://$(node_field "$_n" public_ip):$RU_PORT/" \
		    'printf %s "$(curl -s --max-time 5 "http://$(node_field "$RU_NODE" public_ip):$RU_PORT/" 2>/dev/null)" | grep -q "$OVL_BODY"'
	done

	# --- phase 1: the rolling update, under load ----------------------------
	ru_load_start
	_ru_a0=0
	_ru_f0=0
	info "satl service update --image $RU_TAG_B $RU"
	ru_cli_update --image "$_ru_b" >"$TMPD/ruupdate" 2>&1 || {
		show "$TMPD/ruupdate"
		fail "satl service update was refused"
	}

	wait_until "$T_UPDATE" \
	    "the update to complete with at least $RU_MIN_SERVING of $RU_REPLICAS slots serving throughout" \
	    'ru_watch_rolling'

	ru_tasks
	_ru_images=$(ru_live_images | sort -u | tr '\n' ' ' | sed 's/ *$//')
	_ru_count=$(ru_live_images | countl)
	[ "$_ru_count" = "$RU_REPLICAS" ] ||
	    fail "$_ru_count of $RU_REPLICAS tasks serving after the update"
	[ "$_ru_images" = "$_ru_b" ] ||
	    fail "the serving tasks are on '$_ru_images', not on the updated image $_ru_b"
	_ru_slots=$(ru_serving_slots | tr '\n' ' ' | sed 's/ *$//')
	[ "$_ru_slots" = "1 2 3 4 5 6" ] ||
	    fail "the update moved the service to slots '$_ru_slots': a rolling update \
replaces the task in a slot, it does not renumber the replicas"
	info "every slot on $RU_TAG_B, spread $(ru_serving_nodes)"
	_ru_msg=$(ru_message)
	[ "$_ru_msg" = "update completed: $RU_REPLICAS slots updated" ] ||
	    fail "UpdateStatus.Message reads '$_ru_msg'"

	# The update named nothing but --image, so every other field of the policy
	# the service was created with must still be there. This is the assertion
	# phase 2 depends on: it rolls back on its own only if `failure_action` is
	# still `rollback`, and a CLI that posts a partial UpdateConfig resets it to
	# the daemon's default of `pause` -- an automatic rollback silently switched
	# off by an operator changing an image. Read back through the REST API, which
	# is the surface the CLI writes into and the one Docker clients read.
	_ru_policy=$(ru_update_config)
	for _ru_want in '"FailureAction":"rollback"' "\"Monitor\":${RU_MONITOR}000000000" \
	    '"Order":"stop-first"' '"Parallelism":1'; do
		printf %s "$_ru_policy" | grep -qF -- "$_ru_want" ||
		    fail "after 'satl service update --image', the stored UpdateConfig is \
{$_ru_policy} and no longer carries $_ru_want: the CLI sent a partial policy and \
the daemon filled the hole with a default, so this service has lost the rollback \
policy it was created with"
	done
	info "UpdateConfig survived the CLI update: {$_ru_policy}"

	ru_load_report "the rolling update" "$_ru_a0" "$_ru_f0"
	[ "$RU_TOTAL" -ge "$RU_MIN_REQUESTS" ] ||
	    fail "only $RU_TOTAL requests were sent during the update (at least \
$RU_MIN_REQUESTS are needed for 'no request was lost' to mean anything): the load \
generator did not run"
	[ "$RU_LOST" = 0 ] ||
	    fail "$RU_LOST of $RU_TOTAL requests were served by nothing, not even on a \
retry. A rolling update of $RU_REPLICAS replicas over $(cluster_nodes | countl) \
nodes with parallelism 1 must never take the last serving task off a node."
	ru_assert_first_attempts "the rolling update" "$RU_REPLICAS"

	# --- phase 2: an image that cannot start, and the rollback --------------
	# The load generator keeps running: a rollout that fails must not cost a
	# request either, and with stop-first it cannot — a task is stopped only
	# once its replacement is *prepared*, and a replacement whose image is not
	# in the registry never gets there.
	ru_load_mark 2
	_ru_a2=$RU_MARK_2
	_ru_f2=$RU_MARKF_2
	info "satl service update --image $RU_TAG_BROKEN $RU (not in any registry)"
	ru_cli_update --image "$_ru_broken" >"$TMPD/rubroken" 2>&1 || {
		show "$TMPD/rubroken"
		fail "satl service update was refused for the broken image"
	}

	wait_until "$T_UPDATE" "the manager to roll the broken image back on its own" '
		_s=$(ru_state)
		[ "$_s" = "rollback_completed" ] || [ "$_s" = "rollback_paused" ]'
	_ru_state=$(ru_state)
	[ "$_ru_state" = "rollback_completed" ] ||
	    fail "the rollback ended '$_ru_state': the spec it rolled back to is the \
one that was serving a minute ago, so it must not have failed"
	info "UpdateStatus: $_ru_state -- $(ru_message)"

	[ "$(ru_spec_image)" = "$_ru_b" ] ||
	    fail "after the rollback the spec asks for '$(ru_spec_image)', not the \
working image $_ru_b"
	if ru_has_previous; then
		fail "PreviousSpec survived the rollback: nothing must be able to roll \
forward into the broken spec again"
	fi

	wait_until "$T_CONVERGE" "$RU back at $RU_REPLICAS/$RU_REPLICAS on the working image" \
	    'ru_serving_only "$_ru_b" "$RU_REPLICAS"'
	info "serving again: $RU_REPLICAS/$RU_REPLICAS on $RU_TAG_B, spread $(ru_serving_nodes)"

	ru_load_stop
	ru_load_report "the failed rollout and its rollback" "$_ru_a2" "$_ru_f2"
	[ "$RU_TOTAL" -ge "$RU_MIN_REQUESTS" ] ||
	    fail "only $RU_TOTAL requests were sent during the rollback"
	[ "$RU_LOST" = 0 ] ||
	    fail "$RU_LOST of $RU_TOTAL requests were lost during the failed rollout. \
With stop-first, a task is stopped only once its replacement is prepared, and a \
replacement that cannot be pulled is never prepared, so a broken rollout must \
take no serving task away."
	# One stop: with parallelism 1 and a zero failure ratio, the broken rollout
	# takes exactly one slot down before the rollback fires. Two is allowed so
	# that a restart-supervisor replacement being stopped as well is not a flake.
	ru_assert_first_attempts "the failed rollout" 2

	# The ids of every task created so far, banked before phase 3 adds more:
	# `service ps` keeps a bounded history per slot (5 by default), so a slot that
	# churns through three phases can lose its oldest ids -- including the ones the
	# redirect audit below is about.
	_ru_ids_12=$(ru_task_ids)

	# --- phase 3: a paused update, and getting out of it ---------------------
	#
	# The other half of a failure action, and the one an operator meets after a
	# typo: `pause` rather than `rollback`. The update stops with the slot it was
	# replacing down, `UpdateStatus` reads `paused`, and the updater deliberately
	# does nothing more for a paused service (SWK 7.3 step 1) -- so if pushing a
	# corrected spec did not clear that status, the service would be stuck for
	# good and the only way out would be removing and recreating it (api-compat
	# 92). Three CLI updates, in the order an operator would type them:
	#
	#   1. `--update-failure-action pause` -- a policy change and nothing else.
	#      It must not replace a single task: the update configuration is not part
	#      of the task spec, so no task becomes dirty. That is also the assertion
	#      that this flag reaches the daemon at all.
	#   2. `--image <broken>` -- the rollout pauses. `pause` and not a rollback is
	#      the point: it is the state the object gets stuck in.
	#   3. `--image <working>` -- the pause must be gone and the service must come
	#      back to 6/6 on that image.
	#
	# What step 3 deliberately does **not** assert is `UpdateStatus == completed`,
	# and the reason is a race that both outcomes are correct for. The pause leaves
	# one slot empty, and who refills it depends on how far the failed task got: a
	# replacement that died *before* its promotion is terminal at desired `READY`,
	# which the restart supervisor ignores by design, so the updater owns the slot
	# and its rollout ends `completed`; one that was promoted first is terminal at
	# desired `RUNNING`, which is the restart supervisor's own business, and it
	# refills the slot from the *current* spec -- so after step 3 nothing is dirty,
	# the updater correctly does nothing, and `UpdateStatus` stays empty. Measured
	# over eight runs: seven took the updater path (`rolling update started ...
	# dirty=1` then `completed`), one took the supervisor path with an empty status
	# and six healthy replicas. Requiring `completed` failed that run for no defect
	# at all. What matters to an operator is asserted instead: the pause is gone and
	# the service is serving the corrected image.
	#
	# No load generator here. A paused update leaves a slot empty on purpose, and
	# a node with no task of the service does not answer on the port at all
	# (api-compat 75), so counting requests would measure ingress-lite rather than
	# resumability.
	info "satl service update --update-failure-action pause $RU"
	ru_cli_update --update-failure-action pause >"$TMPD/rupause" 2>&1 || {
		show "$TMPD/rupause"
		fail "satl service update --update-failure-action was refused"
	}
	# Waited for rather than read once: $CTL is whichever node answered first, not
	# necessarily the leader, and a follower serves its own applied store (§6.4).
	_ru_want='"FailureAction":"pause"'
	wait_until "$T_QUICK" "the new failure action to be readable" \
	    'printf %s "$(ru_update_config)" | grep -qF -- "$_ru_want"'
	_ru_policy=$(ru_update_config)
	# A policy-only change replaces nothing: the update configuration is not part
	# of the task spec, so no task becomes dirty and the updater has no rollout to
	# start. Read from the same document generation as the policy above, so this
	# is not a race with the write becoming visible.
	[ -z "$(ru_state)" ] ||
	    fail "changing the failure action started a rollout ('$(ru_state)'): the \
update configuration is not part of the task spec, so no task is dirty and the \
service's own status should have stayed cleared"
	ru_serving_only "$_ru_b" "$RU_REPLICAS" ||
	    fail "changing the failure action disturbed the running tasks"
	info "policy changed with no rollout: {$_ru_policy}"

	info "satl service update --image $RU_TAG_BROKEN $RU (expecting a pause)"
	ru_cli_update --image "$_ru_broken" >"$TMPD/rubroken2" 2>&1 || {
		show "$TMPD/rubroken2"
		fail "satl service update was refused for the broken image"
	}
	wait_until "$T_UPDATE" "the update to pause on the broken image" \
	    '[ "$(ru_state)" = "paused" ]'
	info "UpdateStatus: paused -- $(ru_message)"

	info "satl service update --image $RU_TAG_B $RU (the corrected spec)"
	ru_cli_update --image "$_ru_b" >"$TMPD/rufixed" 2>&1 || {
		show "$TMPD/rufixed"
		fail "satl service update was refused for the corrected image"
	}
	# First and separately: the pause must be gone. Its own wait, so a control API
	# that left UpdateStatus alone fails *here* -- naming the defect -- instead of
	# timing out on the convergence below with the reason an indirection away.
	wait_until "$T_QUICK" \
	    "the corrected spec to clear the pause (a stuck 'paused' is api-compat 92)" \
	    '[ "$(ru_state)" != "paused" ]'
	# Then convergence, and no *new* pause on the way: an `UpdateStatus` of
	# `completed` or of nothing at all are both correct here (see the note above),
	# so what is waited for is the service, not the status.
	wait_until "$T_UPDATE" \
	    "$RU back at $RU_REPLICAS/$RU_REPLICAS on $RU_TAG_B, without pausing again" '
		[ "$(ru_state)" != "paused" ] ||
		    fail "the resumed rollout paused again on the working image"
		ru_serving_only "$_ru_b" "$RU_REPLICAS"'
	info "the pause is gone and the service converged: UpdateStatus \
'$(ru_state)' -- $(ru_message), spread $(ru_serving_nodes)"

	# --- the redirect a stopped task must not keep ---------------------------
	# Deterministic where the traffic counters are probabilistic (ru_republished).
	# Read now, while every task of this run still exists in `service ps`.
	RU_IDS=$(printf '%s\n%s\n' "$_ru_ids_12" "$(ru_task_ids)" |
	    grep -v '^$' | sort -u | tr '\n' ' ')
	_ru_stale=$(ru_republished "$RU_IDS")
	[ -z "$_ru_stale" ] || {
		printf '%s\n' "$_ru_stale" | sed 's/^/      /'
		fail "the node(s) above put a task's published-port redirect back after \
their own agent had removed it, so the port pointed at a container that was gone \
until the next pass. running_task_ports must not publish a task whose desired \
state has reached SHUTDOWN (crates/satld/src/reconcile.rs)."
	}
	info "no node re-published a stopped task's redirect, over $(printf %s "$RU_IDS" | wc -w | tr -d ' ') tasks"

	# --- the daemon's own account of it -------------------------------------
	# The CLI shows the outcome; the log shows the decision (CLAUDE.md). Read
	# with grep -a: one non-ASCII byte would make grep call the whole file
	# binary and print nothing, which looks exactly like a silent daemon.
	state_fetch "$CTL"
	_ru_leader=$(node_of_host "$(leader_host)")
	[ -n "$_ru_leader" ] || fail "cannot tell which node is the leader"
	_ru_lines=$(ru_log_count "$_ru_leader" "rolling back to the previous spec")
	[ "$_ru_lines" -ge 1 ] ||
	    fail "the leader ($_ru_leader) rolled the service back but its log does not \
say so; an operator has nothing to read"
	info "$_ru_leader logged the rollback decision ($_ru_lines line(s))"
	ru_log_tail "$_ru_leader" "rolling update|rolling back|updating slot" 12

	# --- teardown ------------------------------------------------------------
	# Audited per *task* rather than with the suite-wide `leftovers_gone`: this
	# scenario runs after the ones that leave `$SERVICE` behind for `cleanup` to
	# remove, so a cluster-wide "nothing anywhere" assertion here can never hold
	# and would only measure the running order. Per task is also the stronger
	# statement — three phases create and destroy well over a dozen containers, and
	# every one of them has to leave, not just the last six. `RU_IDS` is the union
	# banked above, which is wider than a single `service ps` after the history
	# retention has pruned the earliest tasks of a churned slot.
	_ru_n=$(printf %s "$RU_IDS" | wc -w | tr -d ' ')
	info "auditing the $_ru_n tasks this scenario created, on every node"
	ru_rm
	wait_until "$T_CLEAN" "$RU removed, and none of its $_ru_n tasks left a jail, epair, dataset or mount" \
	    '[ -z "$(ru_replicas)" ] && [ "$(ru_leftovers "$RU_IDS")" = 0 ]'
	info "every jail, epair, dataset and mount of every task of $RU is gone from every node"
}

# ru_log_count <node> <pattern> — how many satld log lines match, counted with
# awk so that "none" is a value and not a failing exit status.
ru_log_count() {
	node_root_sh "$1" "$2" <<'REMOTE' 2>/dev/null
pattern=$1
grep -a satld /var/log/messages 2>/dev/null |
    awk -v p="$pattern" '$0 ~ p { n++ } END { print n + 0 }'
REMOTE
}

# ru_log_tail <node> <extended-pattern> <lines> — the last matching log lines,
# indented, as the evidence a reader of the run output wants.
ru_log_tail() {
	node_root_sh "$1" "$2" "$3" <<'REMOTE' 2>/dev/null | sed 's/^/      /'
pattern=$1
lines=$2
grep -a satld /var/log/messages 2>/dev/null |
    grep -aE -- "$pattern" | tail -n "$lines"
REMOTE
}

# ===========================================================================
# Scenarios 10-14 — the live proof of fb5190a: global services, drain, the
# constraint enforcer, and a restart budget that survives an election.
#
# fb5190a shipped with store-backed tests only. These five scenarios are what
# makes it true on three real nodes, and the shape of every assertion below
# comes from a decision that commit argues for — each of them has a weaker form
# that would pass while proving something else:
#
#   - a global service's footprint is *one preassigned task per node*. Three
#     tasks on three nodes is also exactly what `--replicas 3` produces, so
#     counting them proves nothing. What is asserted instead is slot **0**, the
#     node ID standing in for the slot number in the task's name (SWK §4.5),
#     and — in the daemon's log — the scheduler *confirming* a node it was
#     handed rather than choosing one (SWK §8.6);
#   - a drain forces the restart delay to **zero** (SWK §7.4), which is why the
#     replicated service the drain moves is created with a deliberately long
#     one. Without a delay that would otherwise be paid, "the drain was fast"
#     is not a measurement: nothing would have made it slow;
#   - a constraint change is **not** a drain — a label edit is nobody waiting
#     on a node — so it pays that delay in full, asserted from the same log
#     field. And the second half of `constraint_enforcer` is the real test: an
#     enforcer that evicts correctly but re-evaluates carelessly flaps, so a
#     *further* label write must move nothing at all;
#   - the restart budget is derived from the store on every pass, so no leader
#     needs to hand it over. That is asserted across a genuine election: the
#     leader's satld is killed with attempts still on the clock, and the new
#     leader must allow exactly the ones that were left and then stop. Under
#     the pre-fb5190a in-memory history it would have restarted forever.
#
# Quorum: three managers tolerate losing one. `global_node_loss` and
# `restart_budget` each take one daemon away, never two, and each puts it back
# before it returns — `cleanup` and the rest of the suite expect three managers.
#
# Each of these scenarios removes the suite's shared `$SERVICE` first. They
# count containers on a node and audit what a task left behind, and both
# readings are only about *this* scenario if nothing else of the suite is
# running; `ensure_service` rebuilds `web` for whoever needs it next.
# ===========================================================================

# --- reading the tasks of any service --------------------------------------
#
# The same `satl service ps` table the rest of the suite reads, sliced by header
# rather than by whitespace (tcols), but for an arbitrary service and with
# **full task IDs**: these scenarios name individual tasks in the daemon's log
# and in the REST API, and a truncated ID cannot be matched against either.

# tasks_fetch <service> — capture the service's task table from $CTL. Non-zero
# when the manager cannot answer or the table has no data row, which is what
# makes it usable both inside a poll body and as "the service has no tasks left".
#
# The row count and not the exit status: `satl service ps <unknown service>`
# prints an empty table and exits **0** (the CLI asks for tasks filtered by
# service name and an unknown name simply matches none), so a missing service and
# a service whose tasks are all gone are the same observation here — which is
# exactly what svc_rm_audited waits for.
tasks_fetch() {
	node_ssh "$CTL" "satl service ps $1 --no-trunc 2>/dev/null" \
	    >"$TMPD/ptasks" 2>/dev/null || return 1
	[ -s "$TMPD/ptasks" ] || return 1
	[ "$(tasks_rows)" -gt 0 ]
}

# The *live* tasks: desired Running and observed Running — the suite's own
# definition (see live_tasks for why both halves are needed). One line of
# "<task id> <hostname>".
tasks_live() {
	tcols "$TMPD/ptasks" 'ID,NODE,DESIRED STATE,CURRENT STATE' |
	    awk -F'\t' '$3 == "Running" && $4 ~ /^Running/ { print $1, $2 }'
}
tasks_live_total()  { tasks_live | countl; }
tasks_live_on()     { tasks_live | awk -v h="$1" '$2 == h { n++ } END { print n + 0 }'; }
tasks_live_ids_on() { tasks_live | awk -v h="$1" '$2 == h { print $1 }'; }
tasks_live_spread() {
	tasks_live | awk '{ c[$2]++ } END { for (k in c) print c[k] }' |
	    sort -n | tr '\n' ' ' | sed 's/ *$//'
}
# The distinct images the live tasks run, space separated: one value means the
# whole service is on one image, which is what the end of an update looks like.
tasks_live_images() {
	tcols "$TMPD/ptasks" 'IMAGE,DESIRED STATE,CURRENT STATE' |
	    awk -F'\t' '$2 == "Running" && $3 ~ /^Running/ { print $1 }' |
	    sort -u | tr '\n' ' ' | sed 's/ *$//'
}

# The tasks the cluster still *wants*: desired Running, whatever they are
# observed doing. This is the set every "and nothing was created anywhere else"
# assertion below is about — a replacement that exists but has not started yet
# is still a replacement, and a task that was shut down is not one. It is also
# the occupancy question fb5190a's global loop asks (`desired_state <= RUNNING`).
tasks_wanted() {
	tcols "$TMPD/ptasks" 'ID,NODE,DESIRED STATE' |
	    awk -F'\t' '$3 == "Running" { print $1, $2 }'
}
tasks_wanted_total() { tasks_wanted | countl; }
tasks_wanted_on()    { tasks_wanted | awk -v h="$1" '$2 == h { n++ } END { print n + 0 }'; }

# Every task the service has, live and historic: "<id> <host> <desired> <current>".
tasks_all()  { tcols "$TMPD/ptasks" 'ID,NODE,DESIRED STATE,CURRENT STATE' | tr '\t' ' '; }
tasks_rows() { tcols "$TMPD/ptasks" ID | countl; }
tasks_desired_of() {
	tcols "$TMPD/ptasks" 'ID,DESIRED STATE' |
	    awk -F'\t' -v t="$1" '$1 == t { print tolower($2) }'
}
# The one task a bounded restart policy gave up on: terminal, and still desired
# Running because nothing will replace it (the shape crate::update's
# `abandoned()` recognises, and the shape a spent budget leaves behind).
tasks_abandoned() {
	tasks_all | awk '$3 == "Running" && $4 ~ /^(Failed|Complete|Shutdown|Rejected)/ { print $1 }'
}

# tasks_complete_n / tasks_running_n — row counts by CURRENT STATE's first
# word ("Complete 4 seconds ago" reads as Complete) over the last tasks_fetch.
# A job that ran to completion is exactly this: every row Complete, none
# Running, and — held over time — no new rows.
tasks_complete_n() { tasks_all | awk '$4 == "Complete"' | countl; }
tasks_running_n()  { tasks_all | awk '$4 == "Running"' | countl; }

# --- node IDs, and the availability the scenarios depend on ----------------

# build_nodeids — "<node id> <hostname>" per node, from `satl node ls`, whose ID
# column is *not* truncated (unlike `service ps`'s). A global task's name
# carries the node ID rather than a slot number (SWK §4.5), so an assertion
# about that name needs the ID the store uses, and the local node's cell carries
# docker's ` *` marker, which is stripped here rather than in three callers.
NODEIDS="$TMPD/nodeids"

build_nodeids() {
	node_ssh "$CTL" "satl node ls" >"$TMPD/nodels" 2>/dev/null ||
	    fail "cannot read node ls from $CTL"
	tcols "$TMPD/nodels" 'ID,HOSTNAME' |
	    awk -F'\t' '{ sub(/ \*$/, "", $1); print $1, $2 }' >"$NODEIDS"
	_bn=$(countl <"$NODEIDS")
	[ "$_bn" = "$(cluster_nodes | countl)" ] ||
	    fail "node ls lists $_bn node(s), not $(cluster_nodes | countl)"
	awk '{ if (length($1) < 20) exit 1 }' "$NODEIDS" ||
	    fail "node ls truncated the ID column; a global task's name cannot be checked against it"
}

node_id_of() { awk -v h="$1" '$2 == h { print $1 }' "$NODEIDS"; }

# nodes_activate — every node Active before a scenario reads placement decisions.
#
# A run that failed between a drain and the `--availability active` that undoes
# it leaves a node drained, and every later scenario would then be testing a
# two-node cluster while looking like it tests three. Repaired rather than
# reported, exactly as ensure_daemons repairs a stopped satld.
nodes_activate() {
	state_fetch "$CTL" || fail "$CTL cannot answer node ls"
	_na=$(tcols "$TMPD/nodes" 'HOSTNAME,AVAILABILITY' | awk -F'\t' '$2 != "Active" { print $1 }')
	[ -n "$_na" ] || return 0
	for _nah in $_na; do
		info "$_nah is not Active — putting it back (a previous run left it drained or paused)"
		node_ssh "$CTL" "satl node update --availability active $_nah" >/dev/null 2>&1 || true
	done
	wait_until "$T_QUICK" "every node Active again" 'nodes_all_active'
}

nodes_all_active() {
	state_fetch "$CTL" || return 1
	[ "$(nodes_ready)" = "$(cluster_nodes | countl)" ] || return 1
	_naa=$(tcols "$TMPD/nodes" AVAILABILITY | awk '$0 != "Active" { n++ } END { print n + 0 }')
	[ "$_naa" = 0 ]
}

# --- asserting that nothing happened ---------------------------------------

# hold_for <seconds> <what> <shell test> — wait_until's opposite: the condition
# must hold at *every* poll for <seconds>, and the first poll that does not is a
# failure naming how long it lasted.
#
# Three of the assertions below are of this kind, and each of them is the actual
# content of a decision in fb5190a: a global task the cluster gave up must gain
# no replacement *anywhere*, a second label write must move nothing, and a spent
# restart budget must not hand itself back. "It did not happen" can only be
# asserted by looking for a while — long enough to cover several of the
# orchestrator's own passes, since what is asserted is that those passes decide
# nothing.
hold_for() {
	_hf_limit=$1
	_hf_what=$2
	_hf_cond=$3
	_hf_t0=$(date +%s)
	printf '  %-58s' "hold: $_hf_what"
	while :; do
		if ! eval "$_hf_cond"; then
			printf ' BROKE after %ss\n' "$(($(date +%s) - _hf_t0))"
			fail "after $(($(date +%s) - _hf_t0))s this stopped holding: $_hf_what"
		fi
		[ "$(($(date +%s) - _hf_t0))" -ge "$_hf_limit" ] && break
		printf '.'
		sleep "$POLL"
	done
	printf ' ok %ss\n' "$(($(date +%s) - _hf_t0))"
}

# --- what the daemon said --------------------------------------------------

# log_hits_on <node> <needle> [needle] [needle] — satld log lines on that node
# containing *all* the given fixed strings, counted.
#
# `grep -a` is not optional: one non-ASCII byte anywhere in /var/log/messages
# makes grep call the whole file binary and print nothing, which reads exactly
# like a silent daemon (CLAUDE.md). Counted with awk, so "none" is a value and
# not a failing exit status (see ovl_count).
#
# **The rotated files are read too**, oldest first, and that is not belt and
# braces: newsyslog rotates /var/log/messages about once an hour on these VMs —
# measured, and it bites: a daemon 80 minutes old already had its `starting
# satld` line in `messages.0.bz2`, and `leader_nodes` below found no leader at
# all until this reader was used. A rotation landing between a decision and the
# assertion about it would otherwise read as a daemon that never said anything.
# Old runs' lines come along with it, which is harmless: every caller pins a
# needle to a task ID of *this* run, and a task ID is unique.
log_hits_on() {
	_lho_n=$1
	shift
	node_root_sh "$_lho_n" "$1" "${2:-}" "${3:-}" <<'REMOTE' 2>/dev/null || echo 0
{ for f in $(ls -tr /var/log/messages.*.bz2 2>/dev/null); do bzcat "$f"; done
  cat /var/log/messages; } 2>/dev/null | grep -a satld |
    awk -v a="$1" -v b="$2" -v c="$3" '
	index($0, a) > 0 &&
	(b == "" || index($0, b) > 0) &&
	(c == "" || index($0, c) > 0) { n++ }
	END { print n + 0 }'
REMOTE
}

# log_hits <needle> [needle] [needle] — the same, summed over every node.
#
# Summed, because the decisions asserted here are taken by whichever node holds
# leadership and this suite deliberately does not trust MANAGER STATUS to say
# which one that is (README, the M2 gap). Every caller pins one needle to a task
# ID of this run: /var/log/messages outlives the run, a task ID is unique and a
# task is one-shot, so a hit can only be about the decision under test.
log_hits() {
	_lh_total=0
	for _lh in $(cluster_nodes); do
		_lh_n=$(log_hits_on "$_lh" "$1" "${2:-}" "${3:-}")
		_lh_total=$((_lh_total + _lh_n))
	done
	echo "$_lh_total"
}

# log_evidence <needle> [needle] — print the last few matching lines from every
# node, indented and prefixed with the node, as the evidence a reader of the run
# output wants. Never asserts anything; the assertions are log_hits above. Reads
# the rotated files for the same reason (see log_hits_on), so a line or two from
# an earlier run can show up here — the syslog prefix is stripped and the
# daemon's own timestamp left in place, which is what tells them apart.
log_evidence() {
	for _le in $(cluster_nodes); do
		node_root_sh "$_le" "$1" "${2:-}" <<'REMOTE' 2>/dev/null | sed "s/^/      $_le /" || true
{ for f in $(ls -tr /var/log/messages.*.bz2 2>/dev/null); do bzcat "$f"; done
  cat /var/log/messages; } 2>/dev/null | grep -a satld |
    awk -v a="$1" -v b="$2" '
	index($0, a) > 0 && (b == "" || index($0, b) > 0) { print }' |
    tail -4 |
    sed 's/^[A-Z][a-z][a-z] [ 0-9][0-9] [0-9:]* [^ ]* satld\[[0-9]*\]: //'
REMOTE
	done
}

# leader_nodes — the inventory names of every *running* satld that currently
# believes it holds raft leadership, read from its own log.
#
# Not from `satl node ls`: MANAGER STATUS is written when the cluster forms and
# never refreshed on a leadership change (README, the M2 gap), so after
# `leader_kill` it names a node that is not the leader — and `restart_budget`
# has to kill the real one or there is no election to speak of.
#
# Bounded to the current daemon instance, which is what the "starting satld"
# reset is for: these lines outlive a restart, so a node that *was* leader
# before it was killed still carries its "leadership gained". A node whose satld
# is not running is not a candidate at all, however its log ends — which is also
# what keeps the node this scenario has just killed from being reported as the
# leader it was a second ago.
#
# The rotated logs are part of the answer, not an optimisation: a daemon that
# gained leadership two hours ago has both its `starting satld` and its
# `leadership gained` in `messages.*.bz2`, and reading only the current file
# reports *no* leader anywhere (measured on all three nodes before this).
leader_nodes() {
	for _ln in $(cluster_nodes); do
		_lnv=$(node_root_sh "$_ln" <<'REMOTE' 2>/dev/null || true
pgrep -qx satld || { echo down; exit 0; }
{ for f in $(ls -tr /var/log/messages.*.bz2 2>/dev/null); do bzcat "$f"; done
  cat /var/log/messages; } 2>/dev/null | grep -a satld |
    awk '/starting satld/ { last = "" }
         /leadership gained: starting the leader-only components/ { last = "leader" }
         /leadership lost: stopping the leader-only components/ { last = "follower" }
         /shutting down the leader-only components/ { last = "" }
         END { print last }'
REMOTE
		)
		if [ "$_lnv" = leader ]; then echo "$_ln"; fi
	done
	return 0
}

# the_leader — the one node whose satld holds leadership, or a loud failure.
the_leader() {
	_tl=$(leader_nodes | tr '\n' ' ' | sed 's/ *$//')
	[ -n "$_tl" ] || fail "no running satld reports holding raft leadership \
(grep 'leadership gained' in /var/log/messages on each node)"
	case $_tl in
	*" "*) fail "two nodes report holding raft leadership at once ($_tl)" ;;
	esac
	echo "$_tl"
}

# A running manager that is NOT the leader, excluding any node named as an
# argument. Empty when there is none.
#
# The generalisation of the loop ca_rotate already wrote correctly for its
# rejoin target: leadership comes from the daemons' own logs (`the_leader`),
# never from `satl node ls`'s MANAGER STATUS column, which is written at
# cluster formation and never refreshed on a leadership change. A scenario that
# picks "a follower" from that column can hand itself the real leader.
a_follower() {
	_af_leader=$(the_leader)
	for _af_n in $(cluster_nodes); do
		[ "$_af_n" = "$_af_leader" ] && continue
		for _af_x in "$@"; do
			[ "$_af_n" = "$_af_x" ] && continue 2
		done
		echo "$_af_n"
		return 0
	done
	return 0
}

# Fails unless <node> is the current raft leader.
assert_leader() {
	_al_have=$(the_leader)
	[ "$_al_have" = "$1" ] ||
	    fail "expected $1 to be the raft leader, but $_al_have is"
}

# Fails if <node> is the current raft leader.
assert_not_leader() {
	_anl_have=$(the_leader)
	[ "$_anl_have" != "$1" ] ||
	    fail "expected $1 NOT to be the raft leader, but it is"
}

# Moves raft leadership onto <node>, or fails.
#
# **This is a random walk, not a command.** Stopping the leader leaves two
# voters and either may win, so each round has roughly even odds and the cap
# below is a probability, not a guarantee -- 4 rounds failed a real run
# (~6% of the time), which is why it is 8 here (~99.6%). Raft has no "make this
# node lead" operation, and openraft's transfer, which SatL does now use for
# demotion, hands leadership to the most caught-up voter rather than a chosen
# one.
#
# So prefer NOT needing it. A scenario that wants "the hard case" should ask
# `the_leader` who leads and act on that node, which is deterministic and
# costs nothing; `demote_leader` does exactly that. This helper is for the
# suite-level `--leader` option, where the point *is* to start two runs from
# different leaders and see whether the verdict changes.
#
# `satl node demote` is not the mechanism: it removes the node from consensus
# rather than moving leadership within it.
require_leader() {
	_rl_want=$1
	_rl_round=0
	while [ "$(the_leader)" != "$_rl_want" ]; do
		_rl_round=$((_rl_round + 1))
		[ "$_rl_round" -le 8 ] ||
		    fail "could not move raft leadership onto $_rl_want after 8 rounds \
(leader is $(the_leader)); this is a random walk, so a run of bad luck is possible -- \
re-run, and see require_leader's comment"
		_rl_cur=$(the_leader)
		info "moving leadership off $(host_of "$_rl_cur") to reach $(host_of "$_rl_want")"
		node_satld "$_rl_cur" stop
		wait_until "$T_ELECT" "a survivor gained leadership" \
		    '[ -n "$(leader_nodes)" ]'
		node_satld "$_rl_cur" start
		wait_until "$T_JOIN" "$(host_of "$_rl_cur") back and the cluster agreed" \
		    'membership_agreed'
	done
	info "raft leadership is on $(host_of "$_rl_want")"
}

# Redirect rules for <port> in this node's satl/rdr anchor.
#
# Generalised off $PUB_PORT so scenarios other than publish_port can assert pf.
# stderr is dropped on purpose: an anchor that was never loaded prints
# `DIOCGETRULES: Invalid argument` and still exits 0, so "no anchor" and "empty
# anchor" read the same -- which is what absence means here.
rdr_count() {
	node_ssh "$1" "sudo pfctl -a satl/rdr -s nat 2>/dev/null" |
	    awk -v p="$2" '/^rdr/ && $0 ~ ("port = " p) {n++} END {print n+0}'
}

# --- creating and removing the services these scenarios need ---------------

# api_create <spec json> — POST /services/create on $CTL (ru_api: one API helper
# for the suite), failing loudly with what the daemon answered.
#
# The REST API rather than `satl service create` for three of the four services
# below, and for one reason: the CLI has no `--restart-delay`,
# `--restart-max-attempts` or `--restart-window` flag — `--restart-condition` is
# the only restart flag it carries — and every one of those services is *about*
# the restart policy. That is a CLI gap against docker (reported, not worked
# around); the global service, which needs no restart policy, is created through
# the CLI exactly as an operator would.
api_create() {
	ru_api "$CTL" POST "/services/create" "$1" >"$TMPD/apicreate" 2>&1 || true
	grep -q '"ID"' "$TMPD/apicreate" || {
		show "$TMPD/apicreate"
		fail "the API refused a service spec: $1"
	}
}

# svc_json / svc_state / svc_message <service> — the service as the REST API
# renders it, and the two `UpdateStatus` fields the update scenario asserts.
# Compact JSON from the API (the pretty-printer is the CLI's), so a field is a
# `sed` away and no JSON parser has to be shipped to the nodes.
svc_json()    { ru_api "$CTL" GET "/services/$1" 2>/dev/null; }
svc_state()   { svc_json "$1" | sed -n 's/.*"UpdateStatus":{"State":"\([a-z_]*\)".*/\1/p'; }
svc_message() { svc_json "$1" | sed -n 's/.*"UpdateStatus":{[^}]*"Message":"\([^"]*\)".*/\1/p'; }

# task_field <task id> <field> — one top-level field of a task, from
# `GET /tasks/<id>`.
#
# By document order, not by a greedy `sed`: the renderer writes the task's own
# fields before any nested object, and `.*"Name":"..."` would return a network
# attachment's name instead (the same trap ru_spec_image documents).
task_field() {
	ru_api "$CTL" GET "/tasks/$1" 2>/dev/null | tr '{,' '\n\n' |
	    sed -n "s/^\"$2\":\"\{0,1\}\([^\",}]*\).*/\1/p" | head -1
}

# svc_rm_audited <service> — remove a service and wait until every task it ever
# had has left the hosts: no jail, no epair, no container dataset named after it.
#
# Per task (ru_leftovers) rather than cluster-wide (leftovers_gone), because a
# task ID *is* the jail name, the dataset name and the epair description, so the
# audit can name what it is looking for — and because these scenarios can run
# next to services the rest of the suite left behind.
svc_rm_audited() {
	SRA_SVC=$1
	SRA_IDS=""
	if tasks_fetch "$1"; then
		SRA_IDS=$(node_ssh "$CTL" "satl service ps $1 --quiet --no-trunc 2>/dev/null" |
		    tr -d '\r' | tr '\n' ' ')
	fi
	node_ssh "$CTL" "satl service rm $1 >/dev/null 2>&1" || true
	wait_until "$T_CLEAN" "$1 removed, and none of its tasks left a jail, epair, dataset or mount" \
	    '! tasks_fetch "$SRA_SVC" && [ "$(ru_leftovers "$SRA_IDS")" = 0 ]'
}

# gs_create <image> — a fresh global service, through the CLI.
#
# Always fresh, never reused: the *creation decision* is part of what is
# asserted (the global loop's own log lines), and a service that was already
# there took that decision in some earlier run.
gs_create() {
	# Unconditional: a service with no tasks left still owns its name, and
	# svc_rm_audited is a no-op wait when there is nothing to remove.
	svc_rm_audited "$GS"
	info "satl service create --name $GS --mode global $1"
	node_ssh "$CTL" "satl service create --name $GS --mode global $1" \
	    >"$TMPD/gscreate" 2>&1 || {
		show "$TMPD/gscreate"
		fail "satl service create --mode global failed on $CTL"
	}
	wait_until "$T_CONVERGE" "$GS running exactly one task on each of the $GS_NODES nodes" \
	    'tasks_fetch "$GS" && [ "$(tasks_live_total)" = "$GS_NODES" ] &&
	     [ "$(tasks_live_spread)" = "$GS_EACH" ]'
}

# gs_task_shape <service> <task id> <hostname> — the three facts that make a
# task a *global* service's task rather than one replica of a replicated one.
#
# This is the assertion the footprint count cannot make: three tasks spread one
# per node over three nodes is exactly what `--replicas 3` produces, and every
# count in this file would read the same. Read from the REST API because the
# CLI's NAME cell drops the task-ID suffix that is half the point.
#
#   - **slot 0**: a global service has no slot numbering; the node is the
#     replica identity (SWK §4.5), and slot 0 is the marker the whole of
#     fb5190a keys on (crate::task::is_global_task, SlotTuple, the reaper's
#     pruning key);
#   - **the name is `<service>.<node id>.<task id>`** — the node ID standing
#     where a replicated service puts its slot number, which is what "the node
#     is the replica" looks like from outside;
#   - **it is bound to that node**, so the name is not merely well-formed.
gs_task_shape() {
	_gts_want=$(node_id_of "$3")
	[ -n "$_gts_want" ] || fail "no node id known for host $3 (build_nodeids)"
	_gts_slot=$(task_field "$2" Slot)
	_gts_name=$(task_field "$2" Name)
	_gts_node=$(task_field "$2" NodeID)
	[ "$_gts_slot" = 0 ] ||
	    fail "task $2 of the global service $1 is in slot '$_gts_slot', not slot 0: a \
global service has no slots, and slot 0 is what marks its tasks as one-per-node \
(SWK §4.5). A non-zero slot means this service is being reconciled as a \
replicated one"
	[ "$_gts_node" = "$_gts_want" ] ||
	    fail "task $2 runs on $3 but is bound to node '$_gts_node', not to \
$_gts_want: a global task's node is its identity and cannot be somebody else's"
	[ "$_gts_name" = "$1.$_gts_want.$2" ] ||
	    fail "task $2 is named '$_gts_name' and not '$1.$_gts_want.$2': a global \
task carries the node ID where a replicated one carries its slot number \
(SWK §4.5). A slot number here would mean the tasks were numbered rather than \
placed per node"
}

# gs_map — "<node> <hostname> <task id>" for the one live task of $GS on every
# node, and a failure if any node holds a number other than one. Written to a
# file so the assertions can loop over it more than once.
GSMAP="$TMPD/gsmap"

gs_map() {
	: >"$GSMAP"
	tasks_fetch "$GS" || fail "$CTL cannot list the tasks of $GS"
	for _gm in $(cluster_nodes); do
		_gmh=$(host_of "$_gm")
		_gmt=$(tasks_live_ids_on "$_gmh" | tr '\n' ' ' | sed 's/ *$//')
		case $_gmt in
		"") fail "$GS has no live task on $_gm ($_gmh): a global service runs one per node" ;;
		*" "*) fail "$GS has more than one live task on $_gm ($_gmh): $_gmt" ;;
		esac
		printf '%s %s %s\n' "$_gm" "$_gmh" "$_gmt" >>"$GSMAP"
	done
}

# m4_prelude — what all five scenarios need before they can assert anything: a
# formed swarm, the hostname and node-ID maps, every node Active, and none of
# the suite's shared `$SERVICE` left running.
#
# `$SERVICE` goes because these scenarios count containers on a node and audit
# what a task left behind, and both readings are only about the scenario at hand
# if nothing else of the suite is running. `ensure_service` rebuilds `web` for
# whoever needs it next, so removing it here costs a later scenario one create.
m4_prelude() {
	require_swarm
	build_hostmap
	build_nodeids
	nodes_activate
	GS_NODES=$(cluster_nodes | countl)
	GS_EACH=$(even_spread "$GS_NODES")
	if service_present; then
		info "removing the suite's shared $SERVICE first (these scenarios count containers per node)"
		service_rm
	fi
}

# drs_spec <image> — the replicated service a drain moves.
#
# Everything about it is the restart delay: DRS_DELAY seconds, unlimited
# attempts (the budget is another scenario's subject), no published port (pf is
# not what this measures). Through the REST API because the CLI cannot express a
# restart delay at all (api_create).
drs_spec() {
	cat <<JSON | tr -d '\n\t'
{
	"Name": "$DRS",
	"TaskTemplate": {
		"ContainerSpec": {"Image": "$1"},
		"RestartPolicy": {"Condition": "any", "Delay": ${DRS_DELAY}000000000, "MaxAttempts": 0}
	},
	"Mode": {"Replicated": {"Replicas": $DRS_REPLICAS}}
}
JSON
}

# ===========================================================================
# Scenario 10 — global_service
#
# Parts 1 to 3 of fb5190a's own scenario: the footprint of a global service, a
# drain measured against a restart delay long enough to make slowness the
# default, and what comes back when the node does.
#
#   1. `--mode global` puts exactly one task on every node, all Running, **slot
#      0**, each named `<service>.<node id>.<task id>` — and the daemon's log
#      shows the global loop creating one task per node with distinct `node_id`
#      while the *scheduler* only **confirms** the node it was handed. That last
#      distinction is what proves the tasks were preassigned (SWK §8.6): every
#      count in this file reads the same for `--replicas 3`.
#   2. A drain of one node, with a 6-replica service alongside whose restart
#      delay is DRS_DELAY seconds. The drained node's global task goes desired
#      `shutdown` with **no replacement anywhere** — a global task has no
#      elsewhere, its node is its identity — while the replicated tasks are
#      replaced on the survivors, its containers really are gone (`jls`), and
#      the whole thing takes **seconds, not minutes**: SWK §7.4 forces the
#      restart delay to 0 for a drain, and the log is asserted to say
#      `delay_ms=0` with the draining trigger. That is why the long delay
#      exists; without it the measurement would be vacuous.
#   3. `--availability active` gives the node its global task back — a *new*
#      task (a task is one-shot, architecture §4 rule 4) with the same
#      node-derived shape. The replicated service is **not** rebalanced back,
#      and that is asserted as the expected behaviour rather than hoped
#      against: SatL has no rebalancer, so its tasks stay where the drain put
#      them until something else moves them.
# ===========================================================================
scenario_global_service() {
	m4_prelude

	# --- 1. the footprint ---------------------------------------------------
	gs_create "$IMAGE"
	gs_map
	while read -r _gsn _gsh _gst; do
		gs_task_shape "$GS" "$_gst" "$_gsh"
	done <"$GSMAP"
	info "$GS: one live task per node, each in slot 0 and named $GS.<node id>.<task id>"

	while read -r _gsn _gsh _gst; do
		_gsi=$(node_id_of "$_gsh")
		[ "$(log_hits "creating a global task for a node that has none" \
		    "task_id=$_gst" "node_id=$_gsi")" -ge 1 ] ||
		    fail "nothing in any node's log says the global loop created task \
$_gst for node $_gsi ($_gsh). One task per node is the *outcome*; this line is \
the decision, and without it the tasks could have come from anywhere"
		[ "$(log_hits "scheduler confirmed task can run on preassigned node" \
		    "task_id=$_gst")" -ge 1 ] ||
		    fail "the scheduler never confirmed $_gst on a preassigned node"
		[ "$(log_hits "scheduler assigned task to node" "task_id=$_gst")" = 0 ] ||
		    fail "the scheduler *assigned* $_gst to a node it chose itself. A global \
service's tasks are created already bound to their node and the scheduler only \
validates them (SWK §8.6, 'scheduler confirmed task can run on preassigned \
node'); a service whose tasks were scheduled instead would still show one task \
per node here, which is why this is the assertion that tells them apart"
	done <"$GSMAP"
	info "the global loop created a task per node with distinct node_id, and the \
scheduler confirmed each one on its preassigned node (it chose none)"
	log_evidence "creating a global task for a node that has none" "service=$GS"

	# --- 2. the drain -------------------------------------------------------
	# Removed first for the same reason gs_create removes the global service: a
	# run that failed in the middle of this scenario leaves it behind, and
	# creating it again would be a name conflict rather than a test.
	svc_rm_audited "$DRS"
	info "POST /services/create: $DRS, $DRS_REPLICAS replicas, restart delay ${DRS_DELAY}s"
	api_create "$(drs_spec "$IMAGE")"
	wait_until "$T_CONVERGE" "$DRS at $DRS_REPLICAS live tasks, spread $(even_spread "$DRS_REPLICAS")" \
	    'tasks_fetch "$DRS" && [ "$(tasks_live_total)" = "$DRS_REPLICAS" ] &&
	     [ "$(tasks_live_spread)" = "$(even_spread "$DRS_REPLICAS")" ]'

	# The last inventory node, deliberately without asking which one is the
	# leader: a drain stops no daemon, so it changes nothing about quorum or
	# leadership, and MANAGER STATUS is not to be trusted anyway (README).
	GD_NODE=$(cluster_nodes | tail -1)
	GD_HOST=$(host_of "$GD_NODE")
	GD_GTASK=$(awk -v n="$GD_NODE" '$1 == n { print $3 }' "$GSMAP")
	tasks_fetch "$DRS"
	tasks_live_ids_on "$GD_HOST" >"$TMPD/drs.doomed"
	GD_DOOMED=$(tr '\n' ' ' <"$TMPD/drs.doomed" | sed 's/ *$//')
	[ -n "$GD_DOOMED" ] ||
	    fail "$DRS has no task on $GD_NODE, so draining it would move nothing"
	GD_SURVIVORS=$((GS_NODES - 1))
	GD_SPREAD=$(spread_over "$DRS_REPLICAS" "$GD_SURVIVORS")
	info "draining $GD_NODE ($GD_HOST): it holds the global task $GD_GTASK and \
$(countl <"$TMPD/drs.doomed") task(s) of $DRS"

	GD_T0=$(date +%s)
	node_ssh "$CTL" "satl node update --availability drain $GD_HOST" \
	    >"$TMPD/drain" 2>&1 || {
		show "$TMPD/drain"
		fail "satl node update --availability drain $GD_HOST failed"
	}
	wait_until "$T_CONVERGE" \
	    "the drain to empty $GD_NODE: $GS down to $GD_SURVIVORS tasks, $DRS back to $DRS_REPLICAS elsewhere, no container left" '
		tasks_fetch "$GS" &&
		[ "$(tasks_wanted_on "$GD_HOST")" = 0 ] &&
		[ "$(tasks_wanted_total)" = "$GD_SURVIVORS" ] &&
		tasks_fetch "$DRS" &&
		[ "$(tasks_live_total)" = "$DRS_REPLICAS" ] &&
		[ "$(tasks_live_on "$GD_HOST")" = 0 ] &&
		[ "$(tasks_live_spread)" = "$GD_SPREAD" ] &&
		[ "$(node_jails "$GD_NODE" | awk "\$3 > 0" | countl)" = 0 ]'
	GD_SECS=$(($(date +%s) - GD_T0))

	# The measurement, and the reason the delay above is 30s: every other
	# eviction trigger pays it (leader_kill's are logged `delay_ms=5000`), so a
	# drain that waited for it would take at least DRS_DELAY seconds before the
	# first replacement even appeared.
	[ "$GD_SECS" -lt "$DRS_DELAY" ] ||
	    fail "the drain took ${GD_SECS}s, which is not less than the ${DRS_DELAY}s \
restart delay $DRS was created with. SWK §7.4 forces the delay to 0 for a \
draining node — an operator emptying a node is waiting on it — so a drain that \
takes a delay or more is being paced by per-task back-off"
	info "the drain completed in ${GD_SECS}s, against a ${DRS_DELAY}s restart delay \
(SWK §7.4: a drain does not wait)"

	# What the log has to say about it, per task, bound to this run's task IDs:
	# the draining trigger, and the delay it did *not* take.
	for _gdt in $GD_DOOMED; do
		[ "$(log_hits "task_id=$_gdt" 'trigger="node is draining"' "delay_ms=0")" -ge 1 ] ||
		    fail "no node logged task $_gdt of $DRS being replaced with \
trigger=\"node is draining\" and delay_ms=0. The drain converged in ${GD_SECS}s, \
so *something* was fast; this line is the daemon saying it skipped the delay on \
purpose (SWK §7.4) rather than having a delay that never applied"
	done
	[ "$(log_hits "stopping a global task" "task_id=$GD_GTASK" \
	    "node_id=$(node_id_of "$GD_HOST")")" -ge 1 ] ||
	    fail "no node logged the global loop stopping $GD_GTASK on the drained \
$GD_HOST. The global loop owns this decision, not the restart supervisor \
(fb5190a: Trigger::applies_to_global), and its line is the only place that says so"
	info "the log says delay_ms=0 with trigger=\"node is draining\" for every \
replaced task, and the global loop gave the drained node's task up itself"
	log_evidence 'trigger="node is draining"' "delay_ms=0"
	log_evidence "stopping a global task" "task_id=$GD_GTASK"

	# And the half that a drain of a *replicated* service would hide: the global
	# task is not replaced anywhere. Watched rather than read once — a
	# replacement created one orchestrator pass later would satisfy a single
	# read and break the service's "one task per node" invariant just as badly.
	hold_for "$T_SETTLE" "$GS at $GD_SURVIVORS tasks with none wanted on $GD_HOST" '
		tasks_fetch "$GS" &&
		[ "$(tasks_wanted_total)" = "$GD_SURVIVORS" ] &&
		[ "$(tasks_wanted_on "$GD_HOST")" = 0 ]'
	info "no replacement for the drained node's global task: a global task's node \
is its identity, so the service runs on one node fewer until the node returns"

	# --- 3. and back --------------------------------------------------------
	info "satl node update --availability active $GD_HOST"
	node_ssh "$CTL" "satl node update --availability active $GD_HOST" \
	    >"$TMPD/undrain" 2>&1 || {
		show "$TMPD/undrain"
		fail "satl node update --availability active $GD_HOST failed"
	}
	wait_until "$T_CONVERGE" "$GS back to one live task on every node, $GD_HOST included" '
		tasks_fetch "$GS" && [ "$(tasks_live_total)" = "$GS_NODES" ] &&
		[ "$(tasks_live_on "$GD_HOST")" = 1 ]'
	GD_NEW=$(tasks_live_ids_on "$GD_HOST")
	[ "$GD_NEW" != "$GD_GTASK" ] ||
	    fail "the global task on $GD_HOST is task $GD_GTASK again, the one the drain \
stopped: a task is one-shot and is never re-executed (architecture §4 rule 4)"
	gs_task_shape "$GS" "$GD_NEW" "$GD_HOST"
	info "$GD_HOST regained a *new* global task ($GD_NEW), slot 0, named after its node"

	# The replicated service, on the other hand, stays where the drain put it:
	# SatL has no rebalancer (SWK §7.5 is not implemented), so this asserts the
	# behaviour there is rather than the one an operator might hope for. If a
	# rebalancer is ever written, this is the assertion to change deliberately.
	hold_for "$T_SETTLE" "$DRS still $GD_SPREAD over the survivors — SatL has no rebalancer" '
		tasks_fetch "$DRS" &&
		[ "$(tasks_live_total)" = "$DRS_REPLICAS" ] &&
		[ "$(tasks_live_on "$GD_HOST")" = 0 ] &&
		[ "$(tasks_live_spread)" = "$GD_SPREAD" ]'
	info "$DRS was not rebalanced onto the returned node: $DRS_REPLICAS tasks, \
spread $GD_SPREAD, none on $GD_HOST"

	svc_rm_audited "$DRS"
	svc_rm_audited "$GS"
}

# ===========================================================================
# Scenario 11 — global_update
#
# Part 5: a rolling update of a *global* service, whose unit is the **node**.
#
# `rolling_update` covers the replicated shape — six slots, one at a time, under
# load. What cannot be tested there is the shape itself: a global service has no
# slots, its unit set is read from the store on every pass (the eligible nodes),
# and its progress line therefore has to count something else. Asserted here:
#
#   - at no sampling point is more than one node in flight, in either of the two
#     forms a `stop-first` batch takes — a node holding a new task that is not
#     Running yet, and a node holding no live task at all. With `parallelism: 1`
#     over three nodes, "one node at a time" is the whole difference between a
#     rolling update and a restart;
#   - every node ends with exactly one task on the new image, pinned to it, in
#     slot 0 and named after it (gs_task_shape) — the update replaced a task per
#     node rather than renumbering anything;
#   - each of those tasks was created by the **updater** and not by the global
#     loop: `updating slot: replacement task created` naming that task ID. The
#     two components create tasks for the same nodes and only their log lines
#     tell them apart, which is exactly the division fb5190a draws (filling an
#     empty node is the global loop's job, never the updater's);
#   - `UpdateStatus.Message` counts **nodes** — "update completed: 3 nodes
#     updated". The wording is deliberate: a global service has no slots, and
#     "3 slots updated" would be a lie about it;
#   - the whole rollout takes at least **two monitor windows**. Three units at
#     parallelism 1, each watched for GS_MONITOR seconds before the next starts,
#     cannot be done in less; a rollout that was is not pacing itself at all.
#
# The service is created fresh on the first tag and updated to the second, the
# same pair `rolling_update` seeds (same content, different string: every task is
# dirty and nothing observable about the container changes). ru_seed_tag is
# idempotent, so running this scenario alone still finds the tag it needs.
# ===========================================================================

# gs_watch_update — the poll body of the global rollout: it samples the property
# that makes the update "rolling" and fails the moment it does not hold, rather
# than returning false. A violation is not "not converged yet".
gs_watch_update() {
	tasks_fetch "$GS" || return 1
	# Nodes holding a task of the *new* image that the cluster wants running and
	# that is not running yet.
	_gwu_new=$(tcols "$TMPD/ptasks" 'NODE,IMAGE,DESIRED STATE,CURRENT STATE' |
	    awk -F'\t' -v img="$GS_NEW_IMAGE" \
	        '$2 == img && $3 == "Running" && $4 !~ /^Running/ { print $1 }' | sort -u | countl)
	[ "$_gwu_new" -le 1 ] ||
	    fail "$_gwu_new nodes hold a new task that is not Running yet. Over a \
global service the unit of a batch is the node (SWK §7.8), so a parallelism of 1 \
may leave exactly one node in flight"
	# And nodes holding no live task of the service at all, which is the same
	# batch seen from the other side: `stop-first` stops the old task before the
	# new one is promoted.
	_gwu_empty=0
	for _gwu in $(cluster_nodes); do
		if [ "$(tasks_live_on "$(host_of "$_gwu")")" = 0 ]; then
			_gwu_empty=$((_gwu_empty + 1))
		fi
	done
	[ "$_gwu_empty" -le 1 ] ||
	    fail "$_gwu_empty nodes are running no task of $GS at once: with \
parallelism 1 a global rollout takes one node down at a time"
	[ "$(svc_state "$GS")" = completed ]
}

scenario_global_update() {
	m4_prelude
	ru_seed_tag "$RU_TAG_A" "$RU_TAG_B"
	GU_OLD="127.0.0.1:$REG_PORT/$REG_NS/$RU_TAG_A"
	GS_NEW_IMAGE="127.0.0.1:$REG_PORT/$REG_NS/$RU_TAG_B"

	gs_create "$GU_OLD"
	gs_map
	cp "$GSMAP" "$TMPD/gsmap.before"
	[ -z "$(svc_state "$GS")" ] ||
	    fail "$GS has an UpdateStatus of '$(svc_state "$GS")' before any update: \
creating a service is not an update"

	GU_T0=$(date +%s)
	info "satl service update --image $RU_TAG_B --update-parallelism 1 --update-monitor ${GS_MONITOR}s $GS"
	node_ssh "$CTL" "satl service update --image $GS_NEW_IMAGE \
	    --update-parallelism 1 --update-monitor ${GS_MONITOR}s $GS" >"$TMPD/guupdate" 2>&1 || {
		show "$TMPD/guupdate"
		fail "satl service update on the global service $GS was refused"
	}
	wait_until "$T_UPDATE" "the global rollout to complete, at most one node in flight" \
	    'gs_watch_update'
	GU_SECS=$(($(date +%s) - GU_T0))

	# Three nodes at parallelism 1, each watched for GS_MONITOR seconds before
	# the next batch starts: two windows is the floor, and a rollout that beat it
	# did not watch anything.
	[ "$GU_SECS" -ge $((2 * GS_MONITOR)) ] ||
	    fail "the rollout of $GS_NODES nodes finished in ${GU_SECS}s, less than the \
two ${GS_MONITOR}s monitor windows $GS_NODES units at parallelism 1 must take: \
the updater cannot have watched each node's new task before moving on"
	info "the rollout took ${GU_SECS}s, at least two ${GS_MONITOR}s monitor windows"

	wait_until "$T_QUICK" "every node running exactly one task of $RU_TAG_B" '
		tasks_fetch "$GS" && [ "$(tasks_live_total)" = "$GS_NODES" ] &&
		[ "$(tasks_live_spread)" = "$GS_EACH" ] &&
		[ "$(tasks_live_images)" = "$GS_NEW_IMAGE" ]'
	gs_map
	while read -r _gun _guh _gut; do
		gs_task_shape "$GS" "$_gut" "$_guh"
		# The updater created it, not the global loop. Both create tasks bound to
		# a node and only these lines tell them apart: filling a node that has
		# *no* task is the global loop's business, replacing the task a node
		# already has is the updater's (fb5190a).
		[ "$(log_hits "updating slot: replacement task created" "task_id=$_gut" "slot=0")" -ge 1 ] ||
		    fail "task $_gut on $_guh was not logged as the *updater's* \
replacement ('updating slot: replacement task created', slot=0). If the global \
loop created it instead, the node had been left without a task at some point — \
which is what a rolling update exists not to do"
		if awk -v t="$_gut" '$3 == t { exit 1 }' "$TMPD/gsmap.before"; then :; else
			fail "task $_gut was already running before the update: the update \
must replace the task on every node, not leave one behind"
		fi
	done <"$GSMAP"
	info "each node ends with exactly one new task, pinned to it, created by the updater"

	# The progress line counts *nodes*. A global service has no slots, so
	# "3 slots updated" would be a lie about it — the wording is the assertion.
	GU_MSG=$(svc_message "$GS")
	[ "$GU_MSG" = "update completed: $GS_NODES nodes updated" ] ||
	    fail "UpdateStatus.Message reads '$GU_MSG', not 'update completed: \
$GS_NODES nodes updated'. A global service's unit is the node: counting slots \
would describe a service that has none"
	info "UpdateStatus: $(svc_state "$GS") — $GU_MSG"
	log_evidence "rolling update started" "service=$GS"
	log_evidence "rolling update finished" "service=$GS"

	svc_rm_audited "$GS"
}

# ===========================================================================
# Scenario 12 — global_node_loss
#
# Part 7: a node lost outright, rather than drained. `satld` is stopped and its
# containers are deliberately left running (as node_kill does), so the node goes
# `Down` on its session TTL with a container of the global service still alive on
# it. Asserts:
#
#   - the node's global task goes desired `shutdown` — a `DOWN` node is a
#     rejection in fb5190a's verdict table, exactly like a drain;
#   - **nothing is recreated elsewhere**, watched for T_SETTLE. This is the half
#     that separates a global service from a replicated one: the replicated
#     orchestrator moves a task off a dead node (node_kill asserts precisely
#     that), while a global task has no elsewhere to be moved to and the service
#     simply runs on one node fewer;
#   - when the node comes back, its task returns *there* and reaches `Running`,
#     it is a new task (a task is one-shot), and the container of the old one is
#     gone — one jail with processes per live task on every node.
# ===========================================================================

# gs_jails_match — on every node, the number of jails holding a process equals
# the number of live tasks of $GS the store places there.
#
# jails_match_tasks with a service argument, and the reason it is not that
# function: it reads the tasks of $SERVICE. m4_prelude removed $SERVICE, so on
# these scenarios' cluster the global service is the only thing that should own a
# container anywhere — which makes this the whole-cluster statement it looks like.
gs_jails_match() {
	tasks_fetch "$GS" || return 1
	for _gjm in $(cluster_nodes); do
		_gjmj=$(node_jails "$_gjm" | awk '$3 > 0' | countl)
		[ "$_gjmj" = "$(tasks_live_on "$(host_of "$_gjm")")" ] || return 1
	done
	return 0
}

scenario_global_node_loss() {
	m4_prelude
	gs_create "$IMAGE"
	gs_map

	# Any node but the one the reads come from; a stopped satld is a lost node
	# whatever its raft role, and losing one of three keeps quorum at two.
	GN_NODE=$(cluster_nodes | sed -n 2p)
	GN_HOST=$(host_of "$GN_NODE")
	GN_TASK=$(awk -v n="$GN_NODE" '$1 == n { print $3 }' "$GSMAP")
	GN_SURVIVORS=$((GS_NODES - 1))
	CTL=$(live_manager "$GN_NODE") || fail "no other node can serve reads"
	GN_JID=$(node_jails "$GN_NODE" | awk -v t="$GN_TASK" '$2 == t && $3 > 0 { print $1 }')
	[ -n "$GN_JID" ] ||
	    fail "$GS's task $GN_TASK has no running jail on $GN_NODE: there would be \
no container for the node's loss to strand"
	info "victim $GN_NODE ($GN_HOST), holding $GS's task $GN_TASK in jail $GN_JID"
	info "reads and assertions from $CTL for the rest of this scenario"

	info "stopping satld on $GN_NODE (its container is left running, as node_kill does)"
	node_satld "$GN_NODE" stop || fail "could not stop satld on $GN_NODE"
	wait_until "$T_DOWN" "$GN_NODE reported Down" \
	    'state_fetch "$CTL" && [ "$(host_status "$GN_HOST")" = Down ]'
	[ "$(node_jails "$GN_NODE" | awk -v t="$GN_TASK" '$2 == t && $3 > 0' | countl)" = 1 ] ||
	    fail "$GN_TASK's container is already gone from the Down $GN_NODE; satld's \
shutdown must leave running jails alone, or the reaping assertion below is vacuous"

	wait_until "$T_CONVERGE" "$GS gives up its task on $GN_HOST (desired shutdown)" \
	    'tasks_fetch "$GS" && [ "$(tasks_desired_of "$GN_TASK")" = shutdown ]'
	hold_for "$T_SETTLE" "$GS at $GN_SURVIVORS tasks and nothing created for the lost node" '
		tasks_fetch "$GS" &&
		[ "$(tasks_wanted_total)" = "$GN_SURVIVORS" ] &&
		[ "$(tasks_wanted_on "$GN_HOST")" = 0 ]'
	[ "$(log_hits "stopping a global task" "task_id=$GN_TASK")" -ge 1 ] ||
	    fail "no node logged the global loop giving $GN_TASK up. A replicated task \
on a Down node is *replaced* (node_kill); a global one is stopped and not \
replaced, and this line is where that decision is recorded"
	info "the task is given up, nothing recreated: a global task's node is its identity"
	log_evidence "stopping a global task" "task_id=$GN_TASK"

	info "restarting satld on $GN_NODE"
	node_satld "$GN_NODE" start || fail "satld did not come back on $GN_NODE"
	wait_until "$T_JOIN" "$GN_NODE back to Ready" \
	    'state_fetch "$CTL" && [ "$(host_status "$GN_HOST")" = Ready ]'
	wait_until "$T_CONVERGE" "$GS back to one live task on every node, $GN_HOST included" '
		tasks_fetch "$GS" && [ "$(tasks_live_total)" = "$GS_NODES" ] &&
		[ "$(tasks_live_on "$GN_HOST")" = 1 ]'
	GN_NEW=$(tasks_live_ids_on "$GN_HOST")
	[ "$GN_NEW" != "$GN_TASK" ] ||
	    fail "the returned $GN_HOST is running task $GN_TASK again, the one the \
cluster gave up: a task is one-shot (architecture §4 rule 4)"
	gs_task_shape "$GS" "$GN_NEW" "$GN_HOST"
	wait_until "$T_CONVERGE" "one container per live task on every node (the stray reaped)" \
	    'gs_jails_match'
	info "$GN_HOST regained a new global task ($GN_NEW) and the returning agent \
reaped the container of $GN_TASK"

	svc_rm_audited "$GS"
}

# ===========================================================================
# Scenario 13 — constraint_enforcer
#
# Part 4, SWK §7.6: constraints are checked when a task is *scheduled*, against
# the node as it was then. Labels are operator-writable at any moment, so a task
# can keep running somewhere its service no longer allows — the gap fb5190a
# closes, with the eviction going through the restart supervisor's existing
# transaction and budget rather than a second eviction path.
#
# Two halves, and the second is the real test:
#
#   1. every node carries the label, a CE_REPLICAS-replica service is placed by
#      it one per node, and then **one node's label is changed**. Its task must
#      be shut down and rescheduled onto a node that still matches — asserted
#      together with the daemon's own line for it: `trigger="node no longer
#      satisfies the placement constraints"` **and `delay_ms=CE_DELAY×1000`**.
#      That second field is the deliberate asymmetry of fb5190a: a *drain*
#      forces the delay to zero because an operator is waiting on the node
#      (global_service measures exactly that), while a label edit is nobody
#      waiting, so the service's own restart delay is paid in full. Two triggers,
#      one budget, different pacing — and the log is the only place both are
#      visible;
#   2. the label is then **removed entirely**, and nothing may move. The
#      remaining tasks are on nodes that still match, so a correct enforcer has
#      nothing to do; one that re-evaluates carelessly — judging every task on
#      every node write, or judging a task against its own stale placement
#      snapshot instead of the service's current one — evicts them and the
#      service flaps between nodes for as long as an operator keeps editing
#      labels. Asserted by holding the exact set of live task IDs *and* their
#      nodes for T_SETTLE: a flap that moved a task and moved it back would
#      still change an ID, because a task is one-shot.
# ===========================================================================

# ce_spec <image> — CE_REPLICAS replicas placed by a node label, with a restart
# delay that is deliberately not the 5s default: `delay_ms` in the log is one of
# the assertions, and a default would not prove the value came from the policy.
ce_spec() {
	cat <<JSON | tr -d '\n\t'
{
	"Name": "$CE",
	"TaskTemplate": {
		"ContainerSpec": {"Image": "$1"},
		"RestartPolicy": {"Condition": "any", "Delay": ${CE_DELAY}000000000, "MaxAttempts": 0},
		"Placement": {"Constraints": ["node.labels.$CE_LABEL==$CE_MATCH"]}
	},
	"Mode": {"Replicated": {"Replicas": $CE_REPLICAS}}
}
JSON
}

# ce_label <hostname> <value> — set the scenario's label on one node, and read it
# back from the store: an assertion about a label that was never written would
# fail for the wrong reason.
ce_label() {
	node_ssh "$CTL" "satl node update --label-add $CE_LABEL=$2 $1" >"$TMPD/celabel" 2>&1 || {
		show "$TMPD/celabel"
		fail "satl node update --label-add $CE_LABEL=$2 $1 failed"
	}
	CE_H=$1
	CE_V=$2
	wait_until "$T_QUICK" "$1 carries $CE_LABEL=$2 in the store" \
	    'node_ssh "$CTL" "satl node inspect $CE_H" 2>/dev/null |
	     grep -q "\"$CE_LABEL\": *\"$CE_V\""'
}

# ce_unlabel_all — drop the label everywhere, whether or not it is there. Run at
# both ends of the scenario: a run that failed in the middle must not leave a
# label behind that would place (or refuse) somebody else's tasks.
ce_unlabel_all() {
	for _cu in $(cluster_nodes); do
		node_ssh "$CTL" "satl node update --label-rm $CE_LABEL $(host_of "$_cu")" \
		    >/dev/null 2>&1 || true
	done
}

scenario_constraint_enforcer() {
	m4_prelude
	ce_unlabel_all
	svc_rm_audited "$CE"

	for _cen in $(cluster_nodes); do
		ce_label "$(host_of "$_cen")" "$CE_MATCH"
	done
	info "every node carries $CE_LABEL=$CE_MATCH"

	info "POST /services/create: $CE, $CE_REPLICAS replicas constrained on \
node.labels.$CE_LABEL==$CE_MATCH, restart delay ${CE_DELAY}s"
	api_create "$(ce_spec "$IMAGE")"
	CE_EVEN=$(even_spread "$CE_REPLICAS")
	wait_until "$T_CONVERGE" "$CE at $CE_REPLICAS live tasks, spread $CE_EVEN" '
		tasks_fetch "$CE" && [ "$(tasks_live_total)" = "$CE_REPLICAS" ] &&
		[ "$(tasks_live_spread)" = "$CE_EVEN" ]'

	# --- 1. one node stops matching ----------------------------------------
	# KNOWN-FRAGILE, recorded rather than changed: the first inventory node,
	# so usually node1, which may be the raft leader. Eviction through the
	# constraint enforcer then runs on the leader's own node and skips the
	# `Control.ProposeActions` hop a follower would take. It passes either way
	# and asserts neither, so it measures a slightly different path depending
	# on who leads -- the family of problem Phase 4 is about, small enough here
	# to name rather than fix.
	CE_NODE=$(cluster_nodes | sed -n 1p)
	CE_HOST=$(host_of "$CE_NODE")
	CE_DOOMED=$(tasks_live_ids_on "$CE_HOST" | tr '\n' ' ' | sed 's/ *$//')
	[ -n "$CE_DOOMED" ] ||
	    fail "$CE has no task on $CE_NODE, so relabelling it would evict nothing"
	CE_SPREAD=$(spread_over "$CE_REPLICAS" "$((GS_NODES - 1))")
	info "$CE_NODE ($CE_HOST) holds task(s) $CE_DOOMED; relabelling it \
$CE_LABEL=$CE_OTHER so it no longer matches"
	ce_label "$CE_HOST" "$CE_OTHER"

	wait_until "$T_CONVERGE" \
	    "$CE's task(s) to leave $CE_HOST and be replaced on nodes that still match" '
		tasks_fetch "$CE" &&
		[ "$(tasks_wanted_on "$CE_HOST")" = 0 ] &&
		[ "$(tasks_live_total)" = "$CE_REPLICAS" ] &&
		[ "$(tasks_live_on "$CE_HOST")" = 0 ] &&
		[ "$(tasks_live_spread)" = "$CE_SPREAD" ]'
	info "$CE is back at $CE_REPLICAS live tasks, spread $CE_SPREAD over the nodes \
that still carry $CE_LABEL=$CE_MATCH"

	for _cet in $CE_DOOMED; do
		[ "$(log_hits "task_id=$_cet" \
		    'trigger="node no longer satisfies the placement constraints"')" -ge 1 ] ||
		    fail "no node logged task $_cet being given up because its node stopped \
satisfying the placement constraints. The task did move, so *something* decided \
it: this line says it was the constraint enforcer and not, say, a node that had \
gone Down"
		[ "$(log_hits "task_id=$_cet" \
		    'trigger="node no longer satisfies the placement constraints"' \
		    "delay_ms=${CE_DELAY}000")" -ge 1 ] ||
		    fail "task $_cet was replaced without the ${CE_DELAY}s restart delay its \
service asks for (expected delay_ms=${CE_DELAY}000). Only a *draining* node \
skips the delay (SWK §7.4, asserted in global_service); a label edit is nobody \
waiting on a node, and paying no delay here would make every operator label \
change an immediate churn of tasks"
	done
	info "the log names the constraint trigger and delay_ms=${CE_DELAY}000: the \
delay a drain skips is paid here"
	log_evidence 'trigger="node no longer satisfies the placement constraints"' ""

	# --- 2. and now nothing may move ---------------------------------------
	tasks_live | sort >"$TMPD/ce.settled"
	info "satl node update --label-rm $CE_LABEL $CE_HOST — after this, nothing may move"
	node_ssh "$CTL" "satl node update --label-rm $CE_LABEL $CE_HOST" \
	    >"$TMPD/ceunlabel" 2>&1 || {
		show "$TMPD/ceunlabel"
		fail "satl node update --label-rm $CE_LABEL $CE_HOST failed"
	}
	hold_for "$T_SETTLE" "the same task IDs on the same nodes: no flap" '
		tasks_fetch "$CE" && tasks_live | sort | cmp -s - "$TMPD/ce.settled"'
	info "the tasks that moved stayed put: a second label write on a node that \
already did not match evicts nothing"

	svc_rm_audited "$CE"
	ce_unlabel_all
	for _cen in $(cluster_nodes); do
		if node_ssh "$CTL" "satl node inspect $(host_of "$_cen")" 2>/dev/null |
		    grep -q "\"$CE_LABEL\":"; then
			fail "$_cen still carries the $CE_LABEL label after the scenario"
		fi
	done
	info "the $CE_LABEL label is gone from every node"
}

# ===========================================================================
# Scenario 14 — restart_budget
#
# Part 6, SWK §7.9: `max_attempts` is a budget per replica and spec version, and
# after fb5190a it is **derived from the store on every pass** rather than kept
# in the supervisor's memory. What that buys is exactly one thing, and it can
# only be shown by taking the memory away: a leadership change.
#
# A 1-replica service whose entrypoint exits non-zero, `--restart-condition any`
# and RB_ATTEMPTS attempts. One restart is allowed to happen, and then the
# **leader's satld is killed** — with attempts still on the clock and, because
# the delay queue has no store representation (fb5190a says so in as many
# words), with the next replacement pending only in the dead process's memory.
# The new leader has nothing handed to it: it re-derives the budget from the
# slot's task history and must allow **exactly** the attempts that were left and
# then stop.
#
# The numbers are the assertion, and they are precise on purpose. Before
# fb5190a the map was in memory and a new leader started from zero, so this
# service would have restarted forever, RB_ATTEMPTS at a time, once per
# election. What is asserted:
#
#   - RB_ATTEMPTS + 1 tasks in the slot when it settles — the original plus one
#     replacement per attempt — and **not one more**, held for T_SETTLE;
#   - the last of them was created *after* the election, by the node that won it
#     ("restarting task in the same slot" naming that task ID on the new
#     leader, and on no other);
#   - the new leader then refuses: "task not restarted … reason=\"max restart
#     attempts reached\"" for that task. An operator reading the log has to be
#     able to see the budget being spent, not just infer it from a service that
#     stopped moving.
#
# Two details that make the measurement honest:
#
#   - the leader is found by reading each node's own log (leader_nodes), never
#     from `node ls`'s MANAGER STATUS, which is written when the cluster forms
#     and never refreshed (README). After `leader_kill` earlier in the suite that
#     column names a node that is not the leader, and killing it would produce no
#     election at all;
#   - the service is **pinned to a node other than the leader's**. Otherwise its
#     replacement could be scheduled onto the node whose daemon has just been
#     killed but which the store still calls `Ready` — the task would sit
#     `Assigned` and never fail, and the scenario would time out on a placement
#     race rather than measure a budget.
# ===========================================================================

# rb_spec <image> <hostname> — one replica, pinned, with an entrypoint that
# exits RB_EXIT immediately and a bounded restart policy.
rb_spec() {
	cat <<JSON | tr -d '\n\t'
{
	"Name": "$RB",
	"TaskTemplate": {
		"ContainerSpec": {
			"Image": "$1",
			"Command": ["/bin/sh", "-c", "exit $RB_EXIT"]
		},
		"RestartPolicy": {
			"Condition": "any",
			"Delay": ${RB_DELAY}000000000,
			"MaxAttempts": $RB_ATTEMPTS
		},
		"Placement": {"Constraints": ["node.hostname==$2"]}
	},
	"Mode": {"Replicated": {"Replicas": 1}}
}
JSON
}

# rb_new_leader — a single node other than the killed one reports leadership.
# Sets RB_NEW_LEADER, so the assertions below can name it.
rb_new_leader() {
	_rbn=$(leader_nodes | tr '\n' ' ' | sed 's/ *$//')
	case $_rbn in
	"" | *" "* | "$RB_LEADER") return 1 ;;
	esac
	RB_NEW_LEADER=$_rbn
	return 0
}

scenario_restart_budget() {
	m4_prelude
	svc_rm_audited "$RB"
	RB_TOTAL=$((RB_ATTEMPTS + 1))

	RB_LEADER=$(the_leader)
	RB_PIN=$(cluster_nodes | grep -vx "$RB_LEADER" | sed -n 1p)
	RB_PIN_HOST=$(host_of "$RB_PIN")
	CTL=$(live_manager "$RB_LEADER") || fail "no other node can serve reads"
	info "the leader is $RB_LEADER (read from its own log; MANAGER STATUS is not \
refreshed on a leadership change)"
	info "reads from $CTL; $RB is pinned to $RB_PIN ($RB_PIN_HOST), which is not the leader"

	info "POST /services/create: $RB, 1 replica exiting $RB_EXIT, \
$RB_ATTEMPTS attempt(s), ${RB_DELAY}s delay"
	api_create "$(rb_spec "$IMAGE" "$RB_PIN_HOST")"

	# One restart first, before any election: the budget must be half spent when
	# the leader dies, or there is nothing for the new one to have inherited.
	wait_until "$T_CONVERGE" "$RB to fail and be restarted once (2 tasks in its slot)" \
	    'tasks_fetch "$RB" && [ "$(tasks_rows)" = 2 ]'
	tasks_all | awk '{ print $1 }' | sort >"$TMPD/rb.before"
	info "$RB has used 1 of its $RB_ATTEMPTS attempts; $((RB_ATTEMPTS - 1)) left"

	info "kill -9 on satld on the leader $RB_LEADER"
	node_satld "$RB_LEADER" kill9 || fail "could not kill satld on $RB_LEADER"

	# The window this measures in: the second replacement must still be *pending*
	# when the leader dies, since a pending restart lives only in that process's
	# memory. If it had already been created, the new leader would have had
	# nothing left to allow and the assertions below would be about nothing.
	tasks_fetch "$RB" || fail "$CTL cannot list the tasks of $RB after the kill"
	[ "$(tasks_rows)" = 2 ] ||
	    fail "$RB already has $(tasks_rows) tasks: the killed leader created the \
next replacement before it died, so this run cannot tell whether the *new* leader \
allowed it. The delay (SATL_TEST_BUDGET_DELAY=${RB_DELAY}s) is the window this \
needs; re-run, or widen it"

	wait_until "$T_ELECT" "a survivor's satld to report leadership gained (a real election)" \
	    'rb_new_leader'
	info "$RB_NEW_LEADER won the election ('leadership gained: starting the \
leader-only components' in its own log)"

	wait_until "$T_CONVERGE" \
	    "exactly $((RB_ATTEMPTS - 1)) more restart under the new leader: $RB_TOTAL tasks in the slot" \
	    'tasks_fetch "$RB" && [ "$(tasks_rows)" = "$RB_TOTAL" ]'
	hold_for "$T_SETTLE" "the budget stays spent: $RB_TOTAL tasks and no more" '
		tasks_fetch "$RB" && [ "$(tasks_rows)" = "$RB_TOTAL" ]'
	info "$RB settled at $RB_TOTAL tasks: 1 original + $RB_ATTEMPTS restarts, the \
budget its policy allows and not one more"

	# Which task the new leader created, and that it was the new leader.
	tasks_all | awk '{ print $1 }' | sort >"$TMPD/rb.after"
	RB_LAST=$(comm -13 "$TMPD/rb.before" "$TMPD/rb.after" | tr '\n' ' ' | sed 's/ *$//')
	case $RB_LAST in
	"" | *" "*)
		fail "expected exactly one task of $RB to have been created after the \
election, got '$RB_LAST'"
		;;
	esac
	[ "$(log_hits_on "$RB_NEW_LEADER" "restarting task in the same slot" "task_id=$RB_LAST")" -ge 1 ] ||
	    fail "$RB_NEW_LEADER does not say it created $RB_LAST. The task exists and \
was created after the election, so if the new leader did not create it the \
harness is naming the wrong node"
	[ "$(log_hits_on "$RB_LEADER" "restarting task in the same slot" "task_id=$RB_LAST")" = 0 ] ||
	    fail "the killed leader $RB_LEADER logged creating $RB_LAST, a task that \
did not exist while it was alive"

	# And the budget being spent, said out loud. This is the assertion the
	# pre-fb5190a in-memory history could not pass: a new leader started from an
	# empty map, allowed RB_ATTEMPTS restarts of its own, and never reached this
	# line at all.
	RB_ABANDONED=$(tasks_abandoned | tr '\n' ' ' | sed 's/ *$//')
	[ "$RB_ABANDONED" = "$RB_LAST" ] ||
	    fail "the task left terminal-but-still-wanted is '$RB_ABANDONED', not the \
last one created ($RB_LAST): the slot a spent budget leaves behind is the task \
nothing will replace"
	[ "$(log_hits_on "$RB_NEW_LEADER" "task not restarted" "task_id=$RB_LAST" \
	    'reason="max restart attempts reached"')" -ge 1 ] ||
	    fail "$RB_NEW_LEADER stopped restarting $RB but never said why. An \
operator must be able to read 'task not restarted … reason=\"max restart attempts \
reached\"' for $RB_LAST; a service that merely stopped moving is \
indistinguishable from a stuck orchestrator"
	info "the new leader spent the inherited budget and said so"
	log_evidence "task not restarted" "task_id=$RB_LAST"
	log_evidence "restarting task in the same slot" "task_id=$RB_LAST"

	# --- back to three managers --------------------------------------------
	info "restarting satld on $RB_LEADER (the suite expects three managers)"
	node_satld "$RB_LEADER" start || fail "satld did not come back on $RB_LEADER"
	wait_until "$T_JOIN" "$RB_LEADER back to Ready on every node's view" '
		_rbok=1
		for _rbn in $(cluster_nodes); do
			state_fetch "$_rbn" || _rbok=0
			[ "$(nodes_ready)" = "$GS_NODES" ] || _rbok=0
		done
		[ "$_rbok" = 1 ]'
	# The returning ex-leader must not hand the budget back either: it derives
	# the same count from the same store, whether or not it wins leadership again.
	tasks_fetch "$RB" || fail "$CTL cannot list the tasks of $RB"
	[ "$(tasks_rows)" = "$RB_TOTAL" ] ||
	    fail "$RB has $(tasks_rows) tasks now that $RB_LEADER is back, not \
$RB_TOTAL: a restarted manager re-derives the budget from the store and must \
reach the same answer"
	svc_rm_audited "$RB"
	# The cluster is left AGREED, not left with a particular leader.
	#
	# Restoring `$RB_LEADER` was tried and is the wrong fix: forcing a specific
	# node to lead is a random walk (see `require_leader`), so it turns a
	# cleanup step into a coin flip that can fail the scenario. The dependency
	# it was meant to break is fixed at the other end instead -- `ca_rotate`
	# now picks its demote target by raft role rather than inheriting whatever
	# this scenario left. Which node ends up leading is genuinely this
	# scenario's subject and no successor's business.
	wait_until "$T_JOIN" "the cluster agrees again before leaving restart_budget" \
	    'membership_agreed'
	info "cluster left with $GS_NODES managers Ready and agreed, leader \
$(host_of "$(the_leader)")"
}

# ===========================================================================
# Scenario 15 — ca_rotate
#
# M5: `satl ca rotate` replaces the cluster root CA on a live, mixed-role
# cluster with zero downtime, and the mechanisms — not just the outcome — are
# what is asserted (architecture §12.3, SWK §16.5):
#
#   - one node is demoted to a worker first, so the rotation exercises both
#     re-issue paths: managers self-issue from the store, the worker renews
#     through NodeCA after the session pushed it the transitional bundle;
#   - a service with a published port serves throughout, under the
#     rolling_update load generator: at least CR_MIN_REQUESTS requests span
#     pre-rotation, rotation and post-rotation, and none may be lost;
#   - a write commits in every phase (a node label per phase, read back);
#   - the *transitional* trust bundle — exactly two roots — is observed
#     mid-rotation, and the final bundle is one root with a new fingerprint;
#   - every node's leaf is re-issued: new serial, a two-certificate chain
#     (leaf + cross-signed intermediate) that verifies against the OLD root
#     alone and against the NEW root alone — and the leaf *without* the
#     intermediate fails against the old root, which is the proof that the
#     cross-signing is what bridges the trust and not some accident;
#   - the managers present the new chain on the wire (openssl s_client
#     against the 2378 bootstrap listener) with **unchanged pids** — no
#     restart anywhere — and no node logged "agent session lost" across the
#     whole rotation;
#   - both join tokens are regenerated (new digest field; secrets never
#     printed), and the pre-rotation token fails a join with the error that
#     names the rotation;
#   - the negative: a worker stopped through a second rotation holds it open
#     (the reconciler waits for every node, deliberately) until
#     `satl node rm --force` releases it; when that node returns, managers
#     refuse its handshake with the documented operator-facing message, and
#     the documented way back in — leave --force + join with a fresh token —
#     works **through a manager that is deliberately not the leader**, which
#     is the only way the assertion means what it says: only the leader signs
#     a certificate, an operator cannot know which manager leads, and the
#     joiner must follow the `satl-leader-addr` redirect itself (42cae3c
#     stranded a node on exactly this). The node is then promoted back,
#     leaving the all-manager cluster the rest of the suite expects.
# ===========================================================================

# The swarm document, fields of it, and the trust bundle as the API serves it.
# `satl ca` prints TLSInfo.TrustRoot, which is the same store field the 2378
# bootstrap listener serves to joiners — one source of truth, asserted once.
cr_swarm() { ru_api "$CTL" GET "/swarm" 2>/dev/null; }
cr_rotating() { cr_swarm | grep -q '"RootRotationInProgress":true'; }
cr_settled() { cr_swarm | grep -q '"RootRotationInProgress":false'; }
cr_root_pem() { node_ssh "$CTL" "satl ca 2>/dev/null"; }
cr_root_certs() { cr_root_pem | grep -c 'BEGIN CERTIFICATE' || true; }
# Fingerprint of the FIRST certificate of the bundle (openssl x509 reads one).
cr_root_fp() { cr_root_pem | openssl x509 -noout -fingerprint -sha256 2>/dev/null; }

# cr_fetch_certs <node> — copy the node's chain and trust anchors here, split:
# $TMPD/<node>.leaf, $TMPD/<node>.inter (empty if none), $TMPD/<node>.ca
cr_fetch_certs() {
	node_root_sh "$1" "$STATE_DIR" <<'REMOTE' >"$TMPD/$1.chain" 2>/dev/null
cat "$1/certs/node.crt"
echo '@@@ca'
cat "$1/certs/ca.crt"
REMOTE
	awk '/^@@@ca$/ { part = 2; next } { print > (part == 2 ? ca : chain) }' \
	    chain="$TMPD/$1.chain.only" ca="$TMPD/$1.ca" "$TMPD/$1.chain"
	awk '/BEGIN CERTIFICATE/ { n++ } n == 1' "$TMPD/$1.chain.only" >"$TMPD/$1.leaf"
	awk '/BEGIN CERTIFICATE/ { n++ } n == 2' "$TMPD/$1.chain.only" >"$TMPD/$1.inter"
}

cr_node_serial() {
	node_root_sh "$1" "$STATE_DIR" <<'REMOTE' 2>/dev/null
openssl x509 -in "$1/certs/node.crt" -noout -serial 2>/dev/null | head -1
REMOTE
}

# cr_write <phase> — one store write per phase, read back: the control plane
# stayed writable while its own transport security was being replaced.
cr_write() {
	CR_PHASE=$1
	node_ssh "$CTL" "satl node update --label-add $CR_LABEL=$1 $(host_of "$CTL")" \
	    >"$TMPD/crlabel" 2>&1 || {
		show "$TMPD/crlabel"
		fail "a write refused during the '$1' phase: satl node update --label-add"
	}
	wait_until "$T_QUICK" "the '$1' write is readable from the store" \
	    'node_ssh "$CTL" "satl node inspect $(host_of "$CTL")" 2>/dev/null |
	     grep -q "\"$CR_LABEL\": *\"$CR_PHASE\""'
}

cr_unlabel() {
	node_ssh "$CTL" "satl node update --label-rm $CR_LABEL $(host_of "$CTL")" \
	    >/dev/null 2>&1 || true
}

# cr_verify_chain <node> <old-root> <new-root> — the cross-signing property,
# verified with a tool that shares no code with satld. Requires that the leaf
# alone does NOT verify against the old root: if it did, the "bridging" the
# intermediate is for would be untestable here.
cr_verify_chain() {
	_cvc_n=$1
	_cvc_old=$2
	_cvc_new=$3
	[ -s "$TMPD/$_cvc_n.inter" ] ||
	    fail "$_cvc_n's node.crt carries no cross-signed intermediate after the rotation"
	openssl verify -CAfile "$_cvc_new" "$TMPD/$_cvc_n.leaf" >/dev/null 2>&1 ||
	    fail "$_cvc_n's leaf does not verify against the new root alone"
	openssl verify -CAfile "$_cvc_old" -untrusted "$TMPD/$_cvc_n.inter" \
	    "$TMPD/$_cvc_n.leaf" >/dev/null 2>&1 ||
	    fail "$_cvc_n's chain (leaf + cross-signed intermediate) does not verify \
against the old root: the intermediate is not bridging the trust"
	if openssl verify -CAfile "$_cvc_old" "$TMPD/$_cvc_n.leaf" >/dev/null 2>&1; then
		fail "$_cvc_n's leaf verifies against the old root without the intermediate: \
the leaf was signed by the old key, not the new root's"
	fi
}

# The digest field of a join token (field 3 of SATL-1-<digest>-<secret>) —
# public by design (it pins the CA bundle); the secret is never extracted,
# never compared, never printed.
cr_token_digest() {
	node_ssh "$CTL" "satl swarm join-token -q worker 2>/dev/null" | cut -d- -f3
}


# ---------------------------------------------------------------------------
# Scenario: demote_leader — demoting the CURRENT raft leader, on purpose.
#
# The case that used to be met only by accident. `ca_rotate` demoted a
# hardcoded node, and whether that node led was decided by where the previous
# scenario left leadership: one run logged `leader node1` and passed, the next
# logged `leader node3` and timed out, on identical code (decision log,
# 2026-08-24). A scenario that means to exercise the hard case has to say so
# and assert it, which is what `require_leader` and `assert_leader` are for.
#
# What it pins, beyond "the call returns": the demote completes BOTH halves.
# Leaving consensus was never the broken part -- writing the role was, because
# a node out of consensus stops receiving replication and its own store
# freezes. So the role is read back from a SURVIVOR: a demoted node cannot see
# its own demotion.
# ---------------------------------------------------------------------------
scenario_demote_leader() {
	m4_prelude

	# Whoever leads right now IS the case under test, so the scenario asks the
	# cluster instead of imposing a node on it. `require_leader` exists and was
	# used here first; it is a random walk (stopping the leader leaves two
	# nodes and either may win), so pinning a *specific* node is a coin flip
	# with a cap — and it failed a run at 4 rounds. Nothing here needs node1:
	# it needs the leader, and `the_leader` names it.
	# `membership_agreed` is not enough to name the leader: it counts the
	# MANAGER STATUS column, which is written at formation and never refreshed
	# on a leadership change, so it can read "1 Leader" while raft leadership is
	# somewhere else entirely. `leader_nodes` reads the daemons' own logs, which
	# is the only source that moves.
	wait_until "$T_ELECT" "a manager reports holding raft leadership" '[ -n "$(leader_nodes)" ]'

	DL_TARGET=$(the_leader)
	assert_leader "$DL_TARGET"
	DL_HOST=$(host_of "$DL_TARGET")
	DL_OTHER=$(a_follower)
	[ -n "$DL_OTHER" ] || fail "demote_leader needs a second manager to read from"

	# The quorum guard refuses a removal until the leader has *heard from* a
	# quorum of the remaining members within the liveness window, and a
	# cluster that has just changed leadership has not yet. Node status is the
	# observable that moves with it, so wait for it before asserting anything
	# about the demote: without this the scenario failed a run with all three
	# nodes reading `Unknown`, which is the guard doing its job, not the
	# defect this scenario exists to catch.
	wait_until "$T_JOIN" "all nodes Ready, so liveness has observed the managers" \
	    'state_fetch "$CTL" && [ "$(nodes_ready)" = "$(cluster_nodes | countl)" ]'

	info "satl node demote $DL_HOST — the node being demoted IS the raft leader"
	# Bounded retry, and deliberately **not** the `|| true` retry Phase 4
	# removed from `ca_rotate`: that one swallowed every error and turned a
	# permanent failure into a timeout with no message. This one retries only
	# while the refusal is the transient liveness one the daemon's own error
	# text says to retry ("the same command succeeds shortly after"), fails
	# immediately on any other error, and fails with the real message if the
	# transient one outlasts the budget. A single shot would assert something
	# the product explicitly does not promise.
	dl_deadline=$(($(date +%s) + T_ELECT))
	while :; do
		node_ssh "$DL_TARGET" "satl node demote $DL_HOST" >"$TMPD/dldemote" 2>&1 && break
		grep -q "have answered this node within the liveness window" "$TMPD/dldemote" || {
			show "$TMPD/dldemote"
			fail "demoting the current leader was refused"
		}
		[ "$(date +%s)" -lt "$dl_deadline" ] || {
			show "$TMPD/dldemote"
			fail "the quorum guard never let the leader be demoted within ${T_ELECT}s"
		}
		sleep 2
	done
	grep -q "demoted in the swarm" "$TMPD/dldemote" || {
		show "$TMPD/dldemote"
		fail "the demote did not report Docker's success line"
	}

	# Read from a survivor, and require BOTH halves: out of consensus (no
	# manager status) and role flipped. Asserting only the first is what let
	# the half-demoted state go unnoticed.
	wait_until "$T_JOIN" "$DL_HOST is a worker as $(host_of "$DL_OTHER") sees it" \
	    'state_fetch "$DL_OTHER" && [ -z "$(host_mstatus "$DL_HOST")" ] &&
	     [ "$(host_status "$DL_HOST")" = "Ready" ]'
	_dl_role=$(node_ssh "$DL_OTHER" "satl node inspect $DL_HOST" 2>/dev/null |
	    awk -F'"' '/"Role"/ {print $4; exit}')
	[ "$_dl_role" = "worker" ] ||
	    fail "$DL_HOST left consensus but its role is '$_dl_role', not 'worker': \
the demote applied only its raft half"

	# Leadership really moved, and the ex-leader is not it.
	#
	# Order matters: `assert_not_leader` goes through `the_leader`, which fails
	# loudly when nobody holds leadership -- and right after a handover there is
	# a window with no leader at all. Waiting for one first turns that into the
	# transient it is, rather than a scenario failure naming the wrong thing.
	wait_until "$T_ELECT" "another manager leads" '[ -n "$(leader_nodes)" ]'
	assert_not_leader "$DL_TARGET"
	info "leadership moved to $(host_of "$(the_leader)")"

	# Put it back, so the next scenario starts from three managers.
	node_ssh "$DL_OTHER" "satl node promote $DL_HOST" >"$TMPD/dlpromote" 2>&1 || {
		show "$TMPD/dlpromote"
		fail "promoting $DL_HOST back was refused"
	}
	wait_until "$T_JOIN" "$DL_HOST back to three agreeing managers" 'membership_agreed'
}

scenario_ca_rotate() {
	require_swarm
	build_hostmap
	build_nodeids
	wait_until "$T_JOIN" "all nodes Ready" \
	    'state_fetch "$CTL" && [ "$(nodes_ready)" = "$(cluster_nodes | countl)" ]'

	# The load generator and the ru_* service helpers are reused verbatim,
	# rebound to this scenario's service; restored before returning.
	_cr_saved_ru=$RU
	_cr_saved_port=$RU_PORT
	_cr_saved_replicas=$RU_REPLICAS
	RU=$CR
	RU_PORT=$CR_PORT
	RU_REPLICAS=$CR_REPLICAS
	cr_unlabel

	# --- a mixed-role cluster: demote one joiner to a worker -----------------
	# Picked by RAFT role, not by position in the inventory.
	#
	# `nodes_with_role joiner | sed -n 2p` was always node3, and whether node3
	# led was decided by where the previous scenario, restart_budget, happened
	# to leave leadership — so the same code and the same suite produced
	# different verdicts, and the green was partly luck (decision log,
	# 2026-08-24). What this scenario is about is the CA rotation covering a
	# worker's NodeCA path; demoting the leader is a different test, and it has
	# its own scenario now.
	CR_WRK=$(a_follower)
	[ -n "$CR_WRK" ] ||
	    fail "ca_rotate needs a manager that is not the leader to demote"
	assert_not_leader "$CR_WRK"
	CR_WRK_HOST=$(host_of "$CR_WRK")

	# Read through somebody OTHER than the node being demoted.
	#
	# `$CTL` is a global that `require_swarm` points at the first inventory
	# node that answers, which is node1 -- and picking the target by raft role
	# means the target can now BE node1. Then every `state_fetch "$CTL"` below
	# is asking a worker about cluster state, and a worker answers Docker's
	# refusal (api-compat, "Worker nodes can't be used to view or modify
	# cluster state"), so the demote succeeds and the poll waiting to observe
	# it never returns. Measured: fbsd2 showed fbsd1 demoted while this
	# scenario, reading through fbsd1, sat in `wait_until` until it timed out.
	# The old hardcoded target hid this by never colliding with `$CTL`.
	CTL=$(live_manager "$CR_WRK") ||
	    fail "no manager other than $CR_WRK_HOST can serve reads for this scenario"
	info "reading cluster state through $(host_of "$CTL"), not the node being demoted"
	# The demote is issued ONCE and its exit status is asserted.
	#
	# It used to be re-issued inside the poll with `|| true`, on the reasoning
	# that right after restart_budget kills a daemon the quorum check can
	# transiently see a peer Unreachable and refuse — correctly. That is true,
	# and the cost was too high: the loop turned a *permanent* refusal into a
	# 180 s timeout reported as "demote timed out", which is how demoting the
	# current leader stayed broken and unnoticed (it retried ten times and
	# handed leadership over zero). The transient is handled where it belongs,
	# by waiting for the cluster to agree before demoting anything, so a
	# refusal here is a real one and says so immediately.
	wait_until "$T_JOIN" "the cluster agrees on its membership before the demote" \
	    'membership_agreed'
	info "satl node demote $CR_WRK_HOST — the rotation must cover a worker's NodeCA path"
	node_ssh "$CTL" "satl node demote $CR_WRK_HOST" >"$TMPD/crdemote" 2>&1 || {
		show "$TMPD/crdemote"
		fail "satl node demote $CR_WRK_HOST was refused"
	}
	wait_until "$T_JOIN" "$CR_WRK_HOST demoted: empty MANAGER STATUS, still Ready" \
	    'state_fetch "$CTL" && [ -z "$(host_mstatus "$CR_WRK_HOST")" ] &&
	     [ "$(host_status "$CR_WRK_HOST")" = "Ready" ]'

	# --- the service, published, serving from every node ---------------------
	# The base tag every node's registry was seeded with (images.sh); nothing
	# is updated during this scenario, so no second tag is needed.
	_cr_image="127.0.0.1:$REG_PORT/$REG_NS/$RU_TAG_A"
	ru_rm
	wait_until "$T_CLEAN" "no leftover $CR service" '[ -z "$(ru_replicas)" ]'
	info "POST /services/create: $CR, $CR_REPLICAS replicas, -p $CR_PORT:80"
	ru_api "$CTL" POST "/services/create" "$(ru_spec "$_cr_image")" >"$TMPD/crcreate" 2>&1 || true
	grep -q '"ID"' "$TMPD/crcreate" || {
		show "$TMPD/crcreate"
		fail "the API refused the $CR service spec"
	}
	wait_until "$T_CONVERGE" "$CR reaches $CR_REPLICAS/$CR_REPLICAS" \
	    '[ "$(ru_replicas)" = "$CR_REPLICAS/$CR_REPLICAS" ]'
	ru_tasks
	_cr_spread=$(ru_serving_nodes)
	for _n in $(cluster_nodes); do
		printf %s "$_cr_spread" | grep -q "$(host_of "$_n")=" ||
		    fail "$_n runs no task of $CR; the load generator would count its \
requests as lost through the routing-mesh gap (api-compat 75). Spread: $_cr_spread"
	done
	for _n in $(cluster_nodes); do
		CR_NODE=$_n
		wait_until "$T_QUICK" "$_n answers http://$(node_field "$_n" public_ip):$CR_PORT/" \
		    'printf %s "$(curl -s --max-time 5 "http://$(node_field "$CR_NODE" public_ip):$CR_PORT/" 2>/dev/null)" | grep -q "$OVL_BODY"'
	done

	# --- baselines the assertions compare against -----------------------------
	cr_root_pem >"$TMPD/root.old"
	[ "$(grep -c 'BEGIN CERTIFICATE' "$TMPD/root.old")" = 1 ] ||
	    fail "the pre-rotation trust bundle does not hold exactly one root"
	_cr_fp_old=$(cr_root_fp)
	_cr_digest_old=$(cr_token_digest)
	[ -n "$_cr_digest_old" ] || fail "could not read the worker token's digest field"
	for _n in $(cluster_nodes); do
		eval "_cr_pid_$_n=\$(node_pid \"\$_n\")"
		eval "_cr_serial_$_n=\$(cr_node_serial \"\$_n\")"
		eval "_cr_lost_$_n=\$(log_hits_on \"\$_n\" 'agent session lost')"
	done
	info "old root $(printf %s "$_cr_fp_old" | tail -c 24 ), pids: $(for _n in $(cluster_nodes); do eval printf '%s ' "\$_cr_pid_$_n"; done)"

	# --- phase 1: rotate under load, probing every phase ----------------------
	ru_load_start
	cr_write pre
	info "satl ca rotate --detach on $CTL"
	node_ssh "$CTL" "satl ca rotate --detach" >"$TMPD/crrotate" 2>&1 || {
		show "$TMPD/crrotate"
		fail "satl ca rotate was refused"
	}

	# The transitional state is level, not edge: the two-root bundle stays in
	# force until every node converges, so a poll always observes it.
	wait_until "$T_QUICK" "the transitional bundle: rotation in progress, two roots" \
	    'cr_rotating && [ "$(cr_root_certs)" = 2 ]'
	cr_write mid
	info "mid-rotation: RootRotationInProgress=true, trust bundle carries 2 roots, a write committed"

	wait_until "$T_JOIN" "the rotation to complete: one root, not the old one" \
	    'cr_settled && [ "$(cr_root_certs)" = 1 ] && [ "$(cr_root_fp)" != "$_cr_fp_old" ]'
	cr_root_pem >"$TMPD/root.new"
	cr_write post

	# The service must still be serving from every node before the load stops:
	# the count below proves continuity, this proves the end state.
	ru_tasks
	[ "$(ru_live_images | countl)" = "$CR_REPLICAS" ] ||
	    fail "$(ru_live_images | countl) of $CR_REPLICAS tasks serving after the rotation"

	# Hold the load until the sample is big enough to mean something, then stop.
	wait_until "$T_UPDATE" "at least $CR_MIN_REQUESTS requests measured across the rotation" \
	    '[ "$(countl <"$RU_LOAD/attempts")" -ge "$CR_MIN_REQUESTS" ]'
	ru_load_stop
	ru_load_report "the root CA rotation" 0 0
	[ "$RU_LOST" = 0 ] ||
	    fail "$RU_LOST of $RU_TOTAL requests were served by nothing during the \
rotation. Replacing the root CA severs no established connection and restarts \
no task, so it must not cost a request."
	ru_assert_first_attempts "the root CA rotation" 0

	# --- the mechanisms, node by node -----------------------------------------
	for _n in $(cluster_nodes); do
		eval "_cr_was=\$_cr_pid_$_n"
		_cr_now=$(node_pid "$_n")
		[ "$_cr_now" = "$_cr_was" ] ||
		    fail "$_n's satld pid changed across the rotation ($_cr_was -> $_cr_now): \
the rotation must be applied live, never by a restart"
		eval "_cr_was=\$_cr_serial_$_n"
		_cr_now=$(cr_node_serial "$_n")
		[ -n "$_cr_now" ] && [ "$_cr_now" != "$_cr_was" ] ||
		    fail "$_n's leaf certificate was not re-issued (serial unchanged: $_cr_now)"
		cr_fetch_certs "$_n"
		cr_verify_chain "$_n" "$TMPD/root.old" "$TMPD/root.new"
		cmp -s "$TMPD/$_n.ca" "$TMPD/root.new" ||
		    fail "$_n's ca.crt is not the new root alone after completion"
		eval "_cr_was=\$_cr_lost_$_n"
		_cr_now=$(log_hits_on "$_n" 'agent session lost')
		[ "$_cr_now" = "$_cr_was" ] ||
		    fail "$_n logged 'agent session lost' during the rotation \
($_cr_was -> $_cr_now): renewals must never sever an established session"
	done
	info "every leaf re-issued under the new root, chains bridge to the old root, pids stable, no session lost"

	# The worker's path specifically: bundle over the session, re-issue via
	# NodeCA — the storeless half of the design (architecture §12.3).
	[ "$(log_hits_on "$CR_WRK" 'root ca bundle updated')" -ge 2 ] ||
	    fail "$CR_WRK (worker) never received a root CA bundle over its session"
	[ "$(log_hits_on "$CR_WRK" 're-issued for the root rotation')" -ge 1 ] ||
	    fail "$CR_WRK (worker) did not re-issue through NodeCA for the rotation"
	info "$CR_WRK converged as a worker: session bundle push + NodeCA re-issue"

	# The wire, from outside the daemon: each manager's bootstrap listener
	# presents the new leaf *with* the intermediate (the worker runs no
	# listener — its chain was verified from disk above).
	for _n in $(cluster_nodes); do
		[ "$_n" = "$CR_WRK" ] && continue
		_cr_ip=$(node_field "$_n" private_ip)
		node_ssh "$_n" "echo | openssl s_client -connect $_cr_ip:$((MGR_PORT + 1)) -showcerts 2>/dev/null" \
		    >"$TMPD/$_n.wire" 2>/dev/null || true
		_cr_wire=$(grep -c 'BEGIN CERTIFICATE' "$TMPD/$_n.wire" || true)
		[ "$_cr_wire" = 2 ] ||
		    fail "$_n presents $_cr_wire certificate(s) on :$((MGR_PORT + 1)); the \
re-issued identity must carry the cross-signed intermediate on the wire"
	done
	info "managers present leaf + cross-signed intermediate on the wire (:$((MGR_PORT + 1)))"

	# The service has proven what it was for; remove it now so the worker is
	# task-free — both the stale-token join below and the stop/rejoin of the
	# negative phase need a node with nothing running (a dirty node refuses
	# to join before the token is even looked at, and rightly so).
	ru_rm
	wait_until "$T_CLEAN" "$CR removed, no jail/epair/dataset/mount left anywhere" \
	    '[ -z "$(ru_replicas)" ] && leftovers_gone'

	# Tokens: regenerated (digest pins the bundle), and the old one fails a
	# join with the error that names the rotation. The attempt runs on the
	# worker — the CA flow fails before any local state is touched.
	_cr_digest_new=$(cr_token_digest)
	[ -n "$_cr_digest_new" ] && [ "$_cr_digest_new" != "$_cr_digest_old" ] ||
	    fail "the worker join token's digest did not change across the rotation"
	_cr_stale="SATL-1-$_cr_digest_old-0000000000000000000000000"
	if node_ssh "$CR_WRK" "satl swarm join --token $_cr_stale $(node_field "$CTL" private_ip):$MGR_PORT" \
	    >"$TMPD/crstale" 2>&1; then
		fail "a pre-rotation join token was accepted after the rotation"
	fi
	grep -q 'root CA bundle does not match the join token' "$TMPD/crstale" || {
		show "$TMPD/crstale"
		fail "the stale-token refusal does not carry the bundle-digest error"
	}
	grep -q 'satl ca rotate' "$TMPD/crstale" || {
		show "$TMPD/crstale"
		fail "the stale-token refusal does not name the rotation as the likely cause"
	}
	info "join tokens regenerated; a stale token is refused with the rotation named"

	# --- phase 2: the negative — a node offline through a whole rotation ------
	#
	# The waiting-line assertions below pin a needle to the **node id** of the
	# node this run stopped, which no earlier run can have written: an id is
	# minted at join and this scenario's node re-joined with a fresh one, so
	# `>= 1` is enough and no baseline is needed.
	#
	# A baseline was needed while the needle was generic, and it turned out to be
	# unsound on top of a rotating log: `log_hits_on` reads the archives too, and
	# newsyslog keeps a fixed number of them, so a rotation *inside* the waiting
	# window drops the oldest archive's hits out of the total. Measured here: a
	# rotation landed at 16:00:00, the leader's two waiting lines from 15:59:39
	# went into `messages.0.bz2`, the archive that fell off the end took more
	# lines than that with it, and `total > baseline` stayed false for 60 s while
	# the daemon had said exactly what it was supposed to say.
	_cr_wid=$(node_id_of "$CR_WRK_HOST")
	[ -n "$_cr_wid" ] ||
	    fail "cannot resolve the node id of $CR_WRK_HOST; the waiting-line assertions need it"
	_cr_outbound0=$(log_hits_on "$CR_WRK" "agent session ended")
	info "stopping satld on $CR_WRK (task-free) for the whole second rotation"
	node_satld "$CR_WRK" stop
	info "satl ca rotate --detach — the second rotation cannot finish while a node is missing"
	node_ssh "$CTL" "satl ca rotate --detach" >"$TMPD/crrotate2" 2>&1 || {
		show "$TMPD/crrotate2"
		fail "the second satl ca rotate was refused"
	}
	wait_until "$T_QUICK" "the second rotation in progress" 'cr_rotating'
	hold_for "$T_SETTLE" "the rotation held open by the missing $CR_WRK_HOST" \
	    'cr_rotating'

	# A held rotation must SAY it is held, and name the node. "It holds" is
	# only half the requirement: a cluster stuck mid-rotation with nothing in
	# /var/log/messages about it is a cluster nobody knows to repair, which is
	# how 42cae3c's one red assertion became a permanently stranded node. The
	# leader prints this once per change of the waiting set, not once per 3s
	# tick, so it is greppable rather than a flood.
	wait_until "$T_QUICK" "the leader names what holds the rotation open" \
	    '[ "$(log_hits "root CA rotation is waiting" "$_cr_wid")" -ge 1 ]'
	# ...and once the stopped node's session TTL expires, says it is `down`,
	# which is the state that distinguishes "wait" from "an operator must act".
	# T_DOWN, not T_QUICK: this waits on the dispatcher heartbeat TTL, the same
	# clock node_kill waits on.
	wait_until "$T_DOWN" "the waiting line calls the missing node down, not merely unconverged" \
	    '[ "$(log_hits "root CA rotation is waiting" "$_cr_wid=down")" -ge 1 ]'
	log_evidence "root CA rotation is waiting" "$_cr_wid"

	info "satl node rm --force $CR_WRK_HOST — the documented release of a node that will never return"
	node_ssh "$CTL" "satl node rm --force $CR_WRK_HOST" >"$TMPD/crrm" 2>&1 || {
		show "$TMPD/crrm"
		fail "satl node rm --force $CR_WRK_HOST failed"
	}
	wait_until "$T_JOIN" "the second rotation completes once the dead node is removed" \
	    'cr_settled && [ "$(cr_root_certs)" = 1 ]'

	# The refused return: the worker still holds a certificate from a root
	# nobody trusts anymore. The managers must log the documented refusal.
	_cr_refused=0
	for _n in $(cluster_nodes); do
		[ "$_n" = "$CR_WRK" ] && continue
		eval "_cr_ref_$_n=\$(log_hits_on \"\$_n\" 'refused an internal TLS connection')"
	done
	info "restarting satld on $CR_WRK: its certificate now chains to a dropped root"
	node_satld "$CR_WRK" start
	cr_refusals_grew() {
		for _crn in $(cluster_nodes); do
			[ "$_crn" = "$CR_WRK" ] && continue
			eval "_cr_was=\$_cr_ref_$_crn"
			[ "$(log_hits_on "$_crn" 'refused an internal TLS connection')" -gt "$_cr_was" ] &&
			    return 0
		done
		return 1
	}
	wait_until "$T_DOWN" "a manager logs the documented refusal, with the rejoin hint" \
	    'cr_refusals_grew'
	for _n in $(cluster_nodes); do
		[ "$_n" = "$CR_WRK" ] && continue
		if [ "$(log_hits_on "$_n" 'refused an internal TLS connection' 'satl swarm leave --force')" -gt 0 ]; then
			_cr_refused=1
		fi
	done
	[ "$_cr_refused" = 1 ] ||
	    fail "the refusal was logged without the operator's way out (leave --force + rejoin)"
	info "managers refuse the returning node and say exactly how to get it back in"

	# The other side of the same handshake, printed as evidence rather than
	# asserted, because measuring it corrected a wrong model and the correction
	# is worth keeping in front of whoever reads this run.
	#
	# The failure is **one-directional**. The returning node still verifies the
	# managers perfectly well: their leaves carry the cross-signed intermediate,
	# which bridges back to the root the returning node still holds — that
	# bridging is exactly what the cross-signing is for (§12.3), and it does not
	# stop working just because this node is the one that is behind. So the node
	# never logs a verification error of its own; what it sees is the managers'
	# fatal TLS alert, as `agent session ended ... received fatal alert:
	# DecryptError`. An earlier version of this scenario asserted a
	# node-side "refused an outbound" diagnosis here and failed, correctly: that
	# message cannot fire in this situation, and the assertion was encoding a
	# wrong belief rather than a requirement. The manager's line (asserted just
	# above) is the operator-facing message for this case, and
	# docs/operations.md says so and says what the node's own log looks like.
	[ "$(log_hits_on "$CR_WRK" 'agent session ended')" -gt "$_cr_outbound0" ] ||
	    fail "$CR_WRK logged nothing about its failing sessions; the node an operator \
inspects must at least show that it cannot reach a manager"
	log_evidence "agent session ended" "fatal alert"
	info "the returning node sees the managers' alert (its own verification still \
bridges through the cross-signed intermediate) -- the managers' log is where the \
recovery is printed"

	# The documented recovery: leave, rejoin with a fresh token, promoted back.
	#
	# Pointed **deliberately at a manager that is not the leader**, and that is
	# the whole assertion. Only the leader signs a certificate; a follower
	# answers `IssueNodeCertificate` with the leader's address in
	# `satl-leader-addr` metadata, and the joiner has to follow it. An operator
	# handed "rejoin with a fresh token" cannot know which manager leads, so a
	# join that only works against the leader turns every documented recovery
	# into a coin flip — which is exactly what stranded node3 in 42cae3c: the
	# rejoin there happened to hit a follower because restart_budget had moved
	# leadership, and it failed. Picking the follower on purpose is what stops
	# that from depending on luck again.
	#
	# The token is read from that same follower, for the same reason: a token
	# is public cluster material and any manager prints it.
	#
	# Which node leads comes from the daemons' own logs (`the_leader`), NOT
	# from the MANAGER STATUS column: that column is not refreshed on a
	# leadership change (README, "One thing the scenarios do not assert"), and
	# this scenario runs right after restart_budget killed a leader — so the
	# column's "Leader" is very likely the wrong node here. Picking the
	# follower from a stale column could hand us the real leader, the redirect
	# would never happen, and the assertion below would fail for a reason that
	# has nothing to do with the behaviour under test.
	_cr_leader=$(the_leader)
	CR_FOLLOWER=""
	for _n in $(cluster_nodes); do
		[ "$_n" = "$_cr_leader" ] && continue
		[ "$_n" = "$CR_WRK" ] && continue
		CR_FOLLOWER=$_n
		break
	done
	[ -n "$CR_FOLLOWER" ] ||
	    fail "no manager other than the leader ($_cr_leader) and the returning node \
($CR_WRK) to rejoin through; this scenario needs at least two managers"
	info "rejoining through $(host_of "$CR_FOLLOWER"), a manager that is NOT the leader \
($(host_of "$_cr_leader")): the joiner must follow the leader redirect on its own"
	_cr_token=$(node_ssh "$CR_FOLLOWER" "satl swarm join-token -q worker" 2>/dev/null) ||
	    fail "could not read the post-rotation worker token from the follower $CR_FOLLOWER"
	# Counted before, compared after: log_hits_on reads the rotated files too,
	# so an earlier run's line would otherwise satisfy this assertion without
	# this run's join having followed anything.
	_cr_redirects=$(log_hits_on "$CR_WRK" 'following its redirect to the leader')
	node_ssh "$CR_WRK" "satl swarm leave --force" >/dev/null 2>&1 || true
	join_with_token "$CR_WRK" "$(node_field "$CR_WRK" private_ip)" \
	    "$(node_field "$CR_FOLLOWER" private_ip)" "$_cr_token" >"$TMPD/crjoin" 2>&1 || {
		show "$TMPD/crjoin"
		fail "the rejoin of $CR_WRK through the follower $(host_of "$CR_FOLLOWER") failed. \
This is the documented recovery from a root CA rotation (docs/operations.md); if it \
does not work against an arbitrary manager, the documentation is a lie."
	}
	_cr_token=""
	unset _cr_token
	wait_until "$T_JOIN" "$CR_WRK_HOST back and Ready as a worker" \
	    'state_fetch "$CTL" && [ "$(host_status "$CR_WRK_HOST")" = "Ready" ] &&
	     [ -z "$(host_mstatus "$CR_WRK_HOST")" ]'
	# The redirect was actually followed, not sidestepped by luck: the joiner
	# says so, and the follower is not the leader (asserted above).
	[ "$(log_hits_on "$CR_WRK" 'following its redirect to the leader')" -gt "$_cr_redirects" ] ||
	    fail "$CR_WRK never logged following a leader redirect (still $_cr_redirects), so \
the rejoin did not exercise the follower path this assertion exists for"
	info "the way back in works through any manager: $CR_WRK_HOST rejoined via a \
follower (new node id, as documented)"

	# --- restore the suite's baseline ------------------------------------------
	info "satl node promote $CR_WRK_HOST — back to the all-manager cluster"
	node_ssh "$CTL" "satl node promote $CR_WRK_HOST" >"$TMPD/crpromote" 2>&1 || {
		show "$TMPD/crpromote"
		fail "satl node promote $CR_WRK_HOST failed"
	}
	wait_until "$T_JOIN" "3 Ready, 1 Leader, 2 Reachable — on every node" \
	    'membership_agreed'
	cr_unlabel
	RU=$_cr_saved_ru
	RU_PORT=$_cr_saved_port
	RU_REPLICAS=$_cr_saved_replicas
	info "rotated twice, zero requests lost, negative path proven, cluster restored"
}

# ===========================================================================
# Scenario 17 — compose_stack (M5 DoD)
#
# The definition of done in one file: a realistic stack (web + Redis + worker)
# deployed from a Compose file across the cluster, one service consuming a
# secret, and a `down` that leaves nothing.
#
# Driven through `satl stack` (M11a): this is the *cluster* half of Docker's
# two worlds, where a Compose file becomes one service per compose service on a
# project overlay, spread by the scheduler. `satl compose` runs the same file on
# a single node and is asserted by `compose_local`. What this scenario asserts
# is the mechanism behind each of those words, never the outcome alone:
#
#   - the project name comes from the directory, and every object it creates is
#     namespaced *and labelled* with it (`satl compose config` before anything
#     exists, then the labels the daemon stored);
#   - the network is a real overlay — a subnet and a VNI on every node — and not
#     the bridge `docker compose` would have made;
#   - the compose service name resolves inside the stack because the attachment
#     carries it as a DNS alias (111): the worker reaches `redis` by that name
#     from *another node*, which exercises the alias and the overlay data path
#     at once;
#   - the secret is delivered and *applied*: redis answers NOAUTH to an
#     unauthenticated PING and PONG to one authenticated from the file it was
#     given, the file is on a tmpfs (invariant 7) with the mode the compose file
#     asked for, and the payload never appears in this scenario's output;
#   - a refused key is refused before anything is created;
#   - a second `up` updates rather than duplicates, against the version it read;
#   - `down` removes what `up` created and demonstrably *not* a service that
#     merely shares the prefix — the decoy below is the assertion that matters
#     most, because a `down` that removed somebody else's service would be
#     unforgivable;
#   - the secret survives `down` (cluster secret material is not compose's to
#     delete), and no jail, epair or dataset of any of the stack's tasks is left
#     on any node.
# ===========================================================================

# cs_svc <short name> — the namespaced service name `up` creates.
cs_svc() { printf '%s_%s' "$CS_PROJECT" "$1"; }

# cs_compose <verb> [args...] — this scenario's compose verbs, driven through
# `satl stack` (M11a).
#
# The scenario is the *cluster* definition of done — a stack spread over three
# nodes, on an overlay, resolving across it — and since M11a that is `satl
# stack`'s world; `satl compose` runs the same file on one node and refuses the
# `deploy.placement:` this file needs. The verb mapping is docker's own:
# `stack deploy` is `up`, `stack rm` is `down`, `stack ps` and `stack config`
# are themselves. `compose_local` below is the other half of the split.
#
# `stack config` takes no stack name, so the project still comes from the
# directory the command runs in, which is why cd-ing into it is still part of
# what is being tested: it has to agree with the name `deploy` was given.
cs_compose() {
	_cs_verb=$1
	shift
	case $_cs_verb in
	up) set -- deploy "$@" "$CS_PROJECT" ;;
	down) set -- rm "$CS_PROJECT" ;;
	ps) set -- ps "$CS_PROJECT" ;;
	config) set -- config "$@" ;;
	*) fail "cs_compose: unmapped verb $_cs_verb" ;;
	esac
	node_sh "$CTL" "$CS_DIR" "$@" <<'REMOTE'
dir=$1
shift
cd "$dir" || exit 1
satl stack "$@"
REMOTE
}

# cs_write_compose <node> <nginx image> <redis image> <redis hostname> — write
# the stack's compose.yaml into the project directory.
#
# The placeholders are substituted on the node rather than interpolated here,
# because the file's `$$` sequences are compose's escape for a literal `$`
# (api-compat 114) and must survive every shell between here and the disk.
cs_write_compose() {
	node_sh "$1" "$CS_DIR" "$2" "$3" "$4" "$CS_SECRET" "$CS_PORT" <<'REMOTE'
dir=$1
nginx=$2
redis=$3
rhost=$4
secret=$5
port=$6
mkdir -p "$dir"
cat >"$dir/compose.yaml" <<'YAML'
services:
  web:
    image: @NGINX@
    ports:
      - "@PORT@:80"
    deploy:
      mode: global

  redis:
    image: @REDIS@
    secrets:
      - source: redis_auth
        target: redis.conf
        mode: 0400
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.hostname == @RHOST@

  worker:
    image: @REDIS@
    entrypoint: /bin/sh
    command:
      - -c
      - >-
        set -- $$(cat /run/secrets/redis.conf); REDISCLI_AUTH=$$2;
        export REDISCLI_AUTH;
        while :; do /usr/local/bin/redis-cli -h redis INCR satl:ticks
        >/dev/null 2>&1; sleep 2; done
    secrets:
      - source: redis_auth
        target: redis.conf
        mode: 0400
    depends_on:
      - redis
    deploy:
      mode: global

secrets:
  redis_auth:
    external: true
    name: @SECRET@
YAML
sed -i '' -e "s|@NGINX@|$nginx|" -e "s|@REDIS@|$redis|" -e "s|@RHOST@|$rhost|" \
    -e "s|@SECRET@|$secret|" -e "s|@PORT@|$port|" "$dir/compose.yaml"
REMOTE
}

# cs_secret_create — the one object the compose file refers to and does not
# create (api-compat 120). The payload travels over ssh stdin and is never
# printed, here or in any assertion below.
cs_secret_create() {
	node_sh "$CTL" "$CS_SECRET" <<'REMOTE' >/dev/null 2>&1
name=$1
printf 'requirepass %s\n' 'cs-not-a-real-password' | satl secret create "$name" -
REMOTE
}

# cs_services — this project's service names, as the daemon lists them.
cs_services() {
	node_ssh "$CTL" "satl service ls 2>/dev/null" >"$TMPD/cssvc" 2>/dev/null || return 1
	tcols "$TMPD/cssvc" 'NAME' | awk -v p="${CS_PROJECT}_" 'index($1, p) == 1 { print $1 }'
}

# cs_replicas <service> — the `REPLICAS` cell (`running/desired`).
cs_replicas() {
	node_ssh "$CTL" "satl service ls 2>/dev/null" >"$TMPD/cssvc" 2>/dev/null || return 1
	tcols "$TMPD/cssvc" 'NAME,REPLICAS' | awk -F'\t' -v s="$1" '$1 == s { print $2 }'
}

# cs_converged — every service of the stack at its desired count. A poll body.
cs_converged() {
	[ "$(cs_replicas "$(cs_svc web)")" = "$CS_NODES/$CS_NODES" ] || return 1
	[ "$(cs_replicas "$(cs_svc redis)")" = "1/1" ] || return 1
	[ "$(cs_replicas "$(cs_svc worker)")" = "$CS_NODES/$CS_NODES" ]
}

# cs_task_nodes — the hostnames running a live task of the stack, sorted.
cs_task_nodes() {
	for _cst in web redis worker; do
		node_ssh "$CTL" "satl service ps $(cs_svc "$_cst") 2>/dev/null" \
		    >"$TMPD/cstasks" 2>/dev/null || return 1
		tcols "$TMPD/cstasks" 'NODE,DESIRED STATE,CURRENT STATE' |
		    awk -F'\t' '$2 == "Running" && $3 ~ /^Running/ { print $1 }'
	done | sort -u
}

# cs_task_ids — every task id the stack's services have had, for the audit.
cs_task_ids() {
	for _csi in web redis worker; do
		node_ssh "$CTL" "satl service ps $(cs_svc "$_csi") --quiet --no-trunc 2>/dev/null" |
		    tr -d '\r'
	done | grep -v '^$' | sort -u | tr '\n' ' '
}

# cs_jid <node> <short service name> — the jail of that service's task on that
# node, empty when it runs nowhere there.
cs_jid() {
	_csj_ids=$(node_ssh "$CTL" "satl service ps $(cs_svc "$2") --quiet --no-trunc 2>/dev/null" |
	    tr -d '\r')
	# No `awk -v ids=...`: a service with more than one task row (a replaced
	# task keeps one) makes the value multi-line, and FreeBSD awk rejects a
	# literal newline in -v ("newline in string") — measured in compose_stack.
	# Compare against stdin instead.
	node_jails "$1" | awk '$3 > 0 { print $1, $2 }' |
	    while read -r _jid _name; do
		    printf '%s\n' "$_csj_ids" | grep -qx "$_name" && {
			    printf '%s\n' "$_jid"
			    break
		    }
	    done
}

# cs_ticks <node> <jid> — the counter the workers increment, read from inside a
# worker's jail with the password it was given, by service name. Prints nothing
# on failure, which is what makes it usable as a poll body.
cs_ticks() {
	ovl_in_jail "$1" "$2" \
	    'set -- $(cat /run/secrets/redis.conf); REDISCLI_AUTH=$2 /usr/local/bin/redis-cli -h redis GET satl:ticks' |
	    tr -d '\r' | awk '/^[0-9]+$/ { print; exit }'
}

# cs_secret_mounts <node> <task ids> — how many of those tasks still have a
# secret tmpfs mounted on that node. `mount -p` because these mounts are
# MNT_IGNORE and plain `mount` does not list them (measured).
cs_secret_mounts() {
	node_root_sh "$1" "$2" <<'REMOTE' 2>/dev/null
ids=$1
n=0
mounts=$(mount -p | awk '$3 == "tmpfs" && $2 ~ /run\/secrets$/ { print $2 }')
for id in $ids; do
	printf '%s\n' "$mounts" | grep -q "/$id/" && n=$((n + 1))
done
echo "$n"
REMOTE
}

# cs_rm — leave nothing of a previous run behind. Idempotent, never fatal.
cs_rm() {
	cs_compose down >/dev/null 2>&1 || true
	node_ssh "$CTL" "satl service rm $(cs_svc decoy) >/dev/null 2>&1" || true
	node_ssh "$CTL" "satl secret rm $CS_SECRET >/dev/null 2>&1" || true
	node_ssh "$CTL" "rm -rf $CS_DIR" >/dev/null 2>&1 || true
}

scenario_compose_stack() {
	require_swarm
	build_hostmap
	wait_until "$T_JOIN" "all nodes Ready" \
	    'state_fetch "$CTL" && [ "$(nodes_ready)" = "$(cluster_nodes | countl)" ]'

	CS_NODES=$(cluster_nodes | countl)
	_cs_redis_node=$(cluster_nodes | sed -n 1p)
	_cs_redis_host=$(host_of "$_cs_redis_node")
	_cs_other_node=$(cluster_nodes | sed -n 2p)
	[ -n "$_cs_other_node" ] ||
	    fail "compose_stack needs at least two nodes: the point is that the worker reaches \
redis by name from another node"

	cs_rm
	wait_until "$T_CLEAN" "no leftover $CS_PROJECT services" '[ -z "$(cs_services)" ]'

	cs_secret_create
	node_ssh "$CTL" "satl secret ls" >"$TMPD/cssecrets" 2>&1 || fail "satl secret ls failed"
	grep -q "$CS_SECRET" "$TMPD/cssecrets" ||
	    fail "the secret $CS_SECRET was not created; the compose file refers to it and \
compose never creates one"
	info "secret $CS_SECRET created outside the compose file (api-compat 120)"

	cs_write_compose "$CTL" "$CS_WEB_IMAGE" "$CS_REDIS_IMAGE" "$_cs_redis_host"
	info "compose.yaml written to $CS_DIR on $CTL (web global, redis on $_cs_redis_host, worker global)"

	# --- 1. the plan, before anything exists ---------------------------------
	# `config` reaches no daemon, so what it prints is the mapping alone: the
	# project name derived from the directory, the namespaced service names, the
	# DNS alias that makes the file's own hostnames work, and an overlay driver.
	cs_compose config >"$TMPD/csconfig" 2>&1 || {
		show "$TMPD/csconfig"
		fail "satl compose config was refused"
	}
	grep -q "\"Project\": \"$CS_PROJECT\"" "$TMPD/csconfig" ||
	    fail "compose derived a project name other than $CS_PROJECT from $CS_DIR"
	for _cs in web redis worker; do
		grep -q "\"Name\": \"$(cs_svc "$_cs")\"" "$TMPD/csconfig" ||
		    fail "$(cs_svc "$_cs") is not in the plan"
	done
	grep -q "\"Driver\": \"overlay\"" "$TMPD/csconfig" ||
	    fail "the project network is not an overlay, so the stack could not span the \
cluster (api-compat 112)"
	grep -A 2 '"Aliases"' "$TMPD/csconfig" | grep -q '"redis"' ||
	    fail "no service carries its compose name as a DNS alias, so nothing in the file \
would resolve (api-compat 111)"
	info "plan: project $CS_PROJECT, overlay network, aliases present"

	# --- 2. a refused key is refused before anything is created --------------
	# `build:` under the *web service*, not appended at the end of the file: the
	# refusal has to name the service, and a key appended after the last block
	# would be refused as a secret's key instead.
	node_ssh "$CTL" "awk '{ print } /freebsd-nginx/ { print \"    build: .\" }' \
	    $CS_DIR/compose.yaml > $CS_DIR/broken.yaml" ||
	    fail "could not write the deliberately broken compose file"
	if cs_compose up -c "$CS_DIR/broken.yaml" >"$TMPD/csbroken" 2>&1; then
		show "$TMPD/csbroken"
		fail "a compose file with build: was accepted; a stack cannot build its own images \
(api-compat 181)"
	fi
	# Since M11e the refusal is not "unsupported" but "not here": a built image
	# lands in one node's store and a stack's tasks are placed on any node, so
	# the message names both ways out.
	grep -q 'could not pull the result' "$TMPD/csbroken" ||
	    fail "the refusal does not say why: $(tail -1 "$TMPD/csbroken")"
	grep -q 'satl compose up --build' "$TMPD/csbroken" ||
	    fail "the refusal does not name where a build does work: $(tail -1 "$TMPD/csbroken")"
	grep -q 'broken.yaml' "$TMPD/csbroken" ||
	    fail "the refusal does not name the file: $(tail -1 "$TMPD/csbroken")"
	[ -z "$(cs_services)" ] ||
	    fail "the refused file still created services: $(cs_services | tr '\n' ' ')"
	info "a file with build: is refused naming the file, the service and the key, and \
creates nothing"

	# --- 3. up --------------------------------------------------------------
	#
	# stdout and stderr go to *separate* files here, and that is not tidiness.
	# `compose up` writes its progress to stdout and its warnings to stderr;
	# merged into one file with `2>&1`, stdout is block-buffered (no tty) while
	# stderr is not, so a warning can land in the middle of a progress line and
	# glue two of them together. An anchored grep then fails on output that was
	# perfectly correct -- measured on this scenario, where a second `up`
	# printed `...out of the pool.service cstack_web updated` on one line. Both
	# files are shown, so the warnings stay in the record.
	info "satl compose up (in $CS_DIR)"
	cs_compose up >"$TMPD/csup" 2>"$TMPD/csuperr" || {
		show "$TMPD/csup"
		show "$TMPD/csuperr"
		fail "satl compose up failed"
	}
	show "$TMPD/csup"
	show "$TMPD/csuperr"
	grep -q "^network $(cs_svc default) created$" "$TMPD/csup" ||
	    fail "up did not report creating the project network"
	for _cs in web redis worker; do
		grep -q "^service $(cs_svc "$_cs") created$" "$TMPD/csup" ||
		    fail "up did not report creating $(cs_svc "$_cs")"
	done

	# The network is an overlay the allocator finished with, on every node — the
	# same check overlay_dns_multinet makes, because "created" in the store is
	# not the same as programmed on a node.
	wait_until "$T_QUICK" "$(cs_svc default) has a subnet and a vni on every node" '
		_ok=1
		for _n in $(cluster_nodes); do
			_j=$(node_ssh "$_n" "satl network inspect $(cs_svc default) 2>/dev/null") || _ok=0
			printf %s "$_j" | grep -q "\"Subnet\"" || _ok=0
			printf %s "$_j" | grep -q "\"Vni\"" || _ok=0
		done
		[ "$_ok" = 1 ]'

	# The labels `down` will scope by, as the daemon stored them.
	node_ssh "$CTL" "satl service inspect $(cs_svc web)" >"$TMPD/csinspect" 2>&1 ||
	    fail "satl service inspect $(cs_svc web) failed"
	grep -q "\"com.docker.compose.project\": \"$CS_PROJECT\"" "$TMPD/csinspect" ||
	    fail "$(cs_svc web) does not carry the project label, so down could not scope by \
it (api-compat 117)"
	info "every object carries com.docker.compose.project=$CS_PROJECT"

	# --- 4. converge and spread ---------------------------------------------
	wait_until "$T_CONVERGE" \
	    "web $CS_NODES/$CS_NODES, redis 1/1, worker $CS_NODES/$CS_NODES" 'cs_converged'
	_cs_nodes_running=$(cs_task_nodes | tr '\n' ' ')
	for _n in $(cluster_nodes); do
		printf %s "$_cs_nodes_running" | grep -q "$(host_of "$_n")" ||
		    fail "$_n runs no task of the stack, so the stack is not spread across the \
cluster (running on: $_cs_nodes_running)"
	done
	info "tasks on every node: $_cs_nodes_running"

	# `satl compose ps` is the project-scoped view, and the only assertion that
	# runs it against real tasks: it must list every task of the three services
	# and nothing else, with the suite's own six-replica `web` service running
	# at the same time on the same cluster.
	cs_compose ps >"$TMPD/csps" 2>&1 || {
		show "$TMPD/csps"
		fail "satl compose ps failed"
	}
	_cs_ps_rows=$(tail -n +2 "$TMPD/csps" | grep -c . || true)
	[ "$_cs_ps_rows" = "$((CS_NODES * 2 + 1))" ] ||
	    fail "satl compose ps listed $_cs_ps_rows tasks, not the $((CS_NODES * 2 + 1)) of this \
project: it is either missing the stack's tasks or picking up another project's"
	for _cs in web redis worker; do
		grep -q "$(cs_svc "$_cs")\." "$TMPD/csps" ||
		    fail "satl compose ps does not list $(cs_svc "$_cs")'s tasks"
	done
	info "satl compose ps lists this project's $_cs_ps_rows tasks and no others"

	# --- 5. the published port, on every node -------------------------------
	# web is a global service, so every node runs a task and every node
	# redirects the port to it (api-compat 75: a node with no task would not).
	for _n in $(cluster_nodes); do
		CS_NODE=$_n
		wait_until "$T_QUICK" "$_n answers http://$(node_field "$_n" public_ip):$CS_PORT/" \
		    'printf %s "$(curl -s --max-time 5 "http://$(node_field "$CS_NODE" public_ip):$CS_PORT/" 2>/dev/null)" | grep -q "$OVL_BODY"'
	done
	info "the stack's web service answers on :$CS_PORT on all $CS_NODES nodes"

	# --- 6. the secret: delivered, applied, and on a tmpfs ------------------
	_cs_rjid=$(cs_jid "$_cs_redis_node" redis)
	[ -n "$_cs_rjid" ] ||
	    fail "redis has no running jail on $_cs_redis_node ($_cs_redis_host) — the \
deploy.placement constraint did not hold"
	_cs_mode=$(ovl_in_jail "$_cs_redis_node" "$_cs_rjid" "ls -l /run/secrets/redis.conf" |
	    awk '{ print $1; exit }')
	case $_cs_mode in
	-r--------*) : ;;
	*) fail "the secret file's mode is '$_cs_mode', not the 0400 the compose file asked \
for (api-compat 121: an unquoted 0400 must still mean octal)" ;;
	esac
	_cs_task=$(node_ssh "$CTL" "satl service ps $(cs_svc redis) --quiet --no-trunc 2>/dev/null" |
	    tr -d '\r' | head -1)
	# `mount -p`, not `mount`: these tmpfs are mounted MNT_IGNORE, so plain
	# `mount`, `mount -t tmpfs` and `df -t tmpfs` all show nothing at all
	# (measured on node1 while the stack was up). `-p` and `-v` list them.
	node_root_sh "$_cs_redis_node" "$_cs_task" <<'REMOTE' >"$TMPD/csmount" 2>&1
task=$1
mount -p | grep "$task" || true
REMOTE
	grep -q 'run/secrets tmpfs' "$TMPD/csmount" ||
	    fail "the secret is not on a tmpfs on $_cs_redis_node (invariant 7); mount -p said: \
$(cat "$TMPD/csmount")"
	info "the secret is a 0400 file on a tmpfs in redis's jail on $_cs_redis_node"

	# --- 7. applied, and reached by service name from another node ----------
	# Every question below is asked from the *worker's* jail on another node,
	# against the name `redis`, which makes one round trip answer three things:
	# the compose alias resolves (api-compat 111), the overlay carries the
	# connection, and the payload was applied rather than merely delivered --
	# an unauthenticated PING has to be refused.
	#
	# Not from redis's own jail against 127.0.0.1: a VNET jail has no loopback
	# address configured, so that connect fails with "Can't assign requested
	# address" and proves nothing (measured).
	#
	# The trailing `|| true` is load-bearing under `set -e`, the same way it is
	# in ovl_wait_fetch: an assignment takes the status of its command
	# substitution, and redis-cli exits non-zero on NOAUTH -- which is precisely
	# the answer the first assertion is looking for. Without it the run aborts
	# with no message at all (measured).
	_cs_wjid=$(cs_jid "$_cs_other_node" worker)
	[ -n "$_cs_wjid" ] ||
	    fail "no worker jail on $_cs_other_node, so nothing would cross the underlay"
	_cs_noauth=$(ovl_in_jail "$_cs_other_node" "$_cs_wjid" \
	    "/usr/local/bin/redis-cli -h redis PING" 2>&1 || true)
	printf %s "$_cs_noauth" | grep -q NOAUTH ||
	    fail "an unauthenticated PING to redis answered '$_cs_noauth'. If that is a \
connection error, the compose alias (api-compat 111), the DNS responder's scope (73) or \
the overlay data path is broken; if it is PONG, the secret file was delivered but its \
payload was never applied and nothing here proves it arrived"
	_cs_pong=$(ovl_in_jail "$_cs_other_node" "$_cs_wjid" \
	    'set -- $(cat /run/secrets/redis.conf); REDISCLI_AUTH=$2 /usr/local/bin/redis-cli -h redis PING' 2>&1 || true)
	printf %s "$_cs_pong" | grep -q PONG ||
	    fail "redis refused the password the worker read from its own secret file: '$_cs_pong'"
	info "from the worker on $_cs_other_node: redis resolves by its compose name, refuses an \
unauthenticated PING, and answers PONG with the password from the secret"

	# The workers are not just able to connect, they are working: the counter
	# they increment moves while nothing else touches it.
	_cs_ticks0=$(cs_ticks "$_cs_other_node" "$_cs_wjid")
	[ -n "$_cs_ticks0" ] || fail "cannot read the counter the workers increment"
	wait_until "$T_QUICK" "the workers' counter to move past $_cs_ticks0" \
	    '[ "$(cs_ticks "$_cs_other_node" "$_cs_wjid")" -gt "$_cs_ticks0" ] 2>/dev/null'
	info "the workers keep talking to redis over the overlay (counter past $_cs_ticks0)"

	# --- 8. a second up updates, it does not duplicate ----------------------
	cs_compose up >"$TMPD/csup2" 2>"$TMPD/csup2err" || {
		show "$TMPD/csup2"
		show "$TMPD/csup2err"
		fail "the second satl compose up failed"
	}
	grep -q "^network $(cs_svc default) exists$" "$TMPD/csup2" ||
	    fail "the second up did not reuse the network it created: $(cat "$TMPD/csup2")"
	for _cs in web redis worker; do
		grep -q "^service $(cs_svc "$_cs") updated$" "$TMPD/csup2" ||
		    fail "the second up did not update $(cs_svc "$_cs"): $(cat "$TMPD/csup2")"
	done
	[ "$(cs_services | countl)" = 3 ] ||
	    fail "the second up left $(cs_services | countl) services, not 3: \
$(cs_services | tr '\n' ' ')"
	info "a second up updates the three services against the version it read and creates \
nothing new"

	# --- 9. down removes what up created, and only that ---------------------
	# The decoy shares the project's prefix and carries no compose label. A
	# `down` that removed it would be removing somebody else's service.
	node_ssh "$CTL" "satl service create --name $(cs_svc decoy) --replicas 1 $CS_WEB_IMAGE" \
	    >"$TMPD/csdecoy" 2>&1 || {
		show "$TMPD/csdecoy"
		fail "could not create the decoy service"
	}
	wait_until "$T_CONVERGE" "the decoy $(cs_svc decoy) running" \
	    '[ "$(cs_replicas "$(cs_svc decoy)")" = "1/1" ]'

	CS_IDS=$(cs_task_ids)
	info "auditing the $(printf %s "$CS_IDS" | wc -w | tr -d ' ') tasks of the stack after down"

	# Separate streams, for the reason spelled out at step 3: `down` reports
	# progress on stdout and its waiting notes on stderr, and the greps below
	# are anchored.
	cs_compose down >"$TMPD/csdown" 2>"$TMPD/csdownerr" || {
		show "$TMPD/csdown"
		show "$TMPD/csdownerr"
		fail "satl compose down failed"
	}
	show "$TMPD/csdown"
	show "$TMPD/csdownerr"
	for _cs in web redis worker; do
		grep -q "^service $(cs_svc "$_cs") removed$" "$TMPD/csdown" ||
		    fail "down did not report removing $(cs_svc "$_cs")"
	done
	grep -q "^network $(cs_svc default) removed$" "$TMPD/csdown" ||
	    fail "down did not report removing the project network"
	if grep -q "$(cs_svc decoy)" "$TMPD/csdown"; then
		fail "down mentioned $(cs_svc decoy), which it did not create"
	fi

	[ "$(cs_replicas "$(cs_svc decoy)")" = "1/1" ] ||
	    fail "$(cs_svc decoy) did not survive the down: it shares the project's prefix but \
not its label, and label scoping is the only thing standing between a compose project and \
somebody else's services (api-compat 117)"
	info "$(cs_svc decoy) survived: down is scoped by label, not by name"

	# The secret is not compose's to delete.
	node_ssh "$CTL" "satl secret ls" >"$TMPD/cssecrets2" 2>&1 || fail "satl secret ls failed"
	grep -q "$CS_SECRET" "$TMPD/cssecrets2" ||
	    fail "down removed the secret $CS_SECRET; a compose project refers to cluster \
secret material and must never delete it (api-compat 120)"

	# Audited per task rather than with the suite-wide `leftovers_gone`: this
	# scenario runs while $SERVICE and the decoy are deliberately still there.
	wait_until "$T_CLEAN" "no service, network or task of $CS_PROJECT left anywhere" '
		[ -z "$(cs_services | grep -v _decoy)" ] &&
		    ! node_ssh "$CTL" "satl network inspect $(cs_svc default) >/dev/null 2>&1" &&
		    [ "$(ru_leftovers "$CS_IDS")" = 0 ]'
	wait_until "$T_CLEAN" "no overlay interface of $(cs_svc default) on any node" '
		_left=""
		for _n in $(cluster_nodes); do
			_c=$(ovl_count "$_n" "ifconfig -a" "overlay:$(cs_svc default)")
			_c=$((_c + $(ovl_count "$_n" "ifconfig -a" "vxlan:$(cs_svc default)")))
			[ "$_c" = 0 ] || _left="$_left $_n"
		done
		[ -z "$_left" ]'
	info "every jail, epair, dataset and overlay interface of the stack is gone from every node"

	# And the secret's tmpfs with them: a payload left mounted after its task
	# died would still be a payload in memory (invariant 7). Only the secret
	# mount is asserted, because SatL leaks the per-task /tmp tmpfs of every
	# container it removes -- a pre-existing defect the jail/epair/dataset audit
	# cannot see, recorded here rather than papered over.
	wait_until "$T_CLEAN" "no secret tmpfs of the stack's tasks left on any node" '
		_left=""
		for _n in $(cluster_nodes); do
			_m=$(cs_secret_mounts "$_n" "$CS_IDS") || return 1
			[ "$_m" = 0 ] || _left="$_left $_n($_m)"
		done
		[ -z "$_left" ]'
	info "no secret tmpfs left mounted anywhere"

	# --- the daemon's own account -------------------------------------------
	state_fetch "$CTL"
	_cs_leader=$(node_of_host "$(leader_host)")
	[ -n "$_cs_leader" ] || fail "cannot tell which node is the leader"
	ru_log_tail "$_cs_leader" "service created|service removed|network created|network removed" 8

	# --- restore the baseline -----------------------------------------------
	node_ssh "$CTL" "satl service rm $(cs_svc decoy)" >/dev/null 2>&1 || true
	node_ssh "$CTL" "satl secret rm $CS_SECRET" >/dev/null 2>&1 || true
	node_ssh "$CTL" "rm -rf $CS_DIR" >/dev/null 2>&1 || true
	wait_until "$T_CLEAN" "the decoy and the secret gone too" '
		[ -z "$(cs_services)" ] &&
		    ! node_ssh "$CTL" "satl secret inspect $CS_SECRET >/dev/null 2>&1"'
	info "compose stack deployed, proven and removed; cluster left as it was"
}

# ===========================================================================
# mesh_failed_start — B1 non-regression
#
# B1 was a corrected BLOCKER: a task that dies before its first healthcheck
# could leave its overlay attachment behind on the node; the address allocator
# then hands the same address to a replacement elsewhere, the endpoint reads
# "both local and remote" on this node, the FDB pass refuses to program it,
# and about a third of the mesh's traffic silently went nowhere (measured).
# The fix is the dead-attachment sweep in satld's overlay resync
# (crates/satld/src/overlay.rs, detach_dead_attachments). This scenario is the
# audit's replayed trigger, run as a non-regression:
#
#   - $MF_FLAP: $MF_REPLICAS replicas of a container that exits 1 after two
#     seconds, a healthcheck whose first probe cannot run before the death
#     (the prober's first probe is one interval after start, and the interval
#     here is 10s), an explicit ${MF_DELAY}s restart delay (the 5s default of
#     80e179f would pace the storm, not the code), unlimited attempts, and a
#     published port so every death churns the ingress overlay. Through the
#     REST API because the CLI has no healthcheck or restart-delay flags
#     (api_create documents the same gap for restart_budget);
#   - $MF_GOOD: $MF_REPLICAS replicas with a published port, created while the
#     storm is already running — its endpoints are exactly what a stale
#     attachment would collide with;
#   - $MF_REQUESTS requests from this host through EACH node's public address
#     on the good service's port, all of which must return the nginx body,
#     while the storm keeps flapping (asserted: the flap's task-row count must
#     keep growing after the request loop, or the storm stopped and the
#     requests proved nothing);
#   - zero "both local and remote" lines in /var/log/messages on every node.
#     The current file only, per the audit's recipe: a rotated-away line is an
#     old run's, and a conflict from *this* run lands in the current file
#     because the storm and the read are minutes apart while rotation is
#     hourly;
#   - teardown leaves no jail, epair, dataset or mount anywhere.
# ===========================================================================

# mf_spec <image> — the flap service: dies before its first healthcheck,
# forever, published.
mf_spec() {
	cat <<JSON | tr -d '\n\t'
{
	"Name": "$MF_FLAP",
	"TaskTemplate": {
		"ContainerSpec": {
			"Image": "$1",
			"Command": ["/bin/sh", "-c", "sleep 2; exit 1"],
			"Healthcheck": {
				"Test": ["CMD-SHELL", "true"],
				"Interval": 10000000000,
				"Timeout": 5000000000,
				"Retries": 1,
				"StartPeriod": 0
			}
		},
		"RestartPolicy": {"Condition": "any", "Delay": ${MF_DELAY}000000000, "MaxAttempts": 0}
	},
	"Mode": {"Replicated": {"Replicas": $MF_REPLICAS}},
	"EndpointSpec": {
		"Ports": [{
			"Protocol": "tcp", "TargetPort": 80,
			"PublishedPort": $MF_FLAP_PORT, "PublishMode": "ingress"
		}]
	}
}
JSON
}

# mf_conflicts <node> — how many "both local and remote" overlay conflicts the
# node's current /var/log/messages carries. `grep -a`, not optional (one
# non-ASCII byte anywhere in the file makes plain grep read it as binary and
# print nothing — indistinguishable from "no conflict", which is the passing
# answer here; CLAUDE.md). "MISSING" when the file itself cannot be read, so
# that case can never pass as a zero.
mf_conflicts() {
	node_root_sh "$1" <<'REMOTE' 2>/dev/null
if [ -f /var/log/messages ]; then
	grep -ac "both local and remote" /var/log/messages || true
else
	echo MISSING
fi
REMOTE
}

# mf_serve <node> <count> — how many of <count> requests through that node's
# public address on the good service's port returned the nginx body.
mf_serve() {
	_mfs_ip=$(node_field "$1" public_ip)
	_mfs_ok=0
	_mfs_i=0
	while [ "$_mfs_i" -lt "$2" ]; do
		_mfs_i=$((_mfs_i + 1))
		_mfs_body=$(curl -s --max-time 5 "http://$_mfs_ip:$MF_GOOD_PORT/" 2>/dev/null || true)
		case $_mfs_body in
		*"$OVL_BODY"*) _mfs_ok=$((_mfs_ok + 1)) ;;
		esac
	done
	echo "$_mfs_ok"
}

scenario_mesh_failed_start() {
	m4_prelude
	svc_rm_audited "$MF_FLAP"
	svc_rm_audited "$MF_GOOD"

	# --- 1. the flap storm --------------------------------------------------
	info "POST /services/create: $MF_FLAP, $MF_REPLICAS replicas exiting 1 after 2s, \
first healthcheck probe at 10s, restart delay ${MF_DELAY}s, published :$MF_FLAP_PORT"
	api_create "$(mf_spec "$IMAGE")"
	wait_until "$T_CONVERGE" "$MF_FLAP crash-looping (more task rows than replicas)" \
		'tasks_fetch "$MF_FLAP" && [ "$(tasks_rows)" -gt "$MF_REPLICAS" ]'
	info "$MF_FLAP is crash-looping: $(tasks_rows) task rows for $MF_REPLICAS replicas"

	# --- 2. a healthy published service, deployed into the storm --------------
	info "satl service create --name $MF_GOOD --replicas $MF_REPLICAS -p $MF_GOOD_PORT:80"
	node_ssh "$CTL" "satl service create --name $MF_GOOD --replicas $MF_REPLICAS \
	    -p $MF_GOOD_PORT:80 $IMAGE" >"$TMPD/mfcreate" 2>&1 || {
		show "$TMPD/mfcreate"
		fail "satl service create $MF_GOOD failed on $CTL"
	}
	wait_until "$T_CONVERGE" "$MF_GOOD at $MF_REPLICAS live tasks, mid-storm" \
		'tasks_fetch "$MF_GOOD" && [ "$(tasks_live_total)" = "$MF_REPLICAS" ]'

	# --- 3. every node serves on the published port, during the storm ---------
	# First each node must answer at all (its pf redirect is re-derived on a
	# 5s pass after the task goes live — publish_port does the same), so the
	# counted loop below measures the storm's effect and not the warmup.
	for _n in $(cluster_nodes); do
		MF_NODE=$_n
		wait_until "$T_QUICK" \
		    "$_n answers http://$(node_field "$_n" public_ip):$MF_GOOD_PORT/, mid-storm" \
		    '[ "$(mf_serve "$MF_NODE" 1)" = 1 ]'
	done
	tasks_fetch "$MF_FLAP" || fail "$CTL cannot list $MF_FLAP's tasks"
	_mf_rows0=$(tasks_rows)
	_mf_bad=""
	for _n in $(cluster_nodes); do
		_mf_ok=$(mf_serve "$_n" "$MF_REQUESTS")
		if [ "$_mf_ok" = "$MF_REQUESTS" ]; then
			info "$_n: $MF_REQUESTS/$MF_REQUESTS requests through :$MF_GOOD_PORT returned the body"
		else
			log "  $_n: only $_mf_ok/$MF_REQUESTS requests through :$MF_GOOD_PORT returned the body"
			_mf_bad="$_mf_bad $_n"
		fi
	done
	[ -z "$_mf_bad" ] || fail "requests through the published port failed on:$_mf_bad — \
the B1 storm black-holed the healthy service again"
	# The storm must outlive the requests, or they measured a quiet cluster. A
	# bounded wait rather than a second point sample: one flap round (2s alive
	# + ${MF_DELAY}s delay + reschedule) is longer than the request loop, so
	# two samples can legitimately straddle it — but a storm that has actually
	# stopped never grows again and times out here.
	wait_until "$T_QUICK" "$MF_FLAP still flapping after the request loop" \
	    'tasks_fetch "$MF_FLAP" && [ "$(tasks_rows)" -gt "$_mf_rows0" ]'

	# --- 4. the B1 signature: no endpoint "both local and remote" anywhere ----
	for _n in $(cluster_nodes); do
		_mf_hits=$(mf_conflicts "$_n")
		case $_mf_hits in
		0)
			info "$_n: no 'both local and remote' overlay conflict in /var/log/messages"
			;;
		MISSING | "")
			fail "cannot read /var/log/messages on $_n — the zero-conflict \
assertion needs the file, not its absence"
			;;
		*)
			node_root_sh "$_n" <<'REMOTE' 2>/dev/null | sed 's/^/    /' || true
grep -a "both local and remote" /var/log/messages | tail -5
REMOTE
			fail "$_n logged $_mf_hits 'both local and remote' overlay conflict(s): a \
stale attachment claimed a re-allocated address, which is B1 back"
			;;
		esac
	done

	# --- 5. teardown leaves nothing -------------------------------------------
	svc_rm_audited "$MF_FLAP"
	svc_rm_audited "$MF_GOOD"
	wait_until "$T_CLEAN" "no jails, task epairs, container datasets or mounts left anywhere" \
	    'leftovers_gone'
	info "storm over, mesh clean, hosts clean"
}

# ===========================================================================
# build_push_run — M6f build, M7b cache, M8a push, M8b tag, M8c run
#
# One flow over the whole image lifecycle the audit found uncovered (N2 live):
#
#   1. a Satlfile (FROM the seeded freebsd-runtime base + one COPY) is built
#      on the bootstrap node with the build cache wiped first, timed — the
#      cold build;
#   2. the identical build again, timed — the warm rebuild, which must not be
#      slower, and must be at least twice as fast when the cold build was slow
#      enough (the base pull dominates a first run; on later runs only the
#      record is meaningful);
#   3. the cold build's output must carry the N3 warning: on a multi-node
#      cluster an unpushed image exists in this node's store only, and the
#      build says so naming the reference;
#   4. `satl tag` to a registry reference and `satl push` — into the *first
#      joiner's* registry, because "the image runs somewhere else than it was
#      built" is the point. Every node's registry is loopback-only
#      (tests/cluster/images.sh), so the push crosses a two-hop ssh tunnel
#      this host holds: `-L` from this host into the joiner's registry, `-R`
#      from the build node back to this host's hop port. The pushed digest is
#      read back from the joiner's own loopback registry and must match;
#   5. a service pinned to the joiner by constraint runs the pushed reference:
#      one task RUNNING on that node, and the marker file the Satlfile COPYed
#      in must appear in the task's logs;
#   6. teardown: the service audited away, the pushed manifest deleted from
#      the joiner's registry (its storage lives outside zroot/satl, so
#      reset.sh would not take it), the build directory removed, the tunnel
#      down.
#
# The brief's bonus (tag, remove the source reference, run from the target) IS
# covered since M9: `satl images rm` and `DELETE /images/{name}` exist, so
# "forget the source reference and prove the target still runs" is now
# expressible. Step 7 below does it. Until M9 it was not: `/images/{name}`
# served only POST .../tag, and prune knew only dangling/all.
# ===========================================================================

# bp_registry_digest — the digest the joiner's own registry serves for the
# pushed tag, empty when it is not there. Read on the joiner, loopback, so
# what is checked is the registry the joiner's satld will pull from.
bp_registry_digest() {
	node_sh "$BP_RUN" "$REG_PORT" "$REG_NS/$BP_NAME" "$BP_TAG" <<'REMOTE' 2>/dev/null
port=$1
repo=$2
tag=$3
curl -sf -o /dev/null -D - \
    -H 'Accept:application/vnd.oci.image.manifest.v1+json' \
    -H 'Accept:application/vnd.oci.image.index.v1+json' \
    "http://127.0.0.1:$port/v2/$repo/manifests/$tag" 2>/dev/null |
    awk 'tolower($1) == "docker-content-digest:" { print $2 }' | tr -d '\r'
REMOTE
}

# bp_registry_delete — remove the pushed manifest from the joiner's registry
# (deletion is enabled in its config, images.sh). Best-effort: never fatal.
bp_registry_delete() {
	node_sh "$BP_RUN" "$REG_PORT" "$REG_NS/$BP_NAME" "$BP_TAG" <<'REMOTE' 2>/dev/null || true
port=$1
repo=$2
tag=$3
digest=$(curl -sf -o /dev/null -D - \
    -H 'Accept:application/vnd.oci.image.manifest.v1+json' \
    -H 'Accept:application/vnd.oci.image.index.v1+json' \
    "http://127.0.0.1:$port/v2/$repo/manifests/$tag" 2>/dev/null |
    awk 'tolower($1) == "docker-content-digest:" { print $2 }' | tr -d '\r')
[ -n "$digest" ] || exit 0
curl -sf -X DELETE "http://127.0.0.1:$port/v2/$repo/manifests/$digest" >/dev/null 2>&1 || exit 1
REMOTE
}

# bp_tunnel_down — kill the two forwarders and disarm the EXIT trap's copy.
bp_tunnel_down() {
	if [ -n "$BP_TUNNEL_PIDS" ]; then
		# shellcheck disable=SC2086  # PID list must word-split
		kill $BP_TUNNEL_PIDS 2>/dev/null || true
		BP_TUNNEL_PIDS=""
	fi
}

scenario_build_push_run() {
	m4_prelude
	BP_BUILD=$(bootstrap_node)
	BP_RUN=$(nodes_with_role joiner | sed -n 1p)
	[ -n "$BP_RUN" ] ||
	    fail "build_push_run needs a joiner node to push to and run on"
	BP_RUN_HOST=$(host_of "$BP_RUN")
	BP_PUSH_REF="127.0.0.1:$BP_TUN_PORT/$REG_NS/$BP_NAME:$BP_TAG"
	BP_PULL_REF="127.0.0.1:$REG_PORT/$REG_NS/$BP_NAME:$BP_TAG"
	info "build on $BP_BUILD, push to $BP_RUN's registry over the tunnel, run on $BP_RUN ($BP_RUN_HOST)"

	# A previous run of this scenario alone may have left any of these behind.
	svc_rm_audited "$BP_SVC"
	node_ssh "$BP_BUILD" "rm -rf $BP_DIR" >/dev/null 2>&1 || true
	bp_registry_delete

	# --- 1. the Satlfile ------------------------------------------------------
	node_sh "$BP_BUILD" "$BP_DIR" "$BP_BASE" "$BP_MARKER" <<'REMOTE' ||
dir=$1
base=$2
marker=$3
rm -rf "$dir"
mkdir -p "$dir"
printf '%s\n' "$marker" >"$dir/marker.txt"
cat >"$dir/Satlfile" <<EOF
FROM $base
COPY marker.txt /etc/satl-built-marker.txt
EOF
REMOTE
	    fail "cannot write the Satlfile on $BP_BUILD"

	# --- 2. cold build (cache wiped first, so a re-run's cold is cold too) ----
	node_root_sh "$BP_BUILD" "$STATE_DIR" <<'REMOTE' >/dev/null 2>&1
rm -rf "$1/build-cache"
REMOTE
	_bp_t0=$(date +%s)
	if ! node_root_sh "$BP_BUILD" "$BP_DIR/Satlfile" "$BP_LOCAL" <<'REMOTE' >"$TMPD/bpcold" 2>&1; then
satl build -t "$2" -f "$1"
REMOTE
		show "$TMPD/bpcold"
		fail "the cold build failed on $BP_BUILD"
	fi
	BP_COLD=$(($(date +%s) - _bp_t0))
	grep -q "Built and registered" "$TMPD/bpcold" || {
		show "$TMPD/bpcold"
		fail "the cold build did not confirm registration on $BP_BUILD"
	}
	# --- 3. the N3 warning: a local-only image on a multi-node cluster --------
	grep -q "exists only in this node's local store" "$TMPD/bpcold" || {
		show "$TMPD/bpcold"
		fail "the cold build printed no local-store warning: on a 3-node cluster an \
unpushed image is runnable nowhere else, and the build must say so (N3)"
	}
	info "cold build: ${BP_COLD}s, registered $BP_LOCAL, local-store warning printed"

	# --- 4. warm rebuild --------------------------------------------------------
	_bp_t0=$(date +%s)
	if ! node_root_sh "$BP_BUILD" "$BP_DIR/Satlfile" "$BP_LOCAL" <<'REMOTE' >"$TMPD/bpwarm" 2>&1; then
satl build -t "$2" -f "$1"
REMOTE
		show "$TMPD/bpwarm"
		fail "the warm rebuild failed on $BP_BUILD"
	fi
	BP_WARM=$(($(date +%s) - _bp_t0))
	info "warm rebuild: ${BP_WARM}s (cold was ${BP_COLD}s)"
	# The base image stays in the store across runs (nothing can remove it —
	# there is no image-rm verb), so only the first run after a reset pays the
	# pull and the difference between the two builds is small and noisy.
	#
	# BOTH comparisons are therefore gated on the same threshold. "Warm must
	# not be slower" used not to be, and it failed a whole suite run on
	# `cold: 1s, warm: 2s` — one second of ssh jitter, at one-second
	# granularity, on builds too short to measure. An assertion that can only
	# be read as "the build cache made things worse" must not fire on noise:
	# it sends the reader after a performance regression that never happened,
	# which is the same class of harm as a misleading error message.
	if [ "$BP_COLD" -ge 8 ]; then
		[ "$BP_WARM" -le "$BP_COLD" ] ||
		    fail "the warm rebuild (${BP_WARM}s) was slower than the cold build \
(${BP_COLD}s): the build cache made things worse"
		[ "$((BP_WARM * 2))" -le "$BP_COLD" ] ||
		    fail "the warm rebuild (${BP_WARM}s) was faster than cold (${BP_COLD}s) but \
not by half: the cache hit re-executed work it should have skipped"
		info "warm at $((BP_WARM * 100 / BP_COLD))% of cold — the cache did its work"
	else
		info "cold build under 8s (base already in the store) — both timing \
comparisons would measure ssh jitter, recorded only"
	fi

	# --- 5. the two-hop tunnel: build node -> this host -> the joiner's registry --
	# -L: this host's $BP_HOP_PORT answers with $BP_RUN's loopback registry.
	# -R: $BP_BUILD's $BP_TUN_PORT answers with this host's $BP_HOP_PORT.
	# The push then talks plain HTTP to a loopback address on the build node
	# (the only registry shape satl-image speaks plain HTTP to) and lands in
	# the joiner's registry. ExitOnForwardFailure makes a port clash loud
	# instead of silently pushing into the wrong registry.
	# shellcheck disable=SC2086  # SSH_OPTS must word-split
	ssh $SSH_OPTS -o ExitOnForwardFailure=yes -N \
	    -L "127.0.0.1:$BP_HOP_PORT:127.0.0.1:$REG_PORT" \
	    "$(node_target "$BP_RUN")" &
	BP_HOP_PID=$!
	# shellcheck disable=SC2086
	ssh $SSH_OPTS -o ExitOnForwardFailure=yes -N \
	    -R "127.0.0.1:$BP_TUN_PORT:127.0.0.1:$BP_HOP_PORT" \
	    "$(node_target "$BP_BUILD")" &
	BP_TUN_PID=$!
	BP_TUNNEL_PIDS="$BP_HOP_PID $BP_TUN_PID"
	wait_until "$T_QUICK" "the tunnel: $BP_BUILD reaches $BP_RUN's registry on 127.0.0.1:$BP_TUN_PORT" '
		kill -0 "$BP_HOP_PID" 2>/dev/null && kill -0 "$BP_TUN_PID" 2>/dev/null &&
		node_ssh "$BP_BUILD" "curl -sf --max-time 3 http://127.0.0.1:$BP_TUN_PORT/v2/ >/dev/null 2>&1"'

	# --- 6. tag and push --------------------------------------------------------
	node_ssh "$BP_BUILD" "satl tag $BP_LOCAL $BP_PUSH_REF" >"$TMPD/bptag" 2>&1 || {
		show "$TMPD/bptag"
		fail "satl tag $BP_LOCAL $BP_PUSH_REF failed on $BP_BUILD"
	}
	if ! node_root_sh "$BP_BUILD" "$BP_PUSH_REF" <<'REMOTE' >"$TMPD/bppush" 2>&1; then
satl push "$1"
REMOTE
		show "$TMPD/bppush"
		fail "satl push $BP_PUSH_REF failed on $BP_BUILD"
	fi
	show "$TMPD/bppush"
	_bp_pushed=$(sed -n 's/.*(manifest \(sha256:[a-f0-9]*\)).*/\1/p' "$TMPD/bppush")
	[ -n "$_bp_pushed" ] || {
		show "$TMPD/bppush"
		fail "the push output carries no manifest digest"
	}

	# --- 7. the joiner's own registry serves exactly that digest -----------------
	wait_until "$T_QUICK" "$BP_RUN's registry serves $REG_NS/$BP_NAME:$BP_TAG" \
	    '[ -n "$(bp_registry_digest)" ]'
	_bp_served=$(bp_registry_digest)
	[ "$_bp_served" = "$_bp_pushed" ] ||
	    fail "$BP_RUN's registry serves manifest $_bp_served for $BP_TAG, but the push \
reported $_bp_pushed: the image that would run is not the image that was pushed"

	# --- 8. run the pushed image, pinned to the joiner ---------------------------
	if ! node_sh "$CTL" "$BP_SVC" "$BP_RUN_HOST" "$BP_PULL_REF" <<'REMOTE' >"$TMPD/bpcreate" 2>&1; then
svc=$1
host=$2
img=$3
satl service create --name "$svc" --replicas 1 --constraint "node.hostname==$host" "$img" \
    /bin/sh -c 'cat /etc/satl-built-marker.txt; sleep 3600'
REMOTE
		show "$TMPD/bpcreate"
		fail "satl service create $BP_SVC failed on $CTL"
	fi
	wait_until "$T_CONVERGE" "$BP_SVC RUNNING on $BP_RUN_HOST (pulled from $BP_RUN's own registry)" '
		tasks_fetch "$BP_SVC" && [ "$(tasks_live_total)" = 1 ] &&
		[ "$(tasks_live_on "$BP_RUN_HOST")" = 1 ]'
	BP_TASK=$(node_ssh "$CTL" "satl service ps $BP_SVC --quiet --no-trunc 2>/dev/null" |
	    tr -d '\r' | head -1)
	[ -n "$BP_TASK" ] || fail "$BP_SVC has no task id to read logs from"
	[ "$(tasks_live_images)" = "$BP_PULL_REF" ] ||
	    fail "$BP_SVC runs '$(tasks_live_images)', not the pushed reference $BP_PULL_REF"
	wait_until "$T_QUICK" "the task's logs carry the COPYed marker" \
	    'node_ssh "$BP_RUN" "satl logs $BP_TASK 2>/dev/null" | grep -q "$BP_MARKER"'
	info "task $BP_TASK runs the pushed image on $BP_RUN and logged the marker"

	# --- 9. teardown --------------------------------------------------------------
	svc_rm_audited "$BP_SVC"
	node_ssh "$BP_BUILD" "rm -rf $BP_DIR" >/dev/null 2>&1 || true
	bp_registry_delete
	# Not a warn: the registry lives outside zroot/satl, so reset.sh never
	# reclaims this — a leftover here is a real leak the scenario must not
	# pass over. bp_registry_digest is empty exactly when the manifest is
	# gone (a 404 makes curl -sf print nothing), so a non-empty answer is
	# always a true positive.
	_bp_left=$(bp_registry_digest)
	[ -z "$_bp_left" ] ||
	    fail "$REG_NS/$BP_NAME:$BP_TAG is still in $BP_RUN's registry after deletion \
(manifest $_bp_left): the DELETE failed and nothing else will ever reclaim it"
	bp_tunnel_down
	wait_until "$T_CLEAN" "no jails, task epairs, container datasets or mounts left anywhere" \
	    'leftovers_gone'
	info "built (${BP_COLD}s cold / ${BP_WARM}s warm), pushed, ran on $BP_RUN, removed"
}

# ===========================================================================
# stack_verbs — B3 non-regression
#
# B3: `satl stack services` rendered every service 0/N — the stack read path
# dropped the ServiceStatus the daemon sent, so a healthy stack looked empty.
# This scenario drives a two-service stack through every `satl stack` verb and
# asserts the read side tells the truth:
#
#   - `stack deploy` from a Compose file (two replicated services, two
#     replicas each — global modes would make "N/N" vacuous against a count
#     that is always the node count);
#   - `stack ls` lists the stack with SERVICES = 2;
#   - `stack services` converges to 2/2 for both services — the B3 shape is
#     exactly "never leaves 0/2", which this wait fails on by timeout;
#   - `stack ps` lists the four tasks, all Running, each named after a stack
#     service and placed on a node this suite knows;
#   - `stack rm` removes both services and leaves nothing — no stack in
#     `stack ls`, no jail/epair/dataset/mount on any node.
# ===========================================================================

# sv_stack <args...> — `satl stack <args>` in the stack directory on $CTL.
sv_stack() {
	node_sh "$CTL" "$SV_DIR" "$@" <<'REMOTE'
dir=$1
shift
cd "$dir" || exit 1
satl stack "$@"
REMOTE
}

# sv_leftovers — this stack's service names as the daemon lists them, empty
# when none (or when the manager cannot answer, which a wait reads as not
# converged yet).
sv_leftovers() {
	node_ssh "$CTL" "satl service ls 2>/dev/null" >"$TMPD/svls" 2>/dev/null || return 0
	tcols "$TMPD/svls" NAME | awk -v p="${SV}_" 'index($1, p) == 1'
}

# sv_services — capture `satl stack services $SV` for the REPLICAS reads.
sv_services() {
	node_ssh "$CTL" "satl stack services $SV 2>/dev/null" >"$TMPD/svsvc" 2>/dev/null || return 1
	[ -s "$TMPD/svsvc" ] || return 1
}

sv_replicas() {
	tcols "$TMPD/svsvc" 'NAME,REPLICAS' | awk -F'\t' -v s="${SV}_$1" '$1 == s { print $2 }'
}

scenario_stack_verbs() {
	m4_prelude

	# A previous run of this scenario alone may have left the stack behind.
	node_ssh "$CTL" "satl stack rm $SV >/dev/null 2>&1" || true
	node_ssh "$CTL" "rm -rf $SV_DIR" >/dev/null 2>&1 || true
	wait_until "$T_CLEAN" "no leftover ${SV}_ services" \
	    'state_fetch "$CTL" && [ -z "$(sv_leftovers)" ]'

	# --- the file ---------------------------------------------------------------
	# Both services run the nginx image: freebsd-redis deliberately refuses to
	# start without its secret (its baked-in config does `include
	# /run/secrets/redis.conf` — hack/images/build-freebsd-redis.sh), and this
	# scenario is about the stack verbs, not about secrets.
	node_sh "$CTL" "$SV_DIR" "$CS_WEB_IMAGE" "$SV_REPLICAS" <<'REMOTE' ||
dir=$1
nginx=$2
replicas=$3
rm -rf "$dir"
mkdir -p "$dir"
cat >"$dir/compose.yaml" <<EOF
services:
  web:
    image: $nginx
    deploy:
      replicas: $replicas
  side:
    image: $nginx
    deploy:
      replicas: $replicas
EOF
REMOTE
	    fail "cannot write the compose file on $CTL"

	# --- deploy -------------------------------------------------------------------
	info "satl stack deploy -c $SV_DIR/compose.yaml $SV"
	sv_stack deploy -c "$SV_DIR/compose.yaml" "$SV" >"$TMPD/svdeploy" 2>&1 || {
		show "$TMPD/svdeploy"
		fail "satl stack deploy $SV failed"
	}
	show "$TMPD/svdeploy"
	grep -q "^network ${SV}_default created$" "$TMPD/svdeploy" ||
	    fail "stack deploy did not report creating ${SV}_default"
	for _sv in web side; do
		grep -q "^service ${SV}_${_sv} created$" "$TMPD/svdeploy" ||
		    fail "stack deploy did not report creating ${SV}_${_sv}"
	done

	# --- ls -------------------------------------------------------------------------
	node_ssh "$CTL" "satl stack ls" >"$TMPD/svls" 2>&1 || {
		show "$TMPD/svls"
		fail "satl stack ls failed"
	}
	_sv_count=$(tcols "$TMPD/svls" 'NAME,SERVICES' | awk -F'\t' -v s="$SV" '$1 == s { print $2 }')
	[ "$_sv_count" = 2 ] ||
	    fail "satl stack ls shows SERVICES='${_sv_count:-<no row>}' for $SV, expected 2"
	info "satl stack ls: $SV, 2 services"

	# --- services: the B3 assertion ---------------------------------------------------
	wait_until "$T_CONVERGE" \
	    "stack services: ${SV}_web and ${SV}_side at $SV_REPLICAS/$SV_REPLICAS (not 0/$SV_REPLICAS)" '
		sv_services &&
		[ "$(sv_replicas web)" = "$SV_REPLICAS/$SV_REPLICAS" ] &&
		[ "$(sv_replicas side)" = "$SV_REPLICAS/$SV_REPLICAS" ]'
	sv_services
	show "$TMPD/svsvc"

	# --- ps ------------------------------------------------------------------------------
	node_ssh "$CTL" "satl stack ps $SV" >"$TMPD/svps" 2>&1 || {
		show "$TMPD/svps"
		fail "satl stack ps $SV failed"
	}
	show "$TMPD/svps"
	_sv_rows=$(tcols "$TMPD/svps" 'NAME,NODE,DESIRED STATE,CURRENT STATE' | countl)
	[ "$_sv_rows" = "$((SV_REPLICAS * 2))" ] ||
	    fail "satl stack ps lists $_sv_rows tasks, expected $((SV_REPLICAS * 2))"
	tcols "$TMPD/svps" 'NAME,NODE,DESIRED STATE,CURRENT STATE' |
	    while read -r _svn _svnode _svd _svc; do
		    case $_svn in
		    "${SV}_web".* | "${SV}_side".*) : ;;
		    *) echo "    unexpected task name: $_svn" ;;
		    esac
		    case $_svc in
		    Running*) : ;;
		    *) echo "    $_svn is not Running: $_svc" ;;
		    esac
		    grep -q "^$_svnode " "$HOSTMAP" || echo "    $_svn on unknown node: $_svnode"
	    done >"$TMPD/svpsbad"
	if [ -s "$TMPD/svpsbad" ]; then
		cat "$TMPD/svpsbad"
		fail "satl stack ps output is not coherent (above)"
	fi
	info "satl stack ps: $((SV_REPLICAS * 2)) tasks, all Running, all named and placed coherently"

	# --- rm ---------------------------------------------------------------------------------
	sv_stack rm "$SV" >"$TMPD/svrm" 2>&1 || {
		show "$TMPD/svrm"
		fail "satl stack rm $SV failed"
	}
	wait_until "$T_CLEAN" "stack $SV gone: no services, nothing on the hosts" '
		state_fetch "$CTL" && [ -z "$(sv_leftovers)" ] && leftovers_gone'
	node_ssh "$CTL" "satl stack ls" >"$TMPD/svls" 2>&1 || fail "satl stack ls failed after rm"
	if tcols "$TMPD/svls" NAME | grep -qx "$SV"; then
		show "$TMPD/svls"
		fail "$SV is still in satl stack ls after stack rm"
	fi
	node_ssh "$CTL" "rm -rf $SV_DIR" >/dev/null 2>&1 || true
	info "satl stack rm left no service, no stack row and nothing on any host"
}

# ===========================================================================
# jobs_and_prefs — M7d jobs, M7e spread preference
#
#   1. $JP_RJOB: a replicated job, MaxConcurrent and TotalCompletions both 2
#      (what Docker's CLI makes of `--replicas 2` on a replicated job). Both
#      runs must reach Complete, and then NOTHING may happen again: no third
#      task, none back to Running — a clean exit is a success a job never
#      retries (SWK §3.4), held for SATL_T_SETTLE because "it did not happen"
#      can only be watched;
#   2. $JP_GJOB: a global job — exactly one run per node, all Complete, and
#      the same held stillness;
#   3. $JP_SPREAD: four replicas with `--placement-pref
#      spread=node.labels.$JP_ZONE` over two zones — the first inventory node
#      labelled `east`, the other two `west`. The spread must land 2 per zone
#      (the empty-label group would be a third value, so the third node is
#      labelled too — an unlabelled node would absorb replicas and make "2 per
#      zone" untestable). The labels are removed at both ends, and the removal
#      is read back.
# ===========================================================================

# jp_label / jp_unlabel_all — set or drop the zone label, by inventory name.
# Unlabel is idempotent and quiet (a previous run may have failed with the
# label in either state).
jp_label() {
	node_ssh "$CTL" "satl node update --label-add $JP_ZONE=$2 $(host_of "$1")" \
	    >"$TMPD/jplabel" 2>&1 || {
		show "$TMPD/jplabel"
		fail "satl node update --label-add $JP_ZONE=$2 $(host_of "$1") failed"
	}
}

jp_unlabel_all() {
	for _jpu in $(cluster_nodes); do
		node_ssh "$CTL" "satl node update --label-rm $JP_ZONE $(host_of "$_jpu")" \
		    >/dev/null 2>&1 || true
	done
}

# jp_rjob_spec / jp_gjob_spec <image> — the two job services, through the REST
# API for the reason api_create documents: the CLI maps a trailing command to
# ContainerSpec.Args, which the image's own entrypoint then leads — and the
# nginx test image's entrypoint is nginx itself, so `nginx -g ... /bin/sh -c
# 'exit 0'` exits 1 instead of running the shell (measured here: the jobs
# crash-looped). A REST "Command" replaces the entrypoint.
jp_rjob_spec() {
	cat <<JSON | tr -d '\n\t'
{
	"Name": "$JP_RJOB",
	"TaskTemplate": {
		"ContainerSpec": {
			"Image": "$1",
			"Command": ["/bin/sh", "-c", "exit 0"]
		}
	},
	"Mode": {"ReplicatedJob": {"MaxConcurrent": 2, "TotalCompletions": 2}}
}
JSON
}

jp_gjob_spec() {
	cat <<JSON | tr -d '\n\t'
{
	"Name": "$JP_GJOB",
	"TaskTemplate": {
		"ContainerSpec": {
			"Image": "$1",
			"Command": ["/bin/sh", "-c", "exit 0"]
		}
	},
	"Mode": {"GlobalJob": {}}
}
JSON
}

scenario_jobs_and_prefs() {
	m4_prelude
	svc_rm_audited "$JP_RJOB"
	svc_rm_audited "$JP_GJOB"
	svc_rm_audited "$JP_SPREAD"
	jp_unlabel_all

	# --- 1. the replicated job ---------------------------------------------------
	info "POST /services/create: $JP_RJOB, replicated-job, 2 completions of 'exit 0'"
	api_create "$(jp_rjob_spec "$IMAGE")"
	wait_until "$T_CONVERGE" "$JP_RJOB: both runs Complete" '
		tasks_fetch "$JP_RJOB" && [ "$(tasks_rows)" -ge 2 ] &&
		[ "$(tasks_complete_n)" = 2 ]'
	[ "$(tasks_rows)" = 2 ] ||
	    fail "$JP_RJOB has $(tasks_rows) task rows, not 2: a clean exit was retried \
somewhere (a job never retries a success)"
	hold_for "$T_SETTLE" "$JP_RJOB stays at 2 Complete tasks, none relaunched" '
		tasks_fetch "$JP_RJOB" && [ "$(tasks_rows)" = 2 ] &&
		[ "$(tasks_complete_n)" = 2 ] && [ "$(tasks_running_n)" = 0 ]'
	info "$JP_RJOB ran to completion: 2 Complete, no relaunch"
	svc_rm_audited "$JP_RJOB"

	# --- 2. the global job ----------------------------------------------------------
	info "POST /services/create: $JP_GJOB, global-job, one 'exit 0' per node"
	api_create "$(jp_gjob_spec "$IMAGE")"
	_jpg_nodes=$(cluster_nodes | countl)
	wait_until "$T_CONVERGE" "$JP_GJOB: one Complete run on each of the $_jpg_nodes nodes" '
		tasks_fetch "$JP_GJOB" && [ "$(tasks_rows)" = "$_jpg_nodes" ] &&
		[ "$(tasks_complete_n)" = "$_jpg_nodes" ]'
	for _n in $(cluster_nodes); do
		_jpg_h=$(host_of "$_n")
		_jpg_c=$(tasks_all | awk -v h="$_jpg_h" '$2 == h && $4 == "Complete"' | countl)
		[ "$_jpg_c" = 1 ] ||
		    fail "$JP_GJOB has $_jpg_c Complete runs on $_n ($_jpg_h), not exactly one: a \
global job is one run per node"
	done
	hold_for "$T_SETTLE" "$JP_GJOB stays at one Complete run per node" '
		tasks_fetch "$JP_GJOB" && [ "$(tasks_rows)" = "$_jpg_nodes" ] &&
		[ "$(tasks_complete_n)" = "$_jpg_nodes" ] && [ "$(tasks_running_n)" = 0 ]'
	info "$JP_GJOB: one Complete run per node, no relaunch"
	svc_rm_audited "$JP_GJOB"

	# --- 3. the spread preference ------------------------------------------------------
	_jp_east=$(cluster_nodes | sed -n 1p)
	_jp_west1=$(cluster_nodes | sed -n 2p)
	_jp_west2=$(cluster_nodes | sed -n 3p)
	[ -n "$_jp_west2" ] ||
	    fail "jobs_and_prefs needs three nodes: zone east is one, zone west the other two"
	jp_label "$_jp_east" east
	jp_label "$_jp_west1" west
	jp_label "$_jp_west2" west
	info "$_jp_east labelled $JP_ZONE=east; $_jp_west1, $_jp_west2 labelled $JP_ZONE=west"

	if ! node_sh "$CTL" "$JP_SPREAD" "$JP_ZONE" "$JP_REPLICAS" "$IMAGE" <<'REMOTE' >"$TMPD/jpcreate" 2>&1; then
svc=$1
zone=$2
replicas=$3
img=$4
satl service create --name "$svc" --replicas "$replicas" \
    --placement-pref "spread=node.labels.$zone" "$img"
REMOTE
		show "$TMPD/jpcreate"
		fail "satl service create $JP_SPREAD failed"
	fi
	wait_until "$T_CONVERGE" "$JP_SPREAD at $JP_REPLICAS live tasks" \
	    'tasks_fetch "$JP_SPREAD" && [ "$(tasks_live_total)" = "$JP_REPLICAS" ]'
	_jp_counts=$(tasks_live | awk -v e="$(host_of "$_jp_east")" \
	    -v w1="$(host_of "$_jp_west1")" -v w2="$(host_of "$_jp_west2")" '
		$2 == e { east++; next }
		$2 == w1 || $2 == w2 { west++; next }
		{ elsewhere++ }
		END { print east + 0, west + 0, elsewhere + 0 }')
	[ "$_jp_counts" = "2 2 0" ] ||
	    fail "$JP_SPREAD spread (east west elsewhere) = '$_jp_counts', expected '2 2 0': \
a spread preference over node.labels.$JP_ZONE must put $((JP_REPLICAS / 2)) replicas \
in each zone"
	info "$JP_SPREAD: 2 replicas in zone east, 2 in zone west"
	svc_rm_audited "$JP_SPREAD"

	jp_unlabel_all
	for _n in $(cluster_nodes); do
		if node_ssh "$CTL" "satl node inspect $(host_of "$_n")" 2>/dev/null |
		    grep -q "\"$JP_ZONE\":"; then
			fail "$_n still carries the $JP_ZONE label after cleanup"
		fi
	done
	info "the $JP_ZONE label is gone from every node"
}

# ===========================================================================
# hot_resize — M6g live, plus the N4 rctl purge exercised for real
#
#   1. $HR: two replicas with --limit-memory 64M. The rctl rule of each task's
#      jail must carry the cap on the node the task runs on (rules are read
#      with `rctl`, the kernel's own answer — never inferred from the spec);
#   2. `satl service update --limit-memory 128M` is a resources-only change:
#      the SAME task ids must still be live afterwards (a roll would replace
#      them — a task is one-shot, so an id change is the roll), no extra task
#      rows may appear, each jail's rule must show the new cap, and the
#      manager's log must say, per task, "hot resize: resources pushed to the
#      live task, no roll";
#   3. `service rm` takes the rules with the containers: the controller's
#      removal path calls remove_limits while the jail is still alive
#      (crates/satl-agent/src/rctl.rs), so afterwards NO jail:-subject rule
#      may exist on any node — the normal path, asserted rather than the
#      purge, because that is what the code actually does;
#   4. N4 itself: one rule is planted by hand for a dead, task-id-shaped
#      subject on the first inventory node, and satld is restarted there. The
#      startup reconciliation must purge it: the rule gone from `rctl`, and
#      this daemon instance's "startup reconciliation complete" line carrying
#      rctl_rules_purged >= 1 (bounded to this instance by resetting on
#      "starting satld", the same bounding leader_nodes uses).
# ===========================================================================

# hr_mem_of <node> <jail name> — the jail's memoryuse cap in bytes as the
# kernel reports it, empty when the jail has no such rule.
hr_mem_of() {
	node_root_sh "$1" "$2" <<'REMOTE' 2>/dev/null
rctl 2>/dev/null | grep "^jail:$1:" |
    sed -n 's/^jail:[^:]*:memoryuse:sigkill=\([0-9][0-9]*\).*/\1/p' | head -1
REMOTE
}

# hr_jail_rules <node> — how many jail:-subject rctl rules exist at all.
hr_jail_rules() {
	node_root_sh "$1" <<'REMOTE' 2>/dev/null
rctl 2>/dev/null | awk '/^jail:/ { n++ } END { print n + 0 }'
REMOTE
}

# hr_all_limits <bytes> — every task in $TMPD/hr.before capped at exactly
# <bytes>. A wait_until body: re-read each poll.
hr_all_limits() {
	_hra_ok=1
	while read -r _hra_id _hra_host; do
		_hra_node=$(node_of_host "$_hra_host")
		[ "$(hr_mem_of "$_hra_node" "$_hra_id")" = "$1" ] || _hra_ok=0
	done <"$TMPD/hr.before"
	[ "$_hra_ok" = 1 ]
}

# hr_purge_logged <node> — yes when this daemon instance's startup
# reconciliation reported purging at least one rctl rule set.
hr_purge_logged() {
	node_root_sh "$1" <<'REMOTE' 2>/dev/null
grep -a satld /var/log/messages 2>/dev/null | awk '
	/starting satld/ { p = 0 }
	/startup reconciliation complete/ {
		p = ($0 ~ /rctl_rules_purged=[1-9]/) ? 1 : 0
	}
	END { print p ? "yes" : "no" }'
REMOTE
}

scenario_hot_resize() {
	m4_prelude
	svc_rm_audited "$HR"

	# --- 1. create capped -----------------------------------------------------------
	info "satl service create --name $HR --replicas $HR_REPLICAS --limit-memory 64M"
	node_ssh "$CTL" "satl service create --name $HR --replicas $HR_REPLICAS \
	    --limit-memory 64M $IMAGE" >"$TMPD/hrcreate" 2>&1 || {
		show "$TMPD/hrcreate"
		fail "satl service create $HR failed on $CTL"
	}
	wait_until "$T_CONVERGE" "$HR at $HR_REPLICAS live tasks" \
	    'tasks_fetch "$HR" && [ "$(tasks_live_total)" = "$HR_REPLICAS" ]'
	tasks_live | sort >"$TMPD/hr.before"
	while read -r _hr_id _hr_host; do
		_hr_node=$(node_of_host "$_hr_host")
		_hr_mem=$(hr_mem_of "$_hr_node" "$_hr_id")
		[ "$_hr_mem" = "$HR_OLD_BYTES" ] ||
		    fail "task $_hr_id on $_hr_node has memoryuse='${_hr_mem:-<no rule>}', expected \
$HR_OLD_BYTES: the create's --limit-memory never reached rctl"
	done <"$TMPD/hr.before"
	info "both jails capped at $HR_OLD_BYTES bytes (rctl, read back per node)"

	# --- 2. resize, hot -----------------------------------------------------------------
	info "satl service update --limit-memory 128M $HR"
	node_ssh "$CTL" "satl service update --limit-memory 128M $HR" >"$TMPD/hrupdate" 2>&1 || {
		show "$TMPD/hrupdate"
		fail "satl service update --limit-memory failed on $CTL"
	}
	wait_until "$T_QUICK" "the new cap live in rctl on every node" 'hr_all_limits "$HR_NEW_BYTES"'
	tasks_fetch "$HR" || fail "$CTL cannot list $HR's tasks after the update"
	tasks_live | sort >"$TMPD/hr.after"
	if ! cmp -s "$TMPD/hr.before" "$TMPD/hr.after"; then
		log "  before:"
		sed 's/^/    /' "$TMPD/hr.before"
		log "  after:"
		sed 's/^/    /' "$TMPD/hr.after"
		fail "the task set changed across a resources-only update: M6g is a hot resize, \
not a roll — and a task is one-shot, so a new id IS a roll"
	fi
	[ "$(tasks_rows)" = "$HR_REPLICAS" ] ||
	    fail "$HR has $(tasks_rows) task rows, not $HR_REPLICAS: the update created tasks \
somewhere, which is a roll whatever the live set says"
	while read -r _hr_id _hr_host; do
		[ "$(log_hits "hot resize: resources pushed to the live task, no roll" \
		    "task_id=$_hr_id")" -ge 1 ] ||
		    fail "no manager logged the hot resize of task $_hr_id: the rules moved, but \
if the manager did not say 'no roll' for it, the how is guesswork"
	done <"$TMPD/hr.before"
	info "same $HR_REPLICAS tasks, rules rewritten to $HR_NEW_BYTES, 'no roll' logged per task"
	log_evidence "hot resize applied to the live jail"

	# --- 3. removal takes the rules with it (the normal path) ---------------------------
	svc_rm_audited "$HR"
	wait_until "$T_CLEAN" "no jails, task epairs, container datasets or mounts left anywhere" \
	    'leftovers_gone'
	for _n in $(cluster_nodes); do
		_hr_rules=$(hr_jail_rules "$_n")
		[ "$_hr_rules" = 0 ] || {
			node_root_sh "$_n" <<'REMOTE' 2>/dev/null | sed 's/^/    /' || true
rctl 2>/dev/null | grep '^jail:' || true
REMOTE
			fail "$_n still has $_hr_rules jail: rctl rule(s) after service rm — the \
removal path is supposed to take a task's rules with its container"
		}
	done
	info "no jail: rctl rule left on any node after service rm"

	# --- 4. N4: the startup purge, exercised ----------------------------------------------
	# KNOWN-FRAGILE, recorded rather than changed: the first inventory node,
	# whose satld this stops and starts. If it is the raft leader, that forces
	# an election -- which used to be left in flight for the next scenario. The
	# `membership_agreed` wait at the end of this block absorbs it now, which is
	# why the node pick itself is left alone.
	HR_N4=$(cluster_nodes | sed -n 1p)
	if ! node_root_sh "$HR_N4" "$HR_ORPHAN" <<'REMOTE' >"$TMPD/hrplant" 2>&1; then
rctl -a "jail:$1:memoryuse:sigkill=1048576"
REMOTE
		show "$TMPD/hrplant"
		fail "cannot plant the orphan rctl rule on $HR_N4"
	fi
	[ "$(hr_mem_of "$HR_N4" "$HR_ORPHAN")" = 1048576 ] ||
	    fail "the planted orphan rule is not visible in rctl on $HR_N4 — the purge test \
would pass vacuously"
	info "planted orphan rule jail:$HR_ORPHAN on $HR_N4; restarting its satld"
	node_satld "$HR_N4" stop >/dev/null
	node_satld "$HR_N4" start >/dev/null
	wait_until "$T_QUICK" "$HR_N4's startup reconciliation purged the orphan rule" \
	    '[ -z "$(hr_mem_of "$HR_N4" "$HR_ORPHAN")" ]'
	[ "$(hr_purge_logged "$HR_N4")" = yes ] ||
	    fail "$HR_N4 dropped the orphan rule but its log does not say so: this daemon \
instance's 'startup reconciliation complete' must carry rctl_rules_purged >= 1 (N4)"
	[ "$(hr_jail_rules "$HR_N4")" = 0 ] ||
	    fail "$HR_N4 still has jail: rctl rules after the startup purge"
	info "the startup purge reaped the orphan and logged rctl_rules_purged (N4)"

	# The restart above may have taken this node's raft leadership with it, and
	# an election in flight is not a state to hand to the next scenario: this
	# one used to return with one under way, which is precisely the kind of
	# inheritance that decided ca_rotate's verdict elsewhere.
	wait_until "$T_JOIN" "the cluster agrees again after restarting $HR_N4" \
	    'membership_agreed'

	# --- the suite expects three Ready managers ---------------------------------------------
	wait_until "$T_JOIN" "every node Ready again after $HR_N4's restart" '
		_hrok=1
		for _hrn in $(cluster_nodes); do
			state_fetch "$_hrn" || _hrok=0
			[ "$(nodes_ready)" = "$(cluster_nodes | countl)" ] || _hrok=0
		done
		[ "$_hrok" = 1 ]'
	info "resized hot, removed clean, purge proven; cluster Ready"
}

# ===========================================================================

# ===========================================================================
# Scenario 24 — compose_local (M11 DoD, the node-local half)
#
# The other half of the split compose_stack now covers. Docker has two worlds
# and SatL has both: `satl stack deploy` spreads a Compose file over the
# cluster, `satl compose up` runs the same shape of file on the one node the
# CLI is talking to. This asserts the second, and it runs on the *three-node*
# cluster deliberately — on one node "everything landed here" is true for free,
# and every assertion below would pass on a broken pin.
#
# What each step catches, in the order a defect would reach an operator:
#
#   - the plan itself, before anything is created: a `node.id==` constraint
#     naming the receiving node, `<project>-<service>` names with compose v2's
#     hyphen, host-mode publishing, and a relative bind resolved to an absolute
#     path (api-compat 169, 172, 173);
#   - the network is a **bridge**, scope local, which is what `docker compose`
#     makes and what SatL's compose makes since M11b gave bridge networks a DNS
#     responder (api-compat 170);
#   - **every task is on the control node.** This is the assertion that cannot
#     pass by accident: three nodes are Ready and the scheduler would spread a
#     two-service file across them, as compose_stack proves it does under
#     `satl stack`;
#   - **one service reaches the other by its compose name**, from inside the
#     jail, through `fetch` — so a pass means the name resolved *and* the bridge
#     carried the frames. Before M11b a bridge task got a copy of the host's
#     /etc/resolv.conf and this answered NXDOMAIN;
#   - a `deploy.placement:` in the file is refused, naming `satl stack deploy`,
#     because a pinned task has nothing left to place (api-compat 171);
#   - **`stop` is not docker's `stop`**: a task is one-shot, so nothing is
#     paused and resumed. It scales the project to zero and *keeps* the
#     services and the volume, which is what distinguishes it from `down`;
#     `start` puts the counts back from the file, with nothing stashed in a
#     label (api-compat 176);
#   - **`restart` replaces**: every task id must be new and in the same slot,
#     which is what invariant 2 means by restart (api-compat 177);
#   - `down -v` removes the project's volume, which was refused before there
#     was a single node to remove it from (api-compat 118), and leaves no jail,
#     epair or dataset behind.
# ===========================================================================

CL_PROJECT=${SATL_TEST_COMPOSE_LOCAL_PROJECT:-clocal}
CL_PORT=${SATL_TEST_COMPOSE_LOCAL_PORT:-18092}
CL_DIR=${SATL_TEST_COMPOSE_LOCAL_DIR:-/tmp/$CL_PROJECT}

# cl_svc <short name> — the name `satl compose` gives that service. A hyphen,
# where `satl stack` uses an underscore: docker's own split (api-compat 110).
cl_svc() { printf '%s-%s' "$CL_PROJECT" "$1"; }

# cl_compose <args...> — `satl compose <args>` in the project directory, on the
# control node. The project name comes from that directory, and the node it runs
# on is the node it must deploy to, so both are part of what is tested.
cl_compose() {
	node_sh "$CTL" "$CL_DIR" "$@" <<'REMOTE'
dir=$1
shift
cd "$dir" || exit 1
satl compose "$@"
REMOTE
}

# cl_services — this project's service names, as the daemon holds them.
cl_services() {
	node_ssh "$CTL" "satl service ls 2>/dev/null" |
	    tcols - 'NAME' | awk -v p="$CL_PROJECT-" 'index($1, p) == 1 { print $1 }'
}

# cl_task_nodes — the hostnames running a live task of this project, sorted.
cl_task_nodes() {
	for _clt in web peer; do
		node_ssh "$CTL" "satl service ps $(cl_svc "$_clt") 2>/dev/null" \
		    >"$TMPD/cltasks" 2>/dev/null || return 1
		tcols "$TMPD/cltasks" 'NODE,DESIRED STATE,CURRENT STATE' |
		    awk -F'\t' '$2 == "Running" && $3 ~ /^Running/ { print $1 }'
	done | sort -u
}

# cl_live_ids — the ids of this project's *running* tasks, sorted,
# space-separated. Filtered on state, not just listed: `satl service ps` keeps
# the terminal tasks of a slot, so after a restart the same service has both the
# task that went away and the one that replaced it.
cl_live_ids() {
	for _cll in web peer; do
		node_ssh "$CTL" "satl service ps $(cl_svc "$_cll") --no-trunc 2>/dev/null" \
		    >"$TMPD/cllive" 2>/dev/null || return 1
		tcols "$TMPD/cllive" 'ID,DESIRED STATE,CURRENT STATE' |
		    awk -F'\t' '$2 == "Running" && $3 ~ /^Running/ { print $1 }'
	done | sort | tr '\n' ' '
}

cl_rm() { cl_compose down -v >/dev/null 2>&1 || true; }

scenario_compose_local() {
	require_swarm
	build_hostmap
	wait_until "$T_JOIN" "all nodes Ready" \
	    'state_fetch "$CTL" && [ "$(nodes_ready)" = "$(cluster_nodes | countl)" ]'

	_cl_nodes=$(cluster_nodes | countl)
	[ "$_cl_nodes" -ge 2 ] ||
	    fail "compose_local needs at least two nodes: on one node the pin is true for free"
	_cl_host=$(host_of "$CTL")

	cl_rm
	wait_until "$T_CLEAN" "no leftover $CL_PROJECT services" '[ -z "$(cl_services)" ]'

	# --- the file -----------------------------------------------------------
	# A relative bind and a relative env_file are the point of the node-local
	# world: the project directory is a path on the node that will run the
	# task, because satl speaks a unix socket and cannot be talking to another
	# host (api-compat 173).
	node_sh "$CTL" "$CL_DIR" "$IMAGE" "$CL_PORT" <<'REMOTE' ||
dir=$1
image=$2
port=$3
rm -rf "$dir"
mkdir -p "$dir/conf"
printf 'served-from-a-relative-bind\n' > "$dir/conf/marker"
cat > "$dir/compose.yaml" <<YAML
services:
  web:
    image: $image
    ports:
      - "$port:80"
    volumes:
      - "./conf:/mnt/conf"
      - "data:/mnt/data"
  peer:
    image: $image
volumes:
  data:
YAML
REMOTE
	    fail "could not write the compose file on $CTL"
	info "compose.yaml written to $CL_DIR on $CTL (web publishes :$CL_PORT, peer is unpublished)"

	# --- the plan, before anything exists -----------------------------------
	cl_compose config >"$TMPD/clconfig" 2>&1 || {
		show "$TMPD/clconfig"
		fail "satl compose config was refused"
	}
	_cl_node_id=$(node_ssh "$CTL" "satl info 2>/dev/null" |
	    sed -n 's/.*NodeID: *//p' | tr -d '\r' | head -1)
	[ -n "$_cl_node_id" ] || fail "could not read $CTL's own node id from satl info"
	grep -q "node.id==$_cl_node_id" "$TMPD/clconfig" ||
	    fail "the plan carries no node.id==$_cl_node_id constraint: satl compose must pin every \
service to the node it is talking to (api-compat 169)"
	grep -q "\"$(cl_svc web)\"" "$TMPD/clconfig" ||
	    fail "the plan does not name the service $(cl_svc web): compose names with a hyphen \
(api-compat 110)"
	grep -q '"PublishMode": *"host"' "$TMPD/clconfig" ||
	    fail "the plan does not publish in host mode (api-compat 172)"
	grep -q "\"Source\": *\"$CL_DIR/conf\"" "$TMPD/clconfig" ||
	    fail "the relative bind ./conf was not resolved against $CL_DIR (api-compat 173)"
	info "the plan pins to node.id==$_cl_node_id, names $(cl_svc web), publishes host-mode and \
resolved ./conf"

	# --- a cluster-only key is refused, and says where it works -------------
	node_ssh "$CTL" "sed -e 's|^  peer:|  peer:\\
    deploy:\\
      placement:\\
        constraints: [\"node.role == worker\"]|' $CL_DIR/compose.yaml > $CL_DIR/placed.yaml" ||
	    fail "could not write the placement variant"
	if cl_compose -f "$CL_DIR/placed.yaml" config >"$TMPD/clplaced" 2>&1; then
		show "$TMPD/clplaced"
		fail "deploy.placement was accepted by satl compose; a pinned task has nothing left \
to place (api-compat 171)"
	fi
	grep -q 'satl stack deploy' "$TMPD/clplaced" ||
	    fail "the refusal does not name satl stack deploy: $(tail -1 "$TMPD/clplaced")"
	info "deploy.placement is refused, naming satl stack deploy"

	# --- up -----------------------------------------------------------------
	# `-d` is load-bearing since M11d: `satl compose up` attaches to the
	# project's output and does not return until Ctrl-C (api-compat 124), so a
	# script that wants it to come back has to ask.
	cl_compose up -d >"$TMPD/clup" 2>"$TMPD/cluperr" || {
		show "$TMPD/clup"
		show "$TMPD/cluperr"
		fail "satl compose up failed"
	}
	show "$TMPD/clup"

	wait_until "$T_CONVERGE" "$(cl_svc web) and $(cl_svc peer) both running" '
		_clr=$(node_ssh "$CTL" "satl service ls 2>/dev/null" |
		    tcols - "NAME,REPLICAS" |
		    awk -F"\t" -v p="'"$CL_PROJECT"'-" "index(\$1, p) == 1 { print \$2 }" | sort -u)
		[ "$_clr" = "1/1" ]'

	# --- the network is a bridge, scope local -------------------------------
	node_ssh "$CTL" "satl network ls 2>/dev/null" >"$TMPD/clnet" 2>&1 ||
	    fail "satl network ls failed on $CTL"
	_cl_netrow=$(tcols "$TMPD/clnet" 'NAME,DRIVER,SCOPE' |
	    awk -F'\t' -v n="$(cl_svc default)" '$1 == n { print $2 "/" $3 }')
	[ "$_cl_netrow" = "bridge/local" ] ||
	    fail "$(cl_svc default) is '$_cl_netrow', not bridge/local: satl compose creates the \
network docker compose creates (api-compat 170)"
	info "$(cl_svc default) is a bridge network, scope local"

	# --- every task is on the node the CLI spoke to -------------------------
	_cl_on=$(cl_task_nodes | tr '\n' ' ')
	[ "$(printf %s "$_cl_on" | wc -w | tr -d ' ')" = "1" ] && [ "${_cl_on% }" = "$_cl_host" ] ||
	    fail "this project's tasks are on '$_cl_on', not on $CTL ($_cl_host) alone: satl \
compose runs the whole file on the node you are talking to, and $_cl_nodes nodes are Ready \
(api-compat 169)"
	info "every task is on $_cl_host, with $_cl_nodes nodes Ready to have taken them"

	# --- the compose service name resolves, on the bridge -------------------
	_cl_jid=$(ovl_task_jid "$CTL" "$(cl_svc peer)")
	[ -n "$_cl_jid" ] || fail "no jail found on $CTL for $(cl_svc peer)"
	ovl_wait_fetch "$CTL" "$_cl_jid" "web"
	info "peer reached web by its bare compose name over the bridge (api-compat 111, 170)"

	# --- logs (M11d) --------------------------------------------------------
	# Node-local scope is what makes this possible at all: logs are node-local
	# (api-compat 81), so a project spread over the cluster could not be
	# followed from one place. The prefix is the assertion -- it proves the
	# multiplexer attributed the line to the right task, not just that some
	# output arrived.
	cl_compose logs --tail 5 >"$TMPD/cllogs" 2>&1 || {
		show "$TMPD/cllogs"
		fail "satl compose logs failed"
	}
	grep -q '^web-1 *| ' "$TMPD/cllogs" ||
	    fail "satl compose logs printed no web-1 prefixed line (api-compat 179): \
$(head -3 "$TMPD/cllogs")"
	grep -q '^peer-1 *| ' "$TMPD/cllogs" ||
	    fail "satl compose logs printed no peer-1 prefixed line: only one service was read"
	info "logs read both services, each line prefixed <service>-<slot> (api-compat 179)"

	# --- stop, start, restart (M11c) ----------------------------------------
	# None of the three is docker's, because a task is one-shot: nothing is
	# paused and resumed. What is asserted is that difference, not the verb.
	cl_compose stop >"$TMPD/clstop" 2>&1 || {
		show "$TMPD/clstop"
		fail "satl compose stop failed"
	}
	wait_until "$T_CONVERGE" "both services at 0/0, and still there" '
		_clz=$(node_ssh "$CTL" "satl service ls 2>/dev/null" |
		    tcols - "NAME,REPLICAS" |
		    awk -F"\t" -v p="'"$CL_PROJECT"'-" "index(\$1, p) == 1 { print \$2 }" | sort -u)
		[ "$_clz" = "0/0" ]'
	# The distinction from `down`: the services, and the volume, survive.
	[ "$(cl_services | countl)" = 2 ] ||
	    fail "stop removed services; it scales to zero and keeps them (api-compat 176)"
	node_ssh "$CTL" "satl volume ls 2>/dev/null" | grep -q "$(cl_svc data)" ||
	    fail "stop removed the volume $(cl_svc data); only down -v does that"
	info "stop scaled both services to 0/0 and left the services and the volume in place"

	cl_compose start >"$TMPD/clstart" 2>&1 || {
		show "$TMPD/clstart"
		fail "satl compose start failed"
	}
	wait_until "$T_CONVERGE" "both services back at 1/1, from the file" '
		_clr=$(node_ssh "$CTL" "satl service ls 2>/dev/null" |
		    tcols - "NAME,REPLICAS" |
		    awk -F"\t" -v p="'"$CL_PROJECT"'-" "index(\$1, p) == 1 { print \$2 }" | sort -u)
		[ "$_clr" = "1/1" ]'
	info "start restored 1/1 from the file, with nothing stashed in a label"

	# `restart` replaces: the task ids must all be new, in the same slots.
	CL_BEFORE=$(cl_live_ids)
	[ -n "$CL_BEFORE" ] || fail "no live task ids before restart"
	cl_compose restart >"$TMPD/clrestart" 2>&1 || {
		show "$TMPD/clrestart"
		fail "satl compose restart failed"
	}
	wait_until "$T_CONVERGE" "every task replaced by a new one in the same slot" '
		_clnow=$(cl_live_ids)
		_cloverlap=0
		for _clid in $CL_BEFORE; do
			case " $_clnow " in
			*" $_clid "*) _cloverlap=1 ;;
			esac
		done
		[ "$(printf %s "$_clnow" | wc -w | tr -d " ")" = 2 ] && [ "$_cloverlap" = 0 ]'
	info "restart replaced both tasks: new ids in the same slots, which is what invariant 2 \
means by restart (api-compat 177)"

	# --- down leaves nothing ------------------------------------------------
	CL_IDS=$(for _cli in web peer; do
		node_ssh "$CTL" "satl service ps $(cl_svc "$_cli") --quiet --no-trunc 2>/dev/null" |
		    tr -d '\r'
	done | grep -v '^$' | sort -u | tr '\n' ' ')

	cl_compose down -v >"$TMPD/cldown" 2>"$TMPD/cldownerr" || {
		show "$TMPD/cldown"
		show "$TMPD/cldownerr"
		fail "satl compose down -v failed"
	}
	grep -q "^volume $(cl_svc data) removed$" "$TMPD/cldown" ||
	    fail "down -v did not report removing $(cl_svc data): there is one node to remove from \
now, which is the whole reason it is no longer refused (api-compat 118)"
	node_ssh "$CTL" "satl volume ls 2>/dev/null" >"$TMPD/clvols" 2>&1 || true
	if grep -q "$(cl_svc data)" "$TMPD/clvols"; then
		show "$TMPD/clvols"
		fail "$(cl_svc data) is still there after down -v"
	fi
	info "down -v removed the project's volume, after its services and its network"
	# Audited per task rather than with the suite-wide sweep: this scenario
	# runs while the rest of the suite's services are deliberately still up.
	wait_until "$T_CLEAN" "the project's services, network and tasks all gone" '
		[ -z "$(cl_services)" ] &&
		    ! node_ssh "$CTL" "satl network inspect $(cl_svc default) >/dev/null 2>&1" &&
		    [ "$(ru_leftovers "$CL_IDS")" = 0 ]'
	info "compose project deployed on one node, proven and removed; cluster left as it was"
}
# Scenario 10 — cleanup
#
# Removes what the suite created and audits every node for leftovers, the same
# way `make integration` does on a single host: no jail under the state
# directory, no interface still described `satl:<task-id>` (the node's own
# `satl:network:*` bridge is not a leftover), no dataset under
# <zfs_root>/containers.
# ===========================================================================
# ===========================================================================
# scenario images_rm — `satl images rm` on a real cluster.
#
# Two things only a cluster can show, and both are the point:
#
#   1. **the refusal is cluster-aware, and it is not a 503 on a worker.** The
#      claim set comes from the Raft store on a manager and from the local task
#      DB on a worker, so a worker answers the removal rather than refusing to
#      look (api-compat 161) -- the opposite of `satl node ps`, which is cluster
#      state and does 503.
#   2. **removal is node-local.** Forgetting an image on one node must leave the
#      other nodes' stores untouched (api-compat 130). A prune has always been
#      node-local; a targeted removal is the verb an operator will reach for
#      first, and getting this wrong would quietly empty a cluster.
# ===========================================================================

IRM=satl_images_rm
# A private tag of the suite image: the scenario removes it, and removing a
# reference every other scenario depends on would be a booby trap.
IRM_TAG="127.0.0.1:$REG_PORT/$REG_NS/satl-images-rm:v1"

# irm_lists <node> — does this node's store still list IRM_TAG?
irm_lists() {
	node_ssh "$1" "satl images" 2>/dev/null | grep -q "satl-images-rm"
}

scenario_images_rm() {
	m4_prelude
	svc_rm_audited "$IRM"

	_irm_a=$(bootstrap_node)
	_irm_b=""
	for _n in $(cluster_nodes); do
		[ "$_n" = "$_irm_a" ] || { _irm_b=$_n; break; }
	done
	[ -n "$_irm_b" ] || fail "images_rm needs a second node"

	# --- 1. a private tag on one node only ----------------------------------
	info "satl tag on $_irm_a: $IMAGE -> $IRM_TAG"
	node_ssh "$_irm_a" "satl tag $IMAGE $IRM_TAG" >"$TMPD/irm.tag" 2>&1 || {
		show "$TMPD/irm.tag"
		fail "satl tag failed on $_irm_a"
	}
	irm_lists "$_irm_a" || fail "$_irm_a does not list the tag it just created"
	irm_lists "$_irm_b" &&
	    fail "$_irm_b lists a tag created on $_irm_a: tagging is node-local (api-compat 130)"
	info "the tag exists on $_irm_a and nowhere else"

	# --- 2. a service holding it cannot be removed, forced or not -----------
	info "satl service create --name $IRM --replicas 1 $IRM_TAG (constrained to $_irm_a)"
	_irm_host=$(host_of "$_irm_a")
	node_ssh "$_irm_a" "satl service create --name $IRM --replicas 1 \
	    --constraint node.hostname==$_irm_host $IRM_TAG" >"$TMPD/irm.create" 2>&1 || {
		show "$TMPD/irm.create"
		fail "satl service create $IRM failed on $_irm_a"
	}
	wait_until "$T_CONVERGE" "$IRM running on $_irm_host" \
	    'tasks_fetch "$IRM" && [ "$(tasks_live_total)" = "1" ]'

	for _irm_flag in "" "--force"; do
		if node_ssh "$_irm_a" "satl images rm $_irm_flag $IRM_TAG" >"$TMPD/irm.refused" 2>&1; then
			show "$TMPD/irm.refused"
			fail "satl images rm $_irm_flag succeeded while a service still names the image: \
a live claim is not forceable (api-compat 161)"
		fi
		grep -q "cannot be forced" "$TMPD/irm.refused" || {
			show "$TMPD/irm.refused"
			fail "the refusal must say 'cannot be forced', not just fail"
		}
	done
	irm_lists "$_irm_a" || fail "the refused removal forgot the record anyway"
	info "refused with 'cannot be forced' both with and without --force, record intact"

	# --- 3. the worker answers rather than 503-ing --------------------------
	# Same verb on a node that is not the leader: image removal reads the local
	# task DB when there is no manager to ask, so it must produce a real answer.
	if node_ssh "$_irm_b" "satl images rm $IRM_TAG" >"$TMPD/irm.worker" 2>&1; then
		fail "$_irm_b removed an image it does not have"
	fi
	grep -q "No such image" "$TMPD/irm.worker" || {
		show "$TMPD/irm.worker"
		fail "$_irm_b must answer 'No such image' for a reference it does not hold -- \
not a 503: image removal is node-local and never needs a manager (api-compat 161)"
	}
	info "$_irm_b answered 'No such image' rather than refusing to look"

	# --- 4. remove it for real ----------------------------------------------
	svc_rm_audited "$IRM"
	wait_until "$T_CLEAN" "no jails, task epairs, container datasets or mounts left anywhere" \
	    'leftovers_gone'

	info "satl images rm $IRM_TAG on $_irm_a"
	node_ssh "$_irm_a" "satl images rm $IRM_TAG" >"$TMPD/irm.rm" 2>&1 || {
		show "$TMPD/irm.rm"
		fail "satl images rm failed once nothing referenced the image"
	}
	grep -q "^Untagged: " "$TMPD/irm.rm" || {
		show "$TMPD/irm.rm"
		fail "the removal must report the reference it forgot"
	}
	irm_lists "$_irm_a" && fail "$_irm_a still lists the removed tag"

	# The base image is untouched: removing one reference of a shared image
	# must not take the others with it.
	node_ssh "$_irm_a" "satl images" 2>/dev/null | grep -q "freebsd-nginx" ||
	    fail "removing $IRM_TAG also removed $IMAGE: a tag is one reference, not the image"
	info "the tag is gone on $_irm_a, the base image it shared layers with is not"
	log_evidence "targeted image removal, node-local"
}

scenario_cleanup() {
	require_swarm
	if service_present; then
		info "satl service rm $SERVICE"
		service_rm
	else
		info "$SERVICE does not exist — nothing to remove"
	fi

	wait_until "$T_CLEAN" "no jails, task epairs, container datasets or leftover mounts anywhere" \
	    'leftovers_gone'
	for _n in $(cluster_nodes); do
		printf '    %-8s %s\n' "$_n" "$(node_audit "$_n")"
	done
	state_fetch "$CTL"
	info "cluster left formed: $(nodes_ready) Ready, leader $(leader_host), no services"
}

leftovers_gone() {
	for _lg in $(cluster_nodes); do
		_a=$(node_audit "$_lg") || return 1
		[ "$_a" = "jails=0 epairs=0 datasets=0 mounts=0 rdr=0" ] || return 1
	done
	return 0
}

# ===========================================================================
# The readiness gate. Per-node checks: each remote block prints "[ ok ]" /
# "[FAIL]" / "[ -- ]" and exits non-zero when a required check failed.
# Advisory ("[ -- ]") checks never fail the run; they exist so a surprise shows
# up in the report rather than three milestones later.
# ===========================================================================
check_node() {
	node_root_sh "$1" "$1" "$PREFIX" "$ZFS_ROOT" "$STATE_DIR" "$UNDERLAY_IF" \
	    "$2" "$REG_PORT" "$REG_NS" "$IMAGES" "$3" <<'REMOTE'
node_name=$1
prefix=$2
zfs_root=$3
state_dir=$4
underlay_if=$5
want_private_ip=$6
reg_port=$7
reg_ns=$8
images=$9
shift 9
peer_ips=$1
fails=0

ok()    { printf '  [ ok ] %-24s %s\n' "$1" "$2"; }
bad()   { printf '  [FAIL] %-24s %s\n' "$1" "$2"; fails=$((fails + 1)); }
note()  { printf '  [ -- ] %-24s %s\n' "$1" "$2"; }
want()  { if [ "$2" = "$3" ]; then ok "$1" "$3"; else bad "$1" "$3 (expected $2)"; fi; }

# --- host prerequisites (docs/operations.md, docs/networking.md) ------------
ok   "host" "$(hostname) — $(uname -r) $(uname -m)"
want "kern.racct.enable" 1 "$(sysctl -n kern.racct.enable 2>/dev/null)"
want "ip forwarding" 1 "$(sysctl -n net.inet.ip.forwarding 2>/dev/null)"
want "pf status" Enabled \
    "$(pfctl -s info 2>/dev/null | awk '/^Status:/ { print $2; exit }')"
# Any whitespace, not one space: pf(5) does not care, and the pf.conf the
# published install-satl.sh writes -- the one the website tells an operator to
# run -- aligns the third anchor for readability:
#
#     nat-anchor "satl/*"
#     rdr-anchor "satl/*"
#     anchor     "satl/*"
#
# A single literal space counted 2 of 3 on a perfectly good ruleset and told
# three healthy nodes they were NOT READY. Same expression as the install
# script's own PF_ANCHOR_RE, so the two counters cannot disagree again.
want "pf satl anchors" 3 \
    "$(grep -cE '^[[:space:]]*(nat-anchor|rdr-anchor|anchor)[[:space:]]+"satl/\*"' /etc/pf.conf 2>/dev/null)"

# --- storage (invariant #5: ZFS is mandatory) ------------------------------
want "zfs $zfs_root" "$state_dir" \
    "$(zfs get -H -o value mountpoint "$zfs_root" 2>/dev/null)"
if mount | grep -q "^$zfs_root on $state_dir "; then
	ok "zfs mounted" "$state_dir"
else
	bad "zfs mounted" "$zfs_root is not mounted at $state_dir"
fi

# --- underlay --------------------------------------------------------------
got_ip=$(ifconfig "$underlay_if" 2>/dev/null | awk '$1 == "inet" { print $2; exit }')
want "$underlay_if address" "$want_private_ip" "$got_ip"
for peer in $peer_ips; do
	if ping -c 1 -t 3 "$peer" >/dev/null 2>&1; then
		ok "underlay -> $peer" "reachable"
	else
		bad "underlay -> $peer" "no reply (Raft and the dispatcher need this)"
	fi
done

# --- runtime and binaries --------------------------------------------------
if command -v ocijail >/dev/null 2>&1; then
	ok "ocijail" "$(ocijail --version 2>&1 | head -1)"
else
	bad "ocijail" "not installed (invariant #6: SatL drives ocijail)"
fi
for f in "$prefix/bin/satl" "$prefix/sbin/satld" "$prefix/etc/rc.d/satld" \
    "$prefix/etc/satl/satld.toml"; do
	if [ -f "$f" ]; then ok "installed" "$f"; else bad "installed" "$f is missing"; fi
done
want "rc.conf satld_enable" YES "$(sysrc -n satld_enable 2>/dev/null)"

# --- the daemon ------------------------------------------------------------
if service satld status >/dev/null 2>&1; then
	ok "satld" "$(service satld status 2>&1 | head -1)"
else
	bad "satld" "not running (service satld start; check /var/log/messages)"
fi
if ver=$(satl version 2>&1); then
	ok "satl version" \
	    "$(echo "$ver" | awk '/Engine:/ { e = 1; next } e && /Version:/ { print "engine " $2; exit }')"
else
	bad "satl version" "$(printf '%s' "$ver" | tail -1)"
fi
# Straight at the Docker API, on the documented default socket path (deploy.sh
# does not override socket_path). Also the check that catches a stale or
# hand-edited satld.toml: the daemon must report the inventory's node name.
api=$(curl -s --max-time 5 --unix-socket /var/run/satl.sock \
    http://localhost/info 2>/dev/null || true)
if [ -n "$api" ]; then
	want "api node name" "$node_name" \
	    "$(printf '%s' "$api" | sed -n 's/.*"Name":"\([^"]*\)".*/\1/p')"
	ok "swarm state" \
	    "$(printf '%s' "$api" | sed -n 's/.*"LocalNodeState":"\([^"]*\)".*/\1/p')"
else
	bad "docker API /info" "no answer on /var/run/satl.sock"
fi

# --- test images (tests/cluster/images.sh) ---------------------------------
if curl -sf "http://127.0.0.1:$reg_port/v2/" >/dev/null 2>&1; then
	missing=""
	for img in $images; do
		repo=${img%:*}
		tag=${img#*:}
		curl -sf -o /dev/null \
		    -H 'Accept:application/vnd.oci.image.index.v1+json' \
		    -H 'Accept:application/vnd.oci.image.manifest.v1+json' \
		    -H 'Accept:application/vnd.docker.distribution.manifest.list.v2+json' \
		    -H 'Accept:application/vnd.docker.distribution.manifest.v2+json' \
		    "http://127.0.0.1:$reg_port/v2/$reg_ns/$repo/manifests/$tag" ||
		    missing="$missing $reg_ns/$img"
	done
	if [ -z "$missing" ]; then
		ok "test registry" "127.0.0.1:$reg_port — all images present"
	else
		bad "test registry" "missing:$missing (run tests/cluster/images.sh)"
	fi
else
	bad "test registry" "127.0.0.1:$reg_port is not answering (images.sh)"
fi

# --- advisory --------------------------------------------------------------
if rel=$(sysctl -n compat.linux.osrelease 2>/dev/null); then
	ok "linuxulator (advisory)" "$rel"
else
	note "linuxulator (advisory)" "off — linux/* images cannot run here"
fi
jails=$(jls -N 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
note "jails running" "$jails"

[ "$fails" -eq 0 ] || { echo "  $fails required check(s) failed"; exit 1; }
echo "NODE_READY"
REMOTE
}

readiness_gate() {
	_nodes=$1
	_failed=""
	for _n in $_nodes; do
		hdr "$_n ($(node_field "$_n" ssh_host), role $(node_field "$_n" role))"

		if ! node_ssh "$_n" true >/dev/null 2>&1; then
			printf '  [FAIL] %-24s %s\n' "unreachable" \
			    "ssh $(node_target "$_n") failed (BatchMode)"
			_failed="$_failed $_n"
			continue
		fi

		# Every other node's underlay address, so each node proves it can talk
		# to its peers on 10.2.0.0/16 and not just to the dev host.
		_peers=""
		for _p in $(cluster_nodes); do
			[ "$_p" = "$_n" ] && continue
			_peers="$_peers $(node_field "$_p" private_ip)"
		done

		check_node "$_n" "$(node_field "$_n" private_ip)" "${_peers# }" 2>&1 |
		    tee "$TMPD/check"
		grep -q '^NODE_READY$' "$TMPD/check" || _failed="$_failed $_n"
	done

	hdr "readiness"
	for _n in $_nodes; do
		case " $_failed " in
		*" $_n "*) printf '  %-8s %-18s NOT READY\n' "$_n" "$(node_field "$_n" role)" ;;
		*) printf '  %-8s %-18s ready\n' "$_n" "$(node_field "$_n" role)" ;;
		esac
	done

	if [ -n "$_failed" ]; then
		log ""
		log "Not ready:$_failed"
		log ""
		log "Fix with, in order:"
		log "    sh tests/cluster/provision.sh$_failed"
		log "    sh tests/cluster/deploy.sh$_failed"
		log "    sh tests/cluster/images.sh$_failed"
		return 1
	fi
	return 0
}

# =================================================================== driver ==

log "SatL cluster test — inventory $INVENTORY"
log "Bootstrap manager: $(bootstrap_node) (role data, not hardcoded)"

if [ "$READINESS_ONLY" = 1 ]; then
	nodes=$(resolve_nodes "$@")
	[ -n "$nodes" ] || die "no nodes selected"
	ensure_daemons
	readiness_gate "$nodes"
	log ""
	log "Readiness only (-r): no scenario was run."
	exit 0
fi

# Positional arguments name scenarios. With none, the whole suite runs and
# ends with the cleanup audit.
if [ "$#" -gt 0 ]; then
	wanted=""
	for arg in "$@"; do
		found=0
		for s in $SCENARIOS; do
			[ "$arg" = "$s" ] && found=1
		done
		[ "$found" = 1 ] || die "unknown scenario: $arg (try --list; node names need -r)"
		wanted="$wanted $arg"
	done
	wanted=${wanted# }
else
	wanted=$SCENARIOS
fi

ensure_daemons
readiness_gate "$(cluster_nodes)"

hdr "identifying the nodes"
build_hostmap
while read -r hn nn; do info "$nn is '$hn' (as its agent reports it)"; done <"$HOSTMAP"

log ""
log "Scenarios to run: $wanted"

for scenario in $wanted; do
	hdr "scenario $scenario"
	CURRENT=$scenario
	t0=$(date +%s)
	"scenario_$scenario"
	elapsed=$(($(date +%s) - t0))
	printf '  PASS %s in %ss\n' "$scenario" "$elapsed"
	printf 'PASS     %-16s %ss\n' "$scenario" "$elapsed" >>"$SUMMARY"
	PASSED="$PASSED $scenario"
	CURRENT=""
done

hdr "summary"
while read -r line; do info "$line"; done <"$SUMMARY"
log ""
log "All requested scenarios passed:$PASSED"
