#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# tests/cluster/provision.sh — bring the SatL test VMs to a state satld runs in.
#
# Usage: tests/cluster/provision.sh [-h] [node ...]
#
#   With no node names, every node in inventory.toml is provisioned.
#   Idempotent: re-running a provisioned node changes nothing and still prints
#   the full verification report.
#
# Environment:
#   SATL_WITH_LINUX=1   also install linux_base-rl9 and enable the linuxulator
#                       (361 MiB; only needed to run linux/* images on the VMs)
#   SATL_INVENTORY      alternate inventory.toml
#
# What it does, per docs/operations.md "Install" and docs/networking.md
# "Host prerequisite":
#   1. packages: ocijail (the runtime), curl, skopeo + docker-registry (the
#      node-local test registry, see images.sh)
#   2. kern.racct.enable=1 in /boot/loader.conf — a boot-time tunable, so the
#      node is rebooted when it is not already on
#   3. gateway_enable=YES + net.inet.ip.forwarding=1
#   4. /etc/pf.conf with the satl/* anchors + `pass all`, pf enabled and loaded
#   5. ZFS: zroot/satl mounted at /var/db/satl
#
# It deliberately does NOT install satl/satld — that is deploy.sh, which you
# re-run on every code change while provisioning happens once.

set -e

CLUSTER_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$CLUSTER_DIR/lib.sh"

usage() {
	sed -n '2,/^$/p' "$0" | sed 's/^#//; s/^ //'
	exit "${1:-0}"
}

WITH_LINUX=${SATL_WITH_LINUX:-0}
REBOOT_WAIT=300

while [ "$#" -gt 0 ]; do
	case $1 in
	-h | --help) usage 0 ;;
	-*) die "unknown option: $1 (try -h)" ;;
	*) break ;;
	esac
done

# ------------------------------------------------------------------------
# Phase 1 — configure. Prints PROVISION_DONE on success (set -e aborts before
# that on any failure) and PROVISION_REBOOT_REQUIRED when racct is still off.
# Args: $1 with_linux  $2 zfs_root  $3 state_dir  $4 registry_root
# ------------------------------------------------------------------------
configure_node() {
	node_root_sh "$1" "$WITH_LINUX" "$(cluster_setting zfs_root)" \
	    "$(cluster_setting state_dir)" "$(cluster_setting registry_root)" <<'REMOTE'
set -e
with_linux=$1
zfs_root=$2
state_dir=$3
registry_root=$4

# --- linuxulator (optional) ---------------------------------------------
# Before the packages: linux_base-rl9's pre-install script refuses to run
# on a kernel without 64-bit Linux support ("kernel missing 64-bit Linux
# support"), so the modules must be loaded before pkg install sees it.
# Measured on a freshly reinstalled node, 2026-08-23.
if [ "$with_linux" = "1" ]; then
	sysrc linux_enable=YES >/dev/null
	service linux start >/dev/null 2>&1 || kldload -n linux linux64 || true
	echo "linuxulator: enabled"
fi

# --- packages ------------------------------------------------------------
pkgs="ocijail curl skopeo docker-registry"
[ "$with_linux" = "1" ] && pkgs="$pkgs linux_base-rl9"
missing=""
for p in $pkgs; do
	pkg info -e "$p" >/dev/null 2>&1 || missing="$missing $p"
done
if [ -n "$missing" ]; then
	echo "installing:$missing"
	env ASSUME_ALWAYS_YES=yes pkg update -q >/dev/null
	# shellcheck disable=SC2086
	env ASSUME_ALWAYS_YES=yes pkg install -y $missing
else
	echo "packages: already installed ($pkgs)"
fi

# --- hostname ------------------------------------------------------------
# The OVH images ship hostname="freebsd" in rc.conf and let the cloud-init
# datasource set the real name at boot. Pin the running name so a reboot
# cannot silently give all three nodes the same identity.
running_host=$(hostname)
if [ "$(sysrc -n hostname 2>/dev/null)" != "$running_host" ]; then
	sysrc hostname="$running_host" >/dev/null
	echo "hostname: pinned to $running_host in rc.conf"
else
	echo "hostname: $running_host (already pinned)"
fi

# --- kern.racct.enable (boot-time tunable) -------------------------------
# sysrc(8) rejects dotted names, so this is a plain append to loader.conf.
if grep -q '^kern\.racct\.enable=1' /boot/loader.conf; then
	echo "loader.conf: kern.racct.enable=1 already set"
else
	echo 'kern.racct.enable=1' >>/boot/loader.conf
	echo "loader.conf: kern.racct.enable=1 appended"
fi

# --- IP forwarding -------------------------------------------------------
if [ "$(sysrc -n gateway_enable 2>/dev/null)" = "YES" ]; then
	echo "rc.conf: gateway_enable already YES"
else
	sysrc gateway_enable=YES >/dev/null
	echo "rc.conf: gateway_enable=YES"
fi
sysctl net.inet.ip.forwarding=1 >/dev/null
echo "sysctl: net.inet.ip.forwarding=1"

# --- pf ------------------------------------------------------------------
# Same shape as the dev host's /etc/pf.conf: no policy of our own, just the
# satl/* anchors (translation anchors first) and `pass all`.
cat >/tmp/.satl-pf.conf <<'PFCONF'
# /etc/pf.conf — SatL cluster test node.
# Managed by tests/cluster/provision.sh; edits are overwritten.
#
# This host runs no firewall policy: the only reason pf is enabled is that
# SatL publishes container ports through its own anchors (docs/networking.md).
# SatL owns the "satl/*" anchors and never touches rules outside them.
#
# Translation anchors must be declared before filter rules.
nat-anchor "satl/*"
rdr-anchor "satl/*"
anchor "satl/*"

# No filtering on this host.
pass all
PFCONF
if [ -f /etc/pf.conf ] && cmp -s /tmp/.satl-pf.conf /etc/pf.conf; then
	echo "pf.conf: already current"
else
	install -m 0644 /tmp/.satl-pf.conf /etc/pf.conf
	echo "pf.conf: written"
fi
rm -f /tmp/.satl-pf.conf
sysrc pf_enable=YES >/dev/null
kldload -n pf
pfctl -f /etc/pf.conf
if pfctl -s info 2>/dev/null | grep -q '^Status: Enabled'; then
	echo "pf: enabled, ruleset loaded"
else
	pfctl -e
	echo "pf: enabled now, ruleset loaded"
fi

# --- ZFS -----------------------------------------------------------------
if zfs list -H -o name "$zfs_root" >/dev/null 2>&1; then
	echo "zfs: $zfs_root exists (mountpoint $(zfs get -H -o value mountpoint "$zfs_root"))"
else
	zfs create -o mountpoint="$state_dir" "$zfs_root"
	echo "zfs: created $zfs_root at $state_dir"
fi
mkdir -p "$registry_root"

# --- does this node still need a reboot? ---------------------------------
if [ "$(sysctl -n kern.racct.enable)" != "1" ]; then
	echo "PROVISION_REBOOT_REQUIRED"
fi
echo "PROVISION_DONE"
REMOTE
}

# ------------------------------------------------------------------------
# Phase 2 — verify. Every check prints "  [ ok ] ..." or "  [FAIL] ..."; the
# script exits non-zero if any check failed, after running them all so one
# run tells you everything that is wrong.
# ------------------------------------------------------------------------
verify_node() {
	node_root_sh "$1" "$(cluster_setting zfs_root)" "$(cluster_setting state_dir)" \
	    "$(cluster_setting underlay_if)" "$2" <<'REMOTE'
zfs_root=$1
state_dir=$2
underlay_if=$3
want_private_ip=$4
fails=0

check() { # check <label> <expected> <actual>
	if [ "$2" = "$3" ]; then
		printf '  [ ok ] %-26s %s\n' "$1" "$3"
	else
		printf '  [FAIL] %-26s %s (expected %s)\n' "$1" "$3" "$2"
		fails=$((fails + 1))
	fi
}
present() { # present <label> <binary> [version-command...]
	label=$1; bin=$2; shift 2
	if command -v "$bin" >/dev/null 2>&1; then
		printf '  [ ok ] %-26s %s\n' "$label" \
		    "$("$@" 2>&1 | head -1 | cut -c 1-60)"
	else
		printf '  [FAIL] %-26s %s\n' "$label" "not installed"
		fails=$((fails + 1))
	fi
}

printf '  %-33s %s\n' "os" "$(uname -r) $(uname -m), $(hostname)"
check "kern.racct.enable" 1 "$(sysctl -n kern.racct.enable)"
check "net.inet.ip.forwarding" 1 "$(sysctl -n net.inet.ip.forwarding)"
check "rc.conf gateway_enable" YES "$(sysrc -n gateway_enable 2>/dev/null)"
check "rc.conf pf_enable" YES "$(sysrc -n pf_enable 2>/dev/null)"
check "pf status" Enabled \
    "$(pfctl -s info 2>/dev/null | awk '/^Status:/ { print $2; exit }')"
check "pf satl anchors" 3 \
    "$(grep -cE '^(nat-anchor|rdr-anchor|anchor) "satl/\*"' /etc/pf.conf 2>/dev/null)"
check "zfs $zfs_root" "$state_dir" \
    "$(zfs get -H -o value mountpoint "$zfs_root" 2>/dev/null)"
check "$underlay_if address" "$want_private_ip" \
    "$(ifconfig "$underlay_if" 2>/dev/null | awk '$1 == "inet" { print $2; exit }')"
present "ocijail" ocijail ocijail --version
present "skopeo" skopeo skopeo --version
present "curl" curl curl --version
if pkg info -e docker-registry; then
	printf '  [ ok ] %-26s %s\n' "docker-registry" "$(pkg query %v docker-registry)"
else
	printf '  [FAIL] %-26s %s\n' "docker-registry" "not installed"
	fails=$((fails + 1))
fi

if sysctl -n compat.linux.osrelease >/dev/null 2>&1; then
	printf '  [ ok ] %-26s %s\n' "linuxulator (advisory)" \
	    "available ($(sysctl -n compat.linux.osrelease))"
else
	printf '  [ -- ] %-26s %s\n' "linuxulator (advisory)" \
	    "off — linux/* images cannot run (SATL_WITH_LINUX=1 to enable)"
fi

[ "$fails" -eq 0 ] || { echo "  $fails check(s) failed"; exit 1; }
echo "PROVISION_VERIFIED"
REMOTE
}

# ------------------------------------------------------------------------

provision_node() {
	node=$1
	host=$(node_field "$node" ssh_host)
	private_ip=$(node_field "$node" private_ip)
	hdr "$node ($host, role $(node_field "$node" role))"

	node_ssh "$node" true >/dev/null 2>&1 ||
	    die "$node: cannot ssh to $host (BatchMode; check your key and the host)"

	out=$(mktempf satl-provision)
	trap 'rm -f "$out"' EXIT INT TERM

	configure_node "$node" 2>&1 | sed 's/^/  /' | tee "$out"
	grep -q '^ *PROVISION_DONE$' "$out" ||
	    die "$node: configuration failed (see the output above)"

	if grep -q '^ *PROVISION_REBOOT_REQUIRED$' "$out"; then
		info "kern.racct.enable is a boot-time tunable — rebooting $node"
		node_ssh "$node" 'sudo -n shutdown -r now' >/dev/null 2>&1 || true
		sleep 15
		node_wait_ssh "$node" "$REBOOT_WAIT" ||
		    die "$node: did not come back within ${REBOOT_WAIT}s after reboot"
		info "back up after $(node_ssh "$node" uptime | sed 's/^ *//')"
	fi

	: >"$out"
	verify_node "$node" "$private_ip" 2>&1 | tee "$out"
	grep -q '^PROVISION_VERIFIED$' "$out" || {
		rm -f "$out"
		trap - EXIT INT TERM
		return 1
	}
	rm -f "$out"
	trap - EXIT INT TERM
	return 0
}

nodes=$(resolve_nodes "$@")
[ -n "$nodes" ] || die "no nodes selected"

failed=""
for n in $nodes; do
	if provision_node "$n"; then
		info "$n provisioned"
	else
		failed="$failed $n"
	fi
done

hdr "summary"
for n in $nodes; do
	case " $failed " in
	*" $n "*) printf '  %-8s FAILED\n' "$n" ;;
	*) printf '  %-8s ready\n' "$n" ;;
	esac
done

if [ -n "$failed" ]; then
	log ""
	log "Nodes needing attention:$failed"
	log "Re-run 'sh tests/cluster/provision.sh$failed' after fixing the reported checks."
	exit 1
fi

log ""
log "All selected nodes provisioned. Next: tests/cluster/deploy.sh, then images.sh."
