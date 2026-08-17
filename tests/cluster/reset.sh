#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# tests/cluster/reset.sh — return nodes to a clean, pre-cluster state.
#
# Usage: tests/cluster/reset.sh [-h] [--no-start] [node ...]
#
#   With no node names, every node in inventory.toml is reset.
#   --no-start   leave satld stopped (default: start it again afterwards)
#
# M2 testing means running init/join over and over, and a node that still
# carries raft state, certificates or a node identity from the previous run
# will refuse to join or, worse, rejoin the cluster it is supposed to be new
# to. This is the "make it new again" button.
#
# What it destroys, on each node:
#   - the satld service (stopped first, so nothing races the teardown)
#   - every jail whose root is under the state directory, its rctl rules, every
#     orphaned SatL rctl rule set whose jail is already gone (rules survive
#     their jail's death and nothing else removes them), and every interface
#     SatL marked with a "satl:" description (epairs leak when a teardown is
#     interrupted — CLAUDE.md, FreeBSD gotchas)
#   - the satl/nat and satl/rdr pf anchors (and ONLY those: invariant, SatL
#     never touches rules outside its own anchors)
#   - zroot/satl and everything under it: raft log, DEK, node identity,
#     certificates, images, layers, containers, volumes
#
# What it keeps:
#   - the test registry and its images (/var/db/satl-test-registry lives
#     outside zroot/satl precisely so a reset does not force a re-seed)
#   - packages, sysctls, pf.conf, the installed binaries — that is
#     provision.sh and deploy.sh territory
#
# Environment:
#   SATL_INVENTORY      alternate inventory.toml

set -e

CLUSTER_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$CLUSTER_DIR/lib.sh"

usage() {
	sed -n '2,/^$/p' "$0" | sed 's/^#//; s/^ //'
	exit "${1:-0}"
}

START_AFTER=1
while [ "$#" -gt 0 ]; do
	case $1 in
	-h | --help) usage 0 ;;
	--no-start) START_AFTER=0; shift ;;
	-*) die "unknown option: $1 (try -h)" ;;
	*) break ;;
	esac
done

nodes=$(resolve_nodes "$@")
[ -n "$nodes" ] || die "no nodes selected"

reset_node() {
	node_root_sh "$1" "$(cluster_setting zfs_root)" "$(cluster_setting state_dir)" "$2" <<'REMOTE'
set -e
zfs_root=$1
state_dir=$2
start_after=$3

if service satld status >/dev/null 2>&1; then
	service satld stop >/dev/null 2>&1 || true
	echo "satld: stopped"
else
	echo "satld: was not running"
fi

# Jails first: a jail holding a mount inside the dataset blocks zfs destroy.
# The rctl rules go BEFORE the jail out of habit, not necessity: rules survive
# the jail's death, and `rctl -r` on a dead subject works fine (rc=0, rules
# gone) -- measured on FreeBSD 15.1. "No such process" is what rctl answers
# when the filter matches NO rule, not when the subject is dead. The sweep
# below reaps whatever this loop (or a crash, or an older satld) left behind.
killed=0
for entry in $(jls -N name jid path 2>/dev/null |
    awk -v d="$state_dir/" '$3 ~ "^" d { print $1 ":" $2 }'); do
	rctl -r "jail:${entry%%:*}" >/dev/null 2>&1 || true
	jail -r "${entry##*:}" >/dev/null 2>&1 || true
	killed=$((killed + 1))
done
echo "jails: removed $killed under $state_dir"

# Orphan rctl rules: installed for a jail that no longer exists. Only
# SatL-shaped subjects are touched -- jail name = 25-char base36 task id --
# because another tool may manage its own jails' rules. Subjects that still
# have a live jail (jls) are kept.
purged=0
live_jails=$(jls -N name 2>/dev/null || true)
for name in $(rctl 2>/dev/null |
    sed -n 's/^jail:\([0-9a-z]\{25\}\):.*/\1/p' | sort -u); do
	if printf '%s\n' "$live_jails" | grep -qx "$name"; then
		continue
	fi
	if rctl -r "jail:$name" >/dev/null 2>&1; then
		purged=$((purged + 1))
	fi
done
echo "rctl: purged $purged orphan rule set(s)"

# Then the interfaces SatL owns. The description is the only marker that
# survives a vnet move and the jail's death (docs/networking.md).
destroyed=0
for ifn in $(ifconfig -a 2>/dev/null |
    awk '/^[a-z]/ { n = $1; sub(/:$/, "", n) } /^[[:space:]]*description: satl:/ { print n }'); do
	ifconfig "$ifn" destroy >/dev/null 2>&1 || true
	destroyed=$((destroyed + 1))
done
echo "interfaces: destroyed $destroyed marked satl:"

# Only SatL's own anchors, never the main ruleset.
for anchor in satl/nat satl/rdr satl/guard; do
	pfctl -a "$anchor" -F all >/dev/null 2>&1 || true
done
echo "pf: satl/nat, satl/rdr and satl/guard flushed"

# The encrypted-overlay IPsec state (M6): SAD and SPD. Node-wide, but nothing
# but satld programs IPsec on these VMs. The enc0 substrate (filter mask 2,
# enc0 up) is deliberately left: it is documented inert with no encrypted
# networks, and satld leaves it behind on teardown too (crates/satld/src/
# guard.rs).
setkey -F >/dev/null 2>&1 || true
setkey -FP >/dev/null 2>&1 || true
echo "ipsec: SAD and SPD flushed"

# Unmount anything still mounted under the state dir (linprocfs, linsysfs,
# devfs, fdescfs and the per-task tmpfs a container carries) before destroying
# the dataset.
#
# `mount -p`, NOT plain `mount`. ocijail makes these mounts MNT_IGNORE, and
# mount(8) hides those unless -v is given ("show all file systems, including
# those that were mounted with the MNT_IGNORE flag"). This loop used plain
# `mount`, so it saw only the ZFS rows -- and then force-unmounted the
# *container datasets*, which strands their MNT_IGNORE submounts on a
# mountpoint whose filesystem is gone. `zfs destroy -r` then succeeds where it
# would otherwise have refused ("pool or dataset is busy"), and the leftovers
# accumulate one full set per removed container per reset: 54, 54 and 56 stale
# tmpfs measured across the three nodes, invisible to `mount`, `mount -t tmpfs`
# and (once orphaned, because statfs fails) `df -t tmpfs` as well.
#
# Deepest-first (`sort -r` on the path) so /dev/fd goes before /dev, and the
# leaf mounts go before the ZFS dataset they sit inside. `mount -p` prints
# `special<TAB>node<TAB>...`, with a single space instead of the tab when the
# node overflows its tab stop -- so the mountpoint is field 2 under
# `-F'[\t ]+'` either way.
mount -p | awk -F'[\t ]+' -v d="$state_dir/" '$2 ~ "^" d { print $2 }' |
    awk '{ print gsub("/", "/"), $0 }' | sort -rn -k1,1 | cut -d' ' -f2- |
    while read -r mp; do umount -f "$mp" >/dev/null 2>&1 || true; done

if zfs list -H -o name "$zfs_root" >/dev/null 2>&1; then
	zfs destroy -r "$zfs_root"
	echo "zfs: destroyed $zfs_root (raft state, DEK, node identity, images, layers)"
fi
# Extracted image layers restore schg flags on ~10 base files, so a plain
# rm fails until the flags come off (docs/image-sources.md §4).
if [ -d "$state_dir" ]; then
	chflags -R noschg "$state_dir" >/dev/null 2>&1 || true
	rm -rf "${state_dir:?}"/* >/dev/null 2>&1 || true
fi
zfs create -o mountpoint="$state_dir" "$zfs_root"
echo "zfs: recreated $zfs_root at $state_dir"

if [ "$start_after" = "1" ]; then
	service satld start
	i=0
	while [ "$i" -lt 30 ]; do
		satl version >/dev/null 2>&1 && break
		sleep 1
		i=$((i + 1))
	done
	satl version >/dev/null || { echo "satld did not come back"; exit 1; }
	echo "satld: started, fresh node identity"
fi
echo "RESET_DONE"
REMOTE
}

failed=""
for n in $nodes; do
	hdr "$n ($(node_field "$n" ssh_host))"
	out=$(mktempf satl-reset)
	reset_node "$n" "$START_AFTER" 2>&1 | sed 's/^/  /' | tee "$out"
	grep -q '^ *RESET_DONE$' "$out" || failed="$failed $n"
	rm -f "$out"
done

hdr "summary"
for n in $nodes; do
	case " $failed " in
	*" $n "*) printf '  %-8s FAILED\n' "$n" ;;
	*) printf '  %-8s clean\n' "$n" ;;
	esac
done

[ -z "$failed" ] || { log ""; log "Nodes needing attention:$failed"; exit 1; }

log ""
log "Cluster reset. Every node is a fresh single-node cluster again."
