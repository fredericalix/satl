#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# tests/cluster/deploy.sh — build satl/satld here and install them on the VMs.
#
# Usage: tests/cluster/deploy.sh [-h] [node ...]
#
#   With no node names, every node in inventory.toml is deployed to.
#   Idempotent and safe to re-run after every code change; that is its job.
#
# Environment:
#   SATL_SKIP_BUILD=1   deploy target/release/{satl,satld} as they are
#   SATL_INVENTORY      alternate inventory.toml
#   SATL_SATLD_EXTRA    extra satld.toml lines appended verbatim to every
#                       node's generated config — testing knobs only
#                       (e.g. SATL_SATLD_EXTRA='cert_validity = "5m"' for
#                       the certificate-renewal scenario). Never set this
#                       for normal runs; the default template must stay
#                       what production nodes run.
#
# Mirrors `make install` exactly (same paths, same modes) and additionally
# writes /usr/local/etc/satl/satld.toml, which `make install` does not: the
# test cluster wants pf_mode = "enforce" (published ports) and a node_name
# taken from the inventory, so cluster assertions can name nodes deterministically
# instead of depending on whatever hostname the cloud image booted with.
#
# That config is rewritten on every deploy — do not hand-edit it on a node,
# change the template below instead.

set -e

CLUSTER_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$CLUSTER_DIR/../.." && pwd)
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

PREFIX=$(cluster_setting prefix)
# /var/tmp is world-writable and outlives a reboot, so both the login user and
# root see the same staging directory without any $HOME guessing.
STAGE=/var/tmp/satl-deploy

nodes=$(resolve_nodes "$@")
[ -n "$nodes" ] || die "no nodes selected"

# ---------------------------------------------------------------- build -----

if [ "${SATL_SKIP_BUILD:-0}" = "1" ]; then
	log "SATL_SKIP_BUILD=1 — deploying the existing target/release binaries"
else
	hdr "build (make release)"
	(cd "$REPO_ROOT" && make release)
fi

for f in target/release/satl target/release/satld rc.d/satld etc/satld.toml.sample; do
	[ -f "$REPO_ROOT/$f" ] || die "missing build artifact: $REPO_ROOT/$f"
done

# The remote half. Emitted on stdout and piped into `sudo sh -s` on the node,
# so install paths and modes live in exactly one place.
remote_install() {
	cat <<'REMOTE'
set -e
prefix=$1
stage=$2

[ -d "$stage" ] || { echo "staging directory $stage not found"; exit 1; }

# Stop before overwriting: satld is running from the file we are about to
# replace, and the new binary needs a restart to take effect anyway.
if service satld status >/dev/null 2>&1; then
	service satld stop >/dev/null 2>&1 || true
	echo "satld: stopped"
fi

install -d "$prefix/bin" "$prefix/sbin" "$prefix/etc/rc.d" "$prefix/etc/satl"
install -m 0755 "$stage/satl" "$prefix/bin/satl"
install -m 0755 "$stage/satld" "$prefix/sbin/satld"
install -m 0755 "$stage/satld.rc" "$prefix/etc/rc.d/satld"
install -m 0644 "$stage/satld.toml.sample" "$prefix/etc/satl/satld.toml.sample"
install -m 0644 "$stage/satld.toml" "$prefix/etc/satl/satld.toml"
echo "installed: $prefix/bin/satl $prefix/sbin/satld $prefix/etc/rc.d/satld"
echo "           $prefix/etc/satl/satld.toml{,.sample}"

sysrc satld_enable=YES >/dev/null
service satld start

# The socket appears a moment after the process does. Poll for it so a slow
# start reads as slow, not as broken.
i=0
while [ "$i" -lt 30 ]; do
	satl version >/dev/null 2>&1 && break
	sleep 1
	i=$((i + 1))
done
satl version || { echo "satld did not answer on its socket within ${i}s"; exit 1; }
service satld status
echo "DEPLOY_DONE"
REMOTE
}

# --------------------------------------------------------------- deploy -----

failed=""
for n in $nodes; do
	host=$(node_field "$n" ssh_host)
	hdr "$n ($host, role $(node_field "$n" role))"

	node_ssh "$n" true >/dev/null 2>&1 ||
	    die "$n: cannot ssh to $host (BatchMode; check your key and the host)"

	# Per-node satld.toml, generated here so a node never has to know its
	# own name: inventory.toml stays the only source of truth.
	cfg=$(mktempf satld-toml)
	cat >"$cfg" <<EOF
# Managed by tests/cluster/deploy.sh — rewritten on every deploy.
# Node $n (role $(node_field "$n" role)), underlay $(node_field "$n" private_ip).
node_name = "$n"
# Published ports and container egress NAT need the satl/* anchors loaded;
# provision.sh has already declared them in /etc/pf.conf.
pf_mode = "enforce"
zfs_root = "$(cluster_setting zfs_root)"
state_dir = "$(cluster_setting state_dir)"
# Cluster traffic (raft, dispatcher, CA) rides the private underlay, never
# the public interface. satld would otherwise advertise the address of the
# default-route interface — which on these VMs is the *public* vtnet0, so
# every node would publish a public endpoint and the cluster would talk to
# itself across the internet.
listen_addr = "$(node_field "$n" private_ip):2377"
advertise_addr = "$(node_field "$n" private_ip):2377"
EOF
	# Testing knobs, appended only when the caller asks for them (see the
	# header). Kept out of the template so a normal deploy cannot pick one
	# up by accident.
	if [ -n "${SATL_SATLD_EXTRA:-}" ]; then
		printf '# Testing knobs (SATL_SATLD_EXTRA):\n%s\n' "$SATL_SATLD_EXTRA" >>"$cfg"
	fi

	node_ssh "$n" "mkdir -p $STAGE"
	node_scp "$n" "$STAGE" \
	    "$REPO_ROOT/target/release/satl" \
	    "$REPO_ROOT/target/release/satld" \
	    "$REPO_ROOT/etc/satld.toml.sample"
	# scp cannot rename inside a multi-file copy, so these two go separately.
	# shellcheck disable=SC2086
	scp $SSH_OPTS -q "$REPO_ROOT/rc.d/satld" "$(node_target "$n"):$STAGE/satld.rc"
	# shellcheck disable=SC2086
	scp $SSH_OPTS -q "$cfg" "$(node_target "$n"):$STAGE/satld.toml"
	rm -f "$cfg"
	info "staged binaries, rc.d script and config in $STAGE"

	out=$(mktempf satl-deploy)
	remote_install | node_root_sh "$n" "$PREFIX" "$STAGE" 2>&1 |
	    sed 's/^/  /' | tee "$out"
	grep -q '^ *DEPLOY_DONE$' "$out" || failed="$failed $n"
	rm -f "$out"
done

hdr "summary"
for n in $nodes; do
	case " $failed " in
	*" $n "*) printf '  %-8s FAILED\n' "$n" ;;
	*) printf '  %-8s satld running, satl version answers\n' "$n" ;;
	esac
done

if [ -n "$failed" ]; then
	log ""
	log "Nodes needing attention:$failed"
	exit 1
fi

log ""
log "Deployed. Next: tests/cluster/images.sh, then tests/cluster/run.sh."
