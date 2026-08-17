#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# tests/cluster/images.sh — give every VM the SatL test images, locally.
#
# Usage: tests/cluster/images.sh [-h] [node ...]
#
#   With no node names, every node in inventory.toml is seeded.
#   Idempotent: skopeo skips blobs the destination registry already has, so a
#   re-run of a seeded node transfers almost nothing.
#
# Environment:
#   SATL_IMAGES         space-separated repo:tag list (default: the four of
#                       docs/image-sources.md §5 plus the locally built
#                       freebsd-redis the compose scenario needs), relative to
#                       the namespace
#   SATL_TUNNEL_PORT    remote port for the reverse tunnel (default 15000)
#   SATL_INVENTORY      alternate inventory.toml
#
#
# THE DECISION: one loopback-only registry per VM, seeded from the dev host's
# registry over an SSH reverse tunnel.
#
# Constraints (measured 2026-08-10, not assumed):
#   - The dev host's registry listens on 127.0.0.1:5000 only, has no auth and
#     no TLS (docs/image-sources.md §2). Exposing it as-is is not an option.
#   - The dev host has NO address on the 10.2.0.0/16 underlay: its second NIC
#     (ice1) is up but carries no IPv4, so "bind the registry on the private
#     interface" — the cheapest option on paper — is simply unavailable.
#   - The VMs can reach the dev host's public IP, but publishing an
#     unauthenticated read-write registry on a public address is not something
#     a test harness should do.
#   - The VMs reach each other over 10.2.0.0/16 at sub-millisecond latency.
#
# Rejected: a single registry on the bootstrap node, with the other two
# pulling from its private address. It is one fewer copy, but it makes the
# image source die with node 1 — and "kill a node and watch tasks reschedule"
# is an M2 DoD scenario. A rescheduled task would then fail to pull for a
# reason that has nothing to do with the code under test.
#
# Chosen: each node runs the same registry the dev host runs, on 127.0.0.1:5000,
# with the same config and the same repository names. Consequences worth the
# ~100 MB of duplicated transfer:
#   - image references are IDENTICAL to the single-node integration tests
#     (127.0.0.1:5000/satl-test/...), so nothing has to rewrite registry URLs
#     per node and no test needs to know which node it runs on;
#   - no node depends on any other node for images — killing any VM leaves the
#     other two fully able to pull;
#   - satld's insecure-registry handling is exercised the same way everywhere.
#
# The seeding hop is `ssh -R` rather than scp of an OCI layout because it keeps
# a registry-to-registry `skopeo copy --all`, which reproduces the source index
# byte-for-byte (docs/image-sources.md §3) — multi-platform manifest lists
# included, which is exactly what platform-selection tests need.

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

REG_PORT=$(cluster_setting registry_port)
REG_NS=$(cluster_setting registry_namespace)
REG_ROOT=$(cluster_setting registry_root)
TUNNEL_PORT=${SATL_TUNNEL_PORT:-15000}
IMAGES=${SATL_IMAGES:-"freebsd-runtime:15.1 freebsd-nginx:latest freebsd-redis:latest alpine:latest debian:stable-slim"}

nodes=$(resolve_nodes "$@")
[ -n "$nodes" ] || die "no nodes selected"

# ------------------------------------------------- source registry check ----

hdr "source registry (dev host)"
curl -sf "http://127.0.0.1:$REG_PORT/v2/" >/dev/null ||
    die "the dev host registry is not answering on 127.0.0.1:$REG_PORT — \
'service docker_registry start' (docs/image-sources.md §2)"
for img in $IMAGES; do
	repo=${img%:*}
	tag=${img#*:}
	curl -sf "http://127.0.0.1:$REG_PORT/v2/$REG_NS/$repo/manifests/$tag" \
	    -H 'Accept: application/vnd.oci.image.index.v1+json' \
	    -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
	    -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
	    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
	    >/dev/null ||
	    die "$REG_NS/$img is missing from the dev host registry — reseed it \
per docs/image-sources.md §3"
	info "$REG_NS/$img present"
done

# --------------------------------------------------- registry on a node ----

setup_registry() {
	node_root_sh "$1" "$REG_PORT" "$REG_ROOT" <<'REMOTE'
set -e
port=$1
root=$2

pkg info -e docker-registry >/dev/null 2>&1 ||
	{ echo "docker-registry is not installed — run provision.sh first"; exit 1; }
command -v skopeo >/dev/null 2>&1 ||
	{ echo "skopeo is not installed — run provision.sh first"; exit 1; }

mkdir -p /usr/local/etc/docker-registry "$root"

# Byte-identical in shape to the dev host's config (docs/image-sources.md §2):
# loopback only, no auth, no TLS, deletion enabled, storage outside zroot/satl
# because this is test infrastructure and not satld state — reset.sh destroys
# zroot/satl and must not take the images with it.
cat >/tmp/.satl-registry.yml <<YAML
# SatL test registry — local, unauthenticated, loopback only.
# Managed by tests/cluster/images.sh; see docs/image-sources.md.
version: 0.1
log:
  fields:
    service: satl-test-registry
storage:
  cache:
    blobdescriptor: inmemory
  filesystem:
    rootdirectory: $root
  delete:
    enabled: true
http:
  addr: 127.0.0.1:$port
  headers:
    X-Content-Type-Options: [nosniff]
health:
  storagedriver:
    enabled: true
    interval: 10s
    threshold: 3
YAML

cfg=/usr/local/etc/docker-registry/config.yml
if [ -f "$cfg" ] && cmp -s /tmp/.satl-registry.yml "$cfg"; then
	echo "registry config: already current"
else
	install -m 0644 /tmp/.satl-registry.yml "$cfg"
	echo "registry config: written to $cfg"
	service docker_registry stop >/dev/null 2>&1 || true
fi
rm -f /tmp/.satl-registry.yml

sysrc docker_registry_enable=YES >/dev/null
# The output redirection is load-bearing, not tidiness: unlike satld's rc.d
# script, docker_registry's does not pass daemon(8) -f, so the registry
# inherits our stdout. Over ssh that is the session pipe, and ssh then waits
# forever for a daemon that never exits. The poll below reports failures.
service docker_registry status >/dev/null 2>&1 ||
	service docker_registry start >/dev/null 2>&1 </dev/null

i=0
while [ "$i" -lt 30 ]; do
	curl -sf "http://127.0.0.1:$port/v2/" >/dev/null 2>&1 && break
	sleep 1
	i=$((i + 1))
done
curl -sf "http://127.0.0.1:$port/v2/" >/dev/null ||
	{ echo "registry did not answer on 127.0.0.1:$port within ${i}s"; exit 1; }
echo "registry: answering on 127.0.0.1:$port"
echo "REGISTRY_READY"
REMOTE
}

# ------------------------------------------------------------ seeding ------

# skopeo runs ON the node and pulls through the reverse tunnel, so the copy is
# registry-to-registry and `--all` keeps the whole index. -o ExitOnForwardFailure
# turns a port clash into a loud failure instead of a silent fallback to
# "127.0.0.1:15000 is something else entirely".
seed_node() {
	# shellcheck disable=SC2086
	ssh $SSH_OPTS -o ExitOnForwardFailure=yes \
	    -R "127.0.0.1:$TUNNEL_PORT:127.0.0.1:$REG_PORT" \
	    "$(node_target "$1")" \
	    "/bin/sh -s --$(shquote "$TUNNEL_PORT" "$REG_PORT" "$REG_NS" "$IMAGES")" <<'REMOTE'
set -e
src_port=$1
dst_port=$2
ns=$3
images=$4

curl -sf "http://127.0.0.1:$src_port/v2/" >/dev/null ||
	{ echo "the ssh -R tunnel to the dev host registry is not usable"; exit 1; }

for img in $images; do
	printf '  copying %s/%s ... ' "$ns" "$img"
	skopeo copy --all --quiet \
	    --src-tls-verify=false --dest-tls-verify=false \
	    "docker://127.0.0.1:$src_port/$ns/$img" \
	    "docker://127.0.0.1:$dst_port/$ns/$img"
	echo done
done
echo "SEED_DONE"
REMOTE
}

verify_node_images() {
	node_sh "$1" "$REG_PORT" "$REG_NS" "$IMAGES" <<'REMOTE'
port=$1
ns=$2
images=$3
fails=0
accept='-H Accept:application/vnd.oci.image.index.v1+json
-H Accept:application/vnd.oci.image.manifest.v1+json
-H Accept:application/vnd.docker.distribution.manifest.list.v2+json
-H Accept:application/vnd.docker.distribution.manifest.v2+json'
for img in $images; do
	repo=${img%:*}
	tag=${img#*:}
	# shellcheck disable=SC2086
	digest=$(curl -sf -o /dev/null -D - $accept \
	    "http://127.0.0.1:$port/v2/$ns/$repo/manifests/$tag" 2>/dev/null |
	    awk 'tolower($1) == "docker-content-digest:" { print $2 }' | tr -d '\r')
	if [ -n "$digest" ]; then
		printf '  [ ok ] %-32s %s\n' "$ns/$img" "$digest"
	else
		printf '  [FAIL] %-32s not in the local registry\n' "$ns/$img"
		fails=$((fails + 1))
	fi
done
[ "$fails" -eq 0 ] || exit 1
echo "IMAGES_VERIFIED"
REMOTE
}

failed=""
for n in $nodes; do
	hdr "$n ($(node_field "$n" ssh_host))"
	out=$(mktempf satl-images)

	setup_registry "$n" 2>&1 | sed 's/^/  /' | tee "$out"
	if ! grep -q '^ *REGISTRY_READY$' "$out"; then
		failed="$failed $n"
		rm -f "$out"
		continue
	fi

	: >"$out"
	seed_node "$n" 2>&1 | tee "$out"
	if ! grep -q '^SEED_DONE$' "$out"; then
		failed="$failed $n"
		rm -f "$out"
		continue
	fi

	: >"$out"
	verify_node_images "$n" 2>&1 | tee "$out"
	grep -q '^IMAGES_VERIFIED$' "$out" || failed="$failed $n"
	rm -f "$out"
done

hdr "summary"
for n in $nodes; do
	case " $failed " in
	*" $n "*) printf '  %-8s FAILED\n' "$n" ;;
	*) printf '  %-8s registry ready, %s image(s) present\n' "$n" \
	    "$(echo "$IMAGES" | wc -w | tr -d ' ')" ;;
	esac
done

if [ -n "$failed" ]; then
	log ""
	log "Nodes needing attention:$failed"
	exit 1
fi

log ""
log "Every node serves the test images at 127.0.0.1:$REG_PORT/$REG_NS/ —"
log "the same references the single-node integration tests use."
