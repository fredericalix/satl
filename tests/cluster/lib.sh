# SPDX-License-Identifier: BSD-2-Clause
# shellcheck shell=sh
# tests/cluster/lib.sh — shared helpers for the SatL cluster scripts.
#
# Usage: sourced, never executed:  . "$(dirname "$0")/lib.sh"
#
# Provides inventory access (the only place inventory.toml is parsed) and thin
# ssh/scp wrappers that always use BatchMode so nothing can ever hang waiting
# for a password or a host-key prompt.

# Resolved by the sourcing script; SATL_INVENTORY overrides for a scratch cluster.
: "${CLUSTER_DIR:?lib.sh: set CLUSTER_DIR before sourcing}"
INVENTORY="${SATL_INVENTORY:-$CLUSTER_DIR/inventory.toml}"

SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR"

# ---------------------------------------------------------------- output ----

log()  { printf '%s\n' "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# mktempf <prefix> — a temp file, spelled the one way both FreeBSD's and GNU's
# mktemp accept (`-t prefix` is FreeBSD-only, an explicit template is not).
mktempf() {
	mktemp "${TMPDIR:-/tmp}/$1.XXXXXX" || die "mktemp failed"
}

hdr() {
	printf '\n== %s %s\n' "$1" \
	    "$(echo '=======================================================' |
	        cut -c "$((${#1} + 4))-")"
}

# ------------------------------------------------------------- inventory ----

# _inv <mode> [arg1] [arg2] — the one and only inventory.toml parser.
#
# Handles the subset of TOML this file uses: a [cluster] table of quoted
# scalars and an array of [[node]] tables of quoted scalars. Anything else in
# the file is ignored, so it fails loudly on a missing key rather than quietly
# mis-parsing a construct it does not support.
_inv() {
	[ -f "$INVENTORY" ] || die "inventory not found: $INVENTORY"
	awk -v mode="$1" -v a1="${2:-}" -v a2="${3:-}" '
		/^[[:space:]]*#/                { next }
		/^[[:space:]]*\[\[node\]\]/     { n++; sec = "node"; next }
		/^[[:space:]]*\[[A-Za-z_]+\]/   { sec = "table"; next }
		{
			if (match($0, /^[[:space:]]*[A-Za-z_]+[[:space:]]*=[[:space:]]*"[^"]*"/) == 0)
				next
			key = $0; sub(/^[[:space:]]*/, "", key); sub(/[[:space:]]*=.*$/, "", key)
			val = $0; sub(/^[^=]*=[[:space:]]*"/, "", val); sub(/".*$/, "", val)
			if (sec == "node") { node[n, key] = val; if (key == "name") order[n] = val }
			else               { setting[key] = val }
		}
		END {
			if (mode == "nodes") { for (i = 1; i <= n; i++) print order[i]; exit 0 }
			if (mode == "role") {
				for (i = 1; i <= n; i++) if (node[i, "role"] == a1) print order[i]
				exit 0
			}
			if (mode == "setting") {
				if (!(a1 in setting)) {
					printf "inventory: no [cluster] setting %s\n", a1 > "/dev/stderr"
					exit 1
				}
				print setting[a1]; exit 0
			}
			if (mode == "field") {
				for (i = 1; i <= n; i++) if (order[i] == a1) {
					if (!((i SUBSEP a2) in node)) {
						printf "inventory: node %s has no field %s\n", a1, a2 > "/dev/stderr"
						exit 1
					}
					print node[i, a2]; exit 0
				}
				printf "inventory: no node named %s\n", a1 > "/dev/stderr"
				exit 1
			}
			printf "inventory: bad query mode %s\n", mode > "/dev/stderr"
			exit 1
		}
	' "$INVENTORY"
}

cluster_nodes()   { _inv nodes; }              # all node names, in file order
nodes_with_role() { _inv role "$1"; }          # node names having role $1
node_field()      { _inv field "$1" "$2"; }    # <node> <field> -> value
cluster_setting() { _inv setting "$1"; }       # <key> -> value from [cluster]

# The single bootstrap manager, or an error if the inventory does not name
# exactly one. Callers must never assume it is the first node.
bootstrap_node() {
	_bn=$(nodes_with_role bootstrap)
	[ -n "$_bn" ] || die "inventory: no node has role = \"bootstrap\""
	[ "$(echo "$_bn" | wc -l | tr -d ' ')" = "1" ] ||
	    die "inventory: more than one node has role = \"bootstrap\""
	echo "$_bn"
}

# Validate node names given on the command line; with none, return them all.
resolve_nodes() {
	if [ "$#" -eq 0 ]; then
		cluster_nodes
		return 0
	fi
	for _rn in "$@"; do
		node_field "$_rn" name >/dev/null || exit 1
		echo "$_rn"
	done
}

# --------------------------------------------------------------- ssh/scp ----

node_target() { printf '%s@%s' "$(cluster_setting ssh_user)" "$(node_field "$1" ssh_host)"; }

# shquote <word...> — emit the words single-quoted, each preceded by a space.
#
# ssh(1) flattens its command arguments into one string and hands it to the
# remote shell, so anything with a space in it arrives split unless it was
# quoted first. Every remote invocation below goes through this.
shquote() {
	for _sq in "$@"; do
		printf " '"
		printf '%s' "$_sq" | sed "s/'/'\\\\''/g"
		printf "'"
	done
}

# node_ssh <node> [command...] — run a command as the unprivileged user.
node_ssh() {
	_ns=$1
	shift
	# shellcheck disable=SC2086  # SSH_OPTS must word-split
	ssh $SSH_OPTS "$(node_target "$_ns")" "$@"
}

# node_sh <node> [args...] — feed a script on stdin to `sh -s` on the node,
# unprivileged. The remote script sees the args as $1..$n. Keeps quoting sane:
# no shell metacharacter has to survive two levels of expansion.
node_sh() {
	_nu=$1
	shift
	# shellcheck disable=SC2086
	ssh $SSH_OPTS "$(node_target "$_nu")" "/bin/sh -s --$(shquote "$@")"
}

# node_root_sh <node> [args...] — same, as root via passwordless sudo.
node_root_sh() {
	_nr=$1
	shift
	# shellcheck disable=SC2086
	ssh $SSH_OPTS "$(node_target "$_nr")" "sudo -n /bin/sh -s --$(shquote "$@")"
}

# node_scp <node> <remote-dir> <local-file...> — note the destination comes
# second, so the variable-length file list stays in "$@".
node_scp() {
	_nc=$1
	_dest=$2
	shift 2
	# shellcheck disable=SC2086
	scp $SSH_OPTS -q "$@" "$(node_target "$_nc"):$_dest/"
}

# node_wait_ssh <node> <timeout-seconds> — poll until the node answers ssh.
node_wait_ssh() {
	_nw=$1
	_deadline=$2
	_waited=0
	while [ "$_waited" -lt "$_deadline" ]; do
		if node_ssh "$_nw" true >/dev/null 2>&1; then
			return 0
		fi
		sleep 5
		_waited=$((_waited + 5))
	done
	return 1
}
