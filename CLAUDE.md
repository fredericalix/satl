# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What SatL is

A cluster-first container engine for FreeBSD, in Rust: OCI containers run as VNET jails
through the external `ocijail` runtime, with SwarmKit-style orchestration built in
(embedded Raft store, scheduler, reconciliation loops, VXLAN overlay, mTLS everywhere).
It speaks the Docker Engine REST API v1.43+ and mirrors the `docker` CLI.

Two binaries: **`satld`** (daemon, one per node, REST API + internal gRPC + worker and/or
manager components) and **`satl`** (thin REST client over `/var/run/satl.sock`; the CLI
never speaks gRPC). There is no standalone mode, a single node is a cluster of one.

## Where things live

- **Design docs are in `docs/`** and are tracked in git: `architecture.md` (the reference,
  numbered sections cited throughout the code), `roadmap.md` (live status + decision log),
  `project-brief.md` (the non-negotiables), `api-compat.md` (numbered Docker deviations),
  plus `networking.md`, `vxlan.md`, `ocijail.md`, `linuxulator.md`, `jail-teardown.md`,
  `image-sources.md`, `operations.md`.
- `hack/experiments/`, throwaway FreeBSD experiments with captured output; this is where
  uncertainty about jail/vxlan/ocijail behavior gets settled before code. **Not present in
  this checkout**, though the decision log cites results from it (`hack/experiments/esp/`),
  and `make check`'s SPDX scan still looks for `hack/**/*.c`.
- The SwarmKit behavioral spec (`features.md`, cited as **SWK §n**) lives outside the repo
  on the dev host.
- User-facing documentation is a separate repo, `satl-doc`.
- **This checkout is the FreeBSD 15.1 dev host** (`alpha`): rustc/cargo 1.96.1 are
  installed, `satld` is installed with a live socket at `/var/run/satl.sock`, and
  `make check`, `sudo make integration` and `make cluster-test` all run here. The
  cluster testbed is `fbsd{1,2,3}.satl.cc` (replaced 2026-08-19; underlay 10.0.0.0/24).

## Commands

```sh
make check              # SPDX headers, fmt --check, clippy -D warnings, cargo test --workspace
make openapi            # regenerate docs/openapi.yaml + docs/openapi.js (make check only *checks* them)
make build / release    # debug / release build of satl + satld
sudo make install       # binaries + rc.d + sample config (builds into target/install)
make package            # dist/satl-<version>.pkg + dist/CHECKSUM.SHA512
sudo make integration   # root-only #[ignore]-gated tests (target/integration, --test-threads=1)
make cluster-test       # tests/cluster/run.sh, the 3-VM scenario suite
```

`make check` is **the only gate, there is no CI**, and it must be green before any commit.
Root builds go to their own target dir on purpose (a root-owned `target/` breaks every
later unprivileged build); keep it that way.

## Keeping the running daemons current

**Always upgrade `satl`/`satld` from the package, never with `sudo make install`**, on
alpha and on the test VMs alike. `make install` writes files no package manager knows
about, so `pkg info satl` reports nothing and the next `pkg add` has to be forced; the
package is also the only path an operator will ever use, so it is the one worth exercising.

```sh
make package
sudo pkg add -f dist/satl-$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml).pkg
sudo service satld restart
```

Two things this relies on and one to check after:

- **`satld.toml` survives.** `packaging/pkg-plist.in` ships `satld.toml.sample`, never the
  real config; a `.pkgsave` of the old sample is normal.
- **Running containers are re-adopted, not restarted.** Startup reconciliation re-attaches
  live jails (architecture §7.2), so a `satl ps` uptime that resets to seconds means the
  adoption failed, which is a bug, not an upgrade cost. Verify with the jail id and the
  workload's pid, not just with `satl ps`:
  `sudo jls -h jid name` before and after must show the same jid for the same task.
- After a daemon-side change, re-run the verb that changed against the upgraded daemon.
  A CLI built from the branch talking to a stale `satld` answers `page not found`, which
  reads like a missing route rather than a stale daemon.

Narrower runs:

```sh
cargo test -p satl-orchestrator                       # one crate
cargo test -p satl-cluster --test multi_node          # one integration test file
cargo test -p satl-orchestrator update::tests::pause  # one test by path
cargo clippy --workspace --all-targets -- -D warnings
sudo cargo test -p satl-net --test integration --target-dir target/integration \
    -- --ignored --test-threads=1 <name>              # one root test
```

Integration tests mutate global host state (jails, interfaces, ZFS datasets, pf anchors)
and audit for leftovers afterwards, they must stay serialized.

## The eight invariants

Docs and module comments cite these by number ("invariant #7"); **the numbering is stable
and load-bearing, extend, never renumber**.

1. **All cluster state lives in the Raft store.** Manager components are independent
   reconciliation loops that communicate *only* through the store and its watch feed, no
   component calls another, no side-channel mutable state. Workers hold only ephemeral
   executor state (health, for instance, never enters the store), rebuilt from the
   dispatcher's assignment stream.
2. **Every container is a Task of a Service**, even `satl run`. Tasks are immutable and
   one-shot: never moved, never re-executed; "restart" is a replacement task in the slot.
   The task state machine (`NEW`…`ORPHANED`, SwarmKit's sparse values) is the spine, and
   observed state never decreases.
3. **Workers dial managers, never the reverse.** The agent opens the session; the
   dispatcher streams assignments down it.
4. **Raft apply is pure in-memory**, no I/O, no syscalls, no external commands, no awaits
   but the store lock. Nothing blocking runs on the async runtime: `spawn_blocking` for
   sync filesystem work, `tokio::process` for external commands, and no await points while
   holding the store lock.
5. **ZFS is mandatory.** `satld` refuses to start without its root dataset; there is no
   fallback storage driver.
6. **SatL never implements a runtime.** It drives `ocijail` (create/start/kill/delete/state)
   behind the `Runtime` trait, and never manipulates jails out of band.
7. **Secrets never touch a worker's disk.** They arrive over mTLS, are materialized on a
   per-task tmpfs sized to the payloads, and are gone when the jail dies. Error messages
   and logs name the object, never the payload.
8. **The Docker REST API is the only external surface**, and every intentional deviation
   from it gets a numbered entry in `api-compat.md` in the same change. The internal gRPC
   protocol (`satl.internal.v1`) is node-to-node only, with no compatibility promise
   outside this workspace.

## Definition of done

A change is not done until, in the same commit:

- `make check` is green;
- `roadmap.md` reflects any milestone item started, advanced or completed (it is the live
  project status, and its decision log records *measured* findings, not intentions);
- `architecture.md` is updated if the change alters a design it describes, including the
  §2 crate-dependency table when a new internal edge appears, and §15 when a default moves
  (defaults have one home, `satl_core::defaults`);
- `api-compat.md` has an entry for any new Docker-behavior divergence;
- `sudo make integration` has actually been run for networking, runtime or storage changes,
  and `make cluster-test` for cluster behavior. This rule exists because a networking
  change was once committed without it and broke the suite.

## Architecture in brief

**Crate graph** (edges are enumerated in architecture §2, adding one means updating that
table): `satl-core` (domain types, task state machine, IDs, naming, constraints) and
`satl-proto` (generated tonic) depend on nothing. Executor-side crates, `satl-runtime`
(OCI spec + ocijail), `satl-image` (registry client), `satl-storage` (ZFS layers),
`satl-net` (VNET/epair/bridge/pf), `satl-overlay` (VXLAN, DNS, IPsec), depend only on
core (and net, for overlay). `satl-ca` issues identities; `satl-cluster` owns the openraft
FSM, store and watch feed; `satl-sched` and `satl-orchestrator` are the placement and
reconciliation loops; `satl-agent` is the worker-side executor; `satl-dispatcher` holds
**both** sides of the manager↔worker protocol so the wire format cannot drift; `satl-api`
is the axum REST server; `satld` wires everything; `satl-cli` is a REST client only.

**Control plane pipeline** (`satl service create` → running task): REST/control backend
writes the `Service` → orchestrator creates `Task`s (`NEW`) → allocator attaches IPs and
ports (`PENDING`) → scheduler filters and ranks nodes (`ASSIGNED`) → dispatcher streams the
assignment → agent walks `ACCEPTED → PREPARING → READY → STARTING → RUNNING` and reports
back. Restart supervisor, rolling updater, task reaper and constraint enforcer are separate
level-triggered loops: each re-derives its state from the store every pass and keeps none of
its own, which is what makes a leadership change *resume* work instead of replaying it.

**Roles:** every node runs the REST server, the agent and the executor. Managers add the
raft node, the gRPC server (Dispatcher, NodeCA, Raft, Control, Health) and the store.
Leader-only components (orchestrators, allocator, scheduler, dispatcher state, CA signing,
reaper, enforcer) start on leadership gain and stop on loss. Followers forward mutations to
the leader over `Control`; reads are answered from the local applied store.

**Two listeners:** `2377` mTLS, `2378` unauthenticated NodeCA bootstrap (a joining node has
no certificate yet; it pins the CA against the digest in its join token).

## Code conventions

- Edition 2024, rustc ≥ 1.96, `unsafe_code = "deny"` workspace-wide.
- `clippy::pedantic` is on. **Triage, don't blanket-allow**, the four workspace allows in
  `Cargo.toml` each carry their reason; anything else gets fixed or allowed locally with a
  comment.
- Every source file carries its SPDX line first (line 2 after a shebang); `make check`
  enforces it. Fixture files are data, not source, and stay headerless. `.proto` files use
  `//` (a `#` comment is not legal protobuf).
- **No raw `Command::new` in business logic.** Each crate that shells out owns a
  `CommandRunner` trait; wrappers (`Zfs`, `Ifconfig`, `Route`, `PfCtl`, `Ocijail`…) are
  generic over it so argv construction and output parsing are unit-testable without
  privileges. Parsing is pure and tested against fixtures captured from real FreeBSD hosts.
- `thiserror` in libraries, `anyhow` only in binaries. Every external-command failure
  carries the full argv, the exit status and the raw stderr, an operator must see exactly
  what was attempted.
- **Operator-facing text is ASCII-only.** syslogd rewrites bytes in `0x80`–`0x9f`
  irrecoverably, so UTF-8 punctuation arrives mangled in `/var/log/messages`. `M-^`
  sequences in a log line are a bug.
- **Attach spans with `.instrument()`; never hold `span.enter()` across an `.await`.** A
  leaked guard attributes one loop's events to another node's session;
  `crates/satl-dispatcher/tests/span_scoping.rs` pins this.
- Wire payloads are CBOR-encoded `satl-core`/openraft types inside protobuf envelopes, so
  compatibility is governed by serde rules: additive fields with `#[serde(default)]`, never
  repurpose a name. Anything non-additive means `satl.internal.v2`.
- Node addresses live in `tests/cluster/inventory.toml` **only**, never hardcoded in a
  script or a test.

## Diagnosing on a live host

The span chain is the parent chain, so grep by identity rather than by time:
`grep -a 'task_id=1kql' /var/log/messages` returns one task's whole life. **Always
`grep -a`**, a single non-ASCII byte anywhere in the file makes plain `grep` print nothing
at all, which looks exactly like "the daemon logged nothing".

FreeBSD behaviors that have each cost a debugging session:

- **Epairs leak** after an interrupted teardown, and ownership must be recognizable
  afterwards: the ifconfig *group* does not survive a `vnet` move, the *description* does,
  so `<group>:…` descriptions are the ownership marker, and reconciliation classifies them.
- **A dying prison holds the container rootfs.** `jail_remove(2)` moves a prison to `DYING`;
  its `pr_root` keeps the dataset mounted, so `zfs destroy` fails with *cannot unmount*.
  `fstat`, `procstat`, `mount -p` and the process table all show nothing, `jls -d -h name
  dying` is the only observer (and plain `jls -d` lists live jails too, so its output alone
  proves nothing). A VNET prison whose container held an open TCP connection stays `DYING`
  for `2 × net.inet.tcp.msl`; the wait is keyed on the prison disappearing, then deferred to
  the periodic sweep.
- **Jail names are the bare task ID**, not the task name: jail(8) treats `.` as the
  hierarchy separator.
- **Overlay MTU is 1450, measured** (the virtio underlay refuses above 1500, so jumbo is
  impossible). An oversized frame is fragmented, not dropped, the signature is a throughput
  cliff, not a hang.
- A vxlan interface `UP` **without `RUNNING`** is a VTEP the driver refused to initialize;
  `ifconfig` still exits 0 and says `status: active`, and the reason appears only in
  `/var/log/messages`.
- `route -j` installs routes only, it can never install an ARP entry (it never sets
  `RTF_LLDATA`), on any stack.
- `ocijail list -f json` prints `null`, not `[]`, for an empty state db.
- `rctl -r` returning ESRCH means "the filter matched no rule", not "the jail is gone".
- `rctl` enforcement needs `kern.racct.enable=1`; without it `satld` degrades gracefully and
  unit tests never require it.
- Published ports are not reachable from the publishing host via localhost, a pf property,
  recorded as api-compat #35.

## Testing shape

- Unit tests live beside the code (`#[cfg(test)]`), with fixtures under
  `crates/*/tests/fixtures/` captured from real command output and diffed byte-for-byte.
- Store-dependent crates test against `satl-cluster`'s in-process single-node harness (real
  FSM, no network, tempdir persistence); `satl-cluster::testing` mints test CAs and
  identities, and multi-node tests run unprivileged on loopback.
- The CLI is a library so its verbs can be driven in-process against a stub axum daemon on a
  unix socket in a tempdir.
- `#[ignore]`-gated tests are the root/FreeBSD ones (`make integration`). Container images
  for them come from the loopback test registry at `127.0.0.1:5000`, never Docker Hub.
- `tests/cluster/` is POSIX `sh`, `set -e`, every `ssh` in `BatchMode=yes`: a script may
  fail, but must never wait for a password or a host-key prompt.
