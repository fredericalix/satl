# SatL — Cluster-native container engine for FreeBSD

You are building **SatL**, a production-grade, cluster-first container engine for FreeBSD, written in Rust. Think "podman + swarmkit, native to FreeBSD": OCI containers running as jails via the **ocijail** runtime, with built-in orchestration (Raft-backed cluster state, scheduler, desired-state reconciliation, overlay networking, mTLS) inspired by moby/swarmkit.

This is a real production ambition, not a toy. Prioritize correctness, observability, and operational robustness over feature count.

---

## 1. Non-negotiable architectural decisions

These are settled. Do not revisit them; build on them.

1. **Cluster-first architecture.** A single node is a cluster of one. There is no "standalone mode" bolted on later — every container is a task owned by the orchestration layer, even on one node. `satl run` on a fresh install implicitly operates against a self-initialized single-node cluster.
2. **Daemon-based.** A long-running daemon `satld` runs on every node. The CLI `satl` is a thin client speaking to `satld` over a Unix socket locally (`/var/run/satl.sock`) or TCP+mTLS remotely.
3. **Docker-compatible surface.**
   - CLI: `satl` mirrors the `docker` CLI verbs and flags (`run`, `ps`, `pull`, `images`, `exec`, `logs`, `inspect`, `network`, `volume`, `service`, `node`, `stack`...). A `satl compose` subcommand consumes standard `docker-compose.yml` / `compose.yaml` files (Compose Spec).
   - Remote API: implement the **Docker Engine REST API** (target v1.43+ semantics) on `satld`, including the Swarm-mode endpoints (`/services`, `/nodes`, `/tasks`, `/secrets`, `/configs`, `/swarm`). Goal: existing tooling (docker CLI pointed at `DOCKER_HOST`, lazydocker, CI plugins) works against SatL for the common paths. Document every intentional deviation in `docs/api-compat.md`.
4. **Runtime: ocijail.** SatL does not implement its own runtime. It drives `ocijail` (https://github.com/cperciva/ocijail) as an external OCI runtime binary, exactly like podman drives crun/runc: generate the OCI runtime spec (`config.json`), invoke `ocijail create/start/kill/delete/state`. Abstract this behind a `Runtime` trait so alternative runtimes can exist, but ocijail is the only implementation for now.
5. **Storage: ZFS, mandatory.** No fallback drivers. Image layers are ZFS datasets; layer application uses snapshots + clones; container writable layers are clones of the image's top snapshot. `satld` refuses to start if its configured pool/dataset is not ZFS.
6. **Linux images are first-class.** FreeBSD's Linux binary compatibility (linuxulator) must be supported: pulling a `linux/amd64` image and running it inside a jail with `linux.ko` loaded, linprocfs/linsysfs/devfs mounts, and the appropriate jail parameters. Image platform selection: prefer `freebsd/amd64` (or `freebsd/arm64`) variants when the manifest list has them; fall back to `linux/amd64` with linuxulator, with a clear `PLATFORM` column in `satl ps`/`satl images`.
7. **Overlay networking: custom, VXLAN-based.** Multi-host container networking uses `if_vxlan(4)` with VNET jails, epair/bridge on each node, and pf for NAT/port publishing. Control plane distributes IPAM and endpoint/MAC/VTEP mappings through the Raft store (no multicast; unicast VXLAN with a distributed FDB, swarmkit/libnetwork-style).
8. **Raft is embedded.** Cluster state lives in an embedded Raft group among manager nodes (use the `openraft` crate unless you find a disqualifying problem — if so, stop and explain before switching). No external dependency on Consul/etcd. Log + snapshots persisted on ZFS.
9. **Security like swarmkit.** Every node gets an identity certificate from a built-in cluster CA on join (join tokens with the CA hash pinned, swarmkit-style `SWMTKN` equivalent). All node-to-node traffic — Raft, gRPC dispatcher, VXLAN control plane — is mutual TLS. Automatic certificate rotation before expiry. Secrets are encrypted at rest in the Raft store and delivered to containers via an in-memory filesystem (tmpfs mount inside the jail), never written to disk on workers.
10. **Orchestration feature set (all required, phased below):** desired-state services with a reconciliation loop, replicated + global service modes, a scheduler with resource awareness and placement constraints (node labels, engine labels, affinity/anti-affinity), rolling updates with configurable parallelism/delay/failure action + rollback, distributed secrets and configs.

## 2. Target environment

- **FreeBSD 15.1**, amd64. Use current jail(8) capabilities, `rctl(8)` for resource limits (requires `kern.racct.enable=1`), VNET jails, `pf(4)`, `if_vxlan(4)`, `zfs(8)`.
- Development happens **natively on a FreeBSD 15.1 server** (OVHcloud bare metal / VM). Do not set up cross-compilation from Linux/macOS; build and test natively with rustup's `x86_64-unknown-freebsd` host toolchain.
- Integration/cluster testing: **3 FreeBSD 15.1 VMs on OVH Public Cloud** reachable from the dev server. Assume private network connectivity between them (vRack/private network); MTU matters for VXLAN (account for 50-byte overhead, make MTU configurable, document it).
- Shelling out to system tools (`zfs`, `ifconfig`, `pfctl`, `ocijail`) is acceptable and often preferable to FFI for v1 — but isolate every external command behind a module with typed wrappers, structured error parsing, and unit-testable command construction. No raw `Command::new` scattered in business logic.

## 3. Repository layout

Cargo workspace, one repo:

```
satl/
├── Cargo.toml                 # workspace
├── crates/
│   ├── satl-cli/              # `satl` binary — docker-compatible CLI + compose
│   ├── satld/                 # daemon binary — wires everything together
│   ├── satl-api/              # Docker Engine REST API server (axum) + API types
│   ├── satl-core/             # shared domain types: Task, Service, Node, NetworkAttachment... 
│   ├── satl-runtime/          # Runtime trait + ocijail implementation + OCI spec generation
│   ├── satl-image/            # OCI distribution client (pull), manifest/platform resolution, content store
│   ├── satl-storage/          # ZFS layer store: datasets, snapshots, clones, GC
│   ├── satl-net/              # local networking: VNET, epair, bridge, pf rules, IPAM agent side
│   ├── satl-overlay/          # VXLAN overlay: FDB distribution, VTEP programming
│   ├── satl-cluster/          # openraft state machine, membership, join tokens, store (FSM + snapshots)
│   ├── satl-ca/               # embedded CA, cert issuance, rotation, mTLS config (rustls)
│   ├── satl-sched/            # scheduler: filters + ranking, constraints parser
│   ├── satl-orchestrator/     # service reconciliation loops, updaters (rolling), global services
│   └── satl-agent/            # worker-side: dispatcher client, task executor, status reporting
├── proto/                     # internal gRPC (tonic) definitions: dispatcher, control
├── docs/
│   ├── architecture.md
│   ├── api-compat.md          # deviations from Docker Engine API
│   ├── networking.md          # VXLAN design, MTU, pf integration
│   └── operations.md          # install, cluster init/join, cert rotation, backup of Raft state
└── tests/
    ├── integration/           # single-node tests (run on the dev server, root required)
    └── cluster/               # 3-node scenario scripts against the OVH VMs
```

Internal node-to-node protocol is **gRPC over mTLS (tonic + rustls)** — mirroring swarmkit's dispatcher model (workers long-poll/stream task assignments from managers; managers never connect to workers). The Docker REST API is the external surface only.

Key dependency choices (deviate only with written justification in docs/architecture.md): `tokio`, `axum`, `tonic`, `rustls` + `rcgen` (CA), `openraft`, `serde`, `tracing` (+ `tracing-subscriber`, JSON output mode), `clap` (CLI), `oci-spec` crate for OCI types if it compiles cleanly on FreeBSD, otherwise vendor minimal types.

## 4. Delivery phases

Work strictly in this order. Each milestone has a Definition of Done; do not start the next milestone until DoD is met, including tests and docs. Cluster-first means the *architecture* (state store, task model, dispatcher) exists from M1 even when only one node runs.

### M0 — Skeleton & plumbing
Workspace compiles on FreeBSD 15.1; `satld` starts, initializes a single-node Raft cluster, persists state on ZFS, serves `/version` and `/_ping` on the Docker API; `satl version` talks to it over the Unix socket; structured logging with `tracing`; CI script (`make check`: fmt, clippy -D warnings, unit tests).
**DoD:** fresh FreeBSD 15.1 host + `make install` + `satld` running as an rc.d service; `docker -H unix:///var/run/satl.sock version` returns coherent JSON.

### M1 — Single-node container lifecycle (through the orchestrator)
Image pull (registry auth, manifest lists, platform selection incl. linux/amd64), ZFS layer store, OCI spec generation, ocijail lifecycle, `satl run/ps/stop/rm/logs/exec/inspect`, local bridge networking with pf port publishing, volumes (ZFS datasets + host bind mounts), rctl resource limits (`--memory`, `--cpus`). Even `satl run` creates a single-replica anonymous service → task → local scheduling, so the task model is exercised from day one.
**DoD:** `satl run -d -p 8080:80 <freebsd nginx image>` serves traffic; `satl run <linux/amd64 image>` works via linuxulator; kill -9 satld → restart → state fully recovered from Raft log + jail reconciliation (adopt or clean up orphans).

### M2 — Multi-node cluster
`satl swarm init/join/leave` (keep docker verb compat; alias `satl cluster ...`), join tokens, CA issuance on join, mTLS everywhere, dispatcher (managers stream tasks to agents, agents report status), node list/inspect/labels, `satl service create/ls/ps/scale/rm` with replicated mode, scheduler with constraints (`--constraint node.labels.x==y`), spread strategy.
**DoD:** on the 3 OVH VMs: init + 2 joins; `satl service create --replicas 6` spreads tasks; kill a worker VM → tasks rescheduled; kill the leader → new leader elected, API keeps working on remaining managers.

### M3 — Overlay networking
VXLAN overlay networks (`satl network create -d overlay`), cluster IPAM in Raft, FDB/neighbor distribution to nodes, encrypted control plane, service VIP or DNS-RR resolution for service discovery inside overlay networks (pick DNS-RR first — embedded DNS responder per node — document the choice), published ports reachable on every node (ingress: start with per-node pf rdr to local tasks + document routing-mesh gap, full mesh can be M6).
**DoD:** two services on the same overlay network, tasks on different VMs, reach each other by service name; `curl` between containers across nodes works with correct MTU.

### M4 — Desired state, rolling updates, global services
Reconciliation loops comparing desired vs observed state; `satl service update --image ... --update-parallelism --update-delay --update-failure-action`, rollback, health-check-gated updates (Docker HEALTHCHECK semantics inside jails), global services (one task per node), node drain/availability.
**DoD:** rolling update of a 6-replica service across 3 nodes with zero failed requests against a simple HTTP service under continuous load; deliberately broken image triggers automatic rollback.

### M5 — Secrets, configs, compose, hardening
`satl secret/config create` stored encrypted in Raft, delivered via tmpfs into jails; `satl compose up/down` (Compose Spec subset: services, networks, volumes, secrets, deploy.replicas/resources/placement); CA + node cert rotation (`satl ca rotate`, automatic renewal); operational docs; `satl system prune`, layer GC.
**DoD:** deploy a realistic compose stack (web + Redis + worker) across the cluster with a secret; rotate the CA live without downtime; documented backup/restore of manager state.

### M6 — Backlog (do not build now, keep the design compatible)
Full ingress routing mesh, overlay data-plane encryption (IPsec/if_ovpn/wireguard), multi-arch image build (`satl build`), plugin volumes, metrics endpoint (Prometheus format — design the `/metrics` surface early, implement here).

## 5. Engineering standards

- Rust stable, edition 2021+. `#![deny(warnings)]` in CI, `clippy::pedantic` triaged, `rustfmt` enforced.
- Every crate has unit tests; every external command wrapper has tests over command construction and output parsing (fixtures with real captured `zfs`/`ifconfig`/`ocijail` output).
- Integration tests are `#[ignore]`-gated (root + FreeBSD required) and run via `make integration` on the dev server; cluster scenarios are scripted (bash or Rust test harness) in `tests/cluster/` against inventory in a simple TOML (the 3 OVH VM IPs).
- Errors: `thiserror` in libraries, rich context (`anyhow` only in binaries). Every operator-facing failure must say *what* was attempted (which zfs command, which jail id) — this is an SRE tool.
- Observability from day one: `tracing` spans around every lifecycle transition; task/service state transitions logged with structured fields; `satl events` streaming endpoint mirroring Docker's.
- Concurrency: the daemon is a tokio app; Raft FSM apply must stay non-blocking (spawn_blocking for zfs/ocijail invocations); document the locking model in `docs/architecture.md`.
- All state transitions go through the Raft store on managers — no side-channel mutable state. Workers hold only ephemeral executor state, rebuilt from dispatcher assignments.
- Git hygiene: conventional commits, one milestone = one epic branch, PR-sized commits even if working solo.

## 6. How to work

- Start by writing `docs/architecture.md`: component diagram, data model (Service/Task/Node/Network/Secret with state machines for Task states mirroring swarmkit's NEW→PENDING→ASSIGNED→ACCEPTED→PREPARING→READY→STARTING→RUNNING→COMPLETE/FAILED/SHUTDOWN), and the dispatcher flow. Get the data model right before writing feature code.
- When FreeBSD specifics are uncertain (jail parameter names, vxlan sysctls, linuxulator mounts, ocijail flags), read the actual man pages / ocijail source on the dev machine rather than guessing. If genuinely ambiguous, write a tiny throwaway experiment under `hack/experiments/` and record findings in `docs/`.
- Prefer boring, debuggable solutions. This tool will run production workloads; cleverness loses to operability every time.
