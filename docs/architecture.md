# SatL Architecture

Status: **living document.** Written before M0 as the reference for all design
decisions, and updated as milestones land, M0, M1 and M2 are implemented; sections
describing later milestones remain design-only. It must be updated in the same change
as any code that alters a design described here (see CLAUDE.md, definition of done).

Related documents:

- `docs/project-brief.md`, full project brief, non-negotiable decisions, milestones M0–M6.
- `docs/roadmap.md`, live milestone/phase tracking (always current).
- `docs/api-compat.md`, intentional deviations from the Docker Engine API.
- `docs/networking.md`, bridge topology, pf anchor contract, VXLAN plan (M1 done, M3 pending).
- `docs/operations.md`, operator guide (populated from M0 onward).
- SwarmKit behavioral spec, `/home/fralix/src/swarmkit/features.md` (outside this repo):
  a complete behavioral specification of SwarmKit extracted from its source. Referenced
  throughout as **SWK §n**. Where this document says "as SwarmKit", the SWK section is
  the authoritative description of the behavior being adopted.

---

## 1. Overview

SatL is a cluster-first container engine for FreeBSD: OCI containers run as jails via
the external `ocijail` runtime; orchestration (Raft-replicated state, scheduler,
desired-state reconciliation, overlay networking, mTLS) is built in, modeled closely on
SwarmKit. A single node is a cluster of one, there is no standalone mode; every
container is a Task owned by a Service, even `satl run` on a fresh install.

Two binaries:

- **`satld`**, the daemon, one per node. Serves the Docker Engine REST API (external
  surface) and the internal gRPC services (node-to-node surface). Depending on the
  node's role it runs worker components, manager components, or both.
- **`satl`**, thin CLI client speaking the Docker REST API to `satld` over
  `/var/run/satl.sock` (or TCP+mTLS remotely). The CLI never speaks gRPC; everything it
  can do is expressible in the REST API (which keeps `docker`-CLI compatibility honest).

### 1.1 Component diagram

```
                                 ┌─────────────────────────────────────────────┐
   satl CLI / docker CLI         │ satld (manager node)                        │
   lazydocker / CI plugins       │                                             │
        │ Docker REST API        │  ┌─ REST API server (axum) ─────────────┐   │
        ├────────────────────────┼──┤ Docker Engine API v1.43+             │   │
        │ unix sock / TCP+mTLS   │  │ swarm endpoints → control backend    │   │
                                 │  └──────────────┬───────────────────────┘   │
                                 │                 │ (follower → leader        │
                                 │                 ▼  forwarding, gRPC)        │
                                 │  ┌─ LEADER-ONLY components ─────────────┐   │
                                 │  │ orchestrators (replicated, global)   │   │
                                 │  │ allocator (IPAM, VNI, ports)         │   │
                                 │  │ scheduler (filters + ranking)        │   │
                                 │  │ dispatcher (agent sessions)          │   │
                                 │  │ CA server (issuance, rotation)       │   │
                                 │  │ task reaper, constraint enforcer     │   │
                                 │  └───────────────┬──────────────────────┘   │
                                 │                  │ all mutations            │
                                 │                  ▼                          │
                                 │  ┌─ Raft store (openraft FSM) ──────────┐   │
                                 │  │ in-memory object store, watch feed   │   │
                                 │  │ log + snapshots on ZFS, encrypted    │   │
                                 │  └──────────────────────────────────────┘   │
                                 │  ┌─ agent (every node, incl. managers) ─┐   │
                                 │  │ dispatcher client, task executor     │   │
                                 │  └──────────────────────────────────────┘   │
                                 └────────────────────┬────────────────────────┘
                                        gRPC over mTLS │ (worker dials manager,
                                                       │  never the reverse)
                                 ┌────────────────────▼────────────────────────┐
                                 │ satld (worker node)                         │
                                 │  agent: session, assignments, task exec     │
                                 │  executor: satl-runtime (ocijail),          │
                                 │            satl-image, satl-storage (ZFS),  │
                                 │            satl-net (VNET/epair/bridge/pf)  │
                                 │  REST API server (local ops only)           │
                                 └─────────────────────────────────────────────┘
```

### 1.2 What runs where (mirrors SWK §12.1)

**Every node, always:** REST API server (unix socket; TCP if configured), the agent
(managers dispatch work to themselves through their own dispatcher), node-local
executor subsystems (runtime, image store, ZFS store, networking), tracing/metrics.

**Every manager:** the openraft node, internal gRPC server (Dispatcher, NodeCA, Raft,
Control, Health), the store (full in-memory replica).

**Workers (M4):** none of the manager list, no raft, no store, no listener of their
own. A worker runs the agent session to the managers (it dials them, invariant #3),
the executor, the overlay data plane and DNS responder (both fed from the assignment
stream, §11.5), a role watcher, and certificate renewal against a manager's NodeCA.
Its only durable cluster state is its certificate, the local task DB (§7.2) and the
manager list its session last reported (`<state_dir>/managers.json`, SwarmKit
persists its remotes the same way, SWK §14.2); everything else is rebuilt from the
first `COMPLETE` assignment snapshot. Cluster-scoped REST endpoints answer Docker's
worker refusal (§6.5); container reads are served from the local task records.

**Leader only** (started on leadership gain, stopped on loss): orchestrators
(replicated + global), allocator, scheduler, dispatcher state (sessions register
against the leader), CA signing loop, task reaper, constraint enforcer. On first
leadership of a fresh cluster the leader seeds the `default` Cluster object and its own
Node object.

**Bootstrap:** on first start with no prior state and no join configuration, `satld`
self-initializes a single-node cluster (root CA, single-member Raft, both join tokens).
This is a deliberate deviation from Docker (which requires `swarm init`), recorded in
`docs/api-compat.md`. `satl swarm init` still exists for Docker compat and for setting
non-default options (advertise address, address pools); joining an existing cluster
wipes local cluster state only if the local state is "clean" (nothing beyond the
default cluster + own node object, SwarmKit's `IsStateDirty` rule, SWK §12.3).

## 2. Crate map and dependency rules

Cargo workspace. Allowed internal dependency edges are listed exhaustively; adding an
edge requires updating this table in the same PR.

| Crate | Role | May depend on (internal) |
|---|---|---|
| `satl-core` | domain types: Service, Task, Node, Network, Secret, Config, Cluster; task state machine; IDs; naming; constraint expressions; errors | - |
| `satl-proto` | generated tonic code from `proto/` (build.rs) | - |
| `satl-runtime` | `Runtime` trait + ocijail driver + OCI spec generation | `satl-core` |
| `satl-image` | OCI distribution client, manifest/platform resolution, content store | `satl-core` |
| `satl-storage` | ZFS layer store: datasets, snapshots, clones, GC | `satl-core` |
| `satl-net` | node-local networking: VNET, epair, bridge, pf, local IPAM | `satl-core` |
| `satl-overlay` | VXLAN VTEP/FDB programming, embedded DNS responder | `satl-core`, `satl-net` |
| `satl-ca` | root CA, cert issuance/rotation, join tokens, rustls config | `satl-core` |
| `satl-cluster` | openraft FSM + store + watch feed, log/snapshot persistence, membership | `satl-core`, `satl-proto`, `satl-ca` |
| `satl-sched` | scheduler: filter pipeline + ranking | `satl-core`, `satl-cluster` |
| `satl-orchestrator` | reconciliation loops, restart supervisor, rolling updater, task reaper, enforcers | `satl-core`, `satl-cluster`, `satl-sched` |
| `satl-agent` | worker side: task executor (controller), local task DB, in-memory dependency store | `satl-core`, `satl-runtime`, `satl-image`, `satl-storage`, `satl-net`, `satl-overlay` |
| `satl-dispatcher` | **both** sides of the manager↔worker protocol: the `Dispatcher` service and the worker's session client, in one crate so the wire format cannot drift (added in M2) | `satl-core`, `satl-proto`, `satl-ca`, `satl-cluster`, `satl-agent` |
| `satl-api` | Docker REST API server (axum): routes, types, translation to store ops | `satl-core`, `satl-cluster` |
| `satld` | daemon binary: config, wiring, rc.d entrypoint | everything |
| `satl-cli` | `satl` binary: docker-compatible CLI + compose | `satl-core` |

Notes:

- `satl-proto` is an addition to the brief's 14-crate list, justified here: tonic
  generates Rust from `proto/`, and generating once into a dedicated crate avoids N
  crates each running `tonic-build` over the same files.
- `satl-cli` deliberately depends only on `satl-core` (+ an HTTP client): it is a REST
  client, nothing more.
- **`satl-orchestrator` → `satl-sched`, added in M4** for the *node-only* half of the
  placement decision: `PlacementRequirements` (constraints + platform) and
  `accepts_new_tasks` (`Ready`/`Active`). The global orchestrator has to decide which
  nodes a global service should hold a task on, and that set must be exactly the set
  the scheduler will accept, a task created for a node the scheduler then refuses
  sits `PENDING` with an error forever. A second reading of "schedulable" in the
  orchestrator would drift from the filter pipeline, so the predicate is exported from
  the crate that owns placement instead. The edge is one-way and creates no cycle
  (`satl-sched` knows nothing of the orchestrator); the predicates are pure functions
  of a `Node` and a `TaskSpec`, with no store handle and no scheduler state.
- `satl-orchestrator`, `satl-sched` and `satl-api` depend on `satl-cluster` for the
  store handle (reads + proposing mutations). **Revised in M1**: the scheduler was
  originally planned store-free (decisions returned to `satld` for committing), but
  every reconciliation loop already owns its own watch subscription and commits its
  own decisions, so a `Scheduler::spawn(store, shutdown)` shape identical to the
  orchestrator's is simpler and keeps SwarmKit's in-memory-mirror design (SWK §8),
  the mirror is fed from the watch feed, not from store reads on the hot path. Filters
  and ranking stay pure and unit-testable against synthetic nodes.
- Unit tests for store-dependent crates use `satl-cluster`'s single-node in-process
  test harness (a real FSM, no network, temp dir persistence).

## 3. Data model

All cluster state lives in the Raft-replicated store as exactly **seven** object types
(SwarmKit's ten, minus CSI `Volume`, `Extension`, `Resource`, see §14):

| Object | Purpose |
|---|---|
| `Cluster` | Singleton `default`: raft tuning, CA material + join tokens, dispatcher heartbeat period, task defaults, default address pools, blacklisted certificates |
| `Node` | One per member: spec (desired role, availability, labels), description (hostname, platform, resources, engine info), certificate status, observed status, manager status |
| `Service` | Desired state: spec, previous spec (rollback), endpoint (allocated ports/DNS), update status |
| `Task` | One execution unit: spec snapshot, service/slot/node bindings, observed status, desired state, network attachments, endpoint copy |
| `Network` | User/system network: spec, allocated IPAM state + VNI |
| `Secret` | Sensitive blob ≤ 500 KiB, delivered via tmpfs only |
| `Config` | Non-sensitive blob ≤ 1000 KiB |

Design decision, **volumes are not cluster objects in v1**: `satl volume` manages
node-local volumes (ZFS datasets under the volumes dataset, or host bind mounts).
They are recorded in the node-local state, not in Raft; a service using a named volume
gets it created lazily on whatever node its tasks land (Docker swarm behaves the same
with the `local` driver). Cluster-aware volumes (CSI-like) are out of scope (§14).

Common envelope, as SwarmKit (SWK §3.1, §10.4):

- `Meta { version: u64, created_at, updated_at }`. `version` is the Raft log index at
  the mutation that last wrote the object; all `Update*` operations carry the caller's
  copy of `version` and fail with a sequence-conflict error on mismatch (optimistic
  concurrency).
- **IDs**: 25-char base36 from a CSPRNG (~129 bits, top bit of byte 0 set, same
  format as SwarmKit, SWK §3.2). IDs are opaque; prefix match is supported in lookups.
- **Names**: services/networks `^[a-zA-Z0-9](?:[-_]*[A-Za-z0-9]+)*$`, ≤ 63 chars;
  secrets/configs `^[a-zA-Z0-9]+(?:[a-zA-Z0-9-_.]*[a-zA-Z0-9])?$`, ≤ 64 chars.
- **Task names**: `<serviceName>.<slot>.<taskID>` (global tasks use the node ID as the
  slot). **Jail names are the bare task ID**, not the task name: jail(8) treats `.` as
  the hierarchy separator in jail names, so dotted names are not usable. The task name
  appears in `satl ps` and labels; the jail name/id is the task ID.

Spec snapshotting: `Task.spec` is copied from the ServiceSpec at task creation and never
mutated; `Task.spec_version` records the service version it derives from. Rollback
keeps `Service.previous_spec`. (SWK §4.1.)

Spec shapes follow SwarmKit's (SWK §3.4–§3.8) with the FreeBSD adaptations:

- `TaskSpec.resources`: `nano_cpus` and `memory_bytes` limits/reservations map to
  rctl(8) rules (`memoryuse`, `pcpu`); no swap/swappiness fields (Linux-specific).
- `ContainerSpec`: drops Linux/Windows privilege blocks (SELinux/AppArmor/seccomp,
  Windows isolation) for v1; keeps image, command/args, env, dir, user, hostname,
  mounts (`bind`, `volume`, `tmpfs`), stop_signal, `stop_grace_period` (default 10 s),
  healthcheck, hosts, dns_config, labels, pull_options, secrets/configs references.
  A `platform` field records the resolved image platform (`freebsd/amd64`,
  `linux/amd64`, …) so the executor knows whether to build a linuxulator jail.
- `EndpointSpec.mode`: **DNSRR only in v1** (`vip` reserved; see §11.5). Ports carry
  `{protocol tcp|udp, target_port, published_port, publish_mode ingress|host}`.
- Defaults as SwarmKit (SWK §3.9): stop grace 10 s, restart condition `any`, restart
  delay 5 s, update parallelism 1, update monitor 5 s, failure action `pause`, order
  `stop-first`.

## 4. Task model and state machine

Adopted from SwarmKit verbatim (SWK §4), including the sparse numeric values, so the
ordering is explicit and new intermediate states remain possible:

| State | Value | Meaning | Written by |
|---|---|---|---|
| `NEW` | 0 | task object created | orchestrator |
| `PENDING` | 64 | resources allocated, awaiting scheduling | allocator |
| `ASSIGNED` | 192 | node chosen (or preassigned node validated) | scheduler |
| `ACCEPTED` | 256 | agent accepted the task | agent |
| `PREPARING` | 320 | pulling image, cloning layers, creating jail | agent |
| `READY` | 384 | prepared; start would be immediate | agent |
| `STARTING` | 448 | start in progress, **and where a task with a healthcheck waits until its first probe passes** (§8.2) | agent |
| `RUNNING` | 512 | started (and healthy if healthcheck configured) | agent |
| `COMPLETE` | 576 | exited 0 | agent |
| `SHUTDOWN` | 640 | requested shutdown completed | agent |
| `FAILED` | 704 | non-zero exit or execution error | agent |
| `REJECTED` | 768 | never ran: environment problem | agent or constraint enforcer |
| `REMOVE` | 800 | desired-state-only marker: shut down then delete | orchestrator (desired only) |
| `ORPHANED` | 832 | node down too long; frees resources without deleting | manager (dispatcher / node removal) |

Rules (each is an invariant, enforced in `satl-core`'s state machine type):

1. **Monotonic**: observed state never decreases. Given two observations, the greater
   is authoritative (Lamport clock). Transitions that would regress are a bug, reject
   and log at error level (SwarmKit panics; we return a typed error and count it).
2. **Ownership**: the agent owns every transition from `ACCEPTED` upward, with exactly
   two exceptions: `ORPHANED` (manager, node gone) and `REJECTED` written by the
   manager-side constraint enforcer.
3. **Desired state** ∈ {`READY`, `RUNNING`, `COMPLETE`, `SHUTDOWN`, `REMOVE`}, written
   only by manager components, never decreases. Tasks are created with desired
   `RUNNING`; restart/update replacements are created at desired `READY` ("prepare but
   don't start") and promoted later.
4. **Tasks are immutable and one-shot**: never moved to another node, never re-executed.
   "Restart" always means a replacement task in the same slot.
5. `REMOVE` is only ever a desired state: the agent shuts the task down, then the task
   reaper deletes the object, resources are never released while a jail might still
   run.

**Slots** (SWK §4.5): replicated tasks carry slot ∈ 1..N (non-contiguous after
scale-down); global tasks use the node ID. A slot normally holds one live task plus
terminated history; multiple live tasks per slot are legal during `start-first` updates
and partitions, and the updater converges them back to one. Task history per slot is
bounded by the cluster's task-history retention limit (default 5), pruned by the reaper.

## 5. Control plane pipeline

The manager is a set of independent reconciliation loops that communicate **only through
the store and its watch feed** (SWK §5). No component calls another; each watches object
events and writes its own outputs back to the store. Life of `satl service create
--replicas 3`:

1. **REST API / control backend** validates the spec and writes a `Service`.
   (Followers forward the mutation to the leader, §6.5.)
2. **Orchestrator** sees the service event, creates 3 `Task`s: state `NEW`, desired
   `RUNNING`, slots 1–3, spec snapshotted.
3. **Allocator** gives each task its per-network IP attachments (and the service its
   published ports); task state → `PENDING`.
4. **Scheduler** filters + ranks nodes, sets `node_id`, state → `ASSIGNED`.
5. **Dispatcher** streams the assignment (task + referenced secrets/configs) to the
   node's agent session.
6. **Agent** resolves a controller from the executor and walks
   `ACCEPTED → PREPARING → READY → STARTING → RUNNING`, reporting each transition back
   through the dispatcher, which batches status writes to the store.
7. On failure, node loss, or a node that stops satisfying the placement constraints,
   the **restart supervisor** stops the task and creates a replacement in the same
   slot; the **task reaper** prunes history and executes `REMOVE`.
8. `satl service update` engages the **rolling updater** slot by slot, or, for a
   global service, node by node.

Orchestration behavior adopted from SwarmKit with the same semantics and defaults:

- **Dirtiness** (SWK §7.2, `satl-orchestrator::dirty`): a task is replaced iff its spec
  (or endpoint spec) differs from the service's, with the placement-only fast path
  (node still satisfies new constraints ⇒ keep) and the pull-options exemption for
  already-pulled tasks. `force_update` bump dirties everything. The version comparison
  `task.spec_version == service.spec_version` is a fast path for **clean only**: equal
  proves the task was stamped from this spec, unequal proves nothing (a task written
  before the field existed, or a spec that changed and changed back), so the deep
  comparison decides. Service *labels* are part of the spec but not of the task spec,
  so `--label-add` moves `spec_version` and replaces nothing.
- **Rolling updater** (SWK §7.3, `satl-orchestrator::update`): parallelism
  (0 = unlimited), delay between batches, `stop-first`/`start-first`, failure
  monitoring window, max failure ratio, actions `pause`/`continue`/`rollback`. The unit
  it advances one batch at a time is a **slot** for a replicated service and a **node**
  for a global one (SWK §7.8: one slot per node ⇒ node-by-node), so `parallelism` counts
  whichever the service has; every other rule is written once for both. Rollback
  swaps `spec ← previous_spec` (clearing it) and re-runs the updater "in reverse"; a
  failed rollback pauses, rollbacks never roll back. `UpdateStatus`:
  `updating → {completed | paused | rollback_started → {rollback_completed |
  rollback_paused}}`.

  It is **level-triggered and keeps no state of its own**, which is the one structural
  difference from SwarmKit's per-service goroutine: every pass re-derives the batch, the
  failure count and the timers from `Service.update_status` plus the tasks themselves
  (their `spec_version`, desired state, observed state and `status.applied_at`). A
  leadership change therefore *resumes* an update instead of restarting it, with no
  replay step, the property the M2/M3 defect fixes (node status, jail teardown,
  published ports) all converged on. Consequences worth knowing:

  - a **batch is health-gated**: a slot leaves it only once its new task has been
    observed `RUNNING` *and* stayed there for `monitor`. Since a task with a
    healthcheck reaches `RUNNING` only when a probe passes (§8.2), waiting for
    `RUNNING` is waiting for "serving". SwarmKit starts the next slot as soon as the
    task reaches `RUNNING` and monitors in the background; here the window is part of
    the batch, so a broken image is caught before the next slot is disturbed. Only the
    tasks the rollout *created* are watched: a task a rollback returns to has been
    serving since before the rollout began, so it is settled on sight rather than
    holding the batch for a window that would observe nothing;
  - the elapsed time of that window is measured from `status.applied_at` (the manager
    clock, stamped when the manager applied the status), never from the agent's
    `status.timestamp`, which is stamped when a *step begins* and so predates a
    health-gated `RUNNING` by the whole gate;
  - a slot with no live task is **not the updater's**: an empty one belongs to the
    replicated orchestrator and a stopped one to the restart supervisor, both of which
    create tasks from the current spec. The one exception is a slot whose last task is
    finished and whose restart policy alone refuses to replace it (condition `none`, or
    `on-failure` after a clean exit), nobody would ever fill it, so the updater does
    (SwarmKit's `UpdatableTasksInSlot` fallback, minus the attempts-exhausted case:
    the *count* is now derivable from the store, but whether the supervisor has a
    replacement for that slot already queued behind its restart delay is not, that
    queue is in memory, so the updater still leaves those slots alone rather than
    risk a second task in a slot that is about to be refilled);
  - the failure ratio's denominator is derived (the slots this update is responsible
    for) rather than remembered from the update's first pass;
  - **a pause is not cleared by the updater**: it enters `paused`/`rollback_paused`
    and then does nothing at all. Clearing the state belongs to the control surface,
    as it does in SwarmKit (`docs/api-compat.md`); a heuristic in the loop ("resume if
    no task carries the current spec") would resume a paused update the moment the
    reaper pruned its history.
- **Restart supervisor** (SWK §7.4): condition `none|on-failure|any`, delay (default
  5 s, forced 0 on drain), max attempts counted over the optional `Restart.Window`
  (which turns the budget from a lifetime quota into a rate, and discounts restarts
  recorded after the failure being judged). Its replacement is created at the
  predecessor's desired state rather than at `READY`-then-promote: all of its triggers
  are cases where there is nothing to wait for (the predecessor is already terminal, or
  its node is unreachable or disqualified).

  It has **three triggers**, sharing one budget and one replacement transaction: a task
  that terminated (§7.4), a node that can no longer run anything (§7.8: gone, `DOWN`,
  draining) and a node that can no longer run *this* task (§7.6, below). The two
  node-driven ones set `DesiredState = SHUTDOWN` **unconditionally**, as SWK §7.4
  step 2 does: the node will not be running the task, which is a fact and not a policy
  question, so a `restart-condition = none` service loses its tasks when its node is
  drained and simply gains no replacements. The `terminated` trigger deliberately does
  *not*, the rolling updater recognises "a slot no restart policy will refill" by
  exactly that shape (a terminal task still at desired `RUNNING`), and the task has
  already stopped anyway.

  **The `max_attempts` history is derived from the store**, not remembered: per replica
  and spec version, the slot's tasks sorted by creation time, all but the first counted
  as past restarts, with their `meta.created_at` as the restart timestamps. That is
  SwarmKit's `taskinit` reconstruction (SWK §7.9) applied on *every* pass rather than
  once at leadership gain, which removes the replay step altogether: a new leader
  computes the same numbers from the same store, so a node failing right after an
  election no longer hands the slot a fresh budget. It is sound because the reaper prunes
  per-replica history to `max_attempts + 1`, exactly the count at which the budget is
  spent, so pruning can never give it back.
- **Task reaper** (SWK §7.5): 250 ms batching; executes `REMOVE`; prunes slot history.
  History is keyed by SwarmKit's `SlotTuple`, slot, plus the node for a global task,
  so one node of a global service cannot prune another's.
- **Constraint enforcer** (SWK §7.6): on a node update that moves its **labels or its
  availability** (never on a heartbeat, which rewrites the node object every few
  seconds), re-evaluates the constraints of every task on it, against the service's
  *current* placement, since a placement-only update deliberately keeps matching tasks
  and their snapshot goes stale by design. Only an `ACTIVE` node is judged: `DRAIN`
  already evicts, `PAUSE` means "do not touch". Eviction is the restart supervisor's
  third trigger (above) rather than SwarmKit's observed `REJECTED`: the task is stopped
  and replaced in one transaction, so it never looks like a task *failure* and cannot
  spend a rolling update's failure budget. **Resource reservations are not re-checked**
  (SwarmKit also evicts when running totals stop fitting the node's capacity): that
  total lives in the scheduler's in-memory mirror, and a second resource accountant is
  not worth the drift.
- **Global orchestrator** (SWK §7.8, `satl-orchestrator::global`): one task per
  (service × eligible node), created with a preassigned `node_id` for the scheduler to
  validate (SWK §8.6), slot 0 and the node ID in place of the slot in the task name
  (SWK §4.5). Per node, one of three verdicts: `Run` (`Ready`, `Active`, and matching
  the service's constraints and platforms, the scheduler's own predicate, so this loop
  never creates a task the scheduler would refuse), `Hold` (`PAUSE`, or a node that is
  not reachable yet: no new task, nothing taken away) and `Reject` (draining, `DOWN`,
  gone, or no longer matching: its tasks are shut down). A rejected node's task is
  **not** replaced elsewhere, a global task's node is its identity, which is why the
  restart supervisor's node-driven triggers skip global tasks and its `terminated`
  trigger pins the replacement to the same node. Occupancy is SwarmKit's test, "does
  the node hold a task the cluster still wants there" (`desired_state <= RUNNING`), so
  a crashed task stays the supervisor's while a task this loop stopped leaves the node
  free to be filled again when it returns. Rolling updates apply: the updater's *unit*
  is a node for a global service, so `parallelism` counts nodes and a rollout proceeds
  node by node.
- **Jobs are out of scope for v1** (§14).

On leader change every loop starts from a full store pass (SWK §7.9), which is its
periodic self-healing pass fired immediately: tasks of deleted services are marked for
removal, an in-flight rolling update is *resumed* from `update_status` and the tasks
themselves, and restart budgets are re-derived from task history. One piece of
SwarmKit's `taskinit` is deliberately absent: an interrupted delayed start is not
resumed with the *remaining* delay, it takes a fresh one. A replacement that arrives
one delay late is a pacing difference, not a correctness one, and the delay queue holds
nothing a fresh pass cannot re-derive.

## 6. Cluster state store and Raft

`satl-cluster` embeds **openraft** (per the brief; if a disqualifying problem appears,
stop and write it up before switching). Managers form the Raft group; the FSM is the
object store.

### 6.1 Store engine

- In-memory typed maps per object type (`HashMap<Id, Arc<T>>` plus secondary indices:
  name, service→tasks, node→tasks, slot, desired-state). Objects are immutable once
  inserted (`Arc` swap on update), readers clone cheap handles, never see torn state.
- A store **write** is a `StoreAction { create | update | remove, object }` list,
  one Raft proposal = one atomic transaction of ≤ 200 actions / ≤ 1.5 MiB
  (SwarmKit's batch limits, SWK §10.5). Larger work (e.g. orchestrator creating 500
  tasks) uses the batch helper that splits into successive transactions, each
  individually atomic.
- **Apply is pure**: the FSM apply function only mutates the in-memory maps and pushes
  events, no I/O, no syscalls, no external commands, no awaits on anything but the
  store lock. This is CLAUDE.md invariant #4; it is what keeps Raft apply non-blocking.
- After each applied transaction, its events (`Created/Updated(old,new)/Removed` per
  object + a final `Commit(version)` marker) are published on a broadcast watch feed.
  Every control-plane loop and the REST `/events` stream consume this feed. Watchers
  that fall behind get a bounded queue and an explicit "lagged" signal (they must
  re-sync from a snapshot read), no unbounded buffering, no blocking publishers.

### 6.2 Locking model (normative)

- One `RwLock` protects the store maps. Writers = the Raft apply path only. All apply
  work is pure in-memory (§6.1), so the write lock is held for microseconds.
- Reads take the read lock, clone the `Arc`s they need, release. **No await points
  while holding the lock, read or write** (enforced by keeping the lock non-async and
  scoping guards to sync blocks).
- External commands (`zfs`, `ifconfig`, `pfctl`, `ocijail`) never run on the manager
  control plane at all, they are executor-side (agent). Agent code runs them via
  `tokio::process` (async) or `spawn_blocking` for anything synchronous; never inside
  a store lock, never inside FSM apply.
- Proposals: leader-side components call `store.propose(actions)` which submits to
  openraft and resolves when applied. There is **no proposal timeout** (SwarmKit
  learned this: a timeout cannot retract an appended entry and desyncs store vs log,
  SWK §11.6); the only failure is losing leadership, which cancels all pending
  proposals with a typed error. Order on leadership loss: signal followership (stop
  leader components) **then** cancel waits (SWK §23.12).

### 6.3 Persistence (ZFS)

- Raft log + vote + snapshots live under the node state dir on a dedicated ZFS dataset
  (default `zroot/satl/raft`, mounted at `/var/db/satl/raft`).
- Log storage implements openraft's log-storage trait. Backend decision at M0 between
  (a) a small purpose-built append-only segment log with fsync batching, and (b) an
  embedded pure-Rust KV (e.g. `redb`). Requirements either way: atomic vote writes,
  crash-safe append, truncate-from (conflict) and purge-to (compaction), and **at-rest
  encryption of entry payloads** (§12.4).
- Snapshots: full serialized store (all seven tables) + membership; written to a temp
  file and renamed; triggered every 10 000 applied entries (cluster-tunable); log
  compacted keeping the last 500 entries for slow followers (SwarmKit defaults).
- Snapshot install (follower catching up) replaces the store wholesale without
  re-stamping versions.

### 6.4 Consistency model

- **Mutations**: leader-only, linearizable through Raft.
- **Reads**: served from the local applied store, possibly stale on followers, exactly
  like SwarmKit manager reads. This is fine for the Docker API surface (list/inspect)
  and for control loops (leader-local, and every decision is revalidated through
  optimistic concurrency at commit time).
- Optimistic concurrency (§3) turns any stale-read-based mutation into a clean
  sequence-conflict retry.

### 6.5 Follower → leader forwarding

Non-leader managers accept REST mutations and forward them to the leader over the
internal `Control` gRPC service (one hop; the leader re-validates). Reads are answered
locally. Workers do not serve swarm-scoped REST endpoints, they return the Docker
"this node is not a swarm manager" error (api-compat: same behavior as Docker).
Identity forwarding: forwarded requests carry the original caller's identity in
metadata; the leader authorizes the forwarding manager's cert *and* logs the original
caller (SWK §11.7's model, simplified: the REST surface has no per-user authz in v1,
possession of the socket or a valid client cert is authorization).

### 6.6 Membership

- Join (§12.2): the joiner gets a certificate first (CA flow), then, managers only,
  calls `Control.JoinRaft`; the leader health-checks the joiner back before proposing
  the membership change (SWK §11.3). Raft IDs are random u64, never reused; removed IDs
  are blacklisted in snapshots; a node told "removed" wipes its raft state.
- Demotion is two-phase, **raft first** (SWK §12.3): remove from consensus (refusing if
  quorum would break), only then flip the role so cert renewal issues a worker cert.
  Leader self-demotion transfers leadership first.
- Quorum safety on removal: refuse to remove a member if the remaining reachable set
  would lose quorum (SWK §11.5).

## 7. Internal protocols (gRPC over mTLS)

All node-to-node traffic is tonic + rustls, one connection per peer, mTLS with role
verification per service (§12). `proto/` defines package `satl.internal.v1`:

| Service | Role required | RPCs (summary) |
|---|---|---|
| `Dispatcher` | worker or manager | `Session` (server-stream), `Heartbeat`, `UpdateTaskStatus`, `Assignments` (server-stream) |
| `NodeCA` | none (bootstrap) / any | `GetRootCACertificate`, `IssueNodeCertificate` (token-authenticated), `NodeCertificateStatus` |
| `Raft` | manager | openraft network: `AppendEntries`, `Vote`, `InstallSnapshot` (chunked) |
| `Control` | manager | leader-forwarded store mutations, `JoinRaft`/`LeaveRaft`, cluster info for REST backend |
| `Health` | any | standard gRPC health, services `raft`, `control` |

The Docker REST API is the only external surface; gRPC is never exposed to clients.

**Implemented in M2.** The M1 stand-in (a local `satld/src/dispatcher.rs` reading the
store directly) is gone; both sides of the real protocol live in **`satl-dispatcher`**,
deliberately in one crate so the manager's service and the worker's session client
cannot drift apart on the wire format. Leader-only components are started and stopped by
a supervisor watching raft metrics (`satld/src/leadership.rs`).

Four M2 decisions worth recording here, because they diverge from the design above or
from SwarmKit:

1. **Two listeners, not one.** `2377` carries the mTLS server; `2378` carries the
   *unauthenticated* NodeCA bootstrap. §7's table implies one server, but
   `rustls::ServerConfig` takes a mandatory client-certificate verifier, so a shared
   server cannot make a per-service exception, and a node joining for the first time
   has no certificate to present. A cleaner fix (an allow-unauthenticated policy inside
   the server builder) is deferred; `satl swarm join host:2377` derives the second port
   itself.
2. **Join is learner-first, promotion asynchronous.** openraft commits configuration
   changes through joint consensus, so the joint entry needs a majority of the *new*
   configuration, including the joiner, which cannot start its raft node until
   `JoinRaft` has told it its id. Committing the promotion inside the RPC would
   deadlock. So the leader admits a learner (safe to commit alone; learners count for no
   quorum) and a background task promotes it once it acknowledges its first entry.
   SwarmKit does it in one step because etcd/raft commits conf changes against the *old*
   configuration. A re-join heals a promotion that never completed.
3. **The membership address is self-healing.** The membership records what peers dial,
   and it is written once at `initialize`, which on a fresh node happens before any
   operator has configured an advertise address (§1.2 makes first boot form a cluster on
   its own). A leader whose recorded address differs from its configured one corrects it
   at startup. Without that, followers redirect agents to an address that does not
   resolve while the cluster itself looks healthy.
4. **The gRPC health service belongs to `satl-cluster`**, not to the dispatcher crate:
   `Control.JoinRaft` health-checks a joiner before admitting it (SWK §11.3), so health
   must exist before any other service registers, and two `grpc.health.v1`
   registrations would collide on the route.

The two M2 gaps recorded here are closed (M4): certificate renewal applies **live**
(`LiveIdentity`, §12.3), and a **worker-role join is accepted**, the daemon has a
storeless worker bring-up (§1.2), the REST surface answers Docker's worker refusal on
cluster-scoped endpoints and serves container reads from the local task DB, and
promotion/demotion apply live (decision 7 below).

One more, found in M3 and belonging to the same family as decision 3:

5. **Node liveness is published level-triggered.** `Liveness` (in-memory, per manager) is
   the authority on who holds a session; `Node.status.state` is only its published form.
   The registration / TTL-expiry / leadership-change writes are edges, and an edge that
   is lost, or overwritten by another edge racing it, is never re-sent, because
   heartbeats only refresh the in-memory TTL. So the leader's sweep **re-asserts the
   whole projection onto the node objects on every pass** (`heal_node_states`), writing
   only where the two disagree. The bug that forced this: a manager's own agent reaches
   the co-located unix socket in microseconds, so on a restart of an initialised cluster
   it registered before the sweep loop's leadership-gain pass had finished walking the
   store, and that pass overwrote its fresh `READY` with `UNKNOWN`, permanently. The
   leader showed `Unknown` on every node while its own agent streamed assignments, and
   the scheduler skipped it (`satl-sched` filters on `READY`), so nothing could be placed
   on it. Ordering fixes were rejected on principle: they narrow such a window, and the
   next timing change reopens it. Reconciling a level cannot be reopened by timing.
   Nodes a manager does *not* track are left alone, it has no observation to publish
   about them beyond the one-shot leadership-change pass.

And one more, found in M4, closing the hole decision 5 left for nodes nobody tracked:

6. **Leadership gain seeds a registration expectation for every store node.** A killed
   *follower* was always handled, the leader held its session, the TTL expired, `DOWN`,
   eviction. But the node that dies *with* the leadership left the new leader's
   dispatcher holding nothing: no session, no TTL, only the one-shot `UNKNOWN` write,
   which nothing ever moved again, so its tasks kept their desired state and a
   three-node cluster that lost its leader ran the dead node's replicas nowhere,
   indefinitely. Now the new leader walks the store at leadership gain and seeds an
   *expectation* (`Liveness::expect`) for every non-`DOWN`, non-drained node it does not
   track: `UNKNOWN`, the usual doubled grace as its deadline, and **no session**, so no
   RPC can validate against it. A live agent replaces its expectation by registering
   (measured on the VMs: 2.9–7.5 s after `raft leadership gained`, against a 30 s grace
   = 2 × the 15 s session TTL, derived, not a new constant); a dead node expires
   through the ordinary sweep into `DOWN` and the orchestrator's `InvalidNode` eviction.
   One eviction path, not two. This is SWK §13.2's own shape: the swarmkit dispatcher
   marks every non-`DOWN` **store** node `UNKNOWN` with the doubled TTL on leadership
   change, the node set comes from the store, not from the sessions held. `DOWN` nodes
   are skipped so elections cannot resurrect them (their orphaning clock survives only a
   leader's own tenure); drained nodes are skipped because there is nothing a `DOWN`
   would evict and a daemon deliberately stopped for maintenance should not flap. The
   double failure, the new leader dying mid-grace, restarts the clock on the next
   leader (its map starts empty, seeding is idempotent against tracked nodes), so the
   deadline never accumulates.

And the decision that closed the worker gap:

7. **A role change travels as (session push → certificate renewal → runtime
   rebuild), never as a restart.** The store's `Node.spec.role` is the intent; the
   session stream already pushes a node its own object on every change (§7.1), and
   the CA already signs whatever role the store records on a renewal (§12.3). So
   each runtime spawns a *role watcher*: when the pushed role stops matching the
   role the runtime was built for, it renews against a manager's NodeCA over the
   existing mTLS channel (following the leader redirect), swaps the identity live,
   and asks the daemon's cluster supervisor, the same machinery `swarm join` uses,
   to rebuild the runtime in place. Promotion rebuilds as a manager joining raft
   learner-first through the existing membership machinery (§6.6, trying each known
   manager); demotion rebuilds as a worker after wiping the raft directory (the log
   belongs to a membership the node already left; the clean-join rule would refuse
   it on a later promotion anyway). The node-local runtime, jails, worker, task DB,
   overlay interfaces, survives the rebuild untouched, so running tasks are not
   disturbed; the agent re-registers and the snapshot re-applies idempotently. Two
   deliberate asymmetries: the demoted node's own store copy never sees the role
   flip (it was removed from raft *before* the flip, §6.6 two-phase), which is why
   the channel is the session and not the store; and a promotion that no manager
   can admit falls back to the worker runtime and retries from the next session
   event, never to self-initialization, which would mint a second cluster under
   the same certificate (the same rule guards a daemon restarted mid-promotion: a
   manager certificate over an empty raft directory resumes the join, it never
   inits).

### 7.1 Dispatcher protocol (mirrors SWK §13)

- **Session**: agent opens `Session{node_description, session_id?}`; unknown session ⇒
  registration (node object must already exist, it is created at certificate issuance);
  a fresh random session ID is minted (never persisted, never reused). The stream
  pushes, initially and on change: session ID, the node's own object, the manager list,
  and the current root CA bundle (rotation distribution).
- **Heartbeat**: period 5 s ± 500 ms jitter, dictated by the server in each response;
  TTL = 3× period. Expiry ⇒ node `DOWN`, session invalidated; after **24 h** down,
  tasks in `[ASSIGNED, RUNNING]` are set `ORPHANED`. On leadership change all non-down
  nodes get a doubled grace period (agents must find the new leader), including the
  nodes the new leader holds no session for, which are seeded from the store as
  sessionless expectations (§7 decision 6); one that never re-registers goes `DOWN`
  through the same TTL sweep and has its tasks evicted.
- **Assignments**: first message is a `COMPLETE` snapshot (all tasks ≥ `ASSIGNED` for
  this node + every secret/config they reference); then `INCREMENTAL` diffs batched
  over a 100 ms quiescence window (max 100 changes/message). Messages carry
  `applies_to`/`results_in` sequence markers; on mismatch the agent drops the stream
  and re-syncs from a fresh snapshot. Secrets/configs are reference-counted: shipped
  with their first dependent task, removed with the last.
- **UpdateTaskStatus**: batched; a status for a task assigned to another node is a
  permission error (anti-spoofing); the store write refuses backward transitions and
  stamps `applied_by`/`applied_at` (manager clock, used for restart windows to avoid
  agent clock skew).

### 7.2 Worker/agent behavior (mirrors SWK §14)

- One session at a time; local-socket dispatcher preferred when the node is itself a
  manager. Reconnect backoff `min(100ms + 2×backoff, 8s)`, jittered; reset on
  registration. On (re-)registration the agent **re-reports every persisted task
  status**, the manager may have missed updates.
- Assignment application order: **secrets, configs, tasks** (dependencies first). Full
  snapshots reset secrets/configs and delete local tasks absent from the set.
- **Local persistence**: `/var/db/satl/worker/tasks/<taskID>`, one file per task
  (task snapshot + last reported status), CBOR, atomic write-rename. On restart the
  agent rebuilds executor state from these files: tasks still assigned resume from
  their persisted status (a running jail is *re-attached*, not restarted, the
  controller re-syncs against `ocijail state`); tasks no longer assigned are removed.
  The local status is canonical when the manager's copy lags.
- Desired-state updates never move backwards; an in-flight controller operation is
  cancelled when a task update arrives.
- **"Local is canonical" applies to the *observed* status, never to the desired
  state.** The two are owned by opposite ends: the agent reports what is, the manager
  decides what should be (§4 rules 2 and 3). So when the agent resumes a task from
  disk, the desired state it resumes at is only *what it last heard*, the manager may
  well have moved the task on while this node was down. The agent's bookkeeping of
  "what have I already acted on" must therefore be seeded from the **persisted**
  definition and then reconciled against the assignment, not seeded from the
  assignment itself. Getting that backwards makes the agent believe it has already
  applied a desired state it never saw, and it silently stops driving the task: a
  container whose task was told to stop keeps running, and the service never converges
  (fixed in M2, the symptom was a jail outliving its task and a service stuck at
  7/6).

## 8. Runtime layer (executor)

Two layers, both in the worker path:

### 8.1 `Runtime` trait (`satl-runtime`)

Thin, typed wrapper over an OCI runtime binary, the only implementation is ocijail
(verified: `ocijail 0.6.0` provides `create`, `start`, `delete`, `exec`, `kill`,
`state`, `list`, `features`):

```rust
#[async_trait]
trait Runtime {
    async fn create(&self, id: &JailId, bundle: &Path) -> Result<()>;
    async fn start(&self, id: &JailId) -> Result<()>;
    async fn kill(&self, id: &JailId, signal: Signal, all: bool) -> Result<()>;
    async fn delete(&self, id: &JailId, force: bool) -> Result<()>;
    async fn state(&self, id: &JailId) -> Result<RuntimeState>;   // OCI state JSON
    async fn exec(&self, id: &JailId, process: ExecProcess) -> Result<ExecHandle>;
    async fn features(&self) -> Result<Features>;
}
```

SatL never implements a runtime (invariant #6): `satl-runtime` generates the OCI bundle
(`config.json` + rootfs path from `satl-storage`) and drives the binary. All ocijail
invocations follow the external-command-wrapper rules (typed module, fixture-tested
parsing, errors carrying the full command line + raw output).

OCI spec generation covers: process (args/env/cwd/user), root (ZFS clone mountpoint),
mounts (volumes, binds, tmpfs, including the secrets tmpfs), hostname, and the
FreeBSD/jail platform section (VNET config, jail parameters). For **linuxulator**
tasks (resolved platform `linux/*`): require `linux.ko` (fail task creation with a
clear `REJECTED` error if missing), add linprocfs/linsysfs/devfs mounts and the
appropriate emulation jail parameters. Images that require cgroups or systemd fail
fast with an explanatory error, never half-start. Exact jail parameter names and
linuxulator mount sets will be validated against jail(8)/ocijail source during M1,
with findings recorded in `docs/` (`hack/experiments/` for probes).

### 8.2 Controller (task executor, `satl-agent`)

Per-task driver implementing SwarmKit's controller contract (SWK §15.2): `prepare`
(pull image → clone layers → create networks/volumes → generate bundle → `runtime
create`), `start` (`runtime start`, then health gate: with a healthcheck configured,
`RUNNING` is reported only when the first probe passes), `wait` (block on exit),
`shutdown` (stop_signal, grace period 10 s default, then SIGKILL), `terminate`,
`remove` (delete jail, epairs, clones), plus `logs`.

The agent's task manager loops SwarmKit's **one-step state machine** (`exec.Do`,
SWK §15.4), reimplemented as `do_step(task, controller) -> new status`:

1. Shutdown wins: desired ≥ `SHUTDOWN` and not yet terminal ⇒ `shutdown()` → `SHUTDOWN`.
2. Observed past desired ⇒ no-op.
3. In-flight states finish what they started (`PREPARING`→prepare→`READY`,
   `STARTING`→start→`RUNNING`, `RUNNING`→wait→`COMPLETE`/`FAILED`) even past desired.
4. Pause gate: observed ≥ desired ⇒ wait for promotion.
5. Otherwise advance bookkeeping (`ASSIGNED`→`ACCEPTED`→`PREPARING`, `READY`→`STARTING`).

Failure classification: cancellations and explicitly-temporary errors retry (fixed 1 s
backoff initially, as SwarmKit); anything else is terminal, `REJECTED` before
`STARTING`, `FAILED` from `STARTING` on. Exit code and jail state are harvested into
the reported status.

`prepare` is idempotent and re-entrant (image pulls resume; an already-created jail
returns "already prepared"), required for agent-restart re-attachment (§7.2).

**`remove` cannot always finish, and does not pretend to.** A container rootfs
cannot be unmounted while its prison is still `DYING`, and a prison that had an
open TCP connection when it was removed stays dying for 2 x MSL, a minute by
default, measured (`docs/jail-teardown.md`). `destroy_rootfs` therefore waits on
the prison itself (`jls`, via `satl_runtime::Jails`) rather than on a retry
count, but only for 30 s: a removal is applied **inline on the assignment
stream** (`apply_diff` awaits `remove_task`), so waiting out a kernel timer here
would stall every other assignment for this node, including the network teardown
ordered after the task in the same batch. When the budget runs out the dataset is
**deferred**, not abandoned: `satld::reconcile::spawn_dataset_sweep` re-checks
the datasets on disk against the tasks the store and the worker claim every 20 s
and destroys what neither claims. Level-triggered, off the assignment path, and
two consecutive passes must agree before it destroys anything, so a momentarily
incomplete claim set cannot cost a live task its rootfs, and a node converges
without a restart.

**Healthchecks** (M4, `satl_agent::health`): Docker HEALTHCHECK semantics, with the
probe running as `ocijail exec --detach` inside the task's jail with the container's own
env, cwd and user (recovered from the bundle's `config.json`, so a probe survives an
agent restart that adopts a jail it never planned). The module splits in two on purpose:
`HealthTracker` is a pure fold of probe outcomes, Docker's defaults, the `retries`
streak, the `start_period` rule, the bounded log, and `Prober` is the loop that
schedules probes and publishes into the node-local `HealthRegistry` the executor owns.
Health never enters the store (invariant #1); `satl ps`/`satl inspect` read it from that
registry, which is why `State.Health` is only reported by the node running the task
(`docs/api-compat.md` #87-#91).

Two behaviours matter beyond the probe itself, and both are SwarmKit's (SWK §15.2):

- **Health gates `RUNNING`.** `start` releases the container and then blocks until the
  first probe passes, so a task with a healthcheck stays `STARTING` until it is healthy.
  Nothing that keys on observed `RUNNING`, the DNS responder (§11.5), the rolling
  updater's promotion, can therefore see a container that has not passed a probe, and
  neither of them needed a change for that. If the task goes `unhealthy` first, or the
  container dies before any probe passes, `start` fails and the task is `FAILED`.
- **An unhealthy running task fails.** `wait` watches the exit *and* the health verdict;
  `retries` consecutive failures outside `start_period` stop the container and report
  `FAILED` through the ordinary status path, so the existing restart supervisor replaces
  it. There is no second replacement path.

A probe that outlives its `timeout` is **killed** (`kill(2)` on the pid from
`--pid-file`, `satl_runtime::procs`), never dropped: a probe left inside the jail is a
process the delete's `jail_remove(2)` has to kill, and if it held a TCP connection the
prison then stays `DYING`, with the rootfs busy, for 2 x MSL
(`docs/jail-teardown.md`). `Prober::stop` kills the in-flight probe before shutdown and
before removal for the same reason.

### 8.3 Node description

`describe()` builds the node description: hostname, platform (`freebsd`/amd64|arm64),
resources (ncpu×1e9 NanoCPUs, physmem), engine version, whether linuxulator is
available (drives platform filtering), whether racct is enabled, engine labels from
config, and **`data_addr`**, this node's underlay address, i.e. the VXLAN tunnel
endpoint peers must send to (§11.2). Refreshed every 20 s and pushed through session
re-registration on change.

Linux emulation is **re-probed every 10 s on the node** (`reconcile::spawn_linux_probe`,
one `sysctl -n compat.linux.osrelease` per tick into the shared
`satl_agent::LinuxEmulation` handle that the executor's prepare gate, its platform
policy and this describer all read live), so a `kldload linux` after startup takes
effect without a daemon restart and reaches the cluster through the existing 20 s
description refresh, within about 30 s. racct remains probed once at startup:
`kern.racct.enable` is a boot tunable and cannot change under a running daemon.

`data_addr` sits on the **description** and not on `NodeStatus` on purpose: the
description is what a node *asserts about itself*, `NodeStatus` is what a manager
*observed*, and blurring the two is exactly what produced the bug this field fixes.
It is derived from the node's own `advertise_addr` with the port stripped (a VXLAN
endpoint is an address; the UDP port belongs to the overlay), it is re-published on
every bring-up because `swarm join` can change the advertise address, and it is
`Option`/`#[serde(default)]` so state written before it existed still loads.
`SessionRequest.description` is the only agent→manager self-report channel, so this
needed no proto change.

**rctl/racct**: when `kern.racct.enable=0`, `satld` logs a prominent startup warning
and *accepts but does not enforce* `--memory`/`--cpus` (recorded in the task status
message), degrade, don't crash. **The old note here ("the dev server runs with racct
off") is out of date**: `kern.racct.enable=1` is now in `/boot/loader.conf` and active
on the dev host *and* the OVH VMs (measured: `sysctl kern.racct.enable` → 1), so
enforcement is exercised everywhere. The degradation path still has to work, it is
what any operator on a stock GENERIC host gets.

## 9. Image pipeline (`satl-image`)

- **Distribution client**: OCI Distribution spec (pull only in v1): token auth
  (Bearer/Basic), manifest lists / OCI image indexes, `application/vnd.oci.*` and
  `application/vnd.docker.*` media types. Layers stream to a content-addressed blob
  store (`/var/db/satl/images/blobs/sha256/<digest>`) with digest verification.
- **Platform selection** (invariant / brief §1.6): prefer `freebsd/<local arch>` from
  the index; else fall back to `linux/amd64` (linuxulator) when available on the node;
  else fail with a clear error listing available platforms. `satl images` / `satl ps`
  expose a `PLATFORM` column. `--platform` overrides.
- **Metadata store**: image manifests/configs and the layer→dataset mapping live in a
  small node-local metadata file set under `/var/db/satl/images/` (CBOR, atomic
  writes), keyed by digest; repository:tag references map to digests.
- Registry credentials come per-request (`X-Registry-Auth`, Docker semantics) or from
  the task's `pull_options`; nothing is persisted by the daemon.
- Layer *unpacking* is `satl-storage`'s job (§10); `satl-image` owns bytes and
  metadata, `satl-storage` owns datasets. GC (M5 `satl system prune`): delete blobs
  and datasets unreferenced by images/containers, leaf-first.
- **Removing one record** (M9, `DELETE /images/{name}`): a record *is* a reference,
  so removal is `ImageStore::remove`, which writes `repositories.json` before
  anything is deleted, so a store read is never left pointing at a file that has
  gone, followed by the same sweep the prune runs. What makes the record
  unreachable is what makes its content collectable; the order is not negotiable.

## 10. Storage: ZFS layer store (`satl-storage`)

ZFS is mandatory (invariant #5): `satld` refuses to start if the configured root
dataset is absent or the path is not ZFS, with an operator-actionable error.

Dataset layout (root configurable, default `zroot/satl`):

```
zroot/satl                      mountpoint=/var/db/satl
├── raft                        raft log + snapshots (managers)
├── images                      blob + metadata files (not per-layer datasets)
├── layers/<chain-id>           one dataset per applied layer chain
│                               @final snapshot taken after unpack
├── containers/<task-id>        writable layer: clone of image top @final
└── volumes/<volume-name>       named local volumes
```

- **Layer application**: layer N's dataset is a clone of layer N−1's `@final`; the
  tarball (possibly zstd/gzip) is unpacked into it (whiteout handling per OCI image
  spec), then `@final` is snapshotted. `<chain-id>` is the OCI chain ID (digest of the
  diff-id chain), so shared prefixes between images share datasets.
- **Container rootfs**: clone of the image's top `@final`; destroyed on task removal.
- All zfs invocations go through the typed wrapper module (`zfs create/clone/snapshot/
  destroy/list -H -p`, machine-readable output, fixture-tested parsing).
- Unpack runs in `spawn_blocking` (tar extraction is CPU/blocking-IO heavy).
- **Startup reconciliation** (with `satl-runtime`, brief M1 DoD): on start, `satld`
  lists jails (`ocijail list`) and clones, adopts those matching live local task state
  (§7.2), and destroys orphans, including leaked epairs (§11), stale clones from
  interrupted teardowns, and **leftover container mounts**, which run *before* the
  dataset sweep because `zfs destroy` refuses while anything is mounted below a dataset.

### 10.1 Layer garbage collection (M5)

The planner is pure and lives in `satl_storage::gc`; `satld::backend::prune` drives it.
Since M9 it has **two** drivers through one `reclaim()`: `POST /images/prune` and
`DELETE /images/{name}`. That is deliberate, a targeted removal destroys layers too,
so it earns the same two-agreeing-readings rule, and a removal that skipped it would
be a second, weaker policy for the same irreversible act. The deferral is reported on
both, as a body field on the prune and as `X-Satl-Deferred-Layers` on the removal,
whose Docker-shaped array has no room for it.

A layer dataset is referenced when **any** of three readings claims it, and the claim is
then closed **upward** through the clone `origin` edges on disk:

1. an **image record** on this node names it, every chain in the image's stack, from
   folding `chain_id` over the config's `diff_ids` (`chains_of`), not just the top chain;
2. a **clone holds its `@final`**, read straight off ZFS. This is the reading that
   protects a *stopped* container, whose image record may well be gone: a re-pulled tag
   overwrites its `repositories.json` entry in place, so the container's rootfs clone can
   be the last thing in the world that wants a chain;
3. an **apply is in flight**, from `LayerStore`'s per-chain gate.

Without the ancestry closure the GC would go after the layers *below* a live container's
top layer, where ZFS refuses (`filesystem has dependent clones`) on every pass forever.
A dataset with no `@final` is never collected either, it is mid-apply or half-applied,
and `ensure_layer` destroys and rebuilds it.

Two safety properties are structural rather than hoped for. **Two consecutive passes must
agree** before anything is destroyed, the discipline `27ccb64` set for the dataset sweep
and for the same reason (each reading is momentarily incomplete at a different time), and
what the second pass disagreed about is reported. And **`zfs destroy -r`, never `-R`**:
recursion takes the layer's own snapshots, while ZFS refusing to destroy a snapshot that
still has clones is a last line of defence that `-R` would disable, it would flatten a
container's writable layer along with the image layer under it.

Content (blobs, manifests, configs) is reclaimed separately, by reachability from
`repositories.json`. SatL has no untagged image *records*, a record is a reference, so
what Docker calls a dangling image appears here as unreachable content. Reclamation stops
for a pass while any pull holds its per-reference lock: a blob is written before the
metadata naming it, so the reachable set is incomplete by construction.

## 11. Networking

pf rule ownership (invariant, "FreeBSD gotchas"): SatL owns the `satl/*` pf anchors
(`satl/nat`, `satl/rdr`) and never touches rules outside them. Anchors are loaded/
flushed atomically per reconciliation; details in `docs/networking.md` as they land.

### 11.1 Node-local (M1): bridge networks

- Default network `satl0` (Docker's `bridge` equivalent): a bridge(4) per network,
  VNET jail per task, epair(4) pair, `a` end in the bridge, `b` end inside the jail.
- Local IPAM: default subnet pool for local bridges `10.88.0.0/16` (podman's
  convention; avoids the OVH underlay `10.2.0.0/16`), gateway = bridge address on the
  host, per-network allocation bitmap persisted node-locally.
- Outbound NAT via pf (`satl/nat`), port publishing via rdr rules (`satl/rdr`)
  targeting the task IP; published host ports are recorded in task status
  (`port_status`) for `satl ps`.
- epair/bridge lifecycle is reconciled on startup (§10): every SatL-created interface
  carries a `satl:<task-id>` naming/description convention so orphans are identifiable.

### 11.2 Overlay (M3): VXLAN with a Raft-distributed FDB

- One VNI per overlay network (allocated by the allocator, stored on the `Network`
  object). Per node and per network: a vxlan(4) interface (unicast mode, UDP port
  4789 default) bridged with the epairs of local tasks on that network.
- **No multicast, no flooding**: the control plane knows every (task IP, MAC, node
  VTEP) triple from the store. Each node's overlay agent receives endpoint tables via
  its dispatcher session and programs static FDB/bridge entries and static ARP/NDP for
  remote endpoints. Endpoint changes propagate as assignment-stream updates. The ARP
  entries are per *jail*, and neither `jexec arp -s` nor `route -j` can install them,
  a container image has no `arp(8)` and `route(8)` never sets `RTF_LLDATA`, so the
  agent enters the task's VNET and talks to the kernel itself (`docs/vxlan.md` §4).
- **FDB entries are add/remove/replace, not upsert.** `VXLAN_CMD_FTABLE_ENTRY_ADD`
  returns `EEXIST` for a MAC already in the table, whatever VTEP it points at, and
  leaves the stored entry alone (measured; `docs/vxlan.md` §3). Since a MAC is a pure
  function of the endpoint's overlay IP, a task migrating between nodes keeps its MAC
  and changes only its VTEP, exactly the case `add` refuses, so the reconciler's
  delta has three lists (add, remove, replace) and `replace` is a remove followed by
  an add, with a window in which that MAC resolves nowhere.
- **No ~2000-endpoint ceiling, but do not read the whole table back.**
  `vxlanmaxaddr` tops out at a compile-time 2000 and gates only the driver's
  *learning* path, which SatL disables, so static entries are unbounded (2500
  installed on an interface reporting `max 2000`). What does bound the design is the
  read-back: `net.link.vxlan.N.ftable.dump` truncates at one page, **81 IPv4
  entries**, with well-formed output and no error, so reconciliation must diff
  against its own recorded state and the ioctl's `ftable count`, not against the
  dump, for a network to scale past ~80 endpoints on one node (`docs/vxlan.md` §3).
- **MTU**: VXLAN costs 50 bytes; overlay MTU = underlay MTU − 50, configurable
  per-network and cluster-wide. **Measured** on the OVH underlay at M3: path MTU 1500
  (virtio refuses more), so overlay MTU **1450**, and the driver's own default comes
  from the constant `ETHERMTU`, not the underlay, so it is always set explicitly. The
  mismatch symptom is *not* "small packets pass, big ones hang": the outer header has
  DF clear, so an oversized frame is fragmented rather than dropped, and the dangerous
  case is the one that keeps working while doubling packet counts. Evidence and the
  four failure configurations are in `docs/vxlan.md` §1/§6.
- **Node VTEP address = what the node says about itself**, in three steps of
  descending trust: (1) `NodeDescription.data_addr`, the node's own report, derived
  from its `advertise_addr` with the port stripped (§8.3), the only source that is
  not somebody else's inference and the only one a worker has; (2)
  `manager_status.addr`, a manager's raft advertise address, the same configured
  value in practice, for a manager whose agent has not re-registered since
  `data_addr` existed and absent on every worker (managers never dial workers,
  invariant #3); (3) the address the dispatcher **observed** the agent connecting
  from, which is a fallback and not a source, it is the *control-plane* path, and
  only equals the underlay for as long as agents happen to reach their managers over
  the underlay. A VTEP taken from step 3 is logged with a warning.

  Why the last step matters enough to warn about: a wrong VTEP does not fail loudly.
  The tunnel comes up, the interface reports `RUNNING`, and traffic goes nowhere,
  the same shape as the M2 bug where raft membership carried a node name instead of
  an address and the cluster looked healthy. And measured: over the **co-located**
  dispatcher socket the observed address is *empty*, so before `data_addr` the local
  node had no VTEP at all, the one node whose address is least in doubt was the one
  the manager could not name.

  The default remote of every VTEP is a blackhole, which makes a missing FDB entry
  fail instead of silently working on the one peer it happens to point at.
- **Data-plane encryption (M6, `--opt encrypted`).** An encrypted overlay network
  wraps its VXLAN datagrams in ESP transport mode (`aes-gcm-16`), programmed on
  each node with `setkey` from the network's keyring. The design is measured end
  to end in `hack/experiments/esp/`; the facts that shape it: each encrypted
  network binds its own VTEP UDP port from 4790..=4999 (the SPD matches neither
  the VNI nor the hashed outer source port, so the port is what isolates one
  network's keys from another's, `Network.vxlan_port`), and its MTU pays the
  ESP expansion on top of VXLAN's: underlay − 84, i.e. **1416** on the OVH
  underlay (34-byte ESP expansion + the 50 above). The keyring lives on the
  `Network` object (`Network.keys`), so it rides the DEK-encrypted raft store
  for free and reaches **participant nodes only**, inside their dispatcher
  network assignments, which is also why the ingress network can never be
  encrypted: its assignment is broadcast to every node (SWK §9.1), so a keyring
  on it would ship cluster-wide. The leader rotates the ring every 12 h in three
  phases (append → promote → prune, 60 s of settling between them, every
  decision re-derived from store state so a failover resumes mid-rotation);
  nodes emit with the primary key and accept every key in the ring. Cleartext
  injection is blocked by pf, not by the SPD, an inbound `require` policy does
  not drop unprotected packets on 15.1, so a node hosting an encrypted network
  loads the `satl/guard` anchor: block the encrypted ports on the underlay, pass
  them decapsulated on `enc0` with `no state`,
  `net.enc.in.ipsec_filter_mask=2`. Measured detail: `docs/vxlan.md` §10.

### 11.3 IPAM (cluster)

Allocator-owned, in Raft: overlay subnets come from the cluster's default address pool
(default `10.100.0.0/14`, subnet size /24, both configurable at init), chosen to
avoid both the underlay (`10.2.0.0/16`) and local bridges (`10.88.0.0/16`). Per-task
IPs allocated from the network's subnet; gateway and reserved addresses respected.
Allocation state lives on the objects themselves (SwarmKit model): restore-then-
allocate two-phase walk on leader start so a new leader never re-hands out in-use
addresses (SWK §9.2).

### 11.4 Port publishing

- `host` mode: bound only on nodes running a task; per-node exclusivity enforced by the
  scheduler filter; recorded verbatim (no central allocation).
- `ingress` mode: centrally allocated (auto-assign range 30000–32767, master record
  1–65535 per protocol, sticky across updates, SWK §9.5). **Routing mesh (M6d)**:
  every manager answers on the port; a node with no local replica relays over the
  `ingress` overlay network (created lazily on the first ingress publisher, SWK
  §9.3) to a healthy task's ingress address, with a return-path SNAT from the
  relaying node's per-node ingress gateway (`Network.node_gateways`, SWK §9.1's
  per-node load-balancer attachment). The client address is lost on relayed
  connections, same trade as Docker's mesh; the opt-in remedy is M6e's
  PROXY-protocol mode. Workers, having no store replica, keep the pre-mesh
  node-local behavior. The full contract is `docs/networking.md` (M6d) and the
  deviation record is `docs/api-compat.md` #75.
- **The node side is a level, not an edge** (M3). Nothing announces a published port to
  a node: an ingress port is assigned by the leader's allocator and arrives as a field
  of a task object in the store. So each node re-derives its whole `satl/rdr` anchor
  from the tasks that run *there* on a short timer (`satld`'s port sweep), and pf is
  reloaded only when the ruleset text changes. The task controller's publish at
  container start remains as the fast path for host-mode ports; the two writers own
  disjoint slots of the same set so neither can erase the other
  (`crates/satl-net/src/manager.rs`, `docs/networking.md`).
- Several tasks of one service on one node share **one** rdr rule with a `round-robin`
  address pool. pf takes the *first* matching translation rule, so one rule per task
  would leave every task but one unreachable while looking published.

### 11.5 Service discovery: DNS-RR (decision)

Embedded DNS responder per node (part of `satl-overlay`), answering on each SatL
network's gateway address, port 53, and on an overlay that address is allocated
**per node**, since every node's bridge is on one L2 segment and a shared gateway
address is a duplicate address there (measured, `docs/vxlan.md` §8; the Docker-API
consequence is in `docs/api-compat.md`). Task `resolv.conf` points there, one
`nameserver` line per attached network. Answers
`<service>` and `<task-name>` with the healthy tasks' overlay IPs, shuffled
round-robin; forwards everything else upstream (host resolver).

**Scope is the querying task, not the socket.** The chain is source address → local
task → that task's networks, walked in **attachment order** (the order of
`TaskTemplate.Networks`), and the first network that holds the name answers it,
whole, never merged with another network's. Scoping to the network whose socket
received the query would instead scope it to whichever `nameserver` line the stub
resolver picked, so a task on two networks would get `NXDOMAIN` for every service on
the other one, an authoritative denial a stub caches and does not retry on the next
line, which is worse than a timeout. A source address belonging to no task *this node
hosts* is scoped to nothing and forwarded upstream: an overlay's per-node gateways
share one L2 segment, so the socket is reachable from every task of the network on
every node, and answering a stranger from every network this node holds would leak one
tenant's service names to another. The node builds both projections **without a
store** (M4, so a worker resolves like a manager): the endpoint table comes from the
per-network endpoint tables the dispatcher ships, `NetworkEndpoint` carries the
service name, task name, aliases and observed state alongside the address precisely
so this needs no store read, and a state change moves the endpoint value, which is
what pushes "this task left RUNNING" to every node answering for it, and the scope
table comes from the local task DB (a scope is the task's own attachment list). The
DNS code in `satl-overlay` takes both as data and knows nothing of their source.
What Docker does here, and where SatL departs from it, is recorded in
`docs/api-compat.md` #73/#74. Rationale vs VIP:
FreeBSD has no IPVS; a VIP would need pf-based per-connection load balancing that adds
state and failure modes. DNS-RR ships first; `EndpointSpec.mode = vip` is reserved and
rejected in v1 (api-compat entry). pf `rdr ... round-robin` is the likely M6 path to a
VIP-ish mode. DNS answers come from the local endpoint table (§11.2), so they reflect
store state within propagation delay.

## 12. Security model

### 12.1 Identity

Every node has an ECDSA P-256 keypair and an X.509 certificate from the embedded
cluster CA (rcgen): **CN = node ID**, **OU = role** (`satl-manager` / `satl-worker`),
**O = cluster ID**. TLS server name presented by managers: `satl-manager` (and
`satl-ca` for the bootstrap endpoint). Role changes take effect via certificate
renewal (§12.3). rustls everywhere; ECDHE + AES-GCM/ChaCha20-Poly1305 only.

### 12.2 Join flow and tokens

Token format: `SATL-1-<digest>-<secret>`, digest = base36 SHA-256 of the root CA
bundle (pins the CA against MITM on first contact), secret = 16 random bytes base36
(25 chars), constant-time compared. Two tokens (worker/manager); **the token used
determines the role**; rotation regenerates the secret. (SwarmKit's SWMTKN scheme,
SWK §16.2, different prefix, api-compat entry since some tooling pattern-matches
`SWMTKN`.)

Join: fetch root CA (`GetRootCACertificate`, no client cert) → verify digest → generate
key+CSR → `IssueNodeCertificate{csr, token}` → CA creates the Node object (the only
place Node objects are born) and the signing loop issues the cert (server-controlled
subject/SANs; only the public key is taken from the CSR) → poll
`NodeCertificateStatus` → atomic write of cert+key (key `0600`) → open dispatcher
session (workers) / join Raft (managers, §6.6).

### 12.3 Issuance, renewal, rotation

- Node cert validity 90 days (min 1 h in production; the signer's hard floor is 1 min,
  reachable only through the `cert_validity` testing knob in `satld.toml`, which warns
  loudly below 1 h, see docs/operations.md). Backdated for skew: 1 h, capped at an
  eighth of the validity so a short-lived test certificate's renewal window stays in
  its future. Renewal at a random point in the 50–80 % of the NotBefore–NotAfter span
  (herd avoidance); expired certs retry with exponential backoff.
- **Renewal is live (M4).** Every TLS surface of the daemon, the mTLS listener
  (2377), the NodeCA bootstrap listener (2378), the raft/forwarding channels, the
  agent's dispatcher channels, is built once over one shared
  `satl_ca::LiveIdentity`, and rustls resolves the certificate **per handshake**
  through `ResolvesServerCert`/`ResolvesClientCert` seams that read it. The renewal
  loop re-issues from the cluster root, persists to `<state_dir>/certs`, and swaps the
  live identity: the next handshake on either side presents and verifies with the new
  material, no restart, no config rebuild, no channel-cache invalidation. Established
  connections keep the identity they were opened with until they reconnect (TLS
  authenticates at handshake time only), deliberate, a renewal must not sever healthy
  connections. Trust anchors swap through the same seam, so a bundle that grows a
  second root (M5 rotation) is honoured by new handshakes too; the one pinned piece is
  the server's root *hint subjects*, which SatL's single-certificate clients ignore.
  TLS **session resumption is disabled** on the internal clients: a resumed session
  re-attaches the pre-renewal identity (and pre-promotion role) without
  re-verification, and internal connections are long-lived enough that resumption buys
  nothing.
- Promotion/demotion = a renewal whose OU follows the store's role for the node, and
  the swap above is what lets it take effect live. The renewal is *triggered* by the
  role watcher the moment the session reports the changed role (§7 decision 7), not
  left to the 50-80 % window. On a node with a store the periodic loop self-issues
  from the cluster root; a **worker** renews through `NodeCA.IssueNodeCertificate`
  over the authenticated mTLS channel (empty token, the presented certificate is
  the credential; only the leader signs, and the client follows the
  `satl-leader-addr` redirect), then polls `NodeCertificateStatus` on the signer.
- Root CA: self-signed, 20-year validity, key in the Raft store (protected by at-rest
  log encryption, §12.4). External CA support: out of scope v1 (§14).
- **Root rotation (M5): `satl ca rotate`**, replace the root without downtime, via
  Docker's own surface (`POST /swarm/update` with `CAConfig.ForceRotate` above the
  stored counter; `GET /swarm` reports `RootRotationInProgress`). The whole rotation
  is state in the store, level-triggered, resumable across leader changes:
  - **Start** (one atomic Cluster update, built by `satld::rotation::start_rotation`):
    mint the new root; **cross-sign** it with the old root's key (same subject and
    public key, issuer = old root, SWK §16.5); set `Cluster.root_ca_cert` to the
    **transitional bundle** (old + new roots); store new root + key + cross-signed
    cert in `Cluster.root_rotation`; regenerate both join tokens (their digest pins
    the whole bundle, §12.2, so the old tokens die here, and again at completion).
    A second `rotate` while one runs is refused (deviation from SwarmKit, which
    replaces the running rotation; recorded in api-compat).
  - **During**: `NodeCA` and the manager renewal loop sign with the **new** root's
    key and append the cross-signed intermediate to every leaf, so the chain
    `leaf → intermediate → old root` satisfies verifiers still anchored on the old
    root while the same leaf chains directly to the new one, trust anchors and
    leaves may converge in any order, no flag day. The transitional bundle reaches
    managers through the store watch, workers through the session's root-CA push,
    and joiners through `GetRootCACertificate` (2378), each of which persists it to
    `certs/ca.crt` and swaps it into the `LiveIdentity`.
  - **Reconciler** (leader-only, 3 s tick, batch 30, SWK §16.5): every issuance
    records the signing root's digest as `Node.certificate_issuer`; nodes whose
    digest differs from the new root's are marked `CertificateStatus::Rotate`, which
    every renewal loop treats as "renew now" (the mark self-clears: the signer
    records `Issued` + the new digest). When every node has converged the rotation
    finishes atomically: new root alone as trust bundle and signing key, tokens
    regenerated, `root_rotation` cleared.
  - **A node offline through the whole rotation** comes back with a leaf chaining to
    a dropped root: managers refuse the handshake (the refusal is logged
    operator-facing on the manager, with the rejoin instruction), its stale join
    token fails the bundle-digest check with a message naming the rotation, and the
    way back in is `satl swarm leave --force` + a fresh `satl swarm join`
    (docs/operations.md). A node that will never return holds the rotation open
    until `satl node rm --force` removes it, the reconciler waits for *every* node
    object, deliberately.
  - **No renewal flap** under short `cert_validity`: the mark is compared against
    the digest a node last issued under, the periodic window is drawn once per
    certificate, and both the periodic and the rotation-triggered path sign from the
    store's current signer, the two paths converge on the same fact instead of
    racing.
- Removed nodes' certs go on the cluster blacklist until expiry + 7 days grace.

### 12.4 At-rest encryption and secrets

- Raft log entry payloads and snapshots are encrypted at rest from M0
  (XChaCha20-Poly1305 via the RustCrypto `chacha20poly1305` crate; random nonce per
  record; a `MultiDecrypter` shape allows key rotation). The per-manager DEK lives
  beside the node TLS key, mode `0600`. Autolock/KEK (encrypting the DEK with an
  operator-held key) is deferred (§14).
- Since the whole log is encrypted, **secrets are encrypted at rest** wherever manager
  state touches disk. Size limits: secret < 500 KiB, config < 1000 KiB. Control API
  never returns secret payloads. The same covers the data-plane keyrings of
  encrypted overlay networks (`Network.keys`, §11.2): stored on the `Network`
  object, they are encrypted at rest for free, and they leave the managers only
  inside the mTLS dispatcher stream, to participant nodes only.
- **Workers never write secrets to disk** (invariant #7): secrets arrive over the mTLS
  dispatcher stream, live in agent memory (`satl_agent::DependencyStore`, shared
  between the session sink and the executor), and are materialized only inside a
  per-task `tmpfs` mount in the jail, Docker's path, `/run/secrets/<target>`, with
  uid/gid/mode from the file target (numeric only). The agent's local task
  persistence (§7.2) stores secret *references*, never payloads; after an agent
  restart, payloads are re-fetched via the session's COMPLETE assignment snapshot.
- **Mount mechanics (M5).** The tmpfs rides the OCI bundle: `plan_dependencies`
  (satl-agent) appends a `tmpfs` mount at `/run/secrets` sized to the payloads
  (`size=`, floor 128 KiB) and `ocijail create` performs it host-side; the agent then
  writes the payload files into `<rootfs>/run/secrets` **between `create` and
  `start`** (umask-proof: mode and ownership are applied explicitly after the write).
  Secret targets must be relative paths under that directory (`docs/api-compat.md`).
  Teardown needs nothing new: the mount-leak sweep after `ocijail delete` and the
  startup reconciliation's orphan pass unmount everything strictly below the rootfs,
  tmpfs included. The one gap that needed code is the *adoption* path: a daemon
  killed between `create` and the payload writes leaves a created jail with an empty
  tmpfs, so a controller adopting a `Created` container rewrites every payload from
  the (re-fetched) dependency store before reporting `READY`. A referenced
  secret/config not yet delivered is a **retryable** controller error, not a
  rejection, the dispatcher ships dependencies before dependents, so the gap only
  exists mid-resync.
- **Configs** are the same shape without the secrecy: payloads are written under the
  task's bundle directory (`<bundle>/configs/<n>`, uid/gid/mode applied to the
  source) and enter the jail as **read-only nullfs file-mounts** at their absolute
  target (a relative config target is rooted at `/`, as Docker does). The bundle
  directory is removed with the task.

### 12.5 RPC authorization matrix

Per-service role requirements are listed in §7's table; checks are OU + O (cluster ID)
+ not-blacklisted, applied by a tonic interceptor. The REST API has no user-level
authz in v1: the unix socket is root-owned (`0660`, group `satl`); remote REST
requires a client certificate from the cluster CA.

## 13. Docker API compatibility strategy

- Target **Docker Engine API v1.43+** semantics: version-prefixed paths
  (`/v1.43/...`), version negotiation via `/_ping` headers, JSON shapes matching
  Docker's (field-for-field where implemented).
- Endpoint groups by milestone: M0 `/version`, `/_ping`, `/info` (minimal); M1
  containers + images + local volumes/networks + `/events` + `/exec`; M2 `/swarm`,
  `/nodes`, `/services`, `/tasks`; M3 overlay networks; M5 `/secrets`, `/configs`;
  M9 `DELETE /images/{name}` and `GET /images/{name}/json`.
- `satl` CLI verbs map 1:1 to docker's; `satl compose` (M5) consumes Compose Spec
  files (services, networks, volumes, secrets, deploy.{replicas,resources,placement}).
- **Every intentional deviation gets an entry in `docs/api-compat.md` in the same PR**
  (invariant #8). Already-known deviations to record when implemented: auto-initialized
  single-node swarm (§1.2); DNSRR-only endpoint mode (§11.5); ingress ports not
  reachable on task-less nodes until M6 (§11.4); `SATL-` token prefix (§12.2);
  FreeBSD-specific fields (jail id in inspect output, `PLATFORM` column); unsupported
  Linux-only container options rejected with explicit errors (cgroup options, seccomp,
  etc.).
- **The surface has a machine-readable half since M9**: `docs/openapi.yaml` is
  generated from the handlers' own annotations and `make check` fails when it drifts
  from the code, with `docs/api.html` rendering it offline. It is a file and not an
  endpoint, invariant #8 makes the Docker API the only external surface, and a
  `/swagger` route would not be part of it. `api-compat.md` stays the prose half: the
  document says what the API *is*, the entries say where it departs from Docker's.

## 14. SwarmKit feature mapping

Disposition of every SWK feature area. "Adopt" = same semantics and defaults; "adapt" =
same model, FreeBSD implementation; "defer" = keep the design compatible, build later;
"drop" = no plan.

| SWK § | Feature | Disposition |
|---|---|---|
| §3 | Object model, IDs, names, spec defaults | **Adopt** (minus CSI Volume / Extension / Resource objects, defer) |
| §4 | Task model, state machine, slots, history | **Adopt** verbatim |
| §5 | Store-and-watch pipeline architecture | **Adopt** |
| §6 | Control API semantics (validation, optimistic concurrency, restricted updates: no rename, no mode change; update-pauses-clear, rollback swap) | **Adopt**, surfaced through the Docker REST API instead of a public gRPC control API |
| §7.1–7.6 | Orchestrators, updater, restart supervisor, reaper, constraint enforcer | **Adopt** (replicated + global) |
| §7.7 | Volume enforcer | **Drop** (no CSI) |
| §7.8 | Jobs (replicated/global) | **Defer**, state machine reserves `COMPLETE`-desired tasks so jobs can land later |
| §8 | Scheduler: intake, 50 ms/1 s debounce, filters, spread ranking, fault penalty (5/5 min), preassigned tasks, constraint language | **Adopt**, filters: Ready, Resource, Constraint, Platform, HostPort, MaxReplicas (Plugin filter dropped, Volumes filter dropped) |
| §8.5 | Placement preferences (SpreadOver decision tree) | **Defer** (constraints ship in M2; preferences later) |
| §9 | Allocator model (ballot, two-phase restore, retry 5 min, targeted conflict merge), port allocation (dynamic range, sticky) | **Adopt**; IPAM/VNI bookkeeping implemented natively (SwarmKit's real allocator lives in moby, SWK §23.5) |
| §10 | Store engine (indices, batching 200/1.5 MiB, watches, resumable watch) | **Adopt** model; Rust maps + broadcast instead of go-memdb; resumable watch deferred until needed |
| §11 | Raft: encrypted persistence, chunked snapshots, quorum-safe membership, no proposal timeout, leader proxy | **Adapt** onto openraft (which owns elections/log replication; we implement storage, transport, membership policy) |
| §12 | Manager lifecycle, leader-only components, role manager, dirty-state rule | **Adopt** |
| §13 | Dispatcher protocol (sessions, heartbeats, assignments, status batching, 24 h orphaning) | **Adopt** with same constants |
| §14 | Agent: single session, backoff, re-report on register, local task DB, canonical local status | **Adopt** (CBOR files instead of boltdb) |
| §15 | Executor/Controller contract, one-step state machine, Resolve semantics | **Adopt**; executor = ocijail + ZFS + VNET stack |
| §16 | CA, tokens, renewal window, rotation, blacklists | **Adopt** (rcgen/rustls); external CAs and FIPS **drop**; autolock/KEK **defer** |
| §16.8 | Network bootstrap keys (gossip/IPsec key ring) | **Adapt**, the IPsec key-ring shape is adopted (per-network keys, 12 h rotation, primary + previous ring) but gossip dissemination is not: keyrings live on the `Network` object in the encrypted Raft store and reach participant nodes inside dispatcher assignments (§11.2), which makes gossip unnecessary, the store already replicates the ring to managers and the dispatcher already reaches exactly the participants |
| §17 | Secrets/configs delivery, per-task restriction | **Adopt** (tmpfs delivery); secret drivers **drop**; Go-templating **defer** |
| §18 | CSI cluster volumes | **Drop** for v1 (node-local volumes only, §3) |
| §19 | Log broker (cluster-wide `service logs` without manager storage) | **Defer** to M4/M5 (`satl logs` for local tasks lands in M1) |
| §20.1–20.4 | Watch queue, connection broker, metrics namespaces, public watch API | **Adopt** watch queue + broker model; metrics surface designed early, implemented M6; public watch API deferred (REST `/events` covers the need) |
| §20.6 | Attachable-network API | **Defer** |
| §21 | swarmd/Docker executor | Reference only |
| §23 | Known quirks | Reviewed; do-not-reproduce list: quirks 1, 2, 3, 7, 8 (e.g. `RemoveTask` REST equivalent must shut down before delete); must-preserve invariants: 12 (commit inside raft apply; followership-then-cancel ordering) |

## 15. Constants and defaults

Adopted from SwarmKit (SWK §22) unless stated; single source of truth will be
`satl-core::defaults` with this table kept in sync:

| Constant | Value |
|---|---|
| Stop grace period | 10 s |
| Restart condition / delay | `any` / 5 s |
| Update parallelism / monitor / failure action / order | 1 / 5 s / `pause` / `stop-first` |
| Old-task stop wait before a `stop-first` promotion | 1 min (`satl_orchestrator::update::OLD_TASK_TIMEOUT`) |
| Monitor window when `delay >= monitor` | `delay + 1 s` |
| Task history retention per slot | 5 (rct: `MaxAttempts+1` override) |
| Healthcheck interval / timeout / retries (Docker's) | 30 s / 30 s / 3 |
| …on a service that **publishes a port** | 5 s / 3 s / 2 (`docs/api-compat.md` #125, #126; timeout always ≤ interval) |
| Task reaper batching | 250 ms / 1000 dirty |
| Scheduler debounce | 50 ms, 1 s max |
| Scheduler fault penalty | 5 failures / 5 min |
| Ingress dynamic port range | 30000–32767 |
| Allocator retry | 5 min |
| Store transaction limits | 200 actions / 1.5 MiB |
| Raft ticks (heartbeat/election/tick) | 1 / 10 / 1 s |
| Snapshot interval / slow-follower entries | 10 000 / 500 |
| gRPC max message size | 4 MiB |
| Dispatcher heartbeat / jitter / TTL factor | 5 s / ±500 ms / ×3 |
| Node down → ORPHANED | 24 h |
| Status flush | 100 ms / 10 000 updates |
| Assignment batching | 100 changes / 100 ms |
| Agent session backoff | 100 ms → 8 s, jittered |
| Node description refresh | 20 s |
| Root CA validity / node cert validity | 20 y / 90 d |
| Renewal window | 50–80 % of validity |
| Secret / config max size | 500 KiB / 1000 KiB |
| ID format | 25 chars base36 |
| Default local bridge pool | `10.88.0.0/16` |
| Default overlay address pool / subnet size | `10.100.0.0/14` / 24 |
| VXLAN UDP port | 4789 |
| Encrypted-overlay VTEP UDP port range (per network, allocator-assigned) | 4790–4999 (`satl_core::defaults::OVERLAY_VXLAN_PORT_RANGE`) |
| Unix socket | `/var/run/satl.sock` |
| State dir / config | `/var/db/satl` / `/usr/local/etc/satl/satld.toml` |
| Default ZFS root dataset | `zroot/satl` |

## 16. Environment and operational constraints

- **Dev/build host**: FreeBSD 15.1 amd64 (`alpha.fredalix.com`), native builds only.
  **The dev machine is never rebooted** (user policy, 2026-08-09), so any boot-time
  tunable it needs has to be set during a window the user grants. `kern.racct.enable=1`
  is now set there and on the VMs (§8.3), so rctl enforcement is exercised on both;
  unit tests still never require racct and `satld` still degrades gracefully.
- **Cluster testbed**: 3× FreeBSD 15.1 VMs (OVH Public Cloud), 4 vCPU / 8 GiB / ZFS,
  private underlay `10.2.0.0/16` (vtnet1), public IPs on vtnet0. Inventory (hostnames +
  private IPs) lives in `tests/cluster/inventory.toml` **only**, never hardcoded.
  VMs may be freely reconfigured/rebooted; `kern.racct.enable=1` will be set there;
  ocijail must be installed there (M2 setup scripts in `tests/cluster/`).
- Root: integration tests require root (jails/ZFS/pf) and are `#[ignore]`-gated behind
  `make integration`; unit tests run unprivileged.
- Observability: `tracing` spans around every lifecycle transition (image pull, layer
  clone, jail create/start/stop, task state change, raft role change); JSON log mode;
  task state transitions carry structured fields (`task_id`, `service_id`, `node_id`,
  `from`, `to`). Prometheus `/metrics` is implemented (M6b, `satl-metrics`) with a
  **split namespace**: series dockerd itself defines keep Docker's exact names
  (`engine_daemon_*`, `http_requests_total`) so off-the-shelf Docker dashboards
  render unchanged; everything SatL-specific uses the `satl_*` prefix this
  document committed to. The split is recorded in `docs/api-compat.md`.

## 17. Open questions (resolve during implementation, record findings here)

| # | Question | Resolve by |
|---|---|---|
| 1 | ~~openraft log-storage backend~~ **Resolved (M0): redb**, pure Rust, ACID, single file, fsync-on-commit; full justification in `crates/satl-cluster/src/log_store.rs` module docs. Validated by the official openraft storage compliance suite. | done |
| 2 | `oci-spec` crate: does it compile cleanly on FreeBSD and model jail platform extensions acceptably, or do we vendor minimal types? | M1 start |
| 3 | ~~ocijail config.json contract~~ **Resolved (M1)**: see `docs/ocijail.md`, consumed-fields contract, `org.freebsd.jail.*` annotations (vnet=new), stdio inheritance for logs, kqueue NOTE_EXIT for exit codes, delete leaks mounts (cleanup is ours). | done |
| 4 | ~~Linuxulator jail parameters/mounts + failure signatures~~ **Resolved (M1)**: see `docs/linuxulator.md`, ocijail handles mounts/params itself; musl and glibc both work; systemd/cgroup images rejected at task creation (silent-death signatures documented). | done |
| 5 | ~~FreeBSD base image source for tests~~ **Resolved (M1)**: `docker.io/freebsd/freebsd-runtime:15.1` (official) + local `docker-registry` service on 127.0.0.1:5000 seeded via skopeo; DoD nginx image hand-built on top (see `docs/image-sources.md`, incl. the `ld-elf.so.hints` gotcha). | done |
| 6 | ~~OVH private network underlay MTU~~ **Resolved (M3): 1500, so overlay MTU 1450**, measured by DF ping sweep across all six node pairs; virtio refuses any MTU above 1500, so jumbo is impossible here. The driver's default is computed from `ETHERMTU`, not the underlay, so SatL always sets the MTU explicitly (`docs/vxlan.md` §1, §5). | done |
| 7 | ~~DNS responder placement~~ **Resolved (M3): one socket per (node, network), bound to that network's gateway address on the node's bridge**, no pf involvement, and the gateway address must be allocated per node, because on an overlay all nodes' bridges share one L2 segment (`docs/vxlan.md` §8, §11.5 above). | done |
| 8 | ~~rc.d service script shape~~ **Resolved (M0)**: satld runs under daemon(8) (`-f -S -T satld -p /var/run/satld.pid`, stdout/stderr to syslog), `REQUIRE: LOGIN FILESYSTEMS zfs`, knobs `satld_config`/`satld_flags`/`satld_env`, see `rc.d/satld`. | done |
