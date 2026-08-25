# SatL Roadmap & Development Status

> **This file is the live status of the project. It MUST be updated in the same commit
> as any work that starts, advances, or completes a milestone item** (see CLAUDE.md,
> definition of done). Milestone definitions come from `docs/project-brief.md`; this
> file tracks progress against them.

**Last updated:** 2026-08-24
**Current focus:** **M12, launch readiness.** Two cluster defects found during the M11
verification runs kept `make cluster-test` red on `ca_rotate`, and both were masked by
scenario ordering, so the previous green was partly luck. Both are now closed and the
suite has run 24/24 on the new engine. **Phase 1**, the openraft 0.9.25 ->
0.10.0-alpha.34 upgrade, is what made the first fix possible at all: 0.9 has no
leadership-transfer call and no workaround inside it (decision log). The internal gRPC
protocol moved to `satl.internal.v2` with it, non-additively -- the chunked
`InstallSnapshot` became a streamed `FullSnapshot`, and `TransferLeader` is new.
**Phase 2**: `satl node demote <the current leader>` completes in 294 ms on the testbed,
handover measured at 14 ms, where the old code retried for ever; the role write moved to
the leader, because a node out of consensus has a store that no longer moves.
**Phase 3** reframed the second defect by measurement: a worker publishes what it runs
and relays nothing, which is api-compat #75 as written, so what was real was a
convergence delay after a role change and a pass that logged nothing. **Phase 4**,
scenario independence, is the one that decides what a green is worth: scenarios now pick
by raft role and assert it, `demote_leader` exercises the hard case on purpose, and the
leftover audit finally looks at pf. **Phase 5** cleared the credibility items (the build
stamp, the false doc claims, `--force-new-cluster`, the overlay-on-a-/32 message).
Remaining: prove the suite from a different starting leader and in isolation, soak, tag.

Before that: M11 done 2026-08-24 and shipped as **0.2.0**, splitting Docker's two worlds
-- `satl compose` is node-local, `satl stack` keeps the cluster. All five phases landed
(the split, DNS on the node bridge, the lifecycle verbs, attach and logs, `build:`), plus
the version bump and the `satl-doc` sweep. This reversed the M5 decision that
`satl compose` carries stack semantics, which was inferred from "SatL has no standalone
container" and does not follow from it: invariant #2 constrains the execution model, not
the scope. Before that: M10, field fixes found during the documentation-validation run
against the fresh test VMs plus the man pages, done and DoD-verified 2026-08-23. Before
that: M9, whose 2026-08-19 verb audit found five daemon capabilities with no CLI client
(`/events`, `/info`, `/volumes/{name}`, the `node` task filter, the four prune endpoints)
and one operation missing at both layers: there was no way to delete a single image. M9a
closed the CLI half and added `DELETE /images/{name}` and `GET /images/{name}/json`; M9b,
the generated OpenAPI contract, is in progress. The cluster testbed was replaced the same
day (decision log): `fbsd{1,2,3}.satl.cc`, underlay now 10.0.0.0/24. M6a-M6g, M7 and M8
remain done; of the M6 backlog only plugin volumes are unscheduled.

| Milestone | Scope | Status |
|---|---|---|
| pre-M0 | Architecture document, repo bootstrap | ✅ done |
| M0 | Skeleton & plumbing | ✅ done (DoD verified 2026-08-09) |
| M1 | Single-node container lifecycle | ✅ done (DoD verified 2026-08-10) |
| M2 | Multi-node cluster | ✅ done (DoD verified 2026-08-10) |
| M3 | Overlay networking | ✅ done (DoD verified 2026-08-12) |
| M4 | Desired state, rolling updates, global services | ✅ done (DoD verified 2026-08-12) |
| M5 | Secrets, configs, compose, hardening | ✅ done (DoD verified 2026-08-13) |
| M9 | CLI parity and a generated API contract | `[~]` partially done (M9a verbs ✅; M9b OpenAPI contract in progress) |
| M6 | Backlog (routing mesh, dataplane encryption, build, metrics) | `[~]` partially done (`plan-m6.md`: M6a–M6g ✅; dataplane encryption ✅ 2026-08-16 on `m6-encryption`; jobs/placement prefs/autolock landed in M7; only plugin volumes remain, unscheduled) |
| M10 | Field fixes and man pages | ✅ done (DoD verified 2026-08-23) |
| M11 | The two worlds: node-local `satl compose`, cluster `satl stack` | ✅ done (2026-08-24, shipped as 0.2.0) |
| M12 | Launch readiness: the two cluster defects, scenario independence, credibility fixes | 🔨 in progress (Phases 1-6 done; `make check`, `sudo make integration` and `make cluster-test` **25/25 twice**, the encrypted suite 7/7, and `demote_leader` + `ca_rotate` pass in isolation. Five further defects were found by stressing the fixed paths -- an evicted node campaigning against a blacklist for ever, a doubled rebuild, a raced container clone that rolled back a whole update, an unkillable shutdown, and a suite ssh that could hang -- all fixed, and `make cluster-test` is 25/25 on the fleet carrying them, with `demote_leader` and `ca_rotate` green in isolation. Left: soak and push; `main` now carries M12 and is tagged `v0.2.0-alpha`) |

Legend: ⏳ not started · 🔨 in progress · 🔍 in review · ✅ done · 🧊 frozen · `[~]` partially done

---



## pre-M0, Bootstrap & architecture

- [x] Read project brief + SwarmKit behavioral spec (`/home/fralix/src/swarmkit/features.md`)
- [x] Verify dev environment (FreeBSD 15.1-p2, Rust 1.96.1, ocijail 0.6.0, ZFS, linuxulator)
- [x] Verify cluster VMs (3× FreeBSD 15.1-p2, ZFS, sudo, private net 10.2.0.0/16), ocijail missing there (install in M2)
- [x] `git init`, initial import
- [x] `docs/architecture.md` written
- [x] **Architecture reviewed and approved by Frédéric** (2026-08-09)

## M0, Skeleton & plumbing ✅ (2026-08-09)

DoD: fresh FreeBSD 15.1 host + `make install` + `satld` as rc.d service;
`docker -H unix:///var/run/satl.sock version` returns coherent JSON.
**DoD verified on alpha with docker CLI 29.4.2 (API negotiated 1.54→1.43),
plus kill -9 → rc.d restart → identical node identity recovered.**

- [x] Cargo workspace: 15 crates compile on FreeBSD 15.1 (`satl-proto` added, see architecture §2)
- [x] `make check` (fmt, clippy -D warnings, unit tests) green, 161 unit tests
- [x] openraft single-node cluster: FSM store, redb log storage (open question #1 resolved), snapshots, persistence on ZFS dataset; passes the official openraft storage compliance suite
- [x] At-rest encryption of raft log/snapshots (XChaCha20-Poly1305, per-manager DEK 0600)
- [x] `satld` config loading (`satld.toml`), ZFS preflight + child dataset creation, structured tracing (+ JSON mode)
- [x] Docker API: `/_ping`, `/version`, minimal `/info` (real node ID, active Swarm section) on unix socket
- [x] `satl version` end-to-end over the socket
- [x] rc.d service under daemon(8) + `make install` (open question #8 resolved)
- [x] `docs/operations.md`: install & bootstrap section; `docs/api-compat.md`: M0 deviations recorded

## M1, Single-node container lifecycle (through the orchestrator) ✅ (2026-08-10)

DoD: `satl run -d -p 8080:80 <freebsd nginx image>` serves traffic; a `linux/amd64`
image runs via linuxulator; kill -9 satld → restart → full state recovery + jail/epair
reconciliation.

**DoD verified on alpha**, all three criteria:
1. `satl run -d -p 8080:80 …/freebsd-nginx` → served `satl-test-ok` to a **remote**
   client (fbsd-dev---1 → 51.38.30.173:8080) through the `satl/rdr` pf anchor.
   (Published ports are not reachable from the publishing host via localhost, a pf
   property, recorded in `docs/api-compat.md` #35.)
2. `satl run …/alpine uname -a` → `Linux … 5.15.0 FreeBSD 15.1-RELEASE-p2 … x86_64`
   via linuxulator, output captured, exit 0.
3. `kill -9` on satld → jail kept serving through the outage → restart re-attached it
   with the same PID and republished its port; a planted orphan dataset was swept
   (`adopted=2 reattached=1 datasets_destroyed=1`).

- [x] Image pull: registry auth, manifest lists, platform selection (freebsd → linux/amd64 fallback), content store (50 tests + live pull)
- [x] ZFS layer store: chain-id datasets, snapshot+clone application, container clones (88 tests + root e2e)
- [x] Test-image supply chain: local registry 127.0.0.1:5000 + freebsd-nginx DoD image (open question #5 resolved)
- [x] Ground truth: ocijail contract + linuxulator recipe documented from source study + live experiments (open questions #3, #4 resolved)
- [x] OCI spec generation + ocijail wrapper (create/start/kill/delete/state/exec) with fixture tests; exit codes via kqueue NOTE_EXIT; leaked-mount sweep (59 tests + 4 root e2e)
- [x] Linuxulator support in satl-runtime: mount set, presence precheck, explicit rejection of systemd/init entrypoints
- [x] Anonymous single-replica service path: `satl run` → Service → Task → local scheduling (orchestrator owns task creation; the API waits for it)
- [x] `satl ps/stop/rm/logs/exec/inspect/wait/kill/pull/images/volume` + PLATFORM column (resolved from the pulled image)
- [x] Local bridge networking: VNET, epair, bridge, pf nat/rdr in `satl/*` anchors, port publishing (66 tests + 4 root e2e)
- [x] Volumes: ZFS datasets + host bind mounts (`satl volume ls|create|rm`)
- [x] rctl limits (`--memory`, `--cpus`) with racct-off graceful degradation, **enforcement verified on alpha** after enabling racct: memory kills at the cap, cpu throttles (see the decision log)
- [x] Startup reconciliation: adopt live jails, sweep orphan jails/datasets/epairs and orphan rctl rules, rebuild the pf redirect anchor
- [x] `/events` stream; tracing spans on all lifecycle transitions
- [x] Integration tests (`make integration`, root, #[ignore]-gated): 14 tests green, serialized (they mutate global host state)

## M2, Multi-node cluster ✅ (2026-08-10)

DoD: on the 3 OVH VMs: init + 2 joins; `--replicas 6` spreads; worker kill →
reschedule; leader kill → re-election, API stays up.

**All four DoD criteria verified live on the three VMs (2026-08-10)**, with the
cluster running as three managers (a manager runs tasks too, architecture §1.2, and
killing one of three keeps quorum at 2):

1. `satl swarm init` on node1 + `satl swarm join --token …` on nodes 2 and 3 → three
   `Ready` nodes, one `Leader`, two `Reachable`, correct hostnames.
2. `satl service create --replicas 6` → **2/2/2**, all `Running`, no rejected task.
3. `satld` and its jails killed on one node → node marked `Down` on TTL expiry → its
   two tasks evicted and replaced on the survivors (**3+3**).
4. `kill -9` on the leader → re-election; a survivor serves reads **and accepts
   writes** (`satl service scale` committed), exercising follower→leader forwarding.

Pushing past the DoD's letter then found a defect the four criteria did not catch, and
it was worth chasing: a desired state that moved while a node was away never reached
that node's agent, so `scale` did not shrink a service and a returning node kept a
stranded container alive with its jail outliving its task. Root cause and fix in the
decision log; verified live afterwards, `6/6` → `scale 3` → `3/3` with three jails,
and a killed-then-returned node stopping both its stranded containers.

All four scenarios are now scripted in `tests/cluster/run.sh` (`make cluster-test`):
five scenarios including a leftover audit, ~2 min, three clean runs plus a
deliberate-failure check both ways.

**Carried into M3/M4, known and deliberate:**

- **A worker-role join is refused.** A worker holds no replicated store while every
  REST surface reads one. The CA issues worker certificates correctly; the gap is in
  the daemon's own bring-up. Until it closes, a SatL cluster is all-managers.
- **Certificate renewal and node promotion take effect on restart.** The renewal loop
  re-issues on disk in the 50–80 % window but does not swap the live rustls config
  (that needs a `ResolvesServerCert` seam in `satl-cluster`), and a promoted node needs
  a manager certificate before it can join Raft.
- **A killed *leader* becomes `Unknown`, not `Down`, and its tasks are not evicted.**
  The new leader's dispatcher never held a session for it, so no TTL expires against
  it. A killed *follower* is evicted correctly (scenario 3). The scripted
  `leader_kill` therefore asserts "no longer Ready" rather than "reaped".
- `satl swarm init --advertise-addr` is always refused: first boot *is* the init
  (architecture §1.2) and rebinding the listener is a restart. Set it in `satld.toml`,
  `deploy.sh` does, and without it a node advertises its *public* interface.
- `TransferLeadership` **exists since the openraft 0.10 upgrade** (M12): a leader hands over
  through `trigger().transfer_leader()`, which disarms the target's leader lease instead of
  waiting it out. Before that, openraft 0.9 had no such call at all and
  `membership::yield_leadership` stood in by stopping the local ticker and waiting for a
  spontaneous election, which on a cluster that keeps writing can never happen.
- Restart history is in-memory, so a node failure right after an election gets a fresh
  max-attempts budget (SWK §7.9's `taskinit` replay is not implemented).

- [x] VM provisioning scripts (`tests/cluster/`): provision + deploy + images + reset + readiness `run.sh`; all 3 VMs green (racct, forwarding, pf anchors, ZFS, satld, per-node registry)
- [x] Embedded CA: issuance, join tokens (`SATL-1-…`), mTLS everywhere (94 tests, real handshakes). **Cert renewal is restart-to-apply**, re-issued on disk in the 50-80% window, but the live rustls config is not swapped (needs a resolver seam in satl-cluster)
- [x] `satl swarm init/join/leave` (+ `satl cluster` alias), dirty-state guard. **Manager tokens only**: a worker-role join is refused because a worker holds no replicated store while every REST surface reads one, the largest M2 gap
- [x] Raft membership: join via leader (learner-first, promoted asynchronously, see decision log), quorum-safe removal, two-phase demotion, removal blacklist derived in the FSM
- [x] Dispatcher: sessions, heartbeats, assignments stream (COMPLETE/INCREMENTAL with sequence markers), status batching, TTL→DOWN→ORPHANED (98 tests)
- [x] Agent: session lifecycle, local task persistence, re-report on register, dependency ref-counting (secrets in memory only)
- [x] Follower → leader forwarding for mutations (`Control.ProposeActions`, one redirect with the leader address in metadata)
- [x] `satl node ls/inspect/update/rm/promote/demote`, `satl service create/ls/ps/inspect/scale/rm/update` (326 tests). **Promotion completes on restart** (see cert renewal above)
- [x] Scheduler: full filter pipeline (Ready/Resource/Constraint/Platform/HostPort/MaxReplicas), spread ranking with the 5-in-5-minutes fault penalty, SwarmKit constraint language in satl-core
- [x] 3-node scenario scripts (`make cluster-test`): all four DoD scenarios plus a leftover audit, repeatable in ~2 min; three clean runs and a deliberate-failure check both ways (skipped step, broken assertion)

## M3, Overlay networking

DoD: two services on one overlay network, tasks on different VMs, reach each other by
service name; cross-node `curl` works with correct MTU.

Wave 1 (landed), the pieces that hold still while everything else moves:

- [x] Cluster allocator: overlay subnets from the address pool, VNIs from 4096, per-task
      addresses, ingress ports with sticky reallocation (`9d79f34`). Restore is
      structural, every pass reclaims what the store records before allocating, so
      allocator state never outlives a pass (stronger than SWK §9.2's restore-once).
- [x] Embedded DNS responder, hand-rolled RFC 1035 codec, malformed-input table +
      prefix fuzz, drop-response and self-upstream guards (`8167bf7`). Bind address is
      a parameter, not an assumption, wiring is wave 3.
- [x] MTU measured on the OVH underlay, closing open question #6: path MTU 1500
      (virtio refuses jumbo), so **overlay MTU 1450**. Evidence and the verified
      `ifconfig`/ioctl idioms in `docs/vxlan.md` (`719a066`).
- [x] Overlay gateway is **per node**, not one cluster-wide address (`6e2b42b`), one
      shared `.1` is a duplicate address on one L2 segment. Allocation falls out of
      rebuilding from the network's non-terminal tasks; `.1` stays reserved for nobody.

Wave 2 (landed), the data plane and its distribution:

- [x] VXLAN data plane: interface lifecycle, static FDB via `SIOCSDRVSPEC` (`ifconfig`
      cannot program it), ARP, and a pure delta between desired and programmed state.
      Verified on alpha and all three VMs; cross-node MTU proven by **zero** outer-IP
      fragmentation over 500 full-size frames, with an opt-in contrast run showing what
      a wrong MTU looks like in the counters.
- [x] Endpoint distribution via dispatcher assignments, reference-counted like secrets,
      with a separate **teardown** order (`Task < Network < Config < Secret`) because
      destroying a vxlan under a live jail black-holes it and leaks the epair.
- [x] `satl network create -d overlay` end to end: API + CLI.

Wave 3 (in flight), wiring and proof:

- [x] In-jail static ARP without an `arp` binary in the image: `satld` re-execs into the
      jail's VNET and writes to a routing socket (`8b5474a`). `jexec <task> arp` fails
      even where a binary exists, because half the images ship *Linux's* `arp` under the
      linuxulator, a presence check would have passed while the entry never existed.
- [x] Per-overlay bridge and epairs in `satl-net`, MTU and derived MAC explicit (`499ee92`)
- [x] Operator-facing strings are ASCII, with a source-walking guard (`30535de`)
- [x] M3 DoD scenario in `tests/cluster/run.sh` (`4360c20`), written before the wiring,
      so it is the definition of done rather than a lap of honour
- [x] `docs/vxlan.md`, `architecture`, `operations`, `networking` corrected (`085c66c`)
- [x] `satld`: attach tasks to overlay networks, program VXLAN, one responder per node
      binding each gateway it holds, container `resolv.conf` on the overlay gateway
      (`45d85f4`)
- [x] The syslog line merge, the daemon frames its own datagrams now (`10b7025`).
      It was losing **more than half** its records under load, not just merging them.

**The DoD scenario passes on the three VMs** (2026-08-11): two services pinned to
different nodes, `fetch` by service name working in both directions, MTU proven at the
DF boundary (1422 passes, 1423 refused), teardown leaving no interface behind. 61s.

**M3 is not closed**, because that run needed a manual intervention and two real defects
came out of it:

- [x] **Node status is published by level, not by edge** (`9a85d2f`). My first reading,
      that the leader's co-located socket was the cause, was wrong. `mark_unknown` on
      leadership gain walks the store writing `Unknown` over every `Ready` node, a pass of
      tens of milliseconds, and *any* agent registering inside it is read back and
      overwritten; the local socket merely loses that race every time. Two of three nodes
      were clobbered. Because `satl-sched` filters on `status.state == Ready`, nothing
      could be scheduled on them at all.
- [x] **`ocijail list -f json` prints `null`, not `[]`, for an empty state db** (`9a85d2f`)
- [x] **A node that cannot host overlays failed every task, including bridge-only ones**
      (`9a85d2f`). Overlay identity was demanded before looking at what the task attaches
      to; on a host whose underlay carries a /32 no blackhole can be derived, so identity
      adoption degrades to none and then everything failed at `start`. **This broke
      `make integration` in `45d85f4`, which I committed without running it**, the rule
      in CLAUDE.md is to run it for networking changes, and it exists for this.
- [x] **`cleanup`: a task's rootfs was abandoned.** Root cause measured, and it is not a
      timing constant: a VNET prison whose container held an **open TCP connection** stays
      `DYING` for 2 x `net.inet.tcp.msl` while its stack drains, and its `pr_root` keeps
      the dataset mounted. `fstat`, `procstat` and the process table show nothing;
      `jls -d` is the only observer. So the wait is keyed on the prison disappearing, and
      exhausting it defers to a periodic node sweep instead of abandoning. Overlay tasks
      were hit because they are the first that talk **to each other** over TCP, the
      single-node nginx test never could.
- [x] **DNS resolution is scoped to the querying task's networks** (`c0f77c2`), closing the
      NXDOMAIN gap. Scope came from the socket; it now comes from the task. Endpoints stay
      cluster-wide but scopes are local-only, so a source this node does not host resolves
      nothing rather than being answered from a neighbour's view.
- [x] **Two overlay networks on one jail erased each other's ARP entries** (`c0f77c2`).
      One epair per network but a single VNET, so each network's pass saw the others'
      entries as unwanted: a permanent `arp +1 -1` every resync, the loser dead on the
      wire while its FDB entry *and* its DNS answer were both correct. Only a two-network
      scenario could reach it.
- [x] **Ingress-lite port publishing** (`01f6d41`). The allocator was assigning ingress
      ports correctly and the node was discarding them: `Ingress` is the **default** and
      its doc comment promised reachability, so `--publish 8080:80` was accepted,
      allocated, documented as working, and published nowhere. No cluster scenario
      asserted a published port, which is why it survived three milestones. The full
      routing mesh stays M6, and the gap is now **a failing assertion away** rather than a
      sentence in a document: a node with no task of the service must not answer.

**Full suite green on the VMs (2026-08-12):** `init_and_join`, `replicas_spread`,
`node_kill`, `leader_kill`, `overlay_dns`, `overlay_dns_multinet`, `publish_port`,
`cleanup` -- eight scenarios, four consecutive runs. Six deferrals,
six reclaims, zero orphans; leftovers audit clean on all three nodes.

## M4, Desired state, rolling updates, global services

DoD: rolling update of a 6-replica service across 3 nodes with zero failed requests
under load; broken image triggers automatic rollback.

Wave 0 (first, by decision 2026-08-12), the debts carried from M2, closed before any
new feature, because they are the kind that bites hardest latest:

- [x] **Certificate renewal applies live** (`27bd6ed`): resolver seams on both sides
      (`ResolvesServerCert`/`ResolvesClientCert`), one swappable `LiveIdentity` per
      daemon, trust anchors riding the same swap. Proven on the VMs with 5-minute
      certificates: three renewal cycles, zero restarts, writes committing past original
      expiry, `tcpdrop`-forced reconnects re-established in ~250 ms over renewed certs,
      plus the negative proof, whose failure signature is in `docs/operations.md`.
      **TLS 1.3 session resumption is disabled on internal clients**: a resumed session
      re-attaches the original identities and re-verifies nothing, which would also let
      a pre-promotion role survive reconnects (SwarmKit is safe only because Go's
      crypto/tls has no client session cache by default).
- [x] **A killed leader converges to `Down` and its tasks are evicted** (`da3e861`).
      SWK §13.2: on leadership change the new dispatcher owes every non-`Down` node of
      the **store** a registration expectation, not only nodes it held sessions for.
      Grace derived, not invented: TTL x the existing doubled-grace factor = 30 s,
      against re-registrations measured at 2.9-7.5 s. Expiry rides the ordinary
      `mark_down` into the existing eviction; no second path. `leader_kill` now asserts
      Down + eviction + stray reaping instead of the "no longer Ready" workaround.
- [x] **A worker-role join works** (`03f926d`), closing the last M2 debt. No Raft, no
      store, no listeners of its own; durable state = cert + task DB + `managers.json`.
      Cluster-scoped REST answers moby's exact worker refusal as a 503; local container
      reads are served from the worker's records (api-compat 79-86). **Promotion and
      demotion apply live**, ~700 ms / ~100 ms at a constant pid, containers untouched.
      The channel is the *session*, never the store: a demoted node leaves Raft before
      the role flips, so its store copy can never see the flip. A daemon restarted
      mid-promotion resumes the join and never self-initialises, the one path that
      could have minted a divergent cluster. `worker_join` is the ninth scenario;
      two full suite runs green.

**Wave 0 closed 2026-08-12.** All three M2 debts are gone; the milestone proper starts.

Then the milestone proper:

**The M4 DoD is met** (`7e57984`, 2026-08-12): six replicas over three nodes updated
under load with **zero requests lost**, and a broken image rolling itself back
automatically. Ten cluster scenarios green, twice.

The live measurement had to be rebuilt, and that is the part worth remembering. Capping
the *percentage* of failed requests makes the verdict a function of how fast the
generator happens to send, one stale redirect read as 2.7% over 52 seconds and 16% over
ten. It now asserts three properties of the daemon instead: no window of failing requests
outlives one port-reconciliation pass; no more windows than there were task stops (one
stop can strand at most one redirect, so the stop count is the ceiling); and the
generator's own sampling gap stays under that window, the honesty check, because a
measurement that stalls as long as the outage it hunts cannot see it, and "nothing
failed" from a generator that sent nothing is the emptiest possible pass.

- [x] Dirtiness rules over `Service.spec_version` (`4116ab6` pins the contract; `a0acfc7`
      implements the check), the fast path is for **clean only**, and reading it the
      other way round would mark every pre-existing task dirty
- [x] HEALTHCHECK via `ocijail exec`, health-gated `RUNNING` (`6671a72`). A task with a
      healthcheck stays `STARTING` until a probe passes, which the DNS responder and the
      rolling updater both inherit for free, that gate is what makes "zero failed
      requests" reachable at all. Update promotion still to be demonstrated live.
- [x] Rolling updater: parallelism, delay, failure action, monitor window, max failure ratio, stop-first/start-first, and rollback with pause-on-failed-rollback (`7e57984`). The monitor window keys on `status.applied_at`, never the agent step timestamp: with health-gated starts the gap between "step began" and "observed RUNNING" is a real duration, and a window opened there would be spent before the task ever ran
- [x] Restart supervisor: conditions, max-attempts window, delayed starts, and a budget that survives an election (`fb5190a`) -- no replay step: the in-memory attempt map is gone and the budget is derived from the store on every pass, which is SwarmKit's taskinit reconstruction applied continuously instead of once. Sound because the reaper prunes history to `max_attempts + 1`, exactly the count at which the budget is spent, so pruning can never hand it back. Left named rather than approximated: the delay queue has no store representation, so a start interrupted mid-delay takes a fresh delay instead of the remainder
- [x] Global services and node drain/pause (`fb5190a`), proven live on three nodes (`bde81ef`). One task per eligible node, preassigned with the node id standing in for the slot; occupancy asks whether the node holds a task the cluster still *wants* there, which is what stops the global loop and the restart supervisor from both filling one node. A drain sets SHUTDOWN unconditionally and forces the restart delay to zero -- an operator draining a node is waiting on it -- while a label change does not, because that is nobody waiting
- [x] Constraint enforcer (`fb5190a`), proven live on three nodes (`bde81ef`). A new pure predicate feeding a third trigger through the existing eviction transaction, reusing the updater's own `node_satisfies` so the two can never disagree, and gated on a node write having actually moved its labels or availability. Eviction is SHUTDOWN + replacement rather than SwarmKit's observed REJECTED, because a rejection counts as a task *failure* and would spend a rolling update's failure budget over an operator's label edit

## M5, Secrets, configs, compose, hardening

DoD: realistic compose stack (web + Redis + worker) across the cluster with a secret;
live CA rotation without downtime; documented manager state backup/restore.

- [x] `satl secret/config create`, encrypted at rest, tmpfs-only delivery, proven by searching every filesystem on the node for the payload while the task runs and finding it only in the tmpfs (api-compat 97-103, 107-109). Uncommitted on `m5-secrets`
- [x] Dispatcher dependency shipping (reference-counted secrets/configs), shipped since M2, consumed since M5
- [x] `satl compose up/down/ps/config` (Compose Spec subset), **stack** semantics, not
      `docker compose` semantics, because SatL has no standalone container; refuse rather
      than half-deploy (forty-odd keys rejected before anything is created, naming file,
      service, key and reason); `down` scoped by a label `up` stamps, so an object with the
      right name but no label is refused rather than adopted (api-compat 110-124).
      **Evidenced** (`209b153`): two full-suite runs, seventeen scenarios each,
      `compose_stack` at 109s and 107s. The DoD stack is nginx + redis + a redis-cli
      worker on one overlay across three nodes, and the secret assertion cannot pass by
      accident: redis's baked config ends with `include /run/secrets/redis.conf`, so it
      **cannot start without the secret**, and the check is one round trip from the
      worker's jail on another node, unauthenticated PING answers NOAUTH, authenticated
      answers PONG. "Redis is Running" would have passed with the secret ignored.
      The YAML crate was picked by measurement: the successor fork of `serde_yaml`
      **silently drops `<<: *anchor` merge keys** into a struct and takes last-wins on a
      duplicate `services.web`, either of which deploys something other than the file
      says. Also `restart: no` parses as `false` without `strict_booleans`, YAML's Norway
      problem on the commonest value in a compose file.
- [x] Health-to-pool loop tightened (`c5ed75d`), see the M6 section for why this came
      before the routing mesh. 5s interval and 2 retries where a service publishes a port
      and left them unset; **measured 9.967s and 9.971s** from probe failure to the address
      leaving the `satl/rdr` anchor, against ~90s before. The timeout is 3s for a reason
      worth keeping: the prober is *sequential*, so an oversized timeout does not overlap
      probes, it silently stretches the verdict to `retries x (interval + timeout)`, a
      hanging probe at 5s/30s/2 decides in **seventy** seconds, not ten, with nothing in
      the config looking wrong. `satl run -p` is deliberately not warned: the container
      create path reads no healthcheck at all, so there is no way to comply, and a warning
      on the commonest one-node command is how a real warning gets ignored (api-compat
      125-128).
- [x] `satl ca rotate` (cross-signed intermediate flow) + automatic renewal
      hardening. Rotation state lives on the Cluster object as a level-triggered
      leader reconciler that resumes across elections; leaves carry a
      cross-signed intermediate against a transitional two-root bundle; per-node
      marks drive live re-issue through the existing renewal loops; both tokens
      are regenerated because their digest pins the whole bundle. Docker surface
      is `CAConfig.ForceRotate` / `RootRotationInProgress`.
      **Evidenced** (`eb17318`, 2026-08-13): two consecutive full-suite runs,
      sixteen scenarios each, `ca_rotate` at 116s and 120s, **0 of 339 requests
      lost** across the rotation with unchanged pids, not a bare claim.
      An earlier entry here asserted the same thing before any run supported it.
      That sentence was written into the tree by the implementing agent against
      instructions, and I committed it in `2ffb1f4` without reading the diff,
      while the only suite evidence on disk showed the scenario failing. The
      lesson is the cheap one: the status file is only worth what its last
      reviewer actually read.

- [x] `satl system prune`, layer GC (`b47461c`), the claim set is the union of image
      records, ZFS clone origins and applies in flight, closed **upward** through the
      clone graph, with two agreeing passes and `zfs destroy -r` never `-R` (that refusal
      is the safety net `-R` disables). **Measured: 15,179,776 bytes freed**, in two
      invocations, because task *history* names the image and the reaper had to prune it
      first. Answers the M4 open question: prune is what reclaims an exited container's
      jail, epair and dataset.
      The tmpfs leak turned out to be **ours**: `reset.sh` enumerated mounts with plain
      `mount`, could not see the `MNT_IGNORE` ones, and force-unmounted the rootfs
      *datasets*, stranding the children on a filesystem that no longer existed. Our
      cleanup script made the leak it then could not see. 54/54/56 stale mounts, now 0.
- [x] `docs/operations.md`: backup/restore validated, not invented (`dd9a6b0`), 423 lines
      containing only what was measured on three machines. Rejoin beats restore while
      quorum holds (**6s** end to end, no backup needed); `zfs snapshot` of the `raft/`
      dataset is the way to take a copy, and a live `cp` is documented as the option to
      avoid even though it worked 3/3, a deliberately torn copy also started and ran,
      which is the real lesson.
      **The policy is "three managers *and* back up at least two"**, not "three
      managers": losing two of three leaves the survivor unrecoverable from inside,
      writes hang by design, `node ls` still shows three Ready with itself Leader, no
      replacement can join, `ForceNewCluster` is 501, and even `service satld stop` hangs.
      Only restoring a second manager's raft directory brings quorum back.

## M6, Backlog (plan `plan-m6.md` complete 2026-08-14; data-plane encryption 2026-08-16)

Full ingress routing mesh · overlay data-plane encryption · `satl build` ·
plugin volumes · Prometheus `/metrics` (surface designed in M0–M2, implemented here) ·
jobs mode · placement preferences · autolock/KEK.

The session plan `plan-m6.md` sequenced seven review-gated items, M6a–M6g:
license and repo hygiene, Prometheus metrics, health-checked pf tables, the
ingress network and routing mesh, an opt-in L4 proxy mode with PROXY protocol,
`satl build`, and hot vertical resize. **All seven are done** (2026-08-13/14).
Of the wider backlog above, data-plane encryption has since landed (below,
2026-08-16), jobs mode, placement preferences and autolock landed in M7
(2026-08-15), and plugin volumes remain unscheduled. What each item found:

- [x] **M6a, license and repo hygiene** (2026-08-13). BSD-2-Clause `LICENSE`
  (FreeBSD's own template), `license`/`authors`/`repository`/`description`/
  `publish = false` in `[workspace.package]` inherited by all 16 crates, an
  SPDX header on every source file (306 files), and a `license-check` make
  target wired into `check`, the only gate, since there is no CI. CLAUDE.md's
  false "CI enforces" claim corrected. Deviation from the plan: `.proto`
  files got `//` headers, not `#`, `#` is not a legal protobuf comment and
  would have broken the build.
- [x] **M6b, Prometheus metrics** (2026-08-13). New crate `satl-metrics`
  (prometheus-client): registry, typed families, text encoder and a separate
  axum `/metrics` listener, off by default behind `metrics_addr` /
  `--metrics-addr` (dockerd's posture, unauthenticated included). Split
  namespace: Docker's exact names where dockerd defines them
  (`engine_daemon_*`, `http_requests_total`), `satl_*` otherwise, recorded in
  `docs/api-compat.md` #140-142, `docs/architecture.md` §16 amended. Raft,
  store counts, reconcile passes, dispatcher sessions, certificate expiry,
  external-command failures counted in all five runners, health checks counted
  at the probe, and per-task rctl usage (`rctl -hu`, new read capability with
  a real captured fixture) on the 20 s collector cadence, absent when racct
  is off.
- [x] **M6c, pf tables: the health-checked pool** (2026-08-13). The `satl/rdr`
  anchor is now one `table <satl_p<port>_<proto>_<cport>> persist` plus one
  static `rdr … -> <table> … round-robin` per published triple; membership
  moves through `pfctl -T replace` (`PfCtl::replace_table`/`show_table`), and
  `NetworkManager::write_rdr` splits the two: ruleset reloaded only when the
  *set* of triples changes, membership through table replaces, every anchor
  reload followed by a full membership re-push, because the `persist` tables
  come back empty. Level-triggered design, `PORT_REASSERT_EVERY` and the
  two-slot `TaskRedirects` guard unchanged. The empirical question the
  research could not answer is answered and pinned:
  **`pfctl -T replace` leaves established states alone**, a live connection
  held across a membership swap keeps answering from the old member while new
  connections land on the new one (`crates/satld/tests/pf_table.rs`, plus a
  two-server measurement on node1). Second finding, caught by the health-pool
  integration test: **`persist` tables survive an anchor flush *with their
  members***, so `write_rdr` kills a table explicitly (`-T kill`) when its
  triple disappears, without it `-T show` kept reporting a live pool for a
  dead one. The health-to-pool measurement still holds under the new writer:
  9.854s probe-failure-to-pool-drop (bound 39s, `health_pool.rs`). Moving
  `satl/nat`'s source list into a table stays deferred (documented option,
  not a need).
- [x] **M6d, ingress network and the routing mesh** (2026-08-14). Every
  manager answers on an ingress-published port and relays to a healthy task
  over the lazily-created `ingress` overlay (SWK §9.1/§9.3), with a per-pool
  return-path SNAT and an MSS clamp. Measured on the cluster: relay from a
  replica-less node, round-robin across replicas, 40 MB through the relay
  with zero VXLAN fragmentation, ~8 s drop-from-pool after a kill, zero lost
  requests over a rolling update (6612 sampled). The client address is lost
  on relayed connections (Docker's mesh trade; M6e is the opt-in remedy).
  Workers keep the pre-mesh node-local behavior (no store replica to compute
  the pool from). Five latent defects found and fixed by measuring, in the
  decision log: the updater's rollback race, pf statement ordering, the
  dispatcher's ingress event filter, derived bridge MACs, and the
  terminal-task plumbing lifecycle.
- [x] **M6e, L4 proxy mode with PROXY protocol** (2026-08-14). A service
  labeled `satl.publish.proxy_protocol=v2` publishes its TCP ports through
  `satld`'s userspace proxy (`crates/satld/src/proxy.rs`): every manager
  listens on the published port, picks a healthy task from the same set the
  port sweep feeds the pf table, dials it over the overlay, writes a PROXY v2
  header and splices. The port never gets an rdr rule. Measured on the
  cluster: a request through the replica-less node answers with the client's
  real address in nginx's `$proxy_protocol_addr` (a config-mounted nginx.conf
  with `listen 80 proxy_protocol`), and killing a replica leaves every
  request at 200. UDP stays on the pf path; workers proxy their local tasks
  only (the mesh's own carve-out). api-compat #143.
- [x] **M6f, `satl build`** (2026-08-14). New crate `satl-build`: a Satlfile
  (`FROM` a `freebsd-runtime` tag, `PKG`, `ENV`, `LABEL`, `WORKDIR`, `EXPOSE`,
  exec-form `ENTRYPOINT`/`CMD`) is assembled client-side on the node's host,
  base layers applied, `pkg --rootdir`, `ldconfig` hints baked, `schg` flags
  cleared, repacked as a single-layer OCI image and registered in the local
  store through `satl-image` (`register_local`). `satl build` replaces the
  per-image shell scripts; there is no `POST /build` (api-compat #144).
  Verified live: a `freebsd-postgres` image (FROM `freebsd-runtime:15.1` +
  `PKG postgresql17-server`) runs as a single-replica service pinned to one
  node with a node-local ZFS volume; a row written before both an abrupt
  jail crash and a `satld` restart is still there after, and the published
  port answers through the mesh from a replica-less node. Two image-content
  facts the build surfaced, fixed without touching the builder: the minimal
  runtime has no PAM modules at all (so no `sudo`, run stateful services as
  `user: "uid:gid"` and pre-chown the volume), and jails disable SysV IPC by
  default, which PostgreSQL cannot even `initdb` without, hence the
  `satl.jail.*` container labels passing any ocijail jail parameter through
  as an OCI annotation (api-compat #145).
- [x] **M6g, hot vertical resize** (2026-08-14). A service update whose only
  task-spec difference is `Resources` no longer rolls: `dirty.rs` gains a
  resources exemption beside the placement one (and the endpoint guard both
  were missing, a placement-or-resources change that also moved a port was
  called clean), the updater pushes the new values into the live task objects
  (`resize_actions`, the one sanctioned breach of task-spec immutability),
  and the agent's controller re-writes the jail's rctl rules at the next wait
  pass, remove-then-add, because `rctl -a` stacks same-subject rules instead
  of replacing them (measured on 15.1: two `memoryuse:sigkill` rules
  coexisted). The dispatcher's assignment applier now keys on
  (desired state, resources), a resources move with an unchanged desired
  state is the one update that used to be swallowed as "already applied". A
  memory shrink below current usage arms the sigkill rule under the
  watermark: not refused (the manager cannot know node-local usage), but the
  agent logs a loud warning naming the kill that may follow; racct off
  degrades exactly like limits at create. CLI: `service update
  --limit-cpu/--limit-memory/--reserve-cpu/--reserve-memory` (`0` clears).
  api-compat #147. Measured on the cluster against the M6f postgres service:
  512M → 1G → +0.5 CPU → a shrink under the 160M working set (the warning
  fired, naming the exact watermark) → limits cleared, all with the same
  task id serving and `pg_postmaster_start_time()` unmoved; a two-replica
  nginx resize kept both task ids and both nodes answered 200 through the
  mesh. One latent test race surfaced and was hardened along the way:
  `m1_flow` read the published port off a single inspect, but STARTING
  already renders as Docker's "running" while the port only lands with the
  RUNNING harvest, the assertion now polls.
- [x] **M6, overlay data-plane encryption** (2026-08-16, branch
  `m6-encryption`). Docker's `--opt encrypted`: an encrypted overlay network
  wraps its VXLAN datagrams in ESP transport mode (`aes-gcm-16`), programmed
  per node with `setkey` from a per-network keyring. The ring lives on the
  `Network` object in the encrypted raft store and ships to **participant
  nodes only**, inside dispatcher network assignments, which is why the
  ingress network can never be encrypted (its assignment is broadcast to
  every node; refused at create). The leader rotates each ring every 12 h
  (append → promote → prune, 60 s settle between phases, every decision
  re-derived from store state); the `keyring_rotate_after_secs` /
  `keyring_phase_settle_secs` satld.toml knobs exist for tests and warn
  loudly when set. Every design input was measured first
  (`hack/experiments/esp/`, decision log below) and the full fact sheet is
  `docs/vxlan.md` §10: ESP expansion 34 bytes → encrypted MTU **1416**;
  per-network VTEP ports **4790..=4999** because the SPD matches neither the
  VNI nor the hashed outer source port; the pf **`satl/guard`** anchor
  (enc0 + `no state` + `net.enc.in.ipsec_filter_mask=2`) because an inbound
  `require` SP does not drop cleartext on 15.1; rotation ordered
  adds-before-deletes because the old SA's deletion is the promoting step.
  Verified live on the 3-node cluster, all six scenarios: ESP-only wire,
  MTU 1416, guard blocking cleartext, rotation with loss held to a blip
  (SPI switch observed, ceiling 6%; the experiment measured 1.2%), full
  teardown. api-compat #63/#72. (The 6% ceiling is the share of pings lost
  across one full rotation in the cluster scenario, `ROT_LOSS_MAX` in
  `tests/cluster/encrypted.sh`, five times the experiment's measured 1.2%.)

## M8, `satl build` as the FreeBSD image tool (complete per `plan-m8.md`, 2026-08-15)

Scoped with Frédéric: make `satl build` the reference tool for building
FreeBSD container images, registry push, multi-layer builds with an
incremental cache, multi-stage, `FROM scratch`. Linux image builds are
explicitly out.

- [x] **M8a, registry push** (2026-08-15). `satl push` (and `satl build
  --push`): blobs the registry lacks (HEAD-checked) then the manifest,
  client-side like the build, credentials from `--username` +
  `--password-stdin`, never stored. Verified on the cluster: a built image
  pushed to the loopback registry, visible in its catalog, and pulled back
  by digest. api-compat #152. Audit follow-up (N2, 2026-08-17): `satl tag` +
  `POST /images/{name}/tag`, a second reference to the same store entry, so
  pushing to a different registry no longer requires a rebuild (api-compat
  #22).
- [x] **M8b, multi-layer builds with an incremental cache** (2026-08-15).
  The image is now the base's layers plus one layer per mutating step (PKG
  group, each COPY, each RUN), diffed from the rootfs between steps with OCI
  whiteouts for deletions; each step is content-addressed in
  `/var/db/satl/build-cache/` (key = parent chain ID + step inputs), so a
  rebuild with no moved input executes nothing. A hit still applies the
  cached layer to the rootfs with its diff ID verified, a corrupt blob is
  an error, never a poisoned image. `--no-cache` / `--cache-dir`. The layer
  writer is the `tar` crate rather than bsdtar, because bsdtar's pax output
  embeds atime/ctime and identical content must pack to identical bytes.
- [x] **M8c, `FROM scratch` and multi-stage builds** (2026-08-15). Several
  `FROM` lines define stages (`AS <name>`, or an index); every stage builds
  fully and only the last is repacked. `COPY --from=<stage>` reads an
  earlier stage's finished rootfs with the same escape guards as the
  context, is cache-keyed on the copied content (a changed builder output
  invalidates the final stage), and `COPY --from=<image>` is refused
  plainly, name or index a stage. `FROM scratch` chains off the empty
  base. Verified on the cluster: a two-stage build whose final image prints
  the builder's output, and a scratch image with exactly its step layers.
  The E2E also flushed out a pre-existing log-capture race for containers
  that exit within milliseconds (decision log).
- [x] **M8d, the full showcase** (2026-08-15). A C hello-world compiled
  with the `freebsd-toolchain` image in a builder stage, run from a
  `FROM scratch` final stage: the produced image is **1.4 MB** (the static
  binary alone) and prints from a plain service on the cluster. Along the
  way the whole M8 toolchain is proven together: incremental rebuild at 7 s
  against 51 s cold, selective invalidation, multi-layer manifests, push to
  a registry and pull back by digest.

## M9, CLI parity and a generated API contract (2026-08-19)

Started because there was no way to delete an image. `satl system prune` was the
only reclamation and it is all-or-nothing, node-global, and takes containers and
networks with it; `DELETE /images/{name}` answered 404 by design, so a Docker
client could not do it either.

The audit that followed found the omission was not isolated: **five capabilities
the daemon has served since M1-M2 had no CLI client at all**, `GET /events`
first among them, which means an operator had no way to watch a cluster work.
The lesson worth keeping is in the decision log: an endpoint with no verb has no
user, and nothing exercises it end to end.

### M9a, the missing verbs

- [x] `satl images` becomes a noun (`ls`, `rm`, `prune`, `inspect`), bare
      `satl images` unchanged; `satl rmi` as the top-level alias (api-compat 154)
- [x] `DELETE /images/{name}?force=&noprune=`, running the same two-pass layer
      sweep the prune runs, with the deferral on `X-Satl-Deferred-Layers`
      (api-compat 155, 156, 157)
- [x] Removal by image ID, recognised before the reference parser, and the
      multi-repository refusal (api-compat 158, 159)
- [x] `GET /images/{name}/json` + `satl images inspect`, aggregated by image ID
      (api-compat 160)
- [x] One place decides "is this image in use", shared by the removal and the
      prune (api-compat 161), and it fixed a real defect on the way, see below
- [x] `satl events`, `satl info`, `satl volume inspect`, `satl node ps`
      (api-compat 162, 164, 165)
- [x] `satl images prune`, `satl container prune`, `satl network prune`,
      `satl volume prune`, superseding the "one prune verb" statement
      (api-compat 163)

### M9b, a generated API contract

- [ ] `docs/openapi.yaml` generated from the handlers, drift gated by
      `make check`; `docs/api.html` rendering it offline (api-compat 166)

## M7, Swarm parity and the app story (per `plan-m7.md`, 2026-08-15)

Scoped with Frédéric: placement preferences, jobs mode, autolock/KEK, real
image timestamps, `satl stack`, a Satlfile that can build an application
image, and a full Node.js + MariaDB tutorial. Volume drivers are out.

- [x] **M7a, real image timestamps** (2026-08-15). The image config's
  `created` is parsed at pull (`satl-image`), written by `satl build` since
  M6f, and rendered by `/images/json`, the "56 years ago" column is dead.
  A store entry whose config predates the field simply lists 0. api-compat
  #15 amended.
- [x] **M7b, Satlfile `COPY` and `RUN`** (2026-08-15). The build context is
  the Satlfile's own directory (no positional `PATH`): sources are
  context-relative, `..`/absolute/symlink escapes refused, a directory source
  copies its contents. `RUN` is `/bin/sh -c` in a chroot of the assembled
  rootfs, with the Satlfile's `ENV`/`WORKDIR` and the host's `resolv.conf`
  when the image has none, on the build host's kernel, so build on the
  FreeBSD major you deploy. All `PKG` steps run before the first `COPY`/`RUN`
  (a package must exist before a step can use it); the rest run in file
  order. Verified live: a Node.js image built per node from `COPY app/` +
  `RUN node --check` + a RUN that writes a file, served by 3 replicas through
  the mesh with the built-in file's content. api-compat #144 amended.
- [x] **M7c, `satl stack`** (2026-08-15). Docker's stack verbs on the compose
  machinery: `deploy`/`rm`/`config` delegate to `compose up`/`down`/`config`
  (the stack name is the project name), `ls`/`services`/`ps` read the
  `com.docker.compose.project` label off the services, no server-side stack
  object, no new API surface. `--prune` defaults true, as Docker's.
  api-compat #148.
- [x] **M7d, placement preferences** (2026-08-15). `spread=<descriptor>` on
  `Placement.Preferences` (Docker's only strategy, SatL's only one too):
  validated at the API (`node.id`, `node.hostname`, `node.labels.*`,
  `engine.labels.*`, anything else is a 400 rather than a silent no-op),
  ranked in the scheduler after the fault penalty and before the per-service
  spread: the node whose descriptor-value group holds fewer of the service's
  tasks wins. Nodes missing the label form one empty-value group. CLI
  `--placement-pref` (create) / `--placement-pref-add|-rm` (update), compose
  `deploy.placement.preferences`. api-compat #50 amended, #149. The E2E
  caught what the unit test then pinned: a batch must re-rank after each
  placement, a task placed in one group makes its whole group worse, which
  an order computed before the batch cannot see (2 replicas over 2 zones
  landed in the same one), and the candidate list must not be truncated to
  the group size (the better group may sit beyond it).
- [x] **M7e, jobs mode** (2026-08-15). `ReplicatedJob` and `GlobalJob`, run
  to completion: a `Complete` task is a success and is never restarted
  anywhere (the restart supervisor skips job tasks), a failed one is retried
  in its slot within the `max_attempts` budget, and a spec update re-runs the
  job (no rolling, no `update_status`). The jobs loop
  (`satl-orchestrator/src/jobs.rs`) is level-triggered like its siblings and
  reuses the supervisor's budget derivation and the global loop's node
  eligibility. Gaps, stated: retries are immediate (no delay queue),
  `Restart.Window` is not honoured, `JobIteration` is not rendered
  (`spec_version` plays that role). Verified on the cluster: a 2-completion
  replicated job ends 2/2 and goes quiet, a failing job retries in place, a
  global job runs once per node (3/3), an update re-runs every slot, and the
  completions counter counts only the current spec's run (the first build
  reported 4/2 after a re-run). api-compat #50 amended, #150.
- [x] **M7f, manager autolock / KEK** (2026-08-15). `swarm init --autolock` /
  `swarm update --autolock=` seals every manager's raft DEK under a cluster
  unlock key (32 random bytes, base64, printed once) and removes the plain
  file; the key lives only in the DEK-encrypted store, Docker's circular
  construction. A locked manager serves only `/_ping` and `POST
  /swarm/unlock` (503 on everything else) until the key arrives; `swarm
  unlock-key [--rotate]` prints/replaces it and a per-manager watcher
  (`satld/src/autolock.rs`, level-triggered on Cluster events) keeps the key
  files reconciled with the store. The DEK never touches disk in clear on a
  locked manager. api-compat #42/#44 amended, #151.
- [x] **M7g, the Node.js + MariaDB tutorial** (2026-08-15). A full
  guestbook walkthrough on the doc site (`start/app-node-mariadb.md`), every
  step run on the test cluster: both images built with `satl build` (COPY +
  RUN, npm install in the chroot), secrets, a pinned database on a node-local
  volume, a spread preference, healthchecks, `satl stack deploy`, the mesh
  round-robin from every node, a zero-loss rolling update, a hot resize, and
  a `jail -r` crash with the data intact. What it surfaced: a SatL jail's
  `lo0` has only `::1`, Docker-style `localhost` probes cannot connect
  (healthchecks.md now shows the epair-IP probe, pure shell because the
  runtime image has no `awk`); mariadbd lives in `/usr/local/libexec` and
  reads `--init-file` after dropping privileges; and a transient task
  rejection poisons every later resume of the same update (see the decision
  log).

### The routing mesh needs the health loop closed first (Frédéric, 2026-08-13)

**Ordering decision: do not build the mesh before the health-to-pool loop is
closed and its window measured.** The mesh would enlarge an existing hole
rather than sit beside it.

`pf` does not health-check a `rdr` pool, by design, it is a packet filter, not
a load balancer, and a `round-robin` pool distributes connections without ever
probing a target. So a container that stops answering on its port keeps
receiving its share of the traffic. What saves this today is one layer up: an
unhealthy task is stopped and reported `FAILED`, it leaves the live set, and the
level-triggered port reconciler rewrites the whole anchor without it within
`PORT_SWEEP_INTERVAL` (5s). The filter stays dumb and the control plane rewrites
its rule, which is the right split.

**That only holds when the service declares a healthcheck**, and this is the
other half of a gap already recorded above. The M4 note says a task is
*published before it serves*, measured at 5 ms after jail start while nginx
needed 250 ms to bind. Frédéric's observation is the same hole in the other
direction: without a probe it stays published *after* it stops serving, because
`RUNNING` then means only "the jail is up". A container can be a black hole on
port 80 while its jail is perfectly healthy.

Consequences, in the order they should be acted on:

1. **Close the loop before extending the pool.** Today a node with no task of the
   service does not answer at all, which is at least honest. A mesh node would
   answer and promise to route to a task whose health it does not verify,
   strictly worse than refusing the connection.
2. **A healthcheck becomes a de facto prerequisite for a published service.** At
   minimum a loud warning at service create; a refusal is worth arguing.
3. **The defaults are wrong for this use.** 30s interval x 3 retries is ~90s to
   detect, plus up to 5s of reconciliation, about a minute and a half of
   traffic into a dead backend. Those are Docker's defaults, but Docker has IPVS
   in front of the pool where here the `pf` pool is the only thing between the
   client and the task. Something like 5s x 2 gives ~10s. Tune for the
   published-port case specifically rather than globally.

**Decided (Frédéric, 2026-08-13): the simple version now, the decoupling in M6.**

Researched and settled first: **Docker Swarm's mesh has the same architecture.**
IPVS does not probe backends either, orchestration removes the unhealthy task
and the load-balancer rules follow. SatL is therefore not architecturally behind
Docker Swarm here; the whole gap is detection *latency*, which is a matter of
numbers rather than of missing machinery. Two alternatives were surveyed and set
aside for now: `relayd` (packaged as `relayd-7.4`, the native BSD daemon that
health-checks host groups and programs `rdr-to` rules itself) and a real proxy in
front (`haproxy-3.4`, `nginx-1.30`), which is what production Docker Swarm users
generally do anyway and which also recovers the client address the mesh's NAT
destroys. Both need a correct target list, and that list comes from the same
health loop, so closing the loop is a prerequisite either way, not an
alternative to them.

*The simple version*, being built now: tighter probe defaults where they are
earned (a service that publishes a port and left the values unset), a coherent
timeout shorter than the interval, it currently defaults to 30s against a 5s
interval, which cannot work, and a loud warning when a published service has no
healthcheck at all. Target ~10s detection instead of ~90s.

*The cost, accepted deliberately and to be documented rather than hidden*: in
SatL, "drop from the pool" and "kill and replace" are the **same event**, an
unhealthy task is stopped and `FAILED` (api-compat 88), where Docker leaves the
container running and merely removes it from the balancer. So tightening
detection ninefold makes replacement ninefold more eager too, and a long GC pause
or a blipping dependency can produce a restart storm where the operator only
wanted traffic to stop. `retries` is what separates sustained failure from a
blip, and M4's restart budget bounds the loop.

*The decoupling is M6*: an unhealthy task that stays **running** but leaves the
pool, replaced only on prolonged failure. That is Docker's model, it removes the
restart-storm risk, and it lets an operator inspect a sick container instead of
watching it vanish. It needs a task state the machine does not have today, and it
retires api-compat 88.

Design sketch for the mesh itself, unvalidated: extend the existing pool from
node-local task addresses to the overlay addresses of tasks on other nodes,
reusing the M3 data plane, with source NAT so replies return through the
ingress node. Costs to state plainly rather than discover: the client address is
lost to the NAT (Docker's mesh has the same defect, which is why a real load
balancer usually sits in front), a node must only redirect to a node holding a
*local* task or two relays can loop, and forwarded traffic now pays the overlay
MTU. **Before committing to it, measure whether `rdr` to a remote address plus a
return-path `nat` actually behaves as reasoned**, a throwaway two-node
experiment in `hack/experiments/`, because this milestone has already had six
written claims overturned by measurement, two of them mine.

## M10, field fixes and man pages (2026-08-23)

Found during the documentation-validation run of 2026-08-23 against the fresh
test VMs: a batch of small user-visible defects that only surface when the
documented commands are actually executed against a live cluster, plus the
still-missing man pages and packaging polish. Each item is a fix an operator
would otherwise hit in the first hour.

- [x] `satl ps` PLATFORM column: `resolved_platform` now looks the pulled image up by its canonical reference via the new `satl_image::canonical_key`, the one home of the reference-key rule (see the decision log)
- [x] `satl run` rollback + wait parity: the wait body's `Error` now means "terminated without an exit code", and on that signal the foreground CLI removes the anonymous service it created (api-compat 167)
- [x] Live linuxulator re-probe: the probe result now lives in one shared `LinuxEmulation` handle, re-probed every 10 s by a third node sweep; the existing 20 s description refresh carries the flip to the cluster (see the decision log)
- [x] Man pages: satl(1), satld(8), satld.toml(5), hand-written mdoc pinned to the code by three drift tests, linted by `mandoc -T lint` in `make check` (see the decision log); packaging ships them in the next item
- [x] Packaging: license dir, man pages, post-install message, sample keys (see the decision log)
- [x] Cluster inventory refresh: the reinstalled VMs kept their hostnames and underlay addresses, only the public addresses changed (verified live 2026-08-23)
- [x] `satl run` double execution: the updater's abandoned-slot fill now consults the deep dirtiness the dirty module already computes, so a completed one-shot task whose spec matches the current service spec is converged, not refilled (see the decision log)
- [x] `satl run` node pinning: the anonymous service carries a `node.id==<receiving node>` constraint, restoring `docker run`'s "runs on the engine you spoke to" semantics (api-compat 168, see the decision log)

DoD verification, all on 2026-08-23: `make check` green on every commit; `sudo make integration` green end to end (71 suites; it now requires the production satld stopped, which `health_pool` enforces with an explicit message); `make cluster-test` 23/23 scenarios on the reinstalled `fbsd{1,2,3}.satl.cc` testbed; the package installed with `pkg add -f` on the dev host and all three VMs, running containers re-adopted with their jail ids unchanged; the three bug fixes exercised live (PLATFORM column on an informally spelled image, a rejected run leaving nothing behind, `satl run false` exiting 1, and a `kldload`-then-run without a daemon restart).


---

## M11, the two worlds (2026-08-24)

Docker has two worlds: `docker compose` runs containers on one host, `docker
stack deploy` runs services on a swarm. Since M5 SatL had only the second, under
both names — `satl stack deploy` delegated to `satl compose up`, which carried
stack semantics, recorded as api-compat 110 and stated in the doc site.

That was an over-reading. "SatL has no standalone container" is invariant #2,
and invariant #2 constrains the **execution model**, not the **scope**: Docker's
two worlds differ in where things run and what the file may say, not in whether
an orchestrator is involved. So SatL can have both worlds while every container
stays a Task of a Service in the Raft store, and invariants #1, #2 and #8 are
untouched.

The precedent was one day old: M10's last fix pins `satl run` to the receiving
node with `node.id==<self>` (api-compat 168) to restore `docker run`'s "runs on
the engine you spoke to". M11 applies the same idea to a whole compose file.

Two facts make the node-local half natural rather than bolted on. The CLI speaks
`unix://` **only**, so the client's filesystem *is* the target node's filesystem
— which is precisely the reason relative binds were refused, and it evaporates.
And the agent uses a locally present image before considering a pull
(`resolve_image`), so a `build:` will need no registry.

Ships as **0.2.0** (`-alpha` on the git tag only: a hyphen in a `pkg(8)` version
is read as the name/version separator, CHANGELOG's own rule).

- [x] **M11a, the split** (2026-08-24). A `Scope { Local { node_id }, Cluster }`
      threaded through the compose planner, which was already a pure function of
      the file's text. `satl compose` pins every service to the node `GET /info`
      names, publishes in host mode, names objects `<project>-<service>` with
      compose v2's hyphen, honours a relative bind against the project
      directory, honours `driver: bridge` as a single-node overlay with a loud
      warning, and refuses `deploy.placement`, an explicit `mode: ingress`, and
      replicas above 1 sharing a fixed host port. `satl stack` passes
      `Scope::Cluster` and is unchanged. api-compat 110 and 112 rewritten,
      169–174 added. **The regression guard is that every compose unit test
      written before the split still passes untouched under `Scope::Cluster`**,
      so `satl stack`'s output is pinned byte for byte; eight new tests cover the
      local world, each asserting both halves of the same file.
- [x] **M11b, DNS on the node bridge** (2026-08-24). The live verification of
      M11a found that the overlay choice was wrong, and measured why: alpha's
      address is a public **/32**, satld cannot derive a VXLAN blackhole from
      it and degrades to hosting no overlay at all (`cannot measure this node's
      underlay ... bridge networks are unaffected`), so a node-local compose on
      an overlay was dead on exactly the host shape it exists for. Proven
      independent of M11a by deploying the same file through the untouched
      `satl stack deploy`, which failed identically. But bridge was no better
      as it stood: a bridge task got a copy of the host's `/etc/resolv.conf`
      and `nslookup <service>` answered NXDOMAIN. So the responder now serves
      bridge networks: the bind list gains the node bridge's gateway without
      requiring an overlay identity, `resolv_conf` walks the task's attachments
      and hands a bridge one that gateway, and the records and query scopes are
      built from the node's own IPAM (`NetworkManager::address_of`) because
      Raft never sees a bridge address (architecture §11.1) — which loses
      nothing, since every task on a node-local bridge is local by
      construction. `apply_network` now refreshes DNS on the bridge path too;
      without that a node hosting only bridge networks never bound a socket at
      all. Compose then switched to `driver: bridge`, so `satl network ls`
      reports `bridge`/`local` as Docker does, and api-compat 170 was rewritten
      around what is now true. Isolation is the documented cost (175): one
      bridge per node means two projects share an L2, and only the *names* are
      scoped.
M11a+M11b DoD verification, all on 2026-08-24: `make check` green on every
commit; `sudo make integration` green end to end; the package installed with
`pkg add -f` on the dev host and the daemon restarted, re-adopting all three
running jails at their existing jids. Live on alpha, which is the /32 host the
milestone turned on: both services `Running`, `satl network ls` showing
`bridge`/`local`, `resolv.conf` reading `nameserver 10.88.0.1`, the compose
alias `cache` resolving to 10.88.0.6 and `web` to 10.88.0.4 in the other
direction, ping between them at 0% loss, and `down` leaving nothing.

`make cluster-test` **24/24** on `fbsd{1,2,3}.satl.cc` after `deploy.sh` put the
new binaries on all three — worth stating because the suite does *not* deploy,
and a first 23/23 run against the previously-deployed build proved nothing about
this change. Two scenario results carry the weight. `overlay_dns_multinet`
passes, which is the guard that matters most for M11b: it was written to catch
DNS *scoping* defects, including the over-widening fix that would let one
network's names leak into another, and that is exactly what feeding a second
driver into the same tables could have broken. And `compose_local` is new,
running on the three-node cluster on purpose — on one node "everything landed
here" is true for free — asserting the pin (every task on the control node with
three nodes Ready to have taken them) and then reaching one service from the
other's jail by its bare compose name over the bridge, which fails on a DNS
defect and on a data-path defect alike. `compose_stack` keeps every assertion it
had and now drives them through `satl stack`, since spreading a file over the
cluster is that verb's world now; it passes in 109s, the same as its M5
measurement.

- [x] **M11c, what node-local unlocks** (2026-08-24). `down -v` (there is a node
      to remove from now), `up --scale`, and `compose stop`/`start`/`restart`.
      `stop` and `start` cannot be Docker's, because a task is one-shot and a
      stopped one is a 409 (api-compat 30): `stop` scales the project to 0 and
      `start` scales back to what the file says, so no hidden state is stashed
      in a label — which also means `start` needs the file and `stop` does not,
      an asymmetry the help and the docs both state. `restart` bumps
      `TaskSpec::force_update`, which the dirty module already treats as
      dirtying everything, and lets the rolling updater replace the tasks under
      the service's own policy — a replacement in the slot, which is what
      invariant #2 means by restart. `--scale` is applied *after* the plan is
      built and then re-checked against the planner's own rules, so it cannot
      smuggle in the host-port conflict the file would have been refused for
      (api-compat 174, 178). Verified live: `stop` left both services `0/0` with
      the volume intact, `start` restored `1/1`, `restart` moved the old tasks
      to `Shutdown` and brought new ids up in the same slots, `--scale peer=3`
      reached `3/3`, and `down -v` removed services, network and the
      `m11c-data` volume in that order. api-compat 118 and 124 rewritten, 176-178
      added. `compose_local` grew the three verbs and a named volume, and
      `make cluster-test` is **24/24** with them on the deployed testbed. One
      defect in the new assertion, found by it failing: `cl_live_ids` listed
      *every* task of a service, and `satl service ps` keeps the terminal ones,
      so after a restart the count was four rather than two and the wait could
      never converge. It filters on state now — the same shape `cl_task_nodes`
      already had, which is why the failure was in the new helper and not in the
      verb.
- [x] **M11d, attach and logs** (2026-08-24). `up` attaches by default and `-d`
      regains its meaning; `satl compose logs [--follow] [--tail N] [SERVICE…]`.
      Possible only because logs are node-local (api-compat 81) and every task
      is now on this node, which is the exact obstacle api-compat 124 recorded.
      The multiplexer lives in its own module: one reader task per container
      feeding a channel, lines assembled per stream kind so that two containers
      writing at once cannot splice half a line into another, prefixes padded to
      a common width with one colour each, and colour suppressed when stdout is
      not a terminal. Two decisions worth their entries. **`--follow` is
      long-only** (179): `-f` is already the global `--file` at this level and
      clap refuses a duplicate short outright, where docker's parser resolves it
      by position. And **Ctrl-C detaches rather than stopping** (180), unlike
      `docker compose up`: the project is already deployed by the time attaching
      begins, so stopping it on a keystroke would be a second hidden mutation;
      the banner says so before the first line of output. Verified live: both
      services prefixed and interleaved, a container's stdout on stdout and its
      stderr on stderr through the multiplexer, `--follow` streaming new lines
      from both at once, and a SIGINT to an attached `up` leaving both tasks
      `Running`. `compose_local` gained a logs assertion (both services present,
      each line carrying its `<service>-<slot>` prefix) and `make cluster-test`
      is **24/24** with it. The attach change caught the suite itself first: the
      scenario's own `cl_compose up` never returned, because it did not ask for
      `-d`. That is the best evidence there is that this breaks scripts, and it
      is why the CHANGELOG says so rather than leaving it to release notes.
      `docs/operations.md`'s compose section was rewritten around the two
      worlds; it still described `satl compose up` as `docker stack deploy`.
- [x] **M11e, `build:`** (2026-08-24). `satl compose build [SERVICE…]` and
      `up --build`, images tagged `<project>-<service>:latest` (or `image:` when
      given) and used from the local store with no registry — verified end to
      end on alpha: a `build:`-only service deployed from an image that exists
      on one node and nowhere else, the container printing the file its Satlfile
      `COPY`'d. `build:` stays refused under `satl stack`, and the refusal now
      says where the image must come from instead of "not supported".
      **`build:` builds a `Satlfile`, not a Dockerfile** (`docs/image-sources.md`):
      `dockerfile:` keeps compose's key name because it is the one people type,
      but names which file to read; `args:` and `target:` are refused with the
      reason (a Satlfile has no `ARG`, and a multi-stage build always packs its
      last stage), along with `cache_from`, `ssh`, `secrets`, `platform`,
      `network` and `tags`. A Dockerfile pointed at by `dockerfile:` fails
      naming the file, the line and the unknown verb. Both verbs need root,
      because writing to the image store does.

      Two things the live run found that reading could not. **A rebuild under
      the same tag deployed nothing**: the service spec is byte-identical, so no
      task was dirty and the old image kept running while the new one sat in the
      store. Fixed by stamping `ForceUpdate` from the new manifest digest, the
      same counter `compose restart` bumps. And **the builder is not
      reproducible**: two builds of an unchanged tree give different manifest
      digests (the config carries a `created` timestamp), so the stamp changes
      every time and `--build` always replaces the tasks. The digest-derived
      stamp is kept over a counter anyway, because it follows the image and
      would become idempotent for nothing if the builder ever gained
      reproducible output. api-compat 181-182.

      Not added to `compose_local`: M11e is node-local by definition and alpha
      is a node, so the suite's marginal value is lower than for M11a/M11b,
      which were about placement and DNS *across* nodes. `build_push_run`
      already exercises `satl build` on the testbed.

      **M11e verification, stated exactly.** `make check` green; `compose_stack`
      and `compose_local` both pass on the testbed (109s and 53s), which is what
      covers the compose surface; the build path verified live on alpha as
      above. The **full** suite is red on `ca_rotate`, for the port-publishing
      defect in the decision log — pre-existing, order-dependent, and in code
      M11 does not touch (`git diff` reaches no port path; the one `satl-net`
      edit is two read-only accessors). It is reported rather than worked
      around, and the testbed is left with that scenario failing.
- [x] **The version bump** (2026-08-24). `Cargo.toml` to **0.2.0**, numeric, with
      `-alpha` on the git tag only — a hyphen in a `pkg(8)` version is read as
      the name/version separator (CHANGELOG's own rule). The fourteen internal
      path dependencies pin the workspace version explicitly, so they move with
      it or cargo refuses to resolve; `Cargo.lock` follows.
- [x] **The `satl-doc` sweep** (2026-08-24). `use/compose.md` was rewritten
      around the two scopes — the page that prompted the milestone, whose thesis
      was inverted rather than patched — plus `docker-differences.md`'s "You
      bring a Compose file", `reference/out-of-scope.md`'s `#compose-limits` and
      `#no-build`, `about/status.md`, `about/what-satl-is.md` and
      `use/index.md`. The 32 generated CLI pages were regenerated with
      `make gen` against the 0.2.0 binaries; the doc repo's `make check` gates
      that, and it is green (84 nav entries, 59 pages within the prose caps, no
      drift between the committed pages and the generator).

      One claim needed thought rather than a find-and-replace. `what-satl-is.md`
      said there is "no `docker-compose` on one host and Swarm on three", which
      now reads as a denial of exactly what M11 built. The point underneath it
      survives and is worth keeping: the two verbs differ in *scope*, not in
      what they make — a service, with tasks, in the same store, reconciled by
      the same loops. It says that instead. "There are no standalone containers"
      was left alone everywhere: it is still true (invariant #2), and it is the
      sentence the whole milestone turns on.

Deliberately **not** in M11, and now unblocked should they be wanted: variable
interpolation and `.env` loading (api-compat 114 was a design choice, not a
consequence of cluster scope, and widening it is its own decision), and real
per-project bridge networks (one bridge per network in `satl-net`, DNS lifted
out of `satl-overlay`, `reconcile.rs` dropping its overlay filter, root
integration tests) which would make api-compat 170 unnecessary.

---

## M12, launch readiness (in progress)

What stands between 0.2.0 and showing the project to an audience. The two
cluster defects come first because one of them is what keeps `make cluster-test`
red, and because both were **masked by scenario ordering** -- which is the more
important finding: the suite's green was partly luck, and fixing that is what
makes the next green mean something.

This milestone absorbs `LAUNCH-TODO.md`, the untracked working note written at
`a264fa3`. Its every item is here or already elsewhere: the blockers are Phases
2-4, the credibility fixes Phase 5, the "deliberate gaps" were **already**
documented in `satl-doc` (Phase 6), the launch mechanics are Phase 8, and its
backlog was already tracked -- M9b and plugin volumes in this file, the `stack`
auth flags as api-compat #148. Six of the note's claims turned out to be wrong
or incomplete, three of them in ways that changed the fix; each correction is in
the decision log. The note can be deleted.

### Phase 1: openraft 0.9.25 -> 0.10.0-alpha.34 ✅

The prerequisite for a real leadership handover. 0.9 has no transfer call and no
workaround inside it (decision log), so the demote fix is the upgrade.

- [x] `satl-cluster` migrated: `types` (the type config keeps `AnyError` as its
      `ErrorSource`, everything else takes the macro default), `log_store`
      (storage errors become `io::Error` at the trait boundary; `read_vote`
      moved to `RaftLogReader`; `truncate` became `truncate_after`, which keeps
      the log id it is given instead of deleting from it), `state_machine`
      (`apply` takes an entry-and-responder *stream* and answers through an
      `ApplyResponder` rather than returning a `Vec`; `SnapshotData` moved off
      the type config; `SnapshotMeta` lost `snapshot_id`), `transport`
      (`RaftNetworkV2`, with `full_snapshot` and `transfer_leader`), `node`,
      `store`, `membership`, `server`.
- [x] `Proposal` implements `Display`, which openraft 0.10 requires of `AppData`.
      It names the verb, kind and ID of each action and **never a payload**: a
      proposal can carry a `Secret` (invariant #7).
- [x] `proto/*.proto` moved to `satl.internal.v2`. Non-additive: the chunked
      `InstallSnapshot` is replaced by a streamed `FullSnapshot` (0.10 makes
      fragmentation the transport's job) and `TransferLeader` is new. The bump
      moves *every* service, not only `Raft`, so a v1 node and a v2 node fail to
      find each other's methods rather than agreeing on the dispatcher and the
      CA and then failing deep inside raft (rationale in `proto/common.proto`).
- [x] `RaftNode::shutdown` waits for redb to release the log file. 0.10's
      `Raft::shutdown()` joins only its core task, and `satld` rebuilds the
      manager runtime on every role change (decision log).
- [x] `make check` green; the openraft storage compliance suite still passes.

### Phase 2: `satl node demote <the current leader>` ✅

Measured end to end on the 3-VM testbed: `Manager fbsd1.satl.cc demoted in the
swarm.` in **294 ms**, `leadership handed over` in **14 ms**, and the node reads
`"Role": "worker"` with no manager status from the survivors.

- [x] `yield_leadership` uses `trigger().transfer_leader(target)`, picking the
      most caught-up voter (openraft's request names a `last_log_id` the target
      must already have reached). `LEADERSHIP_TRANSFER_TIMEOUT` 35 s -> 10 s.
- [x] **The role write moved to the leader** (`Departing`, `finish_departure`,
      `LeaveRaftRequest.demote`). It had to: phase 1 takes the node out of
      consensus, so a departing node that tried to write its own role re-read a
      frozen store and lost the optimistic-concurrency check for ever --
      measured, ten seconds of retries against version 25 while the leader was
      at 45 (decision log). The leader holds the store that still moves.
- [x] `a_leader_demotes_itself_under_write_load`, **verified to fail against the
      old implementation**; `demoting_the_leader_also_flips_its_role`, which
      reads the outcome from the *survivors* because a demoted node cannot see
      its own demotion.
- [x] SWK §11.5 re-read: it supports the shape. Deviation recorded in the code
      (most caught-up peer, not SWK's longest-active).
- [x] No new `api-compat.md` entry: `docker node demote` on a leader works and
      now so does SatL's, in 294 ms, so there is no divergence left to number.
      #137 gained a clause instead, for the CLI-side `--force-new-cluster`
      refusal.

### Phase 3: published ports on a demoted node ✅ (reframed; see the decision log)

The note's framing was wrong, and the demote fix is what made it checkable:
a worker publishes what it runs, and relays nothing, which is **api-compat #75**
as written. What was real is that a role change could take up to a minute to
re-derive the anchor, and that an empty pass logged nothing at all.

- [x] `local_tasks` and `claimed_tasks` are fallible, and their three callers
      skip the pass instead of sweeping against an empty claim set. This was
      the worst of it: `run_worker` feeds that set to the jail, mount, dataset
      and epair sweeps, so an unreadable task db at startup made every running
      container on the node an orphan to destroy. Pinned by
      `listing_an_unreadable_db_is_an_error_not_an_empty_list`.
- [x] `satld` kicks the port sweep whenever it republishes the cluster core,
      and the pass is forced -- a role change swaps the derivation, so
      "unchanged since I last wrote it" is a belief about a different code
      path's work.
- [x] An empty set logs once per forced pass, naming its source (`store` or
      `task_db`), so an absent `satl/rdr` can be told apart from a dead sweep.
- [x] `ca_rotate` may assert it: #75 promises a worker answers for a **local**
      replica, and the scenario runs 6 replicas on 3 nodes and asserts an even
      spread, so the demoted node always has one. The assertion is legitimate
      as written; what was wrong was the target, not the expectation.
- [x] The mesh ruleset now goes through real `pfctl`, alone and concatenated
      with the rdr rules it shares an anchor with -- `mesh_rules` was the one
      production nothing checked, so a grammar mistake in its table-sourced
      `nat pass` or its `scrub (max-mss n)` could only be found on the cluster,
      where it looks like a data-plane bug. Verified the check has teeth:
      `pfctl -n -f` exits 1 on a deliberately malformed `max-mss`.

### Phase 4: scenario independence ✅

The systemic finding, and the one that decides what a green is worth. Three
instances turned up while fixing the rest, which is the argument in miniature.

- [x] `a_follower`, `assert_leader`, `assert_not_leader`, `require_leader`,
      `rdr_count`. `require_leader` is the primitive the suite never had: it
      moves leadership by stopping the current leader's satld, bounded at four
      rounds. Its absence is why "the hard case" was met only when the
      previous scenario happened to leave leadership in the right place.
- [x] `ca_rotate` picks its demote target by **raft role** (`a_follower`) and
      asserts it, instead of `nodes_with_role joiner | sed -n 2p`, which was
      always node3 and therefore a coin toss.
- [x] `ca_rotate`'s retry-inside-`wait_until` is gone. That loop, with its
      `|| true`, turned a permanent refusal into a 180 s timeout reported as
      "demote timed out" -- which is exactly how demoting the leader stayed
      broken and unnoticed (ten attempts, zero handovers). The transient it
      guarded against is handled by waiting for `membership_agreed` first, so
      a refusal is now real and immediate.
- [x] New `demote_leader` scenario, placed before `ca_rotate`: it exercises the
      hard case **on purpose**, and asserts both halves of the demote, reading
      the role back from a *survivor* because a demoted node cannot see its own
      demotion.
- [x] `node_kill` and `leader_kill` pick by raft role. Both read the
      `MANAGER STATUS` column, which the file's own comments document as never
      refreshed on a leadership change: `node_kill` could kill the leader and
      `leader_kill` a follower, each then asserting the wrong thing.
- [x] `node_audit` counts redirects and `leftovers_gone` demands `rdr=0`, so a
      leaked redirect fails wherever it happens rather than only where someone
      thought to look. The audit was blind to pf entirely.
- [x] `hot_resize` waits for `membership_agreed` after restarting a node's
      satld; `restart_budget` restores the leader it found. A scenario cleans
      up the state it disturbed, and raft leadership is state.
- [x] `build_push_run`'s "warm must not be slower" is gated on the same
      threshold as its 2x rule. It failed a whole suite run on `cold 1s,
      warm 2s` -- one second of ssh jitter at one-second granularity, reported
      as "the build cache made things worse".
- [x] The usage block lists every scenario, `images_rm` included; it was
      missing from the list it claimed to be.
- [x] Proven. Full suite **25/25 twice in a row**, and the four runs before
      them each failed on a *different real defect* rather than on the one the
      milestone started from. `demote_leader` also passes **alone**
      (70 s) and so does `ca_rotate` (132 s), each straight after
      `init_and_join` on a cluster with no history -- so neither inherits
      anything, not even the warm liveness window a demote needs, which their
      own `m4_prelude` supplies.

### Phase 5: credibility fixes ✅

- [x] `satld/build.rs` stamps a build time that moves. Emitting **any**
      `rerun-if-changed` opts the script out of cargo's default package
      tracking, so a source change rebuilt the binary and kept the old
      timestamp; three signals now (sources, `.git/HEAD`, the ref it points
      at). Verified by touching `main.rs`: 20:58:07 -> 20:58:29.
- [x] The two false claims in `satl-doc`'s `out-of-scope.md`: the per-kind
      prune verbs **do** exist (`--filter` is what does not), and `satl events`
      **is** a CLI verb with its own generated page.
- [x] `swarm init --force-new-cluster` is refused by the CLI, in the daemon's
      own words, and its `--help` says NOT IMPLEMENTED. The flag stays: it is
      real Docker surface, and "unexpected argument" teaches less than the
      sentence that names the two recovery procedures. Four `satl-doc` pages
      that said "the daemon answers 501" now say the CLI refuses it.
- [x] The overlay-on-a-/32 error names the right cause. `NoIdentityReason`
      keeps the three cases apart, so a deliberate degradation stops claiming
      to be "a start-up ordering bug in satld". `satl-doc`'s install page says
      what still works (bridge networks, `satl compose`) and what does not
      (`satl stack`, multi-node), and quotes the log at the level it is
      actually written at.
- [x] `README.md`, `docs/operations.md` and five `satl-doc` pages: `0.1.0` ->
      `0.2.0`. `satl-doc`'s `make check` is green, generated pages included.
- [x] The per-task tmpfs does not leak: measured on alpha, on containers a week
      old. `satl rm` takes the jail, both tmpfs mounts and the dataset with it
      (decision log). The `run.sh` comment predates its own fix and goes; the
      scenario asserts the tmpfs mount alongside the secret one instead.

### Phase 6: the deliberate gaps ✅ (they were already stated)

Checked rather than assumed, and the note was wrong here: every item it listed
as needing to reach a reader already does, in `satl-doc`.

- Compose projects are not an isolation boundary: `docs/use/compose.md` carries
  it as a `!!! danger` admonition, plus `docs/docker-differences.md`. This was
  the one most likely to be read as a security claim it is not, and it has the
  strongest treatment of the lot.
- No interpolation, no `.env`, one `-f`: `docs/use/compose.md` and
  `docs/reference/out-of-scope.md`.
- `build:` builds a `Satlfile`, not a Dockerfile, client-side and as root:
  `docs/reference/out-of-scope.md`.
- The builder is not reproducible, so `compose up --build` replaces tasks every
  time: `docs/use/compose.md`.
- Published ports are not reachable via `localhost` on the publishing node:
  `docs/trouble/network-local.md` has a section of its own, reached from two
  troubleshooting indexes.

Still open as a *decision*, not a gap: node-local scope has technically
unblocked interpolation since M11a (the file is on the same filesystem as the
daemon), so `.env` is a choice to revisit rather than a constraint to document.

### Phase 7: soak 🔨 (started)

Running something real for a few days, which now also means soaking an alpha
consensus engine -- the reason it is not optional.

- [x] **The soak host is alpha, and it is on the M12 build since
      2026-08-24T22:26Z.** It was not before: `GET /version` reported commit
      `64709ac`, pre-M12, which invalidated an earlier standalone check until
      it was re-run (decision log). Upgraded through the package, and the
      `web` container was re-adopted across it -- same jail id, same uptime.
- [x] **Re-based the soak on the final M12 build (2026-08-25T00:44Z)**, because
      soaking a build that is not the one being shipped proves nothing about
      the one that is. Re-verified on the way through: the `web` container was
      re-adopted, not restarted (same jail id 6, still "Up 2 weeks"),
      `satld.toml` survived with a `.pkgsave` of the *sample* as expected, and
      a standalone `satl run` returned its output on a single-node cluster.
- [x] The encrypted-overlay suite, 7/7, on the 3-VM testbed. Not part of
      `make cluster-test`, and worth running deliberately because M12 touched
      the raft transport and `satld::overlay`.
- [x] **Re-based on the current build and widened to the cluster
      (2026-08-25T14:11Z).** Two things were wrong with the soak as it stood:
      it was running a build three commits old, which by its own standard
      proves nothing about what ships; and it was **single-node**, so two of
      the three things this phase is looking for -- a raft node that stops
      contributing, and anything that only shows up under real cluster uptime
      -- were outside what it could ever see. All four hosts run **the commit
      the published package is built from**, and that is the form this line is
      written in on purpose: naming a hash here made it wrong again the moment
      the next docs-only package shipped, twice. The check is two commands, not
      a memory: `satl version` on any host against the digest on `/download/`.
      Alpha's `web` container is re-adopted across every one of these upgrades,
      same jail id 6. The 3-node testbed runs the Node.js + MariaDB stack from
      the getting-started page: 3 web replicas spread one per node behind a
      published port, one database pinned by constraint with a node-local
      volume, a secret, healthchecks, and both the `tuto_default` and `ingress`
      overlays. A real workload rather than an idle cluster.
- [x] **`tests/cluster/soak-report.sh`, so the reading happens and is
      comparable.** "Re-read `/var/log/messages`" is a reading, not a test: done
      by hand it is done differently every time and compared against nothing.
      The script prints the same observations in the same order for every node
      (satld uptime and RSS, jail ids *with* their start times, leadership
      churn, ERROR/WARN counts per tracing target, panics and assertions,
      epairs, DYING prisons, layer datasets missing `@final`), asserts nothing,
      and takes `--host` for a machine outside the inventory. Two runs a week
      apart are the finding. Writing it caught three bugs in itself first,
      which is why it is worth having: FreeBSD's `ps` reads `-o rss=,vsz=` as
      one column with a header, `grep -c` prints 0 *and* exits 1 so a `|| echo
      0` yields two lines, and a sed pipeline that looked right reported the
      **month name** as the busiest tracing target. All three produced numbers
      rather than errors, which is the failure mode a reporting script must not
      have.
- [x] **Baseline, 2026-08-25T14:16Z**, on the fleet described above: satld
      71-74 MiB RSS per node, zero leadership or vote lines since start, zero
      panics or assertions, zero DYING prisons, every layer dataset carrying
      its `@final`, and epair counts matching one per (task x network) with
      every description naming a live task. The last one is recorded because it
      nearly read as a leak: five epairs for two containers on node1 is what
      healthy looks like.
      The report earned its keep on the upgrade that set this baseline: satld's
      pid and uptime reset on all three nodes while **every jail id and jail
      start time stayed put**, which is re-adoption (architecture §7.2) visible
      at a glance rather than inferred. A changed jail id under an unchanged
      count is the silent restart this line exists to catch.
- [ ] **Re-read it in a few days** with the same command and diff the numbers.
      This is the only item in this phase that cannot be compressed: it needs
      time to pass, not work to be done. The specific questions the baseline
      makes answerable: does RSS grow, do the epair and layer counts return to
      where they started once tasks churn, does any node stop appearing in the
      leadership lines, and does anything at all show up under `crashes`.

### Phase 8: launch mechanics 🔨

- [x] `CONTRIBUTING.md`. It did not exist, so an outside contributor had no way
      to know `make check` is the gate, that `sudo make integration` exists, or
      that a networking change is expected to run it. Carries the eight
      invariants by number (they are cited that way throughout the tree), the
      definition of done, and the `grep -a` rule for reporting a bug.
- [x] CI: `.cirrus.yml` runs `make check` on FreeBSD for every pull request.
      Cirrus and not GitHub Actions because there is no FreeBSD runner there --
      the workspace would not compile. **Unverified until its first run**: the
      file has never executed, and the image it names is the newest FreeBSD
      Cirrus publishes, not the 15.1 the project targets. `README.md` now says
      what the tick means (compiles, lints, unit tests) and what it cannot
      cover (integration, cluster).
- [x] `README.md` and `docs/operations.md`: `satl-0.1.0.pkg` -> `0.2.0`.
- [x] The merged `m11-two-worlds` branch is gone locally.
- [x] **Tagged `v0.2.0-alpha`**, on `main` after the M12 branch fast-forwarded
      into it. `Cargo.toml` stays numeric (`0.2.0`): a hyphen in a `pkg(8)`
      version is read as the name/version separator, so the package and the tag
      deliberately differ. The tag is annotated and local only -- nothing is
      pushed. Note that `roadmap.md` had claimed a local `v0.1.0-beta` tag that
      never existed; `git tag -l` was empty until this one.
- [x] **Pushed, 2026-08-25.** This item said "nothing is pushed yet ... two
      commits ahead of `origin/main`, which is still at `a264fa3`", and it had
      been wrong for a while: a `git fetch` put `origin/main` at `cea0cd5`, so
      M12 and everything through the cluster-suite fixes were already there.
      Worth recording as a habit rather than a detail: a roadmap line asserting
      the state of a *remote* goes stale without anything local changing, and
      the only honest way to write one is to check it first. The remaining
      commits (the proposal-retry fix, the soak work and this correction) were
      pushed as a fast-forward, nothing to pull.
- [ ] **The `v0.2.0-alpha` tag is still local**, deliberately: pushing a
      release tag is a louder act than pushing a branch, and it is the kind of
      thing to do on purpose rather than as a side effect. `git push origin
      v0.2.0-alpha` when the release is meant to be visible as one.
- [x] No signed releases and no FreeBSD port. `README.md` now says so where the
      package is built, rather than leaving it to be discovered: unsigned, no
      pkg repository, not in the ports tree, verify against
      `dist/CHECKSUM.SHA512`. Both stay out of scope until the API and the
      on-disk layout stop moving.
- [x] **The documented getting-started path does not work on a host that
      followed it.** Found by Frederic re-provisioning the cluster from
      `www.satl.cc` on 2026-08-25: the first command of "Your first container"
      is `satl pull docker.io/library/alpine:latest`, and it fails on any node
      that did not enable the linuxulator, which the install page never told it
      to. Fixed on both sides, in `satl` and in `satl-website-v2`; see the
      decision log.

---

## Decision log

| Date | Decision |
|---|---|
| 2026-08-25 | **A retry loop that could not make progress, and reported a cause it had ruled out by construction.** Found while answering "so no more bugs?", by reading `propose_from_view` rather than trusting yesterday's conclusion -- which was wrong, or rather half right. The `worker_join` failure *was* a weak precondition in the scenario **and** a real defect in the daemon, and I had recorded only the first. `Backend::propose_from_view` retries a sequence conflict five times, rebuilding each attempt from `self.store()`, which is **this node's** applied store, and with no pause between attempts. So for the one case where a retry could ever help -- this node being a few raft entries behind -- all five attempts read the identical stale version in microseconds and the handler gives up with *"the object kept changing underneath (5 attempts)"*. Nothing was changing; the caller was behind. That sends an operator hunting a concurrent writer that does not exist, which is the same defect shape as the quorum guard's refusal (2026-08-24) and the platform error (#183): **a message naming a cause it cannot distinguish**. Two changes. A linear pause between attempts (50 ms x attempt, ~500 ms worst case) so a store that is merely behind can advance and the retry becomes worth making, bounded because this is a REST handler and waiting out a badly lagging node is not on offer. And the exhaustion error now tells the two cases apart from evidence it already had: the version *this node* read on each attempt. If it never moved, the message says the node's copy is stale, names both versions, says why (reads are answered from each node's own store) and what to do (retry, or run it against the leader). If it moved, the object really is contended and the original wording stands. The decision is a pure function, `exhausted_conflict_error`, so all three arms are unit-tested without a cluster. `make check` and `sudo make integration` green |
| 2026-08-25 | **Two smaller things closed in the same pass.** **(1)** `--format` exists on `satl events` and on nothing else -- not on `ps`, `images`, `service ls`/`ps`, `stack ps`, `node ls`, nor any of the seven `inspect` verbs, where docker carries it everywhere. That is deliberate for the reason #162 already gives (no template engine, and half of one is worse than none) and it had **no api-compat entry**, which is an invariant #8 gap rather than a design question. Recorded as #184, with what replaces it: `inspect` already prints the API's JSON verbatim so `jq` needs nothing from the CLI, and the listing verbs carry `-q`. Both checked against the running daemon before the entry was written. **(2)** The `health_pool` timeout that did not reproduce is still unexplained, and the reason it stayed unexplained is now fixed: its failure dump grepped `/var/log/messages` for the *node name*, which appears only in the startup banner and the cluster-init line, so the one chance at diagnosing a non-reproducing failure printed two irrelevant lines. It now greps `satld[<pid>]`, the tag syslog stamps on every line of that daemon, plus everything logged about the task by id, and `log_lines` uses `grep -aF` because `satld[1234]` as a basic regex is a character class matching three digits anywhere. The suite passed on the next full run, so the improved dump is unexercised by design |
| 2026-08-25 | **`make cluster-test` 25/25 on the fixed build, after the run found two defects in the harness and none in the product.** First full run on the reinstalled fleet, carrying the layer-reclaim fix. It stopped twice before going green, both times on `tests/cluster/`. **(1) The readiness gate told three healthy nodes they were NOT READY**, counting `pf satl anchors 2 (expected 3)`. Its regex demanded exactly one space between the keyword and the quoted anchor, and the `pf.conf` that the *published* `install-satl.sh` writes -- the file the website tells an operator to create -- aligns the third anchor for readability (`anchor     "satl/*"`). pf(5) does not care, and the install script's own counter, which uses `[[:space:]]+`, had reported 3/3 on the same file. Two counters over one file disagreeing is the shape of thing that costs an afternoon; the gate now uses the same expression. **(2) `worker_join` failed on `scaling web back through node3`**, with `sequence conflict on service ...: store has version 65, caller wrote from version 14` in every node's log. Not a product defect: `satl service scale` is a read-modify-write and reads are answered from the node's **own** applied store (§7), while the scenario waited only for the *leader* to show the previous scale committed before writing through the freshly promoted node again. The node had not applied it yet, so the second scale submitted a stale version and the leader correctly refused. Confirmed by re-running the scenario alone, where it passed in 88 s -- the signature of a precondition weaker than what it guards, which is exactly the mistake already removed from `node_kill`, `leader_kill` and `demote_leader`. It now waits for the writer's own reading, and the failing branch shows the CLI output instead of discarding it, which is why the first diagnosis had to be made from the daemon log. Green run: 25/25, `rolling_update` 101 s and `hot_resize` 24 s among them, so the path the reclaim fix touches is exercised end to end |
| 2026-08-25 | **The rollout-pausing layer race is fixed, and reading the code turned yesterday's inference into a certainty.** The entry below recorded the `zfs destroy ... dataset is busy` rejection with a hypothesis: cancellation releasing the per-chain gate while a `spawn_blocking` unpack carried on. That is not a hypothesis, it is what `unpack_layer` is written to do: it `spawn_blocking`s the tar extraction and awaits the `JoinHandle`, and **dropping a `JoinHandle` does not cancel a blocking task** -- tokio cannot interrupt one. So when the agent replaces a task manager mid-prepare, the future is dropped, the `tokio::Mutex` guard goes with it, and the extraction keeps writing into a dataset that now has nothing holding its gate. The next apply finds a dataset with no `@final`, correctly reads that as "interrupted", and destroys a mountpoint that is in use. **Fix:** `LayerStore::reclaim_incomplete` replaces the bare destroy. `zfs destroy` makes the decision rather than a check before it, which is the third time this codebase has landed on that rule (the per-chain gate, `ContainerFsStore::create`'s origin check, this): `dataset is busy` means "not yet" and is retried for 15 x 2 s, an `@final` appearing during the wait is adopted instead of rebuilt (the abandoned apply finished after all, so the work is free), and every other refusal -- `filesystem has dependent clones` above all, which means a container rootfs was cloned from this layer -- stays fatal on the first try, because waiting cannot change any of them. The busy classifier `ZfsError::is_busy` is deliberately narrow for exactly that reason. Budget exhaustion returns the real `zfs` error with its argv and stderr, and logs where to look (`mount -p`, `jls -d -h name dying`). **Rejected**: making the apply itself uncancellable by running it in a `tokio::spawn`, which would also have removed the duplicated unpack. It needs `R: Clone + 'static` on the `CommandRunner`, and every storage test injects a `&MockRunner` -- a borrowed, non-`'static` runner. Rewriting the whole crate's test harness to fix a race that the destroy can arbitrate on its own was the worse trade. Four unit tests pin the arms (waited-out, adopted-mid-wait, budget-exhausted, dependent-clones-still-fatal), one pins the classifier, and `tokio`'s `time` feature is now declared by `satl-storage` instead of arriving through workspace feature unification, which is what `tokio::time::sleep` had been compiling on. `make check` green, `sudo make integration` green. **Honest note on the verification**: the first integration run of the session failed `health_pool` on a 180 s timeout waiting for a task to become healthy, with the layer apply visibly fine (`preparing -> ready -> starting` in 2 s). It did not reproduce: that test passes alone with the fix, the full suite passes without it, and the full suite passes with it. Recorded rather than dropped, because it happened immediately after stopping the production daemon on alpha and its log carried the loopback-underlay overlay MTU warnings that host is known for |
| 2026-08-25 | **A rolling update pauses on a layer-dataset race, and the same check-then-act shape that was fixed for container clones is still there one level up.** Measured while walking the Node.js + MariaDB page on a freshly formed three-manager cluster: all three slots reached `:v2` and served traffic throughout (60 polled requests, 60 `200`s, no dropped connection), and the service still ended in `UpdateStatus: paused, 1 of 3 tasks failed`. The rejected task on fbsd3 carried `` `/sbin/zfs destroy -r zroot/satl/layers/175f6d88...` failed ... "cannot unmount ...: pool or dataset is busy" ``. The log gives the shape precisely: the task was assigned **twice**, the second assignment arriving at 25.353 while the first prepare's `layer_apply` of that same chain had started at 25.292; the second prepare re-walked the chain, found the dataset without its `@final` snapshot, took that for an interrupted apply, and ran the destroy-and-rebuild arm of `LayerStore::apply_one` on a dataset still in use. Worth recording what this is **not**: `ensure_layer` does hold a per-chain `tokio::Mutex` across the whole apply, so two live prepares in one process cannot interleave there. The remaining explanation is cancellation: the first prepare's future was dropped when the second assignment replaced its task manager, which releases the mutex immediately while the `spawn_blocking` unpack it started keeps files open in the dataset, so the second prepare sees a genuinely half-made dataset that is genuinely busy. That is inference from the timestamps, not something reproduced on demand, and the fix is not obvious enough to guess at: the candidates are making the destroy arm treat "busy" as "someone else still has it" and retry rather than fail fatally, holding the gate across the blocking unpack so cancellation cannot escape it, or not cancelling a prepare at all. This is the third appearance of the same family (`LayerStore`'s per-chain mutex, then `ContainerFsStore::create`'s origin check, now this), which is the argument for treating "the atomic ZFS operation is the only arbiter" as a rule rather than a series of fixes. **Not fixed in this change**, deliberately: it was found during a documentation mission and it deserves its own, with `sudo make integration` behind it. The published page documents the pause, its mechanism and the remedy that works (re-pushing the identical update cleared it and left the service `3/3`) rather than presenting it as expected behaviour |
| 2026-08-25 | **The first command a new user runs cannot work, and the product was right while the documentation was wrong.** `satl pull docker.io/library/alpine:latest` on a freshly provisioned fbsd1 answered `no matching platform for freebsd/amd64 ... available: [linux/amd64, ...]`. That is correct behaviour: Alpine publishes no FreeBSD image, and `linux/amd64` is only a candidate when the node's linuxulator probe is positive. The defect is that **`linux_enable` is not a FreeBSD default and nothing in the documented install path turned it on** -- `install-satl.sh` had it behind an opt-in `--with-linux`, and `start/install` mentioned the linuxulator only in a flag list and in a log line -- while the *next* page opens on a Linux-only image, because there is no public FreeBSD image small enough to make that step quick. So the getting-started path was guaranteed to stop on its first command for anyone who did not already know. Fixed at three levels rather than one, since any single one of them would have been a patch over the other two. **(1)** The pull error was a dead end: it listed platforms and left the reader to conclude the image was unsupported here. `PlatformPolicy::select` now distinguishes the two cases and `ImageError::LinuxEmulationDisabled` carries the fix in its text (`service linux start`, `sysrc linux_enable=YES`, satld re-probes every 10 s so no restart) -- recorded as api-compat deviation 183. Deliberately kept as a *pull-time* refusal rather than a warn-and-pull: an image in the store whose every task dies at `preparing` puts the cause one layer further from the operator. An explicit `--platform linux/amd64` still pulls, because that is an instruction about the image and the emulation is a fact about one node. **(2)** `install-satl.sh` enables the linuxulator by **default** (`--without-linux` opts out), runs that step before the package rather than after the service, refuses to fall back to `kldload linux` -- the half-enabled trap already recorded on 2026-08-23 -- and now checks `kern.elf64.fallback_brand` as well as `compat.linux.osrelease`, because rc.d/linux sets the brand only when it is `-1` and the sysctl alone cannot tell a working linuxulator from one where every static musl binary dies. The final checklist reports the linuxulator unconditionally. **(3)** The site says it: a numbered install step with both sysctls to check, a requirements row, and the `alpine` step itself opening on the check rather than on the failure table. The general lesson is the one this milestone keeps re-teaching: **a documented path is only verified by walking it on a host that has nothing**, and the dev host had had `linux_enable=YES` for so long that no amount of re-reading the page could have found this |
| 2026-08-25 | **The build-stamp fix is confirmed on the first commit that could confirm it.** LAUNCH-TODO 2.2 said `satl --version` could not be trusted: `build.rs` emitted `rerun-if-changed=.git/HEAD`, which replaces cargo's default package tracking, and `HEAD` does not change when a commit lands on the branch it already points at -- so the stamp froze. The fix adds the *resolved ref file* as a second signal, and until now there was nothing to test it against, because no commit had been made all milestone. Measured immediately after committing M12: the running daemon reported `a264fa3` (the pre-M12 commit) before, and `dcf661a` after a rebuild and package upgrade, with no other change. The container was re-adopted across that upgrade as well -- same jail id 6. Noted because the ordering matters for anyone repeating it: the verification has to follow the commit, and amending the commit afterwards would change the hash and invalidate the very stamp just checked |
| 2026-08-25 | **`LAUNCH-TODO.md` and `REPORT-production-readiness-2026-08-23.md` retired into this milestone.** Both were working notes that had done their job: the launch note became M12 phases 1-8, and its findings, corrections and measurements are recorded here. Before deleting the launch note -- untracked, so unlike the report its deletion is not recoverable from git -- its section 4 backlog was checked item by item against the tree, because that section was deliberately scoped *out* of M12 and would otherwise have gone with it: M9b has its own roadmap section, plugin volumes are in the M6 backlog, per-project bridge networks are recorded above, and `stack deploy --with-registry-auth`/`--resolve-image` live in `api-compat.md` as deviation 148, which is their proper home rather than a note. Nothing was lost. The habit is worth keeping: an untracked note is the one kind of file whose deletion has no undo, so what it uniquely holds gets checked before it goes |
| 2026-08-25 | **25/25 on the fleet carrying all six fixes, and the two scenarios that matter pass in isolation too.** The sixth full-suite run, from a clean `reset.sh`, against binaries carrying the eviction self-heal, the eviction clear, the role-change precedence guard, the idempotent container clone and the bounded shutdown: every scenario green, `rolling_update` 96 s (it had failed at 480 s two runs earlier), `demote_leader` 76 s and `ca_rotate` 133 s. Both of those also pass **standalone** -- 75 s and 127 s -- which is the independence property Phase 4 was for, and the one a suite-order green cannot demonstrate. Worth stating plainly what the six runs cost and bought: runs 1-4 failed on four different real defects, run 5 on a scenario asserting a promise the product never made, run 6 green. Not one of the six failures was the defect M12 started from. The soak host was re-based onto this exact build afterwards (`find crates -name '*.rs' -newermt` against the build stamp returns nothing), and its container was re-adopted across the upgrade -- same jail id 6, and a 2 s restart, which is the bounded-shutdown path taking the clean branch |
| 2026-08-25 | **`demote_leader` asserted something the product explicitly does not promise, and a run finally caught it.** The fifth full-suite run reached `demote_leader` moments after `restart_budget` had moved leadership, and the demote was refused by the quorum guard with all three nodes reading `STATUS Unknown` -- the guard doing its job, not the defect the scenario exists to catch. The scenario waited for a leader to exist and then demoted once, but the guard's precondition is different and stronger: the leader must have **heard from** a quorum of the remaining members within the liveness window, which a cluster that has just changed leadership has not. The daemon's own error text says so and says what to do -- *"this is transient ... the same command succeeds shortly after"* -- so a single-shot assertion was testing a promise nobody made. Two changes: wait for all nodes `Ready` (the observable that moves with liveness) before asserting anything, and bound-retry the demote **only** while the refusal is that specific liveness one. That second part is deliberately not the `|| true` retry Phase 4 deleted from `ca_rotate`: this one fails immediately on any other error and fails with the real message if the transient refusal outlasts the budget, where the old one swallowed everything and turned a permanent failure into a silent timeout. Verified in isolation: `demote_leader` 75 s (demote succeeded first attempt, the Ready wait returning in 1 s) and `ca_rotate` 127 s. The distinction worth keeping: a retry that narrows to a documented transient and reports everything else is the opposite of a retry that hides failures, even though both are loops |
| 2026-08-25 | **`satld` can hang in shutdown for ever, and once it does it ignores every further SIGTERM.** Found because `reset.sh` stalled on node3 for over ten minutes with, at first glance, nothing running there. Chasing it properly: `service satld stop` was parked in `pwait -op 31124`, and pid 31124 was `satld` itself -- **alive for 1h45m, REST socket already removed, its own components silent, while openraft went on retrying replication to two unreachable peers at ~6 lines/second**. Three stacked `service satld stop` invocations and a hand-delivered `kill -TERM` all did nothing; only `kill -9` ended it. Two defects, and the second is what makes the first unescapable. **(1)** `stop()` is unbounded, and `RaftNode::shutdown` awaits `Raft::shutdown()`, which joins openraft's core -- a core that does not return while it cannot reach its peers. **(2)** `tokio::signal` *disarms the default action* when it registers a handler, so after the first SIGTERM the process is immune to SIGTERM by construction; nothing was listening for a second one, so the operator had nothing to escalate to. Fixed at both levels: `Raft::shutdown()` gets a 10 s bound so the rest of the stop (releasing the log file, stopping the task managers, removing the socket) still happens and the log names the raft core as the culprit; `stop()` gets a 30 s outer bound after which the daemon exits anyway; and a **second** signal during shutdown now exits immediately, which is the escalation path that did not exist. Running containers are left in place on all three paths, as on a clean stop (architecture §7.2). **Honest limit on the verification**: the clean path is measured (`service satld stop` on an isolated single-manager node: 3 s, `shutdown signal received` then `satld stopped`, 17 ms apart) and `reset.sh` now completes on all three nodes where it had hung for over an hour -- but the wedge itself has *not* been reproduced on demand since, so the two timeout branches are defensive and unexercised in the field. They are cheap, and the state they prevent cost an hour of a run |
| 2026-08-25 | **The cluster suite's ssh could hang for ever, and its own comment promised it could not.** `lib.sh` said its wrappers use BatchMode "so nothing can ever hang waiting for a password or a host-key prompt" -- true, and not the failure that happened. `ConnectTimeout` bounds only the *initial* connect; an established session whose peer stops answering blocks indefinitely, because ssh has no reason to abandon a TCP connection nobody has reset. That is how the `satld` shutdown wedge above presented: `reset.sh` appeared to be doing slow teardown on node3, and was in fact holding a dead session. Added `ServerAliveInterval=15` and `ServerAliveCountMax=4`, so a peer silent for a minute is declared gone. Keepalives are answered by sshd itself and not by the remote command, so a legitimately slow operation -- a `zfs destroy` waiting out a DYING prison's `2 x net.inet.tcp.msl` -- is never cut short by this; only a genuinely unresponsive host is. The comment now says what the wrappers actually guarantee, which is the part that had been wrong |
| 2026-08-25 | **A rolling update rolled back six slots because two prepares raced over one task's rootfs, and the loser called it a fatal failure.** Found by the fourth full-suite run, which failed `rolling_update` after 480 s: `UpdateStatus` read `rollback completed: 6 slots rolled back`, and the trigger was a single task rejected in `preparing` with `` `/sbin/zfs clone .../layers/d5f1a01...@final zroot/satl/containers/1mpbcd...` failed ... "dataset already exists" ``. The dataset was **still there afterwards, with exactly the expected origin** -- which is what identifies the mechanism: the clone did not fail, it *succeeded and then ran again*. `Controller::ensure_container_fs` already guards this with a `dataset_exists` check, but that is check-then-act: two prepares for the same task both see it absent and both clone, and only one can win. `zfs clone` is the sole step that serialises, so the decision has to be made from its result, not before it. Fixed in `ContainerFsStore::create`: "dataset already exists" is success **when the existing dataset's `origin` is the snapshot this task would have cloned from**, and fatal otherwise -- the dataset name is the task ID and tasks are immutable and one-shot (invariant #2), so a matching origin can only be this task's own earlier attempt. Deliberately conservative: a different origin, an unreadable one, or a `zfs get` that fails all keep the original clone failure fatal, because proceeding over a rootfs whose contents cannot be vouched for is worse than a rejected task. Three unit tests pin the reuse, the foreign-origin collision and the unreadable-origin case. `LayerStore` had already met this exact failure for *layer* datasets and solved it with a per-chain mutex; the container clone had no equivalent, which is worth noting as a pattern: the same race recurs at every level of the dataset tree, and only the atomic operation can arbitrate it |
| 2026-08-25 | **`make cluster-test` 25/25 a third time, and an ad-hoc stress script taught the lesson the suite was built to teach.** The third consecutive full-suite green (`init_and_join` through `cleanup`) came from the fleet carrying the eviction self-heal. Re-validating the two later fixes on top of it needed a fresh run, and the throwaway demote/promote script written to do it failed three times in a row for three reasons **none of which were the product**: `set -e` swallowing a failed `satl node promote` into a bare exit 1 with no message; `grep -c` printing `0` *and* exiting 1, so `|| echo 0` produced the two-line `0\n0` that `$(( ))` choked on; and -- the one worth recording -- a `settle()` that waited for three nodes to read `Reachable` in `satl node ls` before demoting. **That is the stale column**, which `tests/cluster/run.sh` documents in three separate places as written at cluster formation and never refreshed, and it is the exact mistake Phase 4 removed from `node_kill` and `leader_kill`. Having just fixed it in the suite, I reintroduced it in a script written to check the fix. Measured on the way out: the quorum guard's refusal really is transient -- the same demote succeeded on the very next attempt, 0 s later, 0 retries -- so the refusal text is accurate and the script's gate was the defect. The conclusion is not "write better scripts": it is that `demote_leader` **already exists as an asserted scenario** and re-running the suite is both cheaper and stronger than re-deriving its setup by hand |
| 2026-08-25 | **One eviction caused two full wipe-and-re-join cycles, and only the timing of a race kept it from being more.** Found by reading the healed node's log rather than trusting the outcome: the self-heal above worked, but `role change applied` appeared twice, 180 us apart, with a second `raft ID was removed` warning between them. The mechanism is a stale read, not a duplicate log line. The supervisor's `ApplyRole` arm calls `cluster::apply_role`, which brings the new runtime up -- **including spawning its role watcher** -- and only then returns, after which `main` publishes the new core to the slot. So a freshly spawned watcher that reads `slot.get()` before that publish gets the **old** context, whose `Eviction` is still set, and asks for another rebuild. It stopped at two only because the third watcher's read lost the race to the publish; nothing bounded it. Fixed by making the signal **consumed rather than observed**: `Eviction::clear()` is called by the handler before it sends `ApplyRole`, so a stale reader finds nothing. Clearing before the send rather than after is deliberate -- the send only queues, so clearing after it would still lose the race -- and losing the signal on a rebuild that then fails costs nothing, because the peers go on refusing and the next refusal re-arms it. Pinned by `clearing_an_eviction_stops_a_second_reader_acting_on_it`. The general lesson, worth more than the fix: **a component that publishes its own successor must not leave edge-triggered state readable by it**, and verifying a repair by its outcome alone would have shipped this |
| 2026-08-25 | **The eviction self-heal works, and its first version was dead code on exactly the node it was written for.** The fix for the entry above: peers refusing a vote because this node's raft ID is blacklisted now set an `Eviction` signal (`transport.rs`), and the role watcher acts on it by asking the supervisor for `ApplyRole` with the role the node *already* holds -- whose manager arm wipes the raft directory before every join attempt, which is the whole of what a blacklisted ID needs. **No certificate renewal is involved**: an eviction does not change the node's role, so the certificate on disk is already correct, and `renew_remote` would have to reach a CA this node cannot currently reach. The first version folded eviction into the existing `wanted != held` role-change branch, and **deploying it to the live stuck node proved it never fired**: `wanted` comes from the agent session, and an evicted manager has no working session -- it dials its own dispatcher, which refuses with `this manager is not the raft leader`, for ever. So `wanted` was `None` on precisely the node needing the rebuild. Measured: the instrumented daemon logged the refusal every 15 s for six minutes and rebuilt nothing. Two things had to change: eviction became **its own trigger**, independent of `wanted`, and the signal had to **push** -- the watcher parks on the session watch channel, which an evicted node never advances, so `Eviction::record` now notifies waiters and the watcher selects on it. Peer addresses come from the raft membership (`ManagerContext::peer_addrs`) when the session has none, which on an evicted node is always; it is local, needs no peer, and lists exactly the nodes that have been refusing this one. **Verified against the live stuck node** rather than a reconstruction: fbsd3, `Candidate` with raft id `15735553221346738296` for 32 minutes, healed ~10 s after the upgrade -- fresh raft id `3270562938881646221`, Learner -> Follower, `Ready`/`Reachable`. Then three demote/promote rounds on a uniform fleet: demotes at 366/339/257 ms, three managers restored every time |
| 2026-08-25 | **A demote followed quickly by a promote leaves the node campaigning against a blacklist for ever, and nothing heals it.** Found by stressing the leader-demote path three times in a row. Round 1 demoted the leader correctly -- 404 ms, role read back as `worker` from a survivor -- and then the promote back never took: **`spec.role` in the store is `manager`, its `MANAGER STATUS` is empty, and the node has been `Candidate` with raft id `15735553221346738296` since 00:00:02**, getting `PermissionDenied: raft member ... was removed from this cluster: its raft ID is blacklisted and can never be re-admitted` on every vote. Confirmed not self-healing after a minute of further campaigning. The mechanism: the demote blacklists the id and sets the role to worker, but the node's role watcher rebuilds on a *change*; promoting it again before that rebuild happened means the watcher saw worker->manager net-zero and never wiped the raft directory, so the node kept an identity the cluster can never re-admit. The refusal is correct and its text names the recovery ("wipe its raft directory and re-join with a fresh join token") -- what is missing is that **nothing acts on it**. A node told by every peer that it has been removed should wipe and rejoin, which is architecture §6.6's own rule ("a node told 'removed' wipes its raft state") applied to the case where it learns this from a vote refusal rather than from the dispatcher. Not caused by M12: the blacklist, the refusal and the role watcher all predate it. M12 made it *reachable*, because until the leader demote completed at all, this sequence could not be run |
| 2026-08-24 | **The quorum guard's refusal named a cause it could not distinguish, and a stress run caught it.** Three consecutive leader demotions were run against the idle testbed to stress the phase-2 write; the first was refused with *"only 1 of the remaining 2 members are reachable, and 2 are needed for quorum. Bring the unreachable managers back or force-remove them one at a time"* -- on a cluster where all three nodes' own `satl node ls` showed Leader + 2 Reachable. The same command, unchanged, succeeded a minute later. The guard is not wrong: it reads `PeerLiveness`, which records a peer when an **outgoing raft RPC to it succeeds**, inside one election timeout (20 s). The store's `MANAGER STATUS` is a different thing entirely, and a manager that has just won an election or whose connection was re-established has not answered *this* node yet. So "unreachable" meant "not yet observed", and the message told the operator to go bring machines back that were never away. Reworded to say which of the two it is, and to say the transient case is transient. The wiring was checked first and is correct -- `PeerLiveness` is an `Arc<Mutex<..>>` shared between the transport that writes it and the `ManagerContext` that reads it -- so this is a message defect, not a liveness one, which is exactly why it was worth chasing rather than papering over |
| 2026-08-24 | **`make cluster-test` green twice in a row, 25/25 each, and that repetition is the claim -- not the first green.** One passing run of a 25-scenario suite over three networked machines says the run passed; two say the suite is repeatable, which is the property this milestone was actually about. The four runs before them each failed, on four *different* real defects, none of them the one M12 started from: `require_leader`'s random walk, `build_push_run`'s ungated timing assertion, `ca_rotate` reading cluster state through the node it demotes, and the leader-demote defect itself. A suite that surfaces a new genuine defect on each of four consecutive runs and then goes green twice is a better argument for its own value than any of the individual fixes |
| 2026-08-24 | **The external surface was probed against the running daemon, endpoint by endpoint, and it matches its own contract.** Invariant #8 makes the Docker REST API the only external surface, and `docs/openapi.yaml` is generated from the handlers -- so the interesting question is whether the generated contract and the live daemon actually agree. Every documented `GET` without a path parameter answered as declared: 13 of 14 with `200`, and `/swarm/unlockkey` with the `503` it declares (*"this swarm does not have manager autolock enabled"*). The documented error contract holds too, exactly: an unknown path is `404 {"message":"page not found"}`; `/v1.43/info` and `/v1.24/info` both answer, `/v9.99/info` is a `400` in Docker's error shape, and `/v1/info` is a `404` because a bare `v1` is not version negotiation; a wrong method on a known path is `405` with an **empty body**, the deviation recorded daemon-wide. Not-found and malformed input carry Docker's own wording -- `No such container: nope`, `No such image: nope`, a parse error naming line and column. **One near-miss worth recording as method**: `/swarm/unlockkey` first looked like it under-declared its `503`, and it did not -- the grep window used to read the YAML was simply too short to reach it. Checking before reporting cost a minute; reporting first would have cost a reader an afternoon |
| 2026-08-24 | **Encrypted overlays: 7/7 on the new consensus engine, and the soak host was on the wrong build until now.** `tests/cluster/encrypted.sh` is not part of `make cluster-test` and had to be run deliberately, because M12 touched both the raft transport and `satld::overlay`: preflight, create, wire (ESP on the underlay, **zero cleartext** on the network's port), mtu, guard, key rotation (233 s, the SAD showing primary + previous during the overlap) and teardown all pass. **Correction on the way there**, worth recording because it invalidated an earlier claim: the standalone verification reported earlier in this log was run against alpha's daemon at commit `64709ac` -- a *pre-M12* build -- because alpha had never been upgraded. `GET /version` said so. Re-run against the M12 package: published port answers 200 from another host, `satl run` returns, `satl compose up -d` brings up two services, and `http://cache/` answers from inside the sibling's jail. One false alarm on the way, from picking a jail by position instead of by task id -- the `web` container is not in the compose project and cannot resolve `cache`, and reading that as a regression would have been the reader's error, not the code's. The upgrade also re-verified the rule that matters: same jail id, same "Up 2 weeks", so the container was **re-adopted, not restarted** |
| 2026-08-24 | **The independence test that matters: both scenarios pass ALONE.** A scenario that only passes in suite position is still inheriting, so the full 25/25 is not the proof -- this is. Straight after `reset.sh` + `init_and_join`, on a cluster with no history at all: `demote_leader` **70 s**, `ca_rotate` **132 s**, each run on its own. Worth noting what did *not* go wrong, because it was the predicted failure: demoting on a freshly formed cluster was refused by hand earlier in the day -- correctly, the quorum guard counts *reachable* members and liveness is populated by successful RPCs, so a cluster with no traffic yet looks like one with unreachable peers. Both scenarios begin with `m4_prelude`, whose membership and service checks are themselves the traffic that warms it. The old `ca_rotate` masked this the way it masked everything else: its retry-inside-`wait_until` swallowed the refusal and tried again until it stuck |
| 2026-08-24 | **`make cluster-test` is green, 25/25, and the green now means something.** The suite that opened this milestone red on `ca_rotate` -- and whose previous green was decided by where a predecessor happened to leave leadership -- passes end to end on openraft 0.10, including the two scenarios that matter here. `demote_leader` (64 s) exercises demoting the current leader **on purpose**, asserting both halves and reading the role back from a survivor. `ca_rotate` (122 s) picks its target by raft role and issues the demote **once**, asserting its exit status, where it used to retry inside a poll with `|| true` and report a permanent failure as a 180 s timeout. `cleanup` passes with the leftover audit now counting pf redirects, so a leaked `rdr` fails wherever it happens rather than only where a scenario thought to look -- and it produced no false positive across a full run. Three earlier runs each failed on a different defect and each one was real: the `require_leader` random walk, `build_push_run`'s ungated timing assertion, and `ca_rotate` reading cluster state through the node it demotes. None of them were the defect the milestone started from, which is the point |
| 2026-08-24 | **A CLI smoke test found an undocumented Docker gap: `system df`.** Running the seven verbs a new user reaches for first (`version`, `info`, `node ls`, `service ls`, `network ls`, `images`, `system df`) on the standalone node, six answered and the seventh did not exist -- and `GET /system/df` answers `404 page not found`, with **no numbered entry anywhere and no mention in the user docs**. Invariant #8 says every intentional deviation gets a number, so this was a gap in the record rather than in the code. Numbered now under #22, with the reason rather than just the fact: Docker's disk-usage report sums images, containers, volumes and the build cache, and here every one of those is a ZFS dataset, so a per-object total would be **wrong** -- clones share blocks with their origin and compression means logical size is not space used. `zfs list -o space zroot/satl` answers the real question with both accounted for, which is what the docs now point at. Worth repeating as a method: the gap was found by running the commands, not by reading the code |
| 2026-08-24 | **The `satl.internal.v2` bump is an operator-visible upgrade rule, so it is documented as one.** The protocol version lives in the gRPC service path, so a node on v1 and a node on v2 fail to find each other's methods entirely -- which is the intended shape (a half-speaking pair is harder to diagnose than a pair that cannot connect) but is useless as a *surprise*. Seen live while upgrading the testbed, in the window between restarting the first node and the second: `dispatcher rpc Session failed: code: 'Operation is not implemented or not supported'`. `satl-doc`'s cluster page now carries it as a warning next to the port table -- install on every manager, then restart them, and expect no quorum until that is finished -- with the one reassurance that matters: running containers are re-adopted across the restart, not restarted (verified on alpha by jail id and uptime). The `CHANGELOG` says the same under 0.2.0's successor |
| 2026-08-24 | **The mesh ruleset had never been through a real `pfctl`, and now is.** `generated_rulesets_pass_real_pfctl` covered `rdr_rules` and `nat_rules` and stopped there, so `mesh_rules` -- the only place two pf productions are emitted, a table-sourced `nat pass` and a `match out ... scrub (max-mss n)` -- was checked by unit tests that compare strings and by nothing that parses them. A grammar or ordering mistake there could therefore only surface on the cluster, where a ruleset pf refused looks like a data-plane bug rather than a syntax error. The test now checks the mesh half alone **and concatenated with the rdr rules it shares an anchor with**, because that concatenation is what pf actually parses and checking the halves separately would miss a rule about their order. The check was verified to have teeth rather than assumed to: `pfctl -n -f` exits **1** on a deliberately malformed `scrub (max-mss)` and 0 on the generated text |
| 2026-08-24 | **Picking the demote target by raft role exposed a coupling the hardcoded target had been hiding: `ca_rotate` was reading cluster state *through the node it demotes*.** `$CTL` is a global that `require_swarm` points at the first inventory node that answers -- node1 -- and `nodes_with_role joiner \| sed -n 2p` was always node3, so the two could never collide. `a_follower` can return node1, and then every `state_fetch "$CTL"` in the scenario is asking a **worker** about cluster state, which answers Docker's refusal ("Worker nodes can't be used to view or modify cluster state", api-compat). Measured on run 4: the demote itself succeeded -- fbsd2 showed fbsd1 with an empty MANAGER STATUS -- while the scenario, polling through fbsd1, sat in `wait_until` for the full 180 s and reported "demoted: ... timed out". The same failure text as the defect this milestone started from, for an entirely different reason, which is its own small lesson about what a timeout message is worth. Fixed by pointing `$CTL` at a manager that is not the target, with `live_manager`, which the scenarios that kill a node already do. This is the shape §2.1 predicted: "assume there are more of this family" |
| 2026-08-24 | **`demote_leader` passes on the testbed: the hard case is exercised on purpose, and it is a scenario now rather than an accident.** 56 s, on the real fabric, after `restart_budget` happened to leave leadership on fbsd3: `satl node demote fbsd3` on the node that *was* the leader, the role read back as `worker` from fbsd1 four seconds later, leadership on fbsd2 seven seconds after that, and fbsd3 promoted back to three agreeing managers. Every one of those steps is asserted, and the role is read from a **survivor** on purpose -- a demoted node cannot see its own demotion, and asserting only "it left consensus" is what let the half-demoted state go unnoticed for a milestone. Two things this run also settles: `restart_budget` is back to 165 s (it had gone to 240 s while it was made to restore its leader, which was reverted), and `ca_rotate` no longer cares where leadership landed, because it now picks its target by raft role |
| 2026-08-24 | **Standalone verified end to end on alpha, which is the shape most first users will have: one machine, one public /32.** "Standalone" is a cluster of one (there is no other mode), and the whole path works: a one-shot `satl run` returns its output and exits clean; a published port answers **200 from another host**; `satl compose up -d` brings up two services on the node bridge; and `http://cache/` answers from inside the other task's jail, so **service discovery by name works on a /32 host** -- which is exactly what M11b promised and what api-compat #75's bridge half is for. `compose down` then leaves nothing: no jail, no tmpfs, no dataset. One measurement worth keeping for the next reader, because it looks like a leak and is not: the `cache` dataset survived `down` by about two minutes, with `zfs destroy` failing *cannot unmount*. That is the DYING-prison behaviour CLAUDE.md documents -- the task had served one HTTP request, so its VNET prison held a TCP connection and stayed `DYING` for `2 x net.inet.tcp.msl` (60 s here), keeping `pr_root` mounted. The sweep says so in its own warning ("it will try again on the next pass") and it did. Also confirmed on the way: a published port does **not** answer from the publishing host, on `localhost` *or* on its own public address -- api-compat #35 is about traffic originating on the host, not about the loopback name, and testing it from the host is how one mistakes the documented behaviour for a defect |
| 2026-08-24 | **The per-task tmpfs does not leak, measured -- the comment claiming it does predates its own fix.** `tests/cluster/run.sh` carried the only record of it: *"SatL leaks the per-task /tmp tmpfs of every container it removes -- a pre-existing defect the jail/epair/dataset audit cannot see"*, with no `api-compat.md` number and no user-facing mention. Settled on alpha, on containers that had been sitting since 2026-08-17 and survived several daemon restarts. Before: six tmpfs mounts, three jails, three datasets. `satl rm` on one of them, then the counts: **one jail, one tmpfs, one dataset -- the live `web` container and nothing else**. Jail, both tmpfs mounts (`/tmp` and `/dev/shm`) and the ZFS dataset all gone. The two extra containers were not orphans either, which is the part worth writing down: they were the two tasks of one `satl run` service, kept until the service was removed, because `satl run` *is* a service and its task history is the slot's (invariant #2) -- `satl ps -a` shows one and not the other for the same reason Docker hides superseded tasks. So: delete the comment rather than number the defect. What is worth keeping from it is the observation underneath -- a *completed* task holds an empty jail, two tmpfs mounts and a dataset until its service is removed, which is by design for `satl logs` and `satl ps -a` but is not free, and an operator who leaves finished one-shots around should know it |
| 2026-08-24 | **`sudo make integration` is green on the M12 tree, and the one test that "failed" was refusing to run.** Required by the definition of done because M12 touches the port-publishing path in `satld::reconcile`. First attempt stopped at `an_unhealthy_published_task_leaves_the_rdr_anchor_within_the_measured_bound`, which panics with its own instruction: *"another satld is running (pids ...); stop it for this test"* -- it needs the `satl/rdr` and `satl/nat` anchors to itself, and alpha runs a live daemon. Not a regression, a precondition, and the test says so in the message rather than failing on a mismatched rule count three lines later, which is the difference between a good and a bad assertion. With `service satld stop` the whole suite runs: **71 test binaries, 0 failures**. The daemon's re-adoption was checked on the way back, because that is what CLAUDE.md's upgrade rule turns on: same jail id (6), same uptime ("Up 2 weeks") before and after, so the container was re-attached and not restarted |
| 2026-08-24 | **The suite-independence fix produced its own flake, and the answer was to need less control, not more.** `require_leader` was written to give scenarios the primitive the suite never had: put leadership on a named node. It failed a run at four rounds -- and it deserved to. Raft has no "make this node lead" operation, so the helper stops the current leader and waits; that leaves **two** voters and either may win, which makes it a random walk with roughly even odds per round, not a command. A cap is a probability (4 rounds ~94%, 8 ~99.6%), and dressing it up as a guarantee is the same class of error as the assertions this milestone spent its time removing. Two consumers, two different fixes. `demote_leader` does not need a *particular* node at all -- it needs **the** leader, which `the_leader` names, deterministically and for free; forcing node1 to lead was solving a problem the scenario did not have. `restart_budget` was made to restore the leader it found, and that was reverted too: it turned a cleanup step into a coin flip that could fail the scenario, and the dependency it was meant to break is already fixed at the other end, where `ca_rotate` now picks its target by raft role instead of inheriting one. `require_leader` survives with the cap at 8 and a comment saying plainly what it is, for the one use where the point *is* to vary the starting leader across two runs |
| 2026-08-24 | **`CONTRIBUTING.md` and a CI gate, both absent until now.** With no CI, an outside contributor had no way to learn that `make check` is the gate, that `sudo make integration` exists, or that a networking change is expected to run it -- the rules lived in `CLAUDE.md`, which is addressed to an assistant, and in the maintainer's head. `.cirrus.yml` runs `make check` on FreeBSD for every pull request; Cirrus rather than GitHub Actions because there is no FreeBSD runner there and the workspace would not compile. The file states plainly what the tick does **not** cover -- `sudo make integration` needs real jails, ZFS, pf and `ocijail` on the machine, `make cluster-test` needs three hosts -- so a green tick is never mistaken for "this works". It is **unverified until its first run**: written from the documented format, against the newest FreeBSD image Cirrus publishes, which is not the 15.1 the project targets. One bug in it was caught before committing by reading the Makefile's own second line: it is bmake, so the first draft's `gmake check` would have failed immediately |
| 2026-08-24 | **Three more assertions that could not fail for the reason they name, found while fixing the rest.** The theme of M12 is a suite whose green does not mean what it claims, and it kept producing instances. **(1)** `build_push_run` failed a whole suite run on `cold build: 1s, warm rebuild: 2s` -- one second of ssh jitter, at one-second granularity, on builds far too short to measure -- and reported it as *"the build cache made things worse"*. The scenario already knew: it gates its 2x rule on `cold >= 8s` and says in a comment that the difference is "small and noisy". The "warm must not be slower" assertion simply was not gated with it. **(2)** `node_kill` chose its "non-leader" victim, and **(3)** `leader_kill` its kill target, from `satl node ls`'s `MANAGER STATUS` column -- which this same file documents in three places as written at cluster formation and never refreshed on a leadership change. In suite order both are safe by accident; standalone after anything that moved leadership, `node_kill` kills the leader and becomes a worse-asserted `leader_kill`, and `leader_kill` kills a follower and then waits out `T_ELECT` for an election that cannot happen. All three now read the raft role from the daemons' own logs. The lesson is not "these three were wrong": it is that an assertion whose failure message names a cause it cannot actually distinguish is worse than no assertion, because it spends a reader's afternoon on a regression that never happened |
| 2026-08-24 | **`satl --version` could not be trusted, and the mechanism is one line of cargo semantics.** `crates/satld/build.rs` emitted `cargo:rerun-if-changed=.git/HEAD`, and emitting **any** `rerun-if-changed` opts a build script out of cargo's default "re-run when any file in the package changed". So a source change rebuilt the binary without re-running the script, and the new binary carried the previous build's timestamp -- observed as a binary rebuilt at 07:38 reporting `Built: 2026-08-23T11:35:34Z`, which cost real time because the deployment looked like it had not happened. The file's own comment named the trade-off ("tracking the ref file too would rebuild on every commit") and picked the wrong side of it: rebuilding on every commit is exactly what a build stamp is for. Now three signals -- the crate's sources, `.git/HEAD`, and the ref `HEAD` points at -- so a rebuilt binary always gets a fresh timestamp and a commit always moves the sha. Verified by touching `main.rs` and reading the stamp out of the binary: 20:58:07 -> 20:58:29 |
| 2026-08-24 | **`swarm init --force-new-cluster` is now refused by the CLI, in the daemon's own words.** The flag existed in clap and the daemon answered a permanent 501, so an operator spent a round trip to learn that a documented flag never works. Dropping the flag was the alternative and is worse: it would answer "unexpected argument", which teaches nothing, where the 501's text names the two real recovery procedures. The CLI now carries that same text and its `--help` says NOT IMPLEMENTED, so whichever end says no, the operator reads one sentence and finds one procedure in `docs/operations.md`. Pinned by `init_refuses_force_new_cluster_locally`, which asserts the daemon was **never asked** |
| 2026-08-24 | **The overlay-on-a-/32 error blamed a bug that does not exist.** `OverlayManager` collapsed "no advertise_addr", "the underlay could not be measured" and "adoption has not happened yet" into `identity: None`, so every attach failure read *"This is a start-up ordering bug in satld, not a configuration problem"* -- including the case where satld had already said at boot that it was degrading on purpose, because a public /32 yields no VXLAN blackhole (docs/vxlan.md §2). A single public address is the ordinary shape for a first-time user, so this was the first message many would ever see, and it sent them after a race that was not there. The reason is now data (`NoIdentityReason`), and the three cases say three different things; the degraded one names the boot warning, says bridge networks and `satl compose` are unaffected, and says `satl stack` and multi-node need a real underlay |
| 2026-08-24 | **"A demoted node stops publishing ports" is mostly documented behaviour, and the part that is not is a convergence delay -- measured, with the demote fix finally making the case reproducible on purpose.** Until `satl node demote` on a leader completed, this defect could only be met by accident; with Phase 2 in, it can be set up deliberately, and three measurements separate what is a bug from what is not. **(1)** A demoted worker with **no** local replica: `pfctl -sA` lists `satl` and `satl/nat` only, `satl/rdr` is absent, and the published port does not answer (`curl` returns 000 where the managers return 200). That is exactly what **api-compat #75** already promises -- *"a worker keeps the pre-mesh behavior: with no store replica it cannot compute the cluster-wide pool, so on a worker only a local replica is answered"* -- so it is the design, not a defect. **(2)** The same node with a running published replica pinned onto it: the anchor is back, one `rdr` rule, and the port answers 200. So a worker does publish what it runs; the "stops publishing" framing is wrong. **(3)** What is left is timing and blindness. The sweep is level-triggered on a 5 s tick and only *forces* a re-assert every twelfth pass, and a role change swaps the whole derivation (store → local task db) without `reconcile_after_bringup` running, so the anchor could take up to a minute to be re-derived -- against `ca_rotate`'s 60 s assertion. Worse, `reconcile_ports_over` logged **only** when something changed, so a pass computing a steadily-empty set said nothing at all, which is why the evidence read as "nothing publishes after it" and could not distinguish a dead sweep from a legitimately empty one. Fixed both: `satld` notifies the sweep whenever it republishes the cluster core (join, leave, promote, demote) and the pass is forced, and an empty set now logs once per forced pass naming its source (`store` or `task_db`). The remaining open question is whether `ca_rotate` should assert mesh behaviour on a node it has just demoted at all -- per #75 it may only assert it for a node running a local replica, which the scenario's 6-replica spread does guarantee |
| 2026-08-24 | **The leadership transfer works on the real fabric -- 62 ms and 14 ms, measured -- and fixing it exposed a second defect underneath: demotion's phase 2 writes the role from a store that has stopped moving.** Two runs on the 3-VM testbed with the M12 binaries: `asking openraft to transfer leadership` → `leadership handed over` in **62 ms** (19:37:42.835 → .897) and **14 ms** (19:54:32.846 → .860). Against the old code that second line appeared **0 times in 10 attempts** and the call retried for ever, so this is the defect closed, on the fabric and not only in loopback. What it uncovered: `satl node demote` then failed with `sequence conflict on node ...: store has version 1185, caller wrote from version 1081`, leaving the node **out of consensus with its manager role intact** -- the half-demoted state the phase ordering exists to prevent. A retry from a fresh read was added and is not enough, which is the interesting part: phase 1 removes the node from consensus, so when the node being demoted is also the one serving the request, **its applied store stops receiving replication** and every re-read returns the same stale version. Measured: the retry loop spent its whole 10 s budget re-reading version 25 while the leader was at 45. The fix has to be structural -- the leader owns the store that is still moving, so the role write belongs on the leader side of `Control.LeaveRaft`, which is also what SWK §11.5 implies ("only the leader removes members"). Unscheduled inside M12 Phase 2. Two operator traps worth knowing meanwhile: a half-demoted node's raft id is already blacklisted, so `satl node promote` on it answers "promoted" while the node can never rejoin (it needs its raft directory wiped and a fresh join token), and the quorum guard correctly refuses a demote on a freshly formed cluster until liveness has observed the other managers |
| 2026-08-24 | **`ca_rotate` went green on the M12 testbed run, and that is the coin landing the other way -- not the demote defect being fixed.** The run was made with the binaries built *before* the leader-demote fix, so nothing about the demote path had changed. `restart_budget` ended with `cluster left with 3 managers Ready, leader node2`, so `ca_rotate`'s hardcoded target fbsd3 was a **follower** and the demote took 1s. This is LAUNCH-TODO §2.1 reproduced live inside the run that was meant to validate something else, and it is the sharpest argument for Phase 4 there is: the scenario's verdict is decided by where its predecessor happened to leave leadership, so a green tells you nothing about the case that actually breaks. Do not read this suite run as evidence for Phase 2; Phase 2's evidence is `a_leader_demotes_itself_under_write_load`, which was verified to fail against the old implementation |
| 2026-08-24 | **A pre-existing `make check` test flaked once under load, and the race it exposed is real but benign.** `three_managers_form_replicate_and_survive_losing_the_leader` failed at "the new leader accepts proposals" during a `make check` that ran while the cluster suite, ssh sessions and a full workspace build competed for the machine. Not reproduced in eleven subsequent runs, eight of them under deliberate CPU contention -- so it is rare, and the temptation was to call it noise. The mechanism is not noise: `is_leader()` reads a metrics flag set when the node *wins* the election, but a raft leader cannot serve writes until the blank entry it appends on election has committed, and leadership can move again in between. A propose in that window returns `NotLeader`, which is the protocol working. The test now retries **only** on `NotLeader` and fails at once on anything else, so it still tests "the new leader accepts writes" instead of becoming a retry that would swallow a real regression. Recorded rather than quietly fixed because `make check` is the only gate: a flake in it costs more than the test it hides |
| 2026-08-24 | **openraft 0.9.25 has no leadership-transfer call at all, and the 2026-08-24 entry below that says it does is wrong.** Read out of the vendored source before starting M12: `Raft::trigger()` exposes only `elect/heartbeat/snapshot/purge_log` (`openraft-0.9.25/src/raft/trigger.rs:45-79`) and `grep -ri transfer` over its `src/` returns nothing relevant. No workaround exists inside 0.9 either -- `handle_vote_req` (`src/engine/engine_impl.rs:282+`) rejects a vote while **the receiver's own** committed vote is inside the leader lease, which blocks even openraft's documented "node-a electing for node-b" trick for as long as the leader keeps replicating. Two independent reasons `yield_leadership` could never work, both from the source: a follower's first campaign is `leader_lease + election_timeout` after last contact and `leader_lease == election_timeout_max` (`engine_config.rs:46-57`, `raft_core.rs:1471-1479`), i.e. **30-40 s** at SatL's 1 s/10-20 s timings against a 35 s budget; and `tick(false)` does not stop replication, while every AppendEntries refreshes the follower's lease through `VoteHandler::update_vote`'s `vote.touch()` (`vote_handler/mod.rs:110`), so on a daemon that writes node and task status continuously the leases never expire. openraft says as much itself at `raft_core.rs:1204-1208`. The fix is therefore the upgrade, not a patch: 0.10 broadcasts a `TransferLeaderRequest` that disarms the lease for the designated target |
| 2026-08-24 | **`Arc`'s strong count reaching zero does not mean the value's `Drop` has finished, and that cost a green test suite.** Found while migrating to openraft 0.10, whose `Raft::shutdown()` joins its core task but not its state-machine worker or replication tasks -- each of which holds a `LogStore` clone, so shutdown can return while redb still owns the log file and the next `Database::create` fails with `DatabaseAlreadyOpen`. This matters in production, not only in tests: `satld` shuts the manager runtime down and rebuilds it on **every role change**, so a demote racing this leaves the node unable to open its own raft state. The first fix watched a `Weak<Database>` and waited for `strong_count() == 0`; `tests/autolock.rs` still failed, and the probe said why -- `released=true` and `Database::create` refused **in the same breath**. `Arc` decrements the counter *before* running the inner `Drop`, so the count reports "gone" while `Database::drop`, which is what releases the lock, is still executing on the thread that dropped the last clone. The shipped mechanism is a flag set by a `DbHandle` wrapper strictly *after* it has dropped the database, which is the only ordering that means what the caller needs. `RaftNode::shutdown` waits on it for up to 5 s and logs, rather than errors, on timeout: shutdown has done all it can, and a caller that never re-opens should not fail for it |
| 2026-08-24 | **A demoted node stops publishing ports, measured; `ca_rotate` has been passing on leftover state.** The second order-dependent defect the M11 verification runs surfaced, and like the first it is **unrelated to M11**: the port paths (`satld::reconcile`'s sweep, `satl_net::manager`'s publish) are untouched by that work -- the only edit to `satl-net` is two read-only accessors. Reproduced twice: after `ca_rotate` demotes fbsd3, the manager reports `rotca.2` and `rotca.4` `Running` there and `jls` confirms both jails exist, but `pfctl -sA` on that node lists only `satl` and `satl/nat` -- **the `satl/rdr` anchor is absent** -- so its published port answers nothing and the mesh assertion times out at 60s. The node's last `published ports converged` line predates the demote by ten minutes; nothing publishes after it. Note the diagnostic trap met on the way: `satl ps` on a demoted node prints an empty table, because a worker has no store to read from, which reads as "no containers here" and is not (invariant #1, api-compat #80) -- `jls` is the ground truth. Why the suite passed before: the preceding scenario used to leave published rules on that node which the demote did not clear, so the anchor was already populated; in the failing runs the previous scenario had emptied it (`published=none`) first. Unscheduled, and it wants the same treatment as the demote defect: fix the path, and make the scenario assert the case deliberately instead of inheriting it |
| 2026-08-24 | **`satl node demote` on the *current leader* never completes, measured; the cluster suite has been passing it by luck.** Found during M11d verification and **unrelated to M11** (`satl-cluster` is untouched by that work). `ca_rotate` always demotes fbsd3, and whether that is the leader depends on where the previous scenario, `restart_budget`, happened to leave leadership: the passing run of the same suite two hours earlier logged `cluster left with 3 managers Ready, leader node1` and the demote took 0s; the failing one logged `leader node3` and the demote timed out at 180s. On the failing path `satl_cluster::membership` logs `asked to remove the current leader; handing leadership over first` and `yield_leadership` never returns — **10 attempts, 0 `leadership handed over` lines** on that node. `yield_leadership` stops the raft tick and then waits for another node to claim leadership within its budget; on this fabric that election does not happen, so every retry re-enters the same path. Two things follow, both unscheduled: the demote path needs a real handover (openraft has a leadership-transfer call; waiting for a spontaneous election is what fails), and the scenario should pick a demotion target that is *not* the leader, or assert the leader case deliberately rather than meeting it by accident. Worked around for the M11d run by moving leadership to fbsd2 before the suite, which is also the confirmation: with a follower as the target the demote is instant |
| 2026-08-24 | **`satl compose` carrying stack semantics was an inference, not a consequence, and M11a reverses it.** api-compat 110 read "SatL has no standalone container" (invariant #2) as forbidding a node-local compose. It does not: invariant #2 fixes the execution model, and Docker's two worlds differ in scope. The split costs no invariant, adds no REST route, and lives entirely in `satl-cli` plus docs. Two properties read out of the code decided the design rather than taste. **The CLI speaks `unix://` only** (`client.rs`, `only unix:// sockets are supported`), so under a node-local scope the client's filesystem *is* the target node's, which is exactly the reason relative binds were refused (`plan.rs`, "this client's filesystem and not the nodes'") — so the refusal had to go, not be kept out of caution. And **`force_update` already dirties everything** (`satl-orchestrator::dirty`, pinned by `force_update_dirties_everything`), which is what M11c's `compose restart` will use, so restart-as-replacement needs no new mechanism. The regression guard chosen for the whole milestone: every compose planner test written before the split runs untouched under `Scope::Cluster`, so `satl stack`'s output is pinned byte for byte by 400 pre-existing assertions rather than by new ones |
| 2026-08-24 | **The overlay-for-compose choice survived one live test and no more, and the host that killed it is the ordinary one.** M11a first shipped compose on a single-node overlay, on the reasoning that only the overlay driver carries DNS. Deploying it on alpha failed: every task looped through `Failed` with `no cluster identity yet ... This is a start-up ordering bug in satld`, which is a **misleading message for a deliberate degradation** — alpha's address is a public **/32** (`netmask 0xffffffff`), no VXLAN blackhole can be derived from one (docs/vxlan.md §2), and satld had already said so at boot: `cannot measure this node's underlay, so it can host no overlay network; bridge networks are unaffected`. So a node-local compose on an overlay is dead on precisely the host shape a node-local compose is for: one machine with one public address. **Proven independent of the M11a change** by deploying the same file through `satl stack deploy`, whose code path was untouched, and watching it fail identically — the discipline that mattered here, because the symptom looked like a regression. The measured alternative was no better as it stood: a service on a bridge network ran, but its task got a copy of the host's `/etc/resolv.conf` (`nameserver 213.186.33.99`, the upstream provider's) and `nslookup <service>` returned NXDOMAIN. Hence M11b: fix the driver rather than route around it |
| 2026-08-24 | **Bridge DNS needed no new source of truth, because a node-local network has no remote half.** The obstacle looked structural: a bridge address never reaches Raft (architecture §11.1, measured — a bridge task's `NetworksAttachments` carries no `Addresses`), so neither the store nor the dispatcher's endpoint tables can describe one, and both the endpoint records and the query scopes are built from those. But every task on a node-local bridge is local *by construction*, so the node's own IPAM is not a partial view, it is the whole one: `NetworkManager::address_of` supplies what the store cannot, and the record is derived field for field the way `satl_dispatcher::manager` derives an overlay endpoint, so one name means one thing on either driver. Three smaller things had to move with it. `resolv_conf` demanded an overlay identity before looking at what the task attached to, so on a node that hosts no overlay it fell through to the host's file for *every* task — the same shape as the bug `a_task_on_no_overlay_starts_on_a_node_that_has_no_overlay_identity` already pins for `attach`. `apply_network` returned early for a bridge network without refreshing the responder's bind list, so a node hosting only bridge networks never bound a socket at all. And the bind map's value became an owner enum, because one bridge gateway serves every bridge network on the node while an overlay gateway serves exactly one. Verified live on alpha after a package upgrade and a restart that re-adopted all three running jails at their existing jids: both services `Running`, `satl network ls` showing `bridge`/`local`, `resolv.conf` reading `nameserver 10.88.0.1`, the compose alias `cache` resolving to 10.88.0.6 in one direction and `web` to 10.88.0.4 in the other, and ping between them at 0% loss |
| 2026-08-23 | **Every one-shot `satl run` executed its command twice, and nothing user-visible said so.** The mechanism predates M10, it is the composition of M1's autostart contract with M7's abandoned-slot fill: `start_container` flips the `satl.autostart` label, which bumps `spec_version` without touching the task spec; the task completes carrying the old version; the updater then saw an untouched slot whose only task was finished, unreplaceable by any restart policy and at an old version, and filled it with a replacement at the current spec, which re-ran the command. Measured in /var/log/messages on the formed 3-node cluster and on single-node alpha alike: the first task Complete, then a replacement task prepared and started, `uname -a` executed twice. Invisible because the foreground CLI attaches to the first task's logs and exits on its completion, so the second run happened after the output was printed and the exit code returned. The fix makes the fill consult the deep dirtiness the dirty module already computes (`is_task_dirty`, whose own doc warns that a false dirty replaces containers for nothing): a finished task whose spec matches the current one is the converged state of a one-shot service and its slot is nobody's to fill, while a deep-dirty finished task, a real update over a dead slot, is still filled. Regression test `an_annotations_only_bump_does_not_refill_a_finished_slot` drives the planner through the real store |
| 2026-08-23 | **`satl run` now pins its anonymous service to the receiving node (api-compat 168).** Docker parity: `docker run` always runs on the engine you spoke to, and the tutorial is written against that promise. Measured on the formed 3-node cluster: the anonymous service had free placement, the scheduler put the task on another node, and the foreground `satl run` printed nothing (logs are node-local, api-compat 81) and exited 0. The pin is a `node.id==<id>` constraint written into the service spec by the receiving daemon before the mutation is forwarded to the leader, so a worker pins to itself, never to the leader; `satl service create` keeps free placement |
| 2026-08-23 | **Two test-infrastructure defects only a fresh host could reveal, both measured during the M10 verification.** The `daemon.rs` integration test wrote a config that isolated its satld's socket, state, network name and ZFS root, and not its ports: the default `listen_addr` is 0.0.0.0:2377, which the production daemon on the dev host already holds, so the test's satld exited at cluster bring-up with `Address already in use`; it now listens on a loopback port of its own. And `provision.sh` installed `linux_base-rl9` in its packages step, before its own linuxulator step ran: the package's pre-install script refuses on a kernel without 64-bit Linux support, so `SATL_WITH_LINUX=1` provisioning failed on any node that had never loaded the modules, which every node provisioned so far happened to have loaded already. The linuxulator step now precedes the packages |
| 2026-08-23 | **`kldload linux` alone is a half-enabled linuxulator, and the probe cannot tell: it loads `linux_common`, which provides `compat.linux.osrelease`, but neither `linux64.ko` nor `kern.elf64.fallback_brand=3`, so the node advertises the capability while every 64-bit binary dies with `Exec format error` from ocijail.** Measured on fbsd3 during the M10 live verification: `kldload linux` flipped the re-probe to available within 10 s, `satl run alpine` then failed at exec; `service linux onestart` fixed it without touching satld. The two operator hints (the startup line's negative arm and the sweep's became-unavailable warning) now say `service linux start`, which loads all three modules and sets the fallback brand, matching what the user documentation already tells the reader. Probing something stronger than the sysctl was rejected: `osrelease` is the documented capability marker, and enumerating kernel modules would couple satld to module names the base system is free to reshuffle. The same half-loaded state also blocks the reverse test in place, `linux_common` stays busy under linprocfs mounts a dying prison still holds, which is the jail-teardown behavior docs/jail-teardown.md already records |
| 2026-08-23 | **The package's post-install message was the only spelling of `zfs create` in the tree still missing `-o mountpoint`, measured as a real trap during the 2026-08-23 doc validation**: a bare `zfs create zroot/satl` mounts the dataset at `/zroot/satl` and satld then warns that `state_dir` differs from the dataset's mountpoint, so the one command the message exists to hand an operator produced the first startup warning. Fixed together with the rest of the packaging polish: the package now ships the three man pages (gzip `-9n`, no name or mtime in the gzip header) and `share/licenses/satl-<version>/` in the ports-tree layout (BSD2CLAUSE, LICENSE, catalog.mk, field set mirrored from the installed ocijail's catalog.mk minus its distfile line); the plist is now rendered from `packaging/pkg-plist.in` because `pkg create -p` substitutes nothing and the license path carries the version; and `satld.toml.sample` gained the two keys the daemon accepted but the sample never mentioned, `cert_validity` and `overlay_blackhole`. **Measured along the way: gzip `-n` alone does not make the package hash reproducible**, two `make package` runs still differed because `pkg create` records the staging tree's fresh mtimes in the archive, while the same staging tree repacked gave the same bytes; `pkg create -t` now pins the archive timestamps to the last commit's time, and two runs write an identical `CHECKSUM.SHA512`. Follow-up owed to satl-doc: its `make gen` copies the sample, so it needs a regeneration pass |
| 2026-08-23 | **The man pages are hand-written mdoc rather than generated, and three tests pin them to the code so they cannot drift silently**: satl.1's COMMANDS list must be set-equal to clap's subcommands with each verb's one-line about present in its entry, satld.8's flags must match the visible clap surface in both directions, and satld.toml.5's `.Ss` keys are extracted from serde's own deny_unknown_fields error message, so `ConfigFile` stays the single source of truth with no parallel key list to maintain. `mandoc -T lint` runs inside `make check` (at `-W warning`: the pages cross-reference each other before any is installed, which the default level flags as style; a deliberate mdoc error still exits 3, verified). A generated page was rejected: clap renders help, not mdoc, and the openapi.rs regenerate-and-diff precedent needs a generator worth trusting; here the tests carry the whole anti-drift burden instead. One fix fell out: the `satl stack` about carried an em dash, which the ASCII-only rule for operator-facing text forbids and the about-match test would have forced into the page |
| 2026-08-23 | **`kldload linux` after satld started did nothing until a restart: the probe ran once and was copied into two immutable places.** The probe result now lives in one shared `LinuxEmulation` handle read by the executor's prepare gate and platform policy and by the node describer; a third node sweep re-probes the sysctl every 10 s and logs transitions in both directions, and the existing 20 s description refresh re-registers the session on change, so the cluster sees the flip within about 30 s with no dispatcher change. Verified that nothing cluster-side schedules on `NodeDescription.linux_emulation`, so a negative transition needs only the node-local gate, which now reads live; the kernel refuses to unload linux.ko under running linux processes. racct stays probed once, `kern.racct.enable` is a boot tunable |
| 2026-08-23 | **A `satl run` whose task failed image or platform resolution on the node left the anonymous service and a Dead task behind**, and `satl service ls` showed it forever; the create-time rollback only covers no-task-within-5s. Fixed at the layer Docker fixes it, the CLI: the wait body's `Error` now means exactly "terminated without an exit code" (the daemon stopped filling it for plain non-zero exits, a parity bug that made `satl run false` report a daemon error instead of exiting 1), and on that signal the foreground CLI removes the service it created, the same DELETE `--rm` uses. A daemon-side reaper was rejected: it would erase the evidence an operator diagnoses with and would have to interlock with the restart supervisor, whose on-failure condition covers Rejected. Detached runs keep the async failure, recorded as api-compat #167 |
| 2026-08-23 | **The PLATFORM column was empty for any container whose spec spells the image informally, which is nearly all of them.** `image_platforms` keys its map on the pulled image's canonical reference while `resolved_platform` looked it up by the raw `task.spec.container.image`, so `alpine` never matched `docker.io/library/alpine:latest`, another instance of the one-rule-two-callers reference-key family (`list_images`, 2026-08-19). The rule now has one home, `satl_image::canonical_key`; the existing tests were tautological, keying the map on the raw spec string, and are rewritten to fail against the old code. The honest-empty cases stay empty on purpose: a task whose image this node never pulled has no resolved platform to show |
| 2026-08-19 | **An endpoint with no CLI verb has no user, and nothing exercises it end to end.** The M9 audit went looking for why an image could not be deleted and found five capabilities the daemon has served since M1-M2 that **no client reaches**: `GET /events`, `GET /info`, `GET /volumes/{name}`, the `node` filter on `/tasks`, and all four prune endpoints. `/info` was invisible because the CLI called it internally in five places without ever exposing it; `/events` was invisible because nothing called it at all. The rule to keep: a route that no verb drives is a route no test drives either, and the gap will be found by an operator rather than by the suite |
| 2026-08-19 | **`list_images`' `Containers` count was structurally zero for exactly the images most likely to be in use**, found while building the removal's conflict check, not by a test. It keyed the in-use map on the raw `task.spec.container.image` and looked it up by the record's canonical reference, so a service whose spec says `alpine` never counted against `docker.io/library/alpine:latest`. `untag_unused_images` had always got this right, inserting both spellings, which is precisely the kind of divergence that two copies of one rule produce. The fix was to make it one copy: `image_claims` reads the claim set, `image_conflict` answers the question, and `list_images`, `POST /images/prune` and `DELETE /images/{name}` all call them, the same "one rule, two callers, one of them drifts" family as `remove_network_impl`/`prune_networks_impl`, and now the third instance resolved the same way |
| 2026-08-19 | **`satl images rm` costs about 1.5 s by construction, and that is the price of #131 rather than a slip.** A targeted removal has no more right to a single reading of the claim set than a prune does: a layer's loss is recoverable only from a registry that may not answer. So the removal runs the *same* `collect_layers`/`collect_content` the prune runs, two readings `SETTLE` apart, and `--no-prune` is the documented way to pay that cost once for a batch instead of once per image. **Measured 2 s wall on fbsd1** for an image reachable from two references (`satl images rm -f` by ID prefix, 5 items reported, 1374 bytes reclaimed, 0 deferred): the 1.5 s settle plus process start and the sweeps. Two things the API forced: Docker's rmi body is a bare array with no field for what the second pass deferred, so it rides on `X-Satl-Deferred-Layers` (a third field would corrupt a real Docker client's output, moby prints a bare `Untagged: ` for an item with neither field set); and the image-ID form has to be recognised *before* `ImageReference::parse`, because `sha256:abcdef` parses happily as `docker.io/library/sha256:abcdef` and would resolve to nothing |
| 2026-08-19 | **The cluster testbed was replaced, and the underlay changed shape: 10.2.0.0/16 became 10.0.0.0/24.** The `fbsd-dev---N.fredalix.ovh` VMs no longer resolve at all; the replacements are `fbsd{1,2,3}.satl.cc` (same spec: FreeBSD 15.1-p2, 4 vCPU / 8 GiB, zroot 48.5 GiB) and they arrived bare, no satl, no ocijail, no registry, `kern.racct.enable=0`. `inventory.toml` was the only file that had to change for addresses, which is what it exists for; `provision.sh` → `deploy.sh` → `images.sh` → `run.sh` then worked unmodified, the cluster forming in 13 s and **all 22 scenarios passing on the new fabric** (~26 min wall clock), plus all 7 of `encrypted.sh`, the rotation scenario walked `generate -> append -> promote` and the outbound SPI moved from 0x1b026082 to 0x13faadaf, leaving 3 SAs as designed. **The narrower mask is not cosmetic**: satld derives the VXLAN blackhole remote from the underlay prefix as its last usable host (`underlay::blackhole_in`), so the value moved from 10.2.255.254 to **10.0.0.254**, measured free on this fabric (silent to ping, ARP incomplete), and the only other live host on the /24 is 10.0.0.11, the OpenStack metadata helper. Nothing in the code needed changing for it: `parse_netmask` is generic and `blackhole_in` refuses only prefixes narrower than /29. Underlay latency re-measured at 0.76 ms and 0.86 ms average over 30 packets, no loss, so the README's "sub-millisecond" claim still holds; the underlay MTU is still exactly 1500 (a DF ping of 1472+28 crosses, 1473 does not), so the measured overlay figures are unchanged and `encrypted.sh` confirmed them at the bit, 1450 plain, 1416 encrypted. One transient: `images.sh`'s `ssh -R` tunnel dropped mid-seed on one node (`connect_to 127.0.0.1 port 5000: failed`) and a re-run of that node alone fixed it, the idempotence the script advertises. `docs/vxlan.md`'s FDB capture still shows 10.2.x addresses and was deliberately left alone, it is recorded measurement, not a claim about the current fabric |
| 2026-08-19 | **`make package` now also writes `dist/CHECKSUM.SHA512`**, so a `.pkg` handed to an operator out of band (no repository, no signature) can be verified before `pkg add`. Format is sha512sum(1)'s, not a ports `distinfo`, because the consumer-side command is what matters: `sha512sum -c CHECKSUM.SHA512` from inside `dist/`. It lists only the package that run built and is rewritten each time, so a `dist/` holding several versions describes just the last one. Not yet run on the FreeBSD host, `make package` needs `pkg create` and a release build |
| 2026-08-17 | **`v0.1.0-beta` tagged, with a CHANGELOG, a SECURITY.md and the absence of CI stated in the README.** The repo had one commit, no tags and nothing release-facing: the whole M0-M8 history lived in this gitignored file, a project advertising mTLS/CA/secrets/autolock offered no reporting address, and a contributor opening a PR saw an empty checks tab with no way to tell a broken pipeline from a deliberate choice. `CHANGELOG.md` is one release entry grouped by area (containers, cluster, networking, images, security, compatibility) plus an honest known-limitations list, drawn from this file's measured milestones; `SECURITY.md` points at security@satl.cc and, more usefully, lists the *deliberate* choices a reporter would otherwise burn a week on (2378 unauthenticated by design, no user-level authz in v1, root daemon, unauthenticated `/metrics`, handshake-time identity). **`Cargo.toml` stays at `0.1.0`**, the beta qualifier lives on the git tag only, because a hyphen in a pkg(8) version is the name/version separator and `satl-0.1.0-beta.pkg` would parse as name `satl-0.1.0`, version `beta`, breaking `make package`. Tag is annotated and local; pushing is Frédéric's call. Three things this surfaced and did *not* fix: the README's `docs/*.md` and `CLAUDE.md` links all 404 on GitHub (both trees are gitignored), `architecture.md` §12.4/§14 still call autolock/KEK deferred though M7f shipped it, and `/tests/` being gitignored means a contributor cannot run the `make cluster-test` the README points them at |
| 2026-08-17 | **The 2026-08-16 external audit (N1-N8) is landed in full.** N1 made the restart supervisor's `Delay` admission default 5 s (a zero delay restarted crash-looping tasks in a hot loop); N4 added a startup purge of orphaned rctl rule sets and corrected what `rctl -r`'s ESRCH means, "the filter matched no rule", not "the jail is gone" (measured on node1; `is_missing_jail` renamed to `is_no_rule_matched`); N2 added `satl tag`; N3 turned the raw registry 404 into a manifest-unknown message and made `satl build` warn when its base image is missing; N6/N7 were help and CLAUDE.md text fixes; N8 added five cluster scenarios, including the B1 non-regression; and N5's residual was the satl-doc M7b/M8 catch-up. Findings that were misunderstandings of the code were rejected in review rather than patched |
| 2026-08-16 | **Encrypted overlays: ESP expansion is 34 bytes, and each encrypted network gets its own VTEP port from 4790..=4999.** Measured (`hack/experiments/esp/`): ESP/aes-gcm-16 transport mode adds 34 bytes (SPI+seq 8 + IV 8 + pad-len/next 2 + ICV 16, plus 0-3 alignment pad) on top of VXLAN's 50, so the encrypted overlay MTU is underlay − 84 = **1416**, inner IP 1417 already fragments, and the outer DF is clear, so only the fragmentation counters ever say so. Ports are per network because the FreeBSD SPD can match neither the VNI (it sits inside the UDP payload) nor the outer source port (`if_vxlan` hashes it per flow, and pinning it with `vxlanportrange` would defeat the cleartext guard, next entry): the port is the only per-network selector available, so the SP source selector is `[any]`, which is libnetwork's choice too and keeps the source-port entropy an underlay's ECMP wants |
| 2026-08-16 | **Cleartext injection is blocked by pf, not by the SPD: an inbound `require` policy does not drop unprotected packets on 15.1.** Measured: cleartext VXLAN to an encrypted port is decapsulated and answered while `netstat -s -p ipsec` records no violation, ipsec(4) checks inbound policy only against packets handled by IPsec, and only the outbound direction fails closed. The guard is the `satl/guard` anchor (block the encrypted ports on the underlay, pass them decapsulated on `enc0` with `net.enc.in.ipsec_filter_mask=2`), and both qualifiers are load-bearing, each with its own measurement: `no state` on the pass rule (pf consults the state table before the ruleset, so a stateful pass creates the very floating state that lets same-tuple cleartext bypass the block) and an unpinned VXLAN source port (pinned, the pass-all main ruleset's own reply state reverse-matches inbound cleartext, and no rule of ours can prevent it) |
| 2026-08-16 | **ESP key rotation: the old SA's deletion is the promoting step.** The kernel emits with the first-added matching SA and offers no other way to select among equal SAs, so after the new outbound SA is added the wire still shows the old SPI until the old SA is deleted, the 3-phase append → promote → prune design stands, with "promote" inert on the wire until the prune's delete. The node reconciler applies every add before any delete for exactly this reason (the order *is* the rotation protocol), and phase skew across nodes is tolerated because a peer's old inbound SA stays until it prunes. Measured cost of a full rotation under a 250-packet flood: 3 lost, one gap |
| 2026-08-16 | **setkey lives at /sbin/setkey on FreeBSD 15**, found by the encrypted-dataplane integration test's first live run, not by the mocks: the wrapper's original `/usr/sbin/setkey` does not exist on 15.0 or 15.1, so every IPsec call in the daemon would have failed to spawn. Same class of fact as `ifconfig`'s missing `vxlanroute` parameter: binary paths and parameter names are platform facts to verify live, not to assume |
| 2026-08-15 | **A container that exits within milliseconds can lose its final stdout in `satl logs`, found, not yet root-caused.** Measured during the M8c E2E: the same image printing two files via `cat` logs them when the process lingers (`cat; sleep 2`) and loses them on an immediate exit, repeatedly, on a service task. The sinks are plain files handed to `ocijail create` (no pipe on SatL's side), so the loss is inside ocijail's stdio wiring for fast-exiting init processes. Pre-existing, and it matters most for the M7e jobs, whose whole point is printing and exiting. Investigate in ocijail before claiming job logs reliable |
| 2026-08-15 | **A task that failed transiently poisons every later resume of the same update.** The updater counts failed *current-spec* tasks across update attempts, not per attempt: a v2 task rejected by a transient `zfs … dataset is busy` during the M7g tutorial paused the rollout, and re-pushing the same spec re-paused instantly on the same corpse. The recovery is a spec bump (any label), a new `spec_version` starts a clean count. Not fixed: a "failures of *this* update" counter needs the update to have an identity of its own, which the level-triggered updater deliberately does not keep. Documented in the tutorial's pause note; worth a real fix if it bites again |
| 2026-08-15 | **A SatL jail has no `127.0.0.1`**, its `lo0` carries only `::1`, so Docker's canonical `curl http://localhost/` healthcheck cannot connect (measured during the M7g tutorial: `EADDRNOTAVAIL`; `::1` answers). Probes must target the task's own interface address; the runtime base has no `awk`, so the doc's reference probe is pure shell. Not a bug to fix lightly: assigning 127.0.0.1 in every VNET jail is a platform decision with its own edge cases (a jail binding 127.0.0.1 is not the host's), so it is documented instead, `satl-doc`'s healthchecks page |
| 2026-08-14 | **Vertical resize is hot; `rctl -a` stacks, it does not replace.** A resources-only service update mutates the live tasks' specs in place (the one breach of task-spec immutability, architecture §4 rule 4) and each node's agent re-writes the jail's rctl rules, no roll, because a roll for a memory cap is an incident for a database. Two measurements drove the shape: `rctl -a jail:x:memoryuse:sigkill=N` twice installs *both* rules (the older cap stays armed), so the re-apply is remove-then-add; and the assignment applier keyed on desired state alone, so the resize channel is (desired state, resources), the only spec field besides desired state a worker can act on. The shrink-below-usage hazard is a warning, not a refusal: usage is node-local and the manager writing the spec cannot see it (api-compat #147) |
| 2026-08-14 | **Jail parameters pass through as container labels: `satl.jail.<param>=<value>` → the OCI annotation `org.freebsd.jail.<param>`.** The M6f postgres build forced it: the kernel disables SysV IPC in jails and PostgreSQL cannot `initdb` without it (`shmget(key=2, size=56)` → `ENOSYS`, measured on the cluster). ocijail already had the annotation surface and satl-runtime already had `extra_jail_annotations`, what was missing was a user-reachable path, and a label is the only Docker-compatible one (unknown spec fields are a 400, api-compat #50). The pass-through is generic rather than a `sysvipc` boolean because ocijail warns-and-ignores what it does not know, and no privilege boundary is crossed: whoever can create containers can already bind-mount the host into a root-owned jail (api-compat #145) |
| 2026-08-14 | **`satl kill` on a service task retires the slot for good, documented, not fixed.** The M1 kill path writes `desired=shutdown` to the store, which is indistinguishable from an intentional stop: the restart supervisor only restarts terminal tasks the cluster still wants (`desired=running`), and the replicated orchestrator never refills a `Held` slot, so the service sits at 0/N until a spec change or a scale dance. Docker's kill never touches desired state, the container dies, the task fails, the supervisor replaces it, and matching that needs an agent-side signal channel SatL does not have. Found during the M6f postgres persistence check; the workaround used there (and the honest "container restart" test anyway) is an abrupt jail death: `jail -r` on the host, which the agent reports as terminal against `desired=running`, and the replacement came back with the volume's data. Recorded in api-compat #146; fixing it properly is a design conversation, not an M6f drive-by |
| 2026-08-13 | **Table-backed rdr pools: the ruleset is static, membership is dynamic.** The pf pool-type matrix was measured on 15.1 (`pfctl -nf -`, nothing loaded): `rdr -> <table> round-robin` and `-> <table> source-hash` accepted; `-> { a, b } source-hash` rejected (`route.opts must be ROUNDROBIN`); weights rejected; `least-states` is a syntax error; an empty `table <t> persist` with an rdr targeting it accepted. Consequences: a table pool makes membership dynamic without anchor reloads and unlocks `source-hash` later; weighted or least-connection balancing is impossible in pf, and Docker Swarm's IPVS is round-robin with no operator choice either, so this is parity. Two decisive measurements, both pinned as tests: **`pfctl -T replace` leaves established states alone** (`crates/satld/tests/pf_table.rs`, a live connection across a membership swap keeps its member, new connections get the new pool), and **`persist` tables survive an anchor flush with their members** (caught by `health_pool.rs`: a dead pool stayed readable in `-T show`), so the writer kills the table when a triple disappears. Load-bearing corollary of the first: `table <t> persist` declared without inline addresses comes back *empty* from every anchor reload, so the writer re-pushes full membership after every reload |
| 2026-08-14 | **Client-address preservation is an opt-in L4 proxy, not a pf trick.** The mesh's return-path SNAT is what makes a relayed connection complete at all (measured in `hack/experiments/mesh`), and DSR was rejected, it would need pf inside every task's VNET. So the remedy is `satl.publish.proxy_protocol=v2`: `satld` listens on the published port, dials a healthy task over the overlay, writes a PROXY v2 header and splices, the client address survives, and member selection is health-aware in a way pf's table cannot be. The port never gets an rdr rule (the kernel would win the race). The trade is stated in the docs: a userspace copy and the daemon in the data path |
| 2026-08-14 | **`ca_rotate` is flaky in this environment, on both M6c and M6d binaries, not an M6d regression.** Four runs failed at four different points (wire-check ssh hiccup, demote-not-applied during an election storm, the `the_leader` log heuristic, a 180 s teardown wait during rotation churn), and the same targeted run fails identically with M6c binaries. Two harness defects found and fixed along the way: the leadership heuristic missed "shutting down the leader-only components" (a leader stopping cleanly never logged "leadership lost", so a node that led its init-time single-node cluster reported leader forever), and the leftover audit now excludes the ingress segment. The scenario passes when elections are timely; the underlying election slowness on the OVH underlay deserves its own look, as does the scenario's timeout budget |
| 2026-08-14 | **A terminal task's overlay plumbing is torn down at container stop, not at task removal.** The allocator frees a terminal task's addresses (SWK §9.4) and a replacement can receive the same one within seconds; a rolling update's stopped task kept its epair in the overlay bridge and its node-local attachment, so the reallocated address was claimed twice, "endpoint X is both local and remote", no FDB entry, and the mesh black-holed every replacement (measured: 1 of 2 requests refused on the replica-less node during an update, 0 after the fix, 6612 requests, 0 lost). Pre-M6d this lifecycle gap was invisible because no published service had an overlay attachment; the ingress auto-attach (SWK §9.3) exposed it. The jail and rootfs still survive for `logs`/`inspect`, only the network plumbing follows the container |
| 2026-08-14 | **The port sweep is woken by the store's event feed, not just its 5 s timer.** The mesh made pool membership cluster-wide, and a store-driven membership lags a task's own lifecycle by the status round trip; with only the periodic pass, a task stopped by a rolling update stayed a black hole in every node's pool for seconds, measured as lost requests in the `rolling_update` cluster scenario, where the pre-mesh edge-triggered removal was effectively instant. A task or network event now triggers a pass on managers (a no-change pass costs one store read, no pfctl); the 5 s tick remains as the level and the only driver on workers |
| 2026-08-14 | **An overlay bridge's MAC is the derived MAC of its node's gateway** (`MacAddr::from_ipv4(gateway)`), not the kernel-assigned one. The derived MAC is a wire format, every peer computes a peer's MAC from its address alone to program static FDB and in-jail ARP entries, and pre-M6d only tasks lived on an overlay, all with derived MACs. The mesh put *gateways* in jails' ARP tables, and a task's reply to its own node's gateway went to the derived MAC the bridge did not carry and was dropped (measured with tcpdump on the cluster: the reply left the task for `02:42:0a:64:00:03` while the bridge had its real `58:9c:...` MAC). The alternative, shipping each bridge's real MAC in the store, was rejected: one more self-reported fact that can go stale, where setting the bridge's ether once at segment bring-up makes the existing rule cover gateways for free |
| 2026-08-14 | **The routing mesh is pf rdr to the task's overlay address + return-path SNAT, measured before built** (`hack/experiments/mesh`): without SNAT the relayed handshake never completes (the reply bypasses the relay); with it, handshakes and bulk traffic pass, and the mesh SNAT and `satl/nat`'s egress NAT do not interfere. Consequences taken as design inputs: the client address is lost on relayed connections (Docker's mesh makes the same trade; DSR rejected, it would need pf inside every task's VNET; M6e's PROXY mode is the opt-in remedy); the MSS clamp is insurance, not a fix (the task self-clamps and the relay can ICMP too-big, but PMTUD dies on ICMP-filtered paths); the pool targets the task's *container* port at its *overlay* address, so a relayed packet can never re-match a published-port rule, loop safety by construction. The mesh is **managers-only**: a worker has no store replica to compute the cluster-wide pool from and keeps the pre-mesh behavior (api-compat #75 rewritten) |
| 2026-08-14 | **A rollback whose refill tasks fail immediately could report `RollbackCompleted` with a slot serving nothing**, a latent race, not a flaky test: it passed at the M6a gate and failed deterministically at the same commit a day later on the same host. `phase()` called an empty, untouched slot `Absent` ("not the updater's business") even mid-update, so `work_left` went false and `finished` fired before the restart supervisor's refill (from the rollback spec) existed to fail. Fix: mid-update, that slot is `Watching`, the update waits for the refill to settle or fail, and the failure verdict then pauses the rollback as designed (`satl-orchestrator/src/update.rs`, regression test `an_empty_slot_mid_update_is_in_flight_not_absent`) |
| 2026-08-13 | **Metrics: split namespace, separate unauthenticated listener, rctl for per-container usage.** Docker's exact series names where dockerd defines them (so off-the-shelf dashboards render), `satl_*` otherwise, architecture §16's `satl_*`-for-everything commitment amended. The listener mirrors dockerd's `--metrics-addr` including the lack of auth; it is *not* a route on the API router, which would version-rewrite it and cannot be scraped over a unix socket anyway. Per-container usage is read from `rctl -hu jail:<task>` on the 20 s collector cadence and is simply absent with racct off, no cAdvisor equivalent, the kernel accounting the node already has is the source. External-command failures are counted inside the five per-crate runners (no shared wrapper exists, and introducing one for this was rejected); leaf code that cannot be threaded a handle writes through process-global helpers that no-op until satld installs the registry |
| 2026-08-13 | **License: BSD-2-Clause**, the same terms as FreeBSD itself, taken verbatim from `/usr/share/examples/etc/bsd-style-copyright`. The repo is published on GitHub and had no LICENSE, no manifest `license` field, no SPDX header anywhere, legally unclear. Every source file now carries the SPDX line as line 1 (line 2 after a shebang; `//` in Rust *and* proto, since `#` is not a legal protobuf comment), enforced by `make license-check` inside `check`, there is no CI, so the Makefile is the only gate. Fixture data files stay headerless: the parsing tests diff them byte-for-byte against real captured output |
| 2026-08-09 | Iteration gating: architecture.md reviewed before any code (Frédéric) |
| 2026-08-09 | Dev machine (alpha) is never rebooted ⇒ racct/rctl enforcement tested on VMs only, **superseded 2026-08-10**: Frédéric enabled racct and rebooted, so enforcement is now verified on alpha |
| 2026-08-09 | All code/docs/commits in English; conversation in French |
| 2026-08-09 | Local git only, no remote yet |
| 2026-08-09 | `satl-proto` crate added to the workspace (architecture §2) |
| 2026-08-09 | DNS-RR before VIP; volumes node-local in v1; jobs/CSI/external-CA deferred (architecture §14) |
| 2026-08-09 | Architecture approved by Frédéric, M0 started on epic branch `m0-skeleton` |
| 2026-08-09 | Delegation model: primary session = architect/reviewer; coding subagents implement well-scoped chunks |
| 2026-08-09 | Raft log storage = redb (validated by openraft compliance suite); snapshots sealed at rest only (per-manager DEK), wire protection is M2 mTLS |
| 2026-08-09 | docker-cli 29.4.2 installed on the dev machine for API-compat verification |
| 2026-08-09 | M0 DoD verified end-to-end on alpha; satld left running as an rc.d service |
| 2026-08-10 | Dev host prepared for M1 networking: pf loaded/enabled with a pass-all policy plus the `satl/*` anchors (rdr proven live), and IP forwarding enabled (`gateway_enable=YES`, Frédéric), both persisted in rc.conf and documented |
| 2026-08-10 | M1 DoD verified on alpha (remote curl through the pf rdr anchor, linuxulator alpine, kill -9 recovery + orphan sweep); satld running with pf_mode="enforce" |
| 2026-08-10 | Overlay MTU fixed at **1450** from measurement, not arithmetic: the OVH virtio underlay refuses anything above 1500, so jumbo is impossible (open question #6 closed, `docs/vxlan.md`). The pre-existing CLAUDE.md note "small packets pass, big ones hang" was **wrong**, `vxlan_encap4()` clears DF, so an oversized frame is fragmented, not dropped; the real signature is a throughput cliff |
| 2026-08-10 | VXLAN static FDB is programmed through `SIOCSDRVSPEC` **in-process**, with a local `unsafe` exemption confined to one module (one `SAFETY` note per block, safe API outside). Rejected a C helper binary: one more artefact to build, deploy and version, plus a process boundary per FDB entry, more surface, not less. `ifconfig` cannot do it at all |
| 2026-08-10 | An overlay network's gateway is **per node** (`Network.node_gateways`), SWK §9.1's per-node attachment reduced to an address, no VIPs, since FreeBSD has no IPVS. `.1` reserved and assigned to nobody, so what an operator reads in a subnet is never one arbitrary node's address |
| 2026-08-10 | A released node gateway is **not** reusable within the pass that released it: the departing node's bridge may still carry the address. The claim stands for the rest of the pass and `Plan::freed` re-runs the loop |
| 2026-08-10 | `vxlanmaxaddr` cannot be raised above 2000 (2001 is `EINVAL`; a create-time `4000` is accepted *silently* and comes up at 2000), so `docs/vxlan.md` §3's "raise it for large networks" was wrong. **But the 2000-endpoint ceiling does not apply to SatL**, and an earlier entry here claiming it did, plus "watch `ftable_nospace`", was itself wrong: both the count check and that counter live only in `vxlan_ftable_update_locked()`, gated by `VXLAN_FLAG_LEARN`, which SatL turns off. Measured: 2500 static entries install fine at `max 2000` with `ftable_nospace` at 0. Recorded from one agent's report and falsified by another's measurement, the lesson is that a claim about kernel behaviour is not a decision until someone has run it |
| 2026-08-10 | The real bound on any read-back reconciler is that **`net.link.vxlan.<unit>.ftable.dump` truncates at ~81 entries, silently**: the kernel builds it in a fixed `PAGE_SIZE` buffer and backs out the partial line, so the output is well-formed and gives no hint of loss (an IPv6 remote widens the line, lowering the ceiling to ~51). Detect it by comparing the config ioctl's entry count against the number of dumped lines; a mismatch means the read-back is unusable, so flush and re-push the full desired table, safe precisely because learning is off, so every entry is ours |
| 2026-08-10 | FDB `ADD` on an existing entry returns `EEXIST`, it does **not** replace (`docs/vxlan.md` §7 was wrong). Changing an entry is an explicit ordered remove-then-add, so the delta carries a third list; without it a rescheduled task leaves every peer's FDB pointing at the old VTEP, and nothing reports an error |
| 2026-08-10 | Static ARP in a task's jail is programmed by **re-execing `satld` itself** into the jail's VNET and writing to a routing socket. `jexec <task> arp` cannot work, an OCI image has no `arp` binary, and `route -j` cannot either (`RTF_LLDATA` is never set by `route(8)`). Rejected materializing a binary into the container's rootfs: an operator must not find SatL's files in their image, and it breaks distroless and read-only ones. Static entries are mandatory, not an optimisation: unicast VXLAN does not flood, so a broadcast ARP goes to the blackhole default remote |
| 2026-08-12 | **Root rotation keeps SwarmKit's cross-signed-intermediate shape but diverges on tokens and restarts.** Tokens regenerate at rotation *start* as well as completion, forced by an earlier SatL choice: our token digest pins the whole downloadable bundle (MITM-append defense) and `GetRootCACertificate` serves the store's bundle, which becomes two roots the moment the rotation starts, SwarmKit keeps serving the old root alone and can defer its single token rotation to completion (api-compat 99). And a second `rotate` during a rotation is refused rather than replacing the running one (api-compat 98): replacement multiplies the bundle states in flight and makes "which tokens are valid" unanswerable. Convergence is tracked as `Node.certificate_issuer` (digest of the signing root) written by whoever signs, so the reconciler never inspects a certificate; nodes that cannot write the store get theirs recorded by the NodeCA at signing time, managers propose their own through the leader client. The mid-rotation flap risk under short `cert_validity` is closed structurally: one renewal loop per node owns all three triggers (window, `Rotate` mark, bundle change), the window is drawn once per certificate, and both paths sign from the store's current signer |
| 2026-08-12 | Background loops attach spans with `.instrument()`, never `span.enter()` held across an await, enforced by `crates/satl-dispatcher/tests/span_scoping.rs`. The leaked guard put five-deep chains in the log mixing two node identities, so a worker's `jail_create` appeared under another node's `manager_id`. CLAUDE.md prescribes grep-by-id as *the* diagnosis method, so a wrong parent breaks the documented procedure, not just the formatting |
| 2026-08-12 | **Open question for M4:** a stopped container keeps an empty jail (0 processes) until it is removed. Observed on alpha: three containers `Exited (0)` 43 hours earlier, each still holding a live jail and epair. Docker keeps a stopped container's filesystem until `rm` but not a live namespace, and a jail per stopped container is a resource an operator would not expect. Decide whether task completion destroys the jail and keeps only the dataset for `logs`/`inspect` |
| 2026-08-12 | Published ports keep **edge and level side by side** rather than replacing one with the other: the agent's controller writes a `started` slot at container start (fast, host mode) and `satld`'s periodic pass writes a `converged` slot from the store (authoritative, both modes). Neither can erase the other, so no ordering between them has to hold. The anchor is force-reloaded every ~60s because "unchanged" is a belief about the kernel, not a reading of it, and reading it back is not viable, since pfctl prints its own normalisation (`port = http-alt` for 8080) |
| 2026-08-12 | Several tasks of one service on one node become **one** rdr rule with a round-robin pool. pf evaluates translation rules in order and the first match decides, so two rules with the same match would leave the second task looking published while never receiving a connection; taking only the first would make reachability depend on task-id ordering and waste a replica |
| 2026-08-12 | SatL **accepts** ingress publishing together with DNS-RR, where SwarmKit rejects the pair (`validateEndpointSpec`: "port published with ingress mode can't be used with dnsrr mode"). Its mesh needs a VIP to balance behind; SatL has none, since FreeBSD has no IPVS, so refusing the pair would refuse every published port |
| 2026-08-12 | A container rootfs is destroyed by waiting on **the prison disappearing** (`jls -d`), never on a timer, and exhausting that wait **defers to a periodic node sweep** rather than abandoning. The wait is a kernel timer of 2 x `net.inet.tcp.msl`, which cannot be afforded inline on the assignment stream: a removal is applied there, so blocking ~60s per task would stall every other assignment for that node, including the network teardown ordered after it in the same batch. The 30s inline budget stays and the sweep carries the rest, measured end to end at 52-69s |
| 2026-08-10 | A node's VXLAN endpoint address is **self-reported** in `NodeDescription.data_addr` (from `advertise_addr`), not inferred by the manager. Deriving it from the address the dispatcher *observed* the agent connect from was worse than a guess: over the co-located socket that address is **empty**, so the local node had no VTEP at all, and a missing VTEP is silent (tunnel up, interface `RUNNING`, traffic nowhere). Placed on the node's *description* (what a node asserts) rather than its *status* (what a manager observed); blurring the two is what caused the M2 membership-address bug, and the description is also the only agent→manager self-report channel, so it needs no proto change |
| 2026-08-10 | `network connect`/`disconnect` on a running container return **501**, not a hollow 200. A task's spec is immutable and its attachments are allocated once, so hot-plugging means replacing the task, a different container ID than the client named (the api-compat #30 wall). Mutating the service's network list would answer 200 and change nothing, leaving the store claiming an attachment the container does not have |
| 2026-08-10 | **Operator-facing strings are ASCII.** Measured with `od -c` on the log file: syslogd rewrites bytes **0x80–0x9f** as literal `M-^X` text and passes 0xa0–0xff through, so `—`, `×`, `−`, `→`, `…` and curly quotes are destroyed and ungreppable while `§` and `é` survive intact. (An earlier reading of mine through `cat -v` showed `§` as `M-BM-'` and concluded it was corrupted too, that was the *renderer*, not the file. `cat -v` is the wrong instrument for this question.) The rule is unconditional anyway: most offenders are destroyed, and a surviving one still forces an operator to type a non-ASCII character to grep. Same family as the ANSI-escape bug, the log is the diagnosis surface |
| 2026-08-10 | One DNS responder per **node**, binding each overlay gateway address it holds, resolving by source address, not one responder per network. Closing with it the wave-1 gap where a task on two overlays got **NXDOMAIN** for the other network's services: resolution scope is the set of networks the *querying task* is attached to (source → task → networks, in attachment order), not the single network its source address sits in. NXDOMAIN there is a wrong authoritative answer, which applications cache; that is worse than a timeout |
| 2026-08-10 | rctl enforcement exercised on alpha (racct enabled by Frédéric + reboot): found and fixed a real bug, memoryuse:deny is silently ineffective (RSS is not RACCT_DENIABLE) so --memory now uses memoryuse:sigkill; pcpu:deny confirmed to throttle |
| 2026-08-10 | Frédéric's podman pf.conf prompted an audit that found containers had NO outbound connectivity (egress_if never set, so the satl/nat anchor stayed empty) and no /etc/resolv.conf, both fixed and verified; the table-driven NAT alternative is documented in docs/networking.md as the M3 evolution |
| 2026-08-10 | Open product question: a container is a Task, so `start` on a stopped container is refused (api-compat #30); revisit the container-as-Service model in M4 |
| 2026-08-10 | M2 protocol: store objects and openraft messages travel as opaque CBOR inside protobuf `bytes`, with only routing scalars mirrored, satl-core owns the model and its encoding, and a parallel protobuf model would be a second source of truth (proto/README.md) |
| 2026-08-10 | M2 join is **learner-first with asynchronous promotion**, diverging from SwarmKit: openraft commits configuration changes through joint consensus, so the joint entry needs a majority of the NEW config, including a joiner that cannot start raft until JoinRaft gave it an id. etcd/raft commits against the old config, which is why SwarmKit does it in one step |
| 2026-08-10 | openraft 0.9 has no TransferLeadership; `membership::yield_leadership` stands in (stop the local ticker, wait for another manager to win, restore it) |
| 2026-08-10 | The gRPC health service is owned by satl-cluster, not the dispatcher crate: `Control.JoinRaft` health-checks a joiner before admitting it, so it must exist before any other service registers. Two `grpc.health.v1` registrations would collide on the route |
| 2026-08-10 | Unauthenticated NodeCA bootstrap needs its own listener on `listen_addr.port() + 1` (2378): rustls builds a mandatory client verifier, so the mTLS server admits no per-service exception, and a first-time joiner has no certificate. A clean fix is an allow-unauthenticated policy in satl-ca/satl-cluster |
| 2026-08-10 | Two bugs found only by building the real 3-node cluster: `swarm join` tried to remove the raft **directory**, which is a ZFS mountpoint (EBUSY); and the init phase wrote the raft membership with the node *name* instead of the advertise address, so followers redirected agents to an undialable endpoint while the cluster looked healthy. A leader now heals its own membership address at startup |
| 2026-08-10 | Six more bugs found only by running real workloads across three nodes: concurrent replicas raced on ZFS layer application (one destroying the other's mid-unpack dataset); the orchestrator had no node-state awareness, so a Down node kept its tasks Running forever; leader seeding invented a node description from the config's node_name; ANSI escapes made syslog unreadable; rctl cleanup logged two ERRORs per container removal; and satld called Worker::init_from_disk in addition to the session, closing the task managers the session then needed |
| 2026-08-10 | The M2 bug worth remembering: the agent seeded its "already applied" bookkeeping from the assignment snapshot instead of the persisted task, so a desired state that moved while a node was away was skipped as already-applied, a jail outliving its task, a service stuck at 7/6, and no error anywhere. "Local is canonical" holds for the *observed* status only; architecture §7.2 now says so explicitly. The test double hid it: RecordingSink::init did nothing, so no test could express the failing condition |
| 2026-08-10 | Node.manager_status is a stored field, so satl node ls named a dead node Leader forever; list_nodes/inspect_node now overwrite it from the live raft membership, as SwarmKit does (SWK §6.2) rather than trusting the stored copy |
| 2026-08-10 | M2 closed: four DoD criteria verified live and scripted in tests/cluster/run.sh. Eight defects were found only by running real workloads across three machines, none reachable from a single-node test |

---

## M4 carried into M5, known and deliberate

- **The restart delay queue has no store representation.** A start interrupted
  mid-delay takes a fresh delay rather than the remainder. SwarmKit derives it from
  a task parked at desired `READY`; SatL creates replacements at the predecessor's
  desired state, so there is no marker for "this creation was deferred until T". A
  replacement one delay late is a pacing difference, not a correctness one.
- **A task is published before it serves, unless the service has a healthcheck.**
  Without one, `RUNNING` means "the jail started", measured at 5 ms after jail
  start, while nginx needed 250 ms to bind. The health gate (api-compat #87) is what
  closes it; requiring `RUNNING` instead of `>= STARTING` does not.
- **`satl service create/update` has no `--restart-delay`, `--restart-max-attempts`,
  `--restart-window` or `--force`**, all of which Docker has. The cluster scenarios
  create those services over the REST API for exactly this reason.
- **`satl service ps <unknown service>` exits 0 with an empty table** where Docker
  errors. Undocumented deviation; the harness counts rows rather than trusting the
  exit status.
- **Resource reservations are not re-checked by the constraint enforcer**, that
  running total lives in the scheduler's in-memory mirror, and a second resource
  accountant is not worth having.

> **Resume here (paused 2026-08-12 ~20:30 UTC, quota).** The working tree carries M5
> wave 1, uncommitted; a full snapshot (tracked diff + untracked files) is in the
> session job dir under `wave1-snapshot/`.
>
> - **Secrets/configs: COMPLETE and verified.** Surface (api-compat 97-103, CLI
>   107-109), references, tmpfs delivery, both interrupted-teardown windows,
>   never-touches-disk proof green, payload-never-in-logs green, integration 7/7.
> - **CA rotation: MID-EDIT, do not trust the tree's satl-cluster.** The agent was cut
>   while writing "the forwarding helper and error variant" in `membership.rs`;
>   `a_leader_removing_itself_hands_leadership_over_first` now fails *deterministically*
>   (not the known flake, it reproduces). Its scenario `ca_rotate` exists (suite counts
>   16) and had passed within run 1 before the cut; run 1 was at 8/16 when stopped, the
>   `cert_validity` interplay experiment and suite run 2 were still queued.
> - Resume by messaging the CA agent to finish `membership.rs` first, then its queued
>   verification; commit both scopes together once `make check` is green over the
>   settled tree (the two works interleave in `cli.rs` and `backend.rs`, so they cannot
>   be split by file).
> - VMs: clean and Ready (audited post-kill: no jails, epairs, datasets, labels).
>   One orphaned ssh from the killed suite was reaped.

## Found while writing the user documentation (2026-08-13)

Two of these are defects, not documentation drift. Recorded here because the
user-facing site documents what the code does, so the discrepancy is now
written down in two places and one of them is wrong.

- ~~**`satl images` shows "56 years ago" for every image.**~~ **Fixed in M7a**
  (2026-08-15): the config's `created` is parsed at pull, written by `satl
  build` since M6f, and rendered by `/images/json`; api-compat #15 amended.
  `labels` stays empty and `shared_size` zero, still hardcoded, still true.
- **A service on a private registry cannot pull where the image is absent.**
  `X-Registry-Auth` is honoured by `POST /images/create` and **dropped** on
  service and container create, `pull_options` is set to `None` in both
  `satl-api/src/convert/cluster.rs` and `satld/src/backend.rs`, and
  `registry_auth` appears nowhere under `crates/satld/`. `docs/architecture.md`
  section 9 says credentials come per request *or from the task's pull
  options*; the second half is not implemented.
- **A published port is unreachable from the publishing host by *any* of its
  addresses**, not only via `localhost` as api-compat 35 says. Measured: a curl
  to the host's own public address times out identically, because that traffic
  is locally generated and never enters an interface for pf to redirect.
- `docs/operations.md`'s on-disk state section lists five datasets; the live
  state directory also holds `certs/`, `worker/tasks/`, `bundles/`, `logs/`,
  `health/`, `net/`, `ocijail/`, `scratch/`, `managers.json` and
  `dispatcher.sock`.
- ~~**Two operator-facing error strings name milestones** (`... is M4`, `...
  in M1`), which reads oddly to a user.~~ **Fixed 2026-08-15**: these refusals
  are permanent by design (immutable task spec, api-compat #30), so every
  user-facing string now states the reason instead of naming a milestone.
  `crates/satl-agent/src/health.rs` still cites api-compat 89 for
  `StartInterval` where the entry is 90.

| 2026-08-13 | `IssueNodeCertificate` has two callers and only one followed the leader redirect: the mTLS renewal path did, the bootstrap join path did not. So `satl swarm join` against a follower failed with the daemon's own instruction unheeded, and the documented post-rotation recovery was a coin flip decided by which node happened to hold leadership. The redirect is now a shared enum both callers use. **The general shape to watch for: one RPC, two callers, one of them fixed** |
| 2026-08-13 | The refusal after a node misses a CA rotation is **one-directional**, and this is a property of cross-signing rather than an accident. The returning node still verifies the managers, because their leaves carry the cross-signed intermediate bridging back to the root it holds; only the managers reject it. Its own log therefore shows `received fatal alert: DecryptError` and never a certificate error, so **the manager's log is the single operator-facing message for this state**. Relatedly the error is `BadSignature`, not `UnknownIssuer`: every root of a cluster shares `CN=satl-ca`, so a dropped-root leaf matches an anchor by name and fails on the signature |
| 2026-08-13 | Open, found in passing: a stale join token is refused with HTTP **500** where a client error deserves a 4xx. Would touch `docs/api-compat.md` |

| 2026-08-13 | The raft replication batch is **derived** from the two limits that bound it (`MAX_MESSAGE_SIZE / MAX_TX_BYTES`) rather than left at openraft's default of 300 entries. At 1.5 MiB per entry a catch-up batch could exceed the 4 MiB gRPC limit and fail as an opaque `Internal: h2 protocol error`, retried identically **for ever**, a rejoined manager received nothing for three minutes while the leader logged three errors a second against a healthy socket. **This was the root cause of the unexplained cluster stalls of 2026-08-13**, and it lived exactly on the rejoin-and-restore path. Where two constants bound the same thing, derive the second from the first |
| 2026-08-13 | Two new refusals, both of the same shape, a daemon that used to invent state where an operator expected recovery. A manager certificate over an empty `raft/` minted a second empty cluster with a new cluster id and no root CA, *and looked healthy*; and restoring without the `dek` had `Dek::load_or_create` mint a fresh key over sealed state, making the restored copy permanently unreadable with no error at all. Both now refuse and name the recovery. Third instance of this family after `eb17318` |
| 2026-08-13 | **A cluster that permanently loses quorum cannot be recovered from inside**, and `ForceNewCluster` stays 501 by decision rather than by omission. That argues for an offline "force single-voter membership" tool as an M6 candidate; until it exists, the deployment guidance is to back up two managers of three |
| 2026-08-13 | Open, mechanism not pinned: `service satld stop` hangs on a manager that has lost quorum (three occurrences, once 21 minutes). The API socket is already closed and raft shutdown is never reached. `pkill -9` is the documented way out, and `reset.sh` will sit on such a node for ever |
