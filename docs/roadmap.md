# SatL Roadmap & Development Status

> **This file is the live status of the project. It MUST be updated in the same commit
> as any work that starts, advances, or completes a milestone item** (see CLAUDE.md,
> definition of done). Milestone definitions come from `docs/project-brief.md`; this
> file tracks progress against them.

**Last updated:** 2026-08-23
**Current focus:** M10 started 2026-08-23, field fixes found during the documentation-validation run against the fresh test VMs plus the man pages (first fix landed: the `satl ps` PLATFORM column, empty for informally spelled images). Before that: M9, the 2026-08-19 verb audit found five daemon capabilities with no CLI client at all (`/events`, `/info`, `/volumes/{name}`, the `node` task filter, the four prune endpoints) and one operation missing at both layers: there was no way to delete a single image. M9a closed the CLI half and added `DELETE /images/{name}` and `GET /images/{name}/json`; M9b, the generated OpenAPI contract, is in progress. The cluster testbed was replaced the same day (decision log): `fbsd{1,2,3}.satl.cc`, underlay now 10.0.0.0/24, full suite 22/22 plus 7/7 encrypted. M6a–M6g, M7 and M8 remain done; of the M6 backlog only plugin volumes are unscheduled.

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
| M10 | Field fixes and man pages | 🔨 in progress |

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
- No `TransferLeadership` in openraft 0.9; `membership::yield_leadership` stands in.
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

---

## Decision log

| Date | Decision |
|---|---|
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
