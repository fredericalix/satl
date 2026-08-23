# SatL — Production readiness report

**Date:** 2026-08-23 · **Commit:** `910f452` (main, clean tree) · **Version:** 0.1.0 (beta)
**Scope:** read-only assessment of the repository, its documentation, the live daemon on
alpha, and the recorded cluster evidence. Nothing was modified or committed. Annex A is
the SatL / Docker Swarm feature comparison.

---

## 1. Verdict

**SatL is a production-capable beta, not yet a production release.** The distinction is
deliberate and the project's own documents draw it honestly.

What supports "production-capable":

- Every milestone (M0–M9) closed against a measured Definition of Done, on real
  hardware, with the measurements recorded. The last full validation (2026-08-19, on a
  freshly rebuilt 3-node fabric) ran **22/22 cluster scenarios plus 7/7 encrypted-overlay
  scenarios**.
- `make check` is green **today** on this checkout: fmt, clippy `-D warnings`
  (pedantic), SPDX scan, and **2,469 unit/doc tests, 0 failures**.
- The daemon on alpha has been up for 12 days across a package upgrade, with a running
  container re-adopted rather than restarted — the crash-recovery and reconciliation
  story works in practice, not just in tests.
- Code hygiene is exceptional for a project this size: **8 TODOs total** in the whole
  workspace, zero `unimplemented!`/`todo!()`, zero stub CLI verbs, `unsafe` denied
  workspace-wide (one audited exemption for the VXLAN FDB ioctl).
- The operational story is written down and was *validated, not invented*:
  backup/restore measured on three machines, upgrade via `pkg`, rc.d service,
  `dist/satl-0.1.0.pkg` + SHA-512 checksum built and installed.

What keeps it at "beta":

- **One maintainer, no CI, no independent security audit** — all three stated openly in
  README/SECURITY.md, and all three are what a production adopter will ask about first.
- A handful of **known open defects** (section 4), none data-destroying, several with
  documented workarounds.
- **The cluster testbed no longer exists** (confirmed 2026-08-23; the fbsd{1,2,3}
  VMs are gone). `make cluster-test` — the suite that proves every cluster behavior —
  cannot run today. The last green run is 4 days old on a commit 5 commits back.
- Several **doc/reality mismatches** found during this assessment (section 5), including
  one that matters for a public release: the `v0.1.0-beta` tag referenced by
  CHANGELOG.md and SECURITY.md **does not exist** in the repository.

**Bottom line for an operator:** on FreeBSD 15.1/amd64, with ZFS, an all-manager cluster
of 3, backups of at least two managers, and workloads that are trusted (single tenant),
SatL will run real services today and recover from the failures it was tested against.
It is not ready for hostile multi-tenancy, IPv6 networks, workloads needing shared
storage, or organizations that require an audit trail and vendor-grade support.

---

## 2. How this was assessed

| Check | Result |
|---|---|
| `make check` (fmt, clippy pedantic `-D warnings`, SPDX, full test suite) | **Green**, 2,469 tests passed, 0 failed (run 2026-08-23) |
| OpenAPI contract drift (`docs/openapi.yaml` vs handlers) | Gated inside `cargo test --workspace` — passes |
| Live daemon on alpha (`satl version/info/ps`) | satld 0.1.0 (pkg-installed 2026-08-20), API 1.43, swarm active, 1 container up 12 days, re-adopted across the upgrade |
| Package artifacts | `dist/satl-0.1.0.pkg` (15.8 MB) + `CHECKSUM.SHA512`, built 2026-08-21 |
| Git state | main == origin/main (pushed to github.com/fredericalix/satl); working tree clean; **zero tags** |
| Cluster testbed | **Gone** — `fbsd{1,2,3}.satl.cc` NXDOMAIN, public IPs unreachable (expected; VMs were decommissioned). Last full suite: 2026-08-19, 22/22 + 7/7 |
| `sudo make integration` | Not run in this assessment (root, mutates host state); last runs recorded green in the roadmap |
| Code sweep (501s, TODOs, stubs, auth layer) | Full inventory, section 4 and 6 |
| Docs read | roadmap.md (945 l), api-compat.md (166 numbered deviations), architecture.md, operations.md, CHANGELOG, SECURITY, README, project-brief |

---

## 3. What works — verified, with the evidence

Everything below is backed by a recorded measurement or a scripted scenario, not a claim.

### Containers and runtime
- **One VNET jail per OCI container** through ocijail; ZFS clone layers; `linux/amd64`
  images under the linuxulator (verified: alpine `uname` through the task pipeline).
- Full local lifecycle: `run/ps/stop/rm/logs/exec/inspect/wait/kill/pull/images/volume`,
  rctl limits with racct-off graceful degradation (memory kill and CPU throttle verified
  live after enabling racct).
- **Crash recovery**: `kill -9 satld` → jail keeps serving → restart re-adopts it (same
  jid/pid), republishes ports, sweeps orphans (datasets, epairs, rctl rules, DYING
  prisons). Re-verified in practice by the 2026-08-20 package upgrade on alpha.

### Cluster and orchestration
- 3-manager cluster: init + joins in 13 s on fresh VMs; `--replicas 6` spreads 2/2/2;
  **worker-kill eviction** (TTL → Down → reschedule 3+3) and **leader-kill** (re-election,
  writes accepted by survivor, Down + eviction of the dead leader's tasks) both scripted.
- **Rolling updates**: 6 replicas under load, **zero requests lost** (asserted
  structurally: no failure window outlives one port-reconciliation pass); broken image
  → automatic rollback. Through the routing mesh: 6,612 requests, 0 lost.
- Global services, drain/pause, constraint enforcer, placement preferences (re-ranked
  within a batch — a defect the E2E caught), jobs (replicated/global) — all proven on
  the 3-node fabric.
- **Hot vertical resize** (SatL-only vs Swarm): rctl rules rewritten on live jails,
  verified against a running PostgreSQL, `pg_postmaster_start_time()` unmoved.
- Restart supervisor with an election-surviving budget derived from the store every pass.

### Networking
- VXLAN overlays, static FDB (learning off), per-node gateways, embedded DNS-RR
  responder scoped to the querying task's networks. **Overlay MTU 1450 measured** (DF
  boundary 1422/1423; zero fragmentation over 500 full-size frames).
- **Ingress routing mesh** on managers: relay from replica-less nodes, round-robin,
  40 MB through the relay without fragmentation, ~8 s drop-from-pool after a kill.
- **Health-checked pools**: 9.97 s measured from probe failure to the address leaving
  the pf anchor (vs ~90 s with Docker defaults).
- **Encrypted overlays** (`--opt encrypted`): ESP aes-gcm-16, **MTU 1416 measured**,
  ESP-only wire verified, pf `satl/guard` blocking cleartext injection (a FreeBSD 15.1
  SPD behavior found by measurement), 12 h key rotation with loss measured at 1.2 %
  (ceiling 6 % in the scenario). 7/7 scenarios on the new fabric.
- Opt-in **PROXY protocol v2** publish mode preserving the real client address.

### Security machinery
- Embedded CA, mTLS everywhere, role enforced per RPC; **live certificate renewal**
  (proven with 5-minute certs: 3 cycles, zero restarts, reconnects in ~250 ms);
  **live CA rotation**: 0 of 339 requests lost, unchanged pids.
- **Secrets**: tmpfs-only delivery *proven by searching every filesystem on the node
  while the task runs* — payload found only in the tmpfs.
- Raft log/snapshots encrypted at rest; **autolock/KEK** (locked manager serves only
  `/_ping` + unlock); refusal-to-rekey and refusal-to-self-init fail-safes.

### Images, build, compose
- `satl build`: multi-layer with content-addressed cache (7 s incremental vs 51 s
  cold), multi-stage, `FROM scratch` (1.4 MB static-C showcase), `tag`/`push` verified
  round-trip through a registry.
- Compose/stack with refuse-whole semantics; the M5 DoD stack (nginx + redis + worker,
  one overlay, a secret redis cannot start without) at ~108 s, scripted.
- Layer GC with two agreeing passes; `satl images rm` measured (~2 s, by construction).

### Operations
- Backup/restore validated on three machines; **rejoin measured at 6 s**; the
  "three managers *and* back up at least two" policy derived from a real
  quorum-loss experiment.
- Prometheus metrics with Docker's series names (dashboards render unchanged) +
  per-task usage from rctl, no sidecar.
- Package pipeline: `make package` → `pkg add -f` upgrade verified on alpha with config
  survival and container re-adoption.
- Docker CLI 29.4.2 works against the socket (version negotiation 1.54 → 1.43).

---

## 4. What does not work — open defects

None of these lose data; all are recorded in the roadmap/decision log. Ordered by how
much they would hurt an early adopter.

| # | Defect | Impact | State |
|---|---|---|---|
| 1 | **`satl kill` on a service task retires the slot for good** — the service sits at 0/N until a spec change (api-compat #146) | An operator rehearsing failure with the obvious verb strands their service | Documented; fix needs an agent-side signal channel (design conversation) |
| 2 | **Private registries: `X-Registry-Auth` is dropped on service/container create** — a service cannot pull from a private registry on a node where the image is absent | Blocks any private-registry deployment that isn't pre-pulled | Recorded 2026-08-13; `pull_options` set to `None` in two places |
| 3 | **A container exiting within milliseconds can lose its final stdout** — inside ocijail's stdio wiring | Hurts jobs most (their whole point is printing and exiting) | Found, not root-caused; investigate in ocijail before claiming job logs reliable |
| 4 | **A transiently failed task poisons every later resume of the same update** — the updater counts current-spec failures across attempts | A rollout paused by a transient `dataset is busy` re-pauses instantly on resume; workaround is a spec bump (any label) | Documented; real fix needs updates to have an identity |
| 5 | **`service satld stop` hangs on a manager that has lost quorum** (observed up to 21 min) | An operator's shutdown path becomes `pkill -9` | Open, mechanism not pinned |
| 6 | **A stale join token is refused with HTTP 500** instead of a 4xx | Cosmetic-but-confusing for tooling | Open, noted 2026-08-13 |
| 7 | **A published port is unreachable from the publishing host by *any* of its addresses** (wider than api-compat #35 states) | Surprises every first-time user; pf property, needs prominent doc | Measured; doc entry still says "via localhost" only |
| 8 | **`/run/secrets` tmpfs is not remounted read-only** — protection is file mode only (api-compat #101) | Root inside the jail can alter secret files | Deferred (needs a second mount pass) |
| 9 | **A jail's `lo0` has only `::1`** — Docker-style `localhost` healthchecks cannot connect | Every ported compose file with a localhost probe fails; documented recipe exists | Platform decision, documented, not fixed |
| 10 | **Restart delay is not resumable** — an interrupted delay restarts fresh | Pacing difference only | Named, accepted |
| 11 | `ca_rotate` cluster scenario is flaky under slow elections (environment, not binaries) | Suite reliability; underlying election slowness on the OVH underlay "deserves its own look" | Open |
| 12 | `satl-agent/src/health.rs` cites api-compat #89 where the entry is #90 | Trivial doc-reference slip | Open |

---

## 5. Doc/reality mismatches found in this assessment

These are new findings (2026-08-23), not yet in the roadmap:

1. **The `v0.1.0-beta` tag does not exist.** `git tag` lists nothing, yet CHANGELOG.md's
   release links and SECURITY.md's supported-versions table reference it. The decision
   log (2026-08-17) says an annotated local tag was created; it is not in this
   repository today. Public release links will 404.
2. **SECURITY.md and CHANGELOG.md claim "remote REST requires a client certificate from
   the cluster CA" — but there is no remote REST.** The API server binds a unix socket
   only (`satl-api/src/server.rs`), the CLI refuses anything but `unix://`, and the
   OpenAPI doc itself states "There is no TCP listener for this API." The project brief
   promised "TCP+mTLS remotely". Either implement the mTLS TCP listener or fix the
   three documents; today the docs promise a surface the code does not have (the safe
   direction: the code exposes *less* than documented).
3. **architecture.md still calls autolock/KEK deferred** (§12.4 around line 1210, and
   the §16 adoption table) although M7f shipped it — already noted 2026-08-17, still
   unfixed.
4. **roadmap.md's header and M9b checkbox still say "in progress"** although M9b (the
   generated OpenAPI contract, drift-gated by `make check`) landed in `212990c`.
5. **operations.md's on-disk state list is incomplete** (noted 2026-08-13; the live
   state dir holds ~10 entries the doc does not list).
6. `docs/vxlan.md`'s FDB capture shows the old 10.2.x underlay — deliberately kept as
   recorded measurement, but worth a one-line "historical capture" note before a public
   audience reads it as current.

---

## 6. What is missing — gaps, by kind

### Missing by deliberate design (defensible in public, each has a reason)
- **No standalone containers** — everything is a task (the deepest source of the 166
  numbered API deviations; `start` after `stop` is a 409).
- **No VIP/IPVS** — DNS-RR only; FreeBSD has no IPVS. The single largest architectural
  delta vs Swarm, and it is platform-forced.
- **ZFS mandatory; FreeBSD 15.1/amd64 only; ocijail is the only runtime.**
- **Refuse rather than half-apply**: ~40 compose keys, 15+ HostConfig options,
  unknown filters — all loud 400s, never silent drops.
- `ForceNewCluster` permanently 501 (recovery = restore or rejoin, measured);
  secrets/configs immutable (rotation recipe in the error).
- No `POST /build` / push API (client-side by design), 2378 unauthenticated bootstrap
  (digest-pinned tokens), unauthenticated `/metrics` (dockerd posture).

### Missing, acknowledged, not yet built (the honest backlog)
- **Worker-node story**: the mesh spans managers only; a worker's REST surface is
  reads + 503s. Supported v1 shape is all-managers.
- **No cluster-wide `service logs`** / log broker; no log drivers.
- **IPv6** — nothing, anywhere (overlay, IPAM, published ports).
- **No CSI / volume plugins / cluster volumes** — node-local ZFS only; stateful
  services pin to a node (the one unscheduled M6 backlog item).
- **No user-level authorization** on the API (socket group = root-equivalent);
  no remote API access at all (see mismatch #2 above).
- **Health decoupling** (unhealthy → depooled but running, Docker's model) — designed
  for M6, not built; today depool and replace are the same event.
- **Interactive exec / TTY** (output delivered at exit, no stdin TTY); no
  attach/stats/top/restart/pause/cp/commit/export.
- CLI gaps: `--restart-delay/-max-attempts/-window`, `--rollback`, `--force`,
  `--secret-add/-rm` on update; `satl run` healthchecks (container-create path reads
  none, so `satl run -p` is never health-gated).
- Filters on most list endpoints (501), events history/`until`, attachable/internal
  networks, `network connect/disconnect` (501 by model).
- No external CA, FIPS, secret drivers, Go templating, generic resources (GPU),
  offline quorum-recovery tool.

---

## 7. Production readiness by axis

| Axis | Grade | Notes |
|---|---|---|
| Install / upgrade | **Good** | pkg-based, checksummed, rc.d, config survives, containers re-adopted (verified live) |
| Correctness culture | **Excellent** | Measured DoDs, 2,469 tests, integration + cluster suites, evidence-based decision log, fail-loud API |
| Crash/failure recovery | **Good** | kill -9, leader kill, node kill, DYING prisons, orphan sweeps — all scripted; quorum-loss is the sharp edge (backup 2 of 3, documented) |
| Security machinery | **Good (unaudited)** | mTLS, live renewal/rotation, at-rest encryption, autolock, tmpfs secrets — but **no independent audit**, no user authz, root daemon |
| Observability | **Fair–Good** | Metrics + events + identity-keyed tracing are strong; **no cluster log story**, health is node-local |
| Scale envelope | **Unknown beyond tested** | Everything proven at 3 nodes / single-digit services; no load or scale testing beyond the DoDs (6 replicas, 40 MB relays). State this plainly in public |
| Ecosystem fit | **Good** | docker CLI works; dashboards render; compose files deploy (with stack semantics) |
| Sustainability | **Weak** | One maintainer, no CI, testbed currently gone. This, not the code, is the real production risk |

---

## 8. Before presenting to the FreeBSD community

The project is presentation-worthy today on substance: it fills a real gap (there is no
other swarm-style orchestrator native to FreeBSD), it is BSD-2-Clause with FreeBSD's own
license text, and its engineering culture (measure first, refuse loudly, document
deviations) is exactly what that audience respects. The punch list is short and mostly
release mechanics, not engineering.

### P0 — do before any announcement
1. **Rebuild a cluster testbed and re-run the full validation** (`make cluster-test`
   22 scenarios + `encrypted.sh`, and `sudo make integration`) **on the exact commit
   and package being announced**. Announcing cluster software whose cluster suite
   cannot currently run is the one criticism with no answer. Only
   `tests/cluster/inventory.toml` needs editing for new VMs (proven on 2026-08-19:
   provision → deploy → images → run worked unmodified, cluster formed in 13 s).
2. **Create and push the release tag** (`v0.1.0-beta` or a fresh `v0.1.0-beta.2`), and
   verify every CHANGELOG/SECURITY/README link resolves on GitHub.
3. **Fix the five doc mismatches of section 5** — above all the remote-REST claim in
   SECURITY.md/CHANGELOG (a security document must not describe a surface that does
   not exist), and the architecture autolock staleness.
4. **Decide the demo story**: the Node.js + MariaDB tutorial end-to-end on the new
   testbed is the natural showcase; re-run it once on the announced build.

### P1 — credibility items for this specific audience
5. **Man pages**: `satl(1)`, `satld(8)`, `satld.toml(5)`. None exist. For the FreeBSD
   community this is not optional polish; it is the first thing reviewers open.
6. **A ports skeleton** (`sysutils/satl` — the package MANIFEST already claims that
   origin). Even an unsubmitted, working port in-tree signals intent; a submitted one
   starts the relationship with ports@ the right way.
7. **CI**: Cirrus CI provides FreeBSD VMs and is what FreeBSD-adjacent projects use.
   Even a build + `make check` pipeline (no jails/ZFS needed for the unit suite)
   retires the "no CI" caveat from the README and gives contributors a checks tab.
8. **Report the ocijail fast-exit stdio finding upstream** (cperciva/ocijail), with the
   reproduction. Good citizenship, it is their layer, and it is the kind of
   collaboration the announcement can point to.
9. **Pin the compatibility statement**: FreeBSD 15.1-RELEASE amd64, ocijail 0.6.0,
   rustc ≥ 1.96 — and what happens on 15.2/16.0 (the `RUN`-in-chroot build already
   says "build on the major you deploy").
10. **Publish the user documentation site** (satl-doc) at a stable URL and link it
    from the README before the announcement, not after.

### P2 — say it in the talk, fix it after
11. The open-defect list of section 4, verbatim — leading with `satl kill` (#1) and
    private-registry pulls (#2), because early adopters will hit both in week one.
12. The roadmap: health decoupling, worker mesh, service logs, IPv6, authz,
    remote (TCP+mTLS) API, offline quorum recovery, volume plugins.
13. Where to present: an announcement on freebsd-jail@/freebsd-virtualization@ and the
    FreeBSD forums; a talk proposal for EuroBSDCon/BSDCan/AsiaBSDCon; the FreeBSD
    Journal takes exactly this kind of article. The comparison in Annex A is the
    natural backbone of a talk ("Swarm semantics, jail mechanics").

---

# Annex A — SatL vs Docker Swarm (SwarmKit)

Docker Swarm behavior below is taken from the SwarmKit behavioral spec (SWK §n) and
moby's source; SatL behavior from the roadmap's measured milestones and the numbered
API-compatibility ledger. "Measured" marks claims backed by a recorded measurement.

## A.1 Cluster membership & roles

| Area | Docker Swarm (SwarmKit) | SatL | Delta |
|---|---|---|---|
| Bootstrap | `swarm init` creates the cluster; a daemon is `inactive` until then | **No standalone mode**: first boot *is* the init, a single node is a cluster of one; `POST /swarm/init` is idempotent (api-compat #42) | Different by design. `--advertise-addr` on init is always refused (set it in `satld.toml`) |
| Join | Token decides role, `SWMTKN-1-<digest>-<secret>`, one TCP port (2377) | Both tokens work (M4); format `SATL-1-…`, same digest-pins-bundle scheme; **two ports**: 2377 mTLS + 2378 unauthenticated NodeCA bootstrap (#55, #56) | Near-parity; tooling matching `SWMTKN` breaks |
| Raft join mechanics | etcd/raft one-step add, leader health-checks the joiner | **Learner-first, promoted asynchronously** (openraft joint consensus) | Different by design, forced by the Raft library |
| Worker role | First-class; worker runs standalone containers too | Works since M4; worker holds no store: cluster-scoped REST answers Docker's exact `errNoManager` **503**, container *mutations* also 503 (#79–#86) | **SatL gap.** Supported v1 shape is **all-managers** |
| Promote / demote | Reconciled `DesiredRole`, demotion raft-first | Same shape, **applied live**: measured ~700 ms promote / ~100 ms demote at constant pid, containers untouched (#48) | Parity, verified. SatL also disables TLS 1.3 resumption so a stale role cannot survive a reconnect |
| Availability active/pause/drain | Yes; drain forces restart delay to 0 | Implemented, proven live; same drain rule | Parity |
| Node removal | Refusals without force; cert blacklisted to expiry+7 d | Same; removal blacklist derived in the FSM | Parity |
| Leadership transfer | `TransferLeadership` | openraft 0.9 has none; `yield_leadership` stands in | SatL weaker |
| Dead-node handling | TTL → DOWN; leadership change re-owes registration | Same; **killed leader converges to Down and its tasks are evicted**; grace 30 s vs re-registrations measured 2.9–7.5 s | Parity, verified (`leader_kill` scenario) |

## A.2 Raft store & consensus

| Area | Docker Swarm | SatL | Delta |
|---|---|---|---|
| Engine | etcd/raft + go-memdb | openraft 0.9 + redb on a ZFS dataset; passes the openraft storage compliance suite | Different implementation, same model |
| Encryption at rest | WAL + snapshots always encrypted (NaCl secretbox) | XChaCha20-Poly1305, per-manager DEK `0600`, sealed under the KEK with autolock | **Parity, not a SatL advantage** (Swarm encrypts by default too). SatL is stricter: missing/lax `dek` → refuse to start (#139) |
| Optimistic concurrency | `Meta.Version`, sequence conflicts | Same (`?version=` enforced, #54) | Parity |
| Batching / limits | 200 actions / 1.5 MiB per tx; 4 MiB gRPC | Replication batch **derived** from the two limits (root cause of the 2026-08-13 stalls, fixed) | SatL advantage (derived, not defaulted) |
| Watch | Store watch + public Watch API | Internal watch feed only | SatL missing (niche) |
| Disaster recovery | `ForceNewCluster` | **501, permanently**; restore `<state_dir>/raft` incl. `dek`, or rejoin (**measured 6 s**) | **SatL gap.** Quorum permanently lost = unrecoverable from inside; policy: back up 2 of 3 |
| Known defect | — | `service satld stop` hangs on a quorum-lost manager | SatL gap, open |
| Extensions / custom resources | `Extension`/`Resource` objects | Absent | SatL missing (niche) |

## A.3 CA, mTLS, rotation, autolock

| Area | Docker Swarm | SatL | Delta |
|---|---|---|---|
| CA & identity | Embedded CA, ECDSA P-256, CN/OU/O scheme | Same construction (rcgen/rustls), role enforced per RPC | Parity |
| Node certs | 90 d, renew at 50–80 %, live swap | Same; live swap via resolver seams; **proven with 5-min certs: 3 cycles, 0 restarts, reconnects ~250 ms** | Parity, verified |
| Root rotation | Cross-signed intermediate; tokens regenerate at completion | Same shape, resumable across elections; **measured 0/339 requests lost**. Tokens rotate **twice** (start + completion, #106); a second rotation during one is refused (#105) | Parity, verified; two deliberate deviations |
| Rotate to supplied material / external CA / FIPS | Supported | 501 / out of scope | SatL missing |
| Autolock / KEK | `SWMKEY` unlock key, sealed TLS key | M7f: sealed raft DEK; locked manager serves only `/_ping` + unlock | Parity |
| User-level authz | None | None (socket group root-equivalent) | Parity (both coarse) |

## A.4 Task model

| Area | Docker Swarm | SatL | Delta |
|---|---|---|---|
| Task semantics | One-shot, immutable, sparse Lamport states | Same state machine and ownership rule | Parity |
| Spec immutability | Never modified | One sanctioned breach: hot resize rewrites live resources | SatL advantage, scoped |
| History / reaper | Retention limit | Pruned to `max_attempts + 1`, load-bearing for the derived restart budget | Parity + soundness argument |
| Leader-change recovery | `taskinit` replays once per election | **Budget derived from the store every pass** (taskinit applied continuously) | SatL advantage |
| Restart delay resume | Remaining delay resumes | Fresh delay (queue has no store form) | SatL gap (pacing) |
| Constraint eviction | Observed `REJECTED` | SHUTDOWN + replacement, so a label edit never spends an update's failure budget | SatL different by design |
| `kill` semantics | Desired state untouched; supervisor replaces | **`satl kill` retires the slot** (0/N until spec change, #146) | **SatL gap**, documented |

## A.5 Services & scheduler

| Area | Docker Swarm | SatL | Delta |
|---|---|---|---|
| Replicated / global | Yes | Yes — measured: 6 replicas → 2/2/2, node kill → 3+3 | Parity, verified |
| Jobs | `ReplicatedJob`/`GlobalJob`, `JobIteration` | Yes (M7e), verified live; gaps: immediate retries, `Restart.Window` ignored, `JobIteration` not rendered | Parity minus three stated gaps |
| Unnamed service | Requires a name | Generates one (#49) | SatL convenience |
| Unsupported spec fields | Often honoured/ignored | **400, never silently dropped** (#50) | Fail-loud policy |
| Templating / generic resources (GPU) | Supported | 400 / absent | SatL missing |
| Filter pipeline | + Plugin, CSI-volume filters | Ready/Resource/Constraint/Platform/HostPort/MaxReplicas | Missing filters have no object to filter on |
| Constraint language | SwarmKit's | Reimplemented in `satl-core` | Parity |
| Ranking | Fault penalty → spread | Same, incl. 5-in-5-minutes penalty | Parity |
| Placement preferences | `SpreadOver` tree | `spread=` validated at the API, **re-ranked after each placement in a batch** | Parity in effect |
| Reservations re-check | Enforcer re-checks | Not re-checked (scheduler's mirror only) | SatL gap, deliberate |

## A.6 Updates, rollback, restart

| Area | Docker Swarm | SatL | Delta |
|---|---|---|---|
| Update config | Full set | Full set + rollback with pause-on-failed-rollback | Parity |
| Evidence | — | **6 replicas under load, 0 requests lost; broken image auto-rolled back; 6,612 requests 0 lost through the mesh** | Verified |
| Monitor window | Background watch; next batch ASAP | **Window is part of the batch** (≥ monitor per batch, #93) | Slower, strictly safer, by design |
| Health gating | Executor waits healthy | Task stays STARTING until a probe passes (#87) | Parity — and the base of zero-loss |
| Paused update resume | Any update clears status | Same (#92) — but a transient failure poisons resumes (spec-bump workaround) | SatL defect, documented |
| Restart policy | condition/delay/attempts/window | Same; absent `Delay` filled with 5 s at admission (#153, after a measured crash-loop) | Parity; `Window` not honoured for jobs |
| CLI flags | Full | Twelve update/rollback flags; **missing `--restart-delay/-max-attempts/-window`, `--rollback`, `--force`** | SatL CLI gap (REST works) |
| Hot vertical resize | **Not available** (any change rolls) | **Resources-only update rewrites live rctl rules, same task IDs** — verified against live PostgreSQL | **SatL advantage** |

## A.7 Networking

| Area | Docker Swarm | SatL | Delta |
|---|---|---|---|
| Overlay data plane | VXLAN via libnetwork | VXLAN in-tree; static FDB via ioctl, learning off, delta reconciler. **MTU 1450 measured; DF boundary 1422/1423** | Parity in function, self-contained |
| Allocator restore | Once per leadership | Structural, every pass | SatL advantage |
| Gateway | Cluster-wide model | **Per node**, `.1` reserved for nobody (#61) | Different by design |
| Service discovery | **VIP (IPVS) default** + DNSRR | **DNS-RR only**; `vip` → 400, `VirtualIPs` empty (#50, #52) | **Largest SatL gap, platform-forced** (no IPVS on FreeBSD) |
| DNS resolver | Sandbox-scoped, emergent order | Task-scoped, **deterministic spec order**; no `<name>.<network>` form (#73, #74) | Mostly parity |
| Routing mesh | Every node, IPVS | **Every manager**, pf relay over `ingress` overlay + return SNAT; measured (relay, round-robin, 40 MB, ~8 s depool) | Partial gap: workers keep node-local behavior |
| Pool health | IPVS does not probe either | pf tables; **9.97 s probe-failure-to-depool measured** (vs ~90 s at Docker defaults) | **SatL advantage** — cost: depool = replace (#88) |
| Data-plane encryption | `--opt encrypted`, IPsec, 12 h rotation | Same flag; ESP aes-gcm-16, **MTU 1416 measured**, keyring to participants only, + pf cleartext guard (FreeBSD SPD gap found by measurement). Ingress network can never be encrypted | Parity, verified, + a SatL-only guard |
| IPv6 | Supported | **None** — IPv6 anything → 400 (#63) | **SatL gap** |
| Attachable / internal / connect-disconnect | Supported | 400 / 400 / 501 (follow from the task model) | SatL missing |
| Predefined bridge/host/none | Present | Do not exist (#68) | Different |

## A.8 Port publishing

| Area | Docker Swarm | SatL | Delta |
|---|---|---|---|
| Modes | ingress + host, 30000–32767 | Same allocation, sticky (#75) | Parity |
| Ingress + DNSRR | Rejected | Accepted — no VIP to protect; refusing would refuse all published ports (#77) | Different by design |
| Local balancing | IPVS cluster-wide | One pf rdr rule, round-robin over the node's tasks (#76) | Different mechanism |
| PROXY protocol | Not available | **`satl.publish.proxy_protocol=v2`** — real client address, health-aware selection, verified | **SatL advantage** |
| Ranges / SCTP / per-IP | Supported | 400 / TCP-UDP only / warns-and-publishes-all (#7, #25) | SatL gaps |
| localhost reachability | Works (iptables OUTPUT) | **Unreachable from the publishing host by any address** (pf property, #35) | SatL gap, platform-forced |

## A.9 Secrets, configs, volumes

| Area | Docker Swarm | SatL | Delta |
|---|---|---|---|
| Secrets/configs | Store objects, tmpfs delivery, 500 KiB/1000 KiB | Same API and limits; **tmpfs-only proven by full-filesystem search during a run** | Parity, verified |
| Secret target | Arbitrary absolute path | Relative only, under `/run/secrets` (#100) | Restriction (deliberate) |
| tmpfs mount | `ro` | Writable; file-mode protection only (#101) | SatL gap |
| UID/GID by name | Resolved from image | Numeric only (#102) | SatL gap |
| Update | Labels only | 501 with the rotation recipe (#97); in-use delete → 409 naming services (#98) | Different, arguably better |
| Secret drivers / templating | Supported | 400 (#103) | SatL missing |
| Cluster volumes (CSI) / plugins | Full CSI lifecycle / any driver | **None** / `local` (ZFS) only | **SatL gap** — stateful = pinned by constraint |

## A.10 Compose, images, build

| Area | Docker Swarm | SatL | Delta |
|---|---|---|---|
| Compose/stack | CLI-side; **silently drops** unsupported keys | `satl compose` + `satl stack`; stack semantics; ~40 keys refused with file/service/key/reason; label-scoped `down`. DoD stack verified (secret assertion cannot pass by accident) | **SatL advantage** (refuse-whole). Gaps: no interpolation, one `-f`, no merge/include/extends, secrets `external: true` only |
| Build | dockerd BuildKit, `POST /build` | **`satl build`/Satlfile**: incremental cache (7 s vs 51 s), multi-stage, `FROM scratch` 1.4 MB; client-side, FreeBSD images only | **SatL advantage for FreeBSD** (no other tool exists); `POST /build` is 404 |
| Registry auth | Shipped with the task | Honoured on pull endpoint only; **dropped on service/container create** | **SatL defect** (section 4 #2) |
| Image management | Full | ls/rm/prune/inspect/tag/push; targeted rm runs two agreeing passes (~2 s measured); history/save/load 404 | Near-parity |
| GC | Per-object prunes | Two-pass layer GC closed upward through the clone graph; measured | Parity + stronger safety discipline; node-local |

## A.11 Logs, API, platform, ops

| Area | Docker Swarm | SatL | Delta |
|---|---|---|---|
| Service logs | Log broker, cluster-wide | **None** — per-container, node-local; + the fast-exit stdout loss (ocijail) | **SatL gap** |
| Exec | Single-node in both | Non-interactive, no TTY, output at exit; unix-socket-only CLI (ssh to the node) | SatL weaker per-node |
| Client API | gRPC Control API; Docker fronts it | **Docker Engine API v1.43+ on a unix socket only**; 166 numbered deviations; generated OpenAPI 3.1 contract drift-gated by `make check` | Different by design; the deviation ledger is a practice Swarm has no equivalent of |
| Container model | Standalone containers exist | **A container is a task**: `start` after `stop` → 409, `rm` removes the service, no attach/commit/stats/pause | Deepest source of deviations, by design |
| Platform | Linux (+ some Windows) | **FreeBSD 15.1 amd64 only**; VNET jails via ocijail; linuxulator for linux/amd64 images; ZFS mandatory; rctl limits | **SatL's raison d'être** and its hard limit |
| Isolation knobs | privileged/caps/seccomp/sysctls | All 400; escape hatch `satl.jail.<param>` labels → OCI annotations (#145) | Different by design |
| Backup/restore | rafttool, docs | **Validated on 3 machines**: zfs snapshot of `raft/`; rejoin measured 6 s; "back up 2 of 3" policy from a real experiment | Parity + measured guidance |
| Metrics | `swarm_*` names | Docker's exact series names where they exist + `satl_*`; per-task usage from rctl, no cAdvisor | **SatL advantage** |
| Formal grounding | TLA+ specs | No formal spec; instead 22+7 scripted cluster scenarios + measured decision log | Different kinds of rigor |
| CI | Docker's infra | **None** — `make check` on FreeBSD is the only gate | SatL gap |

## A.12 The deltas that matter most

**Where Swarm is ahead:** VIP/IPVS load balancing (the one big architectural gap,
FreeBSD-forced) · cluster-wide `service logs` · first-class workers (SatL's mesh and
cluster REST are manager-only) · IPv6 · CSI/volume plugins · attachable/internal
networks and `network connect` · `ForceNewCluster` recovery · interactive exec ·
`docker kill` semantics · richer CLI flags and filters.

**Where SatL is ahead:** hot vertical resize (Swarm rolls on any change) · `satl build`
as *the* FreeBSD image tool (BuildKit does not target FreeBSD) · PROXY-protocol publish
mode (real client address; Swarm's mesh cannot) · measured ~10 s health-to-depool vs
~90 s · restart budget and allocator state re-derived from the store every pass (no
election replay) · refuse-rather-than-half-apply across the whole surface · operational
fail-safes (no self-init over a manager cert, no re-key over sealed state, two-pass
layer GC) · Prometheus series Docker dashboards already understand + rctl-native
per-task usage · a numbered, public ledger of every API deviation.

---

*Report generated 2026-08-23 against commit `910f452`. Not committed (by request).*
