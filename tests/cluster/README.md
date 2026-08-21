# SatL cluster test harness

Everything needed to turn the three OVH FreeBSD VMs into a SatL test cluster,
and the entry point `make cluster-test` runs against them.

All of it is POSIX `sh`, no bashisms, `set -e`, and every `ssh` uses
`BatchMode=yes`, a script here can fail, but it can never sit waiting for a
password or a host-key prompt.

## The nodes

`inventory.toml` is the **single source of truth** for node names, addresses,
roles and the manager port. CLAUDE.md forbids hardcoding the VM addresses
anywhere else, so no script contains a hostname, an IP, a port, or the
assumption that node1 is the bootstrap manager, they ask the inventory
(`bootstrap_node`, `nodes_with_role joiner`, `cluster_setting manager_port`).
Re-created a VM? Edit that file, nothing else.

| | |
|---|---|
| public NIC | `vtnet0`, public IP, SSH from the dev host, container egress NAT |
| private NIC | `vtnet1`, **10.0.0.0/24**, the cluster underlay |

**The private-network assumption:** Raft, the dispatcher and (from M3) the
VXLAN overlay run over 10.0.0.0/24, never over the public addresses. `run.sh`
proves it every run by pinging each node's peers from each node. The dev host
(alpha) is *not* on that network, it reaches the VMs over SSH on their public
addresses only, which is why images get to the VMs the way they do (below).

## Scripts

| Script | What it does | How often you run it |
|---|---|---|
| `provision.sh` | host prerequisites: packages, `kern.racct.enable=1` (+ reboot), IP forwarding, pf + `satl/*` anchors, `zroot/satl` | once per VM lifetime |
| `deploy.sh` | `make release`, then install `satl`/`satld`/rc.d/config exactly where `make install` puts them, restart the service | after every code change |
| `images.sh` | run a loopback-only test registry on each node and seed it with the SatL test images | once, then only when images change |
| `run.sh` | `make cluster-test`, the readiness gate plus the M2-M5 scenarios | every test run |
| `encrypted.sh` | the M6 encrypted-overlay scenarios (create, wire proof, MTU, pf guard, live key rotation, teardown); deploys itself, including a mid-run re-deploy with the `keyring_*_secs` testing knobs | after `run.sh init_and_join` (needs a formed cluster) |
| `reset.sh` | wipe cluster state on a node (raft, certs, identity, jails, epairs, anchors, SAD/SPD) and start over | constantly, during M2 |
| `lib.sh` | sourced by all of the above: the one and only `inventory.toml` parser, plus the ssh/scp wrappers | never directly |

All of them but `run.sh` take an optional list of node names, with none, they
act on every node in the inventory, and each is idempotent, so re-running a
converged node is a no-op that still prints the full report. `run.sh`'s
arguments are *scenario* names; it takes node names only after `-r`.

```sh
sh tests/cluster/provision.sh              # all nodes
sh tests/cluster/provision.sh node2        # just one
sh tests/cluster/deploy.sh
sh tests/cluster/images.sh
make cluster-test                          # == sh tests/cluster/run.sh
```

Useful environment variables:

| Variable | Effect |
|---|---|
| `SATL_INVENTORY` | use a different inventory file |
| `SATL_WITH_LINUX=1` | `provision.sh` also installs `linux_base-rl9` (361 MiB) and enables the linuxulator, so `linux/*` images can run on the VMs. Off by default: M2 scenarios use FreeBSD images, and `run.sh` reports the linuxulator as an advisory line rather than a failure |
| `SATL_SKIP_BUILD=1` | `deploy.sh` ships the existing `target/release` binaries |
| `SATL_IMAGES` | override the seeded image list |
| `SATL_TUNNEL_PORT` | remote port used for the seeding tunnel (default 15000) |
| `SATL_TEST_IMAGE`, `SATL_TEST_SERVICE`, `SATL_REPLICAS` | what the scenarios run (default: the seeded nginx, `web`, 6) |
| `SATL_TEST_PUB_SERVICE`, `SATL_TEST_PUB_PORT` | the published-port scenario's service and port (default `pub`, 18080) |
| `SATL_TEST_GLOBAL_SERVICE`, `SATL_TEST_GLOBAL_MONITOR` | the global service and the monitor window of its rolling update (default `gagent`, 8 s) |
| `SATL_TEST_DRAIN_SERVICE`, `SATL_TEST_DRAIN_REPLICAS`, `SATL_TEST_DRAIN_DELAY` | the service the drain moves, and the long restart delay that makes the drain's speed a measurement (default `drainee`, 6, 30 s) |
| `SATL_TEST_CONSTRAINT_SERVICE`, `SATL_TEST_CONSTRAINT_REPLICAS`, `SATL_TEST_CONSTRAINT_DELAY`, `SATL_TEST_CONSTRAINT_LABEL` | the constrained service, its replicas, the restart delay a constraint change must *pay*, and the node label it is placed by (default `zoned`, 3, 10 s, `zone`) |
| `SATL_TEST_BUDGET_SERVICE`, `SATL_TEST_BUDGET_ATTEMPTS`, `SATL_TEST_BUDGET_DELAY` | the crash-looping service, its `MaxAttempts`, and the delay that is also the window in which the leader has to be killed (default `flapper`, 2, 25 s) |
| `SATL_TEST_COMPOSE_PROJECT`, `SATL_TEST_COMPOSE_DIR`, `SATL_TEST_COMPOSE_PORT`, `SATL_TEST_COMPOSE_SECRET` | the compose stack's project (and the directory it is derived from -- keep the two in step), its published port and its secret (default `cstack`, /tmp/cstack, 18086, `cs_redis_auth`) |
| `SATL_POLL`, `SATL_T_*` | poll interval and the scenario timeouts, `run.sh -h` lists them. `SATL_T_SETTLE` (40 s) is the odd one: it is how long the M4 scenarios watch for something *not* happening |

### First-time bring-up

```sh
sh tests/cluster/provision.sh    # reboots each VM once: racct is a boot tunable
sh tests/cluster/deploy.sh
sh tests/cluster/images.sh
make cluster-test                # everything green
```

`provision.sh` reboots a VM when `kern.racct.enable` is not already 1 and waits
for it to come back (up to 5 minutes). VMs may be rebooted freely; **the dev
host never is.**

## Configuration the harness imposes on a node

`deploy.sh` writes `/usr/local/etc/satl/satld.toml`, `make install` only ships
the `.sample`, but a test cluster wants two things pinned:

- `pf_mode = "enforce"`, so published ports actually get a `satl/rdr` rule
  (`provision.sh` has already declared the anchors in `/etc/pf.conf`);
- `node_name` set to the **inventory** name (`node1`, `node2`, `node3`), so
  cluster assertions can name a node deterministically instead of depending on
  whatever hostname the cloud image happens to boot with.

That file is rewritten on every deploy. Change the template in `deploy.sh`,
not the copy on a node.

`provision.sh` also pins the running hostname into `rc.conf`: the OVH images
ship `hostname="freebsd"` and rely on the cloud-init datasource to set the real
one at boot, which is a good way to end up with three nodes convinced they are
the same host.

## Images on the VMs, the decision

The integration images live in the dev host's registry on `127.0.0.1:5000`:
unauthenticated, plain HTTP, loopback only, by design
(`docs/image-sources.md` §2). The VMs cannot reach it.

Measured, not assumed (2026-08-10; re-measured 2026-08-19 on the replacement
VMs, where all three still hold):

- alpha has **no address on 10.0.0.0/24**, its second NIC (`ice1`) is up but
  carries no IPv4, so "bind the existing registry on the private interface",
  the cheapest option on paper, is not available at all. Pinging a node's
  underlay address from alpha loses 100% of packets; that is the check to
  re-run, rather than trusting this sentence;
- the VMs *can* reach alpha's public IP, but publishing an unauthenticated
  read-write registry on a public address is not something a test harness gets
  to do;
- the VMs reach each other over the underlay at sub-millisecond latency
  (0.76 ms and 0.86 ms average over 30 packets, no loss).

**Chosen: one loopback-only registry per VM, seeded from the dev host over an
`ssh -R` reverse tunnel** (`images.sh`). Each node runs the same
`docker-registry` package with the same config and repository names as alpha.

Why this over the alternatives:

- **Image references stay identical to the single-node integration tests**,
  `127.0.0.1:5000/satl-test/freebsd-nginx:latest` means the same thing on
  every host. No test has to know which node it is running on, and no per-node
  URL rewriting exists to get wrong.
- **No node depends on another for images.** The obvious alternative, one
  registry on the bootstrap node, the other two pulling from its private
  address, is one fewer copy, but it makes the image source die with node 1.
  "Kill a node, watch its tasks reschedule" is an M2 DoD scenario; a
  rescheduled task failing to pull because the registry went down with the
  node it was testing is a failure that teaches nothing.
- **The reverse tunnel keeps the copy registry-to-registry**, so
  `skopeo copy --all` reproduces the source index byte-for-byte, manifest
  lists and all, verified: the digests seeded on the VMs match the ones
  recorded in `docs/image-sources.md` §1 exactly. Shipping an OCI layout by
  `scp` would not preserve multi-platform indexes as reliably, and platform
  selection is precisely what those images exist to test.

Cost: about 100 MB copied three times instead of once, and three registries to
keep alive. Re-runs transfer almost nothing, skopeo skips blobs the
destination already has.

The registry stores its blobs in `/var/db/satl-test-registry`, deliberately
**outside** `zroot/satl`: this is test infrastructure, not satld state, and
`reset.sh` destroys `zroot/satl` without taking the images with it.

## Resetting a node to a clean state

M2 means running init/join over and over, and a node still holding raft state,
certificates or a node identity from the previous run will refuse to join, or
worse, silently rejoin the cluster it is supposed to be new to.

```sh
sh tests/cluster/reset.sh              # all nodes, satld restarted clean
sh tests/cluster/reset.sh node3        # just one
sh tests/cluster/reset.sh --no-start   # leave satld stopped
```

It stops `satld`, removes every jail rooted under `/var/db/satl` and every
interface SatL marked with a `satl:` description (epairs leak when a teardown
is interrupted), flushes **only** the `satl/nat` and `satl/rdr` pf anchors,
unmounts anything left under the state directory, then destroys and recreates
`zroot/satl`, raft log, DEK, node identity, certificates, images, layers,
volumes, all gone, and starts `satld` again on a fresh identity.

It does **not** touch packages, sysctls, `/etc/pf.conf`, the installed
binaries, or the test registry. Those are `provision.sh`/`deploy.sh` territory,
and re-running either is cheap.

Doing it by hand on one node is three commands:

```sh
sudo service satld stop
sudo zfs destroy -r zroot/satl && sudo zfs create -o mountpoint=/var/db/satl zroot/satl
sudo service satld start
```

`reset.sh` exists because the jail, epair and pf leftovers are what actually
bite you.

## `run.sh`, the readiness gate and the scenarios

```sh
make cluster-test                            # gate + every scenario + cleanup
sh tests/cluster/run.sh                      # the same thing
sh tests/cluster/run.sh node_kill            # gate + one scenario
sh tests/cluster/run.sh node_kill cleanup    # gate + these two, in this order
sh tests/cluster/run.sh --list               # the scenario names
sh tests/cluster/run.sh -r                   # the readiness gate only
sh tests/cluster/run.sh -r node2             # ... on one node
```

The gate always runs first and always gates: a scenario against a
half-provisioned cluster fails in ways that look like orchestration bugs and are
not. With no argument the whole suite runs and ends with `cleanup`; with named
scenarios only those run, so a single scenario leaves the cluster inspectable.

Every wait is a bounded poll, `wait_until <seconds> <what> <test>`, that
prints what it is waiting for and how long it took. There is no `sleep` anywhere
else: a slow cluster reads as slow, a broken one as broken. On a timeout, and on
any failed assertion, the run prints the live cluster state (`satl node ls`,
`satl service ps`), the jails / task epairs / container datasets per node, the
tail of each node's `satld` tracing, the scenario that failed and the one command
that re-runs it. Exit status is non-zero on the first failure.

A join token is never printed and never passed in an argv: it goes to the
joiners inside the script on ssh's stdin, and any captured command output is
filtered on the way out (`satl swarm init` prints the *worker* token in its own
success message).

### What each scenario asserts

**`init_and_join`**, M2 DoD #1. Wipes every node (`reset.sh`), `satl swarm init`
on the inventory's `bootstrap` node, `satl swarm join --token … --advertise-addr
<private>:2377 <bootstrap>:2377` from each `joiner`. Then, until it holds on
*every* node: three nodes listed, all `Ready`, exactly one `Leader` and exactly
two `Reachable`; every node's Manager Status address is its own `inventory.toml`
`private_ip:2377`; and every `HOSTNAME` cell is that node's real hostname, with
no cell showing the `satld.toml` `node_name` label, that column used to show the
config label (fixed in 39c86c4), which would make every other node-named
assertion here lie convincingly.

> `satl swarm init --advertise-addr X` is **always** refused by `satld`, first
> boot *is* the init (architecture §1.2), and rebinding the internal listener is
> a restart, not a request. The address is pinned in `satld.toml` by `deploy.sh`
> instead (without it `satld` advertises the default-route interface, the public
> NIC on these VMs). So the scenario runs `satl swarm init` bare and asserts what
> `--advertise-addr` was meant to guarantee. `satl swarm join --advertise-addr`
> is accepted and is used.

**`worker_join`**, M4. The one scenario that runs a *mixed-role* cluster: after
a wipe, node1 inits, node2 joins as a **manager**, node3 with the **worker**
token (no raft, no store, no listener, architecture §1.2). Asserts, in order:
the join printed "joined a swarm as a worker" and `node ls` shows 3 `Ready` /
1 `Leader` / 1 `Reachable` with node3's Manager Status empty; on node3,
`service ls` / `node ls` / `network ls` / a container mutation answer **moby's
`errNoManager` sentence verbatim** (503, api-compat #79-#80) while `satl ps`
lists exactly the containers the managers placed there (#81); six replicas
spread 2/2/2 puts tasks on the worker, and an overlay service pinned to node3
resolves one pinned to node1 **by name from inside its jail** and fetches the
body across the underlay, DNS answered without a store (§11.5); `satl node
promote` applies **live**, `Reachable` with the same daemon pid, and a `scale`
submitted *through node3* commits (follower → leader forwarding included);
`satl node demote` reverses it live, same pid, refusal back, running
containers untouched; a killed worker converges exactly like the M2 follower
case (Down on TTL, tasks evicted to the two managers, quorum intact, a worker
counts for none, strays reaped when it returns *as a worker*, restarted from
`managers.json`); and node3 is promoted again, leaving the all-manager cluster
every later scenario expects.

**`replicas_spread`**, M2 DoD #2. `satl service create --name web --replicas 6`
of the seeded nginx image; asserts 6/6, a **2/2/2** spread of the running tasks
(the scheduler's spread ranking, not six tasks on whichever node is leader), six
container jails cluster-wide with live processes, and **no task in a `Rejected`
or `Failed` state anywhere in the service's task history**, a
layer-application race (fixed in db38347) used to reject a task on the node that
pulled the image second, and the service still reached 6/6 afterwards, so 6/6
alone did not catch it.

**`node_kill`**, M2 DoD #3, plus the regression guard for 18285de. Stops
`satld` on a non-leader node and **leaves its jails running on purpose**:
`satld`'s shutdown does not touch them, so its two containers become strays that
outlive their tasks. Asserts: the node is reported `Down` once its session TTL
expires (~15s); its containers really are still running (otherwise the last
assertion proves nothing); six tasks Running again with none on the dead node;
then, after the node is restarted, back to `Ready`, the service back to exactly
6/6, none of the stray jails holding a process, exactly six containers
cluster-wide, and one jail with processes per live task on every node. Before
18285de a returning node kept its strays alive and the service sat at 7/6 or 8/6
with nothing in the log to grep for.

**`leader_kill`**, M2 DoD #4, upgraded in M4 to assert eviction. `kill -9` on
the leader's `satld` (a manager runs tasks too, architecture §1.2; losing one of
three keeps quorum at two). Asserts: both survivors keep answering reads; the
killed ex-leader converges to **`Down`** on every survivor's view, the new
leader seeds a registration expectation for every store node it never heard
from (SWK §13.2), and a node that fails to re-register within the grace period
(2 × session TTL = 30 s; measured re-registration is 2.9–7.5 s) expires through
the ordinary TTL sweep; the dead node's tasks are **evicted and rescheduled**,
the service back at six live tasks with none on the dead node, spread over the
two survivors; **each** survivor accepts a `satl service scale` and the new
desired count reads back, exactly one of the two is the new leader, so one of
those writes necessarily travelled follower → leader through
`Control.ProposeActions`; and after the killed node rejoins `Ready`, its stray
containers are reaped by the returning agent (their tasks were evicted, like
`node_kill`'s), 3/3 with three containers cluster-wide and one jail per live
task.

**`overlay_dns`**, the M3 DoD. Creates one `-d overlay` network, waits until
every node can inspect it with an allocated `Subnet` and `Vni` (the object is
raft state but the allocator runs only on the leader), then creates two
single-replica services on it, each **pinned to a named node** with a
`node.hostname` constraint. Asserts that the pinning held, both tasks have a
live jail on the node they were pinned to, before asserting anything about
traffic, because a run where both landed on one node would pass every remaining
check while proving nothing about the overlay.

Reachability is `fetch http://<service-name>/` from inside a jail, **in both
directions**, expecting the body the test image bakes in. One command covers the
whole chain the DoD names: the resolver answers, the FDB entry carries the
frame, the ARP entry lets the peer reply, and a TCP conversation completes.
Pinging an address instead would pass with DNS completely broken; testing one
direction only would pass with one node's tables unprogrammed, since the FDB and
ARP tables are per node.

The MTU is asserted at the **DF boundary**, 1422 bytes of payload passes, 1423
is refused, not by reading `ifconfig` back. A wrong overlay MTU does not fail
functionally: `vxlan_encap4()` clears DF, so oversized frames are fragmented
rather than dropped (`docs/vxlan.md`), which costs throughput and amplifies loss
while every functional test still passes. Reading the value back only proves we
wrote what we meant to; the DF boundary proves what the container can actually
send.

Teardown is asserted too: after both services and the network are removed, no
node may be left with an overlay bridge, epair or VTEP. Interrupted VNET
teardown leaking epairs is a known FreeBSD failure mode (CLAUDE.md), so a
scenario that created an overlay and never checked it disappeared would hide
exactly that.

> The image is built on `freebsd-runtime`, whose `/rescue` carries static
> `fetch` and `ping`. It has no `drill` or `host`, which is why DNS is asserted
> through `fetch` rather than by reading a DNS answer directly.

**`overlay_dns_multinet`**, resolution scope, which `overlay_dns` structurally
cannot test: with a single network every task's scope is the same scope, so that
scenario passes whether the responder scopes queries to the socket, to the node
or to the whole cluster. Two overlay networks and three pinned services, `mn-x`
on `ovlx` and `mn-both` on both, on node A; `mn-y` on `ovly`, on node B, then
three assertions, each failing on a different wrong implementation:

1. `mn-both` → `mn-x`: the control. Same node, first attached network.
2. `mn-both` → `mn-y`: the regression catcher. A different network *and* a
   different node. Scoped to the socket, a stub resolver asks one `nameserver`
   line, gets an authoritative NXDOMAIN for a name that lives on the other
   network, caches it, and never tries the second line, so this is the defect,
   and it is asserted through `fetch` so that a pass also proves the second
   network's data path.
3. `mn-y` must **not** resolve from `mn-x`'s jail: the over-widening catcher.
   Node A's responder demonstrably knows `mn-y` (assertion 2 just resolved it
   there), so answering from every network the *node* holds, the obvious wrong
   way to fix 2, would leak one network's service names into another. The
   output is checked, not just the exit status: a resolution failure and a
   connection timeout mean opposite things here.

The jail's `nameserver` line count is asserted first (2 for `mn-both`, 1 for
`mn-x`). Without it, a second `--network` silently dropped between the CLI and
the allocator would leave assertion 3 passing for the wrong reason and the
scenario proving nothing. Teardown is audited for both networks, as in
`overlay_dns`. Behaviour and the Docker comparison: `docs/api-compat.md` #73/#74.

**`publish_port`**, `satl service create --publish 18080:80`, asserted from
**outside** the cluster: this dev host reaches the VMs on their public addresses
and nowhere else, which is both the only vantage point that can answer "which
node serves this port" and the only one that works at all (api-compat #35: pf
redirects packets *entering* an interface, so a node's own `localhost` is not
redirected). Until M3 the port was accepted, allocated, documented, and
published nowhere; no scenario had ever asked a node for a port, which is how
that survived three milestones.

Two replicas over three nodes, deliberately: fewer replicas than nodes means at
least one node runs no task whatever the scheduler decides, and *which* nodes
got a task is read from `satl service ps` rather than assumed. Then:

1. every node running a task answers on the published port with the body the
   image bakes in, and holds a rule for it in its `satl/rdr` anchor;
2. the node running **no** task answers too, by relaying (the M6d mesh,
   api-compat #75): it holds the same rdr rule, the pool is cluster-wide,
   plus the return-path SNAT rule that makes the relayed handshake complete.
   (Until M6d this assertion was the inverse, "neither answers nor holds a
   rule", pinning the mesh gap as tested behaviour; implementing the mesh
   started by deliberately changing it);
3. the redirect survives its anchor being destroyed behind the daemon's back,
   first with `satld` running, where only the periodic level pass can repair it
   (no event, no restart, up to a minute), then across a `satld` restart with
   the anchor wiped while it was down, where only the startup pass can. An
   edge-triggered publisher passes neither;
4. scaled to one replica more than there are nodes, the node that ends up with
   two tasks holds **one** rdr rule with a `round-robin` address pool
   (api-compat #76), two rules would leave one task unreachable while looking
   published, since pf takes the first matching translation rule;
5. after `service rm`, no rule in any anchor and no node answering.

> The published port is **18080** rather than 8080 because assertions 1, 2, 4
> and 5 read the anchor back, and `pfctl -s nat` prints its own normalisation:
> a port with a name in `/etc/services` comes back as that name (8080 prints as
> `port = http-alt`, with or without `-N`). 18080 has no name. Measured on the
> VMs.

**`rolling_update`**, the M4 DoD, and the only scenario that generates load: six
replicas over three nodes are updated one slot at a time while this host sends a
request per node in a loop, then an update to an image that cannot be pulled is
rolled back by the manager on its own, then the same broken image with
`failure_action: pause` is recovered from by pushing a corrected spec.

**The updates go through `satl service update`.** They used to go through
`curl --unix-socket` because the CLI's `UpdateConfig` carried only `Parallelism`
and `Delay`, so a CLI round trip *erased* the `FailureAction`, `Monitor` and
`Order` this scenario is about, `update` posts back the spec it read. The CLI now
carries all six fields of both policies and has Docker's twelve `--update-*` /
`--rollback-*` flags (api-compat #96), so the operator's surface is the one under
test. Both updates below name nothing but `--image`, which makes phase 2 the
strongest available assertion that the policy survived the round trip: it can only
roll back on its own if `failure_action: rollback` is still there. The **create**
stays on the REST API, the one place in the suite that posts a full `ServiceSpec`
with an explicit `UpdateConfig` and so pins the wire spelling of every field, and
every read-back is REST as well, including an explicit one comparing the stored
`UpdateConfig` against what the service was created with.

Phase 1, the rolling update. The image changes to a second tag with the *same
content* (copied locally on each node with `skopeo`), so every task is dirty and
must be replaced while the body served never changes, which is what lets one
load generator span the update and judge every response by the same rule.
Asserted: `UpdateStatus` reaches `completed`, all six slots end on the new image
with the same slot numbers, the stored `UpdateConfig` is untouched, and, sampled
throughout, at least five of the six slots are serving, which is the difference
between a rolling update and a restart.

Phase 2, the rollback. The image changes to a tag that is in no registry, which
is what a mistyped or unpushed tag looks like from the daemon's side (the pull
404s, the task is `REJECTED`). With `FailureAction: rollback` and
`MaxFailureRatio: 0`, one failed task is enough: the manager swaps the spec back
itself. Asserted: `rollback_completed`, `PreviousSpec` cleared, the service back
at 6/6 on the working image, and the leader's log carrying the decision.

Phase 3, the other failure action and getting out of it. `--update-failure-action
pause` first, on its own: a policy change is not a task change, so it must replace
nothing and start no rollout (which also proves the flag reaches the daemon). Then
the broken image again, it now *pauses* instead of rolling back, which is the
state an operator meets after a typo and the state the updater deliberately does
nothing about. Then the working image: the pause must be gone and the service must
come back to 6/6 on it. The control API clears `UpdateStatus` on any update, and
without that the service would be stuck for good (api-compat #92); the clearing
gets its own wait so a regression fails there, naming the defect, rather than
timing out on convergence. No load generator in this phase: a paused update leaves
a slot empty on purpose and a node with no task of the service does not answer at
all (api-compat #75), so counting requests would measure ingress-lite instead of
resumability.

What phase 3 deliberately does **not** require is `UpdateStatus == completed` after
the corrected spec, because two different components can legitimately do the work.
The pause leaves one slot empty, and who refills it depends on how far the failed
task got: a replacement that died *before* its promotion is terminal at desired
`READY`, which the restart supervisor ignores by design, so the updater owns the
slot and its rollout ends `completed`; one that was promoted first is terminal at
desired `RUNNING`, which is the supervisor's own business, and it refills the slot
from the *current* spec, so after the corrected spec nothing is dirty, the updater
correctly does nothing, and `UpdateStatus` stays empty. Measured over eight runs:
seven took the updater path, one the supervisor path (six healthy replicas, empty
status). An earlier version of this assertion required `completed` and failed that
run for no defect at all.

**How the load is counted**, since "zero failed requests" is only as good as the
counting:

- every attempt is counted, including the failures, and the run fails if fewer
  than 200 were sent, a generator that died in its first second would otherwise
  prove a flawless update;
- an attempt succeeds only if the body carries the marker the image bakes in: a
  200 from anything else, a connection refused, a timeout and an empty body are
  all failures;
- a failed attempt is retried **once, immediately**, and the two outcomes are
  counted separately: `retried` (the second attempt was served) and `lost`
  (nothing served it). That is what a load balancer does with an idempotent GET;
- every attempt records **which node and which second**, so the numbers the run
  prints are the ones an operator would ask for: how long each node answered
  wrong, and, the number that makes the others believable, the longest the
  generator went without asking a given node anything.

`lost` must be **zero**: that is the updater's contract, and it is what "one slot
at a time never takes the last serving task off a node" means from outside.

First-attempt failures are bounded rather than required to be zero, and what is
bounded is deliberately not their *count*. A stale redirect costs as many requests
as the generator happens to send while it lasts, so a count, or a percentage of a
phase that lasted ten seconds, which an earlier version of this assertion used,
says more about the harness than about the daemon. Three things are asserted
instead:

1. **no window of failures outlives one satld port pass** (8 s, one pass plus
   jitter). Failures more than 2 s apart are separate windows, so two brief ones
   half a minute apart are never reported as one long outage;
2. **no more windows than there were task stops in the phase**, one stop can
   strand one redirect on one node, so a defect that made a node answer wrong
   without a task going away fails here even if every window is short;
3. **the generator's own sampling gap stays under that same window**, because a
   measurement that stalls for as long as the outage it hunts cannot see it.

**And, separately and unconditionally: no node re-published a stopped task's
redirect** (`ru_republished`). That is the same fact read from the daemon's log
instead of guessed from traffic, for each task of the run, a `published ports
converged` line naming a task id *after* that node's own `published ports removed`
for it. A task id is unique and a task is one-shot, so there is no innocent reading.
This exists because the traffic measurement is probabilistic and this one is not:

> **Before the fix**, over seven runs of this scenario: 0, 0, 1, 1, 64, 0 and 63
> first attempts failed out of ~2300 each; four runs saw it, three saw nothing,
> and every affected run left three republish events in the logs. The 63/64 runs
> are the full signature, one node answering wrong for **5 s**, every other
> request, because pf alternates the two addresses of that node's round-robin pool
> (api-compat #76). Cause: `running_task_ports` derived its wanted set from the
> **store**, which lags the node's own agent, so a port pass firing in the ~150 ms
> between "the agent stopped the container" and "the store was told" put the
> redirect back for a whole pass. Measured on node2: removed at 38.837, put back at
> 38.977, store told at 38.999, dropped again at 43.976.
>
> **After the fix** (a task whose desired state has reached `SHUTDOWN` is not
> published, desired state is written by a manager *before* the agent acts, so it
> is never late): **0 republish events**, and 1 to 2 first attempts failing per run
> in isolated 0-second windows. Those are a different thing, and both readings have
> been traced: one lined up with a *fresh* task's redirect going live 0.25 s after
> its jail started, i.e. before nginx had finished binding, this service has no
> `Healthcheck`, so `RUNNING` means "the jail started", not "it serves"
> (api-compat #87 is what closes that, and it is not what this scenario exercises);
> the other lined up with no redirect change at all on that node, which is the
> noise floor of ~2300 requests over a public network. Neither is bounded by a port
> pass, and `lost` stays 0 in both.

The five scenarios below are the live proof of `fb5190a` (global services, node
drain, the constraint enforcer, the store-derived restart budget), which shipped
with store-backed tests and no cluster run at all. They share four traits worth
stating once:

- **each removes the suite's shared `web` first** (`m4_prelude`). They count
  containers on a node and audit what a task left behind, and both readings only
  mean "this scenario's" if nothing else of the suite is running. Whoever needs
  `web` next rebuilds it (`ensure_service`);
- **each puts the cluster back**, every node `Active`, no label of its own left,
  three managers, its service removed with a per-task leftover audit
  (`svc_rm_audited`, which is `ru_leftovers` over the task IDs the scenario
  created). `nodes_activate` also *repairs* a node a previously failed run left
  drained, the way `ensure_daemons` repairs a stopped `satld`;
- **three of them assert that nothing happened**, with `hold_for`, wait_until's
  opposite, which requires a condition at every poll for `SATL_T_SETTLE` seconds
  (40 by default) and fails on the first poll that breaks it. "No replacement was
  created anywhere", "nothing flapped" and "the budget stayed spent" are the
  actual content of three decisions in `fb5190a`, and a single read cannot make
  any of them;
- **`drainee`, `zoned` and `flapper` are created over the REST API**, not with
  `satl service create`: the CLI has no `--restart-delay`,
  `--restart-max-attempts` or `--restart-window` flag, `--restart-condition` is
  the only restart flag it carries, and all three services are *about* the
  restart policy. That is a CLI gap against docker, recorded here rather than
  worked around. `gagent` needs no restart policy and is created through the CLI;
- **they read the daemon's log across rotations.** newsyslog rotates
  `/var/log/messages` about once an hour on these VMs, measured, and it bites: a
  daemon 80 minutes old already had its `starting satld` line in
  `messages.0.bz2`, and the first version of `leader_nodes` therefore found no
  leader on any of the three nodes. `log_hits`, `log_evidence` and `leader_nodes`
  read `messages.*.bz2` oldest-first and then `messages`. Earlier runs' lines come
  along with them, which is harmless: every assertion pins a needle to a task ID
  of *this* run, and a task ID is unique.

**`global_service`**, the footprint of a `--mode global` service, a drain, and
the return. Three parts:

1. **One task per node, and preassigned.** Exactly one live task on every node is
   the *outcome*, and it is also exactly what `--replicas 3` produces on three
   nodes, so it is asserted alongside the three facts that tell the two apart
   (`gs_task_shape`, read from `GET /tasks/<id>` because the CLI's `NAME` cell
   drops the task-ID suffix): **slot 0**, a name of
   `<service>.<node id>.<task id>`, the node ID standing where a replicated
   service puts its slot number (SWK §4.5), and the task being bound to that
   node. Then, per task, from the daemon's log: the global loop created it
   (`creating a global task for a node that has none`, with *that* task ID and
   *that* `node_id`, so the three lines name three different nodes), the
   scheduler **confirmed** it (`scheduler confirmed task can run on preassigned
   node`), and the scheduler **never assigned** it (`scheduler assigned task to
   node` must appear zero times for those IDs). That last pair is the assertion
   that the tasks were preassigned rather than scheduled: a global service whose
   tasks were placed by the scheduler would look identical in every count.
2. **A drain, measured.** Alongside the global service, a 6-replica service
   (`drainee`) created with a **30 s restart delay**, the reason the measurement
   means anything: every other eviction trigger pays that delay in full
   (`leader_kill`'s show `delay_ms=5000`), and SWK §7.4 forces it to **zero** for
   a draining node because an operator emptying a node is waiting on it. The
   drain must therefore complete in *seconds*: the scenario times it from
   `satl node update --availability drain` until the drained node holds no wanted
   global task, `drainee` is back at 6 live tasks spread `3 3` over the survivors,
   and the node runs **no container at all** (`jls`), then asserts that elapsed
   time is **below the 30 s delay**. Measured on these VMs: **1–2 s** against 30.
   The log is asserted too, per evicted task ID: `trigger="node is draining"`
   *with* `delay_ms=0`, the daemon saying it skipped the delay on purpose rather
   than a delay that happened not to apply, and, for the global task,
   `stopping a global task … reason="node is no longer eligible for this global
   service"`, which is where the division of labour is recorded (the global loop
   owns this, not the restart supervisor: `Trigger::applies_to_global`).
   Finally, the half a replicated service cannot show: the drained node's global
   task gains **no replacement anywhere**, held for `SATL_T_SETTLE`. A global
   task's node is its identity, so the service runs on one node fewer.
3. **The return.** `--availability active` gives the node its global task back,
   a **new** task (a task is one-shot, architecture §4 rule 4), with the same
   node-derived shape. `drainee`, on the other hand, is **not** rebalanced: SatL
   has no rebalancer, so its tasks stay `3 3` on the survivors, and that is
   asserted (held for `SATL_T_SETTLE`) as the behaviour there is rather than the
   one an operator might hope for. If a rebalancer is ever written, this is the
   assertion to change deliberately.

**`global_update`**, a rolling update of a *global* service, whose unit is the
**node**. `rolling_update` covers the replicated shape under load; what cannot be
tested there is the shape itself, because a global service has no slots and its
unit set is re-read from the store on every pass. Asserted: at no sampling point
is more than one node in flight, in *either* of the two forms a `stop-first`
batch takes, a node holding a new task that is not `Running` yet, and a node
holding no live task at all; every node ends with exactly one task on the new
image, pinned to it, slot 0, named after it; each of those tasks was created by
the **updater** and not by the global loop (`updating slot: replacement task
created` naming that task ID, the two components create tasks for the same nodes
and only these lines tell them apart, which is the division `fb5190a` draws);
`UpdateStatus.Message` counts **nodes** (`update completed: 3 nodes updated`,
the wording is the assertion, since "3 slots updated" would be a lie about a
service that has none); and the rollout takes at least **two monitor windows**,
because three units at parallelism 1, each watched for `SATL_TEST_GLOBAL_MONITOR`
seconds, cannot be done in less. Measured: 27 s for three nodes at an 8 s
monitor. The service is created fresh on `freebsd-nginx:latest` and updated to
the `:rolled` tag `rolling_update` seeds (same content, different string:
every task is dirty and nothing observable about the container changes);
`ru_seed_tag` is idempotent, so this scenario also works run on its own.

**`global_node_loss`**, the same node-driven verdict reached the hard way.
`satld` is stopped with its containers deliberately left running (as `node_kill`
does), so the node goes `Down` on its session TTL with a container of the global
service still alive on it. Asserts: the node's global task goes desired
`shutdown`; **nothing is recreated elsewhere**, held for `SATL_T_SETTLE`, the
half that separates a global service from a replicated one, since `node_kill`
asserts the exact opposite for `web` (its tasks *are* moved); and, when the node
comes back, its task returns **there**, reaches `Running`, is a new task, and the
container of the old one is gone, one jail with processes per live task on every
node.

**`constraint_enforcer`**, SWK §7.6: constraints are checked when a task is
*scheduled*, against the node as it was then, and labels are writable at any
moment. Every node is labelled, a 3-replica service is placed by that label one
per node, and then:

1. **one node's label is changed** so it no longer matches. Its task must be shut
   down and rescheduled onto a node that still matches (spread `1 2`), and the
   log must carry, for that task ID, `trigger="node no longer satisfies the
   placement constraints"` **and `delay_ms=10000`**, the service's own restart
   delay, paid in full. That second field is the deliberate asymmetry of
   `fb5190a` and the reason the delay is not the 5 s default: a *drain* forces the
   delay to zero because someone is waiting on the node, while a label edit is
   nobody waiting. Two triggers, one budget, different pacing, and the log is the
   only place both are visible;
2. **the label is then removed entirely, and nothing may move.** This is the real
   test. The remaining tasks are on nodes that still match, so a correct enforcer
   has nothing to do; one that re-evaluates carelessly, judging every task on
   every node write, or judging a task against its own stale placement snapshot
   instead of the service's current one, evicts them, and the service flaps for
   as long as an operator keeps editing labels. Asserted by holding the exact set
   of live task IDs *and* their nodes for `SATL_T_SETTLE`: a flap that moved a
   task and moved it back would still change an ID, because a task is one-shot.

The label is dropped from every node at both ends of the scenario and the removal
is read back, so a run that fails in the middle cannot leave a label behind that
would place, or refuse, somebody else's tasks.

**`restart_budget`**, SWK §7.9, and the one scenario that needs a *real*
election. `max_attempts` is a budget per replica and spec version, and after
`fb5190a` it is derived from the store on every pass rather than kept in the
supervisor's memory. What that buys can only be shown by taking the memory away.

A 1-replica service (`flapper`) whose entrypoint exits 9, `--restart-condition
any`, 2 attempts, a 25 s delay. One restart is allowed to happen, so the budget
is half spent, and then the **leader's `satld` is killed with `kill -9`**, while
the *next* replacement exists only as a pending entry in that process's delay
queue (which `fb5190a` says outright has no store representation). The new leader
is handed nothing: it re-derives the budget from the slot's task history. Then, in
numbers, because the numbers are the point:

- the slot settles at **3 tasks**, the original plus one per attempt, and not
  one more, held for `SATL_T_SETTLE`. Before `fb5190a` a new leader started from
  an empty map, so this service would have restarted forever, two attempts at a
  time, once per election;
- the **third task was created after the election, by the node that won it**
  (`restarting task in the same slot` naming that ID on the new leader, and zero
  such lines on the killed one). The scenario also re-reads the count right after
  the kill and fails loudly if the dead leader had already created it: that would
  mean the measurement window (the 25 s delay) closed early and this run cannot
  attribute anything;
- the new leader then **refuses, and says so**: `task not restarted … attempts=2
  reason="max restart attempts reached"` for that task, which is also the only
  thing that distinguishes a spent budget from a stuck orchestrator for whoever
  reads the log. The task it names is asserted to be the one left
  terminal-but-still-desired-`Running`, the shape a slot nothing will refill
  has, and the one `crate::update`'s `abandoned()` recognises;
- and after the killed daemon is restarted, the count is **still 3**: a returning
  manager re-derives the same budget from the same store.

Two details make the measurement honest. The leader is found by reading each
node's own log (`leader_nodes`: the last `leadership gained` / `leadership lost`
since that daemon's last `starting satld`, and only for a `satld` that is
running), never from `node ls`'s MANAGER STATUS, which is written when the
cluster forms and never refreshed, so after `leader_kill` it names a node that is
not the leader and killing it would produce no election at all. And `flapper` is
**pinned to a node other than the leader's**, because its replacement could
otherwise be scheduled onto the node whose daemon was just killed but which the
store still calls `Ready`: the task would sit `Assigned` and never fail, and the
scenario would time out on a placement race instead of measuring a budget.

**`ca_rotate`**, M5: `satl ca rotate` replaces the cluster root CA on a live
mixed-role cluster (one node demoted to a worker first, so both re-issue paths
run: managers from the store, the worker through NodeCA). What it asserts is
mechanisms, not vibes: the transitional trust bundle carries exactly two roots
mid-rotation and one new root after; every node's leaf is re-issued (new
serial) as a leaf + cross-signed-intermediate chain that `openssl verify`
accepts against the old root alone *and* the new root alone, and the leaf
without the intermediate fails against the old root, proving the intermediate
does the bridging; managers present that chain on the wire (`openssl s_client`
against 2378) with unchanged pids and zero `agent session lost` lines; a store
write commits in every phase (a node label pre / mid / post, read back); the
rolling_update load generator spans the whole rotation and loses zero requests.
Then the negatives: both join tokens are regenerated (new digest; a
pre-rotation token is refused with the error that names the rotation), and a
worker stopped through a second rotation holds it open (`hold_for`) until
`satl node rm --force` releases it. While it is held, the leader must *say* it
is held and name the node as `down`, a cluster stuck mid-rotation with nothing
in `/var/log/messages` about it is a cluster nobody knows to repair, which is
how the one red assertion of `42cae3c` became a permanently stranded node.
When the removed node returns, the managers must refuse it with the documented
rejoin instruction (`refused an internal TLS connection` … `satl swarm leave
--force`). The refusal is **one-directional** and this scenario measured that:
the returning node still verifies the managers, because their leaves carry the
cross-signed intermediate that bridges back to the root it still holds, so its
own log shows only the managers' fatal alert (`agent session ended` …
`received fatal alert: DecryptError`) and never a certificate error of its own.
An earlier version of this scenario asserted a node-side diagnosis here and
failed, correctly, the assertion encoded a wrong belief, and it was replaced by
`log_evidence` plus a documented note rather than by a weaker assertion.
Finally that instruction
(`leave --force` + join with a fresh token) is executed and must work, and it
is deliberately pointed at **a manager that is not the raft leader**, with the
leader identified from the daemons' logs (`the_leader`) rather than from the
stale MANAGER STATUS column, and with the joiner's `following its redirect to
the leader` line asserted to have grown. Only the leader signs a certificate;
an operator pasting a manager address cannot know which one that is, so a join
that works only against the leader makes every documented recovery a coin flip.
That is exactly how `42cae3c` stranded node3: `restart_budget` had moved
leadership, the rejoin hit a follower, and it failed. Ends by promoting the node
back to the all-manager cluster the suite expects.

**`compose_stack`**, M5's definition of done: a three-service stack (nginx +
redis + a redis-cli worker) deployed from a Compose file across the cluster,
one service consuming a secret, then a `down` that leaves nothing. It exists to
prove the *mechanisms* `satl compose` claims, because the stack coming up would
otherwise be consistent with several of them being broken. In order: the project
name is derived from the directory (`satl compose config`, which reaches no
daemon, prints it along with the namespaced names and the DNS aliases *before*
anything exists); a copy of the file with `build: .` appended is refused naming
the file, the service and the key, and creates nothing; the project network is a
real overlay with a subnet and a VNI **on every node**, not the bridge `docker
compose` would have made; every object carries
`com.docker.compose.project=<project>`, read back from `satl service inspect`;
the three services converge (web and worker global, redis pinned by
`deploy.placement.constraints` to the first node) and a live task of the stack
runs on every node; the published port answers on all three public addresses,
which only holds because web is global (api-compat 75); the secret is a `0400`
file **on a tmpfs** and, more importantly, is *applied*, redis answers `NOAUTH`
to an unauthenticated `PING` and `PONG` to one authenticated from the file it was
given, so a delivered-but-ignored payload cannot pass; the worker **on another
node** reaches redis by its compose name (`redis`, not `cstack_redis`), which is
the alias, the DNS scope and the overlay data path in one assertion; and the
counter the workers increment keeps moving. Then a second `up` must report
`exists`/`updated` and leave three services, not six. The teardown is the part
worth reading twice: a decoy service called `cstack_decoy` is created **without**
compose labels, and `down` must remove the three labelled services and the
network while leaving the decoy alone, a `down` scoped by name instead of by
label would remove somebody else's service. The secret must also survive (a
compose project refers to cluster secret material and never deletes it), and the
audit is per task id (`ru_leftovers`) rather than the suite-wide
`leftovers_gone`, because `web` and the decoy are deliberately still there.
The payload never appears in the output: every authenticated command reads it
from the file inside the jail.

**`mesh_failed_start`**, the B1 non-regression, the audit's replayed trigger.
A `flap` service (3 replicas, published port, explicit 2 s restart delay)
exits 1 two seconds into every attempt, always before its first healthcheck
probe can run (the first probe is one interval after start; the interval is
10 s), so its tasks die exactly the way that used to strand an overlay
attachment. While that storm runs, a healthy published `good` service is
created, converges, and serves 12 requests from the dev host through **each**
node's public address, and the flap's task-row count must grow across the
request loop, or the storm stopped and the requests measured a quiet cluster.
The B1 signature is asserted from the logs: zero `both local and remote`
overlay-conflict lines in `/var/log/messages` on every node (current file
only, a rotated line is an old run's). Teardown of both services must leave
no jail, epair, dataset or mount anywhere.

**`build_push_run`**, M6f/M7b/M8a-c in one flow. A one-COPY Satlfile is built
on the bootstrap node with the build cache wiped (so a re-run's cold build is
cold), timed; the identical warm rebuild must be faster, and at least twice as
fast when the cold build took long enough for the comparison to mean anything.
The cold build must also print the local-store warning, an unpushed image on
a 3-node cluster is runnable nowhere else, and the build says so (N3). The
image is then `satl tag`ged and `satl push`ed into a **joiner's** registry:
every registry is loopback-only, so the push crosses a two-hop ssh tunnel the
dev host holds (`-L` into the joiner's registry, `-R` from the build node back
to the hop), and the manifest digest the joiner's registry serves is compared
against the one the push reported. A service pinned to the joiner by
constraint then runs the pushed reference; the task must come up RUNNING on
that node and log the marker the Satlfile COPYed in. Teardown removes the
service, the pushed manifest (the registry lives outside `zroot/satl`, so
`reset.sh` would not take it), the build directory and the tunnel. The tag →
prune-source → run-from-target bonus is not covered: no image-remove verb
exists in the CLI or the REST API.

**`stack_verbs`**, the B3 non-regression: a two-service Compose stack (two
replicated services, two replicas each) through every `satl stack` verb.
`stack deploy` reports the network and both services created; `stack ls` shows
the stack with SERVICES = 2; `stack services` must converge to 2/2 for both,
B3 rendered a healthy stack 0/N forever, which this wait fails by timeout;
`stack ps` must list exactly the four tasks, all Running, each named after a
stack service and placed on a node the suite knows; `stack rm` must leave no
service, no stack row and nothing on any host.

**`jobs_and_prefs`**, M7d/M7e. A replicated job (`--replicas 2`, so
MaxConcurrent and TotalCompletions are both 2) must reach 2 Complete tasks and
then stay exactly there, no third row, none back to Running, held for
`SATL_T_SETTLE`, because a clean exit is a success a job never retries. A
global job must leave exactly one Complete run per node, held the same way.
Then the spread preference: the first inventory node is labelled `zone=east`,
the other two `zone=west` (an unlabelled node would be a third spread group
and make the count untestable), and a 4-replica service with
`--placement-pref spread=node.labels.zone` must land 2 replicas per zone. The
labels are removed at both ends and the removal is read back from
`node inspect`.

**`hot_resize`**, M6g live, plus N4 exercised for real. A 2-replica service
with `--limit-memory 64M` must show `memoryuse:sigkill=67108864` in `rctl` on
each task's node, read from the kernel, not inferred from the spec.
`satl service update --limit-memory 128M` is a resources-only change: the same
task ids must still be live (a task is one-shot, so a new id *is* a roll), no
extra task rows may appear, every jail's rule must show the new cap, and a
manager must have logged `hot resize: resources pushed to the live task, no
roll` naming each task id. `service rm` then takes the rules with the
containers (the controller calls `remove_limits` while the jail is alive), so
no `jail:`-subject rule may remain on any node. Finally N4: a rule is planted
by hand for a dead, task-id-shaped subject on the first node, its satld is
restarted, and the startup reconciliation must purge it, the rule gone from
`rctl`, and this daemon instance's `startup reconciliation complete` line
carrying `rctl_rules_purged >= 1`.

**`cleanup`**, removes `web` and audits every node the way `make integration`
audits a single host: no jail under `/var/db/satl`, no interface still described
`satl:<task-id>`, no dataset under `zroot/satl/containers`, and **no leftover
mount** under `/var/db/satl/containers/<task id>/`. The node's own `satl0` bridge
(`satl:network:*`) is not a leftover and is excluded. Appended automatically in
full-suite mode.

The mount field was added in M5 and it is the one that had been lying. Every
container carries mounts ocijail makes host-side, `devfs`, `fdescfs`, a tmpfs
`/tmp`, plus `linprocfs`/`linsysfs`/`/dev/shm` for a Linux image, and they are
mounted **`MNT_IGNORE`**, which mount(8) hides unless `-v` is given. Plain
`mount`, `mount -t tmpfs` and (once the dataset under them is gone, because
`statfs` then fails) `df -t tmpfs` show none of them. So an audit that looked at
jails, epairs and datasets reported all three nodes clean while 54, 54 and 56
stale tmpfs piled up across them, three mounts each for 54 task ids long gone.
`node_audit` therefore reads `mount -p`, and counts only mounts whose task has
**no container dataset**, a stopped-but-not-removed container legitimately holds
its own, and counting those would fail the audit for a node working perfectly.

They did not come from the removal path: 247 removals in those same logs all
reported "no leaked mounts". They came from `reset.sh`, which enumerated mounts
with plain `mount`, could not see them, and force-unmounted the *rootfs datasets*
instead, which strands the `MNT_IGNORE` submounts on a filesystem that no longer
exists. Measured: `zfs destroy` refuses while a submount is there ("pool or
dataset is busy"), but `umount -f` on the parent succeeds and leaves the children
behind. Anything that force-unmounts under the state directory must go
deepest-first off `mount -p`.

### One thing the scenarios do *not* assert (M2 gap, measured 2026-08-10)

- **`satl node ls` MANAGER STATUS is not refreshed on a leadership change.** The
  store's `ManagerStatus` is written when the cluster forms; after
  `leader_kill`, every node still calls the killed node `Leader`, permanently,
  including after it rejoins as a follower, while raft's real leader has moved
  (`raft leadership gained … term=2`, `became leader: serving the dispatcher` in
  the new leader's `/var/log/messages`). No API surface reports the live raft
  leader either (`/info`'s `ControlAvailable` is hardcoded `true` on managers).
  That is why `leader_kill` proves the re-election through committed writes
  rather than by reading the column, and why a single `run.sh node_kill` run
  straight after a `leader_kill` should be preceded by `init_and_join`: it picks
  its victim from that column.

A second gap used to sit here, **a killed *leader* stayed `Unknown` forever,
its tasks never evicted**, because the new leader's dispatcher had no session
for it and so no TTL ever ticked against it. Fixed in M4: leadership gain seeds
a registration expectation for every non-`Down`, non-drained store node (SWK
§13.2), and a node that never re-registers goes `Down` through the ordinary
sweep, `leader_kill` now asserts the `Down` and the eviction outright.

### Recovering a cluster left in a bad state

The scenarios stop and `kill -9` daemons, so a run that fails in between leaves
one node stopped. Nothing has to be done by hand: **`run.sh` starts `satld`
wherever it is not answering** before the gate and at the start of every
scenario, and each scenario rebuilds `web` if it is not in the shape it needs. So
the first recovery step is simply to run it again:

```sh
sh tests/cluster/run.sh                # repairs, then re-runs everything
sh tests/cluster/run.sh cleanup        # just remove web and audit the nodes
```

If the cluster state itself is wrong, a node that will not rejoin, a raft group
that disagrees with the inventory, leftovers the audit keeps reporting, go back
to a formed cluster from scratch:

```sh
sh tests/cluster/run.sh init_and_join  # reset.sh on every node, then init + joins
sh tests/cluster/reset.sh              # or just the wipe, without re-forming
```

`reset.sh` keeps the test registry and its images, so re-forming is cheap. If the
readiness gate itself fails, the fix is `provision.sh` / `deploy.sh` /
`images.sh` on the named nodes, the summary prints them in order.

## What the readiness gate checks

Per node, in one pass, printing `[ ok ]` / `[FAIL]` / `[ -- ]` (advisory):

- SSH reachable in BatchMode
- `kern.racct.enable = 1`, `net.inet.ip.forwarding = 1`
- pf enabled and the three `satl/*` anchor lines present in `/etc/pf.conf`
- `zroot/satl` exists **and is mounted** at `/var/db/satl`
- `vtnet1` carries the address the inventory claims, and can reach **every
  other node's** underlay address
- `ocijail` installed; `satl`, `satld`, the rc.d script and `satld.toml`
  installed; `satld_enable=YES`
- `satld` running and answering `satl version`; the Docker API `/info` on
  `/var/run/satl.sock` reporting **the node name the inventory expects** (this
  is what catches a stale or hand-edited `satld.toml`) and its swarm state
- the local test registry answering, with every expected image present
- advisory: linuxulator availability, number of running jails

Anything required that fails makes the whole run exit non-zero and prints the
exact scripts to re-run. `satld` not answering is repaired rather than reported:
the gate starts it first (see "Recovering a cluster left in a bad state").

## Reading the tables

The scenarios assert on the CLI's own output, `satl node ls`,
`satl service ls`, `satl service ps`, because that is the surface an operator
reads. `run.sh`'s `tcols` reads a table by the byte offsets its header line
fixes, not by whitespace: cells contain single spaces (`Running 4 minutes ago`)
and can be empty (a worker's `MANAGER STATUS`), and an unknown header name fails
loudly instead of yielding an empty string.

One definition matters enough to state here. A **live task** is one whose
`DESIRED STATE` is `Running` *and* whose `CURRENT STATE` is `Running`. Both
halves are needed: a task on a node that stopped answering keeps its last
reported `Running` for as long as the node is away, nothing can report
otherwise, and the orphan timer is 24h, while the manager moves its desired
state on and schedules a replacement. Counting observed `Running` alone says
"8 tasks running" for a 6-replica service with one node down, which is not what
the DoD means by six running replicas; `satl service ls` shows exactly that as
`8/6` while a node is down, and it is correct to.
