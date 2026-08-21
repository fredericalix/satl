# SatL networking

Design rationale lives in `docs/architecture.md` §11 (local bridge networks, VXLAN
overlay with a Raft-distributed FDB, DNS-RR service discovery, pf anchors, MTU rules).
This document carries the implementation-level detail and the operator contract.

## M1, node-local bridge networking

### Topology

```
     host                                  jail (VNET, one per task)
  ┌──────────────────────────────┐      ┌───────────────────────────┐
  │  satl0 (bridge)              │      │  epairNb                  │
  │   inet 10.88.0.1/24  ────────┼──────┤   inet 10.88.0.x/24       │
  │        │                     │      │   default route → .1      │
  │   epairNa (member)           │      │                           │
  │                              │      │  container process        │
  │  ice0 (egress) ── pf nat ────┼──▶   └───────────────────────────┘
  └──────────────────────────────┘
```

- One bridge per SatL network; the default network is `satl` on bridge `satl0`.
- One `epair(4)` per task: the `a` end joins the bridge, the `b` end is moved into the
  task's VNET jail (`ifconfig <epair>b vnet <jail>`), addressed and given a default
  route to the bridge address (`route -j <jail> add default 10.88.0.1`, `route(8)`
  supports `-j` natively, no `jexec` needed). `-j` covers *routes* only: `route(8)`
  cannot install a link-layer (ARP) entry in any stack, because it never sets
  `RTF_LLDATA` (`docs/vxlan.md` §4). That matters from M3 on, not here.
- Local IPAM carves a /24 per network out of `10.88.0.0/16`; `.1` is the gateway.
  Addresses are stable per task ID and persisted under the state directory.

### Ownership markers and reconciliation

SatL must be able to recognize its own interfaces after an interrupted teardown
(CLAUDE.md gotcha: epairs leak). Two markers are set, and **only the description is
reliable**:

| Marker | Survives `vnet` move? | Survives jail destruction? |
|---|---|---|
| interface group (`satl`) | no | no |
| interface description (`<group>:…`) | **yes** | **yes** |

That is why ownership lives in the description: an epair `b` end returns to the host
VNET automatically when its jail dies, having lost the group and kept the description.

**One namespace, five forms.** `<group>` is the configured `network_name` (default
`satl`), so two daemons on one host never claim each other's interfaces:

| Description | What it is | Created by |
|---|---|---|
| `<group>:network:<net>` | a node-local bridge | `satl-net` |
| `<group>:<task>` | both ends of a node-local task's epair | `satl-net` |
| `<group>:overlay:<net>` | an overlay network's bridge on this node | `satl-net` |
| `<group>:overlay:<net>:<task>` | both ends of an overlay task's epair | `satl-net` |
| `<group>:vxlan:<net>` | the network's VTEP | **`satl-overlay`** |

Two properties carry the safety argument, and both are asserted in
`satl-net`'s `classify_marker` tests:

- **an unrecognised `<group>:…` description classifies as unowned, and unowned is
  never destroyed.** `<group>:overlay:`, `<group>:overlay:web:task:extra`,
  `<group>:vxlan:`, a bare `<group>`, another daemon's `<group>`, all of them
  classify as `None` and are left alone. The sweep only ever destroys an interface it
  can name completely, so a marker form added later cannot be swept by an older
  daemon;
- **the VTEP is classified precisely so that nothing destroys it.** `satl-net` owns
  the bridge and the epairs and consumes the vxlan interface's name as a bridge
  member; `satl-overlay` creates and destroys it. Recognising the form is what keeps
  it from looking like an unattributable SatL-marked interface.

**Enumeration covers the driver groups too**, not just `<group>`: the sweep lists
`<group>` plus the `epair`, `bridge` and `vxlan` groups the drivers put their clones
into, then classifies each by description. That is what makes it robust against
interruption, a `b` end that auto-returned from a dead jail has lost `<group>` but is
still in `epair`, a bridge whose group tagging was interrupted mid-creation is still in
`bridge`, and the VTEPs are in `vxlan`. An unknown group (module not loaded) prints
nothing and exits 0, so the extra lookups cost nothing on a host with no overlay.

Interface group names may not end in a digit (`setifgroup` rejects them), which is why
the group is `satl` and not `satl0`.

### Host prerequisite: IP forwarding

Container traffic is *routed* between the bridge and the egress interface, so the host
must forward:

```sh
sysrc gateway_enable=YES              # persistent
sysctl net.inet.ip.forwarding=1       # immediate
```

Without it, pf's NAT rule matches nothing useful: packets from `10.88.0.0/24` are
never handed to the egress interface and containers have no outbound connectivity
(inbound `rdr` to a task IP still works, which makes the symptom confusing, published
ports answer, but the container cannot reach a registry or DNS). `satld` checks the
sysctl at startup and logs a warning when it is off. IPv6 forwarding
(`ipv6_gateway_enable`) is not needed in M1, SatL assigns no IPv6 addresses yet.

### pf integration, operator contract

SatL owns the `satl/*` anchors and **never touches rules outside them** (architecture
invariant). The full anchor ruleset is regenerated and reloaded on every change; there
are no incremental edits. The daemon refuses, in code, to load into any anchor outside
`satl`/`satl/*`.

An operator must declare the anchors once in `/etc/pf.conf`, translation anchors
before filter rules:

```
nat-anchor "satl/*"
rdr-anchor "satl/*"
anchor "satl/*"
```

A host that runs no firewall policy of its own still needs pf loaded and enabled for
published ports to work; the minimal working file is the three anchor lines plus
`pass all`. Enable with:

```sh
sysrc pf_enable=YES
service pf start        # or: kldload pf && pfctl -f /etc/pf.conf && pfctl -e
```

`satld` uses `pf_mode` in `satld.toml` to decide what it may do:

| `pf_mode` | Behaviour |
|---|---|
| `enforce` | generate, syntax-check and **load** the anchors (needs pf enabled) |
| `check` (default) | generate and syntax-check only, no loads; published ports are recorded but not redirected |
| `disabled` | generate nothing; for hosts where pf is unavailable |

Rules generated per network/task:

- `satl/nat`, `nat on <egress> inet from <subnet> to any -> (<egress>)` so containers
  reach the outside world. The parenthesised form makes pf re-evaluate the interface's
  address, so the rule survives a DHCP renewal or an interface that comes up later.
- `satl/rdr`, one **table declaration plus one static rule** per
  `(published port, protocol, container port)` triple: `table
  <satl_p8080_tcp_80> persist` and `rdr pass inet proto {tcp|udp} from any to
  any port <host> -> <satl_p8080_tcp_80> port <container> round-robin`. The
  task addresses live in the table, not in the rule, so a membership change
  (task started, dead, rescheduled) goes through `pfctl -T replace` and the
  ruleset is **not** reloaded (M6). In M1 that was host-mode publishing only;
  M3 adds ingress publishing to the same anchor (see "Published ports"
  below).

### The egress interface

NAT needs to know which interface to translate out of. `satld` takes the interface of
the host's **default route** unless `egress_if` is set in `satld.toml`. Set it
explicitly on a multi-homed node, for instance when containers must leave through a
private interface rather than the public one. With no egress interface there is simply
no `nat` rule, and the failure mode is asymmetric and confusing: published ports still
answer (inbound `rdr` is unaffected) while the container cannot reach anything. `satld`
warns loudly at startup when it cannot determine one.

### Alternative: a table-driven NAT rule (podman's model)

podman on FreeBSD puts its NAT rule in the *main* ruleset and keeps the source subnets
in a pf **table** that it fills at runtime:

```
v4egress_if = "vtnet0"
nat on $v4egress_if inet from <cni-nat> to any -> ($v4egress_if)
nat on $v6egress_if inet6 from <cni-nat> to !ff00::/8 -> ($v6egress_if)
rdr-anchor "cni-rdr/*"
nat-anchor "cni-rdr/*"
table <cni-nat>
```

Worth knowing, because it trades differently:

- **Table updates are atomic and cheap** (`pfctl -t … -T add`), no rule reload, so no
  window where NAT is momentarily absent. SatL adopted exactly this model for
  the `satl/rdr` pools in M6 (see "Several tasks of one service on one node");
  the `satl/nat` source list is one node-local subnet today, so moving *it*
  into a table stays a documented-but-deferred option rather than a need.
- **The egress interface becomes the operator's macro**, not our detection. SatL keeps
  detection so the default case needs no configuration, with `egress_if` for the rest.
- The **IPv6 rule excludes multicast** (`to !ff00::/8`), the right pattern for when
  SatL grows IPv6 addressing (not in M1).

SatL keeps its NAT rule inside `satl/nat` so a minimal operator setup is three anchor
lines and nothing else, and so that translation-rule ordering relative to any rules the
operator already has stays explicit and under their control.

### Container DNS

`prepare` writes `/etc/resolv.conf` into the container's writable layer: from the task's
`--dns` settings when given, otherwise a copy of the host's file (Docker's default). It
is written rather than bind-mounted, so it stays per-container and never touches the
shared image layers. Without it a container reaches addresses but resolves no names,
which reads as broken networking rather than missing configuration. M3 replaces this
with the per-node embedded DNS responder for service discovery.

### Known M1 limits

- Published ports were host-mode only: reachable on the node running the task.
  Ingress publishing arrives in M3 below; the full routing mesh (answered on
  every node, forwarded internally) is M6, recorded in `docs/api-compat.md`.
- No IPv6 addressing yet.
- MTU is the bridge default (1500); the overlay MTU accounting (−50 bytes) arrives with
  VXLAN in M3.

## M3, VXLAN overlay

Per architecture §11.2: one VNI per overlay network, unicast VXLAN with a
Raft-distributed FDB (no multicast), static ARP for remote endpoints, per-node embedded
DNS responder for DNS-RR service discovery, overlay MTU = underlay − 50. Milestone
status is in `docs/roadmap.md`; the measured platform facts are in `docs/vxlan.md`, and
four of them change what an implementation may assume:

- **the underlay MTU has been measured: 1500, so the overlay MTU is 1450**, and the
  driver's own default comes from the constant `ETHERMTU`, not from the underlay, so it
  is always set explicitly. There are only two places to set it, and an ordering
  constraint: the **bridge** (which the first `addm` overwrites with that member's MTU,
  and which afterwards propagates to every member) and each **in-jail epair `b` end**
  (never a bridge member, so nothing reaches it). A bridge *member* cannot be set at
  all, `SIOCSIFMTU` is `EOPNOTSUPP` even for the value it already holds
  (`docs/vxlan.md` §1, §5);
- **the FDB is programmed by ioctl, not by `ifconfig`**, there is no `vxlanroute`
  parameter, and `add` on a MAC already present is `EEXIST` whatever the VTEP, so
  moving an endpoint is remove-then-add (§3);
- **static ARP cannot be installed with `jexec arp -s` or `route -j`**: a container
  image has no `arp(8)`, and `route(8)` never sets `RTF_LLDATA` (§4). SatL enters the
  task's VNET and talks to the kernel itself;
- **an overlay network's gateway address is per node, not cluster-wide.** Every
  participating node's bridge is on one L2 segment, so one shared `.1` is a duplicate
  address on that segment: the jails resolve their gateway to whichever node wins the
  ARP race, and that node then receives their egress traffic and their DNS queries
  (measured, §8). The Docker-API consequence is recorded in `docs/api-compat.md`.

### What a container on an overlay can resolve

A task's `/etc/resolv.conf` gets one `nameserver` line per attached network, each this
node's gateway on it. Which names resolve does **not** depend on which of those lines
the stub resolver picks: the responder identifies the querying task by its source
address and answers from **every** network that task is attached to, searching them in
the order the service spec declares (`TaskTemplate.Networks`). The first network that
holds the name answers it, so two services of the same name on two of a task's
networks resolve to whichever network the spec lists first, and the two are never
merged into one round-robin set.

A query whose source address is not one of this node's own tasks is forwarded upstream
rather than answered. That matters because an overlay's per-node gateway addresses all
sit on one L2 segment: every task of the network, on every node, can reach every node's
responder. In normal operation nothing does, a container talks to its own node, and a
container that hardcodes another node's gateway gets its names forwarded to the host's
resolvers instead of answered. Full comparison with Docker: `docs/api-compat.md`
#73/#74.

Operator-facing bring-up requirements and the failure signatures of a one-way or
black-holed overlay are in `docs/operations.md`, "Overlay networks (M3)".

## M6, encrypted overlay networks (`--opt encrypted`)

`satl network create -d overlay --opt encrypted=true <name>` encrypts the
network's data plane. A bare `--opt encrypted` (no `=value`) means the same
thing, the CLI normalizes it to `encrypted=true`; the daemon's own contract
is stricter, so a raw API client sending an empty string still gets a 400. A
truthy `encrypted` on a `bridge` network or on `ingress` is a 400 as well
(`encrypted=false` is accepted there and means no encryption,
`docs/api-compat.md` #63). Compose files have
no spelling for it yet, create the encrypted network up front and reference
it as `external`.

**What is protected, and what is not.** The VXLAN datagrams between the nodes
that run tasks of that network are wrapped in ESP transport mode
(AES-128-GCM) by the kernel: a passive observer on the underlay sees ESP
(protocol 50), not VXLAN, and an active one cannot inject cleartext, the
`satl/guard` pf anchor drops it. Not protected: bridge networks (their
traffic never leaves the node, so there is nothing to encrypt), unencrypted
overlay networks (they stay on VXLAN port 4789, in cleartext), the `ingress`
network (it can never be encrypted, every node holds its assignment, so its
keyring would ship cluster-wide), and everything off the overlay path, like
client-to-published-port traffic. Encryption is per network, so a cluster can
mix encrypted and cleartext overlays.

**Isolation is per network, and keys stay on participants.** Each encrypted
network gets its own keyring and its own VTEP UDP port from 4790..=4999, two
encrypted networks share no key material. The keys live in the encrypted Raft
store and are shipped to a node only when it runs a task of that network
(inside its dispatcher assignment), so a node participating in no encrypted
network holds no key material at all. The leader rotates each ring every
12 h with no operator action.

**MTU and performance.** ESP costs 34 bytes on top of VXLAN's 50, so an
encrypted overlay's MTU is underlay − 84, **1416** on a 1500 underlay, set in
the same two places as the cleartext 1450 (measured, `docs/vxlan.md` §10). And
expect a **non-negligible throughput penalty**: every overlay packet is
encrypted and authenticated, on both ends. That cost is exactly why
encryption is opt-in per network rather than a cluster flag, the same
posture Docker takes with its own `--opt encrypted`.

## M3, published ports ("ingress-lite")

`satl service create --publish 8080:80` publishes in **ingress** mode, which is
Docker's default and therefore what a user gets without asking. What SatL does
with it is deliberately less than Docker's routing mesh, and the difference is
one sentence: **the port is redirected on each node that runs a task of the
service, to that node's own task.** A node running no task of the service does
not answer on it. The Docker-facing consequences are `docs/api-compat.md`
#75–#78; this section is the implementation contract.

### Who decides what, and where

| Step | Where | What |
|---|---|---|
| allocate | leader, in Raft | one cluster-wide owner per `(protocol, published port)`; sticky across updates; `0` auto-assigns from 30000–32767 (`satl-orchestrator/src/allocator/ports.rs`, SWK §9.5) |
| carry | the task object | the allocated `Endpoint.Ports` are copied onto every task of the service; a task whose service is not fully allocated is not scheduled at all |
| publish | each node, from its store replica | `satld`'s port sweep derives the whole `satl/rdr` anchor from the tasks that run *here* (`crates/satld/src/reconcile.rs`) |
| program | `satl-net` | one `rdr pass` rule per `(published port, protocol, container port)` (`crates/satl-net/src/pf.rs`) |

Nothing is allocated node-side. A port the allocator has not assigned yet is
`0`, and a task carrying one is simply not published until a later pass sees a
real one, inventing a port locally would mean two nodes disagreeing about
where a service answers.

### Why it is a level, not an edge

An ingress port is never *announced* to a node. It is assigned centrally and
arrives as a field of a task object in the replicated store, not as an event,
not on the assignment stream. A node that published only when it saw something
happen would therefore never publish an ingress port at all, which is exactly
the defect this milestone fixed (the third of its kind: see the node-status and
task-start fixes before it).

So `satld` recomputes the desired state from the live task set every five
seconds, and, since M6d, **on every store event that can move a pool
member** (a task's state, ports or attachments, the ingress network's
allocation). The event wake exists because the mesh made membership
cluster-wide: a store-driven pool otherwise lags a task's lifecycle by one
status round trip plus a whole sweep interval, and a rolling update left a
black hole in every node's pool for seconds at a time (measured: lost
requests in the `rolling_update` cluster scenario). An unchanged pass costs
one store read and no pfctl, so waking often is cheap; the 5-second tick
remains as the level, and as the only driver on workers, which hold no store.
`satl-net` then splits the application the way pf holds it (M6): the
**ruleset** (table declarations plus the static rdr rules) is reloaded only
when the *set* of published triples changes, and **membership** moves through
`pfctl -T replace` on each pool's table.
Consequences worth knowing:

- a newly allocated port is answered within one pass, with no restart and no
  event;
- a task joining or leaving a pool is a table replace, not an anchor reload,
  established connections are untouched by it (measured, see above);
- a pfctl load that fails is retried by the next pass, and the daemon never
  records a state it failed to load;
- ruleset *and* tables are re-asserted unconditionally once a minute, because
  what the daemon remembers is what it *loaded*, not what the kernel *holds*:
  `pfctl -a satl/rdr -F nat` or a `-T flush` in a root shell is repaired
  within a minute rather than never;
- a task whose container has just started keeps its redirect even though the
  store has not caught up with it, the store's copy of a task's status travels
  through the leader, so it lags this node's own agent, and the node's worker is
  consulted as a second opinion. Only the store reporting a task *terminal*
  removes a redirect, which is what keeps a stale one from pointing at an
  address IPAM is about to hand to the next container.

### Several tasks of one service on one node

They share one pool, and the pool is a **pf table**:

```
table <satl_p8080_tcp_80> persist
rdr pass inet proto tcp from any to any port 8080 -> <satl_p8080_tcp_80> port 80 round-robin
```

pf evaluates translation rules in order and **the first match decides**
(pf.conf(5)), so emitting one rule per task would leave every task but one
looking published and never receiving a connection. A pool is pf's own
answer, and a *table-backed* one specifically (M6, measured on 15.1, the
full pool-type matrix is in `docs/roadmap.md`'s decision log):

- **the ruleset is static, membership is dynamic.** A replica starting or
  dying rewrites the table with `pfctl -a satl/rdr -t satl_p8080_tcp_80 -T
  replace`, not the anchor, the ruleset is reloaded only when the *set* of
  published triples itself changes. `round-robin` is unconditional, so the
  rule text never depends on the member count;
- **`replace` leaves established states alone** (measured in
  `crates/satld/tests/pf_table.rs`): a connection already translated to a
  departing member keeps flowing, only new connections are balanced over the
  new membership, which is exactly what a health-checked pool needs;
- one ordering consequence: the tables are declared `persist` with no inline
  addresses, so **every anchor reload re-creates them empty** and the daemon
  re-pushes the full membership after every reload. The mirror image was
  caught by the health-pool test: a `persist` table also **survives a flush
  with its members**, so the daemon kills a table explicitly (`-T kill`)
  when its triple disappears, without it `-T show` keeps reporting a live
  pool for a dead one;
- weighted or least-connection balancing exists in no form in FreeBSD's pf
  (no weights, `least-states` is a syntax error). Docker Swarm's IPVS is
  round-robin with no operator choice either: parity, not a shortfall. A
  table pool also unlocks `source-hash` (per-client-IP stickiness) later,
  which an inline list could not do.

### Reading it on a node

```sh
pfctl -a satl/rdr -s nat                 # the static redirects (empty anchor: "does not exist")
pfctl -a satl/rdr -s Tables              # the pool tables
pfctl -a satl/rdr -t satl_p8080_tcp_80 -T show   # one pool's live membership
grep -a 'published ports converged' /var/log/messages
```

The daemon logs one line per *change*, carrying every redirect as
`<task id>=<published>/<proto>-><task ip>:<container port>`, so an operator can
grep by task id or by port number. A steady node logs nothing and runs no
pfctl; a membership-only change shows up in `-T show`, never in `-s nat`.

Remember `docs/api-compat.md` #35 when testing: a published port is not
reachable from the publishing host through `localhost`, because pf applies `rdr`
to packets *entering* an interface. Test from another machine, which is what
the `publish_port` cluster scenario does, from the dev host against the VMs'
public addresses.

## M6d, the routing mesh

M6d turns the M3 ingress-lite publish into Docker's mesh semantics: **every
manager answers on an ingress-published port, and a node running no replica of
the service relays to a healthy one**. Everything below was measured before it
was built (`hack/experiments/mesh`, on the cluster VMs): the design is the one
the measurement validated.

### The ingress network

The first service that publishes an ingress port makes the allocator create
the `ingress` network (SWK §9.3), lazily, so a cluster without ingress
publishing never grows one. It is overlay-backed, not user-attachable, and
marked `ingress`, which changes three things:

- **every node is a participant** (SWK §9.1's load-balancer attachment), not
  just the nodes running a task: the allocator gives every node a gateway
  address on it (`Network.node_gateways`), kept for as long as the network
  exists;
- the dispatcher ships it to every node unconditionally, it is never
  refcounted away when a node's last task leaves;
- a service publishing an ingress port is auto-attached to it, and its tasks
  carry an ingress address in `task.networks[].addresses`, that address,
  local or remote, is what the mesh routes to.

### The data path

The port sweep (`crates/satld/src/reconcile.rs`) computes the pool
cluster-wide from the store: every healthy task publishing an ingress port
contributes its **ingress attachment address** to the pool table, on every
manager. The anchor gains the mesh's two rule shapes (`satl-net`'s
`mesh_rules`), rendered after the rdr rules, pf.conf(5) statement order:
a `table` declaration after a translation rule is rejected, and `match` is a
filter-section statement even with `scrub` in it, so the clamp comes last
(measured the hard way: the inverse order fails `pfctl -nf -` with "Rules
must be in order"):

```
rdr pass inet proto tcp from any to any port 8080 -> <satl_p8080_tcp_80> port 80 round-robin
nat pass inet proto tcp from any to <satl_p8080_tcp_80> port 80 -> 10.100.0.4
match out on satl-br4096 inet proto tcp from any to 10.100.0.0/24 scrub (max-mss 1410)
```

- **Return-path SNAT**, one rule per pool, source = this node's own ingress
  gateway. Without it the reply bypasses the relaying node and the handshake
  never completes (measured: `curl` times out at the SYN). The price, accepted
  and recorded in `plan-m6.md`: **the application sees the relaying node's
  gateway address, not the client's**, exactly like Docker's mesh (whose IPVS
  does the same SNAT). DSR-style preservation was rejected, it would need a
  pf instance inside every task's VNET; the opt-in remedy is the M6e
  PROXY-protocol proxy mode (`docs/operations.md`, "Proxy mode").
- **MSS clamp** out of the overlay bridge: the client negotiates its MSS
  against the 1500-MTU underlay and its packets then enter a 1450-MTU overlay
  (docs/vxlan.md's −50, second site). The happy path needs no clamp, the
  task self-clamps (its epair is 1450, so it advertises 1410) and the relaying
  node can ICMP too-big the client itself; the rule is insurance against
  ICMP-filtered internet paths, and costs one `match`.

**Loop safety is by construction**: the rdr targets the task's *container*
port at its *overlay* address, so the forwarded packet can never re-match a
rule keyed on the *published* port. Never target a peer's published port.

**Loop safety's twin**: the SNAT rule matches the *pool table*, so a packet
relayed by another node (source inside the overlay subnet) is never re-NATed
here, one translation per packet, on the node the client connected to.

### The third table

The kernel tables the overlay programmer already maintains (FDB on the VTEPs,
static ARP in every jail, since a non-flooding VXLAN has no cross-node
broadcast ARP) are extended to the **load-balancer attachments**: every other
node's ingress gateway is a remote endpoint too, so a task can answer traffic
relayed through it. And the relaying node's own stack needs **static ARP
entries in the host table** for the remote task addresses it forwards to
(`satl-net`'s `Arp` wrapper, verified by read-back, `arp -s` exits 0 while
printing `cannot locate <ip>` for an off-link address; CLAUDE.md). The
wrapper's read-back exists precisely because that exit status lies.

One wire-format fact makes all of this computable from store state alone:
**an overlay bridge's MAC is the derived MAC of its node's gateway**
(`MacAddr::from_ipv4`, set once at segment bring-up), exactly like a task's
epair `b` end. The first mesh run caught why that matters: a task's reply to
its own node's gateway went to the derived MAC the bridge did not carry, the
kernel had assigned its own, and was dropped.

### What a worker does

A worker has no store replica, so it cannot compute the cluster-wide pool:
its port sweep keeps the pre-mesh, node-local behavior. The mesh is a
managers-only surface in M6d (recorded in `docs/api-compat.md` #75); the test
cluster's scenarios run on all-manager nodes, which is where the E2E proof
lives.

