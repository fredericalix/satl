# SatL VXLAN overlay — measured ground truth (FreeBSD 15.1)

What `satl-overlay` is to be coded against. Every number and every command
sequence here was executed on the three OVH cluster VMs and captured verbatim;
nothing is transcribed by hand and nothing is inferred from documentation alone.
The scripts are in `hack/experiments/vxlan/`, the transcripts in
`hack/experiments/vxlan/captures/`, and each claim below cites the capture it
comes from.

Design rationale stays in `docs/architecture.md` §11.2/§11.3/§11.5; the operator
contract and the M1 bridge topology stay in `docs/networking.md`. This document
is the implementation-level fact sheet in between.

Sources of truth consulted, in this order: `man 4 vxlan`, `man 8 ifconfig`
("Virtual eXtensible LAN Parameters"), `man 4 bridge`, `man 8 arp`,
`/usr/include/net/if_vxlan.h`, and `sys/net/if_vxlan.c` from `releng/15.1`
(fetched to a node, since `/usr/src` is empty on these images).

Reproduce everything with `sh hack/experiments/vxlan/run-all.sh`. All artefacts
are prefixed `expm3-`; `99-verify-clean.sh` audits that none survive.

### Corrections made while implementing `satl-overlay`

Eight claims below did not survive contact with the code — six found while
implementing against this document, one (the bridge-member MTU) found while
implementing the node-local plumbing, and one (the dump truncation) found while
re-verifying the others. Each is corrected **in place and marked**, rather than
quietly rewritten, because a reader who learned the wrong version has to unlearn
it.

The corrections were re-measured on the **dev host**, not on the OVH VMs:
FreeBSD 15.1-RELEASE-p2 `releng/15.1-n283596-aadd58dddcbc`, the same build as the
VMs, against `sys/net/if_vxlan.c`, `sys/net/if_bridge.c`, `sys/net/if.c`,
`sys/net/rtsock.c`, `sys/netinet/if_ether.c`, `sbin/route/route.c` and
`usr.sbin/arp/arp_netlink.c` from that tag. None of the eight depends on the
fabric, so none of them needed three nodes.

| Was claimed | Truth | Where |
|---|---|---|
| `VXLAN_CMD_FTABLE_ENTRY_ADD` on an existing entry replaces it | `EEXIST`, whatever the VTEP; changing an entry is remove-then-add | §3, §7 |
| the FDB ceiling can be raised with `vxlanmaxaddr N` | 2000 is a hard maximum — and it bounds *learning*, not static entries, which are unbounded | §3 |
| `ftable.dump` is how you read the table back | it truncates at one page, **81** IPv4 entries, silently (found here, not in the list) | §3 |
| `arp -s` for an off-link address fails | it prints `cannot locate` on stderr and **exits 0** | §4 |
| static ARP inside a jail "goes through `jexec`" | an OCI image has no `arp(8)`, and `route -j` cannot install a link-layer entry | §4 |
| `Oerrs` counts the frames sent to the default remote | not with an on-link blackhole: the first five are counted as *sent* | §2, §6 |
| `ftable.dump` does not appear in a `sysctl` listing | `sysctl -N` does list it; only *value* listings hide it | §3 |
| a bridge member's MTU is set "automatically", no action needed | it is **unsettable** — `EOPNOTSUPP` even for its current value — and the first `addm` overwrites the *bridge's* MTU | §5 |

§8's account of the allocator is also stale rather than wrong: the per-node gateway
it argued for has since landed as `Network::node_gateways` (commit `6e2b42b`), and
the section now says so in place.

---

## 1. The underlay MTU is 1500, and jumbo frames are impossible here

**Resolves architecture.md §17 open question #6.**
Evidence: `captures/00-underlay-mtu.txt`.

Measured, not assumed, by a DF ping sweep between the private addresses of all
three nodes — six ordered pairs, binary search over the payload size:

```sh
# largest payload that crosses with Don't Fragment set
ping -c 1 -t 2 -D -s 1472 <peer underlay ip>   # OK: 1472 + 8 (ICMP) + 20 (IP) = 1500
ping -c 1 -t 2 -D -s 1473 <peer underlay ip>   # ping: sendto: Message too long
```

(Node addresses live only in `tests/cluster/inventory.toml` — CLAUDE.md — so
every command example in this document takes them as parameters. Where a block
below is *quoted output* rather than a command to run, it is reproduced exactly as
captured, addresses included, because a sanitised transcript is not evidence.)

All six pairs returned `largest DF payload 1472 => path MTU 1500`.

The 1473-byte failure is *local* (`EMSGSIZE` from the kernel refusing to
fragment a DF packet larger than the outgoing interface's MTU), so on its own it
says nothing about the path. To ask the path, the interface MTU has to be raised
first — and it cannot be:

```sh
ifconfig vtnet1 mtu 1501
# ifconfig: ioctl SIOCSIFMTU (set mtu): Invalid argument
```

1501, 1600, 2000, 4000 and 9000 are all refused, on `vtnet1` **and** on
`vtnet0`. The virtio-net device these instances get does not negotiate
`VIRTIO_NET_F_MTU`, so 1500 is a hard ceiling inside the guest, before the OVH
fabric ever gets a say.

| Quantity | Value | How it was obtained |
|---|---|---|
| Underlay path MTU | **1500** | DF ping sweep, 6/6 pairs |
| Largest underlay DF payload | **1472** | same |
| Largest MTU the NIC accepts | **1500** | `SIOCSIFMTU` refuses 1501 |
| Jumbo frames | **not available** | driver-level refusal, both interfaces |
| IPv4 VXLAN encapsulation cost | **50 bytes** | 14 Ethernet + 8 UDP + 8 VXLAN + 20 IPv4, from `vxlan_setup_interface_hdrlen()` |
| **Overlay MTU** | **1450** | 1500 − 50, and also the driver's own default |

1450 is not a SatL constant to invent: it is what `if_vxlan(4)` computes for
itself on an IPv4 tunnel. Read `if_vxlan.c`:

```c
ifp->if_hdrlen = ETHER_HDR_LEN + sizeof(struct vxlanudphdr);   /* 14 + 16 */
if (VXLAN_SOCKADDR_IS_IPV4(&sc->vxl_dst_addr) != 0)
        ifp->if_hdrlen += sizeof(struct ip);                   /* + 20     */
if ((sc->vxl_flags & VXLAN_FLAG_USER_MTU) == 0)
        ifp->if_mtu = ETHERMTU - ifp->if_hdrlen;               /* 1500 - 50 */
```

Two consequences worth writing down:

- **`ETHERMTU` is the constant 1500, not the underlay interface's MTU.** The
  driver default is right here by coincidence. On a jumbo underlay it would still
  say 1450 and SatL would have to set the MTU explicitly. So SatL must always
  compute `overlay_mtu = measured_underlay_mtu − 50` and set it, never inherit
  the default and hope.
- An interface with **no remote address** reports mtu **1470** (1500 − 30): with
  no destination the driver cannot know whether to reserve 20 bytes for IPv4 or
  40 for IPv6. An overlay interface showing 1470 is misconfigured (see §5).

IPv6 VTEPs would cost 70 bytes (40-byte IPv6 header), giving 1430. SatL assigns
no IPv6 yet; when it does, the per-network MTU must follow the VTEP's address
family, not a constant.

**Throughput cost of encapsulation: not separable from this link's noise.**
`captures/20-two-node-overlay.txt` §5 transfers 64 MiB through `nc` twice back to
back on the same pair — once host-to-host over the bare underlay as a control,
once jail-to-jail over the overlay. Both are byte-exact every time. Measured
across runs: control 61.4–61.6 MB/s, overlay 47.3–59.1 MB/s. The gap tracks the
retransmission count, and the retransmissions come from packet loss in the
hypervisor's virtual switch (under 1 % to about 2 % depending on the run, with
`ierrs`/`idrop`/`iqdrops` at zero in both guests), not from encapsulation. Run the
control transfer alongside any overlay measurement, or the numbers mean nothing.

---

## 2. Creating the VTEP

Evidence: `captures/10-idioms.txt` §1, §2, §4, §7.

```sh
kldload if_vxlan                       # NOT in GENERIC; loader.conf: if_vxlan_load="YES"

vx=$(ifconfig vxlan create \
        vxlanid <VNI> \
        vxlanlocal <this node's underlay address> \
        vxlanremote <blackhole: an unused address in the underlay prefix> \
        -vxlanlearn)                   # $vx is the name the kernel chose
ifconfig "$vx" name satl-vx-<network>  # rename immediately, see below
ifconfig satl-vx-<network> up
ifconfig satl-vx-<network> | head -1 | grep -q RUNNING || fail   # see below
```

Six things about that sequence are load-bearing.

**1. `ifconfig <driver> create` prints the name it chose, and clone units are
never recycled.** After `vxlan0` is renamed, the next create returns `vxlan1`,
because the renamed interface still occupies unit 0. Never assume `vxlan0`. SatL
already depends on this for its bridge: `satl0` holds bridge unit 0, so the
experiments' bridges came up as `bridge1`, `bridge2`.

**2. Renaming works, including with a dash**, and create+rename must be one
atomic step in the daemon: a crash in between leaves a `vxlanN` clone that
carries no ownership marker and cannot be attributed. `ifconfig -g vxlan`
enumerates every vxlan interface on the host (the driver puts them in group
`vxlan`) — that plus the `satl:` interface description
(`docs/networking.md`, "Ownership markers") is what startup reconciliation
sweeps with.

**3. The per-interface sysctl tree is keyed by the clone unit, not the name.**
`net.link.vxlan.0.*` stays with the interface after it is renamed, and no ioctl
or sysctl maps a unit back to a name. Anything that wants
`net.link.vxlan.N.ftable.dump` must remember `N` from creation time; the
name-based `VXLAN_CMD_GET_CONFIG` ioctl is the safe way to read interface state,
and the dump sysctl is a diagnostic only. To enumerate units blind:

```sh
sysctl -N net.link.vxlan |
    sed -n 's/^net\.link\.vxlan\.\([0-9]*\)\.ftable\.count$/\1/p'
```

**4. `vxlanremote` (or `vxlangroup`) is mandatory.** `vxlan_valid_init_config()`
rejects an interface with no destination address — "no valid destination address
specified" / "destination address type is not supported". The tidy design (no
remote at all, every destination from the FDB) is not available. So every
unicast overlay interface has one **default remote**, and
`vxlan_transmit()` sends every broadcast, multicast and unknown-unicast frame
there without consulting the FDB:

```c
if ((m->m_flags & (M_BCAST | M_MCAST)) == 0)
        fe = vxlan_ftable_entry_lookup(sc, eh->ether_dhost);
if (fe == NULL)
        fe = &sc->vxl_default_fe;      /* == vxlanremote */
```

**Recommendation: point the default remote at a deliberately unroutable address
on the underlay prefix** (the experiments used the `.255.254` host of the
inventory's `underlay_cidr`). Reasons, all
demonstrated in `captures/40-three-node-mesh.txt`:

- pointing it at a real peer makes a *missing FDB entry work anyway* on that one
  peer. A two-node cluster does this by construction, which is exactly how an
  FDB bug stays invisible until the third node joins
  (`captures/20-two-node-overlay.txt` §1 shows two jails pinging with an empty
  FDB);
- with everything programmed statically, nothing that matters is ever sent to
  the default remote, so a blackhole costs nothing;
- it makes BUM traffic visible on the interface counters — but far less cleanly
  than this document originally claimed. Correction immediately below.

**Correction — `Oerrs` is a one-way signal, not a BUM counter.** The old note
here ("`Oerrs` … counts the frames the driver could not deliver to the default
remote") **was wrong**. `vxlan_encap4()` bumps `Oerrs` only when `ip_output()`
returns an error, and a blackhole that is *on-link* on the underlay — which is
exactly what "an unused address in the underlay prefix" is — usually does not
produce one. `arpresolve()` returns `EWOULDBLOCK` for the first
`net.link.ether.inet.maxtries` (default **5**) frames after the blackhole's ARP
entry is created, `ether_output()` masks that to success, and those frames are
counted in **`Opkts`**. Only from the sixth on, while the entry sits unresolved,
does `arpresolve()` return `EHOSTDOWN`, `ip_output()` fail and `Oerrs` move — and
the count starts over every time that ARP entry is recreated. Measured on the dev
host, blackhole `.254` of a /24 the host is on, driving BUM with pings to an
unresolvable overlay address:

| BUM frames sent | state of the blackhole's ARP entry | ΔOpkts | ΔOerrs |
|---|---|---|---|
| 4 | freshly created | +4 | **0** |
| 6 more | past `maxtries` | +1 | +5 |
| 4 more | deleted first, so fresh again | +4 | **0** |

Identical on an empty bridge and on a live L2 segment, so it is the ARP state
machine, not the segment. So: **`Oerrs > 0` proves something went to the default
remote; `Oerrs == 0` proves nothing.** A three-ping probe — the length of a
typical connectivity check — is entirely invisible.

Two ways to get a signal that means something:

- **give the blackhole no route at all.** With a `reject` route covering it,
  `ip_output()` fails immediately and *every* BUM frame is an `Oerrs` from the
  first (measured: 4 frames → `Opkts` 0, `Oerrs` +4). Note that this contradicts
  the recommendation above: an address *in the underlay prefix* is on-link by
  definition, so "deliberately unroutable address on the underlay prefix" cannot
  be both. Getting the exact counter costs one reject route per node;
- **do not use traffic counters at all.** Compare the FDB against what the
  control plane thinks it programmed (`ftable count` from
  `VXLAN_CMD_GET_CONFIG`, §3) — no traffic needed — and use
  `tcpdump -ni <underlay> "udp port 4789 and host <blackhole>"` when you want to
  watch the frames themselves.

**5. `ifconfig` lies about success; `RUNNING` is the only health signal.** Both
failure modes below leave the interface reporting `UP`, `status: active`, and
`ifconfig` exiting 0. The truth is one flag bit and one kernel log line:

| Condition | Flags | Kernel log (`/var/log/messages`) |
|---|---|---|
| healthy | `1008843<UP,BROADCAST,RUNNING,…>` | `link state changed to UP` |
| no remote address | `1008803<UP,BROADCAST,…>` — no `RUNNING` | `cannot initialize interface: destination address type is not supported` |
| VNI already in use on that socket | `1008803<UP,BROADCAST,…>` — no `RUNNING` | `network identifier 4242 already exists in this socket` |

`satl-overlay` must, after every `up`, check for `RUNNING` and surface the kernel
message. Note that installing a static FDB entry on a broken interface
*succeeds* (the FDB only needs the destination address family, not a working
socket), so FDB programming is not a health check.

**6. Many networks per node share one socket, and that is fine.** Several
interfaces with the same `vxlanlocal` and port 4789 but different VNIs all come
up `RUNNING`, share one UDP socket (`sockstat` shows a single
`<underlay address>:4789` for all of them), and keep independent FDBs. The duplicate-VNI check exists to protect that
sharing, and it only fires on `up`, not on `create`.

One trap: **a multicast interface cannot share port 4789 with a unicast one.**
The unicast socket binds the local address, the multicast one wants the
wildcard, and the second bind fails `EADDRINUSE` — `cannot create socket (error:
48), and no existing socket found`, interface left non-`RUNNING`.
(`net.link.vxlan.reuse_port` exists for this and defaults to 0.) Only relevant to
diagnostics, since SatL is unicast-only.

### Per-peer interfaces are a dead end

For the record, since it is the obvious `ifconfig`-only alternative to §3: one
unicast interface per remote peer, all bridged together, steered by bridge static
entries. Two interfaces with the same VNI, same local address and same port are
*created* happily and then fail on `up` with `network identifier 4242 already
exists in this socket`. It can only be made to work by giving each peer its own
local UDP port — which both ends must then agree on, turning a mesh of N nodes
into N−1 interfaces and N−1 negotiated ports per node per network. Rejected.

---

## 3. Static forwarding entries: the ioctl `ifconfig` does not expose

Evidence: `captures/10-idioms.txt` §3; helper source
`hack/experiments/vxlan/vxlan-ftable.c`.

**There is no `ifconfig` command for a static (MAC → remote VTEP) entry.** The
vxlan parameter list in `ifconfig(8)` ends at:

```
vxlanlearn  -vxlanlearn  vxlanflush  vxlanflushall
```

No `vxlanroute`, no `ftable add`, nothing. `ifconfig <bridge> static <member>
<mac>` is a *different* thing (§4) — it steers to a bridge member, never to a
VTEP address, and cannot replace this.

The kernel does have the operation. `net/if_vxlan.h`:

```c
#define VXLAN_CMD_FTABLE_ENTRY_ADD      13
#define VXLAN_CMD_FTABLE_ENTRY_REM      14
#define VXLAN_CMD_FLUSH                 15
```

driven through `SIOCSDRVSPEC` with a `struct ifdrv` naming the interface and a
`struct ifvxlancmd` payload. **`satl-overlay` has to issue this ioctl directly**
— it is the one place in SatL's networking where an `ifconfig` wrapper is not
available, so it is also the one exception to the "no raw syscalls in business
logic" habit that needs its own typed wrapper module.
`hack/experiments/vxlan/vxlan-ftable.c` is a minimal reference implementation
(`add`/`del`/`flush`/`config`); the Rust side needs the same shape:

```c
struct ifdrv ifd = {
        .ifd_name = "satl-vx-mynet",           /* IFNAMSIZ, NUL-terminated  */
        .ifd_cmd  = VXLAN_CMD_FTABLE_ENTRY_ADD,
        .ifd_len  = sizeof(struct ifvxlancmd), /* must be EXACTLY this      */
        .ifd_data = &cmd,
};
ioctl(s, SIOCSDRVSPEC, &ifd);                  /* s: any AF_INET SOCK_DGRAM */
```

Contract, from `vxlan_ctrl_ftable_entry_add()` and `vxlan_ioctl_drvspec()`:

| Requirement | Consequence of getting it wrong |
|---|---|
| `ifd_len == sizeof(struct ifvxlancmd)` exactly | `EINVAL` |
| `vxlcmd_sa` family must equal the interface's `vxlanremote` family | `EAFNOSUPPORT` |
| `vxlcmd_sa` must not be `INADDR_ANY` or multicast | `EINVAL` |
| `vxlcmd_sa.sin_len`/`sin_family` set | `EINVAL` |
| `vxlcmd_sa.sin_port == 0` | **desirable**: inherits the interface's remote port |
| root (`PRIV_NET_VXLAN`) | `EPERM` |
| removing an absent entry | `ENOENT` |
| adding a MAC that is already present | **`EEXIST`** — see below |

Every entry added this way is stamped `VXLAN_FE_FLAG_STATIC`.

### `add` never replaces: an existing MAC is `EEXIST`

**The old note in §7 — "`add` on an existing entry replaces it" — was wrong.**
`vxlan_ftable_entry_insert()` walks the hash bucket and returns `EEXIST` the
moment it finds the same MAC; the remote VTEP is never compared and the stored
entry is not touched. Measured:

```sh
vxlan-ftable add <if> 02:e3:0a:64:00:0b 127.0.0.11
# <if>: static ftable entry 02:e3:0a:64:00:0b -> 127.0.0.11        (exit 0)
vxlan-ftable add <if> 02:e3:0a:64:00:0b 127.0.0.11
# vxlan-ftable: <if>: FTABLE_ENTRY_ADD …: File exists              (exit 1)
vxlan-ftable add <if> 02:e3:0a:64:00:0b 127.0.0.99   # different VTEP, same MAC
# vxlan-ftable: <if>: FTABLE_ENTRY_ADD …: File exists              (exit 1)
sysctl -n net.link.vxlan.0.ftable.dump
# S 0x02 02:E3:0A:64:00:0B      127.0.0.11 00044511   <-- unchanged
```

**Moving an endpoint to another node is therefore remove-then-add, not add.** That
is not a footnote: a migrating endpoint keeps its MAC — the MAC is a pure function
of its overlay IP (§4) — and changes only its VTEP, which is precisely the case
`add` refuses. So a reconciler needs three operations, not two: add, remove, and a
`replace` that is a remove followed by an add, with a window in between in which
the MAC resolves nowhere. `satl-overlay` carries that third operation and a third
delta list for it.

### Reading the table back

```sh
sysctl -n net.link.vxlan.0.ftable.dump
#
# S 0x02 02:E3:0A:63:00:0C       10.2.1.50 00030602
# S 0x02 02:E3:0A:63:00:0D      10.2.3.124 00030603
```

Columns: `S`/`D` (static/dynamic), entry flags (`0x02` = `VXLAN_FE_FLAG_STATIC`,
`0x01` = dynamic), inner MAC, remote VTEP, an internal age counter. `man 4 vxlan`
documents this sysctl correctly. It is registered `CTLFLAG_SKIP`, so it does
**not** appear in a *value* listing — but the old wording here ("does not appear
in a `sysctl net.link.vxlan` listing"), while literally true, reads as "cannot be
discovered", and that **is wrong**: a *name* listing shows it, which is what §2
point 3's unit-enumeration recipe depends on.

```sh
sysctl -N net.link.vxlan | grep ftable.dump
# net.link.vxlan.0.ftable.dump
sysctl net.link.vxlan | grep -c ftable.dump
# 0
sysctl -a | grep -c 'net.link.vxlan.0.ftable.dump'
# 0
```

`VXLAN_CMD_GET_CONFIG` gives the entry *count* by interface name but not the
entries.

### The dump truncates at one page, silently

**Do not build a reconciler on this sysctl.** `vxlan_ftable_sysctl_dump()`
formats into `sbuf_new(&sb, NULL, PAGE_SIZE, SBUF_FIXEDLEN)` and stops when the
buffer fills, backing out the partial line (`sbuf_setpos()`) so the output stays
perfectly well-formed and carries no hint that anything is missing. The kernel
comment says as much: *"This is mostly intended for debugging during development.
It is not practical to dump an entire large table this way."*

An IPv4 line is exactly 50 bytes (`S 0x02 `, the MAC, a 15-wide right-aligned
address field, an 8-digit counter, newline) after one leading newline, so the
ceiling is **81 entries**. Measured on one interface, flushed between rows:

| Static entries installed | `ftable count` (ioctl) | lines in `ftable.dump` | dump bytes |
|---|---|---|---|
| 80 | 80 | 80 | 4002 |
| 81 | 81 | 81 | 4052 |
| 82 | 82 | **81** | 4052 |
| 90 | 90 | **81** | 4052 |
| 2500 | 2500 | **81** | 4052 |

An IPv6 remote widens the address field to 45, which puts that ceiling near 51.

Two consequences: the ioctl's `ftable count` is the only trustworthy table size,
and **any reconciliation that diffs against the dump is correct only below 81
endpoints per network per node.** Above it the dump reports live entries as
absent, and re-adding them fails `EEXIST` (above) — so the failure is loud rather
than silent, which is the only good news in this paragraph.

### Lifetime — what survives what

Verified, not inferred (`captures/10-idioms.txt` §3):

| Event | Static entries |
|---|---|
| `ifconfig <if> down` then `up` (flap) | **survive** — `vxlan_teardown_locked()` does not flush |
| `ifconfig <if> vxlanflush` | **survive** — dynamic entries only |
| `ifconfig <if> vxlanflushall` | deleted |
| `ifconfig <if> destroy` | deleted with the interface |
| `vxlantimeout` expiry (1200 s) | **never** — pruning only touches dynamic entries |

So an interface flap needs no FDB re-programming, but any destroy/create cycle
needs a full re-push.

### The ceiling: `vxlanmaxaddr` is not a tunable, and does not bound us anyway

**The old note here — "`vxlanmaxaddr` defaults to 2000 entries per interface,
which is the ceiling on endpoints per network per node; raise it with `ifconfig
<if> vxlanmaxaddr N` for large networks, and watch `ftable_nospace`" — was wrong
on all three counts.** Measured, and confirmed against `if_vxlan.c`:

1. **2000 is a hard maximum, not a default that can be raised.**
   `VXLAN_FTABLE_MAX` is a compile-time `#ifndef` constant and
   `vxlan_check_ftable_max()` rejects anything above it. `vxlanmaxaddr` accepts
   0…2000 and refuses the rest, whichever direction you come from:

   ```sh
   ifconfig <if> vxlanmaxaddr 2001   # ifconfig: VXLAN_CMD_SET_FTABLE_MAX: Invalid argument (exit 1)
   ifconfig <if> vxlanmaxaddr 4000   # same, and same from a current value of 100
   ifconfig <if> vxlanmaxaddr 2000   # exit 0
   ifconfig <if> vxlanmaxaddr 1000   # exit 0 — lowering works
   ```

   At **create** time an out-of-range value is not refused, it is *ignored*:
   `ifconfig vxlan create … vxlanmaxaddr 4000` exits 0, prints a clone name, and
   the interface comes up `RUNNING` reporting `ftable count 0 max 2000`. One more
   instance of the §2 point 5 pattern — read the value back, never trust that a
   parameter was applied.

2. **The ceiling bounds *learning*, not static entries.** The
   `vxl_ftable_cnt >= vxl_ftable_max` test lives in one place,
   `vxlan_ftable_update_locked()`, on the learn path — reached only when
   `VXLAN_FLAG_LEARN` is set. `vxlan_ctrl_ftable_entry_add()` goes straight to
   `vxlan_ftable_entry_insert()` with no count check at all. Measured on an
   interface reporting `max 2000`: **2500 static entries all installed**, ending
   at `ftable count 2500 max 2000`, with nothing logged and nothing refused.

3. **`ftable_nospace` can never move in this design.** It is incremented on
   exactly that one learn-path branch, and SatL runs `-vxlanlearn`. It is a
   useful counter for a learning VXLAN and a dead one here.

So there is **no ~2000-endpoint-per-network-per-node limit** on a SatL overlay.
The real bound is the dump sysctl's 81 (above), and it binds only code that reads
the table back. Past that, the FDB is 512 hash buckets of sorted lists
(`VXLAN_SC_FTABLE_SHIFT` = 9, independent of `vxlanmaxaddr`), so the cost of
growth is chain length, not a wall — inferred from the data structure, not
measured as a throughput curve.

### Learning is off

`-vxlanlearn` (accepted at create time and afterwards). The FDB is control-plane
state; a learned entry that ages out after 20 minutes is not something a
reconciler can reason about. `captures/10-idioms.txt` §8 shows what learned
entries look like (`D 0x01 …`) for contrast.

---

## 4. Bridge, epair, and static ARP

Evidence: `captures/10-idioms.txt` §5, §6; `captures/20-two-node-overlay.txt` §1.

The topology is the M1 bridge (`docs/networking.md`) with the vxlan interface as
one more bridge member:

```
   host                                        jail (VNET, one per task)
 ┌────────────────────────────────────┐      ┌────────────────────────────┐
 │  satl-vx-<net> (vxlan, mtu 1450) ──┼──▶ underlay (vtnet1, mtu 1500)    │
 │        │                           │      │                            │
 │  satl-br-<net> (bridge, mtu 1450)  │      │  epairNb  mtu 1450  <-- set│
 │        │                           │      │   inet <overlay ip>/24     │
 │  epairNa (member, mtu 1450)  ──────┼──────┤   arp -s <peer> <peer mac> │
 └────────────────────────────────────┘      └────────────────────────────┘
```

Bring-up, exactly as captured (the full script is `overlay_up()` in
`hack/experiments/vxlan/common.sh` and it is reproduced verbatim inside every
capture):

```sh
# bridge: add the 1450-byte vxlan interface FIRST, then set the MTU explicitly
br=$(ifconfig bridge create); ifconfig "$br" name satl-br-mynet
ifconfig satl-br-mynet addm satl-vx-mynet
ifconfig satl-br-mynet mtu 1450
ifconfig satl-br-mynet up

# the task's epair; MAC derived from the overlay address (see below)
ep=$(ifconfig epair create)                 # e.g. epair1a
ifconfig "$ep" name satl-ep-<task>a
ifconfig "${ep%a}b" name satl-ep-<task>b
ifconfig satl-ep-<task>b ether 02:e3:0a:64:00:0b   # = mac_of(10.100.0.11)
ifconfig satl-br-mynet addm satl-ep-<task>a
ifconfig satl-ep-<task>a up                 # <-- separate command, see below

# the jail
jail -c name=<task> host.hostname=<task> vnet=new persist path=<rootfs> \
     allow.raw_sockets                      # ocijail does this part, docs/ocijail.md
ifconfig satl-ep-<task>b vnet <task>
jexec <task> ifconfig lo0 up
jexec <task> ifconfig satl-ep-<task>b inet 10.100.0.11/24 mtu 1450 up
```

**`ifconfig <bridge> addm <member> up` brings up the *bridge*, not the member.**
`ifconfig` applies every parameter to the interface it was given. A bridge member
that is not `UP` silently forwards nothing — and its flag word still shows
`RUNNING` (the epair link is up), so only the absence of `UP` gives it away. Each
end needs its own `up`. The observed symptom while writing this document was a
host-to-local-jail ping at 100 % packet loss with every interface looking
correctly configured.

### Deterministic MACs

`ifconfig <if> ether 02:e3:0a:64:00:0b` works on an epair, on the host, before
the interface is moved into the jail, and the MAC survives the move. Derive it
from the endpoint's overlay address — the experiments used
`02:e3:<a>:<b>:<c>:<d>` for `a.b.c.d`, the same trick as Docker's `02:42:*`.

This is not cosmetic. It means every node can compute a remote endpoint's MAC
from its overlay IP alone, so the FDB and ARP entries can be programmed from the
store with **no read-back of a kernel-generated MAC** and no ordering dependency
on the remote task actually existing yet. The endpoint record the control plane
distributes then needs only `(overlay IP, node VTEP)`; the MAC is a pure function
of the IP. If SatL instead published kernel-generated MACs, every endpoint would
need a round trip through Raft after its epair was created.

### Static ARP

What the entry has to look like — but **not how to install it**, see the two
corrections at the end of this subsection before copying this:

```sh
jexec <task> arp -s 10.100.0.12 02:e3:0a:64:00:0c
# ? (10.100.0.12) at 02:e3:0a:64:00:0c on satl-ep-<task>b permanent [ethernet]
```

- **It must be installed inside the jail's VNET.** An entry in the host's table is
  in a different stack and does nothing for the jail — demonstrated (`arp -n` on
  the host reports `no entry` for an address the jail has pinned).
- `permanent` means it never expires and is never replaced by an ARP reply.
  Unlike the vxlan FDB (§3), `arp -s` *does* replace an existing entry: it sends
  `RTM_NEWNEIGH` with `NLM_F_CREATE | NLM_F_REPLACE`, and re-issuing it with a
  different MAC overwrites, exit 0. The two tables have opposite semantics on the
  same operation; do not carry a habit from one to the other.
- **`arp -s` requires the address to be on-link for some interface in that
  stack** — and **it exits 0 when it is not**, which the old note omitted:

  ```sh
  arp -s 192.0.2.77 02:e3:c0:00:02:4d ; echo "exit=$?"
  # arp: set: cannot locate 192.0.2.77      <-- stderr
  # exit=0
  arp -n 192.0.2.77 ; echo "exit=$?"
  # 192.0.2.77 (192.0.2.77) -- no entry
  # exit=1
  ```

  This is the same lie as `ifconfig` reporting success for a vxlan interface the
  driver refused to initialise (§2 point 5), and the two belong together as one
  pattern to expect from these tools: **on this platform the exit status of a
  network configuration command is not evidence that anything happened.** In
  `arp(8)` it is not even subtle — `set_nl()` in `usr.sbin/arp/arp_netlink.c`
  `return (0)`s on that path, and `main()` maps that to exit 0. Verify by reading
  back instead: `arp -n <ip>` exits 1 when there is no entry. Inside the jail the
  epair holds the /24, so a peer address is always on-link and it always works;
  on the host it fails — silently — until the bridge has an address in the subnet.
- **Static ARP for remote endpoints is mandatory, not an optimisation.** A
  broadcast ARP request is encapsulated to the single default remote and nowhere
  else, so on any cluster with more than two nodes ARP cannot resolve a peer.
- The host needs no static ARP to reach a *local* jail: the jail answers ARP
  itself over a real L2 segment.

**Correction — "so it goes through `jexec`" was wrong.** The old note said
`arp(8)` has no `-j` flag (`route(8)` does) "so it goes through `jexec`". That
worked only because these experiments used `path=/` jails, which see the host's
userland. `jexec` runs the **jail's** `arp` binary, and a container image does not
have a usable one. Measured against two live task jails on this host:

```sh
jexec <task-from-a-freebsd-image> arp -a
# jexec: execvp: arp: No such file or directory
jexec <task-from-an-alpine-image> /sbin/arp -a
# arp: can't open '/proc/net/arp': No such file or directory
```

The FreeBSD-based rootfs has no `arp` anywhere in it (only `/sbin/route` and
`/sbin/ifconfig`); in the Alpine one `/sbin/arp` is a busybox symlink, i.e. a
*Linux* arp that reads `/proc/net/arp` and speaks `SIOCSARP` — it could not
program a FreeBSD ARP table even with linprocfs mounted.

**Correction — `route -j` is not a substitute either.** `route(8)` does support
`-j` (it `jail_attach()`es itself, which is how `docs/networking.md` sets a task's
default route), but it cannot install a *link-layer* entry on a modern FreeBSD:
`rtsock` hands a message to the link-layer table (`lla_rt_output()`) only when
`RTF_LLDATA` is set in `rtm_flags`, and `RTF_LLDATA` appears **nowhere** in
`sbin/route/route.c`. Every spelling fails, and the jail's ARP table is unchanged
after all four:

```sh
route -j <jail> add -host 10.79.9.12 02:e3:0a:4f:09:0c -iface
# route: bad address: 02:e3:0a:4f:09:0c                                  (exit 68)
route -j <jail> add -host 10.79.9.12 -link 02:e3:0a:4f:09:0c -iface
# route: message indicates error: Invalid argument                       (exit 1)
route -j <jail> add -host 10.79.9.12 -link 02:e3:0a:4f:09:0c
# route: message indicates error: Invalid argument                       (exit 1)
route -j <jail> add -host 10.79.9.12 -llinfo -link 02:e3:0a:4f:09:0c
# route: bad keyword: llinfo                                             (exit 64)
```

So the entry has to be installed by SatL itself, from a process that has entered
the jail's VNET, talking to the kernel directly: a routing-socket `RTM_ADD`
carrying `RTF_LLDATA`, or the `RTM_NEWNEIGH` netlink message `arp(8)` itself now
uses (`usr.sbin/arp/arp_netlink.c`). That mechanism is being implemented; its API
is deliberately not written up here while it is still moving. What is settled is
the constraint: **no in-jail binary, and no `route -j`.**

### Bridge static entries

```sh
ifconfig satl-br-mynet static satl-vx-mynet 02:e3:0a:64:00:0c
ifconfig satl-br-mynet addr
# 02:e3:0a:64:00:0c Vlan0 satl-vx-mynet 0 flags=1<STATIC>
```

Optional but worth doing. Without it the bridge floods a not-yet-learned remote
MAC to every local jail as well as to the vxlan interface (it still reaches the
right place, because the vxlan FDB does the real work). With it, the first frame
to a remote endpoint goes straight out of the vxlan member. Remove with
`ifconfig <bridge> deladdr <mac>`.

---

## 5. Where the MTU has to be set

Evidence: `captures/10-idioms.txt` §5, `captures/30-mtu-failure.txt`.

`man 4 bridge` (15.1): *"The MTU of the first member interface to be added is
used as the bridge MTU. All additional members will have their MTU changed to
match. If the MTU of a bridge is changed after its creation, the MTU of all
member interfaces is also changed to match."* Confirmed live, in both
directions.

| Interface | MTU | Set by | Notes |
|---|---|---|---|
| underlay (`vtnet1`) | 1500 | the operator / the cloud | measure it, never assume |
| vxlan | 1450 | driver default, **or** the bridge | setting it by hand latches `VXLAN_FLAG_USER_MTU` and the driver stops recomputing |
| bridge | 1450 | **set explicitly, after the first `addm`** | the first member added overwrites it; from then on it propagates to all members |
| epair `a` (bridge member) | 1450 | the bridge — and **only** the bridge | **cannot be set at all** while it is a member: `SIOCSIFMTU` is `EOPNOTSUPP` |
| epair `b` (inside the jail) | 1450 | **set explicitly** | not a bridge member, so nothing propagates to it — and nothing refuses it either |

Two places to act, then: the bridge (which fixes the vxlan interface and the
epair `a` ends), and each in-jail epair `b` end. The `b` end is the one that
determines the container's TCP MSS, so missing it is the mistake with the widest
blast radius.

### Correction — a member's MTU is not "automatic", it is *unsettable*

The old note here ("epair `a`: the bridge, automatically — no action needed") is
true but understated in a way that matters: it reads as "you may skip this", when
in fact the attempt **fails**, including for the value the interface already has.

```sh
ifconfig docvfy2-epa mtu 1450    # already 1450, and a member of a 1450 bridge
# ifconfig: ioctl SIOCSIFMTU (set mtu): Operation not supported   (exit 1)
ifconfig docvfy2-epa mtu 1400    # same
# ifconfig: ioctl SIOCSIFMTU (set mtu): Operation not supported   (exit 1)
ifconfig docvfy2-br1 deletem docvfy2-epa
ifconfig docvfy2-epa mtu 1400    # exit 0 — it was the membership, not the interface
```

`sys/net/if.c`, `SIOCSIFMTU`, is unconditional and runs before the value is even
looked at, which is exactly why setting the current value fails too:

```c
/* Disallow MTU changes on bridge member interfaces. */
if (ifp->if_bridge)
        return (EOPNOTSUPP);
```

The bridge itself is exempt because `bridge_ioctl_add()` calls the member's
`if_ioctl` directly, bypassing that check. What it does there (`if_bridge.c`) is
the other half of the rule, and it is a real ordering constraint rather than a
shortcut:

```c
/* Allow the first Ethernet member to define the MTU */
if (CK_LIST_EMPTY(&sc->sc_iflist))
        sc->sc_ifp->if_mtu = ifs->if_mtu;
else if (sc->sc_ifp->if_mtu != ifs->if_mtu)
        /* force the new member to the bridge's MTU, or refuse the addm */
```

Measured, in both directions: a 1500 member joining a 1450 bridge is rewritten to
1450, and raising a 1400 bridge to 1450 pulls its existing member up with it. So:

| Want | Do |
|---|---|
| the bridge at 1450 | either `addm` the already-1450 vxlan interface **first** (the first member defines the bridge MTU), or `addm` anything and then set the *bridge*. Setting a memberless bridge's MTU sticks and is then thrown away by the first `addm` — a silent no-op with a plausible-looking `exit 0` |
| a member (`a` end, vxlan) at 1450 | nothing. Set the bridge; never the member |
| the in-jail `b` end at 1450 | set it explicitly, before or after the `vnet` move — it is never a member, so it neither inherits nor refuses |

Setting an MTU on a vxlan interface — directly or via the bridge — latches
`VXLAN_FLAG_USER_MTU` and the driver never recomputes the MTU again, even if the
remote address family later changes (`if_vxlan.c`, `SIOCSIFMTU` and
`vxlan_setup_interface_hdrlen()`). The accepted range is `ETHERMIN` to
`VXLAN_MAX_MTU`; anything outside it is `EINVAL`.

Verification that the accounting is exactly right, from inside a jail:

```sh
ping -c 2 -D -s 1422 <peer>    # OK: 1422 + 28 = 1450 inner, + 50 = 1500 outer
ping -c 1 -D -s 1423 <peer>    # ping: sendto: Message too long
```

1472 (underlay) − 1422 (overlay) = 50. The encapsulation is the whole
difference.

### The mesh's second −50 site (M6d)

The routing mesh adds one more place where the 50-byte overhead matters, and
it is **not** an interface: a client talking to a published port negotiates
its MSS against the node's 1500-MTU underlay interface, and its packets are
then forwarded *into* a 1450-MTU overlay. Nobody told the client. The mesh
therefore emits an MSS clamp on the ingress path — `match out on <overlay
bridge> inet proto tcp to <subnet> scrub (max-mss 1410)` in the `satl/rdr`
anchor — so the client's SYN is rewritten to what the overlay can carry.

Measured before building it (`hack/experiments/mesh`): the happy path does
not actually need the clamp — the task's own epair is 1450 so the *server*
side advertises 1410 itself, and for the client's direction the relaying node
forwards into the 1450 bridge and can ICMP too-big the client (PMTUD works,
because the relay is on the path). The clamp is insurance against
ICMP-filtered internet paths, and it costs one `match` rule. The check that
proves it keeps working: the VXLAN fragmentation counters before and after a
bulk transfer through the mesh must not move.

---

## 6. Failure signatures

Evidence: `captures/30-mtu-failure.txt`, four configurations on one overlay.

**`if_vxlan(4)` leaves DF clear on the outer header** — `vxlan_encap4()` sets
`ip->ip_off = 0` — so an oversized encapsulated frame is handed to `ip_output()`
to fragment, not rejected. That single line changes the whole symptom picture:
CLAUDE.md's "small packets pass, big ones hang" describes only case D of the four
below. The "VXLAN MTU" gotcha there **has been amended** to say so.

| # | Configuration | Symptom | Evidence |
|---|---|---|---|
| A | overlay 1450, underlay 1500 (correct) | works; 16 MiB byte-exact; pings of every legal size answer | `out_frag +0 frags_created +0` on both nodes |
| B | overlay **1500**, underlay 1500 (the forgotten −50) | **works.** Every ping answers, every byte arrives — and every full-size frame is now split in two and reassembled on the far side | sender `out_frag +11826 frags_created +23652`; receiver `frags_rcvd +23361`, i.e. 2 fragments per datagram for a 16 MiB transfer |
| C | overlay 1450, one node's underlay lowered to 1400 | **works.** Outbound the low-MTU node fragments; inbound the oversized frames are accepted anyway (`Ierrs` does not move) — an interface MTU on FreeBSD is a transmit-side limit | receiver `Ierrs=0`; low-MTU node `out_frag +2` (the two large ping replies) |
| D | overlay **1500** + a path that discards fragments | **hangs, exactly as described.** 56-byte ping 0 % loss; 1472-byte ping **100 % loss with no error printed**; TCP connects (small handshake) then stalls dead and dies on timeout (`nc exit: 124`); receiver got **0 bytes** | receiver `frags_rcvd +44 frags_dropped +44`, and nothing else anywhere |

Case D was produced with `sysctl net.inet.ip.maxfragpackets=0` on the receiver,
which models the real thing: cloud SDNs and stateful firewalls that drop IP
fragments are common. With the MTU corrected to 1450 on the *same* hostile path,
the same probes pass and the transfer completes — because nothing needs
fragmenting any more. That is the entire point of getting the 50 bytes right.

**The dangerous case is B, not D.** B works. It passes every functional test,
answers every ping of every size, completes every transfer byte-exact. What it
costs is two packets per frame instead of one, a reassembly queue on every
receiver, and loss amplification — both fragments must arrive or the datagram is
gone, so a link with 1 % frame loss becomes a link with about 2 % datagram loss.
Nothing in the kernel warns about it: setting an MTU by hand latches
`VXLAN_FLAG_USER_MTU` and the driver stops having an opinion.

Do not expect a throughput number to reveal it. Across runs this link delivered
33–66 MB/s in *correct* configurations, which is a wider spread than the
difference between A and B in any single run (one run measured B at half of A,
the final run measured them within 10 %). **The fragmentation counters are the
only reliable signal**; throughput on a shared virtual switch is not.

### Diagnostic order

1. **DF ping sweep the underlay**, every node to every other
   (`hack/experiments/vxlan/00-underlay-mtu.sh`). This is the only measurement
   that distinguishes "our accounting is wrong" from "the fabric changed".
2. Compare every overlay interface's MTU against that measurement − 50 —
   including the in-jail `b` ends, which are the ones nothing propagates to.
3. **Check the outer fragmentation counters on both ends**
   (`netstat -s -p ip`, host stack). Non-zero on a healthy-looking overlay means
   configuration B.
4. Check `RUNNING` on each vxlan interface and read
   `/var/log/messages` (`docs/architecture.md`; CLAUDE.md "Reading what the
   daemon says") — the two silent-failure modes of §2 only report there.
5. Check `Oerrs` **and `Opkts`** on the vxlan interface. With a blackhole default
   remote, `Oerrs > 0` means traffic was aimed at endpoints the control plane has
   not programmed — but `Oerrs == 0` means nothing at all unless that blackhole is
   genuinely unroutable, because the first five frames after each ARP-entry
   refresh are counted as successful transmits (§2 point 4, correction).
6. Only then look at the FDB and the in-jail ARP table. Prefer `ftable count`
   from the ioctl to `net.link.vxlan.N.ftable.dump`, which truncates at 81
   entries with no error (§3).

### Counters live in two different stacks

The TCP endpoints are inside VNET jails, so **the jail's stack owns the
retransmit and inner-IP statistics** and the host's `netstat` knows nothing about
them. Encapsulation happens on the host stack, so **the outer-IP fragmentation
counters are the host's**. Reading the wrong one of the two is a fast route to a
confident wrong conclusion — it happened while writing this document. `jexec
<task> netstat -s -p tcp` reads the former, but **only in a jail with a full
FreeBSD userland**: the `path=/` jails these experiments used have `netstat`, and a
container built from an OCI image does not (measured — the FreeBSD-based rootfs on
the dev host ships neither `netstat` nor `arp`, and the Alpine one has only
busybox, whose `netstat` reads `/proc/net/*`). Same constraint as the ARP entries
in §4, for the same reason. Against a real container, put a throwaway `path=/`
jail on the same bridge and measure from there.

Worked example of reconciling them, from `captures/20-two-node-overlay.txt` §5.
Sender host `vxlan.opkts` minus receiver host `vxlan.ipkts` gives the frames that
went missing: 209 in one run of the 64 MiB transfer, 208 in another — about 0.4 %
of ~49 000 frames. In the first run the sender *jail's* `tcp.rexmit` was 209,
matching exactly; in the second it was 1047, because retransmission is not
one-to-one with loss (an RTO can resend more than was actually lost — FreeBSD
counts "data packets unnecessarily retransmitted" separately). So the missing-frame
count is the measure of loss and the retransmit counter is only its upper bound.

In every run, `vxlan` `ierrs/idrop/oerrs` and underlay `ierrs/idrop/iqdrops` were
0 on both nodes, so nothing in either guest dropped anything: the loss is in the
hypervisor's virtual switch. Every byte still arrived. Packet counts across a
tunnel are only meaningful next to the byte counts, the retransmit counter and a
bare-underlay control transfer.

---

## 7. The programming model `satl-overlay` should implement

Per **overlay network** on each node that hosts at least one of its tasks:

1. one vxlan interface: `vxlanid <VNI>`, `vxlanlocal <this node's underlay
   address>`, `vxlanremote <blackhole>`, `-vxlanlearn`, MTU = underlay − 50;
2. one bridge, MTU set explicitly, with the vxlan interface as its first member;
3. per local task: an epair, `b` end into the jail's VNET with a deterministic
   MAC and the overlay MTU;
4. per **remote endpoint** on that network, three entries computed from
   `(overlay IP, remote node VTEP)` and nothing else:

```sh
vxlan-ftable add   satl-vx-<net> <mac(ip)> <peer vtep>      # ioctl, §3 — EEXIST if the MAC is present
ifconfig satl-br-<net> static satl-vx-<net> <mac(ip)>       # optional, §4
# a permanent ARP entry <ip> -> <mac(ip)> in each local task's VNET.
# NOT `jexec <task> arp -s`: a container image has no arp(8) — §4.
```

The ARP entry is per *local jail* (each has its own stack), so adding a remote
endpoint is one FDB entry plus one bridge entry plus one ARP entry **per local
task on that network**. Removing an endpoint is the same three deletions.

Properties this model has, all verified in `captures/40-three-node-mesh.txt`
with three nodes and a blackhole default remote:

- **it scales past a pair on one interface**: three nodes, one vxlan interface
  per node, two static FDB entries each, all six directions ping, and a 64 MiB
  transfer between the pair that involves neither node's default remote completes
  byte-exact at 60.1 MB/s with zero fragmentation;
- **the FDB is per-direction**, and this is the diagnostic trap. Deleting node1's
  entry for node3's endpoint breaks the pair in **both** directions: node3 →
  node1 echo requests still arrive (node3's own entry is fine), but node1's
  *replies* are unicast to node3's MAC, whose entry is the one that was deleted.
  The node reporting 100 % loss is the correctly configured one. Diagnose from
  the sender of the replies;
- **it is exactly reversible**: re-adding the single entry restored the pair with
  nothing else touched.

Reconciliation notes:

- **`add` on an existing entry does *not* replace it — that claim was wrong.** It
  is `EEXIST` whatever the VTEP, so changing where a MAC points is remove-then-add
  and a reconciler needs a third `replace` operation and a third delta list (§3,
  "`add` never replaces"). `del` on an absent entry is `ENOENT`, so an idempotent
  reconciler either tolerates both statuses or reads the current table first —
  and if it reads, it must use `ftable count`/the ioctl rather than trusting
  `net.link.vxlan.N.ftable.dump`, which silently stops at 81 entries (§3);
- an interface flap needs no re-push; a destroy/create cycle needs a full one
  (§3, lifetime table);
- record the clone unit at creation time if the dump sysctl is ever to be read
  (§2, point 3);
- everything SatL creates carries a `satl:` description so the startup sweep can
  find orphans, and `ifconfig -g vxlan` enumerates vxlan interfaces specifically.

### Multicast is available on this underlay, and is still not used

`captures/10-idioms.txt` §8: a multicast VXLAN segment (`vxlangroup 239.99.0.1
vxlandev vtnet1`) between two nodes works — the OVH private network floods the
group, ARP resolves across it, and the FDB populates itself with `D` entries. So
"no multicast" is SatL's choice, not this fabric's constraint. The reasons to
keep the choice are visible in that same section: the learned FDB expires
(`vxlantimeout`, 1200 s) and cannot be reconciled against the store, every BUM
frame is flooded to every node in the group whether or not it hosts an endpoint,
the group address is one more thing to allocate, and no operator's fabric can be
assumed to carry multicast.

It stays useful as a diagnostic: if a unicast overlay is broken, a throwaway
multicast segment between the same two nodes separates "the fabric" from "our
FDB programming".

---

## 8. DNS responder placement: one listener per network gateway address

**Resolves architecture.md §17 open question #7.**
Evidence: `captures/50-dns-placement.txt`.

> *one listener per network gateway vs one per node with a pf redirect*

**Recommendation: one responder socket per (node, network), bound to that
network's gateway address on the node's bridge, port 53 — and the gateway
address must be allocated per node, not shared.** No pf involvement.

### What was measured

**A jail reaches a listener bound to its bridge's gateway address, and the reply
carries that source address.** A socket bound to `10.99.0.1:53` on the host
received `query from 10.99.0.11:<ephemeral>` from the jail and the jail got the
answer back through a *connected* UDP socket — which discards any datagram not from
`10.99.0.1:53`, so the round trip is itself the proof about the source address.
This is the property a DNS client depends on, and binding one address gives it
for free.

**Several such listeners coexist on port 53.** Two networks on one node, two
gateway addresses, two responders, no `SO_REUSEPORT` and no coordination:

```
udp4  10.99.1.1:53   *:*
udp4  10.99.0.1:53   *:*
```

Each jail reached its own network's responder and only its own; a jail on
network B could not reach network A's gateway at all (`Network is
unreachable` — no route, no forwarding between bridges). Per-network isolation
comes out of the addressing, with nothing extra to enforce it.

**Binding one address keeps the responder off the public interface.** A wildcard
bind shows `*:5300` in `sockstat` and would answer on the node's public address —
an open resolver. The gateway-bound socket is unreachable from off the node
(probed from the dev host, which is not on the underlay). A single per-node
wildcard listener is therefore not an option without extra firewalling.

### Why not the pf redirect

Two facts, both measured:

1. **pf does not see bridged frames by default.** All three bridge-filtering
   sysctls are off (`net.link.bridge.pfil_bridge=0`, `pfil_member=0`,
   `pfil_local_phys=0`), so a rule on a member interface never matches
   jail-to-jail traffic. Turning them on is a host-global change affecting every
   bridge on the node, including M1's `satl0`.
2. **The redirect still needs the gateway address to exist.** A jail can only
   send to an address it can resolve on its own segment; with no address on the
   bridge there is nothing to ARP for and nothing for pf to rewrite. Removing the
   address made the query unanswerable — and note the shape of that failure: the
   jail's *cached* ARP entry survives, so packets keep being sent to a MAC that
   no longer answers. 100 % loss, no error, until the entry expires. Removing a
   network's gateway address from under running tasks is a silent black hole.

Since the per-network address has to exist either way, binding to it directly is
strictly less machinery than a rule per network plus host-global bridge
filtering.

### The constraint nobody asked about: the gateway address must be per node

This is the part that actually shapes the implementation. On a **local** bridge,
every node using `10.88.0.1` is harmless — the segments are separate. On an
**overlay**, every node's bridge is on one L2 segment, so the same gateway
address on each node is a duplicate address on a shared segment. Measured, with
`10.99.0.1` on two nodes' bridges in the same VNI and a responder on each:

```
node1 kernel: arp: 58:9c:fc:10:e5:0e is using my IP address 10.99.0.1 on expm3-br0!
node1 kernel: arp: 10.99.0.1 moved from 58:9c:fc:10:a8:9b to 58:9c:fc:10:e5:0e on expm3-ep0b
node2 kernel: arp: 58:9c:fc:10:a8:9b is using my IP address 10.99.0.1 on expm3-br0!
```

`58:9c:fc:10:e5:0e` is **node2's** bridge. node1's jail resolved its own
gateway to the remote node's MAC, and **all three of its DNS queries were
answered by node2's responder** while node1's own responder — bound to the same
address, on the same node — received nothing at all.

That is not only a DNS problem: the same address is the jails' default route, so
whichever host wins the ARP race also receives that jail's egress traffic.

Consequences for SatL:

- **cluster IPAM must reserve one gateway address per node per overlay network**,
  from that network's subnet, and each node's bridge gets its own. The agent
  already writes `resolv.conf` per container (`docs/networking.md`, "Container
  DNS"), so pointing it at the *local* node's gateway address costs nothing.

  **Update — this has landed, and the description of the code above is stale.**
  When this section was written the allocator stored a single cluster-wide
  `Network.gateway` (`.1` of the subnet), and assigning that one address to every
  node's overlay bridge would have reproduced the ARP conflict above exactly. That
  changed in commit `6e2b42b`: the field is now **`Network::node_gateways`**, a
  per-node map keyed by node ID, each address allocated on demand from the
  network's own subnet when that node's first task attaches and released when it
  runs no more. **`.1` is reserved and handed to nobody**, so an operator reading
  `10.100.0.1` in a subnet is never looking at one arbitrary node's address. An
  operator-requested `IpamConfig.gateway` is honoured the only way it still means
  anything on an overlay: the address is reserved and given to no node and no
  task. `#[serde(default)]` keeps snapshots written under the old single-gateway
  field loadable. `satl-overlay`'s `DnsServer` took the bind list as a parameter
  all along (`NetworkScope::Fixed` vs `by_source`), so only the allocation moved;
- Docker reports a single gateway per network in `network inspect`. SatL reports
  **this node's** address instead, which is an intentional deviation and is
  recorded in `docs/api-compat.md` (entry 61) — including that a node running no
  task on the network reports no `Gateway` at all;
- the responder binds `<this node's gateway for this network>:53` and nothing
  else. One socket per (node, network), created and destroyed with the network's
  presence on that node;
- do not remove a network's gateway address while tasks are attached (silent
  black hole above); tear the endpoints down first.

---

## 9. Things that were surprising

1. **`ifconfig` reports success and `UP` for a vxlan interface the driver
   refused to initialize.** `RUNNING` in the flag word plus
   `/var/log/messages` are the only truth. Two distinct misconfigurations
   (missing remote, duplicate VNI) present identically.
2. **The duplicate-VNI check runs on `up`, not on `create`** — the socket does
   not exist until then.
3. **A static FDB entry installs fine on a dead interface**, so it is not a
   health check.
4. **Clone units are never recycled and the sysctl tree is keyed by unit, with no
   unit → name mapping.**
5. **`ifconfig <bridge> addm <member> up` brings up the bridge, not the member**,
   and a member that is not `UP` forwards nothing while still showing `RUNNING`.
6. **A wrong (too-large) overlay MTU does not hang between FreeBSD nodes.** The
   outer header has DF clear, so it fragments and merely halves throughput —
   which is worse, because it passes every test. CLAUDE.md's description
   ("small packets pass, big ones hang") applies only when the path also drops
   fragments; that gotcha has been amended.
7. **A receive-side MTU is not enforced.** A node with a 1400-byte underlay MTU
   accepts 1500-byte frames without counting an error.
8. **The OVH private network does carry multicast**, so the unicast-plus-FDB
   design is a portability and reconcilability choice, not a workaround.
9. **`ifconfig` cannot program a static VXLAN FDB entry at all**, although the
   kernel has supported it since the driver was written. This is the only ioctl
   `satl-overlay` has to issue by hand.
10. **`arp -s` needs the target address to be on-link** in the stack it is being
    installed in — and when it is not, it warns `cannot locate` on stderr and
    **exits 0** anyway.
11. **The overlay's throughput penalty is not measurable on this link.** Run to
    run variance (33–66 MB/s in correct configurations) swamps it, and what moves
    the number is packet loss in the hypervisor's virtual switch (0.4–2 %), not
    encapsulation. Every throughput claim about this overlay needs a
    bare-underlay control transfer in the same run or it is noise.
12. **A too-large overlay MTU is not visible in a throughput measurement either**,
    for the same reason. Only the fragmentation counters show it.

Found later, while implementing against this document (see the corrections table
at the top):

13. **`VXLAN_CMD_FTABLE_ENTRY_ADD` on a MAC already in the table is `EEXIST`**,
    whatever the VTEP, and the stored entry is untouched — so moving an endpoint
    is remove-then-add, not add.
14. **`net.link.vxlan.N.ftable.dump` truncates at one page** — 81 IPv4 entries —
    and the truncated output is perfectly well-formed, so nothing says so.
15. **`vxlanmaxaddr` cannot be raised above 2000**, a create-time value above it
    is silently ignored, and the limit gates only the *learning* path: static
    entries are unbounded (2500 installed on an interface reporting `max 2000`)
    and `ftable_nospace` can never move with `-vxlanlearn`.
16. **An OCI container image has no `arp(8)`**, and `route(8)` cannot install a
    link-layer entry (no `RTF_LLDATA`), so neither `jexec arp -s` nor `route -j`
    can program a task's ARP table.
17. **`Oerrs` counts nothing for the first `net.link.ether.inet.maxtries` (5)
    frames sent to an on-link blackhole** — they land in `Opkts` as successful
    transmits.
18. **A bridge member's MTU cannot be set at all**, not even to the value it
    already holds: `sys/net/if.c` returns `EOPNOTSUPP` for any member before it
    looks at the value. Only the bridge may change it, and the *first* `addm`
    overwrites the bridge's own MTU with that member's.

---

## 10. Encrypting the data plane: ESP over VXLAN (M6, `--opt encrypted`)

The companion experiment to this document is `hack/experiments/esp/` (with its
own captures); every number below is measured there and cited to it. This
section is what SatL implements, and the four plan assumptions the measurement
overturned.

**The wire format.** An encrypted overlay network wraps its VXLAN datagrams in
ESP **transport mode** with `aes-gcm-16` (160-bit key material: 128-bit AES +
32-bit salt, RFC 4106), programmed with `setkey`(8) — `/sbin/setkey` here.
State is per ordered pair of underlay addresses: one outbound SP
`<me>[any] <peer>[<port>] udp -P out ipsec esp/transport/<me>-<peer>/require`
per peer, one outbound SA for the ring's primary key, one inbound SA for every
key in the ring. SPIs are derived, never random — FNV-1a/32 over
`local || tag || remote`, exactly libnetwork's `buildSPI`, so both ends compute
the same value for the same key.

**Per-network VTEP ports, 4790..=4999.** An encrypted network's VTEPs bind an
allocator-assigned port from `OVERLAY_VXLAN_PORT_RANGE` instead of 4789
(`Network.vxlan_port`). Two measured facts force this: the FreeBSD SPD cannot
match on the VNI (it sits inside the UDP payload), and it cannot match the
outer **source** port either — `if_vxlan` picks it as a per-flow hash (default
range 10000-65535), so a `[4790]` source selector never matches unless the port
is pinned with `vxlanportrange` (esp README Q2), and pinning defeats the
cleartext guard (§7 G5 of that README, and below). With no per-network
selector available in one SPD, the port is what keeps two encrypted networks'
keyrings apart; the source selector is `[any]`, which also preserves the
source-port entropy an underlay's ECMP wants.

**MTU: 1416, not 1450.** ESP/aes-gcm-16 transport mode expands a datagram by
**34 bytes** (SPI+seq 8 + IV 8 + pad-len/next 2 + ICV 16) plus 0-3 bytes of
4-byte alignment padding — measured by a ping sweep against the outer ESP
datagram length (esp README Q4). The total per-packet overhead vs the inner IP
packet is **84 bytes** (50 VXLAN, inner Ethernet header included, + 34 ESP), so
the encrypted overlay MTU is underlay − 84 = **1416** on the 1500 underlay;
inner IP 1417 already fragments. It is set in the same two places as the
cleartext 1450 (§5): the bridge and each in-jail epair `b` end. Same trap as
§1, one notch deeper: the outer DF is clear, so a forgotten −34 *fragments*
silently — every ping still "succeeds" — and only the fragmentation counters
say so.

**The keyring and its rotation.** Keys live on the `Network` object
(`Network.keys`), so they are encrypted at rest with the rest of the raft store
and reach participant nodes inside their dispatcher network assignments — no
gossip. The leader's keyring loop rotates every 12 h in three phases with a
60 s settle between them: append the new key (accepted on reception
everywhere), promote it to primary, prune back to primary + previous. The
FreeBSD-specific subtlety, measured in esp README Q6: the kernel emits with
the **first-added** matching SA, and there is no way to select among equal SAs
for outbound use other than deletion — so "promote" is inert on the wire until
each node deletes the old outbound SA, and the node reconciler applies every
add before any delete for exactly that reason (the order *is* the rotation
protocol). Measured cost of a full rotation: 3 of 250 pings lost, one gap.

**The cleartext guard is pf, not the SPD.** The plan assumed an inbound
`require` SP would drop cleartext VXLAN. It does not on 15.1 (esp README Q3):
inbound policies are checked against "packets handled by IPsec", so an
unprotected packet is delivered normally — decapsulated and answered. Only the
outbound direction fails closed. The guard that works is the `satl/guard` pf
anchor (one per host, beside `satl/nat` and `satl/rdr`):

```
block in log quick on <underlay> proto udp from any to any port 4790:4999
pass in quick on enc0 proto udp from any to any port 4790:4999 no state
```

plus `net.enc.in.ipsec_filter_mask=2` and `enc0` up, so decapsulated packets
are presented to pf on `enc0` *after* the ESP header is stripped (if_enc(4);
the default mask of 1 presents them as ESP, which a UDP rule cannot match).
Two requirements are load-bearing, each with its own measurement: `no state`
on the pass rule, because pf consults the state table before the ruleset and a
stateful pass creates the very floating state that lets same-tuple cleartext
bypass the block (esp README §7 G4); and the unpinned source port from above,
because with pinned ports the pass-all main ruleset's own reply state
reverse-matches inbound cleartext and no rule of ours can stop it (G5). The
sysctl is node-wide, set once and deliberately never restored.

**The tag-collision edge.** SPIs derive from `local || tag || remote`, so two
encrypted networks whose leader rolled the **same random tag** produce the
same SA tuple on a node pair they share — a ~2^-32 chance per pair, the same
shape libnetwork has by deriving SPIs the same way. The failure mode is one
network blackholing on a node that shares only the other (the colliding SA's
lifetime follows the wrong keyring's); the remedy is to delete and recreate
the affected network, which re-rolls its tag.

---

## 11. Capture index

All under `hack/experiments/vxlan/captures/`, produced by the identically
numbered script.

| Capture | Contents |
|---|---|
| `00-underlay-mtu.txt` | DF ping sweeps at 1500 and with the NIC raised; `SIOCSIFMTU` ceiling; virtio attach lines; underlay is one L2 segment |
| `10-idioms.txt` | driver load; unicast create; MTU arithmetic; clone-unit and rename gotchas; the mandatory-remote proof; static FDB via ioctl + dump + flap/flush/ENOENT; per-peer-interface dead end; bridge MTU propagation; explicit MACs; bridge static entries; static ARP in a VNET jail; many VNIs on one socket; multicast works |
| `20-two-node-overlay.txt` | full two-node bring-up scripts; pre-programming connectivity (the two-node crutch); FDB+ARP programming; ping; `tcpdump` of the outer packets; DF ping at 1422/1423; bare-underlay control transfer; 64 MiB overlay transfer with host and jail counters before/after |
| `30-mtu-failure.txt` | the four MTU configurations with per-configuration fragmentation deltas, throughputs and the hang |
| `40-three-node-mesh.txt` | blackhole default remote; three-node mesh; all six directions; large transfer between the non-default-remote pair; single-FDB-entry deletion and its two-directional failure; what the default remote is for |
| `50-dns-placement.txt` | gateway-address listener with source-address proof; two listeners on port 53; specific vs wildcard bind; pf-redirect prerequisites; the duplicate-gateway ARP hazard with both responders' logs |
| `99-verify-clean.txt` | final nuke, per-node audit, restored sysctls and MTUs, cluster health |

Helpers: `vxlan-ftable.c` (the static-FDB ioctl, reference for the Rust
implementation) and `udp-echo.c` (a one-socket stand-in for the DNS responder).
`common.sh` holds `overlay_up()` and `overlay_peer()` — the two command
sequences an implementation has to reproduce — and the cleanup/audit machinery.

**The corrections listed at the top of this document are not in these captures.**
They were measured afterwards, on the dev host, with throwaway interfaces and
`vxlan-ftable`; the transcripts are in the commit that made the corrections rather
than under `captures/`, and the reproducible form of each one is the command block
printed beside it in §2 to §4. The behaviours they cover are also asserted by the
root integration tests in `crates/satl-overlay/tests/overlay_dataplane.rs`
(`sudo cargo test -p satl-overlay -- --ignored --test-threads=1`), which is the
version that will keep failing if a future FreeBSD changes its mind.
