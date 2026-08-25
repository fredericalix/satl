# lo0rdr — reaching a published port from the publishing host (api-compat #35)

2026-08-25, alpha (FreeBSD 15.1-RELEASE-p2), satld 0.2.0 (9b32038), pf with the
stock dev-host `/etc/pf.conf` (three `satl/*` anchor lines + `pass all`, no
`set skip`). Test workload: the long-running `web` container
(`satl-test/freebsd-nginx`, task `2qw3gxb4uklp`), published `8080:80/tcp`,
task IP `10.88.0.5`, bridge `satl0` = `10.88.0.1/24`, host `51.38.30.173` on
`ice0`. All rule edits were made by hand in the `satl/*` anchors and reverted
at the end (`17-restore.txt`); satld performed no anchor reload during the
window (verified in `/var/log/messages`, last reload 14:26, tests 15:40-15:55).

## Question

`#35` says a published port is unreachable from the publishing host through
`localhost` because "pf applies rdr to packets entering an interface, never to
locally generated traffic". Is that actually the mechanism, and is there a
pf-only fix (no userland proxy)?

## What was measured, in order

Numbered files are the raw captures.

1. **Baseline** (`01`, `02`): direct `10.88.0.5:80` → 200;
   `127.0.0.1:8080` and `51.38.30.173:8080` from the host → timeout.
   Nothing reaches the epair.
2. **The #35 explanation is wrong about the mechanism.** The generated
   interface-less `rdr pass` rule *is* consulted on lo0 — locally generated
   traffic to a local address re-enters through lo0 and pf runs there. The
   state table showed the translation
   (`10.88.0.5:80 (127.0.0.1:8080) <- 127.0.0.1:...`); what killed the packet
   was the next step: the kernel refuses to *forward* a packet whose source is
   `127.0.0.1` (`packets not forwardable` / `bad address in header` counters
   incremented per SYN). The redirect happens; the loopback *source* is what
   dies.
3. **Source-NAT on the reply-blind hooks fails structurally** (`03`-`09`).
   Every two-state variant (old-style `nat on satl0`, `nat on lo0` to the
   bridge address, FreeBSD 15's `rdr-to`/`nat-to` in one filter rule) fails
   the same way: the SYN reaches nginx correctly translated, nginx answers,
   and the SYN-ACK arriving on satl0 is delivered to a *local* address after
   at most one un-translation, so the second translation is never undone and
   the host stack RSTs (`05-epair.txt` shows the full SYN / SYN-ACK / RST).
   A reply must traverse one pf hook per state to be fully un-translated, and
   delivery-to-local gives it only one. Also measured on the way: FreeBSD
   15.1 pfctl *parses* `rdr-to X nat-to Y` on one rule (`06`), but applies
   `nat-to` only outbound and `rdr-to` only inbound — two states, not the
   OpenBSD single-state semantics (`08`, `09`).
4. **The fix: NAT the source to a non-local dummy routed back through lo0**
   (`10`-`12`). `nat on lo0 ... -> 198.18.0.1` plus a host route
   `198.18.0.1 -> 127.0.0.1` makes the reply *non-local*, so it is forwarded
   back out lo0 and re-enters it, giving both states their reverse traversal
   in order: un-rdr at out-lo0, un-nat at in-lo0, then delivery to the curl
   socket. The dummy must be **outside the container subnet**: `10.88.0.254`
   failed because the container ARPed for it on its own link and nobody
   answered (`11-epair.txt`: SYNs arrive, zero replies). With `198.18.0.1`
   (RFC 2544 benchmark block): **HTTP 200 on `127.0.0.1:8080` and on
   `51.38.30.173:8080` from the host** (`12`).
5. **The rdr rule must carry `on lo0`** (`13`-`16`). With only the generated
   interface-less rule, the NATed packet re-entering lo0 is *not* redirected
   (delivered to `127.0.0.1:8080`, instant RST, `14-lo0.txt`) even though the
   same rule matched the un-NATed packet in step 2. Adding the identical rule
   with `on lo0` fixes it (`15`), and that rule alone suffices (`16`): 200 on
   every attempt, table + `round-robin` included. First-match order in `15`
   proves the interface-less rule really does not match this packet; the pf
   internals of *why* an existing nat state changes rdr matching on the
   re-entry pass were not chased further — the behavior is pinned by A/B.

## The working recipe (v6/v7, all measured)

```
# satl/nat — one per published (port, proto)
nat on lo0 inet proto tcp from any to any port 8080 -> 198.18.0.1
# satl/rdr — the existing generated rule, duplicated with an interface
rdr pass on lo0 inet proto tcp from any to any port 8080 -> <satl_p8080_tcp_80> port 80 round-robin
# once per host
route add 198.18.0.1 127.0.0.1
```

Prerequisites: pf enabled without `set skip on lo0` (worth a startup warning,
like the forwarding sysctl), `net.inet.ip.forwarding=1` (already required).
External publishing was live throughout (internet scanners kept completing
sessions against `51.38.30.173:8080` mid-experiment) and is untouched by all
three additions: they only match traffic on lo0.

## Addendum, 2026-08-25 later: the mesh-relay case, measured on the cluster

With the recipe implemented in satld and deployed on fbsd{1,2,3}: a node
running a task of the service answers on its own localhost (200), and the
external ingress relay is unchanged — but a **mesh-relay node** (no local
task) timed out on localhost while carrying all the right rules. The full
translation chain was verified correct (states + tcpdump: lo0 nat ->
198.18.0.1, rdr -> overlay task IP, mesh SNAT -> node gateway, SYN leaving
`satl-br4096` well-formed); the SYN then arrived on the remote node with
`cksum 0xbc65 (incorrect)` and the container's stack dropped it silently.

Mechanism: a packet born on loopback never carries a real TCP checksum — the
stack marks it "already verified" in mbuf flags instead — and vxlan
encapsulation to a remote node loses those flags, so the wire carries the
unfinished pseudo-header value. The local-replica path only worked because
epair propagates mbuf flags in software. Fix, measured on fbsd2:
`ifconfig lo0 -txcsum` -> immediate 3/3 HTTP 200 on the relay node
(IPv4 TXCSUM only; TXCSUM_IPV6 stayed on throughout the passing test). The
sweep owns that flag now, same gating as the route.

## Open questions before this becomes code

- **UDP**: not tested (nginx workload); same shape expected, unverified.
- **Dummy address choice**: `198.18.0.0/15` is reserved for benchmarking and
  never routable, but it must be documented, kept out of any future IPAM
  range, and the route owned/reconciled by satld (it survives nothing).
- **Ingress/mesh (M6d)**: table entries pointing at overlay IPs of remote
  nodes mean the reflected reply comes back over vxlan; untested.
- **Hairpin from inside a container** (container curls the host's published
  port): different path (enters on satl0, not lo0), out of scope here.
- **`pfctl -sn` does not dump table declarations** — restoring an anchor from
  a rules dump silently drops `table ... persist`; bit me in `13`, worth
  remembering for any future anchor surgery.
