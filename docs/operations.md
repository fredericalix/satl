# SatL operations guide

Covers what an operator needs to run SatL. Grows with each milestone; cluster
operations (init/join, CA) arrive in M2, backup and restore in M5 ("Backup and
restore", below — read it before you deploy a cluster with one manager).

## Requirements

- FreeBSD 15.1 (amd64), root on ZFS or at least a ZFS pool available.
- Rust toolchain only for building from source (`cargo`, stable).

## Install (M0)

```sh
# 1. Storage: SatL refuses to start without its ZFS root dataset.
zfs create -o mountpoint=/var/db/satl zroot/satl

# 2. Networking: the host routes container traffic and pf translates it.
sysrc gateway_enable=YES              # IP forwarding, required for container egress
sysctl net.inet.ip.forwarding=1       # take effect now, without a reboot
#    Declare SatL's anchors in /etc/pf.conf (translation anchors first):
#      nat-anchor "satl/*"
#      rdr-anchor "satl/*"
#      anchor     "satl/*"
#    A host with no firewall policy of its own adds a single `pass all` after them.
sysrc pf_enable=YES
service pf start

# 3. Build and install binaries + rc.d script + sample config
make install          # installs satl, satld, /usr/local/etc/rc.d/satld

# 4. Enable and start the daemon
sysrc satld_enable=YES
service satld start
```

### Distributing SatL as a package

`make package` writes `dist/satl-<version>.pkg`, built with `pkg create`
from a staging tree that mirrors `make install` — no ports tree needed.
Alongside it goes `dist/CHECKSUM.SHA512`, in sha512sum(1) format and naming
only the package that run built (it is rewritten on every `make package`).
Install it on any FreeBSD 15 amd64 host with:

```sh
sha512sum -c CHECKSUM.SHA512    # both files in the same directory
pkg add ./satl-0.1.0.pkg
```

`pkg add` needs no configured repository. If one is configured (the
default), the declared `ocijail` dependency is resolved from it
automatically; on an offline host, hand it the dependency's `.pkg` alongside
SatL's. The post-install message recalls the host prerequisites (ZFS root
dataset, pf anchors, `kern.racct.enable=1`). The package's ABI is stamped at
build time from `pkg config ABI` — build on the FreeBSD major you deploy.

See `docs/networking.md` for the anchor contract and the `pf_mode` setting that decides
whether `satld` loads rules, only syntax-checks them, or stays out of pf entirely.

`satld` creates the child datasets it needs under the root on first start
(`raft`, `images`, `layers`, `containers`, `volumes`) and self-initializes a
single-node cluster (no `swarm init` needed — see `docs/api-compat.md`).

Verify:

```sh
satl version                                   # SatL client + engine
docker -H unix:///var/run/satl.sock version    # any Docker CLI works
service satld status
```

## Configuration

`/usr/local/etc/satl/satld.toml` — every key optional; defaults shown in the
installed `satld.toml.sample`:

| Key | Default | Meaning |
|---|---|---|
| `socket_path` | `/var/run/satl.sock` | Docker REST API unix socket (mode 0660) |
| `state_dir` | `/var/db/satl` | Node state directory (should be the ZFS root dataset mountpoint) |
| `zfs_root` | `zroot/satl` | Root ZFS dataset; startup fails if absent |
| `node_name` | hostname | Node name (also the Raft peer name) |
| `socket_group` | `wheel` | Intended socket group (a dedicated `satl` group comes with packaging) |
| `pf_mode` | `check` | `enforce` loads the `satl/*` anchors (needed for published ports), `check` only syntax-checks them, `disabled` stays out of pf entirely — see `docs/networking.md` |
| `network_name` | `satl` | Node-local bridge network; also names the bridge (`satl0`) and the ifconfig group SatL sweeps at startup. **Two daemons on one host must use different names**, or each one's reconciliation destroys the other's interfaces. Max 14 characters |
| `network_pool` | `10.88.0.0/16` | Pool the per-network /24s are carved from; change it if it collides with your underlay |

Published ports require `pf_mode = "enforce"` **and** pf enabled on the host. With the
default `check`, ports are recorded and shown by `satl ps` but no redirect is installed.

rc.conf knobs (see the header of `/usr/local/etc/rc.d/satld`): `satld_enable`,
`satld_config`, `satld_flags` (e.g. `--log-format json`), `satld_env` (e.g.
`RUST_LOG=satld=debug`). The daemon runs under daemon(8) and writes its log to syslog
under the tag `satld`, which lands in `/var/log/messages` and `/var/log/daemon.log` with
the stock `/etc/syslog.conf`.

### One event, one line — do not remove `--log-target syslog`

The rc.d service starts the daemon with `--log-target syslog`, and that flag is a
correctness requirement rather than a preference. **Taking it out silently corrupts the
log**, so if you edit `command_args` in `/usr/local/etc/rc.d/satld`, keep it.

With the flag, `satld` hands each event to syslogd itself as its own datagram, so one
event is one line. Without it, the log travels the way any supervised program's output
does — the daemon writes lines to a pipe and `daemon(8) -S` forwards them — and that
path **merges events**: `daemon(8)` reads the pipe in chunks and passes a whole chunk to
`syslog(3)` as a single message, then syslogd rewrites the newlines inside it as
*spaces*. Two events written microseconds apart by two of the daemon's threads therefore
arrive joined onto one line.

Measured on FreeBSD 15.1, on this daemon's own log: **281 of 7252 lines (3.9%) carried
more than one event**, up to eleven of them, and under `--log-format json` about 3% of
lines were two objects on one line — not JSON, so a consumer doing `json.loads` per line
fails on them. A synthetic burst of 400 lines through `daemon -S` was worse: 138 lines
carrying 174 records, up to 19 records on one line, and **more than half the records lost
outright**, because merging inflates each datagram until it overruns syslogd's 16 KiB
receive buffer. The same 400 lines through `logger(1)`, which calls `syslog(3)` once per
line, arrived complete. `daemon(8)` has no flag that asks for per-line forwarding.

What to know operationally:

- **Two timestamps on one line, or two `{`, is this bug** (or something bypassing the
  log path). The daemon's own events are one per line by construction.
- `-S` is still passed to `daemon(8)` on purpose: `satld`'s log no longer travels that
  way, but a panic message written to stderr does, and it should still be captured.
  A multi-line panic backtrace can still merge — that path is the fallback, not the log.
- If syslogd is unreachable or wedged, the daemon prints one
  `satld: cannot write the log to syslog …` note to stderr and falls back to writing
  lines there, where `daemon(8) -S` picks them up. That fallback can merge lines; it
  never drops them.
- A saturated syslogd applies backpressure to the logging thread (the send is retried
  for up to 2 s) rather than dropping events. A wedged syslogd past that budget costs a
  line's ordering, not the line.
- Every event carries one syslog priority, `daemon.notice`, regardless of its tracing
  level — the same priority `daemon(8) -S` used — so `RUST_LOG=satld=debug` output still
  lands in `/var/log/messages`. Mapping tracing levels onto syslog severities would move
  `INFO` and `DEBUG` lines out of that file with the stock `syslog.conf`.

In the foreground the default is `--log-target stdout`, so `satld --log-format json | jq`
works and colour is enabled only when stdout is really a terminal.

### The log is plain ASCII, on purpose

Everything `satld` writes reaches `/var/log/messages` through syslogd, and syslogd is
not 8-bit clean: it rewrites bytes in the `0x80`–`0x9f` range as literal `M-^X` text.
A UTF-8 punctuation character is two or three bytes, usually including one in that
range, so it arrives mangled and **unrecoverable** — an em dash logged as `—` lands as
`M-^@M-^T` (measured on this platform with `logger`, then read back with `od -c`).

So SatL keeps operator-facing messages ASCII-only, the same way it keeps colour out of
non-terminal output. Two things to know:

- **`M-^` sequences in a log line are a bug**, not a display problem: some message
  escaped the rule. Report it. (Characters above `0x9f`, such as `§` or `é`, do survive
  in the file — if you see those as `M-BM-'`, that is your pager, not the log: `cat -v`
  and non-UTF-8 tools render intact bytes that way.)
- **Grep for words, not symbols.** Every identifier a diagnosis needs — `task_id`,
  `node_id`, `jail_id`, interface names, addresses — is ASCII, so it is greppable
  exactly as printed.
- **Use `grep -a` on the log file.** One non-ASCII byte anywhere in
  `/var/log/messages` — from any program on the host, not necessarily `satld` — makes
  `grep` treat the whole file as binary and print *nothing*, with exit status 1 and no
  explanation. That looks exactly like "the daemon logged nothing", which is the worst
  possible way to be misled while diagnosing. `grep -a` reads it as text regardless;
  `file /var/log/messages` reporting anything other than "ASCII text" is the tell.

### The span chain is the parent chain

Between the level and the module, every line carries the spans it happened inside,
outermost first:

```
INFO agent.session{node_id=1r5f...}:task_step{step="prepare" task_id=1kql... service=pub}:
     jail_create{jail_id=1kql... platform=Freebsd}: satl_runtime::runtime: jail created
```

That chain is what makes the log greppable by identity rather than by time: the
`node_id` on the outer span applies to everything nested under it, so
`grep -a 'task_id=1kql' /var/log/messages` returns one task's whole life, in the
context of the session and the node that ran it.

The chain is only worth that if it is true, so two shapes are bugs, not noise:

- **A background loop's span nested under anything.** `dispatcher.sweep`,
  `dispatcher.status` and `agent.session` are the roots of their own tasks and always
  appear first. A line like `dispatcher.sweep{...}:agent.session{...}:` means one loop's
  span leaked onto the runtime thread and was picked up by an unrelated task -- so the
  events under it are attributed to a subsystem that did not produce them, and to
  another node's `manager_id` at that.
- **The same span twice in one chain**, or a chain that keeps growing across restarts.
  Same cause.

The cause is always the same mistake: entering a span with a guard
(`let _g = span.enter()`) in an `async fn` and holding it across an `.await`. A parked
future drops nothing, so the span stays entered on the worker thread. Attaching the span
to the future with `tracing::Instrument` instead enters and exits it around each poll.
`crates/satl-dispatcher/tests/span_scoping.rs` asserts this on the real loops.

## On-disk state (M0)

```
/var/db/satl/                 zroot/satl (dataset)
├── raft/                     zroot/satl/raft — cluster state (managers)
│   ├── dek                   at-rest encryption key, 0600 — see below
│   ├── log.redb              raft log (entries encrypted)
│   ├── snapshot              raft snapshot (encrypted), appears after ~10k writes
│   ├── node-id               this node's cluster identity (25-char id)
│   └── raft-id               this node's raft member id
├── images/ layers/ containers/ volumes/   (used from M1 on)
```

- **Crash recovery**: cluster state fully recovers from `raft/` after a crash
  (`kill -9` included) — verified by the M0 acceptance test. Node identity is
  stable across restarts.
- **The `dek` file is critical**: it encrypts the raft log and snapshots at
  rest, it is per-node, and a raft directory copied without it is unreadable —
  `satld` refuses to start rather than mint a new key over sealed data. Include
  it in any backup of `/var/db/satl/raft` and protect it like a private key.
  What a backup is worth, and the two ways back from a lost manager, are in
  "Backup and restore" below.
- Logs: `--log-format json` for machine-readable logs; `RUST_LOG` overrides
  the level (e.g. `RUST_LOG=satld=debug,satl_cluster=debug`).

### A container dataset that outlives its container for a minute

Removing a container does not always destroy its `containers/<task id>` dataset
immediately, and that is expected. A rootfs cannot be unmounted while the
container's jail is still `DYING`, and a jail whose container had an open TCP
connection when it was removed stays dying for 2 x `net.inet.tcp.msl` — 60 s with
the default MSL (measured; `docs/jail-teardown.md`). Nothing in `fstat`,
`procstat` or `mount` shows a holder: the reference belongs to the dying prison,
and only `jls -d -h name dying` sees it.

`satld` handles this by itself, in two stages, both visible in the log:

```sh
grep -a "has not finished dying"                 /var/log/messages  # waiting, normal
grep -a "deferring it to the periodic dataset"   /var/log/messages  # handed to the sweep
grep -a "periodic sweep destroyed a container"   /var/log/messages  # reclaimed
```

The removal waits up to 30 s (it runs on the assignment stream, so it may not
wait longer), then defers the dataset to a sweep that runs every 20 s and
destroys it as soon as the jail is gone. Expect the dataset to disappear within
roughly a minute and a half of `satl rm`, with no restart and no intervention.
Each deferral is one warn line carrying `task_id`, `dataset`, `waited_ms`,
`jail_state` and the failed `zfs` command line, and a dataset that stays busy
across several sweeps is reported once, not once per pass.

If a dataset is still there minutes later, check whether its prison ever died —
`jls -d -h name dying | grep <task id>` — and how many vnodes the mount still has
(`mount -v | grep <task id>`). A prison that never dies is a different problem
from this one.

## Backup and restore (M5)

**The recommendation, before the procedures: run three managers and recover a
lost one by rejoining it, not by restoring it.** Everything below was run on
the three-node test cluster, and the numbers are the reason:

| Recovery | Needs a backup | Measured, end to end |
|---|---|---|
| a manager's raft directory restored from a copy of *that* manager | yes | ~2 s of downtime, then 3-4 s to catch up (5 runs) |
| the same manager wiped and re-joined | **no** | **6 s** (leave 1 s, `node rm` 0 s, join 1 s, three managers reachable 4 s) |
| a one-manager cluster restored from a copy | yes | full recovery: services, secrets and the running container |
| a one-manager cluster with no copy | — | **nothing comes back** |

The arithmetic is the ordinary quorum arithmetic and it is what makes the
recommendation: three managers tolerate one loss, so a manager can be destroyed
and rebuilt with no downtime and no backup, and the cluster keeps committing
throughout. One manager tolerates none, and its raft directory is the only copy
of every service, secret, config and network in the cluster — which makes a
scheduled backup of that one directory the whole disaster-recovery plan.

**A rejoin is not a backup policy, though.** It covers one manager failing; it
covers nothing the day the majority goes. A cluster that has lost quorum cannot
admit a replacement, cannot be forced into a smaller membership, and cannot even
be stopped cleanly — so on a three-manager cluster the copy to schedule is the
raft directory of **at least two** of them. That is measured, in "When quorum is
gone" below, and it is the one place where a restore is not just an alternative
to a rejoin but the only way back.

Two managers are the worst of both: quorum is 2, so losing either one stops every
write *and* leaves the survivor in that unrecoverable-without-a-backup state.
Run one and back it up, or run three.

### What has to be in the copy

Everything in `<state_dir>/raft` — `log.redb`, `node-id`, `raft-id` **and
`dek`**:

```sh
ls -l /var/db/satl/raft
-rw-------  1 root wheel       32  dek         # the key. 0600, never in a log, never shared
-rw-r--r--  1 root wheel 18878464  log.redb    # the raft log, sealed with that key
-rw-r--r--  1 root wheel       26  node-id     # this node's cluster identity
-rw-r--r--  1 root wheel       20  raft-id     # this node's raft member id
```

- `dek` is generated per node from OS randomness. A record sealed under one
  manager's key does not open under another's (`satl-cluster`'s crypto tests
  assert exactly that), so **another manager's backup is not a substitute** and
  the copy is only useful to the node it came from.
- `node-id` and `raft-id` are why a restored node comes back *as itself* rather
  than as a new member: they are plain files, they travel in the copy, and the
  daemon reads them instead of minting new ones.
- `snapshot` appears too, once the log has passed ~10 000 entries; it is sealed
  with the same key. Copy it if it is there — it is where most of the state is
  after a compaction.
- `log.redb` is **sparse and only grows**. It was 19 MB on a manager holding a
  store of ~230 small objects, and 1.1 GB after a synthetic burst of 10 000
  writes of 64 KiB objects; a compaction does not shrink the file. Size a backup
  target for the file, not for the state.

The certificates in `<state_dir>/certs` are **not** part of this copy, and that
is worth knowing rather than assuming: the raft state contains the cluster's CA,
so a node whose raft directory is intact re-issues its own certificate. Verified
by deleting `<state_dir>/certs` outright on a single-node cluster and starting
the daemon — same node id, service still running, three log lines:

```
INFO satld::cluster: no node certificate found; initializing this node's identity
INFO satl_cluster::node: raft state found, resuming existing cluster raft_id=6418088851891314064
INFO satld::cluster: re-issued this node's certificate from the cluster CA already in the store
```

The two directories are not interchangeable in the other direction: certificates
without raft state are what the refusal in "the single-node cluster" below is
about.

### Taking the copy

Three ways were tried on a live manager. They are not equally sound, and the
recommendation is not the one that is most convenient.

**1. Stop the daemon, copy, start it (unambiguous).** On a three-manager
cluster this costs nothing: the other two keep committing, and the stop took
0.05 s on a healthy manager.

```sh
service satld stop
tar -C /var/db/satl/raft -cf /var/backups/satl-raft-$(date +%F).tar .
service satld start
```

**2. Snapshot the dataset (recommended for a manager you will not stop).**
`<state_dir>/raft` is its own ZFS dataset, so a snapshot is atomic and
crash-consistent — which is precisely the image `redb` is built to recover
from, and recovery from a `kill -9` is what the M0 acceptance test already
verifies:

```sh
zfs snapshot zroot/satl/raft@backup
tar -C /var/db/satl/raft/.zfs/snapshot/backup -cf /var/backups/satl-raft.tar .
zfs destroy zroot/satl/raft@backup
```

The snapshot directory is readable whether or not `snapdir` is visible, and the
files in it carry their modes, `dek` included (`tar` keeps the 0600).

**3. `cp -Rp` of a live raft directory — it worked, and it is still the one to
avoid.** Three copies taken from a running manager while the cluster committed
about 35 store writes a second were each restored onto that node, and all three
came back and caught up. That is 3 for 3, and it is *not* a guarantee: `cp`
reads a file that is being written, so the result is a smear across the copy
window rather than a point in time, and nothing in `redb`'s design promises a
smeared file is consistent. A snapshot removes the question for free, so there
is no reason to rely on the luck. (Nothing here detected a bad copy either: a
deliberately torn file — one half read six seconds after the other — opened and
ran anyway, so "it started" is not evidence that a copy was sound.)

**A stale copy is fine, on a multi-manager cluster.** The copy only has to give
raft a starting point; the leader replays the rest. Measured: copies a minute
old, and copies taken before hundreds of writes, all converged 3-4 s after the
daemon came up. On a **single-manager** cluster the opposite holds — everything
committed after the copy is gone, so the backup interval *is* the amount of work
you are prepared to lose.

### Restoring onto the same node

The daemon must be stopped first (two raft instances must never share one raft
directory), and the directory is a dataset mountpoint, so empty it rather than
removing it:

```sh
service satld stop
rm -rf /var/db/satl/raft/*                       # empty the dataset, keep the dataset
tar -C /var/db/satl/raft -xf /var/backups/satl-raft.tar
service satld start
```

Nothing has to be told to the cluster, and nothing has to be passed to the
daemon: no `swarm init`, no `--advertise-addr` (which is refused anyway —
`docs/api-compat.md` #42, first boot *is* the init). What the log says, and this
is the sequence that means the restore took:

```
INFO satl_cluster::node: raft storage opened node_id=23hfzohfbk3d80bbf5z8a6hkg
     raft_id=2173359823421821951 raft_dir=/var/db/satl/raft
INFO satl_cluster::node: raft state found, resuming existing cluster raft_id=2173359823421821951
INFO satld::cluster: cluster state ready node_id=23hfzohfbk3d80bbf5z8a6hkg ... joined=false
```

- **`raft state found, resuming existing cluster` is the line to look for.** Its
  opposite, `pristine node, initializing single-node cluster`, means the daemon
  found nothing to resume; on a node that was in a cluster that line is a
  restore that did not happen.
- `node_id` and `raft_id` must be the values the node had before. They came out
  of the copy; if they changed, the copy was not this node's.
- Measured over five restore-and-restart cycles: caught up 3-4 s after start,
  every time, including entries written while the node was down.
- **The containers on that node keep running throughout.** They are jails; the
  daemon stopping does not stop them, and the startup reconciliation re-adopts
  them. A restore is not an outage for the workload on that node.

### Restoring without the `dek`

The one mistake this section exists to prevent. `satld` refuses to start, names
the file, and does not create a new key over sealed data:

```
Error: cluster bring-up failed
Caused by: the raft state in /var/db/satl/raft is sealed but its key file is
  missing: /var/db/satl/raft/dek. log.redb cannot be read without it, and satld
  will not create a new key over sealed data. Restore the key file from the same
  backup as the rest of /var/db/satl/raft (it is per-node and never shared:
  another manager's key does not open this one's state). If this node's cluster
  state is unrecoverable, empty /var/db/satl/raft instead and re-join the node
```

Put the file back and the same start succeeds, with the full state (verified:
identical node id, 224 configs, three node objects). The refusal is deliberate:
a fresh key over a sealed log would make the state unreadable for good, and the
key is usually still in the backup.

Two related refusals, same reason:

- a `dek` that is group- or world-readable is refused with `chmod 600` in the
  message — restoring with a careless `umask` is the way that happens;
- a `dek` of the wrong length is refused as corrupt rather than used.
### Losing a manager entirely: rejoin, do not restore

On a cluster with other managers this is the ordinary path and it needs no
backup at all. Three steps, and the whole thing was **6 s** end to end:

```sh
# on the node that lost its state (its daemon must be able to start; see below)
satl swarm leave --force

# on any surviving manager: the old member is still in the membership and in
# `satl node ls`, and it has to go before its replacement arrives
satl node rm --force <old node id>
satl swarm join-token -q manager          # print a fresh token

# back on the node
satl swarm join --token <token> <any manager>:2377
```

What to expect, all of it observed:

- **the node comes back under a new node id.** The identity is issued by the
  cluster it joins (`docs/api-compat.md` #86), so its old id is gone for good —
  which is why `satl node rm --force` on the old one is part of the procedure
  and not an optional tidy-up. Anything that referred to it by id (a
  `node.labels` constraint pinned to that id, dashboards) has to be repointed.
- **its containers are not its own any more.** Whatever it was running was
  rescheduled while it was `Down` (that is the eviction the `node_kill` scenario
  covers), and its reconciliation pass reaps what is left on it when it comes
  back.
- `satl swarm leave --force` is not "make this node idle": the node immediately
  forms a **fresh single-node cluster of its own** (`docs/api-compat.md` #86) and
  `satl node ls` on it lists one node, itself, as Leader. That is expected — it
  is a cluster of one until the join lands.
- **if the daemon cannot start** (it lost its raft directory, so it refuses —
  see the single-node section), `satl swarm leave --force` is not available.
  Discard the identity by hand instead, which is what the refusal tells you:
  `rm -rf <state_dir>/certs` and empty `<state_dir>/raft`, start `satld` (it
  forms its own single-node cluster), then `satl swarm join`.
- **check `MANAGER STATUS` afterwards.** A join whose learner-to-voter step does
  not complete leaves the node a learner: `satl node ls` shows `Unknown` in that
  column and the leader logged
  `learner never acknowledged replication; it stays a learner and does not count
  towards quorum`. It is *not* a voting manager in that state, whatever the
  `Ready` in the STATUS column suggests. Rejoin it.

A restore is the right answer when the cluster still has quorum and you would
rather not lose the node's identity — and it is the *only* answer once quorum is
gone, which is the case the next section is about.

### When quorum is gone: the case where a backup is the only way back

A cluster commits writes only while a majority of its managers are up, and
losing that majority is the one situation where a restore beats a rejoin — and
where having no backup is unrecoverable. Measured on a three-manager cluster by
destroying two of them (state removed, daemons down) and restarting the third:

**With one of three left, nothing can be fixed from inside the cluster.**

- **writes hang.** They do not fail: `satl secret create` sat there until the
  20 s `timeout` killed it (exit 124). A proposal has no timeout by design (a
  timeout cannot retract an appended entry — architecture §6.2), so a write
  aimed at a quorum that will never form waits for ever. Nothing tells the
  operator why.
- **reads keep working and `satl node ls` lies.** It listed all three nodes
  `Ready` with the survivor as `Leader` — the store frozen at its last applied
  state, and a `current_leader` left over from the term before the restart. In
  this state that column is not evidence of anything.
- **a replacement manager cannot join.** The join needs a certificate, issuing
  one is a store write, and the store cannot commit:
  `NodeCA IssueNodeCertificate at 10.2.2.47:2378: ... "Timeout expired"`.
- **`satl swarm init --force-new-cluster` answers 501.** There is no way to
  shrink the membership to the survivor, which is exactly what Docker's flag
  exists for (`docs/api-compat.md` #137).
- **and `service satld stop` hangs** — 21 minutes, in the run that measured it,
  before it was killed ("A stop that does not finish", below). Use `pkill -9
  satld`: the raft directory is crash-safe, and this is the one state where a
  graceful stop is not available.

**Restoring a second manager brings it back, and that is the whole recovery.**
Node2's raft directory was restored from its own backup — the raft directory
*only*, no certificates — and its daemon started:

```
INFO satld::cluster: re-issued this node's certificate from the cluster CA already in the store
INFO satl_cluster::node: raft state found, resuming existing cluster raft_id=1971981655582681656
INFO satld::cluster: cluster state ready node_id=2gsc8z0qa8db2sk8c7cigvaqv
```

Two of three voters is a majority, so the cluster committed again immediately —
and the write that had been hanging landed: the retry answered `a secret named
q2_after already exists`, which is the pending proposal from before the restore
having gone through. `satl node ls` then showed node3 `Down`, correctly, and the
service that had lost a replica was being re-placed (`4/3` for a moment while
the old task was reaped).

So the arithmetic that decides a backup policy. Every row was run here except the
one marked *inferred*, which follows from the row above it by the same quorum
arithmetic and was not exercised:

| Managers | Lost | Recovery | Backup needed |
|---|---|---|---|
| 3 | 1 | rejoin the node (6 s) — or restore it, either works | none |
| 3 | 2 | restore **two** of the three raft directories: one is not a majority | 2 of 3 |
| 3 | 3 | restore two, then rejoin the third (*inferred*) | 2 of 3 |
| 1 | 1 | restore its raft directory | that one |
| any | quorum, with no backups | **none. The cluster cannot be recovered** | — |

That last row is the sharp edge of this whole section, and it is why the last
line of advice is the boring one: **if the cluster matters, run three managers
*and* copy the raft directory of at least two of them.** A rejoin covers the
ordinary single failure for free; only a backup covers the day two of them go at
once.

Two managers deserve their own warning, for the same arithmetic: quorum is 2, so
losing either one stops every write and leaves the survivor in the state
described above — unable to admit a replacement, unable to be stopped
gracefully. Two managers are strictly worse than one. Run one, or run three.

### The single-node cluster: the backup is the only way back

A one-manager cluster cannot re-sync from anywhere, and this is where the honest
limits are. All three cases were run.

**With a backup: full recovery.** A single-node cluster with a secret, a
service, a running container and its own root CA had its raft directory
destroyed and restored from a stopped-daemon tar. Everything came back — the
secret, the service at 1/1, the container still `Up` (it never stopped), the
same node id.

**With no backup: nothing comes back, and the daemon says so before it does
damage.** With the certificates still on disk and the raft directory empty,
`satld` refuses to start:

```
Error: cluster bring-up failed
Caused by: this node holds a manager certificate for cluster 2e9za8a7stl3nuzf04v2zc3j8
  but its raft state directory /var/db/satl/raft is empty, so there is nothing to
  resume and satld will not form a new cluster here (that would silently replace
  the cluster this certificate belongs to with an empty one). Restore
  /var/db/satl/raft from a backup of THIS node, the 'dek' key file included --
  see the backup and restore section of docs/operations.md. If this node's state
  is unrecoverable and the cluster has other managers, discard its identity
  instead: remove /var/db/satl/certs and empty /var/db/satl/raft, start satld
  (it forms a fresh single-node cluster of its own) and re-join it with
  'satl swarm join'
```

That refusal is the point. A manager certificate is only ever issued to a node
that already has raft state, so a certificate over an empty raft directory is
never a first boot — it is state that was lost. Starting anyway would mint a
**second cluster under the same certificate**: empty, with a new cluster id and
no root CA, looking perfectly healthy while every service, secret and network
the operator had was gone. The daemon stops instead.

**And if you do remove both**, that is exactly what you get, measured: a new
node id, an empty store, no secrets, no services, and the startup
reconciliation destroying the container that used to belong to the old cluster
(`startup reconciliation complete jails_destroyed=1`). There is no way back from
there and no half-way state: the old cluster's root CA and join tokens were in
the raft state that is gone.

**There is no `ForceNewCluster`.** Docker's `swarm init --force-new-cluster`
rebuilds a cluster from one surviving manager's state by discarding the other
members; SatL answers `501` (`docs/api-compat.md` #137) because a manager that
*has* its raft state does not need forcing — restarting `satld` resumes it — and
one that does not have it has nothing to force from.

So: on a one-manager deployment, schedule the copy. A stopped-daemon tar or a
`zfs snapshot` + `zfs send` in cron, off the node, with the `dek` in it. The
backup interval is how much of the cluster's history you are choosing to lose.

### Three failure signatures worth recognising around a restart

All three were met while establishing the procedures above, on the test cluster.

**A manager that cannot be caught up.** The leader repeats, roughly three times
a second, against one member only:

```
ERROR openraft::replication: RPCError err=Unreachable node: ... raft append_entries
      to member 6439433261039395613 at 10.2.3.124:2377: Internal: h2 protocol error
```

while `netstat` shows an `ESTABLISHED` socket to that address, `nc -z` to it
succeeds, and the member's own store stays empty or frozen and it campaigns in a
loop. That was a replication batch bigger than the internal gRPC message limit:
openraft rebuilt the same oversized message on every retry, so nothing ever
progressed. It is fixed — the batch is now derived from the message limit — and
it mattered precisely here, because the manager that has most to catch up on is
the one that just rejoined or was just restored. If a build ever shows this
signature again, note what does *not* help: restarting the member, and waiting.

**A manager whose raft engine has stopped.** openraft treats any storage error
as fatal and exits its core; the daemon stays up, its API keeps answering reads
from the state it froze with, and `satl node ls` can still show it as `Leader`
because that column comes from the store. The daemon now says so once, loudly:

```sh
grep -a "raft engine has stopped" /var/log/messages
# ERROR satl_cluster::node: this manager's raft engine has stopped and nothing will
#       restart it: this node cannot lead, replicate or commit any cluster write until
#       satld is restarted ('service satld restart'), and reads it still answers are
#       frozen at the last state it applied. The reason is the raft error logged just
#       above this line
```

The reason is the line above it (seen once here:
`quit RaftCore::main on error error=when Read Snapshot(None): replication channel
closed`, an openraft 0.9 race between a replication task exiting and the core
handing it a snapshot). The cure is a restart of that daemon; the other managers
elect around it as long as a quorum of them is left, and this one simply stops
contributing.

**A stop that does not finish.** `service satld stop` took 0.05 s on every
healthy manager here, and hung on every manager that had lost its quorum — three
times, once for 21 minutes before it was killed. What is certain is where it is
*not* stuck: the API socket is already gone (`satl` on that node answers
`Cannot connect to the SatL daemon`) and the daemon has not yet reached
`shutting down raft node`, so the block is between those two, and a write that
can never commit is in flight through both. The mechanism has not been pinned
down further, so treat the *symptom* as the fact: if a stop hangs, `pkill -9
satld` is safe — the raft directory is crash-safe by construction and recovery
from `kill -9` is part of the M0 acceptance test. Two consequences worth
internalising: take a backup only after the daemon has *actually* gone
(`pgrep satld`), not after `service satld stop` returns, and expect
`tests/cluster/reset.sh` (which stops the daemon on every node) to sit there
indefinitely if any node is in this state.

### What this section does not cover

Only cluster state — the raft directory on managers. Images, layers, containers
and volumes are node-local (`satl system prune`, below, has the same asymmetry),
they are rebuilt by pulling and by rescheduling, and none of them is in a raft
backup. There is no cluster-wide backup command and no `satl` verb for any of
this: what is above is `zfs`, `tar` and the two cluster commands, on purpose.

## Resource limits (`--memory`, `--cpus`)

Enforcement requires resource accounting, which is a **boot-time tunable** — it
cannot be switched on at runtime:

```sh
echo 'kern.racct.enable=1' >> /boot/loader.conf   # note: sysrc(8) rejects dotted names
shutdown -r now
sysctl kern.racct.enable                          # expect 1
```

`satld` probes it at startup and says which mode it is in (`rctl(8) resource limits
are enforced`, or a warning that limits are *accepted but not enforced*). With
accounting off, `--memory`/`--cpus` are honoured as far as the API is concerned and the
reason is recorded in the task's status message — the daemon never refuses to start.

Do **not** set `rctl_enable="YES"` in `rc.conf`: that loads static rules from
`/etc/rctl.conf`, while SatL adds and removes its own rules per container.

What the flags actually do on FreeBSD:

| Flag | Rule | Behaviour |
|---|---|---|
| `--memory` | `jail:<id>:memoryuse:sigkill=<bytes>` | The process is **killed** when the jail's resident set exceeds the cap — the closest equivalent to a Linux cgroup OOM kill. `memoryuse:deny` would be silently useless: RSS is not a deniable resource in the kernel, yet `rctl` accepts the rule (measured: a 64 MB `deny` cap allocated 200 MB without complaint). |
| `--cpus` | `jail:<id>:pcpu:deny=<percent>` | The scheduler **throttles** the jail toward the cap. Accounting is a decaying average, so the cap is approached rather than imposed instantly: a fixed CPU-bound workload measured 4.4 s unlimited and 10.5 s at `pcpu:deny=20`, converging further on longer runs. |

Inspect the live rules with `rctl -h jail:<container id>`; they are removed when the
container is removed. Accounting adds per-process bookkeeping in the kernel — modest,
but it is why FreeBSD's GENERIC ships `RACCT_DEFAULT_TO_DISABLED`.

Rules persist after the jail dies — a crash, or a satld older than the 2026-08-15
fix (which removed rules after the jail was already gone), leaves them installed.
They are still removable: `rctl -r jail:<name>` on a dead subject returns 0 and
drops the rules (measured on FreeBSD 15.1). `No such process` is what rctl answers
when the filter matches *no rule*, not when the subject is dead. Since 2026-08-17
`satld` purges its own orphans at startup: the reconciliation pass removes every
`jail:<task id>` rule subject that has no live prison — SatL-shaped subjects only,
never another tool's rules.

## Overlay networks (M3)

`if_vxlan` is **not in the GENERIC kernel** — it is `/boot/kernel/if_vxlan.ko`, and
`config -x /boot/kernel/kernel` mentions vxlan nowhere. `satld` runs
`kldload -n if_vxlan` itself before it creates the first VTEP, so an overlay works on
an unprepared host; load it at boot anyway so a `kldload` failure surfaces once, at
boot, instead of on the first `docker network create -d overlay`:

```sh
echo 'if_vxlan_load="YES"' >> /boot/loader.conf     # sysrc(8) is for rc.conf, not loader.conf
kldload if_vxlan                                    # take effect now
kldstat -m if_vxlan                                 # expect one line
```

**Set the overlay MTU from a measurement, never from a guess.** VXLAN costs 50 bytes
over IPv4; SatL computes `underlay MTU − 50` and sets it explicitly on the vxlan
interface, the bridge and each in-jail epair end. On the OVH VMs the underlay is 1500,
so the overlay is 1450. If your underlay differs, measure it — every node to every
other, with DF set — before believing anything else:

```sh
ping -c 1 -D -s 1472 <peer underlay ip>    # 1472 + 28 = 1500: largest that must pass
ping -c 1 -D -s 1473 <peer underlay ip>    # must fail: "Message too long"
```

### Diagnosing a black-holed or one-way overlay

Read `/var/log/messages` first — as everywhere else in SatL, the CLI shows a summary
and the log shows which command failed and why. Then work down this list; it is
ordered by how often each step is the answer.

| Symptom | Look at | What it means |
|---|---|---|
| a task cannot reach any remote task on the network | the vxlan interface's flag word | `UP` without **`RUNNING`** is a VTEP the driver refused to initialise. `ifconfig` exits 0 and prints `status: active` regardless; the reason is the kernel line in `/var/log/messages` (`destination address type is not supported`, `network identifier N already exists in this socket`) |
| one pair of tasks fails, everything else works | the FDB on **both** nodes | the FDB is per direction. The node reporting 100 % loss is usually the *correctly* configured one: its replies are unicast to a MAC the other node cannot resolve. Diagnose from the sender of the replies |
| everything works but throughput is poor and packet counts are doubled | `netstat -s -p ip` on the **hosts**, both ends | non-zero `fragments created` / `fragments received` on a healthy-looking overlay is a forgotten −50. Nothing else reports it, and throughput on a shared virtual switch does not |
| big transfers stall while pings answer | same counters, plus `fragments dropped` | a path that discards IP fragments, on top of a too-large overlay MTU. Correcting the MTU fixes it |
| a task loses the network some time after a config change | the task's ARP table | a static ARP or gateway entry pointing at a MAC that no longer answers. Removing a network's gateway address from under running tasks is a silent black hole — tear the endpoints down first |

Useful commands, in that order:

```sh
ifconfig <satl-vx-*> | head -1                        # RUNNING, and the MTU
ifconfig -g vxlan                                     # every VTEP on the host
netstat -s -p ip | grep -i fragment                   # host stack: outer fragmentation
netstat -I <satl-vx-*> -b                             # Ipkts/Opkts/Oerrs on the tunnel
sysctl -n net.link.vxlan.<unit>.ftable.count          # entries the kernel holds
sysctl -n net.link.vxlan.<unit>.ftable.dump           # the entries — see the caveat below
```

Three counter traps, all measured (`docs/vxlan.md`):

- **`ftable.dump` stops at 81 entries** and the truncated output looks complete.
  `ftable.count` is the trustworthy size.
- **`ftable_nospace` never moves.** It counts learning failures, and SatL disables
  learning. An empty counter is not evidence of a healthy table.
- **`Oerrs` on the tunnel is a one-way signal.** Non-zero means frames went to the
  blackhole default remote, i.e. something tried to reach an endpoint the control
  plane has not programmed. Zero means nothing: a short burst is counted in `Opkts`
  as successfully sent.

**The counters live in two stacks.** TCP retransmits and inner-IP statistics belong to
the **jail's** stack; the outer fragmentation counters belong to the **host's**. Reading
the wrong one of the two is the fastest route to a confident wrong conclusion.

Getting at the jail's side needs care, because a container image generally ships no
diagnostic tools: the FreeBSD-based rootfs on this host has neither `netstat` nor `arp`,
and the Alpine one has only busybox, whose `netstat` reads `/proc/net/*`. So
`jexec <task> netstat -s -p tcp` works against a jail built from a full FreeBSD
userland and not against a real container. For a real container, run a throwaway jail
with `path=/` on the same bridge and measure from there, or read what the host can see
(the vxlan and epair counters, and the fragmentation counters, which are all the host's
anyway).

## Encrypted overlay networks (`--opt encrypted`, M6)

The contract is in `docs/networking.md` ("M6 — encrypted overlay networks"); this
section is what runs where, and what to look at when it misbehaves.

**The node-wide enc0/IPsec substrate is set once and never restored.** On the
first encrypted network a node hosts, `satld` runs
`sysctl net.enc.in.ipsec_filter_mask=2` and `ifconfig enc0 up` — decapsulated
packets are then presented to pf on `enc0` after the ESP header is stripped,
which is what lets the cleartext guard tell ESP from injection. The sysctl is
node-wide, so it is deliberately **not** put back when the last encrypted
network leaves: a third-party IPsec user may have come to rely on the new
presentation in the meantime, and the mask alone is inert without matching
SAs. Expect `enc0` to stay up and the sysctl to stay 2 forever after; that is
the design, not a leak. The `satl/guard` anchor itself (block the encrypted
VXLAN ports 4790:4999 on the underlay, `pass ... no state` on `enc0`) is
loaded on the first encrypted network and flushed when the last one leaves —
`pfctl -a satl/guard -sr` shows the live rules and their counters.

**Rotation events are logged on the leader only.** The keyring loop is a
leader-only component, so `keyring transition` (with `phase=generate|append|
promote|prune` and the network name) appears in exactly one manager's log —
grep **all** managers before concluding rotation is stuck, and remember
`/var/log/messages` rotates roughly hourly (`bzcat messages.*.bz2 | grep -a`):

```sh
sudo grep -a 'keyring transition' /var/log/messages    # run on each manager
```

The cadence knobs `keyring_rotate_after_secs` / `keyring_phase_settle_secs`
(defaults 43200/60, production 12 h / 1 min) are testing knobs — see "Testing
key rotation: the `keyring_*_secs` knobs" below; a non-default value draws a
loud startup warning.

**Verifying encryption on the wire.** tcpdump the underlay between two nodes
running tasks of the network: everything on the network's VTEP port must be
ESP (protocol 50), never cleartext VXLAN:

```sh
sudo tcpdump -ni <underlay-if> proto 50                 # the ESP flow itself
sudo tcpdump -ni <underlay-if> udp port <4790..4999>    # must print NOTHING
sudo setkey -D | head                                   # the SAD this node holds
sudo setkey -DP                                         # the outbound policies
```

To watch the *decapsulated* packets during a capture, present them to bpf on
`enc0` too: `sudo sysctl net.enc.in.ipsec_bpf_mask=2`, then
`tcpdump -ni enc0 udp port <port>`. satld sets the **filter** mask (pf), not
the bpf mask — the bpf one is a capture-time knob for the operator.

**Troubleshooting.** The security reconcile is level-triggered: it runs on
every assignment shipment and on the 1-minute periodic overlay resync, so a
node whose guard anchor, SAs or SPs were flushed or tampered with converges
back **within a minute** — if it does not, the node's log says which of
`sysctl`/`ifconfig`/`pfctl`/`setkey` failed and why. A cleartext probe from a
node whose SAD/SPD was flushed is **expected to be dropped** by the guard:
nothing is decapsulated onto the overlay bridge, while the block rule's
counter moves (`pfctl -a satl/guard -sr`) and the packet hits `pflog0`
(`kldload pflog` first; tcpdump's PFLOG decode prints the packet without a
"block" keyword, so grep for the port). The probe's ping still shows 100 %
loss for the orthogonal reason that replies are ESP towards a flushed node —
the bridge capture and the counters are the evidence, not the ping.

**Upgrades: every manager must run the new build before the first encrypted
network.** The `encrypted` / `keys` / `vxlan_port` fields ride on the `Network`
object as unknown fields to old code, and serde drops unknown fields on
re-serialize: an old-code manager that rewrites the network (any allocator
pass) strips them, and every new-code node then reads `encrypted=false` and
tears down its SAs and guard — a silent downgrade to cleartext with no error
anywhere. So: finish the rolling manager upgrade first, and do not create
encrypted networks while it is in progress. The worker side fails closed
instead: an old-code worker shipped an encrypted network ignores the new
fields, builds its VTEP on the default port 4789 and blackholes — restart it
on the new build.

## Published ports (M3)

`satl service create --publish 18080:80` publishes in **ingress** mode, the Docker
default. Since M6d this is a real routing mesh **on managers**: every manager
answers on the port, and one running no replica of the service relays over the
`ingress` overlay to a healthy task (`docs/api-compat.md` #75). A **worker**
still answers only when it runs a replica — it has no store replica to compute
the cluster-wide pool from. Operator consequences:

- a load balancer in front of the swarm can treat every **manager** as a
  backend; health-check the port anyway — the check is what keeps a dead
  backend out of *your* pool too;
- on a relayed connection the application sees the **relaying node's ingress
  gateway address, not the client's** (the SNAT is what makes the reply come
  back through the relay — same trade Docker's mesh makes). Where the real
  client address matters (logs, rate limiting, fail2ban), use the opt-in
  PROXY-protocol mode below;
- reach a published port from **another host**. pf applies `rdr` to packets *entering*
  an interface, so `curl localhost:18080` on the publishing node itself does not work
  and never did (`docs/api-compat.md` #35).

### Proxy mode: `satl.publish.proxy_protocol=v2` (M6e)

A service labeled `satl.publish.proxy_protocol=v2` publishes its TCP ports
through `satld` itself instead of pf: every manager listens on the published
port, picks a healthy task from the same set that feeds the pf pool, dials it
over the overlay and writes a PROXY protocol v2 header before splicing the
connection. The task — if it parses PROXY v2 — sees the **real client
address**, which the pf mesh cannot deliver. Example:

```sh
satl service create --name web --replicas 3 -p 8080:80 \
    --label satl.publish.proxy_protocol=v2 $IMAGE
```

and on the application side, e.g. nginx:

```nginx
listen 80 proxy_protocol;
set_real_ip_from 10.100.0.0/24;   # the ingress overlay
real_ip_header proxy_protocol;
```

The trade, explicitly: proxy mode costs a userspace copy per connection and
puts `satld` in the data path; pf mode is cheaper and loses the client
address on relayed connections. What proxy mode buys beyond the address:
real health-aware member selection (a member that refuses is skipped to the
next), where pf's pool is just a table. Operational notes:

- a proxy-mode port never has an `rdr` rule — check with
  `pfctl -a satl/rdr -s nat`: the port must be absent from it;
- UDP ports of a labeled service stay on the pf path;
- a port with no healthy member closes connections (a drained pool is
  refused, not black-holed);
- on workers (no store replica) the proxy set covers local tasks only, the
  same carve-out as the mesh itself.


Publishing also needs `pf_mode = "enforce"` and pf enabled on the host; with the
default `check` the ports are allocated and shown by `satl service ls` and no redirect
is installed. What a node holds, and what it says about it:

```sh
pfctl -a satl/rdr -s nat                        # the static redirects on this node
pfctl -a satl/rdr -s Tables                     # the pool tables
pfctl -a satl/rdr -t satl_p8080_tcp_80 -T show  # one pool's live membership
grep -a 'published ports converged' /var/log/messages
```

Each published `(port, protocol, container port)` triple is one `table` plus one
static `rdr` rule (M6): the task addresses live in the table, so a replica
starting or dying is a `pfctl -T replace` on the table and **not** an anchor
reload — established connections are not touched by membership changes. The
ruleset itself is reloaded only when the *set* of published triples changes,
and a triple that disappears has its table killed (`persist` tables survive a
flush with their members), so `-T show` never reports a pool that no longer
exists.

The anchor is re-derived from the node's live tasks on a short periodic level —
and, on managers, woken by the store's event feed the moment a task's state or
ports move, so a stopping task leaves every node's pool within about a second
rather than a sweep interval — so it repairs
itself: one flushed by hand (rules or tables) comes back within a minute, and one
lost across a daemon restart comes back with the daemon. `satld` logs one line per
*change*, carrying every redirect as `<task id>=<published>/<proto>-><task ip>:<container port>`,
so grep by task id or by port number. A node whose published ports are steady logs
nothing here and runs no pfctl at all — silence is the healthy state.

Two tasks of one service on one node share one pool table, listed by
`-T show`, which is what to expect after scaling a service past the node count.
Two separate rules for one published port would be a bug: pf takes the first
matching translation rule and the others would never be reached.

The round-robin pool is also what made one class of bug visible, and worth recognising
if it ever comes back: **connections to one node failing every other attempt, in
bursts of about five seconds**. That is one dead address in a two-address pool, and its
cause was the port pass publishing a task the manager had already ordered to stop —
the node's own agent had removed the redirect, and the pass put it back because the
store's copy of that task was still `RUNNING` for another few hundred milliseconds. The
signature to grep for on the node is a task id that appears in a `published ports
converged` line *after* its own `published ports removed`:

```sh
grep -a -E 'published ports (removed|converged)' /var/log/messages
```

On a meshed manager the anchor also shows the mesh's two rule shapes after
the rdr rules — per pool the return-path SNAT whose target is this node's
ingress gateway, then the MSS clamp (`docs/networking.md`, M6d):

```sh
pfctl -a satl/rdr -s nat   # rdr rules, then nat pass ... -> <gateway> per pool, then match ... scrub (max-mss 1410)
satl network inspect ingress   # the mesh's overlay: every node's gateway under Ingress
```

## The DNS-RR client-caching trap

SatL services resolve by DNS-RR inside the overlays: `proxy_pass
http://myservice:80` from an nginx task gets one answer per healthy task.
**nginx open source resolves that name once, at startup, and pins the first
address forever** — so a proxying task keeps sending every request to one
replica, and when that replica dies the proxy serves 502s against a service
that is up everywhere else. This is the single most common way a SatL (or
Docker Swarm) deployment looks broken while nothing is.

The fix is nginx's runtime resolver, and both halves of it are load-bearing:

```nginx
resolver 10.100.0.4 valid=10s;   # the node's gateway on the overlay (satl network inspect)
server {
    location / {
        set $upstream http://myservice:80;   # a VARIABLE — this is what forces
        proxy_pass $upstream;                # resolution per request, not at startup
    }
}
```

Without the variable, `proxy_pass http://myservice:80` is resolved once even
with a `resolver` line present. The gateway address to name is the node's own
on the overlay the proxying task is attached to — the embedded DNS responder
listens there. The same trap exists in every client that resolves once
(most HTTP libraries' connection pools do not re-resolve either); the general
rule is: against a DNS-RR service, resolution must happen per connection, and
stale-connection errors must be retried.

A redirect is now created only for a task whose desired state is still below
`SHUTDOWN`, so an ordered stop cannot produce this. A container that exits *on its
own* leaves a narrower version of the same window — there the store's lagging copy of
the observed state is the only signal a manager-side pass has — bounded by one pass
(5 s) and by the agent removing the redirect the moment the container dies.

## Published ports and healthchecks (M5)

**`pf` does not health-check what it redirects to.** It is a packet filter: a
`round-robin` pool distributes connections and never probes a target, so a container
that stops answering on its port keeps receiving its share of the traffic. Nothing in
pf will ever fix that, and nothing should — what takes a dead backend out of the pool is
one layer up. An unhealthy task is stopped and reported `FAILED`, it leaves the live
set, and the port pass rewrites the whole anchor without it. Docker Swarm works the same
way (IPVS does not probe backends either; orchestration removes the task), so the
question is not architecture, it is how many seconds.

Which makes the healthcheck the load-bearing part: **without a probe, `RUNNING` means
only "the jail started".** Measured when publishing landed: 5 ms after `jail start`,
while the nginx in the same jail needed 250 ms to bind its port. So an unprobed published
service is answered *before* it can serve — and, worse, stays answered after it stops
serving, for as long as its jail is up. A `satl run -p` container is always in that
state: the container API reads no healthcheck at all and `satl run` has no flag to set
one (`docs/api-compat.md` #127). If a published service has no healthcheck, health-check
the port from whatever is in front of the cluster, and expect the redirect to be
installed the instant the jail exists.

`satl service create` says so, once, at creation:

```text
service web publishes 8080->80/tcp and has no healthcheck: its tasks are published as
soon as the jail starts, before the workload can answer, and stay published while a
dead container keeps its share of the traffic (pf does not probe a redirect pool).
```

### The numbers, and the one they cost

A published service whose healthcheck leaves `interval`, `timeout` or `retries` unset
gets tighter values than Docker's — **5 s interval, 3 s timeout, 2 retries** instead of
30 s / 30 s / 3 — and only where they are earned: it publishes a port, and it left the
field unset (`docs/api-compat.md` #125, #126). They are written into the stored spec, so
`satl service inspect` shows them, and one log line names them at creation:

```sh
grep -a 'tighter health probe defaults' /var/log/messages
# … applied to a published service … name=web published=8080->80/tcp \
#   applied=interval=5s timeout=3s retries=2
```

What that buys, **measured end to end** on one node (`crates/satld/tests/health_pool.rs`,
nginx with `test -f /tmp/serving` as its probe, the marker then removed): **9.97 s** from
the probe starting to fail to the task's address being out of `pfctl -a satl/rdr -s nat`.
The same run with Docker's defaults would be about 90 s of traffic into a dead backend.
The timeline the log gives you, which is the shape to recognise:

```text
10:49:44.857 task health changed from=starting to=healthy streak=0 exit_code=0
10:49:44.9   <- the workload stops passing its probe
10:49:54.866 task health changed: the healthcheck failed too many times \
             from=healthy to=unhealthy streak=2 exit_code=1
10:49:54.867 jail_kill signal=15
10:49:54.868 shutdown complete: container exited with code 0
10:49:54.869 published ports removed        <- out of the pool, 9.97 s after
```

Note *what* removed it: two failed probes, 5 s apart, then the container was **killed**.

**That is the cost, and it is the whole cost of this version.** In SatL "drop from the
pool" and "kill and replace" are the same event — an unhealthy task is stopped and
`FAILED` (`docs/api-compat.md` #88), where Docker leaves the container running and merely
takes it out of the load balancer. So tightening detection ninefold makes replacement
ninefold more eager too. A long GC pause, a wedged dependency, a probe that blips under
load: what used to need 90 s of failure to cost you a container now needs 10 s. That is
how a restart storm starts where the operator only wanted the traffic to stop, and the
tighter the probe, the smaller the hiccup that triggers it.

Two things bound it. `retries` is what separates a blip from a sustained failure — 2
retries at 5 s means the probe must fail for **10 s continuously**, and a single success
resets the streak — and M4's restart budget bounds the loop: `RestartPolicy.MaxAttempts`
counts replacements per replica and per spec version and survives a leadership change, so
a service created with `MaxAttempts` stops replacing instead of churning forever ("The
restart budget survives a manager restart", above). The default is unlimited, so on a
service that matters, set it.

### If you want the tighter pool without the eager restart

Trade detection latency for stability, deliberately, and know the arithmetic. A verdict
takes up to **`retries + 1` cycles** of `interval + timeout` — one cycle more than
`retries` because a container stops answering *between* two probes and the probe already
in flight may have passed a moment before. The stop that follows takes up to
`stop_grace_period` (10 s by default), and if the agent's own `pfctl` load fails, the
port pass repairs the anchor within 5 s:

| interval | retries | sustained failure needed | worst case out of the pool |
|---|---|---|---|
| 5 s (both unset) | 2 | 10 s | 3 x (5+3) + 10 + 5 = 39 s |
| 5 s (unset) | 4 | 20 s | 5 x (5+3) + 10 + 5 = 55 s |
| 10 s (explicit) | 3 | 30 s | 4 x (10+10) + 10 + 5 = 95 s |
| 30 s (Docker's, explicit) | 3 | 90 s | 4 x (30+30) + 10 + 5 = 255 s |

The cycles use the **effective** values, which is why the last two rows carry a bigger
timeout: setting the interval explicitly also moves the timeout to `min(30 s, interval)`.
The third column is what protects a healthy-but-slow container; the fourth one is
how long a dead one keeps taking traffic. Raising `retries` is usually the better knob:
it lengthens the failure a blip must sustain without slowing the probe down, so a
genuinely dead backend still leaves within a couple of intervals of the verdict. Raising
`interval` slows detection and *also* slows the first probe after a start. Setting
either explicitly disables SatL's default for that field — including the coherent
timeout, which then becomes `min(30 s, interval)`, so set `timeout` too if the probe is
slow. Asking for Docker's exact behaviour is `Interval: 30000000000`, `Timeout:
30000000000`, `Retries: 3` in the healthcheck.

> **CLI gap.** There are no `--health-*` flags on `satl service create` — none of
> docker's `--health-cmd`, `--health-interval`, `--health-retries`,
> `--health-timeout`, `--health-start-period` or `--no-healthcheck`. A healthcheck can
> only be declared in a compose file (`healthcheck:`, `satl compose up`) or over the
> REST API:
>
> ```sh
> curl -s --unix-socket /var/run/satl.sock -X POST -H 'Content-Type: application/json' \
>   --data-binary @spec.json http://localhost/services/create
> # spec.json: {"Name":"web","TaskTemplate":{"ContainerSpec":{"Image":"…",
> #   "Healthcheck":{"Test":["CMD-SHELL","fetch -qo /dev/null http://127.0.0.1/"],
> #     "StartPeriod":10000000000}}},
> #   "Mode":{"Replicated":{"Replicas":3}},
> #   "EndpointSpec":{"Ports":[{"Protocol":"tcp","TargetPort":80,"PublishedPort":8080}]}}
> ```
>
> Durations on the wire are nanoseconds. Leave `Interval`, `Timeout` and `Retries` out
> to get the values above.

**Coming in M6: unhealthy will stop meaning killed.** The decoupling — a task that stays
running but leaves the pool, replaced only on prolonged failure, which is Docker's model
— removes the restart-storm risk above and lets you inspect a sick container instead of
watching it vanish. It needs a task state the machine does not have yet, and it retires
`docs/api-compat.md` #88. No date; what is written above is what the daemon does today.

## Certificate renewal (M4)

Every node's mTLS certificate (architecture §12.1) is renewed automatically at a
random point in the 50-80 % of its validity — 90 days by default, so a renewal is
roughly a 50-70 day event — re-issued from the cluster root held in the raft store,
written to `<state_dir>/certs`, and **swapped into the live TLS configuration in the
same breath**. No restart, ever: the listeners and every outbound channel resolve
their certificate per handshake through the daemon's live identity, so the very next
connection — inbound or outbound — presents the new certificate. Role changes
(promotion/demotion) ride the same mechanism, since the role *is* the certificate's
OU.

One log line per renewal, and silence in between is the healthy state:

```
INFO satld::identity: node certificate renewed and live TLS configuration swapped
     node_id=2et9ev120k2nr9np5h4c3ne60 role="satl-manager"
     not_after=2026-08-12 6:19:49.0 +00:00:00
     server_config_swapped=true client_config_swapped=true
```

Grep by `node_id`, or for `certificate renewed`. To see the certificate a node is
*actually presenting* (as opposed to the one on its disk), ask the listener — this is
the check that distinguishes a live swap from a stale config:

```sh
openssl s_client -connect <node>:2377 </dev/null 2>/dev/null |
    openssl x509 -noout -subject -dates
```

Two things are expected and are not bugs:

- **Established connections keep their old identity until they reconnect.** TLS
  authenticates at handshake time; an open raft stream or dispatcher session is not
  severed by a renewal and keeps working. The next reconnect (network blip, leader
  change, daemon restart on the *other* side) picks up the new certificate.
- **The on-disk `not_after` and the presented `not_after` match only after the swap
  log line.** Between the disk write and the swap there is no observable window — they
  happen in the same loop iteration.

If renewal *fails* (CA material missing from the store, disk full), the daemon logs
`certificate renewal failed; will retry` and backs off exponentially (5 s doubling,
capped at 1 h). The certificate stays valid for a long while after the renewal window
opens — 20-45 days at production validity — so a few failed attempts are a warning,
not an incident.

### The failure signature of a stale TLS config

What breaks when renewal writes to disk but nothing swaps the live configuration —
the pre-M4 behavior, reproduced on the test cluster with the swap deliberately
disabled. It is also what a *bug* in the swap would look like, so it is worth
recognizing. The treacherous part is the shape of the failure: **nothing** breaks at
expiry. Established connections never re-check certificates, so the cluster coasts —
reads work, `satl node ls` says `Ready` everywhere — until the first reconnect after
expiry (a network blip, a daemon restart on a peer, an idle connection cycling). Then,
all at once:

- every session re-establishment fails, and keeps failing on every retry, with the
  same error (here 74 s after expiry):

  ```
  WARN satl_dispatcher::agent: agent session ended error=dispatcher rpc Session
       failed: ... "invalid peer certificate: certificate expired: verification
       time 1786516761 (UNIX), but certificate is not valid after 1786516687
       (74 seconds ago)" ... InvalidCertificate(ExpiredContext ...)
  ```

- raft replication hits the identical wall (`ERROR openraft::replication: RPCError
  err=Unreachable node: ... certificate expired`), quorum is lost, and every write is
  refused: `Error response from daemon: cannot update the service: this cluster has
  no raft leader right now`;
- `satl node ls` **still shows every node Ready with the old Leader** — it reads the
  last replicated store state, which can no longer change. Do not trust that column
  in this failure mode; trust `openssl s_client` (above) and the log;
- and the tell that separates this from every other TLS failure: the renewal loop is
  *still succeeding*, interleaving `issued node certificate` / `node certificate
  renewed` lines between the expired-handshake warnings. Certificates on disk are
  fresh; the process is presenting a stale one. **The fix is a daemon restart**, which
  loads the disk certificate — and on any build with live swap working this state is
  unreachable, because the swap happens in the same loop iteration as the disk write.

### Testing renewal: the `cert_validity` knob

`satld.toml` accepts `cert_validity = "5m"` (`s`/`m`/`h`/`d` suffixes), which sets the
validity of every certificate this daemon issues — its own, and the ones its `NodeCA`
signs for joiners when it leads. **It exists to test renewal** by compressing the
50-80 % window from weeks to minutes; values below one hour draw a loud startup
warning, values below one minute are refused at config load. Never set it on a real
cluster; the default (no key) is 90 days. The cluster harness passes it through
`SATL_SATLD_EXTRA='cert_validity = "5m"' sh tests/cluster/deploy.sh` — the deploy
template itself never carries it. The backdate every certificate gets against clock
skew (1 h) is capped at an eighth of the validity, so even a five-minute certificate
renews *before* it expires rather than after.

### Testing key rotation: the `keyring_*_secs` knobs

`satld.toml` accepts `keyring_rotate_after_secs = 43200` and
`keyring_phase_settle_secs = 60` (plain integers, seconds) — the cadence of the
encrypted-overlay keyring (`--opt encrypted`): how old a network's keyring may get
before a fresh key is appended, and how long each rotation phase (append, promote,
prune) settles before the next. **They exist to test rotation**: with the 12h
production default a full rotation can never be observed in a test run, so the
cluster scenario deploys with
`SATL_SATLD_EXTRA='keyring_rotate_after_secs = 120
keyring_phase_settle_secs = 10' sh tests/cluster/deploy.sh`
and watches the ring advance live. A non-default cadence draws a loud startup
warning. Never set them on a real cluster: the rotation interval also bounds ESP
sequence-number exhaustion, and shortening the settle time lets a phase move on
before every node has picked the ring up.

## Root CA rotation (M5)

`satl ca` prints the cluster root CA certificate. `satl ca rotate` replaces it, on a
live cluster, with **no downtime**: services keep serving, dispatcher sessions stay
up, writes keep committing through every phase. Run it from (or pointed at) any
manager; it blocks until the rotation converges (`--detach` to return immediately,
`--quiet` for just the new PEM). Rotate when the root key may have been exposed —
a stolen manager disk, a compromised backup of the raft store — or on a compliance
clock.

What actually happens, in order (architecture §12.3):

1. A new root is minted and **cross-signed by the old root**, and the cluster's
   trust bundle becomes *old + new* (transitional). From this moment `GET /swarm`
   reports `RootRotationInProgress: true` and `TLSInfo.TrustRoot` carries two
   certificates.
2. **Both join tokens are regenerated immediately** — the token digest pins the
   trust bundle, so every token minted before the rotation is void the moment it
   starts (and the tokens are regenerated *again* at completion). Re-print them with
   `satl swarm join-token worker|manager`. A stale token fails its join cleanly:
   `root CA bundle does not match the join token ... if its root CA was rotated
   since (satl ca rotate), every older token is void`.
3. Every node is re-issued under the new root, live — same pid, no dropped
   sessions. New leaves carry the cross-signed intermediate, so they satisfy peers
   still anchored on the old root *and* peers already on the new one, whichever
   state each peer is in. Watch it happen:

   ```sh
   sudo grep -a satld /var/log/messages | grep -aE 'ca_rotation|marked for re-issue|trust bundle changed|certificate signed'
   # leader:  root CA rotation: marked nodes for certificate re-issue  marked=3 converged=0 total=3
   # nodes:   cluster trust bundle changed; persisted and swapped live
   #          certificate marked for re-issue (root CA rotation); renewing now
   # leader:  root CA rotation completed: old root dropped, new root is the sole trust anchor
   ```

4. When every node's certificate chains to the new root, the old root is dropped in
   one atomic store write. `satl ca` now prints one certificate, and it is the new
   one.

The rotation **waits for every node object**, deliberately — a node the store still
lists must be re-issued before the old root can be dropped. Consequences:

- **A node that is down during the rotation holds it open.** If it will come back,
  just wait: a node returning mid-rotation reconnects with its old certificate (the
  old root is still trusted), receives the transitional bundle and the re-issue mark
  over its session, converges, and the rotation finishes. If it will *never* come
  back, remove it: `satl node rm --force <node>` — the reconciler stops waiting on
  the next tick.

  The leader says which nodes are holding it, once per change rather than on every
  three-second tick, so a rotation stuck overnight is one greppable line and not
  twenty thousand:

  ```sh
  sudo grep -a satld /var/log/messages | grep -a 'root CA rotation is waiting'
  # INFO ca_rotation: root CA rotation is waiting; it cannot drop the old root until
  #      every node holds a certificate from the new one. A node listed 'down' here
  #      will never re-issue on its own: bring it back, or remove it with
  #      'satl node rm --force <node>' and the next pass finishes the rotation
  #      new_digest=... waiting_on=1 total=3 nodes=<node-id>=down
  ```

  `nodes=` is `<node id>=<state>` for each one, which is the id `satl node ls`
  shows; `down` is the state that needs an operator, anything else is a renewal in
  flight.
- **A node that stays down through the whole rotation cannot reconnect afterwards,
  and the failure is one-directional.** Measured on the three VMs, because the
  obvious guess is wrong and it decides where you look:

  - the returning node still verifies the managers *fine*. Their leaves carry the
    cross-signed intermediate, which bridges back to the root it still holds —
    that bridging is exactly what the cross-signing is for, and it keeps working
    for the node that is behind;
  - the managers do **not** accept its leaf: it was signed by a root they have
    dropped, so it fails against their anchors and they refuse the handshake.

  So there is one operator-facing message and it is on the **managers**:

  ```
  WARN refused an internal TLS connection: the peer's certificate does not verify
       against this cluster's trust anchors. If that node was offline across a root
       CA rotation ('satl ca rotate'), its certificate chains to a dropped root:
       whichever node missed the rotation must rejoin: 'satl swarm leave --force'
       there, then 'satl swarm join' with a token freshly printed by
       'satl swarm join-token worker|manager' on any manager
       peer=10.2.3.124:12267 error=invalid peer certificate: BadSignature
  ```

  Note `BadSignature`, not `UnknownIssuer`: every root of a given cluster carries
  the same `CN=satl-ca`, so a leaf from the dropped root matches an anchor *name*
  the verifier holds and fails on the signature. Grep for the sentence, not the
  rustls spelling.

  **On the returning node itself you will not see a certificate error** — it has
  none to report. What it shows is the managers' fatal alert, once per reconnect
  attempt:

  ```
  WARN satl_dispatcher::agent: agent session ended
       error=dispatcher rpc Session failed: ... "received fatal alert: DecryptError"
  ```

  `DecryptError` from a peer means *the peer rejected this node's certificate*. If
  that is what a node shows and it will not come back, go read a manager's log for
  the sentence above — that is where the reason and the recovery are printed.

  There *is* a node-side diagnosis, and it fires in the cases where this node is
  the one doing the rejecting — a peer from a different cluster, or a node more
  than one rotation behind, where no cross-signed bridge is left:

  ```
  WARN refused an outbound internal TLS connection: the peer's certificate does not
       verify against this node's trust anchors, ... peer_node_id=<id>
  ```

  Repeated at most once a minute per node, so a node left stranded overnight does
  not bury the rest of the log. When the peer's certificate names a *different
  cluster id*, that message says so rather than blaming a rotation: the two nodes
  are simply not in the same swarm (a node that left, or one that re-initialized
  itself), and the fix is a plain join.

  **The recovery, in full.** On the returning node:

  ```sh
  satl swarm leave --force                       # discards its cluster state
  satl swarm join --token <fresh token> <any manager>:2377
  ```

  Two things about it are load-bearing and were not always true:

  - **Any manager works.** Only the raft leader signs certificates; a manager that
    is not the leader answers `IssueNodeCertificate` with the leader's address and
    the joining daemon follows that redirect itself (`following its redirect to the
    leader` in its log). An operator pasting a manager address has no way to know
    which one leads, so this has to hold — before this was fixed, pointing the
    documented recovery at a follower failed with `this manager is not the raft
    leader; certificates are signed by the leader`, and the node stayed stranded.
    If *no* manager is currently the leader, the join says so and says to wait for
    an election, rather than half-succeeding.
  - **`satl swarm leave --force` is not "make this node idle".** SatL is
    cluster-first: a daemon always has a cluster, so leaving discards this node's
    cluster state and immediately forms a **fresh single-node cluster** of its own,
    with its own root CA and its own tokens (`docs/api-compat.md` #86). Until it
    joins, `satl node ls` on it lists one node — itself, as Leader. That is
    expected, and it is also why the node comes back under a **new node id**: the
    identity it rejoins with is issued by the cluster it joins. Its old containers
    were long since rescheduled elsewhere; the reconciliation pass reaps what is
    left on it.

  Nothing has to be deleted by hand. `leave --force` clears the certificates, the
  raft directory and the persisted manager list, which is everything the joiner's
  clean-state guard checks. The raft-id blacklist a `satl node rm --force` leaves
  behind does **not** block this: it bars one raft id from re-admission, and a
  fresh join mints a new one.
- A second `satl ca rotate` while one is running is refused with the same guidance
  (finish, or remove the nodes that block finishing).

Do not try to shortcut a stuck rotation by editing certificates on disk: every fact
the rotation acts on lives in the raft store, and the reconciler will re-assert it.
The two operator levers are `satl node rm --force` (stop waiting for a dead node)
and rejoining a node that missed the rotation.

**If a whole test or lab cluster has drifted apart** — several nodes each in a
cluster of their own after a botched rotation — do not chase it node by node:
`sh tests/cluster/reset.sh` wipes state on every node in `tests/cluster/inventory.toml`
and restarts the daemons, and `sh tests/cluster/run.sh init_and_join` forms a fresh
three-node cluster from there. On a production cluster the equivalent is per node:
`satl swarm leave --force` on the drifted node, then rejoin it.

## Worker nodes and live role changes (M4)

`satl swarm join --token <worker token> <manager>:2377` brings a node up as a
**worker**: it runs tasks, the overlay data plane and DNS, and nothing else — no
raft, no store, no listener of its own (architecture §1.2). What an operator needs
to know:

- **Cluster commands answer Docker's refusal on a worker.** `satl service ls`,
  `satl node ls`, `satl network ls` etc. return 503 "This node is not a swarm
  manager. Worker nodes can't be used to view or modify cluster state. ..." —
  run them on a manager. `satl ps`, `satl logs`, `satl exec`, `satl images` and
  `satl pull` keep working and show that node's own containers
  (`docs/api-compat.md` #79-#86). Container create/start/stop/rm are refused too:
  every SatL container is a service task, and those are manager writes (#80).
- **A worker finds its cluster again through `<state_dir>/managers.json`** — the
  manager list its session last reported, refreshed automatically. If that file is
  lost the daemon refuses to start with a message saying to re-join; it never
  invents a cluster of its own.
- **`satl node promote <node>` applies live.** Grep the *target node's*
  `/var/log/messages` for the sequence: `this node's role changed in the store;
  renewing the certificate to apply it` → `node certificate renewed by a manager's
  NodeCA and swapped live` → `applying a role change: rebuilding the cluster
  runtime, no daemon restart` → `cluster state ready ... joined=true` → `role
  change applied`. The daemon does not restart (same pid), running containers are
  untouched, and the node shows `Reachable` in `satl node ls` once raft has
  promoted it from learner to voter (a few seconds).
- **`satl node demote <node>` applies live too**, in the reverse shape: the leader
  removes it from raft first (quorum-checked; refuses rather than breaking
  quorum), then flips the role; the node renews into a worker certificate and
  rebuilds as a worker. Its raft state directory is emptied — the log belongs to a
  membership it left.
- **A promotion that cannot reach any manager falls back to the worker runtime and
  retries** on the next session event; a daemon restarted mid-promotion (manager
  certificate, empty raft directory) resumes the join instead of initializing a
  new cluster. Both paths are WARN/ERROR lines worth grepping if a promotion seems
  stuck: `promotion: no manager could admit this node to raft` and
  `manager certificate with no raft state: resuming an interrupted promotion`.
- **Quorum arithmetic changes when you run workers.** Managers alone form quorum:
  two managers plus a worker tolerate *no* manager failure (one of two managers
  down = no quorum). Promote a third manager before taking one down — promotion
  being live is what makes that a viable emergency move.

## Rolling updates (M4)

`satl service update --image <new tag> <service>` replaces the tasks of a service under
the policy in its spec. The policy is set at create time and adjusted with Docker's own
flags on either verb — `--update-parallelism`, `--update-delay`,
`--update-failure-action`, `--update-monitor`, `--update-max-failure-ratio`,
`--update-order`, and the same six as `--rollback-*` for the policy a *rollback* runs
under. Two things to know before using them:

- **A flag you do not pass keeps the value the service already has.** `update` reads
  the stored spec, changes what you named and posts the whole document back. So
  `satl service update --update-parallelism 2 web` does not disturb the service's
  failure action, and `satl service update --image ... web` does not disturb its
  policy at all. (This was not true before M4's tail: the CLI carried only
  parallelism and delay, so every update reset the rest to defaults and quietly
  disabled automatic rollback — `docs/api-compat.md` #96.)
- **Naming one flag of a half names that whole half.** A service created with no
  policy at all and updated with a lone `--update-monitor 30s` gets Docker's defaults
  for the other five (parallelism 1, `pause`, ratio 0, `stop-first`), because
  parallelism 0 means "replace every slot at once" and must never be arrived at by
  omission.

Watch a rollout with `satl service inspect <service>` (`UpdateStatus.State` and
`Message`) or on the leader's log:

```sh
grep -a -E 'rolling update|rolling back|updating slot' /var/log/messages
```

**A paused update, and how to get out of it.** With `--update-failure-action pause`
(the default) a rollout that trips `MaxFailureRatio` stops where it is:
`UpdateStatus.State` reads `paused`, the slot it was replacing may be empty, and the
updater deliberately does nothing more for that service — it will not keep feeding
replicas to a spec that is failing. Everything else keeps working (scale, restart
policy, node eviction), only further slots stop being replaced. **Push a corrected
spec and the rollout starts fresh**: any `satl service update` clears the paused
status, so `satl service update --image <working tag> <service>` is the recovery, and
`satl service rm` + recreate is not needed. With `--update-failure-action rollback` the
manager does the same thing for you, swapping the spec back to `PreviousSpec` and
ending at `rollback_completed`; a rollback that itself fails pauses rather than rolling
again (architecture §5), and the same corrected-spec push gets it moving.

A rollback the manager performs clears `PreviousSpec` on purpose — the spec that just
failed is not a target to return to (`docs/api-compat.md` #95) — so
`?rollback=previous` has nothing to go back to until the next update. There is no
`satl service update --rollback` yet; a manual rollback is
`curl --unix-socket /var/run/satl.sock -X POST '.../services/<id>/update?version=<v>&rollback=previous'`
with the current spec as the body (#96).

## Global services, node availability and labels (M4)

A **global service** (`satl service create --mode global <image>`) runs one task per
eligible node instead of a fixed number of replicas. It has no replica count, so
`--replicas` is refused on both verbs and `satl service scale` answers "scale can only
be used with replicated mode"; the way to change what it runs is
`satl service update`. Its tasks are named `<service>.<node id>.<task id>` rather than
`<service>.<slot>.<task id>` — the node *is* the replica identity — and they all carry
slot 0, which is what `satl service ps` shows as `<service>.<node id>`. The `REPLICAS`
column of `satl service ls` reads `running/wanted`, where "wanted" is the number of
tasks the cluster currently *wants*, so a global service on a three-node cluster with
one node drained honestly reads `2/2`, not `2/3`.

**Node availability** is `satl node update --availability active|pause|drain <node>`:

| | |
|---|---|
| `active` | the normal state: runs tasks, takes new ones |
| `pause` | keeps what it runs, takes no new tasks. Nothing is moved off it — this is the state to put a node in while you inspect it |
| `drain` | gives up every task it runs, and takes none |

Two things about a drain are worth knowing before you rely on it:

- **it does not wait.** Eviction from a draining node is the one case where SatL
  ignores the service's `RestartPolicy.Delay`: an operator emptying a node is waiting
  on it, so the replacements are created immediately (SWK §7.4). Every other
  eviction — a node going `Down`, a constraint that stopped matching — pays the delay
  in full. In the log, the drain's evictions read `trigger="node is draining"` with
  `delay_ms=0`; a `Down` node's read `trigger="node is down"` with the service's own
  delay. Measured on the test cluster: a 6-replica service with a 30 s restart delay
  is fully re-placed **1–2 s** after the drain;
- **a global service's task on that node is stopped and not replaced.** There is no
  other node for it to run on — its node is its identity — so the service simply runs
  on one node fewer (`stopping a global task … reason="node is no longer eligible for
  this global service"`). Put the node back to `active` and it gets a **new** task
  there on its own, with no operator action. The same holds for a node that goes
  `Down`.

**A replicated service is not rebalanced when the node comes back.** SatL has no
rebalancer: the tasks the drain moved stay where they were re-placed, so a 6-replica
service drained off one of three nodes stays 3/3 on the survivors and the returned node
runs none of it. That is deliberate — moving a healthy task costs an outage for
cosmetic balance — but it means a node that has been drained and returned is empty of
everything except global services until something else places work on it. Scaling the
service up and back down, or any update that replaces its tasks, spreads it again.

**Node labels** — `satl node update --label-add zone=eu <node>` /
`--label-rm zone <node>` — are matched by `--constraint node.labels.zone==eu` and, from
M4, are **enforced continuously**: a task whose node stops matching is shut down and
replaced on a node that does match (SWK §7.6). So editing a label is a placement
change that moves running containers, at the service's restart delay. Two caveats:

- only an `active` node is judged. A `pause`d node keeps its tasks whatever its labels
  say, and a draining one is already losing them;
- resource reservations are *not* re-checked, only constraints and platform. A node
  whose capacity is edited downwards keeps the tasks it is already running.

**An absent `RestartPolicy.Delay` is the 5 s SwarmKit default, even when the
rest of the policy is present.** Compose's `deploy.restart_policy` without a
`delay:` and `satl service create --restart-condition` both send a policy that
names a condition and no delay, and admission fills 5 s — the same value an
absent policy gets. That default is the only thing pacing a crash loop: every
attempt costs a jail, a ZFS clone and an epair, and an audit of this cluster
measured a service stored with `Delay: 0` (the shape above, before the fill
landed) failing **~110 tasks/minute across 3 replicas**. One caveat the wire
forces: `Delay` travels as a plain integer, so an explicit `"Delay": 0` is
indistinguishable from an absent one and becomes 5 s too — a zero-delay
restart is not expressible (api-compat 153).

**The restart budget survives a manager restart and a leadership change.**
`RestartPolicy.MaxAttempts` counts replacements per replica *and* per spec version, and
that count is derived from the store's task history on every pass rather than held in
the leader's memory. A crash-looping task therefore stops for good after its attempts
are spent, whatever happens to the managers in between — before M4 an election handed
it a fresh budget and it restarted forever. What an operator reads when a slot has
given up:

```sh
grep -a 'task not restarted' /var/log/messages
# … task not restarted task_id=… slot=1 state=failed trigger="task terminated" \
#   attempts=2 reason="max restart attempts reached"
```

The task is left in its terminal state with `DESIRED STATE` still `Running` — that is
what "nothing will replace this" looks like in `satl service ps`, and it is not a stuck
orchestrator. A service update (a new spec version) starts a fresh budget.

> **CLI gap.** `satl service create` carries `--restart-condition` but none of docker's
> `--restart-delay`, `--restart-max-attempts` or `--restart-window`, so a service that
> needs anything but the defaults (`any`, 5 s, unlimited) has to be created over the
> REST API:
>
> ```sh
> curl -s --unix-socket /var/run/satl.sock -X POST -H 'Content-Type: application/json' \
>   --data-binary @spec.json http://localhost/services/create
> # spec.json: {"Name":"…","TaskTemplate":{"ContainerSpec":{"Image":"…"},
> #   "RestartPolicy":{"Condition":"any","Delay":30000000000,"MaxAttempts":2}}, …}
> ```
>
> Durations on the wire are nanoseconds, as everywhere in the Docker API.

## Secrets and configs (M5)

```sh
# Create (payload from a file or stdin), list, inspect, remove — docker verbs.
printf 'hunter2' | satl secret create db_password -
satl secret ls
satl secret inspect db_password        # metadata only: the payload is never returned
satl config create app.conf ./app.conf
satl service create --name web \
    --secret db_password \
    --secret source=api_key,target=keys/api,uid=1000,gid=1000,mode=0400 \
    --config source=app.conf,target=/etc/app/app.conf \
    registry.example.com/app:1
```

What an operator must know:

- **Inside the container**, each secret is a file at `/run/secrets/<target>` on a
  tmpfs sized to the payloads — it never touches the node's disk (encrypted at rest
  in the Raft store on managers, memory-only on workers). Secret targets are
  relative to `/run/secrets`; config targets are absolute (a relative one is rooted
  at `/`) and mounted read-only. uid/gid must be numeric.
- **Limits**: a secret payload is under 500 KiB, a config under 1000 KiB.
- **Secrets are immutable — rotation is by replacement**: create the new secret
  under a new name, `satl service update` the services to reference it, then
  `satl secret rm` the old one. There is no update verb, and the API's update
  endpoint is refused (`docs/api-compat.md`).
- **Removal is refused while referenced**: `satl secret rm` answers with the list
  of services still using the secret. That refusal is what keeps a running task
  from losing a secret it was promised; the dispatcher tolerates the race anyway
  (a secret deleted mid-flight is withdrawn from nodes and logged), but in normal
  operation the API makes that path unreachable.
- **Logs never carry payloads.** Secret *names* appear in the daemon log
  (`materialized dependency payload`, `secret assigned/withdrawn`); if a payload
  byte sequence ever shows up in `/var/log/messages`, that is a bug to report.
  The integration suite greps for exactly that.

## Compose stacks (M5)

```sh
cd /srv/shop                 # compose.yaml is here; the project is "shop"
satl compose config          # what would be created, as JSON -- reaches no daemon
satl compose up              # networks first, then one service per compose service
satl compose ps              # this project's tasks, across the cluster
satl compose down            # removes exactly what up created, by label
satl compose down -p shop    # ... from anywhere, with no compose file at all
```

**`satl compose up` is not `docker compose up`.** It deploys *services*: one per
compose service, on an overlay network of its own, scheduled across the cluster.
That is `docker stack deploy`'s model, and it is forced by SatL's own — there are
no standalone containers here, every container is a task of a service. The
consequences worth knowing before the first `up`:

- **Names are namespaced, hostnames are not.** The service objects are
  `<project>_<service>`, the networks `<project>_<key>`, the volumes
  `<project>_<key>`; but every attachment carries the bare compose service name
  as a DNS alias, so `redis:6379` inside the file resolves to `shop_redis`'s
  tasks. Read the mapping with `satl compose config` before deploying, and note
  that `satl service ls` shows the namespaced names.
- **The project name decides what `down` removes.** It comes from `-p`, else
  `COMPOSE_PROJECT_NAME`, else the file's `name:`, else the directory name
  (lowercased, with anything outside `[a-z0-9_-]` deleted). `up` labels every
  object it creates with `com.docker.compose.project=<project>` and `down` acts
  on that label alone: an object with the right name but not the label is
  somebody else's and is refused, in both directions. Two projects can therefore
  share a cluster safely, and `down` can clean up without the file.
- **Unsupported keys are refused, not ignored** (`docs/api-compat.md` 110-124).
  The error names the file, the service and the key, and says why. If a stack you
  brought from a single host is refused, the three usual causes are `build:`
  (build and push the image first), a relative bind mount (`./conf:/etc/nginx` —
  the path is on your workstation, not on the nodes; deliver the file as a
  `config:` instead), and `${VAR}` interpolation (substitute it before
  deploying).
- **Secrets and configs must exist first.** Only `external: true` is accepted:
  `satl secret create redis_auth ./auth.conf`, then refer to it. A `file:`
  declaration is refused because a secret is immutable — `up` could create it
  once and would then silently keep the old payload for ever.
- **A second `up` is a rolling update.** Each service is reposted against the
  version `up` read, so the updater replaces tasks under the service's own
  `deploy.update_config` policy; nothing is recreated from scratch and nothing
  else in the spec is lost. A service the file no longer declares is reported as
  an orphan and removed only with `--remove-orphans`.
- **`down` waits, and does not touch volumes.** Removing a network while a task
  still holds it is refused by the daemon, so `down` retries for up to 90 s while
  the tasks stop (it says so on stderr). `-v/--volumes` is refused outright: a
  volume is a node-local dataset on whichever nodes ran a task, and volume labels
  are not persisted, so there is nothing to scope a cluster-wide removal by.
  Remove them on each node that ran a task, where its daemon socket is:
  `ssh node2 satl volume ls`, then `ssh node2 satl volume rm shop_redis-data`. The CLI
  talks to a unix socket only (`--host tcp://...` is refused), so there is no remote
  form of this.
- **What to read when a stack does not come up.** `satl compose ps` gives the
  task states and the nodes; then the daemon's own account on the node that holds
  a failing task (`sudo grep -a satld /var/log/messages | tail -200`). A task
  stuck in `Preparing` is usually an image the node cannot pull; a `Rejected`
  one names the reason (a missing bind source, a secret whose uid is not
  numeric); a task that starts and dies with a healthcheck is `Failed` with the
  probe's exit code in `satl service ps`'s ERROR column.

## Reclaiming disk: `satl system prune` (M5), `satl images rm` (M9)

Before M5 nothing on a SatL node reclaimed anything. Every image layer a node ever
pulled stayed on disk as a ZFS dataset, and deleting one by hand was not a remedy
because nothing reconciled it. `satl system prune` is the reclamation, and there are
three facts to know before running it.

**To reclaim one image rather than everything, use `satl images rm`** (M9; `satl rmi`
is the same verb). It refuses while a running task or any service spec still names
the image, and `--force` does not override that -- a service spec is a standing order
to create tasks, so untagging under it turns the next start into a pull against a
registry that may be gone. Only stopped containers referencing it is a refusal
`--force` *does* override. **Budget about a second and a half per image**: the
removal runs the same two agreeing passes described below, for the same reason, and
`--no-prune` is how you pay that once for a batch instead of once per image:

```sh
for i in $(satl images -q); do satl images rm --no-prune $i; done
satl images prune          # one sweep at the end
```


**It is node-local for everything that costs disk.** Containers and networks are cluster
objects, so pruning them acts on the whole cluster. Images, layers, blobs and volumes
exist on the node that pulled or created them, and a prune answered by one daemon
reclaims one node. Both the prompt and the summary say which node answered:

```
Total reclaimed space: 14.13MB (on alpha; images, layers and volumes are node-local)
```

To reclaim a cluster, run it on every node (`for n in ...; do ssh $n satl system prune -f; done`).

**Pruning a stopped container removes the service behind it.** A container in SatL is a
task of a service (architecture §4), so there is no way to remove the container and keep
the service without the orchestrator immediately creating a replacement — `satl rm` has
resolved this the same way since M1 (api-compat 33). The rail is at the service: a
service is pruned only when **every** container of it is stopped, so a `--replicas 3`
service with one dead task keeps all three. This is also what finally reclaims the jail,
the epair and the rootfs dataset an exited container keeps holding.

**A layer needs two agreeing passes.** The command takes two readings of what is
unreferenced, 1.5 s apart, and destroys only what both agree on. A layer chain that
looked unreferenced on one pass and not the other is reported rather than skipped
silently:

```
2 layer(s) were unreferenced on only one of the two passes and were left alone.
Run prune again to reclaim them.
```

That is not a fault, it is the design: reclaiming a layer is irreversible and only a
registry can undo it, while running prune twice costs nothing.

### What it reclaims, and what it will not

| Object | Scope | Reclaimed when |
|---|---|---|
| container | cluster | it is stopped **and** every container of its service is |
| network | cluster | no task is attached and no service asks for it; the ingress network is never pruned |
| image record | node | `-a` only, and no task's spec names it |
| image content (blob, manifest, config) | node | no image record reaches it — SatL's "dangling image" (api-compat 132) |
| layer dataset | node | no image chain, no clone and no apply in flight claims it, on two passes |
| volume | node | `--volumes` only, and no task mounts it |

Three things a prune will decline to do, all of them on purpose:

- **while an image pull is in flight**, no content is reclaimed: a blob reaches disk
  before the metadata that names it, so the reachable set is incomplete by construction.
  One line at info says so; run it again when the pull is done.
- **a layer something still holds a clone of** is left alone with a warn naming it. ZFS
  refuses this itself (`filesystem has dependent clones`) and `-R`, which would force it,
  is never used — that flag would flatten a container's writable layer along with the
  image layer under it.
- **an image whose metadata is unreadable** stops content reclamation for that pass
  entirely, with a warn: a record whose manifest is missing cannot say which blobs it
  needs, and reclaiming on that reading could delete a live layer.

### Reading it in the log

```sh
grep -a "stopped containers pruned"                      /var/log/messages
grep -a "images and layers pruned on this node"          /var/log/messages
grep -a "layer dataset destroyed"                        /var/log/messages
grep -a "looked unreferenced on only one of the two"     /var/log/messages  # deferred
grep -a "still holds a clone of it"                      /var/log/messages  # ZFS refused, correctly
grep -a "pull is in flight"                              /var/log/messages
```

### Measured, on this host

Three stopped alpine containers plus their service records and the alpine image, against
a running nginx container that had to survive untouched:

```
zroot/satl used       85,770,240 B  ->  70,590,464 B     (15.18 MB reclaimed)
  layers              62,337,024     ->  52,211,712      (the alpine layer, 10.1 MB)
  images              19,914,752     ->  15,945,728      (its blob and metadata, 3.97 MB)
  containers           1,343,488     ->     544,768      (three writable layers)
blobs/manifests/configs   2/3/2      ->        1/1/1
```

Two invocations, and the second one is the point: the first reclaimed the containers and
untagged one image reference, but the alpine layer was still claimed — the removed tasks
were still in the store's task history, and history names the image. The second, once the
reaper had pruned that history, untagged the last reference and destroyed the layer. The
running nginx container kept serving on its own address throughout.

## Leftover container mounts, and why no tool showed them (M5)

Every container carries mounts ocijail makes host-side at create time: `devfs`,
`fdescfs`, a tmpfs `/tmp`, and for a Linux image also `linprocfs`, `linsysfs` and a
tmpfs `/dev/shm`. They are mounted **`MNT_IGNORE`**, and that one flag is why a leak of
them went unnoticed through every clean run this project has had:

| Tool | Shows them |
|---|---|
| `mount` | **no** — mount(8) hides `MNT_IGNORE` unless `-v` is given |
| `mount -t tmpfs` | **no** |
| `df -t tmpfs` | only while the filesystem under them still exists; once orphaned, `statfs` fails and `df` prints `stats possibly stale` to stderr and nothing to stdout |
| `mount -p` | **yes** |
| `mount -v` | **yes** |

So the audit to run is:

```sh
# every container mount on this node
mount -p | awk -F'[\t ]+' '$2 ~ "^/var/db/satl/containers/"'

# the ones that are leftovers: no container dataset under them any more
mount -p | awk -F'[\t ]+' -v d=/var/db/satl/containers/ '
    index($2, d) == 1 { rest = substr($2, length(d) + 1)
                        s = index(rest, "/"); if (s > 1) print substr(rest, 1, s - 1) }' |
  sort -u | while read -r id; do
      zfs list -H -o name "zroot/satl/containers/$id" >/dev/null 2>&1 || echo "orphan: $id"
  done
```

**A container that still exists as a record is not a leftover.** A stopped container keeps
its jail and its rootfs, so its `/tmp` is part of something an operator can still
inspect; only a mount whose task is claimed by nothing is orphaned. `satld` sweeps those
itself now, at startup and every 20 s, and — like the dataset sweep it runs in front of —
only on the second consecutive pass that agrees:

```sh
grep -a "unmounted a leftover container mount"     /var/log/messages
grep -a "the periodic sweep unmounted leftover"    /var/log/messages
```

Where they came from is worth knowing, because nothing in the removal path was at fault.
Measured on the cluster nodes: 54, 54 and 56 stale tmpfs, three mounts each for 54 task
ids long gone, while 247 removals in the same logs all reported "no leaked mounts" —
`ocijail delete` unmounts correctly and `satl-runtime` sweeps the rootfs afterwards. What
orphaned them was `umount -f` on the **rootfs dataset itself** while its `MNT_IGNORE`
submounts were still there, done by a test script that enumerated mounts with plain
`mount` and therefore could not see them to unmount first. The asymmetry is the trap, and
it is measured:

- `zfs destroy` **refuses** while anything is mounted below the dataset:
  `cannot unmount '<path>': pool or dataset is busy`. That is a VFS refusal and it is
  protective.
- `umount -f` on the parent **succeeds**, leaving the children mounted on a filesystem
  that no longer exists. `zfs destroy` then succeeds too, and the orphans are invisible to
  `df` from that moment on.

Anything that force-unmounts under `<state_dir>` must therefore go deepest-first off
`mount -p`, never off `mount`.

## Metrics (M6)

`satld` exposes a Prometheus endpoint on a **separate listener**, off by
default — dockerd's exact posture (`--metrics-addr`). Enable it in
`satld.toml`:

```toml
metrics_addr = "10.2.0.4:9323"
```

or on the command line with `--metrics-addr 10.2.0.4:9323` (the flag wins over
the config key). `GET /metrics` is the only route; everything else is a 404.

**The endpoint is unauthenticated, exactly like dockerd's.** The scrape
reveals cluster shape, task ids and per-task resource usage, so bind it to a
private address reachable by the Prometheus server and nothing else — the
cluster underlay (vtnet1 on the test cluster) is the natural choice, never
the public interface. If only local scraping is needed, `127.0.0.1:9323`
works too.

Naming follows a deliberate split (`docs/api-compat.md` #140): series dockerd
itself defines keep Docker's exact names (`engine_daemon_*`,
`http_requests_total`), so existing Docker dashboards render unchanged;
everything SatL-specific is `satl_*`. What is exposed:

| Series | Source |
|---|---|
| `engine_daemon_engine_info`, `engine_daemon_engine_cpus_cpus`, `engine_daemon_engine_memory_bytes` | build identity + host facts, set once at startup |
| `engine_daemon_container_states_containers{state}` | local task DB, refreshed every 20 s (`paused` is always 0: SatL has no pause) |
| `engine_daemon_health_checks_total`, `engine_daemon_health_checks_failed_total` | every healthcheck probe, counted where it runs |
| `http_requests_total{method,code}` (histogram) | every Docker API request, measured in the API middleware |
| `satl_raft_role{role}`, `satl_raft_leader_id`, `satl_raft_term`, `satl_raft_last_applied_index` | the manager's raft metrics; `none`/0 on a worker |
| `satl_tasks{state}`, `satl_services` | the cluster store as this manager sees it; empty on a worker |
| `satl_dispatcher_sessions` | open agent sessions on this manager |
| `satl_reconcile_pass_seconds{sweep}`, `satl_reconcile_passes_total{sweep,outcome}` | the two node sweeps (dataset 20 s, port 5 s) |
| `satl_external_command_failures_total{tool}` | failed zfs/ifconfig/pfctl/ocijail/rctl invocations, counted in the runners — the early-warning series: anything above zero deserves a look at `/var/log/messages`, which carries the full argv and stderr |
| `satl_node_certificate_not_after_timestamp_seconds` | the node certificate's expiry, re-read from disk so a renewal is reflected |
| `satl_container_memory_usage_bytes{task_id}`, `satl_container_cpu_time_seconds{task_id}` | `rctl -hu jail:<task>` every 20 s — **only when `kern.racct.enable=1`**; with racct off no `rctl` process is ever spawned and these series are absent |

Scrape check and name hygiene:

```sh
curl -s http://10.2.0.4:9323/metrics | head
curl -s http://10.2.0.4:9323/metrics | promtool check metrics
```

One expected `promtool` lint: `http_requests_total non-counter metrics
should not have "_total" suffix`. The name is Docker's own — dockerd names
its API timer exactly that, and the dashboards this series exists for query
it by that name — so the lint is inherited deliberately, not by accident.
Everything else must be clean.

## Known M0 limits

- No containers yet (M1): `/info` reports zero counts; only `/_ping`,
  `/version`, `/info` are served.
- Resource limits (rctl) will require `kern.racct.enable=1` in
  `/boot/loader.conf` (reboot needed) — enforced from M1 on worker nodes;
  without it SatL logs a warning and runs without enforcement.
