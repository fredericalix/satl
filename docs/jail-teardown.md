# Jail teardown: why a container rootfs stays busy

**Status: measured on the dev host (FreeBSD 15.1-RELEASE-p2) and on the OVH
cluster VMs, 2026-08-12. Scripts: `hack/experiments/rootfs-busy/`, captures in
that directory's `captures/`.**

The symptom, from a cluster run:

```
satld[24330]: ERROR ... task_step{step="remove" task_id=1k7gm62t58pxl4mm4twkolzo3 service=ovl-a}:
  satl_agent::controller: task cleanup step failed step="destroy-rootfs"
  error=`/sbin/zfs destroy -r zroot/satl/containers/1k7gm62t58pxl4mm4twkolzo3` failed with
  exit code 1; stderr: "cannot unmount '/var/db/satl/containers/1k7gm62t58pxl4mm4twkolzo3':
  pool or dataset is busy"
```

The task is gone, its jail was deleted, `ocijail delete` reported *no leaked
mounts*, and yet the rootfs cannot be unmounted. Nothing that an operator
normally reaches for shows a holder:

| Tool | What it said, the whole time the dataset was busy |
|---|---|
| `fstat -f <rootfs>` | nothing, **zero** open files on that filesystem |
| `procstat -a -f` | no process with any path under the rootfs |
| `mount -p` | the rootfs itself and **no submount** under it |
| `ps -axo jid` | no process in the jail |
| `mount -v` | `vnodes: count 2`, the kernel *does* hold vnodes there |

## 1. What holds it

The dying prison. `jail_remove(2)` does not destroy a prison: it moves it to
`DYING` and it stays there until its last reference goes. A prison holds its
root directory (`pr_root`), which is an **active vnode in the container's own
ZFS filesystem**, so `unmount(2)` returns `EBUSY`, and `zfs destroy` unmounts
before it destroys, which is why the error says *cannot unmount* rather than
*cannot destroy*. That distinction is the first useful reading of the message:
it is a VFS refusal, not a ZFS one.

That reference belongs to no process and no file, which is exactly why `fstat`
and `procstat` come up empty. The only observer is `jls`(8), and it has to be
asked properly:

```sh
jls -d -h name dying      # -d ADDS dying prisons to the live ones;
                          # the `dying` column is what tells them apart
```

Plain `jls -d` lists live jails too, so "`jls -d` printed something" means
nothing and "`jls -d` printed nothing" means *there are no jails at all*. An
earlier investigation of this defect concluded that nothing held the mount
partly on that reading.

The correlation is exact. Eleven runs of
`hack/experiments/rootfs-busy/10-teardown-busy.sh`, sampling every 250 ms and
retrying `zfs destroy` on every sample; eight of them were busy at all, and in
**all eight** the destroy succeeded in the same sample in which the prison
stopped being listed.

```
+  0.00s  mounts=[/var/db/satl/expm1-busy,] jail=DYING vnodes=2 fstat=0 procs_in_jid=0
+ 57.75s  mounts=[/var/db/satl/expm1-busy,] jail=-     vnodes=2 fstat=0 procs_in_jid=0
+ 57.75s  zfs destroy succeeded
```

**So there is a signal, and it is a level, not an edge: "no prison of this name
exists" means the rootfs is destroyable now.**

## 2. Why the prison takes so long to die

Not because of the jail, and not because of the mounts. Because of TCP.

A VNET prison cannot be dismantled while its network stack still holds protocol
control blocks, and a TCP connection **outlives the process that owned it**:
`jail_remove(2)` kills the processes, the kernel closes their sockets, and each
connection then finishes closing on its own timers with nobody attached. Every
one of those keeps the prison alive, and the prison keeps the rootfs busy.

The controls, all with the same container image, the same two epairs and the
same teardown:

| Run (capture) | What the container did | Busy for |
|---|---|---|
| `e2m1v1t0` | nothing but `sleep` | **0.00 s**, destroyed on the first try |
| `ctl-once` | one connection, **completed and closed** before teardown | **0.00 s** |
| `ctl-jailfirst` | one connection **still open**, jail deleted first | **57.75 s** |
| `ctl-server` | ran nginx; the host fetched, keep-alive left open | **57.75 s** |
| `probe-stacks` | one connection still open, **epair destroyed first** | **76.50 s** |
| `ctl-jailmsl2000` | still open, **`net.inet.tcp.msl=2000` set inside the jail** | **4.00 s** |
| `ctl-novnet` | still open, but the jail has **no VNET** (shared stack) | **0.00 s** |

Two things are pinned by that table.

**It is 2 x MSL, exactly.** `net.inet.tcp.msl` defaults to 30000 ms and the
window is 57.75 s (the teardown started about two seconds after the last
traffic); set to 2000 ms it is 4.00 s. Two times MSL, both times. Nothing else
moved it.

**It is the connection still being open that costs, not the fact that TCP was
used.** A connection the container completed and closed beforehand leaves
nothing to wait for, the prison is already gone by the first sample. Confirmed
again with the real daemon: a container looping `fetch` against another
container, removed while it was between requests, had its dataset destroyed in
under a second.

**And it is the VNET that has to be drained, not the prison as such.** The same
open connection in a jail with a *shared* network stack costs nothing: the
prison is `DYING` at the first sample and the destroy succeeds anyway. It is
dismantling a network stack with live control blocks in it that takes the
minute, which is why this only ever shows up on SatL containers, every one of
them is `vnet=new`.

Two traps around that measurement:

- **`net.inet.tcp.*` is VNET-virtualised.** Changing it on the host does not
  change it for a jail: a new VNET starts from the compile-time defaults, not
  from vnet0's current values. Two runs with the host's `msl` and
  `finwait2_timeout` lowered (`ctl-msl5000`, `ctl-fw2-5000`) measured *exactly*
  the same 57.75 s as the untouched run. The sysctl has to be set inside the
  jail, the FreeBSD base image has `/sbin/sysctl`, and a VNET jail may write
  `msl` though not `finwait2_timeout`.
- **Destroying the epair first costs another ~19 s.** `satl-agent`'s `remove`
  destroys the task's epairs and only then deletes the jail, so the container's
  FIN has nowhere to go and the connection has to time out by retransmission
  instead of closing. Deleting the jail first (`ORDER=jail-first`) brought 76.5 s
  down to 57.75 s, worth knowing, but not a fix: a minute is a minute.

Nothing in this is specific to the overlay. The reason the M3 `cleanup`
scenario exposed it and `make integration` did not is that the overlay
scenario's tasks talk to each other over TCP and are killed with a connection
open, while the single-node test's nginx only ever served a request its client
had already closed. The earlier note in the code, "an overlay task has two
epairs, and returning the extra one stretches the jail's death", had the
mechanism wrong: the second epair adds nothing measurable, and a single-epair
task with a live connection is just as slow.

## 3. What SatL does about it

Two changes, one for each half of the problem.

**The wait is keyed on the prison, not on a clock.** `Controller::destroy_rootfs`
retries the destroy every 250 ms and, on each `busy`, asks `jls` whether a
prison of that name still exists (`satl_runtime::Jails`). While one does, the
wait is expected and is logged once at info with `jail_state=DYING`. When none
does and the filesystem is *still* busy, that is the case nobody has explained,
so it waits only a few more seconds and then reports.

**Giving up is a deferral, not an abandonment.** The wait cannot simply be made
long enough: a removal is applied **inline on the agent's assignment stream**
(`satl_dispatcher::agent::apply_diff` awaits `remove_task`), so a minute spent
here is a minute in which the node applies no other assignment, including the
network teardown ordered after the task in the same batch. The budget therefore
stays at 30 s, and running out of it hands the dataset to `satld`'s **periodic
dataset sweep** (`satld::reconcile::spawn_dataset_sweep`), which runs every 20 s
off that path, compares the datasets on disk against the tasks the store and the
worker claim, and destroys what neither claims. Level-triggered, so nothing has
to be remembered and nothing can be lost; two consecutive passes must agree
before it destroys anything, so a momentarily incomplete claim set cannot cost a
live task its rootfs.

The dataset therefore disappears within roughly one sweep interval of the jail
finishing dying, about 60-100 s after a `service rm` in the worst measured case,
with no restart and no operator.

## 4. Reading it in the log

```sh
# the wait, which is normal and self-resolving
grep -a "has not finished dying" /var/log/messages

# the deferral: this dataset is now the sweep's business
grep -a "deferring it to the periodic dataset sweep" /var/log/messages

# the sweep reclaiming it, one line, with the same task_id
grep -a "periodic sweep destroyed a container dataset" /var/log/messages
```

A deferral is a warn and carries `task_id`, `dataset`, `waited_ms`,
`jail_state` and the failed `zfs` command line. It is reported once per dataset
per pass by the controller and once by the sweep; a dataset that stays busy for
several sweeps is not re-reported until it changes state, so a stuck node
produces one line, not one line every 20 s.

If a deferral is followed by no reclamation line for minutes, look for the
prison: `jls -d -h name dying | grep <task-id>`. A prison that never dies is a
different bug from this one (this one always ended, in every run measured), and
the vnode count in `mount -v` will tell you whether anything else has taken a
reference.

## 5. Reproducing

```sh
# the defect, on any FreeBSD host with ZFS and ocijail:
sudo env TCP=1 sh hack/experiments/rootfs-busy/10-teardown-busy.sh      # ~58-77 s busy
sudo env TCP=0 sh hack/experiments/rootfs-busy/10-teardown-busy.sh      # 0 s, destroyed at once
sudo env TCP=1 JAIL_MSL=2000 sh hack/experiments/rootfs-busy/10-teardown-busy.sh   # ~4 s

# on a live node, while a service is removed:
sudo sh hack/experiments/rootfs-busy/20-observe-node.sh 300
```

The scripts clone a scratch dataset outside `<zfs_root>/containers`, use a
private ocijail state db and prefix everything `expm1-`, so they can be run on a
host with a live `satld` without touching its containers.
