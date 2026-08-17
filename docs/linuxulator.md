# Running Linux images under the linuxulator (ground truth, M1)

Resolves `docs/architecture.md` §17 open question #4. Everything below was
established **empirically** on the dev server (FreeBSD 15.1-RELEASE-p2 amd64,
ocijail 0.6.0 at `/usr/local/bin/ocijail`) on 2026-08-09. Probe scripts,
hand-written OCI bundles, and verbatim outputs live in
`hack/experiments/linuxulator/` (`captures/` for outputs; file names cited
below are relative to that directory).

## TL;DR — the minimal working recipe

* Kernel: `linux.ko` + `linux64.ko` (+ auto-dep `linux_common.ko`), plus
  `linprocfs.ko`, `linsysfs.ko`, `fdescfs.ko`, `pty.ko`;
  `kern.elf64.fallback_brand=3`. All of this is what `linux_enable="YES"`
  (`/etc/rc.d/linux`) sets up.
* Rootfs: any Linux rootfs unpacked as the jail root. **Both musl (Alpine
  3.24) and glibc (Ubuntu 24.04) work** on FreeBSD 15.1 — including
  musl-static busybox, apk, apt/dpkg/perl.
* Mounts (in `config.json`, performed by ocijail at `create`): linprocfs on
  `/proc`, linsysfs on `/sys`, devfs on `/dev`, fdescfs (`linrdlnk`) on
  `/dev/fd`, tmpfs (`mode=1777`) on `/dev/shm` and `/tmp`.
* No `linux` section, no `platform` field, and no other os marker is needed
  in `config.json` — ocijail 0.6.0 ignores both. **Attribution (corrected
  after the ocijail source study, `docs/ocijail.md`): ocijail's source
  never mentions linux at all; the `linux=new` / `linux.osname=Linux` /
  `linux.osrelease=5.15.0` / `linux.oss_version=198144` parameters observed
  on the jails are applied by the kernel as defaults (seeded from the global
  `compat.linux.*` sysctls) whenever the linuxulator modules are loaded.**
  Consequence: the only gate SatL controls is "are the linux modules
  loaded" — the satl-runtime precheck.
* A non-VNET jail defaults to `ip4=inherit`/`ip6=inherit` — a server bound
  in the container is reachable on the host's addresses (proved with busybox
  httpd + curl, `captures/04-httpd-shared-ip.txt`).

Working `config.json` (verbatim from `bundles/alpine-full/`, args elided):

```json
{
  "ociVersion": "1.2.0",
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/busybox", "sh", "-c", "..."],
    "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    "cwd": "/"
  },
  "root": {"path": "../../rootfs/alpine"},
  "hostname": "expm1lx-alpine",
  "mounts": [
    {"destination": "/proc",    "type": "linprocfs", "source": "linprocfs"},
    {"destination": "/sys",     "type": "linsysfs",  "source": "linsysfs"},
    {"destination": "/dev",     "type": "devfs",     "source": "devfs"},
    {"destination": "/dev/fd",  "type": "fdescfs",   "source": "fdescfs", "options": ["linrdlnk"]},
    {"destination": "/dev/shm", "type": "tmpfs",     "source": "tmpfs",   "options": ["mode=1777"]},
    {"destination": "/tmp",     "type": "tmpfs",     "source": "tmpfs",   "options": ["mode=1777"]}
  ]
}
```

With this bundle: `echo` works, glibc/musl dynamic binaries work,
`uname -a` reports `Linux <hostname> 5.15.0 ... x86_64`, `/proc/self/maps`,
`/proc/cpuinfo`, `/proc/meminfo`, `ps` all work
(`captures/03-alpine-full-mounts.txt`, `06-ubuntu-glibc.txt`). Note:
`ocijail create` must be given an **absolute** `-b` bundle path; a relative
path fails with `bundle directory must contain config.json`.

## Host requirements

| Requirement | Value on dev server | Notes |
|---|---|---|
| Kernel modules | `linux.ko`, `linux64.ko`, `linux_common.ko`, `linprocfs.ko`, `linsysfs.ko`, `fdescfs.ko`, `pty.ko` | all loaded by `rc.d/linux`; no extra modules were needed for any experiment |
| `rc.conf` | `linux_enable="YES"` | |
| `kern.elf64.fallback_brand` | `3` (ELFOSABI_LINUX) | **required for musl/static binaries** — Alpine's busybox is an *unbranded* SYSV ELF; without the fallback brand the kernel won't run it as Linux. `rc.d/linux` sets it only if it is `-1` |
| `compat.linux.osrelease` | `5.15.0` | reported by `uname -r` in containers; per-jail overridable (`linux.osrelease` jail param) since ocijail sets `linux=new` |
| `/compat/linux` populated | `linux_base-rl9-9.7` on dev server | **NOT required for containers** — the jail root replaces it entirely (see below) |
| racct/rctl | **on** everywhere now (`kern.racct.enable=1` in `/boot/loader.conf`; the old "off on dev server" note is stale) | unrelated to linuxulator itself; resource limits are SatL's rctl problem |

`satl-agent` node description should verify: modules loaded (or loadable) and
`kern.elf64.fallback_brand=3` — that is the whole "linuxulator available"
check. `/compat/linux` content and the `linux_mounts_enable` host mounts are
irrelevant to jailed containers.

### `compat.linux.emul_path` semantics inside a jail

The linuxulator path-translation prefix (`/compat/linux`) is applied
**relative to the process root**, so inside a jail it points at
`<jail-root>/compat/linux`. Proved empirically: a file placed at
`<rootfs>/compat/linux/tmp2/marker` *shadows* `<rootfs>/tmp2/marker` for
Linux processes in the jail (`captures/expm1lx-emul.out`). Consequences:

* No host `/compat/linux` state leaks into containers; the sysctl needs no
  per-container handling.
* Corner case: an image that itself contains `/compat/linux/...` paths would
  shadow its own files. No real image does this; not worth guarding.

## glibc vs musl

Folklore says the linuxulator targets glibc and musl breaks. **Not
reproducible on FreeBSD 15.1** — the first-choice rootfs works fine:

| Rootfs | libc | Result |
|---|---|---|
| Alpine minirootfs 3.24.1 x86_64 | musl 1.2.x, dynamic **and** `busybox.static` | works: sh, echo, uname, ps, proc introspection, `apk add` (TLS + network), busybox-extras httpd serving HTTP |
| Ubuntu base 24.04.4 amd64 | glibc 2.39 | works: bash, apt-get update/install, dpkg, perl, getconf |

Caveats found: `apt-get update` with the full `universe` component died
parsing the huge package list (`Error occurred while processing ... MergeList`,
`captures/07-apt-update.txt` history); `main` alone works. systemd's dpkg
postinst fails (see failure signatures). Alpine 3.24's default busybox lacks
the `httpd` applet (`busybox-extras` provides it) — an image-content issue,
not a linuxulator one.

## Jail parameters observed via `jls -n all` (ocijail + kernel defaults)

For a bundle with *no* platform-specific config, the resulting jail carries
(ocijail-set parameters per `docs/ocijail.md`; the `linux.*` ones are kernel
defaults, see above):
`linux=new`, `linux.osname=Linux`, `linux.osrelease=5.15.0`,
`linux.oss_version=198144`, `host.hostname=<config hostname>`,
`enforce_statfs=1`, `devfs_ruleset=0`, `allow.nomount` + every
`allow.mount.no*`, `allow.raw_sockets`, `allow.reserved_ports`,
`allow.suser`, `ip4=inherit`, `ip6=inherit`, `vnet=inherit`
(full dump: `captures/03-alpine-full-mounts.txt`). Notes:

* `linux=new` means each container gets its own `linux.*` attribute set —
  SatL can later vary `osrelease` per container if an image needs it.
* Containers **cannot** mount anything themselves (`allow.nomount`): all
  mounts must be in `config.json`.
* `sysvipc` is disabled by default; images using SysV IPC (PostgreSQL is the
  canonical one) opt in per container with the `satl.jail.sysvshm=new` /
  `satl.jail.sysvsem=new` labels (api-compat #145).

## ocijail 0.6.0 behavior facts (established empirically)

1. **`config.json` needs no os/platform marker.** An empty `"linux": {}`, a
   populated `linux` section (namespaces + resources), and a legacy
   `"platform": {"os": "linux"}` field are all accepted and **silently
   ignored** (`captures/expm1lx-varA/B/C.out`). In particular
   `linux.resources.memory.limit` is *not* enforced and produces no error —
   SatL must map resources to rctl itself and must not assume OCI-level
   enforcement.
2. **Mount lifecycle** (`captures/05-mount-lifecycle.txt`):
   * mounts are performed at `create` time, by ocijail, in host context,
     recorded under the realpath of the rootfs;
   * plain `mount` does **not** list them — use `mount -p` or `mount -v`;
   * **`ocijail delete` does NOT unmount them.** They leak. `satl-runtime`
     must unmount everything under the container rootfs (deepest-first,
     from `mount -p`) after `delete` — and the startup reconciliation pass
     must do the same for orphans (extends the epair/clone gotcha in
     CLAUDE.md to mounts).
   * on a *failed* `create`, ocijail unwinds mounts but can leak nested ones
     (`/dev/fd`, `/dev/shm` under an already-unmounted `/dev` were left
     behind once) — same cleanup pass covers this.
3. **`create` validates `process.args[0]`** inside the rootfs and fails with
   `<path>: No such file or directory` — surface this verbatim.
4. **Bundle path must be absolute** (`-b`); relative paths fail bogusly
   ("bundle directory must contain config.json").
5. `state` reports `status` only — **no exit code** for stopped containers;
   the exit status must be reaped by the process that spawned `create`
   (satl-agent side, see the ocijail study in `hack/experiments/ocijail/`).

## /dev: the ruleset problem (`captures/10-devfs-ruleset.txt`)

devfs mounted with no options (ruleset 0) exposes the **entire host device
tree** (disks, bpf, consoles) — unacceptable default. ocijail passes mount
options through, so `{"type": "devfs", "options": ["ruleset=4"]}` works and
yields the classic jail set (`null zero random urandom ptmx pts fd std* zfs`).

**But ruleset 4 breaks the `/dev/shm` tmpfs mount**: devfs does not support
`mkdir` at all, and `/dev/shm` only mounts because a global `shm` directory
already exists in the devfs name tree (FreeBSD 15.1 with the linux rc script
active). Ruleset 4 hides `shm`, so ocijail's create_directory for the mount
destination gets `EOPNOTSUPP` and `create` fails:

```
filesystem error: in create_directory: Operation not supported [".../dev/shm"]
```

Proven fix: SatL ships its **own devfs ruleset** (jail includes + unhide shm):

```
devfs rule -s <N> add include 1        # devfsrules_hide_all
devfs rule -s <N> add include 2        # devfsrules_unhide_basic
devfs rule -s <N> add include 3        # devfsrules_unhide_login
devfs rule -s <N> add path shm unhide
devfs rule -s <N> add path 'shm/*' unhide
```

then mounts devfs with `options: ["ruleset=<N>"]`. Verified: device list =
jail set + `shm`, and tmpfs mounts over `shm` fine. (Same pattern as SatL's
pf anchor: own the ruleset number, install at satld startup.)

## Failure signatures (verbatim; `captures/11-failure-signatures.txt`)

### Images that expect cgroups

There is no cgroup filesystem, period. Inside the container:

```
ls /sys/fs/cgroup   ->  ls: cannot access '/sys/fs/cgroup': No such file or directory (rc 2)
cat /proc/cgroups   ->  cat: /proc/cgroups: No such file or directory (rc 1)
/proc/filesystems   ->  no cgroup entry
```

linsysfs provides only `bus class dev devices kernel` — there is no `/sys/fs`
to even hang a mountpoint on. If a (docker-derived) config *requests* a
cgroup mount, `ocijail create` hard-fails:

```
mounting {"destination":"/sys/fs/cgroup",...,"type":"cgroup2"}: Invalid argument
```

### systemd as PID 1

FreeBSD jails have no PID namespace: the entrypoint keeps its host PID and is
never PID 1. systemd 255 (Ubuntu 24.04):

* `systemd --version` → works (exit 0);
* `systemd --system` → **exit 1 with no output at all** — the container just
  dies instantly;
* kernel log (`dmesg`): `linux: jid N pid M (systemd): unsupported prctl
  option 27|39|47` (PR_MCE_KILL / PR_GET_NO_NEW_PRIVS / PR_CAP_AMBIENT);
* `systemd-detect-virt` → `none` (a jail is not detected as a container);
* even installing systemd (dpkg postinst in a chroot) fails:
  `systemd-tmpfiles` claims "/proc/ is not mounted" (statfs-magic check —
  linprocfs is not `PROC_SUPER_MAGIC`) and `Failed to take /etc/passwd lock:
  Invalid argument` (OFD-lock EINVAL).

### Detection heuristics for SatL (fail fast → `REJECTED`)

1. Platform `linux/*` and `linux.ko` missing → reject at task creation
   (already planned; confirmed necessary).
2. Resolved entrypoint argv[0] is `*/systemd`, `/usr/lib/systemd/systemd`,
   or `*/init` (Docker official images: `/sbin/init` is only ever an init
   system) → reject with: *"image runs systemd/init as PID 1; FreeBSD jails
   provide no PID namespace or cgroups, so systemd cannot run — use an image
   with a plain foreground entrypoint"*. Runtime detection is useless here:
   systemd exits 1 with zero output.
3. SatL always generates its own mount set; any `cgroup`/`cgroup2`/Linux
   `proc`/`sysfs`/`mqueue` mount coming from an imported config must be
   dropped (or rejected) explicitly — otherwise create fails with a cryptic
   `Invalid argument`.
4. Absence of cgroups can not be detected at runtime (apps just get ENOENT
   and may or may not degrade); it is a documented platform limit, not a
   detectable error.

## Known limits (document to operators)

* **No cgroups, no systemd, no PID namespace.** Container processes see host
  PID numbers (but only the jail's own processes, thanks to jail process
  visibility rules).
* `/proc/meminfo`/`/proc/cpuinfo` show **host** resources — JVM/Go-style
  auto-sizing sees the whole machine until SatL wires rctl *and* something
  like an LD_PRELOAD shim (out of scope for M1; document).
* Syscall coverage is incomplete: expect `unsupported prctl option` kernel
  logs; OFD file locks return EINVAL; anything needing netlink, cgroupfs,
  io_uring, etc. fails. `compat.linux.debug=3` (dev default) logs each
  unimplemented syscall once — valuable in bug reports.
* `uname -r` inside containers is `compat.linux.osrelease` (5.15.0), not the
  FreeBSD version; glibc keys behavior off it (do not lower it).
* SysV IPC is off in ocijail-created jails (see jail params above).
* Alpine/musl works on 15.1, but musl exercises different syscall paths than
  glibc; if an Alpine image misbehaves, retest against a glibc image before
  blaming SatL.

## Open risks for M1

1. The `shm` global devfs directory: present on 15.1 with `linux_enable`
   (and used by the host rc script); on a host where it is somehow absent,
   the `/dev/shm` mount would fail even with the unhide rule, because devfs
   mkdir is impossible. Startup check: verify `/dev/shm` exists in a devfs
   instance; if not, fall back to devfs ruleset 0 + warn, or skip the
   `/dev/shm` mount with a prominent log.
2. Exit-code harvesting: `ocijail state` never reports it; agent design must
   keep the `create` child reapable (coordinate with the ocijail study).
3. Mount cleanup after `delete` is entirely SatL's job (incl. failed-create
   unwinding) — must land in the same M1 change as linuxulator support, or
   every Linux container leaks 5–7 mounts.
4. ocijail silently ignoring `linux.resources` means a docker-compose file
   with memory limits will *appear* to work unenforced. `--memory`/`--cpus`
   must go through rctl (racct is now enabled on the dev host as well as the
   OVH VMs, so both can test enforcement).
5. Rare glibc tools care about procfs statfs magic (systemd-tmpfiles does);
   other tools may too — watch for "/proc is not mounted" class errors on
   images that otherwise should work.
