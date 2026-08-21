# ocijail 0.6.0, ground truth for `satl-runtime`

Resolves `docs/architecture.md` §17 open question #3 (exact ocijail jail
parameters / OCI FreeBSD platform spec fields).

- Runtime: **ocijail 0.6.0**, pkg `sysutils/ocijail`, `/usr/local/bin/ocijail`
  (maintainer dfr@FreeBSD.org).
- Source studied at tag `v0.6.0` of <https://github.com/dfr/ocijail>
  (checked out at `/home/fralix/src/ocijail`; the pkg binary matches the tag).
  All `file:line` citations below are relative to that tree's `ocijail/` dir.
- Live behavior verified on FreeBSD 15.1-RELEASE-p2; transcripts in
  `hack/experiments/ocijail/captures/` (referenced as *capture NN*), produced
  by the re-runnable scripts in `hack/experiments/ocijail/`.

Executive summary:

- **config.json contract**: ocijail consumes `ociVersion`, `process`
  (terminal/user/args/env/cwd), `root.path|readonly`, `mounts`, `hostname`,
  `hooks`, `annotations`. Everything else, including the entire `linux`
  section and any `os`/`platform` field, is silently ignored. There is **no
  `freebsd` platform section**; all FreeBSD knobs are annotations.
- **VNET**: request with annotation `"org.freebsd.jail.vnet": "new"`. ocijail
  only creates the isolated stack; satl-net creates the epair and pushes one
  end in with `ifconfig epairXb vnet <id>`.
- **stdio**: for `terminal:false` the container inherits fds 0/1/2 of the
  `ocijail create` invocation verbatim. satld owns the log pipe/file.
- **linux images**: ocijail has zero linuxulator code. Emulation is entirely
  satl-runtime's job (rootfs, linprocfs/linsysfs/devfs mounts, host modules).
- **exit codes**: ocijail never reports one. Watch the container pid
  (`--pid-file`) with `kqueue` `EVFILT_PROC`/`NOTE_EXIT`, which returns the
  wait(2)-format status in `data` (kqueue(2)).

---

## 1. State database and lifecycle

### 1.1 State db

- Default location `/var/run/ocijail` (`main.h:104`), overridden per
  invocation by the **global** `--root` flag (before the subcommand).
  **satld must always pass its own `--root`** so operator use of the bare
  `ocijail` CLI can never collide with us. Note `/var/run` is recreated at
  boot; that is acceptable (pids/jids in it are meaningless after reboot) but
  it reinforces that jail reconciliation cannot rely on the state db.
- Layout per container (capture 01):

  ```
  <root>/<id>/state.json    # internal state (status, pid, jid, bundle, config echo,
                            # root_path, root_readonly, file_mount_supported)
  <root>/<id>/state.lock    # flock(2)-based lock (main.cpp:132-143)
  <root>/<id>/start_wait    # fifo used by the create→start handshake
  <root>/<id>/readonly_root # only when root.readonly=true (nullfs ro alias)
  ```

  `state.json` is an implementation detail, parse only the `state`
  subcommand's stdout.

### 1.2 Status model

`created → running → stopped`. No paused, no exited-code.

- `create` writes `status=created` (`create.cpp:410`).
- `start` flips to `running` **before** the container process actually
  execs (`start.cpp:40`); the fifo handshake happens after. "running" is
  therefore *not* a liveness signal.
- "stopped" is computed lazily: `state`/`list`/`delete` probe
  `kill(pid, 0) == ESRCH` and persist the transition (`main.cpp:145-152`).
  Nothing watches the process; if satld never calls `state`, nothing updates.

### 1.3 `create` mechanics (create.cpp:97-606)

`ocijail --root R create -b <bundle> [--pid-file P] [--console-socket S]
[--preserve-fds N] <id>`, `<id>` is also the **jail name**, so it must be a
valid jail name (SatL generates safe ids; avoid dots, which mean jail
hierarchy).

1. Rejects duplicate id (`container <id> exists`).
2. Parses/validates config.json, builds the jail parameter set (§2.4).
3. Creates the state dir, performs **all mounts** (§2.3), mounts exist from
   `create` time, not `start`.
4. Creates the jail via **jail_set(2)** directly (`jail.cpp:35-44`), not
   jail(8).
5. Creates the `start_wait` fifo, then **forks**. The child is the future
   container process: it performs the console-socket handoff (tty case) or
   `setsid()` (non-tty), chdirs to the rootfs, runs `createContainer` hooks,
   **jail_attach(2)**es, and validates that `process.args[0]` exists and is
   executable (absolute path, `$PATH` from `process.env`, or cwd-relative,
   `process.cpp:165-206`). It then blocks reading the fifo.
6. The parent writes `--pid-file`, saves state (pid + jid), runs
   `createRuntime` hooks, waits for the child's validation verdict over a
   socketpair and exits with it. On validation failure everything is rolled
   back: jail removed, mounts unmounted, state deleted (`create.cpp:509-524`,
   proven in capture 06 §2, no leaks).

The reported container pid (`--pid-file`, `state`) is that forked child; it is
reparented to pid 1 once `ocijail create` exits (capture 01: `PPID 1`).

### 1.4 `start` mechanics (start.cpp:29-63)

Requires `status == created` (else
`start: container not in "created" state (currently "...")`). Runs `prestart`
hooks, writes one byte to the fifo, runs `poststart` hooks, returns
immediately, it does **not** wait for the exec. In the container the child
runs `startContainer` hooks inside the jail, then `execvp`s the workload with
the fds described in §3. Same pid before and after (capture 01).

Gotcha: `start` does not liveness-check the created child. Starting a
container whose created-process already died "succeeds" and leaves
status=running until the next `state` call notices. satld should arm its
NOTE_EXIT watch at create time, from `--pid-file`.

### 1.5 `state` / `list` output

`state <id>` prints one-line JSON on stdout (capture 01):

```json
{"annotations":{"org.freebsd.jail.jid":"12"},
 "bundle":"/path/to/bundle","id":"expm1-happy","ociVersion":"1.0.2",
 "pid":66985,"status":"created"}
```

- `ociVersion` is hardcoded `"1.0.2"` (`main.cpp:109`).
- `pid` is present unless `status == "stopped"`.
- `annotations` = the config's annotations plus an injected
  `org.freebsd.jail.jid` (string!) while the state entry exists
  (`main.cpp:120-128`). SatL can round-trip task metadata through
  annotations and read the jid from here.
- No exit code, no timestamps.

`list -f json` prints `[{"bundle":…,"id":…,"pid":…,"status":…}]` (pid 0 when
stopped); no annotations, and **no trailing newline**, `list.cpp` ends with a
bare `std::cout << res`.

**An empty state db prints the JSON literal `null`, not `[]`**, four bytes,
exit 0 (measured on 0.6.0). `list::run` default-constructs `json res`, which is
of type *null* until the first `push_back` makes it an array, and prints it
however it stands. Two distinct cases produce it: a state root that exists and
is empty, and one that holds only directories with no readable `state.json`
(`state.exists()` is `is_regular_file(state.json)`, `main.h:49`). A state root
that does **not** exist is different again: `fs::directory_iterator` throws, so
the command *fails* with `filesystem error: in
directory_iterator::directory_iterator(...): No such file or directory` on
stderr. So "no containers" has two shapes, one of them an error exit, and
neither is a real failure, `satl_runtime::Ocijail::list` maps both to an empty
list (fixtures `ocijail_list_empty.json` and `ocijail_err_list_no_statedb.txt`).
Treating the `null` as a parse error is what put a false ERROR in
`/var/log/messages` on every clean startup.

`features` prints hooks + mount options and claims
`ociVersionMax 1.2.0` (`features.cpp:75`) even though `create` accepts 1.3.x,
don't gate on `features`.

### 1.6 Exit-code retrieval (satl-agent `wait`)

ocijail provides **no exit status anywhere**. The container process is not
satld's child (reparented to init). Obtain the code with
`kqueue`/`EVFILT_PROC`/`NOTE_EXIT` on the pid from `--pid-file`: "The exit
status will be stored in data in the same format as the status returned by
wait(2)" (kqueue(2), verified on this host). Race note: open the kqueue before
calling `start`; if `kevent` registration fails with ESRCH the process already
exited and only `status=stopped` (no code) is recoverable. Polling
`ocijail state` is the fallback and yields no exit code.

---

## 2. config.json contract

### 2.1 Consumed fields

| Field | Rules (source) |
|---|---|
| `ociVersion` | required; `1.0.x`–`1.3.x`, `-rc.N`/`-dev` suffixes ok (`create.cpp:119-130`) |
| `process` | required object (`create.cpp:132`, `process.cpp:19-132`) |
| `process.terminal` | bool, default false; governs §3 |
| `process.user` | optional; `uid`+`gid` required numbers when present (default 0/0); `additionalGids` array; **`umask` is parsed but never applied**, dead assignment after throw (`process.cpp:70-73`), effective umask is always 077 (`process.h:76`) |
| `process.args` | required non-empty array of strings; `args[0]` resolution per §1.3 |
| `process.env` | optional array `"K=V"`; `HOME` forced to `/` if unset/empty (`process.cpp:268-272`); `PATH` used for args[0] lookup |
| `process.cwd` | **required** string; chdir inside the jail before exec |
| `root.path` | optional, default `<bundle>/root`; must be a directory; relative paths resolve against the bundle (create chdirs there, `create.cpp:104`). SatL passes the absolute ZFS clone mountpoint |
| `root.readonly` | optional; remounts the rootfs read-only via a nullfs alias under the state dir (`create.cpp:425-442`) |
| `mounts` | optional array, §2.3 |
| `hostname` | optional; sets `host=new` + `host.hostname`; absent ⇒ `host=inherit` (`create.cpp:394-399`) |
| `hooks` | `prestart`, `createRuntime`, `createContainer`, `startContainer`, `poststart`, `poststop` (`create.cpp:199-212`); state JSON on hook stdin; `path` must be absolute (execve, no PATH, `hook.cpp:165-166`); `timeout` parsed but **not enforced** (`hook.cpp:144`) |
| `annotations` | echoed into `state`; FreeBSD extensions per §2.2 |

### 2.2 FreeBSD extensions, annotations only

There is **no `freebsd` platform section** and no `os`/`platform` check
anywhere in the source. The only platform knobs are annotations
(`create.cpp:218-302`):

| Annotation | Values | Effect |
|---|---|---|
| `org.freebsd.jail.vnet` | `new` \| `inherit` (default `inherit`; `disable` rejected) | `new` sets jail param `vnet=new` (isolated network stack); `inherit` shares the host stack |
| `org.freebsd.jail.ip4.addr` / `org.freebsd.jail.ip6.addr` | comma-separated literal addresses | **only honored when vnet is inherited**: sets `ip4=inherit` + `ip4.addr=<list>` (classic address-pinned jail, live in capture 05). Never read when `vnet=new` (`create.cpp:256-264`). (`ip6.add` is accepted as a legacy typo alias, `create.cpp:262`) |
| `org.freebsd.jail.sysvmsg` / `sysvsem` / `sysvshm` | `new` \| `inherit` \| `disable` | corresponding jail params; kernel default when absent is `disable` (capture 01) |
| `org.freebsd.jail.allow.<param>` | `"true"` / `"1"` as **strings** | enables the allow param; whitelist of 25 (`create.cpp:274-288`): adjtime, chflags, extattr, mlock, mount, mount.devfs, mount.fdescfs, mount.nullfs, mount.procfs, mount.tmpfs, mount.zfs, nfsd, quotas, raw_sockets, read_msgbuf, reserved_ports, routing, set_hostname, setaudit, settime, socket_af, suser, sysvipc, unprivileged_parent_tampering, unprivileged_proc_debug. Unknown params ⇒ warning + ignored |
| `org.freebsd.parentJail` | existing jail name | creates the container as a child jail `<parent>.<id>`; bumps the parent's `children.max` if needed; inherits `allow.chflags` restriction down |

**VNET verdict (load-bearing for satl-net, capture 05):** ocijail creates the
isolated stack (`jls … vnet` → `new`; the jail sees only a DOWN `lo0`). It
does nothing else. satl-net must: `ifconfig epair create`, `ifconfig epairXb
vnet <jail-name-or-jid>`, configure addresses either from the host via
`ifconfig -j <jail> …` or via an in-container process. Verified: ping across
the epair works; **when the jail is removed the in-jail end returns to the
host vnet automatically** (capture 05), reconciliation can find and destroy
returned `epairXb` orphans by name.

### 2.3 Mounts (mount.cpp)

Shape: `{"destination": "<abs path in container>", "type": "<fstype>",
"source": "<path|token>", "options": ["..."]}`.

- `type` defaults to `nullfs`; `"bind"` is aliased to `nullfs`
  (`mount.cpp:362-367`). `source` is the nullfs target. Everything goes
  through nmount(2) **from the host at create time**, in-jail mount
  permissions (`allow.mount.*`) are irrelevant.
- Proven fstypes (capture 01): `nullfs` (with `ro`), `tmpfs` (with
  `size=1m`, perfect for the secrets tmpfs, invariant #7), `devfs` (with
  `ruleset=4`; `ls /dev` shows the jail-safe device set). linprocfs/linsysfs
  work the same way (see `hack/experiments/linuxulator/`).
- `destination` is resolved inside the rootfs with symlink-escape protection
  (`mount.cpp:182-242`); missing mountpoint dirs/files are created and
  recorded in state for removal at delete (`mount.cpp:288-348`).
- Options: the table at `mount.cpp:21-56` maps names to MNT_ flags (`ro`,
  `rw`, `rdonly`, `noexec`→via `exec`, `nosuid`→via `suid`, `async`, `sync`,
  `union`, `force`, `update`, `snapshot`, …); `private`, `rprivate`, `rbind`,
  `nodev`, `bind` are **accepted and ignored** (Linux-ism compat). Unknown
  `key=value` options pass straight through to nmount (that is how
  `ruleset=4` and `size=1m` work). Pseudo-options: `tmpcopyup` (tmpfs:
  copies the image's directory content onto the fresh tmpfs) and `rule`
  (devfs: runs `/sbin/devfs -m <dst> rule apply <rule>` after mounting,
  `mount.cpp:110-162`).
- nullfs file-mounts (regular-file source) are supported, with a copy
  fallback on kernels without file nullfs (`mount.cpp:417-452`).
- Failure of any mount ⇒ create fails, prior mounts are unmounted
  (`mount.cpp:499-515`). ENOENT on a nullfs source yields the operator-grade
  message `…source path does not exist: <path> (create the directory first)`.

### 2.4 Jail parameters ocijail always sets

From `create.cpp:304-399`, confirmed by the live `jls -n all` dump in
capture 01:

| Param | Value |
|---|---|
| `name` | `<id>` (or `<parent>.<id>`) |
| `persist` | set, the jail outlives its processes until `delete` |
| `enforce_statfs` | `1` |
| `allow.raw_sockets` | true (ping works by default) |
| `allow.chflags` | true (unless a parentJail has it off) |
| `path` | rootfs (or the read-only nullfs alias) |
| `host` | `new` + `host.hostname` when config has `hostname`, else `inherit` |
| network | `vnet=new` **or** `ip4=inherit`,`ip6=inherit` (+ `ip4.addr`/`ip6.addr` lists) |

Not set (kernel defaults apply, capture 01): `devfs_ruleset=0` (device
visibility comes from the devfs **mount's** `ruleset=` option, not the jail
param), `children.max=0` (no nested jails), all `allow.mount.*` off,
`sysv*=disable`, no rctl/racct coupling, no `linux.*` params. There is **no
way to set arbitrary jail parameters** through ocijail 0.6.0 beyond the
whitelisted `allow.*` annotations, if SatL ever needs e.g. `linux.osname` or
`devfs_ruleset`, that requires an ocijail patch or `jail_set(JAIL_UPDATE)`
after create (avoid: invariant #6 says drive the runtime, and out-of-band
tampering fights its state model).

### 2.5 Ignored and rejected fields

**Silently ignored** (never read): `process.capabilities`, `process.rlimits`,
`process.noNewPrivileges`, `process.oomScoreAdj`, `process.consoleSize`,
`process.apparmorProfile`, `process.selinuxLabel`, the entire `linux` section
(namespaces, resources/cgroups, seccomp, devices), `solaris`/`windows`/`vm`
sections, `domainname`, and any `os`/`arch`/`platform` declaration. SatL must
therefore enforce its own resource limits (rctl) and must not assume any
seccomp/capability semantics.

**Rejected** (`malformed_config`, exit 1): structural violations of the
consumed fields, missing `process`, missing `process.cwd`, empty
`process.args`, wrong JSON types, malformed/unsupported `ociVersion`,
`hostname`-less configs are fine. Full texts in capture 06.

---

## 3. stdio and logging (the `satl logs` pattern)

Proven in capture 02 (`procstat -f` + late-write test):

- **terminal:false (SatL's default)**: the container process inherits fds
  0/1/2 of the `ocijail create` invocation **verbatim** and `setsid()`s
  (`process.cpp:214-225`, `create.cpp:528`, exec dup2 at
  `process.cpp:300-310`). `ocijail create` exits after validation; the fds
  live on in the container for its whole life. Both regular files and pipes
  work (capture 02 has both).

  **satld pattern**: open the per-task log sinks (files or pipes into the log
  multiplexer), spawn `ocijail create` with `stdin=/dev/null`,
  `stdout/stderr=sinks`, keep reading. Nothing else is needed. No fd is ever
  passed *to* a running ocijail; `--preserve-fds N` additionally keeps fds
  `3..3+N-1` open into the container (runc convention), everything else is
  closed via `close_range(…, CLOSE_RANGE_CLOEXEC)` (`process.cpp:310`).

- **terminal:true**: `create` requires `--console-socket <path>` pointing at
  an **already-listening** unix socket; ocijail allocates the pty, makes the
  slave the container's stdio + controlling tty, and sends the master fd over
  the socket via `SCM_RIGHTS` (`tty.cpp:15-101`). `terminal:false` +
  `--console-socket` is an error, as is `terminal:true` without it (both
  texts in capture 02). satld implements the SCM_RIGHTS receive for
  `satl run -t` / `satl exec -t`.

- **stderr pollution**: create-time validation errors from the forked child
  are written raw to inherited fd 2 (`create.cpp:573-574`), i.e. into the
  container's stderr sink. On non-zero `create` exit, satld should treat the
  stderr sink's content as runtime error text, not container output.

---

## 4. exec / kill / delete semantics

### 4.1 exec (exec.cpp)

```
ocijail --root R exec <id> --process <process.json> [--tty|-t] [--detach|-d]
        [--console-socket S] [--pid-file P] [--preserve-fds N]
```

- `--process` is **required**; the file has exactly the schema of
  `config.json`'s `process` object. There is no inline-args form (capture 04:
  CLI11 error, exit 106).
- Non-detached: the ocijail process itself `jail_attach`es and `execvp`s,
  its stdio is the exec's stdio and **its exit code is the process's exit
  code** (proven: exit 7). This is the `satl exec` streaming pattern: hold
  the pipes on the ocijail child.
- `--detach`: fork; parent exits 0 after in-jail validation of args[0];
  `--pid-file` gives the exec pid (NOTE_EXIT again for its code). This is the
  form **healthcheck probes use** (`satl_agent::health`), and the pid is the
  reason: a non-detached exec's exit code is ocijail's own, which is simpler,
  but the process is then only reachable through the `tokio::process::Child`
  handle, and dropping that handle on a timeout does **not** kill the child
  (`kill_on_drop` is false by default), so an abandoned probe would keep
  running inside the jail. With `--detach` + `--pid-file` the prober owns a
  pid it can `kill(2)` when the timeout fires (`satl_runtime::procs`), and it
  harvests the status with the same kqueue `NOTE_EXIT` watch as a container's.
  Nothing needs to reap: the probe is reparented to init, exactly like the
  container process (§1.3).
- `--tty` overrides `process.terminal` (`exec.cpp:54-56`); detached tty
  requires `--console-socket`.
- Target lookup is by `jid` from the state db (`exec.cpp:68`): exec works in
  `created` and even `stopped` state while the persist jail exists (proven).
  After `delete` it fails with the state-lock error (§6). **Consequence for
  healthchecks**: a probe against a container whose workload has already died
  still runs, `jail_attach` + `execvp` in an empty prison, so a probe can
  even *succeed* on a dead container. Health is therefore never the liveness
  signal (that is the exit watch), and the prober is stopped by the controller
  as soon as the task shuts down or is removed.
- exec'd processes are **invisible to ocijail** (state db untouched); they
  die at `delete` via jail_remove. That is the backstop, not the plan: a probe
  still running when the jail is deleted is a process the kernel kills inside a
  prison that then has to drain, and if the probe held a TCP connection the
  prison stays `DYING` for 2 x MSL with the rootfs busy
  (`docs/jail-teardown.md`). `Prober::stop` kills the in-flight probe *before*
  the delete for that reason.

### 4.2 kill (kill.cpp:32-73)

- Sends the signal **to the container init pid only**. `--all`/`-a` and
  `--pid`/`-p` are parsed in 0.6.0 but never read by `kill::run()`, verified
  live: with `--all`, a grandchild survived init's SIGTERM exit (capture 03).
  Orphaned processes keep running in the persist jail until `delete`.
- Signal argument: number, or **uppercase** FreeBSD `sys_signame` name
  without the SIG prefix (`TERM`, `KILL`, `WINCH`). `term` and `SIGTERM` fail
  with `Unknown signal name …` (capture 03). satl-runtime should always pass
  numeric signals to sidestep naming entirely.
- Allowed in `created` and `running`; on `stopped` it's a **silent no-op
  (exit 0)**; unknown id ⇒ state-lock error, exit 1. ESRCH is swallowed.
- Task-shutdown recipe (architecture §8.2): `kill <id> 15` (or the image's
  stop_signal) → await NOTE_EXIT ≤ grace → `kill <id> 9` → `delete <id>`
  (delete's jail_remove reaps orphaned children, always delete promptly
  after observed exit).

### 4.3 delete (delete.cpp:32-98)

State machine (crun-compatible): `stopped` ⇒ proceed; `created` ⇒ SIGKILL
init, proceed; `running` ⇒ error
`delete: container not in "stopped" or "created" state (currently "running")`
unless `--force` (SIGKILL, proceed). Cleanup order:

1. `jail_remove(2)`, kills **every** process still in the jail;
2. unmount all config mounts (MNT_FORCE; EINVAL i.e. already-unmounted
   tolerated) and remove auto-created mountpoints;
3. unmount the read-only rootfs alias if any;
4. run `poststop` hooks;
5. remove the state dir.

**Idempotency trap**: `delete` of an id with no state db entry returns
**exit 0** and cleans nothing (`delete.cpp:36-41`), "never existed",
"already deleted" and "state lost but jail alive" are indistinguishable.
Proven in capture 03: a jail whose state entry is missing survives
`ocijail delete` untouched.

### 4.4 Crash windows / what leaks

`create`'s order is: state dir → mounts → jail_set → fifo → fork →
state.json save (`create.cpp:416-486`). If satld or ocijail dies mid-create:

- before the jail: leaked **mounts** under the rootfs + state dir without
  state.json;
- after the jail: additionally a leaked **persist jail** named `<id>`;
- `ocijail delete <id>` then "succeeds" while removing only the state dir.

The args[0]-validation failure path is self-cleaning (capture 06 §2: no jail,
no state, no mounts). Everything else is on satld's startup reconciliation
(CLAUDE.md gotcha): enumerate `jls` names by SatL's id scheme, `jail -r`
strays, unmount anything under container rootfs mountpoints (deepest first),
destroy orphaned epairs (both in-jail ends returned to the host and never-
attached pairs). The experiment scripts' `std_cleanup` in
`hack/experiments/ocijail/common.sh` is a working model.

---

## 5. Linux-image handling

`grep -ri linux` over the ocijail 0.6.0 source matches nothing at all:
**ocijail has no linuxulator awareness whatsoever**. It never reads an `os`
field; it will happily create the jail and `execvp` whatever `process.args`
names, the kernel's ELF branding decides that a Linux binary runs under the
linuxulator ABI.

Consequences for satl-runtime when the resolved platform is `linux/*`
(architecture §8.1, open question #4):

- satld must verify host prerequisites itself (`linux64.ko` et al.,
  `sysctl compat.linux.*`) and fail the task `REJECTED` if missing,
  ocijail will produce only a confusing exec error.
- The bundle must carry the full emulation mount set as ordinary `mounts`
  entries (linprocfs on `/proc`, linsysfs on `/sys`, devfs on `/dev`, tmpfs
  on `/dev/shm`), ocijail mounts them host-side, so `allow.mount.*` being
  off is irrelevant. The working mount set lives in
  `hack/experiments/linuxulator/` (question #4's experiments).
- `linux.*` jail parameters (per-jail uname override) **cannot** be set
  through ocijail 0.6.0 (§2.4); the global `compat.linux.osrelease` sysctl is
  what containers see.

---

## 6. Error output format (wrapper contract)

Three distinct channels (captures 00, 02, 03, 06):

1. **Runtime errors**, one line on stderr, exit **1**:

   ```
   2026-08-09T19:37:44000129436Z: root directory "/nonexistent/expm1-rootfs" must be a directory
   ```

   Timestamp gotcha: `%Y-%m-%dT%H:%M:%S` + **9-digit zero-padded
   microseconds** + `Z`, with no `.` separator (`main.cpp:198-207`), do not
   feed it to an RFC3339 parser; strip everything up to `": "`.
   With `--log-format json`: single-line
   `{"level":"error","msg":"...","time":"..."}` on stderr, **recommended for
   the wrapper**. With `--log FILE`: the line goes to the file and stderr
   gets `Error: <msg>` instead.

2. **create-child validation errors**, raw message, no timestamp, written
   to the *inherited* stderr (the container's stderr sink), exit 1,
   regardless of `--log-format`:

   ```
   /bin/no-such-binary: No such file or directory
   'no-such-binary' not found in $PATH: No such file or directory
   ```

3. **CLI11 usage errors**, human text + `Run with --help for more
   information.`, exit **105** (validation, e.g. `--bundle` dir missing) or
   **106** (missing required option). Any exit > 1 means the wrapper built a
   bad command line, not a runtime failure.

Message catalogue for classification (exact strings, capture 03/06):

| Situation | stderr message (after timestamp) | exit |
|---|---|---|
| duplicate id | `container <id> exists` | 1 |
| unknown id (`state`/`start`/`kill`/`exec`) | `opening state lock: No such file or directory` | 1 |
| unknown id (`delete`) | *(silent)* | **0** |
| bad rootfs | `root directory "<path>" must be a directory` | 1 |
| missing config | `create: bundle directory must contain config.json` | 1 |
| malformed config | `create: malformed config: <detail>` | 1 |
| bad version | `create: unsupported OCI version <v>` | 1 |
| start not-created | `start: container not in "created" state (currently "<s>")` | 1 |
| delete running | `delete: container not in "stopped" or "created" state (currently "running")` | 1 |
| bad signal | `Unknown signal name <s>` | 1 |

Note the "container `<id>` not found" message in `main.cpp:96-98` is
effectively unreachable (the lock open at `main.cpp:132-143` fails first);
**map the `opening state lock` ENOENT message to NotFound**.

---

## 7. Gotchas (condensed)

1. `status=running` is set before the workload execs; `stopped` is detected
   only when someone calls `state`/`list`/`delete`. Poll or watch NOTE_EXIT.
2. No exit codes from ocijail, ever, kqueue `EVFILT_PROC`/`NOTE_EXIT` on the
   `--pid-file` pid (§1.6).
3. `kill --all` is a no-op flag in 0.6.0; only init is signalled. Orphans die
   at `delete` (jail_remove). Never leave a stopped container undeleted.
4. Signal names must be uppercase, un-prefixed (`TERM`); prefer numbers.
5. `delete` of an unknown id exits 0 and cleans nothing; orphaned jails and
   mounts need satld's reconciliation (§4.4).
6. `process.user.umask` is dead code (always 077); set permissions via the
   image or entrypoint.
7. `features` underreports `ociVersionMax` (1.2.0 vs accepted 1.3.x).
8. Error timestamps are not RFC3339 (9-digit micros, no dot).
9. Mounts happen at `create` and persist while merely "created", a create
   that is never started still holds devfs/tmpfs/nullfs mounts until delete.
10. The container id is the jail name, enforce SatL's id charset before it
    reaches ocijail; ids with `.` would imply jail hierarchy.
11. devfs visibility is controlled by the mount option `ruleset=N` (+ `rule`
    pseudo-option), not the `devfs_ruleset` jail param (stays 0).
12. `enforce_statfs=1`, `children.max=0`, all `allow.mount.*` off: processes
    inside containers cannot mount or create jails; all mounts must be in the
    bundle.
13. `--console-socket` must exist and be listening before `create`; ocijail
    connects (connectat) and sends the pty master via SCM_RIGHTS.
14. VNET: ocijail only sets `vnet=new`. epair plumbing, addressing and
    cleanup are satl-net's job; jail removal returns in-jail epair ends to
    the host (capture 05), reconcile them.
15. `org.freebsd.jail.allow.*` values must be JSON **strings** `"true"`/`"1"`
    (a bare JSON `true` is ignored by the `value.is_string()` check,
    `create.cpp:291`).
16. A detached `exec` is the only exec form whose process satld can signal
    later (§4.1), healthcheck probes need that, because a probe that outlives
    its timeout has to be killed rather than dropped.
17. **`delete` returning is not the jail being gone.** `jail_remove(2)` leaves
    the prison `DYING` until its last reference goes, and a dying prison still
    holds its root vnode, so the rootfs cannot be unmounted and `zfs destroy`
    fails with `cannot unmount …: pool or dataset is busy`. With an open TCP
    connection in the jail at that moment it stays dying for 2 x
    `net.inet.tcp.msl` (60 s by default). ocijail cannot be asked about it (the
    state entry is already gone); `jls -d -h name dying` is the only observer.
    Measurements and what SatL does about it: `docs/jail-teardown.md`.

---

## 8. Experiment map

Re-runnable scripts (cleanup-trapped, `expm1-` prefixed, private `--root`):
`hack/experiments/ocijail/{mkrootfs,run-all,00-cli-surface,01-happy-path,02-stdio,03-kill-delete,04-exec,05-vnet,06-failures}.sh`.

| Capture | Contents |
|---|---|
| `captures/00-cli-surface.txt` | full `--help` tree, `features`, default-root probe, error formats |
| `captures/01-happy-path.txt` | create→state→start→state→exit→state→delete; state db layout; internal state.json; **full `jls -n all` param dump**; devfs/tmpfs/nullfs mounts; ps proof of the fork model |
| `captures/02-stdio.txt` | fd-inheritance proof (`procstat -f`), file + pipe log sinks, late-write proof, tty validation errors |
| `captures/03-kill-delete.txt` | signal-name matrix, init-only delivery, `--all` no-op, SIGKILL, delete state machine, unknown-id delete, orphan-jail hazard |
| `captures/04-exec.txt` | process.json exec, rc propagation (7), detach + pid-file, exec into created/stopped/deleted, missing `--process` usage error |
| `captures/05-vnet.txt` | vnet=new annotation → isolated stack; epair push-in, `ifconfig -j` config, ping proof, epair auto-return on delete; ip4.addr inherit variant |
| `captures/06-failures.txt` | every classified error string + exit code, rollback proof, `--log`/`--log-format` variants |

Raw per-container logs (`captures/expm1-*.log`) are fixture candidates for
`satl-runtime`'s parser tests.
