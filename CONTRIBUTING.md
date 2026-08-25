# Contributing to SatL

SatL is a cluster-first container engine for FreeBSD. Contributions are
welcome. This file exists because there is **no CI**: nothing runs when you open
a pull request, so the checks are yours to run and yours to show.

## What you need

FreeBSD 15.1 amd64, with ZFS, jails, `pf` and [`ocijail`](https://github.com/cperciva/ocijail).
No other platform is built or tested. That is also why there is no hosted CI --
no runner offers this combination.

`cargo build` is the only build requirement: the protobuf definitions are
compiled by a pure-Rust compiler, so there is no `protoc` and no C++ toolchain
in the path of a build.

## The gate

```sh
make check
```

**`make check` must be green before any commit.** It is the whole gate: SPDX
headers, `cargo fmt --check`, `clippy --all-targets -D warnings`, the OpenAPI
contract, and the workspace test suite. Paste its output in the pull request.

Two more suites are not part of `make check`, because they need root or three
machines. Run the one your change touches:

```sh
sudo make integration   # networking, runtime, storage: jails, ZFS, pf, real ocijail
make cluster-test       # cluster behaviour: the 3-VM scenario suite
```

`sudo make integration` is not optional for a networking, runtime or storage
change. That rule exists because a networking change was once committed without
it and broke the suite.

## Definition of done

A change is not done until, in the same commit:

- `make check` is green;
- `docs/roadmap.md` reflects any milestone item started, advanced or completed
  -- it is the live project status, and its decision log records **measured**
  findings, not intentions;
- `docs/architecture.md` is updated if the change alters a design it describes,
  including the §2 crate-dependency table when a new internal edge appears, and
  §15 when a default moves (defaults have one home, `satl_core::defaults`);
- `docs/api-compat.md` has a numbered entry for any new divergence from Docker's
  behaviour;
- the integration or cluster suite has actually been run, when the rule above
  says so.

## The eight invariants

`CLAUDE.md` lists eight numbered invariants. Docs and module comments cite them
by number, so **the numbering is stable and load-bearing: extend it, never
renumber**. In short:

1. All cluster state lives in the Raft store; manager components talk only
   through it.
2. Every container is a Task of a Service, `satl run` included. Tasks are
   immutable and one-shot.
3. Workers dial managers, never the reverse.
4. Raft apply is pure in-memory -- no I/O, no syscalls, no awaits but the store
   lock.
5. ZFS is mandatory; there is no fallback storage driver.
6. SatL never implements a runtime; it drives `ocijail`.
7. Secrets never touch a worker's disk, and error messages name the object,
   never the payload.
8. The Docker REST API is the only external surface, and every deviation gets a
   number in `api-compat.md`.

If a change seems to need an invariant broken, that is a design discussion
first. Open an issue before writing the code.

## House style

- Edition 2024, rustc >= 1.96, `unsafe_code = "deny"` workspace-wide.
- `clippy::pedantic` is on. **Triage, do not blanket-allow.** The four workspace
  allows each carry their reason; anything else is fixed, or allowed locally
  with a comment saying why.
- Every source file carries its SPDX line first; `make check` enforces it.
  Fixture files are data, not source, and stay headerless.
- **No raw `Command::new` in business logic.** Each crate that shells out owns a
  `CommandRunner` trait, so argv construction and output parsing are unit-
  testable without privileges.
- `thiserror` in libraries, `anyhow` only in binaries. Every external-command
  failure carries the full argv, the exit status and the raw stderr: an
  operator must see exactly what was attempted.
- **Operator-facing text is ASCII-only.** syslogd rewrites bytes in `0x80`-`0x9f`
  irrecoverably, so UTF-8 punctuation arrives mangled in `/var/log/messages`.
- Attach spans with `.instrument()`; never hold a `span.enter()` guard across an
  `.await`.

## Tests

Write the test that would have caught the bug, and check that it *does*: a
regression test that passes against the broken code is worse than none, because
it reads as coverage. Several tests in this tree carry a comment naming what
they would fail against, and that habit is worth keeping.

Unit tests live beside the code, with fixtures under `crates/*/tests/fixtures/`
captured from real FreeBSD command output. Root-only tests are `#[ignore]`-gated
and run through `make integration`. Container images for them come from the
loopback test registry, never Docker Hub.

In `tests/cluster/`: POSIX `sh`, `set -e`, every `ssh` in `BatchMode=yes` -- a
script may fail, but must never wait for a password or a host-key prompt. Node
addresses live in `tests/cluster/inventory.toml` **only**.

## Reporting a bug

Say what you ran, what you expected, and what happened, with the daemon's own
words: `grep -a satld /var/log/messages`. **Always `grep -a`** -- one non-ASCII
byte anywhere in that file makes plain `grep` print nothing at all, which looks
exactly like "the daemon logged nothing".

Security issues go to the address in [SECURITY.md](SECURITY.md), not to the
issue tracker.

## Licence

BSD-2-Clause. By contributing you agree your work is licensed under it.
