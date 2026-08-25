# SatL

**A cluster-first container engine for FreeBSD.** SatL runs OCI containers as
FreeBSD jails, via the [ocijail](https://github.com/cperciva/ocijail) runtime,
with swarm-style orchestration built in: an embedded Raft store, a scheduler,
desired-state reconciliation, VXLAN overlay networking, an ingress routing
mesh, and mTLS everywhere. It speaks the Docker Engine API and mirrors the
Docker CLI, so existing tooling works against it.

```console
$ satl service create --name web --replicas 3 -p 8080:80 freebsd-nginx:latest
$ satl stack deploy -c compose.yaml shop
$ satl service update --limit-memory 512m web     # hot resize: no restart
```

There is no "standalone mode": a single node is a cluster of one, and every
container is a task the orchestrator watches. A fresh daemon self-initialises
its cluster, there is nothing to `init`.

## What it does today

- **Containers as jails**, one VNET jail per task, ZFS clones for layers and
  rootfs, `linux/amd64` images under the linuxulator as a first-class fallback.
- **A real cluster**, `satl swarm join` with pinned-CA tokens, mTLS on every
  internal connection, automatic certificate renewal and live CA rotation,
  manager autolock (the Raft DEK sealed under an operator-held unlock key).
- **Swarm semantics**, replicated, global, and job services
  (`replicated-job` / `global-job`), rolling updates with health-gated batches
  and automatic rollback, restart policies, placement constraints *and*
  preferences (`spread=node.labels.zone`), hot vertical resize (a
  resources-only update rewrites the live jails' `rctl` rules, no roll).
- **Networking**, VXLAN overlays with DNS service discovery, an ingress
  routing mesh in pf (every manager answers every published port), and an
  opt-in L4 PROXY-protocol mode for services that need the real client
  address.
- **Encrypted overlays**, opt-in per network (`--opt encrypted`):
  IPsec ESP (AES-128-GCM) on the VXLAN data plane between nodes, per-network
  keys delivered to participant nodes only, automatic 12h rotation.
- **Images**, pull from any OCI registry, or build FreeBSD images with
  `satl build` and a `Satlfile`: multi-layer with an incremental cache,
  multi-stage (`FROM x AS builder` → `COPY --from=builder`, down to
  `FROM scratch` images of a few MB), and `satl tag` + `satl push` to share
  the result through a registry.
- **Compose & stacks**, `satl compose` and Docker's `satl stack` verbs over
  standard compose files, with stack (not single-host) semantics.
- **Secrets & configs**, encrypted at rest in the Raft log, delivered on a
  per-task tmpfs, never on a worker's disk.
- **Metrics**, a Prometheus `/metrics` endpoint (off by default) with
  Docker's own series names where they exist.

The honest list of what is *not* there (IPv6, shared
storage, and their workarounds) lives in
[docs/roadmap.md](docs/roadmap.md) and in the
[user documentation's out-of-scope page](https://github.com/fredericalix/satl-doc).

## Requirements

- **FreeBSD 15.1 on amd64**, nothing else is built or tested;
- **ZFS**, mandatory, not a storage driver among others;
- **ocijail**, `pkg install ocijail`;
- root, for the daemon and the build's packaging steps;
- Rust stable (`x86_64-unknown-freebsd`) to build from source.

## Build, install, package

```sh
make build            # debug build of satl + satld
make release          # release build into target/release
sudo make install     # binaries + rc.d script + sample config
make package          # dist/satl-<version>.pkg + dist/CHECKSUM.SHA512,
                      # installable anywhere with `pkg add ./satl-0.2.0.pkg`
                      # (no repository needed)
```

The package is built locally and is **not signed**, there is no pkg repository
to point `pkg install` at, and SatL is not in the FreeBSD ports tree. Verify a
package you did not build yourself against `dist/CHECKSUM.SHA512`. Publishing a
signed repository and submitting a port are both out of scope until the API and
the on-disk layout stop moving.

Then, on the host (details in [docs/operations.md](docs/operations.md)):

```sh
zfs create -o mountpoint=/var/db/satl zroot/satl    # SatL refuses to start without it
sysrc gateway_enable=YES pf_enable=YES              # forwarding + pf with the satl/* anchors
sudo cp /usr/local/etc/satl/satld.toml.sample /usr/local/etc/satl/satld.toml
sudo sysrc satld_enable=YES && sudo service satld start
```

## Development

```sh
make check            # fmt, clippy -D warnings, full test suite, the only gate
sudo make integration # root-only integration tests (jails, ZFS, pf)
make cluster-test     # the 3-node scenario suite (tests/cluster/)
```

`make check` must be green before any commit.

**CI runs `make check` on FreeBSD, and that is all it can run.** A pull request
gets one gate, on Cirrus (`.cirrus.yml`) — GitHub's runners have no FreeBSD
image, so the workspace would not even compile there. What CI *cannot* run is
the other two suites: `sudo make integration` needs real jails, ZFS datasets,
pf anchors and `ocijail` on the machine, and `make cluster-test` needs three
networked FreeBSD hosts. Those stay the contributor's and the maintainer's job.
A green tick therefore means "this compiles, lints and passes the unit tests on
FreeBSD", not "this works".

See [CONTRIBUTING.md](CONTRIBUTING.md) for which suite a change is expected to
have run, the eight invariants, and the definition of done.

Release history is in [CHANGELOG.md](CHANGELOG.md). The design rationale lives in
[docs/architecture.md](docs/architecture.md), the Docker API deviations are
numbered in [docs/api-compat.md](docs/api-compat.md), and milestone history
with its measured findings is in [docs/roadmap.md](docs/roadmap.md).
Contributors: read [CLAUDE.md](CLAUDE.md) first.

The user-facing documentation site (tutorials, guides, reference) is built
from the [satl-doc](https://github.com/fredericalix/satl-doc) repository,
including a full [Node.js + MariaDB on SatL
tutorial](https://github.com/fredericalix/satl-doc/blob/main/docs/start/app-node-mariadb.md).

## Security

Vulnerabilities go to **security@satl.cc**, privately, not to an issue or a pull
request. Scope, expectations and the security model are in
[SECURITY.md](SECURITY.md).

## License

BSD-2-Clause, the same terms as FreeBSD itself. Every source file carries
its SPDX line, and `make check` enforces it.
