# Changelog

All notable changes to SatL are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

SatL is pre-1.0: the API and the on-disk formats may still move. The
pre-release qualifier (`-beta`, `-alpha`) lives on the **git tag only**;
`Cargo.toml` and the FreeBSD package stay numeric (`0.2.0`), because a hyphen in
a `pkg(8)` version is read as the name/version separator.

## [Unreleased]

## [0.2.0-alpha] - 2026-08-24

Docker's two worlds, both of them. `satl compose` now runs a Compose file on the
node you are talking to, the way `docker compose` does; `satl stack deploy`
keeps the cluster, the way `docker stack deploy` does. Until 0.1.0 both verbs
did the second thing.

**Read the two BREAKING entries below before upgrading.** `satl compose up`
changes what it deploys *and* stops returning on its own.

### Changed

- **BREAKING: `satl compose` now deploys to the node you are talking to.**
  Docker has two worlds and SatL now has both: `satl compose` is
  `docker compose`'s scope (everything on one host) and `satl stack deploy` is
  `docker stack deploy`'s (spread over the cluster). Until 0.1.0 both verbs did
  the second thing. **For the old behaviour of `satl compose up`, use
  `satl stack deploy`**; `satl stack` itself is unchanged in every respect.

  What changes when you run `satl compose up`: every service is pinned to the
  receiving node, ports are published on that node instead of the cluster's
  ingress mesh, objects are named `<project>-<service>` instead of
  `<project>_<service>`, and a relative bind source such as `./conf:/etc/nginx`
  is honoured against the project directory instead of being refused. Newly
  refused, each naming `satl stack deploy` as where it works: `deploy.placement`,
  an explicit `mode: ingress` on a port, and `deploy.replicas` above 1 sharing a
  fixed host port (a host port can only be taken once on one node). `driver:
  bridge` is now the default, and `driver: overlay` is refused with a pointer to
  `satl stack deploy`.

- **`satl compose` gained the verbs node-local scope makes possible**: `down -v`
  removes the volumes the file declares, on the node it runs on; `up --scale
  web=3` overrides the file's replica count; and `stop` / `start` / `restart`
  manage a running project without removing it.

  None of the three lifecycle verbs is docker's, and the reason is invariant
  #2: a task is one-shot, so nothing is ever paused and resumed. `stop` scales
  every service to zero and leaves the services, networks and volumes in place;
  `start` scales them back **from the compose file**, so it needs the file where
  `stop` does not, and nothing is stashed in a hidden label; `restart` bumps
  `ForceUpdate` and lets the rolling updater replace the tasks under each
  service's own policy, so the tasks come back with new ids. See
  `docs/api-compat.md` 176-178.

- **`satl compose` can build its own images.** A service may declare `build:`
  instead of `image:`; `satl compose build` builds without deploying and
  `satl compose up --build` builds first. The image is tagged
  `<project>-<service>:latest` and used straight from this node's store, with no
  registry — which works because the task is pinned to the node that built it.

  Two things to know. It builds a **`Satlfile`**, not a Dockerfile
  (`docs/image-sources.md`): `dockerfile:` names which file to read, but its
  contents must be Satlfile syntax, and `args:`/`target:` are refused with the
  reason rather than ignored. And both verbs need **root**, because writing to
  the image store does. Under `satl stack`, `build:` is still refused: a stack's
  tasks are placed on any node and a built image exists on one. See
  `docs/api-compat.md` 181-182.

- **BREAKING: `satl compose up` now attaches to its project's output** and does
  not return until Ctrl-C; `-d/--detach` stops being a no-op and is how a script
  gets the old behaviour. Anything non-interactive that calls `satl compose up`
  will hang without it — this caught the project's own cluster test suite, which
  is why it is called out here rather than left to the release notes. There is a
  new `satl compose logs [--follow] [--tail N] [SERVICE…]`, with docker's
  `<service>-<slot>` line prefixes, one colour per service on a terminal and
  none when redirected.

  Two differences from `docker compose` worth knowing. `--follow` has **no
  `-f`**: at this level `-f` is the compose file, and it is global so every
  subcommand reads the same one. And **Ctrl-C detaches rather than stopping the
  project** — a script relying on docker's behaviour to clean up will leave it
  running; `satl compose stop` is the verb that stops it. `satl stack deploy`
  stays detached, because following a project spread over the cluster needs a
  log broker that does not exist. See `docs/api-compat.md` 124, 179, 180.

- **The embedded DNS responder now serves bridge networks.** Before this a task
  on a bridge network received a copy of the host's `/etc/resolv.conf` and every
  service name answered `NXDOMAIN`; only overlay networks had service discovery.
  This is what lets `satl compose` use bridge networks, and it fixes name
  resolution for any bridge-network service, compose or not. It also means a
  node that can host no overlay at all -- one whose underlay address is a `/32`,
  an ordinary way for a single public server to be configured -- now runs
  containers with working service discovery instead of none.

  Note the isolation this does *not* give you: SatL programs one bridge per
  node, so two projects on "different" bridge networks share one L2 and can
  reach each other by address. Names are scoped per network, addresses are not
  (`docs/api-compat.md` 175).

  Because the object names change, a project deployed with 0.1.0's
  `satl compose up` is not adopted by 0.2.0's: run `satl compose down` (or
  `satl stack rm <project>`) with the old binary first, or keep it on the
  cluster with `satl stack deploy`. Deviations 110 and 112 rewritten, 169-174
  added in `docs/api-compat.md`.

### Added

- **Man pages**: hand-written satl(1), satld(8) and satld.toml(5), pinned
  against the CLI and the config by tests so they cannot drift silently
  (satl.1's COMMANDS list is set-equal to the CLI's verbs, satld.8's flags
  match the daemon's, satld.toml.5's keys match the config struct), and
  linted by `mandoc -T lint` inside `make check`.
- The package (and `make install`) now ships the three man pages, gzipped,
  and `share/licenses/satl-<version>/` (BSD2CLAUSE, LICENSE, catalog.mk) in
  the same layout the ports tree uses.
- **`satl images rm`** (and `satl rmi`), plus `DELETE /images/{name}`, there was
  no way to delete a single image, from the CLI or from a Docker client. It runs
  the same two-agreeing-passes layer reclamation `satl system prune` runs, so
  budget about 1.5 s per image; `--no-prune` skips the sweep for a batch. A
  running task or any service spec referencing the image is a refusal `--force`
  does not override.
- **`satl images` is now a noun**: `ls`, `rm`, `prune`, `inspect`. Bare
  `satl images` is unchanged.
- **`satl events`**, the daemon has streamed `GET /events` since M1 and nothing
  reached it. `--filter` is applied client-side; `--since` is sent with a warning
  that SatL keeps no history.
- **`satl info`**, **`satl volume inspect`**, **`satl node ps`**, and
  `satl images|container|network|volume prune`, all endpoints that existed and
  had no verb.
- **`GET /images/{name}/json`** and `satl images inspect`.
- `make package` writes `dist/CHECKSUM.SHA512` next to the package, in
  sha512sum(1) format: `sha512sum -c CHECKSUM.SHA512` from inside `dist/`
  verifies a `.pkg` distributed out of band.

### Fixed

- Every one-shot `satl run` executed its command twice: starting the container
  flips a service label, which bumped the spec version, and the rolling updater
  then refilled the completed task's slot with a replacement that re-ran the
  command. The abandoned-slot fill now consults the deep spec comparison, so a
  finished task whose spec matches the current one is converged, not refilled.
- `satl run` now pins its container to the node that served the request
  (api-compat 168), like `docker run`; before, a formed cluster could schedule
  it on another node, where a foreground run printed nothing and exited 0.
- The package's post-install message now spells the state dataset's creation
  with its mountpoint (`zfs create -o mountpoint=/var/db/satl zroot/satl`);
  without it the dataset mounts at `/zroot/satl` and satld warns that
  `state_dir` differs from the dataset's mountpoint.
- `satld.toml.sample` now lists `cert_validity` and `overlay_blackhole`, the
  two keys the daemon accepted but the sample never mentioned.
- `GET /images/json`'s `Containers` count read 0 for exactly the images most
  likely to be in use: it compared a task spec's raw image string against the
  store's canonical reference, so a service saying `alpine` never matched
  `docker.io/library/alpine:latest`.

## [0.1.0-beta] - 2026-08-17

First public pre-release. SatL runs OCI containers as FreeBSD VNET jails through
the [ocijail](https://github.com/cperciva/ocijail) runtime, with swarm-style
orchestration built in, and speaks the Docker Engine API. Everything below was
built and verified on FreeBSD 15.1, most of it on a three-node cluster, with the
measurements kept in the project's roadmap. "Beta" here means: the feature set is
complete enough to run real workloads (the documentation site's Node.js + MariaDB
tutorial runs end to end), it has had no independent security audit, and no
compatibility promise is made across pre-1.0 versions.

### Added

#### Containers and runtime

- OCI containers as **one VNET jail per task**, driven through `ocijail`
  (create/start/kill/delete/state), SatL never manipulates jails out of band.
- ZFS clones for image layers and container rootfs; ZFS is mandatory, and `satld`
  refuses to start without its root dataset.
- `linux/amd64` images under the **linuxulator** as a first-class fallback when no
  FreeBSD image exists.
- `satl run`, `ps`, `logs`, `exec`, `inspect`, `stop`, `kill`, `rm`, `wait`, plus
  node-local `satl volume`, every container is a task of a service, including
  `satl run`.
- Resource limits through `rctl` (CPU, memory, with the `satl.jail.*` labels
  passing any jail parameter through); needs `kern.racct.enable=1` and degrades
  gracefully without it.
- Crash recovery: after `kill -9` and an rc.d restart, the daemon recovers its
  identity and reconciles jails, epairs, mounts and datasets, including prisons
  left `DYING` by an interrupted teardown.

#### Cluster and orchestration

- **Embedded Raft store** (openraft over a redb log), encrypted at rest, on its
  own ZFS dataset with snapshots. All cluster state lives there; manager
  components are independent level-triggered loops that communicate only through
  the store and its watch feed.
- **No standalone mode**, a fresh daemon self-initialises its cluster; a single
  node is a cluster of one, and there is nothing to `init`.
- `satl swarm join` with **pinned-CA tokens**, separate worker and manager tokens,
  and `satl node ls/promote/demote/rm` with live role changes.
- Services in every mode: **replicated**, **global**, and run-to-completion jobs
  (`replicated-job`, `global-job`).
- **Rolling updates** with health-gated batches, `start-first`/`stop-first`,
  pause-on-failure and automatic rollback; measured at zero lost requests over a
  rolling update through the routing mesh.
- Restart policies with a restart supervisor, a task reaper and a constraint
  enforcer, each re-deriving its state from the store every pass, a leadership
  change resumes work rather than replaying it.
- **Placement constraints** (`node.labels.*`, `engine.labels.*`, `node.role`, …)
  and **placement preferences** (`spread=node.labels.zone`), ranked after the
  fault penalty and re-ranked within a batch.
- **Hot vertical resize**: a resources-only service update rewrites the live
  jails' `rctl` rules instead of rolling the service, same task IDs, no restart.
- Manager quorum operations: backup and restore of manager state, documented and
  validated on three machines (the policy is three managers *and* backing up at
  least two).

#### Networking

- **VXLAN overlay networks** with a Raft-distributed forwarding table (learning
  off, every entry ours) and **DNS round-robin service discovery**.
- **Ingress routing mesh** in pf: every manager answers every published port,
  relaying over the lazily created `ingress` overlay to a healthy task on another
  node, with return-path SNAT and an MSS clamp. Pool membership is health-checked
  through pf tables, measured under 10 seconds from probe failure to a task
  leaving the pool.
- Node-local bridge networks, cluster IPAM, sticky port allocation from the
  30000–32767 range, and NAT for container egress.
- **Opt-in L4 PROXY-protocol publish mode** (`satl.publish.proxy_protocol=v2`) for
  services that need the real client address, which the mesh otherwise replaces
  with the relaying node's gateway.
- **Encrypted overlays** (`--opt encrypted`): IPsec ESP (`aes-gcm-16`) over the
  VXLAN data plane, per-network keyrings delivered to participant nodes only,
  automatic 12-hour rotation, and a pf guard anchor that drops cleartext on the
  overlay port. Measured overlay MTU: 1450 plain, 1416 encrypted.

#### Images and builds

- Pull from any OCI registry into a ZFS-backed local layer store, with private
  registries authenticated through Docker's `X-Registry-Auth` header.
- **`satl build`** with a `Satlfile` (`FROM`, `PKG`, `COPY`, `RUN`, `ENV`,
  `WORKDIR`, `EXPOSE`, `LABEL`, exec-form `ENTRYPOINT`/`CMD`): multi-layer with a
  content-addressed incremental cache, **multi-stage** builds
  (`FROM x AS builder` → `COPY --from=builder`) and `FROM scratch`, the showcase
  image, a static C binary in a scratch image, is 1.4 MB, and an incremental
  rebuild takes 7 s against 51 s cold.
- `satl tag` and `satl push` to share a built image through a registry, with
  credentials read from `--password-stdin` and never stored.
- `satl system prune` with layer garbage collection, closed upward through the
  ZFS clone graph with two agreeing passes.

#### Secrets, configs and security

- **Cluster CA** (ECDSA P-256, rcgen/rustls) issuing every node identity;
  **mTLS on every internal connection**, with the role carried in the certificate
  and enforced per RPC.
- 90-day node certificates with **live renewal**, every TLS surface resolves its
  certificate per handshake, so renewal, promotion and demotion take effect
  without a restart and without severing healthy connections.
- **`satl ca rotate`**: root rotation without downtime through a cross-signed
  intermediate and a transitional two-root bundle, level-triggered and resumable
  across leader changes. Measured at 0 of 339 requests lost across a rotation.
- **Manager autolock** (`swarm init --autolock`, `swarm unlock`,
  `swarm unlock-key --rotate`): every manager's Raft data-encryption key is sealed
  under an operator-held unlock key, and a locked manager serves only `/_ping` and
  the unlock endpoint.
- **Secrets and configs**: encrypted at rest in the Raft log, delivered over the
  mTLS dispatcher stream, and materialized on a per-task tmpfs inside the jail,
  never on a worker's disk. Configs mount read-only at their target path.
- Removed nodes' certificates are blacklisted until expiry plus a 7-day grace.

#### Compatibility, tooling and observability

- **Docker Engine API v1.43+** over `/var/run/satl.sock` with version negotiation,
  so the `docker` CLI and existing tooling work against `satld` unchanged. Every
  intentional deviation is numbered in the project's API compatibility document.
- `satl`, a CLI mirroring `docker`'s verbs, speaking REST only, it never speaks
  the internal gRPC protocol.
- **`satl compose`** and Docker's **`satl stack`** verbs over standard Compose
  files, with stack (not single-host) semantics: a file is refused whole rather
  than half-deployed.
- **Prometheus `/metrics`** on a separate listener, off by default, using Docker's
  own series names where dockerd defines them and `satl_*` otherwise.
- Structured tracing with span chains keyed on identity, so one task's whole life
  is greppable out of `/var/log/messages`.
- FreeBSD packaging: `make install`, `make package` (an installable
  `satl-0.1.0.pkg` needing no repository), and an rc.d service.
- BSD-2-Clause throughout, with an SPDX header on every source file, enforced by
  `make check`.

### Known limitations

- **FreeBSD 15.1 on amd64 only**, nothing else is built or tested. ZFS is
  mandatory; there is no fallback storage driver.
- **IPv4 only.** Overlay networking, IPAM and published ports have no IPv6 path.
- **Node-local volumes only**, no cluster volumes, no CSI, no volume plugins. A
  stateful service is pinned to its node with a placement constraint.
- **No `POST /build`.** Builds are client-side (`satl build`) and run on the
  invoking node's host, so build on the FreeBSD major you deploy on.
- **`satl logs` is per-container and node-local**, there is no cluster-wide
  `service logs` and no log broker.
- **No user-level authorization in the REST API.** The unix socket is
  `0660 root:satl` (group `satl` is root-equivalent), and remote REST requires a
  client certificate from the cluster CA. See SECURITY.md.
- **A worker publishes only its local replicas.** The routing mesh is computed
  from the store, so it spans managers; the supported v1 shape is an all-manager
  cluster.
- **Published ports are not reachable from the publishing host via localhost**,
  a pf property, recorded as a numbered API deviation.
- **Jobs**: retries are immediate (no delay queue), `Restart.Window` is not
  honoured, and `JobIteration` is not rendered.
- **The ingress network can never be encrypted**, its assignment is broadcast to
  every node, so an `encrypted` ingress network is refused at create.
- **External CAs and FIPS are out of scope**; so are Go-templated secrets, secret
  drivers and attachable networks.

The full account of what is missing, with the workarounds, lives in the project's
roadmap and in the [user documentation's out-of-scope
page](https://github.com/fredericalix/satl-doc).

[Unreleased]: https://github.com/fredericalix/satl/compare/v0.1.0-beta...HEAD
[0.1.0-beta]: https://github.com/fredericalix/satl/releases/tag/v0.1.0-beta
