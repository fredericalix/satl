# Changelog

All notable changes to SatL are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

SatL is pre-1.0: the API and the on-disk formats may still move. The `-beta`
qualifier lives on the git tag only, `Cargo.toml` and the FreeBSD package stay
numeric (`0.1.0`), because a hyphen in a `pkg(8)` version is read as the
name/version separator.

## [Unreleased]

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
