# Security Policy

SatL is a container engine: it runs an embedded certificate authority, issues
node identities, encrypts its cluster store at rest, ships secrets to workers and
seals manager keys under an operator-held unlock key. Bugs in any of that are
worth reporting, and this page says where to send them.

## Reporting a vulnerability

**Email `security@satl.cc`.** Please do not open a public issue, a discussion or a
pull request for anything security-relevant until a fix is available, a patch on
a public branch is a disclosure.

Reports in English or French are both fine. What helps most, in rough order:

- the version or commit (`satl version`, or the git revision you built);
- the FreeBSD version and the shape of the cluster (how many managers, how many
  workers, whether the overlay is encrypted, whether autolock is on);
- the relevant part of `satld.toml`, with secrets stripped;
- what an attacker needs to start with (a jail on the cluster? the `satl` unix
  group? the underlay network? a valid join token?) and what they end up with;
- a reproduction, even a rough one, and the log lines around it, `grep -a` on
  `/var/log/messages`, since a single non-ASCII byte makes plain `grep` silently
  print nothing.

Do not include real secrets, private keys or unlock keys in the report. If a
proof of concept needs them, say so and we will arrange something.

## What to expect

SatL is maintained by one person, so these are honest targets rather than a
service-level agreement:

| Stage | Target |
| --- | --- |
| Acknowledgement that the report arrived | 5 business days |
| Assessment, severity and a plan, once reproduced | 10 business days |
| Fix released and advisory published | coordinated with you; 90 days by default |

You will be credited in the advisory and in `CHANGELOG.md` unless you would
rather not be. If the report turns out to describe one of the deliberate design
choices listed below, you will get the reasoning rather than a patch, and if the
reasoning does not hold up, that is a finding too.

## Supported versions

| Version | Supported |
| --- | --- |
| `v0.1.0-beta` (tip of `main`) | Yes, fixes land on `main` |
| Any earlier build from `main` | No, rebuild from the tip |

There are no maintenance branches and no backports: the fix for a reported issue
goes to the tip of `main` and into the next tag. Upgrading means rebuilding, or
installing the next `.pkg`.

**This is a beta.** SatL has had no independent security audit. Treat a SatL
cluster as a single trust domain: every node holds a certificate from the same
CA, and containers are isolated by jails and VNET, not by a hypervisor. Do not
run untrusted or hostile multi-tenant workloads on it.

## Scope

In scope, the daemon (`satld`) and the CLI (`satl`) in this repository:

- the cluster CA, node identity, certificate issuance, renewal, root rotation and
  the removed-node blacklist;
- the mTLS surfaces and the internal gRPC protocol, including the unauthenticated
  bootstrap listener and the join-token scheme;
- manager autolock and the key-encryption-key construction;
- secret and config delivery, and the guarantee that a secret payload never
  reaches a worker's disk;
- at-rest encryption of the Raft log and snapshots;
- overlay data-plane encryption (IPsec ESP) and its key rotation;
- the pf rules SatL writes (`satl/*` anchors: NAT, redirects, the routing mesh
  pool, the cleartext guard);
- the REST API, its unix socket and its remote TLS listener;
- image pull, digest verification and the layer store;
- the OCI bundle and jail/VNET configuration SatL produces, where the bug is in
  what SatL configured.

Out of scope here, report these to their own maintainers:

- the FreeBSD base system, its kernel, jail, pf, ZFS and the linuxulator;
- `ocijail` itself, SatL never implements a runtime, it drives one;
- container images built or pulled by a user, and what runs inside them;
- the deliberate design choices below.

## Deliberate design choices, not vulnerabilities

Each of these looks like a finding and is not. If you disagree with the
reasoning, that argument is welcome, send it to the same address.

- **Port 2378 is unauthenticated.** A node that has never joined has no
  certificate, so the bootstrap listener cannot require one. It serves the root
  CA certificate and certificate issuance only; issuance still requires a valid
  join token, and the joiner pins the CA against the token's digest, so a MITM on
  first contact fails the digest check. Everything else is on 2377, behind mTLS.
- **The REST API has no user-level authorization.** In v1 there is one privilege
  level: the local unix socket is `0660`, owned by `root` and the `satl` group, so
  membership of that group is root-equivalent by design; remote REST requires a
  client certificate from the cluster CA. Per-user roles are not implemented, and
  their absence is documented rather than accidental.
- **`satld` runs as root.** Creating jails, moving interfaces between VNETs,
  loading pf anchors and manipulating ZFS all require it.
- **`/metrics` is unauthenticated.** It is off by default and binds only where
  the operator points it, matching dockerd's posture for the same endpoint. It
  exposes node, task and certificate-expiry series, do not put it on a public
  interface.
- **Published ports are not reachable from the publishing host through
  `localhost`.** A pf property: the redirect applies to traffic arriving on an
  interface, not to a connection the host opens to itself. Recorded as a numbered
  deviation in the API compatibility document.
- **Established TLS connections keep the identity they were opened with.** TLS
  authenticates at handshake time; a renewal or a role change applies to the next
  handshake, deliberately, so that renewing certificates does not sever healthy
  connections. Session resumption is disabled on the internal clients precisely so
  that a resumed session cannot re-attach a stale identity.

## The security model, in brief

A map for anyone looking for somewhere to push. The full design is in the
project's architecture document, section 12.

- **Identity.** Every node holds an ECDSA P-256 key pair and an X.509 certificate
  from the cluster CA: `CN` = node ID, `OU` = role (`satl-manager` /
  `satl-worker`), `O` = cluster ID. rustls everywhere, ECDHE with AES-GCM or
  ChaCha20-Poly1305 only. RPC authorization checks the OU, the cluster ID and the
  blacklist.
- **Joining.** Token format `SATL-1-<digest>-<secret>`: the digest is a base36
  SHA-256 of the root CA bundle and pins it against a first-contact MITM; the
  secret is 16 random bytes, compared in constant time. There are two tokens, and
  the one used decides the role. The CA controls the subject and SANs, only the
  public key comes from the CSR.
- **Certificate lifecycle.** 90-day leaves, renewed at a random point between 50%
  and 80% of their life. Renewal is live across every TLS surface. Root rotation
  (`satl ca rotate`) mints a new root, cross-signs it with the old key, publishes
  a transitional two-root bundle and converges every node before finishing;
  regenerating both join tokens twice, because their digest pins the bundle.
  Removed nodes' certificates are blacklisted until expiry plus 7 days.
- **At rest.** Raft log payloads and snapshots are encrypted with
  XChaCha20-Poly1305 under a per-manager data-encryption key stored `0600`.
  Because the whole log is encrypted, secrets, configs and overlay keyrings are
  encrypted with it. With autolock on, that key is sealed under the cluster unlock
  key and never touches disk in the clear; a locked manager answers only `/_ping`
  and `POST /swarm/unlock`.
- **Secrets on workers.** Payloads arrive over the mTLS dispatcher stream, live in
  agent memory, and are written into a per-task tmpfs sized to the payloads inside
  the jail, gone when the jail dies. The agent's local task database stores
  references, never payloads. Error messages and logs name the object, never its
  contents.
- **Overlay data plane.** An `encrypted` overlay wraps its VXLAN datagrams in
  IPsec ESP (`aes-gcm-16`), with a per-network keyring that reaches participant
  nodes only, rotates every 12 hours, and is backed by a pf guard anchor that
  drops cleartext arriving on the overlay's port.
