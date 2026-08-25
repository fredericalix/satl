# `proto/`, SatL's internal node-to-node protocol

These `.proto` files define **package `satl.internal.v2`** (plus the standard
`grpc.health.v1`), the gRPC protocol SatL nodes speak to each other over mTLS.
They are compiled by `crates/satl-proto`; see `docs/architecture.md` §7 for
where each service sits in the system.

| File | Package | Service | Role required | Reference |
|---|---|---|---|---|
| `common.proto` | `satl.internal.v2` | - (shared types) | - | architecture §3, §4 |
| `dispatcher.proto` | `satl.internal.v2` | `Dispatcher` | worker or manager | architecture §7.1, SWK §13 |
| `ca.proto` | `satl.internal.v2` | `NodeCA` | none (bootstrap) / any | architecture §12.2–§12.3, SWK §16.2–§16.3 |
| `raft.proto` | `satl.internal.v2` | `Raft` | manager | architecture §6, SWK §11.7 |
| `control.proto` | `satl.internal.v2` | `Control` | manager | architecture §6.5–§6.6, SWK §11.3, §11.5 |
| `health.proto` | `grpc.health.v1` | `Health` | any | architecture §7 |

## Internal only

**This protocol is never exposed to clients.** The external surface is the
Docker Engine REST API (CLAUDE.md invariant #8, `docs/api-compat.md`). gRPC here
is node-to-node: manager ↔ manager (`Raft`, `Control`, `Health`) and
worker → manager (`Dispatcher`, `NodeCA`). Nothing outside the cluster's mTLS
perimeter dials it, and no compatibility promise is made to anything but SatL
binaries built from this workspace.

Corollary, and the reason the design below is affordable: there is no third
party to keep happy. Both ends of every connection are the same version in a
supported cluster, and mixed-version clusters are supported only within one
package version.

## Versioning convention

- The package is `satl.internal.v2`. The version is in the **package name**, not
  in file paths or service names.
- **Within a version, changes are additive only.** Add fields with new numbers;
  add RPCs; add enum values. Never renumber, never change a field's type, never
  repurpose a name, never remove a field, use `reserved` for anything retired
  (there are examples in `dispatcher.proto` and `ca.proto`).
- Anything that is not additive means a new package, `satl.internal.v3`, served
  alongside v2 for as long as a rolling upgrade needs both. v2 exists because of
  the openraft 0.10 upgrade (M12): the chunked `InstallSnapshot` became a
  streamed `FullSnapshot` and `TransferLeader` is new. The bump moved every
  service, not only `Raft` -- see the note at the top of `common.proto` for why.
- Enum values are open in proto3: an unknown value decodes to a bare `i32`.
  Servers and clients must reject unknown values **and** the `*_UNSPECIFIED`
  zero values explicitly. Do not `unwrap` a `try_from` on the wire path.
- `TaskState`'s sparse numeric values (0, 64, 192, 256, …, 832) are copied from
  SwarmKit and are shared with `satl_core::TaskState` and with the on-disk task
  database. They are not free to change, a test in `crates/satl-proto` pins
  them.

## The one design decision: opaque CBOR payloads

Store objects and openraft messages are **not re-modelled field-by-field in
protobuf**. Each envelope carries:

- `bytes payload`, the CBOR (`ciborium`) encoding of the corresponding
  `satl-core` or openraft Rust type. **This is the authoritative value.**
  One exception, `NetworkAssignment.payload`, encodes a *protocol* type
  (`satl_dispatcher::assignment::NetworkAssignment` = a `satl_core::Network`
  plus the endpoint table a node needs to program its FDB, and, since M4, to
  answer DNS without a store: each endpoint carries its service/task names,
  aliases and observed state, all `#[serde(default)]` so pre-M4 payloads still
  decode, to a state the DNS table never answers). The rule below is about not
  re-modelling in protobuf, not about where the Rust type lives, and the crate
  that owns both ends of the dispatcher protocol owns that type.
- a small set of scalars the protocol itself routes, filters, diffs and logs on
  (`id`, `meta.version`, `TaskState`, `DesiredState`, `NodeRole`,
  `Availability`). These are **mirrors** extracted from the payload. A receiver
  that finds them inconsistent trusts the payload and logs the discrepancy.

### Why

`satl-core` already owns the domain model: its invariants, its validation, and
its serde encoding, the same CBOR that goes into the Raft log, into snapshots,
and into the agent's on-disk task database (architecture §6.3, §7.2). A parallel
protobuf definition of `ContainerSpec`, `Mount`, `HealthConfig`,
`NetworkAttachment`, `TaskStatus`… would be a **second source of truth** for the
same data, kept in sync by hand-written conversions. That is not a theoretical
risk: it is how a task spec field silently stops crossing from manager to agent.
Shipping one encoding everywhere also means the agent's persisted copy of a task
is byte-identical to what the dispatcher sent.

The same argument applies to `raft.proto`: openraft owns the shapes of log
entries, vote records, snapshot metadata and membership configs, and they change
with openraft upgrades. We own the transport, not raft's internals.

### The tradeoff

- **No cross-language clients.** A Go or Python client could parse the frames
  but not the payloads. Accepted: see "Internal only" above.
- **No `protoc --decode` readability** of payloads. Debug tooling has to decode
  CBOR, which is why the mirrored scalars exist and must stay populated.
- **Version skew is serde skew.** Payload compatibility is governed by serde
  rules (add fields with `#[serde(default)]`, never repurpose a name), not by
  protobuf field numbers.
- Changing the payload codec is a **breaking change** and requires
  `satl.internal.v2`. (If that ever becomes likely, the additive migration path
  is a codec-tag field on the envelopes, deliberately not added now, because an
  unused tag is just another thing to get wrong.)

## Message size

Every message is capped at **4 MiB** (architecture §15,
`satl_proto::MAX_MESSAGE_SIZE`), and tonic's defaults are not that value, set
`max_decoding_message_size` / `max_encoding_message_size` explicitly on every
client and server. Assignment batching (100 changes / 100 ms), task-status
batching (100 ms / 10 000 updates), store transaction limits (200 actions /
1.5 MiB) and raft snapshot chunking all exist to stay under it.

## Building

`crates/satl-proto/build.rs` compiles these files with
[`protox`](https://crates.io/crates/protox), a pure-Rust protobuf compiler, and
feeds the resulting `FileDescriptorSet` to `tonic-prost-build`. **`protoc` is
not required**, not on the dev host, not on the cluster VMs, not in CI.
`cargo build` is the whole toolchain.

Adding a file means adding it to the explicit list in `build.rs`; a `.proto`
that is not listed is silently not compiled.
