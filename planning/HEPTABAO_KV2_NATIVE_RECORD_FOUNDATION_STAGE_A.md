# Native KV2 records: stage A foundation and remaining integration

Status: **NOT_ADMITTED**. This branch implements a detached runtime codec.
It does not enable a V6 Service writer, authenticate a committed root, authorize
migration, remove V5's 16 MiB aggregate owner limit, or qualify full OpenBao
2.7.1 replacement. The eleven replacement admission gates remain authoritative.

## Implemented dataflow

`engines/kv2_native_records.rs` is a child of the real `engines/kv.rs`, so it
encodes the existing `Kv2`, `Config`, `EntryState`, `Version`, `EntryPrecision`
and `SharedJson` types. It does not use the experimental V6 shard representation.

Each detached mount has one configuration cell, one metadata cell per logical
path, and one canonical JSON payload cell per retained nondestroyed version.
The metadata cell carries the real runtime fields and sparse version headers;
an explicit version set binds exactly which payload cells must exist. Destroyed
versions retain their header without payload. Soft deletion retains payload.
Custom metadata, both CAS counters, retention floors, lossless numbers and
nanosecond/source-deletion precision survive reconstruction.

The existing immutable authenticated B-tree is the graph primitive. A new
native domain derives its graph key from a caller-supplied secret parent key and
canonical namespace/mount/incarnation scope. Independently keyed path tokens
retain the original 1,024-byte logical path bound without appending a version
suffix to the original path. This is graph authentication under the supplied
key, not proof that the caller holds production namespace custody.

Reopening authenticates all referenced objects before typed closure validation.
Every key must match the expected scope. Configuration and metadata cells must
match the native format and canonical bytes; metadata must match its keyed path
identity. Payload references must exactly match retained version headers, with
no missing payload, orphan, inline metadata payload, duplicate, or fallback to
opaque owner data. Sparse histories are retained, rather than being subjected
to the lossless migration importer's separate contiguous-input contract.

`engines::kv2_native_records::verify_native_owner_records` is an ordinary-build,
read-only verifier. Its raw owner decode still invokes the actual KV2
`SecretJson` deserializer, including lexical JSON/private-tag handling. It checks
the sticky lossless marker and runtime field invariants, reconstructs the actual
owner, and requires byte-for-byte canonical logical equality. Its receipt always
sets production-writer admission, migration admission and replacement authority
to false. The encoded graph is never published or written to storage.

## Bounds and ownership

| Boundary | Limit |
| --- | --- |
| Borrowed namespace and mount | 1,024 bytes each, no NUL; nonempty mount |
| Mount incarnation | Nonzero |
| Canonical owner input | 64 MiB before parsing |
| Paths | 10,000, counted through borrowed raw values before runtime allocation |
| Retained versions and precision entries per path | 10,000 each |
| Config + path + retained-header count | 100,000 |
| Custom metadata | 64 entries; existing 128-byte key / 512-byte value limits |
| Configuration / path metadata / payload cell | 16 KiB / 4 MiB / 16 MiB |
| Encoded graph | Existing 64 MiB graph primitive budget |

The graph primitive additionally enforces its existing page, block, height and
object-count bounds. Scope strings and encoded buffers are zeroizing; existing
`EntryState` and `SecretJson` owners retain their cleanup semantics. A detached
decoded owner guard erases its owning path map on success and typed-validation
failure. Immutable graph pins and shared payloads preserve an earlier owner
while a later candidate is discarded. The verifier can hold several bounded
materialized views; these individual bounds do not establish a production RSS
ceiling, staged-I/O quota or namespace key lifecycle.

## Scoped native validation

On native macOS arm64 with locked/offline Rust 1.98.0 dependencies and a dedicated
target directory, all ten new codec tests passed. The capacity case exercised
80 actual retained versions, one destroyed version and 79 payload records:
36,268,233 canonical owner bytes and 36,297,820 unique encoded object bytes across
240 objects. Every 4 KiB fixture chunk contains distinct version/chunk markers,
so repeated filler cannot satisfy the capacity check through deduplication.
These are in-memory encoded graph bytes, not a durable Service capacity claim.

Existing KV2 lossless tests (9) and version-array tests (7), strict server
all-target Clippy with `-D warnings`, Rustfmt/diff checks, 290 repository Python
tests, repository-v2/module-closure validators and the structural replacement
admission validator passed. The last validator checks truthful structure only.
The initial test failure caused by deduplicated filler and the initial test
compile failure remain preserved in local evidence rather than being relabeled
as passes. No production TLS, HA, storage fault or migration qualification was
performed by this branch.

## Required stage B: distinct root identity and closed reader admission

Introduce a real V6 root type and a distinct `StateIdentity` variant in
`state_record_root.rs`; retain exact V5 decoding and rejection of V6 by V5.
Bind independent KV1/KV2 references, protected owner domains, cluster identity,
schema floor and replay/retirement epoch. The foundation's format string and
reused graph object envelope must never be substituted into the existing V5 root.

`service_records.rs::{decode_root, materialize_record_state,
verify_received_record_graph}` and `service_identity.rs::{writer_schema,
validate_publication_schema, validate_format}` need explicit dual-reader logic,
canonical legacy provenance, monotonic schema/identity checks and absent/missing
graph rejection. The resource naming in `state_records::ObjectRef::resource`
currently belongs to V5; V6 resource roles and authentication contexts must be
defined explicitly before persistence. No stage-A receipt grants this authority.

## Required stage C: membership fencing, custody and retained closure

`ha_record_codec.rs` currently uses HBSM5/HBRO5 and `RecordRootBase::RecordsV5`.
It and the typed record protocol in `heptabao-raft-runtime` need distinct V6
root/object transport and replay identity. All voters and eligible leaders must
prove V6 reader capability under committed membership before writer admission;
`ha_forward.rs` transport negotiation alone is not this proof. Stale or
downgraded writers must fail closed across membership transitions and restart.

`ha_record_runtime.rs::{preflight_record_replacement, commit_record_state,
read_record_object}`, `service_records.rs::{materialize_committed_ha_records,
install_received_record_state}`, the HA state machine and snapshot archive/transfer
paths must preserve every KV2 dependency through snapshots, installation,
catch-up, compaction and reader pins. A source-only graph roundtrip cannot prove
these properties.

`engine_namespace_assets.rs` currently partitions `EngineState.records` for KV1.
It, `engine_namespace_record_cells.rs`, `namespace_record_graph.rs`,
`service_namespace_assets.rs` and `service_namespace_sdk_custody.rs` need explicit
KV2 graph partition/restore ownership. Derive native keys from actual barrier or
independent `NamespaceKey` custody, remove closed namespace plaintext views,
enforce incarnation/retirement floors, and prove reseal/re-unseal and peer key
transport. Caller-supplied stage-A keys are never a substitute for these owners.

## Required stage D: production mutation and atomic migration

Add a real record-backed KV2 backend alongside `Backend::Kv2` and route the
existing logical API through selected metadata/version records. Preserve exact
CAS, patch, metadata/list/scan/subkeys, destroy, sparse-retention and timing
semantics. The current detached codec still encodes/reconstructs whole owners;
production point operations must avoid whole-owner payload materialization and
stage only the changed path/version and immutable graph ancestors.

Build the candidate through `Service` mutation flow and
`service_records.rs::{prepare_record_plan, commit_record_plan,
persist_record_plan_local, persist_record_batch}`. Retain original operation
identity/deadline, mandatory audit ordering, before-publication durability and
post-Raft uncertainty reconciliation. Promote V5 to V6 atomically only after
stages B/C grant authority; do not clear the opaque KV2 owner before a validated
replacement root commits. Define staged-object/I/O/runtime quotas and report
KV2 graph headroom separately in `/sys/internal/capacity`.

The eventual acceptance proof must include pinned OpenBao 2.7.1 logical
comparisons, actual restart/recovery, disk-full/fsync/root-publication faults,
snapshots/catch-up/compaction, leader SIGKILL and quorum loss, independent
namespace sealing, mixed-version rolling admission and downgrade refusal on
native Mac and Linux. Stage A alone closes none of those admission gates.
