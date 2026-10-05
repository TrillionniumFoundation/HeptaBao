# heptabao-raft-runtime module closure dossier

This dossier is the independently reviewable design, boundary, failure-semantics, and acceptance record for **`heptabao-raft-runtime`**. It is generated from the exact candidate tree and must be reviewed whenever the source or manifest hash changes. It does not grant compatibility, production, migration, or release authority.

## Design and state ownership

- **Capability domain:** durable Raft replication with deadline-adaptive contiguous replay prefixes, applied-frontier recovery and bounded snapshots, passive true-term and actual-role observation
- **Repository state:** `IMPLEMENTED_REVIEW_REQUIRED`.
- **Source root:** `crates/heptabao-raft-runtime`; Rust files: `crates/heptabao-raft-runtime/src/cluster.rs`, `crates/heptabao-raft-runtime/src/lib.rs`, `crates/heptabao-raft-runtime/src/network.rs`, `crates/heptabao-raft-runtime/src/process/admin.rs`, `crates/heptabao-raft-runtime/src/process/follower_read.rs`, `crates/heptabao-raft-runtime/src/process/leader_status.rs`, `crates/heptabao-raft-runtime/src/process/network.rs`, `crates/heptabao-raft-runtime/src/process/node.rs`, `crates/heptabao-raft-runtime/src/process/read_deadline.rs`, `crates/heptabao-raft-runtime/src/process/read_index_tests.rs`, `crates/heptabao-raft-runtime/src/process/replication_tests.rs`, `crates/heptabao-raft-runtime/src/process/rpc_observation.rs`, `crates/heptabao-raft-runtime/src/process/snapshot.rs`, `crates/heptabao-raft-runtime/src/process/snapshot_receive_tests.rs`, `crates/heptabao-raft-runtime/src/process.rs`, `crates/heptabao-raft-runtime/src/record_store_tests.rs`, `crates/heptabao-raft-runtime/src/records.rs`, `crates/heptabao-raft-runtime/src/records_tests.rs`, `crates/heptabao-raft-runtime/src/replication_bounds.rs`, `crates/heptabao-raft-runtime/src/snapshot_encoding_tests.rs`, `crates/heptabao-raft-runtime/src/state_machine.rs`, `crates/heptabao-raft-runtime/src/store.rs`, `crates/heptabao-raft-runtime/src/store_io.rs`.
- **Internal dependencies:** none.
- **Runtime placement:** `yes`. The current runtime map is authoritative for whether this package is in the executable server dependency closure.
- **Public design surface:** type `AnyResult`; struct `DurableNode`; struct `DurableCluster`; fn `new`; fn `artifact_paths`; struct `ReplicatedEnvelope`; fn `new`; fn `operation_id`; const `fn`; fn `sealed`; fn `decode_status`; struct `CommitReceipt`; enum `RaftRuntimeError`; struct `RaftRuntime`; type `DurableRaft`; struct `DurableRouter`; struct `DurableNetworkFactory`; fn `new`; struct `DurableNetwork`; struct `MembershipObservation`; struct `SnapshotObservation`; struct `ReadIndexRequest`; struct `ReadIndexWitness`; enum `ReadIndexFailure`; fn `remote`; fn `bound`; struct `LocalLeaderObservation`; fn `local_leader_observation`; enum `RaftRpcKind`; enum `RemoteRaftError`

The module owns only the state and transitions described by its source files. It must not silently create an HTTP route, persistence format, authorization decision, external effect, or production guarantee unless that responsibility is visible in the source and in the current runtime map. Cross-module state is passed through typed APIs; callers remain responsible for transaction scope and durable publication where this package has no storage dependency.

## Module boundaries and trust assumptions

The package boundary is `crates/heptabao-raft-runtime`. Inputs crossing it are untrusted unless the source validates them; secrets, credentials, bearer tokens, and provider responses must not be placed in logs or debug output. heptabao-raft-runtime has no authority to claim OpenBao compatibility merely because a type or contract exists. Runtime integration, if any, is limited to the routes and owners recorded in `docs/modules/CURRENT_RUNTIME_MAP.md`; otherwise this is a standalone model, contract, or qualification tool.

The module does not own external clocks, network peers, KMS/HSM custody, filesystem ownership, process supervision, or operator approval unless its source explicitly implements and tests that boundary. Those concerns remain caller obligations and are listed as open evidence below.

## Failure semantics and ordering

The source-defined failure vocabulary is: `RaftRuntimeError::InvalidEnvelope`; `RaftRuntimeError::InvalidSerial`; `RaftRuntimeError::RecordRejected`; `RaftRuntimeError::Shutdown`; `RaftRuntimeError::Consensus`; `ReadIndexFailure::NotLeader`; `ReadIndexFailure::Deadline`; `ReadIndexFailure::Unavailable`; `RemoteRaftError::InvalidTopology`; `RemoteRaftError::InvalidRpc`; `RemoteRaftError::InvalidSnapshot`; `RemoteRaftError::Transport`; `RemoteRaftError::Consensus`; `RemoteRaftError::Io`

Validation must happen before irreversible state mutation. A caller must distinguish a definite pre-entry rejection from an outcome that became unknown after provider, journal, network, or publication entry. Unknown-after-entry outcomes require authoritative readback/reconciliation and must not be retried blindly. Invalid transitions, stale generations/terms, malformed identifiers, unauthorized inputs, exhausted capacity, and I/O/transport errors remain failures unless the source explicitly converts them into a typed safe state. This dossier does not reinterpret a missing error enum as success.

Ordering obligations are source-specific: inspect the public functions and tests listed below before changing call order. If this module is later given durable or external effects, add a persisted intent/readback test and update this dossier rather than relying on a happy-path unit test.

## Acceptance evidence

- **Source/manifest evidence:** portable repository-relative source SHA-256 `3349abad1ad22730a5f85bec4a9945ff5b135e5d2bee88934069dc923a64bf35`; manifest SHA-256 `5cc5e8a860fa39c811b8d792f60920f8c3f48153bb5029425bde844ff4e33b37`.
- **Named executable anchor:** `envelope_status_v3_round_trip_and_legacy_compatibility` in `crates/heptabao-raft-runtime/src/lib.rs`.
- **Required command:** `cargo +1.99.0 test --locked -p heptabao-raft-runtime` (must be executed against this exact source tree; historical CI output is not current evidence).
- **Repository/documentation checks:** `python scripts/validate_module_closure.py`; `python scripts/validate_current_documentation_semantics.py`.
- **Acceptance interpretation:** a passing unit test proves only the named module behavior. It does not prove server integration, OpenBao parity, HA, external provider correctness, crash recovery, or production qualification. Those require separate executable profiles and independent admission.

The acceptance status for this dossier is **source-bound, execution-pending** until the exact-head command and applicable integration profile produce a receipt bound to the same commit.

## Known gaps and evolution

Current open boundaries include full API/error-surface review, adversarial and crash/reopen cases, platform qualification, and any integration claimed by a different package. When behavior changes, update this dossier, the module guide, capability matrix, runtime map and named tests together. Never replace an unexecuted or failed acceptance result with prose claiming completion.
