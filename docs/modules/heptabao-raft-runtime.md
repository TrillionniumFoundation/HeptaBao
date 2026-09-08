# heptabao-raft-runtime

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package implements a durable three-voter OpenRaft consensus core for HeptaBao. It replicates bounded opaque sealed envelopes, persists Raft log, vote, membership, state-machine and snapshot generations, rejects writes without a quorum, and exposes an explicit ReadIndex linearizability barrier. It is a repository-scope vertical slice, not yet the public networked HA service: peer mTLS, operator join authorization, listener discovery, request forwarding, rolling upgrade and the `heptabao-server` composition remain separate blockers.

## Public API and ownership

`ReplicatedEnvelope` is the only application payload accepted by the public façade. It binds a bounded operation identifier, a nonzero 32-byte semantic digest and 1 byte to 1 MiB of already sealed ciphertext. `RaftRuntime` exclusively owns three `openraft::Raft` instances, their durable log/state-machine stores and the deterministic in-process transport used by the qualification profile. `replicate` returns `CommitReceipt` only after the leader accepts the request and all three state machines report the committed index. Callers never receive mutable access to OpenRaft stores, routers or node handles.

## State and data model

Each node owns a versioned CRC-protected log generation, persistent vote and committed membership, a versioned state-machine bundle, and a snapshot generation. Store initialization is marked before the first generation is published; interrupted replacement preserves exactly one recoverable predecessor and ambiguous multiple predecessors fail closed. Application entries contain the `hbr1` envelope profile: operation identity, semantic digest and ciphertext encoded without plaintext interpretation. Client serial numbers provide OpenRaft state-machine deduplication and must be nonzero.

## Invariants and authorization

Only the current consensus leader may acknowledge mutation. A successful public receipt requires a committed log index and convergence of every configured voter. An isolated former leader cannot advance its committed index. Read callers must cross `ensure_linearizable`, which executes OpenRaft ReadIndex against a freshly resolved leader. Consensus membership is not application authorization: authentication, policy, namespace qualification, final-use grants and audit remain upstream responsibilities. The runtime never unseals, parses or logs the opaque application ciphertext.

## Failure, retry and reconciliation

Invalid bounds and zero client serials fail before consensus entry. Fatal OpenRaft failures terminate the operation; leader-forwarding and short membership transitions are retried with the same serial and identical payload under a bounded attempt/deadline policy. A caller that loses the response after consensus entry must reconcile through its stable operation identity rather than issue a new semantic mutation. Quorum loss, partition or shutdown returns an error and must not be interpreted as proof that no earlier commit occurred. Store corruption, incompatible magic, truncated envelopes, symlink substitution and ambiguous interrupted replacement fail closed during reopen.

## Concurrency and ordering

OpenRaft serializes leader terms, log append, commitment and state-machine application. The façade first resolves the current leader, invokes one idempotent client write, observes the returned log index, and waits for every voter to apply at least that index before releasing a receipt. ReadIndex occurs after leader resolution and before a linearizable read may be served. The deterministic router supports isolation, pause, healing and RPC counting only for qualification; it is not exposed as a production bypass. Shutdown unregisters every node before releasing the corresponding Raft task.

## Security and privacy

The public payload must already be protected by the HeptaBao Barrier; this package deliberately has no key, unseal or plaintext API. `Debug` for `ReplicatedEnvelope` redacts operation identity and digest and reports only ciphertext length. Durable application values are ciphertext, while Raft metadata such as node IDs, terms and membership remain nonsecret. The store rejects symlinked roots/generations and limits every durable artifact to 128 MiB. Peer authentication, transport encryption, certificate rotation, join tokens, anti-rollback hardware and host isolation are explicitly outside this in-process vertical slice and remain mandatory before production activation.

## Persistence and compatibility

The package owns repository-local formats `HBRLOG01`, `HBRSB001` and `HBRINI01`, each with exact length and CRC validation. Atomic replacement writes a temporary complete generation, syncs it, renames it, syncs the parent, and retires one validated predecessor. Reopen refuses a missing authoritative generation after initialization, unresolved multiple predecessors, corrupt checksums, wrong format magic, non-regular files and unsafe directory substitution. Format changes require new magic/version identifiers, hostile decoder tests, an interruption-safe migration and an explicit rollback decision; existing bytes are never silently reinterpreted.

## Observability

The public façade exposes leader ID, committed log index and the caller-supplied semantic digest in `CommitReceipt`; no ciphertext or credential enters metrics. The internal qualification router records bounded RPC counts by method so tests can prove vote, append, snapshot and ReadIndex activity. Recommended production events are term/leader change, quorum unavailable, stale leader forwarding, snapshot publish, store recovery and corruption rejection. Labels must remain low-cardinality and must not contain operation identifiers, paths, namespaces, tokens or encrypted payload bytes.

## Operations

Repository qualification supports bootstrap of exactly three voters, orderly shutdown, exact-root reopen, leader discovery, snapshot generation, deterministic partition/heal and state convergence checks. Operators must treat a failed reopen, checksum mismatch or ambiguous replacement as a recovery event and preserve all artifacts. Deleting log/state files to regain liveness is forbidden. The future networked service must add peer certificate enrollment, membership-change authorization, rolling upgrade, node replacement, snapshot transfer limits, quorum-loss runbooks and cross-host backup/restore before this runtime can back production requests.

## Tests and executable evidence

Run `cargo +1.98.0 test --locked -p heptabao-raft-runtime` for the package and the full workspace commands from `README.md`. The primary executable regression bootstraps three voters, commits a bounded sealed envelope, proves all state machines converge, crosses ReadIndex, isolates the leader and proves no isolated commit, shuts down, reopens every durable store, crosses ReadIndex again and proves convergence. Store tests additionally cover interrupted atomic replacement, corruption, missing generations, stale predecessors, legacy adoption boundaries, symlink roots/generations, directory substitution and exact round-trip encoding.

## Evolution and open boundaries

The next mandatory slice replaces the deterministic router with authenticated bounded inter-process RPC, composes consensus into `heptabao-server`, forwards clients to the current leader without forwarding credentials to unverified peers, and executes real three-process failover, quorum-loss, snapshot transfer, restart and rolling-upgrade tests. Joint-consensus membership changes, witness/learner operation, production storage performance, disk-full behavior, mTLS/KMS custody, cross-platform destructive tests and independent linearizability campaigns remain open. This guide grants no compatibility, production, migration or release authority.
