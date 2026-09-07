# heptabao-kv-engine

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns an in-memory versioned KV state machine with compare-and-set, soft delete, undelete, atomic multi-version destroy and bounded version retention. It does not encrypt or persist values and is not a production secrets engine.

## Public API and ownership

`KvStore` owns per-path version histories. `write` validates the current version before creating a map entry. `destroy` validates the complete version set before mutating any record. `KvRead` borrows a redacted secret value and returns owned metadata. Callers own namespace and mount qualification before providing the engine key.

## State and data model

Each successful write creates one monotonically increasing version. Soft delete hides a version, undelete restores a non-destroyed version, and destroy clears the owned secret buffer and sets both destroyed and deleted flags. A rejected first-write CAS leaves no path entry, version, list result or changed read classification.

## Invariants and authorization

Compare-and-set must equal the current version when supplied. Every fallible condition for a multi-version destroy is preflighted before its commit loop, so mixed existing/missing inputs are order-independent and leave all records unchanged. Duplicate destroy version numbers are idempotent and count one state change. Destroyed data cannot be restored. Prefix listing uses canonical segment boundaries. Authorization is enforced by the service before engine dispatch.

## Failure, retry and reconciliation

Invalid capacity, CAS mismatch, missing key, missing version and version overflow fail before mutation. A rejected first write remains `MissingKey`, not an empty history. A rejected multi-version destroy preserves both value bytes and metadata in either argument order. Current in-memory mutations are deterministic; a durable adapter must additionally classify commit uncertainty and prohibit blind duplicate writes.

## Concurrency and ordering

The engine has no interior synchronization. A composition root serializes mutation per instance. `write` performs lookup and validation before the insertion commit point; `destroy` performs an immutable all-version preflight followed by a non-fallible mutation pass over the validated records.

## Security and privacy

Secret buffers use `SecretValue` and are cleared when dropped. Debug output exposes length and metadata only. Atomic rejection prevents a malformed request from partially destroying an earlier version. This package does not provide encryption, locked memory or secure deletion from physical media.

## Persistence and compatibility

No persisted or wire encoding exists. A production format must version metadata, encrypt values, preserve CAS generations and distinguish deleted from destroyed state during replay. The atomic rejection rules are part of the semantic contract and must survive provider substitution.

## Observability

Recommended events are `kv.write`, `kv.read`, `kv.delete`, `kv.undelete`, `kv.destroy`, `kv.cas_mismatch` and `kv.destroy_preflight_failed`. Full secret keys, values and destroyed bytes are prohibited labels.

## Operations

Version retention is configured at construction. Operators should treat CAS mismatch and destroy preflight failure as no-op outcomes. Production operation additionally requires durable compaction, backup behavior, quota enforcement, metadata inspection and disaster recovery.

## Tests and executable evidence

`cargo test -p heptabao-kv-engine` executes `rejected_first_write_cas_does_not_publish_a_ghost_key`, `rejected_multi_version_destroy_is_atomic_in_both_orders`, `duplicate_destroy_versions_are_idempotent_and_count_once`, CAS/version lifecycle and segment-safe retention/listing scenarios.

## Evolution and open boundaries

Metadata custom fields, check-and-set-required policy, subkeys, patch, delete metadata and encrypted durable storage remain open until the service and storage composition is qualified. New mutators must preserve preflight-before-commit and rejected-operation no-op semantics.
