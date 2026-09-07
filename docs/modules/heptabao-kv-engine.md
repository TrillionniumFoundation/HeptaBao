# heptabao-kv-engine

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns an in-memory versioned KV state machine with compare-and-set, soft delete, undelete, destroy and bounded version retention. It does not encrypt or persist values and is not a production secrets engine.

## Public API and ownership

`KvStore` owns per-path version histories. `KvRead` borrows a redacted secret value and returns version metadata. Callers own namespace and mount qualification before providing the engine key.

## State and data model

Each successful write creates a monotonically increasing version. Soft delete hides a version, undelete restores a non-destroyed version, and destroy removes the owned secret buffer permanently.

## Invariants and authorization

Compare-and-set must equal the current version when supplied. Destroyed data cannot be restored. Prefix listing uses canonical segment boundaries. Authorization is enforced by the service before engine dispatch.

## Failure, retry and reconciliation

Validation, CAS and missing-version failures happen before mutation. Current in-memory mutations are deterministic. A durable adapter must classify commit uncertainty and prohibit blind duplicate writes.

## Concurrency and ordering

The engine has no interior synchronization. A composition root serializes mutation per instance and binds a write to the current version at one commit point.

## Security and privacy

Secret buffers use `SecretValue` and are cleared when dropped. Debug output exposes length and metadata only. This does not provide encryption, locked memory or secure deletion from physical media.

## Persistence and compatibility

No persisted encoding exists. A production format must version metadata, encrypt values, preserve CAS generations and distinguish deleted from destroyed state during replay.

## Observability

Recommended events are `kv.write`, `kv.read`, `kv.delete`, `kv.undelete`, `kv.destroy` and `kv.cas_mismatch`; full secret keys and values are prohibited labels.

## Operations

Version retention is configured at construction. Production operation requires durable compaction, backup behavior, quota enforcement, metadata inspection and disaster recovery.

## Tests and executable evidence

`cargo test -p heptabao-kv-engine` covers CAS, version creation, soft delete, undelete, destroy, retention pruning and segment-safe listing.

## Evolution and open boundaries

Metadata custom fields, check-and-set-required policy, subkeys, patch, delete metadata and encrypted durable storage remain open until the service and storage composition is qualified.
