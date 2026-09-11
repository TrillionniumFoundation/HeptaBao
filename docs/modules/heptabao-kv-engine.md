# heptabao-kv-engine

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns an in-memory versioned KV state machine with compare-and-set, soft delete, undelete, atomic multi-version destroy and bounded version retention. It does not encrypt or persist values and is not a production secrets engine.

## Public API and ownership

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-kv-engine`; Cargo SHA-256 `1548333d3e46ddb77572406809229ef0e8ade28f39e10a84d2d76f0c096192d0`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `struct` | `KvMetadata` | `crates/heptabao-kv-engine/src/lib.rs:13` | `pub struct KvMetadata {` |
| `struct` | `KvRead` | `crates/heptabao-kv-engine/src/lib.rs:37` | `pub struct KvRead<'a> {` |
| `struct` | `KvStore` | `crates/heptabao-kv-engine/src/lib.rs:54` | `pub struct KvStore {` |
| `fn` | `new` | `crates/heptabao-kv-engine/src/lib.rs:60` | `pub fn new(max_versions: usize) -> Result<Self, KvError> {` |
| `fn` | `current_version` | `crates/heptabao-kv-engine/src/lib.rs:70` | `pub fn current_version(&self, path: &CanonicalPath) -> u64 {` |
| `fn` | `write` | `crates/heptabao-kv-engine/src/lib.rs:77` | `pub fn write(` |
| `fn` | `read` | `crates/heptabao-kv-engine/src/lib.rs:112` | `pub fn read(&self, path: &CanonicalPath, version: Option<u64>) -> Result<KvRead<'_>, KvError> {` |
| `fn` | `delete_latest` | `crates/heptabao-kv-engine/src/lib.rs:134` | `pub fn delete_latest(&mut self, path: &CanonicalPath) -> Result<KvMetadata, KvError> {` |
| `fn` | `undelete` | `crates/heptabao-kv-engine/src/lib.rs:147` | `pub fn undelete(&mut self, path: &CanonicalPath, version: u64) -> Result<KvMetadata, KvError> {` |
| `fn` | `destroy` | `crates/heptabao-kv-engine/src/lib.rs:163` | `pub fn destroy(&mut self, path: &CanonicalPath, versions: &[u64]) -> Result<usize, KvError> {` |
| `fn` | `list` | `crates/heptabao-kv-engine/src/lib.rs:194` | `pub fn list(&self, prefix: &CanonicalPath) -> Vec<CanonicalPath> {` |
| `enum` | `KvError` | `crates/heptabao-kv-engine/src/lib.rs:204` | `pub enum KvError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

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

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-kv-engine`
- Crate path: `crates/heptabao-kv-engine`
- Cargo manifest SHA-256: `1548333d3e46ddb77572406809229ef0e8ade28f39e10a84d2d76f0c096192d0`
- Rust source files: `1`
- Public lexical declarations: `12`
- Discovered test functions: `5`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
