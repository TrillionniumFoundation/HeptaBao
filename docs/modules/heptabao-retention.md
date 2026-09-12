# heptabao-retention

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns retention-policy validation, compaction counts and a backup lifecycle contract. It does not read storage, encrypt archives or perform offsite transfer.

## Public API and ownership

### Current API contract and integration boundary

`RetentionPolicy` is a public configuration value. `validate()` requires positive secret-version/audit-event limits and positive intervals, with restore-drill interval at least the backup interval. `versions_to_prune(current_versions)` only computes a saturating subtraction and does not call validation or delete anything; the caller must validate configuration first and execute pruning under the storage owner's transaction rules.

`BackupCoordinator` owns one memory lifecycle, an attempt's source generation/start tick and an optional receipt. `begin(source_generation, now)` accepts Idle, Verified or Failed, clearing an old receipt. `seal(nonzero_digest)` accepts Snapshotting, creates a `BackupReceipt` and increments the coordinator's generation. `verify(digest)` requires Sealed and exact digest equality; a mismatch moves to Failed. `fail()` is available only while Snapshotting. Transition errors do not perform I/O or infer whether a provider snapshot succeeded.

The supplied digest is not computed or independently verified here; submitting the same arbitrary digest to seal and verify satisfies this model. An adapter must obtain a stable snapshot, hash real bytes, authenticate/encrypt the archive, perform independent readback/restore and persist the manifest before claiming recovery. Source generation 0 and repeated generations are not rejected by the coordinator.

This contract is outside the current server dependency closure and does not operate the server's existing snapshot/restore paths. The runbook obligations below apply to a real backup adapter, scheduler and offsite custody service.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-retention`; Cargo SHA-256 `a5cea0533a315670560cf62a20d7d465ae12f06c884b7c07ffcd0cfc77d8293f`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `struct` | `RetentionPolicy` | `crates/heptabao-retention/src/lib.rs:12` | `pub struct RetentionPolicy {` |
| `fn` | `validate` | `crates/heptabao-retention/src/lib.rs:20` | `pub fn validate(&self) -> Result<(), RetentionError> {` |
| `fn` | `versions_to_prune` | `crates/heptabao-retention/src/lib.rs:34` | `pub fn versions_to_prune(&self, current_versions: usize) -> usize {` |
| `enum` | `BackupState` | `crates/heptabao-retention/src/lib.rs:40` | `pub enum BackupState {` |
| `struct` | `BackupReceipt` | `crates/heptabao-retention/src/lib.rs:49` | `pub struct BackupReceipt {` |
| `struct` | `BackupCoordinator` | `crates/heptabao-retention/src/lib.rs:56` | `pub struct BackupCoordinator {` |
| `fn` | `state` | `crates/heptabao-retention/src/lib.rs:77` | `pub fn state(&self) -> BackupState {` |
| `fn` | `generation` | `crates/heptabao-retention/src/lib.rs:81` | `pub fn generation(&self) -> u64 {` |
| `fn` | `begin` | `crates/heptabao-retention/src/lib.rs:85` | `pub fn begin(&mut self, source_generation: u64, now: Tick) -> Result<(), RetentionError> {` |
| `fn` | `seal` | `crates/heptabao-retention/src/lib.rs:99` | `pub fn seal(&mut self, digest: [u8; 32]) -> Result<BackupReceipt, RetentionError> {` |
| `fn` | `verify` | `crates/heptabao-retention/src/lib.rs:121` | `pub fn verify(&mut self, digest: [u8; 32]) -> Result<(), RetentionError> {` |
| `fn` | `fail` | `crates/heptabao-retention/src/lib.rs:137` | `pub fn fail(&mut self) -> Result<(), RetentionError> {` |
| `enum` | `RetentionError` | `crates/heptabao-retention/src/lib.rs:147` | `pub enum RetentionError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

Backup state moves through idle, snapshotting, sealed and verified, with a failed branch. Each sealed receipt binds source generation, start tick and nonzero digest.

## Invariants and authorization

Zero limits and a restore-drill interval shorter than the backup interval are rejected. Verification requires an exact digest match.

## Failure, retry and reconciliation

A failed snapshot may begin again under a new operation. Digest mismatch moves the coordinator to failed and requires investigation rather than silent acceptance.

## Concurrency and ordering

The coordinator has one owner and no interior lock. Storage snapshotting must bind a stable source generation before `seal` is called.

## Security and privacy

Receipts contain digests and generations, never plaintext secrets. Digest presence is integrity metadata and does not prove encryption or custody.

## Persistence and compatibility

No archive format exists. Production backup formats need versioned manifests, encryption, key custody, retention deletion evidence and restore compatibility.

## Observability

Recommended events are `backup.started`, `backup.sealed`, `backup.verified` and `backup.failed`, with bounded outcome and state labels.

## Operations

Operators must schedule backup and restore drills separately. A successful snapshot without readback and restore validation is not a qualified backup.

## Tests and executable evidence

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::policy_and_compaction_plan_are_bounded`](../../crates/heptabao-retention/src/lib.rs) checks validation of the example policy and its prune count.
- [`tests::backup_must_seal_and_verify_before_completion`](../../crates/heptabao-retention/src/lib.rs) checks ordered seal/verify and rejects a second verify; it is not a restore drill.

`cargo test -p heptabao-retention` covers policy validation, prune planning and backup transition/digest enforcement.

## Evolution and open boundaries

Offsite custody, WORM retention, compaction execution, legal hold and destructive restore drills remain environment and operator work.

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-retention`
- Crate path: `crates/heptabao-retention`
- Cargo manifest SHA-256: `a5cea0533a315670560cf62a20d7d465ae12f06c884b7c07ffcd0cfc77d8293f`
- Rust source files: `1`
- Public lexical declarations: `13`
- Discovered test functions: `2`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
