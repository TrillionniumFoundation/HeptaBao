# heptabao-migration

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns migration writer authority, the immutable source-to-target inventory, durable copy intents, reconciliation-only unknown outcomes, cutover anchors and rollback anchors. It does not manufacture OpenBao source bytes, provider credentials, legal approval, compatibility evidence or migration authority.

## Public API and ownership

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-migration`; Cargo SHA-256 `77984cf865ac37a5a7d49c9746551c690b5fda21cd5030725d4f32fee0337e9d`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `enum` | `MigrationObjectClass` | `crates/heptabao-migration/src/durable.rs:31` | `pub enum MigrationObjectClass {` |
| `struct` | `MigrationObject` | `crates/heptabao-migration/src/durable.rs:51` | `pub struct MigrationObject {` |
| `fn` | `new` | `crates/heptabao-migration/src/durable.rs:61` | `pub fn new(` |
| `struct` | `MigrationInventory` | `crates/heptabao-migration/src/durable.rs:110` | `pub struct MigrationInventory {` |
| `fn` | `new` | `crates/heptabao-migration/src/durable.rs:116` | `pub fn new(mut objects: Vec<MigrationObject>) -> Result<Self, MigrationJournalError> {` |
| `fn` | `objects` | `crates/heptabao-migration/src/durable.rs:182` | `pub fn objects(&self) -> &[MigrationObject] {` |
| `fn` | `sha256` | `crates/heptabao-migration/src/durable.rs:186` | `pub fn sha256(&self) -> &str {` |
| `fn` | `execution_order` | `crates/heptabao-migration/src/durable.rs:190` | `pub fn execution_order(&self) -> Result<Vec<&MigrationObject>, MigrationJournalError> {` |
| `struct` | `MigrationBinding` | `crates/heptabao-migration/src/durable.rs:244` | `pub struct MigrationBinding {` |
| `fn` | `new` | `crates/heptabao-migration/src/durable.rs:253` | `pub fn new(` |
| `enum` | `MigrationObjectState` | `crates/heptabao-migration/src/durable.rs:297` | `pub enum MigrationObjectState {` |
| `fn` | `requires_reconciliation` | `crates/heptabao-migration/src/durable.rs:322` | `pub fn requires_reconciliation(&self) -> bool {` |
| `enum` | `DurableMigrationPhase` | `crates/heptabao-migration/src/durable.rs:330` | `pub enum DurableMigrationPhase {` |
| `struct` | `WriterFenceReceipt` | `crates/heptabao-migration/src/durable.rs:343` | `pub struct WriterFenceReceipt {` |
| `fn` | `new` | `crates/heptabao-migration/src/durable.rs:351` | `pub fn new(` |
| `struct` | `CopyIntent` | `crates/heptabao-migration/src/durable.rs:382` | `pub struct CopyIntent {` |
| `struct` | `DurableMigrationJournal` | `crates/heptabao-migration/src/durable.rs:626` | `pub struct DurableMigrationJournal {` |
| `fn` | `create_new` | `crates/heptabao-migration/src/durable.rs:647` | `pub fn create_new(` |
| `fn` | `open` | `crates/heptabao-migration/src/durable.rs:708` | `pub fn open(` |
| `fn` | `binding` | `crates/heptabao-migration/src/durable.rs:735` | `pub fn binding(&self) -> MigrationBinding {` |
| `const` | `fn` | `crates/heptabao-migration/src/durable.rs:739` | `pub const fn generation(&self) -> u64 {` |
| `const` | `fn` | `crates/heptabao-migration/src/durable.rs:743` | `pub const fn phase(&self) -> DurableMigrationPhase {` |
| `const` | `fn` | `crates/heptabao-migration/src/durable.rs:747` | `pub const fn source_writer_enabled(&self) -> bool {` |
| `const` | `fn` | `crates/heptabao-migration/src/durable.rs:751` | `pub const fn target_writer_enabled(&self) -> bool {` |
| `const` | `fn` | `crates/heptabao-migration/src/durable.rs:755` | `pub const fn recovered_from_previous(&self) -> bool {` |
| `fn` | `object_state` | `crates/heptabao-migration/src/durable.rs:759` | `pub fn object_state(&self, object_id: &str) -> Option<&MigrationObjectState> {` |
| `fn` | `pending_reconciliation` | `crates/heptabao-migration/src/durable.rs:763` | `pub fn pending_reconciliation(&self) -> Vec<&str> {` |
| `fn` | `fence_source` | `crates/heptabao-migration/src/durable.rs:775` | `pub fn fence_source(` |
| `fn` | `begin_object` | `crates/heptabao-migration/src/durable.rs:794` | `pub fn begin_object(` |
| `fn` | `mark_outcome_unknown` | `crates/heptabao-migration/src/durable.rs:859` | `pub fn mark_outcome_unknown(` |
| `fn` | `confirm_committed` | `crates/heptabao-migration/src/durable.rs:888` | `pub fn confirm_committed(` |
| `fn` | `confirm_not_committed` | `crates/heptabao-migration/src/durable.rs:920` | `pub fn confirm_not_committed(` |
| `fn` | `fail_object` | `crates/heptabao-migration/src/durable.rs:946` | `pub fn fail_object(` |
| `fn` | `verify_copy` | `crates/heptabao-migration/src/durable.rs:990` | `pub fn verify_copy(&mut self) -> Result<(), MigrationJournalError> {` |
| `fn` | `activate_target` | `crates/heptabao-migration/src/durable.rs:1007` | `pub fn activate_target(` |
| `fn` | `fence_target` | `crates/heptabao-migration/src/durable.rs:1031` | `pub fn fence_target(` |
| `fn` | `rollback` | `crates/heptabao-migration/src/durable.rs:1054` | `pub fn rollback(` |
| `enum` | `MigrationJournalError` | `crates/heptabao-migration/src/durable.rs:1138` | `pub enum MigrationJournalError {` |
| `use` | `durable::*` | `crates/heptabao-migration/src/lib.rs:16` | `pub use durable::*;` |
| `enum` | `MigrationPhase` | `crates/heptabao-migration/src/lib.rs:19` | `pub enum MigrationPhase {` |
| `struct` | `MigrationState` | `crates/heptabao-migration/src/lib.rs:31` | `pub struct MigrationState {` |
| `fn` | `new` | `crates/heptabao-migration/src/lib.rs:42` | `pub fn new(migration_id: Id, source_id: Id, target_id: Id) -> Result<Self, MigrationError> {` |
| `fn` | `fence_source` | `crates/heptabao-migration/src/lib.rs:57` | `pub fn fence_source(&mut self) -> Result<(), MigrationError> {` |
| `fn` | `begin_copy` | `crates/heptabao-migration/src/lib.rs:65` | `pub fn begin_copy(&mut self) -> Result<(), MigrationError> {` |
| `fn` | `verify_copy` | `crates/heptabao-migration/src/lib.rs:72` | `pub fn verify_copy(&mut self) -> Result<(), MigrationError> {` |
| `fn` | `activate_target` | `crates/heptabao-migration/src/lib.rs:79` | `pub fn activate_target(&mut self) -> Result<(), MigrationError> {` |
| `fn` | `fence_target` | `crates/heptabao-migration/src/lib.rs:90` | `pub fn fence_target(&mut self) -> Result<(), MigrationError> {` |
| `fn` | `rollback` | `crates/heptabao-migration/src/lib.rs:98` | `pub fn rollback(&mut self) -> Result<(), MigrationError> {` |
| `fn` | `fail` | `crates/heptabao-migration/src/lib.rs:117` | `pub fn fail(&mut self) {` |
| `fn` | `validate_no_overlap` | `crates/heptabao-migration/src/lib.rs:124` | `pub fn validate_no_overlap(&self) -> Result<(), MigrationError> {` |
| `enum` | `MigrationError` | `crates/heptabao-migration/src/lib.rs:144` | `pub enum MigrationError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

The admitted object classes are policy, mount, auth method, identity, token, lease, KV history, Transit, PKI, SSH, database, audit, plugin catalog and system metadata. Every object has a bounded identifier, canonical absolute source path, source digest, expected target digest and a closed dependency set. The inventory is sorted, dependency-closed, acyclic and SHA-256 bound. Per-object states are pending, intent persisted, outcome unknown after entry, verified or failed closed.

The journal envelope contains a schema identifier, canonical payload digest and payload. The payload binds both endpoint identities, profile, inventory digest, generation, writer flags, fence and cutover receipts, every object state and the complete used-operation denominator.

## Invariants and authorization

Source and target writer flags may never both be true. Identical endpoints, source/profile/inventory rebinding, duplicate objects, missing dependencies, cycles, duplicate operation identifiers and digest substitutions are rejected. Target activation requires the source writer to be fenced and every object to be verified against its exact expected target digest. Rollback after cutover requires a target-fence receipt first.

The journal validates state; it does not authorize an operator. The surrounding control plane must authorize enrollment of the migration plan and custody of every provider credential before invoking a transition.

## Failure, retry and reconciliation

A copy operation receives an intent only after its operation identifier and object transition have been durably published. Once backend entry may have occurred, `OutcomeUnknownAfterEntry` is sticky and permits only authoritative readback. A missing local receipt is never treated as proof that the target effect is absent. `confirm_not_committed` returns the object to pending, but the original operation identifier remains permanently consumed; a retry needs a new identifier. A digest mismatch fails before verification, and explicit object failure disables both writers and fails the journal closed.

## Concurrency and ordering

`ExclusiveDirectory` anchors the root by descriptor and holds one inter-process writer lock for the journal lifetime. Dependency order is deterministic. Object entry is forbidden until every dependency is verified. All mutations clone the current record, validate the candidate, publish it atomically, and update in-memory state only after durable publication succeeds.

## Security and privacy

The journal stores identifiers, paths, digests, bounded reason codes and authority receipts, never source secret bytes or migration credentials. Files are created with owner-only mode on Unix, final and parent symlinks are rejected by the guarded root, and diagnostic `Debug` output omits absolute paths and journal contents. Integrity failures, conflicting generations and unsafe roots are terminal errors rather than fallback paths.

## Persistence and compatibility

The Linux runtime writes a SHA-256 envelope to a create-new temporary file, fsyncs it, rotates the previous generation, renames the new current generation and fsyncs the descriptor-bound parent directory. Startup verifies current and previous generations and selects only the unique highest valid generation. A missing current file may recover the previous valid generation and reports that fact; equal-generation conflicts are rejected. Non-Linux storage operation is explicitly unsupported rather than weakened.

The journal represents the migration protocol, not proof that every OpenBao format adapter exists. Provider adapters must supply exact source and expected normalized target digests and authoritative readback.

## Observability

Safe dimensions are migration identifier, phase, generation, object class, bounded reason code, operation outcome class, recovery-from-previous and reconciliation queue length. Source values, target values, credentials, journal bytes and absolute filesystem paths are prohibited from telemetry.

## Operations

Operators create a closed inventory, bind the exact source and target, obtain and record a source-writer fence, copy in deterministic dependency order, reconcile every unknown result, verify every expected target digest, then activate the target with a cutover anchor. Rollback after activation requires a separately observed target fence. Writer overlap, unexplained generation rollback, integrity mismatch or ambiguous generations are incidents.

## Tests and executable evidence

`cargo test -p heptabao-migration --all-targets` covers inventory sorting and cycle rejection, intent-before-entry, restart-persistent unknown outcomes, new-identifier retry, dependency gating, exact target-digest verification, all-object cutover, target-fenced rollback, binding substitution, exclusive writer fencing and previous-generation recovery. Strict Clippy, exact-head and prospective-main workflows provide repository-controlled evidence only.

## Evolution and open boundaries

Still external or integration-owned are OpenBao provider acquisition, complete class-specific adapters, live interruption campaigns against every supported backend, platform qualification, independent data comparison, operator approval and migration authority. Those gaps remain fail-closed even when this journal passes all repository tests.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-migration`
- Crate path: `crates/heptabao-migration`
- Cargo manifest SHA-256: `77984cf865ac37a5a7d49c9746551c690b5fda21cd5030725d4f32fee0337e9d`
- Rust source files: `2`
- Public lexical declarations: `51`
- Discovered test functions: `7`
- Workspace-internal dependencies: `heptabao-domain` (dependencies), `heptabao-filesystem-guard` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
