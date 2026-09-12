# heptabao-migration

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns migration writer authority, the immutable source-to-target inventory, durable copy intents, reconciliation-only unknown outcomes, cutover anchors and rollback anchors. It does not manufacture OpenBao source bytes, provider credentials, legal approval, compatibility evidence or migration authority.

## Public API and ownership

### Current API contract and integration boundary

Two exported layers coexist. `MigrationState` in `lib.rs` is a public-field in-memory phase model: `fence_source`, `begin_copy`, `verify_copy`, `activate_target`, `fence_target`, `rollback` and `fail` change flags/generation but do not operate a source or target. `validate_no_overlap` checks the two local flags; caller mutation of public fields is not an externally enforced writer fence.

`MigrationObject::new` binds ID/class/source path/source SHA-256/expected target SHA-256/dependencies. `MigrationInventory::new` owns 1–4096 objects, canonicalizes object order, requires at most 128 sorted unique dependencies per object, rejects missing dependencies/cycles and computes the inventory digest. `execution_order()` returns borrowed objects in deterministic dependency order. The 14 object-class variants define an inventory vocabulary; they do not supply class-specific OpenBao readers or target writers. SHA-256 text validation accepts 64 lowercase hex characters, including an all-zero value; actual source/target hashing is an adapter duty.

`DurableMigrationJournal` owns the Linux exclusive directory guard, frozen inventory, current record and selected journal authentication profile. `create_new(root, binding, inventory)` and `open(root, &expected_binding, inventory)` remain compatibility aliases for the **unkeyed v1 checksum** profile; new explicit `create_legacy_checksum`/`open_legacy_checksum` names expose that limitation. The root must meet the guarded safe-directory contract. `binding`, `phase`, `generation`, writer flags and `recovered_from_previous` expose status; `object_state(id)` borrows a per-object record.

For keyed checkpoints, `MigrationJournalAuthenticator::new(key_id, material: &[u8])` requires a valid bounded key ID and exactly 32 non-all-zero key bytes. `create_authenticated(root, binding, inventory, authenticator)` and `open_authenticated(root, &expected_binding, inventory, authenticator)` take ownership of that provider. `authentication_key_id()` exposes `Some(id)` for v2 or `None` for legacy. The caller owns key generation, external custody and clearing its original key buffer; key material is not written to the journal or exposed by Debug.

V2 uses HMAC-SHA256 over a domain-separated canonical envelope containing schema, key ID, payload digest and typed record. `InvalidAuthenticationKey` rejects bad construction; `AuthenticationFailed` rejects wrong key/ID, tampered envelope or profile mismatch. Opening v2 never falls back to an unkeyed v1 checkpoint, and the legacy reader rejects v2. Creation does not overwrite or automatically migrate an existing journal. A v1 SHA-256 checksum only detects inconsistency, whereas a v2 HMAC rejects unauthorized rewriting by a writer without the key. Neither profile encrypts metadata, provides an append-only complete history or detects a consistent rollback of all local files without an independent anchor.

Current authenticated constructor declaration (illustrative excerpt, not a standalone program):

<!-- CURRENT API: crates/heptabao-migration/src/durable.rs#create_authenticated -->
```text
pub fn create_authenticated(
        root: impl AsRef<Path>,
        binding: MigrationBinding,
        inventory: MigrationInventory,
        authenticator: MigrationJournalAuthenticator,
    ) -> Result<Self, MigrationJournalError>
```

After an externally obtained `WriterFenceReceipt`, `fence_source(&receipt)` records source fencing. `begin_object(object_id, operation_id)` requires every dependency Verified, both writers disabled and a globally unused operation ID; it persists intent before returning `CopyIntent`. The copy adapter then performs the effect. `confirm_committed` accepts only the bound target digest; `mark_outcome_unknown` marks an entered uncertainty; `confirm_not_committed` requires that explicit unknown state before returning Pending with a permanently consumed old operation ID. `fail_object` records a bounded reason code and locally fails both writer flags closed.

On restart, an `IntentPersisted` object is not automatically converted to `OutcomeUnknownAfterEntry`. `pending_reconciliation()` lists only the latter. A restart controller must inspect every inventory object's state, treat surviving intents as requiring readback, and explicitly mark them unknown if the effect is not proven committed. It must not interpret an empty pending-reconciliation list as proof that no copy entered. A journal publication I/O error may leave a newer generation on disk; stop transitions, release ownership and reopen before deciding the next action.

`verify_copy()` requires every object Verified; `activate_target(&receipt, anchor_digest)` records target activation only after that point. Rollback after activation requires `fence_target` with a newer target generation, then `rollback` with a newer source-reactivation receipt and no outstanding intent/unknown state. These methods validate receipt fields and local ordering, not the external fencing action or receipt signatures. The controller owns real writer exclusion, source preservation, target readback and anchor custody.

The durable journal is implemented but **outside the current server dependency closure**. The Python live KV tool `qa/openbao-acceptance/migrate_kv2.py` does not use this Rust journal; selecting its v2 HMAC API does not automatically authenticate that tool's checkpoint. There is no automatic migration entrypoint in the native server through this crate, and no general OpenBao migration is established merely by serializing all object classes.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

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

The Linux runtime writes the selected v1 checksum envelope or `heptabao.migration-journal-authenticated-envelope.v2` HMAC envelope to a create-new temporary file, fsyncs it, rotates the previous generation, renames the new current generation and fsyncs the descriptor-bound parent directory. The inner journal record remains `heptabao.migration-journal.v1`; the authenticated envelope profile is a separate version boundary. Startup verifies current and previous generations under the explicitly selected profile/key and selects only the unique highest valid generation. A profile/key authentication failure is not permission to fall back to an older unkeyed file. A missing current file may recover the previous valid generation and reports that fact; equal-generation conflicts are rejected. Non-Linux storage operation is explicitly unsupported rather than weakened.

The journal represents the migration protocol, not proof that every OpenBao format adapter exists. Provider adapters must supply exact source and expected normalized target digests and authoritative readback.

## Observability

No metrics exporter is emitted by this crate. Suggested integration dimensions are migration identifier, phase, generation, object class, bounded reason code, operation outcome class, recovery-from-previous and reconciliation queue length. Source values, target values, credentials, journal bytes and absolute filesystem paths are prohibited from telemetry.

## Operations

Operators select an explicit checksum or authenticated profile and preserve its key ID/key custody separately; changing profiles or keys requires an explicit offline migration design, not a different argument to reopen. They create a closed inventory, bind the exact source and target, obtain and record a source-writer fence, copy in deterministic dependency order, reconcile every unknown result, verify every expected target digest, then activate the target with a cutover anchor. Rollback after activation requires a separately observed target fence. Writer overlap, unexplained generation rollback, integrity mismatch or ambiguous generations are incidents.

## Tests and executable evidence

Current authenticated-profile regressions in `crates/heptabao-migration/src/durable.rs`:

- `authenticated_checkpoint_preserves_reconciliation_and_cutover_after_restart` preserves the admitted transition state across reopen.
- `authenticated_checkpoint_rejects_recomputed_checksum_and_wrong_key_without_rewriting` rejects malicious recomputation and wrong keys without repairing files.
- `authenticated_checkpoint_rejects_legacy_downgrade_in_either_generation` rejects unkeyed current/previous substitutions.
- `authentication_profiles_require_explicit_creation_without_implicit_upgrade` preserves the explicit profile boundary.
- `authenticated_previous_generation_recovery_keeps_binding_and_reconcile_only_state` checks fallback still requires the correct authenticated binding.
- `authentication_key_validation_and_debug_do_not_expose_key_material` checks key bounds and redaction.

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::rollback_requires_target_fencing_after_cutover`](../../crates/heptabao-migration/src/lib.rs) checks the in-memory phase ordering before source reactivation.
- [`durable::tests::inventory_is_closed_sorted_dependency_checked_and_hashed`](../../crates/heptabao-migration/src/durable.rs) checks inventory ordering/digest and rejects a dependency cycle.
- [`durable::tests::intent_unknown_and_reconciliation_survive_restart`](../../crates/heptabao-migration/src/durable.rs) checks explicitly marked unknown state persists, blocks blind retry and consumes old operation IDs.
- [`durable::tests::cutover_requires_every_digest_and_never_overlaps_writers`](../../crates/heptabao-migration/src/durable.rs) checks target digest/all-object gates and target fencing before rollback.
- [`durable::tests::binding_tampering_and_second_writer_fail_closed`](../../crates/heptabao-migration/src/durable.rs) checks source rebinding and concurrent writer rejection.
- [`durable::tests::previous_generation_is_recovered_but_conflicts_are_rejected`](../../crates/heptabao-migration/src/durable.rs) checks previous-generation fallback and conflicting bindings.

`cargo test -p heptabao-migration --all-targets` covers inventory sorting and cycle rejection, intent-before-entry, restart-persistent unknown outcomes, new-identifier retry, dependency gating, exact target-digest verification, all-object cutover, target-fenced rollback, binding substitution, exclusive writer fencing and previous-generation recovery. Strict Clippy, exact-head and prospective-main workflows provide repository-controlled evidence only.

## Evolution and open boundaries

Still external or integration-owned are OpenBao provider acquisition, complete class-specific adapters, live interruption campaigns against every supported backend, platform qualification, independent data comparison, operator approval and migration authority. Those gaps remain fail-closed even when this journal passes all repository tests.

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

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
