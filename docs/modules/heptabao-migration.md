# heptabao-migration

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns migration writer authority, the immutable source-to-target inventory, durable copy intents, reconciliation-only unknown outcomes, cutover anchors and rollback anchors. It does not manufacture OpenBao source bytes, provider credentials, legal approval, compatibility evidence or migration authority.

## Public API and ownership

`MigrationState` remains the small in-memory writer-authority primitive. `MigrationInventory` owns the closed persisted-domain denominator and dependency graph. `MigrationBinding` binds an exact migration, source, target, profile and inventory digest. `DurableMigrationJournal` is the only owner allowed to publish durable copy, cutover and rollback state under an exclusive directory writer fence.

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
