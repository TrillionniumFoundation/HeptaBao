# `heptabao-recovery-core` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `recovery-storage-audit-security`  
**Maturity:** `ANCHORED_RECOVERY_FOUNDATION_IMPLEMENTED`  
**Authority effect:** `NONE`

## Purpose and non-goals

Creates, authenticates, decodes, verifies and stages bounded recovery archives tied to current rollback checkpoints.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: an injected recovery target publisher after verification.
- Accountable owner role: `recovery-storage-audit-security`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `heptabao-barrier-api`
- `heptabao-journal-api`
- `heptabao-rollback-anchor`
- `heptabao-storage-api`

Reverse HeptaBao dependants:
- `none`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

- `const MAX_RECOVERY_AUTHENTICATOR_ID_BYTES` (crates/heptabao-recovery-core/src/lib.rs)
- `const MAX_RECOVERY_ID_BYTES` (crates/heptabao-recovery-core/src/lib.rs)
- `const MAX_RECOVERY_PAYLOAD_BYTES` (crates/heptabao-recovery-core/src/lib.rs)
- `const MAX_RECOVERY_RECORDS` (crates/heptabao-recovery-core/src/lib.rs)
- `const MAX_RECOVERY_STATE_BYTES` (crates/heptabao-recovery-core/src/lib.rs)
- `const fn` (crates/heptabao-recovery-core/src/lib.rs)
- `enum PublishFailure` (crates/heptabao-recovery-core/src/lib.rs)
- `enum RecoveryCaptureError` (crates/heptabao-recovery-core/src/lib.rs)
- `enum RecoveryContractError` (crates/heptabao-recovery-core/src/lib.rs)
- `enum RecoveryRestoreError` (crates/heptabao-recovery-core/src/lib.rs)
- `enum RecoveryVerificationError` (crates/heptabao-recovery-core/src/lib.rs)
- `enum StageFailure` (crates/heptabao-recovery-core/src/lib.rs)
- `fn archive_id` (crates/heptabao-recovery-core/src/lib.rs)
- `fn as_str` (crates/heptabao-recovery-core/src/lib.rs)
- `fn capture` (crates/heptabao-recovery-core/src/lib.rs)
- `fn decode` (crates/heptabao-recovery-core/src/lib.rs)
- `fn encode` (crates/heptabao-recovery-core/src/lib.rs)
- `fn from_journal_record` (crates/heptabao-recovery-core/src/lib.rs)
- `fn into_image` (crates/heptabao-recovery-core/src/lib.rs)
- `fn into_journal_record` (crates/heptabao-recovery-core/src/lib.rs)
- `fn into_parts` (crates/heptabao-recovery-core/src/lib.rs)
- `fn new` (crates/heptabao-recovery-core/src/lib.rs)
- `fn payload` (crates/heptabao-recovery-core/src/lib.rs)
- `fn records` (crates/heptabao-recovery-core/src/lib.rs)
- `fn restore` (crates/heptabao-recovery-core/src/lib.rs)
- `fn seal` (crates/heptabao-recovery-core/src/lib.rs)
- `fn sealed_state` (crates/heptabao-recovery-core/src/lib.rs)
- `fn stage_if_empty` (crates/heptabao-recovery-core/src/lib.rs)
- `fn verify` (crates/heptabao-recovery-core/src/lib.rs)
- `struct AuthorizedRecoveryImage` (crates/heptabao-recovery-core/src/lib.rs)
- `struct RecoveryArchiveId` (crates/heptabao-recovery-core/src/lib.rs)
- `struct RecoveryArchive` (crates/heptabao-recovery-core/src/lib.rs)
- `struct RecoveryAuthenticatorId` (crates/heptabao-recovery-core/src/lib.rs)
- `struct RecoveryImage` (crates/heptabao-recovery-core/src/lib.rs)
- `struct RecoveryRecord` (crates/heptabao-recovery-core/src/lib.rs)
- `struct RecoveryRestorer` (crates/heptabao-recovery-core/src/lib.rs)
- `struct RecoveryTag` (crates/heptabao-recovery-core/src/lib.rs)
- `struct RestoreReceipt` (crates/heptabao-recovery-core/src/lib.rs)
- `struct VerifiedRecoveryImage` (crates/heptabao-recovery-core/src/lib.rs)
- `trait RecoveryAuthenticator` (crates/heptabao-recovery-core/src/lib.rs)
- `trait RecoveryTarget` (crates/heptabao-recovery-core/src/lib.rs)
- `type RecoveryCaptureResult` (crates/heptabao-recovery-core/src/lib.rs)
- `type RecoveryImageParts` (crates/heptabao-recovery-core/src/lib.rs)
- `type RecoveryRestoreResult` (crates/heptabao-recovery-core/src/lib.rs)
- `type RecoveryVerifyResult` (crates/heptabao-recovery-core/src/lib.rs)

This index is generated from explicit `pub` declarations and is not a replacement for rustdoc. New public items require an invariant, error semantics, tests and an entry in this guide.

## State and invariants

- Archive binds state generation/digest, journal tail, key epoch, checkpoint and authenticator identities.
- Decoder rejects malformed, excessive, discontinuous, divergent, truncated and trailing input.
- Restore requires the exact externally verified current checkpoint.
- Target admission and staging are one atomic provider operation.
- Unknown publication outcome remains explicit.
- An outer anchor-fence error after closure entry is an outcome-unknown result even when the target returned an exact receipt.
- Anchor contract, anchor provider, checkpoint-authenticator and target errors remain distinct.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

After unknown publication, inspect the target and exact receipt before any retry. Never overwrite a non-empty target blindly.

The restore error classes have different retry authority:

| Error class | Publication by this call | Retry rule |
|---|---|---|
| `CheckpointNotAnchored` | definitely not entered through the current fence | obtain a new authorized archive/checkpoint; do not reinterpret stale authority |
| `Anchor(error)` | fence failed before closure entry | diagnose provider; no publication is attributed to this invocation |
| `CheckpointAuthenticator(error)` | current checkpoint could not be authenticated | security hold; no publication |
| `Target(error)` from staging or proven-not-published path | provider-specific, bounded by the variant | follow target contract; never switch targets automatically |
| `PublishOutcomeUnknown(error)` | may have published | target readback required |
| `PublishReceiptMismatchOutcomeUnknown` | published effect may exist | exact target readback required |
| `AnchorFenceOutcomeUnknown(error)` | closure ran; target and fence completion may have occurred | reconcile both external anchor and target before retry |

Errors are part of the public contract. Unknown, blocked, stale, corrupt, unauthenticated and unauthorized outcomes remain distinct. Callers must not collapse them into a generic retryable transport failure.

## Persistent or wire formats

All durable or wire encodings are versioned, bounded and strict. Decoders reject truncation, impossible lengths, invalid identity/version and trailing bytes. Exact field layouts remain normative in the linked domain contract and source tests.

Format changes require an explicit version transition, backward/forward compatibility decision, hostile decoder tests and migration/rollback treatment.

## Concurrency and cancellation

The caller must preserve single-writer or immutable-reader ownership declared by the domain. Cancellation after an irreversible provider call or durable publication changes only the waiter; it does not revoke the completed authority or commit. Shared mutable state requires a documented fence, generation or epoch.

Cancellation or provider lease loss after entry into `with_current_fence` is classified as `AnchorFenceOutcomeUnknown`; cancellation must not turn an already-published restore into a pre-entry failure.

## Security and secret handling

- Secret-bearing bytes are not logged, formatted, cloned or serialized unless an explicit audited exposure method permits it.
- `Debug` output carries only opaque identity, lengths and safe state classes.
- Buffer overwrite is best effort and does not prove allocator, swap, crash-dump or side-channel resistance.
- No real token, unseal share, recovery key, private key or production snapshot belongs in source, tests, CI or diagnostics.

## Testing and evidence

Detected crate-local tests include:
- `archive_authenticator_identity_is_bound` (crates/heptabao-recovery-core/src/lib.rs)
- `capture_encode_decode_verify_and_restore_round_trip` (crates/heptabao-recovery-core/src/lib.rs)
- `restore_requires_the_exact_externally_verified_checkpoint` (crates/heptabao-recovery-core/src/lib.rs)
- `tamper_trailing_bytes_and_non_empty_target_fail_closed` (crates/heptabao-recovery-core/src/lib.rs)
- `unknown_target_publication_remains_explicit` (crates/heptabao-recovery-core/src/lib.rs)
- `anchor_fence_is_held_across_target_publication` (crates/heptabao-recovery-core/src/lib.rs)
- `wrong_receipt_after_publication_is_outcome_unknown` (crates/heptabao-recovery-core/src/lib.rs)
- `post_entry_anchor_fence_failure_is_outcome_unknown` (crates/heptabao-recovery-core/src/lib.rs)

The post-entry test uses a deterministic anchor that invokes the restore closure, leaves the target occupied with restored state and then returns `OutcomeUnknownAfterEntry`. The required API result is `AnchorFenceOutcomeUnknown`, proving the call cannot be safely retried from its return value alone.

Required local gate:

```text
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
```

Domain changes also run plan mutation tests, current platform/Oracle regressions and frozen inherited-source replay. A green run is technical evidence only.

## Extension workflow

1. Bind the exact base commit/tree and read the current plan, blocker register and this guide.
2. Add or change typed contracts before concrete adapters.
3. Define state transition, error, retry and cancellation behavior.
4. Add positive, hostile and restart/replay tests.
5. Update this guide, traceability and normative manifest in the same change.
6. Run exact-head read-only CI; preserve failed evidence.
7. Obtain independent review for storage, cryptography, security or distributed-systems critical changes.

Any recovery target or anchor provider must document its linearization point, no-effect proof, outcome-unknown boundary, readback method and operator hold state before it may be composed into a higher profile.

## Operations and diagnostics

Recovery requires a two-person, source-bound procedure with archive digest, external anchor observation and post-restore verification.

Diagnostics must preserve stable distinctions among stale anchor, anchor contract failure, pre-entry provider failure, checkpoint authentication failure, target failure, publication uncertainty, receipt mismatch and post-entry fence uncertainty. After `AnchorFenceOutcomeUnknown`, freeze automation and retain the archive ID, checkpoint digest, anchor revision and safe target/anchor observations without logging sealed payload bytes or authentication tags.

## Known gaps

- No production archive authenticator or backup custody.
- No production remote anchor or target readback provider.
- No online upgrade/migration integration.
- No HA/replicated recovery.
- Destructive controller/filesystem qualification remains external.

## Traceability and maintenance

- Crate path: `crates/heptabao-recovery-core`
- Module guide: `docs/modules/heptabao-recovery-core.md`
- Historical module baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- V1.4.6 phase-aware fence source preflight: `8893cdaad4eec3c11f7b367c7bf0e57c20b6631a` / `5c551fa2665bc002113b39cec1b65afe02fe2b99`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`, `scripts/validate_plan_v1_4_6.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.

### V1.4.5 linear restore admission

Restore receives an `AnchorCoordinator`, not a detached verified token. It verifies the archive checkpoint against the live external anchor before target inspection and again immediately before creating the private `AuthorizedRecoveryImage` capability. Targets can stage only that capability, cannot receive a public verified image, and the receipt binds the current anchor revision. The verified image cannot be downgraded to a raw recovery image.

### V1.4.5 publication receipt uncertainty

A mismatched receipt returned after `publish` is classified as `PublishReceiptMismatchOutcomeUnknown`, because publication may already have occurred. It is never a safe retryable contract failure. Operators and target providers must perform authoritative readback and reconciliation before another restore attempt. Only `AuthorizedRecoveryImage` exposes consumable sealed state and journal records; archive-authenticated images do not.

## V1.4.6 atomic admission and fenced publish

`RecoveryTarget::stage_if_empty` replaces separate advisory emptiness and stage calls. The provider atomically verifies/claims an empty target and returns a staged token consumed by `publish`. `RecoveryRestorer` creates the `AuthorizedRecoveryImage`, stages and publishes it, and compares the complete receipt while the rollback provider's exact-current fence is held.

A provider-declared publication-unknown or mismatched post-publication receipt requires target readback. It is never a safe automatic retry.

## V1.4.6 outer-fence outcome preservation

`RecoveryRestorer` now maps only a real `AnchorContractError::CheckpointNotCurrent` to `CheckpointNotAnchored`. Other anchor contract errors, pre-entry anchor provider failures and checkpoint-authenticator failures retain separate typed variants. When the anchor reports `FenceOutcomeUnknown` after closure entry, restore returns `AnchorFenceOutcomeUnknown` regardless of an inner exact receipt. This prevents release, lease or post-operation failures from being relabelled as a safe stale-checkpoint result.
