# HeptaBao Authoritative Recovery Protocol V1

## 1. Scope and non-authority statement

This document specifies the as-built V1.4.6 single-node recovery kernel. It is a
source contract and review aid. It does not qualify a production rollback
provider, recovery target, filesystem, controller, KMS/HSM, backup ceremony or
operator process.

## 2. Capability topology

| Capability | Constructor / owner | May release sealed state? | May publish? | Reusable? |
|---|---|---:|---:|---:|
| `RecoveryArchive` | capture or decoder | no | no | value object |
| `VerifiedRecoveryImage` | archive authenticator | no | no | non-cloneable |
| `AuthorizedRecoveryImage` | `RecoveryRestorer` inside anchor fence | yes, only to target | indirectly | consumed |
| `CommitIntent` | storage provider / validated metadata constructor | no | no | metadata only |
| `PreparedDurableMutation` | durable engine after barrier sealing | owns sealed candidate | through durable engine only | consumed |
| anchor fence closure | rollback provider | no | serializes publication authority | single invocation |
| target staged token | recovery target | provider-defined | yes, through target | consumed |

`CommitIntent` is intentionally not described as proof of ledger persistence.
The journaled composition derives recovery from replayed `IntentCommitted`
state; the storage descriptor only identifies the exact provider state to
classify.

## 3. Anchor publication-fence protocol

The authoritative sequence is:

```text
archive authentication
→ exact current-checkpoint verification
→ provider current-checkpoint fence acquisition
→ exact checkpoint comparison while held
→ target.stage_if_empty(authorized image)
→ target.publish(staged token)
→ complete receipt comparison
→ prove clean fence completion or return post-entry uncertainty
```

`RollbackAnchor::with_current_fence` must serialize against
`compare_and_swap` using the same provider primitive. The closure must not run
when the current checkpoint differs. For an in-process provider this can be one
mutex or transaction. A remote implementation needs a lease or transaction
whose validity spans publication.

The fence has an explicit phase contract:

| Public result | Closure invocation guarantee | Required caller action |
|---|---|---|
| `AnchorFenceError::CheckpointNotCurrent` | definitely not invoked | reject stale authority |
| `AnchorFenceError::ProviderBeforeEntry(error)` | definitely not invoked | preserve provider error; no publication attributed to this call |
| `Ok(operation_result)` | invoked exactly once | process the operation result without reinterpretation |
| `AnchorFenceError::OutcomeUnknownAfterEntry(error)` | invoked; completion/fence validity uncertain | reconcile external anchor and target before any retry |

Once the closure has been invoked, unlock, lease-release, transport,
persistence, cancellation or post-operation verification uncertainty must never
be returned as `CheckpointNotCurrent` or `ProviderBeforeEntry`. The provider
must use `OutcomeUnknownAfterEntry`; the operation result is then deliberately
unavailable because the fence cannot prove a clean authority boundary.

`AnchorCoordinator` preserves `FenceOutcomeUnknown`, and
`RecoveryRestorer` maps it to `RecoveryRestoreError::AnchorFenceOutcomeUnknown`.
It separately preserves non-current contract errors, other anchor contract
errors, anchor provider failures and checkpoint-authenticator failures. The
restore layer may translate only an actual `CheckpointNotCurrent` contract
result to `CheckpointNotAnchored`.

A mere reread before `publish` is forbidden because it leaves a race window.

## 4. Atomic empty-target admission

`RecoveryTarget::stage_if_empty` atomically verifies that no authoritative
target state exists and claims/stages the target under its writer fence.
`StageFailure::TargetNotEmpty` is a stable admission result.
`StageFailure::Provider` is an operational provider failure.

The staged token must retain whatever target-side exclusivity is required so a
second writer cannot publish between staging and `publish`.

## 5. Durable mutation recovery state machine

| Ledger phase | Authoritative provider observation | Legal transition | Retry |
|---|---|---|---|
| `Accepted` | no durable descriptor | remain accepted | no blind duplicate |
| `IntentCommitted` | exact committed generation+digest | `StateCommitted` | lookup only |
| `IntentCommitted` | previous current; exact candidate absent | `AbortedBeforeStateCommit` | new operation ID |
| `IntentCommitted` | exact orphan bundle authenticates and matches | provider completes publish, then `StateCommitted` | lookup only |
| `IntentCommitted` | divergent generation/digest or malformed layout | none; remain fenced | operator reconciliation |
| `StateCommitted` | any | terminal | lookup only |

Generic `Reconciled` remains forbidden for durable mutation intent.

## 6. Storage crash matrix

| Crash / error boundary | Durable observation on reopen | Required action |
|---|---|---|
| before intent journal append | no intent | request was not admitted |
| event bytes durable, append returns error | authenticated record/orphan may exist | enter `ReplayRequired`; authoritative journal recovery |
| after `IntentCommitted`, before bundle creation | exact previous generation | record `AbortedBeforeStateCommit` |
| bundle fsync complete, before `CURRENT` rename | one exact orphan bundle | complete only when descriptor and authenticated bundle match |
| `CURRENT` rename complete, parent sync/return uncertain | exact committed generation may be visible | authoritative readback; never blind retry |
| state committed, `StateCommitted` append uncertain | store exact; ledger append ambiguous | journal replay then record/confirm exact committed state |
| divergent/multiple orphan/temp artifacts | corrupt or conflicting layout | fail closed |

## 7. Journal append-unknown matrix

| Provider proof | Ledger response |
|---|---|
| affirmative proof no record and no tail publication occurred | provider may classify `DefinitelyNotAppended` |
| record may have persisted, tail may have advanced, or classification unavailable | `OutcomeUnknown`; set `ReplayRequired` |
| while `ReplayRequired` | reject every write before provider append |
| recovery | provider refreshes authoritative tail, reconciles at most one exact authenticated next orphan, then replay |

## 8. Recovery publication outcomes

| Outcome | Meaning | Follow-up |
|---|---|---|
| `StageFailure::TargetNotEmpty` | target already authoritative | stop |
| `PublishFailure::NotPublished` | provider proves no publication | provider error; no automatic alternate target |
| `PublishFailure::OutcomeUnknown` | publication may have happened | target readback/reconciliation |
| complete receipt mismatch | effect occurred but proof differs | outcome unknown; target readback |
| `ProviderBeforeEntry` at outer fence | closure was not entered | preserve anchor provider error |
| `OutcomeUnknownAfterEntry` at outer fence | closure ran; publication and fence completion may have happened | anchor and target readback; never safe retry |
| exact receipt plus clean fence completion | archive, observation, checkpoint digest and anchor revision match | restore complete for this kernel |

The outer fence classification dominates a successful inner receipt when the
provider cannot prove clean fence completion. A target may therefore contain the
restored bytes while the API returns `AnchorFenceOutcomeUnknown`. That is an
intentional fail-closed result, not a contradiction.

## 9. Filesystem permission and provenance boundary

The Linux filesystem guard walks every ancestor from an opened root descriptor
with no-follow directory opens and identity checks. The single-node store and
journal create durable regular files owner-only (`0600`) on Unix. These controls
do not establish protection against a compromised kernel, privileged mount
namespace replacement, unqualified network filesystems, controller write-cache
loss, rollback outside the directory, or a remote external anchor.

## 10. CI provenance contract

The V1.4.6 workflow is read-only and pull-request-only. The `exact-head` matrix
entry checks `pull_request.head.sha`; the `prospective-merge` entry checks the
GitHub pull-request merge commit. Distinct job names prevent a push check from
satisfying a required PR context.

Inherited Rust semantic validation ignores only whitespace differences produced
by formatting. Non-Rust documents and workflows retain exact token checks, and
hostile mutations must continue to reject removed or renamed security symbols.

## 11. Hostile evidence map

| Claim | Evidence |
|---|---|
| anchor cannot advance across publish | `anchor_fence_is_held_across_target_publication` |
| stale checkpoint cannot publish | `stale_checkpoint_cannot_authorize_restore` |
| post-entry fence failure is outcome unknown | `post_entry_anchor_fence_failure_is_outcome_unknown` |
| non-empty target rejected atomically | `tamper_trailing_bytes_and_non_empty_target_fail_closed` |
| append persisted then errored | `append_outcome_unknown_after_persistence_requires_authoritative_replay` |
| store files owner-only | `durable_store_files_are_owner_only_on_unix` |
| exact orphan bundle only | `exact_orphan_bundle_is_completed_only_for_matching_intent` |
| file provider end-to-end interrupted recovery | `crates/heptabao-journaled-core/tests/file_provider_recovery.rs` |
| semantic drift rejected | `tests/plan/test_plan_v1_4_6.py` |
| rustfmt whitespace does not create a false blocker | `test_rustfmt_whitespace_is_semantically_transparent` |

## 12. Known limitations

No remote anchor or production recovery target is implemented. A remote provider
must define acquisition, fencing token, lease duration, renewal, cancellation,
release and authoritative readback semantics, and must produce
`OutcomeUnknownAfterEntry` whenever it cannot prove that authority remained
valid through completion.

`CommitIntent` is provider metadata and is publicly representable; it is not
authorization. The only repository composition that may use it to settle a
mutation is the journaled core after replaying the matching ledger operation.
Provider conformance, crash/power-cut qualification and independent security
review remain mandatory before any authority claim.
