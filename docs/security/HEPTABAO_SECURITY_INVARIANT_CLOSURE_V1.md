# HeptaBao Security Invariant Closure Contract V1

## 1. Capability topology

| Capability | Constructor/owner | Permitted effect | Forbidden escape |
|---|---|---|---|
| `DurableStateEngine` | composition root | barrier-sealed generation commit | mutable/raw store extraction |
| `OperationLedger` | authenticated journal replay | operation transition append | raw journal extraction after unknown append |
| `KeyRingLedger` | authenticated journal replay | key-lifecycle transition append | continuation after unknown append |
| `AnchorCoordinator` | recovery composition root | monotonic exact checkpoint CAS/verification | raw anchor or signer extraction |
| `VerifiedRecoveryImage` | archive authenticator | inspect bound metadata | state/record extraction or target publication |
| `AuthorizedRecoveryImage` | `RecoveryRestorer` only | one target stage/publish handoff | public construction, clone or downgrade |

## 2. Journal append failure matrix

| Provider evidence | Disposition | In-memory candidate | Later writes | Recovery |
|---|---|---|---|---|
| proof no record/tail publication occurred | `DefinitelyNotAppended` | not installed | permitted subject to state machine | none |
| durable side effect possible or unknown | `OutcomeUnknown` | not installed | rejected before provider call | drop and authenticated replay |
| append receipt returned | success | installed after receipt | permitted | normal replay |

The default trait disposition is `OutcomeUnknown`. Silence or a generic I/O
error is never proof of non-publication.

## 3. Durable mutation reconciliation matrix

| Current phase | Generic reconcile | Exact storage reconcile |
|---|---:|---:|
| `Accepted` | allowed only as defined by transition table | not applicable |
| `IntentCommitted` + durable mutation | forbidden | required; generation and digest must match |
| external `EffectFailed`/`EffectUnknown` | allowed with external evidence | not applicable |
| post-commit audit/delivery failure | allowed with bound state/response facts | optional lookup path |

## 4. Recovery sequence and failure semantics

The live anchor is read twice to narrow the time-of-check/time-of-use window.
The second successful read produces a private capability bound to the current
anchor revision. Target providers must treat stage/publish as an empty-target
CAS and return a receipt containing the same archive ID, observation,
checkpoint digest and anchor revision.

| Failure | Publication interpretation | Retry rule |
|---|---|---|
| archive authentication failure | not started | safe only after replacing input |
| anchor not current/authentic | not started | no restore |
| target not empty | not started | no restore |
| stage error | target provider-defined known failure | follow provider evidence |
| explicit `OutcomeUnknown` | may be published | readback/reconcile first |
| success with wrong receipt | may be published | readback/reconcile first |
| exact receipt | published | do not repeat |

## 5. Filesystem path acquisition

```text
open("/")
for each normal component:
    verify current descriptor path identity
    lstat next component and reject symlink/non-directory
    open next through /proc/self/fd/<current>/<name> with O_NOFOLLOW
    require pre/open/post device+inode equality
retain final descriptor and exclusive writer lock
```

The component walk rejects intermediate symlinks and path traversal. It is not
an `openat2` claim and does not qualify mount, kernel or filesystem durability.

## 6. Hostile evidence map

| Claim | Hostile test/evidence |
|---|---|
| unknown operation append fences writes | `append_outcome_unknown_fences_until_authenticated_replay` |
| unknown key append fences writes | `append_outcome_unknown_poison_requires_replay` |
| durable intent cannot generic-reconcile | journaled-core postcommit reconciliation test |
| stale anchor cannot restore | `stale_checkpoint_cannot_authorize_restore` |
| wrong publish receipt is unknown | `wrong_receipt_after_publication_is_outcome_unknown` |
| alternate valid CAS receipt rejected | `alternate_authenticated_cas_receipt_is_rejected` |
| intermediate symlink rejected | `intermediate_symlink_is_rejected` |
| source/API/document drift rejected | `tests/plan/test_plan_v1_4_5.py` |

## 7. Non-authority

This contract is repository-controlled technical evidence only. It grants no
provider selection, compatibility, qualification, production, migration,
release, signing-custody or operator authority.
