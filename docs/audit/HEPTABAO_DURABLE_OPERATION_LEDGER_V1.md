# HeptaBao Durable Operation Ledger Contract V1

## 1. Scope

The durable operation ledger records enough authenticated state to prevent a
process restart, response loss or audit failure from turning an already
executed operation into a blind retry. It is an evidence and reconciliation
boundary. It is not authorization, compatibility, a release receipt or an
operational authority grant.

```text
profile = HB-P1-DEV-JOURNALED-SINGLE-PROCESS
production_supported = false
replicated = false
authority_effect = NONE
```

## 2. Journal layout

```text
<journal-root>/
  heptabao-journal.marker
  TAIL
  entry-00000000000000000001.hbj
  entry-00000000000000000002.hbj
  ...
```

The marker binds the journal domain and authenticator identity. Each immutable
entry binds sequence, previous authentication tag, current tag and an opaque
payload. `TAIL` binds the only committed contiguous prefix. Every control and
entry decoder rejects invalid magic, truncation, trailing bytes, impossible
lengths, zero sequence/tag and invalid UTF-8 identities.

The directory scan uses no-follow metadata. Symlinked or non-regular marker,
tail and entry paths are corruption. Unknown entries, gaps, duplicate sequence,
more than one future entry and unresolved `.tmp-` artifacts fail closed.

Journal files are created with owner-only mode `0600` on Linux. The containing
directory remains an operator-controlled boundary and must not be writable by
untrusted principals.

## 3. Authentication chain

For record `n` the provider receives:

```text
domain
sequence = n
previous_tag = tag(n-1) or NONE for n=1
payload bytes
```

and returns one non-zero 32-byte tag. Reopen and replay recompute and compare
all tags in order. A tag is not accepted merely because it is present in an
entry or in `TAIL`.

The interface does not prescribe a primitive. Production selection requires a
reviewed MAC or signature construction, key identity, custody, rotation,
revocation, algorithm-agility and downgrade policy. The test provider is not
cryptography.

## 4. Append and publication

```text
validate marker + disk tail + in-memory tail
→ reject pending orphan and stale expected tail
→ authenticate next payload
→ create immutable entry with create_new
→ write-all + flush + sync file
→ sync directory
→ write/sync temporary TAIL
→ atomic rename temporary TAIL over TAIL
→ sync directory
→ reread TAIL
→ reread and authenticate entry
→ publish in-memory tail
→ return receipt
```

An entry that exists without a committed `TAIL` is not automatically committed.
Exactly one next entry may be explicitly reconciled after full authentication.
If tail publication may have happened but cannot be proven, the append returns
`AppendOutcomeUnknown`; callers reopen and reconcile before any further append.

## 5. Operation event envelope

Each payload uses a strict binary envelope with:

```text
version
operation class
previous phase
new phase
field-presence flags
operation ID length
detail-code length
request digest
optional state generation and digest
optional external-effect key digest
optional response digest
operation ID bytes
detail-code bytes
```

The operation ID and request digest are immutable. State, effect and response
bindings are monotonic accumulated facts. Replay uses the same transition
validator as live append.

## 6. State machine invariants

- an operation is accepted at most once;
- no non-accept event exists without a previous state;
- `previous_phase` exactly matches the current durable phase;
- a durable mutation cannot carry an external-effect key;
- an external-effect operation carries its effect key after intent commit;
- response and delivery phases require a committed state and response digest;
- once state/effect/response binding exists, later events cannot replace it;
- unknown effect, post-commit response-audit failure and post-commit delivery
  failure are reconciliation states, not mutation failure;
- a consumed operation ID is never silently made reusable.

## 7. Reconciliation behavior

| Durable observation | Directive |
|---|---|
| accepted, dispatch uncertain | manual hold |
| rejected before dispatch | retry only as a new operation identity |
| intent/effect in progress or unknown | reconcile/lookup only |
| committed state | lookup committed generation/result |
| post-commit response audit or delivery failure | re-audit/lookup/reconcile only |
| delivered | lookup only |
| failed/reconciled terminal operation | no automatic retry |

A lookup service must return the current phase, state generation/digest and
opaque recovery reference without exposing secret payloads. Retention must not
delete records while their operation IDs can still be presented or while an
external effect can still be reconciled.

A missing post-commit transition is repaired only by rereading the authoritative
storage snapshot and matching both generation and digest to the returned commit
receipt before appending `StateCommitted`. Receipt text alone is insufficient.

An unresolved intent is also a global writer fence. No later operation may
advance the authoritative generation until that intent is either bound to the
exact stored commit or durably classified as rejected before dispatch.

## 8. Crash and corruption cases

Required tests include:

- entry durable before tail publication;
- tail publication outcome unknown;
- stale expected tail;
- missing committed entry;
- future gap or multiple orphans;
- entry/tail tag mismatch;
- payload bit flip;
- marker domain/authenticator drift;
- symlink, non-regular path and unresolved temporary file;
- truncation and trailing bytes;
- illegal operation transition and immutable-field drift;
- state commit followed by ledger append failure;
- restart replay and duplicate-operation rejection.

Process-level file tests are logical crash-boundary evidence only. They do not
replace kernel/VM power-cut and storage-controller testing.

## 9. Residual security boundary

The mutable journal directory does not itself prevent complete rollback. A
production profile requires an external rollback anchor or monotonic signed
inventory. Pure-`std` path validation does not eliminate check/open races;
production requires descriptor-relative no-follow APIs and writer fencing.
Single-process serialization does not establish HA ordering or quorum audit.

No real key, token, customer secret, root material or production journal may be
used with this development profile.
