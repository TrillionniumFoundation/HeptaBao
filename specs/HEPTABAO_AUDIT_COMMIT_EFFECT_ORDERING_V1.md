# HeptaBao Audit / Commit / External-Effect Ordering V1

Status: `NORMATIVE_SECURITY_BOUNDARY`  
Plan: `HEPTABAO-PLAN-2026-08-28` revision `1.1`

## 1. Purpose

Audit success, durable state and external effects cannot be treated as one atomic transaction. This specification defines the ordering and recovery contract so that an audit outage cannot leak a secret, an ambiguous provider response cannot be retried blindly, and an already committed mutation cannot be silently rolled back because a client disconnected.

## 2. Common records

Every non-trivial operation uses immutable, digest-bound records:

```text
OperationIntent
DispatchAttemptStarted
EffectObservation
LocalCommit
ResponseAuditObservation
TerminalReceipt | IndeterminateReceipt | ManualHoldReceipt
```

The records bind at least:

```text
operation_id
operation_key
operation_class
request_digest
payload_digest
namespace_id
mount_id
subject_digest
authority_epoch
owner_epoch
generation
fencing_token_digest
policy_digest
request_audit_event_id
deadline
created_at
```

No record may contain a raw token, unseal share, root/recovery key, dynamic credential, plugin mTLS private key, provider response body or authorization header.

## 3. Global ordering

For an operation that can mutate durable state or create an external effect:

```text
canonicalize/context/auth/policy
→ request audit succeeds
→ OperationIntent physically commits
→ DispatchAttemptStarted physically commits
→ dispatch crosses the effect boundary
→ EffectObservation physically commits
→ local token/lease/backend state commits
→ response audit succeeds
→ secret or success response is released
→ TerminalReceipt commits
```

`fsync complete` means the configured durability profile has acknowledged both file data and the required metadata/directory boundary. A buffered write, process-local future completion or Raft proposal without quorum commit is not physical commit.

## 4. Operation-class rules

### 4.1 PURE_READ

- Request audit follows the exact route profile.
- No durable intent is required unless the read updates durable usage, token use count, quota or other authority.
- A response containing a secret still requires successful response audit before release.
- If response audit fails, return an error and discard process-local response bytes.

### 4.2 DURABLE_MUTATION

- Persist intent before mutation.
- Mutation and terminal local receipt should share one transaction when the storage contract permits.
- A timeout after commit is reconciled by operation key; it is not redispatched.
- Client disconnect does not undo a committed mutation.

### 4.3 LEASE_ISSUING_READ

A read that creates a dynamic credential or lease is a mutation/effect operation:

```text
request audit
→ durable intent
→ provider/plugin dispatch
→ effect observation
→ lease commit
→ response audit
→ secret response
```

If the provider creates a credential but the response is lost, state becomes `INDETERMINATE`. Only provider lookup, revoke, compensation or manual evidence may resolve it.

### 4.4 EXTERNAL_EFFECT

- Persist a durable operation key before call.
- Persist `DispatchAttemptStarted` immediately before crossing the boundary.
- A pre-send transport failure can be retried within the same deadline and budget.
- Once bytes may have reached the provider, retry is forbidden without evidence that the first effect did not occur.
- A provider result must be reduced to typed status, opaque references and digests before it enters durable storage.

### 4.5 AUTH_LOGIN and TOKEN_ISSUE

- Login request and token response are audited.
- Token issuance commits before token response audit.
- If response audit fails after token issuance, the raw token is not returned.
- Resolution must be one of: revoke the issued token, permit one-time retrieval using an opaque operation-bound wrapper, or retain manual hold. Reissuing a second token by default is forbidden.

### 4.6 SEAL_CEREMONY

- Each accepted share/approval is bound to ceremony ID, share digest, epoch and threshold state.
- A response timeout cannot cause the same share to be counted twice.
- Unseal completion, key loading and active transition have separate durable markers.
- Audit records redact share material and preserve ceremony lineage.

### 4.7 CLUSTER_OPERATION

- Membership and active-authority mutations are committed through consensus.
- A client timeout is resolved by committed/applied index and membership state.
- A node cannot infer membership success from TCP success alone.
- Stepdown and seal fence active-only workers before a new active owner begins effects.

### 4.8 MIGRATION_OPERATION

- Source writer freeze, final delta, validation, authority-epoch bump and target enablement are separate fenced commits.
- Any unknown state after authority switch uses forward recovery unless rollback is proven not to create dual writers or revive invalid credentials.
- Both source and target record signed cutover lineage.

## 5. Response-audit failure after an external effect

The dangerous case is:

```text
external credential created
→ local observation/lease committed
→ response audit fails
```

Required behavior:

1. Do not release the secret.
2. Persist `ResponseAuditFailed` with operation/effect digests only.
3. Mark operation `INDETERMINATE` or `MANUAL_HOLD`; never report terminal success to the client.
4. Attempt a bounded, audited response-audit retry only if the device contract allows exact replay without duplicate semantic events.
5. Otherwise use one of:
   - revoke the external credential;
   - expose a one-time, policy-checked retrieval reference after audit recovers;
   - retain the credential under manual hold with expiry/revocation worker;
   - execute a documented compensation.
6. Never create a replacement credential unless evidence proves the first credential was not created or has been revoked.

## 6. Audit-device semantics

- Every configured device is attempted according to the compatibility profile.
- The request/response may proceed only when the profile's minimum-success policy is satisfied; the default production policy requires at least one successful device.
- A blocked device must be observable and bounded by an explicitly qualified device policy. Timeout must not silently convert failure into success.
- Device-specific salts and HMAC keys remain within the audit domain.
- Audit destinations have SSRF, path, ownership, permissions and redirect controls.
- Audit raw values are never included in diagnostic bundles.

## 7. Crash and recovery matrix

| Last durable marker | Recovery action |
|---|---|
| no `OperationIntent` | no effect authorized |
| `OperationIntent` only | safe to cancel or claim under current fence |
| `DispatchAttemptStarted`, no observation | effect may have happened; lookup/reconcile only |
| `EffectObservation`, no local commit | finish idempotent local commit or reconcile |
| local commit, no response audit | withhold response; re-audit/revoke/retrieve/manual hold |
| response audit, no terminal receipt | reconstruct immutable terminal receipt |
| terminal receipt | return same terminal result; never reopen |

Corrupt or missing lineage, stale fence, payload mismatch, unknown operation or invalid digest causes safe stop.

## 8. Acceptance invariants

- Backend dispatch before successful request audit: zero.
- Secret response before successful response audit: zero.
- Blind retry after `DispatchAttemptStarted` with unknown outcome: zero.
- Duplicate active operation for the same operation key and fence: zero.
- Terminal receipt mutation/reopen: zero.
- Raw secret-bearing fields in WAL, audit metadata, metrics, trace or crash artifact: zero.
- Recovery from every named kill point is deterministic or enters explicit manual hold.
