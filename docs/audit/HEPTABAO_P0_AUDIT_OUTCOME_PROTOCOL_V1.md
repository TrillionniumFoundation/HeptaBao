# HeptaBao P0 Audit and Outcome Protocol V1

## 1. Scope

This contract defines the audit ordering and outcome vocabulary for `HB-P0-DEV-MEMORY`. It covers transport rejection, request dispatch, mutation outcome, response audit and response delivery. It is not a production audit-device, durability or non-repudiation claim.

## 2. Request-attempt identity

A request-attempt ID is allocated immediately after `accept` and before any request bytes are parsed. Therefore malformed framing, duplicate headers, Host mismatch, read timeout, read I/O failure, connection-capacity rejection and worker-allocation failure can be correlated without storing raw secret-bearing bytes.

A valid client-proposed `X-HeptaBao-Request-Id` may replace the attempt ID after strict parsing and exact Host verification. The original attempt ID is transport-local metadata; future structured audit schemas must preserve the mapping when both identities exist.

## 3. Stable phases

The logical state machine is:

```text
CONNECTION_ACCEPTED
→ REQUEST_PARSE_ACCEPTED | REQUEST_REJECTED
→ REQUEST_AUDITED
→ DISPATCH_NOT_ATTEMPTED | DISPATCH_ATTEMPTED
→ NOT_COMMITTED | COMMITTED | OUTCOME_UNKNOWN
→ RESPONSE_AUDITED | RESPONSE_AUDIT_FAILED
→ RESPONSE_DELIVERED | RESPONSE_DELIVERY_FAILED
```

The current shared `AuditEvent` schema represents request rejection, request acceptance, prepared/committed response and post-commit audit failure. Transport-only failures use `operation=None`, `RequestRejected`, `NotAttempted` and a stable detail code. Delivery failure is recorded with a stable detail code and the known commit disposition; a future schema revision must expose delivery as a first-class phase rather than overloading a request-level phase.

## 4. Ordering invariants

1. Parse or Host rejection is audited before the error response is written.
2. If rejection audit fails, the response becomes 503 and states that rejection audit is unavailable.
3. Every normal and transport-error response uses one absolute response-write deadline. Before each partial write and the final flush, the remaining lifetime is recomputed; successful short writes cannot reset or extend the bound. Failure to configure or complete the write closes the connection and never blocks admission indefinitely.
4. Per-connection worker creation uses a fallible interface. Failure releases the admission count, records `connection-worker-spawn-failed` against the attempt ID and closes the socket without dispatch.
5. Operation-specific body validation occurs before request acceptance and dispatch. A forbidden or non-exact body records `operation-body-forbidden`, `RequestRejected` and `NotAttempted`.
6. Request audit succeeds before any state mutation.
7. Request-audit failure prevents dispatch and mutation.
8. A successful mutating operation is marked committed before response-audit evaluation.
9. Response-audit failure after commit returns 503 with `committed=true` and a recovery reference.
10. A response delivery failure does not change a committed outcome and must not trigger an automatic retry.
11. No audit event contains raw token, unseal key, secret value, signature, nonce, request body, request target or KV path.

## 5. Stable transport and request detail codes

The P0 transport and request pipeline use bounded identifiers including:

- `connection-capacity-exhausted`;
- `connection-worker-spawn-failed`;
- `request-read-deadline-exceeded`;
- `request-read-io-failed`;
- `host-listener-mismatch`;
- `client-request-id-invalid`;
- `client-request-id-replayed`;
- `request-id-registry-unavailable`;
- `request-id-registry-saturated`;
- `protocol-duplicate-header`;
- `protocol-transfer-encoding-forbidden`;
- `protocol-content-length-mismatch`;
- `operation-body-forbidden`;
- `response-delivery-failed-before-commit`;
- `response-delivery-failed-after-commit`.

Unknown free-form exception text is not a stable machine identifier.

## 6. Recovery references

The P0 recovery reference is process-local development evidence. It does not survive process restart, is not backed by a durable idempotency ledger and does not prove whether a client received a response. Production implementation requires a durable outcome record keyed by request ID, operation digest, commit index/generation and authority epoch.

A production query must return one of:

```text
NOT_FOUND
REJECTED_BEFORE_DISPATCH
NOT_COMMITTED
COMMITTED
OUTCOME_UNKNOWN
REVOKED_OR_STALE_EPOCH
```

It must never recreate an external effect while answering the query.

## 7. Production audit requirements

Before promotion beyond P0, the audit subsystem requires a versioned structured schema, descriptor-relative no-follow file/device adapters, record framing, checksums or authenticated chaining, rotation, fsync semantics, disk-full behavior, multi-device policy, redaction tests, clock fields, sequence integrity, crash recovery, retention and independent review.

`qualification=false`, `compatibility_claim=false`, `production_supported=false`, `authority_effect=NONE`.
