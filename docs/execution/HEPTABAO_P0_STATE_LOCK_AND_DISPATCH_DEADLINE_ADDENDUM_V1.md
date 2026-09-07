# HeptaBao P0 State-Lock and Dispatch-Deadline Addendum V1

## Scope

This addendum closes the request-timing gap between successful socket parsing and entry into the single-process P0 state machine. It applies only to `HB-P0-DEV-MEMORY` and grants no compatibility, qualification or authority.

## Invariant

A request may not use a dispatch-time sample taken before waiting for the shared server-state lock. Doing so could allow a request to spend its remaining lifetime queued behind another request and still dispatch with a stale `now` value.

The P0 listener therefore uses the following fail-closed sequence:

```text
strict parse and Host verification
→ request-ID claim
→ construct envelope with absolute monotonic deadline
→ non-blocking server-state try-lock
→ if busy: reject with 503 / p0-state-busy and audit NotAttempted
→ if poisoned: reject with 503 / p0-state-lock-unavailable and audit NotAttempted
→ after successful lock acquisition, sample monotonic now
→ validate deadline and dispatch
```

No accepted connection waits indefinitely on `Mutex::lock`. A concurrent request that cannot immediately enter the development state machine is rejected rather than queued. This intentionally favors bounded fail-closed behavior over P0 throughput.

## Audit and retry semantics

A `p0-state-busy` or `p0-state-lock-unavailable` result is recorded as a pre-dispatch rejection with `operation=None` and `CommitDisposition::NotAttempted`. A client-proposed P0 request ID has already been claimed by this point and remains consumed for the development replay window. Retrying requires a new request ID.

These semantics are deliberately narrower than a production scheduler. A later production implementation requires bounded queues, cancellation, fairness, per-request deadlines, overload telemetry, HA forwarding and a durable request/outcome authority.

## Evidence requirements

The exact-head gate must compile and lint the `TryLockError` path and execute regression evidence showing that:

- the blocking `server.lock()` path is absent;
- `p0-state-busy` is stable and fail-closed;
- the dispatch-time `now` sample occurs inside the successful lock branch;
- no state mutation occurs after deadline expiration;
- rejection audit failure remains a 503 and does not dispatch.

`qualification=false`, `compatibility_claim=false`, `authority_effect=NONE`.
