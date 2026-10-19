# Native-large KV2 terminal custody candidate, 2026-10-19

This is a narrow follow-up to the dedicated native-large r1 source overlay
`b627fb108bc111d204de4d349c982e92e6d733374483c7772156ec28b5ebf03b`.
Its two existing Rust files are bound to their exact r1 blobs. It changes neither
the wire protocol nor any body, storage, connection, or deadline budget.

## Boundary being repaired

The r1 publisher rechecked the original Principal, RequestClock, source Auth,
and deadline throughout graph preparation and the durable locator/root protocol.
Its post-audit delivery gate checked the deadline and response status only.
An original credential could therefore expire while mandatory response audit
was completing, even though the import itself had committed successfully.

A terminal observation can legitimately write the Auth clock floor. Comparing
post-audit Auth bytes directly to the admission bytes would reject that valid
self-write. Accepting arbitrary newer Auth bytes would also be incorrect.

## Exact delivery binding

Immediately after a successful import, the owner captures the exact V6 identity
and existing publication generation. It asks the existing terminal observation
writer for its affine receipt. A receipt advances only the matching original
checkpoint; a mismatched or non-advancing receipt is rejected. The current root
and generation must then equal the resulting checkpoint.

After real mandatory audit, delivery checks the original deadline, Service
activation, single-upload lease, unsealed state, and live durable ownership. It
observes the original Principal and RequestClock against both immutable admitted
Auth and the exact receipt-bound current Auth. It does not authenticate again,
consume another token use, renew the actor, or allocate another request budget.

A delivery veto after a committed import emits a negative audit event and
returns HTTP 503 with `recovery_required=true` and `retry_allowed=false`.
The live Service is fenced; normal cold recovery selects the committed import.
There is no automatic retry or rollback of an already committed root.

## Added meaningful regression cases

1. `native_large_kv2_service_terminal_clock_self_write_keeps_actual_finite_actor`
   uses a real two-use token, real native publication, and actual terminal Auth
   floor advancement. It requires successful delivery and one remaining use in
   both live and cold lookup, proving delivery did not authenticate anew.
2. `native_large_kv2_service_original_actor_expires_after_real_audit` performs
   the real import and response audit, then expires the original two-second
   credential using the existing after-audit hook while the original request
   deadline remains live. It requires a negative delivery audit linked to the
   prior 204 event, a 503 response with no retry authority, an intact cold import,
   pre-body rejection of the expired actor, and pre-body rejection of replay.

The prior actual revoke-before-finalization regression remains unchanged. The
13 existing native-large tests are retained, giving an exact discovery count of
15 for `native_large_kv2_`. The earlier eight `native_kv2_graph_import_` tests
also remain unchanged and must continue to run after integration.

## Validation status

This overlay is a source candidate. No local Rust compiler was available and no
new test has been executed here. Actual compilation and Mac/Linux test receipts
are required before claiming this gate is closed. Neither a source review nor
these Service tests substitute for the independent real OpenBao 2.7.1/full34
network migration controller or multi-machine HA evidence.
