# Formatter report BODY0: bounded public Runtime source review

## Finding

No independently callable, lookup-only by-idempotency-key API was found in the current exposed operation tool family. The inspected public Runtime source has a private key lookup and a no-dispatch Existing branch, but the same public operation_start entry also admits and can dispatch a new read when no binding exists. The present BODY0 MCP timeout provides no operation ID and does not establish which branch was reached. Consequently, an exact same-key call cannot be represented as lookup-only or as recovery of the original ACK.

This is a SOURCE and interface review only. It neither reads private state nor proves that the inspected public revision is the currently deployed controller.

## Fixed evidence and scope

- Public repository: TrillionniumFoundation/hepta-runtime.
- Public branch observed: codex/native-runtime-integration-20261024.
- Commit: d4d48189d03b8ff8dfe8d82652b749fb44cd9d50.
- Canonical tree: 3dbc55020b06e37ebd66d55f2125bec03cb50c2a. The returned recursive entries independently reconstruct 611 Merkle trees and 6,270 leaves.
- operation_async.rs: 7636673d55ab4e3eb6c861be021d47a1c36fc227; 57879 bytes; SHA256 610879ccdcb477da688030f507baa64541d7439fdc157aa543af9d63d04c534c.
- operation_crypto.rs: 0c07318a6d85efb920069ce4f190c4f2ed56e84f; 15524 bytes; SHA256 a48463ef35ca41d0aa8ef64fcaeb9d3245773052221789a38d18d52ced891633.
- operation_async_tests.rs: 74192e39b71e8d4fba9f762f3465541e57471f1a; 30757 bytes; SHA256 671019d889592f7993679916f022058a19ca9b5e1859140552b80f107f51e65d.
- Current exposed tool descriptions/schema were read from ALL_TOOLS without calling Runtime.
- Original BODY0 UNKNOWN packet: 29b6302cc3cb329566b6f66c0441c0899b0cc811. Exact request 06f7a3eccf5de1c877b552cab886d14086d0c51c; original SDK f181c1e93e7b64c402b332fd29b23d0141762082.
- Original formatter terminal and previously closed report metadata remain independently valid; this review changes neither.

The bounded lookup also read the public default branch and public host-source custody archive metadata. Neither supplied a closer operation implementation. No unlimited history search, private ledger read, credential access, process inspection, or Native call was made.

## Relevant source contracts

| Source lines | Finding | Consequence |
|---|---|---|
| operation_async.rs 135–160 | Start accepts operation plus idempotency_key and denies unknown fields; status/result require operation_id. | No lookup-only boolean or key selector exists in these types. |
| 304–307 | next_id reads 32 random bytes from /dev/urandom. | A missing ID cannot be recomputed from the public request. |
| 440–483 | publish writes and fsyncs a create-only staging file, links the record, removes staging, then fsyncs the directory. | This inspected implementation persists individual binding graph records before returning New. This is not evidence that this BODY0 reached that point. |
| 950–1013 | Private lookup_key_at validates the namespace, primary and occupancy records, matching historical intent, owner, request, policy and ledger identity. | Existing means an exact complete binding in this source. Partial/inconsistent graphs refuse; they do not issue a new permit. |
| 1055–1108 | reserve_at returns Existing for a matching old graph; otherwise publishes historical intent, occupancy, primary, then returns New. | The same entry can create a new immutable binding when it has no prior binding. |
| 1523–1526, 1539–1542, 1565–1566 | Each Existing case returns checked_receipt(old, true) before dispatch. | This branch does not redispatch the native read. |
| 1569–1572 | An audit-admission error may return checked_receipt(binding, false) without spawning. | reused=false is not itself proof of dispatch, and cannot prove that the first client call never reached admission. |
| 1585–1597 | After New, a receipt is prepared and an owned task may call the native read dispatcher once. | Recalling public start without prior binding evidence may be a first admission, rather than lookup-only. |
| 1663–1666 | checked_receipt performs audit identity observation and emits the receipt. | No native dispatch occurs in this helper. |
| 1725–1829 | Known-ID status/result authenticate the owned binding and retained original payload; result only pages the bytes. | Once an ID is actually returned, further same-ID status/pages are a distinct no-dispatch retrieval path. |
| operation_crypto.rs 280–340 | Private token-derived or session keys bind the idempotency key and typed request. | No public request-only reconstruction of the binding is available; no secret was accessed or requested. |

The current exposed start description promises that identical-key retries return the original operation_id without replay. This supports retaining one immutable key and identical typed arguments. It does not expose a query-only mode and does not establish that a timeout occurred after admission. The inspected public source is a concrete explanation of that distinction, not deployed-version attestation.

## Original state retained

The only submitted BODY0 request was the fixed-version public binary_read at offset 0, limit 65,536. Its complete original SDK is the preserved MCP -32603 timeout. There is no returned operation ID, no retained body byte at this client boundary, and no proof that an owned future stopped or that admission never occurred. The old context remains paused with pending BODY0, started=1, ranges=[], and BODY1 unsubmitted. There is no ordinary lane release.

No same-key retry, rekey, fresh read, process_start, cancellation, body1 admission, or modification of the original context was performed by this review.

## Recovery implication

A future explicit admission-reconciliation proposal can preserve the exact key and typed request while accurately admitting both possibilities: Existing returns the retained identity, or an absent prior binding causes a new admission. Such a proposal requires its own exact source and authorization. reused=false must remain a new observation and cannot rewrite the original timeout as not-submitted. Returned admission is not proof of native completion or body delivery; only subsequent authenticated same-ID closed state and full original bytes can establish those facts.

A dedicated lookup-only API would avoid this ambiguity, but none is callable in the exposed operation family inspected here. No Runtime implementation change is proposed or executed.

## Validation and limits

22 local V8 source/byte/membership checks passed. They cover full source identities, exact canonical membership, the relevant branches and persistence order, exposed method geometry, and tests present in source. No Rust module or test was compiled or executed. The source tests at lines 326–425 address pending keys and damaged binding graphs; they are cited as code, not as newly executed evidence.

One preliminary local tree audit incorrectly treated the API's echoed commit reference as a tree SHA and failed. Subsequent exact public commit metadata supplied the actual tree SHA; the unchanged recursive entries verified against that tree. The original failure and the first raw SDK's unconfirmed local durability are explicitly retained in the accompanying record. No Runtime request or mutation occurred during that correction.
