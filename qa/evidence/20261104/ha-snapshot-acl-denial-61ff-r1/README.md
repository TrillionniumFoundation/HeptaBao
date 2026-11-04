# Snapshot ACL and proved standby denial candidate

This is an independent, unformatted source draft based on review commit `c71b405970544682e7b9b25c91214f66351a767b`, whose full tree equals the strict-Clippy-qualified physical source `70714605c39014bea93545f7f6aa4217d2a23544`. The candidate itself has not been compiled or executed. It does not change the current physical checkout, a production service, or the running normal build.

## Product change

Public snapshot download and upload routes use the actual original actor and their read or update policy. Root-only checks remain on internal recovery, maintenance, and pending-restore reconciliation. The native historical upload's deep guard is also restricted to the two public POST/PUT upload routes before the existing original-actor update authorization, so a malformed archive passing a superficial error test cannot conceal a later root-only restore rejection.

A standby policy refusal has its own affine capsule. The capsule retains the real actor, request clock and deadline, source A, original ReadIndex proof, held physical-seal reader, and authenticated ingress. It cannot create a snapshot transfer lease, export archive, restore writer, or ordinary KV authority. Mandatory response audit precedes the one leader clock observation. The leader evaluates the actual token and ACL, commits only its own trusted-clock floor through the existing terminal writer, and returns either an actual receipt-derived completion or strict complete NoChange. The follower consumes the actual authenticated receipt, synchronizes, obtains a new real ReadIndex proof, verifies the shared A-to-B relation or unchanged A, and only then rechecks the original actor and finishes a Denied 403.

The imported protocol is exactly the reviewed sibling draft at commit `061f96a4b272b556329b89d461b918e370d21e45`. Its old Completed and Rejected wire shapes remain unchanged. The new Denied shape accepts only status 403. Pure decoded metadata cannot create the affine completion.

The physical-seal reader is moved without changing its checks from SnapshotLease to the already-held SnapshotSpool. SnapshotLease delegates to that implementation. Denial acquires no transfer lease and writes no archive or application data.

## Remaining work and qualification

No runtime pass is claimed for this draft. The next checks must cover actual nonroot policy, Denied and NoChange, original actor, physical seal, term/source changes, deadline and expiry, malformed and valid uploads, and the normal binary observer. A new expiry first observed only after the leader writer remains a conservative 503 without replay. Generic pre-plan quota/error paths, ordinary KV NoForward with precision state, and listener consistency precedence are still separate product work.

The old 070f token oracle has 87 known operations and 83 dynamic checks but contains no TTL-token invalid restore request. That attribution was withdrawn. The prepared normal observer is blocked from scoped compatibility success until a fresh exact official observation supplies this missing reference. Snapshot archive shape checks are not restoration proof. This candidate is not qualified for full replacement or production cutover.
