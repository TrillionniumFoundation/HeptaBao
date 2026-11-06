# R1 owner-priority and deadline cross-review

This is source inspection of the nine frozen R1 candidate blobs, not an
executed request, compiler result or qualification. R1 remains immutable as
the before-state for the authorized R2 correction. The source checker's 799
passing checks establish the advertised byte/lexical constraints, not freedom
from functional gaps.

## Confirmed functional blockers

1. **Token API service children of a JWT parent.** The existing
   `AuthState::create_token_observed` writes `TokenApi` provenance for every
   Token API service grant and, for a non-orphan without an entity alias,
   inherits `parent.auth_mount`. R1's `native_v6_jwt_state_supported` instead
   requires every token whose live mount is JWT to have direct `Jwt`
   provenance. Therefore the real child candidate is rejected by the new
   profile; it cannot be described as supported. The original Token API
   creation/TTL, provenance, identity and parent-edge rules must be retained.
   Orphan/explicit-alias creation has different mount assignment and must not
   be conflated with this case.
2. **Token API batch issuance by a JWT actor.** The native owner selector picks
   `Jwt` for this actor. R1 leaves `select_batch_issuer` restricted to `Auth`
   and non-login `Userpass`. The actual domain may construct the batch grant,
   but the subsequent `batch_reply` gate has no lifecycle owner and returns
   501 before publication/delivery. R2 must reuse the existing typed
   `NativeBatchIssuerOwner` and paired native batch lifecycle, without
   pretending JWT bearer login itself has batch support.

Neither scenario is among R1's ten new tests. Root requested separate real
service-child and Token API batch regressions, including parent revocation,
cold reopen and child renewal. No R1 assertions were changed to hide them.

## Mixed Userpass / JWT Token API ownership

`dispatch_native_auth_request` consults `capture_native_v6_userpass_owner`
first. That original selector examines both actor and target provenance. A
JWT actor targeting a Userpass token, or a Userpass actor targeting a JWT
token, therefore keeps the existing Userpass owner. Its source/profile checks
do not reject a direct JWT token merely because JWT is present. Ordinary
Token API target validation, source Auth digest, real backend renewal/revoke,
response digest, terminal checkpoint and final actor ACL checks remain in
the encompassing `NativeAuthDelivery`. JWT login-specific lifetime is not a
renewal requirement. This is a static path observation only; R2 must add real
mixed-origin tests before claiming behavioral coverage.

## Metadata scan and original deadline

`native_v6_jwt_state_supported` has no per-entry deadline callback. Its
validators and role/token `.all` loops are non-preemptive metadata scans.
The first JWT owner capture performs the scan before entering the native
delivery dispatcher. `OriginalDeadline::capture` later captures the already
active request deadline; it does not create a fresh budget.

During custody, `NativeAuthDelivery::check_source` calls `time()` (which checks
that original deadline), then JWT source/profile checks, and checks the same
deadline again at its end. Candidate admission also scans; the original
identity-change callback and `prepare_native_live_root_checked` source gate
subsequently check the same deadline. The original writer checks its retained
deadline before custody and before durable publication, and calls the same
before-publication gate around installation. Late delivery checks also use
the retained deadline.

Thus an overlong scan is rejected at the next enclosing gate; this is not a
hard CPU preemption guarantee or a measured cost bound. No timeout is reset or
increased. R2 will not claim a new bounded-per-element scanner without an
explicit source change and corresponding review.

## Verifier-call precision

The selected native login calls `verified_claims` once through the private
identity-plus-lifetime verifier. The unchanged `federated_auth.rs` PEM-keyset
branch uses `.find` over matching keys and may call `verify_signature` more
than once inside that invocation. The correct claim is one verifier pass and
no second authentication, not exactly one cryptographic primitive call.

## Compatibility and execution limits

JWT named role DELETE = update + sudo, and role collection GET = list, are
only this repository's legacy contract. Official OpenBao 2.7.1 source mapping
and a real ACL oracle observation remain separate gates. All findings above
come from exact source, not earlier comments or fabricated runtime outputs.
No Runtime, Rust compile, rustfmt or Rust test was performed.
