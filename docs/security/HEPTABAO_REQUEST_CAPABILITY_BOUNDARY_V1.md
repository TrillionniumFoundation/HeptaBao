# HeptaBao Request Capability Boundary V1

Status: `IMPLEMENTED_REVIEW_REQUIRED`

This contract applies to `heptabao-server` and the exact source in which the raw `auth` module is non-exported. It closes the public capability-replay surface without claiming that authentication, compatibility, security qualification, production authority, migration authority, or release authority is complete.

## Threat

Authentication consumes any finite-use token allowance before service dispatch. A request capability must not be retained, cloned by an external caller, cached, serialized, or presented to authorize a later request. Otherwise a capability acquired before token exhaustion, expiry, parent expiry, policy replacement, or revocation could outlive the authoritative credential state.

## Ownership and transaction scope

`Service::handle` and `Service::handle_at` are the only public request entry points. The raw authentication module is **non-exported**. `AuthState`, `Principal`, and direct authorization methods therefore cannot be named by downstream crates.

The service creates one transaction-scoped principal after request audit and before dispatch. It stores the finite-use decrement durably before the authorized operation proceeds. The principal remains a local value owned by that request invocation, is passed only by shared reference to the internal dispatcher, and is dropped before the public call returns. No public method accepts or returns it.

Repeated authorization checks inside the same request are permitted for layered capability checks such as `update` plus `sudo`. They do not create another token use and do not make the principal reusable by another request.

## Live authority checks

Internal authorization re-resolves the authoritative token record and parent chain. Revocation, token replacement, parent removal, namespace mismatch, accessor mismatch, and policy denial fail closed. The request time captured during authentication is the service decision time for that synchronous request; a later request must authenticate again against a fresh service time.

Finite-use exhaustion after the admitted request is intentional: the current request has already paid and durably committed its use. A second request cannot obtain another principal after the counter reaches zero.

## Public API invariant

The following must remain true:

1. `crates/heptabao-server/src/lib.rs` declares `mod auth;`, never `pub mod auth;` or `pub(crate) mod auth;`.
2. The crate root does not re-export `AuthState`, `Principal`, or a direct authorization function.
3. No public `Service` method accepts or returns an authentication capability.
4. Authentication state is serialized only as part of the encrypted durable service state; the request principal itself is never serialized.
5. Public callers receive only `Response` values and cannot recover a principal from a response.

The crate-level `compile_fail` example and `tests/repository/test_auth_capability_boundary_v2_6.py` enforce the public shape. Exact-head Rust and repository checks are mandatory; an old-head pass does not admit a changed boundary.

## Required hostile evidence

The executable suite must continue to prove:

- a finite-use token cannot authenticate after its final committed use;
- a token or parent revoked after a principal was created cannot authorize through stale state;
- expired subject and parent tokens fail on a fresh request;
- policy and token replacement fail closed;
- namespace crossing and accessor mismatch are rejected;
- response-audit or durable publication uncertainty withholds sensitive output.

## Evolution rule

Any future need to expose lower-level authentication must introduce a new affine, non-cloneable, non-serializable request capability that is consumed by one dispatcher call and bound to a fresh request identity and decision time. Re-exporting the current raw module is prohibited. Such a change requires hostile replay tests, an exact-head security review, and an explicit revision of this contract.
