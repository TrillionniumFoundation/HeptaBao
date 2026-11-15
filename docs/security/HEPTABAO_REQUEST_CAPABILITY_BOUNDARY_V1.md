# HeptaBao Request Capability Boundary V1

Status: `IMPLEMENTED_REVIEW_REQUIRED`

This contract applies to `heptabao-server` and the exact source in which the raw `auth` module is non-exported. It closes the public capability-replay surface without claiming that authentication, compatibility, security qualification, production authority, migration authority, or release authority is complete.

## Threat

Authentication consumes any finite-use token allowance before service dispatch. A request capability must not be retained, cloned by an external caller, cached, serialized, or presented to authorize a later request. Otherwise a capability acquired before token exhaustion, expiry, parent expiry, policy replacement, or revocation could outlive the authoritative credential state.

## Ownership and transaction scope

`Service::handle` and `Service::handle_at` are the only public request entry points. The raw authentication module is **non-exported**. `AuthState`, `Principal`, and direct authorization methods therefore cannot be named by downstream crates.

The service creates one transaction-scoped principal after request audit and before dispatch. It stores the finite-use decrement durably before the authorized operation proceeds. The principal is non-cloneable and is consumed by value by exactly one internal dispatcher invocation; subsystems borrow it only inside that invocation. It is dropped before the public call returns, and no public method accepts or returns it.

Repeated authorization checks inside the same request are permitted for layered capability checks such as `update` plus `sudo`. They do not create another token use and do not make the principal reusable by another request.

## Live authority checks

Internal authorization re-resolves the authoritative token record and parent chain at the live decision time supplied by the service dispatcher. Revocation, token replacement, parent removal or expiry, namespace mismatch, accessor mismatch, and policy denial fail closed. A later request must authenticate again and cannot recover or replay the consumed principal.

Finite-use exhaustion after the admitted request is intentional: the current request has already paid and durably committed its use. A second request cannot obtain another principal after the counter reaches zero.

## Public API invariant

The following must remain true:

1. `crates/heptabao-server/src/lib.rs` declares `mod auth;`, never `pub mod auth;` or `pub(crate) mod auth;`.
2. The crate root does not re-export `AuthState`, `Principal`, or a direct authorization function.
3. No public `Service` method accepts or returns an authentication capability.
4. `Principal` is crate-internal, non-cloneable, non-serializable, and consumed by value by one dispatcher call.
5. Every production authorization path receives the current request's live decision time.
6. Authentication state is serialized only as part of the encrypted durable service state; the request principal itself is never serialized.
7. Public callers receive only `Response` values and cannot recover a principal from a response.

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

## Transactional response-wrapping increment

`ServiceRequest` carries only raw bounded request inputs and optional TTL, never
a Principal/AuthState or preauthorized actor. The actual Principal is still
consumed by value exactly once by dispatch. The isolated State candidate is now
named `transaction`, cloned from durably `admitted` state so failed wrapper
publication can roll back domain mutation without undoing finite-use admission.
The lexical guard follows this explicit call, not an old variable name. Runtime
failure tests and compile-fail visibility remain the semantic checks.

## External effect completion and activation

The private request principal can remain owned by the same in-flight request
while a provider executes outside the Service writer. It is not exported,
cloned, serialized, reauthenticated, or made available to a different request.
`PluginResponseAuthority` binds that admission to the original path/capability,
namespace incarnation, cluster, request deadline and Service activation nonce.
Current identity and policy are resolved again before delivery; HA state is
installed before this check, and the activation fence is rechecked after sync.
A seal followed by unseal invalidates the old admission even when the durable
cluster, token and namespace identities are unchanged. A freshly admitted
request after unseal remains valid. Unrelated durable writes alone do not
invalidate a request and repeated checks do not spend another token use.

The shared boundary is used by secret/KMS plugin responses, database
configuration and credential issue/renewal, and Kubernetes/OpenLDAP credential
delivery. Durable finalizers also recheck after publication where applicable.
An already-admitted subtractive revoke is not a fresh credential grant and may
complete cleanup after the requester's policy changes. Unknown outcomes retain
the original durable identity instead of authorizing a blind new issue.

Recovery does not reconstruct an HTTP principal. In particular, an OpenLDAP
pending issue in a still-sealed namespace is admitted only for tombstone/revoke
reconciliation after restart. An already-delivered active lease is not revoked
solely because the namespace was sealed; its original expiry and owner remain
binding. After global unseal, a still-live durable pending issue may reconcile
its original identity, but maintenance returns only a completion result, not a
credential response to the old request, and never resets its expiry.

`service_secret_delivery_tests.rs` covers delivery revocation, policy changes,
deadlines, namespace/global seal, seal/unseal, crash before finalization,
original-expiry recovery and unaffected positive paths.
`service_plugin_completion_tests.rs` covers shared admission and fresh requests
after reactivation. `database_delivery_live.py` and
`plugin_completion_live.py` exercise the real TLS service with checksum-bound
external fixture processes, including seal/unseal while a provider is paused.
These are scoped regression paths, not native-provider or independent
qualification. The separate `openldap_secret_live.py` executes real slapd
credential binding, revocation, idle expiry and restart.

### Authentication-plugin result binding

Unauthenticated plugin login has no request Principal. Its private response
context instead retains the cluster, namespace incarnation, Service activation
and original request deadline. The finalizer reuses the native online-auth
leadership and post-synchronization checks before creating a token and after
durable publication. It additionally compares the entire original auth-mount
revision and the admitted plugin configuration. Deleting and recreating the
same path with identical configuration cannot adopt the old plugin decision.
Only the server chooses policies, identity projection, uses and token lifetime.

Token issuance uses the monotonic elapsed completion clock, not the stale
admission sample; a slow successful provider cannot produce an already-expired
short-lived token merely because its request started earlier. The original
request deadline still bounds whether that decision may be accepted. Native
unit regressions and the existing real-process `plugin_completion_live.py`
cover namespace/global seal, global reactivation, replacement, slow issuance,
new requests after recovery and unrelated writes. This does not claim general
OpenBao plugin RPC, hot reload, or independent sandbox qualification.
