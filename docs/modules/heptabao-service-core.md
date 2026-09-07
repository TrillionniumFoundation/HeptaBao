# heptabao-service-core

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package is the mandatory V2 in-process request composition root. It joins token validation, identity policy expansion, default-deny authorization, namespace qualification, mount routing, KV dispatch, telemetry, bounded request admission and reconciliation. It is not a TLS server, persistent idempotency ledger or qualified durable production service.

## Public API and ownership

`ServiceCore` owns all in-memory control/data-plane stores, a `PostCommitHook` and a bounded request registry. `new_with_request_capacity` makes retained-request capacity explicit; `request_registry_counts` exposes pending, unresolved and resolved counts; `resolve_unknown` releases an exact unresolved binding only after an operator resolution. `ServiceRequest` owns request identity, bearer token identifier, namespace, path and operation. `ServiceResponse` preserves completed versus unknown-after-entry outcomes.

## State and data model

Mutation identity is keyed by authenticated principal, namespace and request identifier. Pending and unresolved entries retain the exact path and operation binding; write values remain in redacted zeroizing `SecretValue` storage only while that exact binding is required. Successful outcomes retain key-only FIFO records within the configured capacity. Unresolved effects are never evicted to admit new work. Unknown outcomes receive a service-generated recovery reference distinct from the external request identifier.

## Invariants and authorization

Token validation, identity expansion, default-deny policy evaluation, namespace qualification, mount selection, backend validation, telemetry construction and engine-path construction all precede mutation-ID admission. Invalid tokens and unauthorized or unroutable requests cannot reserve identifiers or grow the registry. The same external request identifier is independent across authenticated principals and namespaces. Within one scoped key, a changed path, CAS or write value fails as `RequestBindingMismatch`; an exact duplicate fails as `DuplicateRequest`.

## Failure, retry and reconciliation

A mutation rejected by the KV engine removes its pending reservation, permitting a corrected safe retry with the same scoped identifier. Resolved entries are retained in a finite FIFO window and are evicted only when a later mutation has actually succeeded; rejected attempts cannot churn the window. A post-commit failure moves the exact binding to the non-evictable unresolved set, returns `OutcomeUnknownAfterEntry` and requires lookup by its unique recovery reference. If unresolved records fill capacity, new mutations fail closed with `RequestRegistrySaturated` before dispatch. `resolve_unknown` records the operator resolution and converts the unresolved binding to a bounded resolved key.

## Concurrency and ordering

The current service is mutably owned and serial, so at most one transient pending entry exists. Retained capacity applies to resolved plus unresolved outcomes; one synchronous pending operation may temporarily occupy an additional slot without evicting history. A future concurrent server must preserve authentication-before-admission, exact binding comparison, successful-commit-only FIFO eviction and non-eviction of unresolved effects.

## Security and privacy

Token identifiers and secret values have redacted debug representations. Request registry keys and bindings use redacted debug output. Exact write bindings temporarily duplicate secret bytes only for pending or unresolved safety and zeroize them when dropped or resolved. Telemetry accepts bounded labels and carries no token, path or secret value. The service still lacks encryption, TLS, locked memory and durable token/policy/idempotency state.

## Persistence and compatibility

All control-plane, KV, request-registry and reconciliation state remains in memory. Restart loses resolved retention and unresolved recovery state, so this package alone cannot make a durable replay-safety claim. A production composition must map the same scoped key, exact operation binding, recovery reference and outcome taxonomy onto operation-ledger, journal, barrier and storage providers without changing retry meaning.

## Observability

Completed and unknown outcomes emit `request_completed` with operation and outcome labels. `request_registry_counts` provides bounded cardinality for saturation monitoring. Recommended additional metrics are resolved, unresolved, saturation rejection, binding mismatch, safe retry and operator resolution counts; request IDs, principals, namespaces, paths, tokens and values are prohibited labels.

## Operations

Administrators configure stores through explicit mutable accessors in this candidate and select request-retention capacity at construction. Capacity must cover the expected resolved replay window plus worst-case unresolved effects. Saturation caused solely by unresolved entries requires authoritative readback and `resolve_unknown`; capacity must not be increased merely to bypass unresolved outcomes.

## Tests and executable evidence

`cargo test -p heptabao-service-core` executes invalid-token-then-valid-ID, cross-principal scoped-ID, failed-CAS reservation release, rejected-mutation retention preservation, bounded invalid-input, finite FIFO retention, exact unresolved binding, saturation-before-dispatch, distinct cross-principal recovery-reference and operator-resolution scenarios in addition to accepted, denied, revoked and namespace-isolation paths.

## Evolution and open boundaries

Durable request-ledger integration, restart-safe recovery references, lease issuance, plugin execution, TLS transport, HA fencing and compatibility routing remain open. The in-memory bounded registry is an executable semantic contract, not evidence of durable exactly-once processing.
