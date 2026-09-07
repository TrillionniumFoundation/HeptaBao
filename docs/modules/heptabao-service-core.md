# heptabao-service-core

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package is the mandatory V2 in-process request composition root. It joins token validation, identity policy expansion, namespace-bound default-deny authorization, mount routing, KV dispatch, telemetry, bounded non-evicting request admission and reconciliation. It is not a TLS server, persistent idempotency ledger or qualified durable production service.

## Public API and ownership

`ServiceCore` owns all in-memory control/data-plane stores, a `PostCommitHook` and a bounded request registry. `new_with_request_capacity` makes the process-lifetime mutation admission ceiling explicit; `request_registry_counts` exposes pending, unresolved and resolved counts; `resolve_unknown` releases an exact unresolved binding only after an operator resolution. `ServiceRequest` owns request identity, bearer token identifier, namespace, user-relative path and operation. `ServiceResponse` preserves completed versus unknown-after-entry outcomes.

## State and data model

Mutation identity is keyed by authenticated principal, namespace and request identifier. Pending and unresolved entries retain the exact path and operation binding; write values remain in redacted zeroizing `SecretValue` storage only while that exact binding is required. Completed mutation keys are retained without eviction for the lifetime of the service instance. Unresolved effects are also non-evicting and remain bound until resolution. Unknown outcomes receive a service-generated recovery reference distinct from the external request identifier.

## Invariants and authorization

Token validation and identity expansion precede namespace qualification. Policy evaluates the qualified canonical resource, not the user-relative path: root `/secret/app` stays `/secret/app`, while namespace `team` becomes `/team/secret/app`. Therefore a root policy cannot cross into a child namespace merely because both mounts expose `/secret`. Mount selection, backend validation, telemetry construction and engine-path construction all precede mutation-ID admission. Invalid tokens and unauthorized or unroutable requests cannot reserve identifiers or grow the registry. The same external request identifier is independent across authenticated principals and namespaces. Within one scoped key, a changed path, CAS or write value fails as `RequestBindingMismatch`; an exact duplicate fails as `DuplicateRequest`.

## Failure, retry and reconciliation

A mutation rejected by the KV engine removes its pending reservation, permitting a corrected safe retry with the same scoped identifier. Completed keys are never evicted to make room for later operations. Once completed plus unresolved records reach capacity, any new unique mutation fails as `RequestRegistrySaturated` before backend dispatch. A retained identifier therefore cannot become a new operation through capacity churn. A post-commit failure moves the exact binding to the unresolved set, returns `OutcomeUnknownAfterEntry` and requires lookup by its unique recovery reference. `resolve_unknown` records the operator resolution and converts the unresolved binding to a completed non-replay key without freeing its slot.

## Concurrency and ordering

The current service is mutably owned and serial, so at most one transient pending entry exists. Capacity covers all admitted mutation identities; no admitted completed or unresolved identity is evicted. A future concurrent server must preserve authentication-before-admission, qualified-resource authorization, exact binding comparison and non-eviction throughout the declared replay lifetime.

## Security and privacy

Token identifiers and secret values have redacted debug representations. Request registry keys and bindings use redacted debug output. Exact write bindings temporarily duplicate secret bytes only for pending or unresolved safety and zeroize them when dropped or resolved. Telemetry accepts bounded labels and carries no token, path or secret value. Qualified policy evaluation prevents equal user-relative paths from becoming a cross-namespace authorization bypass. The service still lacks encryption, TLS, locked memory and durable token/policy/idempotency state.

## Persistence and compatibility

All control-plane, KV, request-registry and reconciliation state remains in memory. Restart loses completed replay records and unresolved recovery state, so this package makes a non-replay guarantee only for the lifetime of one service instance. A production composition must durably persist the scoped key, qualified authorization resource, exact operation binding, recovery reference and outcome taxonomy before serving traffic. Restart must not be used as a capacity-reset mechanism while old clients can retry.

## Observability

Completed and unknown outcomes emit `request_completed` with operation and outcome labels. `request_registry_counts` provides bounded cardinality for saturation monitoring. Recommended additional metrics are completed, unresolved, saturation rejection, binding mismatch, safe retry, namespace-denial and operator-resolution counts; request IDs, principals, namespaces, paths, tokens and values are prohibited labels.

## Operations

Administrators configure stores through explicit mutable accessors in this candidate and select request capacity at construction. Capacity is a hard process-lifetime ceiling, not a FIFO cache size. Saturation requires controlled replacement by a durable implementation or a service restart coordinated with client retry expiry and reconciliation of all unknown effects; simply increasing capacity or restarting to forget IDs is not valid production recovery.

## Tests and executable evidence

`cargo test -p heptabao-service-core` executes invalid-token-then-valid-ID, cross-principal scoped-ID, failed-CAS reservation release, non-evicting completed-ID saturation, bounded invalid-input, exact unresolved binding, saturation-before-dispatch, distinct recovery-reference, explicit operator-resolution, explicit namespace-policy storage isolation and hostile cross-principal/cross-namespace denial scenarios in addition to accepted, denied and revoked paths.

## Evolution and open boundaries

Durable request-ledger integration, restart-safe recovery references, lease issuance, plugin execution, TLS transport, HA fencing and compatibility routing remain open. The in-memory hard-cap registry is an executable fail-closed semantic contract, not evidence of durable exactly-once processing or indefinite production availability.
