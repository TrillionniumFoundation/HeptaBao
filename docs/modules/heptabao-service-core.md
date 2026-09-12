# heptabao-service-core

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package is the V2 in-memory request composition model with mandatory admission within its `handle` entrypoint. It joins token validation, identity policy expansion, namespace-bound default-deny authorization, mount routing, KV dispatch, telemetry, bounded non-evicting request admission and reconciliation. It is not a TLS server, persistent idempotency ledger or qualified durable production service.

## Public API and ownership

### Current API contract and integration boundary

`ServiceCore<H: PostCommitHook>` owns the in-memory identity, policy, token, namespace and mount stores, KV engine, telemetry, request registry and reconciliation records. `new(max_versions, hook)` selects a request capacity of 256; `new_with_request_capacity(max_versions, capacity, hook)` requires both capacities to be positive. The `*_mut` accessors are trusted administrative/bootstrap interfaces with no authorization of their own. `kv`, `telemetry` and `reconciliation` return borrowed read-only stores; those are privileged in-process inspection paths, not independently authenticated endpoints.

`handle(ServiceRequest, now: Tick)` consumes the request and uses caller-supplied trusted time. It validates the token, expands live identity/group policies, adds token policy IDs, qualifies the resource under the selected namespace, authorizes, routes the mount and accepts only `Backend::Kv`. `ServiceOperation` supports read with optional version, write with owned secret and optional CAS, delete-latest, and list. Every write requests `Capability::Update`, even for an absent key; this composition does not select Create separately. The engine storage key includes namespace ID, mount ID and relative path.

Read responses own a copied `SecretValue` plus metadata. Listed paths are the engine's internal canonical keys, including namespace/mount components, not an OpenBao directory-style response. Write/delete results contain metadata. Only mutations reserve `(authenticated entity, namespace, request_id)` in the registry; rejected authentication, policy, routing or backend validation reserves nothing. Pending/unresolved records retain the exact path/operation/value/CAS binding. Completed records retain only the scoped key: any later reuse of a completed key returns `DuplicateRequest`, not a returned cached response or a changed-binding diagnosis.

`PostCommitHook::after_commit(&request_id)` runs only after KV mutation and reports confirmation failure as `ServiceResponse::OutcomeUnknownAfterEntry`, which is an `Ok` response variant rather than `Err(ServiceError)`. Callers must inspect that variant and use its separately generated `recovery_N` reference. `resolve_unknown(reference, Resolution)` trusts the caller's authoritative decision, records it, drops the unresolved secret binding and retains the completed key without freeing capacity. It neither performs readback nor authorizes the resolver.

`request_registry_counts` reports capacity/pending/unresolved/resolved; saturation rejects a new mutation before engine entry without evicting old keys. Deterministic KV rejection releases only the pending reservation. Neither completed replay records nor reconciliation state survives restart, and telemetry storage has no event-count bound. The owner must serialize access and must not use restart as a safe replay-capacity reset.

This is an independent in-memory composition model **outside the current server dependency closure**. It does not drive `heptabao-server` routes, native authentication, HA or durable storage. `heptabao-runtime-service` and the server's native service are distinct compositions, not implicit layers beneath this type.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-service-core`; Cargo SHA-256 `087b15eaee03ade930f3144d443ab3c23bd8ab1f35a78d1370ad2647a80df100`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `enum` | `ServiceOperation` | `crates/heptabao-service-core/src/lib.rs:21` | `pub enum ServiceOperation {` |
| `struct` | `ServiceRequest` | `crates/heptabao-service-core/src/lib.rs:58` | `pub struct ServiceRequest {` |
| `const` | `DEFAULT_REQUEST_REGISTRY_CAPACITY` | `crates/heptabao-service-core/src/lib.rs:66` | `pub const DEFAULT_REQUEST_REGISTRY_CAPACITY: usize = 256;` |
| `struct` | `RequestRegistryCounts` | `crates/heptabao-service-core/src/lib.rs:103` | `pub struct RequestRegistryCounts {` |
| `const` | `fn` | `crates/heptabao-service-core/src/lib.rs:111` | `pub const fn total(self) -> usize {` |
| `enum` | `ServiceOutput` | `crates/heptabao-service-core/src/lib.rs:214` | `pub enum ServiceOutput {` |
| `enum` | `ServiceResponse` | `crates/heptabao-service-core/src/lib.rs:225` | `pub enum ServiceResponse {` |
| `struct` | `PostCommitError` | `crates/heptabao-service-core/src/lib.rs:231` | `pub struct PostCommitError;` |
| `trait` | `PostCommitHook` | `crates/heptabao-service-core/src/lib.rs:241` | `pub trait PostCommitHook: fmt::Debug {` |
| `struct` | `NoopPostCommitHook` | `crates/heptabao-service-core/src/lib.rs:246` | `pub struct NoopPostCommitHook;` |
| `struct` | `FailOncePostCommitHook` | `crates/heptabao-service-core/src/lib.rs:255` | `pub struct FailOncePostCommitHook {` |
| `struct` | `ServiceCore` | `crates/heptabao-service-core/src/lib.rs:270` | `pub struct ServiceCore<H: PostCommitHook> {` |
| `fn` | `new` | `crates/heptabao-service-core/src/lib.rs:286` | `pub fn new(max_versions: usize, post_commit: H) -> Result<Self, ServiceError> {` |
| `fn` | `new_with_request_capacity` | `crates/heptabao-service-core/src/lib.rs:294` | `pub fn new_with_request_capacity(` |
| `fn` | `identities_mut` | `crates/heptabao-service-core/src/lib.rs:315` | `pub fn identities_mut(&mut self) -> &mut IdentityStore {` |
| `fn` | `policies_mut` | `crates/heptabao-service-core/src/lib.rs:319` | `pub fn policies_mut(&mut self) -> &mut PolicyStore {` |
| `fn` | `tokens_mut` | `crates/heptabao-service-core/src/lib.rs:323` | `pub fn tokens_mut(&mut self) -> &mut TokenStore {` |
| `fn` | `namespaces_mut` | `crates/heptabao-service-core/src/lib.rs:327` | `pub fn namespaces_mut(&mut self) -> &mut NamespaceStore {` |
| `fn` | `mounts_mut` | `crates/heptabao-service-core/src/lib.rs:331` | `pub fn mounts_mut(&mut self) -> &mut MountRouter {` |
| `fn` | `kv` | `crates/heptabao-service-core/src/lib.rs:335` | `pub fn kv(&self) -> &KvStore {` |
| `fn` | `telemetry` | `crates/heptabao-service-core/src/lib.rs:339` | `pub fn telemetry(&self) -> &MemoryTelemetry {` |
| `fn` | `reconciliation` | `crates/heptabao-service-core/src/lib.rs:343` | `pub fn reconciliation(&self) -> &ReconciliationStore {` |
| `fn` | `request_registry_counts` | `crates/heptabao-service-core/src/lib.rs:347` | `pub fn request_registry_counts(&self) -> RequestRegistryCounts {` |
| `fn` | `resolve_unknown` | `crates/heptabao-service-core/src/lib.rs:351` | `pub fn resolve_unknown(` |
| `fn` | `handle` | `crates/heptabao-service-core/src/lib.rs:381` | `pub fn handle(` |
| `enum` | `ServiceError` | `crates/heptabao-service-core/src/lib.rs:542` | `pub enum ServiceError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

Mutation identity is keyed by authenticated principal, namespace and request identifier. Pending and unresolved entries retain the exact path and operation binding; write values remain in redacted zeroizing `SecretValue` storage only while that exact binding is required. Completed mutation keys are retained without eviction for the lifetime of the service instance. Unresolved effects are also non-evicting and remain bound until resolution. Unknown outcomes receive a service-generated recovery reference distinct from the external request identifier.

## Invariants and authorization

Token validation and identity expansion precede namespace qualification. Policy evaluates the qualified canonical resource, not the user-relative path: root `/secret/app` stays `/secret/app`, while namespace `team` becomes `/team/secret/app`. Therefore a root policy cannot cross into a child namespace merely because both mounts expose `/secret`. Mount selection, backend validation, telemetry construction and engine-path construction all precede mutation-ID admission. Invalid tokens and unauthorized or unroutable requests cannot reserve identifiers or grow the registry. The same external request identifier is independent across authenticated principals and namespaces. For a pending or unresolved scoped key, a changed path, CAS or write value fails as `RequestBindingMismatch`; an exact duplicate fails as `DuplicateRequest`. A completed key retains no exact payload binding and always rejects reuse as `DuplicateRequest`.

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

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::completed_request_ids_are_non_evicting_and_capacity_fails_closed`](../../crates/heptabao-service-core/src/lib.rs) checks saturation rejects a new mutation while old IDs remain blocked.
- [`tests::rejected_engine_operation_releases_request_identity_for_a_safe_retry`](../../crates/heptabao-service-core/src/lib.rs) checks failed CAS leaves a reservation available for corrected retry.
- [`tests::unresolved_effects_are_exactly_bound_and_never_evicted`](../../crates/heptabao-service-core/src/lib.rs) checks changed unresolved bindings, exact duplicate and capacity-before-dispatch.
- [`tests::recovery_references_disambiguate_cross_principal_unknown_outcomes`](../../crates/heptabao-service-core/src/lib.rs) checks separate recovery references for a shared external ID and terminal resolution.
- [`tests::qualified_namespace_policy_denies_cross_principal_access`](../../crates/heptabao-service-core/src/lib.rs) checks root/team cross-access denial occurs before registry or KV mutation.

`cargo test -p heptabao-service-core` executes invalid-token-then-valid-ID, cross-principal scoped-ID, failed-CAS reservation release, non-evicting completed-ID saturation, bounded invalid-input, exact unresolved binding, saturation-before-dispatch, distinct recovery-reference, explicit operator-resolution, explicit namespace-policy storage isolation and hostile cross-principal/cross-namespace denial scenarios in addition to accepted, denied and revoked paths.

## Evolution and open boundaries

Durable request-ledger integration, restart-safe recovery references, lease issuance, plugin execution, TLS transport, HA fencing and compatibility routing remain open. The in-memory hard-cap registry is an executable fail-closed semantic contract, not evidence of durable exactly-once processing or indefinite production availability.

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-service-core`
- Crate path: `crates/heptabao-service-core`
- Cargo manifest SHA-256: `087b15eaee03ade930f3144d443ab3c23bd8ab1f35a78d1370ad2647a80df100`
- Rust source files: `1`
- Public lexical declarations: `26`
- Discovered test functions: `14`
- Workspace-internal dependencies: `heptabao-domain` (dependencies), `heptabao-identity` (dependencies), `heptabao-kv-engine` (dependencies), `heptabao-mount-router` (dependencies), `heptabao-namespace` (dependencies), `heptabao-operator-api` (dependencies), `heptabao-policy` (dependencies), `heptabao-telemetry` (dependencies), `heptabao-token` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
