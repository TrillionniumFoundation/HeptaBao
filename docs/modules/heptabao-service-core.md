# heptabao-service-core

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package is the mandatory V2 in-process request composition root. It joins token validation, identity policy expansion, namespace-bound default-deny authorization, mount routing, KV dispatch, telemetry, bounded non-evicting request admission and reconciliation. It is not a TLS server, persistent idempotency ledger or qualified durable production service.

## Public API and ownership

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

## Machine-verified source truth

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
