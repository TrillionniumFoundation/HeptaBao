# heptabao-proxy

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns bounded local proxy planning for request credential replacement, response filtering and HTTP header-smuggling defense. It does not open sockets, terminate TLS, pool upstream connections, parse request bodies or claim production proxy compatibility.

## Public API and ownership

### Current API contract and integration boundary

`HeaderName::parse` owns a lowercase validated token of 1–64 bytes; `HeaderValue::new(Vec<u8>)` owns at most 8192 bytes and rejects CR, LF and NUL. Values may be empty and are otherwise not a complete HTTP parser. `ProxyPolicy::new` owns request/response header allowlists, positive body-size limits and a positive timeout in ticks; an empty allowlist is accepted and forwards only the generated request credential.

`plan_request(ProxyRequest, SecretValue)` consumes headers and the server token. It checks the caller-reported body length, rejects duplicate normalized names, strips hop-by-hop/Connection-nominated/credential headers, retains allowlisted fields and appends one `Authorization: Bearer ...` value. The prefixed token must also fit `HeaderValue` bounds. `plan_response(headers, body_bytes)` applies the response bound and filtering without injecting credentials. Both return owned `ForwardPlan` values, not transmitted HTTP messages.

The adapter must enforce actual streamed body and aggregate-header limits, validate authority/URL/framing, establish TLS and honor `upstream_timeout_ticks`. There is no header-count bound or aggregate byte budget in these types, and `body_bytes` is supplied rather than measured. Unknown results after transport entry require readback classification; planning errors happen before any network effect.

This independent planner is outside the current server dependency closure. It implements no listener, pooling, caching or OpenBao Proxy process; the operational runbook below describes responsibilities for a future transport adapter, not existing deployment commands.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-proxy`; Cargo SHA-256 `f7a165e2852da3eb931b8ac2637d2a957078fb615279ad8ff2998f58500e6c0d`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `const` | `MAX_HEADER_NAME_BYTES` | `crates/heptabao-proxy/src/lib.rs:12` | `pub const MAX_HEADER_NAME_BYTES: usize = 64;` |
| `const` | `MAX_HEADER_VALUE_BYTES` | `crates/heptabao-proxy/src/lib.rs:13` | `pub const MAX_HEADER_VALUE_BYTES: usize = 8192;` |
| `struct` | `HeaderName` | `crates/heptabao-proxy/src/lib.rs:34` | `pub struct HeaderName(String);` |
| `fn` | `parse` | `crates/heptabao-proxy/src/lib.rs:37` | `pub fn parse(value: impl Into<String>) -> Result<Self, ProxyError> {` |
| `fn` | `as_str` | `crates/heptabao-proxy/src/lib.rs:48` | `pub fn as_str(&self) -> &str {` |
| `struct` | `HeaderValue` | `crates/heptabao-proxy/src/lib.rs:60` | `pub struct HeaderValue(Vec<u8>);` |
| `fn` | `new` | `crates/heptabao-proxy/src/lib.rs:63` | `pub fn new(bytes: Vec<u8>) -> Result<Self, ProxyError> {` |
| `fn` | `expose` | `crates/heptabao-proxy/src/lib.rs:72` | `pub fn expose(&self) -> &[u8] {` |
| `struct` | `ProxyRequest` | `crates/heptabao-proxy/src/lib.rs:98` | `pub struct ProxyRequest {` |
| `struct` | `ForwardPlan` | `crates/heptabao-proxy/src/lib.rs:104` | `pub struct ForwardPlan {` |
| `struct` | `ProxyPolicy` | `crates/heptabao-proxy/src/lib.rs:111` | `pub struct ProxyPolicy {` |
| `fn` | `new` | `crates/heptabao-proxy/src/lib.rs:120` | `pub fn new(` |
| `fn` | `plan_request` | `crates/heptabao-proxy/src/lib.rs:142` | `pub fn plan_request(` |
| `fn` | `plan_response` | `crates/heptabao-proxy/src/lib.rs:173` | `pub fn plan_response(` |
| `enum` | `ProxyError` | `crates/heptabao-proxy/src/lib.rs:252` | `pub enum ProxyError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

Header names are normalized to validated lowercase tokens. Header values are bounded byte vectors with CR, LF and NUL rejection and are zeroed on drop. Forward plans contain only retained allowlisted headers, body length and the configured timeout, not an open connection or reusable credential object.

## Invariants and authorization

Duplicate headers fail closed before forwarding. Standard hop-by-hop headers, every header nominated by `Connection`, and known credential headers are stripped. Exactly one server-generated `Authorization: Bearer` value is appended to an accepted request; client credentials never win precedence.

## Failure, retry and reconciliation

Policy, header and size errors occur before upstream entry. A transport failure after forwarding requires the client/operator unknown-outcome taxonomy and must not be retried merely because the local proxy lost the response. The generated timeout is a dispatch bound, not proof of non-entry.

## Concurrency and ordering

`ProxyPolicy` is immutable after construction and may be shared by an outer synchronization layer. Request headers are validated, de-duplicated, stripped and allowlisted before server credential injection; response credentials and hop-by-hop fields are removed before any downstream serialization.

## Security and privacy

Header-value diagnostics are always redacted and buffers are zeroed on drop. The proxy must run on a constrained local interface, obtain its server token outside process arguments, enforce TLS upstream, reject absolute-form or authority confusion in the transport layer and avoid forwarding tracing headers not explicitly allowed.

## Persistence and compatibility

No cache, cookie jar or durable format is defined. Header policy and transport behavior require explicit versioning if exposed as a stable product surface. Compatibility evidence must include duplicate headers, `Connection` nominations, credential aliases, size limits and ambiguous upstream outcomes.

## Observability

Recommended counters cover rejected duplicate headers, invalid header bytes, stripped credential fields, body-limit rejection, upstream timeout and outcome class. Header names may be reported only from a bounded approved vocabulary; values, tokens, paths and arbitrary connection nominations are never telemetry labels.

## Operations

Runbooks must address local listener ownership, upstream certificate rotation, token replacement, header policy rollout, timeout saturation and ambiguous request reconciliation. The transport adapter must reject deployment configuration it cannot safely implement. Empty allowlists are valid in this model and have the filtering semantics described above; constructor success does not validate listener or upstream configuration.

## Tests and executable evidence

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::inbound_credentials_are_replaced_by_the_server_token`](../../crates/heptabao-proxy/src/lib.rs) checks exactly one injected server credential survives.
- [`tests::connection_nominated_headers_cannot_be_smuggled`](../../crates/heptabao-proxy/src/lib.rs) checks a nominated otherwise-allowed header is removed.
- [`tests::duplicate_and_oversized_requests_fail_closed`](../../crates/heptabao-proxy/src/lib.rs) checks duplicate names and caller-reported request length.

`cargo test -p heptabao-proxy` proves attacker credentials are replaced, `Connection`-nominated headers cannot be smuggled, duplicate and oversized requests fail closed and debug output contains no header value. Strict workspace Clippy and rustdoc are additional current-head gates.

## Evolution and open boundaries

A real listener, TLS, HTTP/2 and HTTP/3 normalization, streaming limits, cancellation, upstream health, response body filtering and OpenBao proxy behavior remain open. Those implementations must preserve the credential and ambiguity boundaries defined here.

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-proxy`
- Crate path: `crates/heptabao-proxy`
- Cargo manifest SHA-256: `f7a165e2852da3eb931b8ac2637d2a957078fb615279ad8ff2998f58500e6c0d`
- Rust source files: `1`
- Public lexical declarations: `15`
- Discovered test functions: `4`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
