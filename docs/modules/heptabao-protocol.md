# `heptabao-protocol` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `protocol-ingress-security`  
**Maturity:** `STRICT_P0_PROTOCOL_FOUNDATION`  
**Authority effect:** `NONE`

## Purpose and non-goals

Defines strict HTTP request framing, canonical targets, operation classification, monotonic deadlines and secret-bearing request wrappers for the P0 profile.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: none; protocol parsing is pure with injected time/context.
- Accountable owner role: `protocol-ingress-security`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `none`

Reverse HeptaBao dependants:
- `heptabao-authbus-contracts`
- `heptabao-p0-server`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-protocol`; Cargo SHA-256 `951de609e5e4f963856967dccae040184a9215084f138141b9205747d6a7f226`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `const` | `MAX_HTTP_HEAD_BYTES` | `crates/heptabao-protocol/src/lib.rs:13` | `pub const MAX_HTTP_HEAD_BYTES: usize = 16 * 1024;` |
| `const` | `MAX_HTTP_BODY_BYTES` | `crates/heptabao-protocol/src/lib.rs:14` | `pub const MAX_HTTP_BODY_BYTES: usize = 1024 * 1024;` |
| `const` | `MAX_TARGET_BYTES` | `crates/heptabao-protocol/src/lib.rs:15` | `pub const MAX_TARGET_BYTES: usize = 2 * 1024;` |
| `const` | `MAX_HEADER_COUNT` | `crates/heptabao-protocol/src/lib.rs:16` | `pub const MAX_HEADER_COUNT: usize = 64;` |
| `const` | `MAX_HEADER_VALUE_BYTES` | `crates/heptabao-protocol/src/lib.rs:17` | `pub const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;` |
| `const` | `MONOTONIC_NANOS_PER_SECOND` | `crates/heptabao-protocol/src/lib.rs:18` | `pub const MONOTONIC_NANOS_PER_SECOND: u64 = 1_000_000_000;` |
| `const` | `MAX_REQUEST_BUDGET_NANOS` | `crates/heptabao-protocol/src/lib.rs:19` | `pub const MAX_REQUEST_BUDGET_NANOS: u64 = 60 * MONOTONIC_NANOS_PER_SECOND;` |
| `const` | `MAX_REQUEST_BUDGET_TICKS` | `crates/heptabao-protocol/src/lib.rs:20` | `pub const MAX_REQUEST_BUDGET_TICKS: u64 = MAX_REQUEST_BUDGET_NANOS;` |
| `enum` | `Method` | `crates/heptabao-protocol/src/lib.rs:23` | `pub enum Method {` |
| `const` | `fn` | `crates/heptabao-protocol/src/lib.rs:43` | `pub const fn as_str(self) -> &'static str {` |
| `enum` | `Operation` | `crates/heptabao-protocol/src/lib.rs:55` | `pub enum Operation {` |
| `const` | `fn` | `crates/heptabao-protocol/src/lib.rs:68` | `pub const fn mutates(self) -> bool {` |
| `const` | `fn` | `crates/heptabao-protocol/src/lib.rs:75` | `pub const fn requires_authentication(self) -> bool {` |
| `const` | `fn` | `crates/heptabao-protocol/src/lib.rs:82` | `pub const fn allowed_while_sealed(self) -> bool {` |
| `struct` | `CanonicalTarget` | `crates/heptabao-protocol/src/lib.rs:123` | `pub struct CanonicalTarget {` |
| `fn` | `parse` | `crates/heptabao-protocol/src/lib.rs:149` | `pub fn parse(raw: &str) -> Result<Self, ProtocolError> {` |
| `fn` | `path` | `crates/heptabao-protocol/src/lib.rs:168` | `pub fn path(&self) -> &str {` |
| `fn` | `query` | `crates/heptabao-protocol/src/lib.rs:172` | `pub fn query(&self) -> &[(String, String)] {` |
| `fn` | `canonical_string` | `crates/heptabao-protocol/src/lib.rs:176` | `pub fn canonical_string(&self) -> String {` |
| `fn` | `matches_canonical` | `crates/heptabao-protocol/src/lib.rs:193` | `pub fn matches_canonical(&self, raw: &str) -> bool {` |
| `struct` | `HeaderMap` | `crates/heptabao-protocol/src/lib.rs:307` | `pub struct HeaderMap(BTreeMap<String, Vec<u8>>);` |
| `fn` | `get` | `crates/heptabao-protocol/src/lib.rs:329` | `pub fn get(&self, name: &str) -> Option<&str> {` |
| `fn` | `len` | `crates/heptabao-protocol/src/lib.rs:335` | `pub fn len(&self) -> usize {` |
| `fn` | `is_empty` | `crates/heptabao-protocol/src/lib.rs:339` | `pub fn is_empty(&self) -> bool {` |
| `fn` | `iter` | `crates/heptabao-protocol/src/lib.rs:343` | `pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {` |
| `struct` | `ParsedHttpRequest` | `crates/heptabao-protocol/src/lib.rs:353` | `pub struct ParsedHttpRequest {` |
| `fn` | `parse_http_request` | `crates/heptabao-protocol/src/lib.rs:378` | `pub fn parse_http_request(input: &[u8]) -> Result<ParsedHttpRequest, ProtocolError> {` |
| `fn` | `classify_operation` | `crates/heptabao-protocol/src/lib.rs:532` | `pub fn classify_operation(` |
| `struct` | `MonotonicTick` | `crates/heptabao-protocol/src/lib.rs:563` | `pub struct MonotonicTick(pub u64);` |
| `const` | `fn` | `crates/heptabao-protocol/src/lib.rs:566` | `pub const fn from_nanos(value: u64) -> Self {` |
| `const` | `fn` | `crates/heptabao-protocol/src/lib.rs:570` | `pub const fn as_nanos(self) -> u64 {` |
| `fn` | `checked_add_duration` | `crates/heptabao-protocol/src/lib.rs:574` | `pub fn checked_add_duration(self, duration: Duration) -> Option<Self> {` |
| `fn` | `checked_duration_since` | `crates/heptabao-protocol/src/lib.rs:579` | `pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> {` |
| `struct` | `RequestEnvelope` | `crates/heptabao-protocol/src/lib.rs:585` | `pub struct RequestEnvelope {` |
| `fn` | `validate_at` | `crates/heptabao-protocol/src/lib.rs:605` | `pub fn validate_at(&self, now: MonotonicTick) -> Result<Operation, ProtocolError> {` |
| `struct` | `RequestId` | `crates/heptabao-protocol/src/lib.rs:627` | `pub struct RequestId(String);` |
| `fn` | `new` | `crates/heptabao-protocol/src/lib.rs:630` | `pub fn new(value: String) -> Result<Self, ProtocolError> {` |
| `fn` | `as_str` | `crates/heptabao-protocol/src/lib.rs:642` | `pub fn as_str(&self) -> &str {` |
| `enum` | `AuditPhase` | `crates/heptabao-protocol/src/lib.rs:648` | `pub enum AuditPhase {` |
| `enum` | `CommitDisposition` | `crates/heptabao-protocol/src/lib.rs:657` | `pub enum CommitDisposition {` |
| `struct` | `AuditEvent` | `crates/heptabao-protocol/src/lib.rs:665` | `pub struct AuditEvent {` |
| `struct` | `SecretBytes` | `crates/heptabao-protocol/src/lib.rs:675` | `pub struct SecretBytes(Vec<u8>);` |
| `fn` | `new` | `crates/heptabao-protocol/src/lib.rs:678` | `pub fn new(mut value: Vec<u8>) -> Result<Self, ProtocolError> {` |
| `fn` | `expose` | `crates/heptabao-protocol/src/lib.rs:686` | `pub fn expose(&self) -> &[u8] {` |
| `fn` | `constant_time_eq` | `crates/heptabao-protocol/src/lib.rs:690` | `pub fn constant_time_eq(&self, candidate: &[u8]) -> bool {` |
| `enum` | `ProtocolError` | `crates/heptabao-protocol/src/lib.rs:715` | `pub enum ProtocolError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and invariants

- HTTP framing, Host, Content-Length and canonical target rules are strict and bounded.
- Classification follows canonicalization and precedes authentication or mutation.
- Deadline values are process-local monotonic ticks and never serialized across processes.
- Secret-bearing buffers are non-clone, redacted and best-effort overwritten.
- Unknown operations and ignored bodies fail closed.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

Parsing failure is terminal for the byte stream. Client retry requires a new connection and follows operation-specific idempotency rules.

Errors are part of the public contract. Unknown, blocked, stale, corrupt, unauthenticated and unauthorized outcomes remain distinct. Callers must not collapse them into a generic retryable transport failure.

## Persistent or wire formats

All durable or wire encodings are versioned, bounded and strict. Decoders reject truncation, impossible lengths, invalid identity/version and trailing bytes. Exact field layouts remain normative in the linked domain contract and source tests.

Format changes require an explicit version transition, backward/forward compatibility decision, hostile decoder tests and migration/rollback treatment.

## Concurrency and cancellation

The caller must preserve single-writer or immutable-reader ownership declared by the domain. Cancellation after an irreversible provider call or durable publication changes only the waiter; it does not revoke the completed authority or commit. Shared mutable state requires a documented fence, generation or epoch.

## Security and secret handling

- Secret-bearing bytes are not logged, formatted, cloned or serialized unless an explicit audited exposure method permits it.
- `Debug` output carries only opaque identity, lengths and safe state classes.
- Buffer overwrite is best effort and does not prove allocator, swap, crash-dump or side-channel resistance.
- No real token, unseal share, recovery key, private key or production snapshot belongs in source, tests, CI or diagnostics.

## Testing and evidence

Detected crate-local tests:
- `body_requires_exact_content_length` (crates/heptabao-protocol/src/lib.rs)
- `deadline_must_be_strictly_after_receipt` (crates/heptabao-protocol/src/lib.rs)
- `deadline_uses_actual_dispatch_time` (crates/heptabao-protocol/src/lib.rs)
- `duplicate_host_is_rejected` (crates/heptabao-protocol/src/lib.rs)
- `encoded_slash_and_lowercase_encoding_are_rejected` (crates/heptabao-protocol/src/lib.rs)
- `monotonic_duration_addition_fails_on_overflow` (crates/heptabao-protocol/src/lib.rs)
- `monotonic_units_are_nanoseconds_and_budget_is_sixty_seconds` (crates/heptabao-protocol/src/lib.rs)
- `oversized_unterminated_head_is_rejected_early` (crates/heptabao-protocol/src/lib.rs)
- `query_keys_are_unique_sorted_and_exactly_matchable` (crates/heptabao-protocol/src/lib.rs)
- `request_debug_redacts_path_header_values_and_body` (crates/heptabao-protocol/src/lib.rs)
- `request_line_whitespace_smuggling_is_rejected` (crates/heptabao-protocol/src/lib.rs)
- `secret_debug_is_redacted_and_compare_is_length_aware` (crates/heptabao-protocol/src/lib.rs)
- `strict_request_parses_and_classifies` (crates/heptabao-protocol/src/lib.rs)

Required local gate:

```text
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
```

Domain changes also run plan mutation tests, current platform/Oracle regressions and frozen inherited-source replay. A green run is technical evidence only.

## Extension workflow

1. Bind the exact base commit/tree and read the current plan, blocker register and this guide.
2. Add or change typed contracts before concrete adapters.
3. Define state transition, error, retry and cancellation behavior.
4. Add positive, hostile and restart/replay tests.
5. Update this guide, traceability and normative manifest in the same change.
6. Run exact-head read-only CI; preserve failed evidence.
7. Obtain independent review for storage, cryptography, security or distributed-systems critical changes.

## Operations and diagnostics

Use stable rejection detail codes and request-attempt identity; raw target, headers and body must not be logged.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- Full OpenBao normalization/error compatibility is absent.
- HTTP/2, HTTP/3, proxy forwarding and TLS are out of scope.
- Production framework integration is not implemented.


## Traceability and maintenance

- Crate path: `crates/heptabao-protocol`
- Module guide: `docs/modules/heptabao-protocol.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-protocol`
- Crate path: `crates/heptabao-protocol`
- Cargo manifest SHA-256: `951de609e5e4f963856967dccae040184a9215084f138141b9205747d6a7f226`
- Rust source files: `1`
- Public lexical declarations: `46`
- Discovered test functions: `13`
- Workspace-internal dependencies: none
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
