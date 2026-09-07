# `heptabao-p0-server` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `protocol-core-development`  
**Maturity:** `P0_DEVELOPMENT_MEMORY_ONLY`  
**Authority effect:** `NONE`

## Purpose and non-goals

Provides a loopback-only in-memory development server for strict request parsing, init/seal/unseal, KV v1 and audit-order experiments.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: in-process P0 memory state.
- Accountable owner role: `protocol-core-development`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `heptabao-protocol`

Reverse HeptaBao dependants:
- `none`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-p0-server`; Cargo SHA-256 `21a883c7709d8ba3574270452eb57615fc815e274d689448e5b631133bb56365`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `const` | `P0_PROFILE` | `crates/heptabao-p0-server/src/lib.rs:23` | `pub const P0_PROFILE: &str = "HB-P0-DEV-MEMORY";` |
| `const` | `P0_PRODUCTION_SUPPORTED` | `crates/heptabao-p0-server/src/lib.rs:24` | `pub const P0_PRODUCTION_SUPPORTED: bool = false;` |
| `const` | `P0_COMPATIBILITY_CLAIM` | `crates/heptabao-p0-server/src/lib.rs:25` | `pub const P0_COMPATIBILITY_CLAIM: bool = false;` |
| `const` | `P0_AUTHORITY_EFFECT` | `crates/heptabao-p0-server/src/lib.rs:26` | `pub const P0_AUTHORITY_EFFECT: &str = "NONE";` |
| `struct` | `DevelopmentCredentials` | `crates/heptabao-p0-server/src/lib.rs:29` | `pub struct DevelopmentCredentials {` |
| `fn` | `new` | `crates/heptabao-p0-server/src/lib.rs:35` | `pub fn new(mut root_token: Vec<u8>, mut unseal_key: Vec<u8>) -> Result<Self, P0Error> {` |
| `trait` | `AuditSink` | `crates/heptabao-p0-server/src/lib.rs:58` | `pub trait AuditSink: fmt::Debug + Send {` |
| `struct` | `MemoryAuditSink` | `crates/heptabao-p0-server/src/lib.rs:63` | `pub struct MemoryAuditSink {` |
| `fn` | `with_failure_on` | `crates/heptabao-p0-server/src/lib.rs:70` | `pub fn with_failure_on(call: usize) -> Self {` |
| `fn` | `events` | `crates/heptabao-p0-server/src/lib.rs:78` | `pub fn events(&self) -> &[AuditEvent] {` |
| `struct` | `FileAuditSink` | `crates/heptabao-p0-server/src/lib.rs:94` | `pub struct FileAuditSink {` |
| `fn` | `create_new` | `crates/heptabao-p0-server/src/lib.rs:125` | `pub fn create_new(path: impl AsRef<Path>) -> Result<Self, AuditError> {` |
| `fn` | `path` | `crates/heptabao-p0-server/src/lib.rs:152` | `pub fn path(&self) -> &Path {` |
| `struct` | `P0Server` | `crates/heptabao-p0-server/src/lib.rs:180` | `pub struct P0Server<A: AuditSink> {` |
| `struct` | `P0Response` | `crates/heptabao-p0-server/src/lib.rs:264` | `pub struct P0Response {` |
| `fn` | `new` | `crates/heptabao-p0-server/src/lib.rs:318` | `pub fn new(credentials: DevelopmentCredentials, audit: A) -> Self {` |
| `fn` | `audit` | `crates/heptabao-p0-server/src/lib.rs:326` | `pub fn audit(&self) -> &A {` |
| `fn` | `generation` | `crates/heptabao-p0-server/src/lib.rs:330` | `pub fn generation(&self) -> u64 {` |
| `fn` | `handle` | `crates/heptabao-p0-server/src/lib.rs:334` | `pub fn handle(&mut self, envelope: RequestEnvelope, now: MonotonicTick) -> P0Response {` |
| `enum` | `AuditError` | `crates/heptabao-p0-server/src/lib.rs:828` | `pub enum AuditError {` |
| `enum` | `P0Error` | `crates/heptabao-p0-server/src/lib.rs:853` | `pub enum P0Error {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and invariants

- Server starts sealed and fail closed.
- Request bounds, canonicalization, authentication and audit precede mutation.
- HTTP 204 responses contain no body.
- Request IDs are single-use within the bounded P0 registry.
- Secret paths and values are redacted and best-effort overwritten.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

Committed-but-undelivered responses are not blindly retried. The P0 request registry is not an HA replay authority.

Errors are part of the public contract. Unknown, blocked, stale, corrupt, unauthenticated and unauthorized outcomes remain distinct. Callers must not collapse them into a generic retryable transport failure.

## Persistent or wire formats

This crate does not own a durable or wire format; it consumes typed contracts from dependencies.

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
- `client_request_id_is_single_use_inside_the_p0_window` (crates/heptabao-p0-server/src/main.rs)
- `delete_no_content_is_always_body_free` (crates/heptabao-p0-server/src/lib.rs)
- `expired_request_never_dispatches` (crates/heptabao-p0-server/src/lib.rs)
- `file_audit_requires_new_absolute_non_symlink_path` (crates/heptabao-p0-server/src/lib.rs)
- `fresh_server_starts_fail_closed_and_sealed` (crates/heptabao-p0-server/src/lib.rs)
- `ignored_operation_bodies_fail_closed_before_dispatch` (crates/heptabao-p0-server/src/lib.rs)
- `init_requires_the_exact_empty_object_body` (crates/heptabao-p0-server/src/lib.rs)
- `init_unseal_write_and_read_are_audited` (crates/heptabao-p0-server/src/lib.rs)
- `invalid_unescaped_quote_is_rejected` (crates/heptabao-p0-server/src/lib.rs)
- `kv_list_response_is_direct_owned_and_debug_redacted` (crates/heptabao-p0-server/src/lib.rs)
- `no_content_response_never_emits_a_wire_body` (crates/heptabao-p0-server/src/main.rs)
- `rejection_audit_failure_returns_service_unavailable` (crates/heptabao-p0-server/src/lib.rs)
- `request_audit_failure_prevents_mutation` (crates/heptabao-p0-server/src/lib.rs)
- `request_id_registry_fails_closed_when_saturated` (crates/heptabao-p0-server/src/main.rs)
- `request_registry_debug_redacts_live_ids` (crates/heptabao-p0-server/src/main.rs)
- `response_audit_failure_preserves_commit_and_returns_recovery_reference` (crates/heptabao-p0-server/src/lib.rs)
- `sealed_and_authentication_bypasses_fail_closed` (crates/heptabao-p0-server/src/lib.rs)
- `secret_path_debug_is_redacted` (crates/heptabao-p0-server/src/lib.rs)
- `server_debug_redacts_kv_paths_and_values` (crates/heptabao-p0-server/src/lib.rs)
- `trailing_escape_is_rejected` (crates/heptabao-p0-server/src/lib.rs)
- `weak_or_equal_credentials_are_rejected` (crates/heptabao-p0-server/src/lib.rs)

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

Bind only to loopback and use disposable non-secret fixtures. This binary must not be exposed as a production secrets server.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- Not connected to durable store, journal, Authbus, policy or recovery.
- No TLS or production listener.
- No OpenBao compatibility claim.


## Traceability and maintenance

- Crate path: `crates/heptabao-p0-server`
- Module guide: `docs/modules/heptabao-p0-server.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-p0-server`
- Crate path: `crates/heptabao-p0-server`
- Cargo manifest SHA-256: `21a883c7709d8ba3574270452eb57615fc815e274d689448e5b631133bb56365`
- Rust source files: `2`
- Public lexical declarations: `21`
- Discovered test functions: `21`
- Workspace-internal dependencies: `heptabao-protocol` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
