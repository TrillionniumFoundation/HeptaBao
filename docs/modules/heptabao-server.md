# heptabao-server

Current plan: `HEPTABAO-PLAN-2026-09-07-V2.1`, single-node service increment. Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package provides the runnable Linux single-node HTTPS secrets service. It joins persistent authentication, default-deny ACL, namespace-qualified KV/Transit/TOTP engines, real AES-GCM storage encryption and authenticated audit to the repaired durable journal. This is a bounded development candidate; it does not implement production networked Raft, qualified KMS auto-unseal, dynamic database/cloud credentials, an external rollback anchor or full OpenBao compatibility.

## Public API and ownership

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-server`; Cargo SHA-256 `490216f98630a660661ec40865f476a1d6779868874c6a1a2c773aac569b97d1`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `struct` | `AuthState` | `crates/heptabao-server/src/auth.rs:30` | `pub struct AuthState {` |
| `struct` | `AuthResponse` | `crates/heptabao-server/src/auth.rs:171` | `pub struct AuthResponse {` |
| `struct` | `AuthError` | `crates/heptabao-server/src/auth.rs:178` | `pub struct AuthError {` |
| `struct` | `AeadBarrier` | `crates/heptabao-server/src/crypto.rs:20` | `pub struct AeadBarrier(aead::LessSafeKey);` |
| `fn` | `new` | `crates/heptabao-server/src/crypto.rs:23` | `pub fn new(mut key: [u8; 32]) -> Result<Self, BarrierError> {` |
| `struct` | `SecretShare` | `crates/heptabao-server/src/crypto.rs:77` | `pub struct SecretShare {` |
| `const` | `fn` | `crates/heptabao-server/src/crypto.rs:104` | `pub const fn total(&self) -> u8 {` |
| `const` | `fn` | `crates/heptabao-server/src/crypto.rs:109` | `pub const fn threshold(&self) -> u8 {` |
| `const` | `fn` | `crates/heptabao-server/src/crypto.rs:114` | `pub const fn index(&self) -> u8 {` |
| `fn` | `encode` | `crates/heptabao-server/src/crypto.rs:119` | `pub fn encode(&self) -> Vec<u8> {` |
| `fn` | `decode` | `crates/heptabao-server/src/crypto.rs:129` | `pub fn decode(encoded: &[u8]) -> Result<Self, &'static str> {` |
| `fn` | `split_secret` | `crates/heptabao-server/src/crypto.rs:157` | `pub fn split_secret(` |
| `fn` | `combine_shares` | `crates/heptabao-server/src/crypto.rs:194` | `pub fn combine_shares(shares: &[SecretShare]) -> Result<[u8; SHARE_SECRET_BYTES], &'static str> {` |
| `fn` | `wrap_barrier_key` | `crates/heptabao-server/src/crypto.rs:236` | `pub fn wrap_barrier_key(` |
| `fn` | `unwrap_barrier_key` | `crates/heptabao-server/src/crypto.rs:264` | `pub fn unwrap_barrier_key(` |
| `fn` | `random` | `crates/heptabao-server/src/crypto.rs:298` | `pub fn random<const N: usize>() -> Result<[u8; N], &'static str> {` |
| `fn` | `digest` | `crates/heptabao-server/src/crypto.rs:306` | `pub fn digest(bytes: &[u8]) -> [u8; 32] {` |
| `struct` | `EngineState` | `crates/heptabao-server/src/engines.rs:17` | `pub struct EngineState {` |
| `struct` | `EngineResponse` | `crates/heptabao-server/src/engines.rs:134` | `pub struct EngineResponse {` |
| `struct` | `EngineError` | `crates/heptabao-server/src/engines.rs:157` | `pub struct EngineError {` |
| `fn` | `required_capability` | `crates/heptabao-server/src/engines.rs:292` | `pub fn required_capability(` |
| `fn` | `handle` | `crates/heptabao-server/src/engines.rs:339` | `pub fn handle(` |
| `struct` | `Config` | `crates/heptabao-server/src/http.rs:28` | `pub struct Config {` |
| `fn` | `serve` | `crates/heptabao-server/src/http.rs:126` | `pub fn serve(config: Config) -> Result<(), String> {` |
| `mod` | `engines` | `crates/heptabao-server/src/lib.rs:15` | `pub mod engines;` |
| `mod` | `http` | `crates/heptabao-server/src/lib.rs:16` | `pub mod http;` |
| `use` | `service::{Response, Service}` | `crates/heptabao-server/src/lib.rs:18` | `pub use service::{Response, Service};` |
| `struct` | `Response` | `crates/heptabao-server/src/service.rs:125` | `pub struct Response {` |
| `fn` | `error` | `crates/heptabao-server/src/service.rs:136` | `pub fn error(status: u16, message: &str) -> Self {` |
| `struct` | `Service` | `crates/heptabao-server/src/service.rs:223` | `pub struct Service {` |
| `fn` | `new` | `crates/heptabao-server/src/service.rs:247` | `pub fn new(data_dir: PathBuf, audit_path: &Path) -> Result<Self, &'static str> {` |
| `fn` | `handle` | `crates/heptabao-server/src/service.rs:310` | `pub fn handle(` |
| `fn` | `handle_at` | `crates/heptabao-server/src/service.rs:352` | `pub fn handle_at(` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

The lifecycle is uninitialized → initialized/sealed → unsealed → sealed. Startup never implicitly unseals. Initialization accepts a bounded Shamir share/threshold profile, returns freshly generated shares and a root token over TLS, then seals. Unsupported initialization options fail before creating state. `State` schema 1 owns cluster identity, token/policy/auth state and namespace/mount-qualified engine maps, including TOTP anti-replay and guess-count state. A single `(system,state)` record stores its serialization through durable HBS2/HBJ2/HBL2 formats and the HBA1 AES-256-GCM barrier envelope. See the durable guide for snapshot/intent/commit/ledger relations and explicit rejection of legacy ambiguous schemas.

## Invariants and authorization

TLS and canonical HTTP parsing precede service dispatch. Every parsed service request requires a synced request audit. Authentication resolves a bearer digest to a namespace-bound, transaction-scoped principal; ACL defaults to deny, and administrative capabilities are checked separately. A successfully authenticated finite token use is committed before dispatch, including requests later denied or rejected for capacity. The principal never crosses the public API and is dropped before the service call returns. Auth and engine mutations use isolated clones, publish only explicitly successful changes, and commit before their response is released. Transit batch responses can contain successful operations with an overall HTTP 400, so their explicit mutation flag owns publication. No secret or newly minted credential is returned after uncertain persistence or failed response audit.

## Failure, retry and reconciliation

Malformed input yields 400, missing/invalid/denied credentials 403, absent or unsupported paths 404, oversized requests 413, unimplemented providers 501, sealed/fenced service or unknown durable outcome 503, and exhausted state capacity 507. Post-entry I/O failures retain a recovery reference and fence service admission. Do not blindly retry writes or initialization after a lost response. Reopen with the original key invokes durable reconciliation before accepting state; the public HTTP profile does not yet provide a complete authorized operation-reference lookup API. A lost initialization response may leave initialized data whose key was not received; do not automatically erase it or reinitialize.

## Concurrency and ordering

One OS-locked audit writer and one OS-locked durable directory prevent concurrent writers. Connections are bounded (default 16, maximum 128); a mutex serializes service transitions while parsing and TLS I/O occur outside that mutex. Each connection has an absolute deadline enforced at underlying socket I/O, including fragmented TLS handshakes. One HTTP request is handled per connection; chunked request bodies, duplicate headers, encoded path separators and pipelining are rejected. Query parameters use a small explicit allowlist; secret-bearing fields must use JSON bodies. Unsupported `X-Vault-*`/`X-Bao-*` security headers (including wrapping, MFA and consistency requirements) return 501 before dispatch instead of silently releasing an unwrapped response. HTTP bounds are 16 KiB headers, 256 KiB body and 1 MiB response. Authentication can be CPU-expensive; throughput tuning and rate limiting remain unqualified.

## Security and privacy

Rustls uses ring with TLS 1.2/1.3 and a configured certificate/key; plaintext transport and TLS verification bypass are absent. Private TLS files must be owner-only, are opened without following a final symlink on Linux and checked through the opened descriptor. The data directory and audit paths are separate. Storage uses OS randomness, AES-256-GCM, a fresh 96-bit nonce per seal and context-bound AAD; cryptography is provided by ring. The unseal key is supplied out of band and never stored beside ciphertext. Owned request, response, serialized-state and cryptographic buffers are erased where ownership permits; this is not a claim of locked memory or removal of all allocator/library copies. Audit contains request fingerprints/status and a keyed sequence chain, never request bodies or bearer tokens. HMAC detects local modification under the retained key; complete consistent rollback of all local evidence still requires an external monotonic anchor.

The request principal is an internal capability, not a public authentication token. It is created only after request audit and authentication, remains local to one synchronous dispatcher invocation, and cannot be imported by downstream crates. A finite-use decrement is durably committed before dispatch; the admitted request may perform layered internal checks without charging another use, while a subsequent request must authenticate again. Re-exporting the raw module is a security regression guarded by a compile-fail example and repository test.

## Persistence and compatibility

All auth and engine state shares the durable transaction boundary. KV data, passwords/verifiers, token digests and Transit keys survive SIGKILL/reopen only after durable acknowledgment. Auth passwords use salted PBKDF2; bearer and AppRole secret IDs persist as digests. The bounded profile limits state to 768 KiB, retains 32,000 operation identities and stops before the 64 MiB journal or 32 MiB audit budget is exhausted. No automatic compaction, online backup or supported format upgrade is implemented. HTTP wire behavior implements a documented subset of OpenBao v1 routes; independent differential observations cover only named cases and cannot confer overall compatibility.

## Observability

The process logs only listener readiness and safe errors. `sys/health`, `sys/seal-status` and `sys/leader` report seal/recovery and single-node state. Audit writes request and response events with timestamp, keyed route/principal fingerprint, sequence, previous MAC and current HMAC. Invalid framing rejected before service dispatch has no service audit record. Audit capacity, verification, sync and lock failures stop admission. Operators must preserve data, journal, ledger, audit and audit-key files together for analysis, keeping keys outside ordinary logs.

## Operations

Use the executable setup in `qa/single-node/smoke.py` for synthetic local data. Build with `cargo build --locked -p heptabao-server`; run `heptabao-server --config /absolute/server.json`. Required config fields are `listen`, absolute `data_dir`, `audit_file`, `tls_cert_file`, `tls_key_file`; optional fields are `max_connections` and `timeout_seconds`. Initialization and unseal are JSON HTTPS requests to `/v1/sys/init` and `/v1/sys/unseal`; credentials belong in private files or protected request bodies, never command arguments. Keep the unseal material under separate custody. Capacity exhaustion requires an explicitly reviewed offline recovery/format procedure; deleting a journal to resume is invalid.

## Tests and executable evidence

Run `cargo test --locked -p heptabao-server` and the workspace gates from the current README. Tests cover real AEAD context/tamper rejection, canonical HTTP framing, auth TTL/usage/revocation, RFC crypto vectors, KV CAS/namespace isolation, partial batch semantics and service transaction/response-audit failure. `tests/repository/test_auth_capability_boundary_v2_6.py` additionally rejects a public raw auth module or any public `Service` signature that exposes `Principal` or `AuthState`. Run `python qa/single-node/smoke.py --binary /absolute/target/debug/heptabao-server --work-dir /new/absolute/private-directory` for a real TLS process, initialization/sealing, invalid credentials, durable finite-use denial and SIGKILL/restart recovery with ciphertext/redacted-audit checks. `qa/openbao-acceptance/acceptance.py` separately executes named KV/token/Transit cases against an independent OpenBao binary. Current results belong in `docs/plan/HEPTABAO_SINGLE_NODE_EXECUTION_STATUS.md`; commands listed here are requirements, not implied passes.

## Evolution and open boundaries

Next gates are full authentication/identity/MFA coverage; PKI/SSH/database/cloud engines and lease revocation; networked Raft replication, linearizable reads and destructive three-node tests; complete interruption-safe migration of policies, identities, keys and leases; external audit anchoring, compaction, provider and platform qualification. Any future lower-level authentication API must use an affine, non-cloneable, non-serializable request capability consumed by one dispatcher call and must receive fresh exact-head hostile replay review. Repository tests and a runnable single node do not close the remaining product gates.

```text
qualification: false
compatibility_claim: false
production_authority: false
migration_authority: false
release_authority: false
authority_effect: NONE
```

## Affine request-principal closure

The authenticated request principal is crate-internal, non-cloneable and non-serializable. `Service` moves it into exactly one dispatcher invocation; internal authorization layers borrow it only during that invocation. Every production authorization decision receives the current service request's live decision time, so subject and parent expiry, revocation, token replacement and policy replacement are re-evaluated without charging an unrelated fresh token use. Repository guards and hostile Rust tests reject a borrowed dispatcher signature, stale authentication-time authorization and a cloneable principal. This source-level closure remains subject to exact-head independent review and grants no production authority.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-server`
- Crate path: `crates/heptabao-server`
- Cargo manifest SHA-256: `490216f98630a660661ec40865f476a1d6779868874c6a1a2c773aac569b97d1`
- Rust source files: `13`
- Public lexical declarations: `33`
- Discovered test functions: `44`
- Workspace-internal dependencies: `heptabao-durable-service` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
