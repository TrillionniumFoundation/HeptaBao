# heptabao-server

Current plan: `HEPTABAO-PLAN-2026-09-07-V2.1`, single-node service increment. Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package provides the runnable Linux HTTPS secrets service. It joins persistent token/userpass/AppRole and bounded JWT/JWKS authentication, default-deny ACL, namespace-qualified KV/Transit/TOTP, SSH OTP and internal PKI engines, real AES-GCM storage encryption and authenticated audit to the repaired durable journal. The mandatory file audit owner may be paired with a process-configured, host-enrolled HTTPS collector and/or one bounded TCP socket collector. HTTPS delivery is TLS pinned, redirect-free, deadline bounded and fail-closed after the local audit record is fsynced. TCP socket delivery is also deadline bounded but remains nonblocking for application admission because the mandatory authenticated file record is already durable; failed socket writes are counted and exposed through `sys/audit/socket`. It includes per-process networked Raft composition and authenticated explicit leadership transfer. This remains a bounded development candidate: it does not establish production HA qualification, qualified KMS auto-unseal, fully qualified dynamic database/cloud credentials, the complete PKI/JWT/OIDC surfaces, an external rollback anchor or full OpenBao compatibility.

## Public API and ownership

The developing `postgres_storage` library component provides physical records
and transactions for PostgreSQL. Its [storage design and validation guide](../storage/HEPTABAO_POSTGRESQL_PHYSICAL_STORAGE.md)
distinguishes it from dynamic database credentials and records the remaining
server persistence and HA integration. It is not selected by HTTP server configuration.

`Service::new(data_dir, audit_path)` owns the private state lifecycle, durable writer, audit owner and seal material. `new_with_audit_config` takes the exported `AuditConfig` retention policy; `new_with_ha_audit_config` combines both options, while existing constructors use defaults. `new_with_ha` additionally shares an `Arc<Mutex<HaProcess>>`; it does not permit the caller to inject an authenticated principal. Public `Service::handle` derives Unix seconds from the system clock. `handle_at` takes the same borrowed method/path/namespace/bearer inputs, consumes an owned JSON body and accepts an explicit `now` for deterministic tests or a trusted embedding. It returns owned `Response { status, body }`. Production callers must not accept a client-supplied time.

Paths passed to Service omit `/v1/` and the root namespace is empty; the HTTPS parser owns wire canonicalization and bounds. `http::Config` owns absolute storage/audit/TLS paths, optional deployment-owned client CA/CRL paths for certificate authentication, listen address, connection/deadline/rate-limit settings, audit retention configuration, the deployment-owned outbound endpoint allowlist, an optional fixed `audit_http_url`, and an optional fixed `audit_socket`. The HTTP audit URL must already resolve through that allowlist before unseal; `sys/audit/http` can inspect it but cannot dynamically redirect, replace or disable the process-owned destination. `audit_socket` currently admits only a bounded TCP address/write deadline; `sys/audit/socket` exposes its non-secret status and failure counter but cannot create, rebind or disable it at runtime. UDP, Unix-domain socket mode and complete OpenBao socket options remain outside this profile. Unknown JSON configuration fields are rejected. `http::serve` owns configuration and starts the listener; `serve_with_ha` shares the HA process. The private `auth` and `service` modules are not exported, even where historical tables below show `pub` declarations.

Current API declaration excerpt (illustrative, not a standalone program):

<!-- CURRENT API: crates/heptabao-server/src/service.rs#handle_at -->
```text
pub fn handle_at(
        &mut self,
        method: &str,
        path: &str,
        namespace: &str,
        token: &str,
        body: Value,
        now: u64,
    ) -> Response
```

Authentication, engine and maintenance route parameters/errors are detailed in `docs/auth/HEPTABAO_SINGLE_NODE_AUTH.md`, `docs/engines/HEPTABAO_SINGLE_NODE_ENGINES.md` and `docs/operations/HEPTABAO_SINGLE_NODE_OPERATOR_RUNBOOK_V1.md`. The actual crate and internal owner graph is `docs/architecture/HEPTABAO_CURRENT_RUNTIME_ARCHITECTURE.md`; the standalone token/policy/identity/plugin crates are not server state owners.

Current source binding: `docs/modules/CURRENT_SOURCE_BINDING.md` and
`planning/HEPTABAO_CURRENT_SOURCE_INVENTORY_V2.json`. Any V1.4.7 generated
blocks below are historical lexical snapshots, not current API authority.

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

## Integrated runtime extensions

Response wrapping now uses `ServiceRequest`, `handle_request` and
`handle_request_at` to bind TTL without widening the Principal interface. Read
[the wrapping contract](../auth/HEPTABAO_RESPONSE_WRAPPING.md) for durable
single-use capture, HBFQ2 forwarding, limits, failure and upgrade semantics.
[Live capability inspection](../auth/HEPTABAO_CAPABILITIES.md) uses the same
current ACL/Identity evaluator; inspecting another finite token does not consume it.
[SSH OTP and its registered leases](../engines/HEPTABAO_SSH_OTP.md) are actual
Service paths, not an imported in-memory lease model. Issuance, consumption,
revocation, clock fencing and wrapper capture share the existing writer.

The [Python SDK and CLI](../../clients/python/README.md) makes real HTTPS calls
and publishes responses privately. It does not implement full CLI/Agent/Proxy
parity and does not turn the standalone Rust contract crates into runtime owners.

Source test anchors include `wrapping_result_audit_failure_withholds_response_and_persists_single_use`,
`ssh_lease_path_and_body_identity_cannot_redirect_authorized_revocation` and
`ssh_disabled_login_identity_revokes_issued_otp_without_resurrection`.
These names identify test code; only exact-candidate execution evidence proves a pass.

### Idle lifetime worker and operational consumers

The host starts one bounded `service_lifecycle.rs` worker for local lease expiry
and wrapped-payload erasure, using the existing Service writer, ReadIndex, audit
and durable commit. It cannot issue credentials or run external-provider callbacks.
`lifecycle_interval_seconds` is default 5, enabled 1–60, explicitly disabled at 0;
per-request expiry remains enforced. Source tests include
`idle_maintenance_commits_expiry_without_a_client_request_and_no_clock_revival`
and `lifecycle_worker_is_bounded_joined_and_does_not_keep_service_alive`.
The real Python AppRole Agent, same-UID Unix proxy and host-bound OTP helper
are described in [the operational contract](../operations/HEPTABAO_AGENT_PROXY_HELPER.md).
They are separately installable consumers, not new server state owners. Successful
`auth/token/renew-self` and token-selected `renew` echo only the already supplied
bearer, before optional wrapping; accessor lookup never reconstructs a credential.

## State and data model

The lifecycle is uninitialized → initialized/sealed → unsealed → sealed. Startup never implicitly unseals. Initialization accepts a bounded Shamir share/threshold profile, returns freshly generated shares and a root token over TLS, then seals. Unsupported initialization options fail before creating state. `State` (with the current discriminator defined below) owns cluster identity, cluster-visible `replay_epoch`, token/policy/auth state, namespace/mount-qualified engine maps, database intent/lease state, the durable PostgreSQL provider fence and Raft administration policy. TOTP anti-replay and guess-count state remain in the same encrypted transaction. [The current state-format contract](../architecture/HEPTABAO_CURRENT_STATE_FORMAT.md) defines legacy read admission, mutation promotion and rollback; schema numbers in retained increment descriptions are not current rollout instructions. The serialized logical application state is bounded to **16 MiB**. Current local durability uses owner-scoped `heptabao-state-owners-v4` content-defined chunks with 384 KiB minimum, 512 KiB target and 768 KiB maximum sizes. Auth, Engines, Database, Raft-admin and Namespace are serialized independently; one owner manifest is the sole atomic local publication point, unchanged owner chunks are reused, and replaced chunks are removed in the same durable batch. The owner plan derives a content-authenticated changed/reused-owner write set and rejects any staged or retired owner chunk outside that changed set; only explicit legacy `state-chunks/*` migration cleanup is exempt. HA still begins from the fully serialized logical image and uses HBSM3 content-defined logical chunks over a bounded 128-index/two-slot physical Raft keyspace; historical HBSR1/HBSM2 committed state remains readable; HBSR1 mutation promotion is refused until explicit migration. New owner-bound commits use HBSM4, carrying an encrypted canonical owner-manifest digest and changed-owner mask; followers rebuild and compare the canonical target manifest before durable catch-up, failing closed on target divergence. The mask is range-validated but not compared to a lagging follower’s wider local delta because HBSM4 does not carry the predecessor manifest identity. V4 removes whole-state local physical rewrites, but HA digest/planning still serializes the complete logical state, so end-to-end write cost is not yet fully record-oriented or production-scale qualified. Replay-epoch ordering and local-ledger retirement are specified in [HEPTABAO_REPLAY_EPOCH_PROTOCOL.md](../architecture/HEPTABAO_REPLAY_EPOCH_PROTOCOL.md). See the durable guide for snapshot/intent/commit/ledger relations and explicit rejection of legacy ambiguous schemas.

## Invariants and authorization

TLS and canonical HTTP parsing precede service dispatch. Every parsed service request requires a synced request audit. Authentication resolves a bearer digest to a namespace-bound, transaction-scoped principal; ACL defaults to deny, and administrative capabilities are checked separately. A successfully authenticated finite token use is committed before dispatch, including requests later denied or rejected for capacity. The principal never crosses the public API and is dropped before the service call returns. Auth and engine mutations use isolated clones, publish only explicitly successful changes, and commit before their response is released. Transit batch responses can contain successful operations with an overall HTTP 400, so their explicit mutation flag owns publication. No secret or newly minted credential is returned after uncertain persistence or failed response audit.

## Failure, retry and reconciliation

Malformed input yields 400, missing/invalid/denied credentials 403, absent or unsupported paths 404, oversized requests 413, unimplemented providers 501, sealed/fenced service or unknown durable outcome 503, and exhausted state capacity 507. Post-entry I/O failures retain a recovery reference and fence service admission. Do not blindly retry writes or initialization after a lost response. Reopen with the original key invokes durable reconciliation before accepting state; root `GET sys/internal/recovery/<reference>` reports committed/aborted/unknown for the bounded local durable ledger; it is not a general external-effect operator API. For initialization opted into client-secret recovery, repeat the same bound request to recover the response before acknowledgement. Without that opt-in, response loss may leave initialized data whose shares were not received; do not automatically erase it or reinitialize.

## Concurrency and ordering

One OS-locked audit writer and one OS-locked durable directory prevent concurrent writers. Connections are bounded (default 16, maximum 128); a mutex serializes service transitions while parsing and TLS I/O occur outside that mutex. Each connection has an absolute deadline enforced at underlying socket I/O, including fragmented TLS handshakes. One HTTP request is handled per connection; chunked request bodies, duplicate headers, encoded path separators and pipelining are rejected. Query parameters use a small explicit allowlist; secret-bearing fields must use JSON bodies. Unsupported `X-Vault-*`/`X-Bao-*` security headers (including unsupported wrapping formats, MFA and consistency requirements) return 501 before dispatch instead of silently releasing an unwrapped response. HTTP bounds are 16 KiB headers, 256 KiB normal body, 32 MiB snapshot request body and 32 MiB response; decoded backup transfer is limited to 20 MiB. Per-peer rate-limit controls exist; authentication is CPU-expensive and production throughput/SLO qualification remains open.

## Security and privacy

Rustls uses ring with TLS 1.2/1.3 and a configured certificate/key; plaintext transport and TLS verification bypass are absent. When a client CA is configured, the same listener requires a WebPKI-validated client chain and can enforce a deployment-owned CRL. Private TLS files must be owner-only, are opened without following a final symlink on Linux and checked through the opened descriptor. The data directory and audit paths are separate. Storage uses OS randomness, AES-256-GCM, a fresh 96-bit nonce per seal and context-bound AAD; cryptography is provided by ring. The unseal key is supplied out of band and never stored beside ciphertext. Owned request, response, serialized-state and cryptographic buffers are erased where ownership permits; this is not a claim of locked memory or removal of all allocator/library copies. Audit contains request fingerprints/status and a keyed sequence chain, never request bodies or bearer tokens. HMAC detects local modification under the retained key; complete consistent rollback of all local evidence still requires an external monotonic anchor.

`qa/openbao-acceptance/cert_auth_live.py` is a bounded real-listener certificate-auth fixture. It generates a root/intermediate chain with OpenSSL, starts the Linux server with client-CA enforcement, and observes missing-chain rejection, client-auth EKU rejection, exact leaf digest and CN/SAN/OU/extension selectors, login metadata, wrong-leaf denial, certificate-bound renewal, and renewal after SIGKILL/restart. The fixture is executable evidence for this scoped profile only; it does not claim OpenBao 2.6.2 certificate parity for CRL/OCSP/distribution, forwarded client-certificate headers, provider rotation, or independent oracle qualification.

Certificate renewal applies the current role and mount maximum to the original token issue time. Newly issued certificate tokens can extend beyond the original ordinary role maximum when that maximum is raised; this profile does not accept certificate-role explicit maximum TTLs. Old persisted absolute caps remain enforced because an unmarked parentless token may instead be a historical token-API orphan with a real explicit cap; log in again to use the current role's raised maximum. A still-active token past a shortened current maximum returns 500, matching OpenBao 2.6.2's renewal error; an already expired token remains 403. Token-API children do not inherit certificate renewal constraints, and their explicit caps remain enforced. Parented children revoke with their issuer, while token-API orphans survive the parent's auth-mount removal. The explicit `TokenApi` marker also corrects mount/certificate fields incorrectly inherited in older snapshots. An old parentless token without that marker cannot be distinguished from a direct login and retains conservative issuer restrictions. `qa/openbao-acceptance/cert_renewal_live.py` compares this bounded behavior over HTTPS, disclosing the candidate's same-store restart without client-CA enforcement for requests that carry no client certificate; it does not claim optional-client-certificate listener parity.

The request principal is an internal capability, not a public authentication token. It is created only after request audit and authentication, remains local to one synchronous dispatcher invocation, and cannot be imported by downstream crates. A finite-use decrement is durably committed before dispatch; the admitted request may perform layered internal checks without charging another use, while a subsequent request must authenticate again. Re-exporting the raw module is a security regression guarded by a compile-fail example and repository test.

## Persistence and compatibility

All auth and engine state shares the durable transaction boundary. KV data, passwords/verifiers, token digests and Transit keys survive SIGKILL/reopen only after durable acknowledgment. Auth passwords use salted PBKDF2; bearer and AppRole secret IDs persist as digests. The bounded profile limits the serialized logical application state to 16 MiB locally and in HA; local V3 content-defined storage and HA chunk framing both operate on a fully serialized logical state rather than record-oriented ownership. Before an HA Raft write is accepted, the owner manifest is preflighted and bound to the exact operation identity and logical-state digest; a mismatch is rejected before any replicated publication. The active replay ledger retains at most 32,000 operation identities per `replay_epoch`; ordinary compaction never evicts them. Root `POST`/`PUT sys/storage/raft/replay-retire` advances exactly one epoch. In HA the new `replay_epoch` is Raft-ordered in application state, and each applying node retires its local durable ledger before publishing the higher epoch; a partial retirement/publication failure fences the Service. Before-entry journal-capacity rejection triggers one authenticated checkpoint and one exact-envelope retry without silently discarding replay identities. The 64 MiB journal budget remains separate from logical state capacity. Root-authorized manual compaction and encrypted backup export/restore are implemented; compaction preserves identities in the active epoch. Audit rotates automatically at `audit.segment_bytes` (4 KiB–32 MiB, default 32 MiB), retaining `audit.retained_segments` (1–64, default 8) sealed segments plus the active file. An HMAC-authenticated manifest preserves retained-chain and evicted-prefix frontiers; evicted event contents require external archival. Audit corruption or I/O failure still fails closed. Qualified format upgrades and external archive delivery remain open. The snapshot response uses the HeptaBao encrypted-backup profile, not OpenBao snapshot bytes. Direct local restore is rejected when HA is enabled. HTTP wire behavior implements a documented subset of OpenBao v1 routes; independent differential observations cover only named cases and cannot confer overall compatibility.

## Observability

`GET sys/internal/capacity` is a root-token, root-namespace-only service endpoint. It reports the serving leader's serialized logical state bytes, active replay-operation count, journal budget and generation. It accepts no mutation/reset fields and does not reserve headroom. The retained `GET sys/internal/storage/capacity` view additionally reports the serving node's `replay_epoch`, `retired_through_generation`, and whether replay retirement is `raft-coordinated` in HA. Standby requests can forward to the leader, so this HTTP view alone is not follower-local convergence evidence. Ordinary request/result audit and sealed/recovery rejection still apply. See `docs/operations/HEPTABAO_CAPACITY_AND_GROWTH.md`, `docs/architecture/HEPTABAO_REPLAY_EPOCH_PROTOCOL.md`, and `crates/heptabao-server/src/service_capacity.rs` for the source-bound contracts. These are HeptaBao extensions, not newly completed OpenBao compatibility surfaces.

The process logs only listener readiness and safe errors. `sys/health`, `sys/seal-status` and `sys/leader` report seal/recovery and single-node state; in HA, active success also requires `ha_application_ready`, meaning the local logical-state digest matches the committed Raft application envelope after a successful ReadIndex. Audit writes request and response events with timestamp, keyed route/principal fingerprint, sequence, previous MAC and current HMAC. Framing rejections entering `handle_wire_rejection` produce redacted service audit records. Failures before that hook, such as TLS handshake failure, do not carry a parsed service request. Audit capacity, verification, sync and lock failures stop admission. Operators must preserve data, journal, ledger, audit and audit-key files together for analysis, keeping keys outside ordinary logs.

## Operations

Use the executable setup in `qa/single-node/smoke.py` for synthetic local data. Build with `cargo build --locked -p heptabao-server`; run `heptabao-server --config /absolute/server.json`. Required config fields are `listen`, absolute `data_dir`, `audit_file`, `tls_cert_file`, `tls_key_file`; optional fields are `max_connections` and `timeout_seconds`. Initialization and unseal are JSON HTTPS requests to `/v1/sys/init` and `/v1/sys/unseal`; credentials belong in private files or protected request bodies, never command arguments. Keep the unseal material under separate custody. Capacity exhaustion requires an explicitly reviewed recovery/format or replay-epoch procedure; deleting journal or replay-ledger material to resume is invalid.

## Tests and executable evidence

Current named source scenarios:

- `finite_use_is_committed_for_acl_denial_and_state_capacity_rejection` — `crates/heptabao-server/src/service_tests.rs`.
- `result_audit_failure_withholds_plaintext_and_preserves_consumed_token_after_reopen` — `crates/heptabao-server/src/service_tests.rs`.
- `root_maintenance_routes_compact_snapshot_restore_and_reconcile` — `crates/heptabao-server/src/service_tests.rs`.
- `replay_retirement_is_root_only_and_state_commits_continue_in_new_epoch` — `crates/heptabao-server/src/service_capacity_tests.rs`.
- `ha_catch_up_epoch_transition_retires_local_ledger_before_state_publication` — `crates/heptabao-server/src/service_capacity_tests.rs`.
- `failed_state_publication_after_epoch_retirement_fences_service` — `crates/heptabao-server/src/service_capacity_tests.rs`.
- `ha_commit_rejects_owner_binding_for_different_operation_or_state` — `crates/heptabao-server/src/ha.rs`.
- `owner_plan_publication_binding_covers_operation_and_logical_state` — `crates/heptabao-server/src/service_owner_store.rs`.

Run `cargo +1.98.0 test --locked -p heptabao-server --all-targets`. These are source anchors; a current test receipt is separate. `qa/openbao-acceptance/replay_epoch_ha.py` is the exact-binary three-process mTLS/Raft lifecycle fixture: it retires an epoch, kills the acknowledged leader, forces a former follower to become authoritative and write, rejoins and re-elects the old leader, then repeats retirement/failover. A checked-in fixture is not a passing receipt; exact-head CI must execute it.

Run `cargo test --locked -p heptabao-server` and the workspace gates from the current README. Tests cover real AEAD context/tamper rejection, canonical HTTP framing, auth TTL/usage/revocation, RFC crypto vectors, KV CAS/namespace isolation, partial batch semantics and service transaction/response-audit failure. `tests/repository/test_auth_capability_boundary_v2_6.py` additionally rejects a public raw auth module or any public `Service` signature that exposes `Principal` or `AuthState`. Run `python qa/single-node/smoke.py --binary /absolute/target/debug/heptabao-server --work-dir /new/absolute/private-directory` for a real TLS process, initialization/sealing, invalid credentials, durable finite-use denial and SIGKILL/restart recovery with ciphertext/redacted-audit checks. `qa/openbao-acceptance/acceptance.py` separately executes named KV/token/Transit cases against an independent OpenBao binary. Current results belong in `docs/plan/HEPTABAO_SINGLE_NODE_EXECUTION_STATUS.md`; commands listed here are requirements, not implied passes.

## Evolution and open boundaries

Next gates are full authentication/identity/OIDC/MFA coverage; complete PKI/SSH plus database/cloud dynamic providers and general renewable external-provider leases; record-oriented/bounded-write-amplification state ownership beyond whole-state serialization; mixed-version/membership/snapshot-install and multi-host qualification of networked Raft; replay retirement under partition, forced snapshot install and >32,000-operation long-running cycles; complete interruption-safe migration of policies, identities, keys and leases; external audit anchoring/archival and qualification of implemented compaction, providers and platforms. Any future lower-level authentication API must use an affine, non-cloneable, non-serializable request capability consumed by one dispatcher call and must receive fresh exact-head hostile replay review. Repository tests and a runnable single node do not close the remaining product gates.

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

## Optional initialization-response recovery

`POST`/`PUT sys/init` accepts optional `recovery_nonce`: 32 client-generated random bytes encoded as canonical standard base64 or lowercase hex. The initializer validates share/threshold bounds (defaults 5/3), creates the usual Shamir state and, when opted in, publishes an encrypted `init-recovery.hbe` alongside staged state. The 16 KiB, owner-only recovery object contains the original response; a key derived from the client secret and seal context protects it independently of the audit key. No recovery secret or response plaintext is stored in audit.

A matching repeat with the same secret and effective share/threshold settings returns the same original shares/root token after response loss or restart. Missing recovery credentials on an already initialized server fail closed; wrong share/threshold settings return 400, failed recovery authentication 403, absent pending recovery 409, and an in-process/on-disk seal disagreement or unavailable/uncertain durable file 503 (a changed binding discovered by decryption after restart yields 403). The response adds `init_ack_required: true`; ordinary requests without recovery credentials keep the existing compatibility profile. This extension cannot retroactively recover an older lost initialization that never supplied a client secret.

After unseal and custody verification, root-namespace `POST`/`PUT sys/init/ack` with an effective root token and `{}` removes/synchronizes the pending encrypted response. Acknowledgement returns 204 and also synchronizes the directory when the file is already absent, making an authorized retry meaningful after a lost acknowledgement. A directory-sync failure returns 503 and fences the live service; reopen/reconcile before retrying. Pending recovery blocks rekey (409) and HA startup. `GET sys/init` never exposes sensitive recovery fields. An old audit-key-dependent `.init-escrow` artifact is a migration error, not a current decryption source. See the operator runbook for the custody sequence; local encryption is not external custody or a production initialization-ceremony qualification.

Current initialization regressions in `crates/heptabao-server/src/service_tests.rs` are `initialization_recovery_survives_response_loss_and_requires_root_ack`, `initialization_recovery_rejects_tampering_wrong_seal_and_invalid_secret`, `initialization_ack_directory_sync_failure_fences_and_retry_resyncs` and `initialization_without_recovery_secret_never_creates_escrow_and_legacy_is_rejected`. They bind the local recovery/custody boundary; they do not qualify a production ceremony.

The bounded `qa/openbao-acceptance/self_init_live.py` fixture drives this
recovery path through a real TLS process. It loses the initial response across
SIGKILL, recovers the identical response with the same client nonce, applies a
declared policy/token step, acknowledges the encrypted response and revokes the
bootstrap root with its child token before a restart. This is a scoped runtime
profile for `sys/init` recovery and transient-token cleanup. Declarative profile
parsing, automatic revocation by a separate runner, namespace-aware enrollment,
independent custody and production admission remain open.

## Current per-process HA composition

The binary accepts `--ha-config /absolute/ha.json` in addition to the existing
`--config`. `Service::new_with_ha` connects `HaProcess` to one `ProcessRaftNode`
voter per process. The server crate now depends on `heptabao-ha-service` and
`heptabao-raft-runtime` as well as `heptabao-durable-service`.

The HA config requires `node_id`, `cluster_id`, `raft_dir`, `listen`, `ca_file`,
`cert_file`, `key_file`, `replication_key_file` and `peers`. Each peer supplies
`node_name`, `address`, `server_name` and `certificate_sha256`. Optional
`bootstrap`, `peer_timeout_ms` (default 750) and `max_inflight` (default 64) are
validated before entry; `listen` must use a nonzero statically enrolled port
because an ephemeral listener would not match the peer registry after restart.
The replication key is an owner-protected 32-byte file,
not a plaintext value in configuration or logs.

Authority-bearing requests cross a current-leader/ReadIndex barrier. Complete
application state is sealed once, proposed with its exact predecessor digest,
replicated and reconciled into local durable state. Standbys forward only to a
pinned mTLS peer; the receiving leader re-enters the public service dispatch
boundary rather than trusting a client-supplied principal. After-entry failures
remain uncertain; losing a response does not authorize replay of a write.

Forward request Debug exposes only source, target and bounded method; path,
namespace, token and body are redacted. Response Debug exposes direction/status
and redacts the body. Serialization staging buffers are zeroized on drop,
including oversize rejection; this does not guarantee removal of every library
or allocator copy. Every HBRT1 consensus frame and HBFQ/HBFS forwarding frame
also carries the configured cluster identity; receivers reject a validly signed
or mTLS-authenticated frame from another cluster before dispatch. Hostile Rust
tests exercise redaction, frame bounds and cross-cluster rejection.

Synthetic three-process testing is provided by
`qa/openbao-acceptance/ha_destructive.py`; replay-epoch failover extends it in
`qa/openbao-acceptance/replay_epoch_ha.py`. Both create their own private state
and TLS identities, never attach to a pre-existing deployment, and never treat a
successful stale read as acceptable eventual consistency. Their scenario receipts
are repository-controlled observations, not independent HA or release approval.

## HA bootstrap and bounded process validation

Set `cluster_id` in every HA configuration to the exact cluster identity returned
by the initialized, unsealed seed's `sys/health`. Initialization uses canonical
Base64 of sixteen random bytes; do not invent an unrelated name or rewrite an
existing durable identity. The replication codec accepts that exact canonical
encoding in addition to legacy named identities. Unseal rejects an HA/application
cluster mismatch before installing decrypted local state. Peer receiver workers
are bounded to 4–16 by `max_inflight`; only one forwarded public request may wait
for service admission, leaving receiver capacity for consensus traffic.

The process runtime uses a 200 ms heartbeat and 1000–2000 ms election timeouts;
TLS peers set TCP_NODELAY. These are bounded development settings, not a measured
production latency or availability SLO. ReadIndex remains mandatory; no cached or
lease-read success replaces quorum confirmation. The destructive fixture performs
read-only leader stabilization before fault-phase writes, never retries an
ambiguous write, and rejects a successful stale read immediately. Its synthetic
cold-cloned seed is not an implementation of production peer enrollment. Each
result binds the actual binary digest and lists uncovered fault categories.

## Core-isolation implementation supplement

The actual Service now dispatches built-in `cubbyhole/*` to the private token
owner, with encrypted state, non-inheriting issuance, ACL create/update
classification and atomic final-use clearing. Read the [Cubbyhole development
and operations contract](../engines/HEPTABAO_CUBBYHOLE.md). The matching-policy
algorithm is `src/auth_acl.rs`: highest-priority pattern selection replaces the
earlier broad/narrow permission union. Policy rollout needs explicit review.

The service-internal Identity API, login/entity binding, live internal-group
policy projection, merge algorithm, reverse indexes and remaining MFA/OIDC work
are detailed in the [current Identity runtime contract](../engines/HEPTABAO_IDENTITY_RUNTIME.md). The standalone
`heptabao-identity` guide is not a substitute for these Service-owned semantics.

Focused source tests: `auth_cubbyhole_tests.rs`, `auth_acl.rs` and
`cubbyhole_service_tests.rs`. The executable local differential entry point is
`qa/openbao-acceptance/core_isolation.py`; it compares only selected Cubbyhole
and ACL behavior against the pinned official OpenBao 2.6.2 binary. Response
wrapping, autonomous expiry, production-scale state layout, full compatibility
and independent operational qualification are not established by this increment.

## Audit target-ABI boundary

The audit rotation implementation uses the pinned `libc` target definitions for
`O_DIRECTORY`, `O_NOFOLLOW`, `O_CLOEXEC` and `O_NONBLOCK`. Linux x86_64 numeric
flags are not portable to Linux aarch64. The private-file, directory-descriptor,
symlink, permissions and nonblocking protections are retained, not disabled.
`audit_platform_tests.rs` exercises real directories and regular files, leaf and
intermediate symlinks, and group/world-writable audit roots. Run these source
tests on both Linux architectures as part of the existing all-target workspace
gate; an x86_64 run alone is not aarch64 qualification. Non-Linux durable storage
remains explicitly unsupported by this implementation profile.

## Live Identity authorization boundary

`src/service_identity.rs` composes the existing auth and engine transaction
owners. `src/auth_identity.rs` binds only a newly issued, mount-provenanced token;
`src/engine_identity.rs` reads the namespace owner; `engines/identity_runtime.rs`
resolves aliases and bounded internal-group policies. None is a public authority
constructor, new daemon, cache or independent store. After the existing HA
ReadIndex/state synchronization and finite-use commit, Service checks live
entity admission before dispatch. Login stages token, alias and entity in the
same encrypted commit; failure discards candidate grants and withholds output.

Persisted token `entity_id` and mount `accessor` are optional for legacy decoding.
Legacy tokens are not auto-enrolled. A new mount incarnation gets a new accessor;
merge redirects only by explicit lineage, never by reused display names. Entity
and group partial updates preserve omitted fields, reject unknown parameters,
and cannot recreate an explicitly supplied deleted identifier.

Live expansion is limited to 4,096 group records, 256 reached groups, depth 32
and 256 effective policy names. Root-policy injection, cycles, missing entities,
ambiguous merge lineage and capacity overflow reject authorization. Service
state size and existing transaction/audit limits still apply. The general
performance profile is not upgraded by these pilot bounds.

Run `cargo +1.98.0 test --locked -p heptabao-server --lib identity_` together with
the complete workspace and real TLS/HA suites. `identity_service_tests.rs` names
the actual caller tests. External-group membership synchronization, templated
ACLs, broader subject formats, full MFA/OIDC, migration and destructive HA
invalidation qualification are not implemented by this bounded increment.

The selected live-Identity differential runner is
`qa/openbao-acceptance/identity_live.py`. Explicit existing entity/group-ID
updates return 204/no body, matched to the pinned official OpenBao 2.6.2
behavior. This does not change all other Identity mutation response shapes.

## Identity-aware persisted state format and rollback

The Identity increment originally introduced `State.schema = 2`; the current
discriminator is 5 as defined in the [current state-format contract](../architecture/HEPTABAO_CURRENT_STATE_FORMAT.md).
Seal metadata remains schema 1, and the underlying HBS2/HBJ2/HBL2/HBA1 envelopes are unchanged. Schema
1 can be read only without the new persisted token/entity and mount-accessor
bindings. Missing optional identity fields are omitted during serialization to
preserve the legacy canonical bytes and HA base digest. Merely unsealing or
reading a valid schema-1 store does not silently write a migration.

The first committed auth/engine mutation, including finite-use consumption
before a subsequently denied request, stages the current schema with the existing atomic
state commit. A rejected precommit does not publish a schema transition. New
initialization starts at 5. Unseal, durable refresh and HA state admission all
reject unsupported versions and schema-1 records carrying identity-aware fields.
The original schema-1-only binary therefore refuses upgraded state instead of
ignoring the new identity constraints.

Rollback from current state requires a binary that understands its stored schema, compatible
provider/HA formats and the current revocation state. Never edit the discriminator, discard new fields, or restore a stale
schema-1 backup to make an old binary run. This format fence is not an external
monotonic rollback anchor and does not qualify mixed-version rolling upgrades.
`identity_upgrade.py` exercises actual legacy and new binaries through fresh
local TLS state; its receipt binds both executable digests. `identity_schema_`
source tests additionally cover unknown versions, contradictory legacy fields,
byte-preserving reads, commit promotion and finite-use denial/reopen behavior.

## Platform file-open regression boundary

Audit rotation, configuration, TLS material, seal/rekey/recovery state, audit keys
and HA material use target `libc::O_NOFOLLOW`, `O_CLOEXEC` and `O_NONBLOCK` flags
rather than Linux-x86 numeric constants. The libc dependency follows `cfg(unix)`
where Unix-only code consumes it. The whole server source is checked for numeric
`custom_flags` regressions. This static guard and x86 execution do not establish
new ARM64/macOS runtime qualification; the existing Linux-only durable-store
profile and independent platform gates remain unchanged.

## Earlier schema-4 runtime extensions

Current Service integrates [PostgreSQL](../engines/HEPTABAO_POSTGRESQL_PROVIDER.md), [remote JWT keys](../auth/HEPTABAO_REMOTE_JWT_KEYS.md), and [Raft administration](../operations/HEPTABAO_RAFT_ADMINISTRATION.md) through its existing writer. Source files `service_database.rs`, `postgres_wire.rs`, `outbound.rs`, `auth_remote.rs` and `service_raft_admin.rs` own the corresponding concrete boundaries; server package existence alone does not qualify them. Database effect intent and exact readback are durable. Remote destinations are enrolled at startup. Native membership acknowledgement requires stable committed configuration. Real PostgreSQL execution remains an exact-candidate gate, distinct from protocol models. Current online code-flow authentication is described below; full OIDC/MFA, mixed-version/forced restore and independent production acceptance remain open. These earlier fields required schema 4; current writes use the discriminator in the current state-format contract and old readers must not ignore the new state. See the linked guides for limits, configuration, state machine, failures and exact test commands.

## Current online authentication and native callback

`auth_kubernetes.rs`, `auth_oidc.rs` and `service_online_auth.rs` add actual
Service-integrated TokenReview and confidential S256 authorization-code OIDC.
Read [the complete online authentication guide](../auth/HEPTABAO_ONLINE_AUTHENTICATION.md)
for per-route fields, encrypted state, error precedence, expiry/role invalidation,
identity aliases, CA enrollment, two-commit code-exchange sequencing, owned
credential cleanup, private native-client output and actual test commands.
No separate public Principal or authentication bypass is exposed. Online login
wrapping is rejected before any issuer request or session consumption.

The current schema is defined in `HEPTABAO_CURRENT_STATE_FORMAT.md`; schema 1–4 cannot carry online method state, schema 5 cannot carry the durable PostgreSQL provider fence, schema 6 cannot carry LDAP group synchronization, and schema 7 cannot carry Kubernetes secrets-engine state.
New Kubernetes tokens renew locally against their current issuing role; online
TokenReview is per login, not continuous revocation of issued service tokens.
Legacy tokens without role provenance remain nonrenewable. OIDC sessions are at most 128 per mount and
live for 300 seconds; client proof is independent of browser-visible state.
New OIDC tokens use native role/mount leases and local renewal independently of
ID-token expiry; legacy OIDC tokens remain nonrenewable. In-flight discovery and
code exchange retain the auth mount incarnation through publication.
Config/role changes invalidate the affected sessions, and realm/client changes
require remount. Current HA uses the same durable state and ReadIndex path.

Native tests `oidc_service_commits_consumption_before_failed_egress_and_reopen_rejects_replay`,
`oidc_service_pre_entry_capacity_refusal_preserves_session_without_code_exchange`,
`oidc_service_observed_expiry_is_durable_even_on_denial` and
`oidc_service_request_audit_failure_preserves_session_and_result_failure_never_refunds_it`
anchor effect ordering. Actual executable profiles are
`kubernetes_online.py`, `oidc_code_live.py` and `online_auth_ha.py` under
`qa/openbao-acceptance/`; none changes the fixed corpus or independent authority.


## Retained capacity endpoint compatibility

The PR96 `GET sys/internal/storage/capacity` endpoint remains available alongside
`GET sys/internal/capacity`. Both remain root-token/root-namespace only and audited;
the former retains its original response shape and now reports replay-epoch
lifecycle fields, while the latter supplies the logical application-state
observation contract used by migration preflight. Neither reserves capacity.
`service_capacity_tests.rs` retains the older route's negative and replay tests.
Both durable maintenance method names delegate to the same policy, checkpointing
only after a definite pre-entry journal-capacity refusal; replay identities are
retired only through the explicit epoch transition, never by compaction or an
uncertain-effect recovery shortcut.

## Independent module closure dossier

The detailed design, boundary, failure-semantics and exact-head acceptance record is maintained in [the module closure dossier](../module-closure/heptabao-server.md).

## Valkey provider integration

`service_database.rs` also dispatches the bounded Valkey 7.2 TLS ACL provider.
`valkey_wire.rs` owns bounded RESP2 framing; the database engine retains durable
intent and validates provider readback before returning credentials.
[The Valkey guide](../engines/HEPTABAO_VALKEY_PROVIDER.md) specifies exact
command permissions, WATCH/EXEC plus durable ACL marker fencing, expiry and
restart semantics, and the remaining full-provider compatibility work.
