# heptabao-runtime-service

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Current plan: `HEPTABAO-PLAN-2026-09-07-V2.1`. Shared rules live in `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This crate provides an admission adapter whose own mutation/read/list entrypoints require authentication, authorization and audit before private durable-service access. The current native server uses a separate composition. It authenticates, authorizes, records accepted-before-entry audit evidence, constructs the immutable durable envelope and classifies the result. It does not implement a network listener, credential protocol, persistent identity database, production audit provider or KMS/HSM.

## Public API and ownership

### Current API contract and integration boundary

`RuntimeService<A, Z, U, B>::new(authenticator, authorizer, audit, durable)` takes exclusive ownership of an `Authenticator`, `Authorizer`, `AuditSink` and `DurableService<B>`. Its durable writer is private and has no mutable accessor. This makes admission mandatory for calls through this adapter; it does not prevent other assemblies from using `DurableService` directly.

`Credential::new(Vec<u8>)` accepts 1 byte through 16 KiB, owns and zeroizes the buffer, and lends it through `expose()`. `InboundMutation::new(credential, namespace, request_id, resource, InboundOperation)` owns either Put(Secret) or Delete and checks nonempty ASCII fields of at most 4096 bytes. This preliminary validation does not enforce the durable namespace/path grammar; envelope construction later performs that stricter validation. `AuthenticatedPrincipal::new` restricts principal syntax/length to the durable 256-byte identifier grammar; `AuthorizationDigest::new` rejects an all-zero digest.

`Authenticator::authenticate(&Credential)` must establish the principal from live credentials. `Authorizer::authorize(&principal, namespace, resource, OperationKind)` must enforce the actual policy and return a decision digest; the adapter does not create that policy evidence. `AuditSink::append(&AuditEvent)` must return success only under the sink's declared durability contract. Audit events expose stage, binary request fingerprint and optional generation, without request or secret bytes. The fingerprint binds principal, namespace, request ID, resource, operation and authorization digest; it does not include the Put value digest (the durable operation binding does).

`handle(InboundMutation)` and `handle_with_failpoint` validate, authenticate, authorize and append `AcceptedBeforeEntry` before durable dispatch. A pre-entry audit failure returns `AuditUnavailableBeforeEntry` without a storage identity. Success/duplicate gets a second audit event; failure there returns `OutcomeUnknown` with the committed recovery reference and does not itself poison an otherwise healthy durable writer. A durable after-entry fault retains uncertainty and may require reopen. Errors distinguish invalid input, authentication/authorization denial, unavailable audit, recovery required, durable rejection and durable corruption.

`read(&credential, namespace, resource, request_id)` and `list(&credential, namespace, prefix, request_id)` use the same admission sequence, then require result audit before releasing a secret or key list. An empty list prefix is namespace-root access and is passed explicitly to the authorizer. `reconcile(reference)`, `generation`, `retained_request_count` and `recovery_required` expose read-only durable status without authentication arguments; a network/operator adapter must separately restrict them.

This is a functional candidate admission adapter **outside the current server dependency closure**. `heptabao-server` has its own native admission/audit composition and owns `DurableService` directly; its behavior cannot be inferred from this crate's tests. Integration would require real authentication/policy/audit adapters, transport mappings and tests of that concrete assembly.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-runtime-service`; Cargo SHA-256 `c8321f283c18f1bdb47e88910d8d0ac052f62eb247b785b6076e81ad6878f927`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `struct` | `Credential` | `crates/heptabao-runtime-service/src/lib.rs:24` | `pub struct Credential(Vec<u8>);` |
| `fn` | `new` | `crates/heptabao-runtime-service/src/lib.rs:33` | `pub fn new(bytes: Vec<u8>) -> Result<Self, RuntimeError> {` |
| `fn` | `expose` | `crates/heptabao-runtime-service/src/lib.rs:41` | `pub fn expose(&self) -> &[u8] {` |
| `enum` | `OperationKind` | `crates/heptabao-runtime-service/src/lib.rs:53` | `pub enum OperationKind {` |
| `enum` | `InboundOperation` | `crates/heptabao-runtime-service/src/lib.rs:61` | `pub enum InboundOperation {` |
| `const` | `fn` | `crates/heptabao-runtime-service/src/lib.rs:68` | `pub const fn kind(&self) -> OperationKind {` |
| `struct` | `InboundMutation` | `crates/heptabao-runtime-service/src/lib.rs:86` | `pub struct InboundMutation {` |
| `fn` | `new` | `crates/heptabao-runtime-service/src/lib.rs:95` | `pub fn new(` |
| `struct` | `AuthenticatedPrincipal` | `crates/heptabao-runtime-service/src/lib.rs:135` | `pub struct AuthenticatedPrincipal(String);` |
| `fn` | `new` | `crates/heptabao-runtime-service/src/lib.rs:138` | `pub fn new(value: impl Into<String>) -> Result<Self, RuntimeError> {` |
| `fn` | `as_str` | `crates/heptabao-runtime-service/src/lib.rs:145` | `pub fn as_str(&self) -> &str {` |
| `struct` | `AuthorizationDigest` | `crates/heptabao-runtime-service/src/lib.rs:157` | `pub struct AuthorizationDigest([u8; 32]);` |
| `fn` | `new` | `crates/heptabao-runtime-service/src/lib.rs:160` | `pub fn new(value: [u8; 32]) -> Result<Self, RuntimeError> {` |
| `const` | `fn` | `crates/heptabao-runtime-service/src/lib.rs:168` | `pub const fn into_inner(self) -> [u8; 32] {` |
| `trait` | `Authenticator` | `crates/heptabao-runtime-service/src/lib.rs:179` | `pub trait Authenticator {` |
| `trait` | `Authorizer` | `crates/heptabao-runtime-service/src/lib.rs:186` | `pub trait Authorizer {` |
| `struct` | `AuthenticationFailure` | `crates/heptabao-runtime-service/src/lib.rs:197` | `pub struct AuthenticationFailure;` |
| `struct` | `AuthorizationFailure` | `crates/heptabao-runtime-service/src/lib.rs:200` | `pub struct AuthorizationFailure;` |
| `struct` | `AuditFailure` | `crates/heptabao-runtime-service/src/lib.rs:203` | `pub struct AuditFailure;` |
| `enum` | `AuditStage` | `crates/heptabao-runtime-service/src/lib.rs:206` | `pub enum AuditStage {` |
| `struct` | `AuditEvent` | `crates/heptabao-runtime-service/src/lib.rs:216` | `pub struct AuditEvent {` |
| `const` | `fn` | `crates/heptabao-runtime-service/src/lib.rs:225` | `pub const fn request_fingerprint(&self) -> &[u8; 32] {` |
| `const` | `fn` | `crates/heptabao-runtime-service/src/lib.rs:230` | `pub const fn stage(&self) -> AuditStage {` |
| `const` | `fn` | `crates/heptabao-runtime-service/src/lib.rs:235` | `pub const fn generation(&self) -> Option<u64> {` |
| `trait` | `AuditSink` | `crates/heptabao-runtime-service/src/lib.rs:251` | `pub trait AuditSink {` |
| `enum` | `RuntimeOutcome` | `crates/heptabao-runtime-service/src/lib.rs:256` | `pub enum RuntimeOutcome {` |
| `enum` | `RuntimeError` | `crates/heptabao-runtime-service/src/lib.rs:268` | `pub enum RuntimeError {` |
| `struct` | `RuntimeService` | `crates/heptabao-runtime-service/src/lib.rs:308` | `pub struct RuntimeService<A, Z, U, B>` |
| `const` | `fn` | `crates/heptabao-runtime-service/src/lib.rs:344` | `pub const fn new(` |
| `fn` | `handle` | `crates/heptabao-runtime-service/src/lib.rs:358` | `pub fn handle(&mut self, request: InboundMutation) -> Result<RuntimeOutcome, RuntimeError> {` |
| `fn` | `handle_with_failpoint` | `crates/heptabao-runtime-service/src/lib.rs:362` | `pub fn handle_with_failpoint(` |
| `fn` | `read` | `crates/heptabao-runtime-service/src/lib.rs:482` | `pub fn read(` |
| `fn` | `list` | `crates/heptabao-runtime-service/src/lib.rs:510` | `pub fn list(` |
| `const` | `fn` | `crates/heptabao-runtime-service/src/lib.rs:579` | `pub const fn recovery_required(&self) -> bool {` |
| `fn` | `reconcile` | `crates/heptabao-runtime-service/src/lib.rs:584` | `pub fn reconcile(&self, recovery_reference: &str) -> ReconciliationStatus {` |
| `const` | `fn` | `crates/heptabao-runtime-service/src/lib.rs:589` | `pub const fn generation(&self) -> u64 {` |
| `fn` | `retained_request_count` | `crates/heptabao-runtime-service/src/lib.rs:594` | `pub fn retained_request_count(&self) -> usize {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

The adapter itself has no separate persisted database. It derives one request fingerprint and one authorization digest from authenticated, canonical inputs, then transfers principal, namespace, request ID, resource, operation and value into the durable envelope. Audit events carry only stage, fingerprint and optional generation. `AuditEvent::request_fingerprint()` returns the 32-byte correlation value for controlled durable audit serialization while Debug remains redacted; durable request identity is allocated only after admission succeeds.

## Invariants and authorization

Authentication precedes authorization; authorization binds principal, namespace, resource and operation. `AcceptedBeforeEntry` audit must succeed before durable dispatch. Inbound values cannot replace the derived identity or decision digest. Invalid credentials, denied policy, malformed inputs and pre-entry audit failure allocate no replay identity and produce no state generation. Reads/listing release their results only after `ReadCompleted`/`ListCompleted` audit succeeds; otherwise `AuditUnavailableAfterRead` returns no secret. Listing an empty prefix requests namespace-root access and must be explicitly authorized by the assembly.

## Failure, retry and reconciliation

Pre-entry failures are definite and may be retried only after correcting their cause. Once durable entry may have happened, including real append, snapshot or ledger I/O failure, the result is `OutcomeUnknown` with a service-generated recovery reference: never blind retry. The durable service converts these failures before this adapter maps errors. A poisoned live writer rejects later mutation/read/list as `RecoveryRequired` until reopening; this is distinct from a deterministic input rejection. A post-commit audit failure also returns outcome unknown rather than falsely acknowledging success. Reconciliation reports committed, aborted or unknown; an exact committed resubmission is a duplicate, not a second effect.

## Concurrency and ordering

The adapter uses the durable service's exclusive mutable ownership and writer fence. The fixed order is request validation, authenticate, authorize, accepted-before-entry audit, durable envelope construction, durable dispatch, result audit and response. There is no replay identity allocated before admission. Cancellation between durable dispatch and response is treated as post-entry uncertainty.

## Security and privacy

Request fingerprints and decision bindings use domain-separated SHA-256 with explicit length prefixes. The digest is not a signature and cannot replace a trusted policy engine, audit authenticator or Barrier. `Credential`, principal, authorization digest, namespace, request ID, resource, secret operation and audit fingerprint have redacted Debug implementations. Error display never includes secret or identity bytes. Owned credential buffers and durable `Secret` values zeroize on drop; this does not claim locked memory or erasure of all provider/compiler copies.

## Persistence and compatibility

Persistence belongs to `heptabao-durable-service`; this crate must not introduce a second write path. The injected Barrier protects durable state below the adapter. Compatibility is not inferred from matching function names: request, response, error and side-effect behavior require the independent compatibility/Oracle process. Any adapter format or API change must preserve exact request binding and recovery semantics.

## Observability

Safe metrics are authentication denied, authorization denied, pre-entry audit unavailable, durable committed, duplicate, outcome unknown, durable rejected and durable corrupt. High-cardinality identities and secret-bearing fields are forbidden labels. Operators correlate an outcome only through controlled recovery-reference lookup, not by logging the reference or credential in general telemetry.

## Operations

Assembly must construct exactly one durable root in a sealed composition boundary, install a production authenticator/authorizer/audit provider, and prevent unrelated code from constructing a bypass writer. On post-entry failure, withhold normal success and direct the authenticated operator to reconciliation. On audit or durable corruption, stop admission and preserve evidence.

## Tests and executable evidence

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::invalid_credential_cannot_allocate_durable_request_identity`](../../crates/heptabao-runtime-service/src/lib.rs) checks invalid authentication leaves generation and replay count unchanged.
- [`tests::pre_entry_audit_failure_prevents_durable_dispatch`](../../crates/heptabao-runtime-service/src/lib.rs) checks the first audit failure prevents storage entry.
- [`tests::post_commit_audit_failure_is_reconcile_only`](../../crates/heptabao-runtime-service/src/lib.rs) checks postcommit audit loss reports uncertainty while readback proves the commit and replay is duplicate.
- [`tests::actual_io_failure_is_never_mapped_to_rejection`](../../crates/heptabao-runtime-service/src/lib.rs) checks actual ledger-publication I/O failure remains unknown and recoverable.
- [`tests::read_and_list_require_admission_and_result_audit`](../../crates/heptabao-runtime-service/src/lib.rs) checks query authorization and withholds a read result when result audit fails.

Run `cargo test -p heptabao-runtime-service`. Rust tests inject an actual post-publication ledger EISDIR error and verify preserved outcome reference, unknown audit event, blocked read and committed reopen reconciliation. Read/list tests verify authentication, authorization, fingerprint serialization and result-audit denial without releasing secret bytes. Existing tests prove invalid credentials and denied policy cannot preempt request identity, principal scoping holds, pre-entry audit failure prevents dispatch, post-commit audit failure is reconcile-only, durable unknown survives restart, exact replay is duplicate and Debug is redacted. Repository tests bind mandatory ordering, private ownership, truth files, read-only CI and the SHA-256 boundary.

## Evolution and open boundaries

Repository completion requires current exact-head/prospective-main-merge success and independent review. Production completion needs persistent identity and token administration, MFA/auth methods, append-only authenticated audit, TLS/HTTP transport, operator lookup authorization, concrete Barrier/KMS custody, destructive fault evidence, HA, compatibility admission, incident operations and release authority.

```text
qualification: false
compatibility_claim: false
production_authority: false
migration_authority: false
release_authority: false
authority_effect: NONE
```

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-runtime-service`
- Crate path: `crates/heptabao-runtime-service`
- Cargo manifest SHA-256: `c8321f283c18f1bdb47e88910d8d0ac052f62eb247b785b6076e81ad6878f927`
- Rust source files: `1`
- Public lexical declarations: `37`
- Discovered test functions: `9`
- Workspace-internal dependencies: `heptabao-durable-service` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
