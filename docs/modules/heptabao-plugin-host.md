# heptabao-plugin-host

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns a fail-closed process boundary between HeptaBao and an externally installed sandbox provider, plus the repository-side issue, renew, revoke and reconciliation state machine for dynamic-secret leases. It never executes a plugin directly and does not claim that a particular operating-system sandbox, database provider or production deployment has been qualified.

## Public API and ownership

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-plugin-host`; Cargo SHA-256 `e9cfa822b4d4d47fd23fcd7046a5e4ee93559ef380a94a6ab5afc95b6106cb6f`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `struct` | `PluginMutationContext` | `crates/heptabao-plugin-host/src/durable.rs:32` | `pub struct PluginMutationContext {` |
| `fn` | `new` | `crates/heptabao-plugin-host/src/durable.rs:39` | `pub fn new(` |
| `fn` | `principal` | `crates/heptabao-plugin-host/src/durable.rs:54` | `pub fn principal(&self) -> &Id {` |
| `fn` | `request_id` | `crates/heptabao-plugin-host/src/durable.rs:58` | `pub fn request_id(&self) -> &Id {` |
| `struct` | `PendingPluginInvocation` | `crates/heptabao-plugin-host/src/durable.rs:76` | `pub struct PendingPluginInvocation {` |
| `enum` | `DurableReconciliationDecision` | `crates/heptabao-plugin-host/src/durable.rs:84` | `pub enum DurableReconciliationDecision {` |
| `struct` | `DurableDynamicSecretBroker` | `crates/heptabao-plugin-host/src/durable.rs:108` | `pub struct DurableDynamicSecretBroker<B: Barrier, R: SandboxRunner> {` |
| `fn` | `create_new` | `crates/heptabao-plugin-host/src/durable.rs:115` | `pub fn create_new(` |
| `fn` | `reopen` | `crates/heptabao-plugin-host/src/durable.rs:129` | `pub fn reopen(` |
| `fn` | `host_state` | `crates/heptabao-plugin-host/src/durable.rs:188` | `pub fn host_state(&self) -> PluginHostState {` |
| `fn` | `pending_invocation` | `crates/heptabao-plugin-host/src/durable.rs:192` | `pub fn pending_invocation(&self) -> Option<PendingPluginInvocation> {` |
| `fn` | `view` | `crates/heptabao-plugin-host/src/durable.rs:200` | `pub fn view(&mut self, lease_id: &Id, now: Tick) -> Result<DynamicLeaseView, PluginHostError> {` |
| `fn` | `issue` | `crates/heptabao-plugin-host/src/durable.rs:204` | `pub fn issue(` |
| `fn` | `renew` | `crates/heptabao-plugin-host/src/durable.rs:261` | `pub fn renew(` |
| `fn` | `revoke` | `crates/heptabao-plugin-host/src/durable.rs:323` | `pub fn revoke(` |
| `fn` | `reconcile` | `crates/heptabao-plugin-host/src/durable.rs:383` | `pub fn reconcile(` |
| `use` | `durable::{` | `crates/heptabao-plugin-host/src/lib.rs:27` | `pub use durable::{` |
| `enum` | `PluginOperation` | `crates/heptabao-plugin-host/src/lib.rs:42` | `pub enum PluginOperation {` |
| `struct` | `PluginLimits` | `crates/heptabao-plugin-host/src/lib.rs:73` | `pub struct PluginLimits {` |
| `fn` | `validate` | `crates/heptabao-plugin-host/src/lib.rs:80` | `pub fn validate(self) -> Result<Self, PluginHostError> {` |
| `struct` | `SandboxBinding` | `crates/heptabao-plugin-host/src/lib.rs:94` | `pub struct SandboxBinding {` |
| `fn` | `new` | `crates/heptabao-plugin-host/src/lib.rs:102` | `pub fn new(` |
| `struct` | `PluginManifest` | `crates/heptabao-plugin-host/src/lib.rs:121` | `pub struct PluginManifest {` |
| `fn` | `new` | `crates/heptabao-plugin-host/src/lib.rs:130` | `pub fn new(` |
| `fn` | `descriptor` | `crates/heptabao-plugin-host/src/lib.rs:159` | `pub fn descriptor(&self) -> &PluginDescriptor {` |
| `fn` | `sandbox` | `crates/heptabao-plugin-host/src/lib.rs:163` | `pub fn sandbox(&self) -> &SandboxBinding {` |
| `const` | `fn` | `crates/heptabao-plugin-host/src/lib.rs:167` | `pub const fn limits(&self) -> PluginLimits {` |
| `fn` | `operations` | `crates/heptabao-plugin-host/src/lib.rs:171` | `pub fn operations(&self) -> &BTreeSet<PluginOperation> {` |
| `fn` | `environment_allowlist` | `crates/heptabao-plugin-host/src/lib.rs:175` | `pub fn environment_allowlist(&self) -> &BTreeSet<String> {` |
| `struct` | `SecretEnvironment` | `crates/heptabao-plugin-host/src/lib.rs:192` | `pub struct SecretEnvironment {` |
| `fn` | `new` | `crates/heptabao-plugin-host/src/lib.rs:197` | `pub fn new() -> Self {` |
| `fn` | `insert` | `crates/heptabao-plugin-host/src/lib.rs:203` | `pub fn insert(&mut self, name: &str, value: String) -> Result<(), PluginHostError> {` |
| `enum` | `SandboxFailure` | `crates/heptabao-plugin-host/src/lib.rs:240` | `pub enum SandboxFailure {` |
| `trait` | `SandboxRunner` | `crates/heptabao-plugin-host/src/lib.rs:245` | `pub trait SandboxRunner: fmt::Debug {` |
| `struct` | `CommandSandboxRunner` | `crates/heptabao-plugin-host/src/lib.rs:258` | `pub struct CommandSandboxRunner;` |
| `enum` | `PluginHostState` | `crates/heptabao-plugin-host/src/lib.rs:500` | `pub enum PluginHostState {` |
| `enum` | `ReconciliationProof` | `crates/heptabao-plugin-host/src/lib.rs:507` | `pub enum ReconciliationProof {` |
| `struct` | `PluginHost` | `crates/heptabao-plugin-host/src/lib.rs:513` | `pub struct PluginHost<R: SandboxRunner> {` |
| `fn` | `admit` | `crates/heptabao-plugin-host/src/lib.rs:520` | `pub fn admit(manifest: PluginManifest, runner: R) -> Result<Self, PluginHostError> {` |
| `const` | `fn` | `crates/heptabao-plugin-host/src/lib.rs:531` | `pub const fn state(&self) -> PluginHostState {` |
| `fn` | `manifest` | `crates/heptabao-plugin-host/src/lib.rs:535` | `pub fn manifest(&self) -> &PluginManifest {` |
| `fn` | `invoke` | `crates/heptabao-plugin-host/src/lib.rs:539` | `pub fn invoke(` |
| `fn` | `reconcile` | `crates/heptabao-plugin-host/src/lib.rs:583` | `pub fn reconcile(&mut self, proof: ReconciliationProof) -> Result<(), PluginHostError> {` |
| `fn` | `revoke` | `crates/heptabao-plugin-host/src/lib.rs:598` | `pub fn revoke(&mut self) {` |
| `enum` | `DynamicLeaseState` | `crates/heptabao-plugin-host/src/lib.rs:604` | `pub enum DynamicLeaseState {` |
| `struct` | `DynamicLeaseSpec` | `crates/heptabao-plugin-host/src/lib.rs:612` | `pub struct DynamicLeaseSpec {` |
| `struct` | `DynamicLeaseView` | `crates/heptabao-plugin-host/src/lib.rs:622` | `pub struct DynamicLeaseView {` |
| `struct` | `DynamicSecretIssue` | `crates/heptabao-plugin-host/src/lib.rs:640` | `pub struct DynamicSecretIssue {` |
| `struct` | `DynamicSecretBroker` | `crates/heptabao-plugin-host/src/lib.rs:646` | `pub struct DynamicSecretBroker<R: SandboxRunner> {` |
| `fn` | `new` | `crates/heptabao-plugin-host/src/lib.rs:652` | `pub fn new(host: PluginHost<R>) -> Result<Self, PluginHostError> {` |
| `fn` | `host_state` | `crates/heptabao-plugin-host/src/lib.rs:670` | `pub fn host_state(&self) -> PluginHostState {` |
| `fn` | `issue` | `crates/heptabao-plugin-host/src/lib.rs:674` | `pub fn issue(` |
| `fn` | `view` | `crates/heptabao-plugin-host/src/lib.rs:713` | `pub fn view(&mut self, lease_id: &Id, now: Tick) -> Result<DynamicLeaseView, PluginHostError> {` |
| `fn` | `renew` | `crates/heptabao-plugin-host/src/lib.rs:729` | `pub fn renew(` |
| `fn` | `revoke` | `crates/heptabao-plugin-host/src/lib.rs:774` | `pub fn revoke(` |
| `fn` | `reconcile_host` | `crates/heptabao-plugin-host/src/lib.rs:816` | `pub fn reconcile_host(` |
| `enum` | `PluginHostError` | `crates/heptabao-plugin-host/src/lib.rs:885` | `pub enum PluginHostError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

The host is `Active`, `ReconciliationRequired` or `Revoked`. A dynamic lease is `Active`, `Expired`, `Revoked` or `ReconciliationRequired`, and carries owner, canonical scope, issuance and expiry ticks, renewable flag, generation and a SHA-256 digest of the last returned secret. `HBDI` records contain only operation, lease metadata, previous projection and a request digest; `HBDL` records contain only the bounded lease projection. Both cross the injected authenticated Barrier through the durable service. Secret request and response bytes are held in `SecretValue` or `Zeroizing` buffers and are never stored in either record.

## Invariants and authorization

Only operations declared by the enabled descriptor and manifest can cross the boundary. Authentication and audit plugins cannot request dynamic-secret operations. The host verifies the wrapper and plugin files against their bound SHA-256 digests before entry, rejects symlinked/non-regular/unbounded executables, clears inherited environment state and passes only allowlisted names. A composition root must authorize manifest creation before calling this package.

## Failure, retry and reconciliation

Failure before process entry is retry-classifiable only after the durable invocation intent has itself been durably removed. Any failure after request publication, timeout, non-success exit, malformed response, over-bound response, lease-publication failure or intent-clear failure fences the host as outcome-unknown. The pending `HBDI` survives restart and blocks every later call. Reconciliation revalidates both executable bindings, validates an authoritative provider decision, durably publishes or restores the lease projection, durably clears the intent and only then reactivates the host. Repository code cannot manufacture provider readback.

## Concurrency and ordering

`PluginHost`, `DynamicSecretBroker` and `DurableDynamicSecretBroker` require exclusive mutable access and contain no interior synchronization. Exactly one durable plugin invocation may be pending; a second operation is rejected rather than queued. Ordering is durable intent → sandbox entry → bounded response → encrypted lease publication → encrypted intent deletion → plaintext release. Reconciliation uses the same single-writer ordering.

## Security and privacy

The concrete runner invokes only the sandbox wrapper and supplies the plugin path as a descriptor-bound argument. Standard input and output use bounded binary frames, standard error is discarded, inherited environment variables are cleared, and `Debug` output redacts environment values and secret payloads. File digests are integrity bindings, not code signatures; signer trust, sandbox isolation and provider credentials remain external qualification boundaries.

## Persistence and compatibility

The process wire format is versioned by the descriptor. Requests use `HBP1`, protocol version, operation tag, payload length and payload; responses use `HBR1`, payload length and payload, with exact-length validation and no trailing bytes. Durable records use strict `HBDI` and `HBDL` version 1 encodings with exact-length and trailing-byte rejection. The existing durable service owns snapshot, journal, replay ledger, writer fencing and Barrier authentication; this package owns the plugin-specific intent and lease semantics layered on it.

## Observability

Safe events are `plugin.admitted`, `plugin.before_entry_failure`, `plugin.outcome_unknown`, `plugin.reconciled`, `plugin.revoked`, `dynamic_lease.issued`, `dynamic_lease.renewed` and `dynamic_lease.revoked`. Labels may include descriptor ID, generation, operation and bounded outcome class, but never command-line secrets, environment values, request bodies, response bodies or secret digests.

## Operations

Operators install the plugin executable and sandbox wrapper outside the repository, set owner-controlled non-writable permissions, calculate reviewed SHA-256 values and register the exact manifest. Rotation requires disabling admission, draining or reconciling outstanding calls, replacing both files, publishing a new descriptor generation and re-running destructive timeout, crash and revocation qualification.

## Tests and executable evidence

`cargo +1.98.0 test -p heptabao-plugin-host` covers undeclared operations and environment names, pre-entry versus post-entry failure, mandatory reconciliation, monotonic dynamic lease issue/renew/revoke, durable intent recovery, encrypted lease reopen, capacity failure after process entry, plaintext withholding and secret-redacted debug output. On Unix, `command_runner_uses_the_verified_wrapper_and_bounded_frame` launches a real checksum-pinned wrapper process, verifies inherited environment clearing and round-trips the bounded `HBP1`/`HBR1` frame.

## Evolution and open boundaries

Repository-controlled durable invocation and lease journaling are implemented and remain review-required. External work includes independently qualified Linux/macOS/Windows sandbox providers, process-tree termination guarantees, authenticated multiplexed transport, server routing, real database and cloud provider connectors, rolling plugin upgrades and destructive provider qualification. Those observations are tracked as external completion and this package alone grants no production or dynamic-secret authority.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-plugin-host`
- Crate path: `crates/heptabao-plugin-host`
- Cargo manifest SHA-256: `e9cfa822b4d4d47fd23fcd7046a5e4ee93559ef380a94a6ab5afc95b6106cb6f`
- Rust source files: `2`
- Public lexical declarations: `57`
- Discovered test functions: `9`
- Workspace-internal dependencies: `heptabao-domain` (dependencies), `heptabao-durable-service` (dependencies), `heptabao-plugin-contracts` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
