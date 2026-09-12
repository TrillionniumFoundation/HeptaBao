# heptabao-plugin-host

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns a fail-closed process boundary between HeptaBao and an externally installed sandbox provider, plus the repository-side issue, renew, revoke and reconciliation state machine for dynamic-secret leases. It never executes a plugin directly and does not claim that a particular operating-system sandbox, database provider or production deployment has been qualified.

## Public API and ownership

### Current API contract and integration boundary

`PluginManifest::new(descriptor, sandbox, limits, operations, environment_allowlist)` owns an enabled descriptor, sandbox-wrapper metadata, declared operations and environment names. `PluginLimits::validate` permits 1 byte–1 MiB request/response payloads and 1–60,000 ms timeout; there are at most 64 environment entries, with at most 16 KiB per nonempty value. `SecretEnvironment::insert` owns zeroizing values and can replace an existing name; the host additionally requires every supplied name be declared. Authentication plugins allow only Read/Write and audit plugins only Write; Secrets/Database may declare dynamic operations.

`SandboxRunner::admit(&manifest)` and `invoke(&manifest, operation, &request, &environment)` define provider validation and the before-entry/unknown result boundary. `PluginHost::admit` owns manifest and runner. `PluginHost::invoke` rejects undeclared operations, size/environment violations and revoked/fenced state before delegating; provider uncertainty or an oversized successful response fences future calls. `reconcile(ReconciliationProof)` rechecks runner admission and accepts a caller-supplied no-effect/nonzero completed digest; it does not independently obtain provider evidence. `revoke()` is terminal host admission state, not external credential revocation.

`CommandSandboxRunner` is a Linux wrapper-process adapter implemented in `src/command_runner.rs`. Admission opens owner-controlled regular files through no-follow directory descriptors, copies each bounded executable (at most 64 MiB) into an executable memfd while hashing, checks the manifest SHA-256, and seals the snapshot against write/grow/shrink and execution-mode changes. Invocation launches the wrapper's sealed descriptor path and passes the plugin's sealed descriptor path, retaining both parent-owned descriptors for the invocation. The sandbox wrapper must open the supplied proc descriptor before changing proc mounts or credentials in a way that removes access; it must not resolve the original manifest pathname again. Replacing or modifying the original installed paths after snapshot creation cannot substitute different executed bytes. It requires kernel executable-memfd/sealing support and usable proc descriptor paths; unsupported environments fail before entry rather than falling back to path execution.

The process deadline starts before spawn and covers the nonblocking stdin/stdout loop and process-status observation. The runner clears inherited environment, writes `HBP1`, bounds `HBR1` output and requires exact response framing plus successful parent exit. Full-duplex polling allows output before the provider consumes all stdin. Timeout, oversized output and uncertain after-entry failures do not perform a blocking reader-thread join; process-group cleanup and nonblocking exit observation keep inherited pipes from extending that I/O deadline. Admission of owner-installed files, hashing/copying and kernel process creation are separate synchronous system operations, not an independently qualified total invocation latency bound.

Cleanup targets the process group; a descendant that escapes via a new session still cannot extend the caller's pipe deadline, but containment and removal of escaped processes belong to the external sandbox. Executable checksum binding does not authenticate scripts' interpreters, shared libraries or sandbox policy and is not a code signature. This runner supplies bounded process/framing mechanics, not a qualified operating-system security sandbox.

`DynamicSecretBroker::new(host)` requires Issue and Revoke operations. `issue(DynamicLeaseSpec, &request, &environment)` binds lease ID/generation to the provider request, validates TTL in 1..=31,622,400 ticks and returns an owned plaintext secret plus metadata; the broker retains only its digest. `view(id, now)` lazily marks expired state in memory. `renew` requires active/renewable state, invokes the provider and returns metadata with a new expiry/digest; it does not return renewed secret bytes. `revoke` requires Active; an already Expired local record cannot take this path. `reconcile_host` updates a recorded uncertain lease using supplied evidence; these memory methods are not restart-safe and there is no automatic expiry scheduler/provider revocation.

`DurableDynamicSecretBroker::create_new/reopen(root, barrier, broker, max_retained_requests)` owns a durable writer plus the broker, persists strict `HBDI` intent/`HBDL` lease records, and permits one pending invocation. `PluginMutationContext::new(principal, request_id, nonzero_authorization_digest)` records an already authorized context; it performs no policy check. Durable `issue`, `renew` and `revoke` borrow that context and perform intent publication, provider call, lease publication and intent deletion before success/plaintext release. Each phase consumes durable request-ledger capacity; a single successful invocation normally uses three retained storage mutations, so capacity planning must reserve completion/reconciliation space.

`pending_invocation()` returns a safe projection; `reopen` detects persisted intent and fences the host. `reconcile(&context, DurableReconciliationDecision)` revalidates runner admission, checks a completed lease against the exact pending ID/owner/scope/generation/expiry/digest or restores the previous no-effect projection, persists the result and clears intent before activation. The caller must supply authenticated provider readback and fresh operation context. Known `ProcessBeforeEntry` clears the durable intent; other validation errors after intent publication can leave it pending, so callers must inspect pending state rather than assume every pre-process rejection is automatically retryable. `view` still performs lazy in-memory expiry and does not itself publish an expiry transition.

These process and durable broker implementations are **outside the current server dependency closure**. The current server has no generic plugin-success or database credential backend route and does not invoke this host. The `HBP1`/`HBR1` protocol is repository-defined, not OpenBao's plugin gRPC ABI, and the wrapper test below establishes process/framing behavior rather than a real database connector or qualified sandbox.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

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

The host is `Active`, `ReconciliationRequired` or `Revoked`. A dynamic lease is `Active`, `Expired`, `Revoked` or `ReconciliationRequired`, and carries owner, canonical scope, issuance and expiry ticks, renewable flag, generation and a SHA-256 digest of the last returned secret. `HBDI` records contain only operation, lease metadata, previous projection and a request digest; `HBDL` records contain only the bounded lease projection. Both cross the injected authenticated Barrier through the durable service. Neither durable record stores secret request/response bytes. Main request and response types use `SecretValue` or `Zeroizing`; temporary buffers such as response framing and request-digest material are not all zeroizing, so the implementation does not guarantee complete transient-copy erasure.

## Invariants and authorization

Only operations declared by the enabled descriptor and manifest can cross the boundary. Authentication and audit plugins cannot request dynamic-secret operations. The concrete command runner verifies wrapper/plugin files against their bound SHA-256 digests before immutable descriptor-bound execution, rejects symlinked/non-regular/unbounded executables, clears inherited environment state and passes only allowlisted names. Custom `SandboxRunner` implementations must enforce their own admission contract. A composition root must authorize manifest creation before calling this package.

## Failure, retry and reconciliation

Failure before process entry is retry-classifiable only after the durable invocation intent has itself been durably removed. Provider uncertainty, non-success exit, malformed/over-bound response, lease-publication failure or intent-clear failure requires reconciliation and withholds normal success. Timeout enforcement uses the nonblocking pipe/process deadline described above; kernel/admission latency and escaped-process containment remain external bounds. A known local validation error after intent publication can leave the durable intent pending even if host state remains Active. The pending `HBDI` survives restart and blocks every later call. Reconciliation revalidates both executable bindings, validates an authoritative provider decision, durably publishes or restores the lease projection, durably clears the intent and only then reactivates the host. Repository code cannot manufacture provider readback.

## Concurrency and ordering

`PluginHost`, `DynamicSecretBroker` and `DurableDynamicSecretBroker` require exclusive mutable access and contain no interior synchronization. Exactly one durable plugin invocation may be pending; a second operation is rejected rather than queued. Ordering is durable intent → sandbox entry → bounded response → encrypted lease publication → encrypted intent deletion → plaintext release. Reconciliation uses the same single-writer ordering.

## Security and privacy

The concrete Linux runner invokes sealed snapshots of the verified wrapper and plugin through retained descriptors. Installed paths remain an admission input, while immutable snapshots bind the execution bytes. Standard input/output use bounded binary frames, stderr is discarded, inherited environment is cleared, and Debug redacts environment values/payloads. Descriptors are resolved against the process identity visible to the proc mount, including PID-namespace deployments. File digests are integrity bindings, not code signatures; signer trust, interpreter/library trust, sandbox isolation and provider credentials remain external qualification boundaries.

## Persistence and compatibility

The process wire format is versioned by the descriptor. Requests use `HBP1`, protocol version, operation tag, payload length and payload; responses use `HBR1`, payload length and payload, with exact-length validation and no trailing bytes. Durable records use strict `HBDI` and `HBDL` version 1 encodings with exact-length and trailing-byte rejection. The existing durable service owns snapshot, journal, replay ledger, writer fencing and Barrier authentication; this package owns the plugin-specific intent and lease semantics layered on it.

## Observability

This crate does not emit an event sink or metrics exporter. Proposed integration event names are `plugin.admitted`, `plugin.before_entry_failure`, `plugin.outcome_unknown`, `plugin.reconciled`, `plugin.revoked`, `dynamic_lease.issued`, `dynamic_lease.renewed` and `dynamic_lease.revoked`. Labels may include descriptor ID, generation, operation and bounded outcome class, but never command-line secrets, environment values, request bodies, response bodies or secret digests.

## Operations

Operators install the plugin executable and sandbox wrapper outside the repository, set owner-controlled non-writable permissions, calculate reviewed SHA-256 values and register the exact manifest. Rotation requires disabling admission, draining or reconciling outstanding calls, replacing both files, publishing a new descriptor generation and re-running destructive timeout, crash and revocation qualification.

## Tests and executable evidence

Current Linux runner scenarios in `crates/heptabao-plugin-host/src/command_runner_tests.rs`:

- `blocked_stdin_obeys_deadline_before_any_output` and `full_duplex_io_does_not_deadlock_when_provider_writes_before_reading` exercise both pipe directions.
- `successful_parent_cannot_leave_stdout_join_blocked_on_descendant` and `timed_out_parent_and_descendant_do_not_block_cleanup` exercise inherited stdout and process cleanup.
- `escaped_descendant_cannot_extend_io_deadline` checks the caller returns even when a descendant changes session; it does not qualify containment.
- `verified_snapshots_execute_after_both_original_paths_are_replaced` and `verified_snapshots_survive_in_place_mutation_and_reject_writes` verify immutable execution bindings.
- `changed_checksum_or_symlink_path_fails_before_entry` and `oversized_stdout_fails_without_waiting_for_process_exit` exercise hostile admission/output.

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::undeclared_environment_and_operation_fail_before_entry`](../../crates/heptabao-plugin-host/src/lib.rs) checks undeclared inputs reject without fencing an active host.
- [`tests::outcome_unknown_fences_until_explicit_reconciliation`](../../crates/heptabao-plugin-host/src/lib.rs) checks process uncertainty blocks later calls until caller-supplied reconciliation.
- [`tests::command_runner_uses_the_verified_wrapper_and_bounded_frame`](../../crates/heptabao-plugin-host/src/lib.rs) executes a checksum-pinned wrapper and checks environment clearing and HBP1/HBR1 framing; the dedicated Linux regressions below separately check snapshot binding and pipe deadlines.
- [`durable::tests::issued_secret_is_released_only_after_durable_metadata_and_survives_reopen`](../../crates/heptabao-plugin-host/src/durable.rs) checks lease metadata persists and returned plaintext is absent from stored files.
- [`durable::tests::unknown_effect_persists_intent_and_fences_restart_until_readback`](../../crates/heptabao-plugin-host/src/durable.rs) checks a persisted unknown intent blocks restarted admission.
- [`durable::tests::durable_failure_after_plugin_entry_withholds_secret_and_retains_intent`](../../crates/heptabao-plugin-host/src/durable.rs) checks post-provider storage capacity failure withholds plaintext and retains a reconciliation intent.

`cargo +1.98.0 test -p heptabao-plugin-host` covers undeclared operations and environment names, pre-entry versus post-entry failure, mandatory reconciliation, monotonic dynamic lease issue/renew/revoke, durable intent recovery, encrypted lease reopen, capacity failure after process entry, plaintext withholding and secret-redacted debug output. On Linux, `command_runner_uses_the_verified_wrapper_and_bounded_frame` launches a real checksum-pinned wrapper process, verifies inherited environment clearing and round-trips the bounded `HBP1`/`HBR1` frame.

## Evolution and open boundaries

Repository-controlled durable invocation and lease journaling are implemented and remain review-required. External work includes independently qualified Linux/macOS/Windows sandbox providers, process-tree termination guarantees, authenticated multiplexed transport, server routing, real database and cloud provider connectors, rolling plugin upgrades and destructive provider qualification. Those observations are tracked as external completion and this package alone grants no production or dynamic-secret authority.

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

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
