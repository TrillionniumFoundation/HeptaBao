# heptabao-plugin-contracts

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns plugin descriptors, registry lifecycle and the semantic distinction between pre-entry failure and post-entry unknown outcome. It does not launch processes, verify signatures, sandbox plugins or implement RPC.

## Public API and ownership

### Current API contract and integration boundary

`PluginDescriptor::new(id, kind, command, checksum, protocol_version)` owns a canonical command path and metadata. It rejects an all-zero 32-byte checksum and protocol version 0. It does not open the executable, compute its checksum, authenticate a publisher or negotiate RPC; callers must perform those checks using a host/provider before execution.

`PluginRegistry::register` owns a descriptor under a unique ID, while `get` borrows it. `enable` accepts Registered/Disabled, `disable` accepts Enabled, and `revoke` accepts any non-revoked status; successful transitions advance a saturating generation. Revoked is terminal and no API deletes/replaces a descriptor. The registry alone does not synchronize an already running plugin with an administrative change.

`PluginCallOutcome<T>` distinguishes `BeforeEntryFailure`, `Completed(T)` and `OutcomeUnknownAfterEntry { recovery_reference }`. The host must preserve this classification across process/IPC failure, bind the exact descriptor generation to each call, and obtain authoritative readback before retrying uncertainty. The enum carries no automatic retry or reconciliation implementation.

This descriptor/outcome model is consumed by the independent `heptabao-plugin-host`, outside the current server dependency closure. It does not implement the server's native plugin paths or OpenBao's plugin RPC ABI. An operator action on this memory registry therefore does not administer a deployed server plugin.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-plugin-contracts`; Cargo SHA-256 `f65f8c26ed9b3989b8a2fece8b8bd2913d87697905e05ee6715fc1edbe2e4e02`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `enum` | `PluginKind` | `crates/heptabao-plugin-contracts/src/lib.rs:13` | `pub enum PluginKind {` |
| `enum` | `PluginStatus` | `crates/heptabao-plugin-contracts/src/lib.rs:21` | `pub enum PluginStatus {` |
| `struct` | `PluginDescriptor` | `crates/heptabao-plugin-contracts/src/lib.rs:29` | `pub struct PluginDescriptor {` |
| `fn` | `new` | `crates/heptabao-plugin-contracts/src/lib.rs:40` | `pub fn new(` |
| `fn` | `id` | `crates/heptabao-plugin-contracts/src/lib.rs:64` | `pub fn id(&self) -> &Id {` |
| `fn` | `status` | `crates/heptabao-plugin-contracts/src/lib.rs:68` | `pub fn status(&self) -> PluginStatus {` |
| `fn` | `generation` | `crates/heptabao-plugin-contracts/src/lib.rs:72` | `pub fn generation(&self) -> u64 {` |
| `fn` | `kind` | `crates/heptabao-plugin-contracts/src/lib.rs:76` | `pub fn kind(&self) -> PluginKind {` |
| `fn` | `command` | `crates/heptabao-plugin-contracts/src/lib.rs:80` | `pub fn command(&self) -> &CanonicalPath {` |
| `fn` | `checksum` | `crates/heptabao-plugin-contracts/src/lib.rs:84` | `pub fn checksum(&self) -> &[u8; 32] {` |
| `fn` | `protocol_version` | `crates/heptabao-plugin-contracts/src/lib.rs:88` | `pub fn protocol_version(&self) -> u16 {` |
| `enum` | `PluginCallOutcome` | `crates/heptabao-plugin-contracts/src/lib.rs:94` | `pub enum PluginCallOutcome<T> {` |
| `struct` | `PluginRegistry` | `crates/heptabao-plugin-contracts/src/lib.rs:101` | `pub struct PluginRegistry {` |
| `fn` | `register` | `crates/heptabao-plugin-contracts/src/lib.rs:106` | `pub fn register(&mut self, plugin: PluginDescriptor) -> Result<(), PluginError> {` |
| `fn` | `get` | `crates/heptabao-plugin-contracts/src/lib.rs:114` | `pub fn get(&self, id: &Id) -> Result<&PluginDescriptor, PluginError> {` |
| `fn` | `enable` | `crates/heptabao-plugin-contracts/src/lib.rs:118` | `pub fn enable(&mut self, id: &Id) -> Result<(), PluginError> {` |
| `fn` | `disable` | `crates/heptabao-plugin-contracts/src/lib.rs:131` | `pub fn disable(&mut self, id: &Id) -> Result<(), PluginError> {` |
| `fn` | `revoke` | `crates/heptabao-plugin-contracts/src/lib.rs:141` | `pub fn revoke(&mut self, id: &Id) -> Result<(), PluginError> {` |
| `enum` | `PluginError` | `crates/heptabao-plugin-contracts/src/lib.rs:153` | `pub enum PluginError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

Lifecycle is registered, enabled, disabled and revoked. Revocation is terminal. Zero checksums and protocol version zero are rejected before registration.

## Invariants and authorization

Only a separately authorized composition root may enable or invoke a plugin. Registry presence never grants execution authority, and revoked plugins cannot return to service.

## Failure, retry and reconciliation

`BeforeEntryFailure` permits policy-controlled retry. `OutcomeUnknownAfterEntry` forbids blind retry and carries a bounded recovery reference. Lifecycle errors are deterministic.

## Concurrency and ordering

The registry has no interior synchronization. A host must validate descriptor generation and checksum immediately before process entry and hold no unrelated service lock across RPC.

## Security and privacy

The checksum is an integrity binding, not a signature or trust decision. Production requires executable ownership checks, sandboxing, protocol authentication, resource limits and external qualification.

## Persistence and compatibility

No registry persistence or RPC wire format exists. Future formats must version plugin kind, protocol, checksum algorithm, status and generation.

## Observability

Recommended events include `plugin.registered`, `plugin.enabled`, `plugin.revoked` and `plugin.outcome_unknown`; command paths and request payloads are not labels.

## Operations

Operators may disable or revoke a descriptor before replacing it. Production upgrades require drain, checksum admission, rollback and reconciliation procedures.

## Tests and executable evidence

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::lifecycle_is_monotonic_after_revocation`](../../crates/heptabao-plugin-contracts/src/lib.rs) checks register/enable/disable/re-enable/revoke and the terminal revocation guard.
- [`tests::invalid_descriptor_is_rejected_before_registration`](../../crates/heptabao-plugin-contracts/src/lib.rs) checks zero-checksum rejection before a descriptor exists.

`cargo test -p heptabao-plugin-contracts` covers descriptor validation and terminal revocation. The current repository validator requires this V3 guide and at least one Rust test.

## Evolution and open boundaries

Process supervision, RPC multiplexing, mTLS, plugin catalogs, reload and compatibility negotiation remain open provider work.

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-plugin-contracts`
- Crate path: `crates/heptabao-plugin-contracts`
- Cargo manifest SHA-256: `f65f8c26ed9b3989b8a2fece8b8bd2913d87697905e05ee6715fc1edbe2e4e02`
- Rust source files: `1`
- Public lexical declarations: `19`
- Discovered test functions: `2`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
