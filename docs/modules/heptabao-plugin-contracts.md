# heptabao-plugin-contracts

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns plugin descriptors, registry lifecycle and the semantic distinction between pre-entry failure and post-entry unknown outcome. It does not launch processes, verify signatures, sandbox plugins or implement RPC.

## Public API and ownership

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

`cargo test -p heptabao-plugin-contracts` covers descriptor validation and terminal revocation. The current repository validator requires this V3 guide and at least one Rust test.

## Evolution and open boundaries

Process supervision, RPC multiplexing, mTLS, plugin catalogs, reload and compatibility negotiation remain open provider work.

## Machine-verified source truth

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
