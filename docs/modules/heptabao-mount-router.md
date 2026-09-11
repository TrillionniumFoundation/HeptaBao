# heptabao-mount-router

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns namespace-scoped longest-prefix routing from canonical request paths to KV or plugin backends. It does not execute backends, authorize access or persist the mount table.

## Public API and ownership

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-mount-router`; Cargo SHA-256 `9a0fa2697289993cf1ce471fc686ee3aab42874a777a18424cef2bac58cde78e`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `enum` | `Backend` | `crates/heptabao-mount-router/src/lib.rs:13` | `pub enum Backend {` |
| `struct` | `Mount` | `crates/heptabao-mount-router/src/lib.rs:19` | `pub struct Mount {` |
| `fn` | `id` | `crates/heptabao-mount-router/src/lib.rs:29` | `pub fn id(&self) -> &Id {` |
| `fn` | `namespace_id` | `crates/heptabao-mount-router/src/lib.rs:33` | `pub fn namespace_id(&self) -> &Id {` |
| `fn` | `path` | `crates/heptabao-mount-router/src/lib.rs:37` | `pub fn path(&self) -> &CanonicalPath {` |
| `fn` | `backend` | `crates/heptabao-mount-router/src/lib.rs:41` | `pub fn backend(&self) -> &Backend {` |
| `struct` | `Route` | `crates/heptabao-mount-router/src/lib.rs:47` | `pub struct Route {` |
| `struct` | `MountRouter` | `crates/heptabao-mount-router/src/lib.rs:55` | `pub struct MountRouter {` |
| `fn` | `mount` | `crates/heptabao-mount-router/src/lib.rs:60` | `pub fn mount(` |
| `fn` | `set_enabled` | `crates/heptabao-mount-router/src/lib.rs:89` | `pub fn set_enabled(&mut self, id: &Id, enabled: bool) -> Result<(), MountError> {` |
| `fn` | `unmount` | `crates/heptabao-mount-router/src/lib.rs:99` | `pub fn unmount(&mut self, id: &Id) -> Result<Mount, MountError> {` |
| `fn` | `route` | `crates/heptabao-mount-router/src/lib.rs:103` | `pub fn route(&self, namespace_id: &Id, path: &CanonicalPath) -> Result<Route, MountError> {` |
| `enum` | `MountError` | `crates/heptabao-mount-router/src/lib.rs:128` | `pub enum MountError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

Mounts are inserted enabled, can be disabled or re-enabled with generation advancement, and can be removed explicitly. One namespace cannot contain two mounts at the same canonical path.

## Invariants and authorization

Only enabled mounts in the exact requested namespace participate. Longest canonical segment-prefix match wins. Routing is not authorization and must execute only after policy evaluation.

## Failure, retry and reconciliation

Duplicate, missing and no-route errors are deterministic before backend entry. The router creates no external side effects and therefore has no ambiguous outcome.

## Concurrency and ordering

There is no interior lock. A composition root serializes mount mutations and binds dispatch to the returned mount generation to detect concurrent administrative change.

## Security and privacy

Routes carry canonical paths but no token or secret value. Telemetry should record mount identifiers and operation classes, not full secret paths.

## Persistence and compatibility

No persisted format exists. Production recovery must reject duplicate namespace/path pairs and unsupported backend kinds before accepting traffic.

## Observability

Recommended events are `mount.created`, `mount.state_changed`, `mount.removed` and `route.miss`; labels remain bounded to backend kind and outcome.

## Operations

Disabling a mount immediately makes it unroutable. Safe production unmount additionally requires lease revocation, in-flight request draining and durable tombstones.

## Tests and executable evidence

`cargo test -p heptabao-mount-router` proves longest-prefix selection, namespace isolation and disabled-mount failure. Strict Clippy is part of V2 CI.

## Evolution and open boundaries

Tune endpoints, remount, mount aliases, replication filters and plugin health-aware routing remain open and require explicit transition protocols.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-mount-router`
- Crate path: `crates/heptabao-mount-router`
- Cargo manifest SHA-256: `9a0fa2697289993cf1ce471fc686ee3aab42874a777a18424cef2bac58cde78e`
- Rust source files: `1`
- Public lexical declarations: `13`
- Discovered test functions: `2`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
