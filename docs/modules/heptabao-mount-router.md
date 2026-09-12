# heptabao-mount-router

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns namespace-scoped longest-prefix routing from canonical request paths to KV or plugin backends. It does not execute backends, authorize access or persist the mount table.

## Public API and ownership

### Current API contract and integration boundary

`MountRouter` owns a map keyed by store-global mount ID. `mount(id, namespace_id, path, Backend)` rejects duplicate IDs and duplicate namespace/path pairs, then returns an owned enabled `Mount` at generation 1. Backend is either `Kv` or `Plugin(Id)`; registration does not validate namespace existence, plugin existence/health or policy. The service must establish those constraints before dispatch.

`route(namespace_id, path)` selects the longest enabled segment-bounded prefix in that exact namespace and returns owned `Route { mount_id, backend, relative_path, mount_generation }`. An exact mount path has an empty relative path. A `/` mount routes descendants as a namespace-scoped fallback; a longer enabled mount takes precedence. `NoRoute` remains the result when the selected namespace has no enabled matching mount.

`set_enabled(id, enabled)` rejects a repeated state as `NoStateChange` and saturating-increments generation on change; `unmount` removes and returns the record. No method drains calls, revokes leases or keeps a tombstone. A route is a snapshot, not a lock: concurrent adapters must revalidate administrative state/generation before backend entry.

This crate is composed by the independent `heptabao-service-core`, outside the current server dependency closure. Current server routes use a separate native mount implementation; a plugin route here does not execute a plugin process.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

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

- `root_mount_routes_descendants_and_preserves_namespace_and_precedence` — `crates/heptabao-mount-router/src/lib.rs`; verifies root fallback, longest prefix, namespace isolation and disabled-root rejection.

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::longest_prefix_wins_within_namespace`](../../crates/heptabao-mount-router/src/lib.rs) checks nested plugin mount selection and the relative backend path.
- [`tests::namespace_and_enablement_are_fail_closed`](../../crates/heptabao-mount-router/src/lib.rs) checks wrong-namespace and disabled-mount rejection.

`cargo test -p heptabao-mount-router` proves longest-prefix selection, namespace isolation and disabled-mount failure. Strict Clippy is part of V2 CI.

## Evolution and open boundaries

Tune endpoints, remount, mount aliases, replication filters and plugin health-aware routing remain open and require explicit transition protocols.

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

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
