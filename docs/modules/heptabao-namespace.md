# heptabao-namespace

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns hierarchical namespaces and the mapping from namespace identifiers to canonical path roots. It does not authorize requests, persist namespace records or implement replication.

## Public API and ownership

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-namespace`; Cargo SHA-256 `ffbf4c8704c5c73c0c78a43833978258b35fbc6863a2afd8839b8125b9fca0ba`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `enum` | `NamespaceState` | `crates/heptabao-namespace/src/lib.rs:13` | `pub enum NamespaceState {` |
| `struct` | `Namespace` | `crates/heptabao-namespace/src/lib.rs:19` | `pub struct Namespace {` |
| `fn` | `id` | `crates/heptabao-namespace/src/lib.rs:28` | `pub fn id(&self) -> &Id {` |
| `fn` | `parent_id` | `crates/heptabao-namespace/src/lib.rs:32` | `pub fn parent_id(&self) -> Option<&Id> {` |
| `fn` | `path` | `crates/heptabao-namespace/src/lib.rs:36` | `pub fn path(&self) -> &CanonicalPath {` |
| `fn` | `state` | `crates/heptabao-namespace/src/lib.rs:40` | `pub fn state(&self) -> NamespaceState {` |
| `fn` | `generation` | `crates/heptabao-namespace/src/lib.rs:44` | `pub fn generation(&self) -> u64 {` |
| `struct` | `NamespaceStore` | `crates/heptabao-namespace/src/lib.rs:50` | `pub struct NamespaceStore {` |
| `fn` | `bootstrap_root` | `crates/heptabao-namespace/src/lib.rs:56` | `pub fn bootstrap_root(&mut self, id: Id) -> Result<(), NamespaceError> {` |
| `fn` | `create` | `crates/heptabao-namespace/src/lib.rs:75` | `pub fn create(&mut self, id: Id, parent_id: &Id) -> Result<Namespace, NamespaceError> {` |
| `fn` | `get` | `crates/heptabao-namespace/src/lib.rs:102` | `pub fn get(&self, id: &Id) -> Result<&Namespace, NamespaceError> {` |
| `fn` | `disable` | `crates/heptabao-namespace/src/lib.rs:108` | `pub fn disable(&mut self, id: &Id) -> Result<(), NamespaceError> {` |
| `fn` | `resolve` | `crates/heptabao-namespace/src/lib.rs:124` | `pub fn resolve(&self, path: &CanonicalPath) -> Result<&Namespace, NamespaceError> {` |
| `fn` | `qualify` | `crates/heptabao-namespace/src/lib.rs:134` | `pub fn qualify(` |
| `enum` | `NamespaceError` | `crates/heptabao-namespace/src/lib.rs:160` | `pub enum NamespaceError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

The first operation bootstraps one root namespace. Child creation derives a canonical child path. Non-root namespaces move from active to disabled and do not silently reactivate.

## Invariants and authorization

Identifiers and paths are canonical. Duplicate identifiers and paths are rejected. Disabled parents cannot receive children, and a disabled namespace cannot qualify a resource path. Namespace validity alone grants no capability.

## Failure, retry and reconciliation

All current transitions are deterministic and occur in memory. Rejected creation happens before insertion. A future durable adapter must apply namespace and path-index changes atomically.

## Concurrency and ordering

The store has no interior synchronization. A service or administrative composition root serializes namespace mutations and publishes a new generation only after both indexes agree.

## Security and privacy

Namespace records contain no secret values. Error messages do not echo namespace paths or request content. Isolation depends on every downstream policy, mount and storage key including the resolved namespace.

## Persistence and compatibility

No persisted schema is owned. A production schema must version parent links, paths, state and generation and must reject cycles or duplicate canonical roots during recovery.

## Observability

Recommended administrative events are `namespace.created` and `namespace.disabled`, using bounded outcome and generation fields without secret resource paths.

## Operations

Root bootstrap is a one-time operation. Disabling a child blocks qualification immediately; production deletion, reparenting and recursive cleanup remain deliberately absent.

## Tests and executable evidence

`cargo test -p heptabao-namespace` covers hierarchy, longest-prefix resolution, qualification, disabled isolation and root protection. The V2 repository validator binds the package to this guide.

## Evolution and open boundaries

Deletion, reparenting, namespace quotas and HA replication remain open. They require tombstones, cycle checks and recovery semantics before implementation.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-namespace`
- Crate path: `crates/heptabao-namespace`
- Cargo manifest SHA-256: `ffbf4c8704c5c73c0c78a43833978258b35fbc6863a2afd8839b8125b9fca0ba`
- Rust source files: `1`
- Public lexical declarations: `15`
- Discovered test functions: `2`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
