# heptabao-identity

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns entities, aliases, groups and deterministic effective-policy expansion. It does not validate OIDC/JWT credentials, perform MFA, persist identity data or implement nested groups.

## Public API and ownership

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-identity`; Cargo SHA-256 `2d2f6724ac89240dadb689e07e17b9422388c8bcff3e24efd1f2b6b317735deb`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `struct` | `Entity` | `crates/heptabao-identity/src/lib.rs:13` | `pub struct Entity {` |
| `fn` | `id` | `crates/heptabao-identity/src/lib.rs:22` | `pub fn id(&self) -> &Id {` |
| `fn` | `aliases` | `crates/heptabao-identity/src/lib.rs:26` | `pub fn aliases(&self) -> &BTreeSet<Id> {` |
| `fn` | `disabled` | `crates/heptabao-identity/src/lib.rs:30` | `pub fn disabled(&self) -> bool {` |
| `struct` | `Group` | `crates/heptabao-identity/src/lib.rs:36` | `pub struct Group {` |
| `fn` | `id` | `crates/heptabao-identity/src/lib.rs:43` | `pub fn id(&self) -> &Id {` |
| `fn` | `members` | `crates/heptabao-identity/src/lib.rs:47` | `pub fn members(&self) -> &BTreeSet<Id> {` |
| `struct` | `IdentityStore` | `crates/heptabao-identity/src/lib.rs:53` | `pub struct IdentityStore {` |
| `fn` | `create_entity` | `crates/heptabao-identity/src/lib.rs:60` | `pub fn create_entity(&mut self, id: Id) -> Result<(), IdentityError> {` |
| `fn` | `create_group` | `crates/heptabao-identity/src/lib.rs:77` | `pub fn create_group(&mut self, id: Id, policies: BTreeSet<Id>) -> Result<(), IdentityError> {` |
| `fn` | `add_alias` | `crates/heptabao-identity/src/lib.rs:92` | `pub fn add_alias(&mut self, entity_id: &Id, alias: Id) -> Result<(), IdentityError> {` |
| `fn` | `attach_policy` | `crates/heptabao-identity/src/lib.rs:105` | `pub fn attach_policy(&mut self, entity_id: &Id, policy_id: Id) -> Result<(), IdentityError> {` |
| `fn` | `add_entity_to_group` | `crates/heptabao-identity/src/lib.rs:114` | `pub fn add_entity_to_group(` |
| `fn` | `set_disabled` | `crates/heptabao-identity/src/lib.rs:134` | `pub fn set_disabled(&mut self, entity_id: &Id, disabled: bool) -> Result<(), IdentityError> {` |
| `fn` | `resolve_alias` | `crates/heptabao-identity/src/lib.rs:143` | `pub fn resolve_alias(&self, alias: &Id) -> Result<&Entity, IdentityError> {` |
| `fn` | `entity` | `crates/heptabao-identity/src/lib.rs:150` | `pub fn entity(&self, entity_id: &Id) -> Result<&Entity, IdentityError> {` |
| `fn` | `effective_policy_ids` | `crates/heptabao-identity/src/lib.rs:156` | `pub fn effective_policy_ids(&self, entity_id: &Id) -> Result<BTreeSet<Id>, IdentityError> {` |
| `enum` | `IdentityError` | `crates/heptabao-identity/src/lib.rs:174` | `pub enum IdentityError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and data model

Entity lifecycle is create, enabled or disabled. Alias and group identifiers are globally unique in a store. Group membership updates both authoritative membership views in one method.

## Invariants and authorization

Missing or disabled entities fail closed. Alias collisions and duplicate entities/groups are rejected. This package expands policy identifiers but does not decide whether an operation is authorized.

## Failure, retry and reconciliation

All operations are in-memory and deterministic. Validation and duplicate failures occur before a successful return; there is no after-entry unknown result in this package.

## Concurrency and ordering

The store has no internal locks. The composition root must serialize identity mutations and must not expose mutable references across callbacks.

## Security and privacy

Errors expose classifications only. External identity attributes and credentials are outside this package and must be sanitized before mapping to a bounded alias identifier.

## Persistence and compatibility

The package owns no persisted schema. Future persistence must version entity, alias, group and membership records and apply updates atomically.

## Observability

The package emits no telemetry directly. Administrative callers should record entity create, disable, alias and membership changes without credential claims or raw identity documents.

## Operations

Disabling an entity immediately causes policy expansion to fail. Production operation still requires durable storage, conflict-safe updates, audit events and identity-provider adapters.

## Tests and executable evidence

`cargo test -p heptabao-identity` covers alias resolution, direct and group policy expansion and disabled-entity denial. The current repository workflow also formats and strictly lints the crate.

## Evolution and open boundaries

Nested groups, MFA bindings, identity-provider metadata, merge semantics and deletion tombstones remain open and require cycle and migration rules before implementation.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-identity`
- Crate path: `crates/heptabao-identity`
- Cargo manifest SHA-256: `2d2f6724ac89240dadb689e07e17b9422388c8bcff3e24efd1f2b6b317735deb`
- Rust source files: `1`
- Public lexical declarations: `18`
- Discovered test functions: `2`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
