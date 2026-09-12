# heptabao-identity

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns entities, aliases, groups and deterministic effective-policy expansion. It does not validate OIDC/JWT credentials, perform MFA, persist identity data or implement nested groups.

## Public API and ownership

### Current API contract and integration boundary

`IdentityStore` owns entity records, a global alias-to-entity index and group membership/policies in memory. `create_entity(id)` and `create_group(id, policy_ids)` reject duplicate IDs. `add_alias(entity_id, alias)` rejects an existing alias before linking it to an existing entity; aliases are store-global, with no authentication-mount or namespace component. `attach_policy` stores an ID without checking that the policy exists in a `PolicyStore`.

`add_entity_to_group` validates both records before updating both membership sets. `entity` and `resolve_alias` borrow an `Entity`; they report missing records but can return disabled entities. Enforcement of disabled state happens in `effective_policy_ids(entity_id)`, which returns an owned deduplicated ordered union of direct and group policy IDs, or `EntityDisabled`. A caller must not treat successful alias lookup alone as authorization. Groups are flat and cannot recursively include groups.

`set_disabled` changes the flag without a generation counter or revocation of tokens. The composition must re-expand identity policies for every authorized request, handle policy removal in the policy store and arrange any required token revocation separately. This crate is composed by the independent in-memory `heptabao-service-core`; it is outside the current server dependency closure and does not implement the server's native identity/authentication state.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

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

Effective-policy expansion rejects missing or disabled entities; plain entity/alias lookup can return a disabled record. Alias collisions and duplicate entities/groups are rejected. This package expands policy identifiers but does not decide whether an operation is authorized.

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

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::aliases_groups_and_direct_policies_expand_deterministically`](../../crates/heptabao-identity/src/lib.rs) checks alias resolution and union of direct/group policies.
- [`tests::disabled_entities_fail_closed`](../../crates/heptabao-identity/src/lib.rs) checks denial specifically at effective-policy expansion.

`cargo test -p heptabao-identity` covers alias resolution, direct and group policy expansion and disabled-entity denial. The current repository workflow also formats and strictly lints the crate.

## Evolution and open boundaries

Nested groups, MFA bindings, identity-provider metadata, merge semantics and deletion tombstones remain open and require cycle and migration rules before implementation.

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

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
