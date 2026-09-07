# heptabao-identity

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns entities, aliases, groups and deterministic effective-policy expansion. It does not validate OIDC/JWT credentials, perform MFA, persist identity data or implement nested groups.

## Public API and ownership

`IdentityStore` owns entity, alias and group maps. Entities own direct policies and group membership; groups own their policy set and reciprocal member set.

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
