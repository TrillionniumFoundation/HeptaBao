# heptabao-namespace

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns hierarchical namespaces and the mapping from namespace identifiers to canonical path roots. It does not authorize requests, persist namespace records or implement replication.

## Public API and ownership

`NamespaceStore` owns namespace records and a path index. Each `Namespace` owns its identifier, optional parent, canonical root, state and generation.

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
