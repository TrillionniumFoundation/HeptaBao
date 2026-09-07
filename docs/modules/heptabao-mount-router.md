# heptabao-mount-router

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns namespace-scoped longest-prefix routing from canonical request paths to KV or plugin backends. It does not execute backends, authorize access or persist the mount table.

## Public API and ownership

`MountRouter` owns `Mount` records. A `Route` contains the selected mount, backend, relative path and mount generation required for dispatch-time consistency checks.

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
