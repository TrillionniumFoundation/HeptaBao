# heptabao-plugin-contracts

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns plugin descriptors, registry lifecycle and the semantic distinction between pre-entry failure and post-entry unknown outcome. It does not launch processes, verify signatures, sandbox plugins or implement RPC.

## Public API and ownership

`PluginRegistry` owns `PluginDescriptor` records. A descriptor binds identifier, kind, canonical command, 32-byte checksum, protocol version, status and generation. `PluginCallOutcome` preserves execution uncertainty.

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
