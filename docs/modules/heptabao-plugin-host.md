# heptabao-plugin-host

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns a fail-closed process boundary between HeptaBao and an externally installed sandbox provider, plus the repository-side issue, renew, revoke and reconciliation state machine for dynamic-secret leases. It never executes a plugin directly and does not claim that a particular operating-system sandbox, database provider or production deployment has been qualified.

## Public API and ownership

`PluginManifest` binds one enabled `PluginDescriptor` to a checksum-pinned sandbox wrapper, resource limits, an operation allowlist and a bounded environment-name allowlist. `PluginHost<R>` owns host admission and uncertainty fencing for a `SandboxRunner`; `CommandSandboxRunner` is the concrete subprocess transport. `DynamicSecretBroker<R>` owns lease metadata and returns plaintext only in the one-shot `DynamicSecretIssue` result.

## State and data model

The host is `Active`, `ReconciliationRequired` or `Revoked`. A dynamic lease is `Active`, `Expired`, `Revoked` or `ReconciliationRequired`, and carries owner, canonical scope, issuance and expiry ticks, renewable flag, generation and a SHA-256 digest of the last returned secret. Secret request and response bytes are held in `SecretValue` or `Zeroizing` buffers and are not stored in lease records.

## Invariants and authorization

Only operations declared by the enabled descriptor and manifest can cross the boundary. Authentication and audit plugins cannot request dynamic-secret operations. The host verifies the wrapper and plugin files against their bound SHA-256 digests before entry, rejects symlinked/non-regular/unbounded executables, clears inherited environment state and passes only allowlisted names. A composition root must authorize manifest creation before calling this package.

## Failure, retry and reconciliation

Failure before process entry is retry-classifiable. Any failure after request publication, timeout, non-success exit, malformed response or over-bound response fences the host as outcome-unknown. No subsequent call is accepted until an explicit proof is supplied and both executable bindings pass admission again. The current proof object is repository-side metadata; a production service must obtain authoritative provider readback before constructing it.

## Concurrency and ordering

`PluginHost` and `DynamicSecretBroker` require exclusive mutable access and contain no interior synchronization. Callers must serialize one plugin generation or place the host behind a bounded actor. The request frame is written completely before response observation; lease generation changes only after a completed response or an explicit reconciliation decision.

## Security and privacy

The concrete runner invokes only the sandbox wrapper and supplies the plugin path as a descriptor-bound argument. Standard input and output use bounded binary frames, standard error is discarded, inherited environment variables are cleared, and `Debug` output redacts environment values and secret payloads. File digests are integrity bindings, not code signatures; signer trust, sandbox isolation and provider credentials remain external qualification boundaries.

## Persistence and compatibility

The wire format is versioned by the descriptor. Requests use `HBP1`, protocol version, operation tag, payload length and payload; responses use `HBR1`, payload length and payload, with exact-length validation and no trailing bytes. The package currently owns no durable lease journal. A service integration must persist invocation intent and reconciliation state through the existing durable operation ledger before production use.

## Observability

Safe events are `plugin.admitted`, `plugin.before_entry_failure`, `plugin.outcome_unknown`, `plugin.reconciled`, `plugin.revoked`, `dynamic_lease.issued`, `dynamic_lease.renewed` and `dynamic_lease.revoked`. Labels may include descriptor ID, generation, operation and bounded outcome class, but never command-line secrets, environment values, request bodies, response bodies or secret digests.

## Operations

Operators install the plugin executable and sandbox wrapper outside the repository, set owner-controlled non-writable permissions, calculate reviewed SHA-256 values and register the exact manifest. Rotation requires disabling admission, draining or reconciling outstanding calls, replacing both files, publishing a new descriptor generation and re-running destructive timeout, crash and revocation qualification.

## Tests and executable evidence

`cargo +1.98.0 test -p heptabao-plugin-host` covers undeclared operations and environment names, pre-entry versus post-entry failure, mandatory reconciliation, monotonic dynamic lease issue/renew/revoke and secret-redacted debug output. On Unix, `command_runner_uses_the_verified_wrapper_and_bounded_frame` launches a real checksum-pinned wrapper process, verifies inherited environment clearing and round-trips the bounded `HBP1`/`HBR1` frame.

## Evolution and open boundaries

Open work includes an independently qualified Linux/macOS/Windows sandbox provider, process-tree termination guarantees, authenticated multiplexed transport, durable invocation and lease journaling, server routing, database and cloud provider connectors, rolling plugin upgrades and destructive provider qualification. These remain explicit in `HB-V2-REP-015`; this package alone grants no production or dynamic-secret authority.
