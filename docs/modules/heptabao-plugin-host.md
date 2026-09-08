# heptabao-plugin-host

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns a fail-closed process boundary between HeptaBao and an externally installed sandbox provider, plus the repository-side issue, renew, revoke and reconciliation state machine for dynamic-secret leases. It never executes a plugin directly and does not claim that a particular operating-system sandbox, database provider or production deployment has been qualified.

## Public API and ownership

`PluginManifest` binds one enabled `PluginDescriptor` to a checksum-pinned sandbox wrapper, resource limits, an operation allowlist and a bounded environment-name allowlist. `PluginHost<R>` owns host admission and uncertainty fencing for a `SandboxRunner`; `CommandSandboxRunner` is the concrete subprocess transport. `DynamicSecretBroker<R>` owns the in-memory lease state machine. `DurableDynamicSecretBroker<B, R>` composes it with `heptabao-durable-service`, accepts only a validated `PluginMutationContext`, persists an encrypted invocation intent before process entry and returns plaintext only in the one-shot `DynamicSecretIssue` result after durable publication and intent clearance.

## State and data model

The host is `Active`, `ReconciliationRequired` or `Revoked`. A dynamic lease is `Active`, `Expired`, `Revoked` or `ReconciliationRequired`, and carries owner, canonical scope, issuance and expiry ticks, renewable flag, generation and a SHA-256 digest of the last returned secret. `HBDI` records contain only operation, lease metadata, previous projection and a request digest; `HBDL` records contain only the bounded lease projection. Both cross the injected authenticated Barrier through the durable service. Secret request and response bytes are held in `SecretValue` or `Zeroizing` buffers and are never stored in either record.

## Invariants and authorization

Only operations declared by the enabled descriptor and manifest can cross the boundary. Authentication and audit plugins cannot request dynamic-secret operations. The host verifies the wrapper and plugin files against their bound SHA-256 digests before entry, rejects symlinked/non-regular/unbounded executables, clears inherited environment state and passes only allowlisted names. A composition root must authorize manifest creation before calling this package.

## Failure, retry and reconciliation

Failure before process entry is retry-classifiable only after the durable invocation intent has itself been durably removed. Any failure after request publication, timeout, non-success exit, malformed response, over-bound response, lease-publication failure or intent-clear failure fences the host as outcome-unknown. The pending `HBDI` survives restart and blocks every later call. Reconciliation revalidates both executable bindings, validates an authoritative provider decision, durably publishes or restores the lease projection, durably clears the intent and only then reactivates the host. Repository code cannot manufacture provider readback.

## Concurrency and ordering

`PluginHost`, `DynamicSecretBroker` and `DurableDynamicSecretBroker` require exclusive mutable access and contain no interior synchronization. Exactly one durable plugin invocation may be pending; a second operation is rejected rather than queued. Ordering is durable intent → sandbox entry → bounded response → encrypted lease publication → encrypted intent deletion → plaintext release. Reconciliation uses the same single-writer ordering.

## Security and privacy

The concrete runner invokes only the sandbox wrapper and supplies the plugin path as a descriptor-bound argument. Standard input and output use bounded binary frames, standard error is discarded, inherited environment variables are cleared, and `Debug` output redacts environment values and secret payloads. File digests are integrity bindings, not code signatures; signer trust, sandbox isolation and provider credentials remain external qualification boundaries.

## Persistence and compatibility

The process wire format is versioned by the descriptor. Requests use `HBP1`, protocol version, operation tag, payload length and payload; responses use `HBR1`, payload length and payload, with exact-length validation and no trailing bytes. Durable records use strict `HBDI` and `HBDL` version 1 encodings with exact-length and trailing-byte rejection. The existing durable service owns snapshot, journal, replay ledger, writer fencing and Barrier authentication; this package owns the plugin-specific intent and lease semantics layered on it.

## Observability

Safe events are `plugin.admitted`, `plugin.before_entry_failure`, `plugin.outcome_unknown`, `plugin.reconciled`, `plugin.revoked`, `dynamic_lease.issued`, `dynamic_lease.renewed` and `dynamic_lease.revoked`. Labels may include descriptor ID, generation, operation and bounded outcome class, but never command-line secrets, environment values, request bodies, response bodies or secret digests.

## Operations

Operators install the plugin executable and sandbox wrapper outside the repository, set owner-controlled non-writable permissions, calculate reviewed SHA-256 values and register the exact manifest. Rotation requires disabling admission, draining or reconciling outstanding calls, replacing both files, publishing a new descriptor generation and re-running destructive timeout, crash and revocation qualification.

## Tests and executable evidence

`cargo +1.98.0 test -p heptabao-plugin-host` covers undeclared operations and environment names, pre-entry versus post-entry failure, mandatory reconciliation, monotonic dynamic lease issue/renew/revoke, durable intent recovery, encrypted lease reopen, capacity failure after process entry, plaintext withholding and secret-redacted debug output. On Unix, `command_runner_uses_the_verified_wrapper_and_bounded_frame` launches a real checksum-pinned wrapper process, verifies inherited environment clearing and round-trips the bounded `HBP1`/`HBR1` frame.

## Evolution and open boundaries

Repository-controlled durable invocation and lease journaling are implemented and remain review-required. External work includes independently qualified Linux/macOS/Windows sandbox providers, process-tree termination guarantees, authenticated multiplexed transport, server routing, real database and cloud provider connectors, rolling plugin upgrades and destructive provider qualification. Those observations are tracked as external completion and this package alone grants no production or dynamic-secret authority.
