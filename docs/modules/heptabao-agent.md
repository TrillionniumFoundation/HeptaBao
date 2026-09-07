# heptabao-agent

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns the fail-closed lifecycle for local auto-authentication, token renewal, sink delivery, backoff, revocation and outcome reconciliation. It does not implement an authentication backend, persist credentials, create operating-system services or claim production agent compatibility.

## Public API and ownership

`AgentConfig` declares one authentication method, one credential source, one token sink and bounded retry parameters. `AgentSession` is the sole owner of lifecycle state; callers drive explicit transitions and cannot directly mutate generation, deadlines or reconciliation state.

## State and data model

The lifecycle is `Stopped → Authenticating → Authenticated → Renewing` with explicit `Backoff`, `Revoking` and `FailedClosed` branches. A successful authentication or renewal advances `token_generation`; retry and renewal deadlines use monotonic `Tick` values rather than wall-clock timestamps.

## Invariants and authorization

Only one credential source and one token sink are configured. Inherited descriptors below three, zero backoff and decreasing maximum backoff are rejected. Authentication produces a local session but never grants policy authorization or repository authority.

## Failure, retry and reconciliation

A failure proven to occur before provider entry enters bounded exponential backoff and may start a new operation when due. Any authentication, renewal or revocation result that becomes unknown after entry moves to `FailedClosed`; blind retry is prohibited until an authoritative `ReconciledAgentState` is supplied.

## Concurrency and ordering

`AgentSession` contains no internal synchronization and is intended to be driven by one serialized controller. Token sink publication must occur only after the provider result is known, and reconciliation must complete before another authentication or renewal transition is accepted.

## Security and privacy

Credential values and token bytes never appear in these contracts. Sink and reconciliation references are redacted from `Debug`; callers must use owner-only files, inherited descriptors or local memory sockets and must not place live tokens in arguments, logs, fixtures or telemetry labels.

## Persistence and compatibility

The crate defines no on-disk format. A production agent must persist only versioned nonsecret lifecycle metadata and bind any token cache to platform-specific owner identity, file permissions, atomic replacement and restart reconciliation rules.

## Observability

Recommended low-cardinality events are `agent.auth.started`, `agent.auth.failed_before_entry`, `agent.backoff.entered`, `agent.renewed`, `agent.revoked` and `agent.reconciliation.required`. Events may include state and outcome class but never credential, token, sink-reference or workload-identity contents.

## Operations

Operators need explicit procedures for startup, authentication outage, clock/tick source failure, sink permission failure, token renewal loss, ambiguous provider outcomes and emergency revocation. A failed-closed session remains unavailable rather than silently reusing an uncertain token.

## Tests and executable evidence

`cargo test -p heptabao-agent` exercises the complete authentication/renewal/revocation path, bounded exponential backoff, deadline enforcement, generation monotonicity, unknown-after-entry fencing and redacted diagnostics. The V2 assurance workflow also applies formatting, strict Clippy and rustdoc checks.

## Evolution and open boundaries

Concrete authentication methods, workload identity providers, durable agent state, token sink implementations, process supervision, namespace-aware templates and OpenBao agent compatibility remain separate work. No compatibility or production claim is created by this contract package.
