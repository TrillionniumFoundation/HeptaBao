# heptabao-agent

Current source binding: [docs/modules/CURRENT_SOURCE_BINDING.md](CURRENT_SOURCE_BINDING.md). Runtime integration: [docs/modules/CURRENT_RUNTIME_MAP.md](CURRENT_RUNTIME_MAP.md).

Shared rules: `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

This package owns the fail-closed lifecycle for local auto-authentication, token renewal, sink delivery, backoff, revocation and outcome reconciliation. It does not implement an authentication backend, persist credentials, create operating-system services or claim production agent compatibility.

## Public API and ownership

### Current API contract and integration boundary

`AgentSession::new(AgentConfig)` takes ownership of the configuration and all lifecycle metadata. `TokenSink::new(kind, reference)` describes a sink; it does not open a file or socket. `CredentialSource` describes stdin, an inherited descriptor or workload identity without reading credentials. The constructor rejects a zero initial backoff, a maximum below the initial value, and inherited descriptors below 3; it does not check descriptor ownership or sink permissions.

The controller calls `start`, then reports provider results through `authentication_succeeded(now, ttl_ticks)` or `authentication_failed_before_entry(now)`. Success requires nonzero TTL, checked deadline arithmetic and a non-overflowing generation. Before-entry failures return the next retry tick using capped exponential delay; `retry_authentication(now)` rejects early attempts with `RetryNotDue`. `begin_renewal(now)` must precede the expiry deadline: equality returns `SessionExpired` and moves to `FailedClosed`. Revocation is a separate begin/success pair; none of these methods performs the external effect.

After provider entry, an uncertain result must go through `mark_outcome_unknown_after_entry(reference)` and `reconcile(ReconciledAgentState)`. Reconciliation rejects generation regression, but has no `now` parameter and does not validate whether an authenticated deadline is still live. The caller must obtain authoritative state and validate its deadline. An expiry-induced failed-closed state has no reconciliation reference, so it cannot use the same reconciliation path without a separate recovery policy.

This crate is an independent controller model outside the current `heptabao-server` dependency closure. The agent adapter must own transport, trusted monotonic time, actual token bytes, sink publication and restart recovery; the model supplies no running agent process.

### Historical V1.4.7 lexical snapshot

The following generated block is retained unchanged for historical verification. Its declarations and line numbers are not the current API contract; use the explanation above and the [current source binding](CURRENT_SOURCE_BINDING.md).

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-agent`; Cargo SHA-256 `081f9b1eb2c4647064ae04f7f44d4328767af72cd133b491add40e8cb38fede5`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `enum` | `CredentialSource` | `crates/heptabao-agent/src/lib.rs:14` | `pub enum CredentialSource {` |
| `enum` | `TokenSinkKind` | `crates/heptabao-agent/src/lib.rs:21` | `pub enum TokenSinkKind {` |
| `struct` | `TokenSink` | `crates/heptabao-agent/src/lib.rs:28` | `pub struct TokenSink {` |
| `fn` | `new` | `crates/heptabao-agent/src/lib.rs:34` | `pub fn new(kind: TokenSinkKind, reference: Id) -> Self {` |
| `const` | `fn` | `crates/heptabao-agent/src/lib.rs:38` | `pub const fn kind(&self) -> TokenSinkKind {` |
| `fn` | `reference` | `crates/heptabao-agent/src/lib.rs:42` | `pub fn reference(&self) -> &Id {` |
| `struct` | `AgentConfig` | `crates/heptabao-agent/src/lib.rs:58` | `pub struct AgentConfig {` |
| `enum` | `AgentState` | `crates/heptabao-agent/src/lib.rs:80` | `pub enum AgentState {` |
| `enum` | `ReconciledAgentState` | `crates/heptabao-agent/src/lib.rs:91` | `pub enum ReconciledAgentState {` |
| `struct` | `AgentSession` | `crates/heptabao-agent/src/lib.rs:100` | `pub struct AgentSession {` |
| `fn` | `new` | `crates/heptabao-agent/src/lib.rs:111` | `pub fn new(config: AgentConfig) -> Result<Self, AgentError> {` |
| `const` | `fn` | `crates/heptabao-agent/src/lib.rs:124` | `pub const fn state(&self) -> AgentState {` |
| `const` | `fn` | `crates/heptabao-agent/src/lib.rs:128` | `pub const fn retry_at(&self) -> Option<Tick> {` |
| `const` | `fn` | `crates/heptabao-agent/src/lib.rs:132` | `pub const fn renewal_deadline(&self) -> Option<Tick> {` |
| `const` | `fn` | `crates/heptabao-agent/src/lib.rs:136` | `pub const fn token_generation(&self) -> u64 {` |
| `fn` | `requires_reconciliation` | `crates/heptabao-agent/src/lib.rs:140` | `pub fn requires_reconciliation(&self) -> bool {` |
| `fn` | `start` | `crates/heptabao-agent/src/lib.rs:144` | `pub fn start(&mut self) -> Result<(), AgentError> {` |
| `fn` | `authentication_succeeded` | `crates/heptabao-agent/src/lib.rs:150` | `pub fn authentication_succeeded(` |
| `fn` | `authentication_failed_before_entry` | `crates/heptabao-agent/src/lib.rs:159` | `pub fn authentication_failed_before_entry(&mut self, now: Tick) -> Result<Tick, AgentError> {` |
| `fn` | `retry_authentication` | `crates/heptabao-agent/src/lib.rs:180` | `pub fn retry_authentication(&mut self, now: Tick) -> Result<(), AgentError> {` |
| `fn` | `begin_renewal` | `crates/heptabao-agent/src/lib.rs:191` | `pub fn begin_renewal(&mut self, now: Tick) -> Result<(), AgentError> {` |
| `fn` | `renewal_succeeded` | `crates/heptabao-agent/src/lib.rs:202` | `pub fn renewal_succeeded(&mut self, now: Tick, ttl_ticks: u64) -> Result<(), AgentError> {` |
| `fn` | `begin_revocation` | `crates/heptabao-agent/src/lib.rs:207` | `pub fn begin_revocation(&mut self) -> Result<(), AgentError> {` |
| `fn` | `revocation_succeeded` | `crates/heptabao-agent/src/lib.rs:213` | `pub fn revocation_succeeded(&mut self) -> Result<(), AgentError> {` |
| `fn` | `mark_outcome_unknown_after_entry` | `crates/heptabao-agent/src/lib.rs:221` | `pub fn mark_outcome_unknown_after_entry(` |
| `fn` | `reconcile` | `crates/heptabao-agent/src/lib.rs:237` | `pub fn reconcile(&mut self, state: ReconciledAgentState) -> Result<(), AgentError> {` |
| `enum` | `AgentError` | `crates/heptabao-agent/src/lib.rs:325` | `pub enum AgentError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

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

Current executable anchors (source assertions, not a claim that tests were rerun for this documentation edit):

- [`tests::authentication_renewal_and_revocation_are_monotonic`](../../crates/heptabao-agent/src/lib.rs) checks the success transitions and generation increment through renewal and revocation.
- [`tests::retry_backoff_is_bounded_and_deadline_checked`](../../crates/heptabao-agent/src/lib.rs) checks the 2, 4, 8, 8 tick backoff sequence and rejects early retry.
- [`tests::unknown_after_entry_blocks_blind_retry_until_reconciled`](../../crates/heptabao-agent/src/lib.rs) checks that uncertainty blocks restart until an explicit reconciliation result.

`cargo test -p heptabao-agent` exercises the complete authentication/renewal/revocation path, bounded exponential backoff, deadline enforcement, generation monotonicity, unknown-after-entry fencing and redacted diagnostics. The V2 assurance workflow also applies formatting, strict Clippy and rustdoc checks.

## Evolution and open boundaries

Concrete authentication methods, workload identity providers, durable agent state, token sink implementations, process supervision, namespace-aware templates and OpenBao agent compatibility remain separate work. No compatibility or production claim is created by this contract package.

## Machine-verified source truth

The V1.4.7 generated facts below are a preserved historical snapshot. Current dependency/integration statements are given above; historic declaration/test counts are not a current completion measure.

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-agent`
- Crate path: `crates/heptabao-agent`
- Cargo manifest SHA-256: `081f9b1eb2c4647064ae04f7f44d4328767af72cd133b491add40e8cb38fede5`
- Rust source files: `1`
- Public lexical declarations: `27`
- Discovered test functions: `4`
- Workspace-internal dependencies: `heptabao-domain` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
