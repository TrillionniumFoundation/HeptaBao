# `heptabao-key-lifecycle` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `cryptography-custody-core-security`  
**Maturity:** `STATE_MACHINE_FOUNDATION_IMPLEMENTED`  
**Authority effect:** `NONE`

## Purpose and non-goals

Implements a provider-neutral durable key-epoch event state machine for bootstrap, staging, rotation, retirement and revocation.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: one key-lifecycle journal writer.
- Accountable owner role: `cryptography-custody-core-security`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `heptabao-barrier-api`
- `heptabao-journal-api`

Reverse HeptaBao dependants:
- `none`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-key-lifecycle`; Cargo SHA-256 `b16bae50f3b6e4741e02846566db7bae7c98c21c69027d03eb401d5fab0c13a4`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `const` | `MAX_REASON_CODE_BYTES` | `crates/heptabao-key-lifecycle/src/lib.rs:23` | `pub const MAX_REASON_CODE_BYTES: usize = 96;` |
| `struct` | `ReasonCode` | `crates/heptabao-key-lifecycle/src/lib.rs:26` | `pub struct ReasonCode(String);` |
| `fn` | `new` | `crates/heptabao-key-lifecycle/src/lib.rs:29` | `pub fn new(value: String) -> Result<Self, KeyLifecycleContractError> {` |
| `fn` | `as_str` | `crates/heptabao-key-lifecycle/src/lib.rs:42` | `pub fn as_str(&self) -> &str {` |
| `enum` | `KeyStatus` | `crates/heptabao-key-lifecycle/src/lib.rs:54` | `pub enum KeyStatus {` |
| `enum` | `KeyUseDirective` | `crates/heptabao-key-lifecycle/src/lib.rs:63` | `pub enum KeyUseDirective {` |
| `enum` | `KeyRingEventKind` | `crates/heptabao-key-lifecycle/src/lib.rs:70` | `pub enum KeyRingEventKind {` |
| `struct` | `KeyRingEvent` | `crates/heptabao-key-lifecycle/src/lib.rs:102` | `pub struct KeyRingEvent {` |
| `const` | `fn` | `crates/heptabao-key-lifecycle/src/lib.rs:126` | `pub const fn kind(&self) -> KeyRingEventKind {` |
| `const` | `fn` | `crates/heptabao-key-lifecycle/src/lib.rs:130` | `pub const fn epoch(&self) -> KeyEpoch {` |
| `const` | `fn` | `crates/heptabao-key-lifecycle/src/lib.rs:134` | `pub const fn previous_active(&self) -> Option<KeyEpoch> {` |
| `fn` | `reason` | `crates/heptabao-key-lifecycle/src/lib.rs:138` | `pub fn reason(&self) -> &ReasonCode {` |
| `fn` | `encode` | `crates/heptabao-key-lifecycle/src/lib.rs:142` | `pub fn encode(&self) -> Result<JournalPayload, KeyLifecycleContractError> {` |
| `fn` | `decode` | `crates/heptabao-key-lifecycle/src/lib.rs:160` | `pub fn decode(bytes: &[u8]) -> Result<Self, KeyLifecycleContractError> {` |
| `struct` | `KeyRingState` | `crates/heptabao-key-lifecycle/src/lib.rs:199` | `pub struct KeyRingState {` |
| `const` | `fn` | `crates/heptabao-key-lifecycle/src/lib.rs:205` | `pub const fn active_epoch(&self) -> Option<KeyEpoch> {` |
| `fn` | `status` | `crates/heptabao-key-lifecycle/src/lib.rs:209` | `pub fn status(&self, epoch: KeyEpoch) -> Option<KeyStatus> {` |
| `fn` | `directive` | `crates/heptabao-key-lifecycle/src/lib.rs:213` | `pub fn directive(&self, epoch: KeyEpoch) -> KeyUseDirective {` |
| `fn` | `known_epoch_count` | `crates/heptabao-key-lifecycle/src/lib.rs:223` | `pub fn known_epoch_count(&self) -> usize {` |
| `enum` | `KeyLedgerWriteState` | `crates/heptabao-key-lifecycle/src/lib.rs:307` | `pub enum KeyLedgerWriteState {` |
| `struct` | `KeyRingLedger` | `crates/heptabao-key-lifecycle/src/lib.rs:312` | `pub struct KeyRingLedger<J: DurableJournal> {` |
| `fn` | `open` | `crates/heptabao-key-lifecycle/src/lib.rs:331` | `pub fn open(mut journal: J) -> Result<Self, KeyLifecycleError<J::Error>> {` |
| `const` | `fn` | `crates/heptabao-key-lifecycle/src/lib.rs:348` | `pub const fn write_state(&self) -> KeyLedgerWriteState {` |
| `const` | `fn` | `crates/heptabao-key-lifecycle/src/lib.rs:352` | `pub const fn replay_required(&self) -> bool {` |
| `const` | `fn` | `crates/heptabao-key-lifecycle/src/lib.rs:356` | `pub const fn state(&self) -> &KeyRingState {` |
| `const` | `fn` | `crates/heptabao-key-lifecycle/src/lib.rs:360` | `pub const fn journal(&self) -> &J {` |
| `fn` | `bootstrap` | `crates/heptabao-key-lifecycle/src/lib.rs:364` | `pub fn bootstrap(` |
| `fn` | `stage` | `crates/heptabao-key-lifecycle/src/lib.rs:377` | `pub fn stage(` |
| `fn` | `rotate` | `crates/heptabao-key-lifecycle/src/lib.rs:390` | `pub fn rotate(` |
| `fn` | `retire` | `crates/heptabao-key-lifecycle/src/lib.rs:404` | `pub fn retire(` |
| `fn` | `revoke` | `crates/heptabao-key-lifecycle/src/lib.rs:417` | `pub fn revoke(` |
| `fn` | `recover_after_append_failure` | `crates/heptabao-key-lifecycle/src/lib.rs:430` | `pub fn recover_after_append_failure(&mut self) -> Result<(), KeyLifecycleError<J::Error>> {` |
| `fn` | `reopen` | `crates/heptabao-key-lifecycle/src/lib.rs:449` | `pub fn reopen(self) -> Result<Self, KeyLifecycleError<J::Error>> {` |
| `enum` | `KeyLifecycleError` | `crates/heptabao-key-lifecycle/src/lib.rs:489` | `pub enum KeyLifecycleError<E>` |
| `enum` | `KeyLifecycleContractError` | `crates/heptabao-key-lifecycle/src/lib.rs:529` | `pub enum KeyLifecycleContractError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and invariants

- Bootstrap produces exactly one active epoch.
- Staged epochs are unique and strictly monotonic.
- Rotation atomically demotes the old active epoch and promotes exactly one staged epoch.
- The active epoch cannot be revoked.
- Live append and replay enforce identical rules.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

Lifecycle events are retried only by exact event identity after replay confirms they were not committed.

Errors are part of the public contract. Unknown, blocked, stale, corrupt, unauthenticated and unauthorized outcomes remain distinct. Callers must not collapse them into a generic retryable transport failure.

## Persistent or wire formats

All durable or wire encodings are versioned, bounded and strict. Decoders reject truncation, impossible lengths, invalid identity/version and trailing bytes. Exact field layouts remain normative in the linked domain contract and source tests.

Format changes require an explicit version transition, backward/forward compatibility decision, hostile decoder tests and migration/rollback treatment.

## Concurrency and cancellation

The caller must preserve single-writer or immutable-reader ownership declared by the domain. Cancellation after an irreversible provider call or durable publication changes only the waiter; it does not revoke the completed authority or commit. Shared mutable state requires a documented fence, generation or epoch.

## Security and secret handling

- Secret-bearing bytes are not logged, formatted, cloned or serialized unless an explicit audited exposure method permits it.
- `Debug` output carries only opaque identity, lengths and safe state classes.
- Buffer overwrite is best effort and does not prove allocator, swap, crash-dump or side-channel resistance.
- No real token, unseal share, recovery key, private key or production snapshot belongs in source, tests, CI or diagnostics.

## Testing and evidence

Detected crate-local tests:
- `active_revocation_and_unstaged_rotation_fail_closed` (crates/heptabao-key-lifecycle/src/lib.rs)
- `bootstrap_stage_rotate_retire_and_revoke_replay` (crates/heptabao-key-lifecycle/src/lib.rs)
- `event_decoder_rejects_trailing_bytes` (crates/heptabao-key-lifecycle/src/lib.rs)

Required local gate:

```text
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
```

Domain changes also run plan mutation tests, current platform/Oracle regressions and frozen inherited-source replay. A green run is technical evidence only.

## Extension workflow

1. Bind the exact base commit/tree and read the current plan, blocker register and this guide.
2. Add or change typed contracts before concrete adapters.
3. Define state transition, error, retry and cancellation behavior.
4. Add positive, hostile and restart/replay tests.
5. Update this guide, traceability and normative manifest in the same change.
6. Run exact-head read-only CI; preserve failed evidence.
7. Obtain independent review for storage, cryptography, security or distributed-systems critical changes.

## Operations and diagnostics

Key bytes and provider credentials never enter lifecycle events. Ceremony tooling must bind operator, provider key identity and resulting epoch.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- Production KMS/HSM and custody ceremony are not selected.
- Generation wrapping and emergency recovery are not integrated.
- Distributed epoch propagation is not implemented.


## Traceability and maintenance

- Crate path: `crates/heptabao-key-lifecycle`
- Module guide: `docs/modules/heptabao-key-lifecycle.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.


### V1.4.5 append-unknown fail-stop

`KeyRingLedger` uses the journal provider's append-failure disposition. An
`OutcomeUnknown` error transitions it to `KeyLedgerWriteState::ReplayRequired`;
stage, rotate, retire, revoke and bootstrap all fail before provider access until the
ledger is consumed by `reopen` and reconstructed through authenticated replay. The
raw journal is no longer returned to callers.

## V1.4.6 authoritative journal recovery

An append classified outcome-unknown sets `ReplayRequired`. Recovery invokes
the journal provider's authoritative recovery method rather than replaying a
possibly stale cached tail, then rebuilds the complete key-ring state before
writes resume. The hostile provider persists the key event before returning its
error.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-key-lifecycle`
- Crate path: `crates/heptabao-key-lifecycle`
- Cargo manifest SHA-256: `b16bae50f3b6e4741e02846566db7bae7c98c21c69027d03eb401d5fab0c13a4`
- Rust source files: `1`
- Public lexical declarations: `35`
- Discovered test functions: `4`
- Workspace-internal dependencies: `heptabao-barrier-api` (dependencies), `heptabao-journal-api` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
