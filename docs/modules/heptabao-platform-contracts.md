# `heptabao-platform-contracts` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `platform-runtime-tls-distributed-systems`  
**Maturity:** `CONTRACT_AND_PROBE_FOUNDATION`  
**Authority effect:** `NONE`

## Purpose and non-goals

Defines provider-neutral runtime, TLS, Raft and artifact-provenance contracts used by isolated dependency probes.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: none in product runtime.
- Accountable owner role: `platform-runtime-tls-distributed-systems`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `none`

Reverse HeptaBao dependants:
- `none`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

- `const fn` (crates/heptabao-platform-contracts/src/lib.rs)
- `enum AuthorityEffect` (crates/heptabao-platform-contracts/src/lib.rs)
- `enum ClientAuthMode` (crates/heptabao-platform-contracts/src/lib.rs)
- `enum ContractError` (crates/heptabao-platform-contracts/src/lib.rs)
- `enum EvidenceMaturity` (crates/heptabao-platform-contracts/src/lib.rs)
- `enum RaftError` (crates/heptabao-platform-contracts/src/lib.rs)
- `enum RuntimeError` (crates/heptabao-platform-contracts/src/lib.rs)
- `enum TaskClass` (crates/heptabao-platform-contracts/src/lib.rs)
- `enum TlsError` (crates/heptabao-platform-contracts/src/lib.rs)
- `enum TlsVersion` (crates/heptabao-platform-contracts/src/lib.rs)
- `fn new` (crates/heptabao-platform-contracts/src/lib.rs)
- `fn validate_artifact_binding` (crates/heptabao-platform-contracts/src/lib.rs)
- `fn validate` (crates/heptabao-platform-contracts/src/lib.rs)
- `struct ApplyCursor` (crates/heptabao-platform-contracts/src/lib.rs)
- `struct ArtifactBinding` (crates/heptabao-platform-contracts/src/lib.rs)
- `struct Digest32` (crates/heptabao-platform-contracts/src/lib.rs)
- `struct LogPosition` (crates/heptabao-platform-contracts/src/lib.rs)
- `struct MonotonicInstant` (crates/heptabao-platform-contracts/src/lib.rs)
- `struct ObjectId20` (crates/heptabao-platform-contracts/src/lib.rs)
- `struct PrivateKeyHandle` (crates/heptabao-platform-contracts/src/lib.rs)
- `struct SnapshotMeta` (crates/heptabao-platform-contracts/src/lib.rs)
- `struct StagedTlsConfig` (crates/heptabao-platform-contracts/src/lib.rs)
- `struct TaskId` (crates/heptabao-platform-contracts/src/lib.rs)
- `struct TaskSpec` (crates/heptabao-platform-contracts/src/lib.rs)
- `struct TlsConfigId` (crates/heptabao-platform-contracts/src/lib.rs)
- `struct TlsProfile` (crates/heptabao-platform-contracts/src/lib.rs)
- `struct ValidatedArtifact` (crates/heptabao-platform-contracts/src/lib.rs)
- `trait ConsensusAdapter` (crates/heptabao-platform-contracts/src/lib.rs)
- `trait RuntimeAdapter` (crates/heptabao-platform-contracts/src/lib.rs)
- `trait StateMachineAdapter` (crates/heptabao-platform-contracts/src/lib.rs)
- `trait TlsProvider` (crates/heptabao-platform-contracts/src/lib.rs)
- `type BoxTask` (crates/heptabao-platform-contracts/src/lib.rs)

This index is generated from explicit `pub` declarations and is not a replacement for rustdoc. New public items require an invariant, error semantics, tests and an entry in this guide.

## State and invariants

- Critical tasks require cancellation and future deadlines.
- Raft apply order is contiguous and monotonic.
- Snapshots cannot regress applied state.
- Registry checksum mismatch and unsafe TLS policy fail closed.
- Independent reproduction has no authority effect.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

Probe retries preserve the original failed evidence and bind a new run identity, runner and exact source.

Errors are part of the public contract. Unknown, blocked, stale, corrupt, unauthenticated and unauthorized outcomes remain distinct. Callers must not collapse them into a generic retryable transport failure.

## Persistent or wire formats

This crate does not own a durable or wire format; it consumes typed contracts from dependencies.

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
- `critical_task_requires_cancellation_and_future_deadline` (crates/heptabao-platform-contracts/src/lib.rs)
- `independent_reproduction_still_has_no_authority` (crates/heptabao-platform-contracts/src/lib.rs)
- `raft_apply_is_contiguous_and_term_monotonic` (crates/heptabao-platform-contracts/src/lib.rs)
- `registry_checksum_mismatch_is_rejected` (crates/heptabao-platform-contracts/src/lib.rs)
- `registry_metadata_has_no_authority` (crates/heptabao-platform-contracts/src/lib.rs)
- `snapshot_cannot_regress_applied_state` (crates/heptabao-platform-contracts/src/lib.rs)
- `unsafe_ticket_policy_is_rejected` (crates/heptabao-platform-contracts/src/lib.rs)

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

Use isolated probe workspaces and never import candidate-specific types into product domain APIs.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- Candidates are not production-selected.
- Cross-platform and independent reproductions remain incomplete.
- Provider operational runbooks are absent.


## Traceability and maintenance

- Crate path: `crates/heptabao-platform-contracts`
- Module guide: `docs/modules/heptabao-platform-contracts.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.
