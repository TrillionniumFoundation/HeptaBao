# `heptabao-single-node-store` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `storage-platform-security`  
**Maturity:** `SINGLE_NODE_DURABLE_FOUNDATION`  
**Authority effect:** `NONE`

## Purpose and non-goals

Implements explicit create, reopen and legacy-adoption lifecycle over immutable generation bundles and an atomically published CURRENT record.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: one descriptor-fenced process.
- Accountable owner role: `storage-platform-security`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `heptabao-filesystem-guard`
- `heptabao-storage-api`

Reverse HeptaBao dependants:
- `none`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

- `enum FileStoreError` (crates/heptabao-single-node-store/src/lib.rs)
- `fn adopt_legacy` (crates/heptabao-single-node-store/src/lib.rs)
- `fn create_new` (crates/heptabao-single-node-store/src/lib.rs)
- `fn reopen_existing` (crates/heptabao-single-node-store/src/lib.rs)
- `fn root_identity` (crates/heptabao-single-node-store/src/lib.rs)
- `fn root` (crates/heptabao-single-node-store/src/lib.rs)
- `struct FileGenerationStore` (crates/heptabao-single-node-store/src/lib.rs)

This index is generated from explicit `pub` declarations and is not a replacement for rustdoc. New public items require an invariant, error semantics, tests and an entry in this guide.

## State and invariants

- Lifecycle mode is caller selected; reopen never silently adopts.
- Generation bundles are immutable and CURRENT binds exact generation/digest.
- Persist and sync precede publication and acknowledgement.
- Corrupt current state never falls back to an older generation.
- Missing initialized state and unknown layout fail closed.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

CommitOutcomeUnknown requires reopen/load and receipt reconciliation. A pre-publication orphan generation requires explicit operator-safe handling.

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
- `compare_and_swap_rejects_stale_expected_generation` (crates/heptabao-single-node-store/src/lib.rs)
- `corrupt_bundle_is_never_silently_reopened` (crates/heptabao-single-node-store/src/lib.rs)
- `create_commit_load_and_reopen_round_trip` (crates/heptabao-single-node-store/src/lib.rs)
- `create_new_rejects_non_empty_root` (crates/heptabao-single-node-store/src/lib.rs)
- `legacy_state_requires_explicit_adoption` (crates/heptabao-single-node-store/src/lib.rs)
- `missing_current_after_initialization_fails_closed` (crates/heptabao-single-node-store/src/lib.rs)
- `open_store_remains_bound_after_root_path_replacement` (crates/heptabao-single-node-store/src/lib.rs)
- `second_store_writer_is_fenced` (crates/heptabao-single-node-store/src/lib.rs)
- `symlinked_storage_root_is_rejected` (crates/heptabao-single-node-store/src/lib.rs)

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

Monitor generation, digest, marker/current integrity and writer ownership. Preserve the directory for forensic analysis after corruption.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- Exact-next orphan-generation reconciliation requires a formal operator path.
- Retention and disk-space policy are absent.
- Filesystem/controller qualification remains external.


## Traceability and maintenance

- Crate path: `crates/heptabao-single-node-store`
- Module guide: `docs/modules/heptabao-single-node-store.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.

## V1.4.6 exact orphan and permission closure

The file provider writes an immutable generation bundle before publishing
`CURRENT`. Recovery recognizes at most one exact next-generation orphan and
completes publication only when its authenticated generation and digest equal
the ledger-derived commit descriptor. Multiple, stale, malformed or divergent
artifacts fail closed.

On Unix every newly created marker, temporary control file, `CURRENT` image and
generation bundle uses mode `0600`; `durable_store_files_are_owner_only_on_unix`
checks the durable artifacts. Root-directory ownership and controller
power-loss behavior remain deployment/qualification responsibilities.
