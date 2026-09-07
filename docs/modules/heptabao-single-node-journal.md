# `heptabao-single-node-journal` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `audit-storage-platform`  
**Maturity:** `SINGLE_NODE_DURABLE_FOUNDATION`  
**Authority effect:** `NONE`

## Purpose and non-goals

Implements a strict authenticated append-only file journal with immutable entries, atomic TAIL publication and exact-next orphan reconciliation.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: one descriptor-fenced process.
- Accountable owner role: `audit-storage-platform`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `heptabao-filesystem-guard`
- `heptabao-journal-api`

Reverse HeptaBao dependants:
- `none`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-single-node-journal`; Cargo SHA-256 `6c8619a9a64dc5fa807b9c4757492aca5a75e515ec235a589e52b9ea82807325`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `const` | `MAX_JOURNAL_RECORDS` | `crates/heptabao-single-node-journal/src/lib.rs:42` | `pub const MAX_JOURNAL_RECORDS: u64 = 65_536;` |
| `struct` | `FileDurableJournal` | `crates/heptabao-single-node-journal/src/lib.rs:46` | `pub struct FileDurableJournal<A: JournalAuthenticator> {` |
| `fn` | `create_new` | `crates/heptabao-single-node-journal/src/lib.rs:68` | `pub fn create_new(` |
| `fn` | `reopen_existing` | `crates/heptabao-single-node-journal/src/lib.rs:96` | `pub fn reopen_existing(` |
| `fn` | `root` | `crates/heptabao-single-node-journal/src/lib.rs:119` | `pub fn root(&self) -> &Path {` |
| `fn` | `root_identity` | `crates/heptabao-single-node-journal/src/lib.rs:123` | `pub fn root_identity(&self) -> heptabao_filesystem_guard::DirectoryIdentity {` |
| `fn` | `reconcile_next_orphan` | `crates/heptabao-single-node-journal/src/lib.rs:127` | `pub fn reconcile_next_orphan(&mut self) -> Result<AppendReceipt, FileJournalError<A::Error>> {` |
| `enum` | `FileJournalError` | `crates/heptabao-single-node-journal/src/lib.rs:429` | `pub enum FileJournalError<E>` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and invariants

- Marker, entry and tail formats are strict and domain bound.
- Entry files are immutable and chain authenticated.
- TAIL is atomically published and directory synchronized.
- Only the exact next orphan may be reconciled.
- Corruption, stale tail, symlink and unexpected layout fail closed.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

AppendOutcomeUnknown requires replay and exact-next reconciliation. Duplicate append without reconciliation is forbidden.

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
- `create_append_replay_and_reopen_round_trip` (crates/heptabao-single-node-journal/src/lib.rs)
- `exact_next_orphan_requires_explicit_reconciliation` (crates/heptabao-single-node-journal/src/lib.rs)
- `journal_files_are_owner_only_on_unix` (crates/heptabao-single-node-journal/src/lib.rs)
- `open_journal_remains_bound_after_root_path_replacement` (crates/heptabao-single-node-journal/src/lib.rs)
- `second_journal_writer_is_fenced` (crates/heptabao-single-node-journal/src/lib.rs)
- `stale_tail_is_rejected` (crates/heptabao-single-node-journal/src/lib.rs)
- `symlinked_root_is_rejected` (crates/heptabao-single-node-journal/src/lib.rs)
- `tampered_entry_fails_authentication` (crates/heptabao-single-node-journal/src/lib.rs)

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

Report tail identity, orphan sequence and corruption class. Do not expose payload bytes in diagnostics.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- Retention/compaction and capacity control are not implemented.
- Production authenticator not selected.
- Replicated journal is absent.


## Traceability and maintenance

- Crate path: `crates/heptabao-single-node-journal`
- Module guide: `docs/modules/heptabao-single-node-journal.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.

## V1.4.6 exact-next orphan recovery

A journal append persists an immutable authenticated entry and then publishes
`TAIL`. Reopen/recovery may reconcile one exact authenticated next entry when a
crash separated those effects. Any gap, additional orphan, temporary artifact,
chain mismatch or tag failure is corruption and keeps the writer fenced.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-single-node-journal`
- Crate path: `crates/heptabao-single-node-journal`
- Cargo manifest SHA-256: `6c8619a9a64dc5fa807b9c4757492aca5a75e515ec235a589e52b9ea82807325`
- Rust source files: `1`
- Public lexical declarations: `8`
- Discovered test functions: `9`
- Workspace-internal dependencies: `heptabao-filesystem-guard` (dependencies), `heptabao-journal-api` (dependencies)
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
