# `heptabao-filesystem-guard` developer guide

> Current reading order: the semantic supplement below and `docs/modules/CURRENT_RUNTIME_MAP.md` describe the current source. The source baseline/tree, reverse-dependency prose and V1.4.7 generated tables retained below are historical evidence. `docs/modules/CURRENT_SOURCE_BINDING.md` explains current inventory regeneration; do not run the historical renderer in write mode.

## Current API semantics and runtime integration

`ExclusiveDirectory::open(root)` owns one Unix directory descriptor and exclusive
writer lock. `root` must be an existing absolute directory; every path component
is opened without following symlinks, with pre/open/post device/inode checks.
On macOS, the fixed compatibility aliases `/var`, `/tmp` and `/etc` are first
normalized to `/private/...` only after verifying that `/` is root-owned and not
group/world-writable and that the alias is the exact root-owned platform link.
No caller-selected or later symlink is admitted.
The owner is deliberately not cloneable. New consumers use `open_file`,
`entry_exists`, `remove_file`, `rename` and independent streaming `entries`
operations on that held descriptor, never reconstruct authority from the original
pathname. `FileAccess` distinguishes Read, Write, Append, exclusive CreateNew and
CreateNewReadWrite for a private unlinked snapshot transfer;
Write does not implicitly truncate. Opened leaves must be singly linked regular
files; creation is mode 0600. Names remain flat, bounded to 240 bytes and reject
separators/traversal. `verify()` checks the held directory identity, and
`sync_all()` synchronizes that same handle even after pathname replacement.

`access_path()` is a fallible `Result<&Path, DirectoryGuardError>` compatibility
API for legacy Linux consumers only. It verifies the `/proc/self/fd` identity;
`leaf_path(name)` depends on it. Those adapters return `UnsupportedPlatform` on
non-Linux rather than falling back to ambient paths. They are not required by
the Unix relative operations. Non-Unix acquisition remains unsupported.

`normalize_root_owned_system_alias` exposes that narrow platform normalization to
other descriptor walkers; non-macOS paths are returned unchanged. It is not a
general canonicalization or symlink-following API. `open_absolute_directory_no_symlinks`
then exposes the same Unix component traversal as a read-only directory handle
without a writer lock. Snapshot parent custody uses it alongside, not instead of,
the existing durable writer. The spool has its own `ExclusiveDirectory` and a
single-transfer lease. This primitive never grants durable-write authorization or
permits competing writers.

`RootIdentityChanged`, `UnsafeRoot`, `WriterBusy` and `InvalidLeafName` fail closed.
Writer acquisition retains the bounded 64 ms fork/exec inheritance retry, not a
live-owner takeover. Dropping the owner releases the lock. Current native
`durable-service::FileBackend` operations and ordinary server initialization
publication use this owner; the server audit implementation has its own Unix
directory fence. Legacy journal/store consumers are not thereby ported. Repair
must never delete or bypass a live writer lock to force admission.

Current executable checks (source anchors, not a pass receipt):

- `root_is_descriptor_bound_and_leaf_names_are_closed` — `crates/heptabao-filesystem-guard/src/lib.rs`.
- `symlink_root_is_rejected` — `crates/heptabao-filesystem-guard/src/lib.rs`.
- `darwin_root_owned_var_alias_is_normalized_but_later_symlinks_remain_denied` — `crates/heptabao-filesystem-guard/src/relative_tests.rs`.

Run `cargo +1.98.0 test --locked -p heptabao-filesystem-guard --all-targets`. Exercise descriptor replacement, competing writers and fsync failure on each Unix target; successful unit tests do not qualify a target filesystem.

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `storage-platform-security`  
**Maturity:** `V1_4_3_CANDIDATE_TECHNICAL_SOURCE`  
**Authority effect:** `NONE`

## Purpose and non-goals

Owns a Unix directory descriptor, validates root identity, provides bounded descriptor-relative leaf access and retains an exclusive writer fence for object lifetime.

This crate does not by itself grant qualification, compatibility, production, migration or release authority. It must not be used to infer behavior outside the currently declared profile.

## Maturity and authority boundary

The source is a bounded foundation component. Technical tests establish only the checked invariants on the exact source. Production provider selection, independent review and an authority grant are separate objects.

## Ownership and trust boundary

- Authoritative writer: one cooperating process holding the directory writer lock.
- Accountable owner role: `storage-platform-security`.
- Inputs from clients, storage, providers, plugins, clocks, filesystems and evidence stores are untrusted unless explicitly wrapped by a verified type.
- Callers may not bypass typed constructors or reinterpret an error as success.

## Dependency contract

Direct HeptaBao dependencies:
- `none`

Reverse HeptaBao dependants:
- `heptabao-single-node-journal`
- `heptabao-single-node-store`

The allowed direction follows the system crate graph: provider-neutral types and APIs do not depend on adapters; governance and Oracle tooling do not enter the product authority path.

## Public API index

<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->
Source-bound lexical inventory: `crates/heptabao-filesystem-guard`; Cargo SHA-256 `a9ea4b0d9f7a5284049fbbb60a81509260c4e675ea04d5933468363738da9cb8`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `const` | `MAX_GUARDED_LEAF_BYTES` | `crates/heptabao-filesystem-guard/src/lib.rs:32` | `pub const MAX_GUARDED_LEAF_BYTES: usize = 240;` |
| `struct` | `DirectoryIdentity` | `crates/heptabao-filesystem-guard/src/lib.rs:38` | `pub struct DirectoryIdentity {` |
| `const` | `fn` | `crates/heptabao-filesystem-guard/src/lib.rs:44` | `pub const fn device(self) -> u64 {` |
| `const` | `fn` | `crates/heptabao-filesystem-guard/src/lib.rs:48` | `pub const fn inode(self) -> u64 {` |
| `struct` | `ExclusiveDirectory` | `crates/heptabao-filesystem-guard/src/lib.rs:57` | `pub struct ExclusiveDirectory {` |
| `fn` | `open` | `crates/heptabao-filesystem-guard/src/lib.rs:77` | `pub fn open(root: impl AsRef<Path>) -> Result<Self, DirectoryGuardError> {` |
| `fn` | `original_path` | `crates/heptabao-filesystem-guard/src/lib.rs:95` | `pub fn original_path(&self) -> &Path {` |
| `fn` | `access_path` | `crates/heptabao-filesystem-guard/src/lib.rs:99` | `pub fn access_path(&self) -> &Path {` |
| `const` | `fn` | `crates/heptabao-filesystem-guard/src/lib.rs:103` | `pub const fn identity(&self) -> DirectoryIdentity {` |
| `fn` | `leaf_path` | `crates/heptabao-filesystem-guard/src/lib.rs:107` | `pub fn leaf_path(&self, name: &str) -> Result<PathBuf, DirectoryGuardError> {` |
| `fn` | `verify` | `crates/heptabao-filesystem-guard/src/lib.rs:112` | `pub fn verify(&self) -> Result<(), DirectoryGuardError> {` |
| `fn` | `sync_all` | `crates/heptabao-filesystem-guard/src/lib.rs:139` | `pub fn sync_all(&self) -> Result<(), DirectoryGuardError> {` |
| `enum` | `DirectoryGuardError` | `crates/heptabao-filesystem-guard/src/lib.rs:195` | `pub enum DirectoryGuardError {` |

This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise.
<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->

## State and invariants

- Root must be absolute, non-symlink and stable across pre/open/post device and inode checks.
- Directory access is descriptor-relative with no-follow semantics.
- Leaf names are flat, bounded and closed-world.
- A second writer fails while the first guard remains alive.
- The held descriptor remains bound if the configured path is replaced.

A code change that weakens one of these invariants requires a new plan revision rather than a silent compatibility interpretation.

## Failure and retry semantics

WriterBusy is retryable only after operator-confirmed owner release. UnsupportedPlatform and root-identity drift are terminal for the selected profile.

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
- `cooperating_processes_observe_writer_fence` (crates/heptabao-filesystem-guard/src/lib.rs)
- `descriptor_survives_root_path_replacement` (crates/heptabao-filesystem-guard/src/lib.rs)
- `intermediate_symlink_is_rejected` (crates/heptabao-filesystem-guard/src/lib.rs)
- `relative_root_is_rejected` (crates/heptabao-filesystem-guard/src/lib.rs)
- `root_is_descriptor_bound_and_leaf_names_are_closed` (crates/heptabao-filesystem-guard/src/lib.rs)
- `second_open_is_fenced_until_drop` (crates/heptabao-filesystem-guard/src/lib.rs)
- `symlink_root_is_rejected` (crates/heptabao-filesystem-guard/src/lib.rs)

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

Diagnose device/inode mismatch, unsupported /proc descriptor access and writer-lock ownership without exposing secret-bearing filenames.

Diagnostics use stable typed error classes and opaque correlation identities. Operators must preserve suspect state for investigation instead of deleting files or rewriting evidence to obtain a pass.

## Known gaps

- Current local-filesystem behavior is exercised on Linux and macOS; other Unix
  kernels and filesystems are not inferred from those runs.
- Network filesystem semantics are not claimed.
- Kernel power-cut and storage-controller qualification remain external.


## Traceability and maintenance

- Crate path: `crates/heptabao-filesystem-guard`
- Module guide: `docs/modules/heptabao-filesystem-guard.md`
- Source baseline: `3582fda50cd9b03ca39713814cdd8229462bbbd2` / `123c99b71c7e33169bef6033eaefb71e386ed6ca`
- Validation: `scripts/validate_module_documentation_v1_4_4.py`
- Coverage object: `planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml`

The owner updates this document whenever public API, dependency edges, persistent formats, security invariants, retry behavior, tests or known gaps change.


### V1.4.5 ancestor provenance

Linux acquisition now walks every normal component from an opened `/` descriptor.
Each next component is reached only through the preceding `/proc/self/fd/<fd>`
capability, opened with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`, and checked for
pre-open/opened/post-open device and inode equality. Intermediate symlinks and
non-directory components fail closed. This is a descriptor walk, not a claim of
`openat2` kernel-enforced `RESOLVE_*` semantics or mount-namespace immunity.

### V1.4.6 fork/exec test isolation

The Linux writer fence is intentionally fail closed. `O_CLOEXEC` closes inherited
descriptors at exec rather than at fork, so a test subprocess created while an
unrelated guard is live can retain that lock briefly between fork and exec. The
crate-local tests therefore use one process-local `TEST_SERIAL` guard around all
writer-fence scenarios. This prevents the subprocess test from extending another
test's lock lifetime and makes exact-head and prospective-merge runs repeatable
without weakening the public fail-closed `WriterBusy` behavior.

## Machine-verified source truth

<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->
- Crate: `heptabao-filesystem-guard`
- Crate path: `crates/heptabao-filesystem-guard`
- Cargo manifest SHA-256: `a9ea4b0d9f7a5284049fbbb60a81509260c4e675ea04d5933468363738da9cb8`
- Rust source files: `1`
- Public lexical declarations: `13`
- Discovered test functions: `7`
- Workspace-internal dependencies: none
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->

## Independent module closure dossier

The detailed design, boundary, failure-semantics and exact-head acceptance record is maintained in [the module closure dossier](../module-closure/heptabao-filesystem-guard.md).
