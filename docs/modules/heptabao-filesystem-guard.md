# `heptabao-filesystem-guard` developer guide

**Source baseline:** `3582fda50cd9b03ca39713814cdd8229462bbbd2`  
**Source tree:** `123c99b71c7e33169bef6033eaefb71e386ed6ca`  
**Owner role:** `storage-platform-security`  
**Maturity:** `V1_4_3_CANDIDATE_TECHNICAL_SOURCE`  
**Authority effect:** `NONE`

## Purpose and non-goals

Owns a Linux directory descriptor, validates root identity, provides bounded descriptor-relative leaf access and retains an exclusive writer fence for object lifetime.

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
Source-bound lexical inventory: `crates/heptabao-filesystem-guard`; Cargo SHA-256 `273084bb18dc1d6e29ea9cfcd156e65d92a034a6c00657224fa7a23b47d98d25`.

| Kind | Name | Source | Declaration |
|---|---|---|---|
| `const` | `MAX_GUARDED_LEAF_BYTES` | `crates/heptabao-filesystem-guard/src/lib.rs:28` | `pub const MAX_GUARDED_LEAF_BYTES: usize = 240;` |
| `struct` | `DirectoryIdentity` | `crates/heptabao-filesystem-guard/src/lib.rs:40` | `pub struct DirectoryIdentity {` |
| `const` | `fn` | `crates/heptabao-filesystem-guard/src/lib.rs:46` | `pub const fn device(self) -> u64 {` |
| `const` | `fn` | `crates/heptabao-filesystem-guard/src/lib.rs:50` | `pub const fn inode(self) -> u64 {` |
| `struct` | `ExclusiveDirectory` | `crates/heptabao-filesystem-guard/src/lib.rs:59` | `pub struct ExclusiveDirectory {` |
| `fn` | `open` | `crates/heptabao-filesystem-guard/src/lib.rs:79` | `pub fn open(root: impl AsRef<Path>) -> Result<Self, DirectoryGuardError> {` |
| `fn` | `original_path` | `crates/heptabao-filesystem-guard/src/lib.rs:97` | `pub fn original_path(&self) -> &Path {` |
| `fn` | `access_path` | `crates/heptabao-filesystem-guard/src/lib.rs:101` | `pub fn access_path(&self) -> &Path {` |
| `const` | `fn` | `crates/heptabao-filesystem-guard/src/lib.rs:105` | `pub const fn identity(&self) -> DirectoryIdentity {` |
| `fn` | `leaf_path` | `crates/heptabao-filesystem-guard/src/lib.rs:109` | `pub fn leaf_path(&self, name: &str) -> Result<PathBuf, DirectoryGuardError> {` |
| `fn` | `verify` | `crates/heptabao-filesystem-guard/src/lib.rs:114` | `pub fn verify(&self) -> Result<(), DirectoryGuardError> {` |
| `fn` | `sync_all` | `crates/heptabao-filesystem-guard/src/lib.rs:141` | `pub fn sync_all(&self) -> Result<(), DirectoryGuardError> {` |
| `enum` | `DirectoryGuardError` | `crates/heptabao-filesystem-guard/src/lib.rs:197` | `pub enum DirectoryGuardError {` |

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

- Current profile is Linux-local-filesystem only.
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
- Cargo manifest SHA-256: `273084bb18dc1d6e29ea9cfcd156e65d92a034a6c00657224fa7a23b47d98d25`
- Rust source files: `1`
- Public lexical declarations: `13`
- Discovered test functions: `7`
- Workspace-internal dependencies: none
- Authoritative inventory: `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`
- Regeneration: `python scripts/render_plan_v1_4_7.py --write`
- Verification: `python scripts/render_plan_v1_4_7.py --check`
<!-- END GENERATED V1.4.7 MODULE FACTS -->
