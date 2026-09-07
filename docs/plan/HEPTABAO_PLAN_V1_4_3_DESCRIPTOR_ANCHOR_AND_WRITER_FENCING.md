# HeptaBao Development Plan V1.4.3 — Descriptor Anchor and Writer Fencing

## 1. Authority and exact-source binding

```text
plan_id          = HEPTABAO-PLAN-2026-08-28
revision         = 1.4.3
inherited_commit = 34e8dc0caceb84288d4ef61f79cd7ca062718b63
inherited_tree   = a1a0e7ab4e5ae8d4a2a5a7cde425eaf94a54b1d7
profile          = HB-P1-DEV-DESCRIPTOR-FENCED-SINGLE-NODE
```

The inherited V1.4.2 commit is the only accepted baseline. Runtime receipts are
resolved from the exact GitHub event and commit; this source document cannot
self-issue an execution, review, compatibility, qualification or authority
receipt.

## 2. Objective

V1.4.3 removes the path-reopen and cooperating-writer races that remained in
the V1.4/V1.4.1 filesystem implementations. It adds one Linux-only,
dependency-free directory capability that:

1. opens the existing absolute root with `O_DIRECTORY`, `O_NOFOLLOW` and
   `O_CLOEXEC`;
2. proves that pre-open, opened-handle and post-open device/inode identities
   are identical;
3. proves that `/proc/self/fd/<fd>` resolves to the same opened directory;
4. acquires and retains an exclusive `File::try_lock` writer fence for the
   complete store or journal lifetime;
5. exposes only a bounded flat leaf namespace beneath the descriptor-bound
   access path;
6. fails closed on unsupported platforms rather than falling back to ordinary
   path-relative access.

The existing store and journal are then rewired to resolve every durable
object through that capability. Reads open first with no-follow semantics and
validate the opened file metadata. New immutable files use atomic
`create_new`; control publication uses descriptor-rooted temporary files,
rename, directory-handle synchronization and post-publication verification.

## 3. Bounded profile

```text
operating_system                  = linux
local_filesystem                  = required
proc_self_fd                      = required
flat_root_namespace               = required
cooperating_multi_process_fencing = supported
root_path_replacement_resistance  = supported
leaf_symlink_following            = forbidden
network_filesystem                = unsupported
hostile_noncooperating_writer     = outside_lock_authority
production_supported              = false
replicated                        = false
compatibility_supported           = false
```

The writer fence is advisory at the operating-system level. Correctness is
claimed only for HeptaBao processes that acquire the same directory lock before
mutation. The profile does not claim protection against a privileged process
that ignores advisory locks, replaces `/proc`, writes through a raw block
device or controls the kernel/filesystem.

## 4. Directory acquisition invariant

One acquisition follows:

```text
require existing absolute path
→ lstat root and reject symlink/non-directory
→ open final root with O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC
→ fstat opened handle
→ lstat root again
→ require equal device/inode across all three observations
→ resolve /proc/self/fd/<fd>
→ require descriptor path device/inode equals opened handle
→ acquire non-blocking exclusive file lock on directory handle
→ verify descriptor identity again
→ expose guarded handle
```

A lock conflict returns `WriterBusy`. A moved or replaced pathname does not
retarget an already opened store or journal: every later path is rooted at the
held descriptor. Closing or dropping the guard releases the operating-system
lock.

## 5. Flat leaf invariant

The capability accepts only non-empty bounded ASCII leaf names composed of
letters, digits, `.`, `_` and `-`. Absolute paths, separators, `.` and `..` are
rejected. The current store and journal formats use one flat directory, so no
nested path traversal is required.

Every regular-file read follows:

```text
open descriptor-rooted leaf with O_NOFOLLOW|O_CLOEXEC
→ fstat opened file
→ require regular file and bounded length
→ read at most bound + 1
→ reject overflow
```

Every immutable write follows:

```text
verify directory descriptor identity
→ create_new descriptor-rooted leaf with O_NOFOLLOW|O_CLOEXEC
→ write all
→ flush
→ fsync file
→ fsync held directory handle
```

Control-file replacement follows the same rooted temporary-file discipline,
then `rename` within the descriptor-bound directory and syncs the held
directory handle. A sync failure after rename remains outcome-unknown.

## 6. Store integration

`FileGenerationStore` owns `ExclusiveDirectory` instead of a reusable
`PathBuf`. `create_new`, `reopen_existing` and `adopt_legacy` acquire the
exclusive writer fence before inspecting state. `CURRENT`, marker and
immutable generation bundles are resolved under the held descriptor.

Generation creation no longer performs a check-then-create existence test.
`create_new` is the authoritative atomic conflict detector and maps
`AlreadyExists` to `GenerationAlreadyExists`.

A second live opener of the same directory fails with `WriterBusy`. If the
original root pathname is renamed and replaced after open, a commit still lands
in the originally opened directory and never in the replacement path.

## 7. Journal integration

`FileDurableJournal` likewise owns `ExclusiveDirectory`. Marker, `TAIL`, entry
enumeration, immutable entry creation, replay and orphan reconciliation are
all descriptor-rooted. Layout inspection checks the held root identity before
using the authenticated chain.

A second live opener fails with `WriterBusy`. If the original pathname is
replaced after open, append and tail publication remain bound to the original
directory.

## 8. Work packages

### V143-WP01 — Linux descriptor and lock capability

Implement root identity binding, `/proc/self/fd` access, exclusive writer lock,
bounded leaf validation, synchronization and hostile tests.

### V143-WP02 — Descriptor-fenced generation store

Replace internal root reuse, close read-open and check-create races, retain
outcome-unknown semantics and add live-writer/root-replacement tests.

### V143-WP03 — Descriptor-fenced authenticated journal

Anchor layout/read/write/publication paths, retain orphan reconciliation and
add live-writer/root-replacement tests.

### V143-WP04 — Exact-head and inherited-surface gate

Prove the closed 18-path delta, replay frozen V1.4.2, run current V1.4.3
hostile tests and execute Rust 1.98 format/test/strict-Clippy.

## 9. Repository blocker mapping

```text
HB-BLK-REPO-033  directory root was not held as a verified descriptor capability
HB-BLK-REPO-034  generation store lacked descriptor anchoring and writer fencing
HB-BLK-REPO-035  durable journal lacked descriptor anchoring and writer fencing
HB-BLK-REPO-036  V1.4.3 lacked a version-aware exact-head gate
```

Source presence is not execution. Technical closure requires a clean exact
head and successful canonical read-only gate. Independent storage/security
review and designated-ratifier evidence remain separate completion objects.

## 10. Remaining product boundaries

After this bounded extension, the following remain open:

- production key generation, custody, wrapping, rotation and revocation
  ceremony;
- production remote append-only rollback anchor;
- non-Linux descriptor implementations and network/distributed filesystem lock
  qualification;
- retention, archive compaction, garbage collection and off-site backup
  custody;
- replicated audit, HA recovery, online upgrade/downgrade and schema migration;
- policy, identity, token, lease, namespace and plugin domains;
- Raft membership, snapshot, standby-read and mixed-version behavior;
- Oracle-derived compatibility implementation;
- every inherited external/control blocker.

No provider, operator, production topology, lock service or compatibility
surface is selected by this revision.

## 11. Required exact execution

```text
python scripts/validate_plan_v1_4_3.py
python scripts/validate_v1_4_3_inherited_surface.py
python -m unittest discover -s tests/plan -p 'test_plan_v1_4_3.py' -v

# frozen V1.4.2 detached worktree
python scripts/validate_plan_v1_4_2.py
python scripts/validate_v1_4_2_inherited_surface.py
python -m unittest discover -s tests/plan -p 'test_plan_v1_4_2.py' -v
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings

# current exact head
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
```

The canonical workflow is read-only. Temporary materializers, source archives
and write-capable workflows must be absent from the final tree.

```text
qualification=false
compatibility_claim=false
selected_candidates=[]
selection_effect=NONE
production_authority=false
migration_authority=false
release_authority=false
authority_effect=NONE
```
