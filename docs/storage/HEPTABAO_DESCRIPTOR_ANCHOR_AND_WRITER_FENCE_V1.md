# HeptaBao Descriptor Anchor and Writer Fence Contract V1

## 1. Security property

The contract binds one mutable filesystem component to an already opened Linux
directory descriptor and one exclusive operating-system writer lock. A later
rename or replacement of the user-facing root pathname must not retarget the
open component.

The protected tuple is:

```text
(device, inode, descriptor, descriptor_access_path, exclusive_lock_lifetime)
```

All durable leaf access must use the descriptor access path. The original path
is diagnostic metadata only after acquisition.

## 2. Acquisition

The root must already exist and be absolute. Acquisition starts from an opened
`/` descriptor and walks every normal component through the preceding
`/proc/self/fd/<fd>` capability. Every component is opened with directory,
no-follow and close-on-exec flags; symlinks and non-directories at any level fail
closed. Device/inode identity is observed before open, from the opened handle and
after open for every component; all observations must agree. The final
`/proc/self/fd/<fd>` access path must resolve to the same identity.

The handle then acquires a non-blocking exclusive file lock. Contention returns
`WriterBusy`; it must never silently downgrade to an unlocked writer. The lock
is retained until the guard is dropped.

## 3. Root replacement

Once acquired, replacing the original pathname does not replace the held
directory. Store and journal operations continue under `/proc/self/fd/<fd>`.
Tests rename the original directory, create a fresh directory at the old path,
then prove that new `CURRENT` or `TAIL` state appears only under the moved
original directory.

## 4. Leaf operations

Only a flat bounded ASCII leaf is accepted. Separators and traversal tokens are
invalid. Reads use no-follow open followed by opened-file metadata validation.
Immutable writes use atomic `create_new`. Control updates use a new temporary
leaf, file synchronization, same-directory rename and held-directory
synchronization.

No check-then-open or check-then-create result is treated as authority.

## 5. Writer fencing

The lock is advisory and process-scoped. It protects against another
cooperating HeptaBao writer opening the same local directory inode. The second
opener must fail before it reads, adopts, initializes or mutates durable state.
The lock is released by descriptor close/drop, allowing a later process to
reopen after a clean exit or crash.

The contract does not authorize lock-file deletion or manual lock stealing and
does not infer correctness on filesystems whose lock or durability semantics
have not been independently qualified.

## 6. Failure semantics

- unsupported operating system: fail closed;
- relative root: fail closed;
- root symlink/non-directory: fail closed;
- acquisition identity drift: fail closed;
- missing or mismatched descriptor path: fail closed;
- writer lock conflict: fail closed;
- invalid leaf: fail closed;
- leaf symlink/non-regular file: fail closed;
- post-rename directory sync failure: outcome unknown;
- root identity verification failure during operation: fail before publication
  when possible, otherwise preserve explicit outcome uncertainty.

## 7. Explicit non-claims

This contract does not claim:

- protection from a privileged non-cooperating writer or compromised kernel;
- mandatory lock enforcement;
- NFS, clustered filesystem or distributed-lock correctness;
- kernel-enforced `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
  RESOLVE_NO_MAGICLINKS)` semantics; the current implementation instead performs
  an explicit descriptor-rooted component walk;
- macOS, Windows or non-Linux support;
- storage-controller power-loss behavior;
- production suitability, compatibility, qualification or authority.
