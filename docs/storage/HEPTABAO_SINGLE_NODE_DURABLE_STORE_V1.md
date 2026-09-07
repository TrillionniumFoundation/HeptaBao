# HeptaBao Single-Node Durable Store Contract V1

## 1. Profile

```text
profile = HB-P1-DEV-DURABLE-SINGLE-PROCESS
production_supported = false
multi_process_supported = false
authority_effect = NONE
```

The profile validates generation and crash-boundary structure before a
production backend or cryptographic provider is selected. It stores only
opaque bytes. The `heptabao-durable-core` composition is responsible for
sealing plaintext before those bytes reach this store.

## 2. Directory contract

The configured root must be an existing absolute directory. Every component
observed during open must be a directory and must not be a symlink. The
implementation never creates a missing root and never interprets a damaged or
missing initialized generation as an empty database.

```text
<root>/
  heptabao.marker
  CURRENT
  generation-00000000000000000001.hbs
  generation-00000000000000000002.hbs
  ...
```

Generation bundles are immutable. Reuse of an existing generation filename is
an error. Unknown entries are rejected by `create_new`; unresolved temporary
replacement files block legacy adoption.

## 3. Lifecycle operations

### CreateNew

- root exists, is absolute, is safe and is empty;
- current generation is `None`;
- no marker or default state is written merely by opening;
- the first successful commit publishes generation 1, `CURRENT`, then the
  initialization marker.

### ReopenExisting

- marker is required and must bind the exact domain and integrity algorithm;
- `CURRENT` is required and must identify a non-zero generation and non-zero
  digest;
- the selected immutable bundle must be regular, bounded, strict and digest
  valid;
- no legacy adoption or initialization is attempted.

### AdoptLegacy

- marker must be absent;
- unresolved temporary artifacts are forbidden;
- `CURRENT` and its selected bundle must pass all normal validation;
- only then is the marker atomically published and directory-synced.

The lifecycle mode is caller selected. Reopen never silently calls adoption.

## 4. Generation commit protocol

For an expected current generation `G` and candidate opaque state:

1. validate the live marker/current/bundle against in-memory `G`;
2. reject a stale expected generation;
3. compute `G+1` with checked arithmetic, or 1 for a fresh store;
4. compute the injected integrity digest over domain, generation and bytes;
5. create the immutable generation file with `create_new`;
6. write all bytes, flush and `sync_all` the file;
7. sync the parent directory;
8. write and sync a unique `CURRENT` temporary file;
9. atomically rename it over `CURRENT`;
10. sync the storage directory;
11. on the first commit, atomically publish and sync the marker;
12. reread `CURRENT` and the bundle and verify every binding;
13. update in-memory current state and return the receipt.

If an error occurs after `CURRENT` may have changed, the operation returns
`CommitOutcomeUnknown`. Callers must reconcile by reopening/loading the exact
operation state before retrying. Blind creation retry is forbidden.

## 5. Strict formats

All integer fields are big-endian. Every decoder rejects truncation, invalid
magic/version, zero generation/digest, impossible lengths, invalid UTF-8 and
trailing bytes.

### Marker

```text
magic
u16 domain_length
u16 integrity_algorithm_length
domain bytes
integrity algorithm bytes
```

### CURRENT

```text
magic
u64 generation
32-byte state digest
```

### Generation bundle

```text
magic
u64 generation
u16 domain_length
u16 integrity_algorithm_length
u64 state_length
32-byte state digest
domain bytes
integrity algorithm bytes
opaque state bytes
```

The format deliberately records the integrity algorithm identity. Silent
algorithm drift is corruption rather than an upgrade.

## 6. Failure classification

| Condition | Required outcome |
|---|---|
| relative, symlinked or non-directory root | reject |
| non-empty CreateNew root | reject |
| missing marker on ReopenExisting | reject |
| present marker on AdoptLegacy | reject |
| missing `CURRENT` after initialization | reject |
| non-regular marker/current/bundle | reject |
| generation/digest/domain/algorithm mismatch | reject |
| truncation, trailing bytes or invalid length | reject |
| stale CAS generation | reject before publication |
| existing next-generation filename | reject and require investigation |
| possible `CURRENT` publication without durable proof | outcome unknown |
| corrupt current generation with older bundle present | reject; no fallback |

## 7. Security boundary

The injected `IntegrityProvider` gives corruption binding for the selected
profile. It is not automatically an authenticity boundary against an attacker
who can rewrite the entire directory. Production qualification requires a
reviewed cryptographic construction and a rollback anchor outside the mutable
storage root.

The current pure-`std` path checks remain vulnerable to races between path
inspection and open. A production filesystem provider must use
handle/descriptor-relative no-follow operations, explicit permissions and
writer fencing. Cross-platform directory-sync semantics must be qualified per
filesystem and operating-system profile.

## 8. Required tests

The exact source must exercise:

- create, first commit, load and reopen;
- stale compare-and-swap rejection;
- corrupt/truncated bundle rejection;
- missing `CURRENT` rejection;
- explicit legacy adoption and marker publication;
- non-empty create rejection;
- symlink-root rejection on Unix;
- barrier-before-storage integration and associated-data mismatch rejection;
- Rust formatter, tests and strict Clippy on the locked workspace.

Process-level tests and GitHub-hosted runners do not constitute kernel power-cut
or storage-controller qualification. `HB-BLK-EXT-006` remains open until its
separately operated laboratory evidence verifies.
