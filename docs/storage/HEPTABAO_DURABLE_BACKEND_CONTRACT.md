# HeptaBao durable backend contract

`heptabao-durable-service` currently implements the replay protocol and the
physical files in one type.  The protocol is useful beyond a local directory,
but replacing the files with a database by editing individual `read` and
`write` calls would weaken its crash semantics.  This document fixes the
smallest boundary that lets the existing protocol use a second physical
backend while keeping the filesystem implementation as the default.

## Boundary

The backend receives **sealed bytes only**.  `Barrier::seal` and
`Barrier::open` remain in `DurableService`; a backend must never receive a
plaintext snapshot, replay record, secret, token, or request value.  The
backend owns storage of exactly three artifacts:

| Artifact | Current file | Meaning |
| --- | --- | --- |
| `Snapshot` | `state.hbs` | authenticated materialized state |
| `Ledger` | `ledger.hbl` | authenticated replay ledger checkpoint |
| `Journal` | `journal.hbj` | magic plus authenticated frames |

The backend does not interpret frame bytes.  Generation, sequence, request
binding, and recovery validation stay in `lib.rs`.

The implemented public Rust surface is:

```rust
pub struct BackendBundle {
    pub snapshot: Vec<u8>,
    pub ledger: Vec<u8>,
    pub journal: Vec<u8>,
}

pub trait DurableBackend: Send {
    /// Verify the descriptor-bound writer fence.
    fn verify(&self) -> Result<(), BackendError>;

    /// Acquire the backend's writer fence and return one bounded view.
    /// A database implementation reads the three artifacts in one snapshot.
    fn load(&mut self) -> Result<BackendBundle, BackendError>;

    /// Create an empty store and publish its initial three artifacts together.
    fn initialize_empty(&mut self, initial: &BackendBundle) -> Result<(), BackendError>;

    /// Append one complete, already-sealed journal frame. `expected_len` is
    /// the caller's last durable byte count; a mismatch is a stale-writer
    /// error. The returned length is the new durable length.
    fn append_journal(
        &mut self,
        expected_len: usize,
        frame: &[u8],
    ) -> Result<usize, BackendError>;

    /// Remove a physically incomplete tail after frame decoding has proved
    /// that only the tail is repairable.
    fn truncate_journal(
        &mut self,
        expected_len: usize,
        new_len: usize,
    ) -> Result<(), BackendError>;

    /// Publish a complete checkpoint. Filesystem backends use staged files and
    /// return an unknown outcome if publication crosses a rename boundary.
    /// Database backends must use one transaction for all three rows (or chunks
    /// plus one manifest), so readers never observe a partial bundle.
    fn publish_checkpoint(
        &mut self,
        expected: &BackendBundle,
        replacement: &BackendBundle,
    ) -> Result<(), BackendError>;

    /// Close the writer fence. This method must not send a best-effort network
    /// rollback: an unfinished database transaction is rolled back by closing
    /// the connection, and an unknown result must remain unknown to the
    /// service.
    fn close(self) -> Result<(), BackendError>
    where
        Self: Sized;
}
```

`BackendError` is intentionally a bounded, non-secret error enum.  It needs
at least `Io`, `Unavailable`, `StaleWriter`, `Capacity`, `Corrupt`, and
`OutcomeUnknown`.  Remote SQL text, endpoint URLs, credentials, and sealed
bytes must never be copied into `Display`, logs, or serialized responses.

`load` is the important part of the contract.  A PostgreSQL implementation
must read a manifest revision and all artifact rows under one repeatable-read
transaction.  The manifest revision is advanced in the same transaction as
`publish_checkpoint` and `append_journal`; a connection loss after commit is
`OutcomeUnknown`, so the live service is fenced until a fresh `load` and
normal recovery run.  A filesystem implementation can read the three files
under the existing descriptor writer fence; the service's authenticated
cross-check remains authoritative after a crash.

## Smallest integration change

Keep the current protocol code and add a defaulted second type parameter:

This stage has already moved the default service's create, reopen, append,
truncate, compaction, retirement, and restore paths behind `FileBackend`.
The service still uses the concrete filesystem backend in its public
constructor; the defaulted backend type and injected constructors below are
the next step required before a PostgreSQL backend can be selected by server
configuration.

```rust
pub struct DurableService<B: Barrier, S: DurableBackend = FileBackend> {
    backend: S,
    // barrier, decoded snapshot/ledger, replay state, and limits stay here
}
```

`FileBackend` owns `ExclusiveDirectory` and the anchored `state.hbs`,
`journal.hbj`, and `ledger.hbl` paths; move only the physical helper functions (`atomic_write`,
`append_journal_frame`, `read_bounded`, and path helpers) behind the trait.
`create_new` calls `initialize_empty`, `reopen` calls `load`, `append_frame` calls
`append_journal`, and `compact`, `retire_replay_epoch`, and
`restore_backup` call `publish_checkpoint`.  No mutation ordering or replay
decision should move into a backend.

The backend must be injected at construction, with compatibility constructors
retained:

```rust
DurableService::create_new(root, barrier, max_requests) // FileBackend
DurableService::create_new_with_backend(FileBackend::new(root), barrier, ...)
DurableService::reopen_with_backend(backend, barrier, ...)
```

This keeps all existing server call sites on the filesystem during the first
refactor.  A later server configuration can select `PostgresBackend` only
after the same contract tests and crash receipts pass.

## PostgreSQL mapping

The physical adapter already used for opaque records must not be treated as a
drop-in replacement for this protocol.  It needs a separate backend namespace
and a manifest row, for example:

```text
hb_durable_artifacts(scope, artifact, chunk_no, bytes, revision)
hb_durable_manifest(scope, revision, snapshot_generation, journal_length)
```

`artifact` is a fixed enum (`snapshot`, `ledger`, `journal`), `chunk_no` is a
bounded integer, and all identifiers are parameters or constants.  A
`publish_checkpoint` transaction writes the new chunks, deletes obsolete
chunks, then updates the manifest last.  `append_journal` writes only the new
frame chunks and advances the manifest under `revision = expected_revision`.
The adapter must derive the database from its enrolled connection URL and use
the same TLS/SCRAM and loopback policy as the existing PostgreSQL storage
client.  It must not reuse provider tables or silently create an unregistered
schema.

The 64 MiB per-artifact bound remains a service invariant.  Database rows are
smaller (the current storage client uses a 1 MiB value bound); chunking is a
physical detail and must not change logical journal bytes or sequence checks.

## Contract tests before server wiring

Add one backend contract test module and run it for `FileBackend` first and
`PostgresBackend` before selecting it in server configuration:

1. initialize then load returns the exact three sealed byte strings;
2. append succeeds at the expected length and rejects a stale length;
3. a truncated tail is repairable only through `truncate_journal`;
4. checkpoint replacement is all-or-nothing from a fresh `load`;
5. a failed/unknown commit fences the client and a reopened client recovers;
6. oversized artifacts and chunks are rejected before any write;
7. two writers cannot both hold the backend fence;
8. no backend error or debug representation contains endpoint, credential, or
   sealed payload bytes.

The PostgreSQL fixture must additionally kill the client during a committed
append, restart PostgreSQL, and prove both outcomes: a committed frame is
replayed exactly once, while an uncommitted frame is absent.  The receipt must
record the source and probe hashes, database version, and check names, while
keeping the raw PostgreSQL log private.

This adapter boundary is a prerequisite for server-level PostgreSQL storage;
it does not itself provide HA leadership, fencing, migration, or OpenBao API
compatibility.  Those claims require separate server integration and
production-style receipts.
