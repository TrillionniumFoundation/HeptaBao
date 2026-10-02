//! PostgreSQL backend for the sealed durable-service artifacts.
//!
//! This is a separate namespace from `postgres_storage::records_v1`.  It
//! stores the service's sealed snapshot, ledger, and journal as bounded
//! chunks plus one manifest revision.  A manifest is advanced only in the
//! same repeatable-read transaction that writes the chunks, so a reader never
//! observes a half-published checkpoint.  A session advisory lock is held for
//! the lifetime of the backend and is checked inside every transaction; a
//! lost connection fences this instance and is never silently reconnected.

use crate::postgres_storage::{PgStorageConfig, PostgresStorage, StorageError};
use crate::postgres_wire::{CommitError, PgSession};
use heptabao_durable_service::{BackendBundle, BackendError, DurableBackend, RestoreProfile};
use std::fmt;

const QUALIFIED_MANIFEST: &str = "heptabao_durable_v1.manifest_v1";
const QUALIFIED_CHUNKS: &str = "heptabao_durable_v1.chunks_v1";
const MANIFEST_NAME: &str = "manifest_v1";
const CHUNKS_NAME: &str = "chunks_v1";
const LOCK_SEED: &str = "heptabao-durable-backend-v1";
const MAX_CHUNK_BYTES: usize = 768 * 1024;
const MAX_BACKEND_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

const CREATE_SCHEMA: &str = "CREATE SCHEMA IF NOT EXISTS heptabao_durable_v1";
const CREATE_MANIFEST: &str = "CREATE TABLE IF NOT EXISTS heptabao_durable_v1.manifest_v1 (format_version smallint NOT NULL DEFAULT 1 CONSTRAINT manifest_format_version CHECK (format_version = 1), scope text COLLATE \"C\" NOT NULL, revision bigint NOT NULL CONSTRAINT manifest_revision CHECK (revision > 0), snapshot_len integer NOT NULL CONSTRAINT manifest_snapshot_len CHECK (snapshot_len >= 0), ledger_len integer NOT NULL CONSTRAINT manifest_ledger_len CHECK (ledger_len >= 0), journal_len integer NOT NULL CONSTRAINT manifest_journal_len CHECK (journal_len >= 0), CONSTRAINT manifest_pk PRIMARY KEY (scope))";
const CREATE_CHUNKS: &str = "CREATE TABLE IF NOT EXISTS heptabao_durable_v1.chunks_v1 (format_version smallint NOT NULL DEFAULT 1 CONSTRAINT chunks_format_version CHECK (format_version = 1), scope text COLLATE \"C\" NOT NULL, artifact text COLLATE \"C\" NOT NULL CONSTRAINT chunks_artifact CHECK (artifact IN ('snapshot','ledger','journal')), chunk_no integer NOT NULL CONSTRAINT chunks_chunk_no CHECK (chunk_no >= 0), revision bigint NOT NULL CONSTRAINT chunks_revision CHECK (revision > 0), bytes bytea NOT NULL, CONSTRAINT chunks_pk PRIMARY KEY (scope, artifact, chunk_no))";
const REGCLASS: &str = "SELECT relkind::text, relpersistence::text, relrowsecurity::text, relforcerowsecurity::text FROM pg_class WHERE oid = to_regclass($1)";
const COLUMNS: &str = "SELECT column_name, data_type, is_nullable, collation_name FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 ORDER BY ordinal_position";
const PRIMARY_KEY: &str = "SELECT string_agg(column_name, ',' ORDER BY ordinal_position) FROM information_schema.key_column_usage WHERE table_schema = $1 AND table_name = $2 AND constraint_name IN (SELECT constraint_name FROM information_schema.table_constraints WHERE table_schema = $1 AND table_name = $2 AND constraint_type = 'PRIMARY KEY')";
const CONSTRAINTS: &str = "SELECT conname, pg_get_expr(conbin, conrelid) FROM pg_constraint WHERE conrelid = $1::regclass AND contype = 'c' ORDER BY conname";
const LOCK: &str = "SELECT pg_try_advisory_lock(hashtextextended($1, 0))";
const LOCK_HELD: &str = "SELECT count(*)::text FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'advisory' AND granted AND classid = ((hashtextextended($1, 0) >> 32) & 4294967295)::oid AND objid = (hashtextextended($1, 0) & 4294967295)::oid";
const MANIFEST_GET: &str = "SELECT revision::text, snapshot_len::text, ledger_len::text, journal_len::text FROM heptabao_durable_v1.manifest_v1 WHERE format_version = 1 AND scope = $1";
const SCOPE_CHUNK_COUNT: &str =
    "SELECT count(*)::text FROM heptabao_durable_v1.chunks_v1 WHERE scope = $1";
// Two hex-encoded chunks occupy at most 3 MiB, below the wire client's
// unchanged 4 MiB aggregate result bound (not merely its per-field bound).
// Qualify the numeric source column: ORDER BY the bare output name would
// otherwise sort the selected ::text alias as 0, 1, 10, ... instead of 0, 1, 2.
const CHUNK_PAGE: &str = "SELECT chunk_no::text, encode(bytes, 'hex') FROM heptabao_durable_v1.chunks_v1 WHERE format_version = 1 AND scope = $1 AND artifact = $2 AND chunk_no >= $3::integer ORDER BY heptabao_durable_v1.chunks_v1.chunk_no LIMIT 2";
const CHUNK_LAYOUT: &str = "SELECT chunk_no::text, octet_length(bytes)::text, revision::text FROM heptabao_durable_v1.chunks_v1 WHERE format_version = 1 AND scope = $1 AND artifact = $2 ORDER BY heptabao_durable_v1.chunks_v1.chunk_no LIMIT 87";
const JOURNAL_TAIL_UPDATE: &str = "UPDATE heptabao_durable_v1.chunks_v1 SET bytes = decode($4, 'hex'), revision = $3::bigint WHERE format_version = 1 AND scope = $1 AND artifact = 'journal' AND chunk_no = $2::integer AND bytes = decode($5, 'hex') RETURNING chunk_no::text";
const CHUNK_DELETE: &str = "DELETE FROM heptabao_durable_v1.chunks_v1 WHERE format_version = 1 AND scope = $1 AND artifact = $2";
const CHUNK_INSERT: &str = "INSERT INTO heptabao_durable_v1.chunks_v1 (format_version, scope, artifact, chunk_no, revision, bytes) VALUES (1, $1, $2, $3, $4, decode($5, 'hex'))";
const MANIFEST_INSERT: &str = "INSERT INTO heptabao_durable_v1.manifest_v1 (format_version, scope, revision, snapshot_len, ledger_len, journal_len) VALUES (1, $1, $2, $3, $4, $5)";
const MANIFEST_UPDATE: &str = "UPDATE heptabao_durable_v1.manifest_v1 SET revision = $2, snapshot_len = $3, ledger_len = $4, journal_len = $5 WHERE format_version = 1 AND scope = $1 AND revision = $6 RETURNING revision::text";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Manifest {
    revision: u64,
    snapshot_len: usize,
    ledger_len: usize,
    journal_len: usize,
}

/// A single-session durable backend. `PostgresStorage` supplies the enrolled
/// endpoint and TLS/SCRAM policy; this type owns the session and lock.
pub struct PostgresDurableBackend {
    _storage: PostgresStorage,
    scope: String,
    lock_key: String,
    session: Option<PgSession>,
    poisoned: bool,
}

impl fmt::Debug for PostgresDurableBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresDurableBackend")
            .field("scope", &self.scope)
            .field(
                "writer_fence",
                &if self.poisoned { "POISONED" } else { "HELD" },
            )
            .finish()
    }
}

impl PostgresDurableBackend {
    /// Explicitly initialize the fixed durable schema, then acquire one
    /// session-level advisory writer fence for this scope.
    pub fn initialize(config: PgStorageConfig) -> Result<Self, BackendError> {
        let scope = config.scope.clone();
        let storage = PostgresStorage::new(config).map_err(map_storage)?;
        let mut backend = Self::from_storage(storage, scope)?;
        let mut session = backend.take_session()?;
        let ddl_ok = session.begin(false).is_ok()
            && session.execute(CREATE_SCHEMA, &[]).is_ok()
            && session.execute(CREATE_MANIFEST, &[]).is_ok()
            && session.execute(CREATE_CHUNKS, &[]).is_ok();
        let shape_ok = if ddl_ok {
            schema_ok(&mut session).unwrap_or(false)
        } else {
            false
        };
        if !ddl_ok || !shape_ok {
            let _ = session.rollback();
            backend.put_poisoned(session);
            return Err(BackendError::Corrupt);
        }
        if session.commit().is_err() {
            backend.put_poisoned(session);
            return Err(BackendError::OutcomeUnknown);
        }
        backend.session = Some(session);
        Ok(backend)
    }

    /// Open an already initialized schema. This never creates or alters SQL
    /// objects, and therefore remains safe for an unprivileged deployment
    /// owner after a one-time administrator initialization.
    pub fn open(config: PgStorageConfig) -> Result<Self, BackendError> {
        let scope = config.scope.clone();
        let storage = PostgresStorage::new(config).map_err(map_storage)?;
        let mut backend = Self::from_storage(storage, scope)?;
        let mut session = backend.take_session()?;
        if !schema_ok(&mut session)? {
            backend.put_poisoned(session);
            return Err(BackendError::Corrupt);
        }
        backend.session = Some(session);
        Ok(backend)
    }

    /// Reconcile a previously prepared initialization bundle while holding the
    /// same session writer fence. An existing store is admitted only if every
    /// artifact exactly matches; no existing bytes are replaced or removed.
    /// After an unknown outcome the caller must reopen a new backend and retry
    /// with the same durably staged bundle, never generate a new identity.
    pub fn initialize_or_match(&mut self, initial: &BackendBundle) -> Result<(), BackendError> {
        self.initialize_bundle(initial, true)
    }

    fn initialize_bundle(
        &mut self,
        initial: &BackendBundle,
        accept_identical: bool,
    ) -> Result<(), BackendError> {
        initial.validate_backend()?;
        let mut session = self.transaction_with_budget(false, bundle_transfer_bytes(initial)?)?;
        match Self::manifest(&mut session, &self.scope) {
            Ok(Some(manifest)) => {
                if !accept_identical
                    || manifest.snapshot_len != initial.snapshot.len()
                    || manifest.ledger_len != initial.ledger.len()
                    || manifest.journal_len != initial.journal.len()
                {
                    self.rollback_and_retain(session);
                    return Err(BackendError::RootNotEmpty);
                }
                let existing = match Self::bundle_in(&mut session, &self.scope) {
                    Ok(bundle) => bundle,
                    Err(error) => {
                        self.rollback_and_retain(session);
                        return Err(error);
                    }
                };
                if existing != *initial {
                    self.rollback_and_retain(session);
                    return Err(BackendError::RootNotEmpty);
                }
                return self.finish(session);
            }
            Ok(None) => {}
            Err(error) => {
                self.rollback_and_retain(session);
                return Err(error);
            }
        }
        // A missing manifest does not prove the scope is empty. In particular,
        // never let write_artifact's replacement DELETE erase orphan chunks.
        let empty = match session.query(SCOPE_CHUNK_COUNT, &[&self.scope]) {
            Ok(rows) => rows.len() == 1 && rows[0].len() == 1 && rows[0][0].as_deref() == Some("0"),
            Err(_) => {
                self.rollback_and_retain(session);
                return Err(BackendError::Unavailable);
            }
        };
        if !empty {
            self.rollback_and_retain(session);
            return Err(BackendError::Corrupt);
        }
        let revision = "1";
        for (name, bytes) in [
            ("snapshot", initial.snapshot.as_slice()),
            ("ledger", initial.ledger.as_slice()),
            ("journal", initial.journal.as_slice()),
        ] {
            if let Err(e) = Self::write_artifact(&mut session, &self.scope, name, 1, bytes) {
                self.rollback_and_retain(session);
                return Err(e);
            }
        }
        let lengths = [
            initial.snapshot.len(),
            initial.ledger.len(),
            initial.journal.len(),
        ]
        .map(|v| v.to_string());
        if session
            .execute(
                MANIFEST_INSERT,
                &[&self.scope, revision, &lengths[0], &lengths[1], &lengths[2]],
            )
            .is_err()
        {
            self.put_poisoned(session);
            return Err(BackendError::Unavailable);
        }
        self.finish(session)
    }

    fn from_storage(storage: PostgresStorage, scope: String) -> Result<Self, BackendError> {
        let mut session = storage.connect().map_err(map_storage)?;
        let lock_key = format!("{LOCK_SEED}:{scope}");
        let rows = session
            .query(LOCK, &[&lock_key])
            .map_err(|_| BackendError::Unavailable)?;
        let held = rows.len() == 1
            && rows[0].len() == 1
            && matches!(rows[0][0].as_deref(), Some("t" | "true" | "TRUE"));
        if !held {
            drop(session);
            return Err(BackendError::WriterLocked);
        }
        Ok(Self {
            _storage: storage,
            scope,
            lock_key,
            session: Some(session),
            poisoned: false,
        })
    }

    fn take_session(&mut self) -> Result<PgSession, BackendError> {
        if self.poisoned {
            return Err(BackendError::OutcomeUnknown);
        }
        self.session.take().ok_or(BackendError::Unavailable)
    }

    fn put_poisoned(&mut self, session: PgSession) {
        drop(session);
        self.poisoned = true;
    }

    fn fail(&mut self, session: PgSession, error: BackendError) -> BackendError {
        self.put_poisoned(session);
        error
    }

    fn transaction(&mut self, read_only: bool) -> Result<PgSession, BackendError> {
        self.transaction_with_budget(read_only, 0)
    }

    fn transaction_with_budget(
        &mut self,
        read_only: bool,
        transfer_bytes: usize,
    ) -> Result<PgSession, BackendError> {
        let mut session = self.take_session()?;
        if session
            .begin_with_transfer_budget(read_only, transfer_bytes)
            .is_err()
        {
            return Err(self.fail(session, BackendError::Unavailable));
        }
        let held = session
            .query(LOCK_HELD, &[&self.lock_key])
            .ok()
            .and_then(|rows| {
                rows.first()
                    .and_then(|r| r.first())
                    .and_then(|v| v.as_deref())
                    .map(|v| v == "1")
            })
            .unwrap_or(false);
        if !held {
            return Err(self.fail(session, BackendError::StaleWriter));
        }
        Ok(session)
    }

    fn finish(&mut self, session: PgSession) -> Result<(), BackendError> {
        let mut session = session;
        match session.commit() {
            Ok(()) => {
                self.session = Some(session);
                Ok(())
            }
            Err(CommitError::Rejected) => Err(self.fail(session, BackendError::Unavailable)),
            Err(CommitError::OutcomeUnknown) => {
                Err(self.fail(session, BackendError::OutcomeUnknown))
            }
        }
    }

    fn rollback_and_retain(&mut self, session: PgSession) {
        let mut session = session;
        if session.rollback().is_ok() && !self.poisoned {
            self.session = Some(session);
        } else {
            self.put_poisoned(session);
        }
    }

    fn manifest(session: &mut PgSession, scope: &str) -> Result<Option<Manifest>, BackendError> {
        let rows = session
            .query(MANIFEST_GET, &[scope])
            .map_err(|_| BackendError::Unavailable)?;
        if rows.is_empty() {
            return Ok(None);
        }
        if rows.len() != 1 || rows[0].len() != 4 {
            return Err(BackendError::Corrupt);
        }
        let parse = |v: &Option<String>| {
            v.as_deref()
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or(BackendError::Corrupt)
        };
        let revision = parse(&rows[0][0])?;
        let snapshot_len =
            usize::try_from(parse(&rows[0][1])?).map_err(|_| BackendError::Corrupt)?;
        let ledger_len = usize::try_from(parse(&rows[0][2])?).map_err(|_| BackendError::Corrupt)?;
        let journal_len =
            usize::try_from(parse(&rows[0][3])?).map_err(|_| BackendError::Corrupt)?;
        if snapshot_len > MAX_BACKEND_ARTIFACT_BYTES
            || ledger_len > MAX_BACKEND_ARTIFACT_BYTES
            || journal_len > MAX_BACKEND_ARTIFACT_BYTES
            || revision == 0
        {
            return Err(BackendError::Capacity);
        }
        Ok(Some(Manifest {
            revision,
            snapshot_len,
            ledger_len,
            journal_len,
        }))
    }

    fn artifact_layout(
        session: &mut PgSession,
        scope: &str,
        artifact: &str,
        expected_len: usize,
        manifest_revision: u64,
    ) -> Result<(), BackendError> {
        let rows = session
            .query(CHUNK_LAYOUT, &[scope, artifact])
            .map_err(|_| BackendError::Unavailable)?;
        // Every writer in this schema emits full chunks followed by at most
        // one partial tail. The extra bounded row detects orphan suffixes.
        if rows.len() != expected_len.div_ceil(MAX_CHUNK_BYTES) {
            return Err(BackendError::Corrupt);
        }
        for (index, row) in rows.iter().enumerate() {
            let expected_chunk_len = (expected_len - index * MAX_CHUNK_BYTES).min(MAX_CHUNK_BYTES);
            if row.len() != 3
                || row[0].as_deref().and_then(|s| s.parse::<usize>().ok()) != Some(index)
                || row[1].as_deref().and_then(|s| s.parse::<usize>().ok())
                    != Some(expected_chunk_len)
                || !row[2]
                    .as_deref()
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_some_and(|revision| revision > 0 && revision <= manifest_revision)
            {
                return Err(BackendError::Corrupt);
            }
        }
        Ok(())
    }

    fn artifact(
        session: &mut PgSession,
        scope: &str,
        artifact: &str,
        expected_len: usize,
        manifest_revision: u64,
    ) -> Result<Vec<u8>, BackendError> {
        Self::artifact_layout(session, scope, artifact, expected_len, manifest_revision)?;
        let mut output = Vec::with_capacity(expected_len);
        let chunk_count = expected_len.div_ceil(MAX_CHUNK_BYTES);
        for first in (0..chunk_count).step_by(2) {
            let start = first.to_string();
            let rows = session
                .query(CHUNK_PAGE, &[scope, artifact, &start])
                .map_err(|_| BackendError::Unavailable)?;
            if rows.len() != (chunk_count - first).min(2) {
                return Err(BackendError::Corrupt);
            }
            for (offset, row) in rows.iter().enumerate() {
                let index = first + offset;
                if row.len() != 2
                    || row[0].as_deref().and_then(|s| s.parse::<usize>().ok()) != Some(index)
                {
                    return Err(BackendError::Corrupt);
                }
                let bytes = decode_hex(row[1].as_deref().ok_or(BackendError::Corrupt)?)?;
                if bytes.len() != (expected_len - index * MAX_CHUNK_BYTES).min(MAX_CHUNK_BYTES) {
                    return Err(BackendError::Corrupt);
                }
                output.extend_from_slice(&bytes);
            }
        }
        if output.len() != expected_len {
            return Err(BackendError::Corrupt);
        }
        Ok(output)
    }

    fn bundle_in(session: &mut PgSession, scope: &str) -> Result<BackendBundle, BackendError> {
        let manifest = Self::manifest(session, scope)?.ok_or(BackendError::MissingArtifact)?;
        BackendBundle::new(
            Self::artifact(
                session,
                scope,
                "snapshot",
                manifest.snapshot_len,
                manifest.revision,
            )?,
            Self::artifact(
                session,
                scope,
                "ledger",
                manifest.ledger_len,
                manifest.revision,
            )?,
            Self::artifact(
                session,
                scope,
                "journal",
                manifest.journal_len,
                manifest.revision,
            )?,
        )
    }

    fn write_artifact(
        session: &mut PgSession,
        scope: &str,
        artifact: &str,
        revision: u64,
        bytes: &[u8],
    ) -> Result<(), BackendError> {
        if bytes.len() > MAX_BACKEND_ARTIFACT_BYTES {
            return Err(BackendError::Capacity);
        }
        session
            .execute(CHUNK_DELETE, &[scope, artifact])
            .map_err(|_| BackendError::Unavailable)?;
        for (index, chunk) in bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
            let index = index.to_string();
            let revision = revision.to_string();
            let hex = encode_hex(chunk);
            session
                .execute(CHUNK_INSERT, &[scope, artifact, &index, &revision, &hex])
                .map_err(|_| BackendError::Unavailable)?;
        }
        Ok(())
    }

    fn append_in(
        session: &mut PgSession,
        scope: &str,
        expected_len: usize,
        frame: &[u8],
    ) -> Result<usize, BackendError> {
        let manifest = Self::manifest(session, scope)?.ok_or(BackendError::MissingArtifact)?;
        if manifest.journal_len != expected_len {
            return Err(BackendError::StaleWriter);
        }
        // Inspect bounded metadata, never reload snapshot, ledger or journal
        // payloads on append. Full ciphertext authentication remains owned by
        // DurableService on recovery, as for the filesystem backend.
        for (artifact, len) in [
            ("snapshot", manifest.snapshot_len),
            ("ledger", manifest.ledger_len),
            ("journal", manifest.journal_len),
        ] {
            Self::artifact_layout(session, scope, artifact, len, manifest.revision)?;
        }
        if frame.is_empty() {
            return Ok(expected_len);
        }
        let revision = manifest
            .revision
            .checked_add(1)
            .ok_or(BackendError::Capacity)?;
        let revision_s = revision.to_string();
        let tail_len = expected_len % MAX_CHUNK_BYTES;
        let mut consumed = 0;
        let next_chunk = expected_len.div_ceil(MAX_CHUNK_BYTES);
        if tail_len != 0 {
            let index = (next_chunk - 1).to_string();
            let rows = session
                .query(CHUNK_PAGE, &[scope, "journal", &index])
                .map_err(|_| BackendError::Unavailable)?;
            if rows.len() != 1
                || rows[0].len() != 2
                || rows[0][0].as_deref() != Some(index.as_str())
            {
                return Err(BackendError::Corrupt);
            }
            let old_hex = rows[0][1].as_deref().ok_or(BackendError::Corrupt)?;
            let mut tail = decode_hex(old_hex)?;
            if tail.len() != tail_len {
                return Err(BackendError::Corrupt);
            }
            consumed = frame.len().min(MAX_CHUNK_BYTES - tail_len);
            tail.extend_from_slice(&frame[..consumed]);
            let tail_hex = encode_hex(&tail);
            let changed = session
                .query(
                    JOURNAL_TAIL_UPDATE,
                    &[scope, &index, &revision_s, &tail_hex, old_hex],
                )
                .map_err(|_| BackendError::Unavailable)?;
            if changed.len() != 1
                || changed[0].len() != 1
                || changed[0][0].as_deref() != Some(index.as_str())
            {
                return Err(BackendError::StaleWriter);
            }
        }
        for (chunk_no, chunk) in (next_chunk..).zip(frame[consumed..].chunks(MAX_CHUNK_BYTES)) {
            let index = chunk_no.to_string();
            let hex = encode_hex(chunk);
            session
                .execute(CHUNK_INSERT, &[scope, "journal", &index, &revision_s, &hex])
                .map_err(|_| BackendError::Unavailable)?;
        }
        let next_len = expected_len + frame.len();
        let snapshot_len = manifest.snapshot_len.to_string();
        let ledger_len = manifest.ledger_len.to_string();
        let journal_len = next_len.to_string();
        let old_revision = manifest.revision.to_string();
        let changed = session
            .query(
                MANIFEST_UPDATE,
                &[
                    scope,
                    &revision_s,
                    &snapshot_len,
                    &ledger_len,
                    &journal_len,
                    &old_revision,
                ],
            )
            .map_err(|_| BackendError::Unavailable)?;
        if changed.len() != 1
            || changed[0].len() != 1
            || changed[0][0].as_deref() != Some(revision_s.as_str())
        {
            return Err(BackendError::StaleWriter);
        }
        Ok(next_len)
    }

    fn publish(
        &mut self,
        expected: &BackendBundle,
        replacement: &BackendBundle,
        journal_only: bool,
        expected_journal_len: Option<usize>,
    ) -> Result<(), BackendError> {
        replacement.validate_backend()?;
        let transfer_bytes = bundle_transfer_bytes(expected)? + bundle_transfer_bytes(replacement)?;
        let mut session = self.transaction_with_budget(false, transfer_bytes)?;
        let current = match Self::bundle_in(&mut session, &self.scope) {
            Ok(v) => v,
            Err(e) => {
                self.rollback_and_retain(session);
                return Err(e);
            }
        };
        if &current != expected
            || expected_journal_len.is_some_and(|len| current.journal.len() != len)
        {
            self.rollback_and_retain(session);
            return Err(BackendError::StaleWriter);
        }
        let current_manifest = match Self::manifest(&mut session, &self.scope) {
            Ok(Some(v)) => v,
            Ok(None) => {
                self.rollback_and_retain(session);
                return Err(BackendError::MissingArtifact);
            }
            Err(e) => {
                self.rollback_and_retain(session);
                return Err(e);
            }
        };
        let revision = current_manifest
            .revision
            .checked_add(1)
            .ok_or(BackendError::Capacity)?;
        if journal_only {
            if replacement.snapshot != current.snapshot || replacement.ledger != current.ledger {
                self.rollback_and_retain(session);
                return Err(BackendError::StaleWriter);
            }
            if let Err(error) = Self::write_artifact(
                &mut session,
                &self.scope,
                "journal",
                revision,
                &replacement.journal,
            ) {
                self.rollback_and_retain(session);
                return Err(error);
            }
        } else {
            for (name, bytes) in [
                ("snapshot", replacement.snapshot.as_slice()),
                ("ledger", replacement.ledger.as_slice()),
                ("journal", replacement.journal.as_slice()),
            ] {
                if let Err(error) =
                    Self::write_artifact(&mut session, &self.scope, name, revision, bytes)
                {
                    self.rollback_and_retain(session);
                    return Err(error);
                }
            }
        }
        let revision_s = revision.to_string();
        let lengths = [
            replacement.snapshot.len(),
            replacement.ledger.len(),
            replacement.journal.len(),
        ]
        .map(|v| v.to_string());
        let old_revision = current_manifest.revision.to_string();
        let rows = match session.query(
            MANIFEST_UPDATE,
            &[
                &self.scope,
                &revision_s,
                &lengths[0],
                &lengths[1],
                &lengths[2],
                &old_revision,
            ],
        ) {
            Ok(rows) => rows,
            Err(_) => {
                self.put_poisoned(session);
                return Err(BackendError::Unavailable);
            }
        };
        if rows.len() != 1 || rows[0].len() != 1 {
            self.rollback_and_retain(session);
            return Err(BackendError::StaleWriter);
        }
        self.finish(session)
    }
}

impl DurableBackend for PostgresDurableBackend {
    fn verify(&self) -> Result<(), BackendError> {
        if self.poisoned || self.session.is_none() {
            Err(BackendError::OutcomeUnknown)
        } else {
            Ok(())
        }
    }

    fn load(&mut self) -> Result<BackendBundle, BackendError> {
        // A short planning transaction reads only bounded lengths. The session
        // writer fence spans planning and the actual read; all payload pages
        // belong to the second transaction's single repeatable-read snapshot.
        let mut planning = self.transaction(true)?;
        let plan = match Self::manifest(&mut planning, &self.scope) {
            Ok(Some(manifest)) => manifest,
            Ok(None) => {
                self.rollback_and_retain(planning);
                return Err(BackendError::MissingArtifact);
            }
            Err(error) => {
                self.rollback_and_retain(planning);
                return Err(error);
            }
        };
        self.finish(planning)?;
        let transfer_bytes = 2 * (plan.snapshot_len + plan.ledger_len + plan.journal_len);
        let mut session = self.transaction_with_budget(true, transfer_bytes)?;
        let result = match Self::manifest(&mut session, &self.scope) {
            Ok(Some(current)) if current == plan => Self::bundle_in(&mut session, &self.scope),
            Ok(_) => Err(BackendError::StaleWriter),
            Err(error) => Err(error),
        };
        match result {
            Ok(bundle) => {
                self.finish(session)?;
                Ok(bundle)
            }
            Err(error) => {
                self.rollback_and_retain(session);
                Err(error)
            }
        }
    }

    fn initialize_empty(&mut self, initial: &BackendBundle) -> Result<(), BackendError> {
        self.initialize_bundle(initial, false)
    }

    fn append_journal(&mut self, expected_len: usize, frame: &[u8]) -> Result<usize, BackendError> {
        if frame.len() > MAX_BACKEND_ARTIFACT_BYTES
            || expected_len > MAX_BACKEND_ARTIFACT_BYTES.saturating_sub(frame.len())
        {
            return Err(BackendError::Capacity);
        }
        // Hex transfer: the new frame plus read/old-CAS/new tail payloads.
        let transfer_bytes = 2 * frame.len() + 6 * MAX_CHUNK_BYTES;
        let mut session = self.transaction_with_budget(false, transfer_bytes)?;
        match Self::append_in(&mut session, &self.scope, expected_len, frame) {
            Ok(length) => {
                self.finish(session)?;
                Ok(length)
            }
            Err(error) => {
                self.rollback_and_retain(session);
                Err(error)
            }
        }
    }

    fn truncate_journal(
        &mut self,
        expected_len: usize,
        new_len: usize,
    ) -> Result<(), BackendError> {
        if new_len > expected_len {
            return Err(BackendError::StaleWriter);
        }
        let current = self.load()?;
        if current.journal.len() != expected_len {
            return Err(BackendError::StaleWriter);
        }
        let replacement = BackendBundle::new(
            current.snapshot.clone(),
            current.ledger.clone(),
            current.journal[..new_len].to_vec(),
        )
        .map_err(|_| BackendError::Corrupt)?;
        self.publish(&current, &replacement, true, Some(expected_len))
    }

    fn publish_checkpoint(
        &mut self,
        expected: &BackendBundle,
        replacement: &BackendBundle,
    ) -> Result<(), BackendError> {
        self.publish(expected, replacement, false, None)
    }

    fn restore_profile(&self) -> Result<RestoreProfile, BackendError> {
        self.verify()?;
        Ok(RestoreProfile::Atomic)
    }

    fn publish_restore(
        &mut self,
        expected: &BackendBundle,
        replacement: &BackendBundle,
        intent: Option<&[u8]>,
    ) -> Result<(), BackendError> {
        if intent.is_some() {
            return Err(BackendError::Unsupported);
        }
        // Existing writer-fenced SQL transaction publishes the complete triple;
        // unknown COMMIT remains fenced by publish/finish as before.
        self.publish(expected, replacement, false, None)
    }

    fn close(self) -> Result<(), BackendError> {
        drop(self);
        Ok(())
    }
}

trait BackendBundleExt {
    fn validate_backend(&self) -> Result<(), BackendError>;
}
impl BackendBundleExt for BackendBundle {
    fn validate_backend(&self) -> Result<(), BackendError> {
        for bytes in [&self.snapshot, &self.ledger, &self.journal] {
            if bytes.len() > MAX_BACKEND_ARTIFACT_BYTES {
                return Err(BackendError::Capacity);
            }
        }
        Ok(())
    }
}

fn schema_ok(session: &mut PgSession) -> Result<bool, BackendError> {
    for name in [QUALIFIED_MANIFEST, QUALIFIED_CHUNKS] {
        let rows = session
            .query(REGCLASS, &[name])
            .map_err(|_| BackendError::Unavailable)?;
        if rows.len() != 1
            || rows[0].len() != 4
            || rows[0][0].as_deref() != Some("r")
            || rows[0][1].as_deref() != Some("p")
            || rows[0][2].as_deref() != Some("false")
            || rows[0][3].as_deref() != Some("false")
        {
            return Ok(false);
        }
    }
    let manifest_columns = session
        .query(COLUMNS, &["heptabao_durable_v1", MANIFEST_NAME])
        .map_err(|_| BackendError::Unavailable)?;
    let chunk_columns = session
        .query(COLUMNS, &["heptabao_durable_v1", CHUNKS_NAME])
        .map_err(|_| BackendError::Unavailable)?;
    const MANIFEST_EXPECTED: [(&str, &str, Option<&str>); 6] = [
        ("format_version", "smallint", None),
        ("scope", "text", Some("C")),
        ("revision", "bigint", None),
        ("snapshot_len", "integer", None),
        ("ledger_len", "integer", None),
        ("journal_len", "integer", None),
    ];
    const CHUNK_EXPECTED: [(&str, &str, Option<&str>); 6] = [
        ("format_version", "smallint", None),
        ("scope", "text", Some("C")),
        ("artifact", "text", Some("C")),
        ("chunk_no", "integer", None),
        ("revision", "bigint", None),
        ("bytes", "bytea", None),
    ];
    if !columns_match(&manifest_columns, &MANIFEST_EXPECTED)
        || !columns_match(&chunk_columns, &CHUNK_EXPECTED)
    {
        return Ok(false);
    }
    for (table, expected_pk) in [
        (MANIFEST_NAME, "scope"),
        (CHUNKS_NAME, "scope,artifact,chunk_no"),
    ] {
        let rows = session
            .query(PRIMARY_KEY, &["heptabao_durable_v1", table])
            .map_err(|_| BackendError::Unavailable)?;
        if rows.len() != 1 || rows[0].len() != 1 || rows[0][0].as_deref() != Some(expected_pk) {
            return Ok(false);
        }
    }
    let manifest_constraints = session
        .query(CONSTRAINTS, &[QUALIFIED_MANIFEST])
        .map_err(|_| BackendError::Unavailable)?;
    let chunk_constraints = session
        .query(CONSTRAINTS, &[QUALIFIED_CHUNKS])
        .map_err(|_| BackendError::Unavailable)?;
    if !constraint_defs(
        &manifest_constraints,
        &[
            ("manifest_format_version", "(format_version=1)"),
            ("manifest_revision", "(revision>0)"),
            ("manifest_snapshot_len", "(snapshot_len>=0)"),
            ("manifest_ledger_len", "(ledger_len>=0)"),
            ("manifest_journal_len", "(journal_len>=0)"),
        ],
    ) || !constraint_defs(
        &chunk_constraints,
        &[
            ("chunks_format_version", "(format_version=1)"),
            (
                "chunks_artifact",
                "(artifact=any(array['snapshot'::text,'ledger'::text,'journal'::text]))",
            ),
            ("chunks_chunk_no", "(chunk_no>=0)"),
            ("chunks_revision", "(revision>0)"),
        ],
    ) {
        return Ok(false);
    }
    Ok(true)
}

fn columns_match(rows: &[Vec<Option<String>>], expected: &[(&str, &str, Option<&str>)]) -> bool {
    rows.len() == expected.len()
        && rows
            .iter()
            .zip(expected)
            .all(|(row, (name, ty, collation))| {
                row.len() == 4
                    && row[0].as_deref() == Some(*name)
                    && row[1].as_deref() == Some(*ty)
                    && row[2].as_deref() == Some("NO")
                    && row[3].as_deref() == *collation
            })
}

fn constraint_defs(rows: &[Vec<Option<String>>], expected: &[(&str, &str)]) -> bool {
    rows.len() == expected.len()
        && expected.iter().all(|(name, definition_expected)| {
            rows.iter().any(|row| {
                row.len() == 2
                    && row[0].as_deref() == Some(*name)
                    && row[1]
                        .as_deref()
                        .map(|definition| {
                            let compact: String = definition
                                .chars()
                                .filter(|character| !character.is_ascii_whitespace())
                                .flat_map(char::to_lowercase)
                                .collect();
                            compact == *definition_expected
                        })
                        .unwrap_or(false)
            })
        })
}

fn map_storage(error: StorageError) -> BackendError {
    match error {
        StorageError::OutcomeUnknown => BackendError::OutcomeUnknown,
        StorageError::SchemaMismatch | StorageError::NotInitialized => BackendError::Corrupt,
        StorageError::CapacityExhausted => BackendError::Capacity,
        _ => BackendError::Unavailable,
    }
}
fn bundle_transfer_bytes(bundle: &BackendBundle) -> Result<usize, BackendError> {
    bundle.validate_backend()?;
    Ok(2 * (bundle.snapshot.len() + bundle.ledger.len() + bundle.journal.len()))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, BackendError> {
    if !value.is_ascii() || !value.len().is_multiple_of(2) {
        return Err(BackendError::Corrupt);
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| BackendError::Corrupt))
        .collect()
}
fn encode_hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(H[(byte >> 4) as usize] as char);
        out.push(H[(byte & 15) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{BackendError, decode_hex};

    #[test]
    fn malformed_utf8_hex_is_rejected_without_slicing_panics() {
        for value in ["你a", "é", "0", "gg"] {
            assert_eq!(decode_hex(value), Err(BackendError::Corrupt));
        }
        assert_eq!(decode_hex("cafe"), Ok(vec![0xca, 0xfe]));
    }
}
