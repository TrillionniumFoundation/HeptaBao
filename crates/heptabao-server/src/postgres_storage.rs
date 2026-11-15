//! Explicit PostgreSQL physical storage for the server's durable opaque records.
//!
//! This module is deliberately separate from the PostgreSQL dynamic-credentials
//! provider.  It owns a fixed, versioned table and never reuses provider tables.
//! Construction only validates an enrolled endpoint; [`PostgresStorage::initialize`]
//! is the only operation that creates the schema.  [`PostgresStorage::open`]
//! verifies an already initialized schema without changing it.
//!
//! The adapter stores opaque bytes as `bytea`, addressed by a deployment scope,
//! and a key. Schema identifiers are fixed and values are parameters. The
//! transaction uses PostgreSQL repeatable-read snapshots and a revision column
//! so a stale writer receives a conflict rather than silently overwriting a
//! concurrent commit. HA locks and service write fencing require server
//! integration; this component does not provide a leadership protocol.

use crate::outbound::{EndpointConfig, Outbound};
use crate::postgres_wire::{CommitError, PgSession};
use serde::Deserialize;
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use zeroize::Zeroize;

const SCHEMA: &str = "heptabao_storage_v1";
const TABLE: &str = "records_v1";
const QUALIFIED_TABLE: &str = "heptabao_storage_v1.records_v1";
const MAX_COMPONENT_BYTES: usize = 512;
const MAX_SCOPE_BYTES: usize = 256;
/// Fits the server's 768 KiB owner chunks with room for barrier framing.
pub const MAX_VALUE_BYTES: usize = 1024 * 1024;
const MAX_PAGE_SIZE: usize = 256;
const MAX_ACTIVE_TRANSACTIONS: usize = 16;
const ADVISORY_LOCK_SEED: &str = "heptabao-physical-storage-v1-schema";

const CREATE_SCHEMA_SQL: &str = "CREATE SCHEMA IF NOT EXISTS heptabao_storage_v1";
const CREATE_TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS heptabao_storage_v1.records_v1 (format_version smallint NOT NULL DEFAULT 1 CHECK (format_version = 1), scope text COLLATE \"C\" NOT NULL, key text COLLATE \"C\" NOT NULL, value bytea NOT NULL, revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0), PRIMARY KEY (scope, key))";
const ADVISORY_LOCK_SQL: &str = "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))";
const TABLE_REGCLASS_SQL: &str = "SELECT relkind::text, relpersistence::text, relrowsecurity::text, relforcerowsecurity::text FROM pg_class WHERE oid = to_regclass($1)";
const COLUMNS_SQL: &str = "SELECT column_name, data_type, is_nullable, collation_name FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 ORDER BY ordinal_position";
const PRIMARY_KEY_SQL: &str = "SELECT string_agg(column_name, ',' ORDER BY ordinal_position) FROM information_schema.key_column_usage WHERE table_schema = $1 AND table_name = $2 AND constraint_name IN (SELECT constraint_name FROM information_schema.table_constraints WHERE table_schema = $1 AND table_name = $2 AND constraint_type = 'PRIMARY KEY')";
const FORMAT_CHECK_SQL: &str = "SELECT count(*)::text FROM pg_constraint c JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1] WHERE c.conrelid = $1::regclass AND c.contype = 'c' AND c.convalidated AND cardinality(c.conkey) = 1 AND a.attname = 'format_version' AND pg_get_expr(c.conbin, c.conrelid) = '(format_version = 1)'";
const REVISION_CHECK_SQL: &str = "SELECT count(*)::text FROM pg_constraint c JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1] WHERE c.conrelid = $1::regclass AND c.contype = 'c' AND c.convalidated AND cardinality(c.conkey) = 1 AND a.attname = 'revision' AND pg_get_expr(c.conbin, c.conrelid) = '(revision > 0)'";
const GET_SQL: &str = "SELECT encode(value, 'hex') FROM heptabao_storage_v1.records_v1 WHERE format_version = 1 AND scope = $1 AND key = $2";
const REVISION_SQL: &str = "SELECT revision::text FROM heptabao_storage_v1.records_v1 WHERE format_version = 1 AND scope = $1 AND key = $2";
const UPDATE_SQL: &str = "UPDATE heptabao_storage_v1.records_v1 SET value = decode($3, 'hex'), revision = revision + 1 WHERE format_version = 1 AND scope = $1 AND key = $2 AND revision = $4 RETURNING revision::text";
const INSERT_SQL: &str = "INSERT INTO heptabao_storage_v1.records_v1 (format_version, scope, key, value, revision) VALUES (1, $1, $2, decode($3, 'hex'), 1) ON CONFLICT (scope, key) DO NOTHING RETURNING revision::text";
const DELETE_SQL: &str = "DELETE FROM heptabao_storage_v1.records_v1 WHERE format_version = 1 AND scope = $1 AND key = $2 RETURNING key";
const LIST_SQL: &str = "WITH children AS (SELECT DISTINCT (CASE WHEN position('/' IN substring(key FROM char_length($2) + 1)) > 0 THEN substring(key FROM char_length($2) + 1 FOR position('/' IN substring(key FROM char_length($2) + 1))) ELSE substring(key FROM char_length($2) + 1) END) COLLATE \"C\" AS child FROM heptabao_storage_v1.records_v1 WHERE format_version = 1 AND scope = $1 AND left(key, char_length($2)) = $2) SELECT child FROM children WHERE child <> '' AND ($3 = '' OR child > $3 COLLATE \"C\") ORDER BY child ASC LIMIT $4";

/// Errors intentionally contain no server text, SQL, credentials, or opaque
/// state.  PostgreSQL's wire layer has already collapsed remote errors to a
/// bounded static outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    InvalidConfig,
    InvalidKey,
    InvalidPrefix,
    InvalidValue,
    InvalidPage,
    InvalidCursor,
    Wire,
    OutcomeUnknown,
    CapacityExhausted,
    NotInitialized,
    SchemaMismatch,
    ReadOnly,
    Conflict,
    TransactionClosed,
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => "invalid PostgreSQL storage configuration",
            Self::InvalidKey => "invalid PostgreSQL storage key",
            Self::InvalidPrefix => "invalid PostgreSQL storage prefix",
            Self::InvalidValue => "invalid PostgreSQL storage value",
            Self::InvalidPage => "invalid PostgreSQL storage page size",
            Self::InvalidCursor => "invalid PostgreSQL storage cursor",
            Self::Wire => "PostgreSQL storage operation failed",
            Self::OutcomeUnknown => "PostgreSQL commit outcome unknown; reconcile before retrying",
            Self::CapacityExhausted => "PostgreSQL storage connection capacity exhausted",
            Self::NotInitialized => "PostgreSQL storage is not initialized",
            Self::SchemaMismatch => "PostgreSQL storage schema mismatch",
            Self::ReadOnly => "PostgreSQL storage transaction is read-only",
            Self::Conflict => "PostgreSQL storage write conflict",
            Self::TransactionClosed => "PostgreSQL storage transaction is closed",
        })
    }
}
impl std::error::Error for StorageError {}

/// Deployment-owned connection settings. Debug output redacts credentials;
/// the password is cleared when the final configured client is dropped.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PgStorageConfig {
    pub endpoint: EndpointConfig,
    pub connection_url: String,
    pub username: String,
    pub password: String,
    pub scope: String,
}

impl Drop for PgStorageConfig {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl fmt::Debug for PgStorageConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PgStorageConfig")
            .field("endpoint", &self.endpoint)
            .field("connection_url", &self.connection_url)
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .field("scope", &self.scope)
            .finish()
    }
}

impl PgStorageConfig {
    /// Validates configuration without opening a socket.  The database name is
    /// the single path component of `connection_url` (for example `/app`).
    pub fn validate(&self) -> Result<(), StorageError> {
        if !self.endpoint.origin.starts_with("postgresql://")
            || !valid_text(&self.connection_url, 2048)
            || !valid_text(&self.username, MAX_COMPONENT_BYTES)
            || !valid_text(&self.password, MAX_COMPONENT_BYTES)
            || !valid_component(&self.scope, MAX_SCOPE_BYTES)
        {
            return Err(StorageError::InvalidConfig);
        }
        let outbound =
            Outbound::new(vec![self.endpoint.clone()]).map_err(|_| StorageError::InvalidConfig)?;
        let (_, target) = outbound
            .endpoint(&self.connection_url, "postgresql")
            .map_err(|_| StorageError::InvalidConfig)?;
        database_from_path(&target.path).map(|_| ())
    }
}

/// A physical storage client.  Clones share the bounded transaction budget;
/// this prevents a caller from bypassing the resource limit by cloning a
/// configured client.
#[derive(Clone)]
pub struct PostgresStorage {
    config: Arc<PgStorageConfig>,
    outbound: Outbound,
    database: String,
    permits: Arc<PermitPool>,
}

impl fmt::Debug for PostgresStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresStorage")
            .field("config", &self.config)
            .field(
                "active_transactions",
                &self.permits.active.load(Ordering::Relaxed),
            )
            .field("max_active_transactions", &self.permits.max)
            .finish()
    }
}

impl PostgresStorage {
    /// Creates a client and validates enrollment.  This does not create a
    /// schema or perform network I/O; call [`Self::initialize`] explicitly.
    pub fn new(config: PgStorageConfig) -> Result<Self, StorageError> {
        config.validate()?;
        let outbound = Outbound::new(vec![config.endpoint.clone()])
            .map_err(|_| StorageError::InvalidConfig)?;
        let (_, target) = outbound
            .endpoint(&config.connection_url, "postgresql")
            .map_err(|_| StorageError::InvalidConfig)?;
        let database = database_from_path(&target.path)?;
        Ok(Self {
            config: Arc::new(config),
            outbound,
            database,
            permits: Arc::new(PermitPool {
                active: AtomicUsize::new(0),
                max: MAX_ACTIVE_TRANSACTIONS,
            }),
        })
    }

    /// Read one opaque value in an isolated transaction.
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        validate_key(key)?;
        let mut transaction = self.begin(true)?;
        let value = transaction.get(key)?;
        transaction.commit()?;
        Ok(value)
    }

    /// Write one opaque value in a transaction and commit it.
    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        validate_key(key)?;
        if value.len() > MAX_VALUE_BYTES {
            return Err(StorageError::InvalidValue);
        }
        let mut transaction = self.begin(false)?;
        transaction.put(key, value)?;
        transaction.commit()
    }

    pub fn delete(&self, key: &str) -> Result<bool, StorageError> {
        validate_key(key)?;
        let mut transaction = self.begin(false)?;
        let deleted = transaction.delete(key)?;
        transaction.commit()?;
        Ok(deleted)
    }

    /// Return shallow child names.  A child containing descendants carries a
    /// trailing slash, matching the logical list contract.
    pub fn list_page(
        &self,
        prefix: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, StorageError> {
        let mut transaction = self.begin(true)?;
        let page = transaction.list_page(prefix, Some(after), limit)?;
        transaction.commit()?;
        Ok(page.keys)
    }

    /// Creates the fixed schema/table after taking a database advisory lock.
    /// Existing objects are verified exactly and are never migrated or dropped.
    pub fn initialize(&self) -> Result<(), StorageError> {
        let _permit = self.permits.acquire()?;
        let mut session = self.connect()?;
        if let Err(error) = session.begin(false) {
            return Err(map_wire(error));
        }
        if let Err(error) = self.initialize_in_transaction(&mut session) {
            let _ = session.rollback();
            return Err(map_wire(error));
        }
        session.commit().map_err(map_commit)
    }

    /// Opens an existing store and verifies its fixed schema without changing
    /// it.  A missing relation is reported separately from a malformed one.
    pub fn open(&self) -> Result<(), StorageError> {
        let _permit = self.permits.acquire()?;
        let mut session = self.connect()?;
        if let Err(error) = session.begin(true) {
            return Err(map_wire(error));
        }
        if let Err(error) = self.verify_schema(&mut session) {
            let _ = session.rollback();
            return Err(error);
        }
        session.commit().map_err(map_commit)
    }

    /// Begins a repeatable-read transaction. Scope is
    /// fixed by the deployment config and cannot be selected by a request.
    pub fn begin(&self, read_only: bool) -> Result<PostgresTransaction, StorageError> {
        let permit = self.permits.acquire()?;
        let mut session = self.connect()?;
        if let Err(error) = session.begin(read_only) {
            return Err(map_wire(error));
        }
        if let Err(error) = self.verify_schema(&mut session) {
            let _ = session.rollback();
            return Err(error);
        }
        Ok(PostgresTransaction {
            session: Some(session),
            scope: self.config.scope.clone(),
            read_only,
            permit: Some(permit),
        })
    }

    /// Open one enrolled PostgreSQL session for a specialized physical
    /// backend. The caller owns the session and must never reconnect after an
    /// uncertain result; this is crate-visible by design.
    pub(crate) fn connect(&self) -> Result<PgSession, StorageError> {
        let (endpoint, _) = self
            .outbound
            .endpoint(&self.config.connection_url, "postgresql")
            .map_err(|_| StorageError::InvalidConfig)?;
        PgSession::connect(
            &endpoint,
            &self.database,
            &self.config.username,
            &self.config.password,
        )
        .map_err(map_wire)
    }

    fn initialize_in_transaction(&self, session: &mut PgSession) -> Result<(), &'static str> {
        session.query(ADVISORY_LOCK_SQL, &[ADVISORY_LOCK_SEED])?;
        session.execute(CREATE_SCHEMA_SQL, &[])?;
        session.execute(CREATE_TABLE_SQL, &[])?;
        self.verify_schema(session)
            .map_err(|_| "PostgreSQL schema verification failed")
    }

    fn verify_schema(&self, session: &mut PgSession) -> Result<(), StorageError> {
        let relation = session
            .query(TABLE_REGCLASS_SQL, &[QUALIFIED_TABLE])
            .map_err(map_wire)?;
        if relation.is_empty() {
            return Err(StorageError::NotInitialized);
        }
        if relation.len() != 1
            || !relation[0].iter().map(Option::as_deref).eq([
                Some("r"),
                Some("p"),
                Some("false"),
                Some("false"),
            ])
        {
            return Err(StorageError::SchemaMismatch);
        }
        let columns = session
            .query(COLUMNS_SQL, &[SCHEMA, TABLE])
            .map_err(map_wire)?;
        const EXPECTED: [(&str, &str, Option<&str>); 5] = [
            ("format_version", "smallint", None),
            ("scope", "text", Some("C")),
            ("key", "text", Some("C")),
            ("value", "bytea", None),
            ("revision", "bigint", None),
        ];
        if columns.len() != EXPECTED.len()
            || columns.iter().zip(EXPECTED).any(|(row, expected)| {
                row.len() != 4
                    || row[0].as_deref() != Some(expected.0)
                    || row[1].as_deref() != Some(expected.1)
                    || row[2].as_deref() != Some("NO")
                    || row[3].as_deref() != expected.2
            })
        {
            return Err(StorageError::SchemaMismatch);
        }
        let primary_key = session
            .query(PRIMARY_KEY_SQL, &[SCHEMA, TABLE])
            .map_err(map_wire)?;
        if primary_key.len() != 1
            || primary_key[0].len() != 1
            || primary_key[0][0].as_deref() != Some("scope,key")
        {
            return Err(StorageError::SchemaMismatch);
        }
        for check_sql in [FORMAT_CHECK_SQL, REVISION_CHECK_SQL] {
            let check = session
                .query(check_sql, &[QUALIFIED_TABLE])
                .map_err(map_wire)?;
            if check.len() != 1 || check[0].len() != 1 || check[0][0].as_deref() != Some("1") {
                return Err(StorageError::SchemaMismatch);
            }
        }
        Ok(())
    }
}

/// A transaction with a fixed storage scope.  Dropping an unfinished
/// transaction closes/rolls back the PostgreSQL session and releases its
/// shared permit; no implicit commit exists.
pub struct PostgresTransaction {
    session: Option<PgSession>,
    scope: String,
    read_only: bool,
    permit: Option<Permit>,
}

impl fmt::Debug for PostgresTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresTransaction")
            .field("scope", &self.scope)
            .field("read_only", &self.read_only)
            .field("active", &self.session.is_some())
            .finish()
    }
}

impl PostgresTransaction {
    pub fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        validate_key(key)?;
        let scope = self.scope.clone();
        let rows = self
            .session_mut()?
            .query(GET_SQL, &[&scope, key])
            .map_err(map_wire)?;
        if rows.is_empty() {
            return Ok(None);
        }
        if rows.len() != 1 || rows[0].len() != 1 {
            return Err(StorageError::Wire);
        }
        let encoded = rows[0][0].as_deref().ok_or(StorageError::Wire)?;
        Ok(Some(decode_hex(encoded)?))
    }

    pub fn put(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        validate_key(key)?;
        if value.len() > MAX_VALUE_BYTES {
            return Err(StorageError::InvalidValue);
        }
        self.ensure_writable()?;
        let encoded = encode_hex(value);
        let scope = self.scope.clone();
        let revision_rows = self
            .session_mut()?
            .query(REVISION_SQL, &[&scope, key])
            .map_err(map_wire)?;
        if revision_rows.len() > 1 || revision_rows.iter().any(|row| row.len() != 1) {
            return Err(StorageError::Wire);
        }
        if let Some(row) = revision_rows.first() {
            let revision = row[0].as_deref().ok_or(StorageError::Wire)?;
            let rows = self
                .session_mut()?
                .query(UPDATE_SQL, &[&scope, key, &encoded, revision])
                .map_err(map_wire)?;
            return if rows.len() == 1 && rows[0].len() == 1 {
                Ok(())
            } else if rows.is_empty() {
                Err(self.abort_without_network(StorageError::Conflict))
            } else {
                Err(StorageError::Wire)
            };
        }
        let rows = self
            .session_mut()?
            .query(INSERT_SQL, &[&scope, key, &encoded])
            .map_err(map_wire)?;
        if rows.len() == 1 && rows[0].len() == 1 {
            Ok(())
        } else if rows.is_empty() {
            Err(self.abort_without_network(StorageError::Conflict))
        } else {
            Err(StorageError::Wire)
        }
    }

    pub fn delete(&mut self, key: &str) -> Result<bool, StorageError> {
        validate_key(key)?;
        self.ensure_writable()?;
        let scope = self.scope.clone();
        let rows = self
            .session_mut()?
            .query(DELETE_SQL, &[&scope, key])
            .map_err(map_wire)?;
        if rows.is_empty() {
            Ok(false)
        } else if rows.len() == 1 && rows[0].len() == 1 {
            Ok(true)
        } else {
            Err(StorageError::Wire)
        }
    }

    pub fn list_page(
        &mut self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<StoragePage, StorageError> {
        if !valid_prefix(prefix, MAX_COMPONENT_BYTES) {
            return Err(StorageError::InvalidPrefix);
        }
        if limit == 0 || limit > MAX_PAGE_SIZE {
            return Err(StorageError::InvalidPage);
        }
        if let Some(cursor) = after
            && !valid_prefix(cursor, MAX_COMPONENT_BYTES)
        {
            return Err(StorageError::InvalidCursor);
        }
        // Fetch one extra row to make continuation explicit without relying on
        // an offset, which is unstable under concurrent writers.
        let requested = (limit + 1).to_string();
        let cursor = after.unwrap_or("");
        let scope = self.scope.clone();
        let rows = self
            .session_mut()?
            .query(LIST_SQL, &[&scope, prefix, cursor, &requested])
            .map_err(map_wire)?;
        page_from_rows(rows, limit)
    }

    pub fn commit(mut self) -> Result<(), StorageError> {
        let mut session = self.session.take().ok_or(StorageError::TransactionClosed)?;
        let result = session.commit().map_err(map_commit);
        self.permit.take();
        result
    }

    pub fn rollback(mut self) -> Result<(), StorageError> {
        let mut session = self.session.take().ok_or(StorageError::TransactionClosed)?;
        let result = session.rollback().map_err(map_wire);
        self.permit.take();
        result
    }

    fn ensure_writable(&self) -> Result<(), StorageError> {
        if self.read_only {
            Err(StorageError::ReadOnly)
        } else {
            Ok(())
        }
    }

    fn abort_without_network(&mut self, error: StorageError) -> StorageError {
        // Closing the TLS stream causes PostgreSQL to roll back an open
        // transaction.  Avoid issuing a blocking best-effort network rollback
        // from an error path or from Drop.
        self.session.take();
        self.permit.take();
        error
    }

    fn session_mut(&mut self) -> Result<&mut PgSession, StorageError> {
        self.session.as_mut().ok_or(StorageError::TransactionClosed)
    }
}

impl Drop for PostgresTransaction {
    fn drop(&mut self) {
        // Dropping the socket is PostgreSQL's rollback boundary.  Never block
        // a destructor on a remote acknowledgement.
        self.session.take();
        self.permit.take();
    }
}

/// Shallow list page.  Values are intentionally not fetched for list
/// operations, preserving the logical storage contract and limiting exposure.
pub struct StoragePage {
    pub keys: Vec<String>,
    pub next: Option<String>,
}
impl fmt::Debug for StoragePage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoragePage")
            .field("keys", &self.keys.len())
            .field("next", &self.next.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

struct PermitPool {
    active: AtomicUsize,
    max: usize,
}
impl fmt::Debug for PermitPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PermitPool")
            .field("active", &self.active.load(Ordering::Relaxed))
            .field("max", &self.max)
            .finish()
    }
}
struct Permit {
    pool: Arc<PermitPool>,
}
impl fmt::Debug for Permit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Permit([HELD])")
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.pool.active.fetch_sub(1, Ordering::AcqRel);
    }
}
impl PermitPool {
    fn acquire(self: &Arc<Self>) -> Result<Permit, StorageError> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.max {
                return Err(StorageError::CapacityExhausted);
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(Permit {
                        pool: Arc::clone(self),
                    });
                }
                Err(next) => current = next,
            }
        }
    }
}

fn map_commit(error: CommitError) -> StorageError {
    match error {
        CommitError::Rejected => StorageError::Wire,
        CommitError::OutcomeUnknown => StorageError::OutcomeUnknown,
    }
}
fn map_wire(_: &'static str) -> StorageError {
    StorageError::Wire
}
fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte >= 32 && byte != 127 && byte != 0)
}
fn valid_component(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.chars().any(|character| character.is_control())
}
fn valid_prefix(value: &str, max: usize) -> bool {
    value.len() <= max && !value.chars().any(|character| character.is_control())
}
fn validate_key(value: &str) -> Result<(), StorageError> {
    if valid_component(value, MAX_COMPONENT_BYTES) {
        Ok(())
    } else {
        Err(StorageError::InvalidKey)
    }
}
fn database_from_path(path: &str) -> Result<String, StorageError> {
    let database = path.strip_prefix('/').ok_or(StorageError::InvalidConfig)?;
    if database.is_empty() || database.contains('/') || !valid_text(database, MAX_COMPONENT_BYTES) {
        return Err(StorageError::InvalidConfig);
    }
    Ok(database.to_owned())
}
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
fn decode_hex(encoded: &str) -> Result<Vec<u8>, StorageError> {
    if !encoded.len().is_multiple_of(2)
        || encoded.len() / 2 > MAX_VALUE_BYTES
        || !encoded.is_ascii()
    {
        return Err(StorageError::Wire);
    }
    let mut bytes = Vec::with_capacity(encoded.len() / 2);
    let chars = encoded.as_bytes();
    for pair in chars.as_chunks::<2>().0 {
        let high = hex_digit(pair[0]).ok_or(StorageError::Wire)?;
        let low = hex_digit(pair[1]).ok_or(StorageError::Wire)?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
fn page_from_rows(
    rows: Vec<Vec<Option<String>>>,
    limit: usize,
) -> Result<StoragePage, StorageError> {
    if rows.len() > limit + 1 {
        return Err(StorageError::Wire);
    }
    let has_next = rows.len() > limit;
    let mut keys = Vec::with_capacity(rows.len().min(limit));
    for row in rows.into_iter().take(limit) {
        if row.len() != 1 {
            return Err(StorageError::Wire);
        }
        let key = row[0].as_deref().ok_or(StorageError::Wire)?;
        if !valid_component(key, MAX_COMPONENT_BYTES) {
            return Err(StorageError::Wire);
        }
        keys.push(key.to_owned());
    }
    let next = has_next.then(|| keys.last().cloned()).flatten();
    Ok(StoragePage { keys, next })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_values_round_trip_through_hex() -> Result<(), StorageError> {
        let value = [0, 1, 0x7f, 0xfe, b'%', b'_'];
        assert_eq!(decode_hex(&encode_hex(&value))?, value);
        assert!(decode_hex("bad").is_err());
        assert!(decode_hex("zz").is_err());
        Ok(())
    }

    #[test]
    fn shallow_page_parser_retains_continuation() -> Result<(), StorageError> {
        let rows = vec![
            vec![Some("a".to_owned())],
            vec![Some("a/".to_owned())],
            vec![Some("ab".to_owned())],
        ];
        let page = page_from_rows(rows, 2)?;
        assert_eq!(page.keys, ["a", "a/"]);
        assert_eq!(page.next.as_deref(), Some("a/"));
        Ok(())
    }

    #[test]
    fn components_reject_controls_but_allow_unicode_and_literal_wildcards() {
        assert!(valid_component("namespace/%/_/中文", MAX_COMPONENT_BYTES));
        assert!(valid_prefix("", MAX_COMPONENT_BYTES));
        assert!(!valid_component("bad\nvalue", MAX_COMPONENT_BYTES));
        assert!(!valid_component("", MAX_COMPONENT_BYTES));
    }

    #[test]
    fn connection_permits_are_shared_and_return_on_drop() -> Result<(), StorageError> {
        let pool = Arc::new(PermitPool {
            active: AtomicUsize::new(0),
            max: 2,
        });
        let first = pool.acquire()?;
        let second = Arc::clone(&pool).acquire()?;
        assert!(matches!(
            pool.acquire(),
            Err(StorageError::CapacityExhausted)
        ));
        drop(first);
        let replacement = pool.acquire()?;
        assert_eq!(pool.active.load(Ordering::Acquire), 2);
        drop(second);
        drop(replacement);
        assert_eq!(pool.active.load(Ordering::Acquire), 0);
        Ok(())
    }
}
