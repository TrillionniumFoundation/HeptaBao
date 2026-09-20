//! A bounded PostgreSQL v3 client: mandatory verified TLS and SCRAM-SHA-256,
//! extended-query parameters only, absolute socket deadline, no raw SQL errors.
//! It never downgrades to clear transport, MD5, or trust authentication.
use crate::outbound::{Endpoint, TlsStream};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::{digest, hmac, pbkdf2};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    num::NonZeroU32,
    time::Duration,
};
use zeroize::Zeroizing;
const MAX_FRAME: usize = 4 * 1024 * 1024;
const MAX_SQL: usize = 32 * 1024;
const MAX_PARAMETER_VALUE: usize = 2 * 1024 * 1024;
const MAX_PARAMETERS: usize = 256;
const MAX_RESULT_ROWS: usize = 4096;
const MAX_RESULT_COLUMNS: usize = 256;
const MAX_RESULT_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESULT_FIELD: usize = 2 * 1024 * 1024;
// Largest durable checkpoint: three 64 MiB artifacts, read and replacement,
// hex encoded. A single transaction has one absolute budget, never per-page.
const MAX_TRANSACTION_TRANSFER_BYTES: usize = 768 * 1024 * 1024;
const TRANSACTION_BYTES_PER_SECOND: usize = 8 * 1024 * 1024;

fn transaction_budget(transfer_bytes: usize) -> Result<Duration, &'static str> {
    if transfer_bytes > MAX_TRANSACTION_TRANSFER_BYTES {
        return Err("PostgreSQL transaction transfer budget exceeds bound");
    }
    Ok(Duration::from_secs(
        3 + transfer_bytes.div_ceil(TRANSACTION_BYTES_PER_SECOND) as u64,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadyState {
    Idle,
    InTransaction,
    FailedTransaction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitError {
    Rejected,
    OutcomeUnknown,
}

pub(crate) struct PgSession {
    stream: TlsStream,
    usable: bool,
    ready: ReadyState,
}
impl PgSession {
    pub fn connect(
        endpoint: &Endpoint,
        database: &str,
        user: &str,
        password: &str,
    ) -> Result<Self, &'static str> {
        for text in [database, user, password] {
            if text.is_empty()
                || text.len() > 512
                || !text.is_ascii()
                || text.bytes().any(|b| b < 32 || b == 127)
            {
                return Err("invalid PostgreSQL connection field");
            }
        }
        let mut socket = endpoint.connect()?;
        socket
            .write_all(&[0, 0, 0, 8, 4, 210, 22, 47])
            .map_err(|_| "PostgreSQL SSL request failed")?;
        let mut mode = [0];
        socket
            .read_exact(&mut mode)
            .map_err(|_| "PostgreSQL SSL response failed")?;
        if mode != *b"S" {
            return Err("PostgreSQL server refused TLS");
        }
        let stream = endpoint.tls(socket)?;
        let mut session = Self {
            stream,
            usable: true,
            ready: ReadyState::Idle,
        };
        let mut startup = Vec::new();
        startup.extend_from_slice(&196608u32.to_be_bytes());
        for (k, v) in [
            ("user", user),
            ("database", database),
            ("client_encoding", "UTF8"),
            (
                "options",
                "-c statement_timeout=2500 -c lock_timeout=1500 -c synchronous_commit=on",
            ),
        ] {
            cstring(&mut startup, k)?;
            cstring(&mut startup, v)?;
        }
        startup.push(0);
        session
            .stream
            .write_all(&((startup.len() + 4) as u32).to_be_bytes())
            .and_then(|_| session.stream.write_all(&startup))
            .map_err(|_| "PostgreSQL startup failed")?;
        let mut stage = 0;
        let mut scram = None;
        for _ in 0..128 {
            let (tag, bytes) = session.message_bounded(256 * 1024)?;
            match tag {
                b'R' if bytes.len() >= 4 => {
                    let kind = u32::from_be_bytes(
                        bytes[..4]
                            .try_into()
                            .map_err(|_| "invalid authentication frame")?,
                    );
                    match (stage, kind) {
                        (0, 10) => {
                            if !bytes[4..].split(|b| *b == 0).any(|m| m == b"SCRAM-SHA-256") {
                                return Err("PostgreSQL requires SCRAM-SHA-256");
                            }
                            let state = Scram::new()?;
                            let first = format!("n,,{}", state.bare);
                            let mut payload = b"SCRAM-SHA-256\0".to_vec();
                            payload.extend_from_slice(&(first.len() as u32).to_be_bytes());
                            payload.extend_from_slice(first.as_bytes());
                            session.send(b'p', &payload)?;
                            scram = Some(state);
                            stage = 1;
                        }
                        (1, 11) => {
                            let state = scram.as_mut().ok_or("missing SCRAM exchange")?;
                            let answer = state.answer(&bytes[4..], password)?;
                            session.send(b'p', answer.as_bytes())?;
                            stage = 2;
                        }
                        (2, 12) => {
                            scram
                                .as_ref()
                                .ok_or("missing SCRAM exchange")?
                                .finish(&bytes[4..])?;
                            stage = 3;
                        }
                        (3, 0) if bytes.len() == 4 => {
                            stage = 4;
                        }
                        _ => return Err("unsupported PostgreSQL authentication or sequence"),
                    }
                }
                b'S' | b'K' | b'N' if stage == 4 => {}
                b'Z' if stage == 4 && bytes.as_slice() == b"I" => return Ok(session),
                b'E' => return Err("PostgreSQL authentication rejected"),
                _ => return Err("unexpected PostgreSQL startup frame"),
            }
        }
        Err("PostgreSQL startup frame count exceeded")
    }
    fn poison<T>(&mut self, error: &'static str) -> Result<T, &'static str> {
        self.usable = false;
        Err(error)
    }
    fn check_usable(&mut self) -> Result<(), &'static str> {
        if self.usable {
            Ok(())
        } else {
            Err("PostgreSQL connection is not reusable")
        }
    }
    fn send(&mut self, tag: u8, body: &[u8]) -> Result<(), &'static str> {
        self.check_usable()?;
        if body.len() > MAX_FRAME {
            return self.poison("PostgreSQL request exceeds bound");
        }
        if self
            .stream
            .write_all(&[tag])
            .and_then(|_| {
                self.stream
                    .write_all(&((body.len() + 4) as u32).to_be_bytes())
            })
            .and_then(|_| self.stream.write_all(body))
            .and_then(|_| self.stream.flush())
            .is_err()
        {
            return self.poison("PostgreSQL request delivery uncertain");
        }
        Ok(())
    }
    fn message(&mut self) -> Result<(u8, Zeroizing<Vec<u8>>), &'static str> {
        self.message_bounded(MAX_FRAME)
    }
    fn message_bounded(&mut self, limit: usize) -> Result<(u8, Zeroizing<Vec<u8>>), &'static str> {
        let mut head = [0u8; 5];
        self.check_usable()?;
        if self.stream.read_exact(&mut head).is_err() {
            return self.poison("PostgreSQL response unavailable");
        }
        let n = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
        if !(4..=limit).contains(&n) {
            return self.poison("invalid PostgreSQL response length");
        }
        let mut body = Zeroizing::new(vec![0; n - 4]);
        if self.stream.read_exact(&mut body).is_err() {
            return self.poison("truncated PostgreSQL response");
        }
        Ok((head[0], body))
    }
    fn build_bind(parameters: &[&str]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        if parameters.len() > MAX_PARAMETERS
            || parameters
                .iter()
                .any(|value| value.len() > MAX_PARAMETER_VALUE || value.contains('\0'))
        {
            return Err("PostgreSQL parameter bound exceeded");
        }
        let encoded = parameters.iter().try_fold(12usize, |size, value| {
            size.checked_add(4 + value.len())
                .ok_or("PostgreSQL parameter payload exceeds bound")
        })?;
        if encoded > MAX_FRAME {
            return Err("PostgreSQL parameter payload exceeds bound");
        }
        let mut bind = Zeroizing::new(Vec::with_capacity(encoded));
        cstring(&mut bind, "")?;
        cstring(&mut bind, "")?;
        bind.extend_from_slice(&0u16.to_be_bytes()); // all parameters use text format
        bind.extend_from_slice(&(parameters.len() as u16).to_be_bytes());
        for value in parameters {
            let length =
                i32::try_from(value.len()).map_err(|_| "PostgreSQL parameter bound exceeded")?;
            bind.extend_from_slice(&length.to_be_bytes());
            bind.extend_from_slice(value.as_bytes());
        }
        bind.extend_from_slice(&0u16.to_be_bytes()); // all result columns use text format
        Ok(bind)
    }
    fn send_extended(&mut self, sql: &str, parameters: &[&str]) -> Result<(), &'static str> {
        if sql.is_empty() || sql.len() > MAX_SQL || sql.contains('\0') {
            return Err("PostgreSQL statement bound exceeded");
        }
        // Validate and encode the bind before sending Parse. A rejected
        // parameter must not leave a half-issued extended-query sequence on a
        // connection that the caller might otherwise reuse.
        let bind = Self::build_bind(parameters)?;
        let mut parse = Vec::with_capacity(sql.len() + 5);
        cstring(&mut parse, "")?;
        cstring(&mut parse, sql)?;
        parse.extend_from_slice(&0u16.to_be_bytes());
        self.send(b'P', &parse)?;
        self.send(b'B', &bind)?;
        self.send(b'D', b"P\0")?;
        self.send(b'E', &[0, 0, 0, 0, 0])?;
        self.send(b'S', &[])?;
        Ok(())
    }
    /// One statement, one parameterized execution, one JSON/text scalar row.
    /// This intentionally retains the small historical contract used by the
    /// dynamic credentials provider.
    pub fn scalar(&mut self, sql: &str, parameters: &[&str]) -> Result<String, &'static str> {
        if sql.len() > 4096
            || parameters.len() > 12
            || parameters
                .iter()
                .any(|p| p.len() > 4096 || p.contains('\0'))
        {
            return Err("PostgreSQL parameter bound exceeded");
        }
        self.check_usable()?;
        if self.ready != ReadyState::Idle {
            return Err("PostgreSQL session is in a transaction");
        }
        self.send_extended(sql, parameters)?;
        let mut result = None;
        let mut failure = false;
        let mut complete = false;
        for _ in 0..256 {
            let (tag, body) = self.message_bounded(256 * 1024)?;
            match tag {
                b'1' | b'2' | b'T' | b'N' | b'S' => {}
                b'D' => {
                    if result.is_some() || body.len() < 6 || body[..2] != [0, 1] {
                        return self.poison("unexpected PostgreSQL row shape");
                    }
                    let n = match body[2..6].try_into() {
                        Ok(bytes) => i32::from_be_bytes(bytes),
                        Err(_) => return self.poison("invalid PostgreSQL column"),
                    };
                    if n < 0 || n as usize != body.len() - 6 {
                        return self.poison("invalid PostgreSQL scalar size");
                    }
                    result = Some(match std::str::from_utf8(&body[6..]) {
                        Ok(text) => text.to_owned(),
                        Err(_) => return self.poison("invalid PostgreSQL text"),
                    });
                }
                b'C' => complete = true,
                b'E' => failure = true, // Never include server messages or secret-bearing statements.
                b'Z' => {
                    let state = match ready_state(&body) {
                        Ok(state) => state,
                        Err(error) => return self.poison(error),
                    };
                    if state != ReadyState::Idle {
                        return self.poison("unexpected PostgreSQL ReadyForQuery state");
                    }
                    self.ready = state;
                    return if !failure && complete {
                        result.ok_or("PostgreSQL scalar absent")
                    } else {
                        Err("PostgreSQL statement rejected or not committed")
                    };
                }
                _ => return self.poison("unexpected PostgreSQL query frame"),
            }
        }
        self.poison("PostgreSQL query frame count exceeded")
    }

    /// Execute a parameterized statement and reject any returned rows.
    pub(crate) fn execute(&mut self, sql: &str, parameters: &[&str]) -> Result<(), &'static str> {
        if self.ready == ReadyState::FailedTransaction {
            return Err("PostgreSQL transaction is failed; rollback required");
        }
        self.check_usable()?;
        let expected = if self.ready == ReadyState::Idle {
            ReadyState::Idle
        } else {
            ReadyState::InTransaction
        };
        self.send_extended(sql, parameters)?;
        let failure = if expected == ReadyState::InTransaction {
            ReadyState::FailedTransaction
        } else {
            ReadyState::Idle
        };
        self.consume_result(false, expected, failure, None)
            .map(|_| ())
    }

    /// Execute a parameterized query and return bounded UTF-8 text rows.
    pub(crate) fn query(
        &mut self,
        sql: &str,
        parameters: &[&str],
    ) -> Result<Vec<Vec<Option<String>>>, &'static str> {
        if self.ready == ReadyState::FailedTransaction {
            return Err("PostgreSQL transaction is failed; rollback required");
        }
        self.check_usable()?;
        let expected = if self.ready == ReadyState::Idle {
            ReadyState::Idle
        } else {
            ReadyState::InTransaction
        };
        self.send_extended(sql, parameters)?;
        let failure = if expected == ReadyState::InTransaction {
            ReadyState::FailedTransaction
        } else {
            ReadyState::Idle
        };
        self.consume_result(true, expected, failure, None)
    }

    /// Start a repeatable-read transaction. A failed transaction can only be
    /// made usable again by rollback.
    pub(crate) fn begin(&mut self, read_only: bool) -> Result<(), &'static str> {
        self.begin_with_transfer_budget(read_only, 0)
    }

    /// Only an idle, non-poisoned session can start a new operation budget.
    /// Idle time is not transaction time; all frames through COMMIT share this
    /// one absolute deadline, including rollback on a failed statement.
    pub(crate) fn begin_with_transfer_budget(
        &mut self,
        read_only: bool,
        transfer_bytes: usize,
    ) -> Result<(), &'static str> {
        self.check_usable()?;
        if self.ready != ReadyState::Idle {
            return Err("PostgreSQL transaction is already active");
        }
        let budget = transaction_budget(transfer_bytes)?;
        self.stream
            .sock
            .begin_operation(budget)
            .map_err(|_| "PostgreSQL operation deadline unavailable")?;
        self.send_extended(begin_sql(read_only), &[])?;
        self.consume_result(
            false,
            ReadyState::InTransaction,
            ReadyState::Idle,
            Some("BEGIN"),
        )
        .map(|_| ())
    }

    pub(crate) fn commit(&mut self) -> Result<(), CommitError> {
        self.check_usable().map_err(|_| CommitError::Rejected)?;
        if self.ready != ReadyState::InTransaction {
            return Err(CommitError::Rejected);
        }
        self.send_extended("COMMIT", &[])
            .map_err(|_| CommitError::OutcomeUnknown)?;
        self.consume_result(
            false,
            ReadyState::Idle,
            ReadyState::FailedTransaction,
            Some("COMMIT"),
        )
        .map(|_| ())
        .map_err(|_| CommitError::OutcomeUnknown)
    }

    pub(crate) fn rollback(&mut self) -> Result<(), &'static str> {
        self.check_usable()?;
        if !matches!(
            self.ready,
            ReadyState::InTransaction | ReadyState::FailedTransaction
        ) {
            return Err("PostgreSQL transaction is not active");
        }
        self.send_extended("ROLLBACK", &[])?;
        self.consume_result(
            false,
            ReadyState::Idle,
            ReadyState::FailedTransaction,
            Some("ROLLBACK"),
        )
        .map(|_| ())
    }

    fn consume_result(
        &mut self,
        want_rows: bool,
        success_state: ReadyState,
        failure_state: ReadyState,
        expected_command: Option<&'static str>,
    ) -> Result<Vec<Vec<Option<String>>>, &'static str> {
        let mut result =
            QueryResponse::new(want_rows, success_state, failure_state, expected_command);
        for _ in 0..MAX_RESULT_ROWS + 256 {
            let (tag, body) = self.message()?;
            match result.accept(tag, &body) {
                Ok(Some(state)) => {
                    self.ready = state;
                    return if result.failed {
                        Err("PostgreSQL statement rejected")
                    } else {
                        Ok(result.rows)
                    };
                }
                Ok(None) => {}
                Err(error) => return self.poison(error),
            }
        }
        self.poison("PostgreSQL query frame count exceeded")
    }
}

// Kept separate from socket I/O so malformed server sequences exercise the
// same decoder as live queries, including the terminal commit acknowledgement.
struct QueryResponse {
    want_rows: bool,
    success_state: ReadyState,
    failure_state: ReadyState,
    expected_command: Option<&'static str>,
    columns: Option<usize>,
    rows: Vec<Vec<Option<String>>>,
    total_bytes: usize,
    failed: bool,
    parsed: bool,
    bound: bool,
    described: bool,
    completed: bool,
    finished: bool,
}

impl QueryResponse {
    fn new(
        want_rows: bool,
        success_state: ReadyState,
        failure_state: ReadyState,
        expected_command: Option<&'static str>,
    ) -> Self {
        Self {
            want_rows,
            success_state,
            failure_state,
            expected_command,
            columns: None,
            rows: Vec::new(),
            total_bytes: 0,
            failed: false,
            parsed: false,
            bound: false,
            described: false,
            completed: false,
            finished: false,
        }
    }

    fn accept(&mut self, tag: u8, body: &[u8]) -> Result<Option<ReadyState>, &'static str> {
        if self.finished {
            return Err("PostgreSQL query is already complete");
        }
        match tag {
            b'1' if !self.failed && !self.parsed && body.is_empty() => self.parsed = true,
            b'2' if !self.failed && self.parsed && !self.bound && body.is_empty() => {
                self.bound = true
            }
            b'T' if !self.failed && self.bound && !self.described && !self.completed => {
                self.columns = Some(parse_row_description(body)?);
                self.described = true;
            }
            b'n' if !self.failed
                && self.bound
                && !self.described
                && !self.completed
                && body.is_empty() =>
            {
                self.described = true
            }
            b'D' if !self.failed && self.described && !self.completed => {
                let columns = self
                    .columns
                    .ok_or("PostgreSQL row arrived without description")?;
                if !self.want_rows {
                    return Err("PostgreSQL execute returned rows");
                }
                if self.rows.len() >= MAX_RESULT_ROWS {
                    return Err("PostgreSQL result row bound exceeded");
                }
                let (row, bytes) = parse_data_row(body, columns)?;
                self.total_bytes = self
                    .total_bytes
                    .checked_add(bytes)
                    .ok_or("PostgreSQL result size overflow")?;
                if self.total_bytes > MAX_RESULT_BYTES {
                    return Err("PostgreSQL result byte bound exceeded");
                }
                self.rows.push(row);
            }
            b'C' if !self.failed && self.described && !self.completed => {
                if !command_complete_shape(body, self.expected_command) {
                    return Err("invalid PostgreSQL command completion");
                }
                self.completed = true;
            }
            b'E' if !self.failed && !self.completed => self.failed = true,
            b'N' | b'S' => {} // Remote diagnostics and parameter notices are never surfaced.
            b'Z' => {
                let state = ready_state(body)?;
                if self.failed {
                    if state != self.failure_state {
                        return Err("unexpected PostgreSQL ReadyForQuery state");
                    }
                } else {
                    if !self.parsed || !self.bound || !self.described || !self.completed {
                        return Err("PostgreSQL statement did not complete");
                    }
                    if state != self.success_state {
                        return Err("unexpected PostgreSQL ReadyForQuery state");
                    }
                    if self.want_rows && self.columns.is_none() {
                        return Err("PostgreSQL query returned no row description");
                    }
                }
                self.finished = true;
                return Ok(Some(state));
            }
            _ => return Err("unexpected PostgreSQL query frame"),
        }
        Ok(None)
    }
}

fn ready_state(body: &[u8]) -> Result<ReadyState, &'static str> {
    match body {
        b"I" => Ok(ReadyState::Idle),
        b"T" => Ok(ReadyState::InTransaction),
        b"E" => Ok(ReadyState::FailedTransaction),
        _ => Err("invalid PostgreSQL ReadyForQuery state"),
    }
}

fn begin_sql(read_only: bool) -> &'static str {
    if read_only {
        "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"
    } else {
        "BEGIN ISOLATION LEVEL REPEATABLE READ"
    }
}
fn cstring(target: &mut Vec<u8>, text: &str) -> Result<(), &'static str> {
    if text.contains('\0') {
        return Err("NUL in PostgreSQL field");
    }
    target.extend_from_slice(text.as_bytes());
    target.push(0);
    Ok(())
}

fn parse_row_description(body: &[u8]) -> Result<usize, &'static str> {
    if body.len() < 2 {
        return Err("invalid PostgreSQL row description");
    }
    let count = usize::from(u16::from_be_bytes([body[0], body[1]]));
    if count > MAX_RESULT_COLUMNS {
        return Err("PostgreSQL result column bound exceeded");
    }
    let mut offset = 2;
    for _ in 0..count {
        if offset >= body.len() {
            return Err("truncated PostgreSQL row description");
        }
        let name_end = body[offset..]
            .iter()
            .position(|byte| *byte == 0)
            .ok_or("unterminated PostgreSQL column name")?;
        if name_end == 0 || name_end > MAX_RESULT_FIELD {
            return Err("invalid PostgreSQL column name");
        }
        offset = offset
            .checked_add(name_end + 1 + 18)
            .ok_or("PostgreSQL row description overflow")?;
        if offset > body.len() {
            return Err("truncated PostgreSQL row description");
        }
        if body[offset - 2..offset] != [0, 0] {
            return Err("PostgreSQL result column is not text format");
        }
    }
    if offset != body.len() {
        return Err("trailing PostgreSQL row description bytes");
    }
    Ok(count)
}

fn parse_data_row(
    body: &[u8],
    expected_columns: usize,
) -> Result<(Vec<Option<String>>, usize), &'static str> {
    if body.len() < 2 {
        return Err("invalid PostgreSQL data row");
    }
    let count = usize::from(u16::from_be_bytes([body[0], body[1]]));
    if count != expected_columns || count > MAX_RESULT_COLUMNS {
        return Err("PostgreSQL data row column mismatch");
    }
    let mut offset = 2usize;
    let mut bytes = 0usize;
    let mut row = Vec::with_capacity(count);
    for _ in 0..count {
        if body.len() - offset < 4 {
            return Err("truncated PostgreSQL data row");
        }
        let length = i32::from_be_bytes(
            body[offset..offset + 4]
                .try_into()
                .map_err(|_| "invalid PostgreSQL data column")?,
        );
        offset += 4;
        if length < 0 {
            if length != -1 {
                return Err("invalid PostgreSQL NULL column");
            }
            row.push(None);
            continue;
        }
        let length = usize::try_from(length).map_err(|_| "invalid PostgreSQL data column")?;
        if length > MAX_RESULT_FIELD || length > body.len() - offset {
            return Err("PostgreSQL result field bound exceeded");
        }
        let text = std::str::from_utf8(&body[offset..offset + length])
            .map_err(|_| "invalid PostgreSQL text")?
            .to_owned();
        offset += length;
        bytes = bytes
            .checked_add(length)
            .ok_or("PostgreSQL result size overflow")?;
        row.push(Some(text));
    }
    if offset != body.len() {
        return Err("trailing PostgreSQL data row bytes");
    }
    Ok((row, bytes))
}

fn command_complete_shape(body: &[u8], expected: Option<&str>) -> bool {
    if body.len() < 2 || body.last() != Some(&0) || body[..body.len() - 1].contains(&0) {
        return false;
    }
    match expected {
        Some(command) => body[..body.len() - 1] == *command.as_bytes(),
        None => true,
    }
}

struct Scram {
    nonce: String,
    bare: String,
    server_key: Zeroizing<Vec<u8>>,
    message: Zeroizing<String>,
}
impl Scram {
    fn new() -> Result<Self, &'static str> {
        let nonce = STANDARD.encode(crate::crypto::random::<24>()?);
        let bare = format!("n=,r={nonce}");
        Ok(Self {
            nonce,
            bare,
            server_key: Zeroizing::new(Vec::new()),
            message: Zeroizing::new(String::new()),
        })
    }
    fn answer(&mut self, raw: &[u8], password: &str) -> Result<Zeroizing<String>, &'static str> {
        let first = std::str::from_utf8(raw).map_err(|_| "invalid SCRAM server-first")?;
        let attrs = attributes(first)?;
        if attrs.len() != 3 {
            return Err("unsupported SCRAM server-first fields");
        }
        let nonce = *attrs.get("r").ok_or("missing SCRAM nonce")?;
        if !nonce.starts_with(&self.nonce) || nonce.len() <= self.nonce.len() || nonce.len() > 1024
        {
            return Err("SCRAM nonce binding failed");
        }
        let salt = STANDARD
            .decode(attrs.get("s").ok_or("missing SCRAM salt")?)
            .map_err(|_| "invalid SCRAM salt")?;
        if !(8..=64).contains(&salt.len()) {
            return Err("invalid SCRAM salt length");
        }
        let rounds: u32 = attrs
            .get("i")
            .ok_or("missing SCRAM iterations")?
            .parse()
            .map_err(|_| "invalid SCRAM iterations")?;
        if !(4096..=1_000_000).contains(&rounds) {
            return Err("SCRAM iteration budget exceeded");
        }
        let mut salted = Zeroizing::new([0u8; 32]);
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(rounds).ok_or("invalid SCRAM iterations")?,
            &salt,
            password.as_bytes(),
            salted.as_mut(),
        );
        let salted_key = hmac::Key::new(hmac::HMAC_SHA256, salted.as_slice());
        let client = hmac::sign(&salted_key, b"Client Key");
        let stored = digest::digest(&digest::SHA256, client.as_ref());
        let final_bare = format!("c=biws,r={nonce}");
        self.message = Zeroizing::new(format!("{},{first},{final_bare}", self.bare));
        let signature = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, stored.as_ref()),
            self.message.as_bytes(),
        );
        let mut proof = Zeroizing::new([0u8; 32]);
        for (i, b) in proof.iter_mut().enumerate() {
            *b = client.as_ref()[i] ^ signature.as_ref()[i];
        }
        self.server_key = Zeroizing::new(hmac::sign(&salted_key, b"Server Key").as_ref().to_vec());
        Ok(Zeroizing::new(format!(
            "{final_bare},p={}",
            STANDARD.encode(proof.as_slice())
        )))
    }
    fn finish(&self, raw: &[u8]) -> Result<(), &'static str> {
        let attrs =
            attributes(std::str::from_utf8(raw).map_err(|_| "invalid SCRAM server-final")?)?;
        if attrs.len() != 1 || self.server_key.len() != 32 {
            return Err("invalid SCRAM server-final");
        }
        let signature = STANDARD
            .decode(attrs.get("v").ok_or("SCRAM server authentication failed")?)
            .map_err(|_| "invalid SCRAM server proof")?;
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, &self.server_key),
            self.message.as_bytes(),
            &signature,
        )
        .map_err(|_| "SCRAM server signature mismatch")
    }
}
fn attributes(input: &str) -> Result<BTreeMap<&str, &str>, &'static str> {
    if input.len() > 2048 || !input.is_ascii() || input.bytes().any(|c| c < 33 || c == 127) {
        return Err("invalid SCRAM message");
    }
    let mut result = BTreeMap::new();
    for part in input.split(',') {
        let (k, v) = part.split_once('=').ok_or("invalid SCRAM attribute")?;
        if k.len() != 1 || v.is_empty() || result.insert(k, v).is_some() {
            return Err("invalid or duplicate SCRAM attribute");
        }
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transaction_deadline_budget_is_bounded_by_transfer_size() -> Result<(), &'static str> {
        assert_eq!(transaction_budget(0)?, Duration::from_secs(3));
        assert_eq!(transaction_budget(1)?, Duration::from_secs(4));
        assert_eq!(
            transaction_budget(128 * 1024 * 1024)?,
            Duration::from_secs(19)
        );
        assert_eq!(
            transaction_budget(MAX_TRANSACTION_TRANSFER_BYTES)?,
            Duration::from_secs(99)
        );
        assert!(transaction_budget(MAX_TRANSACTION_TRANSFER_BYTES + 1).is_err());
        Ok(())
    }

    #[test]
    fn scram_rejects_nonce_rebinding_duplicate_fields_and_excessive_work()
    -> Result<(), &'static str> {
        let mut s = Scram::new()?;
        assert!(s.answer(b"r=wrong,s=c2FsdHNhbHQ=,i=4096", "pw").is_err());
        let first = format!("r={}suffix,s=c2FsdHNhbHQ=,i=1000001", s.nonce);
        assert!(s.answer(first.as_bytes(), "pw").is_err());
        assert!(attributes("r=a,r=b,s=c,i=4096").is_err());
        assert!(s.finish(b"e=wrong").is_err());
        Ok(())
    }
    #[test]
    fn scram_server_signature_is_verified() -> Result<(), &'static str> {
        let mut s = Scram::new()?;
        let first = format!("r={}suffix,s=c2FsdHNhbHQ=,i=4096", s.nonce);
        let proof = s.answer(first.as_bytes(), "password")?;
        assert!(proof.contains(",p="));
        let sig = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &s.server_key),
            s.message.as_bytes(),
        );
        s.finish(format!("v={}", STANDARD.encode(sig.as_ref())).as_bytes())?;
        assert!(
            s.finish(b"v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .is_err()
        );
        Ok(())
    }
    #[test]
    fn rfc7677_scram_sha256_known_answer() -> Result<(), &'static str> {
        // RFC 7677 section 3 public test vector; not generated by this client.
        let mut s = Scram {
            nonce: "rOprNGfwEbeRWgbNEkqO".into(),
            bare: "n=user,r=rOprNGfwEbeRWgbNEkqO".into(),
            server_key: Zeroizing::new(Vec::new()),
            message: Zeroizing::new(String::new()),
        };
        let answer=s.answer(b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096","pencil")?;
        assert_eq!(
            answer.as_str(),
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        s.finish(b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")?;
        Ok(())
    }

    #[test]
    fn extended_bind_allows_physical_records_but_fences_total_payload() -> Result<(), &'static str>
    {
        let value = "x".repeat(MAX_PARAMETER_VALUE);
        let bind = PgSession::build_bind(&[value.as_str()])?;
        assert!(bind.len() <= MAX_FRAME);
        let too_large = "x".repeat(MAX_PARAMETER_VALUE + 1);
        assert!(PgSession::build_bind(&[too_large.as_str()]).is_err());
        let many = vec![value.as_str(); MAX_PARAMETERS];
        assert!(PgSession::build_bind(&many).is_err());
        Ok(())
    }

    #[test]
    fn row_parsers_reject_truncation_and_preserve_nulls() -> Result<(), &'static str> {
        let mut description = vec![0, 2];
        description.extend_from_slice(b"first\0");
        description.extend_from_slice(&[0; 18]);
        description.extend_from_slice(b"second\0");
        description.extend_from_slice(&[0; 18]);
        assert_eq!(parse_row_description(&description)?, 2);
        assert!(parse_row_description(&description[..description.len() - 1]).is_err());
        let last = description.len() - 1;
        description[last] = 1;
        assert!(parse_row_description(&description).is_err());

        let mut row = vec![0, 2];
        row.extend_from_slice(&(-1i32).to_be_bytes());
        row.extend_from_slice(&(3i32).to_be_bytes());
        row.extend_from_slice(b"yes");
        let (values, bytes) = parse_data_row(&row, 2)?;
        assert_eq!(values, vec![None, Some("yes".into())]);
        assert_eq!(bytes, 3);
        assert!(parse_data_row(&row[..row.len() - 1], 2).is_err());
        Ok(())
    }

    #[test]
    fn command_completion_rejects_wrong_transaction_tag_and_shape() {
        assert!(command_complete_shape(b"COMMIT\0", Some("COMMIT")));
        assert!(!command_complete_shape(b"ROLLBACK\0", Some("COMMIT")));
        assert!(!command_complete_shape(b"COMMIT", Some("COMMIT")));
        assert!(!command_complete_shape(b"COM\0MIT\0", None));
    }

    #[test]
    fn commit_requires_complete_ordered_acknowledgement() -> Result<(), &'static str> {
        let response = || {
            QueryResponse::new(
                false,
                ReadyState::Idle,
                ReadyState::FailedTransaction,
                Some("COMMIT"),
            )
        };
        let mut premature = response();
        assert!(premature.accept(b'Z', b"I").is_err());
        let mut malformed = response();
        assert!(malformed.accept(b'1', b"extra").is_err());
        let mut out_of_order = response();
        assert!(out_of_order.accept(b'2', b"").is_err());
        let mut duplicate = response();
        duplicate.accept(b'1', b"")?;
        assert!(duplicate.accept(b'1', b"").is_err());

        let prefix = |result: &mut QueryResponse| -> Result<(), &'static str> {
            result.accept(b'1', b"")?;
            result.accept(b'2', b"")?;
            result.accept(b'n', b"")?;
            Ok(())
        };
        let mut rollback = response();
        prefix(&mut rollback)?;
        assert!(rollback.accept(b'C', b"ROLLBACK\0").is_err());
        let mut missing_command = response();
        prefix(&mut missing_command)?;
        assert!(missing_command.accept(b'Z', b"I").is_err());
        let mut wrong_state = response();
        prefix(&mut wrong_state)?;
        wrong_state.accept(b'C', b"COMMIT\0")?;
        assert!(wrong_state.accept(b'Z', b"T").is_err());
        let mut good = response();
        prefix(&mut good)?;
        assert_eq!(good.accept(b'C', b"COMMIT\0")?, None);
        assert_eq!(good.accept(b'Z', b"I")?, Some(ReadyState::Idle));
        assert!(!good.failed);
        assert!(good.accept(b'Z', b"I").is_err());
        Ok(())
    }

    #[test]
    fn failed_statement_requires_failed_transaction_state() -> Result<(), &'static str> {
        let mut error = QueryResponse::new(
            true,
            ReadyState::InTransaction,
            ReadyState::FailedTransaction,
            None,
        );
        error.accept(b'E', b"remote details are discarded")?;
        assert_eq!(
            error.accept(b'Z', b"E")?,
            Some(ReadyState::FailedTransaction)
        );
        assert!(error.failed);
        let mut inconsistent = QueryResponse::new(
            true,
            ReadyState::InTransaction,
            ReadyState::FailedTransaction,
            None,
        );
        inconsistent.accept(b'E', b"")?;
        assert!(inconsistent.accept(b'Z', b"I").is_err());
        Ok(())
    }
}
