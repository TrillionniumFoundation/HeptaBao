#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Non-production P0 in-memory server slice.
//!
//! The implementation exists to exercise H03/H04/H07/H12/H16 request and
//! audit contracts. It is loopback/development only, has no durable storage,
//! no compatibility claim and no production authority.

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use heptabao_protocol::{
    AuditEvent, AuditPhase, CommitDisposition, MonotonicTick, Operation, ProtocolError,
    RequestEnvelope, RequestId, SecretBytes,
};

pub const P0_PROFILE: &str = "HB-P0-DEV-MEMORY";
pub const P0_PRODUCTION_SUPPORTED: bool = false;
pub const P0_COMPATIBILITY_CLAIM: bool = false;
pub const P0_AUTHORITY_EFFECT: &str = "NONE";

#[derive(Debug)]
pub struct DevelopmentCredentials {
    root_token: SecretBytes,
    unseal_key: SecretBytes,
}

impl DevelopmentCredentials {
    pub fn new(mut root_token: Vec<u8>, mut unseal_key: Vec<u8>) -> Result<Self, P0Error> {
        if root_token.len() < 24 || unseal_key.len() < 24 || root_token == unseal_key {
            root_token.fill(0);
            unseal_key.fill(0);
            return Err(P0Error::WeakDevelopmentCredential);
        }
        let root_token = SecretBytes::new(root_token).map_err(P0Error::Protocol)?;
        let unseal_key = SecretBytes::new(unseal_key).map_err(P0Error::Protocol)?;
        Ok(Self {
            root_token,
            unseal_key,
        })
    }

    fn root_token_matches(&self, candidate: &[u8]) -> bool {
        self.root_token.constant_time_eq(candidate)
    }

    fn unseal_key_matches(&self, candidate: &[u8]) -> bool {
        self.unseal_key.constant_time_eq(candidate)
    }
}

pub trait AuditSink: fmt::Debug + Send {
    fn record(&mut self, event: &AuditEvent) -> Result<(), AuditError>;
}

#[derive(Debug, Default)]
pub struct MemoryAuditSink {
    events: Vec<AuditEvent>,
    fail_on_call: Option<usize>,
    calls: usize,
}

impl MemoryAuditSink {
    pub fn with_failure_on(call: usize) -> Self {
        Self {
            events: Vec::new(),
            fail_on_call: Some(call),
            calls: 0,
        }
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&mut self, event: &AuditEvent) -> Result<(), AuditError> {
        self.calls = self.calls.saturating_add(1);
        if self.fail_on_call == Some(self.calls) {
            return Err(AuditError::InjectedFailure);
        }
        self.events.push(event.clone());
        Ok(())
    }
}

pub struct FileAuditSink {
    path: PathBuf,
    file: File,
}

impl fmt::Debug for FileAuditSink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileAuditSink")
            .field("path", &"[REDACTED]")
            .field("open", &true)
            .finish()
    }
}

fn ensure_directory_chain_is_safe(path: &Path) -> Result<(), AuditError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if current.as_os_str().is_empty() || current.parent().is_none() {
            continue;
        }
        let metadata = fs::symlink_metadata(&current).map_err(AuditError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(AuditError::UnsafePath);
        }
    }
    Ok(())
}

impl FileAuditSink {
    pub fn create_new(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(AuditError::PathMustBeAbsolute);
        }
        let parent = path.parent().ok_or(AuditError::InvalidPath)?;
        ensure_directory_chain_is_safe(parent)?;
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(AuditError::PathAlreadyExists),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(AuditError::Io(error)),
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(AuditError::Io)?;
        let metadata = file.metadata().map_err(AuditError::Io)?;
        if !metadata.is_file() {
            return Err(AuditError::UnsafePath);
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for FileAuditSink {
    fn record(&mut self, event: &AuditEvent) -> Result<(), AuditError> {
        let operation = event
            .operation
            .map(|value| format!("{value:?}"))
            .unwrap_or_else(|| "NONE".to_owned());
        let line = format!(
            "request_id={} operation={} phase={:?} commit={:?} status={} detail={}\n",
            event.request_id.as_str(),
            operation,
            event.phase,
            event.commit,
            event.status_code,
            event.detail_code,
        );
        self.file
            .write_all(line.as_bytes())
            .map_err(AuditError::Io)?;
        self.file.flush().map_err(AuditError::Io)?;
        self.file.sync_data().map_err(AuditError::Io)
    }
}

pub struct P0Server<A: AuditSink> {
    state: ServerState,
    credentials: DevelopmentCredentials,
    audit: A,
}

impl<A: AuditSink> fmt::Debug for P0Server<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("P0Server")
            .field("state", &self.state)
            .field("credentials", &"[REDACTED]")
            .field("audit", &"[CONFIGURED]")
            .finish()
    }
}

fn zeroize_string(value: &mut String) {
    let mut bytes = std::mem::take(value).into_bytes();
    bytes.fill(0);
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct SecretPath(String);

impl SecretPath {
    fn new(value: &str) -> Self {
        Self(value.to_owned())
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for SecretPath {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for SecretPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretPath([REDACTED])")
    }
}

impl Drop for SecretPath {
    fn drop(&mut self) {
        zeroize_string(&mut self.0);
    }
}

struct ServerState {
    initialized: bool,
    sealed: bool,
    kv: BTreeMap<SecretPath, SecretBytes>,
    generation: u64,
}

impl fmt::Debug for ServerState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerState")
            .field("initialized", &self.initialized)
            .field("sealed", &self.sealed)
            .field("kv_entries", &self.kv.len())
            .field("generation", &self.generation)
            .finish()
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            initialized: false,
            sealed: true,
            kv: BTreeMap::new(),
            generation: 0,
        }
    }
}

#[derive(Eq, PartialEq)]
pub struct P0Response {
    pub status_code: u16,
    pub body: Vec<u8>,
    pub committed: bool,
    pub recovery_reference: Option<String>,
}

impl fmt::Debug for P0Response {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("P0Response")
            .field("status_code", &self.status_code)
            .field("body_bytes", &self.body.len())
            .field("body", &"[REDACTED]")
            .field("committed", &self.committed)
            .field(
                "recovery_reference_present",
                &self.recovery_reference.is_some(),
            )
            .finish()
    }
}

impl Drop for P0Response {
    fn drop(&mut self) {
        self.body.fill(0);
    }
}

impl P0Response {
    fn json(status_code: u16, body: String) -> Self {
        Self::json_bytes(status_code, body.into_bytes())
    }

    fn json_bytes(status_code: u16, body: Vec<u8>) -> Self {
        Self {
            status_code,
            body,
            committed: false,
            recovery_reference: None,
        }
    }

    fn no_content(committed: bool) -> Self {
        Self {
            status_code: 204,
            body: Vec::new(),
            committed,
            recovery_reference: None,
        }
    }
}

impl<A: AuditSink> P0Server<A> {
    pub fn new(credentials: DevelopmentCredentials, audit: A) -> Self {
        Self {
            state: ServerState::default(),
            credentials,
            audit,
        }
    }

    pub fn audit(&self) -> &A {
        &self.audit
    }

    pub fn generation(&self) -> u64 {
        self.state.generation
    }

    pub fn handle(&mut self, envelope: RequestEnvelope, now: MonotonicTick) -> P0Response {
        let request_id = envelope.request_id.clone();
        let operation = match envelope.validate_at(now) {
            Ok(value) => value,
            Err(error) => {
                let response = protocol_error_response(error);
                if self
                    .audit
                    .record(&AuditEvent {
                        request_id,
                        operation: None,
                        phase: AuditPhase::RequestRejected,
                        commit: CommitDisposition::NotAttempted,
                        status_code: response.status_code,
                        detail_code: protocol_detail_code(error),
                    })
                    .is_err()
                {
                    return P0Response::json(
                        503,
                        r#"{"errors":["rejection audit unavailable"]}"#.to_owned(),
                    );
                }
                return response;
            }
        };

        if !operation_body_is_valid(operation, &envelope.request.body) {
            return self.reject_before_dispatch(
                request_id,
                Some(operation),
                400,
                "operation-body-forbidden",
                r#"{"errors":["request body is not valid for this operation"]}"#,
            );
        }
        if self.state.sealed && !operation.allowed_while_sealed() {
            return self.reject_before_dispatch(
                request_id,
                Some(operation),
                503,
                "sealed",
                r#"{"errors":["server is sealed"]}"#,
            );
        }
        if !self.state.initialized
            && !matches!(
                operation,
                Operation::SysHealth | Operation::SysInit | Operation::SysSealStatus
            )
        {
            return self.reject_before_dispatch(
                request_id,
                Some(operation),
                503,
                "not-initialized",
                r#"{"errors":["server is not initialized"]}"#,
            );
        }
        if operation.requires_authentication() && !self.authenticated(&envelope) {
            return self.reject_before_dispatch(
                request_id,
                Some(operation),
                403,
                "authentication-failed",
                r#"{"errors":["permission denied"]}"#,
            );
        }

        let request_event = AuditEvent {
            request_id: request_id.clone(),
            operation: Some(operation),
            phase: AuditPhase::RequestAccepted,
            commit: CommitDisposition::NotAttempted,
            status_code: 0,
            detail_code: "dispatch-authorized",
        };
        if self.audit.record(&request_event).is_err() {
            return P0Response::json(
                503,
                r#"{"errors":["request audit unavailable"]}"#.to_owned(),
            );
        }

        let mut response = self.dispatch(operation, &envelope);
        let response_event = AuditEvent {
            request_id: request_id.clone(),
            operation: Some(operation),
            phase: if response.committed {
                AuditPhase::ResponseCommitted
            } else {
                AuditPhase::ResponsePrepared
            },
            commit: if response.committed {
                CommitDisposition::Committed
            } else {
                CommitDisposition::NotCommitted
            },
            status_code: response.status_code,
            detail_code: if response.committed {
                "response-committed"
            } else {
                "response-prepared"
            },
        };
        if self.audit.record(&response_event).is_err() {
            if response.committed {
                let reference = format!(
                    "p0-audit-reconcile-{}-{}",
                    request_id.as_str(),
                    self.state.generation
                );
                return P0Response {
                    status_code: 503,
                    body: format!(
                        "{{\"errors\":[\"response audit failed after commit\"],\"committed\":true,\"recovery_reference\":\"{}\"}}",
                        escape_json(&reference)
                    )
                    .into_bytes(),
                    committed: true,
                    recovery_reference: Some(reference),
                };
            }
            response.status_code = 503;
            response.body.fill(0);
            response.body = br#"{"errors":["response audit unavailable"]}"#.to_vec();
        }
        response
    }

    fn authenticated(&self, envelope: &RequestEnvelope) -> bool {
        envelope
            .request
            .headers
            .get("x-vault-token")
            .is_some_and(|candidate| self.credentials.root_token_matches(candidate.as_bytes()))
    }

    fn reject_before_dispatch(
        &mut self,
        request_id: RequestId,
        operation: Option<Operation>,
        status_code: u16,
        detail_code: &'static str,
        body: &str,
    ) -> P0Response {
        if self
            .audit
            .record(&AuditEvent {
                request_id,
                operation,
                phase: AuditPhase::RequestRejected,
                commit: CommitDisposition::NotAttempted,
                status_code,
                detail_code,
            })
            .is_err()
        {
            return P0Response::json(
                503,
                r#"{"errors":["rejection audit unavailable"]}"#.to_owned(),
            );
        }
        P0Response::json(status_code, body.to_owned())
    }

    fn dispatch(&mut self, operation: Operation, envelope: &RequestEnvelope) -> P0Response {
        match operation {
            Operation::SysHealth => self.health(),
            Operation::SysInit => self.initialize(),
            Operation::SysSealStatus => self.seal_status(),
            Operation::SysSeal => self.seal(),
            Operation::SysUnseal => self.unseal(&envelope.request.body),
            Operation::KvRead => self.kv_read(envelope.request.target.path()),
            Operation::KvWrite => {
                self.kv_write(envelope.request.target.path(), &envelope.request.body)
            }
            Operation::KvList => self.kv_list(envelope.request.target.path()),
            Operation::KvDelete => self.kv_delete(envelope.request.target.path()),
        }
    }

    fn health(&self) -> P0Response {
        let status = if !self.state.initialized {
            501
        } else if self.state.sealed {
            503
        } else {
            200
        };
        P0Response::json(
            status,
            format!(
                "{{\"initialized\":{},\"sealed\":{},\"active\":true,\"standby\":false,\"performance_standby\":false,\"replication_performance_mode\":\"disabled\",\"replication_dr_mode\":\"disabled\",\"server_time_utc\":0,\"version\":\"0.0.0-p0-dev\",\"cluster_name\":\"heptabao-p0-development\",\"cluster_id\":\"development-only\",\"production_supported\":false}}",
                self.state.initialized, self.state.sealed
            ),
        )
    }

    fn initialize(&mut self) -> P0Response {
        if self.state.initialized {
            return P0Response::json(400, r#"{"errors":["already initialized"]}"#.to_owned());
        }
        self.state.initialized = true;
        self.state.sealed = true;
        self.state.generation = self.state.generation.saturating_add(1);
        let mut response = P0Response::json(
            200,
            r#"{"initialized":true,"sealed":true,"development_credentials_returned":false,"production_supported":false}"#
                .to_owned(),
        );
        response.committed = true;
        response
    }

    fn seal_status(&self) -> P0Response {
        P0Response::json(
            200,
            format!(
                "{{\"initialized\":{},\"sealed\":{},\"t\":1,\"n\":1,\"progress\":0,\"nonce\":\"\",\"type\":\"development-injected\",\"production_supported\":false}}",
                self.state.initialized, self.state.sealed
            ),
        )
    }

    fn seal(&mut self) -> P0Response {
        self.state.sealed = true;
        self.state.generation = self.state.generation.saturating_add(1);
        P0Response::no_content(true)
    }

    fn unseal(&mut self, body: &[u8]) -> P0Response {
        let key = match parse_secret_field(body, "key") {
            Ok(value) => value,
            Err(error) => return body_error_response(error),
        };
        if !self.credentials.unseal_key_matches(key.expose()) {
            return P0Response::json(400, r#"{"errors":["invalid unseal key"]}"#.to_owned());
        }
        self.state.sealed = false;
        self.state.generation = self.state.generation.saturating_add(1);
        let mut response = P0Response::json(
            200,
            r#"{"sealed":false,"t":1,"n":1,"progress":0,"production_supported":false}"#.to_owned(),
        );
        response.committed = true;
        response
    }

    fn kv_read(&self, target: &str) -> P0Response {
        let key = kv_key(target);
        match self.state.kv.get(key) {
            Some(value) => {
                let mut body = br#"{"data":{"value":""#.to_vec();
                append_json_string_bytes(value.expose(), &mut body);
                body.extend_from_slice(br#""},"production_supported":false}"#);
                P0Response::json_bytes(200, body)
            }
            None => P0Response::json(404, r#"{"errors":["secret not found"]}"#.to_owned()),
        }
    }

    fn kv_write(&mut self, target: &str, body: &[u8]) -> P0Response {
        let secret = match parse_secret_field(body, "value") {
            Ok(value) => value,
            Err(error) => return body_error_response(error),
        };
        self.state
            .kv
            .insert(SecretPath::new(kv_key(target)), secret);
        self.state.generation = self.state.generation.saturating_add(1);
        P0Response::no_content(true)
    }

    fn kv_delete(&mut self, target: &str) -> P0Response {
        let removed = self.state.kv.remove(kv_key(target)).is_some();
        if removed {
            self.state.generation = self.state.generation.saturating_add(1);
        }
        P0Response::no_content(removed)
    }

    fn kv_list(&self, target: &str) -> P0Response {
        let prefix = kv_key(target);
        let keys = self
            .state
            .kv
            .keys()
            .filter_map(|key| key.as_str().strip_prefix(prefix))
            .filter_map(|suffix| suffix.strip_prefix('/'))
            .filter(|suffix| !suffix.is_empty())
            .map(|suffix| suffix.split('/').next().unwrap_or(suffix))
            .collect::<BTreeSet<_>>();
        let mut body = br#"{"data":{"keys":["#.to_vec();
        for (index, key) in keys.into_iter().enumerate() {
            if index != 0 {
                body.push(b',');
            }
            body.push(b'"');
            append_json_string_bytes(key.as_bytes(), &mut body);
            body.push(b'"');
        }
        body.extend_from_slice(br#"]},"production_supported":false}"#);
        P0Response::json_bytes(200, body)
    }
}

fn operation_body_is_valid(operation: Operation, body: &[u8]) -> bool {
    match operation {
        Operation::SysInit => body == b"{}",
        Operation::SysUnseal | Operation::KvWrite => !body.is_empty(),
        Operation::SysHealth
        | Operation::SysSealStatus
        | Operation::SysSeal
        | Operation::KvRead
        | Operation::KvList
        | Operation::KvDelete => body.is_empty(),
    }
}

fn kv_key(target: &str) -> &str {
    target.strip_prefix("/v1/secret/").unwrap_or("")
}

fn parse_secret_field(body: &[u8], required_key: &str) -> Result<SecretBytes, BodyError> {
    let text = std::str::from_utf8(body).map_err(|_| BodyError::InvalidUtf8)?;
    if text.len() > 64 * 1024 || !text.starts_with('{') || !text.ends_with('}') {
        return Err(BodyError::InvalidObject);
    }
    let inner = &text[1..text.len() - 1];
    let prefix = format!("\"{required_key}\":\"");
    if !inner.starts_with(&prefix) || !inner.ends_with('"') {
        return Err(BodyError::UnexpectedShape);
    }
    let encoded = &inner[prefix.len()..inner.len() - 1];
    let decoded = decode_json_string(encoded)?;
    SecretBytes::new(decoded).map_err(|_| BodyError::InvalidObject)
}

fn decode_json_string(value: &str) -> Result<Vec<u8>, BodyError> {
    let source = value.as_bytes();
    let mut output = Vec::with_capacity(source.len());
    let mut index = 0;
    while index < source.len() {
        let byte = source[index];
        if byte == b'\\' {
            index += 1;
            if index >= source.len() {
                output.fill(0);
                return Err(BodyError::InvalidEscape);
            }
            match source[index] {
                b'"' => output.push(b'"'),
                b'\\' => output.push(b'\\'),
                b'n' => output.push(b'\n'),
                b'r' => output.push(b'\r'),
                b't' => output.push(b'\t'),
                _ => {
                    output.fill(0);
                    return Err(BodyError::InvalidEscape);
                }
            }
        } else if byte.is_ascii_control() || !byte.is_ascii() || byte == b'"' {
            output.fill(0);
            return Err(BodyError::InvalidCharacter);
        } else {
            output.push(byte);
        }
        index += 1;
    }
    if output.is_empty() {
        return Err(BodyError::EmptyValue);
    }
    Ok(output)
}

fn append_json_string_bytes(value: &[u8], output: &mut Vec<u8>) {
    for byte in value.iter().copied() {
        match byte {
            b'"' => output.extend_from_slice(br#"\""#),
            b'\\' => output.extend_from_slice(br#"\\"#),
            b'\n' => output.extend_from_slice(br#"\n"#),
            b'\r' => output.extend_from_slice(br#"\r"#),
            b'\t' => output.extend_from_slice(br#"\t"#),
            0x20..=0x7e => output.push(byte),
            _ => output.extend_from_slice(br#"\uFFFD"#),
        }
    }
}

fn escape_json(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => output.push_str("\\uFFFD"),
            character => output.push(character),
        }
    }
    output
}

fn protocol_error_response(error: ProtocolError) -> P0Response {
    let status = match error {
        ProtocolError::DeadlineExceeded => 408,
        ProtocolError::UnknownOperation | ProtocolError::UnsupportedMethod => 404,
        ProtocolError::RequestTooLarge
        | ProtocolError::HeadTooLarge
        | ProtocolError::BodyTooLarge => 413,
        _ => 400,
    };
    P0Response::json(
        status,
        format!("{{\"errors\":[\"{}\"]}}", escape_json(&error.to_string())),
    )
}

const fn protocol_detail_code(error: ProtocolError) -> &'static str {
    match error {
        ProtocolError::RequestTooLarge => "protocol-request-too-large",
        ProtocolError::HeadTooLarge => "protocol-head-too-large",
        ProtocolError::BodyTooLarge => "protocol-body-too-large",
        ProtocolError::IncompleteHead => "protocol-incomplete-head",
        ProtocolError::BareLineFeed => "protocol-bare-line-feed",
        ProtocolError::BareCarriageReturn => "protocol-bare-carriage-return",
        ProtocolError::ControlCharacter => "protocol-control-character",
        ProtocolError::NonUtf8Head => "protocol-non-utf8-head",
        ProtocolError::NonAsciiHead => "protocol-non-ascii-head",
        ProtocolError::InvalidRequestLine => "protocol-invalid-request-line",
        ProtocolError::UnsupportedHttpVersion => "protocol-unsupported-http-version",
        ProtocolError::UnsupportedMethod => "protocol-unsupported-method",
        ProtocolError::InvalidTarget => "protocol-invalid-target",
        ProtocolError::AmbiguousPath => "protocol-ambiguous-path",
        ProtocolError::FragmentForbidden => "protocol-fragment-forbidden",
        ProtocolError::InvalidPercentEncoding => "protocol-invalid-percent-encoding",
        ProtocolError::NonCanonicalPercentEncoding => "protocol-noncanonical-percent-encoding",
        ProtocolError::AmbiguousQuery => "protocol-ambiguous-query",
        ProtocolError::DuplicateQueryKey => "protocol-duplicate-query-key",
        ProtocolError::UnsupportedQuery => "protocol-unsupported-query",
        ProtocolError::TooManyHeaders => "protocol-too-many-headers",
        ProtocolError::InvalidHeader => "protocol-invalid-header",
        ProtocolError::InvalidHeaderName => "protocol-invalid-header-name",
        ProtocolError::NonCanonicalHeaderValue => "protocol-noncanonical-header-value",
        ProtocolError::DuplicateHeader => "protocol-duplicate-header",
        ProtocolError::MissingHost => "protocol-missing-host",
        ProtocolError::TransferEncodingForbidden => "protocol-transfer-encoding-forbidden",
        ProtocolError::InvalidContentLength => "protocol-invalid-content-length",
        ProtocolError::ContentLengthMismatch => "protocol-content-length-mismatch",
        ProtocolError::ContentLengthExceeded => "protocol-content-length-exceeded",
        ProtocolError::UnknownOperation => "protocol-unknown-operation",
        ProtocolError::InvalidDeadline => "protocol-invalid-deadline",
        ProtocolError::DeadlineBudgetTooLarge => "protocol-deadline-budget-too-large",
        ProtocolError::ClockRegression => "protocol-clock-regression",
        ProtocolError::DeadlineExceeded => "protocol-deadline-exceeded",
        ProtocolError::InvalidRequestId => "protocol-invalid-request-id",
        ProtocolError::InvalidSecret => "protocol-invalid-secret",
    }
}

fn body_error_response(error: BodyError) -> P0Response {
    P0Response::json(
        400,
        format!("{{\"errors\":[\"{}\"]}}", escape_json(&error.to_string())),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyError {
    InvalidUtf8,
    InvalidObject,
    UnexpectedShape,
    InvalidEscape,
    InvalidCharacter,
    EmptyValue,
}

impl fmt::Display for BodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidUtf8 => "body is not UTF-8",
            Self::InvalidObject => "body is not a bounded single-field JSON object",
            Self::UnexpectedShape => "body has an unexpected single-field JSON shape",
            Self::InvalidEscape => "body contains an invalid escape",
            Self::InvalidCharacter => "body contains an invalid character",
            Self::EmptyValue => "body value is empty",
        })
    }
}

#[derive(Debug)]
pub enum AuditError {
    PathMustBeAbsolute,
    InvalidPath,
    UnsafePath,
    PathAlreadyExists,
    Io(io::Error),
    InjectedFailure,
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathMustBeAbsolute => formatter.write_str("audit path must be absolute"),
            Self::InvalidPath => formatter.write_str("audit path is invalid"),
            Self::UnsafePath => formatter.write_str("audit path crosses an unsafe file type"),
            Self::PathAlreadyExists => formatter.write_str("audit path already exists"),
            Self::Io(error) => write!(formatter, "audit I/O failure: {error}"),
            Self::InjectedFailure => formatter.write_str("injected audit failure"),
        }
    }
}

impl Error for AuditError {}

#[derive(Debug)]
pub enum P0Error {
    WeakDevelopmentCredential,
    Protocol(ProtocolError),
    Audit(AuditError),
}

impl fmt::Display for P0Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WeakDevelopmentCredential => formatter
                .write_str("development credentials must be distinct and at least 24 bytes"),
            Self::Protocol(error) => write!(formatter, "protocol error: {error}"),
            Self::Audit(error) => write!(formatter, "audit error: {error}"),
        }
    }
}

impl Error for P0Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use heptabao_protocol::{MonotonicTick, RequestEnvelope, RequestId, parse_http_request};

    fn credentials() -> Result<DevelopmentCredentials, P0Error> {
        DevelopmentCredentials::new(
            b"development-root-token-0001".to_vec(),
            b"development-unseal-key-0001".to_vec(),
        )
    }

    fn envelope(raw: &str, id: &str) -> Result<RequestEnvelope, P0Error> {
        let request = parse_http_request(raw.as_bytes()).map_err(P0Error::Protocol)?;
        let request_id = RequestId::new(id.to_owned()).map_err(P0Error::Protocol)?;
        Ok(RequestEnvelope {
            request_id,
            request,
            received_at: MonotonicTick(10),
            deadline: MonotonicTick(100),
        })
    }

    fn initialized_unsealed_server() -> Result<P0Server<MemoryAuditSink>, P0Error> {
        let mut server = P0Server::new(credentials()?, MemoryAuditSink::default());
        let init = envelope(
            "POST /v1/sys/init HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}",
            "request-init-helper-0001",
        )?;
        let init_response = server.handle(init, MonotonicTick(20));
        if init_response.status_code != 200 {
            return Err(P0Error::WeakDevelopmentCredential);
        }
        let body = r#"{"key":"development-unseal-key-0001"}"#;
        let unseal = envelope(
            &format!(
                "POST /v1/sys/unseal HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            ),
            "request-unseal-helper-0001",
        )?;
        let unseal_response = server.handle(unseal, MonotonicTick(20));
        if unseal_response.status_code != 200 {
            return Err(P0Error::WeakDevelopmentCredential);
        }
        Ok(server)
    }

    #[test]
    fn fresh_server_starts_fail_closed_and_sealed() {
        let credentials = credentials();
        assert!(credentials.is_ok());
        if let Ok(credentials) = credentials {
            let mut server = P0Server::new(credentials, MemoryAuditSink::default());
            let health = envelope(
                "GET /v1/sys/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                "request-fresh-0001",
            );
            assert!(health.is_ok());
            if let Ok(health) = health {
                let response = server.handle(health, MonotonicTick(20));
                assert_eq!(response.status_code, 501);
                assert!(String::from_utf8_lossy(&response.body).contains("\"sealed\":true"));
            }
        }
    }

    #[test]
    fn weak_or_equal_credentials_are_rejected() {
        assert!(DevelopmentCredentials::new(b"short".to_vec(), b"other".to_vec()).is_err());
        assert!(
            DevelopmentCredentials::new(
                b"same-development-credential".to_vec(),
                b"same-development-credential".to_vec(),
            )
            .is_err()
        );
    }

    #[test]
    fn init_unseal_write_and_read_are_audited() {
        let server = initialized_unsealed_server();
        assert!(server.is_ok());
        if let Ok(mut server) = server {
            let body = r#"{"value":"alpha"}"#;
            let write = envelope(
                &format!(
                    "POST /v1/secret/example HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Vault-Token: development-root-token-0001\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                ),
                "request-write-0001",
            );
            assert!(write.is_ok());
            if let Ok(write) = write {
                let response = server.handle(write, MonotonicTick(20));
                assert_eq!(response.status_code, 204);
                assert!(response.body.is_empty());
                assert!(response.committed);
            }
            let read = envelope(
                "GET /v1/secret/example HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Vault-Token: development-root-token-0001\r\n\r\n",
                "request-read-0001",
            );
            assert!(read.is_ok());
            if let Ok(read) = read {
                let response = server.handle(read, MonotonicTick(20));
                assert_eq!(response.status_code, 200);
                assert!(String::from_utf8_lossy(&response.body).contains("alpha"));
                assert!(!format!("{response:?}").contains("alpha"));
            }
            assert_eq!(server.audit().events().len(), 8);
            assert!(
                server
                    .audit()
                    .events()
                    .iter()
                    .any(|event| event.detail_code == "response-committed")
            );
        }
    }

    #[test]
    fn server_debug_redacts_kv_paths_and_values() {
        let server = initialized_unsealed_server();
        assert!(server.is_ok());
        if let Ok(mut server) = server {
            let body = r#"{"value":"diagnostic-secret-value"}"#;
            let write = envelope(
                &format!(
                    "POST /v1/secret/diagnostic-secret-path HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Vault-Token: development-root-token-0001\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                ),
                "request-debug-0001",
            );
            assert!(write.is_ok());
            if let Ok(write) = write {
                assert_eq!(server.handle(write, MonotonicTick(20)).status_code, 204);
            }
            let rendered = format!("{server:?}");
            assert!(!rendered.contains("diagnostic-secret-path"));
            assert!(!rendered.contains("diagnostic-secret-value"));
            assert!(rendered.contains("kv_entries"));
            assert!(!rendered.contains("MemoryAuditSink"));
        }
    }

    #[test]
    fn kv_list_response_is_direct_owned_and_debug_redacted() {
        let server = initialized_unsealed_server();
        assert!(server.is_ok());
        if let Ok(mut server) = server {
            let body = r#"{"value":"list-value"}"#;
            let write = envelope(
                &format!(
                    "POST /v1/secret/folder/private-child HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Vault-Token: development-root-token-0001\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                ),
                "request-list-write-0001",
            );
            assert!(write.is_ok());
            if let Ok(write) = write {
                assert_eq!(server.handle(write, MonotonicTick(20)).status_code, 204);
            }
            let list = envelope(
                "LIST /v1/secret/folder HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Vault-Token: development-root-token-0001\r\n\r\n",
                "request-list-0001",
            );
            assert!(list.is_ok());
            if let Ok(list) = list {
                let response = server.handle(list, MonotonicTick(20));
                assert_eq!(response.status_code, 200);
                assert!(String::from_utf8_lossy(&response.body).contains("private-child"));
                assert!(!format!("{response:?}").contains("private-child"));
            }
        }
    }

    #[test]
    fn delete_no_content_is_always_body_free() {
        let server = initialized_unsealed_server();
        assert!(server.is_ok());
        if let Ok(mut server) = server {
            let delete = envelope(
                "DELETE /v1/secret/missing HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Vault-Token: development-root-token-0001\r\n\r\n",
                "request-delete-0001",
            );
            assert!(delete.is_ok());
            if let Ok(delete) = delete {
                let response = server.handle(delete, MonotonicTick(20));
                assert_eq!(response.status_code, 204);
                assert!(response.body.is_empty());
                assert!(!response.committed);
            }
        }
    }

    #[test]
    fn ignored_operation_bodies_fail_closed_before_dispatch() {
        let server = initialized_unsealed_server();
        assert!(server.is_ok());
        if let Ok(mut server) = server {
            let before = server.generation();
            let read = envelope(
                "GET /v1/secret/example HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Vault-Token: development-root-token-0001\r\nContent-Length: 2\r\n\r\n{}",
                "request-body-policy-0001",
            );
            assert!(read.is_ok());
            if let Ok(read) = read {
                let response = server.handle(read, MonotonicTick(20));
                assert_eq!(response.status_code, 400);
                assert!(!response.committed);
                assert_eq!(server.generation(), before);
                assert_eq!(
                    server
                        .audit()
                        .events()
                        .last()
                        .map(|event| event.detail_code),
                    Some("operation-body-forbidden")
                );
            }
        }
    }

    #[test]
    fn init_requires_the_exact_empty_object_body() {
        let credentials = credentials();
        assert!(credentials.is_ok());
        if let Ok(credentials) = credentials {
            let mut server = P0Server::new(credentials, MemoryAuditSink::default());
            let body = r#"{"x":"y"}"#;
            let init = envelope(
                &format!(
                    "POST /v1/sys/init HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                ),
                "request-init-body-policy-0001",
            );
            assert!(init.is_ok());
            if let Ok(init) = init {
                let response = server.handle(init, MonotonicTick(20));
                assert_eq!(response.status_code, 400);
                assert_eq!(server.generation(), 0);
            }
        }
    }

    #[test]
    fn secret_path_debug_is_redacted() {
        let path = SecretPath::new("internal-secret-path");
        let rendered = format!("{path:?}");
        assert!(!rendered.contains("internal-secret-path"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn invalid_unescaped_quote_is_rejected() {
        assert_eq!(
            parse_secret_field(br#"{"value":"alpha"tail"}"#, "value"),
            Err(BodyError::InvalidCharacter)
        );
    }

    #[test]
    fn trailing_escape_is_rejected() {
        assert_eq!(decode_json_string("alpha\\"), Err(BodyError::InvalidEscape));
    }

    #[test]
    fn expired_request_never_dispatches() {
        let credentials = credentials();
        assert!(credentials.is_ok());
        if let Ok(credentials) = credentials {
            let mut server = P0Server::new(credentials, MemoryAuditSink::default());
            let health = envelope(
                "GET /v1/sys/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                "request-expired-0001",
            );
            assert!(health.is_ok());
            if let Ok(health) = health {
                let response = server.handle(health, MonotonicTick(100));
                assert_eq!(response.status_code, 408);
                assert_eq!(server.generation(), 0);
                assert_eq!(
                    server.audit().events()[0].detail_code,
                    "protocol-deadline-exceeded"
                );
            }
        }
    }

    #[test]
    fn sealed_and_authentication_bypasses_fail_closed() {
        let credentials = credentials();
        assert!(credentials.is_ok());
        if let Ok(credentials) = credentials {
            let mut server = P0Server::new(credentials, MemoryAuditSink::default());
            let read = envelope(
                "GET /v1/secret/example HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Vault-Token: development-root-token-0001\r\n\r\n",
                "request-sealed-0001",
            );
            assert!(read.is_ok());
            if let Ok(read) = read {
                assert_eq!(server.handle(read, MonotonicTick(20)).status_code, 503);
            }
        }
    }

    #[test]
    fn request_audit_failure_prevents_mutation() {
        let credentials = credentials();
        assert!(credentials.is_ok());
        if let Ok(credentials) = credentials {
            let mut server = P0Server::new(credentials, MemoryAuditSink::with_failure_on(1));
            let init = envelope(
                "POST /v1/sys/init HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}",
                "request-audit-0001",
            );
            assert!(init.is_ok());
            if let Ok(init) = init {
                let response = server.handle(init, MonotonicTick(20));
                assert_eq!(response.status_code, 503);
                assert_eq!(server.generation(), 0);
            }
        }
    }

    #[test]
    fn rejection_audit_failure_returns_service_unavailable() {
        let credentials = credentials();
        assert!(credentials.is_ok());
        if let Ok(credentials) = credentials {
            let mut server = P0Server::new(credentials, MemoryAuditSink::with_failure_on(1));
            let read = envelope(
                "GET /v1/secret/example HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                "request-reject-audit-0001",
            );
            assert!(read.is_ok());
            if let Ok(read) = read {
                let response = server.handle(read, MonotonicTick(20));
                assert_eq!(response.status_code, 503);
                assert!(
                    String::from_utf8_lossy(&response.body).contains("rejection audit unavailable")
                );
                assert_eq!(server.generation(), 0);
            }
        }
    }

    #[test]
    fn response_audit_failure_preserves_commit_and_returns_recovery_reference() {
        let credentials = credentials();
        assert!(credentials.is_ok());
        if let Ok(credentials) = credentials {
            let mut server = P0Server::new(credentials, MemoryAuditSink::with_failure_on(2));
            let init = envelope(
                "POST /v1/sys/init HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}",
                "request-audit-0002",
            );
            assert!(init.is_ok());
            if let Ok(init) = init {
                let response = server.handle(init, MonotonicTick(20));
                assert_eq!(response.status_code, 503);
                assert!(response.committed);
                assert!(response.recovery_reference.is_some());
                assert!(String::from_utf8_lossy(&response.body).contains("\"committed\":true"));
                assert!(
                    String::from_utf8_lossy(&response.body).contains("\"recovery_reference\":")
                );
                assert_eq!(server.generation(), 1);
            }
        }
    }

    #[test]
    fn file_audit_requires_new_absolute_non_symlink_path() {
        let root =
            std::env::temp_dir().join(format!("heptabao-p0-audit-test-{}", std::process::id()));
        let _remove_result = fs::remove_dir_all(&root);
        assert!(fs::create_dir_all(&root).is_ok());
        let relative = FileAuditSink::create_new("relative-audit.log");
        assert!(matches!(relative, Err(AuditError::PathMustBeAbsolute)));
        let path = root.join("audit.log");
        let first = FileAuditSink::create_new(&path);
        assert!(first.is_ok());
        let second = FileAuditSink::create_new(&path);
        assert!(matches!(second, Err(AuditError::PathAlreadyExists)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let real = root.join("real");
            assert!(fs::create_dir_all(&real).is_ok());
            let linked = root.join("linked");
            assert!(symlink(&real, &linked).is_ok());
            let through_link = FileAuditSink::create_new(linked.join("audit.log"));
            assert!(matches!(through_link, Err(AuditError::UnsafePath)));
        }
        let _remove_result = fs::remove_dir_all(root);
    }
}
