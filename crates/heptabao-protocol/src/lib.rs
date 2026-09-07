#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Provider-neutral H03 request, canonicalization, error and audit contracts.
//! The crate intentionally has no HTTP framework, runtime or cryptographic
//! dependency. It is suitable for the non-production P0 development slice.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::time::Duration;

pub const MAX_HTTP_HEAD_BYTES: usize = 16 * 1024;
pub const MAX_HTTP_BODY_BYTES: usize = 1024 * 1024;
pub const MAX_TARGET_BYTES: usize = 2 * 1024;
pub const MAX_HEADER_COUNT: usize = 64;
pub const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;
pub const MONOTONIC_NANOS_PER_SECOND: u64 = 1_000_000_000;
pub const MAX_REQUEST_BUDGET_NANOS: u64 = 60 * MONOTONIC_NANOS_PER_SECOND;
pub const MAX_REQUEST_BUDGET_TICKS: u64 = MAX_REQUEST_BUDGET_NANOS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    List,
}

impl Method {
    fn parse(value: &str) -> Result<Self, ProtocolError> {
        match value {
            "GET" => Ok(Self::Get),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "DELETE" => Ok(Self::Delete),
            "LIST" => Ok(Self::List),
            _ => Err(ProtocolError::UnsupportedMethod),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::List => "LIST",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    SysHealth,
    SysInit,
    SysSealStatus,
    SysSeal,
    SysUnseal,
    KvRead,
    KvWrite,
    KvList,
    KvDelete,
}

impl Operation {
    pub const fn mutates(self) -> bool {
        matches!(
            self,
            Self::SysInit | Self::SysSeal | Self::SysUnseal | Self::KvWrite | Self::KvDelete
        )
    }

    pub const fn requires_authentication(self) -> bool {
        !matches!(
            self,
            Self::SysHealth | Self::SysInit | Self::SysSealStatus | Self::SysUnseal
        )
    }

    pub const fn allowed_while_sealed(self) -> bool {
        matches!(
            self,
            Self::SysHealth | Self::SysInit | Self::SysSealStatus | Self::SysUnseal
        )
    }
}

fn zeroize_string(value: &mut String) {
    let mut bytes = std::mem::take(value).into_bytes();
    bytes.fill(0);
}

#[derive(Default)]
struct SensitiveQueryMap(BTreeMap<String, String>);

impl SensitiveQueryMap {
    fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    fn insert(&mut self, key: String, value: String) {
        self.0.insert(key, value);
    }

    fn into_pairs(mut self) -> Vec<(String, String)> {
        std::mem::take(&mut self.0).into_iter().collect()
    }
}

impl Drop for SensitiveQueryMap {
    fn drop(&mut self) {
        let values = std::mem::take(&mut self.0);
        for (mut name, mut value) in values {
            zeroize_string(&mut name);
            zeroize_string(&mut value);
        }
    }
}

#[derive(Eq, PartialEq)]
pub struct CanonicalTarget {
    path: String,
    query: Vec<(String, String)>,
}

impl fmt::Debug for CanonicalTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalTarget")
            .field("path_bytes", &self.path.len())
            .field("query_pairs", &self.query.len())
            .finish()
    }
}

impl Drop for CanonicalTarget {
    fn drop(&mut self) {
        zeroize_string(&mut self.path);
        for (name, value) in &mut self.query {
            zeroize_string(name);
            zeroize_string(value);
        }
    }
}

impl CanonicalTarget {
    pub fn parse(raw: &str) -> Result<Self, ProtocolError> {
        if raw.is_empty() || raw.len() > MAX_TARGET_BYTES || !raw.is_ascii() {
            return Err(ProtocolError::InvalidTarget);
        }
        if raw.contains('#') {
            return Err(ProtocolError::FragmentForbidden);
        }
        let (path, raw_query) = match raw.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (raw, None),
        };
        validate_canonical_path(path)?;
        let query = parse_canonical_query(raw_query)?;
        Ok(Self {
            path: path.to_owned(),
            query,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn query(&self) -> &[(String, String)] {
        &self.query
    }

    pub fn canonical_string(&self) -> String {
        if self.query.is_empty() {
            return self.path.clone();
        }
        let mut result = self.path.clone();
        result.push('?');
        for (index, (name, value)) in self.query.iter().enumerate() {
            if index != 0 {
                result.push('&');
            }
            result.push_str(name);
            result.push('=');
            result.push_str(value);
        }
        result
    }

    pub fn matches_canonical(&self, raw: &str) -> bool {
        if self.query.is_empty() {
            return self.path == raw;
        }
        let Some((path, query)) = raw.split_once('?') else {
            return false;
        };
        if path != self.path {
            return false;
        }
        let mut actual_pairs = query.split('&');
        for (expected_name, expected_value) in &self.query {
            let Some(actual_pair) = actual_pairs.next() else {
                return false;
            };
            let Some((actual_name, actual_value)) = actual_pair.split_once('=') else {
                return false;
            };
            if actual_name != expected_name || actual_value != expected_value {
                return false;
            }
        }
        actual_pairs.next().is_none()
    }
}

fn validate_canonical_path(path: &str) -> Result<(), ProtocolError> {
    if !path.starts_with("/v1/") || path.len() > MAX_TARGET_BYTES {
        return Err(ProtocolError::InvalidTarget);
    }
    if path.contains('\\') || path.contains("//") || path.as_bytes().contains(&0) {
        return Err(ProtocolError::AmbiguousPath);
    }
    for segment in path.split('/').skip(1) {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(ProtocolError::AmbiguousPath);
        }
        validate_percent_encoding(segment)?;
    }
    Ok(())
}

fn parse_canonical_query(raw: Option<&str>) -> Result<Vec<(String, String)>, ProtocolError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if raw.is_empty() {
        return Err(ProtocolError::AmbiguousQuery);
    }
    let mut values = SensitiveQueryMap::default();
    for pair in raw.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            return Err(ProtocolError::AmbiguousQuery);
        };
        if name.is_empty() {
            return Err(ProtocolError::AmbiguousQuery);
        }
        validate_percent_encoding(name)?;
        validate_percent_encoding(value)?;
        if values.contains_key(name) {
            return Err(ProtocolError::DuplicateQueryKey);
        }
        values.insert(name.to_owned(), value.to_owned());
    }
    Ok(values.into_pairs())
}

fn validate_percent_encoding(value: &str) -> Result<(), ProtocolError> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len() {
                return Err(ProtocolError::InvalidPercentEncoding);
            }
            let high = hex_value(bytes[index + 1]).ok_or(ProtocolError::InvalidPercentEncoding)?;
            let low = hex_value(bytes[index + 2]).ok_or(ProtocolError::InvalidPercentEncoding)?;
            if !bytes[index + 1].is_ascii_uppercase() && bytes[index + 1].is_ascii_alphabetic() {
                return Err(ProtocolError::NonCanonicalPercentEncoding);
            }
            if !bytes[index + 2].is_ascii_uppercase() && bytes[index + 2].is_ascii_alphabetic() {
                return Err(ProtocolError::NonCanonicalPercentEncoding);
            }
            let decoded = (high << 4) | low;
            if decoded == b'/'
                || decoded == b'\\'
                || decoded == 0
                || decoded.is_ascii_alphanumeric()
                || matches!(decoded, b'-' | b'.' | b'_' | b'~')
            {
                return Err(ProtocolError::NonCanonicalPercentEncoding);
            }
            index += 3;
            continue;
        }
        if byte.is_ascii_control() || byte == b' ' {
            return Err(ProtocolError::InvalidTarget);
        }
        index += 1;
    }
    Ok(())
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'A'..=b'F' => Some(value - b'A' + 10),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[derive(Eq, PartialEq)]
pub struct HeaderMap(BTreeMap<String, Vec<u8>>);

impl fmt::Debug for HeaderMap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = self.0.keys().map(String::as_str).collect::<Vec<_>>();
        formatter
            .debug_struct("HeaderMap")
            .field("names", &names)
            .field("count", &self.0.len())
            .finish()
    }
}

impl Drop for HeaderMap {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.fill(0);
        }
    }
}

impl HeaderMap {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .get(&name.to_ascii_lowercase())
            .and_then(|value| std::str::from_utf8(value).ok())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().filter_map(|(name, value)| {
            std::str::from_utf8(value)
                .ok()
                .map(|value| (name.as_str(), value))
        })
    }
}

#[derive(Eq, PartialEq)]
pub struct ParsedHttpRequest {
    pub method: Method,
    pub target: CanonicalTarget,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl fmt::Debug for ParsedHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedHttpRequest")
            .field("method", &self.method)
            .field("target", &self.target)
            .field("headers", &self.headers)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl Drop for ParsedHttpRequest {
    fn drop(&mut self) {
        self.body.fill(0);
    }
}

pub fn parse_http_request(input: &[u8]) -> Result<ParsedHttpRequest, ProtocolError> {
    if input.len() > MAX_HTTP_HEAD_BYTES + MAX_HTTP_BODY_BYTES + 4 {
        return Err(ProtocolError::RequestTooLarge);
    }
    let head_end = match input.windows(4).position(|window| window == b"\r\n\r\n") {
        Some(value) => value,
        None if input.len() > MAX_HTTP_HEAD_BYTES + 3 => {
            return Err(ProtocolError::HeadTooLarge);
        }
        None => return Err(ProtocolError::IncompleteHead),
    };
    if head_end > MAX_HTTP_HEAD_BYTES {
        return Err(ProtocolError::HeadTooLarge);
    }
    validate_crlf(&input[..head_end + 4])?;
    let head = std::str::from_utf8(&input[..head_end]).map_err(|_| ProtocolError::NonUtf8Head)?;
    if !head.is_ascii() {
        return Err(ProtocolError::NonAsciiHead);
    }
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(ProtocolError::InvalidRequestLine)?;
    let (method, target) = parse_request_line(request_line)?;
    let mut headers = HeaderMap(BTreeMap::new());
    for line in lines {
        if headers.0.len() >= MAX_HEADER_COUNT {
            return Err(ProtocolError::TooManyHeaders);
        }
        if line.is_empty() || line.starts_with(' ') || line.starts_with('\t') {
            return Err(ProtocolError::InvalidHeader);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(ProtocolError::InvalidHeader);
        };
        validate_header_name(name)?;
        let value = value.strip_prefix(' ').unwrap_or(value);
        if value.is_empty()
            || value.starts_with(' ')
            || value.starts_with('\t')
            || value.ends_with(' ')
            || value.ends_with('\t')
            || value.contains('\t')
        {
            return Err(ProtocolError::NonCanonicalHeaderValue);
        }
        if value.len() > MAX_HEADER_VALUE_BYTES || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(ProtocolError::InvalidHeader);
        }
        let canonical_name = name.to_ascii_lowercase();
        if headers.0.contains_key(&canonical_name) {
            return Err(ProtocolError::DuplicateHeader);
        }
        headers.0.insert(canonical_name, value.as_bytes().to_vec());
    }
    if headers.get("host").is_none_or(str::is_empty) {
        return Err(ProtocolError::MissingHost);
    }
    if headers.get("transfer-encoding").is_some() {
        return Err(ProtocolError::TransferEncodingForbidden);
    }
    let body = &input[head_end + 4..];
    if body.len() > MAX_HTTP_BODY_BYTES {
        return Err(ProtocolError::BodyTooLarge);
    }
    let declared_length = match headers.get("content-length") {
        Some(value) => parse_content_length(value)?,
        None => 0,
    };
    if declared_length > MAX_HTTP_BODY_BYTES {
        return Err(ProtocolError::BodyTooLarge);
    }
    if body.len() < declared_length {
        return Err(ProtocolError::ContentLengthMismatch);
    }
    if body.len() > declared_length {
        return Err(ProtocolError::ContentLengthExceeded);
    }
    Ok(ParsedHttpRequest {
        method,
        target,
        headers,
        body: body.to_vec(),
    })
}

fn parse_content_length(value: &str) -> Result<usize, ProtocolError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(ProtocolError::InvalidContentLength);
    }
    value
        .parse::<usize>()
        .map_err(|_| ProtocolError::InvalidContentLength)
}

fn validate_crlf(head: &[u8]) -> Result<(), ProtocolError> {
    for (index, byte) in head.iter().copied().enumerate() {
        if byte == b'\n' && (index == 0 || head[index - 1] != b'\r') {
            return Err(ProtocolError::BareLineFeed);
        }
        if byte == b'\r' && head.get(index + 1).copied() != Some(b'\n') {
            return Err(ProtocolError::BareCarriageReturn);
        }
        if byte == 0 {
            return Err(ProtocolError::ControlCharacter);
        }
    }
    Ok(())
}

fn parse_request_line(line: &str) -> Result<(Method, CanonicalTarget), ProtocolError> {
    if line.contains('\t') || line.starts_with(' ') || line.ends_with(' ') || line.contains("  ") {
        return Err(ProtocolError::InvalidRequestLine);
    }
    let mut parts = line.split(' ');
    let method = parts.next().ok_or(ProtocolError::InvalidRequestLine)?;
    let target = parts.next().ok_or(ProtocolError::InvalidRequestLine)?;
    let version = parts.next().ok_or(ProtocolError::InvalidRequestLine)?;
    if parts.next().is_some() || version != "HTTP/1.1" {
        return Err(ProtocolError::UnsupportedHttpVersion);
    }
    Ok((Method::parse(method)?, CanonicalTarget::parse(target)?))
}

fn validate_header_name(name: &str) -> Result<(), ProtocolError> {
    if name.is_empty()
        || name.bytes().any(|byte| {
            !byte.is_ascii_alphanumeric()
                && !matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    {
        return Err(ProtocolError::InvalidHeaderName);
    }
    Ok(())
}

pub fn classify_operation(
    method: Method,
    target: &CanonicalTarget,
) -> Result<Operation, ProtocolError> {
    if !target.query().is_empty() {
        return Err(ProtocolError::UnsupportedQuery);
    }
    match (method, target.path()) {
        (Method::Get, "/v1/sys/health") => Ok(Operation::SysHealth),
        (Method::Put | Method::Post, "/v1/sys/init") => Ok(Operation::SysInit),
        (Method::Get, "/v1/sys/seal-status") => Ok(Operation::SysSealStatus),
        (Method::Put | Method::Post, "/v1/sys/seal") => Ok(Operation::SysSeal),
        (Method::Put | Method::Post, "/v1/sys/unseal") => Ok(Operation::SysUnseal),
        (Method::Get, path) if is_kv_path(path) => Ok(Operation::KvRead),
        (Method::List, path) if is_kv_path(path) => Ok(Operation::KvList),
        (Method::Put | Method::Post, path) if is_kv_path(path) => Ok(Operation::KvWrite),
        (Method::Delete, path) if is_kv_path(path) => Ok(Operation::KvDelete),
        _ => Err(ProtocolError::UnknownOperation),
    }
}

fn is_kv_path(path: &str) -> bool {
    path.strip_prefix("/v1/secret/")
        .is_some_and(|suffix| !suffix.is_empty())
}

/// Nanoseconds from one process-local monotonic clock epoch.
///
/// Values from different processes or clock domains must never be compared or
/// serialized as cross-process validity evidence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicTick(pub u64);

impl MonotonicTick {
    pub const fn from_nanos(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    pub fn checked_add_duration(self, duration: Duration) -> Option<Self> {
        let nanos = u64::try_from(duration.as_nanos()).ok()?;
        self.0.checked_add(nanos).map(Self)
    }

    pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0).map(Duration::from_nanos)
    }
}

#[derive(Eq, PartialEq)]
pub struct RequestEnvelope {
    pub request_id: RequestId,
    pub request: ParsedHttpRequest,
    pub received_at: MonotonicTick,
    pub deadline: MonotonicTick,
}

impl fmt::Debug for RequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestEnvelope")
            .field("request_id", &self.request_id)
            .field("request", &self.request)
            .field("received_at", &self.received_at)
            .field("deadline", &self.deadline)
            .finish()
    }
}

impl RequestEnvelope {
    pub fn validate_at(&self, now: MonotonicTick) -> Result<Operation, ProtocolError> {
        if self.deadline <= self.received_at {
            return Err(ProtocolError::InvalidDeadline);
        }
        let budget = self
            .deadline
            .checked_duration_since(self.received_at)
            .ok_or(ProtocolError::InvalidDeadline)?;
        if budget > Duration::from_nanos(MAX_REQUEST_BUDGET_NANOS) {
            return Err(ProtocolError::DeadlineBudgetTooLarge);
        }
        if now < self.received_at {
            return Err(ProtocolError::ClockRegression);
        }
        if now >= self.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        classify_operation(self.request.method, &self.request.target)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RequestId(String);

impl RequestId {
    pub fn new(value: String) -> Result<Self, ProtocolError> {
        if value.len() < 8
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ProtocolError::InvalidRequestId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditPhase {
    RequestAccepted,
    RequestRejected,
    ResponsePrepared,
    ResponseCommitted,
    ResponseAuditFailedAfterCommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitDisposition {
    NotAttempted,
    NotCommitted,
    Committed,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    pub request_id: RequestId,
    pub operation: Option<Operation>,
    pub phase: AuditPhase,
    pub commit: CommitDisposition,
    pub status_code: u16,
    pub detail_code: &'static str,
}

#[derive(Eq, PartialEq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(mut value: Vec<u8>) -> Result<Self, ProtocolError> {
        if value.is_empty() || value.len() > MAX_HTTP_BODY_BYTES {
            value.fill(0);
            return Err(ProtocolError::InvalidSecret);
        }
        Ok(Self(value))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn constant_time_eq(&self, candidate: &[u8]) -> bool {
        let mut difference = self.0.len() ^ candidate.len();
        let maximum = self.0.len().max(candidate.len());
        for index in 0..maximum {
            let left = self.0.get(index).copied().unwrap_or(0);
            let right = candidate.get(index).copied().unwrap_or(0);
            difference |= usize::from(left ^ right);
        }
        difference == 0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    RequestTooLarge,
    HeadTooLarge,
    BodyTooLarge,
    IncompleteHead,
    BareLineFeed,
    BareCarriageReturn,
    ControlCharacter,
    NonUtf8Head,
    NonAsciiHead,
    InvalidRequestLine,
    UnsupportedHttpVersion,
    UnsupportedMethod,
    InvalidTarget,
    AmbiguousPath,
    FragmentForbidden,
    InvalidPercentEncoding,
    NonCanonicalPercentEncoding,
    AmbiguousQuery,
    DuplicateQueryKey,
    UnsupportedQuery,
    TooManyHeaders,
    InvalidHeader,
    InvalidHeaderName,
    NonCanonicalHeaderValue,
    DuplicateHeader,
    MissingHost,
    TransferEncodingForbidden,
    InvalidContentLength,
    ContentLengthMismatch,
    ContentLengthExceeded,
    UnknownOperation,
    InvalidDeadline,
    DeadlineBudgetTooLarge,
    ClockRegression,
    DeadlineExceeded,
    InvalidRequestId,
    InvalidSecret,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RequestTooLarge => "request exceeds the total size bound",
            Self::HeadTooLarge => "request head exceeds the size bound",
            Self::BodyTooLarge => "request body exceeds the size bound",
            Self::IncompleteHead => "request head terminator is missing",
            Self::BareLineFeed => "bare line feed is forbidden",
            Self::BareCarriageReturn => "bare carriage return is forbidden",
            Self::ControlCharacter => "control character is forbidden",
            Self::NonUtf8Head => "request head is not UTF-8",
            Self::NonAsciiHead => "request head is not ASCII",
            Self::InvalidRequestLine => "request line is invalid or non-canonical",
            Self::UnsupportedHttpVersion => "HTTP version is unsupported",
            Self::UnsupportedMethod => "method is unsupported",
            Self::InvalidTarget => "request target is invalid",
            Self::AmbiguousPath => "request path is ambiguous",
            Self::FragmentForbidden => "URI fragment is forbidden",
            Self::InvalidPercentEncoding => "percent encoding is invalid",
            Self::NonCanonicalPercentEncoding => "percent encoding is non-canonical",
            Self::AmbiguousQuery => "query is ambiguous",
            Self::DuplicateQueryKey => "query key is duplicated",
            Self::UnsupportedQuery => "query is unsupported for this operation",
            Self::TooManyHeaders => "header count exceeds the bound",
            Self::InvalidHeader => "header is invalid",
            Self::InvalidHeaderName => "header name is invalid",
            Self::NonCanonicalHeaderValue => "header value is non-canonical",
            Self::DuplicateHeader => "duplicate header is forbidden",
            Self::MissingHost => "one non-empty Host header is required",
            Self::TransferEncodingForbidden => "Transfer-Encoding is forbidden in P0",
            Self::InvalidContentLength => "Content-Length is invalid",
            Self::ContentLengthMismatch => "request body is incomplete for Content-Length",
            Self::ContentLengthExceeded => "request body exceeds Content-Length",
            Self::UnknownOperation => "operation is not registered",
            Self::InvalidDeadline => "deadline is not after receipt",
            Self::DeadlineBudgetTooLarge => "deadline budget exceeds the bound",
            Self::ClockRegression => "monotonic clock regressed",
            Self::DeadlineExceeded => "request deadline is exceeded",
            Self::InvalidRequestId => "request identity is invalid",
            Self::InvalidSecret => "secret value is invalid",
        })
    }
}

impl Error for ProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(raw: &str) -> Result<ParsedHttpRequest, ProtocolError> {
        parse_http_request(raw.as_bytes())
    }

    #[test]
    fn strict_request_parses_and_classifies() {
        let result = request("GET /v1/sys/health HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");
        assert!(result.is_ok());
        if let Ok(value) = result {
            assert_eq!(
                classify_operation(value.method, &value.target),
                Ok(Operation::SysHealth)
            );
            assert_eq!(value.headers.get("HOST"), Some("127.0.0.1"));
        }
    }

    #[test]
    fn duplicate_host_is_rejected() {
        let result = request("GET /v1/sys/health HTTP/1.1\r\nHost: a\r\nhost: b\r\n\r\n");
        assert_eq!(result, Err(ProtocolError::DuplicateHeader));
    }

    #[test]
    fn request_line_whitespace_smuggling_is_rejected() {
        for raw in [
            "GET  /v1/sys/health HTTP/1.1\r\nHost: a\r\n\r\n",
            "GET\t/v1/sys/health HTTP/1.1\r\nHost: a\r\n\r\n",
            " GET /v1/sys/health HTTP/1.1\r\nHost: a\r\n\r\n",
        ] {
            assert!(request(raw).is_err());
        }
    }

    #[test]
    fn encoded_slash_and_lowercase_encoding_are_rejected() {
        assert_eq!(
            CanonicalTarget::parse("/v1/secret/a%2Fb"),
            Err(ProtocolError::NonCanonicalPercentEncoding)
        );
        assert_eq!(
            CanonicalTarget::parse("/v1/secret/a%3ab"),
            Err(ProtocolError::NonCanonicalPercentEncoding)
        );
    }

    #[test]
    fn query_keys_are_unique_sorted_and_exactly_matchable() {
        let target = CanonicalTarget::parse("/v1/secret/a?b=2&a=1");
        assert!(target.is_ok());
        if let Ok(value) = target {
            assert_eq!(value.canonical_string(), "/v1/secret/a?a=1&b=2");
            assert!(value.matches_canonical("/v1/secret/a?a=1&b=2"));
            assert!(!value.matches_canonical("/v1/secret/a?b=2&a=1"));
        }
        assert_eq!(
            CanonicalTarget::parse("/v1/secret/a?a=1&a=2"),
            Err(ProtocolError::DuplicateQueryKey)
        );
    }

    #[test]
    fn oversized_unterminated_head_is_rejected_early() {
        let mut raw = b"GET /v1/sys/health HTTP/1.1\r\nHost: a\r\nX-Fill: ".to_vec();
        raw.resize(MAX_HTTP_HEAD_BYTES + 4, b'a');
        assert_eq!(parse_http_request(&raw), Err(ProtocolError::HeadTooLarge));
    }

    #[test]
    fn body_requires_exact_content_length() {
        assert!(request("POST /v1/sys/init HTTP/1.1\r\nHost: a\r\n\r\n{}").is_err());
        assert!(
            request("POST /v1/sys/init HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\n{}").is_ok()
        );
        assert_eq!(
            request("POST /v1/sys/init HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\n{}"),
            Err(ProtocolError::ContentLengthExceeded)
        );
        assert_eq!(
            request("POST /v1/sys/init HTTP/1.1\r\nHost: a\r\nContent-Length: 02\r\n\r\n{}"),
            Err(ProtocolError::InvalidContentLength)
        );
    }

    #[test]
    fn deadline_uses_actual_dispatch_time() {
        let parsed = request("GET /v1/sys/health HTTP/1.1\r\nHost: a\r\n\r\n");
        assert!(parsed.is_ok());
        if let Ok(request) = parsed {
            let request_id = RequestId::new("request-0001".to_owned());
            assert!(request_id.is_ok());
            if let Ok(request_id) = request_id {
                let received = MonotonicTick::from_nanos(100);
                let deadline = received.checked_add_duration(Duration::from_nanos(10));
                assert!(deadline.is_some());
                if let Some(deadline) = deadline {
                    let envelope = RequestEnvelope {
                        request_id,
                        request,
                        received_at: received,
                        deadline,
                    };
                    assert_eq!(
                        envelope.validate_at(MonotonicTick::from_nanos(109)),
                        Ok(Operation::SysHealth)
                    );
                    assert_eq!(
                        envelope.validate_at(MonotonicTick::from_nanos(110)),
                        Err(ProtocolError::DeadlineExceeded)
                    );
                }
            }
        }
    }

    #[test]
    fn deadline_must_be_strictly_after_receipt() {
        let parsed = request("GET /v1/sys/health HTTP/1.1\r\nHost: a\r\n\r\n");
        assert!(parsed.is_ok());
        if let Ok(request) = parsed {
            let request_id = RequestId::new("request-0002".to_owned());
            assert!(request_id.is_ok());
            if let Ok(request_id) = request_id {
                let at = MonotonicTick::from_nanos(100);
                let envelope = RequestEnvelope {
                    request_id,
                    request,
                    received_at: at,
                    deadline: at,
                };
                assert_eq!(
                    envelope.validate_at(at),
                    Err(ProtocolError::InvalidDeadline)
                );
            }
        }
    }

    #[test]
    fn monotonic_units_are_nanoseconds_and_budget_is_sixty_seconds() {
        assert_eq!(MONOTONIC_NANOS_PER_SECOND, 1_000_000_000);
        assert_eq!(MAX_REQUEST_BUDGET_NANOS, 60_000_000_000);
        let start = MonotonicTick::from_nanos(5);
        let end = start.checked_add_duration(Duration::from_secs(60));
        assert_eq!(end.map(MonotonicTick::as_nanos), Some(60_000_000_005));
    }

    #[test]
    fn monotonic_duration_addition_fails_on_overflow() {
        let start = MonotonicTick::from_nanos(u64::MAX);
        assert!(
            start
                .checked_add_duration(Duration::from_nanos(1))
                .is_none()
        );
    }

    #[test]
    fn request_debug_redacts_path_header_values_and_body() {
        let raw = concat!(
            "POST /v1/secret/top-secret-path HTTP/1.1\r\n",
            "Host: example.invalid\r\n",
            "X-Vault-Token: development-token-must-not-leak\r\n",
            "Content-Length: 23\r\n",
            "\r\n",
            "{\"value\":\"body-secret\"}"
        );
        let parsed = request(raw);
        assert!(parsed.is_ok());
        if let Ok(parsed) = parsed {
            let rendered = format!("{parsed:?}");
            assert!(!rendered.contains("top-secret-path"));
            assert!(!rendered.contains("development-token-must-not-leak"));
            assert!(!rendered.contains("body-secret"));
            assert!(rendered.contains("body_bytes"));
        }
    }

    #[test]
    fn secret_debug_is_redacted_and_compare_is_length_aware() {
        let secret = SecretBytes::new(b"correct horse".to_vec());
        assert!(secret.is_ok());
        if let Ok(value) = secret {
            assert!(value.constant_time_eq(b"correct horse"));
            assert!(!value.constant_time_eq(b"correct horse!"));
            assert!(!format!("{value:?}").contains("correct"));
        }
    }
}
