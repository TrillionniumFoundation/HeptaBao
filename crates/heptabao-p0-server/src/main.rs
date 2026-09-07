#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::env;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use heptabao_p0_server::{
    AuditError, AuditSink, DevelopmentCredentials, FileAuditSink, P0Response, P0Server,
};
use heptabao_protocol::{
    AuditEvent, AuditPhase, CommitDisposition, MonotonicTick, ProtocolError, RequestEnvelope,
    RequestId, parse_http_request,
};

const TOTAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONCURRENT_CONNECTIONS: usize = 32;
const REQUEST_ID_TTL: Duration = Duration::from_secs(60);
const MAX_CLIENT_REQUEST_IDS: usize = 4096;

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("heptabao-p0-server: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let bind = env::var("HEPTABAO_P0_BIND").unwrap_or_else(|_| "127.0.0.1:18200".to_owned());
    let address = bind
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid HEPTABAO_P0_BIND: {error}"))?;
    if !is_loopback(address.ip()) {
        return Err("P0 listener must bind to a loopback address".to_owned());
    }

    let token = env::var("HEPTABAO_P0_DEV_TOKEN")
        .map_err(|_| "HEPTABAO_P0_DEV_TOKEN is required".to_owned())?;
    let unseal_key = env::var("HEPTABAO_P0_DEV_UNSEAL_KEY")
        .map_err(|_| "HEPTABAO_P0_DEV_UNSEAL_KEY is required".to_owned())?;
    let audit_path = env::var("HEPTABAO_P0_AUDIT_PATH")
        .map_err(|_| "HEPTABAO_P0_AUDIT_PATH is required".to_owned())?;

    let credentials = DevelopmentCredentials::new(token.into_bytes(), unseal_key.into_bytes())
        .map_err(|error| error.to_string())?;
    let shared_audit = SharedAuditSink::new(
        FileAuditSink::create_new(audit_path).map_err(|error| error.to_string())?,
    );
    let server = Arc::new(Mutex::new(P0Server::new(credentials, shared_audit.clone())));
    let request_ids = Arc::new(RequestIdRegistry::new(
        MAX_CLIENT_REQUEST_IDS,
        REQUEST_ID_TTL,
    ));
    let active_connections = Arc::new(AtomicUsize::new(0));

    let listener = TcpListener::bind(address).map_err(|error| format!("bind failed: {error}"))?;
    let local_address = listener
        .local_addr()
        .map_err(|error| format!("read local listener address failed: {error}"))?;
    let expected_host = Arc::new(local_address.to_string());
    let epoch = Instant::now();
    let startup_id = startup_id()?;

    eprintln!(
        "HeptaBao P0 development server listening on \
         {local_address}; production_supported=false authority=NONE"
    );

    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("accept failed: {error}");
                continue;
            }
        };
        let attempt_id = next_request_id(&startup_id)?;
        let previous = active_connections.fetch_add(1, Ordering::AcqRel);
        if previous >= MAX_CONCURRENT_CONNECTIONS {
            active_connections.fetch_sub(1, Ordering::AcqRel);
            // The client may already have sent bytes, but the capacity gate
            // rejects before a worker is allocated.  Drain only bytes already
            // available with a tiny bounded read window.  Closing a TCP stream
            // while unread ingress remains can produce a kernel RST and erase
            // the rejection response; the bounded drain preserves the wire
            // contract without allowing a slow client to hold the listener.
            discard_available_ingress(&mut stream);
            let audit_ok = record_transport_rejection(
                &shared_audit,
                attempt_id,
                429,
                "connection-capacity-exhausted",
            )
            .is_ok();
            let (status, message) = if audit_ok {
                (429, "connection capacity exhausted")
            } else {
                (503, "transport rejection audit unavailable")
            };
            let response = error_response(status, message);
            let _write_result = write_response_with_timeout(&mut stream, &response);
            continue;
        }

        let worker_server = Arc::clone(&server);
        let worker_audit = shared_audit.clone();
        let worker_ids = Arc::clone(&request_ids);
        let worker_active = Arc::clone(&active_connections);
        let worker_host = Arc::clone(&expected_host);
        let spawn_failure_audit = worker_audit.clone();
        let spawn_failure_active = Arc::clone(&worker_active);
        let spawn_failure_attempt_id = attempt_id.clone();
        let worker_result = thread::Builder::new()
            .name("heptabao-p0-connection".to_owned())
            .spawn(move || {
                let _connection_guard = ConnectionGuard::new(worker_active);
                if let Err(error) = serve_one(
                    &mut stream,
                    &worker_server,
                    &worker_audit,
                    &worker_ids,
                    epoch,
                    worker_host.as_str(),
                    attempt_id.clone(),
                ) {
                    let audit_ok = record_transport_rejection(
                        &worker_audit,
                        attempt_id,
                        error.status_code,
                        error.detail_code,
                    )
                    .is_ok();
                    let status = if audit_ok { error.status_code } else { 503 };
                    let message = if audit_ok {
                        error.message
                    } else {
                        "transport rejection audit unavailable".to_owned()
                    };
                    let response = error_response(status, &message);
                    let _write_result = write_response_with_timeout(&mut stream, &response);
                }
            });
        if let Err(error) = worker_result {
            spawn_failure_active.fetch_sub(1, Ordering::AcqRel);
            let _audit_result = record_transport_rejection(
                &spawn_failure_audit,
                spawn_failure_attempt_id,
                503,
                "connection-worker-spawn-failed",
            );
            eprintln!("connection worker spawn failed: {error}");
        }
    }
    Ok(())
}

fn is_loopback(address: IpAddr) -> bool {
    address.is_loopback()
}

fn discard_available_ingress(stream: &mut TcpStream) {
    // Bound the *whole* drain window, not each individual read.  Repeated
    // per-read timeouts could otherwise stretch a saturated rejection into
    // roughly 128ms on a peer that keeps trickling bytes.
    let deadline = Instant::now() + Duration::from_millis(2);
    let mut buffer = [0_u8; 4096];
    for _ in 0..64 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let _ = stream.set_read_timeout(Some(remaining));
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => buffer[..count].fill(0),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                ) =>
            {
                break;
            }
            Err(_) => break,
        }
    }
    buffer.fill(0);
}

#[derive(Clone, Debug)]
struct SharedAuditSink {
    inner: Arc<Mutex<FileAuditSink>>,
}

impl SharedAuditSink {
    fn new(inner: FileAuditSink) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

impl AuditSink for SharedAuditSink {
    fn record(&mut self, event: &AuditEvent) -> Result<(), AuditError> {
        let mut guard = self.inner.lock().map_err(|_| AuditError::InjectedFailure)?;
        guard.record(event)
    }
}

#[derive(Debug)]
struct ConnectionGuard {
    active: Arc<AtomicUsize>,
}

impl ConnectionGuard {
    fn new(active: Arc<AtomicUsize>) -> Self {
        Self { active }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct RequestIdRegistry {
    entries: Mutex<BTreeMap<String, Instant>>,
    max_entries: usize,
    ttl: Duration,
}

impl fmt::Debug for RequestIdRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestIdRegistry")
            .field("entries", &"[REDACTED]")
            .field("max_entries", &self.max_entries)
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl RequestIdRegistry {
    fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
            max_entries,
            ttl,
        }
    }

    fn claim(&self, raw: &str, now: Instant) -> Result<RequestId, ServeError> {
        let request_id = RequestId::new(raw.to_owned()).map_err(|error| ServeError {
            status_code: 400,
            detail_code: "client-request-id-invalid",
            message: error.to_string(),
        })?;
        let mut entries = self.entries.lock().map_err(|_| ServeError {
            status_code: 503,
            detail_code: "request-id-registry-unavailable",
            message: "request ID registry unavailable".to_owned(),
        })?;
        entries.retain(|_, expires_at| *expires_at > now);
        let current_len = entries.len();
        let expires_at = now.checked_add(self.ttl).ok_or_else(|| ServeError {
            status_code: 503,
            detail_code: "request-id-expiry-overflow",
            message: "request ID expiry overflow".to_owned(),
        })?;
        match entries.entry(request_id.as_str().to_owned()) {
            Entry::Occupied(_) => Err(ServeError {
                status_code: 409,
                detail_code: "client-request-id-replayed",
                message: "client request ID was already used".to_owned(),
            }),
            Entry::Vacant(entry) => {
                if current_len >= self.max_entries {
                    return Err(ServeError {
                        status_code: 503,
                        detail_code: "request-id-registry-saturated",
                        message: "request ID registry is saturated".to_owned(),
                    });
                }
                entry.insert(expires_at);
                Ok(request_id)
            }
        }
    }
}

#[derive(Debug)]
struct ServeError {
    status_code: u16,
    detail_code: &'static str,
    message: String,
}

impl ServeError {
    fn from_protocol(error: ProtocolError) -> Self {
        Self {
            status_code: protocol_status(error),
            detail_code: protocol_detail_code(error),
            message: error.to_string(),
        }
    }
}

fn serve_one(
    stream: &mut TcpStream,
    server: &Arc<Mutex<P0Server<SharedAuditSink>>>,
    audit: &SharedAuditSink,
    request_ids: &RequestIdRegistry,
    epoch: Instant,
    expected_host: &str,
    attempt_id: RequestId,
) -> Result<(), ServeError> {
    stream
        .set_write_timeout(Some(TOTAL_REQUEST_TIMEOUT))
        .map_err(|error| ServeError {
            status_code: 503,
            detail_code: "socket-write-timeout-configuration-failed",
            message: format!("set write timeout failed: {error}"),
        })?;

    let received = tick(epoch).map_err(internal_serve_error)?;
    let read_deadline = Instant::now()
        .checked_add(TOTAL_REQUEST_TIMEOUT)
        .ok_or_else(|| internal_serve_error("request read deadline overflow".to_owned()))?;
    let request = read_request(stream, read_deadline)?;
    if request.headers.get("host") != Some(expected_host) {
        return Err(ServeError {
            status_code: 400,
            detail_code: "host-listener-mismatch",
            message: "Host must exactly match the loopback listener address".to_owned(),
        });
    }

    let request_id = match request.headers.get("x-heptabao-request-id") {
        Some(raw) => request_ids.claim(raw, Instant::now())?,
        None => attempt_id,
    };
    let deadline = received
        .checked_add_duration(TOTAL_REQUEST_TIMEOUT)
        .ok_or_else(|| internal_serve_error("request deadline overflow".to_owned()))?;
    let envelope = RequestEnvelope {
        request_id: request_id.clone(),
        request,
        received_at: received,
        deadline,
    };
    let response = match server.try_lock() {
        Ok(mut guard) => {
            let now = tick(epoch).map_err(internal_serve_error)?;
            guard.handle(envelope, now)
        }
        Err(TryLockError::WouldBlock) => {
            return Err(ServeError {
                status_code: 503,
                detail_code: "p0-state-busy",
                message: "P0 state is busy".to_owned(),
            });
        }
        Err(TryLockError::Poisoned(_)) => {
            return Err(ServeError {
                status_code: 503,
                detail_code: "p0-state-lock-unavailable",
                message: "P0 state lock unavailable".to_owned(),
            });
        }
    };

    if let Err(error) = write_response_with_timeout(stream, &response) {
        let _audit_result = record_delivery_failure(audit, request_id, response.committed);
        eprintln!("response delivery failed: {error}");
    }
    Ok(())
}

fn read_request(
    stream: &mut TcpStream,
    absolute_deadline: Instant,
) -> Result<heptabao_protocol::ParsedHttpRequest, ServeError> {
    let max_total =
        heptabao_protocol::MAX_HTTP_HEAD_BYTES + heptabao_protocol::MAX_HTTP_BODY_BYTES + 4;
    let mut input = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        match parse_http_request(&input) {
            Ok(request) => {
                clear_request_buffers(&mut input, &mut buffer);
                return Ok(request);
            }
            Err(ProtocolError::IncompleteHead | ProtocolError::ContentLengthMismatch) => {}
            Err(error) if !input.is_empty() => {
                clear_request_buffers(&mut input, &mut buffer);
                return Err(ServeError::from_protocol(error));
            }
            Err(_) => {}
        }

        let now = Instant::now();
        let remaining = match absolute_deadline.checked_duration_since(now) {
            Some(value) if !value.is_zero() => value,
            _ => {
                clear_request_buffers(&mut input, &mut buffer);
                return Err(ServeError {
                    status_code: 408,
                    detail_code: "request-read-deadline-exceeded",
                    message: "request read deadline exceeded".to_owned(),
                });
            }
        };
        if let Err(error) = stream.set_read_timeout(Some(remaining)) {
            clear_request_buffers(&mut input, &mut buffer);
            return Err(ServeError {
                status_code: 503,
                detail_code: "socket-read-timeout-configuration-failed",
                message: format!("set read timeout failed: {error}"),
            });
        }

        if input.len() >= max_total {
            clear_request_buffers(&mut input, &mut buffer);
            return Err(ServeError::from_protocol(ProtocolError::RequestTooLarge));
        }
        let capacity = (max_total - input.len()).min(buffer.len());
        let count = match stream.read(&mut buffer[..capacity]) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                clear_request_buffers(&mut input, &mut buffer);
                return Err(ServeError {
                    status_code: 408,
                    detail_code: "request-read-deadline-exceeded",
                    message: "request read deadline exceeded".to_owned(),
                });
            }
            Err(error) => {
                clear_request_buffers(&mut input, &mut buffer);
                return Err(ServeError {
                    status_code: 400,
                    detail_code: "request-read-io-failed",
                    message: format!("request read failed: {error}"),
                });
            }
        };
        if count == 0 {
            let result = parse_http_request(&input).map_err(ServeError::from_protocol);
            clear_request_buffers(&mut input, &mut buffer);
            return result;
        }
        input.extend_from_slice(&buffer[..count]);
        buffer[..count].fill(0);
    }
}

fn clear_request_buffers(input: &mut [u8], buffer: &mut [u8]) {
    input.fill(0);
    buffer.fill(0);
}

fn record_transport_rejection(
    audit: &SharedAuditSink,
    request_id: RequestId,
    status_code: u16,
    detail_code: &'static str,
) -> Result<(), AuditError> {
    let mut sink = audit.clone();
    sink.record(&AuditEvent {
        request_id,
        operation: None,
        phase: AuditPhase::RequestRejected,
        commit: CommitDisposition::NotAttempted,
        status_code,
        detail_code,
    })
}

fn record_delivery_failure(
    audit: &SharedAuditSink,
    request_id: RequestId,
    committed: bool,
) -> Result<(), AuditError> {
    let mut sink = audit.clone();
    sink.record(&AuditEvent {
        request_id,
        operation: None,
        phase: if committed {
            AuditPhase::ResponseCommitted
        } else {
            AuditPhase::ResponsePrepared
        },
        commit: if committed {
            CommitDisposition::Committed
        } else {
            CommitDisposition::NotCommitted
        },
        status_code: 503,
        detail_code: if committed {
            "response-delivery-failed-after-commit"
        } else {
            "response-delivery-failed-before-commit"
        },
    })
}

fn error_response(status_code: u16, message: &str) -> P0Response {
    P0Response {
        status_code,
        body: format!("{{\"errors\":[\"{}\"]}}", escape_json(message)).into_bytes(),
        committed: false,
        recovery_reference: None,
    }
}

fn write_response_with_timeout(
    stream: &mut TcpStream,
    response: &P0Response,
) -> Result<(), String> {
    let absolute_deadline = Instant::now()
        .checked_add(TOTAL_REQUEST_TIMEOUT)
        .ok_or_else(|| "response write deadline overflow".to_owned())?;
    write_response_until(stream, response, absolute_deadline)
}

fn write_response_until(
    stream: &mut TcpStream,
    response: &P0Response,
    absolute_deadline: Instant,
) -> Result<(), String> {
    let mut bytes = render_response(response);
    let result = (|| -> Result<(), String> {
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let remaining = absolute_deadline
                .checked_duration_since(Instant::now())
                .filter(|value| !value.is_zero())
                .ok_or_else(|| "response write deadline exceeded".to_owned())?;
            stream
                .set_write_timeout(Some(remaining))
                .map_err(|error| format!("set response write timeout failed: {error}"))?;
            match stream.write(&bytes[offset..]) {
                Ok(0) => return Err("response write returned zero bytes".to_owned()),
                Ok(count) => offset += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    return Err("response write deadline exceeded".to_owned());
                }
                Err(error) => return Err(format!("response write failed: {error}")),
            }
        }
        let remaining = absolute_deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
            .ok_or_else(|| "response write deadline exceeded".to_owned())?;
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|error| format!("set response flush timeout failed: {error}"))?;
        stream
            .flush()
            .map_err(|error| format!("response flush failed: {error}"))
    })();
    bytes.fill(0);
    result
}

fn render_response(response: &P0Response) -> Vec<u8> {
    let body = if response.status_code == 204 {
        &[][..]
    } else {
        response.body.as_slice()
    };
    let reason = status_reason(response.status_code);
    let mut head = format!(
        concat!(
            "HTTP/1.1 {} {}\r\n",
            "Content-Length: {}\r\n",
            "Connection: close\r\n",
            "X-HeptaBao-Profile: HB-P0-DEV-MEMORY\r\n",
            "X-HeptaBao-Production-Supported: false\r\n"
        ),
        response.status_code,
        reason,
        body.len()
    );
    if !body.is_empty() {
        head.push_str("Content-Type: application/json\r\n");
    }
    head.push_str("\r\n");
    let mut wire = head.into_bytes();
    wire.extend_from_slice(body);
    wire
}

const fn status_reason(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

const fn protocol_status(error: ProtocolError) -> u16 {
    match error {
        ProtocolError::DeadlineExceeded => 408,
        ProtocolError::UnknownOperation | ProtocolError::UnsupportedMethod => 404,
        ProtocolError::RequestTooLarge
        | ProtocolError::HeadTooLarge
        | ProtocolError::BodyTooLarge => 413,
        _ => 400,
    }
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

fn tick(epoch: Instant) -> Result<MonotonicTick, String> {
    let nanos = epoch.elapsed().as_nanos();
    let value = u64::try_from(nanos).map_err(|_| "monotonic tick overflow".to_owned())?;
    Ok(MonotonicTick::from_nanos(value))
}

fn startup_id() -> Result<String, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system time is before the Unix epoch".to_owned())?
        .as_nanos();
    Ok(format!("{}-{nanos:x}", std::process::id()))
}

fn next_request_id(startup_id: &str) -> Result<RequestId, String> {
    let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    RequestId::new(format!("p0-{startup_id}-{sequence:016x}")).map_err(|error| error.to_string())
}

fn internal_serve_error(message: String) -> ServeError {
    ServeError {
        status_code: 503,
        detail_code: "internal-transport-failure",
        message,
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

#[cfg(test)]
mod tests {
    use super::{RequestIdRegistry, render_response};
    use heptabao_p0_server::P0Response;
    use std::time::{Duration, Instant};

    #[test]
    fn no_content_response_never_emits_a_wire_body() {
        let response = P0Response {
            status_code: 204,
            body: br#"{"unexpected":true}"#.to_vec(),
            committed: true,
            recovery_reference: None,
        };
        let wire = render_response(&response);
        assert!(wire.starts_with(b"HTTP/1.1 204 No Content\r\n"));
        assert!(
            wire.windows(19)
                .any(|window| window == b"Content-Length: 0\r\n")
        );
        assert!(wire.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn request_registry_debug_redacts_live_ids() {
        let registry = RequestIdRegistry::new(2, Duration::from_secs(60));
        let now = Instant::now();
        assert!(registry.claim("client-request-private-0001", now).is_ok());
        let rendered = format!("{registry:?}");
        assert!(!rendered.contains("client-request-private-0001"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn client_request_id_is_single_use_inside_the_p0_window() {
        let registry = RequestIdRegistry::new(2, Duration::from_secs(60));
        let now = Instant::now();
        assert!(registry.claim("client-request-0001", now).is_ok());
        let replay = registry.claim("client-request-0001", now);
        assert!(replay.is_err());
    }

    #[test]
    fn request_id_registry_fails_closed_when_saturated() {
        let registry = RequestIdRegistry::new(1, Duration::from_secs(60));
        let now = Instant::now();
        assert!(registry.claim("client-request-0001", now).is_ok());
        assert!(registry.claim("client-request-0002", now).is_err());
    }
}
