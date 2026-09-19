//! Bounded HTTP/1.1 over verified Rustls TLS. One request per connection avoids
//! ambiguous reuse, smuggling and unbounded streaming in this single-node profile.
use crate::{
    Response, Service, ServiceRequest, crypto,
    ha::HaProcess,
    service::{RequestExecution, WireRejection},
};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{self, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard, TryLockError,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_HEADERS: usize = 16 * 1024;
const MAX_BODY: usize = 256 * 1024;
const MAX_SNAPSHOT_BODY: usize = 32 * 1024 * 1024;
const MAX_RESPONSE: usize = 32 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub audit_file: PathBuf,
    #[serde(default)]
    pub audit: crate::AuditConfig,
    pub tls_cert_file: PathBuf,
    pub tls_key_file: PathBuf,
    #[serde(default = "default_connections")]
    pub max_connections: usize,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_rate_limit_per_second")]
    pub rate_limit_per_second: u32,
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: u32,
    #[serde(default = "default_rate_limit_entries")]
    pub rate_limit_entries: usize,
    /// Zero explicitly disables idle maintenance. Active request checks remain mandatory.
    #[serde(default = "default_lifecycle_interval")]
    pub lifecycle_interval_seconds: u64,
    /// Deployment-owned egress allowlist; API configuration cannot widen it.
    #[serde(default)]
    pub outbound_endpoints: Vec<crate::outbound::EndpointConfig>,
    /// Optional mandatory HTTPS audit collector. The URL must resolve only
    /// through `outbound_endpoints`; API requests cannot replace it.
    #[serde(default)]
    pub audit_http_url: Option<String>,
    /// Optional deployment-owned TCP socket audit collector. The mandatory
    /// authenticated file sink remains enabled even if this collector fails.
    #[serde(default)]
    pub audit_socket: Option<crate::AuditSocketConfig>,
    /// Optional deployment-owned local Unix syslog audit device.
    #[serde(default)]
    pub audit_syslog: Option<crate::AuditSyslogConfig>,
    #[serde(default)]
    pub plugin_auth: Vec<crate::PluginAuthConfig>,
    #[serde(default)]
    pub plugin_secrets: Vec<crate::PluginSecretConfig>,
}
fn default_lifecycle_interval() -> u64 {
    5
}
fn default_connections() -> usize {
    16
}
fn default_timeout() -> u64 {
    15
}
fn default_rate_limit_per_second() -> u32 {
    200
}
fn default_rate_limit_burst() -> u32 {
    400
}
fn default_rate_limit_entries() -> usize {
    4_096
}

const TOKEN_SCALE: u128 = 1_000_000_000;
const RATE_BUCKET_IDLE_NANOS: u128 = 60 * TOKEN_SCALE;

#[derive(Clone, Copy)]
struct RateBucket {
    tokens: u128,
    last_nanos: u128,
}

struct RateLimiter {
    rate_per_second: u128,
    burst_tokens: u128,
    max_entries: usize,
    started: Instant,
    buckets: BTreeMap<IpAddr, RateBucket>,
}

impl RateLimiter {
    fn new(rate_per_second: u32, burst: u32, max_entries: usize) -> Result<Self, String> {
        if rate_per_second == 0
            || rate_per_second > 100_000
            || burst == 0
            || burst > 1_000_000
            || !(64..=65_536).contains(&max_entries)
        {
            return Err("invalid bounded rate-limit policy".into());
        }
        Ok(Self {
            rate_per_second: u128::from(rate_per_second),
            burst_tokens: u128::from(burst) * TOKEN_SCALE,
            max_entries,
            started: Instant::now(),
            buckets: BTreeMap::new(),
        })
    }

    fn allow(&mut self, peer: IpAddr) -> bool {
        self.allow_at(peer, self.started.elapsed().as_nanos())
    }

    fn allow_at(&mut self, peer: IpAddr, now_nanos: u128) -> bool {
        if !self.buckets.contains_key(&peer) && self.buckets.len() >= self.max_entries {
            self.buckets.retain(|_, bucket| {
                now_nanos.saturating_sub(bucket.last_nanos) < RATE_BUCKET_IDLE_NANOS
            });
            if self.buckets.len() >= self.max_entries {
                return false;
            }
        }
        let bucket = self.buckets.entry(peer).or_insert(RateBucket {
            tokens: self.burst_tokens,
            last_nanos: now_nanos,
        });
        let elapsed = now_nanos.saturating_sub(bucket.last_nanos);
        let refill = elapsed.saturating_mul(self.rate_per_second);
        bucket.tokens = bucket.tokens.saturating_add(refill).min(self.burst_tokens);
        bucket.last_nanos = now_nanos;
        if bucket.tokens < TOKEN_SCALE {
            return false;
        }
        bucket.tokens -= TOKEN_SCALE;
        true
    }
}

pub fn serve(config: Config) -> Result<(), String> {
    serve_inner(config, None)
}

pub fn serve_with_ha(config: Config, ha: Arc<Mutex<HaProcess>>) -> Result<(), String> {
    serve_inner(config, Some(ha))
}

fn serve_inner(config: Config, ha: Option<Arc<Mutex<HaProcess>>>) -> Result<(), String> {
    if !(1..=128).contains(&config.max_connections) || !(1..=60).contains(&config.timeout_seconds) {
        return Err("invalid bounded connection policy".into());
    }
    if config.lifecycle_interval_seconds > 60 {
        return Err("lifecycle interval must be zero or 1..=60 seconds".into());
    }
    let limiter = Arc::new(Mutex::new(RateLimiter::new(
        config.rate_limit_per_second,
        config.rate_limit_burst,
        config.rate_limit_entries,
    )?));
    if !config.tls_cert_file.is_absolute() || !config.tls_key_file.is_absolute() {
        return Err("TLS paths must be absolute".into());
    }
    if config.tls_cert_file.starts_with(&config.data_dir)
        || config.tls_key_file.starts_with(&config.data_dir)
    {
        return Err("TLS material must live outside the data directory".into());
    }
    let certificates = bounded_file(&config.tls_cert_file, false)?;
    let mut cert_reader = BufReader::new(certificates.as_slice());
    let certificates = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid TLS certificate chain")?;
    if certificates.is_empty() {
        return Err("TLS certificate chain is empty".into());
    }
    let key_bytes = bounded_file(&config.tls_key_file, true)?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))
        .map_err(|_| "invalid TLS key")?
        .ok_or("missing TLS private key")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| "TLS versions unavailable")?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|_| "TLS key and certificate do not match")?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = Arc::new(tls);
    let ha_enabled = ha.is_some();
    let forwarding_ha = ha.clone();
    let service = Arc::new(Mutex::new(
        match ha {
            Some(ha) => Service::new_with_ha_audit_config(
                config.data_dir,
                &config.audit_file,
                ha,
                config.audit,
            ),
            None => {
                Service::new_with_audit_config(config.data_dir, &config.audit_file, config.audit)
            }
        }
        .map_err(str::to_owned)?,
    ));
    {
        let mut service = service.lock().map_err(|_| "service lock unavailable")?;
        service.install_outbound_endpoints(config.outbound_endpoints)?;
        service.install_auth_plugins(config.plugin_auth)?;
        service.install_secret_plugins(config.plugin_secrets)?;
        service.install_audit_http_endpoint(config.audit_http_url)?;
        service.install_audit_socket(config.audit_socket)?;
        service.install_audit_syslog(config.audit_syslog)?;
    }
    if let Some(ha) = forwarding_ha {
        let weak_service = Arc::downgrade(&service);
        let handler: crate::ha::ForwardHandler = Arc::new(move |mut request| {
            let Some(service) = weak_service.upgrade() else {
                return Response::error(503, "HA forward service is unavailable");
            };
            let response = execute_service_request(
                &service,
                ServiceRequest {
                    method: &request.method,
                    path: &request.path,
                    namespace: &request.namespace,
                    token: &request.token,
                    body: std::mem::take(&mut request.body),
                    wrap_ttl_seconds: request.wrap_ttl_seconds,
                },
                Instant::now() + Duration::from_secs(15),
                true,
            );
            request.token.zeroize();
            response
        });
        ha.lock()
            .map_err(|_| "HA process lock is unavailable".to_owned())?
            .register_forward_handler(handler)?;
    }
    let listener =
        TcpListener::bind(config.listen).map_err(|_| "cannot bind configured listener")?;
    let _lifecycle = crate::service::start_lifecycle_worker(
        &service,
        Duration::from_secs(config.lifecycle_interval_seconds),
    )?;
    let connections = Arc::new(AtomicUsize::new(0));
    eprintln!(
        "HeptaBao {} TLS listener ready at {}",
        if ha_enabled { "HA" } else { "single-node" },
        config.listen
    );
    for stream in listener.incoming() {
        let stream = stream.map_err(|_| "listener accept failed")?;
        if connections
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                (value < config.max_connections).then_some(value + 1)
            })
            .is_err()
        {
            drop(stream);
            continue;
        }
        let guard = ConnectionGuard(Arc::clone(&connections));
        let peer = stream
            .peer_addr()
            .map_err(|_| "cannot identify accepted peer")?
            .ip();
        let rate_limited = limiter
            .lock()
            .map_or(true, |mut limiter| !limiter.allow(peer));
        let service = Arc::clone(&service);
        let tls = Arc::clone(&tls);
        let timeout = Duration::from_secs(config.timeout_seconds);
        let spawn = std::thread::Builder::new()
            .name("heptabao-request".into())
            .spawn(move || {
                let _guard = guard;
                if stream.set_read_timeout(Some(timeout)).is_err()
                    || stream.set_write_timeout(Some(timeout)).is_err()
                {
                    return;
                }
                let Ok(connection) = ServerConnection::new(tls) else {
                    return;
                };
                let mut stream = StreamOwned::new(
                    connection,
                    DeadlineStream {
                        stream,
                        deadline: Instant::now() + timeout,
                    },
                );
                let attempt_id = match crypto::random::<16>() {
                    Ok(value) => value,
                    Err(_) => return,
                };
                if rate_limited {
                    let response = audited_wire_rejection(
                        &service,
                        &attempt_id,
                        WireRejection::RateLimited,
                        429,
                        "request rate limit exceeded",
                        Instant::now() + timeout,
                    );
                    let _ = write_response(&mut stream, response, false);
                    return;
                }
                let parsed = read_request(&mut stream, timeout);
                let (response, head) = match parsed {
                    Ok(mut request) => {
                        let is_head = request.method == "HEAD";
                        let response = execute_service_request(
                            &service,
                            ServiceRequest {
                                method: if is_head && request.wrap_ttl_seconds.is_none() {
                                    "GET"
                                } else {
                                    &request.method
                                },
                                path: &request.path,
                                namespace: &request.namespace,
                                token: &request.token,
                                body: std::mem::take(&mut request.body.0),
                                wrap_ttl_seconds: request.wrap_ttl_seconds,
                            },
                            Instant::now() + timeout,
                            false,
                        );
                        (response, is_head)
                    }
                    Err(error) => (
                        audited_wire_rejection(
                            &service,
                            &attempt_id,
                            WireRejection::ParseRejected,
                            error.status,
                            error.message,
                            Instant::now() + timeout,
                        ),
                        false,
                    ),
                };
                let _ = write_response(&mut stream, response, head);
            });
        if spawn.is_err() {
            return Err("cannot create bounded request worker".into());
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LockWaitError {
    Busy,
    Poisoned,
}

fn lock_until<'a, T>(
    mutex: &'a Mutex<T>,
    deadline: Instant,
) -> Result<MutexGuard<'a, T>, LockWaitError> {
    loop {
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(_)) => return Err(LockWaitError::Poisoned),
            Err(TryLockError::WouldBlock) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(LockWaitError::Busy);
                }
                std::thread::sleep(
                    deadline
                        .saturating_duration_since(now)
                        .min(Duration::from_millis(2)),
                );
            }
        }
    }
}

fn execute_external_without_writer<T, P, R, E, F>(
    state: &Arc<Mutex<T>>,
    pending: P,
    deadline: Instant,
    execute: E,
    finish: F,
) -> Response
where
    E: FnOnce(&P) -> R,
    F: FnOnce(&mut T, P, R) -> Response,
{
    // Deliberately execute before acquiring the state writer. This helper is the
    // production boundary that prevents slow enrolled providers from monopolizing
    // unrelated service state while their external effect/readback is in flight.
    let result = execute(&pending);
    match lock_until(state, deadline) {
        Ok(mut writer) => finish(&mut writer, pending, result),
        Err(LockWaitError::Busy) => Response::error(
            503,
            "provider result awaits durable reconciliation; service finalize deadline exceeded",
        ),
        Err(LockWaitError::Poisoned) => Response::error(
            503,
            "provider result awaits durable reconciliation; service state unavailable",
        ),
    }
}

fn execute_service_request(
    service: &Arc<Mutex<Service>>,
    request: ServiceRequest<'_>,
    deadline: Instant,
    forwarded: bool,
) -> Response {
    let execution = match lock_until(service, deadline) {
        Ok(mut writer) => {
            if forwarded {
                writer.begin_forwarded(request)
            } else {
                writer.begin_request(request)
            }
        }
        Err(LockWaitError::Busy) => {
            return Response::error(503, "service state lock deadline exceeded");
        }
        Err(LockWaitError::Poisoned) => {
            return Response::error(503, "service state is unavailable");
        }
    };
    match execution {
        RequestExecution::Complete(response) => response,
        RequestExecution::External(pending) => execute_external_without_writer(
            service,
            pending,
            deadline,
            |pending| pending.execute(),
            |writer, pending, result| writer.finish_external_request(*pending, result),
        ),
    }
}

fn audited_wire_rejection(
    service: &Arc<Mutex<Service>>,
    attempt_id: &[u8; 16],
    rejection: WireRejection,
    status: u16,
    message: &'static str,
    deadline: Instant,
) -> Response {
    match lock_until(service, deadline) {
        Ok(mut service) => service.handle_wire_rejection(attempt_id, rejection, status, message),
        Err(LockWaitError::Busy) => Response::error(503, "service state lock deadline exceeded"),
        Err(LockWaitError::Poisoned) => Response::error(503, "service state is unavailable"),
    }
}

struct ConnectionGuard(Arc<AtomicUsize>);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

struct DeadlineStream {
    stream: TcpStream,
    deadline: Instant,
}
impl DeadlineStream {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "connection deadline exceeded"))
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buffer)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush()
    }
}

fn bounded_file(path: &PathBuf, private: bool) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| "cannot open TLS file")?;
    let meta = file.metadata().map_err(|_| "cannot inspect TLS file")?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
        return Err("invalid bounded TLS file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if private && meta.permissions().mode() & 0o077 != 0 {
            return Err("TLS key must be owner only".into());
        }
    }
    let mut data = Zeroizing::new(Vec::new());
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|_| "cannot read TLS file")?;
    if data.len() > 1024 * 1024 {
        return Err("TLS file grew beyond limit".into());
    }
    Ok(data)
}

struct SecretJson(Value);
impl Drop for SecretJson {
    fn drop(&mut self) {
        crate::service::erase_json(&mut self.0);
    }
}
struct Request {
    method: String,
    path: String,
    namespace: String,
    token: Zeroizing<String>,
    body: SecretJson,
    wrap_ttl_seconds: Option<u64>,
}
struct ParseError {
    status: u16,
    message: &'static str,
}
impl From<io::Error> for ParseError {
    fn from(_: io::Error) -> Self {
        Self {
            status: 400,
            message: "incomplete or timed out HTTP request",
        }
    }
}
fn bad(message: &'static str) -> ParseError {
    ParseError {
        status: 400,
        message,
    }
}

fn read_request(reader: &mut impl Read, timeout: Duration) -> Result<Request, ParseError> {
    let start = Instant::now();
    let mut bytes = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0; 4096]);
    let header_end = loop {
        if start.elapsed() > timeout {
            return Err(bad("request deadline exceeded"));
        }
        if let Some(index) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            if index > MAX_HEADERS {
                return Err(bad("headers too large"));
            }
            break index + 4;
        }
        if bytes.len() > MAX_HEADERS {
            return Err(bad("headers too large"));
        }
        let count = reader.read(buffer.as_mut())?;
        if count == 0 {
            return Err(bad("incomplete headers"));
        }
        bytes.extend_from_slice(&buffer[..count]);
    };
    let headers =
        std::str::from_utf8(&bytes[..header_end]).map_err(|_| bad("headers must be ASCII"))?;
    if !headers.is_ascii() {
        return Err(bad("headers must be ASCII"));
    }
    let mut lines = headers[..headers.len() - 4].split("\r\n");
    let request_line = lines.next().ok_or_else(|| bad("missing request line"))?;
    let parts: Vec<_> = request_line.split(' ').collect();
    if parts.len() != 3
        || parts[2] != "HTTP/1.1"
        || !matches!(
            parts[0],
            "GET" | "POST" | "PUT" | "DELETE" | "LIST" | "SCAN" | "PATCH" | "HEAD"
        )
    {
        return Err(bad("unsupported HTTP method or version"));
    }
    let method = parts[0].to_owned();
    let target = Zeroizing::new(parts[1].to_owned());
    if target.len() > 8192 || !target.starts_with("/v1/") {
        return Err(bad("request must use /v1/ API"));
    }
    let mut map = BTreeMap::new();
    for (count, line) in lines.enumerate() {
        if count >= 100 || line.starts_with([' ', '\t']) {
            return Err(bad("invalid header framing"));
        }
        let (name, value) = line.split_once(':').ok_or_else(|| bad("invalid header"))?;
        if name.is_empty()
            || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            || value.bytes().any(|c| c < 32 && c != b'\t')
        {
            return Err(bad("invalid header bytes"));
        }
        let name = name.to_ascii_lowercase();
        if map
            .insert(name, Zeroizing::new(value.trim().to_owned()))
            .is_some()
        {
            return Err(bad("duplicate headers are not supported"));
        }
    }
    if !map.contains_key("host") {
        return Err(bad("Host header is required"));
    }
    if map.keys().any(|name| {
        (name.starts_with("x-vault-") || name.starts_with("x-bao-"))
            && !matches!(
                name.as_str(),
                "x-vault-token"
                    | "x-vault-namespace"
                    | "x-vault-request"
                    | "x-vault-wrap-ttl"
                    | "x-vault-wrap-format"
            )
    }) {
        return Err(ParseError {
            status: 501,
            message: "requested OpenBao header semantics are not implemented",
        });
    }
    if map
        .get("x-vault-wrap-format")
        .is_some_and(|value| value.as_str() != "uuid")
    {
        return Err(ParseError {
            status: 501,
            message: "only opaque response wrapping tokens are supported",
        });
    }
    let wrap_ttl_seconds = map
        .get("x-vault-wrap-ttl")
        .map(|value| parse_wrap_ttl(value))
        .transpose()?
        .flatten();
    if map.contains_key("transfer-encoding") || map.contains_key("expect") {
        return Err(bad("streamed request bodies are not supported"));
    }
    let length = match map.get("content-length") {
        Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => v
            .parse::<usize>()
            .map_err(|_| bad("invalid content length"))?,
        None => 0,
        _ => return Err(bad("invalid content length")),
    };
    let maximum_body = if target.starts_with("/v1/sys/storage/raft/snapshot") {
        MAX_SNAPSHOT_BODY
    } else {
        MAX_BODY
    };
    if length > maximum_body {
        return Err(ParseError {
            status: 413,
            message: "request body exceeds limit",
        });
    }
    let raw_namespace = map.get("x-vault-namespace").map_or("", |s| s.as_str());
    if raw_namespace == "/" || raw_namespace.contains("//") {
        return Err(bad("ambiguous namespace segments"));
    }
    let namespace = raw_namespace
        .strip_suffix('/')
        .unwrap_or(raw_namespace)
        .to_owned();
    let token = map.remove("x-vault-token").unwrap_or_default();
    if token.len() > 16 * 1024 {
        return Err(bad("token header exceeds limit"));
    }
    if length > 0
        && map.get("content-type").is_some_and(|v| {
            !matches!(
                v.split(';').next(),
                Some("application/json" | "application/merge-patch+json")
            )
        })
    {
        return Err(bad("JSON content type required"));
    }
    while bytes.len() < header_end + length {
        if start.elapsed() > timeout {
            return Err(bad("request deadline exceeded"));
        }
        let remaining = (header_end + length - bytes.len()).min(buffer.len());
        let count = reader.read(&mut buffer[..remaining])?;
        if count == 0 {
            return Err(bad("incomplete body"));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    if bytes.len() != header_end + length {
        return Err(bad("pipelining and trailing bytes are not supported"));
    }
    let mut body = SecretJson(if length == 0 {
        json!({})
    } else {
        crate::auth::parse_strict_json(&bytes[header_end..])
            .map_err(|_| bad("invalid JSON object"))?
    });
    let Some(object) = body.0.as_object_mut() else {
        return Err(bad("JSON object required"));
    };
    let (path, query) = target[4..].split_once('?').unwrap_or((&target[4..], ""));
    if path.contains('%') || path.contains('#') {
        return Err(bad("ambiguous encoded paths are not supported"));
    }
    for pair in query.split('&').filter(|v| !v.is_empty()) {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| bad("query parameters require values"))?;
        let key = decode_query(key)?;
        let value = Zeroizing::new(decode_query(value)?);
        if !matches!(
            key.as_str(),
            "version"
                | "depth"
                | "limit"
                | "list"
                | "after"
                | "exclude_deleted"
                | "standbyok"
                | "perfstandbyok"
        ) {
            return Err(bad(
                "unsupported query parameter; request fields belong in JSON body",
            ));
        }
        if object.contains_key(&key) {
            return Err(bad("duplicate body/query parameter"));
        }
        let parsed = if matches!(key.as_str(), "version" | "depth" | "limit") {
            json!(
                value
                    .parse::<u64>()
                    .map_err(|_| bad("invalid numeric query"))?
            )
        } else if matches!(key.as_str(), "standbyok" | "perfstandbyok")
            && matches!(value.as_str(), "true" | "1")
        {
            Value::Bool(true)
        } else if matches!(key.as_str(), "standbyok" | "perfstandbyok")
            && matches!(value.as_str(), "false" | "0")
        {
            Value::Bool(false)
        } else {
            Value::String(value.to_string())
        };
        object.insert(key, parsed);
    }
    if method == "GET" && object.get("list").is_some_and(|v| !v.is_boolean()) {
        return Err(bad("list parameter must be boolean"));
    }
    let method = if method == "GET" && object.get("list") == Some(&Value::Bool(true)) {
        object.remove("list");
        "LIST".to_owned()
    } else {
        method
    };
    Ok(Request {
        method,
        path: path.to_owned(),
        namespace,
        token,
        body,
        wrap_ttl_seconds,
    })
}

fn parse_wrap_ttl(value: &str) -> Result<Option<u64>, ParseError> {
    let invalid = || bad("invalid or unsupported wrapping TTL");
    if value.is_empty() || value.len() > 64 || !value.is_ascii() {
        return Err(invalid());
    }
    let mut total = 0u64;
    let mut number = 0u64;
    let mut digits = false;
    for byte in value.bytes() {
        if byte.is_ascii_digit() {
            number = number
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(byte - b'0')))
                .ok_or_else(invalid)?;
            digits = true;
        } else {
            if !digits {
                return Err(invalid());
            }
            let unit = match byte {
                b'h' => 3600,
                b'm' => 60,
                b's' => 1,
                _ => return Err(invalid()),
            };
            total = total
                .checked_add(number.checked_mul(unit).ok_or_else(invalid)?)
                .ok_or_else(invalid)?;
            number = 0;
            digits = false;
        }
    }
    if digits {
        if !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        total = number;
    }
    if total > 32 * 24 * 3600 {
        return Err(invalid());
    }
    Ok((total != 0).then_some(total))
}

fn decode_query(value: &str) -> Result<String, ParseError> {
    let mut result = Zeroizing::new(Vec::new());
    let mut bytes = value.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let a = bytes.next().ok_or_else(|| bad("invalid query escape"))?;
                let b = bytes.next().ok_or_else(|| bad("invalid query escape"))?;
                let digits = [a, b];
                let text = std::str::from_utf8(&digits).map_err(|_| bad("invalid query escape"))?;
                result.push(u8::from_str_radix(text, 16).map_err(|_| bad("invalid query escape"))?);
            }
            b'+' => result.push(b' '),
            _ => result.push(b),
        }
    }
    if result.iter().any(|b| *b < 32 || *b == 127) {
        return Err(bad("invalid query bytes"));
    }
    std::str::from_utf8(&result)
        .map(str::to_owned)
        .map_err(|_| bad("invalid query text"))
}

fn write_response(writer: &mut impl Write, response: Response, head: bool) -> io::Result<()> {
    let mut bytes = Zeroizing::new(if response.status == 204 {
        Vec::new()
    } else {
        serde_json::to_vec(&response.body)?
    });
    let status = if bytes.len() > MAX_RESPONSE {
        bytes = Zeroizing::new(br#"{"errors":["response exceeds limit"]}"#.to_vec());
        500
    } else {
        response.status
    };
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        507 => "Insufficient Storage",
        _ => "Error",
    };
    let retry_after = if status == 429 {
        "Retry-After: 1\r\n"
    } else {
        ""
    };
    write!(
        writer,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{retry_after}Connection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        bytes.len()
    )?;
    if !head {
        writer.write_all(&bytes)?;
    }
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_enforces_burst_refill_and_bounded_peer_table() -> Result<(), String> {
        let mut limiter = RateLimiter::new(2, 3, 64)?;
        let first: IpAddr = "192.0.2.1".parse().map_err(|_| "invalid test address")?;
        assert!(limiter.allow_at(first, 0));
        assert!(limiter.allow_at(first, 0));
        assert!(limiter.allow_at(first, 0));
        assert!(!limiter.allow_at(first, 0));
        assert!(!limiter.allow_at(first, TOKEN_SCALE / 4));
        assert!(limiter.allow_at(first, TOKEN_SCALE / 2));

        for suffix in 2..=64 {
            let peer: IpAddr = format!("192.0.2.{suffix}")
                .parse()
                .map_err(|_| "invalid test address")?;
            assert!(limiter.allow_at(peer, TOKEN_SCALE / 2));
        }
        let overflow: IpAddr = "198.51.100.1".parse().map_err(|_| "invalid test address")?;
        assert!(!limiter.allow_at(overflow, TOKEN_SCALE / 2));
        assert!(limiter.allow_at(overflow, RATE_BUCKET_IDLE_NANOS + TOKEN_SCALE));
        Ok(())
    }

    #[test]
    fn rate_limit_configuration_rejects_disabled_or_unbounded_values() {
        assert!(RateLimiter::new(0, 1, 64).is_err());
        assert!(RateLimiter::new(10, 10, 63).is_err());
        assert!(RateLimiter::new(100_001, 100_001, 64).is_err());
    }
    #[test]
    fn rejects_smuggling_duplicate_headers_and_ambiguous_paths() {
        for request in [
            "POST /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            "POST /v1/a HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
            "GET /v1/a%2fb HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "GET /v1/a HTTP/1.1\r\nHost: localhost\r\n\r\nignored",
        ] {
            assert!(read_request(&mut request.as_bytes(), Duration::from_secs(1)).is_err());
        }
    }
    #[test]
    fn reads_versioned_request_without_mutating_secret_body() -> Result<(), String> {
        let text = "GET /v1/secret/data/a?version=2 HTTP/1.1\r\nHost: localhost\r\nX-Vault-Token: synthetic\r\n\r\n";
        let r = read_request(&mut text.as_bytes(), Duration::from_secs(1))
            .map_err(|e| e.message.to_owned())?;
        assert_eq!(r.path, "secret/data/a");
        assert_eq!(r.body.0, json!({"version":2}));
        Ok(())
    }

    #[test]
    fn rejects_duplicate_json_and_ambiguous_namespaces() {
        for namespace in ["/", "a//", "a//b", "///"] {
            let request = format!(
                "GET /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\nX-Vault-Namespace: {namespace}\r\n\r\n"
            );
            assert!(read_request(&mut request.as_bytes(), Duration::from_secs(1)).is_err());
        }
        let payload = r#"{"data":{"value":"first","value":"second"}}"#;
        let request = format!(
            "POST /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{payload}",
            payload.len()
        );
        assert!(read_request(&mut request.as_bytes(), Duration::from_secs(1)).is_err());
        for header in ["X-Vault-MFA", "X-Vault-Policy-Override", "X-Vault-Index"] {
            let request = format!(
                "GET /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\n{header}: synthetic\r\n\r\n"
            );
            let result = read_request(&mut request.as_bytes(), Duration::from_secs(1));
            assert!(
                result.is_err_and(|error| error.status == 501),
                "unsupported security semantics must not silently return a raw secret"
            );
        }
        let request = "GET /v1/secret/data/a?token=synthetic HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert!(read_request(&mut request.as_bytes(), Duration::from_secs(1)).is_err());
    }

    #[test]
    fn repeated_socket_reads_cannot_extend_connection_deadline() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let client = TcpStream::connect(listener.local_addr()?)?;
        let (stream, _) = listener.accept()?;
        let mut stream = DeadlineStream {
            stream,
            deadline: Instant::now() + Duration::from_millis(80),
        };
        let sender = std::thread::spawn(move || {
            let mut client = client;
            for _ in 0..8 {
                if client.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let started = Instant::now();
        let mut byte = [0; 1];
        let mut received = 0;
        while stream.read(&mut byte).is_ok_and(|count| count == 1) {
            received += 1;
        }
        assert!(received < 8, "slow fragments extended the fixed deadline");
        assert!(started.elapsed() < Duration::from_millis(400));
        drop(stream);
        sender
            .join()
            .map_err(|_| io::Error::other("sender thread failed"))?;
        Ok(())
    }
}

#[cfg(test)]
mod service_lock_deadline_tests {
    use super::*;

    #[test]
    fn service_lock_wait_is_bounded_when_another_request_holds_the_writer()
    -> Result<(), Box<dyn std::error::Error>> {
        let lock = Mutex::new(());
        let _held = lock.lock().map_err(|_| "test mutex poisoned")?;
        assert!(matches!(
            lock_until(&lock, Instant::now() + Duration::from_millis(5)),
            Err(LockWaitError::Busy)
        ));
        Ok(())
    }

    #[test]
    fn external_effect_phase_does_not_hold_the_shared_state_writer()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = Arc::new(Mutex::new(0_u64));
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let worker_state = Arc::clone(&state);
        let worker_entered = Arc::clone(&entered);
        let worker_release = Arc::clone(&release);
        let worker = std::thread::spawn(move || {
            execute_external_without_writer(
                &worker_state,
                (),
                Instant::now() + Duration::from_secs(2),
                |_| {
                    worker_entered.wait();
                    worker_release.wait();
                    41_u64
                },
                |value, (), result| {
                    *value = result + 1;
                    Response {
                        status: 200,
                        body: json!({"data":{"completed":true}}),
                    }
                },
            )
        });
        entered.wait();
        let observed = state
            .try_lock()
            .map(|guard| *guard)
            .map_err(|_| "external effect held the shared writer");
        release.wait();
        let response = worker
            .join()
            .map_err(|_| "external effect worker panicked")?;
        assert_eq!(observed?, 0);
        assert_eq!(response.status, 200);
        assert_eq!(
            *state
                .lock()
                .map_err(|_| "state poisoned after external effect")?,
            42
        );
        Ok(())
    }

    #[test]
    fn poisoned_service_lock_fails_without_waiting_for_the_deadline() {
        let lock = Arc::new(Mutex::new(()));
        let worker = Arc::clone(&lock);
        let poisoned = std::thread::spawn(move || {
            if let Ok(_held) = worker.lock() {
                // Deliberately unwind while holding the lock: this is the fault
                // being tested, not an assertion failure or production panic.
                std::panic::resume_unwind(Box::new("poison test mutex"));
            }
        })
        .join();
        assert!(poisoned.is_err());
        assert!(matches!(
            lock_until(&lock, Instant::now() + Duration::from_secs(1)),
            Err(LockWaitError::Poisoned)
        ));
    }
}

#[cfg(test)]
mod wrapping_header_tests {
    use super::*;
    #[test]
    fn wrapping_duration_is_bounded_and_rejects_silent_rounding() {
        for (input, expected) in [
            ("60", Some(60)),
            ("1h30m5s", Some(5405)),
            ("0s", None),
            ("0", None),
        ] {
            assert!(parse_wrap_ttl(input).is_ok_and(|actual| actual == expected));
        }
        for input in [
            "",
            "-1",
            "1.5s",
            "1ms",
            "1d",
            "1s5",
            "s",
            " 60",
            "18446744073709551616",
            "768h1s",
        ] {
            assert!(parse_wrap_ttl(input).is_err());
        }
    }
    #[test]
    fn wrapping_headers_are_retained_and_duplicates_or_jwt_reject() {
        let valid =
            b"GET /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\nX-Vault-Wrap-TTL: 60s\r\n\r\n";
        assert!(
            read_request(&mut valid.as_slice(), Duration::from_secs(1))
                .is_ok_and(|r| r.wrap_ttl_seconds == Some(60))
        );
        for header in [
            "X-Vault-Wrap-TTL: 60s\r\nx-vault-wrap-ttl: 1s",
            "X-Vault-Wrap-TTL: invalid",
            "X-Vault-Wrap-Format: jwt",
        ] {
            let request =
                format!("GET /v1/secret/data/a HTTP/1.1\r\nHost: localhost\r\n{header}\r\n\r\n");
            assert!(read_request(&mut request.as_bytes(), Duration::from_secs(1)).is_err());
        }
    }

    #[test]
    fn health_probe_query_flags_are_parsed_as_booleans() {
        for (query, key) in [
            ("standbyok=1", "standbyok"),
            ("perfstandbyok=true", "perfstandbyok"),
        ] {
            let request = format!("GET /v1/sys/health?{query} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            assert!(
                read_request(&mut request.as_bytes(), Duration::from_secs(1))
                    .is_ok_and(|r| r.body.0[key] == Value::Bool(true))
            );
        }
        let request = b"GET /v1/sys/health?standbyok=maybe HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert!(read_request(&mut request.as_slice(), Duration::from_secs(1)).is_err());
    }
}
