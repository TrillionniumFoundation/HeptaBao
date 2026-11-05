//! Independent QA client: one strict-TLS HTTP/2 GET; no reconnect or retry.
//! This source is not part of the product or its 44/7/9 test denominators.
use bytes::Bytes;
use h2::RecvStream;
use http::{HeaderMap, HeaderValue, Request, Version, header};
use rustls::{ClientConfig, RootCertStore, pki_types::{CertificateDer, ServerName}};
use sha2::{Digest, Sha256};
use std::{env, io::{Read, Write}, net::{Ipv4Addr, SocketAddrV4}, sync::Arc,
          time::{Duration, Instant}};
use tokio::{net::TcpStream, runtime::Builder, time::timeout_at};
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

const CANDIDATE: &str = "df026fe323dd7cf0f0ec57d7d2d9c5a79897053c";
const TREE: &str = "424463ccd2310ddc1e7b2bbcd7b7af29ae58c825";
const MAX_SPEC: usize = 64 * 1024;
const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_HEADERS: usize = 64 * 1024;
const HTTP_NS: u128 = 15_000_000_000;
type Checked<T> = Result<T, &'static str>;

fn digest(raw: &[u8]) -> String {
    let value = Sha256::digest(raw);
    let mut result = String::with_capacity(64);
    for byte in value {
        use std::fmt::Write as _;
        // String formatting cannot fail; keep the closed error path explicit.
        if write!(&mut result, "{byte:02x}").is_err() {
            return String::new();
        }
    }
    result
}

fn clock_ns() -> Checked<u128> {
    let mut value = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: value is a live, aligned timespec; this call writes only it.
    // CLOCK_MONOTONIC is the same Linux clock used by the owning Python process.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0
        || value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err("clock_unavailable");
    }
    Ok((value.tv_sec as u128) * 1_000_000_000 + value.tv_nsec as u128)
}

fn deadline(until: u128) -> Checked<Instant> {
    // Sample the Instant first: the conversion cannot grant time between clocks.
    let instant = Instant::now();
    let current = clock_ns()?;
    let left = until.checked_sub(current).ok_or("original_deadline")?;
    if left == 0 || left > HTTP_NS {
        return Err("original_deadline");
    }
    let nanos = u64::try_from(left).map_err(|_| "deadline_range")?;
    instant.checked_add(Duration::from_nanos(nanos)).ok_or("deadline_range")
}

fn take<'a>(raw: &mut &'a [u8], length: usize) -> Checked<&'a [u8]> {
    let item = raw.get(..length).ok_or("input_framing")?;
    *raw = raw.get(length..).ok_or("input_framing")?;
    Ok(item)
}
fn be16(raw: &mut &[u8]) -> Checked<u16> {
    Ok(u16::from_be_bytes(take(raw, 2)?.try_into().map_err(|_| "input_framing")?))
}
fn be32(raw: &mut &[u8]) -> Checked<u32> {
    Ok(u32::from_be_bytes(take(raw, 4)?.try_into().map_err(|_| "input_framing")?))
}
fn be64(raw: &mut &[u8]) -> Checked<u64> {
    Ok(u64::from_be_bytes(take(raw, 8)?.try_into().map_err(|_| "input_framing")?))
}
fn hex32(raw: &[u8]) -> String {
    let mut result = String::with_capacity(raw.len() * 2);
    const HEX: &[u8] = b"0123456789abcdef";
    for byte in raw {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 15) as usize] as char);
    }
    result
}

struct Spec {
    until: u128,
    port: u16,
    operation: u8,
    ca_der: Vec<u8>,
    leaf_sha256: String,
    token: Zeroizing<Vec<u8>>,
}
impl Spec {
    fn path(&self) -> Checked<&'static str> {
        match self.operation {
            1 => Ok("/v1/wire/data/seed?version=2"),
            2 => Ok("/v1/sys/storage/raft/snapshot"),
            _ => Err("input_operation"),
        }
    }
    fn parse(raw: &[u8]) -> Checked<Self> {
        let mut rest = raw;
        if take(&mut rest, 8)? != b"HBH2QA01" {
            return Err("input_magic");
        }
        let until = be64(&mut rest)? as u128;
        let port = be16(&mut rest)?;
        if ![48630, 48632, 48634].contains(&port) {
            return Err("input_endpoint");
        }
        let operation = *take(&mut rest, 1)?.first().ok_or("input_framing")?;
        if ![1, 2].contains(&operation) {
            return Err("input_operation");
        }
        let ca_len = usize::try_from(be32(&mut rest)?).map_err(|_| "input_ca_size")?;
        if !(128..=16 * 1024).contains(&ca_len) {
            return Err("input_ca_size");
        }
        let ca_der = take(&mut rest, ca_len)?.to_vec();
        let leaf_sha256 = hex32(take(&mut rest, 32)?);
        let token_len = be16(&mut rest)? as usize;
        if !(16..=16 * 1024).contains(&token_len) {
            return Err("input_token_size");
        }
        let token = Zeroizing::new(take(&mut rest, token_len)?.to_vec());
        if !rest.is_empty() || !token.iter().all(|b| (33..=126).contains(b)) {
            return Err("input_framing");
        }
        Ok(Self { until, port, operation, ca_der, leaf_sha256, token })
    }
}

#[derive(Default)]
struct Observation {
    stage: &'static str,
    deadline_ns: u128,
    operation: u8,
    connections_started: u32,
    tls_verified: bool,
    selected_h2: bool,
    tls_version: &'static str,
    leaf_sha256: String,
    request_dispatched: bool,
    request_calls: u32,
    stream_id: u32,
    status: Option<u16>,
    header_count: usize,
    header_bytes: usize,
    header_sha256: String,
    content_length: Option<usize>,
    content_type: &'static str,
    data_frames: usize,
    data_none_observed: bool,
    trailers_completed: bool,
    trailers_empty: bool,
    recv_end_stream: bool,
    response_complete: bool,
    connection_task_joined: bool,
    connection_task_cancelled_after_observation: bool,
    completed_before_deadline: bool,
}
impl Observation {
    fn report(&self, body: &[u8], failure: Option<&'static str>) -> serde_json::Value {
        serde_json::json!({
            "schema": "heptabao.h2-single-request-client.v1",
            "candidate_commit": CANDIDATE, "candidate_tree": TREE,
            "stage": self.stage, "error_code": failure,
            "deadline_monotonic_ns": self.deadline_ns.to_string(),
            "operation": self.operation,
            "connections_started": self.connections_started,
            "tls_chain_and_hostname_verified": self.tls_verified,
            "selected_alpn_h2": self.selected_h2,
            "tls_version": self.tls_version, "peer_leaf_sha256": self.leaf_sha256,
            "request_dispatched": self.request_dispatched,
            "send_request_calls": self.request_calls, "stream_id": self.stream_id,
            "response_status": self.status,
            "header_count": self.header_count, "header_bytes": self.header_bytes,
            "header_sha256": self.header_sha256,
            "content_length": self.content_length, "content_type": self.content_type,
            "data_frames": self.data_frames, "data_none_observed": self.data_none_observed,
            "trailers_completed": self.trailers_completed, "trailers_empty": self.trailers_empty,
            "recv_end_stream": self.recv_end_stream,
            "response_complete": self.response_complete,
            "body_bytes": body.len(), "body_sha256": digest(body),
            "connection_task_joined": self.connection_task_joined,
            "connection_task_cancelled_after_observation": self.connection_task_cancelled_after_observation,
            "completed_before_original_deadline": self.completed_before_deadline,
            "outcome_unknown": self.request_dispatched && !self.response_complete,
            "client_reconnects": 0, "client_request_retries": 0, "redirects_followed": 0,
            "trace_enabled": false, "raw_error_messages_emitted": false,
            "product_or_official_cli_qualification": false
        })
    }
}

fn inspect_headers(headers: &HeaderMap, observation: &mut Observation) -> Checked<usize> {
    let mut canonical = Vec::new();
    let mut count = 0usize;
    for (name, value) in headers {
        count = count.checked_add(1).ok_or("header_bound")?;
        canonical.extend_from_slice(&(name.as_str().len() as u32).to_be_bytes());
        canonical.extend_from_slice(name.as_str().as_bytes());
        canonical.extend_from_slice(&(value.as_bytes().len() as u32).to_be_bytes());
        canonical.extend_from_slice(value.as_bytes());
        if count > 128 || canonical.len() > MAX_HEADERS {
            return Err("header_bound");
        }
    }
    observation.header_count = count;
    observation.header_bytes = canonical.len();
    observation.header_sha256 = digest(&canonical);
    for forbidden in ["connection", "keep-alive", "proxy-connection",
                      "upgrade", "transfer-encoding", "content-encoding", "location"] {
        if headers.contains_key(forbidden) {
            return Err("response_header_contract");
        }
    }
    let lengths: Vec<_> = headers.get_all(header::CONTENT_LENGTH).iter().collect();
    if lengths.len() != 1 {
        return Err("single_content_length_required");
    }
    let raw = lengths[0].as_bytes();
    if raw.is_empty() || !raw.iter().all(u8::is_ascii_digit)
        || (raw.len() > 1 && raw.first() == Some(&b'0')) {
        return Err("content_length_syntax");
    }
    let value = std::str::from_utf8(raw).map_err(|_| "content_length_syntax")?
        .parse::<usize>().map_err(|_| "content_length_range")?;
    if value > MAX_BODY {
        return Err("body_bound");
    }
    observation.content_length = Some(value);
    let types: Vec<_> = headers.get_all(header::CONTENT_TYPE).iter().collect();
    if types.len() != 1 {
        return Err("single_content_type_required");
    }
    observation.content_type = match types[0].as_bytes() {
        b"application/json" => "application/json",
        b"application/gzip" => "application/gzip",
        _ => return Err("content_type_contract"),
    };
    Ok(value)
}

async fn receive_body(stream: &mut RecvStream, expected: usize,
                      body: &mut Zeroizing<Vec<u8>>, observation: &mut Observation) -> Checked<()> {
    while let Some(chunk) = stream.data().await {
        let chunk = chunk.map_err(|_| "h2_data_error")?;
        observation.data_frames = observation.data_frames.checked_add(1).ok_or("frame_bound")?;
        if observation.data_frames > 16_384 {
            return Err("frame_bound");
        }
        let count = body.len().checked_add(chunk.len()).ok_or("body_bound")?;
        if count > MAX_BODY || count > expected {
            return Err("body_exceeds_content_length");
        }
        body.extend_from_slice(&chunk);
        stream.flow_control().release_capacity(chunk.len()).map_err(|_| "h2_flow_control")?;
    }
    observation.data_none_observed = true;
    // data(None) can mean "trailers queued", not EOS. Await and inspect both.
    let trailers = stream.trailers().await.map_err(|_| "h2_trailers_error")?;
    observation.trailers_completed = true;
    observation.trailers_empty = trailers.as_ref().is_none_or(HeaderMap::is_empty);
    observation.recv_end_stream = stream.is_end_stream();
    if !observation.trailers_empty || !observation.recv_end_stream || body.len() != expected {
        return Err("h2_eos_or_length_contract");
    }
    observation.response_complete = true;
    Ok(())
}

async fn exchange(spec: &Spec, until: Instant, body: &mut Zeroizing<Vec<u8>>,
                  observation: &mut Observation) -> Checked<()> {
    observation.stage = "tls_config";
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(spec.ca_der.clone())).map_err(|_| "ca_der_invalid")?;
    let mut config = ClientConfig::builder_with_provider(
        Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| "tls_config")?
        .with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    let connector = TlsConnector::from(Arc::new(config));
    let destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, spec.port);
    observation.stage = "tcp_connect";
    if Instant::now() >= until {
        return Err("original_deadline_before_connect");
    }
    observation.connections_started = 1;
    let tcp = timeout_at(until.into(), TcpStream::connect(destination)).await
        .map_err(|_| "original_deadline")?.map_err(|_| "tcp_connect_failed")?;
    if tcp.peer_addr().map_err(|_| "peer_address")? != destination.into() {
        return Err("peer_address");
    }
    tcp.set_nodelay(true).map_err(|_| "tcp_configuration")?;
    observation.stage = "tls_handshake";
    let name = ServerName::try_from("localhost").map_err(|_| "fixed_server_name")?;
    let tls = timeout_at(until.into(), connector.connect(name, tcp)).await
        .map_err(|_| "original_deadline")?.map_err(|_| "tls_handshake_failed")?;
    let session = tls.get_ref().1;
    observation.tls_verified = true;
    observation.selected_h2 = session.alpn_protocol() == Some(b"h2".as_slice());
    observation.tls_version = match session.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLS1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLS1.2",
        _ => return Err("tls_version"),
    };
    let peer = session.peer_certificates().and_then(|chain| chain.first())
        .ok_or("peer_leaf_missing")?;
    observation.leaf_sha256 = digest(peer.as_ref());
    if !observation.selected_h2 || observation.leaf_sha256 != spec.leaf_sha256 {
        return Err("alpn_or_leaf_mismatch");
    }
    observation.stage = "h2_handshake";
    let mut builder = h2::client::Builder::new();
    builder.enable_push(false).max_concurrent_streams(0)
        .max_header_list_size(MAX_HEADERS as u32).initial_max_send_streams(1);
    let (mut sender, connection) = timeout_at(
        until.into(), builder.handshake::<_, Bytes>(tls)).await
        .map_err(|_| "original_deadline")?.map_err(|_| "h2_handshake_failed")?;
    let mut driver = tokio::spawn(connection);
    let operation = async {
        let mut token = HeaderValue::from_bytes(&spec.token).map_err(|_| "token_header")?;
        token.set_sensitive(true);
        let request = Request::builder().method("GET")
            .uri(format!("https://localhost:{}{}", spec.port, spec.path()?))
            .version(Version::HTTP_2).header("x-vault-token", token)
            .header(header::ACCEPT_ENCODING, "identity").body(())
            .map_err(|_| "request_build")?;
        observation.stage = "send_request";
        if Instant::now() >= until {
            return Err("original_deadline_before_dispatch");
        }
        // Set conservative dispatch evidence before the sole send call.
        observation.request_dispatched = true;
        observation.request_calls = 1;
        let (response, send_stream) = sender.send_request(request, true)
            .map_err(|_| "h2_send_failed")?;
        observation.stream_id = send_stream.stream_id().as_u32();
        if observation.stream_id != 1 {
            return Err("unexpected_stream_id");
        }
        observation.stage = "response_headers";
        let response = response.await.map_err(|_| "h2_headers_failed")?;
        if response.version() != Version::HTTP_2 {
            return Err("response_http_version");
        }
        observation.status = Some(response.status().as_u16());
        let expected = inspect_headers(response.headers(), observation)?;
        observation.stage = "response_body";
        let mut stream = response.into_body();
        let result = receive_body(&mut stream, expected, body, observation).await;
        drop(stream);
        drop(send_stream);
        result
    };
    let result = timeout_at(until.into(), operation).await
        .map_err(|_| "original_deadline").and_then(|value| value);
    drop(sender);
    // Connection driver never creates a second connection or resends a request.
    // Abort only this client's driver and await its actual destruction.
    driver.abort();
    match timeout_at(until.into(), &mut driver).await {
        Ok(Err(join_error)) if join_error.is_cancelled() => {
            observation.connection_task_joined = true;
            observation.connection_task_cancelled_after_observation = true;
        }
        Ok(Ok(Ok(()))) => observation.connection_task_joined = true,
        Ok(Ok(Err(_))) => {
            observation.connection_task_joined = true;
            if result.is_ok() {
                return Err("h2_connection_driver_failed");
            }
        }
        Ok(Err(_)) => return Err("h2_connection_driver_panicked"),
        Err(_) => return Err("original_deadline_during_driver_join"),
    }
    result
}

fn run() -> i32 {
    let mut body = Zeroizing::new(Vec::new());
    let mut observation = Observation { stage: "input", ..Observation::default() };
    let outcome = (|| -> Checked<()> {
        let args: Vec<_> = env::args().collect();
        if args.len() != 3 || args[1] != "--spec-sha256" || args[2].len() != 64
            || !args[2].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err("exact_argv");
        }
        let mut raw = Zeroizing::new(Vec::new());
        std::io::stdin().take((MAX_SPEC + 1) as u64).read_to_end(&mut raw)
            .map_err(|_| "input_read")?;
        if raw.len() > MAX_SPEC || digest(&raw) != args[2] {
            return Err("input_digest_or_bound");
        }
        let spec = Spec::parse(&raw)?;
        observation.deadline_ns = spec.until;
        observation.operation = spec.operation;
        let until = deadline(spec.until)?;
        let runtime = Builder::new_current_thread().enable_all().build()
            .map_err(|_| "runtime_create")?;
        let result = runtime.block_on(exchange(&spec, until, &mut body, &mut observation));
        drop(runtime);
        result?;
        if clock_ns()? >= spec.until {
            return Err("original_deadline_after_runtime");
        }
        observation.completed_before_deadline = true;
        observation.stage = "complete";
        Ok(())
    })();
    let mut failure = outcome.err();
    // stdout is the parent's already-created private body file. No body, token,
    // certificate text, URL input or dynamic library error goes into JSON.
    if std::io::stdout().write_all(&body).and_then(|_| std::io::stdout().flush()).is_err() {
        failure = Some("private_body_output_failed");
    }
    if observation.deadline_ns != 0
        && clock_ns().map_or(true, |now| now >= observation.deadline_ns) {
        failure = Some("original_deadline_before_report");
        observation.completed_before_deadline = false;
    }
    let report = observation.report(&body, failure);
    let published = serde_json::to_vec(&report).map_err(|_| ())
        .and_then(|mut raw| {
            raw.push(b'\n');
            std::io::stderr().write_all(&raw).and_then(|_| std::io::stderr().flush())
                .map_err(|_| ())
        }).is_ok();
    let still_before = observation.deadline_ns != 0
        && clock_ns().is_ok_and(|now| now < observation.deadline_ns);
    if failure.is_none() && published && still_before
        && observation.response_complete && observation.connection_task_joined {
        0
    } else {
        1
    }
}
fn main() {
    std::process::exit(run());
}
