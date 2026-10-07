//! Verified TLS ALPN and multiplexed HTTP/2 share the existing logical ingress.
use super::*;
use bytes::Bytes;
use futures::future::poll_fn;
use rustls::ServerConnection;
use tokio_rustls::{TlsAcceptor, server::TlsStream};

const MAX_STREAMS: u32 = 32;
const DATA_CHUNK: usize = 16 * 1024;

#[allow(clippy::too_many_arguments)]
pub(super) fn negotiate(
    stream: TcpStream,
    tls: Arc<ServerConfig>,
    deadline: Instant,
    timeout: Duration,
    service: Arc<Mutex<Service>>,
    limiter: Arc<Mutex<RateLimiter>>,
    peer: IpAddr,
    consistency: consistency::Settings,
    first_rate_limited: bool,
) -> Option<StreamOwned<ServerConnection, DeadlineStream>> {
    stream.set_nonblocking(true).ok()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(MAX_STREAMS as usize)
        .build()
        .ok()?;
    let accepted = runtime.block_on(async {
        let transport = tokio::net::TcpStream::from_std(stream).ok()?;
        tokio::time::timeout_at(deadline.into(), TlsAcceptor::from(tls).accept(transport))
            .await
            .ok()?
            .ok()
    })?;
    if accepted.get_ref().1.alpn_protocol() != Some(b"h2") {
        let (transport, connection) = accepted.into_inner();
        let stream = transport.into_std().ok()?;
        stream.set_nonblocking(false).ok()?;
        return Some(StreamOwned::new(
            connection,
            DeadlineStream { stream, deadline },
        ));
    }
    let certificates = accepted
        .get_ref()
        .1
        .peer_certificates()
        .map(|certificates| {
            certificates
                .iter()
                .map(|certificate| certificate.as_ref().to_vec())
                .collect()
        });
    let context = Arc::new(Context {
        service,
        limiter,
        peer,
        consistency,
        certificates,
    });
    runtime.block_on(async {
        let _ = serve(accepted, context, deadline, timeout, first_rate_limited).await;
    });
    // Runtime drop waits for the owned synchronous Service effects. Cancelling
    // a stream never refunds admission or abandons a started durable effect.
    drop(runtime);
    None
}

struct Context {
    service: Arc<Mutex<Service>>,
    limiter: Arc<Mutex<RateLimiter>>,
    peer: IpAddr,
    consistency: consistency::Settings,
    certificates: Option<Vec<Vec<u8>>>,
}

async fn serve(
    transport: TlsStream<tokio::net::TcpStream>,
    context: Arc<Context>,
    first_deadline: Instant,
    timeout: Duration,
    first_rate_limited: bool,
) -> Result<(), ()> {
    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(MAX_STREAMS)
        .max_header_list_size(MAX_HEADERS as u32)
        .max_send_buffer_size(64 * 1024)
        .initial_window_size(64 * 1024)
        .initial_connection_window_size(1024 * 1024);
    let mut connection = builder
        .handshake::<_, Bytes>(transport)
        .await
        .map_err(|_| ())?;
    let mut first = true;
    loop {
        // Bound idle connections while giving each subsequent HEADERS admission
        // one new request budget. Body, writer, provider and audit share it.
        let accept_deadline = if first {
            first_deadline
        } else {
            Instant::now() + timeout
        };
        let Some(accepted) = tokio::time::timeout_at(accept_deadline.into(), connection.accept())
            .await
            .map_err(|_| ())?
        else {
            break;
        };
        let (request, sender) = accepted.map_err(|_| ())?;
        let deadline = if first {
            first_deadline
        } else {
            Instant::now() + timeout
        };
        let limited = if first {
            first_rate_limited
        } else {
            context
                .limiter
                .lock()
                .map_or(true, |mut limiter| !limiter.allow(context.peer))
        };
        first = false;
        let context = Arc::clone(&context);
        let _task = tokio::spawn(async move {
            let _ = tokio::time::timeout_at(
                deadline.into(),
                exchange(request, sender, context, deadline, limited),
            )
            .await;
        });
    }
    Ok(())
}

async fn exchange(
    request: ::http::Request<h2::RecvStream>,
    sender: h2::server::SendResponse<Bytes>,
    context: Arc<Context>,
    deadline: Instant,
    limited: bool,
) -> Result<(), ()> {
    let (parts, mut body) = request.into_parts();
    let attempt = crypto::random::<16>().map_err(|_| ())?;
    if limited {
        let service = Arc::clone(&context.service);
        let response = tokio::task::spawn_blocking(move || {
            audited_wire_rejection(
                &service,
                &attempt,
                WireRejection::RateLimited,
                429,
                "request rate limit exceeded",
                deadline,
            )
        })
        .await
        .map_err(|_| ())?;
        return send_reply(
            sender,
            snapshot::NativeReply::Json(response),
            false,
            "",
            deadline,
        )
        .await;
    }
    let path = parts.uri.path();
    let maximum = if matches!(
        path,
        "/v1/sys/storage/raft/snapshot" | "/v1/sys/storage/raft/snapshot-force"
    ) {
        MAX_SNAPSHOT_BODY
    } else {
        MAX_BODY
    };
    let mut payload = Zeroizing::new(Vec::new());
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|_| ())?;
        if payload
            .len()
            .checked_add(chunk.len())
            .is_none_or(|size| size > maximum)
        {
            let service = Arc::clone(&context.service);
            let response = tokio::task::spawn_blocking(move || {
                audited_wire_rejection(
                    &service,
                    &attempt,
                    WireRejection::ParseRejected,
                    413,
                    "request body exceeds limit",
                    deadline,
                )
            })
            .await
            .map_err(|_| ())?;
            return send_reply(
                sender,
                snapshot::NativeReply::Json(response),
                false,
                "",
                deadline,
            )
            .await;
        }
        payload.extend_from_slice(&chunk);
        body.flow_control()
            .release_capacity(chunk.len())
            .map_err(|_| ())?;
    }
    let wire = request_wire(&parts, &payload);
    let reply = tokio::task::spawn_blocking(move || {
        let (wire, rejection) = match wire {
            Ok(wire) => (wire, None),
            Err(error) => (Zeroizing::new(Vec::new()), Some(error)),
        };
        let mut source = io::Cursor::new(wire);
        let parsed = match rejection {
            Some(error) => Err(error),
            None => read_request_mode(
                &mut source,
                deadline.saturating_duration_since(Instant::now()),
                true,
            ),
        };
        process_parsed_request(
            &context.service,
            parsed,
            &mut source,
            context.certificates.clone(),
            context.peer,
            &attempt,
            context.consistency,
            deadline,
        )
    })
    .await
    .map_err(|_| ())?;
    send_reply(sender, reply.0, reply.1, &reply.2, deadline).await
}

fn request_wire(
    parts: &::http::request::Parts,
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ParseError> {
    let target = parts
        .uri
        .path_and_query()
        .ok_or_else(|| bad("missing HTTP/2 request target"))?
        .as_str();
    let mut wire = Zeroizing::new(Vec::new());
    write!(wire, "{} {target} HTTP/1.1\r\n", parts.method)
        .map_err(|_| bad("cannot frame HTTP/2 request"))?;
    if !parts.headers.contains_key(::http::header::HOST) {
        let authority = parts
            .uri
            .authority()
            .ok_or_else(|| bad("missing HTTP/2 authority"))?
            .as_str();
        write!(wire, "Host: {authority}\r\n").map_err(|_| bad("cannot frame HTTP/2 request"))?;
    }
    for (name, value) in &parts.headers {
        wire.extend_from_slice(name.as_str().as_bytes());
        wire.extend_from_slice(b": ");
        wire.extend_from_slice(value.as_bytes());
        wire.extend_from_slice(b"\r\n");
        if wire.len() > MAX_HEADERS {
            return Err(bad("headers too large"));
        }
    }
    if !parts.headers.contains_key(::http::header::CONTENT_LENGTH) {
        write!(wire, "Content-Length: {}\r\n", payload.len())
            .map_err(|_| bad("cannot frame HTTP/2 request"))?;
    }
    wire.extend_from_slice(b"\r\n");
    if wire.len() > MAX_HEADERS {
        return Err(bad("headers too large"));
    }
    wire.extend_from_slice(payload);
    Ok(wire)
}

async fn send_reply(
    mut sender: h2::server::SendResponse<Bytes>,
    reply: snapshot::NativeReply,
    head: bool,
    namespace: &str,
    deadline: Instant,
) -> Result<(), ()> {
    if Instant::now() >= deadline {
        return Err(());
    }
    let mut wire = Zeroizing::new(Vec::new());
    reply
        .write_with_namespace(&mut *wire, head, namespace)
        .map_err(|_| ())?;
    let (response, payload) = response_frames(wire)?;
    let mut output = sender
        .send_response(response, payload.is_empty())
        .map_err(|_| ())?;
    let bytes = Bytes::from_owner(payload);
    let mut offset = 0;
    while offset < bytes.len() {
        if Instant::now() >= deadline {
            return Err(());
        }
        let requested = DATA_CHUNK.min(bytes.len() - offset);
        output.reserve_capacity(requested);
        let capacity = poll_fn(|cx| output.poll_capacity(cx))
            .await
            .ok_or(())?
            .map_err(|_| ())?;
        if capacity == 0 {
            continue;
        }
        let count = requested.min(capacity);
        let end = offset + count;
        output
            .send_data(bytes.slice(offset..end), end == bytes.len())
            .map_err(|_| ())?;
        offset = end;
    }
    Ok(())
}

fn response_frames(
    wire: Zeroizing<Vec<u8>>,
) -> Result<(::http::Response<()>, Zeroizing<Vec<u8>>), ()> {
    let split = wire
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or(())?;
    let header = std::str::from_utf8(&wire[..split]).map_err(|_| ())?;
    let mut lines = header.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or(())?
        .parse::<u16>()
        .map_err(|_| ())?;
    let mut response = ::http::Response::builder().status(status);
    let mut chunked = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(())?;
        match name.to_ascii_lowercase().as_str() {
            "connection" | "keep-alive" | "proxy-connection" | "upgrade" => {}
            "transfer-encoding" => {
                chunked = value.trim() == "chunked";
            }
            _ => response = response.header(name, value.trim()),
        }
    }
    let body = &wire[split + 4..];
    let mut payload = Zeroizing::new(Vec::new());
    if chunked {
        let mut remaining = body;
        loop {
            let end = remaining
                .windows(2)
                .position(|bytes| bytes == b"\r\n")
                .ok_or(())?;
            let size =
                usize::from_str_radix(std::str::from_utf8(&remaining[..end]).map_err(|_| ())?, 16)
                    .map_err(|_| ())?;
            remaining = &remaining[end + 2..];
            if size == 0 {
                if remaining != b"\r\n" {
                    return Err(());
                }
                break;
            }
            if size > remaining.len() || remaining.get(size..size + 2) != Some(b"\r\n") {
                return Err(());
            }
            payload.extend_from_slice(&remaining[..size]);
            remaining = &remaining[size + 2..];
        }
    } else {
        payload.extend_from_slice(body);
    }
    Ok((response.body(()).map_err(|_| ())?, payload))
}
