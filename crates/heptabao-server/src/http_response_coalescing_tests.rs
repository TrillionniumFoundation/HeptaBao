//! Ordinary response framing retains the complete small body and original I/O failures.
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const REJECTION: &str = "requested OpenBao header semantics are not implemented";
const REJECTION_BODY: &[u8] =
    b"{\"errors\":[\"requested OpenBao header semantics are not implemented\"]}\n";

#[derive(Default)]
struct WireWriter {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
    short: bool,
    interrupt_once: bool,
    write_zero: bool,
    fail_after_first: bool,
    fail_flush: bool,
}

impl Write for WireWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if std::mem::take(&mut self.interrupt_once) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.write_zero {
            return Ok(0);
        }
        if self.fail_after_first && !self.bytes.is_empty() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let count = if self.short {
            bytes.len().min(7)
        } else {
            bytes.len()
        };
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.fail_flush {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
}

fn split_wire(wire: &[u8]) -> io::Result<(&str, &[u8])> {
    let end = wire
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or_else(|| io::Error::other("complete response head required"))?;
    let header = std::str::from_utf8(&wire[..end]).map_err(io::Error::other)?;
    assert!(!header.replace("\r\n", "").contains(['\r', '\n']));
    Ok((header, &wire[end + 4..]))
}

fn values<'a>(header: &'a str, name: &str) -> Vec<&'a str> {
    header
        .split("\r\n")
        .skip(1)
        .filter_map(|line| {
            let (key, value) = line.split_once(": ")?;
            key.eq_ignore_ascii_case(name).then_some(value)
        })
        .collect()
}

fn assert_rejection(wire: &[u8]) -> io::Result<()> {
    let (header, body) = split_wire(wire)?;
    assert!(header.starts_with("HTTP/1.1 501 Not Implemented\r\n"));
    assert_eq!(
        values(header, "Content-Length"),
        [REJECTION_BODY.len().to_string()]
    );
    assert!(values(header, "Transfer-Encoding").is_empty());
    assert_eq!(values(header, "Content-Type"), ["application/json"]);
    assert_eq!(values(header, "Connection"), ["close"]);
    assert_eq!(values(header, "Cache-Control"), ["no-store"]);
    assert_eq!(values(header, "Date").len(), 1);
    assert_eq!(
        values(header, "Strict-Transport-Security"),
        ["max-age=31536000; includeSubDomains"]
    );
    assert_eq!(body.len(), REJECTION_BODY.len(), "complete declared body");
    assert_eq!(
        body, REJECTION_BODY,
        "exact original body, including newline"
    );
    Ok(())
}

#[test]
fn ordinary_http_complete_small_prefix_keeps_body_and_bounded_metadata() -> TestResult {
    let mut writer = WireWriter::default();
    write_response_with_namespace(
        &mut writer,
        Response::error(501, REJECTION),
        false,
        "team/path",
    )?;
    assert_eq!((writer.writes, writer.flushes), (1, 1));
    assert_rejection(&writer.bytes)?;
    assert_eq!(
        values(split_wire(&writer.bytes)?.0, "X-Vault-Namespace"),
        ["team/path"]
    );

    // Preserve admitted metadata near its aggregate 32 KiB cap, including the
    // original canonical spelling and the independently bounded namespace.
    let mut response = Response::error(501, REJECTION);
    let supplied = json!({"X-Bounded": vec!["v".repeat(4090); 7]});
    response.response_headers =
        crate::service::ResponseHeaders::from_sdk(Some(&supplied), &["X-Bounded".to_owned()])
            .map_err(|()| "admitted bounded response metadata")?;
    let mut writer = WireWriter::default();
    write_response_with_namespace(&mut writer, response, false, &"n".repeat(512))?;
    assert_eq!((writer.writes, writer.flushes), (1, 1));
    assert_rejection(&writer.bytes)?;
    assert_eq!(
        values(split_wire(&writer.bytes)?.0, "X-Bounded"),
        vec!["v".repeat(4090); 7]
    );
    assert!(
        crate::service::ResponseHeaders::from_sdk(
            Some(&json!({"X-Bounded": vec!["v".repeat(4090); 8]})),
            &["X-Bounded".to_owned()],
        )
        .is_err(),
        "the existing aggregate bound is not expanded"
    );
    Ok(())
}

#[test]
fn ordinary_http_original_head_no_body_chunked_and_large_raw_framing_remain() -> TestResult {
    let mut writer = WireWriter::default();
    write_response(&mut writer, Response::error(501, REJECTION), true)?;
    let (header, body) = split_wire(&writer.bytes)?;
    assert_eq!(
        values(header, "Content-Length"),
        [REJECTION_BODY.len().to_string()]
    );
    assert!(body.is_empty());
    assert_eq!((writer.writes, writer.flushes), (1, 1));

    for status in [100, 204, 304] {
        let mut writer = WireWriter::default();
        write_response(&mut writer, Response::error(status, REJECTION), false)?;
        let (header, body) = split_wire(&writer.bytes)?;
        assert!(header.starts_with(&format!("HTTP/1.1 {status} ")));
        assert!(values(header, "Content-Length").is_empty());
        assert!(values(header, "Transfer-Encoding").is_empty());
        assert!(body.is_empty());
        assert_eq!((writer.writes, writer.flushes), (1, 1));
    }

    let large = "L".repeat(4096);
    let expected = format!("{{\"errors\":[\"{large}\"]}}\n");
    let mut writer = WireWriter::default();
    write_response(&mut writer, Response::error(501, &large), false)?;
    let (header, body) = split_wire(&writer.bytes)?;
    assert!(values(header, "Content-Length").is_empty());
    assert_eq!(values(header, "Transfer-Encoding"), ["chunked"]);
    assert_eq!(
        body,
        format!("{:x}\r\n{expected}\r\n0\r\n\r\n", expected.len()).as_bytes()
    );
    assert!(
        writer.writes > 1,
        "the large body keeps its existing streaming writes"
    );
    let mut head = WireWriter::default();
    write_response(&mut head, Response::error(501, &large), true)?;
    let (header, body) = split_wire(&head.bytes)?;
    assert!(values(header, "Content-Length").is_empty());
    assert!(values(header, "Transfer-Encoding").is_empty());
    assert!(body.is_empty());

    // The existing closed certificate producer retains fixed-length raw bytes.
    use base64::Engine as _;
    let raw = vec![0xa5; 4096];
    let mut response = Response::error(200, "unused");
    response.body = json!({
        "format":"der", "__heptabao_pki_certificate":
            base64::engine::general_purpose::STANDARD.encode(&raw),
    });
    let mut writer = WireWriter::default();
    write_response(&mut writer, response, false)?;
    let (header, body) = split_wire(&writer.bytes)?;
    assert_eq!(values(header, "Content-Length"), ["4096"]);
    assert_eq!(values(header, "Content-Type"), ["application/pkix-cert"]);
    assert!(values(header, "Transfer-Encoding").is_empty());
    assert_eq!(body, raw);
    assert_eq!((writer.writes, writer.flushes), (2, 1));
    Ok(())
}

#[test]
fn ordinary_http_prefix_keeps_partial_writes_and_original_io_failures() -> TestResult {
    let mut short = WireWriter {
        short: true,
        interrupt_once: true,
        ..Default::default()
    };
    write_response(&mut short, Response::error(501, REJECTION), false)?;
    assert!(short.writes > 2);
    assert_eq!(short.flushes, 1);
    assert_rejection(&short.bytes)?;

    let mut zero = WireWriter {
        write_zero: true,
        ..Default::default()
    };
    assert_eq!(
        write_response(&mut zero, Response::error(501, REJECTION), false)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WriteZero
    );
    assert_eq!((zero.writes, zero.flushes), (1, 0));
    let mut broken = WireWriter {
        short: true,
        fail_after_first: true,
        ..Default::default()
    };
    assert_eq!(
        write_response(&mut broken, Response::error(501, REJECTION), false)
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(
        (broken.writes, broken.flushes, broken.bytes.len()),
        (2, 0, 7)
    );
    let mut flush = WireWriter {
        fail_flush: true,
        ..Default::default()
    };
    assert_eq!(
        write_response(&mut flush, Response::error(501, REJECTION), false)
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!((flush.writes, flush.flushes), (1, 1));
    assert_rejection(&flush.bytes)?;
    let mut invalid = WireWriter::default();
    assert_eq!(
        write_response_with_namespace(
            &mut invalid,
            Response::error(501, REJECTION),
            false,
            "invalid\r\nnamespace"
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        (invalid.writes, invalid.flushes, invalid.bytes.len()),
        (0, 0, 0)
    );
    Ok(())
}

struct ObservedSocket {
    inner: DeadlineStream,
    reads: usize,
    written: usize,
}
impl Read for ObservedSocket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.inner.read(bytes)
    }
}
impl Write for ObservedSocket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.inner.write(bytes)?;
        self.written += count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn tcp_tls_rejection(
    version: &'static rustls::SupportedProtocolVersion,
    expired: bool,
) -> TestResult {
    use rustls::{ClientConfig, ClientConnection, ServerConnection, pki_types::ServerName};
    use std::sync::mpsc;
    let (root, certificates, key) = api_alpn_tests::tls_identity()?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[version])?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    server_config.send_tls13_tickets = 0;
    configure_api_alpn(&mut server_config);
    let mut roots = RootCertStore::empty();
    roots.add(root)?;
    let mut client_config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "original TLS fixture deadline"))
    };
    let (parsed_send, parsed_recv) = mpsc::sync_channel(1);
    let (body_send, body_recv) = mpsc::sync_channel(1);
    std::thread::scope(|scope| -> io::Result<()> {
        let server = scope.spawn(
            move || -> io::Result<(Option<io::ErrorKind>, usize, usize)> {
                listener.set_nonblocking(true)?;
                let socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            remaining()?;
                            std::thread::yield_now();
                        }
                        Err(error) => return Err(error),
                    }
                };
                socket.set_nonblocking(false)?;
                socket.set_nodelay(true)?;
                let mut stream = StreamOwned::new(
                    ServerConnection::new(Arc::new(server_config)).map_err(io::Error::other)?,
                    ObservedSocket {
                        inner: DeadlineStream {
                            stream: socket,
                            deadline,
                        },
                        reads: 0,
                        written: 0,
                    },
                );
                // The actual ordinary parser rejects this closed unsupported header
                // before a body is sent. No Service/audit/auth result is fabricated.
                let rejection = match read_request_mode(&mut stream, remaining()?, false) {
                    Err(error) if error.status == 501 && error.message == REJECTION => error,
                    _ => return Err(io::Error::other("expected actual ordinary header refusal")),
                };
                assert_eq!(stream.conn.alpn_protocol(), Some(b"http/1.1".as_slice()));
                parsed_send.send(()).map_err(io::Error::other)?;
                body_recv
                    .recv_timeout(remaining()?)
                    .map_err(io::Error::other)?;
                let reads = stream.sock.reads;
                let written = stream.sock.written;
                if expired {
                    stream.sock.inner.deadline = Instant::now() - Duration::from_millis(1);
                }
                let error = write_response(
                    &mut stream,
                    Response::error(rejection.status, rejection.message),
                    false,
                )
                .err()
                .map(|error| error.kind());
                let observation = (
                    error,
                    stream.sock.reads - reads,
                    stream.sock.written - written,
                );
                // Match the listener's drop. Never drain upload bytes, send an
                // extra close_notify, retry a response, or extend its deadline.
                drop(stream);
                Ok(observation)
            },
        );
        let client_result = (|| -> io::Result<Vec<u8>> {
            let socket = TcpStream::connect_timeout(&address, remaining()?)?;
            socket.set_nodelay(true)?;
            let mut socket = DeadlineStream {
                stream: socket,
                deadline,
            };
            let mut connection = ClientConnection::new(
                Arc::new(client_config),
                ServerName::try_from("localhost").map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
            while connection.is_handshaking() {
                connection.complete_io(&mut socket)?;
            }
            assert_eq!(connection.protocol_version(), Some(version.version));
            assert_eq!(connection.alpn_protocol(), Some(b"http/1.1".as_slice()));
            {
                let mut tls = rustls::Stream::new(&mut connection, &mut socket);
                tls.write_all(b"POST /v1/wire/data/unread HTTP/1.1\r\nHost: localhost\r\nX-Vault-Unsupported-Synthetic: 1\r\nContent-Type: application/json\r\nContent-Length: 56\r\n\r\n")?;
                tls.flush()?;
            }
            parsed_recv
                .recv_timeout(remaining()?)
                .map_err(io::Error::other)?;
            {
                let mut tls = rustls::Stream::new(&mut connection, &mut socket);
                tls.write_all(&[b'b'; 56])?;
                tls.flush()?;
            }
            body_send.send(()).map_err(io::Error::other)?;
            let mut socket = test_client::DeadlineClientReader::new(socket.stream, deadline)?;
            let mut header = [0_u8; 5];
            if let Err(error) = socket.read_exact(&mut header) {
                if expired
                    && matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                    )
                {
                    return Ok(Vec::new());
                }
                return Err(error);
            }
            assert_eq!(header[0], 23, "first application record");
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            assert!(length > 0 && length <= 18 * 1024);
            let mut record = header.to_vec();
            record.resize(5 + length, 0);
            socket.read_exact(&mut record[5..])?;
            let mut input = io::Cursor::new(record);
            while input.position() < input.get_ref().len() as u64 {
                assert!(connection.read_tls(&mut input)? > 0);
            }
            let state = connection.process_new_packets().map_err(io::Error::other)?;
            let mut plaintext = vec![0; state.plaintext_bytes_to_read()];
            connection.reader().read_exact(&mut plaintext)?;
            Ok(plaintext)
        })();
        let (error, reads, written) = server
            .join()
            .map_err(|_| io::Error::other("ordinary TLS writer thread panicked"))??;
        let plaintext = client_result?;
        assert_eq!(
            reads, 0,
            "response emission never consumes the pending upload"
        );
        if expired {
            assert_eq!(error, Some(io::ErrorKind::TimedOut));
            assert_eq!(written, 0);
            assert!(plaintext.is_empty());
        } else {
            assert_eq!(error, None);
            assert!(written > 0);
            assert_rejection(&plaintext)?;
        }
        Ok(())
    })?;
    Ok(())
}

#[test]
fn ordinary_http_tcp_tls_first_record_contains_full_small_response_with_unread_upload() -> TestResult
{
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        tcp_tls_rejection(version, false)?;
    }
    Ok(())
}

#[test]
fn ordinary_http_tcp_tls_response_preserves_original_expired_deadline() -> TestResult {
    tcp_tls_rejection(&rustls::version::TLS13, true)
}
