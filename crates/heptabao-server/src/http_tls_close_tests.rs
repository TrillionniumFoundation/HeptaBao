//! Real loopback TLS for the production HTTP/1 writer and terminal close.
//! This is transport regression evidence, not a Service, HA or migration pass.
use super::*;
use rustls::{ClientConfig, ClientConnection, ServerConnection, pki_types::ServerName};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const REQUEST_SECONDS: u64 = 15;
const MAX_REPLY_BYTES: u64 = 64 * 1024;

struct OwnedTlsWorker(Option<std::thread::JoinHandle<io::Result<()>>>);

impl OwnedTlsWorker {
    fn join(mut self) -> TestResult {
        self.0
            .take()
            .ok_or("TLS worker already joined")?
            .join()
            .map_err(|_| "owned TLS worker panicked")??;
        Ok(())
    }
}

impl Drop for OwnedTlsWorker {
    fn drop(&mut self) {
        if let Some(worker) = self.0.take() {
            let _ = worker.join();
        }
    }
}

fn reply(status: u16) -> snapshot::NativeReply {
    snapshot::NativeReply::Json(Response {
        status,
        unwrapped_json: None,
        response_headers: Default::default(),
        consistency_index: None,
        body: json!({"data":{"marker":"synthetic-tls-close"}}),
    })
}

fn exchange(
    version: &'static rustls::SupportedProtocolVersion,
    status: u16,
    head: bool,
    orderly_close: bool,
) -> TestResult<(Vec<u8>, Option<io::ErrorKind>)> {
    let (root, certificates, key) = api_alpn_tests::tls_identity()?;
    let expected_leaf = certificates[0].as_ref().to_vec();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[version])?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    configure_api_alpn(&mut server_config);
    let mut roots = RootCertStore::empty();
    roots.add(root)?;
    let mut client_config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    // Connect, verified TLS, HTTP bytes, terminal alert and worker join share
    // one original deadline. The client never sends a reciprocal close alert.
    let deadline = Instant::now() + Duration::from_secs(REQUEST_SECONDS);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let client_socket = TcpStream::connect_timeout(
        &listener.local_addr()?,
        deadline.saturating_duration_since(Instant::now()),
    )?;
    let (server_socket, _) = listener.accept()?;
    drop(listener);
    let request: &'static [u8] = if head {
        b"HEAD /v1/synthetic HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    } else {
        b"GET /v1/synthetic HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    };
    let server_connection = ServerConnection::new(Arc::new(server_config))?;
    let client_connection =
        ClientConnection::new(Arc::new(client_config), ServerName::try_from("localhost")?)?;
    let worker = OwnedTlsWorker(Some(std::thread::spawn(move || -> io::Result<()> {
        let mut server = StreamOwned::new(
            server_connection,
            DeadlineStream {
                stream: server_socket,
                deadline,
            },
        );
        let mut received = vec![0; request.len()];
        server.read_exact(&mut received)?;
        if received.as_slice() != request {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "test request mismatch",
            ));
        }
        write_http1_reply(&mut server, reply(status), head, "", deadline)?;
        if orderly_close {
            finish_http1_connection(&mut server)?;
        }
        assert_eq!(
            server.sock.deadline, deadline,
            "terminal close cannot renew time"
        );
        Ok(())
    })));
    let mut client = StreamOwned::new(
        client_connection,
        DeadlineStream {
            stream: client_socket,
            deadline,
        },
    );
    let observed = (|| -> TestResult<(Vec<u8>, Option<io::ErrorKind>)> {
        client.write_all(request)?;
        client.flush()?;
        let mut wire = Vec::new();
        // Consume beyond the advertised HTTP body to actual TLS EOF. A complete
        // HTTP response followed by bare TCP EOF must remain a rejected result.
        let error = Read::by_ref(&mut client)
            .take(MAX_REPLY_BYTES)
            .read_to_end(&mut wire)
            .err()
            .map(|error| error.kind());
        assert!(
            wire.len() < MAX_REPLY_BYTES as usize,
            "bounded TLS response"
        );
        assert!(!client.conn.is_handshaking());
        assert_eq!(client.conn.protocol_version(), Some(version.version));
        assert_eq!(client.conn.alpn_protocol(), Some(b"http/1.1".as_slice()));
        let peers = client
            .conn
            .peer_certificates()
            .ok_or("verified peer missing")?;
        assert_eq!(peers[0].as_ref(), expected_leaf.as_slice());
        assert!(Instant::now() < deadline, "original TLS request deadline");
        Ok((wire, error))
    })();
    // Join even when the client returned an error, with its socket still open:
    // completing the close must not depend on the client acknowledging it.
    let joined = worker.join();
    let observed = observed?;
    joined?;
    Ok(observed)
}

fn check_wire(bytes: &[u8], status: u16, head: bool) -> TestResult {
    let boundary = bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .ok_or("complete HTTP response head")?;
    let headers = std::str::from_utf8(&bytes[..boundary])?;
    assert!(headers.starts_with(&format!("HTTP/1.1 {status} ")));
    assert!(!headers.contains("Transfer-Encoding:"));
    let body = &bytes[boundary + 4..];
    let length = headers
        .split("\r\n")
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .map(str::parse::<usize>)
        .transpose()?;
    if status == 204 {
        assert!(length.is_none());
        assert!(body.is_empty());
    } else if head {
        assert!(length.is_some_and(|length| length > 0));
        assert!(body.is_empty());
    } else {
        assert_eq!(length, Some(body.len()));
        assert_eq!(
            serde_json::from_slice::<Value>(body)?,
            json!({"data":{"marker":"synthetic-tls-close"}})
        );
    }
    Ok(())
}

#[test]
fn http1_completed_replies_end_with_verified_tls_close_notify() -> TestResult {
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        for (status, head) in [
            (200, false),
            (200, true),
            (204, false),
            (403, false),
            (429, false),
        ] {
            let (wire, error) = exchange(version, status, head, true)?;
            assert_eq!(error, None, "strict TLS EOF after complete response");
            check_wire(&wire, status, head)?;
        }
    }
    Ok(())
}

#[test]
fn http1_abrupt_tls_eof_is_rejected_after_complete_http_response() -> TestResult {
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        let (wire, error) = exchange(version, 200, false, false)?;
        check_wire(&wire, 200, false)?;
        assert_eq!(
            error,
            Some(io::ErrorKind::UnexpectedEof),
            "missing close_notify cannot qualify"
        );
    }
    Ok(())
}

#[test]
fn http1_reply_writer_propagates_write_and_flush_failures() {
    struct Failure {
        fail_write: bool,
        flush_attempted: bool,
    }
    impl Write for Failure {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail_write {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "synthetic write failure",
                ))
            } else {
                Ok(bytes.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flush_attempted = true;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "synthetic flush failure",
            ))
        }
    }
    for (fail_write, expected) in [
        (true, io::ErrorKind::BrokenPipe),
        (false, io::ErrorKind::TimedOut),
    ] {
        let mut writer = Failure {
            fail_write,
            flush_attempted: false,
        };
        let result = write_http1_reply(
            &mut writer,
            reply(200),
            false,
            "",
            Instant::now() + Duration::from_secs(REQUEST_SECONDS),
        );
        assert_eq!(result.err().map(|error| error.kind()), Some(expected));
        assert_eq!(writer.flush_attempted, !fail_write);
    }
}

#[test]
fn http1_terminal_close_rejects_expired_original_deadline() -> TestResult {
    let (_, certificates, key) = api_alpn_tests::tls_identity()?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut peer = TcpStream::connect_timeout(&listener.local_addr()?, Duration::from_secs(1))?;
    let (socket, _) = listener.accept()?;
    drop(listener);
    let original_deadline = Instant::now();
    let mut server = StreamOwned::new(
        ServerConnection::new(Arc::new(server_config))?,
        DeadlineStream {
            stream: socket,
            deadline: original_deadline,
        },
    );
    let error = finish_http1_connection(&mut server)
        .err()
        .ok_or("expired original deadline must reject terminal close")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(server.sock.deadline, original_deadline);
    assert!(
        !server.conn.wants_write(),
        "expired close cannot queue TLS output"
    );
    drop(server);
    peer.set_read_timeout(Some(Duration::from_secs(1)))?;
    assert_eq!(
        peer.read(&mut [0; 1])?,
        0,
        "expired close sent no TLS bytes"
    );
    Ok(())
}
