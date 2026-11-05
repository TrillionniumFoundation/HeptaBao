//! Framing tests use real Service + Raft observations, not a fabricated origin.
use super::*;
use crate::ha::snapshot_test_support::Cluster;

type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct UnreadBody(usize);
impl Read for UnreadBody {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        self.0 += 1;
        Err(io::Error::other("standby must not read the native upload"))
    }
}

fn dispatch(
    service: &Arc<Mutex<Service>>,
    raw: &str,
    reader: &mut impl Read,
    deadline: Instant,
) -> Result<(NativeReply, bool), Box<dyn std::error::Error>> {
    let mut parsed = read_request_mode(&mut raw.as_bytes(), Duration::from_secs(5), true)
        .map_err(|_| "parse request")?;
    let head = parsed.method == "HEAD";
    let native = parsed.native_snapshot.take().ok_or("native request")?;
    let request = ServiceRequest {
        method: &parsed.method,
        path: &parsed.path,
        namespace: &parsed.namespace,
        token: &parsed.token,
        body: std::mem::take(&mut parsed.body.0),
        wrap_ttl_seconds: parsed.wrap_ttl_seconds,
        origin_peer: None,
        client_certificates: None,
    };
    Ok((execute(service, request, native, reader, deadline), head))
}

struct StandbyFixture {
    service: Arc<Mutex<Service>>,
    _cluster: Cluster,
    _root: Directory,
}

fn standby_fixture() -> Result<StandbyFixture, Box<dyn std::error::Error>> {
    let root = Directory(std::env::temp_dir().join(format!(
        "heptabao-native-redirect-{}-{}",
        std::process::id(),
        u64::from_le_bytes(crypto::random::<8>()?),
    )));
    std::fs::create_dir(&root.0)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700))?;
    }
    let data = root.0.join("data");
    let audit = root.0.join("audit.jsonl");
    let mut local = Service::new(data.clone(), &audit)?;
    let initialized = local.handle(
        "POST",
        "sys/init",
        "",
        "",
        json!({"secret_shares":1,"secret_threshold":1}),
    );
    assert_eq!(initialized.status, 200);
    let key = initialized.body["keys_base64"][0]
        .as_str()
        .ok_or("key")?
        .to_owned();
    assert_eq!(
        local
            .handle("POST", "sys/unseal", "", "", json!({"key":key}))
            .status,
        200
    );
    let health = local.handle("GET", "sys/health", "", "", json!({}));
    let cluster_id = health.body["cluster_id"]
        .as_str()
        .ok_or("cluster id")?
        .to_owned();
    drop(local);
    let cluster = Cluster::new(&root.0.join("raft"), &cluster_id)?;
    cluster.configure_api_address(1, "https://[::1]:18200/")?;
    // This legacy transport fixture intentionally has no native committed-root
    // owner. Redirecting an unread archive must not require a native read.
    #[cfg(feature = "native-v6-ha")]
    assert!(
        !cluster.processes[1]
            .lock()
            .map_err(|_| "HA poisoned")?
            .native_v6_enabled()
    );
    let mut standby = Service::new_with_ha(data, &audit, Arc::clone(&cluster.processes[1]))?;
    assert_eq!(
        standby
            .handle("POST", "sys/unseal", "", "", json!({"key":key}))
            .status,
        200
    );
    let service = Arc::new(Mutex::new(standby));
    Ok(StandbyFixture {
        service,
        _cluster: cluster,
        _root: root,
    })
}

#[test]
fn native_http_redirect_has_exact_safe_location_and_no_upload_read_or_response_body() -> TestResult
{
    let fixture = standby_fixture()?;
    let service = Arc::clone(&fixture.service);
    let deadline = || Instant::now() + Duration::from_secs(5);
    for (method, route, framing) in [
        ("GET", "snapshot?after=a%2Fb+z&limit=00", ""),
        ("HEAD", "snapshot", ""),
        ("POST", "snapshot", "Content-Length: 25000000\r\n"),
        (
            "PUT",
            "snapshot-force?after=x%26y",
            "Transfer-Encoding: chunked\r\n",
        ),
    ] {
        let raw = format!(
            "{method} /v1/sys/storage/raft/{route} HTTP/1.1\r\nHost: attacker.invalid\r\nX-Forwarded-Host: attacker.invalid\r\nX-Forwarded-Proto: http\r\nX-Vault-Token: invalid\r\n{framing}\r\n"
        );
        let mut source = UnreadBody(0);
        let (reply, head) = dispatch(&service, &raw, &mut source, deadline())?;
        let mut response = Vec::new();
        reply.write(&mut response, head)?;
        assert_eq!(source.0, 0);
        let wire = std::str::from_utf8(&response)?;
        assert!(wire.starts_with(&format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://[::1]:18200/v1/sys/storage/raft/{route}\r\nContent-Length: 0\r\n",
        )));
        assert!(
            wire.contains("\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\n")
        );
        assert!(wire.contains("\r\nDate: "));
        assert!(wire.ends_with("\r\nConnection: close\r\n\r\n"));
        assert!(!wire.contains("X-Content-Type-Options:"));
    }
    let mut source = UnreadBody(0);
    let (reply, _) = dispatch(
        &service,
        "POST /v1/sys/storage/raft/snapshot HTTP/1.1\r\nHost: local\r\nContent-Length: 25000000\r\n\r\n",
        &mut source,
        Instant::now() - Duration::from_millis(1),
    )?;
    assert!(matches!(reply, NativeReply::Json(ref response) if response.status == 503));
    assert_eq!(source.0, 0);
    assert!(crate::request_deadline::current().is_none());
    Ok(())
}

#[test]
fn native_redirect_target_keeps_existing_query_validation_and_rejects_header_injection() {
    for target in [
        "/v1/sys/storage/raft/snapshot?after=%0d%0aLocation%3aevil",
        "/v1/sys/storage/raft/snapshot?after=%0a",
        "/v1/sys/storage/raft/snapshot?after=%zz",
        "/v1/sys/storage/raft/snapshot?after=fragment#ignored",
        "/v1/sys/storage/raft/snapshot?after=raw\tcontrol",
        "/v1/sys/storage/raft/snapshot?after=x&after=y",
        "/v1/sys/storage/raft/snapshot?unknown=x",
        "/v1/sys/storage/raft/snapshot%2fforce",
        "https://evil.invalid/v1/sys/storage/raft/snapshot",
    ] {
        let raw = format!("GET {target} HTTP/1.1\r\nHost: local\r\n\r\n");
        assert!(read_request_mode(&mut raw.as_bytes(), Duration::from_secs(5), true).is_err());
    }
}

#[derive(Default)]
struct HeadWriter {
    bytes: Vec<u8>,
    first_offer: Vec<u8>,
    writes: usize,
    flushes: usize,
    short: bool,
    interrupt_once: bool,
    write_zero: bool,
    fail_flush: bool,
}
impl Write for HeadWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        // The first call must contain the final blank line. Every subsequent
        // short/Interrupted call must offer precisely the unconsumed suffix.
        if self.writes == 1 {
            assert!(bytes.ends_with(b"\r\n\r\n"));
            self.first_offer.extend_from_slice(bytes);
        }
        assert_eq!(bytes, &self.first_offer[self.bytes.len()..]);
        if self.interrupt_once {
            self.interrupt_once = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.write_zero {
            return Ok(0);
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
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
}

#[test]
fn native_http_redirect_complete_head_preserves_short_writes_and_transport_errors() -> TestResult {
    let fixture = standby_fixture()?;
    let raw = "POST /v1/sys/storage/raft/snapshot?after=a%2Fb+z HTTP/1.1\r\nHost: local\r\nContent-Length: 22\r\n\r\n";
    let reply = || -> Result<NativeReply, Box<dyn std::error::Error>> {
        let mut source = UnreadBody(0);
        let (reply, _) = dispatch(
            &fixture.service,
            raw,
            &mut source,
            Instant::now() + Duration::from_secs(5),
        )?;
        assert_eq!(source.0, 0);
        assert!(matches!(&reply, NativeReply::Redirect { .. }));
        Ok(reply)
    };
    for short in [false, true] {
        let mut writer = HeadWriter {
            short,
            interrupt_once: short,
            ..Default::default()
        };
        reply()?.write_with_namespace(&mut writer, false, "synthetic/namespace")?;
        assert_eq!(writer.flushes, 1);
        if !short {
            assert_eq!(
                writer.writes, 1,
                "one complete plaintext write when accepted"
            );
        }
        let wire = std::str::from_utf8(&writer.bytes)?;
        assert!(wire.starts_with("HTTP/1.1 307 Temporary Redirect\r\nLocation: https://[::1]:18200/v1/sys/storage/raft/snapshot?after=a%2Fb+z\r\nContent-Length: 0\r\n"));
        assert!(wire.ends_with("\r\nX-Vault-Namespace: synthetic/namespace\r\n\r\n"));
        assert_eq!(wire.matches("HTTP/1.1 ").count(), 1);
    }
    let mut zero = HeadWriter {
        write_zero: true,
        ..Default::default()
    };
    assert_eq!(
        reply()?
            .write(&mut zero, false)
            .err()
            .ok_or("expected original I/O failure")?
            .kind(),
        io::ErrorKind::WriteZero
    );
    assert_eq!((zero.writes, zero.flushes), (1, 0));
    let mut flush = HeadWriter {
        fail_flush: true,
        ..Default::default()
    };
    assert_eq!(
        reply()?
            .write(&mut flush, false)
            .err()
            .ok_or("expected original I/O failure")?
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!((flush.writes, flush.flushes), (1, 1));
    let mut invalid = HeadWriter::default();
    assert_eq!(
        reply()?
            .write_with_namespace(&mut invalid, false, "invalid\r\nnamespace")
            .err()
            .ok_or("expected original I/O failure")?
            .kind(),
        io::ErrorKind::InvalidInput,
    );
    assert_eq!((invalid.writes, invalid.flushes), (0, 0));
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

// The client sends the upload only after the server has parsed the headers.
// No body drain, close-notify, retry, verifier bypass, or added deadline is
// substituted for the actual HTTP listener's StreamOwned + DeadlineStream.
fn tcp_tls_redirect(
    service: &Arc<Mutex<Service>>,
    version: &'static rustls::SupportedProtocolVersion,
    expire_before_write: bool,
) -> TestResult {
    use rustls::{ClientConfig, ClientConnection, ServerConnection, pki_types::ServerName};
    use std::sync::mpsc;

    let (root, certificates, key) = crate::http::api_alpn_tests::tls_identity()?;
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
    let (parsed_send, parsed_recv) = mpsc::sync_channel(1);
    let (body_send, body_recv) = mpsc::sync_channel(1);
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "original TLS fixture deadline"))
    };
    let result = std::thread::scope(|scope| -> io::Result<()> {
        let server = scope.spawn(
            move || -> io::Result<(Option<io::ErrorKind>, usize, usize)> {
                // A successful connect is started below; accept is bounded by the
                // same deadline even if the client setup fails before connecting.
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
                // Darwin can inherit the listener's nonblocking mode. The real
                // HTTP/1.1 negotiation restores blocking before DeadlineStream.
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
                let mut parsed = read_request_mode(&mut stream, remaining()?, true)
                    .map_err(|_| io::Error::other("actual native HTTP header parse"))?;
                assert_eq!(stream.conn.alpn_protocol(), Some(b"http/1.1".as_slice()));
                let native = parsed
                    .native_snapshot
                    .take()
                    .ok_or_else(|| io::Error::other("actual deferred native request"))?;
                assert!(
                    native.body.prefix.is_empty(),
                    "upload is a later TLS record"
                );
                parsed_send.send(()).map_err(io::Error::other)?;
                body_recv
                    .recv_timeout(remaining()?)
                    .map_err(io::Error::other)?;
                let mut unread = UnreadBody(0);
                let request = ServiceRequest {
                    method: &parsed.method,
                    path: &parsed.path,
                    namespace: &parsed.namespace,
                    token: &parsed.token,
                    body: std::mem::take(&mut parsed.body.0),
                    wrap_ttl_seconds: parsed.wrap_ttl_seconds,
                    origin_peer: None,
                    client_certificates: None,
                };
                let reply = execute(service, request, native, &mut unread, deadline);
                assert!(matches!(&reply, NativeReply::Redirect { .. }));
                assert_eq!(unread.0, 0);
                let reads = stream.sock.reads;
                let written = stream.sock.written;
                if expire_before_write {
                    // Inject expiry at the real writer boundary. This only tightens
                    // the socket's existing deadline; it cannot grant a fresh one.
                    stream.sock.inner.deadline = Instant::now() - Duration::from_millis(1);
                }
                let error = reply
                    .write_with_namespace(&mut stream, false, &parsed.namespace)
                    .err()
                    .map(|error| error.kind());
                let observation = (
                    error,
                    stream.sock.reads - reads,
                    stream.sock.written - written,
                );
                // This probe ends at the writer boundary. The production
                // staged close has a separate full-listener regression below.
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
            let raw = b"POST /v1/sys/storage/raft/snapshot?after=a%2Fb+z HTTP/1.1\r\nHost: attacker.invalid\r\nX-Forwarded-Host: attacker.invalid\r\nContent-Type: application/octet-stream\r\nContent-Length: 22\r\n\r\n";
            {
                let mut stream = rustls::Stream::new(&mut connection, &mut socket);
                stream.write_all(raw)?;
                stream.flush()?;
            }
            parsed_recv
                .recv_timeout(remaining()?)
                .map_err(io::Error::other)?;
            {
                let mut stream = rustls::Stream::new(&mut connection, &mut socket);
                stream.write_all(b"invalid-snapshot-body!")?;
                stream.flush()?;
            }
            body_send.send(()).map_err(io::Error::other)?;
            let mut socket =
                crate::http::test_client::DeadlineClientReader::new(socket.stream, deadline)?;
            let mut record_head = [0_u8; 5];
            if let Err(error) = socket.read_exact(&mut record_head) {
                if expire_before_write
                    && matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                    )
                {
                    return Ok(Vec::new());
                }
                return Err(error);
            }
            assert_eq!(
                record_head[0], 23,
                "first post-handshake application record"
            );
            let length = usize::from(u16::from_be_bytes([record_head[3], record_head[4]]));
            assert!(
                length > 0 && length <= 18 * 1024,
                "bounded actual TLS record"
            );
            let mut record = record_head.to_vec();
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
        // Join on every client success/failure path; no detached test worker.
        let (error, reads, written) = server
            .join()
            .map_err(|_| io::Error::other("TLS redirect server thread panicked"))??;
        let plaintext = client_result?;
        assert_eq!(reads, 0, "no socket/body read during response emission");
        if expire_before_write {
            assert_eq!(error, Some(io::ErrorKind::TimedOut));
            assert_eq!(
                written, 0,
                "expired original writer sends no TLS ciphertext"
            );
            assert!(plaintext.is_empty());
        } else {
            assert_eq!(error, None);
            assert!(written > 0);
            let wire = std::str::from_utf8(&plaintext).map_err(io::Error::other)?;
            assert!(wire.starts_with("HTTP/1.1 307 Temporary Redirect\r\nLocation: https://[::1]:18200/v1/sys/storage/raft/snapshot?after=a%2Fb+z\r\nContent-Length: 0\r\n"));
            assert!(
                wire.ends_with("\r\nConnection: close\r\n\r\n"),
                "complete response head in first application record"
            );
            assert!(wire.contains(
                "\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
            ));
            assert!(wire.contains("\r\nDate: "));
            assert_eq!(wire.matches("\r\n\r\n").count(), 1);
        }
        Ok(())
    });
    result?;
    Ok(())
}

#[test]
fn native_http_redirect_tcp_tls_first_record_is_complete_with_unread_upload() -> TestResult {
    let fixture = standby_fixture()?;
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        tcp_tls_redirect(&fixture.service, version, false)?;
    }
    Ok(())
}

#[test]
fn native_http_redirect_tcp_tls_flush_retains_original_deadline_failure() -> TestResult {
    let fixture = standby_fixture()?;
    tcp_tls_redirect(&fixture.service, &rustls::version::TLS13, true)
}

// Exercise the production HTTP parser, Service admission and writer over real
// TLS/TCP. The Raft fixture has real nodes and durable stores, but its internal
// RPC router is in-process; this test makes no physical-host HA claim.
struct RedirectTlsFixture {
    service: Arc<Mutex<Service>>,
    _cluster: Cluster,
    root: Directory,
    server_tls: Arc<ServerConfig>,
    client_tls: Arc<rustls::ClientConfig>,
    expected_leaf: Vec<u8>,
}

struct RedirectTlsWorker(Option<std::thread::JoinHandle<io::Result<()>>>);
impl RedirectTlsWorker {
    fn join(mut self) -> io::Result<()> {
        self.0
            .take()
            .ok_or_else(|| io::Error::other("TLS worker already joined"))?
            .join()
            .map_err(|_| io::Error::other("TLS worker panicked"))?
    }
}
impl Drop for RedirectTlsWorker {
    fn drop(&mut self) {
        if let Some(worker) = self.0.take() {
            let _ = worker.join();
        }
    }
}

impl RedirectTlsFixture {
    fn raw_request(method: &str, route: &str, framing: &str, namespace: &str) -> String {
        let namespace = if namespace.is_empty() {
            String::new()
        } else {
            format!("X-Vault-Namespace: {namespace}\r\n")
        };
        format!(
            "{method} /v1/sys/storage/raft/{route} HTTP/1.1\r\nHost: attacker.invalid\r\nX-Forwarded-Host: attacker.invalid\r\nX-Vault-Token: invalid\r\nContent-Type: application/octet-stream\r\n{framing}{namespace}Connection: close\r\n\r\n"
        )
    }

    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = Directory(std::env::temp_dir().join(format!(
            "heptabao-redirect-tls-{}-{}",
            std::process::id(),
            u64::from_le_bytes(crypto::random::<8>()?),
        )));
        std::fs::create_dir(&root.0)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700))?;
        }
        let data = root.0.join("data");
        let audit = root.0.join("audit.jsonl");
        let mut local = Service::new(data.clone(), &audit)?;
        let initialized = local.handle(
            "POST",
            "sys/init",
            "",
            "",
            json!({"secret_shares":1,"secret_threshold":1}),
        );
        assert_eq!(initialized.status, 200);
        let key = Zeroizing::new(
            initialized.body["keys_base64"][0]
                .as_str()
                .ok_or("unseal key")?
                .to_owned(),
        );
        assert_eq!(
            local
                .handle("POST", "sys/unseal", "", "", json!({"key":key.as_str()}))
                .status,
            200
        );
        let health = local.handle("GET", "sys/health", "", "", json!({}));
        let cluster_id = health.body["cluster_id"]
            .as_str()
            .ok_or("cluster id")?
            .to_owned();
        drop(local);
        let cluster = Cluster::new(&root.0.join("raft"), &cluster_id)?;
        cluster.configure_api_address(1, "https://[::1]:18200/")?;
        let mut standby = Service::new_with_ha(data, &audit, Arc::clone(&cluster.processes[1]))?;
        assert_eq!(
            standby
                .handle("POST", "sys/unseal", "", "", json!({"key":key.as_str()}))
                .status,
            200
        );
        let (ca, certificates, key) = super::super::api_alpn_tests::tls_identity()?;
        let expected_leaf = certificates[0].as_ref().to_vec();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_tls = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certificates, key)?;
        configure_api_alpn(&mut server_tls);
        let mut roots = RootCertStore::empty();
        roots.add(ca)?;
        let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            service: Arc::new(Mutex::new(standby)),
            _cluster: cluster,
            root,
            server_tls: Arc::new(server_tls),
            client_tls: Arc::new(client_tls),
            expected_leaf,
        })
    }

    fn exchange(
        &self,
        method: &str,
        route: &str,
        framing: &str,
        body: &[u8],
        namespace: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Every operation, including the two scheduling gates and worker join,
        // uses this one original request budget. No connection or replay retry.
        let deadline = Instant::now() + Duration::from_secs(15);
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let client_socket = TcpStream::connect_timeout(
            &address,
            deadline.saturating_duration_since(Instant::now()),
        )?;
        let (server_socket, peer) = listener.accept()?;
        drop(listener);
        let server_connection = rustls::ServerConnection::new(Arc::clone(&self.server_tls))?;
        let client_connection = rustls::ClientConnection::new(
            Arc::clone(&self.client_tls),
            rustls::pki_types::ServerName::try_from("localhost")?,
        )?;
        let service = Arc::clone(&self.service);
        let body_pending = !body.is_empty();
        let attempt = crypto::random::<16>()?;
        let (headers_parsed, await_parsed) = std::sync::mpsc::sync_channel(1);
        let (upload_sent, await_upload) = std::sync::mpsc::sync_channel(1);
        let worker = RedirectTlsWorker(Some(std::thread::spawn(move || -> io::Result<()> {
            let mut stream = StreamOwned::new(
                server_connection,
                DeadlineStream {
                    stream: server_socket,
                    deadline,
                },
            );
            stream.sock.deadline =
                execution_deadline_with_response_reserve(Instant::now(), deadline);
            let read_budget = stream
                .sock
                .deadline
                .saturating_duration_since(Instant::now());
            let parsed = read_request_with_ui(&mut stream, read_budget, true, false);
            stream.sock.deadline = deadline;
            headers_parsed
                .send(())
                .map_err(|_| io::Error::other("client abandoned parsed headers"))?;
            await_upload
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "original upload gate deadline")
                })?;
            if body_pending {
                // The client sends the body only after parsing has finished.
                // Peek proves actual encrypted upload bytes are waiting in TCP;
                // it neither consumes plaintext nor changes Service admission.
                stream
                    .sock
                    .stream
                    .set_read_timeout(Some(stream.sock.remaining()?))?;
                if stream.sock.stream.peek(&mut [0u8; 1])? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "upload missing",
                    ));
                }
            }
            let (reply, head, namespace) = process_parsed_request(
                &service,
                None,
                parsed,
                &mut stream,
                None,
                peer.ip(),
                &attempt,
                consistency::Settings::default(),
                deadline,
            );
            let native_redirect = matches!(&reply, NativeReply::Redirect { .. });
            write_http1_reply(&mut stream, reply, head, &namespace, deadline);
            if native_redirect {
                finish_redirect_connection(&mut stream);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original TLS reply deadline",
                ));
            }
            Ok(())
        })));
        let mut client = StreamOwned::new(
            client_connection,
            DeadlineStream {
                stream: client_socket,
                deadline,
            },
        );
        let result = (|| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let request = Self::raw_request(method, route, framing, namespace);
            client.write_all(request.as_bytes())?;
            client.flush()?;
            await_parsed.recv_timeout(deadline.saturating_duration_since(Instant::now()))?;
            client.write_all(body)?;
            client.flush()?;
            upload_sent.send(())?;
            let mut reply = Vec::new();
            while !reply.ends_with(b"\r\n\r\n") {
                // The accepted target plus namespace shares MAX_HEADERS at
                // ingress. The advertised HTTPS origin and response fields
                // can make the valid redirect exceed one 16 KiB TLS record.
                assert!(reply.len() < MAX_HEADERS + 4096, "response headers bounded");
                let mut byte = [0u8; 1];
                if let Err(error) = client.read_exact(&mut byte) {
                    return Err(format!(
                        "redirect headers incomplete after {} bytes: {:?}",
                        reply.len(),
                        error.kind()
                    )
                    .into());
                }
                reply.push(byte[0]);
            }
            assert!(!client.conn.is_handshaking());
            assert_eq!(client.conn.alpn_protocol(), Some(b"http/1.1".as_slice()));
            assert_eq!(
                client
                    .conn
                    .peer_certificates()
                    .ok_or("TLS peer certificate missing")?[0]
                    .as_ref(),
                self.expected_leaf.as_slice()
            );
            assert!(Instant::now() < deadline);
            Ok(reply)
        })();
        drop(client);
        worker.join()?;
        assert!(Instant::now() < deadline);
        result
    }
}

#[test]
fn native_http_redirect_tls_body_preserves_complete_headers() -> TestResult {
    let fixture = RedirectTlsFixture::new()?;
    let long_route = format!("snapshot?after={}", "r".repeat(7000));
    let max_route = format!(
        "snapshot?after={}",
        "r".repeat(8192 - "/v1/sys/storage/raft/snapshot?after=".len())
    );
    let max_namespace = "n".repeat(
        MAX_HEADERS + 4
            - RedirectTlsFixture::raw_request("POST", &max_route, "Content-Length: 22\r\n", "")
                .len()
            - "X-Vault-Namespace: \r\n".len(),
    );
    assert_eq!(
        RedirectTlsFixture::raw_request(
            "POST",
            &max_route,
            "Content-Length: 22\r\n",
            &max_namespace
        )
        .len(),
        MAX_HEADERS + 4
    );
    for (case, (method, route, framing, body, namespace)) in [
        (
            "GET",
            "snapshot?after=a%2Fb+z&limit=00",
            "",
            b"".as_slice(),
            "",
        ),
        (
            "POST",
            "snapshot",
            "Content-Length: 22\r\n",
            b"owned-invalid-snapshot".as_slice(),
            "",
        ),
        (
            "POST",
            long_route.as_str(),
            "Content-Length: 22\r\n",
            b"owned-invalid-snapshot".as_slice(),
            "",
        ),
        (
            "PUT",
            "snapshot-force",
            "Transfer-Encoding: chunked\r\n",
            b"16\r\nowned-invalid-snapshot\r\n0\r\n\r\n".as_slice(),
            "",
        ),
        (
            "POST",
            max_route.as_str(),
            "Content-Length: 22\r\n",
            b"owned-invalid-snapshot".as_slice(),
            max_namespace.as_str(),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let response = fixture
            .exchange(method, route, framing, body, namespace)
            .map_err(|error| format!("TLS redirect case {case}: {error}"))?;
        let wire = std::str::from_utf8(&response)?;
        assert!(wire.starts_with(&format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: https://[::1]:18200/v1/sys/storage/raft/{route}\r\nContent-Length: 0\r\n")));
        assert!(wire.contains("\r\nCache-Control: no-store\r\n"));
        assert!(
            wire.contains("\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\n")
        );
        assert!(wire.contains("\r\nDate: "));
        if namespace.is_empty() {
            assert!(wire.ends_with("\r\nConnection: close\r\n\r\n"));
        } else {
            assert!(wire.ends_with(&format!(
                "\r\nConnection: close\r\nX-Vault-Namespace: {namespace}\r\n\r\n"
            )));
            assert!(
                response.len() > 16 * 1024,
                "cross-record response exercised"
            );
        }
        eprintln!(
            "HBHTTP-REDIRECT-TLS-CASE case={case} header_bytes={} complete=true",
            response.len()
        );
        assert!(!fixture.root.0.join("data/.snapshot-transfer").exists());
    }
    Ok(())
}
