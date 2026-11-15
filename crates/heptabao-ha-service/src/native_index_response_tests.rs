use super::*;
use std::io::Cursor;

fn inner(magic: &[u8; 5], size: usize) -> Vec<u8> {
    assert!(size > INNER_HEADER_BYTES);
    let mut frame = vec![b' '; size];
    frame[..5].copy_from_slice(magic);
    frame[5..9].copy_from_slice(&((size - INNER_HEADER_BYTES) as u32).to_be_bytes());
    frame[9] = b'0';
    frame
}

fn q9() -> Vec<u8> {
    inner(NATIVE_INDEX_REQUEST_MAGIC, INNER_HEADER_BYTES + 2)
}

#[derive(Default)]
struct CountWriter(usize);
impl Write for CountWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.0 += input.len();
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn native_index_transport_capacity_comes_only_from_original_request() {
    let ordinary = ResponseFrameProfile::for_request(&inner(b"HBFQ4", 11)).unwrap();
    let native = ResponseFrameProfile::for_request(&q9()).unwrap();
    assert_eq!(ordinary, ResponseFrameProfile::Legacy);
    assert_eq!(native, ResponseFrameProfile::NativeIndexV1);
    assert_eq!(
        ResponseFrameProfile::for_request(&inner(NATIVE_INDEX_RESPONSE_MAGIC, 11)).unwrap(),
        ResponseFrameProfile::Legacy
    );
    let frame = inner(NATIVE_INDEX_RESPONSE_MAGIC, 2 * 1024 * 1024 + 97);
    let mut wire = Vec::new();
    assert_eq!(native.write(&mut wire, &frame), Ok(()));
    assert_eq!(native.read(&mut Cursor::new(&wire)), Ok(frame.clone()));
    let mut old_reader = Cursor::new(&wire);
    assert_eq!(ordinary.read(&mut old_reader), Err(HaError::InvalidFrame));
    assert_eq!(
        old_reader.position(),
        4,
        "an unsolicited large S7 cannot allocate under Q4"
    );
    let mut old_writer = CountWriter::default();
    assert_eq!(
        ordinary.write(&mut old_writer, &frame),
        Err(HaError::InvalidFrame)
    );
    assert_eq!(old_writer.0, 0);
    assert_eq!(
        write_bounded_frame(&mut old_writer, &frame),
        Err(HaError::InvalidFrame)
    );
    let mut wrong_version = frame;
    wrong_version[..5].copy_from_slice(b"HBFS2");
    assert_eq!(
        native.write(&mut CountWriter::default(), &wrong_version),
        Err(HaError::InvalidFrame)
    );
}

#[test]
fn native_index_transport_keeps_request_bound_and_strict_alpn() {
    let exact = inner(NATIVE_INDEX_REQUEST_MAGIC, MAX_NATIVE_INDEX_REQUEST_BYTES);
    assert_eq!(
        ResponseFrameProfile::for_request(&exact),
        Ok(ResponseFrameProfile::NativeIndexV1)
    );
    let mut oversized = inner(
        NATIVE_INDEX_REQUEST_MAGIC,
        MAX_NATIVE_INDEX_REQUEST_BYTES + 1,
    );
    assert_eq!(
        ResponseFrameProfile::for_request(&oversized),
        Err(HaError::InvalidFrame)
    );
    oversized.truncate(10);
    assert_eq!(
        ResponseFrameProfile::for_request(&oversized),
        Err(HaError::InvalidFrame)
    );
    assert_eq!(
        ResponseFrameProfile::for_request(NATIVE_INDEX_REQUEST_MAGIC),
        Err(HaError::InvalidFrame)
    );
    let native = ResponseFrameProfile::NativeIndexV1;
    assert_eq!(native.require_alpn(Some(RAFT_ALPN_PROTOCOL)), Ok(()));
    assert_eq!(
        native.require_alpn(None),
        Err(HaError::PeerAuthenticationFailed)
    );
    assert_eq!(
        native.require_alpn(Some(b"http/1.1")),
        Err(HaError::PeerAuthenticationFailed)
    );
    assert_eq!(
        ResponseFrameProfile::Legacy.require_alpn(None),
        Ok(()),
        "legacy exception contract is not changed"
    );
}

#[test]
fn native_index_transport_enforces_exact_wire_limit_before_allocation_or_write() {
    let profile = ResponseFrameProfile::NativeIndexV1;
    for length in [
        0_u32,
        9,
        (MAX_NATIVE_INDEX_RESPONSE_FRAME_BYTES + 1) as u32,
        u32::MAX,
    ] {
        let mut reader = Cursor::new(length.to_be_bytes());
        assert_eq!(profile.read(&mut reader), Err(HaError::InvalidFrame));
        assert_eq!(reader.position(), 4);
    }
    for (magic, declared_json) in [
        (b"HBFS2", 1024_u32),
        (NATIVE_INDEX_RESPONSE_MAGIC, 1023_u32),
    ] {
        let mut header = (1024_u32 + 9).to_be_bytes().to_vec();
        header.extend_from_slice(magic);
        header.extend_from_slice(&declared_json.to_be_bytes());
        let mut reader = Cursor::new(header);
        assert_eq!(profile.read(&mut reader), Err(HaError::InvalidFrame));
        assert_eq!(
            reader.position(),
            13,
            "bad inner version/length is refused without body I/O"
        );
    }
    let mut exact = inner(
        NATIVE_INDEX_RESPONSE_MAGIC,
        MAX_NATIVE_INDEX_RESPONSE_FRAME_BYTES,
    );
    let mut written = CountWriter::default();
    assert_eq!(profile.write(&mut written, &exact), Ok(()));
    assert_eq!(written.0, 4 + MAX_NATIVE_INDEX_RESPONSE_FRAME_BYTES);
    let length = (exact.len() as u32).to_be_bytes();
    let read = profile
        .read(&mut Cursor::new(length).chain(Cursor::new(&exact)))
        .unwrap();
    assert_eq!(read, exact);
    drop(read);
    exact.push(b' ');
    let length = (exact.len() - 9) as u32;
    exact[5..9].copy_from_slice(&length.to_be_bytes());
    let mut refused = CountWriter::default();
    assert_eq!(
        profile.write(&mut refused, &exact),
        Err(HaError::InvalidFrame)
    );
    assert_eq!(refused.0, 0);
}

#[test]
fn native_index_transport_original_expired_deadline_refuses_before_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let peer = NodeId::parse("native-index-peer").unwrap();
    let transport = MutualTlsPeerTransport::new(
        BTreeMap::from([(
            peer.clone(),
            TlsPeerEndpoint::new(listener.local_addr().unwrap(), "localhost").unwrap(),
        )]),
        Arc::new(tls),
        Duration::from_secs(8),
    )
    .unwrap();
    assert_eq!(
        transport.exchange_before(&peer, &q9(), Instant::now()),
        Err(HaError::Transport)
    );
    assert!(
        listener
            .accept()
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
    );
}

#[cfg(unix)]
mod real_mtls {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use std::io::BufReader;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::thread;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct Root(std::path::PathBuf);
    impl Root {
        fn new() -> io::Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "hb-native-index-tls-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).create(&path)?;
            Ok(Self(path))
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn openssl(path: &Path, args: &[&str]) -> TestResult {
        if !Command::new("openssl")
            .current_dir(path)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success()
        {
            return Err("disposable native-index TLS generation failed".into());
        }
        Ok(())
    }
    fn certificates(path: &Path) -> TestResult<Vec<CertificateDer<'static>>> {
        Ok(
            rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
                .collect::<Result<Vec<_>, _>>()?,
        )
    }
    fn private_key(path: &Path) -> TestResult<PrivateKeyDer<'static>> {
        rustls_pemfile::private_key(&mut BufReader::new(File::open(path)?))?
            .ok_or_else(|| "disposable TLS key missing".into())
    }
    struct TlsFixture {
        client: Arc<ClientConfig>,
        server: Arc<ServerConfig>,
        client_pin: [u8; 32],
    }
    fn tls_fixture(path: &Path) -> TestResult<TlsFixture> {
        openssl(
            path,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-keyout",
                "ca.key",
                "-out",
                "ca.crt",
                "-subj",
                "/CN=NativeIndexFixtureCA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        )?;
        for name in ["client", "server"] {
            openssl(
                path,
                &[
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    &format!("{name}.key"),
                    "-out",
                    &format!("{name}.csr"),
                    "-subj",
                    &format!("/CN={name}"),
                ],
            )?;
            fs::set_permissions(
                path.join(format!("{name}.key")),
                fs::Permissions::from_mode(0o600),
            )?;
            fs::write(
                path.join(format!("{name}.ext")),
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth,serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n",
            )?;
            openssl(
                path,
                &[
                    "x509",
                    "-req",
                    "-in",
                    &format!("{name}.csr"),
                    "-CA",
                    "ca.crt",
                    "-CAkey",
                    "ca.key",
                    "-CAcreateserial",
                    "-out",
                    &format!("{name}.crt"),
                    "-days",
                    "2",
                    "-sha256",
                    "-extfile",
                    &format!("{name}.ext"),
                ],
            )?;
        }
        fs::set_permissions(path.join("ca.key"), fs::Permissions::from_mode(0o600))?;
        let mut roots = RootCertStore::empty();
        roots.add(certificates(&path.join("ca.crt"))?[0].clone())?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client_chain = certificates(&path.join("client.crt"))?;
        let client_pin = sha256(client_chain[0].as_ref());
        let mut client = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(client_chain, private_key(&path.join("client.key"))?)?;
        client.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];
        let mut server = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots),
                    provider,
                )
                .build()?,
            )
            .with_single_cert(
                certificates(&path.join("server.crt"))?,
                private_key(&path.join("server.key"))?,
            )?;
        server.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];
        Ok(TlsFixture {
            client: Arc::new(client),
            server: Arc::new(server),
            client_pin,
        })
    }

    #[test]
    fn native_index_transport_actual_mtls_large_reply_and_old_receiver_refuses_once() -> TestResult
    {
        let root = Root::new()?;
        let tls = tls_fixture(&root.0)?;
        let client_peer = NodeId::parse("native-index-client")?;
        let server_peer = NodeId::parse("native-index-server")?;
        let expected = inner(NATIVE_INDEX_RESPONSE_MAGIC, 2 * 1024 * 1024 + 97);
        for legacy_receiver in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            let address = listener.local_addr()?;
            let identities = PinnedClientCertificateMap::new(BTreeMap::from([(
                tls.client_pin,
                client_peer.clone(),
            )]))?;
            let server = tls.server.clone();
            let handler_calls = Arc::new(AtomicUsize::new(0));
            let calls = handler_calls.clone();
            let reply = expected.clone();
            let expected_peer = client_peer.clone();
            let worker = thread::spawn(move || {
                let until = Instant::now() + Duration::from_secs(8);
                // Nonblocking listener polling follows the product worker's
                // existing accept lifecycle. It never resends a client request.
                loop {
                    let result = if legacy_receiver {
                        serve_one_mtls_peer_frame_with_origin(
                            &listener,
                            server.clone(),
                            &identities,
                            Duration::from_secs(8),
                            false,
                            |_, _, _| {
                                calls.fetch_add(1, Ordering::SeqCst);
                                Ok(reply.clone())
                            },
                        )
                    } else {
                        serve_one_mtls_authenticated_peer_frame(
                            &listener,
                            server.clone(),
                            &identities,
                            Duration::from_secs(8),
                            false,
                            |admitted| {
                                calls.fetch_add(1, Ordering::SeqCst);
                                if admitted.peer() != &expected_peer
                                    || !admitted.has_strict_raft_alpn()
                                    || admitted.payload() != q9()
                                {
                                    return Err(HaError::PeerAuthenticationFailed);
                                }
                                Ok(reply.clone())
                            },
                        )
                    };
                    if result != Err(HaError::Transport)
                        || calls.load(Ordering::SeqCst) != 0
                        || Instant::now() >= until
                    {
                        return (result, listener);
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            });
            let transport = MutualTlsPeerTransport::new(
                BTreeMap::from([(
                    server_peer.clone(),
                    TlsPeerEndpoint::new(address, "localhost")?,
                )]),
                tls.client.clone(),
                Duration::from_secs(8),
            )?;
            let result = transport.exchange_before(
                &server_peer,
                &q9(),
                Instant::now() + Duration::from_secs(8),
            );
            let (served, listener) = worker.join().map_err(|_| "native index receiver panic")?;
            if legacy_receiver {
                assert!(result.is_err());
                assert_eq!(served, Err(HaError::InvalidFrame));
                assert_eq!(
                    handler_calls.load(Ordering::SeqCst),
                    0,
                    "old receiver refuses Q9 before application dispatch"
                );
            } else {
                assert_eq!(served, Ok(()));
                assert_eq!(result?, expected);
                assert_eq!(handler_calls.load(Ordering::SeqCst), 1);
            }
            assert!(
                listener
                    .accept()
                    .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock),
                "failed negotiation must not cause a second connection/version fallback"
            );
        }
        Ok(())
    }

    #[test]
    fn native_kv2_write_transport_actual_mtls_once_old_receiver_and_unpinned_peer_refuse()
    -> TestResult {
        let root = Root::new()?;
        let tls = tls_fixture(&root.0)?;
        let client_peer = NodeId::parse("native-write-client")?;
        let server_peer = NodeId::parse("native-write-server")?;
        let request = inner(NATIVE_KV2_WRITE_REQUEST_MAGIC, 2 * 1024 * 1024 + 97);
        let expected = inner(NATIVE_INDEX_RESPONSE_MAGIC, 2 * 1024 * 1024 + 73);
        for case in 0..3 {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            let address = listener.local_addr()?;
            let mut client_pin = tls.client_pin;
            if case == 2 {
                client_pin[0] ^= 1;
            }
            let identities = PinnedClientCertificateMap::new(BTreeMap::from([(
                client_pin,
                client_peer.clone(),
            )]))?;
            let server = tls.server.clone();
            let handler_calls = Arc::new(AtomicUsize::new(0));
            let calls = handler_calls.clone();
            let reply = expected.clone();
            let expected_request = request.clone();
            let expected_peer = client_peer.clone();
            let worker = thread::spawn(move || {
                let until = Instant::now() + Duration::from_secs(8);
                loop {
                    let result = if case == 1 {
                        serve_one_mtls_peer_frame_with_origin(
                            &listener,
                            server.clone(),
                            &identities,
                            Duration::from_secs(8),
                            false,
                            |_, _, _| {
                                calls.fetch_add(1, Ordering::SeqCst);
                                Ok(reply.clone())
                            },
                        )
                    } else {
                        serve_one_mtls_authenticated_peer_frame(
                            &listener,
                            server.clone(),
                            &identities,
                            Duration::from_secs(8),
                            false,
                            |admitted| {
                                calls.fetch_add(1, Ordering::SeqCst);
                                if admitted.peer() != &expected_peer
                                    || !admitted.has_strict_raft_alpn()
                                    || admitted.payload() != expected_request.as_slice()
                                {
                                    return Err(HaError::PeerAuthenticationFailed);
                                }
                                Ok(reply.clone())
                            },
                        )
                    };
                    if result != Err(HaError::Transport)
                        || calls.load(Ordering::SeqCst) != 0
                        || Instant::now() >= until
                    {
                        return (result, listener);
                    }
                    // Only accept readiness is polled; no client request is resent.
                    thread::sleep(Duration::from_millis(1));
                }
            });
            let transport = MutualTlsPeerTransport::new(
                BTreeMap::from([(
                    server_peer.clone(),
                    TlsPeerEndpoint::new(address, "localhost")?,
                )]),
                tls.client.clone(),
                Duration::from_secs(8),
            )?;
            let result = transport.exchange_before(
                &server_peer,
                &request,
                Instant::now() + Duration::from_secs(8),
            );
            let (served, listener) = worker.join().map_err(|_| "native write receiver panic")?;
            match case {
                0 => {
                    assert_eq!(served, Ok(()));
                    assert!(result? == expected);
                    assert_eq!(handler_calls.load(Ordering::SeqCst), 1);
                }
                1 => {
                    assert!(result.is_err());
                    assert_eq!(served, Err(HaError::InvalidFrame));
                    assert_eq!(handler_calls.load(Ordering::SeqCst), 0);
                }
                _ => {
                    assert!(result.is_err());
                    assert_eq!(served, Err(HaError::PeerAuthenticationFailed));
                    assert_eq!(handler_calls.load(Ordering::SeqCst), 0);
                }
            }
            assert!(
                listener
                    .accept()
                    .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock),
                "a refused profile or peer never triggers a second connection or fallback"
            );
        }
        Ok(())
    }
}
