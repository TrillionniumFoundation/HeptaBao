//! Actual rustls/TCP component sources, separate from native Service qualification.
//! These use the existing disposable OpenSSL fixture style and existing eight
//! second transport bound. No product process, repository or external peer is used.

#![cfg(unix)]

use super::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::fs::{self, File};
use std::io::BufReader;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Root(std::path::PathBuf);
impl Root {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "hb-native-snapshot-stream-tls-{}-{}",
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
        return Err("disposable snapshot TLS generation failed".into());
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
    server_pin: [u8; 32],
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
    roots.add(certificates(&path.join("ca.crt"))?.first().ok_or("CA chain empty")?.clone())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_chain = certificates(&path.join("client.crt"))?;
    let client_pin = sha256(client_chain.first().ok_or("client chain empty")?.as_ref());
    let mut client = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots.clone())
        .with_client_auth_cert(client_chain, private_key(&path.join("client.key"))?)?;
    client.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];
    let server_chain = certificates(&path.join("server.crt"))?;
    let server_pin = sha256(server_chain.first().ok_or("server chain empty")?.as_ref());
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
            server_chain,
            private_key(&path.join("server.key"))?,
        )?;
    server.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];
    Ok(TlsFixture {
        client: Arc::new(client),
        server: Arc::new(server),
        client_pin,
        server_pin,
    })
}


const TEST_TIMEOUT: Duration = Duration::from_secs(8);

fn serve_snapshot_once<F>(
    listener: TcpListener,
    server: Arc<ServerConfig>,
    identities: PinnedClientCertificateMap,
    client_done: Arc<AtomicBool>,
    handler: F,
) -> (Result<(), HaError>, TcpListener)
where
    F: FnOnce(AuthenticatedSnapshotPeer<'_>) -> Result<(), HaError>,
{
    let until = Instant::now() + TEST_TIMEOUT;
    let mut handler = Some(handler);
    loop {
        let result = serve_one_mtls_peer_frame_or_snapshot(
            &listener,
            server.clone(),
            &identities,
            TEST_TIMEOUT,
            false,
            (
                |_| Err(HaError::InvalidFrame),
                |peer| handler.take().ok_or(HaError::InvalidFrame)?(peer),
            ),
        );
        if handler.is_none()
            || result != Err(HaError::Transport)
            || client_done.load(Ordering::SeqCst)
            || Instant::now() >= until
        {
            return (result, listener);
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn identity_map(fixture: &TlsFixture) -> TestResult<PinnedClientCertificateMap> {
    Ok(PinnedClientCertificateMap::new(BTreeMap::from([(
        fixture.client_pin,
        NodeId::parse("snapshot-client")?,
    )]))?)
}

fn selected_transport(
    fixture: &TlsFixture,
    listener: &TcpListener,
) -> TestResult<(MutualTlsPeerTransport, NodeId)> {
    let peer = NodeId::parse("snapshot-leader")?;
    let transport = MutualTlsPeerTransport::new(
        BTreeMap::from([(
            peer.clone(),
            TlsPeerEndpoint::new(listener.local_addr()?, "localhost")?,
        )]),
        fixture.client.clone(),
        TEST_TIMEOUT,
    )?;
    Ok((transport, peer))
}

#[test]
fn snapshot_peer_actual_mtls_upload_close_notify_allows_opposite_download() -> TestResult {
    let root = Root::new()?;
    let fixture = tls_fixture(&root.0)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let identities = identity_map(&fixture)?;
    let (transport, target) = selected_transport(&fixture, &listener)?;
    let source = vec![0x31_u8; 1024 * 1024 + 19];
    let response = vec![0x52_u8; 1024 * 1024 + 37];
    let expected_source = source.clone();
    let expected_response = response.clone();
    let pins = [fixture.server_pin];
    let limits = SnapshotBodyLimits::new(2 * 1024 * 1024)?;
    let request = SnapshotPeerRequest::new(
        b"public synthetic request metadata",
        &pins,
        (limits, limits),
        Instant::now() + TEST_TIMEOUT,
    )?;
    let done = Arc::new(AtomicBool::new(false));
    let server_done = done.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let server_calls = calls.clone();
    let server = fixture.server.clone();
    let worker = thread::spawn(move || {
        serve_snapshot_once(listener, server, identities, server_done, |mut peer| {
            server_calls.fetch_add(1, Ordering::SeqCst);
            if peer.peer().as_str() != "snapshot-client"
                || peer.metadata() != b"public synthetic request metadata"
            {
                return Err(HaError::InvalidFrame);
            }
            let (parsed, verified) = peer.accept_body(limits, |reader| {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).map(|_| bytes)
            })?;
            let parsed = parsed.map_err(|_| HaError::Transport)?;
            if parsed != expected_source
                || verified.bytes() != parsed.len() as u64
                || verified.sha256() != sha256(&parsed)
                || verified.frames() != 17
            {
                return Err(HaError::InvalidFrame);
            }
            // accept_body could return only after actual rustls close-notify.
            // This opposite-direction application write must still succeed.
            let mut response = io::Cursor::new(expected_response);
            let encoded = peer.complete(
                200,
                b"public synthetic completion metadata",
                &mut response,
                limits,
            )?;
            if encoded.bytes() != response.get_ref().len() as u64
                || encoded.sha256() != sha256(response.get_ref())
            {
                return Err(HaError::InvalidFrame);
            }
            Ok(())
        })
    });
    let mut received = Vec::new();
    let result = transport.exchange_snapshot_before(
        &target,
        request,
        &mut io::Cursor::new(&source),
        &mut received,
    );
    done.store(true, Ordering::SeqCst);
    let (served, listener) = worker.join().map_err(|_| "snapshot receiver panic")?;
    assert_eq!(served, Ok(()));
    let result = result?;
    assert_eq!(result.status(), 200);
    assert_eq!(result.metadata(), b"public synthetic completion metadata");
    assert_eq!(result.request_body().ok_or("request END missing")?.sha256(), sha256(&source));
    assert_eq!(result.response_body().ok_or("response END missing")?.sha256(), sha256(&response));
    assert_eq!(received, response);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(listener.accept().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

#[test]
fn snapshot_peer_actual_mtls_bare_tcp_eof_cannot_finalize_upload() -> TestResult {
    let root = Root::new()?;
    let fixture = tls_fixture(&root.0)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let identities = identity_map(&fixture)?;
    let done = Arc::new(AtomicBool::new(false));
    let server_done = done.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let server_calls = calls.clone();
    let finalized = Arc::new(AtomicUsize::new(0));
    let server_finalized = finalized.clone();
    let server = fixture.server.clone();
    let limits = SnapshotBodyLimits::new(1024)?;
    let worker = thread::spawn(move || {
        serve_snapshot_once(listener, server, identities, server_done, |mut peer| {
            server_calls.fetch_add(1, Ordering::SeqCst);
            let (parsed, _) = peer.accept_body(limits, |reader| {
                io::copy(reader, &mut io::sink())
            })?;
            parsed.map_err(|_| HaError::Transport)?;
            server_finalized.fetch_add(1, Ordering::SeqCst);
            peer.complete(204, b"completion", &mut io::empty(), limits)?;
            Ok(())
        })
    });
    let result = (|| -> TestResult {
        let deadline = Instant::now() + TEST_TIMEOUT;
        let stream = TcpStream::connect_timeout(&address, TEST_TIMEOUT)?;
        let connection = rustls::ClientConnection::new(
            fixture.client.clone(),
            rustls::pki_types::ServerName::try_from("localhost")?,
        )?;
        let mut tls = rustls::StreamOwned::new(
            connection,
            ForwardDeadlineStream { stream, deadline },
        );
        tls.conn.complete_io(&mut tls.sock)?;
        assert_eq!(tls.conn.alpn_protocol(), Some(RAFT_ALPN_PROTOCOL));
        exact_write(&mut tls, STREAM_PREFIX, deadline)?;
        exact_write(&mut tls, STREAM_VERSION, deadline)?;
        exact_write(&mut tls, &8_000_000_000_u64.to_be_bytes(), deadline)?;
        metadata_write(&mut tls, b"public synthetic request", deadline)?;
        flush_before(&mut tls, deadline)?;
        let mut decision = [0_u8; 1];
        exact_read(&mut tls, &mut decision, deadline)?;
        assert_eq!(decision, [READY]);
        encode_snapshot_body(&mut io::Cursor::new(b"archive"), &mut tls, limits, deadline)?;
        tls.sock.stream.shutdown(std::net::Shutdown::Write)?;
        // Deliberately omit close-notify. The server must not treat the valid
        // END frame plus TCP FIN as authenticated upload completion.
        Ok(())
    })();
    done.store(true, Ordering::SeqCst);
    let (served, listener) = worker.join().map_err(|_| "snapshot receiver panic")?;
    result?;
    assert_eq!(served, Err(HaError::Transport));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(finalized.load(Ordering::SeqCst), 0);
    assert!(listener.accept().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

#[test]
fn snapshot_peer_actual_mtls_wrong_selected_leaf_never_admits_body() -> TestResult {
    let root = Root::new()?;
    let fixture = tls_fixture(&root.0)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let identities = identity_map(&fixture)?;
    let (transport, target) = selected_transport(&fixture, &listener)?;
    let mut wrong = fixture.server_pin;
    wrong[0] ^= 1;
    let pins = [wrong];
    let limits = SnapshotBodyLimits::new(1024)?;
    let request = SnapshotPeerRequest::new(
        b"synthetic token metadata must not reach handler",
        &pins,
        (limits, limits),
        Instant::now() + TEST_TIMEOUT,
    )?;
    let done = Arc::new(AtomicBool::new(false));
    let server_done = done.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let server_calls = calls.clone();
    let server = fixture.server.clone();
    let worker = thread::spawn(move || {
        serve_snapshot_once(listener, server, identities, server_done, |peer| {
            server_calls.fetch_add(1, Ordering::SeqCst);
            peer.reject(403, b"must not reach handler")
        })
    });
    let mut source = io::Cursor::new(b"never sent");
    let mut sink = Vec::new();
    let result = transport.exchange_snapshot_before(&target, request, &mut source, &mut sink);
    done.store(true, Ordering::SeqCst);
    let (served, listener) = worker.join().map_err(|_| "snapshot receiver panic")?;
    assert!(matches!(result, Err(HaError::PeerAuthenticationFailed)));
    assert_eq!(served, Err(HaError::Transport));
    assert_eq!(source.position(), 0);
    assert!(sink.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(listener.accept().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

#[test]
fn snapshot_peer_actual_mtls_terminal_rejection_consumes_no_upload() -> TestResult {
    let root = Root::new()?;
    let fixture = tls_fixture(&root.0)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let identities = identity_map(&fixture)?;
    let (transport, target) = selected_transport(&fixture, &listener)?;
    let pins = [fixture.server_pin];
    let limits = SnapshotBodyLimits::new(1024)?;
    let request = SnapshotPeerRequest::new(
        b"public synthetic request",
        &pins,
        (limits, limits),
        Instant::now() + TEST_TIMEOUT,
    )?;
    let done = Arc::new(AtomicBool::new(false));
    let server_done = done.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let server_calls = calls.clone();
    let server = fixture.server.clone();
    let worker = thread::spawn(move || {
        serve_snapshot_once(listener, server, identities, server_done, |peer| {
            server_calls.fetch_add(1, Ordering::SeqCst);
            peer.reject(403, b"native denial metadata")
        })
    });
    let mut upload = io::Cursor::new(b"never uploaded");
    let mut response = Vec::new();
    let result = transport.exchange_snapshot_before(&target, request, &mut upload, &mut response);
    done.store(true, Ordering::SeqCst);
    let (served, listener) = worker.join().map_err(|_| "snapshot receiver panic")?;
    assert_eq!(served, Ok(()));
    let result = result?;
    assert_eq!(result.status(), 403);
    assert_eq!(result.metadata(), b"native denial metadata");
    assert!(result.request_body().is_none());
    assert!(result.response_body().is_none());
    assert_eq!(upload.position(), 0);
    assert!(response.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(listener.accept().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

#[test]
fn snapshot_peer_original_frame_still_uses_only_old_callback() -> TestResult {
    let root = Root::new()?;
    let fixture = tls_fixture(&root.0)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let identities = identity_map(&fixture)?;
    let (transport, target) = selected_transport(&fixture, &listener)?;
    let done = Arc::new(AtomicBool::new(false));
    let server_done = done.clone();
    let old_calls = Arc::new(AtomicUsize::new(0));
    let server_calls = old_calls.clone();
    let new_calls = Arc::new(AtomicUsize::new(0));
    let snapshot_calls = new_calls.clone();
    let server = fixture.server.clone();
    let worker = thread::spawn(move || {
        let until = Instant::now() + TEST_TIMEOUT;
        loop {
            let result = serve_one_mtls_peer_frame_or_snapshot(
                &listener,
                server.clone(),
                &identities,
                TEST_TIMEOUT,
                false,
                (
                    |frame| {
                        server_calls.fetch_add(1, Ordering::SeqCst);
                        if frame.payload() != b"legacy request" {
                            return Err(HaError::InvalidFrame);
                        }
                        Ok(b"legacy response".to_vec())
                    },
                    |_| {
                        snapshot_calls.fetch_add(1, Ordering::SeqCst);
                        Err(HaError::InvalidFrame)
                    },
                ),
            );
            if result != Err(HaError::Transport)
                || server_calls.load(Ordering::SeqCst) != 0
                || server_done.load(Ordering::SeqCst)
                || Instant::now() >= until
            {
                return (result, listener);
            }
            thread::sleep(Duration::from_millis(1));
        }
    });
    let result = transport.exchange_before(
        &target,
        b"legacy request",
        Instant::now() + TEST_TIMEOUT,
    );
    done.store(true, Ordering::SeqCst);
    let (served, listener) = worker.join().map_err(|_| "legacy receiver panic")?;
    assert_eq!(served, Ok(()));
    assert_eq!(result?, b"legacy response");
    assert_eq!(old_calls.load(Ordering::SeqCst), 1);
    assert_eq!(new_calls.load(Ordering::SeqCst), 0);
    assert!(listener.accept().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

#[test]
fn snapshot_peer_expired_deadline_refuses_before_connect() -> TestResult {
    let pins = [[7_u8; 32]];
    let limits = SnapshotBodyLimits::new(0)?;
    let result = SnapshotPeerRequest::new(b"request", &pins, (limits, limits), Instant::now());
    assert!(matches!(result, Err(HaError::Transport)));
    Ok(())
}
