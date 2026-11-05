use super::*;
use base64::Engine;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::os::unix::fs::PermissionsExt;
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn request_reload(resolver: &LeafResolver) -> TestResult {
    let before = resolver.completed.load(Ordering::Acquire);
    resolver.requested.store(true, Ordering::Release);
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while resolver.completed.load(Ordering::Acquire) == before {
        if std::time::Instant::now() >= deadline {
            return Err("independent TLS leaf reload did not complete".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

struct Files(PathBuf);
impl Files {
    fn new() -> TestResult<Self> {
        let path = std::env::temp_dir().join(format!(
            "heptabao-tls-reload-{}-{}",
            std::process::id(),
            crate::test_support::random_ascii(24).as_str()
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }
    fn cert(&self) -> PathBuf {
        self.0.join("leaf.pem")
    }
    fn key(&self) -> PathBuf {
        self.0.join("key.pem")
    }
    fn write_pair(
        &self,
        certificates: &[CertificateDer<'static>],
        key: &PrivateKeyDer<'static>,
    ) -> TestResult {
        let mut certs = Zeroizing::new(String::new());
        for cert in certificates {
            certs.push_str(&pem("CERTIFICATE", cert.as_ref()));
        }
        fs::write(self.cert(), certs.as_bytes())?;
        let key = pem("PRIVATE KEY", key.secret_der());
        fs::write(self.key(), key.as_bytes())?;
        fs::set_permissions(self.key(), fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn pem(label: &str, bytes: &[u8]) -> Zeroizing<String> {
    let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(bytes));
    let mut out = Zeroizing::new(format!("-----BEGIN {label}-----\n"));
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn handshake(
    config: Arc<ServerConfig>,
    roots: &[CertificateDer<'static>],
    provider: Arc<CryptoProvider>,
) -> TestResult<(ClientConnection, ServerConnection)> {
    let mut trusted = RootCertStore::empty();
    for cert in roots {
        trusted.add(cert.clone())?;
    }
    let client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(trusted)
        .with_no_client_auth();
    let mut client = ClientConnection::new(Arc::new(client), "localhost".try_into()?)?;
    let mut server = ServerConnection::new(config)?;
    for _ in 0..32 {
        let mut flight = Vec::new();
        client.write_tls(&mut flight)?;
        assert!(flight.len() <= 1024 * 1024);
        if !flight.is_empty() {
            server.read_tls(&mut Cursor::new(flight))?;
            server.process_new_packets()?;
        }
        let mut flight = Vec::new();
        server.write_tls(&mut flight)?;
        assert!(flight.len() <= 1024 * 1024);
        if !flight.is_empty() {
            client.read_tls(&mut Cursor::new(flight))?;
            client.process_new_packets()?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok((client, server));
        }
    }
    Err("TLS leaf reload handshake exceeded original bounded pump".into())
}

#[test]
fn reload_flag_rotates_leaf_on_the_same_server_config_without_changing_existing_connection()
-> TestResult {
    let files = Files::new()?;
    let (root_a, cert_a, key_a) = super::super::api_alpn_tests::tls_identity()?;
    let (root_b, cert_b, key_b) = super::super::api_alpn_tests::tls_identity()?;
    let provider = Arc::new(crate::tls_key_exchange::provider(None)?);
    files.write_pair(&cert_a, &key_a)?;
    let resolver = LeafResolver::new(
        files.cert(),
        files.key(),
        cert_a.clone(),
        key_a,
        Arc::clone(&provider),
    )?;
    let config = Arc::new(
        ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone()),
    );
    let roots = [root_a, root_b];
    let (mut original, mut original_server) =
        handshake(Arc::clone(&config), &roots, Arc::clone(&provider))?;
    assert_eq!(
        original
            .peer_certificates()
            .ok_or("missing original peer")?[0],
        cert_a[0]
    );
    files.write_pair(&cert_b, &key_b)?;
    // File changes alone never request publication of a replacement TLS key.
    let (unchanged, _) = handshake(Arc::clone(&config), &roots, Arc::clone(&provider))?;
    assert_eq!(
        unchanged
            .peer_certificates()
            .ok_or("missing unchanged peer")?[0],
        cert_a[0]
    );
    request_reload(&resolver)?;
    let (rotated, _) = handshake(Arc::clone(&config), &roots, provider)?;
    assert_eq!(
        rotated.peer_certificates().ok_or("missing rotated peer")?[0],
        cert_b[0]
    );
    assert_eq!(
        original
            .peer_certificates()
            .ok_or("existing connection lost its peer")?[0],
        cert_a[0]
    );
    // The prior server endpoint remains alive and accepts actual encrypted
    // application data after the newly selected leaf has been published.
    let message = b"application data on the established pre-reload connection";
    original.writer().write_all(message)?;
    let mut records = Vec::new();
    original.write_tls(&mut records)?;
    original_server.read_tls(&mut Cursor::new(records))?;
    original_server.process_new_packets()?;
    let mut received = vec![0; message.len()];
    original_server.reader().read_exact(&mut received)?;
    assert_eq!(received, message);
    Ok(())
}

#[test]
fn malformed_mismatched_and_publicly_readable_reload_keys_retain_the_prior_leaf_and_allow_explicit_rollback()
-> TestResult {
    let files = Files::new()?;
    let (root_a, cert_a, key_a) = super::super::api_alpn_tests::tls_identity()?;
    let (root_b, cert_b, key_b) = super::super::api_alpn_tests::tls_identity()?;
    let provider = Arc::new(crate::tls_key_exchange::provider(None)?);
    files.write_pair(&cert_a, &key_a)?;
    let resolver = LeafResolver::new(
        files.cert(),
        files.key(),
        cert_a.clone(),
        key_a.clone_key(),
        Arc::clone(&provider),
    )?;
    let config = Arc::new(
        ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone()),
    );
    for defect in 0..3 {
        match defect {
            0 => fs::write(files.cert(), b"invalid certificate bytes")?,
            1 => files.write_pair(&cert_b, &key_a)?,
            _ => {
                files.write_pair(&cert_b, &key_b)?;
                fs::set_permissions(files.key(), fs::Permissions::from_mode(0o644))?;
            }
        }
        request_reload(&resolver)?;
        let (client, _) = handshake(
            Arc::clone(&config),
            std::slice::from_ref(&root_a),
            Arc::clone(&provider),
        )?;
        assert_eq!(
            client.peer_certificates().ok_or("prior TLS leaf lost")?[0],
            cert_a[0]
        );
    }
    files.write_pair(&cert_b, &key_b)?;
    request_reload(&resolver)?;
    let (published, _) = handshake(
        Arc::clone(&config),
        &[root_a.clone(), root_b],
        Arc::clone(&provider),
    )?;
    assert_eq!(
        published
            .peer_certificates()
            .ok_or("successful B publication absent")?[0],
        cert_b[0]
    );
    files.write_pair(&cert_a, &key_a)?;
    request_reload(&resolver)?;
    let (client, _) = handshake(config, &[root_a], provider)?;
    assert_eq!(
        client
            .peer_certificates()
            .ok_or("rollback TLS leaf absent")?[0],
        cert_a[0]
    );
    Ok(())
}

#[test]
fn concurrent_handshakes_keep_a_complete_leaf_during_background_publication() -> TestResult {
    let files = Files::new()?;
    let (root_a, cert_a, key_a) = super::super::api_alpn_tests::tls_identity()?;
    let (root_b, cert_b, key_b) = super::super::api_alpn_tests::tls_identity()?;
    let provider = Arc::new(crate::tls_key_exchange::provider(None)?);
    files.write_pair(&cert_a, &key_a)?;
    let resolver = LeafResolver::new(
        files.cert(),
        files.key(),
        cert_a.clone(),
        key_a.clone_key(),
        Arc::clone(&provider),
    )?;
    let config = Arc::new(
        ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone()),
    );
    let barrier = Arc::new(std::sync::Barrier::new(9));
    let mut children = Vec::new();
    for _ in 0..8 {
        let (config, provider, barrier) = (
            Arc::clone(&config),
            Arc::clone(&provider),
            Arc::clone(&barrier),
        );
        let roots = [root_a.clone(), root_b.clone()];
        let leaves = [cert_a[0].clone(), cert_b[0].clone()];
        children.push(std::thread::spawn(move || -> Result<(), String> {
            barrier.wait();
            for _ in 0..16 {
                let (client, _) = handshake(Arc::clone(&config), &roots, Arc::clone(&provider))
                    .map_err(|e| e.to_string())?;
                let leaf = &client
                    .peer_certificates()
                    .ok_or("missing concurrent peer")?[0];
                if !leaves.contains(leaf) {
                    return Err("unexpected concurrent peer".into());
                }
            }
            Ok(())
        }));
    }
    barrier.wait();
    files.write_pair(&cert_b, &key_b)?;
    request_reload(&resolver)?;
    files.write_pair(&cert_a, &key_a)?;
    request_reload(&resolver)?;
    for child in children {
        child
            .join()
            .map_err(|_| "concurrent TLS child panicked")??;
    }
    Ok(())
}
