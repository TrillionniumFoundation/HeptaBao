use super::*;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, Error, ServerConnection,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(super) fn tls_identity() -> TestResult<(
    CertificateDer<'static>,
    Vec<CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    fn key() -> TestResult<PKey<Private>> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        Ok(PKey::from_ec_key(EcKey::generate(&group)?)?)
    }
    let ca_key = key()?;
    let mut ca_name = X509NameBuilder::new()?;
    ca_name.append_entry_by_text("CN", "synthetic API ALPN test CA")?;
    let ca_name = ca_name.build();
    let mut ca = X509::builder()?;
    ca.set_version(2)?;
    let serial_number = BigNum::from_u32(1)?;
    let serial = Asn1Integer::from_bn(&serial_number)?;
    ca.set_serial_number(&serial)?;
    ca.set_subject_name(&ca_name)?;
    ca.set_issuer_name(&ca_name)?;
    ca.set_pubkey(&ca_key)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(2)?;
    ca.set_not_before(&not_before)?;
    ca.set_not_after(&not_after)?;
    ca.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    ca.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;
    ca.sign(&ca_key, MessageDigest::sha256())?;
    let ca = ca.build();

    let leaf_key = key()?;
    let mut leaf_name = X509NameBuilder::new()?;
    leaf_name.append_entry_by_text("CN", "localhost")?;
    let leaf_name = leaf_name.build();
    let mut leaf = X509::builder()?;
    leaf.set_version(2)?;
    let serial_number = BigNum::from_u32(2)?;
    let serial = Asn1Integer::from_bn(&serial_number)?;
    leaf.set_serial_number(&serial)?;
    leaf.set_subject_name(&leaf_name)?;
    leaf.set_issuer_name(ca.subject_name())?;
    leaf.set_pubkey(&leaf_key)?;
    leaf.set_not_before(&not_before)?;
    leaf.set_not_after(&not_after)?;
    leaf.append_extension(BasicConstraints::new().critical().build()?)?;
    leaf.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
    leaf.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
    leaf.append_extension(
        SubjectAlternativeName::new()
            .dns("localhost")
            .build(&leaf.x509v3_context(Some(&ca), None))?,
    )?;
    leaf.sign(&ca_key, MessageDigest::sha256())?;
    let root = CertificateDer::from(ca.to_der()?);
    let certificates = vec![CertificateDer::from(leaf.build().to_der()?), root.clone()];
    let private_key = PrivatePkcs8KeyDer::from(leaf_key.private_key_to_pkcs8()?).into();
    Ok((root, certificates, private_key))
}

// No verifier is bypassed: both peers process actual TLS records, including the
// signed certificate flight and Finished. A bounded pump fails stalled peers.
fn handshake(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), Error> {
    for _ in 0..32 {
        let mut outbound = Vec::new();
        client
            .write_tls(&mut outbound)
            .map_err(|error| Error::General(error.to_string()))?;
        assert!(outbound.len() <= 1024 * 1024, "bounded client TLS flight");
        if !outbound.is_empty() {
            let mut incoming = io::Cursor::new(outbound);
            while incoming.position() < incoming.get_ref().len() as u64 {
                let count = server
                    .read_tls(&mut incoming)
                    .map_err(|error| Error::General(error.to_string()))?;
                assert!(count > 0, "server consumes each actual client record");
                server.process_new_packets()?;
            }
        }
        let mut outbound = Vec::new();
        server
            .write_tls(&mut outbound)
            .map_err(|error| Error::General(error.to_string()))?;
        assert!(outbound.len() <= 1024 * 1024, "bounded server TLS flight");
        if !outbound.is_empty() {
            let mut incoming = io::Cursor::new(outbound);
            while incoming.position() < incoming.get_ref().len() as u64 {
                let count = client
                    .read_tls(&mut incoming)
                    .map_err(|error| Error::General(error.to_string()))?;
                assert!(count > 0, "client consumes each actual server record");
                client.process_new_packets()?;
            }
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    Err(Error::General(
        "actual TLS handshake exceeded bounded record pump".into(),
    ))
}

#[test]
fn api_tls_alpn_negotiates_supported_protocols_and_rejects_wrong_hostname() -> TestResult {
    let (root, certificates, key) = tls_identity()?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    configure_api_alpn(&mut server_config);
    let server_config = Arc::new(server_config);
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        for (offered, expected) in [
            (
                vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                Some(b"h2".as_slice()),
            ),
            (vec![b"http/1.1".to_vec()], Some(b"http/1.1".as_slice())),
            (Vec::new(), None),
        ] {
            let mut roots = RootCertStore::empty();
            roots.add(root.clone())?;
            let mut config = ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[version])?
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = offered;
            let mut client =
                ClientConnection::new(Arc::new(config), ServerName::try_from("localhost")?)?;
            let mut server = ServerConnection::new(server_config.clone())?;
            handshake(&mut client, &mut server)?;
            assert_eq!(client.protocol_version(), Some(version.version));
            assert_eq!(server.protocol_version(), Some(version.version));
            assert_eq!(client.alpn_protocol(), expected, "actual client ALPN");
            assert_eq!(server.alpn_protocol(), expected, "actual server ALPN");

            // Complete authenticated application delivery, not only ClientHello
            // inspection. HTTP/2 request dispatch remains a browser control.
            let payload = b"synthetic authenticated application record";
            client.writer().write_all(payload)?;
            let mut wire = Vec::new();
            client.write_tls(&mut wire)?;
            assert!(!wire.is_empty() && !wire.windows(payload.len()).any(|part| part == payload));
            let mut incoming = io::Cursor::new(wire);
            while incoming.position() < incoming.get_ref().len() as u64 {
                assert!(server.read_tls(&mut incoming)? > 0);
                server.process_new_packets()?;
            }
            let mut plaintext = vec![0; payload.len()];
            server.reader().read_exact(&mut plaintext)?;
            assert_eq!(plaintext, payload);
        }
        for (hostname, offered, wrong_hostname) in [
            ("localhost", vec![b"h3".to_vec()], false),
            (
                "wrong.example",
                vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                true,
            ),
        ] {
            let mut roots = RootCertStore::empty();
            roots.add(root.clone())?;
            let mut config = ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[version])?
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = offered;
            let mut client =
                ClientConnection::new(Arc::new(config), ServerName::try_from(hostname)?)?;
            let mut server = ServerConnection::new(server_config.clone())?;
            let error = handshake(&mut client, &mut server)
                .err()
                .ok_or("negative real TLS handshake must fail")?;
            if wrong_hostname {
                assert!(
                    matches!(
                        &error,
                        Error::InvalidCertificate(
                            CertificateError::NotValidForName
                                | CertificateError::NotValidForNameContext { .. }
                        )
                    ),
                    "wrong hostname must fail actual certificate-name verification: {error:?}"
                );
            } else {
                assert_eq!(error, Error::NoApplicationProtocol);
            }
        }
    }
    Ok(())
}
