use super::*;
use std::{io::{self, Read, Write}, sync::Arc};
use openssl::{
    asn1::{Asn1Integer, Asn1Time}, bn::BigNum, ec::{EcGroup, EcKey},
    hash::MessageDigest, nid::Nid, pkey::{PKey, Private},
    x509::{X509, X509NameBuilder, extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName}},
};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName}};
use aws_lc_rs::signature::{PqdsaKeyPair, PqdsaSigningAlgorithm};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn names(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn identity() -> TestResult<(CertificateDer<'static>, Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    fn key() -> TestResult<PKey<Private>> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        Ok(PKey::from_ec_key(EcKey::generate(&group)?)?)
    }
    let digest = MessageDigest::sha256();
    let ca_key = key()?;
    let mut ca_name = X509NameBuilder::new()?;
    ca_name.append_entry_by_text("CN", "synthetic PQC TLS test CA")?;
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
    ca.append_extension(KeyUsage::new().critical().key_cert_sign().crl_sign().build()?)?;
    ca.sign(&ca_key, digest)?;
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
    leaf.append_extension(SubjectAlternativeName::new().dns("localhost").build(&leaf.x509v3_context(Some(&ca), None))?)?;
    leaf.sign(&ca_key, digest)?;
    let root = CertificateDer::from(ca.to_der()?);
    let chain = vec![CertificateDer::from(leaf.build().to_der()?), root.clone()];
    let private = PrivatePkcs8KeyDer::from(leaf_key.private_key_to_pkcs8()?).into();
    Ok((root, chain, private))
}

// Synthetic certificates are DER encoded here so ML-DSA signing uses the SDK's
// pure message API, without passing an invented hash to OpenSSL X509_sign.
// The production verifier parses and authenticates the complete certificate.
fn mldsa_identity(algorithm: &'static PqdsaSigningAlgorithm, oid_tail: u8) -> TestResult<(CertificateDer<'static>, Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    use aws_lc_rs::signature::KeyPair;
    fn der(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut output = vec![tag];
        if value.len() < 128 {
            output.push(value.len() as u8);
        } else {
            let bytes = value.len().to_be_bytes();
            let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len() - 1);
            output.push(0x80 | (bytes.len() - first) as u8);
            output.extend_from_slice(&bytes[first..]);
        }
        output.extend_from_slice(value);
        output
    }
    fn sequence(values: &[Vec<u8>]) -> Vec<u8> { der(0x30, &values.concat()) }
    fn name(value: &[u8]) -> Vec<u8> {
        sequence(&[der(0x31, &sequence(&[der(6, &[0x55, 4, 3]), der(0x0c, value)]))])
    }
    fn extension(oid: &[u8], critical: bool, value: Vec<u8>) -> Vec<u8> {
        let mut parts = vec![der(6, oid)];
        if critical { parts.push(der(1, &[0xff])); }
        parts.push(der(4, &value));
        sequence(&parts)
    }
    #[allow(clippy::too_many_arguments)]
    fn certificate(
        subject: &PqdsaKeyPair, issuer: &PqdsaKeyPair, subject_name: Vec<u8>,
        issuer_name: Vec<u8>, is_ca: bool, serial: u8, algorithm: &[u8], validity: &[u8],
    ) -> TestResult<CertificateDer<'static>> {
        let mut public_bits = vec![0];
        public_bits.extend_from_slice(subject.public_key().as_ref());
        let public = sequence(&[algorithm.to_vec(), der(3, &public_bits)]);
        let constraints = if is_ca { sequence(&[der(1, &[0xff])]) } else { sequence(&[]) };
        let usage = if is_ca { der(3, &[1, 6]) } else { der(3, &[7, 0x80]) };
        let mut extensions = vec![extension(&[0x55, 0x1d, 0x13], true, constraints),
            extension(&[0x55, 0x1d, 0x0f], true, usage)];
        if !is_ca {
            extensions.push(extension(&[0x55, 0x1d, 0x25], false,
                sequence(&[der(6, &[0x2b, 6, 1, 5, 5, 7, 3, 1])])));
            extensions.push(extension(&[0x55, 0x1d, 0x11], false,
                sequence(&[der(0x82, b"localhost")])));
        }
        let tbs = sequence(&[der(0xa0, &der(2, &[2])), der(2, &[serial]), algorithm.to_vec(),
            issuer_name, validity.to_vec(), subject_name, public, der(0xa3, &sequence(&extensions))]);
        let mut signature = vec![0; issuer.algorithm().signature_len()];
        let size = issuer.sign(&tbs, &mut signature).map_err(|_| "ML-DSA certificate signing failed")?;
        assert_eq!(size, signature.len());
        let mut signature_bits = vec![0];
        signature_bits.extend_from_slice(&signature);
        Ok(CertificateDer::from(sequence(&[tbs, algorithm.to_vec(), der(3, &signature_bits)])))
    }
    let ca = PqdsaKeyPair::generate(algorithm).map_err(|_| "ML-DSA CA generation failed")?;
    let leaf = PqdsaKeyPair::generate(algorithm).map_err(|_| "ML-DSA leaf generation failed")?;
    let signature_algorithm = sequence(&[der(6, &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, oid_tail])]);
    let now = chrono::Utc::now();
    let validity = sequence(&[
        der(0x17, (now - chrono::Duration::hours(1)).format("%y%m%d%H%M%SZ").to_string().as_bytes()),
        der(0x17, (now + chrono::Duration::days(2)).format("%y%m%d%H%M%SZ").to_string().as_bytes()),
    ]);
    let ca_name = name(b"synthetic ML-DSA TLS CA");
    let root = certificate(&ca, &ca, ca_name.clone(), ca_name.clone(), true, 1, &signature_algorithm, &validity)?;
    let leaf_cert = certificate(&leaf, &ca, name(b"localhost"), ca_name, false, 2, &signature_algorithm, &validity)?;
    let pkcs8 = leaf.to_pkcs8v1().map_err(|_| "ML-DSA leaf PKCS8 failed")?;
    let key = PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec()).into();
    // Parsing is an additional fixture shape check, not a replacement for TLS's
    // real chain, certificate signature and Finished verification.
    assert!(x509_parser::parse_x509_certificate(root.as_ref())?.1.tbs_certificate.is_ca());
    assert!(!x509_parser::parse_x509_certificate(leaf_cert.as_ref())?.1.tbs_certificate.is_ca());
    Ok((root.clone(), vec![leaf_cert, root], key))
}

fn handshake(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), Error> {
    for _ in 0..32 {
        let mut wire = Vec::new();
        client.write_tls(&mut wire).map_err(|error| Error::General(error.to_string()))?;
        assert!(wire.len() <= 1024 * 1024);
        let mut input = io::Cursor::new(wire);
        while input.position() < input.get_ref().len() as u64 {
            let count = server.read_tls(&mut input).map_err(|error| Error::General(error.to_string()))?;
            assert!(count > 0);
            server.process_new_packets()?;
        }
        let mut wire = Vec::new();
        server.write_tls(&mut wire).map_err(|error| Error::General(error.to_string()))?;
        assert!(wire.len() <= 1024 * 1024);
        let mut input = io::Cursor::new(wire);
        while input.position() < input.get_ref().len() as u64 {
            let count = client.read_tls(&mut input).map_err(|error| Error::General(error.to_string()))?;
            assert!(count > 0);
            client.process_new_packets()?;
        }
        if !client.is_handshaking() && !server.is_handshaking() { return Ok(()); }
    }
    Err(Error::General("PQC TLS handshake exceeded bounded record pump".into()))
}

#[allow(clippy::too_many_arguments)]
fn pair(
    root: CertificateDer<'static>, chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>,
    client_names: &[&str], server_names: &[&str], version: &'static SupportedProtocolVersion,
    hostname: &str, alpn: &[u8],
) -> TestResult<(ClientConnection, ServerConnection)> {
    let mut roots = RootCertStore::empty();
    roots.add(root)?;
    let client_provider = Arc::new(provider(Some(&names(client_names)))?);
    let mut config = ClientConfig::builder_with_provider(client_provider)
        .with_protocol_versions(&[version])?.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    let client = ClientConnection::new(Arc::new(config), ServerName::try_from(hostname.to_owned())?)?;
    let server_provider = Arc::new(provider(Some(&names(server_names)))?);
    let mut config = ServerConfig::builder_with_provider(server_provider)
        .with_protocol_versions(&[version])?.with_no_client_auth().with_single_cert(chain, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let server = ServerConnection::new(Arc::new(config))?;
    Ok((client, server))
}

fn application_record(client: &mut ClientConnection, server: &mut ServerConnection) -> TestResult {
    let plaintext = b"synthetic PQC authenticated TLS application record";
    client.writer().write_all(plaintext)?;
    let mut wire = Vec::new();
    client.write_tls(&mut wire)?;
    assert!(!wire.is_empty() && !wire.windows(plaintext.len()).any(|window| window == plaintext));
    let mut input = io::Cursor::new(wire);
    while input.position() < input.get_ref().len() as u64 {
        assert!(server.read_tls(&mut input)? > 0);
        server.process_new_packets()?;
    }
    let mut output = vec![0; plaintext.len()];
    server.reader().read_exact(&mut output)?;
    assert_eq!(output, plaintext);
    Ok(())
}

#[test]
fn tls270_listener_config_preserves_exact_groups_order_and_tls13_bounds() -> TestResult {
    let base = serde_json::json!({
        "listen":"127.0.0.1:8200","data_dir":"/synthetic/data","audit_file":"/synthetic/audit",
        "tls_cert_file":"/synthetic/tls/cert","tls_key_file":"/synthetic/tls/key"
    });
    let mut value = base.clone();
    value["tls_key_exchange_preferences"] = serde_json::json!(["CurveP521","MLKEM1024","X25519MLKEM768"]);
    value["tls_min_version"] = "tls13".into();
    value["tls_max_version"] = "tls13".into();
    let config: crate::http::Config = serde_json::from_value(value)?;
    let actual = provider(config.tls_key_exchange_preferences.as_deref())?;
    assert_eq!(actual.kx_groups.iter().map(|group| group.name()).collect::<Vec<_>>(),
        vec![NamedGroup::secp521r1, NamedGroup::MLKEM1024, NamedGroup::X25519MLKEM768]);
    let versions = protocol_versions(config.tls_min_version.as_deref(), config.tls_max_version.as_deref())?;
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].version, ProtocolVersion::TLSv1_3);
    for preferences in [serde_json::Value::Null, serde_json::json!([])] {
        let mut value = base.clone();
        value["tls_key_exchange_preferences"] = preferences;
        let config: crate::http::Config = serde_json::from_value(value)?;
        assert_eq!(provider(config.tls_key_exchange_preferences.as_deref())?.kx_groups.len(), 8);
    }
    let config: crate::http::Config = serde_json::from_value(base.clone())?;
    assert_eq!(provider(config.tls_key_exchange_preferences.as_deref())?.kx_groups.len(), 8);
    for bad in [serde_json::json!("MLKEM1024"), serde_json::json!([512])] {
        let mut value = base.clone();
        value["tls_key_exchange_preferences"] = bad;
        assert!(serde_json::from_value::<crate::http::Config>(value).is_err());
    }
    for bad in ["mlkem1024", "MLKEM768", "CurveP25519", ""] {
        assert!(provider(Some(&names(&[bad]))).is_err());
    }
    assert!(protocol_versions(Some("tls13"), Some("tls12")).is_err());
    assert!(protocol_versions(Some("tls11"), None).is_err());
    assert!(protocol_versions(None, Some("TLS13")).is_err());
    Ok(())
}

#[test]
fn tls270_all_eight_named_groups_execute_real_key_exchange() -> TestResult {
    for (name, group_id, client_len, server_len, secret_len, pq) in [
        ("CurveP256", 0x17, 65, 65, 32, false),
        ("CurveP384", 0x18, 97, 97, 48, false),
        ("CurveP521", 0x19, 133, 133, 66, false),
        ("SecP256r1MLKEM768", 0x11eb, 1249, 1153, 64, true),
        ("SecP384r1MLKEM1024", 0x11ed, 1665, 1665, 80, true),
        ("X25519", 0x1d, 32, 32, 32, false),
        ("X25519MLKEM768", 0x11ec, 1216, 1120, 64, true),
        ("MLKEM1024", 0x0202, 1568, 1568, 32, true),
    ] {
        let group = named_group(name)?;
        assert_eq!(u16::from(group.name()), group_id);
        assert!(group.usable_for_version(ProtocolVersion::TLSv1_3));
        assert_eq!(group.usable_for_version(ProtocolVersion::TLSv1_2), !pq);
        let client = group.start()?;
        assert_eq!(client.pub_key().len(), client_len);
        let server = group.start_and_complete(client.pub_key())?;
        assert_eq!(server.group, group.name());
        assert_eq!(server.pub_key.len(), server_len);
        assert_eq!(server.secret.secret_bytes().len(), secret_len);
        let secret = client.complete(&server.pub_key)?;
        assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
    }
    Ok(())
}

#[test]
fn tls270_p384_hybrid_matches_independent_component_wire_and_rejects_invalid_points() -> TestResult {
    let classical = kx_group::SECP384R1.start()?;
    let kem = kx_group::MLKEM1024.start()?;
    let peer = [classical.pub_key(), kem.pub_key()].concat();
    let server = P384_MLKEM1024.start_and_complete(&peer)?;
    let expected = [classical.complete(&server.pub_key[..97])?.secret_bytes(),
        kem.complete(&server.pub_key[97..])?.secret_bytes()].concat();
    assert_eq!(server.secret.secret_bytes(), expected);
    // Independently constructed responder validates the client's component order.
    let client = P384_MLKEM1024.start()?;
    let classical = kx_group::SECP384R1.start_and_complete(&client.pub_key()[..97])?;
    let kem = kx_group::MLKEM1024.start_and_complete(&client.pub_key()[97..])?;
    let reply = [classical.pub_key.as_slice(), kem.pub_key.as_slice()].concat();
    let expected = [classical.secret.secret_bytes(), kem.secret.secret_bytes()].concat();
    assert_eq!(client.complete(&reply)?.secret_bytes(), expected);
    for length in [0, 97, 1568, 1664, 1666] {
        assert!(P384_MLKEM1024.start_and_complete(&vec![4; length]).is_err());
        assert!(P384_MLKEM1024.start()?.complete(&vec![4; length]).is_err());
    }
    for prefix in [0, 2, 3] {
        let mut invalid = peer.clone();
        invalid[0] = prefix;
        assert!(P384_MLKEM1024.start_and_complete(&invalid).is_err());
    }
    let mut invalid = peer;
    invalid[..97].fill(0);
    invalid[0] = 4;
    assert!(P384_MLKEM1024.start_and_complete(&invalid).is_err());
    // FIPS 203 encapsulation-key check: packed coefficients 4095 are not
    // canonical modulo q=3329. The SDK must reject them before encapsulation.
    for (name, offset) in [("SecP384r1MLKEM1024", 97), ("SecP256r1MLKEM768", 65),
        ("X25519MLKEM768", 0), ("MLKEM1024", 0)] {
        let group = named_group(name)?;
        let client = group.start()?;
        let mut invalid = client.pub_key().to_vec();
        invalid[offset..offset + 3].fill(0xff);
        assert!(group.start_and_complete(&invalid).is_err());
    }
    let mut invalid = vec![0; 133];
    invalid[0] = 4;
    assert!(P521.start()?.complete(&invalid).is_err());
    invalid[0] = 2;
    assert!(P521.start()?.complete(&invalid).is_err());
    Ok(())
}

#[test]
fn tls270_all_groups_negotiate_authenticated_tls13_and_preserve_alpn() -> TestResult {
    let (root, chain, key) = identity()?;
    for name in ["CurveP256", "CurveP384", "CurveP521", "SecP256r1MLKEM768",
        "SecP384r1MLKEM1024", "X25519", "X25519MLKEM768", "MLKEM1024"] {
        for alpn in [b"h2".as_slice(), b"http/1.1".as_slice()] {
            let (mut client, mut server) = pair(root.clone(), chain.clone(), key.clone_key(),
                &[name], &[name], &rustls::version::TLS13, "localhost", alpn)?;
            handshake(&mut client, &mut server)?;
            assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
            assert_eq!(client.negotiated_key_exchange_group().map(|group| group.name()), Some(named_group(name)?.name()));
            assert_eq!(server.negotiated_key_exchange_group().map(|group| group.name()), Some(named_group(name)?.name()));
            assert_eq!(client.alpn_protocol(), Some(alpn));
            assert_eq!(server.alpn_protocol(), Some(alpn));
            application_record(&mut client, &mut server)?;
        }
    }
    Ok(())
}

#[test]
fn tls270_pqc_only_has_no_classical_or_tls12_fallback_and_keeps_hostname_verification() -> TestResult {
    let (root, chain, key) = identity()?;
    for name in ["SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768", "MLKEM1024"] {
        for (offered, required) in [(vec!["X25519", "CurveP256"], vec![name]),
            (vec![name], vec!["X25519", "CurveP256"])] {
            let (mut client, mut server) = pair(root.clone(), chain.clone(), key.clone_key(),
                &offered, &required, &rustls::version::TLS13, "localhost", b"h2")?;
            assert!(handshake(&mut client, &mut server).is_err());
        }
        let result = pair(root.clone(), chain.clone(), key.clone_key(),
            &[name], &[name], &rustls::version::TLS12, "localhost", b"h2")
            .and_then(|(mut client, mut server)| { handshake(&mut client, &mut server)?; Ok(()) });
        assert!(result.is_err(), "PQ group must never negotiate TLS 1.2");
        let (mut client, mut server) = pair(root.clone(), chain.clone(), key.clone_key(),
            &[name], &[name], &rustls::version::TLS13, "wrong.example", b"h2")?;
        assert!(matches!(handshake(&mut client, &mut server), Err(Error::InvalidCertificate(_))));
    }
    // The provider change preserves actual classical TLS 1.2.
    for name in ["CurveP256", "CurveP384", "CurveP521", "X25519"] {
        let (mut client, mut server) = pair(root.clone(), chain.clone(), key.clone_key(),
            &[name], &[name], &rustls::version::TLS12, "localhost", b"h2")?;
        handshake(&mut client, &mut server)?;
        assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_2));
        application_record(&mut client, &mut server)?;
    }
    Ok(())
}

#[test]
fn tls270_mldsa_server_and_ca_certificates_authenticate_pure_mlkem_and_reject_untrusted_names() -> TestResult {
    use aws_lc_rs::signature::{ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING};
    for (algorithm, oid_tail) in [(&ML_DSA_44_SIGNING, 17), (&ML_DSA_65_SIGNING, 18), (&ML_DSA_87_SIGNING, 19)] {
        let (root, chain, key) = mldsa_identity(algorithm, oid_tail)?;
        let (mut client, mut server) = pair(root.clone(), chain.clone(), key.clone_key(),
            &["MLKEM1024"], &["MLKEM1024"], &rustls::version::TLS13, "localhost", b"h2")?;
        handshake(&mut client, &mut server)?;
        assert_eq!(client.negotiated_key_exchange_group().map(|group| group.name()), Some(NamedGroup::MLKEM1024));
        assert_eq!(client.alpn_protocol(), Some(b"h2".as_slice()));
        application_record(&mut client, &mut server)?;
        let (mut client, mut server) = pair(root, chain.clone(), key.clone_key(),
            &["MLKEM1024"], &["MLKEM1024"], &rustls::version::TLS13, "wrong.example", b"h2")?;
        assert!(matches!(handshake(&mut client, &mut server), Err(Error::InvalidCertificate(_))));
        let (untrusted, _, _) = mldsa_identity(algorithm, oid_tail)?;
        let (mut client, mut server) = pair(untrusted, chain.clone(), key.clone_key(),
            &["MLKEM1024"], &["MLKEM1024"], &rustls::version::TLS13, "localhost", b"h2")?;
        assert!(matches!(handshake(&mut client, &mut server), Err(Error::InvalidCertificate(_))));
    }
    Ok(())
}
