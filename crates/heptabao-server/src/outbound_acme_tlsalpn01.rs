//! Public TLS-ALPN proof has no Vault actor, enrollment or provider credential.
use super::*;
use x509_parser::{extensions::GeneralName, prelude::*};

const ACME_ID: &str = "1.3.6.1.5.5.7.1.31";
fn remaining(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| "tls-alpn-01: attempt deadline exceeded".into())
}
fn certificate_error(text: impl Into<String>) -> String {
    format!("tls-alpn-01: failed to perform handshake: {}", text.into())
}
fn octets(raw: &[u8]) -> Result<&[u8], String> {
    let invalid = || {
        certificate_error(
            "server under test returned a certificate with invalid acmeIdentifier extension value",
        )
    };
    if raw.first() != Some(&4) || raw.len() < 2 {
        return Err(invalid());
    }
    let first = raw[1];
    let (at, length) = if first < 128 {
        (2, first as usize)
    } else {
        let width = (first & 127) as usize;
        if width == 0 || width > 4 || raw.len() < 2 + width || raw[2] == 0 {
            return Err(invalid());
        }
        let mut size = 0usize;
        for byte in &raw[2..2 + width] {
            size = (size << 8) | *byte as usize;
        }
        if size < 128 {
            return Err(invalid());
        }
        (2 + width, size)
    };
    let end = at
        .checked_add(length)
        .filter(|end| *end <= raw.len())
        .ok_or_else(invalid)?;
    if end != raw.len() {
        return Err(certificate_error(
            "server under test returned a certificate with invalid acmeIdentifier extension value with additional trailing data",
        ));
    }
    Ok(&raw[at..end])
}
fn verify_certificate(
    raw: &[u8],
    host: &str,
    token: &str,
    thumbprint: &str,
    deadline: Instant,
) -> Result<(), String> {
    remaining(deadline)?;
    if raw.len() > 128 * 1024 {
        return Err(certificate_error("public proof certificate exceeds bound"));
    }
    let (rest, certificate) = X509Certificate::from_der(raw)
        .map_err(|_| certificate_error("invalid public proof certificate"))?;
    if !rest.is_empty()
        || certificate.signature_value.unused_bits != 0
        || certificate.signature_algorithm != certificate.tbs_certificate.signature
    {
        return Err(certificate_error(
            "invalid public proof certificate signature framing",
        ));
    }
    if matches!(
        certificate
            .signature_algorithm
            .algorithm
            .to_id_string()
            .as_str(),
        "1.2.840.113549.1.1.2"
            | "1.2.840.113549.1.1.4"
            | "1.2.840.113549.1.1.5"
            | "1.2.840.10045.4.1"
    ) {
        return Err(certificate_error(
            "server under test returned a certificate with an insecure signature algorithm",
        ));
    }
    let public = openssl::x509::X509::from_der(raw)
        .map_err(|_| certificate_error("invalid public proof certificate"))?;
    let key = public
        .public_key()
        .map_err(|_| certificate_error("invalid public proof certificate key"))?;
    if !public.verify(&key).unwrap_or(false) {
        return Err(certificate_error(
            "server under test returned a non-self-signed certificate: signature verification failed",
        ));
    }
    if certificate.subject().as_raw() != certificate.issuer().as_raw() {
        return Err(certificate_error(format!(
            "server under test returned a non-self-signed certificate: invalid subject ({}) <-> issuer ({}) match",
            certificate.subject(),
            certificate.issuer()
        )));
    }
    let san = certificate
        .subject_alternative_name()
        .map_err(|_| {
            certificate_error("server under test returned a certificate with incorrect SANs")
        })?
        .ok_or_else(|| {
            certificate_error("server under test returned a certificate with incorrect SANs")
        })?;
    let names = &san.value.general_names;
    let dns = names
        .iter()
        .filter_map(|n| {
            if let GeneralName::DNSName(s) = n {
                Some(*s)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if dns.len() != 1
        || names.iter().any(|n| {
            matches!(
                n,
                GeneralName::RFC822Name(_) | GeneralName::IPAddress(_) | GeneralName::URI(_)
            )
        })
    {
        return Err(certificate_error(
            "server under test returned a certificate with incorrect SANs",
        ));
    }
    if !dns[0].eq_ignore_ascii_case(host) {
        return Err(certificate_error(format!(
            "server under test returned a certificate with unexpected identifier: {}",
            dns[0]
        )));
    }
    let mut found = false;
    let mut unknown_critical = Vec::new();
    for extension in certificate.extensions() {
        let oid = extension.oid.to_id_string();
        if oid == ACME_ID {
            if found {
                return Err(certificate_error(
                    "server under test returned a certificate with multiple acmeIdentifier extensions",
                ));
            }
            found = true;
            if !extension.critical {
                return Err(certificate_error(
                    "server under test returned a certificate with an acmeIdentifier extension marked non-Critical",
                ));
            }
            let proof = octets(extension.value)?;
            if proof != crate::crypto::digest(format!("{token}.{thumbprint}").as_bytes()) {
                return Err(certificate_error(
                    "server under test returned a certificate with an invalid key authorization (sha256 key authorization was invalid)",
                ));
            }
        } else if extension.critical
            && !matches!(
                oid.as_str(),
                "2.5.29.14"
                    | "2.5.29.15"
                    | "2.5.29.17"
                    | "2.5.29.19"
                    | "2.5.29.30"
                    | "2.5.29.31"
                    | "2.5.29.32"
                    | "2.5.29.35"
                    | "2.5.29.37"
                    | "1.3.6.1.5.5.7.1.1"
            )
        {
            unknown_critical.push(oid);
        }
    }
    if !found {
        return Err(certificate_error(
            "server under test returned a certificate without the required acmeIdentifier extension",
        ));
    }
    if !unknown_critical.is_empty() {
        return Err(certificate_error(format!(
            "server under test returned a certificate with additional unknown critical extensions ([{}])",
            unknown_critical.join(" ")
        )));
    }
    remaining(deadline)?;
    Ok(())
}
pub(crate) fn verify_tlsalpn01(
    host: &str,
    token: &str,
    thumbprint: &str,
    deadline: Instant,
) -> Result<(), String> {
    verify_at(host, 443, token, thumbprint, deadline)
}
fn verify_at(
    host: &str,
    port: u16,
    token: &str,
    thumbprint: &str,
    deadline: Instant,
) -> Result<(), String> {
    let addresses = ldap_transport::resolve_addresses(host, port, deadline).map_err(|_| {
        "tls-alpn-01: failed to dial host: challenge destination resolution failed".to_owned()
    })?;
    let mut socket = None;
    for address in addresses {
        if let Ok(stream) =
            TcpStream::connect_timeout(&address, remaining(deadline)?.min(Duration::from_secs(10)))
        {
            socket = Some(stream);
            break;
        }
    }
    let stream = socket.ok_or_else(|| {
        "tls-alpn-01: failed to dial host: challenge destination unavailable".to_owned()
    })?;
    let socket = DeadlineSocket { stream, deadline };
    let mut builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
        .map_err(|_| certificate_error("proof TLS configuration unavailable"))?;
    // The self signature, exact SAN and critical ACME hash are verified below.
    builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
    builder.set_session_cache_mode(openssl::ssl::SslSessionCacheMode::OFF);
    builder
        .set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
        .map_err(|_| certificate_error("proof TLS configuration unavailable"))?;
    builder.set_cipher_list("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305").map_err(|_| certificate_error("proof TLS configuration unavailable"))?;
    builder
        .set_alpn_protos(b"\x0aacme-tls/1")
        .map_err(|_| certificate_error("proof ALPN configuration unavailable"))?;
    let mut configuration = builder
        .build()
        .configure()
        .map_err(|_| certificate_error("proof TLS configuration unavailable"))?;
    configuration.set_verify_hostname(false);
    configuration.set_use_server_name_indication(host.parse::<std::net::IpAddr>().is_err());
    let stream = configuration
        .connect(host, socket)
        .map_err(|_| certificate_error("public proof TLS handshake failed"))?;
    remaining(deadline)?;
    let peer = stream.ssl();
    if peer.session_reused() {
        return Err(certificate_error(
            "server under test incorrectly reported that handshake was resumed when no session cache was provided; refusing to continue",
        ));
    }
    if peer.selected_alpn_protocol() != Some(b"acme-tls/1".as_slice()) {
        return Err(certificate_error(format!(
            "server under test negotiated unexpected ALPN protocol {}",
            String::from_utf8_lossy(peer.selected_alpn_protocol().unwrap_or_default())
        )));
    }
    let chain = peer
        .peer_cert_chain()
        .ok_or_else(|| certificate_error("server under test returned no certificate"))?;
    if chain.len() != 1 {
        return Err(certificate_error(format!(
            "server under test returned multiple ({}) certificates when we expected only one",
            chain.len()
        )));
    }
    let certificate = peer
        .peer_certificate()
        .ok_or_else(|| certificate_error("server under test returned no certificate"))?;
    let raw = certificate
        .to_der()
        .map_err(|_| certificate_error("invalid public proof certificate"))?;
    verify_certificate(&raw, host, token, thumbprint, deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::{Asn1Object, Asn1OctetString, Asn1Time},
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, Private},
        ssl::{SslAcceptor, SslMethod, select_next_proto},
        x509::{X509, X509Extension, X509NameBuilder, extension::SubjectAlternativeName},
    };
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
    fn certificate(mode: &str) -> TestResult<(X509, PKey<Private>)> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "localhost")?;
        let name = name.build();
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&key)?;
        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(2)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;
        let mut san = SubjectAlternativeName::new();
        san.dns(if mode == "case" {
            "LOCALHOST"
        } else {
            "localhost"
        });
        if mode == "twoSAN" {
            san.dns("wrong.example");
        }
        builder.append_extension(san.build(&builder.x509v3_context(None, None))?)?;
        if mode != "missing" {
            let mut digest = crate::crypto::digest(b"token.thumb");
            if mode == "wrong" {
                digest[0] ^= 1;
            }
            let mut bytes = vec![4, 32];
            bytes.extend(digest);
            let oid = Asn1Object::from_str(ACME_ID)?;
            let contents = Asn1OctetString::new_from_bytes(&bytes)?;
            builder.append_extension(X509Extension::new_from_der(
                &oid,
                mode != "noncritical",
                &contents,
            )?)?;
        }
        if mode == "unknown" {
            let oid = Asn1Object::from_str("1.2.3.4")?;
            let contents = Asn1OctetString::new_from_bytes(&[5, 0])?;
            builder.append_extension(X509Extension::new_from_der(&oid, true, &contents)?)?;
        }
        builder.sign(&key, MessageDigest::sha256())?;
        Ok((builder.build(), key))
    }
    #[test]
    fn pki_acme99_tlsalpn01_actual_selfsignature_san_critical_hash_and_original_deadline()
    -> TestResult {
        for mode in [
            "valid",
            "case",
            "wrong",
            "noncritical",
            "missing",
            "twoSAN",
            "unknown",
        ] {
            let (cert, _) = certificate(mode)?;
            let der = cert.to_der()?;
            let result = verify_certificate(
                &der,
                "localhost",
                "token",
                "thumb",
                Instant::now() + Duration::from_secs(3),
            );
            assert_eq!(
                result.is_ok(),
                matches!(mode, "valid" | "case"),
                "{mode}: {result:?}"
            );
            if mode == "valid" {
                let deadline = Instant::now()
                    .checked_sub(Duration::from_millis(1))
                    .ok_or("clock underflow")?;
                assert!(verify_certificate(&der, "localhost", "token", "thumb", deadline).is_err());
                assert!(
                    verify_certificate(
                        &der,
                        "wrong.example",
                        "token",
                        "thumb",
                        Instant::now() + Duration::from_secs(3)
                    )
                    .is_err()
                );
            }
        }
        Ok(())
    }
    #[test]
    fn pki_acme99_tlsalpn01_actual_tls12_alpn_sni_public_proof_and_wrong_protocol() -> TestResult {
        for correct_alpn in [true, false] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            let port = listener.local_addr()?.port();
            let (certificate, key) = certificate("valid")?;
            let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
            acceptor.set_certificate(&certificate)?;
            acceptor.set_private_key(&key)?;
            acceptor.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))?;
            if correct_alpn {
                acceptor.set_alpn_select_callback(|_, supplied| {
                    select_next_proto(b"\x0aacme-tls/1", supplied)
                        .ok_or(openssl::ssl::AlpnError::NOACK)
                });
            }
            let acceptor = acceptor.build();
            let server = std::thread::spawn(move || -> TestResult {
                let (stream, _) = listener.accept()?;
                stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                stream.set_write_timeout(Some(Duration::from_secs(3)))?;
                let peer = acceptor
                    .accept(stream)
                    .map_err(|_| "TLS fixture handshake")?;
                assert_eq!(
                    peer.ssl().servername(openssl::ssl::NameType::HOST_NAME),
                    Some("localhost")
                );
                Ok(())
            });
            let result = verify_at(
                "localhost",
                port,
                "token",
                "thumb",
                Instant::now() + Duration::from_secs(3),
            );
            server.join().map_err(|_| "TLS fixture thread")??;
            assert_eq!(result.is_ok(), correct_alpn, "{result:?}");
        }
        Ok(())
    }
}
