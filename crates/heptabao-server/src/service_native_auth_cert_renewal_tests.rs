//! A direct certificate token keeps its original TLS leaf as delivery authority.
//! Pauses occur only after real renewal dispatch or successful mandatory audit.
use super::*;
use std::cell::RefCell;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

struct ArmedPause {
    path: &'static str,
    until: SystemTime,
    fired: Arc<AtomicBool>,
}

thread_local! {
    static BEFORE_CERT_RENEWAL_PUBLICATION: RefCell<Option<ArmedPause>> =
        const { RefCell::new(None) };
}

struct CertRenewalPublicationPause {
    fired: Arc<AtomicBool>,
}

impl CertRenewalPublicationPause {
    fn once(path: &'static str, until: SystemTime) -> Self {
        assert!(matches!(
            path,
            "auth/token/renew-self" | "auth/token/renew" | "auth/token/renew-accessor"
        ));
        let fired = Arc::new(AtomicBool::new(false));
        BEFORE_CERT_RENEWAL_PUBLICATION.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(ArmedPause {
                path,
                until,
                fired: Arc::clone(&fired),
            });
        });
        Self { fired }
    }
}

impl Drop for CertRenewalPublicationPause {
    fn drop(&mut self) {
        BEFORE_CERT_RENEWAL_PUBLICATION.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

fn wait_until_after(expiry: SystemTime) {
    let until = expiry + Duration::from_millis(50);
    let delay = until.duration_since(SystemTime::now()).unwrap_or_default();
    assert!(delay <= Duration::from_secs(10));
    std::thread::sleep(delay);
    assert!(SystemTime::now() > expiry);
}

// This hook is reached only after the real dispatcher has returned 200 and the
// retained source has confirmed a direct certificate renewal binding. A thread
// can arm one exact route; an unrelated successful request cannot consume it.
pub(crate) fn before_native_cert_renewal_publication(path: &str) {
    let armed = BEFORE_CERT_RENEWAL_PUBLICATION.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|armed| armed.path == path) {
            slot.take()
        } else {
            None
        }
    });
    if let Some(armed) = armed {
        armed.fired.store(true, Ordering::Release);
        wait_until_after(armed.until);
    }
}

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
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    server::WebPkiClientVerifier,
};
use std::io::{Read, Write};

struct Identity {
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

struct Certificates {
    ca: CertificateDer<'static>,
    server: Identity,
    client: Identity,
    client_expiry: SystemTime,
}

fn private_key() -> TestResult<PKey<Private>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    Ok(PKey::from_ec_key(EcKey::generate(&group)?)?)
}

fn certificates() -> TestResult<Certificates> {
    let ca_key = private_key()?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "synthetic native renewal CA")?;
    let name = name.build();
    let mut ca = X509::builder()?;
    ca.set_version(2)?;
    let serial_number = BigNum::from_u32(1)?;
    let serial = Asn1Integer::from_bn(&serial_number)?;
    ca.set_serial_number(&serial)?;
    ca.set_subject_name(&name)?;
    ca.set_issuer_name(&name)?;
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

    fn leaf(
        ca: &X509,
        ca_key: &PKey<Private>,
        serial: u32,
        name: &str,
        server: bool,
        expires_at: Option<i64>,
    ) -> TestResult<Identity> {
        let key = private_key()?;
        let mut subject = X509NameBuilder::new()?;
        subject.append_entry_by_text("CN", name)?;
        let subject = subject.build();
        let mut leaf = X509::builder()?;
        leaf.set_version(2)?;
        let serial_number = BigNum::from_u32(serial)?;
        let serial = Asn1Integer::from_bn(&serial_number)?;
        leaf.set_serial_number(&serial)?;
        leaf.set_subject_name(&subject)?;
        leaf.set_issuer_name(ca.subject_name())?;
        leaf.set_pubkey(&key)?;
        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = match expires_at {
            Some(expiry) => Asn1Time::from_unix(expiry)?,
            None => Asn1Time::days_from_now(2)?,
        };
        leaf.set_not_before(&not_before)?;
        leaf.set_not_after(&not_after)?;
        leaf.append_extension(BasicConstraints::new().critical().build()?)?;
        leaf.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
        let mut eku = ExtendedKeyUsage::new();
        if server {
            eku.server_auth();
        } else {
            eku.client_auth();
        }
        leaf.append_extension(eku.build()?)?;
        if server {
            leaf.append_extension(
                SubjectAlternativeName::new()
                    .dns(name)
                    .build(&leaf.x509v3_context(Some(ca), None))?,
            )?;
        }
        leaf.sign(ca_key, MessageDigest::sha256())?;
        Ok(Identity {
            certificates: vec![
                CertificateDer::from(leaf.build().to_der()?),
                CertificateDer::from(ca.to_der()?),
            ],
            key: PrivatePkcs8KeyDer::from(key.private_key_to_pkcs8()?).into(),
        })
    }

    let server = leaf(&ca, &ca_key, 2, "localhost", true, None)?;
    // Start the short interval only after service setup and CA/server key work.
    // Token grants deliberately remain much longer than this real leaf.
    let expiry = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 4;
    let client = leaf(
        &ca,
        &ca_key,
        3,
        "native-renewal-client",
        false,
        Some(i64::try_from(expiry)?),
    )?;
    Ok(Certificates {
        ca: CertificateDer::from(ca.to_der()?),
        server,
        client,
        client_expiry: UNIX_EPOCH + Duration::from_secs(expiry),
    })
}

// Real signed TLS records, verified client chain and Finished messages carried
// in bounded memory. This is not a physical HTTPS listener qualification.
fn pump(client: &mut ClientConnection, server: &mut ServerConnection) -> TestResult {
    for _ in 0..32 {
        let mut wire = Vec::new();
        client.write_tls(&mut wire)?;
        assert!(wire.len() <= 1024 * 1024);
        let mut incoming = std::io::Cursor::new(wire);
        while incoming.position() < incoming.get_ref().len() as u64 {
            assert!(server.read_tls(&mut incoming)? > 0);
            server.process_new_packets()?;
        }
        let mut wire = Vec::new();
        server.write_tls(&mut wire)?;
        assert!(wire.len() <= 1024 * 1024);
        let mut incoming = std::io::Cursor::new(wire);
        while incoming.position() < incoming.get_ref().len() as u64 {
            assert!(client.read_tls(&mut incoming)? > 0);
            client.process_new_packets()?;
        }
        if !client.is_handshaking()
            && !server.is_handshaking()
            && !client.wants_write()
            && !server.wants_write()
        {
            return Ok(());
        }
    }
    Err("bounded real renewal TLS exchange stalled".into())
}

fn connected(certificates: &Certificates) -> TestResult<(ClientConnection, ServerConnection)> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(certificates.ca.clone())?;
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots.clone()), provider.clone())
            .build()?;
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            certificates.server.certificates.clone(),
            certificates.server.key.clone_key(),
        )?;
    let client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_client_auth_cert(
            certificates.client.certificates.clone(),
            certificates.client.key.clone_key(),
        )?;
    let mut client = ClientConnection::new(Arc::new(client), ServerName::try_from("localhost")?)?;
    let mut server = ServerConnection::new(Arc::new(server))?;
    pump(&mut client, &mut server)?;
    assert!(
        server
            .peer_certificates()
            .is_some_and(|chain| !chain.is_empty())
    );
    Ok((client, server))
}

struct VerifiedRequest {
    fields: Value,
    chain: Vec<Vec<u8>>,
}

impl Drop for VerifiedRequest {
    fn drop(&mut self) {
        erase_json(&mut self.fields);
    }
}

fn send_request(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> TestResult<VerifiedRequest> {
    assert!(!client.is_handshaking() && !server.is_handshaking());
    let mut request = json!({"method":method,"path":path,"token":token,"body":body});
    let request_bytes = Zeroizing::new(serde_json::to_vec(&request)?);
    erase_json(&mut request);
    client.writer().write_all(&request_bytes)?;
    pump(client, server)?;
    let mut plaintext = Zeroizing::new(vec![0; request_bytes.len()]);
    server.reader().read_exact(&mut plaintext)?;
    let fields = serde_json::from_slice(&plaintext)?;
    // No raw or injected certificate field supplies authority here: this chain
    // comes exclusively from the completed WebPKI-verified Rustls connection.
    let chain = server
        .peer_certificates()
        .ok_or("missing actual verified renewal TLS peer")?
        .iter()
        .map(|certificate| certificate.as_ref().to_vec())
        .collect();
    Ok(VerifiedRequest { fields, chain })
}

fn send_response(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
    response: &Response,
) -> TestResult {
    let mut envelope = json!({"status":response.status,"body":&response.body});
    let reply = Zeroizing::new(serde_json::to_vec(&envelope)?);
    erase_json(&mut envelope);
    server.writer().write_all(&reply)?;
    pump(client, server)?;
    let mut received = Zeroizing::new(vec![0; reply.len()]);
    client.reader().read_exact(&mut received)?;
    assert!(received.as_slice() == reply.as_slice());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn call_tls(
    service: &mut Service,
    client: &mut ClientConnection,
    server: &mut ServerConnection,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> TestResult<Response> {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let request = send_request(client, server, method, path, token, body)?;
    let response = service.handle_request(ServiceRequest {
        method: request.fields["method"].as_str().ok_or("TLS method")?,
        path: request.fields["path"].as_str().ok_or("TLS path")?,
        namespace: "",
        token: request.fields["token"].as_str().ok_or("TLS token")?,
        body: request.fields["body"].clone(),
        wrap_ttl_seconds: None,
        origin_peer: Some(std::net::IpAddr::from([127, 0, 0, 1])),
        client_certificates: Some(request.chain.clone()),
    });
    assert!(service.pending_native_auth_delivery.is_none());
    send_response(client, server, &response)?;
    Ok(response)
}

struct Fixture {
    files: Root,
    service: Service,
    key: Zeroizing<String>,
    admin: Zeroizing<String>,
    token: Zeroizing<String>,
    accessor: Zeroizing<String>,
    client: ClientConnection,
    peer: ServerConnection,
    expiry: SystemTime,
}

fn fixture() -> TestResult<Fixture> {
    const CERT_POLICY: &str = r#"
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "auth/token/create" { capabilities = ["update"] }
"#;
    let (files, mut service, key, admin) = activated()?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/native-cert-renewal",
            &admin,
            json!({"policy":CERT_POLICY})
        )
        .status,
        204,
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/native-cert",
            &admin,
            json!({"type":"cert"})
        )
        .status,
        204,
    );
    let certificates = certificates()?;
    let digest = hex(&crypto::digest(
        certificates.client.certificates[0].as_ref(),
    ));
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/native-cert/certs/client",
            &admin,
            json!({"certificate_sha256":digest,"token_policies":["native-cert-renewal"],
                "token_ttl":600,"token_max_ttl":1800,"token_type":"service"})
        )
        .status,
        204,
    );
    let (mut client, mut peer) = connected(&certificates)?;
    let mut login = call_tls(
        &mut service,
        &mut client,
        &mut peer,
        "POST",
        "auth/native-cert/login",
        "",
        json!({"name":"client"}),
    )?;
    assert_eq!(login.status, 200);
    assert!(
        login.body["auth"]["lease_duration"]
            .as_u64()
            .is_some_and(|ttl| ttl > 300)
    );
    let accessor = Zeroizing::new(
        login.body["auth"]["accessor"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or("missing synthetic cert accessor")?
            .to_owned(),
    );
    let token = secret_field(&mut login, "/auth/client_token")?;
    assert!(SystemTime::now() < certificates.client_expiry);
    Ok(Fixture {
        files,
        service,
        key,
        admin,
        token,
        accessor,
        client,
        peer,
        expiry: certificates.client_expiry,
    })
}

fn renewal_body(path: &str, token: &str, accessor: &str) -> TestResult<Value> {
    match path {
        "auth/token/renew-self" => Ok(json!({"increment":"15m"})),
        "auth/token/renew" => Ok(json!({"token":token,"increment":"15m"})),
        "auth/token/renew-accessor" => Ok(json!({"accessor":accessor,"increment":"15m"})),
        _ => Err("unexpected synthetic cert renewal route".into()),
    }
}

fn token_expiry(service: &mut Service, token: &str) -> TestResult<String> {
    let mut lookup = call(service, "GET", "auth/token/lookup-self", token, json!({}));
    assert_eq!(lookup.status, 200);
    assert!(
        lookup.body["data"]["ttl"]
            .as_u64()
            .is_some_and(|ttl| ttl > 300)
    );
    let expiry = lookup.body["data"]["expire_time"]
        .as_str()
        .ok_or("missing synthetic public token expiry")?
        .to_owned();
    let echoed = secret_field(&mut lookup, "/data/id")?;
    assert!(echoed.as_str() == token);
    Ok(expiry)
}

fn assert_no_credentials(response: &Response) {
    assert!(response.status >= 300);
    assert!(response.body.get("auth").is_none());
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("wrap_info").is_none());
    assert!(response.unwrapped_json.is_none());
    assert!(response.consistency_index.is_none());
}

fn leaf_expiry_before_publication(path: &'static str) -> TestResult {
    let mut f = fixture()?;
    let original_expiry = token_expiry(&mut f.service, &f.token)?;
    let body = renewal_body(path, &f.token, &f.accessor)?;
    let actor = if path == "auth/token/renew-self" {
        f.token.as_str()
    } else {
        f.admin.as_str()
    };
    let generation = f.service.durable.as_ref().ok_or("durable")?.generation();
    let pause = CertRenewalPublicationPause::once(path, f.expiry);
    let response = call_tls(
        &mut f.service,
        &mut f.client,
        &mut f.peer,
        "POST",
        path,
        actor,
        body,
    )?;
    // Only a successful real dispatcher and direct target validation can enter
    // the pause. An initially expired leaf cannot make this test pass.
    assert!(pause.fired.load(Ordering::Acquire));
    drop(pause);
    assert_no_credentials(&response);
    assert_eq!(
        f.service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert!(!f.service.recovery_required);
    assert!(!f.service.audit_failed);
    assert_eq!(token_expiry(&mut f.service, &f.token)?, original_expiry);
    drop(f.service);

    let mut service = reopened(&f.files, &f.key)?;
    assert_eq!(token_expiry(&mut service, &f.token)?, original_expiry);
    assert!(!service.recovery_required);
    Ok(())
}

fn leaf_expiry_after_audit(path: &'static str) -> TestResult {
    let mut f = fixture()?;
    let original_expiry = token_expiry(&mut f.service, &f.token)?;
    let body = renewal_body(path, &f.token, &f.accessor)?;
    let actor = if path == "auth/token/renew-self" {
        f.token.as_str()
    } else {
        f.admin.as_str()
    };
    let request = send_request(&mut f.client, &mut f.peer, "POST", path, actor, body)?;
    let generation = f.service.durable.as_ref().ok_or("durable")?.generation();
    let started = Instant::now();
    let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, started)?;
    let scope =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let response = f.service.handle_inner(RequestView {
        method: request.fields["method"].as_str().ok_or("TLS method")?,
        path: request.fields["path"].as_str().ok_or("TLS path")?,
        namespace: "",
        token: request.fields["token"].as_str().ok_or("TLS token")?,
        body: &request.fields["body"],
        now: clock.admitted_at().seconds(),
        admission_started: started,
        token_clock: Some(clock),
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: Some(std::net::IpAddr::from([127, 0, 0, 1])),
        client_certificates: Some(&request.chain),
    });
    assert_eq!(response.status, 200);
    assert!(
        response.body["auth"]["lease_duration"]
            .as_u64()
            .is_some_and(|ttl| ttl > 800)
    );
    assert!(f.service.durable.as_ref().ok_or("durable")?.generation() > generation);
    assert!(f.service.pending_native_auth_delivery.is_some());
    assert!(SystemTime::now() < f.expiry);
    let response = f.service.audit_completed_response_with_receipt(
        "native-renewal-original-leaf-expiry",
        clock.admitted_at().seconds(),
        Some(clock),
        response,
        || wait_until_after(f.expiry),
    );
    assert_eq!(response.status, 200);
    let response = f.service.complete_native_auth_delivery(
        true,
        response,
        "native-renewal-original-leaf-expiry",
    );
    assert_no_credentials(&response);
    assert!(f.service.pending_native_auth_delivery.is_none());
    assert!(!f.service.recovery_required);
    assert!(!f.service.audit_failed);
    send_response(&mut f.client, &mut f.peer, &response)?;
    drop(scope);
    drop(request);

    // The response's authority has expired, while the longer token renewal is
    // already durable. A new bearer lookup observes that committed state.
    let renewed_expiry = token_expiry(&mut f.service, &f.token)?;
    assert_ne!(renewed_expiry, original_expiry);
    drop(f.service);
    let mut service = reopened(&f.files, &f.key)?;
    assert_eq!(token_expiry(&mut service, &f.token)?, renewed_expiry);
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn native_cert_renew_self_original_leaf_expiry_before_publication() -> TestResult {
    leaf_expiry_before_publication("auth/token/renew-self")
}

#[test]
fn native_cert_renew_target_original_leaf_expiry_before_publication() -> TestResult {
    leaf_expiry_before_publication("auth/token/renew")
}

#[test]
fn native_cert_renew_accessor_original_leaf_expiry_before_publication() -> TestResult {
    leaf_expiry_before_publication("auth/token/renew-accessor")
}

#[test]
fn native_cert_renew_self_original_leaf_expiry_after_audit() -> TestResult {
    leaf_expiry_after_audit("auth/token/renew-self")
}

#[test]
fn native_cert_renew_target_original_leaf_expiry_after_audit() -> TestResult {
    leaf_expiry_after_audit("auth/token/renew")
}

#[test]
fn native_cert_renew_accessor_original_leaf_expiry_after_audit() -> TestResult {
    leaf_expiry_after_audit("auth/token/renew-accessor")
}

#[test]
fn native_cert_parent_token_api_child_renews_without_unrelated_peer_after_leaf_expiry() -> TestResult
{
    let mut f = fixture()?;
    let mut issued = call_tls(
        &mut f.service,
        &mut f.client,
        &mut f.peer,
        "POST",
        "auth/token/create",
        &f.token,
        json!({"policies":["native-cert-renewal"],"ttl":"10m","explicit_max_ttl":"30m"}),
    )?;
    assert_eq!(issued.status, 200);
    let accessor = Zeroizing::new(
        issued.body["auth"]["accessor"]
            .as_str()
            .ok_or("missing synthetic child accessor")?
            .to_owned(),
    );
    let child = secret_field(&mut issued, "/auth/client_token")?;
    wait_until_after(f.expiry);
    let original_expiry = token_expiry(&mut f.service, &child)?;
    for path in [
        "auth/token/renew-self",
        "auth/token/renew",
        "auth/token/renew-accessor",
    ] {
        let actor = if path == "auth/token/renew-self" {
            child.as_str()
        } else {
            f.admin.as_str()
        };
        let mut response = call(
            &mut f.service,
            "POST",
            path,
            actor,
            renewal_body(path, &child, &accessor)?,
        );
        assert_eq!(response.status, 200);
        assert!(
            response.body["auth"]["lease_duration"]
                .as_u64()
                .is_some_and(|ttl| ttl > 800)
        );
        erase_json(&mut response.body);
    }
    let renewed_expiry = token_expiry(&mut f.service, &child)?;
    assert_ne!(renewed_expiry, original_expiry);
    drop(f.service);
    let mut service = reopened(&f.files, &f.key)?;
    assert_eq!(token_expiry(&mut service, &child)?, renewed_expiry);
    assert!(!service.recovery_required);
    Ok(())
}
