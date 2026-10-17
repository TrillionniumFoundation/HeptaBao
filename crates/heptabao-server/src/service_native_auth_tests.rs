//! Genuine Service dispatch, V6 publication, audited delivery and cold reopen.
//! All credentials are disposable test values and are never included in assertions.
use super::*;

#[path = "service_native_auth_cert_renewal_tests.rs"]
pub(super) mod cert_renewal_tests;
#[path = "service_native_auth_login_tests.rs"]
pub(super) mod login_tests;
#[path = "service_native_auth_renewal_tests.rs"]
mod renewal_tests;
use super::super::tests::Root;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MOUNT: &str = "native-authbus";
const ROLE: &str = "auth/native-authbus/role/client";
const LOGIN: &str = "auth/native-authbus/login";
const SECRET: &str = "secret/data/native-authbus/credential";
const POLICY: &str = r#"
path "secret/data/native-authbus/*" { capabilities = ["create", "read", "update", "delete"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
"#;
const SELF_ONLY_POLICY: &str = r#"
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
"#;

fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(30),
    );
    let response = service.handle(method, path, "", token, body);
    if response.status >= 400 {
        // These are fixed test routes and generic server errors. Never include
        // request bodies, headers, successful data or authentication replies.
        let errors: Vec<&str> = response
            .body
            .get("errors")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        eprintln!(
            "native AuthBus {path}: HTTP {} errors={errors:?}",
            response.status
        );
    }
    assert!(service.pending_native_auth_delivery.is_none());
    response
}

fn secret_field(response: &mut Response, pointer: &str) -> TestResult<Zeroizing<String>> {
    let value = response
        .body
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("missing synthetic credential field")?;
    let value = Zeroizing::new(value.to_owned());
    erase_json(&mut response.body);
    Ok(value)
}

fn activated() -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    let files = Root::new();
    let mut service = files.service()?;
    service.configure_native_v6_candidate()?;
    let (key, admin) = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(30),
        );
        super::super::tests::bootstrap(&mut service)?
    };
    let key = Zeroizing::new(key);
    let admin = Zeroizing::new(admin);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/internal/native-v6/activate",
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert!(service.native_root.is_some());
    assert!(service.record_root.is_none());
    Ok((files, service, key, admin))
}

fn reopened(files: &Root, key: &str) -> TestResult<Service> {
    let mut service = files.service()?;
    service.configure_native_v6_candidate()?;
    let response = call(&mut service, "POST", "sys/unseal", "", json!({"key":key}));
    assert_eq!(response.status, 200);
    assert_eq!(response.body["sealed"], false);
    assert!(service.native_root.is_some());
    assert!(service.record_root.is_none());
    assert!(!service.recovery_required);
    Ok(service)
}

fn issue_secret_id(service: &mut Service, admin: &str) -> TestResult<Zeroizing<String>> {
    let mut response = call(
        service,
        "POST",
        &format!("{ROLE}/secret-id"),
        admin,
        json!({}),
    );
    assert_eq!(response.status, 200);
    secret_field(&mut response, "/data/secret_id")
}

fn login(
    service: &mut Service,
    role_id: &str,
    secret_id: &str,
) -> TestResult<(Zeroizing<String>, Zeroizing<String>)> {
    let mut response = call(
        service,
        "POST",
        LOGIN,
        "",
        json!({"role_id":role_id,"secret_id":secret_id}),
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["auth"]["renewable"], true);
    let entity = Zeroizing::new(
        response.body["auth"]["entity_id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or("AppRole login did not bind a real identity")?
            .to_owned(),
    );
    let token = secret_field(&mut response, "/auth/client_token")?;
    Ok((token, entity))
}

fn assert_consumed(service: &mut Service, role_id: &str, secret_id: &str) {
    let response = call(
        service,
        "POST",
        LOGIN,
        "",
        json!({"role_id":role_id,"secret_id":secret_id}),
    );
    assert_eq!(response.status, 400);
    assert!(response.body.get("auth").is_none());
}

#[test]
fn native_authbus_approle_policy_kv_cas_renew_revoke_and_cold_reopen() -> TestResult {
    let (files, mut service, key, admin) = activated()?;
    // The mount, role, policy and credentials are all created after the actual
    // V6 activation, through the same public dispatch used by a local client.
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/native-authbus",
            &admin,
            json!({"policy":POLICY})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            &format!("sys/auth/{MOUNT}"),
            &admin,
            json!({"type":"approle"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            ROLE,
            &admin,
            json!({
                "token_policies":["native-authbus"],
                "token_ttl":"10m",
                "token_max_ttl":"20m",
                "secret_id_ttl":"10m",
                "secret_id_num_uses":1,
                "token_type":"service"
            })
        )
        .status,
        204
    );
    let mut role_response = call(
        &mut service,
        "GET",
        &format!("{ROLE}/role-id"),
        &admin,
        json!({}),
    );
    assert_eq!(role_response.status, 200);
    let role_id = secret_field(&mut role_response, "/data/role_id")?;
    let first_secret_id = issue_secret_id(&mut service, &admin)?;
    let (first_token, first_entity) = login(&mut service, &role_id, &first_secret_id)?;
    assert_consumed(&mut service, &role_id, &first_secret_id);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/outside-policy",
            &first_token,
            json!({"data":{"synthetic":"denied"}})
        )
        .status,
        403
    );
    let first = call(
        &mut service,
        "POST",
        SECRET,
        &first_token,
        json!({"options":{"cas":0},"data":{"synthetic":"first"}}),
    );
    assert_eq!(first.status, 200);
    assert_eq!(first.body["data"]["version"], 1);
    assert_eq!(
        call(
            &mut service,
            "POST",
            SECRET,
            &first_token,
            json!({"options":{"cas":0},"data":{"synthetic":"conflicting"}})
        )
        .status,
        400
    );
    let unchanged = call(&mut service, "GET", SECRET, &first_token, json!({}));
    assert_eq!(unchanged.status, 200);
    assert_eq!(unchanged.body["data"]["metadata"]["version"], 1);
    assert_eq!(unchanged.body["data"]["data"]["synthetic"], "first");
    let second = call(
        &mut service,
        "POST",
        SECRET,
        &first_token,
        json!({"options":{"cas":1},"data":{"synthetic":"second"}}),
    );
    assert_eq!(second.status, 200);
    assert_eq!(second.body["data"]["version"], 2);
    drop(service);

    // Reopen real encrypted storage with no retained Service/State/Root cache.
    let mut service = reopened(&files, &key)?;
    let persisted = call(&mut service, "GET", SECRET, &first_token, json!({}));
    assert_eq!(persisted.status, 200);
    assert_eq!(persisted.body["data"]["metadata"]["version"], 2);
    assert_eq!(persisted.body["data"]["data"]["synthetic"], "second");
    assert_consumed(&mut service, &role_id, &first_secret_id);
    let mut role_response = call(
        &mut service,
        "GET",
        &format!("{ROLE}/role-id"),
        &admin,
        json!({}),
    );
    assert_eq!(role_response.status, 200);
    let reopened_role = secret_field(&mut role_response, "/data/role_id")?;
    assert!(reopened_role.as_str() == role_id.as_str());
    let second_secret_id = issue_secret_id(&mut service, &admin)?;
    let (second_token, second_entity) = login(&mut service, &role_id, &second_secret_id)?;
    assert!(first_entity.as_str() == second_entity.as_str());
    assert_consumed(&mut service, &role_id, &second_secret_id);

    let mut lookup = call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &first_token,
        json!({}),
    );
    assert_eq!(lookup.status, 200);
    let echoed = secret_field(&mut lookup, "/data/id")?;
    assert!(echoed.as_str() == first_token.as_str());
    let mut renewed = call(
        &mut service,
        "POST",
        "auth/token/renew-self",
        &first_token,
        json!({"increment":"10m"}),
    );
    assert_eq!(renewed.status, 200);
    assert_eq!(renewed.body["auth"]["renewable"], true);
    let echoed = secret_field(&mut renewed, "/auth/client_token")?;
    assert!(echoed.as_str() == first_token.as_str());

    // A changed policy must affect the already issued credential, then recover
    // its allowed access when the administrator restores the same named policy.
    for (policy, status) in [(SELF_ONLY_POLICY, 403), (POLICY, 200)] {
        assert_eq!(
            call(
                &mut service,
                "PUT",
                "sys/policies/acl/native-authbus",
                &admin,
                json!({"policy":policy})
            )
            .status,
            204
        );
        assert_eq!(
            call(&mut service, "GET", SECRET, &first_token, json!({})).status,
            status
        );
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/revoke-self",
            &first_token,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(&mut service, "GET", SECRET, &first_token, json!({})).status,
        403
    );
    assert_eq!(
        call(&mut service, "GET", SECRET, &second_token, json!({})).status,
        200
    );
    drop(service);

    let mut service = reopened(&files, &key)?;
    assert_eq!(
        call(&mut service, "GET", SECRET, &first_token, json!({})).status,
        403
    );
    assert_eq!(
        call(&mut service, "GET", SECRET, &second_token, json!({})).status,
        200
    );
    assert_consumed(&mut service, &role_id, &first_secret_id);
    assert_consumed(&mut service, &role_id, &second_secret_id);
    Ok(())
}

#[test]
fn native_token_target_expired_after_real_audit_withholds_lookup_and_accessor_reply() -> TestResult
{
    for path in [
        "auth/token/lookup",
        "auth/token/lookup-accessor",
        "auth/token/renew-accessor",
    ] {
        let (files, mut service, key, admin) = activated()?;
        let mut issued = call(
            &mut service,
            "POST",
            "auth/token/create",
            &admin,
            json!({"policies":["default"],"ttl":"2s","explicit_max_ttl":"2s"}),
        );
        assert_eq!(issued.status, 200);
        let accessor = Zeroizing::new(
            issued.body["auth"]["accessor"]
                .as_str()
                .ok_or("missing synthetic token accessor")?
                .to_owned(),
        );
        let token = secret_field(&mut issued, "/auth/client_token")?;
        let body = if path == "auth/token/lookup" {
            json!({"token":token.as_str()})
        } else if path == "auth/token/renew-accessor" {
            json!({"accessor":accessor.as_str(),"increment":"2s"})
        } else {
            json!({"accessor":accessor.as_str()})
        };
        let started = Instant::now();
        let clock = RequestClock::anchored(SystemTime::now().duration_since(UNIX_EPOCH)?, started)?;
        let _scope =
            crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
        let response = service.handle_inner(RequestView {
            method: "POST",
            path,
            namespace: "",
            token: &admin,
            body: &body,
            now: clock.admitted_at().seconds(),
            admission_started: started,
            token_clock: Some(clock),
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        });
        assert_eq!(response.status, 200);
        assert!(service.pending_native_auth_delivery.is_some());
        // Preserve the original capsule/Clock across actual mandatory audit.
        // Only the target expires; the administrator and original deadline live.
        let response = service.audit_completed_response_with_receipt(
            "native-target-expiry",
            clock.admitted_at().seconds(),
            Some(clock),
            response,
            || std::thread::sleep(Duration::from_millis(2100)),
        );
        assert_eq!(response.status, 200);
        let response =
            service.complete_native_auth_delivery(true, response, "native-target-expiry");
        assert!(response.status >= 300);
        assert!(response.body.get("data").is_none());
        assert!(response.body.get("auth").is_none());
        assert!(response.consistency_index.is_none());
        assert!(service.pending_native_auth_delivery.is_none());
        assert!(!service.recovery_required);
        drop(service);
        let mut service = reopened(&files, &key)?;
        assert_eq!(
            call(&mut service, "GET", SECRET, &token, json!({})).status,
            403
        );
    }
    Ok(())
}

#[test]
fn native_token_lookup_keeps_real_control_group_admission_before_dispatch() -> TestResult {
    let files = Root::new();
    let mut service = files.service()?;
    service.configure_native_v6_candidate()?;
    let (key, admin) = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(30),
        );
        super::super::tests::bootstrap(&mut service)?
    };
    let key = Zeroizing::new(key);
    let admin = Zeroizing::new(admin);
    // Identity management remains outside this native AuthBus slice. Establish
    // a real reviewer group through the prior writer before migrating it.
    assert_eq!(
        call(
            &mut service,
            "POST",
            "identity/group",
            &admin,
            json!({"name":"native-reviewers","type":"internal"})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/internal/native-v6/activate",
            &admin,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/native-controlled",
            &admin,
            json!({"policy":SELF_ONLY_POLICY})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            &format!("sys/auth/{MOUNT}"),
            &admin,
            json!({"type":"approle"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            ROLE,
            &admin,
            json!({"token_policies":["native-controlled"],
                "token_ttl":"10m","token_max_ttl":"20m","secret_id_num_uses":1})
        )
        .status,
        204
    );
    let mut response = call(
        &mut service,
        "GET",
        &format!("{ROLE}/role-id"),
        &admin,
        json!({}),
    );
    assert_eq!(response.status, 200);
    let role_id = secret_field(&mut response, "/data/role_id")?;
    let secret_id = issue_secret_id(&mut service, &admin)?;
    let (token, _) = login(&mut service, &role_id, &secret_id)?;
    let mut response = call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &token,
        json!({}),
    );
    assert_eq!(response.status, 200);
    erase_json(&mut response.body);
    let policy = r#"path "auth/token/lookup-self" {
      capabilities = ["read"]
      control_group = { ttl = "60s" factor "review" {
        identity { group_names = ["native-reviewers"] approvals = 1 self_authorization = false }
      } }
    }"#;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/native-controlled",
            &admin,
            json!({"policy":policy})
        )
        .status,
        204
    );
    for after_reopen in [false, true] {
        if after_reopen {
            drop(service);
            service = reopened(&files, &key)?;
        }
        let response = call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &token,
            json!({}),
        );
        assert!(
            response.status >= 300,
            "native local-auth dispatch bypassed an actual control-group policy"
        );
        assert!(response.body.get("data").is_none());
        assert!(response.body.get("auth").is_none());
        assert!(response.body.get("wrap_info").is_none());
        assert_eq!(
            service
                .state
                .as_ref()
                .ok_or("state")?
                .auth
                .control_group_request_count_for_test(),
            0,
            "unsupported native deferral must not publish a partial control-group owner"
        );
    }
    Ok(())
}

mod verified_tls {
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
        ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
        server::WebPkiClientVerifier,
    };
    use std::io::{Read, Write};
    use std::sync::Arc;

    struct Identity {
        certificates: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    }
    struct Certificates {
        ca: CertificateDer<'static>,
        server: Identity,
        allowed: Identity,
        other: Identity,
    }
    fn private_key() -> TestResult<PKey<Private>> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        Ok(PKey::from_ec_key(EcKey::generate(&group)?)?)
    }
    fn certificates() -> TestResult<Certificates> {
        let ca_key = private_key()?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "synthetic native AuthBus CA")?;
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
            let not_after = Asn1Time::days_from_now(2)?;
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
        Ok(Certificates {
            ca: CertificateDer::from(ca.to_der()?),
            server: leaf(&ca, &ca_key, 2, "localhost", true)?,
            allowed: leaf(&ca, &ca_key, 3, "native-client", false)?,
            other: leaf(&ca, &ca_key, 4, "other-client", false)?,
        })
    }

    // Actual signed Rustls TLS records and Finished messages. There is no
    // dangerous verifier, injected peer chain or assumed successful handshake.
    // The bounded in-memory carrier is not a physical listener qualification.
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
        Err("bounded real TLS record exchange stalled".into())
    }

    fn connected(
        certificates: &Certificates,
        client_identity: Option<&Identity>,
        hostname: &'static str,
    ) -> TestResult<(ClientConnection, ServerConnection)> {
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
            .with_root_certificates(roots);
        let client = match client_identity {
            Some(identity) => client
                .with_client_auth_cert(identity.certificates.clone(), identity.key.clone_key())?,
            None => client.with_no_client_auth(),
        };
        let mut client = ClientConnection::new(Arc::new(client), ServerName::try_from(hostname)?)?;
        let mut server = ServerConnection::new(Arc::new(server))?;
        pump(&mut client, &mut server)?;
        assert!(
            server
                .peer_certificates()
                .is_some_and(|chain| !chain.is_empty())
        );
        Ok((client, server))
    }

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
            Instant::now() + Duration::from_secs(30),
        );
        assert!(!client.is_handshaking() && !server.is_handshaking());
        let mut request = json!({"method":method,"path":path,"token":token,"body":body});
        let request_bytes = Zeroizing::new(serde_json::to_vec(&request)?);
        erase_json(&mut request);
        client.writer().write_all(&request_bytes)?;
        pump(client, server)?;
        let mut plaintext = Zeroizing::new(vec![0; request_bytes.len()]);
        server.reader().read_exact(&mut plaintext)?;
        let mut request: Value = serde_json::from_slice(&plaintext)?;
        let verified_chain = server
            .peer_certificates()
            .ok_or("no actual verified TLS peer")?
            .iter()
            .map(|certificate| certificate.as_ref().to_vec())
            .collect();
        // The only chain admitted below comes from a completed real TLS
        // connection, and every API field comes from its decrypted record.
        let mut response = service.handle_request(ServiceRequest {
            method: request["method"].as_str().ok_or("TLS method")?,
            path: request["path"].as_str().ok_or("TLS path")?,
            namespace: "",
            token: request["token"].as_str().ok_or("TLS token")?,
            body: request["body"].clone(),
            wrap_ttl_seconds: None,
            origin_peer: Some(std::net::IpAddr::from([127, 0, 0, 1])),
            client_certificates: Some(verified_chain),
        });
        erase_json(&mut request);
        assert!(service.pending_native_auth_delivery.is_none());
        let reply = Zeroizing::new(serde_json::to_vec(
            &json!({"status":response.status,"body":response.body}),
        )?);
        erase_json(&mut response.body);
        server.writer().write_all(&reply)?;
        pump(client, server)?;
        let mut received = Zeroizing::new(vec![0; reply.len()]);
        client.reader().read_exact(&mut received)?;
        let mut received: Value = serde_json::from_slice(&received)?;
        let status = u16::try_from(received["status"].as_u64().ok_or("TLS response status")?)?;
        let body = received["body"].take();
        erase_json(&mut received);
        Ok(Response {
            unwrapped_json: None,
            response_headers: Default::default(),
            consistency_index: None,
            status,
            body,
        })
    }

    #[test]
    fn native_cert_auth_uses_verified_tls_peer_and_survives_cold_reopen() -> TestResult {
        let certificates = certificates()?;
        assert!(connected(&certificates, None, "localhost").is_err());
        assert!(connected(&certificates, Some(&certificates.allowed), "wrong.example").is_err());
        let (files, mut service, key, admin) = activated()?;
        assert_eq!(
            call(
                &mut service,
                "PUT",
                "sys/policies/acl/native-authbus",
                &admin,
                json!({"policy":POLICY})
            )
            .status,
            204
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
            204
        );
        let digest = hex(&crypto::digest(
            certificates.allowed.certificates[0].as_ref(),
        ));
        assert_eq!(
            call(
                &mut service,
                "POST",
                "auth/native-cert/certs/client",
                &admin,
                json!({"certificate_sha256":digest,"token_policies":["native-authbus"],
                    "token_ttl":600,"token_max_ttl":1200,"token_type":"service"})
            )
            .status,
            204
        );
        let (mut client, mut server) =
            connected(&certificates, Some(&certificates.allowed), "localhost")?;
        let mut login = call_tls(
            &mut service,
            &mut client,
            &mut server,
            "POST",
            "auth/native-cert/login",
            "",
            json!({"name":"client"}),
        )?;
        assert_eq!(login.status, 200);
        assert!(
            login.body["auth"]["entity_id"]
                .as_str()
                .is_some_and(|id| !id.is_empty())
        );
        let token = secret_field(&mut login, "/auth/client_token")?;
        let (mut other_client, mut other_server) =
            connected(&certificates, Some(&certificates.other), "localhost")?;
        let denied = call_tls(
            &mut service,
            &mut other_client,
            &mut other_server,
            "POST",
            "auth/native-cert/login",
            "",
            json!({"name":"client"}),
        )?;
        assert_eq!(denied.status, 403);
        assert!(denied.body.get("auth").is_none());
        let denied = call_tls(
            &mut service,
            &mut other_client,
            &mut other_server,
            "POST",
            "auth/token/renew-self",
            &token,
            json!({"increment":"10m"}),
        )?;
        assert_eq!(denied.status, 403);
        assert!(denied.body.get("auth").is_none());
        let written = call_tls(
            &mut service,
            &mut client,
            &mut server,
            "POST",
            SECRET,
            &token,
            json!({"options":{"cas":0},"data":{"synthetic":"verified-tls"}}),
        )?;
        assert_eq!(written.status, 200);
        let mut renewed = call_tls(
            &mut service,
            &mut client,
            &mut server,
            "POST",
            "auth/token/renew-self",
            &token,
            json!({"increment":"10m"}),
        )?;
        assert_eq!(renewed.status, 200);
        let echoed = secret_field(&mut renewed, "/auth/client_token")?;
        assert!(echoed.as_str() == token.as_str());
        drop(service);
        drop((client, server, other_client, other_server));

        let mut service = reopened(&files, &key)?;
        let (mut client, mut server) =
            connected(&certificates, Some(&certificates.allowed), "localhost")?;
        let read = call_tls(
            &mut service,
            &mut client,
            &mut server,
            "GET",
            SECRET,
            &token,
            json!({}),
        )?;
        assert_eq!(read.status, 200);
        assert_eq!(read.body["data"]["data"]["synthetic"], "verified-tls");
        let revoked = call_tls(
            &mut service,
            &mut client,
            &mut server,
            "POST",
            "auth/token/revoke-self",
            &token,
            json!({}),
        )?;
        assert_eq!(revoked.status, 204);
        let denied = call_tls(
            &mut service,
            &mut client,
            &mut server,
            "GET",
            SECRET,
            &token,
            json!({}),
        )?;
        assert_eq!(denied.status, 403);
        assert!(denied.body.get("data").is_none());
        Ok(())
    }
}
