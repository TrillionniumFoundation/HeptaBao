//! Anonymous OCSP stays within the actual mounted PKI, encrypted state and
//! original Service admission/audit boundaries.
use super::*;
use openssl::{
    hash::MessageDigest,
    ocsp::{OcspCertId, OcspRequest},
};

use base64::engine::general_purpose::STANDARD as BASE64;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_OCSP: AtomicU64 = AtomicU64::new(0);
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> TestResultWith<Self> {
        let path = std::env::temp_dir().join(format!(
            "heptabao-ocsp-service-{}-{}",
            std::process::id(),
            NEXT_OCSP.fetch_add(1, Ordering::Relaxed)
        ));
        private_directory(&path)?;
        Ok(Self(path))
    }
    fn service(&self) -> TestResultWith<Service> {
        Ok(Service::new(
            self.0.join("data"),
            &self.0.join("audit.jsonl"),
        )?)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn call(
    service: &mut Service,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
    now: u64,
) -> Response {
    service.handle_at(method, path, "", token, body, now)
}
fn text(value: &Value, pointer: &str) -> TestResultWith<String> {
    Ok(value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or("missing response field")?
        .to_owned())
}
fn start(service: &mut Service) -> TestResultWith<(String, String)> {
    let initialized = call(
        service,
        "",
        "POST",
        "sys/init",
        json!({"secret_shares":1,"secret_threshold":1}),
        100,
    );
    assert_eq!(initialized.status, 200);
    let root = text(&initialized.body, "/root_token")?;
    let key = text(&initialized.body, "/keys_base64/0")?;
    assert_eq!(
        call(service, "", "POST", "sys/unseal", json!({"key":key}), 100).status,
        200
    );
    Ok((root, key))
}
fn install(service: &mut Service, root: &str) {
    for (path, body, status) in [
        ("sys/mounts/pki", json!({"type":"pki"}), 204),
        (
            "pki/root/generate/internal",
            json!({"common_name":"ca.example.test","key_type":"ec","key_bits":256,"ttl":"48h"}),
            200,
        ),
        (
            "pki/roles/web",
            json!({"allowed_domains":["example.test"],"allow_subdomains":true,"key_type":"ec","max_ttl":"2h"}),
            200,
        ),
    ] {
        assert_eq!(call(service, root, "POST", path, body, 100).status, status);
    }
}

fn actual_request(service: &mut Service, root: &str) -> TestResultWith<Vec<u8>> {
    let issued = call(
        service,
        root,
        "POST",
        "pki/issue/web",
        json!({"common_name":"leaf.example.test","ttl":"1h"}),
        101,
    );
    assert_eq!(issued.status, 200);
    let leaf = openssl::x509::X509::from_pem(text(&issued.body, "/data/certificate")?.as_bytes())?;
    let issuer = openssl::x509::X509::from_pem(text(&issued.body, "/data/issuing_ca")?.as_bytes())?;
    let mut request = OcspRequest::new()?;
    request.add_id(OcspCertId::from_cert(
        MessageDigest::sha256(),
        &leaf,
        &issuer,
    )?)?;
    Ok(request.to_der()?)
}
type TestResultWith<T> = Result<T, Box<dyn std::error::Error>>;
fn carrier(bytes: &[u8]) -> Value {
    json!({"__heptabao_pki_ocsp_request":BASE64.encode(bytes)})
}
fn get_carrier(path: &str) -> Value {
    json!({"__heptabao_pki_ocsp_get_path": {"path":path,"query":""}})
}

#[test]
fn opaque_get_selects_actual_nested_mount_and_namespace_before_payload_decode() -> TestResult {
    let f = Fixture::new()?;
    let mut service = f.service()?;
    let (root, _) = start(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            &root,
            "POST",
            "sys/namespaces/team",
            json!({}),
            100
        )
        .status,
        200
    );
    let mount = "nested/ocsp/pki";
    for (path, body, status) in [
        (format!("sys/mounts/{mount}"), json!({"type":"pki"}), 204),
        (
            format!("{mount}/root/generate/internal"),
            json!({"common_name":"nested.example.test","key_type":"ec","key_bits":256,"ttl":"48h"}),
            200,
        ),
        (
            format!("{mount}/roles/web"),
            json!({"allowed_domains":["example.test"],"allow_subdomains":true,"key_type":"ec","max_ttl":"2h"}),
            200,
        ),
    ] {
        assert_eq!(
            service
                .handle_at("POST", &path, "team", &root, body, 100)
                .status,
            status
        );
    }
    let leaf = service.handle_at(
        "POST",
        &format!("{mount}/issue/web"),
        "team",
        &root,
        json!({"common_name":"leaf.example.test","ttl":"1h"}),
        101,
    );
    assert_eq!(leaf.status, 200);
    let issuer = openssl::x509::X509::from_pem(text(&leaf.body, "/data/issuing_ca")?.as_bytes())?;
    // Construct a genuine maintained-parser request whose serial encodes a
    // literal `/ocsp/`. Serial alignment is varied without changing the issuer.
    let serial_fragment = BASE64.decode("AA/ocsp/AAA=")?;
    let mut request = None;
    for pad in 0..3 {
        let mut serial = vec![0x41; pad + 1];
        serial.extend_from_slice(&serial_fragment);
        let number = openssl::bn::BigNum::from_slice(&serial)?.to_asn1_integer()?;
        let mut certificate = openssl::x509::X509::builder()?;
        certificate.set_serial_number(&number)?;
        certificate.set_issuer_name(issuer.subject_name())?;
        let mut ocsp = OcspRequest::new()?;
        ocsp.add_id(OcspCertId::from_cert(
            MessageDigest::sha256(),
            &certificate.build(),
            &issuer,
        )?)?;
        let encoded = BASE64.encode(ocsp.to_der()?);
        if encoded.contains("/ocsp/") {
            request = Some(encoded);
            break;
        }
    }
    let encoded = request.ok_or("literal base64 OCSP fragment")?;
    for suffix in [
        encoded.clone(),
        encoded
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D"),
    ] {
        let path = format!("{mount}/ocsp/{suffix}");
        let response = service.handle_at("GET", &path, "team", "", get_carrier(&path), 102);
        assert_raw(&response, 200);
        let raw =
            crate::engines::raw_ocsp_response(response.status, &response.body).ok_or("raw OCSP")?;
        let parsed = openssl::ocsp::OcspResponse::from_der(&raw)?;
        assert_eq!(
            parsed.status(),
            openssl::ocsp::OcspResponseStatus::SUCCESSFUL
        );
        let mut issuers = openssl::stack::Stack::new()?;
        issuers.push(issuer.clone())?;
        let mut trust = openssl::x509::store::X509StoreBuilder::new()?;
        trust.add_cert(issuer.clone())?;
        let mut clock = openssl::x509::verify::X509VerifyParam::new()?;
        clock.set_time(102);
        trust.set_param(&clock)?;
        parsed
            .basic()?
            .verify(&issuers, &trust.build(), openssl::ocsp::OcspFlag::empty())?;
    }
    let actual = format!("{mount}/ocsp/{encoded}");
    for (namespace, path) in [
        ("", actual.clone()),
        ("missing", actual.clone()),
        ("team", "secret/ocsp/AA%2F%3D".into()),
        ("team", "sys/mounts/ocsp/AA==".into()),
        ("team", "unknown/ocsp/AA==".into()),
    ] {
        let response = service.handle_at("GET", &path, namespace, &root, get_carrier(&path), 102);
        assert_ne!(response.status, 200);
        assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_none());
    }
    for body in [
        json!({"__heptabao_pki_ocsp_get_path":"other/ocsp/AA=="}),
        json!({"__heptabao_pki_ocsp_get_path":actual,"extra":true}),
    ] {
        assert_eq!(
            service
                .handle_at("GET", &actual, "team", "", body, 102)
                .status,
            400
        );
    }
    assert_eq!(
        service
            .handle_at(
                "POST",
                &format!("{mount}/config/crl"),
                "team",
                &root,
                json!({"ocsp_disable":true}),
                103
            )
            .status,
        200
    );
    let malformed = format!("{mount}/ocsp/%gg");
    assert_raw(
        &service.handle_at("GET", &malformed, "team", "", get_carrier(&malformed), 103),
        401,
    );
    Ok(())
}

fn assert_raw(response: &Response, status: u16) {
    assert_eq!(response.status, status);
    assert!(crate::engines::raw_ocsp_response(status, &response.body).is_some());
}

#[test]
fn anonymous_ocsp_mount_namespace_restart_seal_deadline_and_audit() -> TestResult {
    let f = Fixture::new()?;
    let mut service = f.service()?;
    let (root, key) = start(&mut service)?;
    install(&mut service, &root);
    let request = actual_request(&mut service, &root)?;
    assert_raw(
        &call(&mut service, "", "POST", "pki/ocsp", carrier(&request), 102),
        200,
    );
    assert_raw(
        &call(&mut service, "", "GET", "pki/ocsp", carrier(&request), 102),
        200,
    );
    let malformed = call(
        &mut service,
        "",
        "POST",
        "pki/ocsp",
        carrier(b"different request"),
        102,
    );
    assert_raw(&malformed, 400);
    let audit = fs::read_to_string(f.0.join("audit.jsonl"))?;
    let events: Vec<Value> = audit
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let requests: Vec<&Value> = events
        .iter()
        .filter(|record| record["event"]["kind"] == "request")
        .collect();
    let valid = requests
        .get(requests.len().saturating_sub(2))
        .ok_or("valid request event")?;
    let invalid = requests.last().ok_or("invalid request event")?;
    assert_ne!(
        valid["event"]["path_digest"],
        invalid["event"]["path_digest"]
    );
    assert!(!audit.contains(&BASE64.encode(&request)));
    assert!(!audit.contains(&root));
    assert!(!audit.contains("PRIVATE KEY"));
    for (namespace, path) in [
        ("missing", "pki/ocsp"),
        ("", "secret/ocsp"),
        ("", "missing/ocsp"),
    ] {
        let response = service.handle_at("POST", path, namespace, "", carrier(&request), 102);
        assert_ne!(response.status, 200);
        assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_none());
    }
    {
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
            std::time::Instant::now() - std::time::Duration::from_secs(1),
        );
        let response = call(&mut service, "", "POST", "pki/ocsp", carrier(&request), 102);
        assert_eq!(response.status, 503);
        assert!(crate::engines::raw_ocsp_response(response.status, &response.body).is_none());
    }
    drop(service);
    let mut service = f.service()?;
    let sealed = call(&mut service, "", "POST", "pki/ocsp", carrier(&request), 103);
    assert_eq!(sealed.status, 503);
    assert!(crate::engines::raw_ocsp_response(sealed.status, &sealed.body).is_none());
    assert_eq!(
        call(
            &mut service,
            "",
            "POST",
            "sys/unseal",
            json!({"key":key}),
            103
        )
        .status,
        200
    );
    assert_raw(
        &call(&mut service, "", "POST", "pki/ocsp", carrier(&request), 103),
        200,
    );
    assert_eq!(
        call(
            &mut service,
            &root,
            "POST",
            "pki/config/crl",
            json!({"ocsp_disable":true}),
            104
        )
        .status,
        200
    );
    assert_raw(
        &call(
            &mut service,
            "",
            "POST",
            "pki/ocsp",
            carrier(b"malformed"),
            104,
        ),
        401,
    );
    service.audit_failed = true;
    let denied = call(&mut service, "", "POST", "pki/ocsp", carrier(&request), 104);
    assert_eq!(denied.status, 503);
    assert!(crate::engines::raw_ocsp_response(denied.status, &denied.body).is_none());
    Ok(())
}
