//! Service-level PKI persistence, lease revocation and encrypted-at-rest checks.
use super::*;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_PKI: AtomicU64 = AtomicU64::new(0);
type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "heptabao-pki-{}-{}",
            std::process::id(),
            NEXT_PKI.fetch_add(1, Ordering::Relaxed)
        ));
        private_directory(&path)?;
        Ok(Self(path))
    }
    fn service(&self) -> Result<Service, Box<dyn std::error::Error>> {
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
fn text(value: &Value, pointer: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or("missing field")?
        .to_owned())
}
fn start(service: &mut Service) -> Result<(String, String), Box<dyn std::error::Error>> {
    let init = call(
        service,
        "",
        "POST",
        "sys/init",
        json!({"secret_shares":1,"secret_threshold":1}),
        100,
    );
    assert_eq!(init.status, 200);
    let root = text(&init.body, "/root_token")?;
    let key = text(&init.body, "/keys_base64/0")?;
    assert_eq!(
        call(service, "", "POST", "sys/unseal", json!({"key":key}), 100).status,
        200
    );
    Ok((root, key))
}
fn install(service: &mut Service, root: &str) {
    assert_eq!(
        call(
            service,
            root,
            "POST",
            "sys/mounts/pki",
            json!({"type":"pki"}),
            100
        )
        .status,
        204
    );
    assert_eq!(
        call(
            service,
            root,
            "POST",
            "pki/root/generate/internal",
            json!({"common_name":"ca.example.test","ttl":"48h"}),
            100
        )
        .status,
        200
    );
    assert_eq!(
        call(
            service,
            root,
            "POST",
            "pki/roles/web",
            json!({"allowed_domains":["example.test"],"allow_subdomains":true,"max_ttl":"2h","generate_lease":true}),
            100
        )
        .status,
        200
    );
}
fn pem_der(value: &str, label: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = value
        .strip_prefix(&format!("{begin}\n"))
        .and_then(|v| v.strip_suffix(&format!("{end}\n")))
        .ok_or("bad pem")?;
    Ok(BASE64.decode(body.lines().collect::<String>())?)
}

#[test]
fn pki_issue_persists_encrypted_and_lease_revoke_publishes_crl() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, key) = start(&mut s)?;
    install(&mut s, &root);
    let issued = call(
        &mut s,
        &root,
        "POST",
        "pki/issue/web",
        json!({"common_name":"api.example.test","alt_names":["www.example.test"],"ttl":"1h"}),
        101,
    );
    assert_eq!(issued.status, 200);
    let lease = text(&issued.body, "/lease_id")?;
    let serial = text(&issued.body, "/data/serial_number")?;
    let private_key = text(&issued.body, "/data/private_key")?;
    let certificate = text(&issued.body, "/data/certificate")?;
    let der = pem_der(&certificate, "CERTIFICATE")?;
    assert_eq!(der.first(), Some(&0x30));
    assert!(pem_der(&private_key, "PRIVATE KEY")?.len() > 32);
    assert_eq!(
        call(
            &mut s,
            &root,
            "POST",
            "sys/leases/lookup",
            json!({"lease_id":lease}),
            101
        )
        .status,
        200
    );
    for entry in fs::read_dir(f.0.join("data"))? {
        let path = entry?.path();
        if path.is_file() {
            let bytes = fs::read(path)?;
            assert!(
                !bytes
                    .windows(private_key.len())
                    .any(|w| w == private_key.as_bytes())
            );
        }
    }
    assert_eq!(
        call(
            &mut s,
            &root,
            "POST",
            "sys/leases/revoke",
            json!({"lease_id":lease}),
            102
        )
        .status,
        204
    );
    let cert = call(
        &mut s,
        &root,
        "GET",
        &format!("pki/cert/{serial}"),
        json!({}),
        102,
    );
    assert_eq!(cert.status, 200);
    assert_eq!(cert.body["data"]["revocation_time"], 102);
    let crl = call(&mut s, &root, "GET", "pki/cert/crl", json!({}), 102);
    assert_eq!(crl.status, 200);
    let crl_der = pem_der(
        crl.body["data"]["certificate"].as_str().ok_or("crl")?,
        "X509 CRL",
    )?;
    assert_eq!(crl_der.first(), Some(&0x30));
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "POST", "sys/unseal", json!({"key":key}), 103).status,
        200
    );
    let cert = call(
        &mut s,
        &root,
        "GET",
        &format!("pki/cert/{serial}"),
        json!({}),
        103,
    );
    assert_eq!(cert.body["data"]["revocation_time"], 102);
    Ok(())
}

#[test]
fn pki_rejects_domain_escape_and_unknown_fields_without_mutation() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    install(&mut s, &root);
    let before = serde_json::to_vec(s.state.as_ref().ok_or("state")?)?;
    for body in [
        json!({"common_name":"example.invalid"}),
        json!({"common_name":"evil-example.test"}),
        json!({"common_name":"api.example.test","unknown":true}),
    ] {
        let denied = call(&mut s, &root, "POST", "pki/issue/web", body, 101);
        assert!(matches!(denied.status, 400 | 403));
        assert_eq!(
            serde_json::to_vec(s.state.as_ref().ok_or("state")?)?,
            before
        );
    }
    Ok(())
}

#[test]
fn pki_ip_sans_require_role_permission_and_are_encoded_as_ip_general_names() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    install(&mut s, &root);
    let denied = call(
        &mut s,
        &root,
        "POST",
        "pki/issue/web",
        json!({"common_name":"api.example.test","ip_sans":["127.0.0.1"]}),
        101,
    );
    assert_eq!(denied.status, 403);
    assert_eq!(
        call(
            &mut s,
            &root,
            "POST",
            "pki/roles/web-ip",
            json!({"allowed_domains":["example.test"],"allow_subdomains":true,"allow_ip_sans":true}),
            101,
        )
        .status,
        200
    );
    let issued = call(
        &mut s,
        &root,
        "POST",
        "pki/issue/web-ip",
        json!({"common_name":"api.example.test","ip_sans":["127.0.0.1","2001:db8::1"]}),
        101,
    );
    assert_eq!(issued.status, 200);
    let certificate = text(&issued.body, "/data/certificate")?;
    let der = pem_der(&certificate, "CERTIFICATE")?;
    assert!(der.windows(6).any(|w| w == [0x87, 0x04, 127, 0, 0, 1]));
    assert!(der.windows(18).any(|w| w[0] == 0x87 && w[1] == 0x10));
    Ok(())
}

#[test]
fn pki_extension_configuration_is_hostile_bounded_and_persists_after_restart() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, key) = start(&mut s)?;
    install(&mut s, &root);
    let unauthorized = call(
        &mut s,
        "invalid-pkiext-token",
        "GET",
        "pki/config/cluster",
        json!({}),
        101,
    );
    assert_eq!(unauthorized.status, 403);
    assert!(!unauthorized.body.to_string().contains("private_key"));
    assert_eq!(
        call(
            &mut s,
            &root,
            "POST",
            "pki/config/cluster",
            json!({
                "path":"https://acme.example.test/v1/pki",
                "aia_path":"http://cdn.example.test/pki"
            }),
            101,
        )
        .status,
        200
    );
    let enabled = call(
        &mut s,
        &root,
        "POST",
        "pki/config/acme",
        json!({"enabled":true,"eab_policy":"new-account-required"}),
        101,
    );
    assert_eq!(enabled.status, 200);
    assert_eq!(enabled.body["data"]["enabled"], true);
    assert_eq!(enabled.body["data"]["eab_policy"], "new-account-required");
    let before = call(&mut s, &root, "GET", "pki/config/acme", json!({}), 101)
        .body
        .clone();
    for (path, body) in [
        (
            "pki/config/acme",
            json!({"enabled":false,"unknown":"must-not-persist"}),
        ),
        (
            "pki/config/cluster",
            json!({"path":"file:///secret-location"}),
        ),
    ] {
        let rejected = call(&mut s, &root, "POST", path, body, 101);
        assert_eq!(rejected.status, 400);
        assert!(!rejected.body.to_string().contains("must-not-persist"));
        assert!(!rejected.body.to_string().contains("secret-location"));
    }
    assert_eq!(
        call(&mut s, &root, "GET", "pki/config/acme", json!({}), 101,).body,
        before
    );
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "POST", "sys/unseal", json!({"key":key}), 102).status,
        200
    );
    let reopened = call(&mut s, &root, "GET", "pki/config/acme", json!({}), 102);
    assert_eq!(reopened.status, 200);
    assert_eq!(reopened.body, before);
    assert_eq!(
        call(&mut s, &root, "GET", "pki/config/cluster", json!({}), 102,).body["data"],
        json!({
            "path":"https://acme.example.test/v1/pki",
            "aia_path":"http://cdn.example.test/pki"
        })
    );
    Ok(())
}

#[test]
fn pki_extension_protocol_routes_remain_explicitly_unsupported() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    install(&mut s, &root);
    for path in [
        "pki/acme/directory",
        "pki/acme/new-account",
        "pki/acme/new-order",
        "pki/acme/revoke-cert",
    ] {
        let response = call(&mut s, &root, "GET", path, json!({}), 101);
        assert_eq!(response.status, 404, "{path}");
        assert!(!response.body.to_string().contains("private_key"));
    }
    Ok(())
}
