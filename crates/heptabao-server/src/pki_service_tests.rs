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
    install_with_key_type(service, root, None);
}
fn install_with_key_type(service: &mut Service, root: &str, key_type: Option<&str>) {
    let mut root_body = json!({"common_name":"ca.example.test","ttl":"48h"});
    let mut role_body = json!({"allowed_domains":["example.test"],"allow_subdomains":true,"max_ttl":"2h","generate_lease":true});
    if let Some(key_type) = key_type {
        root_body["key_type"] = json!(key_type);
        role_body["key_type"] = json!(key_type);
    }
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
            root_body,
            100
        )
        .status,
        200
    );
    assert_eq!(
        call(service, root, "POST", "pki/roles/web", role_body, 100).status,
        200
    );
}
fn pem_der(value: &str, label: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let value = value.strip_suffix('\n').unwrap_or(value);
    let body = value
        .strip_prefix(&format!("{begin}\n"))
        .and_then(|v| v.strip_suffix(&end))
        .ok_or("bad pem")?;
    Ok(BASE64.decode(body.lines().collect::<String>())?)
}

#[test]
fn pem_der_accepts_canonical_and_public_footer_without_final_lf() -> TestResult {
    let public = "-----BEGIN X509 CRL-----\nMAA=\n-----END X509 CRL-----";
    assert_eq!(pem_der(public, "X509 CRL")?, vec![0x30, 0x00]);
    assert_eq!(
        pem_der(&format!("{public}\n"), "X509 CRL")?,
        vec![0x30, 0x00]
    );
    for malformed in [
        format!("{public}\n\n"),
        public.replace("-----END X509 CRL-----", "-----END CERTIFICATE-----"),
        public.replace("-----BEGIN X509 CRL-----", "-----BEGIN CERTIFICATE-----"),
        public.replace('\n', "\r\n"),
    ] {
        assert!(pem_der(&malformed, "X509 CRL").is_err());
    }
    Ok(())
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
    assert!(pem_der(&private_key, "RSA PRIVATE KEY")?.len() > 32);
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
    assert_eq!(
        call(&mut s, &root, "GET", "pki/roles/web", json!({}), 101).body["data"]["allow_ip_sans"],
        true,
        "real new-role IP default remains independent of explicit denial"
    );
    assert_eq!(call(&mut s, &root, "POST", "pki/roles/web-no-ip",
        json!({"allowed_domains":["example.test"],"allow_subdomains":true,"allow_ip_sans":false}), 101).status, 200);
    let denied = call(
        &mut s,
        &root,
        "POST",
        "pki/issue/web-no-ip",
        json!({"common_name":"api.example.test","ip_sans":["127.0.0.1"]}),
        101,
    );
    assert_eq!(denied.status, 400);
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
    let warned = call(
        &mut s,
        &root,
        "POST",
        "pki/config/acme",
        json!({"enabled":false,"unknown":"ignored-value-must-not-persist"}),
        101,
    );
    assert_eq!(warned.status, 200);
    assert_eq!(warned.body["data"]["enabled"], false);
    assert!(
        warned.body["warnings"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
    );
    assert!(
        !warned
            .body
            .to_string()
            .contains("ignored-value-must-not-persist")
    );
    assert_eq!(
        call(&mut s, &root, "GET", "pki/config/acme", json!({}), 101).body["data"]["enabled"],
        false
    );
    assert!(
        !serde_json::to_string(s.state.as_ref().ok_or("state")?)?
            .contains("ignored-value-must-not-persist")
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            "POST",
            "pki/config/acme",
            json!({"enabled":true}),
            101
        )
        .status,
        200
    );
    let before = call(&mut s, &root, "GET", "pki/config/acme", json!({}), 101)
        .body
        .clone();
    for (path, body, expected_status) in [
        (
            "pki/config/acme",
            json!({"enabled":"invalid-bool","unknown":"must-not-persist"}),
            400,
        ),
        (
            "pki/config/cluster",
            json!({"path":"file:///secret-location"}),
            500,
        ),
        (
            "pki/config/cluster",
            json!({"path":"https://private-user:private-password@private.example/secret-location"}),
            500,
        ),
    ] {
        let rejected = call(&mut s, &root, "POST", path, body, 101);
        assert_eq!(rejected.status, expected_status);
        assert!(!rejected.body.to_string().contains("must-not-persist"));
        assert!(!rejected.body.to_string().contains("secret-location"));
        assert!(!rejected.body.to_string().contains("private-password"));
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

#[test]
fn pki_new_default_identifiers_require_schema75_and_reject_legacy_labels() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    install(&mut s, &root);
    let role = call(&mut s, &root, "GET", "pki/roles/web", json!({}), 101);
    assert_eq!(role.status, 200);
    assert_eq!(role.body["data"]["key_type"], "rsa");
    assert_eq!(role.body["data"]["key_bits"], 2048);
    let state = s.state.as_ref().ok_or("state")?;
    assert!(state.engines.has_local_typed_pki_state());
    assert!(state.engines.has_local_pki_crl_state());
    assert_eq!(state.schema, LOCAL_PKI_CRL_STATE_SCHEMA);
    assert_eq!(state.writer_schema(), LOCAL_PKI_CRL_STATE_SCHEMA);
    assert!(state.validate_format().is_ok());
    // Isolate the historical identifier floor from the CRL cache now created
    // by a real root. The production state above must retain the current floor.
    let mut encoded = serde_json::to_value(&state.engines)?;
    encoded
        .pointer_mut("/namespaces//mounts/pki~1/backend/Pki")
        .and_then(Value::as_object_mut)
        .ok_or("identifier-only PKI projection")?
        .remove("local_crl");
    let mut state = state.clone();
    state.engines = serde_json::from_value(encoded)?;
    state.schema = LOCAL_PKI_IDENTIFIER_STATE_SCHEMA;
    assert!(state.engines.has_local_pki_identifier_state());
    assert!(!state.engines.has_local_pki_crl_state());
    assert_eq!(state.writer_schema(), LOCAL_PKI_IDENTIFIER_STATE_SCHEMA);
    assert!(state.validate_format().is_ok());
    for schema in [
        57,
        59,
        CURRENT_STATE_SCHEMA,
        LOCAL_TYPED_PKI_STATE_SCHEMA,
        INDEXED_RECOVERY_WIRE_STATE_SCHEMA,
    ] {
        let mut disguised = state.clone();
        disguised.schema = schema;
        let rejected = disguised
            .validate_format()
            .err()
            .ok_or("typed local key admitted as historical PKI shape")?;
        assert_eq!(rejected.status, 503);
        assert_eq!(
            rejected.body["errors"][0],
            "local PKI identifiers require schema 75"
        );
    }
    Ok(())
}

#[test]
fn pki_default_shape_remains_readable_as_schema57_without_new_fields() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    install_with_key_type(&mut s, &root, Some("ed25519"));
    let state = s.state.as_ref().ok_or("state")?;
    assert!(!state.engines.has_local_typed_pki_state());
    assert!(!state.engines.has_pki_extension_state());
    let mut encoded = serde_json::to_value(&state.engines)?;
    encoded
        .pointer_mut("/namespaces//mounts/pki~1/backend/Pki")
        .and_then(Value::as_object_mut)
        .ok_or("legacy PKI projection")?
        .remove("local_crl");
    let legacy_root = encoded
        .pointer_mut("/namespaces//mounts/pki~1/backend/Pki/root")
        .and_then(Value::as_object_mut)
        .ok_or("legacy root projection")?;
    legacy_root.remove("issuer_id");
    legacy_root.remove("key_id");
    let text = Zeroizing::new(encoded.to_string());
    assert!(!text.contains("\"cluster_path\""));
    assert!(!text.contains("\"aia_path\""));
    assert!(!text.contains("\"acme\""));
    let mut legacy = state.clone();
    legacy.engines = serde_json::from_value(encoded)?;
    assert!(!legacy.engines.has_local_pki_identifier_state());
    assert!(!legacy.engines.has_local_pki_crl_state());
    legacy.schema = 57;
    assert!(legacy.validate_format().is_ok());
    let bytes = serde_json::to_vec(&legacy)?;
    let reopened: State = serde_json::from_slice(&bytes)?;
    assert!(reopened.validate_format().is_ok());
    assert_eq!(bytes, serde_json::to_vec(&reopened)?);
    Ok(())
}

#[test]
fn pki_extension_state_requires_schema59_independently() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    assert_eq!(
        call(
            &mut s,
            &root,
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
            &mut s,
            &root,
            "POST",
            "pki/config/cluster",
            json!({"path":"https://acme.example.test/v1/pki"}),
            101,
        )
        .status,
        200
    );
    let state = s.state.as_ref().ok_or("state")?;
    assert!(!state.engines.has_local_typed_pki_state());
    assert!(!state.engines.has_local_pki_identifier_state());
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    assert!(state.engines.has_pki_extension_state());
    assert!(state.validate_format().is_ok());
    for schema in [57, 58] {
        let mut disguised = state.clone();
        disguised.schema = schema;
        let rejected = disguised
            .validate_format()
            .err()
            .ok_or("pre-PKI schema admitted PKI extension state")?;
        assert_eq!(rejected.status, 503);
        assert_eq!(
            rejected.body["errors"][0],
            "PKI cluster or ACME configuration requires schema 59"
        );
    }
    Ok(())
}

#[test]
fn pki_root_formats_preserve_acl_and_encrypted_restart_public_der() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, key) = start(&mut s)?;
    let root = zeroize::Zeroizing::new(root);
    let key = zeroize::Zeroizing::new(key);
    let mut expected = Vec::new();
    for (index, format) in ["pem", "der", "pem_bundle"].into_iter().enumerate() {
        let mount = format!("rootfmt{index}");
        assert!(
            call(
                &mut s,
                &root,
                "POST",
                &format!("sys/mounts/{mount}"),
                json!({"type":"pki"}),
                100
            )
            .status
                == 204,
            "format fixture mount failed"
        );
        let body = json!({"common_name":"Synthetic Format Root", "ttl":"1h", "key_type":"ed25519", "format":format, "private_key_format":"unknown-internal-format"});
        let before = zeroize::Zeroizing::new(serde_json::to_vec(s.state.as_ref().ok_or("state")?)?);
        let denied = call(
            &mut s,
            "invalid-format-token",
            "POST",
            &format!("{mount}/root/generate/internal"),
            body.clone(),
            100,
        );
        assert!(
            denied.status == 403,
            "format route bypassed caller authorization"
        );
        let invalid = call(
            &mut s,
            &root,
            "POST",
            &format!("{mount}/root/generate/internal"),
            json!({"common_name":"Synthetic Format Root", "key_type":"ed25519", "format":null}),
            100,
        );
        assert!(invalid.status == 400, "invalid format did not reject");
        let after = zeroize::Zeroizing::new(serde_json::to_vec(s.state.as_ref().ok_or("state")?)?);
        assert!(
            before.as_slice() == after.as_slice(),
            "denial published state"
        );
        let generated = call(
            &mut s,
            &root,
            "POST",
            &format!("{mount}/root/generate/internal"),
            body,
            100,
        );
        assert!(generated.status == 200, "internal format generation failed");
        assert!(
            generated.body["data"].get("private_key").is_none(),
            "internal generation exposes private field"
        );
        let certificate = text(&generated.body, "/data/certificate")?;
        let issuing_ca = text(&generated.body, "/data/issuing_ca")?;
        assert!(
            certificate == issuing_ca,
            "response CA does not match certificate"
        );
        let der = if format == "der" {
            BASE64.decode(&certificate)?
        } else {
            assert!(!certificate.ends_with('\n'), "internal PEM has final LF");
            pem_der(&certificate, "CERTIFICATE")?
        };
        let cert = openssl::x509::X509::from_der(&der)?;
        let public = cert.public_key()?;
        assert!(cert.verify(&public)?, "root actual signature invalid");
        let read = call(
            &mut s,
            "",
            "GET",
            &format!("{mount}/cert/ca"),
            json!({}),
            100,
        );
        assert!(read.status == 200, "anonymous CA read failed");
        assert!(
            pem_der(&text(&read.body, "/data/certificate")?, "CERTIFICATE")? == der,
            "CA read does not match original DER"
        );
        expected.push((mount, der));
    }
    drop(s);
    let mut s = f.service()?;
    assert!(
        call(
            &mut s,
            "",
            "POST",
            "sys/unseal",
            json!({"key":key.as_str()}),
            101
        )
        .status
            == 200,
        "format fixture reopen failed"
    );
    for (mount, der) in expected {
        let read = call(
            &mut s,
            "",
            "GET",
            &format!("{mount}/cert/ca"),
            json!({}),
            101,
        );
        assert!(read.status == 200, "restarted CA read failed");
        let actual = pem_der(&text(&read.body, "/data/certificate")?, "CERTIFICATE")?;
        assert!(actual == der, "encrypted restart changed stored DER");
        let cert = openssl::x509::X509::from_der(&actual)?;
        let public = cert.public_key()?;
        assert!(
            cert.verify(&public)?,
            "restarted root actual signature invalid"
        );
        assert!(
            read.body["data"].get("private_key").is_none(),
            "restarted public read exposes private field"
        );
    }
    Ok(())
}
