use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(1);
struct Root {
    path: PathBuf,
}
impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "heptabao-service-test-{}-{}",
            std::process::id(),
            ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        Self { path }
    }
    fn service(&self) -> Result<Service, Box<dyn std::error::Error>> {
        if !self.path.exists() {
            private_directory(&self.path)?;
        }
        Service::new(self.path.join("data"), &self.path.join("audit.jsonl")).map_err(Into::into)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    service.handle_at(method, path, "", token, body, 100)
}
fn bootstrap(service: &mut Service) -> Result<(String, String), Box<dyn std::error::Error>> {
    let response = call(
        service,
        "PUT",
        "sys/init",
        "",
        json!({"secret_shares":1,"secret_threshold":1,"recovery_nonce":STANDARD.encode([91_u8;32])}),
    );
    assert_eq!(response.status, 200);
    let key = response.body["keys_base64"][0]
        .as_str()
        .ok_or("missing key")?
        .to_owned();
    let token = response.body["root_token"]
        .as_str()
        .ok_or("missing token")?
        .to_owned();
    let ack_token = response.body["init_ack_token"]
        .as_str()
        .ok_or("missing initialization acknowledgement token")?
        .to_owned();
    assert_eq!(
        call(
            service,
            "POST",
            "sys/init/ack",
            "",
            json!({"recovery_nonce":STANDARD.encode([91_u8;32]),"ack_token":ack_token})
        )
        .status,
        204
    );
    assert!(service.state.is_none());
    assert_eq!(
        call(service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    Ok((key, token))
}
fn limited_token(
    service: &mut Service,
    root: &str,
    policy: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let policy_response = call(
        service,
        "PUT",
        "sys/policies/acl/scoped",
        root,
        json!({"policy":policy}),
    );
    assert!(policy_response.status < 300);
    let response = call(
        service,
        "POST",
        "auth/token/create",
        root,
        json!({"policies":["scoped"],"no_default_policy":true,"num_uses":1}),
    );
    assert_eq!(response.status, 200);
    Ok(response.body["auth"]["client_token"]
        .as_str()
        .ok_or("missing limited token")?
        .to_owned())
}

#[test]
fn init_seal_wrong_key_root_policy_kv_restart_and_no_plaintext_disk()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/app",
            &token,
            json!({"data":{"password":"synthetic-private-secret"}})
        )
        .status,
        200
    );
    let reader = limited_token(
        &mut service,
        &token,
        r#"path "secret/data/app" { capabilities = ["read"] }"#,
    )?;
    let read = call(&mut service, "GET", "secret/data/app", &reader, json!({}));
    assert_eq!(read.status, 200);
    assert_eq!(
        read.body["data"]["data"]["password"],
        "synthetic-private-secret"
    );
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &token, json!({})).status,
        204
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &token, json!({})).status,
        503
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":STANDARD.encode([5;32])})
        )
        .status,
        400
    );
    assert!(service.state.is_none());
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "GET", "sys/seal-status", "", json!({})).body["sealed"],
        true
    );
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &token, json!({})).body["data"]["data"]["password"],
        "synthetic-private-secret"
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &reader, json!({})).status,
        403
    );
    for file in [
        "data/state.hbs",
        "data/journal.hbj",
        "data/ledger.hbl",
        "audit.jsonl",
    ] {
        let bytes = fs::read(root.path.join(file))?;
        for secret in ["synthetic-private-secret", token.as_str(), key.as_str()] {
            assert!(!bytes.windows(secret.len()).any(|b| b == secret.as_bytes()));
        }
    }
    Ok(())
}

#[test]
fn finite_use_is_committed_for_acl_denial_and_state_capacity_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let denied = limited_token(
        &mut service,
        &token,
        r#"path "secret/data/allowed" { capabilities = ["read"] }"#,
    )?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/forbidden",
            &denied,
            json!({})
        )
        .status,
        403
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/allowed",
            &denied,
            json!({})
        )
        .status,
        403
    );
    let writer = limited_token(
        &mut service,
        &token,
        r#"path "secret/data/large" { capabilities = ["create", "update", "read"] }"#,
    )?;
    service.state_capacity =
        serde_json::to_vec(service.state.as_ref().ok_or("missing state")?)?.len();
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/large",
            &writer,
            json!({"data":{"value":"x".repeat(4000)}})
        )
        .status,
        507
    );
    service.state_capacity = MAX_STATE_BYTES;
    assert_eq!(
        call(&mut service, "GET", "secret/data/large", &writer, json!({})).status,
        403
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/large", &token, json!({})).status,
        404
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/large", &writer, json!({})).status,
        403
    );
    Ok(())
}

#[test]
fn unknown_commit_releases_no_secret_and_recovers_written_value()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    fs::create_dir(root.path.join("data/ledger.tmp"))?;
    let result = call(
        &mut service,
        "PUT",
        "secret/data/uncertain",
        &token,
        json!({"data":{"value":"uncertain-secret"}}),
    );
    assert_eq!(result.status, 503);
    assert!(result.body["recovery_reference"].is_string());
    assert!(!result.body.to_string().contains("uncertain-secret"));
    assert!(service.recovery_required);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/uncertain",
            &token,
            json!({})
        )
        .status,
        503
    );
    drop(service);
    fs::remove_dir(root.path.join("data/ledger.tmp"))?;
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/uncertain",
            &token,
            json!({})
        )
        .body["data"]["data"]["value"],
        "uncertain-secret"
    );
    Ok(())
}

#[test]
fn failed_engine_and_auth_transactions_leave_only_the_durable_token_consumption()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (_key, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/app",
            &token,
            json!({"data":{"value":"first"}})
        )
        .status,
        200
    );
    let finite = limited_token(
        &mut service,
        &token,
        r#"path "secret/data/app" { capabilities = ["read", "update"] }"#,
    )?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/app",
            &finite,
            json!({"data":{"value":"bad-change"},"options":{"cas":99}})
        )
        .status,
        400
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &finite, json!({})).status,
        403
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &token, json!({})).body["data"]["data"]["value"],
        "first"
    );
    let state_before = serde_json::to_vec(service.state.as_ref().ok_or("missing state")?)?;
    let response = call(
        &mut service,
        "PUT",
        "auth/userpass/users/broken",
        &token,
        json!({"password":"synthetic-password","token_ttl":"not-a-duration"}),
    );
    assert_eq!(response.status, 400);
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("missing state")?)?,
        state_before
    );
    Ok(())
}

#[test]
fn all_failed_routes_are_audited_and_authenticated_audit_rejects_tampering()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    for (method, path, token, body, status) in [
        ("GET", "../invalid", "", json!({}), 400),
        ("GET", "secret/data/app", "invalid-token", json!({}), 403),
        ("PUT", "sys/init", "", json!({}), 400),
    ] {
        let sequence = service.audit_sequence;
        assert_eq!(call(&mut service, method, path, token, body).status, status);
        assert_eq!(service.audit_sequence, sequence + 2);
    }
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &token, json!({})).status,
        204
    );
    let sequence = service.audit_sequence;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":"wrong"})
        )
        .status,
        400
    );
    assert_eq!(service.audit_sequence, sequence + 2);
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert!(root.service().is_err()); // A second audit writer is fenced.
    drop(service);
    let path = root.path.join("audit.jsonl");
    let mut bytes = fs::read(&path)?;
    let index = bytes
        .windows(7)
        .position(|b| b == b"request")
        .ok_or("missing audit request")?;
    bytes[index] = b'X';
    fs::write(path, bytes)?;
    assert!(root.service().is_err());
    Ok(())
}

#[test]
fn result_audit_failure_withholds_plaintext_and_preserves_consumed_token_after_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/app",
            &token,
            json!({"data":{"value":"withhold-this-plaintext"}})
        )
        .status,
        200
    );
    let finite = limited_token(
        &mut service,
        &token,
        r#"path "secret/data/app" { capabilities = ["read"] }"#,
    )?;
    // Reserve exactly the encoded next request audit record, leaving no room for
    // the result record. Admission and token consumption succeed before failure.
    let fingerprint = service.request_fingerprint("GET", "secret/data/app", "", &finite);
    let event = AuditUnsigned {
        schema: 2,
        sequence: service.audit_sequence + 1,
        previous: STANDARD.encode(service.audit_previous),
        time: 100,
        kind: "request".into(),
        path_digest: fingerprint,
        status: None,
    };
    let payload = serde_json::to_vec(&event)?;
    let mac = STANDARD.encode(hmac::sign(&service.audit_key, &payload).as_ref());
    let next = serde_json::to_vec(&AuditRecord { event, mac })?.len() + 1;
    service.audit_capacity = service.audit.metadata()?.len() + next as u64;
    let result = call(&mut service, "GET", "secret/data/app", &finite, json!({}));
    assert_eq!(result.status, 503);
    assert!(!result.body.to_string().contains("withhold-this-plaintext"));
    assert!(service.recovery_required);
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &finite, json!({})).status,
        403
    );
    assert_eq!(
        call(&mut service, "GET", "secret/data/app", &token, json!({})).body["data"]["data"]["value"],
        "withhold-this-plaintext"
    );
    Ok(())
}

#[test]
fn legacy_unkeyed_audit_and_partial_audit_tail_are_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    private_directory(&root.path)?;
    let audit = root.path.join("audit.jsonl");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&audit)?;
    file.write_all(b"{\"schema\":1}\n")?;
    drop(file);
    assert!(root.service().is_err());
    fs::remove_file(&audit)?;
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "GET", "sys/init", "", json!({})).status,
        200
    );
    drop(service);
    let length = fs::metadata(&audit)?.len();
    OpenOptions::new()
        .write(true)
        .open(&audit)?
        .set_len(length - 2)?;
    assert!(root.service().is_err());
    Ok(())
}

#[test]
fn transport_rejections_are_authenticated_without_raw_wire_material()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let before = service.audit_sequence;
    let response = service.handle_transport_rejection_at(
        501,
        "synthetic-wire-secret-must-not-enter-audit",
        100,
    );
    assert_eq!(response.status, 501);
    assert_eq!(service.audit_sequence, before + 2);
    let audit = fs::read(root.path.join("audit.jsonl"))?;
    assert!(
        !audit
            .windows(b"synthetic-wire-secret-must-not-enter-audit".len())
            .any(|window| window == b"synthetic-wire-secret-must-not-enter-audit")
    );
    Ok(())
}

#[test]
fn initialization_credentials_are_recoverable_after_response_audit_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let body = json!({
        "secret_shares": 1,
        "secret_threshold": 1,
        "recovery_nonce": STANDARD.encode([73_u8; 32])
    });

    let capacity_root = Root::new();
    let mut service = capacity_root.service()?;
    let fingerprint = service.request_fingerprint("PUT", "sys/init", "", "");
    let event = AuditUnsigned {
        schema: 2,
        sequence: service.audit_sequence + 1,
        previous: STANDARD.encode(service.audit_previous),
        time: 100,
        kind: "request".into(),
        path_digest: fingerprint,
        status: None,
    };
    let payload = serde_json::to_vec(&event)?;
    let mac = STANDARD.encode(hmac::sign(&service.audit_key, &payload).as_ref());
    let next = serde_json::to_vec(&AuditRecord { event, mac })?.len() + 1;
    service.audit_capacity = service.audit.metadata()?.len() + next as u64;
    assert_eq!(
        call(&mut service, "PUT", "sys/init", "", body.clone()).status,
        503
    );
    assert!(service.init_escrow_path.exists());
    service.audit_capacity = MAX_AUDIT_BYTES;
    let recovered = call(&mut service, "PUT", "sys/init", "", body.clone());
    assert_eq!(recovered.status, 200);
    let key = recovered.body["keys_base64"][0]
        .as_str()
        .ok_or("missing recovered key")?
        .to_owned();
    let token = recovered.body["root_token"]
        .as_str()
        .ok_or("missing recovered root token")?
        .to_owned();
    let ack = recovered.body["init_ack_token"]
        .as_str()
        .ok_or("missing recovered ack token")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/init/ack",
            "",
            json!({"recovery_nonce":STANDARD.encode([73_u8;32]),"ack_token":ack})
        )
        .status,
        204
    );
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "sys/health", &token, json!({})).status,
        200
    );

    let io_root = Root::new();
    let mut service = io_root.service()?;
    service.fail_response_audit_io = true;
    assert_eq!(
        call(&mut service, "PUT", "sys/init", "", body.clone()).status,
        503
    );
    assert!(service.audit_failed);
    assert!(service.init_escrow_path.exists());
    drop(service);
    let mut service = io_root.service()?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/init",
            "",
            json!({
                "secret_shares":1,
                "secret_threshold":1,
                "recovery_nonce":STANDARD.encode([74_u8;32])
            })
        )
        .status,
        403,
        "a different recovery nonce must not disclose initialization credentials"
    );
    let recovered = call(&mut service, "PUT", "sys/init", "", body);
    assert_eq!(recovered.status, 200);
    assert!(recovered.body["root_token"].is_string());
    assert!(recovered.body["keys_base64"][0].is_string());
    Ok(())
}
