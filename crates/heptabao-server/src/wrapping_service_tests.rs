//! Only synthetic credentials and private temporary state; exercises Service,
//! encrypted durable storage, audit failure and schema admission together.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "heptabao-wrapping-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
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
fn text(value: &Value, pointer: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or("missing field")?
        .to_owned())
}
fn call(service: &mut Service, token: &str, path: &str, body: Value) -> Response {
    service.handle_at("POST", path, "", token, body, 100)
}
fn wrapped(
    service: &mut Service,
    token: &str,
    namespace: &str,
    path: &str,
    body: Value,
) -> Response {
    service.handle_request_at(
        ServiceRequest {
            method: "POST",
            path,
            namespace,
            token,
            body,
            wrap_ttl_seconds: Some(60),
            origin_peer: None,
            client_certificates: None,
        },
        100,
    )
}
fn start(service: &mut Service) -> Result<(String, String), Box<dyn std::error::Error>> {
    let init = call(
        service,
        "",
        "sys/init",
        json!({"secret_shares":1,"secret_threshold":1}),
    );
    assert_eq!(init.status, 200);
    let root = text(&init.body, "/root_token")?;
    let key = text(&init.body, "/keys_base64/0")?;
    assert_eq!(
        call(service, "", "sys/unseal", json!({"key":key})).status,
        200
    );
    Ok((root, key))
}
fn snapshot(service: &Service) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(serde_json::to_vec(service.state.as_ref().ok_or("state")?)?)
}

#[test]
fn wrapping_survives_reopen_and_replay_never_releases_payload() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, key) = start(&mut s)?;
    let original =
        json!({"secret":"synthetic-wrapped-payload","entity_id":"user-data-not-an-identity"});
    let r = wrapped(&mut s, &root, "", "sys/wrapping/wrap", original.clone());
    assert_eq!(r.status, 200);
    assert!(r.body["data"].is_null());
    assert!(r.body["auth"].is_null());
    let token = text(&r.body, "/wrap_info/token")?;
    assert_eq!(r.body["wrap_info"]["ttl"], 60);
    assert_eq!(r.body["wrap_info"]["creation_path"], "sys/wrapping/wrap");
    for _ in 0..2 {
        let r = s.handle_at("GET", "sys/wrapping/lookup", "", &token, json!({}), 100);
        assert_eq!(r.status, 200);
        assert_eq!(r.body["data"]["creation_ttl"], 60);
        assert!(!r.body.to_string().contains("synthetic-wrapped-payload"));
    }
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "sys/unseal", json!({"key":key})).status,
        200
    );
    let r = call(&mut s, &token, "sys/wrapping/unwrap", json!({}));
    assert_eq!(r.status, 200);
    assert_eq!(r.body["data"], original);
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut s, &token, "sys/wrapping/unwrap", json!({})).status,
        400
    );
    assert_eq!(
        call(&mut s, &root, "sys/wrapping/lookup", json!({"token":token})).status,
        400
    );
    for relative in [
        "data/state.hbs",
        "data/journal.hbj",
        "data/ledger.hbl",
        "audit.jsonl",
    ] {
        let bytes = fs::read(f.0.join(relative))?;
        for forbidden in ["synthetic-wrapped-payload", token.as_str()] {
            assert!(
                !bytes
                    .windows(forbidden.len())
                    .any(|w| w == forbidden.as_bytes())
            );
        }
    }
    Ok(())
}

#[test]
fn wrapping_rewrap_is_atomic_preserves_origin_and_rotates_token() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    let r = wrapped(
        &mut s,
        &root,
        "",
        "sys/wrapping/wrap",
        json!({"v":"synthetic"}),
    );
    let old = text(&r.body, "/wrap_info/token")?;
    let new = s.handle_at(
        "POST",
        "sys/wrapping/rewrap",
        "",
        &root,
        json!({"token":old}),
        120,
    );
    assert_eq!(new.status, 200);
    assert_eq!(new.body["wrap_info"]["ttl"], 60);
    assert_eq!(new.body["wrap_info"]["creation_path"], "sys/wrapping/wrap");
    let new = text(&new.body, "/wrap_info/token")?;
    assert_ne!(new, old);
    assert_eq!(
        call(&mut s, &root, "sys/wrapping/unwrap", json!({"token":old})).status,
        400
    );
    let result = call(&mut s, &root, "sys/wrapping/unwrap", json!({"token":new}));
    assert_eq!(result.status, 200);
    assert_eq!(result.body["data"], json!({"v":"synthetic"}));
    assert_eq!(
        call(&mut s, &root, "sys/wrapping/unwrap", json!({"token":new})).status,
        400
    );
    Ok(())
}

#[test]
fn wrapping_expiry_observation_survives_clock_rollback_and_restart() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, key) = start(&mut s)?;
    let r = wrapped(
        &mut s,
        &root,
        "",
        "sys/wrapping/wrap",
        json!({"v":"synthetic"}),
    );
    let token = text(&r.body, "/wrap_info/token")?;
    assert_eq!(
        s.handle_at("GET", "sys/wrapping/lookup", "", &token, json!({}), 160)
            .status,
        400
    );
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(
        s.handle_at("POST", "sys/wrapping/unwrap", "", &token, json!({}), 101)
            .status,
        400
    );
    assert_eq!(
        call(&mut s, &root, "sys/wrapping/lookup", json!({"token":token})).status,
        400
    );
    Ok(())
}

#[test]
fn wrapping_namespace_isolation_does_not_consume_body_token_on_denial() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    let a = wrapped(&mut s, &root, "a", "sys/wrapping/wrap", json!({"v":"ns-a"}));
    let token = text(&a.body, "/wrap_info/token")?;
    for path in [
        "sys/wrapping/lookup",
        "sys/wrapping/unwrap",
        "sys/wrapping/rewrap",
    ] {
        assert_eq!(
            s.handle_at("POST", path, "b", &root, json!({"token":token}), 100)
                .status,
            400
        );
    }
    let r = s.handle_at(
        "POST",
        "sys/wrapping/unwrap",
        "a",
        &root,
        json!({"token":token}),
        100,
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body["data"], json!({"v":"ns-a"}));
    Ok(())
}

#[test]
fn wrapping_token_has_no_general_or_policy_manufactured_authority() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    assert_eq!(
        s.handle_at(
            "PUT",
            "sys/policies/acl/response-wrapping",
            "",
            &root,
            json!({"policy":"path \"*\" { capabilities = [\"read\",\"update\"] }"}),
            100
        )
        .status,
        204
    );
    let r = wrapped(
        &mut s,
        &root,
        "",
        "sys/wrapping/wrap",
        json!({"v":"secret"}),
    );
    let token = text(&r.body, "/wrap_info/token")?;
    assert_eq!(
        s.handle_at("GET", "sys/auth", "", &token, json!({}), 100)
            .status,
        403
    );
    assert_eq!(
        call(&mut s, &token, "sys/wrapping/unwrap", json!({})).status,
        400
    );
    let r = call(
        &mut s,
        &root,
        "auth/token/create",
        json!({"policies":["response-wrapping"],"no_default_policy":true}),
    );
    let forged = text(&r.body, "/auth/client_token")?;
    assert_eq!(
        call(&mut s, &forged, "sys/wrapping/unwrap", json!({})).status,
        400
    );
    assert_eq!(
        call(&mut s, &root, "sys/wrapping/unwrap", json!({"token":root})).status,
        400
    );
    assert_eq!(
        s.handle_at("GET", "auth/token/lookup-self", "", &root, json!({}), 100)
            .status,
        200
    );
    Ok(())
}

#[test]
fn wrapping_revoke_accessor_and_default_policy_work_through_service() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    let created = call(
        &mut s,
        &root,
        "auth/token/create",
        json!({"policies":["default"]}),
    );
    let user = text(&created.body, "/auth/client_token")?;
    let r = wrapped(
        &mut s,
        &user,
        "",
        "sys/wrapping/wrap",
        json!({"v":"synthetic"}),
    );
    assert_eq!(r.status, 200);
    let token = text(&r.body, "/wrap_info/token")?;
    let accessor = text(&r.body, "/wrap_info/accessor")?;
    assert_eq!(
        call(
            &mut s,
            &root,
            "auth/token/revoke-accessor",
            json!({"accessor":accessor})
        )
        .status,
        204
    );
    assert_eq!(
        call(&mut s, &user, "sys/wrapping/unwrap", json!({"token":token})).status,
        400
    );
    Ok(())
}

#[test]
fn wrapping_capture_of_token_response_retains_wrapped_accessor_and_exact_body() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    let r = wrapped(
        &mut s,
        &root,
        "",
        "auth/token/create",
        json!({"policies":["default"],"ttl":"10m"}),
    );
    assert_eq!(r.status, 200);
    let token = text(&r.body, "/wrap_info/token")?;
    let accessor = text(&r.body, "/wrap_info/wrapped_accessor")?;
    assert_ne!(accessor, text(&r.body, "/wrap_info/accessor")?);
    let result = call(&mut s, &token, "sys/wrapping/unwrap", json!({}));
    assert_eq!(result.status, 200);
    assert_eq!(result.body["auth"]["accessor"], accessor);
    let issued = text(&result.body, "/auth/client_token")?;
    assert_eq!(
        s.handle_at("GET", "auth/token/lookup-self", "", &issued, json!({}), 100)
            .status,
        200
    );
    Ok(())
}

#[test]
fn wrapping_capacity_failure_rolls_back_issued_token_and_large_payload() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    let before = snapshot(&s)?;
    let r = wrapped(
        &mut s,
        &root,
        "",
        "sys/wrapping/wrap",
        json!({"v":"x".repeat(65*1024)}),
    );
    assert_eq!(r.status, 413);
    assert_eq!(before, snapshot(&s)?);
    s.state_capacity = 1;
    let r = wrapped(
        &mut s,
        &root,
        "",
        "auth/token/create",
        json!({"policies":["default"]}),
    );
    assert_eq!(r.status, 507);
    assert!(r.body.get("wrap_info").is_none());
    assert!(r.body.get("auth").is_none());
    assert_eq!(before, snapshot(&s)?);
    Ok(())
}

#[test]
fn wrapping_invalid_ttl_and_nontransactional_effects_never_dispatch() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    let before = snapshot(&s)?;
    for ttl in [0, u64::MAX, 32 * 24 * 3600 + 1] {
        let r = s.handle_request_at(
            ServiceRequest {
                method: "POST",
                path: "auth/token/create",
                namespace: "",
                token: &root,
                body: json!({}),
                wrap_ttl_seconds: Some(ttl),
                origin_peer: None,
                client_certificates: None,
            },
            100,
        );
        assert_eq!(r.status, 400);
        assert_eq!(before, snapshot(&s)?);
    }
    assert_eq!(
        wrapped(&mut s, &root, "", "sys/seal", json!({})).status,
        501
    );
    assert_eq!(before, snapshot(&s)?);
    let leader = s.handle_request_at(
        ServiceRequest {
            method: "GET",
            path: "sys/leader",
            namespace: "",
            token: &root,
            body: json!({}),
            wrap_ttl_seconds: Some(60),
            origin_peer: None,
            client_certificates: None,
        },
        100,
    );
    // OpenBao's dedicated public diagnostic ignores response wrapping and
    // returns its ordinary local shape without creating a wrapper token.
    assert_eq!(leader.status, 200);
    assert_eq!(leader.body, json!({"ha_enabled": false}));
    assert_eq!(before, snapshot(&s)?);
    assert_eq!(
        call(&mut s, &root, "sys/wrapping/wrap", json!({})).status,
        400
    );
    assert_eq!(
        wrapped(&mut s, "", "", "sys/wrapping/wrap", json!({})).status,
        403
    );
    Ok(())
}

#[test]
fn wrapping_result_audit_failure_withholds_response_and_persists_single_use() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, key) = start(&mut s)?;
    let r = wrapped(
        &mut s,
        &root,
        "",
        "sys/wrapping/wrap",
        json!({"v":"never-leak-after-audit-failure"}),
    );
    let token = text(&r.body, "/wrap_info/token")?;
    let fingerprint = s.request_fingerprint("POST", "sys/wrapping/unwrap", "", &token);
    let event = AuditUnsigned {
        schema: 2,
        sequence: s.audit_sequence + 1,
        previous: STANDARD.encode(s.audit_previous),
        time: 100,
        kind: "request".into(),
        path_digest: fingerprint,
        status: None,
    };
    let payload = serde_json::to_vec(&event)?;
    let mac = STANDARD.encode(hmac::sign(&s.audit_key, &payload).as_ref());
    let next = serde_json::to_vec(&AuditRecord { event, mac })?.len() + 1;
    s.audit_capacity = s.audit.metadata()?.len() + next as u64;
    let result = call(&mut s, &token, "sys/wrapping/unwrap", json!({}));
    assert_eq!(result.status, 503);
    assert!(
        !result
            .body
            .to_string()
            .contains("never-leak-after-audit-failure")
    );
    assert!(s.recovery_required);
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(&mut s, &token, "sys/wrapping/unwrap", json!({})).status,
        400
    );
    Ok(())
}

#[test]
fn wrapping_format_rejects_legacy_rebinding_and_critical_record_tampering() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    let response = wrapped(
        &mut s,
        &root,
        "",
        "sys/wrapping/wrap",
        json!({"v":"synthetic"}),
    );
    assert_eq!(response.status, 200);
    let current = serde_json::to_value(s.state.as_ref().ok_or("state")?)?;
    for version in [1, 2, CURRENT_STATE_SCHEMA + 1] {
        let mut candidate = current.clone();
        candidate["schema"] = json!(version);
        assert!(
            serde_json::from_value::<State>(candidate)?
                .validate_format()
                .is_err()
        );
    }
    for (field, value) in [
        ("root", json!(true)),
        ("renewable", json!(true)),
        ("uses_remaining", json!(5)),
        ("expires_at", json!(999)),
    ] {
        let mut candidate = current.clone();
        let token = candidate["auth"]["tokens"]
            .as_object_mut()
            .ok_or("tokens")?
            .values_mut()
            .find(|t| t.get("wrapping").is_some())
            .ok_or("wrapper")?;
        token[field] = value;
        assert!(
            serde_json::from_value::<State>(candidate)?
                .validate_format()
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn wrapping_concurrent_unwrap_releases_payload_at_most_once() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    let r = wrapped(
        &mut s,
        &root,
        "",
        "sys/wrapping/wrap",
        json!({"v":"synthetic"}),
    );
    let token = text(&r.body, "/wrap_info/token")?;
    let shared = Arc::new(Mutex::new(s));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let service = shared.clone();
        let token = token.clone();
        tasks.push(std::thread::spawn(move || {
            service
                .lock()
                .map(|mut s| call(&mut s, &token, "sys/wrapping/unwrap", json!({})).status)
                .unwrap_or(503)
        }));
    }
    let results = tasks
        .into_iter()
        .map(|t| t.join().map_err(|_| "worker panic"))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(results.iter().filter(|&&s| s == 200).count(), 1);
    assert_eq!(results.iter().filter(|&&s| s == 400).count(), 7);
    Ok(())
}
