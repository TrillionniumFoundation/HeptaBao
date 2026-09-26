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
            "heptabao-ssh-leases-{}-{}",
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

fn install(s: &mut Service, root: &str) {
    assert_eq!(
        call(
            s,
            root,
            "sys/mounts/ssh",
            json!({"type":"ssh","config":{"default_lease_ttl":"60s","max_lease_ttl":"120s"}})
        )
        .status,
        204
    );
    assert_eq!(call(s,root,"ssh/roles/test",json!({"key_type":"otp","default_user":"deploy","allowed_users":"deploy,backup","cidr_list":"127.0.0.0/8,::1/128","exclude_cidr_list":"127.1.0.0/16"})).status,204);
}
fn issue(s: &mut Service, token: &str) -> Response {
    call(s, token, "ssh/creds/test", json!({"ip":"127.0.0.1"}))
}
fn verify(s: &mut Service, otp: &str, now: u64) -> Response {
    s.handle_at("POST", "ssh/verify", "", "", json!({"otp":otp}), now)
}
fn metadata(s: &mut Service, root: &str, id: &str) -> Response {
    call(s, root, "sys/leases/lookup", json!({"lease_id":id}))
}

#[test]
fn ssh_otp_is_encrypted_restart_persistent_and_single_use() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, key) = start(&mut s)?;
    install(&mut s, &root);
    let issued = issue(&mut s, &root);
    assert_eq!(issued.status, 200);
    let otp = text(&issued.body, "/data/key")?;
    let id = text(&issued.body, "/lease_id")?;
    assert_eq!(issued.body["lease_duration"], 60);
    assert_eq!(issued.body["renewable"], false);
    let meta = metadata(&mut s, &root, &id);
    assert_eq!(meta.status, 200);
    assert_eq!(meta.body["data"]["ttl"], 60);
    assert_eq!(meta.body["data"]["path"], "ssh/creds/test");
    for entry in fs::read_dir(f.0.join("data"))? {
        let p = entry?.path();
        if p.is_file() {
            assert!(
                !fs::read(p)?
                    .windows(otp.len())
                    .any(|bytes| bytes == otp.as_bytes())
            );
        }
    }
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "sys/unseal", json!({"key":key})).status,
        200
    );
    let response = verify(&mut s, &otp, 100);
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["data"],
        json!({"ip":"127.0.0.1","username":"deploy","role_name":"test"})
    );
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(verify(&mut s, &otp, 100).status, 400);
    assert_eq!(metadata(&mut s, &root, &id).status, 200);
    Ok(())
}

#[test]
fn ssh_role_cidr_exclusions_user_and_family_boundaries_are_enforced() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    install(&mut s, &root);
    let before = snapshot(&s)?;
    for payload in [
        json!({"ip":"127.1.2.3"}),
        json!({"ip":"10.0.0.1"}),
        json!({"ip":"::ffff:127.0.0.1"}),
        json!({"ip":"localhost"}),
        json!({"ip":"127.0.0.1","username":"root"}),
        json!({"ip":"127.0.0.1","username":"../../escape"}),
        json!({"ip":"127.0.0.1","extra":true}),
    ] {
        assert_eq!(call(&mut s, &root, "ssh/creds/test", payload).status, 400);
    }
    assert_eq!(snapshot(&s)?, before);
    assert_eq!(
        call(
            &mut s,
            &root,
            "ssh/creds/test",
            json!({"ip":"::1","username":"backup"})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            "ssh/roles/bad",
            json!({"key_type":"otp","default_user":"deploy","cidr_list":"127.0.0.1/33"})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            "ssh/roles/bad",
            json!({"key_type":"otp","default_user":"deploy","cidr_list":"::1/129"})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            "ssh/roles/bad",
            json!({"key_type":"ca","default_user":"deploy","cidr_list":"127.0.0.1/32"})
        )
        .status,
        501
    );
    Ok(())
}

#[test]
fn ssh_expiry_is_durable_and_cannot_be_reversed_by_clock_rollback() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, key) = start(&mut s)?;
    install(&mut s, &root);
    let issued = issue(&mut s, &root);
    let otp = text(&issued.body, "/data/key")?;
    assert_eq!(verify(&mut s, &otp, 160).status, 400);
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(verify(&mut s, &otp, 100).status, 400);
    Ok(())
}

#[test]
fn ssh_issuer_and_parent_revocation_invalidate_online_credential() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    install(&mut s, &root);
    assert_eq!(
        call(
            &mut s,
            &root,
            "sys/policies/acl/ssh-issuer",
            json!({"policy":"path \"ssh/creds/test\" { capabilities = [\"update\"] }"})
        )
        .status,
        204
    );
    let p = call(
        &mut s,
        &root,
        "auth/token/create",
        json!({"policies":["default","ssh-issuer"]}),
    );
    let parent = text(&p.body, "/auth/client_token")?;
    let p = call(
        &mut s,
        &root,
        "auth/token/create",
        json!({"policies":["default","ssh-issuer"],"ttl":"5s"}),
    );
    let short = text(&p.body, "/auth/client_token")?;
    let issued = issue(&mut s, &short);
    assert_eq!(issued.status, 200);
    assert_eq!(issued.body["lease_duration"], 5);
    let issued = issue(&mut s, &parent);
    assert_eq!(issued.status, 200);
    let otp = text(&issued.body, "/data/key")?;
    assert_eq!(
        call(&mut s, &root, "auth/token/revoke", json!({"token":parent})).status,
        204
    );
    assert_eq!(verify(&mut s, &otp, 100).status, 400);
    // Root is the real parent of this derived token; revoking it invalidates
    // outstanding delegated leases without retaining a second credential store.
    let issued = issue(&mut s, &short);
    let otp = text(&issued.body, "/data/key")?;
    assert_eq!(
        call(&mut s, &root, "auth/token/revoke-self", json!({})).status,
        204
    );
    assert_eq!(verify(&mut s, &otp, 100).status, 400);
    Ok(())
}

#[test]
fn ssh_lease_administration_revokes_exact_or_segment_bound_prefix() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    install(&mut s, &root);
    let issued = issue(&mut s, &root);
    let otp = text(&issued.body, "/data/key")?;
    let id = text(&issued.body, "/lease_id")?;
    assert_eq!(
        call(
            &mut s,
            &root,
            "sys/leases/renew",
            json!({"lease_id":id,"increment":10})
        )
        .status,
        400
    );
    assert_eq!(metadata(&mut s, &root, &id).status, 200);
    assert_eq!(
        call(
            &mut s,
            &root,
            "sys/leases/revoke",
            json!({"lease_id":id,"sync":true})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            "sys/leases/revoke",
            json!({"lease_id":id,"sync":true})
        )
        .status,
        204
    );
    assert_eq!(verify(&mut s, &otp, 100).status, 400);
    assert_eq!(
        call(
            &mut s,
            &root,
            "ssh/roles/test-other",
            json!({"key_type":"otp","default_user":"deploy","cidr_list":"127.0.0.1/32"})
        )
        .status,
        204
    );
    let a = issue(&mut s, &root);
    let b = call(
        &mut s,
        &root,
        "ssh/creds/test-other",
        json!({"ip":"127.0.0.1"}),
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            "sys/leases/revoke-prefix/ssh/creds/test",
            json!({"sync":true})
        )
        .status,
        204
    );
    assert_eq!(
        verify(&mut s, &text(&a.body, "/data/key")?, 100).status,
        400
    );
    assert_eq!(
        verify(&mut s, &text(&b.body, "/data/key")?, 100).status,
        200
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            "sys/leases/revoke-prefix/auth",
            json!({"sync":true})
        )
        .status,
        501
    );
    Ok(())
}

#[test]
fn ssh_namespace_and_remounted_backend_cannot_reuse_old_otp() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    install(&mut s, &root);
    let issued = issue(&mut s, &root);
    let otp = text(&issued.body, "/data/key")?;
    let id = text(&issued.body, "/lease_id")?;
    assert_eq!(
        s.handle_at(
            "POST",
            "sys/leases/lookup",
            "other",
            &root,
            json!({"lease_id":id}),
            100
        )
        .status,
        400
    );
    assert_eq!(
        s.handle_at(
            "POST",
            "sys/mounts/ssh",
            "other",
            &root,
            json!({"type":"ssh"}),
            100
        )
        .status,
        204
    );
    assert_eq!(
        s.handle_at("POST", "ssh/verify", "other", "", json!({"otp":otp}), 100)
            .status,
        400
    );
    assert_eq!(metadata(&mut s, &root, &id).status, 200);
    assert_eq!(
        s.handle_at("DELETE", "sys/mounts/ssh", "", &root, json!({}), 100)
            .status,
        204
    );
    install(&mut s, &root);
    assert_eq!(verify(&mut s, &otp, 100).status, 400);
    Ok(())
}

#[test]
fn ssh_wrapped_credentials_and_wrapper_failure_preserve_transaction_atomicity() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    install(&mut s, &root);
    let response = s.handle_request_at(
        ServiceRequest {
            method: "POST",
            path: "ssh/creds/test",
            namespace: "",
            token: &root,
            body: json!({"ip":"127.0.0.1"}),
            wrap_ttl_seconds: Some(30),
            origin_peer: None,
            client_certificates: None,
        },
        100,
    );
    assert_eq!(response.status, 200);
    assert!(response.body["data"].is_null());
    let token = text(&response.body, "/wrap_info/token")?;
    let unwrapped = call(&mut s, &token, "sys/wrapping/unwrap", json!({}));
    assert_eq!(unwrapped.status, 200);
    let otp = text(&unwrapped.body, "/data/key")?;
    assert_eq!(verify(&mut s, &otp, 100).status, 200);
    let before = snapshot(&s)?;
    s.state_capacity = before.len();
    assert_eq!(issue(&mut s, &root).status, 507);
    assert_eq!(snapshot(&s)?, before);
    Ok(())
}

#[test]
fn ssh_finite_exhausted_issuer_and_unprivileged_admin_requests_fail_closed() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    install(&mut s, &root);
    let limited = call(
        &mut s,
        &root,
        "auth/token/create",
        json!({"policies":["root"],"num_uses":1}),
    );
    let limited = text(&limited.body, "/auth/client_token")?;
    assert_eq!(issue(&mut s, &limited).status, 403);
    let p = call(
        &mut s,
        &root,
        "auth/token/create",
        json!({"policies":["default"]}),
    );
    let token = text(&p.body, "/auth/client_token")?;
    assert_eq!(issue(&mut s, &token).status, 403);
    assert_eq!(
        call(&mut s, &token, "sys/leases/revoke-prefix/ssh", json!({})).status,
        403
    );
    assert_eq!(
        s.handle_at("LIST", "sys/leases/lookup/ssh", "", &token, json!({}), 100)
            .status,
        403
    );
    Ok(())
}

#[test]
fn ssh_state_rejects_downgrade_and_malformed_lease_bindings() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    install(&mut s, &root);
    assert_eq!(issue(&mut s, &root).status, 200);
    let state = s.state.as_ref().ok_or("state")?;
    state
        .validate_format()
        .map_err(|_| "invalid current state")?;
    let mut legacy = state.clone();
    legacy.schema = 2;
    legacy.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(legacy.validate_format().is_err());
    let mut value = serde_json::to_value(state)?;
    value["engines"]["lease_clock"] = json!(0);
    let invalid: State = serde_json::from_value(value)?;
    assert!(invalid.validate_format().is_err());
    Ok(())
}

#[test]
fn ssh_simultaneous_verification_releases_once_only() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    install(&mut s, &root);
    let issued = issue(&mut s, &root);
    let otp = text(&issued.body, "/data/key")?;
    let service = Arc::new(Mutex::new(s));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let service = service.clone();
        let otp = otp.clone();
        threads.push(std::thread::spawn(move || {
            let mut guard = service.lock().map_err(|_| "poison")?;
            Ok::<_, &str>(verify(&mut guard, &otp, 100).status)
        }));
    }
    let mut statuses = Vec::new();
    for thread in threads {
        statuses.push(thread.join().map_err(|_| "thread")??);
    }
    assert_eq!(statuses.iter().filter(|&&s| s == 200).count(), 1);
    assert_eq!(statuses.iter().filter(|&&s| s == 400).count(), 7);
    Ok(())
}

#[test]
fn ssh_lease_path_and_body_identity_cannot_redirect_authorized_revocation() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    install(&mut s, &root);
    let a = issue(&mut s, &root);
    let b = issue(&mut s, &root);
    let a_id = text(&a.body, "/lease_id")?;
    let b_id = text(&b.body, "/lease_id")?;
    let target = format!("sys/leases/revoke/{a_id}");
    assert_eq!(
        call(
            &mut s,
            &root,
            "sys/policies/acl/revoke-one",
            json!({"policy":format!("path \"{target}\" {{ capabilities = [\"update\"] }}")})
        )
        .status,
        204
    );
    let t = call(
        &mut s,
        &root,
        "auth/token/create",
        json!({"policies":["revoke-one"],"no_default_policy":true}),
    );
    let actor = text(&t.body, "/auth/client_token")?;
    let before = snapshot(&s)?;
    assert_eq!(
        call(&mut s, &actor, &target, json!({"lease_id":b_id})).status,
        400
    );
    assert_eq!(snapshot(&s)?, before);
    assert_eq!(metadata(&mut s, &root, &a_id).status, 200);
    assert_eq!(metadata(&mut s, &root, &b_id).status, 200);
    assert_eq!(call(&mut s, &actor, &target, json!({})).status, 204);
    assert_eq!(metadata(&mut s, &root, &a_id).status, 400);
    assert_eq!(
        verify(&mut s, &text(&b.body, "/data/key")?, 100).status,
        200
    );
    Ok(())
}

#[test]
fn ssh_result_audit_failure_withholds_metadata_without_reenabling_otp() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, key) = start(&mut s)?;
    install(&mut s, &root);
    let issued = issue(&mut s, &root);
    let otp = text(&issued.body, "/data/key")?;
    let id = text(&issued.body, "/lease_id")?;
    let fingerprint = s.request_fingerprint("POST", "ssh/verify", "", "");
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
    let response = verify(&mut s, &otp, 100);
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(!response.body.to_string().contains(&otp));
    assert!(s.recovery_required);
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(verify(&mut s, &otp, 100).status, 400);
    assert_eq!(metadata(&mut s, &root, &id).status, 200);
    Ok(())
}

#[test]
fn ssh_disabled_login_identity_revokes_issued_otp_without_resurrection() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, key) = start(&mut s)?;
    install(&mut s, &root);
    assert_eq!(
        call(
            &mut s,
            &root,
            "sys/policies/acl/ssh-issuer",
            json!({"policy":"path \"ssh/creds/test\" { capabilities = [\"update\"] }"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            "sys/auth/ssh-login",
            json!({"type":"approle"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut s,
            &root,
            "auth/ssh-login/role/test",
            json!({"token_policies":["ssh-issuer"]})
        )
        .status,
        204
    );
    let role = s.handle_at(
        "GET",
        "auth/ssh-login/role/test/role-id",
        "",
        &root,
        json!({}),
        100,
    );
    let secret = call(
        &mut s,
        &root,
        "auth/ssh-login/role/test/secret-id",
        json!({}),
    );
    let login = call(
        &mut s,
        "",
        "auth/ssh-login/login",
        json!({"role_id":role.body["data"]["role_id"],"secret_id":secret.body["data"]["secret_id"]}),
    );
    assert_eq!(login.status, 200);
    let actor = text(&login.body, "/auth/client_token")?;
    let entity = text(&login.body, "/auth/entity_id")?;
    let issued = issue(&mut s, &actor);
    assert_eq!(issued.status, 200);
    let otp = text(&issued.body, "/data/key")?;
    let entity_path = format!("identity/entity/id/{entity}");
    assert_eq!(
        call(&mut s, &root, &entity_path, json!({"disabled":true})).status,
        204
    );
    assert_eq!(verify(&mut s, &otp, 100).status, 400);
    assert_eq!(
        call(&mut s, &root, &entity_path, json!({"disabled":false})).status,
        204
    );
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(verify(&mut s, &otp, 100).status, 400);
    assert_eq!(issue(&mut s, &actor).status, 200);
    Ok(())
}

#[test]
fn idle_maintenance_commits_expiry_without_a_client_request_and_no_clock_revival() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, key) = start(&mut s)?;
    install(&mut s, &root);
    let issued = issue(&mut s, &root);
    let otp = text(&issued.body, "/data/key")?;
    assert!(s.state.as_ref().ok_or("state")?.engines.has_live_leases());
    assert!(s.maintain_lifetimes_at(160)?);
    assert!(!s.state.as_ref().ok_or("state")?.engines.has_live_leases());
    let current = snapshot(&s)?;
    assert!(!s.maintain_lifetimes_at(100)?);
    assert_eq!(current, snapshot(&s)?);
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(verify(&mut s, &otp, 100).status, 400);
    Ok(())
}

#[test]
fn idle_maintenance_requires_pre_entry_audit_and_has_no_network_authority() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    assert!(!s.maintain_lifetimes_at(100)?);
    let (root, _) = start(&mut s)?;
    install(&mut s, &root);
    assert_eq!(issue(&mut s, &root).status, 200);
    let before = snapshot(&s)?;
    s.audit_capacity = s.audit.metadata()?.len();
    assert!(s.maintain_lifetimes_at(160).is_err());
    assert_eq!(snapshot(&s)?, before);
    s.audit_capacity = u64::MAX;
    // No route exists that lets a caller choose a lifecycle clock or dispatch an INTERNAL request.
    assert_ne!(
        call(&mut s, "", "lifecycle/expiry", json!({"now":999999})).status,
        204
    );
    Ok(())
}

#[test]
fn idle_maintenance_erases_expired_wrapped_payload_and_then_stops_writing() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    let wrapped = s.handle_request_at(
        ServiceRequest {
            method: "POST",
            path: "sys/wrapping/wrap",
            namespace: "",
            token: &root,
            body: json!({"value":"synthetic-idle-wrapped-secret"}),
            wrap_ttl_seconds: Some(5),
            origin_peer: None,
            client_certificates: None,
        },
        100,
    );
    assert_eq!(wrapped.status, 200);
    assert!(s.state.as_ref().ok_or("state")?.auth.has_live_wrappers());
    assert!(s.maintain_lifetimes_at(105)?);
    assert!(!s.state.as_ref().ok_or("state")?.auth.has_live_wrappers());
    let bytes = snapshot(&s)?;
    assert!(
        !bytes
            .windows(b"synthetic-idle-wrapped-secret".len())
            .any(|b| b == b"synthetic-idle-wrapped-secret")
    );
    assert!(!s.maintain_lifetimes_at(106)?);
    assert_eq!(bytes, snapshot(&s)?);
    Ok(())
}

#[test]
fn lifecycle_worker_is_bounded_joined_and_does_not_keep_service_alive() -> TestResult {
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };
    let f = Fixture::new()?;
    let s = Arc::new(Mutex::new(f.service()?));
    assert!(lifecycle::start_lifecycle_worker(&s, Duration::ZERO)?.is_none());
    assert!(lifecycle::start_lifecycle_worker(&s, Duration::from_millis(1)).is_err());
    assert!(lifecycle::start_lifecycle_worker(&s, Duration::from_secs(61)).is_err());
    let worker = lifecycle::start_lifecycle_worker(&s, Duration::from_secs(60))?;
    assert_eq!(Arc::strong_count(&s), 1);
    let before = Instant::now();
    drop(worker);
    assert!(before.elapsed() < Duration::from_secs(2));
    Ok(())
}

#[test]
fn idle_result_audit_failure_fences_but_preserves_committed_revocation_on_reopen() -> TestResult {
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, key) = start(&mut s)?;
    install(&mut s, &root);
    let otp = text(&issue(&mut s, &root).body, "/data/key")?;
    let fingerprint = s.request_fingerprint("INTERNAL", "lifecycle/expiry", "", "");
    let event = AuditUnsigned {
        schema: 2,
        sequence: s.audit_sequence + 1,
        previous: STANDARD.encode(s.audit_previous),
        time: 160,
        kind: "lifecycle-request".into(),
        path_digest: fingerprint,
        status: None,
    };
    let payload = serde_json::to_vec(&event)?;
    let mac = STANDARD.encode(hmac::sign(&s.audit_key, &payload).as_ref());
    let length = serde_json::to_vec(&AuditRecord { event, mac })?.len() + 1;
    s.audit_capacity = s.audit.metadata()?.len() + length as u64;
    assert!(s.maintain_lifetimes_at(160).is_err());
    assert!(s.recovery_required);
    assert!(!s.state.as_ref().ok_or("state")?.engines.has_live_leases());
    assert!(s.maintain_lifetimes_at(161).is_err());
    drop(s);
    let mut s = f.service()?;
    assert_eq!(
        call(&mut s, "", "sys/unseal", json!({"key":key})).status,
        200
    );
    assert_eq!(verify(&mut s, &otp, 100).status, 400);
    Ok(())
}

#[test]
fn renewed_bearer_echo_is_request_bound_wrapped_and_never_reconstructed_from_accessor() -> TestResult
{
    let f = Fixture::new()?;
    let mut s = f.service()?;
    let (root, _) = start(&mut s)?;
    let created = call(
        &mut s,
        &root,
        "auth/token/create",
        json!({"policies":["default"],"ttl":"60s"}),
    );
    assert_eq!(created.status, 200);
    let token = text(&created.body, "/auth/client_token")?;
    let accessor = text(&created.body, "/auth/accessor")?;
    let renewed = call(
        &mut s,
        &token,
        "auth/token/renew-self",
        json!({"increment":60}),
    );
    assert_eq!(renewed.status, 200);
    assert_eq!(renewed.body["auth"]["client_token"], token);
    let renewed = call(
        &mut s,
        &root,
        "auth/token/renew",
        json!({"token":token,"increment":60}),
    );
    assert_eq!(renewed.status, 200);
    assert_eq!(renewed.body["auth"]["client_token"], token);
    let hidden = call(
        &mut s,
        &root,
        "auth/token/renew-accessor",
        json!({"accessor":accessor,"increment":60}),
    );
    assert_eq!(hidden.status, 200);
    assert!(!hidden.body.to_string().contains(&token));
    let wrapped = s.handle_request_at(
        ServiceRequest {
            method: "POST",
            path: "auth/token/renew-self",
            namespace: "",
            token: &token,
            body: json!({"increment":60}),
            wrap_ttl_seconds: Some(10),
            origin_peer: None,
            client_certificates: None,
        },
        100,
    );
    assert_eq!(wrapped.status, 200);
    assert!(!wrapped.body.to_string().contains(&token));
    let wrap_token = text(&wrapped.body, "/wrap_info/token")?;
    let opened = call(&mut s, &wrap_token, "sys/wrapping/unwrap", json!({}));
    assert_eq!(opened.status, 200);
    assert_eq!(opened.body["auth"]["client_token"], token);
    Ok(())
}
