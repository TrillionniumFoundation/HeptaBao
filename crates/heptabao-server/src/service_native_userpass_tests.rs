//! Normal configured File V6 and actual Auth operations. No fixture activation,
//! injected actor, synthetic publication receipt or invented token provenance.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::Root;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PASSWORD: &str = "native-userpass-synthetic-password";
const USER_POLICY: &str = "path \"up-kv/data/*\" { capabilities = [\"read\"] } path \"auth/token/create\" { capabilities = [\"update\"] }";

fn status(response: &Response, expected: u16) {
    assert_eq!(
        response.status,
        expected,
        "native Userpass error shape={:?}",
        response.body.get("errors")
    );
}

fn text(response: &Response, path: &str) -> TestResult<String> {
    response
        .body
        .pointer(path)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "required synthetic Userpass response field absent".into())
}

fn secret(response: &mut Response, path: &str) -> TestResult<Zeroizing<String>> {
    let result = Zeroizing::new(text(response, path)?);
    erase_json(&mut response.body);
    Ok(result)
}

fn call(
    service: &mut Service,
    now: &mut u64,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
) -> TestResult<Response> {
    *now += 1;
    let started = Instant::now();
    let clock = RequestClock::anchored(Duration::from_secs(*now), started)?;
    let _scope =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method,
            path,
            namespace: "",
            token,
            body,
            now: *now,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        clock,
    );
    let response = service.finish_synchronous_request(execution);
    assert!(service.pending_native_auth_delivery.is_none());
    Ok(response)
}

struct Fixture {
    files: Root,
    service: Service,
    key: Zeroizing<String>,
    admin: Zeroizing<String>,
    now: u64,
}

impl Fixture {
    fn initialized() -> TestResult<Self> {
        let files = Root::new();
        let mut service = files.service()?;
        service.configure_native_v6_storage(NativeStorageProfile::File)?;
        let mut now = 100;
        let mut initialized = call(
            &mut service,
            &mut now,
            "",
            "POST",
            "sys/init",
            json!({"secret_shares":1,"secret_threshold":1}),
        )?;
        status(&initialized, 200);
        let key = Zeroizing::new(text(&initialized, "/keys/0")?);
        let admin = secret(&mut initialized, "/root_token")?;
        status(
            &call(
                &mut service,
                &mut now,
                "",
                "POST",
                "sys/unseal",
                json!({"key":key.as_str()}),
            )?,
            200,
        );
        status(
            &call(
                &mut service,
                &mut now,
                &admin,
                "POST",
                "sys/init/ack",
                json!({}),
            )?,
            204,
        );
        Ok(Self {
            files,
            service,
            key,
            admin,
            now,
        })
    }

    fn new() -> TestResult<Self> {
        let mut f = Self::initialized()?;
        status(
            &f.admin("POST", native_storage::ACTIVATE_PATH, json!({}))?,
            204,
        );
        f.assert_native()?;
        status(
            &f.admin(
                "POST",
                "sys/mounts/up-kv",
                json!({"type":"kv","options":{"version":"2"}}),
            )?,
            204,
        );
        status(
            &f.admin(
                "POST",
                "up-kv/data/value",
                json!({"options":{"cas":0},"data":{"value":"native-userpass-preserved"}}),
            )?,
            200,
        );
        status(
            &f.admin(
                "POST",
                "sys/policies/acl/native-up",
                json!({"policy":USER_POLICY}),
            )?,
            204,
        );
        status(
            &f.admin("POST", "sys/auth/up", json!({"type":"userpass"}))?,
            204,
        );
        Ok(f)
    }

    fn assert_native(&self) -> TestResult {
        assert!(matches!(
            self.service.native_storage_profile,
            Some(NativeStorageProfile::File)
        ));
        // Normal File mode retains this descriptor-bound custody capsule.
        // Public ACTIVATE_PATH plus the explicit File selector identify the path.
        assert!(self.service.native_candidate_profile.is_some());
        assert!(self.service.native_root.is_some() && self.service.record_root.is_none());
        assert!(!self.service.recovery_required);
        // These fixtures can create current ordinary children. Their bound
        // factory defaults are real owners, so check the same complete catalog
        // and storage profile used by publication instead of a root-only Auth
        // predicate which deliberately excludes child policy state.
        assert!(
            self.service
                .require_native_root_candidate(self.service.state.as_ref().ok_or("state")?)
                .is_ok()
        );
        Ok(())
    }

    fn admin(&mut self, method: &str, path: &str, body: Value) -> TestResult<Response> {
        call(
            &mut self.service,
            &mut self.now,
            &self.admin,
            method,
            path,
            body,
        )
    }

    fn actor(
        &mut self,
        token: &str,
        method: &str,
        path: &str,
        body: Value,
    ) -> TestResult<Response> {
        call(&mut self.service, &mut self.now, token, method, path, body)
    }

    fn user(&mut self, name: &str, uses: u64) -> TestResult {
        status(
            &self.admin(
                "POST",
                &format!("auth/up/users/{name}"),
                json!({
                    "password":PASSWORD, "policies":["native-up"],
                    "token_ttl":120, "token_max_ttl":600, "token_num_uses":uses,
                }),
            )?,
            204,
        );
        Ok(())
    }

    fn login(&mut self, name: &str) -> TestResult<Zeroizing<String>> {
        let mut response = self.actor(
            "",
            "POST",
            &format!("auth/up/login/{name}"),
            json!({"password":PASSWORD}),
        )?;
        status(&response, 200);
        assert_eq!(response.body["auth"]["token_type"], "service");
        secret(&mut response, "/auth/client_token")
    }

    fn restart(mut self) -> TestResult<Self> {
        drop(self.service);
        self.service = self.files.service()?;
        self.service
            .configure_native_v6_storage(NativeStorageProfile::File)?;
        status(
            &call(
                &mut self.service,
                &mut self.now,
                "",
                "POST",
                "sys/unseal",
                json!({"key":self.key.as_str()}),
            )?,
            200,
        );
        self.assert_native()?;
        Ok(self)
    }

    fn root(&self) -> TestResult<RecordStateRootV6> {
        self.service
            .native_root
            .clone()
            .ok_or_else(|| "native root absent".into())
    }

    fn assert_business_unchanged(&self, before: &RecordStateRootV6) -> TestResult {
        auth_only_root_change(before, &self.root()?, true)
            .map_err(|_| "Userpass changed a non-Auth/non-Identity owner")?;
        Ok(())
    }

    fn assert_value(&mut self, token: &str) -> TestResult {
        let response = self.actor(token, "GET", "up-kv/data/value", json!({}))?;
        status(&response, 200);
        assert_eq!(response.body["data"]["metadata"]["version"], 1);
        assert_eq!(
            response.body["data"]["data"]["value"],
            "native-userpass-preserved"
        );
        Ok(())
    }

    fn token(&mut self, policy: &str) -> TestResult<Zeroizing<String>> {
        let mut response = self.admin(
            "POST",
            "auth/token/create",
            json!({"policies":[policy],"no_default_policy":true,"ttl":"600s"}),
        )?;
        status(&response, 200);
        secret(&mut response, "/auth/client_token")
    }

    fn audited_login(
        &mut self,
        password: &str,
        budget: Duration,
    ) -> TestResult<(Response, Instant)> {
        self.now += 1;
        let started = Instant::now();
        let until = started + budget;
        let clock = RequestClock::anchored(Duration::from_secs(self.now), started)?;
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(until);
        let body = json!({"password":password});
        let response = self.service.handle_inner(RequestView {
            method: "POST",
            path: "auth/up/login/alice",
            namespace: "",
            token: "",
            body: &body,
            now: self.now,
            admission_started: started,
            token_clock: Some(clock),
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        });
        let delivery = self
            .service
            .pending_native_auth_delivery
            .as_ref()
            .ok_or("Userpass delivery")?;
        assert!(delivery.userpass_owner.is_some());
        assert!(delivery.requires_local_proof() && delivery.tracks_terminal_checkpoint());
        assert!(delivery.proof.is_none() && delivery.delivery_checkpoint.is_some());
        let response = self.service.audit_completed_response_with_receipt(
            "native-userpass-actual-audit",
            self.now,
            Some(clock),
            response,
            || {},
        );
        let delivery = self
            .service
            .pending_native_auth_delivery
            .as_ref()
            .ok_or("audited Userpass owner")?;
        assert!(matches!(
            delivery.proof.as_ref(),
            Some(native_v6_reader::NativeProof::Single(_))
        ));
        Ok((response, until))
    }
}

#[test]
fn native_userpass_formal_source_promotion_keeps_real_preexisting_credentials() -> TestResult {
    let mut f = Fixture::initialized()?;
    assert!(f.service.native_root.is_none());
    status(
        &f.admin(
            "POST",
            "sys/mounts/up-kv",
            json!({"type":"kv","options":{"version":"2"}}),
        )?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "up-kv/data/value",
            json!({"options":{"cas":0},"data":{"value":"native-userpass-preserved"}}),
        )?,
        200,
    );
    status(
        &f.admin(
            "POST",
            "sys/policies/acl/native-up",
            json!({"policy":USER_POLICY}),
        )?,
        204,
    );
    status(
        &f.admin("POST", "sys/auth/up", json!({"type":"userpass"}))?,
        204,
    );
    f.user("Alice", 0)?;
    let token = f.login("alice")?;
    let original = f.actor(&token, "GET", "auth/token/lookup-self", json!({}))?;
    status(&original, 200);
    assert_eq!(original.body["data"]["creation_ttl"], 120);
    let created_at = original.body["data"]["creation_time"]
        .as_u64()
        .ok_or("creation time")?;
    assert!(f.service.native_root.is_none());
    assert!(matches!(
        f.service
            .current_state_identity()
            .map_err(|_| "source identity")?,
        crate::state_record_root::StateIdentity::RecordsV5(_)
    ));
    status(
        &f.admin("POST", native_storage::ACTIVATE_PATH, json!({}))?,
        204,
    );
    f.assert_native()?;
    let mut f = f.restart()?;
    let retained = f.actor(&token, "GET", "auth/token/lookup-self", json!({}))?;
    status(&retained, 200);
    assert!(retained.body["data"]["id"].as_str() == Some(token.as_str()));
    assert_eq!(retained.body["data"]["meta"]["username"], "alice");
    assert_eq!(retained.body["data"]["creation_time"], created_at);
    assert_eq!(retained.body["data"]["creation_ttl"], 120);
    f.assert_value(&token)?;
    status(
        &f.actor(
            &token,
            "POST",
            "auth/token/renew-self",
            json!({"increment":"180s"}),
        )?,
        200,
    );
    Ok(())
}

#[test]
fn native_userpass_formal_file_login_renew_cold_provenance_and_revoke() -> TestResult {
    let mut f = Fixture::new()?;
    let before = f.root()?;
    f.user("Alice", 0)?;
    let token = f.login("ALICE")?;
    let first = f.actor(&token, "GET", "auth/token/lookup-self", json!({}))?;
    status(&first, 200);
    assert_eq!(first.body["data"]["meta"]["username"], "alice");
    assert_eq!(first.body["data"]["creation_ttl"], 120);
    let creation_time = first.body["data"]["creation_time"]
        .as_u64()
        .ok_or("creation time")?;
    let first_expiry = first.body["data"]["expire_time_unix"]
        .as_u64()
        .ok_or("expiry")?;
    let renewed = f.actor(
        &token,
        "POST",
        "auth/token/renew-self",
        json!({"increment":"180s"}),
    )?;
    status(&renewed, 200);
    assert!(renewed.body["auth"]["client_token"].as_str() == Some(token.as_str()));
    let mut f = f.restart()?;
    let cold = f.actor(&token, "GET", "auth/token/lookup-self", json!({}))?;
    status(&cold, 200);
    assert_eq!(cold.body["data"]["meta"]["username"], "alice");
    assert_eq!(cold.body["data"]["creation_ttl"], 120);
    assert_eq!(cold.body["data"]["creation_time"], creation_time);
    assert!(
        cold.body["data"]["expire_time_unix"]
            .as_u64()
            .is_some_and(|value| value > first_expiry)
    );
    f.assert_value(&token)?;
    let state = f.service.state.as_ref().ok_or("state")?;
    assert!(state.auth.has_userpass_issuance_state());
    assert!(state.auth.validate_userpass_native_tokens().is_ok());
    assert!(state.schema >= crate::auth::userpass_creation_ttl::STATE_SCHEMA);
    status(
        &f.actor(&token, "POST", "auth/token/revoke-self", json!({}))?,
        204,
    );
    let mut f = f.restart()?;
    status(
        &f.actor(&token, "GET", "auth/token/lookup-self", json!({}))?,
        403,
    );
    assert!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_userpass_issuance_state()
    );
    f.assert_business_unchanged(&before)?;
    Ok(())
}

#[test]
fn native_userpass_formal_mount_retirement_revokes_parent_child_and_keeps_floor() -> TestResult {
    let mut f = Fixture::new()?;
    f.user("alice", 0)?;
    status(
        &f.admin(
            "POST",
            "sys/policies/acl/up-retirer",
            json!({"policy":
                "path \"sys/auth/up\" { capabilities = [\"update\",\"sudo\"] }"
            }),
        )?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "auth/up/users/alice",
            json!({"policies":["native-up","up-retirer"]}),
        )?,
        204,
    );
    let parent = f.login("alice")?;
    let mut issued = f.actor(
        &parent,
        "POST",
        "auth/token/create",
        json!({"policies":["native-up"],"ttl":"60s"}),
    )?;
    status(&issued, 200);
    let child = secret(&mut issued, "/auth/client_token")?;
    f.assert_value(&parent)?;
    f.assert_value(&child)?;
    let before = f.root()?;
    // The actual Userpass actor retires its own mount and both real tokens.
    // Only this exact empty acknowledgement may survive its own revocation.
    let retired = f.actor(&parent, "DELETE", "sys/auth/up", json!({}))?;
    status(&retired, 204);
    assert!(retired.body.is_null());
    let mut f = f.restart()?;
    for token in [&parent, &child] {
        let response = f.actor(token, "GET", "up-kv/data/value", json!({}))?;
        status(&response, 403);
        assert!(response.body.get("data").is_none());
    }
    assert!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_userpass_issuance_state()
    );
    f.assert_business_unchanged(&before)?;
    let admin = Zeroizing::new(f.admin.to_string());
    f.assert_value(&admin)?;
    Ok(())
}

#[test]
fn native_userpass_formal_failed_login_lockout_is_durable_across_cold_open() -> TestResult {
    let mut f = Fixture::new()?;
    f.user("alice", 0)?;
    status(&f.admin("POST", "sys/auth/up/tune", json!({
        "user_lockout_disable":false, "user_lockout_threshold":2, "user_lockout_duration":"60s",
        "user_lockout_counter_reset_duration":"60s",
    }))?, 204);
    let before = f.root()?;
    for _ in 0..2 {
        let response = f.actor(
            "",
            "POST",
            "auth/up/login/alice",
            json!({"password":"wrong"}),
        )?;
        status(&response, 400);
        assert!(response.body.get("auth").is_none());
    }
    let mut f = f.restart()?;
    let denied = f.actor(
        "",
        "POST",
        "auth/up/login/alice",
        json!({"password":PASSWORD}),
    )?;
    status(&denied, 403);
    assert!(denied.body.get("auth").is_none());
    f.now += 61;
    let token = f.login("alice")?;
    f.assert_value(&token)?;
    f.assert_business_unchanged(&before)?;
    Ok(())
}

#[test]
fn native_userpass_formal_acl_retains_admin_sudo_and_account_scope() -> TestResult {
    let mut f = Fixture::new()?;
    status(&f.admin("POST", "sys/policies/acl/up-delegate", json!({"policy":
        "path \"auth/up/users/alice\" { capabilities = [\"read\",\"update\"] } path \"auth/up/users/alice/mfa\" { capabilities = [\"update\"] } path \"sys/auth/up/tune\" { capabilities = [\"read\",\"update\"] }"
    }))?, 204);
    let delegate = f.token("up-delegate")?;
    status(
        &f.actor(
            &delegate,
            "POST",
            "auth/up/users/alice",
            json!({"password":PASSWORD,"policies":["native-up"]}),
        )?,
        204,
    );
    status(
        &f.actor(&delegate, "GET", "auth/up/users/alice", json!({}))?,
        200,
    );
    for (method, path, body) in [
        ("GET", "sys/auth/up/tune", json!({})),
        (
            "POST",
            "sys/auth/up/tune",
            json!({"description":"unauthorized"}),
        ),
        ("POST", "auth/up/users/alice/mfa", json!({})),
        ("POST", "auth/up/users/bob", json!({"password":PASSWORD})),
    ] {
        let response = f.actor(&delegate, method, path, body)?;
        status(&response, 403);
        assert!(response.body.get("data").is_none());
        assert!(response.body.get("auth").is_none());
    }
    let token = f.login("alice")?;
    f.assert_value(&token)?;
    let denied = f.actor(
        &token,
        "POST",
        "up-kv/data/value",
        json!({"data":{"value":"not-authorized"}}),
    )?;
    status(&denied, 403);
    f.assert_value(&token)?;
    Ok(())
}

#[test]
fn native_userpass_formal_finite_token_delivery_does_not_consume_an_extra_use() -> TestResult {
    let mut f = Fixture::new()?;
    f.user("alice", 2)?;
    let token = f.login("alice")?;
    let lookup = f.admin("POST", "auth/token/lookup", json!({"token":token.as_str()}))?;
    status(&lookup, 200);
    assert_eq!(lookup.body["data"]["num_uses"], 2);
    let mut f = f.restart()?;
    f.assert_value(&token)?;
    f.assert_value(&token)?;
    let response = f.actor(&token, "GET", "up-kv/data/value", json!({}))?;
    status(&response, 403);
    assert!(response.body.get("data").is_none());
    Ok(())
}

#[test]
fn native_userpass_actual_audit_response_status_and_error_tampering_are_vetoed() -> TestResult {
    let mut f = Fixture::new()?;
    f.user("alice", 0)?;
    let (mut response, _) = f.audited_login(PASSWORD, Duration::from_secs(15))?;
    status(&response, 200);
    let issued = Zeroizing::new(text(&response, "/auth/client_token")?);
    response.status = 503;
    let response = f
        .service
        .complete_native_auth_delivery(true, response, "up-status-custody");
    status(&response, 503);
    assert!(response.body.get("auth").is_none() && response.body.get("data").is_none());
    assert!(!response.body.to_string().contains(issued.as_str()));
    assert!(response.consistency_index.is_none());
    let (mut response, _) = f.audited_login("wrong", Duration::from_secs(15))?;
    status(&response, 400);
    response.status = 200;
    response.body = json!({"auth":{"client_token":"invented-after-actual-audit"}});
    let response = f
        .service
        .complete_native_auth_delivery(true, response, "up-error-custody");
    status(&response, 503);
    assert!(response.body.get("auth").is_none());
    assert!(f.service.pending_native_auth_delivery.is_none());
    Ok(())
}

#[test]
fn native_userpass_actual_audit_cannot_refresh_the_original_request_deadline() -> TestResult {
    let mut f = Fixture::new()?;
    f.user("alice", 0)?;
    let (response, until) = f.audited_login(PASSWORD, Duration::from_millis(1500))?;
    status(&response, 200);
    std::thread::sleep(until.saturating_duration_since(Instant::now()) + Duration::from_millis(2));
    let response = f
        .service
        .complete_native_auth_delivery(true, response, "up-original-deadline");
    status(&response, 503);
    assert!(response.body.get("auth").is_none() && response.body.get("data").is_none());
    assert!(response.consistency_index.is_none());
    assert!(f.service.pending_native_auth_delivery.is_none());
    let mut f = f.restart()?;
    let token = f.login("alice")?;
    f.assert_value(&token)?;
    Ok(())
}

#[test]
fn native_userpass_actual_post_audit_revocation_vetoes_the_original_credential_reply() -> TestResult
{
    let mut f = Fixture::new()?;
    f.user("alice", 0)?;
    let (response, _) = f.audited_login(PASSWORD, Duration::from_secs(15))?;
    status(&response, 200);
    let issued = Zeroizing::new(text(&response, "/auth/client_token")?);
    // Retain the actual already-audited affine delivery; do not mint a new
    // actor or proof. Interleave one separately authorized real root request.
    let original = f
        .service
        .pending_native_auth_delivery
        .take()
        .ok_or("original audited owner")?;
    status(
        &f.admin(
            "POST",
            "auth/token/revoke",
            json!({"token":issued.as_str()}),
        )?,
        204,
    );
    assert!(f.service.pending_native_auth_delivery.is_none());
    f.service.pending_native_auth_delivery = Some(original);
    let response = f
        .service
        .complete_native_auth_delivery(true, response, "up-actual-retirement");
    status(&response, 503);
    assert!(response.body.get("auth").is_none() && response.body.get("data").is_none());
    assert!(!response.body.to_string().contains(issued.as_str()));
    assert!(response.consistency_index.is_none());
    assert!(f.service.pending_native_auth_delivery.is_none());
    let mut f = f.restart()?;
    status(
        &f.actor(&issued, "GET", "auth/token/lookup-self", json!({}))?,
        403,
    );
    Ok(())
}

#[test]
fn native_userpass_selector_keeps_other_providers_and_wrapped_login_closed() -> TestResult {
    let mut f = Fixture::new()?;
    f.user("alice", 0)?;
    let before = f.root()?;
    for (path, body) in [
        ("sys/auth/other", json!({"type":"jwt"})),
        ("auth/up/config", json!({})),
    ] {
        let response = f.admin("POST", path, body)?;
        status(&response, 501);
        assert!(response.body.get("auth").is_none());
    }
    // The formal Auth remount owner still requires its own ACL grant.
    // A real ordinary user token must not move the mount or create a job.
    let actor = f.token("native-up")?;
    let denied = f.actor(
        &actor,
        "POST",
        "sys/remount",
        json!({"from":"auth/up","to":"auth/moved"}),
    )?;
    status(&denied, 403);
    assert!(denied.body.get("data").is_none());
    assert!(f.service.pending_native_remount.is_none());
    assert!(f.service.native_remount_jobs.is_empty());
    assert!(f.service.native_remount_statuses.is_empty());
    status(&f.admin("GET", "auth/up/users/alice", json!({}))?, 200);
    f.now += 1;
    let started = Instant::now();
    let clock = RequestClock::anchored(Duration::from_secs(f.now), started)?;
    let _scope =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let execution = f.service.begin_at_mode_precise(
        RequestDispatch {
            method: "POST",
            path: "auth/up/login/alice",
            namespace: "",
            token: "",
            body: json!({"password":PASSWORD}),
            now: f.now,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: Some(30),
            origin_peer: None,
            client_certificates: None,
        },
        clock,
    );
    let response = f.service.finish_synchronous_request(execution);
    status(&response, 501);
    assert!(response.body.get("auth").is_none() && response.body.get("wrap_info").is_none());
    f.assert_business_unchanged(&before)?;
    Ok(())
}

#[path = "service_native_userpass_batch_tests.rs"]
mod batch_tests;

#[path = "service_native_batch_issuer_tests.rs"]
mod batch_issuer_tests;
