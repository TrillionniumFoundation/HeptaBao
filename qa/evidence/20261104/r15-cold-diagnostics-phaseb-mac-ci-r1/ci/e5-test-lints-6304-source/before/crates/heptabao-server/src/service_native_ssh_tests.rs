//! Synthetic credentials through the configured normal File profile, public
//! activation, real SSH crypto, exact native publication, audit and cold open.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::Root;
use ssh_key::{Certificate, HashAlg, PublicKey};
use std::cell::RefCell;

#[path = "service_native_ssh_archive_tests.rs"]
mod archive;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type AfterAudit = Box<dyn FnOnce(&mut Service, &mut Response)>;
thread_local! { static AFTER_AUDIT: RefCell<Option<AfterAudit>> = RefCell::new(None); }

pub(super) fn after_actual_ssh_audit(service: &mut Service, response: &mut Response) {
    let hook = AFTER_AUDIT.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        assert!(service.native_failure_notice.is_none());
        let binding = service.native_request_binding.take();
        assert!(binding.is_some());
        assert!(service.pending_native_auth_delivery.is_none());
        hook(service, response);
        assert!(service.native_request_binding.is_none());
        assert!(service.native_failure_notice.is_none());
        assert!(service.pending_native_auth_delivery.is_none());
        service.native_request_binding = binding;
    }
}
struct HookGuard;
impl Drop for HookGuard {
    fn drop(&mut self) {
        AFTER_AUDIT.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
fn after_audit(hook: impl FnOnce(&mut Service, &mut Response) + 'static) -> TestResult<HookGuard> {
    AFTER_AUDIT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err("SSH audit hook already armed".into());
        }
        *slot = Some(Box::new(hook));
        Ok(HookGuard)
    })
}
fn status(response: &Response, expected: u16) {
    assert_eq!(response.status, expected, "native SSH response status");
}
fn field(response: &Response, path: &str) -> TestResult<String> {
    response
        .body
        .pointer(path)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "required synthetic SSH field absent".into())
}
fn secret(response: &mut Response, path: &str) -> TestResult<Zeroizing<String>> {
    let result = Zeroizing::new(field(response, path)?);
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
    scoped_call(service, now, token, method, path, body, "", None)
}
#[allow(clippy::too_many_arguments)]
fn scoped_call(
    service: &mut Service,
    now: &mut u64,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
    namespace: &str,
    wrap_ttl_seconds: Option<u64>,
) -> TestResult<Response> {
    *now += 1;
    let started = Instant::now();
    let clock = RequestClock::anchored(Duration::from_secs(*now), started)?;
    let _deadline =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let execution = service.begin_at_mode_precise(
        RequestDispatch {
            method,
            path,
            namespace,
            token,
            body,
            now: *now,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds,
            origin_peer: None,
            client_certificates: None,
        },
        clock,
    );
    let response = service.finish_synchronous_request(execution);
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "original SSH request budget"
    );
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
        let mut init = call(
            &mut service,
            &mut now,
            "",
            "POST",
            "sys/init",
            json!({"secret_shares":1,"secret_threshold":1}),
        )?;
        status(&init, 200);
        let key = Zeroizing::new(field(&init, "/keys/0")?);
        let admin = secret(&mut init, "/root_token")?;
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
        f.activate()?;
        Ok(f)
    }
    fn activate(&mut self) -> TestResult {
        status(
            &self.admin("POST", native_storage::ACTIVATE_PATH, json!({}))?,
            204,
        );
        assert!(self.service.native_root.is_some());
        assert!(self.service.record_root.is_none());
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
        actor: &str,
        method: &str,
        path: &str,
        body: Value,
    ) -> TestResult<Response> {
        call(&mut self.service, &mut self.now, actor, method, path, body)
    }
    fn install(&mut self) -> TestResult {
        status(
            &self.admin(
                "POST",
                "sys/mounts/ssh",
                json!({"type":"ssh",
            "config":{"default_lease_ttl":"600s","max_lease_ttl":"1200s"}}),
            )?,
            204,
        );
        status(
            &self.admin(
                "POST",
                "ssh/roles/test",
                json!({"key_type":"otp",
            "default_user":"deploy","allowed_users":"deploy,backup",
            "cidr_list":"127.0.0.0/8,::1/128","exclude_cidr_list":"127.1.0.0/16"}),
            )?,
            204,
        );
        Ok(())
    }
    fn issue(&mut self, actor: &str) -> TestResult<(Zeroizing<String>, String)> {
        let mut issued = self.actor(actor, "POST", "ssh/creds/test", json!({"ip":"127.0.0.1"}))?;
        status(&issued, 200);
        assert_eq!(issued.body["renewable"], false);
        let id = field(&issued, "/lease_id")?;
        let otp = secret(&mut issued, "/data/key")?;
        Ok((otp, id))
    }
    fn restart(mut self) -> TestResult<Self> {
        drop(self.service);
        self.service = self.files.service()?;
        self.service
            .configure_native_v6_storage(NativeStorageProfile::File)?;
        status(
            &self.actor("", "POST", "sys/unseal", json!({"key":self.key.as_str()}))?,
            200,
        );
        assert!(self.service.native_root.is_some());
        Ok(self)
    }
    fn policy_actor(&mut self) -> TestResult<Zeroizing<String>> {
        status(
            &self.admin(
                "POST",
                "sys/policies/acl/ssh-issue",
                json!({"policy":
            "path \"ssh/creds/test\" { capabilities=[\"update\"] }"}),
            )?,
            204,
        );
        let mut issued = self.admin(
            "POST",
            "auth/token/create",
            json!({
            "policies":["ssh-issue"],"no_default_policy":true,"ttl":"1h"}),
        )?;
        status(&issued, 200);
        secret(&mut issued, "/auth/client_token")
    }
    fn audited(
        &mut self,
        actor: &str,
        method: &str,
        path: &str,
        body: Value,
        budget: Duration,
    ) -> TestResult<(Response, Instant)> {
        self.now += 1;
        let started = Instant::now();
        let until = started + budget;
        let clock = RequestClock::anchored(Duration::from_secs(self.now), started)?;
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(until);
        let response = self.service.handle_inner(RequestView {
            method,
            path,
            namespace: "",
            token: actor,
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
        status(&response, 200);
        let delivery = self
            .service
            .pending_native_auth_delivery
            .as_ref()
            .ok_or("actual SSH owner")?;
        assert!(delivery.ssh_owner.is_some() && delivery.requires_local_proof());
        assert!(delivery.tracks_terminal_checkpoint() && delivery.proof.is_none());
        let response = self.service.audit_completed_response_with_receipt(
            "native-ssh-actual-audit",
            self.now,
            Some(clock),
            response,
            || {},
        );
        status(&response, 200);
        let delivery = self
            .service
            .pending_native_auth_delivery
            .as_ref()
            .ok_or("audited SSH owner")?;
        assert!(matches!(
            delivery.proof.as_ref(),
            Some(native_v6_reader::NativeProof::Single(_))
        ));
        Ok((response, until))
    }
    fn complete(&mut self, response: Response, until: Instant) -> Response {
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(until);
        self.service
            .complete_native_auth_delivery(true, response, "ssh-original-audited-delivery")
    }
    fn idle(&mut self, now: u64) -> TestResult<bool> {
        self.now = now;
        let started = Instant::now();
        let clock = RequestClock::anchored(Duration::from_secs(now), started)?;
        let _deadline =
            crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
        Ok(self
            .service
            .maintain_native_transit_with_clock_for_test(now, clock)?)
    }
}
fn private_bytes_absent(path: &std::path::Path, secret: &[u8]) -> TestResult {
    for entry in fs::read_dir(path)? {
        let path = entry?.path();
        if path.is_dir() {
            private_bytes_absent(&path, secret)?;
        } else if path.is_file() {
            assert!(
                !fs::read(path)?
                    .windows(secret.len())
                    .any(|bytes| bytes == secret),
                "issued OTP must not appear in durable plaintext"
            );
        }
    }
    Ok(())
}

#[test]
fn native_ssh_formal_otp_promotion_cold_verify_and_replay() -> TestResult {
    let mut f = Fixture::initialized()?;
    f.install()?;
    let admin = f.admin.clone();
    let (otp, lease) = f.issue(&admin)?;
    f.activate()?;
    private_bytes_absent(&f.files.path.join("data"), otp.as_bytes())?;
    let mut f = f.restart()?;
    status(
        &f.admin("POST", "sys/leases/lookup", json!({"lease_id":lease}))?,
        200,
    );
    let verified = f.actor(
        "invalid-ignored-bearer",
        "POST",
        "ssh/verify",
        json!({"otp":otp.as_str()}),
    )?;
    status(&verified, 200);
    assert_eq!(
        verified.body["data"],
        json!({"ip":"127.0.0.1","username":"deploy","role_name":"test"})
    );
    let mut f = f.restart()?;
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":otp.as_str()}))?,
        400,
    );
    status(
        &f.admin("POST", "sys/leases/lookup", json!({"lease_id":lease}))?,
        200,
    );
    Ok(())
}

#[test]
fn native_ssh_formal_acl_nonrenewable_revoke_and_segment_prefix() -> TestResult {
    let mut f = Fixture::new()?;
    f.install()?;
    let actor = f.policy_actor()?;
    status(
        &f.actor(&actor, "POST", "ssh/creds/test", json!({"ip":"127.1.0.1"}))?,
        400,
    );
    status(
        &f.actor(
            &actor,
            "POST",
            "ssh/creds/test",
            json!({"ip":"127.0.0.1","username":"root"}),
        )?,
        400,
    );
    status(
        &f.actor(&actor, "POST", "ssh/roles/other", json!({"key_type":"otp"}))?,
        403,
    );
    let (otp, lease) = f.issue(&actor)?;
    status(
        &f.admin(
            "POST",
            "sys/leases/renew",
            json!({"lease_id":lease,"increment":60}),
        )?,
        400,
    );
    status(
        &f.admin("POST", "sys/leases/revoke-prefix/ssh/creds/tes", json!({}))?,
        204,
    );
    status(
        &f.admin("POST", "sys/leases/lookup", json!({"lease_id":lease}))?,
        200,
    );
    status(
        &f.admin("POST", "sys/leases/revoke", json!({"lease_id":lease}))?,
        204,
    );
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":otp.as_str()}))?,
        400,
    );
    let (second, _) = f.issue(&actor)?;
    status(
        &f.admin("POST", "auth/token/revoke", json!({"token":actor.as_str()}))?,
        204,
    );
    let mut f = f.restart()?;
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":second.as_str()}))?,
        400,
    );
    Ok(())
}

fn install_ca(f: &mut Fixture) -> TestResult<String> {
    let created = f.admin("POST", "ssh/config/ca", json!({"key_type":"ed25519"}))?;
    status(&created, 200);
    let public = field(&created, "/data/public_key")?;
    status(
        &f.admin(
            "POST",
            "ssh/roles/operators",
            json!({"key_type":"ca",
        "allow_user_certificates":true,"allowed_users":"alice","default_user":"alice","ttl":"60s"}),
        )?,
        204,
    );
    Ok(public)
}

#[test]
fn native_ssh_formal_ca_real_signature_cold_typed_public_transport() -> TestResult {
    let mut f = Fixture::new()?;
    f.install()?;
    let public = install_ca(&mut f)?;
    let mut f = f.restart()?;
    let mut issued = f.admin("POST", "ssh/issue/operators", json!({"key_type":"ed25519"}))?;
    status(&issued, 200);
    let certificate = Certificate::from_openssh(
        issued.body["data"]["signed_key"]
            .as_str()
            .ok_or("certificate")?,
    )?;
    certificate.validate_at(
        f.now,
        [&PublicKey::from_openssh(&public)?.fingerprint(HashAlg::Sha256)],
    )?;
    assert_eq!(certificate.valid_principals(), &["alice"]);
    erase_json(&mut issued.body);
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .native_ssh_signature_count("ssh/"),
        Some(1)
    );
    let _ingress = crate::auth::IngressReplyScope::listener(&[0xd1; 16]);
    let response = f.actor("", "GET", "ssh/public_key", json!({}))?;
    status(&response, 200);
    let origin = response
        .unwrapped_json
        .as_ref()
        .ok_or("actual public transport")?;
    assert_eq!(
        origin.raw_http_transport(&response.body)?,
        Some((200, "text/plain"))
    );
    assert_eq!(
        origin.raw_bytes(&response.body)?.ok_or("public bytes")?,
        public.as_bytes()
    );
    status(&f.actor("", "GET", "ssh/config/ca", json!({}))?, 403);
    Ok(())
}

#[test]
fn native_ssh_after_actual_audit_actor_revocation_never_delivers_otp() -> TestResult {
    let mut f = Fixture::new()?;
    f.install()?;
    let actor = f.policy_actor()?;
    let revoke_root = f.admin.clone();
    let revoke_actor = actor.clone();
    let mut hook_now = f.now + 1;
    let _hook = after_audit(move |service, response| {
        assert!(response.status == 200 && response.body["data"]["key"].is_string());
        let revoked = call(
            service,
            &mut hook_now,
            &revoke_root,
            "POST",
            "auth/token/revoke",
            json!({"token":revoke_actor.as_str()}),
        )
        .expect("actual token revocation");
        status(&revoked, 204);
    })?;
    let response = f.actor(&actor, "POST", "ssh/creds/test", json!({"ip":"127.0.0.1"}))?;
    assert!(response.status >= 400);
    assert!(response.body.get("data").is_none());
    status(
        &f.actor(&actor, "POST", "ssh/creds/test", json!({"ip":"127.0.0.1"}))?,
        403,
    );
    Ok(())
}

#[test]
fn native_ssh_after_actual_audit_changed_status_does_not_bypass_or_resign() -> TestResult {
    let mut f = Fixture::new()?;
    f.install()?;
    install_ca(&mut f)?;
    let _hook = after_audit(|service, response| {
        assert!(response.status == 200 && response.body["data"]["private_key"].is_string());
        assert_eq!(
            service
                .state
                .as_ref()
                .expect("state")
                .engines
                .native_ssh_signature_count("ssh/"),
            Some(1)
        );
        response.status = 503;
    })?;
    let response = f.admin("POST", "ssh/issue/operators", json!({"key_type":"ed25519"}))?;
    status(&response, 503);
    assert!(response.body.get("data").is_none());
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .native_ssh_signature_count("ssh/"),
        Some(1)
    );
    let f = f.restart()?;
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .native_ssh_signature_count("ssh/"),
        Some(1)
    );
    Ok(())
}

#[test]
fn native_ssh_public_reply_cannot_lose_affine_transport_after_audit() -> TestResult {
    let mut f = Fixture::new()?;
    f.install()?;
    install_ca(&mut f)?;
    let _hook = after_audit(|_service, response| {
        assert!(response.status == 200 && response.unwrapped_json.is_some());
        response.unwrapped_json = None;
    })?;
    let _ingress = crate::auth::IngressReplyScope::listener(&[0xd2; 16]);
    let response = f.actor("", "GET", "ssh/public_key", json!({}))?;
    status(&response, 503);
    assert!(response.body.get("data").is_none());
    Ok(())
}

#[test]
fn native_ssh_and_pki_original_idle_retire_both_without_touching_ca_or_kv() -> TestResult {
    let mut f = Fixture::new()?;
    f.install()?;
    let public = install_ca(&mut f)?;
    status(
        &f.admin(
            "POST",
            "sys/mounts/kv",
            json!({"type":"kv","options":{"version":"2"}}),
        )?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "kv/data/sentinel",
            json!({"options":{"cas":0},"data":{"kept":"unchanged"}}),
        )?,
        200,
    );
    status(
        &f.admin("POST", "sys/mounts/pki", json!({"type":"pki"}))?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "pki/root/generate/internal",
            json!({"common_name":"ca.example.test",
        "key_type":"ec","key_bits":256,"ttl":"48h"}),
        )?,
        200,
    );
    status(&f.admin("POST", "pki/roles/web", json!({"allowed_domains":["example.test"],
        "allow_subdomains":true,"key_type":"ec","key_bits":256,"max_ttl":"2h","generate_lease":true}))?, 200);
    let mut leaf = f.admin(
        "POST",
        "pki/issue/web",
        json!({"common_name":"api.example.test","ttl":"60s"}),
    )?;
    status(&leaf, 200);
    let pki_lease = field(&leaf, "/lease_id")?;
    erase_json(&mut leaf.body);
    let admin = f.admin.clone();
    let (otp, ssh_lease) = f.issue(&admin)?;
    let before = f.service.native_root.clone().ok_or("native root")?;
    let old = f.now;
    assert!(f.idle(old + 1300)?);
    let after = f.service.native_root.clone().ok_or("native root")?;
    assert!(before.kv1 == after.kv1 && before.kv2 == after.kv2);
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .native_ssh_signature_count("ssh/"),
        Some(0)
    );
    let generation = f.service.durable.as_ref().ok_or("durable")?.generation();
    assert!(!f.idle(old)?);
    assert_eq!(
        f.service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    let mut f = f.restart()?;
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":otp.as_str()}))?,
        400,
    );
    for lease in [ssh_lease, pki_lease] {
        let response = f.admin("POST", "sys/leases/lookup", json!({"lease_id":lease}))?;
        assert!(response.status >= 400);
    }
    let _ingress = crate::auth::IngressReplyScope::listener(&[0xd3; 16]);
    let response = f.actor("", "GET", "ssh/public_key", json!({}))?;
    status(&response, 200);
    assert_eq!(
        response
            .unwrapped_json
            .as_ref()
            .ok_or("public owner")?
            .raw_bytes(&response.body)?
            .ok_or("public bytes")?,
        public.as_bytes()
    );
    let response = f.admin("GET", "kv/data/sentinel", json!({}))?;
    status(&response, 200);
    assert_eq!(response.body["data"]["data"], json!({"kept":"unchanged"}));
    Ok(())
}

#[test]
fn native_ssh_consumed_verify_rechecks_original_issuer_after_actual_audit() -> TestResult {
    let mut f = Fixture::new()?;
    f.install()?;
    let actor = f.policy_actor()?;
    let (otp, _) = f.issue(&actor)?;
    let revoke_root = f.admin.clone();
    let revoke_actor = actor.clone();
    let mut hook_now = f.now + 1;
    let _hook = after_audit(move |service, response| {
        assert!(response.status == 200 && response.body["data"]["username"].is_string());
        status(
            &call(
                service,
                &mut hook_now,
                &revoke_root,
                "POST",
                "auth/token/revoke",
                json!({"token":revoke_actor.as_str()}),
            )
            .expect("actual issuer revoke"),
            204,
        );
    })?;
    let response = f.actor("", "POST", "ssh/verify", json!({"otp":otp.as_str()}))?;
    assert!(response.status >= 400 && response.body.get("data").is_none());
    let mut f = f.restart()?;
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":otp.as_str()}))?,
        400,
    );
    Ok(())
}

#[test]
fn native_ssh_formal_batch_expiry_is_clipped_persistent_and_not_revivable() -> TestResult {
    let mut f = Fixture::new()?;
    f.install()?;
    status(
        &f.admin(
            "POST",
            "sys/policies/acl/ssh-issue",
            json!({"policy":
        "path \"ssh/creds/test\" { capabilities=[\"update\"] }"}),
        )?,
        204,
    );
    status(
        &f.admin("POST", "sys/auth/up", json!({"type":"userpass"}))?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "auth/up/users/batch",
            json!({
        "password":"synthetic-ssh-batch-password","policies":["ssh-issue"],
        "token_type":"batch","token_ttl":120,"token_max_ttl":600,"token_num_uses":0}),
        )?,
        204,
    );
    let mut login = f.actor(
        "",
        "POST",
        "auth/up/login/batch",
        json!({"password":"synthetic-ssh-batch-password"}),
    )?;
    status(&login, 200);
    assert_eq!(login.body["auth"]["token_type"], "batch");
    let actor = secret(&mut login, "/auth/client_token")?;
    let lookup = f.actor(&actor, "GET", "auth/token/lookup-self", json!({}))?;
    status(&lookup, 200);
    let expires = lookup.body["data"]["expire_time_unix"]
        .as_u64()
        .ok_or("batch expiry")?;
    let mut issued = f.actor(&actor, "POST", "ssh/creds/test", json!({"ip":"127.0.0.1"}))?;
    status(&issued, 200);
    let ttl = issued.body["lease_duration"]
        .as_u64()
        .ok_or("actual OTP lifetime")?;
    assert!(ttl > 0 && ttl <= expires.saturating_sub(f.now));
    let otp = secret(&mut issued, "/data/key")?;
    let mut f = f.restart()?;
    assert!(f.idle(expires + 1)?);
    f.now = 100;
    let mut f = f.restart()?;
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":otp.as_str()}))?,
        400,
    );
    Ok(())
}

#[test]
fn native_ssh_formal_disabled_login_identity_stays_retired_after_reenable_and_cold() -> TestResult {
    let mut f = Fixture::new()?;
    f.install()?;
    status(
        &f.admin(
            "POST",
            "sys/policies/acl/ssh-issue",
            json!({"policy":
        "path \"ssh/creds/test\" { capabilities=[\"update\"] }"}),
        )?,
        204,
    );
    status(
        &f.admin("POST", "sys/auth/ssh-login", json!({"type":"approle"}))?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "auth/ssh-login/role/test",
            json!({"token_policies":["ssh-issue"]}),
        )?,
        204,
    );
    let mut role = f.admin("GET", "auth/ssh-login/role/test/role-id", json!({}))?;
    let mut sid = f.admin("POST", "auth/ssh-login/role/test/secret-id", json!({}))?;
    status(&role, 200);
    status(&sid, 200);
    let mut login = f.actor(
        "",
        "POST",
        "auth/ssh-login/login",
        json!({
        "role_id":role.body["data"]["role_id"],"secret_id":sid.body["data"]["secret_id"]}),
    )?;
    erase_json(&mut role.body);
    erase_json(&mut sid.body);
    status(&login, 200);
    let entity = field(&login, "/auth/entity_id")?;
    let actor = secret(&mut login, "/auth/client_token")?;
    let (otp, _) = f.issue(&actor)?;
    let path = format!("identity/entity/id/{entity}");
    status(&f.admin("POST", &path, json!({"disabled":true}))?, 204);
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":otp.as_str()}))?,
        400,
    );
    status(&f.admin("POST", &path, json!({"disabled":false}))?, 204);
    let mut f = f.restart()?;
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":otp.as_str()}))?,
        400,
    );
    let _ = f.issue(&actor)?;
    Ok(())
}

#[test]
fn native_ssh_actual_audit_cannot_refresh_original_deadline_or_repeat_signature() -> TestResult {
    let mut f = Fixture::new()?;
    f.install()?;
    install_ca(&mut f)?;
    let admin = f.admin.clone();
    let (response, until) = f.audited(
        &admin,
        "POST",
        "ssh/issue/operators",
        json!({"key_type":"ed25519"}),
        Duration::from_millis(1500),
    )?;
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .native_ssh_signature_count("ssh/"),
        Some(1)
    );
    std::thread::sleep(until.saturating_duration_since(Instant::now()) + Duration::from_millis(20));
    let denied = f.complete(response, until);
    status(&denied, 503);
    assert!(denied.body.get("data").is_none() && denied.consistency_index.is_none());
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .native_ssh_signature_count("ssh/"),
        Some(1)
    );
    Ok(())
}

#[test]
fn native_ssh_formal_registry_tune_retire_and_recreate_preserves_other_graphs() -> TestResult {
    let mut f = Fixture::new()?;
    f.install()?;
    status(
        &f.admin(
            "POST",
            "sys/mounts/kept",
            json!({"type":"kv","options":{"version":"2"}}),
        )?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "kept/data/sentinel",
            json!({"options":{"cas":0},"data":{"kept":true}}),
        )?,
        200,
    );
    let graph = f
        .service
        .state
        .as_ref()
        .ok_or("state")?
        .engines
        .record_root();
    let admin = f.admin.clone();
    let (old, _) = f.issue(&admin)?;
    status(
        &f.admin(
            "POST",
            "sys/mounts/ssh/tune",
            json!({"default_lease_ttl":"300s","max_lease_ttl":"900s"}),
        )?,
        204,
    );
    let tuned = f.admin("GET", "sys/mounts/ssh/tune", json!({}))?;
    status(&tuned, 200);
    assert_eq!(tuned.body["data"]["max_lease_ttl"], 900);
    let mut f = f.restart()?;
    status(&f.admin("DELETE", "sys/mounts/ssh", json!({}))?, 204);
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .record_root(),
        graph
    );
    let mut f = f.restart()?;
    let mounts = f.admin("GET", "sys/mounts", json!({}))?;
    status(&mounts, 200);
    assert!(mounts.body["data"].get("ssh/").is_none());
    f.install()?;
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":old.as_str()}))?,
        400,
    );
    let value = f.admin("GET", "kept/data/sentinel", json!({}))?;
    status(&value, 200);
    assert_eq!(value.body["data"]["data"], json!({"kept":true}));
    Ok(())
}

#[test]
fn native_ssh_actual_audited_reply_cannot_follow_recreated_mount_incarnation() -> TestResult {
    let mut f = Fixture::new()?;
    f.install()?;
    let admin = f.admin.clone();
    let (response, until) = f.audited(
        &admin,
        "POST",
        "ssh/creds/test",
        json!({"ip":"127.0.0.1"}),
        Duration::from_secs(15),
    )?;
    let otp = Zeroizing::new(field(&response, "/data/key")?);
    let capsule = f
        .service
        .pending_native_auth_delivery
        .take()
        .ok_or("audited SSH capsule")?;
    status(&f.admin("DELETE", "sys/mounts/ssh", json!({}))?, 204);
    f.install()?;
    assert!(f.service.pending_native_auth_delivery.is_none());
    f.service.pending_native_auth_delivery = Some(capsule);
    let rejected = f.complete(response, until);
    status(&rejected, 503);
    assert!(rejected.body.get("data").is_none() && rejected.consistency_index.is_none());
    let mut f = f.restart()?;
    status(
        &f.actor("", "POST", "ssh/verify", json!({"otp":otp.as_str()}))?,
        400,
    );
    Ok(())
}

#[test]
fn native_ssh_child_and_response_wrap_ownership_remain_explicitly_closed() -> TestResult {
    let mut f = Fixture::new()?;
    f.install()?;
    let before = f
        .service
        .state
        .as_ref()
        .ok_or("state")?
        .engines
        .lease_owners();
    let wrapped = scoped_call(
        &mut f.service,
        &mut f.now,
        &f.admin,
        "POST",
        "ssh/creds/test",
        json!({"ip":"127.0.0.1"}),
        "",
        Some(60),
    )?;
    status(&wrapped, 501);
    assert!(wrapped.body.get("data").is_none() && wrapped.body.get("wrap_info").is_none());
    assert!(
        f.service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .lease_owners()
            == before
    );
    status(&f.admin("POST", "sys/namespaces/child", json!({}))?, 200);
    let child = scoped_call(
        &mut f.service,
        &mut f.now,
        &f.admin,
        "POST",
        "sys/mounts/ssh",
        json!({"type":"ssh"}),
        "child",
        None,
    )?;
    status(&child, 501);
    assert!(
        !f.service
            .state
            .as_ref()
            .ok_or("state")?
            .engines
            .native_local_ssh_mounted("child", "ssh/")
    );
    Ok(())
}

#[test]
fn native_ssh_actual_audit_io_failure_never_returns_the_signed_private_reply() -> TestResult {
    let mut f = Fixture::new()?;
    f.install()?;
    install_ca(&mut f)?;
    f.now += 1;
    let started = Instant::now();
    let until = started + Duration::from_secs(15);
    let clock = RequestClock::anchored(Duration::from_secs(f.now), started)?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(until);
    let body = json!({"key_type":"ed25519"});
    let response = f.service.handle_inner(RequestView {
        method: "POST",
        path: "ssh/issue/operators",
        namespace: "",
        token: &f.admin,
        body: &body,
        now: f.now,
        admission_started: started,
        token_clock: Some(clock),
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    });
    status(&response, 200);
    assert!(response.body["data"]["private_key"].is_string());
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("actual signed state")?
            .engines
            .native_ssh_signature_count("ssh/"),
        Some(1)
    );
    assert!(
        f.service
            .pending_native_auth_delivery
            .as_ref()
            .is_some_and(|delivery| delivery.ssh_owner.is_some())
    );
    // The actual mandatory audit writer now has the same owned file opened
    // read-only. Its real append fails; no successful audit receipt is invented.
    let readonly = fs::File::open(f.files.path.join("audit.jsonl"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let held = f.service.audit.metadata()?;
        let replacement = readonly.metadata()?;
        assert_eq!(
            (held.dev(), held.ino()),
            (replacement.dev(), replacement.ino())
        );
    }
    let original = std::mem::replace(&mut f.service.audit, readonly);
    let denied = f.service.audit_completed_response_with_receipt(
        "native-ssh-real-readonly-audit-failure",
        f.now,
        Some(clock),
        response,
        || {},
    );
    status(&denied, 503);
    assert!(denied.body.get("data").is_none() && denied.body.get("auth").is_none());
    assert!(denied.unwrapped_json.is_none() && denied.consistency_index.is_none());
    assert!(f.service.audit_failed);
    assert!(
        f.service
            .pending_native_auth_delivery
            .as_ref()
            .is_some_and(|delivery| delivery.ssh_owner.is_some())
    );
    // The real request path completes its pending owner after response audit,
    // including an audit failure. Audit alone does not consume that owner.
    let denied = f.service.complete_native_auth_delivery(
        true,
        denied,
        "native-ssh-real-failed-audit-delivery",
    );
    status(&denied, 503);
    assert!(denied.body.get("data").is_none() && denied.body.get("auth").is_none());
    assert!(denied.unwrapped_json.is_none() && denied.consistency_index.is_none());
    assert!(f.service.audit_failed && f.service.pending_native_auth_delivery.is_none());
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("actual signed state after failed audit")?
            .engines
            .native_ssh_signature_count("ssh/"),
        Some(1)
    );
    f.service.audit = original;
    let f = f.restart()?;
    assert_eq!(
        f.service
            .state
            .as_ref()
            .ok_or("actual cold signed state")?
            .engines
            .native_ssh_signature_count("ssh/"),
        Some(1)
    );
    Ok(())
}

#[test]
fn native_ssh_actual_audited_otp_retains_original_precise_issuer_expiry() -> TestResult {
    let mut f = Fixture::new()?;
    f.install()?;
    status(
        &f.admin(
            "POST",
            "sys/policies/acl/ssh-short",
            json!({"policy":
        "path \"ssh/creds/test\" { capabilities=[\"update\"] }"}),
        )?,
        204,
    );
    let mut token = f.admin(
        "POST",
        "auth/token/create",
        json!({"policies":["ssh-short"],"no_default_policy":true,"ttl":"2s"}),
    )?;
    status(&token, 200);
    let actor = secret(&mut token, "/auth/client_token")?;
    let (response, until) = f.audited(
        &actor,
        "POST",
        "ssh/creds/test",
        json!({"ip":"127.0.0.1"}),
        Duration::from_secs(15),
    )?;
    assert!(response.body["data"]["key"].is_string());
    std::thread::sleep(Duration::from_millis(1200));
    let denied = f.complete(response, until);
    status(&denied, 403);
    assert!(denied.body.get("data").is_none() && denied.body.get("auth").is_none());
    assert!(denied.consistency_index.is_none() && f.service.pending_native_auth_delivery.is_none());
    Ok(())
}
