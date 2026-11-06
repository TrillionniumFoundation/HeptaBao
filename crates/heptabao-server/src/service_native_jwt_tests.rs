//! Real configured File V6, one JWT verifier, native publication and delivery.
//! Synthetic credentials stay private; these are new independent regressions.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::Root;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::cell::RefCell;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const LOGIN: &str = "auth/native-jwt/login";
const ROLE: &str = "auth/native-jwt/role/client";
const CONFIG: &str = "auth/native-jwt/config";
const POLICY: &str = r#"
path "jwt-kv/data/value" { capabilities = ["read"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
"#;

thread_local! {
    static BEFORE_PUBLICATION: RefCell<Option<(Duration, Arc<AtomicBool>)>> = const { RefCell::new(None) };
}

struct PublicationPause(Arc<AtomicBool>);
impl PublicationPause {
    fn once(delay: Duration) -> Self {
        let fired = Arc::new(AtomicBool::new(false));
        BEFORE_PUBLICATION.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some((delay, Arc::clone(&fired)));
        });
        Self(fired)
    }
}
impl Drop for PublicationPause {
    fn drop(&mut self) {
        BEFORE_PUBLICATION.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

// Reached only after the real successful JWT and Identity dispatch, before
// native planning. This cannot fabricate a token, clock or verifier witness.
pub(super) fn before_actual_jwt_publication() {
    if let Some((delay, fired)) = BEFORE_PUBLICATION.with(|slot| slot.borrow_mut().take()) {
        fired.store(true, Ordering::Release);
        std::thread::sleep(delay);
    }
}

fn status(response: &Response, expected: u16) {
    assert_eq!(
        response.status,
        expected,
        "JWT error shape={:?}",
        response.body.get("errors")
    );
}
fn text(response: &Response, pointer: &str) -> TestResult<String> {
    response
        .body
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "synthetic JWT field missing".into())
}
fn secret(response: &mut Response, pointer: &str) -> TestResult<Zeroizing<String>> {
    let value = Zeroizing::new(text(response, pointer)?);
    erase_json(&mut response.body);
    Ok(value)
}
fn no_credential(response: &Response) {
    assert!(response.status >= 300);
    assert!(response.body.get("auth").is_none());
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("wrap_info").is_none());
    assert!(response.unwrapped_json.is_none() && response.consistency_index.is_none());
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
    // Local JWT must not acquire a remote issuer/provider execution capsule.
    let RequestExecution::Complete(response) = execution else {
        return Err("local native JWT escaped to external execution".into());
    };
    assert!(service.pending_native_auth_delivery.is_none());
    Ok(response)
}

struct Fixture {
    files: Root,
    service: Service,
    key: Zeroizing<String>,
    admin: Zeroizing<String>,
    now: u64,
    pair: Ed25519KeyPair,
}
impl Fixture {
    fn new() -> TestResult<Self> {
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
        let key = Zeroizing::new(text(&init, "/keys/0")?);
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
        let pair =
            Ed25519KeyPair::from_seed_unchecked(&[67; 32]).map_err(|_| "synthetic signing key")?;
        let mut f = Self {
            files,
            service,
            key,
            admin,
            now,
            pair,
        };
        status(
            &f.admin("POST", native_storage::ACTIVATE_PATH, json!({}))?,
            204,
        );
        assert!(f.service.native_root.is_some() && f.service.record_root.is_none());
        status(
            &f.admin(
                "POST",
                "sys/mounts/jwt-kv",
                json!({"type":"kv","options":{"version":"2"}}),
            )?,
            204,
        );
        status(
            &f.admin(
                "POST",
                "jwt-kv/data/value",
                json!({"options":{"cas":0},"data":{"value":"jwt-preserved"}}),
            )?,
            200,
        );
        status(
            &f.admin(
                "PUT",
                "sys/policies/acl/native-jwt",
                json!({"policy":POLICY}),
            )?,
            204,
        );
        // Base 4e808 rejects this actual native mount. Merely exercising the
        // pre-existing legacy JWT handler cannot make this regression pass.
        status(
            &f.admin("POST", "sys/auth/native-jwt", json!({"type":"jwt"}))?,
            204,
        );
        let config = f.config(&f.pair);
        status(&f.admin("POST", CONFIG, config)?, 204);
        status(
            &f.admin(
                "POST",
                ROLE,
                json!({"role_type":"jwt","user_claim":"sub",
            "bound_audiences":["native"],"token_policies":["native-jwt"],
            "token_ttl":300,"token_max_ttl":600,"token_type":"service"}),
            )?,
            204,
        );
        Ok(f)
    }
    fn config(&self, pair: &Ed25519KeyPair) -> Value {
        json!({"issuer":"https://native-jwt.example","audiences":["native"],
            "clock_skew_seconds":0,"keys":[{"kid":"key","algorithm":"EdDSA",
            "key_base64":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())}]})
    }
    fn assertion(&self, expires: u64) -> Zeroizing<String> {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"key"}"#);
        let claims = json!({"iss":"https://native-jwt.example","aud":"native","sub":"alice",
            "iat":self.now,"exp":expires,"jti":"reusable-not-a-nonce"});
        let signing = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims.to_string()));
        Zeroizing::new(format!(
            "{signing}.{}",
            URL_SAFE_NO_PAD.encode(self.pair.sign(signing.as_bytes()).as_ref())
        ))
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
    fn login(&mut self, assertion: &str) -> TestResult<(Zeroizing<String>, String)> {
        let mut response =
            self.actor("", "POST", LOGIN, json!({"role":"client","jwt":assertion}))?;
        status(&response, 200);
        assert_eq!(response.body["auth"]["token_type"], "service");
        assert_eq!(response.body["auth"]["renewable"], true);
        let entity = text(&response, "/auth/entity_id")?;
        let token = secret(&mut response, "/auth/client_token")?;
        Ok((token, entity))
    }
    fn token(&mut self, policy: &str) -> TestResult<Zeroizing<String>> {
        let mut response = self.admin(
            "POST",
            "auth/token/create",
            json!({
                "policies":[policy],"no_default_policy":true,"ttl":"600s"
            }),
        )?;
        status(&response, 200);
        secret(&mut response, "/auth/client_token")
    }
    fn restart(mut self) -> TestResult<Self> {
        drop(self.service);
        let mut service = self.files.service()?;
        service.configure_native_v6_storage(NativeStorageProfile::File)?;
        status(
            &call(
                &mut service,
                &mut self.now,
                "",
                "POST",
                "sys/unseal",
                json!({"key":self.key.as_str()}),
            )?,
            200,
        );
        assert!(service.native_root.is_some() && service.record_root.is_none());
        assert!(!service.recovery_required);
        self.service = service;
        Ok(self)
    }
    fn snapshot(&self) -> TestResult<Zeroizing<Vec<u8>>> {
        let state = self.service.state.as_ref().ok_or("native state")?;
        let auth_bytes =
            owner_store::serialize_owner(&state.auth).map_err(|_| "Auth projection")?;
        let identity = state
            .engines
            .fixture_root_identity()
            .ok_or("root Identity absent")?;
        let identity_bytes =
            owner_store::serialize_owner(identity).map_err(|_| "Identity projection")?;
        let mut auth: Value = serde_json::from_slice(&auth_bytes)?;
        let mut identity: Value = serde_json::from_slice(&identity_bytes)?;
        assert!(auth["auth_mounts"].is_object());
        assert!(auth["jwt_mounts"].is_object());
        assert!(auth["tokens"].is_object());
        assert!(identity.is_object());
        // Exclude only unrelated terminal-clock metadata. Compare complete
        // auth mount/JWT/token and Identity objects, not a handpicked count.
        let mut projection = json!({"mounts":auth["auth_mounts"].take(),
            "jwt":auth["jwt_mounts"].take(),"tokens":auth["tokens"].take(),
            "identity":identity.take()});
        let bytes = Zeroizing::new(serde_json::to_vec(&projection)?);
        erase_json(&mut projection);
        erase_json(&mut auth);
        erase_json(&mut identity);
        Ok(bytes)
    }
    fn begin_login(
        &mut self,
        assertion: &str,
        budget: Duration,
    ) -> TestResult<(Response, RequestClock, Instant)> {
        self.now += 1;
        let started = Instant::now();
        let until = started + budget;
        let clock = RequestClock::anchored(Duration::from_secs(self.now), started)?;
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(until);
        let body = json!({"role":"client","jwt":assertion});
        let response = self.service.handle_inner(RequestView {
            method: "POST",
            path: LOGIN,
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
            .ok_or("actual JWT owner")?;
        assert!(delivery.jwt_owner.is_some());
        assert!(delivery.requires_local_proof() && delivery.tracks_terminal_checkpoint());
        assert!(delivery.proof.is_none() && delivery.delivery_checkpoint.is_some());
        assert_eq!(delivery.deadline.instant(), until);
        Ok((response, clock, until))
    }
}

#[test]
fn native_jwt_local_service_token_identity_renewal_and_cold_reopen() -> TestResult {
    let mut f = Fixture::new()?;
    let expires = f.now + 30;
    let assertion = f.assertion(expires);
    let (first, entity) = f.login(&assertion)?;
    let (second, same_entity) = f.login(&assertion)?;
    assert!(first.as_str() != second.as_str());
    assert_eq!(entity, same_entity);
    let mut f = f.restart()?;
    let read = f.actor(&first, "GET", "jwt-kv/data/value", json!({}))?;
    status(&read, 200);
    assert_eq!(read.body["data"]["data"]["value"], "jwt-preserved");
    f.now = expires + 1;
    // Renewal follows the issuing role and issued token, not the expired JWT
    // or the role's later trust keys. No remote issuer execution is permitted.
    let rotated = Ed25519KeyPair::from_seed_unchecked(&[68; 32]).map_err(|_| "rotation key")?;
    let config = f.config(&rotated);
    status(&f.admin("POST", CONFIG, config)?, 204);
    let mut renewed = f.actor(
        &first,
        "POST",
        "auth/token/renew-self",
        json!({"increment":120}),
    )?;
    status(&renewed, 200);
    assert_eq!(renewed.body["auth"]["entity_id"], entity);
    let echoed = secret(&mut renewed, "/auth/client_token")?;
    assert!(echoed.as_str() == first.as_str());
    let mut f = f.restart()?;
    status(
        &f.actor(&first, "POST", "auth/token/revoke-self", json!({}))?,
        204,
    );
    status(
        &f.actor(&first, "GET", "auth/token/lookup-self", json!({}))?,
        403,
    );
    status(
        &f.actor(&second, "GET", "auth/token/lookup-self", json!({}))?,
        200,
    );
    status(&f.admin("DELETE", ROLE, json!({}))?, 204);
    let missing_role = f.actor(&second, "POST", "auth/token/renew-self", json!({}))?;
    status(&missing_role, 500);
    no_credential(&missing_role);
    status(&f.admin("DELETE", "sys/auth/native-jwt", json!({}))?, 204);
    let mut f = f.restart()?;
    status(
        &f.actor(&second, "GET", "auth/token/lookup-self", json!({}))?,
        403,
    );
    Ok(())
}

#[test]
fn native_jwt_rejects_remote_and_bad_signature_without_candidate_delta() -> TestResult {
    let mut f = Fixture::new()?;
    for (path, body) in [
        (
            CONFIG,
            json!({"issuer":"https://native-jwt.example","audiences":["native"],
        "jwks_url":"https://remote-issuer.invalid/keys"}),
        ),
    ] {
        let before = f.snapshot()?;
        let response = f.admin("POST", path, body)?;
        status(&response, 501);
        no_credential(&response);
        assert!(before.as_slice() == f.snapshot()?.as_slice());
    }
    let assertion = f.assertion(f.now + 60);
    let mut segments = assertion.split('.').map(str::to_owned).collect::<Vec<_>>();
    segments[2] = URL_SAFE_NO_PAD.encode([0; 64]);
    let bad = Zeroizing::new(segments.join("."));
    let before = f.snapshot()?;
    let response = f.actor(
        "",
        "POST",
        LOGIN,
        json!({"role":"client","jwt":bad.as_str()}),
    )?;
    status(&response, 400);
    no_credential(&response);
    assert!(before.as_slice() == f.snapshot()?.as_slice());
    assert!(f.service.pending_native_auth_delivery.is_none());
    Ok(())
}

fn acl_token(
    f: &mut Fixture,
    name: &str,
    path: &str,
    capabilities: &[&str],
) -> TestResult<Zeroizing<String>> {
    let policy = format!(
        "path {path:?} {{ capabilities = {} }}",
        serde_json::to_string(capabilities)?
    );
    status(
        &f.admin(
            "PUT",
            &format!("sys/policies/acl/{name}"),
            json!({"policy":policy}),
        )?,
        204,
    );
    // Verify the real writer has only its path policy, with neither root nor
    // default. JWT role configuration is not token-API policy delegation.
    let token_policies = vec![name];
    let mut issued = f.admin(
        "POST",
        "auth/token/create",
        json!({"policies":&token_policies,"no_default_policy":true,"ttl":"600s"}),
    )?;
    status(&issued, 200);
    assert_eq!(issued.body["auth"]["token_type"], "service");
    assert_eq!(issued.body["auth"]["policies"], json!(&token_policies));
    assert_eq!(issued.body["auth"]["token_policies"], json!(&token_policies));
    let token = secret(&mut issued, "/auth/client_token")?;
    let mut looked = f.admin("POST", "auth/token/lookup", json!({"token":token.as_str()}))?;
    status(&looked, 200);
    assert_eq!(looked.body["data"]["policies"], json!(&token_policies));
    erase_json(&mut looked.body);
    Ok(token)
}

#[test]
fn native_jwt_role_management_uses_source_create_update_and_delete_after_cold_reopen()
-> TestResult {
    let mut f = Fixture::new()?;
    let path = "auth/native-jwt/role/acl-managed";
    let create = acl_token(&mut f, "jwt-acl-create", path, &["create"])?;
    let update = acl_token(&mut f, "jwt-acl-update", path, &["update"])?;
    let update_sudo = acl_token(&mut f, "jwt-acl-update-sudo", path, &["update", "sudo"])?;
    let delete = acl_token(&mut f, "jwt-acl-delete", path, &["delete"])?;
    let role = json!({
        "role_type":"jwt","user_claim":"sub","bound_audiences":["native"],
        "token_policies":[],"token_ttl":120,"token_max_ttl":600
    });
    status(&f.admin("GET", path, json!({}))?, 404);
    let before = f.snapshot()?;
    for token in [&update, &update_sudo] {
        let denied = f.actor(token, "POST", path, role.clone())?;
        status(&denied, 403);
        no_credential(&denied);
        assert!(before.as_slice() == f.snapshot()?.as_slice());
    }
    // Once published, this role exists. Delivery must retain the source's
    // Create capability instead of recomputing Update against the new root.
    status(&f.actor(&create, "POST", path, role.clone())?, 204);
    assert_eq!(f.admin("GET", path, json!({}))?.body["data"]["token_policies"], json!([]));
    let created = f.snapshot()?;
    assert!(before.as_slice() != created.as_slice());
    let mut f = f.restart()?;
    assert!(created.as_slice() == f.snapshot()?.as_slice());
    assert_eq!(f.admin("GET", path, json!({}))?.body["data"]["token_ttl"], 120);
    let denied = f.actor(&create, "POST", path, json!({"token_ttl":121}))?;
    status(&denied, 403);
    no_credential(&denied);
    assert!(created.as_slice() == f.snapshot()?.as_slice());
    status(&f.actor(&update, "POST", path, json!({"token_ttl":121}))?, 204);
    assert_eq!(f.admin("GET", path, json!({}))?.body["data"]["token_ttl"], 121);
    let updated = f.snapshot()?;
    for token in [&update, &update_sudo] {
        let denied = f.actor(token, "DELETE", path, json!({}))?;
        status(&denied, 403);
        no_credential(&denied);
        assert!(updated.as_slice() == f.snapshot()?.as_slice());
    }
    // The update-only writer may define a future login's policies even though
    // it does not own those policies. Its Create/Delete/other-path restrictions
    // above remain effective under the actual captured Native Actor.
    status(
        &f.actor(&update, "POST", path, json!({"token_policies":["native-jwt"]}))?,
        204,
    );
    assert_eq!(
        f.admin("GET", path, json!({}))?.body["data"]["token_policies"],
        json!(["native-jwt"])
    );
    status(&f.actor(&delete, "DELETE", path, json!({}))?, 204);
    status(&f.admin("GET", path, json!({}))?, 404);
    let deleted = f.snapshot()?;
    status(&f.actor(&delete, "DELETE", path, json!({}))?, 204);
    assert!(deleted.as_slice() == f.snapshot()?.as_slice());
    let mut f = f.restart()?;
    assert!(deleted.as_slice() == f.snapshot()?.as_slice());
    status(&f.admin("GET", path, json!({}))?, 404);
    status(&f.actor(&create, "POST", path, role)?, 204);
    status(&f.admin("GET", path, json!({}))?, 200);
    Ok(())
}

#[test]
fn native_jwt_collection_read_is_authorized_before_unsupported_and_list_stays_list()
-> TestResult {
    let mut f = Fixture::new()?;
    let path = "auth/native-jwt/role";
    let read = acl_token(&mut f, "jwt-acl-read", path, &["read"])?;
    let list = acl_token(&mut f, "jwt-acl-list", path, &["list"])?;
    let none = acl_token(
        &mut f,
        "jwt-acl-unrelated",
        "jwt-kv/data/unrelated",
        &["read"],
    )?;
    let before = f.snapshot()?;
    for (token, method, expected) in [
        (&read, "GET", 405),
        (&list, "GET", 403),
        (&none, "GET", 403),
        (&read, "LIST", 403),
        (&none, "LIST", 403),
    ] {
        let denied = f.actor(token, method, path, json!({}))?;
        status(&denied, expected);
        no_credential(&denied);
        assert!(before.as_slice() == f.snapshot()?.as_slice());
    }
    let listed = f.actor(&list, "LIST", path, json!({}))?;
    status(&listed, 200);
    assert_eq!(listed.body["data"]["keys"], json!(["client"]));
    assert!(before.as_slice() == f.snapshot()?.as_slice());
    let mut f = f.restart()?;
    assert!(before.as_slice() == f.snapshot()?.as_slice());
    let listed = f.actor(&list, "LIST", path, json!({}))?;
    status(&listed, 200);
    assert_eq!(listed.body["data"]["keys"], json!(["client"]));
    Ok(())
}

#[test]
fn native_jwt_config_update_without_sudo_persists_and_rejects_read_only_actor()
-> TestResult {
    let mut f = Fixture::new()?;
    let update = acl_token(&mut f, "jwt-acl-config-update", CONFIG, &["update"])?;
    let read = acl_token(&mut f, "jwt-acl-config-read", CONFIG, &["read"])?;
    let mut config = f.config(&f.pair);
    config["issuer"] = json!("https://native-jwt-config-updated.example");
    let before = f.snapshot()?;
    let denied = f.actor(&read, "POST", CONFIG, config.clone())?;
    status(&denied, 403);
    no_credential(&denied);
    assert!(before.as_slice() == f.snapshot()?.as_slice());
    status(&f.actor(&update, "POST", CONFIG, config)?, 204);
    let updated = f.snapshot()?;
    assert!(before.as_slice() != updated.as_slice());
    let mut f = f.restart()?;
    assert!(updated.as_slice() == f.snapshot()?.as_slice());
    let value = f.actor(&read, "GET", CONFIG, json!({}))?;
    status(&value, 200);
    assert_eq!(
        value.body["data"]["bound_issuer"],
        "https://native-jwt-config-updated.example"
    );
    let config = f.config(&f.pair);
    status(&f.actor(&update, "POST", CONFIG, config)?, 204);
    Ok(())
}

#[test]
fn native_jwt_identity_failure_does_not_export_witness_or_token_and_next_login_is_fresh()
-> TestResult {
    let mut f = Fixture::new()?;
    let assertion = f.assertion(f.now + 60);
    let (_, entity) = f.login(&assertion)?;
    let route = format!("identity/entity/id/{entity}");
    status(&f.admin("PATCH", &route, json!({"disabled":true}))?, 204);
    let before = f.snapshot()?;
    let denied = f.actor(
        "",
        "POST",
        LOGIN,
        json!({"role":"client","jwt":assertion.as_str()}),
    )?;
    status(&denied, 403);
    no_credential(&denied);
    assert!(before.as_slice() == f.snapshot()?.as_slice());
    assert!(f.service.pending_native_auth_delivery.is_none());
    status(&f.admin("PATCH", &route, json!({"disabled":false}))?, 204);
    let (_, again) = f.login(&assertion)?;
    assert_eq!(again, entity);
    Ok(())
}

#[test]
fn native_jwt_original_assertion_expiry_before_publication_keeps_auth_identity_atomic() -> TestResult
{
    let mut f = Fixture::new()?;
    let assertion = f.assertion(f.now + 2);
    let before = f.snapshot()?;
    let pause = PublicationPause::once(Duration::from_millis(2100));
    let response = f.actor(
        "",
        "POST",
        LOGIN,
        json!({"role":"client","jwt":assertion.as_str()}),
    )?;
    assert!(pause.0.load(Ordering::Acquire));
    drop(pause);
    status(&response, 503);
    no_credential(&response);
    assert!(before.as_slice() == f.snapshot()?.as_slice());
    assert!(f.service.pending_native_auth_delivery.is_none());
    assert!(!f.service.recovery_required);
    let f = f.restart()?;
    assert!(before.as_slice() == f.snapshot()?.as_slice());
    Ok(())
}

#[test]
fn native_jwt_native_owner_capacity_veto_after_authentication_keeps_the_old_root() -> TestResult {
    let mut f = Fixture::new()?;
    let assertion = f.assertion(f.now + 60);
    let before = f.snapshot()?;
    let root = f.service.native_root.as_ref().ok_or("native root")?;
    let bytes = root
        .owners
        .iter()
        .try_fold(0u64, |sum, owner| sum.checked_add(owner.owner.total_bytes))
        .ok_or("native owner bytes")?;
    let original_capacity = f.service.opaque_owner_capacity;
    f.service.opaque_owner_capacity = usize::try_from(bytes)?;
    // The original root fits; a real newly issued token and Identity require
    // more opaque-owner space. The existing writer's capacity gate must veto
    // publication after real authentication, without a partial root or grant.
    let reached = PublicationPause::once(Duration::ZERO);
    let response = f.actor(
        "",
        "POST",
        LOGIN,
        json!({"role":"client","jwt":assertion.as_str()}),
    )?;
    assert!(reached.0.load(Ordering::Acquire));
    drop(reached);
    status(&response, 507);
    no_credential(&response);
    assert!(before.as_slice() == f.snapshot()?.as_slice());
    assert!(f.service.pending_native_auth_delivery.is_none());
    assert!(!f.service.recovery_required);
    f.service.opaque_owner_capacity = original_capacity;
    let f = f.restart()?;
    assert!(before.as_slice() == f.snapshot()?.as_slice());
    Ok(())
}

#[test]
fn native_jwt_original_assertion_expiry_after_commit_withholds_reply_without_rollback() -> TestResult
{
    let mut f = Fixture::new()?;
    let assertion = f.assertion(f.now + 2);
    let before = f.snapshot()?;
    let (response, clock, _) = f.begin_login(&assertion, Duration::from_secs(15))?;
    status(&response, 200);
    let issued = Zeroizing::new(text(&response, "/auth/client_token")?);
    let committed = f.snapshot()?;
    assert!(before.as_slice() != committed.as_slice());
    let response = f.service.audit_completed_response_with_receipt(
        "native-jwt-expiry-after-commit",
        f.now,
        Some(clock),
        response,
        || std::thread::sleep(Duration::from_millis(2100)),
    );
    status(&response, 200);
    let response =
        f.service
            .complete_native_auth_delivery(true, response, "native-jwt-expiry-after-commit");
    status(&response, 503);
    no_credential(&response);
    assert!(f.service.pending_native_auth_delivery.is_none());
    assert!(committed.as_slice() == f.snapshot()?.as_slice());
    let mut f = f.restart()?;
    status(
        &f.actor(&issued, "GET", "auth/token/lookup-self", json!({}))?,
        200,
    );
    Ok(())
}

#[test]
fn native_jwt_post_commit_audit_failure_keeps_whole_root_and_recovery_required() -> TestResult {
    let mut f = Fixture::new()?;
    let assertion = f.assertion(f.now + 60);
    let (response, clock, _) = f.begin_login(&assertion, Duration::from_secs(15))?;
    status(&response, 200);
    let committed = f.snapshot()?;
    // Existing cfg(test) audit I/O capacity injection: exercise the actual
    // mandatory audit failure, not a fabricated Response or forged receipt.
    f.service.audit_capacity = f.service.audit.metadata()?.len();
    let response = f.service.audit_completed_response_with_receipt(
        "native-jwt-audit-failure",
        f.now,
        Some(clock),
        response,
        || {},
    );
    status(&response, 503);
    no_credential(&response);
    assert!(f.service.recovery_required);
    let response =
        f.service
            .complete_native_auth_delivery(true, response, "native-jwt-audit-failure");
    status(&response, 503);
    no_credential(&response);
    assert!(f.service.pending_native_auth_delivery.is_none());
    assert!(committed.as_slice() == f.snapshot()?.as_slice());
    // No retry, replacement token or attempt to erase this committed root.
    Ok(())
}

#[test]
fn native_jwt_post_audit_response_and_original_deadline_cannot_be_rebound() -> TestResult {
    let mut f = Fixture::new()?;
    let assertion = f.assertion(f.now + 60);
    let (response, clock, _) = f.begin_login(&assertion, Duration::from_secs(15))?;
    let mut response = f.service.audit_completed_response_with_receipt(
        "native-jwt-status-custody",
        f.now,
        Some(clock),
        response,
        || {},
    );
    status(&response, 200);
    response.status = 403;
    let response =
        f.service
            .complete_native_auth_delivery(true, response, "native-jwt-status-custody");
    status(&response, 503);
    no_credential(&response);
    let (response, clock, until) = f.begin_login(&assertion, Duration::from_millis(1500))?;
    let response = f.service.audit_completed_response_with_receipt(
        "native-jwt-original-deadline",
        f.now,
        Some(clock),
        response,
        || {},
    );
    status(&response, 200);
    std::thread::sleep(until.saturating_duration_since(Instant::now()) + Duration::from_millis(2));
    let response =
        f.service
            .complete_native_auth_delivery(true, response, "native-jwt-original-deadline");
    status(&response, 503);
    no_credential(&response);
    assert!(f.service.pending_native_auth_delivery.is_none());
    Ok(())
}

#[test]
fn native_jwt_post_audit_revocation_cannot_replace_the_original_publication_proof() -> TestResult {
    let mut f = Fixture::new()?;
    let assertion = f.assertion(f.now + 60);
    let (response, clock, _) = f.begin_login(&assertion, Duration::from_secs(15))?;
    let response = f.service.audit_completed_response_with_receipt(
        "native-jwt-original-publication",
        f.now,
        Some(clock),
        response,
        || {},
    );
    status(&response, 200);
    let issued = Zeroizing::new(text(&response, "/auth/client_token")?);
    // Retain the actual affine owner and proof. The intervening mutation is a
    // separately authorized real request, not a fabricated checkpoint/token.
    let original = f
        .service
        .pending_native_auth_delivery
        .take()
        .ok_or("original JWT delivery")?;
    assert!(matches!(
        original.proof.as_ref(),
        Some(native_v6_reader::NativeProof::Single(_))
    ));
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
    let response =
        f.service
            .complete_native_auth_delivery(true, response, "native-jwt-stale-publication");
    status(&response, 503);
    no_credential(&response);
    assert!(!response.body.to_string().contains(issued.as_str()));
    assert!(f.service.pending_native_auth_delivery.is_none());
    let mut f = f.restart()?;
    status(
        &f.actor(&issued, "GET", "auth/token/lookup-self", json!({}))?,
        403,
    );
    Ok(())
}

// R2 additions below. The ten R1 regressions and all their assertions remain
// byte-identical; these are independent Token API composition regressions.
const DELEGATION_POLICY: &str = r#"
path "jwt-kv/data/value" { capabilities = ["read"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/lookup" { capabilities = ["read"] }
path "auth/token/create" { capabilities = ["update"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/renew" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "auth/token/revoke" { capabilities = ["update"] }
"#;

fn allow_delegation(f: &mut Fixture) -> TestResult {
    status(
        &f.admin(
            "PUT",
            "sys/policies/acl/native-jwt",
            json!({"policy":DELEGATION_POLICY}),
        )?,
        204,
    );
    Ok(())
}

fn create_service_child(f: &mut Fixture, parent: &str, ttl: u64) -> TestResult<Zeroizing<String>> {
    let mut response = f.actor(
        parent,
        "POST",
        "auth/token/create",
        json!({
            "policies":["native-jwt"],"no_default_policy":true,"ttl":ttl
        }),
    )?;
    status(&response, 200);
    assert_eq!(response.body["auth"]["token_type"], "service");
    assert_eq!(response.body["auth"]["orphan"], false);
    secret(&mut response, "/auth/client_token")
}

#[test]
fn native_jwt_token_api_service_descendants_keep_own_renewal_and_parent_revocation() -> TestResult {
    let mut f = Fixture::new()?;
    allow_delegation(&mut f)?;
    let assertion_expires = f.now + 60;
    let assertion = f.assertion(assertion_expires);
    let (parent, entity) = f.login(&assertion)?;
    let child = create_service_child(&mut f, &parent, 80)?;
    // A descendant is still a Token API issuer, not a direct JWT login.
    let grandchild = create_service_child(&mut f, &child, 70)?;
    let mut f = f.restart()?;
    let lookup = f.actor(&child, "GET", "auth/token/lookup-self", json!({}))?;
    status(&lookup, 200);
    assert_eq!(lookup.body["data"]["entity_id"], entity);
    assert_eq!(lookup.body["data"]["path"], "auth/token/create");
    assert_eq!(lookup.body["data"]["orphan"], false);
    status(&f.admin("DELETE", ROLE, json!({}))?, 204);
    f.now = assertion_expires + 1;
    // The old assertion and issuing JWT role are no longer usable. The real
    // child's renewal must use Token API provenance, not its inherited mount.
    let mut renewed = f.actor(
        &child,
        "POST",
        "auth/token/renew-self",
        json!({"increment":120}),
    )?;
    status(&renewed, 200);
    let echo = secret(&mut renewed, "/auth/client_token")?;
    assert!(echo.as_str() == child.as_str());
    let parent_renew = f.actor(&parent, "POST", "auth/token/renew-self", json!({}))?;
    status(&parent_renew, 500);
    no_credential(&parent_renew);
    let mut f = f.restart()?;
    status(
        &f.actor(&child, "GET", "jwt-kv/data/value", json!({}))?,
        200,
    );
    status(
        &f.actor(&grandchild, "GET", "auth/token/lookup-self", json!({}))?,
        200,
    );
    status(
        &f.actor(&parent, "POST", "auth/token/revoke-self", json!({}))?,
        204,
    );
    let mut f = f.restart()?;
    for token in [&parent, &child, &grandchild] {
        status(
            &f.actor(token, "GET", "auth/token/lookup-self", json!({}))?,
            403,
        );
    }
    Ok(())
}

#[test]
fn native_jwt_token_api_batch_owner_preserves_real_parent_binding_across_cold_reopen() -> TestResult
{
    let mut f = Fixture::new()?;
    allow_delegation(&mut f)?;
    let assertion = f.assertion(f.now + 60);
    let (parent, _) = f.login(&assertion)?;
    let child = create_service_child(&mut f, &parent, 250)?;
    let mut batches = Vec::new();
    for issuer in [&parent, &child] {
        let mut response = f.actor(
            issuer,
            "POST",
            "auth/token/create",
            json!({
                "type":"batch","policies":["native-jwt"],"no_default_policy":true,"ttl":150
            }),
        )?;
        status(&response, 200);
        assert_eq!(response.body["auth"]["token_type"], "batch");
        assert_eq!(response.body["auth"]["renewable"], false);
        assert_eq!(response.body["auth"]["orphan"], false);
        let batch = secret(&mut response, "/auth/client_token")?;
        assert!(batch.starts_with("hvb."));
        batches.push(batch);
    }
    let mut f = f.restart()?;
    for batch in &batches {
        status(&f.actor(batch, "GET", "jwt-kv/data/value", json!({}))?, 200);
        let renewal = f.actor(batch, "POST", "auth/token/renew-self", json!({}))?;
        status(&renewal, 400);
        no_credential(&renewal);
    }
    status(
        &f.actor(&parent, "POST", "auth/token/revoke-self", json!({}))?,
        204,
    );
    let mut f = f.restart()?;
    for batch in &batches {
        status(&f.actor(batch, "GET", "jwt-kv/data/value", json!({}))?, 403);
    }
    status(
        &f.actor(&child, "GET", "auth/token/lookup-self", json!({}))?,
        403,
    );
    Ok(())
}

#[test]
fn native_jwt_token_api_revoke_orphan_keeps_own_issuer_but_mount_retirement_still_revokes()
-> TestResult {
    let mut f = Fixture::new()?;
    allow_delegation(&mut f)?;
    let assertion = f.assertion(f.now + 60);
    let (parent, _) = f.login(&assertion)?;
    let child = create_service_child(&mut f, &parent, 250)?;
    status(
        &f.admin(
            "POST",
            "auth/token/revoke-orphan",
            json!({"token":parent.as_str()}),
        )?,
        204,
    );
    status(&f.admin("DELETE", ROLE, json!({}))?, 204);
    let mut f = f.restart()?;
    status(
        &f.actor(&parent, "GET", "auth/token/lookup-self", json!({}))?,
        403,
    );
    let lookup = f.actor(&child, "GET", "auth/token/lookup-self", json!({}))?;
    status(&lookup, 200);
    assert_eq!(lookup.body["data"]["orphan"], true);
    let mut renewed = f.actor(
        &child,
        "POST",
        "auth/token/renew-self",
        json!({"increment":120}),
    )?;
    status(&renewed, 200);
    let echo = secret(&mut renewed, "/auth/client_token")?;
    assert!(echo.as_str() == child.as_str());
    status(&f.admin("DELETE", "sys/auth/native-jwt", json!({}))?, 204);
    let mut f = f.restart()?;
    status(
        &f.actor(&child, "GET", "auth/token/lookup-self", json!({}))?,
        403,
    );
    Ok(())
}

#[test]
fn native_jwt_and_userpass_token_api_targets_keep_real_owner_and_renewal_in_both_directions()
-> TestResult {
    let mut f = Fixture::new()?;
    allow_delegation(&mut f)?;
    status(
        &f.admin("POST", "sys/auth/native-up", json!({"type":"userpass"}))?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "auth/native-up/users/bob",
            json!({
                "password":"native-jwt-cross-owner-synthetic","token_policies":["native-jwt"],
                "token_ttl":300,"token_max_ttl":600
            }),
        )?,
        204,
    );
    let mut response = f.actor(
        "",
        "POST",
        "auth/native-up/login/bob",
        json!({"password":"native-jwt-cross-owner-synthetic"}),
    )?;
    status(&response, 200);
    let userpass = secret(&mut response, "/auth/client_token")?;
    let assertion = f.assertion(f.now + 60);
    let (jwt, _) = f.login(&assertion)?;
    let (other_jwt, _) = f.login(&assertion)?;
    let mut first = f.actor(
        &jwt,
        "POST",
        "auth/token/renew",
        json!({"token":userpass.as_str(),"increment":120}),
    )?;
    status(&first, 200);
    let echo = secret(&mut first, "/auth/client_token")?;
    assert!(echo.as_str() == userpass.as_str());
    let mut second = f.actor(
        &userpass,
        "POST",
        "auth/token/renew",
        json!({"token":jwt.as_str(),"increment":120}),
    )?;
    status(&second, 200);
    let echo = secret(&mut second, "/auth/client_token")?;
    assert!(echo.as_str() == jwt.as_str());
    let mut f = f.restart()?;
    status(
        &f.actor(
            &userpass,
            "POST",
            "auth/token/revoke",
            json!({"token":jwt.as_str()}),
        )?,
        204,
    );
    status(
        &f.actor(&jwt, "GET", "auth/token/lookup-self", json!({}))?,
        403,
    );
    status(
        &f.actor(
            &other_jwt,
            "POST",
            "auth/token/revoke",
            json!({"token":userpass.as_str()}),
        )?,
        204,
    );
    let mut f = f.restart()?;
    status(
        &f.actor(&userpass, "GET", "auth/token/lookup-self", json!({}))?,
        403,
    );
    status(
        &f.actor(&jwt, "GET", "auth/token/lookup-self", json!({}))?,
        403,
    );
    status(
        &f.actor(&other_jwt, "GET", "auth/token/lookup-self", json!({}))?,
        200,
    );
    Ok(())
}

#[test]
fn native_jwt_token_api_profile_rejects_mount_label_without_real_issuer_or_parent_graph()
-> TestResult {
    let mut f = Fixture::new()?;
    allow_delegation(&mut f)?;
    let assertion = f.assertion(f.now + 60);
    let (parent, _) = f.login(&assertion)?;
    let child = create_service_child(&mut f, &parent, 250)?;
    let original = f.snapshot()?;
    let auth = &f.service.state.as_ref().ok_or("actual native state")?.auth;
    assert!(auth.native_v6_jwt_state_supported());
    let bytes = owner_store::serialize_owner(auth).map_err(|_| "actual Auth bytes")?;
    let mut value: Value = serde_json::from_slice(&bytes)?;
    let child_id = value["tokens"]
        .as_object()
        .ok_or("actual token map")?
        .iter()
        .find(|(_, token)| {
            token["auth_mount"] == "native-jwt" && token["auth_provenance"]["kind"] == "token_api"
        })
        .map(|(id, _)| id.clone())
        .ok_or("actual Token API child")?;
    // Negative format/profile probes operate on detached values only. They
    // never install a forged token, mutate the fixture or grant a Principal.
    for mutation in 0..7 {
        let mut changed = value.clone();
        let token = &mut changed["tokens"][&child_id];
        match mutation {
            0 => token["auth_provenance"] = Value::Null,
            1 => token["auth_origin_known"] = json!(false),
            2 => token["public_origin"] = Value::Null,
            3 => token["auth_provenance"]["issued_creation_ttl"] = Value::Null,
            4 => token["parent"] = json!(&child_id),
            5 => token["parent"] = json!("0".repeat(64)),
            _ => token["public_origin"]["creation_path"] = json!(LOGIN),
        }
        let changed_bytes = Zeroizing::new(serde_json::to_vec(&changed)?);
        erase_json(&mut changed);
        if let Ok(detached) = serde_json::from_slice::<crate::auth::AuthState>(&changed_bytes) {
            assert!(!detached.native_v6_jwt_state_supported());
        }
    }
    erase_json(&mut value);
    assert!(original.as_slice() == f.snapshot()?.as_slice());
    status(
        &f.actor(&child, "GET", "auth/token/lookup-self", json!({}))?,
        200,
    );
    Ok(())
}

fn assert_native_jwt_policy_grant(
    f: &mut Fixture,
    expected: &[&str],
) -> TestResult<Zeroizing<String>> {
    let assertion = f.assertion(f.now + 60);
    let mut response = f.actor(
        "",
        "POST",
        LOGIN,
        json!({"role":"client","jwt":assertion.as_str()}),
    )?;
    status(&response, 200);
    assert_eq!(response.body["auth"]["token_type"], "service");
    assert_eq!(response.body["auth"]["policies"], json!(expected));
    assert_eq!(response.body["auth"]["token_policies"], json!(expected));
    let entity = text(&response, "/auth/entity_id")?;
    let token = secret(&mut response, "/auth/client_token")?;
    let mut looked = f.admin(
        "POST",
        "auth/token/lookup",
        json!({"token":token.as_str()}),
    )?;
    status(&looked, 200);
    assert_eq!(looked.body["data"]["policies"], json!(expected));
    assert_eq!(looked.body["data"]["entity_id"], entity);
    erase_json(&mut looked.body);
    Ok(token)
}

#[test]
fn native_jwt_empty_role_policies_and_no_default_flag_survive_real_cold_reopen()
-> TestResult {
    for field in ["token_policies", "policies"] {
        let mut f = Fixture::new()?;
        let mut body = json!({});
        body[field] = json!([]);
        status(&f.admin("POST", ROLE, body)?, 204);
        let role = f.admin("GET", ROLE, json!({}))?;
        status(&role, 200);
        assert_eq!(role.body["data"]["token_policies"], json!([]));
        assert_eq!(role.body["data"]["token_no_default_policy"], false);
        let mut f = f.restart()?;
        let _with_default = assert_native_jwt_policy_grant(&mut f, &["default"])?;
        status(
            &f.admin("POST", ROLE, json!({"token_no_default_policy":true}))?,
            204,
        );
        // Omitted updates retain the flag, and a cold reopen must keep it.
        status(&f.admin("POST", ROLE, json!({"token_ttl":301}))?, 204);
        let mut f = f.restart()?;
        assert_eq!(
            f.admin("GET", ROLE, json!({}))?.body["data"]["token_no_default_policy"],
            true
        );
        let _without_default = assert_native_jwt_policy_grant(&mut f, &[])?;
        // Suppression prevents injection; it must not remove explicit default.
        let mut body = json!({"token_no_default_policy":true});
        body[field] = json!(["default"]);
        status(&f.admin("POST", ROLE, body)?, 204);
        let mut f = f.restart()?;
        let _explicit = assert_native_jwt_policy_grant(&mut f, &["default"])?;
    }
    Ok(())
}

#[test]
fn native_jwt_no_default_policy_weak_bool_updates_are_atomic_and_persist()
-> TestResult {
    let mut f = Fixture::new()?;
    // Official HTTP JSON uses json.Number; only 0/1 spellings reach ParseBool.
    // These are real Service requests, not a private flag-parser unit fixture.
    for (raw, expected) in [
        ("true", true), ("false", false), ("1", true), ("0", false),
        ("\"t\"", true), ("\"T\"", true), ("\"true\"", true),
        ("\"TRUE\"", true), ("\"True\"", true), ("\"1\"", true),
        ("\"f\"", false), ("\"F\"", false), ("\"false\"", false),
        ("\"FALSE\"", false), ("\"False\"", false), ("\"0\"", false),
        ("\"\"", false), ("null", false),
    ] {
        let value: Value = serde_json::from_str(raw)?;
        status(
            &f.admin("POST", ROLE, json!({"token_no_default_policy":value}))?,
            204,
        );
        assert_eq!(
            f.admin("GET", ROLE, json!({}))?.body["data"]["token_no_default_policy"],
            expected
        );
    }
    status(&f.admin("POST", ROLE, json!({"token_no_default_policy":true}))?, 204);
    status(&f.admin("POST", ROLE, json!({"token_ttl":302}))?, 204);
    let mut f = f.restart()?;
    assert_eq!(
        f.admin("GET", ROLE, json!({}))?.body["data"]["token_no_default_policy"],
        true
    );
    for raw in [
        "[]", "{}", "2", "-1", "0.5", "1.0", "1e0",
        "\"yes\"", "\"true \"", "\" true\"", "\"2\"",
    ] {
        let value: Value = serde_json::from_str(raw)?;
        let before = f.snapshot()?;
        let response = f.admin("POST", ROLE, json!({"token_no_default_policy":value}))?;
        status(&response, 400);
        no_credential(&response);
        assert!(before.as_slice() == f.snapshot()?.as_slice());
    }
    status(&f.admin("POST", ROLE, json!({"token_no_default_policy":null}))?, 204);
    let mut f = f.restart()?;
    assert_eq!(
        f.admin("GET", ROLE, json!({}))?.body["data"]["token_no_default_policy"],
        false
    );
    Ok(())
}

#[test]
fn native_jwt_root_role_configuration_is_stored_but_never_issued_or_retroactively_renewed()
-> TestResult {
    let mut f = Fixture::new()?;
    let issued = assert_native_jwt_policy_grant(&mut f, &["default", "native-jwt"])?;
    let update = acl_token(&mut f, "jwt-root-role-writer", ROLE, &["update"])?;
    for field in ["token_policies", "policies"] {
        for suppress_default in [false, true] {
            let mut body = json!({"token_no_default_policy":suppress_default});
            body[field] = json!(["root"]);
            // Official role storage allows root; issuance rejects it later.
            status(&f.actor(&update, "POST", ROLE, body)?, 204);
            let mut reopened = f.restart()?;
            assert_eq!(
                reopened.admin("GET", ROLE, json!({}))?.body["data"]["token_policies"],
                json!(["root"])
            );
            let assertion = reopened.assertion(reopened.now + 60);
            let before = reopened.snapshot()?;
            let denied = reopened.actor(
                "",
                "POST",
                LOGIN,
                json!({"role":"client","jwt":assertion.as_str()}),
            )?;
            status(&denied, 400);
            no_credential(&denied);
            assert!(before.as_slice() == reopened.snapshot()?.as_slice());
            f = reopened;
        }
    }
    // Renewal must retain the issued grant. A later root role cannot promote it,
    // and changing the flag does not remove default from an existing token.
    let mut renewed = f.admin(
        "POST",
        "auth/token/renew",
        json!({"token":issued.as_str(),"increment":120}),
    )?;
    status(&renewed, 200);
    assert_eq!(renewed.body["auth"]["policies"], json!(["default", "native-jwt"]));
    assert_eq!(renewed.body["auth"]["token_policies"], json!(["default", "native-jwt"]));
    let echoed = secret(&mut renewed, "/auth/client_token")?;
    assert!(echoed.as_str() == issued.as_str());
    let mut looked = f.admin("POST", "auth/token/lookup", json!({"token":issued.as_str()}))?;
    status(&looked, 200);
    assert_eq!(looked.body["data"]["policies"], json!(["default", "native-jwt"]));
    erase_json(&mut looked.body);
    Ok(())
}


// Native JWT batch coverage. Every credential below comes through the real
// local signature verifier, Identity finalizer, File V6 writer and audit path.
fn native_jwt_service_row_count(f: &Fixture) -> TestResult<usize> {
    let state = f.service.state.as_ref().ok_or("native state")?;
    let bytes = owner_store::serialize_owner(&state.auth).map_err(|_| "Auth projection")?;
    let mut auth: Value = serde_json::from_slice(&bytes)?;
    let count = auth["tokens"].as_object().ok_or("service token map")?.len();
    erase_json(&mut auth);
    Ok(count)
}

fn native_jwt_batch_snapshot(f: &Fixture) -> TestResult<Zeroizing<Vec<u8>>> {
    let state = f.service.state.as_ref().ok_or("native state")?;
    let bytes = owner_store::serialize_owner(&state.auth).map_err(|_| "Auth projection")?;
    let mut auth: Value = serde_json::from_slice(&bytes)?;
    let base: Value = serde_json::from_slice(f.snapshot()?.as_slice())?;
    let namespace_bytes = owner_store::serialize_owner(&state.namespaces)
        .map_err(|_| "Namespace projection")?;
    let namespaces: Value = serde_json::from_slice(&namespace_bytes)?;
    let mut projection = json!({
        "auth_and_identity": base,
        "batch_authority": auth["batch_authority"].take(),
        "namespace_batch_registry": auth["namespace_batch_registry"].take(),
        "namespaces": namespaces
    });
    let result = Zeroizing::new(serde_json::to_vec(&projection)?);
    erase_json(&mut projection);
    erase_json(&mut auth);
    Ok(result)
}

fn native_jwt_batch_login(
    f: &mut Fixture,
    assertion: &str,
) -> TestResult<(Zeroizing<String>, String)> {
    let mut response =
        f.actor("", "POST", LOGIN, json!({"role":"client","jwt":assertion}))?;
    status(&response, 200);
    assert_eq!(response.body["auth"]["token_type"], "batch");
    assert_eq!(response.body["auth"]["renewable"], false);
    assert_eq!(response.body["auth"]["accessor"], "");
    assert_eq!(response.body["auth"]["metadata"]["role"], "client");
    let entity = text(&response, "/auth/entity_id")?;
    let token = secret(&mut response, "/auth/client_token")?;
    assert!(token.starts_with("hvb."));
    Ok((token, entity))
}

#[test]
fn native_jwt_batch_type_matrix_keeps_identity_and_stateless_grants_across_cold_reopen()
-> TestResult {
    for mount_type in ["default-service", "default-batch", "service", "batch"] {
        for role_type in ["default", "service", "batch"] {
            let mut f = Fixture::new()?;
            status(
                &f.admin("POST", "sys/auth/native-jwt/tune",
                    json!({"token_type":mount_type}))?,
                204,
            );
            status(&f.admin("POST", ROLE, json!({"token_type":role_type}))?, 204);
            let batch = mount_type == "batch"
                || mount_type == "default-service" && role_type == "batch"
                || mount_type == "default-batch" && role_type != "service";
            let rows = native_jwt_service_row_count(&f)?;
            let assertion = f.assertion(f.now + 60);
            let (first, first_entity) = if batch {
                native_jwt_batch_login(&mut f, &assertion)?
            } else {
                f.login(&assertion)?
            };
            let (second, second_entity) = if batch {
                native_jwt_batch_login(&mut f, &assertion)?
            } else {
                f.login(&assertion)?
            };
            assert!(first.as_str() != second.as_str());
            assert_eq!(first_entity, second_entity);
            assert_eq!(native_jwt_service_row_count(&f)?, rows + 2 * usize::from(!batch));
            let mut f = f.restart()?;
            assert_eq!(native_jwt_service_row_count(&f)?, rows + 2 * usize::from(!batch));
            for token in [&first, &second] {
                status(&f.actor(token, "GET", "jwt-kv/data/value", json!({}))?, 200);
                let mut lookup = f.actor(token, "GET", "auth/token/lookup-self", json!({}))?;
                status(&lookup, 200);
                assert_eq!(lookup.body["data"]["entity_id"], first_entity);
                assert_eq!(lookup.body["data"]["path"], LOGIN);
                erase_json(&mut lookup.body);
                if batch {
                    let renewal = f.actor(token, "POST", "auth/token/renew-self", json!({}))?;
                    status(&renewal, 400);
                    no_credential(&renewal);
                }
            }
            f.now += 301;
            for token in [&first, &second] {
                let expired = f.actor(token, "GET", "jwt-kv/data/value", json!({}))?;
                status(&expired, 403);
                no_credential(&expired);
            }
        }
    }
    Ok(())
}

#[test]
fn native_jwt_batch_bad_signature_and_expiry_before_publication_keep_old_issuance_state()
-> TestResult {
    let mut f = Fixture::new()?;
    status(&f.admin("POST", ROLE, json!({"token_type":"batch"}))?, 204);
    let assertion = f.assertion(f.now + 60);
    let mut segments = assertion.split('.').map(str::to_owned).collect::<Vec<_>>();
    segments[2] = URL_SAFE_NO_PAD.encode([0; 64]);
    let bad = Zeroizing::new(segments.join("."));
    let before = native_jwt_batch_snapshot(&f)?;
    let response = f.actor("", "POST", LOGIN, json!({"role":"client","jwt":bad.as_str()}))?;
    status(&response, 400);
    no_credential(&response);
    assert!(before.as_slice() == native_jwt_batch_snapshot(&f)?.as_slice());

    let assertion = f.assertion(f.now + 2);
    let pause = PublicationPause::once(Duration::from_millis(2100));
    let response = f.actor("", "POST", LOGIN,
        json!({"role":"client","jwt":assertion.as_str()}))?;
    assert!(pause.0.load(Ordering::Acquire));
    drop(pause);
    status(&response, 503);
    no_credential(&response);
    assert!(before.as_slice() == native_jwt_batch_snapshot(&f)?.as_slice());
    assert!(f.service.pending_native_auth_delivery.is_none());
    assert!(!f.service.recovery_required);
    let mut f = f.restart()?;
    assert!(before.as_slice() == native_jwt_batch_snapshot(&f)?.as_slice());
    let fresh = f.assertion(f.now + 60);
    let (token, _) = native_jwt_batch_login(&mut f, &fresh)?;
    status(&f.actor(&token, "GET", "jwt-kv/data/value", json!({}))?, 200);
    Ok(())
}

#[test]
fn native_jwt_batch_identity_disable_veto_and_reenable_use_the_real_entity()
-> TestResult {
    let mut f = Fixture::new()?;
    status(&f.admin("POST", ROLE, json!({"token_type":"batch"}))?, 204);
    let assertion = f.assertion(f.now + 60);
    let (token, entity) = native_jwt_batch_login(&mut f, &assertion)?;
    let route = format!("identity/entity/id/{entity}");
    status(&f.admin("PATCH", &route, json!({"disabled":true}))?, 204);
    let before = native_jwt_batch_snapshot(&f)?;
    let response = f.actor("", "POST", LOGIN,
        json!({"role":"client","jwt":assertion.as_str()}))?;
    status(&response, 403);
    no_credential(&response);
    assert!(before.as_slice() == native_jwt_batch_snapshot(&f)?.as_slice());
    status(&f.actor(&token, "GET", "jwt-kv/data/value", json!({}))?, 403);
    status(&f.admin("PATCH", &route, json!({"disabled":false}))?, 204);
    let (_, again) = native_jwt_batch_login(&mut f, &assertion)?;
    assert_eq!(again, entity);
    let mut f = f.restart()?;
    status(&f.actor(&token, "GET", "jwt-kv/data/value", json!({}))?, 200);
    Ok(())
}

#[test]
fn native_jwt_batch_forced_mount_retains_domain_ttl_and_discards_service_use_limits()
-> TestResult {
    for (limits, maximum_ttl) in [
        (json!({"token_period":30}), 30),
        (json!({"token_num_uses":2}), 300),
    ] {
        let mut f = Fixture::new()?;
        status(&f.admin("POST", ROLE, limits)?, 204);
        status(&f.admin("POST", "sys/auth/native-jwt/tune",
            json!({"token_type":"batch"}))?, 204);
        let assertion = f.assertion(f.now + 60);
        let mut response = f.actor("", "POST", LOGIN,
            json!({"role":"client","jwt":assertion.as_str()}))?;
        status(&response, 200);
        assert_eq!(response.body["auth"]["token_type"], "batch");
        assert_eq!(response.body["auth"]["renewable"], false);
        let ttl = response.body["auth"]["lease_duration"].as_u64().ok_or("batch TTL")?;
        assert!(ttl > 0 && ttl <= maximum_ttl);
        let token = secret(&mut response, "/auth/client_token")?;
        let mut f = f.restart()?;
        for _ in 0..4 {
            status(&f.actor(&token, "GET", "jwt-kv/data/value", json!({}))?, 200);
        }
        let renewal = f.actor(&token, "POST", "auth/token/renew-self", json!({}))?;
        status(&renewal, 400);
        no_credential(&renewal);
    }
    Ok(())
}

#[test]
fn native_jwt_batch_no_default_policy_and_root_rejection_survive_cold_reopen()
-> TestResult {
    for no_default in [false, true] {
        let mut f = Fixture::new()?;
        status(&f.admin("POST", ROLE, json!({
            "token_type":"batch","token_policies":[],
            "token_no_default_policy":no_default
        }))?, 204);
        let expected = if no_default { json!([]) } else { json!(["default"]) };
        let rows = native_jwt_service_row_count(&f)?;
        let assertion = f.assertion(f.now + 60);
        let mut response = f.actor("", "POST", LOGIN,
            json!({"role":"client","jwt":assertion.as_str()}))?;
        status(&response, 200);
        assert_eq!(response.body["auth"]["token_type"], "batch");
        assert_eq!(response.body["auth"]["policies"], expected);
        assert_eq!(response.body["auth"]["token_policies"], expected);
        let token = secret(&mut response, "/auth/client_token")?;
        let mut f = f.restart()?;
        assert_eq!(native_jwt_service_row_count(&f)?, rows);
        let mut lookup = f.admin("POST", "auth/token/lookup", json!({"token":token.as_str()}))?;
        status(&lookup, 200);
        assert_eq!(lookup.body["data"]["policies"], expected);
        erase_json(&mut lookup.body);
        status(&f.admin("POST", ROLE, json!({"token_policies":["root"]}))?, 204);
        let before = native_jwt_batch_snapshot(&f)?;
        let assertion = f.assertion(f.now + 60);
        let denied = f.actor("", "POST", LOGIN,
            json!({"role":"client","jwt":assertion.as_str()}))?;
        status(&denied, 400);
        no_credential(&denied);
        assert!(before.as_slice() == native_jwt_batch_snapshot(&f)?.as_slice());
        assert_eq!(native_jwt_service_row_count(&f)?, rows);
    }
    Ok(())
}

#[test]
fn native_jwt_batch_post_commit_audit_response_and_assertion_guards_keep_the_committed_root()
-> TestResult {
    for fault in ["audit", "response", "assertion"] {
        let mut f = Fixture::new()?;
        status(&f.admin("POST", ROLE, json!({"token_type":"batch"}))?, 204);
        let expires = f.now + if fault == "assertion" { 2 } else { 60 };
        let assertion = f.assertion(expires);
        let (response, clock, _) = f.begin_login(&assertion, Duration::from_secs(15))?;
        status(&response, 200);
        assert_eq!(response.body["auth"]["token_type"], "batch");
        let committed = native_jwt_batch_snapshot(&f)?;
        if fault == "audit" {
            f.service.audit_capacity = f.service.audit.metadata()?.len();
        }
        let mut response = f.service.audit_completed_response_with_receipt(
            "native-jwt-batch-original-delivery", f.now, Some(clock), response,
            || {
                if fault == "assertion" {
                    std::thread::sleep(Duration::from_millis(2100));
                }
            },
        );
        if fault == "audit" {
            status(&response, 503);
            assert!(f.service.recovery_required);
        } else {
            status(&response, 200);
            if fault == "response" {
                response.body["auth"]["metadata"]["role"] = json!("another-role");
            }
        }
        let response = f.service.complete_native_auth_delivery(
            true, response, "native-jwt-batch-original-delivery",
        );
        status(&response, 503);
        no_credential(&response);
        assert!(committed.as_slice() == native_jwt_batch_snapshot(&f)?.as_slice());
        assert!(f.service.pending_native_auth_delivery.is_none());
        if fault != "audit" {
            let f = f.restart()?;
            assert!(committed.as_slice() == native_jwt_batch_snapshot(&f)?.as_slice());
        }
    }
    Ok(())
}
