//! Real File startup, original 15-second requests and actual public issuers.
//! Reuses only the established fixture; no grants, principals, existing-request
//! clocks, native plans or completion receipts are manufactured.
use super::*;
use crate::service::native_auth::batch_issuer_test_observer::after_audit;
use std::sync::atomic::{AtomicBool, Ordering};

fn services(f: &Fixture) -> TestResult<usize> {
    let raw = owner_store::serialize_owner(&f.service.state.as_ref().ok_or("state")?.auth)
        .map_err(|_| "actual Auth serialization")?;
    let mut value: Value = serde_json::from_slice(&raw)?;
    let count = value["tokens"].as_object().map(|tokens| tokens.len());
    erase_json(&mut value);
    count.ok_or_else(|| "actual service token count".into())
}

fn paired(f: &Fixture) -> TestResult {
    f.assert_native()?;
    let state = f.service.state.as_ref().ok_or("state")?;
    state
        .validate_namespace_batch_state()
        .map_err(|_| "actual paired lifecycle")?;
    namespaces::native_empty::empty_profile(state).map_err(|_| "actual closed catalog")?;
    let registry = state
        .auth
        .namespace_batch_registry()
        .ok_or("actual batch registry")?;
    assert!(registry.native_v6_flat_catalog_profile());
    assert_eq!(registry.current_incarnation(""), Some(0));
    Ok(())
}

fn approle(
    f: &mut Fixture,
    uses: u64,
    ttl: u64,
    extra: Value,
) -> TestResult<(Zeroizing<String>, Zeroizing<String>)> {
    status(
        &f.admin("POST", "sys/auth/nb", json!({"type":"approle"}))?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "auth/nb/role/issuer",
            json!({
                "bind_secret_id":true,"token_type":"batch","token_policies":["native-up"],
                "token_ttl":"120s","token_max_ttl":"600s","secret_id_num_uses":uses,
                "secret_id_ttl":ttl,
            }),
        )?,
        204,
    );
    let mut role = f.admin("GET", "auth/nb/role/issuer/role-id", json!({}))?;
    status(&role, 200);
    let role_id = secret(&mut role, "/data/role_id")?;
    let mut sid = f.admin("POST", "auth/nb/role/issuer/secret-id", extra)?;
    status(&sid, 200);
    Ok((role_id, secret(&mut sid, "/data/secret_id")?))
}

fn login(f: &mut Fixture, role: &str, sid: &str) -> TestResult<Response> {
    f.actor(
        "",
        "POST",
        "auth/nb/login",
        json!({"role_id":role,"secret_id":sid}),
    )
}

fn login_from(f: &mut Fixture, role: &str, sid: &str) -> TestResult<Response> {
    f.now += 1;
    let started = Instant::now();
    let clock = RequestClock::anchored(Duration::from_secs(f.now), started)?;
    let _scope =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let execution = f.service.begin_at_mode_precise(
        RequestDispatch {
            method: "POST",
            path: "auth/nb/login",
            namespace: "",
            token: "",
            body: json!({"role_id":role,"secret_id":sid}),
            now: f.now,
            allow_forward: true,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: Some("127.0.0.1".parse()?),
            client_certificates: None,
        },
        clock,
    );
    Ok(f.service.finish_synchronous_request(execution))
}

fn sid_uses(f: &mut Fixture, sid: &str) -> TestResult<u64> {
    let mut response = f.admin(
        "POST",
        "auth/nb/role/issuer/secret-id/lookup",
        json!({"secret_id":sid}),
    )?;
    status(&response, 200);
    let result = response.body["data"]["secret_id_num_uses"]
        .as_u64()
        .ok_or("actual SID uses");
    erase_json(&mut response.body);
    Ok(result?)
}

fn batch(response: &mut Response) -> TestResult<Zeroizing<String>> {
    status(response, 200);
    assert_eq!(response.body["auth"]["token_type"], "batch");
    assert_eq!(response.body["auth"]["accessor"], "");
    assert_eq!(response.body["auth"]["renewable"], false);
    secret(response, "/auth/client_token")
}

fn lifetime(f: &mut Fixture, token: &str) -> TestResult<(u64, u64)> {
    let mut response = f.actor(token, "GET", "auth/token/lookup-self", json!({}))?;
    status(&response, 200);
    assert_eq!(response.body["data"]["type"], "batch");
    assert_eq!(response.body["data"]["num_uses"], 0);
    let created = response.body["data"]["creation_time"]
        .as_u64()
        .ok_or("actual creation")?;
    let expires = response.body["data"]["expire_time_unix"]
        .as_u64()
        .ok_or("actual expiry")?;
    erase_json(&mut response.body);
    Ok((created, expires))
}

fn no_private(response: &Response, code: u16) {
    status(response, code);
    assert!(response.body.get("auth").is_none());
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("wrap_info").is_none());
    assert!(response.unwrapped_json.is_none());
    assert!(response.consistency_index.is_none());
}

fn token_batch(f: &mut Fixture, actor: &str, path: &str) -> TestResult<Zeroizing<String>> {
    batch(&mut f.actor(
        actor,
        "POST",
        path,
        json!({"type":"batch","policies":["native-up"],"no_default_policy":true,"ttl":"120s"}),
    )?)
}

#[test]
fn native_batch_approle_file_first_issuance_sid_once_paired_catalog_and_cold() -> TestResult {
    let mut f = Fixture::new()?;
    status(
        &f.admin("POST", "sys/namespaces/before-native-batch", json!({}))?,
        200,
    );
    let (role, sid) = approle(
        &mut f,
        2,
        300,
        json!({"metadata":r#"{"fixture":"native-batch"}"#}),
    )?;
    let count = services(&f)?;
    let mut first = login(
        &mut f,
        &format!("  {}  ", role.as_str()),
        &format!(" {} ", sid.as_str()),
    )?;
    status(&first, 200);
    assert_eq!(first.body["auth"]["metadata"]["role_name"], "issuer");
    assert_eq!(first.body["auth"]["metadata"]["fixture"], "native-batch");
    assert_eq!(first.body["auth"]["orphan"], true);
    let first = batch(&mut first)?;
    assert_eq!(services(&f)?, count);
    paired(&f)?;
    assert_eq!(sid_uses(&mut f, &sid)?, 1);
    let grant = lifetime(&mut f, &first)?;
    assert_eq!(grant.1 - grant.0, 120);
    f.assert_value(&first)?;
    status(
        &f.admin("POST", "sys/namespaces/after-native-batch", json!({}))?,
        200,
    );
    let second = batch(&mut login(&mut f, &role, &sid)?)?;
    assert!(first.as_str() != second.as_str());
    no_private(&login(&mut f, &role, &sid)?, 400);
    assert_eq!(services(&f)?, count);
    let mut f = f.restart()?;
    paired(&f)?;
    assert_eq!(lifetime(&mut f, &first)?, grant);
    f.assert_value(&first)?;
    f.assert_value(&second)?;
    no_private(&login(&mut f, &role, &sid)?, 400);
    let registry = f
        .service
        .state
        .as_ref()
        .ok_or("state")?
        .auth
        .namespace_batch_registry()
        .ok_or("registry")?;
    assert_eq!(registry.current_incarnation("before-native-batch"), Some(1));
    assert_eq!(registry.current_incarnation("after-native-batch"), Some(1));
    Ok(())
}

#[test]
fn native_batch_approle_failed_cidr_consumes_only_authenticated_sid_and_stays_cold() -> TestResult {
    let mut f = Fixture::new()?;
    let (role, sid) = approle(&mut f, 2, 300, json!({"cidr_list":["192.0.2.0/24"]}))?;
    let count = services(&f)?;
    let denied = login_from(&mut f, &role, &sid)?;
    no_private(&denied, 400);
    assert_eq!(
        denied.body["errors"],
        json!(["source address unauthorized by CIDR restrictions on the secret ID"])
    );
    assert_eq!(sid_uses(&mut f, &sid)?, 1);
    let denied = login_from(&mut f, &role, &sid)?;
    no_private(&denied, 400);
    assert_eq!(
        denied.body["errors"],
        json!(["source address unauthorized by CIDR restrictions on the secret ID"])
    );
    no_private(&login(&mut f, &role, &sid)?, 400);
    assert_eq!(services(&f)?, count);
    assert!(
        !f.service
            .state
            .as_ref()
            .ok_or("state")?
            .has_namespace_batch_state()
    );
    let mut f = f.restart()?;
    no_private(&login(&mut f, &role, &sid)?, 400);
    assert_eq!(services(&f)?, count);
    Ok(())
}

#[test]
fn native_batch_token_api_file_parent_revocation_survives_cold_without_backing() -> TestResult {
    let mut f = Fixture::new()?;
    status(
        &f.admin(
            "POST",
            "sys/policies/acl/native-batch-inspection",
            json!({"policy":format!("{USER_POLICY} {}", r#"path "auth/token/lookup-self" { capabilities = ["read"] }"#)}),
        )?,
        204,
    );
    let parent = f.token("native-batch-inspection")?;
    let count = services(&f)?;
    assert!(
        !f.service
            .state
            .as_ref()
            .ok_or("state")?
            .has_namespace_batch_state()
    );
    let token = batch(&mut f.actor(
        &parent,
        "POST",
        "auth/token/create",
        json!({
            "type":"batch","policies":["native-batch-inspection"],
            "no_default_policy":true,"ttl":"120s",
        }),
    )?)?;
    paired(&f)?;
    assert_eq!(services(&f)?, count);
    let grant = lifetime(&mut f, &token)?;
    assert_eq!(grant.1 - grant.0, 120);
    f.assert_value(&token)?;
    let mut f = f.restart()?;
    assert_eq!(lifetime(&mut f, &token)?, grant);
    status(
        &f.admin(
            "POST",
            "auth/token/revoke",
            json!({"token":parent.as_str()}),
        )?,
        204,
    );
    no_private(&f.actor(&token, "GET", "up-kv/data/value", json!({}))?, 403);
    let mut f = f.restart()?;
    paired(&f)?;
    no_private(&f.actor(&token, "GET", "up-kv/data/value", json!({}))?, 403);
    no_private(
        &f.actor(&parent, "GET", "up-kv/data/value", json!({}))?,
        403,
    );
    Ok(())
}

#[test]
fn native_batch_token_api_file_role_suffix_and_orphan_keep_actual_claims() -> TestResult {
    let mut f = Fixture::new()?;
    status(
        &f.admin(
            "POST",
            "sys/policies/acl/native-batch-self-api",
            json!({"policy":format!("{USER_POLICY} {}", r#"path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }"#)}),
        )?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "auth/token/roles/native-batch",
            json!({
                "allowed_policies":["native-batch-self-api"],"token_type":"batch","orphan":true,"renewable":false,
                "path_suffix":"fixed-origin","token_num_uses":7,"token_no_default_policy":true,
            }),
        )?,
        204,
    );
    let admin = Zeroizing::new(f.admin.as_str().to_owned());
    let count = services(&f)?;
    let mut response = f.actor(
        &admin,
        "POST",
        "auth/token/create/native-batch",
        json!({"policies":["native-batch-self-api"],"ttl":"120s"}),
    )?;
    status(&response, 200);
    assert_eq!(response.body["auth"]["num_uses"], 7);
    assert_eq!(response.body["auth"]["orphan"], true);
    let role_token = batch(&mut response)?;
    let mut lookup = f.actor(&role_token, "GET", "auth/token/lookup-self", json!({}))?;
    status(&lookup, 200);
    assert_eq!(
        lookup.body["data"]["path"],
        "auth/token/create/native-batch/fixed-origin"
    );
    assert_eq!(lookup.body["data"]["num_uses"], 0);
    erase_json(&mut lookup.body);
    let orphan = token_batch(&mut f, &admin, "auth/token/create-orphan")?;
    assert_eq!(services(&f)?, count);
    let mut f = f.restart()?;
    paired(&f)?;
    f.assert_value(&role_token)?;
    f.assert_value(&orphan)?;
    no_private(
        &f.actor(
            &role_token,
            "POST",
            "auth/token/renew-self",
            json!({"increment":"120s"}),
        )?,
        400,
    );
    no_private(
        &f.actor(&role_token, "POST", "auth/token/revoke-self", json!({}))?,
        400,
    );
    Ok(())
}

#[test]
fn native_batch_token_api_file_inert_precise_grant_is_issued_once_and_never_authenticated()
-> TestResult {
    let mut f = Fixture::new()?;
    let count = services(&f)?;
    f.now += 1;
    let started = Instant::now();
    let clock = RequestClock::anchored(Duration::new(f.now, 900_000_000), started)?;
    let _scope =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let execution = f.service.begin_at_mode_precise(RequestDispatch {
        method:"POST",path:"auth/token/create",namespace:"",token:&f.admin,
        body:json!({"type":"batch","policies":["native-up"],"no_default_policy":true,"ttl":"1ns"}),
        now:f.now,allow_forward:true,enforce_namespace:true,wrap_ttl_seconds:None,
        origin_peer:None,client_certificates:None,
    }, clock);
    let mut response = f.service.finish_synchronous_request(execution);
    status(&response, 200);
    assert_eq!(response.body["auth"]["lease_duration"], 0);
    let token = batch(&mut response)?;
    assert_eq!(services(&f)?, count);
    paired(&f)?;
    no_private(&f.actor(&token, "GET", "up-kv/data/value", json!({}))?, 403);
    let mut f = f.restart()?;
    no_private(&f.actor(&token, "GET", "up-kv/data/value", json!({}))?, 403);
    assert_eq!(services(&f)?, count);
    Ok(())
}

#[test]
fn native_batch_token_api_file_restricted_actor_rejected_and_last_use_consumed_once() -> TestResult
{
    let mut f = Fixture::new()?;
    let mut response = f.admin(
        "POST",
        "auth/token/create",
        json!({
            "policies":["native-up"],"no_default_policy":true,"ttl":"120s","num_uses":1,
        }),
    )?;
    status(&response, 200);
    let parent = secret(&mut response, "/auth/client_token")?;
    let count = services(&f)?;
    let rejected = f.actor(
        &parent,
        "POST",
        "auth/token/create",
        json!({
            "type":"batch","policies":["native-up"],"no_default_policy":true,"ttl":"120s",
        }),
    )?;
    no_private(&rejected, 400);
    assert_eq!(
        rejected.body["errors"],
        json!(["parent token lookup failed: no parent found"])
    );
    assert_eq!(services(&f)?, count);
    assert!(
        !f.service
            .state
            .as_ref()
            .ok_or("state")?
            .has_namespace_batch_state()
    );
    no_private(
        &f.actor(&parent, "GET", "up-kv/data/value", json!({}))?,
        403,
    );
    let mut f = f.restart()?;
    no_private(
        &f.actor(&parent, "GET", "up-kv/data/value", json!({}))?,
        403,
    );
    Ok(())
}

#[test]
fn native_batch_file_actual_post_audit_policy_and_parent_revoke_veto_old_grant() -> TestResult {
    for revoke in [false, true] {
        let mut f = Fixture::new()?;
        let parent = f.token("native-up")?;
        let actor = Zeroizing::new(parent.as_str().to_owned());
        let admin = Zeroizing::new(f.admin.as_str().to_owned());
        let mut later = f.now + 1;
        let observed = Arc::new(AtomicBool::new(false));
        let observed_hook = Arc::clone(&observed);
        let captured = Arc::new(Mutex::new(None::<Zeroizing<String>>));
        let captured_hook = Arc::clone(&captured);
        let _hook = after_audit(move |service, response| {
            assert!(response.status == 200 && response.body["auth"]["token_type"] == "batch");
            observed_hook.store(true, Ordering::SeqCst);
            let capture_result = (|| -> TestResult {
                let token = response.body["auth"]["client_token"]
                    .as_str()
                    .ok_or("actual batch")?;
                *captured_hook.lock().map_err(|_| "captured test token")? =
                    Some(Zeroizing::new(token.to_owned()));
                Ok(())
            })();
            assert!(capture_result.is_ok(), "capture actual audited batch");
            let (path, body) = if revoke {
                ("auth/token/revoke", json!({"token":actor.as_str()}))
            } else {
                (
                    "sys/policies/acl/native-up",
                    json!({"policy":"path \"up-kv/data/*\" { capabilities = [\"deny\"] }"}),
                )
            };
            let changed = call(service, &mut later, &admin, "POST", path, body)
                .map(|changed| status(&changed, 204));
            assert!(changed.is_ok(), "real post-audit commit");
        })?;
        let response = f.actor(
            &parent,
            "POST",
            "auth/token/create",
            json!({
                "type":"batch","policies":["native-up"],"no_default_policy":true,"ttl":"120s",
            }),
        )?;
        assert!(observed.load(Ordering::SeqCst));
        no_private(&response, 503);
        let token = captured
            .lock()
            .map_err(|_| "capture")?
            .take()
            .ok_or("actual audited batch")?;
        assert!(!response.body.to_string().contains(token.as_str()));
        let mut f = f.restart()?;
        paired(&f)?;
        no_private(&f.actor(&token, "GET", "up-kv/data/value", json!({}))?, 403);
    }
    Ok(())
}

#[test]
fn native_batch_approle_file_post_audit_sid_destroy_vetoes_and_cannot_resurrect() -> TestResult {
    let mut f = Fixture::new()?;
    let (role, sid) = approle(&mut f, 2, 300, json!({}))?;
    let admin = Zeroizing::new(f.admin.as_str().to_owned());
    let secret_id = Zeroizing::new(sid.as_str().to_owned());
    let mut later = f.now + 1;
    let observed = Arc::new(AtomicBool::new(false));
    let observed_hook = Arc::clone(&observed);
    let _hook = after_audit(move |service, response| {
        assert!(response.status == 200 && response.body["auth"]["token_type"] == "batch");
        observed_hook.store(true, Ordering::SeqCst);
        let changed = call(
            service,
            &mut later,
            &admin,
            "POST",
            "auth/nb/role/issuer/secret-id/destroy",
            json!({"secret_id":secret_id.as_str()}),
        )
        .map(|changed| status(&changed, 204));
        assert!(changed.is_ok(), "actual SID destroy");
    })?;
    no_private(&login(&mut f, &role, &sid)?, 503);
    assert!(observed.load(Ordering::SeqCst));
    let mut f = f.restart()?;
    no_private(&login(&mut f, &role, &sid)?, 400);
    paired(&f)?;
    Ok(())
}

#[test]
fn native_batch_approle_file_original_sid_clock_expires_after_actual_audit() -> TestResult {
    let mut f = Fixture::new()?;
    let (role, sid) = approle(&mut f, 2, 2, json!({}))?;
    let observed = Arc::new(AtomicBool::new(false));
    let observed_hook = Arc::clone(&observed);
    let _hook = after_audit(move |_service, response| {
        assert!(response.status == 200 && response.body["auth"]["token_type"] == "batch");
        observed_hook.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(1100));
    })?;
    no_private(&login(&mut f, &role, &sid)?, 503);
    assert!(observed.load(Ordering::SeqCst));
    no_private(&login(&mut f, &role, &sid)?, 400);
    Ok(())
}

#[test]
fn native_batch_file_actual_audit_body_and_error_status_tampering_cannot_release() -> TestResult {
    for approle_issuer in [false, true] {
        let mut f = Fixture::new()?;
        let credentials = if approle_issuer {
            Some(approle(&mut f, 2, 300, json!({}))?)
        } else {
            None
        };
        let observed = Arc::new(AtomicBool::new(false));
        let observed_hook = Arc::clone(&observed);
        let _hook = after_audit(move |_service, response| {
            assert!(response.status == 200 && response.body["auth"]["client_token"].is_string());
            observed_hook.store(true, Ordering::SeqCst);
            response.status = 400;
            response.body["auth"]["renewable"] = json!(true);
        })?;
        let response =
            if let Some((role, sid)) = credentials.as_ref() {
                login(&mut f, role, sid)?
            } else {
                f.admin("POST", "auth/token/create", json!({
                "type":"batch","policies":["native-up"],"no_default_policy":true,"ttl":"120s",
            }))?
            };
        assert!(observed.load(Ordering::SeqCst));
        no_private(&response, 503);
    }
    Ok(())
}

#[test]
fn native_batch_token_api_file_userpass_service_actor_keeps_independent_issuer() -> TestResult {
    let mut f = Fixture::new()?;
    f.user("issuer", 0)?;
    let parent = f.login("issuer")?;
    let count = services(&f)?;
    let token = token_batch(&mut f, &parent, "auth/token/create")?;
    paired(&f)?;
    assert_eq!(services(&f)?, count);
    f.assert_value(&token)?;
    let mut f = f.restart()?;
    f.assert_value(&token)?;
    status(
        &f.admin(
            "POST",
            "auth/token/revoke",
            json!({"token":parent.as_str()}),
        )?,
        204,
    );
    no_private(&f.actor(&token, "GET", "up-kv/data/value", json!({}))?, 403);
    Ok(())
}
