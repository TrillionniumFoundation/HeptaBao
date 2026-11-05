//! Actual Userpass batch credentials share the original Auth/Namespace commit.
//! All public calls use the normal File fixture and its original request clock.
use super::*;

#[derive(Eq, PartialEq)]
struct BatchObservation {
    service_token_count: usize,
    authority: Option<[u8; 32]>,
    namespace_owner: [u8; 32],
}

fn observation(service: &Service) -> TestResult<BatchObservation> {
    let state = service.state.as_ref().ok_or("batch state")?;
    let encoded = owner_store::serialize_owner(&state.auth).map_err(|_| "Auth owner")?;
    let mut auth: Value = serde_json::from_slice(&encoded)?;
    let result = (|| -> TestResult<BatchObservation> {
        let service_token_count = auth
            .get("tokens")
            .and_then(Value::as_object)
            .ok_or("actual service token records")?
            .len();
        let authority = auth
            .get("batch_authority")
            .filter(|v| !v.is_null())
            .map(|value| -> TestResult<[u8; 32]> {
                let bytes = Zeroizing::new(serde_json::to_vec(value)?);
                Ok(crypto::digest(&bytes))
            })
            .transpose()?;
        let namespace = owner_store::serialize_owner(&state.namespaces)
            .map_err(|_| "actual Namespace owner")?;
        Ok(BatchObservation {
            service_token_count,
            authority,
            namespace_owner: crypto::digest(&namespace),
        })
    })();
    erase_json(&mut auth);
    result
}

fn batch_account(f: &mut Fixture) -> TestResult {
    status(
        &f.admin(
            "POST",
            "auth/up/users/alice",
            json!({
                "password":PASSWORD,"policies":["native-up"],"token_type":"batch",
                "token_ttl":120,"token_max_ttl":600,"token_num_uses":0,
            }),
        )?,
        204,
    );
    Ok(())
}

fn batch_login(f: &mut Fixture) -> TestResult<Zeroizing<String>> {
    let before = observation(&f.service)?;
    let mut response = f.actor(
        "",
        "POST",
        "auth/up/login/ALICE",
        json!({"password":PASSWORD}),
    )?;
    status(&response, 200);
    assert_eq!(response.body["auth"]["token_type"], "batch");
    assert_eq!(response.body["auth"]["accessor"], "");
    assert_eq!(response.body["auth"]["renewable"], false);
    assert_eq!(response.body["auth"]["metadata"]["username"], "alice");
    assert!(
        response.body["auth"]["entity_id"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    let issued = secret(&mut response, "/auth/client_token")?;
    let after = observation(&f.service)?;
    assert_eq!(after.service_token_count, before.service_token_count);
    assert!(after.authority.is_some());
    Ok(issued)
}

fn paired_native_lifecycle(f: &Fixture) -> TestResult {
    f.assert_native()?;
    let state = f.service.state.as_ref().ok_or("paired state")?;
    assert!(state.has_namespace_batch_state());
    state
        .validate_namespace_batch_state()
        .map_err(|_| "paired lifecycle validation")?;
    namespaces::native_empty::empty_profile(state).map_err(|_| "closed native catalog")?;
    let registry = state
        .auth
        .namespace_batch_registry()
        .ok_or("actual batch registry")?;
    assert!(registry.native_v6_flat_catalog_profile());
    assert_eq!(registry.current_incarnation(""), Some(0));
    Ok(())
}

fn lookup(f: &mut Fixture, raw: &str) -> TestResult<(u64, u64)> {
    let response = f.actor(raw, "GET", "auth/token/lookup-self", json!({}))?;
    status(&response, 200);
    assert_eq!(response.body["data"]["type"], "batch");
    assert_eq!(response.body["data"]["meta"]["username"], "alice");
    assert_eq!(response.body["data"]["renewable"], false);
    let created = response.body["data"]["creation_time"]
        .as_u64()
        .ok_or("actual issue time")?;
    let expires = response.body["data"]["expire_time_unix"]
        .as_u64()
        .ok_or("actual expiry")?;
    assert_eq!(expires.checked_sub(created), Some(120));
    Ok((created, expires))
}

#[test]
fn native_userpass_batch_file_cold_keeps_exact_grant_without_service_backing() -> TestResult {
    let mut f = Fixture::new()?;
    batch_account(&mut f)?;
    let before = observation(&f.service)?;
    let token = batch_login(&mut f)?;
    paired_native_lifecycle(&f)?;
    let actual = observation(&f.service)?;
    assert_eq!(actual.service_token_count, before.service_token_count);
    let lifetime = lookup(&mut f, &token)?;
    f.assert_value(&token)?;
    status(
        &f.actor(
            &token,
            "POST",
            "auth/token/renew-self",
            json!({"increment":"180s"}),
        )?,
        400,
    );
    status(
        &f.actor(&token, "POST", "auth/token/revoke-self", json!({}))?,
        400,
    );
    let mut f = f.restart()?;
    paired_native_lifecycle(&f)?;
    assert!(observation(&f.service)? == actual);
    assert_eq!(lookup(&mut f, &token)?, lifetime);
    f.assert_value(&token)?;
    f.now = lifetime.1;
    let denied = f.actor(&token, "GET", "up-kv/data/value", json!({}))?;
    status(&denied, 403);
    assert!(denied.body.get("data").is_none());
    Ok(())
}

#[test]
fn native_userpass_batch_actual_v5_promotion_does_not_reseal_or_reissue() -> TestResult {
    let mut f = Fixture::initialized()?;
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
            json!({
                "options":{"cas":0},"data":{"value":"native-userpass-preserved"}
            }),
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
    batch_account(&mut f)?;
    let token = batch_login(&mut f)?;
    let lifetime = lookup(&mut f, &token)?;
    let original = observation(&f.service)?;
    assert!(f.service.native_root.is_none());
    assert!(matches!(
        f.service
            .current_state_identity()
            .map_err(|_| "V5 identity")?,
        crate::state_record_root::StateIdentity::RecordsV5(_)
    ));
    status(
        &f.admin("POST", native_storage::ACTIVATE_PATH, json!({}))?,
        204,
    );
    paired_native_lifecycle(&f)?;
    let mut f = f.restart()?;
    paired_native_lifecycle(&f)?;
    assert!(observation(&f.service)? == original);
    assert_eq!(lookup(&mut f, &token)?, lifetime);
    f.assert_value(&token)?;
    Ok(())
}

#[test]
fn native_userpass_batch_catalog_before_and_after_issuance_moves_in_one_native_root() -> TestResult
{
    let mut f = Fixture::new()?;
    status(
        &f.admin("POST", "sys/namespaces/before-batch", json!({}))?,
        200,
    );
    batch_account(&mut f)?;
    let token = batch_login(&mut f)?;
    paired_native_lifecycle(&f)?;
    let before = observation(&f.service)?;
    status(
        &f.admin("POST", "sys/namespaces/after-batch", json!({}))?,
        200,
    );
    let after = observation(&f.service)?;
    assert!(after.namespace_owner != before.namespace_owner);
    assert_eq!(after.authority, before.authority);
    assert_eq!(after.service_token_count, before.service_token_count);
    let mut f = f.restart()?;
    paired_native_lifecycle(&f)?;
    assert!(observation(&f.service)? == after);
    let registry = f
        .service
        .state
        .as_ref()
        .ok_or("catalog state")?
        .auth
        .namespace_batch_registry()
        .ok_or("paired catalog")?;
    assert_eq!(registry.current_incarnation("before-batch"), Some(1));
    assert_eq!(registry.current_incarnation("after-batch"), Some(1));
    status(
        &f.admin("GET", "sys/namespaces/before-batch", json!({}))?,
        200,
    );
    status(
        &f.admin("GET", "sys/namespaces/after-batch", json!({}))?,
        200,
    );
    f.assert_value(&token)?;
    status(
        &f.admin(
            "POST",
            "sys/policies/acl/native-up",
            json!({
                "policy":"path \"up-kv/data/*\" { capabilities = [\"deny\"] }"
            }),
        )?,
        204,
    );
    let mut f = f.restart()?;
    paired_native_lifecycle(&f)?;
    let denied = f.actor(&token, "GET", "up-kv/data/value", json!({}))?;
    status(&denied, 403);
    assert!(denied.body.get("data").is_none());
    Ok(())
}

#[test]
fn native_userpass_batch_wrong_password_and_independent_token_api_owner_publish_only_real_grants()
-> TestResult {
    let mut f = Fixture::new()?;
    batch_account(&mut f)?;
    let before = observation(&f.service)?;
    assert!(
        !f.service
            .state
            .as_ref()
            .ok_or("state")?
            .has_namespace_batch_state()
    );
    let denied = f.actor(
        "",
        "POST",
        "auth/up/login/alice",
        json!({"password":"wrong"}),
    )?;
    status(&denied, 400);
    assert!(denied.body.get("auth").is_none());
    assert!(observation(&f.service)? == before);
    assert!(
        !f.service
            .state
            .as_ref()
            .ok_or("state")?
            .has_namespace_batch_state()
    );
    let token = batch_login(&mut f)?;
    let actual = observation(&f.service)?;
    // OpenBao 2.7.1's actual oracle accepts this unwrapped Token API
    // request. Its new independent typed issuer replaces the former missing-
    // owner 501; the separate wrapped/other-issuer negative tests stay intact.
    let mut issued = f.admin(
        "POST",
        "auth/token/create",
        json!({
            "type":"batch","policies":["native-up"],"ttl":"120s","no_default_policy":true
        }),
    )?;
    status(&issued, 200);
    assert_eq!(issued.body["auth"]["token_type"], "batch");
    let independent = secret(&mut issued, "/auth/client_token")?;
    let after = observation(&f.service)?;
    assert_eq!(after.service_token_count, actual.service_token_count);
    assert_eq!(after.namespace_owner, actual.namespace_owner);
    assert!(after.authority.is_some());
    f.assert_value(&independent)?;
    let mut f = f.restart()?;
    paired_native_lifecycle(&f)?;
    f.assert_value(&token)?;
    f.assert_value(&independent)?;
    Ok(())
}

#[test]
fn native_userpass_batch_actual_post_audit_catalog_commit_vetoes_original_delivery() -> TestResult {
    let mut f = Fixture::new()?;
    batch_account(&mut f)?;
    let (response, _) = f.audited_login(PASSWORD, Duration::from_secs(15))?;
    status(&response, 200);
    assert_eq!(response.body["auth"]["token_type"], "batch");
    let issued = Zeroizing::new(text(&response, "/auth/client_token")?);
    let original = f
        .service
        .pending_native_auth_delivery
        .take()
        .ok_or("original audited owner")?;
    assert!(original.batch_lifecycle_owner.is_some());
    status(
        &f.admin("POST", "sys/namespaces/after-actual-audit", json!({}))?,
        200,
    );
    assert!(f.service.pending_native_auth_delivery.is_none());
    f.service.pending_native_auth_delivery = Some(original);
    let response =
        f.service
            .complete_native_auth_delivery(true, response, "batch-catalog-interleave");
    status(&response, 503);
    assert!(response.body.get("auth").is_none() && response.body.get("data").is_none());
    assert!(!response.body.to_string().contains(issued.as_str()));
    assert!(response.consistency_index.is_none());
    let mut f = f.restart()?;
    paired_native_lifecycle(&f)?;
    status(
        &f.admin("GET", "sys/namespaces/after-actual-audit", json!({}))?,
        200,
    );
    Ok(())
}

#[test]
fn native_userpass_batch_actual_audited_status_tampering_erases_the_credential() -> TestResult {
    let mut f = Fixture::new()?;
    batch_account(&mut f)?;
    let (mut response, _) = f.audited_login(PASSWORD, Duration::from_secs(15))?;
    status(&response, 200);
    assert_eq!(response.body["auth"]["token_type"], "batch");
    let issued = Zeroizing::new(text(&response, "/auth/client_token")?);
    response.status = 503;
    let response = f
        .service
        .complete_native_auth_delivery(true, response, "batch-status-custody");
    status(&response, 503);
    assert!(response.body.get("auth").is_none() && response.body.get("data").is_none());
    assert!(!response.body.to_string().contains(issued.as_str()));
    assert!(response.consistency_index.is_none());
    assert!(f.service.pending_native_auth_delivery.is_none());
    Ok(())
}

#[test]
fn native_userpass_batch_actual_audit_cannot_replace_the_original_deadline() -> TestResult {
    let mut f = Fixture::new()?;
    batch_account(&mut f)?;
    let (response, until) = f.audited_login(PASSWORD, Duration::from_millis(1500))?;
    status(&response, 200);
    assert_eq!(response.body["auth"]["token_type"], "batch");
    std::thread::sleep(until.saturating_duration_since(Instant::now()) + Duration::from_millis(2));
    let response =
        f.service
            .complete_native_auth_delivery(true, response, "batch-original-deadline");
    status(&response, 503);
    assert!(response.body.get("auth").is_none() && response.body.get("data").is_none());
    assert!(response.consistency_index.is_none());
    assert!(f.service.pending_native_auth_delivery.is_none());
    let f = f.restart()?;
    paired_native_lifecycle(&f)?;
    Ok(())
}

// Integration regressions: a response wrapper is not a batch-issuer owner.
// Use the actual normal File fixture, the original dispatcher, the real audit
// completion path and the original 15-second request budget throughout.
fn wrapped_batch_request(
    f: &mut Fixture,
    token: &str,
    path: &str,
    body: Value,
) -> TestResult<Response> {
    f.now += 1;
    let started = Instant::now();
    let clock = RequestClock::anchored(Duration::from_secs(f.now), started)?;
    let _scope =
        crate::request_deadline::RequestDeadlineScope::enter(started + Duration::from_secs(15));
    let ingress = crypto::random::<16>().map_err(std::io::Error::other)?;
    let _ingress = crate::auth::IngressReplyScope::listener(&ingress);
    let execution = f.service.begin_at_mode_precise(
        RequestDispatch {
            method: "POST",
            path,
            namespace: "",
            token,
            body,
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
    assert!(f.service.pending_native_auth_delivery.is_none());
    assert!(f.service.pending_ordinary_kv_authority.is_none());
    Ok(response)
}

fn batch_issuer_engine_owner(f: &Fixture) -> TestResult<[u8; 32]> {
    let root = f
        .service
        .native_root
        .as_ref()
        .ok_or("actual batch issuer native root")?;
    let owner = root
        .owners
        .iter()
        .find(|owner| owner.domain == OwnerDomain::Engines)
        .ok_or("actual batch issuer Engine owner")?;
    // Native KV views intentionally cannot serialize as a legacy EngineState.
    // Bind the actual selected Engine descriptor and both immutable KV graphs,
    // retaining their original content identities without materializing data.
    let bytes = owner_store::serialize_owner(&(owner, &root.kv1, &root.kv2))
        .map_err(|_| "actual batch issuer Engine references")?;
    Ok(crypto::digest(&bytes))
}

fn no_batch_wrapper_output(response: &Response) {
    status(response, 501);
    assert!(response.body.get("auth").is_none());
    assert!(response.body.get("data").is_none());
    assert!(response.body.get("wrap_info").is_none());
    assert!(response.unwrapped_json.is_none());
    assert!(response.response_headers.is_empty());
    assert!(response.consistency_index.is_none());
}

fn unchanged_batch_issuer_owners(
    f: &Fixture,
    before: &BatchObservation,
    engines: [u8; 32],
) -> TestResult {
    let actual = observation(&f.service)?;
    assert!(&actual == before);
    assert_eq!(batch_issuer_engine_owner(f)?, engines);
    paired_native_lifecycle(f)?;
    Ok(())
}

#[test]
fn native_userpass_batch_response_wrapper_cannot_hide_token_api_issuer() -> TestResult {
    let mut f = Fixture::new()?;
    batch_account(&mut f)?;
    let original = batch_login(&mut f)?;
    paired_native_lifecycle(&f)?;
    let before = observation(&f.service)?;
    let engines = batch_issuer_engine_owner(&f)?;
    let admin = Zeroizing::new(f.admin.as_str().to_owned());
    let rejected = wrapped_batch_request(
        &mut f,
        &admin,
        "auth/token/create",
        json!({
            "type":"batch", "policies":["native-up"], "ttl":"120s", "no_default_policy":true,
        }),
    )?;
    no_batch_wrapper_output(&rejected);
    assert_eq!(
        rejected.body["errors"],
        json!(["native batch issuer has no lifecycle owner"])
    );
    unchanged_batch_issuer_owners(&f, &before, engines)?;
    let mut f = f.restart()?;
    unchanged_batch_issuer_owners(&f, &before, engines)?;
    f.assert_value(&original)?;
    Ok(())
}

#[test]
fn native_userpass_batch_response_wrapper_cannot_hide_approle_issuer() -> TestResult {
    let mut f = Fixture::new()?;
    batch_account(&mut f)?;
    let original = batch_login(&mut f)?;
    status(
        &f.admin("POST", "sys/auth/other-batch", json!({"type":"approle"}))?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "auth/other-batch/role/issuer",
            json!({
                "bind_secret_id":true, "token_type":"batch", "token_policies":["native-up"],
                "token_ttl":"120s", "token_max_ttl":"600s", "token_num_uses":0,
            }),
        )?,
        204,
    );
    let mut role = f.admin("GET", "auth/other-batch/role/issuer/role-id", json!({}))?;
    status(&role, 200);
    let role_id = secret(&mut role, "/data/role_id")?;
    // A valid AppRole must retain an actual credential constraint. Obtain its
    // real SecretID before observing owners and exercising the batch veto.
    let mut issued = f.admin("POST", "auth/other-batch/role/issuer/secret-id", json!({}))?;
    status(&issued, 200);
    let secret_id = secret(&mut issued, "/data/secret_id")?;
    let before = observation(&f.service)?;
    let engines = batch_issuer_engine_owner(&f)?;
    let rejected = wrapped_batch_request(
        &mut f,
        "",
        "auth/other-batch/login",
        json!({
            "role_id":role_id.as_str(), "secret_id":secret_id.as_str(),
        }),
    )?;
    no_batch_wrapper_output(&rejected);
    assert_eq!(
        rejected.body["errors"],
        json!(["native batch issuer has no lifecycle owner"])
    );
    unchanged_batch_issuer_owners(&f, &before, engines)?;
    let mut f = f.restart()?;
    unchanged_batch_issuer_owners(&f, &before, engines)?;
    f.assert_value(&original)?;
    Ok(())
}

#[test]
fn native_userpass_batch_response_wrapper_keeps_userpass_enrollment_closed() -> TestResult {
    let mut f = Fixture::new()?;
    batch_account(&mut f)?;
    let original = batch_login(&mut f)?;
    let before = observation(&f.service)?;
    let engines = batch_issuer_engine_owner(&f)?;
    let rejected = wrapped_batch_request(
        &mut f,
        "",
        "auth/up/login/alice",
        json!({
            "password":PASSWORD,
        }),
    )?;
    no_batch_wrapper_output(&rejected);
    unchanged_batch_issuer_owners(&f, &before, engines)?;
    let mut f = f.restart()?;
    unchanged_batch_issuer_owners(&f, &before, engines)?;
    f.assert_value(&original)?;
    let still_supported = batch_login(&mut f)?;
    f.assert_value(&still_supported)?;
    Ok(())
}
