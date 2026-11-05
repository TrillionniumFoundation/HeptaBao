//! Actual normal File V6 output composition. Every secret below is synthetic
//! and fixture-owned. Tests retain the original dispatcher and audit path.
use super::*;

#[derive(Clone, Copy)]
enum Kind {
    Kv,
    Auth,
}

fn no_output(response: &Response) {
    no_private(response);
    assert!(response.body.get("auth").is_none());
}

fn wrapped(response: &mut Response, path: &str) -> TestResult<Zeroizing<String>> {
    status(response, 200);
    assert_eq!(response.body["wrap_info"]["creation_path"], path);
    assert!(response.body["data"].is_null());
    assert!(response.body["auth"].is_null());
    assert!(!response.body.to_string().contains(PAYLOAD));
    secret(response, "/wrap_info/token")
}

fn accessors(f: &mut Fixture) -> TestResult<Value> {
    let response = f.admin("LIST", "auth/token/accessors", json!({}), None)?;
    status(&response, 200);
    response
        .body
        .pointer("/data/keys")
        .cloned()
        .ok_or_else(|| "accessor listing".into())
}

fn role(f: &mut Fixture, uses: u64) -> TestResult<Zeroizing<String>> {
    status(
        &f.admin("POST", "sys/auth/compose", json!({"type":"approle"}), None)?,
        204,
    );
    status(
        &f.admin(
            "POST",
            "auth/compose/role/once",
            json!({
                "token_policies":["default"],"token_ttl":"300s","token_max_ttl":"600s",
                "secret_id_ttl":"600s","secret_id_num_uses":uses,
            }),
            None,
        )?,
        204,
    );
    let mut response = f.admin("GET", "auth/compose/role/once/role-id", json!({}), None)?;
    status(&response, 200);
    secret(&mut response, "/data/role_id")
}

#[allow(clippy::too_many_arguments)]
fn dispatched(
    f: &mut Fixture,
    kind: Kind,
    token: &str,
    method: &str,
    path: &str,
    body: &Value,
    ttl: u64,
    budget: Duration,
) -> TestResult<(Response, RequestClock, Instant, Instant)> {
    f.now += 1;
    let started = Instant::now();
    let until = started + budget;
    let clock = RequestClock::anchored(Duration::from_secs(f.now), started)?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(until);
    let ingress = crypto::random::<16>().map_err(std::io::Error::other)?;
    let _ingress = crate::auth::IngressReplyScope::listener(&ingress);
    let response = f.service.handle_inner(RequestView {
        method,
        path,
        namespace: "",
        token,
        body,
        now: f.now,
        admission_started: started,
        token_clock: Some(clock),
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: Some(ttl),
        origin_peer: None,
        client_certificates: None,
    });
    status(&response, 200);
    match kind {
        Kind::Kv => {
            assert!(f.service.pending_native_auth_delivery.is_none());
            assert!(
                f.service
                    .pending_ordinary_kv_authority
                    .as_ref()
                    .is_some_and(|owner| owner.native_response_wrapping.is_some())
            );
            assert!(f.service.native_wrapped_kv_terminal_deadline().is_some());
        }
        Kind::Auth => {
            assert!(f.service.pending_ordinary_kv_authority.is_none());
            let owner = f
                .service
                .pending_native_auth_delivery
                .as_ref()
                .ok_or("actual Auth output owner")?;
            assert!(owner.wrapping_owner.is_none() && owner.response_wrapping_owner.is_some());
            assert!(owner.requires_local_proof() && owner.tracks_terminal_checkpoint());
            assert!(owner.delivery_checkpoint.is_some() && owner.proof.is_none());
        }
    }
    Ok((response, clock, started, until))
}

#[allow(clippy::too_many_arguments)]
fn audited(
    f: &mut Fixture,
    kind: Kind,
    token: &str,
    method: &str,
    path: &str,
    body: &Value,
    ttl: u64,
    budget: Duration,
) -> TestResult<(Response, Instant, Instant)> {
    let (response, clock, started, until) =
        dispatched(f, kind, token, method, path, body, ttl, budget)?;
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(until);
    let response = f.service.audit_completed_response_with_receipt(
        "native-response-composition-real-audit",
        f.now,
        Some(clock),
        response,
        || {},
    );
    status(&response, 200);
    if let Kind::Auth = kind {
        let owner = f
            .service
            .pending_native_auth_delivery
            .as_ref()
            .ok_or("audited Auth output owner")?;
        assert!(matches!(
            owner.proof.as_ref(),
            Some(native_v6_reader::NativeProof::Single(_))
        ));
    }
    Ok((response, started, until))
}

enum Held {
    Kv(Box<ordinary_kv_delivery::OrdinaryKvAuthority>),
    Auth(Box<NativeAuthDelivery>),
}
fn suspend(f: &mut Fixture, kind: Kind) -> TestResult<Held> {
    match kind {
        Kind::Kv => Ok(Held::Kv(Box::new(
            f.service
                .pending_ordinary_kv_authority
                .take()
                .ok_or("original KV actor")?,
        ))),
        Kind::Auth => Ok(Held::Auth(Box::new(
            f.service
                .pending_native_auth_delivery
                .take()
                .ok_or("original Auth actor")?,
        ))),
    }
}
fn restore(f: &mut Fixture, held: Held) {
    assert!(f.service.pending_native_auth_delivery.is_none());
    assert!(f.service.pending_ordinary_kv_authority.is_none());
    match held {
        Held::Kv(owner) => f.service.pending_ordinary_kv_authority = Some(*owner),
        Held::Auth(owner) => f.service.pending_native_auth_delivery = Some(*owner),
    }
}
fn finish(f: &mut Fixture, kind: Kind, response: Response) -> TestResult<Response> {
    let response = match kind {
        Kind::Kv => {
            let owner = f
                .service
                .pending_ordinary_kv_authority
                .take()
                .ok_or("original KV delivery")?;
            f.service.complete_ordinary_kv_delivery(
                owner,
                response,
                "native-response-composition-real-audit",
            )
        }
        Kind::Auth => f.service.complete_native_auth_delivery(
            true,
            response,
            "native-response-composition-real-audit",
        ),
    };
    assert!(f.service.pending_native_auth_delivery.is_none());
    assert!(f.service.pending_ordinary_kv_authority.is_none());
    Ok(response)
}
fn selection(kind: Kind) -> (&'static str, &'static str, Value) {
    match kind {
        Kind::Kv => ("GET", "wrap-kv/data/preserved", json!({})),
        Kind::Auth => (
            "POST",
            "auth/token/create",
            json!({"policies":["default"],"ttl":"300s"}),
        ),
    }
}

#[test]
fn native_wrapping_response_kv2_actual_read_cold_and_single_unwrap() -> TestResult {
    let mut f = Fixture::new()?;
    let mut response = f.admin("GET", "wrap-kv/data/preserved", json!({}), Some(120))?;
    let token = wrapped(&mut response, "wrap-kv/data/preserved")?;
    let mut f = f.restart()?;
    let response = f.actor(&token, "POST", UNWRAP, json!({}), None)?;
    status(&response, 200);
    assert_eq!(response.body["data"]["data"]["value"], "unchanged-KV");
    assert_eq!(response.body["data"]["metadata"]["version"], 1);
    assert!(
        response
            .unwrapped_json
            .as_ref()
            .is_some_and(|origin| origin.has_stored_reply())
    );
    let mut f = f.restart()?;
    status(&f.actor(&token, "POST", UNWRAP, json!({}), None)?, 400);
    f.assert_kv()?;
    Ok(())
}

#[test]
fn native_wrapping_response_kv2_actual_cas_writes_once_and_commits_with_wrapper() -> TestResult {
    let mut f = Fixture::new()?;
    let body = json!({"options":{"cas":0},"data":{"value":PAYLOAD}});
    let mut response = f.admin("POST", "wrap-kv/data/composed", body.clone(), Some(120))?;
    let token = wrapped(&mut response, "wrap-kv/data/composed")?;
    let mut f = f.restart()?;
    let value = f.admin("GET", "wrap-kv/data/composed", json!({}), None)?;
    status(&value, 200);
    assert_eq!(value.body["data"]["metadata"]["version"], 1);
    assert_eq!(value.body["data"]["data"]["value"], PAYLOAD);
    let result = f.actor(&token, "POST", UNWRAP, json!({}), None)?;
    status(&result, 200);
    assert_eq!(result.body["data"]["version"], 1);
    let failure = f.admin("POST", "wrap-kv/data/composed", body, Some(120))?;
    status(&failure, 400);
    no_output(&failure);
    let value = f.admin("GET", "wrap-kv/data/composed", json!({}), None)?;
    assert_eq!(value.body["data"]["metadata"]["version"], 1);
    status(&f.actor(&token, "POST", UNWRAP, json!({}), None)?, 400);
    Ok(())
}

#[test]
fn native_wrapping_response_kv1_formal_activation_cold_payload() -> TestResult {
    let mut f = Fixture::initialized()?;
    status(
        &f.admin(
            "POST",
            "sys/mounts/plain",
            json!({"type":"kv","options":{"version":"1"}}),
            None,
        )?,
        204,
    );
    status(
        &f.admin("POST", "plain/value", json!({"value":PAYLOAD}), None)?,
        204,
    );
    status(
        &f.admin("POST", native_storage::ACTIVATE_PATH, json!({}), None)?,
        204,
    );
    f.assert_native()?;
    let mut response = f.admin("GET", "plain/value", json!({}), Some(120))?;
    let token = wrapped(&mut response, "plain/value")?;
    let mut f = f.restart()?;
    let result = f.actor(&token, "POST", UNWRAP, json!({}), None)?;
    status(&result, 200);
    assert_eq!(result.body["data"]["value"], PAYLOAD);
    status(&f.actor(&token, "POST", UNWRAP, json!({}), None)?, 400);
    let value = f.admin("GET", "plain/value", json!({}), None)?;
    status(&value, 200);
    assert_eq!(value.body["data"]["value"], PAYLOAD);
    Ok(())
}

#[test]
fn native_wrapping_response_invalid_ttl_preserves_original_predispatch_finite_actor() -> TestResult
{
    let mut f = Fixture::new()?;
    status(&f.admin("POST", "sys/policies/acl/compose-create", json!({
        "policy":"path \"wrap-kv/data/rollback\" { capabilities = [\"create\",\"update\"] }",
    }), None)?, 204);
    let actor = f.token("compose-create", 1)?;
    let before = f.root()?;
    let response = f.actor(
        &actor,
        "POST",
        "wrap-kv/data/rollback",
        json!({"options":{"cas":0},"data":{"value":PAYLOAD}}),
        Some(u64::MAX),
    )?;
    status(&response, 400);
    no_output(&response);
    assert!(
        f.root()?
            .encode()
            .map_err(|_| "current native root encoding")?
            == before
                .encode()
                .map_err(|_| "original native root encoding")?
    );
    assert!(
        !f.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_live_wrappers()
    );
    let mut f = f.restart()?;
    status(
        &f.admin("GET", "wrap-kv/data/rollback", json!({}), None)?,
        404,
    );
    // The public ingress rejects this TTL before authenticating the actor or
    // executing the domain. It must not be confused with wrapper construction
    // failure after actual dispatch and authenticated finite-use consumption.
    let mut response = f.actor(
        &actor,
        "POST",
        "wrap-kv/data/rollback",
        json!({"options":{"cas":0},"data":{"value":PAYLOAD}}),
        Some(120),
    )?;
    let wrapper = wrapped(&mut response, "wrap-kv/data/rollback")?;
    let result = f.actor(&wrapper, "POST", UNWRAP, json!({}), None)?;
    status(&result, 200);
    assert_eq!(result.body["data"]["version"], 1);
    status(
        &f.actor(
            &actor,
            "POST",
            "wrap-kv/data/rollback",
            json!({"options":{"cas":1},"data":{"value":PAYLOAD}}),
            Some(120),
        )?,
        403,
    );
    Ok(())
}

#[test]
fn native_wrapping_response_real_size_failure_keeps_payload_and_spends_original_actor() -> TestResult
{
    let mut f = Fixture::new()?;
    status(
        &f.admin(
            "POST",
            "wrap-kv/data/large",
            json!({"data":{"value":"x".repeat(70*1024)}}),
            None,
        )?,
        200,
    );
    status(
        &f.admin(
            "POST",
            "sys/policies/acl/compose-large-read",
            json!({
                "policy":"path \"wrap-kv/data/large\" { capabilities = [\"read\"] }",
            }),
            None,
        )?,
        204,
    );
    let actor = f.token("compose-large-read", 1)?;
    let response = f.actor(&actor, "GET", "wrap-kv/data/large", json!({}), Some(120))?;
    status(&response, 413);
    no_output(&response);
    assert!(
        !f.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_live_wrappers()
    );
    let mut f = f.restart()?;
    status(
        &f.actor(&actor, "GET", "wrap-kv/data/large", json!({}), Some(120))?,
        403,
    );
    let value = f.admin("GET", "wrap-kv/data/large", json!({}), None)?;
    status(&value, 200);
    assert_eq!(value.body["data"]["metadata"]["version"], 1);
    assert_eq!(
        value.body["data"]["data"]["value"].as_str().map(str::len),
        Some(70 * 1024)
    );
    Ok(())
}

#[test]
fn native_wrapping_response_auth_create_cold_does_not_spend_new_credential_for_delivery()
-> TestResult {
    let mut f = Fixture::new()?;
    let mut response = f.admin(
        "POST",
        "auth/token/create",
        json!({
            "policies":["default"],"ttl":"300s","num_uses":2,
        }),
        Some(120),
    )?;
    let wrapper = wrapped(&mut response, "auth/token/create")?;
    let mut f = f.restart()?;
    let mut response = f.actor(&wrapper, "POST", UNWRAP, json!({}), None)?;
    status(&response, 200);
    let token = secret(&mut response, "/auth/client_token")?;
    status(
        &f.actor(&token, "GET", "auth/token/lookup-self", json!({}), None)?,
        200,
    );
    status(
        &f.actor(&token, "GET", "auth/token/lookup-self", json!({}), None)?,
        200,
    );
    status(
        &f.actor(&token, "GET", "auth/token/lookup-self", json!({}), None)?,
        403,
    );
    status(&f.actor(&wrapper, "POST", UNWRAP, json!({}), None)?, 400);
    Ok(())
}

#[test]
fn native_wrapping_response_renew_and_lookup_echo_are_inside_actual_wrapped_payload() -> TestResult
{
    let mut f = Fixture::new()?;
    let mut issued = f.admin(
        "POST",
        "auth/token/create",
        json!({
            "policies":["default"],"ttl":"300s","explicit_max_ttl":"600s","renewable":true,
        }),
        None,
    )?;
    status(&issued, 200);
    let accessor = Zeroizing::new(text(&issued, "/auth/accessor")?);
    let token = secret(&mut issued, "/auth/client_token")?;
    let mut response = f.actor(
        &token,
        "POST",
        "auth/token/renew-self",
        json!({"increment":"300s"}),
        Some(120),
    )?;
    let wrapper = wrapped(&mut response, "auth/token/renew-self")?;
    let response = f.actor(&wrapper, "POST", UNWRAP, json!({}), None)?;
    status(&response, 200);
    assert!(response.body["auth"]["client_token"].as_str() == Some(token.as_str()));
    let mut response = f.actor(
        &token,
        "GET",
        "auth/token/lookup-self",
        json!({}),
        Some(120),
    )?;
    let wrapper = wrapped(&mut response, "auth/token/lookup-self")?;
    let response = f.actor(&wrapper, "POST", UNWRAP, json!({}), None)?;
    status(&response, 200);
    assert!(response.body["data"]["id"].as_str() == Some(token.as_str()));
    let mut response = f.admin(
        "POST",
        "auth/token/lookup-accessor",
        json!({"accessor":accessor.as_str()}),
        Some(120),
    )?;
    let wrapper = wrapped(&mut response, "auth/token/lookup-accessor")?;
    let mut f = f.restart()?;
    let response = f.actor(&wrapper, "POST", UNWRAP, json!({}), None)?;
    status(&response, 200);
    assert_eq!(response.body["data"]["id"], "");
    assert!(!response.body.to_string().contains(token.as_str()));
    Ok(())
}

#[test]
fn native_wrapping_response_approle_secretid_and_login_keep_original_single_consumption()
-> TestResult {
    let mut f = Fixture::new()?;
    let role_id = role(&mut f, 1)?;
    let mut response = f.admin(
        "POST",
        "auth/compose/role/once/secret-id",
        json!({}),
        Some(120),
    )?;
    let wrapper = wrapped(&mut response, "auth/compose/role/once/secret-id")?;
    let mut f = f.restart()?;
    let mut response = f.actor(&wrapper, "POST", UNWRAP, json!({}), None)?;
    status(&response, 200);
    let secret_id = secret(&mut response, "/data/secret_id")?;
    let body = json!({"role_id":role_id.as_str(),"secret_id":secret_id.as_str()});
    let mut response = f.actor("", "POST", "auth/compose/login", body.clone(), Some(120))?;
    let login_wrapper = wrapped(&mut response, "auth/compose/login")?;
    let mut f = f.restart()?;
    status(&f.actor("", "POST", "auth/compose/login", body, None)?, 400);
    let mut response = f.actor(&login_wrapper, "POST", UNWRAP, json!({}), None)?;
    status(&response, 200);
    let token = secret(&mut response, "/auth/client_token")?;
    status(
        &f.actor(&token, "GET", "auth/token/lookup-self", json!({}), None)?,
        200,
    );
    status(
        &f.actor(&login_wrapper, "POST", UNWRAP, json!({}), None)?,
        400,
    );
    Ok(())
}

#[test]
fn native_wrapping_response_real_login_size_failure_keeps_exact_authenticated_secretid_use()
-> TestResult {
    let mut f = Fixture::new()?;
    let role_id = role(&mut f, 2)?;
    // OpenBao 2.7.1 rejects a fresh alias metadata value over 512 bytes.
    // Establish the actual alias with a separate one-use small SID first;
    // this must not consume either use of the large SID exercised below.
    let mut prime_sid = f.admin(
        "POST",
        "auth/compose/role/once/secret-id",
        json!({"metadata":r#"{"setup":"existing-alias"}"#,"num_uses":1}),
        None,
    )?;
    status(&prime_sid, 200);
    let prime_sid = secret(&mut prime_sid, "/data/secret_id")?;
    let mut primed = f.actor(
        "",
        "POST",
        "auth/compose/login",
        json!({"role_id":role_id.as_str(),"secret_id":prime_sid.as_str()}),
        None,
    )?;
    status(&primed, 200);
    let prime_token = secret(&mut primed, "/auth/client_token")?;
    status(
        &f.admin(
            "POST",
            "auth/token/revoke",
            json!({"token":prime_token.as_str()}),
            None,
        )?,
        204,
    );
    // Original metadata permits 256 KiB, whereas an actual wrapper permits
    // 64 KiB. A valid 70 KiB SID metadata map therefore reaches real backend
    // authentication/issuance, then fails the unchanged wrapper constructor.
    // No fake response, private Auth mutation or capacity override is used.
    let metadata = json!({"large":"x".repeat(70*1024)}).to_string();
    assert!(metadata.len() > 64 * 1024 && metadata.len() < crate::login_metadata::MAX_BYTES);
    let mut issued = f.admin(
        "POST",
        "auth/compose/role/once/secret-id",
        json!({"metadata":metadata}),
        None,
    )?;
    status(&issued, 200);
    let secret_id = secret(&mut issued, "/data/secret_id")?;
    let original_tokens = accessors(&mut f)?;
    let before = f.root()?;
    let body = json!({"role_id":role_id.as_str(),"secret_id":secret_id.as_str()});
    let response = f.actor("", "POST", "auth/compose/login", body.clone(), Some(120))?;
    status(&response, 413);
    no_output(&response);
    assert_eq!(
        response.body["errors"][0],
        "wrapped response exceeds supported bounds"
    );
    f.assert_auth_only(&before)?;
    assert!(original_tokens == accessors(&mut f)?);
    assert!(
        !f.service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_live_wrappers()
    );
    let mut f = f.restart()?;
    // Exactly one SID use survived the failed wrapper construction: zero uses
    // would reject this login; two uses would permit the final replay below.
    let mut response = f.actor("", "POST", "auth/compose/login", body.clone(), None)?;
    status(&response, 200);
    assert_eq!(
        response.body["auth"]["metadata"]["large"]
            .as_str()
            .map(str::len),
        Some(70 * 1024)
    );
    let token = secret(&mut response, "/auth/client_token")?;
    status(
        &f.actor(&token, "GET", "auth/token/lookup-self", json!({}), None)?,
        200,
    );
    status(&f.actor("", "POST", "auth/compose/login", body, None)?, 400);
    Ok(())
}

#[test]
fn native_wrapping_response_cubbyhole_retains_actual_inner_owner_and_payload() -> TestResult {
    let mut f = Fixture::new()?;
    status(
        &f.admin(
            "POST",
            "sys/policies/acl/compose-cubby",
            json!({
                "policy":"path \"cubbyhole/*\" { capabilities = [\"read\",\"update\",\"create\"] }",
            }),
            None,
        )?,
        204,
    );
    let actor = f.token("compose-cubby", 0)?;
    status(
        &f.actor(
            &actor,
            "POST",
            "cubbyhole/value",
            json!({"value":PAYLOAD}),
            None,
        )?,
        204,
    );
    let mut response = f.actor(&actor, "GET", "cubbyhole/value", json!({}), Some(120))?;
    let wrapper = wrapped(&mut response, "cubbyhole/value")?;
    let mut f = f.restart()?;
    let response = f.actor(&wrapper, "POST", UNWRAP, json!({}), None)?;
    status(&response, 200);
    assert_eq!(response.body["data"]["value"], PAYLOAD);
    let original = f.actor(&actor, "GET", "cubbyhole/value", json!({}), None)?;
    status(&original, 200);
    assert_eq!(original.body["data"]["value"], PAYLOAD);
    Ok(())
}

#[test]
fn native_wrapping_response_actual_audit_outer_status_or_token_tampering_is_vetoed() -> TestResult {
    for kind in [Kind::Kv, Kind::Auth] {
        for status_tamper in [false, true] {
            let mut f = Fixture::new()?;
            let admin = Zeroizing::new(f.admin.as_str().to_owned());
            let (method, path, body) = selection(kind);
            let (mut response, _, _) = audited(
                &mut f,
                kind,
                &admin,
                method,
                path,
                &body,
                120,
                Duration::from_secs(15),
            )?;
            if status_tamper {
                response.status = 400;
            } else {
                response.body["wrap_info"]["token"] = json!("unowned-substitute-wrapper");
            }
            let response = finish(&mut f, kind, response)?;
            status(&response, 503);
            no_output(&response);
        }
    }
    Ok(())
}

#[test]
fn native_wrapping_response_original_ttl_and_deadline_survive_actual_audit() -> TestResult {
    for kind in [Kind::Kv, Kind::Auth] {
        for deadline_expiry in [false, true] {
            let mut f = Fixture::new()?;
            let admin = Zeroizing::new(f.admin.as_str().to_owned());
            let (method, path, body) = selection(kind);
            let budget = if deadline_expiry {
                Duration::from_millis(1500)
            } else {
                Duration::from_secs(15)
            };
            let ttl = if deadline_expiry { 120 } else { 1 };
            let (response, started, until) =
                audited(&mut f, kind, &admin, method, path, &body, ttl, budget)?;
            let wait_until = if deadline_expiry {
                until + Duration::from_millis(2)
            } else {
                started + Duration::from_millis(1100)
            };
            std::thread::sleep(wait_until.saturating_duration_since(Instant::now()));
            let _replacement_ambient = crate::request_deadline::RequestDeadlineScope::enter(
                Instant::now() + Duration::from_secs(30),
            );
            let response = finish(&mut f, kind, response)?;
            status(&response, 503);
            no_output(&response);
        }
    }
    Ok(())
}

#[test]
fn native_wrapping_response_actual_post_audit_root_change_cannot_refresh_proof() -> TestResult {
    for kind in [Kind::Kv, Kind::Auth] {
        let mut f = Fixture::new()?;
        let admin = Zeroizing::new(f.admin.as_str().to_owned());
        let (method, path, body) = selection(kind);
        let (response, _, _) = audited(
            &mut f,
            kind,
            &admin,
            method,
            path,
            &body,
            120,
            Duration::from_secs(15),
        )?;
        let wrapper = Zeroizing::new(text(&response, "/wrap_info/token")?);
        let checkpoint = f
            .service
            .current_state_identity()
            .map_err(|_| "checkpoint")?;
        let held = suspend(&mut f, kind)?;
        status(
            &f.admin(
                "POST",
                "wrap-kv/data/other",
                json!({"options":{"cas":0},"data":{"value":"other-root"}}),
                None,
            )?,
            200,
        );
        assert!(f.service.current_state_identity().map_err(|_| "new root")? != checkpoint);
        restore(&mut f, held);
        let response = finish(&mut f, kind, response)?;
        status(&response, 503);
        no_output(&response);
        let mut f = f.restart()?;
        // The original operation/wrapper was durable before audit; a veto is
        // not a fabricated rollback or permission to execute it a second time.
        status(&f.actor(&wrapper, "POST", UNWRAP, json!({}), None)?, 200);
        status(&f.actor(&wrapper, "POST", UNWRAP, json!({}), None)?, 400);
        let value = f.admin("GET", "wrap-kv/data/other", json!({}), None)?;
        assert_eq!(value.body["data"]["metadata"]["version"], 1);
    }
    Ok(())
}

#[test]
fn native_wrapping_response_actual_post_audit_actor_revocation_is_not_hidden_by_outer_wrapper()
-> TestResult {
    for kind in [Kind::Kv, Kind::Auth] {
        let mut f = Fixture::new()?;
        status(&f.admin("POST", "sys/policies/acl/compose-reader", json!({
            "policy":"path \"wrap-kv/data/preserved\" { capabilities = [\"read\"] } path \"auth/token/lookup-self\" { capabilities = [\"read\"] }",
        }), None)?, 204);
        let actor = f.token("compose-reader", 0)?;
        let (method, path) = match kind {
            Kind::Kv => ("GET", "wrap-kv/data/preserved"),
            Kind::Auth => ("GET", "auth/token/lookup-self"),
        };
        let (response, _, _) = audited(
            &mut f,
            kind,
            &actor,
            method,
            path,
            &json!({}),
            120,
            Duration::from_secs(15),
        )?;
        let held = suspend(&mut f, kind)?;
        status(
            &f.admin(
                "POST",
                "auth/token/revoke",
                json!({"token":actor.as_str()}),
                None,
            )?,
            204,
        );
        restore(&mut f, held);
        let response = finish(&mut f, kind, response)?;
        // Ordinary KV performs its original final actor check before the
        // output capsule (403). Native Auth first checks its exact immutable
        // pre-audit root checkpoint (503). Neither branch may release output.
        status(
            &response,
            match kind {
                Kind::Kv => 403,
                Kind::Auth => 503,
            },
        );
        no_output(&response);
        let mut f = f.restart()?;
        status(
            &f.actor(&actor, "GET", "auth/token/lookup-self", json!({}), None)?,
            403,
        );
    }
    Ok(())
}

#[test]
fn native_wrapping_response_real_audit_write_failure_releases_no_inner_or_outer_secret()
-> TestResult {
    for kind in [Kind::Kv, Kind::Auth] {
        let mut f = Fixture::new()?;
        let admin = Zeroizing::new(f.admin.as_str().to_owned());
        let (method, path, body) = selection(kind);
        let (response, clock, _, until) = dispatched(
            &mut f,
            kind,
            &admin,
            method,
            path,
            &body,
            120,
            Duration::from_secs(15),
        )?;
        let wrapper = Zeroizing::new(text(&response, "/wrap_info/token")?);
        let readonly = File::open(f.files.path.join("audit.jsonl"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let a = f.service.audit.metadata()?;
            let b = readonly.metadata()?;
            assert_eq!((a.dev(), a.ino()), (b.dev(), b.ino()));
        }
        let original = std::mem::replace(&mut f.service.audit, readonly);
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(until);
        let response = f.service.audit_completed_response_with_receipt(
            "native-response-composition-real-audit",
            f.now,
            Some(clock),
            response,
            || {},
        );
        status(&response, 503);
        assert!(f.service.audit_failed);
        let response = finish(&mut f, kind, response)?;
        status(&response, 503);
        no_output(&response);
        f.service.audit = original;
        let mut f = f.restart()?;
        status(&f.actor(&wrapper, "POST", UNWRAP, json!({}), None)?, 200);
        status(&f.actor(&wrapper, "POST", UNWRAP, json!({}), None)?, 400);
    }
    Ok(())
}

struct ReplacedJournal {
    digest: [u8; 32],
    before: RecordStateRootV6,
}
thread_local! {
    static COMPOSITION_JOURNAL: RefCell<Option<Result<Option<ReplacedJournal>, String>>> = const { RefCell::new(None) };
}
pub(super) fn before_publication(service: &mut Service) {
    COMPOSITION_JOURNAL.with(|slot| {
        if !matches!(*slot.borrow(), Some(Ok(None))) {
            return;
        }
        let actual = (|| -> Result<Option<ReplacedJournal>, String> {
            let path = service.data_dir.join("journal.hbj");
            let saved = service.data_dir.join("composition-original-journal.hbj");
            let original = Zeroizing::new(fs::read(&path).map_err(|e| e.to_string())?);
            let before = service.native_root.clone().ok_or("source root absent")?;
            fs::rename(&path, &saved).map_err(|e| e.to_string())?;
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .map_err(|e| e.to_string())?
                .sync_all()
                .map_err(|e| e.to_string())?;
            Ok(Some(ReplacedJournal {
                digest: crypto::digest(&original),
                before,
            }))
        })();
        *slot.borrow_mut() = Some(actual);
    });
}
struct CompositionJournalFault;
impl Drop for CompositionJournalFault {
    fn drop(&mut self) {
        COMPOSITION_JOURNAL.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

#[test]
fn native_wrapping_response_actual_journal_owner_loss_does_not_publish_half_transaction()
-> TestResult {
    for kind in [Kind::Kv, Kind::Auth] {
        let mut f = Fixture::new()?;
        let original_tokens = accessors(&mut f)?;
        let _fault = CompositionJournalFault;
        COMPOSITION_JOURNAL.with(|slot| *slot.borrow_mut() = Some(Ok(None)));
        let (path, body) = match kind {
            Kind::Kv => (
                "wrap-kv/data/journal-rejected",
                json!({"options":{"cas":0},"data":{"value":PAYLOAD}}),
            ),
            Kind::Auth => (
                "auth/token/create",
                json!({"policies":["default"],"ttl":"300s"}),
            ),
        };
        let response = f.admin("POST", path, body, Some(120))?;
        status(&response, 503);
        no_output(&response);
        let observed = COMPOSITION_JOURNAL
            .with(|slot| slot.borrow_mut().take())
            .ok_or("fault observation absent")?
            .map_err(std::io::Error::other)?
            .ok_or("fault was not reached")?;
        let data = f.service.data_dir.clone();
        drop(f.service);
        let saved = Zeroizing::new(fs::read(data.join("composition-original-journal.hbj"))?);
        assert!(crypto::digest(&saved) == observed.digest);
        fs::remove_file(data.join("journal.hbj"))?;
        fs::rename(
            data.join("composition-original-journal.hbj"),
            data.join("journal.hbj"),
        )?;
        f.service = Fixture::open(&f.files)?;
        status(
            &call(
                &mut f.service,
                &mut f.now,
                "",
                "POST",
                "sys/unseal",
                "",
                json!({"key":f.key.as_str()}),
                None,
            )?,
            200,
        );
        f.assert_native()?;
        assert!(
            !f.service
                .state
                .as_ref()
                .ok_or("state")?
                .auth
                .has_live_wrappers()
        );
        f.assert_auth_only(&observed.before)?;
        status(
            &f.admin("GET", "wrap-kv/data/journal-rejected", json!({}), None)?,
            404,
        );
        assert!(original_tokens == accessors(&mut f)?);
        f.assert_kv()?;
    }
    Ok(())
}
