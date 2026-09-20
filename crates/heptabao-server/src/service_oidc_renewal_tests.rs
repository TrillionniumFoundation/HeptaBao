//! Durable code consumption, native role renewal and atomic wrapped responses.
//! Provider observations are injected here; the real OIDC issuer fixture tests
//! authorization-code exchange and signed ID tokens over verified TLS.
use super::online_auth::OnlineAuthObservation;
use super::tests::{Root, bootstrap, call};
use super::*;
use crate::auth::OidcLoginObservation;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn prepared(root: &Root) -> TestResult<(Service, String, String, Value)> {
    let mut service = root.service()?;
    let (key, _) = bootstrap(&mut service)?;
    let (auth, admin, body) = AuthState::oidc_test_fixture();
    let mut state = service.state.clone().ok_or("state")?;
    state.auth = auth.into();
    state.schema = 20;
    state
        .validate_format()
        .map_err(|_| "legacy pending state")?;
    service.commit_state(&state).map_err(|_| "pending commit")?;
    service.state = Some(state);
    Ok((service, key, admin, body))
}
fn pending(
    service: &mut Service,
    body: Value,
    now: u64,
) -> TestResult<Box<PendingExternalRequest>> {
    match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path: "auth/browser/oidc/callback",
        namespace: "",
        token: "",
        body,
        now,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        client_certificates: None,
    }) {
        RequestExecution::External(plan) => Ok(plan),
        RequestExecution::Complete(response) => {
            Err(format!("expected callback effect, got {}", response.status).into())
        }
    }
}
fn accepted(service: &mut Service, plan: PendingExternalRequest, now: u64) -> Response {
    service.finish_external_request(
        plan,
        ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::OidcCallback(
            OidcLoginObservation::observed("alice", now),
        ))),
    )
}
fn sessions(service: &Service) -> TestResult<usize> {
    let state = serde_json::to_value(&service.state.as_ref().ok_or("state")?.auth)?;
    Ok(state["oidc_mounts"][""]["browser"]["sessions"]
        .as_object()
        .ok_or("sessions")?
        .len())
}
fn fixture(root: &Root) -> TestResult<(Service, String, String, String)> {
    let (mut service, key, admin, body) = prepared(root)?;
    let plan = pending(&mut service, body.clone(), 110)?;
    assert_eq!(
        sessions(&service)?,
        0,
        "consumption must precede external exchange"
    );
    let response = accepted(&mut service, *plan, 110);
    assert_eq!(response.status, 200);
    assert_eq!(response.body["auth"]["lease_duration"], 300);
    assert_eq!(response.body["auth"]["renewable"], true);
    let token = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned();
    assert_eq!(
        service
            .handle_at("POST", "auth/browser/oidc/callback", "", "", body, 111)
            .status,
        403
    );
    Ok((service, key, admin, token))
}
fn renew(
    service: &mut Service,
    path: &str,
    actor: &str,
    body: Value,
    now: u64,
) -> TestResult<Response> {
    match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path,
        namespace: "",
        token: actor,
        body,
        now,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: Some(60),
        client_certificates: None,
    }) {
        RequestExecution::Complete(response) => Ok(response),
        RequestExecution::External(_) => Err("OIDC service renewal must not contact IdP".into()),
    }
}

#[test]
fn oidc_renewal_all_routes_publish_wrapping_echo_and_ttl_across_restart() -> TestResult {
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let root = Root::new();
        let (mut service, key, admin, token) = fixture(&root)?;
        let info = service.handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 112);
        let accessor = info.body["data"]["accessor"].as_str().ok_or("accessor")?;
        let body = match operation {
            "renew" => json!({"token":token,"increment":600}),
            "renew-accessor" => json!({"accessor":accessor,"increment":600}),
            _ => json!({"increment":600}),
        };
        let path = format!("auth/token/{operation}");
        let actor = if operation == "renew-self" {
            &token
        } else {
            &admin
        };
        let response = renew(&mut service, &path, actor, body.clone(), 120)?;
        assert_eq!(response.status, 200);
        assert!(response.body["auth"].is_null());
        assert!(!response.body.to_string().contains(&token));
        let wrapper = response.body["wrap_info"]["token"]
            .as_str()
            .ok_or("wrapper")?
            .to_owned();
        drop(service);
        let mut service = root.service()?;
        assert_eq!(
            service
                .handle_at("POST", "sys/unseal", "", "", json!({"key":key}), 121)
                .status,
            200
        );
        let response =
            service.handle_at("POST", "sys/wrapping/unwrap", "", &wrapper, json!({}), 121);
        assert_eq!(response.status, 200);
        assert_eq!(response.body["auth"]["lease_duration"], 600);
        if operation == "renew-accessor" {
            assert!(response.body["auth"].get("client_token").is_none());
        } else {
            assert_eq!(response.body["auth"]["client_token"], token);
        }
        assert!(
            service
                .handle_at("POST", "sys/wrapping/unwrap", "", &wrapper, json!({}), 121)
                .status
                >= 400
        );
        assert_eq!(
            service
                .handle_at(
                    "DELETE",
                    "auth/browser/role/app",
                    "",
                    &admin,
                    json!({}),
                    122
                )
                .status,
            204
        );
        let response = renew(&mut service, &path, actor, body, 122)?;
        assert_eq!(response.status, 500);
        assert!(response.body.get("wrap_info").is_none());
        assert_eq!(
            service
                .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 122)
                .body["data"]["expire_time_unix"],
            720
        );
        assert!(
            service
                .state
                .as_ref()
                .ok_or("state")?
                .validate_format()
                .is_ok()
        );
    }
    Ok(())
}

#[test]
fn oidc_renewal_live_identity_and_capacity_denials_do_not_publish_extension() -> TestResult {
    let root = Root::new();
    let (mut service, _, admin, token) = fixture(&root)?;
    let info = service.handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 112);
    let entity = info.body["data"]["entity_id"]
        .as_str()
        .ok_or("entity")?
        .to_owned();
    let expiry = info.body["data"]["expire_time_unix"].clone();
    service.state_capacity = 1;
    assert_eq!(
        renew(
            &mut service,
            "auth/token/renew-self",
            &token,
            json!({"increment":600}),
            120
        )?
        .status,
        507
    );
    service.state_capacity = MAX_STATE_BYTES;
    assert_eq!(
        service
            .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 120)
            .body["data"]["expire_time_unix"],
        expiry
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                &format!("identity/entity/id/{entity}"),
                "",
                &admin,
                json!({"disabled":true}),
                121
            )
            .status,
        204
    );
    for (path, actor, body) in [
        (
            "auth/token/renew-self",
            token.as_str(),
            json!({"increment":600}),
        ),
        (
            "auth/token/renew",
            admin.as_str(),
            json!({"token":token,"increment":600}),
        ),
    ] {
        let response = renew(&mut service, path, actor, body, 122)?;
        assert_eq!(response.status, 403);
        assert!(response.body.get("wrap_info").is_none());
    }
    assert_eq!(
        service
            .handle_at(
                "POST",
                &format!("identity/entity/id/{entity}"),
                "",
                &admin,
                json!({"disabled":false}),
                123
            )
            .status,
        204
    );
    assert_eq!(
        service
            .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 123)
            .body["data"]["expire_time_unix"],
        expiry
    );
    Ok(())
}

#[test]
fn oidc_consumed_callback_never_crosses_activation_or_failed_publication() -> TestResult {
    for failure in ["activation", "capacity"] {
        let root = Root::new();
        let (mut service, key, admin, body) = prepared(&root)?;
        let plan = pending(&mut service, body.clone(), 110)?;
        assert_eq!(sessions(&service)?, 0);
        if failure == "activation" {
            assert_eq!(
                call(&mut service, "POST", "sys/seal", &admin, json!({})).status,
                204
            );
            assert_eq!(
                call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
                200
            );
        } else {
            service.state_capacity = 1;
        }
        let before = service.state_digest;
        let response = accepted(&mut service, *plan, 111);
        assert_eq!(response.status, 503);
        assert_eq!(response.body["oidc_session_consumed"], true);
        assert_eq!(response.body["retry_allowed"], false);
        assert!(response.body.get("auth").is_none());
        assert_eq!(service.state_digest, before);
        service.state_capacity = MAX_STATE_BYTES;
        drop(service);
        let mut service = root.service()?;
        assert_eq!(
            service
                .handle_at("POST", "sys/unseal", "", "", json!({"key":key}), 112)
                .status,
            200
        );
        assert_eq!(sessions(&service)?, 0);
        assert_eq!(
            service
                .handle_at("POST", "auth/browser/oidc/callback", "", "", body, 113)
                .status,
            403
        );
    }
    Ok(())
}

#[test]
fn oidc_schema_twenty_one_keeps_old_pending_session_and_old_token_authority() -> TestResult {
    let root = Root::new();
    let (mut service, key, admin, body) = prepared(&root)?;
    assert_eq!(service.state.as_ref().ok_or("state")?.schema, 20);
    drop(service);
    service = root.service()?;
    assert_eq!(
        service
            .handle_at("POST", "sys/unseal", "", "", json!({"key":key}), 110)
            .status,
        200
    );
    let plan = pending(&mut service, body, 111)?;
    let response = accepted(&mut service, *plan, 111);
    assert_eq!(response.status, 200);
    let token = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned();
    let mut state = service.state.clone().ok_or("state")?;
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    state.schema = 20;
    assert!(state.validate_format().is_err());
    let mut auth = serde_json::to_value(&state.auth)?;
    for entry in auth["tokens"].as_object_mut().ok_or("tokens")?.values_mut() {
        if entry["auth_provenance"]["kind"] == "oidc" {
            entry
                .as_object_mut()
                .ok_or("token")?
                .remove("auth_provenance");
            entry["renewable"] = json!(false);
            entry["max_expires_at"] = entry["expires_at"].clone();
        }
    }
    state.auth = serde_json::from_value::<AuthState>(auth)?.into();
    assert!(state.validate_format().is_ok());
    let mut actor = state.auth.authenticate(&token, 112)?;
    Service::bind_identity_principal(&state, &mut actor, "").map_err(|_| "identity")?;
    assert_eq!(
        state
            .auth
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/token/renew-self",
                &json!({}),
                112
            )
            .err()
            .ok_or("legacy renewed")?
            .status,
        400
    );
    assert!(state.auth.authenticate(&token, 112).is_ok());
    let root_actor = state.auth.authenticate(&admin, 112)?;
    let mut policies_only = state.clone();
    policies_only.auth.handle(
        Some(&root_actor),
        "",
        "POST",
        "auth/browser/role/app",
        &json!({"token_policies":[]}),
        112,
    )?;
    assert!(
        policies_only.validate_format().is_err(),
        "empty configured policies require schema 21 even with legacy positive TTL"
    );
    policies_only.schema = CURRENT_STATE_SCHEMA;
    assert!(policies_only.validate_format().is_ok());
    state.auth.handle(
        Some(&root_actor),
        "",
        "POST",
        "auth/browser/role/app",
        &json!({"token_max_ttl":600}),
        112,
    )?;
    assert!(
        state.validate_format().is_err(),
        "new OIDC role limits require schema 21 even without provenance"
    );
    state.schema = CURRENT_STATE_SCHEMA;
    assert!(state.validate_format().is_ok());
    Ok(())
}
