//! These tests drive real durable Service state and split-phase completion.
//! Packet authentication is exercised separately by radius_renewal_live.py.
use super::online_auth::OnlineAuthObservation;
use super::tests::{Root, bootstrap, call};
use super::*;
use crate::auth::{ProviderRenewalObservation, RadiusLoginObservation, RadiusRenewalObservation};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn enroll(service: &mut Service) -> TestResult {
    service.install_outbound_endpoints(vec![crate::outbound::EndpointConfig {
        origin: "radius://radius.example.test:1812".into(),
        address: "127.0.0.1:1812".parse()?,
        server_name: "radius.example.test".into(),
        ca_pem: String::new(),
        path_prefix: "/".into(),
        shared_secret: "synthetic-shared-secret".into(),
    }])?;
    Ok(())
}

fn pending(
    service: &mut Service,
    path: &str,
    token: &str,
    body: Value,
    now: u64,
) -> TestResult<Box<PendingExternalRequest>> {
    pending_with_wrapping(service, path, token, body, now, None)
}

fn pending_with_wrapping(
    service: &mut Service,
    path: &str,
    token: &str,
    body: Value,
    now: u64,
    wrap_ttl_seconds: Option<u64>,
) -> TestResult<Box<PendingExternalRequest>> {
    match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path,
        namespace: "",
        token,
        body,
        now,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds,
        client_certificates: None,
    }) {
        RequestExecution::External(plan) => Ok(plan),
        RequestExecution::Complete(_) => Err("expected staged provider request".into()),
    }
}

fn accepted(service: &mut Service, plan: PendingExternalRequest) -> Response {
    service.finish_external_request(
        plan,
        ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::ProviderRenewal(
            ProviderRenewalObservation::Radius(RadiusRenewalObservation),
        ))),
    )
}

fn fixture(root: &Root) -> TestResult<(Service, String, String, String, String)> {
    let mut service = root.service()?;
    enroll(&mut service)?;
    let (key, root_token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/radius",
            &root_token,
            json!({"type":"radius"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/radius/config",
            &root_token,
            json!({"url":"radius://radius.example.test:1812","token_ttl":120,"token_max_ttl":600})
        )
        .status,
        204
    );
    let login = pending(
        &mut service,
        "auth/radius/login",
        "",
        json!({"username":"alice","password":"synthetic-radius-password"}),
        100,
    )?;
    let response = service.finish_external_request(
        *login,
        ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::Radius(RadiusLoginObservation))),
    );
    assert_eq!(response.status, 200);
    let token = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("missing token")?
        .to_owned();
    let entity = response.body["auth"]["entity_id"]
        .as_str()
        .ok_or("missing entity")?
        .to_owned();
    assert!(!entity.is_empty());
    Ok((service, key, root_token, token, entity))
}

#[test]
fn radius_renewal_is_durable_across_reopen_and_failed_provider_never_extends() -> TestResult {
    let root = Root::new();
    let (mut service, key, _, token, _) = fixture(&root)?;
    let before = service.state_digest;
    let request = pending(
        &mut service,
        "auth/token/renew-self",
        &token,
        json!({"increment":300}),
        110,
    )?;
    let rejected = service.finish_external_request(
        *request,
        ExternalEffectResult::OnlineAuth(Err(Response::error(
            400,
            "access denied by the authentication server",
        ))),
    );
    assert_eq!(rejected.status, 400);
    assert_eq!(service.state_digest, before);
    drop(service);
    let mut service = root.service()?;
    enroll(&mut service)?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let request = pending(
        &mut service,
        "auth/token/renew-self",
        &token,
        json!({"increment":300}),
        120,
    )?;
    let renewed = accepted(&mut service, *request);
    assert_eq!(renewed.status, 200);
    assert_eq!(renewed.body["auth"]["lease_duration"], 300);
    assert_ne!(service.state_digest, before);
    drop(service);
    let mut reopened = root.service()?;
    enroll(&mut reopened)?;
    assert_eq!(
        call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let info = reopened.handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 130);
    assert_eq!(info.status, 200);
    assert!(
        info.body["data"]["ttl"]
            .as_u64()
            .is_some_and(|ttl| ttl > 200)
    );
    let mut paths = vec![root.path.clone()];
    while let Some(path) = paths.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                paths.push(entry?.path());
            }
        } else {
            let bytes = fs::read(path)?;
            assert!(
                !bytes
                    .windows(b"synthetic-radius-password".len())
                    .any(|chunk| chunk == b"synthetic-radius-password")
            );
        }
    }
    Ok(())
}

#[test]
fn radius_renewal_rechecks_identity_config_and_revocation_after_provider() -> TestResult {
    for mutation in [
        "identity",
        "config",
        "target",
        "actor",
        "sealed",
        "reactivated",
        "renewed",
    ] {
        let root = Root::new();
        let (mut service, key, root_token, token, entity) = fixture(&root)?;
        let request = pending(
            &mut service,
            "auth/token/renew",
            &root_token,
            json!({"token":token,"increment":300}),
            110,
        )?;
        match mutation {
            "identity" => assert_eq!(call(&mut service, "POST", &format!("identity/entity/id/{entity}"),
                &root_token, json!({"disabled":true})).status, 204),
            "config" => assert_eq!(call(&mut service, "POST", "auth/radius/config", &root_token,
                json!({"url":"radius://radius.example.test:1812","token_ttl":60,"token_max_ttl":600})).status, 204),
            "target" => assert_eq!(call(&mut service, "POST", "auth/token/revoke", &root_token,
                json!({"token":token})).status, 204),
            "actor" => assert_eq!(call(&mut service, "POST", "auth/token/revoke-self", &root_token, json!({})).status, 204),
            "sealed" => assert_eq!(call(&mut service, "POST", "sys/seal", &root_token, json!({})).status, 204),
            "reactivated" => {
                assert_eq!(call(&mut service, "POST", "sys/seal", &root_token, json!({})).status, 204);
                enroll(&mut service)?;
                assert_eq!(call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status, 200);
            }
            "renewed" => {
                let other = pending(&mut service, "auth/token/renew-self", &token, json!({"increment":200}), 110)?;
                assert_eq!(accepted(&mut service, *other).status, 200);
            }
            _ => return Err("unknown mutation".into()),
        }
        let before = service.state_digest;
        let response = accepted(&mut service, *request);
        assert!(response.status >= 400, "{mutation}");
        assert!(response.body.get("auth").is_none(), "{mutation}");
        assert_eq!(service.state_digest, before, "{mutation}");
    }
    Ok(())
}

#[test]
fn radius_renewal_schema_fence_rejects_downgrade_and_token_api_provenance_is_distinct() -> TestResult
{
    let root = Root::new();
    let (service, _, _, _, _) = fixture(&root)?;
    let state = service.state.as_ref().ok_or("missing state")?;
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    let mut downgraded = state.clone();
    downgraded.schema = 15;
    assert!(downgraded.validate_format().is_err());
    let (plain_auth, root_token) = AuthState::bootstrap(100)?;
    downgraded.auth = plain_auth.into();
    assert!(downgraded.validate_format().is_ok());
    let actor = downgraded.auth.authenticate(&root_token, 100)?;
    downgraded
        .auth
        .handle(
            Some(&actor),
            "",
            "POST",
            "auth/token/create",
            &json!({"policies":["default"]}),
            100,
        )?
        .ok_or("missing route")?;
    assert!(downgraded.validate_format().is_err());
    downgraded.schema = 16;
    assert!(downgraded.validate_format().is_ok());
    Ok(())
}

#[test]
fn radius_renewal_echoes_only_request_supplied_bearers_after_commit() -> TestResult {
    let root = Root::new();
    let (mut service, _, root_token, token, _) = fixture(&root)?;
    let info = call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &token,
        json!({}),
    );
    let accessor = info.body["data"]["accessor"]
        .as_str()
        .ok_or("missing accessor")?
        .to_owned();
    for (path, bearer, body) in [
        (
            "auth/token/renew-self",
            token.as_str(),
            json!({"increment":300}),
        ),
        (
            "auth/token/renew",
            root_token.as_str(),
            json!({"token":token,"increment":301}),
        ),
        (
            "auth/token/renew-accessor",
            root_token.as_str(),
            json!({"accessor":accessor,"increment":302}),
        ),
    ] {
        let request = pending(&mut service, path, bearer, body, 110)?;
        let response = accepted(&mut service, *request);
        assert_eq!(response.status, 200);
        if path.ends_with("accessor") {
            assert!(response.body["auth"].get("client_token").is_none());
        } else {
            assert_eq!(response.body["auth"]["client_token"], token);
        }
    }
    Ok(())
}

#[test]
fn radius_renewal_and_response_wrapper_commit_together_without_exposing_bearer() -> TestResult {
    let root = Root::new();
    let (mut service, _, _, token, _) = fixture(&root)?;
    let request = pending_with_wrapping(
        &mut service,
        "auth/token/renew-self",
        &token,
        json!({"increment":300}),
        110,
        Some(60),
    )?;
    let response = accepted(&mut service, *request);
    assert_eq!(response.status, 200);
    assert!(response.body["auth"].is_null());
    assert!(!response.body.to_string().contains(&token));
    assert_eq!(
        response.body["wrap_info"]["creation_path"],
        "auth/token/renew-self"
    );
    let wrapper = response.body["wrap_info"]["token"]
        .as_str()
        .ok_or("missing wrapper")?;
    let unwrapped = service.handle_at("POST", "sys/wrapping/unwrap", "", wrapper, json!({}), 112);
    assert_eq!(unwrapped.status, 200);
    assert_eq!(unwrapped.body["auth"]["client_token"], token);
    assert_eq!(unwrapped.body["auth"]["lease_duration"], 300);
    assert_eq!(
        service
            .handle_at("POST", "sys/wrapping/unwrap", "", wrapper, json!({}), 112)
            .status,
        400
    );
    Ok(())
}

#[test]
fn radius_wrapping_or_commit_failure_never_publishes_partial_renewal() -> TestResult {
    for failure in ["wrappers", "commit"] {
        let root = Root::new();
        let (mut service, _, _, token, _) = fixture(&root)?;
        if failure == "wrappers" {
            let mut state = service.state.clone().ok_or("missing state")?;
            for _ in 0..256 {
                state.auth.wrap_response(
                    "",
                    "synthetic/wrapped",
                    3600,
                    &json!({"synthetic":true}),
                    100,
                )?;
            }
            service
                .commit_state(&state)
                .map_err(|_| "wrapper fixture commit failed")?;
            service.state = Some(state);
        }
        let request = pending_with_wrapping(
            &mut service,
            "auth/token/renew-self",
            &token,
            json!({"increment":300}),
            110,
            Some(60),
        )?;
        let before = service.state_digest;
        if failure == "commit" {
            service.state_capacity = 1;
        }
        let response = accepted(&mut service, *request);
        assert_eq!(response.status, if failure == "commit" { 507 } else { 503 });
        assert!(response.body.get("auth").is_none());
        assert!(response.body.get("wrap_info").is_none());
        assert_eq!(service.state_digest, before);
    }
    Ok(())
}

#[test]
fn radius_periodic_renewal_all_entries_keep_provider_checks_wrapping_and_issue_snapshot()
-> TestResult {
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let root = Root::new();
        let (mut service, key, admin, _, _) = fixture(&root)?;
        assert_eq!(
            service
                .handle_at(
                    "POST",
                    "auth/radius/config",
                    "",
                    &admin,
                    json!({"token_period":30,"token_explicit_max_ttl":120}),
                    105
                )
                .status,
            204
        );
        let login = pending(
            &mut service,
            "auth/radius/login",
            "",
            json!({"username":"alice","password":"synthetic-radius-password"}),
            110,
        )?;
        let response = service.finish_external_request(
            *login,
            ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::Radius(
                RadiusLoginObservation,
            ))),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["auth"]["lease_duration"], 30);
        let token = response.body["auth"]["client_token"]
            .as_str()
            .ok_or("periodic token")?
            .to_owned();
        let accessor = response.body["auth"]["accessor"]
            .as_str()
            .ok_or("accessor")?
            .to_owned();
        let body = match operation {
            "renew" => json!({"token":token,"increment":300}),
            "renew-accessor" => json!({"accessor":accessor,"increment":300}),
            _ => json!({"increment":300}),
        };
        let path = format!("auth/token/{operation}");
        let actor = if operation == "renew-self" {
            &token
        } else {
            &admin
        };
        let plan = pending_with_wrapping(&mut service, &path, actor, body.clone(), 120, Some(60))?;
        let response = accepted(&mut service, *plan);
        assert_eq!(response.status, 200);
        assert!(response.body["auth"].is_null());
        assert!(!response.body.to_string().contains(&token));
        let wrapper = response.body["wrap_info"]["token"]
            .as_str()
            .ok_or("wrapper")?
            .to_owned();
        let response =
            service.handle_at("POST", "sys/wrapping/unwrap", "", &wrapper, json!({}), 121);
        assert_eq!(response.status, 200);
        assert_eq!(response.body["auth"]["lease_duration"], 30);
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
        let before = service
            .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 122)
            .body["data"]["expire_time_unix"]
            .clone();
        let plan = pending_with_wrapping(&mut service, &path, actor, body.clone(), 122, Some(60))?;
        let before_digest = service.state_digest;
        let denied = service.finish_external_request(
            *plan,
            ExternalEffectResult::OnlineAuth(Err(Response::error(
                400,
                "access denied by provider",
            ))),
        );
        assert_eq!(denied.status, 400);
        assert!(denied.body.get("auth").is_none());
        assert!(denied.body.get("wrap_info").is_none());
        assert_eq!(service.state_digest, before_digest);
        assert_eq!(
            service
                .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 123)
                .body["data"]["expire_time_unix"],
            before
        );
        drop(service);
        let mut service = root.service()?;
        enroll(&mut service)?;
        assert_eq!(
            service
                .handle_at("POST", "sys/unseal", "", "", json!({"key":key}), 124)
                .status,
            200
        );
        assert_eq!(
            service
                .handle_at(
                    "POST",
                    "auth/radius/config",
                    "",
                    &admin,
                    json!({"token_period":45,"token_explicit_max_ttl":1}),
                    125
                )
                .status,
            204
        );
        let plan = pending(&mut service, &path, actor, body, 126)?;
        let response = accepted(&mut service, *plan);
        assert_eq!(response.status, 200);
        assert_eq!(response.body["auth"]["lease_duration"], 45);
        let info = service.handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 127);
        assert_eq!(info.body["data"]["period"], 30);
        assert_eq!(info.body["data"]["explicit_max_ttl"], 120);
    }
    Ok(())
}

#[test]
fn radius_periodic_provider_success_cannot_publish_after_config_or_identity_changes() -> TestResult
{
    for mutation in ["period", "explicit", "identity"] {
        let root = Root::new();
        let (mut service, _, admin, token, entity) = fixture(&root)?;
        assert_eq!(
            service
                .handle_at(
                    "POST",
                    "auth/radius/config",
                    "",
                    &admin,
                    json!({"token_period":30}),
                    105
                )
                .status,
            204
        );
        let before = service
            .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 110)
            .body["data"]["expire_time_unix"]
            .clone();
        let plan = pending_with_wrapping(
            &mut service,
            "auth/token/renew-self",
            &token,
            json!({"increment":300}),
            110,
            Some(60),
        )?;
        let update = match mutation {
            "period" => service.handle_at(
                "POST",
                "auth/radius/config",
                "",
                &admin,
                json!({"token_period":45}),
                111,
            ),
            "explicit" => service.handle_at(
                "POST",
                "auth/radius/config",
                "",
                &admin,
                json!({"token_explicit_max_ttl":90}),
                111,
            ),
            _ => service.handle_at(
                "POST",
                &format!("identity/entity/id/{entity}"),
                "",
                &admin,
                json!({"disabled":true}),
                111,
            ),
        };
        assert_eq!(update.status, 204);
        let before_digest = service.state_digest;
        let response = accepted(&mut service, *plan);
        assert_eq!(
            response.status,
            if mutation == "identity" { 403 } else { 409 }
        );
        assert!(response.body.get("auth").is_none());
        assert!(response.body.get("wrap_info").is_none());
        assert_eq!(service.state_digest, before_digest);
        if mutation == "identity" {
            assert_eq!(
                service
                    .handle_at(
                        "POST",
                        &format!("identity/entity/id/{entity}"),
                        "",
                        &admin,
                        json!({"disabled":false}),
                        112
                    )
                    .status,
                204
            );
        }
        assert_eq!(
            service
                .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 113)
                .body["data"]["expire_time_unix"],
            before
        );
    }
    Ok(())
}

#[test]
fn radius_schema_twenty_two_fences_new_parameters_but_preserves_true_legacy_shape() -> TestResult {
    let root = Root::new();
    let (mut service, _, admin, _, _) = fixture(&root)?;
    let mut state = service.state.clone().ok_or("state")?;
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    state.schema = 21;
    assert!(
        state.validate_format().is_err(),
        "new empty configured policy list requires schema 22"
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                "auth/radius/config",
                "",
                &admin,
                json!({"token_policies":["default"]}),
                105
            )
            .status,
        204
    );
    state = service.state.clone().ok_or("state")?;
    state.schema = 21;
    assert!(state.validate_format().is_ok());
    let encoded = serde_json::to_value(&state.auth)?;
    for field in ["token_period", "token_explicit_max_ttl"] {
        assert!(
            encoded["radius_mounts"][""]["radius"].get(field).is_none(),
            "zero fields must preserve historical serialized shape"
        );
        let mut changed = state.clone();
        let actor = changed.auth.authenticate(&admin, 105)?;
        let mut body = json!({});
        body[field] = json!(30);
        changed
            .auth
            .handle(Some(&actor), "", "POST", "auth/radius/config", &body, 105)?;
        assert!(changed.validate_format().is_err());
        changed.schema = CURRENT_STATE_SCHEMA;
        assert!(changed.validate_format().is_ok());
    }
    assert_eq!(
        service
            .handle_at(
                "POST",
                "auth/radius/config",
                "",
                &admin,
                json!({"token_period":30}),
                106
            )
            .status,
        204
    );
    let login = pending(
        &mut service,
        "auth/radius/login",
        "",
        json!({"username":"alice","password":"synthetic-radius-password"}),
        107,
    )?;
    let response = service.finish_external_request(
        *login,
        ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::Radius(RadiusLoginObservation))),
    );
    assert_eq!(response.status, 200);
    assert_eq!(
        service
            .handle_at(
                "POST",
                "auth/radius/config",
                "",
                &admin,
                json!({"token_period":0}),
                108
            )
            .status,
        204
    );
    let mut state = service.state.clone().ok_or("state")?;
    state.schema = 21;
    assert!(
        state.validate_format().is_err(),
        "issued periodic provenance must remain fenced after config resets"
    );
    state.schema = CURRENT_STATE_SCHEMA;
    assert!(state.validate_format().is_ok());
    Ok(())
}
