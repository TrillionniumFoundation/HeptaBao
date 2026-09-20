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
        shared_secret: String::new(),
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
        origin_peer: None,
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
            json!({"host":"radius.example.test","secret":"synthetic-shared-secret","token_ttl":120,"token_max_ttl":600})
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
fn native_radius_partial_profile_schema_restart_and_unenrolled_config() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
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
            "auth/radius/users/alice",
            &root_token,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "auth/radius/users/alice",
            &root_token,
            json!({})
        )
        .status,
        204
    );
    let state = service.state.as_ref().ok_or("missing state")?;
    assert!(state.auth.has_native_radius_state());
    let mut downgraded = state.clone();
    downgraded.schema = 24;
    assert!(
        downgraded.validate_format().is_ok(),
        "an empty native mapping entry has no schema-25 semantics"
    );
    downgraded.schema = 23;
    assert!(downgraded.validate_format().is_err());
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/radius/config",
            &root_token,
            json!({"url":"radius://radius.example.test:1812"})
        )
        .status,
        409
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/radius/config",
            &root_token,
            json!({"host":"unenrolled.example.test","port":0,"secret":"synthetic-shared-secret"})
        )
        .status,
        204
    );
    let state = service.state.as_ref().ok_or("missing configured state")?;
    let mut downgraded = state.clone();
    downgraded.schema = 25;
    assert!(
        downgraded.validate_format().is_err(),
        "API-authorized targets need schema 26"
    );
    downgraded.schema = 24;
    assert!(
        downgraded.validate_format().is_err(),
        "new policy-presence semantics need schema 25"
    );
    let request = pending(
        &mut service,
        "auth/radius/login/alice",
        "",
        json!({"password":"synthetic-password"}),
        110,
    )?;
    let before = service.state_digest;
    let result = request.execute();
    let failed = service.finish_external_request(*request, result);
    assert_eq!(failed.status, 400);
    assert_eq!(service.state_digest, before);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/radius/config",
            &root_token,
            json!({})
        )
        .body["data"]["port"],
        0
    );
    Ok(())
}

#[test]
fn native_radius_service_three_renewals_echo_wrapping_and_reopen() -> TestResult {
    let root = Root::new();
    let (mut service, key, root_token, token, entity) = fixture(&root)?;
    let config = call(
        &mut service,
        "GET",
        "auth/radius/config",
        &root_token,
        json!({}),
    );
    assert!(config.body["data"].get("secret").is_none());
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
        ExternalEffectResult::OnlineAuth(Err(Response::error(400, "RADIUS provider rejected"))),
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
    let lookup = service.handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 115);
    assert_eq!(
        lookup.body["data"]["meta"],
        json!({"username":"alice","policies":""})
    );
    let accessor = lookup.body["data"]["accessor"]
        .as_str()
        .ok_or("missing accessor")?;
    for (index, (path, caller, body)) in [
        (
            "auth/token/renew-self",
            token.as_str(),
            json!({"increment":300}),
        ),
        (
            "auth/token/renew",
            root_token.as_str(),
            json!({"token":token,"increment":300}),
        ),
        (
            "auth/token/renew-accessor",
            root_token.as_str(),
            json!({"accessor":accessor,"increment":300}),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let request = pending(&mut service, path, caller, body, 120 + index as u64)?;
        let response = accepted(&mut service, *request);
        assert_eq!(response.status, 200);
        assert_eq!(
            response.body["auth"]["metadata"],
            json!({"username":"alice","policies":""})
        );
        assert_eq!(response.body["auth"]["entity_id"], entity);
        if index < 2 {
            assert_eq!(response.body["auth"]["client_token"], token);
        } else {
            assert!(response.body["auth"].get("client_token").is_none());
        }
    }
    let request = pending_with_wrapping(
        &mut service,
        "auth/token/renew-self",
        &token,
        json!({"increment":300}),
        125,
        Some(60),
    )?;
    let wrapped = accepted(&mut service, *request);
    assert_eq!(wrapped.status, 200);
    assert!(wrapped.body["auth"].is_null());
    assert!(!wrapped.body.to_string().contains(&token));
    let wrapper = wrapped.body["wrap_info"]["token"]
        .as_str()
        .ok_or("missing wrapper")?;
    let unwrapped = service.handle_at("POST", "sys/wrapping/unwrap", "", wrapper, json!({}), 126);
    assert_eq!(unwrapped.status, 200);
    assert_eq!(unwrapped.body["auth"]["client_token"], token);
    let request = pending_with_wrapping(
        &mut service,
        "auth/token/renew-self",
        &token,
        json!({"increment":400}),
        130,
        Some(60),
    )?;
    let before = service.state_digest;
    service.state_capacity = 1;
    let failed = accepted(&mut service, *request);
    assert_eq!(failed.status, 507);
    assert_eq!(service.state_digest, before);
    assert!(failed.body.get("auth").is_none());
    assert!(failed.body.get("wrap_info").is_none());
    Ok(())
}

#[test]
fn native_radius_service_login_and_renewal_mapping_absence_and_live_identity_fences() -> TestResult
{
    for mode in [
        "login-map",
        "renew-map",
        "renew-secret",
        "renew-identity",
        "renew-actor",
    ] {
        let root = Root::new();
        let (mut service, _, root_token, token, entity) = fixture(&root)?;
        let request = if mode == "login-map" {
            pending(
                &mut service,
                "auth/radius/login/ignored",
                "",
                json!({"username":"alice","password":"synthetic-password"}),
                110,
            )?
        } else {
            pending(
                &mut service,
                "auth/token/renew",
                &root_token,
                json!({"token":token,"increment":300}),
                110,
            )?
        };
        let changed = match mode {
            "login-map" | "renew-map" => call(
                &mut service,
                "POST",
                "auth/radius/users/alice",
                &root_token,
                json!({"policies":[]}),
            ),
            "renew-secret" => call(
                &mut service,
                "POST",
                "auth/radius/config",
                &root_token,
                json!({"secret":"rotated-secret"}),
            ),
            "renew-identity" => call(
                &mut service,
                "POST",
                &format!("identity/entity/id/{entity}"),
                &root_token,
                json!({"disabled":true}),
            ),
            _ => call(
                &mut service,
                "POST",
                "auth/token/revoke-self",
                &root_token,
                json!({}),
            ),
        };
        assert!(changed.status < 300);
        let before = service.state_digest;
        let failed = if mode == "login-map" {
            service.finish_external_request(
                *request,
                ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::Radius(
                    RadiusLoginObservation,
                ))),
            )
        } else {
            accepted(&mut service, *request)
        };
        assert!(failed.status >= 400, "{mode}");
        assert_eq!(service.state_digest, before, "{mode}");
    }
    Ok(())
}

fn request_from(
    service: &mut Service,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
    peer: Option<std::net::IpAddr>,
) -> Response {
    let mut request = ServiceRequest::new(method, path, "", token, body);
    request.origin_peer = peer;
    service.handle_request_at(request, 100)
}

fn login_from(service: &mut Service, peer: Option<std::net::IpAddr>) -> RequestExecution {
    service.begin_at_mode(RequestDispatch {
        method: "POST",
        path: "auth/radius/login",
        namespace: "",
        token: "",
        body: json!({"username":"alice","password":"synthetic-password"}),
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: peer,
        client_certificates: None,
    })
}

#[test]
fn native_radius_cidr_enforces_both_immutable_and_mutating_service_admission_after_restart()
-> TestResult {
    let root = Root::new();
    let (mut service, key, root_token, _, _) = fixture(&root)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/cidr-reader",
            &root_token,
            json!({"policy":"path \"secret/data/cidr\" { capabilities = [\"read\",\"update\"] }"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/cidr",
            &root_token,
            json!({"data":{"value":"synthetic"}})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/radius/config",
            &root_token,
            json!({"token_bound_cidrs":["127.0.0.1"],"token_policies":["cidr-reader"]})
        )
        .status,
        204
    );
    let mut downgraded = service.state.clone().ok_or("missing state")?;
    downgraded.schema = 26;
    assert!(
        downgraded.validate_format().is_err(),
        "configured CIDRs require schema 27"
    );
    let good = Some("127.0.0.1".parse()?);
    let wrong = Some("127.0.0.2".parse()?);
    for peer in [None, wrong] {
        let before = service
            .current_state_digest()
            .map_err(|_| "missing digest")?;
        match login_from(&mut service, peer) {
            RequestExecution::Complete(response) => assert_eq!(response.status, 403),
            RequestExecution::External(_) => return Err("denied peer reached provider".into()),
        }
        assert_eq!(
            service
                .current_state_digest()
                .map_err(|_| "missing digest")?,
            before
        );
    }
    let pending = match login_from(&mut service, good) {
        RequestExecution::External(pending) => pending,
        _ => return Err("allowed peer did not stage provider".into()),
    };
    let issued = service.finish_external_request(
        *pending,
        ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::Radius(RadiusLoginObservation))),
    );
    assert_eq!(issued.status, 200);
    let token = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("missing token")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/radius/config",
            &root_token,
            json!({"token_bound_cidrs":[]})
        )
        .status,
        204
    );
    let mut downgraded = service.state.clone().ok_or("missing state")?;
    downgraded.schema = 26;
    assert!(
        downgraded.validate_format().is_err(),
        "issued token retains schema 27 fence after config clear"
    );
    for reopened in [false, true] {
        if reopened {
            drop(service);
            service = root.service()?;
            assert_eq!(
                call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
                200
            );
        }
        for peer in [None, wrong] {
            let before = service
                .current_state_digest()
                .map_err(|_| "missing digest")?;
            assert_eq!(
                request_from(
                    &mut service,
                    "GET",
                    "secret/data/cidr",
                    &token,
                    json!({}),
                    peer
                )
                .status,
                403
            );
            assert_eq!(
                request_from(
                    &mut service,
                    "POST",
                    "secret/data/cidr",
                    &token,
                    json!({"data":{"value":"must-not-publish"}}),
                    peer
                )
                .status,
                403
            );
            assert_eq!(
                service
                    .current_state_digest()
                    .map_err(|_| "missing digest")?,
                before
            );
        }
        let before_dispatches = service.kv_read_only_dispatches;
        assert_eq!(
            request_from(
                &mut service,
                "GET",
                "secret/data/cidr",
                &token,
                json!({}),
                good
            )
            .status,
            200
        );
        assert!(service.kv_read_only_dispatches > before_dispatches);
        assert_eq!(
            request_from(
                &mut service,
                "POST",
                "secret/data/cidr",
                &token,
                json!({"data":{"value":"allowed"}}),
                good
            )
            .status,
            200
        );
        let lookup = request_from(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &token,
            json!({}),
            good,
        );
        assert_eq!(lookup.body["data"]["bound_cidrs"], json!(["127.0.0.1"]));
    }
    Ok(())
}

#[test]
fn native_radius_cidr_change_during_provider_call_prevents_issuance() -> TestResult {
    let root = Root::new();
    let (mut service, _, root_token, _, _) = fixture(&root)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/radius/config",
            &root_token,
            json!({"token_bound_cidrs":["127.0.0.1"]})
        )
        .status,
        204
    );
    // RADIUS login wrapping is rejected before a provider effect is prepared.
    // Check that boundary separately; the inflight CIDR fence below must stage
    // an actually supported, unwrapped login rather than expect a wrapped plan.
    let before_wrapped = service
        .current_state_digest()
        .map_err(|_| "missing digest")?;
    match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path: "auth/radius/login",
        namespace: "",
        token: "",
        body: json!({"username":"alice","password":"synthetic-password"}),
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: Some(60),
        origin_peer: Some("127.0.0.1".parse()?),
        client_certificates: None,
    }) {
        RequestExecution::Complete(response) => {
            assert_eq!(response.status, 400);
            assert!(response.body.get("auth").is_none());
            assert!(response.body.get("wrap_info").is_none());
        }
        RequestExecution::External(_) => {
            return Err("unsupported wrapped login reached provider".into());
        }
    }
    assert_eq!(
        service
            .current_state_digest()
            .map_err(|_| "missing digest")?,
        before_wrapped
    );
    let pending = match login_from(&mut service, Some("127.0.0.1".parse()?)) {
        RequestExecution::External(pending) => pending,
        RequestExecution::Complete(_) => return Err("allowed peer did not stage provider".into()),
    };
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/radius/config",
            &root_token,
            json!({"token_bound_cidrs":["127.0.0.2"]})
        )
        .status,
        204
    );
    let before = service
        .current_state_digest()
        .map_err(|_| "missing digest")?;
    let rejected = service.finish_external_request(
        *pending,
        ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::Radius(RadiusLoginObservation))),
    );
    assert_eq!(rejected.status, 409);
    assert!(rejected.body.get("auth").is_none());
    assert!(rejected.body.get("wrap_info").is_none());
    assert_eq!(
        service
            .current_state_digest()
            .map_err(|_| "missing digest")?,
        before
    );
    Ok(())
}
