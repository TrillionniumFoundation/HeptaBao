//! Split-phase publication tests use parsed public-key observations; real TLS,
//! fetching and writer-release concurrency are covered by live fixtures.
use super::super::tests::{Root, bootstrap, call};
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{Ed25519KeyPair, KeyPair};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn keys() -> TestResult<Value> {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[79; 32]).map_err(|_| "test key")?;
    Ok(
        json!({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"synthetic","alg":"EdDSA","x":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())}]}),
    )
}

fn config() -> Value {
    json!({"issuer":"https://synthetic.example:443","jwks_url":"https://synthetic.example:443/keys","audiences":["service"],"jwt_supported_algs":["EdDSA"]})
}

fn assertion() -> TestResult<Value> {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[79; 32]).map_err(|_| "test key")?;
    let payload = format!("{}.{}", URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"synthetic"}"#), URL_SAFE_NO_PAD.encode(br#"{"iss":"https://synthetic.example:443","aud":"service","sub":"alice","iat":100,"exp":1000}"#));
    Ok(
        json!({"role":"app","jwt":format!("{payload}.{}",URL_SAFE_NO_PAD.encode(pair.sign(payload.as_bytes()).as_ref()))}),
    )
}

fn pending(
    service: &mut Service,
    path: &str,
    token: &str,
    body: Value,
    wrap: Option<u64>,
) -> TestResult<Box<PendingExternalRequest>> {
    match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path,
        namespace: "",
        token,
        body,
        now: 110,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: wrap,
        client_certificates: None,
        origin_peer: None,
    }) {
        RequestExecution::External(plan) => Ok(plan),
        RequestExecution::Complete(_) => Err("expected external JWT plan".into()),
    }
}

fn observed(
    service: &mut Service,
    request: PendingExternalRequest,
    configuration: bool,
) -> TestResult<Response> {
    let keys = RemoteJwtLoginObservation::from_test_jwks(&keys()?)?;
    let observation = if configuration {
        OnlineAuthObservation::RemoteJwtConfig(keys)
    } else {
        OnlineAuthObservation::RemoteJwt(keys)
    };
    Ok(service.finish_external_request(request, ExternalEffectResult::OnlineAuth(Ok(observation))))
}

fn fixture(root: &Root) -> TestResult<(Service, String)> {
    let mut service = root.service()?;
    let (_, root_token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/remote",
            &root_token,
            json!({"type":"jwt"})
        )
        .status,
        204
    );
    let request = pending(
        &mut service,
        "auth/remote/config",
        &root_token,
        config(),
        None,
    )?;
    assert_eq!(observed(&mut service, *request, true)?.status, 204);
    assert_eq!(call(&mut service, "POST", "auth/remote/role/app", &root_token, json!({"role_type":"jwt","user_claim":"sub","bound_audiences":["service"],"token_ttl":120,"token_max_ttl":600})).status, 204);
    Ok((service, root_token))
}

#[test]
fn config_preflight_failure_preserves_old_config_and_concurrent_write_survives_success()
-> TestResult {
    let root = Root::new();
    let (mut service, token) = fixture(&root)?;
    let before = service.state_digest;
    let request = pending(&mut service, "auth/remote/config", &token, config(), None)?;
    let response = service.finish_external_request(
        *request,
        ExternalEffectResult::OnlineAuth(Err(Response::error(
            503,
            "synthetic provider unavailable",
        ))),
    );
    assert_eq!(response.status, 503);
    assert_eq!(service.state_digest, before);
    let request = pending(&mut service, "auth/remote/config", &token, config(), None)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/policies/acl/concurrent",
            &token,
            json!({"policy":"path \"secret/*\" { capabilities = [\"read\"] }"})
        )
        .status,
        204
    );
    assert_eq!(observed(&mut service, *request, true)?.status, 204);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/policies/acl/concurrent",
            &token,
            json!({})
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn wrapped_remote_jwt_login_stages_and_publishes_one_use_wrapper_atomically() -> TestResult {
    let root = Root::new();
    let (mut service, _) = fixture(&root)?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let request = pending(
        &mut service,
        "auth/remote/login",
        "",
        assertion()?,
        Some(60),
    )?;
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    let response = observed(&mut service, *request, false)?;
    assert_eq!(response.status, 200);
    assert!(response.body["auth"].is_null());
    let wrapper = response.body["wrap_info"]["token"]
        .as_str()
        .ok_or("wrapper")?
        .to_owned();
    assert_eq!(
        response.body["wrap_info"]["creation_path"],
        "auth/remote/login"
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation + 1
    );
    let unwrapped = service.handle_at("POST", "sys/wrapping/unwrap", "", &wrapper, json!({}), 112);
    assert_eq!(unwrapped.status, 200);
    assert!(unwrapped.body["auth"]["client_token"].as_str().is_some());
    assert_eq!(
        service
            .handle_at("POST", "sys/wrapping/unwrap", "", &wrapper, json!({}), 112)
            .status,
        400
    );
    Ok(())
}

#[test]
fn wrapped_remote_jwt_store_refusal_publishes_no_token_or_key_update() -> TestResult {
    for failure in ["commit", "wrappers"] {
        let root = Root::new();
        let (mut service, _) = fixture(&root)?;
        if failure == "wrappers" {
            let mut state = service.state.clone().ok_or("state")?;
            for _ in 0..256 {
                state.auth.wrap_response(
                    "",
                    "synthetic/wrapper",
                    3600,
                    &json!({"synthetic":true}),
                    100,
                )?;
            }
            service
                .commit_state(&state)
                .map_err(|_| "wrapper fixture commit")?;
            service.state = Some(state);
        }
        let request = pending(
            &mut service,
            "auth/remote/login",
            "",
            assertion()?,
            Some(60),
        )?;
        let before = service.state_digest;
        if failure == "commit" {
            service.state_capacity = 1;
        }
        let response = observed(&mut service, *request, false)?;
        assert_eq!(response.status, if failure == "commit" { 507 } else { 503 });
        assert!(response.body.get("auth").is_none());
        assert!(response.body.get("wrap_info").is_none());
        assert_eq!(service.state_digest, before);
    }
    Ok(())
}

#[test]
fn pending_remote_login_role_mutation_is_fenced_without_publishing_wrapper() -> TestResult {
    let root = Root::new();
    let (mut service, token) = fixture(&root)?;
    let request = pending(
        &mut service,
        "auth/remote/login",
        "",
        assertion()?,
        Some(60),
    )?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/remote/role/app",
            &token,
            json!({"token_ttl":121})
        )
        .status,
        204
    );
    let before = service.state_digest;
    let response = observed(&mut service, *request, false)?;
    assert_eq!(response.status, 409);
    assert_eq!(service.state_digest, before);
    assert!(response.body.get("wrap_info").is_none());
    Ok(())
}

#[test]
fn remote_config_affine_last_use_authority_is_not_debited_twice() -> TestResult {
    let root = Root::new();
    let (mut service, root_token) = fixture(&root)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/policies/acl/configure",
            &root_token,
            json!({"policy":"path \"auth/remote/config\" { capabilities = [\"update\",\"sudo\"] }"})
        )
        .status,
        204
    );
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &root_token,
        json!({"policies":["configure"],"num_uses":1,"ttl":600}),
    );
    assert_eq!(issued.status, 200);
    let actor = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("actor")?;
    let request = pending(
        &mut service,
        "auth/remote/config",
        actor,
        config(),
        Some(60),
    )?;
    let response = observed(&mut service, *request, true)?;
    assert_eq!(response.status, 204); // ordinary204 config writes do not acquire a wrapper
    assert!(response.body.is_null());
    assert_eq!(
        service
            .handle_at("POST", "auth/remote/config", "", actor, config(), 112)
            .status,
        403
    );
    Ok(())
}

#[test]
fn same_remote_config_and_keys_do_not_append_but_rotated_keys_do() -> TestResult {
    let root = Root::new();
    let (mut service, actor) = fixture(&root)?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let digest = service.state_digest;
    let request = pending(&mut service, "auth/remote/config", &actor, config(), None)?;
    assert_eq!(observed(&mut service, *request, true)?.status, 204);
    assert_eq!(service.state_digest, digest);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(
        call(&mut service, "GET", "auth/remote/config", &actor, json!({})).status,
        200
    );
    let request = pending(&mut service, "auth/remote/config", &actor, config(), None)?;
    let pair = Ed25519KeyPair::from_seed_unchecked(&[80; 32]).map_err(|_| "test key")?;
    let mut rotated = keys()?;
    rotated["keys"][0]["x"] = json!(URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()));
    let response = service.finish_external_request(
        *request,
        ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::RemoteJwtConfig(
            RemoteJwtLoginObservation::from_test_jwks(&rotated)?,
        ))),
    );
    assert_eq!(response.status, 204);
    assert_ne!(service.state_digest, digest);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation + 1
    );
    Ok(())
}
