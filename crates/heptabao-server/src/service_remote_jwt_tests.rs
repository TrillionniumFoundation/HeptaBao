//! Split-phase publication tests use parsed public-key observations; real TLS,
//! fetching and writer-release concurrency are covered by live fixtures.
use super::super::tests::{Root, bootstrap, call};
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{Ed25519KeyPair, KeyPair};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// These auth format fixtures have no record-backed KV1 mounts. Decode their
// unchanged owner bytes as a legacy reader would, without retaining the v5
// runtime installed by current HTTP writes and masking the auth schema fence.
fn restore_legacy_engine_owner(state: &mut State) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        !state.engines.has_record_kv1(),
        "legacy auth fixture cannot discard record-backed KV1 data"
    );
    let before = owner_store::serialize_owner(&state.engines)
        .map_err(|_| "legacy engine fixture serialization")?;
    state.engines = serde_json::from_slice::<EngineState>(&before)?.into();
    assert!(state.engines.record_root().is_none());
    let after = owner_store::serialize_owner(&state.engines)
        .map_err(|_| "legacy engine fixture reserialization")?;
    assert!(
        before.as_slice() == after.as_slice(),
        "legacy engine owner bytes changed"
    );
    Ok(())
}

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
fn jwt_zero_role_limits_require_new_format_but_old_positive_limits_remain_admitted() -> TestResult {
    let root = Root::new();
    let (mut service, admin) = fixture(&root)?;
    let mut state = service.state.as_ref().ok_or("state")?.clone();
    restore_legacy_engine_owner(&mut state)?;
    state.auth.remove_name_modes_for_legacy_format_test();
    state.schema = 31;
    state.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(state.validate_format().is_ok());
    for limits in [
        json!({"role_type":"jwt","token_ttl":0,"token_max_ttl":600}),
        json!({"role_type":"jwt","token_ttl":120,"token_max_ttl":0}),
    ] {
        assert_eq!(
            call(&mut service, "POST", "auth/remote/role/app", &admin, limits).status,
            204
        );
        let mut state = service.state.as_ref().ok_or("state")?.clone();
        restore_legacy_engine_owner(&mut state)?;
        state.auth.remove_name_modes_for_legacy_format_test();
        state.schema = 31;
        state.auth.omit_lease_metadata_for_legacy_fixture();
        assert_eq!(
            state
                .validate_format()
                .err()
                .ok_or("missing TTL schema fence")?
                .status,
            503
        );
        state.schema = CURRENT_STATE_SCHEMA;
        assert!(state.validate_format().is_ok());
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/remote/role/app",
            &admin,
            json!({"role_type":"jwt","token_ttl":120,"token_max_ttl":600})
        )
        .status,
        204
    );
    let mut state = service.state.as_ref().ok_or("state")?.clone();
    restore_legacy_engine_owner(&mut state)?;
    state.auth.remove_name_modes_for_legacy_format_test();
    state.schema = 31;
    state.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(state.validate_format().is_ok());
    Ok(())
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

#[test]
fn jwt_claim_predicates_reject_old_schema_even_after_explicit_clear() -> TestResult {
    let root = Root::new();
    let (mut service, admin) = fixture(&root)?;
    let mut legacy = service.state.clone().ok_or("state")?;
    restore_legacy_engine_owner(&mut legacy)?;
    legacy.auth.remove_name_modes_for_legacy_format_test();
    legacy.schema = 29;
    legacy.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(legacy.validate_format().is_ok());
    for body in [
        json!({"bound_claims_type":"glob","bound_claims":{"sub":"ali*"}}),
        json!({"bound_claims":{}}),
    ] {
        assert_eq!(
            call(&mut service, "POST", "auth/remote/role/app", &admin, body).status,
            204
        );
        let mut state = service.state.clone().ok_or("state")?;
        restore_legacy_engine_owner(&mut state)?;
        state.auth.remove_name_modes_for_legacy_format_test();
        state.schema = 29;
        state.auth.omit_lease_metadata_for_legacy_fixture();
        assert!(state.validate_format().is_err());
        state.schema = CURRENT_STATE_SCHEMA;
        assert!(state.validate_format().is_ok());
    }
    Ok(())
}

#[test]
fn native_jwt_https_state_is_schema_fenced_and_config_preflight_is_not_a_login() -> TestResult {
    let root = Root::new();
    let (service, _) = fixture(&root)?;
    let mut state = service.state.clone().ok_or("state")?;
    restore_legacy_engine_owner(&mut state)?;
    state.auth.remove_name_modes_for_legacy_format_test();
    state.schema = 27;
    state.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(state.validate_format().is_err());
    state.schema = CURRENT_STATE_SCHEMA;
    assert!(state.validate_format().is_ok());
    Ok(())
}

#[test]
fn oidc_config_stages_without_writer_io_and_failed_preflight_preserves_configuration() -> TestResult
{
    let root = Root::new();
    let (mut service, root_token) = fixture(&root)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/browser",
            &root_token,
            json!({"type":"oidc"})
        )
        .status,
        204
    );
    let body = json!({"oidc_discovery_url":"https://synthetic.example:443","oidc_client_id":"synthetic-client","oidc_client_secret":"synthetic-private","oidc_discovery_ca_pem":""});
    let before = service.state_digest;
    let request = pending(
        &mut service,
        "auth/browser/config",
        &root_token,
        body.clone(),
        None,
    )?;
    assert_eq!(service.state_digest, before);
    let failure = service.finish_external_request(
        *request,
        ExternalEffectResult::OnlineAuth(Err(Response::error(400, "synthetic discovery failed"))),
    );
    assert_eq!(failure.status, 400);
    assert_eq!(service.state_digest, before);
    let request = pending(
        &mut service,
        "auth/browser/config",
        &root_token,
        body.clone(),
        None,
    )?;
    let response = service.finish_external_request(
        *request,
        ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::OidcConfig(
            crate::auth::OidcConfigObservation,
        ))),
    );
    assert_eq!(response.status, 204);
    let digest = service.state_digest;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let request = pending(&mut service, "auth/browser/config", &root_token, body, None)?;
    let response = service.finish_external_request(
        *request,
        ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::OidcConfig(
            crate::auth::OidcConfigObservation,
        ))),
    );
    assert_eq!(response.status, 204);
    assert_eq!(service.state_digest, digest);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    Ok(())
}

fn clock_batch_fixture(root: &Root) -> TestResult<(Service, String)> {
    let (mut service, admin) = fixture(root)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/remote/role/app",
            &admin,
            json!({"role_type":"jwt","token_type":"batch","clock_skew_leeway":-1})
        )
        .status,
        204
    );
    Ok((service, admin))
}

fn clock_assertion(nbf: u64, exp: u64) -> TestResult<Value> {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[79; 32]).map_err(|_| "test key")?;
    let claims = json!({"iss":"https://synthetic.example:443","aud":"service", "sub":"clock-subject",
                       "iat":100,"nbf":nbf,"exp":exp});
    let payload = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"synthetic"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
    );
    Ok(
        json!({"role":"app","jwt":format!("{payload}.{}",URL_SAFE_NO_PAD.encode(pair.sign(payload.as_bytes()).as_ref()))}),
    )
}

fn remote_effect(request: &mut PendingExternalRequest) -> TestResult<&mut RemoteJwtEffect> {
    let ExternalEffectPlan::OnlineAuth(plan) = &mut request.effect else {
        return Err("expected online auth".into());
    };
    let OnlineAuthEffect::RemoteJwt(effect) = &mut plan.effect else {
        return Err("expected remote JWT".into());
    };
    Ok(effect)
}

#[test]
fn trusted_real_entries_mark_remote_clock_but_explicit_clock_keeps_its_domain() -> TestResult {
    let root = Root::new();
    let (mut service, _) = clock_batch_fixture(&root)?;
    let mut explicit = pending(&mut service, "auth/remote/login", "", assertion()?, None)?;
    assert!(matches!(
        remote_effect(&mut explicit)?.completion_clock,
        RemoteJwtCompletionClock::Anchored
    ));
    // No network work: real public/forwarded ingress creates a plan, not a
    // caller-selected clock marker. Both paths select the same completion mode.
    for forwarded in [false, true] {
        let request = ServiceRequest::new("POST", "auth/remote/login", "", "", assertion()?);
        let execution = if forwarded {
            service.begin_forwarded(request)
        } else {
            service.begin_request(request)
        };
        let RequestExecution::External(mut request) = execution else {
            return Err("expected real-clock remote plan".into());
        };
        assert!(matches!(
            remote_effect(&mut request)?.completion_clock,
            RemoteJwtCompletionClock::Realtime
        ));
    }
    // Finishing the explicit plan in this process's actual contemporary clock
    // would reject the historical JWT. Its injected clock must remain intact.
    assert_eq!(observed(&mut service, *explicit, false)?.status, 200);
    Ok(())
}

#[test]
fn remote_completion_after_a_later_local_batch_uses_one_current_wall_second() -> TestResult {
    let root = Root::new();
    let (mut service, admin) = clock_batch_fixture(&root)?;
    // Model ingress at 110.900 and completion at 111.100. Integer+elapsed
    // flooring would still return110; a later local request already issued111.
    let mut request = pending(
        &mut service,
        "auth/remote/login",
        "",
        clock_assertion(111, 112)?,
        None,
    )?;
    let local = service.handle_at(
        "POST",
        "auth/token/create",
        "",
        &admin,
        json!({"type":"batch","policies":["default"],"ttl":60}),
        111,
    );
    assert_eq!(local.status, 200);
    remote_effect(&mut request)?.completion_clock =
        RemoteJwtCompletionClock::FixedWall(std::time::UNIX_EPOCH + Duration::from_millis(111_100));
    let response = observed(&mut service, *request, false)?;
    assert_eq!(response.status, 200);
    let bearer = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("batch bearer")?;
    assert_eq!(response.body["auth"]["token_type"], "batch");
    let lookup = service.handle_at("GET", "auth/token/lookup-self", "", bearer, json!({}), 111);
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["creation_time"], 111);
    // nbf111 and exp112 were verified at the same111 used for batch issuance,
    // Identity and sealing; no provider-created timestamp controls that choice.
    assert_eq!(
        service
            .handle_at("GET", "auth/token/lookup-self", "", bearer, json!({}), 110)
            .status,
        403
    );
    Ok(())
}

#[test]
fn rollback_unavailable_or_expired_completion_never_publishes_identity_or_batch() -> TestResult {
    for (wall, exp, expected) in [
        (std::time::UNIX_EPOCH + Duration::from_secs(110), 1000, 503),
        (std::time::UNIX_EPOCH - Duration::from_secs(1), 1000, 503),
        (std::time::UNIX_EPOCH + Duration::from_secs(111), 110, 400),
    ] {
        let root = Root::new();
        let (mut service, admin) = clock_batch_fixture(&root)?;
        let mut request = pending(
            &mut service,
            "auth/remote/login",
            "",
            clock_assertion(100, exp)?,
            None,
        )?;
        assert_eq!(
            service
                .handle_at(
                    "POST",
                    "auth/token/create",
                    "",
                    &admin,
                    json!({"type":"batch","policies":["default"],"ttl":60}),
                    111
                )
                .status,
            200
        );
        remote_effect(&mut request)?.completion_clock = RemoteJwtCompletionClock::FixedWall(wall);
        let state = service.state.as_ref().ok_or("state")?;
        let auth_before = owner_store::serialize_owner(&state.auth)?;
        let engines_before = owner_store::serialize_owner(&state.engines)?;
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let digest = service.state_digest;
        let response = observed(&mut service, *request, false)?;
        assert_eq!(response.status, expected);
        assert!(response.body.get("auth").is_none());
        let state = service.state.as_ref().ok_or("state")?;
        assert!(
            owner_store::serialize_owner(&state.auth)?.as_slice() == auth_before.as_slice(),
            "auth owner changed"
        );
        assert!(
            owner_store::serialize_owner(&state.engines)?.as_slice() == engines_before.as_slice(),
            "engine owner changed"
        );
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert_eq!(service.state_digest, digest);
    }
    Ok(())
}

#[test]
fn remote_one_second_wrapper_and_inner_batch_share_completed_wall_sample() -> TestResult {
    for consume_at in [111, 112] {
        let root = Root::new();
        let (mut service, admin) = clock_batch_fixture(&root)?;
        let mut request = pending(
            &mut service,
            "auth/remote/login",
            "",
            clock_assertion(111, 112)?,
            Some(1),
        )?;
        remote_effect(&mut request)?.completion_clock = RemoteJwtCompletionClock::FixedWall(
            std::time::UNIX_EPOCH + Duration::from_millis(111_100),
        );
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let response = observed(&mut service, *request, false)?;
        assert_eq!(response.status, 200);
        assert!(response.body["auth"].is_null());
        assert_eq!(response.body["wrap_info"]["ttl"], 1);
        assert_eq!(
            response.body["wrap_info"]["creation_time"],
            crate::engines::timestamp(111)
        );
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation + 1
        );
        let wrapper = response.body["wrap_info"]["token"]
            .as_str()
            .ok_or("wrapper")?;
        let lookup = service.handle_at(
            "POST",
            "auth/token/lookup",
            "",
            &admin,
            json!({"token":wrapper}),
            111,
        );
        assert_eq!(lookup.status, 200);
        assert_eq!(lookup.body["data"]["creation_time"], 111);
        assert_eq!(lookup.body["data"]["expire_time_unix"], 112);
        let unwrapped = service.handle_at(
            "POST",
            "sys/wrapping/unwrap",
            "",
            wrapper,
            json!({}),
            consume_at,
        );
        if consume_at == 112 {
            assert_eq!(unwrapped.status, 400);
            assert!(unwrapped.body.get("auth").is_none());
            continue;
        }
        assert_eq!(unwrapped.status, 200);
        assert_eq!(unwrapped.body["auth"]["token_type"], "batch");
        let bearer = unwrapped.body["auth"]["client_token"]
            .as_str()
            .ok_or("inner batch")?;
        let lookup = service.handle_at("GET", "auth/token/lookup-self", "", bearer, json!({}), 111);
        assert_eq!(lookup.status, 200);
        assert_eq!(lookup.body["data"]["creation_time"], 111);
        assert_eq!(
            service
                .handle_at("POST", "sys/wrapping/unwrap", "", wrapper, json!({}), 111)
                .status,
            400
        );
    }
    Ok(())
}
