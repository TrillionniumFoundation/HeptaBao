//! Native JWT renewal is local, but its role check, identity projection,
//! response wrapping and updated lease still publish in one Service commit.
use super::tests::{Root, bootstrap, call};
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{Ed25519KeyPair, KeyPair};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture(root: &Root) -> TestResult<(Service, String, String, String)> {
    let mut service = root.service()?;
    let (key, admin) = bootstrap(&mut service)?;
    let pair = Ed25519KeyPair::from_seed_unchecked(&[59; 32]).map_err(|_| "test key")?;
    for (path, body) in [
        ("sys/auth/jwt", json!({"type":"jwt"})),
        (
            "auth/jwt/config",
            json!({"issuer":"https://issuer.example","audiences":["service"],"clock_skew_seconds":0,"keys":[{"kid":"key","algorithm":"EdDSA","key_base64":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())}]}),
        ),
        (
            "auth/jwt/role/app",
            json!({"bound_audiences":["service"],"token_ttl":60,"token_max_ttl":600}),
        ),
    ] {
        assert_eq!(
            call(&mut service, "POST", path, &admin, body).status,
            204,
            "{path}"
        );
    }
    let payload = format!("{}.{}",URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"key"}"#),URL_SAFE_NO_PAD.encode(br#"{"iss":"https://issuer.example","aud":"service","sub":"alice","iat":100,"exp":102,"jti":"durable-renewal"}"#));
    let jwt = format!(
        "{payload}.{}",
        URL_SAFE_NO_PAD.encode(pair.sign(payload.as_bytes()).as_ref())
    );
    let login = call(
        &mut service,
        "POST",
        "auth/jwt/login",
        "",
        json!({"role":"app","jwt":jwt}),
    );
    assert_eq!(login.status, 200);
    assert_eq!(login.body["auth"]["lease_duration"], 60);
    let token = login.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned();
    Ok((service, key, admin, token))
}

fn wrapped(
    service: &mut Service,
    path: &str,
    token: &str,
    body: Value,
    now: u64,
) -> TestResult<Response> {
    match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path,
        namespace: "",
        token,
        body,
        now,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: Some(60),
        origin_peer: None,
        client_certificates: None,
    }) {
        RequestExecution::Complete(response) => Ok(response),
        RequestExecution::External(_) => Err("JWT renewal must not contact an issuer".into()),
    }
}

fn restore_v18_jwt_config(auth: &mut Value) -> TestResult {
    for mounts in auth["jwt_mounts"]
        .as_object_mut()
        .ok_or("JWT namespaces")?
        .values_mut()
    {
        for mount in mounts.as_object_mut().ok_or("JWT mounts")?.values_mut() {
            mount
                .as_object_mut()
                .ok_or("JWT mount")?
                .remove("native_claims");
            // These fields were mandatory numbers before native defaults.
            mount["config"]["clock_skew_seconds"] = json!(0);
            mount["config"]["maximum_token_lifetime_seconds"] = json!(3600);
        }
    }
    Ok(())
}

#[test]
fn jwt_renewal_role_check_echo_and_wrapper_survive_restart() -> TestResult {
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let root = Root::new();
        let (mut service, key, admin, token) = fixture(&root)?;
        let info = call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &token,
            json!({}),
        );
        let accessor = info.body["data"]["accessor"].as_str().ok_or("accessor")?;
        let request = match operation {
            "renew" => json!({"token":token,"increment":120}),
            "renew-accessor" => json!({"accessor":accessor,"increment":120}),
            _ => json!({"increment":120}),
        };
        let path = format!("auth/token/{operation}");
        let actor = if operation == "renew-self" {
            &token
        } else {
            &admin
        };
        let response = wrapped(&mut service, &path, actor, request.clone(), 110)?;
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
                .handle_at("POST", "sys/unseal", "", "", json!({"key":key}), 111)
                .status,
            200
        );
        let response =
            service.handle_at("POST", "sys/wrapping/unwrap", "", &wrapper, json!({}), 111);
        assert_eq!(response.status, 200);
        assert_eq!(response.body["auth"]["lease_duration"], 120);
        if operation == "renew-accessor" {
            assert!(response.body["auth"].get("client_token").is_none());
        } else {
            assert_eq!(response.body["auth"]["client_token"], token);
        }
        assert!(
            service
                .handle_at("POST", "sys/wrapping/unwrap", "", &wrapper, json!({}), 111)
                .status
                >= 400
        );
        let expiry = service
            .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 112)
            .body["data"]["expire_time_unix"]
            .clone();
        assert_eq!(expiry, 230);
        assert_eq!(
            service
                .handle_at("DELETE", "auth/jwt/role/app", "", &admin, json!({}), 112)
                .status,
            204
        );
        let response = wrapped(&mut service, &path, actor, request, 112)?;
        assert_eq!(response.status, 500);
        assert!(response.body.get("wrap_info").is_none());
        assert_eq!(
            service
                .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 112)
                .body["data"]["expire_time_unix"],
            expiry
        );
        let state = service.state.as_ref().ok_or("state")?;
        assert!(
            state.validate_format().is_ok(),
            "role deletion must remain durable"
        );
    }
    Ok(())
}

#[test]
fn jwt_schema_eighteen_fences_new_issuer_semantics_and_admits_real_legacy_records() -> TestResult {
    let root = Root::new();
    let (mut service, _, admin, token) = fixture(&root)?;
    let mut state = service.state.clone().ok_or("state")?;
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    state.schema = 17;
    state.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(state.validate_format().is_err());
    let mut auth = serde_json::to_value(&state.auth)?;
    for entry in auth["tokens"].as_object_mut().ok_or("tokens")?.values_mut() {
        if entry["auth_provenance"]["kind"] == "jwt" {
            // The old implementation capped both the lease and its stored
            // maximum at the fixture assertion's exp=102. Removing a marker
            // alone would leave this new token's uncapped shape behind.
            entry["expires_at"] = json!(102);
            entry["max_expires_at"] = json!(102);
        }
        entry
            .as_object_mut()
            .ok_or("token")?
            .remove("auth_provenance");
    }
    restore_v18_jwt_config(&mut auth)?;
    state.auth = serde_json::from_value::<AuthState>(auth)?.into();
    assert!(state.validate_format().is_ok());
    let mut actor = state.auth.authenticate(&token, 101)?;
    // Service-issued tokens have a real entity. Bind the live projection just
    // as dispatch does, so this check reaches the legacy-origin renewal fence.
    Service::bind_identity_principal(&state, &mut actor, "").map_err(|_| "identity projection")?;
    assert_eq!(
        state
            .auth
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/token/renew-self",
                &json!({}),
                101
            )
            .err()
            .ok_or("legacy renewal succeeded")?
            .status,
        400
    );
    assert!(state.auth.authenticate(&token, 101).is_ok());
    assert!(state.auth.authenticate(&token, 102).is_err());
    // A role carrying the new periodic or explicit maximum semantics also
    // requires the new format even before its first direct token is issued.
    assert_eq!(call(&mut service,"POST","auth/jwt/role/app",&admin,json!({"bound_audiences":["service"],"token_ttl":30,"token_max_ttl":60,"token_period":10,"token_explicit_max_ttl":120})).status,204);
    let mut roles_only = service.state.clone().ok_or("state")?;
    let mut auth = serde_json::to_value(&roles_only.auth)?;
    for entry in auth["tokens"].as_object_mut().ok_or("tokens")?.values_mut() {
        if entry["auth_provenance"]["kind"] == "jwt" {
            entry["expires_at"] = json!(102);
            entry["max_expires_at"] = json!(102);
        }
        entry
            .as_object_mut()
            .ok_or("token")?
            .remove("auth_provenance");
    }
    restore_v18_jwt_config(&mut auth)?;
    roles_only.auth = serde_json::from_value::<AuthState>(auth)?.into();
    roles_only.schema = 17;
    roles_only.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(roles_only.validate_format().is_err());
    roles_only.schema = 18;
    roles_only.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(roles_only.validate_format().is_ok());
    Ok(())
}

#[test]
fn native_jwt_schema_nineteen_distinguishes_old_limits_new_defaults_and_leeways() -> TestResult {
    let root = Root::new();
    let (service, _, _, _) = fixture(&root)?;
    let mut state = service.state.clone().ok_or("state")?;
    let mut legacy = serde_json::to_value(&state.auth)?;
    restore_v18_jwt_config(&mut legacy)?;
    state.auth = serde_json::from_value::<AuthState>(legacy.clone())?.into();
    state.schema = 18;
    state.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(state.validate_format().is_ok());
    for variant in ["default", "leeway", "native"] {
        let mut value = legacy.clone();
        let mount = &mut value["jwt_mounts"][""]["jwt"];
        match variant {
            "default" => {
                mount["config"]
                    .as_object_mut()
                    .ok_or("config")?
                    .remove("maximum_token_lifetime_seconds");
            }
            "leeway" => mount["roles"]["app"]["clock_skew_leeway"] = json!(0),
            _ => mount["native_claims"] = json!(true),
        }
        state.auth = serde_json::from_value::<AuthState>(value)?.into();
        state.schema = 18;
        state.auth.omit_lease_metadata_for_legacy_fixture();
        assert!(state.validate_format().is_err(), "{variant}");
        state.schema = CURRENT_STATE_SCHEMA;
        assert!(state.validate_format().is_ok(), "{variant}");
    }
    Ok(())
}
