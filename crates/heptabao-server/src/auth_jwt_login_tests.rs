use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};

fn fixture(extensions: bool) -> (AuthState, Principal, Ed25519KeyPair) {
    let (mut state, _, root) = setup();
    let pair = Ed25519KeyPair::from_seed_unchecked(&[62; 32]).unwrap();
    configured_jwt_mount(
        &mut state,
        &root,
        "workload",
        pair.public_key().as_ref(),
        "EdDSA",
    );
    if !extensions {
        let mut config = jwt_config(pair.public_key().as_ref(), "EdDSA");
        config.as_object_mut().unwrap().remove("clock_skew_seconds");
        config
            .as_object_mut()
            .unwrap()
            .remove("maximum_token_lifetime_seconds");
        call(
            &mut state,
            &root,
            "team",
            "POST",
            "auth/workload/config",
            config,
            1000,
        );
    }
    (state, root, pair)
}

fn login(
    state: &mut AuthState,
    pair: &Ed25519KeyPair,
    claims: Value,
) -> Result<AuthResponse, AuthError> {
    let jwt = signed_jwt(pair, &json!({"alg":"EdDSA","kid":"key-1"}), &claims);
    state
        .handle(
            None,
            "team",
            "POST",
            "auth/workload/login",
            &json!({"role":"app","jwt":jwt}),
            1050,
        )?
        .ok_or_else(|| bad("missing route"))
}

#[test]
fn native_config_defaults_allow_optional_dates_reuse_and_unbounded_assertion_lifetime() {
    let (mut state, root, pair) = fixture(false);
    let config = call(
        &mut state,
        &root,
        "team",
        "GET",
        "auth/workload/config",
        json!({}),
        1000,
    );
    assert!(config.body["data"]["clock_skew_seconds"].is_null());
    assert!(config.body["data"]["maximum_token_lifetime_seconds"].is_null());
    let mut claims = jwt_claims("reuse");
    claims.as_object_mut().unwrap().remove("jti");
    claims.as_object_mut().unwrap().remove("iat");
    claims.as_object_mut().unwrap().remove("nbf");
    claims["exp"] = json!(1150);
    let first = login(&mut state, &pair, claims.clone()).unwrap();
    let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut reopened: AuthState = serde_json::from_slice(&encoded).unwrap();
    let second = login(&mut reopened, &pair, claims).unwrap();
    assert_ne!(
        first.body["auth"]["client_token"],
        second.body["auth"]["client_token"]
    );
    let mut claims = jwt_claims("long");
    claims["exp"] = json!(100000);
    assert_eq!(
        login(&mut reopened, &pair, claims).unwrap().body["auth"]["lease_duration"],
        600
    );
}

#[test]
fn explicit_legacy_limits_remain_enforced_and_role_clock_takes_precedence() {
    let (state, root, pair) = fixture(true);
    let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut state: AuthState = serde_json::from_slice(&encoded).unwrap();
    let scope = AuthScope {
        namespace: "team",
        mount: "workload",
    };
    let config = state.jwt_at(scope).unwrap().config.as_ref().unwrap();
    assert_eq!(config.clock_skew_seconds, Some(0));
    assert_eq!(config.maximum_token_lifetime_seconds, Some(3600));
    for field in ["iat", "exp"] {
        let mut claims = jwt_claims("missing");
        claims.as_object_mut().unwrap().remove(field);
        assert_eq!(login(&mut state, &pair, claims).err().unwrap().status, 400);
    }
    let mut long = jwt_claims("long");
    long["exp"] = json!(100000);
    assert_eq!(login(&mut state, &pair, long).err().unwrap().status, 400);
    let mut future = jwt_claims("future");
    future["iat"] = json!(1055);
    assert_eq!(
        login(&mut state, &pair, future.clone())
            .err()
            .unwrap()
            .status,
        400
    );
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/workload/role/app",
        json!({"clock_skew_leeway":0}),
        1000,
    );
    assert_eq!(
        login(&mut state, &pair, future.clone()).unwrap().status,
        200
    );
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/workload/role/app",
        json!({"clock_skew_leeway":-1}),
        1000,
    );
    assert_eq!(login(&mut state, &pair, future).err().unwrap().status, 400);
}

#[test]
fn legacy_config_clock_grace_does_not_extend_expiry_without_explicit_role_override() {
    let (mut state, root, pair) = fixture(true);
    let mut config = jwt_config(pair.public_key().as_ref(), "EdDSA");
    config["clock_skew_seconds"] = json!(30);
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/workload/config",
        config,
        1000,
    );
    let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut state: AuthState = serde_json::from_slice(&encoded).unwrap();
    let mut future = jwt_claims("future-grace");
    future["iat"] = json!(1055);
    assert_eq!(login(&mut state, &pair, future).unwrap().status, 200);
    for expiry in [1049, 1050] {
        let mut claims = jwt_claims("expired");
        claims["exp"] = json!(expiry);
        assert_eq!(login(&mut state, &pair, claims).err().unwrap().status, 400);
    }
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/workload/role/app",
        json!({"clock_skew_leeway":0}),
        1000,
    );
    for expiry in [1049, 1050] {
        let mut claims = jwt_claims("native-grace");
        claims["exp"] = json!(expiry);
        assert_eq!(login(&mut state, &pair, claims).unwrap().status, 200);
    }
}

#[test]
fn jwt_role_leeway_readback_updates_and_signed_duration_types_are_bounded() {
    let (mut state, root, _) = fixture(false);
    let before = call(
        &mut state,
        &root,
        "team",
        "GET",
        "auth/workload/role/app",
        json!({}),
        1000,
    )
    .body["data"]
        .clone();
    for field in [
        "clock_skew_leeway",
        "expiration_leeway",
        "not_before_leeway",
    ] {
        assert_eq!(before[field], 0);
    }
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/workload/role/app",
        json!({"clock_skew_leeway":"1m30s","expiration_leeway":"-1s","not_before_leeway":"2500ms"}),
        1000,
    );
    let after = call(
        &mut state,
        &root,
        "team",
        "GET",
        "auth/workload/role/app",
        json!({}),
        1000,
    )
    .body["data"]
        .clone();
    assert_eq!(after["clock_skew_leeway"], 90);
    assert_eq!(after["expiration_leeway"], -1);
    assert_eq!(after["not_before_leeway"], 2);
    for field in [
        "token_ttl",
        "token_max_ttl",
        "token_policies",
        "bound_audiences",
        "bound_subject",
        "bound_groups",
    ] {
        assert_eq!(before[field], after[field], "{field}");
    }
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/workload/role/app",
        json!({"clock_skew_leeway":null}),
        1000,
    );
    assert_eq!(
        call(
            &mut state,
            &root,
            "team",
            "GET",
            "auth/workload/role/app",
            json!({}),
            1000
        )
        .body["data"],
        after
    );
    let saved = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    for value in [
        json!(true),
        json!({}),
        json!("NaN"),
        json!("1e100h"),
        json!("1.2.3s"),
    ] {
        assert!(
            state
                .handle(
                    Some(&root),
                    "team",
                    "POST",
                    "auth/workload/role/app",
                    &json!({"clock_skew_leeway":value}),
                    1000
                )
                .is_err()
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), *saved);
    }
}
