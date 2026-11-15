use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};

fn fixture() -> (AuthState, Principal, Ed25519KeyPair) {
    let (mut state, _, root) = setup();
    let pair = Ed25519KeyPair::from_seed_unchecked(&[74; 32]).unwrap();
    configured_jwt_mount(
        &mut state,
        &root,
        "bound",
        pair.public_key().as_ref(),
        "EdDSA",
    );
    (state, root, pair)
}

fn update(state: &mut AuthState, root: &Principal, body: Value) -> Result<AuthResponse, AuthError> {
    state
        .handle(
            Some(root),
            "team",
            "POST",
            "auth/bound/role/app",
            &body,
            1050,
        )?
        .ok_or_else(|| bad("missing role route"))
}

fn login_body(pair: &Ed25519KeyPair, additional: Value) -> Value {
    let mut claims = jwt_claims("bound-test");
    claims
        .as_object_mut()
        .unwrap()
        .extend(additional.as_object().unwrap().clone());
    json!({"role":"app", "jwt":signed_jwt(pair, &json!({"alg":"EdDSA","kid":"key-1"}), &claims)})
}

fn login(state: &mut AuthState, body: &Value) -> Result<AuthResponse, AuthError> {
    state
        .handle(None, "team", "POST", "auth/bound/login", body, 1050)?
        .ok_or_else(|| bad("missing login route"))
}

fn read_role(state: &mut AuthState, root: &Principal) -> Value {
    call(
        state,
        root,
        "team",
        "GET",
        "auth/bound/role/app",
        json!({}),
        1050,
    )
    .body["data"]
        .clone()
}

#[test]
fn jwt_bound_role_partial_updates_follow_observed_map_and_mode_semantics() {
    let (mut state, root, pair) = fixture();
    let initial = read_role(&mut state, &root);
    assert_eq!(initial["role_type"], "jwt");
    assert_eq!(initial["user_claim"], "sub");
    assert_eq!(initial["bound_claims_type"], "string");
    assert!(initial["bound_claims"].is_null());
    assert!(!state.has_jwt_bound_claims_state());
    update(
        &mut state,
        &root,
        json!({"role_type":"jwt", "bound_claims_type":"glob", "bound_claims":{"value":"a*"}}),
    )
    .unwrap();
    assert!(state.has_jwt_bound_claims_state());
    let body = login_body(&pair, json!({"value":"alpha"}));
    assert_eq!(login(&mut state, &body).unwrap().status, 200);
    update(
        &mut state,
        &root,
        json!({"role_type":"jwt", "token_ttl":601}),
    )
    .unwrap();
    let role = read_role(&mut state, &root);
    assert_eq!(role["bound_claims_type"], "string");
    assert_eq!(role["bound_claims"], json!({"value":"a*"}));
    assert_eq!(login(&mut state, &body).err().unwrap().status, 400);
    update(
        &mut state,
        &root,
        json!({"role_type":"jwt", "bound_claims_type":"glob"}),
    )
    .unwrap();
    assert_eq!(login(&mut state, &body).unwrap().status, 200);
    for null_or_empty in [json!(null), json!({})] {
        update(
            &mut state,
            &root,
            json!({"role_type":"jwt", "bound_claims_type":"glob", "bound_claims":{"value":"a*"}}),
        )
        .unwrap();
        update(
            &mut state,
            &root,
            json!({"role_type":"jwt", "bound_claims":null_or_empty}),
        )
        .unwrap();
        let role = read_role(&mut state, &root);
        assert_eq!(role["bound_claims_type"], "string");
        assert_eq!(role["bound_claims"], json!({}));
        assert_eq!(
            login(&mut state, &login_body(&pair, json!({})))
                .unwrap()
                .status,
            200
        );
    }
    for invalid in [
        json!({"bound_claims_type":null}),
        json!({"bound_claims_type":""}),
        json!({"bound_claims_type":"regex"}),
        json!({"bound_claims":42}),
        json!({"bound_claims_type":"glob","bound_claims":{"value":42}}),
        json!({"bound_claims_type":"glob","bound_claims":{"value":["a*",42]}}),
    ] {
        let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        assert_eq!(
            update(&mut state, &root, invalid).err().unwrap().status,
            400
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), *before);
    }
}

#[test]
fn jwt_bound_login_uses_verified_original_claims_and_reopens_the_same_predicate() {
    let (mut state, root, pair) = fixture();
    update(
        &mut state,
        &root,
        json!({"bound_claims": {
            "iss":"https://issuer.example", "sub":"alice", "/iat":1000,
            "/a~1b/~0name/+1":"one", "value":[42]
        }}),
    )
    .unwrap();
    let body = login_body(
        &pair,
        json!({"a/b":{"~name":["zero","one"]}, "value":42.9,
        "unretained":"signed-extra-claim-must-not-be-persisted"}),
    );
    assert_eq!(login(&mut state, &body).unwrap().status, 200);
    let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    assert!(
        !String::from_utf8_lossy(&encoded).contains("signed-extra-claim-must-not-be-persisted")
    );
    let mut state: AuthState = serde_json::from_slice(&encoded).unwrap();
    assert!(state.has_jwt_bound_claims_state());
    assert_eq!(login(&mut state, &body).unwrap().status, 200);
    for additional in [
        json!({"a/b":{"~name":["zero","one"]}, "value":[42]}),
        json!({"a/b":{"~name":["zero","different"]}, "value":42}),
        json!({"value":42}),
    ] {
        let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        assert_eq!(
            login(&mut state, &login_body(&pair, additional))
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), *before);
    }
    let other_pair = Ed25519KeyPair::from_seed_unchecked(&[75; 32]).unwrap();
    let untrusted = login_body(
        &other_pair,
        json!({"a/b":{"~name":["zero","one"]}, "value":42}),
    );
    assert_eq!(login(&mut state, &untrusted).err().unwrap().status, 400);
}

#[test]
fn jwt_bound_legacy_role_bytes_stay_exact_and_new_state_marker_survives_empty_bounds() {
    let old = br#"{"bound_groups":[],"bound_subject":null,"bound_audiences":[],"policies":["default"],"token_ttl":60,"token_max_ttl":90,"token_num_uses":0}"#;
    let role: JwtRole = serde_json::from_slice(old).unwrap();
    assert!(role.bound_claims.is_none());
    assert_eq!(serde_json::to_vec(&role).unwrap(), old);
    let (mut state, root, _) = fixture();
    update(&mut state, &root, json!({"bound_claims":{}})).unwrap();
    let bytes = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let state: AuthState = serde_json::from_slice(&bytes).unwrap();
    assert!(state.has_jwt_bound_claims_state());
    let mut invalid = serde_json::to_value(role).unwrap();
    invalid["bound_claims"] = json!({"kind":"regex", "claims":{}});
    assert!(serde_json::from_value::<JwtRole>(invalid).is_err());
}

#[test]
fn native_token_renewal_does_not_reapply_new_claim_rules() {
    let (mut state, root, pair) = fixture();
    let issued = login(&mut state, &login_body(&pair, json!({"value":"old"}))).unwrap();
    let token = issued.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    update(&mut state, &root, json!({"bound_claims":{"value":"new"}})).unwrap();
    for route in ["renew-self", "renew", "renew-accessor"] {
        let actor = state.authenticate(&token, 1051).unwrap();
        let body = match route {
            "renew" => json!({"token":token,"increment":60}),
            "renew-accessor" => {
                json!({"accessor":state.tokens[&actor.digest].accessor,"increment":60})
            }
            _ => json!({"increment":60}),
        };
        assert_eq!(
            state
                .handle(
                    Some(if route == "renew-self" { &actor } else { &root }),
                    "team",
                    "POST",
                    &format!("auth/token/{route}"),
                    &body,
                    1051
                )
                .unwrap()
                .unwrap()
                .status,
            200
        );
    }
}

#[test]
fn remote_login_uses_common_bound_rules_and_fences_inflight_role_changes() {
    let (mut state, root, pair) = fixture();
    let scope = AuthScope {
        namespace: "team",
        mount: "bound",
    };
    state.jwt_at_mut(scope).config.as_mut().unwrap().remote = Some(RemoteJwtSource {
        jwks_url: Some("https://issuer.example/keys".into()),
        oidc_discovery_url: None,
        transport: None,
        inactive_ca_pem: String::new(),
    });
    let jwks = json!({"keys":[{"kty":"OKP", "crv":"Ed25519", "alg":"EdDSA", "kid":"key-1",
        "x":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())}]});
    update(&mut state, &root, json!({"bound_claims":{"value":42}})).unwrap();
    for (value, accepted) in [(json!(42.9), true), (json!([42]), false)] {
        let body = login_body(&pair, json!({"value":value}));
        let plan = state
            .prepare_remote_jwt_login("team", "auth/bound/login", "POST", &body, 1050)
            .unwrap()
            .unwrap();
        let before = state.tokens.len();
        let result = state.finish_remote_jwt_login(
            plan,
            RemoteJwtLoginObservation::from_test_jwks(&jwks).unwrap(),
            1051,
        );
        if accepted {
            assert_eq!(result.unwrap().status, 200);
            assert_eq!(state.tokens.len(), before + 1);
        } else {
            assert_eq!(result.err().unwrap().status, 400);
            assert_eq!(state.tokens.len(), before);
        }
    }
    let body = login_body(&pair, json!({"value":42}));
    let plan = state
        .prepare_remote_jwt_login("team", "auth/bound/login", "POST", &body, 1050)
        .unwrap()
        .unwrap();
    update(&mut state, &root, json!({"bound_claims":{"value":43}})).unwrap();
    let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    assert_eq!(
        state
            .finish_remote_jwt_login(
                plan,
                RemoteJwtLoginObservation::from_test_jwks(&jwks).unwrap(),
                1051,
            )
            .err()
            .unwrap()
            .status,
        409
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), *before);
}
