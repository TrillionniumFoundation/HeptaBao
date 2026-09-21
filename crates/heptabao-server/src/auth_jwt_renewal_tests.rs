use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};

fn fixture() -> (AuthState, Principal, String) {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[57; 32]).unwrap();
    let (mut state, _, root) = setup();
    configured_jwt_mount(
        &mut state,
        &root,
        "workload",
        pair.public_key().as_ref(),
        "EdDSA",
    );
    put_policy(
        &mut state,
        &root,
        "team",
        "reader",
        json!(r#"path "auth/token/*" { capabilities = ["read", "update", "sudo"] }"#),
    );
    let mut claims = jwt_claims("renewal");
    claims["exp"] = json!(1052);
    let jwt = signed_jwt(&pair, &json!({"alg":"EdDSA","kid":"key-1"}), &claims);
    let response = state
        .handle(
            None,
            "team",
            "POST",
            "auth/workload/login",
            &json!({"role":"app","jwt":jwt}),
            1050,
        )
        .unwrap()
        .unwrap();
    assert_eq!(response.body["auth"]["lease_duration"], 600);
    let raw = response.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let bytes = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    assert!(!String::from_utf8_lossy(&bytes).contains(&jwt));
    let state: AuthState = serde_json::from_slice(&bytes).unwrap();
    state.validate_jwt_renewal_state().unwrap();
    (state, root, raw)
}

fn renew(
    state: &mut AuthState,
    root: &Principal,
    raw: &str,
    operation: &str,
    increment: u64,
    now: u64,
) -> Result<AuthResponse, AuthError> {
    let actor = state.authenticate(raw, now)?;
    let body = match operation {
        "renew" => json!({"token":raw,"increment":increment}),
        "renew-accessor" => {
            json!({"accessor":state.tokens[&actor.digest].accessor,"increment":increment})
        }
        _ => json!({"increment":increment}),
    };
    state
        .handle(
            Some(if operation == "renew-self" {
                &actor
            } else {
                root
            }),
            "team",
            "POST",
            &format!("auth/token/{operation}"),
            &body,
            now,
        )?
        .ok_or_else(|| bad("missing renewal response"))
}

#[test]
fn jwt_all_renewal_routes_require_the_live_role_without_rechecking_the_assertion() {
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let (mut state, root, raw) = fixture();
        let id = hash(&raw);
        assert!(
            matches!(&state.tokens[&id].auth_provenance, Some(TokenAuthProvenance::Jwt { role_name }) if role_name == "app")
        );
        assert_eq!(state.tokens[&id].max_expires_at, None);
        // The assertion expired at 1052. A changed trust configuration and
        // role policy/claim binding must not become renewal predicates.
        let scope = AuthScope {
            namespace: "team",
            mount: "workload",
        };
        state.jwt_at_mut(scope).config = None;
        let role = state.jwt_at_mut(scope).roles.get_mut("app").unwrap();
        role.policies = BTreeSet::from(["new-policy".into()]);
        role.bound_subject = Some("other-subject".into());
        role.bound_groups = BTreeSet::from(["other-group".into()]);
        let response = renew(&mut state, &root, &raw, operation, 500, 1100).unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], 500);
        assert_eq!(response.body["auth"]["metadata"], json!({"role":"app"}));
        assert_eq!(response.body["auth"]["orphan"], true);
        assert!(state.tokens[&id].policies.contains("reader"));
        assert!(!state.tokens[&id].policies.contains("new-policy"));
        let removed = state.jwt_at_mut(scope).roles.remove("app").unwrap();
        state.validate_jwt_renewal_state().unwrap();
        let before = state.tokens[&id].expires_at;
        assert_eq!(
            renew(&mut state, &root, &raw, operation, 600, 1101)
                .err()
                .unwrap()
                .status,
            500
        );
        assert_eq!(state.tokens[&id].expires_at, before);
        state.jwt_at_mut(scope).roles.insert("app".into(), removed);
        assert_eq!(
            renew(&mut state, &root, &raw, operation, 600, 1102)
                .unwrap()
                .status,
            200
        );
    }
}

#[test]
fn jwt_current_role_and_mount_maxima_count_from_issue_time_and_can_increase() {
    for mount_limit in [false, true] {
        let (mut state, root, raw) = fixture();
        let id = hash(&raw);
        let scope = AuthScope {
            namespace: "team",
            mount: "workload",
        };
        if mount_limit {
            call(
                &mut state,
                &root,
                "team",
                "POST",
                "sys/auth/workload/tune",
                json!({"default_lease_ttl":30,"max_lease_ttl":90}),
                1100,
            );
        } else {
            let role = state.jwt_at_mut(scope).roles.get_mut("app").unwrap();
            role.token_ttl = 30;
            role.token_max_ttl = 90;
        }
        let mut limited = state.clone();
        assert_eq!(
            renew(&mut limited, &root, &raw, "renew-self", 300, 1100)
                .unwrap()
                .body["auth"]["lease_duration"],
            40
        );
        assert_eq!(limited.tokens[&id].expires_at, Some(1140));
        // Keep the old unexpired lease to distinguish max-age failure from
        // ordinary expired-token rejection.
        let before = state.tokens[&id].expires_at;
        assert_eq!(
            renew(&mut state, &root, &raw, "renew-self", 300, 1140)
                .err()
                .unwrap()
                .status,
            500
        );
        assert_eq!(state.tokens[&id].expires_at, before);
        if mount_limit {
            call(
                &mut state,
                &root,
                "team",
                "POST",
                "sys/auth/workload/tune",
                json!({"default_lease_ttl":30,"max_lease_ttl":1800}),
                1141,
            );
        }
        state
            .jwt_at_mut(scope)
            .roles
            .get_mut("app")
            .unwrap()
            .token_max_ttl = 1800;
        assert_eq!(
            renew(&mut state, &root, &raw, "renew-self", 1200, 1141)
                .unwrap()
                .body["auth"]["lease_duration"],
            1200
        );
        assert_eq!(state.tokens[&id].expires_at, Some(2341));
    }
}

#[test]
fn jwt_role_api_issues_periodic_tokens_with_a_fixed_explicit_maximum() {
    let (mut state, root, _) = fixture();
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/workload/role/app",
        json!({"bound_audiences":["https://service.example/bao"],"token_ttl":60,"token_max_ttl":90,"token_period":20,"token_explicit_max_ttl":120}),
        1050,
    );
    let pair = Ed25519KeyPair::from_seed_unchecked(&[57; 32]).unwrap();
    let jwt = signed_jwt(
        &pair,
        &json!({"alg":"EdDSA","kid":"key-1"}),
        &jwt_claims("periodic"),
    );
    let response = state
        .handle(
            None,
            "team",
            "POST",
            "auth/workload/login",
            &json!({"role":"app","jwt":jwt}),
            1050,
        )
        .unwrap()
        .unwrap();
    assert_eq!(response.body["auth"]["lease_duration"], 20);
    let raw = response.body["auth"]["client_token"].as_str().unwrap();
    let id = hash(raw);
    assert_eq!(state.tokens[&id].period, 20);
    assert_eq!(state.tokens[&id].max_expires_at, Some(1170));
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/workload/role/app",
        json!({"bound_audiences":["other"],"token_ttl":3,"token_max_ttl":3,"token_period":20,"token_explicit_max_ttl":1}),
        1054,
    );
    assert_eq!(
        renew(&mut state, &root, raw, "renew-self", 300, 1054)
            .unwrap()
            .body["auth"]["lease_duration"],
        3
    );
    assert_eq!(state.tokens[&id].max_expires_at, Some(1170));
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/workload/role/app",
        json!({"bound_audiences":["other"],"token_ttl":60,"token_max_ttl":90,"token_period":10,"token_explicit_max_ttl":1}),
        1055,
    );
    assert_eq!(
        renew(&mut state, &root, raw, "renew-self", 300, 1055)
            .unwrap()
            .body["auth"]["lease_duration"],
        10
    );
}

#[test]
fn jwt_period_and_explicit_maximum_keep_distinct_lifetime_semantics() {
    let (state, root, raw) = fixture();
    let id = hash(&raw);
    let scope = AuthScope {
        namespace: "team",
        mount: "workload",
    };
    for (explicit, expected) in [(None, 90), (Some(1680), 80)] {
        let mut state = state.clone();
        state.tokens.get_mut(&id).unwrap().max_expires_at = explicit;
        let role = state.jwt_at_mut(scope).roles.get_mut("app").unwrap();
        role.token_ttl = 30;
        role.token_max_ttl = 90;
        role.token_period = 120;
        // The currently configured explicit max does not replace the issued
        // token's explicit max; native JWT renewal only updates TTL/max/period.
        role.token_explicit_max_ttl = 1;
        assert_eq!(
            renew(&mut state, &root, &raw, "renew-self", 1, 1600)
                .unwrap()
                .body["auth"]["lease_duration"],
            expected
        );
        assert_eq!(state.tokens[&id].max_expires_at, explicit);
        if explicit.is_none() {
            assert_eq!(
                renew(&mut state, &root, &raw, "renew-self", 1, 1680)
                    .unwrap()
                    .body["auth"]["lease_duration"],
                90
            );
        }
    }
    let mut state = state;
    state.tokens.get_mut(&id).unwrap().max_expires_at = Some(1700);
    let role = state.jwt_at_mut(scope).roles.get_mut("app").unwrap();
    role.token_max_ttl = 1800;
    role.token_explicit_max_ttl = 1800;
    assert_eq!(
        renew(&mut state, &root, &raw, "renew-self", 1000, 1600)
            .unwrap()
            .body["auth"]["lease_duration"],
        100
    );
}

#[test]
fn jwt_token_api_descendants_do_not_inherit_role_and_ambiguous_legacy_orphans_fail_closed() {
    for orphan in [false, true] {
        let (mut state, root, raw) = fixture();
        let issuer = state.authenticate(&raw, 1100).unwrap();
        let child = call(
            &mut state,
            &issuer,
            "team",
            "POST",
            "auth/token/create",
            json!({"policies":["default"],"ttl":120,"no_parent":orphan}),
            1100,
        );
        let child_raw = child.body["auth"]["client_token"].as_str().unwrap();
        let child_id = hash(child_raw);
        assert!(matches!(
            state.tokens[&child_id].auth_provenance,
            Some(TokenAuthProvenance::TokenApi)
        ));
        state
            .jwt_at_mut(AuthScope {
                namespace: "team",
                mount: "workload",
            })
            .roles
            .clear();
        assert_eq!(
            renew(&mut state, &root, child_raw, "renew-self", 120, 1110)
                .unwrap()
                .status,
            200
        );
        state.tokens.get_mut(&child_id).unwrap().auth_provenance = None;
        state.tokens.get_mut(&child_id).unwrap().auth_mount = Some("workload".into());
        let before = state.tokens[&child_id].expires_at;
        let result = renew(&mut state, &root, child_raw, "renew-self", 120, 1111);
        if orphan {
            assert_eq!(result.err().unwrap().status, 400);
            assert_eq!(state.tokens[&child_id].expires_at, before);
        } else {
            assert_eq!(result.unwrap().status, 200);
        }
        state
            .tokens
            .get_mut(&issuer.digest)
            .unwrap()
            .auth_provenance = None;
        assert_eq!(
            renew(&mut state, &root, &raw, "renew-self", 120, 1112)
                .err()
                .unwrap()
                .status,
            400
        );
        assert!(state.authenticate(&raw, 1113).is_ok());
    }
}

#[test]
fn jwt_provenance_validation_rejects_impossible_issuer_shapes() {
    let (state, _, raw) = fixture();
    let id = hash(&raw);
    for field in ["parent", "role", "root", "origin", "certificate", "mount"] {
        let mut state = state.clone();
        let token = state.tokens.get_mut(&id).unwrap();
        match field {
            "parent" => token.parent = Some("parent".into()),
            "role" => {
                token.auth_provenance = Some(TokenAuthProvenance::Jwt {
                    role_name: "../invalid".into(),
                })
            }
            "root" => token.root = true,
            "origin" => token.auth_origin_known = false,
            "certificate" => token.auth_cert_role = Some("cert".into()),
            _ => token.auth_mount = Some("missing".into()),
        }
        assert!(state.validate_jwt_renewal_state().is_err(), "{field}");
    }
}

fn native_ttl_role(
    state: &mut AuthState,
    root: &Principal,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(
            Some(root),
            "team",
            "POST",
            "auth/workload/role/app",
            &body,
            1050,
        )?
        .ok_or_else(|| bad("missing JWT role route"))
}

fn native_ttl_fixture() -> (AuthState, Principal) {
    let (mut state, root, _) = fixture();
    call(
        &mut state,
        &root,
        "team",
        "DELETE",
        "auth/workload/role/app",
        json!({}),
        1050,
    );
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "sys/auth/workload/tune",
        json!({"default_lease_ttl":75,"max_lease_ttl":600}),
        1050,
    );
    (state, root)
}

fn native_ttl_login(state: &mut AuthState) -> AuthResponse {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[57; 32]).unwrap();
    let jwt = signed_jwt(
        &pair,
        &json!({"alg":"EdDSA","kid":"key-1"}),
        &jwt_claims("native-ttl"),
    );
    state
        .handle(
            None,
            "team",
            "POST",
            "auth/workload/login",
            &json!({"role":"app","jwt":jwt}),
            1050,
        )
        .unwrap()
        .unwrap()
}

#[test]
fn jwt_native_role_zero_defaults_issue_and_renew_using_current_mount_limits() {
    for (limits, stored_ttl, stored_max, expected) in [
        (json!({}), 0, 0, 75),
        (json!({"token_ttl":null,"token_max_ttl":null}), 0, 0, 75),
        (json!({"token_ttl":0,"token_max_ttl":0}), 0, 0, 75),
        (json!({"token_ttl":120,"token_max_ttl":0}), 120, 0, 120),
        (json!({"token_ttl":0,"token_max_ttl":90}), 0, 90, 75),
    ] {
        let (mut state, root) = native_ttl_fixture();
        assert!(!state.has_jwt_native_ttl_defaults());
        let mut body =
            json!({"role_type":"jwt","bound_subject":"alice","token_policies":["reader"]});
        body.as_object_mut()
            .unwrap()
            .extend(limits.as_object().unwrap().clone());
        native_ttl_role(&mut state, &root, body).unwrap();
        let read = call(
            &mut state,
            &root,
            "team",
            "GET",
            "auth/workload/role/app",
            json!({}),
            1050,
        );
        assert_eq!(read.body["data"]["token_ttl"], stored_ttl);
        assert_eq!(read.body["data"]["token_max_ttl"], stored_max);
        assert!(state.has_jwt_native_ttl_defaults());
        // The actual signed-assertion path proves zero service-token limits do
        // not become invalid zero assertion-lifetime TrustPolicy values.
        let issued = native_ttl_login(&mut state);
        assert_eq!(issued.body["auth"]["lease_duration"], expected);
        let raw = issued.body["auth"]["client_token"].as_str().unwrap();
        assert_eq!(state.tokens[&hash(raw)].max_expires_at, None);
        let bytes = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        let reopened: AuthState = serde_json::from_slice(&bytes).unwrap();
        reopened.validate_jwt_renewal_state().unwrap();
        assert!(reopened.has_jwt_native_ttl_defaults());
        for operation in ["renew-self", "renew", "renew-accessor"] {
            for explicit_zero in [false, true] {
                let mut renewed = reopened.clone();
                let actor = renewed.authenticate(raw, 1051).unwrap();
                let mut body = match operation {
                    "renew" => json!({"token":raw}),
                    "renew-accessor" => json!({"accessor":renewed.tokens[&actor.digest].accessor}),
                    _ => json!({}),
                };
                if explicit_zero {
                    body["increment"] = json!(0);
                }
                let result = renewed
                    .handle(
                        Some(if operation == "renew-self" {
                            &actor
                        } else {
                            &root
                        }),
                        "team",
                        "POST",
                        &format!("auth/token/{operation}"),
                        &body,
                        1051,
                    )
                    .unwrap()
                    .unwrap();
                assert_eq!(result.body["auth"]["lease_duration"], expected);
            }
        }
    }
}

#[test]
fn jwt_native_role_null_preserves_each_duration_but_zero_resets_it() {
    let (mut state, root) = native_ttl_fixture();
    native_ttl_role(
        &mut state,
        &root,
        json!({"role_type":"jwt","bound_subject":"alice",
        "token_ttl":40,"token_max_ttl":300,"token_period":20,"token_explicit_max_ttl":200}),
    )
    .unwrap();
    let scope = AuthScope {
        namespace: "team",
        mount: "workload",
    };
    let before = state.jwt_at(scope).unwrap().roles["app"].clone();
    native_ttl_role(
        &mut state,
        &root,
        json!({"token_ttl":null,"token_max_ttl":null,
        "token_period":null,"token_explicit_max_ttl":null}),
    )
    .unwrap();
    assert_eq!(state.jwt_at(scope).unwrap().roles["app"], before);
    native_ttl_role(&mut state, &root, json!({"token_ttl":50})).unwrap();
    let role = &state.jwt_at(scope).unwrap().roles["app"];
    assert_eq!(
        (
            role.token_ttl,
            role.token_max_ttl,
            role.token_period,
            role.token_explicit_max_ttl
        ),
        (50, 300, 20, 200)
    );
    native_ttl_role(
        &mut state,
        &root,
        json!({"token_ttl":0,"token_max_ttl":0,
        "token_period":0,"token_explicit_max_ttl":0}),
    )
    .unwrap();
    let role = &state.jwt_at(scope).unwrap().roles["app"];
    assert_eq!(
        (
            role.token_ttl,
            role.token_max_ttl,
            role.token_period,
            role.token_explicit_max_ttl
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(
        native_ttl_login(&mut state).body["auth"]["lease_duration"],
        75
    );
}

#[test]
fn jwt_native_role_zero_max_tracks_mount_but_explicit_cap_stays_at_issue() {
    for explicit in [0, 100] {
        let (mut state, root) = native_ttl_fixture();
        native_ttl_role(
            &mut state,
            &root,
            json!({"role_type":"jwt","bound_subject":"alice",
            "token_policies":["reader"],"token_explicit_max_ttl":explicit}),
        )
        .unwrap();
        let issued = native_ttl_login(&mut state);
        let raw = issued.body["auth"]["client_token"].as_str().unwrap();
        call(
            &mut state,
            &root,
            "team",
            "POST",
            "sys/auth/workload/tune",
            json!({"default_lease_ttl":80,"max_lease_ttl":1200}),
            1051,
        );
        // An updated role explicit maximum only applies to future logins.
        native_ttl_role(&mut state, &root, json!({"token_explicit_max_ttl":600})).unwrap();
        let result = renew(&mut state, &root, raw, "renew-self", 900, 1051).unwrap();
        assert_eq!(
            result.body["auth"]["lease_duration"],
            if explicit == 0 { 900 } else { 99 }
        );
        assert_eq!(
            state.tokens[&hash(raw)].max_expires_at,
            if explicit == 0 { None } else { Some(1150) }
        );
    }
    let (mut state, root) = native_ttl_fixture();
    native_ttl_role(
        &mut state,
        &root,
        json!({"role_type":"jwt","bound_subject":"alice",
        "token_policies":["reader"],"token_period":800,"token_explicit_max_ttl":650}),
    )
    .unwrap();
    let issued = native_ttl_login(&mut state);
    assert_eq!(issued.body["auth"]["lease_duration"], 600);
    let raw = issued.body["auth"]["client_token"].as_str().unwrap();
    let result = renew(&mut state, &root, raw, "renew-self", 1, 1100).unwrap();
    assert_eq!(result.body["auth"]["lease_duration"], 600);
    assert_eq!(state.tokens[&hash(raw)].period, 800);
}

#[test]
fn jwt_native_role_invalid_durations_are_atomic_and_persisted_limits_are_checked() {
    let (mut state, root) = native_ttl_fixture();
    native_ttl_role(
        &mut state,
        &root,
        json!({"role_type":"jwt","bound_subject":"alice"}),
    )
    .unwrap();
    for body in [
        json!({"token_ttl":91,"token_max_ttl":90}),
        json!({"token_ttl":-1}),
        json!({"token_max_ttl":"invalid"}),
        json!({"token_period":MAX_TTL+1}),
        json!({"token_explicit_max_ttl":MAX_TTL+1}),
    ] {
        let before = provider_renewal::state_revision(&state).unwrap();
        assert_eq!(
            native_ttl_role(&mut state, &root, body)
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    }
    for (ttl, max) in [(MAX_TTL + 1, 0), (0, MAX_TTL + 1), (91, 90)] {
        let mut corrupt = state.clone();
        let role = corrupt
            .jwt_at_mut(AuthScope {
                namespace: "team",
                mount: "workload",
            })
            .roles
            .get_mut("app")
            .unwrap();
        role.token_ttl = ttl;
        role.token_max_ttl = max;
        assert!(corrupt.validate_jwt_renewal_state().is_err());
    }
}

#[test]
fn jwt_legacy_positive_role_limits_survive_read_partial_update_and_reopen() {
    let bytes = br#"{"bound_groups":[],"bound_subject":null,"bound_audiences":[],"policies":["default"],"token_ttl":3600,"token_max_ttl":3600,"token_num_uses":0}"#;
    let role: JwtRole = serde_json::from_slice(bytes).unwrap();
    assert_eq!(serde_json::to_vec(&role).unwrap(), bytes);
    let (mut state, root) = native_ttl_fixture();
    state
        .jwt_at_mut(AuthScope {
            namespace: "team",
            mount: "workload",
        })
        .roles
        .insert("app".into(), role);
    assert!(!state.has_jwt_native_ttl_defaults());
    native_ttl_role(
        &mut state,
        &root,
        json!({"token_period":null,"token_ttl":null,"token_num_uses":2}),
    )
    .unwrap();
    let bytes = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut reopened: AuthState = serde_json::from_slice(&bytes).unwrap();
    reopened.validate_jwt_renewal_state().unwrap();
    assert!(!reopened.has_jwt_native_ttl_defaults());
    let read = call(
        &mut reopened,
        &root,
        "team",
        "GET",
        "auth/workload/role/app",
        json!({}),
        1050,
    );
    assert_eq!(read.body["data"]["token_ttl"], 3600);
    assert_eq!(read.body["data"]["token_max_ttl"], 3600);
    assert_eq!(read.body["data"]["token_num_uses"], 2);
}

#[test]
fn jwt_zero_service_ttl_does_not_relax_the_legacy_assertion_lifetime_limit() {
    let (mut state, root) = native_ttl_fixture();
    native_ttl_role(
        &mut state,
        &root,
        json!({"role_type":"jwt","bound_subject":"alice"}),
    )
    .unwrap();
    let pair = Ed25519KeyPair::from_seed_unchecked(&[57; 32]).unwrap();
    let mut claims = jwt_claims("overlong-assertion");
    claims["exp"] = json!(4601); // Explicit config allows at most 3600s from iat=1000.
    let jwt = signed_jwt(&pair, &json!({"alg":"EdDSA","kid":"key-1"}), &claims);
    let before = provider_renewal::state_revision(&state).unwrap();
    assert_eq!(
        state
            .handle(
                None,
                "team",
                "POST",
                "auth/workload/login",
                &json!({"role":"app","jwt":jwt}),
                1050
            )
            .err()
            .unwrap()
            .status,
        400
    );
    assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    assert_eq!(
        native_ttl_login(&mut state).body["auth"]["lease_duration"],
        75
    );
}
