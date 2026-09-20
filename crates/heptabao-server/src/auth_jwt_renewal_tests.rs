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
