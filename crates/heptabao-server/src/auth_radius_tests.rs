#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;

fn fixture() -> (AuthState, String, String) {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    let actor = state.authenticate(&root, 100).unwrap();
    for (path, body) in [
        ("sys/auth/radius", json!({"type":"radius"})),
        (
            "sys/policies/acl/issuer",
            json!({"policy":"path \"auth/token/*\" { capabilities = [\"read\", \"update\", \"sudo\"] }"}),
        ),
        (
            "auth/radius/config",
            json!({"url":"radius://radius.example.test:1812", "token_policies":["issuer"], "token_ttl":120, "token_max_ttl":600}),
        ),
    ] {
        state
            .handle(Some(&actor), "", "POST", path, &body, 100)
            .unwrap()
            .unwrap();
    }
    let plan = state
        .prepare_radius_login(
            "",
            "radius",
            "POST",
            &json!({"username":"alice","password":"synthetic-radius-password"}),
            100,
        )
        .unwrap();
    let response = state
        .finish_radius_login(plan, RadiusLoginObservation)
        .unwrap();
    let raw = response.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    (state, root, raw)
}

fn prepare(state: &mut AuthState, raw: &str, now: u64) -> (Principal, RadiusRenewalPlan) {
    let actor = state.authenticate(raw, now).unwrap();
    let plan = state
        .prepare_radius_renewal(
            Some(&actor),
            "",
            "POST",
            "auth/token/renew-self",
            &json!({"increment":300}),
            now,
        )
        .unwrap()
        .unwrap();
    (actor, plan)
}

#[test]
fn radius_renewal_credentials_survive_serialization_but_never_reach_token_output() {
    let (state, _, raw) = fixture();
    let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut state: AuthState = serde_json::from_slice(&encoded).unwrap();
    state.validate_radius_renewal_state().unwrap();
    let id = hash(&raw);
    assert!(matches!(
        state.tokens[&id].auth_provenance,
        Some(TokenAuthProvenance::Radius { .. })
    ));
    assert!(
        !token_info(&state.tokens[&id], 110)
            .to_string()
            .contains("password")
    );
    assert!(
        !token_info(&state.tokens[&id], 110)
            .to_string()
            .contains("credential")
    );
    let (actor, plan) = prepare(&mut state, &raw, 110);
    let before = state.tokens[&id].expires_at;
    let bypass = state.handle(
        Some(&actor),
        "",
        "POST",
        "auth/token/renew-self",
        &json!({}),
        110,
    );
    assert_eq!(bypass.err().unwrap().status, 503);
    assert_eq!(state.tokens[&id].expires_at, before);
    let response = state
        .finish_radius_renewal(plan, &actor, RadiusRenewalObservation, 111)
        .unwrap();
    assert_eq!(response.body["auth"]["lease_duration"], 300);
    assert_eq!(state.tokens[&id].expires_at, Some(411));
    assert!(
        !response
            .body
            .to_string()
            .contains("synthetic-radius-password")
    );
}

#[test]
fn radius_renewal_rejects_stale_target_config_mount_actor_and_expired_authority() {
    for mutation in ["target", "config", "mount", "actor", "expiry", "acl"] {
        let (mut state, root, raw) = fixture();
        let actor = state.authenticate(&root, 110).unwrap();
        let plan = state
            .prepare_radius_renewal(
                Some(&actor),
                "",
                "POST",
                "auth/token/renew",
                &json!({"token":raw,"increment":300}),
                110,
            )
            .unwrap()
            .unwrap();
        let id = hash(&raw);
        let before = state.tokens[&id].expires_at;
        let mut now = 111;
        match mutation {
            "target" => state.tokens.get_mut(&id).unwrap().accessor.push('x'),
            "config" => {
                state
                    .radius_mounts
                    .get_mut("")
                    .unwrap()
                    .get_mut("radius")
                    .unwrap()
                    .token_ttl = 90
            }
            "mount" => {
                state
                    .auth_mounts
                    .get_mut("")
                    .unwrap()
                    .get_mut("radius")
                    .unwrap()
                    .revision += 1
            }
            "actor" => state.revoke(&hash(&root)),
            "expiry" => now = 999,
            "acl" => {
                let root_token = state.tokens.get_mut(&hash(&root)).unwrap();
                root_token.root = false;
                root_token.policies.clear();
            }
            _ => unreachable!(),
        }
        assert!(
            state
                .finish_radius_renewal(plan, &actor, RadiusRenewalObservation, now)
                .is_err(),
            "{mutation}"
        );
        assert_eq!(
            state.tokens.get(&id).and_then(|token| token.expires_at),
            before,
            "{mutation}"
        );
    }
}

#[test]
fn radius_renewal_checks_live_policy_after_provider_and_uses_current_ttl_limits() {
    let (mut state, _, raw) = fixture();
    state
        .radius_mounts
        .get_mut("")
        .unwrap()
        .get_mut("radius")
        .unwrap()
        .policies
        .insert("new-grant".into());
    let (actor, plan) = prepare(&mut state, &raw, 110);
    let before = state.tokens[&hash(&raw)].expires_at;
    assert_eq!(
        state
            .finish_radius_renewal(plan, &actor, RadiusRenewalObservation, 111)
            .err()
            .unwrap()
            .status,
        500
    );
    assert_eq!(state.tokens[&hash(&raw)].expires_at, before);
    let config = state
        .radius_mounts
        .get_mut("")
        .unwrap()
        .get_mut("radius")
        .unwrap();
    config.policies.remove("new-grant");
    config.policies.remove("default"); // OpenBao ignores this implicit policy during equivalence.
    config.token_ttl = 45;
    config.token_max_ttl = 90;
    let actor = state.authenticate(&raw, 120).unwrap();
    let plan = state
        .prepare_radius_renewal(
            Some(&actor),
            "",
            "POST",
            "auth/token/renew-self",
            &json!({}),
            120,
        )
        .unwrap()
        .unwrap();
    let response = state
        .finish_radius_renewal(plan, &actor, RadiusRenewalObservation, 121)
        .unwrap();
    assert_eq!(response.body["auth"]["lease_duration"], 45);
    assert_eq!(state.tokens[&hash(&raw)].expires_at, Some(166));
}

#[test]
fn token_api_children_never_copy_radius_password_and_legacy_orphans_fail_closed() {
    let (mut state, _, raw) = fixture();
    let actor = state.authenticate(&raw, 101).unwrap();
    let mut children = Vec::new();
    for orphan in [false, true] {
        let response = state
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/token/create",
                &json!({"policies":["default"],"no_parent":orphan}),
                101,
            )
            .unwrap()
            .unwrap();
        let child = response.body["auth"]["client_token"]
            .as_str()
            .unwrap()
            .to_owned();
        let encoded = serde_json::to_string(&state.tokens[&hash(&child)]).unwrap();
        assert!(!encoded.contains("synthetic-radius-password"));
        assert!(!encoded.contains("credential"));
        assert!(matches!(
            state.tokens[&hash(&child)].auth_provenance,
            Some(TokenAuthProvenance::TokenApi)
        ));
        let child_actor = state.authenticate(&child, 102).unwrap();
        assert!(
            state
                .prepare_radius_renewal(
                    Some(&child_actor),
                    "",
                    "POST",
                    "auth/token/renew-self",
                    &json!({}),
                    102
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(
            state
                .handle(
                    Some(&child_actor),
                    "",
                    "POST",
                    "auth/token/renew-self",
                    &json!({}),
                    102
                )
                .unwrap()
                .unwrap()
                .status,
            200
        );
        children.push((child, orphan));
    }
    state.tokens.get_mut(&hash(&raw)).unwrap().auth_provenance = None;
    let parent_before = state.tokens[&hash(&raw)].expires_at;
    let actor = state.authenticate(&raw, 103).unwrap();
    assert_eq!(
        state
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/token/renew-self",
                &json!({}),
                103
            )
            .err()
            .unwrap()
            .status,
        400
    );
    assert_eq!(state.tokens[&hash(&raw)].expires_at, parent_before);
    for (child, orphan) in children {
        state.tokens.get_mut(&hash(&child)).unwrap().auth_provenance = None;
        let actor = state.authenticate(&child, 103).unwrap();
        let result = state.handle(
            Some(&actor),
            "",
            "POST",
            "auth/token/renew-self",
            &json!({}),
            103,
        );
        if orphan {
            assert_eq!(result.err().unwrap().status, 400);
        } else {
            assert_eq!(result.unwrap().unwrap().status, 200);
        }
    }
}

#[test]
fn radius_provenance_rejects_malformed_or_transplanted_credentials() {
    for mutation in ["empty", "oversize", "nul", "parent", "mount", "root"] {
        let (mut state, _, raw) = fixture();
        let token = state.tokens.get_mut(&hash(&raw)).unwrap();
        match mutation {
            "parent" => token.parent = Some("unrelated".into()),
            "mount" => token.auth_mount = Some("token".into()),
            "root" => token.root = true,
            _ => {
                let Some(TokenAuthProvenance::Radius { credential, .. }) =
                    token.auth_provenance.as_mut()
                else {
                    unreachable!()
                };
                credential.0 = match mutation {
                    "empty" => String::new(),
                    "oversize" => "x".repeat(129),
                    _ => "bad\0secret".into(),
                };
            }
        }
        assert!(state.validate_radius_renewal_state().is_err(), "{mutation}");
    }
}
