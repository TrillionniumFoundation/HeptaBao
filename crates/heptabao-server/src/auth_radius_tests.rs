#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;

fn native_config(state: &mut AuthState, root: &str, body: Value, now: u64) {
    let actor = state.authenticate(root, now).unwrap();
    assert_eq!(
        state
            .handle(Some(&actor), "", "POST", "auth/radius/config", &body, now)
            .unwrap()
            .unwrap()
            .status,
        204
    );
}

fn native_login(state: &mut AuthState, now: u64) -> String {
    let plan = state
        .prepare_radius_login(
            "",
            "radius",
            "POST",
            &json!({"username":"alice","password":"synthetic-radius-password"}),
            now,
        )
        .unwrap();
    state
        .finish_radius_login(plan, RadiusLoginObservation)
        .unwrap()
        .body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .into()
}

fn native_renew(
    state: &mut AuthState,
    root: &str,
    raw: &str,
    operation: &str,
    increment: u64,
    now: u64,
) -> Result<AuthResponse, AuthError> {
    let actor = state.authenticate(if operation == "renew-self" { raw } else { root }, now)?;
    let body = match operation {
        "renew" => json!({"token":raw,"increment":increment}),
        "renew-accessor" => {
            json!({"accessor":state.tokens[&hash(raw)].accessor,"increment":increment})
        }
        _ => json!({"increment":increment}),
    };
    let plan = state
        .prepare_radius_renewal(
            Some(&actor),
            "",
            "POST",
            &format!("auth/token/{operation}"),
            &body,
            now,
        )?
        .ok_or_else(denied)?;
    state.finish_radius_renewal(plan, &actor, RadiusRenewalObservation, now)
}

impl AuthState {
    #[allow(clippy::too_many_arguments)]
    fn prepare_radius_renewal(
        &self,
        actor: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<RadiusRenewalPlan>, AuthError> {
        match self.prepare_provider_renewal(actor, namespace, method, path, body, now)? {
            Some(ProviderRenewalPlan::Radius(plan)) => Ok(Some(plan)),
            None => Ok(None),
            _ => Err(denied()),
        }
    }
}

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
fn radius_login_rejects_observation_from_deleted_and_identically_recreated_mount() {
    let (mut state, root_raw, _) = fixture();
    let root = state.authenticate(&root_raw, 101).unwrap();
    let credentials = json!({"username": "alice", "password": "synthetic-radius-password"});
    let plan = state
        .prepare_radius_login("", "radius", "POST", &credentials, 101)
        .unwrap();
    let old_mount = state.effective_auth_mounts("")["radius"].clone();
    let old_config = plan.config.clone();
    for (method, path, body) in [
        ("DELETE", "sys/auth/radius", json!({})),
        ("POST", "sys/auth/radius", json!({"type": "radius"})),
        (
            "POST",
            "auth/radius/config",
            json!({"url": "radius://radius.example.test:1812",
            "token_policies": ["issuer"], "token_ttl": 120, "token_max_ttl": 600}),
        ),
    ] {
        state
            .handle(Some(&root), "", method, path, &body, 102)
            .unwrap()
            .unwrap();
    }
    assert_eq!(
        state.effective_auth_mounts("")["radius"].kind,
        old_mount.kind
    );
    assert_ne!(
        state.effective_auth_mounts("")["radius"].accessor,
        old_mount.accessor
    );
    assert!(state.radius_mounts[""]["radius"] == old_config);
    let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let rejected = state.finish_radius_login(plan, RadiusLoginObservation);
    assert_eq!(rejected.err().unwrap().status, 409);
    let after = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    assert!(before.as_slice() == after.as_slice());

    // A fresh observation for the replacement mount is still usable; the
    // rejection is tied to the old mount incarnation, not its path or config.
    let current = state
        .prepare_radius_login("", "radius", "POST", &credentials, 103)
        .unwrap();
    let accepted = state
        .finish_radius_login(current, RadiusLoginObservation)
        .unwrap();
    assert_eq!(accepted.status, 200);
    assert!(accepted.body["auth"]["client_token"].as_str().is_some());
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
            Some(TokenAuthProvenance::TokenApi { .. })
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
        let legacy = state.tokens.get_mut(&hash(&child)).unwrap();
        // Simulate the old inherited mount as well as the absent issuer
        // marker; clearing only the marker on a new orphan is not old state.
        legacy.auth_mount = Some("radius".into());
        legacy.auth_provenance = None;
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

#[test]
fn radius_fresh_maximum_can_increase_across_all_renewal_routes_after_reopen() {
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let (mut state, root, raw) = fixture();
        let id = hash(&raw);
        let issued_at = state.tokens[&id].created_at;
        assert_eq!(state.tokens[&id].max_expires_at, None);
        let config = state
            .radius_mounts
            .get_mut("")
            .unwrap()
            .get_mut("radius")
            .unwrap();
        config.token_ttl = 90;
        config.token_max_ttl = 1200;
        let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        let mut state: AuthState = serde_json::from_slice(&encoded).unwrap();
        let actor = state
            .authenticate(
                if operation == "renew-self" {
                    &raw
                } else {
                    &root
                },
                110,
            )
            .unwrap();
        let body = match operation {
            "renew-self" => json!({"increment": 900}),
            "renew" => json!({"token": raw, "increment": 900}),
            _ => json!({"accessor": state.tokens[&id].accessor, "increment": 900}),
        };
        let plan = state
            .prepare_provider_renewal(
                Some(&actor),
                "",
                "POST",
                &format!("auth/token/{operation}"),
                &body,
                110,
            )
            .unwrap()
            .unwrap();
        let response = state
            .finish_provider_renewal(
                plan,
                &actor,
                ProviderRenewalObservation::Radius(RadiusRenewalObservation),
                111,
            )
            .unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], 900);
        assert_eq!(state.tokens[&id].expires_at, Some(1011));
        assert!(state.tokens[&id].expires_at.unwrap() > issued_at + 600);
        assert_eq!(state.tokens[&id].max_expires_at, None);

        let actor = state.authenticate(&raw, 112).unwrap();
        let plan = state
            .prepare_provider_renewal(
                Some(&actor),
                "",
                "POST",
                "auth/token/renew-self",
                &json!({}),
                112,
            )
            .unwrap()
            .unwrap();
        let response = state
            .finish_provider_renewal(
                plan,
                &actor,
                ProviderRenewalObservation::Radius(RadiusRenewalObservation),
                113,
            )
            .unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], 90);
        assert_eq!(state.tokens[&id].expires_at, Some(203));
    }
}

#[test]
fn radius_legacy_absolute_cap_survives_raised_maximum_and_reopen() {
    let (mut state, _, raw) = fixture();
    let id = hash(&raw);
    let legacy_cap = state.tokens[&id].created_at + 600;
    state.tokens.get_mut(&id).unwrap().max_expires_at = Some(legacy_cap);
    let config = state
        .radius_mounts
        .get_mut("")
        .unwrap()
        .get_mut("radius")
        .unwrap();
    config.token_ttl = 90;
    config.token_max_ttl = 1200;
    let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut state: AuthState = serde_json::from_slice(&encoded).unwrap();
    let actor = state.authenticate(&raw, 110).unwrap();
    let plan = state
        .prepare_provider_renewal(
            Some(&actor),
            "",
            "POST",
            "auth/token/renew-self",
            &json!({"increment":900}),
            110,
        )
        .unwrap()
        .unwrap();
    let response = state
        .finish_provider_renewal(
            plan,
            &actor,
            ProviderRenewalObservation::Radius(RadiusRenewalObservation),
            111,
        )
        .unwrap();
    assert_eq!(response.body["auth"]["lease_duration"], legacy_cap - 111);
    assert_eq!(state.tokens[&id].expires_at, Some(legacy_cap));
    assert_eq!(state.tokens[&id].max_expires_at, Some(legacy_cap));
}

#[test]
fn radius_past_current_maximum_returns_500_without_revoking_live_lease() {
    let (mut state, _, raw) = fixture();
    let id = hash(&raw);
    let config = state
        .radius_mounts
        .get_mut("")
        .unwrap()
        .get_mut("radius")
        .unwrap();
    config.token_ttl = 1;
    config.token_max_ttl = 1;
    let actor = state.authenticate(&raw, 110).unwrap();
    let plan = state
        .prepare_provider_renewal(
            Some(&actor),
            "",
            "POST",
            "auth/token/renew-self",
            &json!({}),
            110,
        )
        .unwrap()
        .unwrap();
    let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let expiry = state.tokens[&id].expires_at.unwrap();
    assert_eq!(
        state
            .finish_provider_renewal(
                plan,
                &actor,
                ProviderRenewalObservation::Radius(RadiusRenewalObservation),
                111
            )
            .err()
            .unwrap()
            .status,
        500
    );
    let after = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    assert!(before.as_slice() == after.as_slice());
    assert!(state.authenticate_read_only(&raw, 111).is_ok());
    assert!(state.authenticate_read_only(&raw, expiry).is_err());
}

#[test]
fn radius_native_period_and_issued_explicit_cap_apply_to_all_provider_checked_renewals() {
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let (mut state, root, _) = fixture();
        native_config(
            &mut state,
            &root,
            json!({"token_ttl":40,"token_max_ttl":600,"token_period":30,"token_explicit_max_ttl":90}),
            102,
        );
        let raw = native_login(&mut state, 103);
        let id = hash(&raw);
        let issued = state.tokens[&id].created_at;
        assert_eq!(state.tokens[&id].expires_at, Some(issued + 30));
        assert_eq!(state.tokens[&id].max_expires_at, Some(issued + 90));
        assert_eq!(state.tokens[&id].period, 30);
        let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        let mut state: AuthState = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            native_renew(&mut state, &root, &raw, operation, 300, issued + 1)
                .unwrap()
                .body["auth"]["lease_duration"],
            30
        );
        native_config(
            &mut state,
            &root,
            json!({"token_ttl":3,"token_max_ttl":3,"token_explicit_max_ttl":1}),
            issued + 4,
        );
        assert_eq!(
            native_renew(&mut state, &root, &raw, operation, 300, issued + 4)
                .unwrap()
                .body["auth"]["lease_duration"],
            3
        );
        native_config(
            &mut state,
            &root,
            json!({"token_ttl":40,"token_max_ttl":600,"token_period":45,"token_explicit_max_ttl":0}),
            issued + 5,
        );
        assert_eq!(
            native_renew(&mut state, &root, &raw, operation, 300, issued + 5)
                .unwrap()
                .body["auth"]["lease_duration"],
            45
        );
        assert_eq!(token_info(&state.tokens[&id], issued + 5)["period"], 30);
        native_config(&mut state, &root, json!({"token_period":0}), issued + 6);
        assert_eq!(
            native_renew(&mut state, &root, &raw, operation, 300, issued + 6)
                .unwrap()
                .body["auth"]["lease_duration"],
            84
        );
        assert_eq!(state.tokens[&id].max_expires_at, Some(issued + 90));
        assert_eq!(token_info(&state.tokens[&id], issued + 6)["period"], 30);
    }
}

#[test]
fn radius_current_period_does_not_replace_issue_snapshot_or_retroactively_add_explicit_cap() {
    let (mut state, root, raw) = fixture();
    let id = hash(&raw);
    let issued = state.tokens[&id].created_at;
    native_config(
        &mut state,
        &root,
        json!({"token_period":30,"token_explicit_max_ttl":90}),
        issued + 1,
    );
    assert_eq!(
        native_renew(&mut state, &root, &raw, "renew-self", 300, issued + 1)
            .unwrap()
            .body["auth"]["lease_duration"],
        30
    );
    assert!(
        token_info(&state.tokens[&id], issued + 1)
            .get("period")
            .is_none()
    );
    assert_eq!(state.tokens[&id].max_expires_at, None);
    native_config(&mut state, &root, json!({"token_period":0}), issued + 2);
    assert_eq!(
        native_renew(&mut state, &root, &raw, "renew-self", 300, issued + 2)
            .unwrap()
            .body["auth"]["lease_duration"],
        300
    );
    let fresh = native_login(&mut state, issued + 3);
    let fresh_id = hash(&fresh);
    let fresh_issue = state.tokens[&fresh_id].created_at;
    assert_eq!(state.tokens[&fresh_id].expires_at, Some(fresh_issue + 90));
    assert_eq!(
        state.tokens[&fresh_id].max_expires_at,
        Some(fresh_issue + 90)
    );
}

#[test]
fn radius_partial_configuration_preserves_routes_and_limits_but_policy_null_clears() {
    let (mut state, root, _) = fixture();
    native_config(
        &mut state,
        &root,
        json!({"token_ttl":40,"token_max_ttl":600,"token_period":30,"token_explicit_max_ttl":240,"token_num_uses":4}),
        102,
    );
    native_config(&mut state, &root, json!({"token_max_ttl":500}), 103);
    native_config(
        &mut state,
        &root,
        json!({"token_ttl":null,"token_max_ttl":null,"token_period":null,"token_explicit_max_ttl":null}),
        104,
    );
    let actor = state.authenticate(&root, 104).unwrap();
    let data = state
        .handle(
            Some(&actor),
            "",
            "GET",
            "auth/radius/config",
            &json!({}),
            104,
        )
        .unwrap()
        .unwrap()
        .body["data"]
        .clone();
    assert_eq!(data["url"], "radius://radius.example.test:1812");
    for (field, value) in [
        ("token_ttl", 40),
        ("token_max_ttl", 500),
        ("token_period", 30),
        ("token_explicit_max_ttl", 240),
    ] {
        assert_eq!(data[field], value);
    }
    assert_eq!(data["token_policies"], json!(["issuer"]));
    assert_eq!(data["token_num_uses"], 4);
    native_config(&mut state, &root, json!({"token_num_uses":null}), 105);
    assert_eq!(state.radius_mounts[""]["radius"].token_num_uses, 0);
    for value in [Value::Null, json!([])] {
        native_config(&mut state, &root, json!({"token_policies":["issuer"]}), 105);
        native_config(&mut state, &root, json!({"token_policies":value}), 106);
        assert!(state.radius_mounts[""]["radius"].policies.is_empty());
        let raw = native_login(&mut state, 107);
        assert_eq!(
            state.tokens[&hash(&raw)].policies,
            BTreeSet::from(["default".into()])
        );
    }
    for body in [
        json!({"url":null}),
        json!({"token_period":MAX_TTL+1}),
        json!({"token_explicit_max_ttl":MAX_TTL+1}),
        json!({"token_period":-1}),
        json!({"token_explicit_max_ttl":-1}),
        json!({"policies":["default"],"token_policies":[]}),
    ] {
        let before = state_revision(&state).unwrap();
        assert_eq!(
            state
                .handle(Some(&actor), "", "POST", "auth/radius/config", &body, 108)
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(state_revision(&state).unwrap(), before);
    }
}

#[test]
fn radius_zero_ttl_uses_mount_defaults_and_old_caps_remain_conservative() {
    let (mut state, root, raw) = fixture();
    let id = hash(&raw);
    let issued = state.tokens[&id].created_at;
    let actor = state.authenticate(&root, issued).unwrap();
    state
        .handle(
            Some(&actor),
            "",
            "POST",
            "sys/auth/radius/tune",
            &json!({"default_lease_ttl":75,"max_lease_ttl":600}),
            issued,
        )
        .unwrap()
        .unwrap();
    native_config(
        &mut state,
        &root,
        json!({"token_ttl":0,"token_max_ttl":500}),
        issued,
    );
    let fresh = native_login(&mut state, issued + 1);
    let fresh_id = hash(&fresh);
    let fresh_issue = state.tokens[&fresh_id].created_at;
    assert_eq!(state.tokens[&fresh_id].expires_at, Some(fresh_issue + 75));
    assert_eq!(
        native_renew(&mut state, &root, &fresh, "renew-self", 0, fresh_issue + 1)
            .unwrap()
            .body["auth"]["lease_duration"],
        75
    );
    state.tokens.get_mut(&id).unwrap().max_expires_at = Some(issued + 50);
    native_config(&mut state, &root, json!({"token_period":30}), issued + 40);
    assert_eq!(
        native_renew(&mut state, &root, &raw, "renew-self", 300, issued + 40)
            .unwrap()
            .body["auth"]["lease_duration"],
        10
    );
    assert_eq!(state.tokens[&id].max_expires_at, Some(issued + 50));
}

#[test]
fn radius_native_config_changes_during_provider_roundtrip_reject_atomically() {
    for field in ["token_period", "token_explicit_max_ttl"] {
        let (mut state, root, raw) = fixture();
        let (actor, plan) = prepare(&mut state, &raw, 110);
        let mut body = json!({});
        body[field] = json!(30);
        native_config(&mut state, &root, body, 110);
        let before = state_revision(&state).unwrap();
        assert_eq!(
            state
                .finish_radius_renewal(plan, &actor, RadiusRenewalObservation, 111)
                .err()
                .unwrap()
                .status,
            409
        );
        assert_eq!(state_revision(&state).unwrap(), before);
    }
    let (mut state, root, raw) = fixture();
    native_config(
        &mut state,
        &root,
        json!({"token_policies":["changed"]}),
        110,
    );
    let (actor, plan) = prepare(&mut state, &raw, 110);
    let before = state_revision(&state).unwrap();
    assert_eq!(
        state
            .finish_radius_renewal(plan, &actor, RadiusRenewalObservation, 111)
            .err()
            .unwrap()
            .status,
        500
    );
    assert_eq!(state_revision(&state).unwrap(), before);
}
