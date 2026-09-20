#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;

fn fixture() -> (AuthState, String, String) {
    let (mut state, root) = AuthState::bootstrap(100).unwrap();
    let actor = state.authenticate(&root, 100).unwrap();
    for (path, body) in [
        ("sys/auth/ldap", json!({"type":"ldap"})),
        (
            "sys/policies/acl/issuer",
            json!({"policy":"path \"auth/token/*\" { capabilities = [\"read\", \"update\", \"sudo\"] }"}),
        ),
        (
            "auth/ldap/config",
            json!({"url":"ldaps://directory.example.test", "bind_dn":"cn=admin,dc=example,dc=test", "user_dn_template":"uid={{username}},ou=people,dc=example,dc=test", "group_dn":"ou=groups,dc=example,dc=test"}),
        ),
        (
            "auth/ldap/users/alice",
            json!({"password":"unused-local-verifier", "token_policies":["issuer"], "token_ttl":120, "token_max_ttl":600}),
        ),
        (
            "auth/ldap/groups/engineering",
            json!({"policies":["engineering"]}),
        ),
    ] {
        state
            .handle(Some(&actor), "", "POST", path, &body, 100)
            .unwrap()
            .unwrap();
    }
    let plan = state
        .prepare_ldap_login(
            "",
            "ldap",
            "alice",
            "POST",
            &json!({"password":"synthetic-directory-password"}),
            100,
        )
        .unwrap();
    let response = state
        .finish_ldap_login(plan, LdapLoginObservation { groups: groups() })
        .unwrap();
    let raw = response.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    (state, root, raw)
}

fn groups() -> BTreeSet<String> {
    BTreeSet::from(["engineering".into()])
}

fn prepare(state: &mut AuthState, raw: &str, now: u64) -> (Principal, ProviderRenewalPlan) {
    let actor = state.authenticate(raw, now).unwrap();
    let plan = state
        .prepare_provider_renewal(
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

fn accepted(groups: BTreeSet<String>) -> ProviderRenewalObservation {
    ProviderRenewalObservation::Ldap(LdapRenewalObservation { groups })
}

#[test]
fn ldap_renewal_persists_only_direct_credentials_and_rejects_offline_bypass() {
    let (state, _, raw) = fixture();
    let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut state: AuthState = serde_json::from_slice(&encoded).unwrap();
    state.validate_ldap_renewal_state().unwrap();
    let id = hash(&raw);
    assert!(matches!(
        state.tokens[&id].auth_provenance,
        Some(TokenAuthProvenance::Ldap { .. })
    ));
    let (actor, plan) = prepare(&mut state, &raw, 110);
    let before = state.tokens[&id].expires_at;
    assert_eq!(
        state
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/token/renew-self",
                &json!({}),
                110
            )
            .err()
            .unwrap()
            .status,
        503
    );
    assert_eq!(state.tokens[&id].expires_at, before);
    let response = state
        .finish_provider_renewal(plan, &actor, accepted(groups()), 111)
        .unwrap();
    assert_eq!(response.body["auth"]["lease_duration"], 300);
    assert_eq!(response.external_groups.unwrap().names, groups());
    assert!(
        !token_info(&state.tokens[&id], 111)
            .to_string()
            .contains("credential")
    );
    assert!(
        !response
            .body
            .to_string()
            .contains("synthetic-directory-password")
    );
}

#[test]
fn ldap_renewal_rechecks_live_groups_before_extending_and_current_ttl_caps() {
    let (mut state, _, raw) = fixture();
    let (actor, plan) = prepare(&mut state, &raw, 110);
    let before = state.tokens[&hash(&raw)].expires_at;
    assert_eq!(
        state
            .finish_provider_renewal(plan, &actor, accepted(BTreeSet::new()), 111)
            .err()
            .unwrap()
            .status,
        500
    );
    assert_eq!(state.tokens[&hash(&raw)].expires_at, before);
    let scope = AuthScope {
        namespace: "",
        mount: "ldap",
    };
    let user = state.users_at_mut(scope).get_mut("alice").unwrap();
    user.token_ttl = 45;
    user.token_max_ttl = 90;
    user.policies.remove("default");
    let actor = state.authenticate(&raw, 120).unwrap();
    let plan = state
        .prepare_provider_renewal(
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
        .finish_provider_renewal(plan, &actor, accepted(groups()), 121)
        .unwrap();
    assert_eq!(response.body["auth"]["lease_duration"], 45);
    assert_eq!(state.tokens[&hash(&raw)].expires_at, Some(166));
}

#[test]
fn ldap_renewal_fences_user_group_mapping_mount_config_target_actor_and_expiry() {
    let (baseline, root, raw) = fixture();
    for mutation in [
        "user", "groups", "mount", "config", "target", "actor", "expiry", "acl",
    ] {
        let mut state = baseline.clone();
        let actor = state.authenticate(&root, 110).unwrap();
        let plan = state
            .prepare_provider_renewal(
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
        let scope = AuthScope {
            namespace: "",
            mount: "ldap",
        };
        let mut now = 111;
        match mutation {
            "user" => {
                state
                    .users_at_mut(scope)
                    .get_mut("alice")
                    .unwrap()
                    .token_ttl = 90
            }
            "groups" => {
                state
                    .ldap_groups_at_mut(scope)
                    .get_mut("engineering")
                    .unwrap()
                    .insert("new-policy".into());
            }
            "mount" => {
                state
                    .auth_mounts
                    .get_mut("")
                    .unwrap()
                    .get_mut("ldap")
                    .unwrap()
                    .revision += 1
            }
            "config" => {
                state
                    .ldap_mounts
                    .get_mut("")
                    .unwrap()
                    .get_mut("ldap")
                    .unwrap()
                    .group_dn = "ou=changed,dc=example,dc=test".into()
            }
            "target" => state.tokens.get_mut(&id).unwrap().accessor.push('x'),
            "actor" => state.revoke(&hash(&root)),
            "expiry" => now = 999,
            "acl" => {
                let token = state.tokens.get_mut(&hash(&root)).unwrap();
                token.root = false;
                token.policies.clear();
            }
            _ => unreachable!(),
        }
        assert!(
            state
                .finish_provider_renewal(plan, &actor, accepted(groups()), now)
                .is_err(),
            "{mutation}"
        );
        assert_eq!(state.tokens[&id].expires_at, before, "{mutation}");
    }
}

#[test]
fn ldap_children_are_credential_free_and_only_ambiguous_legacy_orphans_require_relogin() {
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
        assert!(matches!(
            state.tokens[&hash(&child)].auth_provenance,
            Some(TokenAuthProvenance::TokenApi)
        ));
        assert!(
            !serde_json::to_string(&state.tokens[&hash(&child)])
                .unwrap()
                .contains("credential")
        );
        let actor = state.authenticate(&child, 102).unwrap();
        assert!(
            state
                .prepare_provider_renewal(
                    Some(&actor),
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
                    Some(&actor),
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
    children.push((raw, true));
    for (child, ambiguous) in children {
        state.tokens.get_mut(&hash(&child)).unwrap().auth_provenance = None;
        let actor = state.authenticate(&child, 103).unwrap();
        let response = state.handle(
            Some(&actor),
            "",
            "POST",
            "auth/token/renew-self",
            &json!({}),
            103,
        );
        if ambiguous {
            assert_eq!(response.err().unwrap().status, 400);
        } else {
            assert_eq!(response.unwrap().unwrap().status, 200);
        }
    }
}

#[test]
fn ldap_provenance_validation_rejects_malformed_credentials_or_transplanted_origin() {
    let (baseline, _, raw) = fixture();
    for mutation in [
        "empty", "oversize", "nul", "username", "parent", "mount", "root",
    ] {
        let mut state = baseline.clone();
        let token = state.tokens.get_mut(&hash(&raw)).unwrap();
        match mutation {
            "parent" => token.parent = Some("unrelated".into()),
            "mount" => token.auth_mount = Some("token".into()),
            "root" => token.root = true,
            _ => {
                let Some(TokenAuthProvenance::Ldap {
                    username,
                    credential,
                }) = token.auth_provenance.as_mut()
                else {
                    unreachable!()
                };
                if mutation == "username" {
                    *username = "a,cn=admin".into();
                } else {
                    credential.0 = match mutation {
                        "empty" => String::new(),
                        "oversize" => "x".repeat(1025),
                        _ => "bad\0secret".into(),
                    };
                }
            }
        }
        assert!(state.validate_ldap_renewal_state().is_err(), "{mutation}");
    }
}
