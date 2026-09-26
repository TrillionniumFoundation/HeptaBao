use super::*;

const PASSWORD: &str = "correct userpass password";

fn configured(mount: &str) -> (AuthState, Principal) {
    let (mut state, _, root) = setup();
    if mount != "userpass" {
        mount_auth(&mut state, &root, "team", mount, "userpass");
    }
    call(
        &mut state,
        &root,
        "team",
        "POST",
        &format!("sys/auth/{mount}/tune"),
        json!({"default_lease_ttl":75,"max_lease_ttl":600}),
        100,
    );
    (state, root)
}

fn write(
    state: &mut AuthState,
    root: &Principal,
    mount: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(
            Some(root),
            "team",
            "POST",
            &format!("auth/{mount}/users/alice"),
            &body,
            100,
        )?
        .ok_or_else(denied)
}

fn login(state: &mut AuthState, mount: &str) -> String {
    state
        .handle(
            None,
            "team",
            "POST",
            &format!("auth/{mount}/login/alice"),
            &json!({"password":PASSWORD}),
            100,
        )
        .unwrap()
        .unwrap()
        .body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn renew(
    state: &mut AuthState,
    root: &Principal,
    raw: &str,
    route: &str,
    increment: Option<u64>,
    now: u64,
) -> Result<AuthResponse, AuthError> {
    let actor = state.authenticate(raw, now)?;
    let mut body = match route {
        "renew" => json!({"token":raw}),
        "renew-accessor" => json!({"accessor":state.tokens[&hash(raw)].accessor}),
        _ => json!({}),
    };
    if let Some(increment) = increment {
        body["increment"] = json!(increment);
    }
    state
        .handle(
            Some(if route == "renew-self" { &actor } else { root }),
            "team",
            "POST",
            &format!("auth/token/{route}"),
            &body,
            now,
        )?
        .ok_or_else(denied)
}

#[test]
fn userpass_native_defaults_and_null_preserve_existing_account_fields() {
    for mount in ["userpass", "staff"] {
        let (mut state, root) = configured(mount);
        write(&mut state, &root, mount, json!({"password":PASSWORD})).unwrap();
        let data = call(
            &mut state,
            &root,
            "team",
            "GET",
            &format!("auth/{mount}/users/alice"),
            json!({}),
            100,
        )
        .body["data"]
            .clone();
        for field in [
            "token_ttl",
            "token_max_ttl",
            "token_period",
            "token_explicit_max_ttl",
            "token_num_uses",
        ] {
            assert_eq!(data[field], 0);
        }
        assert_eq!(data["token_policies"], json!([]));
        assert!(state.has_userpass_native_tokens());
        write(&mut state,&root,mount,json!({"token_ttl":40,"token_max_ttl":300,"token_period":20,"token_explicit_max_ttl":180,"token_num_uses":3})).unwrap();
        let before = provider_renewal::state_revision(&state).unwrap();
        write(&mut state,&root,mount,json!({"token_ttl":null,"token_max_ttl":null,"token_period":null,"token_explicit_max_ttl":null})).unwrap();
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
        write(&mut state, &root, mount, json!({"token_num_uses":null})).unwrap();
        assert_eq!(
            state
                .users_at(AuthScope {
                    namespace: "team",
                    mount
                })
                .unwrap()["alice"]
                .token_num_uses,
            0
        );
        write(
            &mut state,
            &root,
            mount,
            json!({"token_ttl":0,"token_max_ttl":0,"token_period":0,"token_explicit_max_ttl":0}),
        )
        .unwrap();
        let raw = login(&mut state, mount);
        assert_eq!(state.tokens[&hash(&raw)].expires_at, Some(175));
        assert_eq!(state.tokens[&hash(&raw)].max_expires_at, None);
    }
}

#[test]
fn userpass_three_renewal_routes_use_live_limits_without_password_revalidation() {
    let (mut state, root) = configured("staff");
    write(&mut state, &root, "staff", json!({"password":PASSWORD})).unwrap();
    let raw = login(&mut state, "staff");
    write(
        &mut state,
        &root,
        "staff",
        json!({"password":"new account password","token_ttl":95,"token_max_ttl":900}),
    )
    .unwrap();
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "sys/auth/staff/tune",
        json!({"max_lease_ttl":900}),
        100,
    );
    // Deliberately misleading display text cannot redirect trusted provenance.
    state.tokens.get_mut(&hash(&raw)).unwrap().display_name = "userpass-someone-else".into();
    let bytes = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    assert!(!String::from_utf8_lossy(&bytes).contains(PASSWORD));
    assert!(!String::from_utf8_lossy(&bytes).contains("new account password"));
    for route in ["renew-self", "renew", "renew-accessor"] {
        let mut reopened: AuthState = serde_json::from_slice(&bytes).unwrap();
        reopened.validate_userpass_native_tokens().unwrap();
        let response = renew(&mut reopened, &root, &raw, route, None, 101).unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], 95);
        assert_eq!(response.body["auth"]["metadata"]["username"], "alice");
        let response = renew(&mut reopened, &root, &raw, route, Some(700), 102).unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], 700);
        assert_eq!(
            token_info(&reopened.tokens[&hash(&raw)], 102)["meta"]["username"],
            "alice"
        );
    }
}

#[test]
fn userpass_policy_or_account_removal_prevents_every_renewal_without_extending_live_token() {
    let (mut baseline, root) = configured("staff");
    write(&mut baseline, &root, "staff", json!({"password":PASSWORD})).unwrap();
    let raw = login(&mut baseline, "staff");
    for deleted in [false, true] {
        for route in ["renew-self", "renew", "renew-accessor"] {
            let mut state = baseline.clone();
            if deleted {
                state
                    .users_at_mut(AuthScope {
                        namespace: "team",
                        mount: "staff",
                    })
                    .remove("alice");
            } else {
                write(
                    &mut state,
                    &root,
                    "staff",
                    json!({"token_policies":["changed"]}),
                )
                .unwrap();
            }
            let before = provider_renewal::state_revision(&state).unwrap();
            let result = renew(&mut state, &root, &raw, route, None, 101);
            if deleted && route != "renew-accessor" {
                let response = result.unwrap();
                assert_eq!(response.status, 204);
                assert!(response.body.get("auth").is_none_or(Value::is_null));
                assert!(!response.mutated);
            } else {
                assert_eq!(result.err().unwrap().status, 500);
            }
            assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
            assert!(state.authenticate(&raw, 101).is_ok());
        }
    }
    // Default is not a substantive change under OpenBao EquivalentPolicies.
    baseline
        .users_at_mut(AuthScope {
            namespace: "team",
            mount: "staff",
        })
        .get_mut("alice")
        .unwrap()
        .policies
        .clear();
    assert_eq!(
        renew(&mut baseline, &root, &raw, "renew-self", None, 101)
            .unwrap()
            .body["auth"]["lease_duration"],
        75
    );
}

#[test]
fn userpass_period_is_live_but_lookup_snapshot_and_explicit_cap_remain_at_issue() {
    let (mut baseline, root) = configured("staff");
    write(&mut baseline,&root,"staff",json!({"password":PASSWORD,"token_ttl":40,"token_max_ttl":300,"token_period":30,"token_explicit_max_ttl":180})).unwrap();
    let raw = login(&mut baseline, "staff");
    write(
        &mut baseline,
        &root,
        "staff",
        json!({"token_period":50,"token_explicit_max_ttl":600}),
    )
    .unwrap();
    for route in ["renew-self", "renew", "renew-accessor"] {
        let mut state = baseline.clone();
        assert_eq!(
            renew(&mut state, &root, &raw, route, Some(1), 101)
                .unwrap()
                .body["auth"]["lease_duration"],
            50
        );
        assert_eq!(state.tokens[&hash(&raw)].period, 30);
        assert_eq!(state.tokens[&hash(&raw)].max_expires_at, Some(280));
        write(
            &mut state,
            &root,
            "staff",
            json!({"token_period":0,"token_explicit_max_ttl":0,"token_max_ttl":900}),
        )
        .unwrap();
        call(
            &mut state,
            &root,
            "team",
            "POST",
            "sys/auth/staff/tune",
            json!({"max_lease_ttl":900}),
            100,
        );
        assert_eq!(
            renew(&mut state, &root, &raw, route, Some(700), 102)
                .unwrap()
                .body["auth"]["lease_duration"],
            178
        );
        assert_eq!(state.tokens[&hash(&raw)].expires_at, Some(280));
        let fresh = login(&mut state, "staff");
        assert_eq!(state.tokens[&hash(&fresh)].period, 0);
        assert_eq!(state.tokens[&hash(&fresh)].max_expires_at, None);
    }
}

#[test]
fn userpass_past_live_maximum_fails_while_original_lease_stays_active() {
    let (mut baseline, root) = configured("staff");
    write(&mut baseline, &root, "staff", json!({"password":PASSWORD})).unwrap();
    let raw = login(&mut baseline, "staff");
    write(&mut baseline, &root, "staff", json!({"token_max_ttl":1})).unwrap();
    for route in ["renew-self", "renew", "renew-accessor"] {
        let mut state = baseline.clone();
        let before = provider_renewal::state_revision(&state).unwrap();
        assert_eq!(
            renew(&mut state, &root, &raw, route, None, 102)
                .err()
                .unwrap()
                .status,
            500
        );
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
        assert!(state.authenticate(&raw, 102).is_ok());
        write(&mut state, &root, "staff", json!({"token_max_ttl":600})).unwrap();
        assert!(renew(&mut state, &root, &raw, route, None, 102).is_ok());
    }
}

#[test]
fn userpass_legacy_identity_is_not_guessed_and_explicit_token_api_children_stay_independent() {
    let (mut state, root) = configured("staff");
    put_policy(
        &mut state,
        &root,
        "team",
        "issuer",
        json!(r#"path "auth/token/create*" { capabilities = ["update", "sudo"] }"#),
    );
    write(
        &mut state,
        &root,
        "staff",
        json!({"password":PASSWORD,"token_policies":["issuer"]}),
    )
    .unwrap();
    let raw = login(&mut state, "staff");
    // Format-only old token: genuine binary upgrade acceptance is separate.
    let legacy = state.tokens.get_mut(&hash(&raw)).unwrap();
    legacy.auth_provenance = None;
    legacy.max_expires_at = Some(700);
    for route in ["renew-self", "renew", "renew-accessor"] {
        assert_eq!(
            renew(&mut state, &root, &raw, route, None, 101)
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(state.tokens[&hash(&raw)].max_expires_at, Some(700));
    }
    let actor = state.authenticate(&raw, 101).unwrap();
    let child = token(
        &mut state,
        &actor,
        "team",
        json!({"policies":["default"],"ttl":120}),
        101,
    );
    let orphan = token(
        &mut state,
        &actor,
        "team",
        json!({"policies":["default"],"ttl":120,"no_parent":true}),
        101,
    );
    assert_eq!(
        state.tokens[&hash(&child)].parent.as_ref(),
        Some(&actor.digest)
    );
    assert_eq!(state.tokens[&hash(&orphan)].parent, None);
    assert_eq!(state.tokens[&hash(&orphan)].auth_mount, None);
    state
        .users_at_mut(AuthScope {
            namespace: "team",
            mount: "staff",
        })
        .remove("alice");
    for target in [&child, &orphan] {
        assert!(matches!(
            state.tokens[&hash(target)].auth_provenance,
            Some(TokenAuthProvenance::TokenApi { .. })
        ));
        assert!(
            token_info(&state.tokens[&hash(target)], 101)
                .get("meta")
                .is_none()
        );
        assert!(renew(&mut state, &root, target, "renew-self", Some(60), 101).is_ok());
    }
    state.tokens.get_mut(&hash(&child)).unwrap().auth_provenance = None;
    assert!(renew(&mut state, &root, &child, "renew-self", Some(60), 102).is_ok());
    // Recreate the old ambiguous orphan shape, which historically inherited
    // origin mount despite lacking a parent or an explicit issuer marker.
    let orphan_token = state.tokens.get_mut(&hash(&orphan)).unwrap();
    orphan_token.auth_provenance = None;
    orphan_token.auth_mount = Some("staff".into());
    assert_eq!(
        renew(&mut state, &root, &orphan, "renew-self", Some(60), 102)
            .err()
            .unwrap()
            .status,
        400
    );
}

#[test]
fn userpass_old_positive_account_shape_is_stable_until_new_login_or_default_reset() {
    let (mut state, root) = configured("staff");
    write(&mut state,&root,"staff",json!({"password":PASSWORD,"token_ttl":120,"token_max_ttl":600,"token_policies":["default"]})).unwrap();
    assert!(!state.has_userpass_native_tokens());
    let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    assert!(!String::from_utf8_lossy(&before).contains("token_explicit_max_ttl"));
    let mut reopened: AuthState = serde_json::from_slice(&before).unwrap();
    reopened.validate_userpass_native_tokens().unwrap();
    write(&mut reopened,&root,"staff",json!({"token_ttl":null,"token_max_ttl":null,"token_period":null,"token_explicit_max_ttl":null})).unwrap();
    assert_eq!(
        serde_json::to_vec(&reopened).unwrap().as_slice(),
        before.as_slice()
    );
    let raw = login(&mut reopened, "staff");
    assert!(reopened.has_userpass_native_tokens());
    assert!(matches!(
        reopened.tokens[&hash(&raw)].auth_provenance,
        Some(TokenAuthProvenance::Userpass { .. })
    ));
    let mut corrupt = reopened.clone();
    corrupt.tokens.get_mut(&hash(&raw)).unwrap().parent = Some(hash("unrelated"));
    assert!(corrupt.validate_userpass_native_tokens().is_err());
}

#[test]
fn userpass_invalid_limits_are_atomic_and_bounded_ldap_keeps_prior_local_mapping_semantics() {
    let (mut state, root) = configured("staff");
    write(&mut state, &root, "staff", json!({"password":PASSWORD})).unwrap();
    for body in [
        json!({"token_ttl":91,"token_max_ttl":90}),
        json!({"token_period":MAX_TTL+1}),
        json!({"token_explicit_max_ttl":MAX_TTL+1}),
        json!({"token_num_uses":-1}),
    ] {
        let before = provider_renewal::state_revision(&state).unwrap();
        assert_eq!(
            write(&mut state, &root, "staff", body)
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    }
    mount_auth(&mut state, &root, "team", "directory", "ldap");
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/directory/users/alice",
        json!({"password":PASSWORD}),
        100,
    );
    let user = &state
        .users_at(AuthScope {
            namespace: "team",
            mount: "directory",
        })
        .unwrap()["alice"];
    assert_eq!(user.token_ttl, MAX_TTL);
    assert_eq!(user.token_max_ttl, MAX_TTL);
    let before = provider_renewal::state_revision(&state).unwrap();
    assert_eq!(
        state
            .handle(
                Some(&root),
                "team",
                "POST",
                "auth/directory/users/alice",
                &json!({"token_period":30}),
                100
            )
            .err()
            .unwrap()
            .status,
        400
    );
    assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    // Shared User storage must not silently smuggle new native parameters
    // into the older bounded LDAP profile when persisted bytes are validated.
    state
        .users_at_mut(AuthScope {
            namespace: "team",
            mount: "directory",
        })
        .get_mut("alice")
        .unwrap()
        .token_period = 30;
    assert!(state.has_userpass_native_tokens());
    assert!(state.validate_userpass_native_tokens().is_err());
}

#[test]
fn userpass_configured_policies_do_not_store_or_remove_the_tokens_implicit_default() {
    let (mut state, root) = configured("staff");
    write(
        &mut state,
        &root,
        "staff",
        json!({"password":PASSWORD,"token_ttl":120,"token_max_ttl":600}),
    )
    .unwrap();
    assert!(
        state.has_userpass_native_tokens(),
        "positive limits with native empty policies require the new format"
    );
    let raw = login(&mut state, "staff");
    for policies in [json!(["default"]), Value::Null, json!([])] {
        write(
            &mut state,
            &root,
            "staff",
            json!({"token_policies":policies}),
        )
        .unwrap();
        let response = renew(&mut state, &root, &raw, "renew-self", None, 101).unwrap();
        assert_eq!(response.body["auth"]["policies"], json!(["default"]));
        assert_eq!(
            state.tokens[&hash(&raw)].policies,
            BTreeSet::from(["default".into()])
        );
    }
    assert!(
        state
            .users_at(AuthScope {
                namespace: "team",
                mount: "staff"
            })
            .unwrap()["alice"]
            .policies
            .is_empty()
    );
}
