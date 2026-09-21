use super::*;

fn configured(mount: &str) -> (AuthState, Principal) {
    let (mut state, _, root) = setup();
    if mount != "approle" {
        mount_auth(&mut state, &root, "team", mount, "approle");
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

fn role(
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
            &format!("auth/{mount}/role/app"),
            &body,
            100,
        )?
        .ok_or_else(|| bad("missing AppRole route"))
}

fn credentials(
    state: &mut AuthState,
    root: &Principal,
    mount: &str,
    body: Value,
) -> (String, String, Value) {
    let role_id = call(
        state,
        root,
        "team",
        "GET",
        &format!("auth/{mount}/role/app/role-id"),
        json!({}),
        100,
    )
    .body["data"]["role_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let issued = call(
        state,
        root,
        "team",
        "POST",
        &format!("auth/{mount}/role/app/secret-id"),
        body,
        100,
    );
    let secret = issued.body["data"]["secret_id"]
        .as_str()
        .unwrap()
        .to_owned();
    (role_id, secret, issued.body["data"].clone())
}

fn login(
    state: &mut AuthState,
    mount: &str,
    role_id: &str,
    secret_id: &str,
    now: u64,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(
            None,
            "team",
            "POST",
            &format!("auth/{mount}/login"),
            &json!({"role_id":role_id,"secret_id":secret_id}),
            now,
        )?
        .ok_or_else(denied)
}

fn read(state: &mut AuthState, root: &Principal, mount: &str) -> Value {
    call(
        state,
        root,
        "team",
        "GET",
        &format!("auth/{mount}/role/app"),
        json!({}),
        100,
    )
    .body["data"]
        .clone()
}

#[test]
fn approle_native_defaults_are_zero_and_credentials_are_reusable_without_expiration() {
    for mount in ["approle", "build"] {
        let (mut state, root) = configured(mount);
        role(&mut state, &root, mount, json!({})).unwrap();
        let read = read(&mut state, &root, mount);
        for field in [
            "token_ttl",
            "token_max_ttl",
            "token_period",
            "token_explicit_max_ttl",
            "token_num_uses",
            "secret_id_ttl",
            "secret_id_num_uses",
        ] {
            assert_eq!(read[field], 0, "{field}");
        }
        assert!(state.has_approle_native_defaults());
        let (role_id, secret, issued) = credentials(&mut state, &root, mount, json!({}));
        assert_eq!(issued["secret_id_ttl"], 0);
        assert_eq!(issued["secret_id_num_uses"], 0);
        let bytes = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        assert!(!String::from_utf8_lossy(&bytes).contains(&secret));
        let mut reopened: AuthState = serde_json::from_slice(&bytes).unwrap();
        reopened.validate_approle_native_defaults().unwrap();
        for now in [101, 102, 4000, 8000] {
            let response = login(&mut reopened, mount, &role_id, &secret, now).unwrap();
            assert_eq!(response.body["auth"]["lease_duration"], 75);
        }
        let stored = &reopened
            .roles_at(AuthScope {
                namespace: "team",
                mount,
            })
            .unwrap()["app"]
            .secret_ids[&hash(&secret)];
        assert_eq!(stored.expires_at, None);
        assert_eq!(stored.uses_remaining, None);
    }
}

#[test]
fn approle_duration_null_preserves_values_but_counter_null_clears_counts() {
    let (mut state, root) = configured("build");
    role(
        &mut state,
        &root,
        "build",
        json!({"token_ttl":40,"token_max_ttl":300,
        "token_period":20,"token_explicit_max_ttl":200,"token_num_uses":3,
        "secret_id_ttl":120,"secret_id_num_uses":2}),
    )
    .unwrap();
    let before = provider_renewal::state_revision(&state).unwrap();
    role(
        &mut state,
        &root,
        "build",
        json!({"token_ttl":null,"token_max_ttl":null,
        "token_period":null,"token_explicit_max_ttl":null,"secret_id_ttl":null}),
    )
    .unwrap();
    assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    role(&mut state, &root, "build", json!({"token_ttl":50})).unwrap();
    let data = read(&mut state, &root, "build");
    assert_eq!(data["token_ttl"], 50);
    for (field, value) in [
        ("token_max_ttl", 300),
        ("token_period", 20),
        ("token_explicit_max_ttl", 200),
        ("secret_id_ttl", 120),
        ("token_num_uses", 3),
        ("secret_id_num_uses", 2),
    ] {
        assert_eq!(data[field], value, "{field}");
    }
    role(
        &mut state,
        &root,
        "build",
        json!({"token_num_uses":null,"secret_id_num_uses":null}),
    )
    .unwrap();
    let data = read(&mut state, &root, "build");
    assert_eq!(data["token_num_uses"], 0);
    assert_eq!(data["secret_id_num_uses"], 0);
    role(
        &mut state,
        &root,
        "build",
        json!({"token_ttl":0,"token_max_ttl":0,
        "token_period":0,"token_explicit_max_ttl":0,"secret_id_ttl":0}),
    )
    .unwrap();
    let data = read(&mut state, &root, "build");
    for field in [
        "token_ttl",
        "token_max_ttl",
        "token_period",
        "token_explicit_max_ttl",
        "secret_id_ttl",
    ] {
        assert_eq!(data[field], 0, "{field}");
    }
}

#[test]
fn approle_new_secret_maximum_is_capped_at_issue_but_zero_stays_unlimited() {
    let (mut state, root) = configured("build");
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "sys/auth/build/tune",
        json!({"default_lease_ttl":0,"max_lease_ttl":60}),
        100,
    );
    role(
        &mut state,
        &root,
        "build",
        json!({"secret_id_ttl":120,"secret_id_num_uses":2}),
    )
    .unwrap();
    let (role_id, secret, issued) = credentials(&mut state, &root, "build", json!({"ttl":null}));
    assert_eq!(issued["secret_id_ttl"], 60);
    assert_eq!(issued["secret_id_num_uses"], 2);
    role(
        &mut state,
        &root,
        "build",
        json!({"secret_id_ttl":0,"secret_id_num_uses":0}),
    )
    .unwrap();
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "sys/auth/build/tune",
        json!({"max_lease_ttl":600}),
        100,
    );
    let stored = &state
        .roles_at(AuthScope {
            namespace: "team",
            mount: "build",
        })
        .unwrap()["app"]
        .secret_ids[&hash(&secret)];
    assert_eq!(stored.expires_at, Some(160));
    assert_eq!(stored.uses_remaining, Some(2));
    let mut expiry = state.clone();
    assert!(login(&mut expiry, "build", &role_id, &secret, 160).is_err());
    assert!(login(&mut state, "build", &role_id, &secret, 101).is_ok());
    assert!(login(&mut state, "build", &role_id, &secret, 102).is_ok());
    assert!(login(&mut state, "build", &role_id, &secret, 103).is_err());
    let (_, unlimited, issued) = credentials(&mut state, &root, "build", json!({}));
    assert_eq!(issued["secret_id_ttl"], 0);
    assert!(login(&mut state, "build", &role_id, &unlimited, 4000).is_ok());
}

#[test]
fn approle_secret_overrides_enforce_role_constraints_atomically() {
    let (mut state, root) = configured("build");
    role(
        &mut state,
        &root,
        "build",
        json!({"secret_id_ttl":120,"secret_id_num_uses":2}),
    )
    .unwrap();
    for body in [
        json!({"ttl":0}),
        json!({"ttl":121}),
        json!({"num_uses":0}),
        json!({"num_uses":null}),
        json!({"num_uses":3}),
        json!({"ttl":-1}),
    ] {
        let before = provider_renewal::state_revision(&state).unwrap();
        assert_eq!(
            state
                .handle(
                    Some(&root),
                    "team",
                    "POST",
                    "auth/build/role/app/secret-id",
                    &body,
                    100
                )
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    }
    let (_, _, issued) = credentials(&mut state, &root, "build", json!({"ttl":60,"num_uses":1}));
    assert_eq!(issued["secret_id_ttl"], 60);
    assert_eq!(issued["secret_id_num_uses"], 1);
}

#[test]
fn approle_zero_token_limits_follow_mount_and_all_renewal_routes_without_secret_reuse() {
    let (mut baseline, root) = configured("build");
    role(
        &mut baseline,
        &root,
        "build",
        json!({"secret_id_num_uses":1}),
    )
    .unwrap();
    let (role_id, secret, _) = credentials(&mut baseline, &root, "build", json!({}));
    let issued = login(&mut baseline, "build", &role_id, &secret, 100).unwrap();
    assert_eq!(issued.body["auth"]["lease_duration"], 75);
    let raw = issued.body["auth"]["client_token"].as_str().unwrap();
    assert!(login(&mut baseline, "build", &role_id, &secret, 101).is_err());
    call(
        &mut baseline,
        &root,
        "team",
        "POST",
        "sys/auth/build/tune",
        json!({"default_lease_ttl":95,"max_lease_ttl":900}),
        100,
    );
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let mut state = baseline.clone();
        let actor = state.authenticate(raw, 101).unwrap();
        let body = match operation {
            "renew" => json!({"token":raw}),
            "renew-accessor" => json!({"accessor":state.tokens[&hash(raw)].accessor}),
            _ => json!({}),
        };
        let response = state
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
                101,
            )
            .unwrap()
            .unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], 95);
        assert_eq!(state.tokens[&hash(raw)].max_expires_at, None);
        assert!(
            !state
                .roles_at(AuthScope {
                    namespace: "team",
                    mount: "build"
                })
                .unwrap()["app"]
                .secret_ids
                .contains_key(&hash(&secret))
        );
    }
}

#[test]
fn approle_historical_positive_roles_and_issued_credentials_survive_defaults_change() {
    let (mut state, root) = configured("approle");
    role(
        &mut state,
        &root,
        "approle",
        json!({"token_ttl":3600,"token_max_ttl":MAX_TTL,
        "secret_id_ttl":3600,"secret_id_num_uses":1}),
    )
    .unwrap();
    assert!(!state.has_approle_native_defaults());
    let (_, secret, _) = credentials(&mut state, &root, "approle", json!({}));
    // Recreate the old serialized record shape only in this format unit test.
    // An actual old binary is used separately by the upgrade acceptance runner.
    let historical = state
        .roles_at_mut(AuthScope {
            namespace: "team",
            mount: "approle",
        })
        .get_mut("app")
        .unwrap()
        .secret_ids
        .get_mut(&hash(&secret))
        .unwrap();
    historical.issuance = None;
    historical.expires_at = Some(3700);
    let before = provider_renewal::state_revision(&state).unwrap();
    role(
        &mut state,
        &root,
        "approle",
        json!({"token_ttl":null,"secret_id_ttl":null}),
    )
    .unwrap();
    assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    let mut reopened: AuthState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    reopened.validate_approle_native_defaults().unwrap();
    assert!(!reopened.has_approle_native_defaults());
    let data = read(&mut reopened, &root, "approle");
    assert_eq!(data["token_ttl"], 3600);
    assert_eq!(data["secret_id_ttl"], 3600);
    assert_eq!(data["secret_id_num_uses"], 1);
    let historical = &reopened
        .roles_at(AuthScope {
            namespace: "team",
            mount: "approle",
        })
        .unwrap()["app"]
        .secret_ids[&hash(&secret)];
    assert_eq!(historical.expires_at, Some(3700));
    assert!(
        approle_renewal::secret_id_info(historical)
            .get("secret_id_ttl")
            .is_none()
    );
    let before = serde_json::to_vec(
        &reopened
            .roles_at(AuthScope {
                namespace: "team",
                mount: "approle",
            })
            .unwrap()["app"]
            .secret_ids,
    )
    .unwrap();
    role(
        &mut reopened,
        &root,
        "approle",
        json!({"token_ttl":0,"token_max_ttl":0,"secret_id_ttl":0,"secret_id_num_uses":0}),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_vec(
            &reopened
                .roles_at(AuthScope {
                    namespace: "team",
                    mount: "approle"
                })
                .unwrap()["app"]
                .secret_ids
        )
        .unwrap(),
        before
    );
    assert_eq!(
        reopened
            .roles_at(AuthScope {
                namespace: "team",
                mount: "approle"
            })
            .unwrap()["app"]
            .secret_ids[&hash(&secret)]
            .uses_remaining,
        Some(1)
    );
}

#[test]
fn approle_legacy_zero_credentials_do_not_require_the_new_token_default_format() {
    let (mut state, root) = configured("build");
    role(
        &mut state,
        &root,
        "build",
        json!({"token_ttl":120,"token_max_ttl":600,"secret_id_ttl":0,"secret_id_num_uses":0}),
    )
    .unwrap();
    assert!(!state.has_approle_native_defaults());
    state.validate_approle_native_defaults().unwrap();
    let (role_id, secret, _) = credentials(&mut state, &root, "build", json!({}));
    assert!(login(&mut state, "build", &role_id, &secret, 4000).is_ok());
    role(&mut state, &root, "build", json!({"token_max_ttl":0})).unwrap();
    assert!(state.has_approle_native_defaults());
}

#[test]
fn approle_bad_role_limits_do_not_change_existing_credentials_or_role() {
    let (mut state, root) = configured("build");
    role(&mut state, &root, "build", json!({})).unwrap();
    credentials(&mut state, &root, "build", json!({}));
    for body in [
        json!({"token_ttl":91,"token_max_ttl":90}),
        json!({"secret_id_ttl":-1}),
        json!({"token_period":MAX_TTL+1}),
        json!({"token_explicit_max_ttl":MAX_TTL+1}),
        json!({"secret_id_num_uses":-1}),
        json!({"token_num_uses":-1}),
    ] {
        let before = provider_renewal::state_revision(&state).unwrap();
        assert_eq!(
            role(&mut state, &root, "build", body).err().unwrap().status,
            400
        );
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    }
    let role = state
        .roles_at_mut(AuthScope {
            namespace: "team",
            mount: "build",
        })
        .get_mut("app")
        .unwrap();
    role.token_ttl = 91;
    role.token_max_ttl = 90;
    assert!(state.validate_approle_native_defaults().is_err());
}

#[test]
fn approle_secret_lookup_preserves_requested_ttl_and_tracks_only_finite_successful_uses() {
    let (mut state, root) = configured("build");
    call(
        &mut state,
        &root,
        "team",
        "POST",
        "sys/auth/build/tune",
        json!({"default_lease_ttl":0,"max_lease_ttl":60}),
        100,
    );
    role(
        &mut state,
        &root,
        "build",
        json!({"secret_id_ttl":120,"secret_id_num_uses":2}),
    )
    .unwrap();
    let (role_id, secret, issued) = credentials(&mut state, &root, "build", json!({}));
    assert_eq!(issued["secret_id_ttl"], 60);
    let accessor = issued["secret_id_accessor"].as_str().unwrap();
    for (operation, body) in [
        ("secret-id/lookup", json!({"secret_id":secret})),
        (
            "secret-id-accessor/lookup",
            json!({"secret_id_accessor":accessor}),
        ),
    ] {
        let data = call(
            &mut state,
            &root,
            "team",
            "POST",
            &format!("auth/build/role/app/{operation}"),
            body,
            100,
        )
        .body["data"]
            .clone();
        assert_eq!(data["secret_id_ttl"], 120);
        assert_eq!(data["cidr_list"], json!([]));
        assert_eq!(data["token_bound_cidrs"], json!([]));
        assert_eq!(data["creation_time"], crate::engines::timestamp(100));
        assert_eq!(data["expiration_time"], crate::engines::timestamp(160));
        assert_eq!(data["last_updated_time"], crate::engines::timestamp(100));
    }
    role(
        &mut state,
        &root,
        "build",
        json!({"secret_id_ttl":0,"secret_id_num_uses":0}),
    )
    .unwrap();
    login(&mut state, "build", &role_id, &secret, 101).unwrap();
    let mut state: AuthState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    state.validate_approle_native_defaults().unwrap();
    let data = call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/build/role/app/secret-id/lookup",
        json!({"secret_id":secret}),
        101,
    )
    .body["data"]
        .clone();
    assert_eq!(data["secret_id_ttl"], 120);
    assert_eq!(data["secret_id_num_uses"], 1);
    assert_eq!(data["last_updated_time"], crate::engines::timestamp(101));
    assert_eq!(data["expiration_time"], crate::engines::timestamp(160));
    login(&mut state, "build", &role_id, &secret, 102).unwrap();
    assert_eq!(
        login(&mut state, "build", &role_id, &secret, 103)
            .err()
            .unwrap()
            .status,
        400
    );
    for (operation, body) in [
        ("secret-id/lookup", json!({"secret_id":secret})),
        (
            "secret-id-accessor/lookup",
            json!({"secret_id_accessor":accessor}),
        ),
    ] {
        let result = state.handle(
            Some(&root),
            "team",
            "POST",
            &format!("auth/build/role/app/{operation}"),
            &body,
            102,
        );
        if operation == "secret-id/lookup" {
            assert_eq!(result.unwrap().unwrap().status, 204);
        } else {
            assert_eq!(result.err().unwrap().status, 404);
        }
    }
    let (_, unlimited, _) = credentials(&mut state, &root, "build", json!({}));
    login(&mut state, "build", &role_id, &unlimited, 4000).unwrap();
    let data = call(
        &mut state,
        &root,
        "team",
        "POST",
        "auth/build/role/app/secret-id/lookup",
        json!({"secret_id":unlimited}),
        4000,
    )
    .body["data"]
        .clone();
    assert_eq!(data["secret_id_ttl"], 0);
    assert_eq!(data["expiration_time"], "0001-01-01T00:00:00Z");
    assert_eq!(data["last_updated_time"], crate::engines::timestamp(100));
}

#[test]
fn approle_secret_issuance_facts_require_format_fence_even_with_positive_role_token_limits() {
    let (mut state, root) = configured("build");
    role(
        &mut state,
        &root,
        "build",
        json!({"token_ttl":75,"token_max_ttl":600,"secret_id_ttl":120}),
    )
    .unwrap();
    assert!(!state.has_approle_native_defaults());
    let (_, secret, _) = credentials(&mut state, &root, "build", json!({}));
    assert!(state.has_approle_native_defaults());
    let mut corrupt = state.clone();
    corrupt
        .roles_at_mut(AuthScope {
            namespace: "team",
            mount: "build",
        })
        .get_mut("app")
        .unwrap()
        .secret_ids
        .get_mut(&hash(&secret))
        .unwrap()
        .expires_at = Some(400);
    assert!(corrupt.validate_approle_native_defaults().is_err());
    let mut legacy = state;
    let stored = legacy
        .roles_at_mut(AuthScope {
            namespace: "team",
            mount: "build",
        })
        .get_mut("app")
        .unwrap()
        .secret_ids
        .get_mut(&hash(&secret))
        .unwrap();
    stored.issuance = None;
    stored.uses_remaining = Some(0);
    assert!(!legacy.has_approle_native_defaults());
    let before = provider_renewal::state_revision(&legacy).unwrap();
    assert_eq!(
        legacy
            .handle(
                Some(&root),
                "team",
                "POST",
                "auth/build/role/app/secret-id/lookup",
                &json!({"secret_id":secret}),
                100
            )
            .unwrap()
            .unwrap()
            .status,
        204
    );
    assert_eq!(provider_renewal::state_revision(&legacy).unwrap(), before);
}
