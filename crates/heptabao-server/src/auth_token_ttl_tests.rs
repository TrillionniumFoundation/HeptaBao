use super::*;

fn tune(state: &mut AuthState, root: &Principal, namespace: &str, body: Value) {
    call(
        state,
        root,
        namespace,
        "POST",
        "sys/auth/token/tune",
        body,
        100,
    );
}

fn create(state: &mut AuthState, root: &Principal, namespace: &str, mut body: Value) -> String {
    body["policies"] = json!(["default"]);
    token(state, root, namespace, body, 100)
}

fn renew_api(
    state: &mut AuthState,
    root: &Principal,
    namespace: &str,
    raw: &str,
    operation: &str,
    increment: Option<u64>,
    now: u64,
) -> Result<AuthResponse, AuthError> {
    let actor = state.authenticate(raw, now)?;
    let mut body = match operation {
        "renew" => json!({"token":raw}),
        "renew-accessor" => json!({"accessor":state.tokens[&hash(raw)].accessor}),
        _ => json!({}),
    };
    if let Some(increment) = increment {
        body["increment"] = json!(increment);
    }
    state
        .handle(
            Some(if operation == "renew-self" {
                &actor
            } else {
                root
            }),
            namespace,
            "POST",
            &format!("auth/token/{operation}"),
            &body,
            now,
        )?
        .ok_or_else(|| bad("missing renewal"))
}

#[test]
fn system_defaults_distinguish_fresh_and_legacy_without_read_migration() {
    for (legacy, expected) in [(false, MAX_TTL), (true, LEGACY_DEFAULT_TTL)] {
        let (mut state, _, root) = setup();
        if legacy {
            state.system_lease_defaults = None;
        }
        let bytes = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        let mut reopened: AuthState = serde_json::from_slice(&bytes).unwrap();
        reopened.validate_system_lease_defaults().unwrap();
        assert_eq!(reopened.has_system_lease_defaults(), !legacy);
        for namespace in ["", "team", "other/nested"] {
            let read = call(
                &mut reopened,
                &root,
                namespace,
                "GET",
                "sys/auth/token/tune",
                json!({}),
                100,
            );
            assert_eq!(read.body["data"]["default_lease_ttl"], expected);
            assert_eq!(read.body["data"]["max_lease_ttl"], MAX_TTL);
        }
        assert_eq!(
            serde_json::to_vec(&reopened).unwrap().as_slice(),
            bytes.as_slice()
        );
        let raw = create(&mut reopened, &root, "", json!({}));
        assert_eq!(
            reopened.tokens[&hash(&raw)].expires_at,
            Some(100 + expected)
        );
        assert_eq!(reopened.tokens[&hash(&raw)].max_expires_at, None);
        assert!(reopened.has_system_lease_defaults());
        let mut reopened: AuthState =
            serde_json::from_slice(&serde_json::to_vec(&reopened).unwrap()).unwrap();
        let read = call(
            &mut reopened,
            &root,
            "",
            "GET",
            "sys/auth/token/tune",
            json!({}),
            101,
        );
        assert_eq!(read.body["data"]["default_lease_ttl"], expected);
    }
}

#[test]
fn token_mount_inherited_default_is_reported_but_issuance_is_capped_and_reset_is_live() {
    let (mut state, _, root) = setup();
    tune(&mut state, &root, "", json!({"max_lease_ttl":60}));
    let read = call(
        &mut state,
        &root,
        "",
        "GET",
        "sys/auth/token/tune",
        json!({}),
        100,
    );
    assert_eq!(read.body["data"]["default_lease_ttl"], MAX_TTL);
    assert_eq!(read.body["data"]["max_lease_ttl"], 60);
    let descriptor = call(&mut state, &root, "", "GET", "sys/auth", json!({}), 100);
    assert_eq!(
        descriptor.body["data"]["token/"]["config"]["default_lease_ttl"],
        0
    );
    for body in [json!({}), json!({"ttl":0}), json!({"ttl":600})] {
        let raw = create(&mut state, &root, "", body);
        assert_eq!(state.tokens[&hash(&raw)].expires_at, Some(160));
    }
    tune(
        &mut state,
        &root,
        "",
        json!({"default_lease_ttl":75,"max_lease_ttl":600}),
    );
    let raw = create(&mut state, &root, "", json!({}));
    assert_eq!(state.tokens[&hash(&raw)].expires_at, Some(175));
    // Namespace overrides cannot leak into other namespaces.
    let other = create(&mut state, &root, "team", json!({}));
    assert_eq!(state.tokens[&hash(&other)].expires_at, Some(100 + MAX_TTL));
    tune(
        &mut state,
        &root,
        "",
        json!({"default_lease_ttl":0,"max_lease_ttl":0}),
    );
    let raw = create(&mut state, &root, "", json!({"ttl":0}));
    assert_eq!(state.tokens[&hash(&raw)].expires_at, Some(100 + MAX_TTL));
}

#[test]
fn token_api_renewal_uses_previous_grant_and_current_token_mount_maximum() {
    let (mut state, _, root) = setup();
    tune(
        &mut state,
        &root,
        "",
        json!({"default_lease_ttl":75,"max_lease_ttl":600}),
    );
    let raw = create(&mut state, &root, "", json!({}));
    // Historical descendants may carry their parent's provider mount for
    // revocation lineage; TokenApi provenance owns renewal TTL selection.
    state.tokens.get_mut(&hash(&raw)).unwrap().auth_mount = Some("approle".into());
    tune(
        &mut state,
        &root,
        "",
        json!({"default_lease_ttl":95,"max_lease_ttl":900}),
    );
    for operation in ["renew-self", "renew", "renew-accessor"] {
        for increment in [None, Some(0), Some(700)] {
            let mut candidate = state.clone();
            let response =
                renew_api(&mut candidate, &root, "", &raw, operation, increment, 101).unwrap();
            assert_eq!(
                response.body["auth"]["lease_duration"],
                if increment == Some(700) { 700 } else { 75 }
            );
            assert_eq!(candidate.tokens[&hash(&raw)].max_expires_at, None);
        }
    }
}

#[test]
fn token_api_explicit_and_ambiguous_legacy_caps_are_not_erased() {
    let (mut state, _, root) = setup();
    state.system_lease_defaults = None;
    tune(
        &mut state,
        &root,
        "",
        json!({"default_lease_ttl":75,"max_lease_ttl":600}),
    );
    assert!(!state.has_system_lease_defaults());
    let raw = create(&mut state, &root, "", json!({"explicit_max_ttl":120}));
    assert_eq!(state.tokens[&hash(&raw)].max_expires_at, Some(220));
    tune(
        &mut state,
        &root,
        "",
        json!({"default_lease_ttl":95,"max_lease_ttl":900}),
    );
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let mut candidate = state.clone();
        let response =
            renew_api(&mut candidate, &root, "", &raw, operation, Some(700), 101).unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], 119);
        assert_eq!(candidate.tokens[&hash(&raw)].max_expires_at, Some(220));
    }
    // Old serialized ordinary caps and true explicit caps used the same field.
    // Preserve a concrete deadline even when the current mount permits longer.
    state.tokens.get_mut(&hash(&raw)).unwrap().max_expires_at = Some(180);
    state.system_lease_defaults = None;
    state
        .tokens
        .get_mut(&hash(&raw))
        .unwrap()
        .token_api_lease_ttl = None;
    let mut reopened: AuthState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    let response = renew_api(&mut reopened, &root, "", &raw, "renew-self", Some(700), 101).unwrap();
    assert_eq!(response.body["auth"]["lease_duration"], 79);
    assert_eq!(reopened.tokens[&hash(&raw)].max_expires_at, Some(180));
    assert!(reopened.has_system_lease_defaults());
    let read = call(
        &mut reopened,
        &root,
        "team",
        "GET",
        "sys/auth/token/tune",
        json!({}),
        101,
    );
    assert_eq!(read.body["data"]["default_lease_ttl"], LEGACY_DEFAULT_TTL);
}

#[test]
fn token_api_past_current_max_fails_without_lease_or_metadata_publication() {
    let (mut state, _, root) = setup();
    let raw = create(&mut state, &root, "", json!({"ttl":300}));
    state.system_lease_defaults = None;
    state
        .tokens
        .get_mut(&hash(&raw))
        .unwrap()
        .token_api_lease_ttl = None;
    tune(&mut state, &root, "", json!({"max_lease_ttl":60}));
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let before = provider_renewal::state_revision(&state).unwrap();
        assert!(state.authenticate(&raw, 170).is_ok());
        assert_eq!(
            renew_api(&mut state, &root, "", &raw, operation, Some(100), 170)
                .err()
                .unwrap()
                .status,
            500
        );
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
        assert!(!state.has_system_lease_defaults());
    }
    let before = provider_renewal::state_revision(&state).unwrap();
    assert!(
        state
            .handle(
                Some(&root),
                "",
                "POST",
                "auth/token/create",
                &json!({"ttl":-1}),
                170
            )
            .is_err()
    );
    assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
}

#[test]
fn token_api_period_is_snapshot_but_current_mount_caps_each_renewal() {
    let (mut state, _, root) = setup();
    tune(&mut state, &root, "", json!({"max_lease_ttl":60}));
    let raw = create(
        &mut state,
        &root,
        "",
        json!({"period":200,"explicit_max_ttl":500}),
    );
    assert_eq!(state.tokens[&hash(&raw)].expires_at, Some(160));
    assert_eq!(state.tokens[&hash(&raw)].period, 200);
    tune(&mut state, &root, "", json!({"max_lease_ttl":300}));
    assert_eq!(
        renew_api(&mut state, &root, "", &raw, "renew-self", Some(1), 101)
            .unwrap()
            .body["auth"]["lease_duration"],
        200
    );
    assert_eq!(state.tokens[&hash(&raw)].max_expires_at, Some(600));
    assert_eq!(state.tokens[&hash(&raw)].period, 200);
}

#[test]
fn state_default_reaches_new_auth_mounts_without_extending_secret_id_defaults() {
    for (legacy, expected) in [(false, MAX_TTL), (true, LEGACY_DEFAULT_TTL)] {
        let (mut state, _, root) = setup();
        if legacy {
            state.system_lease_defaults = None;
        }
        for namespace in ["", "team"] {
            mount_auth(&mut state, &root, namespace, "new-approle", "approle");
            call(
                &mut state,
                &root,
                namespace,
                "POST",
                "auth/new-approle/role/app",
                json!({}),
                100,
            );
            let read = call(
                &mut state,
                &root,
                namespace,
                "GET",
                "auth/new-approle/role/app",
                json!({}),
                100,
            );
            assert_eq!(read.body["data"]["token_ttl"], expected);
            assert_eq!(read.body["data"]["token_max_ttl"], MAX_TTL);
            assert_eq!(read.body["data"]["secret_id_ttl"], 3600);
            call(
                &mut state,
                &root,
                namespace,
                "POST",
                "auth/new-approle/role/app",
                json!({"token_ttl":0,"token_max_ttl":0}),
                100,
            );
            let read = call(
                &mut state,
                &root,
                namespace,
                "GET",
                "auth/new-approle/role/app",
                json!({}),
                100,
            );
            assert_eq!(read.body["data"]["token_ttl"], expected);
            assert_eq!(read.body["data"]["secret_id_ttl"], 3600);
        }
    }
}

#[test]
fn malformed_system_defaults_fail_closed_and_legacy_absence_round_trips() {
    let (state, _, _) = setup();
    for defaults in [
        json!({"default_ttl":0,"max_ttl":MAX_TTL}),
        json!({"default_ttl":61,"max_ttl":60}),
        json!({"default_ttl":1,"max_ttl":MAX_TTL+1}),
    ] {
        let mut value = serde_json::to_value(&state).unwrap();
        value["system_lease_defaults"] = defaults;
        let corrupt: AuthState = serde_json::from_value(value).unwrap();
        assert!(corrupt.validate_system_lease_defaults().is_err());
        assert!(
            corrupt
                .auth_mount_token_limits(
                    AuthScope {
                        namespace: "",
                        mount: "token"
                    },
                    0,
                    0
                )
                .is_err()
        );
    }
    let mut legacy = serde_json::to_value(&state).unwrap();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("system_lease_defaults");
    let restored: AuthState = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(serde_json::to_value(restored).unwrap(), legacy);
}

#[test]
fn root_tokens_keep_the_nonexpiring_special_case_and_explicit_cap() {
    let (mut state, _, root) = setup();
    tune(&mut state, &root, "", json!({"max_lease_ttl":60}));
    let raw = token(&mut state, &root, "", json!({"policies":["root"]}), 100);
    assert_eq!(state.tokens[&hash(&raw)].expires_at, None);
    assert!(!state.tokens[&hash(&raw)].renewable);
    let finite = token(
        &mut state,
        &root,
        "",
        json!({"policies":["root"],"explicit_max_ttl":120}),
        100,
    );
    assert_eq!(state.tokens[&hash(&finite)].expires_at, Some(220));
    let actor = state.authenticate(&finite, 101).unwrap();
    assert_eq!(
        state
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/token/create",
                &json!({"policies":["root"]}),
                101
            )
            .err()
            .unwrap()
            .status,
        400
    );
}

#[test]
fn token_api_previous_grant_survives_renewal_restart_and_legacy_adoption() {
    let (mut state, _, root) = setup();
    tune(
        &mut state,
        &root,
        "",
        json!({"default_lease_ttl":75,"max_lease_ttl":900}),
    );
    let raw = create(&mut state, &root, "", json!({}));
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let mut candidate = state.clone();
        assert_eq!(
            renew_api(&mut candidate, &root, "", &raw, operation, Some(700), 101)
                .unwrap()
                .body["auth"]["lease_duration"],
            700
        );
        let mut reopened: AuthState =
            serde_json::from_slice(&serde_json::to_vec(&candidate).unwrap()).unwrap();
        tune(&mut reopened, &root, "", json!({"default_lease_ttl":95}));
        assert_eq!(
            renew_api(&mut reopened, &root, "", &raw, operation, None, 102)
                .unwrap()
                .body["auth"]["lease_duration"],
            700
        );
        assert_eq!(
            renew_api(&mut reopened, &root, "", &raw, operation, Some(0), 103)
                .unwrap()
                .body["auth"]["lease_duration"],
            700
        );
        assert_eq!(reopened.tokens[&hash(&raw)].token_api_lease_ttl, Some(700));
    }
    // A format-only historical fixture: an old lease may have been renewed,
    // so expires_at-created_at is not evidence of its last granted duration.
    state.system_lease_defaults = None;
    let target = state.tokens.get_mut(&hash(&raw)).unwrap();
    target.token_api_lease_ttl = None;
    target.max_expires_at = Some(100 + MAX_TTL);
    target.expires_at = Some(800);
    tune(&mut state, &root, "", json!({"max_lease_ttl":7200}));
    assert_eq!(
        renew_api(&mut state, &root, "", &raw, "renew-self", None, 101)
            .unwrap()
            .body["auth"]["lease_duration"],
        LEGACY_DEFAULT_TTL
    );
    assert_eq!(
        state.tokens[&hash(&raw)].token_api_lease_ttl,
        Some(LEGACY_DEFAULT_TTL)
    );
    assert_eq!(
        state.tokens[&hash(&raw)].max_expires_at,
        Some(100 + MAX_TTL)
    );
}

#[test]
fn token_api_grant_metadata_is_bound_to_its_issuer_and_cannot_hide_from_schema_gate() {
    let (mut state, _, root) = setup();
    let raw = create(&mut state, &root, "", json!({"ttl":60}));
    state.system_lease_defaults = None;
    assert!(state.has_system_lease_defaults());
    for ttl in [0, MAX_TTL + 1] {
        let mut corrupt = state.clone();
        corrupt
            .tokens
            .get_mut(&hash(&raw))
            .unwrap()
            .token_api_lease_ttl = Some(ttl);
        assert!(corrupt.validate_system_lease_defaults().is_err());
    }
    let mut corrupt = state.clone();
    corrupt.tokens.get_mut(&hash(&raw)).unwrap().auth_provenance = None;
    assert!(corrupt.validate_system_lease_defaults().is_err());
    let mut corrupt = state;
    corrupt.tokens.get_mut(&hash(&raw)).unwrap().expires_at = None;
    assert!(corrupt.validate_system_lease_defaults().is_err());
}
