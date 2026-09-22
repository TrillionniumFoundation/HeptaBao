use super::*;

fn lookup_all(state: &mut AuthState, root: &Principal, raw: &str, now: u64) -> Vec<Value> {
    let actor = state.authenticate(raw, now).unwrap();
    let accessor = state.tokens[&hash(raw)].accessor.clone();
    [
        ("lookup-self", &actor, json!({})),
        ("lookup", root, json!({"token":raw})),
        ("lookup-accessor", root, json!({"accessor":accessor})),
    ]
    .into_iter()
    .map(|(route, actor, body)| {
        let response = call(
            state,
            actor,
            "",
            "GET",
            &format!("auth/token/{route}"),
            body,
            now,
        );
        assert_eq!(response.status, 200);
        response.body["data"].clone()
    })
    .collect()
}

fn tune_token(state: &mut AuthState, root: &Principal, ttl: u64, maximum: u64) {
    call(
        state,
        root,
        "",
        "POST",
        "sys/auth/token/tune",
        json!({"default_lease_ttl":ttl,"max_lease_ttl":maximum}),
        100,
    );
}

#[test]
fn token_api_lookup_retains_its_initial_grant_across_every_renewal_and_reopen() {
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let (mut state, _, root) = setup();
        tune_token(&mut state, &root, 75, 900);
        let raw = token(&mut state, &root, "", json!({"policies":["default"]}), 100);
        let accessor = state.tokens[&hash(&raw)].accessor.clone();
        for lookup in lookup_all(&mut state, &root, &raw, 100) {
            assert_eq!(lookup["creation_ttl"], 75);
            assert_eq!(lookup["ttl"], 75);
        }
        let actor = state.authenticate(&raw, 101).unwrap();
        let mut body = json!({"increment":300});
        if operation == "renew" {
            body["token"] = json!(raw);
        } else if operation == "renew-accessor" {
            body["accessor"] = json!(accessor);
        }
        let renewed = call(
            &mut state,
            if operation == "renew-self" {
                &actor
            } else {
                &root
            },
            "",
            "POST",
            &format!("auth/token/{operation}"),
            body,
            101,
        );
        assert_eq!(renewed.body["auth"]["lease_duration"], 300);
        assert_eq!(state.tokens[&hash(&raw)].token_api_lease_ttl, Some(300));
        // The reopened lookup must not substitute the changed renewal grant.
        let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        let mut state: AuthState = serde_json::from_slice(&encoded).unwrap();
        state.validate_token_api_creation_ttl().unwrap();
        for lookup in lookup_all(&mut state, &root, &raw, 101) {
            assert_eq!(lookup["creation_ttl"], 75);
            assert_eq!(lookup["ttl"], 300);
        }
        // Shorter subsequent renewals likewise preserve the initial value.
        call(
            &mut state,
            &root,
            "",
            "POST",
            "auth/token/renew",
            json!({"token":raw,"increment":10}),
            102,
        );
        state.validate_token_api_creation_ttl().unwrap();
        assert_eq!(state.tokens[&hash(&raw)].expires_at, Some(112));
        for lookup in lookup_all(&mut state, &root, &raw, 102) {
            assert_eq!(lookup["creation_ttl"], 75);
            assert_eq!(lookup["ttl"], 10);
        }
    }
}

#[test]
fn token_api_children_and_orphans_capture_their_own_grant_not_the_parent() {
    let (mut state, _, root) = setup();
    put_policy(
        &mut state,
        &root,
        "",
        "issuer",
        json!(r#"path "auth/token/create*" { capabilities = ["update", "sudo"] }"#),
    );
    tune_token(&mut state, &root, 75, 600);
    let parent = token(
        &mut state,
        &root,
        "",
        json!({"policies":["default","issuer"],"ttl":240}),
        100,
    );
    let issuer = state.authenticate(&parent, 101).unwrap();
    for orphan in [false, true] {
        let child = token(
            &mut state,
            &issuer,
            "",
            json!({"policies":["default"],"ttl":120,"explicit_max_ttl":40,"no_parent":orphan}),
            101,
        );
        assert_eq!(state.tokens[&hash(&child)].parent.is_none(), orphan);
        for lookup in lookup_all(&mut state, &root, &child, 101) {
            assert_eq!(lookup["creation_ttl"], 40);
            assert_eq!(lookup["ttl"], 40);
        }
    }
    assert_eq!(
        token_info(&state.tokens[&hash(&parent)], 101)["creation_ttl"],
        240
    );
    state.validate_token_api_creation_ttl().unwrap();
}

#[test]
fn token_api_creation_ttl_old_marker_bytes_and_absence_survive_read_renew_reopen() {
    const OLD_MARKER: &[u8] = br#"{"kind":"token_api"}"#;
    let old: TokenAuthProvenance = serde_json::from_slice(OLD_MARKER).unwrap();
    assert_eq!(serde_json::to_vec(&old).unwrap(), OLD_MARKER);
    for invalid in [
        br#"{"kind":"token_api","unexpected":1}"#.as_slice(),
        br#"{"kind":"token_api","issued_creation_ttl":-1}"#.as_slice(),
        br#"{"kind":"token_api","issued_creation_ttl":"60"}"#.as_slice(),
    ] {
        assert!(serde_json::from_slice::<TokenAuthProvenance>(invalid).is_err());
    }
    let (mut state, _, root) = setup();
    let raw = token(
        &mut state,
        &root,
        "",
        json!({"policies":["default"],"ttl":75}),
        100,
    );
    state.tokens.get_mut(&hash(&raw)).unwrap().auth_provenance = Some(old);
    assert!(!state.has_token_api_creation_ttl());
    let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut state: AuthState = serde_json::from_slice(&before).unwrap();
    for lookup in lookup_all(&mut state, &root, &raw, 101) {
        assert!(lookup.get("creation_ttl").is_none());
    }
    assert_eq!(
        serde_json::to_vec(&state).unwrap().as_slice(),
        before.as_slice()
    );
    call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/renew",
        json!({"token":raw,"increment":300}),
        102,
    );
    assert!(!state.has_token_api_creation_ttl());
    let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut reopened: AuthState = serde_json::from_slice(&encoded).unwrap();
    for lookup in lookup_all(&mut reopened, &root, &raw, 102) {
        assert!(lookup.get("creation_ttl").is_none());
    }
    state.omit_lease_metadata_for_legacy_fixture();
    assert!(!state.has_token_api_creation_ttl());
}

#[test]
fn token_api_periodic_creation_ttl_is_the_clamped_grant_not_issued_period() {
    let (mut state, _, root) = setup();
    tune_token(&mut state, &root, 0, 20);
    let raw = token(
        &mut state,
        &root,
        "",
        json!({"policies":["default"],"period":30}),
        100,
    );
    assert_eq!(state.tokens[&hash(&raw)].period, 30);
    assert_eq!(
        token_info(&state.tokens[&hash(&raw)], 100)["creation_ttl"],
        20
    );
    tune_token(&mut state, &root, 75, 600);
    let renewed = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/token/renew",
        json!({"token":raw}),
        101,
    );
    assert_eq!(renewed.body["auth"]["lease_duration"], 30);
    assert_eq!(
        token_info(&state.tokens[&hash(&raw)], 101)["creation_ttl"],
        20
    );
    state.validate_system_lease_defaults().unwrap();
}

#[test]
fn token_api_creation_zero_is_only_a_permanent_root_and_explicit_root_is_finite() {
    let (mut state, _, root) = setup();
    for orphan in [false, true] {
        let raw = token(
            &mut state,
            &root,
            "",
            json!({"policies":["root"],"no_parent":orphan}),
            100,
        );
        for lookup in lookup_all(&mut state, &root, &raw, 101) {
            assert_eq!(lookup["creation_ttl"], 0);
            assert_eq!(lookup["ttl"], 0);
            assert_eq!(lookup["renewable"], false);
        }
        assert!(state.has_token_api_creation_ttl());
        state.validate_token_api_creation_ttl().unwrap();
        let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        assert!(
            state
                .handle(
                    Some(&root),
                    "",
                    "POST",
                    "auth/token/renew",
                    &json!({"token":raw}),
                    101
                )
                .is_err()
        );
        assert_eq!(
            serde_json::to_vec(&state).unwrap().as_slice(),
            before.as_slice()
        );
        for mutation in [
            "not-root",
            "extra-policy",
            "namespace",
            "expiry",
            "cap",
            "period",
            "renewable",
            "cidr",
        ] {
            let mut corrupt = state.clone();
            let token = corrupt.tokens.get_mut(&hash(&raw)).unwrap();
            match mutation {
                "not-root" => token.root = false,
                "extra-policy" => {
                    token.policies.insert("default".into());
                }
                "namespace" => token.namespace = "other".into(),
                "expiry" => token.expires_at = Some(120),
                "cap" => token.max_expires_at = Some(120),
                "period" => token.period = 30,
                "renewable" => token.renewable = true,
                _ => token.bound_cidrs = vec!["127.0.0.1/32".into()],
            }
            assert!(
                corrupt.validate_system_lease_defaults().is_err(),
                "{mutation}"
            );
        }
    }
    let raw = token(
        &mut state,
        &root,
        "",
        json!({"policies":["root"],"explicit_max_ttl":40}),
        100,
    );
    assert_eq!(
        token_info(&state.tokens[&hash(&raw)], 100)["creation_ttl"],
        40
    );
    state.validate_token_api_creation_ttl().unwrap();
    state.omit_lease_metadata_for_legacy_fixture();
    assert!(!state.has_token_api_creation_ttl());
}

#[test]
fn token_api_creation_ttl_validator_rejects_impossible_issuance_without_time_liveness() {
    let (mut state, _, root) = setup();
    let raw = token(
        &mut state,
        &root,
        "",
        json!({"policies":["default"],"ttl":40,"explicit_max_ttl":60}),
        100,
    );
    for invalid in [0, MAX_TTL + 1, 61] {
        let mut corrupt = state.clone();
        corrupt.tokens.get_mut(&hash(&raw)).unwrap().auth_provenance =
            Some(TokenAuthProvenance::TokenApi {
                issued_creation_ttl: Some(invalid),
            });
        assert!(corrupt.validate_system_lease_defaults().is_err());
    }
    for mutation in [
        "no-expiry",
        "overflow",
        "cert-role",
        "cert-digest",
        "period",
    ] {
        let mut corrupt = state.clone();
        let token = corrupt.tokens.get_mut(&hash(&raw)).unwrap();
        match mutation {
            "no-expiry" => token.expires_at = None,
            "overflow" => token.created_at = u64::MAX,
            "cert-role" => token.auth_cert_role = Some("operator".into()),
            "cert-digest" => token.auth_cert_sha256 = Some("synthetic".into()),
            _ => token.period = MAX_TTL + 1,
        }
        assert!(
            corrupt.validate_system_lease_defaults().is_err(),
            "{mutation}"
        );
    }
    // Retired/expired tokens may still be retained for reconciliation. Shape
    // validation has no clock and must not require an active lease or mount.
    state.tokens.get_mut(&hash(&raw)).unwrap().uses_remaining = Some(0);
    state.validate_system_lease_defaults().unwrap();
    assert_eq!(
        token_info(&state.tokens[&hash(&raw)], 1000)["creation_ttl"],
        40
    );
    assert_eq!(token_info(&state.tokens[&hash(&raw)], 1000)["ttl"], 0);
    assert!(state.has_token_api_creation_ttl());
    let wrapped = state
        .wrap_response(
            "",
            "synthetic/wrapped",
            60,
            &json!({"data":{"value":1}}),
            100,
        )
        .unwrap();
    let wrapper = wrapped.body["wrap_info"]["token"].as_str().unwrap();
    state
        .tokens
        .get_mut(&hash(wrapper))
        .unwrap()
        .auth_provenance = Some(TokenAuthProvenance::TokenApi {
        issued_creation_ttl: Some(60),
    });
    assert!(state.validate_token_api_creation_ttl().is_err());
}
