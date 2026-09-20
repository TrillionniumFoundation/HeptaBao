use super::*;

fn issuer_state() -> (AuthState, Principal) {
    let (mut state, _, root) = setup();
    put_policy(
        &mut state,
        &root,
        "",
        "issuer",
        json!(r#"path "auth/token/create*" { capabilities = ["update", "sudo"] }"#),
    );
    (state, root)
}

fn descendant(state: &mut AuthState, issuer: &str, ttl: u64, now: u64) -> String {
    let actor = state.authenticate(issuer, now).unwrap();
    token(
        state,
        &actor,
        "",
        json!({"policies": ["issuer"], "ttl": ttl}),
        now,
    )
}

#[test]
fn children_report_own_ttl_but_all_renewal_paths_still_require_live_ancestors() {
    let (mut baseline, root) = issuer_state();
    let parent = token(
        &mut baseline,
        &root,
        "",
        json!({"policies": ["issuer"], "ttl": 60}),
        100,
    );
    let child = descendant(&mut baseline, &parent, 120, 101);
    let grandchild = descendant(&mut baseline, &child, 240, 102);
    assert_eq!(baseline.tokens[&hash(&child)].expires_at, Some(221));
    assert_eq!(baseline.tokens[&hash(&grandchild)].expires_at, Some(342));
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let mut state = baseline.clone();
        let actor = state.authenticate(&grandchild, 110).unwrap();
        let body = match operation {
            "renew" => json!({"token": grandchild, "increment": 600}),
            "renew-accessor" => {
                json!({"accessor": state.tokens[&hash(&grandchild)].accessor, "increment": 600})
            }
            _ => json!({"increment": 600}),
        };
        let response = call(
            &mut state,
            if operation == "renew-self" {
                &actor
            } else {
                &root
            },
            "",
            "POST",
            &format!("auth/token/{operation}"),
            body.clone(),
            110,
        );
        assert_eq!(response.body["auth"]["lease_duration"], 600);
        assert_eq!(state.tokens[&hash(&grandchild)].expires_at, Some(710));
        let mut state: AuthState =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(state.authenticate(&grandchild, 159).is_ok());
        // Dynamic-secret issuance retains its separate conservative ancestor
        // bound; relaxing the reported token lifetime must not change it.
        assert_eq!(
            state
                .lease_issuer_by_digest(&hash(&grandchild), "", 159)
                .unwrap()
                .expires_at,
            Some(160)
        );
        assert!(state.authenticate(&grandchild, 160).is_err());
        assert!(state.authenticate_read_only(&grandchild, 160).is_err());
        let denied = state.handle(
            Some(if operation == "renew-self" {
                &actor
            } else {
                &root
            }),
            "",
            "POST",
            &format!("auth/token/{operation}"),
            &body,
            160,
        );
        assert_eq!(denied.err().unwrap().status, 403);
        assert_eq!(state.tokens[&hash(&grandchild)].expires_at, Some(710));
    }
}

#[test]
fn intermediate_expiry_missing_parent_cycles_and_revoke_remain_authoritative() {
    let (mut baseline, root) = issuer_state();
    let parent = token(
        &mut baseline,
        &root,
        "",
        json!({"policies": ["issuer"], "ttl": 600}),
        100,
    );
    let child = descendant(&mut baseline, &parent, 20, 101);
    let grandchild = descendant(&mut baseline, &child, 300, 102);
    let child_actor = baseline.authenticate(&child, 103).unwrap();
    let orphan = token(
        &mut baseline,
        &child_actor,
        "",
        json!({"policies": ["default"], "ttl": 300, "no_parent": true}),
        103,
    );
    assert!(baseline.authenticate(&grandchild, 120).is_ok());
    assert!(baseline.authenticate(&grandchild, 121).is_err());
    assert!(baseline.authenticate(&parent, 121).is_ok());
    assert!(baseline.authenticate(&orphan, 121).is_ok());

    let mut extended = baseline.clone();
    let response = call(
        &mut extended,
        &child_actor,
        "",
        "POST",
        "auth/token/renew-self",
        json!({"increment": 300}),
        110,
    );
    assert_eq!(response.body["auth"]["lease_duration"], 300);
    assert!(extended.authenticate(&grandchild, 121).is_ok());
    for mutation in ["missing", "cycle", "exhausted", "revoked"] {
        let mut state = baseline.clone();
        match mutation {
            "missing" => {
                state.tokens.remove(&hash(&child));
            }
            "cycle" => {
                state.tokens.get_mut(&hash(&parent)).unwrap().parent = Some(hash(&grandchild))
            }
            "exhausted" => state.tokens.get_mut(&hash(&child)).unwrap().uses_remaining = Some(0),
            _ => {
                call(
                    &mut state,
                    &root,
                    "",
                    "POST",
                    "auth/token/revoke",
                    json!({"token": parent}),
                    110,
                );
            }
        }
        assert!(state.authenticate(&grandchild, 110).is_err());
        assert!(state.authenticate(&orphan, 110).is_ok());
    }
}

#[test]
fn child_explicit_cap_is_independent_of_parent_renewal_and_survives_restart() {
    let (mut state, root) = issuer_state();
    let parent = token(
        &mut state,
        &root,
        "",
        json!({"policies": ["issuer"], "ttl": 60}),
        100,
    );
    let actor = state.authenticate(&parent, 101).unwrap();
    let response = call(
        &mut state,
        &actor,
        "",
        "POST",
        "auth/token/create",
        json!({"policies": ["default"], "ttl": 120, "explicit_max_ttl": 90}),
        101,
    );
    assert_eq!(response.body["auth"]["lease_duration"], 90);
    let child = response.body["auth"]["client_token"].as_str().unwrap();
    let child_actor = state.authenticate(child, 110).unwrap();
    let response = call(
        &mut state,
        &child_actor,
        "",
        "POST",
        "auth/token/renew-self",
        json!({"increment": 300}),
        110,
    );
    assert_eq!(response.body["auth"]["lease_duration"], 81);
    call(
        &mut state,
        &actor,
        "",
        "POST",
        "auth/token/renew-self",
        json!({"increment": 300}),
        110,
    );
    let mut state: AuthState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(state.authenticate(child, 190).is_ok());
    assert!(state.authenticate(child, 191).is_err());
    assert!(state.authenticate(&parent, 191).is_ok());
}

#[test]
fn lookup_period_omits_zero_and_retains_issue_snapshot_after_live_role_changes() {
    for (initial, current) in [(0, 30), (30, 45), (30, 0)] {
        let (mut state, root) = issuer_state();
        call(
            &mut state,
            &root,
            "",
            "POST",
            "auth/approle/role/period-snapshot",
            json!({"token_ttl": 60, "token_max_ttl": 600, "token_period": initial, "secret_id_num_uses": 0}),
            100,
        );
        let role_id = call(
            &mut state,
            &root,
            "",
            "GET",
            "auth/approle/role/period-snapshot/role-id",
            json!({}),
            100,
        )
        .body["data"]["role_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let secret_id = call(
            &mut state,
            &root,
            "",
            "POST",
            "auth/approle/role/period-snapshot/secret-id",
            json!({}),
            100,
        )
        .body["data"]["secret_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let login = state
            .handle(
                None,
                "",
                "POST",
                "auth/approle/login",
                &json!({"role_id": role_id, "secret_id": secret_id}),
                100,
            )
            .unwrap()
            .unwrap();
        let raw = login.body["auth"]["client_token"].as_str().unwrap();
        let actor = state.authenticate(raw, 101).unwrap();
        let before = call(
            &mut state,
            &actor,
            "",
            "GET",
            "auth/token/lookup-self",
            json!({}),
            101,
        );
        let expected_period = (initial > 0).then(|| json!(initial));
        assert_eq!(before.body["data"].get("period"), expected_period.as_ref());
        call(
            &mut state,
            &root,
            "",
            "POST",
            "auth/approle/role/period-snapshot",
            json!({"token_period": current}),
            102,
        );
        let renewed = call(
            &mut state,
            &actor,
            "",
            "POST",
            "auth/token/renew-self",
            json!({}),
            102,
        );
        assert_eq!(
            renewed.body["auth"]["lease_duration"],
            if current == 0 { 60 } else { current }
        );
        let mut state: AuthState =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        let after = call(
            &mut state,
            &actor,
            "",
            "GET",
            "auth/token/lookup-self",
            json!({}),
            103,
        );
        assert_eq!(
            after.body["data"].get("period"),
            before.body["data"].get("period")
        );
    }
}
