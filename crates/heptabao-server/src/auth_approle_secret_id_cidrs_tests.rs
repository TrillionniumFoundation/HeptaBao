#![allow(clippy::unwrap_used)]
use super::*;

fn setup() -> (AuthState, Principal) {
    let (state, raw) = AuthState::bootstrap(100).unwrap();
    let root = state.authenticate_read_only(&raw, 100).unwrap().unwrap();
    (state, root)
}
fn call(
    state: &mut AuthState,
    root: &Principal,
    path: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(Some(root), "", "POST", path, &body, 100)?
        .ok_or_else(denied)
}
fn role(state: &mut AuthState, root: &Principal, body: Value) {
    assert_eq!(
        call(state, root, "auth/approle/role/example", body)
            .unwrap()
            .status,
        204
    );
}
fn issue(
    state: &mut AuthState,
    root: &Principal,
    mut body: Value,
    custom: bool,
) -> Result<AuthResponse, AuthError> {
    if custom {
        body["secret_id"] = json!("synthetic-custom-credential");
    }
    let operation = if custom {
        "custom-secret-id"
    } else {
        "secret-id"
    };
    call(
        state,
        root,
        &format!("auth/approle/role/example/{operation}"),
        body,
    )
}
fn bytes(state: &AuthState) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(serde_json::to_vec(state).unwrap())
}
fn credentials(state: &AuthState, issued: &AuthResponse) -> Value {
    json!({"role_id":state.roles[""]["example"].role_id,"secret_id":issued.body["data"]["secret_id"]})
}
fn login(state: &mut AuthState, body: &Value, peer: &str) -> AuthResponse {
    state
        .handle_with_connection(
            None,
            "",
            "POST",
            "auth/approle/login",
            body,
            100,
            None,
            Some(peer.parse().unwrap()),
        )
        .unwrap()
        .unwrap()
}
fn complete(state: &mut AuthState, response: &mut AuthResponse) -> Zeroizing<String> {
    assert_eq!(response.status, 200);
    response.login_identity.take();
    state
        .bind_issued_entity(response, "", "approle", "test-entity")
        .unwrap();
    state.finish_pending_batch(response, "", 100).unwrap();
    Zeroizing::new(
        response.body["auth"]["client_token"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
}

#[test]
fn secret_id_legacy_bytes_and_explicit_empty_presence_roundtrip() {
    let legacy = br#"{"accessor":"sa.legacy","expires_at":null,"uses_remaining":null}"#;
    let secret: SecretId = serde_json::from_slice(legacy).unwrap();
    assert!(serde_json::to_vec(&secret).unwrap().as_slice() == legacy);
    assert_eq!(
        approle_renewal::secret_id_info(&secret)["cidr_list"],
        json!([])
    );
    assert_eq!(
        approle_renewal::secret_id_info(&secret)["token_bound_cidrs"],
        json!([])
    );
    for custom in [false, true] {
        for value in [None, Some(Value::Null), Some(json!([])), Some(json!(""))] {
            let (mut state, root) = setup();
            role(&mut state, &root, json!({}));
            let mut body = json!({});
            if let Some(value) = &value {
                body["cidr_list"] = value.clone();
                body["token_bound_cidrs"] = value.clone();
            }
            let issued = issue(&mut state, &root, body, custom).unwrap();
            assert_eq!(issued.status, 200);
            assert_eq!(state.has_approle_secret_id_cidrs(), value.is_some());
            let secret = state.roles[""]["example"]
                .secret_ids
                .values()
                .next()
                .unwrap();
            assert_eq!(secret.cidr_list.is_some(), value.is_some());
            for field in ["cidr_list", "token_bound_cidrs"] {
                assert_eq!(approle_renewal::secret_id_info(secret)[field], json!([]));
            }
            let wire = bytes(&state);
            let reopened: AuthState = serde_json::from_slice(&wire).unwrap();
            reopened.validate_approle_token_bound_cidrs().unwrap();
            assert!(wire.as_slice() == bytes(&reopened).as_slice());
        }
    }
}

#[test]
fn secret_id_issue_parses_both_fields_preserves_host_bits_and_is_atomic_on_invalid_inputs() {
    for custom in [false, true] {
        for field in ["cidr_list", "token_bound_cidrs"] {
            for (value, status) in [
                (json!("127.0.0.1"), 500),
                (json!(["127.0.0.1/33"]), 500),
                (json!({}), 400),
                (json!([1]), 400),
            ] {
                let (mut state, root) = setup();
                role(&mut state, &root, json!({}));
                let before = bytes(&state);
                let mut body = json!({});
                body[field] = value;
                assert_eq!(
                    issue(&mut state, &root, body, custom).err().unwrap().status,
                    status
                );
                assert!(before.as_slice() == bytes(&state).as_slice());
            }
        }
        let (mut state, root) = setup();
        role(&mut state, &root, json!({}));
        let issued = issue(
            &mut state,
            &root,
            json!({"cidr_list":"127.0.0.99/24, ::1/128","token_bound_cidrs":["127.0.0.99/24"]}),
            custom,
        )
        .unwrap();
        let by_id = call(
            &mut state,
            &root,
            "auth/approle/role/example/secret-id/lookup",
            json!({"secret_id":issued.body["data"]["secret_id"]}),
        )
        .unwrap();
        let by_accessor = call(
            &mut state,
            &root,
            "auth/approle/role/example/secret-id-accessor/lookup",
            json!({"secret_id_accessor":issued.body["data"]["secret_id_accessor"]}),
        )
        .unwrap();
        assert!(by_id.body == by_accessor.body);
        assert_eq!(
            by_id.body["data"]["cidr_list"],
            json!(["127.0.0.99/24", "::1/128"])
        );
        assert_eq!(
            by_id.body["data"]["token_bound_cidrs"],
            json!(["127.0.0.99/24"])
        );
    }
}

#[test]
fn secret_id_subset_requires_one_parent_not_union_and_preserves_upstream_zero_mask_rule() {
    for (field, parent_field) in [
        ("cidr_list", "secret_id_bound_cidrs"),
        ("token_bound_cidrs", "token_bound_cidrs"),
    ] {
        for (parents, child, allowed) in [
            (json!(["127.0.0.0/24"]), "127.0.0.1/32", true),
            (json!(["127.0.0.0/24"]), "127.0.0.99/24", true),
            (json!(["127.0.0.0/24"]), "127.0.0.0/23", false),
            (json!(["127.0.0.0/24"]), "127.0.1.1/32", false),
            (
                json!(["127.0.0.0/25", "127.0.0.128/25"]),
                "127.0.0.0/24",
                false,
            ),
            (json!(["0.0.0.0/0"]), "127.0.0.0/0", false),
            (json!(["127.0.0.1/32"]), "127.0.0.1/32", true),
            (json!(["127.0.0.0/24"]), "::ffff:127.0.0.1/120", true),
            (json!(["::/0"]), "::ffff:127.0.0.1/120", false),
        ] {
            let (mut state, root) = setup();
            let mut input = json!({});
            input[parent_field] = parents;
            role(&mut state, &root, input);
            let before = bytes(&state);
            let mut input = json!({});
            input[field] = json!([child]);
            let result = issue(&mut state, &root, input, false);
            if allowed {
                assert_eq!(result.unwrap().status, 200);
            } else {
                assert_eq!(result.err().unwrap().status, 500);
                assert!(before.as_slice() == bytes(&state).as_slice());
            }
        }
    }
}

#[test]
fn secret_id_source_subset_error_precedes_invalid_token_prefix_without_mutation() {
    for custom in [false, true] {
        let (mut state, root) = setup();
        role(
            &mut state,
            &root,
            json!({"secret_id_bound_cidrs":["127.0.0.0/24"]}),
        );
        let before = bytes(&state);
        let error = issue(
            &mut state,
            &root,
            json!({"cidr_list":["127.0.1.0/24"],"token_bound_cidrs":["127.0.0.1/33"]}),
            custom,
        )
        .err()
        .unwrap();
        assert_eq!(error.status, 500);
        assert!(error.message.contains("subset relationship"));
        assert!(before.as_slice() == bytes(&state).as_slice());
    }
    // Preserve Go's raw prefix comparison for a mapped source parent. Role
    // token CIDRs normalize their representation before reaching this helper.
    let (mut state, root) = setup();
    role(
        &mut state,
        &root,
        json!({"secret_id_bound_cidrs":["::ffff:127.0.0.0/120"]}),
    );
    assert_eq!(
        issue(
            &mut state,
            &root,
            json!({"cidr_list":["127.0.0.1/24"]}),
            false
        )
        .err()
        .unwrap()
        .status,
        500
    );
}

#[test]
fn secret_id_source_denial_consumes_only_finite_authenticated_sid_for_service_and_batch() {
    for kind in ["service", "batch"] {
        for uses in [0, 1, 2] {
            for custom in [false, true] {
                let (mut state, root) = setup();
                role(
                    &mut state,
                    &root,
                    json!({"token_type":kind,"secret_id_num_uses":uses}),
                );
                let issued = issue(
                    &mut state,
                    &root,
                    json!({"cidr_list":["127.0.0.1/32"]}),
                    custom,
                )
                .unwrap();
                let body = credentials(&state, &issued);
                let before = bytes(&state);
                let mut rejected = login(&mut state, &body, "127.0.0.2");
                assert_eq!(rejected.status, 400);
                assert!(rejected.body.get("auth").is_none());
                assert!(rejected.pending_batch.is_none());
                assert!(rejected.login_identity.is_none());
                assert!(!rejected.mutated);
                assert!(before.as_slice() == bytes(&state).as_slice());
                assert_eq!(rejected.approle_secret_consumption.is_some(), uses > 0);
                if let Some(transition) = rejected.approle_secret_consumption.take() {
                    transition.apply(&mut state).unwrap();
                }
                let secrets = &state.roles[""]["example"].secret_ids;
                if uses == 1 {
                    assert!(secrets.is_empty());
                } else {
                    assert_eq!(
                        secrets.values().next().unwrap().uses_remaining,
                        if uses == 0 { None } else { Some(1) }
                    );
                    let mut accepted = login(&mut state, &body, "127.0.0.1");
                    let raw = complete(&mut state, &mut accepted);
                    assert!(
                        state
                            .authenticate_read_only_from(
                                &raw,
                                100,
                                Some("127.0.0.2".parse().unwrap())
                            )
                            .unwrap()
                            .is_some()
                    );
                    if uses == 2 {
                        assert!(state.roles[""]["example"].secret_ids.is_empty());
                    }
                }
            }
        }
    }
}

#[test]
fn secret_id_current_source_subset_failure_consumes_then_remains_recoverable_after_reopen() {
    for uses in [0, 2] {
        let (mut state, root) = setup();
        role(
            &mut state,
            &root,
            json!({"secret_id_num_uses":uses,"secret_id_bound_cidrs":["127.0.0.0/24"]}),
        );
        let issued = issue(
            &mut state,
            &root,
            json!({"cidr_list":["127.0.0.1/32"]}),
            false,
        )
        .unwrap();
        let body = credentials(&state, &issued);
        role(
            &mut state,
            &root,
            json!({"secret_id_bound_cidrs":["127.0.0.2/32"]}),
        );
        let mut reopened: AuthState = serde_json::from_slice(&bytes(&state)).unwrap();
        reopened.validate_approle_token_bound_cidrs().unwrap();
        let mut denied = login(&mut reopened, &body, "127.0.0.1");
        assert_eq!(denied.status, 500);
        assert_eq!(denied.approle_secret_consumption.is_some(), uses > 0);
        if let Some(transition) = denied.approle_secret_consumption.take() {
            transition.apply(&mut reopened).unwrap();
        }
        role(&mut reopened, &root, json!({"secret_id_bound_cidrs":[]}));
        assert_eq!(login(&mut reopened, &body, "127.0.0.1").status, 200);
    }
}

#[test]
fn secret_id_nonempty_token_override_survives_role_changes_and_empty_uses_current_role() {
    for kind in ["service", "batch"] {
        for explicit in [false, true] {
            let (mut state, root) = setup();
            role(
                &mut state,
                &root,
                json!({"token_type":kind,"token_bound_cidrs":["127.0.0.0/24"]}),
            );
            let issued = issue(&mut state, &root, json!({"token_bound_cidrs":if explicit { json!(["127.0.0.2/32"]) } else { json!([]) }}), false).unwrap();
            let body = credentials(&state, &issued);
            role(
                &mut state,
                &root,
                json!({"token_bound_cidrs":["127.0.0.1/32"]}),
            );
            let mut accepted = login(&mut state, &body, "127.0.0.1");
            let raw = complete(&mut state, &mut accepted);
            let (allowed, denied) = if explicit {
                ("127.0.0.2", "127.0.0.1")
            } else {
                ("127.0.0.1", "127.0.0.2")
            };
            assert!(
                state
                    .authenticate_read_only_from(&raw, 100, Some(allowed.parse().unwrap()))
                    .unwrap()
                    .is_some()
            );
            assert!(
                state
                    .authenticate_read_only_from(&raw, 100, Some(denied.parse().unwrap()))
                    .is_err()
            );
            role(&mut state, &root, json!({"token_bound_cidrs":[]}));
            let mut reopened: AuthState = serde_json::from_slice(&bytes(&state)).unwrap();
            reopened.validate_approle_token_bound_cidrs().unwrap();
            assert!(
                reopened
                    .authenticate_read_only_from(&raw, 100, Some(denied.parse().unwrap()))
                    .is_err()
            );
            let mut fresh = login(&mut reopened, &body, "127.0.0.1");
            let fresh_raw = complete(&mut reopened, &mut fresh);
            assert_eq!(
                reopened
                    .authenticate_read_only_from(
                        &fresh_raw,
                        100,
                        Some("127.0.0.1".parse().unwrap())
                    )
                    .is_ok(),
                !explicit
            );
            if kind == "service" {
                let mut actor = reopened
                    .authenticate_from(&raw, 100, Some(allowed.parse().unwrap()))
                    .unwrap();
                actor.bind_identity_policies(BTreeSet::new());
                assert_eq!(
                    reopened
                        .handle(
                            Some(&actor),
                            "",
                            "POST",
                            "auth/token/renew-self",
                            &json!({"increment":120}),
                            100
                        )
                        .unwrap()
                        .unwrap()
                        .status,
                    200
                );
                assert!(
                    reopened
                        .authenticate_read_only_from(&raw, 100, Some(denied.parse().unwrap()))
                        .is_err()
                );
            }
        }
    }
}

#[test]
fn secret_id_shape_validation_checks_retained_fields_namespace_mount_and_bounds() {
    let (mut state, root) = setup();
    let created = state
        .handle(
            Some(&root),
            "team",
            "POST",
            "sys/auth/build",
            &json!({"type":"approle"}),
            100,
        )
        .unwrap()
        .unwrap();
    assert_eq!(created.status, 204);
    for (path, body) in [
        ("auth/build/role/example", json!({})),
        (
            "auth/build/role/example/secret-id",
            json!({"cidr_list":[],"token_bound_cidrs":[]}),
        ),
    ] {
        assert!(
            state
                .handle(Some(&root), "team", "POST", path, &body, 100)
                .unwrap()
                .is_some()
        );
    }
    assert!(state.has_approle_secret_id_cidrs());
    state.validate_approle_token_bound_cidrs().unwrap();
    let mut malformed = state.clone();
    malformed
        .mounted_roles
        .get_mut("team")
        .unwrap()
        .get_mut("build")
        .unwrap()
        .get_mut("example")
        .unwrap()
        .secret_ids
        .values_mut()
        .next()
        .unwrap()
        .cidr_list = Some(vec!["127.0.0.1".into()]);
    assert!(malformed.validate_approle_token_bound_cidrs().is_err());
    let mut oversized = state.clone();
    oversized
        .mounted_roles
        .get_mut("team")
        .unwrap()
        .get_mut("build")
        .unwrap()
        .get_mut("example")
        .unwrap()
        .secret_ids
        .values_mut()
        .next()
        .unwrap()
        .token_bound_cidrs = Some(vec!["127.0.0.1/32".into(); 129]);
    assert!(oversized.validate_approle_token_bound_cidrs().is_err());
    let roles = state
        .mounted_roles
        .get_mut("team")
        .unwrap()
        .remove("build")
        .unwrap();
    state
        .mounted_roles
        .entry("other".into())
        .or_default()
        .insert("build".into(), roles);
    assert!(state.validate_approle_token_bound_cidrs().is_err());
}

#[test]
fn secret_id_consumption_capsule_compares_full_cidr_snapshot_and_cannot_replay() {
    let (mut state, root) = setup();
    role(&mut state, &root, json!({"secret_id_num_uses":2}));
    let issued = issue(
        &mut state,
        &root,
        json!({"cidr_list":["127.0.0.1/32"],"token_bound_cidrs":[]}),
        false,
    )
    .unwrap();
    let body = credentials(&state, &issued);
    let mut first = login(&mut state, &body, "127.0.0.2");
    let mut duplicate = login(&mut state, &body, "127.0.0.2");
    let mut changed = state.clone();
    changed
        .roles
        .get_mut("")
        .unwrap()
        .get_mut("example")
        .unwrap()
        .secret_ids
        .values_mut()
        .next()
        .unwrap()
        .token_bound_cidrs = Some(vec!["127.0.0.2/32".into()]);
    let before = bytes(&changed);
    assert_eq!(
        duplicate
            .approle_secret_consumption
            .take()
            .unwrap()
            .apply(&mut changed)
            .err()
            .unwrap()
            .status,
        409
    );
    assert!(before.as_slice() == bytes(&changed).as_slice());
    let mut replay = login(&mut state, &body, "127.0.0.2");
    first
        .approle_secret_consumption
        .take()
        .unwrap()
        .apply(&mut state)
        .unwrap();
    let consumed = bytes(&state);
    assert_eq!(
        replay
            .approle_secret_consumption
            .take()
            .unwrap()
            .apply(&mut state)
            .err()
            .unwrap()
            .status,
        409
    );
    assert!(consumed.as_slice() == bytes(&state).as_slice());
}
