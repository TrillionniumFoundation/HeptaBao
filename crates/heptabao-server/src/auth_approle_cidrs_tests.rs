#![allow(clippy::unwrap_used)]
use super::*;
fn setup() -> (AuthState, String, Principal) {
    let (state, raw) = AuthState::bootstrap(100).unwrap();
    let root = state.authenticate_read_only(&raw, 100).unwrap().unwrap();
    (state, raw, root)
}
fn call(
    state: &mut AuthState,
    actor: Option<&Principal>,
    method: &str,
    path: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(actor, "", method, path, &body, 100)?
        .ok_or_else(denied)
}
fn role(state: &mut AuthState, root: &Principal, body: Value) -> Result<AuthResponse, AuthError> {
    call(state, Some(root), "POST", "auth/approle/role/source", body)
}
fn field(
    state: &mut AuthState,
    root: &Principal,
    method: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    call(
        state,
        Some(root),
        method,
        "auth/approle/role/source/token-bound-cidrs",
        body,
    )
}
fn stored(state: &AuthState) -> &Role {
    &state.roles[""]["source"]
}
fn credentials(state: &mut AuthState, root: &Principal) -> Value {
    let rid = stored(state).role_id.clone();
    let sid = call(
        state,
        Some(root),
        "POST",
        "auth/approle/role/source/secret-id",
        json!({}),
    )
    .unwrap();
    json!({"role_id":rid,"secret_id":sid.body["data"]["secret_id"]})
}
fn login(
    state: &mut AuthState,
    body: &Value,
    peer: Option<&str>,
) -> Result<AuthResponse, AuthError> {
    let mut response = state
        .handle_with_connection(
            None,
            "",
            "POST",
            "auth/approle/login",
            body,
            100,
            None,
            peer.map(|p| p.parse().unwrap()),
        )?
        .ok_or_else(denied)?;
    // Auth-only test: use the production pending grant bind/seal operations.
    response.login_identity.take();
    state.bind_issued_entity(&mut response, "", "approle", "test-entity")?;
    state.finish_pending_batch(&mut response, "", 100)?;
    Ok(response)
}
#[test]
fn approle_cidr_presence_clear_and_dedicated_route_are_one_role_state() {
    let (mut state, _, root) = setup();
    role(&mut state, &root, json!({})).unwrap();
    let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    assert!(stored(&state).token_bound_cidrs.is_none());
    assert_eq!(
        field(&mut state, &root, "GET", json!({})).unwrap().body["data"]["token_bound_cidrs"],
        Value::Null
    );
    assert_eq!(
        before.as_slice(),
        Zeroizing::new(serde_json::to_vec(&state).unwrap()).as_slice()
    );
    role(
        &mut state,
        &root,
        json!({"token_bound_cidrs":"127.0.0.1/32,::1/128"}),
    )
    .unwrap();
    assert_eq!(
        stored(&state).token_bound_cidrs,
        Some(vec!["127.0.0.1".to_owned(), "::1".to_owned()])
    );
    role(&mut state, &root, json!({"token_ttl":60})).unwrap();
    field(&mut state, &root, "POST", json!({})).unwrap();
    assert_eq!(stored(&state).token_bound_cidrs.as_ref().unwrap().len(), 2);
    for empty in [Value::Null, json!([]), json!("")] {
        field(
            &mut state,
            &root,
            "POST",
            json!({"token_bound_cidrs":empty}),
        )
        .unwrap();
        assert_eq!(
            field(&mut state, &root, "GET", json!({})).unwrap().body["data"]["token_bound_cidrs"],
            json!([])
        );
        assert!(state.has_approle_token_bound_cidrs());
        role(
            &mut state,
            &root,
            json!({"token_bound_cidrs":["127.0.0.1"]}),
        )
        .unwrap();
    }
    field(&mut state, &root, "DELETE", json!({})).unwrap();
    assert!(stored(&state).token_bound_cidrs.is_none());
    assert_eq!(
        field(&mut state, &root, "GET", json!({})).unwrap().body["data"]["token_bound_cidrs"],
        Value::Null
    );
    assert_eq!(
        call(
            &mut state,
            Some(&root),
            "GET",
            "auth/approle/role/source",
            json!({})
        )
        .unwrap()
        .body["data"]["token_bound_cidrs"],
        json!([])
    );
}
#[test]
fn approle_token_cidrs_do_not_restrict_login_or_skip_finite_secret_consumption() {
    for kind in ["service", "batch"] {
        for peer in [None, Some("127.0.0.2")] {
            let (mut state, _, root) = setup();
            role(
                &mut state,
                &root,
                json!({"token_type":kind,"token_ttl":120,"token_max_ttl":600,
                "token_bound_cidrs":["127.0.0.1/32"],"secret_id_num_uses":1}),
            )
            .unwrap();
            let credentials = credentials(&mut state, &root);
            let result = login(&mut state, &credentials, peer).unwrap();
            let token = result.body["auth"]["client_token"].as_str().unwrap();
            assert_eq!(
                state
                    .authenticate_from(token, 100, Some("127.0.0.2".parse().unwrap()))
                    .err()
                    .unwrap()
                    .status,
                403
            );
            assert!(
                state
                    .authenticate_from(token, 100, Some("::ffff:127.0.0.1".parse().unwrap()))
                    .is_ok()
            );
            assert_eq!(
                state
                    .authenticate_from(token, 100, None)
                    .err()
                    .unwrap()
                    .status,
                403
            );
            assert!(stored(&state).secret_ids.is_empty());
            assert_eq!(
                login(&mut state, &credentials, Some("127.0.0.1"))
                    .err()
                    .unwrap()
                    .status,
                400
            );
        }
    }
}
#[test]
fn approle_cidr_changes_do_not_rebind_issued_service_or_batch_and_admin_targets_ignore_peer() {
    for kind in ["service", "batch"] {
        let (mut state, admin_raw, root) = setup();
        role(
            &mut state,
            &root,
            json!({"token_type":kind,"token_ttl":120,"token_max_ttl":600,
            "token_bound_cidrs":["127.0.0.1"]}),
        )
        .unwrap();
        let credentials = credentials(&mut state, &root);
        let issued = login(&mut state, &credentials, Some("127.0.0.2")).unwrap();
        let raw = issued.body["auth"]["client_token"]
            .as_str()
            .unwrap()
            .to_owned();
        role(&mut state, &root, json!({"token_bound_cidrs":null})).unwrap();
        let admin = state
            .authenticate_from(&admin_raw, 101, Some("127.0.0.2".parse().unwrap()))
            .unwrap();
        let lookup = state
            .handle(
                Some(&admin),
                "",
                "POST",
                "auth/token/lookup",
                &json!({"token":raw}),
                101,
            )
            .unwrap()
            .unwrap();
        assert_eq!(lookup.body["data"]["bound_cidrs"], json!(["127.0.0.1"]));
        if kind == "service" {
            for (path, body) in [
                ("auth/token/renew", json!({"token":raw,"increment":180})),
                (
                    "auth/token/renew-accessor",
                    json!({"accessor":issued.body["auth"]["accessor"],"increment":180}),
                ),
            ] {
                assert_eq!(
                    state
                        .handle(Some(&admin), "", "POST", path, &body, 101)
                        .unwrap()
                        .unwrap()
                        .status,
                    200
                );
            }
            assert_eq!(state.tokens[&hash(&raw)].bound_cidrs, ["127.0.0.1"]);
        }
        assert_eq!(
            state
                .authenticate_from(&raw, 101, Some("127.0.0.2".parse().unwrap()))
                .err()
                .unwrap()
                .status,
            403
        );
        let new = login(&mut state, &credentials, Some("127.0.0.2")).unwrap();
        assert!(
            state
                .authenticate_from(
                    new.body["auth"]["client_token"].as_str().unwrap(),
                    101,
                    Some("127.0.0.2".parse().unwrap())
                )
                .is_ok()
        );
        let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        let mut restored: AuthState = serde_json::from_slice(&encoded).unwrap();
        restored.validate_approle_token_bound_cidrs().unwrap();
        assert_eq!(
            restored
                .authenticate_from(&raw, 101, Some("127.0.0.2".parse().unwrap()))
                .err()
                .unwrap()
                .status,
            403
        );
    }
}
#[test]
fn approle_cidr_field_acl_atomic_failure_and_constraint_removal() {
    let (mut state, _, root) = setup();
    let path = "auth/approle/role/missing/token-bound-cidrs";
    assert_eq!(
        call(&mut state, None, "GET", path, json!({}))
            .err()
            .unwrap()
            .status,
        403
    );
    let read = call(&mut state, Some(&root), "GET", path, json!({})).unwrap();
    assert_eq!(read.status, 404);
    assert_eq!(read.body, json!({"errors":[]}));
    assert_eq!(
        call(&mut state, Some(&root), "DELETE", path, json!({}))
            .unwrap()
            .status,
        204
    );
    assert_eq!(
        call(
            &mut state,
            Some(&root),
            "POST",
            path,
            json!({"token_bound_cidrs":[]})
        )
        .err()
        .unwrap()
        .status,
        404
    );
    role(
        &mut state,
        &root,
        json!({"bind_secret_id":false,"token_bound_cidrs":["127.0.0.1"]}),
    )
    .unwrap();
    let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    assert_eq!(
        field(&mut state, &root, "DELETE", json!({}))
            .err()
            .unwrap()
            .status,
        500
    );
    assert_eq!(
        role(&mut state, &root, json!({"token_bound_cidrs":null}))
            .err()
            .unwrap()
            .status,
        500
    );
    assert_eq!(
        role(
            &mut state,
            &root,
            json!({"token_ttl":5,"token_bound_cidrs":{}})
        )
        .err()
        .unwrap()
        .status,
        400
    );
    assert_eq!(
        before.as_slice(),
        Zeroizing::new(serde_json::to_vec(&state).unwrap()).as_slice()
    );
}

#[test]
fn approle_cidr_legacy_absence_roundtrip_and_noncanonical_or_foreign_mount_rejected() {
    let (mut state, _, root) = setup();
    role(&mut state, &root, json!({})).unwrap();
    let old = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    assert!(!state.has_approle_token_bound_cidrs());
    let roundtrip: AuthState = serde_json::from_slice(&old).unwrap();
    assert_eq!(
        old.as_slice(),
        Zeroizing::new(serde_json::to_vec(&roundtrip).unwrap()).as_slice()
    );
    role(&mut state, &root, json!({"token_bound_cidrs":[]})).unwrap();
    assert!(state.has_approle_token_bound_cidrs());
    let wire = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut restored: AuthState = serde_json::from_slice(&wire).unwrap();
    assert!(restored.has_approle_token_bound_cidrs());
    restored
        .roles
        .get_mut("")
        .unwrap()
        .get_mut("source")
        .unwrap()
        .token_bound_cidrs = Some(vec!["127.0.0.1/32".into()]);
    assert!(restored.validate_approle_token_bound_cidrs().is_err());
    restored
        .roles
        .get_mut("")
        .unwrap()
        .get_mut("source")
        .unwrap()
        .token_bound_cidrs = Some(Vec::new());
    let role = restored
        .roles
        .get_mut("")
        .unwrap()
        .remove("source")
        .unwrap();
    restored
        .mounted_roles
        .entry("".into())
        .or_default()
        .entry("userpass".into())
        .or_default()
        .insert("source".into(), role);
    assert!(restored.validate_approle_token_bound_cidrs().is_err());
}

#[test]
fn approle_cidr_dedicated_update_needs_only_its_own_acl_and_cannot_smuggle_role_fields() {
    let (mut state, _, root) = setup();
    role(&mut state, &root, json!({"token_ttl":60})).unwrap();
    call(&mut state, Some(&root), "PUT", "sys/policies/acl/field-editor",
        json!({"policy":"path \"auth/approle/role/source/token-bound-cidrs\" { capabilities=[\"read\",\"update\",\"delete\"] }"})).unwrap();
    let grant = call(
        &mut state,
        Some(&root),
        "POST",
        "auth/token/create",
        json!({"policies":["field-editor"],"ttl":300}),
    )
    .unwrap();
    let actor = state
        .authenticate_from(
            grant.body["auth"]["client_token"].as_str().unwrap(),
            100,
            None,
        )
        .unwrap();
    assert_eq!(
        field(
            &mut state,
            &actor,
            "POST",
            json!({"token_bound_cidrs":["127.0.0.1"]})
        )
        .unwrap()
        .status,
        204
    );
    assert_eq!(
        role(&mut state, &actor, json!({"token_bound_cidrs":[]}))
            .err()
            .unwrap()
            .status,
        403
    );
    let original_role_id = stored(&state).role_id.clone();
    assert_eq!(
        field(
            &mut state,
            &actor,
            "POST",
            json!({"token_bound_cidrs":[],"token_ttl":1,"role_id":"ignored",
                "role_name":"another-role","secret_id_bound_cidrs":["10.0.0.0/8"]})
        )
        .unwrap()
        .status,
        204
    );
    assert_eq!(stored(&state).token_bound_cidrs, Some(Vec::new()));
    assert_eq!(stored(&state).token_ttl, 60);
    assert_eq!(stored(&state).role_id, original_role_id);
    assert!(!state.roles[""].contains_key("another-role"));
    let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let ignored = field(&mut state, &actor, "POST", json!({"token_ttl":{}})).unwrap();
    assert_eq!(ignored.status, 204);
    assert!(ignored.body.get("warnings").is_none());
    assert_eq!(
        before.as_slice(),
        Zeroizing::new(serde_json::to_vec(&state).unwrap()).as_slice()
    );
    assert_eq!(
        field(&mut state, &actor, "DELETE", json!({}))
            .unwrap()
            .status,
        204
    );
}

#[test]
fn approle_cidr_management_requires_constraint_but_legacy_reads_and_login_do_not_migrate() {
    let (mut state, _, root) = setup();
    for body in [
        json!({"bind_secret_id":false}),
        json!({"bind_secret_id":false,"token_bound_cidrs":null}),
        json!({"bind_secret_id":false,"token_bound_cidrs":[]}),
    ] {
        let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        assert_eq!(role(&mut state, &root, body).err().unwrap().status, 500);
        assert_eq!(
            before.as_slice(),
            Zeroizing::new(serde_json::to_vec(&state).unwrap()).as_slice()
        );
        assert!(
            state
                .roles
                .get("")
                .is_none_or(|roles| !roles.contains_key("source"))
        );
    }
    role(&mut state, &root, json!({})).unwrap();
    let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    assert_eq!(
        role(&mut state, &root, json!({"bind_secret_id":false}))
            .err()
            .unwrap()
            .status,
        500
    );
    assert_eq!(
        before.as_slice(),
        Zeroizing::new(serde_json::to_vec(&state).unwrap()).as_slice()
    );

    // Reproduce a previously accepted RoleID-only record, without new CIDR
    // metadata. Loading or logging in does not guess a stronger constraint.
    state
        .roles
        .get_mut("")
        .unwrap()
        .get_mut("source")
        .unwrap()
        .bind_secret_id = false;
    let legacy = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut restored: AuthState = serde_json::from_slice(&legacy).unwrap();
    restored.validate_approle_token_bound_cidrs().unwrap();
    assert!(!restored.has_approle_token_bound_cidrs());
    assert_eq!(
        call(
            &mut restored,
            Some(&root),
            "GET",
            "auth/approle/role/source",
            json!({})
        )
        .unwrap()
        .body["data"]["bind_secret_id"],
        false
    );
    assert_eq!(
        field(&mut restored, &root, "GET", json!({})).unwrap().body["data"]["token_bound_cidrs"],
        Value::Null
    );
    assert_eq!(
        legacy.as_slice(),
        Zeroizing::new(serde_json::to_vec(&restored).unwrap()).as_slice()
    );
    let rid = stored(&restored).role_id.clone();
    assert_eq!(
        login(&mut restored, &json!({"role_id":rid}), None)
            .unwrap()
            .status,
        200
    );
    assert!(stored(&restored).token_bound_cidrs.is_none());
    let before = Zeroizing::new(serde_json::to_vec(&restored).unwrap());
    assert_eq!(
        role(&mut restored, &root, json!({"token_ttl":10}))
            .err()
            .unwrap()
            .status,
        500
    );
    assert_eq!(
        call(
            &mut restored,
            Some(&root),
            "POST",
            "auth/approle/role/source/role-id",
            json!({"role_id":"changed-role-id"})
        )
        .err()
        .unwrap()
        .status,
        500
    );
    assert_eq!(
        before.as_slice(),
        Zeroizing::new(serde_json::to_vec(&restored).unwrap()).as_slice()
    );

    let mut repaired_with_secret = restored.clone();
    role(
        &mut repaired_with_secret,
        &root,
        json!({"bind_secret_id":true}),
    )
    .unwrap();
    assert!(stored(&repaired_with_secret).bind_secret_id);
    assert!(stored(&repaired_with_secret).token_bound_cidrs.is_none());
    field(
        &mut restored,
        &root,
        "POST",
        json!({"token_bound_cidrs":["127.0.0.1"]}),
    )
    .unwrap();
    assert!(!stored(&restored).bind_secret_id);
    assert_eq!(
        stored(&restored).token_bound_cidrs,
        Some(vec!["127.0.0.1".to_owned()])
    );
    call(
        &mut restored,
        Some(&root),
        "POST",
        "auth/approle/role/source/role-id",
        json!({"role_id":"changed-role-id"}),
    )
    .unwrap();
}
