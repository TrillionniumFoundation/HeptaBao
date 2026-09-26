#![allow(clippy::unwrap_used)]
use super::*;
fn call(
    state: &mut AuthState,
    admin: &Principal,
    path: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(Some(admin), "", "POST", path, &body, 100)?
        .ok_or_else(|| bad("missing route"))
}
fn setup(kind: &str, uses: u64) -> (AuthState, Principal, Value) {
    let (mut state, raw) = AuthState::bootstrap(100).unwrap();
    let admin = state.authenticate(&raw, 100).unwrap();
    call(
        &mut state,
        &admin,
        "auth/approle/role/example",
        json!({"token_type":kind,"token_ttl":60,"secret_id_num_uses":uses}),
    )
    .unwrap();
    let role = state.roles[""]["example"].role_id.clone();
    let secret = call(
        &mut state,
        &admin,
        "auth/approle/role/example/secret-id",
        json!({}),
    )
    .unwrap();
    let body = json!({"role_id":role,"secret_id":secret.body["data"]["secret_id"]});
    (state, admin, body)
}
fn login(state: &mut AuthState, body: &Value) -> AuthResponse {
    state
        .handle(None, "", "POST", "auth/approle/login", body, 100)
        .unwrap()
        .unwrap()
}
#[test]
fn approle_role_read_does_not_invent_deprecated_period_provenance() {
    let (mut state, admin, _) = setup("service", 2);
    for period in [0, 30] {
        call(
            &mut state,
            &admin,
            "auth/approle/role/example",
            json!({"token_period":period}),
        )
        .unwrap();
        let stored = serde_json::to_vec(&state).unwrap();
        let mut reopened: AuthState = serde_json::from_slice(&stored).unwrap();
        let read = reopened
            .handle(
                Some(&admin),
                "",
                "GET",
                "auth/approle/role/example",
                &json!({}),
                100,
            )
            .unwrap()
            .unwrap();
        assert_eq!(read.status, 200);
        assert_eq!(read.body["data"]["token_period"], period);
        assert!(read.body["data"].get("period").is_none());
        assert!(!read.mutated);
        assert_eq!(serde_json::to_vec(&reopened).unwrap(), stored);
    }
}

#[test]
fn approle_batch_all_twelve_types_bind_role_id_before_seal_without_backing_token() {
    for (mount, role, batch) in [
        ("default-service", "default", false),
        ("default-service", "service", false),
        ("default-service", "batch", true),
        ("default-batch", "default", true),
        ("default-batch", "service", false),
        ("default-batch", "batch", true),
        ("service", "default", false),
        ("service", "service", false),
        ("service", "batch", false),
        ("batch", "default", true),
        ("batch", "service", true),
        ("batch", "batch", true),
    ] {
        let (mut state, admin, credentials) = setup(role, 2);
        call(
            &mut state,
            &admin,
            "sys/auth/approle/tune",
            json!({"token_type":mount}),
        )
        .unwrap();
        let before = state.tokens.len();
        let mut response = login(&mut state, &credentials);
        assert_eq!(response.pending_batch.is_some(), batch, "{mount}/{role}");
        let identity = response.login_identity.take().unwrap();
        assert_eq!(identity.alias, credentials["role_id"].as_str().unwrap());
        state
            .bind_issued_entity(&mut response, "", "approle", "fixture-entity")
            .unwrap();
        state.finish_pending_batch(&mut response, "", 100).unwrap();
        assert_eq!(response.body["auth"]["orphan"], true);
        assert_eq!(
            response.body["auth"]["metadata"],
            json!({"role_name":"example"})
        );
        assert_eq!(state.tokens.len(), before + usize::from(!batch));
        if batch {
            assert_eq!(
                response.body["auth"]["metadata"],
                json!({"role_name":"example"})
            );
            assert_eq!(response.body["auth"]["renewable"], false);
            assert!(
                response.body["auth"]["client_token"]
                    .as_str()
                    .unwrap()
                    .starts_with("hvb.")
            );
        }
        assert_eq!(
            state.roles[""]["example"]
                .secret_ids
                .values()
                .next()
                .unwrap()
                .uses_remaining,
            Some(1)
        );
    }
}
#[test]
fn approle_batch_aliases_warn_and_invalid_null_period_uses_are_atomic() {
    let (mut state, admin, _) = setup("default", 0);
    for (alias, kind) in [("default-service", "service"), ("default-batch", "batch")] {
        let response = call(
            &mut state,
            &admin,
            "auth/approle/role/example",
            json!({"token_type":alias}),
        )
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body["warnings"].as_array().unwrap().len(), 1);
        assert_eq!(state.roles[""]["example"].token_type.unwrap().name(), kind);
    }
    for body in [
        json!({"token_type":null}),
        json!({"token_type":"invalid"}),
        json!({"token_period":30}),
        json!({"token_num_uses":2}),
    ] {
        let before = zeroize::Zeroizing::new(serde_json::to_vec(&state).unwrap());
        assert_eq!(
            call(&mut state, &admin, "auth/approle/role/example", body)
                .err()
                .unwrap()
                .status,
            400
        );
        assert!(
            before.as_slice()
                == zeroize::Zeroizing::new(serde_json::to_vec(&state).unwrap()).as_slice()
        );
    }
}
#[test]
fn approle_batch_forced_service_limits_cap_ttl_without_period_or_use_claims() {
    for (fields, ttl) in [
        (json!({"token_period":30}), 30),
        (json!({"token_num_uses":2}), 60),
        (json!({"token_explicit_max_ttl":20}), 20),
    ] {
        let (mut state, admin, credentials) = setup("service", 0);
        call(&mut state, &admin, "auth/approle/role/example", fields).unwrap();
        call(
            &mut state,
            &admin,
            "sys/auth/approle/tune",
            json!({"token_type":"batch"}),
        )
        .unwrap();
        let mut response = login(&mut state, &credentials);
        response.login_identity.take();
        state
            .bind_issued_entity(&mut response, "", "approle", "fixture-entity")
            .unwrap();
        state.finish_pending_batch(&mut response, "", 100).unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], ttl);
        assert_eq!(response.body.get("warnings").is_some(), ttl == 20);
        let raw = response.body["auth"]["client_token"].as_str().unwrap();
        let principal = state.authenticate(raw, 100).unwrap();
        assert!(!principal.consumed_use());
    }
}
#[test]
fn approle_secret_consumption_cannot_replay_or_cross_mount_configuration() {
    let (base, admin, credentials) = setup("batch", 2);
    let mut first = base.clone();
    let mut second = base.clone();
    let delta1 = login(&mut first, &credentials)
        .approle_secret_consumption
        .take()
        .unwrap();
    let delta2 = login(&mut second, &credentials)
        .approle_secret_consumption
        .take()
        .unwrap();
    let mut target = base.clone();
    delta1.apply(&mut target).unwrap();
    let before = zeroize::Zeroizing::new(serde_json::to_vec(&target).unwrap());
    assert_eq!(delta2.apply(&mut target).err().unwrap().status, 409);
    assert!(
        before.as_slice()
            == zeroize::Zeroizing::new(serde_json::to_vec(&target).unwrap()).as_slice()
    );
    let mut candidate = base.clone();
    let delta = login(&mut candidate, &credentials)
        .approle_secret_consumption
        .take()
        .unwrap();
    let mut changed = base;
    call(
        &mut changed,
        &admin,
        "sys/auth/approle/tune",
        json!({"description":"changed"}),
    )
    .unwrap();
    assert_eq!(delta.apply(&mut changed).err().unwrap().status, 409);
}
#[test]
fn approle_batch_old_role_none_round_trips_and_unknown_type_is_rejected() {
    let (mut state, _, _) = setup("default", 0);
    state
        .roles
        .get_mut("")
        .unwrap()
        .get_mut("example")
        .unwrap()
        .token_type = None;
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let reopened: AuthState = serde_json::from_slice(&bytes).unwrap();
    assert!(!reopened.has_approle_batch_state());
    assert!(
        bytes.as_slice()
            == zeroize::Zeroizing::new(serde_json::to_vec(&reopened).unwrap()).as_slice()
    );
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["roles"][""]["example"]["token_type"] = json!("unknown");
    assert!(serde_json::from_value::<AuthState>(value).is_err());
}

#[test]
fn approle_missing_role_reads_are_empty_after_authorization_and_invalid_writes() {
    let (mut state, admin, _) = setup("service", 0);
    for (name, body) in [
        ("invalid-kind", json!({"token_type":"invalid"})),
        ("null-kind", json!({"token_type":null})),
        (
            "invalid-period",
            json!({"token_type":"batch","token_period":30}),
        ),
        (
            "invalid-uses",
            json!({"token_type":"batch","token_num_uses":2}),
        ),
    ] {
        let path = format!("auth/approle/role/{name}");
        let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        assert_eq!(
            call(&mut state, &admin, &path, body).err().unwrap().status,
            400
        );
        let read = state
            .handle(Some(&admin), "", "GET", &path, &json!({}), 100)
            .unwrap()
            .unwrap();
        assert_eq!(read.status, 404);
        assert_eq!(read.body, json!({"errors":[]}));
        assert!(!read.mutated);
        assert_eq!(
            state
                .handle(None, "", "GET", &path, &json!({}), 100)
                .err()
                .unwrap()
                .status,
            403
        );
        assert_eq!(
            before.as_slice(),
            Zeroizing::new(serde_json::to_vec(&state).unwrap()).as_slice()
        );
    }
}
