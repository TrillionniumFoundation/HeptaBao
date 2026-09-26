#![allow(clippy::unwrap_used)]
use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};

const MOUNT: &str = "nested/jwt";
fn write(
    state: &mut AuthState,
    admin: &Principal,
    path: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(Some(admin), "", "POST", path, &body, 100)?
        .ok_or_else(|| bad("missing route"))
}
fn fixture() -> (AuthState, Principal, Value) {
    fixture_subject("alice")
}
fn fixture_subject(subject: &str) -> (AuthState, Principal, Value) {
    let (mut state, raw) = AuthState::bootstrap(100).unwrap();
    let admin = state.authenticate(&raw, 100).unwrap();
    let pair = Ed25519KeyPair::from_seed_unchecked(&[73; 32]).unwrap();
    write(
        &mut state,
        &admin,
        "sys/auth/nested/jwt",
        json!({"type":"jwt"}),
    )
    .unwrap();
    write(&mut state, &admin, "auth/nested/jwt/config", json!({
        "issuer":"https://issuer.example", "audiences":["service"], "clock_skew_seconds":0,
        "keys":[{"kid":"key","algorithm":"EdDSA","key_base64":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())}]
    })).unwrap();
    write(
        &mut state,
        &admin,
        "auth/nested/jwt/role/app",
        json!({
            "role_type":"jwt", "bound_audiences":["service"],"token_ttl":120,"token_max_ttl":600
        }),
    )
    .unwrap();
    let payload = format!("{}.{}", URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"key"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"iss":"https://issuer.example","aud":"service","sub":subject,"iat":100,"exp":1000})).unwrap()));
    let jwt = format!(
        "{payload}.{}",
        URL_SAFE_NO_PAD.encode(pair.sign(payload.as_bytes()).as_ref())
    );
    (state, admin, json!({"role":"app","jwt":jwt}))
}
fn login(state: &mut AuthState, body: &Value) -> AuthResponse {
    login_subject(state, body, "alice")
}
fn login_subject(state: &mut AuthState, body: &Value, subject: &str) -> AuthResponse {
    let mut response = state
        .handle(None, "", "POST", "auth/nested/jwt/login", body, 100)
        .unwrap()
        .unwrap();
    let identity = response.login_identity.take().unwrap();
    assert_eq!(identity.alias, subject);
    assert_eq!(
        identity.metadata,
        Some(BTreeMap::from([("role".into(), "app".into())]))
    );
    state
        .bind_issued_entity(&mut response, "", MOUNT, "fixture-entity")
        .unwrap();
    state.finish_pending_batch(&mut response, "", 100).unwrap();
    response
}
fn lookup(state: &mut AuthState, raw: &str) -> Value {
    let mut actor = state.authenticate(raw, 100).unwrap();
    actor.bind_identity_policies(BTreeSet::new());
    state
        .handle(
            Some(&actor),
            "",
            "GET",
            "auth/token/lookup-self",
            &json!({}),
            100,
        )
        .unwrap()
        .unwrap()
        .body["data"]
        .clone()
}

#[test]
fn jwt_display_name_removes_one_trailing_hyphen_and_keeps_the_full_bounded_subject() {
    for subject in ["alice--".to_owned(), "-".to_owned(), "s".repeat(1024)] {
        let joined = format!("nested-jwt-{subject}");
        let expected = joined.strip_suffix('-').unwrap_or(&joined);
        for kind in ["service", "batch"] {
            let (mut state, admin, body) = fixture_subject(&subject);
            write(
                &mut state,
                &admin,
                "auth/nested/jwt/role/app",
                json!({"token_type":kind}),
            )
            .unwrap();
            let issued = login_subject(&mut state, &body, &subject);
            let info = lookup(
                &mut state,
                issued.body["auth"]["client_token"].as_str().unwrap(),
            );
            assert_eq!(info["display_name"], expected);
        }
    }
}

#[test]
fn jwt_batch_type_matrix_seals_after_identity_without_service_rows_and_allows_assertion_reuse() {
    for mode in ["default-service", "default-batch", "service", "batch"] {
        for kind in ["default", "service", "batch"] {
            let (mut state, admin, body) = fixture();
            write(
                &mut state,
                &admin,
                "auth/nested/jwt/role/app",
                json!({"token_type":kind}),
            )
            .unwrap();
            write(
                &mut state,
                &admin,
                "sys/auth/nested/jwt/tune",
                json!({"token_type":mode}),
            )
            .unwrap();
            let batch = mode == "batch"
                || mode == "default-service" && kind == "batch"
                || mode == "default-batch" && kind != "service";
            let before = state.tokens.len();
            let first = login(&mut state, &body);
            let second = login(&mut state, &body);
            assert_eq!(state.tokens.len(), before + 2 * usize::from(!batch));
            assert_ne!(
                first.body["auth"]["client_token"],
                second.body["auth"]["client_token"]
            );
            assert_eq!(
                first.body["auth"]["token_type"],
                if batch { "batch" } else { "service" }
            );
            assert_eq!(first.body["auth"]["renewable"], !batch);
            assert_eq!(first.body["auth"]["orphan"], true);
            assert_eq!(first.body["auth"]["metadata"], json!({"role":"app"}));
            let info = lookup(
                &mut state,
                first.body["auth"]["client_token"].as_str().unwrap(),
            );
            assert_eq!(info["display_name"], "nested-jwt-alice");
            assert_eq!(info["meta"], json!({"role":"app"}));
            assert_eq!(info["entity_id"], "fixture-entity");
            assert_eq!(info["accessor"].as_str().unwrap().is_empty(), batch);
        }
    }
}

#[test]
fn jwt_batch_null_empty_and_partial_updates_follow_generic_types_and_rejections_are_atomic() {
    let (mut state, admin, _) = fixture();
    for (body, expected) in [
        (json!({"token_type":"batch"}), "batch"),
        (json!({"token_ttl":60}), "batch"),
        (json!({"token_type":null}), "default"),
        (json!({"token_type":"service"}), "service"),
        (json!({"token_type":""}), "default"),
    ] {
        write(&mut state, &admin, "auth/nested/jwt/role/app", body).unwrap();
        let read = state
            .handle(
                Some(&admin),
                "",
                "GET",
                "auth/nested/jwt/role/app",
                &json!({}),
                100,
            )
            .unwrap()
            .unwrap();
        assert_eq!(read.body["data"]["token_type"], expected);
    }
    for body in [
        json!({"token_type":"default-service"}),
        json!({"token_type":"default-batch"}),
        json!({"token_type":"invalid"}),
        json!({"token_type":"batch","token_period":30}),
        json!({"token_type":"batch","token_num_uses":2}),
    ] {
        let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        assert_eq!(
            write(&mut state, &admin, "auth/nested/jwt/role/app", body)
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(
            serde_json::to_vec(&state).unwrap().as_slice(),
            before.as_slice()
        );
    }
}

#[test]
fn jwt_rejected_role_creation_reads_as_empty_not_found_without_mutation() {
    let (mut state, admin, _) = fixture();
    let path = "auth/nested/jwt/role/rejected";
    for body in [
        json!({"token_type":"invalid"}),
        json!({"token_type":"default-service"}),
        json!({"token_type":"default-batch"}),
        json!({"token_type":"batch","token_period":30}),
        json!({"token_type":"batch","token_num_uses":2}),
    ] {
        let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        assert_eq!(
            write(&mut state, &admin, path, body).err().unwrap().status,
            400
        );
        let read = state
            .handle(Some(&admin), "", "GET", path, &json!({}), 100)
            .unwrap()
            .unwrap();
        assert_eq!(read.status, 404);
        assert_eq!(read.body, json!({"errors": []}));
        assert!(!read.mutated);
        assert_eq!(
            serde_json::to_vec(&state).unwrap().as_slice(),
            before.as_slice()
        );
    }
}

#[test]
fn jwt_mount_forced_batch_calculates_ttl_before_discarding_service_period_and_uses() {
    for (fields, ttl, warned) in [
        (json!({"token_period":30}), 30, false),
        (json!({"token_num_uses":2}), 120, false),
        (json!({"token_explicit_max_ttl":20}), 20, true),
    ] {
        let (mut state, admin, body) = fixture();
        write(&mut state, &admin, "auth/nested/jwt/role/app", fields).unwrap();
        write(
            &mut state,
            &admin,
            "sys/auth/nested/jwt/tune",
            json!({"token_type":"batch"}),
        )
        .unwrap();
        let response = login(&mut state, &body);
        assert_eq!(response.body["auth"]["lease_duration"], ttl);
        assert_eq!(response.body.get("warnings").is_some(), warned);
        let info = lookup(
            &mut state,
            response.body["auth"]["client_token"].as_str().unwrap(),
        );
        assert_eq!(info["num_uses"], 0);
        assert_eq!(info["explicit_max_ttl"], 0);
        assert!(info.get("period").is_none());
    }
}

#[test]
fn jwt_legacy_absent_type_read_preserves_bytes_and_typed_state_requires_live_jwt_mount() {
    let (state, admin, _) = fixture();
    let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut restored: AuthState = serde_json::from_slice(&before).unwrap();
    assert!(!restored.has_jwt_batch_state());
    let read = restored
        .handle(
            Some(&admin),
            "",
            "GET",
            "auth/nested/jwt/role/app",
            &json!({}),
            100,
        )
        .unwrap()
        .unwrap();
    assert_eq!(read.body["data"]["token_type"], "default");
    assert!(!read.mutated);
    assert_eq!(
        serde_json::to_vec(&restored).unwrap().as_slice(),
        before.as_slice()
    );
    write(
        &mut restored,
        &admin,
        "auth/nested/jwt/role/app",
        json!({"token_type":"default"}),
    )
    .unwrap();
    assert!(restored.has_jwt_batch_state());
    restored.validate_jwt_batch_state().unwrap();
    restored
        .auth_mounts
        .get_mut("")
        .unwrap()
        .get_mut(MOUNT)
        .unwrap()
        .kind = "oidc".into();
    assert!(restored.validate_jwt_batch_state().is_err());
}
