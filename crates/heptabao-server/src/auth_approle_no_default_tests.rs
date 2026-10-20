#![allow(clippy::unwrap_used)]
use super::tests::mount_auth;
use super::*;

fn setup(mount: &str) -> (AuthState, Principal) {
    let (mut state, raw) = AuthState::bootstrap(100).unwrap();
    let root = state.authenticate(&raw, 100).unwrap();
    mount_auth(&mut state, &root, "", mount, "approle");
    (state, root)
}

fn request(
    state: &mut AuthState,
    root: &Principal,
    method: &str,
    path: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    state
        .handle(Some(root), "", method, path, &body, 100)?
        .ok_or_else(denied)
}

fn write(
    state: &mut AuthState,
    root: &Principal,
    mount: &str,
    body: Value,
) -> Result<AuthResponse, AuthError> {
    request(state, root, "POST", &format!("auth/{mount}/role/app"), body)
}

fn read(state: &mut AuthState, root: &Principal, mount: &str) -> Value {
    request(
        state,
        root,
        "GET",
        &format!("auth/{mount}/role/app"),
        json!({}),
    )
    .unwrap()
    .body["data"]
        .clone()
}

fn credentials(state: &mut AuthState, root: &Principal, mount: &str) -> Value {
    let role_id = request(
        state,
        root,
        "GET",
        &format!("auth/{mount}/role/app/role-id"),
        json!({}),
    )
    .unwrap()
    .body["data"]["role_id"]
        .clone();
    let secret = request(
        state,
        root,
        "POST",
        &format!("auth/{mount}/role/app/secret-id"),
        json!({}),
    )
    .unwrap()
    .body["data"]["secret_id"]
        .clone();
    json!({"role_id":role_id,"secret_id":secret})
}

fn login(state: &mut AuthState, mount: &str, credentials: &Value) -> AuthResponse {
    let mut response = state
        .handle(
            None,
            "",
            "POST",
            &format!("auth/{mount}/login"),
            credentials,
            100,
        )
        .unwrap()
        .unwrap();
    response.login_identity.take();
    state
        .bind_issued_entity(&mut response, "", mount, "policy-fixture-entity")
        .unwrap();
    state.finish_pending_batch(&mut response, "", 100).unwrap();
    response
}

fn assert_policies(response: &AuthResponse, expected: &[&str]) {
    assert_eq!(response.body["auth"]["policies"], json!(expected));
    if expected.is_empty() {
        assert!(response.body["auth"].get("token_policies").is_none());
    } else {
        assert_eq!(response.body["auth"]["token_policies"], json!(expected));
    }
}

#[test]
fn approle135_fresh_roles_store_raw_lists_and_issue_implicit_default_at_login() {
    for mount in ["approle", "build"] {
        let (mut state, root) = setup(mount);
        assert_eq!(
            write(&mut state, &root, mount, json!({"token_ttl":60})).unwrap().status,
            204
        );
        let role = &state.roles_at(AuthScope { namespace: "", mount }).unwrap()["app"];
        assert_eq!(role.token_no_default_policy, Some(false));
        assert!(role.policies.is_empty());
        let data = read(&mut state, &root, mount);
        assert_eq!(data["token_no_default_policy"], false);
        assert_eq!(data["token_policies"], json!([]));
        let credentials = credentials(&mut state, &root, mount);
        let response = login(&mut state, mount, &credentials);
        assert_policies(&response, &["default"]);
        assert_eq!(read(&mut state, &root, mount)["token_policies"], json!([]));
    }
}

#[test]
fn approle135_no_default_and_explicit_default_cover_service_and_batch_on_custom_mounts() {
    for mount in ["approle", "build"] {
        for kind in ["service", "batch"] {
            for (flag, raw, expected) in [
                (true, vec![], vec![]),
                (true, vec!["named"], vec!["named"]),
                (true, vec!["default", "named"], vec!["default", "named"]),
                (false, vec!["named"], vec!["default", "named"]),
            ] {
                let (mut state, root) = setup(mount);
                assert_eq!(write(
                    &mut state,
                    &root,
                    mount,
                    json!({"token_type":kind,"token_ttl":60,
                        "token_no_default_policy":flag,"token_policies":raw}),
                ).unwrap().status, 204);
                let data = read(&mut state, &root, mount);
                assert_eq!(data["token_no_default_policy"], flag);
                assert_eq!(data["token_policies"], json!(raw));
                let credentials = credentials(&mut state, &root, mount);
                let token_count = state.tokens.len();
                let response = login(&mut state, mount, &credentials);
                assert_policies(&response, &expected);
                assert_eq!(response.body["auth"]["token_type"], kind);
                assert_eq!(state.tokens.len(), token_count + usize::from(kind == "service"));
                let bearer = response.body["auth"]["client_token"].as_str().unwrap();
                let actor = state.authenticate(bearer, 101).unwrap();
                assert_eq!(
                    actor.policies(),
                    &expected.iter().map(|p| (*p).to_owned()).collect::<BTreeSet<_>>()
                );
            }
        }
    }
}

#[test]
fn approle135_omitted_flag_preserves_and_framework_null_and_string_flags_update() {
    let (mut state, root) = setup("approle");
    write(&mut state, &root, "approle", json!({
        "token_no_default_policy":true,"token_policies":["named"]
    })).unwrap();
    write(&mut state, &root, "approle", json!({"token_ttl":60})).unwrap();
    assert_eq!(read(&mut state, &root, "approle")["token_no_default_policy"], true);
    for (value, expected) in [
        (json!(false), false),
        (json!("true"), true),
        (json!("FALSE"), false),
        (json!(1), true),
        (json!(0), false),
        (json!(true), true),
        (Value::Null, false),
    ] {
        assert_eq!(write(&mut state, &root, "approle",
            json!({"token_no_default_policy":value})).unwrap().status, 204);
        let data = read(&mut state, &root, "approle");
        assert_eq!(data["token_no_default_policy"], expected);
        assert_eq!(data["token_policies"], json!(["named"]));
    }
    for body in [
        json!({"token_no_default_policy":true,"token_policies":null}),
        json!({"policies":[]}),
        json!({"token_policies":""}),
    ] {
        write(&mut state, &root, "approle", body).unwrap();
        let data = read(&mut state, &root, "approle");
        assert_eq!(data["token_no_default_policy"], true);
        assert_eq!(data["token_policies"], json!([]));
        let credentials = credentials(&mut state, &root, "approle");
        assert_policies(&login(&mut state, "approle", &credentials), &[]);
    }
}

#[test]
fn approle135_false_marker_survives_serialization_and_readback_is_not_a_write() {
    for flag in [false, true] {
        let (mut state, root) = setup("build");
        write(&mut state, &root, "build", json!({
            "token_no_default_policy":flag,"token_policies":["named"]
        })).unwrap();
        let wire = serde_json::to_value(&state).unwrap();
        assert_eq!(wire["mounted_roles"][""]["build"]["app"]["token_no_default_policy"], flag);
        let bytes = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        let mut reopened: AuthState = serde_json::from_slice(&bytes).unwrap();
        reopened.validate_approle_no_default_policy().unwrap();
        assert!(reopened.has_approle_no_default_policy());
        assert_eq!(read(&mut reopened, &root, "build")["token_no_default_policy"], flag);
        assert_eq!(serde_json::to_vec(&reopened).unwrap().as_slice(), bytes.as_slice());
        let credentials = credentials(&mut reopened, &root, "build");
        let expected = if flag { vec!["named"] } else { vec!["default", "named"] };
        assert_policies(&login(&mut reopened, "build", &credentials), &expected);
    }
}

#[test]
fn approle135_legacy_none_preserves_normalized_policies_until_explicit_replacement() {
    let (mut state, root) = setup("approle");
    write(&mut state, &root, "approle", json!({"token_policies":["named"]})).unwrap();
    // Exact legacy policy shape: the predecessor stored its implicit default.
    let role = state.roles_at_mut(AuthScope { namespace: "", mount: "approle" })
        .get_mut("app").unwrap();
    role.token_no_default_policy = None;
    role.policies.insert("default".into());
    let wire = serde_json::to_value(&state).unwrap();
    assert!(wire["roles"][""]["app"].get("token_no_default_policy").is_none());
    let mut state: AuthState = serde_json::from_value(wire).unwrap();
    assert!(!state.has_approle_no_default_policy());
    assert_eq!(read(&mut state, &root, "approle")["token_no_default_policy"], false);
    let credentials = credentials(&mut state, &root, "approle");
    assert_policies(&login(&mut state, "approle", &credentials), &["default", "named"]);
    write(&mut state, &root, "approle", json!({"token_ttl":60})).unwrap();
    assert_eq!(state.roles[""]["app"].token_no_default_policy, None);
    write(&mut state, &root, "approle", json!({"token_no_default_policy":true})).unwrap();
    assert_policies(&login(&mut state, "approle", &credentials), &["default", "named"]);
    write(&mut state, &root, "approle", json!({"token_policies":["named"]})).unwrap();
    assert_eq!(state.roles[""]["app"].token_no_default_policy, Some(true));
    assert_policies(&login(&mut state, "approle", &credentials), &["named"]);
}

#[test]
fn approle135_invalid_flags_and_conflicting_aliases_leave_role_and_secret_ids_unchanged() {
    let (mut state, root) = setup("approle");
    write(&mut state, &root, "approle", json!({
        "token_no_default_policy":true,"token_policies":["named"],"secret_id_num_uses":2
    })).unwrap();
    let _credentials = credentials(&mut state, &root, "approle");
    for body in [
        json!({"token_no_default_policy":[],"token_policies":["changed"]}),
        json!({"token_no_default_policy":{},"token_ttl":120}),
        json!({"token_no_default_policy":"not-a-bool"}),
        json!({"token_no_default_policy":true,"policies":[],"token_policies":[]}),
        json!({"token_no_default_policy":true,"token_policies":[{}]}),
        json!({"token_no_default_policy":false,"unsupported_field":true}),
    ] {
        let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        assert_eq!(write(&mut state, &root, "approle", body).err().unwrap().status, 400);
        assert_eq!(serde_json::to_vec(&state).unwrap().as_slice(), before.as_slice());
    }
    for flag in [false, true] {
        let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        assert_eq!(write(&mut state, &root, "approle",
            json!({"token_no_default_policy":flag,"token_policies":["root"]}))
            .err().unwrap().status, 403);
        assert_eq!(serde_json::to_vec(&state).unwrap().as_slice(), before.as_slice());
    }
}

#[test]
fn approle135_renewal_keeps_issued_grants_after_role_flag_and_policy_changes() {
    let (mut state, root) = setup("build");
    write(&mut state, &root, "build", json!({
        "token_no_default_policy":true,"token_policies":["named"],
        "token_ttl":60,"token_max_ttl":600
    })).unwrap();
    let credentials = credentials(&mut state, &root, "build");
    let response = login(&mut state, "build", &credentials);
    let bearer = response.body["auth"]["client_token"].as_str().unwrap().to_owned();
    for body in [
        json!({"token_no_default_policy":false}),
        json!({"token_no_default_policy":true,"token_policies":["other"]}),
        json!({"token_no_default_policy":null,"token_policies":[]}),
    ] {
        write(&mut state, &root, "build", body).unwrap();
        let response = state.handle(Some(&root), "", "POST", "auth/token/renew",
            &json!({"token":bearer,"increment":120}), 101).unwrap().unwrap();
        assert_eq!(response.status, 200);
        assert_policies(&response, &["named"]);
    }
    request(&mut state, &root, "POST", "auth/token/revoke",
        json!({"token":bearer})).unwrap();
    assert!(state.authenticate(&bearer, 101).is_err());
}

#[test]
fn approle135_empty_service_grant_renews_without_default_and_cannot_renew_self() {
    let (mut state, root) = setup("approle");
    write(&mut state, &root, "approle", json!({
        "token_no_default_policy":true,"token_ttl":60,"token_max_ttl":600
    })).unwrap();
    let credentials = credentials(&mut state, &root, "approle");
    let response = login(&mut state, "approle", &credentials);
    let bearer = response.body["auth"]["client_token"].as_str().unwrap().to_owned();
    assert_policies(&response, &[]);
    let actor = state.authenticate(&bearer, 101).unwrap();
    assert_eq!(state.handle(Some(&actor), "", "POST", "auth/token/renew-self",
        &json!({}), 101).err().unwrap().status, 403);
    let response = state.handle(Some(&root), "", "POST", "auth/token/renew",
        &json!({"token":bearer}), 101).unwrap().unwrap();
    assert_eq!(response.status, 200);
    assert_policies(&response, &[]);
}

impl AuthState {
    /// Rebuild only predecessor AppRole policy owners for isolated old-format
    /// unit inputs. This cannot erase a no-default grant, credential, or mount.
    pub(crate) fn restore_legacy_approle_policy_owners_for_format_test(&mut self) {
        assert!(!self.tokens.values().any(|token| {
            matches!(
                token.auth_provenance,
                Some(TokenAuthProvenance::AppRole { .. })
            ) && !token.policies.contains("default")
        }));
        for role in self.roles.values_mut().flat_map(|roles| roles.values_mut()).chain(
            self.mounted_roles
                .values_mut()
                .flat_map(|mounts| mounts.values_mut())
                .flat_map(|roles| roles.values_mut()),
        ) {
            assert_ne!(role.token_no_default_policy, Some(true));
            let issued = approle_no_default::issued_policies(role);
            if role.token_no_default_policy.take().is_some() {
                role.policies = issued.clone();
            }
            assert_eq!(approle_no_default::issued_policies(role), issued);
        }
    }
}
