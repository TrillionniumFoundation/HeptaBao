#![allow(clippy::unwrap_used)]
use super::super::tests::mount_auth;
use super::*;

const CLUSTER: &str = "local-secret-id-test-cluster";

fn setup() -> (AuthState, Principal) {
    let (mut state, raw) = AuthState::bootstrap(100).unwrap();
    let root = state.authenticate(&raw, 100).unwrap();
    mount_auth(&mut state, &root, "", "approle", "approle");
    (state, root)
}

#[allow(clippy::too_many_arguments)]
fn request(
    state: &mut AuthState,
    principal: Option<&Principal>,
    namespace: &str,
    method: &str,
    path: &str,
    body: Value,
    now: u64,
    peer: Option<&str>,
) -> Result<AuthResponse, AuthError> {
    state
        .handle_with_connection_clock_for_cluster(
            principal,
            namespace,
            method,
            path,
            &body,
            AuthorityTime::Coarse(now),
            None,
            None,
            peer.map(|value| value.parse().unwrap()),
            Some(CLUSTER),
        )?
        .ok_or_else(denied)
}

fn create(state: &mut AuthState, root: &Principal, name: &str, local: bool, uses: u64) {
    assert_eq!(
        request(
            state,
            Some(root),
            "",
            "POST",
            &format!("auth/approle/role/{name}"),
            json!({"local_secret_ids":local,"secret_id_num_uses":uses,"token_ttl":120}),
            100,
            None,
        )
        .unwrap()
        .status,
        204
    );
}

fn issue(state: &mut AuthState, root: &Principal, name: &str, body: Value) -> Value {
    let response = request(
        state,
        Some(root),
        "",
        "POST",
        &format!("auth/approle/role/{name}/secret-id"),
        body,
        100,
        None,
    )
    .unwrap();
    assert_eq!(response.status, 200);
    json!({"role_id":state.roles[""][name].role_id,"secret_id":response.body["data"]["secret_id"]})
}

#[test]
fn approle142_cluster_owner_is_required_and_role_flag_is_creation_only() {
    let (mut state, root) = setup();
    let before = serde_json::to_vec(&state).unwrap();
    assert_eq!(
        state
            .handle(
                Some(&root),
                "",
                "POST",
                "auth/approle/role/no-owner",
                &json!({"local_secret_ids":true}),
                100
            )
            .err()
            .unwrap()
            .status,
        503
    );
    assert_eq!(before, serde_json::to_vec(&state).unwrap());
    create(&mut state, &root, "local", true, 0);
    let before = serde_json::to_vec(&state).unwrap();
    for value in [json!(false), json!(true), Value::Null] {
        assert_eq!(
            request(
                &mut state,
                Some(&root),
                "",
                "POST",
                "auth/approle/role/local",
                json!({"local_secret_ids":value}),
                100,
                None
            )
            .err()
            .unwrap()
            .status,
            400
        );
        assert_eq!(before, serde_json::to_vec(&state).unwrap());
    }
    assert_eq!(
        request(
            &mut state,
            Some(&root),
            "",
            "GET",
            "auth/approle/role/local",
            json!({}),
            100,
            None
        )
        .unwrap()
        .body["data"]["local_secret_ids"],
        true
    );
    state.validate_cluster_local_approle_state(CLUSTER).unwrap();
}

#[test]
fn approle142_global_owners_keep_their_existing_wire_representation() {
    let (mut state, root) = setup();
    create(&mut state, &root, "global", false, 0);
    issue(&mut state, &root, "global", json!({}));
    assert!(!state.has_cluster_local_approle_state());
    let wire = serde_json::to_vec(&state).unwrap();
    let json: Value = serde_json::from_slice(&wire).unwrap();
    assert!(
        json["roles"][""]["global"]
            .get("local_secret_ids")
            .is_none()
    );
    let restored: AuthState = serde_json::from_slice(&wire).unwrap();
    assert_eq!(wire, serde_json::to_vec(&restored).unwrap());
    restored
        .validate_cluster_local_approle_state("another-cluster")
        .unwrap();
}

#[test]
fn approle142_local_restart_retains_credentials_and_rejects_foreign_cluster_splice() {
    let (mut state, root) = setup();
    create(&mut state, &root, "local", true, 0);
    let credentials = issue(
        &mut state,
        &root,
        "local",
        json!({"metadata":r#"{"owner":"local"}"#}),
    );
    let wire = serde_json::to_vec(&state).unwrap();
    let mut restored: AuthState = serde_json::from_slice(&wire).unwrap();
    restored
        .validate_cluster_local_approle_state(CLUSTER)
        .unwrap();
    assert!(
        restored
            .validate_cluster_local_approle_state("foreign-cluster")
            .is_err()
    );
    assert_eq!(wire, serde_json::to_vec(&restored).unwrap());
    assert_eq!(
        request(
            &mut restored,
            None,
            "",
            "POST",
            "auth/approle/login",
            credentials,
            101,
            None
        )
        .unwrap()
        .status,
        200
    );
}

#[test]
fn approle142_local_miss_does_not_fall_back_to_global_and_dual_owners_fail_closed() {
    let (mut state, root) = setup();
    create(&mut state, &root, "local", true, 0);
    create(&mut state, &root, "global", false, 0);
    let global = issue(&mut state, &root, "global", json!({}));
    let forged =
        json!({"role_id":state.roles[""]["local"].role_id,"secret_id":global["secret_id"]});
    assert_eq!(
        request(
            &mut state,
            None,
            "",
            "POST",
            "auth/approle/login",
            forged.clone(),
            100,
            None
        )
        .err()
        .unwrap()
        .status,
        400
    );
    let global_map = state.roles[""]["global"].secret_ids.clone();
    state
        .roles
        .get_mut("")
        .unwrap()
        .get_mut("local")
        .unwrap()
        .secret_ids = global_map;
    assert!(state.validate_cluster_local_approle_state(CLUSTER).is_err());
    assert_eq!(
        request(
            &mut state,
            None,
            "",
            "POST",
            "auth/approle/login",
            forged,
            100,
            None
        )
        .err()
        .unwrap()
        .status,
        503
    );
}

#[test]
fn approle142_custom_secret_id_duplicate_and_destroy_preserve_the_other_partition() {
    let (mut state, root) = setup();
    create(&mut state, &root, "local", true, 0);
    create(&mut state, &root, "global", false, 0);
    for name in ["local", "global"] {
        assert_eq!(
            request(
                &mut state,
                Some(&root),
                "",
                "POST",
                &format!("auth/approle/role/{name}/custom-secret-id"),
                json!({"secret_id":"same-private-test-id"}),
                100,
                None
            )
            .unwrap()
            .status,
            200
        );
    }
    let before = serde_json::to_vec(&state).unwrap();
    assert_eq!(
        request(
            &mut state,
            Some(&root),
            "",
            "POST",
            "auth/approle/role/local/custom-secret-id",
            json!({"secret_id":"same-private-test-id"}),
            100,
            None
        )
        .err()
        .unwrap()
        .status,
        400
    );
    assert_eq!(before, serde_json::to_vec(&state).unwrap());
    assert_eq!(
        request(
            &mut state,
            Some(&root),
            "",
            "POST",
            "auth/approle/role/local/secret-id/destroy",
            json!({"secret_id":"same-private-test-id"}),
            100,
            None
        )
        .unwrap()
        .status,
        204
    );
    assert!(
        state.roles[""]["local"]
            .approle_secrets()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        state.roles[""]["global"].approle_secrets().unwrap().len(),
        1
    );
    state.validate_cluster_local_approle_state(CLUSTER).unwrap();
}

#[test]
fn approle142_accessor_lookup_and_destroy_stay_in_the_role_prefix() {
    let (mut state, root) = setup();
    create(&mut state, &root, "local", true, 0);
    create(&mut state, &root, "global", false, 0);
    let global = issue(&mut state, &root, "global", json!({}));
    let local = issue(&mut state, &root, "local", json!({}));
    let global_accessor = state.roles[""]["global"]
        .approle_secrets()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .accessor
        .clone();
    let local_accessor = state.roles[""]["local"]
        .approle_secrets()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .accessor
        .clone();
    let hidden = request(
        &mut state,
        Some(&root),
        "",
        "POST",
        "auth/approle/role/local/secret-id-accessor/lookup",
        json!({"secret_id_accessor":global_accessor}),
        100,
        None,
    )
    .unwrap();
    assert_eq!(hidden.status, 404);
    let visible = request(
        &mut state,
        Some(&root),
        "",
        "POST",
        "auth/approle/role/local/secret-id-accessor/lookup",
        json!({"secret_id_accessor":local_accessor}),
        100,
        None,
    )
    .unwrap();
    assert_eq!(visible.status, 200);
    assert_eq!(
        request(
            &mut state,
            Some(&root),
            "",
            "LIST",
            "auth/approle/role/local/secret-id",
            json!({}),
            100,
            None
        )
        .unwrap()
        .body["data"]["keys"],
        json!([local_accessor])
    );
    assert_eq!(
        request(
            &mut state,
            Some(&root),
            "",
            "POST",
            "auth/approle/role/local/secret-id-accessor/destroy",
            json!({"secret_id_accessor":local_accessor}),
            100,
            None
        )
        .unwrap()
        .status,
        204
    );
    assert_eq!(
        request(
            &mut state,
            None,
            "",
            "POST",
            "auth/approle/login",
            local,
            100,
            None
        )
        .err()
        .unwrap()
        .status,
        400
    );
    assert_eq!(
        request(
            &mut state,
            None,
            "",
            "POST",
            "auth/approle/login",
            global,
            100,
            None
        )
        .unwrap()
        .status,
        200
    );
}

#[test]
fn approle142_failed_login_consumes_only_the_authenticated_finite_local_credential() {
    let (mut state, root) = setup();
    create(&mut state, &root, "local", true, 2);
    request(
        &mut state,
        Some(&root),
        "",
        "POST",
        "auth/approle/role/local",
        json!({"secret_id_bound_cidrs":["127.0.0.1/32"]}),
        100,
        None,
    )
    .unwrap();
    let credentials = issue(&mut state, &root, "local", json!({}));
    let before = serde_json::to_vec(&state).unwrap();
    let mut first = request(
        &mut state,
        None,
        "",
        "POST",
        "auth/approle/login",
        credentials.clone(),
        100,
        Some("127.0.0.2"),
    )
    .unwrap();
    let mut stale = request(
        &mut state,
        None,
        "",
        "POST",
        "auth/approle/login",
        credentials,
        100,
        Some("127.0.0.2"),
    )
    .unwrap();
    assert_eq!(first.status, 400);
    assert_eq!(before, serde_json::to_vec(&state).unwrap());
    (*first.approle_secret_consumption.take().unwrap())
        .apply(&mut state)
        .unwrap();
    assert_eq!(
        state.roles[""]["local"]
            .approle_secrets()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .uses_remaining,
        Some(1)
    );
    assert_eq!(
        (*stale.approle_secret_consumption.take().unwrap())
            .apply(&mut state)
            .err()
            .unwrap()
            .status,
        409
    );
    assert!(state.roles[""]["local"].secret_ids.is_empty());
}

#[test]
fn approle142_expired_local_credentials_are_rejected_before_consumption_and_tidy() {
    let (mut state, root) = setup();
    create(&mut state, &root, "local", true, 2);
    let credentials = issue(&mut state, &root, "local", json!({"ttl":5}));
    let before = serde_json::to_vec(&state).unwrap();
    assert_eq!(
        request(
            &mut state,
            None,
            "",
            "POST",
            "auth/approle/login",
            credentials.clone(),
            105,
            None
        )
        .err()
        .unwrap()
        .status,
        400
    );
    assert_eq!(before, serde_json::to_vec(&state).unwrap());
    #[cfg(any(feature = "native-v6-storage", feature = "native-v6-ha"))]
    assert_eq!(
        state
            .validate_native_v6_approle_login_lifetime_observed(
                "",
                "POST",
                "auth/approle/login",
                &credentials,
                AuthorityTime::Coarse(105)
            )
            .err()
            .unwrap()
            .status,
        400
    );
    let owner = state
        .admit_approle_tidy(
            Some(&root),
            "",
            "POST",
            "auth/approle/tidy/secret-id",
            &json!({}),
            AuthorityTime::Coarse(106),
        )
        .unwrap();
    let swept = state
        .native_approle_tidy_batch(&owner, None, Timestamp::whole(106).unwrap())
        .unwrap();
    assert_eq!(swept.checked, 1);
    assert_eq!(swept.removed, 1);
    assert!(
        state.roles[""]["local"]
            .approle_secrets()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn approle142_local_metadata_and_cidrs_keep_all_existing_format_validation() {
    let (mut state, root) = setup();
    create(&mut state, &root, "local", true, 0);
    issue(
        &mut state,
        &root,
        "local",
        json!({"metadata":r#"{"env":"test"}"#,"cidr_list":["127.0.0.1/32"]}),
    );
    assert!(state.has_approle_metadata());
    assert!(state.has_approle_secret_id_cidrs());
    state.validate_approle_metadata().unwrap();
    state.validate_approle_secret_id_cidrs().unwrap();
    state
        .roles
        .get_mut("")
        .unwrap()
        .get_mut("local")
        .unwrap()
        .approle_secrets_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap()
        .cidr_list = Some(vec!["invalid".into()]);
    assert!(state.validate_approle_secret_id_cidrs().is_err());
}

#[test]
fn approle142_custom_mount_and_namespace_do_not_share_local_credentials() {
    let (mut state, root) = setup();
    mount_auth(&mut state, &root, "team", "build", "approle");
    request(
        &mut state,
        Some(&root),
        "team",
        "POST",
        "auth/build/role/local",
        json!({"local_secret_ids":true}),
        100,
        None,
    )
    .unwrap();
    let sid = request(
        &mut state,
        Some(&root),
        "team",
        "POST",
        "auth/build/role/local/secret-id",
        json!({}),
        100,
        None,
    )
    .unwrap();
    let credentials = json!({"role_id":state.mounted_roles["team"]["build"]["local"].role_id,
        "secret_id":sid.body["data"]["secret_id"]});
    assert!(
        request(
            &mut state,
            None,
            "",
            "POST",
            "auth/approle/login",
            credentials.clone(),
            100,
            None
        )
        .is_err()
    );
    assert_eq!(
        request(
            &mut state,
            None,
            "team",
            "POST",
            "auth/build/login",
            credentials,
            100,
            None
        )
        .unwrap()
        .status,
        200
    );
    state.validate_cluster_local_approle_state(CLUSTER).unwrap();
}
