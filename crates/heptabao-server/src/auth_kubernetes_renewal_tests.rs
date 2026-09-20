#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;

fn config() -> Value {
    json!({"kubernetes_host":"https://cluster.example.test:6443","token_reviewer_jwt":"synthetic-reviewer-credential","disable_local_ca_jwt":true})
}
fn role() -> Value {
    json!({"bound_service_account_names":["worker"],"bound_service_account_namespaces":["workload"],"audience":"heptabao","token_policies":["issuer"],"token_ttl":60,"token_max_ttl":90})
}
fn update(state: &mut AuthState, root: &Principal, path: &str, body: Value, now: u64) {
    assert_eq!(
        state
            .handle(Some(root), "", "POST", path, &body, now)
            .unwrap()
            .unwrap()
            .status,
        204
    );
}
fn fixture() -> (AuthState, Principal, String, u64) {
    let (mut state, root_raw) = AuthState::bootstrap(100).unwrap();
    let root = state.authenticate(&root_raw, 100).unwrap();
    for (path, body) in [
        ("sys/auth/kubernetes", json!({"type":"kubernetes"})),
        (
            "sys/policies/acl/issuer",
            json!({"policy":"path \"auth/token/*\" { capabilities = [\"read\", \"update\", \"sudo\"] }"}),
        ),
        ("auth/kubernetes/config", config()),
        ("auth/kubernetes/role/app", role()),
    ] {
        update(&mut state, &root, path, body, 100);
    }
    let response = login(&mut state, 100);
    let raw = response.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let now = state.tokens[&hash(&raw)].created_at;
    assert_eq!(response.body["auth"]["lease_duration"], 60);
    assert_eq!(response.body["auth"]["renewable"], true);
    (state, root, raw, now)
}
fn login(state: &mut AuthState, now: u64) -> AuthResponse {
    let plan = state
        .prepare_kubernetes_login(
            "",
            "kubernetes",
            &json!({"role":"app","jwt":"synthetic-login-credential"}),
            now,
        )
        .unwrap();
    state
        .finish_kubernetes_login(
            plan,
            KubernetesLoginObservation::observed("workload", "worker", "uid-1"),
        )
        .unwrap()
}
fn renew(
    state: &mut AuthState,
    root: &Principal,
    raw: &str,
    operation: &str,
    increment: u64,
    now: u64,
) -> Result<AuthResponse, AuthError> {
    let actor = state.authenticate(raw, now)?;
    let body = match operation {
        "renew" => json!({"token":raw,"increment":increment}),
        "renew-accessor" => {
            json!({"accessor":state.tokens[&hash(raw)].accessor,"increment":increment})
        }
        _ => json!({"increment":increment}),
    };
    state
        .handle(
            Some(if operation == "renew-self" {
                &actor
            } else {
                root
            }),
            "",
            "POST",
            &format!("auth/token/{operation}"),
            &body,
            now,
        )?
        .ok_or_else(denied)
}

#[test]
fn kubernetes_all_renew_routes_use_current_role_without_rechecking_tokenreview() {
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let (mut state, root, raw, now) = fixture();
        let scope = AuthScope {
            namespace: "",
            mount: "kubernetes",
        };
        assert_eq!(state.tokens[&hash(&raw)].max_expires_at, None);
        state.kubernetes_mut(scope).config = None;
        update(
            &mut state,
            &root,
            "auth/kubernetes/role/app",
            json!({"token_ttl":60,"token_max_ttl":600,"token_policies":["changed"],"audience":"changed","bound_service_account_names":["changed"],"bound_service_account_namespaces":["changed"]}),
            now + 3,
        );
        let response = renew(&mut state, &root, &raw, operation, 300, now + 3).unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], 300);
        assert!(state.tokens[&hash(&raw)].policies.contains("issuer"));
        assert!(!state.tokens[&hash(&raw)].policies.contains("changed"));
        let saved = state.kubernetes_mut(scope).roles.remove("app").unwrap();
        state.validate_kubernetes_renewal_state().unwrap();
        let before = state.tokens[&hash(&raw)].expires_at;
        assert_eq!(
            renew(&mut state, &root, &raw, operation, 400, now + 4)
                .err()
                .unwrap()
                .status,
            500
        );
        assert_eq!(state.tokens[&hash(&raw)].expires_at, before);
        state
            .kubernetes_mut(scope)
            .roles
            .insert("app".into(), saved);
        assert_eq!(
            renew(&mut state, &root, &raw, operation, 300, now + 5)
                .unwrap()
                .status,
            200
        );
    }
}

#[test]
fn kubernetes_current_role_and_mount_maximum_count_from_issue_time() {
    for mount in [false, true] {
        let (mut state, root, raw, now) = fixture();
        update(
            &mut state,
            &root,
            "auth/kubernetes/role/app",
            json!({"token_ttl":60,"token_max_ttl":600}),
            now,
        );
        if mount {
            update(
                &mut state,
                &root,
                "sys/auth/kubernetes/tune",
                json!({"default_lease_ttl":3,"max_lease_ttl":3}),
                now + 4,
            );
        } else {
            update(
                &mut state,
                &root,
                "auth/kubernetes/role/app",
                json!({"token_ttl":3,"token_max_ttl":3}),
                now + 4,
            );
        }
        let before = state.tokens[&hash(&raw)].expires_at;
        assert_eq!(
            renew(&mut state, &root, &raw, "renew-self", 300, now + 4)
                .err()
                .unwrap()
                .status,
            500
        );
        assert_eq!(state.tokens[&hash(&raw)].expires_at, before);
        update(
            &mut state,
            &root,
            "sys/auth/kubernetes/tune",
            json!({"default_lease_ttl":60,"max_lease_ttl":600}),
            now + 5,
        );
        update(
            &mut state,
            &root,
            "auth/kubernetes/role/app",
            json!({"token_ttl":60,"token_max_ttl":600}),
            now + 5,
        );
        assert_eq!(
            renew(&mut state, &root, &raw, "renew-self", 300, now + 5)
                .unwrap()
                .body["auth"]["lease_duration"],
            300
        );
    }
}

#[test]
fn kubernetes_period_reads_current_limits_but_retains_issued_explicit_cap() {
    let (mut state, root, _, now) = fixture();
    update(
        &mut state,
        &root,
        "auth/kubernetes/role/app",
        json!({"token_period":20,"token_explicit_max_ttl":120}),
        now,
    );
    let response = login(&mut state, now);
    assert_eq!(response.body["auth"]["lease_duration"], 20);
    let raw = response.body["auth"]["client_token"].as_str().unwrap();
    let issued = state.tokens[&hash(raw)].created_at;
    assert_eq!(state.tokens[&hash(raw)].max_expires_at, Some(issued + 120));
    update(
        &mut state,
        &root,
        "auth/kubernetes/role/app",
        json!({"token_ttl":3,"token_max_ttl":3,"token_explicit_max_ttl":1}),
        issued + 4,
    );
    assert_eq!(
        renew(&mut state, &root, raw, "renew-self", 300, issued + 4)
            .unwrap()
            .body["auth"]["lease_duration"],
        3
    );
    update(
        &mut state,
        &root,
        "auth/kubernetes/role/app",
        json!({"token_ttl":60,"token_max_ttl":600,"token_period":120}),
        issued + 5,
    );
    assert_eq!(
        renew(&mut state, &root, raw, "renew-self", 300, issued + 5)
            .unwrap()
            .body["auth"]["lease_duration"],
        115
    );
    assert_eq!(state.tokens[&hash(raw)].max_expires_at, Some(issued + 120));
}

#[test]
fn kubernetes_role_zero_defaults_and_partial_updates_are_durable() {
    let (mut state, root, _, now) = fixture();
    update(
        &mut state,
        &root,
        "sys/auth/kubernetes/tune",
        json!({"default_lease_ttl":45,"max_lease_ttl":600}),
        now,
    );
    update(
        &mut state,
        &root,
        "auth/kubernetes/role/app",
        json!({"token_ttl":0,"token_max_ttl":0,"token_period":0,"token_explicit_max_ttl":0}),
        now,
    );
    update(
        &mut state,
        &root,
        "auth/kubernetes/role/app",
        json!({"token_policies":["changed"],"token_ttl":null}),
        now,
    );
    let data = state
        .handle(
            Some(&root),
            "",
            "GET",
            "auth/kubernetes/role/app",
            &json!({}),
            now,
        )
        .unwrap()
        .unwrap()
        .body["data"]
        .clone();
    for field in [
        "token_ttl",
        "token_max_ttl",
        "token_period",
        "token_explicit_max_ttl",
    ] {
        assert_eq!(data[field], 0);
    }
    assert_eq!(data["bound_service_account_names"], json!(["worker"]));
    let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut state: AuthState = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(login(&mut state, now).body["auth"]["lease_duration"], 45);
    for field in [
        "token_ttl",
        "token_max_ttl",
        "token_period",
        "token_explicit_max_ttl",
    ] {
        let mut body = json!({});
        body[field] = json!(MAX_TTL + 1);
        assert_eq!(
            state
                .handle(
                    Some(&root),
                    "",
                    "POST",
                    "auth/kubernetes/role/app",
                    &body,
                    now
                )
                .err()
                .unwrap()
                .status,
            400
        );
    }
}

#[test]
fn kubernetes_tokenapi_children_never_inherit_role_authority_and_legacy_fails_closed() {
    let (mut state, root, raw, now) = fixture();
    let actor = state.authenticate(&raw, now).unwrap();
    let mut children = Vec::new();
    for operation in ["create", "create-orphan"] {
        let response = state
            .handle(
                Some(&actor),
                "",
                "POST",
                &format!("auth/token/{operation}"),
                &json!({"policies":["issuer"],"ttl":60}),
                now,
            )
            .unwrap()
            .unwrap();
        let child = response.body["auth"]["client_token"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(matches!(
            state.tokens[&hash(&child)].auth_provenance,
            Some(TokenAuthProvenance::TokenApi)
        ));
        children.push(child);
    }
    state
        .kubernetes_mut(AuthScope {
            namespace: "",
            mount: "kubernetes",
        })
        .roles
        .remove("app");
    for child in children {
        assert_eq!(
            renew(&mut state, &root, &child, "renew-self", 30, now + 1)
                .unwrap()
                .status,
            200
        );
    }
    let token = state.tokens.get_mut(&hash(&raw)).unwrap();
    token.auth_provenance = None;
    token.renewable = false;
    token.max_expires_at = token.expires_at;
    assert_eq!(
        renew(&mut state, &root, &raw, "renew-self", 30, now + 1)
            .err()
            .unwrap()
            .status,
        400
    );
    state.tokens.get_mut(&hash(&raw)).unwrap().renewable = true;
    assert_eq!(
        renew(&mut state, &root, &raw, "renew-self", 30, now + 1)
            .err()
            .unwrap()
            .status,
        400
    );
}

#[test]
fn kubernetes_tokenreview_cannot_issue_into_recreated_mount() {
    let (mut state, root, _, now) = fixture();
    let plan = state
        .prepare_kubernetes_login(
            "",
            "kubernetes",
            &json!({"role":"app","jwt":"synthetic-login-credential"}),
            now,
        )
        .unwrap();
    state
        .handle(
            Some(&root),
            "",
            "DELETE",
            "sys/auth/kubernetes",
            &json!({}),
            now,
        )
        .unwrap()
        .unwrap();
    update(
        &mut state,
        &root,
        "sys/auth/kubernetes",
        json!({"type":"kubernetes"}),
        now,
    );
    update(&mut state, &root, "auth/kubernetes/config", config(), now);
    update(&mut state, &root, "auth/kubernetes/role/app", role(), now);
    let before = provider_renewal::state_revision(&state).unwrap();
    assert_eq!(
        state
            .finish_kubernetes_login(
                plan,
                KubernetesLoginObservation::observed("workload", "worker", "uid-1")
            )
            .err()
            .unwrap()
            .status,
        409
    );
    assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
}
