#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;

fn config() -> Value {
    json!({"kubernetes_host":"https://cluster.example.test:6443","kubernetes_ca_cert":include_str!("testdata/kubernetes-api-ca.pem"),"token_reviewer_jwt":"synthetic-reviewer-credential","disable_local_ca_jwt":true})
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
    assert_eq!(data["token_policies"], json!(["changed"]));
    let encoded = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut state: AuthState = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(login(&mut state, now).body["auth"]["lease_duration"], 45);
    update(
        &mut state,
        &root,
        "auth/kubernetes/role/app",
        json!({"token_policies":[]}),
        now,
    );
    assert!(
        state
            .kubernetes_at(AuthScope {
                namespace: "",
                mount: "kubernetes"
            })
            .unwrap()
            .roles["app"]
            .token_policies
            .is_empty()
    );
    assert_eq!(
        login(&mut state, now).body["auth"]["token_policies"],
        json!(["default"])
    );
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
            Some(TokenAuthProvenance::TokenApi { .. })
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

fn cidr_login(
    state: &mut AuthState,
    peer: Option<std::net::IpAddr>,
    now: u64,
) -> Result<AuthResponse, AuthError> {
    let plan = state.prepare_kubernetes_login_from(
        "",
        "kubernetes",
        &json!({"role":"app","jwt":"synthetic-login-credential"}),
        now,
        peer,
    )?;
    state.finish_kubernetes_login(
        plan,
        KubernetesLoginObservation::observed("workload", "worker", "uid-1"),
    )
}

#[test]
fn kubernetes_cidr_role_partial_null_and_empty_preserve_old_canonical_bytes() {
    let (mut state, root, _, now) = fixture();
    let scope = AuthScope {
        namespace: "",
        mount: "kubernetes",
    };
    let old = serde_json::to_vec(&state.kubernetes_at(scope).unwrap().roles["app"]).unwrap();
    assert!(!state.has_kube_role_bound_cidrs());
    assert!(!String::from_utf8_lossy(&old).contains("token_bound_cidrs"));
    for clear in [Value::Null, json!([])] {
        update(
            &mut state,
            &root,
            "auth/kubernetes/role/app",
            json!({"token_bound_cidrs":"127.0.0.1/32,::1/128"}),
            now,
        );
        assert!(state.has_kube_role_bound_cidrs() && state.has_token_bound_cidrs());
        update(
            &mut state,
            &root,
            "auth/kubernetes/role/app",
            json!({"token_ttl":60}),
            now,
        );
        let read = state
            .handle(
                Some(&root),
                "",
                "GET",
                "auth/kubernetes/role/app",
                &json!({}),
                now,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            read.body["data"]["token_bound_cidrs"],
            json!(["127.0.0.1", "::1"])
        );
        let before = provider_renewal::state_revision(&state).unwrap();
        assert_eq!(
            state
                .handle(
                    Some(&root),
                    "",
                    "POST",
                    "auth/kubernetes/role/app",
                    &json!({"token_bound_cidrs":["host.invalid"]}),
                    now
                )
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
        update(
            &mut state,
            &root,
            "auth/kubernetes/role/app",
            json!({"token_bound_cidrs":clear}),
            now,
        );
        assert!(!state.has_kube_role_bound_cidrs());
        assert_eq!(
            serde_json::to_vec(&state.kubernetes_at(scope).unwrap().roles["app"]).unwrap(),
            old
        );
        let read = state
            .handle(
                Some(&root),
                "",
                "GET",
                "auth/kubernetes/role/app",
                &json!({}),
                now,
            )
            .unwrap()
            .unwrap();
        assert_eq!(read.body["data"]["token_bound_cidrs"], json!([]));
    }
}

#[test]
fn kubernetes_cidr_denies_missing_wrong_and_cross_family_origin_before_issuance_or_use() {
    let (mut state, root, _, now) = fixture();
    let good = Some("127.0.0.1".parse().unwrap());
    let bad = Some("127.0.0.2".parse().unwrap());
    update(
        &mut state,
        &root,
        "auth/kubernetes/role/app",
        json!({"token_bound_cidrs":["::ffff:127.0.0.1/128"],"token_num_uses":2}),
        now,
    );
    let before = provider_renewal::state_revision(&state).unwrap();
    for peer in [None, bad, Some("::1".parse().unwrap())] {
        assert_eq!(cidr_login(&mut state, peer, now).err().unwrap().status, 403);
        assert_eq!(provider_renewal::state_revision(&state).unwrap(), before);
    }
    let issued = cidr_login(&mut state, good, now).unwrap();
    let raw = issued.body["auth"]["client_token"].as_str().unwrap();
    assert_eq!(state.tokens[&hash(raw)].bound_cidrs, ["127.0.0.1"]);
    for peer in [None, bad] {
        assert_eq!(
            state
                .authenticate_read_only_from(raw, now, peer)
                .err()
                .unwrap()
                .status,
            403
        );
        assert_eq!(
            state
                .authenticate_from(raw, now, peer)
                .err()
                .unwrap()
                .status,
            403
        );
    }
    assert_eq!(state.tokens[&hash(raw)].uses_remaining, Some(2));
    assert!(state.authenticate_from(raw, now, good).is_ok());
    assert_eq!(state.tokens[&hash(raw)].uses_remaining, Some(1));
    update(
        &mut state,
        &root,
        "auth/kubernetes/role/app",
        json!({"token_bound_cidrs":["::/0"]}),
        now,
    );
    assert_eq!(cidr_login(&mut state, good, now).err().unwrap().status, 403);
    assert!(cidr_login(&mut state, Some("::1".parse().unwrap()), now).is_ok());
}

#[test]
fn kubernetes_cidr_issued_snapshot_survives_role_clear_reopen_and_admin_renewal() {
    let (mut state, root, old, now) = fixture();
    let good = Some("127.0.0.1".parse().unwrap());
    let other = Some("127.0.0.2".parse().unwrap());
    update(
        &mut state,
        &root,
        "auth/kubernetes/role/app",
        json!({"token_bound_cidrs":["127.0.0.1"]}),
        now,
    );
    let issued = cidr_login(&mut state, good, now).unwrap();
    let raw = issued.body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(state.authenticate_read_only_from(&old, now, other).is_ok());
    update(
        &mut state,
        &root,
        "auth/kubernetes/role/app",
        json!({"token_bound_cidrs":[]}),
        now,
    );
    let bytes = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let mut state: AuthState = serde_json::from_slice(&bytes).unwrap();
    state.validate_online_auth().unwrap();
    assert!(state.has_kube_role_bound_cidrs());
    assert_eq!(
        state
            .authenticate_from(&raw, now, other)
            .err()
            .unwrap()
            .status,
        403
    );
    let mut admin = root;
    admin.origin_peer = other;
    for via in ["renew-self", "renew", "renew-accessor"] {
        let actor = state.authenticate_from(&raw, now, good).unwrap();
        let body = match via {
            "renew" => json!({"token":raw,"increment":60}),
            "renew-accessor" => {
                json!({"accessor":state.tokens[&hash(&raw)].accessor,"increment":60})
            }
            _ => json!({"increment":60}),
        };
        let response = state
            .handle(
                Some(if via == "renew-self" { &actor } else { &admin }),
                "",
                "POST",
                &format!("auth/token/{via}"),
                &body,
                now,
            )
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(state.tokens[&hash(&raw)].bound_cidrs, ["127.0.0.1"]);
    }
    state
        .kubernetes_mut(AuthScope {
            namespace: "",
            mount: "kubernetes",
        })
        .roles
        .remove("app");
    assert!(state.has_kube_role_bound_cidrs());
    assert_eq!(
        state
            .authenticate_read_only_from(&raw, now, other)
            .err()
            .unwrap()
            .status,
        403
    );
    assert!(state.authenticate_read_only_from(&raw, now, good).is_ok());
}

#[test]
fn kubernetes_cidr_token_api_child_inherits_while_orphan_does_not() {
    let (mut state, root, _, now) = fixture();
    let good = Some("127.0.0.1".parse().unwrap());
    let other = Some("127.0.0.2".parse().unwrap());
    update(
        &mut state,
        &root,
        "auth/kubernetes/role/app",
        json!({"token_bound_cidrs":["127.0.0.1"]}),
        now,
    );
    let issued = cidr_login(&mut state, good, now).unwrap();
    let raw = issued.body["auth"]["client_token"].as_str().unwrap();
    let actor = state.authenticate_from(raw, now, good).unwrap();
    for (route, inherits) in [("create", true), ("create-orphan", false)] {
        let response = state
            .handle(
                Some(&actor),
                "",
                "POST",
                &format!("auth/token/{route}"),
                &json!({"policies":["default"],"ttl":60}),
                now,
            )
            .unwrap()
            .unwrap();
        let child = response.body["auth"]["client_token"].as_str().unwrap();
        assert_eq!(state.tokens[&hash(child)].bound_cidrs.is_empty(), !inherits);
        assert_eq!(
            state.authenticate_read_only_from(child, now, other).is_ok(),
            !inherits
        );
    }
}
