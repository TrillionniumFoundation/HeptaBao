#![allow(clippy::unwrap_used)]
use super::*;

const CA: &str = include_str!("testdata/kubernetes-api-ca.pem");
const HOST: &str = "https://unresolvable.invalid:6443";

fn mounted() -> AuthState {
    let (mut state, token) = AuthState::bootstrap(100).unwrap();
    let actor = state.authenticate(&token, 100).unwrap();
    state
        .handle(
            Some(&actor),
            "",
            "POST",
            "sys/auth/kubernetes",
            &json!({"type":"kubernetes"}),
            100,
        )
        .unwrap()
        .unwrap();
    state
}
fn scope() -> AuthScope<'static> {
    AuthScope {
        namespace: "",
        mount: "kubernetes",
    }
}
fn body() -> Value {
    json!({"kubernetes_host":HOST,"kubernetes_ca_cert":CA,"disable_local_ca_jwt":true})
}

#[test]
fn old_absent_transport_reopens_unchanged_and_requires_explicit_ca_promotion() {
    let old = json!({"kubernetes_host":HOST,"token_reviewer_jwt":"synthetic-old-reviewer"});
    let config: KubernetesConfig = serde_json::from_value(old.clone()).unwrap();
    assert_eq!(serde_json::to_value(&config).unwrap(), old);
    config.validate().unwrap();
    let mut state = mounted();
    state.kubernetes_mut(scope()).config = Some(config);
    let old_bytes = Zeroizing::new(serde_json::to_vec(&state).unwrap());
    let reopened: AuthState = serde_json::from_slice(&old_bytes).unwrap();
    assert_eq!(
        serde_json::to_vec(&reopened).unwrap().as_slice(),
        old_bytes.as_slice()
    );
    assert!(!reopened.has_kubernetes_api_https_state());
    let preserved = reopened.parse_kubernetes_config(scope(), &old).unwrap();
    assert!(preserved.transport.is_none());
    assert_eq!(
        preserved.reviewer_for("synthetic-presented"),
        "synthetic-old-reviewer"
    );
    let without_reviewer = json!({"kubernetes_host":HOST});
    assert!(
        reopened
            .parse_kubernetes_config(scope(), &without_reviewer)
            .is_err()
    );
    let promoted = reopened.parse_kubernetes_config(scope(), &body()).unwrap();
    assert!(promoted.transport.is_some());
    state.kubernetes_mut(scope()).config = Some(promoted);
    assert!(state.has_kubernetes_api_https_state());
    assert!(state.parse_kubernetes_config(scope(), &old).is_err());
}

#[test]
fn native_configuration_is_pure_explicit_ca_and_no_ambient_trust() {
    let state = mounted();
    for value in [Value::Null, json!(""), json!("malformed CA"), json!(false)] {
        let mut request = body();
        request["kubernetes_ca_cert"] = value;
        assert!(state.parse_kubernetes_config(scope(), &request).is_err());
    }
    let mut request = body();
    request
        .as_object_mut()
        .unwrap()
        .remove("kubernetes_ca_cert");
    assert!(state.parse_kubernetes_config(scope(), &request).is_err());
    let mut request = body();
    request["disable_local_ca_jwt"] = json!(false);
    assert!(state.parse_kubernetes_config(scope(), &request).is_err());
    for host in [
        "https://unresolvable.invalid",
        "https://[::1]",
        "https://127.0.0.1:6443/base/",
    ] {
        let mut request = body();
        request["kubernetes_host"] = json!(host);
        let config = state.parse_kubernetes_config(scope(), &request).unwrap();
        assert_eq!(
            config.token_review_url(),
            format!("{}{TOKEN_REVIEW_PATH}", host.trim_end_matches('/'))
        );
    }
    for host in [
        "http://localhost",
        "https://localhost?token=hidden",
        "https://user@localhost",
        "https://localhost/#fragment",
    ] {
        let mut request = body();
        request["kubernetes_host"] = json!(host);
        assert!(state.parse_kubernetes_config(scope(), &request).is_err());
    }
    assert!(!state.has_kubernetes_api_https_state());
}

#[test]
fn native_reviewer_omission_borrows_presented_token_but_configured_reviewer_never_falls_back() {
    let state = mounted();
    for reviewer in [None, Some(Value::Null), Some(json!(""))] {
        let mut request = body();
        if let Some(reviewer) = reviewer {
            request["token_reviewer_jwt"] = reviewer;
        }
        let config = state.parse_kubernetes_config(scope(), &request).unwrap();
        assert_eq!(
            config.reviewer_for("synthetic-presented"),
            "synthetic-presented"
        );
        assert!(config.token_reviewer_jwt.is_empty());
    }
    let mut request = body();
    request["token_reviewer_jwt"] = json!("synthetic-configured-reviewer");
    let config = state.parse_kubernetes_config(scope(), &request).unwrap();
    assert_eq!(
        config.reviewer_for("synthetic-other-presented"),
        "synthetic-configured-reviewer"
    );
    request["token_reviewer_jwt"] = json!("bad\r\nAuthorization: hidden");
    assert!(state.parse_kubernetes_config(scope(), &request).is_err());
}

#[test]
fn native_ca_reviewer_and_role_mutations_fence_pending_tokenreview() {
    for changed in ["ca", "reviewer", "role"] {
        let mut state = mounted();
        let config = state.parse_kubernetes_config(scope(), &body()).unwrap();
        let mount = state.kubernetes_mut(scope());
        mount.config = Some(config);
        mount.roles.insert(
            "app".into(),
            KubernetesRole {
                bound_service_account_names: BTreeSet::from(["worker".into()]),
                bound_service_account_namespaces: BTreeSet::from(["workload".into()]),
                audience: "heptabao".into(),
                token_policies: BTreeSet::new(),
                token_ttl: 60,
                token_max_ttl: 90,
                token_period: 0,
                token_explicit_max_ttl: 0,
                token_num_uses: 0,
            },
        );
        let plan = state
            .prepare_kubernetes_login(
                "",
                "kubernetes",
                &json!({"role":"app","jwt":"synthetic-presented-token"}),
                100,
            )
            .unwrap();
        let deadline = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            plan.execute(&Outbound::default(), deadline)
                .err()
                .unwrap()
                .status,
            503
        );
        let mount = state.kubernetes_mut(scope());
        match changed {
            "ca" => mount
                .config
                .as_mut()
                .unwrap()
                .transport
                .as_mut()
                .unwrap()
                .certificate
                .push('\n'),
            "reviewer" => {
                mount.config.as_mut().unwrap().token_reviewer_jwt =
                    "synthetic-rotated-reviewer".into()
            }
            _ => mount.roles.get_mut("app").unwrap().token_ttl = 61,
        }
        let before = Zeroizing::new(serde_json::to_vec(&state).unwrap());
        let result = state.finish_kubernetes_login(
            plan,
            KubernetesLoginObservation::observed("workload", "worker", "synthetic-uid"),
        );
        assert_eq!(result.err().unwrap().status, 409);
        assert_eq!(
            serde_json::to_vec(&state).unwrap().as_slice(),
            before.as_slice()
        );
    }
}

#[test]
fn native_provider_failure_is_denied_but_legacy_and_expired_operations_stay_unavailable() {
    let mut state = mounted();
    let config = state.parse_kubernetes_config(scope(), &body()).unwrap();
    state.kubernetes_mut(scope()).config = Some(config);
    state.kubernetes_mut(scope()).roles.insert(
        "app".into(),
        KubernetesRole {
            bound_service_account_names: BTreeSet::from(["worker".into()]),
            bound_service_account_namespaces: BTreeSet::from(["workload".into()]),
            audience: "heptabao".into(),
            token_policies: BTreeSet::new(),
            token_ttl: 60,
            token_max_ttl: 90,
            token_period: 0,
            token_explicit_max_ttl: 0,
            token_num_uses: 0,
        },
    );
    let mut plan = state
        .prepare_kubernetes_login(
            "",
            "kubernetes",
            &json!({"role":"app","jwt":"synthetic-presented-token"}),
            100,
        )
        .unwrap();
    // Invalid bearer fails in the scoped transport before DNS, TLS or any POST.
    plan.config.token_reviewer_jwt = "invalid\r\nheader".into();
    let future = std::time::Instant::now() + std::time::Duration::from_secs(30);
    assert_eq!(
        plan.execute(&Outbound::default(), future)
            .err()
            .unwrap()
            .status,
        403
    );
    let expired = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(1))
        .unwrap();
    assert_eq!(
        plan.execute(&Outbound::default(), expired)
            .err()
            .unwrap()
            .status,
        503
    );
    plan.config.transport = None;
    assert_eq!(
        plan.execute(&Outbound::default(), future)
            .err()
            .unwrap()
            .status,
        503
    );
}
