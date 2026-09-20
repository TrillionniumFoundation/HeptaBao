//! Service publication tests inject a TokenReview observation only at login.
//! The real TLS fixture separately proves login I/O and renewal's absence of I/O.
use super::online_auth::OnlineAuthObservation;
use super::tests::{Root, bootstrap, call};
use super::*;
use crate::auth::KubernetesLoginObservation;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture(root: &Root) -> TestResult<(Service, String, String, String)> {
    let mut service = root.service()?;
    let mut engines = EngineState::default();
    engines.handle("", "POST", "sys/mounts/pki", &json!({"type":"pki"}), 100)?;
    let certificate = engines
        .handle(
            "",
            "POST",
            "pki/root/generate/internal",
            &json!({"common_name":"cluster.example.test","ttl":"48h"}),
            100,
        )?
        .ok_or("CA")?;
    service.install_outbound_endpoints(vec![crate::outbound::EndpointConfig {
        origin: "https://cluster.example.test:6443".into(),
        address: "127.0.0.1:6443".parse()?,
        server_name: "cluster.example.test".into(),
        ca_pem: certificate.body["data"]["certificate"]
            .as_str()
            .ok_or("CA PEM")?
            .into(),
        path_prefix: "/".into(),
        shared_secret: String::new(),
    }])?;
    let (key, admin) = bootstrap(&mut service)?;
    for (path, body) in [
        ("sys/auth/kubernetes", json!({"type":"kubernetes"})),
        (
            "auth/kubernetes/config",
            json!({"kubernetes_host":"https://cluster.example.test:6443","token_reviewer_jwt":"synthetic-reviewer-credential","disable_local_ca_jwt":true}),
        ),
        (
            "auth/kubernetes/role/app",
            json!({"bound_service_account_names":["worker"],"bound_service_account_namespaces":["workload"],"audience":"heptabao","token_ttl":60,"token_max_ttl":600}),
        ),
    ] {
        assert_eq!(
            call(&mut service, "POST", path, &admin, body).status,
            204,
            "{path}"
        );
    }
    let pending = match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path: "auth/kubernetes/login",
        namespace: "",
        token: "",
        body: json!({"role":"app","jwt":"synthetic-login-credential"}),
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        client_certificates: None,
    }) {
        RequestExecution::External(pending) => pending,
        RequestExecution::Complete(response) => {
            return Err(format!("expected login effect, got {}", response.status).into());
        }
    };
    let response = service.finish_external_request(
        *pending,
        ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::Kubernetes(
            KubernetesLoginObservation::observed("workload", "worker", "uid-1"),
        ))),
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["auth"]["lease_duration"], 60);
    assert_eq!(response.body["auth"]["renewable"], true);
    let token = response.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned();
    Ok((service, key, admin, token))
}

fn local_renew(
    service: &mut Service,
    path: &str,
    actor: &str,
    body: Value,
    now: u64,
    wrap: bool,
) -> TestResult<Response> {
    match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path,
        namespace: "",
        token: actor,
        body,
        now,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: wrap.then_some(60),
        client_certificates: None,
    }) {
        RequestExecution::Complete(response) => Ok(response),
        RequestExecution::External(_) => {
            Err("Kubernetes renewal must not perform TokenReview".into())
        }
    }
}

#[test]
fn kubernetes_service_renewal_echo_wrapping_and_role_deletion_survive_restart() -> TestResult {
    for operation in ["renew-self", "renew", "renew-accessor"] {
        let root = Root::new();
        let (mut service, key, admin, token) = fixture(&root)?;
        let info = call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &token,
            json!({}),
        );
        let accessor = info.body["data"]["accessor"].as_str().ok_or("accessor")?;
        let request = match operation {
            "renew" => json!({"token":token,"increment":120}),
            "renew-accessor" => json!({"accessor":accessor,"increment":120}),
            _ => json!({"increment":120}),
        };
        let path = format!("auth/token/{operation}");
        let actor = if operation == "renew-self" {
            &token
        } else {
            &admin
        };
        let response = local_renew(&mut service, &path, actor, request.clone(), 110, true)?;
        assert_eq!(response.status, 200);
        assert!(response.body["auth"].is_null());
        assert!(!response.body.to_string().contains(&token));
        let wrapper = response.body["wrap_info"]["token"]
            .as_str()
            .ok_or("wrapper")?
            .to_owned();
        drop(service);
        let mut service = root.service()?;
        assert_eq!(
            service
                .handle_at("POST", "sys/unseal", "", "", json!({"key":key}), 111)
                .status,
            200
        );
        let response =
            service.handle_at("POST", "sys/wrapping/unwrap", "", &wrapper, json!({}), 111);
        assert_eq!(response.status, 200);
        assert_eq!(response.body["auth"]["lease_duration"], 120);
        if operation == "renew-accessor" {
            assert!(response.body["auth"].get("client_token").is_none());
        } else {
            assert_eq!(response.body["auth"]["client_token"], token);
        }
        assert!(
            service
                .handle_at("POST", "sys/wrapping/unwrap", "", &wrapper, json!({}), 111)
                .status
                >= 400
        );
        assert_eq!(
            service
                .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 112)
                .body["data"]["expire_time_unix"],
            230
        );
        assert_eq!(
            service
                .handle_at(
                    "DELETE",
                    "auth/kubernetes/role/app",
                    "",
                    &admin,
                    json!({}),
                    112
                )
                .status,
            204
        );
        let response = local_renew(&mut service, &path, actor, request, 112, true)?;
        assert_eq!(response.status, 500);
        assert!(response.body.get("wrap_info").is_none());
        assert_eq!(
            service
                .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 112)
                .body["data"]["expire_time_unix"],
            230
        );
        assert!(
            service
                .state
                .as_ref()
                .ok_or("state")?
                .validate_format()
                .is_ok()
        );
    }
    Ok(())
}

#[test]
fn kubernetes_renewal_obeys_live_identity_and_capacity_without_extending_lease() -> TestResult {
    let root = Root::new();
    let (mut service, _, admin, token) = fixture(&root)?;
    let info = call(
        &mut service,
        "GET",
        "auth/token/lookup-self",
        &token,
        json!({}),
    );
    let entity = info.body["data"]["entity_id"]
        .as_str()
        .ok_or("entity")?
        .to_owned();
    let expiry = info.body["data"]["expire_time_unix"].clone();
    service.state_capacity = 1;
    assert_eq!(
        local_renew(
            &mut service,
            "auth/token/renew-self",
            &token,
            json!({"increment":300}),
            110,
            true
        )?
        .status,
        507
    );
    service.state_capacity = MAX_STATE_BYTES;
    assert_eq!(
        service
            .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 110)
            .body["data"]["expire_time_unix"],
        expiry
    );
    assert_eq!(
        service
            .handle_at(
                "POST",
                &format!("identity/entity/id/{entity}"),
                "",
                &admin,
                json!({"disabled":true}),
                111
            )
            .status,
        204
    );
    for (path, actor, body) in [
        (
            "auth/token/renew-self",
            token.as_str(),
            json!({"increment":300}),
        ),
        (
            "auth/token/renew",
            admin.as_str(),
            json!({"token":token,"increment":300}),
        ),
    ] {
        let response = local_renew(&mut service, path, actor, body, 112, true)?;
        assert_eq!(response.status, 403);
        assert!(response.body.get("wrap_info").is_none());
    }
    assert_eq!(
        service
            .handle_at(
                "POST",
                &format!("identity/entity/id/{entity}"),
                "",
                &admin,
                json!({"disabled":false}),
                113
            )
            .status,
        204
    );
    assert_eq!(
        service
            .handle_at("GET", "auth/token/lookup-self", "", &token, json!({}), 113)
            .body["data"]["expire_time_unix"],
        expiry
    );
    Ok(())
}

#[test]
fn kubernetes_schema_twenty_fences_new_authority_and_preserves_legacy_tokens() -> TestResult {
    let root = Root::new();
    let (service, _, _, token) = fixture(&root)?;
    let mut state = service.state.clone().ok_or("state")?;
    assert_eq!(state.schema, CURRENT_STATE_SCHEMA);
    state.schema = 19;
    assert!(state.validate_format().is_err());
    let mut auth = serde_json::to_value(&state.auth)?;
    for entry in auth["tokens"].as_object_mut().ok_or("tokens")?.values_mut() {
        if entry["auth_provenance"]["kind"] == "kubernetes" {
            entry
                .as_object_mut()
                .ok_or("token")?
                .remove("auth_provenance");
            entry["renewable"] = json!(false);
            entry["max_expires_at"] = entry["expires_at"].clone();
        }
    }
    state.auth = serde_json::from_value::<AuthState>(auth.clone())?.into();
    assert!(
        state.validate_format().is_err(),
        "new role limits also require schema 20"
    );
    for mounts in auth["kubernetes_mounts"]
        .as_object_mut()
        .ok_or("namespaces")?
        .values_mut()
    {
        for mount in mounts.as_object_mut().ok_or("mounts")?.values_mut() {
            for role in mount["roles"].as_object_mut().ok_or("roles")?.values_mut() {
                for field in ["token_max_ttl", "token_period", "token_explicit_max_ttl"] {
                    role.as_object_mut().ok_or("role")?.remove(field);
                }
            }
        }
    }
    state.auth = serde_json::from_value::<AuthState>(auth)?.into();
    assert!(state.validate_format().is_ok());
    let mut actor = state.auth.authenticate(&token, 110)?;
    Service::bind_identity_principal(&state, &mut actor, "").map_err(|_| "identity")?;
    assert_eq!(
        state
            .auth
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/token/renew-self",
                &json!({}),
                110
            )
            .err()
            .ok_or("legacy renewed")?
            .status,
        400
    );
    assert!(state.auth.authenticate(&token, 110).is_ok());
    Ok(())
}
