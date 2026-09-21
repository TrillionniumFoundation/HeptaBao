//! Service publication tests inject a TokenReview observation only at login.
//! The real TLS fixture separately proves login I/O and renewal's absence of I/O.
use super::online_auth::OnlineAuthObservation;
use super::tests::{Root, bootstrap, call};
use super::*;
use crate::auth::KubernetesLoginObservation;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// These auth format fixtures have no record-backed KV1 mounts. Decode their
// unchanged owner bytes as a legacy reader would, without retaining the v5
// runtime installed by current HTTP writes and masking the auth schema fence.
fn restore_legacy_engine_owner(state: &mut State) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        !state.engines.has_record_kv1(),
        "legacy auth fixture cannot discard record-backed KV1 data"
    );
    let before = owner_store::serialize_owner(&state.engines)
        .map_err(|_| "legacy engine fixture serialization")?;
    state.engines = serde_json::from_slice::<EngineState>(&before)?.into();
    assert!(state.engines.record_root().is_none());
    let after = owner_store::serialize_owner(&state.engines)
        .map_err(|_| "legacy engine fixture reserialization")?;
    assert!(
        before.as_slice() == after.as_slice(),
        "legacy engine owner bytes changed"
    );
    Ok(())
}

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
            json!({"kubernetes_host":"https://cluster.example.test:6443","kubernetes_ca_cert":include_str!("testdata/kubernetes-api-ca.pem"),"token_reviewer_jwt":"synthetic-reviewer-credential","disable_local_ca_jwt":true}),
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
        origin_peer: None,
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
        origin_peer: None,
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
    restore_legacy_engine_owner(&mut state)?;
    state.schema = 19;
    state.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(state.validate_format().is_err());
    let mut auth = serde_json::to_value(&state.auth)?;
    // This historical format test removes the later API-transport authority
    // before isolating schema20's role/provenance admission boundary.
    for mounts in auth["kubernetes_mounts"]
        .as_object_mut()
        .ok_or("namespaces")?
        .values_mut()
    {
        for mount in mounts.as_object_mut().ok_or("mounts")?.values_mut() {
            mount["config"]
                .as_object_mut()
                .ok_or("config")?
                .remove("transport");
        }
    }

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
    state.auth = serde_json::from_value::<AuthState>(auth.clone())?.into();
    assert!(
        state.validate_format().is_err(),
        "empty configured policies require schema 20"
    );
    for mounts in auth["kubernetes_mounts"]
        .as_object_mut()
        .ok_or("namespaces")?
        .values_mut()
    {
        for mount in mounts.as_object_mut().ok_or("mounts")?.values_mut() {
            for role in mount["roles"].as_object_mut().ok_or("roles")?.values_mut() {
                // Schema 19 stored the implicit default in every role.
                role["token_policies"] = json!(["default"]);
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

#[test]
fn wrapped_kubernetes_login_commits_once_and_rejects_changed_role() -> TestResult {
    for stale in [false, true] {
        let root = Root::new();
        let (mut service, _, admin, _) = fixture(&root)?;
        let plan = match service.begin_at_mode(RequestDispatch {
            method: "POST",
            path: "auth/kubernetes/login",
            namespace: "",
            token: "",
            body: json!({"role":"app","jwt":"synthetic-login-credential"}),
            now: 100,
            allow_forward: false,
            enforce_namespace: true,
            wrap_ttl_seconds: Some(60),
            origin_peer: None,
            client_certificates: None,
        }) {
            RequestExecution::External(plan) => plan,
            RequestExecution::Complete(_) => {
                return Err("expected wrapped TokenReview effect".into());
            }
        };
        if stale {
            assert_eq!(call(&mut service, "POST", "auth/kubernetes/role/app", &admin,
                json!({"bound_service_account_names":["worker"],"bound_service_account_namespaces":["workload"],"audience":"heptabao","token_ttl":120,"token_max_ttl":600})).status, 204);
        }
        let before = service.state_digest;
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let response = service.finish_external_request(
            *plan,
            ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::Kubernetes(
                KubernetesLoginObservation::observed("workload", "worker", "uid-1"),
            ))),
        );
        if stale {
            assert_eq!(response.status, 409);
            assert!(response.body.get("auth").is_none());
            assert!(response.body.get("wrap_info").is_none());
            assert_eq!(service.state_digest, before);
            assert_eq!(
                service.durable.as_ref().ok_or("durable")?.generation(),
                generation
            );
        } else {
            assert_eq!(response.status, 200);
            assert!(response.body.get("auth").is_none_or(Value::is_null));
            assert_eq!(
                response.body["wrap_info"]["creation_path"],
                "auth/kubernetes/login"
            );
            assert_eq!(
                service.durable.as_ref().ok_or("durable")?.generation(),
                generation + 1
            );
            let wrapper = response.body["wrap_info"]["token"]
                .as_str()
                .ok_or("wrapper")?
                .to_owned();
            let unwrapped = call(
                &mut service,
                "POST",
                "sys/wrapping/unwrap",
                &wrapper,
                json!({}),
            );
            assert_eq!(unwrapped.status, 200);
            assert!(unwrapped.body["auth"]["client_token"].as_str().is_some());
            assert_eq!(
                unwrapped.body["auth"]["accessor"],
                response.body["wrap_info"]["wrapped_accessor"]
            );
            assert_eq!(
                call(
                    &mut service,
                    "POST",
                    "sys/wrapping/unwrap",
                    &wrapper,
                    json!({})
                )
                .status,
                400
            );
        }
    }
    Ok(())
}

#[test]
fn native_kubernetes_config_needs_no_endpoint_and_redacts_optional_reviewer() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, admin) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/kubernetes",
            &admin,
            json!({"type":"kubernetes"})
        )
        .status,
        204
    );
    let body = json!({"kubernetes_host":"https://unresolvable.invalid",
        "kubernetes_ca_cert":include_str!("testdata/kubernetes-api-ca.pem"),
        "disable_local_ca_jwt":true});
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/kubernetes/config",
            &admin,
            body.clone()
        )
        .status,
        204
    );
    let read = call(
        &mut service,
        "GET",
        "auth/kubernetes/config",
        &admin,
        json!({}),
    );
    assert_eq!(read.status, 200);
    assert_eq!(read.body["data"]["token_reviewer_jwt_set"], false);
    assert_eq!(
        read.body["data"]["kubernetes_ca_cert"],
        body["kubernetes_ca_cert"]
    );
    assert!(read.body["data"].get("token_reviewer_jwt").is_none());
    let state = service.state.as_ref().ok_or("state")?;
    assert!(state.auth.has_kubernetes_api_https_state());
    let mut downgraded = state.clone();
    restore_legacy_engine_owner(&mut downgraded)?;
    downgraded.schema = 28;
    downgraded.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(downgraded.validate_format().is_err());
    downgraded.schema = CURRENT_STATE_SCHEMA;
    assert!(downgraded.validate_format().is_ok());
    let before = service.state_digest;
    let mut malformed = body.clone();
    malformed["kubernetes_ca_cert"] = json!("invalid CA");
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/kubernetes/config",
            &admin,
            malformed
        )
        .status,
        400
    );
    assert_eq!(service.state_digest, before);
    let mut replaced = body;
    replaced["token_reviewer_jwt"] = json!("synthetic-stored-reviewer");
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/kubernetes/config",
            &admin,
            replaced
        )
        .status,
        204
    );
    let read = call(
        &mut service,
        "GET",
        "auth/kubernetes/config",
        &admin,
        json!({}),
    );
    assert_eq!(read.body["data"]["token_reviewer_jwt_set"], true);
    assert!(read.body["data"].get("token_reviewer_jwt").is_none());
    Ok(())
}

#[test]
fn schema_twenty_eight_admits_legacy_kubernetes_enrollment_without_api_authority() -> TestResult {
    let root = Root::new();
    let (service, _, _, _) = fixture(&root)?;
    let mut state = service.state.clone().ok_or("state")?;
    let mut auth = serde_json::to_value(&state.auth)?;
    auth["kubernetes_mounts"][""]["kubernetes"]["config"]
        .as_object_mut()
        .ok_or("config")?
        .remove("transport");
    state.auth = serde_json::from_value::<AuthState>(auth)?.into();
    restore_legacy_engine_owner(&mut state)?;
    state.schema = 28;
    state.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(!state.auth.has_kubernetes_api_https_state());
    assert!(state.auth.validate_online_auth().is_ok());
    assert!(state.validate_format().is_ok());
    Ok(())
}

fn cidr_dispatch(
    service: &mut Service,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
    peer: Option<std::net::IpAddr>,
    wrap_ttl_seconds: Option<u64>,
) -> RequestExecution {
    service.begin_at_mode(RequestDispatch {
        method,
        path,
        namespace: "",
        token,
        body,
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds,
        origin_peer: peer,
        client_certificates: None,
    })
}

fn cidr_local(
    service: &mut Service,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
    peer: Option<std::net::IpAddr>,
) -> TestResult<Response> {
    match cidr_dispatch(service, method, path, token, body, peer, None) {
        RequestExecution::Complete(response) => Ok(response),
        _ => Err("local token operation unexpectedly staged TokenReview or forwarding".into()),
    }
}

#[test]
fn kubernetes_cidr_checks_source_before_tokenreview_and_stale_role_cannot_wrap() -> TestResult {
    for wrap in [None, Some(60)] {
        let root = Root::new();
        let (mut service, _, admin, _) = fixture(&root)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "auth/kubernetes/role/app",
                &admin,
                json!({"token_bound_cidrs":["127.0.0.1"]})
            )
            .status,
            204
        );
        let login_body = json!({"role":"app","jwt":"synthetic-login-credential"});
        for peer in [None, Some("127.0.0.2".parse()?)] {
            let before = service.state_digest;
            let response = match cidr_dispatch(
                &mut service,
                "POST",
                "auth/kubernetes/login",
                "",
                login_body.clone(),
                peer,
                wrap,
            ) {
                RequestExecution::Complete(response) => response,
                _ => return Err("denied source staged TokenReview".into()),
            };
            assert_eq!(response.status, 403);
            assert_eq!(service.state_digest, before);
        }
        let pending = match cidr_dispatch(
            &mut service,
            "POST",
            "auth/kubernetes/login",
            "",
            login_body,
            Some("127.0.0.1".parse()?),
            wrap,
        ) {
            RequestExecution::External(pending) => pending,
            _ => return Err("allowed source did not stage TokenReview".into()),
        };
        assert_eq!(
            call(
                &mut service,
                "POST",
                "auth/kubernetes/role/app",
                &admin,
                json!({"token_bound_cidrs":["127.0.0.2"]})
            )
            .status,
            204
        );
        let before = service.state_digest;
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let response = service.finish_external_request(
            *pending,
            ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::Kubernetes(
                KubernetesLoginObservation::observed("workload", "worker", "uid-1"),
            ))),
        );
        assert_eq!(response.status, 409);
        assert!(response.body.get("auth").is_none_or(Value::is_null));
        assert!(response.body.get("wrap_info").is_none_or(Value::is_null));
        assert_eq!(service.state_digest, before);
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
    }
    Ok(())
}

#[test]
fn kubernetes_cidr_wrapper_is_unbound_but_inner_snapshot_persists_and_admin_can_renew() -> TestResult
{
    let root = Root::new();
    let (mut service, key, admin, old) = fixture(&root)?;
    let mut admission = service.state.as_ref().ok_or("state")?.clone();
    restore_legacy_engine_owner(&mut admission)?;
    admission.schema = 30;
    admission.auth.omit_lease_metadata_for_legacy_fixture();
    assert!(admission.validate_format().is_ok());
    let good = Some("127.0.0.1".parse()?);
    let other = Some("127.0.0.2".parse()?);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/kubernetes/role/app",
            &admin,
            json!({"token_bound_cidrs":["127.0.0.1"]})
        )
        .status,
        204
    );
    let mut admission = service.state.as_ref().ok_or("state")?.clone();
    restore_legacy_engine_owner(&mut admission)?;
    admission.schema = 30;
    admission.auth.omit_lease_metadata_for_legacy_fixture();
    assert_eq!(
        admission
            .validate_format()
            .err()
            .ok_or("missing role schema fence")?
            .status,
        503
    );
    admission.schema = CURRENT_STATE_SCHEMA;
    assert!(admission.validate_format().is_ok());
    assert_eq!(
        cidr_local(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &old,
            json!({}),
            other
        )?
        .status,
        200
    );
    let pending = match cidr_dispatch(
        &mut service,
        "POST",
        "auth/kubernetes/login",
        "",
        json!({"role":"app","jwt":"synthetic-login-credential"}),
        good,
        Some(60),
    ) {
        RequestExecution::External(pending) => pending,
        _ => return Err("expected wrapped TokenReview".into()),
    };
    let wrapped = service.finish_external_request(
        *pending,
        ExternalEffectResult::OnlineAuth(Ok(OnlineAuthObservation::Kubernetes(
            KubernetesLoginObservation::observed("workload", "worker", "uid-1"),
        ))),
    );
    assert_eq!(wrapped.status, 200);
    let wrapper = wrapped.body["wrap_info"]["token"]
        .as_str()
        .ok_or("wrapper")?
        .to_owned();
    let inner = cidr_local(
        &mut service,
        "POST",
        "sys/wrapping/unwrap",
        &wrapper,
        json!({}),
        other,
    )?;
    assert_eq!(inner.status, 200);
    let raw = inner.body["auth"]["client_token"]
        .as_str()
        .ok_or("inner token")?
        .to_owned();
    let accessor = inner.body["auth"]["accessor"]
        .as_str()
        .ok_or("accessor")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/kubernetes/role/app",
            &admin,
            json!({"token_bound_cidrs":null})
        )
        .status,
        204
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .has_kube_role_bound_cidrs()
    );
    let mut admission = service.state.as_ref().ok_or("state")?.clone();
    restore_legacy_engine_owner(&mut admission)?;
    admission.schema = 30;
    admission.auth.omit_lease_metadata_for_legacy_fixture();
    assert_eq!(
        admission
            .validate_format()
            .err()
            .ok_or("missing issued-token schema fence")?
            .status,
        503
    );
    admission.schema = CURRENT_STATE_SCHEMA;
    assert!(admission.validate_format().is_ok());
    for peer in [None, other] {
        assert_eq!(
            cidr_local(
                &mut service,
                "GET",
                "auth/token/lookup-self",
                &raw,
                json!({}),
                peer
            )?
            .status,
            403
        );
        assert_eq!(
            cidr_local(
                &mut service,
                "POST",
                "auth/token/renew-self",
                &raw,
                json!({"increment":60}),
                peer
            )?
            .status,
            403
        );
    }
    assert_eq!(
        cidr_local(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &raw,
            json!({}),
            good
        )?
        .status,
        200
    );
    for (path, actor, body, peer) in [
        (
            "auth/token/renew-self",
            raw.as_str(),
            json!({"increment":60}),
            good,
        ),
        (
            "auth/token/renew",
            admin.as_str(),
            json!({"token":raw,"increment":60}),
            other,
        ),
        (
            "auth/token/renew-accessor",
            admin.as_str(),
            json!({"accessor":accessor,"increment":60}),
            other,
        ),
    ] {
        assert_eq!(
            cidr_local(&mut service, "POST", path, actor, body, peer)?.status,
            200
        );
    }
    let lookup = cidr_local(
        &mut service,
        "POST",
        "auth/token/lookup",
        &admin,
        json!({"token":raw}),
        other,
    )?;
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["bound_cidrs"], json!(["127.0.0.1"]));
    Ok(())
}
