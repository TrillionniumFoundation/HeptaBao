use super::*;
use crate::service::tests::{Root, bootstrap, call};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn diagnostic(service: &mut Service, method: &str, token: &str) -> Response {
    // Exercise the same dispatch as HTTP, including ignored namespace, body,
    // wrapping and invalid token; no synthetic leader/role state is installed.
    match service.begin_at_mode(RequestDispatch {
        method,
        path: "sys/leader",
        namespace: "not-a-live-namespace",
        token,
        body: json!({"ignored": true}),
        now: 100,
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: Some(60),
        origin_peer: None,
        client_certificates: None,
    }) {
        RequestExecution::Complete(response) => response,
        RequestExecution::External(_) => Response::error(599, "unexpected external observation"),
    }
}

#[test]
fn leader_non_ha_is_anonymous_in_all_lifecycle_states_and_get_only() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let audit = fs::read(root.path.join("audit.jsonl"))?;
    assert_eq!(
        diagnostic(&mut service, "GET", "").body,
        json!({"ha_enabled": false})
    );
    assert_eq!(fs::read(root.path.join("audit.jsonl"))?, audit);
    let initialized = call(
        &mut service,
        "POST",
        "sys/init",
        "",
        json!({"secret_shares": 1, "secret_threshold": 1}),
    );
    assert_eq!(initialized.status, 200);
    let key = initialized.body["keys_base64"][0]
        .as_str()
        .ok_or("key")?
        .to_owned();
    let token = initialized.body["root_token"]
        .as_str()
        .ok_or("token")?
        .to_owned();
    assert_eq!(
        diagnostic(&mut service, "GET", "invalid").body,
        json!({"ha_enabled": false})
    );
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key": key})).status,
        200
    );
    assert_eq!(
        diagnostic(&mut service, "GET", "").body,
        json!({"ha_enabled": false})
    );
    for method in ["HEAD", "POST", "PUT", "DELETE", "LIST"] {
        let response = diagnostic(&mut service, method, &token);
        assert_eq!(response.status, 405);
        assert_eq!(response.body, json!({"errors": []}));
    }
    assert_eq!(
        call(&mut service, "POST", "sys/seal", &token, json!({})).status,
        204
    );
    assert_eq!(
        diagnostic(&mut service, "GET", "").body,
        json!({"ha_enabled": false})
    );
    Ok(())
}

#[test]
fn leader_never_consumes_limited_tokens_or_mutates_audit_and_application() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, root_token) = bootstrap(&mut service)?;
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &root_token,
        json!({"policies": ["default"], "num_uses": 2, "ttl": 600}),
    );
    assert_eq!(issued.status, 200);
    let token = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned();
    let before = service.durable.as_ref().ok_or("durable")?.generation();
    let audit = fs::read(root.path.join("audit.jsonl"))?;
    for credential in ["", "invalid", token.as_str(), token.as_str()] {
        assert_eq!(diagnostic(&mut service, "GET", credential).status, 200);
    }
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        before
    );
    assert_eq!(fs::read(root.path.join("audit.jsonl"))?, audit);
    let lookup = call(
        &mut service,
        "POST",
        "auth/token/lookup",
        &root_token,
        json!({"token": token}),
    );
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["num_uses"], 2);
    // Ordinary protected routes continue to authenticate and authorize.
    assert_eq!(
        call(&mut service, "GET", "secret/data/private", "", json!({})).status,
        403
    );
    Ok(())
}

#[test]
fn standby_leader_observation_is_local_and_does_not_admit_read_authority() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster =
        crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &cluster_id)?;
    let follower = Arc::clone(&cluster.processes[1]);
    service.ha = Some(Arc::clone(&follower));
    let observed = follower.lock().map_err(|_| "HA mutex")?.leader_status()?;
    assert_ne!(observed.leader, Some(observed.local_id));
    let before = service
        .current_state_identity()
        .map_err(|_| "state identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let response = diagnostic(&mut service, "GET", "invalid");
    assert_eq!(response.status, 200);
    assert_eq!(response.body["ha_enabled"], true);
    assert!(response.body.get("is_self").is_none());
    assert!(response.body.get("leader_address").is_none());
    assert!(response.body.get("active_time").is_none());
    assert!(response.body.get("leader_cluster_address").is_none());
    for (name, minimum) in [
        ("raft_committed_index", observed.committed_index),
        ("raft_applied_index", observed.applied_index),
    ] {
        if let Some(index) = minimum.filter(|index| *index != 0) {
            assert!(
                response.body[name]
                    .as_u64()
                    .is_some_and(|actual| actual >= index)
            );
        }
    }
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "state identity")?,
        before
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert!(service.ha_read_cache.is_none());
    // This fixture has no network forward listener. A regular standby request
    // still follows the protected forwarding path and is unavailable.
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/private",
            &token,
            json!({})
        )
        .status,
        503
    );
    Ok(())
}

#[test]
fn ha_sealed_status_and_lost_quorum_diagnosis_do_not_replace_read_index() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster =
        crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/protected",
            &token,
            json!({"data": {"value": "retained"}})
        )
        .status,
        200
    );
    cluster.block_quorum(true);
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    assert_eq!(diagnostic(&mut service, "GET", "").status, 200);
    let deadline = std::time::Instant::now() + Duration::from_millis(100);
    let result = service.begin_request_before(
        ServiceRequest::new("GET", "secret/data/protected", "", &token, json!({})),
        deadline,
        false,
    );
    assert!(matches!(
        result,
        RequestExecution::Complete(Response { status: 503, .. })
    ));
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    cluster.block_quorum(false);
    assert_eq!(
        call(&mut service, "POST", "sys/seal", &token, json!({})).status,
        204
    );
    let sealed = diagnostic(&mut service, "GET", "");
    assert_eq!(sealed.status, 503);
    assert_eq!(sealed.body, json!({"errors": ["Vault is sealed"]}));
    assert_eq!(diagnostic(&mut service, "HEAD", "").status, 405);
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key": key})).status,
        200
    );
    assert_eq!(diagnostic(&mut service, "GET", "").status, 200);
    let fresh = Root::new();
    let mut uninitialized = fresh.service()?;
    uninitialized.ha = Some(Arc::clone(&cluster.processes[0]));
    assert!(!uninitialized.initialized());
    assert_eq!(diagnostic(&mut uninitialized, "GET", "").status, 503);
    Ok(())
}
