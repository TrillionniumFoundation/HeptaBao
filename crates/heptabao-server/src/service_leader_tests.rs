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
fn health_get_and_head_never_consume_tokens_or_append_audit() -> TestResult {
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
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let sequence = service.audit_sequence;
    let audit = fs::read(root.path.join("audit.jsonl"))?;
    for method in ["GET", "HEAD"] {
        for credential in ["", "invalid", root_token.as_str(), token.as_str()] {
            let response = call(&mut service, method, "sys/health", credential, json!({}));
            assert_eq!(response.status, 200);
            assert!(response.consistency_index.is_none());
            assert_eq!(response.body["initialized"], true);
            assert_eq!(response.body["sealed"], false);
        }
    }
    assert_eq!(
        service.audit_sequence, sequence,
        "health appended audit events"
    );
    assert!(fs::read(root.path.join("audit.jsonl"))? == audit);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    let lookup = call(
        &mut service,
        "POST",
        "auth/token/lookup",
        &root_token,
        json!({"token": token}),
    );
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["num_uses"], 2);
    assert_eq!(service.audit_sequence, sequence + 2);
    assert_eq!(
        call(&mut service, "GET", "sys/mounts", &root_token, json!({})).status,
        200
    );
    assert_eq!(service.audit_sequence, sequence + 4);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/private",
            "invalid",
            json!({})
        )
        .status,
        403
    );
    assert_eq!(service.audit_sequence, sequence + 6);
    Ok(())
}

#[test]
fn health_diagnostic_preserves_lifecycle_validation_and_audit_fences() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    for (body, expected) in [(json!({}), 501), (json!({"uninitcode": 204}), 204)] {
        let sequence = service.audit_sequence;
        let response = call(&mut service, "GET", "sys/health", "invalid", body);
        assert_eq!(response.status, expected);
        assert_eq!(response.body["initialized"], false);
        assert_eq!(service.audit_sequence, sequence);
    }
    let (_, token) = bootstrap(&mut service)?;
    let audit = fs::read(root.path.join("audit.jsonl"))?;
    for (namespace, body, wrap, expected) in [
        ("", json!({"activecode": 201}), None, 201),
        ("", json!({"standbyok": "true"}), None, 400),
        ("", json!({"perfstandbyok": 1}), None, 400),
        ("", json!({"activecode": 99}), None, 400),
        ("", json!({"activecode": "201"}), None, 400),
        ("../invalid", json!({}), None, 400),
        ("absent", json!({}), None, 404),
        ("", json!({}), Some(0), 200),
        ("", json!({}), Some(60), 200),
        ("", json!({}), Some(32 * 24 * 3600 + 1), 200),
    ] {
        for method in ["GET", "HEAD"] {
            let response = service.begin_at_mode(RequestDispatch {
                method,
                path: "sys/health",
                namespace,
                token: "invalid",
                body: body.clone(),
                now: 100,
                allow_forward: true,
                enforce_namespace: true,
                wrap_ttl_seconds: wrap,
                origin_peer: None,
                client_certificates: None,
            });
            assert!(
                matches!(response, RequestExecution::Complete(Response { status, consistency_index: None, .. }) if status == expected)
            );
        }
    }
    assert!(fs::read(root.path.join("audit.jsonl"))? == audit);
    service.recovery_required = true;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "sys/health",
            "",
            json!({"activecode": 201})
        )
        .status,
        503
    );
    service.recovery_required = false;
    // A real failed write to the mandatory device establishes its persistent
    // fence. Diagnostics report failure without trying that device again.
    let writable_audit = std::mem::replace(
        &mut service.audit,
        fs::File::open(root.path.join("audit.jsonl"))?,
    );
    assert_eq!(
        call(&mut service, "GET", "sys/mounts", &token, json!({})).status,
        503
    );
    assert!(service.audit_failed);
    assert_eq!(
        call(&mut service, "HEAD", "sys/health", "", json!({})).status,
        503
    );
    assert!(service.audit_failed);
    assert!(fs::read(root.path.join("audit.jsonl"))? == audit);
    // Restore this test's device to exercise the subsequent sealed lifecycle.
    // Production does not repair the fence by issuing a diagnostic request.
    service.audit = writable_audit;
    service.audit_failed = false;
    assert_eq!(
        call(&mut service, "POST", "sys/seal", &token, json!({})).status,
        204
    );
    let sealed_audit = fs::read(root.path.join("audit.jsonl"))?;
    for method in ["GET", "HEAD"] {
        let response = call(
            &mut service,
            method,
            "sys/health",
            "",
            json!({"sealedcode": 499}),
        );
        assert_eq!(response.status, 499);
        assert_eq!(response.body["sealed"], true);
    }
    assert!(fs::read(root.path.join("audit.jsonl"))? == sealed_audit);
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
    assert_eq!(response.body.get("is_self"), Some(&json!(false)));
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
        RequestExecution::Complete(Response {
            consistency_index: None,
            status: 503,
            ..
        })
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

#[test]
fn health_quorum_loss_replies_within_probe_budget_without_admitting_reads() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster =
        crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/probe-retained",
            &token,
            json!({"data":{"value":"synthetic-retained"}})
        )
        .status,
        200
    );
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let audit = fs::read(root.path.join("audit.jsonl"))?;
    cluster.isolate_all_peers(true);
    let started = std::time::Instant::now();
    let result = service.begin_request_before(
        ServiceRequest::new("HEAD", "sys/health", "", "", json!({})),
        started + Duration::from_secs(12),
        false,
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "health consumed the business request budget instead of its probe budget"
    );
    let RequestExecution::Complete(response) = result else {
        return Err("unexpected external health effect".into());
    };
    assert_eq!(response.status, 503);
    assert_eq!(response.body["ha_active"], false);
    assert_eq!(response.body["ha_application_ready"], false);
    assert!(cluster.blocked_probes() > 0);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert!(crate::request_deadline::current().is_none());
    let earlier = std::time::Instant::now();
    let result = service.begin_request_before(
        ServiceRequest::new("GET", "sys/health", "", "", json!({})),
        earlier + Duration::from_millis(30),
        false,
    );
    assert!(earlier.elapsed() < Duration::from_millis(500));
    assert!(matches!(
        result,
        RequestExecution::Complete(Response {
            consistency_index: None,
            status: 503,
            ..
        })
    ));
    assert!(crate::request_deadline::current().is_none());
    assert!(fs::read(root.path.join("audit.jsonl"))? == audit);
    cluster.isolate_all_peers(false);
    assert_eq!(
        call(&mut service, "GET", "sys/health", "", json!({})).status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/probe-retained",
            &token,
            json!({})
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn idle_quorum_observation_releases_product_writer_within_maintenance_budget() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster =
        crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/idle-retained",
            &token,
            json!({"data":{"value":"synthetic-idle"}})
        )
        .status,
        200
    );
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let service = Arc::new(Mutex::new(service));
    cluster.isolate_all_peers(true);
    let worker =
        crate::service::lifecycle::start_lifecycle_worker(&service, Duration::from_secs(1))?
            .ok_or("idle worker missing")?;
    let start = std::time::Instant::now();
    let became_busy = loop {
        if service.try_lock().is_err() {
            break true;
        }
        if start.elapsed() >= Duration::from_secs(5) {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let acquired = crate::request_deadline::lock_until(
        &service,
        std::time::Instant::now() + Duration::from_secs(2),
    )
    .is_ok();
    cluster.isolate_all_peers(false);
    drop(worker);
    assert!(became_busy, "the actual idle writer pass must have run");
    assert!(
        acquired,
        "idle quorum probes monopolized the product writer"
    );
    let service = service.lock().map_err(|_| "service lock")?;
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    Ok(())
}

#[test]
fn cluster_address_uses_explicit_current_leader_and_stays_passive_across_handoff() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster =
        crate::ha::snapshot_test_support::Cluster::new(&root.path.join("raft"), &cluster_id)?;
    for node in 1..=3 {
        cluster.configure_api_address(node, &format!("https://api-{node}.example:8200"))?;
        cluster
            .configure_cluster_address(node, &format!("https://cluster-{node}.example:8201/"))?;
    }
    let before = service
        .current_state_identity()
        .map_err(|_| "state identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let audit = fs::read(root.path.join("audit.jsonl"))?;
    for (index, process) in cluster.processes.iter().enumerate() {
        service.ha = Some(Arc::clone(process));
        let response = diagnostic(&mut service, "GET", "invalid");
        assert_eq!(response.status, 200);
        assert_eq!(response.body["is_self"], index == 0);
        assert_eq!(
            response.body["leader_address"],
            "https://api-1.example:8200"
        );
        assert_eq!(
            response.body["leader_cluster_address"],
            "https://cluster-1.example:8201"
        );
        assert!(response.body.get("active_time").is_none());
    }
    let successor = cluster.processes[0].lock().map_err(|_| "HA")?.step_down()?;
    // The old leader's own passive view must use its actual successor; the
    // diagnostic does not force a follower catch-up or resolve via ReadIndex.
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    let response = diagnostic(&mut service, "GET", "");
    assert_eq!(response.status, 200);
    assert_eq!(response.body["is_self"], false);
    assert_eq!(
        response.body["leader_address"],
        format!("https://api-{successor}.example:8200")
    );
    assert_eq!(
        response.body["leader_cluster_address"],
        format!("https://cluster-{successor}.example:8201")
    );
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
    assert_eq!(fs::read(root.path.join("audit.jsonl"))?, audit);
    assert!(service.ha_read_cache.is_none());
    // No origin is revealed while sealed, even when the same Raft term survives.
    service.ha = None;
    assert_eq!(
        call(&mut service, "POST", "sys/seal", &token, json!({})).status,
        204
    );
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    assert_eq!(
        diagnostic(&mut service, "GET", "").body,
        json!({"errors": ["Vault is sealed"]})
    );
    Ok(())
}

#[test]
fn configured_cluster_address_is_not_returned_without_an_observed_leader() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    bootstrap(&mut service)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster = crate::ha::snapshot_test_support::Cluster::uninitialized(
        &root.path.join("raft"),
        &cluster_id,
    )?;
    cluster.configure_api_address(1, "https://api.example:8200")?;
    cluster.configure_cluster_address(1, "https://cluster.example:8201")?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    let response = diagnostic(&mut service, "GET", "");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, json!({"ha_enabled": true, "is_self": false}));
    Ok(())
}
