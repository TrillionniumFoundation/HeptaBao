//! Actual three-node Raft/state materialization, no mocked completion.
use super::*;
use crate::service::tests::{Root, bootstrap, call};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn native(service: &mut Service, method: &str, token: &str, body: Value) -> Response {
    let execution = service.begin_request_before(
        ServiceRequest {
            method,
            path: "secret/data/legacy",
            namespace: "",
            token,
            body,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now() + Duration::from_secs(10),
        false,
    );
    service.finish_synchronous_request(execution)
}

type Fixture = (Service, crate::ha::snapshot_test_support::Cluster, String);
fn prepare(root: &Root) -> TestResult<Fixture> {
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "secret/data/legacy",
            &token,
            json!({"data":{"value":"actual-committed"}})
        )
        .status,
        200
    );
    let cluster = crate::ha::snapshot_test_support::Cluster::new(
        &root.path.join("raft"),
        &service.state.as_ref().ok_or("state")?.cluster_id,
    )?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    service.sync_from_ha().map_err(|_| "leader publication")?;
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    service
        .sync_from_ha()
        .map_err(|_| "follower materialization")?;
    cluster.processes[1]
        .lock()
        .map_err(|_| "HA")?
        .set_legacy_peer_v1_for_test(true);
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .has_token_api_precision_state()
    );
    Ok((service, cluster, token))
}

#[test]
fn legacy_replica_kv_real_read_keeps_original_state_and_never_needs_forward_handler() -> TestResult
{
    let root = Root::new();
    let (mut service, cluster, token) = prepare(&root)?;
    let state = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let audits = service.audit_sequence;
    let response = native(&mut service, "GET", &token, json!({}));
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.body["data"]["data"]["value"], "actual-committed");
    assert!(service.pending_forward_delivery.is_none());
    assert!(service.pending_ordinary_kv_authority.is_none());
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?,
        state
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(service.audit_sequence, audits + 2);
    assert_eq!(service.kv_read_only_dispatches, 1);
    drop(service);
    drop(cluster);
    Ok(())
}

#[test]
fn legacy_replica_kv_real_quorum_deadline_and_local_damage_are_not_completion() -> TestResult {
    let root = Root::new();
    let (mut service, cluster, token) = prepare(&root)?;
    {
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(10),
        );
        let proof = LegacyReplicaRead::capture(&mut service, Arc::clone(&cluster.processes[1]))
            .map_err(|_| "original replica proof")?;
        assert!(proof.check(&mut service).is_ok());
        let old = service.unseal_nonce.clone();
        service.rotate_unseal_nonce()?;
        assert!(proof.check(&mut service).is_err());
        service.unseal_nonce = old;
        assert!(proof.check(&mut service).is_ok());
        let mut damaged = service.state.clone().ok_or("state")?;
        damaged.cluster_id.push('x');
        let old = service.state.replace(damaged);
        assert!(proof.check(&mut service).is_err());
        service.state = old;
        assert!(proof.check(&mut service).is_ok());
        cluster.isolate_all_peers(true);
        {
            let _bounded = crate::request_deadline::RequestDeadlineScope::enter(
                Instant::now() + Duration::from_millis(250),
            );
            assert!(proof.check(&mut service).is_err());
        }
        cluster.isolate_all_peers(false);
        let _expired = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() - Duration::from_millis(1),
        );
        assert!(proof.check(&mut service).is_err());
    }
    assert_eq!(native(&mut service, "GET", &token, json!({})).status, 200);
    drop(service);
    drop(cluster);
    Ok(())
}

#[test]
fn legacy_replica_kv_finite_wrapped_mutation_and_modern_precision_keep_forward_rejection()
-> TestResult {
    let root = Root::new();
    let (mut service, cluster, token) = prepare(&root)?;
    let before = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    let failed = native(
        &mut service,
        "PUT",
        &token,
        json!({"data":{"value":"forbidden"}}),
    );
    assert_eq!(failed.status, 503);
    assert!(failed.body["data"].is_null());
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?,
        before
    );
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    let issued = service.handle_at(
        "POST",
        "auth/token/create",
        "",
        &token,
        json!({"ttl":"1h","num_uses":2,"policies":["root"],"no_default_policy":true}),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    );
    assert_eq!(issued.status, 200, "{}", issued.body);
    let finite = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("finite")?;
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    service.sync_from_ha().map_err(|_| "finite follower")?;
    let before = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    assert_eq!(native(&mut service, "GET", finite, json!({})).status, 503);
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?,
        before
    );
    let execution = service.begin_request_before(
        ServiceRequest {
            method: "GET",
            path: "secret/data/legacy",
            namespace: "",
            token: &token,
            body: json!({}),
            wrap_ttl_seconds: Some(30),
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now() + Duration::from_secs(10),
        false,
    );
    assert_eq!(service.finish_synchronous_request(execution).status, 503);
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    let execution = service.begin_request_before(
        ServiceRequest {
            method: "POST",
            path: "auth/token/create",
            namespace: "",
            token: &token,
            body: json!({"ttl":"1h","policies":["root"],"no_default_policy":true}),
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        Instant::now() + Duration::from_secs(10),
        false,
    );
    assert_eq!(service.finish_synchronous_request(execution).status, 200);
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    service.sync_from_ha().map_err(|_| "precision follower")?;
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .has_token_api_precision_state()
    );
    let response = native(&mut service, "GET", &token, json!({}));
    assert_eq!(response.status, 503);
    assert!(response.body["data"].is_null());
    drop(service);
    drop(cluster);
    Ok(())
}

#[test]
fn legacy_replica_kv_original_actor_rechecks_current_acl_after_real_publication() -> TestResult {
    let root = Root::new();
    let (mut service, cluster, token) = prepare(&root)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/legacy-read",
            &token,
            json!({"policy":"path \"secret/data/legacy\" {capabilities=[\"read\"]}"})
        )
        .status,
        204
    );
    let issued = service.handle_at(
        "POST",
        "auth/token/create",
        "",
        &token,
        json!({"ttl":"1h","policies":["legacy-read"],"no_default_policy":true}),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    );
    assert_eq!(issued.status, 200, "{}", issued.body);
    let actor = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("actor")?;
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    service.sync_from_ha().map_err(|_| "actor follower")?;
    assert_eq!(native(&mut service, "GET", actor, json!({})).status, 200);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let deadline = Instant::now() + Duration::from_secs(10);
    let _original_deadline = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    let original_clock = RequestClock::anchored(
        SystemTime::now().duration_since(UNIX_EPOCH)?,
        Instant::now(),
    )?;
    let mut response = service.handle_inner(RequestView {
        method: "GET",
        path: "secret/data/legacy",
        namespace: "",
        token: actor,
        body: &json!({}),
        now,
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
        admission_started: Instant::now(),
        token_clock: Some(original_clock),
    });
    assert_eq!(response.status, 200);
    let authority = service
        .pending_ordinary_kv_authority
        .take()
        .ok_or("held original authority")?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/policies/acl/legacy-read",
            &token,
            json!({"policy":"path \"secret/data/legacy\" {capabilities=[\"deny\"]}"})
        )
        .status,
        204
    );
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    response = service.audit_completed_response(
        "legacy-read-original",
        now,
        Some(original_clock),
        response,
    );
    let withheld =
        service.complete_ordinary_kv_delivery(authority, response, "legacy-read-original");
    assert_eq!(withheld.status, 403, "{}", withheld.body);
    assert!(withheld.body["data"].is_null());
    drop(service);
    drop(cluster);
    Ok(())
}

#[test]
fn legacy_replica_kv_original_whole_expiry_withholds_after_actual_mandatory_audit() -> TestResult {
    let root = Root::new();
    let (mut service, cluster, token) = prepare(&root)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    let issued = service.handle_at(
        "POST",
        "auth/token/create",
        "",
        &token,
        json!({"ttl":"3s","policies":["root"],"no_default_policy":true}),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    );
    assert_eq!(issued.status, 200, "{}", issued.body);
    let actor = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("actor")?;
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    service.sync_from_ha().map_err(|_| "actor follower")?;
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .has_token_api_precision_state()
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let _original_deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(10),
    );
    let original_clock = RequestClock::anchored(
        SystemTime::now().duration_since(UNIX_EPOCH)?,
        Instant::now(),
    )?;
    let response = service.handle_inner(RequestView {
        method: "GET",
        path: "secret/data/legacy",
        namespace: "",
        token: actor,
        body: &json!({}),
        now,
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
        admission_started: Instant::now(),
        token_clock: Some(original_clock),
    });
    assert_eq!(response.status, 200, "{}", response.body);
    let authority = service
        .pending_ordinary_kv_authority
        .take()
        .ok_or("original authority")?;
    let before = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let response = service.audit_completed_response_with_receipt(
        "legacy-read-expired-original",
        now,
        Some(original_clock),
        response,
        || std::thread::sleep(Duration::from_millis(3100)),
    );
    let withheld =
        service.complete_ordinary_kv_delivery(authority, response, "legacy-read-expired-original");
    assert_eq!(withheld.status, 403, "{}", withheld.body);
    assert!(withheld.body["data"].is_null() && withheld.response_headers.is_empty());
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?,
        before
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert!(service.pending_forward_delivery.is_none());
    drop(service);
    drop(cluster);
    Ok(())
}

#[test]
fn legacy_replica_kv_original_revoked_actor_and_real_provider_keep_no_grant() -> TestResult {
    let root = Root::new();
    let (mut service, cluster, token) = prepare(&root)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    let issued = service.handle_at(
        "POST",
        "auth/token/create",
        "",
        &token,
        json!({"ttl":"1h","policies":["root"],"no_default_policy":true}),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    );
    assert_eq!(issued.status, 200, "{}", issued.body);
    let actor = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("actor")?;
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    service.sync_from_ha().map_err(|_| "actor follower")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let _original_deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(10),
    );
    let original_clock = RequestClock::anchored(
        SystemTime::now().duration_since(UNIX_EPOCH)?,
        Instant::now(),
    )?;
    let response = service.handle_inner(RequestView {
        method: "GET",
        path: "secret/data/legacy",
        namespace: "",
        token: actor,
        body: &json!({}),
        now,
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
        admission_started: Instant::now(),
        token_clock: Some(original_clock),
    });
    assert_eq!(response.status, 200, "{}", response.body);
    let authority = service
        .pending_ordinary_kv_authority
        .take()
        .ok_or("original authority")?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    let revoked = service.handle_at(
        "POST",
        "auth/token/revoke",
        "",
        &token,
        json!({"token":actor}),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    );
    assert_eq!(revoked.status, 204, "{}", revoked.body);
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    let response = service.audit_completed_response(
        "legacy-read-revoked-original",
        now,
        Some(original_clock),
        response,
    );
    let withheld =
        service.complete_ordinary_kv_delivery(authority, response, "legacy-read-revoked-original");
    assert_eq!(withheld.status, 403, "{}", withheld.body);
    assert!(withheld.body["data"].is_null() && withheld.response_headers.is_empty());
    assert!(service.pending_forward_delivery.is_none());
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    let policy = service.handle_at(
        "PUT",
        "sys/policies/acl/legacy-provider-read",
        "",
        &token,
        json!({"policy":"path \"secret/data/legacy\" {capabilities=[\"read\"]}"}),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    );
    assert_eq!(policy.status, 204, "{}", policy.body);
    let configured = service.handle_at(
        "POST",
        "auth/userpass/users/legacy-provider",
        "",
        &token,
        json!({"password":"actual legacy fixture password","token_policies":["legacy-provider-read"]}),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    );
    assert_eq!(configured.status, 204, "{}", configured.body);
    let login = service.handle_at(
        "POST",
        "auth/userpass/login/legacy-provider",
        "",
        "",
        json!({"password":"actual legacy fixture password"}),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    );
    assert_eq!(login.status, 200, "{}", login.body);
    let provider = login.body["auth"]["client_token"]
        .as_str()
        .ok_or("provider")?;
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    service.sync_from_ha().map_err(|_| "provider follower")?;
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("state")?
            .has_token_api_precision_state()
    );
    let before = serde_json::to_vec(service.state.as_ref().ok_or("state")?)?;
    let response = native(&mut service, "GET", provider, json!({}));
    assert_eq!(response.status, 503, "{}", response.body);
    assert!(response.body["data"].is_null());
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("state")?)?,
        before
    );
    assert!(
        service.pending_forward_delivery.is_none()
            && service.pending_ordinary_kv_authority.is_none()
    );
    drop(service);
    drop(cluster);
    Ok(())
}
