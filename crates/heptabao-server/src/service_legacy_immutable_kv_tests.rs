//! Actual three-node Raft/state materialization, no mocked completion.
use super::*;
use crate::service::tests::{Root, bootstrap_legacy_auth_fixture as bootstrap, call};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn no_forward271_keeps_actual_legacy_local_readindex_get() -> TestResult {
    let root = Root::new();
    let (service, cluster, token) = prepare(&root)?;
    let before = Zeroizing::new(serde_json::to_vec(service.state.as_ref().ok_or("state")?)?);
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let identity = service
        .current_state_identity()
        .map_err(|_| "actual local identity")?;
    let audits = service.audit_sequence;
    let dispatches = service.kv_read_only_dispatches;
    let service = Arc::new(Mutex::new(service));
    let raw = crate::http::no_forward_tests::request(
        "GET",
        "/v1/secret/data/legacy",
        &token,
        "X-Vault-No-Request-Forwarding: 1\r\n",
        &json!({}),
    );
    let response = crate::http::no_forward_tests::wire(
        &service,
        &raw,
        &[0x71; 16],
        Instant::now() + Duration::from_secs(10),
    )?;
    assert_eq!(response.status, 200);
    assert!(response.header("Location").is_empty());
    assert_eq!(
        response.json()?["data"]["data"]["value"],
        "actual-committed"
    );
    {
        let writer = service.lock().map_err(|_| "actual Service lock")?;
        assert!(
            writer
                .current_state_identity()
                .map_err(|_| "actual local identity")?
                == identity
        );
        assert_eq!(
            writer.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert!(
            serde_json::to_vec(writer.state.as_ref().ok_or("state")?)?.as_slice()
                == before.as_slice()
        );
        assert_eq!(writer.audit_sequence, audits + 2);
        assert_eq!(writer.kv_read_only_dispatches, dispatches + 1);
        assert!(writer.pending_forward_delivery.is_none());
        assert!(writer.pending_ordinary_kv_authority.is_none());
    }
    drop(service);
    drop(cluster);
    Ok(())
}

#[test]
fn legacy_replica_kv_expiration143_eligibility_tracks_real_policy_publication() -> TestResult {
    fn precise(
        service: &mut Service,
        seconds: u64,
        method: &str,
        path: &str,
        token: &str,
        body: Value,
    ) -> TestResult<Response> {
        let clock = RequestClock::anchored(Duration::ZERO, Instant::now())
            .map_err(|_| "actual request clock")?
            .with_timestamp_floor(Timestamp::whole(seconds).map_err(|_| "fixture epoch")?);
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(10),
        );
        let _explicit = external_pki::PublicationClockScope::explicit();
        Ok(service.handle_request_clock(
            ServiceRequest::new(method, path, "", token, body),
            seconds,
            true,
            Some(clock),
        ))
    }

    let root = Root::new();
    let (mut service, cluster, admin) = prepare(&root)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let source = r#"path "secret/data/legacy" { capabilities=["read"] }"#;
    let policy_path = "sys/policies/acl/legacy-expiration143";
    assert_eq!(
        service
            .handle_at(
                "POST",
                policy_path,
                "",
                &admin,
                json!({"policy":source}),
                now
            )
            .status,
        204
    );
    let issued = service.handle_at(
        "POST",
        "auth/token/create",
        "",
        &admin,
        json!({"policies":["legacy-expiration143"],"ttl":3600,"no_default_policy":true}),
        now,
    );
    assert_eq!(issued.status, 200, "{}", issued.body);
    let actor = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("actual legacy actor")?
        .to_owned();
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    service
        .sync_from_ha()
        .map_err(|_| "actual untimed follower")?;
    assert!(
        service
            .state
            .as_ref()
            .ok_or("state")?
            .auth
            .legacy_immutable_token_is_non_consuming(&actor)
    );
    assert_eq!(native(&mut service, "GET", &actor, json!({})).status, 200);
    let dispatches = service.kv_read_only_dispatches;

    service.ha = Some(Arc::clone(&cluster.processes[0]));
    assert_eq!(
        precise(
            &mut service,
            now,
            "POST",
            policy_path,
            &admin,
            json!({"policy":source,"expiration":now+60,"cas":1,"cas_required":true})
        )?
        .status,
        204
    );
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    service
        .sync_from_ha()
        .map_err(|_| "actual timed follower")?;
    let state = service.state.as_ref().ok_or("timed follower state")?;
    assert!(!state.has_token_api_precision_state());
    assert!(state.auth.legacy_immutable_token_is_non_consuming(&actor));
    assert!(state.auth.has_policy_expiration_state());
    let before = serde_json::to_vec(state)?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    // The historical replica has no completed-forward authority. Timed
    // policies must use that existing gate, including while still future.
    let refused = native(&mut service, "GET", &actor, json!({}));
    assert_eq!(refused.status, 503, "{}", refused.body);
    assert!(refused.body.get("data").is_none());
    assert_eq!(service.kv_read_only_dispatches, dispatches);
    assert!(service.pending_ordinary_kv_authority.is_none());
    assert!(service.pending_forward_delivery.is_none());
    assert_eq!(
        serde_json::to_vec(service.state.as_ref().ok_or("follower state")?)?,
        before
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );

    // The actual leader performs the independent deletion before denial.
    // Its replicated absence lets the old read route re-evaluate the actor,
    // which remains valid but no longer has a granting policy.
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    assert_eq!(
        precise(
            &mut service,
            now + 61,
            "GET",
            "secret/data/legacy",
            &actor,
            json!({})
        )?
        .status,
        403
    );
    let listed = precise(
        &mut service,
        now + 61,
        "LIST",
        "sys/policies/acl",
        &admin,
        json!({}),
    )?;
    assert_eq!(listed.status, 200);
    assert!(
        !listed.body["data"]["keys"]
            .as_array()
            .ok_or("policy keys")?
            .contains(&json!("legacy-expiration143"))
    );
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    service
        .sync_from_ha()
        .map_err(|_| "actual retired follower")?;
    assert!(
        !service
            .state
            .as_ref()
            .ok_or("retired state")?
            .auth
            .has_policy_expiration_state()
    );
    assert_eq!(native(&mut service, "GET", &actor, json!({})).status, 403);
    drop(service);
    drop(cluster);
    Ok(())
}

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
