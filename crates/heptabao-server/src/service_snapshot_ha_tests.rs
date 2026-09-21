//! Real Service + three durable OpenRaft nodes. The controlled RPC loopback
//! tests consensus/authority gates, not TLS, HTTP wall time or separate hosts.
use super::super::tests::{Root, bootstrap, call};
use super::*;
use crate::ha::snapshot_test_support::Cluster;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn stage(
    service: &mut Service,
    method: &str,
    path: &str,
    token: &str,
    deadline: Instant,
) -> RequestExecution {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    service.native_snapshot_transport = true;
    service.native_snapshot_clock = Some((Instant::now(), Duration::from_secs(100)));
    let result = service.begin_at_mode(RequestDispatch {
        method,
        path,
        namespace: "",
        token,
        body: json!({}),
        now: 100,
        allow_forward: true,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: None,
        client_certificates: None,
    });
    service.native_snapshot_transport = false;
    service.native_snapshot_clock = None;
    result
}
fn pending(
    service: &mut Service,
    token: &str,
    method: &str,
    deadline: Instant,
) -> TestResult<Box<PendingExternalRequest>> {
    match stage(
        service,
        method,
        "sys/storage/raft/snapshot",
        token,
        deadline,
    ) {
        RequestExecution::External(plan) => Ok(plan),
        RequestExecution::Complete(response) => {
            Err(format!("snapshot admission {}", response.status).into())
        }
    }
}
fn write(service: &mut Service, token: &str, value: &str) {
    assert_eq!(
        call(
            service,
            "PUT",
            "secret/data/ha-snapshot",
            token,
            json!({"data":{"value":value}})
        )
        .status,
        200
    );
}
fn assert_export_matches_committed_root(
    service: &mut Service,
    token: &str,
    method: &str,
) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut request = pending(service, token, method, deadline)?;
    let ExternalEffectPlan::SnapshotTransfer(ref plan) = request.effect else {
        return Err("plan kind".into());
    };
    let lease = Arc::clone(&plan.lease);
    let (result, file) = request.execute_snapshot_transfer(&mut io::empty());
    assert_eq!(
        service.finish_external_request(*request, result).status,
        200
    );
    let mut imported = snapshot_archive::import(file.ok_or("export file")?, &lease, deadline)?;
    assert!(imported.metadata.seal_identity().is_some());
    let durable = service.durable.as_ref().ok_or("durable")?;
    let length = imported.state.len();
    let prepared = durable.prepare_restore_from_reader(&mut imported.state, length)?;
    let current = durable.get("system", "state")?.ok_or("current root")?;
    assert_eq!(
        prepared.get("system", "state")?.ok_or("archive root")?,
        current.expose()
    );
    assert_eq!(
        prepared.metadata().generation,
        imported.metadata.generation()
    );
    Ok(())
}

#[test]
fn native_ha_save_requires_live_leader_read_authority_and_never_json_forwards() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    write(&mut service, &token, "initial");
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster = Cluster::new(&root.path.join("raft"), &cluster_id)?;
    let first = Arc::clone(&cluster.processes[0]);
    service.ha = Some(Arc::clone(&first));
    // Admission anchors through the preexisting HA path, then both GET and
    // direct Service HEAD capture the actual committed encrypted root.
    assert_export_matches_committed_root(&mut service, &token, "GET")?;
    assert_export_matches_committed_root(&mut service, &token, "HEAD")?;
    let deadline = || Instant::now() + Duration::from_secs(15);
    for path in [
        "sys/storage/raft/snapshot",
        "sys/storage/raft/snapshot-force",
    ] {
        assert!(matches!(
            stage(&mut service, "POST", path, &token, deadline()),
            RequestExecution::External(_)
        ));
    }

    // A detached archive remains a valid past read, but this initial profile
    // deliberately rejects intervening application writes at finalization.
    let mut request = pending(&mut service, &token, "GET", deadline())?;
    let (result, file) = request.execute_snapshot_transfer(&mut io::empty());
    write(&mut service, &token, "newer");
    assert_eq!(
        service.finish_external_request(*request, result).status,
        409
    );
    drop(file);
    assert_export_matches_committed_root(&mut service, &token, "GET")?;

    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &token,
        json!({"policies":["root"],"ttl":300}),
    );
    assert_eq!(issued.status, 200);
    let actor = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("actor")?
        .to_owned();
    let mut request = pending(&mut service, &actor, "GET", deadline())?;
    let (result, file) = request.execute_snapshot_transfer(&mut io::empty());
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/revoke",
            &token,
            json!({"token":actor})
        )
        .status,
        204
    );
    assert_eq!(
        service.finish_external_request(*request, result).status,
        409
    );
    drop(file);
    let mut request = pending(&mut service, &token, "GET", deadline())?;
    let (result, file) = request.execute_snapshot_transfer(&mut io::empty());
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &token, json!({})).status,
        204
    );
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(
        service.finish_external_request(*request, result).status,
        409
    );
    drop(file);
    assert_export_matches_committed_root(&mut service, &token, "GET")?;

    // The cached/readied leader cannot release an archive after losing quorum.
    let original_deadline = Instant::now() + Duration::from_millis(500);
    let mut request = pending(&mut service, &token, "GET", original_deadline)?;
    let (result, file) = request.execute_snapshot_transfer(&mut io::empty());
    assert!(first.lock().map_err(|_| "HA")?.is_leader()?);
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let blocked_before = cluster.blocked_probes();
    cluster.block_quorum(true);
    let response = service.finish_external_request(*request, result);
    cluster.block_quorum(false);
    assert_eq!(response.status, 503);
    assert!(cluster.blocked_probes() > blocked_before);
    assert!(crate::request_deadline::current().is_none());
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    drop(file);
    // Restore reachability and use the same node/state without mutation retry.
    first.lock().map_err(|_| "HA")?.ensure_linearizable()?;
    assert_export_matches_committed_root(&mut service, &token, "GET")?;

    // Replacing or removing the configured HA instance cannot turn a pending
    // cluster export into a local-profile export with identical application.
    let mut request = pending(&mut service, &token, "GET", deadline())?;
    let (result, file) = request.execute_snapshot_transfer(&mut io::empty());
    service.ha = None;
    assert_eq!(
        service.finish_external_request(*request, result).status,
        409
    );
    service.ha = Some(Arc::clone(&first));
    drop(file);

    // A real committed leadership transfer invalidates the detached result.
    let mut request = pending(&mut service, &token, "GET", deadline())?;
    let (result, file) = request.execute_snapshot_transfer(&mut io::empty());
    let successor = first.lock().map_err(|_| "HA")?.step_down()?;
    assert_ne!(successor, 1);
    assert_eq!(
        service.finish_external_request(*request, result).status,
        503
    );
    drop(file);
    for method in ["GET", "HEAD"] {
        let response = match stage(
            &mut service,
            method,
            "sys/storage/raft/snapshot",
            &token,
            deadline(),
        ) {
            RequestExecution::Complete(response) => response,
            RequestExecution::External(_) => return Err("standby staged native export".into()),
        };
        assert_eq!(response.status, 503);
        assert_eq!(
            response.body["errors"][0],
            "native snapshot requires the leader; standby streaming is unsupported"
        );
    }
    // The ordinary JSON standby route keeps its old forwarding behavior. Test
    // peer API endpoints intentionally have no listener, so it fails there.
    let json = call(
        &mut service,
        "GET",
        "sys/storage/raft/snapshot",
        &token,
        json!({}),
    );
    assert_eq!(json.status, 503);
    assert_eq!(json.body["errors"][0], "HA leader forwarding failed");
    service.ha = Some(Arc::clone(
        &cluster.processes[usize::try_from(successor - 1)?],
    ));
    assert_export_matches_committed_root(&mut service, &token, "GET")?;
    Ok(())
}

fn archive_bytes(service: &mut Service, token: &str) -> TestResult<Zeroizing<Vec<u8>>> {
    let mut request = pending(
        service,
        token,
        "GET",
        Instant::now() + Duration::from_secs(15),
    )?;
    let (result, file) = request.execute_snapshot_transfer(&mut io::empty());
    assert_eq!(
        service.finish_external_request(*request, result).status,
        200
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.ok_or("archive")?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[test]
fn native_ha_restore_publishes_new_epoch_not_local_rewind_and_fences_old_provider_result()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    write(&mut service, &token, "saved");
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/radius",
            &token,
            json!({"type":"radius"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/radius/config",
            &token,
            json!({"host":"localhost","secret":"synthetic-restore-secret","token_ttl":120})
        )
        .status,
        204
    );
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster = Cluster::new(&root.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    let saved = archive_bytes(&mut service, &token)?;
    let epoch = service.state.as_ref().ok_or("state")?.replay_epoch;
    write(&mut service, &token, "newer");
    let old = match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path: "auth/radius/login",
        namespace: "",
        token: "",
        body: json!({"username":"alice","password":"synthetic-provider-password"}),
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: Some(60),
        origin_peer: None,
        client_certificates: None,
    }) {
        RequestExecution::External(plan) => plan,
        _ => return Err("provider admission".into()),
    };
    let before = service.durable.as_ref().ok_or("durable")?.generation();
    let activation = service.unseal_nonce.clone();
    let mut restore = pending(
        &mut service,
        &token,
        "POST",
        Instant::now() + Duration::from_secs(15),
    )?;
    let (result, file) = restore.execute_snapshot_transfer(&mut saved.as_slice());
    assert!(file.is_none());
    let response = service.finish_external_request(*restore, result);
    assert_eq!(response.status, 200);
    assert_eq!(
        service.state.as_ref().ok_or("state")?.schema,
        CURRENT_STATE_SCHEMA
    );
    assert_eq!(
        service.state.as_ref().ok_or("state")?.replay_epoch,
        epoch + 1
    );
    assert!(service.durable.as_ref().ok_or("durable")?.generation() > before);
    assert_ne!(service.unseal_nonce, activation);
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/ha-snapshot",
            &token,
            json!({})
        )
        .body["data"]["data"]["value"],
        "saved"
    );
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let rejected = service.finish_external_request(
        *old,
        ExternalEffectResult::OnlineAuth(Ok(
            super::super::online_auth::OnlineAuthObservation::Radius(
                crate::auth::RadiusLoginObservation,
            ),
        )),
    );
    assert_eq!(rejected.status, 503);
    assert!(rejected.body.get("wrap_info").is_none_or(Value::is_null));
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    let leader = Arc::clone(&cluster.processes[0]);
    let successor = leader.lock().map_err(|_| "HA")?.step_down()?;
    service.ha = Some(Arc::clone(
        &cluster.processes[usize::try_from(successor - 1)?],
    ));
    assert_export_matches_committed_root(&mut service, &token, "GET")?;
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/ha-snapshot",
            &token,
            json!({})
        )
        .body["data"]["data"]["value"],
        "saved"
    );
    Ok(())
}

#[test]
fn native_ha_restore_capacity_refusal_has_no_epoch_or_root_publication() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    write(&mut service, &token, "saved");
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster = Cluster::new(&root.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    let saved = archive_bytes(&mut service, &token)?;
    write(&mut service, &token, "live");
    let raft_before = cluster.processes[0]
        .lock()
        .map_err(|_| "HA")?
        .snapshot_test_record_usage()?;
    let before = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let epoch = service.state.as_ref().ok_or("state")?.replay_epoch;
    let nonce = service.unseal_nonce.clone();
    let mut restore = pending(
        &mut service,
        &token,
        "POST",
        Instant::now() + Duration::from_secs(15),
    )?;
    let (result, _) = restore.execute_snapshot_transfer(&mut saved.as_slice());
    service.state_capacity = 1;
    assert_eq!(
        service.finish_external_request(*restore, result).status,
        507
    );
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        before
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(service.state.as_ref().ok_or("state")?.replay_epoch, epoch);
    assert_eq!(service.unseal_nonce, nonce);
    assert!(!service.recovery_required);
    assert_eq!(
        cluster.processes[0]
            .lock()
            .map_err(|_| "HA")?
            .snapshot_test_record_usage()?,
        raft_before
    );
    Ok(())
}

#[test]
fn native_ha_restore_stale_base_and_expired_transfer_do_not_publish() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    write(&mut service, &token, "saved");
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster = Cluster::new(&root.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    let saved = archive_bytes(&mut service, &token)?;
    for expired in [false, true] {
        let mut restore = pending(
            &mut service,
            &token,
            "POST",
            Instant::now() + Duration::from_secs(15),
        )?;
        let (result, _) = restore.execute_snapshot_transfer(&mut saved.as_slice());
        if expired {
            let ExternalEffectPlan::SnapshotTransfer(plan) = &mut restore.effect else {
                return Err("transfer kind".into());
            };
            plan.deadline = Instant::now() - Duration::from_millis(1);
        } else {
            write(&mut service, &token, "concurrent");
        }
        let before = cluster.processes[0]
            .lock()
            .map_err(|_| "HA")?
            .snapshot_test_record_usage()?;
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let identity = service.current_state_identity().map_err(|_| "identity")?;
        let response = service.finish_external_request(*restore, result);
        assert_eq!(response.status, if expired { 503 } else { 409 });
        assert_eq!(
            service.current_state_identity().map_err(|_| "identity")?,
            identity
        );
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert_eq!(
            cluster.processes[0]
                .lock()
                .map_err(|_| "HA")?
                .snapshot_test_record_usage()?,
            before
        );
    }
    Ok(())
}

#[test]
fn epoch_publication_expired_actor_after_real_stage_keeps_old_root() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    write(&mut service, &token, "live");
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &token,
        json!({"policies":["root"],"ttl":1}),
    );
    assert_eq!(issued.status, 200);
    let short = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?;
    let actor = service
        .state
        .as_mut()
        .ok_or("state")?
        .auth
        .authenticate(short, 100)
        .map_err(|_| "admit actor")?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster = Cluster::new(&root.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    // Anchor the actual typed root before attempting the new epoch.
    let _ = archive_bytes(&mut service, &token)?;
    let before = service.current_state_identity().map_err(|_| "identity")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let epoch = service.state.as_ref().ok_or("state")?.replay_epoch;
    let nonce = service.unseal_nonce.clone();
    let usage = cluster.processes[0]
        .lock()
        .map_err(|_| "HA")?
        .snapshot_test_record_usage()?;
    let mut candidate = service.state.clone().ok_or("state")?;
    candidate.replay_epoch = epoch + 1;
    candidate.engines.handle(
        "",
        "PUT",
        "secret/data/ha-snapshot",
        &json!({"data":{"value":"candidate-not-published"}}),
        100,
    )?;
    let plan = service
        .prepare_record_plan(&candidate)
        .map_err(|_| "plan")?;
    service
        .state
        .as_ref()
        .ok_or("state")?
        .auth
        .authorize_request(&actor, "", "sys/storage/raft/snapshot", "update", 100)
        .map_err(|_| "initial authorization")?;
    let called = std::cell::Cell::new(false);
    let response = service
        .commit_record_plan_with_before_publish(&candidate, plan, |auth| {
            called.set(true);
            // Controlled logical time advances only at the final callback, after
            // actual consensus Stage. No wall-clock sleeps or fake successful writes.
            auth.authorize_request(&actor, "", "sys/storage/raft/snapshot", "update", 101)
                .map_err(|error| Response::error(error.status, &error.message))
        })
        .err()
        .ok_or("expired actor unexpectedly published")?;
    assert!(called.get());
    assert_eq!(response.status, 403);
    assert!(!service.recovery_required);
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        before
    );
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(service.state.as_ref().ok_or("state")?.replay_epoch, epoch);
    assert_eq!(service.unseal_nonce, nonce);
    let staged = cluster.processes[0]
        .lock()
        .map_err(|_| "HA")?
        .snapshot_test_record_usage()?;
    assert!(staged.0 > usage.0, "real Stage commands must have applied");
    assert!(staged.1.object_count > usage.1.object_count);
    // ReadIndex re-observes Raft authority, proving no new root was published.
    service.sync_from_ha().map_err(|_| "read current root")?;
    assert_eq!(
        service.current_state_identity().map_err(|_| "identity")?,
        before
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "secret/data/ha-snapshot",
            &token,
            json!({})
        )
        .body["data"]["data"]["value"],
        "live"
    );
    Ok(())
}
