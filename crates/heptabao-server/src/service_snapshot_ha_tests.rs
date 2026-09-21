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
        assert!(
            matches!(stage(&mut service, "POST", path, &token, deadline()),
            RequestExecution::Complete(ref response) if response.status == 409)
        );
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
            "native snapshot save requires the leader; standby streaming is unsupported"
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
