//! Real Raft observations route requests; they never admit application effects.
use super::*;
use crate::ha::snapshot_test_support::Cluster;
use crate::service::tests::{Root, bootstrap, call};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn admit(
    service: &mut Service,
    method: &str,
    token: &str,
    deadline: Instant,
) -> NativeSnapshotAdmission {
    service.begin_native_snapshot_before(
        ServiceRequest {
            method,
            path: if method == "PUT" {
                "sys/storage/raft/snapshot-force"
            } else {
                "sys/storage/raft/snapshot"
            },
            namespace: "",
            token,
            body: json!({}),
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
        },
        deadline,
    )
}

fn failure(admission: NativeSnapshotAdmission) -> Result<Response, Box<dyn std::error::Error>> {
    match admission {
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => Ok(response),
        _ => Err("unexpected native admission".into()),
    }
}

#[test]
fn native_redirect_uses_configured_current_leader_without_consuming_uses_or_staging() -> TestResult
{
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &token,
        json!({"policies":["default"],"num_uses":2,"ttl":600}),
    );
    assert_eq!(issued.status, 200);
    let limited = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("token")?
        .to_owned();
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster = Cluster::new(&root.path.join("raft"), &cluster_id)?;
    service.ha = Some(Arc::clone(&cluster.processes[1]));
    let before = service.current_state_identity().map_err(|_| "state")?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let deadline = || Instant::now() + Duration::from_secs(5);
    assert_eq!(
        failure(admit(&mut service, "GET", "", deadline()))?.status,
        503
    );
    cluster.configure_api_address(1, "https://leader.example:8200/")?;
    for method in ["GET", "HEAD", "POST", "PUT"] {
        for credential in ["", "invalid", limited.as_str()] {
            match admit(&mut service, method, credential, deadline()) {
                NativeSnapshotAdmission::Redirect(origin) => {
                    assert_eq!(origin.as_str(), "https://leader.example:8200")
                }
                _ => return Err("standby must redirect native request".into()),
            }
        }
    }
    assert!(service.snapshot_spool.is_none());
    assert!(service.pending_snapshot_transfer.is_none());
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(
        service.current_state_identity().map_err(|_| "state")?,
        before
    );
    assert!(crate::request_deadline::current().is_none());
    // The same ordinary JSON route still uses its bounded forwarding path.
    let json = call(
        &mut service,
        "GET",
        "sys/storage/raft/snapshot",
        &token,
        json!({}),
    );
    assert_eq!(json.status, 503);
    assert_eq!(json.body["errors"][0], "HA leader forwarding failed");
    service.ha = None;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/token/lookup",
            &token,
            json!({"token":limited})
        )
        .body["data"]["num_uses"],
        2
    );
    // A leadership change changes only the routing hint, never application authority.
    let successor = cluster.processes[0].lock().map_err(|_| "HA")?.step_down()?;
    cluster.configure_api_address(successor, "https://successor.example")?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    match admit(&mut service, "GET", "", deadline()) {
        NativeSnapshotAdmission::Redirect(origin) => {
            assert_eq!(origin.as_str(), "https://successor.example:443")
        }
        _ => return Err("successor routing".into()),
    }
    // Sealing does not reveal an origin or stage an archive, even if Raft still runs.
    service.ha = None;
    assert_eq!(
        call(&mut service, "PUT", "sys/seal", &token, json!({})).status,
        204
    );
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    assert_eq!(
        failure(admit(&mut service, "GET", "", deadline()))?.status,
        503
    );
    Ok(())
}

#[test]
fn native_redirect_unknown_leader_and_expired_original_scope_fail_without_effect() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let cluster = Cluster::uninitialized(&root.path.join("raft"), &cluster_id)?;
    cluster.configure_api_address(1, "https://configured.example")?;
    service.ha = Some(Arc::clone(&cluster.processes[0]));
    let before = service.durable.as_ref().ok_or("durable")?.generation();
    let response = failure(admit(
        &mut service,
        "GET",
        &token,
        Instant::now() + Duration::from_secs(5),
    ))?;
    assert_eq!(response.status, 503);
    assert_eq!(
        response.body["errors"][0],
        "HA cluster has no elected leader"
    );
    let original = Instant::now() - Duration::from_millis(1);
    {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(original);
        let response = failure(admit(
            &mut service,
            "POST",
            &token,
            Instant::now() + Duration::from_secs(5),
        ))?;
        assert_eq!(response.status, 503);
        assert_eq!(
            response.body["errors"][0],
            "snapshot admission deadline exceeded"
        );
        assert_eq!(crate::request_deadline::current(), Some(original));
    }
    assert!(crate::request_deadline::current().is_none());
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        before
    );
    assert!(service.snapshot_spool.is_none());
    Ok(())
}
