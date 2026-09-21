use super::super::tests::{Root, bootstrap, call};
use super::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn stage(service: &mut Service, method: &str, path: &str, token: &str) -> RequestExecution {
    stage_at(service, method, path, token, Instant::now())
}
fn stage_at(
    service: &mut Service,
    method: &str,
    path: &str,
    token: &str,
    started: Instant,
) -> RequestExecution {
    service.native_snapshot_transport = true;
    service.native_snapshot_clock = Some((started, Duration::from_secs(100)));
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(30),
    );
    let result = service.begin_at_mode(RequestDispatch {
        method,
        path,
        namespace: "",
        token,
        body: json!({}),
        now: 100,
        allow_forward: false,
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
    method: &str,
    token: &str,
) -> TestResult<Box<PendingExternalRequest>> {
    match stage(
        service,
        method,
        if method == "GET" {
            "sys/storage/raft/snapshot"
        } else {
            "sys/storage/raft/snapshot-force"
        },
        token,
    ) {
        RequestExecution::External(value) => Ok(value),
        RequestExecution::Complete(value) => {
            Err(format!("snapshot admission {}", value.status).into())
        }
    }
}
fn download(service: &mut Service, token: &str) -> TestResult<Vec<u8>> {
    let mut plan = pending(service, "GET", token)?;
    let (result, file) = plan.execute_snapshot_transfer(&mut io::empty());
    assert_eq!(service.finish_external_request(*plan, result).status, 200);
    let mut file = file.ok_or("missing file")?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}
fn put(service: &mut Service, token: &str, value: &str) {
    assert_eq!(
        call(
            service,
            "PUT",
            "secret/data/native-backup",
            token,
            json!({"data":{"value":value}})
        )
        .status,
        200
    );
}
fn get(service: &mut Service, token: &str) -> Value {
    call(
        service,
        "GET",
        "secret/data/native-backup",
        token,
        json!({}),
    )
    .body["data"]["data"]["value"]
        .clone()
}

#[test]
fn native_archive_roundtrip_preserves_v5_state_and_reopens() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    put(&mut service, &token, "before");
    let archive = download(&mut service, &token)?;
    assert!(archive.starts_with(&[0x1f, 0x8b]));
    put(&mut service, &token, "after");
    let mut plan = pending(&mut service, "POST", &token)?;
    let (result, file) = plan.execute_snapshot_transfer(&mut archive.as_slice());
    assert!(file.is_none());
    assert_eq!(service.finish_external_request(*plan, result).status, 200);
    assert_eq!(get(&mut service, &token), "before");
    assert!(
        fs::read_dir(service.data_dir.join(".snapshot-transfer"))?
            .next()
            .is_none()
    );
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(get(&mut service, &token), "before");
    Ok(())
}

#[test]
fn snapshot_authorization_precedes_spool_and_cancel_releases_single_transfer_slot() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let rejected = stage(&mut service, "POST", "sys/storage/raft/snapshot", "");
    assert!(matches!(rejected, RequestExecution::Complete(ref response) if response.status == 403));
    assert!(service.snapshot_spool.is_none());
    let plan = pending(&mut service, "GET", &token)?;
    let rejected = stage(&mut service, "GET", "sys/storage/raft/snapshot", &token);
    assert!(matches!(rejected, RequestExecution::Complete(ref response) if response.status == 429));
    drop(plan);
    let mut plan = pending(&mut service, "GET", &token)?;
    let (result, file) = plan.execute_snapshot_transfer(&mut io::empty());
    assert_eq!(service.finish_external_request(*plan, result).status, 200);
    let rejected = stage(&mut service, "POST", "sys/storage/raft/snapshot", &token);
    assert!(matches!(rejected, RequestExecution::Complete(ref response) if response.status == 429));
    drop(file); // Socket cancellation closes the sole remaining file capability.
    drop(pending(&mut service, "POST", &token)?);
    assert!(
        fs::read_dir(service.data_dir.join(".snapshot-transfer"))?
            .next()
            .is_none()
    );
    Ok(())
}

#[test]
fn changed_state_activation_and_authenticated_checksum_failure_never_publish_uploaded_state()
-> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    put(&mut service, &token, "before");
    let archive = download(&mut service, &token)?;
    for mode in 0..3 {
        put(&mut service, &token, "current");
        let mut plan = pending(&mut service, "POST", &token)?;
        let (mut result, _) = plan.execute_snapshot_transfer(&mut archive.as_slice());
        if mode == 0 {
            put(&mut service, &token, "newer");
        }
        if mode == 1 {
            service.rotate_unseal_nonce()?;
        }
        if mode == 2 {
            let ExternalEffectResult::SnapshotTransfer(Ok(Observation::Upload(ref mut imported))) =
                result
            else {
                return Err("upload parse".into());
            };
            imported.sealed_sums[0] ^= 1;
        }
        let before = service.durable.as_ref().ok_or("durable")?.generation();
        let response = service.finish_external_request(*plan, result);
        assert_eq!(response.status, if mode == 2 { 400 } else { 409 });
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            before
        );
        assert_eq!(
            get(&mut service, &token),
            if mode == 0 { "newer" } else { "current" }
        );
        assert!(
            fs::read_dir(service.data_dir.join(".snapshot-transfer"))?
                .next()
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn spool_reopen_cleans_only_owned_interrupted_leaves_and_never_follows_links() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    drop(pending(&mut service, "POST", &token)?);
    let directory = service.data_dir.join(".snapshot-transfer");
    service.snapshot_spool = None;
    let interrupted = directory.join("transfer-00000000000000000000000000000000");
    fs::write(&interrupted, b"sealed temporary")?;
    let spool = SnapshotSpool::open(&service.data_dir)?;
    assert!(!interrupted.exists());
    drop(spool);
    let foreign = directory.join("unrelated-file");
    fs::write(&foreign, b"do not delete")?;
    assert!(SnapshotSpool::open(&service.data_dir).is_err());
    assert_eq!(fs::read(&foreign)?, b"do not delete");
    fs::remove_file(foreign)?;
    #[cfg(target_os = "linux")]
    {
        let outside = root.path.join("outside");
        fs::write(&outside, b"outside")?;
        std::os::unix::fs::symlink(&outside, &interrupted)?;
        assert!(SnapshotSpool::open(&service.data_dir).is_err());
        assert_eq!(fs::read(outside)?, b"outside");
        assert!(fs::symlink_metadata(&interrupted)?.file_type().is_symlink());
    }
    Ok(())
}

#[test]
fn native_archive_rejects_truncation_concatenated_gzip_and_corruption() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    put(&mut service, &token, "keep");
    let valid = download(&mut service, &token)?;
    let mut appended = valid.clone();
    appended.extend_from_slice(&valid);
    let mut corrupt = valid.clone();
    let middle = corrupt.len() / 2;
    corrupt[middle] ^= 64;
    for mut archive in [
        &valid[..valid.len() - 1],
        appended.as_slice(),
        corrupt.as_slice(),
        b"not a gzip native snapshot".as_slice(),
    ] {
        let mut plan = pending(&mut service, "POST", &token)?;
        let before = service.durable.as_ref().ok_or("durable")?.generation();
        let (result, _) = plan.execute_snapshot_transfer(&mut archive);
        assert_eq!(service.finish_external_request(*plan, result).status, 400);
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            before
        );
        assert_eq!(get(&mut service, &token), "keep");
    }
    Ok(())
}

#[test]
fn expired_transfer_plan_drops_files_and_cannot_publish() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    put(&mut service, &token, "keep");
    let archive = download(&mut service, &token)?;
    let mut plan = pending(&mut service, "POST", &token)?;
    let (result, _) = plan.execute_snapshot_transfer(&mut archive.as_slice());
    let ExternalEffectPlan::SnapshotTransfer(ref mut transfer) = plan.effect else {
        return Err("plan kind".into());
    };
    transfer.deadline = Instant::now();
    let before = service.durable.as_ref().ok_or("durable")?.generation();
    assert_eq!(service.finish_external_request(*plan, result).status, 503);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        before
    );
    assert!(
        fs::read_dir(service.data_dir.join(".snapshot-transfer"))?
            .next()
            .is_none()
    );
    drop(pending(&mut service, "POST", &token)?);
    Ok(())
}

#[test]
fn finite_use_root_snapshot_request_consumes_exactly_once_at_admission() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &token,
        json!({"policies":["root"],"ttl":100,"num_uses":2}),
    );
    assert_eq!(issued.status, 200);
    let finite = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("finite token")?
        .to_owned();
    let before = service.durable.as_ref().ok_or("durable")?.generation();
    let mut plan = pending(&mut service, "GET", &finite)?;
    let admitted = service.durable.as_ref().ok_or("durable")?.generation();
    // Record publication and retirement may use multiple physical generations.
    // Assert the capability's actual use count, not a physical write count.
    assert!(admitted > before);
    let lookup = call(
        &mut service,
        "POST",
        "auth/token/lookup",
        &token,
        json!({"token":finite}),
    );
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.body["data"]["num_uses"], 1);
    let (result, file) = plan.execute_snapshot_transfer(&mut io::empty());
    assert_eq!(service.finish_external_request(*plan, result).status, 200);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        admitted
    );
    drop(file);
    // The final use also completes without reauthentication during finalization.
    assert!(!download(&mut service, &finite)?.is_empty());
    assert!(
        matches!(stage(&mut service, "GET", "sys/storage/raft/snapshot", &finite), RequestExecution::Complete(ref response) if response.status == 403)
    );
    Ok(())
}

#[test]
fn admission_elapsed_time_expires_actor_before_download_or_restore_publication() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    put(&mut service, &token, "before");
    let archive = download(&mut service, &token)?;
    for method in ["GET", "POST"] {
        let issued = call(
            &mut service,
            "POST",
            "auth/token/create",
            &token,
            json!({"policies":["root"],"ttl":2}),
        );
        assert_eq!(issued.status, 200);
        let short = issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("short token")?
            .to_owned();
        put(&mut service, &token, "current");
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        // Deterministically model five seconds in reconciliation/audit before
        // stage_snapshot_transfer. Request time remains the paired t=100.
        let admission_started = Instant::now()
            .checked_sub(Duration::from_secs(5))
            .ok_or("clock")?;
        let path = if method == "GET" {
            "sys/storage/raft/snapshot"
        } else {
            "sys/storage/raft/snapshot-force"
        };
        let RequestExecution::External(mut pending) =
            stage_at(&mut service, method, path, &short, admission_started)
        else {
            return Err("admission must stage before final expiry check".into());
        };
        let ExternalEffectPlan::SnapshotTransfer(ref transfer) = pending.effect else {
            return Err("plan kind".into());
        };
        assert_eq!(transfer.started, admission_started);
        assert_eq!(transfer.now, Duration::from_secs(100));
        let (result, file) = pending.execute_snapshot_transfer(&mut archive.as_slice());
        assert_eq!(
            service.finish_external_request(*pending, result).status,
            403
        );
        drop(file);
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert_eq!(get(&mut service, &token), "current");
        assert!(
            fs::read_dir(service.data_dir.join(".snapshot-transfer"))?
                .next()
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn fractional_admission_clock_preserves_short_lease_until_actual_expiration() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
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
        .ok_or("short token")?
        .to_owned();
    let pending = pending(&mut service, "GET", &short)?;
    let ExternalEffectPlan::SnapshotTransfer(ref transfer) = pending.effect else {
        return Err("plan kind".into());
    };
    let auth = &service.state.as_ref().ok_or("state")?.auth;
    // Exact virtual elapsed intervals keep this test independent of CPU speed.
    // t=100.750 plus249ms is still second100, whereas250ms reaches expiry101.
    let wall = Duration::from_millis(100_750);
    for (elapsed, expected_now, allowed) in [
        (Duration::ZERO, 100, true),
        (Duration::from_micros(500), 100, true),
        (Duration::from_millis(249), 100, true),
        (Duration::from_millis(250), 101, false),
        (Duration::from_secs(5), 105, false),
    ] {
        let observed = snapshot_observed_time(wall, elapsed);
        assert_eq!(observed, expected_now);
        let result = auth.authorize_request(
            &transfer.actor,
            "",
            "sys/storage/raft/snapshot",
            "read",
            observed,
        );
        assert_eq!(result.is_ok(), allowed);
        if !allowed {
            assert!(matches!(result, Err(error) if error.status == 403));
        }
    }
    drop(pending);
    assert!(
        fs::read_dir(service.data_dir.join(".snapshot-transfer"))?
            .next()
            .is_none()
    );
    Ok(())
}

// Real split-phase admission with a substituted successful provider observation;
// no network is needed to test the restore/activation publication boundary.
fn pending_radius_login(
    service: &mut Service,
    wrap_ttl_seconds: Option<u64>,
) -> TestResult<Box<PendingExternalRequest>> {
    match service.begin_at_mode(RequestDispatch {
        method: "POST",
        path: "auth/radius/login",
        namespace: "",
        token: "",
        body: json!({"username":"alice","password":"synthetic-snapshot-password"}),
        now: 100,
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds,
        origin_peer: None,
        client_certificates: None,
    }) {
        RequestExecution::External(plan) => Ok(plan),
        RequestExecution::Complete(response) => {
            Err(format!("radius admission {}", response.status).into())
        }
    }
}

fn complete_radius_login(service: &mut Service, plan: PendingExternalRequest) -> Response {
    service.finish_external_request(
        plan,
        ExternalEffectResult::OnlineAuth(Ok(
            super::super::online_auth::OnlineAuthObservation::Radius(
                crate::auth::RadiusLoginObservation,
            ),
        )),
    )
}

fn configure_radius(service: &mut Service, token: &str) {
    assert_eq!(
        call(
            service,
            "POST",
            "sys/auth/radius",
            token,
            json!({"type":"radius"})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            service,
            "POST",
            "auth/radius/config",
            token,
            json!({"host":"localhost","secret":"synthetic-snapshot-shared-secret",
                "token_ttl":120,"token_max_ttl":600})
        )
        .status,
        204
    );
}

#[test]
fn restored_auth_configuration_cannot_reauthorize_a_pre_restore_provider_observation() -> TestResult
{
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    configure_radius(&mut service, &token);
    let original_config = call(&mut service, "GET", "auth/radius/config", &token, json!({}));
    assert_eq!(original_config.status, 200);
    let archive = download(&mut service, &token)?;
    let old_login = pending_radius_login(&mut service, Some(60))?;
    let activation = service.unseal_nonce.clone();
    // The restore puts exactly the old mount and provider configuration back.
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/radius/config",
            &token,
            json!({"token_ttl":90})
        )
        .status,
        204
    );
    let mut restore = pending(&mut service, "POST", &token)?;
    let (result, file) = restore.execute_snapshot_transfer(&mut archive.as_slice());
    assert!(file.is_none());
    assert_eq!(
        service.finish_external_request(*restore, result).status,
        200
    );
    assert_ne!(service.unseal_nonce, activation);
    assert_eq!(
        call(&mut service, "GET", "auth/radius/config", &token, json!({})).body,
        original_config.body
    );
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let restored_root = service
        .durable
        .as_ref()
        .ok_or("durable")?
        .get("system", "state")?;
    let rejected = complete_radius_login(&mut service, *old_login);
    assert_eq!(rejected.status, 503);
    assert!(rejected.body.get("auth").is_none_or(Value::is_null));
    assert!(rejected.body.get("wrap_info").is_none_or(Value::is_null));
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(
        service
            .durable
            .as_ref()
            .ok_or("durable")?
            .get("system", "state")?,
        restored_root
    );
    assert!(!service.recovery_required);
    let fresh_login = pending_radius_login(&mut service, None)?;
    let accepted = complete_radius_login(&mut service, *fresh_login);
    assert_eq!(accepted.status, 200);
    assert!(
        accepted.body["auth"]["client_token"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
    // Both completions still pass through response auditing; successful restore
    // must not invalidate its own already-checked transfer result.
    assert!(!service.audit_failed);
    Ok(())
}

#[test]
fn cancelled_and_rejected_restore_leave_an_existing_provider_plan_usable() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    configure_radius(&mut service, &token);
    let archive = download(&mut service, &token)?;
    let login = pending_radius_login(&mut service, None)?;
    let activation = service.unseal_nonce.clone();
    drop(pending(&mut service, "POST", &token)?);
    assert_eq!(service.unseal_nonce, activation);
    let mut restore = pending(&mut service, "POST", &token)?;
    let (mut result, _) = restore.execute_snapshot_transfer(&mut archive.as_slice());
    let ExternalEffectResult::SnapshotTransfer(Ok(Observation::Upload(ref mut imported))) = result
    else {
        return Err("upload parse".into());
    };
    imported.sealed_sums[0] ^= 1;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    assert_eq!(
        service.finish_external_request(*restore, result).status,
        400
    );
    assert_eq!(service.unseal_nonce, activation);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    let accepted = complete_radius_login(&mut service, *login);
    assert_eq!(accepted.status, 200);
    assert!(
        accepted.body["auth"]["client_token"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
    assert!(!service.recovery_required);
    Ok(())
}
