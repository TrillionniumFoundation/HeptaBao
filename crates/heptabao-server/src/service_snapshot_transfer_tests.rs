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

fn upload_native_path(
    service: &mut Service,
    token: &str,
    path: &str,
    bytes: &[u8],
) -> TestResult<Response> {
    let mut plan = match stage(service, "POST", path, token) {
        RequestExecution::External(plan) => plan,
        RequestExecution::Complete(response) => return Ok(response),
    };
    let mut reader = bytes;
    let (result, file) = plan.execute_snapshot_transfer(&mut reader);
    assert!(file.is_none());
    Ok(service.finish_external_request(*plan, result))
}

fn rekey_once(service: &mut Service, token: &str, old_key: &str) -> TestResult<String> {
    let start = call(
        service,
        "POST",
        "sys/rekey/init",
        token,
        json!({"secret_shares":1,"secret_threshold":1,"require_verification":false}),
    );
    assert_eq!(start.status, 200);
    let nonce = start.body["nonce"].as_str().ok_or("rekey nonce")?;
    let completed = call(
        service,
        "POST",
        "sys/rekey/update",
        token,
        json!({"nonce":nonce,"key":old_key}),
    );
    assert_eq!(completed.status, 200);
    assert_eq!(completed.body["complete"], true);
    assert_eq!(completed.body["verification_required"], false);
    Ok(completed.body["keys_base64"][0]
        .as_str()
        .ok_or("new share")?
        .to_owned())
}

#[test]
fn native_same_seal_ordinary_restore_rolls_back_without_changing_json_policy() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    put(&mut service, &token, "before");
    let archive = download(&mut service, &token)?;
    let json_backup = service.durable.as_ref().ok_or("durable")?.export_backup()?;
    let seal = fs::read(service.data_dir.join("seal.json"))?;
    put(&mut service, &token, "after");
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let rejected = call(
        &mut service,
        "POST",
        "sys/storage/raft/snapshot",
        &token,
        json!({"snapshot":STANDARD.encode(json_backup)}),
    );
    assert_eq!(rejected.status, 400);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    assert_eq!(get(&mut service, &token), "after");
    let restored = upload_native_path(&mut service, &token, "sys/storage/raft/snapshot", &archive)?;
    assert_eq!(restored.status, 200);
    assert_eq!(restored.body["data"]["rollback"], true);
    assert_eq!(get(&mut service, &token), "before");
    assert_eq!(fs::read(service.data_dir.join("seal.json"))?, seal);
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
fn rekeyed_native_restore_rejects_old_seal_and_accepts_new_seal_after_reopen() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (old_key, token) = bootstrap(&mut service)?;
    put(&mut service, &token, "original");
    let old_archive = download(&mut service, &token)?;
    let new_key = rekey_once(&mut service, &token, &old_key)?;
    put(&mut service, &token, "rekeyed");
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let seal = fs::read(service.data_dir.join("seal.json"))?;
    let activation = service.unseal_nonce.clone();
    for (path, text) in [
        (
            "sys/storage/raft/snapshot",
            "native snapshot seal identity differs",
        ),
        (
            "sys/storage/raft/snapshot-force",
            "cross-seal native snapshot force restore is unsupported",
        ),
    ] {
        let rejected = upload_native_path(&mut service, &token, path, &old_archive)?;
        assert_eq!(rejected.status, 400);
        assert_eq!(rejected.body["errors"][0], text);
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert_eq!(service.unseal_nonce, activation);
        assert_eq!(fs::read(service.data_dir.join("seal.json"))?, seal);
        assert_eq!(get(&mut service, &token), "rekeyed");
    }
    let new_archive = download(&mut service, &token)?;
    put(&mut service, &token, "newer");
    assert_eq!(
        upload_native_path(
            &mut service,
            &token,
            "sys/storage/raft/snapshot",
            &new_archive
        )?
        .status,
        200
    );
    assert_eq!(get(&mut service, &token), "rekeyed");
    drop(service);
    let mut service = root.service()?;
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":old_key})
        )
        .status,
        400
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/unseal",
            "",
            json!({"key":new_key})
        )
        .status,
        200
    );
    assert_eq!(get(&mut service, &token), "rekeyed");
    Ok(())
}

#[test]
fn completed_rekey_fences_pending_native_upload_and_download() -> TestResult {
    for method in ["GET", "POST"] {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, token) = bootstrap(&mut service)?;
        put(&mut service, &token, "keep");
        let archive = download(&mut service, &token)?;
        let mut plan = pending(&mut service, method, &token)?;
        let (result, file) = plan.execute_snapshot_transfer(&mut archive.as_slice());
        let before = service
            .current_state_identity()
            .map_err(|_| "state identity")?;
        let activation = service.unseal_nonce.clone();
        rekey_once(&mut service, &token, &key)?;
        // Rekey changes seal authority while retaining the same barrier and
        // application: the native seal fence must carry this distinction.
        assert_eq!(
            service
                .current_state_identity()
                .map_err(|_| "state identity")?,
            before
        );
        assert_eq!(service.unseal_nonce, activation);
        let rejected = service.finish_external_request(*plan, result);
        assert_eq!(rejected.status, 409);
        assert_eq!(
            rejected.body["errors"][0],
            "snapshot transfer seal identity changed"
        );
        drop(file);
        assert_eq!(get(&mut service, &token), "keep");
        assert!(!download(&mut service, &token)?.is_empty());
    }
    Ok(())
}

#[test]
fn seal_json_reencoding_preserves_the_canonical_native_seal_identity() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    put(&mut service, &token, "before");
    let archive = download(&mut service, &token)?;
    let path = service.data_dir.join("seal.json");
    let original = fs::read(&path)?;
    let value: Value = serde_json::from_slice(&original)?;
    let reencoded = serde_json::to_vec_pretty(&value)?;
    assert_ne!(original, reencoded);
    fs::write(&path, reencoded)?;
    put(&mut service, &token, "after");
    assert_eq!(
        upload_native_path(&mut service, &token, "sys/storage/raft/snapshot", &archive)?.status,
        200
    );
    assert_eq!(get(&mut service, &token), "before");
    Ok(())
}

fn authenticated_v1_archive(service: &Service) -> TestResult<Vec<u8>> {
    let lease = service.snapshot_spool.as_ref().ok_or("spool")?.lease()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut state = lease.file(MAX_NATIVE_STATE, deadline)?;
    let mut writer = snapshot_archive::HashWriter {
        writer: &mut state,
        hash: Sha256::new(),
    };
    let durable = service.durable.as_ref().ok_or("durable")?;
    let length = durable.export_backup_to(&mut writer)?;
    let digest = writer.hash.finalize().into();
    let metadata = serde_json::to_vec(&json!({"format":"heptabao-native-snapshot-v1",
        "state_format":"heptabao-encrypted-backup-v1/HBB2", "generation":durable.generation(),"state_bytes":length}))?;
    let sums = snapshot_archive::sums(&metadata, &digest);
    let barrier = AeadBarrier::new(**service.barrier_key.as_ref().ok_or("barrier")?)?;
    let sealed_sums = barrier.seal(b"heptabao.native-snapshot.checksums.v1", &sums)?;
    let mut file = snapshot_archive::export(
        DownloadSource {
            state,
            metadata,
            sums,
            sealed_sums,
        },
        &lease,
        deadline,
    )?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[test]
fn authenticated_historical_v1_is_explicitly_refused_by_both_native_restore_paths() -> TestResult {
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    put(&mut service, &token, "before");
    drop(pending(&mut service, "GET", &token)?);
    let archive = authenticated_v1_archive(&service)?;
    put(&mut service, &token, "keep");
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let activation = service.unseal_nonce.clone();
    for path in [
        "sys/storage/raft/snapshot",
        "sys/storage/raft/snapshot-force",
    ] {
        let rejected = upload_native_path(&mut service, &token, path, &archive)?;
        assert_eq!(rejected.status, 400);
        assert_eq!(
            rejected.body["errors"][0],
            "native snapshot v1 has no seal binding; restore is unsupported"
        );
        assert_eq!(
            service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert_eq!(service.unseal_nonce, activation);
        assert_eq!(get(&mut service, &token), "keep");
    }
    Ok(())
}

#[test]
fn canonical_seal_digest_matches_its_fixed_versioned_wire_vector() -> TestResult {
    let seal = SealMetadata {
        schema: 1,
        generation: 7,
        share_format: "shamir-v1".into(),
        secret_shares: 3,
        secret_threshold: 2,
        wrapped_barrier_key: STANDARD.encode((0u8..64).collect::<Vec<_>>()),
    };
    assert_eq!(
        hex(&canonical_seal_identity(&seal)?),
        "f58c3b3767e14344112ac338bd2d3eee531195b3dbaf9958cd58dc927648ee84"
    );
    let expected = canonical_seal_identity(&seal)?;
    for mode in 0..4 {
        let mut changed = seal.clone();
        match mode {
            0 => changed.generation += 1,
            1 => changed.secret_shares = 4,
            2 => changed.secret_threshold = 1,
            _ => changed.wrapped_barrier_key = STANDARD.encode([5; 64]),
        }
        assert_ne!(canonical_seal_identity(&changed)?, expected);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn native_seal_reader_rejects_linked_nonprivate_and_oversized_metadata() -> TestResult {
    use std::os::unix::{fs::PermissionsExt, fs::symlink};
    let root = Root::new();
    let mut service = root.service()?;
    let (_, token) = bootstrap(&mut service)?;
    let path = service.data_dir.join("seal.json");
    let saved = service.data_dir.join("saved-seal-for-test");
    let original = fs::read(&path)?;
    for mode in 0..4 {
        match mode {
            0 => {
                fs::rename(&path, &saved)?;
                symlink(&saved, &path)?;
            }
            1 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?,
            2 => fs::hard_link(&path, &saved)?,
            _ => fs::write(&path, vec![b' '; 64 * 1024 + 1])?,
        }
        let denied = stage(&mut service, "GET", "sys/storage/raft/snapshot", &token);
        assert!(
            matches!(denied, RequestExecution::Complete(ref response) if response.status == 503)
        );
        match mode {
            0 => {
                fs::remove_file(&path)?;
                fs::rename(&saved, &path)?;
            }
            1 => fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?,
            2 => fs::remove_file(&saved)?,
            _ => fs::write(&path, &original)?,
        }
        assert!(!service.recovery_required);
    }
    assert!(!download(&mut service, &token)?.is_empty());
    Ok(())
}
