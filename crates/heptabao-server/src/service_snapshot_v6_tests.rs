//! Real Service, production AeadBarrier, native root and existing snapshot
//! admission/finalization. Test helpers never construct an Actor or restore plan.
use super::*;
use crate::service::tests::{Root, bootstrap};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    service.handle(method, path, "", token, body)
}
fn initialized() -> TestResult<(Root, Service, String, String)> {
    let root = Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_candidate()?;
    let (key, token) = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        bootstrap(&mut service)?
    };
    Ok((root, service, key, token))
}
fn activate(service: &mut Service, token: &str) {
    let response = call(
        service,
        "POST",
        "sys/internal/native-v6/activate",
        token,
        json!({}),
    );
    assert_eq!(response.status, 204, "activation: {}", response.body);
}
fn put(service: &mut Service, token: &str, value: &str) {
    let response = call(
        service,
        "POST",
        "secret/data/snapshot-v6",
        token,
        json!({"data":{"value":value}}),
    );
    assert_eq!(response.status, 200, "native write: {}", response.body);
}
fn get(service: &mut Service, token: &str) -> Value {
    let response = call(service, "GET", "secret/data/snapshot-v6", token, json!({}));
    assert_eq!(response.status, 200, "native read: {}", response.body);
    response.body["data"]["data"].clone()
}
fn begin(service: &mut Service, method: &str, token: &str) -> TestResult<RequestExecution> {
    match service.begin_native_snapshot_before(
        ServiceRequest::new(method, "sys/storage/raft/snapshot", "", token, json!({})),
        Instant::now() + Duration::from_secs(15),
    ) {
        NativeSnapshotAdmission::Execute(value) => Ok(value),
        NativeSnapshotAdmission::Redirect(_) => {
            Err("single-node fixture unexpectedly redirected".into())
        }
    }
}
fn pending(
    service: &mut Service,
    method: &str,
    token: &str,
) -> TestResult<Box<PendingExternalRequest>> {
    match begin(service, method, token)? {
        RequestExecution::External(value) => Ok(value),
        RequestExecution::Complete(value) => {
            Err(format!("snapshot admission {} {}", value.status, value.body).into())
        }
    }
}
fn download(service: &mut Service, token: &str) -> TestResult<Vec<u8>> {
    let mut plan = pending(service, "GET", token)?;
    let (result, file) = plan.execute_snapshot_transfer(&mut io::empty());
    let response = service.finish_external_request(*plan, result);
    assert_eq!(
        response.status, 200,
        "download finalization: {}",
        response.body
    );
    let mut file = file.ok_or("download missing")?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}
fn upload(service: &mut Service, token: &str, bytes: &[u8]) -> TestResult<Response> {
    let mut plan = pending(service, "POST", token)?;
    let (result, file) = plan.execute_snapshot_transfer(&mut &bytes[..]);
    assert!(file.is_none());
    Ok(service.finish_external_request(*plan, result))
}
#[test]
fn actual_service_v6_archive_roundtrip_restores_graph_and_reopens() -> TestResult {
    let (root, mut service, key, token) = initialized()?;
    put(&mut service, &token, "before-migration");
    activate(&mut service, &token);
    let expected = "genuine-v6-snapshot-value".repeat(20000);
    put(&mut service, &token, &expected);
    let archive = download(&mut service, &token)?;
    assert!(archive.starts_with(&[0x1f, 0x8b]));
    put(&mut service, &token, "newer-live-value");
    let response = upload(&mut service, &token, &archive)?;
    assert_eq!(response.status, 200, "restore: {}", response.body);
    assert_eq!(get(&mut service, &token), json!({"value":expected}));
    assert!(service.native_root.is_some());
    assert!(service.record_root.is_none());
    assert!(
        fs::read_dir(service.data_dir.join(".snapshot-transfer"))?
            .next()
            .is_none()
    );
    drop(service);
    let mut reopened = root.service()?;
    reopened.configure_native_v6_candidate()?;
    let response = call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key}));
    assert_eq!(response.status, 200, "cold restore: {}", response.body);
    assert_eq!(get(&mut reopened, &token), json!({"value":expected}));
    put(&mut reopened, &token, "write-after-restored-cold-owner");
    Ok(())
}
#[test]
fn anonymous_native_snapshot_is_denied_before_spool_or_ciphertext() -> TestResult {
    let (_root, mut service, _key, token) = initialized()?;
    put(&mut service, &token, "kept");
    activate(&mut service, &token);
    for method in ["GET", "POST"] {
        let response = begin(&mut service, method, "")?;
        assert!(matches!(response,RequestExecution::Complete(ref r) if r.status==403));
    }
    assert!(service.snapshot_spool.is_none());
    assert_eq!(get(&mut service, &token), json!({"value":"kept"}));
    Ok(())
}
#[test]
fn native_archive_rejects_bad_checksum_and_changed_activation_without_root_restore() -> TestResult {
    let (_root, mut service, _key, token) = initialized()?;
    put(&mut service, &token, "old");
    activate(&mut service, &token);
    let archive = download(&mut service, &token)?;
    put(&mut service, &token, "must-survive");
    for mode in 0..2 {
        let mut plan = pending(&mut service, "POST", &token)?;
        let (mut result, _) = plan.execute_snapshot_transfer(&mut archive.as_slice());
        if mode == 0 {
            let ExternalEffectResult::SnapshotTransfer(Ok(Observation::Upload(ref mut imported))) =
                result
            else {
                return Err("actual archive parse".into());
            };
            imported.sealed_sums[0] ^= 1;
        } else {
            service.rotate_unseal_nonce()?;
        }
        let response = service.finish_external_request(*plan, result);
        assert_eq!(
            response.status,
            if mode == 0 { 400 } else { 409 },
            "must reject: {}",
            response.body
        );
        assert_eq!(get(&mut service, &token), json!({"value":"must-survive"}));
    }
    Ok(())
}
#[test]
fn v6_metadata_never_relabels_hbb2_or_raises_legacy_state_limit() -> TestResult {
    let seal = [7; 32];
    let v6 = Metadata::new_v6(1, MAX_NATIVE_STATE + 1, &seal);
    assert!(v6.valid());
    assert!(v6.is_v6());
    let old = Metadata::new(1, MAX_NATIVE_STATE + 1, &seal);
    assert!(!old.valid());
    assert!(!old.is_v6());
    let json = serde_json::to_value(v6)?;
    assert_eq!(json["format"], "heptabao-native-object-snapshot-v1");
    Ok(())
}

#[test]
fn v6_snapshot_moves_into_same_seal_store_without_preexisting_external_objects() -> TestResult {
    let (source_root, service, key, token) = initialized()?;
    let source_data = service.data_dir.clone();
    drop(service);
    let target_root = Root::new();
    private_directory(&target_root.path)?;
    let target_data = target_root.path.join("data");
    private_directory(&target_data)?;
    for entry in fs::read_dir(&source_data)? {
        let entry = entry?;
        assert!(
            entry.file_type()?.is_file(),
            "initial seed must contain only owned regular artifacts"
        );
        assert!(!entry.file_name().to_string_lossy().ends_with(".hbo"));
        fs::copy(entry.path(), target_data.join(entry.file_name()))?;
    }
    let mut source = source_root.service()?;
    source.configure_native_v6_candidate()?;
    assert_eq!(
        call(&mut source, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    put(&mut source, &token, "before-v6");
    activate(&mut source, &token);
    let expected = "external-only-from-archive".repeat(24000);
    put(&mut source, &token, &expected);
    let bytes = download(&mut source, &token)?;
    let mut target = target_root.service()?;
    target.configure_native_v6_candidate()?;
    assert_eq!(
        call(&mut target, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert!(target.native_root.is_none());
    let before = fs::read_dir(&target_data)?
        .filter_map(Result::ok)
        .filter(|x| x.file_name().to_string_lossy().ends_with(".hbo"))
        .count();
    assert_eq!(before, 0);
    let response = upload(&mut target, &token, &bytes)?;
    assert_eq!(
        response.status, 200,
        "fresh target restore: {}",
        response.body
    );
    assert_eq!(get(&mut target, &token), json!({"value":expected}));
    assert!(target.native_root.is_some());
    let count = fs::read_dir(&target_data)?
        .filter_map(Result::ok)
        .filter(|x| x.file_name().to_string_lossy().ends_with(".hbo"))
        .count();
    assert!(count > 0);
    drop(target);
    let mut target = target_root.service()?;
    target.configure_native_v6_candidate()?;
    assert_eq!(
        call(&mut target, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert_eq!(get(&mut target, &token), json!({"value":expected}));
    Ok(())
}

#[test]
fn non_snapshot_raft_and_direct_json_paths_remain_closed_for_native_v6() -> TestResult {
    let (_root, mut service, _key, token) = initialized()?;
    put(&mut service, &token, "kept");
    activate(&mut service, &token);
    for path in [
        "sys/storage/raft/configuration",
        "sys/storage/raft/snapshot",
        "sys/raw/state",
    ] {
        let response = call(&mut service, "GET", path, &token, json!({}));
        assert_eq!(
            response.status, 501,
            "unrelated path must stay closed: {path}"
        );
    }
    assert_eq!(get(&mut service, &token), json!({"value":"kept"}));
    Ok(())
}

#[test]
fn v6_snapshot_expired_outer_context_does_not_stage_or_disclose() -> TestResult {
    let (_root, mut service, _key, token) = initialized()?;
    put(&mut service, &token, "kept");
    activate(&mut service, &token);
    let result = service.begin_native_snapshot_before(
        ServiceRequest::new("GET", "sys/storage/raft/snapshot", "", &token, json!({})),
        Instant::now() - Duration::from_millis(1),
    );
    assert!(
        matches!(result,NativeSnapshotAdmission::Execute(RequestExecution::Complete(ref r)) if r.status==503 && r.body.get("data").is_none())
    );
    assert!(service.snapshot_spool.is_none());
    Ok(())
}

#[test]
fn v6_snapshot_final_audit_failure_is_not_successful_restore() -> TestResult {
    let (_root, mut service, _key, token) = initialized()?;
    put(&mut service, &token, "old");
    activate(&mut service, &token);
    let archive = download(&mut service, &token)?;
    put(&mut service, &token, "current");
    let mut plan = pending(&mut service, "POST", &token)?;
    let (result, _) = plan.execute_snapshot_transfer(&mut archive.as_slice());
    let before = service.state_digest;
    service.audit_failed = true;
    let response = service.finish_external_request(*plan, result);
    assert!(response.status >= 400);
    assert!(response.body.get("data").is_none());
    assert_eq!(service.state_digest, before);
    Ok(())
}

#[test]
fn cancelling_native_snapshot_drops_its_binding_without_poisoning_next_request() -> TestResult {
    let (_root, mut service, _key, token) = initialized()?;
    put(&mut service, &token, "kept");
    activate(&mut service, &token);
    for method in ["GET", "POST"] {
        let plan = pending(&mut service, method, &token)?;
        assert!(
            service.native_request_binding.is_none(),
            "pending request must own its own failure binding"
        );
        drop(plan);
        assert!(!service.recovery_required);
        assert_eq!(get(&mut service, &token), json!({"value":"kept"}));
    }
    let _archive = download(&mut service, &token)?;
    assert!(service.native_request_binding.is_none());
    Ok(())
}

#[test]
fn native_snapshot_changed_target_is_rejected_and_unrelated_request_remains_usable() -> TestResult {
    let (_root, mut service, _key, token) = initialized()?;
    put(&mut service, &token, "old");
    activate(&mut service, &token);
    let archive = download(&mut service, &token)?;
    let mut plan = pending(&mut service, "POST", &token)?;
    assert!(service.native_request_binding.is_none());
    let (result, _) = plan.execute_snapshot_transfer(&mut archive.as_slice());
    put(&mut service, &token, "interleaved-new-value");
    let response = service.finish_external_request(*plan, result);
    assert_eq!(
        response.status, 409,
        "changed source must not be rebound: {}",
        response.body
    );
    assert_eq!(
        get(&mut service, &token),
        json!({"value":"interleaved-new-value"})
    );
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn finite_use_snapshot_retains_original_completion_clock_and_consumes_once() -> TestResult {
    let (_root, mut service, _key, root_token) = initialized()?;
    put(&mut service, &root_token, "finite-use-kept");
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &root_token,
        json!({"policies":["root"],"num_uses":1,"ttl":"30s","no_default_policy":true,"no_parent":true}),
    );
    assert_eq!(
        issued.status, 200,
        "real pre-migration token setup: {}",
        issued.body
    );
    let token = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("issued token")?
            .to_owned(),
    );
    activate(&mut service, &root_token);
    let bytes = download(&mut service, &token)?;
    assert!(bytes.starts_with(&[0x1f, 0x8b]));
    assert!(service.native_request_binding.is_none());
    let denied = begin(&mut service, "GET", &token)?;
    assert!(matches!(denied,RequestExecution::Complete(ref response) if response.status==403));
    assert_eq!(
        get(&mut service, &root_token),
        json!({"value":"finite-use-kept"})
    );
    assert!(!service.recovery_required);
    Ok(())
}

#[test]
fn cancelled_finite_snapshot_does_not_rearm_consumption_or_poison_root_actor() -> TestResult {
    let (_root, mut service, _key, root_token) = initialized()?;
    put(&mut service, &root_token, "kept");
    let issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &root_token,
        json!({"policies":["root"],"num_uses":1,"ttl":"30s","no_default_policy":true,"no_parent":true}),
    );
    assert_eq!(issued.status, 200);
    let token = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("issued token")?
            .to_owned(),
    );
    activate(&mut service, &root_token);
    drop(pending(&mut service, "POST", &token)?);
    assert!(service.native_request_binding.is_none());
    assert!(
        matches!(begin(&mut service,"POST",&token)?,RequestExecution::Complete(ref response) if response.status==403)
    );
    assert_eq!(get(&mut service, &root_token), json!({"value":"kept"}));
    assert!(!service.recovery_required);
    Ok(())
}
