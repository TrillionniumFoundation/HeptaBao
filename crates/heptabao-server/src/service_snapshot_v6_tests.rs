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
fn begin(service: &mut Service, method: &str, token: &str) -> RequestExecution {
    match service.begin_native_snapshot_before(
        ServiceRequest::new(method, "sys/storage/raft/snapshot", "", token, json!({})),
        Instant::now() + Duration::from_secs(15),
    ) {
        NativeSnapshotAdmission::Execute(value) => value,
        NativeSnapshotAdmission::Redirect(_) => panic!("single-node fixture cannot redirect"),
    }
}
fn pending(
    service: &mut Service,
    method: &str,
    token: &str,
) -> TestResult<Box<PendingExternalRequest>> {
    match begin(service, method, token) {
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
        let response = begin(&mut service, method, "");
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
fn v6_metadata_never_relabels_hbb2_or_raises_legacy_state_limit() {
    let seal = [7; 32];
    let v6 = Metadata::new_v6(1, MAX_NATIVE_STATE + 1, &seal);
    assert!(v6.valid());
    assert!(v6.is_v6());
    let old = Metadata::new(1, MAX_NATIVE_STATE + 1, &seal);
    assert!(!old.valid());
    assert!(!old.is_v6());
    let json = serde_json::to_value(v6).expect("test metadata");
    assert_eq!(json["format"], "heptabao-native-object-snapshot-v1");
}
