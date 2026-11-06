//! Real default native-file custody and original typed request completion.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::Root;
use std::sync::atomic::{AtomicBool, Ordering};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
type Initialized = (Root, Service, Zeroizing<String>, Zeroizing<String>);

fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    service.handle(method, path, "", token, body)
}

fn bundle() -> TestResult<Value> {
    let data = crate::engines::decode_lossless_json(
        br#"{"integer":9007199254740993,"decimal":0.123456789012345678901234567890,"private":{"$serde_json::private::Number":"001"}}"#,
    )?;
    Ok(json!({
        "schema":"openbao270-kv2-lossless-v1",
        "config":{"max_versions":4,"cas_required":true,"metadata_cas_required":true,"delete_version_after":"0s"},
        "entries":{"history":{
            "created_time":"1970-01-01T00:01:40.000000113Z","updated_time":"1970-01-01T00:01:43.000000113Z",
            "current_version":3,"oldest_version":0,"current_metadata_version":2,
            "max_versions":4,"cas_required":true,"metadata_cas_required":true,
            "delete_version_after":"0s","custom_metadata":{"purpose":"lossless export"},
            "versions":{
                "1":{"created_time":"1970-01-01T00:01:41.000000113Z","deletion_time":"1970-01-01T00:03:20.000000113Z","destroyed":false,"source_deletion_time":"1970-01-01T00:04:20.000000113Z","data":data},
                "2":{"created_time":"1970-01-01T00:01:42.000000113Z","deletion_time":"","destroyed":true,"source_deletion_time":"1970-01-01T00:04:21.000000113Z","data":null},
                "3":{"created_time":"1970-01-01T00:01:43.000000113Z","deletion_time":"","destroyed":false,"source_deletion_time":"","data":data}
            }
        }}
    }))
}

fn initialized() -> TestResult<Initialized> {
    let files = Root::new();
    let mut service = files.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let mut initialized = call(
        &mut service,
        "POST",
        "sys/init",
        "",
        json!({"secret_shares":1,"secret_threshold":1}),
    );
    assert_eq!(initialized.status, 200);
    let key = Zeroizing::new(
        initialized.body["keys"][0]
            .as_str()
            .ok_or("Shamir share")?
            .to_owned(),
    );
    let token = Zeroizing::new(
        initialized.body["root_token"]
            .as_str()
            .ok_or("root token")?
            .to_owned(),
    );
    erase_json(&mut initialized.body);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut service, "POST", "sys/init/ack", &token, json!({})).status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/secret",
            &token,
            json!({"type":"kv","options":{"version":"2"}})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/storage/native-v6/activate",
            &token,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/migration/openbao/kv2",
            &token,
            json!({"mount":"secret","bundle":bundle()?})
        )
        .status,
        204
    );
    Ok((files, service, key, token))
}

fn transfer(
    service: &mut Service,
    token: &str,
    namespace: &str,
    query: Value,
) -> TestResult<(Response, Option<Zeroizing<Vec<u8>>>)> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let request = ServiceRequest::new("GET", PATH, namespace, token, query);
    match service.begin_native_snapshot_before(request, deadline) {
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            Ok((response, None))
        }
        NativeSnapshotAdmission::Execute(RequestExecution::External(mut pending)) => {
            assert!(pending.has_lossless_download());
            let (observation, file) = pending.execute_snapshot_transfer(&mut io::empty());
            let response = service.finish_external_request(*pending, observation);
            // This is the same mandatory response-status gate as HTTP. A
            // staged private file is never delivered after a terminal veto.
            if response.status != 200 {
                return Ok((response, None));
            }
            let mut file = file.ok_or("missing successful lossless export")?;
            let mut bytes = Zeroizing::new(Vec::new());
            file.read_to_end(&mut bytes)?;
            Ok((response, Some(bytes)))
        }
        NativeSnapshotAdmission::Redirect(_) => Err("standalone export redirected".into()),
        #[cfg(feature = "native-v6-ha")]
        NativeSnapshotAdmission::Forward(_) => Err("standalone export forwarded".into()),
    }
}

fn downloaded(service: &mut Service, token: &str, mount: &str) -> TestResult<Zeroizing<Vec<u8>>> {
    let (response, bytes) = transfer(service, token, "", json!({"mount":mount}))?;
    assert_eq!(response.status, 200);
    bytes.ok_or_else(|| "lossless export missing".into())
}

struct AuditHookGuard;
impl Drop for AuditHookGuard {
    fn drop(&mut self) {
        AFTER_AUDIT_TEST_HOOK.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
fn audit_hook(hook: impl FnOnce(&mut Service) + 'static) -> TestResult<AuditHookGuard> {
    AFTER_AUDIT_TEST_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err("export audit hook already armed".into());
        }
        *slot = Some(Box::new(hook));
        Ok(AuditHookGuard)
    })
}

#[test]
fn lossless_export_default_file_exact_history_cold_reopen_and_restore_cas() -> TestResult {
    let (files, mut service, key, token) = initialized()?;
    let first = downloaded(&mut service, &token, "secret")?;
    let mut decoded = crate::engines::decode_lossless_json(&first)?;
    assert_eq!(decoded, bundle()?);
    assert!(service.pending_snapshot_transfer.is_none());
    assert!(service.native_request_binding.is_none());
    erase_json(&mut decoded);
    drop(service);
    let mut service = files.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        downloaded(&mut service, &token, "secret")?.as_slice(),
        first.as_slice()
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/restored",
            &token,
            json!({"type":"kv","options":{"version":"2"}})
        )
        .status,
        204
    );
    let decoded = crate::engines::decode_lossless_json(&first)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/migration/openbao/kv2",
            &token,
            json!({"mount":"restored","bundle":decoded})
        )
        .status,
        204
    );
    assert_eq!(
        downloaded(&mut service, &token, "restored")?.as_slice(),
        first.as_slice()
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "restored/data/history",
            &token,
            json!({"data":{"after":"restore"},"options":{"cas":2}})
        )
        .status,
        400
    );
    let wrote = call(
        &mut service,
        "POST",
        "restored/data/history",
        &token,
        json!({"data":{"after":"restore"},"options":{"cas":3}}),
    );
    assert_eq!(wrote.status, 200);
    assert_eq!(wrote.body["data"]["version"], 4);
    Ok(())
}

#[test]
fn lossless_export_requires_root_original_transport_and_closed_query() -> TestResult {
    let (_files, mut service, _key, token) = initialized()?;
    let ordinary = call(&mut service, "GET", PATH, &token, json!({"mount":"secret"}));
    assert_eq!(ordinary.status, 501);
    assert!(service.pending_snapshot_transfer.is_none());
    let mut issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &token,
        json!({"policies":["default"],"ttl":"1h"}),
    );
    assert_eq!(issued.status, 200);
    let child = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("child token")?
            .to_owned(),
    );
    erase_json(&mut issued.body);
    for actor in ["", child.as_str()] {
        let (response, bytes) = transfer(&mut service, actor, "", json!({"mount":"secret"}))?;
        assert_eq!(response.status, 403);
        assert!(bytes.is_none());
    }
    for query in [
        json!({}),
        json!({"mount":""}),
        json!({"mount":"secret","force":true}),
        json!({"mount":true}),
    ] {
        let (response, bytes) = transfer(&mut service, &token, "", query)?;
        assert_eq!(response.status, 400);
        assert!(bytes.is_none());
    }
    for mount in [
        "../secret",
        "/secret",
        "secret//",
        "secret/data/history",
        "absent",
    ] {
        let (response, bytes) = transfer(&mut service, &token, "", json!({"mount":mount}))?;
        assert!(response.status >= 400);
        assert!(bytes.is_none());
    }
    let (response, bytes) = transfer(&mut service, &token, "other/", json!({"mount":"secret"}))?;
    assert!(response.status >= 400);
    assert!(bytes.is_none());
    Ok(())
}

#[test]
fn lossless_export_source_change_between_staging_and_completion_withholds_file() -> TestResult {
    let (_files, mut service, _key, token) = initialized()?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let request = ServiceRequest::new("GET", PATH, "", &token, json!({"mount":"secret"}));
    let NativeSnapshotAdmission::Execute(RequestExecution::External(mut pending)) =
        service.begin_native_snapshot_before(request, deadline)
    else {
        return Err("export did not reach actual staging".into());
    };
    let (observation, file) = pending.execute_snapshot_transfer(&mut io::empty());
    assert!(file.is_some());
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/history",
            &token,
            json!({"data":{"different":"root"},"options":{"cas":3}})
        )
        .status,
        200
    );
    let response = service.finish_external_request(*pending, observation);
    assert!(response.status >= 400);
    drop(file);
    assert!(service.pending_snapshot_transfer.is_none());
    Ok(())
}

#[test]
fn lossless_export_nonce_and_seal_loss_after_real_audit_withhold_file() -> TestResult {
    for seal_loss in [false, true] {
        let (_files, mut service, _key, token) = initialized()?;
        let fired = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&fired);
        let _hook = audit_hook(move |service| {
            observed.store(true, Ordering::SeqCst);
            if seal_loss {
                service.barrier_key = None;
            } else {
                service.unseal_nonce.push_str("-owner-changed");
            }
        })?;
        let (response, bytes) = transfer(&mut service, &token, "", json!({"mount":"secret"}))?;
        assert!(
            fired.load(Ordering::SeqCst),
            "test must reach mandatory audit"
        );
        assert_eq!(response.status, 503);
        assert!(bytes.is_none());
        assert!(service.native_request_binding.is_none());
    }
    Ok(())
}

#[test]
fn lossless_export_original_root_actor_expiry_after_audit_withholds_file() -> TestResult {
    let (_files, mut service, _key, root) = initialized()?;
    let mut issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &root,
        json!({"policies":["root"],"no_default_policy":true,"ttl":"6s"}),
    );
    assert_eq!(issued.status, 200);
    let actor = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("expiring root")?
            .to_owned(),
    );
    erase_json(&mut issued.body);
    let issued_before = Instant::now();
    let fired = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&fired);
    let _hook = audit_hook(move |_| {
        observed.store(true, Ordering::SeqCst);
        std::thread::sleep(
            (issued_before + Duration::from_secs(7)).saturating_duration_since(Instant::now()),
        );
    })?;
    let (response, bytes) = transfer(&mut service, &actor, "", json!({"mount":"secret"}))?;
    assert!(
        fired.load(Ordering::SeqCst),
        "original Actor must reach real audit before expiry"
    );
    assert_eq!(response.status, 503);
    assert!(bytes.is_none());
    Ok(())
}

#[path = "service_snapshot_typed_root_identity_tests.rs"]
mod typed_root_identity;

#[path = "service_snapshot_lossless_parallel_tests.rs"]
mod parallel_boundaries;
