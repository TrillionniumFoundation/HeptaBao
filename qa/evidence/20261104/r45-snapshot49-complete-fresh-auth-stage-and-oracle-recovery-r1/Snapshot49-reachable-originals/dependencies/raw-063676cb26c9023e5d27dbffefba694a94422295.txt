//! Formal configured File service, real Shamir credentials, typed retained
//! histories, mandatory audit and actual same-data cold reopen. No fixture CLI.
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::service::tests::Root;
use std::io::{self, Read};
use std::time::Instant;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Fixture = (Root, Service, Zeroizing<String>, Zeroizing<String>);
fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    service.handle(method, path, "", token, body)
}
fn initialize(service: &mut Service) -> TestResult<(Zeroizing<String>, Zeroizing<String>)> {
    let mut initialized = call(
        service,
        "POST",
        "sys/init",
        "",
        json!({"secret_shares":1,"secret_threshold":1}),
    );
    assert_eq!(initialized.status, 200);
    let key = Zeroizing::new(
        initialized.body["keys"][0]
            .as_str()
            .ok_or("real Shamir key absent")?
            .to_owned(),
    );
    let token = Zeroizing::new(
        initialized.body["root_token"]
            .as_str()
            .ok_or("real root token absent")?
            .to_owned(),
    );
    erase_json(&mut initialized.body);
    assert_eq!(
        call(
            service,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(
        call(service, "POST", "sys/init/ack", &token, json!({})).status,
        204
    );
    Ok((key, token))
}
fn value(version: u64) -> Value {
    json!({"version":version,"payload":"credential-history-preservation-凭证🧪".repeat(1024)})
}
fn fixture() -> TestResult<Fixture> {
    let root = Root::new();
    let mut service = root.service()?;
    service.configure_native_v6_storage(NativeStorageProfile::File)?;
    let (key, token) = initialize(&mut service)?;
    for mount in ["secret", "keep", "scratch"] {
        assert_eq!(
            call(
                &mut service,
                "POST",
                &format!("sys/mounts/{mount}"),
                &token,
                json!({"type":"kv","options":{"version":"2"}})
            )
            .status,
            204
        );
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/history",
            &token,
            json!({"data":value(1),"options":{"cas":0}})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "keep/data/sentinel",
            &token,
            json!({"data":{"kept":"byte exact"},"options":{"cas":0}})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            native_storage::ACTIVATE_PATH,
            &token,
            json!({})
        )
        .status,
        204
    );
    assert_eq!(
        service
            .native_root
            .as_ref()
            .ok_or("native root absent")?
            .reader_floor
            .native_kv2_format,
        2
    );
    for version in 2..=3 {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "secret/data/history",
                &token,
                json!({"data":value(version),"options":{"cas":version-1}})
            )
            .status,
            200
        );
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/destroy/history",
            &token,
            json!({"versions":[2]})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "scratch/config",
            &token,
            json!({"max_versions":1})
        )
        .status,
        204
    );
    for version in 1..=8 {
        assert_eq!(call(&mut service, "POST", "scratch/data/pruned", &token,
            json!({"data":{"version":version,"large":"obsolete".repeat(4096)},"options":{"cas":version-1}})).status, 200);
    }
    Ok((root, service, key, token))
}
fn selected_files(service: &Service) -> TestResult<BTreeSet<PathBuf>> {
    // Observational file counts in the test only. The production selector uses
    // authenticated locator metadata and a complete typed graph, never names.
    let mut result = BTreeSet::new();
    for item in fs::read_dir(&service.data_dir)? {
        let item = item?;
        if item
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("nv6.") && name.ends_with(".hbo"))
        {
            result.insert(item.path());
        }
    }
    Ok(result)
}
fn history(service: &mut Service, token: &str) -> TestResult<Value> {
    for version in [1, 3] {
        let response = call(
            service,
            "GET",
            "secret/data/history",
            token,
            json!({"version":version}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["data"], value(version));
    }
    let destroyed = call(
        service,
        "GET",
        "secret/data/history",
        token,
        json!({"version":2}),
    );
    assert_eq!(destroyed.status, 404);
    assert_eq!(destroyed.body["data"]["metadata"]["destroyed"], true);
    let retained = call(service, "GET", "keep/data/sentinel", token, json!({}));
    assert_eq!(retained.status, 200);
    assert_eq!(retained.body["data"]["data"], json!({"kept":"byte exact"}));
    let metadata = call(service, "GET", "secret/metadata/history", token, json!({}));
    assert_eq!(metadata.status, 200);
    Ok(metadata.body["data"].clone())
}
fn transfer(
    service: &mut Service,
    method: &str,
    token: &str,
    input: &mut impl Read,
) -> TestResult<(Response, Option<crate::snapshot_file::SnapshotFile>)> {
    let request = ServiceRequest::new(method, "sys/storage/raft/snapshot", "", token, json!({}));
    match service.begin_native_snapshot_before(request, Instant::now() + Duration::from_secs(15)) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(mut pending)) => {
            let (observation, file) = pending.execute_snapshot_transfer(input);
            Ok((service.finish_external_request(*pending, observation), file))
        }
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            Ok((response, None))
        }
        NativeSnapshotAdmission::Redirect(_) => Err("standalone snapshot redirected".into()),
        #[cfg(feature = "native-v6-ha")]
        NativeSnapshotAdmission::Forward(_) => Err("standalone snapshot forwarded".into()),
    }
}
fn download(service: &mut Service, token: &str) -> TestResult<Zeroizing<Vec<u8>>> {
    let (response, file) = transfer(service, "GET", token, &mut io::empty())?;
    assert_eq!(response.status, 200);
    let mut file = file.ok_or("actual snapshot absent")?;
    file.rewind_checked()?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[test]
fn native_file_gc_formal_preserves_retained_history_and_same_data_cold_reopen() -> TestResult {
    let (root, mut service, key, token) = fixture()?;
    let expected = history(&mut service, &token)?;
    let before = selected_files(&service)?;
    let response = call(&mut service, "POST", PATH, &token, json!({}));
    assert_eq!(response.status, 200);
    assert!(
        response.body["data"]["removed_objects"]
            .as_u64()
            .is_some_and(|n| n > 0 && n <= 32)
    );
    assert!(
        response.body["data"]["removed_ciphertext_bytes"]
            .as_u64()
            .is_some_and(|n| n > 0)
    );
    assert_eq!(response.body["data"]["confirmed_absent_objects"], 0);
    assert!(selected_files(&service)?.len() < before.len());
    assert_eq!(history(&mut service, &token)?, expected);
    assert!(service.pending_native_file_gc.is_none());
    assert!(!service.recovery_required);
    drop(service);
    let mut cold = root.service()?;
    cold.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        call(
            &mut cold,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(history(&mut cold, &token)?, expected);
    assert_eq!(
        call(
            &mut cold,
            "POST",
            "secret/data/history",
            &token,
            json!({"data":value(4),"options":{"cas":3}})
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn native_file_gc_formal_snapshot_restore_recreates_archived_graph_after_gc() -> TestResult {
    let (_root, mut service, _key, token) = fixture()?;
    let expected = history(&mut service, &token)?;
    let archive = download(&mut service, &token)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/history",
            &token,
            json!({"data":value(4),"options":{"cas":3}})
        )
        .status,
        200
    );
    let response = call(&mut service, "POST", PATH, &token, json!({}));
    assert_eq!(response.status, 200);
    assert!(
        response.body["data"]["removed_objects"]
            .as_u64()
            .is_some_and(|n| n > 0)
    );
    let (restored, output) = transfer(&mut service, "POST", &token, &mut archive.as_slice())?;
    assert_eq!(restored.status, 200);
    assert!(output.is_none());
    assert_eq!(history(&mut service, &token)?, expected);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "secret/data/history",
            &token,
            json!({"data":value(4),"options":{"cas":3}})
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn native_file_gc_formal_active_backup_and_spool_hold_without_deleting_files() -> TestResult {
    let (_root, mut service, _key, token) = fixture()?;
    let source = service
        .durable
        .as_mut()
        .ok_or("durable absent")?
        .prepare_v6_backup(&mut || Ok(()))?;
    let before = selected_files(&service)?;
    assert_eq!(
        call(&mut service, "POST", PATH, &token, json!({})).status,
        503
    );
    assert!(before.iter().all(|path| path.exists()));
    assert!(!service.recovery_required);
    drop(source);
    let _archive = download(&mut service, &token)?;
    let lease = service
        .snapshot_spool
        .as_ref()
        .ok_or("actual snapshot spool absent")?
        .lease()?;
    let before = selected_files(&service)?;
    assert_eq!(
        call(&mut service, "POST", PATH, &token, json!({})).status,
        409
    );
    assert!(before.iter().all(|path| path.exists()));
    drop(lease);
    assert_eq!(
        call(&mut service, "POST", PATH, &token, json!({})).status,
        200
    );
    Ok(())
}

#[test]
fn native_file_gc_formal_requires_actual_root_actor_and_empty_post() -> TestResult {
    let (_root, mut service, _key, token) = fixture()?;
    let mut issued = call(
        &mut service,
        "POST",
        "auth/token/create",
        &token,
        json!({"policies":["default"],"ttl":"60s"}),
    );
    assert_eq!(issued.status, 200);
    let child = Zeroizing::new(
        issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("actual child token absent")?
            .to_owned(),
    );
    erase_json(&mut issued.body);
    let before = selected_files(&service)?;
    assert_eq!(
        call(&mut service, "POST", PATH, &child, json!({})).status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            PATH,
            &token,
            json!({"paths":["unrelated"]})
        )
        .status,
        400
    );
    assert_eq!(
        call(&mut service, "DELETE", PATH, &token, json!({})).status,
        400
    );
    assert!(before.iter().all(|path| path.exists()));
    assert!(service.pending_native_file_gc.is_none());
    Ok(())
}

#[test]
fn native_file_gc_formal_after_audit_activation_change_vetoes_reply_without_retry() -> TestResult {
    struct Hook;
    impl Drop for Hook {
        fn drop(&mut self) {
            AFTER_AUDIT_HOOK.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    let (_root, mut service, _key, token) = fixture()?;
    AFTER_AUDIT_HOOK.with(|slot| {
        assert!(slot.borrow().is_none());
        *slot.borrow_mut() = Some(Box::new(|service| service.unseal_nonce.push('x')));
    });
    let _hook = Hook;
    let before = selected_files(&service)?.len();
    let response = call(&mut service, "POST", PATH, &token, json!({}));
    assert_eq!(response.status, 503);
    assert!(response.body.get("data").is_none());
    assert!(selected_files(&service)?.len() < before);
    assert!(service.pending_native_file_gc.is_none());
    Ok(())
}

#[path = "service_native_file_gc_full34_tests.rs"]
mod full34;
#[path = "service_native_file_gc_reconciliation_tests.rs"]
mod reconciliation;
