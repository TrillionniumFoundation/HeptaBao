#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use crate::service::NativeSnapshotAdmission;
use crate::service::tests::{Root, bootstrap};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    root: Root,
    key: Zeroizing<String>,
    token: Zeroizing<String>,
    data: PathBuf,
    audit: PathBuf,
    shares: PathBuf,
    token_file: PathBuf,
    bundle: PathBuf,
    digest: String,
}
fn write_private(path: &Path, bytes: &[u8]) -> TestResult {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn request(
    service: &mut Service,
    method: &str,
    path: &str,
    token: &str,
    body: serde_json::Value,
) -> Response {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(30),
    );
    service.handle(method, path, "", token, body)
}
fn bundle() -> serde_json::Value {
    let mut entries = serde_json::Map::new();
    for n in 0..40 {
        entries.insert(format!("item-{n:03}"), json!({
            "created_time":"1970-01-01T00:01:30.000000113Z",
            "updated_time":"1970-01-01T00:01:35.000000113Z",
            "current_version":3,"oldest_version":0,"current_metadata_version":2,
            "max_versions":3,"cas_required":true,"metadata_cas_required":true,
            "delete_version_after":"0s","custom_metadata":{"owner":"offline-fixture"},
            "versions":{
                "1":{"created_time":"1970-01-01T00:01:30.000000113Z","deletion_time":"","destroyed":true,"data":null},
                "2":{"created_time":"1970-01-01T00:01:33.000000113Z","deletion_time":"1970-01-01T00:01:36.000000113Z","destroyed":false,"data":{"old":n}},
                "3":{"created_time":"1970-01-01T00:01:35.000000113Z","deletion_time":"","destroyed":false,"data":{"ordinal":n,"payload":"offline-secret-sentinel".repeat(200)}}
            }
        }));
    }
    json!({"schema":"openbao270-kv2-lossless-v1",
        "config":{"max_versions":3,"cas_required":false,"metadata_cas_required":true,"delete_version_after":"0s"},
        "entries":entries})
}
impl Fixture {
    fn new() -> TestResult<Self> {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, token) = bootstrap(&mut service)?;
        drop(service);
        let data = root.path.join("data");
        let audit = root.path.join("audit.jsonl");
        let mut service = root.service()?;
        service.configure_native_v6_storage(NativeStorageProfile::File)?;
        assert_eq!(
            request(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        assert_eq!(
            request(
                &mut service,
                "POST",
                "sys/storage/native-v6/activate",
                &token,
                json!({})
            )
            .status,
            204
        );
        assert!(service.native_root.is_some());
        let mut issued = request(
            &mut service,
            "POST",
            "auth/token/create",
            &token,
            json!({"policies":["default"],"ttl":"10m"}),
        );
        assert_eq!(issued.status, 200);
        erase_json(&mut issued.body);
        assert!(
            service
                .state
                .as_ref()
                .unwrap()
                .has_token_api_precision_state()
        );
        drop(service);
        let shares = root.path.join("shares.json");
        let token_file = root.path.join("token.txt");
        let bundle_path = root.path.join("bundle.json");
        write_private(&shares, &serde_json::to_vec(&vec![key.as_str()])?)?;
        write_private(&token_file, token.as_bytes())?;
        let encoded = serde_json::to_vec(&bundle())?;
        let digest = hex(Sha256::digest(&encoded).as_ref());
        write_private(&bundle_path, &encoded)?;
        Ok(Self {
            root,
            key: Zeroizing::new(key),
            token: Zeroizing::new(token),
            data,
            audit,
            shares,
            token_file,
            bundle: bundle_path,
            digest,
        })
    }
    fn options(&self) -> OfflineKv2Import<'_> {
        OfflineKv2Import {
            data_dir: &self.data,
            audit_path: &self.audit,
            shares_path: &self.shares,
            token_path: &self.token_file,
            bundle_path: &self.bundle,
            mount: "secret",
            bundle_sha256: &self.digest,
            budget_seconds: None,
        }
    }
    fn reopen(&self) -> TestResult<Service> {
        let mut service = self.root.service()?;
        service.configure_native_v6_storage(NativeStorageProfile::File)?;
        assert_eq!(
            request(
                &mut service,
                "POST",
                "sys/unseal",
                "",
                json!({"key":self.key.as_str()})
            )
            .status,
            200
        );
        Ok(service)
    }
    fn files(&self) -> TestResult<Vec<Vec<u8>>> {
        ["state.hbs", "journal.hbj", "ledger.hbl", "seal.json"]
            .into_iter()
            .map(|name| fs::read(self.data.join(name)).map_err(Into::into))
            .collect()
    }
}
fn snapshot(
    service: &mut Service,
    token: &str,
    method: &str,
) -> TestResult<Box<crate::service::PendingExternalRequest>> {
    match service.begin_native_snapshot_before(
        ServiceRequest::new(method, "sys/storage/raft/snapshot", "", token, json!({})),
        Instant::now() + Duration::from_secs(30),
    ) {
        NativeSnapshotAdmission::Execute(RequestExecution::External(pending)) => Ok(pending),
        _ => Err("snapshot admission failed".into()),
    }
}
fn assert_imported(service: &mut Service, token: &str) {
    for n in [0, 19, 39] {
        let value = request(
            service,
            "GET",
            &format!("secret/data/item-{n:03}"),
            token,
            json!({}),
        );
        assert_eq!(value.status, 200);
        assert_eq!(value.body["data"]["data"]["ordinal"], json!(n));
        assert_eq!(value.body["data"]["metadata"]["version"], json!(3));
        assert_eq!(
            request(
                service,
                "GET",
                &format!("secret/data/item-{n:03}"),
                token,
                json!({"version":1})
            )
            .status,
            404
        );
        assert_eq!(
            request(
                service,
                "GET",
                &format!("secret/data/item-{n:03}"),
                token,
                json!({"version":2})
            )
            .status,
            404
        );
    }
}

#[test]
fn offline_native_import_real_file_cold_reopen_and_snapshot_preserve_history() -> TestResult {
    let fixture = Fixture::new()?;
    let receipt = import_kv2(fixture.options())?;
    let encoded = serde_json::to_string(&receipt)?;
    assert!(encoded.contains("offline-native-import"));
    assert!(receipt.complete_cold_graph_verified);
    // Native Shamir unseal uses LocalUnsealCompletion: it authenticates the
    // exact local owner through mandatory audit without a terminal clock write.
    // The separate observer test exercises a real clock write via seal-status.
    assert!(!receipt.cold_auth_clock_advance_verified);
    assert_eq!(receipt.cold_generation, receipt.committed_generation);
    assert_eq!(receipt.cold_root_identity, receipt.committed_root_identity);
    assert_eq!(receipt.cold_root_sha256, receipt.committed_root_sha256);
    assert!(!receipt.http_latency_qualified && !receipt.ha_qualified);
    for secret in [
        fixture.key.as_str(),
        fixture.token.as_str(),
        "offline-secret-sentinel",
    ] {
        assert!(!encoded.contains(secret));
    }
    let mut service = fixture.reopen()?;
    // Reconcile the receipt through another independent real cold owner before
    // any ordinary read is allowed to publish its own Auth clock observation.
    assert_eq!(
        hex(&service
            .current_state_identity()
            .map_err(|_| "cold identity")?
            .digest()),
        receipt.cold_root_identity
    );
    {
        let durable = service.durable.as_ref().ok_or("cold durable owner")?;
        assert_eq!(durable.generation(), receipt.cold_generation);
        let published = durable.get("system", "state")?.ok_or("cold native root")?;
        assert_eq!(
            hex(Sha256::digest(published.expose()).as_ref()),
            receipt.cold_root_sha256
        );
    }
    assert_imported(&mut service, &fixture.token);
    let mut pending = snapshot(&mut service, &fixture.token, "GET")?;
    let (result, file) = pending.execute_snapshot_transfer(&mut io::empty());
    assert_eq!(
        service.finish_external_request(*pending, result).status,
        200
    );
    let mut archive = Zeroizing::new(Vec::new());
    file.ok_or("snapshot absent")?.read_to_end(&mut archive)?;
    assert_eq!(
        request(
            &mut service,
            "POST",
            "secret/data/item-000",
            &fixture.token,
            json!({"options":{"cas":3},"data":{"discard":"later"}})
        )
        .status,
        200
    );
    let mut pending = snapshot(&mut service, &fixture.token, "POST")?;
    let (result, file) = pending.execute_snapshot_transfer(&mut &archive[..]);
    assert!(file.is_none());
    assert_eq!(
        service.finish_external_request(*pending, result).status,
        200
    );
    drop(service);
    let mut service = fixture.reopen()?;
    assert_imported(&mut service, &fixture.token);
    assert_eq!(
        request(
            &mut service,
            "POST",
            "secret/undelete/item-000",
            &fixture.token,
            json!({"versions":[1,2]})
        )
        .status,
        204
    );
    assert_eq!(
        request(
            &mut service,
            "GET",
            "secret/data/item-000",
            &fixture.token,
            json!({"version":1})
        )
        .status,
        404
    );
    let recovered = request(
        &mut service,
        "GET",
        "secret/data/item-000",
        &fixture.token,
        json!({"version":2}),
    );
    assert_eq!(recovered.status, 200);
    assert_eq!(recovered.body["data"]["data"]["old"], json!(0));
    Ok(())
}

#[test]
fn offline_native_import_wrong_digest_and_changed_original_fd_keep_storage_unchanged() -> TestResult
{
    let fixture = Fixture::new()?;
    let original = fixture.files()?;
    let wrong = "0".repeat(64);
    let mut options = fixture.options();
    options.bundle_sha256 = &wrong;
    assert!(matches!(
        import_kv2(options),
        Err(OfflineImportError::DigestMismatch)
    ));
    assert_eq!(fixture.files()?, original);
    let start = Instant::now();
    let result = import_before(
        fixture.options(),
        start,
        start + Duration::from_secs(30),
        |phase| {
            if phase == Phase::BundleVerified {
                let mut file = OpenOptions::new()
                    .write(true)
                    .open(&fixture.bundle)
                    .unwrap();
                file.write_all(b"!").unwrap();
                file.sync_all().unwrap();
            }
        },
    );
    assert!(matches!(result, Err(OfflineImportError::InputChanged)));
    assert_eq!(fixture.files()?, original);
    Ok(())
}

#[test]
fn offline_native_import_rejects_changed_input_after_real_graph_preparation() -> TestResult {
    let fixture = Fixture::new()?;
    let original = {
        let service = fixture.reopen()?;
        service.native_root.as_ref().unwrap().kv2[0].root.clone()
    };
    let start = Instant::now();
    let result = import_before(
        fixture.options(),
        start,
        start + Duration::from_secs(30),
        |phase| {
            if phase == Phase::GraphPrepared {
                let mut file = OpenOptions::new()
                    .write(true)
                    .open(&fixture.bundle)
                    .unwrap();
                file.write_all(b"!").unwrap();
                file.sync_all().unwrap();
            }
        },
    );
    assert!(matches!(result, Err(OfflineImportError::InputChanged)));
    let service = fixture.reopen()?;
    assert_eq!(service.native_root.as_ref().unwrap().kv2[0].root, original);
    Ok(())
}

#[test]
fn offline_native_import_original_deadline_survives_graph_preparation() -> TestResult {
    let fixture = Fixture::new()?;
    let original = {
        let service = fixture.reopen()?;
        service.native_root.as_ref().unwrap().kv2[0].root.clone()
    };
    let start = Instant::now();
    let until = start + Duration::from_secs(15);
    let mut observed = false;
    let result = import_before(fixture.options(), start, until, |phase| {
        if phase == Phase::GraphPrepared {
            observed = true;
            std::thread::sleep(
                until.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
            );
        }
    });
    assert!(
        observed,
        "real graph preparation must run before the deadline observation"
    );
    assert!(matches!(result, Err(OfflineImportError::Deadline)));
    assert!(crate::request_deadline::current().is_none());
    let service = fixture.reopen()?;
    assert_eq!(service.native_root.as_ref().unwrap().kv2[0].root, original);
    Ok(())
}

#[test]
fn offline_native_import_after_commit_failure_retains_unknown_outcome() -> TestResult {
    let fixture = Fixture::new()?;
    let start = Instant::now();
    let mut committed = false;
    let result = import_before(
        fixture.options(),
        start,
        start + Duration::from_secs(30),
        |phase| {
            if phase == Phase::Committed {
                committed = true;
                fs::set_permissions(&fixture.token_file, fs::Permissions::from_mode(0o640))
                    .unwrap();
            }
        },
    );
    assert!(committed);
    assert!(matches!(result, Err(OfflineImportError::OutcomeUnknown)));
    let mut service = fixture.reopen()?;
    assert_imported(&mut service, &fixture.token);
    assert!(
        OfflineImportError::OutcomeUnknown
            .to_string()
            .contains("do not blindly retry")
    );
    Ok(())
}

#[test]
fn offline_native_import_rejects_real_concurrent_auth_write_between_cold_owners() -> TestResult {
    let fixture = Fixture::new()?;
    let start = Instant::now();
    let mut wrote = false;
    let result = import_before(
        fixture.options(),
        start,
        start + Duration::from_secs(60),
        |phase| {
            if phase == Phase::RawColdVerified {
                let mut other = fixture.reopen().unwrap();
                assert_eq!(
                    request(
                        &mut other,
                        "PUT",
                        "sys/policies/acl/intervening",
                        &fixture.token,
                        json!({"policy":"path \"secret/data/allowed\" { capabilities=[\"read\"] }"})
                    )
                    .status,
                    204
                );
                wrote = true;
            }
        },
    );
    assert!(
        wrote,
        "an actual separately opened writer must commit the Auth change"
    );
    assert!(matches!(result, Err(OfflineImportError::OutcomeUnknown)));
    let mut service = fixture.reopen()?;
    assert_imported(&mut service, &fixture.token);
    assert_eq!(
        request(
            &mut service,
            "GET",
            "sys/policies/acl/intervening",
            &fixture.token,
            json!({})
        )
        .status,
        200
    );
    Ok(())
}

#[test]
fn offline_clock_observation_refuses_wrong_before_nested_owner_and_multiple_writes() -> TestResult {
    let fixture = Fixture::new()?;
    let mut service = fixture.reopen()?;
    let initial = (
        service.current_state_identity().map_err(|_| "identity")?,
        service
            .external_effect_generation()
            .map_err(|_| "generation")?,
    );
    let valid = token_precision::offline::Scope::enter(&service, initial).map_err(|_| "scope")?;
    let mut response = request(&mut service, "GET", "sys/seal-status", "", json!({}));
    assert_eq!(response.status, 200);
    erase_json(&mut response.body);
    assert_eq!(
        valid.finish(&service),
        Ok(true),
        "one actual owner clock receipt must advance the exact checkpoint"
    );
    let old = (
        service.current_state_identity().map_err(|_| "identity")?,
        service
            .external_effect_generation()
            .map_err(|_| "generation")?,
    );
    let mut response = request(&mut service, "GET", "sys/seal-status", "", json!({}));
    assert_eq!(response.status, 200);
    erase_json(&mut response.body);
    let scope = token_precision::offline::Scope::enter(&service, old).map_err(|_| "scope")?;
    let mut response = request(&mut service, "GET", "sys/seal-status", "", json!({}));
    assert_eq!(response.status, 200);
    erase_json(&mut response.body);
    assert!(
        scope.finish(&service).is_err(),
        "wrong original before cannot advance"
    );
    let current = (
        service.current_state_identity().map_err(|_| "identity")?,
        service
            .external_effect_generation()
            .map_err(|_| "generation")?,
    );
    let scope = token_precision::offline::Scope::enter(&service, current).map_err(|_| "scope")?;
    assert!(token_precision::offline::Scope::enter(&service, current).is_err());
    assert!(
        scope.finish(&service).is_err(),
        "a nested scope invalidates the original capture"
    );
    let current = (
        service.current_state_identity().map_err(|_| "identity")?,
        service
            .external_effect_generation()
            .map_err(|_| "generation")?,
    );
    let scope = token_precision::offline::Scope::enter(&service, current).map_err(|_| "scope")?;
    for _ in 0..2 {
        let mut response = request(&mut service, "GET", "sys/seal-status", "", json!({}));
        assert_eq!(response.status, 200);
        erase_json(&mut response.body);
    }
    assert!(
        scope.finish(&service).is_err(),
        "more than one actual clock publication is refused"
    );
    let foreign = Fixture::new()?;
    let mut other = foreign.reopen()?;
    let current = (
        service.current_state_identity().map_err(|_| "identity")?,
        service
            .external_effect_generation()
            .map_err(|_| "generation")?,
    );
    let scope = token_precision::offline::Scope::enter(&service, current).map_err(|_| "scope")?;
    let mut response = request(&mut other, "GET", "sys/seal-status", "", json!({}));
    assert_eq!(response.status, 200);
    erase_json(&mut response.body);
    assert!(
        scope.finish(&service).is_err(),
        "another real Service instance cannot feed the collector"
    );
    Ok(())
}

#[test]
fn offline_native_import_rejects_symlinks_hardlinks_foreign_mode_and_active_writer() -> TestResult {
    let fixture = Fixture::new()?;
    let original = fixture.files()?;
    let linked = fixture.root.path.join("linked-bundle");
    std::os::unix::fs::symlink(&fixture.bundle, &linked)?;
    let mut options = fixture.options();
    options.bundle_path = &linked;
    assert!(matches!(
        import_kv2(options),
        Err(OfflineImportError::UnsafeOwner)
    ));
    fs::remove_file(&linked)?;
    fs::hard_link(&fixture.bundle, &linked)?;
    assert!(matches!(
        import_kv2(fixture.options()),
        Err(OfflineImportError::UnsafeOwner)
    ));
    fs::remove_file(&linked)?;
    fs::set_permissions(&fixture.bundle, fs::Permissions::from_mode(0o640))?;
    assert!(matches!(
        import_kv2(fixture.options()),
        Err(OfflineImportError::UnsafeOwner)
    ));
    fs::set_permissions(&fixture.bundle, fs::Permissions::from_mode(0o600))?;
    assert_eq!(fixture.files()?, original);
    let writer = heptabao_filesystem_guard::ExclusiveDirectory::open(&fixture.data)?;
    assert!(import_kv2(fixture.options()).is_err());
    writer.verify()?;
    assert_eq!(fixture.files()?, original);
    Ok(())
}

#[test]
fn offline_native_import_rejects_budget_changes_and_keeps_error_output_secret_free() -> TestResult {
    let fixture = Fixture::new()?;
    let original = fixture.files()?;
    for seconds in [0, MAX_OFFLINE_IMPORT_SECONDS + 1] {
        let mut options = fixture.options();
        options.budget_seconds = Some(seconds);
        assert!(matches!(
            import_kv2(options),
            Err(OfflineImportError::InvalidInput)
        ));
    }
    {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(1),
        );
        assert!(matches!(
            import_kv2(fixture.options()),
            Err(OfflineImportError::InvalidInput)
        ));
    }
    assert_eq!(fixture.files()?, original);
    fs::write(&fixture.token_file, b"private-rejected-token-value")?;
    let error = match import_kv2(fixture.options()) {
        Ok(_) => return Err("unexpected successful token".into()),
        Err(error) => error,
    };
    let rendered = format!("{error:?}: {error}");
    for secret in [
        "private-rejected-token-value",
        fixture.key.as_str(),
        fixture.token.as_str(),
        "offline-secret-sentinel",
    ] {
        assert!(!rendered.contains(secret));
    }
    Ok(())
}
