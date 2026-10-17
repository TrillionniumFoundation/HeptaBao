//! Populated V5 migration through real Service writes, locator journals,
//! barrier encryption, snapshot authority and cold recovery. Synthetic data only.
use super::*;
use crate::service::tests::{Root, bootstrap};
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ENTRIES: usize = 112;
const HISTORY: &str = "secret/data/migration-history";

fn call(service: &mut Service, method: &str, path: &str, token: &str, body: Value) -> Response {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(30),
    );
    let response = service.handle(method, path, "", token, body);
    if response.status >= 400 {
        let errors: Vec<_> = response
            .body
            .get("errors")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        eprintln!(
            "native migration {path}: HTTP {} errors={errors:?}",
            response.status
        );
    }
    response
}

fn initialized() -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
    let files = Root::new();
    let mut service = files.service()?;
    service.configure_native_v6_candidate()?;
    let (key, token) = {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(30),
        );
        bootstrap(&mut service)?
    };
    Ok((files, service, Zeroizing::new(key), Zeroizing::new(token)))
}

fn reopen(files: &Root, key: &str) -> TestResult<Service> {
    let mut service = files.service()?;
    service.configure_native_v6_candidate()?;
    assert_eq!(
        call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    assert!(!service.recovery_required);
    Ok(service)
}

fn populate(service: &mut Service, token: &str) -> TestResult<Value> {
    for index in 0..ENTRIES {
        assert_eq!(
            call(
                service,
                "POST",
                &format!("secret/data/migration-bulk/{index:03}"),
                token,
                json!({"options":{"cas":0},"data":{"index":index,"padding":"p".repeat(2048)}})
            )
            .status,
            200
        );
    }
    for version in 1..=4 {
        let response = call(
            service,
            "POST",
            HISTORY,
            token,
            json!({"options":{"cas":version-1},"data":{"version":version,"source":"populated-v5"}}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["version"], version);
    }
    assert_eq!(
        call(
            service,
            "POST",
            "secret/delete/migration-history",
            token,
            json!({"versions":[2]})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            service,
            "POST",
            "secret/destroy/migration-history",
            token,
            json!({"versions":[1]})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            service,
            "POST",
            "secret/metadata/migration-history",
            token,
            json!({"cas_required":true,"custom_metadata":{"migration":"preserve-history"}})
        )
        .status,
        204
    );
    let mut response = call(
        service,
        "GET",
        "secret/metadata/migration-history",
        token,
        json!({}),
    );
    assert_eq!(response.status, 200);
    assert!(service.record_root.is_some());
    assert!(service.native_root.is_none());
    Ok(response.body.take())
}

fn assert_history(service: &mut Service, token: &str, metadata: &Value) {
    let observed = call(
        service,
        "GET",
        "secret/metadata/migration-history",
        token,
        json!({}),
    );
    assert_eq!(observed.status, 200);
    assert_eq!(&observed.body, metadata);
    for version in 1..=4 {
        let response = call(service, "GET", HISTORY, token, json!({"version":version}));
        assert_eq!(response.status, if version <= 2 { 404 } else { 200 });
        if version > 2 {
            assert_eq!(response.body["data"]["data"]["version"], version);
            assert_eq!(response.body["data"]["data"]["source"], "populated-v5");
        }
    }
    for index in [0, ENTRIES / 2, ENTRIES - 1] {
        let response = call(
            service,
            "GET",
            &format!("secret/data/migration-bulk/{index:03}"),
            token,
            json!({}),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["data"]["data"]["index"], index);
        assert!(
            response.body["data"]["data"]["padding"]
                .as_str()
                .is_some_and(|value| value.len() == 2048)
        );
    }
}

fn require_more_than_one_locator_batch(service: &mut Service) -> TestResult {
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(30),
    );
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    let plan = service
        .prepare_native_root_migration_paged(&|| Ok(()))
        .map_err(|_| "populated V5 plan rejected")?;
    let payloads = plan
        .objects
        .iter()
        .filter(|((domain, _), object)| {
            matches!(domain, crate::state_record_root_v6::ObjectDomain::Kv2(_))
                && object.reference().kind == crate::state_records::ObjectKind::Block
        })
        .count();
    assert!(
        payloads >= ENTRIES,
        "fixture did not create distinct actual payload objects"
    );
    assert!(plan.objects.len() > heptabao_durable_service::MAX_ATOMIC_MUTATIONS);
    assert_eq!(
        service.durable.as_ref().ok_or("durable")?.generation(),
        generation
    );
    Ok(())
}

fn activate(service: &mut Service, token: &str) {
    assert_eq!(
        call(
            service,
            "POST",
            "sys/internal/native-v6/activate",
            token,
            json!({})
        )
        .status,
        204
    );
    assert!(service.native_root.is_some());
    assert!(service.record_root.is_none());
}

#[test]
fn populated_v5_migration_exceeds_atomic_locator_limit_preserves_history_and_cold_root()
-> TestResult {
    let (files, mut service, key, token) = initialized()?;
    let metadata = populate(&mut service, &token)?;
    require_more_than_one_locator_batch(&mut service)?;
    let generation = service.durable.as_ref().ok_or("durable")?.generation();
    activate(&mut service, &token);
    assert!(service.durable.as_ref().ok_or("durable")?.generation() > generation + 1);
    assert_history(&mut service, &token, &metadata);
    let identity = service
        .current_state_identity()
        .map_err(|_| "native identity")?;
    drop(service);
    let mut service = reopen(&files, &key)?;
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "cold native identity")?,
        identity
    );
    assert_history(&mut service, &token, &metadata);
    let rejected = call(
        &mut service,
        "POST",
        HISTORY,
        &token,
        json!({"options":{"cas":3},"data":{"version":5}}),
    );
    assert_eq!(rejected.status, 400);
    assert_history(&mut service, &token, &metadata);
    let written = call(
        &mut service,
        "POST",
        HISTORY,
        &token,
        json!({"options":{"cas":4},"data":{"version":5,"source":"native-after-cold"}}),
    );
    assert_eq!(written.status, 200);
    assert_eq!(written.body["data"]["version"], 5);
    Ok(())
}

fn snapshot_request(
    service: &mut Service,
    token: &str,
    method: &str,
) -> TestResult<Box<PendingExternalRequest>> {
    let admitted = service.begin_native_snapshot_before(
        ServiceRequest::new(method, "sys/storage/raft/snapshot", "", token, json!({})),
        Instant::now() + Duration::from_secs(30),
    );
    match admitted {
        NativeSnapshotAdmission::Execute(RequestExecution::External(plan)) => Ok(plan),
        NativeSnapshotAdmission::Execute(RequestExecution::Complete(response)) => {
            let errors: Vec<_> = response
                .body
                .get("errors")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            Err(format!(
                "migration snapshot admission HTTP {} errors={errors:?}",
                response.status
            )
            .into())
        }
        NativeSnapshotAdmission::Redirect(_) => {
            Err("isolated snapshot unexpectedly redirected".into())
        }
    }
}

fn download(service: &mut Service, token: &str) -> TestResult<Vec<u8>> {
    let mut request = snapshot_request(service, token, "GET")?;
    let (result, file) = request.execute_snapshot_transfer(&mut io::empty());
    assert_eq!(
        service.finish_external_request(*request, result).status,
        200
    );
    let mut output = Vec::new();
    file.ok_or("snapshot download file")?
        .read_to_end(&mut output)?;
    Ok(output)
}

fn upload(service: &mut Service, token: &str, bytes: &[u8]) -> TestResult {
    let mut request = snapshot_request(service, token, "POST")?;
    let (result, file) = request.execute_snapshot_transfer(&mut &bytes[..]);
    assert!(file.is_none());
    assert_eq!(
        service.finish_external_request(*request, result).status,
        200
    );
    Ok(())
}

fn ciphertext_files(service: &Service) -> TestResult<BTreeMap<PathBuf, [u8; 32]>> {
    let mut observed = BTreeMap::new();
    for entry in fs::read_dir(&service.data_dir)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().ends_with(".hbo") {
            observed.insert(entry.path(), crypto::digest(&fs::read(entry.path())?));
        }
    }
    Ok(observed)
}

// Only this fixture's real, barrier-authenticated first locator Apply loses
// its acknowledgement, after the actual file append and fsync. No root Apply
// is reached; frame counting and invented logical service mutations are unused.
struct LostLocatorApplyAck {
    inner: heptabao_durable_service::FileBackend,
    barrier: AeadBarrier,
    fired: Arc<AtomicBool>,
}
impl LostLocatorApplyAck {
    fn selected(&self, frame: &[u8]) -> Result<bool, heptabao_durable_service::BackendError> {
        use heptabao_durable_service::BackendError;
        let invalid = || BackendError::OutcomeUnknown;
        let word = |offset: usize| -> Result<usize, BackendError> {
            let bytes = frame.get(offset..offset + 4).ok_or_else(invalid)?;
            Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| invalid())?) as usize)
        };
        if frame.len().checked_sub(4) != Some(word(0)?) {
            return Err(invalid());
        }
        let end = 16usize.checked_add(word(12)?).ok_or_else(invalid)?;
        if end.checked_add(32) != Some(frame.len()) {
            return Err(invalid());
        }
        let mut context = b"heptabao.durable-service.journal.v2".to_vec();
        context.extend_from_slice(frame.get(4..12).ok_or_else(invalid)?);
        let plain = Zeroizing::new(
            heptabao_durable_service::Barrier::open(
                &self.barrier,
                &context,
                frame.get(16..end).ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?,
        );
        if plain.first() != Some(&5) {
            return Ok(false);
        }
        let mut offset = 1usize;
        for field_index in 0..3 {
            let length_end = offset.checked_add(4).ok_or_else(invalid)?;
            let length = u32::from_le_bytes(
                plain
                    .get(offset..length_end)
                    .ok_or_else(invalid)?
                    .try_into()
                    .map_err(|_| invalid())?,
            ) as usize;
            let end = length_end.checked_add(length).ok_or_else(invalid)?;
            let value = std::str::from_utf8(plain.get(length_end..end).ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
            if field_index == 2 {
                return Ok(
                    value.starts_with("native6-migration-") && value.ends_with("-locators-0")
                );
            }
            offset = end;
        }
        Ok(false)
    }
}
impl heptabao_durable_service::DurableBackend for LostLocatorApplyAck {
    fn verify(&self) -> Result<(), heptabao_durable_service::BackendError> {
        self.inner.verify()
    }
    fn verify_live_ownership(&mut self) -> Result<(), heptabao_durable_service::BackendError> {
        self.inner.verify_live_ownership()
    }
    fn immutable_blob_profile(
        &self,
    ) -> Result<
        heptabao_durable_service::ImmutableBlobProfile,
        heptabao_durable_service::BackendError,
    > {
        self.inner.immutable_blob_profile()
    }
    fn stage_immutable_ciphertext_checked(
        &mut self,
        locator: heptabao_durable_service::BlobLocator,
        ciphertext: &[u8],
        gate: &mut dyn FnMut() -> Result<(), heptabao_durable_service::BackendError>,
    ) -> Result<heptabao_durable_service::ImmutableBlobStage, heptabao_durable_service::BackendError>
    {
        self.inner
            .stage_immutable_ciphertext_checked(locator, ciphertext, gate)
    }
    fn pin_immutable_ciphertext(
        &self,
        locator: heptabao_durable_service::BlobLocator,
        exact_len: usize,
    ) -> Result<
        heptabao_durable_service::ImmutableBlobReadPin,
        heptabao_durable_service::BackendError,
    > {
        self.inner.pin_immutable_ciphertext(locator, exact_len)
    }
    fn load(
        &mut self,
    ) -> Result<heptabao_durable_service::BackendBundle, heptabao_durable_service::BackendError>
    {
        self.inner.load()
    }
    fn initialize_empty(
        &mut self,
        initial: &heptabao_durable_service::BackendBundle,
    ) -> Result<(), heptabao_durable_service::BackendError> {
        self.inner.initialize_empty(initial)
    }
    fn append_journal(
        &mut self,
        expected_len: usize,
        frame: &[u8],
    ) -> Result<usize, heptabao_durable_service::BackendError> {
        let length = self.inner.append_journal(expected_len, frame)?;
        if self.selected(frame)? {
            self.fired.store(true, Ordering::SeqCst);
            return Err(heptabao_durable_service::BackendError::OutcomeUnknown);
        }
        Ok(length)
    }
    fn truncate_journal(
        &mut self,
        expected_len: usize,
        new_len: usize,
    ) -> Result<(), heptabao_durable_service::BackendError> {
        self.inner.truncate_journal(expected_len, new_len)
    }
    fn publish_checkpoint(
        &mut self,
        expected: &heptabao_durable_service::BackendBundle,
        replacement: &heptabao_durable_service::BackendBundle,
    ) -> Result<(), heptabao_durable_service::BackendError> {
        self.inner.publish_checkpoint(expected, replacement)
    }
    fn close(self) -> Result<(), heptabao_durable_service::BackendError> {
        self.inner.close()
    }
}

#[test]
fn interrupted_populated_v5_migration_keeps_root_repairs_snapshot_and_retries_after_restore()
-> TestResult {
    let (files, mut service, key, token) = initialized()?;
    let metadata = populate(&mut service, &token)?;
    require_more_than_one_locator_batch(&mut service)?;
    // A separate same-seal V5 target has no staged native ciphertext. It is
    // isolated and closed while copying the already committed fixture seed.
    let data_dir = service.data_dir.clone();
    drop(service);
    let target_files = Root::new();
    private_directory(&target_files.path)?;
    let target_data = target_files.path.join("data");
    private_directory(&target_data)?;
    for entry in fs::read_dir(&data_dir)? {
        let entry = entry?;
        assert!(entry.file_type()?.is_file());
        assert!(!entry.file_name().to_string_lossy().ends_with(".hbo"));
        fs::copy(entry.path(), target_data.join(entry.file_name()))?;
    }
    let mut service = reopen(&files, &key)?;
    let barrier = Zeroizing::new(**service.barrier_key.as_ref().ok_or("barrier")?);
    drop(service.durable.take().ok_or("durable")?);
    let fired = Arc::new(AtomicBool::new(false));
    let backend = LostLocatorApplyAck {
        inner: heptabao_durable_service::FileBackend::open(&data_dir)?,
        barrier: AeadBarrier::new(*barrier)?,
        fired: Arc::clone(&fired),
    };
    service.durable = Some(DurableService::reopen_with_backend(
        Box::new(backend) as Box<dyn heptabao_durable_service::DurableBackend>,
        AeadBarrier::new(*barrier)?,
        MAX_OPERATIONS,
    )?);
    let response = call(
        &mut service,
        "POST",
        "sys/internal/native-v6/activate",
        &token,
        json!({}),
    );
    assert!(
        fired.load(Ordering::SeqCst),
        "actual locator Apply fault did not fire"
    );
    assert_eq!(response.status, 503);
    assert!(service.recovery_required);
    assert!(service.native_root.is_none());
    drop(service);

    let mut service = reopen(&files, &key)?;
    assert!(service.native_root.is_none());
    assert!(service.record_root.is_some());
    assert_history(&mut service, &token, &metadata);
    assert!(
        service
            .durable
            .as_ref()
            .ok_or("durable")?
            .export_backup()
            .is_err(),
        "HBB2 must not silently omit external objects registered by an interrupted batch"
    );
    let physical_before = ciphertext_files(&service)?;
    assert!(physical_before.len() > heptabao_durable_service::MAX_ATOMIC_MUTATIONS);
    let identity = service
        .current_state_identity()
        .map_err(|_| "V5 identity")?;
    // A new real root-authorized snapshot request owns any staging repair.
    // The failed migration's expired/unknown authority is never reused.
    let archive = download(&mut service, &token)?;
    assert_eq!(
        service
            .current_state_identity()
            .map_err(|_| "repaired identity")?,
        identity
    );
    assert!(service.native_root.is_none());
    assert_eq!(
        ciphertext_files(&service)?,
        physical_before,
        "staging repair must preserve every physical ciphertext and V5 object"
    );
    assert_history(&mut service, &token, &metadata);
    assert!(
        service
            .durable
            .as_ref()
            .ok_or("durable")?
            .export_backup()
            .is_ok()
    );

    let mut target = reopen(&target_files, &key)?;
    assert!(ciphertext_files(&target)?.is_empty());
    assert_eq!(
        call(
            &mut target,
            "POST",
            HISTORY,
            &token,
            json!({"options":{"cas":4},"data":{"version":5,"source":"discarded-target-change"}})
        )
        .status,
        200
    );
    upload(&mut target, &token, &archive)?;
    assert_history(&mut target, &token, &metadata);
    assert!(target.native_root.is_none());
    assert!(ciphertext_files(&target)?.is_empty());
    activate(&mut target, &token);
    assert_history(&mut target, &token, &metadata);
    drop(target);
    let mut target = reopen(&target_files, &key)?;
    assert!(target.native_root.is_some());
    assert_history(&mut target, &token, &metadata);
    Ok(())
}
