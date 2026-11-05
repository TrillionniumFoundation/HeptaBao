//! Real formal File service with a one-shot interruption after the actual
//! authenticated retirement transaction, followed by same-data cold reopening.
use super::*;
use heptabao_durable_service::{
    BackendBundle, BackendError, BlobLocator, DurableBackend, FileBackend, ImmutableBlobProfile,
    ImmutableBlobReadPin, ImmutableBlobStage, PreparedImmutableRetirement, RestoreProfile,
};
use std::sync::atomic::{AtomicUsize, Ordering};

struct StopBeforePhysical {
    inner: FileBackend,
    entered: Arc<AtomicUsize>,
}
impl DurableBackend for StopBeforePhysical {
    fn verify(&self) -> Result<(), BackendError> {
        self.inner.verify()
    }
    fn verify_live_ownership(&mut self) -> Result<(), BackendError> {
        self.inner.verify_live_ownership()
    }
    fn immutable_blob_profile(&self) -> Result<ImmutableBlobProfile, BackendError> {
        self.inner.immutable_blob_profile()
    }
    fn stage_immutable_ciphertext(
        &mut self,
        locator: BlobLocator,
        bytes: &[u8],
    ) -> Result<ImmutableBlobStage, BackendError> {
        self.inner.stage_immutable_ciphertext(locator, bytes)
    }
    fn stage_immutable_ciphertext_checked(
        &mut self,
        locator: BlobLocator,
        bytes: &[u8],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<ImmutableBlobStage, BackendError> {
        self.inner
            .stage_immutable_ciphertext_checked(locator, bytes, gate)
    }
    fn stage_immutable_ciphertext_batch_checked(
        &mut self,
        objects: &[(BlobLocator, &[u8])],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<Vec<ImmutableBlobStage>, BackendError> {
        self.inner
            .stage_immutable_ciphertext_batch_checked(objects, gate)
    }
    fn stage_new_immutable_ciphertext_batch_checked(
        &mut self,
        objects: &[(BlobLocator, &[u8])],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<Option<Vec<ImmutableBlobReadPin>>, BackendError> {
        self.inner
            .stage_new_immutable_ciphertext_batch_checked(objects, gate)
    }
    fn stage_immutable_ciphertext_batch_with_io_gate(
        &mut self,
        objects: &[(BlobLocator, &[u8])],
        full_gate: &mut dyn FnMut() -> Result<(), BackendError>,
        io_gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<Vec<ImmutableBlobStage>, BackendError> {
        self.inner
            .stage_immutable_ciphertext_batch_with_io_gate(objects, full_gate, io_gate)
    }
    fn pin_immutable_ciphertext(
        &self,
        locator: BlobLocator,
        length: usize,
    ) -> Result<ImmutableBlobReadPin, BackendError> {
        self.inner.pin_immutable_ciphertext(locator, length)
    }
    fn reuse_immutable_ciphertext_checked(
        &mut self,
        locator: BlobLocator,
        length: usize,
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<Option<ImmutableBlobReadPin>, BackendError> {
        self.inner
            .reuse_immutable_ciphertext_checked(locator, length, gate)
    }
    fn reuse_immutable_ciphertext_batch_checked(
        &mut self,
        objects: &[(BlobLocator, usize)],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<Vec<Option<ImmutableBlobReadPin>>, BackendError> {
        self.inner
            .reuse_immutable_ciphertext_batch_checked(objects, gate)
    }
    fn prepare_immutable_retirement(
        &mut self,
        objects: &[(BlobLocator, usize)],
        auth: &mut dyn FnMut(usize, &[u8]) -> Result<(), BackendError>,
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<PreparedImmutableRetirement, BackendError> {
        self.inner.prepare_immutable_retirement(objects, auth, gate)
    }
    fn retire_prepared_immutable_ciphertexts(
        &mut self,
        prepared: PreparedImmutableRetirement,
        _auth: &mut dyn FnMut(usize, &[u8]) -> Result<(), BackendError>,
        _gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<(), BackendError> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        drop(prepared);
        // This exact call is reachable only after the actual metadata commit.
        // No fixture marker, alternate graph or original unlink is fabricated.
        Err(BackendError::OutcomeUnknown)
    }
    fn confirm_immutable_retirement_absent(
        &mut self,
        objects: &[BlobLocator],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<(), BackendError> {
        self.inner
            .confirm_immutable_retirement_absent(objects, gate)
    }
    fn load(&mut self) -> Result<BackendBundle, BackendError> {
        self.inner.load()
    }
    fn initialize_empty(&mut self, bundle: &BackendBundle) -> Result<(), BackendError> {
        self.inner.initialize_empty(bundle)
    }
    fn append_journal(&mut self, expected: usize, frame: &[u8]) -> Result<usize, BackendError> {
        self.inner.append_journal(expected, frame)
    }
    fn truncate_journal(&mut self, expected: usize, length: usize) -> Result<(), BackendError> {
        self.inner.truncate_journal(expected, length)
    }
    fn publish_checkpoint(
        &mut self,
        expected: &BackendBundle,
        replacement: &BackendBundle,
    ) -> Result<(), BackendError> {
        self.inner.publish_checkpoint(expected, replacement)
    }
    fn restore_profile(&self) -> Result<RestoreProfile, BackendError> {
        self.inner.restore_profile()
    }
    fn close(self) -> Result<(), BackendError> {
        self.inner.close()
    }
}

#[test]
fn native_file_gc_reconciliation_formal_cold_present_requires_fresh_actual_root_request()
-> TestResult {
    let (root, mut service, key, token) = fixture()?;
    let expected = history(&mut service, &token)?;
    let original_files = selected_files(&service)?;
    let barrier = Zeroizing::new(
        **service
            .barrier_key
            .as_ref()
            .ok_or("actual barrier absent")?,
    );
    drop(service.durable.take().ok_or("actual File owner absent")?);
    let entered = Arc::new(AtomicUsize::new(0));
    let backend: Box<dyn DurableBackend> = Box::new(StopBeforePhysical {
        inner: FileBackend::open(&service.data_dir)?,
        entered: Arc::clone(&entered),
    });
    service.durable = Some(DurableService::reopen_with_backend(
        backend,
        AeadBarrier::new(*barrier)?,
        MAX_OPERATIONS,
    )?);
    let original_failed = call(&mut service, "POST", PATH, &token, json!({}));
    assert_eq!(original_failed.status, 503);
    assert_eq!(entered.load(Ordering::SeqCst), 1);
    assert!(service.recovery_required);
    assert!(original_files.iter().all(|file| file.exists()));
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
    let status = call(&mut cold, "GET", PATH, &token, json!({}));
    assert_eq!(status.status, 200);
    let pending = &status.body["data"]["retirement"];
    assert_eq!(pending["pending"], true);
    assert_eq!(pending["phase"], "pending");
    let original_digest = pending["record_sha256"]
        .as_str()
        .ok_or("actual pending SHA absent")?
        .to_owned();
    assert_eq!(pending["original_pending_sha256"], original_digest);
    assert_eq!(pending["historical_request_outcome_reclassified"], false);
    let selected = pending["selected_objects"]
        .as_u64()
        .ok_or("selection count absent")?;
    assert!(selected > 0 && selected <= 32);
    assert_eq!(call(&mut cold, "POST", PATH, &token, json!({})).status, 503);
    assert!(!cold.recovery_required);
    assert!(original_files.iter().all(|file| file.exists()));
    assert_eq!(
        call(
            &mut cold,
            "POST",
            RECONCILE_PATH,
            &token,
            json!({"expected_pending_sha256":"0".repeat(64)})
        )
        .status,
        409
    );
    assert!(original_files.iter().all(|file| file.exists()));
    let response = call(
        &mut cold,
        "POST",
        RECONCILE_PATH,
        &token,
        json!({"expected_pending_sha256":original_digest}),
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.body["data"]["removed_objects"], selected);
    assert_eq!(response.body["data"]["confirmed_absent_objects"], 0);
    assert_eq!(
        response.body["data"]["retirement"]["phase"],
        "reconciliation-completed"
    );
    assert_eq!(
        response.body["data"]["retirement"]["original_pending_sha256"],
        original_digest
    );
    assert_eq!(
        response.body["data"]["retirement"]["original_completion_recorded"],
        false
    );
    assert_eq!(
        response.body["data"]["historical_request_outcome_reclassified"],
        false
    );
    assert_eq!(original_failed.status, 503); // the original result is retained
    let removed = original_files.iter().filter(|file| !file.exists()).count();
    assert_eq!(removed as u64, selected);
    assert_eq!(history(&mut cold, &token)?, expected);
    assert!(cold.pending_native_file_gc.is_none());
    assert!(!cold.recovery_required);
    drop(cold);

    let mut again = root.service()?;
    again.configure_native_v6_storage(NativeStorageProfile::File)?;
    assert_eq!(
        call(
            &mut again,
            "POST",
            "sys/unseal",
            "",
            json!({"key":key.as_str()})
        )
        .status,
        200
    );
    assert_eq!(history(&mut again, &token)?, expected);
    let status = call(&mut again, "GET", PATH, &token, json!({}));
    assert_eq!(status.status, 200);
    assert_eq!(
        status.body["data"]["retirement"]["phase"],
        "reconciliation-completed"
    );
    assert_eq!(
        status.body["data"]["retirement"]["original_pending_sha256"],
        original_digest
    );
    assert_eq!(
        call(
            &mut again,
            "POST",
            "secret/data/history",
            &token,
            json!({"data":value(4),"options":{"cas":3}})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut again, "POST", PATH, &token, json!({})).status,
        200
    );
    Ok(())
}

#[test]
fn native_file_gc_reconciliation_status_and_exact_body_keep_root_authority() -> TestResult {
    let (_root, mut service, _key, token) = fixture()?;
    let status = call(&mut service, "GET", PATH, &token, json!({}));
    assert_eq!(status.status, 200);
    assert!(status.body["data"]["retirement"].is_null());
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
        call(&mut service, "GET", PATH, &child, json!({})).status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            RECONCILE_PATH,
            &child,
            json!({"expected_pending_sha256":"0".repeat(64)})
        )
        .status,
        403
    );
    for body in [
        json!({}),
        json!({"expected_pending_sha256":"0".repeat(63)}),
        json!({"expected_pending_sha256":"A".repeat(64)}),
        json!({"expected_pending_sha256":"0".repeat(64),"paths":["unrelated"]}),
    ] {
        assert_eq!(
            call(&mut service, "POST", RECONCILE_PATH, &token, body).status,
            400
        );
    }
    assert_eq!(
        call(
            &mut service,
            "POST",
            RECONCILE_PATH,
            &token,
            json!({"expected_pending_sha256":"0".repeat(64)})
        )
        .status,
        409
    );
    assert!(before.iter().all(|file| file.exists()));
    assert!(service.pending_native_file_gc.is_none());
    assert!(!service.recovery_required);
    Ok(())
}
