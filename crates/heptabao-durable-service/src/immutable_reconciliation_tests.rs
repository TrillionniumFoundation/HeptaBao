//! Every pending record below comes from the real File journal transaction.
//! The interruptions drop only an acknowledgement or a post-Apply callback.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn cold_pending(label: &str) -> Result<(TestRoot, Owner, [u8; 32]), Box<dyn std::error::Error>> {
    let (root, mut owner) = fixture(label)?;
    let original = objects(&root)?;
    let stop = Stop::at(2);
    let req = request(&mut owner, "original-retirement")?;
    assert!(owner.retire_immutable_objects(req, &mut gate).is_err());
    assert!(owner.recovery_required());
    assert_eq!(objects(&root)?, original);
    drop(stop);
    drop(owner);
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    let status = cold
        .immutable_retirement_status()?
        .ok_or("actual pending status absent")?;
    assert!(status.pending);
    assert_eq!(status.phase, "pending");
    assert!(!status.original_completion_recorded);
    assert!(!status.historical_request_outcome_reclassified);
    assert_eq!(status.record_sha256, status.original_pending_sha256);
    Ok((root, cold, status.record_sha256))
}

#[test]
fn immutable_reconciliation_fresh_present_commit_cold_and_subsequent_gc() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner, original_digest) = cold_pending("reconciliation-present")?;
    let original = owner.backend.load()?;
    let original_files = objects(&root)?;
    let generation = owner.generation();
    let req = request(&mut owner, "ordinary-gc-still-holds")?;
    assert!(owner.retire_immutable_objects(req, &mut gate).is_err());
    assert_eq!(owner.backend.load()?, original);
    assert_eq!(objects(&root)?, original_files);
    let req = request(&mut owner, "fresh-explicit-reconciliation")?;
    let result = owner.reconcile_pending_immutable_retirement(req, original_digest, &mut gate)?;
    assert_eq!(result.generation, generation + 2);
    assert_eq!(result.removed_objects, 1);
    assert_eq!(result.confirmed_absent_objects, 0);
    assert!(!root.0.join(leaf(3)).exists());
    assert_eq!(read(&mut owner, 1)?, bytes(1));
    assert_eq!(read(&mut owner, 2)?, bytes(2));
    assert_eq!(fs::read(root.0.join(leaf(99)))?, original_files[3]);
    let status = owner
        .immutable_retirement_status()?
        .ok_or("new completion absent")?;
    assert_eq!(status.phase, "reconciliation-completed");
    assert!(!status.pending);
    assert_eq!(status.original_pending_sha256, original_digest);
    assert_eq!(status.reconciliation_attempt, 1);
    assert!(!status.original_completion_recorded);
    assert!(!status.historical_request_outcome_reclassified);
    let (_, record) = owner.retirement_record()?.ok_or("lineage absent")?;
    let lineage = record.lineage.ok_or("fresh lineage absent")?;
    assert_eq!(lineage.predecessor_digest, original_digest);
    assert_eq!(lineage.present_mask, 1);
    assert_ne!(lineage.descriptor_digest, [0; 32]);
    owner.close()?;
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(
        cold.immutable_retirement_status()?
            .ok_or("cold status absent")?,
        status
    );
    assert_eq!(read(&mut cold, 1)?, bytes(1));
    add(&mut cold, 4, true)?;
    let req = request(&mut cold, "later-independent-gc")?;
    assert_eq!(
        cold.retire_immutable_objects(req, &mut gate)?
            .removed_objects,
        1
    );
    assert!(!root.0.join(leaf(4)).exists());
    assert_eq!(read(&mut cold, 2)?, bytes(2));
    Ok(())
}

#[test]
fn immutable_reconciliation_stale_digest_session_pin_and_live_alias_refuse_without_effects()
-> TestResult {
    let _serial = serial_test();
    for kind in [
        "digest",
        "session",
        "pin",
        "root",
        "reachable",
        "physical-alias",
        "ciphertext",
    ] {
        let (root, mut owner, digest) = cold_pending(&format!("reconciliation-negative-{kind}"))?;
        let mut held: Option<Box<dyn Any>> = None;
        match kind {
            "session" => {
                held = Some(Box::new(
                    owner.immutable_source_session("system", "state", ROOT, STORE)?,
                ))
            }
            "pin" => {
                let marker = owner
                    .get("system", &resource(1))?
                    .ok_or("retained marker absent")?;
                let slot = Slot::decode(&resource(1), marker.expose())?;
                let session = owner.immutable_source_session("system", "state", ROOT, STORE)?;
                held = Some(Box::new(owner.pin_immutable_object_before_read(
                    &session,
                    slot.locator,
                    slot.ciphertext_bytes,
                    &mut gate,
                )?));
            }
            "physical-alias" => {
                let (_, record) = owner.retirement_record()?.ok_or("pending record absent")?;
                // A different resource points at the SAME selected physical
                // locator. The fresh full catalog scan must catch this ABA.
                let alias = resource(3).replacen("/kv2/", "/kv1/", 1);
                let decoded = Slot::decode(&alias, record.entries[0].marker.expose())?;
                assert!(decoded.locator == record.entries[0].slot.locator);
                put(
                    &mut owner,
                    &alias,
                    record.entries[0].marker.expose(),
                    "alias-metadata",
                )?;
            }
            "ciphertext" => {
                let path = root.0.join(leaf(3));
                let mut changed = fs::read(&path)?;
                changed[0] ^= 1;
                fs::write(path, changed)?;
            }
            _ => {}
        }
        let original = owner.backend.load()?;
        let original_files = objects(&root)?;
        let mut req = request(&mut owner, "refuse-fresh-attempt")?;
        if kind == "root" {
            req.conditions[0].expected = Some(Secret::new(b"foreign-root".to_vec())?);
        }
        if kind == "reachable" {
            req.retained_resources.insert(resource(3));
        }
        let expected = if kind == "digest" { [0; 32] } else { digest };
        assert!(
            owner
                .reconcile_pending_immutable_retirement(req, expected, &mut gate)
                .is_err(),
            "{kind}"
        );
        assert_eq!(owner.backend.load()?, original, "{kind}");
        assert_eq!(objects(&root)?, original_files, "{kind}");
        assert!(!owner.recovery_required(), "{kind}");
        assert_eq!(
            owner
                .immutable_retirement_status()?
                .ok_or("pending disappeared")?
                .record_sha256,
            digest,
            "{kind}"
        );
        drop(held);
    }
    Ok(())
}

#[test]
fn immutable_reconciliation_new_commit_ack_loss_cold_requires_new_exact_intent() -> TestResult {
    let _serial = serial_test();
    let (root, owner, original_digest) = cold_pending("reconciliation-ack-loss")?;
    owner.close()?;
    let lost = Arc::new(AtomicUsize::new(0));
    let unlinks = Arc::new(AtomicUsize::new(0));
    let backend: Box<dyn DurableBackend> = Box::new(LoseFileAck {
        inner: Box::new(crate::FileBackend::open(&root.0)?),
        lose_after: Arc::clone(&lost),
        unlinks_entered: Arc::clone(&unlinks),
    });
    let mut owner = Owner::reopen_with_backend(backend, TestBarrier::new(), 256)?;
    let original_files = objects(&root)?;
    let generation = owner.generation();
    lost.store(3, Ordering::SeqCst);
    let req = request(&mut owner, "fresh-commit-ack-lost")?;
    assert!(
        owner
            .reconcile_pending_immutable_retirement(req, original_digest, &mut gate)
            .is_err()
    );
    assert!(owner.recovery_required());
    assert_eq!(lost.load(Ordering::SeqCst), 0);
    assert_eq!(unlinks.load(Ordering::SeqCst), 0);
    assert_eq!(objects(&root)?, original_files);
    drop(owner);
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(cold.generation(), generation + 1);
    let pending = cold
        .immutable_retirement_status()?
        .ok_or("new durable intent absent")?;
    assert!(pending.pending);
    assert_eq!(pending.phase, "reconciliation-pending");
    assert_eq!(pending.original_pending_sha256, original_digest);
    assert_eq!(pending.reconciliation_attempt, 1);
    assert_ne!(pending.record_sha256, original_digest);
    let original = cold.backend.load()?;
    let req = request(&mut cold, "stale-original-intent")?;
    assert!(
        cold.reconcile_pending_immutable_retirement(req, original_digest, &mut gate)
            .is_err()
    );
    let req = request(&mut cold, "ordinary-gc-still-no-replay")?;
    assert!(cold.retire_immutable_objects(req, &mut gate).is_err());
    assert_eq!(cold.backend.load()?, original);
    assert_eq!(objects(&root)?, original_files);
    let req = request(&mut cold, "second-fresh-explicit-attempt")?;
    assert_eq!(
        cold.reconcile_pending_immutable_retirement(req, pending.record_sha256, &mut gate)?
            .removed_objects,
        1
    );
    let complete = cold
        .immutable_retirement_status()?
        .ok_or("completion absent")?;
    assert_eq!(complete.reconciliation_attempt, 2);
    assert_eq!(complete.original_pending_sha256, original_digest);
    assert!(!complete.original_completion_recorded);
    assert!(!complete.historical_request_outcome_reclassified);
    assert_eq!(read(&mut cold, 1)?, bytes(1));
    Ok(())
}

#[test]
fn immutable_reconciliation_physical_done_then_cold_absence_confirmation_is_separate() -> TestResult
{
    let _serial = serial_test();
    let (root, mut owner, original_digest) = cold_pending("reconciliation-after-physical")?;
    let generation = owner.generation();
    let stop = Stop::at(6);
    let req = request(&mut owner, "fresh-physical-finished")?;
    assert!(
        owner
            .reconcile_pending_immutable_retirement(req, original_digest, &mut gate)
            .is_err()
    );
    assert!(owner.recovery_required());
    assert!(!root.0.join(leaf(3)).exists());
    drop(stop);
    drop(owner);
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(cold.generation(), generation + 1);
    let pending = cold
        .immutable_retirement_status()?
        .ok_or("fresh pending absent")?;
    let req = request(&mut cold, "fresh-absence-confirmation")?;
    let result =
        cold.reconcile_pending_immutable_retirement(req, pending.record_sha256, &mut gate)?;
    assert_eq!(result.removed_objects, 0);
    assert_eq!(result.removed_ciphertext_bytes, 0);
    assert_eq!(result.confirmed_absent_objects, 1);
    assert_eq!(result.generation, generation + 2);
    let complete = cold
        .immutable_retirement_status()?
        .ok_or("absence completion absent")?;
    assert_eq!(complete.phase, "absence-confirmed");
    assert_eq!(complete.reconciliation_attempt, 1);
    assert_eq!(complete.original_pending_sha256, original_digest);
    assert!(!complete.original_completion_recorded);
    assert!(!complete.historical_request_outcome_reclassified);
    assert_eq!(read(&mut cold, 1)?, bytes(1));
    assert_eq!(read(&mut cold, 2)?, bytes(2));
    Ok(())
}

#[test]
fn immutable_reconciliation_both_metadata_transactions_reserved_before_dispatch() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner, digest) = cold_pending("reconciliation-reserved-capacity")?;
    let original = owner.backend.load()?;
    let original_files = objects(&root)?;
    owner.max_retained_requests = owner.ledger.len() + 1;
    let req = request(&mut owner, "only-one-slot")?;
    assert!(matches!(
        owner.reconcile_pending_immutable_retirement(req, digest, &mut gate),
        Err(ServiceError::RequestCapacityExhausted)
    ));
    assert!(!owner.recovery_required());
    assert_eq!(owner.backend.load()?, original);
    assert_eq!(objects(&root)?, original_files);
    owner.max_retained_requests = 256;
    let stop = Stop::at(4);
    let req = request(&mut owner, "before-new-metadata")?;
    assert!(
        owner
            .reconcile_pending_immutable_retirement(req, digest, &mut gate)
            .is_err()
    );
    assert!(!owner.recovery_required());
    assert_eq!(owner.backend.load()?, original);
    assert_eq!(objects(&root)?, original_files);
    drop(stop);
    Ok(())
}

#[test]
fn immutable_reconciliation_v1_codec_preserves_original_digest_when_upgraded() -> TestResult {
    let _serial = serial_test();
    let (_root, owner, _) = cold_pending("reconciliation-v1-codec")?;
    let (_, mut record) = owner
        .retirement_record()?
        .ok_or("real pending record absent")?;
    // Detached codec regression only: no generated old record is published or
    // used to claim a historical R1 execution. All entries came from the actual
    // current File retirement and retain their authenticated resource markers.
    record.format = RecordFormat::V1;
    let old = record.encode()?;
    assert!(old.expose().starts_with(MAGIC_V1));
    let mut decoded = Retirement::decode(old.expose())?;
    assert_eq!(decoded.original_pending_digest()?, raw_digest(old.expose()));
    decoded.format = RecordFormat::V2;
    decoded.phase = RetirementPhase::ReconciliationPending;
    decoded.lineage = Some(ReconciliationLineage {
        original_format: RecordFormat::V1,
        original_pending_digest: raw_digest(old.expose()),
        predecessor_digest: raw_digest(old.expose()),
        attempt: 1,
        source_generation: record.retirement_generation,
        publication_generation: record.retirement_generation + 1,
        replay_epoch: record.replay_epoch,
        selection_digest: record.selection_digest,
        descriptor_digest: [9; 32],
        present_mask: 1,
    });
    let upgraded = decoded.encode()?;
    let fresh = Retirement::decode(upgraded.expose())?;
    assert_eq!(fresh.original_pending_digest()?, raw_digest(old.expose()));
    assert_eq!(
        fresh
            .encode_wire(RecordFormat::V1, RetirementPhase::Pending, None)?
            .expose(),
        old.expose()
    );
    let mut trailing = upgraded.expose().to_vec();
    trailing.push(0);
    assert!(Retirement::decode(&trailing).is_err());
    Ok(())
}

struct StopSecondUnlink {
    inner: crate::FileBackend,
}
impl DurableBackend for StopSecondUnlink {
    fn verify(&self) -> Result<(), BackendError> {
        self.inner.verify()
    }
    fn immutable_blob_profile(&self) -> Result<ImmutableBlobProfile, BackendError> {
        self.inner.immutable_blob_profile()
    }
    fn pin_immutable_ciphertext(
        &self,
        locator: BlobLocator,
        length: usize,
    ) -> Result<ImmutableBlobReadPin, BackendError> {
        self.inner.pin_immutable_ciphertext(locator, length)
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
        auth: &mut dyn FnMut(usize, &[u8]) -> Result<(), BackendError>,
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<(), BackendError> {
        // The first real syscall is permitted. The next member's original
        // before-unlink callback refuses, so the actual directory owner reports
        // OutcomeUnknown after a genuine partial physical effect.
        let mut interrupt = |index, bytes: &[u8]| {
            if index == 1 {
                Err(BackendError::Unavailable)
            } else {
                auth(index, bytes)
            }
        };
        self.inner
            .retire_prepared_immutable_ciphertexts(prepared, &mut interrupt, gate)
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
    fn close(self) -> Result<(), BackendError> {
        self.inner.close()
    }
}

#[test]
fn immutable_reconciliation_partial_actual_unlink_confirms_absent_and_deletes_only_present()
-> TestResult {
    let _serial = serial_test();
    let (root, mut owner) = fixture("reconciliation-partial")?;
    add(&mut owner, 4, true)?;
    let retained = [
        fs::read(root.0.join(leaf(1)))?,
        fs::read(root.0.join(leaf(2)))?,
    ];
    let fourth = fs::read(root.0.join(leaf(4)))?;
    owner.close()?;
    let backend: Box<dyn DurableBackend> = Box::new(StopSecondUnlink {
        inner: crate::FileBackend::open(&root.0)?,
    });
    let mut owner = Owner::reopen_with_backend(backend, TestBarrier::new(), 256)?;
    let req = request(&mut owner, "real-partial-retirement")?;
    assert!(owner.retire_immutable_objects(req, &mut gate).is_err());
    assert!(owner.recovery_required());
    assert!(!root.0.join(leaf(3)).exists());
    assert_eq!(fs::read(root.0.join(leaf(4)))?, fourth);
    drop(owner);
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    let original = cold
        .immutable_retirement_status()?
        .ok_or("actual original pending absent")?;
    assert!(original.pending);
    assert_eq!(original.selected_objects, 2);
    let generation = cold.generation();
    let req = request(&mut cold, "ordinary-gc-partial-hold")?;
    assert!(cold.retire_immutable_objects(req, &mut gate).is_err());
    assert_eq!(cold.generation(), generation);
    assert_eq!(fs::read(root.0.join(leaf(4)))?, fourth);
    let req = request(&mut cold, "fresh-partial-reconciliation")?;
    let result =
        cold.reconcile_pending_immutable_retirement(req, original.record_sha256, &mut gate)?;
    assert_eq!(result.removed_objects, 1);
    assert_eq!(result.confirmed_absent_objects, 1);
    assert_eq!(result.removed_ciphertext_bytes, fourth.len() as u64);
    assert_eq!(result.generation, generation + 2);
    assert!(!root.0.join(leaf(3)).exists());
    assert!(!root.0.join(leaf(4)).exists());
    assert_eq!(fs::read(root.0.join(leaf(1)))?, retained[0]);
    assert_eq!(fs::read(root.0.join(leaf(2)))?, retained[1]);
    let (_, record) = cold
        .retirement_record()?
        .ok_or("completion record absent")?;
    let lineage = record.lineage.ok_or("fresh descriptor lineage absent")?;
    assert_eq!(lineage.present_mask, 2);
    assert_eq!(lineage.original_pending_digest, original.record_sha256);
    cold.close()?;
    let mut again = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(read(&mut again, 1)?, bytes(1));
    assert_eq!(read(&mut again, 2)?, bytes(2));
    Ok(())
}
