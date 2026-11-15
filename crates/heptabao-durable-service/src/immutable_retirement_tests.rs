//! Actual FileBackend metadata/descriptor/AEAD boundaries. TestBarrier and the
//! fixture retained set do not qualify the server's typed mark or HTTP Actor.
use super::*;
use crate::tests::{TestBarrier, TestRoot, serial_test};
use std::{any::Any, fs};

#[path = "immutable_ha_local_retirement_tests.rs"]
mod native_ha_local;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Owner = DurableService<TestBarrier>;
const ROOT: &[u8] = b"owned-retirement-root";
const STORE: [u8; 16] = [0x39; 16];
const CURSOR: &str = "state-native-v6/active-publication-cursor";
const SOURCE: &str = "state-native-v6/active-source-root";
fn gate() -> Result<(), ServiceError> {
    Ok(())
}
fn put(owner: &mut Owner, resource: &str, value: &[u8], id: &str) -> Result<(), ServiceError> {
    owner.put(PutRequest::new(
        "retirement-fixture",
        "system",
        id,
        resource,
        [7; 32],
        Secret::new(value.to_vec())?,
    )?)?;
    Ok(())
}
fn locator(index: u8) -> Result<BlobLocator, ServiceError> {
    BlobLocator::new(STORE, [index; 32]).map_err(map_backend_error)
}
fn leaf(index: u8) -> String {
    format!(
        "nv6.{}.{}.hbo",
        "39".repeat(16),
        format!("{index:02x}").repeat(32)
    )
}
fn resource(index: u8) -> String {
    format!("state-records/v6/kv2/{}", format!("{index:02x}").repeat(32))
}
fn bytes(index: u8) -> Vec<u8> {
    vec![index; 8192]
}
fn add(owner: &mut Owner, index: u8, register: bool) -> Result<(), ServiceError> {
    let resource = resource(index);
    let session = owner.immutable_source_session("system", "state", ROOT, STORE)?;
    let mut aad = b"HeptaBao/native-v6/typed-object-file/v1\0".to_vec();
    aad.extend_from_slice(resource.as_bytes());
    let data = bytes(index);
    let pin = owner.stage_immutable_object_before_publish(
        &session,
        locator(index)?,
        &aad,
        &data,
        &mut gate,
    )?;
    if register {
        let mut marker = b"HBV6BLOBREF0001\0".to_vec();
        marker.extend_from_slice(&STORE);
        marker.extend_from_slice(&[index; 32]);
        marker.extend_from_slice(&(pin.ciphertext_len() as u32).to_be_bytes());
        marker.extend_from_slice(&(data.len() as u32).to_be_bytes());
        put(owner, &resource, &marker, &format!("object-{index}"))?;
    }
    Ok(())
}
fn private_root(label: &str) -> Result<TestRoot, Box<dyn std::error::Error>> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let root = TestRoot::new(label)?;
    // Match the formal service's private directory custody without changing
    // the original process owner's umask or permissions of an existing root.
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(&root.0)?;
    let metadata = fs::symlink_metadata(&root.0)?;
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.mode() & 0o777, 0o700);
    Ok(root)
}
fn fixture(label: &str) -> Result<(TestRoot, Owner), Box<dyn std::error::Error>> {
    let root = private_root(label)?;
    let mut owner = Owner::create_new(&root.0, TestBarrier::new(), 256)?;
    put(&mut owner, "state", ROOT, "root")?;
    put(&mut owner, CURSOR, b"exact-current-cursor", "cursor")?;
    put(&mut owner, SOURCE, b"retained-v5-source", "source")?;
    for index in 1..=3 {
        add(&mut owner, index, true)?;
    }
    add(&mut owner, 99, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let directory = fs::metadata(&root.0)?;
        let object = fs::metadata(root.0.join(leaf(3)))?;
        eprintln!(
            "HBGC-FIXTURE root_mode={:o} object_mode={:o} nlink={} bytes={} owner_matches={}",
            directory.mode() & 0o7777,
            object.mode() & 0o7777,
            object.nlink(),
            object.len(),
            directory.uid() == object.uid()
        );
    }
    Ok((root, owner))
}
fn request(owner: &mut Owner, id: &str) -> Result<ImmutableRetirementRequest, ServiceError> {
    let session = owner.immutable_source_session("system", "state", ROOT, STORE)?;
    let conditions = ["state", CURSOR, SOURCE]
        .into_iter()
        .map(|resource| {
            Ok(PublicationCondition {
                resource: resource.into(),
                expected: owner.get("system", resource)?,
            })
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;
    Ok(ImmutableRetirementRequest {
        session,
        principal: "retirement-fixture".into(),
        operation_id: id.into(),
        authorization_digest: [8; 32],
        conditions,
        retained_resources: [resource(1), resource(2)].into_iter().collect(),
    })
}
fn read(owner: &mut Owner, index: u8) -> Result<Vec<u8>, ServiceError> {
    let value = owner
        .get("system", &resource(index))?
        .ok_or(ServiceError::CorruptState)?;
    let slot = Slot::decode(&resource(index), value.expose())?;
    let session = owner.immutable_source_session("system", "state", ROOT, STORE)?;
    let pin = owner.pin_immutable_object_before_read(
        &session,
        slot.locator,
        slot.ciphertext_bytes,
        &mut gate,
    )?;
    Ok(owner
        .read_immutable_object_before_delivery(&session, &pin, &slot.aad(), &mut gate)?
        .to_vec())
}
fn objects(root: &TestRoot) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    [1, 2, 3, 99]
        .into_iter()
        .map(|i| Ok(fs::read(root.0.join(leaf(i)))?))
        .collect()
}
struct Stop;
impl Stop {
    fn at(stage: u8) -> Self {
        TEST_RETIREMENT_STOP.with(|slot| {
            assert_eq!(slot.get(), 0);
            slot.set(stage);
        });
        Self
    }
}
impl Drop for Stop {
    fn drop(&mut self) {
        TEST_RETIREMENT_STOP.with(|slot| slot.set(0));
    }
}

#[test]
fn immutable_retirement_consumes_own_session_and_real_file_cold_reopens() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner) = fixture("retirement-positive")?;
    let generation = owner.generation();
    let expected_1 = read(&mut owner, 1)?;
    let expected_2 = read(&mut owner, 2)?;
    let orphan = fs::read(root.0.join(leaf(99)))?;
    let req = request(&mut owner, "positive")?;
    let result = owner.retire_immutable_objects(req, &mut gate)?;
    assert_eq!(result.generation, generation + 2);
    assert_eq!(result.removed_objects, 1);
    assert_eq!(result.removed_ciphertext_bytes, 8192 + 32);
    assert_eq!(result.registered_objects_before, 3);
    assert_eq!(result.retained_objects, 2);
    assert_eq!(result.confirmed_absent_objects, 0);
    assert!(owner.get("system", &resource(3))?.is_none());
    assert!(!root.0.join(leaf(3)).exists());
    assert_eq!(read(&mut owner, 1)?, expected_1);
    assert_eq!(read(&mut owner, 2)?, expected_2);
    assert_eq!(fs::read(root.0.join(leaf(99)))?, orphan);
    assert_eq!(
        owner
            .get("system", SOURCE)?
            .ok_or("missing retained source")?
            .expose(),
        b"retained-v5-source"
    );
    owner.close()?;
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(read(&mut cold, 1)?, expected_1);
    assert_eq!(read(&mut cold, 2)?, expected_2);
    assert_eq!(
        cold.retirement_record()?
            .ok_or("missing completed record")?
            .1
            .phase,
        RetirementPhase::OriginalCompleted
    );
    let req = request(&mut cold, "zero-object")?;
    let result = cold.retire_immutable_objects(req, &mut gate)?;
    assert_eq!(result.generation, generation + 2);
    assert_eq!(result.removed_objects, 0);
    assert_eq!(fs::read(root.0.join(leaf(99)))?, orphan);
    Ok(())
}

#[test]
fn immutable_retirement_holds_each_actual_session_profile_pin_restore_and_backup() -> TestResult {
    let _serial = serial_test();
    for kind in [
        "session",
        "profile",
        "pin",
        "prepared-restore",
        "backup-source",
    ] {
        let (root, mut owner) = fixture(&format!("retirement-holder-{kind}"))?;
        let held: Box<dyn Any> = match kind {
            "session" => Box::new(owner.immutable_source_session("system", "state", ROOT, STORE)?),
            "profile" => Box::new(owner.backend.immutable_blob_profile()?),
            "pin" => {
                let value = owner
                    .get("system", &resource(1))?
                    .ok_or("missing retained marker")?;
                let slot = Slot::decode(&resource(1), value.expose())?;
                let session = owner.immutable_source_session("system", "state", ROOT, STORE)?;
                Box::new(owner.pin_immutable_object_before_read(
                    &session,
                    slot.locator,
                    slot.ciphertext_bytes,
                    &mut gate,
                )?)
            }
            "prepared-restore" => {
                let mut core = Vec::new();
                owner.export_core_backup_to(&mut core)?;
                Box::new(owner.prepare_core_restore(&core)?)
            }
            "backup-source" => Box::new(owner.prepare_v6_backup(&mut gate)?),
            _ => return Err("unreachable fixture holder".into()),
        };
        let original = owner.backend.load()?;
        let original_objects = objects(&root)?;
        let req = request(&mut owner, "blocked")?;
        assert!(
            owner.retire_immutable_objects(req, &mut gate).is_err(),
            "{kind}"
        );
        assert_eq!(owner.backend.load()?, original, "{kind}");
        assert_eq!(objects(&root)?, original_objects, "{kind}");
        assert!(!owner.recovery_required());
        drop(held);
        let req = request(&mut owner, "now-quiescent")?;
        assert_eq!(
            owner
                .retire_immutable_objects(req, &mut gate)?
                .removed_objects,
            1,
            "{kind}"
        );
    }
    Ok(())
}

#[test]
fn immutable_retirement_before_metadata_failure_changes_no_artifact() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner) = fixture("retirement-before-metadata")?;
    let original = owner.backend.load()?;
    let original_objects = objects(&root)?;
    let _stop = Stop::at(1);
    let req = request(&mut owner, "before-metadata")?;
    assert!(owner.retire_immutable_objects(req, &mut gate).is_err());
    assert!(!owner.recovery_required());
    assert_eq!(owner.backend.load()?, original);
    assert_eq!(objects(&root)?, original_objects);
    assert!(owner.retirement_record()?.is_none());
    Ok(())
}

#[test]
fn immutable_retirement_committed_pending_present_cold_holds_and_never_replays_unlink() -> TestResult
{
    let _serial = serial_test();
    let (root, mut owner) = fixture("retirement-pending-present")?;
    let original_objects = objects(&root)?;
    let generation = owner.generation();
    let _stop = Stop::at(2);
    let req = request(&mut owner, "after-apply")?;
    assert!(owner.retire_immutable_objects(req, &mut gate).is_err());
    assert!(owner.recovery_required());
    assert_eq!(objects(&root)?, original_objects);
    drop(owner);
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(cold.generation(), generation + 1);
    assert_eq!(
        cold.retirement_record()?
            .ok_or("missing pending record")?
            .1
            .phase,
        RetirementPhase::Pending
    );
    assert!(cold.get("system", &resource(3))?.is_none());
    assert_eq!(read(&mut cold, 1)?, bytes(1));
    let original = cold.backend.load()?;
    let req = request(&mut cold, "explicit-absence-check")?;
    assert!(cold.retire_immutable_objects(req, &mut gate).is_err());
    assert_eq!(cold.backend.load()?, original);
    assert_eq!(objects(&root)?, original_objects);
    assert!(cold.prepare_v6_backup(&mut gate).is_err());
    assert!(add(&mut cold, 3, true).is_err());
    assert_eq!(cold.backend.load()?, original);
    assert_eq!(objects(&root)?, original_objects);
    Ok(())
}

#[test]
fn immutable_retirement_confirmed_absent_cold_completes_metadata_without_unlink() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner) = fixture("retirement-pending-absent")?;
    let generation = owner.generation();
    let retained = [
        fs::read(root.0.join(leaf(1)))?,
        fs::read(root.0.join(leaf(2)))?,
    ];
    let _stop = Stop::at(3);
    let req = request(&mut owner, "after-physical")?;
    assert!(owner.retire_immutable_objects(req, &mut gate).is_err());
    assert!(owner.recovery_required());
    assert!(!root.0.join(leaf(3)).exists());
    drop(owner);
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(cold.generation(), generation + 1);
    let old_pending = cold
        .retirement_record()?
        .ok_or("actual old pending record")?
        .0;
    let req = request(&mut cold, "explicit-absence-check")?;
    let result = cold.retire_immutable_objects(req, &mut gate)?;
    assert_eq!(result.removed_objects, 0);
    assert_eq!(result.removed_ciphertext_bytes, 0);
    assert_eq!(result.confirmed_absent_objects, 1);
    assert_eq!(result.generation, generation + 2);
    let (_, mut confirmation) = cold
        .retirement_record()?
        .ok_or("missing confirmation record")?;
    assert_eq!(confirmation.phase, RetirementPhase::AbsenceConfirmed);
    // A separate terminal phase preserves the complete original binding; it
    // must not relabel the old pending mutation as OriginalCompleted.
    confirmation.phase = RetirementPhase::Pending;
    assert_eq!(confirmation.encode()?.expose(), old_pending.expose());
    assert_eq!(fs::read(root.0.join(leaf(1)))?, retained[0]);
    assert_eq!(fs::read(root.0.join(leaf(2)))?, retained[1]);
    cold.close()?;
    let mut again = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(read(&mut again, 1)?, bytes(1));
    assert_eq!(read(&mut again, 2)?, bytes(2));
    Ok(())
}

#[test]
fn immutable_retirement_unknown_root_catalog_and_incomplete_reachability_hold() -> TestResult {
    let _serial = serial_test();
    for selector in [
        "state-native-v6/root",
        "state-native-v6/publication-cursor",
        "state-native-v6/ha-publication-cursor",
    ] {
        let (root, mut owner) = fixture("retirement-side-selector")?;
        put(
            &mut owner,
            selector,
            b"additional-owner",
            "additional-selector",
        )?;
        let original = owner.backend.load()?;
        let original_objects = objects(&root)?;
        let req = request(&mut owner, "held-side-root")?;
        assert!(matches!(
            owner.retire_immutable_objects(req, &mut gate),
            Err(ServiceError::UnsupportedProfile)
        ));
        assert_eq!(owner.backend.load()?, original);
        assert_eq!(objects(&root)?, original_objects);
    }
    let (root, mut owner) = fixture("retirement-unregistered-reachability")?;
    let original = owner.backend.load()?;
    let original_objects = objects(&root)?;
    let mut req = request(&mut owner, "missing-retained-marker")?;
    req.retained_resources.insert(resource(99));
    assert!(owner.retire_immutable_objects(req, &mut gate).is_err());
    assert_eq!(owner.backend.load()?, original);
    assert_eq!(objects(&root)?, original_objects);
    Ok(())
}

#[test]
fn immutable_retirement_candidate_ciphertext_is_freshly_authenticated_before_apply() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner) = fixture("retirement-corrupt-candidate")?;
    let path = root.0.join(leaf(3));
    let mut ciphertext = fs::read(&path)?;
    ciphertext[100] ^= 1;
    fs::write(&path, &ciphertext)?;
    let original = owner.backend.load()?;
    let req = request(&mut owner, "corrupt-candidate")?;
    assert!(owner.retire_immutable_objects(req, &mut gate).is_err());
    assert_eq!(owner.backend.load()?, original);
    assert_eq!(fs::read(path)?, ciphertext);
    assert!(owner.retirement_record()?.is_none());
    Ok(())
}

// The original FileBackend performs and synchronizes the real journal append.
// Only its acknowledgement is dropped. This is not a fabricated metadata state
// or a replacement in-memory backend, and no physical retire call may follow.
struct LoseFileAck {
    inner: Box<dyn DurableBackend>,
    lose_after: Arc<std::sync::atomic::AtomicUsize>,
    unlinks_entered: Arc<std::sync::atomic::AtomicUsize>,
}
impl DurableBackend for LoseFileAck {
    fn verify(&self) -> Result<(), BackendError> {
        self.inner.verify()
    }
    fn immutable_blob_profile(&self) -> Result<ImmutableBlobProfile, BackendError> {
        self.inner.immutable_blob_profile()
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
    fn pin_immutable_ciphertext(
        &self,
        locator: BlobLocator,
        length: usize,
    ) -> Result<ImmutableBlobReadPin, BackendError> {
        self.inner.pin_immutable_ciphertext(locator, length)
    }
    fn prepare_immutable_reconciliation(
        &mut self,
        objects: &[(BlobLocator, usize, [u8; 32])],
        auth: &mut dyn FnMut(usize, &[u8]) -> Result<(), BackendError>,
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<PreparedImmutableReconciliation, BackendError> {
        self.inner
            .prepare_immutable_reconciliation(objects, auth, gate)
    }
    fn finish_prepared_immutable_reconciliation(
        &mut self,
        prepared: PreparedImmutableReconciliation,
        auth: &mut dyn FnMut(usize, &[u8]) -> Result<(), BackendError>,
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<(), BackendError> {
        self.unlinks_entered
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner
            .finish_prepared_immutable_reconciliation(prepared, auth, gate)
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
        self.unlinks_entered
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner
            .retire_prepared_immutable_ciphertexts(prepared, auth, gate)
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
    fn initialize_empty(&mut self, initial: &BackendBundle) -> Result<(), BackendError> {
        self.inner.initialize_empty(initial)
    }
    fn append_journal(&mut self, expected: usize, frame: &[u8]) -> Result<usize, BackendError> {
        use std::sync::atomic::Ordering;
        let result = self.inner.append_journal(expected, frame)?;
        if self.lose_after.load(Ordering::SeqCst) > 0
            && self.lose_after.fetch_sub(1, Ordering::SeqCst) == 1
        {
            return Err(BackendError::OutcomeUnknown);
        }
        Ok(result)
    }
    fn truncate_journal(&mut self, expected: usize, new_len: usize) -> Result<(), BackendError> {
        self.inner.truncate_journal(expected, new_len)
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
fn immutable_retirement_real_committed_journal_ack_loss_never_enters_unlink() -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let _serial = serial_test();
    let root = private_root("retirement-real-ack-loss")?;
    let lost = Arc::new(AtomicUsize::new(0));
    let unlinks = Arc::new(AtomicUsize::new(0));
    let backend: Box<dyn DurableBackend> = Box::new(LoseFileAck {
        inner: Box::new(crate::FileBackend::create_new(&root.0)?),
        lose_after: Arc::clone(&lost),
        unlinks_entered: Arc::clone(&unlinks),
    });
    let mut owner = Owner::create_new_with_backend(backend, TestBarrier::new(), 256)?;
    put(&mut owner, "state", ROOT, "root")?;
    put(&mut owner, CURSOR, b"exact-current-cursor", "cursor")?;
    put(&mut owner, SOURCE, b"retained-v5-source", "source")?;
    for index in 1..=3 {
        add(&mut owner, index, true)?;
    }
    add(&mut owner, 99, false)?;
    let original_objects = objects(&root)?;
    let generation = owner.generation();
    lost.store(3, Ordering::SeqCst); // Intent, Apply, then the actual Commit sync.
    let req = request(&mut owner, "commit-ack-loss")?;
    assert!(owner.retire_immutable_objects(req, &mut gate).is_err());
    assert!(owner.recovery_required());
    assert_eq!(lost.load(Ordering::SeqCst), 0);
    assert_eq!(unlinks.load(Ordering::SeqCst), 0);
    assert_eq!(objects(&root)?, original_objects);
    drop(owner);
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(cold.generation(), generation + 1);
    assert_eq!(
        cold.retirement_record()?
            .ok_or("missing durable pending record")?
            .1
            .phase,
        RetirementPhase::Pending
    );
    let req = request(&mut cold, "fresh-no-unlink-absence")?;
    assert!(cold.retire_immutable_objects(req, &mut gate).is_err());
    assert_eq!(objects(&root)?, original_objects);
    assert_eq!(cold.generation(), generation + 1);
    Ok(())
}

#[test]
fn immutable_retirement_reserves_completion_before_the_first_metadata_apply() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner) = fixture("retirement-pair-capacity")?;
    let req = request(&mut owner, "two-transaction-capacity")?;
    let original = owner.backend.load()?;
    let original_objects = objects(&root)?;
    let marker_bytes = owner
        .get("system", &resource(3))?
        .ok_or("actual candidate marker")?;
    // Only lengths are needed to make exactly the first transaction fit.
    // This detached length fixture is never published or used as authority.
    let pending = Retirement {
        format: RecordFormat::V2,
        phase: RetirementPhase::Pending,
        lineage: None,
        source_generation: owner.generation(),
        retirement_generation: owner.generation() + 1,
        replay_epoch: owner.replay_epoch,
        selection_digest: selection_digest(&req.conditions),
        entries: vec![Entry {
            slot: Slot::decode(&resource(3), marker_bytes.expose())?,
            marker: marker_bytes,
            ciphertext_digest: [0; 32],
        }],
    }
    .encode()?;
    let begin_id = format!("{}-retire", req.operation_id);
    let generation = owner.generation() + 1;
    let sequence = owner.journal_sequence + 1;
    let marker = CommitMarker {
        key: RequestKey {
            principal: req.principal.clone(),
            namespace: "system".into(),
            request_id: scope_request_id(owner.replay_epoch, &begin_id)?,
        },
        binding_digest: req.authorization_digest,
        recovery_reference: recovery_reference(&req.authorization_digest, generation, sequence),
        generation,
    };
    let entries = vec![
        JournalMutation {
            resource: resource(3),
            value: None,
        },
        JournalMutation {
            resource: IMMUTABLE_RETIREMENT_RESOURCE.into(),
            value: Some(pending),
        },
    ];
    let mut first_transaction_bound = 0;
    for event in [
        JournalEvent::Intent(marker.clone()),
        JournalEvent::Apply {
            marker: marker.clone(),
            mutations: entries,
        },
        JournalEvent::Commit(marker),
    ] {
        let encoded = encode_journal_event(&event)?;
        first_transaction_bound += owner
            .barrier
            .sealed_len_bound(encoded.len())
            .ok_or("actual barrier frame bound")?
            + 48;
    }
    owner.journal_limit = owner.journal_bytes + first_transaction_bound;
    assert!(matches!(
        owner.retire_immutable_objects(req, &mut gate),
        Err(ServiceError::JournalCapacityExhausted)
    ));
    assert!(!owner.recovery_required());
    assert_eq!(owner.backend.load()?, original);
    assert_eq!(objects(&root)?, original_objects);
    assert!(owner.retirement_record()?.is_none());
    Ok(())
}

#[path = "immutable_reconciliation_tests.rs"]
mod reconciliation;
