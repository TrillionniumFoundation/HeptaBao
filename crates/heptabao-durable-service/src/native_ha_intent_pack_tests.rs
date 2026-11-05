//! Actual FileBackend object-pack hold and cold-recovery tests. The parent
//! submission/observation fixture is not Raft or Service authority. These tests
//! exercise the production pack entry points and real sealed local objects;
//! they do not qualify an HTTP HBB3 snapshot or a physical HA deployment.
use super::*;
use std::collections::BTreeMap;
use std::io::{Cursor as IoCursor, Read, Seek, SeekFrom};

const OBJECT: &str =
    "state-records/v6/kv2/7373737373737373737373737373737373737373737373737373737373737373";
const OBJECT_BYTES: &[u8] =
    b"one exact registered ciphertext object through pending and cold restore";
const OBJECT_AAD: &[u8] = b"HeptaBao/native-v6/typed-object-file/v1\0";
const PACK_AAD: &[u8] = b"HeptaBao/native-v6/object-backup/transcript/v1\0";

#[path = "native_ha_local_catalog_tests.rs"]
mod local_catalog;

fn add_object(owner: &mut Owner) -> Result<(), ServiceError> {
    let root = owner
        .get("system", "state")?
        .ok_or(ServiceError::CorruptState)?;
    let session = owner.immutable_source_session("system", "state", root.expose(), STORE)?;
    let locator = BlobLocator::new(STORE, [0x73; 32]).map_err(map_backend_error)?;
    let mut context = OBJECT_AAD.to_vec();
    context.extend_from_slice(OBJECT.as_bytes());
    let pin = owner.stage_immutable_object_before_publish(
        &session,
        locator,
        &context,
        OBJECT_BYTES,
        &mut gate,
    )?;
    let mut slot = b"HBV6BLOBREF0001\0".to_vec();
    slot.extend_from_slice(&STORE);
    slot.extend_from_slice(&[0x73; 32]);
    slot.extend_from_slice(&(pin.ciphertext_len() as u32).to_be_bytes());
    slot.extend_from_slice(&(OBJECT_BYTES.len() as u32).to_be_bytes());
    owner.put(PutRequest::new(
        "intent-fixture",
        "system",
        "object-slot",
        OBJECT,
        [5; 32],
        Secret::new(slot)?,
    )?)?;
    Ok(())
}

fn export(owner: &mut Owner) -> Result<Vec<u8>, ServiceError> {
    let source = owner.prepare_v6_backup(&mut gate)?;
    let mut bytes = Vec::new();
    let size = owner.export_v6_backup_to(source, &mut bytes, &mut gate, &mut |name, plain| {
        if name != OBJECT || plain != OBJECT_BYTES {
            return Err(ServiceError::CorruptState);
        }
        Ok(())
    })?;
    assert_eq!(size.object_count, 1);
    assert_eq!(size.archive_bytes, bytes.len() as u64);
    Ok(bytes)
}

fn validate(_: &PreparedRestore, name: &str, plain: &[u8]) -> Result<(), ServiceError> {
    if name != OBJECT || plain != OBJECT_BYTES {
        return Err(ServiceError::CorruptState);
    }
    Ok(())
}

fn registered_bytes(owner: &mut Owner) -> Result<Vec<u8>, ServiceError> {
    let root = owner
        .get("system", "state")?
        .ok_or(ServiceError::CorruptState)?;
    let slot = owner
        .get("system", OBJECT)?
        .ok_or(ServiceError::CorruptState)?;
    let slot = crate::v6_object_backup::Slot::decode(OBJECT, slot.expose())?;
    let session = owner.immutable_source_session("system", "state", root.expose(), STORE)?;
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

struct CountedReader {
    inner: IoCursor<Vec<u8>>,
    calls: Rc<Cell<usize>>,
}
impl CountedReader {
    fn new(bytes: &[u8], calls: Rc<Cell<usize>>) -> Self {
        Self {
            inner: IoCursor::new(bytes.to_vec()),
            calls,
        }
    }
}
impl Read for CountedReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        self.calls.set(self.calls.get() + 1);
        self.inner.read(output)
    }
}
impl Seek for CountedReader {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.calls.set(self.calls.get() + 1);
        self.inner.seek(to)
    }
}

fn blob_inventory(root: &std::path::Path) -> Result<BTreeMap<String, Vec<u8>>, std::io::Error> {
    let mut observed = BTreeMap::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("nv6.") && name.ends_with(".hbo") {
            observed.insert(name, std::fs::read(entry.path())?);
        }
    }
    Ok(observed)
}

#[test]
fn native_ha_intent_ledger_v6_pack_pending_holds_before_io_and_cold_reconciliation_restores()
-> TestResult {
    let _serial = serial_test();
    let (root, mut owner) = fixture("ha-intent-v6-pack-hold")?;
    add_object(&mut owner)?;
    let safe = export(&mut owner)?;
    let calls = Rc::new(Cell::new(0));
    let held = Rc::new(Cell::new(false));

    // A real prepared object restore is an active restore owner, even though
    // no target object has been staged. It must prevent the first Pending.
    let restore = owner.prepare_v6_restore_from_reader(
        IoCursor::new(safe.clone()),
        safe.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    let before = owner.backend.load()?;
    let action = request(
        &mut owner,
        "prepared-pack-hold",
        false,
        calls.clone(),
        held.clone(),
    )?;
    assert!(owner.retire_native_ha_intents(action, &mut gate).is_err());
    assert_eq!(calls.get(), 0);
    assert_eq!(owner.backend.load()?, before);
    drop(restore);

    // A live export source also owns the original source instance through a
    // Weak session. It must hold metadata retirement before Pending/submit;
    // it cannot legitimately coexist with the later Pending on this owner.
    let active_source = owner.prepare_v6_backup(&mut gate)?;
    let before = owner.backend.load()?;
    let blocked = request(
        &mut owner,
        "active-pack-export-hold",
        false,
        calls.clone(),
        held.clone(),
    )?;
    assert!(matches!(
        owner.retire_native_ha_intents(blocked, &mut gate),
        Err(ServiceError::PublicationConditionConflict)
    ));
    assert_eq!(calls.get(), 0);
    assert!(owner.native_ha_intent_retirement_status()?.is_none());
    assert_eq!(owner.backend.load()?, before);
    drop(active_source);

    // Use a real affine plan from a different live owner only to check the
    // export entry's Pending priority and zero output. It is not current
    // owner authority; no valid current-owner export can outlive the hold.
    let (_export_root, mut exporter) = fixture("ha-intent-foreign-pack-export")?;
    add_object(&mut exporter)?;
    let foreign_source = exporter.prepare_v6_backup(&mut gate)?;
    let action = request(&mut owner, "pack-unknown", true, calls.clone(), held)?;
    assert!(owner.retire_native_ha_intents(action, &mut gate).is_err());
    assert_eq!(calls.get(), 1);
    drop(owner);
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    let pending = cold
        .native_ha_intent_retirement_status()?
        .ok_or("pending")?;
    assert!(pending.pending);
    let before = cold.backend.load()?;
    let blobs = blob_inventory(&root.0)?;
    assert_eq!(blobs.len(), 1);
    assert!(matches!(
        cold.prepare_v6_backup(&mut gate),
        Err(ServiceError::RecoveryRequired)
    ));
    let mut output = Vec::new();
    assert!(matches!(
        cold.export_v6_backup_to(foreign_source, &mut output, &mut gate, &mut |_, _| Ok(())),
        Err(ServiceError::RecoveryRequired)
    ));
    assert!(output.is_empty());

    let input_calls = Rc::new(Cell::new(0));
    assert!(matches!(
        cold.prepare_v6_restore_from_reader(
            CountedReader::new(&safe, input_calls.clone()),
            safe.len() as u64,
            &mut gate,
            &mut validate,
        ),
        Err(ServiceError::RecoveryRequired)
    ));
    assert_eq!(
        input_calls.get(),
        0,
        "Pending is checked before even seek/header/core input"
    );
    assert!(matches!(
        cold.prepare_v6_restore_from_reader_with_io_gate(
            CountedReader::new(&safe, input_calls.clone()),
            safe.len() as u64,
            &mut gate,
            &mut gate,
            &mut validate,
        ),
        Err(ServiceError::RecoveryRequired)
    ));
    assert_eq!(input_calls.get(), 0);
    assert_eq!(cold.backend.load()?, before);
    assert_eq!(blob_inventory(&root.0)?, blobs);

    let observation = reconcile(
        &mut cold,
        "pack-read-only-close",
        pending.record_sha256,
        Observation {
            capsule: digest(CAPSULE),
            resolution: NativeHaIntentResolution::EffectsObserved,
            valid: true,
        },
    )?;
    cold.reconcile_native_ha_intent_retirement(observation, &mut gate)?;
    assert_eq!(
        calls.get(),
        1,
        "closing Pending cannot resubmit its original owner"
    );
    let terminal = cold
        .native_ha_intent_retirement_status()?
        .ok_or("terminal")?;
    assert_eq!(terminal.phase, "reconciled-effects-observed");
    assert!(!terminal.historical_request_outcome_reclassified);
    let complete = export(&mut cold)?;
    cold.close()?;

    let (target_root, mut target) = fixture("ha-intent-v6-pack-cold-target")?;
    let mut prepared = target.prepare_v6_restore_from_reader_with_io_gate(
        IoCursor::new(complete.clone()),
        complete.len() as u64,
        &mut gate,
        &mut gate,
        &mut validate,
    )?;
    assert_eq!(
        target
            .read_v6_restore_object(&mut prepared, OBJECT, &mut gate)?
            .as_slice(),
        OBJECT_BYTES
    );
    let projection = target.v6_restore_projection_target(&prepared)?;
    let prior_root = Secret::new(
        prepared
            .state()
            .get("system", "state")?
            .ok_or("incoming root")?
            .to_vec(),
    )?;
    let cursor = Secret::new(
        prepared
            .state()
            .get("system", "state-native-v6/active-publication-cursor")?
            .ok_or("incoming cursor")?
            .to_vec(),
    )?;
    target.project_v6_restore_before_install(
        &mut prepared,
        projection,
        prior_root.expose(),
        (prior_root.clone(), cursor),
        Vec::new(),
        &mut gate,
    )?;
    target.restore_v6_prepared_with_io_gate(prepared, false, &mut gate, &mut gate)?;
    assert_eq!(
        &encode_snapshot(&target.snapshot)?[..4],
        HA_INTENT_SNAPSHOT_PLAINTEXT_MAGIC
    );
    assert_eq!(registered_bytes(&mut target)?, OBJECT_BYTES);
    assert_eq!(target.native_ha_intent_retirement_status()?, Some(terminal));
    target.close()?;
    let mut reopened = Owner::reopen(&target_root.0, TestBarrier::new(), 256)?;
    assert_eq!(registered_bytes(&mut reopened)?, OBJECT_BYTES);
    assert_eq!(
        reopened.native_ha_intent_retirement_status()?,
        Some(terminal)
    );
    assert_eq!(calls.get(), 1);
    Ok(())
}

// Construct a historical authenticated archive below the public exporter,
// which must never export Pending. Reuse exact registered ciphertext from a
// real preceding safe pack, replace its core, and seal the entire transcript.
fn historical_pending_pack(owner: &Owner, safe: &[u8]) -> Result<Vec<u8>, ServiceError> {
    let core = historical_pending_backup(owner)?;
    let old_core_len = u64::from_le_bytes(
        safe[8..16]
            .try_into()
            .map_err(|_| ServiceError::CorruptState)?,
    ) as usize;
    let count = u32::from_le_bytes(
        safe[16..20]
            .try_into()
            .map_err(|_| ServiceError::CorruptState)?,
    ) as usize;
    let total = u64::from_le_bytes(
        safe[24..32]
            .try_into()
            .map_err(|_| ServiceError::CorruptState)?,
    ) as usize;
    let start = 32 + old_core_len;
    let end = start + count * 4 + total;
    let mut bytes = safe[..32].to_vec();
    bytes[8..16].copy_from_slice(&(core.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&core);
    bytes.extend_from_slice(safe.get(start..end).ok_or(ServiceError::CorruptState)?);
    let mut transcript = PACK_AAD.to_vec();
    transcript.extend_from_slice(&bytes);
    let footer = owner
        .barrier
        .seal(PACK_AAD, &digest(&transcript))
        .map_err(|_| ServiceError::BarrierFailure)?;
    bytes.extend_from_slice(&(footer.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&footer);
    Ok(bytes)
}

#[test]
fn native_ha_intent_ledger_v6_pack_incoming_pending_is_rejected_before_stage_in_both_lanes()
-> TestResult {
    let _serial = serial_test();
    let (root, mut source) = fixture("ha-intent-incoming-pack")?;
    add_object(&mut source)?;
    let safe = export(&mut source)?;
    let calls = Rc::new(Cell::new(0));
    let action = request(
        &mut source,
        "incoming-pack-unknown",
        true,
        calls.clone(),
        Rc::new(Cell::new(false)),
    )?;
    assert!(source.retire_native_ha_intents(action, &mut gate).is_err());
    drop(source);
    let source = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    let incoming = historical_pending_pack(&source, &safe)?;
    let (target_root, mut target) = fixture("ha-intent-incoming-pack-target")?;
    let before = target.backend.load()?;
    let blobs = blob_inventory(&target_root.0)?;
    assert!(blobs.is_empty());
    assert!(matches!(
        target.prepare_v6_restore_from_reader(
            IoCursor::new(incoming.clone()),
            incoming.len() as u64,
            &mut gate,
            &mut validate,
        ),
        Err(ServiceError::RecoveryRequired)
    ));
    assert!(matches!(
        target.prepare_v6_restore_from_reader_with_io_gate(
            IoCursor::new(incoming.clone()),
            incoming.len() as u64,
            &mut gate,
            &mut gate,
            &mut validate,
        ),
        Err(ServiceError::RecoveryRequired)
    ));
    assert_eq!(target.backend.load()?, before);
    assert_eq!(blob_inventory(&target_root.0)?, blobs);
    assert!(!target.recovery_required());
    assert_eq!(calls.get(), 1);
    // The same target and actual pack decoder accept the preceding safe pack.
    let mut accepted = target.prepare_v6_restore_from_reader(
        IoCursor::new(safe.clone()),
        safe.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    assert_eq!(
        target
            .read_v6_restore_object(&mut accepted, OBJECT, &mut gate)?
            .as_slice(),
        OBJECT_BYTES
    );
    drop(accepted);
    assert_eq!(target.backend.load()?, before);
    assert_eq!(blob_inventory(&target_root.0)?, blobs);
    Ok(())
}
