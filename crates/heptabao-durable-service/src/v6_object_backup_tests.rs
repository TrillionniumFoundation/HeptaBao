//! Real descriptor-bound FileBackend tests of the new pack transport.
//! TestBarrier is deliberately NOT production cryptography. These tests do
//! not grant native Service graph admission or qualify an HTTP snapshot API.
use super::*;
use crate::tests::{TestBarrier, TestRoot, serial_test};
use std::fs;
use std::io::Cursor as IoCursor;

type ResultTest = Result<(), Box<dyn std::error::Error>>;
type Owner = DurableService<TestBarrier>;
const ROOT: &[u8] = b"owned-v6-slot-transport-fixture-root";
const STORE: [u8; 16] = [0x37; 16];
fn gate() -> Result<(), ServiceError> {
    Ok(())
}
fn allow(_: &str, _: &[u8]) -> Result<(), ServiceError> {
    Ok(())
}
fn validate(_: &PreparedRestore, _: &str, _: &[u8]) -> Result<(), ServiceError> {
    Ok(())
}
fn put(owner: &mut Owner, resource: &str, value: &[u8], id: &str) -> Result<(), ServiceError> {
    owner.put(PutRequest::new(
        "backup-fixture",
        "system",
        id,
        resource,
        [7; 32],
        Secret::new(value.to_vec())?,
    )?)?;
    Ok(())
}
fn address(index: usize) -> [u8; 32] {
    let mut value = [0x41; 32];
    value[..8].copy_from_slice(&(index as u64).to_be_bytes());
    value
}
fn resource(index: usize) -> String {
    format!(
        "state-records/v6/kv2/{}",
        address(index)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}
fn payload(index: usize, length: usize) -> Vec<u8> {
    (0..length)
        .map(|x| ((x as u64 * 37 + index as u64 * 19 + (x as u64 >> 8)) & 255) as u8)
        .collect()
}
fn add(owner: &mut Owner, index: usize, data: &[u8], register: bool) -> Result<(), ServiceError> {
    let name = resource(index);
    let locator = BlobLocator::new(STORE, address(index)).map_err(map_backend_error)?;
    let session = owner.immutable_source_session("system", "state", ROOT, STORE)?;
    let mut aad = OBJECT_AAD.to_vec();
    aad.extend_from_slice(name.as_bytes());
    let pin =
        owner.stage_immutable_object_before_publish(&session, locator, &aad, data, &mut gate)?;
    if register {
        let mut value = SLOT_MAGIC.to_vec();
        value.extend_from_slice(&STORE);
        value.extend_from_slice(&address(index));
        value.extend_from_slice(&(pin.ciphertext_len() as u32).to_be_bytes());
        value.extend_from_slice(&(data.len() as u32).to_be_bytes());
        put(owner, &name, &value, &format!("slot-{index}"))?;
    }
    Ok(())
}
fn fixture(
    label: &str,
    count: usize,
    size: usize,
) -> Result<(TestRoot, Owner), Box<dyn std::error::Error>> {
    let root = TestRoot::new(label)?;
    let mut owner = Owner::create_new(&root.0, TestBarrier::new(), 2048)?;
    put(&mut owner, "state", ROOT, "root")?;
    for index in 1..=count {
        add(&mut owner, index, &payload(index, size), true)?;
    }
    Ok((root, owner))
}
fn empty(label: &str) -> Result<(TestRoot, Owner), Box<dyn std::error::Error>> {
    let root = TestRoot::new(label)?;
    let owner = Owner::create_new(&root.0, TestBarrier::new(), 2048)?;
    Ok((root, owner))
}
fn pack(owner: &mut Owner) -> Result<Vec<u8>, ServiceError> {
    let plan = owner.prepare_v6_backup(&mut gate)?;
    let mut bytes = Vec::new();
    let size = owner.export_v6_backup_to(plan, &mut bytes, &mut gate, &mut allow)?;
    assert_eq!(size.archive_bytes, bytes.len() as u64);
    Ok(bytes)
}
fn blob_count(root: &std::path::Path) -> usize {
    fs::read_dir(root)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|p| {
            p.file_name()
                .to_str()
                .is_some_and(|x| x.starts_with("nv6.") && x.ends_with(".hbo"))
        })
        .count()
}
fn read_object(owner: &mut Owner, index: usize) -> Result<Vec<u8>, ServiceError> {
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

#[test]
fn pack_roundtrip_carries_registered_ciphertext_not_unreferenced_orphan_and_cold_reopens()
-> ResultTest {
    let _serial = serial_test();
    let (source_root, mut source) = fixture("pack-roundtrip-source", 3, 8192)?;
    add(&mut source, 90, b"unreferenced immutable orphan", false)?;
    let original = source.backend.load()?;
    let original_generation = source.generation();
    let bytes = pack(&mut source)?;
    assert_eq!(source.backend.load()?, original);
    assert_eq!(source.generation(), original_generation);
    let (target_root, mut target) = empty("pack-roundtrip-target")?;
    let prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    assert_eq!(prepared.size().object_count, 3);
    assert_eq!(prepared.state().get("system", "state")?, Some(ROOT));
    assert_eq!(blob_count(&target_root.0), 0);
    target.restore_v6_prepared(prepared, false, &mut gate)?;
    assert_eq!(blob_count(&source_root.0), 4);
    assert_eq!(blob_count(&target_root.0), 3);
    target.close()?;
    let mut reopened = Owner::reopen(&target_root.0, TestBarrier::new(), 2048)?;
    for index in 1..=3 {
        assert_eq!(read_object(&mut reopened, index)?, payload(index, 8192));
    }
    assert_eq!(reopened.generation(), source.generation());
    Ok(())
}

#[test]
fn legacy_hbb2_export_and_both_import_paths_reject_incomplete_external_state() -> ResultTest {
    let _serial = serial_test();
    let (_root, source) = fixture("pack-legacy", 1, 128)?;
    let mut output = Vec::new();
    assert!(matches!(
        source.export_backup_to(&mut output),
        Err(ServiceError::UnsupportedProfile)
    ));
    assert!(output.is_empty());
    let mut core = Vec::new();
    source.export_core_backup_to(&mut core)?;
    let (_r, target) = empty("pack-legacy-target")?;
    assert!(matches!(
        target.prepare_restore(&core),
        Err(ServiceError::UnsupportedProfile)
    ));
    assert!(matches!(
        target.prepare_restore_from_reader(&mut core.as_slice(), core.len() as u64),
        Err(ServiceError::UnsupportedProfile)
    ));
    Ok(())
}

#[test]
fn ordinary_user_value_marker_does_not_become_a_native_slot() -> ResultTest {
    let _serial = serial_test();
    let (_root, mut owner) = empty("pack-user-marker")?;
    owner.put(PutRequest::new(
        "fixture",
        "user",
        "user-value",
        resource(1),
        [3; 32],
        Secret::new(SLOT_MAGIC.to_vec())?,
    )?)?;
    let bytes = owner.export_backup()?;
    assert!(owner.prepare_restore(&bytes).is_ok());
    assert!(matches!(
        owner.prepare_v6_backup(&mut gate),
        Err(ServiceError::UnsupportedProfile)
    ));
    Ok(())
}

#[test]
fn stale_export_source_is_rejected_before_any_output() -> ResultTest {
    let _serial = serial_test();
    let (_root, mut source) = fixture("pack-stale-source", 1, 128)?;
    let plan = source.prepare_v6_backup(&mut gate)?;
    put(&mut source, "other", b"changed", "change")?;
    let mut output = Vec::new();
    assert!(
        source
            .export_v6_backup_to(plan, &mut output, &mut gate, &mut allow)
            .is_err()
    );
    assert!(output.is_empty());
    Ok(())
}

#[test]
fn source_close_revokes_export_instead_of_adopting_reopened_owner() -> ResultTest {
    let _serial = serial_test();
    let (root, mut source) = fixture("pack-closed-source", 1, 128)?;
    let plan = source.prepare_v6_backup(&mut gate)?;
    source.close()?;
    let mut next = Owner::reopen(&root.0, TestBarrier::new(), 2048)?;
    let mut bytes = Vec::new();
    assert!(
        next.export_v6_backup_to(plan, &mut bytes, &mut gate, &mut allow)
            .is_err()
    );
    assert!(bytes.is_empty());
    Ok(())
}

#[test]
fn malformed_alias_duplicate_and_mismatched_slot_addresses_fail_before_export() -> ResultTest {
    let _serial = serial_test();
    let (_root, mut source) = fixture("pack-slot-syntax", 1, 128)?;
    let value = source.get("system", &resource(1))?.ok_or("slot")?;
    let alias = resource(1).replace("/kv2/", "/kv1/");
    put(&mut source, &alias, value.expose(), "alias")?;
    assert!(source.prepare_v6_backup(&mut gate).is_err());
    assert!(Slot::decode(&resource(2), value.expose()).is_err());
    let mut bad = value.expose().to_vec();
    bad[16..32].fill(0);
    assert!(Slot::decode(&resource(1), &bad).is_err());
    for length in [0, 71, 73] {
        assert!(Slot::decode(&resource(1), &vec![0; length]).is_err());
    }
    let upper = resource(1).to_uppercase();
    assert!(Slot::decode(&upper, value.expose()).is_err());
    Ok(())
}

#[test]
fn missing_registered_ciphertext_never_produces_completed_pack() -> ResultTest {
    let _serial = serial_test();
    let (root, mut source) = fixture("pack-missing", 1, 128)?;
    let plan = source.prepare_v6_backup(&mut gate)?;
    let file = fs::read_dir(&root.0)?
        .filter_map(Result::ok)
        .find(|x| x.file_name().to_str().is_some_and(|x| x.ends_with(".hbo")))
        .ok_or("object")?;
    fs::remove_file(file.path())?;
    let mut bytes = Vec::new();
    assert!(
        source
            .export_v6_backup_to(plan, &mut bytes, &mut gate, &mut allow)
            .is_err()
    );
    let (_target_root, target) = empty("pack-missing-target")?;
    assert!(
        target
            .prepare_v6_restore_from_reader(
                IoCursor::new(bytes.clone()),
                bytes.len() as u64,
                &mut gate,
                &mut validate
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn all_truncations_at_format_boundaries_and_trailing_bytes_leave_target_unchanged() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-truncate", 2, 256)?;
    let good = pack(&mut source)?;
    let (root, mut target) = empty("pack-truncate-target")?;
    let original = target.backend.load()?;
    for cut in [0, 7, 31, 32, 60, good.len() / 2, good.len() - 1] {
        assert!(
            target
                .prepare_v6_restore_from_reader(
                    IoCursor::new(good[..cut].to_vec()),
                    cut as u64,
                    &mut gate,
                    &mut validate
                )
                .is_err()
        );
    }
    let mut extra = good.clone();
    extra.push(1);
    assert!(
        target
            .prepare_v6_restore_from_reader(
                IoCursor::new(extra.clone()),
                extra.len() as u64,
                &mut gate,
                &mut validate
            )
            .is_err()
    );
    assert!(
        target
            .prepare_v6_restore_from_reader(
                IoCursor::new(good.clone()),
                good.len() as u64 + 1,
                &mut gate,
                &mut validate
            )
            .is_err()
    );
    assert_eq!(target.backend.load()?, original);
    assert_eq!(blob_count(&root.0), 0);
    assert!(!target.recovery_required());
    Ok(())
}

#[test]
fn damaged_core_object_footer_and_forged_bounds_are_rejected_before_staging() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-corrupt", 2, 256)?;
    let good = pack(&mut source)?;
    let core_len = u64::from_le_bytes(good[8..16].try_into()?) as usize;
    let (root, mut target) = empty("pack-corrupt-target")?;
    let original = target.backend.load()?;
    for offset in [0, 20, 40, 32 + core_len + 4 + 40, good.len() - 5] {
        let mut bytes = good.clone();
        bytes[offset] ^= 1;
        assert!(
            target
                .prepare_v6_restore_from_reader(
                    IoCursor::new(bytes.clone()),
                    bytes.len() as u64,
                    &mut gate,
                    &mut validate
                )
                .is_err()
        );
    }
    for range in [8..16, 16..20, 24..32] {
        let mut bytes = good.clone();
        bytes[range].fill(255);
        assert!(
            target
                .prepare_v6_restore_from_reader(
                    IoCursor::new(bytes.clone()),
                    bytes.len() as u64,
                    &mut gate,
                    &mut validate
                )
                .is_err()
        );
    }
    assert_eq!(target.backend.load()?, original);
    assert_eq!(blob_count(&root.0), 0);
    Ok(())
}

#[test]
fn reordered_equal_length_objects_fail_context_binding_without_target_writes() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-reorder", 2, 256)?;
    let mut bytes = pack(&mut source)?;
    let first = 32 + u64::from_le_bytes(bytes[8..16].try_into()?) as usize;
    let record = 4 + u32::from_le_bytes(bytes[first..first + 4].try_into()?) as usize;
    let (a, b) = bytes[first..first + 2 * record].split_at_mut(record);
    a.swap_with_slice(b);
    let (root, target) = empty("pack-reorder-target")?;
    assert!(
        target
            .prepare_v6_restore_from_reader(
                IoCursor::new(bytes.clone()),
                bytes.len() as u64,
                &mut gate,
                &mut validate
            )
            .is_err()
    );
    assert_eq!(blob_count(&root.0), 0);
    Ok(())
}

#[test]
fn application_object_validator_vetoes_export_and_import() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-validator", 1, 256)?;
    let bytes = pack(&mut source)?;
    let plan = source.prepare_v6_backup(&mut gate)?;
    assert!(
        source
            .export_v6_backup_to(plan, &mut Vec::new(), &mut gate, &mut |_, _| Err(
                ServiceError::CorruptState
            ))
            .is_err()
    );
    let (root, target) = empty("pack-validator-target")?;
    assert!(
        target
            .prepare_v6_restore_from_reader(
                IoCursor::new(bytes.clone()),
                bytes.len() as u64,
                &mut gate,
                &mut |_, _, _| Err(ServiceError::CorruptState)
            )
            .is_err()
    );
    assert_eq!(blob_count(&root.0), 0);
    Ok(())
}

#[test]
fn original_gate_expiration_prevents_export_or_preparation_without_reset() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-expiry", 2, 256 * 1024)?;
    let bytes = pack(&mut source)?;
    let plan = source.prepare_v6_backup(&mut gate)?;
    let mut calls = 0;
    let mut expires = || {
        calls += 1;
        if calls > 18 {
            Err(ServiceError::BarrierFailure)
        } else {
            Ok(())
        }
    };
    assert!(
        source
            .export_v6_backup_to(plan, &mut Vec::new(), &mut expires, &mut allow)
            .is_err()
    );
    let (root, target) = empty("pack-expiry-target")?;
    let mut calls = 0;
    let mut expires = || {
        calls += 1;
        if calls > 18 {
            Err(ServiceError::BarrierFailure)
        } else {
            Ok(())
        }
    };
    assert!(
        target
            .prepare_v6_restore_from_reader(
                IoCursor::new(bytes.clone()),
                bytes.len() as u64,
                &mut expires,
                &mut validate
            )
            .is_err()
    );
    assert_eq!(blob_count(&root.0), 0);
    Ok(())
}

#[test]
fn changed_restore_frontier_and_foreign_instance_fail_before_any_blob_stage() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-frontier", 1, 256)?;
    let bytes = pack(&mut source)?;
    let (root, mut target) = empty("pack-frontier-target")?;
    let prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    put(&mut target, "unrelated", b"must preserve", "update")?;
    assert!(matches!(
        target.restore_v6_prepared(prepared, false, &mut gate),
        Err(ServiceError::RequestBindingConflict)
    ));
    assert_eq!(blob_count(&root.0), 0);
    let prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    let (foreign_root, mut foreign) = empty("pack-foreign-target")?;
    assert!(matches!(
        foreign.restore_v6_prepared(prepared, false, &mut gate),
        Err(ServiceError::RequestBindingConflict)
    ));
    assert_eq!(blob_count(&foreign_root.0), 0);
    Ok(())
}

#[test]
fn post_preparation_ciphertext_substitution_is_detected_before_publication() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-substitution", 1, 256)?;
    let bytes = pack(&mut source)?;
    let (root, mut target) = empty("pack-substitution-target")?;
    let mut prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    let offset = prepared.members[0].offset as usize;
    prepared.reader.get_mut()[offset + 40] ^= 1;
    assert!(matches!(
        target.restore_v6_prepared(prepared, false, &mut gate),
        Err(ServiceError::CorruptState)
    ));
    assert_eq!(blob_count(&root.0), 0);
    assert_eq!(target.generation(), 0);
    Ok(())
}

#[test]
fn rejection_after_real_immutable_stage_leaves_no_canonical_restore() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-stage-expiry", 2, 256)?;
    let bytes = pack(&mut source)?;
    let (root, mut target) = empty("pack-stage-expiry-target")?;
    let original = target.backend.load()?;
    let prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    let mut expires = || {
        if blob_count(&root.0) > 0 {
            Err(ServiceError::BarrierFailure)
        } else {
            Ok(())
        }
    };
    assert!(
        target
            .restore_v6_prepared(prepared, false, &mut expires)
            .is_err()
    );
    assert_eq!(target.backend.load()?, original);
    assert_eq!(target.generation(), 0);
    assert_eq!(blob_count(&root.0), 1);
    Ok(())
}

#[test]
fn preexisting_conflicting_ciphertext_is_never_overwritten_or_published() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-conflict", 1, 256)?;
    let bytes = pack(&mut source)?;
    let (root, mut target) = fixture("pack-conflict-target", 0, 256)?;
    add(&mut target, 1, &vec![0x99; 256], false)?;
    let file = fs::read_dir(&root.0)?
        .filter_map(Result::ok)
        .find(|x| x.file_name().to_str().is_some_and(|x| x.ends_with(".hbo")))
        .ok_or("object")?
        .path();
    let before = fs::read(&file)?;
    let state = target.backend.load()?;
    let prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    assert!(
        target
            .restore_v6_prepared(prepared, false, &mut gate)
            .is_err()
    );
    assert_eq!(fs::read(file)?, before);
    assert_eq!(target.backend.load()?, state);
    Ok(())
}

#[test]
fn bounded_short_io_and_interrupts_preserve_one_gate_without_looping_forever() -> ResultTest {
    let mut calls = 0;
    let mut expired = || {
        calls += 1;
        if calls > 3 {
            Err(ServiceError::BarrierFailure)
        } else {
            Ok(())
        }
    };
    struct Interrupted;
    impl Read for Interrupted {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::Interrupted.into())
        }
    }
    assert!(read_exact_checked(&mut Interrupted, &mut [0; 1], &mut expired).is_err());
    assert_eq!(calls, 4);
    let mut calls = 0;
    let mut gate = || {
        calls += 1;
        Ok(())
    };
    assert!(read_exact_checked(&mut Interrupted, &mut [0; 1], &mut gate).is_err());
    assert!(calls < 150);
    Ok(())
}

#[test]
fn file_streaming_pack_exceeds_old_single_artifact_bound_and_restores_132mib() -> ResultTest {
    let _serial = serial_test();
    const COUNT: usize = 528;
    const BYTES: usize = 256 * 1024;
    let (_source_root, mut source) = fixture("pack-132-source", COUNT, BYTES)?;
    let archive_root = TestRoot::new("pack-132-archive")?;
    fs::create_dir(&archive_root.0)?;
    let path = archive_root.0.join("objects.hbv6");
    let mut file = fs::File::create(&path)?;
    let plan = source.prepare_v6_backup(&mut gate)?;
    let size = source.export_v6_backup_to(plan, &mut file, &mut gate, &mut allow)?;
    file.sync_all()?;
    drop(file);
    assert!(size.ciphertext_bytes > 132 * 1024 * 1024);
    assert_eq!(fs::metadata(&path)?.len(), size.archive_bytes);
    let (target_root, mut target) = empty("pack-132-target")?;
    let prepared = target.prepare_v6_restore_from_reader(
        fs::File::open(&path)?,
        size.archive_bytes,
        &mut gate,
        &mut validate,
    )?;
    assert_eq!(prepared.size().object_count, COUNT);
    assert_eq!(blob_count(&target_root.0), 0);
    target.restore_v6_prepared(prepared, false, &mut gate)?;
    target.close()?;
    let mut reopened = Owner::reopen(&target_root.0, TestBarrier::new(), 2048)?;
    for index in 1..=COUNT {
        assert_eq!(read_object(&mut reopened, index)?, payload(index, BYTES));
    }
    eprintln!(
        "v6-pack-132 objects={} plaintext_bytes={} archive_bytes={} every_object_reopened=true",
        COUNT,
        COUNT * BYTES,
        size.archive_bytes
    );
    Ok(())
}

#[test]
fn rollback_requires_explicit_permission_and_invalidates_other_prepared_handles() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-rollback", 1, 256)?;
    let bytes = pack(&mut source)?;
    let (root, mut target) = empty("pack-rollback-target")?;
    for index in 0..5 {
        put(
            &mut target,
            "later-state",
            b"keep until explicit restore",
            &format!("later-{index}"),
        )?;
    }
    let prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    assert!(matches!(
        target.restore_v6_prepared(prepared, false, &mut gate),
        Err(ServiceError::BackupRollbackRejected)
    ));
    assert_eq!(blob_count(&root.0), 0);
    assert_eq!(target.generation(), 5);
    let first = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    let stale = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    target.restore_v6_prepared(first, true, &mut gate)?;
    assert_eq!(read_object(&mut target, 1)?, payload(1, 256));
    assert!(matches!(
        target.restore_v6_prepared(stale, true, &mut gate),
        Err(ServiceError::RequestBindingConflict)
    ));
    Ok(())
}

struct ContextBarrier(TestBarrier);
impl Barrier for ContextBarrier {
    fn seal(&self, context: &[u8], plain: &[u8]) -> Result<Vec<u8>, BarrierError> {
        let mut aad = b"different-barrier-context".to_vec();
        aad.extend_from_slice(context);
        self.0.seal(&aad, plain)
    }
    fn open(&self, context: &[u8], cipher: &[u8]) -> Result<Vec<u8>, BarrierError> {
        let mut aad = b"different-barrier-context".to_vec();
        aad.extend_from_slice(context);
        self.0.open(&aad, cipher)
    }
}
#[test]
fn foreign_barrier_cannot_authenticate_or_stage_the_pack() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-foreign-barrier", 1, 256)?;
    let bytes = pack(&mut source)?;
    let root = TestRoot::new("pack-foreign-barrier-target")?;
    let mut target = DurableService::create_new(&root.0, ContextBarrier(TestBarrier::new()), 2048)?;
    let before = target.backend.load()?;
    assert!(
        target
            .prepare_v6_restore_from_reader(
                IoCursor::new(bytes.clone()),
                bytes.len() as u64,
                &mut gate,
                &mut validate
            )
            .is_err()
    );
    assert_eq!(target.backend.load()?, before);
    assert_eq!(blob_count(&root.0), 0);
    Ok(())
}

struct FaultBackend {
    inner: FileBackend,
    lose_stage_ack: bool,
    transactional: bool,
}
impl DurableBackend for FaultBackend {
    fn close(self) -> Result<(), BackendError> {
        self.inner.close()
    }
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
    fn stage_immutable_ciphertext_checked(
        &mut self,
        locator: BlobLocator,
        bytes: &[u8],
        gate: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<ImmutableBlobStage, BackendError> {
        let result = self
            .inner
            .stage_immutable_ciphertext_checked(locator, bytes, gate)?;
        if self.lose_stage_ack {
            self.lose_stage_ack = false;
            Err(BackendError::OutcomeUnknown)
        } else {
            Ok(result)
        }
    }
    fn load(&mut self) -> Result<BackendBundle, BackendError> {
        self.inner.load()
    }
    fn initialize_empty(&mut self, value: &BackendBundle) -> Result<(), BackendError> {
        self.inner.initialize_empty(value)
    }
    fn append_journal(&mut self, length: usize, frame: &[u8]) -> Result<usize, BackendError> {
        self.inner.append_journal(length, frame)
    }
    fn truncate_journal(&mut self, expected: usize, next: usize) -> Result<(), BackendError> {
        self.inner.truncate_journal(expected, next)
    }
    fn publish_checkpoint(
        &mut self,
        old: &BackendBundle,
        next: &BackendBundle,
    ) -> Result<(), BackendError> {
        self.inner.publish_checkpoint(old, next)
    }
    fn restore_profile(&self) -> Result<RestoreProfile, BackendError> {
        if self.transactional {
            self.inner.restore_profile()
        } else {
            Err(BackendError::Unsupported)
        }
    }
    fn publish_restore(
        &mut self,
        old: &BackendBundle,
        next: &BackendBundle,
        intent: Option<&[u8]>,
    ) -> Result<(), BackendError> {
        self.inner.publish_restore(old, next, intent)
    }
}

#[test]
fn missing_transactional_restore_capability_rejects_before_any_external_stage() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-no-restore-profile", 1, 256)?;
    let bytes = pack(&mut source)?;
    let root = TestRoot::new("pack-no-restore-profile-target")?;
    let backend = FaultBackend {
        inner: FileBackend::create_new(&root.0)?,
        lose_stage_ack: false,
        transactional: false,
    };
    let mut target = DurableService::create_new_with_backend(backend, TestBarrier::new(), 2048)?;
    let prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    assert!(matches!(
        target.restore_v6_prepared(prepared, false, &mut gate),
        Err(ServiceError::UnsupportedProfile)
    ));
    assert_eq!(blob_count(&root.0), 0);
    assert_eq!(target.generation(), 0);
    assert!(!target.recovery_required());
    Ok(())
}

#[test]
fn real_staging_lost_ack_fences_owner_and_cold_reopen_keeps_old_root() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-stage-lost-ack", 1, 256)?;
    let bytes = pack(&mut source)?;
    let root = TestRoot::new("pack-stage-lost-ack-target")?;
    let backend = FaultBackend {
        inner: FileBackend::create_new(&root.0)?,
        lose_stage_ack: true,
        transactional: true,
    };
    let mut target = DurableService::create_new_with_backend(backend, TestBarrier::new(), 2048)?;
    let prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    assert!(matches!(
        target.restore_v6_prepared(prepared, false, &mut gate),
        Err(ServiceError::RecoveryRequired)
    ));
    assert!(target.recovery_required());
    assert_eq!(target.generation(), 0);
    assert_eq!(blob_count(&root.0), 1);
    drop(target);
    let mut reopened = Owner::reopen(&root.0, TestBarrier::new(), 2048)?;
    assert_eq!(reopened.generation(), 0);
    assert!(reopened.get("system", "state")?.is_none());
    let fresh = reopened.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    reopened.restore_v6_prepared(fresh, false, &mut gate)?;
    assert_eq!(blob_count(&root.0), 1);
    assert_eq!(read_object(&mut reopened, 1)?, payload(1, 256));
    Ok(())
}

#[test]
fn unresolved_owner_refuses_before_legacy_format_inspection() -> ResultTest {
    let _serial = serial_test();
    let (_root, mut source) = fixture("pack-unresolved-precedence", 1, 128)?;
    source.unresolved = true;
    let mut bytes = Vec::new();
    assert!(matches!(
        source.export_backup_to(&mut bytes),
        Err(ServiceError::RecoveryRequired)
    ));
    assert!(bytes.is_empty());
    Ok(())
}

#[test]
fn registered_identical_restore_uses_fresh_pin_and_aead_without_restaging() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-registered-source", 2, 256)?;
    let bytes = pack(&mut source)?;
    let (root, target) = fixture("pack-registered-target", 2, 256)?;
    target.close()?;
    // Any staging call would really write and then inject OutcomeUnknown. A
    // successful restore therefore proves that committed objects were reused
    // only through current descriptor pinning and fresh authentication.
    let backend = FaultBackend {
        inner: FileBackend::open(&root.0)?,
        lose_stage_ack: true,
        transactional: true,
    };
    let mut target = DurableService::reopen_with_backend(backend, TestBarrier::new(), 2048)?;
    let prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    target.restore_v6_prepared(prepared, true, &mut gate)?;
    assert!(!target.recovery_required());
    assert!(target.backend.lose_stage_ack);
    assert_eq!(blob_count(&root.0), 2);
    target.close()?;
    let mut reopened = Owner::reopen(&root.0, TestBarrier::new(), 2048)?;
    for index in 1..=2 {
        assert_eq!(read_object(&mut reopened, index)?, payload(index, 256));
    }
    Ok(())
}

#[test]
fn registered_corrupt_ciphertext_is_refused_not_repaired_or_trusted_from_slot() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-registered-bad-source", 1, 256)?;
    let bytes = pack(&mut source)?;
    let (root, mut target) = fixture("pack-registered-bad-target", 1, 256)?;
    let file = fs::read_dir(&root.0)?
        .filter_map(Result::ok)
        .find(|x| x.file_name().to_string_lossy().ends_with(".hbo"))
        .ok_or("object")?
        .path();
    let mut damaged = fs::read(&file)?;
    damaged[40] ^= 1;
    fs::write(&file, &damaged)?;
    let old = target.backend.load()?;
    let prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    assert!(matches!(
        target.restore_v6_prepared(prepared, true, &mut gate),
        Err(ServiceError::BarrierFailure)
    ));
    assert_eq!(target.backend.load()?, old);
    assert_eq!(fs::read(file)?, damaged);
    Ok(())
}

#[test]
fn registered_missing_ciphertext_is_refused_without_creating_a_replacement() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-registered-missing-source", 1, 256)?;
    let bytes = pack(&mut source)?;
    let (root, mut target) = fixture("pack-registered-missing-target", 1, 256)?;
    let file = fs::read_dir(&root.0)?
        .filter_map(Result::ok)
        .find(|x| x.file_name().to_string_lossy().ends_with(".hbo"))
        .ok_or("object")?
        .path();
    fs::remove_file(&file)?;
    let old = target.backend.load()?;
    let prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    assert!(
        target
            .restore_v6_prepared(prepared, true, &mut gate)
            .is_err()
    );
    assert_eq!(target.backend.load()?, old);
    assert_eq!(blob_count(&root.0), 0);
    Ok(())
}

#[test]
fn large_io_checks_live_owner_before_and_after_each_bounded_call() -> ResultTest {
    assert_eq!(IO_CHUNK, 256 * 1024);
    struct ReadSteps {
        calls: usize,
    }
    impl Read for ReadSteps {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            buffer.fill(0x5e);
            Ok(buffer.len())
        }
    }
    let mut reader = ReadSteps { calls: 0 };
    let mut buffer = vec![0u8; 2 * IO_CHUNK];
    let mut observed = 0;
    let result = read_exact_checked(&mut reader, &mut buffer, &mut || {
        observed += 1;
        if observed == 4 {
            Err(ServiceError::BarrierFailure)
        } else {
            Ok(())
        }
    });
    assert!(matches!(result, Err(ServiceError::BarrierFailure)));
    assert_eq!(reader.calls, 2);
    assert_eq!(observed, 4);
    assert!(buffer.iter().all(|byte| *byte == 0x5e));
    // A late actor/clock rejection occurs after actual I/O, before delivery.
    struct WriteSteps {
        calls: usize,
        written: usize,
    }
    impl Write for WriteSteps {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            self.written += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = WriteSteps {
        calls: 0,
        written: 0,
    };
    let mut checks = 0;
    let result = write_checked(&mut writer, &buffer, &mut || {
        checks += 1;
        if checks == 4 {
            Err(ServiceError::BarrierFailure)
        } else {
            Ok(())
        }
    });
    assert!(matches!(result, Err(ServiceError::BarrierFailure)));
    assert_eq!(writer.calls, 2);
    assert_eq!(writer.written, 2 * IO_CHUNK);
    assert_eq!(checks, 4);
    Ok(())
}

#[test]
fn typed_graph_fast_io_retains_full_pre_and_post_owner_with_each_bounded_gate() -> ResultTest {
    let _serial = serial_test();
    let (_source_root, mut source) = fixture("typed-fast-io-source", 1, IO_CHUNK + 160)?;
    let archive = pack(&mut source)?;
    let (target_root, target) = empty("typed-fast-io-target")?;
    let mut prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(archive.clone()),
        archive.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    let mut full = 0_usize;
    let mut bounded = 0_usize;
    let bytes = target.read_v6_restore_object_with_io_gate(
        &mut prepared,
        &resource(1),
        &mut || {
            full += 1;
            Ok(())
        },
        &mut || {
            bounded += 1;
            Ok(())
        },
    )?;
    assert_eq!(bytes.as_slice(), payload(1, IO_CHUNK + 160));
    assert_eq!(
        full, 2,
        "complete owner gate immediately surrounds the object"
    );
    assert!(
        bounded >= 7,
        "every bounded seek and I/O checks original deadline"
    );
    assert_eq!(blob_count(&target_root.0), 0);
    assert_eq!(target.generation(), 0);

    let mut legacy = 0_usize;
    let bytes = target.read_v6_restore_object(&mut prepared, &resource(1), &mut || {
        legacy += 1;
        Ok(())
    })?;
    assert_eq!(bytes.as_slice(), payload(1, IO_CHUNK + 160));
    assert!(
        legacy > full,
        "the existing public API keeps the full gate per syscall"
    );
    Ok(())
}

#[test]
fn typed_graph_fast_io_late_full_or_live_io_denial_refuses_plaintext() -> ResultTest {
    let _serial = serial_test();
    let (_source_root, mut source) = fixture("typed-fast-denial-source", 1, IO_CHUNK + 160)?;
    let archive = pack(&mut source)?;
    let (target_root, target) = empty("typed-fast-denial-target")?;
    let mut prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(archive.clone()),
        archive.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    let mut full = 0_usize;
    let mut bounded = 0_usize;
    let error = target.read_v6_restore_object_with_io_gate(
        &mut prepared,
        &resource(1),
        &mut || {
            full += 1;
            if full == 2 {
                Err(ServiceError::BarrierFailure)
            } else {
                Ok(())
            }
        },
        &mut || {
            bounded += 1;
            Ok(())
        },
    );
    assert!(matches!(error, Err(ServiceError::BarrierFailure)));
    assert_eq!(full, 2);
    assert!(bounded >= 7);
    assert_eq!(blob_count(&target_root.0), 0);
    assert_eq!(target.generation(), 0);

    let mut full = 0_usize;
    let mut bounded = 0_usize;
    let error = target.read_v6_restore_object_with_io_gate(
        &mut prepared,
        &resource(1),
        &mut || {
            full += 1;
            Ok(())
        },
        &mut || {
            bounded += 1;
            if bounded == 5 {
                Err(ServiceError::BarrierFailure)
            } else {
                Ok(())
            }
        },
    );
    assert!(matches!(error, Err(ServiceError::BarrierFailure)));
    assert_eq!(full, 1, "no full post-gate on a failed physical operation");
    assert_eq!(bounded, 5);
    assert_eq!(blob_count(&target_root.0), 0);
    assert_eq!(target.generation(), 0);
    Ok(())
}

#[test]
fn typed_graph_fast_io_rejects_post_prepare_ciphertext_mutation() -> ResultTest {
    let _serial = serial_test();
    let (_source_root, mut source) = fixture("typed-fast-mutate-source", 1, 8192)?;
    let archive = pack(&mut source)?;
    let (target_root, target) = empty("typed-fast-mutate-target")?;
    let mut prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(archive.clone()),
        archive.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    let offset = prepared.members[0].offset as usize;
    prepared.reader.get_mut()[offset + 16] ^= 1;
    let error = target.read_v6_restore_object_with_io_gate(
        &mut prepared,
        &resource(1),
        &mut || Ok(()),
        &mut || Ok(()),
    );
    assert!(matches!(error, Err(ServiceError::CorruptState)));
    assert_eq!(blob_count(&target_root.0), 0);
    assert_eq!(target.generation(), 0);
    Ok(())
}

#[test]
fn restore_fast_bounded_io_keeps_exact_ciphertext_and_cold_reopen() -> ResultTest {
    let _serial = serial_test();
    let (_src_root, mut source) = fixture("pack-restore-fast-source", 3, IO_CHUNK + 96)?;
    let bytes = pack(&mut source)?;
    let (root, mut target) = empty("pack-restore-fast-target")?;
    let prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    let mut full_owner_checks = 0_usize;
    let mut live_io_checks = 0_usize;
    target.restore_v6_prepared_with_io_gate(
        prepared,
        false,
        &mut || {
            full_owner_checks += 1;
            Ok(())
        },
        &mut || {
            live_io_checks += 1;
            Ok(())
        },
    )?;
    assert!(full_owner_checks >= 6, "every object has full owner checks");
    assert!(
        live_io_checks >= 12,
        "bounded physical calls keep live stop gates"
    );
    assert_eq!(blob_count(&root.0), 3);
    target.close()?;
    let mut reopened = Owner::reopen(&root.0, TestBarrier::new(), 2048)?;
    for i in 1..=3 {
        assert_eq!(read_object(&mut reopened, i)?, payload(i, IO_CHUNK + 96));
    }
    assert_eq!(reopened.generation(), source.generation());
    Ok(())
}

#[test]
fn restore_fast_live_io_denial_before_release_keeps_root_unchanged() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-restore-io-denial-source", 1, IO_CHUNK + 96)?;
    let bytes = pack(&mut source)?;
    let (root, mut target) = empty("pack-restore-io-denial-target")?;
    let old = target.backend.load()?;
    let prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    let mut full = 0;
    let mut io = 0;
    let error = target.restore_v6_prepared_with_io_gate(
        prepared,
        false,
        &mut || {
            full += 1;
            Ok(())
        },
        &mut || {
            io += 1;
            if io == 4 {
                Err(ServiceError::BarrierFailure)
            } else {
                Ok(())
            }
        },
    );
    assert!(matches!(error, Err(ServiceError::BarrierFailure)));
    assert!(full > 0 && io == 4);
    assert_eq!(blob_count(&root.0), 0);
    assert_eq!(target.generation(), 0);
    assert_eq!(target.backend.load()?, old);
    Ok(())
}

#[test]
fn restore_fast_late_full_owner_denial_cannot_be_overridden_by_live_io() -> ResultTest {
    let _serial = serial_test();
    let (_sr, mut source) = fixture("pack-restore-owner-denial-source", 1, IO_CHUNK + 96)?;
    let bytes = pack(&mut source)?;
    let (root, mut target) = empty("pack-restore-owner-denial-target")?;
    let old = target.backend.load()?;
    let prepared = target.prepare_v6_restore_from_reader(
        IoCursor::new(bytes.clone()),
        bytes.len() as u64,
        &mut gate,
        &mut validate,
    )?;
    let mut full = 0;
    let mut io = 0;
    let error = target.restore_v6_prepared_with_io_gate(
        prepared,
        false,
        &mut || {
            full += 1;
            if full == 3 {
                Err(ServiceError::BarrierFailure)
            } else {
                Ok(())
            }
        },
        &mut || {
            io += 1;
            Ok(())
        },
    );
    assert!(matches!(error, Err(ServiceError::BarrierFailure)));
    assert_eq!(full, 3);
    assert!(
        io >= 4,
        "physical input was consumed before full owner veto"
    );
    assert_eq!(blob_count(&root.0), 0);
    assert_eq!(target.generation(), 0);
    assert_eq!(target.backend.load()?, old);
    Ok(())
}

// Cross-implementation, frozen output equivalence: V6 pack hashes retain the
// exact SHA-256 transcript expected by older producer/consumer binaries.
#[test]
fn accelerated_v6_sha256_is_bit_exact_across_chunk_boundaries() -> ResultTest {
    for length in [
        0, 1, 31, 32, 63, 64, 65, 128, 4096, 65_536, 262_144, 524_288,
    ] {
        let input = payload(31, length);
        let old = Sha256::digest(&input);
        let accelerated = accelerated_sha256(&input)?;
        assert_eq!(accelerated.as_slice(), old.as_slice());
        let mut streaming = hardware_sha256::Context::new(&hardware_sha256::SHA256);
        for chunk in input.chunks(17_003) {
            streaming.update(chunk);
        }
        assert_eq!(streaming.finish().as_ref(), old.as_slice());
    }
    Ok(())
}

#[test]
fn bounded_v6_pack_io_still_requires_full_owner_after_actual_ciphertext_read() -> ResultTest {
    use std::cell::Cell;
    let _serial = serial_test();
    let (_source_root, mut source) = fixture("pack-bound-owner-source", 1, IO_CHUNK + 160)?;
    let archive = pack(&mut source)?;
    let (target_root, target) = empty("pack-bound-owner-target")?;
    let physical_read_seen = Cell::new(false);
    let rejected = target.prepare_v6_restore_from_reader_with_io_gate(
        IoCursor::new(archive.clone()),
        archive.len() as u64,
        &mut || {
            if physical_read_seen.get() {
                Err(ServiceError::BarrierFailure)
            } else {
                Ok(())
            }
        },
        &mut || {
            physical_read_seen.set(true);
            Ok(())
        },
        &mut validate,
    );
    assert!(
        physical_read_seen.get(),
        "bounded physical I/O never occurred"
    );
    assert!(matches!(rejected, Err(ServiceError::BarrierFailure)));
    assert_eq!(target.generation(), 0);
    assert_eq!(blob_count(&target_root.0), 0);
    let mut full_checks = 0_usize;
    let mut physical_checks = 0_usize;
    let prepared = target.prepare_v6_restore_from_reader_with_io_gate(
        IoCursor::new(archive.clone()),
        archive.len() as u64,
        &mut || {
            full_checks += 1;
            Ok(())
        },
        &mut || {
            physical_checks += 1;
            Ok(())
        },
        &mut validate,
    )?;
    assert!(physical_checks >= 4, "bounded I/O gate was omitted");
    assert!(
        full_checks >= 4,
        "both complete object boundaries were omitted"
    );
    assert_eq!(prepared.size().object_count, 1);
    assert_eq!(blob_count(&target_root.0), 0);
    Ok(())
}
