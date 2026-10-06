//! Actual descriptor-held HBS/HBJ/HBL reads; no cached put simulates damage.
use super::*;
use crate::tests::{TestBarrier, TestRoot, put_request, serial_test};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn files(root: &Path) -> Result<BackendBundle, std::io::Error> {
    Ok(BackendBundle {
        snapshot: fs::read(root.join("state.hbs"))?,
        ledger: fs::read(root.join("ledger.hbl"))?,
        journal: fs::read(root.join("journal.hbj"))?,
    })
}

fn rewrite_same_file(root: &Path, leaf: &str, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join(leaf))?;
    let before = file.metadata()?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(bytes)?;
    file.set_len(bytes.len() as u64)?;
    file.sync_all()?;
    let after = file.metadata()?;
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    let mut readback = Vec::new();
    file.seek(SeekFrom::Start(0))?;
    file.read_to_end(&mut readback)?;
    assert_eq!(readback, bytes);
    Ok(())
}

#[test]
fn negative_current_physical_journal_checkpoint_and_retirement_are_readonly() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("negative-physical-valid")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 32)?;
    for id in ["one", "two"] {
        service.put(put_request(id, b"actual-value")?)?;
        let before = files(&root.0)?;
        let generation = service.generation();
        service.verify_negative_current_publication()?;
        assert_eq!(files(&root.0)?, before);
        assert_eq!(service.generation(), generation);
    }
    service.compact()?;
    let before = files(&root.0)?;
    service.verify_negative_current_publication()?;
    assert_eq!(files(&root.0)?, before);
    service.retire_replay_epoch()?;
    let before = files(&root.0)?;
    service.verify_negative_current_publication()?;
    assert_eq!(files(&root.0)?, before);
    assert!(!service.recovery_required());
    Ok(())
}

fn physical_mac_damage(leaf: &str, domain: &[u8]) -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("negative-physical-mac")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 32)?;
    service.put(put_request("original", b"cached-original-value")?)?;
    service.verify_negative_current_publication()?;
    let generation = service.generation();
    let cached = service
        .get("root/team-a", "secret/application")?
        .ok_or("cached value")?;
    let mut bytes = fs::read(root.0.join(leaf))?;
    // Modify a protected byte, then recompute the public frame checksum.
    // Outer framing therefore remains valid and the original barrier MAC
    // (rather than a mere public checksum) must independently reject it.
    let (start, end, protected) = if leaf == "journal.hbj" {
        let len = u32::from_le_bytes(bytes[4..8].try_into()?) as usize;
        (8, 8 + len - 32, 20)
    } else {
        (0, bytes.len() - 32, 16)
    };
    bytes[protected] ^= 0x80;
    let checksum = digest32(domain, &bytes[start..end]);
    bytes[end..end + 32].copy_from_slice(&checksum);
    rewrite_same_file(&root.0, leaf, &bytes)?;
    assert_eq!(service.generation(), generation);
    assert_eq!(
        service
            .get("root/team-a", "secret/application")?
            .ok_or("still cached")?
            .expose(),
        cached.expose()
    );
    assert!(matches!(
        service.verify_negative_current_publication(),
        Err(ServiceError::BarrierFailure)
    ));
    assert_eq!(fs::read(root.0.join(leaf))?, bytes);
    assert_eq!(service.generation(), generation);
    Ok(())
}

#[test]
fn negative_current_physical_hbs_mac_damage_is_rejected() -> TestResult {
    physical_mac_damage("state.hbs", b"heptabao.durable-service.snapshot-frame.v2")
}
#[test]
fn negative_current_physical_hbj_mac_damage_is_rejected() -> TestResult {
    physical_mac_damage("journal.hbj", b"heptabao.durable-service.journal-frame.v2")
}
#[test]
fn negative_current_physical_hbl_mac_damage_is_rejected() -> TestResult {
    physical_mac_damage("ledger.hbl", b"heptabao.durable-service.ledger-frame.v2")
}

#[test]
fn negative_current_physical_authenticated_older_prefix_is_not_current_cache() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("negative-physical-rollback")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 32)?;
    service.put(put_request("one", b"older")?)?;
    let old = files(&root.0)?;
    service.put(put_request("two", b"current")?)?;
    service.verify_negative_current_publication()?;
    let generation = service.generation();
    rewrite_same_file(&root.0, "state.hbs", &old.snapshot)?;
    rewrite_same_file(&root.0, "ledger.hbl", &old.ledger)?;
    rewrite_same_file(&root.0, "journal.hbj", &old.journal)?;
    assert!(matches!(
        service.verify_negative_current_publication(),
        Err(ServiceError::CorruptState)
    ));
    assert_eq!(service.generation(), generation);
    assert_eq!(files(&root.0)?, old);
    Ok(())
}

#[test]
fn negative_current_physical_partial_tail_is_not_repaired() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("negative-physical-partial")?;
    let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 32)?;
    service.put(put_request("one", b"current")?)?;
    service.verify_negative_current_publication()?;
    let mut bytes = fs::read(root.0.join("journal.hbj"))?;
    bytes.push(0x01);
    rewrite_same_file(&root.0, "journal.hbj", &bytes)?;
    assert!(matches!(
        service.verify_negative_current_publication(),
        Err(ServiceError::RecoveryRequired)
    ));
    assert_eq!(fs::read(root.0.join("journal.hbj"))?, bytes);
    Ok(())
}

#[test]
fn negative_current_physical_complete_pending_intent_is_not_repaired() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("negative-physical-pending")?;
    let barrier = TestBarrier::new();
    let mut service = DurableService::create_new(&root.0, barrier.clone(), 32)?;
    service.put(put_request("one", b"current")?)?;
    service.verify_negative_current_publication()?;
    let generation = service.generation() + 1;
    let sequence = service.journal_sequence + 1;
    let digest = [9; 32];
    let marker = CommitMarker {
        key: RequestKey {
            principal: "actual-pending".to_owned(),
            namespace: "root/team-a".to_owned(),
            request_id: "pending-physical-intent".to_owned(),
        },
        binding_digest: digest,
        recovery_reference: recovery_reference(&digest, generation, sequence),
        generation,
    };
    let frame = sealed_journal_record(&barrier, sequence, &JournalEvent::Intent(marker))?;
    let mut bytes = fs::read(root.0.join("journal.hbj"))?;
    bytes.extend_from_slice(&frame);
    rewrite_same_file(&root.0, "journal.hbj", &bytes)?;
    assert!(matches!(
        service.verify_negative_current_publication(),
        Err(ServiceError::RecoveryRequired)
    ));
    assert_eq!(fs::read(root.0.join("journal.hbj"))?, bytes);
    Ok(())
}
