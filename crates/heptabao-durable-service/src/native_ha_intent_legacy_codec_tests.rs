//! Exact pre-floor 840 decoder functions, renamed only for comparison.
//! This is source-level old-reader evidence, NOT an executed old server binary.
//! Real old-binary cold-open tests on owned fixture copies remain a release gate.
use super::*;

// Original snapshot decoder SHA-256: bddcb21c08c1529797357a9abd9094b7cac3ae670adc649ecaf12837622fb72c
// Original journal decoder SHA-256: 209b81f16f3b4ef46aee7d4028bc76e76cc94f90cde03b7528ad940e14d6150b

fn old_decode_snapshot(bytes: &[u8]) -> Result<Snapshot, ServiceError> {
    if bytes.len() < 4 || &bytes[..4] != SNAPSHOT_PLAINTEXT_MAGIC {
        return Err(ServiceError::CorruptState);
    }
    let mut cursor = Cursor::new(&bytes[4..]);
    let generation = cursor.read_u64()?;
    let last_commit = match cursor.read_u8()? {
        0 => None,
        1 => Some(decode_marker(&mut cursor)?),
        _ => return Err(ServiceError::CorruptState),
    };
    let count = usize::try_from(cursor.read_u32()?).map_err(|_| ServiceError::CorruptState)?;
    if count > MAX_RECORDS {
        return Err(ServiceError::CorruptState);
    }
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        let namespace = cursor.read_string(1024)?;
        let resource = cursor.read_string(MAX_STRING_BYTES)?;
        validate_namespace(&namespace)?;
        validate_resource(&resource)?;
        let key = (namespace, resource);
        let value = cursor.read_bytes(MAX_SECRET_BYTES)?.to_vec();
        if value.is_empty() {
            return Err(ServiceError::CorruptState);
        }
        if entries.insert(key, Secret(value)).is_some() {
            return Err(ServiceError::CorruptState);
        }
    }
    cursor.finish()?;
    Ok(Snapshot {
        generation,
        entries,
        last_commit,
    })
}

fn old_decode_journal_event(bytes: &[u8]) -> Result<JournalEvent, ServiceError> {
    let mut cursor = Cursor::new(bytes);
    let kind = cursor.read_u8()?;
    let event = match kind {
        1 => JournalEvent::Intent(decode_marker(&mut cursor)?),
        2 => JournalEvent::Commit(decode_marker(&mut cursor)?),
        3 => JournalEvent::Abort(decode_marker(&mut cursor)?),
        4 => {
            let generation = cursor.read_u64()?;
            let retained_requests = cursor.read_u64()?;
            let last_commit = match cursor.read_u8()? {
                0 => None,
                1 => Some(decode_marker(&mut cursor)?),
                _ => return Err(ServiceError::CorruptState),
            };
            let ledger_digest = cursor.read_array_32()?;
            JournalEvent::Checkpoint(CheckpointMarker {
                generation,
                retained_requests,
                last_commit,
                ledger_digest,
            })
        }
        5 => {
            let marker = decode_marker(&mut cursor)?;
            let count =
                usize::try_from(cursor.read_u32()?).map_err(|_| ServiceError::CorruptState)?;
            if count == 0 || count > MAX_ATOMIC_MUTATIONS {
                return Err(ServiceError::CorruptState);
            }
            let mut resources = std::collections::BTreeSet::new();
            let mut mutations = Vec::with_capacity(count);
            for _ in 0..count {
                let resource = cursor.read_string(MAX_STRING_BYTES)?;
                validate_resource(&resource)?;
                if !resources.insert(resource.clone()) {
                    return Err(ServiceError::CorruptState);
                }
                let value = match cursor.read_u8()? {
                    1 => Some(Secret::new(cursor.read_bytes(MAX_SECRET_BYTES)?.to_vec())?),
                    2 => None,
                    _ => return Err(ServiceError::CorruptState),
                };
                mutations.push(JournalMutation { resource, value });
            }
            JournalEvent::Apply { marker, mutations }
        }
        _ => return Err(ServiceError::CorruptState),
    };
    cursor.finish()?;
    Ok(event)
}

#[test]
fn native_ha_intent_ledger_floor_is_atomic_with_pending_and_survives_checkpoint_backup()
-> TestResult {
    let _serial = serial_test();
    let (root, mut owner) = fixture("ha-intent-reader-floor")?;
    let legacy_snapshot = encode_snapshot(&owner.snapshot)?;
    assert_eq!(&legacy_snapshot[..4], b"HBP2");
    old_decode_snapshot(&legacy_snapshot)?;
    let calls = Rc::new(Cell::new(0));
    let held = Rc::new(Cell::new(false));
    let action = request(
        &mut owner,
        "reader-floor-unknown",
        true,
        calls.clone(),
        held,
    )?;
    assert!(owner.retire_native_ha_intents(action, &mut gate).is_err());
    assert_eq!(calls.get(), 1);
    let bundle = owner.backend.load()?;
    let (_, events, _, incomplete) = decode_journal_frames(&bundle.journal, &owner.barrier)?;
    assert!(!incomplete);
    let pending_apply = events
        .iter()
        .find(|event| {
            matches!(event,
        JournalEvent::Apply { marker, mutations } if ha_intent_apply_floor(marker, mutations))
        })
        .ok_or("actual authenticated Pending Apply absent")?;
    let encoded = encode_journal_event(pending_apply)?;
    assert_eq!(
        encoded[0], 6,
        "floor and Pending are the same authenticated Apply frame"
    );
    assert!(old_decode_journal_event(&encoded).is_err());
    decode_journal_event(&encoded)?;
    let mut downgraded = encoded.clone();
    downgraded[0] = 5;
    assert!(
        old_decode_journal_event(&downgraded).is_ok(),
        "old decoder demonstrably ignores unknown resource semantics"
    );
    assert!(
        decode_journal_event(&downgraded).is_err(),
        "new decoder forbids a downgraded envelope"
    );
    for event in &events {
        let plain = encode_journal_event(event)?;
        if plain.first() != Some(&HA_INTENT_APPLY_KIND) {
            old_decode_journal_event(&plain)?;
        }
    }
    drop(owner);
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert!(
        cold.native_ha_intent_retirement_status()?
            .ok_or("cold Pending")?
            .pending
    );
    let snapshot = encode_snapshot(&cold.snapshot)?;
    assert_eq!(&snapshot[..4], b"HBP3");
    assert!(old_decode_snapshot(&snapshot).is_err());
    decode_snapshot(&snapshot)?;
    let mut downgraded = snapshot.clone();
    downgraded[..4].copy_from_slice(b"HBP2");
    assert!(old_decode_snapshot(&downgraded).is_ok());
    assert!(decode_snapshot(&downgraded).is_err());
    let incoming = historical_pending_backup(&cold)?;
    let components = decode_backup(&cold.barrier, &incoming, cold.max_retained_requests)?;
    assert_eq!(&encode_snapshot(&components.snapshot)?[..4], b"HBP3");
    assert!(old_decode_snapshot(&encode_snapshot(&components.snapshot)?).is_err());
    assert_eq!(calls.get(), 1);
    Ok(())
}
