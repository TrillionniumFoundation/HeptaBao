//! Additional protocol boundaries for the bounded production staging method.
//! These extend coverage without changing any original fixed108 selector.
use super::*;
use std::os::unix::fs::OpenOptionsExt;

fn leaf(root: &std::path::Path, locator: BlobLocator) -> std::path::PathBuf {
    let store: String = locator
        .store_id()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect();
    let address: String = locator
        .address()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect();
    root.join(format!("nv6.{store}.{address}.hbo"))
}

#[test]
fn immutable_batch_source_new_and_cold_existing_keep_primary_root() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-batch-source-cold")?;
    let barrier = NonceBarrier::new();
    let payloads: Vec<_> = (1..=32).map(|byte| vec![byte; 16 * 1024]).collect();
    let mut owner = DurableService::create_new(&root.0, barrier.clone(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation = owner.generation();
    let session = source_session(&mut owner)?;
    let old = owner.stage_immutable_object_before_publish(
        &session,
        locator(1)?,
        CONTEXT,
        &payloads[0],
        &mut no_gate,
    )?;
    owner.close()?;
    assert!(old.read_ciphertext().is_err());
    let mut owner = DurableService::reopen(&root.0, barrier.clone(), 16)?;
    let session = source_session(&mut owner)?;
    let inputs: Vec<_> = payloads
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            Ok((
                locator((index + 1) as u8)?,
                bytes.len() + 40,
                CONTEXT,
                bytes.as_slice(),
            ))
        })
        .collect::<Result<_, BackendError>>()?;
    let seals = barrier.seals.load(Ordering::Relaxed);
    let pins = owner.stage_immutable_objects_reusing_existing_before_publish(
        &session,
        &inputs,
        &mut no_gate,
    )?;
    assert_eq!(pins.len(), 32);
    assert_eq!(barrier.seals.load(Ordering::Relaxed) - seals, 31);
    assert!(pins[0].has_synchronized_ciphertext());
    for (pin, bytes) in pins.iter().zip(&payloads) {
        assert_eq!(
            owner
                .read_immutable_object_before_delivery(&session, pin, CONTEXT, &mut no_gate,)?
                .as_slice(),
            bytes
        );
    }
    source_unchanged(&owner, generation)?;
    owner.close()?;
    let mut cold = DurableService::reopen(&root.0, barrier, 16)?;
    let fresh = source_session(&mut cold)?;
    for (index, bytes) in payloads.iter().enumerate() {
        let pin = cold.pin_immutable_object_before_read(
            &fresh,
            locator((index + 1) as u8)?,
            bytes.len() + 40,
            &mut no_gate,
        )?;
        assert_eq!(
            cold.read_immutable_object_before_delivery(&fresh, &pin, CONTEXT, &mut no_gate,)?
                .as_slice(),
            bytes
        );
    }
    source_unchanged(&cold, generation)?;
    Ok(())
}

#[test]
fn immutable_batch_source_exact_physical_byte_and_count_limits() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-batch-physical-limits")?;
    let barrier = NonceBarrier::new();
    let mut owner = DurableService::create_new(&root.0, barrier.clone(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation = owner.generation();
    let session = source_session(&mut owner)?;
    let payload = vec![0x51; MAX_IMMUTABLE_CIPHERTEXT_BYTES - 40];
    let inputs: Vec<_> = (1..=9)
        .map(|address| {
            Ok((
                locator(address)?,
                payload.len() + 40,
                CONTEXT,
                payload.as_slice(),
            ))
        })
        .collect::<Result<_, BackendError>>()?;
    assert_eq!(
        inputs[0].1 * 8,
        ImmutableSourceSession::MAX_BATCH_CIPHERTEXT_BYTES
    );
    let seals = barrier.seals.load(Ordering::Relaxed);
    assert!(matches!(
        owner.stage_immutable_objects_reusing_existing_before_publish(
            &session,
            &inputs,
            &mut no_gate,
        ),
        Err(ServiceError::RequestCapacityExhausted)
    ));
    assert_eq!(barrier.seals.load(Ordering::Relaxed), seals);
    assert!(!has_object(&root.0));
    let tiny = b"count limit";
    let too_many: Vec<_> = (1..=33)
        .map(|address| Ok((locator(address)?, tiny.len() + 40, CONTEXT, tiny.as_slice())))
        .collect::<Result<_, BackendError>>()?;
    assert!(matches!(
        owner.stage_immutable_objects_reusing_existing_before_publish(
            &session,
            &too_many,
            &mut no_gate,
        ),
        Err(ServiceError::RequestCapacityExhausted)
    ));
    assert_eq!(barrier.seals.load(Ordering::Relaxed), seals);
    assert!(!has_object(&root.0));
    source_unchanged(&owner, generation)?;
    // Eight complete physical leaves reach the exact four-MiB boundary;
    // the supplied lengths include the real barrier's nonce and AEAD overhead.
    let pins = owner.stage_immutable_objects_reusing_existing_before_publish(
        &session,
        &inputs[..8],
        &mut no_gate,
    )?;
    assert_eq!(pins.len(), 8);
    assert_eq!(barrier.seals.load(Ordering::Relaxed) - seals, 8);
    for pin in &pins {
        assert_eq!(pin.ciphertext_len(), MAX_IMMUTABLE_CIPHERTEXT_BYTES);
        assert_eq!(
            owner
                .read_immutable_object_before_delivery(&session, pin, CONTEXT, &mut no_gate,)?
                .as_slice(),
            payload.as_slice()
        );
    }
    source_unchanged(&owner, generation)?;
    Ok(())
}

#[test]
fn immutable_batch_source_corrupt_existing_never_repairs_or_seals_new() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-batch-existing-corrupt")?;
    let barrier = NonceBarrier::new();
    let mut owner = DurableService::create_new(&root.0, barrier.clone(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation = owner.generation();
    let session = source_session(&mut owner)?;
    let payload = b"actual existing plaintext";
    owner.stage_immutable_object_before_publish(
        &session,
        locator(1)?,
        CONTEXT,
        payload,
        &mut no_gate,
    )?;
    let path = leaf(&root.0, locator(1)?);
    let mut corrupt = fs::read(&path)?;
    *corrupt.last_mut().ok_or("empty ciphertext")? ^= 1;
    fs::write(&path, &corrupt)?;
    let seals = barrier.seals.load(Ordering::Relaxed);
    let inputs = [
        (locator(1)?, payload.len() + 40, CONTEXT, payload.as_slice()),
        (locator(2)?, payload.len() + 40, CONTEXT, payload.as_slice()),
    ];
    assert!(
        owner
            .stage_immutable_objects_reusing_existing_before_publish(
                &session,
                &inputs,
                &mut no_gate,
            )
            .is_err()
    );
    assert_eq!(barrier.seals.load(Ordering::Relaxed), seals);
    assert_eq!(fs::read(&path)?, corrupt);
    assert!(!leaf(&root.0, locator(2)?).exists());
    source_unchanged(&owner, generation)?;
    Ok(())
}

#[test]
fn immutable_batch_source_original_gate_after_link_returns_no_pin() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-batch-gate-after-link")?;
    let mut owner = DurableService::create_new(&root.0, NonceBarrier::new(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation = owner.generation();
    let session = source_session(&mut owner)?;
    let payload = b"new object";
    let inputs = [
        (locator(1)?, payload.len() + 40, CONTEXT, payload.as_slice()),
        (locator(2)?, payload.len() + 40, CONTEXT, payload.as_slice()),
    ];
    let mut rejected_after_link = false;
    let result = owner.stage_immutable_objects_reusing_existing_before_publish(
        &session,
        &inputs,
        &mut || {
            if has_object(&root.0) {
                rejected_after_link = true;
                Err(ServiceError::BarrierFailure)
            } else {
                Ok(())
            }
        },
    );
    assert!(rejected_after_link);
    assert!(matches!(result, Err(ServiceError::BarrierFailure)));
    source_unchanged(&owner, generation)?;
    Ok(())
}

#[test]
fn immutable_batch_source_competing_existing_leaf_is_not_new_receipt() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-batch-competing-existing")?;
    let barrier = NonceBarrier::new();
    let mut owner = DurableService::create_new(&root.0, barrier.clone(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation = owner.generation();
    let session = source_session(&mut owner)?;
    let payload = b"same authenticated plaintext";
    let competing = barrier.seal(CONTEXT, payload)?;
    let destination = leaf(&root.0, locator(1)?);
    let inputs = [(locator(1)?, payload.len() + 40, CONTEXT, payload.as_slice())];
    let mut raced = false;
    let result = owner.stage_immutable_objects_reusing_existing_before_publish(
        &session,
        &inputs,
        &mut || {
            if !raced && root.0.join("native-v6-batch-0.tmp").exists() {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&destination)
                    .map_err(|_| ServiceError::BarrierFailure)?;
                file.write_all(&competing)
                    .map_err(|_| ServiceError::BarrierFailure)?;
                file.sync_all().map_err(|_| ServiceError::BarrierFailure)?;
                raced = true;
            }
            Ok(())
        },
    );
    assert!(raced);
    assert!(matches!(result, Err(ServiceError::RequestBindingConflict)));
    assert_eq!(fs::read(destination)?, competing);
    source_unchanged(&owner, generation)?;
    Ok(())
}

#[test]
fn immutable_batch_source_existing_aba_during_new_publication_rejects() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-batch-existing-aba")?;
    let barrier = NonceBarrier::new();
    let mut owner = DurableService::create_new(&root.0, barrier.clone(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation = owner.generation();
    let session = source_session(&mut owner)?;
    let payload = b"existing ABA plaintext";
    owner.stage_immutable_object_before_publish(
        &session,
        locator(1)?,
        CONTEXT,
        payload,
        &mut no_gate,
    )?;
    let existing = leaf(&root.0, locator(1)?);
    let original_wire = fs::read(&existing)?;
    let changed_wire = barrier.seal(CONTEXT, payload)?;
    assert_ne!(original_wire, changed_wire);
    let new_leaf = leaf(&root.0, locator(2)?);
    let inputs = [
        (locator(1)?, payload.len() + 40, CONTEXT, payload.as_slice()),
        (locator(2)?, payload.len() + 40, CONTEXT, payload.as_slice()),
    ];
    let mut rewrote = false;
    let result = owner.stage_immutable_objects_reusing_existing_before_publish(
        &session,
        &inputs,
        &mut || {
            if !rewrote && new_leaf.exists() {
                fs::write(&existing, &changed_wire).map_err(|_| ServiceError::BarrierFailure)?;
                fs::write(&existing, &original_wire).map_err(|_| ServiceError::BarrierFailure)?;
                rewrote = true;
            }
            Ok(())
        },
    );
    assert!(rewrote);
    assert!(result.is_err());
    assert_eq!(fs::read(existing)?, original_wire);
    source_unchanged(&owner, generation)?;
    Ok(())
}

#[test]
fn immutable_batch_source_existing_aba_at_final_gate_rejects() -> TestResult {
    let _serial = serial_test();
    let root = TestRoot::new("immutable-batch-existing-final-gate-aba")?;
    let barrier = NonceBarrier::new();
    let mut owner = DurableService::create_new(&root.0, barrier.clone(), 16)?;
    owner.put(put_request("source", SOURCE)?)?;
    let generation = owner.generation();
    let session = source_session(&mut owner)?;
    let payload = b"existing final gate ABA plaintext";
    let inputs = [
        (locator(1)?, payload.len() + 40, CONTEXT, payload.as_slice()),
        (locator(2)?, payload.len() + 40, CONTEXT, payload.as_slice()),
    ];
    for (locator, _, context, plaintext) in &inputs {
        owner.stage_immutable_object_before_publish(
            &session,
            *locator,
            context,
            plaintext,
            &mut no_gate,
        )?;
    }
    let existing = leaf(&root.0, locator(1)?);
    let original_wire = fs::read(&existing)?;
    let changed_wire = barrier.seal(CONTEXT, payload)?;
    assert_ne!(original_wire, changed_wire);
    // Observe the actual callback boundary for this unchanged all-existing
    // input; do not assume a hard-coded number of crypto or filesystem gates.
    let mut admitted_gates = 0usize;
    let control = owner.stage_immutable_objects_reusing_existing_before_publish(
        &session,
        &inputs,
        &mut || {
            admitted_gates += 1;
            Ok(())
        },
    )?;
    assert_eq!(control.len(), 2);
    assert!(admitted_gates > 0);
    drop(control);
    let mut gates = 0usize;
    let mut rewrote = false;
    let result = owner.stage_immutable_objects_reusing_existing_before_publish(
        &session,
        &inputs,
        &mut || {
            gates += 1;
            if gates == admitted_gates {
                fs::write(&existing, &changed_wire).map_err(|_| ServiceError::BarrierFailure)?;
                fs::write(&existing, &original_wire).map_err(|_| ServiceError::BarrierFailure)?;
                rewrote = true;
            }
            Ok(())
        },
    );
    assert_eq!(gates, admitted_gates);
    assert!(rewrote);
    assert!(matches!(result, Err(ServiceError::CorruptState)));
    assert_eq!(fs::read(existing)?, original_wire);
    source_unchanged(&owner, generation)?;
    Ok(())
}
