//! Deterministic size-accounting regression, with no timing-based assertion.
use super::*;
use std::cell::Cell;

#[derive(Clone, Copy, Default)]
struct Observation {
    serialized_bytes: usize,
    last_counted_size: Option<usize>,
}

thread_local! {
    static ACTIVE: Cell<Option<Observation>> = const { Cell::new(None) };
}

pub(super) fn record_serialized_bytes(bytes: usize) {
    ACTIVE.with(|active| {
        if let Some(mut observation) = active.get() {
            observation.serialized_bytes = observation.serialized_bytes.saturating_add(bytes);
            active.set(Some(observation));
        }
    });
}

pub(super) fn record_counted_size(bytes: usize) {
    ACTIVE.with(|active| {
        if let Some(mut observation) = active.get() {
            observation.last_counted_size = Some(bytes);
            active.set(Some(observation));
        }
    });
}

fn observe<T>(operation: impl FnOnce() -> T) -> (T, Observation) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ACTIVE.with(|active| active.set(None));
        }
    }
    assert!(
        ACTIVE
            .with(|active| active.replace(Some(Observation::default())))
            .is_none()
    );
    let _reset = Reset;
    let value = operation();
    let observation = ACTIVE.with(|active| active.get()).unwrap_or_default();
    (value, observation)
}

fn fixture(bytes: usize, pattern: u8) -> Vec<u8> {
    match pattern {
        0 => vec![0; bytes],
        1 => vec![255; bytes],
        _ => (0_u8..=255).cycle().take(bytes).collect(),
    }
}

fn debug_error(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

#[test]
fn constructor_json_accounting_does_not_serialize_ciphertext() -> Result<(), String> {
    let ciphertext = fixture(MAX_NATIVE_V6_CIPHERTEXT_CHUNK_BYTES, 2);
    let (object, observed) =
        observe(|| SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext));
    let object = object.map_err(debug_error)?;
    assert!(
        observed.serialized_bytes < 4096,
        "bounded native chunk validation must count its exact JSON without serializing its payload: observed={} ciphertext={}",
        observed.serialized_bytes,
        object.sealed.len(),
    );
    assert_eq!(
        observed.last_counted_size,
        Some(serde_json::to_vec(&object).map_err(debug_error)?.len())
    );
    Ok(())
}

#[test]
fn constructor_json_accounting_matches_actual_serde_all_tails() -> Result<(), String> {
    let sizes = [
        25, 26, 27, 28, 31, 32, 33, 255, 256, 257, 4095, 4096, 4097, 65535, 65536, 65537, 262142,
        262143, 262144,
    ];
    for size in sizes {
        for pattern in 0..3 {
            let ciphertext = fixture(size, pattern);
            let original = ciphertext.clone();
            let (object, observed) =
                observe(|| SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext));
            let object = object.map_err(debug_error)?;
            let actual = serde_json::to_vec(&object).map_err(debug_error)?;
            assert_eq!(observed.last_counted_size, Some(actual.len()));
            assert_eq!(object.sealed(), original.as_slice());
            assert_eq!(object.reference.encoded_bytes as usize, size);
            assert_eq!(object.reference.payload_bytes, size as u64);
            assert_eq!(object.reference.record_count, 0);
            assert!(object.children.is_empty());
            object.validate().map_err(debug_error)?;
            let reopened: SealedRecordObject =
                serde_json::from_slice(&actual).map_err(debug_error)?;
            reopened.validate().map_err(debug_error)?;
            assert_eq!(reopened, object);
        }
    }
    Ok(())
}

#[test]
fn constructor_rejects_original_ciphertext_bounds() {
    for size in [0, 1, 24, MAX_NATIVE_V6_CIPHERTEXT_CHUNK_BYTES + 1] {
        let (result, observed) =
            observe(|| SealedRecordObject::new_native_v6_ciphertext_chunk(fixture(size, 2)));
        assert!(matches!(
            result,
            Err(RaftRuntimeError::RecordRejected(RecordRejection::Invalid))
        ));
        assert_eq!(observed.serialized_bytes, 0);
        assert_eq!(observed.last_counted_size, None);
    }
}

#[test]
fn constructor_preserves_untrusted_reference_and_payload_rejection() -> Result<(), String> {
    let ciphertext = fixture(4096, 2);
    let original = SealedRecordObject::new_native_v6_ciphertext_chunk(ciphertext.clone())
        .map_err(debug_error)?;
    let mut changes = Vec::new();
    let mut changed = original.reference.clone();
    changed.id[0] ^= 1;
    changes.push(changed);
    let mut changed = original.reference.clone();
    changed.kind = RecordObjectKind::Block;
    changes.push(changed);
    let mut changed = original.reference.clone();
    changed.encoded_bytes -= 1;
    changes.push(changed);
    let mut changed = original.reference.clone();
    changed.payload_bytes -= 1;
    changes.push(changed);
    let mut changed = original.reference.clone();
    changed.record_count = 1;
    changes.push(changed);
    for reference in changes {
        assert!(
            SealedRecordObject::new(reference.clone(), Vec::new(), ciphertext.clone()).is_err()
        );
        let mut serialized = original.clone();
        serialized.reference = reference;
        let json = serde_json::to_vec(&serialized).map_err(debug_error)?;
        let reopened: SealedRecordObject = serde_json::from_slice(&json).map_err(debug_error)?;
        assert!(reopened.validate().is_err());
    }
    let mut corrupted = ciphertext.clone();
    corrupted[2048] ^= 0x80;
    assert!(SealedRecordObject::new(original.reference.clone(), Vec::new(), corrupted).is_err());
    assert!(
        SealedRecordObject::new(
            original.reference.clone(),
            vec![original.reference],
            ciphertext,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn generic_non_chunk_json_accounting_still_serializes_its_payload() -> Result<(), String> {
    let sealed = fixture(65536, 2);
    let reference = RecordObjectRef {
        id: [0x51; 32],
        kind: RecordObjectKind::Block,
        encoded_bytes: 25 + 65536,
        record_count: 0,
        payload_bytes: 65536,
    };
    let (object, observed) = observe(|| SealedRecordObject::new(reference, Vec::new(), sealed));
    let object = object.map_err(debug_error)?;
    let encoded = serde_json::to_vec(&object).map_err(debug_error)?;
    assert_eq!(observed.serialized_bytes, encoded.len());
    assert_eq!(observed.last_counted_size, Some(encoded.len()));
    assert!(observed.serialized_bytes > object.sealed.len());
    Ok(())
}

#[test]
fn constructor_keeps_wire_json_and_domain_digest_goldens() -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let object =
        SealedRecordObject::new_native_v6_ciphertext_chunk(fixture(25, 2)).map_err(debug_error)?;
    assert_eq!(
        hex(&object.reference.id),
        "59b600324f4cc76f43f572469a7450bf8e2df924a2c9b8aa706f423879cb1fa0"
    );
    let json = serde_json::to_vec(&object).map_err(debug_error)?;
    let json_sha: [u8; 32] = Sha256::digest(&json).into();
    assert_eq!(
        hex(&json_sha),
        "dd48cb661e4e6bbf11d9eb717dae8b0462f77b4f2db3519caa97cebeb2a188be"
    );
    assert_eq!(json.len(), 284);
    let reopened: SealedRecordObject = serde_json::from_slice(&json).map_err(debug_error)?;
    reopened.validate().map_err(debug_error)?;
    assert_eq!(reopened, object);
    Ok(())
}
