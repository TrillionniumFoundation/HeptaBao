//! Unit sources for the unwired crypto preparation; not executed by this task.
use super::*;
use crate::crypto::AeadBarrier;
use heptabao_durable_service::Barrier;

type TestResult = Result<(), Error>;
fn fixture() -> Result<(RootKey, ScopeBinding, PreparedRing), Error> {
    let root = RootKey::from_owned(Zeroizing::new([7; 32]));
    let binding = ScopeBinding::root("rotation-fixture".into(), [9; 32])?;
    let ring = PreparedRing::bootstrap(&root, binding.clone(), Duration::from_secs(10))?;
    Ok((root, binding, ring))
}

#[test]
fn existing_production_hba1_bytes_still_open_after_staged_data_rotation() -> TestResult {
    let (_, _, ring) = fixture()?;
    let legacy = AeadBarrier::new([7; 32])
        .map_err(|_| Error::Authentication)?
        .seal(b"original-resource-context", b"old physical value")
        .map_err(|_| Error::Authentication)?;
    let rotated = ring.prepare_manual_rotation(Duration::from_secs(20))?;
    assert_eq!(
        rotated
            .open(b"original-resource-context", &legacy)?
            .as_slice(),
        b"old physical value"
    );
    assert!(matches!(
        rotated.open(b"other-context", &legacy),
        Err(Error::Authentication)
    ));
    Ok(())
}
#[test]
fn new_term_ciphertext_authenticates_existing_term_header_and_original_context() -> TestResult {
    let (_, _, mut ring) = fixture()?;
    let encrypted = ring.seal_candidate(b"resource-a", b"value")?;
    assert_eq!(&encrypted[..4], b"HBA2");
    assert_eq!(encrypted.len(), b"value".len() + DATA_OVERHEAD);
    assert_eq!(ring.open(b"resource-a", &encrypted)?.as_slice(), b"value");
    let rotated = ring.prepare_manual_rotation(Duration::from_secs(20))?;
    let mut changed = encrypted.to_vec();
    changed[4..8].copy_from_slice(&3_u32.to_be_bytes());
    assert!(matches!(
        rotated.open(b"resource-a", &changed),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        ring.open(b"resource-b", &encrypted),
        Err(Error::Authentication)
    ));
    Ok(())
}
#[test]
fn unknown_data_term_version_and_legacy_term_in_new_envelope_fail_closed() -> TestResult {
    let (_, _, mut ring) = fixture()?;
    let encrypted = ring.seal_candidate(b"resource", b"value")?;
    let mut changed = encrypted.to_vec();
    changed[4..8].copy_from_slice(&999_u32.to_be_bytes());
    assert!(matches!(
        ring.open(b"resource", &changed),
        Err(Error::UnknownTerm)
    ));
    changed[4..8].copy_from_slice(&1_u32.to_be_bytes());
    assert!(matches!(
        ring.open(b"resource", &changed),
        Err(Error::InvalidTerm)
    ));
    changed = encrypted.to_vec();
    changed[3] = b'3';
    assert!(matches!(
        ring.open(b"resource", &changed),
        Err(Error::UnsupportedVersion)
    ));
    assert!(matches!(
        ring.open(b"resource", &encrypted[..20]),
        Err(Error::InvalidFormat)
    ));
    Ok(())
}
#[test]
fn root_sealed_capsule_roundtrip_retains_config_counter_and_old_ciphertext() -> TestResult {
    let (root, binding, mut ring) = fixture()?;
    ring.set_config_candidate(ConfigPatch {
        enabled: Some(false),
        interval: Some(MIN_INTERVAL),
        ..ConfigPatch::default()
    })?;
    let encrypted = ring.seal_candidate(b"resource", b"value")?;
    let capsule = ring.root_sealed_capsule(&root)?;
    let restored = PreparedRing::from_root_sealed_capsule(&root, binding, &capsule)?;
    assert_eq!(restored.active_term(), 2);
    assert_eq!(restored.active_encryptions()?, 1);
    assert_eq!(restored.config(), ring.config());
    assert_eq!(restored.open(b"resource", &encrypted)?.as_slice(), b"value");
    Ok(())
}
#[test]
fn capsule_wrong_root_scope_generation_version_and_corruption_reject() -> TestResult {
    let (root, binding, ring) = fixture()?;
    let capsule = ring.root_sealed_capsule(&root)?;
    let wrong = RootKey::from_owned(Zeroizing::new([8; 32]));
    assert!(matches!(
        PreparedRing::from_root_sealed_capsule(&wrong, binding.clone(), &capsule),
        Err(Error::Authentication)
    ));
    let wrong_binding = ScopeBinding::root("different-cluster".into(), [9; 32])?;
    assert!(matches!(
        PreparedRing::from_root_sealed_capsule(&root, wrong_binding, &capsule),
        Err(Error::Authentication)
    ));
    let mut changed = capsule.to_vec();
    changed[12] ^= 1;
    assert!(matches!(
        PreparedRing::from_root_sealed_capsule(&root, binding.clone(), &changed),
        Err(Error::Authentication)
    ));
    changed = capsule.to_vec();
    changed[4] = 2;
    assert!(matches!(
        PreparedRing::from_root_sealed_capsule(&root, binding.clone(), &changed),
        Err(Error::UnsupportedVersion)
    ));
    changed = capsule.to_vec();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(matches!(
        PreparedRing::from_root_sealed_capsule(&root, binding.clone(), &changed),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        PreparedRing::from_root_sealed_capsule(&root, binding, &capsule[..20]),
        Err(Error::InvalidFormat)
    ));
    Ok(())
}
#[test]
fn authenticated_capsule_duplicate_term_is_not_silently_last_wins() -> TestResult {
    let (root, binding, ring) = fixture()?;
    let mut payload = ring.encode_payload()?;
    const PREFIX: usize = 37;
    const SLOT: usize = 56;
    let first = payload[PREFIX..PREFIX + 4].to_vec();
    payload[PREFIX + SLOT..PREFIX + SLOT + 4].copy_from_slice(&first);
    let capsule = seal_capsule_payload(&root, &binding, ring.generation, &payload)?;
    assert!(matches!(
        PreparedRing::from_root_sealed_capsule(&root, binding, &capsule),
        Err(Error::DuplicateTerm)
    ));
    Ok(())
}
#[test]
fn authenticated_capsule_cannot_fake_rotation_with_same_key_under_another_term() -> TestResult {
    let (root, binding, ring) = fixture()?;
    let mut payload = ring.encode_payload()?;
    const FIRST_MATERIAL: usize = 37 + 4 + 12 + 8;
    const SLOT: usize = 56;
    let material = Zeroizing::new(payload[FIRST_MATERIAL..FIRST_MATERIAL + 32].to_vec());
    payload[FIRST_MATERIAL + SLOT..FIRST_MATERIAL + SLOT + 32].copy_from_slice(&material);
    let capsule = seal_capsule_payload(&root, &binding, ring.generation, &payload)?;
    assert!(matches!(
        PreparedRing::from_root_sealed_capsule(&root, binding, &capsule),
        Err(Error::DuplicateMaterial)
    ));
    Ok(())
}
#[test]
fn disabled_only_stops_auto_and_partial_patch_preserves_other_values() -> TestResult {
    let (_, _, mut ring) = fixture()?;
    ring.set_config_candidate(ConfigPatch {
        max_operations: Some(MIN_OPERATIONS),
        interval: Some(MIN_INTERVAL),
        ..ConfigPatch::default()
    })?;
    let enabled = ring.config();
    ring.set_config_candidate(ConfigPatch {
        enabled: Some(false),
        ..ConfigPatch::default()
    })?;
    assert_ne!(ring.config(), enabled);
    assert_eq!(ring.config().max_operations, MIN_OPERATIONS);
    assert_eq!(ring.config().interval, MIN_INTERVAL);
    assert_eq!(ring.auto_reason(Duration::from_secs(1_000_000))?, None);
    let one = ring.seal_candidate(b"resource", b"one")?;
    let two = ring.seal_candidate(b"resource", b"two")?;
    assert_eq!(ring.active_encryptions()?, 2);
    let manual = ring.prepare_manual_rotation(Duration::from_secs(30))?;
    assert_eq!(manual.active_term(), 3);
    assert!(manual.config().disabled);
    assert_eq!(manual.open(b"resource", &one)?.as_slice(), b"one");
    assert_eq!(manual.open(b"resource", &two)?.as_slice(), b"two");
    // Preparing a candidate cannot activate it or mutate the predecessor.
    assert_eq!(ring.active_term(), 2);
    assert_eq!(ring.active_encryptions()?, 2);
    Ok(())
}
#[test]
fn max_operations_and_interval_follow_official_strict_greater_than_contract() -> TestResult {
    let (_, _, mut ring) = fixture()?;
    ring.set_config_candidate(ConfigPatch {
        max_operations: Some(MIN_OPERATIONS),
        interval: Some(MIN_INTERVAL),
        ..ConfigPatch::default()
    })?;
    ring.keys.get_mut(&2).ok_or(Error::InvalidTerm)?.encryptions = MIN_OPERATIONS;
    let exactly = Duration::from_secs(10) + MIN_INTERVAL;
    assert_eq!(ring.auto_reason(exactly)?, None);
    assert_eq!(
        ring.auto_reason(exactly + Duration::from_nanos(1))?,
        Some(AutoReason::Interval)
    );
    ring.keys.get_mut(&2).ok_or(Error::InvalidTerm)?.encryptions += 1;
    assert_eq!(ring.auto_reason(exactly)?, Some(AutoReason::Operations));
    Ok(())
}
#[test]
fn invalid_config_patch_preserves_prior_candidate_and_counter_overflow_precedes_crypto()
-> TestResult {
    let (_, _, mut ring) = fixture()?;
    let before = ring.config();
    for patch in [
        ConfigPatch {
            max_operations: Some(MIN_OPERATIONS - 1),
            ..ConfigPatch::default()
        },
        ConfigPatch {
            max_operations: Some(MAX_OPERATIONS + 1),
            ..ConfigPatch::default()
        },
        ConfigPatch {
            interval: Some(MIN_INTERVAL - Duration::from_nanos(1)),
            ..ConfigPatch::default()
        },
    ] {
        assert_eq!(ring.set_config_candidate(patch), Err(Error::InvalidConfig));
        assert_eq!(ring.config(), before);
    }
    ring.keys.get_mut(&2).ok_or(Error::InvalidTerm)?.encryptions = u64::MAX;
    assert!(matches!(
        ring.seal_candidate(b"resource", b"value"),
        Err(Error::Overflow)
    ));
    assert_eq!(ring.active_encryptions()?, u64::MAX);
    Ok(())
}
#[test]
fn namespace_binding_cannot_borrow_root_ring_or_capsule() -> TestResult {
    let (root, mut binding, _) = fixture()?;
    binding.namespace = "child".into();
    assert!(matches!(
        PreparedRing::bootstrap(&root, binding, Duration::ZERO),
        Err(Error::InvalidBinding)
    ));
    Ok(())
}

#[test]
fn manual_rotation_rejects_time_regression_without_mutating_predecessor() -> TestResult {
    let (_, _, ring) = fixture()?;
    assert!(matches!(
        ring.prepare_manual_rotation(Duration::from_secs(9)),
        Err(Error::ClockRegression)
    ));
    assert_eq!(ring.active_term(), 2);
    Ok(())
}
