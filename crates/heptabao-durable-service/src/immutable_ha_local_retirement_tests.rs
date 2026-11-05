//! Real FileBackend tests for the lower transaction. This fixture history is
//! test DATA; only the server tests exercise the actual private HA custody.
use super::*;
use std::cell::Cell;

const HA_CURSOR: &str = "state-native-v6/ha-publication-cursor";

struct HistoricalFixture {
    resources: BTreeSet<String>,
    live: Cell<bool>,
}

impl HistoricalFixture {
    fn new() -> Self {
        Self {
            resources: BTreeSet::from([resource(1), resource(2), resource(80)]),
            live: Cell::new(true),
        }
    }
}

impl NativeHaLocalRetentionOwner for HistoricalFixture {
    fn catalog_sha256(&self) -> [u8; 32] {
        [0x4b; 32]
    }
    fn typed_retained_resources(&self) -> &BTreeSet<String> {
        &self.resources
    }
    fn verify(&self) -> Result<(), ServiceError> {
        if self.live.get() {
            Ok(())
        } else {
            Err(ServiceError::BarrierFailure)
        }
    }
}

fn ha_fixture(label: &str) -> Result<(TestRoot, Owner), Box<dyn std::error::Error>> {
    let (root, mut owner) = fixture(label)?;
    put(
        &mut owner,
        HA_CURSOR,
        b"exact-real-test-HA-cursor",
        "ha-cursor",
    )?;
    Ok((root, owner))
}

fn ha_request(owner: &mut Owner, id: &str) -> Result<ImmutableRetirementRequest, ServiceError> {
    let mut req = request(owner, id)?;
    req.conditions.push(PublicationCondition {
        resource: HA_CURSOR.into(),
        expected: owner.get("system", HA_CURSOR)?,
    });
    // Object 2 is absent from the current set but remains historical.
    req.retained_resources = BTreeSet::from([resource(1)]);
    Ok(req)
}

#[test]
fn native_ha_local_retirement_reuses_real_file_transaction_and_preserves_historical_members()
-> TestResult {
    let _serial = serial_test();
    let (root, mut owner) = ha_fixture("ha-local-real-file")?;
    let historical = HistoricalFixture::new();
    let generation = owner.generation();
    let original = objects(&root)?;
    let req = ha_request(&mut owner, "standalone-still-refuses")?;
    assert!(matches!(
        owner.retire_immutable_objects(req, &mut gate),
        Err(ServiceError::UnsupportedProfile)
    ));
    assert_eq!(owner.generation(), generation);
    assert_eq!(objects(&root)?, original);
    let req = ha_request(&mut owner, "real-ha-local")?;
    let result = owner.retire_native_ha_local_immutable_objects(req, &historical)?;
    assert_eq!(result.generation, generation + 2);
    assert_eq!(result.registered_objects_before, 3);
    assert_eq!(result.retained_objects, 2);
    assert_eq!(result.removed_objects, 1);
    assert_eq!(result.confirmed_absent_objects, 0);
    assert!(!root.0.join(leaf(3)).exists());
    assert_eq!(read(&mut owner, 1)?, bytes(1));
    assert_eq!(read(&mut owner, 2)?, bytes(2));
    assert_eq!(fs::read(root.0.join(leaf(99)))?, original[3]);
    owner.close()?;
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(read(&mut cold, 1)?, bytes(1));
    assert_eq!(read(&mut cold, 2)?, bytes(2));
    let req = ha_request(&mut cold, "new-empty-operation")?;
    let outcome = cold.retire_native_ha_local_immutable_objects(req, &HistoricalFixture::new())?;
    assert_eq!(outcome.generation, generation + 2);
    assert_eq!(outcome.removed_objects, 0);
    Ok(())
}

#[test]
fn native_ha_local_retirement_rejects_missing_history_selectors_and_live_source_holders()
-> TestResult {
    let _serial = serial_test();
    for case in 0..6 {
        let (root, mut owner) = ha_fixture(&format!("ha-local-hold-{case}"))?;
        let mut historical = HistoricalFixture::new();
        let extra = if case >= 4 {
            Some(owner.immutable_source_session("system", "state", ROOT, STORE)?)
        } else {
            None
        };
        if case == 5 {
            historical.resources.insert(resource(3));
        }
        let mut req = ha_request(&mut owner, "held-local")?;
        match case {
            0 => {
                req.conditions.pop();
            }
            1 => {
                req.retained_resources.insert(resource(90));
            }
            2 => {
                historical.resources.remove(&resource(1));
            }
            3 => {
                historical.live.set(false);
            }
            _ => {}
        }
        let generation = owner.generation();
        let original = objects(&root)?;
        assert!(
            owner
                .retire_native_ha_local_immutable_objects(req, &historical)
                .is_err()
        );
        assert_eq!(owner.generation(), generation);
        assert_eq!(objects(&root)?, original);
        assert!(owner.immutable_retirement_status()?.is_none());
        drop(extra);
    }
    let (root, mut owner) = ha_fixture("ha-local-unknown-selector")?;
    put(
        &mut owner,
        "state-native-v6/unknown-restore-root",
        b"hold",
        "unknown-selector",
    )?;
    let original = objects(&root)?;
    let generation = owner.generation();
    let req = ha_request(&mut owner, "unknown-side-root")?;
    assert!(matches!(
        owner.retire_native_ha_local_immutable_objects(req, &HistoricalFixture::new()),
        Err(ServiceError::UnsupportedProfile)
    ));
    assert_eq!(owner.generation(), generation);
    assert_eq!(objects(&root)?, original);
    Ok(())
}

fn pending_reconciliation(stage: u8) -> TestResult {
    let (root, mut owner) = ha_fixture(&format!("ha-local-cold-{stage}"))?;
    let historical = HistoricalFixture::new();
    let original_generation = owner.generation();
    let req = ha_request(&mut owner, "original-operation")?;
    {
        let _stop = Stop::at(stage);
        assert!(
            owner
                .retire_native_ha_local_immutable_objects(req, &historical)
                .is_err()
        );
    }
    assert!(owner.recovery_required());
    assert_eq!(root.0.join(leaf(3)).exists(), stage == 2);
    drop(owner);
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    let original = cold.immutable_retirement_status()?.ok_or("cold pending")?;
    assert!(original.pending && !original.original_completion_recorded);
    assert_eq!(cold.generation(), original_generation + 1);
    assert_eq!(read(&mut cold, 1)?, bytes(1));
    assert_eq!(read(&mut cold, 2)?, bytes(2));
    let generation = cold.generation();
    let req = ha_request(&mut cold, "cannot-replay-original")?;
    assert!(
        cold.retire_native_ha_local_immutable_objects(req, &HistoricalFixture::new())
            .is_err()
    );
    let req = ha_request(&mut cold, "wrong-pending-selector")?;
    assert!(
        cold.reconcile_native_ha_local_immutable_retirement(
            req,
            [0; 32],
            &HistoricalFixture::new()
        )
        .is_err()
    );
    let mut newly_retained = HistoricalFixture::new();
    newly_retained.resources.insert(resource(3));
    let object_states = || -> Result<Vec<Option<Vec<u8>>>, std::io::Error> {
        [1, 2, 3, 99]
            .into_iter()
            .map(|id| match fs::read(root.0.join(leaf(id))) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            })
            .collect()
    };
    let prior_files = object_states()?;
    let req = ha_request(&mut cold, "fresh-history-retains-old-pending")?;
    assert!(matches!(
        cold.reconcile_native_ha_local_immutable_retirement(
            req,
            original.record_sha256,
            &newly_retained
        ),
        Err(ServiceError::PublicationConditionConflict)
    ));
    assert_eq!(cold.generation(), generation);
    assert_eq!(object_states()?, prior_files);
    assert_eq!(
        cold.immutable_retirement_status()?
            .ok_or("fresh history holds pending")?
            .record_sha256,
        original.record_sha256
    );
    historical.live.set(false);
    let req = ha_request(&mut cold, "expired-old-owner")?;
    assert!(
        cold.reconcile_native_ha_local_immutable_retirement(
            req,
            original.record_sha256,
            &historical
        )
        .is_err()
    );
    assert_eq!(cold.generation(), generation);
    assert_eq!(
        cold.immutable_retirement_status()?
            .ok_or("still pending")?
            .record_sha256,
        original.record_sha256
    );
    let req = ha_request(&mut cold, "fresh-explicit-reconciliation")?;
    let outcome = cold.reconcile_native_ha_local_immutable_retirement(
        req,
        original.record_sha256,
        &HistoricalFixture::new(),
    )?;
    assert_eq!(outcome.removed_objects, usize::from(stage == 2));
    assert_eq!(outcome.confirmed_absent_objects, usize::from(stage == 3));
    assert_eq!(
        outcome.generation,
        generation + if stage == 2 { 2 } else { 1 }
    );
    assert!(!root.0.join(leaf(3)).exists());
    let completed = cold.immutable_retirement_status()?.ok_or("completed")?;
    assert!(!completed.pending);
    assert!(!completed.original_completion_recorded);
    assert!(!completed.historical_request_outcome_reclassified);
    assert_eq!(
        completed.original_pending_sha256,
        original.original_pending_sha256
    );
    cold.close()?;
    let mut again = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(read(&mut again, 1)?, bytes(1));
    assert_eq!(read(&mut again, 2)?, bytes(2));
    assert!(
        !again
            .immutable_retirement_status()?
            .ok_or("cold terminal")?
            .pending
    );
    Ok(())
}

#[test]
fn native_ha_local_retirement_cold_pending_needs_fresh_owner_and_exact_digest() -> TestResult {
    let _serial = serial_test();
    pending_reconciliation(2)
}

#[test]
fn native_ha_local_retirement_cold_absence_does_not_reclassify_original_completion() -> TestResult {
    let _serial = serial_test();
    pending_reconciliation(3)
}
