//! Real barrier/journal/cold-owner tests. The submission/observation fixture is
//! explicit: these tests grant no Raft, Service Actor, TLS or physical-host proof.
use super::*;
use crate::tests::{TestBarrier, TestRoot, serial_test};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::{cell::Cell, rc::Rc};

type Owner = DurableService<TestBarrier>;
type TestResult = Result<(), Box<dyn std::error::Error>>;
const STORE: [u8; 16] = [0x42; 16];
const CAPSULE: &[u8] = b"fixture-data-not-a-raft-submission-owner";
fn gate() -> Result<(), ServiceError> {
    Ok(())
}

struct Submission {
    calls: Rc<Cell<usize>>,
    held: Rc<Cell<bool>>,
    fail: bool,
}
struct Completion {
    held: Rc<Cell<bool>>,
}
impl Drop for Completion {
    fn drop(&mut self) {
        self.held.set(false);
    }
}
impl NativeHaIntentOwner for Submission {
    type Completed = Completion;
    fn selection(&self) -> Result<NativeHaIntentSelection, ServiceError> {
        Ok(NativeHaIntentSelection {
            capsule: Secret::new(CAPSULE.to_vec())?,
            serial: 7,
            command_sha256: [9; 32],
            selected_intents: 0,
        })
    }
    fn verify(
        &self,
        original: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        original()
    }
    fn submit(
        self,
        known: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<Completion, ServiceError> {
        known()?;
        self.calls.set(self.calls.get() + 1);
        if self.fail {
            return Err(ServiceError::RecoveryRequired);
        }
        self.held.set(true);
        known()?;
        Ok(Completion { held: self.held })
    }
}
impl NativeHaIntentCompletedOwner for Completion {
    fn committed(&self) -> NativeHaIntentCommit {
        NativeHaIntentCommit {
            leader_id: 1,
            log_index: 11,
            command_sha256: [9; 32],
        }
    }
    fn verify_completed(
        &self,
        original: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        if !self.held.get() {
            return Err(ServiceError::RecoveryRequired);
        }
        original()
    }
}
struct Observation {
    capsule: [u8; 32],
    resolution: NativeHaIntentResolution,
    valid: bool,
}
impl NativeHaIntentReconciliationOwner for Observation {
    fn capsule_sha256(&self) -> [u8; 32] {
        self.capsule
    }
    fn resolution(&self) -> NativeHaIntentResolution {
        self.resolution
    }
    fn verify_observation(
        &self,
        original: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        if !self.valid {
            return Err(ServiceError::PublicationConditionConflict);
        }
        original()
    }
}
fn fixture(label: &str) -> Result<(TestRoot, Owner), Box<dyn std::error::Error>> {
    let root = TestRoot::new(label)?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&root.0)?;
    std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700))?;
    let mut owner = Owner::create_new(&root.0, TestBarrier::new(), 256)?;
    for (index, resource) in REQUIRED.into_iter().enumerate() {
        owner.put(PutRequest::new(
            "intent-fixture",
            "system",
            format!("seed-{index}"),
            resource,
            [5; 32],
            Secret::new(format!("exact-current-{resource}").into_bytes())?,
        )?)?;
    }
    Ok((root, owner))
}
fn source(
    owner: &mut Owner,
) -> Result<(ImmutableSourceSession, Vec<PublicationCondition>), ServiceError> {
    let root = owner
        .get("system", "state")?
        .ok_or(ServiceError::CorruptState)?;
    let session = owner.immutable_source_session("system", "state", root.expose(), STORE)?;
    let conditions = REQUIRED
        .into_iter()
        .map(|resource| {
            Ok(PublicationCondition {
                resource: resource.into(),
                expected: owner.get("system", resource)?,
            })
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;
    Ok((session, conditions))
}
fn request(
    owner: &mut Owner,
    id: &str,
    fail: bool,
    calls: Rc<Cell<usize>>,
    held: Rc<Cell<bool>>,
) -> Result<NativeHaIntentRetirementRequest<Submission>, ServiceError> {
    let (session, conditions) = source(owner)?;
    Ok(NativeHaIntentRetirementRequest {
        session,
        principal: "intent-fixture".into(),
        operation_id: id.into(),
        authorization_digest: [6; 32],
        conditions,
        owner: Submission { calls, held, fail },
    })
}
fn reconcile(
    owner: &mut Owner,
    id: &str,
    expected: [u8; 32],
    observer: Observation,
) -> Result<NativeHaIntentReconciliationRequest<Observation>, ServiceError> {
    let (session, conditions) = source(owner)?;
    Ok(NativeHaIntentReconciliationRequest {
        session,
        principal: "intent-fixture".into(),
        operation_id: id.into(),
        authorization_digest: [6; 32],
        conditions,
        expected_pending_sha256: expected,
        observer,
    })
}

#[test]
fn native_ha_intent_ledger_zero_selection_still_commits_pending_before_one_command_and_complete()
-> TestResult {
    let _serial = serial_test();
    let (root, mut owner) = fixture("ha-intent-complete")?;
    let calls = Rc::new(Cell::new(0));
    let held = Rc::new(Cell::new(false));
    let generation = owner.generation();
    let action = request(
        &mut owner,
        "one-command",
        false,
        calls.clone(),
        held.clone(),
    )?;
    let result = owner.retire_native_ha_intents(action, &mut gate)?;
    assert_eq!(result.generation, generation + 2);
    assert_eq!(calls.get(), 1);
    assert!(!held.get());
    let status = owner
        .native_ha_intent_retirement_status()?
        .ok_or("status")?;
    assert_eq!(status.phase, "original-completed");
    assert_eq!(status.selected_intents, 0);
    assert!(!status.pending);
    assert!(!status.historical_request_outcome_reclassified);
    owner.close()?;
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(cold.native_ha_intent_retirement_status()?, Some(status));
    assert_eq!(calls.get(), 1);
    cold.export_core_backup_to(&mut Vec::new())?;
    Ok(())
}

#[test]
fn native_ha_intent_ledger_unknown_is_durable_and_cold_observation_cannot_resubmit() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner) = fixture("ha-intent-unknown")?;
    let calls = Rc::new(Cell::new(0));
    let held = Rc::new(Cell::new(false));
    let generation = owner.generation();
    let action = request(&mut owner, "unknown", true, calls.clone(), held.clone())?;
    assert!(owner.retire_native_ha_intents(action, &mut gate).is_err());
    assert!(owner.recovery_required());
    assert_eq!(calls.get(), 1);
    drop(owner);
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(cold.generation(), generation + 1);
    let status = cold
        .native_ha_intent_retirement_status()?
        .ok_or("pending")?;
    assert!(status.pending);
    let capsule = cold.native_ha_pending_intent_retirement(status.record_sha256)?;
    assert_eq!(capsule.expose(), CAPSULE);
    assert!(cold.export_core_backup_to(&mut Vec::new()).is_err());
    let bytes = cold.backend.load()?;
    let again = request(
        &mut cold,
        "must-not-replay",
        false,
        calls.clone(),
        held.clone(),
    )?;
    assert!(cold.retire_native_ha_intents(again, &mut gate).is_err());
    assert_eq!(calls.get(), 1);
    assert_eq!(cold.backend.load()?, bytes);
    for (index, pending, cap, resolution, valid) in [
        (
            0,
            [0x55; 32],
            digest(CAPSULE),
            NativeHaIntentResolution::EffectsObserved,
            true,
        ),
        (
            1,
            status.record_sha256,
            [0x66; 32],
            NativeHaIntentResolution::EffectsObserved,
            true,
        ),
        (
            2,
            status.record_sha256,
            digest(CAPSULE),
            NativeHaIntentResolution::Pending,
            true,
        ),
        (
            3,
            status.record_sha256,
            digest(CAPSULE),
            NativeHaIntentResolution::EffectsObserved,
            false,
        ),
    ] {
        let read = reconcile(
            &mut cold,
            &format!("refuse-{index}"),
            pending,
            Observation {
                capsule: cap,
                resolution,
                valid,
            },
        )?;
        assert!(
            cold.reconcile_native_ha_intent_retirement(read, &mut gate)
                .is_err()
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(cold.backend.load()?, bytes);
        assert!(!cold.recovery_required());
    }
    let read = reconcile(
        &mut cold,
        "new-read-only-observation",
        status.record_sha256,
        Observation {
            capsule: digest(CAPSULE),
            resolution: NativeHaIntentResolution::EffectsObserved,
            valid: true,
        },
    )?;
    let result = cold.reconcile_native_ha_intent_retirement(read, &mut gate)?;
    assert_eq!(result.generation, generation + 2);
    assert_eq!(calls.get(), 1, "observer has no submission interface");
    let now = cold
        .native_ha_intent_retirement_status()?
        .ok_or("completed observation")?;
    assert_eq!(now.phase, "reconciled-effects-observed");
    assert_eq!(now.original_pending_sha256, status.record_sha256);
    assert!(!now.historical_request_outcome_reclassified);
    cold.close()?;
    let mut again = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(again.native_ha_intent_retirement_status()?, Some(now));
    assert_eq!(calls.get(), 1);
    Ok(())
}

#[test]
fn native_ha_intent_ledger_actor_capacity_and_foreign_source_stop_before_pending_or_submission()
-> TestResult {
    let _serial = serial_test();
    let (_root, mut owner) = fixture("ha-intent-before-submit")?;
    let calls = Rc::new(Cell::new(0));
    let held = Rc::new(Cell::new(false));
    let bytes = owner.backend.load()?;
    let action = request(&mut owner, "actor-veto", false, calls.clone(), held.clone())?;
    assert!(
        owner
            .retire_native_ha_intents(action, &mut || Err(ServiceError::BarrierFailure))
            .is_err()
    );
    assert_eq!(owner.backend.load()?, bytes);
    assert_eq!(calls.get(), 0);
    let mut action = request(
        &mut owner,
        "source-veto",
        false,
        calls.clone(),
        held.clone(),
    )?;
    action.conditions[0].expected = Some(Secret::new(b"different-current-root".to_vec())?);
    assert!(owner.retire_native_ha_intents(action, &mut gate).is_err());
    assert_eq!(owner.backend.load()?, bytes);
    assert_eq!(calls.get(), 0);
    owner.max_retained_requests = owner.ledger.len() + 1;
    let action = request(
        &mut owner,
        "pair-capacity",
        false,
        calls.clone(),
        held.clone(),
    )?;
    assert!(owner.retire_native_ha_intents(action, &mut gate).is_err());
    assert_eq!(owner.backend.load()?, bytes);
    assert_eq!(calls.get(), 0);
    assert!(owner.native_ha_intent_retirement_status()?.is_none());
    Ok(())
}

// Deliberately build an authenticated historical backup fixture below the
// public exporter. The exporter itself must never produce this Pending backup.
fn historical_pending_backup(owner: &Owner) -> Result<Vec<u8>, ServiceError> {
    let snapshot = sealed_snapshot(&owner.barrier, &owner.snapshot)?;
    let ledger = sealed_ledger(
        &owner.barrier,
        owner.generation(),
        owner.replay_epoch,
        owner.retired_through_generation,
        &owner.ledger,
    )?;
    let checkpoint = sealed_journal_record(
        &owner.barrier,
        1,
        &JournalEvent::Checkpoint(checkpoint_marker(
            &owner.snapshot,
            &owner.ledger,
            owner.retired_through_generation,
        )?),
    )?;
    let mut journal = JOURNAL_MAGIC.to_vec();
    journal.extend_from_slice(&checkpoint);
    encode_backup(owner.generation(), &snapshot, &journal, &ledger)
}

#[test]
fn native_ha_intent_ledger_pending_blocks_export_restore_stream_and_active_restore_owner()
-> TestResult {
    let _serial = serial_test();
    let (root, mut owner) = fixture("ha-intent-restore-holds")?;
    let safe = owner.export_backup()?;
    let prepared = owner.prepare_restore(&safe)?;
    let bytes = owner.backend.load()?;
    let calls = Rc::new(Cell::new(0));
    let held = Rc::new(Cell::new(false));
    let action = request(
        &mut owner,
        "active-restore",
        false,
        calls.clone(),
        held.clone(),
    )?;
    assert!(owner.retire_native_ha_intents(action, &mut gate).is_err());
    assert_eq!(calls.get(), 0);
    assert_eq!(owner.backend.load()?, bytes);
    drop(prepared);
    let action = request(
        &mut owner,
        "unknown-before-restore",
        true,
        calls.clone(),
        held,
    )?;
    assert!(owner.retire_native_ha_intents(action, &mut gate).is_err());
    drop(owner);
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    let bytes = cold.backend.load()?;
    assert!(matches!(
        cold.export_backup(),
        Err(ServiceError::RecoveryRequired)
    ));
    assert!(matches!(
        cold.prepare_restore(&safe),
        Err(ServiceError::RecoveryRequired)
    ));
    assert!(matches!(
        cold.prepare_restore_from_reader(&mut safe.as_slice(), safe.len() as u64),
        Err(ServiceError::RecoveryRequired)
    ));
    assert!(matches!(
        cold.restore_backup(&safe, true),
        Err(ServiceError::RecoveryRequired)
    ));
    assert_eq!(cold.backend.load()?, bytes);
    assert_eq!(calls.get(), 1);
    let incoming = historical_pending_backup(&cold)?;
    let (_target_root, mut target) = fixture("ha-intent-incoming-pending")?;
    let target_bytes = target.backend.load()?;
    assert!(matches!(
        target.prepare_restore(&incoming),
        Err(ServiceError::RecoveryRequired)
    ));
    assert!(matches!(
        target.prepare_restore_from_reader(&mut incoming.as_slice(), incoming.len() as u64),
        Err(ServiceError::RecoveryRequired)
    ));
    assert!(matches!(
        target.restore_backup(&incoming, true),
        Err(ServiceError::RecoveryRequired)
    ));
    assert!(matches!(
        Owner::ensure_ha_intent_retirement_snapshot_complete(&cold.snapshot),
        Err(ServiceError::RecoveryRequired)
    ));
    assert_eq!(target.backend.load()?, target_bytes);
    assert!(!target.recovery_required());
    Ok(())
}

#[path = "native_ha_intent_legacy_codec_tests.rs"]
mod legacy_codec;

#[path = "native_ha_intent_pack_tests.rs"]
mod pack_holds;
