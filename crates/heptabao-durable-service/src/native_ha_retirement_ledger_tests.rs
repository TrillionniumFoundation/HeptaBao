//! Real barrier/journal/cold-owner tests. The physical trait fixture supplies
//! no Raft/typed-mark/TLS qualification; separate shared-store tests owe that.
use super::*;
use crate::tests::{TestBarrier, TestRoot, serial_test};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::{cell::Cell, rc::Rc};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Owner = DurableService<TestBarrier>;
const ROOT: &[u8] = b"actual-local-native-shared-ledger-fixture";
const STORE: [u8; 16] = [0x71; 16];
fn gate() -> Result<(), ServiceError> {
    Ok(())
}

struct Physical {
    capsule: Vec<u8>,
    predecessor: Option<[u8; 32]>,
    invocations: Rc<Cell<usize>>,
    completed_held: Rc<Cell<bool>>,
    fail: bool,
}
struct Completed {
    invocations: Rc<Cell<usize>>,
    held: Rc<Cell<bool>>,
}
impl Drop for Completed {
    fn drop(&mut self) {
        self.held.set(false);
    }
}
impl NativeHaSharedPhysicalOwner for Physical {
    type Completed = Completed;
    fn selection(&self) -> Result<NativeHaSharedSelection, ServiceError> {
        Ok(NativeHaSharedSelection {
            capsule: Secret::new(self.capsule.clone())?,
            selected_files: 1,
            predecessor_selection_sha256: self.predecessor,
        })
    }
    fn verify(
        &self,
        original: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        original()
    }
    fn retire(
        self,
        original: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<Completed, ServiceError> {
        // This callback has to observe the actual known pending metadata. The
        // ledger checks its exact generation and bytes before admitting us.
        original()?;
        self.invocations.set(self.invocations.get() + 1);
        if self.fail {
            return Err(ServiceError::RecoveryRequired);
        }
        self.completed_held.set(true);
        original()?;
        Ok(Completed {
            invocations: self.invocations,
            held: self.completed_held,
        })
    }
}
impl NativeHaSharedCompletedOwner for Completed {
    fn outcome(&self) -> NativeHaSharedPhysicalOutcome {
        NativeHaSharedPhysicalOutcome {
            removed_blobs: 1,
            removed_ciphertext_bytes: 64,
            ..Default::default()
        }
    }
    fn verify_completed(
        &self,
        original: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        if !self.held.get() || self.invocations.get() == 0 {
            return Err(ServiceError::RecoveryRequired);
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
        let value = if resource == "state" {
            ROOT
        } else {
            b"exact-current-fixture-resource"
        };
        owner.put(PutRequest::new(
            "ha-ledger-fixture",
            "system",
            format!("seed-{index}"),
            resource,
            [7; 32],
            Secret::new(value.to_vec())?,
        )?)?;
    }
    Ok((root, owner))
}
fn request(
    owner: &mut Owner,
    operation: &str,
    expected: Option<[u8; 32]>,
    predecessor: Option<[u8; 32]>,
    fail: bool,
    invoked: Rc<Cell<usize>>,
    held: Rc<Cell<bool>>,
) -> Result<NativeHaSharedRetirementRequest<Physical>, ServiceError> {
    Ok(NativeHaSharedRetirementRequest {
        session: owner.immutable_source_session("system", "state", ROOT, STORE)?,
        principal: "ha-ledger-fixture".into(),
        operation_id: operation.into(),
        authorization_digest: [8; 32],
        expected_pending_sha256: expected,
        conditions: REQUIRED
            .into_iter()
            .map(|resource| {
                Ok(PublicationCondition {
                    resource: resource.into(),
                    expected: owner.get("system", resource)?,
                })
            })
            .collect::<Result<Vec<_>, ServiceError>>()?,
        physical: Physical {
            capsule: format!("data-only-physical-selection-{operation}").into_bytes(),
            predecessor,
            invocations: invoked,
            completed_held: held,
            fail,
        },
    })
}

#[test]
fn native_ha_shared_ledger_actual_pair_and_completed_owner_survive_cold_reopen() -> TestResult {
    let _serial = serial_test();
    let (root, mut owner) = fixture("ha-shared-ledger-positive")?;
    let invoked = Rc::new(Cell::new(0));
    let held = Rc::new(Cell::new(false));
    let generation = owner.generation();
    let request = request(
        &mut owner,
        "positive",
        None,
        None,
        false,
        invoked.clone(),
        held.clone(),
    )?;
    let out = owner.retire_native_ha_shared(request, &mut gate)?;
    assert_eq!(out.generation, generation + 2);
    assert_eq!(out.physical.removed_blobs, 1);
    assert_eq!(invoked.get(), 1);
    assert!(!held.get());
    let status = owner
        .native_ha_shared_retirement_status()?
        .ok_or("missing status")?;
    assert!(!status.pending);
    assert_eq!(status.phase, "original-completed");
    assert!(!status.historical_request_outcome_reclassified);
    let original = owner
        .get("system", NATIVE_HA_SHARED_RETIREMENT_RESOURCE)?
        .ok_or("missing record")?;
    owner.close()?;
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(
        cold.get("system", NATIVE_HA_SHARED_RETIREMENT_RESOURCE)?
            .as_ref()
            .map(Secret::expose),
        Some(original.expose())
    );
    assert_eq!(cold.native_ha_shared_retirement_status()?, Some(status));
    let mut backup = Vec::new();
    cold.export_core_backup_to(&mut backup)?;
    assert!(!backup.is_empty());
    Ok(())
}

#[test]
fn native_ha_shared_ledger_unknown_cold_requires_exact_digest_and_new_physical_owner() -> TestResult
{
    let _serial = serial_test();
    let (root, mut owner) = fixture("ha-shared-ledger-unknown")?;
    let invoked = Rc::new(Cell::new(0));
    let held = Rc::new(Cell::new(false));
    let generation = owner.generation();
    let original = request(
        &mut owner,
        "original",
        None,
        None,
        true,
        invoked.clone(),
        held.clone(),
    )?;
    assert!(owner.retire_native_ha_shared(original, &mut gate).is_err());
    assert!(owner.recovery_required());
    assert_eq!(invoked.get(), 1);
    assert!(!held.get());
    drop(owner);
    let mut cold = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(cold.generation(), generation + 1);
    let status = cold
        .native_ha_shared_retirement_status()?
        .ok_or("pending status absent")?;
    assert!(status.pending);
    assert_eq!(status.reconciliation_attempt, 0);
    let prior = cold
        .get("system", NATIVE_HA_SHARED_RETIREMENT_RESOURCE)?
        .ok_or("pending record absent")?;
    let selected = cold.native_ha_shared_pending_selection(status.record_sha256)?;
    let before = cold.backend.load()?;
    for (label, expected, predecessor) in [
        ("normal-must-not-replay", None, None),
        (
            "wrong-record",
            Some([0x55; 32]),
            Some(raw_digest(selected.expose())),
        ),
        (
            "wrong-selection",
            Some(status.record_sha256),
            Some([0x66; 32]),
        ),
    ] {
        let next = request(
            &mut cold,
            label,
            expected,
            predecessor,
            false,
            invoked.clone(),
            held.clone(),
        )?;
        assert!(cold.retire_native_ha_shared(next, &mut gate).is_err());
        assert!(!cold.recovery_required());
        assert_eq!(invoked.get(), 1);
        assert_eq!(cold.backend.load()?, before);
    }
    assert!(
        cold.export_core_backup_to(&mut Vec::new()).is_err(),
        "pending physical retirement must not enter backup"
    );
    let new = request(
        &mut cold,
        "explicit-new-owner",
        Some(status.record_sha256),
        Some(raw_digest(selected.expose())),
        false,
        invoked.clone(),
        held.clone(),
    )?;
    let result = cold.retire_native_ha_shared(new, &mut gate)?;
    assert_eq!(result.generation, generation + 3);
    assert_eq!(invoked.get(), 2);
    assert!(!held.get());
    let now = cold
        .native_ha_shared_retirement_status()?
        .ok_or("new completion absent")?;
    assert!(!now.pending);
    assert_eq!(now.reconciliation_attempt, 1);
    assert_eq!(now.original_pending_sha256, status.record_sha256);
    assert!(!now.historical_request_outcome_reclassified);
    assert_eq!(
        raw_digest(prior.expose()),
        status.record_sha256,
        "original failed receipt is unchanged data"
    );
    cold.close()?;
    let mut again = Owner::reopen(&root.0, TestBarrier::new(), 256)?;
    assert_eq!(again.native_ha_shared_retirement_status()?, Some(now));
    Ok(())
}

#[test]
fn native_ha_shared_ledger_two_request_slots_and_full_journal_pair_precede_physical_call()
-> TestResult {
    let _serial = serial_test();
    for pressure in ["request-slots", "journal"] {
        let (_root, mut owner) = fixture(&format!("ha-shared-ledger-capacity-{pressure}"))?;
        let invoked = Rc::new(Cell::new(0));
        let held = Rc::new(Cell::new(false));
        if pressure == "request-slots" {
            owner.max_retained_requests = owner.ledger.len() + 1;
        } else {
            owner.journal_limit = owner.journal_bytes + 1;
        }
        let before = owner.backend.load()?;
        let request = request(
            &mut owner,
            "must-preflight-pair",
            None,
            None,
            false,
            invoked.clone(),
            held.clone(),
        )?;
        assert!(owner.retire_native_ha_shared(request, &mut gate).is_err());
        assert_eq!(invoked.get(), 0);
        assert!(!held.get());
        assert!(!owner.recovery_required());
        assert_eq!(owner.backend.load()?, before);
    }
    let (_root, mut owner) = fixture("ha-shared-ledger-two-exact-slots")?;
    let invoked = Rc::new(Cell::new(0));
    let held = Rc::new(Cell::new(false));
    owner.max_retained_requests = owner.ledger.len() + 2;
    let request = request(
        &mut owner,
        "two-exact-slots",
        None,
        None,
        false,
        invoked.clone(),
        held,
    )?;
    owner.retire_native_ha_shared(request, &mut gate)?;
    assert_eq!(invoked.get(), 1);
    assert_eq!(owner.ledger.len(), owner.max_retained_requests);
    Ok(())
}

#[test]
fn native_ha_shared_ledger_original_session_and_prepared_restore_hold_before_any_metadata()
-> TestResult {
    let _serial = serial_test();
    for kind in ["session", "prepared-restore"] {
        let (_root, mut owner) = fixture(&format!("ha-shared-ledger-held-{kind}"))?;
        let hold: Box<dyn std::any::Any> = if kind == "session" {
            Box::new(owner.immutable_source_session("system", "state", ROOT, STORE)?)
        } else {
            let mut backup = Vec::new();
            owner.export_core_backup_to(&mut backup)?;
            Box::new(owner.prepare_core_restore(&backup)?)
        };
        let before = owner.backend.load()?;
        let invoked = Rc::new(Cell::new(0));
        let held = Rc::new(Cell::new(false));
        let blocked = request(
            &mut owner,
            "held",
            None,
            None,
            false,
            invoked.clone(),
            held.clone(),
        )?;
        assert!(owner.retire_native_ha_shared(blocked, &mut gate).is_err());
        assert_eq!(invoked.get(), 0);
        assert_eq!(owner.backend.load()?, before);
        drop(hold);
        let current = request(
            &mut owner,
            "released",
            None,
            None,
            false,
            invoked.clone(),
            held,
        )?;
        owner.retire_native_ha_shared(current, &mut gate)?;
        assert_eq!(invoked.get(), 1);
    }
    Ok(())
}

#[test]
fn native_ha_shared_ledger_source_conditions_reconciliation_lineage_and_counts_fail_closed()
-> TestResult {
    let _serial = serial_test();
    let (_root, mut owner) = fixture("ha-shared-ledger-invalid")?;
    let invoked = Rc::new(Cell::new(0));
    let held = Rc::new(Cell::new(false));
    let before = owner.backend.load()?;
    for changed in 0..3 {
        let mut invalid = request(
            &mut owner,
            &format!("invalid-{changed}"),
            None,
            None,
            false,
            invoked.clone(),
            held.clone(),
        )?;
        match changed {
            0 => {
                invalid.conditions.pop();
            }
            1 => invalid.conditions[0].expected = Some(Secret::new(b"different-source".to_vec())?),
            _ => invalid.physical.predecessor = Some([1; 32]),
        }
        assert!(owner.retire_native_ha_shared(invalid, &mut gate).is_err());
        assert_eq!(owner.backend.load()?, before);
        assert_eq!(invoked.get(), 0);
    }
    let valid = request(&mut owner, "valid", None, None, false, invoked, held)?;
    owner.retire_native_ha_shared(valid, &mut gate)?;
    let encoded = owner
        .get("system", NATIVE_HA_SHARED_RETIREMENT_RESOURCE)?
        .ok_or("record")?;
    for changed in 0..4 {
        let mut record = Record::decode(encoded.expose())?;
        match changed {
            0 => record.attempt = 1,
            1 => record.original_pending_sha256 = [1; 32],
            2 => record.physical.removed_blobs = 2,
            _ => record.pending_generation += 1,
        }
        assert!(record.encode().is_err());
    }
    Ok(())
}
