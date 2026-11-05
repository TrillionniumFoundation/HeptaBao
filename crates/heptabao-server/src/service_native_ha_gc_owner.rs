//! One affine shared-store owner, adapted to the existing authenticated ledger.
//! This adapter creates no Actor, deadline, Raft retention or file authority.
//! Its constructor accepts only the actual already-held physical plan.
use heptabao_durable_service::{
    NativeHaSharedCompletedOwner, NativeHaSharedPhysicalOutcome, NativeHaSharedPhysicalOwner,
    NativeHaSharedSelection, Secret, ServiceError,
};
use heptabao_raft_runtime::{
    LocalV6BlobError, NativeV6SharedRetirementPlan, NativeV6SharedRetirementReceipt,
};
use zeroize::Zeroizing;

pub(super) struct Physical<'a>(NativeV6SharedRetirementPlan<'a>);

impl<'a> Physical<'a> {
    pub(super) fn new(plan: NativeV6SharedRetirementPlan<'a>) -> Self {
        Self(plan)
    }
}

pub(super) struct Completed<'a>(NativeV6SharedRetirementReceipt<'a>);

impl<'a> NativeHaSharedPhysicalOwner for Physical<'a> {
    type Completed = Completed<'a>;

    fn selection(&self) -> Result<NativeHaSharedSelection, ServiceError> {
        let selected = self.0.selection();
        Ok(NativeHaSharedSelection {
            capsule: Secret::new(
                selected
                    .encode()
                    .map_err(|_| ServiceError::PublicationConditionConflict)?,
            )?,
            selected_files: selected.selected_files(),
            predecessor_selection_sha256: selected.predecessor_selection_digest(),
        })
    }

    fn verify(
        &self,
        original: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        original()?;
        self.0
            .verify_prepared()
            .map_err(|_| ServiceError::PublicationConditionConflict)?;
        original()
    }

    fn retire(
        self,
        verify_known_pending: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<Self::Completed, ServiceError> {
        let exact = Zeroizing::new(
            self.0
                .selection()
                .encode()
                .map_err(|_| ServiceError::RecoveryRequired)?,
        );
        // The ledger owns verify_known_pending: it checks the same original
        // Actor, current source/cursors, exact pending bytes and generation at
        // every physical boundary. The lower plan additionally checks its own
        // held Raft writers, shared quiescence, same FDs and ciphertext bytes.
        // Neither decoded capsule bytes nor a future lookup can mint the plan.
        let mut gate = |capsule: &[u8]| -> Result<(), LocalV6BlobError> {
            if capsule != exact.as_slice() {
                return Err(LocalV6BlobError::CorruptOrChanged);
            }
            verify_known_pending().map_err(|_| LocalV6BlobError::CorruptOrChanged)
        };
        let completed = self
            .0
            .retire_after_known_ledger(&mut gate)
            // A known Pending Apply already exists. Preserve it for explicit
            // new reconciliation even when the physical refusal was early.
            // Never reinterpret an unlink error as proof that nothing changed.
            .map_err(|_| ServiceError::RecoveryRequired)?;
        #[cfg(test)]
        if FAIL_AFTER_PHYSICAL.with(|slot| slot.replace(false)) {
            // The actual unlink/fsync completed, but the local ledger did not
            // receive its completion. This models an unknown physical outcome
            // while retaining the real committed pending capsule for recovery.
            return Err(ServiceError::RecoveryRequired);
        }
        Ok(Completed(completed))
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_AFTER_PHYSICAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(super) fn fail_after_physical_once() {
    FAIL_AFTER_PHYSICAL.with(|slot| assert!(!slot.replace(true)));
}

impl NativeHaSharedCompletedOwner for Completed<'_> {
    fn outcome(&self) -> NativeHaSharedPhysicalOutcome {
        let actual = self.0.outcome();
        // The physical plan is bounded to 32 names. An unsupported wider usize
        // cannot truncate a count: the ledger rejects the saturated sentinel.
        let count = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
        NativeHaSharedPhysicalOutcome {
            removed_blobs: count(actual.removed_blobs),
            removed_manifests: count(actual.removed_manifests),
            removed_temporary_files: count(actual.removed_temporary_files),
            removed_ciphertext_bytes: actual.removed_ciphertext_bytes,
            removed_other_bytes: actual.removed_other_bytes,
            confirmed_absent_files: count(actual.confirmed_absent_files),
            currently_retained_files: count(actual.currently_retained_files),
        }
    }

    fn verify_completed(
        &self,
        original: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        original()?;
        self.0
            .verify_completed()
            .map_err(|_| ServiceError::RecoveryRequired)?;
        original()
    }
}
