//! Adapt actual process-minted affine owners to the authenticated local ledger.
//! Recovery bytes have no constructor for Prepared and no submission method.
use crate::ha::{
    NativeHaCommittedIntentRetirement, NativeHaIntentReadObservation,
    NativeHaPreparedIntentRetirement,
};
use heptabao_durable_service::{
    NativeHaIntentCommit, NativeHaIntentCompletedOwner, NativeHaIntentOwner,
    NativeHaIntentReconciliationOwner, NativeHaIntentResolution, NativeHaIntentSelection, Secret,
    ServiceError,
};
use heptabao_raft_runtime::{LocalV6BlobError, NativeV6IntentRetirementResolution};

pub(super) struct Prepared<'a>(NativeHaPreparedIntentRetirement<'a>);
pub(super) struct Completed<'a>(NativeHaCommittedIntentRetirement<'a>);
pub(super) struct Observation<'a>(NativeHaIntentReadObservation<'a>);

impl<'a> Prepared<'a> {
    pub(super) fn new(owner: NativeHaPreparedIntentRetirement<'a>) -> Self {
        Self(owner)
    }
}
impl<'a> Observation<'a> {
    pub(super) fn new(owner: NativeHaIntentReadObservation<'a>) -> Self {
        Self(owner)
    }
}

impl<'a> NativeHaIntentOwner for Prepared<'a> {
    type Completed = Completed<'a>;
    fn selection(&self) -> Result<NativeHaIntentSelection, ServiceError> {
        let data = self.0.recovery();
        Ok(NativeHaIntentSelection {
            capsule: Secret::new(
                data.encode()
                    .map_err(|_| ServiceError::PublicationConditionConflict)?,
            )?,
            serial: data.serial(),
            command_sha256: data
                .command_digest()
                .map_err(|_| ServiceError::PublicationConditionConflict)?,
            selected_intents: data.selected_intents(),
        })
    }
    fn verify(
        &self,
        original: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        original()?;
        self.0
            .verify()
            .map_err(|_| ServiceError::PublicationConditionConflict)?;
        original()
    }
    fn submit(
        self,
        known_pending: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<Self::Completed, ServiceError> {
        // Known Pending is checked immediately around the single actual Raft
        // submission and its new read-only observation. No old capsule is
        // converted back to a command owner after an unknown outcome.
        #[cfg(test)]
        SUBMISSION_OWNERS_CONSUMED.with(|slot| slot.set(slot.get() + 1));
        let completed = self
            .0
            .submit(&mut || known_pending().map_err(|_| LocalV6BlobError::CorruptOrChanged))
            .map_err(|_| ServiceError::RecoveryRequired)?;
        #[cfg(test)]
        if FAIL_AFTER_COMMIT.with(|slot| slot.replace(false)) {
            return Err(ServiceError::RecoveryRequired);
        }
        Ok(Completed(completed))
    }
}
impl NativeHaIntentCompletedOwner for Completed<'_> {
    fn committed(&self) -> NativeHaIntentCommit {
        let receipt = self.0.receipt();
        NativeHaIntentCommit {
            leader_id: receipt.leader_id,
            log_index: receipt.log_index,
            command_sha256: receipt.envelope_digest,
        }
    }
    fn verify_completed(
        &self,
        original: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        original()?;
        self.0
            .verify()
            .map_err(|_| ServiceError::RecoveryRequired)?;
        original()
    }
}
impl NativeHaIntentReconciliationOwner for Observation<'_> {
    fn capsule_sha256(&self) -> [u8; 32] {
        self.0.capsule_digest()
    }
    fn resolution(&self) -> NativeHaIntentResolution {
        match self.0.resolution() {
            NativeV6IntentRetirementResolution::Pending => NativeHaIntentResolution::Pending,
            NativeV6IntentRetirementResolution::EffectsObserved => {
                NativeHaIntentResolution::EffectsObserved
            }
            NativeV6IntentRetirementResolution::SupersededByNewRoot => {
                NativeHaIntentResolution::SupersededByNewRoot
            }
        }
    }
    fn verify_observation(
        &self,
        original: &mut dyn FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        original()?;
        self.0
            .verify()
            .map_err(|_| ServiceError::PublicationConditionConflict)?;
        original()
    }
}

#[cfg(test)]
thread_local! {
    static SUBMISSION_OWNERS_CONSUMED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static FAIL_AFTER_COMMIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(super) fn fail_after_commit_once() {
    FAIL_AFTER_COMMIT.with(|slot| assert!(!slot.replace(true)));
}

#[cfg(test)]
pub(super) fn submission_owners_consumed() -> usize {
    SUBMISSION_OWNERS_CONSUMED.with(std::cell::Cell::get)
}
