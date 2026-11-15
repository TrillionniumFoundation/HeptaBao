//! Affine prepared submission and fresh read-only metadata reconciliation.
//! The caller must separately hold the original Actor/deadline, all-member
//! reader6 admission and its authenticated exact Pending barrier record.
use super::*;
use crate::v6_retention::{
    NativeV6IntentRetirementRecovery, NativeV6IntentRetirementResolution, NativeV6RetentionSource,
};

fn source(read: &NativeV6CommittedRootRead) -> NativeV6RetentionSource {
    NativeV6RetentionSource {
        enrollment_digest: read.enrollment().digest(),
        root_digest: read.root().root_digest(),
        generation: read.root().generation(),
        epoch: read.enrollment().epoch(),
        publication_log: read.root().publication_log_id(),
        intent_log: read.root().intent_log_id(),
    }
}
fn unavailable() -> RemoteRaftError {
    RemoteRaftError::Consensus("native intent retirement original observation unavailable".into())
}

/// This non-Clone, non-Serde owner is minted only from this process's actual
/// selected ReadIndex and command preparation. The recovery capsule is data;
/// no API reconstructs this owner from it after an unknown result.
pub struct NativeV6PreparedIntentRetirement {
    selected: NativeV6CommittedRootRead,
    recovery: NativeV6IntentRetirementRecovery,
}
impl std::fmt::Debug for NativeV6PreparedIntentRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeV6PreparedIntentRetirement")
            .field("recovery", &self.recovery)
            .finish_non_exhaustive()
    }
}
impl NativeV6PreparedIntentRetirement {
    pub fn recovery(&self) -> &NativeV6IntentRetirementRecovery {
        &self.recovery
    }
    pub fn original_deadline(&self) -> std::time::Instant {
        self.selected.operation_deadline()
    }
}

/// A new actual quorum observation, not an old completion receipt. It remains
/// valid only under this same process, store generation and original deadline.
pub struct NativeV6IntentRetirementObservation {
    selected: NativeV6CommittedRootRead,
    capsule_digest: [u8; 32],
    resolution: NativeV6IntentRetirementResolution,
}
impl std::fmt::Debug for NativeV6IntentRetirementObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeV6IntentRetirementObservation")
            .field("resolution", &self.resolution)
            .finish_non_exhaustive()
    }
}
impl NativeV6IntentRetirementObservation {
    pub fn resolution(&self) -> NativeV6IntentRetirementResolution {
        self.resolution
    }
    pub fn capsule_digest(&self) -> [u8; 32] {
        self.capsule_digest
    }
    pub fn applied_log_index(&self) -> u64 {
        self.selected.applied_log_index()
    }
    pub fn current_root(&self) -> &crate::NativeV6PublishedRoot {
        self.selected.root()
    }
    pub fn current_enrollment(&self) -> &crate::NativeV6PeerEnrollment {
        self.selected.enrollment()
    }
    pub fn original_deadline(&self) -> std::time::Instant {
        self.selected.operation_deadline()
    }
}

impl ProcessRaftNode {
    /// A distinct actual preparation, sharing only the existing one-shot
    /// Pending/owner/reconciliation carrier. The wire command is never the
    /// old retirement command with silently changed Apply semantics.
    pub async fn prepare_native_v6_retained_root_activation(
        &self,
        selected: NativeV6CommittedRootRead,
    ) -> Result<NativeV6PreparedIntentRetirement, RemoteRaftError> {
        let deadline = selected
            .operation_deadline()
            .min(selected.read_index_deadline());
        super::super::with_read_index_deadline(selected.operation_deadline(), async {
            self.verify_native_v6_committed_root_read(&selected).await?;
            if selected.leader_id() != self.id {
                return Err(unavailable());
            }
            let activation = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.state_machine.native_v6_retained_root_activation(
                    selected.application_generation(),
                    &source(&selected),
                ),
            )
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
            let serial = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.next_production_client_serial(),
            )
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
            let recovery = NativeV6IntentRetirementRecovery::prepared_root_activation(
                selected.enrollment().cluster_digest(),
                serial,
                activation,
            )
            .map_err(|_| unavailable())?;
            self.verify_native_v6_committed_root_read(&selected).await?;
            Ok(NativeV6PreparedIntentRetirement { selected, recovery })
        })
        .await
    }

    pub async fn prepare_native_v6_intent_retirement(
        &self,
        selected: NativeV6CommittedRootRead,
        limit: usize,
    ) -> Result<NativeV6PreparedIntentRetirement, RemoteRaftError> {
        let deadline = selected
            .operation_deadline()
            .min(selected.read_index_deadline());
        super::super::with_read_index_deadline(selected.operation_deadline(), async {
            self.verify_native_v6_committed_root_read(&selected).await?;
            if selected.leader_id() != self.id {
                return Err(unavailable());
            }
            let command = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.state_machine.native_v6_retirement_command(
                    selected.application_generation(),
                    &source(&selected),
                    limit,
                ),
            )
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
            let serial = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.next_production_client_serial(),
            )
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
            let recovery = NativeV6IntentRetirementRecovery::prepared(
                selected.enrollment().cluster_digest(),
                serial,
                command,
            )
            .map_err(|_| unavailable())?;
            self.verify_native_v6_committed_root_read(&selected).await?;
            Ok(NativeV6PreparedIntentRetirement { selected, recovery })
        })
        .await
    }

    pub async fn verify_native_v6_prepared_intent_retirement(
        &self,
        prepared: &NativeV6PreparedIntentRetirement,
    ) -> Result<(), RemoteRaftError> {
        self.verify_native_v6_committed_root_read(&prepared.selected)
            .await?;
        if prepared.selected.leader_id() != self.id
            || source(&prepared.selected) != prepared.recovery.command.source
            || prepared.selected.enrollment().cluster_digest() != prepared.recovery.cluster_digest
        {
            return Err(unavailable());
        }
        Ok(())
    }

    /// Consume once, only after the caller's exact Pending Apply is known.
    /// There is no recovery-data-to-submission API and no internal retry.
    pub async fn submit_native_v6_prepared_intent_retirement(
        &self,
        prepared: NativeV6PreparedIntentRetirement,
    ) -> Result<CommitReceipt, RaftRuntimeError> {
        self.verify_native_v6_prepared_intent_retirement(&prepared)
            .await
            .map_err(|error| RaftRuntimeError::Consensus(error.to_string()))?;
        let deadline = prepared
            .selected
            .operation_deadline()
            .min(prepared.selected.read_index_deadline());
        let digest = prepared
            .recovery
            .command_digest()
            .map_err(RaftRuntimeError::RecordRejected)?;
        let serial = prepared.recovery.serial;
        let minimum_index = prepared.recovery.command.source.publication_log.index;
        super::super::with_read_index_deadline(deadline, async {
            let receipt = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.replicate_record_command(
                    serial,
                    prepared.recovery.into_record_command(),
                    digest,
                ),
            )
            .await
            .map_err(|_| {
                RaftRuntimeError::Consensus("native intent retirement outcome unknown".into())
            })??;
            if std::time::Instant::now() >= deadline
                || receipt.envelope_digest != digest
                || receipt.leader_id != self.id
                || receipt.log_index <= minimum_index
                || receipt.log_index < serial
            {
                return Err(RaftRuntimeError::Consensus(
                    "native intent retirement outcome unknown".into(),
                ));
            }
            Ok(receipt)
        })
        .await
    }

    /// Fresh quorum read only. The result never asserts the old request's
    /// acknowledgement, and it grants no new metadata or file mutation.
    pub async fn observe_native_v6_intent_retirement(
        &self,
        selected: NativeV6CommittedRootRead,
        previous: &NativeV6IntentRetirementRecovery,
    ) -> Result<NativeV6IntentRetirementObservation, RemoteRaftError> {
        let deadline = selected
            .operation_deadline()
            .min(selected.read_index_deadline());
        super::super::with_read_index_deadline(selected.operation_deadline(), async {
            self.verify_native_v6_committed_root_read(&selected).await?;
            let resolution = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.state_machine.native_v6_intent_retirement_observation(
                    selected.application_generation(),
                    &source(&selected),
                    previous,
                ),
            )
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
            self.verify_native_v6_committed_root_read(&selected).await?;
            Ok(NativeV6IntentRetirementObservation {
                selected,
                capsule_digest: previous.capsule_digest().map_err(|_| unavailable())?,
                resolution,
            })
        })
        .await
    }

    pub async fn verify_native_v6_intent_retirement_observation(
        &self,
        observation: &NativeV6IntentRetirementObservation,
    ) -> Result<(), RemoteRaftError> {
        self.verify_native_v6_committed_root_read(&observation.selected)
            .await
    }
}
