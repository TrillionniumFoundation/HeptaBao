//! Trusted native maintenance under an actual original ReadIndex selection.
//! Client Actor, typed graph and peer rollout admission stay with the server.
use super::*;
use crate::store::NativeV6RetentionGuard;
use crate::v6_retention::NativeV6RetentionSource;

/// A known Raft metadata completion. It does not assert that any ciphertext
/// was removed, that an earlier unknown request succeeded, or that a client
/// response was delivered.
#[derive(Debug)]
pub struct NativeV6IntentRetirementOutcome {
    receipt: CommitReceipt,
    retired_intents: usize,
}
impl NativeV6IntentRetirementOutcome {
    pub fn receipt(&self) -> &CommitReceipt {
        &self.receipt
    }
    pub fn retired_intents(&self) -> usize {
        self.retired_intents
    }
}

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
    RemoteRaftError::Consensus("native retention source unavailable or changed".into())
}

impl ProcessRaftNode {
    /// Exactly ONE bounded replicated metadata command, with no replay after
    /// timeout. Before first use the caller must have explicitly upgraded all
    /// admitted voters/readers to retention format 6. The new command and sticky
    /// snapshot version make an old reader reject it; there is no old protocol
    /// fallback. Server ownership/Actor and the complete external graph remain
    /// additional independent admission conditions.
    pub async fn retire_native_v6_obsolete_intents(
        &self,
        serial: u64,
        selected: &NativeV6CommittedRootRead,
        limit: usize,
    ) -> Result<NativeV6IntentRetirementOutcome, RaftRuntimeError> {
        let deadline = selected.operation_deadline();
        super::super::with_read_index_deadline(deadline, async {
            if selected.leader_id() != self.id {
                return Err(RaftRuntimeError::Consensus(
                    "native retention requires actual leader ownership".into(),
                ));
            }
            self.verify_native_v6_committed_root_read(selected)
                .await
                .map_err(|_| {
                    RaftRuntimeError::Consensus("native retention source changed".into())
                })?;
            let retirement = tokio::time::timeout_at(
                tokio::time::Instant::from_std(selected.read_index_deadline()),
                self.state_machine.native_v6_retirement_command(
                    selected.application_generation(),
                    &source(selected),
                    limit,
                ),
            )
            .await
            .map_err(|_| {
                RaftRuntimeError::Consensus("native retention preparation expired".into())
            })?
            .map_err(|_| {
                RaftRuntimeError::Consensus("native retention preparation rejected".into())
            })?;
            let retired_intents = retirement.intents.len();
            let digest = retirement
                .digest()
                .map_err(RaftRuntimeError::RecordRejected)?;
            self.verify_native_v6_committed_root_read(selected)
                .await
                .map_err(|_| {
                    RaftRuntimeError::Consensus("native retention source changed".into())
                })?;
            let receipt = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.replicate_record_command(
                    serial,
                    crate::records::RecordCommand::RetireNativeV6Intents { retirement },
                    digest,
                ),
            )
            .await
            .map_err(|_| {
                RaftRuntimeError::Consensus("native intent retirement outcome unknown".into())
            })??;
            if std::time::Instant::now() >= deadline {
                return Err(RaftRuntimeError::Consensus(
                    "native intent retirement outcome unknown".into(),
                ));
            }
            Ok(NativeV6IntentRetirementOutcome {
                receipt,
                retired_intents,
            })
        })
        .await
    }

    /// Retain the actual log/state writers while a local collector reads every
    /// durable retention source. This is independent of shared-blob operation
    /// quiescence, full typed graph validation, Actor/deadline and local barrier
    /// ownership. Holding this guard cannot manufacture any of those proofs.
    /// Dropping an async waiter cannot release owners held by its blocking I/O.
    pub async fn native_v6_retention_guard(
        &self,
        selected: &NativeV6CommittedRootRead,
    ) -> Result<NativeV6RetentionGuard, RemoteRaftError> {
        self.verify_native_v6_committed_root_read(selected).await?;
        if selected.leader_id() != self.id {
            return Err(unavailable());
        }
        let deadline = selected
            .read_index_deadline()
            .min(selected.operation_deadline());
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.state_machine.native_v6_retention_guard(
                &self.v6_intent_log_reader,
                selected.application_generation(),
                source(selected),
                deadline,
            ),
        )
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())
    }
}
