//! Pre-admission checks for a future Raft-ordered V6 root.
//! This module does NOT publish a V6 root or authorize V6 HA. The single-node
//! writer remains fenced until replicated objects and crash-safe apply exist.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct V6RootFence {
    pub cluster: [u8; 32],
    pub epoch: u64,
    pub generation: u64,
    pub root_digest: [u8; 32],
    pub committed_log_index: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct V6RootProposal {
    pub cluster: [u8; 32],
    pub epoch: u64,
    pub expected_generation: u64,
    pub expected_committed_log_index: u64,
    /// Exact log entry assigned to this proposal by the future Raft writer.
    /// An unrelated later commit cannot attest this root by advancing the index.
    pub target_committed_log_index: u64,
    pub expected_root_digest: [u8; 32],
    pub next_generation: u64,
    pub next_root_digest: [u8; 32],
    pub operation_digest: [u8; 32],
    pub object_closure_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum V6RootAdmissionError {
    WrongCluster,
    StaleEpoch,
    StaleBase,
    InvalidGeneration,
    EmptyCommitment,
    NonAdvancingCommitIndex,
    WrongCommittedLogIndex,
    CommittedOperationMismatch,
    UnappliedCommit,
    PublishedRootMismatch,
    InvalidClosure,
    RootMismatch,
}

/// A read-only reconciliation witness: never creates commit authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct V6CommittedRootWitness {
    pub committed_log_index: u64,
    /// Must originate from the exact committed log entry, not caller data.
    pub committed_operation_digest: [u8; 32],
    pub applied_log_index: u64,
    pub durable_log_index: u64,
    pub published_generation: u64,
    pub published_root_digest: [u8; 32],
}

impl V6CommittedRootWitness {
    /// Refuse to acknowledge unless the exact candidate root is known to be
    /// applied AND persisted after a newer committed Raft log index.
    /// This proof is purely structural; caller must separately authenticate
    /// quorum receipts, epoch, object closure and barrier ownership.
    pub(crate) fn validate_publication(
        self,
        previous: V6RootFence,
        candidate: V6RootProposal,
    ) -> Result<(), V6RootAdmissionError> {
        candidate.validate_against(previous)?;
        if self.committed_log_index <= previous.committed_log_index {
            return Err(V6RootAdmissionError::NonAdvancingCommitIndex);
        }
        if self.committed_log_index != candidate.target_committed_log_index {
            return Err(V6RootAdmissionError::WrongCommittedLogIndex);
        }
        if self.committed_operation_digest != candidate.operation_digest {
            return Err(V6RootAdmissionError::CommittedOperationMismatch);
        }
        if self.applied_log_index < self.committed_log_index
            || self.durable_log_index < self.committed_log_index
        {
            return Err(V6RootAdmissionError::UnappliedCommit);
        }
        if self.published_generation != candidate.next_generation
            || self.published_root_digest != candidate.next_root_digest
        {
            return Err(V6RootAdmissionError::PublishedRootMismatch);
        }
        Ok(())
    }
}

impl V6RootProposal {
    /// Pure structural preflight, not a Raft or authentication proof.
    /// It cannot be used as a success acknowledgment or local publication permit.
    pub(crate) fn validate_against(self, prior: V6RootFence) -> Result<(), V6RootAdmissionError> {
        if self.cluster != prior.cluster {
            return Err(V6RootAdmissionError::WrongCluster);
        }
        if self.epoch != prior.epoch {
            return Err(V6RootAdmissionError::StaleEpoch);
        }
        if self.expected_generation != prior.generation
            || self.expected_committed_log_index != prior.committed_log_index
            || self.expected_root_digest != prior.root_digest
        {
            return Err(V6RootAdmissionError::StaleBase);
        }
        if self.target_committed_log_index <= prior.committed_log_index {
            return Err(V6RootAdmissionError::NonAdvancingCommitIndex);
        }
        if self.next_generation
            != prior
                .generation
                .checked_add(1)
                .ok_or(V6RootAdmissionError::InvalidGeneration)?
        {
            return Err(V6RootAdmissionError::InvalidGeneration);
        }
        if self.next_root_digest == [0; 32]
            || self.operation_digest == [0; 32]
            || self.object_closure_digest == [0; 32]
            || self.next_root_digest == prior.root_digest
        {
            return Err(V6RootAdmissionError::EmptyCommitment);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn baseline() -> (V6RootFence, V6RootProposal) {
        let fence = V6RootFence {
            cluster: [1; 32],
            epoch: 7,
            generation: 50,
            root_digest: [2; 32],
            committed_log_index: 125,
        };
        let proposal = V6RootProposal {
            cluster: [1; 32],
            epoch: 7,
            expected_generation: 50,
            expected_committed_log_index: 125,
            target_committed_log_index: 126,
            expected_root_digest: [2; 32],
            next_generation: 51,
            next_root_digest: [3; 32],
            operation_digest: [4; 32],
            object_closure_digest: [5; 32],
        };
        (fence, proposal)
    }
    #[test]
    fn exact_committed_applied_durable_publication_structurally_matches() {
        let (prior, candidate) = baseline();
        let witness = V6CommittedRootWitness {
            committed_log_index: 126,
            committed_operation_digest: [4; 32],
            applied_log_index: 126,
            durable_log_index: 126,
            published_generation: 51,
            published_root_digest: [3; 32],
        };
        assert_eq!(witness.validate_publication(prior, candidate), Ok(()));
    }
    #[test]
    fn uncommitted_or_unapplied_or_undurable_root_is_denied() {
        let (prior, candidate) = baseline();
        let mut witness = V6CommittedRootWitness {
            committed_log_index: 125,
            committed_operation_digest: [4; 32],
            applied_log_index: 125,
            durable_log_index: 125,
            published_generation: 51,
            published_root_digest: [3; 32],
        };
        assert_eq!(
            witness.validate_publication(prior, candidate),
            Err(V6RootAdmissionError::NonAdvancingCommitIndex)
        );
        witness.committed_log_index = 126;
        assert_eq!(
            witness.validate_publication(prior, candidate),
            Err(V6RootAdmissionError::UnappliedCommit)
        );
        witness.applied_log_index = 126;
        assert_eq!(
            witness.validate_publication(prior, candidate),
            Err(V6RootAdmissionError::UnappliedCommit)
        );
        witness.durable_log_index = 126;
        witness.published_root_digest = [8; 32];
        assert_eq!(
            witness.validate_publication(prior, candidate),
            Err(V6RootAdmissionError::PublishedRootMismatch)
        );
        witness.published_root_digest = [3; 32];
        witness.published_generation = 52;
        assert_eq!(
            witness.validate_publication(prior, candidate),
            Err(V6RootAdmissionError::PublishedRootMismatch)
        );
    }
    #[test]
    fn unrelated_committed_index_or_operation_cannot_witness_this_root() {
        let (previous, proposal) = baseline();
        let exact = V6CommittedRootWitness {
            committed_log_index: proposal.target_committed_log_index,
            committed_operation_digest: proposal.operation_digest,
            applied_log_index: proposal.target_committed_log_index,
            durable_log_index: proposal.target_committed_log_index,
            published_generation: proposal.next_generation,
            published_root_digest: proposal.next_root_digest,
        };
        assert_eq!(exact.validate_publication(previous, proposal), Ok(()));
        let unrelated_later_commit = V6CommittedRootWitness {
            committed_log_index: proposal.target_committed_log_index + 1,
            applied_log_index: proposal.target_committed_log_index + 1,
            durable_log_index: proposal.target_committed_log_index + 1,
            ..exact
        };
        assert_eq!(
            unrelated_later_commit.validate_publication(previous, proposal),
            Err(V6RootAdmissionError::WrongCommittedLogIndex)
        );
        let wrong_operation = V6CommittedRootWitness {
            committed_operation_digest: [9; 32],
            ..exact
        };
        assert_eq!(
            wrong_operation.validate_publication(previous, proposal),
            Err(V6RootAdmissionError::CommittedOperationMismatch)
        );
        let stale_proposal = V6RootProposal {
            target_committed_log_index: previous.committed_log_index,
            ..proposal
        };
        assert_eq!(
            stale_proposal.validate_against(previous),
            Err(V6RootAdmissionError::NonAdvancingCommitIndex)
        );
        // A legitimate intervening Raft no-op is allowed only when the exact
        // proposed index and operation digest are observed at the later entry.
        let later_proposal = V6RootProposal {
            target_committed_log_index: previous.committed_log_index + 3,
            ..proposal
        };
        let later_exact = V6CommittedRootWitness {
            committed_log_index: later_proposal.target_committed_log_index,
            applied_log_index: later_proposal.target_committed_log_index,
            durable_log_index: later_proposal.target_committed_log_index,
            ..exact
        };
        assert_eq!(
            later_exact.validate_publication(previous, later_proposal),
            Ok(())
        );
    }
    #[test]
    fn exact_root_transition_admits_only_structural_candidate() {
        let (f, p) = baseline();
        assert_eq!(p.validate_against(f), Ok(()));
    }
    #[test]
    fn foreign_cluster_and_epoch_fail_closed() {
        let (f, mut p) = baseline();
        p.cluster = [9; 32];
        assert_eq!(
            p.validate_against(f),
            Err(V6RootAdmissionError::WrongCluster)
        );
        let (_, mut p) = baseline();
        p.epoch += 1;
        assert_eq!(p.validate_against(f), Err(V6RootAdmissionError::StaleEpoch));
    }
    #[test]
    fn stale_base_and_generation_gap_fail_closed() {
        let (f, mut p) = baseline();
        p.expected_root_digest = [8; 32];
        assert_eq!(p.validate_against(f), Err(V6RootAdmissionError::StaleBase));
        let (_, mut p) = baseline();
        p.next_generation += 1;
        assert_eq!(
            p.validate_against(f),
            Err(V6RootAdmissionError::InvalidGeneration)
        );
        let (_, p) = baseline();
        let mut max = f;
        max.generation = u64::MAX;
        assert_eq!(
            p.validate_against(max),
            Err(V6RootAdmissionError::StaleBase)
        );
        let mut p = p;
        p.expected_generation = u64::MAX;
        assert_eq!(
            p.validate_against(max),
            Err(V6RootAdmissionError::InvalidGeneration)
        );
    }
    #[test]
    fn absent_replayed_or_unbound_payload_fails_closed() {
        let (f, mut p) = baseline();
        p.next_root_digest = f.root_digest;
        assert_eq!(
            p.validate_against(f),
            Err(V6RootAdmissionError::EmptyCommitment)
        );
        let (_, mut p) = baseline();
        p.operation_digest = [0; 32];
        assert_eq!(
            p.validate_against(f),
            Err(V6RootAdmissionError::EmptyCommitment)
        );
        let (_, mut p) = baseline();
        p.object_closure_digest = [0; 32];
        assert_eq!(
            p.validate_against(f),
            Err(V6RootAdmissionError::EmptyCommitment)
        );
    }
}
