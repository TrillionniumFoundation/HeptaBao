//! A selected native root belongs to one actual quorum read and local store
//! generation. Ciphertext availability, an Actor, and installation/publication
//! authority must still be obtained from their separate owners.
use super::*;
use crate::{NativeV6PeerEnrollment, NativeV6PublishedRoot};

/// No public constructor, Clone or Serde can turn a root, applied number or
/// configured pin map into this process's committed-read evidence.
pub struct NativeV6CommittedRootRead {
    witness: ApplicationReadWitness,
    enrollment: NativeV6PeerEnrollment,
    root: NativeV6PublishedRoot,
    operation_deadline: std::time::Instant,
}

impl std::fmt::Debug for NativeV6CommittedRootRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeV6CommittedRootRead")
            .field("leader", &self.witness.leader)
            .field("term", &self.witness.term)
            .field("application_generation", &self.witness.generation)
            .field("publication_index", &self.root.publication_log_id().index)
            .finish_non_exhaustive()
    }
}

impl NativeV6CommittedRootRead {
    pub fn enrollment(&self) -> &NativeV6PeerEnrollment {
        &self.enrollment
    }
    pub fn root(&self) -> &NativeV6PublishedRoot {
        &self.root
    }
    pub fn leader_id(&self) -> u64 {
        self.witness.leader
    }
    pub fn term(&self) -> u64 {
        self.witness.term
    }
    /// This is the local Raft observation generation, NOT a Service/Durable
    /// journal generation and not a value with which to install a local root.
    pub fn application_generation(&self) -> u64 {
        self.witness.generation
    }
    /// The original operation bound can outlast this witness's capped
    /// ReadIndex bound. A later read is a NEW actual ReadIndex, not a renewal.
    pub fn operation_deadline(&self) -> std::time::Instant {
        self.operation_deadline
    }
    pub fn read_index_deadline(&self) -> std::time::Instant {
        self.witness.deadline.into_std()
    }
    /// Consume the selected native root and retain its SAME opaque applied
    /// witness for application prefix/delivery checks. This does not perform
    /// another ReadIndex, renew the deadline, or authenticate application data.
    /// The caller must authenticate the selected closure and finally verify
    /// this handle before discarding its root/enrollment binding here.
    pub fn into_application_witness(self) -> ApplicationReadWitness {
        self.witness
    }
    /// Equality of two actual selections grants no authority by itself. The
    /// caller must verify the new handle. In particular this deliberately does
    /// not revive the old witness after its original ReadIndex bound expires.
    /// Every apply/checkpoint, even an unrelated stage, changes the local
    /// generation and makes this strict repair relation false.
    pub fn same_selection(&self, other: &Self) -> bool {
        self.witness.store.same_instance(&other.witness.store)
            && self.witness.generation == other.witness.generation
            && self.witness.leader == other.witness.leader
            && self.witness.term == other.witness.term
            && self.enrollment == other.enrollment
            && self.root == other.root
            && self.operation_deadline == other.operation_deadline
    }
}

impl ProcessRaftNode {
    /// A cold process obtains the enrollment and root from the same actual
    /// applied snapshot as its fresh quorum read. Before first V6 activation,
    /// the successful native observation returns None; it never fabricates a
    /// native root from a retained V5 root or from configured enrollment pins.
    pub async fn native_v6_committed_root_read(
        &self,
        deadline: std::time::Instant,
    ) -> Result<Option<NativeV6CommittedRootRead>, RemoteRaftError> {
        super::super::with_read_index_deadline(deadline, async {
            let operation_deadline = super::super::read_deadline::current().unwrap_or(deadline);
            let (witness, enrollment, root) = self
                .native_v6_application_read_witness(operation_deadline)
                .await?;
            let Some(root) = root else {
                return Ok(None);
            };
            let enrollment = enrollment.ok_or_else(|| {
                RemoteRaftError::Io("committed native root enrollment absent".into())
            })?;
            if !enrollment.pins().contains_key(&self.id)
                || !enrollment.pins().contains_key(&witness.leader)
            {
                return Err(RemoteRaftError::Consensus(
                    "committed native root is outside this voter enrollment".into(),
                ));
            }
            let selected = NativeV6CommittedRootRead {
                witness,
                enrollment,
                root,
                operation_deadline,
            };
            self.verify_native_v6_committed_root_read(&selected).await?;
            Ok(Some(selected))
        })
        .await
    }

    /// Recheck the same store, generation, leader, term and original capped
    /// ReadIndex deadline. No ciphertext fsync, write lease, Actor or HTTP
    /// delivery authority follows from this read-only verification.
    pub async fn verify_native_v6_committed_root_read(
        &self,
        selected: &NativeV6CommittedRootRead,
    ) -> Result<(), RemoteRaftError> {
        super::super::with_read_index_deadline(selected.operation_deadline, async {
            self.verify_application_read_witness(&selected.witness)
                .await
        })
        .await
    }

    /// Observe only the pending operation selector under this SAME actual
    /// committed-root witness. None is a verified absence, not a timeout or a
    /// failed lookup. The selector grants no cancellation or publication: a
    /// caller must obtain the existing opaque pending read and its full Begin
    /// provenance before using the explicit cancellation primitive.
    pub async fn native_v6_pending_epoch_restore_operation(
        &self,
        selected: &NativeV6CommittedRootRead,
    ) -> Result<Option<[u8; 32]>, RemoteRaftError> {
        super::super::with_read_index_deadline(selected.operation_deadline, async {
            self.verify_native_v6_committed_root_read(selected).await?;
            let pending = tokio::time::timeout_at(
                selected.witness.deadline,
                self.state_machine.native_v6_pending_epoch_restore(),
            ).await.map_err(|_| RemoteRaftError::Consensus(
                "native pending restore observation deadline elapsed".into(),
            ))?;
            if let Some(pending) = &pending {
                pending.matches_current(&selected.enrollment.0, &selected.root.0)
                    .map_err(|_| RemoteRaftError::Consensus(
                        "native pending restore differs from selected current root".into(),
                    ))?;
            }
            self.verify_native_v6_committed_root_read(selected).await?;
            Ok(pending.map(|pending| pending.command.operation_digest))
        }).await
    }
}
