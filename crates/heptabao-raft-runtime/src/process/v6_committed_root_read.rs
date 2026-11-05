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
    continuation_read_bound: Option<std::time::Instant>,
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
    fn observe_selected(&self,stage:u8) {
        if let Some(observation)=self.witness.observation_id.as_ref() {
            observation.selected(self.witness.generation,self.witness.applied_log,
                Some((self.root.generation(),self.enrollment.epoch(),self.root.publication_log_id())),stage);
        }
    }
    /// Diagnostic side effect only; called after the server's original final
    /// closure/witness/deadline verification, never used as read authority.
    pub fn observe_service_read_verified(&self) { self.observe_selected(4); }
    /// Diagnostic side effect only; the original native local-root proof must
    /// have already passed its existing warm owner/cursor/consensus checks.
    pub fn observe_service_payload_proof_checked(&self) { self.observe_selected(8); }
    /// An opaque, nonpersistent correlation reference. It cannot be compared,
    /// serialized, or supplied to any application authority API.
    pub fn read_observation_identity(&self)->Option<crate::read_index_observation::ReadIdentity> {
        self.witness.observation_id.clone()
    }
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
    /// Read-only applied frontier of this actual quorum observation. It is
    /// not a reconstructed commit receipt or a new submission authority.
    pub fn applied_log_index(&self) -> u64 {
        self.witness.applied_log.index
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
    /// A later application observation can invalidate a read while leaving
    /// the complete published root unchanged (for example a staged intent or
    /// durable checkpoint). This relation grants no authority: the caller must
    /// obtain and verify the new real ReadIndex within the OLD read bound.
    fn same_root_after_application_progress(&self, previous: &Self) -> bool {
        self.witness.store.same_instance(&previous.witness.store)
            && self.witness.generation > previous.witness.generation
            && self.witness.applied_log.index >= previous.witness.applied_log.index
            && self.witness.leader == previous.witness.leader
            && self.witness.term == previous.witness.term
            && self.enrollment == previous.enrollment
            && self.root == previous.root
            && self.operation_deadline == previous.operation_deadline
            && self.witness.deadline <= previous.witness.deadline
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
            && self.continuation_read_bound == other.continuation_read_bound
    }
}

impl ProcessRaftNode {
    /// A NEW read-only observation for the dedicated pre-business ingress
    /// caller. This does not repair, publish, authenticate a caller, or revive
    /// the previous handle. Existing same-root/selection APIs stay strict.
    pub async fn native_v6_fresh_ingress_selection_read(
        &self,
        previous: &NativeV6CommittedRootRead,
    ) -> Result<NativeV6CommittedRootRead, RemoteRaftError> {
        let until = previous
            .read_index_deadline()
            .min(previous.operation_deadline);
        if std::time::Instant::now() >= until {
            return Err(RemoteRaftError::Consensus(
                "original native ingress bound expired".into(),
            ));
        }
        super::super::with_read_index_deadline(until, async {
            let mut fresh = self
                .native_v6_committed_root_read(until)
                .await?
                .ok_or_else(|| {
                    RemoteRaftError::Consensus("native ingress selection absent".into())
                })?;
            fresh.operation_deadline = previous.operation_deadline;
            fresh.continuation_read_bound = Some(until);
            let same_root = fresh.root == previous.root;
            // A different root must be a later actual publication in this same
            // epoch/retained origin. Neither a rewind nor online restore can be
            // selected as ordinary ingress application progress.
            let publication = same_root
                || (fresh.witness.generation > previous.witness.generation
                    && fresh.root.publication_log_id().index
                        > previous.root.publication_log_id().index
                    && fresh.root.generation() > previous.root.generation());
            if !fresh.witness.store.same_instance(&previous.witness.store)
                || fresh.witness.generation < previous.witness.generation
                || fresh.witness.applied_log.index < previous.witness.applied_log.index
                || fresh.witness.leader != previous.witness.leader
                || fresh.witness.term != previous.witness.term
                || fresh.enrollment != previous.enrollment
                || fresh.root.intent().epoch != previous.root.intent().epoch
                || fresh.root.migration_source() != previous.root.migration_source()
                || fresh.root.native_origin_epoch() != previous.root.native_origin_epoch()
                || fresh.operation_deadline != previous.operation_deadline
                || fresh.read_index_deadline() > previous.read_index_deadline()
                || !publication
            {
                return Err(RemoteRaftError::Consensus(
                    "native ingress successor changed original owner or bound".into(),
                ));
            }
            self.verify_native_v6_committed_root_read(&fresh).await?;
            Ok(fresh)
        })
        .await
    }

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
                continuation_read_bound: None,
            };
            self.verify_native_v6_committed_root_read(&selected).await?;
            Ok(Some(selected))
        })
        .await
    }

    /// Obtain a new actual read after application-only progress, keeping both
    /// original deadlines and the complete selected publication exact. This
    /// cannot adopt a new root, epoch, membership, leader, term or store owner.
    pub async fn native_v6_same_root_progress_read(
        &self,
        previous: &NativeV6CommittedRootRead,
    ) -> Result<NativeV6CommittedRootRead, RemoteRaftError> {
        let until = previous
            .read_index_deadline()
            .min(previous.operation_deadline);
        super::super::with_read_index_deadline(until, async {
            let mut fresh = self
                .native_v6_committed_root_read(until)
                .await?
                .ok_or_else(|| {
                    RemoteRaftError::Consensus("native progressed root absent".into())
                })?;
            // Only this genuine previous handle supplies the original operation
            // bound. The fresh witness remains capped by the old ReadIndex.
            fresh.operation_deadline = previous.operation_deadline;
            fresh.continuation_read_bound = Some(until);
            if !fresh.same_root_after_application_progress(previous) {
                return Err(RemoteRaftError::Consensus(
                    "native application progress changed the selected root or owner".into(),
                ));
            }
            self.verify_native_v6_committed_root_read(&fresh).await?;
            Ok(fresh)
        })
        .await
    }

    /// A terminal fresh read of an authenticated physical closure preserves
    /// any explicit continuation cap. Ordinary reads retain their existing
    /// operation-bound phase behavior; a capped continuation never gains time.
    pub async fn native_v6_fresh_same_selection_read(
        &self,
        previous: &NativeV6CommittedRootRead,
    ) -> Result<NativeV6CommittedRootRead, RemoteRaftError> {
        let mut fresh = if let Some(until) = previous.continuation_read_bound {
            super::super::with_read_index_deadline(until, self.native_v6_committed_root_read(until))
                .await?
        } else {
            self.native_v6_committed_root_read(previous.operation_deadline)
                .await?
        }
        .ok_or_else(|| RemoteRaftError::Consensus("native fresh same root absent".into()))?;
        if previous.continuation_read_bound.is_some() {
            fresh.operation_deadline = previous.operation_deadline;
        }
        fresh.continuation_read_bound = previous.continuation_read_bound;
        if !fresh.same_selection(previous)
            || previous
                .continuation_read_bound
                .is_some_and(|until| fresh.read_index_deadline() > until)
        {
            return Err(RemoteRaftError::Consensus(
                "native fresh read changed the selected root or bound".into(),
            ));
        }
        self.verify_native_v6_committed_root_read(&fresh).await?;
        Ok(fresh)
    }

    /// Recheck the same store, generation, leader, term and original capped
    /// ReadIndex deadline. No ciphertext fsync, write lease, Actor or HTTP
    /// delivery authority follows from this read-only verification.
    pub async fn verify_native_v6_committed_root_read(
        &self,
        selected: &NativeV6CommittedRootRead,
    ) -> Result<(), RemoteRaftError> {
        let result=super::super::with_read_index_deadline(selected.operation_deadline, async {
            self.verify_application_read_witness(&selected.witness)
                .await
        })
        .await;
        if result.is_ok() { selected.observe_selected(2); }
        result
    }

    /// Return the retained V5 predecessor selected by this exact native root.
    /// This does not turn historical V5 into a current application observation,
    /// create a second witness, or extend either original deadline.
    pub async fn native_v6_retained_migration_source(
        &self,
        selected: &NativeV6CommittedRootRead,
    ) -> Result<crate::PublishedRecordRoot, RemoteRaftError> {
        super::super::with_read_index_deadline(selected.operation_deadline, async {
            self.verify_native_v6_committed_root_read(selected).await?;
            let source = tokio::time::timeout_at(
                selected.witness.deadline,
                self.state_machine
                    .native_v6_retained_migration_source(&selected.root),
            )
            .await
            .map_err(|_| {
                RemoteRaftError::Consensus(
                    "native migration source observation deadline elapsed".into(),
                )
            })?
            .ok_or_else(|| {
                RemoteRaftError::Consensus(
                    "native migration source differs from selected native provenance".into(),
                )
            })?;
            self.verify_native_v6_committed_root_read(selected).await?;
            Ok(source)
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
            )
            .await
            .map_err(|_| {
                RemoteRaftError::Consensus(
                    "native pending restore observation deadline elapsed".into(),
                )
            })?;
            if let Some(pending) = &pending {
                pending
                    .matches_current(&selected.enrollment.0, &selected.root.0)
                    .map_err(|_| {
                        RemoteRaftError::Consensus(
                            "native pending restore differs from selected current root".into(),
                        )
                    })?;
            }
            self.verify_native_v6_committed_root_read(selected).await?;
            Ok(pending.map(|pending| pending.command.operation_digest))
        })
        .await
    }
}
