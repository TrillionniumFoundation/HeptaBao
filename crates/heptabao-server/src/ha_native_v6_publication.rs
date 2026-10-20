//! One actual native HA publication under the Service writer's original gate.
//! Fresh consensus observations do not renew that Actor, local source or clock.
//! An attempted root command is never reported as definitely uncommitted.
use super::*;
use crate::ha_state::native_v6::{CodecResult, NativeV6CipherClosure, NativeV6CodecError};
use crate::service::native_v6_ha_objects::PreparedNativeV6HaObjects;
use crate::state_record_root::StateIdentity;
use heptabao_ha_service::replicate_native_v6_closure_to_quorum;
use heptabao_raft_runtime::{NativeV6CommitIntent, SealedRecordObject, with_read_index_deadline};
use ring::rand::{SecureRandom, SystemRandom};

// Opt-in phase observations only: no payload, credential, source admission or
// new deadline is created. Drop also records the phase that returned an error.
// Diagnostic I/O failure never changes the original result or its custody.
#[cfg(feature = "private-ha-forward-diagnostic")]
struct NativeHaPhaseTimer {
    phase: &'static str,
    started: std::time::Instant,
    original_until: std::time::Instant,
    generation: u64,
    objects: u64,
    bytes: u64,
    completed: bool,
}
#[cfg(feature = "private-ha-forward-diagnostic")]
impl NativeHaPhaseTimer {
    fn start(
        phase: &'static str,
        original_until: std::time::Instant,
        generation: u64,
        objects: u64,
        bytes: u64,
    ) -> Self {
        Self {
            phase,
            started: std::time::Instant::now(),
            original_until,
            generation,
            objects,
            bytes,
            completed: false,
        }
    }
    fn finish(mut self, completed: bool) {
        self.completed = completed;
    }
}
#[cfg(feature = "private-ha-forward-diagnostic")]
impl Drop for NativeHaPhaseTimer {
    fn drop(&mut self) {
        use std::io::Write as _;
        let observed = std::time::Instant::now();
        let _ = writeln!(
            std::io::stderr().lock(),
            "HBHA-PRIVATE-PERF phase={} elapsed_us={} completed={} original_deadline_expired={} generation={} objects={} bytes={}",
            self.phase,
            observed.duration_since(self.started).as_micros(),
            self.completed,
            observed >= self.original_until,
            self.generation,
            self.objects,
            self.bytes,
        );
    }
}

/// Data for reconciling this exact operation, not a publication or reply grant.
/// The constructor is private and no decoder can manufacture its provenance.
pub(crate) struct NativeHaRecoveryReference {
    intent: NativeV6CommitIntent,
    enrollment: NativeV6PeerEnrollment,
    intent_receipt: CommitReceipt,
    intent_log: [u64; 3],
    root_serial: u64,
    deadline: OriginalDeadline,
    published: Option<NativeV6PublishedRoot>,
}

impl NativeHaRecoveryReference {
    /// Random operation identity only; it discloses no credential or payload.
    pub(crate) fn reference_id(&self) -> String {
        let mut id = String::with_capacity(10 + 64);
        id.push_str("native-v6-");
        for byte in self.intent().operation_digest {
            use std::fmt::Write as _;
            let _ = write!(id, "{byte:02x}");
        }
        id
    }
    pub(crate) fn intent(&self) -> &NativeV6CommitIntent {
        &self.intent
    }
    pub(crate) fn enrollment(&self) -> &NativeV6PeerEnrollment {
        &self.enrollment
    }
    pub(crate) fn published(&self) -> Option<&NativeV6PublishedRoot> {
        self.published.as_ref()
    }
}

impl fmt::Debug for NativeHaRecoveryReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeHaRecoveryReference")
            .field("reference_id", &self.reference_id())
            .field("intent_index", &self.intent_receipt.log_index)
            .field("intent_log", &self.intent_log)
            .field("root_serial", &self.root_serial)
            .field("original_deadline", &self.deadline.instant())
            .field("published", &self.published().is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) enum NativeHaPublicationError {
    /// This operation never invoked root publication. A committed enrollment,
    /// staged intent and unreferenced fsynced ciphertext may still remain.
    BeforeRoot { reason: String },
    /// Includes success followed by lost source/Actor/read/install authority.
    /// The caller must fence/reconcile and must not mint another operation.
    RootOutcomeUnknown {
        recovery: NativeHaRecoveryReference,
        reason: String,
    },
}

impl NativeHaPublicationError {
    pub(crate) fn root_attempted(&self) -> bool {
        matches!(self, Self::RootOutcomeUnknown { .. })
    }
}

impl fmt::Display for NativeHaPublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforeRoot { reason } => {
                write!(f, "native HA stopped before root publication: {reason}")
            }
            Self::RootOutcomeUnknown { recovery, reason } => write!(
                f,
                "native HA root outcome requires reconciliation ({}): {reason}",
                recovery.reference_id()
            ),
        }
    }
}
impl std::error::Error for NativeHaPublicationError {}

fn before(reason: impl ToString) -> NativeHaPublicationError {
    NativeHaPublicationError::BeforeRoot {
        reason: reason.to_string(),
    }
}

fn original(
    deadline: OriginalDeadline,
    gate: &mut dyn FnMut() -> CodecResult<()>,
) -> CodecResult<()> {
    deadline.check().map_err(|_| NativeV6CodecError::Gate)?;
    gate()?;
    deadline.check().map_err(|_| NativeV6CodecError::Gate)
}

/// Root identity and ORIGINAL full publication LogId, observed from actual
/// state. Equality after a fresh read tolerates this operation's intent stage,
/// but never treats a stale generation-bound witness as current authority.
#[derive(Clone, Eq, PartialEq)]
enum PublicationSource {
    V5 {
        digest: [u8; 32],
        publication: [u64; 3],
    },
    V6(NativeV6PublishedRoot),
}
impl PublicationSource {
    fn prior_generation(&self) -> u64 {
        match self {
            Self::V5 { .. } => 0,
            Self::V6(root) => root.generation(),
        }
    }
    fn previous_commit_index(&self) -> u64 {
        match self {
            Self::V5 { publication, .. } => publication[2],
            Self::V6(root) => root.publication_log_id().index,
        }
    }
}

struct SourceObservation {
    source: PublicationSource,
    enrollment: Option<NativeV6PeerEnrollment>,
    term: u64,
}

impl HaProcess {
    /// Select source/enrollment under one actual native application witness.
    /// The V5 provenance and sealed descriptor are read while that witness's
    /// generation is held, then verified again. A racing apply fails closed.
    fn observe_native_publication_source(
        &self,
        expected: StateIdentity,
        epoch: u64,
        deadline: OriginalDeadline,
    ) -> Result<SourceObservation, String> {
        deadline.check().map_err(|error| error.to_string())?;
        let node = self.node.as_ref().ok_or("HA process is shut down")?;
        let native = self
            .native_v6
            .as_ref()
            .filter(|native| native.enabled())
            .ok_or("native HA was not explicitly enabled")?;
        self.runtime
            .block_on(with_read_index_deadline(deadline.instant(), async {
                let (witness, enrollment, root) = node
                    .native_v6_application_read_witness(deadline.instant())
                    .await
                    .map_err(|error| error.to_string())?;
                if let Some(enrollment) = enrollment.as_ref() {
                    native.validate_enrollment(&self.codec, enrollment)?;
                    if enrollment.epoch() != epoch {
                        return Err("native HA source replay epoch changed".into());
                    }
                }
                let source = match (expected, root) {
                    (StateIdentity::RecordsV6(digest), Some(root))
                        if root.root_digest() == digest && root.intent().epoch == epoch =>
                    {
                        if enrollment.is_none() {
                            return Err("native HA source enrollment absent".into());
                        }
                        PublicationSource::V6(root)
                    }
                    (StateIdentity::RecordsV5(digest), None) => {
                        let (source_digest, log) = node.native_v6_migration_source().await.ok_or(
                            "native migration requires original V5 publication provenance",
                        )?;
                        let (_, published) = node
                            .record_root_at_generation()
                            .await
                            .map_err(|error| error.to_string())?;
                        let published = published.ok_or("native migration V5 source absent")?;
                        let envelope = published.envelope();
                        let CommittedStateDescriptor::RecordsV5(decoded) = self
                            .codec
                            .open_committed_descriptor(
                                envelope.operation_id(),
                                envelope.digest(),
                                envelope.sealed(),
                            )
                            .map_err(|error| error.to_string())?
                        else {
                            return Err("native migration source is not authenticated V5".into());
                        };
                        if source_digest != digest
                            || envelope.digest() != digest
                            || decoded.root.cluster_id != self.cluster_id
                            || decoded.root.replay_epoch != epoch
                            || decoded.base != published.base()
                            || decoded
                                .root
                                .references()
                                .map(crate::ha_state::runtime_reference)
                                .collect::<Vec<_>>()
                                != published.direct_refs()
                        {
                            return Err(
                                "native migration source differs from current V5 publication"
                                    .into(),
                            );
                        }
                        let leader = log.committed_leader_id();
                        if leader.term == 0 || leader.node_id == 0 || log.index == 0 {
                            return Err("native migration original full LogId unavailable".into());
                        }
                        PublicationSource::V5 {
                            digest,
                            publication: [leader.term, leader.node_id, log.index],
                        }
                    }
                    _ => return Err("native HA source identity changed".into()),
                };
                // This observation only rejects obvious non-leaders. The actual
                // OpenRaft engine must still enforce its independent write lease.
                // A ReadIndex is never promoted into writable-leader authority.
                let role = node
                    .local_leader_observation()
                    .map_err(|error| error.to_string())?;
                if !role.local_is_leader || role.leader != Some(node.id()) || role.term == 0 {
                    return Err("native HA publication requires the actual current leader".into());
                }
                node.verify_application_read_witness(&witness)
                    .await
                    .map_err(|error| error.to_string())?;
                deadline.check().map_err(|error| error.to_string())?;
                Ok(SourceObservation {
                    source,
                    enrollment,
                    term: role.term,
                })
            }))
    }

    fn check_native_publication_source(
        &self,
        expected: StateIdentity,
        epoch: u64,
        deadline: OriginalDeadline,
        source: &PublicationSource,
        enrollment: &NativeV6PeerEnrollment,
        term: u64,
    ) -> Result<(), String> {
        let current = self.observe_native_publication_source(expected, epoch, deadline)?;
        if current.source != *source
            || current.enrollment.as_ref() != Some(enrollment)
            || current.term != term
        {
            return Err("native HA source, full provenance, enrollment or term changed".into());
        }
        Ok(())
    }

    /// Only the explicit native candidate Service writer can call this path.
    /// It creates exactly one operation, one staged intent and one root CAS.
    /// The supplied gate owns original Actor, local journal/source and seal
    /// custody; this coordinator cannot replace those with a consensus read.
    pub(crate) fn publish_native_v6_candidate(
        &self,
        expected: StateIdentity,
        epoch: u64,
        deadline: OriginalDeadline,
        prepare: impl FnOnce(
            &ClusterStateCodec,
            &NativeV6PeerEnrollment,
            &LocalV6BlobStage,
            Option<&NativeV6CipherClosure>,
            &mut dyn FnMut() -> CodecResult<()>,
        ) -> CodecResult<PreparedNativeV6HaObjects>,
        original_gate: &mut dyn FnMut() -> CodecResult<()>,
    ) -> Result<CommittedNativeV6Read, NativeHaPublicationError> {
        original(deadline, original_gate).map_err(before)?;
        let node = self
            .node
            .as_ref()
            .ok_or_else(|| before("HA process is shut down"))?;
        let native = self
            .native_v6
            .as_ref()
            .filter(|native| native.enabled())
            .ok_or_else(|| before("native HA was not explicitly enabled"))?;
        let storage = native
            .storage
            .get()
            .ok_or_else(|| before("native ciphertext store absent"))?;
        #[cfg(feature = "private-ha-forward-diagnostic")]
        let phase =
            NativeHaPhaseTimer::start("publication_source_enrollment", deadline.instant(), 0, 0, 0);
        let initial = self
            .observe_native_publication_source(expected, epoch, deadline)
            .map_err(before)?;
        let source = initial.source;
        let term = initial.term;
        let enrollment = match initial.enrollment {
            Some(enrollment) => enrollment,
            None if matches!(source, PublicationSource::V5 { .. }) => {
                original(deadline, original_gate).map_err(before)?;
                let serial = self
                    .runtime
                    .block_on(node.next_production_client_serial())
                    .map_err(before)?;
                // A partial first enrollment is an explicit pre-root failure.
                // It is never replayed internally under a fresh serial.
                let enrollment = self
                    .runtime
                    .block_on(with_read_index_deadline(
                        deadline.instant(),
                        node.enroll_native_v6_peers(
                            serial,
                            self.codec.native_v6_cluster_digest(),
                            epoch,
                            native.configured_pins.clone(),
                            deadline.instant(),
                        ),
                    ))
                    .map_err(before)?;
                original(deadline, original_gate).map_err(before)?;
                enrollment
            }
            None => return Err(before("native HA committed enrollment absent")),
        };
        native
            .validate_enrollment(&self.codec, &enrollment)
            .map_err(before)?;
        self.check_native_publication_source(expected, epoch, deadline, &source, &enrollment, term)
            .map_err(before)?;
        original(deadline, original_gate).map_err(before)?;

        #[cfg(feature = "private-ha-forward-diagnostic")]
        phase.finish(true);
        // A previous native root is reopened through its actual opaque read;
        // missing ciphertext is repaired from pinned committed voters first.
        #[cfg(feature = "private-ha-forward-diagnostic")]
        let phase = NativeHaPhaseTimer::start(
            "publication_previous_closure",
            deadline.instant(),
            source.prior_generation(),
            0,
            0,
        );
        let previous = if let PublicationSource::V6(previous) = &source {
            let selected = self
                .native_v6_committed_read_for_local_root(deadline, previous.root_digest())
                .map_err(before)?
                .ok_or_else(|| before("native HA previous committed root absent"))?;
            if selected.published() != previous || selected.enrollment() != &enrollment {
                return Err(before("native HA previous closure selection changed"));
            }
            let closure = self
                .codec
                .open_native_v6_committed_closure(&enrollment, previous, storage, &mut || {
                    original(deadline, original_gate)?;
                    self.verify_native_v6_committed_read(&selected)
                        .map_err(|_| NativeV6CodecError::Gate)
                })
                .map_err(before)?;
            Some(closure)
        } else {
            None
        };
        #[cfg(feature = "private-ha-forward-diagnostic")]
        phase.finish(true);
        original(deadline, original_gate).map_err(before)?;
        #[cfg(feature = "private-ha-forward-diagnostic")]
        let phase = NativeHaPhaseTimer::start(
            "publication_typed_prepare",
            deadline.instant(),
            source.prior_generation(),
            0,
            0,
        );
        let prepared = prepare(
            &self.codec,
            &enrollment,
            storage,
            previous.as_ref(),
            &mut || original(deadline, original_gate),
        )
        .map_err(before)?;
        original(deadline, original_gate).map_err(before)?;
        #[cfg(feature = "private-ha-forward-diagnostic")]
        phase.finish(true);
        if prepared.original_deadline().instant() != deadline.instant() {
            return Err(before(
                "native HA preparation changed the original operation deadline",
            ));
        }
        self.check_native_publication_source(expected, epoch, deadline, &source, &enrollment, term)
            .map_err(before)?;
        #[cfg(feature = "private-ha-forward-diagnostic")]
        let phase = NativeHaPhaseTimer::start(
            "publication_intent_admission",
            deadline.instant(),
            source.prior_generation(),
            0,
            0,
        );
        let local = prepared.local_closure();
        let mut operation_digest = [0u8; 32];
        SystemRandom::new()
            .fill(&mut operation_digest)
            .map_err(|_| before("native HA operation randomness unavailable"))?;
        let intent = NativeV6CommitIntent {
            cluster_digest: enrollment.cluster_digest(),
            epoch,
            operation_digest,
            closure_manifest_sha256: local.manifest_sha256(),
            object_count: local.object_count() as u64,
            ciphertext_bytes: local.ciphertext_bytes(),
            prior_root_digest: expected.digest(),
            proposed_root_digest: prepared.root_digest(),
            prior_generation: source.prior_generation(),
            proposed_generation: source
                .prior_generation()
                .checked_add(1)
                .ok_or_else(|| before("native HA root generation exhausted"))?,
            expected_previous_commit_index: source.previous_commit_index(),
        };
        let object = SealedRecordObject::new_native_v6_commit_intent(intent).map_err(before)?;
        let proposal = prepared
            .into_proposal(&self.codec, &enrollment, intent, &mut || {
                original(deadline, original_gate)
            })
            .map_err(before)?;
        if proposal.intent() != intent
            || proposal.original_deadline().instant() != deadline.instant()
        {
            return Err(before(
                "native HA proposal changed the original intent or deadline",
            ));
        }
        original(deadline, original_gate).map_err(before)?;
        self.check_native_publication_source(expected, epoch, deadline, &source, &enrollment, term)
            .map_err(before)?;
        let serial = self
            .runtime
            .block_on(node.next_production_client_serial())
            .map_err(before)?;
        original(deadline, original_gate).map_err(before)?;
        let intent_receipt = self
            .runtime
            .block_on(with_read_index_deadline(deadline.instant(), async {
                tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline.instant()),
                    node.stage_application_object(serial, &object),
                )
                .await
            }))
            .map_err(|_| before("native HA staged intent outcome unknown; root was not invoked"))?
            .map_err(before)?;
        original(deadline, original_gate).map_err(before)?;
        // Intent staging legitimately invalidated the prior generation witness.
        // Obtain a NEW actual read and compare the original root/provenance.
        self.check_native_publication_source(expected, epoch, deadline, &source, &enrollment, term)
            .map_err(before)?;
        self.runtime
            .block_on(with_read_index_deadline(
                deadline.instant(),
                node.reconcile_exact_staged_v6_intent(&intent, &intent_receipt),
            ))
            .map_err(before)?;
        let admission = self
            .runtime
            .block_on(node.admit_native_v6_closure(&intent, deadline.instant()))
            .map_err(before)?;
        if admission.enrollment() != &enrollment
            || admission.leader_id() != node.id()
            || admission.term() != term
            || admission.intent_log_id().index != intent_receipt.log_index
        {
            return Err(before("native HA actual intent provenance differs"));
        }
        let original_log = admission.intent_log_id();
        let original_leader = original_log.committed_leader_id();
        let intent_log = [
            original_leader.term,
            original_leader.node_id,
            original_log.index,
        ];
        original(deadline, original_gate).map_err(before)?;
        #[cfg(feature = "private-ha-forward-diagnostic")]
        phase.finish(true);
        #[cfg(feature = "private-ha-forward-diagnostic")]
        let phase = NativeHaPhaseTimer::start(
            "publication_fsync_quorum",
            deadline.instant(),
            source.prior_generation(),
            intent.object_count,
            intent.ciphertext_bytes,
        );
        let quorum = replicate_native_v6_closure_to_quorum(
            node,
            self.runtime.handle(),
            &native.transport,
            &self.peers,
            storage,
            proposal.references(),
            &intent,
            deadline.instant(),
        )
        .map_err(before)?;
        original(deadline, original_gate).map_err(before)?;
        #[cfg(feature = "private-ha-forward-diagnostic")]
        phase.finish(true);
        if quorum.intent() != &intent || quorum.enrollment() != &enrollment {
            return Err(before("native HA fsync quorum selected a different intent"));
        }
        self.check_native_publication_source(expected, epoch, deadline, &source, &enrollment, term)
            .map_err(before)?;
        let root_serial = self
            .runtime
            .block_on(node.next_production_client_serial())
            .map_err(before)?;
        self.runtime
            .block_on(with_read_index_deadline(
                deadline.instant(),
                quorum.verify_for_publication(node),
            ))
            .map_err(before)?;
        original(deadline, original_gate).map_err(before)?;

        let mut recovery = NativeHaRecoveryReference {
            intent,
            enrollment: enrollment.clone(),
            intent_receipt,
            intent_log,
            root_serial,
            deadline,
            published: None,
        };
        // From this call onward, every error preserves the exact recovery
        // reference. Engine rejection, timeout and lost reconciliation do not
        // authorize another root invocation or a changed operation identity.
        #[cfg(feature = "private-ha-forward-diagnostic")]
        let phase = NativeHaPhaseTimer::start(
            "publication_root_cas",
            deadline.instant(),
            source.prior_generation(),
            intent.object_count,
            intent.ciphertext_bytes,
        );
        let published = match self.runtime.block_on(node.publish_native_v6_root(
            root_serial,
            recovery.intent(),
            &recovery.intent_receipt,
            recovery.enrollment(),
            proposal.sealed_root().to_vec(),
            deadline.instant(),
        )) {
            Ok(published) => published,
            Err(error) => {
                return Err(NativeHaPublicationError::RootOutcomeUnknown {
                    recovery,
                    reason: error.to_string(),
                });
            }
        };
        #[cfg(feature = "private-ha-forward-diagnostic")]
        phase.finish(true);
        recovery.published = Some(published.clone());
        let mut after_commit = || -> Result<CommittedNativeV6Read, String> {
            #[cfg(feature = "private-ha-forward-diagnostic")]
            let phase = NativeHaPhaseTimer::start(
                "publication_committed_readback",
                deadline.instant(),
                source.prior_generation(),
                intent.object_count,
                intent.ciphertext_bytes,
            );
            original(deadline, original_gate).map_err(|error| error.to_string())?;
            let read = self.native_v6_committed_read_for_published_proposal(
                deadline,
                &proposal,
                &published,
            )?;
            if read.published() != &published
                || read.enrollment() != &enrollment
                || read.published().intent() != intent
            {
                return Err("native HA root publication was superseded or differs".into());
            }
            self.verify_native_v6_committed_read(&read)?;
            original(deadline, original_gate).map_err(|error| error.to_string())?;
            #[cfg(feature = "private-ha-forward-diagnostic")]
            phase.finish(true);
            Ok(read)
        };
        after_commit()
            .map_err(|reason| NativeHaPublicationError::RootOutcomeUnknown { recovery, reason })
    }
}
