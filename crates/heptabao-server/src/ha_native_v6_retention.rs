//! One bounded retention request under the actual configured HA process.
//! Member admission is a fresh pinned-mTLS exchange with EVERY enrolled member.
//! It has no caller Boolean, cached receipt, quorum shortcut or retry.
use super::*;
use crate::state_record_root::StateIdentity;
use heptabao_raft_runtime::{
    LocalV6BlobError, NativeV6SharedRetirementPlan, NativeV6SharedRetirementSelection,
};

const REQUEST: &[u8; 8] = b"HBN6R7Q3";
const RESPONSE: &[u8; 8] = b"HBN6R7A3";
const FRAME_BYTES: usize = 8 + 32 + 8 + 8 + 32 + 32 + 32 + 8 + 8 + 24 + 24 + 2;
// This handler is compiled with the actual RetireNativeV6Intents command and
// sticky format-7 snapshot decoder. Older binaries have no matching handler.
// The external release gate independently pins all deployed source/binaries.
const RETENTION_READER_FORMAT: u8 = 7;
const INTENT_DURABLE_READER_FORMAT: u8 = 3;

/// This concrete production custody has no public constructor, Clone or wire
/// form. Only with_native_v6_local_retirement constructs it, borrowing the
/// original Actor and real held Raft/shared-store authorities for the callback.
pub(crate) struct NativeHaLocalRetirementCustody<'a> {
    marked: &'a crate::service::native_v6_ha_objects::NativeV6TypedRetainedResources,
    check: &'a dyn Fn() -> Result<(), heptabao_durable_service::ServiceError>,
}

impl NativeHaLocalRetirementCustody<'_> {
    pub(crate) fn root_count(&self) -> usize {
        self.marked.root_count()
    }
}

impl heptabao_durable_service::NativeHaLocalRetentionOwner for NativeHaLocalRetirementCustody<'_> {
    fn catalog_sha256(&self) -> [u8; 32] {
        self.marked.catalog_sha256()
    }

    fn typed_retained_resources(&self) -> &std::collections::BTreeSet<String> {
        self.marked.resources()
    }

    fn verify(&self) -> Result<(), heptabao_durable_service::ServiceError> {
        (self.check)()
    }

    fn verify_boundary(
        &self,
        boundary: heptabao_durable_service::NativeHaLocalRetirementBoundary,
    ) -> Result<(), heptabao_durable_service::ServiceError> {
        self.verify()?;
        #[cfg(test)]
        if FAIL_LOCAL_RETIREMENT.with(|slot| {
            if slot.get() == Some(boundary) {
                slot.set(None);
                true
            } else {
                false
            }
        }) {
            // The original lower transaction, not the test, reached the real
            // known Pending or completed unlink/fsync boundary. Preserve its
            // durable pending record exactly and require a fresh cold owner.
            return Err(heptabao_durable_service::ServiceError::RecoveryRequired);
        }
        #[cfg(not(test))]
        let _ = boundary;
        self.verify()
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_LOCAL_RETIREMENT: std::cell::Cell<Option<heptabao_durable_service::NativeHaLocalRetirementBoundary>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
impl HaProcess {
    pub(crate) fn fail_native_v6_local_retirement_once(
        &self,
        boundary: heptabao_durable_service::NativeHaLocalRetirementBoundary,
    ) {
        FAIL_LOCAL_RETIREMENT.with(|slot| {
            assert_eq!(slot.get(), None);
            slot.set(Some(boundary));
        });
    }
}

pub(crate) struct NativeHaPreparedIntentRetirement<'a> {
    process: &'a HaProcess,
    instance: Arc<()>,
    _operation: heptabao_raft_runtime::NativeV6BlobOperation,
    prepared: heptabao_raft_runtime::NativeV6PreparedIntentRetirement,
    expected: StateIdentity,
    deadline: OriginalDeadline,
}
pub(crate) struct NativeHaIntentReadObservation<'a> {
    process: &'a HaProcess,
    instance: Arc<()>,
    _operation: heptabao_raft_runtime::NativeV6BlobOperation,
    observed: heptabao_raft_runtime::NativeV6IntentRetirementObservation,
    expected: StateIdentity,
    deadline: OriginalDeadline,
}
pub(crate) struct NativeHaCommittedIntentRetirement<'a> {
    observed: NativeHaIntentReadObservation<'a>,
    receipt: heptabao_raft_runtime::CommitReceipt,
}

impl NativeHaPreparedIntentRetirement<'_> {
    pub(crate) fn recovery(&self) -> &heptabao_raft_runtime::NativeV6IntentRetirementRecovery {
        self.prepared.recovery()
    }
    pub(crate) fn verify(&self) -> Result<(), String> {
        self.deadline.check().map_err(|_| denied())?;
        let native = self
            .process
            .native_v6
            .as_ref()
            .filter(|native| native.enabled())
            .ok_or_else(denied)?;
        let node = self.process.node.as_ref().ok_or_else(denied)?;
        if !Arc::ptr_eq(&self.instance, &native.identity)
            || self.prepared.original_deadline() != self.deadline.instant()
        {
            return Err(denied());
        }
        self.process
            .runtime
            .block_on(node.verify_native_v6_prepared_intent_retirement(&self.prepared))
            .map_err(|_| denied())?;
        self.deadline.check().map_err(|_| denied())
    }
}

impl<'a> NativeHaPreparedIntentRetirement<'a> {
    pub(crate) fn submit(
        self,
        original: &mut dyn FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<NativeHaCommittedIntentRetirement<'a>, String> {
        original().map_err(|_| denied())?;
        self.verify()?;
        let data = self.prepared.recovery().clone(); // DATA, never a reconstructed submission owner
        let expected_digest = data.command_digest().map_err(|_| denied())?;
        let node = self.process.node.as_ref().ok_or_else(denied)?;
        let receipt = self
            .process
            .runtime
            .block_on(node.submit_native_v6_prepared_intent_retirement(self.prepared))
            .map_err(|_| denied())?;
        original().map_err(|_| denied())?;
        if receipt.envelope_digest != expected_digest {
            return Err(denied());
        }
        let observed = self.process.observe_native_v6_intent_retirement_owner(
            self.deadline,
            self.expected,
            &data,
            &mut || original(),
        )?;
        if observed.resolution()
            != heptabao_raft_runtime::NativeV6IntentRetirementResolution::EffectsObserved
            || observed.observed.applied_log_index() < receipt.log_index
        {
            return Err(denied());
        }
        observed.verify()?;
        original().map_err(|_| denied())?;
        Ok(NativeHaCommittedIntentRetirement { observed, receipt })
    }
}

impl NativeHaIntentReadObservation<'_> {
    pub(crate) fn capsule_digest(&self) -> [u8; 32] {
        self.observed.capsule_digest()
    }
    pub(crate) fn resolution(&self) -> heptabao_raft_runtime::NativeV6IntentRetirementResolution {
        self.observed.resolution()
    }
    pub(crate) fn verify(&self) -> Result<(), String> {
        self.deadline.check().map_err(|_| denied())?;
        let native = self
            .process
            .native_v6
            .as_ref()
            .filter(|native| native.enabled())
            .ok_or_else(denied)?;
        let node = self.process.node.as_ref().ok_or_else(denied)?;
        if !Arc::ptr_eq(&self.instance, &native.identity)
            || self.observed.original_deadline() != self.deadline.instant()
            || self.expected != StateIdentity::RecordsV6(self.observed.current_root().root_digest())
        {
            return Err(denied());
        }
        native.validate_enrollment(&self.process.codec, self.observed.current_enrollment())?;
        self.process
            .runtime
            .block_on(node.verify_native_v6_intent_retirement_observation(&self.observed))
            .map_err(|_| denied())?;
        self.deadline.check().map_err(|_| denied())
    }
}
impl NativeHaCommittedIntentRetirement<'_> {
    pub(crate) fn receipt(&self) -> &heptabao_raft_runtime::CommitReceipt {
        &self.receipt
    }
    pub(crate) fn verify(&self) -> Result<(), String> {
        if self.observed.observed.applied_log_index() < self.receipt.log_index {
            return Err(denied());
        }
        self.observed.verify()
    }
}

pub(in crate::ha) fn is_admission_frame(frame: &[u8]) -> bool {
    frame.starts_with(REQUEST)
}

fn denied() -> String {
    "native HA retention original source, all-member readers or custody unavailable".into()
}

fn frame(
    magic: &[u8; 8],
    nonce: [u8; 32],
    from: u64,
    to: u64,
    selected: &NativeV6CommittedRootRead,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FRAME_BYTES);
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&from.to_be_bytes());
    bytes.extend_from_slice(&to.to_be_bytes());
    bytes.extend_from_slice(&selected.enrollment().cluster_digest());
    bytes.extend_from_slice(&selected.enrollment().digest());
    bytes.extend_from_slice(&selected.root().root_digest());
    bytes.extend_from_slice(&selected.enrollment().epoch().to_be_bytes());
    bytes.extend_from_slice(&selected.root().generation().to_be_bytes());
    for log in [
        selected.root().publication_log_id(),
        selected.root().intent_log_id(),
    ] {
        bytes.extend_from_slice(&log.committed_leader_id().term.to_be_bytes());
        bytes.extend_from_slice(&log.committed_leader_id().node_id.to_be_bytes());
        bytes.extend_from_slice(&log.index.to_be_bytes());
    }
    bytes.push(RETENTION_READER_FORMAT);
    bytes.push(INTENT_DURABLE_READER_FORMAT);
    bytes
}

impl NativeV6Runtime {
    pub(super) fn handle_retention_admission(
        &self,
        authenticated: AuthenticatedPeerFrame,
        node: &Arc<ProcessRaftNode>,
        handle: &tokio::runtime::Handle,
        cluster_digest: [u8; 32],
    ) -> Result<Vec<u8>, HaError> {
        let deadline = authenticated.deadline();
        if !self.enabled() || Instant::now() >= deadline || !authenticated.has_strict_raft_alpn() {
            return Err(HaError::PeerAuthenticationFailed);
        }
        let (peer, request, _) = authenticated.into_legacy_parts();
        if request.len() != FRAME_BYTES || !is_admission_frame(&request) {
            return Err(HaError::InvalidFrame);
        }
        let nonce: [u8; 32] = request[8..40]
            .try_into()
            .map_err(|_| HaError::InvalidFrame)?;
        let from = u64::from_be_bytes(
            request[40..48]
                .try_into()
                .map_err(|_| HaError::InvalidFrame)?,
        );
        let to = u64::from_be_bytes(
            request[48..56]
                .try_into()
                .map_err(|_| HaError::InvalidFrame)?,
        );
        if nonce == [0; 32]
            || from == 0
            || to != node.id()
            || self.configured_nodes.get(&from) != Some(&peer)
        {
            return Err(HaError::PeerAuthenticationFailed);
        }
        // The peer cannot echo arbitrary source bytes into an admission. This
        // member supplies a fresh real ReadIndex and its own committed source.
        let selected = handle
            .block_on(node.native_v6_committed_root_read(deadline))
            .map_err(|_| HaError::OutcomeUnknown)?
            .ok_or(HaError::InvalidMembership)?;
        self.validate_enrollment_binding(cluster_digest, selected.enrollment())
            .map_err(|_| HaError::InvalidMembership)?;
        if request != frame(REQUEST, nonce, from, to, &selected) {
            return Err(HaError::InvalidFrame);
        }
        let response = frame(RESPONSE, nonce, from, to, &selected);
        handle
            .block_on(heptabao_raft_runtime::with_read_index_deadline(
                deadline,
                node.verify_native_v6_committed_root_read(&selected),
            ))
            .map_err(|_| HaError::OutcomeUnknown)?;
        if Instant::now() >= deadline {
            return Err(HaError::OutcomeUnknown);
        }
        Ok(response)
    }
}

enum MetadataPreparation {
    RetireIntents,
    ActivateRetainedRoots,
}

impl HaProcess {
    pub(crate) fn prepare_native_v6_intent_retirement_owner(
        &self,
        deadline: OriginalDeadline,
        expected: StateIdentity,
        original: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<NativeHaPreparedIntentRetirement<'_>, String> {
        self.prepare_native_v6_metadata_owner(
            deadline,
            expected,
            original,
            MetadataPreparation::RetireIntents,
        )
    }

    pub(crate) fn prepare_native_v6_retained_root_activation_owner(
        &self,
        deadline: OriginalDeadline,
        expected: StateIdentity,
        original: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<NativeHaPreparedIntentRetirement<'_>, String> {
        self.prepare_native_v6_metadata_owner(
            deadline,
            expected,
            original,
            MetadataPreparation::ActivateRetainedRoots,
        )
    }

    fn prepare_native_v6_metadata_owner(
        &self,
        deadline: OriginalDeadline,
        expected: StateIdentity,
        original: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
        preparation: MetadataPreparation,
    ) -> Result<NativeHaPreparedIntentRetirement<'_>, String> {
        original().map_err(|_| denied())?;
        let read = self
            .native_v6_committed_read_for_local_root(deadline, expected.digest())?
            .ok_or_else(denied)?;
        if expected != StateIdentity::RecordsV6(read.published().root_digest()) {
            return Err(denied());
        }
        self.admit_native_v6_retention_readers(&read, original)?;
        self.verify_native_v6_committed_read(&read)?;
        original().map_err(|_| denied())?;
        let node = self.node.as_ref().ok_or_else(denied)?;
        let CommittedNativeV6Read {
            _operation,
            instance,
            selected,
            ..
        } = read;
        let prepared = match preparation {
            MetadataPreparation::RetireIntents => self
                .runtime
                .block_on(node.prepare_native_v6_intent_retirement(selected, 32)),
            MetadataPreparation::ActivateRetainedRoots => self
                .runtime
                .block_on(node.prepare_native_v6_retained_root_activation(selected)),
        }
        .map_err(|_| denied())?;
        let owner = NativeHaPreparedIntentRetirement {
            process: self,
            instance,
            _operation,
            prepared,
            expected,
            deadline,
        };
        owner.verify()?;
        original().map_err(|_| denied())?;
        Ok(owner)
    }

    pub(crate) fn observe_native_v6_intent_retirement_owner(
        &self,
        deadline: OriginalDeadline,
        expected: StateIdentity,
        previous: &heptabao_raft_runtime::NativeV6IntentRetirementRecovery,
        original: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<NativeHaIntentReadObservation<'_>, String> {
        original().map_err(|_| denied())?;
        let read = self
            .native_v6_committed_read_for_local_root(deadline, expected.digest())?
            .ok_or_else(denied)?;
        if expected != StateIdentity::RecordsV6(read.published().root_digest()) {
            return Err(denied());
        }
        self.verify_native_v6_committed_read(&read)?;
        let node = self.node.as_ref().ok_or_else(denied)?;
        let CommittedNativeV6Read {
            _operation,
            instance,
            selected,
            ..
        } = read;
        let observed = self
            .runtime
            .block_on(node.observe_native_v6_intent_retirement(selected, previous))
            .map_err(|_| denied())?;
        let result = NativeHaIntentReadObservation {
            process: self,
            instance,
            _operation,
            observed,
            expected,
            deadline,
        };
        result.verify()?;
        original().map_err(|_| denied())?;
        Ok(result)
    }

    fn admit_native_v6_retention_readers(
        &self,
        read: &CommittedNativeV6Read,
        original: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<(), String> {
        let native = self
            .native_v6
            .as_ref()
            .filter(|native| native.enabled())
            .ok_or_else(denied)?;
        let node = self.node.as_ref().ok_or_else(denied)?;
        original().map_err(|_| denied())?;
        self.verify_native_v6_committed_read(read)?;
        if read.selected.leader_id() != node.id()
            || native.configured_nodes.len() != read.enrollment().pins().len()
        {
            return Err(denied());
        }
        // Every member, including this node, must answer on its actual pinned
        // listener. A successful majority or local compile-time constant is
        // not a substitute for the missing member's new-format admission.
        for (&id, &pin) in read.enrollment().pins() {
            original().map_err(|_| denied())?;
            self.verify_native_v6_committed_read(read)?;
            let peer = native.configured_nodes.get(&id).ok_or_else(denied)?;
            let nonce = crate::crypto::random::<32>().map_err(|_| denied())?;
            if nonce == [0; 32] {
                return Err(denied());
            }
            let request = frame(REQUEST, nonce, node.id(), id, &read.selected);
            let response = native
                .transport
                .exchange_before_pinned_server(
                    peer,
                    &request,
                    read.deadline
                        .instant()
                        .min(read.selected.read_index_deadline()),
                    pin,
                )
                .map_err(|_| denied())?;
            if response != frame(RESPONSE, nonce, node.id(), id, &read.selected) {
                return Err(denied());
            }
            self.verify_native_v6_committed_read(read)?;
            original().map_err(|_| denied())?;
        }
        self.verify_native_v6_committed_read(read)?;
        original().map_err(|_| denied())
    }

    /// Shared physical collection does not retire Raft intent metadata. That
    /// separately authorized one-command operation must already have admitted
    /// retention format 6. Missing protocol, side roots or history are holds.
    pub(crate) fn with_native_v6_shared_retirement<T, F>(
        &self,
        deadline: OriginalDeadline,
        expected: StateIdentity,
        previous: Option<&NativeV6SharedRetirementSelection>,
        original: &mut F,
        consume: impl FnOnce(NativeV6SharedRetirementPlan<'_>, &mut F) -> T,
    ) -> Result<T, String>
    where
        F: FnMut() -> Result<(), LocalV6BlobError>,
    {
        original().map_err(|_| denied())?;
        let read = self
            .native_v6_committed_read_for_local_root(deadline, expected.digest())?
            .ok_or_else(denied)?;
        if expected != StateIdentity::RecordsV6(read.published().root_digest()) {
            return Err(denied());
        }
        self.admit_native_v6_retention_readers(&read, original)?;
        let native = self
            .native_v6
            .as_ref()
            .filter(|native| native.enabled())
            .ok_or_else(denied)?;
        let node = self.node.as_ref().ok_or_else(denied)?;
        let store = native.storage.get().ok_or_else(denied)?;
        self.verify_native_v6_committed_read(&read)?;
        let CommittedNativeV6Read {
            _operation,
            selected,
            ..
        } = read;
        // The original selected ReadIndex remains exact. Only its shared-store
        // operation is released before acquiring the actual exclusive lease.
        drop(_operation);
        original().map_err(|_| denied())?;
        let exclusive = store.try_native_quiescence().map_err(|_| denied())?;
        let retained = self
            .runtime
            .block_on(node.native_v6_retention_guard(&selected))
            .map_err(|_| denied())?;
        // From here the actual Raft writers are held. Calling another Raft
        // read would self-deadlock; the opaque retention guard independently
        // rechecks its held FDs, exact durable sources and original deadline.
        let physical = if let Some(previous) = previous {
            store.prepare_shared_retirement_reconciliation(retained, exclusive, previous, original)
        } else {
            store.prepare_shared_retirement(retained, exclusive, original)
        }
        .map_err(|_| denied())?;
        original().map_err(|_| denied())?;
        // No fallible post-callback check: the caller owns the exact durable
        // Pending/Complete result and must retain any unknown result intact.
        Ok(consume(physical, original))
    }

    /// Run one local barrier retirement while the real writers and complete
    /// historical typed mark remain held. This is separate from read-only
    /// inspection: no fallible post-callback check may replace a durable
    /// Pending/Complete/unknown result after physical effects have begun.
    pub(crate) fn with_native_v6_local_retirement<T, F>(
        &self,
        deadline: OriginalDeadline,
        expected: StateIdentity,
        original: &mut F,
        consume: impl FnOnce(NativeHaLocalRetirementCustody<'_>) -> T,
    ) -> Result<T, String>
    where
        F: FnMut() -> Result<(), LocalV6BlobError>,
    {
        original().map_err(|_| denied())?;
        let read = self
            .native_v6_committed_read_for_local_root(deadline, expected.digest())?
            .ok_or_else(denied)?;
        if expected != StateIdentity::RecordsV6(read.published().root_digest()) {
            return Err(denied());
        }
        self.admit_native_v6_retention_readers(&read, original)?;
        let native = self
            .native_v6
            .as_ref()
            .filter(|native| native.enabled())
            .ok_or_else(denied)?;
        let node = self.node.as_ref().ok_or_else(denied)?;
        let store = native.storage.get().ok_or_else(denied)?;
        self.verify_native_v6_committed_read(&read)?;
        let CommittedNativeV6Read {
            _operation,
            selected,
            ..
        } = read;
        drop(_operation);
        original().map_err(|_| denied())?;
        let exclusive = store.try_native_quiescence().map_err(|_| denied())?;
        let retained = self
            .runtime
            .block_on(node.native_v6_retention_guard(&selected))
            .map_err(|_| denied())?;
        let catalog = retained.retained_root_catalog().map_err(|_| denied())?;
        let marked = crate::service::native_v6_ha_objects::mark_native_v6_retained_roots(
            &self.codec,
            store,
            &catalog,
            &exclusive,
            deadline,
            &mut || original().map_err(|_| crate::ha_state::native_v6::NativeV6CodecError::Gate),
        )
        .map_err(|_| denied())?;
        let fingerprint = catalog.fingerprint().map_err(|_| denied())?;
        if marked.catalog_sha256() != fingerprint {
            return Err(denied());
        }
        // No further Raft read is legal while these actual writers are held.
        // Every lower metadata/FD/authentication/unlink/fsync boundary calls
        // this exact borrowed closure; it never reconstructs an owner from a
        // mark, hash, current-node lookup or old pending record.
        let actor = std::cell::RefCell::new(original);
        let check = || -> Result<(), heptabao_durable_service::ServiceError> {
            use heptabao_durable_service::ServiceError;
            deadline.check().map_err(|_| ServiceError::BarrierFailure)?;
            actor
                .try_borrow_mut()
                .map_err(|_| ServiceError::BarrierFailure)?()
            .map_err(|_| ServiceError::BarrierFailure)?;
            store
                .verify_retention_ownership(&retained, &exclusive)
                .map_err(|_| ServiceError::PublicationConditionConflict)?;
            if catalog
                .fingerprint()
                .map_err(|_| ServiceError::PublicationConditionConflict)?
                != fingerprint
                || marked.catalog_sha256() != fingerprint
            {
                return Err(ServiceError::PublicationConditionConflict);
            }
            actor
                .try_borrow_mut()
                .map_err(|_| ServiceError::BarrierFailure)?()
            .map_err(|_| ServiceError::BarrierFailure)?;
            deadline.check().map_err(|_| ServiceError::BarrierFailure)
        };
        check().map_err(|_| denied())?;
        let owner = NativeHaLocalRetirementCustody {
            marked: &marked,
            check: &check,
        };
        Ok(consume(owner))
    }

    /// Inspect the complete historical typed union while keeping the actual
    /// writers and ciphertext store quiescent. This does not create a local
    /// barrier retirement owner or authorize any physical operation.
    pub(crate) fn inspect_native_v6_local_retained_resources<T, F>(
        &self,
        deadline: OriginalDeadline,
        expected: StateIdentity,
        original: &mut F,
        inspect: impl FnOnce(
            &crate::service::native_v6_ha_objects::NativeV6TypedRetainedResources,
            &mut F,
        ) -> Result<T, String>,
    ) -> Result<T, String>
    where
        F: FnMut() -> Result<(), LocalV6BlobError>,
    {
        original().map_err(|_| denied())?;
        let read = self
            .native_v6_committed_read_for_local_root(deadline, expected.digest())?
            .ok_or_else(denied)?;
        if expected != StateIdentity::RecordsV6(read.published().root_digest()) {
            return Err(denied());
        }
        self.admit_native_v6_retention_readers(&read, original)?;
        let native = self
            .native_v6
            .as_ref()
            .filter(|native| native.enabled())
            .ok_or_else(denied)?;
        let node = self.node.as_ref().ok_or_else(denied)?;
        let store = native.storage.get().ok_or_else(denied)?;
        self.verify_native_v6_committed_read(&read)?;
        let CommittedNativeV6Read {
            _operation,
            selected,
            ..
        } = read;
        drop(_operation);
        original().map_err(|_| denied())?;
        let exclusive = store.try_native_quiescence().map_err(|_| denied())?;
        let retained = self
            .runtime
            .block_on(node.native_v6_retention_guard(&selected))
            .map_err(|_| denied())?;
        let catalog = retained.retained_root_catalog().map_err(|_| denied())?;
        let marked = crate::service::native_v6_ha_objects::mark_native_v6_retained_roots(
            &self.codec,
            store,
            &catalog,
            &exclusive,
            deadline,
            &mut || original().map_err(|_| crate::ha_state::native_v6::NativeV6CodecError::Gate),
        )
        .map_err(|_| denied())?;
        original().map_err(|_| denied())?;
        store
            .verify_retention_ownership(&retained, &exclusive)
            .map_err(|_| denied())?;
        if marked.catalog_sha256() != catalog.fingerprint().map_err(|_| denied())? {
            return Err(denied());
        }
        let result = inspect(&marked, original)?;
        // No mutation takes place in this lane. A late owner/deadline denial
        // discards the inspection result instead of returning an old mark.
        original().map_err(|_| denied())?;
        store
            .verify_retention_ownership(&retained, &exclusive)
            .map_err(|_| denied())?;
        if marked.catalog_sha256() != catalog.fingerprint().map_err(|_| denied())? {
            return Err(denied());
        }
        original().map_err(|_| denied())?;
        Ok(result)
    }
}
