//! Exact committed-intent ciphertext custody over the existing pinned mTLS.
//!
//! A final acknowledgement is emitted only after every declared immutable
//! ciphertext was actually fsynced and the whole canonical manifest was fsynced
//! with its directory. The collector counts distinct committed voter pins,
//! including a real loopback TLS exchange for any local vote. There is no
//! public acknowledgement constructor/decoder or local-observation promotion.
//!
//! This is a trusted-replica durability component, not Byzantine attestation,
//! a Raft root CAS, a barrier/typed-graph check, Actor/ACL permission or an HTTP
//! reply grant. Production native-HA guards remain closed. Run these blocking
//! peer operations on a separate bounded worker pool, never the Raft runtime
//! workers or a recursively acquired Service writer.
use super::{
    HaError, MutualTlsPeerTransport, NodeId, PinnedClientCertificateMap,
    serve_one_mtls_authenticated_peer_frame,
};
#[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
use crate::closure_phase_diagnostic as diagnostic;
use heptabao_raft_runtime::{
    LocalV6BlobError, LocalV6BlobStage, NativeV6ClosureAdmission, NativeV6CommitIntent,
    NativeV6PeerEnrollment, ProcessRaftNode, RecordObjectRef,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::{Future, poll_fn};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use tokio::sync::{Semaphore, SemaphorePermit, oneshot};

#[path = "v6_closure_quorum_wire.rs"]
mod wire;
use wire::{Binding, Kind};
#[path = "v6_closure_batch.rs"]
mod batch;
#[path = "v6_closure_ingress.rs"]
mod ingress;
pub use ingress::is_native_v6_closure_frame;
#[path = "v6_committed_root_pull.rs"]
mod committed_pull;
pub use committed_pull::{
    NATIVE_V6_ROOT_PULL_GLOBAL_FRAMES, NATIVE_V6_ROOT_PULL_REQUESTS_PER_DONOR,
    NativeV6CommittedRootSource, NativeV6IngressClosureRead, NativeV6IngressSupersededRead,
    RecoveredNativeV6LocalClosure, is_native_v6_root_pull_frame,
    read_native_v6_fresh_ingress_closure, read_or_recover_native_v6_committed_closure,
    recover_native_v6_committed_closure,
};

fn unknown() -> HaError {
    HaError::OutcomeUnknown
}

fn check_deadline(deadline: Instant) -> Result<(), HaError> {
    if Instant::now() >= deadline {
        return Err(unknown());
    }
    Ok(())
}

fn require_blocking_worker() -> Result<(), HaError> {
    // Handle::block_on from an asynchronous runtime worker can panic or stall
    // the consensus tasks needed by follower ReadIndex. Fail before any I/O.
    if Handle::try_current().is_ok() {
        return Err(HaError::InvalidCluster);
    }
    Ok(())
}

// One bounded ciphertext frame per charged socket worker, across ALL callers.
// A cancelled exchange retains its permit until the actual bounded socket I/O
// ends. It owns no borrowed store, consensus owner, Actor, or closure payload.
const MAX_INFLIGHT_CLOSURE_FRAMES: usize = 8;
static CLOSURE_FRAME_CAPACITY: OnceLock<Arc<Semaphore>> = OnceLock::new();
// A transfer may overlap two independently authenticated packed frames, but
// its receiver still performs only ONE physical batch at a time. The second
// frame may wait briefly after its own fresh admission; it cannot consume an
// entire original frame budget behind another worker's slow filesystem I/O.
const PACKED_FRAME_WINDOW: usize = 2;
const MAX_PACKED_STORAGE_HANDOFF: Duration = Duration::from_millis(100);

struct CancelSocketJob(Arc<AtomicBool>);
impl Drop for CancelSocketJob {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn private_peer_name(id: u64) -> Result<NodeId, HaError> {
    if id == 0 {
        return Err(HaError::InvalidMembership);
    }
    NodeId::parse(format!("native-v6-voter-{id}"))
}

struct IncomingClosure {
    binding: Binding,
    references: Vec<RecordObjectRef>,
    fsynced: Vec<bool>,
    fsynced_count: usize,
    complete: bool,
}

impl IncomingClosure {
    fn new(binding: Binding) -> Result<Self, HaError> {
        let count =
            usize::try_from(binding.intent.object_count).map_err(|_| HaError::InvalidFrame)?;
        if count == 0 || count > wire::MAX_OBJECTS {
            return Err(HaError::InvalidFrame);
        }
        Ok(Self {
            binding,
            references: Vec::with_capacity(count),
            fsynced: Vec::new(),
            fsynced_count: 0,
            complete: false,
        })
    }

    fn page(&mut self, offset: usize, references: Vec<RecordObjectRef>) -> Result<usize, HaError> {
        let end = offset
            .checked_add(references.len())
            .ok_or(HaError::InvalidFrame)?;
        if end > self.binding.intent.object_count as usize || references.is_empty() {
            return Err(HaError::InvalidFrame);
        }
        if offset < self.references.len() {
            // Exact duplicate manifest pages can reconcile a lost page reply.
            // They confer no durability and never reset completed fsync work.
            if self.references.get(offset..end) != Some(references.as_slice()) {
                return Err(HaError::InvalidFrame);
            }
            return Ok(end);
        }
        if offset != self.references.len()
            || self.complete
            || self
                .references
                .last()
                .is_some_and(|last| last.id >= references[0].id)
        {
            return Err(HaError::InvalidFrame);
        }
        self.references.extend(references);
        if end == self.binding.intent.object_count as usize {
            wire::exact_manifest(&self.references, &self.binding.intent)?;
            self.fsynced = vec![false; self.references.len()];
            self.complete = true;
        }
        Ok(end)
    }

    fn selected(&self, reference: &RecordObjectRef) -> Result<usize, HaError> {
        if !self.complete {
            return Err(HaError::InvalidFrame);
        }
        let at = self
            .references
            .binary_search_by_key(&reference.id, |item| item.id)
            .map_err(|_| HaError::InvalidFrame)?;
        if &self.references[at] != reference {
            return Err(HaError::InvalidFrame);
        }
        Ok(at)
    }
}

/// A receiver owned by a real ProcessRaftNode and immutable local store.
/// The externally supplied enrollment is only an initial pin-map selection;
/// every actual request must match a fresh local committed enrollment/intent
/// admission. No public raw-frame handler can accept an asserted NodeId.
pub struct NativeV6ClosureReceiver {
    raft: Arc<ProcessRaftNode>,
    runtime: Handle,
    storage: Arc<LocalV6BlobStage>,
    pinned: PinnedClientCertificateMap,
    voter_by_peer: BTreeMap<NodeId, u64>,
    // The initial opaque enrollment fixes static trust, not a perpetual epoch.
    // Every accepted scope comes from the exact fresh runtime admission below.
    initial_enrollment: NativeV6PeerEnrollment,
    // One bounded manifest, at most MAX_OBJECTS, per receiver. It is merely a
    // transfer cache; a restart or a different admitted operation discards it.
    incoming: Mutex<Option<IncomingClosure>>,
    // One executing storage batch and at most one bounded packed-frame waiter.
    // Keeping physical batches serial preserves the existing Darwin object-FD
    // budget and the storage layer's four-worker fsync bound.
    incoming_storage: Semaphore,
    incoming_waiter: Semaphore,
    #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
    diagnostic: Arc<diagnostic::Stats>,
}

impl fmt::Debug for NativeV6ClosureReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeV6ClosureReceiver")
            .field("local_voter", &self.raft.id())
            .field("voters", &self.voter_by_peer.len())
            .finish_non_exhaustive()
    }
}

impl NativeV6ClosureReceiver {
    pub fn new(
        raft: Arc<ProcessRaftNode>,
        runtime: Handle,
        storage: Arc<LocalV6BlobStage>,
        enrollment: &NativeV6PeerEnrollment,
    ) -> Result<Self, HaError> {
        if !enrollment.pins().contains_key(&raft.id()) || enrollment.pins().len() < 3 {
            return Err(HaError::InvalidMembership);
        }
        let mut pins = BTreeMap::new();
        let mut voter_by_peer = BTreeMap::new();
        for (&id, &pin) in enrollment.pins() {
            let peer = private_peer_name(id)?;
            if pins.insert(pin, peer.clone()).is_some() || voter_by_peer.insert(peer, id).is_some()
            {
                return Err(HaError::InvalidMembership);
            }
        }
        Ok(Self {
            raft,
            runtime,
            storage,
            pinned: PinnedClientCertificateMap::new(pins)?,
            voter_by_peer,
            initial_enrollment: enrollment.clone(),
            incoming: Mutex::new(None),
            incoming_storage: Semaphore::new(1),
            incoming_waiter: Semaphore::new(1),
            #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
            diagnostic: diagnostic::Stats::new("receiver"),
        })
    }

    /// The sole ingress is actual strict client-certificate verification,
    /// actual leaf-pin lookup and mandatory Raft ALPN. Use a private listener
    /// with a separate bounded worker budget. Public API traffic cannot reach
    /// the internal parser through an unauthenticated callback.
    pub fn serve_one_mtls(
        &self,
        listener: &TcpListener,
        server: Arc<rustls::ServerConfig>,
        timeout: Duration,
    ) -> Result<(), HaError> {
        require_blocking_worker()?;
        #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
        let _diagnostic = diagnostic::Scope::enter(self.diagnostic.clone(), None);
        serve_one_mtls_authenticated_peer_frame(
            listener,
            server,
            &self.pinned,
            timeout,
            false,
            |frame| self.handle_authenticated(frame),
        )
    }

    // Read-only private failure classification. Preserve every original
    // result, consensus observation, filesystem operation and deadline.
    fn observe_receive_result<T, E>(
        &self,
        phase: &'static str,
        deadline: Instant,
        result: Result<T, E>,
    ) -> Result<T, E> {
        #[cfg(feature = "private-forward-stage-diagnostic")]
        if result.is_err() {
            eprintln!(
                "HBHA-PRIVATE-CLOSURE-FAIL phase={} voter={} original_remaining_ns={}",
                phase,
                self.raft.id(),
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_nanos(),
            );
        }
        let _ = (phase, deadline);
        result
    }

    fn verify(
        &self,
        admission: &NativeV6ClosureAdmission,
        deadline: Instant,
    ) -> Result<(), HaError> {
        check_deadline(deadline)?;
        self.observe_receive_result(
            "verify_original_admission",
            deadline,
            observe_closure_phase!(
                ReceiverVerify,
                self.runtime
                    .block_on(self.raft.verify_native_v6_closure_admission(admission))
            ),
        )
        .map_err(|_| unknown())?;
        check_deadline(deadline)
    }

    fn enter_storage(&self, kind: Kind, deadline: Instant) -> Result<SemaphorePermit<'_>, HaError> {
        check_deadline(deadline)?;
        if let Ok(permit) = self.incoming_storage.try_acquire() {
            return Ok(permit);
        }
        // Manifest, Ensure and Finalize retain their immediate busy rejection.
        // Only packed ciphertext frames need a short storage handoff.
        if kind != Kind::PackedStageBatch {
            return Err(unknown());
        }
        let _waiter = self.incoming_waiter.try_acquire().map_err(|_| unknown())?;
        let handoff = Instant::now()
            .checked_add(MAX_PACKED_STORAGE_HANDOFF)
            .ok_or_else(unknown)?
            .min(deadline);
        let permit = self.runtime.block_on(async {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(handoff),
                self.incoming_storage.acquire(),
            )
            .await
            .map_err(|_| unknown())?
            .map_err(|_| unknown())
        })?;
        check_deadline(deadline)?;
        Ok(permit)
    }

    fn receive(
        &self,
        actual_peer: &NodeId,
        bytes: &[u8],
        accepted_at: Instant,
        timeout: Duration,
    ) -> Result<Vec<u8>, HaError> {
        let deadline = accepted_at.checked_add(timeout).ok_or(HaError::Transport)?;
        #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
        let _diagnostic = diagnostic::Scope::enter(self.diagnostic.clone(), Some(deadline));
        check_deadline(deadline)?;
        let request = wire::parse(bytes)?;
        #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
        diagnostic::frame(request.kind as u8, request.payload.len());
        let sender = self
            .voter_by_peer
            .get(actual_peer)
            .copied()
            .ok_or(HaError::UnknownPeer)?;
        if request.target != self.raft.id() || sender != request.binding.leader {
            return Err(HaError::PeerAuthenticationFailed);
        }
        let admission = self
            .observe_receive_result(
                "admit_committed_intent",
                deadline,
                observe_closure_phase!(
                    ReceiverAdmission,
                    self.runtime.block_on(
                        self.raft
                            .admit_native_v6_closure(&request.binding.intent, deadline)
                    )
                ),
            )
            .map_err(|_| unknown())?;
        if Binding::observed(&admission) != request.binding
            || admission.leader_id() != sender
            || !admission
                .enrollment()
                .same_peer_configuration(&self.initial_enrollment)
        {
            return Err(HaError::PeerAuthenticationFailed);
        }
        self.verify(&admission, deadline)?;
        // Both frames performed their own fresh quorum admission above. A
        // queued frame rechecks that same original witness after acquiring the
        // sole physical-storage slot; the wait creates no authority or clock.
        // Declare this permit before the mutex guard so the guard drops first.
        let _storage = self.enter_storage(request.kind, deadline)?;
        self.verify(&admission, deadline)?;
        // A different transfer worker cannot consume this request's whole
        // deadline while holding the manifest owner during slow filesystem I/O.
        let mut incoming = observe_closure_phase!(ReceiverOwnerLock, self.incoming.try_lock()).map_err(|error| {
            #[cfg(feature = "private-forward-stage-diagnostic")]
            eprintln!(
                "HBHA-PRIVATE-CLOSURE-ADMISSION gate={} voter={} request_kind={} original_remaining_ns={}",
                match &error {
                    std::sync::TryLockError::WouldBlock => "incoming_owner_busy",
                    std::sync::TryLockError::Poisoned(_) => "incoming_owner_poisoned",
                },
                self.raft.id(),
                request.kind as u8,
                deadline.saturating_duration_since(Instant::now()).as_nanos(),
            );
            let _ = error;
            unknown()
        })?;
        let payload = match request.kind {
            Kind::Manifest => {
                let (offset, references) = wire::parse_manifest_page(request.payload)?;
                if incoming
                    .as_ref()
                    .is_none_or(|state| state.binding != request.binding)
                {
                    if offset != 0 {
                        return Err(HaError::InvalidFrame);
                    }
                    *incoming = Some(IncomingClosure::new(request.binding.clone())?);
                }
                let result = incoming
                    .as_mut()
                    .ok_or_else(unknown)?
                    .page(offset, references);
                let end = match result {
                    Ok(end) => end,
                    Err(error) => {
                        *incoming = None;
                        return Err(error);
                    }
                };
                (end as u64).to_be_bytes().to_vec()
            }
            Kind::Stage | Kind::FsyncExisting => {
                if request.payload.len() < 36 {
                    return Err(HaError::InvalidFrame);
                }
                let reference = wire::parse_reference(&request.payload[..36])?;
                let state = incoming
                    .as_mut()
                    .filter(|state| state.binding == request.binding)
                    .ok_or(HaError::InvalidFrame)?;
                let index = state.selected(&reference)?;
                let existing;
                let ciphertext = if request.kind == Kind::Stage {
                    if request.payload.len() != 36 + reference.encoded_bytes as usize {
                        return Err(HaError::InvalidFrame);
                    }
                    &request.payload[36..]
                } else {
                    if request.payload.len() != 36 {
                        return Err(HaError::InvalidFrame);
                    }
                    // A read-only probe is not a durable ACK. Reconciliation
                    // re-enters the actual no-replace file+directory fsync path.
                    existing = self.storage.read_local(&reference).map_err(|_| unknown())?;
                    &existing
                };
                self.verify(&admission, deadline)?;
                let mut gate = || {
                    self.verify(&admission, deadline)
                        .map_err(|_| LocalV6BlobError::CorruptOrChanged)
                };
                self.storage
                    .stage_received_replica_checked(&reference, ciphertext, &mut gate)
                    .map_err(|_| unknown())?;
                self.verify(&admission, deadline)?;
                if !state.fsynced[index] {
                    state.fsynced[index] = true;
                    state.fsynced_count += 1;
                }
                wire::reference_payload(&reference)?
            }
            Kind::StageBatch | Kind::FsyncExistingBatch => {
                let state = incoming
                    .as_mut()
                    .filter(|state| state.binding == request.binding)
                    .ok_or(HaError::InvalidFrame)?;
                self.observe_receive_result(
                    "receive_stage_batch",
                    deadline,
                    self.receive_batch(
                        state,
                        &admission,
                        deadline,
                        request.payload,
                        request.kind == Kind::StageBatch,
                    ),
                )?
            }
            Kind::PackedStageBatch => {
                let state = incoming
                    .as_mut()
                    .filter(|state| state.binding == request.binding)
                    .ok_or(HaError::InvalidFrame)?;
                self.observe_receive_result(
                    "receive_packed_stage_batch",
                    deadline,
                    self.receive_packed_stage(state, &admission, deadline, request.payload),
                )?
            }
            Kind::EnsureBatch => {
                let state = incoming
                    .as_mut()
                    .filter(|state| state.binding == request.binding)
                    .ok_or(HaError::InvalidFrame)?;
                self.observe_receive_result(
                    "receive_ensure_batch",
                    deadline,
                    observe_closure_phase!(
                        ReceiverEnsure,
                        self.receive_ensure_batch(state, &admission, deadline, request.payload)
                    ),
                )?
            }
            Kind::Finalize => {
                if !request.payload.is_empty() {
                    return Err(HaError::InvalidFrame);
                }
                let state = incoming
                    .as_ref()
                    .filter(|state| state.binding == request.binding)
                    .ok_or(HaError::InvalidFrame)?;
                if !state.complete
                    || state.fsynced_count != state.references.len()
                    || state.fsynced.iter().any(|done| !done)
                {
                    return Err(HaError::OutcomeUnknown);
                }
                let mut gate = || {
                    self.verify(&admission, deadline)
                        .map_err(|_| LocalV6BlobError::CorruptOrChanged)
                };
                // This physically reopens EVERY ciphertext and performs the
                // canonical manifest's no-replace file and directory fsync.
                // Only preceding actual stage/fsync calls populated fsynced.
                let persisted = self
                    .observe_receive_result(
                        "final_manifest_persist",
                        deadline,
                        observe_closure_phase!(
                            FinalizeManifest,
                            self.storage
                                .persist_local_closure(&state.references, &mut gate)
                        ),
                    )
                    .map_err(|_| unknown())?;
                if persisted.manifest_sha256() != request.binding.intent.closure_manifest_sha256
                    || persisted.object_count() as u64 != request.binding.intent.object_count
                    || persisted.ciphertext_bytes() != request.binding.intent.ciphertext_bytes
                {
                    return Err(unknown());
                }
                wire::final_payload(&request.binding.intent)
            }
        };
        self.verify(&admission, deadline)?;
        wire::reply(&request, &payload)
    }
}

/// Final custody on a majority of DISTINCT numeric voters authenticated using
/// their actually committed TLS leaf pins. The only constructor is the real
/// network collector below, after fresh final Raft admission. It is neither
/// Clone nor Serialize/Deserialize; wire ACKs and local receipts cannot build it.
pub struct NativeV6ClosureQuorum {
    admission: NativeV6ClosureAdmission,
    voters: Vec<u64>,
    deadline: Instant,
}

impl fmt::Debug for NativeV6ClosureQuorum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeV6ClosureQuorum")
            .field("voters", &self.voters)
            .field("intent_index", &self.admission.intent_log_id().index)
            .finish_non_exhaustive()
    }
}

impl NativeV6ClosureQuorum {
    pub fn voter_ids(&self) -> &[u64] {
        &self.voters
    }
    pub fn enrollment(&self) -> &NativeV6PeerEnrollment {
        self.admission.enrollment()
    }
    pub fn intent(&self) -> &NativeV6CommitIntent {
        self.admission.intent()
    }

    /// Required immediately before the caller's real root CAS, together with
    /// its own original Actor, barrier/graph and delivery checks. This never
    /// refreshes the stored witness or extends the operation deadline.
    pub async fn verify_for_publication(&self, raft: &ProcessRaftNode) -> Result<(), HaError> {
        check_deadline(self.deadline)?;
        if raft.id() != self.admission.leader_id()
            || self.voters.len() < self.admission.enrollment().pins().len() / 2 + 1
            || self
                .voters
                .iter()
                .any(|id| !self.admission.enrollment().pins().contains_key(id))
        {
            return Err(unknown());
        }
        raft.verify_native_v6_closure_admission(&self.admission)
            .await
            .map_err(|_| unknown())?;
        check_deadline(self.deadline)
    }
}

/// Borrowed immutable-source inputs for one closure collection. This groups
/// the local ciphertext store, its exact reference list and proposed intent;
/// construction grants no admission, durability receipt or publication right.
/// The collector still validates every reference and obtains fresh Raft gates.
pub struct NativeV6ClosureSource<'a> {
    pub source: &'a LocalV6BlobStage,
    pub references: &'a [RecordObjectRef],
    pub intent: &'a NativeV6CommitIntent,
}

impl fmt::Debug for NativeV6ClosureSource<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeV6ClosureSource")
            .field("object_count", &self.references.len())
            .finish_non_exhaustive()
    }
}

/// Copy exact ciphertext references and obtain final fsync receipts on a
/// majority. Routing names are transport hints only: every socket is pinned to
/// the leaf in the actual committed numeric-voter enrollment. Include the local
/// listener in routes; there is no implicit local vote. A failed peer may have
/// durable unreferenced bytes; it is skipped, never counted or blindly retried.
pub fn replicate_native_v6_closure_to_quorum(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    transport: &MutualTlsPeerTransport,
    routes: &BTreeMap<u64, NodeId>,
    closure: NativeV6ClosureSource<'_>,
    deadline: Instant,
) -> Result<NativeV6ClosureQuorum, HaError> {
    collect(raft, runtime, transport, routes, closure, deadline, true)
}

/// Reconcile a lost final response without transferring ciphertext. Existing
/// bytes are physically reopened and passed through real file+directory fsync
/// at every counted voter; this intentionally is not the old read-only probe.
pub fn reconcile_native_v6_closure_quorum(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    transport: &MutualTlsPeerTransport,
    routes: &BTreeMap<u64, NodeId>,
    closure: NativeV6ClosureSource<'_>,
    deadline: Instant,
) -> Result<NativeV6ClosureQuorum, HaError> {
    collect(raft, runtime, transport, routes, closure, deadline, false)
}

fn collect(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    transport: &MutualTlsPeerTransport,
    routes: &BTreeMap<u64, NodeId>,
    closure: NativeV6ClosureSource<'_>,
    deadline: Instant,
    transfer: bool,
) -> Result<NativeV6ClosureQuorum, HaError> {
    let NativeV6ClosureSource {
        source,
        references,
        intent,
    } = closure;
    let _native_operation = source
        .begin_native_operation()
        .map_err(|_| HaError::Transport)?;
    #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
    let _diagnostic = diagnostic::Scope::enter(diagnostic::Stats::new("collector"), Some(deadline));
    require_blocking_worker()?;
    check_deadline(deadline)?;
    let admission = observe_closure_phase!(
        CollectorAdmission,
        runtime.block_on(raft.admit_native_v6_closure(intent, deadline))
    )
    .map_err(|_| unknown())?;
    if admission.leader_id() != raft.id()
        || routes.keys().copied().collect::<BTreeSet<_>>()
            != admission
                .enrollment()
                .pins()
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
        || routes.values().collect::<BTreeSet<_>>().len() != routes.len()
    {
        return Err(HaError::InvalidMembership);
    }
    let binding = Binding::observed(&admission);
    let pins = admission.enrollment().pins().clone();
    let majority = pins.len() / 2 + 1;
    let mut ordered = references.to_vec();
    ordered.sort_unstable_by_key(|reference| reference.id);
    wire::exact_manifest(&ordered, intent)?;
    #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
    let source_timing = diagnostic::Span::start(diagnostic::Phase::SourcePreflight);
    for reference in &ordered {
        check_deadline(deadline)?;
        drop(source.read_local(reference).map_err(|_| unknown())?);
    }
    #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
    if let Some(timing) = source_timing {
        timing.finish(true);
    }
    check_deadline(deadline)?;
    // All counted voters, including self, pass through exactly the same TLS
    // path. Prioritize self for one-follower-down availability, but never add
    // its numeric ID merely because a local source was observed.
    let mut targets: Vec<_> = routes.iter().collect();
    targets.sort_by_key(|(id, _)| (**id != raft.id(), **id));
    // Poll each voter's transfer concurrently. A blackholed first socket may
    // retain its own bounded capacity, but cannot consume the healthy voters'
    // opportunity to finish before the same original request deadline.
    let mut voters = runtime.block_on(async {
        let mut pending: Vec<_> = targets
            .into_iter()
            .map(|(&target, route)| {
                (
                    target,
                    Box::pin(transfer_one(
                        ClosurePeer {
                            transport,
                            route,
                            target,
                            pin: pins[&target],
                            binding: &binding,
                            deadline,
                        },
                        source,
                        &ordered,
                        transfer,
                    )),
                )
            })
            .collect();
        let mut voters = Vec::new();
        while voters.len() < majority {
            check_deadline(deadline)?;
            if voters.len() + pending.len() < majority {
                return Err(unknown());
            }
            let (index, result) = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                poll_fn(|cx| {
                    for (index, (_, operation)) in pending.iter_mut().enumerate() {
                        if let Poll::Ready(result) = operation.as_mut().poll(cx) {
                            return Poll::Ready((index, result));
                        }
                    }
                    Poll::Pending
                }),
            )
            .await
            .map_err(|_| unknown())?;
            check_deadline(deadline)?;
            let (target, completed) = pending.swap_remove(index);
            drop(completed);
            if result.is_ok() {
                voters.push(target);
            }
        }
        // Dropping unfinished futures cancels queued work and prevents their
        // next frame. Never join a blackholed socket after a real majority.
        // A last already-running frame may leave unreferenced durable bytes;
        // its now-unobserved result cannot enter any quorum constructor.
        drop(pending);
        Ok::<_, HaError>(voters)
    })?;
    // A fresh final quorum must still describe exactly the same enrollment,
    // original intent/full LogId and leader term. Earlier socket responses do
    // not renew a consensus witness or the original operation deadline.
    let after = observe_closure_phase!(
        FinalAdmission,
        runtime.block_on(raft.admit_native_v6_closure(intent, deadline))
    )
    .map_err(|_| unknown())?;
    if Binding::observed(&after) != binding || after.leader_id() != raft.id() {
        return Err(unknown());
    }
    observe_closure_phase!(
        FinalVerify,
        runtime.block_on(raft.verify_native_v6_closure_admission(&after))
    )
    .map_err(|_| unknown())?;
    check_deadline(deadline)?;
    voters.sort_unstable();
    Ok(NativeV6ClosureQuorum {
        admission: after,
        voters,
        deadline,
    })
}

// One transfer's fixed routing and original request scope. This borrows the
// actual collector inputs; it does not cache an ACK or renew the admission.
struct ClosurePeer<'a> {
    transport: &'a MutualTlsPeerTransport,
    route: &'a NodeId,
    target: u64,
    pin: [u8; 32],
    binding: &'a Binding,
    deadline: Instant,
}

async fn exchange_reply(
    peer: &ClosurePeer<'_>,
    kind: Kind,
    payload: impl FnOnce() -> Result<Vec<u8>, HaError>,
    expected: &[u8],
) -> Result<Vec<RecordObjectRef>, HaError> {
    let &ClosurePeer {
        transport,
        route,
        target,
        pin,
        binding,
        deadline,
    } = peer;
    check_deadline(deadline)?;
    let capacity = CLOSURE_FRAME_CAPACITY
        .get_or_init(|| Arc::new(Semaphore::new(MAX_INFLIGHT_CLOSURE_FRAMES)))
        .clone();
    #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
    let capacity_timing = diagnostic::Span::start(diagnostic::Phase::FrameCapacity);
    let permit = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        capacity.acquire_owned(),
    )
    .await
    .map_err(|_| unknown())?
    .map_err(|_| unknown())?;
    #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
    if let Some(timing) = capacity_timing {
        timing.finish(true);
    }
    check_deadline(deadline)?;
    // Build/read only one bounded payload AFTER obtaining actual capacity.
    // The borrowed local store remains on the synchronous collector thread.
    let request = observe_closure_phase!(
        FramePayload,
        wire::encode(binding, target, kind, &payload()?)
    )?;
    #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
    diagnostic::frame(kind as u8, request.len().saturating_sub(wire::HEADER_BYTES));
    check_deadline(deadline)?;
    let transport = transport.clone();
    let route = route.clone();
    let expected = expected.to_vec();
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancel = CancelSocketJob(cancelled.clone());
    let (send, received) = oneshot::channel();
    #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
    let diagnostic_context = diagnostic::capture();
    #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
    let diagnostic_queued = Instant::now();
    let worker = std::thread::Builder::new()
        .name("hb-v6-peer-frame".into())
        .spawn(move || {
            #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
            let _diagnostic = diagnostic::Scope::attach(diagnostic_context);
            #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
            if let Some(timing) =
                diagnostic::Span::since(diagnostic::Phase::WorkerQueue, diagnostic_queued)
            {
                timing.finish(true);
            }
            // Capacity stays charged on panic, cancellation and unknown I/O until
            // this real OS worker exits; no unbounded detached worker accumulation.
            let _permit = permit;
            let result = (|| {
                if cancelled.load(Ordering::Acquire) {
                    return Err(unknown());
                }
                check_deadline(deadline)?;
                let response = transport
                    .exchange_before_pinned_server(&route, &request, deadline, pin)
                    .map_err(|_| unknown())?;
                check_deadline(deadline)?;
                if cancelled.load(Ordering::Acquire) {
                    return Err(unknown());
                }
                // This private response came from the above actual pinned socket,
                // and must echo its unpredictable nonce and complete binding.
                if kind == Kind::EnsureBatch {
                    observe_closure_phase!(
                        ReplyVerify,
                        wire::verify_missing_reply(&request, &response, &expected)
                    )
                } else {
                    observe_closure_phase!(
                        ReplyVerify,
                        wire::verify_reply(&request, &response, &expected)
                    )?;
                    Ok(Vec::new())
                }
            })();
            let _ = send.send(result);
        })
        .map_err(|_| unknown())?;
    drop(worker);
    #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
    let wait_timing = diagnostic::Span::start(diagnostic::Phase::FrameWait);
    let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), received)
        .await
        .map_err(|_| unknown())?
        .map_err(|_| unknown())?;
    #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
    if let Some(timing) = wait_timing {
        timing.finish(result.is_ok());
    }
    check_deadline(deadline)?;
    drop(cancel);
    result
}

// Keep the original exact-payload exchange interface for every existing
// frame kind, including reconciliation and final whole-closure custody.
async fn exchange(
    peer: &ClosurePeer<'_>,
    kind: Kind,
    payload: impl FnOnce() -> Result<Vec<u8>, HaError>,
    expected: &[u8],
) -> Result<(), HaError> {
    if kind == Kind::EnsureBatch {
        return Err(HaError::InvalidFrame);
    }
    exchange_reply(peer, kind, payload, expected)
        .await
        .map(|_| ())
}

async fn transfer_one(
    peer: ClosurePeer<'_>,
    source: &LocalV6BlobStage,
    references: &[RecordObjectRef],
    transfer: bool,
) -> Result<(), HaError> {
    let deadline = peer.deadline;
    let binding = peer.binding;
    for (page, references) in references.chunks(wire::PAGE_OBJECTS).enumerate() {
        let offset = page * wire::PAGE_OBJECTS;
        exchange(
            &peer,
            Kind::Manifest,
            || wire::manifest_page(offset, references),
            &((offset + references.len()) as u64).to_be_bytes(),
        )
        .await?;
    }
    if transfer {
        // Reference-only inventory retains its separate bound. Pack each
        // authenticated missing subset by actual encoded bytes and at most
        // eight leaves, under the SAME original frame and operation deadlines.
        for references in references.chunks(batch::ENSURE_OBJECTS) {
            check_deadline(deadline)?;
            let requested = batch::ensure_expected(references)?;
            let missing = exchange_reply(
                &peer,
                Kind::EnsureBatch,
                || Ok(requested.clone()),
                &requested,
            )
            .await?;
            check_deadline(deadline)?;
            // This exact authenticated response is the sole permission to
            // transfer a subset. Lost ACKs, corrupt leaves and stale admission
            // return above; none is converted into an automatic payload retry.
            // Unknown kinds/replies are terminal here. In particular this
            // new kind never falls back to replaying a mutation as kind 5.
            transfer_packed_frames(&peer, source, &batch::packed_batches(&missing)?).await?;
        }
    } else {
        for references in references.chunks(batch::OBJECTS) {
            check_deadline(deadline)?;
            // Reconciliation remains fsync-only and fails if any leaf is
            // absent. It never borrows the new missing-transfer permission.
            let expected = batch::expected(references)?;
            exchange(
                &peer,
                Kind::FsyncExistingBatch,
                || batch::payload(source, references, false, deadline),
                &expected,
            )
            .await?;
        }
    }
    exchange(
        &peer,
        Kind::Finalize,
        || Ok(Vec::new()),
        &wire::final_payload(&binding.intent),
    )
    .await
}

async fn transfer_packed_frames(
    peer: &ClosurePeer<'_>,
    source: &LocalV6BlobStage,
    batches: &[&[RecordObjectRef]],
) -> Result<(), HaError> {
    // The original authenticated missing set is partitioned without changing
    // its objects, frame bounds or canonical order within a frame. Each frame
    // acquires the original
    // global socket capacity before reading its own payload, and independently
    // validates the real pinned TLS response, nonce and complete binding.
    for window in batches.chunks(PACKED_FRAME_WINDOW) {
        let mut pending: Vec<_> = window
            .iter()
            .map(|references| {
                Box::pin(async move {
                    let expected = batch::packed_expected(references)?;
                    exchange(
                        peer,
                        Kind::PackedStageBatch,
                        || batch::packed_payload(source, references, peer.deadline),
                        &expected,
                    )
                    .await
                })
            })
            .collect();
        while !pending.is_empty() {
            check_deadline(peer.deadline)?;
            let (index, result) = tokio::time::timeout_at(
                tokio::time::Instant::from_std(peer.deadline),
                poll_fn(|cx| {
                    for (index, operation) in pending.iter_mut().enumerate() {
                        if let Poll::Ready(result) = operation.as_mut().poll(cx) {
                            return Poll::Ready((index, result));
                        }
                    }
                    Poll::Pending
                }),
            )
            .await
            .map_err(|_| unknown())?;
            check_deadline(peer.deadline)?;
            drop(pending.swap_remove(index));
            // Any failed or unknown frame ends this transfer. Dropping the
            // other future cancels its next work; an already running socket
            // retains its charged permit until its real bounded I/O exits.
            // No mutation is replayed and no Finalize follows this error.
            result?;
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "v6_closure_quorum_tests.rs"]
mod tests;
