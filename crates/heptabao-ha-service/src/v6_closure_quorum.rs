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
use tokio::sync::{Semaphore, oneshot};

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
    NativeV6CommittedRootSource, RecoveredNativeV6LocalClosure, is_native_v6_root_pull_frame,
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
    enrollment_digest: [u8; 32],
    // One bounded manifest, at most MAX_OBJECTS, per receiver. It is merely a
    // transfer cache; a restart or a different admitted operation discards it.
    incoming: Mutex<Option<IncomingClosure>>,
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
            enrollment_digest: enrollment.digest(),
            incoming: Mutex::new(None),
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
        serve_one_mtls_authenticated_peer_frame(
            listener,
            server,
            &self.pinned,
            timeout,
            false,
            |frame| self.handle_authenticated(frame),
        )
    }

    fn verify(
        &self,
        admission: &NativeV6ClosureAdmission,
        deadline: Instant,
    ) -> Result<(), HaError> {
        check_deadline(deadline)?;
        self.runtime
            .block_on(self.raft.verify_native_v6_closure_admission(admission))
            .map_err(|_| unknown())?;
        check_deadline(deadline)
    }

    fn receive(
        &self,
        actual_peer: &NodeId,
        bytes: &[u8],
        accepted_at: Instant,
        timeout: Duration,
    ) -> Result<Vec<u8>, HaError> {
        let deadline = accepted_at.checked_add(timeout).ok_or(HaError::Transport)?;
        check_deadline(deadline)?;
        let request = wire::parse(bytes)?;
        let sender = self
            .voter_by_peer
            .get(actual_peer)
            .copied()
            .ok_or(HaError::UnknownPeer)?;
        if request.target != self.raft.id()
            || sender != request.binding.leader
            || request.binding.enrollment_digest != self.enrollment_digest
        {
            return Err(HaError::PeerAuthenticationFailed);
        }
        let admission = self
            .runtime
            .block_on(
                self.raft
                    .admit_native_v6_closure(&request.binding.intent, deadline),
            )
            .map_err(|_| unknown())?;
        if Binding::observed(&admission) != request.binding
            || admission.leader_id() != sender
            || admission.enrollment().digest() != self.enrollment_digest
        {
            return Err(HaError::PeerAuthenticationFailed);
        }
        self.verify(&admission, deadline)?;
        // A different transfer worker cannot consume this request's whole
        // deadline while holding the manifest owner during slow filesystem I/O.
        let mut incoming = self.incoming.try_lock().map_err(|_| unknown())?;
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
                self.receive_batch(
                    state,
                    &admission,
                    deadline,
                    request.payload,
                    request.kind == Kind::StageBatch,
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
                    .storage
                    .persist_local_closure(&state.references, &mut gate)
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
    source: &LocalV6BlobStage,
    references: &[RecordObjectRef],
    intent: &NativeV6CommitIntent,
    deadline: Instant,
) -> Result<NativeV6ClosureQuorum, HaError> {
    collect(
        raft, runtime, transport, routes, source, references, intent, deadline, true,
    )
}

/// Reconcile a lost final response without transferring ciphertext. Existing
/// bytes are physically reopened and passed through real file+directory fsync
/// at every counted voter; this intentionally is not the old read-only probe.
pub fn reconcile_native_v6_closure_quorum(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    transport: &MutualTlsPeerTransport,
    routes: &BTreeMap<u64, NodeId>,
    source: &LocalV6BlobStage,
    references: &[RecordObjectRef],
    intent: &NativeV6CommitIntent,
    deadline: Instant,
) -> Result<NativeV6ClosureQuorum, HaError> {
    collect(
        raft, runtime, transport, routes, source, references, intent, deadline, false,
    )
}

fn collect(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    transport: &MutualTlsPeerTransport,
    routes: &BTreeMap<u64, NodeId>,
    source: &LocalV6BlobStage,
    references: &[RecordObjectRef],
    intent: &NativeV6CommitIntent,
    deadline: Instant,
    transfer: bool,
) -> Result<NativeV6ClosureQuorum, HaError> {
    require_blocking_worker()?;
    check_deadline(deadline)?;
    let admission = runtime
        .block_on(raft.admit_native_v6_closure(intent, deadline))
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
    for reference in &ordered {
        check_deadline(deadline)?;
        drop(source.read_local(reference).map_err(|_| unknown())?);
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
                        transport,
                        route,
                        target,
                        pins[&target],
                        source,
                        &ordered,
                        &binding,
                        deadline,
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
    let after = runtime
        .block_on(raft.admit_native_v6_closure(intent, deadline))
        .map_err(|_| unknown())?;
    if Binding::observed(&after) != binding || after.leader_id() != raft.id() {
        return Err(unknown());
    }
    runtime
        .block_on(raft.verify_native_v6_closure_admission(&after))
        .map_err(|_| unknown())?;
    check_deadline(deadline)?;
    voters.sort_unstable();
    Ok(NativeV6ClosureQuorum {
        admission: after,
        voters,
        deadline,
    })
}

async fn exchange(
    transport: &MutualTlsPeerTransport,
    route: &NodeId,
    target: u64,
    pin: [u8; 32],
    binding: &Binding,
    kind: Kind,
    payload: impl FnOnce() -> Result<Vec<u8>, HaError>,
    expected: &[u8],
    deadline: Instant,
) -> Result<(), HaError> {
    check_deadline(deadline)?;
    let capacity = CLOSURE_FRAME_CAPACITY
        .get_or_init(|| Arc::new(Semaphore::new(MAX_INFLIGHT_CLOSURE_FRAMES)))
        .clone();
    let permit = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        capacity.acquire_owned(),
    )
    .await
    .map_err(|_| unknown())?
    .map_err(|_| unknown())?;
    check_deadline(deadline)?;
    // Build/read only one bounded payload AFTER obtaining actual capacity.
    // The borrowed local store remains on the synchronous collector thread.
    let request = wire::encode(binding, target, kind, &payload()?)?;
    check_deadline(deadline)?;
    let transport = transport.clone();
    let route = route.clone();
    let expected = expected.to_vec();
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancel = CancelSocketJob(cancelled.clone());
    let (send, received) = oneshot::channel();
    let worker = std::thread::Builder::new()
        .name("hb-v6-peer-frame".into())
        .spawn(move || {
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
                wire::verify_reply(&request, &response, &expected)
            })();
            let _ = send.send(result);
        })
        .map_err(|_| unknown())?;
    drop(worker);
    let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), received)
        .await
        .map_err(|_| unknown())?
        .map_err(|_| unknown())?;
    check_deadline(deadline)?;
    drop(cancel);
    result
}

async fn transfer_one(
    transport: &MutualTlsPeerTransport,
    route: &NodeId,
    target: u64,
    pin: [u8; 32],
    source: &LocalV6BlobStage,
    references: &[RecordObjectRef],
    binding: &Binding,
    deadline: Instant,
    transfer: bool,
) -> Result<(), HaError> {
    for (page, references) in references.chunks(wire::PAGE_OBJECTS).enumerate() {
        let offset = page * wire::PAGE_OBJECTS;
        exchange(
            transport,
            route,
            target,
            pin,
            binding,
            Kind::Manifest,
            || wire::manifest_page(offset, references),
            &((offset + references.len()) as u64).to_be_bytes(),
            deadline,
        )
        .await?;
    }
    for references in references.chunks(batch::OBJECTS) {
        check_deadline(deadline)?;
        let expected = batch::expected(references)?;
        let kind = if transfer {
            Kind::StageBatch
        } else {
            Kind::FsyncExistingBatch
        };
        exchange(
            transport,
            route,
            target,
            pin,
            binding,
            kind,
            || batch::payload(source, references, transfer, deadline),
            &expected,
            deadline,
        )
        .await?;
    }
    exchange(
        transport,
        route,
        target,
        pin,
        binding,
        Kind::Finalize,
        || Ok(Vec::new()),
        &wire::final_payload(&binding.intent),
        deadline,
    )
    .await
}

#[cfg(all(test, unix))]
#[path = "v6_closure_quorum_tests.rs"]
mod tests;
