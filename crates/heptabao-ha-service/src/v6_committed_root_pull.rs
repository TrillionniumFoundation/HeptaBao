//! Scoped repair of an already committed native closure. This path only reads
//! enrolled peers and stages exact immutable ciphertext locally. It submits no
//! Raft write, creates no quorum ACK and grants no Actor or local install right.
use super::*;
use crate::{AuthenticatedPeerFrame, serve_one_mtls_authenticated_peer_frame};
use heptabao_raft_runtime::{LocalV6ClosureReceipt, NativeV6CommittedRootRead};
use ring::rand::{SecureRandom, SystemRandom};
use std::pin::Pin;
use tokio::sync::OwnedSemaphorePermit;

#[path = "v6_committed_root_pull_wire.rs"]
mod pull_wire;
use pull_wire::{Kind as PullKind, RootBinding};

/// Classification alone grants no authenticated ingress or selected-root right.
pub fn is_native_v6_root_pull_frame(bytes: &[u8]) -> bool {
    bytes.starts_with(b"HBVP2")
}

struct SourceManifest {
    binding: RootBinding,
    generation: u64,
    references: Vec<RecordObjectRef>,
}

/// Read-only ciphertext source on an actual enrolled ProcessRaftNode. Its
/// configured opaque enrollment only selects initial pins. EVERY request must
/// match a fresh actual applied native root under the accepted socket deadline.
pub struct NativeV6CommittedRootSource {
    raft: Arc<ProcessRaftNode>,
    runtime: Handle,
    storage: Arc<LocalV6BlobStage>,
    pinned: PinnedClientCertificateMap,
    voters: BTreeMap<[u8; 32], u64>,
    initial_enrollment: NativeV6PeerEnrollment,
    // One bounded immutable-reference cache, not a read or fsync capability.
    manifest: Mutex<Option<SourceManifest>>,
}

impl fmt::Debug for NativeV6CommittedRootSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeV6CommittedRootSource")
            .field("voter", &self.raft.id())
            .field("enrolled_voters", &self.voters.len())
            .finish_non_exhaustive()
    }
}

impl NativeV6CommittedRootSource {
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
        let mut voters = BTreeMap::new();
        for (&voter, &pin) in enrollment.pins() {
            if pins.insert(pin, private_peer_name(voter)?).is_some()
                || voters.insert(pin, voter).is_some()
            {
                return Err(HaError::InvalidMembership);
            }
        }
        Ok(Self {
            raft,
            runtime,
            storage,
            pinned: PinnedClientCertificateMap::new(pins)?,
            voters,
            initial_enrollment: enrollment.clone(),
            manifest: Mutex::new(None),
        })
    }

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

    /// Native repair accepts any actually enrolled requesting voter, including
    /// a new leader whose local closure is absent. It does not infer leadership
    /// from that client's leaf. The selected root/full LogIds/term must equal
    /// this source's own fresh real ReadIndex observation before bytes leave.
    pub fn handle_authenticated(&self, frame: AuthenticatedPeerFrame) -> Result<Vec<u8>, HaError> {
        require_blocking_worker()?;
        check_deadline(frame.deadline())?;
        if !frame.has_strict_raft_alpn() {
            return Err(HaError::PeerAuthenticationFailed);
        }
        let actual_voter = self
            .voters
            .get(&frame.actual_leaf_sha256())
            .copied()
            .ok_or(HaError::UnknownPeer)?;
        let request = pull_wire::parse(frame.payload())?;
        if request.requester != actual_voter
            || request.target != self.raft.id()
        {
            return Err(HaError::PeerAuthenticationFailed);
        }
        let read = self
            .runtime
            .block_on(self.raft.native_v6_committed_root_read(frame.deadline()))
            .map_err(|_| unknown())?
            .ok_or_else(unknown)?;
        if !read.enrollment().same_peer_configuration(&self.initial_enrollment)
            || RootBinding::observed(&read) != request.binding
            || read.enrollment().pins().get(&actual_voter) != Some(&frame.actual_leaf_sha256())
        {
            return Err(HaError::PeerAuthenticationFailed);
        }
        let verify = || {
            check_deadline(frame.deadline())?;
            self.runtime
                .block_on(self.raft.verify_native_v6_committed_root_read(&read))
                .map_err(|_| unknown())?;
            check_deadline(frame.deadline())
        };
        verify()?;
        let mut manifest = self.manifest.try_lock().map_err(|_| unknown())?;
        if manifest.as_ref().is_none_or(|cached| {
            cached.binding != request.binding || cached.generation != read.application_generation()
        }) {
            // Rebuilding a cache reopens the actual full manifest/closure under
            // this new witness; no cached generation ever becomes authority.
            let mut gate = || verify().map_err(|_| LocalV6BlobError::CorruptOrChanged);
            let references = self
                .storage
                .reopen_root_closure(read.root(), &mut gate)
                .map_err(|_| unknown())?;
            wire::exact_manifest(&references, &request.binding.intent)?;
            *manifest = Some(SourceManifest {
                binding: request.binding.clone(),
                generation: read.application_generation(),
                references,
            });
        }
        let selected = manifest.as_ref().ok_or_else(unknown)?;
        let payload = match request.kind {
            PullKind::Manifest => {
                if request.payload.len() != 4 {
                    return Err(HaError::InvalidFrame);
                }
                let offset = u32::from_be_bytes(
                    request
                        .payload
                        .try_into()
                        .map_err(|_| HaError::InvalidFrame)?,
                ) as usize;
                if offset >= selected.references.len() {
                    return Err(HaError::InvalidFrame);
                }
                let end = offset
                    .saturating_add(wire::PAGE_OBJECTS)
                    .min(selected.references.len());
                wire::manifest_page(offset, &selected.references[offset..end])?
            }
            PullKind::Object => {
                let reference = wire::parse_reference(request.payload)?;
                let index = selected
                    .references
                    .binary_search_by_key(&reference.id, |item| item.id)
                    .map_err(|_| HaError::InvalidFrame)?;
                if selected.references.get(index) != Some(&reference) {
                    return Err(HaError::InvalidFrame);
                }
                verify()?;
                self.storage.read_local(&reference).map_err(|_| unknown())?
            }
        };
        verify()?;
        pull_wire::reply(&request, &payload)
    }
}

/// A locally fsynced exact closure plus a NEW, actually verified same-root
/// ReadIndex handle. This contains no remote quorum receipts and cannot be
/// passed as NativeV6ClosureQuorum. The Service still owns Actor/barrier/install.
pub struct RecoveredNativeV6LocalClosure {
    selected: NativeV6CommittedRootRead,
    local: LocalV6ClosureReceipt,
}

impl fmt::Debug for RecoveredNativeV6LocalClosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredNativeV6LocalClosure")
            .field("selected", &self.selected)
            .field("object_count", &self.local.object_count())
            .finish_non_exhaustive()
    }
}

impl RecoveredNativeV6LocalClosure {
    pub fn read(&self) -> &NativeV6CommittedRootRead {
        &self.selected
    }
    pub fn local_receipt(&self) -> &LocalV6ClosureReceipt {
        &self.local
    }
    pub fn into_parts(self) -> (NativeV6CommittedRootRead, LocalV6ClosureReceipt) {
        (self.selected, self.local)
    }
}

fn fresh_same(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    selected: &NativeV6CommittedRootRead,
) -> Result<NativeV6CommittedRootRead, HaError> {
    check_deadline(selected.operation_deadline())?;
    let fresh = runtime
        .block_on(raft.native_v6_committed_root_read(selected.operation_deadline()))
        .map_err(|_| unknown())?
        .ok_or_else(unknown)?;
    if !fresh.same_selection(selected) {
        return Err(unknown());
    }
    runtime
        .block_on(raft.verify_native_v6_committed_root_read(&fresh))
        .map_err(|_| unknown())?;
    check_deadline(selected.operation_deadline())?;
    Ok(fresh)
}

fn finish_local(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    storage: &LocalV6BlobStage,
    selected: NativeV6CommittedRootRead,
    references: &[RecordObjectRef],
    fsynced: &[bool],
) -> Result<RecoveredNativeV6LocalClosure, HaError> {
    if references.len() != fsynced.len() {
        return Err(HaError::InvalidFrame);
    }
    wire::exact_manifest(references, &selected.root().intent())?;
    let fresh = fresh_same(raft, runtime, &selected)?;
    let mut gate = || {
        check_deadline(selected.operation_deadline())
            .and_then(|()| {
                runtime
                    .block_on(raft.verify_native_v6_committed_root_read(&fresh))
                    .map_err(|_| unknown())
            })
            .map_err(|_| LocalV6BlobError::CorruptOrChanged)
    };
    for (reference, already_fsynced) in references.iter().zip(fsynced) {
        if !already_fsynced {
            gate().map_err(|_| unknown())?;
            let ciphertext = storage.read_local(reference).map_err(|_| unknown())?;
            storage
                .stage_received_replica_checked(reference, &ciphertext, &mut gate)
                .map_err(|_| unknown())?;
        }
    }
    let local = storage
        .persist_local_closure(references, &mut gate)
        .map_err(|_| unknown())?;
    let intent = selected.root().intent();
    if local.manifest_sha256() != intent.closure_manifest_sha256
        || local.object_count() as u64 != intent.object_count
        || local.ciphertext_bytes() != intent.ciphertext_bytes
    {
        return Err(unknown());
    }
    gate().map_err(|_| unknown())?;
    // This new read may have a new capped ReadIndex deadline, but the old
    // witness is never edited and the original operation deadline is identical.
    let selected = fresh_same(raft, runtime, &selected)?;
    Ok(RecoveredNativeV6LocalClosure { selected, local })
}

// A payload keeps its capacity charge until the sole consumer processes or
// drops it. Completed socket replies therefore cannot accumulate beyond the
// same eight-frame budget while slow local fsync blocks the controller.
struct VerifiedPullReply {
    payload: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

#[derive(Clone, Copy)]
enum PullStep {
    Manifest(usize),
    Object(usize),
}

struct PendingPull {
    target: u64,
    step: PullStep,
    operation: Pin<Box<dyn Future<Output = Result<VerifiedPullReply, HaError>> + Send>>,
}

fn pending_pull(
    transport: &MutualTlsPeerTransport,
    route: &NodeId,
    target: u64,
    pin: [u8; 32],
    binding: &RootBinding,
    requester: u64,
    round: [u8; 32],
    step: PullStep,
    references: &[RecordObjectRef],
    deadline: Instant,
) -> Result<PendingPull, HaError> {
    let (kind, payload) = match step {
        PullStep::Manifest(offset) => (
            PullKind::Manifest,
            u32::try_from(offset)
                .map_err(|_| HaError::InvalidFrame)?
                .to_be_bytes()
                .to_vec(),
        ),
        PullStep::Object(index) => (
            PullKind::Object,
            wire::reference_payload(references.get(index).ok_or(HaError::InvalidFrame)?)?,
        ),
    };
    let transport = transport.clone();
    let route = route.clone();
    let binding = binding.clone();
    Ok(PendingPull {
        target,
        step,
        operation: Box::pin(async move {
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
            let request = pull_wire::encode(&binding, requester, target, round, kind, &payload)?;
            let cancelled = Arc::new(AtomicBool::new(false));
            let cancel = CancelSocketJob(cancelled.clone());
            let (send, received) = oneshot::channel();
            let worker = std::thread::Builder::new()
                .name("hb-v6-root-pull".into())
                .spawn(move || {
                    let result = (|| {
                        check_deadline(deadline)?;
                        if cancelled.load(Ordering::Acquire) {
                            return Err(unknown());
                        }
                        let response = transport
                            .exchange_before_pinned_server(&route, &request, deadline, pin)
                            .map_err(|_| unknown())?;
                        check_deadline(deadline)?;
                        if cancelled.load(Ordering::Acquire) {
                            return Err(unknown());
                        }
                        let payload = pull_wire::verified_payload(&request, response)?;
                        Ok(VerifiedPullReply {
                            payload,
                            _permit: permit,
                        })
                    })();
                    let _ = send.send(result);
                })
                .map_err(|_| unknown())?;
            drop(worker);
            let result =
                tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), received)
                    .await
                    .map_err(|_| unknown())?
                    .map_err(|_| unknown())?;
            check_deadline(deadline)?;
            drop(cancel);
            result
        }),
    })
}

/// Consume one selected actual root and repair only that root's exact external
/// closure. Parallel donors prevent a blackholed first peer from spending the
/// healthy peer's whole original deadline. All destination bytes go through
/// the real checked immutable file+directory fsync path. The selected local
/// Raft generation, full root/enrollment/leader/term remain STRICTLY unchanged.
pub fn recover_native_v6_committed_closure(
    raft: &ProcessRaftNode,
    runtime: &Handle,
    transport: &MutualTlsPeerTransport,
    routes: &BTreeMap<u64, NodeId>,
    storage: &LocalV6BlobStage,
    selected: NativeV6CommittedRootRead,
) -> Result<RecoveredNativeV6LocalClosure, HaError> {
    require_blocking_worker()?;
    let deadline = selected.operation_deadline();
    check_deadline(deadline)?;
    runtime
        .block_on(raft.verify_native_v6_committed_root_read(&selected))
        .map_err(|_| unknown())?;
    let pins = selected.enrollment().pins();
    if !pins.contains_key(&raft.id())
        || routes.keys().copied().collect::<BTreeSet<_>>() != pins.keys().copied().collect()
        || routes.values().collect::<BTreeSet<_>>().len() != routes.len()
    {
        return Err(HaError::InvalidMembership);
    }
    let mut initial_gate = || {
        runtime
            .block_on(raft.verify_native_v6_committed_root_read(&selected))
            .map_err(|_| LocalV6BlobError::CorruptOrChanged)
    };
    if let Ok(references) = storage.reopen_root_closure(selected.root(), &mut initial_gate) {
        let fsynced = vec![false; references.len()];
        return finish_local(raft, runtime, storage, selected, &references, &fsynced);
    }
    runtime
        .block_on(raft.verify_native_v6_committed_root_read(&selected))
        .map_err(|_| unknown())?;
    let binding = RootBinding::observed(&selected);
    let count = usize::try_from(binding.intent.object_count).map_err(|_| HaError::InvalidFrame)?;
    if count == 0 || count > wire::MAX_OBJECTS {
        return Err(HaError::InvalidFrame);
    }
    let mut round = [0u8; 32];
    SystemRandom::new()
        .fill(&mut round)
        .map_err(|_| HaError::Transport)?;
    let mut references = Vec::with_capacity(count);
    let mut fsynced = vec![false; count];
    let mut pending = Vec::new();
    for (&target, route) in routes.iter().filter(|(id, _)| **id != raft.id()) {
        pending.push(pending_pull(
            transport,
            route,
            target,
            pins[&target],
            &binding,
            raft.id(),
            round,
            PullStep::Manifest(0),
            &references,
            deadline,
        )?);
    }
    loop {
        check_deadline(deadline)?;
        if pending.is_empty() {
            return Err(unknown());
        }
        let (index, result) = runtime.block_on(async {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                poll_fn(|cx| {
                    for (index, operation) in pending.iter_mut().enumerate() {
                        if let Poll::Ready(result) = operation.operation.as_mut().poll(cx) {
                            return Poll::Ready((index, result));
                        }
                    }
                    Poll::Pending
                }),
            )
            .await
            .map_err(|_| unknown())
        })?;
        let completed = pending.swap_remove(index);
        let target = completed.target;
        let step = completed.step;
        drop(completed);
        let Ok(response) = result else {
            continue;
        };
        check_deadline(deadline)?;
        let next = match step {
            PullStep::Manifest(expected_offset) => {
                let (offset, page) = wire::parse_manifest_page(&response.payload)?;
                let end = offset
                    .checked_add(page.len())
                    .ok_or(HaError::InvalidFrame)?;
                if offset != expected_offset || end > count {
                    return Err(HaError::InvalidFrame);
                }
                if offset < references.len() {
                    if references.get(offset..end) != Some(page.as_slice()) {
                        return Err(HaError::InvalidFrame);
                    }
                } else if offset == references.len() {
                    if references
                        .last()
                        .is_some_and(|last: &RecordObjectRef| last.id >= page[0].id)
                    {
                        return Err(HaError::InvalidFrame);
                    }
                    references.extend(page);
                } else {
                    return Err(HaError::InvalidFrame);
                }
                if references.len() == count {
                    wire::exact_manifest(&references, &binding.intent)?;
                    PullStep::Object(0)
                } else {
                    PullStep::Manifest(end)
                }
            }
            PullStep::Object(index) => {
                let reference = references.get(index).ok_or(HaError::InvalidFrame)?;
                if response.payload.len() != reference.encoded_bytes as usize {
                    return Err(HaError::InvalidFrame);
                }
                let fresh = fresh_same(raft, runtime, &selected)?;
                let mut gate = || {
                    runtime
                        .block_on(raft.verify_native_v6_committed_root_read(&fresh))
                        .map_err(|_| LocalV6BlobError::CorruptOrChanged)
                };
                storage
                    .stage_received_replica_checked(reference, &response.payload, &mut gate)
                    .map_err(|_| unknown())?;
                gate().map_err(|_| unknown())?;
                fsynced[index] = true;
                PullStep::Object(0)
            }
        };
        drop(response);
        // Keep fsync/consensus work outside an entered Tokio runtime. Socket
        // workers own no borrowed Raft, storage, Service or Actor handle.
        if references.len() == count {
            if let Some(index) = fsynced.iter().position(|done| !done) {
                pending.push(pending_pull(
                    transport,
                    &routes[&target],
                    target,
                    pins[&target],
                    &binding,
                    raft.id(),
                    round,
                    PullStep::Object(index),
                    &references,
                    deadline,
                )?);
            } else {
                drop(pending);
                return finish_local(raft, runtime, storage, selected, &references, &fsynced);
            }
        } else {
            pending.push(pending_pull(
                transport,
                &routes[&target],
                target,
                pins[&target],
                &binding,
                raft.id(),
                round,
                next,
                &references,
                deadline,
            )?);
        }
    }
}
