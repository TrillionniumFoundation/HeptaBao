//! One selected native snapshot peer; no HA control guard crosses network I/O.
//! Listener custody still uses the existing forwarding semaphore and workers.
use super::*;
use heptabao_ha_service::{
    AuthenticatedSnapshotPeer, SnapshotBodyLimits, SnapshotPeerRequest, SnapshotPeerResponse,
};

pub(crate) type SnapshotForwardHandler =
    Arc<dyn for<'a> Fn(SnapshotIngress<'a>) -> Result<(), heptabao_ha_service::HaError> + Send + Sync>;

/// Only the real listener's enrolled NodeId mapping constructs this owner.
pub(crate) struct SnapshotIngress<'a> {
    peer: AuthenticatedSnapshotPeer<'a>,
    cluster: String,
    source: u64,
    target: u64,
}
impl<'a> SnapshotIngress<'a> {
    pub(crate) fn cluster(&self) -> &str { &self.cluster }
    pub(crate) fn source(&self) -> u64 { self.source }
    pub(crate) fn target(&self) -> u64 { self.target }
    pub(crate) fn peer(&self) -> &AuthenticatedSnapshotPeer<'_> { &self.peer }
    pub(crate) fn into_peer(self) -> AuthenticatedSnapshotPeer<'a> { self.peer }
}

pub(super) fn dispatch<'a>(
    peer: AuthenticatedSnapshotPeer<'a>,
    ids: &BTreeMap<NodeId, u64>,
    cluster: &str,
    local: u64,
    slots: &Arc<Semaphore>,
    handler: &Arc<Mutex<Option<SnapshotForwardHandler>>>,
) -> Result<(), heptabao_ha_service::HaError> {
    let source = *ids.get(peer.peer()).ok_or(heptabao_ha_service::HaError::UnknownPeer)?;
    if source == local || cluster.is_empty() {
        return Err(heptabao_ha_service::HaError::PeerAuthenticationFailed);
    }
    // No new thread or detached task. The original peer worker and capacity
    // permit live until the complete body/response and callback have returned.
    let _permit = slots.clone().try_acquire_owned()
        .map_err(|_| heptabao_ha_service::HaError::WriterBusy)?;
    let callback = handler.lock()
        .map_err(|_| heptabao_ha_service::HaError::Transport)?
        .clone().ok_or(heptabao_ha_service::HaError::NotLeader)?;
    callback(SnapshotIngress {
        peer,
        cluster: cluster.to_owned(),
        source,
        target: local,
    })
}

/// A routing/data capability, never an Actor or native completion proof.
/// Its owned clone of the TLS configuration permits I/O after the HaProcess
/// mutex has been released. A new leader observation cannot retarget it.
pub(crate) struct SnapshotEndpoint {
    transport: MutualTlsPeerTransport,
    node: NodeId,
    pins: Vec<[u8; 32]>,
    cluster: String,
    source: u64,
    target: u64,
    deadline: Instant,
}
impl SnapshotEndpoint {
    pub(crate) fn cluster(&self) -> &str { &self.cluster }
    pub(crate) fn source(&self) -> u64 { self.source }
    pub(crate) fn target(&self) -> u64 { self.target }
    pub(crate) fn deadline(&self) -> Instant { self.deadline }

    pub(crate) fn exchange(
        self,
        metadata: &[u8],
        upload: &mut impl Read,
        response: &mut crate::snapshot_file::SnapshotFile,
        limits: (SnapshotBodyLimits, SnapshotBodyLimits),
        admission: impl FnOnce(&[u8]) -> Result<(), heptabao_ha_service::HaError>,
    ) -> Result<SnapshotPeerResponse, heptabao_ha_service::HaError> {
        let request = SnapshotPeerRequest::new(metadata, &self.pins, limits, self.deadline)?;
        self.transport.exchange_snapshot_before(
            &self.node, request, upload, response, admission,
        )
    }
}

impl HaProcess {
    pub(crate) fn register_snapshot_forward_handler(
        &mut self,
        handler: SnapshotForwardHandler,
    ) -> Result<(), String> {
        if !self.native_v6_enabled() {
            return Err("snapshot peer handler requires native HA".into());
        }
        let mut slot = self.snapshot_forward_handler.lock()
            .map_err(|_| "snapshot peer registry unavailable".to_owned())?;
        if slot.is_some() {
            return Err("snapshot peer handler already registered".into());
        }
        *slot = Some(handler);
        Ok(())
    }

    pub(crate) fn snapshot_endpoint_before(
        &self,
        original_deadline: Instant,
    ) -> Result<SnapshotEndpoint, String> {
        if !self.native_v6_enabled() || self.emit_legacy_peer_v1 {
            return Err("native snapshot peer profile unavailable".into());
        }
        let status = self.leader_status()?;
        let source = status.local_id;
        let target = status.leader.ok_or("native snapshot leader unavailable")?;
        if source == target {
            return Err("snapshot forwarding target is local".into());
        }
        let deadline = original_deadline.min(Instant::now() + self.forward_timeout);
        if Instant::now() >= deadline {
            return Err("snapshot forwarding deadline elapsed".into());
        }
        let node = self.peers.get(&target).ok_or("snapshot leader not enrolled")?.clone();
        let pins = self.snapshot_server_pins.get(&target)
            .ok_or("snapshot leader leaf pin unavailable")?.clone();
        Ok(SnapshotEndpoint {
            transport: self.forward_transport.clone(),
            node,
            pins,
            cluster: self.cluster_id.clone(),
            source,
            target,
            deadline,
        })
    }

    /// This is the same committed-prefix relationship as ordinary completion,
    /// without importing its JSON/ack-only/retained-KV receipt type.
    pub(crate) fn wait_snapshot_prefix(
        &self,
        cluster: &str,
        source: u64,
        target: u64,
        prefix: &heptabao_raft_runtime::CommittedApplicationPrefix,
        deadline: Instant,
    ) -> Result<(), String> {
        if cluster != self.cluster_id
            || target != self.local_id()?
            || source == target
            || !self.enrolled(source)
            || !prefix.valid()
        {
            return Err("native snapshot completed owner differs".into());
        }
        loop {
            if Instant::now() >= deadline {
                return Err("native snapshot original deadline elapsed".into());
            }
            let seen = self.leader_status()?;
            if seen.committed_index.is_some_and(|index| index >= prefix.index())
                && seen.applied_index.is_some_and(|index| index >= prefix.index())
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(5)
                .min(deadline.saturating_duration_since(Instant::now())));
        }
    }
}
