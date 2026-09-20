use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::OpenOptions;
use std::io::{BufReader, Read};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::future::BoxFuture;
use heptabao_ha_service::{
    MutualTlsPeerTransport, NodeId, PinnedClientCertificateMap, RAFT_ALPN_PROTOCOL,
    TlsPeerEndpoint, serve_one_mtls_peer_frame,
};
use heptabao_raft_runtime::{
    CommitReceipt, ProcessRaftNode, RaftPeerRpc, RaftRpcKind, RemoteNetworkFactory,
    RemoteRaftError, ReplicatedEnvelope,
};
use ring::digest;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::Deserialize;
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::{
    Response,
    ha_forward::{
        ForwardRequest, decode_request_for_cluster as decode_forward_request,
        decode_response_for_cluster as decode_forward_response,
        encode_request_for_cluster as encode_forward_request,
        encode_response_for_cluster as encode_forward_response, encode_wrapped_request_for_cluster,
        is_forward_request,
    },
    ha_state::{
        ClusterStateCodec, CommittedStateDescriptor, MAX_REPLICATED_STATE_CHUNKS,
        REPLICATED_STATE_CHUNK_BYTES, ReplicatedChunkRef, ReplicatedStateManifest,
    },
    service::OwnerPublicationBinding,
};

const RAFT_FRAME_MAGIC: &[u8; 5] = b"HBRT1";
const RAFT_FRAME_REQUEST: u8 = 1;
const RAFT_FRAME_RESPONSE: u8 = 2;
const RAFT_FRAME_HEADER_BYTES: usize = 29;
const MAX_CLUSTER_ID_BYTES: usize = 128;
const MAX_RAFT_FRAME_BYTES: usize = 896 * 1024;
const MAX_TLS_FILE_BYTES: usize = 1024 * 1024;
const REPLICATION_KEY_BYTES: usize = 32;
const REPLICATED_CHUNK_MIN_BYTES: usize = 192 * 1024;
const REPLICATED_CHUNK_WINDOW_BYTES: usize = 64;
const REPLICATED_CHUNK_MASK: u64 = (1_u64 << 18) - 1;

type MutualTlsConfigs = (Arc<ClientConfig>, Arc<ServerConfig>, [u8; 32]);
pub(crate) type ForwardHandler = Arc<dyn Fn(ForwardRequest) -> Response + Send + Sync>;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HaPeerConfig {
    pub node_name: String,
    pub address: SocketAddr,
    pub server_name: String,
    pub certificate_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HaProcessConfig {
    pub node_id: u64,
    pub cluster_id: String,
    pub raft_dir: PathBuf,
    pub listen: SocketAddr,
    pub ca_file: PathBuf,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub replication_key_file: PathBuf,
    pub peers: BTreeMap<u64, HaPeerConfig>,
    #[serde(default)]
    pub bootstrap: bool,
    /// Initial voters may be a subset of the statically enrolled peer registry.
    #[serde(default)]
    pub initial_voters: Option<BTreeSet<u64>>,
    #[serde(default = "default_peer_timeout_ms")]
    pub peer_timeout_ms: u64,
    #[serde(default = "default_max_inflight")]
    pub max_inflight: usize,
}

fn default_peer_timeout_ms() -> u64 {
    750
}

fn default_max_inflight() -> usize {
    64
}

struct ParsedPeer {
    id: u64,
    node: NodeId,
    endpoint: TlsPeerEndpoint,
    certificate_sha256: [u8; 32],
}

#[derive(Clone)]
struct MutualTlsRaftRpc {
    local_id: u64,
    cluster_id: String,
    peers: Arc<BTreeMap<u64, NodeId>>,
    transport: MutualTlsPeerTransport,
    inflight: Arc<Semaphore>,
}

impl fmt::Debug for MutualTlsRaftRpc {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MutualTlsRaftRpc")
            .field("local_id", &self.local_id)
            .field("cluster_id", &self.cluster_id)
            .field("peers", &self.peers.keys().collect::<Vec<_>>())
            .field("transport", &"[MUTUAL_TLS]")
            .finish()
    }
}

impl RaftPeerRpc for MutualTlsRaftRpc {
    fn exchange(
        &self,
        source: u64,
        target: u64,
        kind: RaftRpcKind,
        payload: Vec<u8>,
        timeout: Duration,
    ) -> BoxFuture<'static, Result<Vec<u8>, RemoteRaftError>> {
        let local_id = self.local_id;
        let cluster_id = self.cluster_id.clone();
        let target_node = self.peers.get(&target).cloned();
        let transport = self.transport.clone();
        let inflight = self.inflight.clone();
        Box::pin(async move {
            if source != local_id || source == target || timeout.is_zero() {
                return Err(RemoteRaftError::InvalidRpc);
            }
            let target_node = target_node.ok_or(RemoteRaftError::InvalidTopology)?;
            let request = encode_raft_frame(RaftWireFrame {
                cluster_id: cluster_id.clone(),
                role: RAFT_FRAME_REQUEST,
                source,
                target,
                kind,
                payload,
            })?;
            let permit = tokio::time::timeout(timeout, inflight.acquire_owned())
                .await
                .map_err(|_| RemoteRaftError::Transport("peer RPC admission timed out".into()))?
                .map_err(|_| RemoteRaftError::Transport("peer RPC admission closed".into()))?;
            let work = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                transport
                    .exchange(&target_node, &request)
                    .map_err(|error| RemoteRaftError::Transport(error.to_string()))
            });
            let response = tokio::time::timeout(timeout, work)
                .await
                .map_err(|_| RemoteRaftError::Transport("peer RPC timed out".into()))?
                .map_err(|error| RemoteRaftError::Transport(error.to_string()))??;
            let response = decode_raft_frame_for_cluster(&response, &cluster_id)?;
            if response.role != RAFT_FRAME_RESPONSE
                || response.source != target
                || response.target != source
                || response.kind != kind
            {
                return Err(RemoteRaftError::InvalidRpc);
            }
            Ok(response.payload)
        })
    }
}

#[derive(Debug)]
struct RaftWireFrame {
    cluster_id: String,
    role: u8,
    source: u64,
    target: u64,
    kind: RaftRpcKind,
    payload: Vec<u8>,
}

// Fixed workers bound inbound TLS memory and keep a forwarded client request
// from monopolizing the only receiver of Raft votes and append messages.
struct PeerListener {
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl Drop for PeerListener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

/// Opaque evidence issued only after complete chunk authentication and hashing.
/// It is process-local, contains no plaintext state and is never serialized.
#[derive(Clone)]
pub(crate) struct ValidatedReadCursor {
    generation: u64,
    envelope_identity: [u8; 32],
}

pub(crate) enum CommittedStateRead {
    Absent,
    Unchanged,
    Materialized(CommittedApplicationState),
}

pub(crate) struct CommittedApplicationState {
    pub digest: [u8; 32],
    pub bytes: Zeroizing<Vec<u8>>,
    /// True only for the pre-manifest HBSR1 whole-state envelope.  HBSM2-
    /// HBSM4 are all manifest-backed, even when older manifests do not carry
    /// owner publication metadata, so callers must not infer this from the
    /// optional owner fields.
    pub legacy_whole_state: bool,
    pub read_cursor: Option<ValidatedReadCursor>,
    pub owner_manifest_digest: Option<[u8; 32]>,
    pub changed_owner_mask: Option<u8>,
}

pub struct HaProcess {
    runtime: Runtime,
    node: Option<ProcessRaftNode>,
    codec: ClusterStateCodec,
    cluster_id: String,
    peers: Arc<BTreeMap<u64, NodeId>>,
    forward_transport: MutualTlsPeerTransport,
    forward_handler: Arc<Mutex<Option<ForwardHandler>>>,
    listener: Option<PeerListener>,
}

impl fmt::Debug for HaProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HaProcess")
            .field("cluster_id", &self.cluster_id)
            .field("running", &self.node.is_some())
            .field("listener", &self.listener.is_some())
            .finish()
    }
}

impl HaProcess {
    pub fn start(config: HaProcessConfig) -> Result<Self, String> {
        validate_config(&config)?;
        let replication_key = load_replication_key(&config.replication_key_file)?;
        let codec = ClusterStateCodec::new(config.cluster_id.clone(), replication_key)
            .map_err(|error| error.to_string())?;
        let parsed_peers = parse_peers(&config)?;
        let peer_ids = parsed_peers
            .iter()
            .map(|peer| peer.id)
            .collect::<BTreeSet<_>>();
        let nodes_by_id = parsed_peers
            .iter()
            .map(|peer| (peer.id, peer.node.clone()))
            .collect::<BTreeMap<_, _>>();
        let ids_by_node = parsed_peers
            .iter()
            .map(|peer| (peer.node.clone(), peer.id))
            .collect::<BTreeMap<_, _>>();
        let endpoint_map = parsed_peers
            .iter()
            .filter(|peer| peer.id != config.node_id)
            .map(|peer| (peer.node.clone(), peer.endpoint.clone()))
            .collect::<BTreeMap<_, _>>();
        let pinned = parsed_peers
            .iter()
            .filter(|peer| peer.id != config.node_id)
            .map(|peer| (peer.certificate_sha256, peer.node.clone()))
            .collect::<BTreeMap<_, _>>();
        let timeout = Duration::from_millis(config.peer_timeout_ms);
        let (client_tls, server_tls, local_leaf_digest) = build_mutual_tls(&config)?;
        let local = parsed_peers
            .iter()
            .find(|peer| peer.id == config.node_id)
            .ok_or_else(|| "HA local node is missing from peer registry".to_owned())?;
        if local.certificate_sha256 != local_leaf_digest {
            return Err("HA local certificate digest does not match peer registry".into());
        }
        let transport = MutualTlsPeerTransport::new(endpoint_map, client_tls, timeout)
            .map_err(|error| error.to_string())?;
        let peers = Arc::new(nodes_by_id);
        let rpc = Arc::new(MutualTlsRaftRpc {
            local_id: config.node_id,
            cluster_id: config.cluster_id.clone(),
            peers: peers.clone(),
            transport: transport.clone(),
            inflight: Arc::new(Semaphore::new(config.max_inflight)),
        });
        let network = RemoteNetworkFactory::new(config.node_id, peer_ids.clone(), rpc)
            .map_err(|error| error.to_string())?;
        let runtime = RuntimeBuilder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .build()
            .map_err(|error| error.to_string())?;
        let existing = durable_state_exists(&config.raft_dir)?;
        let node = if existing {
            runtime
                .block_on(ProcessRaftNode::reopen(
                    &config.raft_dir,
                    config.node_id,
                    network,
                ))
                .map_err(|error| error.to_string())?
        } else {
            runtime
                .block_on(ProcessRaftNode::create(
                    &config.raft_dir,
                    config.node_id,
                    network,
                ))
                .map_err(|error| error.to_string())?
        };
        let rpc_service = node.rpc_service();
        let listener = TcpListener::bind(config.listen)
            .map_err(|_| "cannot bind HA peer listener".to_owned())?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "cannot configure HA peer listener".to_owned())?;
        let identities =
            PinnedClientCertificateMap::new(pinned).map_err(|error| error.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let listener = Arc::new(listener);
        let identities = Arc::new(identities);
        let ids_by_node = Arc::new(ids_by_node);
        let forward_handler: Arc<Mutex<Option<ForwardHandler>>> = Arc::new(Mutex::new(None));
        let forward_slots = Arc::new(Semaphore::new(1));
        let mut listener_pool = PeerListener {
            stop: stop.clone(),
            workers: Vec::new(),
        };
        let local_id = config.node_id;
        let cluster_id = config.cluster_id.clone();
        for worker_id in 0..config.max_inflight.clamp(4, 16) {
            let listener_stop = stop.clone();
            let listener = listener.clone();
            let identities = identities.clone();
            let ids_by_node = ids_by_node.clone();
            let server_tls = server_tls.clone();
            let rpc_service = rpc_service.clone();
            let runtime_handle = runtime.handle().clone();
            let listener_forward_handler = forward_handler.clone();
            let forward_slots = forward_slots.clone();
            let listener_cluster_id = cluster_id.clone();
            let worker = thread::Builder::new()
                .name(format!("heptabao-raft-peer-{local_id}-{worker_id}"))
                .spawn(move || {
                    while !listener_stop.load(Ordering::Acquire) {
                        let service = rpc_service.clone();
                        let ids = &ids_by_node;
                        let handle = &runtime_handle;
                        let result = serve_one_mtls_peer_frame(
                            &listener,
                            server_tls.clone(),
                            &identities,
                            timeout,
                            |peer, frame| {
                                let source = *ids
                                    .get(&peer)
                                    .ok_or(heptabao_ha_service::HaError::UnknownPeer)?;
                                if is_forward_request(&frame) {
                                    let request =
                                        decode_forward_request(&frame, &listener_cluster_id)
                                            .map_err(|_| {
                                                heptabao_ha_service::HaError::InvalidFrame
                                            })?;
                                    if request.source != source || request.target != local_id {
                                        return Err(
                                            heptabao_ha_service::HaError::PeerAuthenticationFailed,
                                        );
                                    }
                                    // At most one forward may await the public service mutex.
                                    // The remaining workers stay available to consensus traffic.
                                    let _forward_slot =
                                        forward_slots.clone().try_acquire_owned().map_err(
                                            |_| heptabao_ha_service::HaError::WriterBusy,
                                        )?;
                                    let handler = listener_forward_handler
                                        .lock()
                                        .map_err(|_| heptabao_ha_service::HaError::Transport)?
                                        .clone()
                                        .ok_or(heptabao_ha_service::HaError::NotLeader)?;
                                    let response = handler(request);
                                    return encode_forward_response(
                                        &listener_cluster_id,
                                        local_id,
                                        source,
                                        response.status,
                                        &response.body,
                                    )
                                    .map_err(|_| heptabao_ha_service::HaError::InvalidFrame);
                                }
                                let request =
                                    decode_raft_frame_for_cluster(&frame, &listener_cluster_id)
                                        .map_err(|_| heptabao_ha_service::HaError::InvalidFrame)?;
                                if request.role != RAFT_FRAME_REQUEST
                                    || request.source != source
                                    || request.target != local_id
                                {
                                    return Err(
                                        heptabao_ha_service::HaError::PeerAuthenticationFailed,
                                    );
                                }
                                let payload = handle
                                    .block_on(service.handle(source, request.kind, request.payload))
                                    .map_err(map_remote_service_error)?;
                                encode_raft_frame(RaftWireFrame {
                                    cluster_id: listener_cluster_id.clone(),
                                    role: RAFT_FRAME_RESPONSE,
                                    source: local_id,
                                    target: source,
                                    kind: request.kind,
                                    payload,
                                })
                                .map_err(|_| heptabao_ha_service::HaError::InvalidFrame)
                            },
                        );
                        if result.is_err() {
                            thread::sleep(Duration::from_millis(2));
                        }
                    }
                })
                .map_err(|_| "cannot start bounded HA peer worker".to_owned())?;
            listener_pool.workers.push(worker);
        }

        if !existing && config.bootstrap {
            runtime
                .block_on(node.initialize_single())
                .map_err(|error| error.to_string())?;
            runtime.block_on(async {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                loop {
                    if node.current_leader().await == Some(config.node_id) {
                        break Ok::<(), String>(());
                    }
                    if tokio::time::Instant::now() >= deadline {
                        break Err(
                            "HA bootstrap did not elect the local node before membership expansion"
                                .into(),
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })?;
            let voters = config.initial_voters.clone().unwrap_or(peer_ids);
            for peer_id in voters.iter().copied().filter(|id| *id != config.node_id) {
                runtime
                    .block_on(node.add_learner(peer_id))
                    .map_err(|error| error.to_string())?;
            }
            runtime
                .block_on(node.change_membership(voters))
                .map_err(|error| error.to_string())?;
        }

        Ok(Self {
            runtime,
            node: Some(node),
            codec,
            cluster_id: config.cluster_id,
            peers,
            forward_transport: transport,
            forward_handler,
            listener: Some(listener_pool),
        })
    }

    pub(crate) fn register_forward_handler(
        &mut self,
        handler: ForwardHandler,
    ) -> Result<(), String> {
        let mut slot = self
            .forward_handler
            .lock()
            .map_err(|_| "HA forward handler registry is unavailable".to_owned())?;
        if slot.is_some() {
            return Err("HA forward handler is already registered".into());
        }
        *slot = Some(handler);
        Ok(())
    }

    // Forwarding preserves the existing wire tuple plus the verified client
    // chain; keep fields explicit so no identity is silently omitted.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn forward_request(
        &self,
        method: &str,
        path: &str,
        namespace: &str,
        token: &str,
        body: &serde_json::Value,
        wrap_ttl_seconds: Option<u64>,
        client_certificates: Option<&[Vec<u8>]>,
    ) -> Result<Response, String> {
        let local = self.local_id()?;
        let leader = self
            .leader()?
            .ok_or_else(|| "HA cluster has no elected leader".to_owned())?;
        if leader == local {
            return Err("HA forward request cannot target the local leader".into());
        }
        let target = self
            .peers
            .get(&leader)
            .ok_or_else(|| "HA elected leader is absent from peer registry".to_owned())?;
        let request = Zeroizing::new(match wrap_ttl_seconds {
            Some(ttl) => encode_wrapped_request_for_cluster(
                &self.cluster_id,
                (local, leader),
                method,
                path,
                namespace,
                token,
                body,
                ttl,
                client_certificates,
            )?,
            None => encode_forward_request(
                &self.cluster_id,
                local,
                leader,
                method,
                path,
                namespace,
                token,
                body,
                client_certificates,
            )?,
        });
        let response = zeroize::Zeroizing::new(
            self.forward_transport
                .exchange(target, &request)
                .map_err(|error| error.to_string())?,
        );
        let mut response = decode_forward_response(&response, &self.cluster_id)?;
        if response.source != leader || response.target != local {
            return Err("HA forward response direction is invalid".into());
        }
        Ok(Response {
            status: response.status,
            body: std::mem::take(&mut response.body),
        })
    }

    pub fn local_id(&self) -> Result<u64, String> {
        self.node
            .as_ref()
            .map(ProcessRaftNode::id)
            .ok_or_else(|| "HA process is shut down".into())
    }

    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    pub fn leader(&self) -> Result<Option<u64>, String> {
        let node = self
            .node
            .as_ref()
            .ok_or_else(|| "HA process is shut down".to_owned())?;
        Ok(self.runtime.block_on(node.current_leader()))
    }

    pub fn is_leader(&self) -> Result<bool, String> {
        let local_id = self.local_id()?;
        Ok(self.leader()? == Some(local_id))
    }

    /// Transfer leadership to another configured voter and wait until this node
    /// observes a different leader. A failed/unreachable target is tried once
    /// before the next configured peer; no client mutation is retried here.
    pub fn step_down(&self) -> Result<u64, String> {
        let node = self
            .node
            .as_ref()
            .ok_or_else(|| "HA process is shut down".to_owned())?;
        let local = node.id();
        if self.runtime.block_on(node.current_leader()) != Some(local) {
            return Err("HA step-down requires the current leader".into());
        }
        let membership = self
            .runtime
            .block_on(node.membership_observation())
            .map_err(|_| "membership unavailable")?;
        let targets: Vec<u64> = membership
            .voters
            .iter()
            .copied()
            .filter(|id| *id != local)
            .collect();
        if targets.is_empty() {
            return Err("HA cluster has no alternate voter".into());
        }
        self.runtime.block_on(async {
            for target in targets {
                if node.transfer_leadership(target).await.is_err() {
                    continue;
                }
                let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
                loop {
                    if let Some(leader) = node.current_leader().await
                        && leader != local
                    {
                        return Ok(leader);
                    }
                    if tokio::time::Instant::now() >= deadline {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }
            Err("HA leadership transfer did not complete".into())
        })
    }

    pub fn enrolled(&self, id: u64) -> bool {
        self.peers.contains_key(&id)
    }
    pub fn membership(&self) -> Result<heptabao_raft_runtime::MembershipObservation, String> {
        let node = self.node.as_ref().ok_or("HA stopped")?;
        self.ensure_linearizable()?;
        self.runtime
            .block_on(node.membership_observation())
            .map_err(|_| "membership observation failed".into())
    }
    pub fn modify_membership(
        &self,
        index: u64,
        id: u64,
        operation: &str,
    ) -> Result<heptabao_raft_runtime::MembershipObservation, String> {
        if !self.enrolled(id) {
            return Err("peer is not host-enrolled".into());
        }
        let node = self.node.as_ref().ok_or("HA stopped")?;
        self.runtime
            .block_on(node.change_membership_guarded(index, id, operation))
            .map_err(|_| "membership operation requires reconciliation".into())
    }
    pub fn observed_snapshot(&self) -> Result<heptabao_raft_runtime::SnapshotObservation, String> {
        let node = self.node.as_ref().ok_or("HA stopped")?;
        self.runtime
            .block_on(node.snapshot_observed())
            .map_err(|_| "snapshot completion unobserved".into())
    }

    pub fn ensure_linearizable(&self) -> Result<(), String> {
        let node = self
            .node
            .as_ref()
            .ok_or_else(|| "HA process is shut down".to_owned())?;
        self.runtime
            .block_on(node.ensure_linearizable())
            .map_err(|error| error.to_string())
    }

    /// Prove that the local process is observing the committed application
    /// generation identified by `expected_digest`.
    ///
    /// A successful ReadIndex only proves quorum authority; it does not prove
    /// that this process has applied the same application state after a
    /// restart, snapshot install, or leadership transfer.  Health and request
    /// admission use this stronger fence so a node cannot report an active
    /// authority while serving a stale local state image.
    pub(crate) fn ensure_application_digest(
        &self,
        expected_digest: [u8; 32],
    ) -> Result<(), String> {
        if expected_digest == [0; 32] {
            return Err("HA application digest is not initialized".into());
        }
        let node = self
            .node
            .as_ref()
            .ok_or_else(|| "HA process is shut down".to_owned())?;
        self.runtime
            .block_on(node.ensure_linearizable())
            .map_err(|error| error.to_string())?;
        let committed = self
            .runtime
            .block_on(node.latest_envelope())
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "HA application state has not been committed".to_owned())?;
        if committed.digest() != expected_digest {
            return Err("HA application state is not converged on the committed digest".into());
        }
        Ok(())
    }

    pub fn trigger_snapshot(&self) -> Result<(), String> {
        let node = self
            .node
            .as_ref()
            .ok_or_else(|| "HA process is shut down".to_owned())?;
        self.runtime
            .block_on(node.snapshot_observed())
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Replicate the next authoritative application state with a manifest as
    /// the sole publication point. HBSM3 separates logical chunk order from the
    /// bounded physical Raft chunk index so content-defined boundaries can reuse
    /// authenticated chunks after insertions/deletions instead of shifting every
    /// later fixed chunk. HBSM4 additionally carries the authenticated local
    /// owner-plan digest and changed-owner mask, so the record-oriented local
    /// delta cannot be replaced by an opaque whole-state fallback at the HA
    /// boundary. New chunks are staged into an unreferenced index/slot; the
    /// production manifest remains the only publication point.
    pub(crate) fn commit_state_with_owner_binding(
        &self,
        operation_id: &str,
        expected_base_digest: [u8; 32],
        bytes: &[u8],
        binding: OwnerPublicationBinding,
    ) -> Result<CommitReceipt, String> {
        validate_owner_binding(operation_id, bytes, binding)?;
        self.commit_state_inner(
            operation_id,
            expected_base_digest,
            bytes,
            Some((
                binding.owner_manifest_digest(),
                binding.changed_owner_mask(),
            )),
            false,
        )
    }

    /// Explicitly promote an HBSR1 whole-state envelope to an owner-bound
    /// HBSM4 manifest.  This is intentionally separate from ordinary state
    /// mutation: the latter must remain fail-closed until an operator invokes
    /// the authenticated migration route.
    pub(crate) fn commit_legacy_owner_migration_with_binding(
        &self,
        operation_id: &str,
        expected_base_digest: [u8; 32],
        bytes: &[u8],
        binding: OwnerPublicationBinding,
    ) -> Result<CommitReceipt, String> {
        validate_owner_binding(operation_id, bytes, binding)?;
        self.commit_state_inner(
            operation_id,
            expected_base_digest,
            bytes,
            Some((
                binding.owner_manifest_digest(),
                binding.changed_owner_mask(),
            )),
            true,
        )
    }

    pub fn commit_state(
        &self,
        operation_id: &str,
        expected_base_digest: [u8; 32],
        bytes: &[u8],
    ) -> Result<CommitReceipt, String> {
        self.commit_state_inner(operation_id, expected_base_digest, bytes, None, false)
    }

    fn commit_state_inner(
        &self,
        operation_id: &str,
        expected_base_digest: [u8; 32],
        bytes: &[u8],
        owner_binding: Option<([u8; 32], u8)>,
        allow_legacy_migration: bool,
    ) -> Result<CommitReceipt, String> {
        if bytes.is_empty() || bytes.len() > crate::MAX_APPLICATION_STATE_BYTES {
            return Err("HA application state is empty or exceeds the shared bound".into());
        }
        let node = self
            .node
            .as_ref()
            .ok_or_else(|| "HA process is shut down".to_owned())?;
        let local_id = node.id();
        let leader = self
            .runtime
            .block_on(node.current_leader())
            .ok_or_else(|| "HA cluster has no elected leader".to_owned())?;
        if leader != local_id {
            return Err(format!("HA write requires current leader node {leader}"));
        }
        self.runtime
            .block_on(node.ensure_linearizable())
            .map_err(|error| error.to_string())?;
        let latest = self
            .runtime
            .block_on(node.latest_envelope())
            .map_err(|error| error.to_string())?;
        if let Some(envelope) = latest.as_ref()
            && envelope.digest() != expected_base_digest
        {
            return Err("HA application base conflicts with latest committed state".into());
        }
        if allow_legacy_migration && latest.is_none() {
            return Err("legacy owner-manifest migration requires an HBSR1 base state".into());
        }

        let previous_manifest = match latest.as_ref() {
            None => None,
            Some(envelope) => {
                let descriptor = self
                    .codec
                    .open_committed_descriptor(
                        envelope.operation_id(),
                        envelope.digest(),
                        envelope.sealed(),
                    )
                    .map_err(|error| error.to_string())?;
                if allow_legacy_migration {
                    validate_legacy_migration_base(&descriptor, owner_binding.is_some())?;
                } else {
                    reject_legacy_mutation_fallback(&descriptor)?;
                }
                match descriptor {
                    CommittedStateDescriptor::Legacy(state) => {
                        if sha256(&state) != envelope.digest() {
                            return Err("legacy HA state digest readback failed".into());
                        }
                        None
                    }
                    CommittedStateDescriptor::Chunked(manifest) => Some(manifest),
                }
            }
        };

        let plans = plan_replicated_chunks(bytes, previous_manifest.as_ref())?;
        let mut refs = Vec::with_capacity(plans.len());
        for plan in plans {
            let reference = plan.reference.clone();
            if plan.reused {
                let staged = self
                    .runtime
                    .block_on(node.application_chunk_envelope(reference.index, reference.slot))
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "HA committed manifest references a missing chunk".to_owned())?;
                if staged.digest() != reference.digest {
                    return Err("HA committed chunk digest metadata is inconsistent".into());
                }
                let opened = self
                    .codec
                    .open_chunk_parts(
                        reference.index,
                        reference.slot,
                        staged.operation_id(),
                        staged.digest(),
                        staged.sealed(),
                    )
                    .map_err(|error| error.to_string())?;
                if opened.as_slice() != plan.bytes
                    || opened.len() != usize::try_from(reference.bytes).unwrap_or(usize::MAX)
                    || sha256(&opened) != reference.digest
                {
                    return Err("HA committed reusable chunk failed authenticated readback".into());
                }
            } else {
                let chunk_operation =
                    chunk_operation_id(operation_id, reference.index, reference.slot);
                let proposal = self
                    .codec
                    .seal_chunk(
                        chunk_operation.clone(),
                        reference.index,
                        reference.slot,
                        plan.bytes,
                    )
                    .map_err(|error| error.to_string())?;
                let envelope = ReplicatedEnvelope::new(
                    proposal.operation_id().to_owned(),
                    proposal.digest(),
                    proposal.sealed().to_vec(),
                )
                .map_err(|error| error.to_string())?;
                let serial = self
                    .runtime
                    .block_on(node.next_production_client_serial())
                    .map_err(|error| error.to_string())?;
                let receipt = self
                    .runtime
                    .block_on(node.replicate_application_chunk(
                        reference.index,
                        reference.slot,
                        serial,
                        &envelope,
                    ))
                    .map_err(|error| error.to_string())?;
                if receipt.leader_id != local_id || receipt.envelope_digest != reference.digest {
                    return Err("HA chunk commit receipt did not bind the staged payload".into());
                }
            }
            refs.push(reference);
        }

        let proposal = match owner_binding {
            Some((owner_manifest_digest, changed_owner_mask)) => self
                .codec
                .seal_manifest_with_owner_binding(
                    operation_id.to_owned(),
                    expected_base_digest,
                    bytes,
                    refs,
                    owner_manifest_digest,
                    changed_owner_mask,
                )
                .map_err(|error| error.to_string())?,
            None => self
                .codec
                .seal_manifest(operation_id.to_owned(), expected_base_digest, bytes, refs)
                .map_err(|error| error.to_string())?,
        };
        let envelope = ReplicatedEnvelope::new(
            proposal.operation_id().to_owned(),
            proposal.digest(),
            proposal.sealed().to_vec(),
        )
        .map_err(|error| error.to_string())?;
        let serial = self
            .runtime
            .block_on(node.next_production_client_serial())
            .map_err(|error| error.to_string())?;
        let receipt = self
            .runtime
            .block_on(node.replicate(serial, &envelope))
            .map_err(|error| error.to_string())?;
        if receipt.leader_id != local_id || receipt.envelope_digest != proposal.digest() {
            return Err("HA commit receipt did not bind the submitted application manifest".into());
        }
        Ok(receipt)
    }

    /// Return the newest complete application state after a linearizable
    /// ReadIndex. HBSR1 whole-state envelopes and HBSM2 fixed-position manifests
    /// remain readable for online upgrade; HBSM3/HBSM4 resolve ordered logical
    /// chunks through authenticated position-independent physical index/slot
    /// references. HBSM4 also validates the owner-delta identity carried by the
    /// service publication binding.
    pub(crate) fn latest_committed_state(
        &self,
    ) -> Result<Option<CommittedApplicationState>, String> {
        match self.latest_committed_state_if_changed(None)? {
            CommittedStateRead::Absent => Ok(None),
            CommittedStateRead::Materialized(state) => Ok(Some(state)),
            CommittedStateRead::Unchanged => {
                Err("HA read reused an absent verification cursor".into())
            }
        }
    }

    pub(crate) fn latest_committed_state_if_changed(
        &self,
        known: Option<&ValidatedReadCursor>,
    ) -> Result<CommittedStateRead, String> {
        let node = self
            .node
            .as_ref()
            .ok_or_else(|| "HA process is shut down".to_owned())?;
        read_committed_application(
            &self.codec,
            known,
            || {
                self.runtime
                    .block_on(node.ensure_linearizable())
                    .map_err(|error| error.to_string())
            },
            || {
                self.runtime
                    .block_on(node.latest_envelope_at_generation())
                    .map_err(|error| error.to_string())
            },
            |index, slot| {
                self.runtime
                    .block_on(node.application_chunk_envelope(index, slot))
                    .map_err(|error| error.to_string())
            },
            || self.runtime.block_on(node.application_state_generation()),
        )
    }
}

/// Keep ReadIndex and manifest authentication ahead of every reuse decision.
/// The narrow callbacks also let tests prove that a warm read never loads chunks
/// and that authority loss or a changed mutable slot still fails closed.
fn read_committed_application(
    codec: &ClusterStateCodec,
    known: Option<&ValidatedReadCursor>,
    read_index: impl FnOnce() -> Result<(), String>,
    latest: impl FnOnce() -> Result<(u64, Option<ReplicatedEnvelope>), String>,
    mut load_chunk: impl FnMut(u16, u8) -> Result<Option<ReplicatedEnvelope>, String>,
    current_generation: impl FnOnce() -> u64,
) -> Result<CommittedStateRead, String> {
    read_index()?;
    let (generation, Some(envelope)) = latest()? else {
        return Ok(CommittedStateRead::Absent);
    };
    let descriptor = codec
        .open_committed_descriptor(
            envelope.operation_id(),
            envelope.digest(),
            envelope.sealed(),
        )
        .map_err(|error| error.to_string())?;
    let identity = manifest_envelope_identity(&envelope);
    let (bytes, legacy_whole_state, owner_manifest_digest, changed_owner_mask) = match descriptor {
        CommittedStateDescriptor::Legacy(bytes) => (bytes, true, None, None),
        CommittedStateDescriptor::Chunked(manifest) => {
            if manifest.state_digest != envelope.digest() {
                return Err("HA manifest digest does not match production envelope".into());
            }
            // Only owner-bound HBSM4 has a local canonical publication identity
            // that Service can bind to admitted durable state before reusing.
            if manifest.owner_manifest_digest.is_some()
                && known.is_some_and(|cursor| {
                    cursor.generation == generation && cursor.envelope_identity == identity
                })
            {
                return Ok(CommittedStateRead::Unchanged);
            }
            let total = usize::try_from(manifest.total_bytes)
                .map_err(|_| "HA manifest total length overflow".to_owned())?;
            let mut assembled = Zeroizing::new(Vec::with_capacity(total));
            for chunk in &manifest.chunks {
                let staged = load_chunk(chunk.index, chunk.slot)?.ok_or_else(|| {
                    "HA manifest references an unavailable committed chunk".to_owned()
                })?;
                if staged.digest() != chunk.digest {
                    return Err("HA manifest/chunk digest binding mismatch".into());
                }
                let opened = codec
                    .open_chunk_parts(
                        chunk.index,
                        chunk.slot,
                        staged.operation_id(),
                        staged.digest(),
                        staged.sealed(),
                    )
                    .map_err(|error| error.to_string())?;
                if opened.len()
                    != usize::try_from(chunk.bytes)
                        .map_err(|_| "HA chunk length overflow".to_owned())?
                {
                    return Err("HA committed chunk length mismatch".into());
                }
                assembled.extend_from_slice(&opened);
                if assembled.len() > total {
                    return Err("HA committed chunk set exceeds manifest length".into());
                }
            }
            if assembled.len() != total || sha256(&assembled) != manifest.state_digest {
                return Err("HA committed chunk set does not reconstruct manifest state".into());
            }
            (
                assembled,
                false,
                manifest.owner_manifest_digest,
                manifest.changed_owner_mask,
            )
        }
    };
    if sha256(&bytes) != envelope.digest() {
        return Err("HA committed application digest readback failed".into());
    }
    // An apply or snapshot during materialization invalidates the observation,
    // even if it left the publication envelope itself untouched. Do not issue
    // evidence spanning that mutation; the next read can validate it afresh.
    let read_cursor = (owner_manifest_digest.is_some() && current_generation() == generation)
        .then_some(ValidatedReadCursor {
            generation,
            envelope_identity: identity,
        });
    Ok(CommittedStateRead::Materialized(
        CommittedApplicationState {
            digest: envelope.digest(),
            bytes,
            legacy_whole_state,
            owner_manifest_digest,
            changed_owner_mask,
            read_cursor,
        },
    ))
}

fn manifest_envelope_identity(envelope: &ReplicatedEnvelope) -> [u8; 32] {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(b"heptabao-verified-ha-manifest-v1");
    context.update(&(envelope.operation_id().len() as u64).to_be_bytes());
    context.update(envelope.operation_id().as_bytes());
    context.update(&envelope.digest());
    context.update(&(envelope.sealed().len() as u64).to_be_bytes());
    context.update(envelope.sealed());
    let mut result = [0; 32];
    result.copy_from_slice(context.finish().as_ref());
    result
}

impl Drop for HaProcess {
    fn drop(&mut self) {
        drop(self.listener.take());
        if let Some(node) = self.node.take() {
            let _ = self.runtime.block_on(node.shutdown());
        }
    }
}

fn validate_config(config: &HaProcessConfig) -> Result<(), String> {
    if !valid_cluster_id(&config.cluster_id) {
        return Err("invalid HA cluster identity".into());
    }
    if config.initial_voters.as_ref().is_some_and(|v| {
        v.len() < 3
            || v.len() > 9
            || v.iter().any(|id| !config.peers.contains_key(id))
            || config.bootstrap && !v.contains(&config.node_id)
    }) {
        return Err("invalid initial voter subset".into());
    }
    if config.node_id == 0
        || config.peers.len() < 3
        || config.peers.len() > 9
        || !config.peers.contains_key(&config.node_id)
        // A zero listener port asks the OS to choose an ephemeral endpoint.
        // Peer addresses are statically enrolled, so allowing that choice can
        // leave a node listening on an address no peer can reach after a
        // restart.  Outbound peer endpoints have the same bound in
        // `TlsPeerEndpoint::new`.
        || config.listen.port() == 0
        || !(50..=5_000).contains(&config.peer_timeout_ms)
        || !(4..=256).contains(&config.max_inflight)
        || !config.raft_dir.is_absolute()
        || !config.ca_file.is_absolute()
        || !config.cert_file.is_absolute()
        || !config.key_file.is_absolute()
        || !config.replication_key_file.is_absolute()
        || config.ca_file.starts_with(&config.raft_dir)
        || config.cert_file.starts_with(&config.raft_dir)
        || config.key_file.starts_with(&config.raft_dir)
        || config.replication_key_file.starts_with(&config.raft_dir)
    {
        return Err("invalid bounded HA process configuration".into());
    }
    Ok(())
}

fn parse_peers(config: &HaProcessConfig) -> Result<Vec<ParsedPeer>, String> {
    let mut names = BTreeSet::new();
    let mut digests = BTreeSet::new();
    let mut peers = Vec::with_capacity(config.peers.len());
    for (id, peer) in &config.peers {
        if *id == 0 {
            return Err("HA peer id must be nonzero".into());
        }
        let node = NodeId::parse(peer.node_name.clone()).map_err(|error| error.to_string())?;
        let endpoint = TlsPeerEndpoint::new(peer.address, peer.server_name.clone())
            .map_err(|error| error.to_string())?;
        let certificate_sha256 = decode_hex_32(&peer.certificate_sha256)?;
        if !names.insert(node.clone()) || !digests.insert(certificate_sha256) {
            return Err("HA peer identities and certificate digests must be unique".into());
        }
        peers.push(ParsedPeer {
            id: *id,
            node,
            endpoint,
            certificate_sha256,
        });
    }
    Ok(peers)
}

fn build_mutual_tls(config: &HaProcessConfig) -> Result<MutualTlsConfigs, String> {
    let ca = load_certificates(&config.ca_file)?;
    let certificates = load_certificates(&config.cert_file)?;
    let local_leaf = certificates
        .first()
        .ok_or_else(|| "HA certificate chain is empty".to_owned())?;
    let local_leaf_digest = sha256(local_leaf.as_ref());
    let key_bytes = read_private_bounded_regular_file(&config.key_file, MAX_TLS_FILE_BYTES)?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))
        .map_err(|_| "invalid HA TLS private key".to_owned())?
        .ok_or_else(|| "missing HA TLS private key".to_owned())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let client_roots = root_store(&ca)?;
    let mut client = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|_| "HA TLS protocol versions unavailable".to_owned())?
        .with_root_certificates(client_roots)
        .with_client_auth_cert(certificates.clone(), clone_private_key(&key)?)
        .map_err(|_| "invalid HA TLS client identity".to_owned())?;
    client.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];

    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(root_store(&ca)?),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .map_err(|_| "invalid HA TLS client verifier".to_owned())?;
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| "HA TLS protocol versions unavailable".to_owned())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, key)
        .map_err(|_| "invalid HA TLS server identity".to_owned())?;
    server.alpn_protocols = vec![RAFT_ALPN_PROTOCOL.to_vec()];
    Ok((Arc::new(client), Arc::new(server), local_leaf_digest))
}

fn root_store(certificates: &[CertificateDer<'static>]) -> Result<RootCertStore, String> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate.clone())
            .map_err(|_| "invalid HA TLS trust root".to_owned())?;
    }
    Ok(roots)
}

fn clone_private_key(key: &PrivateKeyDer<'static>) -> Result<PrivateKeyDer<'static>, String> {
    Ok(key.clone_key())
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let bytes = read_bounded_regular_file(path, MAX_TLS_FILE_BYTES)?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(bytes.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid HA TLS certificate file".to_owned())?;
    if certificates.is_empty() {
        return Err("HA TLS certificate file is empty".into());
    }
    Ok(certificates)
}

fn load_replication_key(path: &Path) -> Result<[u8; REPLICATION_KEY_BYTES], String> {
    let bytes = read_private_bounded_regular_file(path, REPLICATION_KEY_BYTES)?;
    if bytes.len() != REPLICATION_KEY_BYTES {
        return Err("HA replication key must contain exactly 32 raw bytes".into());
    }
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "HA replication key has invalid size".into())
}

fn read_bounded_regular_file(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    read_bounded_regular_file_with_privacy(path, maximum, false)
}

fn read_private_bounded_regular_file(
    path: &Path,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, String> {
    read_bounded_regular_file_with_privacy(path, maximum, true)
}

fn read_bounded_regular_file_with_privacy(
    path: &Path,
    maximum: usize,
    private: bool,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| "cannot open HA TLS or replication-key file".to_owned())?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect HA TLS or replication-key file".to_owned())?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err("HA material must be a bounded regular file".into());
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("HA private material must be owner only".into());
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(u64::try_from(maximum).map_err(|_| "HA file bound overflow".to_owned())? + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read HA TLS or replication-key file".to_owned())?;
    if bytes.len() > maximum {
        return Err("HA material exceeds limit".into());
    }
    Ok(bytes)
}

fn durable_state_exists(root: &Path) -> Result<bool, String> {
    let log = root.join("log");
    let state = root.join("state-machine");
    match (log.exists(), state.exists()) {
        (false, false) => Ok(false),
        (true, true) => Ok(true),
        _ => Err("partial HA durable state requires operator recovery".into()),
    }
}

fn encode_raft_frame(frame: RaftWireFrame) -> Result<Vec<u8>, RemoteRaftError> {
    if !valid_cluster_id(&frame.cluster_id)
        || frame.source == 0
        || frame.target == 0
        || frame.source == frame.target
        || !matches!(frame.role, RAFT_FRAME_REQUEST | RAFT_FRAME_RESPONSE)
        || frame.payload.is_empty()
    {
        return Err(RemoteRaftError::InvalidRpc);
    }
    let cluster_length =
        u16::try_from(frame.cluster_id.len()).map_err(|_| RemoteRaftError::InvalidRpc)?;
    let payload_length =
        u32::try_from(frame.payload.len()).map_err(|_| RemoteRaftError::InvalidRpc)?;
    let mut encoded =
        Vec::with_capacity(RAFT_FRAME_HEADER_BYTES + frame.cluster_id.len() + frame.payload.len());
    encoded.extend_from_slice(RAFT_FRAME_MAGIC);
    encoded.push(frame.role);
    encoded.extend_from_slice(&frame.source.to_be_bytes());
    encoded.extend_from_slice(&frame.target.to_be_bytes());
    encoded.push(kind_tag(frame.kind));
    encoded.extend_from_slice(&cluster_length.to_be_bytes());
    encoded.extend_from_slice(&payload_length.to_be_bytes());
    encoded.extend_from_slice(frame.cluster_id.as_bytes());
    encoded.extend_from_slice(&frame.payload);
    if encoded.len() > MAX_RAFT_FRAME_BYTES {
        return Err(RemoteRaftError::InvalidRpc);
    }
    Ok(encoded)
}

fn decode_raft_frame(encoded: &[u8]) -> Result<RaftWireFrame, RemoteRaftError> {
    if encoded.len() < RAFT_FRAME_HEADER_BYTES
        || encoded.len() > MAX_RAFT_FRAME_BYTES
        || &encoded[..5] != RAFT_FRAME_MAGIC
    {
        return Err(RemoteRaftError::InvalidRpc);
    }
    let role = encoded[5];
    if !matches!(role, RAFT_FRAME_REQUEST | RAFT_FRAME_RESPONSE) {
        return Err(RemoteRaftError::InvalidRpc);
    }
    let source = u64::from_be_bytes(
        encoded[6..14]
            .try_into()
            .map_err(|_| RemoteRaftError::InvalidRpc)?,
    );
    let target = u64::from_be_bytes(
        encoded[14..22]
            .try_into()
            .map_err(|_| RemoteRaftError::InvalidRpc)?,
    );
    let kind = decode_kind(encoded[22])?;
    let cluster_length = u16::from_be_bytes(
        encoded[23..25]
            .try_into()
            .map_err(|_| RemoteRaftError::InvalidRpc)?,
    ) as usize;
    let length = u32::from_be_bytes(
        encoded[25..29]
            .try_into()
            .map_err(|_| RemoteRaftError::InvalidRpc)?,
    ) as usize;
    let payload_start = RAFT_FRAME_HEADER_BYTES
        .checked_add(cluster_length)
        .ok_or(RemoteRaftError::InvalidRpc)?;
    if source == 0
        || target == 0
        || source == target
        || cluster_length == 0
        || cluster_length > MAX_CLUSTER_ID_BYTES
        || length == 0
        || encoded.len()
            != payload_start
                .checked_add(length)
                .ok_or(RemoteRaftError::InvalidRpc)?
    {
        return Err(RemoteRaftError::InvalidRpc);
    }
    let cluster_id = std::str::from_utf8(&encoded[RAFT_FRAME_HEADER_BYTES..payload_start])
        .map_err(|_| RemoteRaftError::InvalidRpc)?
        .to_owned();
    if !valid_cluster_id(&cluster_id) {
        return Err(RemoteRaftError::InvalidRpc);
    }
    Ok(RaftWireFrame {
        cluster_id,
        role,
        source,
        target,
        kind,
        payload: encoded[payload_start..].to_vec(),
    })
}

fn valid_cluster_id(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_CLUSTER_ID_BYTES {
        return false;
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return true;
    }
    STANDARD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 16 && STANDARD.encode(bytes) == value)
}

fn decode_raft_frame_for_cluster(
    encoded: &[u8],
    expected_cluster_id: &str,
) -> Result<RaftWireFrame, RemoteRaftError> {
    if !valid_cluster_id(expected_cluster_id) {
        return Err(RemoteRaftError::InvalidTopology);
    }
    let frame = decode_raft_frame(encoded)?;
    if frame.cluster_id != expected_cluster_id {
        return Err(RemoteRaftError::InvalidTopology);
    }
    Ok(frame)
}

fn kind_tag(kind: RaftRpcKind) -> u8 {
    match kind {
        RaftRpcKind::AppendEntries => 1,
        RaftRpcKind::Vote => 2,
        RaftRpcKind::PreVote => 3,
        RaftRpcKind::SnapshotChunk => 4,
    }
}

fn decode_kind(value: u8) -> Result<RaftRpcKind, RemoteRaftError> {
    match value {
        1 => Ok(RaftRpcKind::AppendEntries),
        2 => Ok(RaftRpcKind::Vote),
        3 => Ok(RaftRpcKind::PreVote),
        4 => Ok(RaftRpcKind::SnapshotChunk),
        _ => Err(RemoteRaftError::InvalidRpc),
    }
}

fn map_remote_service_error(error: RemoteRaftError) -> heptabao_ha_service::HaError {
    match error {
        RemoteRaftError::InvalidTopology => heptabao_ha_service::HaError::InvalidCluster,
        RemoteRaftError::InvalidRpc | RemoteRaftError::InvalidSnapshot => {
            heptabao_ha_service::HaError::InvalidFrame
        }
        RemoteRaftError::Transport(_) | RemoteRaftError::Consensus(_) | RemoteRaftError::Io(_) => {
            heptabao_ha_service::HaError::Transport
        }
    }
}

struct ReplicatedChunkPlan<'a> {
    bytes: &'a [u8],
    reference: ReplicatedChunkRef,
    reused: bool,
}

fn validate_owner_binding(
    operation_id: &str,
    bytes: &[u8],
    binding: OwnerPublicationBinding,
) -> Result<(), String> {
    binding
        .verify(operation_id, bytes)
        .map_err(|_| "local owner publication does not bind the HA state".to_owned())
}

fn reject_legacy_mutation_fallback(descriptor: &CommittedStateDescriptor) -> Result<(), String> {
    if matches!(descriptor, CommittedStateDescriptor::Legacy(_)) {
        return Err(
            "legacy HA state requires explicit owner-manifest migration before mutation".into(),
        );
    }
    Ok(())
}

fn validate_legacy_migration_base(
    descriptor: &CommittedStateDescriptor,
    owner_bound: bool,
) -> Result<(), String> {
    if !owner_bound {
        return Err("legacy owner-manifest migration requires an owner publication binding".into());
    }
    if !matches!(descriptor, CommittedStateDescriptor::Legacy(_)) {
        return Err("legacy owner-manifest migration requires an HBSR1 base state".into());
    }
    Ok(())
}

fn plan_replicated_chunks<'a>(
    bytes: &'a [u8],
    previous: Option<&ReplicatedStateManifest>,
) -> Result<Vec<ReplicatedChunkPlan<'a>>, String> {
    let chunks = replicated_content_defined_chunks(bytes);
    if chunks.is_empty() || chunks.len() > MAX_REPLICATED_STATE_CHUNKS {
        return Err("HA content-defined chunk count exceeds bounded physical index space".into());
    }

    let previous_chunks = previous
        .map(|manifest| manifest.chunks.as_slice())
        .unwrap_or(&[]);
    let mut reserved = BTreeSet::new();
    let mut matches = Vec::with_capacity(chunks.len());
    for chunk in &chunks {
        let digest = sha256(chunk);
        let chunk_bytes =
            u32::try_from(chunk.len()).map_err(|_| "HA application chunk length overflow")?;
        let found = previous_chunks
            .iter()
            .find(|reference| {
                !reserved.contains(&reference.index)
                    && reference.digest == digest
                    && reference.bytes == chunk_bytes
            })
            .cloned();
        if let Some(reference) = found.as_ref() {
            reserved.insert(reference.index);
        }
        matches.push(found);
    }

    let old_by_index = previous_chunks
        .iter()
        .map(|reference| (reference.index, reference))
        .collect::<BTreeMap<_, _>>();
    let mut used = reserved;
    let mut plans = Vec::with_capacity(chunks.len());
    for (chunk, matched) in chunks.into_iter().zip(matches) {
        if let Some(reference) = matched {
            plans.push(ReplicatedChunkPlan {
                bytes: chunk,
                reference,
                reused: true,
            });
            continue;
        }
        let index = (0..MAX_REPLICATED_STATE_CHUNKS)
            .find_map(|value| {
                let index = u16::try_from(value).ok()?;
                (!used.contains(&index)).then_some(index)
            })
            .ok_or_else(|| "HA physical chunk index space exhausted".to_owned())?;
        used.insert(index);
        let slot = old_by_index
            .get(&index)
            .map_or(0, |reference| 1 - reference.slot);
        plans.push(ReplicatedChunkPlan {
            bytes: chunk,
            reference: ReplicatedChunkRef {
                index,
                slot,
                bytes: u32::try_from(chunk.len())
                    .map_err(|_| "HA application chunk length overflow")?,
                digest: sha256(chunk),
            },
            reused: false,
        });
    }
    Ok(plans)
}

fn replicated_content_defined_chunks(bytes: &[u8]) -> Vec<&[u8]> {
    let mut chunks = Vec::new();
    let mut start = 0_usize;
    let mut rolling = 0_u64;
    for (index, byte) in bytes.iter().copied().enumerate() {
        rolling = rolling.rotate_left(1) ^ replicated_chunk_byte_hash(byte);
        if index >= REPLICATED_CHUNK_WINDOW_BYTES {
            rolling ^= replicated_chunk_byte_hash(bytes[index - REPLICATED_CHUNK_WINDOW_BYTES])
                .rotate_left((REPLICATED_CHUNK_WINDOW_BYTES % u64::BITS as usize) as u32);
        }
        let length = index + 1 - start;
        if length >= REPLICATED_CHUNK_MIN_BYTES
            && ((rolling & REPLICATED_CHUNK_MASK) == 0 || length >= REPLICATED_STATE_CHUNK_BYTES)
        {
            chunks.push(&bytes[start..=index]);
            start = index + 1;
        }
    }
    if start < bytes.len() {
        chunks.push(&bytes[start..]);
    }
    chunks
}

fn replicated_chunk_byte_hash(byte: u8) -> u64 {
    let mut value = u64::from(byte).wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn chunk_operation_id(operation_id: &str, index: u16, slot: u8) -> String {
    let suffix = format!(":c:{index:03}:{slot}");
    let keep = operation_id
        .len()
        .min(128_usize.saturating_sub(suffix.len()));
    format!("{}{}", &operation_id[..keep], suffix)
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("HA certificate digest must be 64 hex characters".into());
    }
    let mut output = [0_u8; 32];
    let bytes = value.as_bytes();
    for (index, output_byte) in output.iter_mut().enumerate() {
        let high = decode_hex_nibble(bytes[index * 2])?;
        let low = decode_hex_nibble(bytes[index * 2 + 1])?;
        *output_byte = (high << 4) | low;
    }
    Ok(output)
}

fn decode_hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("invalid HA certificate digest".into()),
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let value = digest::digest(&digest::SHA256, bytes);
    let mut output = [0_u8; 32];
    output.copy_from_slice(value.as_ref());
    output
}

#[cfg(test)]
#[path = "ha_read_tests.rs"]
pub(crate) mod read_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_cluster_identity_is_rejected_before_peer_validation() -> Result<(), String> {
        let config = HaProcessConfig {
            node_id: 0,
            cluster_id: "cluster/with-invalid-delimiter".into(),
            raft_dir: PathBuf::new(),
            listen: "127.0.0.1:1"
                .parse()
                .map_err(|_| "synthetic listener address")?,
            ca_file: PathBuf::new(),
            cert_file: PathBuf::new(),
            key_file: PathBuf::new(),
            replication_key_file: PathBuf::new(),
            peers: BTreeMap::new(),
            bootstrap: false,
            initial_voters: None,
            peer_timeout_ms: 750,
            max_inflight: 64,
        };
        assert_eq!(
            validate_config(&config),
            Err("invalid HA cluster identity".into())
        );
        Ok(())
    }

    #[test]
    fn zero_listener_port_is_rejected_for_static_peer_enrollment() -> Result<(), String> {
        let config = HaProcessConfig {
            node_id: 1,
            cluster_id: "cluster-a".into(),
            raft_dir: PathBuf::from("/var/lib/heptabao/node-1/raft"),
            listen: "127.0.0.1:0"
                .parse()
                .map_err(|_| "synthetic listener address")?,
            ca_file: PathBuf::from("/var/lib/heptabao/ca.crt"),
            cert_file: PathBuf::from("/var/lib/heptabao/node-1/tls.crt"),
            key_file: PathBuf::from("/var/lib/heptabao/node-1/tls.key"),
            replication_key_file: PathBuf::from("/var/lib/heptabao/replication.key"),
            peers: BTreeMap::from([
                (
                    1,
                    HaPeerConfig {
                        node_name: "node-1".into(),
                        address: "127.0.0.1:8201".parse().map_err(|_| "peer address")?,
                        server_name: "node-1.example.internal".into(),
                        certificate_sha256: "11".repeat(32),
                    },
                ),
                (
                    2,
                    HaPeerConfig {
                        node_name: "node-2".into(),
                        address: "127.0.0.1:8202".parse().map_err(|_| "peer address")?,
                        server_name: "node-2.example.internal".into(),
                        certificate_sha256: "22".repeat(32),
                    },
                ),
                (
                    3,
                    HaPeerConfig {
                        node_name: "node-3".into(),
                        address: "127.0.0.1:8203".parse().map_err(|_| "peer address")?,
                        server_name: "node-3.example.internal".into(),
                        certificate_sha256: "33".repeat(32),
                    },
                ),
            ]),
            bootstrap: false,
            initial_voters: None,
            peer_timeout_ms: 750,
            max_inflight: 64,
        };
        assert_eq!(
            validate_config(&config),
            Err("invalid bounded HA process configuration".into())
        );
        Ok(())
    }

    #[test]
    fn raft_wire_frame_binds_direction_kind_and_payload() -> Result<(), Box<dyn std::error::Error>>
    {
        let encoded = encode_raft_frame(RaftWireFrame {
            cluster_id: "cluster-a".into(),
            role: RAFT_FRAME_REQUEST,
            source: 1,
            target: 2,
            kind: RaftRpcKind::AppendEntries,
            payload: b"bounded-raft-rpc".to_vec(),
        })?;
        let decoded = decode_raft_frame(&encoded)?;
        assert_eq!(decoded.cluster_id, "cluster-a");
        assert_eq!(decoded.role, RAFT_FRAME_REQUEST);
        assert_eq!(decoded.source, 1);
        assert_eq!(decoded.target, 2);
        assert_eq!(decoded.kind, RaftRpcKind::AppendEntries);
        assert_eq!(decoded.payload, b"bounded-raft-rpc");
        Ok(())
    }

    #[test]
    fn ha_commit_rejects_owner_binding_for_different_operation_or_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let logical = br#"{"schema":9,"cluster_id":"cluster"}"#;
        let plan = crate::service::OwnerWritePlan::new(
            logical,
            "owner-op-binding",
            9,
            "cluster",
            0,
            vec![
                ("namespaces", br#"{"next_incarnation":1}"#.to_vec()),
                ("auth", br#"{"tokens":[]}"#.to_vec()),
                ("engines", br#"{"mounts":[]}"#.to_vec()),
                ("database", br#"{"connections":[]}"#.to_vec()),
                ("raft_admin", br#"{"policy":null}"#.to_vec()),
            ],
            None,
            Vec::new(),
        )?;
        let binding = plan.publication_binding("owner-op-binding", logical)?;
        assert!(validate_owner_binding("owner-op-binding", logical, binding).is_ok());
        assert!(validate_owner_binding("owner-op-other", logical, binding).is_err());
        let mut altered = logical.to_vec();
        altered[0] ^= 1;
        assert!(validate_owner_binding("owner-op-binding", &altered, binding).is_err());
        Ok(())
    }

    #[test]
    fn ha_commit_rejects_legacy_whole_state_fallback() -> Result<(), Box<dyn std::error::Error>> {
        let legacy = CommittedStateDescriptor::Legacy(Zeroizing::new(b"legacy-state".to_vec()));
        let error = match reject_legacy_mutation_fallback(&legacy) {
            Ok(()) => return Err("mutation must not promote HBSR1 implicitly".into()),
            Err(error) => error,
        };
        assert!(error.contains("explicit owner-manifest migration"));
        Ok(())
    }

    #[test]
    fn legacy_migration_requires_owner_binding_and_hbsr1_base() {
        let legacy = CommittedStateDescriptor::Legacy(Zeroizing::new(b"legacy-state".to_vec()));
        assert!(validate_legacy_migration_base(&legacy, false).is_err());
        assert!(validate_legacy_migration_base(&legacy, true).is_ok());

        let manifest = CommittedStateDescriptor::Chunked(ReplicatedStateManifest {
            base_digest: [0; 32],
            state_digest: [7; 32],
            total_bytes: 0,
            chunks: Vec::new(),
            owner_manifest_digest: None,
            changed_owner_mask: None,
        });
        assert!(validate_legacy_migration_base(&manifest, true).is_err());
    }

    #[test]
    fn raft_wire_frame_rejects_direction_and_length_drift() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut encoded = encode_raft_frame(RaftWireFrame {
            cluster_id: "cluster-a".into(),
            role: RAFT_FRAME_RESPONSE,
            source: 2,
            target: 1,
            kind: RaftRpcKind::Vote,
            payload: b"vote".to_vec(),
        })?;
        encoded[26] ^= 1;
        assert!(decode_raft_frame(&encoded).is_err());
        let cross_cluster = encode_raft_frame(RaftWireFrame {
            cluster_id: "cluster-b".into(),
            role: RAFT_FRAME_REQUEST,
            source: 1,
            target: 2,
            kind: RaftRpcKind::Vote,
            payload: b"vote".to_vec(),
        })?;
        let decoded = decode_raft_frame(&cross_cluster)?;
        assert_ne!(decoded.cluster_id, "cluster-a");
        assert!(decode_raft_frame_for_cluster(&cross_cluster, "cluster-a").is_err());
        Ok(())
    }

    #[test]
    fn dropping_peer_pool_stops_and_joins_every_worker() -> Result<(), Box<dyn std::error::Error>> {
        let stop = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut pool = PeerListener {
            stop: stop.clone(),
            workers: Vec::new(),
        };
        for _ in 0..4 {
            let flag = stop.clone();
            let sender = sender.clone();
            pool.workers.push(thread::spawn(move || {
                while !flag.load(Ordering::Acquire) {
                    thread::yield_now();
                }
                let _ = sender.send(());
            }));
        }
        drop(pool);
        assert!(stop.load(Ordering::Acquire));
        for _ in 0..4 {
            receiver.recv_timeout(Duration::from_secs(1))?;
        }
        Ok(())
    }

    #[test]
    fn position_independent_chunk_plan_reuses_tail_after_prefix_insertion()
    -> Result<(), Box<dyn std::error::Error>> {
        const STATE_BYTES: usize = 4 * 1024 * 1024;
        let mut state = Vec::with_capacity(STATE_BYTES);
        let mut value = 0x1234_5678_9abc_def0_u64;
        for _ in 0..STATE_BYTES {
            value ^= value << 13;
            value ^= value >> 7;
            value ^= value << 17;
            state.push((value >> 24) as u8);
        }
        let first = plan_replicated_chunks(&state, None)?;
        assert!(first.len() >= 8);
        let previous = ReplicatedStateManifest {
            base_digest: [1; 32],
            state_digest: sha256(&state),
            total_bytes: u64::try_from(state.len())?,
            chunks: first.iter().map(|plan| plan.reference.clone()).collect(),
            owner_manifest_digest: None,
            changed_owner_mask: None,
        };

        let insertion = b"ha-prefix-insertion-".repeat(7);
        let mut changed = Vec::with_capacity(state.len() + insertion.len());
        changed.extend_from_slice(&state[..96 * 1024]);
        changed.extend_from_slice(&insertion);
        changed.extend_from_slice(&state[96 * 1024..]);
        let second = plan_replicated_chunks(&changed, Some(&previous))?;
        let reused = second.iter().filter(|plan| plan.reused).count();
        assert!(
            reused >= previous.chunks.len().saturating_sub(2),
            "content-defined HA chunking should resynchronize and preserve most physical indices"
        );
        assert_eq!(
            second
                .iter()
                .map(|plan| plan.reference.index)
                .collect::<BTreeSet<_>>()
                .len(),
            second.len()
        );
        Ok(())
    }

    #[test]
    fn changed_chunk_uses_opposite_slot_without_overwriting_previous_manifest()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = vec![0x5a; 512 * 1024];
        let first = plan_replicated_chunks(&state, None)?;
        let previous = ReplicatedStateManifest {
            base_digest: [2; 32],
            state_digest: sha256(&state),
            total_bytes: u64::try_from(state.len())?,
            chunks: first.iter().map(|plan| plan.reference.clone()).collect(),
            owner_manifest_digest: None,
            changed_owner_mask: None,
        };
        let mut changed = state.clone();
        changed[0] ^= 1;
        let next = plan_replicated_chunks(&changed, Some(&previous))?;
        for plan in next.iter().filter(|plan| !plan.reused) {
            if let Some(old) = previous
                .chunks
                .iter()
                .find(|old| old.index == plan.reference.index)
            {
                assert_eq!(plan.reference.slot, 1 - old.slot);
            }
        }
        Ok(())
    }

    #[test]
    fn certificate_digest_is_strict_hex() {
        assert_eq!(decode_hex_32(&"ab".repeat(32)), Ok([0xab; 32]));
        assert!(decode_hex_32("ab").is_err());
        assert!(decode_hex_32(&"gg".repeat(32)).is_err());
    }
}
