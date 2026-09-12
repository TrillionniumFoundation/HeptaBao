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

use futures::future::BoxFuture;
use heptabao_ha_service::{
    MutualTlsPeerTransport, NodeId, PinnedClientCertificateMap, TlsPeerEndpoint,
    serve_one_mtls_peer_frame,
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
        ForwardRequest, decode_request as decode_forward_request,
        decode_response as decode_forward_response, encode_request as encode_forward_request,
        encode_response as encode_forward_response, is_forward_request,
    },
    ha_state::ClusterStateCodec,
};

const RAFT_FRAME_MAGIC: &[u8; 5] = b"HBRT1";
const RAFT_FRAME_REQUEST: u8 = 1;
const RAFT_FRAME_RESPONSE: u8 = 2;
const MAX_RAFT_FRAME_BYTES: usize = 896 * 1024;
const MAX_TLS_FILE_BYTES: usize = 1024 * 1024;
const REPLICATION_KEY_BYTES: usize = 32;

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
    peers: Arc<BTreeMap<u64, NodeId>>,
    transport: MutualTlsPeerTransport,
    inflight: Arc<Semaphore>,
}

impl fmt::Debug for MutualTlsRaftRpc {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MutualTlsRaftRpc")
            .field("local_id", &self.local_id)
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
        let target_node = self.peers.get(&target).cloned();
        let transport = self.transport.clone();
        let inflight = self.inflight.clone();
        Box::pin(async move {
            if source != local_id || source == target || timeout.is_zero() {
                return Err(RemoteRaftError::InvalidRpc);
            }
            let target_node = target_node.ok_or(RemoteRaftError::InvalidTopology)?;
            let request = encode_raft_frame(RaftWireFrame {
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
            let response = decode_raft_frame(&response)?;
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

pub(crate) struct CommittedApplicationState {
    pub digest: [u8; 32],
    pub bytes: Zeroizing<Vec<u8>>,
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
                                    let request = decode_forward_request(&frame)
                                        .map_err(|_| heptabao_ha_service::HaError::InvalidFrame)?;
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
                                        local_id,
                                        source,
                                        response.status,
                                        &response.body,
                                    )
                                    .map_err(|_| heptabao_ha_service::HaError::InvalidFrame);
                                }
                                let request = decode_raft_frame(&frame)
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
            for peer_id in peer_ids.iter().copied().filter(|id| *id != config.node_id) {
                runtime
                    .block_on(node.add_learner(peer_id))
                    .map_err(|error| error.to_string())?;
            }
            runtime
                .block_on(node.change_membership(peer_ids))
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

    pub(crate) fn forward_request(
        &self,
        method: &str,
        path: &str,
        namespace: &str,
        token: &str,
        body: &serde_json::Value,
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
        let request = encode_forward_request(local, leader, method, path, namespace, token, body)?;
        let response = zeroize::Zeroizing::new(
            self.forward_transport
                .exchange(target, &request)
                .map_err(|error| error.to_string())?,
        );
        let mut response = decode_forward_response(&response)?;
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

    pub fn ensure_linearizable(&self) -> Result<(), String> {
        let node = self
            .node
            .as_ref()
            .ok_or_else(|| "HA process is shut down".to_owned())?;
        self.runtime
            .block_on(node.ensure_linearizable())
            .map_err(|error| error.to_string())
    }

    pub fn trigger_snapshot(&self) -> Result<(), String> {
        let node = self
            .node
            .as_ref()
            .ok_or_else(|| "HA process is shut down".to_owned())?;
        self.runtime
            .block_on(node.trigger_snapshot())
            .map_err(|error| error.to_string())
    }

    /// Replicate one complete next application state. The caller supplies the
    /// digest of the exact local state used to derive it. A leader refuses to
    /// commit if Raft already contains a different current application digest.
    pub fn commit_state(
        &self,
        operation_id: &str,
        expected_base_digest: [u8; 32],
        bytes: &[u8],
    ) -> Result<CommitReceipt, String> {
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
        let proposal = self
            .codec
            .seal(operation_id.to_owned(), expected_base_digest, bytes)
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
            .block_on(node.replicate(serial, &envelope))
            .map_err(|error| error.to_string())?;
        if receipt.leader_id != local_id || receipt.envelope_digest != proposal.digest() {
            return Err("HA commit receipt did not bind the submitted application state".into());
        }
        Ok(receipt)
    }

    /// Return the newest complete application state after a linearizable ReadIndex.
    /// The envelope is authenticated under the cluster replication key before
    /// plaintext is returned to the local durable-store reconciliation path.
    pub(crate) fn latest_committed_state(
        &self,
    ) -> Result<Option<CommittedApplicationState>, String> {
        let node = self
            .node
            .as_ref()
            .ok_or_else(|| "HA process is shut down".to_owned())?;
        self.runtime
            .block_on(node.ensure_linearizable())
            .map_err(|error| error.to_string())?;
        let Some(envelope) = self
            .runtime
            .block_on(node.latest_envelope())
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let bytes = self
            .codec
            .open_committed_parts(
                envelope.operation_id(),
                envelope.digest(),
                envelope.sealed(),
            )
            .map_err(|error| error.to_string())?;
        Ok(Some(CommittedApplicationState {
            digest: envelope.digest(),
            bytes,
        }))
    }
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
    if config.node_id == 0
        || config.peers.len() < 3
        || config.peers.len() > 9
        || !config.peers.contains_key(&config.node_id)
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
    client.alpn_protocols = vec![b"heptabao-raft/1".to_vec()];

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
    server.alpn_protocols = vec![b"heptabao-raft/1".to_vec()];
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
        options.custom_flags(0o400000 | 0o2000000 | 0o4000);
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
    if frame.source == 0
        || frame.target == 0
        || frame.source == frame.target
        || !matches!(frame.role, RAFT_FRAME_REQUEST | RAFT_FRAME_RESPONSE)
        || frame.payload.is_empty()
    {
        return Err(RemoteRaftError::InvalidRpc);
    }
    let payload_length =
        u32::try_from(frame.payload.len()).map_err(|_| RemoteRaftError::InvalidRpc)?;
    let mut encoded = Vec::with_capacity(27 + frame.payload.len());
    encoded.extend_from_slice(RAFT_FRAME_MAGIC);
    encoded.push(frame.role);
    encoded.extend_from_slice(&frame.source.to_be_bytes());
    encoded.extend_from_slice(&frame.target.to_be_bytes());
    encoded.push(kind_tag(frame.kind));
    encoded.extend_from_slice(&payload_length.to_be_bytes());
    encoded.extend_from_slice(&frame.payload);
    if encoded.len() > MAX_RAFT_FRAME_BYTES {
        return Err(RemoteRaftError::InvalidRpc);
    }
    Ok(encoded)
}

fn decode_raft_frame(encoded: &[u8]) -> Result<RaftWireFrame, RemoteRaftError> {
    if encoded.len() < 27
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
    let length = u32::from_be_bytes(
        encoded[23..27]
            .try_into()
            .map_err(|_| RemoteRaftError::InvalidRpc)?,
    ) as usize;
    if source == 0 || target == 0 || source == target || length == 0 || encoded.len() != 27 + length
    {
        return Err(RemoteRaftError::InvalidRpc);
    }
    Ok(RaftWireFrame {
        role,
        source,
        target,
        kind,
        payload: encoded[27..].to_vec(),
    })
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
mod tests {
    use super::*;

    #[test]
    fn raft_wire_frame_binds_direction_kind_and_payload() -> Result<(), Box<dyn std::error::Error>>
    {
        let encoded = encode_raft_frame(RaftWireFrame {
            role: RAFT_FRAME_REQUEST,
            source: 1,
            target: 2,
            kind: RaftRpcKind::AppendEntries,
            payload: b"bounded-raft-rpc".to_vec(),
        })?;
        let decoded = decode_raft_frame(&encoded)?;
        assert_eq!(decoded.role, RAFT_FRAME_REQUEST);
        assert_eq!(decoded.source, 1);
        assert_eq!(decoded.target, 2);
        assert_eq!(decoded.kind, RaftRpcKind::AppendEntries);
        assert_eq!(decoded.payload, b"bounded-raft-rpc");
        Ok(())
    }

    #[test]
    fn raft_wire_frame_rejects_direction_and_length_drift() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut encoded = encode_raft_frame(RaftWireFrame {
            role: RAFT_FRAME_RESPONSE,
            source: 2,
            target: 1,
            kind: RaftRpcKind::Vote,
            payload: b"vote".to_vec(),
        })?;
        encoded[26] ^= 1;
        assert!(decode_raft_frame(&encoded).is_err());
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
    fn certificate_digest_is_strict_hex() {
        assert_eq!(decode_hex_32(&"ab".repeat(32)), Ok([0xab; 32]));
        assert!(decode_hex_32("ab").is_err());
        assert!(decode_hex_32(&"gg".repeat(32)).is_err());
    }
}
