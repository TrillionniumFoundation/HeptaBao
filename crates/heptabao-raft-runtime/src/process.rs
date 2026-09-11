use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io::{self, Cursor};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use openraft::errors::{
    NetworkError, RPCError, RaftError, ReplicationClosed, StreamingError, Unreachable,
};
use openraft::network::v2::RaftNetworkV2;
use openraft::network::{RPCOption, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, SnapshotResponse, VoteRequest, VoteResponse,
};
use openraft::type_config::alias::{SnapshotMetaOf, SnapshotOf, VoteOf};
use openraft::{Config, OptionalSend, ReadPolicy, Snapshot, SnapshotPolicy};
use openraft_memstore::{ClientRequest, MemStoreStateMachine, TypeConfig};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::task::spawn_blocking;

use super::network::DurableRaft;
use super::store::{DurableLogStore, DurableStateMachine};
use super::{CommitReceipt, RaftRuntimeError, ReplicatedEnvelope};

/// RPC classes emitted by a production one-voter-per-process Raft node.
///
/// Authentication, peer identity, anti-spoofing and transport integrity belong
/// to the `RaftPeerRpc` implementation. The consensus layer deliberately does
/// not own TLS credentials or network listeners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RaftRpcKind {
    AppendEntries,
    Vote,
    PreVote,
    SnapshotChunk,
}

#[derive(Debug)]
pub enum RemoteRaftError {
    InvalidTopology,
    InvalidRpc,
    InvalidSnapshot,
    Transport(String),
    Consensus(String),
    Io(String),
}

impl std::fmt::Display for RemoteRaftError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTopology => formatter.write_str("remote Raft topology is invalid"),
            Self::InvalidRpc => formatter.write_str("remote Raft RPC is invalid"),
            Self::InvalidSnapshot => formatter.write_str("remote Raft snapshot is invalid"),
            Self::Transport(message) => {
                write!(formatter, "remote Raft transport failed: {message}")
            }
            Self::Consensus(message) => {
                write!(formatter, "remote Raft consensus failed: {message}")
            }
            Self::Io(message) => write!(formatter, "remote Raft durable store failed: {message}"),
        }
    }
}

impl std::error::Error for RemoteRaftError {}

/// Authenticated peer exchange boundary for production Raft networking.
///
/// Implementations must authenticate `source` and `target`, preserve payload
/// integrity, enforce `timeout`, cap frames to the deployment's declared
/// bound, and never silently retry an indeterminate application effect. Raft
/// protocol retransmission is performed by OpenRaft above this boundary.
pub trait RaftPeerRpc: std::fmt::Debug + Send + Sync {
    fn exchange(
        &self,
        source: u64,
        target: u64,
        kind: RaftRpcKind,
        payload: Vec<u8>,
        timeout: Duration,
    ) -> BoxFuture<'static, Result<Vec<u8>, RemoteRaftError>>;
}

#[derive(Clone)]
pub struct RemoteNetworkFactory {
    local_id: u64,
    peers: Arc<BTreeSet<u64>>,
    transport: Arc<dyn RaftPeerRpc>,
}

impl std::fmt::Debug for RemoteNetworkFactory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteNetworkFactory")
            .field("local_id", &self.local_id)
            .field("peers", &self.peers)
            .field("transport", &"[AUTHENTICATED_PEER_RPC]")
            .finish()
    }
}

impl RemoteNetworkFactory {
    pub fn new(
        local_id: u64,
        peers: BTreeSet<u64>,
        transport: Arc<dyn RaftPeerRpc>,
    ) -> Result<Self, RemoteRaftError> {
        if local_id == 0
            || peers.len() < 3
            || !peers.contains(&local_id)
            || peers.contains(&0)
        {
            return Err(RemoteRaftError::InvalidTopology);
        }
        Ok(Self {
            local_id,
            peers: Arc::new(peers),
            transport,
        })
    }

    pub fn local_id(&self) -> u64 {
        self.local_id
    }

    pub fn rpc_service(&self, raft: DurableRaft) -> RaftRpcService {
        RaftRpcService {
            local_id: self.local_id,
            peers: self.peers.clone(),
            raft,
            incoming_snapshots: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl RaftNetworkFactory<TypeConfig> for RemoteNetworkFactory {
    type Network = RemoteNetwork;

    async fn new_client(&mut self, target: u64, _node: &()) -> Self::Network {
        RemoteNetwork {
            source: self.local_id,
            target,
            peers: self.peers.clone(),
            transport: self.transport.clone(),
        }
    }
}

pub struct RemoteNetwork {
    source: u64,
    target: u64,
    peers: Arc<BTreeSet<u64>>,
    transport: Arc<dyn RaftPeerRpc>,
}

impl std::fmt::Debug for RemoteNetwork {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteNetwork")
            .field("source", &self.source)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

const MAX_REMOTE_RPC_BYTES: usize = 768 * 1024;
const SNAPSHOT_CHUNK_BYTES: usize = 128 * 1024;
const MAX_REMOTE_SNAPSHOT_BYTES: usize = 128 * 1024 * 1024;
const MAX_INCOMING_SNAPSHOTS: usize = 4;

impl RemoteNetwork {
    async fn exchange(
        &self,
        kind: RaftRpcKind,
        payload: Vec<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>, RPCError<TypeConfig>> {
        if self.source == 0
            || self.target == 0
            || self.source == self.target
            || !self.peers.contains(&self.source)
            || !self.peers.contains(&self.target)
            || payload.is_empty()
            || payload.len() > MAX_REMOTE_RPC_BYTES
            || timeout.is_zero()
        {
            return Err(remote_network_error(RemoteRaftError::InvalidRpc));
        }
        self.transport
            .exchange(self.source, self.target, kind, payload, timeout)
            .await
            .map_err(remote_network_error)
    }

    async fn rpc<Req, Resp>(
        &self,
        kind: RaftRpcKind,
        request: &Req,
        option: &RPCOption,
    ) -> Result<Resp, RPCError<TypeConfig>>
    where
        Req: Serialize,
        Resp: serde::de::DeserializeOwned,
    {
        let payload = serde_json::to_vec(request)
            .map_err(|error| network_error(error.to_string()))?;
        let response = self.exchange(kind, payload, option.soft_ttl()).await?;
        let result: Result<Resp, RaftError<TypeConfig>> = serde_json::from_slice(&response)
            .map_err(|error| network_error(error.to_string()))?;
        result.map_err(|error| RPCError::Unreachable(Unreachable::new(&error)))
    }

    async fn send_snapshot(
        &self,
        vote: VoteOf<TypeConfig>,
        snapshot: SnapshotOf<TypeConfig, Cursor<Vec<u8>>>,
        option: &RPCOption,
    ) -> Result<SnapshotResponse<TypeConfig>, RPCError<TypeConfig>> {
        let data = snapshot.snapshot.into_inner();
        if data.len() > MAX_REMOTE_SNAPSHOT_BYTES {
            return Err(network_error(
                "remote Raft snapshot exceeds the bounded maximum",
            ));
        }
        let meta_bytes = serde_json::to_vec(&snapshot.meta)
            .map_err(|error| network_error(error.to_string()))?;
        let vote_bytes = serde_json::to_vec(&vote)
            .map_err(|error| network_error(error.to_string()))?;
        let transfer_id = format!(
            "{:08x}-{:08x}-{}",
            crc32(&meta_bytes),
            crc32(&vote_bytes),
            data.len()
        );
        let whole_crc32 = crc32(&data);
        let total_chunks = data.len().max(1).div_ceil(SNAPSHOT_CHUNK_BYTES);
        let total_chunks = u32::try_from(total_chunks)
            .map_err(|_| network_error("remote Raft snapshot chunk count overflow"))?;
        let mut final_result = None;
        for ordinal in 0..total_chunks {
            let start = usize::try_from(ordinal)
                .map_err(|_| network_error("remote Raft snapshot ordinal overflow"))?
                .checked_mul(SNAPSHOT_CHUNK_BYTES)
                .ok_or_else(|| network_error("remote Raft snapshot offset overflow"))?;
            let end = data.len().min(start.saturating_add(SNAPSHOT_CHUNK_BYTES));
            let chunk = if start < data.len() {
                data[start..end].to_vec()
            } else {
                Vec::new()
            };
            let request = SnapshotChunkWire {
                transfer_id: transfer_id.clone(),
                ordinal,
                total_chunks,
                vote: (ordinal == 0).then_some(vote),
                meta: (ordinal == 0).then_some(snapshot.meta.clone()),
                total_bytes: u64::try_from(data.len())
                    .map_err(|_| network_error("remote Raft snapshot length overflow"))?,
                whole_crc32,
                chunk_crc32: crc32(&chunk),
                chunk,
            };
            let payload = serde_json::to_vec(&request)
                .map_err(|error| network_error(error.to_string()))?;
            let response = self
                .exchange(RaftRpcKind::SnapshotChunk, payload, option.soft_ttl())
                .await?;
            let ack: SnapshotChunkAck = serde_json::from_slice(&response)
                .map_err(|error| network_error(error.to_string()))?;
            if ack.transfer_id != transfer_id || ack.next_ordinal != ordinal + 1 {
                return Err(network_error(
                    "remote Raft snapshot acknowledgement mismatch",
                ));
            }
            if ordinal + 1 == total_chunks {
                if !ack.complete {
                    return Err(network_error(
                        "remote Raft snapshot final acknowledgement incomplete",
                    ));
                }
                final_result = ack.result;
            } else if ack.complete || ack.result.is_some() {
                return Err(network_error(
                    "remote Raft snapshot completed before final chunk",
                ));
            }
        }
        final_result
            .ok_or_else(|| network_error("remote Raft snapshot result missing"))?
            .map_err(|error| RPCError::Unreachable(Unreachable::new(&error)))
    }
}

impl RaftNetworkV2<TypeConfig> for RemoteNetwork {
    type SnapshotData = Cursor<Vec<u8>>;

    async fn append_entries(
        &mut self,
        request: AppendEntriesRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<TypeConfig>, RPCError<TypeConfig>> {
        self.rpc(RaftRpcKind::AppendEntries, &request, &option).await
    }

    async fn vote(
        &mut self,
        request: VoteRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<VoteResponse<TypeConfig>, RPCError<TypeConfig>> {
        self.rpc(RaftRpcKind::Vote, &request, &option).await
    }

    async fn pre_vote(
        &mut self,
        request: VoteRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<VoteResponse<TypeConfig>, RPCError<TypeConfig>> {
        self.rpc(RaftRpcKind::PreVote, &request, &option).await
    }

    async fn full_snapshot(
        &mut self,
        vote: VoteOf<TypeConfig>,
        snapshot: SnapshotOf<TypeConfig, Self::SnapshotData>,
        cancel: impl Future<Output = ReplicationClosed> + OptionalSend + 'static,
        option: RPCOption,
    ) -> Result<SnapshotResponse<TypeConfig>, StreamingError<TypeConfig>> {
        let send = self.send_snapshot(vote, snapshot, &option);
        tokio::pin!(send);
        tokio::pin!(cancel);
        tokio::select! {
            closed = &mut cancel => Err(StreamingError::Closed(closed)),
            result = &mut send => result.map_err(StreamingError::from),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SnapshotChunkWire {
    transfer_id: String,
    ordinal: u32,
    total_chunks: u32,
    vote: Option<VoteOf<TypeConfig>>,
    meta: Option<SnapshotMetaOf<TypeConfig>>,
    total_bytes: u64,
    whole_crc32: u32,
    chunk_crc32: u32,
    chunk: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SnapshotChunkAck {
    transfer_id: String,
    next_ordinal: u32,
    complete: bool,
    result: Option<Result<SnapshotResponse<TypeConfig>, RaftError<TypeConfig>>>,
}

struct IncomingSnapshot {
    total_chunks: u32,
    next_ordinal: u32,
    vote: VoteOf<TypeConfig>,
    meta: SnapshotMetaOf<TypeConfig>,
    total_bytes: usize,
    whole_crc32: u32,
    data: Vec<u8>,
}

/// Local RPC executor for a single voter.
///
/// `source` must be supplied by an authenticated upper transport. This service
/// never derives peer identity from untrusted payload bytes.
#[derive(Clone)]
pub struct RaftRpcService {
    local_id: u64,
    peers: Arc<BTreeSet<u64>>,
    raft: DurableRaft,
    incoming_snapshots: Arc<Mutex<BTreeMap<(u64, String), IncomingSnapshot>>>,
}

impl std::fmt::Debug for RaftRpcService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RaftRpcService")
            .field("local_id", &self.local_id)
            .field("peers", &self.peers)
            .finish_non_exhaustive()
    }
}

impl RaftRpcService {
    pub async fn handle(
        &self,
        source: u64,
        kind: RaftRpcKind,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, RemoteRaftError> {
        if source == 0
            || source == self.local_id
            || !self.peers.contains(&source)
            || payload.is_empty()
            || payload.len() > MAX_REMOTE_RPC_BYTES
        {
            return Err(RemoteRaftError::InvalidRpc);
        }
        match kind {
            RaftRpcKind::AppendEntries => {
                let request: AppendEntriesRequest<TypeConfig> =
                    serde_json::from_slice(&payload).map_err(|_| RemoteRaftError::InvalidRpc)?;
                serde_json::to_vec(&self.raft.append_entries(request).await)
                    .map_err(|_| RemoteRaftError::InvalidRpc)
            }
            RaftRpcKind::Vote => {
                let request: VoteRequest<TypeConfig> =
                    serde_json::from_slice(&payload).map_err(|_| RemoteRaftError::InvalidRpc)?;
                serde_json::to_vec(&self.raft.vote(request).await)
                    .map_err(|_| RemoteRaftError::InvalidRpc)
            }
            RaftRpcKind::PreVote => {
                let request: VoteRequest<TypeConfig> =
                    serde_json::from_slice(&payload).map_err(|_| RemoteRaftError::InvalidRpc)?;
                serde_json::to_vec(&self.raft.pre_vote(request).await)
                    .map_err(|_| RemoteRaftError::InvalidRpc)
            }
            RaftRpcKind::SnapshotChunk => {
                let request: SnapshotChunkWire =
                    serde_json::from_slice(&payload).map_err(|_| RemoteRaftError::InvalidSnapshot)?;
                let ack = self.handle_snapshot_chunk(source, request).await?;
                serde_json::to_vec(&ack).map_err(|_| RemoteRaftError::InvalidSnapshot)
            }
        }
    }

    async fn handle_snapshot_chunk(
        &self,
        source: u64,
        request: SnapshotChunkWire,
    ) -> Result<SnapshotChunkAck, RemoteRaftError> {
        let total_bytes = usize::try_from(request.total_bytes)
            .map_err(|_| RemoteRaftError::InvalidSnapshot)?;
        if request.transfer_id.is_empty()
            || request.transfer_id.len() > 128
            || request.total_chunks == 0
            || request.ordinal >= request.total_chunks
            || total_bytes > MAX_REMOTE_SNAPSHOT_BYTES
            || request.chunk.len() > SNAPSHOT_CHUNK_BYTES
            || crc32(&request.chunk) != request.chunk_crc32
        {
            return Err(RemoteRaftError::InvalidSnapshot);
        }
        let key = (source, request.transfer_id.clone());
        let completed = {
            let mut snapshots = self.incoming_snapshots.lock().await;
            if request.ordinal == 0 {
                if snapshots.len() >= MAX_INCOMING_SNAPSHOTS && !snapshots.contains_key(&key) {
                    return Err(RemoteRaftError::InvalidSnapshot);
                }
                let vote = request.vote.ok_or(RemoteRaftError::InvalidSnapshot)?;
                let meta = request.meta.ok_or(RemoteRaftError::InvalidSnapshot)?;
                snapshots.insert(
                    key.clone(),
                    IncomingSnapshot {
                        total_chunks: request.total_chunks,
                        next_ordinal: 0,
                        vote,
                        meta,
                        total_bytes,
                        whole_crc32: request.whole_crc32,
                        data: Vec::with_capacity(total_bytes),
                    },
                );
            } else if request.vote.is_some() || request.meta.is_some() {
                return Err(RemoteRaftError::InvalidSnapshot);
            }
            let snapshot = snapshots
                .get_mut(&key)
                .ok_or(RemoteRaftError::InvalidSnapshot)?;
            if snapshot.total_chunks != request.total_chunks
                || snapshot.next_ordinal != request.ordinal
                || snapshot.total_bytes != total_bytes
                || snapshot.whole_crc32 != request.whole_crc32
                || snapshot
                    .data
                    .len()
                    .saturating_add(request.chunk.len())
                    > snapshot.total_bytes
            {
                return Err(RemoteRaftError::InvalidSnapshot);
            }
            snapshot.data.extend_from_slice(&request.chunk);
            snapshot.next_ordinal += 1;
            if snapshot.next_ordinal == snapshot.total_chunks {
                let snapshot = snapshots
                    .remove(&key)
                    .ok_or(RemoteRaftError::InvalidSnapshot)?;
                if snapshot.data.len() != snapshot.total_bytes
                    || crc32(&snapshot.data) != snapshot.whole_crc32
                {
                    return Err(RemoteRaftError::InvalidSnapshot);
                }
                Some(snapshot)
            } else {
                None
            }
        };
        if let Some(snapshot) = completed {
            let result = self
                .raft
                .install_full_snapshot(
                    snapshot.vote,
                    Snapshot {
                        meta: snapshot.meta,
                        snapshot: Cursor::new(snapshot.data),
                    },
                )
                .await
                .map_err(RaftError::Fatal);
            Ok(SnapshotChunkAck {
                transfer_id: request.transfer_id,
                next_ordinal: request.ordinal + 1,
                complete: true,
                result: Some(result),
            })
        } else {
            Ok(SnapshotChunkAck {
                transfer_id: request.transfer_id,
                next_ordinal: request.ordinal + 1,
                complete: false,
                result: None,
            })
        }
    }
}

/// One durable OpenRaft voter owned by one operating-system process.
pub struct ProcessRaftNode {
    id: u64,
    raft: DurableRaft,
    state_machine: DurableStateMachine,
    rpc_service: RaftRpcService,
}

impl std::fmt::Debug for ProcessRaftNode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessRaftNode")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl ProcessRaftNode {
    pub async fn create(
        root: impl AsRef<Path>,
        id: u64,
        network: RemoteNetworkFactory,
    ) -> Result<Self, RemoteRaftError> {
        Self::open(root.as_ref().to_path_buf(), id, network, true).await
    }

    pub async fn reopen(
        root: impl AsRef<Path>,
        id: u64,
        network: RemoteNetworkFactory,
    ) -> Result<Self, RemoteRaftError> {
        Self::open(root.as_ref().to_path_buf(), id, network, false).await
    }

    async fn open(
        root: PathBuf,
        id: u64,
        network: RemoteNetworkFactory,
        create: bool,
    ) -> Result<Self, RemoteRaftError> {
        if id == 0 || network.local_id() != id {
            return Err(RemoteRaftError::InvalidTopology);
        }
        let stores = spawn_blocking(move || {
            std::fs::create_dir_all(&root)?;
            let log_root = root.join("log");
            let state_root = root.join("state-machine");
            if create {
                Ok::<_, io::Error>((
                    DurableLogStore::create(log_root)?,
                    DurableStateMachine::create(state_root)?,
                ))
            } else {
                Ok::<_, io::Error>((
                    DurableLogStore::open_existing(log_root)?,
                    DurableStateMachine::open_existing(state_root)?,
                ))
            }
        })
        .await
        .map_err(|error| RemoteRaftError::Io(error.to_string()))?
        .map_err(|error| RemoteRaftError::Io(error.to_string()))?;
        let (log_store, state_machine) = stores;
        let config = production_config()?;
        let rpc_factory = network.clone();
        let raft = DurableRaft::new(
            id,
            Arc::new(config),
            network,
            log_store,
            state_machine.clone(),
        )
        .await
        .map_err(|error| RemoteRaftError::Consensus(error.to_string()))?;
        let rpc_service = rpc_factory.rpc_service(raft.clone());
        Ok(Self {
            id,
            raft,
            state_machine,
            rpc_service,
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn rpc_service(&self) -> RaftRpcService {
        self.rpc_service.clone()
    }

    pub async fn initialize_single(&self) -> Result<(), RemoteRaftError> {
        self.raft
            .initialize(BTreeMap::from([(self.id, ())]))
            .await
            .map(|_| ())
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
    }

    pub async fn add_learner(&self, id: u64) -> Result<(), RemoteRaftError> {
        if id == 0 || id == self.id {
            return Err(RemoteRaftError::InvalidTopology);
        }
        self.raft
            .add_learner(id, (), true)
            .await
            .map(|_| ())
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
    }

    pub async fn change_membership(&self, voters: BTreeSet<u64>) -> Result<(), RemoteRaftError> {
        if voters.len() < 3 || !voters.contains(&self.id) || voters.contains(&0) {
            return Err(RemoteRaftError::InvalidTopology);
        }
        self.raft
            .change_membership(voters, false)
            .await
            .map(|_| ())
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
    }

    pub async fn current_leader(&self) -> Option<u64> {
        self.raft.current_leader().await
    }

    pub async fn replicate(
        &self,
        client_serial: u64,
        envelope: &ReplicatedEnvelope,
    ) -> Result<CommitReceipt, RaftRuntimeError> {
        if client_serial == 0 {
            return Err(RaftRuntimeError::InvalidSerial);
        }
        let response = self
            .raft
            .client_write(ClientRequest {
                client: "heptabao-production-ha".to_owned(),
                serial: client_serial,
                status: envelope.encoded_status(),
            })
            .await
            .map_err(|error| RaftRuntimeError::Consensus(error.to_string()))?;
        Ok(CommitReceipt {
            leader_id: self.id,
            log_index: response.log_id.index,
            envelope_digest: envelope.digest,
        })
    }

    pub async fn ensure_linearizable(&self) -> Result<(), RemoteRaftError> {
        self.raft
            .ensure_linearizable(ReadPolicy::ReadIndex)
            .await
            .map(|_| ())
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
    }

    pub async fn trigger_snapshot(&self) -> Result<(), RemoteRaftError> {
        self.raft
            .trigger()
            .snapshot()
            .await
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
    }

    pub async fn applied_state(&self) -> MemStoreStateMachine {
        self.state_machine.get_state_machine().await
    }

    pub async fn shutdown(self) -> Result<(), RemoteRaftError> {
        self.raft
            .shutdown()
            .await
            .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
    }
}

fn production_config() -> Result<Config, RemoteRaftError> {
    Config {
        heartbeat_interval: 40,
        election_timeout_min: 120,
        election_timeout_max: 240,
        snapshot_policy: SnapshotPolicy::LogsSinceLast(3),
        max_in_snapshot_log_to_keep: 0,
        enable_pre_vote: Some(true),
        ..Config::default()
    }
    .validate()
    .map_err(|error| RemoteRaftError::Consensus(error.to_string()))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn network_error(message: impl Into<String>) -> RPCError<TypeConfig> {
    RPCError::Network(NetworkError::from_string(message.into()))
}

fn remote_network_error(error: RemoteRaftError) -> RPCError<TypeConfig> {
    network_error(error.to_string())
}
