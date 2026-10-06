use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::state_machine::TypeConfig;
use futures::future::BoxFuture;
use openraft::errors::{
    NetworkError, RPCError, RaftError, ReplicationClosed, StreamingError, Unreachable,
};
use openraft::network::v2::RaftNetworkV2;
use openraft::network::{RPCOption, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, SnapshotResponse, TransferLeaderRequest,
    TransferLeaderResponse, VoteRequest, VoteResponse,
};
use openraft::type_config::alias::{SnapshotOf, VoteOf};
use openraft::{OptionalSend, Snapshot};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;

use super::snapshot::{
    IncomingSnapshot, MAX_INCOMING_SNAPSHOTS, MAX_REMOTE_RPC_BYTES, MAX_REMOTE_SNAPSHOT_BYTES,
    SNAPSHOT_CHUNK_BYTES, SnapshotChunkAck, SnapshotChunkWire, crc32, snapshot_transfer_id,
};
use crate::network::DurableRaft;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RaftRpcKind {
    AppendEntries,
    Vote,
    PreVote,
    SnapshotChunk,
    TransferLeader,
    ReadIndex,
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
    read_sequence: Arc<AtomicU64>,
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
        if local_id == 0 || peers.len() < 3 || !peers.contains(&local_id) || peers.contains(&0) {
            return Err(RemoteRaftError::InvalidTopology);
        }
        Ok(Self {
            local_id,
            peers: Arc::new(peers),
            transport,
            read_sequence: Arc::new(AtomicU64::new(1)),
        })
    }

    pub(super) fn enrolled_peer_ids(&self) -> &BTreeSet<u64> {
        &self.peers
    }

    pub fn local_id(&self) -> u64 {
        self.local_id
    }

    pub(super) async fn read_index(
        &self,
        leader: u64,
        term: u64,
        remaining: Duration,
    ) -> Result<super::follower_read::ReadIndexWitness, RemoteRaftError> {
        use super::follower_read::{ReadIndexFailure, ReadIndexRequest, ReadIndexWitness};
        if leader == self.local_id || !self.peers.contains(&leader) || remaining.is_zero() {
            return Err(RemoteRaftError::InvalidRpc);
        }
        let request_id = self
            .read_sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| RemoteRaftError::InvalidRpc)?;
        let budget_ms =
            u64::try_from(remaining.as_millis()).map_err(|_| RemoteRaftError::InvalidRpc)?;
        if budget_ms == 0 {
            return Err(RemoteRaftError::Consensus(
                super::node::READ_INDEX_TIMEOUT.into(),
            ));
        }
        let request = ReadIndexRequest {
            leader,
            term,
            request_id,
            budget_ms,
        };
        let payload = serde_json::to_vec(&request).map_err(|_| RemoteRaftError::InvalidRpc)?;
        let response = self
            .transport
            .exchange(
                self.local_id,
                leader,
                RaftRpcKind::ReadIndex,
                payload,
                remaining,
            )
            .await?;
        if response.is_empty() || response.len() > 4096 {
            return Err(RemoteRaftError::InvalidRpc);
        }
        let witness: Result<ReadIndexWitness, ReadIndexFailure> =
            serde_json::from_slice(&response).map_err(|_| RemoteRaftError::InvalidRpc)?;
        let witness = witness.map_err(ReadIndexFailure::remote)?;
        if witness.request_id != request_id || witness.leader != leader || witness.term != term {
            return Err(RemoteRaftError::InvalidRpc);
        }
        Ok(witness)
    }

    pub(crate) fn rpc_service(&self, raft: DurableRaft) -> RaftRpcService {
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
            append_payload_target: crate::replication_bounds::TARGET_APPEND_RPC_BYTES,
        }
    }
}

pub struct RemoteNetwork {
    source: u64,
    target: u64,
    peers: Arc<BTreeSet<u64>>,
    transport: Arc<dyn RaftPeerRpc>,
    // A timeout on a backlog must not replay the same oversized batch forever.
    // This target is local to this peer; the hard wire limit and RPC TTL stay fixed.
    append_payload_target: usize,
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
        Resp: DeserializeOwned,
    {
        use super::rpc_observation::{RpcAttempt, Stage};
        let started = std::time::Instant::now();
        let payload =
            serde_json::to_vec(request).map_err(|error| network_error(error.to_string()))?;
        let observation = RpcAttempt {
            source: self.source,
            target: self.target,
            kind,
            bytes: payload.len(),
            budget: option.soft_ttl(),
            started,
        };
        let response = self
            .exchange(kind, payload, option.soft_ttl())
            .await
            .inspect_err(|_| observation.failed(Stage::Transport))?;
        let result: Result<Resp, RaftError<TypeConfig>> = serde_json::from_slice(&response)
            .inspect_err(|_| observation.failed(Stage::Decode))
            .map_err(|error| network_error(error.to_string()))?;
        result
            .inspect_err(|_| observation.failed(Stage::RemoteRaft))
            .map_err(|error| RPCError::Unreachable(Unreachable::new(&error)))
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
        let meta_bytes =
            serde_json::to_vec(&snapshot.meta).map_err(|error| network_error(error.to_string()))?;
        let vote_bytes =
            serde_json::to_vec(&vote).map_err(|error| network_error(error.to_string()))?;
        let transfer_id = snapshot_transfer_id(&meta_bytes, &vote_bytes, data.len());
        let whole_crc32 = crc32(&data);
        let chunk_count = data.len().max(1).div_ceil(SNAPSHOT_CHUNK_BYTES);
        let total_chunks = u32::try_from(chunk_count)
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
            use super::rpc_observation::{RpcAttempt, Stage};
            let started = std::time::Instant::now();
            let payload =
                serde_json::to_vec(&request).map_err(|error| network_error(error.to_string()))?;
            let observation = RpcAttempt {
                source: self.source,
                target: self.target,
                kind: RaftRpcKind::SnapshotChunk,
                bytes: payload.len(),
                budget: option.soft_ttl(),
                started,
            };
            let response = self
                .exchange(RaftRpcKind::SnapshotChunk, payload, option.soft_ttl())
                .await
                .inspect_err(|_| observation.failed(Stage::Transport))?;
            let ack: SnapshotChunkAck = serde_json::from_slice(&response)
                .inspect_err(|_| observation.failed(Stage::Decode))
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
        mut request: AppendEntriesRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<TypeConfig>, RPCError<TypeConfig>> {
        let entries = std::mem::take(&mut request.entries);
        let mut bytes = serde_json::to_vec(&request)
            .map_err(|error| network_error(error.to_string()))?
            .len();
        let mut keep = 0;
        for entry in &entries {
            let entry_bytes = serde_json::to_vec(entry)
                .map_err(|error| network_error(error.to_string()))?
                .len();
            let next = bytes.saturating_add(entry_bytes + usize::from(keep != 0));
            // Always retain a legal singleton, including accepted entries larger
            // than the soft batching target. Preserve a contiguous log prefix.
            if keep != 0 && next > self.append_payload_target {
                break;
            }
            bytes = next;
            keep += 1;
        }
        let shortened = keep < entries.len();
        request.entries = entries;
        request.entries.truncate(keep);
        let last_sent = request.entries.last().map(|entry| entry.log_id);
        let started = std::time::Instant::now();
        match self
            .rpc(RaftRpcKind::AppendEntries, &request, &option)
            .await
        {
            Ok(AppendEntriesResponse::Success) if shortened => {
                // OpenRaft must retry the suffix: Success would falsely confirm
                // entries that never crossed the authenticated peer transport.
                Ok(AppendEntriesResponse::PartialSuccess(last_sent))
            }
            Ok(response) => Ok(response),
            Err(error) => {
                if request.entries.len() > 1 && started.elapsed() >= option.soft_ttl() {
                    self.append_payload_target = (self.append_payload_target / 2).max(16 * 1024);
                }
                Err(error)
            }
        }
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

    async fn transfer_leader(
        &mut self,
        request: TransferLeaderRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<TransferLeaderResponse<TypeConfig>, RPCError<TypeConfig>> {
        self.rpc(RaftRpcKind::TransferLeader, &request, &option)
            .await
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

#[derive(Clone)]
pub struct RaftRpcService {
    pub(super) local_id: u64,
    peers: Arc<BTreeSet<u64>>,
    pub(super) raft: DurableRaft,
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
            RaftRpcKind::ReadIndex => self.handle_read_index(payload).await,
            RaftRpcKind::AppendEntries => {
                let request =
                    serde_json::from_slice(&payload).map_err(|_| RemoteRaftError::InvalidRpc)?;
                serde_json::to_vec(&self.raft.append_entries(request).await)
                    .map_err(|_| RemoteRaftError::InvalidRpc)
            }
            RaftRpcKind::Vote => {
                let request =
                    serde_json::from_slice(&payload).map_err(|_| RemoteRaftError::InvalidRpc)?;
                serde_json::to_vec(&self.raft.vote(request).await)
                    .map_err(|_| RemoteRaftError::InvalidRpc)
            }
            RaftRpcKind::PreVote => {
                let request =
                    serde_json::from_slice(&payload).map_err(|_| RemoteRaftError::InvalidRpc)?;
                serde_json::to_vec(&self.raft.pre_vote(request).await)
                    .map_err(|_| RemoteRaftError::InvalidRpc)
            }
            RaftRpcKind::SnapshotChunk => {
                let request: SnapshotChunkWire = serde_json::from_slice(&payload)
                    .map_err(|_| RemoteRaftError::InvalidSnapshot)?;
                let ack = self.handle_snapshot_chunk(source, request).await?;
                serde_json::to_vec(&ack).map_err(|_| RemoteRaftError::InvalidSnapshot)
            }
            RaftRpcKind::TransferLeader => {
                let request: TransferLeaderRequest<TypeConfig> =
                    serde_json::from_slice(&payload).map_err(|_| RemoteRaftError::InvalidRpc)?;
                // The authenticated RPC recipient remains this local node.
                // OpenRaft broadcasts the SAME assigned next-leader request to
                // every voter; other voters must clear their current leader lease.
                // Bind the claimed old leader to transport source and the assigned
                // successor to configured peers, then retain Raft's vote/log checks.
                if request.from_leader().leader_id.node_id != source
                    || *request.to_node_id() == source
                    || !self.peers.contains(request.to_node_id())
                {
                    return Err(RemoteRaftError::InvalidRpc);
                }
                let result = self
                    .raft
                    .handle_transfer_leader(request)
                    .await
                    .map_err(RaftError::<TypeConfig>::Fatal);
                serde_json::to_vec(&result).map_err(|_| RemoteRaftError::InvalidRpc)
            }
        }
    }

    async fn handle_snapshot_chunk(
        &self,
        source: u64,
        request: SnapshotChunkWire,
    ) -> Result<SnapshotChunkAck, RemoteRaftError> {
        let total_bytes =
            usize::try_from(request.total_bytes).map_err(|_| RemoteRaftError::InvalidSnapshot)?;
        if request.transfer_id.is_empty()
            || request.transfer_id.len() > 128
            || request.total_chunks == 0
            || request.ordinal >= request.total_chunks
            || total_bytes > MAX_REMOTE_SNAPSHOT_BYTES
            || request.chunk.len() > SNAPSHOT_CHUNK_BYTES
            || request.chunk.len() > total_bytes
            || (request.total_chunks == 1 && request.chunk.len() != total_bytes)
            || (request.total_chunks > 1 && request.chunk.is_empty())
            || crc32(&request.chunk) != request.chunk_crc32
        {
            return Err(RemoteRaftError::InvalidSnapshot);
        }

        let key = (source, request.transfer_id.clone());
        let completed = {
            let mut snapshots = self.incoming_snapshots.lock().await;
            if request.ordinal == 0 {
                let vote = request.vote.ok_or(RemoteRaftError::InvalidSnapshot)?;
                let meta = request.meta.ok_or(RemoteRaftError::InvalidSnapshot)?;
                // Validate the authenticated sender and the complete prefix
                // identity before releasing any already-admitted receive state.
                let meta_bytes =
                    serde_json::to_vec(&meta).map_err(|_| RemoteRaftError::InvalidSnapshot)?;
                let vote_bytes =
                    serde_json::to_vec(&vote).map_err(|_| RemoteRaftError::InvalidSnapshot)?;
                if !vote.committed
                    || vote.leader_id.node_id != source
                    || request.transfer_id
                        != snapshot_transfer_id(&meta_bytes, &vote_bytes, total_bytes)
                    || (request.total_chunks == 1 && request.whole_crc32 != request.chunk_crc32)
                    || snapshots.values().any(|pending| {
                        matches!(
                            vote.partial_cmp(&pending.vote),
                            None | Some(std::cmp::Ordering::Less)
                        ) || (vote == pending.vote
                            && (meta.last_log_id < pending.meta.last_log_id
                                || (meta.last_log_id == pending.meta.last_log_id
                                    && (meta != pending.meta
                                        || total_bytes != pending.total_bytes
                                        || request.whole_crc32 != pending.whole_crc32))))
                    })
                {
                    return Err(RemoteRaftError::InvalidSnapshot);
                }
                // A restart supersedes this sender's incomplete prefix. A new
                // leader also retires older-vote streams; late chunks can no
                // longer append to them. Keep the original aggregate bound.
                snapshots.retain(|(peer, _), pending| {
                    *peer != source
                        && pending.vote.partial_cmp(&vote) != Some(std::cmp::Ordering::Less)
                });
                if snapshots.len() >= MAX_INCOMING_SNAPSHOTS {
                    return Err(RemoteRaftError::InvalidSnapshot);
                }
                snapshots.insert(
                    key.clone(),
                    IncomingSnapshot {
                        total_chunks: request.total_chunks,
                        next_ordinal: 0,
                        vote,
                        meta,
                        total_bytes,
                        whole_crc32: request.whole_crc32,
                        data: Vec::with_capacity(request.chunk.len()),
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
                || snapshot.data.len().saturating_add(request.chunk.len()) > snapshot.total_bytes
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

fn network_error(message: impl Into<String>) -> RPCError<TypeConfig> {
    RPCError::Network(NetworkError::from_string(message.into()))
}

fn remote_network_error(error: RemoteRaftError) -> RPCError<TypeConfig> {
    network_error(error.to_string())
}

#[cfg(test)]
mod append_prefix_tests {
    use super::*;
    use openraft::alias::EntryOf;
    use openraft::{EntryPayload, LogId};

    #[derive(Debug, Default)]
    struct Recorder {
        received: Mutex<Vec<AppendEntriesRequest<TypeConfig>>>,
    }

    impl RaftPeerRpc for Arc<Recorder> {
        fn exchange(
            &self,
            _source: u64,
            _target: u64,
            _kind: RaftRpcKind,
            payload: Vec<u8>,
            _timeout: Duration,
        ) -> BoxFuture<'static, Result<Vec<u8>, RemoteRaftError>> {
            let recorder = self.clone();
            Box::pin(async move {
                let request =
                    serde_json::from_slice(&payload).map_err(|_| RemoteRaftError::InvalidRpc)?;
                recorder.received.lock().await.push(request);
                let response: Result<AppendEntriesResponse<TypeConfig>, RaftError<TypeConfig>> =
                    Ok(AppendEntriesResponse::Success);
                serde_json::to_vec(&response).map_err(|_| RemoteRaftError::InvalidRpc)
            })
        }
    }

    fn log_id(index: u64) -> openraft::alias::LogIdOf<TypeConfig> {
        LogId {
            leader_id: openraft::impls::leader_id_adv::LeaderId {
                term: 2,
                node_id: 1,
            },
            index,
        }
    }

    #[tokio::test]
    async fn successful_shortened_request_confirms_only_actual_contiguous_prefix()
    -> Result<(), Box<dyn std::error::Error>> {
        let recorder = Arc::new(Recorder::default());
        let mut factory =
            RemoteNetworkFactory::new(1, BTreeSet::from([1, 2, 3]), Arc::new(recorder.clone()))?;
        let mut network = factory.new_client(2, &()).await;
        network.append_payload_target = 18 * 1024;
        let vote = VoteOf::<TypeConfig>::new_committed(2, 1);
        let entries = (6..=8)
            .map(|index| EntryOf::<TypeConfig> {
                log_id: log_id(index),
                payload: EntryPayload::Normal(
                    openraft_memstore::ClientRequest {
                        client: "synthetic-prefix".into(),
                        serial: index,
                        status: "x".repeat(8 * 1024),
                    }
                    .into(),
                ),
            })
            .collect();
        let response = network
            .append_entries(
                AppendEntriesRequest {
                    vote,
                    prev_log_id: Some(log_id(5)),
                    entries,
                    leader_commit: Some(log_id(8)),
                },
                RPCOption::new(Duration::from_millis(150)),
            )
            .await?;
        assert!(
            matches!(response, AppendEntriesResponse::PartialSuccess(Some(id)) if id == log_id(7))
        );
        let received = recorder.received.lock().await;
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].vote, vote);
        assert_eq!(received[0].prev_log_id, Some(log_id(5)));
        assert_eq!(received[0].leader_commit, Some(log_id(8)));
        assert_eq!(
            received[0]
                .entries
                .iter()
                .map(|entry| entry.log_id)
                .collect::<Vec<_>>(),
            vec![log_id(6), log_id(7)]
        );
        Ok(())
    }
}
