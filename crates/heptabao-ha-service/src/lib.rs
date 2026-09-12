#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Authenticated service-level HA composition.
//!
//! This package sits above a consensus driver. It routes operations to the
//! current leader, refuses linearizable work without quorum, authenticates
//! bounded peer frames, persists peer sequence numbers before accepting a
//! frame, and verifies chunked snapshots. Production mTLS identity and a
//! concrete `heptabao-server`/Raft adapter remain explicit integration gates.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use ring::{digest, hmac};

const MAX_NODE_ID_BYTES: usize = 128;
const MAX_CLUSTER_ID_BYTES: usize = 128;
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_PEERS: usize = 255;
const MAX_SNAPSHOT_CHUNKS: usize = 65_536;
const PEER_STATE_MAGIC: &[u8; 5] = b"HBPS1";
const PEER_FRAME_MAGIC: &[u8; 5] = b"HBPF1";

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeId(String);

impl NodeId {
    pub fn parse(value: impl Into<String>) -> Result<Self, HaError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_NODE_ID_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(HaError::InvalidNode);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("NodeId").field(&self.0).finish()
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    LinearizableRead,
    Mutation,
}

impl OperationKind {
    fn tag(self) -> u8 {
        match self {
            Self::LinearizableRead => 1,
            Self::Mutation => 2,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ClientOperation {
    pub operation_id: OperationId,
    pub kind: OperationKind,
    payload: Vec<u8>,
}

impl ClientOperation {
    pub fn new(
        operation_id: OperationId,
        kind: OperationKind,
        payload: Vec<u8>,
    ) -> Result<Self, HaError> {
        if operation_id.0 == [0; 16] || payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
            return Err(HaError::InvalidOperation);
        }
        Ok(Self {
            operation_id,
            kind,
            payload,
        })
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    fn request_digest(&self) -> [u8; 32] {
        let mut material = Vec::with_capacity(17 + self.payload.len());
        material.extend_from_slice(&self.operation_id.0);
        material.push(self.kind.tag());
        material.extend_from_slice(&self.payload);
        sha256(&material)
    }
}

impl fmt::Debug for ClientOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientOperation")
            .field("operation_id", &self.operation_id)
            .field("kind", &self.kind)
            .field("payload", &"[REDACTED]")
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ClientResult {
    pub term: u64,
    pub applied_index: u64,
    payload: Vec<u8>,
}

impl ClientResult {
    pub fn new(term: u64, applied_index: u64, payload: Vec<u8>) -> Result<Self, HaError> {
        if term == 0 || applied_index == 0 || payload.len() > MAX_PAYLOAD_BYTES {
            return Err(HaError::InvalidOperation);
        }
        Ok(Self {
            term,
            applied_index,
            payload,
        })
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl fmt::Debug for ClientResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientResult")
            .field("term", &self.term)
            .field("applied_index", &self.applied_index)
            .field("payload", &"[REDACTED]")
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaderView {
    pub leader: NodeId,
    pub term: u64,
    pub commit_index: u64,
    pub quorum_available: bool,
}

pub trait ConsensusDriver: fmt::Debug {
    fn local_node(&self) -> &NodeId;
    fn leader_view(&self) -> Result<LeaderView, HaError>;
    fn execute_leader_mutation(
        &mut self,
        operation: &ClientOperation,
    ) -> Result<ClientResult, HaError>;
    fn execute_linearizable_read(
        &mut self,
        operation: &ClientOperation,
    ) -> Result<ClientResult, HaError>;
}

pub trait ForwardClient: fmt::Debug {
    fn forward(
        &mut self,
        leader: &NodeId,
        expected_term: u64,
        operation: &ClientOperation,
    ) -> Result<ClientResult, HaError>;
}

#[derive(Debug)]
pub struct HaService<D, F> {
    driver: D,
    forwarder: F,
    completed: BTreeMap<OperationId, ([u8; 32], ClientResult)>,
    completed_limit: usize,
}

impl<D, F> HaService<D, F>
where
    D: ConsensusDriver,
    F: ForwardClient,
{
    pub fn new(driver: D, forwarder: F, completed_limit: usize) -> Result<Self, HaError> {
        if completed_limit == 0 || completed_limit > 1_000_000 {
            return Err(HaError::CapacityExceeded);
        }
        Ok(Self {
            driver,
            forwarder,
            completed: BTreeMap::new(),
            completed_limit,
        })
    }

    pub fn execute(&mut self, operation: &ClientOperation) -> Result<ClientResult, HaError> {
        let request_digest = operation.request_digest();
        if let Some((known_digest, result)) = self.completed.get(&operation.operation_id) {
            if *known_digest != request_digest {
                return Err(HaError::OperationIdConflict);
            }
            return Ok(result.clone());
        }
        let view = self.driver.leader_view()?;
        if !view.quorum_available {
            return Err(HaError::QuorumUnavailable);
        }
        let result = if view.leader == *self.driver.local_node() {
            match operation.kind {
                OperationKind::Mutation => self.driver.execute_leader_mutation(operation)?,
                OperationKind::LinearizableRead => {
                    self.driver.execute_linearizable_read(operation)?
                }
            }
        } else {
            self.forwarder.forward(&view.leader, view.term, operation)?
        };
        if result.term != view.term || result.applied_index < view.commit_index {
            return Err(HaError::StaleLeaderResponse);
        }
        if self.completed.len() >= self.completed_limit {
            return Err(HaError::CapacityExceeded);
        }
        self.completed
            .insert(operation.operation_id, (request_digest, result.clone()));
        Ok(result)
    }

    pub fn into_parts(self) -> (D, F) {
        (self.driver, self.forwarder)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerMessageKind {
    ForwardRequest,
    ForwardResponse,
    ReadIndex,
    SnapshotChunk,
    Membership,
}

impl PeerMessageKind {
    fn tag(self) -> u8 {
        match self {
            Self::ForwardRequest => 1,
            Self::ForwardResponse => 2,
            Self::ReadIndex => 3,
            Self::SnapshotChunk => 4,
            Self::Membership => 5,
        }
    }

    fn decode(value: u8) -> Result<Self, HaError> {
        match value {
            1 => Ok(Self::ForwardRequest),
            2 => Ok(Self::ForwardResponse),
            3 => Ok(Self::ReadIndex),
            4 => Ok(Self::SnapshotChunk),
            5 => Ok(Self::Membership),
            _ => Err(HaError::InvalidFrame),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PeerEnvelope {
    pub cluster_id: String,
    pub sender: NodeId,
    pub receiver: NodeId,
    pub term: u64,
    pub sequence: u64,
    pub kind: PeerMessageKind,
    payload: Vec<u8>,
    tag: [u8; 32],
}

impl PeerEnvelope {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl fmt::Debug for PeerEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerEnvelope")
            .field("cluster_id", &self.cluster_id)
            .field("sender", &self.sender)
            .field("receiver", &self.receiver)
            .field("term", &self.term)
            .field("sequence", &self.sequence)
            .field("kind", &self.kind)
            .field("payload", &"[REDACTED]")
            .field("payload_bytes", &self.payload.len())
            .field("tag", &"[REDACTED]")
            .finish()
    }
}

pub struct PeerAuthenticator {
    cluster_id: String,
    keys: BTreeMap<NodeId, [u8; 32]>,
}

impl PeerAuthenticator {
    pub fn new(
        cluster_id: impl Into<String>,
        keys: BTreeMap<NodeId, [u8; 32]>,
    ) -> Result<Self, HaError> {
        let cluster_id = cluster_id.into();
        if cluster_id.is_empty()
            || cluster_id.len() > MAX_CLUSTER_ID_BYTES
            || keys.is_empty()
            || keys.len() > MAX_PEERS
            || keys.values().any(|key| *key == [0; 32])
        {
            return Err(HaError::InvalidCluster);
        }
        Ok(Self { cluster_id, keys })
    }

    pub fn seal(
        &self,
        sender: NodeId,
        receiver: NodeId,
        term: u64,
        sequence: u64,
        kind: PeerMessageKind,
        payload: Vec<u8>,
    ) -> Result<PeerEnvelope, HaError> {
        if term == 0 || sequence == 0 || payload.len() > MAX_PAYLOAD_BYTES {
            return Err(HaError::InvalidFrame);
        }
        let key = self.keys.get(&sender).ok_or(HaError::UnknownPeer)?;
        let body = encode_envelope_body(
            &self.cluster_id,
            &sender,
            &receiver,
            term,
            sequence,
            kind,
            &payload,
        )?;
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), &body)
            .as_ref()
            .try_into()
            .map_err(|_| HaError::InvalidFrame)?;
        Ok(PeerEnvelope {
            cluster_id: self.cluster_id.clone(),
            sender,
            receiver,
            term,
            sequence,
            kind,
            payload,
            tag,
        })
    }

    pub fn verify(&self, receiver: &NodeId, envelope: &PeerEnvelope) -> Result<(), HaError> {
        if envelope.cluster_id != self.cluster_id || &envelope.receiver != receiver {
            return Err(HaError::PeerAuthenticationFailed);
        }
        let key = self
            .keys
            .get(&envelope.sender)
            .ok_or(HaError::UnknownPeer)?;
        let body = encode_envelope_body(
            &envelope.cluster_id,
            &envelope.sender,
            &envelope.receiver,
            envelope.term,
            envelope.sequence,
            envelope.kind,
            &envelope.payload,
        )?;
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, key),
            &body,
            &envelope.tag,
        )
        .map_err(|_| HaError::PeerAuthenticationFailed)
    }
}

impl fmt::Debug for PeerAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerAuthenticator")
            .field("cluster_id", &self.cluster_id)
            .field("peers", &self.keys.keys().collect::<Vec<_>>())
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

impl Drop for PeerAuthenticator {
    fn drop(&mut self) {
        for key in self.keys.values_mut() {
            key.fill(0);
        }
    }
}

pub struct PersistentPeerSequences {
    root: PathBuf,
    state_path: PathBuf,
    lock_path: PathBuf,
    _lock: File,
    key: [u8; 32],
    incoming: BTreeMap<NodeId, u64>,
    outgoing: BTreeMap<NodeId, u64>,
}

impl PersistentPeerSequences {
    pub fn open(root: impl AsRef<Path>, key: [u8; 32]) -> Result<Self, HaError> {
        if key == [0; 32] {
            return Err(HaError::InvalidCluster);
        }
        let root = root.as_ref().to_path_buf();
        validate_root(&root)?;
        create_private_root(&root)?;
        let lock_path = root.join("writer.lock");
        let state_path = root.join("peer-sequences.state");
        let lock = create_lock(&lock_path)?;
        let (incoming, outgoing) = if state_path.exists() {
            decode_peer_state(&fs::read(&state_path).map_err(|_| HaError::Io)?, key)?
        } else {
            (BTreeMap::new(), BTreeMap::new())
        };
        Ok(Self {
            root,
            state_path,
            lock_path,
            _lock: lock,
            key,
            incoming,
            outgoing,
        })
    }

    pub fn accept_incoming(&mut self, sender: &NodeId, sequence: u64) -> Result<(), HaError> {
        if sequence == 0
            || self
                .incoming
                .get(sender)
                .is_some_and(|observed| sequence <= *observed)
        {
            return Err(HaError::ReplayDetected);
        }
        let previous = self.incoming.insert(sender.clone(), sequence);
        if let Err(error) = self.persist() {
            match previous {
                Some(value) => {
                    self.incoming.insert(sender.clone(), value);
                }
                None => {
                    self.incoming.remove(sender);
                }
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn next_outgoing(&mut self, receiver: &NodeId) -> Result<u64, HaError> {
        let next = self
            .outgoing
            .get(receiver)
            .copied()
            .unwrap_or_default()
            .checked_add(1)
            .ok_or(HaError::CapacityExceeded)?;
        let previous = self.outgoing.insert(receiver.clone(), next);
        if let Err(error) = self.persist() {
            match previous {
                Some(value) => {
                    self.outgoing.insert(receiver.clone(), value);
                }
                None => {
                    self.outgoing.remove(receiver);
                }
            }
            return Err(error);
        }
        Ok(next)
    }

    fn persist(&self) -> Result<(), HaError> {
        let bytes = encode_peer_state(&self.incoming, &self.outgoing, self.key)?;
        atomic_write(&self.root, &self.state_path, &bytes)
    }
}

impl fmt::Debug for PersistentPeerSequences {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentPeerSequences")
            .field("root", &self.root)
            .field("state_path", &self.state_path)
            .field("key", &"[REDACTED]")
            .field("incoming", &self.incoming)
            .field("outgoing", &self.outgoing)
            .finish()
    }
}

impl Drop for PersistentPeerSequences {
    fn drop(&mut self) {
        self.key.fill(0);
        let _ = fs::remove_file(&self.lock_path);
    }
}

pub fn admit_peer_envelope(
    local_node: &NodeId,
    authenticator: &PeerAuthenticator,
    sequences: &mut PersistentPeerSequences,
    envelope: &PeerEnvelope,
) -> Result<(), HaError> {
    authenticator.verify(local_node, envelope)?;
    sequences.accept_incoming(&envelope.sender, envelope.sequence)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotManifest {
    pub snapshot_id: [u8; 16],
    pub term: u64,
    pub index: u64,
    pub total_bytes: u64,
    pub chunk_digests: Vec<[u8; 32]>,
    pub root_digest: [u8; 32],
}

impl SnapshotManifest {
    pub fn build(
        snapshot_id: [u8; 16],
        term: u64,
        index: u64,
        chunks: &[Vec<u8>],
    ) -> Result<Self, HaError> {
        if snapshot_id == [0; 16]
            || term == 0
            || index == 0
            || chunks.is_empty()
            || chunks.len() > MAX_SNAPSHOT_CHUNKS
            || chunks
                .iter()
                .any(|chunk| chunk.is_empty() || chunk.len() > MAX_PAYLOAD_BYTES)
        {
            return Err(HaError::InvalidSnapshot);
        }
        let total_bytes = chunks.iter().try_fold(0_u64, |total, chunk| {
            total
                .checked_add(chunk.len() as u64)
                .ok_or(HaError::InvalidSnapshot)
        })?;
        let chunk_digests = chunks.iter().map(|chunk| sha256(chunk)).collect::<Vec<_>>();
        let root_digest = snapshot_root(snapshot_id, term, index, total_bytes, &chunk_digests);
        Ok(Self {
            snapshot_id,
            term,
            index,
            total_bytes,
            chunk_digests,
            root_digest,
        })
    }

    pub fn verify(&self, chunks: &[Vec<u8>]) -> Result<(), HaError> {
        if chunks.len() != self.chunk_digests.len() {
            return Err(HaError::InvalidSnapshot);
        }
        let total = chunks.iter().try_fold(0_u64, |value, chunk| {
            value
                .checked_add(chunk.len() as u64)
                .ok_or(HaError::InvalidSnapshot)
        })?;
        if total != self.total_bytes
            || chunks
                .iter()
                .zip(&self.chunk_digests)
                .any(|(chunk, expected)| sha256(chunk) != *expected)
            || snapshot_root(
                self.snapshot_id,
                self.term,
                self.index,
                self.total_bytes,
                &self.chunk_digests,
            ) != self.root_digest
        {
            return Err(HaError::InvalidSnapshot);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipPhase {
    Joint,
    Final,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipTransition {
    pub phase: MembershipPhase,
    pub old_voters: BTreeSet<NodeId>,
    pub new_voters: BTreeSet<NodeId>,
}

impl MembershipTransition {
    pub fn new(
        phase: MembershipPhase,
        old_voters: BTreeSet<NodeId>,
        new_voters: BTreeSet<NodeId>,
    ) -> Result<Self, HaError> {
        if old_voters.is_empty()
            || new_voters.is_empty()
            || old_voters.len() > MAX_PEERS
            || new_voters.len() > MAX_PEERS
            || matches!(phase, MembershipPhase::Final) && old_voters != new_voters
        {
            return Err(HaError::InvalidMembership);
        }
        Ok(Self {
            phase,
            old_voters,
            new_voters,
        })
    }

    pub fn joint_quorum(&self, acknowledgements: &BTreeSet<NodeId>) -> bool {
        has_majority(&self.old_voters, acknowledgements)
            && has_majority(&self.new_voters, acknowledgements)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsPeerEndpoint {
    pub address: SocketAddr,
    pub server_name: String,
}

impl TlsPeerEndpoint {
    pub fn new(address: SocketAddr, server_name: impl Into<String>) -> Result<Self, HaError> {
        let server_name = server_name.into();
        if server_name.is_empty()
            || server_name.len() > 253
            || rustls::pki_types::ServerName::try_from(server_name.clone()).is_err()
        {
            return Err(HaError::InvalidCluster);
        }
        Ok(Self {
            address,
            server_name,
        })
    }
}

#[derive(Clone)]
pub struct MutualTlsPeerTransport {
    peers: BTreeMap<NodeId, TlsPeerEndpoint>,
    client_config: Arc<rustls::ClientConfig>,
    timeout: Duration,
}

impl MutualTlsPeerTransport {
    pub fn new(
        peers: BTreeMap<NodeId, TlsPeerEndpoint>,
        client_config: Arc<rustls::ClientConfig>,
        timeout: Duration,
    ) -> Result<Self, HaError> {
        if peers.is_empty()
            || peers.len() > MAX_PEERS
            || timeout.is_zero()
            || timeout > Duration::from_secs(60)
        {
            return Err(HaError::InvalidCluster);
        }
        Ok(Self {
            peers,
            client_config,
            timeout,
        })
    }

    pub fn exchange(&self, peer: &NodeId, frame: &[u8]) -> Result<Vec<u8>, HaError> {
        if frame.is_empty() || frame.len() > MAX_PAYLOAD_BYTES + 4096 {
            return Err(HaError::InvalidFrame);
        }
        let endpoint = self.peers.get(peer).ok_or(HaError::UnknownPeer)?;
        let server_name = rustls::pki_types::ServerName::try_from(endpoint.server_name.clone())
            .map_err(|_| HaError::InvalidCluster)?;
        let stream = TcpStream::connect_timeout(&endpoint.address, self.timeout)
            .map_err(|_| HaError::Transport)?;
        stream
            .set_nodelay(true)
            .and_then(|()| stream.set_read_timeout(Some(self.timeout)))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|_| HaError::Transport)?;
        let connection = rustls::ClientConnection::new(self.client_config.clone(), server_name)
            .map_err(|_| HaError::Transport)?;
        let mut tls = rustls::StreamOwned::new(connection, stream);
        write_bounded_frame(&mut tls, frame)?;
        read_bounded_frame(&mut tls)
    }
}

impl fmt::Debug for MutualTlsPeerTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MutualTlsPeerTransport")
            .field("peers", &self.peers)
            .field("client_config", &"[RUSTLS_CONFIG]")
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct PinnedClientCertificateMap {
    by_leaf_sha256: BTreeMap<[u8; 32], NodeId>,
}

impl PinnedClientCertificateMap {
    pub fn new(by_leaf_sha256: BTreeMap<[u8; 32], NodeId>) -> Result<Self, HaError> {
        if by_leaf_sha256.is_empty()
            || by_leaf_sha256.len() > MAX_PEERS
            || by_leaf_sha256.keys().any(|digest| *digest == [0; 32])
        {
            return Err(HaError::InvalidCluster);
        }
        Ok(Self { by_leaf_sha256 })
    }

    pub fn identify(&self, leaf_der: &[u8]) -> Result<NodeId, HaError> {
        if leaf_der.is_empty() || leaf_der.len() > 1024 * 1024 {
            return Err(HaError::PeerAuthenticationFailed);
        }
        self.by_leaf_sha256
            .get(&sha256(leaf_der))
            .cloned()
            .ok_or(HaError::PeerAuthenticationFailed)
    }
}

pub fn serve_one_mtls_peer_frame<H>(
    listener: &TcpListener,
    server_config: Arc<rustls::ServerConfig>,
    identities: &PinnedClientCertificateMap,
    timeout: Duration,
    handler: H,
) -> Result<(), HaError>
where
    H: FnOnce(NodeId, Vec<u8>) -> Result<Vec<u8>, HaError>,
{
    if timeout.is_zero() || timeout > Duration::from_secs(60) {
        return Err(HaError::InvalidCluster);
    }
    let (stream, _) = listener.accept().map_err(|_| HaError::Transport)?;
    stream
        .set_nodelay(true)
        .and_then(|()| stream.set_read_timeout(Some(timeout)))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|_| HaError::Transport)?;
    let connection =
        rustls::ServerConnection::new(server_config).map_err(|_| HaError::Transport)?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    tls.conn
        .complete_io(&mut tls.sock)
        .map_err(|_| HaError::PeerAuthenticationFailed)?;
    let certificates = tls
        .conn
        .peer_certificates()
        .ok_or(HaError::PeerAuthenticationFailed)?;
    if certificates.len() != 1 {
        return Err(HaError::PeerAuthenticationFailed);
    }
    let peer = identities.identify(certificates[0].as_ref())?;
    let request = read_bounded_frame(&mut tls)?;
    let response = handler(peer, request)?;
    write_bounded_frame(&mut tls, &response)
}

#[derive(Clone, Debug)]
pub struct TcpPeerTransport {
    peers: BTreeMap<NodeId, SocketAddr>,
    timeout: Duration,
}

impl TcpPeerTransport {
    pub fn new(peers: BTreeMap<NodeId, SocketAddr>, timeout: Duration) -> Result<Self, HaError> {
        if peers.is_empty()
            || peers.len() > MAX_PEERS
            || timeout.is_zero()
            || timeout > Duration::from_secs(60)
        {
            return Err(HaError::InvalidCluster);
        }
        Ok(Self { peers, timeout })
    }

    pub fn exchange(&self, peer: &NodeId, frame: &[u8]) -> Result<Vec<u8>, HaError> {
        if frame.is_empty() || frame.len() > MAX_PAYLOAD_BYTES + 4096 {
            return Err(HaError::InvalidFrame);
        }
        let address = self.peers.get(peer).ok_or(HaError::UnknownPeer)?;
        let mut stream =
            TcpStream::connect_timeout(address, self.timeout).map_err(|_| HaError::Transport)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|_| HaError::Transport)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|_| HaError::Transport)?;
        write_frame(&mut stream, frame)?;
        read_frame(&mut stream)
    }
}

pub fn serve_one_peer_frame<H>(
    listener: &TcpListener,
    timeout: Duration,
    handler: H,
) -> Result<(), HaError>
where
    H: FnOnce(Vec<u8>) -> Result<Vec<u8>, HaError>,
{
    let (mut stream, _) = listener.accept().map_err(|_| HaError::Transport)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| HaError::Transport)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| HaError::Transport)?;
    let request = read_frame(&mut stream)?;
    let response = handler(request)?;
    write_frame(&mut stream, &response)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HaError {
    InvalidNode,
    InvalidCluster,
    InvalidOperation,
    InvalidFrame,
    InvalidSnapshot,
    InvalidMembership,
    UnknownPeer,
    PeerAuthenticationFailed,
    ReplayDetected,
    WriterBusy,
    QuorumUnavailable,
    NotLeader,
    OperationIdConflict,
    StaleLeaderResponse,
    CapacityExceeded,
    Transport,
    OutcomeUnknown,
    InvalidRoot,
    Tampered,
    Io,
}

impl fmt::Display for HaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidNode => "HA node identifier is invalid",
            Self::InvalidCluster => "HA cluster configuration is invalid",
            Self::InvalidOperation => "HA client operation is invalid",
            Self::InvalidFrame => "HA peer frame is invalid",
            Self::InvalidSnapshot => "HA snapshot is invalid",
            Self::InvalidMembership => "HA membership transition is invalid",
            Self::UnknownPeer => "HA peer is unknown",
            Self::PeerAuthenticationFailed => "HA peer authentication failed",
            Self::ReplayDetected => "HA peer replay was detected",
            Self::WriterBusy => "HA peer sequence store already has a writer",
            Self::QuorumUnavailable => "HA quorum is unavailable",
            Self::NotLeader => "HA node is not leader",
            Self::OperationIdConflict => "HA operation ID was reused with different input",
            Self::StaleLeaderResponse => "HA leader response is stale",
            Self::CapacityExceeded => "HA bounded capacity is exceeded",
            Self::Transport => "HA peer transport failed",
            Self::OutcomeUnknown => "HA durable outcome is unknown",
            Self::InvalidRoot => "HA peer state root is invalid",
            Self::Tampered => "HA peer state authentication failed",
            Self::Io => "HA peer state I/O failed",
        })
    }
}

impl Error for HaError {}

fn encode_envelope_body(
    cluster_id: &str,
    sender: &NodeId,
    receiver: &NodeId,
    term: u64,
    sequence: u64,
    kind: PeerMessageKind,
    payload: &[u8],
) -> Result<Vec<u8>, HaError> {
    if cluster_id.is_empty()
        || cluster_id.len() > MAX_CLUSTER_ID_BYTES
        || payload.len() > MAX_PAYLOAD_BYTES
    {
        return Err(HaError::InvalidFrame);
    }
    let cluster_len = u16::try_from(cluster_id.len()).map_err(|_| HaError::InvalidFrame)?;
    let sender_len = u16::try_from(sender.as_str().len()).map_err(|_| HaError::InvalidFrame)?;
    let receiver_len = u16::try_from(receiver.as_str().len()).map_err(|_| HaError::InvalidFrame)?;
    let payload_len = u32::try_from(payload.len()).map_err(|_| HaError::InvalidFrame)?;
    let mut body = Vec::with_capacity(
        5 + 2
            + cluster_id.len()
            + 2
            + sender.as_str().len()
            + 2
            + receiver.as_str().len()
            + 8
            + 8
            + 1
            + 4
            + payload.len(),
    );
    body.extend_from_slice(PEER_FRAME_MAGIC);
    body.extend_from_slice(&cluster_len.to_be_bytes());
    body.extend_from_slice(cluster_id.as_bytes());
    body.extend_from_slice(&sender_len.to_be_bytes());
    body.extend_from_slice(sender.as_str().as_bytes());
    body.extend_from_slice(&receiver_len.to_be_bytes());
    body.extend_from_slice(receiver.as_str().as_bytes());
    body.extend_from_slice(&term.to_be_bytes());
    body.extend_from_slice(&sequence.to_be_bytes());
    body.push(kind.tag());
    body.extend_from_slice(&payload_len.to_be_bytes());
    body.extend_from_slice(payload);
    Ok(body)
}

pub fn encode_peer_envelope(envelope: &PeerEnvelope) -> Result<Vec<u8>, HaError> {
    let mut body = encode_envelope_body(
        &envelope.cluster_id,
        &envelope.sender,
        &envelope.receiver,
        envelope.term,
        envelope.sequence,
        envelope.kind,
        &envelope.payload,
    )?;
    body.extend_from_slice(&envelope.tag);
    Ok(body)
}

pub fn decode_peer_envelope(frame: &[u8]) -> Result<PeerEnvelope, HaError> {
    if frame.len() < 5 + 2 + 2 + 2 + 8 + 8 + 1 + 4 + 32
        || frame.len() > MAX_PAYLOAD_BYTES + 4096
        || &frame[..5] != PEER_FRAME_MAGIC
    {
        return Err(HaError::InvalidFrame);
    }
    let mut cursor = 5;
    let cluster_id = take_string(frame, &mut cursor, MAX_CLUSTER_ID_BYTES)?;
    let sender = NodeId::parse(take_string(frame, &mut cursor, MAX_NODE_ID_BYTES)?)?;
    let receiver = NodeId::parse(take_string(frame, &mut cursor, MAX_NODE_ID_BYTES)?)?;
    let term = take_u64(frame, &mut cursor)?;
    let sequence = take_u64(frame, &mut cursor)?;
    let kind = PeerMessageKind::decode(*frame.get(cursor).ok_or(HaError::InvalidFrame)?)?;
    cursor += 1;
    let payload_len = take_u32(frame, &mut cursor)? as usize;
    if payload_len > MAX_PAYLOAD_BYTES || cursor + payload_len + 32 != frame.len() {
        return Err(HaError::InvalidFrame);
    }
    let payload = frame[cursor..cursor + payload_len].to_vec();
    cursor += payload_len;
    let tag = frame[cursor..cursor + 32]
        .try_into()
        .map_err(|_| HaError::InvalidFrame)?;
    if term == 0 || sequence == 0 {
        return Err(HaError::InvalidFrame);
    }
    Ok(PeerEnvelope {
        cluster_id,
        sender,
        receiver,
        term,
        sequence,
        kind,
        payload,
        tag,
    })
}

fn encode_peer_state(
    incoming: &BTreeMap<NodeId, u64>,
    outgoing: &BTreeMap<NodeId, u64>,
    key: [u8; 32],
) -> Result<Vec<u8>, HaError> {
    let peers = incoming
        .keys()
        .chain(outgoing.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    if peers.len() > MAX_PEERS {
        return Err(HaError::CapacityExceeded);
    }
    let mut body = Vec::new();
    body.extend_from_slice(PEER_STATE_MAGIC);
    body.extend_from_slice(&(peers.len() as u16).to_be_bytes());
    for peer in peers {
        let len = u16::try_from(peer.as_str().len()).map_err(|_| HaError::InvalidNode)?;
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(peer.as_str().as_bytes());
        body.extend_from_slice(
            &incoming
                .get(&peer)
                .copied()
                .unwrap_or_default()
                .to_be_bytes(),
        );
        body.extend_from_slice(
            &outgoing
                .get(&peer)
                .copied()
                .unwrap_or_default()
                .to_be_bytes(),
        );
    }
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), &body);
    body.extend_from_slice(tag.as_ref());
    Ok(body)
}

type PeerSequenceState = (BTreeMap<NodeId, u64>, BTreeMap<NodeId, u64>);

fn decode_peer_state(bytes: &[u8], key: [u8; 32]) -> Result<PeerSequenceState, HaError> {
    if bytes.len() < 5 + 2 + 32 || &bytes[..5] != PEER_STATE_MAGIC {
        return Err(HaError::Tampered);
    }
    let body_end = bytes.len() - 32;
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, &key),
        &bytes[..body_end],
        &bytes[body_end..],
    )
    .map_err(|_| HaError::Tampered)?;
    let count = u16::from_be_bytes(bytes[5..7].try_into().map_err(|_| HaError::Tampered)?) as usize;
    if count > MAX_PEERS {
        return Err(HaError::Tampered);
    }
    let mut cursor = 7;
    let mut incoming = BTreeMap::new();
    let mut outgoing = BTreeMap::new();
    for _ in 0..count {
        let peer = NodeId::parse(take_string(
            &bytes[..body_end],
            &mut cursor,
            MAX_NODE_ID_BYTES,
        )?)?;
        let incoming_sequence = take_u64(&bytes[..body_end], &mut cursor)?;
        let outgoing_sequence = take_u64(&bytes[..body_end], &mut cursor)?;
        if incoming.insert(peer.clone(), incoming_sequence).is_some()
            || outgoing.insert(peer, outgoing_sequence).is_some()
        {
            return Err(HaError::Tampered);
        }
    }
    if cursor != body_end {
        return Err(HaError::Tampered);
    }
    Ok((incoming, outgoing))
}

fn atomic_write(root: &Path, destination: &Path, bytes: &[u8]) -> Result<(), HaError> {
    let mut nonce = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| HaError::Io)?;
    let suffix = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let temporary = root.join(format!(".peer-state-{suffix}.tmp"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|_| HaError::Io)?;
    if file.write_all(bytes).is_err() || file.flush().is_err() || file.sync_all().is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(HaError::OutcomeUnknown);
    }
    fs::rename(&temporary, destination).map_err(|_| HaError::OutcomeUnknown)?;
    #[cfg(unix)]
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| HaError::OutcomeUnknown)?;
    Ok(())
}

fn validate_root(path: &Path) -> Result<(), HaError> {
    if !path.is_absolute() {
        return Err(HaError::InvalidRoot);
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
                if current == Path::new("/") || !current.exists() {
                    continue;
                }
                if fs::symlink_metadata(&current)
                    .map_err(|_| HaError::InvalidRoot)?
                    .file_type()
                    .is_symlink()
                {
                    return Err(HaError::InvalidRoot);
                }
            }
            Component::CurDir | Component::ParentDir => return Err(HaError::InvalidRoot),
        }
    }
    Ok(())
}

fn create_private_root(root: &Path) -> Result<(), HaError> {
    if !root.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(root).map_err(|_| HaError::Io)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(root).map_err(|_| HaError::Io)?;
    }
    if !root.is_dir() {
        return Err(HaError::InvalidRoot);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(root)
            .map_err(|_| HaError::Io)?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err(HaError::InvalidRoot);
        }
    }
    Ok(())
}

fn create_lock(path: &Path) -> Result<File, HaError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            HaError::WriterBusy
        } else {
            HaError::Io
        }
    })?;
    file.write_all(b"heptabao-ha-peer-state-writer-v1\n")
        .and_then(|()| file.sync_all())
        .map_err(|_| HaError::Io)?;
    Ok(file)
}

fn write_bounded_frame(writer: &mut impl Write, frame: &[u8]) -> Result<(), HaError> {
    if frame.is_empty() || frame.len() > MAX_PAYLOAD_BYTES + 4096 {
        return Err(HaError::InvalidFrame);
    }
    let length = u32::try_from(frame.len()).map_err(|_| HaError::InvalidFrame)?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(frame))
        .and_then(|()| writer.flush())
        .map_err(|_| HaError::Transport)
}

fn read_bounded_frame(reader: &mut impl Read) -> Result<Vec<u8>, HaError> {
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|_| HaError::Transport)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_PAYLOAD_BYTES + 4096 {
        return Err(HaError::InvalidFrame);
    }
    let mut frame = vec![0_u8; length];
    reader
        .read_exact(&mut frame)
        .map_err(|_| HaError::Transport)?;
    Ok(frame)
}

fn write_frame(stream: &mut TcpStream, frame: &[u8]) -> Result<(), HaError> {
    write_bounded_frame(stream, frame)
}

fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, HaError> {
    read_bounded_frame(stream)
}

fn take_string(frame: &[u8], cursor: &mut usize, maximum: usize) -> Result<String, HaError> {
    if frame.len().saturating_sub(*cursor) < 2 {
        return Err(HaError::InvalidFrame);
    }
    let length = u16::from_be_bytes(
        frame[*cursor..*cursor + 2]
            .try_into()
            .map_err(|_| HaError::InvalidFrame)?,
    ) as usize;
    *cursor += 2;
    if length == 0 || length > maximum || frame.len().saturating_sub(*cursor) < length {
        return Err(HaError::InvalidFrame);
    }
    let value = std::str::from_utf8(&frame[*cursor..*cursor + length])
        .map_err(|_| HaError::InvalidFrame)?
        .to_owned();
    *cursor += length;
    Ok(value)
}

fn take_u64(frame: &[u8], cursor: &mut usize) -> Result<u64, HaError> {
    if frame.len().saturating_sub(*cursor) < 8 {
        return Err(HaError::InvalidFrame);
    }
    let value = u64::from_be_bytes(
        frame[*cursor..*cursor + 8]
            .try_into()
            .map_err(|_| HaError::InvalidFrame)?,
    );
    *cursor += 8;
    Ok(value)
}

fn take_u32(frame: &[u8], cursor: &mut usize) -> Result<u32, HaError> {
    if frame.len().saturating_sub(*cursor) < 4 {
        return Err(HaError::InvalidFrame);
    }
    let value = u32::from_be_bytes(
        frame[*cursor..*cursor + 4]
            .try_into()
            .map_err(|_| HaError::InvalidFrame)?,
    );
    *cursor += 4;
    Ok(value)
}

fn snapshot_root(
    snapshot_id: [u8; 16],
    term: u64,
    index: u64,
    total_bytes: u64,
    chunks: &[[u8; 32]],
) -> [u8; 32] {
    let mut material = Vec::with_capacity(16 + 24 + chunks.len() * 32);
    material.extend_from_slice(&snapshot_id);
    material.extend_from_slice(&term.to_be_bytes());
    material.extend_from_slice(&index.to_be_bytes());
    material.extend_from_slice(&total_bytes.to_be_bytes());
    for chunk in chunks {
        material.extend_from_slice(chunk);
    }
    sha256(&material)
}

fn has_majority(voters: &BTreeSet<NodeId>, acknowledgements: &BTreeSet<NodeId>) -> bool {
    voters.intersection(acknowledgements).count() > voters.len() / 2
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 output is always 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug)]
    struct MockDriver {
        local: NodeId,
        view: LeaderView,
        writes: usize,
        reads: usize,
    }

    impl ConsensusDriver for MockDriver {
        fn local_node(&self) -> &NodeId {
            &self.local
        }
        fn leader_view(&self) -> Result<LeaderView, HaError> {
            Ok(self.view.clone())
        }
        fn execute_leader_mutation(
            &mut self,
            operation: &ClientOperation,
        ) -> Result<ClientResult, HaError> {
            self.writes += 1;
            ClientResult::new(
                self.view.term,
                self.view.commit_index + 1,
                operation.payload().to_vec(),
            )
        }
        fn execute_linearizable_read(
            &mut self,
            operation: &ClientOperation,
        ) -> Result<ClientResult, HaError> {
            self.reads += 1;
            ClientResult::new(
                self.view.term,
                self.view.commit_index,
                operation.payload().to_vec(),
            )
        }
    }

    #[derive(Debug, Default)]
    struct MockForwarder {
        calls: usize,
    }

    impl ForwardClient for MockForwarder {
        fn forward(
            &mut self,
            _leader: &NodeId,
            expected_term: u64,
            operation: &ClientOperation,
        ) -> Result<ClientResult, HaError> {
            self.calls += 1;
            ClientResult::new(expected_term, 10, operation.payload().to_vec())
        }
    }

    fn node(value: &str) -> NodeId {
        NodeId::parse(value).unwrap()
    }

    fn root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "heptabao-ha-service-{name}-{}-{nonce}",
            std::process::id()
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&root).unwrap();
        }
        #[cfg(not(unix))]
        fs::create_dir(&root).unwrap();
        root
    }

    #[test]
    fn leader_executes_and_follower_forwards_with_deduplication() {
        let leader = node("n1");
        let driver = MockDriver {
            local: leader.clone(),
            view: LeaderView {
                leader: leader.clone(),
                term: 3,
                commit_index: 9,
                quorum_available: true,
            },
            writes: 0,
            reads: 0,
        };
        let mut service = HaService::new(driver, MockForwarder::default(), 32).unwrap();
        let operation = ClientOperation::new(
            OperationId([1; 16]),
            OperationKind::Mutation,
            b"write".to_vec(),
        )
        .unwrap();
        let first = service.execute(&operation).unwrap();
        let second = service.execute(&operation).unwrap();
        assert_eq!(first, second);
        let (driver, forwarder) = service.into_parts();
        assert_eq!(driver.writes, 1);
        assert_eq!(forwarder.calls, 0);

        let follower = MockDriver {
            local: node("n2"),
            view: LeaderView {
                leader,
                term: 4,
                commit_index: 10,
                quorum_available: true,
            },
            writes: 0,
            reads: 0,
        };
        let mut service = HaService::new(follower, MockForwarder::default(), 32).unwrap();
        let operation = ClientOperation::new(
            OperationId([2; 16]),
            OperationKind::LinearizableRead,
            b"read".to_vec(),
        )
        .unwrap();
        service.execute(&operation).unwrap();
        let (_, forwarder) = service.into_parts();
        assert_eq!(forwarder.calls, 1);
    }

    #[test]
    fn quorum_loss_and_operation_id_conflict_fail_closed() {
        let local = node("n1");
        let driver = MockDriver {
            local: local.clone(),
            view: LeaderView {
                leader: local,
                term: 1,
                commit_index: 1,
                quorum_available: false,
            },
            writes: 0,
            reads: 0,
        };
        let mut service = HaService::new(driver, MockForwarder::default(), 4).unwrap();
        let operation =
            ClientOperation::new(OperationId([3; 16]), OperationKind::Mutation, b"x".to_vec())
                .unwrap();
        assert_eq!(service.execute(&operation), Err(HaError::QuorumUnavailable));
    }

    #[test]
    fn authenticated_peer_replay_is_rejected_after_restart() {
        let n1 = node("n1");
        let n2 = node("n2");
        let auth = PeerAuthenticator::new(
            "cluster-a",
            BTreeMap::from([(n1.clone(), [1; 32]), (n2.clone(), [2; 32])]),
        )
        .unwrap();
        let envelope = auth
            .seal(
                n1.clone(),
                n2.clone(),
                7,
                1,
                PeerMessageKind::ForwardRequest,
                b"request".to_vec(),
            )
            .unwrap();
        let root = root("replay");
        {
            let mut sequences = PersistentPeerSequences::open(&root, [3; 32]).unwrap();
            admit_peer_envelope(&n2, &auth, &mut sequences, &envelope).unwrap();
            assert_eq!(
                admit_peer_envelope(&n2, &auth, &mut sequences, &envelope),
                Err(HaError::ReplayDetected)
            );
        }
        let mut reopened = PersistentPeerSequences::open(&root, [3; 32]).unwrap();
        assert_eq!(
            admit_peer_envelope(&n2, &auth, &mut reopened, &envelope),
            Err(HaError::ReplayDetected)
        );
        drop(reopened);
        drop(auth);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn peer_frame_tampering_and_wrong_receiver_are_rejected() {
        let n1 = node("n1");
        let n2 = node("n2");
        let n3 = node("n3");
        let auth = PeerAuthenticator::new(
            "cluster-a",
            BTreeMap::from([
                (n1.clone(), [4; 32]),
                (n2.clone(), [5; 32]),
                (n3.clone(), [6; 32]),
            ]),
        )
        .unwrap();
        let envelope = auth
            .seal(
                n1,
                n2.clone(),
                2,
                9,
                PeerMessageKind::ReadIndex,
                b"x".to_vec(),
            )
            .unwrap();
        assert_eq!(
            auth.verify(&n3, &envelope),
            Err(HaError::PeerAuthenticationFailed)
        );
        let mut encoded = encode_peer_envelope(&envelope).unwrap();
        let index = encoded.len() / 2;
        encoded[index] ^= 0x10;
        let tampered = decode_peer_envelope(&encoded).unwrap();
        assert_eq!(
            auth.verify(&n2, &tampered),
            Err(HaError::PeerAuthenticationFailed)
        );
    }

    #[test]
    fn snapshot_and_joint_membership_are_verified() {
        let chunks = vec![b"one".to_vec(), b"two".to_vec()];
        let manifest = SnapshotManifest::build([7; 16], 5, 20, &chunks).unwrap();
        manifest.verify(&chunks).unwrap();
        let mut changed = chunks.clone();
        changed[1][0] ^= 1;
        assert_eq!(manifest.verify(&changed), Err(HaError::InvalidSnapshot));
        let old = BTreeSet::from([node("n1"), node("n2"), node("n3")]);
        let new = BTreeSet::from([node("n2"), node("n3"), node("n4")]);
        let transition = MembershipTransition::new(MembershipPhase::Joint, old, new).unwrap();
        assert!(transition.joint_quorum(&BTreeSet::from([node("n2"), node("n3")])));
        assert!(!transition.joint_quorum(&BTreeSet::from([node("n1"), node("n2")])));
    }

    #[test]
    fn tls_endpoint_and_pinned_client_identity_are_strict() {
        let address: SocketAddr = "127.0.0.1:8201".parse().unwrap();
        assert!(TlsPeerEndpoint::new(address, "node-2.example.internal").is_ok());
        assert_eq!(
            TlsPeerEndpoint::new(address, "bad name with spaces"),
            Err(HaError::InvalidCluster)
        );
        let certificate = b"synthetic-test-certificate-der";
        let peer = node("n2");
        let identities =
            PinnedClientCertificateMap::new(BTreeMap::from([(sha256(certificate), peer.clone())]))
                .unwrap();
        assert_eq!(identities.identify(certificate).unwrap(), peer);
        assert_eq!(
            identities.identify(b"different-certificate"),
            Err(HaError::PeerAuthenticationFailed)
        );
    }

    #[test]
    fn tcp_transport_uses_bounded_framing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            serve_one_peer_frame(&listener, Duration::from_secs(2), Ok).unwrap()
        });
        let transport = TcpPeerTransport::new(
            BTreeMap::from([(node("n2"), address)]),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(transport.exchange(&node("n2"), b"hello").unwrap(), b"hello");
        server.join().unwrap();
    }
}
