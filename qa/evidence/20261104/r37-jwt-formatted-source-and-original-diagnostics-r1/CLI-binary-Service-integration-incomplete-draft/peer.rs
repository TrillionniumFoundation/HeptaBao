//! One authenticated snapshot exchange on an existing cluster TLS connection.
//!
//! The peer identity and byte stream are real transport facts. They do not
//! grant end-user Actor, storage, publication or replay authority. The server
//! callback must supply the separately reviewed native Service lifecycle.

use super::*;
use crate::native_snapshot_body::{
    EncodedSnapshotBody, SNAPSHOT_BODY_CHUNK_BYTES, SnapshotBodyLimits, SnapshotBodyReader,
    VerifiedSnapshotBody, encode_snapshot_body,
};
use zeroize::Zeroizing;

const STREAM_PREFIX: &[u8; 4] = b"HBSF";
const STREAM_VERSION: &[u8; 4] = b"0001";
const READY: u8 = 1;
const REJECTED: u8 = 2;
const COMPLETED: u8 = 3;

type ServerTls = rustls::StreamOwned<rustls::ServerConnection, ForwardDeadlineStream>;

/// Data and independent registry pins for exactly one attempted exchange.
pub struct SnapshotPeerRequest<'a> {
    metadata: &'a [u8],
    server_leaves: &'a [[u8; 32]],
    upload_limit: SnapshotBodyLimits,
    response_limit: SnapshotBodyLimits,
    deadline: Instant,
}

impl fmt::Debug for SnapshotPeerRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnapshotPeerRequest")
            .field("metadata_bytes", &self.metadata.len())
            .field("enrolled_server_pins", &self.server_leaves.len())
            .field("upload_limit", &self.upload_limit)
            .field("response_limit", &self.response_limit)
            .finish_non_exhaustive()
    }
}

impl<'a> SnapshotPeerRequest<'a> {
    pub fn new(
        metadata: &'a [u8],
        server_leaves: &'a [[u8; 32]],
        limits: (SnapshotBodyLimits, SnapshotBodyLimits),
        deadline: Instant,
    ) -> Result<Self, HaError> {
        if metadata.is_empty()
            || metadata.len() > MAX_PAYLOAD_BYTES
            || server_leaves.is_empty()
            || server_leaves.len() > 2
            || server_leaves.iter().any(|pin| *pin == [0; 32])
            || (server_leaves.len() == 2 && server_leaves[0] == server_leaves[1])
        {
            return Err(HaError::InvalidFrame);
        }
        time_left(deadline)?;
        Ok(Self {
            metadata,
            server_leaves,
            upload_limit: limits.0,
            response_limit: limits.1,
            deadline,
        })
    }
}

/// An authenticated transport result, still untrusted as application completion.
pub struct SnapshotPeerResponse {
    status: u16,
    metadata: Zeroizing<Vec<u8>>,
    request_body: Option<EncodedSnapshotBody>,
    response_body: Option<VerifiedSnapshotBody>,
}

impl fmt::Debug for SnapshotPeerResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnapshotPeerResponse")
            .field("status", &self.status)
            .field("metadata_bytes", &self.metadata.len())
            .field("request_body", &self.request_body)
            .field("response_body", &self.response_body)
            .finish()
    }
}

impl SnapshotPeerResponse {
    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    pub fn request_body(&self) -> Option<&EncodedSnapshotBody> {
        self.request_body.as_ref()
    }

    pub fn response_body(&self) -> Option<&VerifiedSnapshotBody> {
        self.response_body.as_ref()
    }
}

fn time_left(deadline: Instant) -> Result<Duration, HaError> {
    forward_remaining(deadline).map_err(|_| HaError::Transport)
}

fn exact_read(
    input: &mut impl Read,
    output: &mut [u8],
    deadline: Instant,
) -> Result<(), HaError> {
    time_left(deadline)?;
    input.read_exact(output).map_err(|_| HaError::Transport)?;
    time_left(deadline)?;
    Ok(())
}

fn exact_write(
    output: &mut impl Write,
    input: &[u8],
    deadline: Instant,
) -> Result<(), HaError> {
    time_left(deadline)?;
    output.write_all(input).map_err(|_| HaError::Transport)?;
    time_left(deadline)?;
    Ok(())
}

fn flush_before(output: &mut impl Write, deadline: Instant) -> Result<(), HaError> {
    time_left(deadline)?;
    output.flush().map_err(|_| HaError::Transport)?;
    time_left(deadline)?;
    Ok(())
}

fn metadata_read(
    input: &mut impl Read,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, HaError> {
    let mut length = [0_u8; 4];
    exact_read(input, &mut length, deadline)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_PAYLOAD_BYTES {
        return Err(HaError::InvalidFrame);
    }
    let mut metadata = Zeroizing::new(vec![0_u8; length]);
    exact_read(input, &mut metadata, deadline)?;
    Ok(metadata)
}

fn metadata_write(
    output: &mut impl Write,
    metadata: &[u8],
    deadline: Instant,
) -> Result<(), HaError> {
    if metadata.is_empty() || metadata.len() > MAX_PAYLOAD_BYTES {
        return Err(HaError::InvalidFrame);
    }
    exact_write(output, &(metadata.len() as u32).to_be_bytes(), deadline)?;
    exact_write(output, metadata, deadline)
}

fn eof_before(input: &mut impl Read, deadline: Instant) -> Result<(), HaError> {
    time_left(deadline)?;
    let mut tail = [0_u8; 1];
    let bytes = input.read(&mut tail).map_err(|_| HaError::Transport)?;
    time_left(deadline)?;
    if bytes != 0 {
        return Err(HaError::InvalidFrame);
    }
    Ok(())
}

fn status_read(
    input: &mut impl Read,
    deadline: Instant,
) -> Result<(u16, Zeroizing<Vec<u8>>), HaError> {
    let mut status = [0_u8; 2];
    exact_read(input, &mut status, deadline)?;
    Ok((u16::from_be_bytes(status), metadata_read(input, deadline)?))
}

impl MutualTlsPeerTransport {
    /// One selected peer, one connect and one body. There is no retry/fallback.
    ///
    /// server_leaves must be the selected endpoint's independently enrolled
    /// registry pins, never values learned from a response. Tokens and metadata
    /// are sent only after CA/name/strict ALPN and exact selected-leaf checks.
    pub fn exchange_snapshot_before(
        &self,
        peer: &NodeId,
        request: SnapshotPeerRequest<'_>,
        upload: &mut impl Read,
        response_sink: &mut impl Write,
        admission: impl FnOnce(&[u8]) -> Result<(), HaError>,
    ) -> Result<SnapshotPeerResponse, HaError> {
        let deadline = request.deadline.min(Instant::now() + self.timeout);
        let endpoint = self.peers.get(peer).ok_or(HaError::UnknownPeer)?;
        let server_name = rustls::pki_types::ServerName::try_from(endpoint.server_name.clone())
            .map_err(|_| HaError::InvalidCluster)?;
        let stream = TcpStream::connect_timeout(&endpoint.address, time_left(deadline)?)
            .map_err(|_| HaError::Transport)?;
        stream.set_nodelay(true).map_err(|_| HaError::Transport)?;
        let stream = ForwardDeadlineStream { stream, deadline };
        let connection = rustls::ClientConnection::new(self.client_config.clone(), server_name)
            .map_err(|_| HaError::Transport)?;
        let mut tls = rustls::StreamOwned::new(connection, stream);
        tls.conn
            .complete_io(&mut tls.sock)
            .map_err(|_| HaError::PeerAuthenticationFailed)?;
        if tls.conn.alpn_protocol() != Some(RAFT_ALPN_PROTOCOL) {
            return Err(HaError::PeerAuthenticationFailed);
        }
        let chain = tls
            .conn
            .peer_certificates()
            .ok_or(HaError::PeerAuthenticationFailed)?;
        if chain.is_empty() || chain.len() > MAX_PEER_CERT_CHAIN {
            return Err(HaError::PeerAuthenticationFailed);
        }
        chain.iter().try_fold(0_usize, |total, certificate| {
            if certificate.is_empty() {
                return Err(HaError::PeerAuthenticationFailed);
            }
            total
                .checked_add(certificate.len())
                .filter(|bytes| *bytes <= MAX_PEER_CERT_CHAIN_BYTES)
                .ok_or(HaError::PeerAuthenticationFailed)
        })?;
        let leaf = sha256(chain[0].as_ref());
        if !request.server_leaves.contains(&leaf) {
            return Err(HaError::PeerAuthenticationFailed);
        }
        let remaining = u64::try_from(time_left(deadline)?.as_nanos())
            .map_err(|_| HaError::Transport)?;
        exact_write(&mut tls, STREAM_PREFIX, deadline)?;
        exact_write(&mut tls, STREAM_VERSION, deadline)?;
        exact_write(&mut tls, &remaining.to_be_bytes(), deadline)?;
        metadata_write(&mut tls, request.metadata, deadline)?;
        flush_before(&mut tls, deadline)?;

        let mut decision = [0_u8; 1];
        exact_read(&mut tls, &mut decision, deadline)?;
        if decision[0] == REJECTED {
            let (status, metadata) = status_read(&mut tls, deadline)?;
            if !(400..=599).contains(&status) {
                return Err(HaError::InvalidFrame);
            }
            eof_before(&mut tls, deadline)?;
            return Ok(SnapshotPeerResponse {
                status,
                metadata,
                request_body: None,
                response_body: None,
            });
        }
        if decision[0] != READY {
            return Err(HaError::InvalidFrame);
        }
        // The original Actor's authenticated checkpoint is accepted before any
        // upload bytes leave this node. This callback may synchronize and retain
        // local original Auth custody; it must not repeat Actor admission.
        let ready_metadata = metadata_read(&mut tls, deadline)?;
        admission(&ready_metadata)?;
        time_left(deadline)?;
        let request_body =
            encode_snapshot_body(upload, &mut tls, request.upload_limit, deadline)
                .map_err(|_| HaError::Transport)?;
        // END has no same-direction completion trailer. Actual rustls EOF at
        // the receiver is authenticated close-notify, not bare TCP shutdown.
        tls.conn.send_close_notify();
        flush_before(&mut tls, deadline)?;

        exact_read(&mut tls, &mut decision, deadline)?;
        let (status, metadata) = status_read(&mut tls, deadline)?;
        if decision[0] == REJECTED {
            if !(400..=599).contains(&status) {
                return Err(HaError::InvalidFrame);
            }
            eof_before(&mut tls, deadline)?;
            return Ok(SnapshotPeerResponse {
                status,
                metadata,
                request_body: Some(request_body),
                response_body: None,
            });
        }
        if decision[0] != COMPLETED || !matches!(status, 200 | 204) {
            return Err(HaError::InvalidFrame);
        }
        let mut body = SnapshotBodyReader::new(
            &mut tls,
            request.response_limit,
            deadline,
        )
        .map_err(|_| HaError::Transport)?;
        let mut buffer = Zeroizing::new(vec![0_u8; SNAPSHOT_BODY_CHUNK_BYTES]);
        loop {
            time_left(deadline)?;
            let length = body.read(&mut buffer).map_err(|_| HaError::Transport)?;
            if length == 0 {
                break;
            }
            exact_write(response_sink, &buffer[..length], deadline)?;
        }
        let response_body = body.finish().map_err(|_| HaError::Transport)?;
        flush_before(response_sink, deadline)?;
        time_left(deadline)?;
        Ok(SnapshotPeerResponse {
            status,
            metadata,
            request_body: Some(request_body),
            response_body: Some(response_body),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotPeerPhase {
    Fresh,
    ReadingBody,
    BodyComplete,
    BodyFailed,
    FailedIo,
}

/// Actual peer identity and the sole snapshot connection share one owner.
///
/// Only the real mTLS listener below constructs this object. It exposes no raw
/// socket or TLS mutator. Metadata is still data requiring independent Service
/// authentication and leader/source/target/cluster/nonce validation.
pub struct AuthenticatedSnapshotPeer<'a> {
    tls: &'a mut ServerTls,
    peer: NodeId,
    leaf_sha256: [u8; 32],
    accepted_at: Instant,
    deadline: Instant,
    metadata: Zeroizing<Vec<u8>>,
    phase: SnapshotPeerPhase,
    terminal_written: &'a mut bool,
}

impl fmt::Debug for AuthenticatedSnapshotPeer<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedSnapshotPeer")
            .field("peer", &self.peer)
            .field("metadata_bytes", &self.metadata.len())
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedSnapshotPeer<'_> {
    pub fn peer(&self) -> &NodeId {
        &self.peer
    }

    pub fn actual_leaf_sha256(&self) -> [u8; 32] {
        self.leaf_sha256
    }

    pub fn accepted_at(&self) -> Instant {
        self.accepted_at
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    /// Call only after original native Actor admission; never call twice.
    ///
    /// The caller keeps its actual pending native plan. The consumer may parse
    /// into private staging but must not finalize a restore. Only a successful
    /// return supplies the exact body END needed for that later finalization.
    pub fn accept_body<T>(
        &mut self,
        limits: SnapshotBodyLimits,
        ready_metadata: &[u8],
        consumer: impl FnOnce(&mut dyn Read) -> T,
    ) -> Result<(T, VerifiedSnapshotBody), HaError> {
        if self.phase != SnapshotPeerPhase::Fresh
            || ready_metadata.is_empty()
            || ready_metadata.len() > MAX_PAYLOAD_BYTES
        {
            return Err(HaError::InvalidFrame);
        }
        self.phase = SnapshotPeerPhase::FailedIo;
        exact_write(self.tls, &[READY], self.deadline)?;
        metadata_write(self.tls, ready_metadata, self.deadline)?;
        flush_before(self.tls, self.deadline)?;
        self.phase = SnapshotPeerPhase::ReadingBody;
        let result = (|| {
            let mut body = SnapshotBodyReader::new(&mut *self.tls, limits, self.deadline)
                .map_err(|_| HaError::Transport)?;
            let parsed = consumer(&mut body);
            let verified = body.finish().map_err(|_| HaError::Transport)?;
            time_left(self.deadline)?;
            Ok((parsed, verified))
        })();
        self.phase = if result.is_ok() {
            SnapshotPeerPhase::BodyComplete
        } else {
            SnapshotPeerPhase::BodyFailed
        };
        result
    }

    /// Send a native terminal denial or reconciliation result; never success.
    ///
    /// A receiver cannot label a partially written READY/terminal as a fresh
    /// rejection. The connection is consumed whether the send succeeds or not.
    pub fn reject(mut self, status: u16, metadata: &[u8]) -> Result<(), HaError> {
        if !(400..=599).contains(&status)
            || self.phase == SnapshotPeerPhase::FailedIo
            || metadata.is_empty()
            || metadata.len() > MAX_PAYLOAD_BYTES
        {
            return Err(HaError::InvalidFrame);
        }
        self.phase = SnapshotPeerPhase::FailedIo;
        exact_write(self.tls, &[REJECTED], self.deadline)?;
        exact_write(self.tls, &status.to_be_bytes(), self.deadline)?;
        metadata_write(self.tls, metadata, self.deadline)?;
        self.tls.conn.send_close_notify();
        flush_before(self.tls, self.deadline)?;
        *self.terminal_written = true;
        Ok(())
    }

    /// Send only after the actual native plan's final owner/audit completion.
    ///
    /// Metadata precedes the body and must already bind the exact held file.
    /// It is not minted here. Client-side publication and body-witness checks
    /// remain mandatory before any success HTTP response is released.
    pub fn complete(
        mut self,
        status: u16,
        metadata: &[u8],
        source: &mut impl Read,
        limit: SnapshotBodyLimits,
    ) -> Result<EncodedSnapshotBody, HaError> {
        if self.phase != SnapshotPeerPhase::BodyComplete
            || !matches!(status, 200 | 204)
            || metadata.is_empty()
            || metadata.len() > MAX_PAYLOAD_BYTES
        {
            return Err(HaError::InvalidFrame);
        }
        self.phase = SnapshotPeerPhase::FailedIo;
        exact_write(self.tls, &[COMPLETED], self.deadline)?;
        exact_write(self.tls, &status.to_be_bytes(), self.deadline)?;
        metadata_write(self.tls, metadata, self.deadline)?;
        let body = encode_snapshot_body(source, self.tls, limit, self.deadline)
            .map_err(|_| HaError::Transport)?;
        self.tls.conn.send_close_notify();
        flush_before(self.tls, self.deadline)?;
        *self.terminal_written = true;
        Ok(body)
    }
}

/// Actual mTLS admission, with an explicit snapshot branch and unchanged
/// bounded ordinary-frame callback. New snapshot peers require strict ALPN;
/// the previous missing-ALPN transition remains confined to the old branch.
pub fn serve_one_mtls_peer_frame_or_snapshot<F, S>(
    listener: &TcpListener,
    server_config: Arc<rustls::ServerConfig>,
    identities: &PinnedClientCertificateMap,
    timeout: Duration,
    allow_missing_raft_alpn: bool,
    handlers: (F, S),
) -> Result<(), HaError>
where
    F: FnOnce(AuthenticatedPeerFrame) -> Result<Vec<u8>, HaError>,
    S: FnOnce(AuthenticatedSnapshotPeer<'_>) -> Result<(), HaError>,
{
    if timeout.is_zero() || timeout > Duration::from_secs(60) {
        return Err(HaError::InvalidCluster);
    }
    let (stream, accepted_at) = accept_peer_with_origin(listener)?;
    configure_accepted_peer_stream(&stream, timeout)?;
    let deadline = accepted_at.checked_add(timeout).ok_or(HaError::Transport)?;
    #[cfg(any(test, feature = "private-forward-stage-diagnostic"))]
    let _diagnostic_bound = closure_phase_diagnostic::Scope::original_bound(deadline);
    let stream = ForwardDeadlineStream { stream, deadline };
    let connection = rustls::ServerConnection::new(server_config)
        .map_err(|_| forward_transport_frame_error("receiver_tls_setup", HaError::Transport))?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    observe_closure_phase!(ServerHandshake, tls.conn.complete_io(&mut tls.sock)).map_err(
        |error| {
            forward_io_error_as(
                "receiver_tls_handshake",
                &error,
                HaError::PeerAuthenticationFailed,
            )
        },
    )?;
    let strict = tls.conn.alpn_protocol() == Some(RAFT_ALPN_PROTOCOL);
    require_raft_alpn(tls.conn.alpn_protocol(), allow_missing_raft_alpn)
        .map_err(|error| forward_transport_frame_error("receiver_alpn", error))?;
    let certificates = tls.conn.peer_certificates().ok_or_else(|| {
        forward_transport_frame_error(
            "receiver_certificate_absent",
            HaError::PeerAuthenticationFailed,
        )
    })?;
    let peer = identify_peer_certificate_chain(identities, certificates)
        .map_err(|error| forward_transport_frame_error("receiver_identity", error))?;
    let leaf_sha256 = sha256(
        certificates
            .first()
            .ok_or(HaError::PeerAuthenticationFailed)?
            .as_ref(),
    );
    let mut prefix = [0_u8; 4];
    exact_read(&mut tls, &mut prefix, deadline)
        .map_err(|error| forward_transport_frame_error("receiver_frame_read", error))?;
    if &prefix == STREAM_PREFIX {
        if !strict {
            return Err(HaError::PeerAuthenticationFailed);
        }
        let mut version = [0_u8; 4];
        exact_read(&mut tls, &mut version, deadline)?;
        if &version != STREAM_VERSION {
            return Err(HaError::InvalidFrame);
        }
        let mut remaining = [0_u8; 8];
        exact_read(&mut tls, &mut remaining, deadline)?;
        let remaining = Duration::from_nanos(u64::from_be_bytes(remaining)).min(timeout);
        if remaining.is_zero() {
            return Err(HaError::Transport);
        }
        let deadline = accepted_at
            .checked_add(remaining)
            .ok_or(HaError::Transport)?
            .min(deadline);
        time_left(deadline)?;
        tls.sock.deadline = deadline;
        let metadata = metadata_read(&mut tls, deadline)?;
        let mut terminal_written = false;
        handlers.1(AuthenticatedSnapshotPeer {
            tls: &mut tls,
            peer,
            leaf_sha256,
            accepted_at,
            deadline,
            metadata,
            phase: SnapshotPeerPhase::Fresh,
            terminal_written: &mut terminal_written,
        })?;
        time_left(deadline)?;
        if !terminal_written {
            return Err(HaError::InvalidFrame);
        }
        return Ok(());
    }

    // The four bytes just inspected are the original old frame length. Feeding
    // them back through a bounded in-memory prefix does not reread the socket.
    let payload = {
        let mut prefixed = io::Cursor::new(prefix).chain(&mut tls);
        native_kv2_write_request::read_authenticated_request(
            &mut prefixed,
            strict.then_some(RAFT_ALPN_PROTOCOL),
        )
        .map_err(|error| forward_transport_frame_error("receiver_frame_read", error))?
    };
    let response_profile = ResponseFrameProfile::for_request(&payload)?;
    let coalesced_root_reply = strict
        && response_profile == ResponseFrameProfile::Legacy
        && is_native_v6_root_pull_frame(&payload);
    response_profile.require_alpn(tls.conn.alpn_protocol())?;
    if Instant::now() >= deadline {
        return Err(forward_transport_frame_error(
            "receiver_deadline_before_handler",
            HaError::Transport,
        ));
    }
    let response = Zeroizing::new(
        handlers.0(AuthenticatedPeerFrame {
            payload,
            peer,
            leaf_sha256,
            accepted_at,
            deadline,
            strict_raft_alpn: strict,
        })
        .map_err(|error| forward_transport_frame_error("receiver_handler_result", error))?,
    );
    if coalesced_root_reply {
        return write_coalesced_bounded_frame(
            &mut rustls::Stream::new(&mut tls.conn, &mut tls.sock),
            &response,
        )
        .map_err(|error| forward_transport_frame_error("receiver_frame_write", error));
    }
    response_profile
        .write(&mut tls, &response)
        .map_err(|error| forward_transport_frame_error("receiver_frame_write", error))
}

#[cfg(test)]
#[path = "native_snapshot_peer_tests.rs"]
mod tests;
