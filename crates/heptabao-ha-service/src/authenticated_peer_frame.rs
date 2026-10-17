//! An ingress frame and its actual TLS identity have one owner. A caller may
//! classify these bytes, but cannot attach different bytes, a later clock, or
//! an asserted NodeId to the authenticated context.
use super::*;

pub struct AuthenticatedPeerFrame {
    payload: Vec<u8>,
    peer: NodeId,
    leaf_sha256: [u8; 32],
    accepted_at: Instant,
    deadline: Instant,
    strict_raft_alpn: bool,
}

impl fmt::Debug for AuthenticatedPeerFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedPeerFrame")
            .field("peer", &self.peer)
            .field("payload_bytes", &self.payload.len())
            .field("strict_raft_alpn", &self.strict_raft_alpn)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedPeerFrame {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
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
    pub fn has_strict_raft_alpn(&self) -> bool {
        self.strict_raft_alpn
    }
    /// Consuming legacy handoff preserves its previous callback contract. The
    /// resulting parts cannot reconstruct an authenticated native frame.
    pub fn into_legacy_parts(self) -> (NodeId, Vec<u8>, Instant) {
        (self.peer, self.payload, self.accepted_at)
    }
}

/// Mint the opaque frame only after the actual mTLS handshake, verified leaf
/// pin and bounded frame read. The accepted socket's original absolute bound
/// covers handshake, frame, callback, reply and final flush. A legacy missing
/// ALPN exception is recorded; native receivers must explicitly reject it.
pub fn serve_one_mtls_authenticated_peer_frame<H>(
    listener: &TcpListener,
    server_config: Arc<rustls::ServerConfig>,
    identities: &PinnedClientCertificateMap,
    timeout: Duration,
    allow_missing_raft_alpn: bool,
    handler: H,
) -> Result<(), HaError>
where
    H: FnOnce(AuthenticatedPeerFrame) -> Result<Vec<u8>, HaError>,
{
    if timeout.is_zero() || timeout > Duration::from_secs(60) {
        return Err(HaError::InvalidCluster);
    }
    let (stream, accepted_at) = accept_peer_with_origin(listener)?;
    configure_accepted_peer_stream(&stream, timeout)?;
    let deadline = accepted_at.checked_add(timeout).ok_or(HaError::Transport)?;
    let stream = ForwardDeadlineStream { stream, deadline };
    let connection =
        rustls::ServerConnection::new(server_config).map_err(|_| HaError::Transport)?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    tls.conn
        .complete_io(&mut tls.sock)
        .map_err(|_| HaError::PeerAuthenticationFailed)?;
    let strict_raft_alpn = tls.conn.alpn_protocol() == Some(RAFT_ALPN_PROTOCOL);
    require_raft_alpn(tls.conn.alpn_protocol(), allow_missing_raft_alpn)?;
    let certificates = tls
        .conn
        .peer_certificates()
        .ok_or(HaError::PeerAuthenticationFailed)?;
    let peer = identify_peer_certificate_chain(identities, certificates)?;
    let leaf_sha256 = sha256(
        certificates
            .first()
            .ok_or(HaError::PeerAuthenticationFailed)?
            .as_ref(),
    );
    let payload = read_bounded_frame(&mut tls)?;
    if Instant::now() >= deadline {
        return Err(HaError::Transport);
    }
    let response = handler(AuthenticatedPeerFrame {
        payload,
        peer,
        leaf_sha256,
        accepted_at,
        deadline,
        strict_raft_alpn,
    })?;
    write_bounded_frame(&mut tls, &response)
}
