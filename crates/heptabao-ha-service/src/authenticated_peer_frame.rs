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
    #[cfg(all(
        feature = "native-v6-peer-ingress",
        any(test, feature = "private-forward-stage-diagnostic")
    ))]
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
    let strict_raft_alpn = tls.conn.alpn_protocol() == Some(RAFT_ALPN_PROTOCOL);
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
    #[cfg(not(feature = "native-v6-peer-ingress"))]
    let payload = native_kv2_write_request::read_authenticated_request(
        &mut tls,
        strict_raft_alpn.then_some(RAFT_ALPN_PROTOCOL),
    )
    .map_err(|error| forward_transport_frame_error("receiver_frame_read", error))?;
    #[cfg(feature = "native-v6-peer-ingress")]
    let payload = snapshot_clock_transport::read_authenticated_request(
        &mut tls,
        strict_raft_alpn.then_some(RAFT_ALPN_PROTOCOL),
        accepted_at,
        deadline,
        |tls, shortened| tls.sock.deadline = shortened,
    )
    .map_err(|error| forward_transport_frame_error("receiver_frame_read", error))?;
    // A private terminal-observation request can only shorten the already
    // running socket bound. Handler work and final TLS flush share that bound.
    let deadline = tls.sock.deadline;
    let response_profile = ResponseFrameProfile::for_request(&payload)?;
    #[cfg(feature = "native-v6-peer-ingress")]
    let snapshot_clock_reply = is_snapshot_clock_request(&payload);
    #[cfg(feature = "native-v6-peer-ingress")]
    let coalesced_root_reply = strict_raft_alpn
        && response_profile == ResponseFrameProfile::Legacy
        && is_native_v6_root_pull_frame(&payload);
    response_profile.require_alpn(tls.conn.alpn_protocol())?;
    if Instant::now() >= deadline {
        return Err(forward_transport_frame_error(
            "receiver_deadline_before_handler",
            HaError::Transport,
        ));
    }
    let response = zeroize::Zeroizing::new(
        handler(AuthenticatedPeerFrame {
            payload,
            peer,
            leaf_sha256,
            accepted_at,
            deadline,
            strict_raft_alpn,
        })
        .map_err(|error| forward_transport_frame_error("receiver_handler_result", error))?,
    );
    #[cfg(feature = "native-v6-peer-ingress")]
    if snapshot_clock_reply {
        snapshot_clock_transport::validate_response(&response)?;
        return write_coalesced_bounded_frame(
            &mut rustls::Stream::new(&mut tls.conn, &mut tls.sock),
            &response,
        );
    }
    // Only an authenticated HBVP2 handler result uses the existing bounded
    // coalesced writer. Borrow Stream: StreamOwned's default write_vectored
    // otherwise sends only the first slice and emits a separate header record.
    // The accepted ForwardDeadlineStream still bounds every actual socket I/O.
    #[cfg(feature = "native-v6-peer-ingress")]
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
