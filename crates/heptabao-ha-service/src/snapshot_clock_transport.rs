//! Small, closed snapshot terminal-observation exchange. It carries no archive,
//! caller time or floor. Encoding occurs only after authenticated TLS so the
//! receiver can conservatively charge the caller's remaining original budget
//! from its earlier actual socket admission, including its final reply flush.
use super::*;

pub const SNAPSHOT_CLOCK_REQUEST_MAGIC: &[u8; 5] = b"HBSC1";
pub const SNAPSHOT_CLOCK_RESPONSE_MAGIC: &[u8; 5] = b"HBSC2";
pub const MAX_SNAPSHOT_CLOCK_FRAME_BYTES: usize = 32 * 1024;
const HEADER_BYTES: usize = SNAPSHOT_CLOCK_REQUEST_MAGIC.len() + 8;
const MAX_REMAINING_NANOS: u64 = 60_000_000_000;

pub fn is_snapshot_clock_request(frame: &[u8]) -> bool {
    frame.starts_with(SNAPSHOT_CLOCK_REQUEST_MAGIC)
}

fn remaining_nanos(frame: &[u8]) -> Result<u64, HaError> {
    if !is_snapshot_clock_request(frame)
        || frame.len() < HEADER_BYTES
        || frame.len() > MAX_SNAPSHOT_CLOCK_FRAME_BYTES
    {
        return Err(HaError::InvalidFrame);
    }
    let nanos = u64::from_be_bytes(
        frame[SNAPSHOT_CLOCK_REQUEST_MAGIC.len()..HEADER_BYTES]
            .try_into()
            .map_err(|_| HaError::InvalidFrame)?,
    );
    if nanos == 0 || nanos > MAX_REMAINING_NANOS {
        return Err(HaError::InvalidFrame);
    }
    Ok(nanos)
}

/// Inspect the fixed private header before allocating or reading its tail.
/// Ordinary frames replay these first nine transport bytes into the unchanged
/// N1/legacy reader, so their existing framing and allocation limits remain.
pub(super) fn read_authenticated_request<R: Read>(
    reader: &mut R,
    alpn: Option<&[u8]>,
    accepted_at: Instant,
    outer_deadline: Instant,
    tighten: impl FnOnce(&mut R, Instant),
) -> Result<Vec<u8>, HaError> {
    let mut length_bytes = [0_u8; 4];
    reader
        .read_exact(&mut length_bytes)
        .map_err(|_| HaError::Transport)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_NATIVE_KV2_WRITE_FRAME_BYTES {
        return Err(HaError::InvalidFrame);
    }
    let mut prefix = [0_u8; 5];
    let prefix_bytes = length.min(prefix.len());
    reader
        .read_exact(&mut prefix[..prefix_bytes])
        .map_err(|_| HaError::Transport)?;
    if !prefix[..prefix_bytes].starts_with(SNAPSHOT_CLOCK_REQUEST_MAGIC) {
        let mut replay = length_bytes.to_vec();
        replay.extend_from_slice(&prefix[..prefix_bytes]);
        let mut joined = io::Cursor::new(replay).chain(reader);
        return native_kv2_write_request::read_authenticated_request(&mut joined, alpn);
    }
    if alpn != Some(RAFT_ALPN_PROTOCOL) {
        return Err(HaError::PeerAuthenticationFailed);
    }
    if length <= HEADER_BYTES || length > MAX_SNAPSHOT_CLOCK_FRAME_BYTES {
        return Err(HaError::InvalidFrame);
    }
    let mut header = [0_u8; HEADER_BYTES];
    header[..prefix.len()].copy_from_slice(&prefix);
    reader
        .read_exact(&mut header[prefix.len()..])
        .map_err(|_| HaError::Transport)?;
    let deadline = inbound_deadline(&header, accepted_at, outer_deadline, true)?;
    tighten(reader, deadline);
    // Only the small fixed prefix was read before the socket was shortened.
    // A slow/trickled tail cannot consume the longer outer peer budget.
    let mut frame = zeroize::Zeroizing::new(vec![0_u8; length]);
    frame[..HEADER_BYTES].copy_from_slice(&header);
    reader
        .read_exact(&mut frame[HEADER_BYTES..])
        .map_err(|_| HaError::Transport)?;
    forward_remaining(deadline).map_err(|_| HaError::Transport)?;
    Ok(std::mem::take(&mut *frame))
}

pub(super) fn inbound_deadline(
    frame: &[u8],
    accepted_at: Instant,
    outer_deadline: Instant,
    strict_raft_alpn: bool,
) -> Result<Instant, HaError> {
    if !is_snapshot_clock_request(frame) {
        return Ok(outer_deadline);
    }
    if !strict_raft_alpn {
        return Err(HaError::PeerAuthenticationFailed);
    }
    let deadline = accepted_at
        .checked_add(Duration::from_nanos(remaining_nanos(frame)?))
        .ok_or(HaError::InvalidFrame)?
        .min(outer_deadline);
    forward_remaining(deadline).map_err(|_| HaError::Transport)?;
    Ok(deadline)
}

pub(super) fn validate_response(frame: &[u8]) -> Result<(), HaError> {
    if !frame.starts_with(SNAPSHOT_CLOCK_RESPONSE_MAGIC)
        || frame.len() <= SNAPSHOT_CLOCK_RESPONSE_MAGIC.len()
        || frame.len() > MAX_SNAPSHOT_CLOCK_FRAME_BYTES
    {
        return Err(HaError::InvalidFrame);
    }
    Ok(())
}

impl MutualTlsPeerTransport {
    /// Authenticate the exact enrolled receiver before constructing this one
    /// closed request. The callback gets only the remaining original duration,
    /// never a fresh timeout or any authority over the leader's wall clock.
    /// There is one connection and one attempt; an unknown result is not retried.
    pub fn exchange_snapshot_clock_before_pinned_server(
        &self,
        peer: &NodeId,
        caller_deadline: Instant,
        expected_server_leaf_sha256: [u8; 32],
        encode_after_handshake: impl FnOnce(Duration) -> Result<Vec<u8>, HaError>,
    ) -> Result<Vec<u8>, HaError> {
        if expected_server_leaf_sha256 == [0; 32] {
            return Err(HaError::PeerAuthenticationFailed);
        }
        let deadline = caller_deadline.min(Instant::now() + self.timeout);
        let endpoint = self.peers.get(peer).ok_or(HaError::UnknownPeer)?;
        let server_name = rustls::pki_types::ServerName::try_from(endpoint.server_name.clone())
            .map_err(|_| HaError::InvalidCluster)?;
        let remaining = forward_remaining(deadline).map_err(|_| HaError::Transport)?;
        let stream = TcpStream::connect_timeout(&endpoint.address, remaining)
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
        let total = chain.iter().try_fold(0_usize, |sum, cert| {
            if cert.is_empty() {
                return Err(HaError::PeerAuthenticationFailed);
            }
            sum.checked_add(cert.len())
                .filter(|count| *count <= MAX_PEER_CERT_CHAIN_BYTES)
                .ok_or(HaError::PeerAuthenticationFailed)
        })?;
        if total == 0
            || digest::digest(&digest::SHA256, chain[0].as_ref()).as_ref()
                != expected_server_leaf_sha256.as_slice()
        {
            return Err(HaError::PeerAuthenticationFailed);
        }
        // Server accept necessarily preceded this completed TLS handshake.
        // Its accepted_at + this remaining duration is therefore no later
        // than the caller's original deadline, without comparing host clocks.
        let remaining = forward_remaining(deadline).map_err(|_| HaError::Transport)?;
        let encoded_nanos =
            u64::try_from(remaining.as_nanos()).map_err(|_| HaError::InvalidFrame)?;
        let request = zeroize::Zeroizing::new(encode_after_handshake(remaining)?);
        if request.len() <= HEADER_BYTES || remaining_nanos(&request)? != encoded_nanos {
            return Err(HaError::InvalidFrame);
        }
        forward_remaining(deadline).map_err(|_| HaError::Transport)?;
        write_coalesced_bounded_frame(
            &mut rustls::Stream::new(&mut tls.conn, &mut tls.sock),
            &request,
        )?;
        let mut length = [0_u8; 4];
        tls.read_exact(&mut length)
            .map_err(|_| HaError::Transport)?;
        let length = u32::from_be_bytes(length) as usize;
        if length <= SNAPSHOT_CLOCK_RESPONSE_MAGIC.len() || length > MAX_SNAPSHOT_CLOCK_FRAME_BYTES
        {
            return Err(HaError::InvalidFrame);
        }
        let mut response = zeroize::Zeroizing::new(vec![0_u8; length]);
        tls.read_exact(response.as_mut_slice())
            .map_err(|_| HaError::Transport)?;
        validate_response(&response)?;
        forward_remaining(deadline).map_err(|_| HaError::Transport)?;
        Ok(std::mem::take(&mut *response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(remaining: Duration) -> Vec<u8> {
        let mut frame = SNAPSHOT_CLOCK_REQUEST_MAGIC.to_vec();
        frame.extend_from_slice(&u64::try_from(remaining.as_nanos()).unwrap().to_be_bytes());
        frame.extend_from_slice(b"{}");
        frame
    }

    #[test]
    fn snapshot_clock_receiver_charges_original_accept_and_caps_outer_deadline() {
        let accepted = Instant::now() - Duration::from_millis(100);
        let outer = accepted + Duration::from_secs(1);
        let frame = request(Duration::from_millis(800));
        assert_eq!(
            inbound_deadline(&frame, accepted, outer, true).unwrap(),
            accepted + Duration::from_millis(800)
        );
        assert_eq!(
            inbound_deadline(&request(Duration::from_secs(2)), accepted, outer, true).unwrap(),
            outer
        );
        assert!(
            inbound_deadline(&request(Duration::from_millis(50)), accepted, outer, true).is_err()
        );
    }

    #[test]
    fn snapshot_clock_never_accepts_legacy_alpn_or_oversized_private_frames() {
        let accepted = Instant::now();
        let outer = accepted + Duration::from_secs(1);
        let mut frame = request(Duration::from_millis(500));
        assert_eq!(
            inbound_deadline(&frame, accepted, outer, false),
            Err(HaError::PeerAuthenticationFailed)
        );
        frame.resize(MAX_SNAPSHOT_CLOCK_FRAME_BYTES + 1, 0);
        assert!(inbound_deadline(&frame, accepted, outer, true).is_err());
        assert!(inbound_deadline(&request(Duration::ZERO), accepted, outer, true).is_err());
        assert!(
            inbound_deadline(&request(Duration::from_secs(61)), accepted, outer, true).is_err()
        );
        assert!(validate_response(b"HBFS6{}").is_err());
        assert!(validate_response(b"HBSC2{}").is_ok());
    }
}
