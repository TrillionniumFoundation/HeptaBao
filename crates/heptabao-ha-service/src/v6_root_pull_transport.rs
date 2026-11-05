//! Cancellable, owned I/O for private committed-root repair only. The ordinary
//! forwarding and replication transports retain their existing implementation.
//! Dropping this future closes its sole socket even during connect or TLS. Its
//! caller retains and joins the task; no detached blocking socket job remains.
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

impl MutualTlsPeerTransport {
    pub(super) async fn exchange_root_pull_before_pinned_server(
        &self,
        peer: &NodeId,
        frame: &[u8],
        caller_deadline: Instant,
        expected_server_leaf_sha256: [u8; 32],
    ) -> Result<Vec<u8>, HaError> {
        if expected_server_leaf_sha256 == [0; 32] {
            return Err(HaError::PeerAuthenticationFailed);
        }
        if !is_native_v6_root_pull_frame(frame)
            || frame.is_empty()
            || frame.len() > MAX_PAYLOAD_BYTES + 4096
        {
            return Err(HaError::InvalidFrame);
        }
        let deadline = caller_deadline.min(Instant::now() + self.timeout);
        forward_remaining(deadline).map_err(|_| HaError::Transport)?;
        let endpoint = self.peers.get(peer).ok_or(HaError::UnknownPeer)?;
        let server_name = rustls::pki_types::ServerName::try_from(endpoint.server_name.clone())
            .map_err(|_| HaError::InvalidCluster)?;
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            let stream = tokio::net::TcpStream::connect(endpoint.address)
                .await
                .map_err(|_| HaError::Transport)?;
            stream.set_nodelay(true).map_err(|_| HaError::Transport)?;
            let connector = tokio_rustls::TlsConnector::from(self.client_config.clone());
            let mut tls = connector
                .connect(server_name, stream)
                .await
                .map_err(|_| HaError::PeerAuthenticationFailed)?;

            // The same strict ALPN, full bounded certificate chain and exact
            // enrolled leaf checks as the blocking pinned transport, completed
            // BEFORE any request frame is sent. No early data is submitted.
            let connection = tls.get_ref().1;
            if connection.alpn_protocol() != Some(RAFT_ALPN_PROTOCOL) {
                return Err(HaError::PeerAuthenticationFailed);
            }
            let chain = connection
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
            forward_remaining(deadline).map_err(|_| HaError::Transport)?;
            let length = u32::try_from(frame.len()).map_err(|_| HaError::InvalidFrame)?;
            tls.write_all(&length.to_be_bytes())
                .await
                .map_err(|error| forward_transport_io_error("frame_write_length", &error))?;
            tls.write_all(frame)
                .await
                .map_err(|error| forward_transport_io_error("frame_write_payload", &error))?;
            tls.flush()
                .await
                .map_err(|error| forward_transport_io_error("frame_flush", &error))?;
            let mut length = [0_u8; 4];
            tls.read_exact(&mut length)
                .await
                .map_err(|error| forward_transport_io_error("frame_read_length", &error))?;
            let length = u32::from_be_bytes(length) as usize;
            if length == 0 || length > MAX_PAYLOAD_BYTES + 4096 {
                return Err(HaError::InvalidFrame);
            }
            let mut response = zeroize::Zeroizing::new(vec![0_u8; length]);
            tls.read_exact(response.as_mut_slice())
                .await
                .map_err(|error| forward_transport_io_error("frame_read_payload", &error))?;
            // Buffered plaintext and a ready future cannot bypass the original
            // absolute deadline. Rejected response bytes are still zeroized.
            forward_remaining(deadline).map_err(|_| HaError::Transport)?;
            Ok(std::mem::take(&mut *response))
        })
        .await
        .map_err(|_| HaError::Transport)?
    }
}
