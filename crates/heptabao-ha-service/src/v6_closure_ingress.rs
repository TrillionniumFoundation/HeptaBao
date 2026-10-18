//! Dispatch from the shared actual TLS listener without a public raw peer-ID
//! assertion. This remains a child of the private closure receiver module.
use super::*;
use crate::AuthenticatedPeerFrame;

/// Classification of untrusted bytes is not authentication or admission.
pub fn is_native_v6_closure_frame(bytes: &[u8]) -> bool {
    bytes.starts_with(b"HBVC2")
}

impl NativeV6ClosureReceiver {
    /// Consume the immutable frame and identity minted by actual TLS. The
    /// legacy configured NodeId is only a routing label: the committed leaf
    /// binding selects the native voter, and receive obtains fresh actual
    /// applied intent/membership/leader admission before any fsync or reply.
    pub fn handle_authenticated(&self, frame: AuthenticatedPeerFrame) -> Result<Vec<u8>, HaError> {
        require_blocking_worker()?;
        check_deadline(frame.deadline())?;
        if !frame.has_strict_raft_alpn() {
            return Err(HaError::PeerAuthenticationFailed);
        }
        let peer = self
            .pinned
            .by_leaf_sha256
            .get(&frame.actual_leaf_sha256())
            .cloned()
            .ok_or(HaError::UnknownPeer)?;
        let timeout = frame
            .deadline()
            .checked_duration_since(frame.accepted_at())
            .ok_or(HaError::Transport)?;
        self.receive(&peer, frame.payload(), frame.accepted_at(), timeout)
    }
}
