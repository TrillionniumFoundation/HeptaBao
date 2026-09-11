//! Fail-closed encoding for authoritative server-state proposals replicated by HA.
//!
//! A proposal carries the digest of the state from which it was derived. The
//! current leader must compare that base digest with the latest committed
//! state before admitting the proposal. The complete next state is sealed under
//! a cluster replication key, so nondeterministic values (token IDs, Transit
//! key material, TOTP seeds) are generated exactly once and are never
//! reconstructed independently on followers.

use ring::{
    aead, digest,
    rand::{SecureRandom, SystemRandom},
};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 5] = b"HBSR1";
const NONCE_BYTES: usize = 12;
const DIGEST_BYTES: usize = 32;
const TAG_BYTES: usize = 16;
const MAX_CLUSTER_ID_BYTES: usize = 128;
const MAX_OPERATION_ID_BYTES: usize = 128;
const MAX_STATE_BYTES: usize = 768 * 1024;
const HEADER_BYTES: usize = MAGIC.len() + DIGEST_BYTES + NONCE_BYTES;

#[derive(Clone, Eq, PartialEq)]
pub struct ReplicatedStateProposal {
    operation_id: String,
    digest: [u8; 32],
    sealed: Vec<u8>,
}

impl ReplicatedStateProposal {
    fn new(
        operation_id: String,
        digest: [u8; 32],
        sealed: Vec<u8>,
    ) -> Result<Self, ReplicatedStateError> {
        if operation_id.is_empty()
            || operation_id.len() > MAX_OPERATION_ID_BYTES
            || !operation_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
            || digest == [0; 32]
            || sealed.len() < HEADER_BYTES + TAG_BYTES
            || sealed.len() > HEADER_BYTES + MAX_STATE_BYTES + TAG_BYTES
        {
            return Err(ReplicatedStateError::InvalidEnvelope);
        }
        Ok(Self {
            operation_id,
            digest,
            sealed,
        })
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn sealed(&self) -> &[u8] {
        &self.sealed
    }
}

impl fmt::Debug for ReplicatedStateProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicatedStateProposal")
            .field("operation_id", &"[REDACTED]")
            .field("digest", &"[REDACTED]")
            .field("sealed_bytes", &self.sealed.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicatedStateError {
    InvalidKey,
    InvalidCluster,
    InvalidState,
    InvalidEnvelope,
    BaseStateConflict,
    AuthenticationFailed,
    DigestMismatch,
    RandomnessUnavailable,
}

impl fmt::Display for ReplicatedStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidKey => "cluster replication key is invalid",
            Self::InvalidCluster => "cluster replication identity is invalid",
            Self::InvalidState => "replicated state is empty or exceeds the bounded maximum",
            Self::InvalidEnvelope => "replicated state envelope is malformed",
            Self::BaseStateConflict => "replicated state was derived from a stale base",
            Self::AuthenticationFailed => "replicated state authentication failed",
            Self::DigestMismatch => "replicated state digest does not match the committed envelope",
            Self::RandomnessUnavailable => "operating system randomness is unavailable",
        })
    }
}

impl std::error::Error for ReplicatedStateError {}

/// Cluster-wide codec for the application state carried by the HA layer.
///
/// Production custody for the 32-byte replication key is deliberately outside
/// this type. Callers must obtain it from the independently governed KMS/HSM or
/// protected bootstrap channel and must never place it in Raft, logs or config
/// returned by an API.
pub struct ClusterStateCodec {
    cluster_id: String,
    key: aead::LessSafeKey,
}

impl ClusterStateCodec {
    pub fn new(
        cluster_id: impl Into<String>,
        mut key: [u8; 32],
    ) -> Result<Self, ReplicatedStateError> {
        let cluster_id = cluster_id.into();
        if cluster_id.is_empty()
            || cluster_id.len() > MAX_CLUSTER_ID_BYTES
            || !cluster_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            key.zeroize();
            return Err(ReplicatedStateError::InvalidCluster);
        }
        if key == [0; 32] {
            key.zeroize();
            return Err(ReplicatedStateError::InvalidKey);
        }
        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &key)
            .map_err(|_| ReplicatedStateError::InvalidKey);
        key.zeroize();
        Ok(Self {
            cluster_id,
            key: aead::LessSafeKey::new(unbound?),
        })
    }

    /// Build one immutable state proposal. `base_digest == [0; 32]` is reserved
    /// for the first application-state commit in an otherwise empty HA state.
    pub fn seal(
        &self,
        operation_id: impl Into<String>,
        base_digest: [u8; 32],
        plaintext_state: &[u8],
    ) -> Result<ReplicatedStateProposal, ReplicatedStateError> {
        if plaintext_state.is_empty() || plaintext_state.len() > MAX_STATE_BYTES {
            return Err(ReplicatedStateError::InvalidState);
        }
        let operation_id = operation_id.into();
        let next_digest = sha256(plaintext_state);
        let aad = self.aad(&operation_id, base_digest, next_digest)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ReplicatedStateError::RandomnessUnavailable)?;
        let mut ciphertext = plaintext_state.to_vec();
        self.key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut ciphertext,
            )
            .map_err(|_| ReplicatedStateError::AuthenticationFailed)?;
        let mut sealed = Vec::with_capacity(HEADER_BYTES + ciphertext.len());
        sealed.extend_from_slice(MAGIC);
        sealed.extend_from_slice(&base_digest);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        ciphertext.zeroize();
        ReplicatedStateProposal::new(operation_id, next_digest, sealed)
    }

    /// Recover a committed candidate after checking that it extends the exact
    /// state expected by this node. A stale base is never silently installed.
    pub fn open(
        &self,
        proposal: &ReplicatedStateProposal,
        expected_base_digest: [u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, ReplicatedStateError> {
        let sealed = proposal.sealed();
        if sealed.len() < HEADER_BYTES + TAG_BYTES
            || sealed.len() > HEADER_BYTES + MAX_STATE_BYTES + TAG_BYTES
        {
            return Err(ReplicatedStateError::InvalidEnvelope);
        }
        if &sealed[..MAGIC.len()] != MAGIC {
            return Err(ReplicatedStateError::InvalidEnvelope);
        }
        let base_offset = MAGIC.len();
        let nonce_offset = base_offset + DIGEST_BYTES;
        let payload_offset = nonce_offset + NONCE_BYTES;
        let base_digest: [u8; DIGEST_BYTES] = sealed[base_offset..nonce_offset]
            .try_into()
            .map_err(|_| ReplicatedStateError::InvalidEnvelope)?;
        if base_digest != expected_base_digest {
            return Err(ReplicatedStateError::BaseStateConflict);
        }
        let nonce: [u8; NONCE_BYTES] = sealed[nonce_offset..payload_offset]
            .try_into()
            .map_err(|_| ReplicatedStateError::InvalidEnvelope)?;
        let aad = self.aad(proposal.operation_id(), base_digest, proposal.digest())?;
        let mut ciphertext = Zeroizing::new(sealed[payload_offset..].to_vec());
        let plaintext = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                ciphertext.as_mut_slice(),
            )
            .map_err(|_| ReplicatedStateError::AuthenticationFailed)?;
        if plaintext.is_empty() || plaintext.len() > MAX_STATE_BYTES {
            return Err(ReplicatedStateError::InvalidState);
        }
        if sha256(plaintext) != proposal.digest() {
            return Err(ReplicatedStateError::DigestMismatch);
        }
        Ok(Zeroizing::new(plaintext.to_vec()))
    }

    pub fn base_digest(
        proposal: &ReplicatedStateProposal,
    ) -> Result<[u8; 32], ReplicatedStateError> {
        let sealed = proposal.sealed();
        if sealed.len() < HEADER_BYTES + TAG_BYTES || &sealed[..MAGIC.len()] != MAGIC {
            return Err(ReplicatedStateError::InvalidEnvelope);
        }
        sealed[MAGIC.len()..MAGIC.len() + DIGEST_BYTES]
            .try_into()
            .map_err(|_| ReplicatedStateError::InvalidEnvelope)
    }

    fn aad(
        &self,
        operation_id: &str,
        base_digest: [u8; 32],
        next_digest: [u8; 32],
    ) -> Result<Vec<u8>, ReplicatedStateError> {
        if operation_id.is_empty() || operation_id.len() > MAX_OPERATION_ID_BYTES {
            return Err(ReplicatedStateError::InvalidEnvelope);
        }
        let cluster_len = u16::try_from(self.cluster_id.len())
            .map_err(|_| ReplicatedStateError::InvalidCluster)?;
        let operation_len =
            u16::try_from(operation_id.len()).map_err(|_| ReplicatedStateError::InvalidEnvelope)?;
        let mut aad = Vec::with_capacity(
            MAGIC.len() + 2 + self.cluster_id.len() + 2 + operation_id.len() + DIGEST_BYTES * 2,
        );
        aad.extend_from_slice(MAGIC);
        aad.extend_from_slice(&cluster_len.to_be_bytes());
        aad.extend_from_slice(self.cluster_id.as_bytes());
        aad.extend_from_slice(&operation_len.to_be_bytes());
        aad.extend_from_slice(operation_id.as_bytes());
        aad.extend_from_slice(&base_digest);
        aad.extend_from_slice(&next_digest);
        Ok(aad)
    }
}

impl fmt::Debug for ClusterStateCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClusterStateCodec")
            .field("cluster_id", &self.cluster_id)
            .field("key", &"[REDACTED]")
            .finish()
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
    fn proposal_round_trip_is_base_fenced_and_authenticated()
    -> Result<(), Box<dyn std::error::Error>> {
        let codec = ClusterStateCodec::new("cluster-a", [9; 32])?;
        let base = [3; 32];
        let state = br#"{"schema":1,"value":"nondeterministic-generated-once"}"#;
        let proposal = codec.seal("request:42", base, state)?;
        assert_eq!(ClusterStateCodec::base_digest(&proposal)?, base);
        assert_eq!(codec.open(&proposal, base)?.as_slice(), state);
        assert!(matches!(
            codec.open(&proposal, [4; 32]),
            Err(ReplicatedStateError::BaseStateConflict)
        ));
        Ok(())
    }

    #[test]
    fn proposal_tamper_and_cross_cluster_reuse_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let codec = ClusterStateCodec::new("cluster-a", [9; 32])?;
        let other = ClusterStateCodec::new("cluster-b", [9; 32])?;
        let base = [3; 32];
        let proposal = codec.seal("request-1", base, b"authoritative-state")?;
        assert!(matches!(
            other.open(&proposal, base),
            Err(ReplicatedStateError::AuthenticationFailed)
        ));

        let mut sealed = proposal.sealed().to_vec();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        let tampered = ReplicatedStateProposal::new(
            proposal.operation_id().to_owned(),
            proposal.digest(),
            sealed,
        )?;
        assert!(matches!(
            codec.open(&tampered, base),
            Err(ReplicatedStateError::AuthenticationFailed)
        ));
        Ok(())
    }
}
