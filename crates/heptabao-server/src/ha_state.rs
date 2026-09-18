//! Fail-closed encoding for authoritative server-state proposals replicated by HA.
//!
//! A proposal carries the digest of the state from which it was derived. The
//! current leader must compare that base digest with the latest committed
//! state before admitting the proposal. The complete next state is sealed under
//! a cluster replication key, so nondeterministic values (token IDs, Transit
//! key material, TOTP seeds) are generated exactly once and are never
//! reconstructed independently on followers.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::{
    aead, digest,
    rand::{SecureRandom, SystemRandom},
};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 5] = b"HBSR1";
const MANIFEST_MAGIC: &[u8; 5] = b"HBSM2";
const CHUNK_MAGIC: &[u8; 5] = b"HBSC2";
const NONCE_BYTES: usize = 12;
const DIGEST_BYTES: usize = 32;
const TAG_BYTES: usize = 16;
const MAX_CLUSTER_ID_BYTES: usize = 128;
const MAX_OPERATION_ID_BYTES: usize = 128;
const MAX_STATE_BYTES: usize = crate::MAX_APPLICATION_STATE_BYTES;
pub(crate) const REPLICATED_STATE_CHUNK_BYTES: usize = 384 * 1024;
pub(crate) const MAX_REPLICATED_STATE_CHUNKS: usize =
    MAX_STATE_BYTES.div_ceil(REPLICATED_STATE_CHUNK_BYTES);
const HEADER_BYTES: usize = MAGIC.len() + DIGEST_BYTES + NONCE_BYTES;
const MANIFEST_HEADER_BYTES: usize = MANIFEST_MAGIC.len() + DIGEST_BYTES + NONCE_BYTES;
const CHUNK_HEADER_BYTES: usize = CHUNK_MAGIC.len() + NONCE_BYTES;

#[derive(Clone, Eq, PartialEq)]
pub struct ReplicatedStateProposal {
    operation_id: String,
    digest: [u8; 32],
    sealed: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplicatedChunkRef {
    pub index: u16,
    pub slot: u8,
    pub bytes: u32,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplicatedStateManifest {
    pub base_digest: [u8; 32],
    pub state_digest: [u8; 32],
    pub total_bytes: u64,
    pub chunks: Vec<ReplicatedChunkRef>,
}

pub(crate) enum CommittedStateDescriptor {
    Legacy(Zeroizing<Vec<u8>>),
    Chunked(ReplicatedStateManifest),
}

impl ReplicatedStateProposal {
    fn new(
        operation_id: String,
        digest: [u8; 32],
        sealed: Vec<u8>,
    ) -> Result<Self, ReplicatedStateError> {
        validate_operation_id(&operation_id)?;
        let valid_sealed_size = if sealed.starts_with(MAGIC) {
            (HEADER_BYTES + TAG_BYTES..=HEADER_BYTES + MAX_STATE_BYTES + TAG_BYTES)
                .contains(&sealed.len())
        } else if sealed.starts_with(MANIFEST_MAGIC) {
            let max_manifest_body = 10 + MAX_REPLICATED_STATE_CHUNKS * (2 + 1 + 4 + DIGEST_BYTES);
            (MANIFEST_HEADER_BYTES + TAG_BYTES
                ..=MANIFEST_HEADER_BYTES + max_manifest_body + TAG_BYTES)
                .contains(&sealed.len())
        } else if sealed.starts_with(CHUNK_MAGIC) {
            (CHUNK_HEADER_BYTES + 1 + TAG_BYTES
                ..=CHUNK_HEADER_BYTES + REPLICATED_STATE_CHUNK_BYTES + TAG_BYTES)
                .contains(&sealed.len())
        } else {
            false
        };
        if digest == [0; 32] || !valid_sealed_size {
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
            || !(cluster_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
                || STANDARD
                    .decode(&cluster_id)
                    .is_ok_and(|bytes| bytes.len() == 16 && STANDARD.encode(&bytes) == cluster_id))
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
    /// for a truly empty application state; a cluster enabled after single-node
    /// initialization anchors its first proposal to the actual local state digest.
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

    pub(crate) fn seal_chunk(
        &self,
        operation_id: impl Into<String>,
        index: u16,
        slot: u8,
        plaintext: &[u8],
    ) -> Result<ReplicatedStateProposal, ReplicatedStateError> {
        let operation_id = operation_id.into();
        validate_operation_id(&operation_id)?;
        if usize::from(index) >= MAX_REPLICATED_STATE_CHUNKS
            || slot > 1
            || plaintext.is_empty()
            || plaintext.len() > REPLICATED_STATE_CHUNK_BYTES
        {
            return Err(ReplicatedStateError::InvalidState);
        }
        let chunk_digest = sha256(plaintext);
        let aad = self.chunk_aad(
            &operation_id,
            index,
            slot,
            chunk_digest,
            u32::try_from(plaintext.len()).map_err(|_| ReplicatedStateError::InvalidState)?,
        )?;
        let mut nonce = [0_u8; NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ReplicatedStateError::RandomnessUnavailable)?;
        let mut ciphertext = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut ciphertext,
            )
            .map_err(|_| ReplicatedStateError::AuthenticationFailed)?;
        let mut sealed = Vec::with_capacity(CHUNK_HEADER_BYTES + ciphertext.len());
        sealed.extend_from_slice(CHUNK_MAGIC);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        ciphertext.zeroize();
        ReplicatedStateProposal::new(operation_id, chunk_digest, sealed)
    }

    pub(crate) fn open_chunk_parts(
        &self,
        index: u16,
        slot: u8,
        operation_id: &str,
        digest: [u8; 32],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ReplicatedStateError> {
        if usize::from(index) >= MAX_REPLICATED_STATE_CHUNKS
            || slot > 1
            || sealed.len() < CHUNK_HEADER_BYTES + TAG_BYTES
            || sealed.len() > CHUNK_HEADER_BYTES + REPLICATED_STATE_CHUNK_BYTES + TAG_BYTES
            || &sealed[..CHUNK_MAGIC.len()] != CHUNK_MAGIC
        {
            return Err(ReplicatedStateError::InvalidEnvelope);
        }
        validate_operation_id(operation_id)?;
        let nonce_offset = CHUNK_MAGIC.len();
        let payload_offset = nonce_offset + NONCE_BYTES;
        let nonce: [u8; NONCE_BYTES] = sealed[nonce_offset..payload_offset]
            .try_into()
            .map_err(|_| ReplicatedStateError::InvalidEnvelope)?;
        let plaintext_len = sealed
            .len()
            .checked_sub(CHUNK_HEADER_BYTES + TAG_BYTES)
            .ok_or(ReplicatedStateError::InvalidEnvelope)?;
        let aad = self.chunk_aad(
            operation_id,
            index,
            slot,
            digest,
            u32::try_from(plaintext_len).map_err(|_| ReplicatedStateError::InvalidEnvelope)?,
        )?;
        let mut ciphertext = Zeroizing::new(sealed[payload_offset..].to_vec());
        let plaintext = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                ciphertext.as_mut_slice(),
            )
            .map_err(|_| ReplicatedStateError::AuthenticationFailed)?;
        if plaintext.is_empty()
            || plaintext.len() > REPLICATED_STATE_CHUNK_BYTES
            || sha256(plaintext) != digest
        {
            return Err(ReplicatedStateError::DigestMismatch);
        }
        Ok(Zeroizing::new(plaintext.to_vec()))
    }

    pub(crate) fn seal_manifest(
        &self,
        operation_id: impl Into<String>,
        base_digest: [u8; 32],
        plaintext_state: &[u8],
        chunks: Vec<ReplicatedChunkRef>,
    ) -> Result<ReplicatedStateProposal, ReplicatedStateError> {
        let operation_id = operation_id.into();
        validate_operation_id(&operation_id)?;
        if plaintext_state.is_empty() || plaintext_state.len() > MAX_STATE_BYTES {
            return Err(ReplicatedStateError::InvalidState);
        }
        let state_digest = sha256(plaintext_state);
        let total_bytes =
            u64::try_from(plaintext_state.len()).map_err(|_| ReplicatedStateError::InvalidState)?;
        validate_manifest_parts(total_bytes, &chunks)?;
        let body = encode_manifest_body(total_bytes, &chunks)?;
        let aad = self.manifest_aad(&operation_id, base_digest, state_digest)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ReplicatedStateError::RandomnessUnavailable)?;
        let mut ciphertext = body;
        self.key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut ciphertext,
            )
            .map_err(|_| ReplicatedStateError::AuthenticationFailed)?;
        let mut sealed = Vec::with_capacity(MANIFEST_HEADER_BYTES + ciphertext.len());
        sealed.extend_from_slice(MANIFEST_MAGIC);
        sealed.extend_from_slice(&base_digest);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        ciphertext.zeroize();
        ReplicatedStateProposal::new(operation_id, state_digest, sealed)
    }

    pub(crate) fn open_committed_descriptor(
        &self,
        operation_id: &str,
        digest: [u8; 32],
        sealed: &[u8],
    ) -> Result<CommittedStateDescriptor, ReplicatedStateError> {
        if sealed.starts_with(MAGIC) {
            return self
                .open_committed_parts(operation_id, digest, sealed)
                .map(CommittedStateDescriptor::Legacy);
        }
        if sealed.len() < MANIFEST_HEADER_BYTES + TAG_BYTES || !sealed.starts_with(MANIFEST_MAGIC) {
            return Err(ReplicatedStateError::InvalidEnvelope);
        }
        validate_operation_id(operation_id)?;
        let base_offset = MANIFEST_MAGIC.len();
        let nonce_offset = base_offset + DIGEST_BYTES;
        let payload_offset = nonce_offset + NONCE_BYTES;
        let base_digest: [u8; DIGEST_BYTES] = sealed[base_offset..nonce_offset]
            .try_into()
            .map_err(|_| ReplicatedStateError::InvalidEnvelope)?;
        let nonce: [u8; NONCE_BYTES] = sealed[nonce_offset..payload_offset]
            .try_into()
            .map_err(|_| ReplicatedStateError::InvalidEnvelope)?;
        let aad = self.manifest_aad(operation_id, base_digest, digest)?;
        let mut ciphertext = Zeroizing::new(sealed[payload_offset..].to_vec());
        let plaintext = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                ciphertext.as_mut_slice(),
            )
            .map_err(|_| ReplicatedStateError::AuthenticationFailed)?;
        let (total_bytes, chunks) = decode_manifest_body(plaintext)?;
        validate_manifest_parts(total_bytes, &chunks)?;
        Ok(CommittedStateDescriptor::Chunked(ReplicatedStateManifest {
            base_digest,
            state_digest: digest,
            total_bytes,
            chunks,
        }))
    }

    /// Recover a proposal after checking that it extends the exact state expected
    /// by the caller. Leaders use this property to reject stale proposals.
    pub fn open(
        &self,
        proposal: &ReplicatedStateProposal,
        expected_base_digest: [u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, ReplicatedStateError> {
        let (base_digest, nonce, payload_offset) = validate_envelope(proposal)?;
        if base_digest != expected_base_digest {
            return Err(ReplicatedStateError::BaseStateConflict);
        }
        self.open_validated(proposal, base_digest, nonce, payload_offset)
    }

    /// Authenticate the latest envelope already proven committed by the local
    /// Raft state machine. Followers may use this to jump directly to the latest
    /// complete state after ReadIndex, even when snapshots compacted intermediate
    /// proposals. This must not be used to admit a new leader proposal.
    pub(crate) fn open_committed_parts(
        &self,
        operation_id: &str,
        digest: [u8; 32],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ReplicatedStateError> {
        let proposal =
            ReplicatedStateProposal::new(operation_id.to_owned(), digest, sealed.to_vec())?;
        let (base_digest, nonce, payload_offset) = validate_envelope(&proposal)?;
        self.open_validated(&proposal, base_digest, nonce, payload_offset)
    }

    fn open_validated(
        &self,
        proposal: &ReplicatedStateProposal,
        base_digest: [u8; 32],
        nonce: [u8; NONCE_BYTES],
        payload_offset: usize,
    ) -> Result<Zeroizing<Vec<u8>>, ReplicatedStateError> {
        let aad = self.aad(proposal.operation_id(), base_digest, proposal.digest())?;
        let mut ciphertext = Zeroizing::new(proposal.sealed()[payload_offset..].to_vec());
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
        let (base_digest, _, _) = validate_envelope(proposal)?;
        Ok(base_digest)
    }

    fn chunk_aad(
        &self,
        operation_id: &str,
        index: u16,
        slot: u8,
        chunk_digest: [u8; 32],
        chunk_bytes: u32,
    ) -> Result<Vec<u8>, ReplicatedStateError> {
        validate_operation_id(operation_id)?;
        let cluster_len = u16::try_from(self.cluster_id.len())
            .map_err(|_| ReplicatedStateError::InvalidCluster)?;
        let operation_len =
            u16::try_from(operation_id.len()).map_err(|_| ReplicatedStateError::InvalidEnvelope)?;
        let mut aad = Vec::with_capacity(
            CHUNK_MAGIC.len()
                + 2
                + self.cluster_id.len()
                + 2
                + operation_id.len()
                + 2
                + 1
                + 4
                + DIGEST_BYTES,
        );
        aad.extend_from_slice(CHUNK_MAGIC);
        aad.extend_from_slice(&cluster_len.to_be_bytes());
        aad.extend_from_slice(self.cluster_id.as_bytes());
        aad.extend_from_slice(&operation_len.to_be_bytes());
        aad.extend_from_slice(operation_id.as_bytes());
        aad.extend_from_slice(&index.to_be_bytes());
        aad.push(slot);
        aad.extend_from_slice(&chunk_bytes.to_be_bytes());
        aad.extend_from_slice(&chunk_digest);
        Ok(aad)
    }

    fn manifest_aad(
        &self,
        operation_id: &str,
        base_digest: [u8; 32],
        next_digest: [u8; 32],
    ) -> Result<Vec<u8>, ReplicatedStateError> {
        validate_operation_id(operation_id)?;
        let cluster_len = u16::try_from(self.cluster_id.len())
            .map_err(|_| ReplicatedStateError::InvalidCluster)?;
        let operation_len =
            u16::try_from(operation_id.len()).map_err(|_| ReplicatedStateError::InvalidEnvelope)?;
        let mut aad = Vec::with_capacity(
            MANIFEST_MAGIC.len()
                + 2
                + self.cluster_id.len()
                + 2
                + operation_id.len()
                + DIGEST_BYTES * 2,
        );
        aad.extend_from_slice(MANIFEST_MAGIC);
        aad.extend_from_slice(&cluster_len.to_be_bytes());
        aad.extend_from_slice(self.cluster_id.as_bytes());
        aad.extend_from_slice(&operation_len.to_be_bytes());
        aad.extend_from_slice(operation_id.as_bytes());
        aad.extend_from_slice(&base_digest);
        aad.extend_from_slice(&next_digest);
        Ok(aad)
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

fn validate_operation_id(operation_id: &str) -> Result<(), ReplicatedStateError> {
    if operation_id.is_empty()
        || operation_id.len() > MAX_OPERATION_ID_BYTES
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ReplicatedStateError::InvalidEnvelope);
    }
    Ok(())
}

fn validate_manifest_parts(
    total_bytes: u64,
    chunks: &[ReplicatedChunkRef],
) -> Result<(), ReplicatedStateError> {
    let total = usize::try_from(total_bytes).map_err(|_| ReplicatedStateError::InvalidState)?;
    if total == 0
        || total > MAX_STATE_BYTES
        || chunks.is_empty()
        || chunks.len() > MAX_REPLICATED_STATE_CHUNKS
        || chunks.len() != total.div_ceil(REPLICATED_STATE_CHUNK_BYTES)
    {
        return Err(ReplicatedStateError::InvalidState);
    }
    let mut observed = 0_usize;
    for (position, chunk) in chunks.iter().enumerate() {
        if usize::from(chunk.index) != position || chunk.slot > 1 || chunk.digest == [0; 32] {
            return Err(ReplicatedStateError::InvalidEnvelope);
        }
        let bytes = usize::try_from(chunk.bytes).map_err(|_| ReplicatedStateError::InvalidState)?;
        let last = position + 1 == chunks.len();
        if bytes == 0
            || bytes > REPLICATED_STATE_CHUNK_BYTES
            || (!last && bytes != REPLICATED_STATE_CHUNK_BYTES)
        {
            return Err(ReplicatedStateError::InvalidState);
        }
        observed = observed
            .checked_add(bytes)
            .ok_or(ReplicatedStateError::InvalidState)?;
    }
    if observed != total {
        return Err(ReplicatedStateError::InvalidState);
    }
    Ok(())
}

fn encode_manifest_body(
    total_bytes: u64,
    chunks: &[ReplicatedChunkRef],
) -> Result<Vec<u8>, ReplicatedStateError> {
    validate_manifest_parts(total_bytes, chunks)?;
    let mut body = Vec::with_capacity(8 + 2 + chunks.len() * (2 + 1 + 4 + DIGEST_BYTES));
    body.extend_from_slice(&total_bytes.to_be_bytes());
    body.extend_from_slice(
        &u16::try_from(chunks.len())
            .map_err(|_| ReplicatedStateError::InvalidState)?
            .to_be_bytes(),
    );
    for chunk in chunks {
        body.extend_from_slice(&chunk.index.to_be_bytes());
        body.push(chunk.slot);
        body.extend_from_slice(&chunk.bytes.to_be_bytes());
        body.extend_from_slice(&chunk.digest);
    }
    Ok(body)
}

fn decode_manifest_body(
    bytes: &[u8],
) -> Result<(u64, Vec<ReplicatedChunkRef>), ReplicatedStateError> {
    if bytes.len() < 10 {
        return Err(ReplicatedStateError::InvalidEnvelope);
    }
    let total_bytes = u64::from_be_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| ReplicatedStateError::InvalidEnvelope)?,
    );
    let count = usize::from(u16::from_be_bytes(
        bytes[8..10]
            .try_into()
            .map_err(|_| ReplicatedStateError::InvalidEnvelope)?,
    ));
    let record_bytes = 2 + 1 + 4 + DIGEST_BYTES;
    let expected = 10_usize
        .checked_add(
            count
                .checked_mul(record_bytes)
                .ok_or(ReplicatedStateError::InvalidEnvelope)?,
        )
        .ok_or(ReplicatedStateError::InvalidEnvelope)?;
    if bytes.len() != expected {
        return Err(ReplicatedStateError::InvalidEnvelope);
    }
    let mut chunks = Vec::with_capacity(count);
    let mut offset = 10;
    for _ in 0..count {
        let index = u16::from_be_bytes(
            bytes[offset..offset + 2]
                .try_into()
                .map_err(|_| ReplicatedStateError::InvalidEnvelope)?,
        );
        offset += 2;
        let slot = bytes[offset];
        offset += 1;
        let chunk_bytes = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| ReplicatedStateError::InvalidEnvelope)?,
        );
        offset += 4;
        let digest = bytes[offset..offset + DIGEST_BYTES]
            .try_into()
            .map_err(|_| ReplicatedStateError::InvalidEnvelope)?;
        offset += DIGEST_BYTES;
        chunks.push(ReplicatedChunkRef {
            index,
            slot,
            bytes: chunk_bytes,
            digest,
        });
    }
    Ok((total_bytes, chunks))
}

fn validate_envelope(
    proposal: &ReplicatedStateProposal,
) -> Result<([u8; DIGEST_BYTES], [u8; NONCE_BYTES], usize), ReplicatedStateError> {
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
    let base_digest = sealed[base_offset..nonce_offset]
        .try_into()
        .map_err(|_| ReplicatedStateError::InvalidEnvelope)?;
    let nonce = sealed[nonce_offset..payload_offset]
        .try_into()
        .map_err(|_| ReplicatedStateError::InvalidEnvelope)?;
    Ok((base_digest, nonce, payload_offset))
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
    fn canonical_initialized_cluster_identity_is_supported()
    -> Result<(), Box<dyn std::error::Error>> {
        // Initialization persists STANDARD base64 of sixteen random bytes.
        // Do not silently rewrite that identity when enrolling the same state in HA.
        let id = STANDARD.encode([255; 16]);
        let codec = ClusterStateCodec::new(&id, [7; 32])?;
        let proposal = codec.seal("request-1", [1; 32], b"state")?;
        assert_eq!(codec.open(&proposal, [1; 32])?.as_slice(), b"state");
        for bad in [
            "bad/identity",
            "bad=padding",
            "\ncluster",
            "/////////////////////x==",
        ] {
            assert!(matches!(
                ClusterStateCodec::new(bad, [7; 32]),
                Err(ReplicatedStateError::InvalidCluster)
            ));
        }
        Ok(())
    }

    #[test]
    fn chunked_manifest_round_trip_reconstructs_exact_state_and_binds_slots()
    -> Result<(), Box<dyn std::error::Error>> {
        let codec = ClusterStateCodec::new("cluster-chunked", [13; 32])?;
        let base = [4; 32];
        let state = vec![0x5a; REPLICATED_STATE_CHUNK_BYTES + 73];
        let mut refs = Vec::new();
        let mut opened = Vec::new();
        for (position, chunk) in state.chunks(REPLICATED_STATE_CHUNK_BYTES).enumerate() {
            let index = u16::try_from(position)?;
            let slot = u8::try_from(position % 2)?;
            let operation = format!("chunk-op:{index}:{slot}");
            let proposal = codec.seal_chunk(operation.clone(), index, slot, chunk)?;
            let plaintext = codec.open_chunk_parts(
                index,
                slot,
                proposal.operation_id(),
                proposal.digest(),
                proposal.sealed(),
            )?;
            opened.extend_from_slice(&plaintext);
            refs.push(ReplicatedChunkRef {
                index,
                slot,
                bytes: u32::try_from(chunk.len())?,
                digest: proposal.digest(),
            });
            assert!(matches!(
                codec.open_chunk_parts(
                    index,
                    1 - slot,
                    proposal.operation_id(),
                    proposal.digest(),
                    proposal.sealed()
                ),
                Err(ReplicatedStateError::AuthenticationFailed)
            ));
        }
        assert_eq!(opened, state);

        let manifest = codec.seal_manifest("state-op", base, &state, refs.clone())?;
        let descriptor = codec.open_committed_descriptor(
            manifest.operation_id(),
            manifest.digest(),
            manifest.sealed(),
        )?;
        match descriptor {
            CommittedStateDescriptor::Chunked(decoded) => {
                assert_eq!(decoded.base_digest, base);
                assert_eq!(decoded.state_digest, sha256(&state));
                assert_eq!(usize::try_from(decoded.total_bytes)?, state.len());
                assert_eq!(decoded.chunks, refs);
            }
            CommittedStateDescriptor::Legacy(_) => return Err("expected chunked manifest".into()),
        }

        let legacy = codec.seal("legacy-op", base, b"legacy-state")?;
        assert!(matches!(
            codec.open_committed_descriptor(
                legacy.operation_id(),
                legacy.digest(),
                legacy.sealed()
            )?,
            CommittedStateDescriptor::Legacy(_)
        ));
        Ok(())
    }

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
        assert_eq!(
            codec
                .open_committed_parts(
                    proposal.operation_id(),
                    proposal.digest(),
                    proposal.sealed()
                )?
                .as_slice(),
            state
        );
        Ok(())
    }

    #[test]
    fn ha_replication_accepts_state_above_legacy_768k_bound_and_rejects_over_shared_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let codec = ClusterStateCodec::new("cluster-large", [11; 32])?;
        let base = [5; 32];
        let state = vec![0x5a; 1024 * 1024];
        let proposal = codec.seal("request-large", base, &state)?;
        assert_eq!(codec.open(&proposal, base)?.as_slice(), state.as_slice());

        let oversized = vec![0_u8; MAX_STATE_BYTES + 1];
        assert!(matches!(
            codec.seal("request-too-large", base, &oversized),
            Err(ReplicatedStateError::InvalidState)
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
        assert!(matches!(
            codec.open_committed_parts(
                tampered.operation_id(),
                tampered.digest(),
                tampered.sealed()
            ),
            Err(ReplicatedStateError::AuthenticationFailed)
        ));
        Ok(())
    }
}
