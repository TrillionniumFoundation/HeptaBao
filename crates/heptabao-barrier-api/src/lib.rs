#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Provider-neutral sealed-state contracts for HeptaBao.
//!
//! This crate defines the versioned envelope and associated-data boundary used
//! between an authoritative domain and durable storage. It deliberately
//! contains no cryptographic implementation, key material or production
//! provider selection.

use std::error::Error;
use std::fmt;

use heptabao_storage_api::{Generation, StoreDomain};

pub const SEALED_ENVELOPE_VERSION: u16 = 1;
pub const MAX_BARRIER_FIELD_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ASSOCIATED_DATA_BYTES: usize = 64 * 1024;

const ENVELOPE_MAGIC: &[u8; 20] = b"HEPTABAO-BARRIER-V1\0";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyEpoch(u64);

impl KeyEpoch {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: u64) -> Result<Self, BarrierContractError> {
        if value == 0 {
            return Err(BarrierContractError::ZeroKeyEpoch);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, BarrierContractError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(BarrierContractError::KeyEpochOverflow),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BarrierPurpose {
    AuthoritativeState,
    Snapshot,
    AuditSegment,
    RecoveryObject,
}

impl BarrierPurpose {
    const fn code(self) -> u8 {
        match self {
            Self::AuthoritativeState => 1,
            Self::Snapshot => 2,
            Self::AuditSegment => 3,
            Self::RecoveryObject => 4,
        }
    }
}

pub struct BarrierContext {
    domain: StoreDomain,
    generation: Generation,
    key_epoch: KeyEpoch,
    purpose: BarrierPurpose,
    caller_associated_data: Vec<u8>,
}

impl BarrierContext {
    pub fn new(
        domain: StoreDomain,
        generation: Generation,
        key_epoch: KeyEpoch,
        purpose: BarrierPurpose,
        mut caller_associated_data: Vec<u8>,
    ) -> Result<Self, BarrierContractError> {
        if caller_associated_data.len() > MAX_ASSOCIATED_DATA_BYTES {
            caller_associated_data.fill(0);
            return Err(BarrierContractError::AssociatedDataTooLarge);
        }
        Ok(Self {
            domain,
            generation,
            key_epoch,
            purpose,
            caller_associated_data,
        })
    }

    pub fn domain(&self) -> &StoreDomain {
        &self.domain
    }

    pub const fn generation(&self) -> Generation {
        self.generation
    }

    pub const fn key_epoch(&self) -> KeyEpoch {
        self.key_epoch
    }

    pub const fn purpose(&self) -> BarrierPurpose {
        self.purpose
    }

    pub fn canonical_associated_data(&self) -> Result<Vec<u8>, BarrierContractError> {
        let mut output = Vec::new();
        append_field(&mut output, b"heptabao-barrier-context-v1")?;
        append_field(&mut output, self.domain.as_str().as_bytes())?;
        append_field(&mut output, &self.generation.get().to_be_bytes())?;
        append_field(&mut output, &self.key_epoch.get().to_be_bytes())?;
        append_field(&mut output, &[self.purpose.code()])?;
        append_field(&mut output, &self.caller_associated_data)?;
        Ok(output)
    }
}

impl fmt::Debug for BarrierContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BarrierContext")
            .field("domain", &self.domain)
            .field("generation", &self.generation)
            .field("key_epoch", &self.key_epoch)
            .field("purpose", &self.purpose)
            .field(
                "caller_associated_data_bytes",
                &self.caller_associated_data.len(),
            )
            .finish()
    }
}

impl Drop for BarrierContext {
    fn drop(&mut self) {
        self.caller_associated_data.fill(0);
    }
}

#[derive(Eq, PartialEq)]
pub struct SecretState(Vec<u8>);

impl SecretState {
    pub fn new(mut value: Vec<u8>) -> Result<Self, BarrierContractError> {
        if value.is_empty() || value.len() > MAX_BARRIER_FIELD_BYTES {
            value.fill(0);
            return Err(BarrierContractError::InvalidSecretState);
        }
        Ok(Self(value))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for SecretState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretState")
            .field("bytes", &self.0.len())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SecretState {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Eq, PartialEq)]
pub struct SealedEnvelope {
    version: u16,
    key_epoch: KeyEpoch,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    authentication_tag: Vec<u8>,
}

impl SealedEnvelope {
    pub fn new(
        version: u16,
        key_epoch: KeyEpoch,
        mut nonce: Vec<u8>,
        mut ciphertext: Vec<u8>,
        mut authentication_tag: Vec<u8>,
    ) -> Result<Self, BarrierContractError> {
        if version != SEALED_ENVELOPE_VERSION {
            nonce.fill(0);
            ciphertext.fill(0);
            authentication_tag.fill(0);
            return Err(BarrierContractError::UnsupportedEnvelopeVersion);
        }
        if nonce.is_empty()
            || ciphertext.is_empty()
            || authentication_tag.is_empty()
            || nonce.len() > MAX_BARRIER_FIELD_BYTES
            || ciphertext.len() > MAX_BARRIER_FIELD_BYTES
            || authentication_tag.len() > MAX_BARRIER_FIELD_BYTES
        {
            nonce.fill(0);
            ciphertext.fill(0);
            authentication_tag.fill(0);
            return Err(BarrierContractError::InvalidEnvelopeShape);
        }
        Ok(Self {
            version,
            key_epoch,
            nonce,
            ciphertext,
            authentication_tag,
        })
    }

    pub const fn version(&self) -> u16 {
        self.version
    }

    pub const fn key_epoch(&self) -> KeyEpoch {
        self.key_epoch
    }

    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn authentication_tag(&self) -> &[u8] {
        &self.authentication_tag
    }

    pub fn encode(&self) -> Result<Vec<u8>, BarrierContractError> {
        let nonce_len =
            u32::try_from(self.nonce.len()).map_err(|_| BarrierContractError::LengthOverflow)?;
        let ciphertext_len = u64::try_from(self.ciphertext.len())
            .map_err(|_| BarrierContractError::LengthOverflow)?;
        let tag_len = u32::try_from(self.authentication_tag.len())
            .map_err(|_| BarrierContractError::LengthOverflow)?;

        let mut output = Vec::new();
        output.extend_from_slice(ENVELOPE_MAGIC);
        output.extend_from_slice(&self.version.to_be_bytes());
        output.extend_from_slice(&self.key_epoch.get().to_be_bytes());
        output.extend_from_slice(&nonce_len.to_be_bytes());
        output.extend_from_slice(&ciphertext_len.to_be_bytes());
        output.extend_from_slice(&tag_len.to_be_bytes());
        output.extend_from_slice(&self.nonce);
        output.extend_from_slice(&self.ciphertext);
        output.extend_from_slice(&self.authentication_tag);
        Ok(output)
    }

    pub fn decode(mut encoded: Vec<u8>) -> Result<Self, BarrierContractError> {
        let result = decode_envelope(&encoded);
        encoded.fill(0);
        result
    }
}

impl fmt::Debug for SealedEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedEnvelope")
            .field("version", &self.version)
            .field("key_epoch", &self.key_epoch)
            .field("nonce_bytes", &self.nonce.len())
            .field("ciphertext_bytes", &self.ciphertext.len())
            .field("authentication_tag_bytes", &self.authentication_tag.len())
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SealedEnvelope {
    fn drop(&mut self) {
        self.nonce.fill(0);
        self.ciphertext.fill(0);
        self.authentication_tag.fill(0);
    }
}

pub trait BarrierProvider: fmt::Debug + Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn active_key_epoch(&self) -> Result<KeyEpoch, Self::Error>;

    fn seal(
        &self,
        context: &BarrierContext,
        plaintext: SecretState,
    ) -> Result<SealedEnvelope, Self::Error>;

    fn open(
        &self,
        context: &BarrierContext,
        envelope: SealedEnvelope,
    ) -> Result<SecretState, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarrierContractError {
    ZeroKeyEpoch,
    KeyEpochOverflow,
    InvalidSecretState,
    AssociatedDataTooLarge,
    LengthOverflow,
    UnsupportedEnvelopeVersion,
    InvalidEnvelopeShape,
    TruncatedEnvelope,
    TrailingEnvelopeBytes,
}

impl fmt::Display for BarrierContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroKeyEpoch => "key epoch zero is invalid",
            Self::KeyEpochOverflow => "key epoch overflow",
            Self::InvalidSecretState => "secret state is empty or exceeds the bounded size",
            Self::AssociatedDataTooLarge => "barrier associated data exceeds the bound",
            Self::LengthOverflow => "barrier field length overflow",
            Self::UnsupportedEnvelopeVersion => "sealed envelope version is unsupported",
            Self::InvalidEnvelopeShape => "sealed envelope shape is invalid",
            Self::TruncatedEnvelope => "sealed envelope is truncated",
            Self::TrailingEnvelopeBytes => "sealed envelope has trailing bytes",
        })
    }
}

impl Error for BarrierContractError {}

fn append_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), BarrierContractError> {
    let length = u64::try_from(value.len()).map_err(|_| BarrierContractError::LengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn decode_envelope(encoded: &[u8]) -> Result<SealedEnvelope, BarrierContractError> {
    let mut cursor = SliceCursor::new(encoded);
    if cursor.take(ENVELOPE_MAGIC.len())? != ENVELOPE_MAGIC {
        return Err(BarrierContractError::InvalidEnvelopeShape);
    }
    let version = cursor.take_u16()?;
    if version != SEALED_ENVELOPE_VERSION {
        return Err(BarrierContractError::UnsupportedEnvelopeVersion);
    }
    let key_epoch = KeyEpoch::new(cursor.take_u64()?)?;
    let nonce_len =
        usize::try_from(cursor.take_u32()?).map_err(|_| BarrierContractError::LengthOverflow)?;
    let ciphertext_len =
        usize::try_from(cursor.take_u64()?).map_err(|_| BarrierContractError::LengthOverflow)?;
    let tag_len =
        usize::try_from(cursor.take_u32()?).map_err(|_| BarrierContractError::LengthOverflow)?;
    if nonce_len == 0
        || ciphertext_len == 0
        || tag_len == 0
        || nonce_len > MAX_BARRIER_FIELD_BYTES
        || ciphertext_len > MAX_BARRIER_FIELD_BYTES
        || tag_len > MAX_BARRIER_FIELD_BYTES
    {
        return Err(BarrierContractError::InvalidEnvelopeShape);
    }
    let nonce = cursor.take(nonce_len)?.to_vec();
    let ciphertext = cursor.take(ciphertext_len)?.to_vec();
    let authentication_tag = cursor.take(tag_len)?.to_vec();
    if !cursor.is_finished() {
        return Err(BarrierContractError::TrailingEnvelopeBytes);
    }
    SealedEnvelope::new(version, key_epoch, nonce, ciphertext, authentication_tag)
}

#[derive(Debug)]
struct SliceCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SliceCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BarrierContractError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(BarrierContractError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BarrierContractError::TruncatedEnvelope)?;
        self.offset = end;
        Ok(value)
    }

    fn take_u16(&mut self) -> Result<u16, BarrierContractError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn take_u32(&mut self) -> Result<u32, BarrierContractError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn take_u64(&mut self) -> Result<u64, BarrierContractError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain() -> Result<StoreDomain, heptabao_storage_api::StorageContractError> {
        StoreDomain::new("heptabao/system".to_owned())
    }

    #[test]
    fn envelope_round_trips_strictly() {
        let envelope = SealedEnvelope::new(
            SEALED_ENVELOPE_VERSION,
            KeyEpoch::INITIAL,
            b"nonce".to_vec(),
            b"ciphertext".to_vec(),
            b"tag".to_vec(),
        );
        assert!(envelope.is_ok());
        if let Ok(envelope) = envelope {
            let encoded = envelope.encode();
            assert!(encoded.is_ok());
            if let Ok(encoded) = encoded {
                let decoded = SealedEnvelope::decode(encoded);
                assert!(decoded.is_ok());
                if let Ok(decoded) = decoded {
                    assert_eq!(decoded.version(), SEALED_ENVELOPE_VERSION);
                    assert_eq!(decoded.key_epoch(), KeyEpoch::INITIAL);
                    assert_eq!(decoded.nonce(), b"nonce");
                    assert_eq!(decoded.ciphertext(), b"ciphertext");
                    assert_eq!(decoded.authentication_tag(), b"tag");
                }
            }
        }
    }

    #[test]
    fn context_binds_domain_generation_epoch_purpose_and_caller_data() {
        let domain = domain();
        assert!(domain.is_ok());
        if let Ok(domain) = domain {
            let first = BarrierContext::new(
                domain.clone(),
                Generation::INITIAL,
                KeyEpoch::INITIAL,
                BarrierPurpose::AuthoritativeState,
                b"tenant-a".to_vec(),
            );
            let second = BarrierContext::new(
                domain,
                Generation::new(2).unwrap_or(Generation::INITIAL),
                KeyEpoch::INITIAL,
                BarrierPurpose::AuthoritativeState,
                b"tenant-a".to_vec(),
            );
            assert!(first.is_ok());
            assert!(second.is_ok());
            if let (Ok(first), Ok(second)) = (first, second) {
                assert_ne!(
                    first.canonical_associated_data(),
                    second.canonical_associated_data()
                );
            }
        }
    }

    #[test]
    fn truncated_and_trailing_envelopes_fail_closed() {
        let envelope = SealedEnvelope::new(
            SEALED_ENVELOPE_VERSION,
            KeyEpoch::INITIAL,
            vec![1],
            vec![2],
            vec![3],
        );
        assert!(envelope.is_ok());
        if let Ok(envelope) = envelope {
            let encoded = envelope.encode();
            assert!(encoded.is_ok());
            if let Ok(encoded) = encoded {
                let mut truncated = encoded.clone();
                let _ = truncated.pop();
                assert!(SealedEnvelope::decode(truncated).is_err());
                let mut trailing = encoded;
                trailing.push(0);
                assert_eq!(
                    SealedEnvelope::decode(trailing),
                    Err(BarrierContractError::TrailingEnvelopeBytes)
                );
            }
        }
    }

    #[test]
    fn secret_and_envelope_debug_output_is_redacted() {
        let secret = SecretState::new(b"plaintext-secret".to_vec());
        assert!(secret.is_ok());
        if let Ok(secret) = secret {
            assert!(!format!("{secret:?}").contains("plaintext-secret"));
        }
        let envelope = SealedEnvelope::new(
            SEALED_ENVELOPE_VERSION,
            KeyEpoch::INITIAL,
            b"private-nonce".to_vec(),
            b"private-ciphertext".to_vec(),
            b"private-tag".to_vec(),
        );
        assert!(envelope.is_ok());
        if let Ok(envelope) = envelope {
            let rendered = format!("{envelope:?}");
            assert!(!rendered.contains("private-nonce"));
            assert!(!rendered.contains("private-ciphertext"));
            assert!(!rendered.contains("private-tag"));
        }
    }
}
