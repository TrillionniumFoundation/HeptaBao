#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Provider-neutral durable journal contracts for HeptaBao.
//!
//! The journal is an ordered, append-only evidence boundary. Implementations
//! must authenticate every record against its domain, sequence, previous tag
//! and payload before publishing a new tail. This crate contains no filesystem,
//! database, cryptographic implementation, key or operational authority.

use std::error::Error;
use std::fmt;

pub const MAX_JOURNAL_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_JOURNAL_DOMAIN_BYTES: usize = 128;
pub const MAX_AUTHENTICATOR_ID_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JournalDomain(String);

impl JournalDomain {
    pub fn new(value: String) -> Result<Self, JournalContractError> {
        if !valid_identity(&value, MAX_JOURNAL_DOMAIN_BYTES) {
            return Err(JournalContractError::InvalidJournalDomain);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthenticatorId(String);

impl AuthenticatorId {
    pub fn new(value: String) -> Result<Self, JournalContractError> {
        if !valid_identity(&value, MAX_AUTHENTICATOR_ID_BYTES) {
            return Err(JournalContractError::InvalidAuthenticatorId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_identity(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.is_ascii()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'a'..=b'z'
                    | b'A'..=b'Z'
                    | b'0'..=b'9'
                    | b'-'
                    | b'_'
                    | b'.'
                    | b':'
                    | b'/'
            )
        })
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JournalSequence(u64);

impl JournalSequence {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: u64) -> Result<Self, JournalContractError> {
        if value == 0 {
            return Err(JournalContractError::ZeroJournalSequence);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, JournalContractError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(JournalContractError::JournalSequenceOverflow),
        }
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct JournalTag([u8; 32]);

impl JournalTag {
    pub fn new(value: [u8; 32]) -> Result<Self, JournalContractError> {
        if value == [0; 32] {
            return Err(JournalContractError::ZeroJournalTag);
        }
        Ok(Self(value))
    }

    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for JournalTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JournalTag([BOUND])")
    }
}

#[derive(Eq, PartialEq)]
pub struct JournalPayload(Vec<u8>);

impl JournalPayload {
    pub fn new(mut value: Vec<u8>) -> Result<Self, JournalContractError> {
        if value.is_empty() || value.len() > MAX_JOURNAL_PAYLOAD_BYTES {
            value.fill(0);
            return Err(JournalContractError::InvalidJournalPayload);
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

impl fmt::Debug for JournalPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JournalPayload")
            .field("bytes", &self.0.len())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl Drop for JournalPayload {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Eq, PartialEq)]
pub struct JournalRecord {
    pub sequence: JournalSequence,
    pub previous_tag: Option<JournalTag>,
    pub tag: JournalTag,
    pub payload: JournalPayload,
}

impl fmt::Debug for JournalRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JournalRecord")
            .field("sequence", &self.sequence)
            .field("previous_tag", &self.previous_tag)
            .field("tag", &self.tag)
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalTail {
    pub sequence: JournalSequence,
    pub tag: JournalTag,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppendReceipt {
    pub previous_tail: Option<JournalTail>,
    pub appended: JournalTail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalOpenMode {
    CreateNew,
    ReopenExisting,
}

/// Provider classification for a failed append call.
///
/// Implementations must return [`AppendFailureDisposition::OutcomeUnknown`] unless
/// they can prove that no durable record or tail publication occurred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendFailureDisposition {
    DefinitelyNotAppended,
    OutcomeUnknown,
}

pub trait JournalAuthenticator: fmt::Debug + Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn authenticator_id(&self) -> &AuthenticatorId;

    fn authenticate(
        &self,
        domain: &JournalDomain,
        sequence: JournalSequence,
        previous_tag: Option<JournalTag>,
        payload: &[u8],
    ) -> Result<JournalTag, Self::Error>;
}

pub trait DurableJournal: fmt::Debug + Send {
    type Error: Error + Send + Sync + 'static;

    fn domain(&self) -> &JournalDomain;
    fn open_mode(&self) -> JournalOpenMode;
    fn tail(&self) -> Option<JournalTail>;

    fn replay(&self) -> Result<Vec<JournalRecord>, Self::Error>;

    /// Re-establishes the provider's authoritative in-memory view after an
    /// append whose outcome was unknown, then returns the fully authenticated
    /// committed prefix. Providers with cached tails or exact-next orphan
    /// records must override this method and reconcile them fail-closed.
    fn recover_authoritative(&mut self) -> Result<Vec<JournalRecord>, Self::Error> {
        self.replay()
    }

    fn append(
        &mut self,
        expected_tail: Option<JournalSequence>,
        payload: JournalPayload,
    ) -> Result<AppendReceipt, Self::Error>;

    /// Classifies a failed append. The conservative default permanently fences
    /// the caller until the journal is reopened and authenticated replay
    /// reconstructs the authoritative tail.
    fn classify_append_failure(&self, _error: &Self::Error) -> AppendFailureDisposition {
        AppendFailureDisposition::OutcomeUnknown
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalContractError {
    InvalidJournalDomain,
    InvalidAuthenticatorId,
    ZeroJournalSequence,
    JournalSequenceOverflow,
    ZeroJournalTag,
    InvalidJournalPayload,
}

impl fmt::Display for JournalContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidJournalDomain => "journal domain is invalid",
            Self::InvalidAuthenticatorId => "journal authenticator identity is invalid",
            Self::ZeroJournalSequence => "journal sequence zero is invalid",
            Self::JournalSequenceOverflow => "journal sequence overflow",
            Self::ZeroJournalTag => "journal authentication tag must be non-zero",
            Self::InvalidJournalPayload => "journal payload is empty or exceeds the bound",
        })
    }
}

impl Error for JournalContractError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_is_checked_and_non_zero() {
        assert_eq!(
            JournalSequence::new(0),
            Err(JournalContractError::ZeroJournalSequence)
        );
        assert_eq!(JournalSequence::INITIAL.get(), 1);
        assert_eq!(
            JournalSequence::new(u64::MAX).and_then(JournalSequence::checked_next),
            Err(JournalContractError::JournalSequenceOverflow)
        );
    }

    #[test]
    fn domain_and_authenticator_identity_are_canonical() {
        assert!(JournalDomain::new("heptabao/audit".to_owned()).is_ok());
        assert!(JournalDomain::new("bad domain".to_owned()).is_err());
        assert!(AuthenticatorId::new("hmac-sha256:v1".to_owned()).is_ok());
        assert!(AuthenticatorId::new("bad\nalgorithm".to_owned()).is_err());
    }

    #[test]
    fn payload_debug_is_redacted_and_consumable_without_clone() {
        let payload = JournalPayload::new(b"sensitive-ledger-payload".to_vec());
        assert!(payload.is_ok());
        if let Ok(payload) = payload {
            assert!(!format!("{payload:?}").contains("sensitive-ledger-payload"));
            assert_eq!(payload.into_bytes(), b"sensitive-ledger-payload");
        }
    }

    #[test]
    fn zero_tag_is_rejected() {
        assert_eq!(
            JournalTag::new([0; 32]),
            Err(JournalContractError::ZeroJournalTag)
        );
    }
}
