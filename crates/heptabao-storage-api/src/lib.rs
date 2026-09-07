#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Provider-neutral contracts for one authoritative durable generation store.
//!
//! The crate defines lifecycle, generation, integrity and compare-and-swap
//! semantics. It contains no filesystem, database, cryptographic or consensus
//! implementation and grants no production authority.

use std::error::Error;
use std::fmt;

pub const MAX_OPAQUE_STATE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_STORE_DOMAIN_BYTES: usize = 128;
pub const MAX_INTEGRITY_ALGORITHM_ID_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StoreDomain(String);

impl StoreDomain {
    pub fn new(value: String) -> Result<Self, StorageContractError> {
        if value.is_empty()
            || value.len() > MAX_STORE_DOMAIN_BYTES
            || !value.is_ascii()
            || value.bytes().any(|byte| {
                byte.is_ascii_control()
                    || byte.is_ascii_whitespace()
                    || !matches!(
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
        {
            return Err(StorageContractError::InvalidStoreDomain);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IntegrityAlgorithmId(String);

impl IntegrityAlgorithmId {
    pub fn new(value: String) -> Result<Self, StorageContractError> {
        if value.is_empty()
            || value.len() > MAX_INTEGRITY_ALGORITHM_ID_BYTES
            || !value.is_ascii()
            || value.bytes().any(|byte| {
                byte.is_ascii_control()
                    || byte.is_ascii_whitespace()
                    || !matches!(
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
        {
            return Err(StorageContractError::InvalidIntegrityAlgorithmId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Generation(u64);

impl Generation {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: u64) -> Result<Self, StorageContractError> {
        if value == 0 {
            return Err(StorageContractError::ZeroGeneration);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn previous(self) -> Option<Self> {
        match self.0.checked_sub(1) {
            Some(0) | None => None,
            Some(value) => Some(Self(value)),
        }
    }

    pub const fn checked_next(self) -> Result<Self, StorageContractError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(StorageContractError::GenerationOverflow),
        }
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct StateDigest([u8; 32]);

impl StateDigest {
    pub fn new(value: [u8; 32]) -> Result<Self, StorageContractError> {
        if value == [0; 32] {
            return Err(StorageContractError::ZeroStateDigest);
        }
        Ok(Self(value))
    }

    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for StateDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StateDigest([BOUND])")
    }
}

#[derive(Eq, PartialEq)]
pub struct OpaqueState(Vec<u8>);

impl OpaqueState {
    pub fn new(mut value: Vec<u8>) -> Result<Self, StorageContractError> {
        if value.is_empty() || value.len() > MAX_OPAQUE_STATE_BYTES {
            value.fill(0);
            return Err(StorageContractError::InvalidOpaqueState);
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

impl fmt::Debug for OpaqueState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueState")
            .field("bytes", &self.0.len())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl Drop for OpaqueState {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreOpenMode {
    CreateNew,
    ReopenExisting,
    AdoptLegacy,
}

#[derive(Eq, PartialEq)]
pub struct GenerationSnapshot {
    pub generation: Generation,
    pub digest: StateDigest,
    pub state: OpaqueState,
}

impl fmt::Debug for GenerationSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationSnapshot")
            .field("generation", &self.generation)
            .field("digest", &self.digest)
            .field("state_bytes", &self.state.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    pub previous: Option<Generation>,
    pub committed: Generation,
    pub digest: StateDigest,
}

/// Exact provider metadata for classifying an interrupted commit.
///
/// Constructing this value is not proof that a matching ledger record was
/// persisted and does not authorize publication by itself. The journaled
/// composition derives recovery from authenticated `IntentCommitted` replay.
/// Provider recovery descriptor only; possession is not proof that a matching ledger record was persisted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitIntent {
    previous: Option<Generation>,
    committed: Generation,
    digest: StateDigest,
}

impl CommitIntent {
    pub fn new(
        previous: Option<Generation>,
        committed: Generation,
        digest: StateDigest,
    ) -> Result<Self, StorageContractError> {
        let expected = match previous {
            Some(value) => value.checked_next()?,
            None => Generation::INITIAL,
        };
        if committed != expected {
            return Err(StorageContractError::InvalidCommitIntent);
        }
        Ok(Self {
            previous,
            committed,
            digest,
        })
    }

    pub const fn previous(self) -> Option<Generation> {
        self.previous
    }

    pub const fn committed(self) -> Generation {
        self.committed
    }

    pub const fn digest(self) -> StateDigest {
        self.digest
    }

    pub const fn receipt(self) -> CommitReceipt {
        CommitReceipt {
            previous: self.previous,
            committed: self.committed,
            digest: self.digest,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitRecovery {
    Committed(CommitReceipt),
    NotCommitted,
    Conflict {
        actual: Option<(Generation, StateDigest)>,
    },
}

pub trait IntegrityProvider: fmt::Debug + Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn algorithm_id(&self) -> &IntegrityAlgorithmId;

    fn digest(
        &self,
        domain: &StoreDomain,
        generation: Generation,
        state: &[u8],
    ) -> Result<StateDigest, Self::Error>;
}

pub trait DurableGenerationStore: fmt::Debug + Send {
    type Error: Error + Send + Sync + 'static;

    fn domain(&self) -> &StoreDomain;
    fn open_mode(&self) -> StoreOpenMode;
    fn current_generation(&self) -> Option<Generation>;

    fn load_current(&self) -> Result<Option<GenerationSnapshot>, Self::Error>;

    /// Computes the exact generation and digest that a subsequent commit
    /// must publish, without mutating authoritative storage.
    fn prepare_commit(
        &self,
        expected_current: Option<Generation>,
        candidate: &OpaqueState,
    ) -> Result<CommitIntent, Self::Error>;

    /// Re-reads authoritative provider state and classifies an interrupted
    /// prepared commit. Implementations may complete publication only when
    /// the persisted candidate exactly matches the supplied intent.
    fn recover_commit(&mut self, intent: CommitIntent) -> Result<CommitRecovery, Self::Error>;

    fn commit(
        &mut self,
        expected_current: Option<Generation>,
        candidate: OpaqueState,
    ) -> Result<CommitReceipt, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageContractError {
    InvalidStoreDomain,
    InvalidIntegrityAlgorithmId,
    ZeroGeneration,
    GenerationOverflow,
    ZeroStateDigest,
    InvalidOpaqueState,
    InvalidCommitIntent,
}

impl fmt::Display for StorageContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidStoreDomain => "store domain is invalid",
            Self::InvalidIntegrityAlgorithmId => "integrity algorithm identity is invalid",
            Self::ZeroGeneration => "generation zero is invalid",
            Self::GenerationOverflow => "generation overflow",
            Self::ZeroStateDigest => "state digest must be non-zero",
            Self::InvalidOpaqueState => "opaque state is empty or exceeds the bounded size",
            Self::InvalidCommitIntent => {
                "commit intent generation is not the exact successor of its previous generation"
            }
        })
    }
}

impl Error for StorageContractError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_non_zero_and_checked() {
        assert_eq!(
            Generation::new(0),
            Err(StorageContractError::ZeroGeneration)
        );
        assert_eq!(Generation::INITIAL.get(), 1);
        assert_eq!(
            Generation::new(u64::MAX).and_then(Generation::checked_next),
            Err(StorageContractError::GenerationOverflow)
        );
    }

    #[test]
    fn domains_and_algorithm_ids_are_canonical_ascii() {
        assert!(StoreDomain::new("heptabao/system".to_owned()).is_ok());
        assert!(StoreDomain::new("bad domain".to_owned()).is_err());
        assert!(IntegrityAlgorithmId::new("sha256:v1".to_owned()).is_ok());
        assert!(IntegrityAlgorithmId::new("sha256\n".to_owned()).is_err());
    }

    #[test]
    fn opaque_state_redacts_and_can_be_consumed_without_clone() {
        let value = OpaqueState::new(b"secret-state".to_vec());
        assert!(value.is_ok());
        if let Ok(value) = value {
            let rendered = format!("{value:?}");
            assert!(!rendered.contains("secret-state"));
            assert_eq!(value.into_bytes(), b"secret-state");
        }
    }

    #[test]
    fn commit_intent_requires_exact_generation_successor() {
        let digest = StateDigest::new([7; 32]);
        assert!(digest.is_ok());
        if let Ok(digest) = digest {
            assert!(CommitIntent::new(None, Generation::INITIAL, digest).is_ok());
            assert_eq!(Generation::INITIAL.previous(), None);
            assert_eq!(
                CommitIntent::new(
                    None,
                    Generation::new(2).unwrap_or(Generation::INITIAL),
                    digest
                ),
                Err(StorageContractError::InvalidCommitIntent)
            );
            let second = Generation::INITIAL.checked_next();
            assert!(second.is_ok());
            if let Ok(second) = second {
                assert_eq!(second.previous(), Some(Generation::INITIAL));
                assert!(CommitIntent::new(Some(Generation::INITIAL), second, digest).is_ok());
            }
        }
    }

    #[test]
    fn zero_digest_is_rejected() {
        assert_eq!(
            StateDigest::new([0; 32]),
            Err(StorageContractError::ZeroStateDigest)
        );
    }
}
