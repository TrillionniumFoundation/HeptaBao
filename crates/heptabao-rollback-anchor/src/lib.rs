#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Provider-neutral external rollback-anchor contracts for HeptaBao.
//!
//! A checkpoint binds the authoritative state generation and digest, durable
//! journal tail, active key epoch and the previous checkpoint digest. The
//! repository does not provide a production remote anchor or claim that local
//! memory is rollback resistant.

use std::error::Error;
use std::fmt;

use heptabao_barrier_api::KeyEpoch;
use heptabao_journal_api::{JournalDomain, JournalTail};
use heptabao_storage_api::{Generation, StateDigest, StoreDomain};

pub const MAX_ANCHOR_AUTHENTICATOR_ID_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AnchorAuthenticatorId(String);

impl AnchorAuthenticatorId {
    pub fn new(value: String) -> Result<Self, AnchorContractError> {
        if !valid_identity(&value, MAX_ANCHOR_AUTHENTICATOR_ID_BYTES) {
            return Err(AnchorContractError::InvalidAuthenticatorId);
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
pub struct AnchorRevision(u64);

impl AnchorRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: u64) -> Result<Self, AnchorContractError> {
        if value == 0 {
            return Err(AnchorContractError::ZeroRevision);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, AnchorContractError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(AnchorContractError::RevisionOverflow),
        }
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CheckpointDigest([u8; 32]);

impl CheckpointDigest {
    pub fn new(value: [u8; 32]) -> Result<Self, AnchorContractError> {
        if value == [0; 32] {
            return Err(AnchorContractError::ZeroCheckpointDigest);
        }
        Ok(Self(value))
    }

    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for CheckpointDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CheckpointDigest([BOUND])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointObservation {
    store_domain: StoreDomain,
    generation: Generation,
    state_digest: StateDigest,
    journal_domain: JournalDomain,
    journal_tail: Option<JournalTail>,
    key_epoch: KeyEpoch,
}

impl CheckpointObservation {
    pub fn new(
        store_domain: StoreDomain,
        generation: Generation,
        state_digest: StateDigest,
        journal_domain: JournalDomain,
        journal_tail: Option<JournalTail>,
        key_epoch: KeyEpoch,
    ) -> Self {
        Self {
            store_domain,
            generation,
            state_digest,
            journal_domain,
            journal_tail,
            key_epoch,
        }
    }

    pub const fn store_domain(&self) -> &StoreDomain {
        &self.store_domain
    }

    pub const fn generation(&self) -> Generation {
        self.generation
    }

    pub const fn state_digest(&self) -> StateDigest {
        self.state_digest
    }

    pub const fn journal_domain(&self) -> &JournalDomain {
        &self.journal_domain
    }

    pub const fn journal_tail(&self) -> Option<JournalTail> {
        self.journal_tail
    }

    pub const fn key_epoch(&self) -> KeyEpoch {
        self.key_epoch
    }

    fn journal_position(&self) -> u64 {
        self.journal_tail.map_or(0, |tail| tail.sequence.get())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCheckpoint {
    revision: AnchorRevision,
    previous_digest: Option<CheckpointDigest>,
    authenticator_id: AnchorAuthenticatorId,
    observation: CheckpointObservation,
    digest: CheckpointDigest,
}

impl RecoveryCheckpoint {
    pub fn from_parts(
        revision: AnchorRevision,
        previous_digest: Option<CheckpointDigest>,
        authenticator_id: AnchorAuthenticatorId,
        observation: CheckpointObservation,
        digest: CheckpointDigest,
    ) -> Result<Self, AnchorContractError> {
        if revision == AnchorRevision::INITIAL && previous_digest.is_some() {
            return Err(AnchorContractError::InvalidCheckpointShape);
        }
        if revision != AnchorRevision::INITIAL && previous_digest.is_none() {
            return Err(AnchorContractError::InvalidCheckpointShape);
        }
        Ok(Self {
            revision,
            previous_digest,
            authenticator_id,
            observation,
            digest,
        })
    }

    pub const fn revision(&self) -> AnchorRevision {
        self.revision
    }

    pub const fn previous_digest(&self) -> Option<CheckpointDigest> {
        self.previous_digest
    }

    pub const fn authenticator_id(&self) -> &AnchorAuthenticatorId {
        &self.authenticator_id
    }

    pub const fn observation(&self) -> &CheckpointObservation {
        &self.observation
    }

    pub const fn digest(&self) -> CheckpointDigest {
        self.digest
    }

    pub fn canonical_preimage(
        revision: AnchorRevision,
        previous_digest: Option<CheckpointDigest>,
        authenticator_id: &AnchorAuthenticatorId,
        observation: &CheckpointObservation,
    ) -> Result<Vec<u8>, AnchorContractError> {
        let mut output = Vec::new();
        append_field(&mut output, b"heptabao-rollback-checkpoint-v1")?;
        append_field(&mut output, &revision.get().to_be_bytes())?;
        match previous_digest {
            Some(digest) => {
                append_field(&mut output, &[1])?;
                append_field(&mut output, &digest.bytes())?;
            }
            None => append_field(&mut output, &[0])?,
        }
        append_field(&mut output, authenticator_id.as_str().as_bytes())?;
        append_field(&mut output, observation.store_domain.as_str().as_bytes())?;
        append_field(&mut output, &observation.generation.get().to_be_bytes())?;
        append_field(&mut output, &observation.state_digest.bytes())?;
        append_field(&mut output, observation.journal_domain.as_str().as_bytes())?;
        match observation.journal_tail {
            Some(tail) => {
                append_field(&mut output, &[1])?;
                append_field(&mut output, &tail.sequence.get().to_be_bytes())?;
                append_field(&mut output, &tail.tag.bytes())?;
            }
            None => append_field(&mut output, &[0])?,
        }
        append_field(&mut output, &observation.key_epoch.get().to_be_bytes())?;
        Ok(output)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedRecoveryCheckpoint {
    checkpoint: RecoveryCheckpoint,
}

impl VerifiedRecoveryCheckpoint {
    pub const fn revision(&self) -> AnchorRevision {
        self.checkpoint.revision()
    }

    pub const fn digest(&self) -> CheckpointDigest {
        self.checkpoint.digest()
    }

    pub const fn observation(&self) -> &CheckpointObservation {
        self.checkpoint.observation()
    }
}

pub trait CheckpointAuthenticator: fmt::Debug + Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn authenticator_id(&self) -> &AnchorAuthenticatorId;

    fn authenticate(&self, preimage: &[u8]) -> Result<CheckpointDigest, Self::Error>;
}

#[derive(Debug)]
pub enum AnchorFenceError<E>
where
    E: Error + Send + Sync + 'static,
{
    /// The exact checkpoint comparison failed before `operation` was invoked.
    CheckpointNotCurrent,
    /// The provider failed before `operation` was invoked.
    ProviderBeforeEntry(E),
    /// `operation` was invoked, but the provider cannot prove that the fence
    /// remained valid and completed cleanly after entry. The operation result
    /// is deliberately discarded and callers must reconcile before retry.
    OutcomeUnknownAfterEntry(E),
}

impl<E> fmt::Display for AnchorFenceError<E>
where
    E: Error + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CheckpointNotCurrent => {
                formatter.write_str("rollback checkpoint is no longer current")
            }
            Self::ProviderBeforeEntry(error) => {
                write!(
                    formatter,
                    "rollback anchor fence failed before operation entry: {error}"
                )
            }
            Self::OutcomeUnknownAfterEntry(error) => write!(
                formatter,
                "rollback anchor fence outcome is unknown after operation entry: {error}"
            ),
        }
    }
}

impl<E> Error for AnchorFenceError<E>
where
    E: Error + Send + Sync + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CheckpointNotCurrent => None,
            Self::ProviderBeforeEntry(error) | Self::OutcomeUnknownAfterEntry(error) => Some(error),
        }
    }
}

pub trait RollbackAnchor: fmt::Debug + Send {
    type Error: Error + Send + Sync + 'static;

    fn current(&self) -> Result<Option<RecoveryCheckpoint>, Self::Error>;

    /// Executes `operation` only while `expected` is the exact current
    /// checkpoint and while the provider's anchor-advance serialization
    /// primitive remains held. `compare_and_swap` must use the same primitive.
    ///
    /// `CheckpointNotCurrent` and `ProviderBeforeEntry` guarantee that
    /// `operation` was not invoked. Once `operation` has been invoked, any
    /// provider inability to prove fence validity or clean completion must be
    /// returned as `OutcomeUnknownAfterEntry`; it must never be relabelled as a
    /// safe pre-entry failure.
    fn with_current_fence<T, F>(
        &mut self,
        expected: &RecoveryCheckpoint,
        operation: F,
    ) -> Result<T, AnchorFenceError<Self::Error>>
    where
        F: FnOnce() -> T;

    fn compare_and_swap(
        &mut self,
        expected_revision: Option<AnchorRevision>,
        next: RecoveryCheckpoint,
    ) -> Result<AnchorAdvanceReceipt, Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorAdvanceReceipt {
    pub previous: Option<RecoveryCheckpoint>,
    pub current: RecoveryCheckpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationDisposition {
    Unanchored,
    Exact,
    AdvanceRequired,
}

pub struct AnchorCoordinator<A, P> {
    anchor: A,
    authenticator: P,
}

impl<A, P> AnchorCoordinator<A, P> {
    pub const fn new(anchor: A, authenticator: P) -> Self {
        Self {
            anchor,
            authenticator,
        }
    }
}

impl<A, P> fmt::Debug for AnchorCoordinator<A, P>
where
    A: fmt::Debug,
    P: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnchorCoordinator")
            .field("anchor", &self.anchor)
            .field("authenticator", &self.authenticator)
            .finish()
    }
}

pub type AnchorResult<T, A, P> = Result<T, AnchorCoordinatorError<A, P>>;

impl<A, P> AnchorCoordinator<A, P>
where
    A: RollbackAnchor,
    P: CheckpointAuthenticator,
{
    pub fn classify(
        &self,
        observation: &CheckpointObservation,
    ) -> AnchorResult<ObservationDisposition, A::Error, P::Error> {
        let current = self
            .anchor
            .current()
            .map_err(AnchorCoordinatorError::Anchor)?;
        let Some(current) = current else {
            return Ok(ObservationDisposition::Unanchored);
        };
        self.verify_checkpoint(&current)?;
        compare_observation(current.observation(), observation)
            .map_err(AnchorCoordinatorError::Contract)
    }

    pub fn advance(
        &mut self,
        observation: CheckpointObservation,
    ) -> AnchorResult<AnchorAdvanceReceipt, A::Error, P::Error> {
        let previous = self
            .anchor
            .current()
            .map_err(AnchorCoordinatorError::Anchor)?;
        if let Some(current) = &previous {
            self.verify_checkpoint(current)?;
            match compare_observation(current.observation(), &observation)
                .map_err(AnchorCoordinatorError::Contract)?
            {
                ObservationDisposition::Exact => {
                    return Err(AnchorCoordinatorError::Contract(
                        AnchorContractError::CheckpointAlreadyCurrent,
                    ));
                }
                ObservationDisposition::AdvanceRequired => {}
                ObservationDisposition::Unanchored => {
                    return Err(AnchorCoordinatorError::Contract(
                        AnchorContractError::InvariantViolation,
                    ));
                }
            }
        }
        let revision = match &previous {
            Some(current) => current
                .revision
                .checked_next()
                .map_err(AnchorCoordinatorError::Contract)?,
            None => AnchorRevision::INITIAL,
        };
        let previous_digest = previous.as_ref().map(RecoveryCheckpoint::digest);
        let authenticator_id = self.authenticator.authenticator_id().clone();
        let preimage = RecoveryCheckpoint::canonical_preimage(
            revision,
            previous_digest,
            &authenticator_id,
            &observation,
        )
        .map_err(AnchorCoordinatorError::Contract)?;
        let digest = self
            .authenticator
            .authenticate(&preimage)
            .map_err(AnchorCoordinatorError::Authenticator)?;
        let next = RecoveryCheckpoint {
            revision,
            previous_digest,
            authenticator_id,
            observation,
            digest,
        };
        let receipt = self
            .anchor
            .compare_and_swap(
                previous.as_ref().map(RecoveryCheckpoint::revision),
                next.clone(),
            )
            .map_err(AnchorCoordinatorError::Anchor)?;
        if receipt.previous != previous || receipt.current != next {
            return Err(AnchorCoordinatorError::Contract(
                AnchorContractError::ReceiptMismatch,
            ));
        }
        self.verify_checkpoint(&receipt.current)?;
        let reread = self
            .anchor
            .current()
            .map_err(AnchorCoordinatorError::Anchor)?;
        if reread.as_ref() != Some(&receipt.current) {
            return Err(AnchorCoordinatorError::Contract(
                AnchorContractError::ReceiptMismatch,
            ));
        }
        Ok(receipt)
    }

    pub fn with_current_fence<T, F>(
        &mut self,
        checkpoint: &RecoveryCheckpoint,
        operation: F,
    ) -> AnchorResult<T, A::Error, P::Error>
    where
        F: FnOnce() -> T,
    {
        self.verify_checkpoint(checkpoint)?;
        self.anchor
            .with_current_fence(checkpoint, operation)
            .map_err(|error| match error {
                AnchorFenceError::CheckpointNotCurrent => {
                    AnchorCoordinatorError::Contract(AnchorContractError::CheckpointNotCurrent)
                }
                AnchorFenceError::ProviderBeforeEntry(error) => {
                    AnchorCoordinatorError::Anchor(error)
                }
                AnchorFenceError::OutcomeUnknownAfterEntry(error) => {
                    AnchorCoordinatorError::FenceOutcomeUnknown(error)
                }
            })
    }

    pub fn verify_owned(
        &self,
        checkpoint: RecoveryCheckpoint,
    ) -> AnchorResult<VerifiedRecoveryCheckpoint, A::Error, P::Error> {
        self.verify_current(&checkpoint)
    }

    pub fn verify_current(
        &self,
        checkpoint: &RecoveryCheckpoint,
    ) -> AnchorResult<VerifiedRecoveryCheckpoint, A::Error, P::Error> {
        let current = self
            .anchor
            .current()
            .map_err(AnchorCoordinatorError::Anchor)?
            .ok_or(AnchorCoordinatorError::Contract(
                AnchorContractError::CheckpointNotCurrent,
            ))?;
        if &current != checkpoint {
            return Err(AnchorCoordinatorError::Contract(
                AnchorContractError::CheckpointNotCurrent,
            ));
        }
        self.verify_checkpoint(&current)?;
        Ok(VerifiedRecoveryCheckpoint {
            checkpoint: current,
        })
    }

    pub fn verify_checkpoint(
        &self,
        checkpoint: &RecoveryCheckpoint,
    ) -> AnchorResult<(), A::Error, P::Error> {
        if checkpoint.authenticator_id != *self.authenticator.authenticator_id() {
            return Err(AnchorCoordinatorError::Contract(
                AnchorContractError::AuthenticatorMismatch,
            ));
        }
        if checkpoint.revision == AnchorRevision::INITIAL && checkpoint.previous_digest.is_some() {
            return Err(AnchorCoordinatorError::Contract(
                AnchorContractError::InvalidCheckpointShape,
            ));
        }
        if checkpoint.revision != AnchorRevision::INITIAL && checkpoint.previous_digest.is_none() {
            return Err(AnchorCoordinatorError::Contract(
                AnchorContractError::InvalidCheckpointShape,
            ));
        }
        let preimage = RecoveryCheckpoint::canonical_preimage(
            checkpoint.revision,
            checkpoint.previous_digest,
            &checkpoint.authenticator_id,
            &checkpoint.observation,
        )
        .map_err(AnchorCoordinatorError::Contract)?;
        let expected = self
            .authenticator
            .authenticate(&preimage)
            .map_err(AnchorCoordinatorError::Authenticator)?;
        if expected != checkpoint.digest {
            return Err(AnchorCoordinatorError::Contract(
                AnchorContractError::CheckpointAuthenticationFailed,
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum AnchorCoordinatorError<A, P>
where
    A: Error + Send + Sync + 'static,
    P: Error + Send + Sync + 'static,
{
    Contract(AnchorContractError),
    Anchor(A),
    FenceOutcomeUnknown(A),
    Authenticator(P),
}

impl<A, P> fmt::Display for AnchorCoordinatorError<A, P>
where
    A: Error + Send + Sync + 'static,
    P: Error + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "rollback anchor contract failure: {error}"),
            Self::Anchor(error) => write!(formatter, "rollback anchor provider failure: {error}"),
            Self::FenceOutcomeUnknown(error) => write!(
                formatter,
                "rollback anchor fence may have failed after operation entry; reconcile before retry: {error}"
            ),
            Self::Authenticator(error) => {
                write!(formatter, "checkpoint authenticator failure: {error}")
            }
        }
    }
}

impl<A, P> Error for AnchorCoordinatorError<A, P>
where
    A: Error + Send + Sync + 'static,
    P: Error + Send + Sync + 'static,
{
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorContractError {
    InvalidAuthenticatorId,
    ZeroRevision,
    RevisionOverflow,
    ZeroCheckpointDigest,
    LengthOverflow,
    DomainMismatch,
    RollbackDetected,
    DivergentObservation,
    KeyEpochRegression,
    CheckpointAlreadyCurrent,
    CheckpointNotCurrent,
    InvalidCheckpointShape,
    AuthenticatorMismatch,
    CheckpointAuthenticationFailed,
    ReceiptMismatch,
    InvariantViolation,
}

impl fmt::Display for AnchorContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAuthenticatorId => "anchor authenticator identity is invalid",
            Self::ZeroRevision => "anchor revision zero is invalid",
            Self::RevisionOverflow => "anchor revision overflow",
            Self::ZeroCheckpointDigest => "checkpoint digest must be non-zero",
            Self::LengthOverflow => "checkpoint canonical preimage length overflow",
            Self::DomainMismatch => "checkpoint observation domain mismatch",
            Self::RollbackDetected => "observed durable state is behind the external anchor",
            Self::DivergentObservation => "observed durable state diverges from the anchor",
            Self::KeyEpochRegression => "observed active key epoch regressed",
            Self::CheckpointAlreadyCurrent => "checkpoint observation is already current",
            Self::CheckpointNotCurrent => {
                "checkpoint does not equal the current externally stored anchor"
            }
            Self::InvalidCheckpointShape => "checkpoint revision chain shape is invalid",
            Self::AuthenticatorMismatch => "checkpoint authenticator identity mismatch",
            Self::CheckpointAuthenticationFailed => "checkpoint authentication failed",
            Self::ReceiptMismatch => "anchor provider receipt does not match the requested update",
            Self::InvariantViolation => "rollback-anchor invariant was violated",
        })
    }
}

impl Error for AnchorContractError {}

fn compare_observation(
    anchored: &CheckpointObservation,
    observed: &CheckpointObservation,
) -> Result<ObservationDisposition, AnchorContractError> {
    if anchored.store_domain != observed.store_domain
        || anchored.journal_domain != observed.journal_domain
    {
        return Err(AnchorContractError::DomainMismatch);
    }
    let anchored_generation = anchored.generation.get();
    let observed_generation = observed.generation.get();
    let anchored_journal = anchored.journal_position();
    let observed_journal = observed.journal_position();
    if observed_generation < anchored_generation || observed_journal < anchored_journal {
        return Err(AnchorContractError::RollbackDetected);
    }
    if observed.key_epoch.get() < anchored.key_epoch.get() {
        return Err(AnchorContractError::KeyEpochRegression);
    }
    if observed_generation == anchored_generation && observed_journal == anchored_journal {
        if observed.state_digest != anchored.state_digest
            || observed.journal_tail != anchored.journal_tail
            || observed.key_epoch != anchored.key_epoch
        {
            return Err(AnchorContractError::DivergentObservation);
        }
        return Ok(ObservationDisposition::Exact);
    }
    Ok(ObservationDisposition::AdvanceRequired)
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), AnchorContractError> {
    let length = u32::try_from(value.len()).map_err(|_| AnchorContractError::LengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use heptabao_journal_api::{JournalSequence, JournalTag};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestError {
        StaleRevision,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("test rollback anchor failure")
        }
    }

    impl Error for TestError {}

    #[derive(Debug, Default)]
    struct MemoryAnchor {
        current: Option<RecoveryCheckpoint>,
    }

    impl RollbackAnchor for MemoryAnchor {
        type Error = TestError;

        fn current(&self) -> Result<Option<RecoveryCheckpoint>, Self::Error> {
            Ok(self.current.clone())
        }

        fn with_current_fence<T, F>(
            &mut self,
            expected: &RecoveryCheckpoint,
            operation: F,
        ) -> Result<T, AnchorFenceError<Self::Error>>
        where
            F: FnOnce() -> T,
        {
            if self.current.as_ref() != Some(expected) {
                return Err(AnchorFenceError::CheckpointNotCurrent);
            }
            Ok(operation())
        }

        fn compare_and_swap(
            &mut self,
            expected_revision: Option<AnchorRevision>,
            next: RecoveryCheckpoint,
        ) -> Result<AnchorAdvanceReceipt, Self::Error> {
            if self.current.as_ref().map(RecoveryCheckpoint::revision) != expected_revision {
                return Err(TestError::StaleRevision);
            }
            let previous = self.current.replace(next.clone());
            Ok(AnchorAdvanceReceipt {
                previous,
                current: next,
            })
        }
    }

    #[derive(Debug)]
    struct TestAuthenticator {
        id: AnchorAuthenticatorId,
    }

    impl TestAuthenticator {
        fn new() -> Result<Self, AnchorContractError> {
            Ok(Self {
                id: AnchorAuthenticatorId::new("heptabao/test-anchor".to_owned())?,
            })
        }
    }

    impl CheckpointAuthenticator for TestAuthenticator {
        type Error = TestError;

        fn authenticator_id(&self) -> &AnchorAuthenticatorId {
            &self.id
        }

        fn authenticate(&self, preimage: &[u8]) -> Result<CheckpointDigest, Self::Error> {
            let mut output = [0_u8; 32];
            for (index, byte) in preimage.iter().copied().enumerate() {
                let slot = index % output.len();
                output[slot] = output[slot]
                    .wrapping_add(byte)
                    .rotate_left((slot % 7) as u32);
            }
            if output == [0; 32] {
                output[0] = 1;
            }
            CheckpointDigest::new(output).map_err(|_| TestError::StaleRevision)
        }
    }

    fn observation(
        generation_value: u64,
        journal_value: u64,
        key_value: u64,
        state_byte: u8,
    ) -> Result<CheckpointObservation, Box<dyn Error>> {
        let generation = Generation::new(generation_value)?;
        let state_digest = StateDigest::new([state_byte; 32])?;
        let journal_domain = JournalDomain::new("heptabao/anchor-test".to_owned())?;
        let store_domain = StoreDomain::new("heptabao/state-test".to_owned())?;
        let sequence = JournalSequence::new(journal_value)?;
        let tag = JournalTag::new([journal_value as u8; 32])?;
        let key_epoch = KeyEpoch::new(key_value)?;
        Ok(CheckpointObservation::new(
            store_domain,
            generation,
            state_digest,
            journal_domain,
            Some(JournalTail { sequence, tag }),
            key_epoch,
        ))
    }

    #[test]
    fn checkpoint_advances_and_exact_observation_is_detected() -> Result<(), Box<dyn Error>> {
        let anchor = MemoryAnchor::default();
        let authenticator = TestAuthenticator::new()?;
        let mut coordinator = AnchorCoordinator::new(anchor, authenticator);
        let first = observation(1, 3, 1, 1)?;
        let receipt = coordinator.advance(first.clone())?;
        assert_eq!(receipt.current.revision(), AnchorRevision::INITIAL);
        assert_eq!(coordinator.classify(&first)?, ObservationDisposition::Exact);
        let second = observation(2, 6, 2, 2)?;
        let receipt = coordinator.advance(second.clone())?;
        assert_eq!(receipt.current.revision().get(), 2);
        assert_eq!(
            coordinator.classify(&second)?,
            ObservationDisposition::Exact
        );
        Ok(())
    }

    #[test]
    fn current_checkpoint_fence_rejects_stale_checkpoint() -> Result<(), Box<dyn Error>> {
        let anchor = MemoryAnchor::default();
        let authenticator = TestAuthenticator::new()?;
        let mut coordinator = AnchorCoordinator::new(anchor, authenticator);
        let current = coordinator.advance(observation(1, 3, 1, 1)?)?.current;
        let observed = coordinator.with_current_fence(&current, || 7_u8)?;
        assert_eq!(observed, 7);
        let stale = current;
        let _ = coordinator.advance(observation(2, 4, 2, 2)?)?;
        assert!(matches!(
            coordinator.with_current_fence(&stale, || 9_u8),
            Err(AnchorCoordinatorError::Contract(
                AnchorContractError::CheckpointNotCurrent
            ))
        ));
        Ok(())
    }

    #[test]
    fn rollback_divergence_and_epoch_regression_fail_closed() -> Result<(), Box<dyn Error>> {
        let anchor = MemoryAnchor::default();
        let authenticator = TestAuthenticator::new()?;
        let mut coordinator = AnchorCoordinator::new(anchor, authenticator);
        let current = observation(2, 6, 2, 2)?;
        coordinator.advance(current)?;
        let rollback = observation(1, 3, 1, 1)?;
        assert!(matches!(
            coordinator.classify(&rollback),
            Err(AnchorCoordinatorError::Contract(
                AnchorContractError::RollbackDetected
            ))
        ));
        let divergent = observation(2, 6, 2, 9)?;
        assert!(matches!(
            coordinator.classify(&divergent),
            Err(AnchorCoordinatorError::Contract(
                AnchorContractError::DivergentObservation
            ))
        ));
        let epoch_regression = observation(3, 7, 1, 3)?;
        assert!(matches!(
            coordinator.classify(&epoch_regression),
            Err(AnchorCoordinatorError::Contract(
                AnchorContractError::KeyEpochRegression
            ))
        ));
        Ok(())
    }

    #[test]
    fn historical_but_authentic_checkpoint_cannot_authorize_restore() -> Result<(), Box<dyn Error>>
    {
        let anchor = MemoryAnchor::default();
        let authenticator = TestAuthenticator::new()?;
        let mut coordinator = AnchorCoordinator::new(anchor, authenticator);
        let first_receipt = coordinator.advance(observation(1, 3, 1, 1)?)?;
        let historical = first_receipt.current;
        coordinator.advance(observation(2, 6, 2, 2)?)?;
        assert!(matches!(
            coordinator.verify_owned(historical),
            Err(AnchorCoordinatorError::Contract(
                AnchorContractError::CheckpointNotCurrent
            ))
        ));
        Ok(())
    }

    #[test]
    fn checkpoint_preimage_binds_every_observation_field() -> Result<(), Box<dyn Error>> {
        let first = observation(1, 3, 1, 1)?;
        let second = observation(1, 3, 1, 2)?;
        let authenticator_id = AnchorAuthenticatorId::new("heptabao/test-anchor".to_owned())?;
        let first_bytes = RecoveryCheckpoint::canonical_preimage(
            AnchorRevision::INITIAL,
            None,
            &authenticator_id,
            &first,
        )?;
        let second_bytes = RecoveryCheckpoint::canonical_preimage(
            AnchorRevision::INITIAL,
            None,
            &authenticator_id,
            &second,
        )?;
        assert_ne!(first_bytes, second_bytes);
        Ok(())
    }

    #[derive(Debug)]
    struct AlternateReceiptAnchor {
        alternate: RecoveryCheckpoint,
    }

    impl RollbackAnchor for AlternateReceiptAnchor {
        type Error = TestError;

        fn current(&self) -> Result<Option<RecoveryCheckpoint>, Self::Error> {
            Ok(None)
        }

        fn with_current_fence<T, F>(
            &mut self,
            _expected: &RecoveryCheckpoint,
            _operation: F,
        ) -> Result<T, AnchorFenceError<Self::Error>>
        where
            F: FnOnce() -> T,
        {
            Err(AnchorFenceError::CheckpointNotCurrent)
        }

        fn compare_and_swap(
            &mut self,
            expected_revision: Option<AnchorRevision>,
            _next: RecoveryCheckpoint,
        ) -> Result<AnchorAdvanceReceipt, Self::Error> {
            if expected_revision.is_some() {
                return Err(TestError::StaleRevision);
            }
            Ok(AnchorAdvanceReceipt {
                previous: None,
                current: self.alternate.clone(),
            })
        }
    }

    #[test]
    fn alternate_authenticated_cas_receipt_is_rejected() -> Result<(), Box<dyn Error>> {
        let authenticator = TestAuthenticator::new()?;
        let alternate_observation = observation(1, 1, 1, 9)?;
        let preimage = RecoveryCheckpoint::canonical_preimage(
            AnchorRevision::INITIAL,
            None,
            authenticator.authenticator_id(),
            &alternate_observation,
        )?;
        let alternate = RecoveryCheckpoint::from_parts(
            AnchorRevision::INITIAL,
            None,
            authenticator.authenticator_id().clone(),
            alternate_observation,
            authenticator.authenticate(&preimage)?,
        )?;
        let mut coordinator =
            AnchorCoordinator::new(AlternateReceiptAnchor { alternate }, authenticator);
        assert!(matches!(
            coordinator.advance(observation(1, 1, 1, 3)?),
            Err(AnchorCoordinatorError::Contract(
                AnchorContractError::ReceiptMismatch
            ))
        ));
        Ok(())
    }
}
