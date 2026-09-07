#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Authenticated recovery-image capture, verification and restore admission.
//!
//! Recovery archives contain already sealed opaque state and authenticated
//! journal records. They never decrypt state. Publication is delegated to a
//! target-specific staging implementation and an unknown publish outcome is
//! never relabelled as a safe failure.
//! The irreversible target boundary executes through `anchor.with_current_fence(&publish_checkpoint, ...)`; the provider therefore serializes checkpoint currentness with stage, publish, and receipt verification.

use std::error::Error;
use std::fmt;

use heptabao_barrier_api::KeyEpoch;
use heptabao_journal_api::{
    DurableJournal, JournalDomain, JournalPayload, JournalRecord, JournalSequence, JournalTag,
    JournalTail,
};
use heptabao_rollback_anchor::{
    AnchorAuthenticatorId, AnchorContractError, AnchorCoordinator, AnchorCoordinatorError,
    AnchorRevision, CheckpointAuthenticator, CheckpointDigest, CheckpointObservation,
    RecoveryCheckpoint, RollbackAnchor,
};
use heptabao_storage_api::{DurableGenerationStore, Generation, StateDigest, StoreDomain};

const ARCHIVE_MAGIC: &[u8] = b"HEPTABAO-RECOVERY-ARCHIVE-V1\0";
const ARCHIVE_VERSION: u16 = 1;
pub const MAX_RECOVERY_ID_BYTES: usize = 128;
pub const MAX_RECOVERY_AUTHENTICATOR_ID_BYTES: usize = 128;
pub const MAX_RECOVERY_STATE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RECOVERY_RECORDS: usize = 100_000;
pub const MAX_RECOVERY_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct RecoveryArchiveId(String);

impl RecoveryArchiveId {
    pub fn new(value: String) -> Result<Self, RecoveryContractError> {
        if !valid_identity(&value, MAX_RECOVERY_ID_BYTES) {
            return Err(RecoveryContractError::InvalidArchiveId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RecoveryArchiveId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryArchiveId([OPAQUE])")
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RecoveryAuthenticatorId(String);

impl RecoveryAuthenticatorId {
    pub fn new(value: String) -> Result<Self, RecoveryContractError> {
        if !valid_identity(&value, MAX_RECOVERY_AUTHENTICATOR_ID_BYTES) {
            return Err(RecoveryContractError::InvalidAuthenticatorId);
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

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct RecoveryTag([u8; 32]);

impl RecoveryTag {
    pub fn new(value: [u8; 32]) -> Result<Self, RecoveryContractError> {
        if value == [0; 32] {
            return Err(RecoveryContractError::ZeroRecoveryTag);
        }
        Ok(Self(value))
    }

    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for RecoveryTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryTag([BOUND])")
    }
}

#[derive(Eq, PartialEq)]
pub struct RecoveryRecord {
    sequence: JournalSequence,
    previous_tag: Option<JournalTag>,
    tag: JournalTag,
    payload: Vec<u8>,
}

impl RecoveryRecord {
    pub fn from_journal_record(record: JournalRecord) -> Self {
        Self {
            sequence: record.sequence,
            previous_tag: record.previous_tag,
            tag: record.tag,
            payload: record.payload.into_bytes(),
        }
    }

    pub const fn sequence(&self) -> JournalSequence {
        self.sequence
    }

    pub const fn previous_tag(&self) -> Option<JournalTag> {
        self.previous_tag
    }

    pub const fn tag(&self) -> JournalTag {
        self.tag
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_journal_record(mut self) -> Result<JournalRecord, RecoveryContractError> {
        let payload = JournalPayload::new(std::mem::take(&mut self.payload))
            .map_err(|_| RecoveryContractError::InvalidRecordPayload)?;
        Ok(JournalRecord {
            sequence: self.sequence,
            previous_tag: self.previous_tag,
            tag: self.tag,
            payload,
        })
    }
}

impl fmt::Debug for RecoveryRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryRecord")
            .field("sequence", &self.sequence)
            .field("previous_tag", &self.previous_tag)
            .field("tag", &self.tag)
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

impl Drop for RecoveryRecord {
    fn drop(&mut self) {
        self.payload.fill(0);
    }
}

pub type RecoveryImageParts = (
    RecoveryArchiveId,
    RecoveryAuthenticatorId,
    CheckpointObservation,
    RecoveryCheckpoint,
    Vec<u8>,
    Vec<RecoveryRecord>,
);

#[derive(Eq, PartialEq)]
pub struct RecoveryImage {
    archive_id: RecoveryArchiveId,
    authenticator_id: RecoveryAuthenticatorId,
    observation: CheckpointObservation,
    checkpoint: RecoveryCheckpoint,
    sealed_state: Vec<u8>,
    records: Vec<RecoveryRecord>,
}

impl RecoveryImage {
    pub fn new(
        archive_id: RecoveryArchiveId,
        authenticator_id: RecoveryAuthenticatorId,
        observation: CheckpointObservation,
        checkpoint: RecoveryCheckpoint,
        mut sealed_state: Vec<u8>,
        records: Vec<RecoveryRecord>,
    ) -> Result<Self, RecoveryContractError> {
        if sealed_state.is_empty() || sealed_state.len() > MAX_RECOVERY_STATE_BYTES {
            sealed_state.fill(0);
            return Err(RecoveryContractError::InvalidSealedState);
        }
        let image = Self {
            archive_id,
            authenticator_id,
            observation,
            checkpoint,
            sealed_state,
            records,
        };
        validate_image(&image)?;
        Ok(image)
    }

    pub fn archive_id(&self) -> &RecoveryArchiveId {
        &self.archive_id
    }

    pub const fn authenticator_id(&self) -> &RecoveryAuthenticatorId {
        &self.authenticator_id
    }

    pub const fn observation(&self) -> &CheckpointObservation {
        &self.observation
    }

    pub const fn checkpoint(&self) -> &RecoveryCheckpoint {
        &self.checkpoint
    }

    pub fn sealed_state(&self) -> &[u8] {
        &self.sealed_state
    }

    pub fn records(&self) -> &[RecoveryRecord] {
        &self.records
    }

    fn into_parts(mut self) -> RecoveryImageParts {
        let state = std::mem::take(&mut self.sealed_state);
        let records = std::mem::take(&mut self.records);
        (
            self.archive_id.clone(),
            self.authenticator_id.clone(),
            self.observation.clone(),
            self.checkpoint.clone(),
            state,
            records,
        )
    }
}

impl fmt::Debug for RecoveryImage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryImage")
            .field("archive_id", &self.archive_id)
            .field("authenticator_id", &self.authenticator_id)
            .field("observation", &self.observation)
            .field("checkpoint_revision", &self.checkpoint.revision())
            .field("sealed_state_bytes", &self.sealed_state.len())
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl Drop for RecoveryImage {
    fn drop(&mut self) {
        self.sealed_state.fill(0);
    }
}

#[derive(Eq, PartialEq)]
pub struct RecoveryArchive {
    image: RecoveryImage,
    tag: RecoveryTag,
}

impl RecoveryArchive {
    pub fn seal<A: RecoveryAuthenticator>(
        image: RecoveryImage,
        authenticator: &A,
    ) -> RecoveryVerifyResult<Self, A::Error> {
        validate_image(&image).map_err(RecoveryVerificationError::Contract)?;
        if image.authenticator_id != *authenticator.authenticator_id() {
            return Err(RecoveryVerificationError::Contract(
                RecoveryContractError::AuthenticatorMismatch,
            ));
        }
        let preimage =
            canonical_archive_preimage(&image).map_err(RecoveryVerificationError::Contract)?;
        let tag = authenticator
            .authenticate(&preimage)
            .map_err(RecoveryVerificationError::Authenticator)?;
        Ok(Self { image, tag })
    }

    pub fn capture<S, J, A>(
        archive_id: RecoveryArchiveId,
        store: &S,
        journal: &J,
        key_epoch: KeyEpoch,
        checkpoint: RecoveryCheckpoint,
        authenticator: &A,
    ) -> RecoveryCaptureResult<Self, S::Error, J::Error, A::Error>
    where
        S: DurableGenerationStore,
        J: DurableJournal,
        A: RecoveryAuthenticator,
    {
        let snapshot = store
            .load_current()
            .map_err(RecoveryCaptureError::Storage)?
            .ok_or(RecoveryCaptureError::Contract(
                RecoveryContractError::EmptySource,
            ))?;
        let records = journal
            .replay()
            .map_err(RecoveryCaptureError::Journal)?
            .into_iter()
            .map(RecoveryRecord::from_journal_record)
            .collect::<Vec<_>>();
        let observation = CheckpointObservation::new(
            store.domain().clone(),
            snapshot.generation,
            snapshot.digest,
            journal.domain().clone(),
            journal.tail(),
            key_epoch,
        );
        let image = RecoveryImage::new(
            archive_id,
            authenticator.authenticator_id().clone(),
            observation,
            checkpoint,
            snapshot.state.into_bytes(),
            records,
        )
        .map_err(RecoveryCaptureError::Contract)?;
        Self::seal(image, authenticator).map_err(|error| match error {
            RecoveryVerificationError::Contract(error) => RecoveryCaptureError::Contract(error),
            RecoveryVerificationError::Authenticator(error) => {
                RecoveryCaptureError::Authenticator(error)
            }
        })
    }

    pub fn verify<A: RecoveryAuthenticator>(
        self,
        authenticator: &A,
    ) -> RecoveryVerifyResult<VerifiedRecoveryImage, A::Error> {
        validate_image(&self.image).map_err(RecoveryVerificationError::Contract)?;
        if self.image.authenticator_id != *authenticator.authenticator_id() {
            return Err(RecoveryVerificationError::Contract(
                RecoveryContractError::AuthenticatorMismatch,
            ));
        }
        let preimage =
            canonical_archive_preimage(&self.image).map_err(RecoveryVerificationError::Contract)?;
        let expected = authenticator
            .authenticate(&preimage)
            .map_err(RecoveryVerificationError::Authenticator)?;
        if expected != self.tag {
            return Err(RecoveryVerificationError::Contract(
                RecoveryContractError::ArchiveAuthenticationFailed,
            ));
        }
        Ok(VerifiedRecoveryImage { image: self.image })
    }

    pub fn encode(&self) -> Result<Vec<u8>, RecoveryContractError> {
        validate_image(&self.image)?;
        let mut output = canonical_archive_preimage(&self.image)?;
        output.extend_from_slice(&self.tag.bytes());
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecoveryContractError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(ARCHIVE_MAGIC.len())? != ARCHIVE_MAGIC {
            return Err(RecoveryContractError::MalformedArchive);
        }
        if cursor.take_u16()? != ARCHIVE_VERSION {
            return Err(RecoveryContractError::UnsupportedArchiveVersion);
        }
        let archive_id_len = usize::from(cursor.take_u16()?);
        let authenticator_id_len = usize::from(cursor.take_u16()?);
        let checkpoint_authenticator_id_len = usize::from(cursor.take_u16()?);
        let store_domain_len = usize::from(cursor.take_u16()?);
        let journal_domain_len = usize::from(cursor.take_u16()?);
        let state_len = usize::try_from(cursor.take_u64()?)
            .map_err(|_| RecoveryContractError::LengthOverflow)?;
        let record_count = usize::try_from(cursor.take_u32()?)
            .map_err(|_| RecoveryContractError::LengthOverflow)?;
        if state_len == 0 || state_len > MAX_RECOVERY_STATE_BYTES {
            return Err(RecoveryContractError::InvalidSealedState);
        }
        if record_count > MAX_RECOVERY_RECORDS {
            return Err(RecoveryContractError::TooManyRecords);
        }
        let generation = Generation::new(cursor.take_u64()?)
            .map_err(|_| RecoveryContractError::MalformedArchive)?;
        let state_digest = StateDigest::new(cursor.take_array_32()?)
            .map_err(|_| RecoveryContractError::MalformedArchive)?;
        let key_epoch = KeyEpoch::new(cursor.take_u64()?)
            .map_err(|_| RecoveryContractError::MalformedArchive)?;
        let tail = decode_tail(&mut cursor)?;
        let revision = AnchorRevision::new(cursor.take_u64()?)
            .map_err(|_| RecoveryContractError::MalformedArchive)?;
        let previous_digest = decode_checkpoint_digest(&mut cursor)?;
        let checkpoint_digest = CheckpointDigest::new(cursor.take_array_32()?)
            .map_err(|_| RecoveryContractError::MalformedArchive)?;
        let archive_id = std::str::from_utf8(cursor.take(archive_id_len)?)
            .map_err(|_| RecoveryContractError::MalformedArchive)?;
        let authenticator_id = std::str::from_utf8(cursor.take(authenticator_id_len)?)
            .map_err(|_| RecoveryContractError::MalformedArchive)?;
        let checkpoint_authenticator_id =
            std::str::from_utf8(cursor.take(checkpoint_authenticator_id_len)?)
                .map_err(|_| RecoveryContractError::MalformedArchive)?;
        let store_domain = std::str::from_utf8(cursor.take(store_domain_len)?)
            .map_err(|_| RecoveryContractError::MalformedArchive)?;
        let journal_domain = std::str::from_utf8(cursor.take(journal_domain_len)?)
            .map_err(|_| RecoveryContractError::MalformedArchive)?;
        let sealed_state = cursor.take(state_len)?.to_vec();
        let mut payload_budget = state_len;
        let mut records = Vec::with_capacity(record_count);
        for _ in 0..record_count {
            let record = decode_record(&mut cursor)?;
            payload_budget = payload_budget
                .checked_add(record.payload().len())
                .ok_or(RecoveryContractError::LengthOverflow)?;
            if payload_budget > MAX_RECOVERY_PAYLOAD_BYTES {
                return Err(RecoveryContractError::PayloadBudgetExceeded);
            }
            records.push(record);
        }
        let tag = RecoveryTag::new(cursor.take_array_32()?)?;
        if !cursor.is_finished() {
            return Err(RecoveryContractError::TrailingArchiveBytes);
        }
        let observation = CheckpointObservation::new(
            StoreDomain::new(store_domain.to_owned())
                .map_err(|_| RecoveryContractError::MalformedArchive)?,
            generation,
            state_digest,
            JournalDomain::new(journal_domain.to_owned())
                .map_err(|_| RecoveryContractError::MalformedArchive)?,
            tail,
            key_epoch,
        );
        let checkpoint = RecoveryCheckpoint::from_parts(
            revision,
            previous_digest,
            AnchorAuthenticatorId::new(checkpoint_authenticator_id.to_owned())
                .map_err(|_| RecoveryContractError::MalformedArchive)?,
            observation.clone(),
            checkpoint_digest,
        )
        .map_err(|_| RecoveryContractError::InvalidCheckpoint)?;
        let image = RecoveryImage::new(
            RecoveryArchiveId::new(archive_id.to_owned())?,
            RecoveryAuthenticatorId::new(authenticator_id.to_owned())?,
            observation,
            checkpoint,
            sealed_state,
            records,
        )?;
        Ok(Self { image, tag })
    }
}

impl fmt::Debug for RecoveryArchive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryArchive")
            .field("image", &self.image)
            .field("tag", &self.tag)
            .finish()
    }
}

pub struct VerifiedRecoveryImage {
    image: RecoveryImage,
}

impl VerifiedRecoveryImage {
    pub fn archive_id(&self) -> &RecoveryArchiveId {
        self.image.archive_id()
    }

    pub const fn authenticator_id(&self) -> &RecoveryAuthenticatorId {
        self.image.authenticator_id()
    }

    pub const fn observation(&self) -> &CheckpointObservation {
        self.image.observation()
    }

    pub const fn checkpoint(&self) -> &RecoveryCheckpoint {
        self.image.checkpoint()
    }
}

impl fmt::Debug for VerifiedRecoveryImage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("VerifiedRecoveryImage")
            .field(&self.image)
            .finish()
    }
}

/// A recovery image authorized against the current external rollback anchor.
///
/// The constructor is private. Only [`RecoveryRestorer`] can produce this
/// single-use capability after re-reading and authenticating the current anchor.
pub struct AuthorizedRecoveryImage {
    image: VerifiedRecoveryImage,
    anchor_revision: AnchorRevision,
}

impl AuthorizedRecoveryImage {
    pub fn archive_id(&self) -> &RecoveryArchiveId {
        self.image.archive_id()
    }

    pub const fn observation(&self) -> &CheckpointObservation {
        self.image.observation()
    }

    pub const fn checkpoint(&self) -> &RecoveryCheckpoint {
        self.image.checkpoint()
    }

    pub const fn anchor_revision(&self) -> AnchorRevision {
        self.anchor_revision
    }

    pub fn into_authorized_parts(self) -> (RecoveryImageParts, AnchorRevision) {
        (self.image.image.into_parts(), self.anchor_revision)
    }
}

impl fmt::Debug for AuthorizedRecoveryImage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedRecoveryImage")
            .field("archive_id", self.archive_id())
            .field("checkpoint_digest", &self.checkpoint().digest())
            .field("anchor_revision", &self.anchor_revision)
            .finish()
    }
}

pub trait RecoveryAuthenticator: fmt::Debug + Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn authenticator_id(&self) -> &RecoveryAuthenticatorId;

    fn authenticate(&self, preimage: &[u8]) -> Result<RecoveryTag, Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreReceipt {
    pub archive_id: RecoveryArchiveId,
    pub observation: CheckpointObservation,
    pub checkpoint_digest: CheckpointDigest,
    pub anchor_revision: AnchorRevision,
}

#[derive(Debug)]
pub enum PublishFailure<E>
where
    E: Error + Send + Sync + 'static,
{
    NotPublished(E),
    OutcomeUnknown(E),
}

impl<E> fmt::Display for PublishFailure<E>
where
    E: Error + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPublished(error) => {
                write!(formatter, "recovery target was not published: {error}")
            }
            Self::OutcomeUnknown(error) => write!(
                formatter,
                "recovery target publication outcome is unknown: {error}"
            ),
        }
    }
}

impl<E> Error for PublishFailure<E> where E: Error + Send + Sync + 'static {}

#[derive(Debug)]
pub enum StageFailure<E>
where
    E: Error + Send + Sync + 'static,
{
    TargetNotEmpty,
    Provider(E),
}

impl<E> fmt::Display for StageFailure<E>
where
    E: Error + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetNotEmpty => formatter.write_str("recovery target is not empty"),
            Self::Provider(error) => write!(formatter, "recovery target staging failure: {error}"),
        }
    }
}

impl<E> Error for StageFailure<E> where E: Error + Send + Sync + 'static {}

pub trait RecoveryTarget: fmt::Debug {
    type Error: Error + Send + Sync + 'static;
    type Staged: fmt::Debug;

    /// Atomically verifies and claims an empty target under the provider's
    /// writer fence. The staged token must retain target-side exclusivity
    /// needed through `publish`.
    fn stage_if_empty(
        &mut self,
        image: AuthorizedRecoveryImage,
    ) -> Result<Self::Staged, StageFailure<Self::Error>>;

    fn publish(
        &mut self,
        staged: Self::Staged,
    ) -> Result<RestoreReceipt, PublishFailure<Self::Error>>;
}

#[derive(Debug, Default)]
pub struct RecoveryRestorer;

impl RecoveryRestorer {
    pub fn restore<T, A, R, P>(
        target: &mut T,
        archive: RecoveryArchive,
        authenticator: &A,
        anchor: &mut AnchorCoordinator<R, P>,
    ) -> RecoveryRestoreResult<RestoreReceipt, A::Error, T::Error, R::Error, P::Error>
    where
        T: RecoveryTarget,
        A: RecoveryAuthenticator,
        R: RollbackAnchor,
        P: CheckpointAuthenticator,
    {
        let verified = archive.verify(authenticator).map_err(|error| match error {
            RecoveryVerificationError::Contract(error) => RecoveryRestoreError::Contract(error),
            RecoveryVerificationError::Authenticator(error) => {
                RecoveryRestoreError::Authenticator(error)
            }
        })?;
        anchor
            .verify_current(verified.checkpoint())
            .map_err(map_anchor_restore_error)?;
        let publish_checkpoint = verified.checkpoint().clone();
        let anchor_revision = publish_checkpoint.revision();
        let expected = RestoreReceipt {
            archive_id: verified.archive_id().clone(),
            observation: verified.observation().clone(),
            checkpoint_digest: verified.checkpoint().digest(),
            anchor_revision,
        };
        let authorized = AuthorizedRecoveryImage {
            image: verified,
            anchor_revision,
        };
        anchor
            .with_current_fence(&publish_checkpoint, || {
                let staged = target
                    .stage_if_empty(authorized)
                    .map_err(|error| match error {
                        StageFailure::TargetNotEmpty => {
                            RecoveryRestoreError::Contract(RecoveryContractError::TargetNotEmpty)
                        }
                        StageFailure::Provider(error) => RecoveryRestoreError::Target(error),
                    })?;
                let receipt = target.publish(staged).map_err(|error| match error {
                    PublishFailure::NotPublished(error) => RecoveryRestoreError::Target(error),
                    PublishFailure::OutcomeUnknown(error) => {
                        RecoveryRestoreError::PublishOutcomeUnknown(error)
                    }
                })?;
                if receipt != expected {
                    return Err(RecoveryRestoreError::PublishReceiptMismatchOutcomeUnknown {
                        expected: Box::new(expected),
                        observed: Box::new(receipt),
                    });
                }
                Ok(receipt)
            })
            .map_err(map_anchor_restore_error)?
    }
}

fn map_anchor_restore_error<A, E, R, P>(
    error: AnchorCoordinatorError<R, P>,
) -> RecoveryRestoreError<A, E, R, P>
where
    A: Error + Send + Sync + 'static,
    E: Error + Send + Sync + 'static,
    R: Error + Send + Sync + 'static,
    P: Error + Send + Sync + 'static,
{
    match error {
        AnchorCoordinatorError::Contract(AnchorContractError::CheckpointNotCurrent) => {
            RecoveryRestoreError::Contract(RecoveryContractError::CheckpointNotAnchored)
        }
        AnchorCoordinatorError::Contract(error) => RecoveryRestoreError::AnchorContract(error),
        AnchorCoordinatorError::Anchor(error) => RecoveryRestoreError::Anchor(error),
        AnchorCoordinatorError::FenceOutcomeUnknown(error) => {
            RecoveryRestoreError::AnchorFenceOutcomeUnknown(error)
        }
        AnchorCoordinatorError::Authenticator(error) => {
            RecoveryRestoreError::CheckpointAuthenticator(error)
        }
    }
}

pub type RecoveryCaptureResult<T, S, J, A> = Result<T, RecoveryCaptureError<S, J, A>>;
pub type RecoveryVerifyResult<T, A> = Result<T, RecoveryVerificationError<A>>;
pub type RecoveryRestoreResult<T, A, E, R, P> = Result<T, RecoveryRestoreError<A, E, R, P>>;

#[derive(Debug)]
pub enum RecoveryCaptureError<S, J, A>
where
    S: Error + Send + Sync + 'static,
    J: Error + Send + Sync + 'static,
    A: Error + Send + Sync + 'static,
{
    Contract(RecoveryContractError),
    Storage(S),
    Journal(J),
    Authenticator(A),
}

impl<S, J, A> fmt::Display for RecoveryCaptureError<S, J, A>
where
    S: Error + Send + Sync + 'static,
    J: Error + Send + Sync + 'static,
    A: Error + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => {
                write!(formatter, "recovery capture contract failure: {error}")
            }
            Self::Storage(error) => write!(formatter, "recovery source storage failure: {error}"),
            Self::Journal(error) => write!(formatter, "recovery source journal failure: {error}"),
            Self::Authenticator(error) => {
                write!(formatter, "recovery archive authenticator failure: {error}")
            }
        }
    }
}

impl<S, J, A> Error for RecoveryCaptureError<S, J, A>
where
    S: Error + Send + Sync + 'static,
    J: Error + Send + Sync + 'static,
    A: Error + Send + Sync + 'static,
{
}

#[derive(Debug)]
pub enum RecoveryVerificationError<A>
where
    A: Error + Send + Sync + 'static,
{
    Contract(RecoveryContractError),
    Authenticator(A),
}

impl<A> fmt::Display for RecoveryVerificationError<A>
where
    A: Error + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => {
                write!(formatter, "recovery verification contract failure: {error}")
            }
            Self::Authenticator(error) => {
                write!(formatter, "recovery archive authenticator failure: {error}")
            }
        }
    }
}

impl<A> Error for RecoveryVerificationError<A> where A: Error + Send + Sync + 'static {}

#[derive(Debug)]
pub enum RecoveryRestoreError<A, E, R, P>
where
    A: Error + Send + Sync + 'static,
    E: Error + Send + Sync + 'static,
    R: Error + Send + Sync + 'static,
    P: Error + Send + Sync + 'static,
{
    Contract(RecoveryContractError),
    AnchorContract(AnchorContractError),
    Authenticator(A),
    CheckpointAuthenticator(P),
    Anchor(R),
    AnchorFenceOutcomeUnknown(R),
    Target(E),
    PublishOutcomeUnknown(E),
    PublishReceiptMismatchOutcomeUnknown {
        expected: Box<RestoreReceipt>,
        observed: Box<RestoreReceipt>,
    },
}

impl<A, E, R, P> fmt::Display for RecoveryRestoreError<A, E, R, P>
where
    A: Error + Send + Sync + 'static,
    E: Error + Send + Sync + 'static,
    R: Error + Send + Sync + 'static,
    P: Error + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => {
                write!(formatter, "recovery restore contract failure: {error}")
            }
            Self::AnchorContract(error) => {
                write!(
                    formatter,
                    "rollback anchor contract failure during restore: {error}"
                )
            }
            Self::Authenticator(error) => {
                write!(formatter, "recovery archive authenticator failure: {error}")
            }
            Self::CheckpointAuthenticator(error) => {
                write!(
                    formatter,
                    "checkpoint authenticator failure during restore: {error}"
                )
            }
            Self::Anchor(error) => write!(
                formatter,
                "rollback anchor provider failed before recovery publication began: {error}"
            ),
            Self::AnchorFenceOutcomeUnknown(error) => write!(
                formatter,
                "rollback anchor fence failed after recovery publication may have begun; reconcile anchor and target before retry: {error}"
            ),
            Self::Target(error) => write!(formatter, "recovery target failure: {error}"),
            Self::PublishOutcomeUnknown(error) => write!(
                formatter,
                "recovery target may have been published; reconcile before retry: {error}"
            ),
            Self::PublishReceiptMismatchOutcomeUnknown { expected, observed } => write!(
                formatter,
                "recovery target returned a mismatched receipt after publication; outcome is unknown and requires readback: expected {expected:?}, observed {observed:?}"
            ),
        }
    }
}

impl<A, E, R, P> Error for RecoveryRestoreError<A, E, R, P>
where
    A: Error + Send + Sync + 'static,
    E: Error + Send + Sync + 'static,
    R: Error + Send + Sync + 'static,
    P: Error + Send + Sync + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::AnchorContract(error) => Some(error),
            Self::Authenticator(error) => Some(error),
            Self::CheckpointAuthenticator(error) => Some(error),
            Self::Anchor(error) | Self::AnchorFenceOutcomeUnknown(error) => Some(error),
            Self::Target(error) | Self::PublishOutcomeUnknown(error) => Some(error),
            Self::PublishReceiptMismatchOutcomeUnknown { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryContractError {
    InvalidArchiveId,
    InvalidAuthenticatorId,
    ZeroRecoveryTag,
    UnsupportedArchiveVersion,
    InvalidSealedState,
    InvalidRecordPayload,
    TooManyRecords,
    PayloadBudgetExceeded,
    InvalidRecordSequence,
    InvalidRecordChain,
    TailMismatch,
    InvalidCheckpoint,
    CheckpointNotAnchored,
    EmptySource,
    TargetNotEmpty,
    AuthenticatorMismatch,
    ArchiveAuthenticationFailed,
    RestoreReceiptMismatch,
    LengthOverflow,
    MalformedArchive,
    TrailingArchiveBytes,
}

impl fmt::Display for RecoveryContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArchiveId => "recovery archive identity is invalid",
            Self::InvalidAuthenticatorId => "recovery authenticator identity is invalid",
            Self::ZeroRecoveryTag => "recovery archive tag must be non-zero",
            Self::UnsupportedArchiveVersion => "recovery archive version is unsupported",
            Self::InvalidSealedState => "recovery sealed state is empty or exceeds its bound",
            Self::InvalidRecordPayload => "recovery record payload is empty or invalid",
            Self::TooManyRecords => "recovery archive contains too many journal records",
            Self::PayloadBudgetExceeded => "recovery archive payload budget was exceeded",
            Self::InvalidRecordSequence => "recovery journal sequence is not contiguous",
            Self::InvalidRecordChain => "recovery journal tag chain is invalid",
            Self::TailMismatch => "recovery journal records do not match the observed tail",
            Self::InvalidCheckpoint => "recovery checkpoint does not match the archive observation",
            Self::CheckpointNotAnchored => {
                "recovery checkpoint was not verified against the external anchor"
            }
            Self::EmptySource => "recovery capture source has no current durable state",
            Self::TargetNotEmpty => "recovery target must be empty",
            Self::AuthenticatorMismatch => "recovery authenticator identity mismatch",
            Self::ArchiveAuthenticationFailed => "recovery archive authentication failed",
            Self::RestoreReceiptMismatch => {
                "recovery target receipt does not match the verified image"
            }
            Self::LengthOverflow => "recovery archive length overflow",
            Self::MalformedArchive => "recovery archive is malformed or truncated",
            Self::TrailingArchiveBytes => "recovery archive has trailing bytes",
        })
    }
}

impl Error for RecoveryContractError {}

fn validate_image(image: &RecoveryImage) -> Result<(), RecoveryContractError> {
    if image.sealed_state.is_empty() || image.sealed_state.len() > MAX_RECOVERY_STATE_BYTES {
        return Err(RecoveryContractError::InvalidSealedState);
    }
    if image.records.len() > MAX_RECOVERY_RECORDS {
        return Err(RecoveryContractError::TooManyRecords);
    }
    if image.checkpoint.observation() != &image.observation {
        return Err(RecoveryContractError::InvalidCheckpoint);
    }
    let mut payload_budget = image.sealed_state.len();
    let mut previous_tag = None;
    for (index, record) in image.records.iter().enumerate() {
        if record.payload.is_empty() {
            return Err(RecoveryContractError::InvalidRecordPayload);
        }
        payload_budget = payload_budget
            .checked_add(record.payload.len())
            .ok_or(RecoveryContractError::LengthOverflow)?;
        if payload_budget > MAX_RECOVERY_PAYLOAD_BYTES {
            return Err(RecoveryContractError::PayloadBudgetExceeded);
        }
        let expected_value =
            u64::try_from(index + 1).map_err(|_| RecoveryContractError::LengthOverflow)?;
        if record.sequence.get() != expected_value {
            return Err(RecoveryContractError::InvalidRecordSequence);
        }
        if record.previous_tag != previous_tag {
            return Err(RecoveryContractError::InvalidRecordChain);
        }
        previous_tag = Some(record.tag);
    }
    let expected_tail = image.records.last().map(|record| JournalTail {
        sequence: record.sequence,
        tag: record.tag,
    });
    if expected_tail != image.observation.journal_tail() {
        return Err(RecoveryContractError::TailMismatch);
    }
    Ok(())
}

fn canonical_archive_preimage(image: &RecoveryImage) -> Result<Vec<u8>, RecoveryContractError> {
    validate_image(image)?;
    let archive_id_len = u16::try_from(image.archive_id.as_str().len())
        .map_err(|_| RecoveryContractError::LengthOverflow)?;
    let authenticator_id_len = u16::try_from(image.authenticator_id.as_str().len())
        .map_err(|_| RecoveryContractError::LengthOverflow)?;
    let checkpoint_authenticator_id_len =
        u16::try_from(image.checkpoint.authenticator_id().as_str().len())
            .map_err(|_| RecoveryContractError::LengthOverflow)?;
    let store_domain_len = u16::try_from(image.observation.store_domain().as_str().len())
        .map_err(|_| RecoveryContractError::LengthOverflow)?;
    let journal_domain_len = u16::try_from(image.observation.journal_domain().as_str().len())
        .map_err(|_| RecoveryContractError::LengthOverflow)?;
    let state_len = u64::try_from(image.sealed_state.len())
        .map_err(|_| RecoveryContractError::LengthOverflow)?;
    let record_count =
        u32::try_from(image.records.len()).map_err(|_| RecoveryContractError::LengthOverflow)?;
    let mut output = Vec::new();
    output.extend_from_slice(ARCHIVE_MAGIC);
    output.extend_from_slice(&ARCHIVE_VERSION.to_be_bytes());
    output.extend_from_slice(&archive_id_len.to_be_bytes());
    output.extend_from_slice(&authenticator_id_len.to_be_bytes());
    output.extend_from_slice(&checkpoint_authenticator_id_len.to_be_bytes());
    output.extend_from_slice(&store_domain_len.to_be_bytes());
    output.extend_from_slice(&journal_domain_len.to_be_bytes());
    output.extend_from_slice(&state_len.to_be_bytes());
    output.extend_from_slice(&record_count.to_be_bytes());
    output.extend_from_slice(&image.observation.generation().get().to_be_bytes());
    output.extend_from_slice(&image.observation.state_digest().bytes());
    output.extend_from_slice(&image.observation.key_epoch().get().to_be_bytes());
    encode_tail(&mut output, image.observation.journal_tail());
    output.extend_from_slice(&image.checkpoint.revision().get().to_be_bytes());
    encode_checkpoint_digest(&mut output, image.checkpoint.previous_digest());
    output.extend_from_slice(&image.checkpoint.digest().bytes());
    output.extend_from_slice(image.archive_id.as_str().as_bytes());
    output.extend_from_slice(image.authenticator_id.as_str().as_bytes());
    output.extend_from_slice(image.checkpoint.authenticator_id().as_str().as_bytes());
    output.extend_from_slice(image.observation.store_domain().as_str().as_bytes());
    output.extend_from_slice(image.observation.journal_domain().as_str().as_bytes());
    output.extend_from_slice(&image.sealed_state);
    for record in &image.records {
        encode_record(&mut output, record)?;
    }
    Ok(output)
}

fn encode_tail(output: &mut Vec<u8>, tail: Option<JournalTail>) {
    match tail {
        Some(tail) => {
            output.push(1);
            output.extend_from_slice(&tail.sequence.get().to_be_bytes());
            output.extend_from_slice(&tail.tag.bytes());
        }
        None => output.push(0),
    }
}

fn decode_tail(cursor: &mut Cursor<'_>) -> Result<Option<JournalTail>, RecoveryContractError> {
    match cursor.take_u8()? {
        0 => Ok(None),
        1 => {
            let sequence = JournalSequence::new(cursor.take_u64()?)
                .map_err(|_| RecoveryContractError::MalformedArchive)?;
            let tag = JournalTag::new(cursor.take_array_32()?)
                .map_err(|_| RecoveryContractError::MalformedArchive)?;
            Ok(Some(JournalTail { sequence, tag }))
        }
        _ => Err(RecoveryContractError::MalformedArchive),
    }
}

fn encode_checkpoint_digest(output: &mut Vec<u8>, digest: Option<CheckpointDigest>) {
    match digest {
        Some(digest) => {
            output.push(1);
            output.extend_from_slice(&digest.bytes());
        }
        None => output.push(0),
    }
}

fn decode_checkpoint_digest(
    cursor: &mut Cursor<'_>,
) -> Result<Option<CheckpointDigest>, RecoveryContractError> {
    match cursor.take_u8()? {
        0 => Ok(None),
        1 => CheckpointDigest::new(cursor.take_array_32()?)
            .map(Some)
            .map_err(|_| RecoveryContractError::MalformedArchive),
        _ => Err(RecoveryContractError::MalformedArchive),
    }
}

fn encode_record(
    output: &mut Vec<u8>,
    record: &RecoveryRecord,
) -> Result<(), RecoveryContractError> {
    let payload_len =
        u32::try_from(record.payload.len()).map_err(|_| RecoveryContractError::LengthOverflow)?;
    output.extend_from_slice(&record.sequence.get().to_be_bytes());
    match record.previous_tag {
        Some(tag) => {
            output.push(1);
            output.extend_from_slice(&tag.bytes());
        }
        None => output.push(0),
    }
    output.extend_from_slice(&record.tag.bytes());
    output.extend_from_slice(&payload_len.to_be_bytes());
    output.extend_from_slice(&record.payload);
    Ok(())
}

fn decode_record(cursor: &mut Cursor<'_>) -> Result<RecoveryRecord, RecoveryContractError> {
    let sequence = JournalSequence::new(cursor.take_u64()?)
        .map_err(|_| RecoveryContractError::MalformedArchive)?;
    let previous_tag = match cursor.take_u8()? {
        0 => None,
        1 => Some(
            JournalTag::new(cursor.take_array_32()?)
                .map_err(|_| RecoveryContractError::MalformedArchive)?,
        ),
        _ => return Err(RecoveryContractError::MalformedArchive),
    };
    let tag = JournalTag::new(cursor.take_array_32()?)
        .map_err(|_| RecoveryContractError::MalformedArchive)?;
    let payload_len =
        usize::try_from(cursor.take_u32()?).map_err(|_| RecoveryContractError::LengthOverflow)?;
    if payload_len == 0 || payload_len > MAX_RECOVERY_PAYLOAD_BYTES {
        return Err(RecoveryContractError::InvalidRecordPayload);
    }
    let payload = cursor.take(payload_len)?.to_vec();
    if payload.is_empty() {
        return Err(RecoveryContractError::InvalidRecordPayload);
    }
    Ok(RecoveryRecord {
        sequence,
        previous_tag,
        tag,
        payload,
    })
}

#[derive(Debug)]
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RecoveryContractError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RecoveryContractError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RecoveryContractError::MalformedArchive)?;
        self.offset = end;
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8, RecoveryContractError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, RecoveryContractError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn take_u32(&mut self) -> Result<u32, RecoveryContractError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn take_u64(&mut self) -> Result<u64, RecoveryContractError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn take_array_32(&mut self) -> Result<[u8; 32], RecoveryContractError> {
        let bytes = self.take(32)?;
        let mut output = [0_u8; 32];
        output.copy_from_slice(bytes);
        Ok(output)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use heptabao_journal_api::{AppendReceipt, JournalContractError, JournalOpenMode};
    use heptabao_rollback_anchor::{
        AnchorAdvanceReceipt, AnchorContractError, AnchorCoordinator, CheckpointAuthenticator,
        RollbackAnchor,
    };
    use heptabao_storage_api::{
        CommitIntent, CommitReceipt, CommitRecovery, GenerationSnapshot, OpaqueState, StoreOpenMode,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestError {
        Contract,
        Target,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(match self {
                Self::Contract => "test contract failure",
                Self::Target => "test recovery target failure",
            })
        }
    }

    impl Error for TestError {}

    #[derive(Debug)]
    struct TestAuthenticator {
        id: RecoveryAuthenticatorId,
    }

    impl TestAuthenticator {
        fn new() -> Result<Self, RecoveryContractError> {
            Ok(Self {
                id: RecoveryAuthenticatorId::new("heptabao/test-recovery".to_owned())?,
            })
        }
    }

    impl RecoveryAuthenticator for TestAuthenticator {
        type Error = TestError;

        fn authenticator_id(&self) -> &RecoveryAuthenticatorId {
            &self.id
        }

        fn authenticate(&self, preimage: &[u8]) -> Result<RecoveryTag, Self::Error> {
            let mut output = [0_u8; 32];
            for (index, byte) in preimage.iter().copied().enumerate() {
                let slot = index % output.len();
                output[slot] = output[slot]
                    .wrapping_add(byte)
                    .rotate_left((slot % 5) as u32);
            }
            if output == [0; 32] {
                output[0] = 1;
            }
            RecoveryTag::new(output).map_err(|_| TestError::Contract)
        }
    }

    #[derive(Debug)]
    struct MemoryStore {
        domain: StoreDomain,
        generation: Generation,
        digest: StateDigest,
        bytes: Vec<u8>,
    }

    impl MemoryStore {
        fn new() -> Result<Self, Box<dyn Error>> {
            Ok(Self {
                domain: StoreDomain::new("heptabao/recovery-state".to_owned())?,
                generation: Generation::INITIAL,
                digest: StateDigest::new([3; 32])?,
                bytes: b"sealed-state".to_vec(),
            })
        }
    }

    impl Drop for MemoryStore {
        fn drop(&mut self) {
            self.bytes.fill(0);
        }
    }

    impl DurableGenerationStore for MemoryStore {
        type Error = TestError;

        fn domain(&self) -> &StoreDomain {
            &self.domain
        }

        fn open_mode(&self) -> StoreOpenMode {
            StoreOpenMode::ReopenExisting
        }

        fn current_generation(&self) -> Option<Generation> {
            Some(self.generation)
        }

        fn load_current(&self) -> Result<Option<GenerationSnapshot>, Self::Error> {
            let state = OpaqueState::new(self.bytes.clone()).map_err(|_| TestError::Contract)?;
            Ok(Some(GenerationSnapshot {
                generation: self.generation,
                digest: self.digest,
                state,
            }))
        }

        fn prepare_commit(
            &self,
            _expected_current: Option<Generation>,
            _candidate: &OpaqueState,
        ) -> Result<CommitIntent, Self::Error> {
            Err(TestError::Contract)
        }

        fn recover_commit(&mut self, _intent: CommitIntent) -> Result<CommitRecovery, Self::Error> {
            Err(TestError::Contract)
        }

        fn commit(
            &mut self,
            _expected_current: Option<Generation>,
            _candidate: OpaqueState,
        ) -> Result<CommitReceipt, Self::Error> {
            Err(TestError::Contract)
        }
    }

    #[derive(Debug)]
    struct MemoryJournal {
        domain: JournalDomain,
        payloads: Vec<Vec<u8>>,
    }

    impl MemoryJournal {
        fn new() -> Result<Self, JournalContractError> {
            Ok(Self {
                domain: JournalDomain::new("heptabao/recovery-journal".to_owned())?,
                payloads: vec![b"one".to_vec(), b"two".to_vec()],
            })
        }
    }

    impl Drop for MemoryJournal {
        fn drop(&mut self) {
            for payload in &mut self.payloads {
                payload.fill(0);
            }
        }
    }

    impl DurableJournal for MemoryJournal {
        type Error = TestError;

        fn domain(&self) -> &JournalDomain {
            &self.domain
        }

        fn open_mode(&self) -> JournalOpenMode {
            JournalOpenMode::ReopenExisting
        }

        fn tail(&self) -> Option<JournalTail> {
            let sequence = JournalSequence::new(2).ok()?;
            let tag = JournalTag::new([2; 32]).ok()?;
            Some(JournalTail { sequence, tag })
        }

        fn replay(&self) -> Result<Vec<JournalRecord>, Self::Error> {
            let first_sequence = JournalSequence::new(1).map_err(|_| TestError::Contract)?;
            let second_sequence = JournalSequence::new(2).map_err(|_| TestError::Contract)?;
            let first_tag = JournalTag::new([1; 32]).map_err(|_| TestError::Contract)?;
            let second_tag = JournalTag::new([2; 32]).map_err(|_| TestError::Contract)?;
            Ok(vec![
                JournalRecord {
                    sequence: first_sequence,
                    previous_tag: None,
                    tag: first_tag,
                    payload: JournalPayload::new(self.payloads[0].clone())
                        .map_err(|_| TestError::Contract)?,
                },
                JournalRecord {
                    sequence: second_sequence,
                    previous_tag: Some(first_tag),
                    tag: second_tag,
                    payload: JournalPayload::new(self.payloads[1].clone())
                        .map_err(|_| TestError::Contract)?,
                },
            ])
        }

        fn append(
            &mut self,
            _expected_tail: Option<JournalSequence>,
            _payload: JournalPayload,
        ) -> Result<AppendReceipt, Self::Error> {
            Err(TestError::Contract)
        }
    }

    fn checkpoint(
        store: &MemoryStore,
        journal: &MemoryJournal,
    ) -> Result<RecoveryCheckpoint, Box<dyn Error>> {
        let observation = CheckpointObservation::new(
            store.domain.clone(),
            store.generation,
            store.digest,
            journal.domain.clone(),
            journal.tail(),
            KeyEpoch::INITIAL,
        );
        Ok(RecoveryCheckpoint::from_parts(
            AnchorRevision::INITIAL,
            None,
            AnchorAuthenticatorId::new("heptabao/test-anchor".to_owned())?,
            observation,
            CheckpointDigest::new([7; 32])?,
        )?)
    }

    #[derive(Debug)]
    struct TestAnchor {
        current: RecoveryCheckpoint,
    }

    impl RollbackAnchor for TestAnchor {
        type Error = TestError;

        fn current(&self) -> Result<Option<RecoveryCheckpoint>, Self::Error> {
            Ok(Some(self.current.clone()))
        }

        fn with_current_fence<T, F>(
            &mut self,
            expected: &RecoveryCheckpoint,
            operation: F,
        ) -> Result<T, heptabao_rollback_anchor::AnchorFenceError<Self::Error>>
        where
            F: FnOnce() -> T,
        {
            if &self.current != expected {
                return Err(heptabao_rollback_anchor::AnchorFenceError::CheckpointNotCurrent);
            }
            Ok(operation())
        }

        fn compare_and_swap(
            &mut self,
            _expected_revision: Option<AnchorRevision>,
            _next: RecoveryCheckpoint,
        ) -> Result<AnchorAdvanceReceipt, Self::Error> {
            Err(TestError::Contract)
        }
    }

    #[derive(Debug)]
    struct TestCheckpointAuthenticator {
        id: AnchorAuthenticatorId,
    }

    impl TestCheckpointAuthenticator {
        fn new() -> Result<Self, AnchorContractError> {
            Ok(Self {
                id: AnchorAuthenticatorId::new("heptabao/test-anchor".to_owned())?,
            })
        }
    }

    impl CheckpointAuthenticator for TestCheckpointAuthenticator {
        type Error = TestError;

        fn authenticator_id(&self) -> &AnchorAuthenticatorId {
            &self.id
        }

        fn authenticate(&self, _preimage: &[u8]) -> Result<CheckpointDigest, Self::Error> {
            CheckpointDigest::new([7; 32]).map_err(|_| TestError::Contract)
        }
    }

    fn checkpoint_coordinator(
        checkpoint: RecoveryCheckpoint,
    ) -> Result<AnchorCoordinator<TestAnchor, TestCheckpointAuthenticator>, Box<dyn Error>> {
        Ok(AnchorCoordinator::new(
            TestAnchor {
                current: checkpoint,
            },
            TestCheckpointAuthenticator::new()?,
        ))
    }

    #[derive(Debug)]
    struct PostEntryFenceFailureAnchor {
        current: RecoveryCheckpoint,
    }

    impl RollbackAnchor for PostEntryFenceFailureAnchor {
        type Error = TestError;

        fn current(&self) -> Result<Option<RecoveryCheckpoint>, Self::Error> {
            Ok(Some(self.current.clone()))
        }

        fn with_current_fence<T, F>(
            &mut self,
            expected: &RecoveryCheckpoint,
            operation: F,
        ) -> Result<T, heptabao_rollback_anchor::AnchorFenceError<Self::Error>>
        where
            F: FnOnce() -> T,
        {
            if &self.current != expected {
                return Err(heptabao_rollback_anchor::AnchorFenceError::CheckpointNotCurrent);
            }
            let _operation_result = operation();
            Err(
                heptabao_rollback_anchor::AnchorFenceError::OutcomeUnknownAfterEntry(
                    TestError::Target,
                ),
            )
        }

        fn compare_and_swap(
            &mut self,
            _expected_revision: Option<AnchorRevision>,
            _next: RecoveryCheckpoint,
        ) -> Result<AnchorAdvanceReceipt, Self::Error> {
            Err(TestError::Contract)
        }
    }

    #[derive(Debug, Default)]
    struct MemoryTarget {
        occupied: bool,
        outcome_unknown: bool,
        wrong_receipt: bool,
        restored_state: Vec<u8>,
    }

    impl Drop for MemoryTarget {
        fn drop(&mut self) {
            self.restored_state.fill(0);
        }
    }

    impl RecoveryTarget for MemoryTarget {
        type Error = TestError;
        type Staged = AuthorizedRecoveryImage;

        fn stage_if_empty(
            &mut self,
            image: AuthorizedRecoveryImage,
        ) -> Result<Self::Staged, StageFailure<Self::Error>> {
            if self.occupied {
                return Err(StageFailure::TargetNotEmpty);
            }
            Ok(image)
        }

        fn publish(
            &mut self,
            staged: Self::Staged,
        ) -> Result<RestoreReceipt, PublishFailure<Self::Error>> {
            if self.outcome_unknown {
                return Err(PublishFailure::OutcomeUnknown(TestError::Target));
            }
            let archive_id = staged.archive_id().clone();
            let observation = staged.observation().clone();
            let checkpoint_digest = staged.checkpoint().digest();
            let anchor_revision = staged.anchor_revision();
            let ((_, _, _, _, state, _), authorized_revision) = staged.into_authorized_parts();
            if authorized_revision != anchor_revision {
                return Err(PublishFailure::NotPublished(TestError::Contract));
            }
            self.restored_state = state;
            self.occupied = true;
            let returned_checkpoint_digest = if self.wrong_receipt {
                CheckpointDigest::new([0x55; 32])
                    .map_err(|_| PublishFailure::OutcomeUnknown(TestError::Contract))?
            } else {
                checkpoint_digest
            };
            Ok(RestoreReceipt {
                archive_id,
                observation,
                checkpoint_digest: returned_checkpoint_digest,
                anchor_revision,
            })
        }
    }

    #[derive(Debug)]
    struct SharedAnchor {
        current: Arc<Mutex<RecoveryCheckpoint>>,
    }

    impl RollbackAnchor for SharedAnchor {
        type Error = TestError;

        fn current(&self) -> Result<Option<RecoveryCheckpoint>, Self::Error> {
            self.current
                .lock()
                .map(|current| Some(current.clone()))
                .map_err(|_| TestError::Target)
        }

        fn with_current_fence<T, F>(
            &mut self,
            expected: &RecoveryCheckpoint,
            operation: F,
        ) -> Result<T, heptabao_rollback_anchor::AnchorFenceError<Self::Error>>
        where
            F: FnOnce() -> T,
        {
            let current = self.current.lock().map_err(|_| {
                heptabao_rollback_anchor::AnchorFenceError::ProviderBeforeEntry(TestError::Target)
            })?;
            if &*current != expected {
                return Err(heptabao_rollback_anchor::AnchorFenceError::CheckpointNotCurrent);
            }
            let result = operation();
            drop(current);
            Ok(result)
        }

        fn compare_and_swap(
            &mut self,
            expected_revision: Option<AnchorRevision>,
            next: RecoveryCheckpoint,
        ) -> Result<AnchorAdvanceReceipt, Self::Error> {
            let mut current = self.current.lock().map_err(|_| TestError::Target)?;
            if Some(current.revision()) != expected_revision {
                return Err(TestError::Contract);
            }
            let previous = current.clone();
            *current = next.clone();
            Ok(AnchorAdvanceReceipt {
                previous: Some(previous),
                current: next,
            })
        }
    }

    #[derive(Debug)]
    struct FenceProbeTarget {
        current: Arc<Mutex<RecoveryCheckpoint>>,
        publish_observed_fence: bool,
        occupied: bool,
    }

    impl RecoveryTarget for FenceProbeTarget {
        type Error = TestError;
        type Staged = AuthorizedRecoveryImage;

        fn stage_if_empty(
            &mut self,
            image: AuthorizedRecoveryImage,
        ) -> Result<Self::Staged, StageFailure<Self::Error>> {
            if self.occupied {
                return Err(StageFailure::TargetNotEmpty);
            }
            Ok(image)
        }

        fn publish(
            &mut self,
            staged: Self::Staged,
        ) -> Result<RestoreReceipt, PublishFailure<Self::Error>> {
            self.publish_observed_fence = self.current.try_lock().is_err();
            if !self.publish_observed_fence {
                return Err(PublishFailure::NotPublished(TestError::Target));
            }
            self.occupied = true;
            Ok(RestoreReceipt {
                archive_id: staged.archive_id().clone(),
                observation: staged.observation().clone(),
                checkpoint_digest: staged.checkpoint().digest(),
                anchor_revision: staged.anchor_revision(),
            })
        }
    }

    #[test]
    fn anchor_fence_is_held_across_target_publication() -> Result<(), Box<dyn Error>> {
        let store = MemoryStore::new()?;
        let journal = MemoryJournal::new()?;
        let checkpoint = checkpoint(&store, &journal)?;
        let shared = Arc::new(Mutex::new(checkpoint.clone()));
        let mut anchor = AnchorCoordinator::new(
            SharedAnchor {
                current: Arc::clone(&shared),
            },
            TestCheckpointAuthenticator::new()?,
        );
        let authenticator = TestAuthenticator::new()?;
        let archive = RecoveryArchive::capture(
            RecoveryArchiveId::new("recovery-anchor-fence".to_owned())?,
            &store,
            &journal,
            KeyEpoch::INITIAL,
            checkpoint,
            &authenticator,
        )?;
        let mut target = FenceProbeTarget {
            current: shared,
            publish_observed_fence: false,
            occupied: false,
        };
        let receipt = RecoveryRestorer::restore(&mut target, archive, &authenticator, &mut anchor)?;
        assert_eq!(receipt.anchor_revision, AnchorRevision::INITIAL);
        assert!(target.publish_observed_fence);
        assert!(target.occupied);
        Ok(())
    }

    #[test]
    fn capture_encode_decode_verify_and_restore_round_trip() -> Result<(), Box<dyn Error>> {
        let store = MemoryStore::new()?;
        let journal = MemoryJournal::new()?;
        let checkpoint = checkpoint(&store, &journal)?;
        let mut anchor = checkpoint_coordinator(checkpoint.clone())?;
        let authenticator = TestAuthenticator::new()?;
        let archive = RecoveryArchive::capture(
            RecoveryArchiveId::new("recovery-0001".to_owned())?,
            &store,
            &journal,
            KeyEpoch::INITIAL,
            checkpoint,
            &authenticator,
        )?;
        let encoded = archive.encode()?;
        let decoded = RecoveryArchive::decode(&encoded)?;
        let mut target = MemoryTarget::default();
        let receipt = RecoveryRestorer::restore(&mut target, decoded, &authenticator, &mut anchor)?;
        assert_eq!(receipt.observation.generation(), Generation::INITIAL);
        assert_eq!(target.restored_state, b"sealed-state");
        Ok(())
    }

    #[test]
    fn tamper_trailing_bytes_and_non_empty_target_fail_closed() -> Result<(), Box<dyn Error>> {
        let store = MemoryStore::new()?;
        let journal = MemoryJournal::new()?;
        let authenticator = TestAuthenticator::new()?;
        let archive = RecoveryArchive::capture(
            RecoveryArchiveId::new("recovery-0002".to_owned())?,
            &store,
            &journal,
            KeyEpoch::INITIAL,
            checkpoint(&store, &journal)?,
            &authenticator,
        )?;
        let mut encoded = archive.encode()?;
        encoded.push(0);
        assert_eq!(
            RecoveryArchive::decode(&encoded),
            Err(RecoveryContractError::TrailingArchiveBytes)
        );

        let checkpoint = checkpoint(&store, &journal)?;
        let mut anchor = checkpoint_coordinator(checkpoint.clone())?;
        let archive = RecoveryArchive::capture(
            RecoveryArchiveId::new("recovery-0003".to_owned())?,
            &store,
            &journal,
            KeyEpoch::INITIAL,
            checkpoint,
            &authenticator,
        )?;
        let mut target = MemoryTarget::default();
        target.occupied = true;
        assert!(matches!(
            RecoveryRestorer::restore(&mut target, archive, &authenticator, &mut anchor,),
            Err(RecoveryRestoreError::Contract(
                RecoveryContractError::TargetNotEmpty
            ))
        ));
        Ok(())
    }

    #[test]
    fn restore_requires_the_exact_externally_verified_checkpoint() -> Result<(), Box<dyn Error>> {
        let store = MemoryStore::new()?;
        let journal = MemoryJournal::new()?;
        let checkpoint = checkpoint(&store, &journal)?;
        let authenticator = TestAuthenticator::new()?;
        let archive = RecoveryArchive::capture(
            RecoveryArchiveId::new("recovery-anchored-0001".to_owned())?,
            &store,
            &journal,
            KeyEpoch::INITIAL,
            checkpoint,
            &authenticator,
        )?;
        let other_observation = CheckpointObservation::new(
            store.domain.clone(),
            store.generation,
            StateDigest::new([4; 32])?,
            journal.domain.clone(),
            journal.tail(),
            KeyEpoch::INITIAL,
        );
        let other_checkpoint = RecoveryCheckpoint::from_parts(
            AnchorRevision::INITIAL,
            None,
            AnchorAuthenticatorId::new("heptabao/test-anchor".to_owned())?,
            other_observation,
            CheckpointDigest::new([7; 32])?,
        )?;
        let mut anchor = checkpoint_coordinator(other_checkpoint)?;
        let mut target = MemoryTarget::default();
        assert!(matches!(
            RecoveryRestorer::restore(&mut target, archive, &authenticator, &mut anchor,),
            Err(RecoveryRestoreError::Contract(
                RecoveryContractError::CheckpointNotAnchored
            ))
        ));
        assert!(!target.occupied);
        Ok(())
    }

    #[test]
    fn archive_authenticator_identity_is_bound() -> Result<(), Box<dyn Error>> {
        let store = MemoryStore::new()?;
        let journal = MemoryJournal::new()?;
        let authenticator = TestAuthenticator::new()?;
        let archive = RecoveryArchive::capture(
            RecoveryArchiveId::new("recovery-authenticator-0001".to_owned())?,
            &store,
            &journal,
            KeyEpoch::INITIAL,
            checkpoint(&store, &journal)?,
            &authenticator,
        )?;
        let wrong_authenticator = TestAuthenticator {
            id: RecoveryAuthenticatorId::new("heptabao/other-recovery".to_owned())?,
        };
        assert!(matches!(
            archive.verify(&wrong_authenticator),
            Err(RecoveryVerificationError::Contract(
                RecoveryContractError::AuthenticatorMismatch
            ))
        ));
        Ok(())
    }

    #[test]
    fn unknown_target_publication_remains_explicit() -> Result<(), Box<dyn Error>> {
        let store = MemoryStore::new()?;
        let journal = MemoryJournal::new()?;
        let authenticator = TestAuthenticator::new()?;
        let checkpoint = checkpoint(&store, &journal)?;
        let mut anchor = checkpoint_coordinator(checkpoint.clone())?;
        let archive = RecoveryArchive::capture(
            RecoveryArchiveId::new("recovery-0004".to_owned())?,
            &store,
            &journal,
            KeyEpoch::INITIAL,
            checkpoint,
            &authenticator,
        )?;
        let mut target = MemoryTarget::default();
        target.outcome_unknown = true;
        assert!(matches!(
            RecoveryRestorer::restore(&mut target, archive, &authenticator, &mut anchor,),
            Err(RecoveryRestoreError::PublishOutcomeUnknown(
                TestError::Target
            ))
        ));
        Ok(())
    }
    #[test]
    fn post_entry_anchor_fence_failure_is_outcome_unknown() -> Result<(), Box<dyn Error>> {
        let store = MemoryStore::new()?;
        let journal = MemoryJournal::new()?;
        let authenticator = TestAuthenticator::new()?;
        let checkpoint = checkpoint(&store, &journal)?;
        let archive = RecoveryArchive::capture(
            RecoveryArchiveId::new("recovery-post-entry-anchor-failure-0001".to_owned())?,
            &store,
            &journal,
            KeyEpoch::INITIAL,
            checkpoint.clone(),
            &authenticator,
        )?;
        let mut anchor = AnchorCoordinator::new(
            PostEntryFenceFailureAnchor {
                current: checkpoint,
            },
            TestCheckpointAuthenticator::new()?,
        );
        let mut target = MemoryTarget::default();
        assert!(matches!(
            RecoveryRestorer::restore(&mut target, archive, &authenticator, &mut anchor),
            Err(RecoveryRestoreError::AnchorFenceOutcomeUnknown(
                TestError::Target
            ))
        ));
        assert!(target.occupied);
        assert_eq!(target.restored_state, b"sealed-state");
        Ok(())
    }

    #[test]
    fn stale_checkpoint_cannot_authorize_restore() -> Result<(), Box<dyn Error>> {
        let store = MemoryStore::new()?;
        let journal = MemoryJournal::new()?;
        let authenticator = TestAuthenticator::new()?;
        let stale = checkpoint(&store, &journal)?;
        let archive = RecoveryArchive::capture(
            RecoveryArchiveId::new("recovery-stale-anchor-0001".to_owned())?,
            &store,
            &journal,
            KeyEpoch::INITIAL,
            stale.clone(),
            &authenticator,
        )?;
        let current_observation = CheckpointObservation::new(
            store.domain.clone(),
            Generation::new(2)?,
            StateDigest::new([4; 32])?,
            journal.domain.clone(),
            journal.tail(),
            KeyEpoch::new(2)?,
        );
        let current = RecoveryCheckpoint::from_parts(
            AnchorRevision::new(2)?,
            Some(stale.digest()),
            AnchorAuthenticatorId::new("heptabao/test-anchor".to_owned())?,
            current_observation,
            CheckpointDigest::new([7; 32])?,
        )?;
        let mut anchor = checkpoint_coordinator(current)?;
        let mut target = MemoryTarget::default();
        assert!(matches!(
            RecoveryRestorer::restore(&mut target, archive, &authenticator, &mut anchor),
            Err(RecoveryRestoreError::Contract(
                RecoveryContractError::CheckpointNotAnchored
            ))
        ));
        assert!(!target.occupied);
        Ok(())
    }

    #[test]
    fn wrong_receipt_after_publication_is_outcome_unknown() -> Result<(), Box<dyn Error>> {
        let store = MemoryStore::new()?;
        let journal = MemoryJournal::new()?;
        let authenticator = TestAuthenticator::new()?;
        let checkpoint = checkpoint(&store, &journal)?;
        let mut anchor = checkpoint_coordinator(checkpoint.clone())?;
        let archive = RecoveryArchive::capture(
            RecoveryArchiveId::new("recovery-wrong-receipt-0001".to_owned())?,
            &store,
            &journal,
            KeyEpoch::INITIAL,
            checkpoint,
            &authenticator,
        )?;
        let mut target = MemoryTarget::default();
        target.wrong_receipt = true;
        assert!(matches!(
            RecoveryRestorer::restore(&mut target, archive, &authenticator, &mut anchor),
            Err(RecoveryRestoreError::PublishReceiptMismatchOutcomeUnknown { .. })
        ));
        assert!(target.occupied);
        Ok(())
    }
}
