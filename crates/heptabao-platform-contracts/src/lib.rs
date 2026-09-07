#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Provider-neutral H02 contracts.
//!
//! This crate deliberately contains no Tokio, rustls, OpenSSL, OpenRaft,
//! raft-rs, database, gRPC or cryptographic-provider dependency. Candidate
//! adapters must conform to these contracts before a bounded prototype
//! selection can be considered. Validation always has `AuthorityEffect::None`.

use std::future::Future;
use std::pin::Pin;

/// The only authority effect available to H02 contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityEffect {
    None,
}

/// Maturity of dependency source-integrity evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceMaturity {
    RegistryMetadataOnly,
    ByteVerifiedOnce,
    IndependentlyReproduced,
}

/// A non-zero 32-byte digest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    pub fn new(bytes: [u8; 32]) -> Result<Self, ContractError> {
        if bytes == [0; 32] {
            return Err(ContractError::ZeroDigest);
        }
        Ok(Self(bytes))
    }

    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

/// A non-zero 20-byte Git object ID.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ObjectId20([u8; 20]);

impl ObjectId20 {
    pub fn new(bytes: [u8; 20]) -> Result<Self, ContractError> {
        if bytes == [0; 20] {
            return Err(ContractError::ZeroObjectId);
        }
        Ok(Self(bytes))
    }

    pub const fn bytes(self) -> [u8; 20] {
        self.0
    }
}

/// Exact source and registry binding for one candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactBinding<'a> {
    pub candidate_id: &'a str,
    pub package: &'a str,
    pub version: &'a str,
    pub release_commit: ObjectId20,
    pub release_tree: ObjectId20,
    pub registry_index_blob: ObjectId20,
    pub registry_checksum: Digest32,
    pub downloaded_package_checksum: Option<Digest32>,
    pub package_vcs_commit: Option<ObjectId20>,
    pub source_archive_observation: Option<Digest32>,
    pub independent_reproduction_count: u8,
}

/// Validated artifact evidence. It never grants selection or runtime authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedArtifact {
    pub maturity: EvidenceMaturity,
    pub authority_effect: AuthorityEffect,
}

/// Validate source integrity while keeping selection fail closed.
pub fn validate_artifact_binding(
    binding: ArtifactBinding<'_>,
) -> Result<ValidatedArtifact, ContractError> {
    if binding.candidate_id.is_empty() {
        return Err(ContractError::EmptyCandidateId);
    }
    if binding.package.is_empty() || binding.version.is_empty() {
        return Err(ContractError::EmptyPackageIdentity);
    }

    match binding.downloaded_package_checksum {
        None => {
            if binding.package_vcs_commit.is_some()
                || binding.source_archive_observation.is_some()
                || binding.independent_reproduction_count != 0
            {
                return Err(ContractError::InconsistentByteEvidence);
            }
            Ok(ValidatedArtifact {
                maturity: EvidenceMaturity::RegistryMetadataOnly,
                authority_effect: AuthorityEffect::None,
            })
        }
        Some(downloaded) => {
            if downloaded != binding.registry_checksum {
                return Err(ContractError::RegistryChecksumMismatch);
            }
            if binding.package_vcs_commit != Some(binding.release_commit) {
                return Err(ContractError::PackageVcsCommitMismatch);
            }
            if binding.source_archive_observation.is_none() {
                return Err(ContractError::SourceArchiveObservationMissing);
            }
            let maturity = if binding.independent_reproduction_count >= 2 {
                EvidenceMaturity::IndependentlyReproduced
            } else {
                EvidenceMaturity::ByteVerifiedOnce
            };
            Ok(ValidatedArtifact {
                maturity,
                authority_effect: AuthorityEffect::None,
            })
        }
    }
}

/// A monotonic instant in nanoseconds from a provider-defined epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicInstant(pub u64);

/// A non-zero task identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TaskId(u64);

impl TaskId {
    pub const fn new(value: u64) -> Result<Self, ContractError> {
        if value == 0 {
            return Err(ContractError::ZeroTaskId);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Runtime task class used for capacity and cancellation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskClass {
    AuthorityCritical,
    BackgroundReconcile,
    BoundedBlocking,
    TestOnly,
}

/// Provider-neutral task specification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskSpec {
    pub id: TaskId,
    pub class: TaskClass,
    pub deadline: MonotonicInstant,
    pub cancellation_required: bool,
}

impl TaskSpec {
    pub fn validate(self, now: MonotonicInstant) -> Result<(), ContractError> {
        if self.deadline <= now {
            return Err(ContractError::ExpiredDeadline);
        }
        if matches!(
            self.class,
            TaskClass::AuthorityCritical | TaskClass::BackgroundReconcile
        ) && !self.cancellation_required
        {
            return Err(ContractError::CancellationRequired);
        }
        Ok(())
    }
}

/// Boxed provider-neutral task future.
pub type BoxTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Provider-neutral runtime adapter.
pub trait RuntimeAdapter: Send + Sync {
    type JoinHandle: Send + 'static;

    fn now(&self) -> MonotonicInstant;
    fn spawn(&self, spec: TaskSpec, task: BoxTask) -> Result<Self::JoinHandle, RuntimeError>;
    fn cancel(&self, id: TaskId) -> Result<(), RuntimeError>;
    fn join(
        &self,
        handle: Self::JoinHandle,
        deadline: MonotonicInstant,
    ) -> Result<(), RuntimeError>;
}

/// Runtime adapter errors must remain provider-neutral.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    Rejected,
    CapacityExceeded,
    Cancelled,
    DeadlineExceeded,
    TaskPanicked,
    ProviderFailure,
}

/// TLS versions supported by an exact profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl TlsVersion {
    const fn rank(self) -> u8 {
        match self {
            Self::Tls12 => 12,
            Self::Tls13 => 13,
        }
    }
}

/// Client-authentication policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAuthMode {
    Disabled,
    Optional,
    Required,
}

/// Provider-neutral TLS policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsProfile {
    pub minimum: TlsVersion,
    pub maximum: TlsVersion,
    pub client_auth: ClientAuthMode,
    pub handshake_timeout_ms: u64,
    pub max_handshake_bytes: u32,
    pub max_certificate_chain_bytes: u32,
    pub stateless_tickets: bool,
    pub ticket_key_rotation_ms: Option<u64>,
}

impl TlsProfile {
    pub const fn validate(self) -> Result<(), ContractError> {
        if self.minimum.rank() > self.maximum.rank() {
            return Err(ContractError::InvalidTlsVersionRange);
        }
        if self.handshake_timeout_ms == 0
            || self.max_handshake_bytes == 0
            || self.max_certificate_chain_bytes == 0
        {
            return Err(ContractError::UnboundedTlsProfile);
        }
        if self.stateless_tickets {
            match self.ticket_key_rotation_ms {
                Some(value) if value >= 60_000 => {}
                _ => return Err(ContractError::UnsafeTicketPolicy),
            }
        } else if self.ticket_key_rotation_ms.is_some() {
            return Err(ContractError::InconsistentTicketPolicy);
        }
        Ok(())
    }
}

/// Opaque TLS configuration identity. It contains no private key material.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TlsConfigId(pub Digest32);

/// Opaque key handle. It contains no raw private key material.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PrivateKeyHandle(pub Digest32);

/// Provider-neutral staged TLS configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagedTlsConfig {
    pub config_id: TlsConfigId,
    pub key_handle: PrivateKeyHandle,
    pub policy: TlsProfile,
}

/// Provider-neutral TLS adapter with atomic activation and revocation.
pub trait TlsProvider: Send + Sync {
    fn stage(&self, config: StagedTlsConfig) -> Result<(), TlsError>;
    fn activate(&self, config_id: TlsConfigId) -> Result<(), TlsError>;
    fn revoke(&self, config_id: TlsConfigId) -> Result<(), TlsError>;
}

/// TLS adapter errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsError {
    InvalidPolicy,
    InvalidCertificate,
    InvalidPrivateKeyHandle,
    ProviderUnavailable,
    ActivationConflict,
    RevocationFailed,
}

/// A Raft term/index position.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LogPosition {
    pub term: u64,
    pub index: u64,
}

impl LogPosition {
    pub const fn validate(self) -> Result<(), ContractError> {
        if self.term == 0 || self.index == 0 {
            return Err(ContractError::ZeroRaftPosition);
        }
        Ok(())
    }
}

/// Last deterministically applied position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyCursor {
    pub last_applied: Option<LogPosition>,
}

impl ApplyCursor {
    pub const fn validate_next(self, next: LogPosition) -> Result<Self, ContractError> {
        match next.validate() {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        match self.last_applied {
            None => {
                if next.index != 1 {
                    return Err(ContractError::NonContiguousApply);
                }
            }
            Some(previous) => {
                if next.term < previous.term {
                    return Err(ContractError::RaftTermRegression);
                }
                let expected_index = match previous.index.checked_add(1) {
                    Some(value) => value,
                    None => return Err(ContractError::RaftIndexOverflow),
                };
                if next.index != expected_index {
                    return Err(ContractError::NonContiguousApply);
                }
            }
        }
        Ok(Self {
            last_applied: Some(next),
        })
    }
}

/// Snapshot metadata owned by HeptaBao, not by a candidate library.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotMeta {
    pub last_included: LogPosition,
    pub membership_epoch: u64,
    pub state_digest: Digest32,
    pub byte_length: u64,
}

impl SnapshotMeta {
    pub const fn validate(self, cursor: ApplyCursor) -> Result<(), ContractError> {
        match self.last_included.validate() {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        if self.membership_epoch == 0 || self.byte_length == 0 {
            return Err(ContractError::InvalidSnapshotMetadata);
        }
        if let Some(applied) = cursor.last_applied
            && self.last_included.index < applied.index
        {
            return Err(ContractError::SnapshotRegression);
        }
        Ok(())
    }
}

/// Provider-neutral deterministic state-machine boundary.
pub trait StateMachineAdapter {
    type ApplyOutput;

    fn apply(
        &mut self,
        position: LogPosition,
        command_digest: Digest32,
        command: &[u8],
    ) -> Result<Self::ApplyOutput, RaftError>;

    fn install_snapshot(&mut self, metadata: SnapshotMeta, bytes: &[u8]) -> Result<(), RaftError>;
}

/// Provider-neutral consensus/storage boundary.
pub trait ConsensusAdapter: Send + Sync {
    fn append(&self, position: LogPosition, entry_digest: Digest32) -> Result<(), RaftError>;
    fn committed(&self) -> Result<Option<LogPosition>, RaftError>;
    fn install_snapshot(&self, metadata: SnapshotMeta, bytes: &[u8]) -> Result<(), RaftError>;
}

/// Raft adapter errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RaftError {
    Rejected,
    NotLeader,
    QuorumUnavailable,
    StorageFailure,
    SnapshotConflict,
    MembershipConflict,
    ProviderFailure,
}

/// Fail-closed contract errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractError {
    ZeroDigest,
    ZeroObjectId,
    EmptyCandidateId,
    EmptyPackageIdentity,
    InconsistentByteEvidence,
    RegistryChecksumMismatch,
    PackageVcsCommitMismatch,
    SourceArchiveObservationMissing,
    ZeroTaskId,
    ExpiredDeadline,
    CancellationRequired,
    InvalidTlsVersionRange,
    UnboundedTlsProfile,
    UnsafeTicketPolicy,
    InconsistentTicketPolicy,
    ZeroRaftPosition,
    NonContiguousApply,
    RaftTermRegression,
    RaftIndexOverflow,
    InvalidSnapshotMetadata,
    SnapshotRegression,
}

#[cfg(test)]
mod tests {
    use super::{
        ApplyCursor, ArtifactBinding, AuthorityEffect, ClientAuthMode, ContractError, Digest32,
        EvidenceMaturity, LogPosition, MonotonicInstant, ObjectId20, SnapshotMeta, TaskClass,
        TaskId, TaskSpec, TlsProfile, TlsVersion, validate_artifact_binding,
    };

    fn digest(value: u8) -> Digest32 {
        Digest32([value; 32])
    }

    fn object(value: u8) -> ObjectId20 {
        ObjectId20([value; 20])
    }

    #[test]
    fn registry_metadata_has_no_authority() {
        let binding = ArtifactBinding {
            candidate_id: "HB-DEP-ASYNC-TOKIO",
            package: "tokio",
            version: "1.53.1",
            release_commit: object(1),
            release_tree: object(2),
            registry_index_blob: object(3),
            registry_checksum: digest(4),
            downloaded_package_checksum: None,
            package_vcs_commit: None,
            source_archive_observation: None,
            independent_reproduction_count: 0,
        };
        assert_eq!(
            validate_artifact_binding(binding),
            Ok(super::ValidatedArtifact {
                maturity: EvidenceMaturity::RegistryMetadataOnly,
                authority_effect: AuthorityEffect::None,
            })
        );
    }

    #[test]
    fn registry_checksum_mismatch_is_rejected() {
        let binding = ArtifactBinding {
            candidate_id: "HB-DEP-TLS-RUSTLS",
            package: "rustls",
            version: "0.23.43",
            release_commit: object(1),
            release_tree: object(2),
            registry_index_blob: object(3),
            registry_checksum: digest(4),
            downloaded_package_checksum: Some(digest(5)),
            package_vcs_commit: Some(object(1)),
            source_archive_observation: Some(digest(6)),
            independent_reproduction_count: 1,
        };
        assert_eq!(
            validate_artifact_binding(binding),
            Err(ContractError::RegistryChecksumMismatch)
        );
    }

    #[test]
    fn independent_reproduction_still_has_no_authority() {
        let checksum = digest(4);
        let binding = ArtifactBinding {
            candidate_id: "HB-DEP-RAFT-OPENRAFT",
            package: "openraft",
            version: "0.10.0-alpha.33",
            release_commit: object(1),
            release_tree: object(2),
            registry_index_blob: object(3),
            registry_checksum: checksum,
            downloaded_package_checksum: Some(checksum),
            package_vcs_commit: Some(object(1)),
            source_archive_observation: Some(digest(6)),
            independent_reproduction_count: 2,
        };
        assert_eq!(
            validate_artifact_binding(binding),
            Ok(super::ValidatedArtifact {
                maturity: EvidenceMaturity::IndependentlyReproduced,
                authority_effect: AuthorityEffect::None,
            })
        );
    }

    #[test]
    fn critical_task_requires_cancellation_and_future_deadline() {
        let id = TaskId(7);
        let invalid = TaskSpec {
            id,
            class: TaskClass::AuthorityCritical,
            deadline: MonotonicInstant(100),
            cancellation_required: false,
        };
        assert_eq!(
            invalid.validate(MonotonicInstant(10)),
            Err(ContractError::CancellationRequired)
        );
        let expired = TaskSpec {
            cancellation_required: true,
            deadline: MonotonicInstant(10),
            ..invalid
        };
        assert_eq!(
            expired.validate(MonotonicInstant(10)),
            Err(ContractError::ExpiredDeadline)
        );
    }

    #[test]
    fn unsafe_ticket_policy_is_rejected() {
        let profile = TlsProfile {
            minimum: TlsVersion::Tls12,
            maximum: TlsVersion::Tls13,
            client_auth: ClientAuthMode::Required,
            handshake_timeout_ms: 5_000,
            max_handshake_bytes: 64 * 1024,
            max_certificate_chain_bytes: 256 * 1024,
            stateless_tickets: true,
            ticket_key_rotation_ms: None,
        };
        assert_eq!(profile.validate(), Err(ContractError::UnsafeTicketPolicy));
    }

    #[test]
    fn raft_apply_is_contiguous_and_term_monotonic() {
        let cursor = ApplyCursor { last_applied: None };
        let first = ApplyCursor {
            last_applied: Some(LogPosition { term: 1, index: 1 }),
        };
        assert_eq!(
            cursor.validate_next(LogPosition { term: 1, index: 1 }),
            Ok(first)
        );
        assert_eq!(
            first.validate_next(LogPosition { term: 1, index: 3 }),
            Err(ContractError::NonContiguousApply)
        );
        assert_eq!(
            first.validate_next(LogPosition { term: 0, index: 2 }),
            Err(ContractError::ZeroRaftPosition)
        );
    }

    #[test]
    fn snapshot_cannot_regress_applied_state() {
        let cursor = ApplyCursor {
            last_applied: Some(LogPosition { term: 2, index: 10 }),
        };
        let snapshot = SnapshotMeta {
            last_included: LogPosition { term: 2, index: 9 },
            membership_epoch: 1,
            state_digest: digest(8),
            byte_length: 128,
        };
        assert_eq!(
            snapshot.validate(cursor),
            Err(ContractError::SnapshotRegression)
        );
    }
}
