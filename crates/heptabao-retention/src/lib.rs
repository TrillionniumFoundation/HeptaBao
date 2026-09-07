#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Retention planning and backup lifecycle contracts.

use std::error::Error;
use std::fmt;

use heptabao_domain::Tick;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionPolicy {
    pub max_secret_versions: usize,
    pub max_audit_events: usize,
    pub backup_interval_ticks: u64,
    pub restore_drill_interval_ticks: u64,
}

impl RetentionPolicy {
    pub fn validate(&self) -> Result<(), RetentionError> {
        if self.max_secret_versions == 0
            || self.max_audit_events == 0
            || self.backup_interval_ticks == 0
            || self.restore_drill_interval_ticks == 0
        {
            return Err(RetentionError::InvalidPolicy);
        }
        if self.restore_drill_interval_ticks < self.backup_interval_ticks {
            return Err(RetentionError::InvalidPolicy);
        }
        Ok(())
    }

    pub fn versions_to_prune(&self, current_versions: usize) -> usize {
        current_versions.saturating_sub(self.max_secret_versions)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupState {
    Idle,
    Snapshotting,
    Sealed,
    Verified,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupReceipt {
    pub source_generation: u64,
    pub started_at: Tick,
    pub digest: [u8; 32],
}

#[derive(Debug)]
pub struct BackupCoordinator {
    state: BackupState,
    generation: u64,
    in_progress_generation: Option<u64>,
    started_at: Option<Tick>,
    receipt: Option<BackupReceipt>,
}

impl Default for BackupCoordinator {
    fn default() -> Self {
        Self {
            state: BackupState::Idle,
            generation: 0,
            in_progress_generation: None,
            started_at: None,
            receipt: None,
        }
    }
}

impl BackupCoordinator {
    pub fn state(&self) -> BackupState {
        self.state
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn begin(&mut self, source_generation: u64, now: Tick) -> Result<(), RetentionError> {
        if !matches!(
            self.state,
            BackupState::Idle | BackupState::Verified | BackupState::Failed
        ) {
            return Err(RetentionError::InvalidTransition);
        }
        self.state = BackupState::Snapshotting;
        self.in_progress_generation = Some(source_generation);
        self.started_at = Some(now);
        self.receipt = None;
        Ok(())
    }

    pub fn seal(&mut self, digest: [u8; 32]) -> Result<BackupReceipt, RetentionError> {
        if self.state != BackupState::Snapshotting {
            return Err(RetentionError::InvalidTransition);
        }
        if digest == [0; 32] {
            return Err(RetentionError::InvalidDigest);
        }
        let source_generation = self
            .in_progress_generation
            .ok_or(RetentionError::InvalidTransition)?;
        let started_at = self.started_at.ok_or(RetentionError::InvalidTransition)?;
        let receipt = BackupReceipt {
            source_generation,
            started_at,
            digest,
        };
        self.generation = self.generation.saturating_add(1);
        self.state = BackupState::Sealed;
        self.receipt = Some(receipt.clone());
        Ok(receipt)
    }

    pub fn verify(&mut self, digest: [u8; 32]) -> Result<(), RetentionError> {
        if self.state != BackupState::Sealed {
            return Err(RetentionError::InvalidTransition);
        }
        let receipt = self
            .receipt
            .as_ref()
            .ok_or(RetentionError::InvalidTransition)?;
        if receipt.digest != digest {
            self.state = BackupState::Failed;
            return Err(RetentionError::DigestMismatch);
        }
        self.state = BackupState::Verified;
        Ok(())
    }

    pub fn fail(&mut self) -> Result<(), RetentionError> {
        if self.state != BackupState::Snapshotting {
            return Err(RetentionError::InvalidTransition);
        }
        self.state = BackupState::Failed;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionError {
    InvalidPolicy,
    InvalidTransition,
    InvalidDigest,
    DigestMismatch,
}

impl fmt::Display for RetentionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPolicy => "retention policy is invalid",
            Self::InvalidTransition => "backup transition is invalid",
            Self::InvalidDigest => "backup digest is invalid",
            Self::DigestMismatch => "backup digest does not match",
        })
    }
}

impl Error for RetentionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_and_compaction_plan_are_bounded() -> Result<(), RetentionError> {
        let policy = RetentionPolicy {
            max_secret_versions: 3,
            max_audit_events: 1000,
            backup_interval_ticks: 10,
            restore_drill_interval_ticks: 100,
        };
        policy.validate()?;
        assert_eq!(2, policy.versions_to_prune(5));
        Ok(())
    }

    #[test]
    fn backup_must_seal_and_verify_before_completion() -> Result<(), RetentionError> {
        let mut coordinator = BackupCoordinator::default();
        coordinator.begin(7, Tick::new(10))?;
        let receipt = coordinator.seal([9; 32])?;
        assert_eq!(7, receipt.source_generation);
        coordinator.verify([9; 32])?;
        assert_eq!(BackupState::Verified, coordinator.state());
        assert_eq!(1, coordinator.generation());
        assert_eq!(
            Err(RetentionError::InvalidTransition),
            coordinator.verify([9; 32])
        );
        Ok(())
    }
}
