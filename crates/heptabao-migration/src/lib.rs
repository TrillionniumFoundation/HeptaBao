#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Migration writer-authority state machine that prohibits source/target overlap.

use std::error::Error;
use std::fmt;

use heptabao_domain::Id;

mod durable;
pub use durable::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationPhase {
    Planned,
    SourceFenced,
    Copying,
    CutoverReady,
    TargetActive,
    TargetFenced,
    RolledBack,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationState {
    pub migration_id: Id,
    pub source_id: Id,
    pub target_id: Id,
    pub phase: MigrationPhase,
    pub source_writer: bool,
    pub target_writer: bool,
    pub generation: u64,
}

impl MigrationState {
    pub fn new(migration_id: Id, source_id: Id, target_id: Id) -> Result<Self, MigrationError> {
        if source_id == target_id {
            return Err(MigrationError::SameEndpoint);
        }
        Ok(Self {
            migration_id,
            source_id,
            target_id,
            phase: MigrationPhase::Planned,
            source_writer: true,
            target_writer: false,
            generation: 1,
        })
    }

    pub fn fence_source(&mut self) -> Result<(), MigrationError> {
        self.require_phase(MigrationPhase::Planned)?;
        self.source_writer = false;
        self.phase = MigrationPhase::SourceFenced;
        self.advance();
        Ok(())
    }

    pub fn begin_copy(&mut self) -> Result<(), MigrationError> {
        self.require_phase(MigrationPhase::SourceFenced)?;
        self.phase = MigrationPhase::Copying;
        self.advance();
        Ok(())
    }

    pub fn verify_copy(&mut self) -> Result<(), MigrationError> {
        self.require_phase(MigrationPhase::Copying)?;
        self.phase = MigrationPhase::CutoverReady;
        self.advance();
        Ok(())
    }

    pub fn activate_target(&mut self) -> Result<(), MigrationError> {
        self.require_phase(MigrationPhase::CutoverReady)?;
        if self.source_writer {
            return Err(MigrationError::WriterOverlap);
        }
        self.target_writer = true;
        self.phase = MigrationPhase::TargetActive;
        self.advance();
        self.validate_no_overlap()
    }

    pub fn fence_target(&mut self) -> Result<(), MigrationError> {
        self.require_phase(MigrationPhase::TargetActive)?;
        self.target_writer = false;
        self.phase = MigrationPhase::TargetFenced;
        self.advance();
        Ok(())
    }

    pub fn rollback(&mut self) -> Result<(), MigrationError> {
        if !matches!(
            self.phase,
            MigrationPhase::SourceFenced
                | MigrationPhase::Copying
                | MigrationPhase::CutoverReady
                | MigrationPhase::TargetFenced
        ) {
            return Err(MigrationError::InvalidTransition);
        }
        if self.target_writer {
            return Err(MigrationError::WriterOverlap);
        }
        self.source_writer = true;
        self.phase = MigrationPhase::RolledBack;
        self.advance();
        self.validate_no_overlap()
    }

    pub fn fail(&mut self) {
        self.source_writer = false;
        self.target_writer = false;
        self.phase = MigrationPhase::Failed;
        self.advance();
    }

    pub fn validate_no_overlap(&self) -> Result<(), MigrationError> {
        if self.source_writer && self.target_writer {
            return Err(MigrationError::WriterOverlap);
        }
        Ok(())
    }

    fn require_phase(&self, expected: MigrationPhase) -> Result<(), MigrationError> {
        if self.phase != expected {
            return Err(MigrationError::InvalidTransition);
        }
        Ok(())
    }

    fn advance(&mut self) {
        self.generation = self.generation.saturating_add(1);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationError {
    SameEndpoint,
    InvalidTransition,
    WriterOverlap,
}

impl fmt::Display for MigrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SameEndpoint => "migration source and target are identical",
            Self::InvalidTransition => "migration transition is invalid",
            Self::WriterOverlap => "source and target writer authority overlap",
        })
    }
}

impl Error for MigrationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cutover_never_enables_both_writers() -> Result<(), Box<dyn Error>> {
        let mut state = MigrationState::new(
            Id::parse("migration_one")?,
            Id::parse("source")?,
            Id::parse("target")?,
        )?;
        state.fence_source()?;
        state.begin_copy()?;
        state.verify_copy()?;
        state.activate_target()?;
        assert!(!state.source_writer);
        assert!(state.target_writer);
        state.validate_no_overlap()?;
        Ok(())
    }

    #[test]
    fn rollback_requires_target_fencing_after_cutover() -> Result<(), Box<dyn Error>> {
        let mut state = MigrationState::new(
            Id::parse("migration_two")?,
            Id::parse("source")?,
            Id::parse("target")?,
        )?;
        state.fence_source()?;
        state.begin_copy()?;
        state.verify_copy()?;
        state.activate_target()?;
        assert_eq!(Err(MigrationError::InvalidTransition), state.rollback());
        state.fence_target()?;
        state.rollback()?;
        assert!(state.source_writer);
        assert!(!state.target_writer);
        Ok(())
    }
}
