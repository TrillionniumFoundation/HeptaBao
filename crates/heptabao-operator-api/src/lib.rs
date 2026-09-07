#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Operator-visible commit outcome classification and reconciliation records.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use heptabao_domain::Id;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectPhase {
    BeforeEntry,
    Entered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitState {
    NotCommitted,
    Committed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorAction {
    RetryAllowed,
    DoNotRetry,
    AuthoritativeReadback,
    Reconcile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resolution {
    ConfirmedCommitted,
    ConfirmedNotCommitted,
    Compensated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutcomeRecord {
    pub request_id: Id,
    pub phase: EffectPhase,
    pub commit_state: CommitState,
    pub recovery_reference: Option<Id>,
    pub resolution: Option<Resolution>,
}

impl OutcomeRecord {
    pub fn before_entry(request_id: Id) -> Self {
        Self {
            request_id,
            phase: EffectPhase::BeforeEntry,
            commit_state: CommitState::NotCommitted,
            recovery_reference: None,
            resolution: None,
        }
    }

    pub fn committed(request_id: Id) -> Self {
        Self {
            request_id,
            phase: EffectPhase::Entered,
            commit_state: CommitState::Committed,
            recovery_reference: None,
            resolution: None,
        }
    }

    pub fn unknown_after_entry(request_id: Id, recovery_reference: Id) -> Self {
        Self {
            request_id,
            phase: EffectPhase::Entered,
            commit_state: CommitState::Unknown,
            recovery_reference: Some(recovery_reference),
            resolution: None,
        }
    }

    pub fn action(&self) -> OperatorAction {
        match (self.phase, self.commit_state, self.resolution) {
            (_, _, Some(_)) => OperatorAction::DoNotRetry,
            (EffectPhase::BeforeEntry, CommitState::NotCommitted, None) => {
                OperatorAction::RetryAllowed
            }
            (EffectPhase::Entered, CommitState::Unknown, None) => {
                OperatorAction::AuthoritativeReadback
            }
            (EffectPhase::Entered, CommitState::Committed, None) => OperatorAction::DoNotRetry,
            _ => OperatorAction::Reconcile,
        }
    }
}

#[derive(Debug, Default)]
pub struct ReconciliationStore {
    records: BTreeMap<Id, OutcomeRecord>,
}

impl ReconciliationStore {
    pub fn record(&mut self, record: OutcomeRecord) -> Result<(), OperatorError> {
        if self.records.contains_key(&record.request_id) {
            return Err(OperatorError::DuplicateRequest);
        }
        self.records.insert(record.request_id.clone(), record);
        Ok(())
    }

    pub fn get(&self, request_id: &Id) -> Result<&OutcomeRecord, OperatorError> {
        self.records
            .get(request_id)
            .ok_or(OperatorError::MissingRecord)
    }

    pub fn resolve(
        &mut self,
        request_id: &Id,
        resolution: Resolution,
    ) -> Result<(), OperatorError> {
        let record = self
            .records
            .get_mut(request_id)
            .ok_or(OperatorError::MissingRecord)?;
        if record.resolution.is_some() {
            return Err(OperatorError::AlreadyResolved);
        }
        record.resolution = Some(resolution);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorError {
    DuplicateRequest,
    MissingRecord,
    AlreadyResolved,
}

impl fmt::Display for OperatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateRequest => "reconciliation record already exists",
            Self::MissingRecord => "reconciliation record does not exist",
            Self::AlreadyResolved => "reconciliation record is already resolved",
        })
    }
}

impl Error for OperatorError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_after_entry_forbids_retry_until_readback() -> Result<(), Box<dyn Error>> {
        let request = Id::parse("request_one")?;
        let record = OutcomeRecord::unknown_after_entry(request.clone(), request.clone());
        assert_eq!(OperatorAction::AuthoritativeReadback, record.action());
        let mut store = ReconciliationStore::default();
        store.record(record)?;
        store.resolve(&request, Resolution::ConfirmedCommitted)?;
        assert_eq!(OperatorAction::DoNotRetry, store.get(&request)?.action());
        Ok(())
    }

    #[test]
    fn before_entry_failure_allows_new_attempt() -> Result<(), Box<dyn Error>> {
        let record = OutcomeRecord::before_entry(Id::parse("request_two")?);
        assert_eq!(OperatorAction::RetryAllowed, record.action());
        Ok(())
    }
}
