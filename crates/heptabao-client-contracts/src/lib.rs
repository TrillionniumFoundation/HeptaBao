#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Client retry classification that preserves server commit uncertainty.

use heptabao_domain::Id;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationClass {
    ReadOnly,
    IdempotentMutation,
    NonIdempotentMutation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureClass {
    BeforeEntry,
    DeterministicRejection,
    Committed,
    UnknownAfterEntry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDecision {
    NewRequestAllowed,
    DoNotRetry,
    AuthoritativeReadback,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientAttempt {
    pub request_id: Id,
    pub operation: OperationClass,
    pub attempt: u32,
}

impl ClientAttempt {
    pub fn decision(&self, failure: FailureClass) -> RetryDecision {
        match failure {
            FailureClass::BeforeEntry => RetryDecision::NewRequestAllowed,
            FailureClass::DeterministicRejection | FailureClass::Committed => {
                RetryDecision::DoNotRetry
            }
            FailureClass::UnknownAfterEntry => RetryDecision::AuthoritativeReadback,
        }
    }

    pub fn next_with_new_id(&self, request_id: Id) -> Self {
        Self {
            request_id,
            operation: self.operation,
            attempt: self.attempt.saturating_add(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn unknown_after_entry_never_becomes_automatic_retry() -> Result<(), Box<dyn Error>> {
        let attempt = ClientAttempt {
            request_id: Id::parse("request_one")?,
            operation: OperationClass::NonIdempotentMutation,
            attempt: 1,
        };
        assert_eq!(
            RetryDecision::AuthoritativeReadback,
            attempt.decision(FailureClass::UnknownAfterEntry)
        );
        Ok(())
    }

    #[test]
    fn retry_uses_a_new_request_identifier() -> Result<(), Box<dyn Error>> {
        let attempt = ClientAttempt {
            request_id: Id::parse("request_one")?,
            operation: OperationClass::ReadOnly,
            attempt: 1,
        };
        let next = attempt.next_with_new_id(Id::parse("request_two")?);
        assert_ne!(attempt.request_id, next.request_id);
        assert_eq!(2, next.attempt);
        Ok(())
    }
}
