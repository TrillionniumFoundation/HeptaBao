#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Auto-authentication, renewal, revocation and reconciliation contracts for an agent.

use std::error::Error;
use std::fmt;

use heptabao_domain::{Id, Tick};

const MAX_BACKOFF_EXPONENT: u32 = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialSource {
    StandardInput,
    InheritedFileDescriptor(u32),
    WorkloadIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenSinkKind {
    OwnerOnlyFile,
    InheritedFileDescriptor,
    LocalMemorySocket,
}

#[derive(Clone, Eq, PartialEq)]
pub struct TokenSink {
    kind: TokenSinkKind,
    reference: Id,
}

impl TokenSink {
    pub fn new(kind: TokenSinkKind, reference: Id) -> Self {
        Self { kind, reference }
    }

    pub const fn kind(&self) -> TokenSinkKind {
        self.kind
    }

    pub fn reference(&self) -> &Id {
        &self.reference
    }
}

impl fmt::Debug for TokenSink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenSink")
            .field("kind", &self.kind)
            .field("reference", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AgentConfig {
    pub auth_method: Id,
    pub credential_source: CredentialSource,
    pub token_sink: TokenSink,
    pub initial_backoff_ticks: u64,
    pub maximum_backoff_ticks: u64,
}

impl fmt::Debug for AgentConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentConfig")
            .field("auth_method", &self.auth_method)
            .field("credential_source", &self.credential_source)
            .field("token_sink", &self.token_sink)
            .field("initial_backoff_ticks", &self.initial_backoff_ticks)
            .field("maximum_backoff_ticks", &self.maximum_backoff_ticks)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentState {
    Stopped,
    Authenticating,
    Authenticated,
    Renewing,
    Backoff,
    Revoking,
    FailedClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciledAgentState {
    Stopped,
    Authenticated {
        renewal_deadline: Tick,
        token_generation: u64,
    },
}

#[derive(Eq, PartialEq)]
pub struct AgentSession {
    config: AgentConfig,
    state: AgentState,
    failure_attempts: u32,
    retry_at: Option<Tick>,
    renewal_deadline: Option<Tick>,
    token_generation: u64,
    reconciliation_reference: Option<Id>,
}

impl AgentSession {
    pub fn new(config: AgentConfig) -> Result<Self, AgentError> {
        validate_config(&config)?;
        Ok(Self {
            config,
            state: AgentState::Stopped,
            failure_attempts: 0,
            retry_at: None,
            renewal_deadline: None,
            token_generation: 0,
            reconciliation_reference: None,
        })
    }

    pub const fn state(&self) -> AgentState {
        self.state
    }

    pub const fn retry_at(&self) -> Option<Tick> {
        self.retry_at
    }

    pub const fn renewal_deadline(&self) -> Option<Tick> {
        self.renewal_deadline
    }

    pub const fn token_generation(&self) -> u64 {
        self.token_generation
    }

    pub fn requires_reconciliation(&self) -> bool {
        self.state == AgentState::FailedClosed && self.reconciliation_reference.is_some()
    }

    pub fn start(&mut self) -> Result<(), AgentError> {
        self.require_state(AgentState::Stopped)?;
        self.state = AgentState::Authenticating;
        Ok(())
    }

    pub fn authentication_succeeded(
        &mut self,
        now: Tick,
        ttl_ticks: u64,
    ) -> Result<(), AgentError> {
        self.require_state(AgentState::Authenticating)?;
        self.activate(now, ttl_ticks)
    }

    pub fn authentication_failed_before_entry(&mut self, now: Tick) -> Result<Tick, AgentError> {
        self.require_state(AgentState::Authenticating)?;
        self.failure_attempts = self.failure_attempts.saturating_add(1);
        let exponent = self
            .failure_attempts
            .saturating_sub(1)
            .min(MAX_BACKOFF_EXPONENT);
        let multiplier = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
        let delay = self
            .config
            .initial_backoff_ticks
            .saturating_mul(multiplier)
            .min(self.config.maximum_backoff_ticks);
        let retry_at = now
            .checked_add(delay)
            .map_err(|_| AgentError::TickOverflow)?;
        self.retry_at = Some(retry_at);
        self.state = AgentState::Backoff;
        Ok(retry_at)
    }

    pub fn retry_authentication(&mut self, now: Tick) -> Result<(), AgentError> {
        self.require_state(AgentState::Backoff)?;
        let retry_at = self.retry_at.ok_or(AgentError::InvalidState)?;
        if now < retry_at {
            return Err(AgentError::RetryNotDue);
        }
        self.retry_at = None;
        self.state = AgentState::Authenticating;
        Ok(())
    }

    pub fn begin_renewal(&mut self, now: Tick) -> Result<(), AgentError> {
        self.require_state(AgentState::Authenticated)?;
        let deadline = self.renewal_deadline.ok_or(AgentError::InvalidState)?;
        if now >= deadline {
            self.state = AgentState::FailedClosed;
            return Err(AgentError::SessionExpired);
        }
        self.state = AgentState::Renewing;
        Ok(())
    }

    pub fn renewal_succeeded(&mut self, now: Tick, ttl_ticks: u64) -> Result<(), AgentError> {
        self.require_state(AgentState::Renewing)?;
        self.activate(now, ttl_ticks)
    }

    pub fn begin_revocation(&mut self) -> Result<(), AgentError> {
        self.require_state(AgentState::Authenticated)?;
        self.state = AgentState::Revoking;
        Ok(())
    }

    pub fn revocation_succeeded(&mut self) -> Result<(), AgentError> {
        self.require_state(AgentState::Revoking)?;
        self.state = AgentState::Stopped;
        self.retry_at = None;
        self.renewal_deadline = None;
        Ok(())
    }

    pub fn mark_outcome_unknown_after_entry(
        &mut self,
        reconciliation_reference: Id,
    ) -> Result<(), AgentError> {
        if !matches!(
            self.state,
            AgentState::Authenticating | AgentState::Renewing | AgentState::Revoking
        ) {
            return Err(AgentError::InvalidState);
        }
        self.state = AgentState::FailedClosed;
        self.retry_at = None;
        self.reconciliation_reference = Some(reconciliation_reference);
        Ok(())
    }

    pub fn reconcile(&mut self, state: ReconciledAgentState) -> Result<(), AgentError> {
        self.require_state(AgentState::FailedClosed)?;
        if self.reconciliation_reference.is_none() {
            return Err(AgentError::MissingReconciliationReference);
        }
        match state {
            ReconciledAgentState::Stopped => {
                self.state = AgentState::Stopped;
                self.renewal_deadline = None;
            }
            ReconciledAgentState::Authenticated {
                renewal_deadline,
                token_generation,
            } => {
                if token_generation < self.token_generation {
                    return Err(AgentError::GenerationRegression);
                }
                self.state = AgentState::Authenticated;
                self.renewal_deadline = Some(renewal_deadline);
                self.token_generation = token_generation;
            }
        }
        self.failure_attempts = 0;
        self.reconciliation_reference = None;
        Ok(())
    }

    fn activate(&mut self, now: Tick, ttl_ticks: u64) -> Result<(), AgentError> {
        if ttl_ticks == 0 {
            return Err(AgentError::InvalidTtl);
        }
        let deadline = now
            .checked_add(ttl_ticks)
            .map_err(|_| AgentError::TickOverflow)?;
        self.token_generation = self
            .token_generation
            .checked_add(1)
            .ok_or(AgentError::GenerationOverflow)?;
        self.failure_attempts = 0;
        self.retry_at = None;
        self.renewal_deadline = Some(deadline);
        self.reconciliation_reference = None;
        self.state = AgentState::Authenticated;
        Ok(())
    }

    fn require_state(&self, expected: AgentState) -> Result<(), AgentError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(AgentError::InvalidState)
        }
    }
}

impl fmt::Debug for AgentSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentSession")
            .field("config", &self.config)
            .field("state", &self.state)
            .field("failure_attempts", &self.failure_attempts)
            .field("retry_at", &self.retry_at)
            .field("renewal_deadline", &self.renewal_deadline)
            .field("token_generation", &self.token_generation)
            .field(
                "reconciliation_reference",
                &self.reconciliation_reference.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

fn validate_config(config: &AgentConfig) -> Result<(), AgentError> {
    if config.initial_backoff_ticks == 0
        || config.maximum_backoff_ticks < config.initial_backoff_ticks
    {
        return Err(AgentError::InvalidConfig);
    }
    if let CredentialSource::InheritedFileDescriptor(fd) = config.credential_source
        && fd < 3
    {
        return Err(AgentError::InvalidConfig);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentError {
    InvalidConfig,
    InvalidState,
    InvalidTtl,
    RetryNotDue,
    SessionExpired,
    MissingReconciliationReference,
    GenerationRegression,
    GenerationOverflow,
    TickOverflow,
}

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => "agent configuration is invalid",
            Self::InvalidState => "agent transition is invalid for the current state",
            Self::InvalidTtl => "agent token TTL is invalid",
            Self::RetryNotDue => "agent retry deadline has not been reached",
            Self::SessionExpired => "agent session has expired",
            Self::MissingReconciliationReference => "agent reconciliation reference is missing",
            Self::GenerationRegression => "agent token generation regressed",
            Self::GenerationOverflow => "agent token generation overflowed",
            Self::TickOverflow => "agent monotonic time overflowed",
        })
    }
}

impl Error for AgentError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Result<AgentConfig, Box<dyn Error>> {
        Ok(AgentConfig {
            auth_method: Id::parse("workload_auth")?,
            credential_source: CredentialSource::InheritedFileDescriptor(3),
            token_sink: TokenSink::new(TokenSinkKind::OwnerOnlyFile, Id::parse("token_sink_one")?),
            initial_backoff_ticks: 2,
            maximum_backoff_ticks: 8,
        })
    }

    #[test]
    fn authentication_renewal_and_revocation_are_monotonic() -> Result<(), Box<dyn Error>> {
        let mut session = AgentSession::new(config()?)?;
        session.start()?;
        session.authentication_succeeded(Tick::new(10), 20)?;
        assert_eq!(AgentState::Authenticated, session.state());
        assert_eq!(Some(Tick::new(30)), session.renewal_deadline());
        session.begin_renewal(Tick::new(20))?;
        session.renewal_succeeded(Tick::new(20), 30)?;
        assert_eq!(2, session.token_generation());
        session.begin_revocation()?;
        session.revocation_succeeded()?;
        assert_eq!(AgentState::Stopped, session.state());
        Ok(())
    }

    #[test]
    fn retry_backoff_is_bounded_and_deadline_checked() -> Result<(), Box<dyn Error>> {
        let mut session = AgentSession::new(config()?)?;
        for expected in [2_u64, 4, 8, 8] {
            if session.state() == AgentState::Stopped {
                session.start()?;
            }
            let retry_at = session.authentication_failed_before_entry(Tick::new(100))?;
            assert_eq!(Tick::new(100 + expected), retry_at);
            assert_eq!(
                Err(AgentError::RetryNotDue),
                session.retry_authentication(Tick::new(100))
            );
            session.retry_authentication(retry_at)?;
        }
        Ok(())
    }

    #[test]
    fn unknown_after_entry_blocks_blind_retry_until_reconciled() -> Result<(), Box<dyn Error>> {
        let mut session = AgentSession::new(config()?)?;
        session.start()?;
        session.mark_outcome_unknown_after_entry(Id::parse("reconcile_one")?)?;
        assert!(session.requires_reconciliation());
        assert_eq!(Err(AgentError::InvalidState), session.start());
        session.reconcile(ReconciledAgentState::Authenticated {
            renewal_deadline: Tick::new(50),
            token_generation: 1,
        })?;
        assert_eq!(AgentState::Authenticated, session.state());
        Ok(())
    }

    #[test]
    fn debug_output_redacts_sink_and_reconciliation_references() -> Result<(), Box<dyn Error>> {
        let mut session = AgentSession::new(config()?)?;
        session.start()?;
        session.mark_outcome_unknown_after_entry(Id::parse("reconcile_secret")?)?;
        let rendered = format!("{session:?}");
        assert!(!rendered.contains("token_sink_one"));
        assert!(!rendered.contains("reconcile_secret"));
        assert!(rendered.contains("[REDACTED]"));
        Ok(())
    }
}
