#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Durable request and effect reconciliation state machine for HeptaBao.
//!
//! Every operation transition is encoded as one strict journal payload. The
//! ledger reconstructs current operation state only by replaying an already
//! authenticated [`DurableJournal`]. It never grants authorization or retries
//! a mutation automatically.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use heptabao_journal_api::{
    AppendFailureDisposition, AppendReceipt, DurableJournal, JournalPayload,
};
use heptabao_storage_api::{Generation, StateDigest};

const EVENT_MAGIC: &[u8] = b"HEPTABAO-OPERATION-EVENT-V2\0";
const EVENT_VERSION: u16 = 2;
pub const MAX_OPERATION_ID_BYTES: usize = 128;
pub const MAX_DETAIL_CODE_BYTES: usize = 128;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationId(String);

impl OperationId {
    pub fn new(value: String) -> Result<Self, OperationContractError> {
        if value.len() < 8
            || value.len() > MAX_OPERATION_ID_BYTES
            || !value.is_ascii()
            || !value.bytes().all(|byte| {
                matches!(
                    byte,
                    b'a'..=b'z'
                        | b'A'..=b'Z'
                        | b'0'..=b'9'
                        | b'-'
                        | b'_'
                        | b'.'
                        | b':'
                )
            })
        {
            return Err(OperationContractError::InvalidOperationId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperationId([OPAQUE])")
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct StableDetailCode(String);

impl StableDetailCode {
    pub fn new(value: String) -> Result<Self, OperationContractError> {
        if value.is_empty()
            || value.len() > MAX_DETAIL_CODE_BYTES
            || !value.is_ascii()
            || !value
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
        {
            return Err(OperationContractError::InvalidDetailCode);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for StableDetailCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("StableDetailCode")
            .field(&self.0)
            .finish()
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct OperationDigest([u8; 32]);

impl OperationDigest {
    pub fn new(value: [u8; 32]) -> Result<Self, OperationContractError> {
        if value == [0; 32] {
            return Err(OperationContractError::ZeroOperationDigest);
        }
        Ok(Self(value))
    }

    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for OperationDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperationDigest([BOUND])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationClass {
    DurableMutation,
    ExternalEffect,
}

impl OperationClass {
    const fn code(self) -> u8 {
        match self {
            Self::DurableMutation => 1,
            Self::ExternalEffect => 2,
        }
    }

    const fn from_code(value: u8) -> Result<Self, OperationContractError> {
        match value {
            1 => Ok(Self::DurableMutation),
            2 => Ok(Self::ExternalEffect),
            _ => Err(OperationContractError::MalformedEvent),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationPhase {
    Accepted,
    RejectedBeforeDispatch,
    IntentCommitted,
    AbortedBeforeStateCommit,
    EffectStarted,
    EffectSucceeded,
    EffectFailed,
    EffectUnknown,
    StateCommitted,
    ResponseAudited,
    ResponseAuditFailedAfterCommit,
    Delivered,
    DeliveryFailedAfterCommit,
    Reconciled,
}

impl OperationPhase {
    const fn code(self) -> u8 {
        match self {
            Self::Accepted => 1,
            Self::RejectedBeforeDispatch => 2,
            Self::IntentCommitted => 3,
            Self::AbortedBeforeStateCommit => 14,
            Self::EffectStarted => 4,
            Self::EffectSucceeded => 5,
            Self::EffectFailed => 6,
            Self::EffectUnknown => 7,
            Self::StateCommitted => 8,
            Self::ResponseAudited => 9,
            Self::ResponseAuditFailedAfterCommit => 10,
            Self::Delivered => 11,
            Self::DeliveryFailedAfterCommit => 12,
            Self::Reconciled => 13,
        }
    }

    const fn from_code(value: u8) -> Result<Self, OperationContractError> {
        match value {
            1 => Ok(Self::Accepted),
            2 => Ok(Self::RejectedBeforeDispatch),
            3 => Ok(Self::IntentCommitted),
            4 => Ok(Self::EffectStarted),
            5 => Ok(Self::EffectSucceeded),
            6 => Ok(Self::EffectFailed),
            7 => Ok(Self::EffectUnknown),
            8 => Ok(Self::StateCommitted),
            9 => Ok(Self::ResponseAudited),
            10 => Ok(Self::ResponseAuditFailedAfterCommit),
            11 => Ok(Self::Delivered),
            12 => Ok(Self::DeliveryFailedAfterCommit),
            13 => Ok(Self::Reconciled),
            14 => Ok(Self::AbortedBeforeStateCommit),
            _ => Err(OperationContractError::MalformedEvent),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationEvent {
    operation_id: OperationId,
    request_digest: OperationDigest,
    class: OperationClass,
    previous_phase: Option<OperationPhase>,
    phase: OperationPhase,
    state_generation: Option<Generation>,
    state_digest: Option<StateDigest>,
    effect_key_digest: Option<OperationDigest>,
    response_digest: Option<OperationDigest>,
    detail_code: StableDetailCode,
}

impl OperationEvent {
    pub fn accepted(
        operation_id: OperationId,
        request_digest: OperationDigest,
        class: OperationClass,
        detail_code: StableDetailCode,
    ) -> Result<Self, OperationContractError> {
        let event = Self {
            operation_id,
            request_digest,
            class,
            previous_phase: None,
            phase: OperationPhase::Accepted,
            state_generation: None,
            state_digest: None,
            effect_key_digest: None,
            response_digest: None,
            detail_code,
        };
        validate_event_shape(&event)?;
        Ok(event)
    }

    pub fn next(
        &self,
        phase: OperationPhase,
        state: Option<(Generation, StateDigest)>,
        effect_key_digest: Option<OperationDigest>,
        response_digest: Option<OperationDigest>,
        detail_code: StableDetailCode,
    ) -> Result<Self, OperationContractError> {
        let (state_generation, state_digest) = match state {
            Some((generation, digest)) => (Some(generation), Some(digest)),
            None => (None, None),
        };
        let event = Self {
            operation_id: self.operation_id.clone(),
            request_digest: self.request_digest,
            class: self.class,
            previous_phase: Some(self.phase),
            phase,
            state_generation,
            state_digest,
            effect_key_digest,
            response_digest,
            detail_code,
        };
        validate_transition(Some(self), &event)?;
        Ok(event)
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub const fn request_digest(&self) -> OperationDigest {
        self.request_digest
    }

    pub const fn class(&self) -> OperationClass {
        self.class
    }

    pub const fn previous_phase(&self) -> Option<OperationPhase> {
        self.previous_phase
    }

    pub const fn phase(&self) -> OperationPhase {
        self.phase
    }

    pub const fn state(&self) -> Option<(Generation, StateDigest)> {
        match (self.state_generation, self.state_digest) {
            (Some(generation), Some(digest)) => Some((generation, digest)),
            _ => None,
        }
    }

    pub const fn effect_key_digest(&self) -> Option<OperationDigest> {
        self.effect_key_digest
    }

    pub const fn response_digest(&self) -> Option<OperationDigest> {
        self.response_digest
    }

    pub fn detail_code(&self) -> &StableDetailCode {
        &self.detail_code
    }

    pub fn encode(&self) -> Result<JournalPayload, OperationContractError> {
        validate_event_shape(self)?;
        let operation_id_len = u16::try_from(self.operation_id.as_str().len())
            .map_err(|_| OperationContractError::LengthOverflow)?;
        let detail_len = u16::try_from(self.detail_code.as_str().len())
            .map_err(|_| OperationContractError::LengthOverflow)?;
        let mut flags = 0_u8;
        if self.state_generation.is_some() {
            flags |= 0b001;
        }
        if self.effect_key_digest.is_some() {
            flags |= 0b010;
        }
        if self.response_digest.is_some() {
            flags |= 0b100;
        }
        let mut output = Vec::new();
        output.extend_from_slice(EVENT_MAGIC);
        output.extend_from_slice(&EVENT_VERSION.to_be_bytes());
        output.push(self.class.code());
        output.push(self.previous_phase.map_or(0, OperationPhase::code));
        output.push(self.phase.code());
        output.push(flags);
        output.extend_from_slice(&operation_id_len.to_be_bytes());
        output.extend_from_slice(&detail_len.to_be_bytes());
        output.extend_from_slice(&self.request_digest.bytes());
        if let (Some(generation), Some(digest)) = (self.state_generation, self.state_digest) {
            output.extend_from_slice(&generation.get().to_be_bytes());
            output.extend_from_slice(&digest.bytes());
        }
        if let Some(digest) = self.effect_key_digest {
            output.extend_from_slice(&digest.bytes());
        }
        if let Some(digest) = self.response_digest {
            output.extend_from_slice(&digest.bytes());
        }
        output.extend_from_slice(self.operation_id.as_str().as_bytes());
        output.extend_from_slice(self.detail_code.as_str().as_bytes());
        JournalPayload::new(output).map_err(|_| OperationContractError::LengthOverflow)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, OperationContractError> {
        let mut cursor = SliceCursor::new(bytes);
        if cursor.take(EVENT_MAGIC.len())? != EVENT_MAGIC {
            return Err(OperationContractError::MalformedEvent);
        }
        if cursor.take_u16()? != EVENT_VERSION {
            return Err(OperationContractError::UnsupportedEventVersion);
        }
        let class = OperationClass::from_code(cursor.take_u8()?)?;
        let previous_code = cursor.take_u8()?;
        let previous_phase = if previous_code == 0 {
            None
        } else {
            Some(OperationPhase::from_code(previous_code)?)
        };
        let phase = OperationPhase::from_code(cursor.take_u8()?)?;
        let flags = cursor.take_u8()?;
        if flags & !0b111 != 0 {
            return Err(OperationContractError::MalformedEvent);
        }
        let operation_id_len = usize::from(cursor.take_u16()?);
        let detail_len = usize::from(cursor.take_u16()?);
        let request_digest = OperationDigest::new(cursor.take_array_32()?)?;
        let (state_generation, state_digest) = if flags & 0b001 != 0 {
            let generation = Generation::new(cursor.take_u64()?)
                .map_err(|_| OperationContractError::MalformedEvent)?;
            let digest = StateDigest::new(cursor.take_array_32()?)
                .map_err(|_| OperationContractError::MalformedEvent)?;
            (Some(generation), Some(digest))
        } else {
            (None, None)
        };
        let effect_key_digest = if flags & 0b010 != 0 {
            Some(OperationDigest::new(cursor.take_array_32()?)?)
        } else {
            None
        };
        let response_digest = if flags & 0b100 != 0 {
            Some(OperationDigest::new(cursor.take_array_32()?)?)
        } else {
            None
        };
        if operation_id_len == 0 || detail_len == 0 {
            return Err(OperationContractError::MalformedEvent);
        }
        let operation_id = std::str::from_utf8(cursor.take(operation_id_len)?)
            .map_err(|_| OperationContractError::MalformedEvent)?;
        let detail_code = std::str::from_utf8(cursor.take(detail_len)?)
            .map_err(|_| OperationContractError::MalformedEvent)?;
        if !cursor.is_finished() {
            return Err(OperationContractError::TrailingEventBytes);
        }
        let event = Self {
            operation_id: OperationId::new(operation_id.to_owned())?,
            request_digest,
            class,
            previous_phase,
            phase,
            state_generation,
            state_digest,
            effect_key_digest,
            response_digest,
            detail_code: StableDetailCode::new(detail_code.to_owned())?,
        };
        validate_event_shape(&event)?;
        Ok(event)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDirective {
    SafeToRetryNewOperation,
    LookupOnly,
    ReconcileOnly,
    ManualHold,
    NoAutomaticRetry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerWriteState {
    Writable,
    ReplayRequired,
}

pub struct OperationLedger<J: DurableJournal> {
    journal: J,
    operations: BTreeMap<OperationId, OperationEvent>,
    write_state: LedgerWriteState,
}

impl<J: DurableJournal> fmt::Debug for OperationLedger<J> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationLedger")
            .field("journal", &self.journal)
            .field("operation_count", &self.operations.len())
            .field("write_state", &self.write_state)
            .finish()
    }
}

impl<J: DurableJournal> OperationLedger<J> {
    pub fn open(mut journal: J) -> Result<Self, OperationLedgerError<J::Error>> {
        let records = journal
            .recover_authoritative()
            .map_err(OperationLedgerError::Journal)?;
        let mut operations = BTreeMap::new();
        for record in records {
            let event = OperationEvent::decode(record.payload.as_bytes())
                .map_err(OperationLedgerError::Contract)?;
            apply_replayed_event(&mut operations, event).map_err(OperationLedgerError::Contract)?;
        }
        Ok(Self {
            journal,
            operations,
            write_state: LedgerWriteState::Writable,
        })
    }

    pub const fn write_state(&self) -> LedgerWriteState {
        self.write_state
    }

    pub const fn replay_required(&self) -> bool {
        matches!(self.write_state, LedgerWriteState::ReplayRequired)
    }

    pub fn current(&self, operation_id: &OperationId) -> Option<&OperationEvent> {
        self.operations.get(operation_id)
    }

    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }

    pub fn blocking_phase(&self) -> Option<OperationPhase> {
        self.operations.values().find_map(|event| {
            let phase = event.phase();
            phase_blocks_new_mutation(phase).then_some(phase)
        })
    }

    pub fn retry_directive(&self, operation_id: &OperationId) -> Option<RetryDirective> {
        self.current(operation_id).map(retry_directive_for_event)
    }

    pub fn record(
        &mut self,
        event: OperationEvent,
    ) -> Result<AppendReceipt, OperationLedgerError<J::Error>> {
        if self.replay_required() {
            return Err(OperationLedgerError::ReplayRequiredAfterAppendFailure);
        }
        let previous = self.operations.get(event.operation_id());
        validate_transition(previous, &event).map_err(OperationLedgerError::Contract)?;
        let payload = event.encode().map_err(OperationLedgerError::Contract)?;
        let expected_tail = self.journal.tail().map(|tail| tail.sequence);
        let receipt = match self.journal.append(expected_tail, payload) {
            Ok(receipt) => receipt,
            Err(error) => {
                if self.journal.classify_append_failure(&error)
                    == AppendFailureDisposition::OutcomeUnknown
                {
                    self.write_state = LedgerWriteState::ReplayRequired;
                }
                return Err(OperationLedgerError::Journal(error));
            }
        };
        self.operations.insert(event.operation_id.clone(), event);
        Ok(receipt)
    }

    pub fn recover_after_append_failure(&mut self) -> Result<(), OperationLedgerError<J::Error>> {
        if !self.replay_required() {
            return Err(OperationLedgerError::RecoveryNotRequired);
        }
        let records = self
            .journal
            .recover_authoritative()
            .map_err(OperationLedgerError::Journal)?;
        let mut operations = BTreeMap::new();
        for record in records {
            let event = OperationEvent::decode(record.payload.as_bytes())
                .map_err(OperationLedgerError::Contract)?;
            apply_replayed_event(&mut operations, event).map_err(OperationLedgerError::Contract)?;
        }
        self.operations = operations;
        self.write_state = LedgerWriteState::Writable;
        Ok(())
    }

    pub fn reopen(self) -> Result<Self, OperationLedgerError<J::Error>> {
        let mut ledger = self;
        if ledger.replay_required() {
            ledger.recover_after_append_failure()?;
            Ok(ledger)
        } else {
            Self::open(ledger.journal)
        }
    }
}

#[derive(Debug)]
pub enum OperationLedgerError<E>
where
    E: Error + Send + Sync + 'static,
{
    Contract(OperationContractError),
    Journal(E),
    ReplayRequiredAfterAppendFailure,
    RecoveryNotRequired,
}

impl<E> fmt::Display for OperationLedgerError<E>
where
    E: Error + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => {
                write!(formatter, "operation ledger contract failure: {error}")
            }
            Self::Journal(error) => write!(formatter, "durable journal failure: {error}"),
            Self::ReplayRequiredAfterAppendFailure => formatter.write_str(
                "journal append outcome was unknown; recover authoritative replay before writing",
            ),
            Self::RecoveryNotRequired => formatter
                .write_str("operation ledger recovery was requested while the ledger was writable"),
        }
    }
}

impl<E> Error for OperationLedgerError<E> where E: Error + Send + Sync + 'static {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationContractError {
    InvalidOperationId,
    InvalidDetailCode,
    ZeroOperationDigest,
    LengthOverflow,
    InvalidEventShape,
    InvalidTransition,
    ImmutableFieldDrift,
    DuplicateAcceptedOperation,
    MissingPreviousOperation,
    UnsupportedEventVersion,
    MalformedEvent,
    TrailingEventBytes,
}

impl fmt::Display for OperationContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOperationId => "operation identity is invalid",
            Self::InvalidDetailCode => "stable detail code is invalid",
            Self::ZeroOperationDigest => "operation digest must be non-zero",
            Self::LengthOverflow => "operation event length overflow",
            Self::InvalidEventShape => "operation event fields do not match its phase",
            Self::InvalidTransition => "operation phase transition is forbidden",
            Self::ImmutableFieldDrift => "operation immutable or accumulated fields changed",
            Self::DuplicateAcceptedOperation => "operation was accepted more than once",
            Self::MissingPreviousOperation => "operation transition has no previous state",
            Self::UnsupportedEventVersion => "operation event version is unsupported",
            Self::MalformedEvent => "operation event is malformed or truncated",
            Self::TrailingEventBytes => "operation event has trailing bytes",
        })
    }
}

impl Error for OperationContractError {}

fn apply_replayed_event(
    operations: &mut BTreeMap<OperationId, OperationEvent>,
    event: OperationEvent,
) -> Result<(), OperationContractError> {
    let previous = operations.get(event.operation_id());
    validate_transition(previous, &event)?;
    operations.insert(event.operation_id.clone(), event);
    Ok(())
}

fn validate_transition(
    previous: Option<&OperationEvent>,
    next: &OperationEvent,
) -> Result<(), OperationContractError> {
    validate_event_shape(next)?;
    match previous {
        None => {
            if next.phase != OperationPhase::Accepted || next.previous_phase.is_some() {
                return if next.phase == OperationPhase::Accepted {
                    Err(OperationContractError::DuplicateAcceptedOperation)
                } else {
                    Err(OperationContractError::MissingPreviousOperation)
                };
            }
            Ok(())
        }
        Some(previous) => {
            if next.phase == OperationPhase::Accepted {
                return Err(OperationContractError::DuplicateAcceptedOperation);
            }
            if next.previous_phase != Some(previous.phase) {
                return Err(OperationContractError::InvalidTransition);
            }
            if next.operation_id != previous.operation_id
                || next.request_digest != previous.request_digest
                || next.class != previous.class
            {
                return Err(OperationContractError::ImmutableFieldDrift);
            }
            if previous.state_generation.is_some()
                && (next.state_generation != previous.state_generation
                    || next.state_digest != previous.state_digest)
            {
                return Err(OperationContractError::ImmutableFieldDrift);
            }
            if previous.effect_key_digest.is_some()
                && next.effect_key_digest != previous.effect_key_digest
            {
                return Err(OperationContractError::ImmutableFieldDrift);
            }
            if previous.response_digest.is_some()
                && next.response_digest != previous.response_digest
            {
                return Err(OperationContractError::ImmutableFieldDrift);
            }
            if !allowed_transition(previous.class, previous.phase, next.phase) {
                return Err(OperationContractError::InvalidTransition);
            }
            Ok(())
        }
    }
}

const fn allowed_transition(
    class: OperationClass,
    previous: OperationPhase,
    next: OperationPhase,
) -> bool {
    matches!(
        (class, previous, next),
        (
            _,
            OperationPhase::Accepted,
            OperationPhase::RejectedBeforeDispatch
        ) | (_, OperationPhase::Accepted, OperationPhase::IntentCommitted)
            | (
                OperationClass::DurableMutation,
                OperationPhase::IntentCommitted,
                OperationPhase::StateCommitted | OperationPhase::AbortedBeforeStateCommit,
            )
            | (
                OperationClass::ExternalEffect,
                OperationPhase::IntentCommitted,
                OperationPhase::EffectStarted,
            )
            | (
                OperationClass::ExternalEffect,
                OperationPhase::EffectStarted,
                OperationPhase::EffectSucceeded
                    | OperationPhase::EffectFailed
                    | OperationPhase::EffectUnknown,
            )
            | (
                OperationClass::ExternalEffect,
                OperationPhase::EffectSucceeded,
                OperationPhase::StateCommitted,
            )
            | (
                OperationClass::ExternalEffect,
                OperationPhase::EffectFailed | OperationPhase::EffectUnknown,
                OperationPhase::Reconciled,
            )
            | (
                _,
                OperationPhase::StateCommitted,
                OperationPhase::ResponseAudited | OperationPhase::ResponseAuditFailedAfterCommit,
            )
            | (
                _,
                OperationPhase::ResponseAudited,
                OperationPhase::Delivered | OperationPhase::DeliveryFailedAfterCommit,
            )
            | (
                _,
                OperationPhase::ResponseAuditFailedAfterCommit
                    | OperationPhase::DeliveryFailedAfterCommit,
                OperationPhase::Reconciled,
            )
    )
}

fn validate_event_shape(event: &OperationEvent) -> Result<(), OperationContractError> {
    if event.state_generation.is_some() != event.state_digest.is_some() {
        return Err(OperationContractError::InvalidEventShape);
    }
    if event.phase == OperationPhase::Accepted {
        if event.previous_phase.is_some()
            || event.state_generation.is_some()
            || event.effect_key_digest.is_some()
            || event.response_digest.is_some()
        {
            return Err(OperationContractError::InvalidEventShape);
        }
        return Ok(());
    }
    if event.previous_phase.is_none() {
        return Err(OperationContractError::InvalidEventShape);
    }
    if event.class == OperationClass::DurableMutation && event.effect_key_digest.is_some() {
        return Err(OperationContractError::InvalidEventShape);
    }
    if event.phase == OperationPhase::AbortedBeforeStateCommit
        && event.class != OperationClass::DurableMutation
    {
        return Err(OperationContractError::InvalidEventShape);
    }
    if event.class == OperationClass::ExternalEffect
        && !matches!(event.phase, OperationPhase::RejectedBeforeDispatch)
        && event.effect_key_digest.is_none()
    {
        return Err(OperationContractError::InvalidEventShape);
    }
    if event.phase == OperationPhase::RejectedBeforeDispatch {
        if event.state_generation.is_some()
            || event.effect_key_digest.is_some()
            || event.response_digest.is_some()
        {
            return Err(OperationContractError::InvalidEventShape);
        }
        return Ok(());
    }
    if event.phase == OperationPhase::Reconciled {
        if event.response_digest.is_some() && event.state_generation.is_none() {
            return Err(OperationContractError::InvalidEventShape);
        }
        return Ok(());
    }
    let state_required = (event.class == OperationClass::DurableMutation
        && matches!(
            event.phase,
            OperationPhase::IntentCommitted | OperationPhase::AbortedBeforeStateCommit
        ))
        || matches!(
            event.phase,
            OperationPhase::StateCommitted
                | OperationPhase::ResponseAudited
                | OperationPhase::ResponseAuditFailedAfterCommit
                | OperationPhase::Delivered
                | OperationPhase::DeliveryFailedAfterCommit
        );
    if state_required != event.state_generation.is_some() {
        return Err(OperationContractError::InvalidEventShape);
    }
    let response_required = matches!(
        event.phase,
        OperationPhase::ResponseAudited
            | OperationPhase::ResponseAuditFailedAfterCommit
            | OperationPhase::Delivered
            | OperationPhase::DeliveryFailedAfterCommit
    );
    if response_required != event.response_digest.is_some() {
        return Err(OperationContractError::InvalidEventShape);
    }
    Ok(())
}

const fn phase_blocks_new_mutation(phase: OperationPhase) -> bool {
    matches!(
        phase,
        OperationPhase::Accepted
            | OperationPhase::IntentCommitted
            | OperationPhase::EffectStarted
            | OperationPhase::EffectSucceeded
            | OperationPhase::EffectUnknown
    )
}

const fn retry_directive_for_event(event: &OperationEvent) -> RetryDirective {
    match event.phase {
        OperationPhase::RejectedBeforeDispatch | OperationPhase::AbortedBeforeStateCommit => {
            RetryDirective::SafeToRetryNewOperation
        }
        OperationPhase::StateCommitted
        | OperationPhase::ResponseAudited
        | OperationPhase::Delivered => RetryDirective::LookupOnly,
        OperationPhase::IntentCommitted
        | OperationPhase::EffectStarted
        | OperationPhase::EffectSucceeded
        | OperationPhase::EffectUnknown
        | OperationPhase::ResponseAuditFailedAfterCommit
        | OperationPhase::DeliveryFailedAfterCommit => RetryDirective::ReconcileOnly,
        OperationPhase::Accepted => RetryDirective::ManualHold,
        OperationPhase::EffectFailed | OperationPhase::Reconciled => {
            RetryDirective::NoAutomaticRetry
        }
    }
}

#[derive(Debug)]
struct SliceCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SliceCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], OperationContractError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(OperationContractError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(OperationContractError::MalformedEvent)?;
        self.offset = end;
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8, OperationContractError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, OperationContractError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn take_u64(&mut self) -> Result<u64, OperationContractError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn take_array_32(&mut self) -> Result<[u8; 32], OperationContractError> {
        let bytes = self.take(32)?;
        let mut value = [0_u8; 32];
        value.copy_from_slice(bytes);
        Ok(value)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heptabao_journal_api::{
        JournalContractError, JournalDomain, JournalOpenMode, JournalRecord, JournalSequence,
        JournalTag, JournalTail,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MemoryJournalError {
        Contract(JournalContractError),
        Injected,
    }

    impl fmt::Display for MemoryJournalError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Contract(error) => write!(formatter, "memory journal contract: {error}"),
                Self::Injected => formatter.write_str("injected journal failure"),
            }
        }
    }

    impl Error for MemoryJournalError {}

    #[derive(Debug)]
    struct MemoryJournal {
        domain: JournalDomain,
        payloads: Vec<Vec<u8>>,
        fail_on_append: Option<usize>,
        calls: usize,
    }

    impl MemoryJournal {
        fn new() -> Result<Self, JournalContractError> {
            Ok(Self {
                domain: JournalDomain::new("heptabao/operation-ledger-test".to_owned())?,
                payloads: Vec::new(),
                fail_on_append: None,
                calls: 0,
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
        type Error = MemoryJournalError;

        fn domain(&self) -> &JournalDomain {
            &self.domain
        }

        fn open_mode(&self) -> JournalOpenMode {
            JournalOpenMode::CreateNew
        }

        fn tail(&self) -> Option<JournalTail> {
            let length = u64::try_from(self.payloads.len()).ok()?;
            let sequence = JournalSequence::new(length).ok()?;
            let tag = tag_for_sequence(sequence).ok()?;
            Some(JournalTail { sequence, tag })
        }

        fn replay(&self) -> Result<Vec<JournalRecord>, Self::Error> {
            let mut records = Vec::new();
            let mut previous_tag = None;
            for (index, bytes) in self.payloads.iter().enumerate() {
                let value = u64::try_from(index + 1).map_err(|_| MemoryJournalError::Injected)?;
                let sequence = JournalSequence::new(value).map_err(MemoryJournalError::Contract)?;
                let tag = tag_for_sequence(sequence)?;
                let payload =
                    JournalPayload::new(bytes.clone()).map_err(MemoryJournalError::Contract)?;
                records.push(JournalRecord {
                    sequence,
                    previous_tag,
                    tag,
                    payload,
                });
                previous_tag = Some(tag);
            }
            Ok(records)
        }

        fn append(
            &mut self,
            expected_tail: Option<JournalSequence>,
            payload: JournalPayload,
        ) -> Result<AppendReceipt, Self::Error> {
            self.calls = self
                .calls
                .checked_add(1)
                .ok_or(MemoryJournalError::Injected)?;
            let fail_after_persistence = self.fail_on_append == Some(self.calls);
            let actual = self.tail();
            if expected_tail != actual.map(|tail| tail.sequence) {
                return Err(MemoryJournalError::Injected);
            }
            let value =
                u64::try_from(self.payloads.len() + 1).map_err(|_| MemoryJournalError::Injected)?;
            let sequence = JournalSequence::new(value).map_err(MemoryJournalError::Contract)?;
            let previous_tail = actual;
            let appended = JournalTail {
                sequence,
                tag: tag_for_sequence(sequence)?,
            };
            self.payloads.push(payload.into_bytes());
            if fail_after_persistence {
                return Err(MemoryJournalError::Injected);
            }
            Ok(AppendReceipt {
                previous_tail,
                appended,
            })
        }
    }

    fn tag_for_sequence(sequence: JournalSequence) -> Result<JournalTag, MemoryJournalError> {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&sequence.get().to_be_bytes());
        JournalTag::new(bytes).map_err(MemoryJournalError::Contract)
    }

    fn accepted(class: OperationClass) -> Result<OperationEvent, OperationContractError> {
        OperationEvent::accepted(
            OperationId::new("operation-0001".to_owned())?,
            OperationDigest::new([1; 32])?,
            class,
            StableDetailCode::new("accepted".to_owned())?,
        )
    }

    fn stable_detail(value: &str) -> Result<StableDetailCode, OperationContractError> {
        StableDetailCode::new(value.to_owned())
    }

    fn durable_target() -> Option<(Generation, StateDigest)> {
        StateDigest::new([3; 32])
            .ok()
            .map(|digest| (Generation::INITIAL, digest))
    }

    #[test]
    fn legal_mutation_chain_replays_and_requires_lookup_after_commit() {
        let journal = MemoryJournal::new();
        assert!(journal.is_ok());
        if let Ok(journal) = journal {
            let ledger = OperationLedger::open(journal);
            assert!(ledger.is_ok());
            if let Ok(mut ledger) = ledger {
                let accepted = accepted(OperationClass::DurableMutation);
                assert!(accepted.is_ok());
                if let Ok(accepted) = accepted {
                    assert!(ledger.record(accepted.clone()).is_ok());
                    let detail = stable_detail("intent-committed");
                    assert!(detail.is_ok());
                    if let Ok(detail) = detail {
                        let intent = accepted.next(
                            OperationPhase::IntentCommitted,
                            durable_target(),
                            None,
                            None,
                            detail,
                        );
                        assert!(intent.is_ok());
                        if let Ok(intent) = intent {
                            assert!(ledger.record(intent.clone()).is_ok());
                            let reconcile_detail = stable_detail("unsafe-generic-reconcile");
                            assert!(reconcile_detail.is_ok());
                            if let Ok(reconcile_detail) = reconcile_detail {
                                assert!(matches!(
                                    intent.next(
                                        OperationPhase::Reconciled,
                                        intent.state(),
                                        None,
                                        None,
                                        reconcile_detail,
                                    ),
                                    Err(OperationContractError::InvalidTransition)
                                ));
                            }
                            let state_digest = StateDigest::new([3; 32]);
                            let detail = stable_detail("state-committed");
                            assert!(state_digest.is_ok());
                            assert!(detail.is_ok());
                            if let (Ok(state_digest), Ok(detail)) = (state_digest, detail) {
                                let state = intent.next(
                                    OperationPhase::StateCommitted,
                                    Some((Generation::INITIAL, state_digest)),
                                    None,
                                    None,
                                    detail,
                                );
                                assert!(state.is_ok());
                                if let Ok(state) = state {
                                    assert!(ledger.record(state).is_ok());
                                }
                            }
                        }
                    }
                }
                let operation_id = OperationId::new("operation-0001".to_owned());
                assert!(operation_id.is_ok());
                if let Ok(operation_id) = operation_id {
                    assert_eq!(
                        ledger.retry_directive(&operation_id),
                        Some(RetryDirective::LookupOnly)
                    );
                }
                let reopened = ledger.reopen();
                assert!(reopened.is_ok());
                if let Ok(reopened) = reopened {
                    assert_eq!(reopened.operation_count(), 1);
                }
            }
        }
    }

    #[test]
    fn proven_not_committed_intent_is_terminal_and_unblocks_new_mutations() {
        let journal = MemoryJournal::new();
        assert!(journal.is_ok());
        if let Ok(journal) = journal {
            let ledger = OperationLedger::open(journal);
            assert!(ledger.is_ok());
            if let Ok(mut ledger) = ledger {
                let accepted = accepted(OperationClass::DurableMutation);
                assert!(accepted.is_ok());
                if let Ok(accepted) = accepted {
                    assert!(ledger.record(accepted.clone()).is_ok());
                    let intent_detail = stable_detail("intent-bound-to-target");
                    assert!(intent_detail.is_ok());
                    if let Ok(intent_detail) = intent_detail {
                        let intent = accepted.next(
                            OperationPhase::IntentCommitted,
                            durable_target(),
                            None,
                            None,
                            intent_detail,
                        );
                        assert!(intent.is_ok());
                        if let Ok(intent) = intent {
                            assert!(ledger.record(intent.clone()).is_ok());
                            assert_eq!(
                                ledger.blocking_phase(),
                                Some(OperationPhase::IntentCommitted)
                            );
                            let abort_detail = stable_detail("state-commit-not-observed");
                            assert!(abort_detail.is_ok());
                            if let Ok(abort_detail) = abort_detail {
                                let aborted = intent.next(
                                    OperationPhase::AbortedBeforeStateCommit,
                                    intent.state(),
                                    None,
                                    None,
                                    abort_detail,
                                );
                                assert!(aborted.is_ok());
                                if let Ok(aborted) = aborted {
                                    assert!(ledger.record(aborted).is_ok());
                                    assert_eq!(ledger.blocking_phase(), None);
                                    let operation_id =
                                        OperationId::new("operation-0001".to_owned());
                                    assert!(operation_id.is_ok());
                                    if let Ok(operation_id) = operation_id {
                                        assert_eq!(
                                            ledger.retry_directive(&operation_id),
                                            Some(RetryDirective::SafeToRetryNewOperation)
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn duplicate_acceptance_and_illegal_transition_fail_closed() {
        let accepted = accepted(OperationClass::DurableMutation);
        assert!(accepted.is_ok());
        if let Ok(accepted) = accepted {
            assert_eq!(
                validate_transition(Some(&accepted), &accepted),
                Err(OperationContractError::DuplicateAcceptedOperation)
            );
            let state_digest = StateDigest::new([2; 32]);
            let detail = stable_detail("illegal");
            assert!(state_digest.is_ok());
            assert!(detail.is_ok());
            if let (Ok(state_digest), Ok(detail)) = (state_digest, detail) {
                let illegal = accepted.next(
                    OperationPhase::StateCommitted,
                    Some((Generation::INITIAL, state_digest)),
                    None,
                    None,
                    detail,
                );
                assert_eq!(illegal, Err(OperationContractError::InvalidTransition));
            }
        }
    }

    #[test]
    fn external_unknown_effect_is_reconcile_only() {
        let accepted = accepted(OperationClass::ExternalEffect);
        assert!(accepted.is_ok());
        if let Ok(accepted) = accepted {
            let effect_key = OperationDigest::new([9; 32]);
            let detail = stable_detail("intent");
            assert!(effect_key.is_ok());
            assert!(detail.is_ok());
            if let (Ok(effect_key), Ok(detail)) = (effect_key, detail) {
                let intent = accepted.next(
                    OperationPhase::IntentCommitted,
                    None,
                    Some(effect_key),
                    None,
                    detail,
                );
                assert!(intent.is_ok());
                if let Ok(intent) = intent {
                    let detail = stable_detail("effect-started");
                    assert!(detail.is_ok());
                    if let Ok(detail) = detail {
                        let started = intent.next(
                            OperationPhase::EffectStarted,
                            None,
                            Some(effect_key),
                            None,
                            detail,
                        );
                        assert!(started.is_ok());
                        if let Ok(started) = started {
                            let detail = stable_detail("effect-unknown");
                            assert!(detail.is_ok());
                            if let Ok(detail) = detail {
                                let unknown = started.next(
                                    OperationPhase::EffectUnknown,
                                    None,
                                    Some(effect_key),
                                    None,
                                    detail,
                                );
                                assert!(unknown.is_ok());
                                if let Ok(unknown) = unknown {
                                    assert_eq!(
                                        retry_directive_for_event(&unknown),
                                        RetryDirective::ReconcileOnly
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn encoded_event_rejects_trailing_bytes() {
        let event = accepted(OperationClass::DurableMutation);
        assert!(event.is_ok());
        if let Ok(event) = event {
            let payload = event.encode();
            assert!(payload.is_ok());
            if let Ok(payload) = payload {
                let mut bytes = payload.into_bytes();
                bytes.push(0);
                assert_eq!(
                    OperationEvent::decode(&bytes),
                    Err(OperationContractError::TrailingEventBytes)
                );
            }
        }
    }
    #[test]
    fn append_outcome_unknown_after_persistence_requires_authoritative_replay() {
        let journal = MemoryJournal::new();
        assert!(journal.is_ok());
        if let Ok(mut journal) = journal {
            journal.fail_on_append = Some(1);
            let ledger = OperationLedger::open(journal);
            assert!(ledger.is_ok());
            if let Ok(mut ledger) = ledger {
                let event = accepted(OperationClass::DurableMutation);
                assert!(event.is_ok());
                if let Ok(event) = event {
                    assert!(matches!(
                        ledger.record(event.clone()),
                        Err(OperationLedgerError::Journal(MemoryJournalError::Injected))
                    ));
                    assert_eq!(ledger.write_state(), LedgerWriteState::ReplayRequired);
                    assert!(matches!(
                        ledger.record(event.clone()),
                        Err(OperationLedgerError::ReplayRequiredAfterAppendFailure)
                    ));
                    assert!(ledger.recover_after_append_failure().is_ok());
                    assert_eq!(ledger.write_state(), LedgerWriteState::Writable);
                    assert_eq!(ledger.operation_count(), 1);
                    assert!(matches!(
                        ledger.record(event),
                        Err(OperationLedgerError::Contract(
                            OperationContractError::DuplicateAcceptedOperation
                        ))
                    ));
                }
            }
        }
    }
}
