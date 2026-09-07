#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Durable provider-neutral key-epoch lifecycle state for HeptaBao.
//!
//! The ledger records key-management facts but never contains key material and
//! never claims that a custody provider actually performed an HSM/KMS action.
//! One atomic rotation event moves the old active epoch to decrypt-only while
//! promoting one previously staged epoch. Active-key revocation is forbidden;
//! operators must rotate first so there is never an implicit key-selection gap.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use heptabao_barrier_api::KeyEpoch;
use heptabao_journal_api::{
    AppendFailureDisposition, AppendReceipt, DurableJournal, JournalPayload,
};

const EVENT_MAGIC: &[u8] = b"HEPTABAO-KEY-RING-EVENT-V1\0";
const EVENT_VERSION: u16 = 1;
pub const MAX_REASON_CODE_BYTES: usize = 96;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReasonCode(String);

impl ReasonCode {
    pub fn new(value: String) -> Result<Self, KeyLifecycleContractError> {
        if value.is_empty()
            || value.len() > MAX_REASON_CODE_BYTES
            || !value.is_ascii()
            || !value
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
        {
            return Err(KeyLifecycleContractError::InvalidReasonCode);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ReasonCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ReasonCode").field(&self.0).finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyStatus {
    Staged,
    Active,
    DecryptOnly,
    Retired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyUseDirective {
    SealAndOpen,
    OpenOnly,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyRingEventKind {
    Bootstrap,
    Stage,
    Rotate,
    Retire,
    Revoke,
}

impl KeyRingEventKind {
    const fn code(self) -> u8 {
        match self {
            Self::Bootstrap => 1,
            Self::Stage => 2,
            Self::Rotate => 3,
            Self::Retire => 4,
            Self::Revoke => 5,
        }
    }

    const fn from_code(value: u8) -> Result<Self, KeyLifecycleContractError> {
        match value {
            1 => Ok(Self::Bootstrap),
            2 => Ok(Self::Stage),
            3 => Ok(Self::Rotate),
            4 => Ok(Self::Retire),
            5 => Ok(Self::Revoke),
            _ => Err(KeyLifecycleContractError::MalformedEvent),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRingEvent {
    kind: KeyRingEventKind,
    epoch: KeyEpoch,
    previous_active: Option<KeyEpoch>,
    reason: ReasonCode,
}

impl KeyRingEvent {
    fn new(
        kind: KeyRingEventKind,
        epoch: KeyEpoch,
        previous_active: Option<KeyEpoch>,
        reason: ReasonCode,
    ) -> Result<Self, KeyLifecycleContractError> {
        let event = Self {
            kind,
            epoch,
            previous_active,
            reason,
        };
        validate_event_shape(&event)?;
        Ok(event)
    }

    pub const fn kind(&self) -> KeyRingEventKind {
        self.kind
    }

    pub const fn epoch(&self) -> KeyEpoch {
        self.epoch
    }

    pub const fn previous_active(&self) -> Option<KeyEpoch> {
        self.previous_active
    }

    pub fn reason(&self) -> &ReasonCode {
        &self.reason
    }

    pub fn encode(&self) -> Result<JournalPayload, KeyLifecycleContractError> {
        validate_event_shape(self)?;
        let reason_len = u16::try_from(self.reason.as_str().len())
            .map_err(|_| KeyLifecycleContractError::LengthOverflow)?;
        let mut output = Vec::new();
        output.extend_from_slice(EVENT_MAGIC);
        output.extend_from_slice(&EVENT_VERSION.to_be_bytes());
        output.push(self.kind.code());
        output.push(u8::from(self.previous_active.is_some()));
        output.extend_from_slice(&self.epoch.get().to_be_bytes());
        if let Some(epoch) = self.previous_active {
            output.extend_from_slice(&epoch.get().to_be_bytes());
        }
        output.extend_from_slice(&reason_len.to_be_bytes());
        output.extend_from_slice(self.reason.as_str().as_bytes());
        JournalPayload::new(output).map_err(|_| KeyLifecycleContractError::LengthOverflow)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KeyLifecycleContractError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(EVENT_MAGIC.len())? != EVENT_MAGIC {
            return Err(KeyLifecycleContractError::MalformedEvent);
        }
        if cursor.take_u16()? != EVENT_VERSION {
            return Err(KeyLifecycleContractError::UnsupportedEventVersion);
        }
        let kind = KeyRingEventKind::from_code(cursor.take_u8()?)?;
        let has_previous = cursor.take_u8()?;
        if has_previous > 1 {
            return Err(KeyLifecycleContractError::MalformedEvent);
        }
        let epoch = KeyEpoch::new(cursor.take_u64()?)
            .map_err(|_| KeyLifecycleContractError::MalformedEvent)?;
        let previous_active = if has_previous == 1 {
            Some(
                KeyEpoch::new(cursor.take_u64()?)
                    .map_err(|_| KeyLifecycleContractError::MalformedEvent)?,
            )
        } else {
            None
        };
        let reason_len = usize::from(cursor.take_u16()?);
        let reason = std::str::from_utf8(cursor.take(reason_len)?)
            .map_err(|_| KeyLifecycleContractError::MalformedEvent)?;
        if !cursor.is_finished() {
            return Err(KeyLifecycleContractError::TrailingEventBytes);
        }
        Self::new(
            kind,
            epoch,
            previous_active,
            ReasonCode::new(reason.to_owned())?,
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KeyRingState {
    epochs: BTreeMap<KeyEpoch, KeyStatus>,
    active: Option<KeyEpoch>,
}

impl KeyRingState {
    pub const fn active_epoch(&self) -> Option<KeyEpoch> {
        self.active
    }

    pub fn status(&self, epoch: KeyEpoch) -> Option<KeyStatus> {
        self.epochs.get(&epoch).copied()
    }

    pub fn directive(&self, epoch: KeyEpoch) -> KeyUseDirective {
        match self.status(epoch) {
            Some(KeyStatus::Active) => KeyUseDirective::SealAndOpen,
            Some(KeyStatus::DecryptOnly) => KeyUseDirective::OpenOnly,
            Some(KeyStatus::Staged | KeyStatus::Retired | KeyStatus::Revoked) | None => {
                KeyUseDirective::Deny
            }
        }
    }

    pub fn known_epoch_count(&self) -> usize {
        self.epochs.len()
    }

    fn apply(&mut self, event: &KeyRingEvent) -> Result<(), KeyLifecycleContractError> {
        validate_event_shape(event)?;
        match event.kind {
            KeyRingEventKind::Bootstrap => {
                if !self.epochs.is_empty() || self.active.is_some() {
                    return Err(KeyLifecycleContractError::AlreadyBootstrapped);
                }
                self.epochs.insert(event.epoch, KeyStatus::Active);
                self.active = Some(event.epoch);
            }
            KeyRingEventKind::Stage => {
                let Some(active) = self.active else {
                    return Err(KeyLifecycleContractError::NotBootstrapped);
                };
                if self.epochs.contains_key(&event.epoch)
                    || event.epoch.get() <= active.get()
                    || self
                        .epochs
                        .keys()
                        .next_back()
                        .is_some_and(|latest| event.epoch.get() <= latest.get())
                {
                    return Err(KeyLifecycleContractError::InvalidEpochOrder);
                }
                self.epochs.insert(event.epoch, KeyStatus::Staged);
            }
            KeyRingEventKind::Rotate => {
                let previous = event
                    .previous_active
                    .ok_or(KeyLifecycleContractError::InvalidEventShape)?;
                if self.active != Some(previous)
                    || self.status(previous) != Some(KeyStatus::Active)
                    || self.status(event.epoch) != Some(KeyStatus::Staged)
                    || event.epoch.get() <= previous.get()
                {
                    return Err(KeyLifecycleContractError::InvalidTransition);
                }
                self.epochs.insert(previous, KeyStatus::DecryptOnly);
                self.epochs.insert(event.epoch, KeyStatus::Active);
                self.active = Some(event.epoch);
            }
            KeyRingEventKind::Retire => {
                if self.status(event.epoch) != Some(KeyStatus::DecryptOnly) {
                    return Err(KeyLifecycleContractError::InvalidTransition);
                }
                self.epochs.insert(event.epoch, KeyStatus::Retired);
            }
            KeyRingEventKind::Revoke => {
                if self.active == Some(event.epoch) {
                    return Err(KeyLifecycleContractError::ActiveRevocationForbidden);
                }
                match self.status(event.epoch) {
                    Some(KeyStatus::Staged | KeyStatus::DecryptOnly | KeyStatus::Retired) => {
                        self.epochs.insert(event.epoch, KeyStatus::Revoked);
                    }
                    Some(KeyStatus::Active | KeyStatus::Revoked) | None => {
                        return Err(KeyLifecycleContractError::InvalidTransition);
                    }
                }
            }
        }
        self.validate_invariants()
    }

    fn validate_invariants(&self) -> Result<(), KeyLifecycleContractError> {
        let active_epochs = self
            .epochs
            .iter()
            .filter(|(_, status)| **status == KeyStatus::Active)
            .map(|(epoch, _)| *epoch)
            .collect::<Vec<_>>();
        match (self.active, active_epochs.as_slice()) {
            (None, []) if self.epochs.is_empty() => Ok(()),
            (Some(expected), [actual]) if expected == *actual => Ok(()),
            _ => Err(KeyLifecycleContractError::InvariantViolation),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyLedgerWriteState {
    Writable,
    ReplayRequired,
}

pub struct KeyRingLedger<J: DurableJournal> {
    journal: J,
    state: KeyRingState,
    write_state: KeyLedgerWriteState,
}

impl<J: DurableJournal> fmt::Debug for KeyRingLedger<J> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyRingLedger")
            .field("journal", &self.journal)
            .field("active_epoch", &self.state.active_epoch())
            .field("known_epoch_count", &self.state.known_epoch_count())
            .field("write_state", &self.write_state)
            .finish()
    }
}

impl<J: DurableJournal> KeyRingLedger<J> {
    pub fn open(mut journal: J) -> Result<Self, KeyLifecycleError<J::Error>> {
        let records = journal
            .recover_authoritative()
            .map_err(KeyLifecycleError::Journal)?;
        let mut state = KeyRingState::default();
        for record in records {
            let event = KeyRingEvent::decode(record.payload.as_bytes())
                .map_err(KeyLifecycleError::Contract)?;
            state.apply(&event).map_err(KeyLifecycleError::Contract)?;
        }
        Ok(Self {
            journal,
            state,
            write_state: KeyLedgerWriteState::Writable,
        })
    }

    pub const fn write_state(&self) -> KeyLedgerWriteState {
        self.write_state
    }

    pub const fn replay_required(&self) -> bool {
        matches!(self.write_state, KeyLedgerWriteState::ReplayRequired)
    }

    pub const fn state(&self) -> &KeyRingState {
        &self.state
    }

    pub const fn journal(&self) -> &J {
        &self.journal
    }

    pub fn bootstrap(
        &mut self,
        epoch: KeyEpoch,
        reason: ReasonCode,
    ) -> Result<AppendReceipt, KeyLifecycleError<J::Error>> {
        self.record(KeyRingEvent::new(
            KeyRingEventKind::Bootstrap,
            epoch,
            None,
            reason,
        )?)
    }

    pub fn stage(
        &mut self,
        epoch: KeyEpoch,
        reason: ReasonCode,
    ) -> Result<AppendReceipt, KeyLifecycleError<J::Error>> {
        self.record(KeyRingEvent::new(
            KeyRingEventKind::Stage,
            epoch,
            None,
            reason,
        )?)
    }

    pub fn rotate(
        &mut self,
        previous_active: KeyEpoch,
        new_active: KeyEpoch,
        reason: ReasonCode,
    ) -> Result<AppendReceipt, KeyLifecycleError<J::Error>> {
        self.record(KeyRingEvent::new(
            KeyRingEventKind::Rotate,
            new_active,
            Some(previous_active),
            reason,
        )?)
    }

    pub fn retire(
        &mut self,
        epoch: KeyEpoch,
        reason: ReasonCode,
    ) -> Result<AppendReceipt, KeyLifecycleError<J::Error>> {
        self.record(KeyRingEvent::new(
            KeyRingEventKind::Retire,
            epoch,
            None,
            reason,
        )?)
    }

    pub fn revoke(
        &mut self,
        epoch: KeyEpoch,
        reason: ReasonCode,
    ) -> Result<AppendReceipt, KeyLifecycleError<J::Error>> {
        self.record(KeyRingEvent::new(
            KeyRingEventKind::Revoke,
            epoch,
            None,
            reason,
        )?)
    }

    pub fn recover_after_append_failure(&mut self) -> Result<(), KeyLifecycleError<J::Error>> {
        if !self.replay_required() {
            return Err(KeyLifecycleError::RecoveryNotRequired);
        }
        let records = self
            .journal
            .recover_authoritative()
            .map_err(KeyLifecycleError::Journal)?;
        let mut state = KeyRingState::default();
        for record in records {
            let event = KeyRingEvent::decode(record.payload.as_bytes())
                .map_err(KeyLifecycleError::Contract)?;
            state.apply(&event).map_err(KeyLifecycleError::Contract)?;
        }
        self.state = state;
        self.write_state = KeyLedgerWriteState::Writable;
        Ok(())
    }

    pub fn reopen(self) -> Result<Self, KeyLifecycleError<J::Error>> {
        let mut ledger = self;
        if ledger.replay_required() {
            ledger.recover_after_append_failure()?;
            Ok(ledger)
        } else {
            Self::open(ledger.journal)
        }
    }

    fn record(
        &mut self,
        event: KeyRingEvent,
    ) -> Result<AppendReceipt, KeyLifecycleError<J::Error>> {
        if self.replay_required() {
            return Err(KeyLifecycleError::ReplayRequiredAfterAppendFailure);
        }
        let mut candidate = self.state.clone();
        candidate
            .apply(&event)
            .map_err(KeyLifecycleError::Contract)?;
        let payload = event.encode().map_err(KeyLifecycleError::Contract)?;
        let expected_tail = self.journal.tail().map(|tail| tail.sequence);
        let receipt = match self.journal.append(expected_tail, payload) {
            Ok(receipt) => receipt,
            Err(error) => {
                if self.journal.classify_append_failure(&error)
                    == AppendFailureDisposition::OutcomeUnknown
                {
                    self.write_state = KeyLedgerWriteState::ReplayRequired;
                }
                return Err(KeyLifecycleError::Journal(error));
            }
        };
        self.state = candidate;
        Ok(receipt)
    }
}

#[derive(Debug)]
pub enum KeyLifecycleError<E>
where
    E: Error + Send + Sync + 'static,
{
    Contract(KeyLifecycleContractError),
    Journal(E),
    ReplayRequiredAfterAppendFailure,
    RecoveryNotRequired,
}

impl<E> fmt::Display for KeyLifecycleError<E>
where
    E: Error + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "key lifecycle contract failure: {error}"),
            Self::Journal(error) => write!(formatter, "key lifecycle journal failure: {error}"),
            Self::ReplayRequiredAfterAppendFailure => formatter.write_str(
                "key lifecycle append outcome was unknown; recover authoritative replay before writing",
            ),
            Self::RecoveryNotRequired => formatter.write_str(
                "key lifecycle recovery was requested while the ledger was writable",
            ),
        }
    }
}

impl<E> Error for KeyLifecycleError<E> where E: Error + Send + Sync + 'static {}

impl<E> From<KeyLifecycleContractError> for KeyLifecycleError<E>
where
    E: Error + Send + Sync + 'static,
{
    fn from(error: KeyLifecycleContractError) -> Self {
        Self::Contract(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyLifecycleContractError {
    InvalidReasonCode,
    LengthOverflow,
    UnsupportedEventVersion,
    MalformedEvent,
    TrailingEventBytes,
    InvalidEventShape,
    AlreadyBootstrapped,
    NotBootstrapped,
    InvalidEpochOrder,
    InvalidTransition,
    ActiveRevocationForbidden,
    InvariantViolation,
}

impl fmt::Display for KeyLifecycleContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidReasonCode => "key lifecycle reason code is invalid",
            Self::LengthOverflow => "key lifecycle event length overflow",
            Self::UnsupportedEventVersion => "key lifecycle event version is unsupported",
            Self::MalformedEvent => "key lifecycle event is malformed or truncated",
            Self::TrailingEventBytes => "key lifecycle event has trailing bytes",
            Self::InvalidEventShape => "key lifecycle event fields do not match its kind",
            Self::AlreadyBootstrapped => "key ring is already bootstrapped",
            Self::NotBootstrapped => "key ring is not bootstrapped",
            Self::InvalidEpochOrder => "key epoch order is invalid",
            Self::InvalidTransition => "key lifecycle transition is forbidden",
            Self::ActiveRevocationForbidden => "active key epoch cannot be revoked before rotation",
            Self::InvariantViolation => "key ring invariant was violated",
        })
    }
}

impl Error for KeyLifecycleContractError {}

fn validate_event_shape(event: &KeyRingEvent) -> Result<(), KeyLifecycleContractError> {
    let previous_required = event.kind == KeyRingEventKind::Rotate;
    if previous_required != event.previous_active.is_some() {
        return Err(KeyLifecycleContractError::InvalidEventShape);
    }
    if event.previous_active == Some(event.epoch) {
        return Err(KeyLifecycleContractError::InvalidEventShape);
    }
    Ok(())
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

    fn take(&mut self, length: usize) -> Result<&'a [u8], KeyLifecycleContractError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(KeyLifecycleContractError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(KeyLifecycleContractError::MalformedEvent)?;
        self.offset = end;
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8, KeyLifecycleContractError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, KeyLifecycleContractError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn take_u64(&mut self) -> Result<u64, KeyLifecycleContractError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
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
    enum MemoryError {
        Contract(JournalContractError),
        StaleTail,
    }

    impl fmt::Display for MemoryError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Contract(error) => write!(formatter, "memory journal contract: {error}"),
                Self::StaleTail => formatter.write_str("stale memory journal tail"),
            }
        }
    }

    impl Error for MemoryError {}

    #[derive(Debug)]
    struct MemoryJournal {
        domain: JournalDomain,
        payloads: Vec<Vec<u8>>,
        fail_after_append: bool,
    }

    impl MemoryJournal {
        fn new() -> Result<Self, JournalContractError> {
            Ok(Self {
                domain: JournalDomain::new("heptabao/key-lifecycle-test".to_owned())?,
                payloads: Vec::new(),
                fail_after_append: false,
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
        type Error = MemoryError;

        fn domain(&self) -> &JournalDomain {
            &self.domain
        }

        fn open_mode(&self) -> JournalOpenMode {
            JournalOpenMode::CreateNew
        }

        fn tail(&self) -> Option<JournalTail> {
            let length = u64::try_from(self.payloads.len()).ok()?;
            let sequence = JournalSequence::new(length).ok()?;
            Some(JournalTail {
                sequence,
                tag: tag(sequence).ok()?,
            })
        }

        fn replay(&self) -> Result<Vec<JournalRecord>, Self::Error> {
            let mut records = Vec::new();
            let mut previous_tag = None;
            for (index, bytes) in self.payloads.iter().enumerate() {
                let value = u64::try_from(index + 1).map_err(|_| MemoryError::StaleTail)?;
                let sequence = JournalSequence::new(value).map_err(MemoryError::Contract)?;
                let current_tag = tag(sequence)?;
                records.push(JournalRecord {
                    sequence,
                    previous_tag,
                    tag: current_tag,
                    payload: JournalPayload::new(bytes.clone()).map_err(MemoryError::Contract)?,
                });
                previous_tag = Some(current_tag);
            }
            Ok(records)
        }

        fn append(
            &mut self,
            expected_tail: Option<JournalSequence>,
            payload: JournalPayload,
        ) -> Result<AppendReceipt, Self::Error> {
            let previous_tail = self.tail();
            if expected_tail != previous_tail.map(|value| value.sequence) {
                return Err(MemoryError::StaleTail);
            }
            let value =
                u64::try_from(self.payloads.len() + 1).map_err(|_| MemoryError::StaleTail)?;
            let sequence = JournalSequence::new(value).map_err(MemoryError::Contract)?;
            let appended = JournalTail {
                sequence,
                tag: tag(sequence)?,
            };
            self.payloads.push(payload.into_bytes());
            if self.fail_after_append {
                return Err(MemoryError::StaleTail);
            }
            Ok(AppendReceipt {
                previous_tail,
                appended,
            })
        }
    }

    fn tag(sequence: JournalSequence) -> Result<JournalTag, MemoryError> {
        let mut value = [0_u8; 32];
        value[..8].copy_from_slice(&sequence.get().to_be_bytes());
        JournalTag::new(value).map_err(MemoryError::Contract)
    }

    fn reason(value: &str) -> Result<ReasonCode, KeyLifecycleContractError> {
        ReasonCode::new(value.to_owned())
    }

    #[test]
    fn bootstrap_stage_rotate_retire_and_revoke_replay() -> Result<(), Box<dyn Error>> {
        let journal = MemoryJournal::new()?;
        let mut ledger = KeyRingLedger::open(journal)?;
        let first = KeyEpoch::INITIAL;
        let second = first.checked_next()?;
        ledger.bootstrap(first, reason("bootstrap")?)?;
        ledger.stage(second, reason("stage")?)?;
        ledger.rotate(first, second, reason("rotate")?)?;
        assert_eq!(ledger.state().directive(first), KeyUseDirective::OpenOnly);
        assert_eq!(
            ledger.state().directive(second),
            KeyUseDirective::SealAndOpen
        );
        ledger.retire(first, reason("retire")?)?;
        ledger.revoke(first, reason("revoke")?)?;
        let reopened = ledger.reopen()?;
        assert_eq!(reopened.state().active_epoch(), Some(second));
        assert_eq!(reopened.state().status(first), Some(KeyStatus::Revoked));
        Ok(())
    }

    #[test]
    fn active_revocation_and_unstaged_rotation_fail_closed() -> Result<(), Box<dyn Error>> {
        let mut state = KeyRingState::default();
        let bootstrap = KeyRingEvent::new(
            KeyRingEventKind::Bootstrap,
            KeyEpoch::INITIAL,
            None,
            reason("bootstrap")?,
        )?;
        state.apply(&bootstrap)?;
        let revoke = KeyRingEvent::new(
            KeyRingEventKind::Revoke,
            KeyEpoch::INITIAL,
            None,
            reason("revoke")?,
        )?;
        assert_eq!(
            state.apply(&revoke),
            Err(KeyLifecycleContractError::ActiveRevocationForbidden)
        );
        let second = KeyEpoch::INITIAL.checked_next()?;
        let rotate = KeyRingEvent::new(
            KeyRingEventKind::Rotate,
            second,
            Some(KeyEpoch::INITIAL),
            reason("rotate")?,
        )?;
        assert_eq!(
            state.apply(&rotate),
            Err(KeyLifecycleContractError::InvalidTransition)
        );
        Ok(())
    }

    #[test]
    fn event_decoder_rejects_trailing_bytes() -> Result<(), Box<dyn Error>> {
        let event = KeyRingEvent::new(
            KeyRingEventKind::Bootstrap,
            KeyEpoch::INITIAL,
            None,
            reason("bootstrap")?,
        )?;
        let mut bytes = event.encode()?.into_bytes();
        bytes.push(0);
        assert_eq!(
            KeyRingEvent::decode(&bytes),
            Err(KeyLifecycleContractError::TrailingEventBytes)
        );
        Ok(())
    }

    #[test]
    fn append_outcome_unknown_poison_requires_replay() -> Result<(), Box<dyn Error>> {
        let mut journal = MemoryJournal::new()?;
        journal.fail_after_append = true;
        let mut ledger = KeyRingLedger::open(journal)?;
        assert!(matches!(
            ledger.bootstrap(KeyEpoch::INITIAL, reason("bootstrap")?),
            Err(KeyLifecycleError::Journal(MemoryError::StaleTail))
        ));
        assert_eq!(ledger.write_state(), KeyLedgerWriteState::ReplayRequired);
        assert!(matches!(
            ledger.stage(KeyEpoch::new(2)?, reason("must-not-continue")?),
            Err(KeyLifecycleError::ReplayRequiredAfterAppendFailure)
        ));

        ledger.recover_after_append_failure()?;
        assert_eq!(ledger.write_state(), KeyLedgerWriteState::Writable);
        assert_eq!(ledger.state().active_epoch(), Some(KeyEpoch::INITIAL));
        let reopened = ledger.reopen()?;
        assert_eq!(reopened.state().active_epoch(), Some(KeyEpoch::INITIAL));
        Ok(())
    }
}
