#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Durable state mutation composition with an operation reconciliation ledger.
//!
//! An accepted operation and its durable intent are journaled before the state
//! mutation is attempted. A previously observed operation identity is never
//! executed as a new mutation. If state publication succeeds but the matching
//! ledger transition cannot be appended, the committed generation is returned
//! in an explicit incomplete outcome that requires reconciliation.

use std::error::Error;
use std::fmt;

use heptabao_barrier_api::{BarrierProvider, SecretState};
use heptabao_durable_core::{DurableCoreError, DurableStateEngine};
use heptabao_journal_api::DurableJournal;
use heptabao_operation_ledger::{
    OperationClass, OperationContractError, OperationDigest, OperationEvent, OperationId,
    OperationLedger, OperationLedgerError, OperationPhase, RetryDirective, StableDetailCode,
};
use heptabao_storage_api::{
    CommitIntent, CommitReceipt, CommitRecovery, DurableGenerationStore, Generation, StateDigest,
};

pub type JournaledCoreResult<T, S, B, J> = Result<T, JournaledCoreError<S, B, J>>;

pub struct JournaledDurableCore<S, B, J>
where
    J: DurableJournal,
{
    state: DurableStateEngine<S, B>,
    ledger: OperationLedger<J>,
}

impl<S, B, J> JournaledDurableCore<S, B, J>
where
    J: DurableJournal,
{
    pub const fn new(state: DurableStateEngine<S, B>, ledger: OperationLedger<J>) -> Self {
        Self { state, ledger }
    }

    pub const fn state(&self) -> &DurableStateEngine<S, B> {
        &self.state
    }

    pub const fn ledger(&self) -> &OperationLedger<J> {
        &self.ledger
    }
}

impl<S, B, J> fmt::Debug for JournaledDurableCore<S, B, J>
where
    S: fmt::Debug,
    B: fmt::Debug,
    J: DurableJournal,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JournaledDurableCore")
            .field("state", &self.state)
            .field("ledger", &self.ledger)
            .finish()
    }
}

impl<S, B, J> JournaledDurableCore<S, B, J>
where
    S: DurableGenerationStore,
    B: BarrierProvider,
    J: DurableJournal,
{
    pub fn recover_ledger_after_append_failure(
        &mut self,
    ) -> JournaledCoreResult<(), S::Error, B::Error, J::Error> {
        self.ledger
            .recover_after_append_failure()
            .map_err(JournaledCoreError::Ledger)
    }

    pub fn persist_mutation(
        &mut self,
        operation_id: OperationId,
        request_digest: OperationDigest,
        expected_current: Option<Generation>,
        plaintext: SecretState,
        caller_associated_data: Vec<u8>,
    ) -> JournaledCoreResult<JournaledCommitReceipt, S::Error, B::Error, J::Error> {
        if let Some(existing) = self.ledger.current(&operation_id) {
            return Err(JournaledCoreError::ExistingOperation {
                phase: existing.phase(),
                directive: self
                    .ledger
                    .retry_directive(&operation_id)
                    .unwrap_or(RetryDirective::ManualHold),
            });
        }

        if let Some(phase) = self.ledger.blocking_phase() {
            return Err(JournaledCoreError::UnresolvedOperationBlocksMutation { phase });
        }

        let prepared = self
            .state
            .prepare_persist(expected_current, plaintext, caller_associated_data)
            .map_err(JournaledCoreError::DurableState)?;
        let storage_intent = prepared.intent();

        let accepted = OperationEvent::accepted(
            operation_id.clone(),
            request_digest,
            OperationClass::DurableMutation,
            detail_code("request-accepted").map_err(JournaledCoreError::OperationContract)?,
        )
        .map_err(JournaledCoreError::OperationContract)?;
        self.ledger
            .record(accepted.clone())
            .map_err(JournaledCoreError::Ledger)?;

        let intent = accepted
            .next(
                OperationPhase::IntentCommitted,
                Some((storage_intent.committed(), storage_intent.digest())),
                None,
                None,
                detail_code("mutation-intent-bound-to-target")
                    .map_err(JournaledCoreError::OperationContract)?,
            )
            .map_err(JournaledCoreError::OperationContract)?;
        self.ledger
            .record(intent.clone())
            .map_err(JournaledCoreError::Ledger)?;

        let commit = self
            .state
            .commit_prepared(prepared)
            .map_err(JournaledCoreError::DurableState)?;
        let committed = intent
            .next(
                OperationPhase::StateCommitted,
                intent.state(),
                None,
                None,
                detail_code("state-committed").map_err(JournaledCoreError::OperationContract)?,
            )
            .map_err(JournaledCoreError::OperationContract)?;
        if let Err(ledger_error) = self.ledger.record(committed) {
            return Err(JournaledCoreError::StateCommittedLedgerIncomplete {
                commit,
                ledger_error,
            });
        }
        Ok(JournaledCommitReceipt {
            operation_id,
            commit,
        })
    }

    pub fn record_rejected_before_dispatch(
        &mut self,
        operation_id: &OperationId,
        detail: StableDetailCode,
    ) -> JournaledCoreResult<(), S::Error, B::Error, J::Error> {
        let current = self
            .ledger
            .current(operation_id)
            .cloned()
            .ok_or(JournaledCoreError::OperationMissing)?;
        let rejected = current
            .next(
                OperationPhase::RejectedBeforeDispatch,
                None,
                None,
                None,
                detail,
            )
            .map_err(JournaledCoreError::OperationContract)?;
        self.ledger
            .record(rejected)
            .map_err(JournaledCoreError::Ledger)?;
        Ok(())
    }

    pub fn recover_durable_intent(
        &mut self,
        operation_id: &OperationId,
    ) -> JournaledCoreResult<DurableIntentRecovery, S::Error, B::Error, J::Error> {
        if self.ledger.replay_required() {
            self.ledger
                .recover_after_append_failure()
                .map_err(JournaledCoreError::Ledger)?;
        }
        let current = self
            .ledger
            .current(operation_id)
            .cloned()
            .ok_or(JournaledCoreError::OperationMissing)?;
        if current.class() != OperationClass::DurableMutation
            || !matches!(
                current.phase(),
                OperationPhase::IntentCommitted
                    | OperationPhase::StateCommitted
                    | OperationPhase::AbortedBeforeStateCommit
            )
        {
            return Err(JournaledCoreError::OperationContract(
                OperationContractError::InvalidTransition,
            ));
        }
        let (generation, digest) = current
            .state()
            .ok_or(JournaledCoreError::DurableIntentTargetMissing)?;
        let intent =
            CommitIntent::new(generation.previous(), generation, digest).map_err(|error| {
                JournaledCoreError::DurableState(DurableCoreError::StorageContract(error))
            })?;

        match current.phase() {
            OperationPhase::StateCommitted => {
                return Ok(DurableIntentRecovery::Committed(intent.receipt()));
            }
            OperationPhase::AbortedBeforeStateCommit => {
                return Ok(DurableIntentRecovery::AbortedBeforeStateCommit { intent });
            }
            OperationPhase::IntentCommitted => {}
            _ => {
                return Err(JournaledCoreError::OperationContract(
                    OperationContractError::InvalidTransition,
                ));
            }
        }

        match self
            .state
            .recover_commit(intent)
            .map_err(JournaledCoreError::DurableState)?
        {
            CommitRecovery::Committed(receipt) => {
                if receipt != intent.receipt() {
                    return Err(JournaledCoreError::DurableState(
                        DurableCoreError::CommitReceiptMismatch,
                    ));
                }
                let committed = current
                    .next(
                        OperationPhase::StateCommitted,
                        current.state(),
                        None,
                        None,
                        detail_code("state-commit-recovered")
                            .map_err(JournaledCoreError::OperationContract)?,
                    )
                    .map_err(JournaledCoreError::OperationContract)?;
                self.ledger
                    .record(committed)
                    .map_err(JournaledCoreError::Ledger)?;
                Ok(DurableIntentRecovery::Committed(receipt))
            }
            CommitRecovery::NotCommitted => {
                let aborted = current
                    .next(
                        OperationPhase::AbortedBeforeStateCommit,
                        current.state(),
                        None,
                        None,
                        detail_code("state-commit-not-observed")
                            .map_err(JournaledCoreError::OperationContract)?,
                    )
                    .map_err(JournaledCoreError::OperationContract)?;
                self.ledger
                    .record(aborted)
                    .map_err(JournaledCoreError::Ledger)?;
                Ok(DurableIntentRecovery::AbortedBeforeStateCommit { intent })
            }
            CommitRecovery::Conflict { actual } => Err(JournaledCoreError::DurableIntentConflict {
                expected: (generation, digest),
                actual,
            }),
        }
    }

    pub fn record_response_audited(
        &mut self,
        operation_id: &OperationId,
        response_digest: OperationDigest,
    ) -> JournaledCoreResult<(), S::Error, B::Error, J::Error> {
        self.record_response_phase(
            operation_id,
            OperationPhase::ResponseAudited,
            response_digest,
            "response-audited",
        )
    }

    pub fn record_response_audit_failure_after_commit(
        &mut self,
        operation_id: &OperationId,
        response_digest: OperationDigest,
    ) -> JournaledCoreResult<(), S::Error, B::Error, J::Error> {
        self.record_response_phase(
            operation_id,
            OperationPhase::ResponseAuditFailedAfterCommit,
            response_digest,
            "response-audit-failed-after-commit",
        )
    }

    pub fn record_delivery(
        &mut self,
        operation_id: &OperationId,
        delivered: bool,
    ) -> JournaledCoreResult<(), S::Error, B::Error, J::Error> {
        let current = self
            .ledger
            .current(operation_id)
            .cloned()
            .ok_or(JournaledCoreError::OperationMissing)?;
        let response_digest =
            current
                .response_digest()
                .ok_or(JournaledCoreError::OperationContract(
                    OperationContractError::InvalidEventShape,
                ))?;
        let (phase, detail) = if delivered {
            (OperationPhase::Delivered, "response-delivered")
        } else {
            (
                OperationPhase::DeliveryFailedAfterCommit,
                "response-delivery-failed-after-commit",
            )
        };
        let next = current
            .next(
                phase,
                current.state(),
                current.effect_key_digest(),
                Some(response_digest),
                detail_code(detail).map_err(JournaledCoreError::OperationContract)?,
            )
            .map_err(JournaledCoreError::OperationContract)?;
        self.ledger
            .record(next)
            .map_err(JournaledCoreError::Ledger)?;
        Ok(())
    }

    pub fn reconcile(
        &mut self,
        operation_id: &OperationId,
        detail: StableDetailCode,
    ) -> JournaledCoreResult<(), S::Error, B::Error, J::Error> {
        let current = self
            .ledger
            .current(operation_id)
            .cloned()
            .ok_or(JournaledCoreError::OperationMissing)?;
        if current.class() == OperationClass::DurableMutation
            && current.phase() == OperationPhase::IntentCommitted
        {
            return Err(JournaledCoreError::OperationContract(
                OperationContractError::InvalidTransition,
            ));
        }
        let next = current
            .next(
                OperationPhase::Reconciled,
                current.state(),
                current.effect_key_digest(),
                current.response_digest(),
                detail,
            )
            .map_err(JournaledCoreError::OperationContract)?;
        self.ledger
            .record(next)
            .map_err(JournaledCoreError::Ledger)?;
        Ok(())
    }

    fn record_response_phase(
        &mut self,
        operation_id: &OperationId,
        phase: OperationPhase,
        response_digest: OperationDigest,
        detail: &str,
    ) -> JournaledCoreResult<(), S::Error, B::Error, J::Error> {
        let current = self
            .ledger
            .current(operation_id)
            .cloned()
            .ok_or(JournaledCoreError::OperationMissing)?;
        let next = current
            .next(
                phase,
                current.state(),
                current.effect_key_digest(),
                Some(response_digest),
                detail_code(detail).map_err(JournaledCoreError::OperationContract)?,
            )
            .map_err(JournaledCoreError::OperationContract)?;
        self.ledger
            .record(next)
            .map_err(JournaledCoreError::Ledger)?;
        Ok(())
    }
}

fn detail_code(value: &str) -> Result<StableDetailCode, OperationContractError> {
    StableDetailCode::new(value.to_owned())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournaledCommitReceipt {
    pub operation_id: OperationId,
    pub commit: CommitReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableIntentRecovery {
    Committed(CommitReceipt),
    AbortedBeforeStateCommit { intent: CommitIntent },
}

#[derive(Debug)]
pub enum JournaledCoreError<S, B, J>
where
    S: Error + Send + Sync + 'static,
    B: Error + Send + Sync + 'static,
    J: Error + Send + Sync + 'static,
{
    OperationContract(OperationContractError),
    Ledger(OperationLedgerError<J>),
    DurableState(DurableCoreError<S, B>),
    ExistingOperation {
        phase: OperationPhase,
        directive: RetryDirective,
    },
    UnresolvedOperationBlocksMutation {
        phase: OperationPhase,
    },
    OperationMissing,
    DurableIntentTargetMissing,
    DurableIntentConflict {
        expected: (Generation, StateDigest),
        actual: Option<(Generation, StateDigest)>,
    },
    StateCommittedLedgerIncomplete {
        commit: CommitReceipt,
        ledger_error: OperationLedgerError<J>,
    },
}

impl<S, B, J> fmt::Display for JournaledCoreError<S, B, J>
where
    S: Error + Send + Sync + 'static,
    B: Error + Send + Sync + 'static,
    J: Error + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OperationContract(error) => {
                write!(formatter, "operation contract failure: {error}")
            }
            Self::Ledger(error) => write!(formatter, "operation ledger failure: {error}"),
            Self::DurableState(error) => write!(formatter, "durable state failure: {error}"),
            Self::ExistingOperation { phase, directive } => write!(
                formatter,
                "operation already exists at phase {phase:?}; retry directive is {directive:?}"
            ),
            Self::UnresolvedOperationBlocksMutation { phase } => write!(
                formatter,
                "unresolved operation at phase {phase:?} fences every new mutation"
            ),
            Self::OperationMissing => formatter.write_str("operation is missing from the ledger"),
            Self::DurableIntentTargetMissing => formatter
                .write_str("durable intent is missing its persisted generation and digest target"),
            Self::DurableIntentConflict { expected, actual } => write!(
                formatter,
                "durable intent target generation {} conflicts with authoritative generation {:?}",
                expected.0.get(),
                actual.map(|value| value.0.get())
            ),
            Self::StateCommittedLedgerIncomplete {
                commit,
                ledger_error,
            } => write!(
                formatter,
                "state generation {} committed but ledger transition failed: {ledger_error}",
                commit.committed.get()
            ),
        }
    }
}

impl<S, B, J> Error for JournaledCoreError<S, B, J>
where
    S: Error + Send + Sync + 'static,
    B: Error + Send + Sync + 'static,
    J: Error + Send + Sync + 'static,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use heptabao_barrier_api::{BarrierContext, BarrierContractError, KeyEpoch, SealedEnvelope};
    use heptabao_journal_api::{
        AppendFailureDisposition, AppendReceipt, JournalContractError, JournalDomain,
        JournalOpenMode, JournalPayload, JournalRecord, JournalSequence, JournalTag, JournalTail,
    };
    use heptabao_storage_api::{
        CommitIntent, CommitRecovery, GenerationSnapshot, OpaqueState, StateDigest,
        StorageContractError, StoreDomain, StoreOpenMode,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MemoryStoreError {
        Contract(StorageContractError),
        Conflict,
    }

    impl fmt::Display for MemoryStoreError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Contract(error) => write!(formatter, "memory store contract: {error}"),
                Self::Conflict => formatter.write_str("memory store conflict"),
            }
        }
    }

    impl Error for MemoryStoreError {}

    #[derive(Debug)]
    struct MemoryStore {
        domain: StoreDomain,
        current: Option<Generation>,
        digest: Option<StateDigest>,
        bytes: Vec<u8>,
        fail_commit_before_mutation: bool,
    }

    impl MemoryStore {
        fn new(fail_commit_before_mutation: bool) -> Result<Self, StorageContractError> {
            Ok(Self {
                domain: StoreDomain::new("heptabao/journaled-core-test".to_owned())?,
                current: None,
                digest: None,
                bytes: Vec::new(),
                fail_commit_before_mutation,
            })
        }
    }

    impl Drop for MemoryStore {
        fn drop(&mut self) {
            self.bytes.fill(0);
        }
    }

    impl DurableGenerationStore for MemoryStore {
        type Error = MemoryStoreError;

        fn domain(&self) -> &StoreDomain {
            &self.domain
        }

        fn open_mode(&self) -> StoreOpenMode {
            StoreOpenMode::CreateNew
        }

        fn current_generation(&self) -> Option<Generation> {
            self.current
        }

        fn load_current(&self) -> Result<Option<GenerationSnapshot>, Self::Error> {
            let (Some(generation), Some(digest)) = (self.current, self.digest) else {
                return Ok(None);
            };
            let state = OpaqueState::new(self.bytes.clone()).map_err(MemoryStoreError::Contract)?;
            Ok(Some(GenerationSnapshot {
                generation,
                digest,
                state,
            }))
        }

        fn prepare_commit(
            &self,
            expected_current: Option<Generation>,
            candidate: &OpaqueState,
        ) -> Result<CommitIntent, Self::Error> {
            if expected_current != self.current {
                return Err(MemoryStoreError::Conflict);
            }
            let committed = match self.current {
                Some(value) => value.checked_next().map_err(MemoryStoreError::Contract)?,
                None => Generation::INITIAL,
            };
            let digest = state_digest(committed, candidate.as_bytes())?;
            CommitIntent::new(expected_current, committed, digest)
                .map_err(MemoryStoreError::Contract)
        }

        fn recover_commit(&mut self, intent: CommitIntent) -> Result<CommitRecovery, Self::Error> {
            match (self.current, self.digest) {
                (Some(generation), Some(digest))
                    if generation == intent.committed() && digest == intent.digest() =>
                {
                    Ok(CommitRecovery::Committed(intent.receipt()))
                }
                (generation, _) if generation == intent.previous() => {
                    Ok(CommitRecovery::NotCommitted)
                }
                (Some(generation), Some(digest)) => Ok(CommitRecovery::Conflict {
                    actual: Some((generation, digest)),
                }),
                _ => Ok(CommitRecovery::Conflict { actual: None }),
            }
        }

        fn commit(
            &mut self,
            expected_current: Option<Generation>,
            candidate: OpaqueState,
        ) -> Result<CommitReceipt, Self::Error> {
            if expected_current != self.current {
                return Err(MemoryStoreError::Conflict);
            }
            if self.fail_commit_before_mutation {
                self.fail_commit_before_mutation = false;
                return Err(MemoryStoreError::Conflict);
            }
            let committed = match self.current {
                Some(value) => value.checked_next().map_err(MemoryStoreError::Contract)?,
                None => Generation::INITIAL,
            };
            let bytes = candidate.into_bytes();
            let digest = state_digest(committed, &bytes)?;
            self.bytes.fill(0);
            self.bytes = bytes;
            let previous = self.current;
            self.current = Some(committed);
            self.digest = Some(digest);
            Ok(CommitReceipt {
                previous,
                committed,
                digest,
            })
        }
    }

    fn state_digest(generation: Generation, bytes: &[u8]) -> Result<StateDigest, MemoryStoreError> {
        let mut output = [0_u8; 32];
        for (index, byte) in generation
            .get()
            .to_be_bytes()
            .into_iter()
            .chain(bytes.iter().copied())
            .enumerate()
        {
            let slot = index % output.len();
            output[slot] = output[slot]
                .wrapping_add(byte)
                .rotate_left((slot % 5) as u32);
        }
        if output == [0; 32] {
            output[0] = 1;
        }
        StateDigest::new(output).map_err(MemoryStoreError::Contract)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockBarrierError {
        Contract(BarrierContractError),
        Authentication,
    }

    impl fmt::Display for MockBarrierError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Contract(error) => write!(formatter, "mock barrier contract: {error}"),
                Self::Authentication => formatter.write_str("mock barrier authentication failure"),
            }
        }
    }

    impl Error for MockBarrierError {}

    #[derive(Debug)]
    struct MockBarrier;

    impl BarrierProvider for MockBarrier {
        type Error = MockBarrierError;

        fn active_key_epoch(&self) -> Result<KeyEpoch, Self::Error> {
            Ok(KeyEpoch::INITIAL)
        }

        fn seal(
            &self,
            context: &BarrierContext,
            plaintext: SecretState,
        ) -> Result<SealedEnvelope, Self::Error> {
            let mut aad = context
                .canonical_associated_data()
                .map_err(MockBarrierError::Contract)?;
            let mut clear = plaintext.into_bytes();
            let ciphertext = clear
                .iter()
                .copied()
                .map(|byte| byte ^ 0x5a)
                .collect::<Vec<_>>();
            clear.fill(0);
            let tag = mock_tag(&aad, &ciphertext);
            aad.fill(0);
            SealedEnvelope::new(
                heptabao_barrier_api::SEALED_ENVELOPE_VERSION,
                context.key_epoch(),
                b"journaled-core-nonce".to_vec(),
                ciphertext,
                tag,
            )
            .map_err(MockBarrierError::Contract)
        }

        fn open(
            &self,
            context: &BarrierContext,
            envelope: SealedEnvelope,
        ) -> Result<SecretState, Self::Error> {
            let mut aad = context
                .canonical_associated_data()
                .map_err(MockBarrierError::Contract)?;
            let expected = mock_tag(&aad, envelope.ciphertext());
            aad.fill(0);
            if expected.as_slice() != envelope.authentication_tag() {
                return Err(MockBarrierError::Authentication);
            }
            let clear = envelope
                .ciphertext()
                .iter()
                .copied()
                .map(|byte| byte ^ 0x5a)
                .collect::<Vec<_>>();
            SecretState::new(clear).map_err(MockBarrierError::Contract)
        }
    }

    fn mock_tag(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        let mut output = vec![0_u8; 32];
        for (index, byte) in aad
            .iter()
            .copied()
            .chain(ciphertext.iter().copied())
            .enumerate()
        {
            let slot = index % output.len();
            output[slot] = output[slot]
                .wrapping_add(byte)
                .rotate_left((slot % 7) as u32);
        }
        if output.iter().all(|byte| *byte == 0) {
            output[0] = 1;
        }
        output
    }

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
        fn new(fail_on_append: Option<usize>) -> Result<Self, JournalContractError> {
            Ok(Self {
                domain: JournalDomain::new("heptabao/journaled-core-ledger".to_owned())?,
                payloads: Vec::new(),
                fail_on_append,
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
            Some(JournalTail {
                sequence,
                tag: journal_tag(sequence).ok()?,
            })
        }

        fn replay(&self) -> Result<Vec<JournalRecord>, Self::Error> {
            let mut records = Vec::new();
            let mut previous_tag = None;
            for (index, payload) in self.payloads.iter().enumerate() {
                let value = u64::try_from(index + 1).map_err(|_| MemoryJournalError::Injected)?;
                let sequence = JournalSequence::new(value).map_err(MemoryJournalError::Contract)?;
                let tag = journal_tag(sequence)?;
                records.push(JournalRecord {
                    sequence,
                    previous_tag,
                    tag,
                    payload: JournalPayload::new(payload.clone())
                        .map_err(MemoryJournalError::Contract)?,
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
            if self.fail_on_append == Some(self.calls) {
                return Err(MemoryJournalError::Injected);
            }
            let previous_tail = self.tail();
            if expected_tail != previous_tail.map(|tail| tail.sequence) {
                return Err(MemoryJournalError::Injected);
            }
            let value =
                u64::try_from(self.payloads.len() + 1).map_err(|_| MemoryJournalError::Injected)?;
            let sequence = JournalSequence::new(value).map_err(MemoryJournalError::Contract)?;
            let appended = JournalTail {
                sequence,
                tag: journal_tag(sequence)?,
            };
            self.payloads.push(payload.into_bytes());
            Ok(AppendReceipt {
                previous_tail,
                appended,
            })
        }

        fn classify_append_failure(&self, _error: &Self::Error) -> AppendFailureDisposition {
            AppendFailureDisposition::DefinitelyNotAppended
        }
    }

    fn journal_tag(sequence: JournalSequence) -> Result<JournalTag, MemoryJournalError> {
        let mut value = [0_u8; 32];
        value[..8].copy_from_slice(&sequence.get().to_be_bytes());
        JournalTag::new(value).map_err(MemoryJournalError::Contract)
    }

    fn operation_id() -> Result<OperationId, OperationContractError> {
        OperationId::new("journaled-operation-0001".to_owned())
    }

    fn request_digest() -> Result<OperationDigest, OperationContractError> {
        OperationDigest::new([7; 32])
    }

    fn build_core(
        fail_on_append: Option<usize>,
    ) -> Result<JournaledDurableCore<MemoryStore, MockBarrier, MemoryJournal>, BuildError> {
        build_core_with_commit_failure(fail_on_append, false)
    }

    fn build_core_with_commit_failure(
        fail_on_append: Option<usize>,
        fail_commit_before_mutation: bool,
    ) -> Result<JournaledDurableCore<MemoryStore, MockBarrier, MemoryJournal>, BuildError> {
        let state = DurableStateEngine::new(
            MemoryStore::new(fail_commit_before_mutation).map_err(BuildError::Storage)?,
            MockBarrier,
        );
        let journal = MemoryJournal::new(fail_on_append).map_err(BuildError::Journal)?;
        let ledger = OperationLedger::open(journal).map_err(BuildError::Ledger)?;
        Ok(JournaledDurableCore::new(state, ledger))
    }

    #[derive(Debug)]
    enum BuildError {
        Storage(StorageContractError),
        Journal(JournalContractError),
        Ledger(OperationLedgerError<MemoryJournalError>),
    }

    impl fmt::Display for BuildError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Storage(error) => write!(formatter, "build storage: {error}"),
                Self::Journal(error) => write!(formatter, "build journal: {error}"),
                Self::Ledger(error) => write!(formatter, "build ledger: {error}"),
            }
        }
    }

    impl Error for BuildError {}

    #[test]
    fn intent_precedes_state_commit_and_duplicate_never_mutates_again() {
        let core = build_core(None);
        assert!(core.is_ok());
        if let Ok(mut core) = core {
            let operation_id = operation_id();
            let request_digest = request_digest();
            let secret = SecretState::new(b"first-state".to_vec());
            assert!(operation_id.is_ok());
            assert!(request_digest.is_ok());
            assert!(secret.is_ok());
            if let (Ok(operation_id), Ok(request_digest), Ok(secret)) =
                (operation_id, request_digest, secret)
            {
                let result = core.persist_mutation(
                    operation_id.clone(),
                    request_digest,
                    None,
                    secret,
                    b"tenant-a".to_vec(),
                );
                assert!(result.is_ok());
                assert_eq!(
                    core.ledger()
                        .current(&operation_id)
                        .map(OperationEvent::phase),
                    Some(OperationPhase::StateCommitted)
                );
                assert_eq!(
                    core.state().store().current_generation(),
                    Some(Generation::INITIAL)
                );
                let second_secret = SecretState::new(b"second-state".to_vec());
                assert!(second_secret.is_ok());
                if let Ok(second_secret) = second_secret {
                    let duplicate = core.persist_mutation(
                        operation_id,
                        request_digest,
                        Some(Generation::INITIAL),
                        second_secret,
                        b"tenant-a".to_vec(),
                    );
                    assert!(matches!(
                        duplicate,
                        Err(JournaledCoreError::ExistingOperation {
                            directive: RetryDirective::LookupOnly,
                            ..
                        })
                    ));
                    assert_eq!(
                        core.state().store().current_generation(),
                        Some(Generation::INITIAL)
                    );
                }
            }
        }
    }

    #[test]
    fn postcommit_ledger_failure_is_recovered_from_persisted_target_not_caller_receipt() {
        let core = build_core(Some(3));
        assert!(core.is_ok());
        if let Ok(mut core) = core {
            let operation_id = operation_id();
            let request_digest = request_digest();
            let secret = SecretState::new(b"committed-before-ledger".to_vec());
            if let (Ok(operation_id), Ok(request_digest), Ok(secret)) =
                (operation_id, request_digest, secret)
            {
                let result = core.persist_mutation(
                    operation_id.clone(),
                    request_digest,
                    None,
                    secret,
                    Vec::new(),
                );
                assert!(matches!(
                    result,
                    Err(JournaledCoreError::StateCommittedLedgerIncomplete { .. })
                ));
                assert_eq!(
                    core.state().store().current_generation(),
                    Some(Generation::INITIAL)
                );
                assert_eq!(
                    core.ledger().retry_directive(&operation_id),
                    Some(RetryDirective::ReconcileOnly)
                );
                let generic_detail =
                    StableDetailCode::new("generic-reconcile-forbidden".to_owned());
                assert!(generic_detail.is_ok());
                if let Ok(generic_detail) = generic_detail {
                    assert!(matches!(
                        core.reconcile(&operation_id, generic_detail),
                        Err(JournaledCoreError::OperationContract(
                            OperationContractError::InvalidTransition
                        ))
                    ));
                }
                let recovered = core.recover_durable_intent(&operation_id);
                assert!(matches!(
                    recovered,
                    Ok(DurableIntentRecovery::Committed(receipt))
                        if receipt.committed == Generation::INITIAL
                ));
                assert_eq!(
                    core.ledger().retry_directive(&operation_id),
                    Some(RetryDirective::LookupOnly)
                );
            }
        }
    }

    #[test]
    fn definitely_uncommitted_intent_is_durably_aborted_before_unfencing() {
        let core = build_core_with_commit_failure(None, true);
        assert!(core.is_ok());
        if let Ok(mut core) = core {
            let operation_id = operation_id();
            let request_digest = request_digest();
            let secret = SecretState::new(b"never-committed".to_vec());
            if let (Ok(operation_id), Ok(request_digest), Ok(secret)) =
                (operation_id, request_digest, secret)
            {
                assert!(matches!(
                    core.persist_mutation(
                        operation_id.clone(),
                        request_digest,
                        None,
                        secret,
                        Vec::new(),
                    ),
                    Err(JournaledCoreError::DurableState(_))
                ));
                assert_eq!(
                    core.ledger().blocking_phase(),
                    Some(OperationPhase::IntentCommitted)
                );
                assert_eq!(core.state().store().current_generation(), None);
                let recovered = core.recover_durable_intent(&operation_id);
                assert!(matches!(
                    recovered,
                    Ok(DurableIntentRecovery::AbortedBeforeStateCommit { .. })
                ));
                assert_eq!(core.ledger().blocking_phase(), None);
                assert_eq!(
                    core.ledger().retry_directive(&operation_id),
                    Some(RetryDirective::SafeToRetryNewOperation)
                );
            }
        }
    }

    #[test]
    fn response_audit_and_delivery_are_durable_ledger_transitions() {
        let core = build_core(None);
        assert!(core.is_ok());
        if let Ok(mut core) = core {
            let operation_id = operation_id();
            let request_digest = request_digest();
            let secret = SecretState::new(b"state".to_vec());
            if let (Ok(operation_id), Ok(request_digest), Ok(secret)) =
                (operation_id, request_digest, secret)
            {
                assert!(
                    core.persist_mutation(
                        operation_id.clone(),
                        request_digest,
                        None,
                        secret,
                        Vec::new(),
                    )
                    .is_ok()
                );
                let response_digest = OperationDigest::new([8; 32]);
                assert!(response_digest.is_ok());
                if let Ok(response_digest) = response_digest {
                    assert!(
                        core.record_response_audited(&operation_id, response_digest)
                            .is_ok()
                    );
                    assert!(core.record_delivery(&operation_id, false).is_ok());
                    assert_eq!(
                        core.ledger().retry_directive(&operation_id),
                        Some(RetryDirective::ReconcileOnly)
                    );
                }
            }
        }
    }

    #[test]
    fn unresolved_operation_fences_new_generation_until_provider_recovery() {
        let core = build_core(Some(3));
        assert!(core.is_ok());
        if let Ok(mut core) = core {
            let first_id = operation_id();
            let first_digest = request_digest();
            let first_secret = SecretState::new(b"first-committed-state".to_vec());
            if let (Ok(first_id), Ok(first_digest), Ok(first_secret)) =
                (first_id, first_digest, first_secret)
            {
                assert!(matches!(
                    core.persist_mutation(
                        first_id.clone(),
                        first_digest,
                        None,
                        first_secret,
                        Vec::new(),
                    ),
                    Err(JournaledCoreError::StateCommittedLedgerIncomplete { .. })
                ));
                let second_id = OperationId::new("journaled-operation-0002".to_owned());
                let second_digest = OperationDigest::new([0x22; 32]);
                let second_secret = SecretState::new(b"must-not-advance".to_vec());
                if let (Ok(second_id), Ok(second_digest), Ok(second_secret)) =
                    (second_id, second_digest, second_secret)
                {
                    assert!(matches!(
                        core.persist_mutation(
                            second_id.clone(),
                            second_digest,
                            Some(Generation::INITIAL),
                            second_secret,
                            Vec::new(),
                        ),
                        Err(JournaledCoreError::UnresolvedOperationBlocksMutation {
                            phase: OperationPhase::IntentCommitted
                        })
                    ));
                    assert_eq!(
                        core.state().store().current_generation(),
                        Some(Generation::INITIAL)
                    );
                    assert!(matches!(
                        core.recover_durable_intent(&first_id),
                        Ok(DurableIntentRecovery::Committed(_))
                    ));
                    let second_secret = SecretState::new(b"second-committed-state".to_vec());
                    assert!(second_secret.is_ok());
                    if let Ok(second_secret) = second_secret {
                        assert!(
                            core.persist_mutation(
                                second_id,
                                second_digest,
                                Some(Generation::INITIAL),
                                second_secret,
                                Vec::new(),
                            )
                            .is_ok()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn accepted_pre_dispatch_failure_can_be_durably_rejected() {
        let core = build_core(Some(2));
        assert!(core.is_ok());
        if let Ok(mut core) = core {
            let first_id = operation_id();
            let first_digest = request_digest();
            let first_secret = SecretState::new(b"never-dispatched".to_vec());
            if let (Ok(first_id), Ok(first_digest), Ok(first_secret)) =
                (first_id, first_digest, first_secret)
            {
                assert!(matches!(
                    core.persist_mutation(
                        first_id.clone(),
                        first_digest,
                        None,
                        first_secret,
                        Vec::new(),
                    ),
                    Err(JournaledCoreError::Ledger(_))
                ));
                assert_eq!(
                    core.ledger().blocking_phase(),
                    Some(OperationPhase::Accepted)
                );
                let detail = StableDetailCode::new("intent-not-published".to_owned());
                assert!(detail.is_ok());
                if let Ok(detail) = detail {
                    assert!(
                        core.record_rejected_before_dispatch(&first_id, detail)
                            .is_ok()
                    );
                    assert_eq!(core.ledger().blocking_phase(), None);
                }
            }
        }
    }
}
