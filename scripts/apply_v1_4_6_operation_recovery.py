#!/usr/bin/env python3
from pathlib import Path


def replace(path: str, old: str, new: str, expected: int = 1) -> None:
    file = Path(path)
    value = file.read_text(encoding="utf-8")
    actual = value.count(old)
    if actual != expected:
        raise SystemExit(f"{path}: expected {expected} matches, found {actual}: {old[:160]!r}")
    file.write_text(value.replace(old, new, expected), encoding="utf-8")


def replace_between(path: str, start: str, end: str, replacement: str) -> None:
    file = Path(path)
    value = file.read_text(encoding="utf-8")
    first = value.find(start)
    if first < 0:
        raise SystemExit(f"{path}: missing start marker {start!r}")
    second = value.find(end, first)
    if second < 0:
        raise SystemExit(f"{path}: missing end marker {end!r}")
    if value.find(start, first + 1) >= 0:
        raise SystemExit(f"{path}: duplicate start marker {start!r}")
    file.write_text(value[:first] + replacement + value[second:], encoding="utf-8")


# A committed generation encodes its exact predecessor for durable-intent replay.
replace(
    "crates/heptabao-storage-api/src/lib.rs",
    """    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, StorageContractError> {
""",
    """    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn previous(self) -> Option<Self> {
        match self.0.checked_sub(1) {
            Some(0) | None => None,
            Some(value) => Some(Self(value)),
        }
    }

    pub const fn checked_next(self) -> Result<Self, StorageContractError> {
""",
)
replace(
    "crates/heptabao-storage-api/src/lib.rs",
    """            assert!(CommitIntent::new(None, Generation::INITIAL, digest).is_ok());
            assert_eq!(
""",
    """            assert!(CommitIntent::new(None, Generation::INITIAL, digest).is_ok());
            assert_eq!(Generation::INITIAL.previous(), None);
            assert_eq!(
""",
)
replace(
    "crates/heptabao-storage-api/src/lib.rs",
    """            if let Ok(second) = second {
                assert!(CommitIntent::new(Some(Generation::INITIAL), second, digest).is_ok());
            }
""",
    """            if let Ok(second) = second {
                assert_eq!(second.previous(), Some(Generation::INITIAL));
                assert!(CommitIntent::new(Some(Generation::INITIAL), second, digest).is_ok());
            }
""",
)

# Operation-event V2 binds durable intent to the exact state target.
replace(
    "crates/heptabao-operation-ledger/src/lib.rs",
    "const EVENT_MAGIC: &[u8] = b\"HEPTABAO-OPERATION-EVENT-V1\\0\";\nconst EVENT_VERSION: u16 = 1;\n",
    "const EVENT_MAGIC: &[u8] = b\"HEPTABAO-OPERATION-EVENT-V2\\0\";\nconst EVENT_VERSION: u16 = 2;\n",
)
replace(
    "crates/heptabao-operation-ledger/src/lib.rs",
    """    IntentCommitted,
    EffectStarted,
""",
    """    IntentCommitted,
    AbortedBeforeStateCommit,
    EffectStarted,
""",
)
replace(
    "crates/heptabao-operation-ledger/src/lib.rs",
    """            Self::IntentCommitted => 3,
            Self::EffectStarted => 4,
""",
    """            Self::IntentCommitted => 3,
            Self::AbortedBeforeStateCommit => 14,
            Self::EffectStarted => 4,
""",
)
replace(
    "crates/heptabao-operation-ledger/src/lib.rs",
    """            13 => Ok(Self::Reconciled),
            _ => Err(OperationContractError::MalformedEvent),
""",
    """            13 => Ok(Self::Reconciled),
            14 => Ok(Self::AbortedBeforeStateCommit),
            _ => Err(OperationContractError::MalformedEvent),
""",
)
replace(
    "crates/heptabao-operation-ledger/src/lib.rs",
    """                OperationClass::DurableMutation,
                OperationPhase::IntentCommitted,
                OperationPhase::StateCommitted,
            )
""",
    """                OperationClass::DurableMutation,
                OperationPhase::IntentCommitted,
                OperationPhase::StateCommitted | OperationPhase::AbortedBeforeStateCommit,
            )
""",
)
replace(
    "crates/heptabao-operation-ledger/src/lib.rs",
    """    if event.class == OperationClass::DurableMutation && event.effect_key_digest.is_some() {
        return Err(OperationContractError::InvalidEventShape);
    }
    if event.class == OperationClass::ExternalEffect
""",
    """    if event.class == OperationClass::DurableMutation && event.effect_key_digest.is_some() {
        return Err(OperationContractError::InvalidEventShape);
    }
    if event.phase == OperationPhase::AbortedBeforeStateCommit
        && event.class != OperationClass::DurableMutation
    {
        return Err(OperationContractError::InvalidEventShape);
    }
    if event.class == OperationClass::ExternalEffect
""",
)
replace(
    "crates/heptabao-operation-ledger/src/lib.rs",
    """    let state_required = matches!(
        event.phase,
        OperationPhase::StateCommitted
            | OperationPhase::ResponseAudited
            | OperationPhase::ResponseAuditFailedAfterCommit
            | OperationPhase::Delivered
            | OperationPhase::DeliveryFailedAfterCommit
    );
""",
    """    let state_required = (event.class == OperationClass::DurableMutation
        && matches!(
            event.phase,
            OperationPhase::IntentCommitted | OperationPhase::AbortedBeforeStateCommit
        )) || matches!(
        event.phase,
        OperationPhase::StateCommitted
            | OperationPhase::ResponseAudited
            | OperationPhase::ResponseAuditFailedAfterCommit
            | OperationPhase::Delivered
            | OperationPhase::DeliveryFailedAfterCommit
    );
""",
)
replace(
    "crates/heptabao-operation-ledger/src/lib.rs",
    """        OperationPhase::RejectedBeforeDispatch => RetryDirective::SafeToRetryNewOperation,
""",
    """        OperationPhase::RejectedBeforeDispatch | OperationPhase::AbortedBeforeStateCommit => {
            RetryDirective::SafeToRetryNewOperation
        }
""",
)
replace(
    "crates/heptabao-operation-ledger/src/lib.rs",
    """    fn stable_detail(value: &str) -> Result<StableDetailCode, OperationContractError> {
        StableDetailCode::new(value.to_owned())
    }

""",
    """    fn stable_detail(value: &str) -> Result<StableDetailCode, OperationContractError> {
        StableDetailCode::new(value.to_owned())
    }

    fn durable_target() -> Option<(Generation, StateDigest)> {
        StateDigest::new([3; 32])
            .ok()
            .map(|digest| (Generation::INITIAL, digest))
    }

""",
)
replace(
    "crates/heptabao-operation-ledger/src/lib.rs",
    """                        let intent = accepted.next(
                            OperationPhase::IntentCommitted,
                            None,
                            None,
                            None,
                            detail,
                        );
""",
    """                        let intent = accepted.next(
                            OperationPhase::IntentCommitted,
                            durable_target(),
                            None,
                            None,
                            detail,
                        );
""",
)
replace(
    "crates/heptabao-operation-ledger/src/lib.rs",
    """    #[test]
    fn duplicate_acceptance_and_illegal_transition_fail_closed() {
""",
    """    #[test]
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
                                    let operation_id = OperationId::new("operation-0001".to_owned());
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
""",
)

# Journaled core prepares the sealed target before intent publication and recovers only by provider proof.
replace(
    "crates/heptabao-journaled-core/src/lib.rs",
    "use heptabao_storage_api::{CommitReceipt, DurableGenerationStore, Generation};\n",
    "use heptabao_storage_api::{\n    CommitIntent, CommitReceipt, CommitRecovery, DurableGenerationStore, Generation, StateDigest,\n};\n",
)
replace_between(
    "crates/heptabao-journaled-core/src/lib.rs",
    "    pub fn persist_mutation(\n",
    "    pub fn record_rejected_before_dispatch(\n",
    """    pub fn persist_mutation(
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

""",
)
replace_between(
    "crates/heptabao-journaled-core/src/lib.rs",
    "    pub fn reconcile_committed_state(\n",
    "    pub fn record_response_audited(\n",
    """    pub fn recover_durable_intent(
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
        let intent = CommitIntent::new(generation.previous(), generation, digest).map_err(|error| {
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

""",
)
replace(
    "crates/heptabao-journaled-core/src/lib.rs",
    """#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournaledCommitReceipt {
    pub operation_id: OperationId,
    pub commit: CommitReceipt,
}

""",
    """#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournaledCommitReceipt {
    pub operation_id: OperationId,
    pub commit: CommitReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableIntentRecovery {
    Committed(CommitReceipt),
    AbortedBeforeStateCommit { intent: CommitIntent },
}

""",
)
replace(
    "crates/heptabao-journaled-core/src/lib.rs",
    """    OperationMissing,
    StateCommittedLedgerIncomplete {
""",
    """    OperationMissing,
    DurableIntentTargetMissing,
    DurableIntentConflict {
        expected: (Generation, StateDigest),
        actual: Option<(Generation, StateDigest)>,
    },
    StateCommittedLedgerIncomplete {
""",
)
replace(
    "crates/heptabao-journaled-core/src/lib.rs",
    """            Self::OperationMissing => formatter.write_str("operation is missing from the ledger"),
            Self::StateCommittedLedgerIncomplete {
""",
    """            Self::OperationMissing => formatter.write_str("operation is missing from the ledger"),
            Self::DurableIntentTargetMissing => formatter
                .write_str("durable intent is missing its persisted generation and digest target"),
            Self::DurableIntentConflict { expected, actual } => write!(
                formatter,
                "durable intent target generation {} conflicts with authoritative generation {:?}",
                expected.0.get(),
                actual.map(|value| value.0.get())
            ),
            Self::StateCommittedLedgerIncomplete {
""",
)

# Test store can inject a definitely-not-committed dispatch failure.
replace(
    "crates/heptabao-journaled-core/src/lib.rs",
    """        bytes: Vec<u8>,
    }

    impl MemoryStore {
        fn new() -> Result<Self, StorageContractError> {
            Ok(Self {
                domain: StoreDomain::new("heptabao/journaled-core-test".to_owned())?,
                current: None,
                digest: None,
                bytes: Vec::new(),
            })
        }
""",
    """        bytes: Vec<u8>,
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
""",
)
replace(
    "crates/heptabao-journaled-core/src/lib.rs",
    """            if expected_current != self.current {
                return Err(MemoryStoreError::Conflict);
            }
            let committed = match self.current {
""",
    """            if expected_current != self.current {
                return Err(MemoryStoreError::Conflict);
            }
            if self.fail_commit_before_mutation {
                self.fail_commit_before_mutation = false;
                return Err(MemoryStoreError::Conflict);
            }
            let committed = match self.current {
""",
    expected=1,
)
replace(
    "crates/heptabao-journaled-core/src/lib.rs",
    """    fn build_core(
        fail_on_append: Option<usize>,
    ) -> Result<JournaledDurableCore<MemoryStore, MockBarrier, MemoryJournal>, BuildError> {
        let state = DurableStateEngine::new(
            MemoryStore::new().map_err(BuildError::Storage)?,
            MockBarrier,
        );
        let journal = MemoryJournal::new(fail_on_append).map_err(BuildError::Journal)?;
        let ledger = OperationLedger::open(journal).map_err(BuildError::Ledger)?;
        Ok(JournaledDurableCore::new(state, ledger))
    }
""",
    """    fn build_core(
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
""",
)
replace_between(
    "crates/heptabao-journaled-core/src/lib.rs",
    "    #[test]\n    fn postcommit_ledger_failure_returns_committed_generation() {\n",
    "    #[test]\n    fn response_audit_and_delivery_are_durable_ledger_transitions() {\n",
    """    #[test]
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

""",
)
replace_between(
    "crates/heptabao-journaled-core/src/lib.rs",
    "    #[test]\n    fn unresolved_operation_fences_new_generation_until_reconciled() {\n",
    "    #[test]\n    fn accepted_pre_dispatch_failure_can_be_durably_rejected() {\n",
    """    #[test]
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

""",
)

# The inherited V1.4.5 validator accepts only the stronger superseding recovery API.
replace(
    "scripts/validate_plan_v1_4_5.py",
    """        (
            "reconcile_committed_state",
            "generic-reconcile-forbidden",
            "current.class() == OperationClass::DurableMutation",
        ),
""",
    """        (
            "recover_durable_intent",
            "generic-reconcile-forbidden",
            "current.class() == OperationClass::DurableMutation",
        ),
""",
)
replace(
    "scripts/validate_plan_v1_4_5.py",
    """    forbid_tokens(
        errors,
        root,
        "crates/heptabao-journaled-core/src/lib.rs",
        ("pub fn into_parts(self) -> (DurableStateEngine",),
    )
""",
    """    forbid_tokens(
        errors,
        root,
        "crates/heptabao-journaled-core/src/lib.rs",
        (
            "pub fn into_parts(self) -> (DurableStateEngine",
            "pub fn reconcile_committed_state",
        ),
    )
""",
)

print("V1.4.6 operation recovery patch applied")
