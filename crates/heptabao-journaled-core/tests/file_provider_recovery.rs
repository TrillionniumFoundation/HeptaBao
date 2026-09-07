#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use heptabao_barrier_api::{
    BarrierContext, BarrierProvider, KeyEpoch, SEALED_ENVELOPE_VERSION, SealedEnvelope, SecretState,
};
use heptabao_durable_core::DurableStateEngine;
use heptabao_journal_api::{
    AppendFailureDisposition, AppendReceipt, AuthenticatorId, DurableJournal, JournalAuthenticator,
    JournalDomain, JournalOpenMode, JournalPayload, JournalRecord, JournalSequence, JournalTag,
    JournalTail,
};
use heptabao_journaled_core::{DurableIntentRecovery, JournaledCoreError, JournaledDurableCore};
use heptabao_operation_ledger::{
    OperationDigest, OperationId, OperationLedger, OperationPhase, RetryDirective,
};
use heptabao_single_node_journal::{FileDurableJournal, FileJournalError};
use heptabao_single_node_store::{FileGenerationStore, FileStoreError};
use heptabao_storage_api::{
    CommitIntent, CommitReceipt, CommitRecovery, DurableGenerationStore, Generation,
    GenerationSnapshot, IntegrityAlgorithmId, IntegrityProvider, OpaqueState, StateDigest,
    StoreDomain, StoreOpenMode,
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TestProviderError;

impl fmt::Display for TestProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("deterministic test provider failure")
    }
}

impl Error for TestProviderError {}

fn absorb(output: &mut [u8; 32], input: &[u8]) {
    for (index, byte) in input.iter().copied().enumerate() {
        let slot = index % output.len();
        output[slot] = output[slot]
            .wrapping_add(byte)
            .rotate_left(u32::try_from((index % 7) + 1).unwrap_or(1));
        output[(slot + 11) % output.len()] ^= byte.wrapping_mul(31);
    }
    output[0] |= 1;
}

#[derive(Clone, Debug)]
struct TestIntegrity {
    algorithm_id: IntegrityAlgorithmId,
}

impl TestIntegrity {
    fn new() -> Result<Self, TestProviderError> {
        let algorithm_id = IntegrityAlgorithmId::new("test-digest-v1".to_owned())
            .map_err(|_| TestProviderError)?;
        Ok(Self { algorithm_id })
    }
}

impl IntegrityProvider for TestIntegrity {
    type Error = TestProviderError;

    fn algorithm_id(&self) -> &IntegrityAlgorithmId {
        &self.algorithm_id
    }

    fn digest(
        &self,
        domain: &StoreDomain,
        generation: Generation,
        state: &[u8],
    ) -> Result<StateDigest, Self::Error> {
        let mut output = [0_u8; 32];
        absorb(&mut output, domain.as_str().as_bytes());
        absorb(&mut output, &generation.get().to_be_bytes());
        absorb(&mut output, state);
        StateDigest::new(output).map_err(|_| TestProviderError)
    }
}

#[derive(Clone, Debug)]
struct TestJournalAuthenticator {
    authenticator_id: AuthenticatorId,
}

impl TestJournalAuthenticator {
    fn new() -> Result<Self, TestProviderError> {
        let authenticator_id = AuthenticatorId::new("test-journal-auth-v1".to_owned())
            .map_err(|_| TestProviderError)?;
        Ok(Self { authenticator_id })
    }
}

impl JournalAuthenticator for TestJournalAuthenticator {
    type Error = TestProviderError;

    fn authenticator_id(&self) -> &AuthenticatorId {
        &self.authenticator_id
    }

    fn authenticate(
        &self,
        domain: &JournalDomain,
        sequence: JournalSequence,
        previous_tag: Option<JournalTag>,
        payload: &[u8],
    ) -> Result<JournalTag, Self::Error> {
        let mut output = [0_u8; 32];
        absorb(&mut output, domain.as_str().as_bytes());
        absorb(&mut output, &sequence.get().to_be_bytes());
        match previous_tag {
            Some(tag) => absorb(&mut output, &tag.bytes()),
            None => absorb(&mut output, &[0]),
        }
        absorb(&mut output, payload);
        JournalTag::new(output).map_err(|_| TestProviderError)
    }
}

#[derive(Clone, Copy, Debug)]
struct TestBarrier;

impl BarrierProvider for TestBarrier {
    type Error = TestProviderError;

    fn active_key_epoch(&self) -> Result<KeyEpoch, Self::Error> {
        Ok(KeyEpoch::INITIAL)
    }

    fn seal(
        &self,
        context: &BarrierContext,
        plaintext: SecretState,
    ) -> Result<SealedEnvelope, Self::Error> {
        let mut ciphertext = plaintext.into_bytes();
        for byte in &mut ciphertext {
            *byte ^= 0xa5;
        }
        let nonce = context.generation().get().to_be_bytes().to_vec();
        let mut tag = [0_u8; 32];
        let associated_data = context
            .canonical_associated_data()
            .map_err(|_| TestProviderError)?;
        absorb(&mut tag, &associated_data);
        absorb(&mut tag, &ciphertext);
        SealedEnvelope::new(
            SEALED_ENVELOPE_VERSION,
            KeyEpoch::INITIAL,
            nonce,
            ciphertext,
            tag.to_vec(),
        )
        .map_err(|_| TestProviderError)
    }

    fn open(
        &self,
        _context: &BarrierContext,
        envelope: SealedEnvelope,
    ) -> Result<SecretState, Self::Error> {
        let mut plaintext = envelope.ciphertext().to_vec();
        for byte in &mut plaintext {
            *byte ^= 0xa5;
        }
        SecretState::new(plaintext).map_err(|_| TestProviderError)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreFault {
    None,
    BeforeCommitOnce,
    AfterCommitOnce,
}

#[derive(Debug)]
enum FaultStoreError {
    Provider(FileStoreError<TestProviderError>),
    InjectedBeforeCommit,
    InjectedAfterCommit,
}

impl fmt::Display for FaultStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(formatter, "file store failure: {error}"),
            Self::InjectedBeforeCommit => {
                formatter.write_str("injected failure before file store commit")
            }
            Self::InjectedAfterCommit => {
                formatter.write_str("injected outcome unknown after file store commit")
            }
        }
    }
}

impl Error for FaultStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Provider(error) => Some(error),
            Self::InjectedBeforeCommit | Self::InjectedAfterCommit => None,
        }
    }
}

#[derive(Debug)]
struct FaultStore {
    inner: FileGenerationStore<TestIntegrity>,
    fault: StoreFault,
}

impl FaultStore {
    const fn new(inner: FileGenerationStore<TestIntegrity>, fault: StoreFault) -> Self {
        Self { inner, fault }
    }
}

impl DurableGenerationStore for FaultStore {
    type Error = FaultStoreError;

    fn domain(&self) -> &StoreDomain {
        self.inner.domain()
    }

    fn open_mode(&self) -> StoreOpenMode {
        self.inner.open_mode()
    }

    fn current_generation(&self) -> Option<Generation> {
        self.inner.current_generation()
    }

    fn load_current(&self) -> Result<Option<GenerationSnapshot>, Self::Error> {
        self.inner.load_current().map_err(FaultStoreError::Provider)
    }

    fn prepare_commit(
        &self,
        expected_current: Option<Generation>,
        candidate: &OpaqueState,
    ) -> Result<CommitIntent, Self::Error> {
        self.inner
            .prepare_commit(expected_current, candidate)
            .map_err(FaultStoreError::Provider)
    }

    fn recover_commit(&mut self, intent: CommitIntent) -> Result<CommitRecovery, Self::Error> {
        self.inner
            .recover_commit(intent)
            .map_err(FaultStoreError::Provider)
    }

    fn commit(
        &mut self,
        expected_current: Option<Generation>,
        candidate: OpaqueState,
    ) -> Result<CommitReceipt, Self::Error> {
        if self.fault == StoreFault::BeforeCommitOnce {
            self.fault = StoreFault::None;
            return Err(FaultStoreError::InjectedBeforeCommit);
        }
        let receipt = self
            .inner
            .commit(expected_current, candidate)
            .map_err(FaultStoreError::Provider)?;
        if self.fault == StoreFault::AfterCommitOnce {
            self.fault = StoreFault::None;
            return Err(FaultStoreError::InjectedAfterCommit);
        }
        Ok(receipt)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalFault {
    None,
    BeforeAppendOnce(usize),
    AfterAppendOnce(usize),
}

#[derive(Debug)]
enum FaultJournalError {
    Provider(FileJournalError<TestProviderError>),
    InjectedBeforeAppend,
    InjectedAfterAppend,
}

impl fmt::Display for FaultJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(formatter, "file journal failure: {error}"),
            Self::InjectedBeforeAppend => {
                formatter.write_str("injected definitely-not-appended journal failure")
            }
            Self::InjectedAfterAppend => {
                formatter.write_str("injected outcome unknown after journal append")
            }
        }
    }
}

impl Error for FaultJournalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Provider(error) => Some(error),
            Self::InjectedBeforeAppend | Self::InjectedAfterAppend => None,
        }
    }
}

#[derive(Debug)]
struct FaultJournal {
    inner: FileDurableJournal<TestJournalAuthenticator>,
    fault: JournalFault,
    append_calls: usize,
}

impl FaultJournal {
    const fn new(inner: FileDurableJournal<TestJournalAuthenticator>, fault: JournalFault) -> Self {
        Self {
            inner,
            fault,
            append_calls: 0,
        }
    }
}

impl DurableJournal for FaultJournal {
    type Error = FaultJournalError;

    fn domain(&self) -> &JournalDomain {
        self.inner.domain()
    }

    fn open_mode(&self) -> JournalOpenMode {
        self.inner.open_mode()
    }

    fn tail(&self) -> Option<JournalTail> {
        self.inner.tail()
    }

    fn replay(&self) -> Result<Vec<JournalRecord>, Self::Error> {
        self.inner.replay().map_err(FaultJournalError::Provider)
    }

    fn recover_authoritative(&mut self) -> Result<Vec<JournalRecord>, Self::Error> {
        self.inner
            .recover_authoritative()
            .map_err(FaultJournalError::Provider)
    }

    fn append(
        &mut self,
        expected_tail: Option<JournalSequence>,
        payload: JournalPayload,
    ) -> Result<AppendReceipt, Self::Error> {
        self.append_calls = self.append_calls.saturating_add(1);
        if self.fault == JournalFault::BeforeAppendOnce(self.append_calls) {
            self.fault = JournalFault::None;
            return Err(FaultJournalError::InjectedBeforeAppend);
        }
        let receipt = self
            .inner
            .append(expected_tail, payload)
            .map_err(FaultJournalError::Provider)?;
        if self.fault == JournalFault::AfterAppendOnce(self.append_calls) {
            self.fault = JournalFault::None;
            return Err(FaultJournalError::InjectedAfterAppend);
        }
        Ok(receipt)
    }

    fn classify_append_failure(&self, error: &Self::Error) -> AppendFailureDisposition {
        match error {
            FaultJournalError::InjectedBeforeAppend => {
                AppendFailureDisposition::DefinitelyNotAppended
            }
            FaultJournalError::InjectedAfterAppend => AppendFailureDisposition::OutcomeUnknown,
            FaultJournalError::Provider(error) => self.inner.classify_append_failure(error),
        }
    }
}

type TestCore = JournaledDurableCore<FaultStore, TestBarrier, FaultJournal>;

#[derive(Debug)]
struct TempTree {
    root: PathBuf,
    store: PathBuf,
    journal: PathBuf,
}

impl TempTree {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heptabao-journaled-file-recovery-{}-{sequence}",
            std::process::id()
        ));
        let store = root.join("store");
        let journal = root.join("journal");
        fs::create_dir_all(&store)?;
        fs::create_dir_all(&journal)?;
        Ok(Self {
            root,
            store,
            journal,
        })
    }

    fn store_path(&self) -> &Path {
        &self.store
    }

    fn journal_path(&self) -> &Path {
        &self.journal
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn store_domain() -> Result<StoreDomain, Box<dyn Error>> {
    Ok(StoreDomain::new("heptabao/file-recovery-test".to_owned())?)
}

fn journal_domain() -> Result<JournalDomain, Box<dyn Error>> {
    Ok(JournalDomain::new(
        "heptabao/file-recovery-journal".to_owned(),
    )?)
}

fn create_core(
    tree: &TempTree,
    store_fault: StoreFault,
    journal_fault: JournalFault,
) -> Result<TestCore, Box<dyn Error>> {
    let store =
        FileGenerationStore::create_new(tree.store_path(), store_domain()?, TestIntegrity::new()?)?;
    let journal = FileDurableJournal::create_new(
        tree.journal_path(),
        journal_domain()?,
        TestJournalAuthenticator::new()?,
    )?;
    let ledger = OperationLedger::open(FaultJournal::new(journal, journal_fault))?;
    Ok(JournaledDurableCore::new(
        DurableStateEngine::new(FaultStore::new(store, store_fault), TestBarrier),
        ledger,
    ))
}

fn reopen_core(tree: &TempTree, store_initialized: bool) -> Result<TestCore, Box<dyn Error>> {
    let store = if store_initialized {
        FileGenerationStore::reopen_existing(
            tree.store_path(),
            store_domain()?,
            TestIntegrity::new()?,
        )?
    } else {
        FileGenerationStore::create_new(tree.store_path(), store_domain()?, TestIntegrity::new()?)?
    };
    let journal = FileDurableJournal::reopen_existing(
        tree.journal_path(),
        journal_domain()?,
        TestJournalAuthenticator::new()?,
    )?;
    let ledger = OperationLedger::open(FaultJournal::new(journal, JournalFault::None))?;
    Ok(JournaledDurableCore::new(
        DurableStateEngine::new(FaultStore::new(store, StoreFault::None), TestBarrier),
        ledger,
    ))
}

fn operation(value: u8) -> Result<(OperationId, OperationDigest), Box<dyn Error>> {
    let operation_id = OperationId::new(format!("file-recovery-operation-{value:02}"))?;
    let mut digest = [value; 32];
    digest[0] |= 1;
    Ok((operation_id, OperationDigest::new(digest)?))
}

#[test]
fn storage_outcome_unknown_recovers_from_persisted_intent_after_reopen()
-> Result<(), Box<dyn Error>> {
    let tree = TempTree::new()?;
    let mut core = create_core(&tree, StoreFault::AfterCommitOnce, JournalFault::None)?;
    let (operation_id, request_digest) = operation(1)?;
    let result = core.persist_mutation(
        operation_id.clone(),
        request_digest,
        None,
        SecretState::new(b"store-outcome-unknown".to_vec())?,
        Vec::new(),
    );
    assert!(matches!(result, Err(JournaledCoreError::DurableState(_))));
    assert_eq!(
        core.ledger().blocking_phase(),
        Some(OperationPhase::IntentCommitted)
    );
    drop(core);

    let mut reopened = reopen_core(&tree, true)?;
    assert!(matches!(
        reopened.recover_durable_intent(&operation_id)?,
        DurableIntentRecovery::Committed(receipt)
            if receipt.committed == Generation::INITIAL
    ));
    assert_eq!(
        reopened.state().store().current_generation(),
        Some(Generation::INITIAL)
    );
    assert_eq!(
        reopened.ledger().retry_directive(&operation_id),
        Some(RetryDirective::LookupOnly)
    );
    Ok(())
}

#[test]
fn journal_outcome_unknown_after_state_event_is_idempotent_after_reopen()
-> Result<(), Box<dyn Error>> {
    let tree = TempTree::new()?;
    let mut core = create_core(&tree, StoreFault::None, JournalFault::AfterAppendOnce(3))?;
    let (operation_id, request_digest) = operation(2)?;
    let result = core.persist_mutation(
        operation_id.clone(),
        request_digest,
        None,
        SecretState::new(b"journal-outcome-unknown".to_vec())?,
        Vec::new(),
    );
    assert!(matches!(
        result,
        Err(JournaledCoreError::StateCommittedLedgerIncomplete { .. })
    ));
    assert!(core.ledger().replay_required());
    drop(core);

    let mut reopened = reopen_core(&tree, true)?;
    assert_eq!(
        reopened
            .ledger()
            .current(&operation_id)
            .map(|event| event.phase()),
        Some(OperationPhase::StateCommitted)
    );
    assert!(matches!(
        reopened.recover_durable_intent(&operation_id)?,
        DurableIntentRecovery::Committed(receipt)
            if receipt.committed == Generation::INITIAL
    ));
    Ok(())
}

#[test]
fn definitely_missing_state_event_is_reconstructed_from_file_store_after_reopen()
-> Result<(), Box<dyn Error>> {
    let tree = TempTree::new()?;
    let mut core = create_core(&tree, StoreFault::None, JournalFault::BeforeAppendOnce(3))?;
    let (operation_id, request_digest) = operation(3)?;
    let result = core.persist_mutation(
        operation_id.clone(),
        request_digest,
        None,
        SecretState::new(b"state-event-not-appended".to_vec())?,
        Vec::new(),
    );
    assert!(matches!(
        result,
        Err(JournaledCoreError::StateCommittedLedgerIncomplete { .. })
    ));
    assert!(!core.ledger().replay_required());
    assert_eq!(
        core.ledger().blocking_phase(),
        Some(OperationPhase::IntentCommitted)
    );
    drop(core);

    let mut reopened = reopen_core(&tree, true)?;
    assert!(matches!(
        reopened.recover_durable_intent(&operation_id)?,
        DurableIntentRecovery::Committed(receipt)
            if receipt.committed == Generation::INITIAL
    ));
    assert_eq!(
        reopened
            .ledger()
            .current(&operation_id)
            .map(|event| event.phase()),
        Some(OperationPhase::StateCommitted)
    );
    Ok(())
}

#[test]
fn definitely_uncommitted_file_intent_is_aborted_after_reopen() -> Result<(), Box<dyn Error>> {
    let tree = TempTree::new()?;
    let mut core = create_core(&tree, StoreFault::BeforeCommitOnce, JournalFault::None)?;
    let (operation_id, request_digest) = operation(4)?;
    let result = core.persist_mutation(
        operation_id.clone(),
        request_digest,
        None,
        SecretState::new(b"file-state-never-committed".to_vec())?,
        Vec::new(),
    );
    assert!(matches!(result, Err(JournaledCoreError::DurableState(_))));
    assert_eq!(core.state().store().current_generation(), None);
    drop(core);

    let mut reopened = reopen_core(&tree, false)?;
    assert!(matches!(
        reopened.recover_durable_intent(&operation_id)?,
        DurableIntentRecovery::AbortedBeforeStateCommit { .. }
    ));
    assert_eq!(reopened.state().store().current_generation(), None);
    assert_eq!(reopened.ledger().blocking_phase(), None);
    assert_eq!(
        reopened.ledger().retry_directive(&operation_id),
        Some(RetryDirective::SafeToRetryNewOperation)
    );
    Ok(())
}
