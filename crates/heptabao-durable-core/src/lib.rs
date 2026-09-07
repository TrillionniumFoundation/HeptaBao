#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Minimal durable single-node composition for HeptaBao.
//!
//! The engine binds one authoritative durable-generation store to one barrier
//! provider. Plaintext is sealed before it crosses the storage boundary, and a
//! generation compare-and-swap is checked before provider work begins. This is
//! a development foundation, not a production secrets server or authority
//! grant.

use std::error::Error;
use std::fmt;

use heptabao_barrier_api::{
    BarrierContext, BarrierContractError, BarrierProvider, BarrierPurpose, KeyEpoch,
    SealedEnvelope, SecretState,
};
use heptabao_storage_api::{
    CommitIntent, CommitReceipt, CommitRecovery, DurableGenerationStore, Generation, OpaqueState,
    StateDigest, StorageContractError,
};

pub struct DurableStateEngine<S, B> {
    store: S,
    barrier: B,
}

impl<S, B> DurableStateEngine<S, B> {
    pub const fn new(store: S, barrier: B) -> Self {
        Self { store, barrier }
    }

    pub const fn store(&self) -> &S {
        &self.store
    }

    pub const fn barrier(&self) -> &B {
        &self.barrier
    }
}

impl<S, B> fmt::Debug for DurableStateEngine<S, B>
where
    S: fmt::Debug,
    B: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableStateEngine")
            .field("store", &self.store)
            .field("barrier", &"[CONFIGURED_PROVIDER]")
            .finish()
    }
}

pub struct PreparedDurableMutation {
    intent: CommitIntent,
    candidate: OpaqueState,
}

impl PreparedDurableMutation {
    pub const fn intent(&self) -> CommitIntent {
        self.intent
    }
}

impl fmt::Debug for PreparedDurableMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedDurableMutation")
            .field("intent", &self.intent)
            .field("candidate_bytes", &self.candidate.len())
            .field("candidate", &"[SEALED_REDACTED]")
            .finish()
    }
}

impl<S, B> DurableStateEngine<S, B>
where
    S: DurableGenerationStore,
    B: BarrierProvider,
{
    pub fn prepare_persist(
        &self,
        expected_current: Option<Generation>,
        plaintext: SecretState,
        caller_associated_data: Vec<u8>,
    ) -> Result<PreparedDurableMutation, DurableCoreError<S::Error, B::Error>> {
        let actual = self.store.current_generation();
        if expected_current != actual {
            return Err(DurableCoreError::GenerationConflict {
                expected: expected_current,
                actual,
            });
        }
        let generation = match actual {
            Some(value) => value
                .checked_next()
                .map_err(DurableCoreError::StorageContract)?,
            None => Generation::INITIAL,
        };
        let key_epoch = self
            .barrier
            .active_key_epoch()
            .map_err(DurableCoreError::Barrier)?;
        let context = BarrierContext::new(
            self.store.domain().clone(),
            generation,
            key_epoch,
            BarrierPurpose::AuthoritativeState,
            caller_associated_data,
        )
        .map_err(DurableCoreError::BarrierContract)?;
        let envelope = self
            .barrier
            .seal(&context, plaintext)
            .map_err(DurableCoreError::Barrier)?;
        if envelope.key_epoch() != key_epoch {
            return Err(DurableCoreError::BarrierEpochMismatch {
                requested: key_epoch,
                returned: envelope.key_epoch(),
            });
        }
        let encoded = envelope
            .encode()
            .map_err(DurableCoreError::BarrierContract)?;
        let candidate = OpaqueState::new(encoded).map_err(DurableCoreError::StorageContract)?;
        let intent = self
            .store
            .prepare_commit(expected_current, &candidate)
            .map_err(DurableCoreError::Storage)?;
        if intent.previous() != expected_current || intent.committed() != generation {
            return Err(DurableCoreError::CommitIntentMismatch);
        }
        Ok(PreparedDurableMutation { intent, candidate })
    }

    pub fn commit_prepared(
        &mut self,
        prepared: PreparedDurableMutation,
    ) -> Result<CommitReceipt, DurableCoreError<S::Error, B::Error>> {
        let receipt = self
            .store
            .commit(prepared.intent.previous(), prepared.candidate)
            .map_err(DurableCoreError::Storage)?;
        if receipt != prepared.intent.receipt() {
            return Err(DurableCoreError::CommitReceiptMismatch);
        }
        Ok(receipt)
    }

    pub fn recover_commit(
        &mut self,
        intent: CommitIntent,
    ) -> Result<CommitRecovery, DurableCoreError<S::Error, B::Error>> {
        self.store
            .recover_commit(intent)
            .map_err(DurableCoreError::Storage)
    }

    pub fn persist(
        &mut self,
        expected_current: Option<Generation>,
        plaintext: SecretState,
        caller_associated_data: Vec<u8>,
    ) -> Result<CommitReceipt, DurableCoreError<S::Error, B::Error>> {
        let prepared = self.prepare_persist(expected_current, plaintext, caller_associated_data)?;
        self.commit_prepared(prepared)
    }

    pub fn load_current(
        &self,
        caller_associated_data: Vec<u8>,
    ) -> Result<Option<LoadedSecretState>, DurableCoreError<S::Error, B::Error>> {
        let snapshot = self
            .store
            .load_current()
            .map_err(DurableCoreError::Storage)?;
        let Some(snapshot) = snapshot else {
            return Ok(None);
        };
        let generation = snapshot.generation;
        let digest = snapshot.digest;
        let envelope = SealedEnvelope::decode(snapshot.state.into_bytes())
            .map_err(DurableCoreError::BarrierContract)?;
        let key_epoch = envelope.key_epoch();
        let context = BarrierContext::new(
            self.store.domain().clone(),
            generation,
            key_epoch,
            BarrierPurpose::AuthoritativeState,
            caller_associated_data,
        )
        .map_err(DurableCoreError::BarrierContract)?;
        let state = self
            .barrier
            .open(&context, envelope)
            .map_err(DurableCoreError::Barrier)?;
        Ok(Some(LoadedSecretState {
            generation,
            digest,
            key_epoch,
            state,
        }))
    }
}

pub struct LoadedSecretState {
    pub generation: Generation,
    pub digest: StateDigest,
    pub key_epoch: KeyEpoch,
    pub state: SecretState,
}

impl fmt::Debug for LoadedSecretState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedSecretState")
            .field("generation", &self.generation)
            .field("digest", &self.digest)
            .field("key_epoch", &self.key_epoch)
            .field("state_bytes", &self.state.len())
            .finish()
    }
}

#[derive(Debug)]
pub enum DurableCoreError<S, B>
where
    S: Error + Send + Sync + 'static,
    B: Error + Send + Sync + 'static,
{
    Storage(S),
    Barrier(B),
    StorageContract(StorageContractError),
    BarrierContract(BarrierContractError),
    GenerationConflict {
        expected: Option<Generation>,
        actual: Option<Generation>,
    },
    BarrierEpochMismatch {
        requested: KeyEpoch,
        returned: KeyEpoch,
    },
    CommitIntentMismatch,
    CommitReceiptMismatch,
}

impl<S, B> fmt::Display for DurableCoreError<S, B>
where
    S: Error + Send + Sync + 'static,
    B: Error + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "durable storage failure: {error}"),
            Self::Barrier(error) => write!(formatter, "barrier provider failure: {error}"),
            Self::StorageContract(error) => {
                write!(formatter, "storage contract failure: {error}")
            }
            Self::BarrierContract(error) => {
                write!(formatter, "barrier contract failure: {error}")
            }
            Self::GenerationConflict { expected, actual } => write!(
                formatter,
                "generation compare-and-swap conflict: expected {expected:?}, actual {actual:?}"
            ),
            Self::BarrierEpochMismatch {
                requested,
                returned,
            } => write!(
                formatter,
                "barrier returned key epoch {returned:?} for requested epoch {requested:?}"
            ),
            Self::CommitIntentMismatch => {
                formatter.write_str("durable store returned a mismatched commit intent")
            }
            Self::CommitReceiptMismatch => {
                formatter.write_str("durable store returned a mismatched commit receipt")
            }
        }
    }
}

impl<S, B> Error for DurableCoreError<S, B>
where
    S: Error + Send + Sync + 'static,
    B: Error + Send + Sync + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            Self::Barrier(error) => Some(error),
            Self::StorageContract(error) => Some(error),
            Self::BarrierContract(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heptabao_storage_api::{GenerationSnapshot, StoreDomain, StoreOpenMode};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MemoryStoreError {
        Contract(StorageContractError),
        Conflict,
    }

    impl fmt::Display for MemoryStoreError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Contract(error) => write!(formatter, "memory store contract: {error}"),
                Self::Conflict => formatter.write_str("memory store generation conflict"),
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
    }

    impl MemoryStore {
        fn new(domain: StoreDomain) -> Self {
            Self {
                domain,
                current: None,
                digest: None,
                bytes: Vec::new(),
            }
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
            let digest = test_digest(committed, candidate.as_bytes())?;
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
            let generation = match self.current {
                Some(value) => value.checked_next().map_err(MemoryStoreError::Contract)?,
                None => Generation::INITIAL,
            };
            let bytes = candidate.into_bytes();
            let digest = test_digest(generation, &bytes)?;
            self.bytes.fill(0);
            self.bytes = bytes;
            let previous = self.current;
            self.current = Some(generation);
            self.digest = Some(digest);
            Ok(CommitReceipt {
                previous,
                committed: generation,
                digest,
            })
        }
    }

    fn test_digest(generation: Generation, bytes: &[u8]) -> Result<StateDigest, MemoryStoreError> {
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
        AuthenticationFailed,
    }

    impl fmt::Display for MockBarrierError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Contract(error) => write!(formatter, "mock barrier contract: {error}"),
                Self::AuthenticationFailed => {
                    formatter.write_str("mock barrier authentication failed")
                }
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
            let mut associated_data = context
                .canonical_associated_data()
                .map_err(MockBarrierError::Contract)?;
            let mut plaintext = plaintext.into_bytes();
            let ciphertext = plaintext
                .iter()
                .copied()
                .map(|byte| byte ^ 0xaa)
                .collect::<Vec<_>>();
            plaintext.fill(0);
            let tag = mock_tag(&associated_data, &ciphertext);
            associated_data.fill(0);
            SealedEnvelope::new(
                heptabao_barrier_api::SEALED_ENVELOPE_VERSION,
                context.key_epoch(),
                b"test-nonce-v1".to_vec(),
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
            let mut associated_data = context
                .canonical_associated_data()
                .map_err(MockBarrierError::Contract)?;
            let expected_tag = mock_tag(&associated_data, envelope.ciphertext());
            associated_data.fill(0);
            if expected_tag.as_slice() != envelope.authentication_tag() {
                return Err(MockBarrierError::AuthenticationFailed);
            }
            let plaintext = envelope
                .ciphertext()
                .iter()
                .copied()
                .map(|byte| byte ^ 0xaa)
                .collect::<Vec<_>>();
            SecretState::new(plaintext).map_err(MockBarrierError::Contract)
        }
    }

    fn mock_tag(associated_data: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        let mut output = vec![0_u8; 32];
        for (index, byte) in associated_data
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

    fn domain() -> Result<StoreDomain, StorageContractError> {
        StoreDomain::new("heptabao/durable-core-test".to_owned())
    }

    #[test]
    fn prepared_mutation_binds_target_before_authoritative_commit() {
        let domain = domain();
        if let Ok(domain) = domain {
            let store = MemoryStore::new(domain);
            let mut engine = DurableStateEngine::new(store, MockBarrier);
            let secret = SecretState::new(b"prepared-state".to_vec());
            assert!(secret.is_ok());
            if let Ok(secret) = secret {
                let prepared = engine.prepare_persist(None, secret, Vec::new());
                assert!(prepared.is_ok());
                if let Ok(prepared) = prepared {
                    assert_eq!(prepared.intent().previous(), None);
                    assert_eq!(prepared.intent().committed(), Generation::INITIAL);
                    assert_eq!(engine.store().current_generation(), None);
                    let committed = engine.commit_prepared(prepared);
                    assert!(committed.is_ok());
                    if let Ok(receipt) = committed {
                        assert_eq!(receipt.committed, Generation::INITIAL);
                    }
                }
            }
        }
    }

    #[test]
    fn plaintext_is_sealed_before_storage_and_round_trips() {
        let domain = domain();
        assert!(domain.is_ok());
        if let Ok(domain) = domain {
            let store = MemoryStore::new(domain);
            let mut engine = DurableStateEngine::new(store, MockBarrier);
            let secret = SecretState::new(b"plaintext-state".to_vec());
            assert!(secret.is_ok());
            if let Ok(secret) = secret {
                let receipt = engine.persist(None, secret, b"namespace-a".to_vec());
                assert!(receipt.is_ok());
            }
            assert!(
                !engine
                    .store()
                    .bytes
                    .windows(15)
                    .any(|window| window == b"plaintext-state")
            );
            let loaded = engine.load_current(b"namespace-a".to_vec());
            assert!(loaded.is_ok());
            if let Ok(Some(loaded)) = loaded {
                assert_eq!(loaded.generation, Generation::INITIAL);
                assert_eq!(loaded.state.as_bytes(), b"plaintext-state");
                assert!(!format!("{loaded:?}").contains("plaintext-state"));
            }
        }
    }

    #[test]
    fn associated_data_mismatch_fails_authentication() {
        let domain = domain();
        if let Ok(domain) = domain {
            let store = MemoryStore::new(domain);
            let mut engine = DurableStateEngine::new(store, MockBarrier);
            let secret = SecretState::new(b"plaintext-state".to_vec());
            if let Ok(secret) = secret {
                assert!(
                    engine
                        .persist(None, secret, b"namespace-a".to_vec())
                        .is_ok()
                );
            }
            assert!(matches!(
                engine.load_current(b"namespace-b".to_vec()),
                Err(DurableCoreError::Barrier(
                    MockBarrierError::AuthenticationFailed
                ))
            ));
        }
    }

    #[test]
    fn stale_expected_generation_is_rejected_before_sealing() {
        let domain = domain();
        if let Ok(domain) = domain {
            let store = MemoryStore::new(domain);
            let mut engine = DurableStateEngine::new(store, MockBarrier);
            let first = SecretState::new(b"first".to_vec());
            if let Ok(first) = first {
                assert!(engine.persist(None, first, Vec::new()).is_ok());
            }
            let stale = SecretState::new(b"stale".to_vec());
            assert!(stale.is_ok());
            if let Ok(stale) = stale {
                assert!(matches!(
                    engine.persist(None, stale, Vec::new()),
                    Err(DurableCoreError::GenerationConflict { .. })
                ));
            }
        }
    }
}
