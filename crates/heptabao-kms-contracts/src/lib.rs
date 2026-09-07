#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Provider-neutral KMS key lifecycle and operation outcome contracts.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use heptabao_domain::{Id, SecretValue, Tick};

pub const MAX_WRAPPED_VALUE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum KmsCapability {
    Wrap,
    Unwrap,
    GenerateDataKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyState {
    Enabled,
    Disabled,
    PendingDestruction { not_before: Tick },
    Destroyed,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KeyVersion(u64);

impl KeyVersion {
    pub fn new(value: u64) -> Result<Self, KmsError> {
        if value == 0 {
            return Err(KmsError::InvalidKeyVersion);
        }
        Ok(Self(value))
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRegistration {
    pub key_id: Id,
    pub version: KeyVersion,
    pub capabilities: BTreeSet<KmsCapability>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyView {
    pub key_id: Id,
    pub version: KeyVersion,
    pub state: KeyState,
    pub capabilities: BTreeSet<KmsCapability>,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeyRecord {
    key_id: Id,
    version: KeyVersion,
    state: KeyState,
    capabilities: BTreeSet<KmsCapability>,
    generation: u64,
}

impl KeyRecord {
    fn view(&self) -> KeyView {
        KeyView {
            key_id: self.key_id.clone(),
            version: self.version,
            state: self.state,
            capabilities: self.capabilities.clone(),
            generation: self.generation,
        }
    }
}

#[derive(Debug, Default)]
pub struct KeyCatalog {
    keys: BTreeMap<Id, KeyRecord>,
}

impl KeyCatalog {
    pub fn register(&mut self, registration: KeyRegistration) -> Result<KeyView, KmsError> {
        if registration.capabilities.is_empty() {
            return Err(KmsError::MissingCapability);
        }
        if self.keys.contains_key(&registration.key_id) {
            return Err(KmsError::DuplicateKey);
        }
        let record = KeyRecord {
            key_id: registration.key_id.clone(),
            version: registration.version,
            state: KeyState::Enabled,
            capabilities: registration.capabilities,
            generation: 1,
        };
        let view = record.view();
        self.keys.insert(registration.key_id, record);
        Ok(view)
    }

    pub fn view(&self, key_id: &Id) -> Result<KeyView, KmsError> {
        self.keys
            .get(key_id)
            .map(KeyRecord::view)
            .ok_or(KmsError::MissingKey)
    }

    pub fn require_operation(
        &self,
        key_id: &Id,
        version: KeyVersion,
        capability: KmsCapability,
    ) -> Result<(), KmsError> {
        let key = self.keys.get(key_id).ok_or(KmsError::MissingKey)?;
        if key.version != version {
            return Err(KmsError::KeyVersionMismatch);
        }
        if key.state != KeyState::Enabled {
            return Err(match key.state {
                KeyState::Disabled => KmsError::KeyDisabled,
                KeyState::PendingDestruction { .. } => KmsError::KeyPendingDestruction,
                KeyState::Destroyed => KmsError::KeyDestroyed,
                KeyState::Enabled => KmsError::MissingKey,
            });
        }
        if !key.capabilities.contains(&capability) {
            return Err(KmsError::CapabilityDenied);
        }
        Ok(())
    }

    pub fn disable(&mut self, key_id: &Id) -> Result<KeyView, KmsError> {
        let key = self.keys.get_mut(key_id).ok_or(KmsError::MissingKey)?;
        if key.state != KeyState::Enabled {
            return Err(KmsError::InvalidKeyTransition);
        }
        key.state = KeyState::Disabled;
        key.generation = key
            .generation
            .checked_add(1)
            .ok_or(KmsError::GenerationOverflow)?;
        Ok(key.view())
    }

    pub fn enable(&mut self, key_id: &Id) -> Result<KeyView, KmsError> {
        let key = self.keys.get_mut(key_id).ok_or(KmsError::MissingKey)?;
        if key.state != KeyState::Disabled {
            return Err(KmsError::InvalidKeyTransition);
        }
        key.state = KeyState::Enabled;
        key.generation = key
            .generation
            .checked_add(1)
            .ok_or(KmsError::GenerationOverflow)?;
        Ok(key.view())
    }

    pub fn schedule_destruction(
        &mut self,
        key_id: &Id,
        not_before: Tick,
        now: Tick,
    ) -> Result<KeyView, KmsError> {
        if not_before <= now {
            return Err(KmsError::InvalidDestructionDeadline);
        }
        let key = self.keys.get_mut(key_id).ok_or(KmsError::MissingKey)?;
        if !matches!(key.state, KeyState::Enabled | KeyState::Disabled) {
            return Err(KmsError::InvalidKeyTransition);
        }
        key.state = KeyState::PendingDestruction { not_before };
        key.generation = key
            .generation
            .checked_add(1)
            .ok_or(KmsError::GenerationOverflow)?;
        Ok(key.view())
    }

    pub fn destroy(&mut self, key_id: &Id, now: Tick) -> Result<KeyView, KmsError> {
        let key = self.keys.get_mut(key_id).ok_or(KmsError::MissingKey)?;
        let KeyState::PendingDestruction { not_before } = key.state else {
            return Err(KmsError::InvalidKeyTransition);
        };
        if now < not_before {
            return Err(KmsError::DestructionNotDue);
        }
        key.state = KeyState::Destroyed;
        key.generation = key
            .generation
            .checked_add(1)
            .ok_or(KmsError::GenerationOverflow)?;
        Ok(key.view())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrappingContext {
    pub namespace_id: Id,
    pub purpose: Id,
    pub associated_data_digest: [u8; 32],
}

impl WrappingContext {
    pub fn new(
        namespace_id: Id,
        purpose: Id,
        associated_data_digest: [u8; 32],
    ) -> Result<Self, KmsError> {
        if associated_data_digest == [0; 32] {
            return Err(KmsError::InvalidAssociatedDataDigest);
        }
        Ok(Self {
            namespace_id,
            purpose,
            associated_data_digest,
        })
    }
}

#[derive(Eq, PartialEq)]
pub struct WrappedValue(Vec<u8>);

impl WrappedValue {
    pub fn new(bytes: Vec<u8>) -> Result<Self, KmsError> {
        if bytes.is_empty() || bytes.len() > MAX_WRAPPED_VALUE_BYTES {
            return Err(KmsError::InvalidWrappedValue);
        }
        Ok(Self(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for WrappedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WrappedValue")
            .field("bytes", &"[REDACTED]")
            .field("length", &self.0.len())
            .finish()
    }
}

impl Drop for WrappedValue {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug)]
pub struct WrapCommand {
    pub operation_id: Id,
    pub key_id: Id,
    pub key_version: KeyVersion,
    pub context: WrappingContext,
    pub plaintext: SecretValue,
}

#[derive(Debug)]
pub struct UnwrapCommand {
    pub operation_id: Id,
    pub key_id: Id,
    pub key_version: KeyVersion,
    pub context: WrappingContext,
    pub ciphertext: WrappedValue,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDisposition {
    RetryWithNewOperationId,
    ReconcileOnly,
    DoNotRetry,
}

#[derive(Debug, Eq, PartialEq)]
pub enum KmsOutcome<T> {
    Completed(T),
    FailedBeforeEntry(KmsError),
    OutcomeUnknownAfterEntry { reconciliation_reference: Id },
}

impl<T> KmsOutcome<T> {
    pub fn retry_disposition(&self) -> RetryDisposition {
        match self {
            Self::Completed(_) => RetryDisposition::DoNotRetry,
            Self::FailedBeforeEntry(error) => {
                if error.is_retryable_before_entry() {
                    RetryDisposition::RetryWithNewOperationId
                } else {
                    RetryDisposition::DoNotRetry
                }
            }
            Self::OutcomeUnknownAfterEntry { .. } => RetryDisposition::ReconcileOnly,
        }
    }
}

pub trait KmsProvider {
    fn wrap(&mut self, command: WrapCommand) -> KmsOutcome<WrappedValue>;
    fn unwrap(&mut self, command: UnwrapCommand) -> KmsOutcome<SecretValue>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KmsError {
    InvalidKeyVersion,
    InvalidAssociatedDataDigest,
    InvalidWrappedValue,
    MissingCapability,
    DuplicateKey,
    MissingKey,
    KeyVersionMismatch,
    KeyDisabled,
    KeyPendingDestruction,
    KeyDestroyed,
    CapabilityDenied,
    InvalidKeyTransition,
    InvalidDestructionDeadline,
    DestructionNotDue,
    ProviderUnavailableBeforeEntry,
    ProviderRejected,
    GenerationOverflow,
}

impl KmsError {
    pub const fn is_retryable_before_entry(self) -> bool {
        matches!(self, Self::ProviderUnavailableBeforeEntry)
    }
}

impl fmt::Display for KmsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidKeyVersion => "KMS key version is invalid",
            Self::InvalidAssociatedDataDigest => "KMS associated-data digest is invalid",
            Self::InvalidWrappedValue => "KMS wrapped value is invalid",
            Self::MissingCapability => "KMS key has no declared capability",
            Self::DuplicateKey => "KMS key is already registered",
            Self::MissingKey => "KMS key does not exist",
            Self::KeyVersionMismatch => "KMS key version does not match",
            Self::KeyDisabled => "KMS key is disabled",
            Self::KeyPendingDestruction => "KMS key is pending destruction",
            Self::KeyDestroyed => "KMS key is destroyed",
            Self::CapabilityDenied => "KMS key capability is denied",
            Self::InvalidKeyTransition => "KMS key lifecycle transition is invalid",
            Self::InvalidDestructionDeadline => "KMS destruction deadline is invalid",
            Self::DestructionNotDue => "KMS key destruction is not due",
            Self::ProviderUnavailableBeforeEntry => "KMS provider was unavailable before entry",
            Self::ProviderRejected => "KMS provider rejected the operation",
            Self::GenerationOverflow => "KMS key generation overflowed",
        })
    }
}

impl Error for KmsError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities() -> BTreeSet<KmsCapability> {
        [KmsCapability::Wrap, KmsCapability::Unwrap]
            .into_iter()
            .collect()
    }

    fn context() -> Result<WrappingContext, Box<dyn Error>> {
        Ok(WrappingContext::new(
            Id::parse("root_namespace")?,
            Id::parse("barrier_wrap")?,
            [7; 32],
        )?)
    }

    #[test]
    fn key_lifecycle_is_fail_closed_and_monotonic() -> Result<(), Box<dyn Error>> {
        let key_id = Id::parse("kms_key_one")?;
        let version = KeyVersion::new(1)?;
        let mut catalog = KeyCatalog::default();
        catalog.register(KeyRegistration {
            key_id: key_id.clone(),
            version,
            capabilities: capabilities(),
        })?;
        catalog.require_operation(&key_id, version, KmsCapability::Wrap)?;
        catalog.disable(&key_id)?;
        assert_eq!(
            Err(KmsError::KeyDisabled),
            catalog.require_operation(&key_id, version, KmsCapability::Wrap)
        );
        catalog.enable(&key_id)?;
        catalog.schedule_destruction(&key_id, Tick::new(20), Tick::new(10))?;
        assert_eq!(
            Err(KmsError::DestructionNotDue),
            catalog.destroy(&key_id, Tick::new(19))
        );
        let destroyed = catalog.destroy(&key_id, Tick::new(20))?;
        assert_eq!(KeyState::Destroyed, destroyed.state);
        assert_eq!(5, destroyed.generation);
        Ok(())
    }

    #[test]
    fn key_version_capability_and_context_are_bound() -> Result<(), Box<dyn Error>> {
        let key_id = Id::parse("kms_key_two")?;
        let mut catalog = KeyCatalog::default();
        catalog.register(KeyRegistration {
            key_id: key_id.clone(),
            version: KeyVersion::new(2)?,
            capabilities: [KmsCapability::Wrap].into_iter().collect(),
        })?;
        assert_eq!(
            Err(KmsError::KeyVersionMismatch),
            catalog.require_operation(&key_id, KeyVersion::new(1)?, KmsCapability::Wrap)
        );
        assert_eq!(
            Err(KmsError::CapabilityDenied),
            catalog.require_operation(&key_id, KeyVersion::new(2)?, KmsCapability::Unwrap)
        );
        assert_eq!(
            Err(KmsError::InvalidAssociatedDataDigest),
            WrappingContext::new(
                Id::parse("root_namespace")?,
                Id::parse("barrier_wrap")?,
                [0; 32]
            )
        );
        Ok(())
    }

    #[test]
    fn unknown_after_entry_is_reconcile_only() -> Result<(), Box<dyn Error>> {
        let outcome: KmsOutcome<WrappedValue> = KmsOutcome::OutcomeUnknownAfterEntry {
            reconciliation_reference: Id::parse("kms_reconcile_one")?,
        };
        assert_eq!(RetryDisposition::ReconcileOnly, outcome.retry_disposition());
        let retryable: KmsOutcome<WrappedValue> =
            KmsOutcome::FailedBeforeEntry(KmsError::ProviderUnavailableBeforeEntry);
        assert_eq!(
            RetryDisposition::RetryWithNewOperationId,
            retryable.retry_disposition()
        );
        Ok(())
    }

    #[test]
    fn secret_and_wrapped_debug_output_are_redacted() -> Result<(), Box<dyn Error>> {
        let command = WrapCommand {
            operation_id: Id::parse("wrap_one")?,
            key_id: Id::parse("kms_key_three")?,
            key_version: KeyVersion::new(1)?,
            context: context()?,
            plaintext: SecretValue::new(b"plaintext-secret".to_vec())?,
        };
        let ciphertext = WrappedValue::new(b"wrapped-secret".to_vec())?;
        let rendered = format!("{command:?} {ciphertext:?}");
        assert!(!rendered.contains("plaintext-secret"));
        assert!(!rendered.contains("wrapped-secret"));
        assert!(rendered.contains("[REDACTED]"));
        Ok(())
    }
}
