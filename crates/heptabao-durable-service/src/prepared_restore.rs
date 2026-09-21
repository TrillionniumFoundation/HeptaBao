//! One authenticated backup, borrowed for owner validation and consumed at commit.

use super::*;
use std::sync::Arc;

/// Public, non-secret facts about the authenticated incoming backup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedRestoreMetadata {
    pub generation: u64,
    pub replay_epoch: u64,
    pub retired_through_generation: u64,
    pub entry_count: usize,
    pub retained_requests: usize,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RestoreFrontier {
    generation: u64,
    replay_epoch: u64,
    retired_through_generation: u64,
    journal_sequence: u64,
    journal_bytes: usize,
}

/// An authenticated backup bound to one live service instance and frontier.
///
/// Values are borrowed only while this handle lives. Dropping an unused or
/// rejected handle erases its decrypted values and identifying metadata. The
/// handle cannot be cloned or serialized; publication consumes it.
///
/// ```compile_fail
/// use heptabao_durable_service::PreparedRestore;
/// fn duplicate(prepared: PreparedRestore) -> (PreparedRestore, PreparedRestore) {
///     (prepared, prepared)
/// }
/// ```
///
/// ```compile_fail
/// use heptabao_durable_service::{PreparedRestore, ServiceError};
/// fn outlive_owner(prepared: PreparedRestore) -> Result<&'static [u8], ServiceError> {
///     prepared.get("system", "state")?.ok_or(ServiceError::CorruptState)
/// }
/// ```
pub struct PreparedRestore {
    instance: Arc<()>,
    frontier: RestoreFrontier,
    components: BackupComponents,
}

impl fmt::Debug for PreparedRestore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRestore")
            .field("metadata", &self.metadata())
            .finish_non_exhaustive()
    }
}

impl PreparedRestore {
    #[must_use]
    pub fn metadata(&self) -> PreparedRestoreMetadata {
        PreparedRestoreMetadata {
            generation: self.components.snapshot.generation,
            replay_epoch: self.components.replay_epoch,
            retired_through_generation: self.components.retired_through_generation,
            entry_count: self.components.snapshot.entries.len(),
            retained_requests: self.components.ledger.len(),
        }
    }

    /// Borrow an authenticated resource without copying its plaintext. Names
    /// obey the same bounded syntax as live durable reads. Callers can adapt
    /// this method to their own application-specific record reader.
    pub fn get(&self, namespace: &str, resource: &str) -> Result<Option<&[u8]>, ServiceError> {
        validate_namespace(namespace)?;
        validate_resource(resource)?;
        Ok(self
            .components
            .snapshot
            .entries
            .get(&(namespace.to_owned(), resource.to_owned()))
            .map(Secret::expose))
    }

    /// Visit authenticated resources without retaining an extra copy. A
    /// caller must finish all application/schema/provider checks before
    /// passing this handle to `restore_prepared`.
    pub fn inspect(&self, mut visit: impl FnMut(&str, &str, &[u8])) {
        for ((namespace, resource), value) in &self.components.snapshot.entries {
            visit(namespace, resource, value.expose());
        }
    }
}

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    fn restore_frontier(&self) -> RestoreFrontier {
        RestoreFrontier {
            generation: self.snapshot.generation,
            replay_epoch: self.replay_epoch,
            retired_through_generation: self.retired_through_generation,
            journal_sequence: self.journal_sequence,
            journal_bytes: self.journal_bytes,
        }
    }

    /// Authenticate and decode a backup once, without publishing or fencing
    /// live state. Hard container/artifact bounds and all cross-artifact
    /// checks are shared with the existing backup decoder.
    pub fn prepare_restore(&self, backup: &[u8]) -> Result<PreparedRestore, ServiceError> {
        if self.unresolved {
            return Err(ServiceError::RecoveryRequired);
        }
        self.backend.verify().map_err(map_backend_error)?;
        let components = decode_backup(&self.barrier, backup, self.max_retained_requests)?;
        Ok(PreparedRestore {
            instance: Arc::clone(&self.restore_instance),
            frontier: self.restore_frontier(),
            components,
        })
    }

    /// Authenticate a precisely bounded HBB2 file/stream without first copying
    /// its complete container. `length` is the complete input length, not a
    /// caller-controlled allocation hint: exact EOF and checksum are checked.
    pub fn prepare_restore_from_reader(
        &self,
        reader: &mut impl std::io::Read,
        length: u64,
    ) -> Result<PreparedRestore, ServiceError> {
        if self.unresolved {
            return Err(ServiceError::RecoveryRequired);
        }
        self.backend.verify().map_err(map_backend_error)?;
        let components =
            backup_stream::decode_from(&self.barrier, reader, length, self.max_retained_requests)?;
        Ok(PreparedRestore {
            instance: Arc::clone(&self.restore_instance),
            frontier: self.restore_frontier(),
            components,
        })
    }

    /// Consume a prepared backup after owner validation. No barrier open is
    /// performed here. A plan for another instance, a reopened service, or a
    /// changed frontier is rejected with `RequestBindingConflict` before any
    /// publication. A physically unchanged maintenance operation is allowed.
    /// Successful restore invalidates all other plans, including generation
    /// ABA after rollback. Backend CAS and unknown-outcome fences are unchanged.
    pub fn restore_prepared(
        &mut self,
        prepared: PreparedRestore,
        allow_rollback: bool,
    ) -> Result<RestoreOutcome, ServiceError> {
        if self.unresolved {
            return Err(ServiceError::RecoveryRequired);
        }
        self.backend.verify().map_err(map_backend_error)?;
        if !Arc::ptr_eq(&self.restore_instance, &prepared.instance)
            || self.restore_frontier() != prepared.frontier
        {
            return Err(ServiceError::RequestBindingConflict);
        }
        let mut restored = prepared.components;
        if restored.snapshot.generation < self.snapshot.generation && !allow_rollback {
            return Err(ServiceError::BackupRollbackRejected);
        }
        let snapshot_plaintext_bytes = snapshot_plaintext_len(&restored.snapshot)?;
        let ledger_plaintext_bytes = ledger_plaintext_len(&restored.ledger)?;
        let previous_generation = self.snapshot.generation;
        let journal_bytes = restored.journal_bytes.len();
        // Move encrypted components; do not duplicate the full backup bundle.
        let replacement = BackendBundle {
            snapshot: std::mem::take(&mut restored.snapshot_bytes),
            ledger: std::mem::take(&mut restored.ledger_bytes),
            journal: std::mem::take(&mut restored.journal_bytes),
        };
        let profile = self.backend.restore_profile().map_err(map_backend_error)?;
        let expected = self.backend.load().map_err(map_backend_error)?;
        let intent = match profile {
            RestoreProfile::Atomic => None,
            RestoreProfile::FileIntent { target_identity } => {
                Some(restore_transaction::seal_intent(
                    &self.barrier,
                    target_identity,
                    self.restore_authority(),
                    [
                        restored.snapshot.generation,
                        restored.replay_epoch,
                        restored.retired_through_generation,
                    ],
                    &expected,
                    &replacement,
                )?)
            }
        };
        // Unsupported profiles and all authentication/bounds checks are read
        // only. Once publication starts, any failure requires reopen.
        self.unresolved = true;
        self.backend
            .publish_restore(&expected, &replacement, intent.as_deref())
            .map_err(map_backend_error)?;
        self.snapshot = std::mem::replace(
            &mut restored.snapshot,
            Snapshot {
                generation: 0,
                entries: BTreeMap::new(),
                last_commit: None,
            },
        );
        self.snapshot_plaintext_bytes = snapshot_plaintext_bytes;
        self.ledger = std::mem::take(&mut restored.ledger);
        self.ledger_plaintext_bytes = ledger_plaintext_bytes;
        self.replay_epoch = restored.replay_epoch;
        self.retired_through_generation = restored.retired_through_generation;
        self.journal_sequence = restored.journal_sequence;
        self.journal_bytes = journal_bytes;
        self.rebuild_reconciliation()?;
        self.restore_instance = Arc::new(());
        self.unresolved = false;
        Ok(RestoreOutcome {
            previous_generation,
            restored_generation: self.snapshot.generation,
            retained_requests: self.ledger.len(),
        })
    }
}

// Secret already zeroizes each resource value. Clear names, replay metadata
// and encrypted buffers as well when a plan is abandoned or rejected. On a
// successful commit the installed maps have been moved out of this container.
impl Drop for BackupComponents {
    fn drop(&mut self) {
        self.snapshot_bytes.zeroize();
        self.journal_bytes.zeroize();
        self.ledger_bytes.zeroize();
        while let Some(((mut namespace, mut resource), _value)) = self.snapshot.entries.pop_first()
        {
            namespace.zeroize();
            resource.zeroize();
        }
        if let Some(mut marker) = self.snapshot.last_commit.take() {
            erase_request_key(&mut marker.key);
            marker.binding_digest.zeroize();
            marker.recovery_reference.zeroize();
        }
        while let Some((mut key, mut record)) = self.ledger.pop_first() {
            erase_request_key(&mut key);
            record.binding_digest.zeroize();
            record.recovery_reference.zeroize();
        }
    }
}

fn erase_request_key(key: &mut RequestKey) {
    key.principal.zeroize();
    key.namespace.zeroize();
    key.request_id.zeroize();
}

#[cfg(test)]
mod tests;
