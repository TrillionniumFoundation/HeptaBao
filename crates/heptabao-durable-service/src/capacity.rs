//! Capacity observations and opt-in journal maintenance. Neither erases replay IDs.
use super::*;

/// Metadata only. Bounds are admission limits, not a production capacity claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityStatus {
    pub generation: u64,
    pub stored_value_bytes: usize,
    pub journal_bytes: usize,
    pub journal_limit_bytes: usize,
    pub retained_requests: usize,
    pub retained_request_limit: usize,
    pub recovery_required: bool,
}

impl<B: Barrier> DurableService<B> {
    #[must_use]
    pub fn capacity_status(&self) -> CapacityStatus {
        CapacityStatus {
            generation: self.snapshot.generation,
            stored_value_bytes: self
                .snapshot
                .entries
                .values()
                .map(|v| v.expose().len())
                .sum(),
            journal_bytes: self.journal_bytes,
            journal_limit_bytes: self.journal_limit,
            retained_requests: self.ledger.len(),
            retained_request_limit: self.max_retained_requests,
            recovery_required: self.unresolved,
        }
    }

    /// Retry only a proven *pre-entry journal-capacity rejection*, after one
    /// authenticated checkpoint. The same request/binding is retained; unknown
    /// outcomes, I/O failures and exhausted replay capacity are never retried.
    /// The caller must fence its own cached state if recovery_required() is true
    /// on ANY error, including a failed checkpoint rename/directory sync.
    pub fn put_with_maintenance(
        &mut self,
        request: PutRequest,
    ) -> Result<MutationOutcome, ServiceError> {
        match self.put(request.clone()) {
            Err(ServiceError::JournalCapacityExhausted) if !self.unresolved => {
                self.compact()?;
                self.put(request)
            }
            outcome => outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{TestBarrier, TestRoot, put_request, serial_test};

    #[test]
    fn automatic_checkpoint_retains_every_binding_and_survives_restart() -> Result<(), ServiceError>
    {
        let _serial = serial_test();
        let root = TestRoot::new("automatic-capacity")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 128)?;
        service.journal_limit = 2048;
        let mut receipts = Vec::new();
        for n in 0..40 {
            let request = put_request(&format!("request-{n}"), b"same-value")?;
            receipts.push(service.put_with_maintenance(request)?);
            assert!(service.capacity_status().journal_bytes <= 2048);
        }
        assert_eq!(service.retained_request_count(), 40);
        let before = service.capacity_status();
        let first = service.put_with_maintenance(put_request("request-0", b"same-value")?)?;
        assert!(matches!(
            first,
            MutationOutcome::Duplicate { generation: 1, .. }
        ));
        assert_eq!(before, service.capacity_status());
        assert!(matches!(
            service.put_with_maintenance(put_request("request-0", b"changed")?),
            Err(ServiceError::RequestBindingConflict)
        ));
        drop(service);
        let mut service = DurableService::reopen(&root.0, TestBarrier::new(), 128)?;
        assert_eq!(service.generation(), 40);
        assert_eq!(service.retained_request_count(), 40);
        for receipt in receipts {
            if let MutationOutcome::Committed {
                generation,
                recovery_reference,
            } = receipt
            {
                assert_eq!(
                    service.reconcile(&recovery_reference),
                    ReconciliationStatus::Committed { generation }
                );
            } else {
                return Err(ServiceError::CorruptState);
            }
        }
        assert!(matches!(
            service.put_with_maintenance(put_request("request-0", b"same-value")?)?,
            MutationOutcome::Duplicate { .. }
        ));
        Ok(())
    }

    #[test]
    fn maintenance_never_evicts_ids_to_admit_a_new_request() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("capacity-no-eviction")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 1)?;
        service.put_with_maintenance(put_request("one", b"one")?)?;
        let before = fs::read(journal_path(&root.0))?;
        assert!(matches!(
            service.put_with_maintenance(put_request("two", b"two")?),
            Err(ServiceError::RequestCapacityExhausted)
        ));
        assert_eq!(before, fs::read(journal_path(&root.0))?);
        assert_eq!(service.retained_request_count(), 1);
        assert!(!service.recovery_required());
        Ok(())
    }

    #[test]
    fn pending_publication_is_not_checkpointed_or_retried() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("capacity-no-unknown-retry")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 8)?;
        assert!(matches!(
            service.put_with_failpoint(
                put_request("one", b"one")?,
                Failpoint::AfterSnapshotPublication
            ),
            Err(ServiceError::OutcomeUnknown { .. })
        ));
        let before = fs::read(journal_path(&root.0))?;
        assert!(matches!(
            service.put_with_maintenance(put_request("two", b"two")?),
            Err(ServiceError::RecoveryRequired)
        ));
        assert_eq!(before, fs::read(journal_path(&root.0))?);
        Ok(())
    }

    #[test]
    fn failed_automatic_checkpoint_fences_the_live_reader() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("capacity-checkpoint-io")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 8)?;
        service.put(put_request("one", b"one")?)?;
        service.journal_limit = service.journal_bytes;
        let path = journal_path(&root.0);
        let saved = fs::read(&path)?;
        fs::remove_file(&path)?;
        fs::create_dir(&path)?;
        assert!(
            service
                .put_with_maintenance(put_request("two", b"two")?)
                .is_err()
        );
        assert!(service.recovery_required());
        assert!(matches!(
            service.get("tenant-a", "secret/item"),
            Err(ServiceError::RecoveryRequired)
        ));
        fs::remove_dir(&path)?;
        fs::write(&path, saved)?;
        drop(service);
        let service = DurableService::reopen(&root.0, TestBarrier::new(), 8)?;
        assert_eq!(service.generation(), 1);
        Ok(())
    }
}
