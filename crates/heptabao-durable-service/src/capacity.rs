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

struct AtomicBatchRequest {
    principal: String,
    namespace: String,
    request_id: String,
    authorization_digest: [u8; 32],
    mutations: Vec<(String, Option<Secret>)>,
}

impl<B: Barrier> DurableService<B> {
    /// Atomically apply several mutations under one replay identity and one
    /// durable generation. `Some(secret)` is a put and `None` is a delete.
    ///
    /// The ordered mutation set is part of the request binding. A retry with
    /// the same identity must therefore provide byte-identical semantics or it
    /// fails closed with `RequestBindingConflict`.
    pub fn apply_batch(
        &mut self,
        principal: impl Into<String>,
        namespace: impl Into<String>,
        request_id: impl Into<String>,
        authorization_digest: [u8; 32],
        mutations: Vec<(String, Option<Secret>)>,
    ) -> Result<MutationOutcome, ServiceError> {
        self.apply_batch_with_policy(
            AtomicBatchRequest {
                principal: principal.into(),
                namespace: namespace.into(),
                request_id: request_id.into(),
                authorization_digest,
                mutations,
            },
            Failpoint::None,
            false,
        )
    }

    /// Apply one atomic batch and, only for a proven pre-entry journal-capacity
    /// rejection, checkpoint the journal and retry the exact same bound batch once.
    /// Replay-ledger exhaustion, unknown outcomes, I/O failures and binding
    /// conflicts are never compacted or retried.
    pub fn apply_batch_with_compaction(
        &mut self,
        principal: impl Into<String>,
        namespace: impl Into<String>,
        request_id: impl Into<String>,
        authorization_digest: [u8; 32],
        mutations: Vec<(String, Option<Secret>)>,
    ) -> Result<MutationOutcome, ServiceError> {
        self.apply_batch_with_policy(
            AtomicBatchRequest {
                principal: principal.into(),
                namespace: namespace.into(),
                request_id: request_id.into(),
                authorization_digest,
                mutations,
            },
            Failpoint::None,
            true,
        )
    }

    #[cfg(test)]
    fn apply_batch_with_failpoint(
        &mut self,
        principal: String,
        namespace: String,
        request_id: String,
        authorization_digest: [u8; 32],
        mutations: Vec<(String, Option<Secret>)>,
        failpoint: Failpoint,
    ) -> Result<MutationOutcome, ServiceError> {
        self.apply_batch_with_policy(
            AtomicBatchRequest {
                principal,
                namespace,
                request_id,
                authorization_digest,
                mutations,
            },
            failpoint,
            false,
        )
    }

    fn apply_batch_with_policy(
        &mut self,
        mut request: AtomicBatchRequest,
        failpoint: Failpoint,
        compact_before_entry: bool,
    ) -> Result<MutationOutcome, ServiceError> {
        validate_identifier(&request.principal)?;
        validate_namespace(&request.namespace)?;
        validate_identifier(&request.request_id)?;
        if request.authorization_digest == [0; 32] {
            return Err(ServiceError::InvalidAuthorizationDigest);
        }
        if request.mutations.is_empty() || request.mutations.len() > 64 {
            return Err(ServiceError::InvalidResource);
        }
        let mut resources = std::collections::BTreeSet::new();
        for (resource, _) in &request.mutations {
            validate_resource(resource)?;
            if !resources.insert(resource.clone()) {
                return Err(ServiceError::InvalidResource);
            }
        }
        if self.unresolved {
            return Err(ServiceError::RecoveryRequired);
        }
        self.directory.verify().map_err(map_guard_error)?;

        let key = RequestKey {
            principal: request.principal.clone(),
            namespace: request.namespace.clone(),
            request_id: request.request_id.clone(),
        };
        let mut binding_bytes = Vec::new();
        encode_string(&mut binding_bytes, &key.principal);
        encode_string(&mut binding_bytes, &key.namespace);
        encode_string(&mut binding_bytes, &key.request_id);
        binding_bytes.extend_from_slice(&request.authorization_digest);
        for (resource, value) in &request.mutations {
            encode_string(&mut binding_bytes, resource);
            match value {
                Some(secret) => {
                    binding_bytes.push(1);
                    binding_bytes.extend_from_slice(&digest32(
                        b"heptabao.durable-service.value.v1",
                        secret.expose(),
                    ));
                }
                None => {
                    binding_bytes.push(2);
                    binding_bytes.extend_from_slice(&digest32(
                        b"heptabao.durable-service.delete.v1",
                        b"delete",
                    ));
                }
            }
        }
        let binding_digest = digest32(b"heptabao.durable-service.batch-binding.v1", &binding_bytes);
        if let Some(existing) = self.ledger.get(&key) {
            if existing.binding_digest != binding_digest {
                return Err(ServiceError::RequestBindingConflict);
            }
            return Ok(MutationOutcome::Duplicate {
                generation: existing.generation,
                recovery_reference: existing.recovery_reference.clone(),
            });
        }
        if self.ledger.len() >= self.max_retained_requests {
            return Err(ServiceError::RequestCapacityExhausted);
        }

        let generation = self
            .snapshot
            .generation
            .checked_add(1)
            .ok_or(ServiceError::GenerationOverflow)?;
        let intent_sequence = self
            .journal_sequence
            .checked_add(1)
            .ok_or(ServiceError::GenerationOverflow)?;
        let terminal_sequence = intent_sequence
            .checked_add(1)
            .ok_or(ServiceError::GenerationOverflow)?;
        let recovery_reference = recovery_reference(&binding_digest, generation, intent_sequence);
        let marker = CommitMarker {
            key: key.clone(),
            binding_digest,
            recovery_reference: recovery_reference.clone(),
            generation,
        };

        let mut candidate = self.snapshot.clone();
        candidate.generation = generation;
        candidate.last_commit = Some(marker.clone());
        for (resource, value) in &request.mutations {
            let storage_key = (request.namespace.clone(), resource.clone());
            if let Some(secret) = value {
                candidate.entries.insert(storage_key, secret.clone());
            } else {
                candidate.entries.remove(&storage_key);
            }
        }
        let mut candidate_ledger = self.ledger.clone();
        candidate_ledger.insert(
            key,
            LedgerRecord {
                binding_digest,
                recovery_reference: recovery_reference.clone(),
                generation,
            },
        );

        let snapshot_bytes = sealed_snapshot(&self.barrier, &candidate)?;
        let ledger_bytes = sealed_ledger(&self.barrier, generation, &candidate_ledger)?;
        let intent = sealed_journal_record(
            &self.barrier,
            intent_sequence,
            &JournalEvent::Intent(marker.clone()),
        )?;
        let commit = sealed_journal_record(
            &self.barrier,
            terminal_sequence,
            &JournalEvent::Commit(marker),
        )?;
        if snapshot_bytes.len() > MAX_FILE_BYTES || ledger_bytes.len() > MAX_FILE_BYTES {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        if terminal_sequence > MAX_RECORDS as u64
            || self
                .journal_bytes
                .checked_add(intent.len())
                .and_then(|n| n.checked_add(commit.len()))
                .is_none_or(|n| n > self.journal_limit)
        {
            if compact_before_entry {
                self.compact()?;
                return self.apply_batch_with_policy(request, failpoint, false);
            }
            return Err(ServiceError::JournalCapacityExhausted);
        }

        self.unresolved = true;
        let result = (|| {
            self.append_frame(&intent)?;
            if failpoint == Failpoint::AfterIntent {
                return Err(ServiceError::RecoveryRequired);
            }
            atomic_write(&self.root, &snapshot_path(&self.root), &snapshot_bytes)?;
            self.snapshot = candidate;
            if failpoint == Failpoint::AfterSnapshotPublication {
                return Err(ServiceError::RecoveryRequired);
            }
            self.append_frame(&commit)?;
            if failpoint == Failpoint::AfterCommitJournal {
                return Err(ServiceError::RecoveryRequired);
            }
            atomic_write(&self.root, &ledger_path(&self.root), &ledger_bytes)?;
            self.ledger = candidate_ledger;
            Ok(())
        })();
        // Ensure caller-owned plaintext is released promptly on both success
        // and failure; `Secret::drop` zeroizes each payload.
        request.mutations.clear();
        if result.is_err() {
            return Err(ServiceError::OutcomeUnknown { recovery_reference });
        }
        self.reconciliation.insert(
            recovery_reference.clone(),
            ReconciliationStatus::Committed { generation },
        );
        self.unresolved = false;
        Ok(MutationOutcome::Committed {
            generation,
            recovery_reference,
        })
    }

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
        self.put_with_compaction(request)
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

    #[test]
    fn atomic_batch_uses_one_identity_and_generation() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("atomic-batch-one-identity")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 8)?;
        let result = service.apply_batch(
            "principal-a",
            "tenant-a",
            "batch-1",
            [7; 32],
            vec![
                ("secret/a".to_owned(), Some(Secret::new(b"a".to_vec())?)),
                ("secret/b".to_owned(), Some(Secret::new(b"b".to_vec())?)),
                ("secret/missing".to_owned(), None),
            ],
        )?;
        assert!(matches!(
            result,
            MutationOutcome::Committed { generation: 1, .. }
        ));
        assert_eq!(service.generation(), 1);
        assert_eq!(service.retained_request_count(), 1);
        assert_eq!(
            service
                .get("tenant-a", "secret/a")?
                .as_ref()
                .map(Secret::expose),
            Some(&b"a"[..])
        );
        assert_eq!(
            service
                .get("tenant-a", "secret/b")?
                .as_ref()
                .map(Secret::expose),
            Some(&b"b"[..])
        );
        let duplicate = service.apply_batch(
            "principal-a",
            "tenant-a",
            "batch-1",
            [7; 32],
            vec![
                ("secret/a".to_owned(), Some(Secret::new(b"a".to_vec())?)),
                ("secret/b".to_owned(), Some(Secret::new(b"b".to_vec())?)),
                ("secret/missing".to_owned(), None),
            ],
        )?;
        assert!(matches!(
            duplicate,
            MutationOutcome::Duplicate { generation: 1, .. }
        ));
        assert_eq!(service.retained_request_count(), 1);
        Ok(())
    }

    #[test]
    fn atomic_batch_binding_conflict_fails_closed() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("atomic-batch-conflict")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 8)?;
        service.apply_batch(
            "principal-a",
            "tenant-a",
            "batch-1",
            [7; 32],
            vec![("secret/a".to_owned(), Some(Secret::new(b"a".to_vec())?))],
        )?;
        assert!(matches!(
            service.apply_batch(
                "principal-a",
                "tenant-a",
                "batch-1",
                [7; 32],
                vec![(
                    "secret/a".to_owned(),
                    Some(Secret::new(b"changed".to_vec())?),
                )],
            ),
            Err(ServiceError::RequestBindingConflict)
        ));
        assert_eq!(service.generation(), 1);
        assert_eq!(service.retained_request_count(), 1);
        Ok(())
    }

    #[test]
    fn atomic_batch_unknown_outcome_reconciles_as_one_commit() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("atomic-batch-reconcile")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 8)?;
        let reference = match service.apply_batch_with_failpoint(
            "principal-a".to_owned(),
            "tenant-a".to_owned(),
            "batch-1".to_owned(),
            [7; 32],
            vec![
                ("secret/a".to_owned(), Some(Secret::new(b"a".to_vec())?)),
                ("secret/b".to_owned(), Some(Secret::new(b"b".to_vec())?)),
            ],
            Failpoint::AfterSnapshotPublication,
        ) {
            Err(ServiceError::OutcomeUnknown { recovery_reference }) => recovery_reference,
            _ => return Err(ServiceError::CorruptState),
        };
        drop(service);
        let service = DurableService::reopen(&root.0, TestBarrier::new(), 8)?;
        assert_eq!(service.generation(), 1);
        assert_eq!(service.retained_request_count(), 1);
        assert_eq!(
            service.reconcile(&reference),
            ReconciliationStatus::Committed { generation: 1 }
        );
        assert_eq!(
            service
                .get("tenant-a", "secret/a")?
                .as_ref()
                .map(Secret::expose),
            Some(&b"a"[..])
        );
        assert_eq!(
            service
                .get("tenant-a", "secret/b")?
                .as_ref()
                .map(Secret::expose),
            Some(&b"b"[..])
        );
        Ok(())
    }
}
