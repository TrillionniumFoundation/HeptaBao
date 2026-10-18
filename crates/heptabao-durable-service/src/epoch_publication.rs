//! Atomically retire the CURRENT replay ledger and publish a conditional root.
//! The replacement is built only from this live local owner. No incoming
//! backup, archived generation or archived ledger participates in this path.
//! The existing authenticated restore transaction covers every file prefix.
use super::*;

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    /// Publish a locally prepared root/cursor batch together with a strictly
    /// higher replay epoch. The caller must own the application's ACTUAL
    /// committed epoch transition; numeric arguments grant no such authority.
    ///
    /// Unreferenced object/locator batches may be staged under the old epoch.
    /// This single transaction then advances the local generation by one,
    /// retires exactly its current ledger frontier, and installs all supplied
    /// root/cursor mutations. Reopen therefore selects either the complete old
    /// bundle or the complete new bundle; it cannot open new epoch/old root.
    /// A later target epoch permits a cold replica to catch up across multiple
    /// ACTUAL committed transitions without installing intermediate archives.
    ///
    /// The original owner gate and exact generation/epoch/resource conditions
    /// survive all serialization and run immediately before publication. Any
    /// attempted publication failure fences until reopen. This method never
    /// retries a lost acknowledgement or recreates the prior replay ledger.
    pub fn publish_epoch_batch_conditionally_before_publish(
        &mut self,
        expected_generation: u64,
        expected_epoch: u64,
        request: BatchPublication,
        conditions: Vec<PublicationCondition>,
        mut original_owner: impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<MutationOutcome, ServiceError> {
        validate_identifier(&request.principal)?;
        validate_namespace(&request.namespace)?;
        validate_identifier(&request.request_id)?;
        if request.replay_epoch <= expected_epoch {
            return Err(ServiceError::ReplayEpochMismatch);
        }
        if request.authorization_digest == [0; 32] {
            return Err(ServiceError::InvalidAuthorizationDigest);
        }
        if request.mutations.is_empty()
            || request.mutations.len() > MAX_ATOMIC_MUTATIONS
            || conditions.is_empty()
            || conditions.len() > MAX_ATOMIC_MUTATIONS
        {
            return Err(ServiceError::InvalidResource);
        }
        let key = RequestKey {
            principal: request.principal.clone(),
            namespace: request.namespace.clone(),
            request_id: scope_request_id(request.replay_epoch, &request.request_id)?,
        };
        let mut binding = Vec::new();
        binding.extend_from_slice(&expected_generation.to_be_bytes());
        binding.extend_from_slice(&expected_epoch.to_be_bytes());
        binding.extend_from_slice(&request.replay_epoch.to_be_bytes());
        encode_string(&mut binding, &key.principal);
        encode_string(&mut binding, &key.namespace);
        encode_string(&mut binding, &key.request_id);
        binding.extend_from_slice(&request.authorization_digest);
        let mut seen = std::collections::BTreeSet::new();
        for (resource, value) in &request.mutations {
            validate_resource(resource)?;
            if !seen.insert(resource.as_str()) {
                return Err(ServiceError::InvalidResource);
            }
            encode_string(&mut binding, resource);
            match value {
                Some(value) => {
                    binding.push(1);
                    binding.extend_from_slice(&digest32(
                        b"heptabao.durable-service.value.v1", value.expose(),
                    ));
                }
                None => binding.push(0),
            }
        }
        binding.extend_from_slice(b"heptabao.epoch-publication.conditions.v1");
        seen.clear();
        for condition in &conditions {
            validate_resource(&condition.resource)?;
            if !seen.insert(condition.resource.as_str()) {
                return Err(ServiceError::InvalidResource);
            }
            encode_string(&mut binding, &condition.resource);
            match &condition.expected {
                Some(value) => {
                    binding.push(1);
                    binding.extend_from_slice(&digest32(
                        b"heptabao.durable-service.condition-value.v1", value.expose(),
                    ));
                }
                None => binding.push(0),
            }
        }
        let binding_digest = digest32(
            b"heptabao.durable-service.epoch-publication.v1", &binding,
        );
        binding.zeroize();
        self.check_epoch_publication_source(
            (expected_generation, expected_epoch), &request.namespace,
            &conditions, &mut original_owner,
        )?;
        let frontier = self.restore_frontier();
        let generation = expected_generation.checked_add(1)
            .ok_or(ServiceError::GenerationOverflow)?;
        let recovery_reference = recovery_reference(&binding_digest, generation, 1);
        let marker = CommitMarker {
            key: key.clone(), binding_digest,
            recovery_reference: recovery_reference.clone(), generation,
        };
        let mutations = request.mutations.iter().map(|(resource, value)| JournalMutation {
            resource: resource.clone(), value: value.clone(),
        }).collect::<Vec<_>>();
        let candidate_len = candidate_snapshot_plaintext_len(
            &self.snapshot, self.snapshot_plaintext_bytes, &marker, &mutations,
        )?;
        preflight_snapshot_capacity(
            &self.barrier, &self.snapshot, candidate_len, &marker, &mutations,
        )?;
        let mut snapshot = self.snapshot.clone();
        apply_journal_mutations(&mut snapshot, &marker, &mutations)?;
        if snapshot_plaintext_len(&snapshot)? != candidate_len {
            return Err(ServiceError::CorruptState);
        }
        let snapshot_bytes = sealed_snapshot(&self.barrier, &snapshot)?;
        if snapshot_bytes.len() > MAX_FILE_BYTES {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        self.check_epoch_publication_source(
            (expected_generation, expected_epoch), &request.namespace,
            &conditions, &mut original_owner,
        )?;
        // Every old resolved identity is retired at the exact CURRENT local
        // frontier. Retain only this new epoch's actual publication identity.
        let ledger = BTreeMap::from([(key, LedgerRecord {
            binding_digest, recovery_reference: recovery_reference.clone(), generation,
        })]);
        if ledger.len() > self.max_retained_requests {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        let ledger_bytes = sealed_ledger(
            &self.barrier, generation, request.replay_epoch, expected_generation, &ledger,
        )?;
        if ledger_bytes.len() > MAX_FILE_BYTES {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        let checkpoint = checkpoint_marker(&snapshot, &ledger, expected_generation)?;
        let frame = sealed_journal_record(
            &self.barrier, 1, &JournalEvent::Checkpoint(checkpoint),
        )?;
        let mut journal_bytes = Vec::with_capacity(JOURNAL_MAGIC.len() + frame.len());
        journal_bytes.extend_from_slice(JOURNAL_MAGIC);
        journal_bytes.extend_from_slice(&frame);
        if journal_bytes.len() > self.journal_limit || journal_bytes.len() > MAX_FILE_BYTES {
            return Err(ServiceError::JournalCapacityExhausted);
        }
        let prepared = PreparedRestore {
            instance: Arc::clone(&self.restore_instance),
            frontier,
            components: BackupComponents {
                snapshot_bytes, ledger_bytes, journal_bytes, snapshot, ledger,
                replay_epoch: request.replay_epoch,
                retired_through_generation: expected_generation,
                journal_sequence: 1,
            },
        };
        self.check_epoch_publication_source(
            (expected_generation, expected_epoch), &request.namespace,
            &conditions, &mut original_owner,
        )?;
        // Reuses the actual target-identity-bound authenticated FileIntent and
        // backend bundle CAS. No sequence of independent epoch/root writes.
        if let Err(error) = self.restore_prepared(prepared, false) {
            return if self.recovery_required() {
                Err(ServiceError::OutcomeUnknown { recovery_reference })
            } else {
                Err(error)
            };
        }
        if self.verify_live_ownership().and_then(|()| original_owner()).is_err() {
            self.unresolved = true;
            return Err(ServiceError::OutcomeUnknown { recovery_reference });
        }
        Ok(MutationOutcome::Committed { generation, recovery_reference })
    }

    fn check_epoch_publication_source(
        &mut self,
        expected: (u64, u64),
        namespace: &str,
        conditions: &[PublicationCondition],
        original_owner: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        original_owner()?;
        self.verify_live_ownership()?;
        if self.snapshot.generation != expected.0 || self.replay_epoch != expected.1 {
            return Err(ServiceError::PublicationConditionConflict);
        }
        for condition in conditions {
            let actual = self.get(namespace, &condition.resource)?;
            if actual.as_ref().map(Secret::expose)
                != condition.expected.as_ref().map(Secret::expose)
            {
                return Err(ServiceError::PublicationConditionConflict);
            }
        }
        original_owner()
    }
}
