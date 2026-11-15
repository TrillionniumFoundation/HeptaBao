//! Explicit fresh reconciliation of an authenticated cold pending record.
//! Reopening an old pending record alone never dispatches a physical mutation.
use super::*;

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    pub fn immutable_retirement_status(
        &mut self,
    ) -> Result<Option<ImmutableRetirementStatus>, ServiceError> {
        if self.unresolved {
            return Err(ServiceError::RecoveryRequired);
        }
        self.verify_live_ownership()?;
        self.retirement_record()?
            .map(|(bytes, record)| {
                Ok(ImmutableRetirementStatus {
                    phase: record.phase.name(),
                    pending: !record.phase.is_terminal(),
                    record_sha256: raw_digest(bytes.expose()),
                    original_pending_sha256: record.original_pending_digest()?,
                    original_completion_recorded: record.phase
                        == RetirementPhase::OriginalCompleted,
                    historical_request_outcome_reclassified: false,
                    selected_objects: record.entries.len(),
                    original_retirement_generation: record.retirement_generation,
                    active_retirement_generation: record.active_retirement_generation(),
                    replay_epoch: record.replay_epoch,
                    reconciliation_attempt: record
                        .lineage
                        .as_ref()
                        .map_or(0, |lineage| lineage.attempt),
                })
            })
            .transpose()
    }

    /// Caller supplies a newly authenticated complete current typed closure,
    /// current root/cursor conditions, and a fresh original Actor/deadline.
    /// expected_pending selects the actual fixed-slot record, never filenames.
    pub fn reconcile_pending_immutable_retirement(
        &mut self,
        request: ImmutableRetirementRequest,
        expected_pending: [u8; 32],
        before: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<ImmutableRetirementOutcome, ServiceError> {
        self.reconcile_pending_immutable_retirement_owned(
            request,
            expected_pending,
            before,
            RetirementCatalog::Standalone,
            &mut |_| Ok(()),
        )
    }

    pub(super) fn reconcile_pending_immutable_retirement_owned(
        &mut self,
        request: ImmutableRetirementRequest,
        expected_pending: [u8; 32],
        before: &mut impl FnMut() -> Result<(), ServiceError>,
        catalog: RetirementCatalog,
        boundary: &mut impl FnMut(NativeHaLocalRetirementBoundary) -> Result<(), ServiceError>,
    ) -> Result<ImmutableRetirementOutcome, ServiceError> {
        before()?;
        self.check_immutable_source_session(&request.session)?;
        if request.session.namespace != "system"
            || request.session.resource != "state"
            || request.retained_resources.is_empty()
            || request.retained_resources.len() > MAX_OBJECTS
            || request.conditions.len() < 3
            || request.conditions.len() > MAX_CONDITIONS
            || request.authorization_digest == [0; 32]
        {
            return Err(ServiceError::InvalidResource);
        }
        validate_identifier(&request.principal)?;
        validate_identifier(&request.operation_id)?;
        let begin_id = format!("{}-reconcile", request.operation_id);
        let done_id = format!("{}-complete", request.operation_id);
        validate_identifier(&begin_id)?;
        validate_identifier(&done_id)?;
        let mut names = BTreeSet::new();
        for condition in &request.conditions {
            validate_resource(&condition.resource)?;
            if condition.resource == IMMUTABLE_RETIREMENT_RESOURCE
                || !names.insert(condition.resource.as_str())
            {
                return Err(ServiceError::InvalidResource);
            }
        }
        for resource in [
            "state",
            "state-native-v6/active-publication-cursor",
            "state-native-v6/active-source-root",
        ] {
            if !request
                .conditions
                .iter()
                .any(|condition| condition.resource == resource && condition.expected.is_some())
            {
                return Err(ServiceError::InvalidResource);
            }
        }
        if request
            .conditions
            .iter()
            .find(|condition| condition.resource == "state")
            .and_then(|condition| condition.expected.as_ref())
            .map(Secret::expose)
            != Some(request.session.root.expose())
        {
            return Err(ServiceError::PublicationConditionConflict);
        }
        self.check_retirement_conditions(&request.conditions)?;
        self.check_immutable_retirement_catalog(catalog, &request.conditions, before)?;
        let (old_bytes, mut record) = self
            .retirement_record()?
            .ok_or(ServiceError::PublicationConditionConflict)?;
        if record.phase.is_terminal() || raw_digest(old_bytes.expose()) != expected_pending {
            return Err(ServiceError::PublicationConditionConflict);
        }
        let generation = self.generation();
        let epoch = self.replay_epoch;
        let store_id = request.session.store_id;
        if record.replay_epoch != epoch || record.active_retirement_generation() > generation {
            return Err(ServiceError::PublicationConditionConflict);
        }
        let selected_addresses = record
            .entries
            .iter()
            .map(|entry| (entry.slot.locator.store_id(), entry.slot.locator.address()))
            .collect::<BTreeSet<_>>();
        if selected_addresses.len() != record.entries.len()
            || record.entries.iter().any(|entry| {
                entry.slot.locator.store_id() != store_id
                    || request.retained_resources.contains(&entry.slot.resource)
                    || self
                        .snapshot
                        .entries
                        .contains_key(&("system".into(), entry.slot.resource.clone()))
            })
        {
            return Err(ServiceError::PublicationConditionConflict);
        }
        let mut addresses = BTreeSet::new();
        let mut reached = BTreeSet::new();
        let mut registered = 0_usize;
        for ((namespace, resource), value) in &self.snapshot.entries {
            before()?;
            if namespace != "system" || !resource.starts_with(OBJECT_PREFIX) {
                continue;
            }
            let slot = Slot::decode(resource, value.expose())?;
            let address = (slot.locator.store_id(), slot.locator.address());
            if slot.locator.store_id() != store_id
                || !addresses.insert(address)
                || selected_addresses.contains(&address)
            {
                return Err(ServiceError::PublicationConditionConflict);
            }
            registered = registered
                .checked_add(1)
                .filter(|count| *count <= MAX_OBJECTS)
                .ok_or(ServiceError::RequestCapacityExhausted)?;
            if request.retained_resources.contains(resource) {
                reached.insert(resource.clone());
            }
        }
        if reached != request.retained_resources {
            return Err(ServiceError::CorruptState);
        }
        self.check_immutable_source_session(&request.session)?;
        drop(request.session);
        Arc::get_mut(&mut self.restore_instance)
            .ok_or(ServiceError::PublicationConditionConflict)?;
        before()?;
        let objects = record
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.slot.locator,
                    entry.slot.ciphertext_bytes,
                    entry.ciphertext_digest,
                )
            })
            .collect::<Vec<_>>();
        let prepared = {
            let barrier = &self.barrier;
            let mut authenticate = |index: usize, bytes: &[u8]| {
                super::authenticate(
                    barrier,
                    record.entries.get(index).ok_or(BackendError::Corrupt)?,
                    bytes,
                )
            };
            let mut gate = || before().map_err(|_| BackendError::Unavailable);
            self.backend
                .prepare_immutable_reconciliation(&objects, &mut authenticate, &mut gate)
                .map_err(map_backend_error)?
        };
        let present_mask = prepared.present_mask();
        let present_count = present_mask.count_ones() as usize;
        let descriptor_digest = prepared.descriptor_digest();
        before()?;
        self.check_retirement_conditions(&request.conditions)?;
        if self.generation() != generation
            || self.replay_epoch != epoch
            || self
                .get("system", IMMUTABLE_RETIREMENT_RESOURCE)?
                .as_ref()
                .map(Secret::expose)
                != Some(old_bytes.expose())
        {
            return Err(ServiceError::PublicationConditionConflict);
        }
        if present_count == 0 {
            drop(prepared);
            let selected = record
                .entries
                .iter()
                .map(|entry| entry.slot.locator)
                .collect::<Vec<_>>();
            let mut gate = || before().map_err(|_| BackendError::Unavailable);
            self.backend
                .confirm_immutable_retirement_absent(&selected, &mut gate)
                .map_err(map_backend_error)?;
            before()?;
            self.check_retirement_conditions(&request.conditions)?;
            if self.generation() != generation || self.replay_epoch != epoch {
                return Err(ServiceError::PublicationConditionConflict);
            }
            record.phase = RetirementPhase::AbsenceConfirmed;
            let mut conditions = copy_conditions(&request.conditions);
            conditions.push(PublicationCondition {
                resource: IMMUTABLE_RETIREMENT_RESOURCE.into(),
                expected: Some(old_bytes),
            });
            for entry in &record.entries {
                conditions.push(PublicationCondition {
                    resource: entry.slot.resource.clone(),
                    expected: None,
                });
            }
            let expected_generation = generation
                .checked_add(1)
                .ok_or(ServiceError::GenerationOverflow)?;
            let outcome = self.apply_batch_conditionally_with_io_gate(
                BatchPublication {
                    replay_epoch: epoch,
                    principal: request.principal,
                    namespace: "system".into(),
                    request_id: done_id,
                    authorization_digest: request.authorization_digest,
                    mutations: vec![(IMMUTABLE_RETIREMENT_RESOURCE.into(), Some(record.encode()?))],
                },
                conditions,
                before,
            );
            if !matches!(outcome, Ok(MutationOutcome::Committed { generation: actual, .. }) if actual == expected_generation)
            {
                self.unresolved = true;
                return Err(ServiceError::RecoveryRequired);
            }
            return Ok(ImmutableRetirementOutcome {
                generation: self.generation(),
                removed_objects: 0,
                removed_ciphertext_bytes: 0,
                confirmed_absent_objects: record.entries.len(),
                registered_objects_before: registered,
                retained_objects: request.retained_resources.len(),
            });
        }
        if self
            .ledger
            .len()
            .checked_add(2)
            .is_none_or(|count| count > self.max_retained_requests)
        {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        let active_generation = generation
            .checked_add(1)
            .ok_or(ServiceError::GenerationOverflow)?;
        let lineage = ReconciliationLineage {
            original_format: record.original_format(),
            original_pending_digest: record.original_pending_digest()?,
            predecessor_digest: expected_pending,
            attempt: record
                .lineage
                .as_ref()
                .map_or(0, |lineage| lineage.attempt)
                .checked_add(1)
                .ok_or(ServiceError::GenerationOverflow)?,
            source_generation: generation,
            publication_generation: active_generation,
            replay_epoch: epoch,
            selection_digest: selection_digest(&request.conditions),
            descriptor_digest,
            present_mask,
        };
        record.format = RecordFormat::V2;
        record.phase = RetirementPhase::ReconciliationPending;
        record.lineage = Some(lineage);
        let pending = record.encode()?;
        let mutations = vec![(IMMUTABLE_RETIREMENT_RESOURCE.into(), Some(pending.clone()))];
        self.reserve_retirement_pair(
            &request.principal,
            &begin_id,
            &done_id,
            request.authorization_digest,
            &mutations,
            &pending,
        )?;
        let mut conditions = copy_conditions(&request.conditions);
        conditions.push(PublicationCondition {
            resource: IMMUTABLE_RETIREMENT_RESOURCE.into(),
            expected: Some(old_bytes),
        });
        for entry in &record.entries {
            conditions.push(PublicationCondition {
                resource: entry.slot.resource.clone(),
                expected: None,
            });
        }
        before()?;
        #[cfg(test)]
        test_boundary(4)?;
        let outcome = self.apply_batch_conditionally_with_io_gate(
            BatchPublication {
                replay_epoch: epoch,
                principal: request.principal.clone(),
                namespace: "system".into(),
                request_id: begin_id,
                authorization_digest: request.authorization_digest,
                mutations,
            },
            conditions,
            &mut *before,
        )?;
        if !matches!(outcome, MutationOutcome::Committed { generation: actual, .. } if actual == active_generation)
        {
            self.unresolved = true;
            return Err(ServiceError::RecoveryRequired);
        }
        let result = (|| -> Result<ImmutableRetirementOutcome, ServiceError> {
            #[cfg(test)]
            test_boundary(5)?;
            boundary(NativeHaLocalRetirementBoundary::KnownPending)?;
            before()?;
            self.check_retirement_conditions(&request.conditions)?;
            if self.generation() != active_generation
                || self.replay_epoch != epoch
                || self
                    .get("system", IMMUTABLE_RETIREMENT_RESOURCE)?
                    .as_ref()
                    .map(Secret::expose)
                    != Some(pending.expose())
                || record.entries.iter().any(|entry| {
                    self.snapshot
                        .entries
                        .contains_key(&("system".into(), entry.slot.resource.clone()))
                })
            {
                return Err(ServiceError::PublicationConditionConflict);
            }
            Arc::get_mut(&mut self.restore_instance)
                .ok_or(ServiceError::PublicationConditionConflict)?;
            {
                let barrier = &self.barrier;
                let mut authenticate = |index: usize, bytes: &[u8]| {
                    super::authenticate(
                        barrier,
                        record.entries.get(index).ok_or(BackendError::Corrupt)?,
                        bytes,
                    )
                };
                let mut gate = || before().map_err(|_| BackendError::Unavailable);
                self.backend
                    .finish_prepared_immutable_reconciliation(
                        prepared,
                        &mut authenticate,
                        &mut gate,
                    )
                    .map_err(map_backend_error)?;
            }
            #[cfg(test)]
            test_boundary(6)?;
            boundary(NativeHaLocalRetirementBoundary::PhysicalCompleted)?;
            before()?;
            self.check_retirement_conditions(&request.conditions)?;
            if self.generation() != active_generation || self.replay_epoch != epoch {
                return Err(ServiceError::PublicationConditionConflict);
            }
            record.phase = RetirementPhase::ReconciliationCompleted;
            let mut conditions = copy_conditions(&request.conditions);
            conditions.push(PublicationCondition {
                resource: IMMUTABLE_RETIREMENT_RESOURCE.into(),
                expected: Some(pending),
            });
            for entry in &record.entries {
                conditions.push(PublicationCondition {
                    resource: entry.slot.resource.clone(),
                    expected: None,
                });
            }
            let expected_generation = active_generation
                .checked_add(1)
                .ok_or(ServiceError::GenerationOverflow)?;
            let outcome = self.apply_batch_conditionally_with_io_gate(
                BatchPublication {
                    replay_epoch: epoch,
                    principal: request.principal,
                    namespace: "system".into(),
                    request_id: done_id,
                    authorization_digest: request.authorization_digest,
                    mutations: vec![(IMMUTABLE_RETIREMENT_RESOURCE.into(), Some(record.encode()?))],
                },
                conditions,
                &mut *before,
            )?;
            if !matches!(outcome, MutationOutcome::Committed { generation: actual, .. } if actual == expected_generation)
            {
                return Err(ServiceError::RecoveryRequired);
            }
            before()?;
            Ok(ImmutableRetirementOutcome {
                generation: self.generation(),
                removed_objects: present_count,
                removed_ciphertext_bytes: record
                    .entries
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| present_mask & (1_u32 << *index) != 0)
                    .map(|(_, entry)| entry.slot.ciphertext_bytes as u64)
                    .sum(),
                confirmed_absent_objects: record.entries.len() - present_count,
                registered_objects_before: registered,
                retained_objects: request.retained_resources.len(),
            })
        })();
        if result.is_err() {
            self.unresolved = true;
        }
        result
    }
}
