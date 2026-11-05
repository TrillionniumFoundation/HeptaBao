//! Two known local commits around one affine external submission, and a
//! separate read-only reconciliation path with no submission capability.
use super::*;

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    pub fn retire_native_ha_intents<O: NativeHaIntentOwner>(
        &mut self,
        request: NativeHaIntentRetirementRequest<O>,
        before: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<NativeHaIntentRetirementOutcome, ServiceError> {
        before()?;
        self.ha_intent_admit(
            &request.session,
            &request.principal,
            &request.operation_id,
            request.authorization_digest,
            &request.conditions,
        )?;
        self.ensure_no_pending_ha_intent_retirement()?;
        let generation = self.generation();
        let epoch = self.replay_epoch;
        let selected = request.owner.selection()?;
        let mut record = Record {
            phase: Phase::Pending,
            source_generation: generation,
            pending_generation: generation
                .checked_add(1)
                .ok_or(ServiceError::GenerationOverflow)?,
            epoch,
            serial: selected.serial,
            selected_intents: selected.selected_intents,
            command_sha256: selected.command_sha256,
            leader_id: 0,
            log_index: 0,
            capsule: selected.capsule,
        };
        let pending = record.encode()?;
        let begin_id = format!("{}-pending", request.operation_id);
        let done_id = format!("{}-complete", request.operation_id);
        validate_identifier(&begin_id)?;
        validate_identifier(&done_id)?;
        request.owner.verify(before)?;
        self.check_immutable_source_session(&request.session)?;
        drop(request.session);
        Arc::get_mut(&mut self.restore_instance)
            .ok_or(ServiceError::PublicationConditionConflict)?;
        self.reserve_ha_intent_pair(
            &request.principal,
            &begin_id,
            &done_id,
            request.authorization_digest,
            &pending,
        )?;
        request.owner.verify(before)?;
        let stable = request.owner.selection()?;
        if stable.capsule.expose() != record.capsule.expose()
            || stable.serial != record.serial
            || stable.selected_intents != record.selected_intents
            || stable.command_sha256 != record.command_sha256
        {
            return Err(ServiceError::PublicationConditionConflict);
        }
        self.ha_intent_check_conditions(&request.conditions)?;
        if self.generation() != generation || self.replay_epoch != epoch {
            return Err(ServiceError::PublicationConditionConflict);
        }
        let previous = self.ha_intent_record()?.map(|(bytes, _)| bytes);
        let mut conditions = copy_conditions(&request.conditions);
        conditions.push(PublicationCondition {
            resource: NATIVE_HA_INTENT_RETIREMENT_RESOURCE.into(),
            expected: previous,
        });
        before()?;
        let begin = self.apply_batch_conditionally_with_io_gate(
            BatchPublication {
                replay_epoch: epoch,
                principal: request.principal.clone(),
                namespace: "system".into(),
                request_id: begin_id,
                authorization_digest: request.authorization_digest,
                mutations: vec![(
                    NATIVE_HA_INTENT_RETIREMENT_RESOURCE.into(),
                    Some(pending.clone()),
                )],
            },
            conditions,
            &mut *before,
        )?;
        if !matches!(begin, MutationOutcome::Committed { generation: actual, .. } if actual == record.pending_generation)
        {
            self.unresolved = true;
            return Err(ServiceError::RecoveryRequired);
        }
        let result = (|| -> Result<NativeHaIntentRetirementOutcome, ServiceError> {
            let completed = {
                let mut known = || -> Result<(), ServiceError> {
                    before()?;
                    self.verify_live_ownership()?;
                    self.ha_intent_check_conditions(&request.conditions)?;
                    if self.generation() != record.pending_generation
                        || self.replay_epoch != epoch
                        || self
                            .get("system", NATIVE_HA_INTENT_RETIREMENT_RESOURCE)?
                            .as_ref()
                            .map(Secret::expose)
                            != Some(pending.expose())
                    {
                        return Err(ServiceError::PublicationConditionConflict);
                    }
                    Arc::get_mut(&mut self.restore_instance)
                        .ok_or(ServiceError::PublicationConditionConflict)?;
                    before()
                };
                known()?;
                request.owner.submit(&mut known)?
            };
            completed.verify_completed(before)?;
            let receipt = completed.committed();
            if receipt.leader_id == 0
                || receipt.log_index == 0
                || receipt.log_index < record.serial
                || receipt.command_sha256 != record.command_sha256
            {
                return Err(ServiceError::CorruptState);
            }
            before()?;
            self.verify_live_ownership()?;
            self.ha_intent_check_conditions(&request.conditions)?;
            if self.generation() != record.pending_generation || self.replay_epoch != epoch {
                return Err(ServiceError::PublicationConditionConflict);
            }
            record.phase = Phase::Completed;
            record.leader_id = receipt.leader_id;
            record.log_index = receipt.log_index;
            let terminal = record.encode()?;
            if terminal.expose().len() != pending.expose().len() {
                return Err(ServiceError::CorruptState);
            }
            let mut conditions = copy_conditions(&request.conditions);
            conditions.push(PublicationCondition {
                resource: NATIVE_HA_INTENT_RETIREMENT_RESOURCE.into(),
                expected: Some(pending),
            });
            let mut terminal_gate = || completed.verify_completed(before);
            let done = self.apply_batch_conditionally_with_io_gate(
                BatchPublication {
                    replay_epoch: epoch,
                    principal: request.principal,
                    namespace: "system".into(),
                    request_id: done_id,
                    authorization_digest: request.authorization_digest,
                    mutations: vec![(NATIVE_HA_INTENT_RETIREMENT_RESOURCE.into(), Some(terminal))],
                },
                conditions,
                &mut terminal_gate,
            )?;
            if !matches!(done, MutationOutcome::Committed { generation: actual, .. } if Some(actual) == record.pending_generation.checked_add(1))
            {
                return Err(ServiceError::RecoveryRequired);
            }
            completed.verify_completed(before)?;
            Ok(NativeHaIntentRetirementOutcome {
                generation: self.generation(),
                committed: receipt,
            })
        })();
        if result.is_err() {
            self.unresolved = true;
        }
        result
    }

    pub fn reconcile_native_ha_intent_retirement<O: NativeHaIntentReconciliationOwner>(
        &mut self,
        request: NativeHaIntentReconciliationRequest<O>,
        before: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<NativeHaIntentReconciliationOutcome, ServiceError> {
        before()?;
        self.ha_intent_admit(
            &request.session,
            &request.principal,
            &request.operation_id,
            request.authorization_digest,
            &request.conditions,
        )?;
        let generation = self.generation();
        let epoch = self.replay_epoch;
        let (pending, mut record) = self
            .ha_intent_record()?
            .ok_or(ServiceError::PublicationConditionConflict)?;
        if record.phase != Phase::Pending
            || digest(pending.expose()) != request.expected_pending_sha256
            || record.epoch != epoch
            || record.pending_generation > generation
            || request.observer.capsule_sha256() != digest(record.capsule.expose())
        {
            return Err(ServiceError::PublicationConditionConflict);
        }
        let resolution = request.observer.resolution();
        record.phase = match resolution {
            NativeHaIntentResolution::Pending => {
                return Err(ServiceError::PublicationConditionConflict);
            }
            NativeHaIntentResolution::EffectsObserved => Phase::Observed,
            NativeHaIntentResolution::SupersededByNewRoot => Phase::Superseded,
        };
        let capsule_sha256 = digest(record.capsule.expose());
        request.observer.verify_observation(before)?;
        self.check_immutable_source_session(&request.session)?;
        drop(request.session);
        Arc::get_mut(&mut self.restore_instance)
            .ok_or(ServiceError::PublicationConditionConflict)?;
        self.ha_intent_check_conditions(&request.conditions)?;
        if self.generation() != generation || self.replay_epoch != epoch {
            return Err(ServiceError::PublicationConditionConflict);
        }
        let terminal = record.encode()?;
        let mut conditions = copy_conditions(&request.conditions);
        conditions.push(PublicationCondition {
            resource: NATIVE_HA_INTENT_RETIREMENT_RESOURCE.into(),
            expected: Some(pending),
        });
        // A new local terminal Apply follows the read-only Raft observation.
        // No method on this observer can resubmit the old command.
        let mut terminal_gate = || -> Result<(), ServiceError> {
            request.observer.verify_observation(before)?;
            if request.observer.capsule_sha256() != capsule_sha256
                || request.observer.resolution() != resolution
            {
                return Err(ServiceError::PublicationConditionConflict);
            }
            Ok(())
        };
        terminal_gate()?;
        let result = (|| -> Result<NativeHaIntentReconciliationOutcome, ServiceError> {
            let done = self.apply_batch_conditionally_with_io_gate(
                BatchPublication {
                    replay_epoch: epoch,
                    principal: request.principal,
                    namespace: "system".into(),
                    request_id: request.operation_id,
                    authorization_digest: request.authorization_digest,
                    mutations: vec![(NATIVE_HA_INTENT_RETIREMENT_RESOURCE.into(), Some(terminal))],
                },
                conditions,
                &mut terminal_gate,
            )?;
            if !matches!(done, MutationOutcome::Committed { generation: actual, .. } if Some(actual) == generation.checked_add(1))
            {
                return Err(ServiceError::RecoveryRequired);
            }
            terminal_gate()?;
            Ok(NativeHaIntentReconciliationOutcome {
                generation: self.generation(),
                resolution,
            })
        })();
        if result.is_err() {
            self.unresolved = true;
        }
        result
    }
}
