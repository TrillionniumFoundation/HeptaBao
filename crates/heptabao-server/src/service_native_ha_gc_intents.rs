//! Persistent metadata preparation is separate from physical shared GC.
//! Old capsules support only a new read-only reconciliation, never replay.
use super::*;
use heptabao_durable_service::{
    NativeHaIntentReconciliationRequest, NativeHaIntentResolution, NativeHaIntentRetirementRequest,
    NativeHaIntentRetirementStatus,
};
use heptabao_raft_runtime::NativeV6IntentRetirementRecovery;

#[path = "service_native_ha_gc_intent_owner.rs"]
mod intent_owner;

pub(super) fn public_status(status: Option<NativeHaIntentRetirementStatus>) -> Value {
    status.map_or(Value::Null, |status| {
        json!({
            "phase":status.phase, "pending":status.pending,
            "record_sha256":hex(&status.record_sha256),
            "original_pending_sha256":hex(&status.original_pending_sha256),
            "capsule_sha256":hex(&status.capsule_sha256),
            "serial":status.serial, "selected_intents":status.selected_intents,
            "pending_generation":status.pending_generation,
            "replay_epoch":status.replay_epoch,
            "historical_request_outcome_reclassified":status.historical_request_outcome_reclassified
        })
    })
}

impl Service {
    fn native_ha_intent_previous(
        &mut self,
        operation: Operation,
    ) -> Result<Option<NativeV6IntentRetirementRecovery>, Response> {
        let durable = self.durable.as_mut().ok_or_else(rejected)?;
        let status = durable
            .native_ha_intent_retirement_status()
            .map_err(|_| rejected())?;
        match operation {
            Operation::RetireIntents | Operation::ActivateRetainedRoots => {
                if status.is_some_and(|status| status.pending) {
                    return Err(Response::error(
                        409,
                        "explicit exact pending intent reconciliation required; do not replay",
                    ));
                }
                Ok(None)
            }
            Operation::ReconcileIntents(expected) => {
                if status.is_none_or(|status| !status.pending || status.record_sha256 != expected) {
                    return Err(Response::error(409, "exact pending intent record required"));
                }
                let capsule = durable
                    .native_ha_pending_intent_retirement(expected)
                    .map_err(|_| rejected())?;
                NativeV6IntentRetirementRecovery::decode_for_reconciliation(capsule.expose())
                    .map(Some)
                    .map_err(|_| rejected())
            }
            _ => Err(rejected()),
        }
    }

    pub(super) fn execute_native_ha_intent_gc(
        &mut self,
        plan: &mut GcDelivery,
        source_generation: u64,
        conditions: Vec<PublicationCondition>,
        root_bytes: Secret,
    ) -> Result<Response, Response> {
        let previous = self.native_ha_intent_previous(plan.operation)?;
        let roots_activation = matches!(plan.operation, Operation::ActivateRetainedRoots)
            || previous
                .as_ref()
                .is_some_and(NativeV6IntentRetirementRecovery::activates_retained_roots);
        plan.check_source(self)?;
        let original_checkpoint = plan.checkpoint;
        let operation_id = format!(
            "native6-ha-intents-{}",
            hex(&crypto::random::<16>().map_err(|_| rejected())?)
        );
        let ha = Arc::clone(&plan.ha);
        let process = ha.lock_for_request().map_err(|_| rejected())?;
        let durable = self.durable.as_mut().ok_or_else(rejected)?;
        let session =
            native_blob_source::session(durable, root_bytes.expose()).map_err(|_| rejected())?;
        if session.generation() != source_generation {
            return Err(rejected());
        }
        let mut before = || {
            plan.authorize_original()
                .map_err(|_| LocalV6BlobError::CorruptOrChanged)
        };
        // The live prepared owner can be constructed only before durable
        // Pending. Reconciliation receives data plus a NEW actual read owner;
        // it has no code path to preparation or Raft submission.
        let result = match plan.operation {
            Operation::RetireIntents | Operation::ActivateRetainedRoots => {
                let owner = if roots_activation {
                    process.prepare_native_v6_retained_root_activation_owner(
                        plan.deadline,
                        original_checkpoint.0,
                        &mut before,
                    )
                } else {
                    process.prepare_native_v6_intent_retirement_owner(
                        plan.deadline,
                        original_checkpoint.0,
                        &mut before,
                    )
                }
                .map_err(|_| rejected())?;
                durable
                    .retire_native_ha_intents(
                        NativeHaIntentRetirementRequest {
                            session,
                            principal: "native-v6-ha-intent-gc".into(),
                            operation_id,
                            authorization_digest: original_checkpoint.0.digest(),
                            conditions,
                            owner: intent_owner::Prepared::new(owner),
                        },
                        &mut || {
                            plan.authorize_original()
                                .map_err(|_| ServiceError::BarrierFailure)
                        },
                    )
                    .map(|outcome| (outcome.generation, 2_u64, "original-completed"))
            }
            Operation::ReconcileIntents(expected_pending_sha256) => {
                let observer = process
                    .observe_native_v6_intent_retirement_owner(
                        plan.deadline,
                        original_checkpoint.0,
                        previous.as_ref().ok_or_else(rejected)?,
                        &mut before,
                    )
                    .map_err(|_| rejected())?;
                durable
                    .reconcile_native_ha_intent_retirement(
                        NativeHaIntentReconciliationRequest {
                            session,
                            principal: "native-v6-ha-intent-gc".into(),
                            operation_id,
                            authorization_digest: original_checkpoint.0.digest(),
                            conditions,
                            expected_pending_sha256,
                            observer: intent_owner::Observation::new(observer),
                        },
                        &mut || {
                            plan.authorize_original()
                                .map_err(|_| ServiceError::BarrierFailure)
                        },
                    )
                    .map(|outcome| {
                        (
                            outcome.generation,
                            1_u64,
                            match outcome.resolution {
                                NativeHaIntentResolution::EffectsObserved => "effects-observed",
                                NativeHaIntentResolution::SupersededByNewRoot => {
                                    "source-superseded"
                                }
                                NativeHaIntentResolution::Pending => "pending",
                            },
                        )
                    })
            }
            _ => return Err(rejected()),
        };
        drop(process);
        let unresolved = durable.recovery_required();
        if unresolved {
            self.recovery_required = true;
            self.ha_activation = None;
            self.ha_read_cache = None;
        }
        let (generation, delta, observation) = result.map_err(|error| {
            if unresolved {
                Response::error(503, "native HA intent retirement outcome unknown; reopen this owner and reconcile its exact pending digest; do not replay")
            } else if matches!(error, ServiceError::PublicationConditionConflict) {
                Response::error(409, "pending intent effects are not yet proved by this new observation")
            } else { rejected() }
        })?;
        let finish = (|| -> Result<Response, Response> {
            if source_generation.checked_add(delta) != Some(generation) {
                return Err(rejected());
            }
            let checkpoint = self.native_ha_gc_checkpoint()?;
            if checkpoint.0 != original_checkpoint.0
                || self
                    .durable
                    .as_ref()
                    .is_none_or(|durable| durable.generation() != generation)
            {
                return Err(rejected());
            }
            plan.checkpoint = checkpoint;
            plan.check_source(self)?;
            let after = self
                .capture_native_request_proof(&mut || plan.authorize_original())?
                .ok_or_else(rejected)?;
            if after.identity() != checkpoint.0 || after.generation() != generation {
                return Err(rejected());
            }
            after.check_with(self, Self::check_native_installed)?;
            plan.check_source(self)?;
            let status = self
                .durable
                .as_mut()
                .ok_or_else(rejected)?
                .native_ha_intent_retirement_status()
                .map_err(|_| rejected())?;
            plan.check_source(self)?;
            Ok(Response::ok(json!({"data":{
                "schema":if matches!(plan.operation, Operation::ReconcileIntents(_)) { "heptabao-native-ha-intent-reconciliation-v1" } else { "heptabao-native-ha-intent-retirement-v1" },
                "scope":if roots_activation { "raft-retained-root-provenance-only" } else { "raft-intent-metadata-only" }, "generation":generation,
                "retained_root_activation_observed":roots_activation && matches!(observation, "original-completed" | "effects-observed"),
                "observation":observation, "retirement":public_status(status),
                "physical_deletion_authorized":false,
                "local_barrier_objects_retained":true, "local_barriers_gc_qualified":false,
                "historical_request_outcome_reclassified":false
            }})))
        })();
        if finish.is_err() {
            self.recovery_required = true;
        }
        finish
    }
}

#[cfg(test)]
pub(super) fn fail_after_commit_once() {
    intent_owner::fail_after_commit_once();
}

#[cfg(test)]
pub(super) fn submission_owners_consumed() -> usize {
    intent_owner::submission_owners_consumed()
}
