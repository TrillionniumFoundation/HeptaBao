//! Local .hbo retirement through the original HA request and existing local
//! authenticated ledger. Historical typed mark DATA is usable only inside the
//! live private HaProcess custody; no inspection response can invoke this lane.
use super::*;
use heptabao_durable_service::{ImmutableRetirementRequest, NativeHaLocalRetentionOwner};

pub(super) fn public_status(
    status: Option<heptabao_durable_service::ImmutableRetirementStatus>,
) -> Value {
    status.map_or(Value::Null, |status| json!({
        "phase":status.phase, "pending":status.pending,
        "record_sha256":hex(&status.record_sha256),
        "original_pending_sha256":hex(&status.original_pending_sha256),
        "original_completion_recorded":status.original_completion_recorded,
        "historical_request_outcome_reclassified":status.historical_request_outcome_reclassified,
        "selected_objects":status.selected_objects,
        "original_retirement_generation":status.original_retirement_generation,
        "active_retirement_generation":status.active_retirement_generation,
        "replay_epoch":status.replay_epoch, "reconciliation_attempt":status.reconciliation_attempt
    }))
}

impl Service {
    pub(super) fn execute_native_ha_local_retirement(
        &mut self,
        plan: &mut GcDelivery,
        source_generation: u64,
        conditions: Vec<PublicationCondition>,
        root_bytes: Secret,
    ) -> Result<Response, Response> {
        let expected = match plan.operation {
            Operation::RetireLocal => None,
            Operation::ReconcileLocal(expected) => Some(expected),
            _ => return Err(rejected()),
        };
        plan.check_source(self)?;
        let prior = self
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .immutable_retirement_status()
            .map_err(|_| rejected())?;
        match expected {
            Some(digest)
                if prior
                    .as_ref()
                    .is_none_or(|status| !status.pending || status.record_sha256 != digest) =>
            {
                return Err(Response::error(
                    409,
                    "exact pending local HA retirement record required",
                ));
            }
            None if prior.as_ref().is_some_and(|status| status.pending) => {
                return Err(Response::error(
                    409,
                    "local HA retirement is pending; reconcile its exact digest",
                ));
            }
            _ => {}
        }
        let root = self.native_root.as_ref().ok_or_else(rejected)?.clone();
        if root.encode().map_err(|_| rejected())?.as_slice() != root_bytes.expose() {
            return Err(rejected());
        }
        // Uses the actual complete local materializer and releases its source
        // session/profile before the final retirement session is opened.
        let current = self.native_ha_current_local_mark(plan, &root)?;
        plan.check_source(self)?;
        let original_checkpoint = plan.checkpoint;
        let operation = format!(
            "native6-ha-local-gc-{}",
            hex(&crypto::random::<16>().map_err(|_| rejected())?),
        );
        let ha = Arc::clone(&plan.ha);
        let process = ha.lock_for_request().map_err(|_| rejected())?;
        let durable = self.durable.as_mut().ok_or_else(rejected)?;
        let session =
            native_blob_source::session(durable, root_bytes.expose()).map_err(|_| rejected())?;
        if session.generation() != source_generation {
            return Err(rejected());
        }
        let request = ImmutableRetirementRequest {
            session,
            principal: "native-v6-ha-local-gc".into(),
            operation_id: operation,
            authorization_digest: original_checkpoint.0.digest(),
            conditions,
            retained_resources: current,
        };
        let result = process
            .with_native_v6_local_retirement(
                plan.deadline,
                original_checkpoint.0,
                &mut || {
                    plan.authorize_original()
                        .map_err(|_| LocalV6BlobError::CorruptOrChanged)
                },
                |owner| {
                    let fingerprint = owner.catalog_sha256();
                    let root_count = owner.root_count();
                    let historical_count = owner.typed_retained_resources().len();
                    let outcome = match expected {
                        Some(digest) => durable.reconcile_native_ha_local_immutable_retirement(
                            request, digest, &owner,
                        ),
                        None => durable.retire_native_ha_local_immutable_objects(request, &owner),
                    };
                    outcome.map(|outcome| (fingerprint, root_count, historical_count, outcome))
                },
            )
            .map_err(|_| rejected())?;
        drop(process);
        let unresolved = durable.recovery_required();
        if unresolved {
            self.recovery_required = true;
            self.ha_activation = None;
            self.ha_read_cache = None;
        }
        let (fingerprint, root_count, historical_count, outcome) = result.map_err(|_| {
            if unresolved {
                Response::error(503, "native HA local retirement outcome unknown; reopen the same owner and reconcile its exact pending digest; do not replay")
            } else {
                rejected()
            }
        })?;
        let finish = (|| -> Result<Response, Response> {
            let delta = if outcome.removed_objects > 0 {
                2
            } else if outcome.confirmed_absent_objects > 0 {
                1
            } else {
                0
            };
            if source_generation.checked_add(delta) != Some(outcome.generation) {
                return Err(rejected());
            }
            let checkpoint = self.native_ha_gc_checkpoint()?;
            if checkpoint.0 != original_checkpoint.0
                || self
                    .durable
                    .as_ref()
                    .is_none_or(|durable| durable.generation() != outcome.generation)
            {
                return Err(rejected());
            }
            plan.checkpoint = checkpoint;
            plan.check_source(self)?;
            // The real retention guard has now ended. A fresh ordinary proof
            // may reenter Raft only here, before the existing audit/terminal
            // delivery owner stages this exact response.
            let after = self
                .capture_native_request_proof(&mut || plan.authorize_original())?
                .ok_or_else(rejected)?;
            if after.identity() != checkpoint.0 || after.generation() != outcome.generation {
                return Err(rejected());
            }
            after.check_with(self, Self::check_native_installed)?;
            plan.check_source(self)?;
            let status = self
                .durable
                .as_mut()
                .ok_or_else(rejected)?
                .immutable_retirement_status()
                .map_err(|_| rejected())?;
            plan.check_source(self)?;
            Ok(Response::ok(json!({"data":{
                "schema":if expected.is_some() { "heptabao-native-ha-local-reconciliation-v1" } else { "heptabao-native-ha-local-retirement-v1" },
                "scope":"local-barrier-ciphertext", "local_barriers_gc_qualified":false,
                "generation":outcome.generation,
                "removed_objects":outcome.removed_objects,
                "removed_ciphertext_bytes":outcome.removed_ciphertext_bytes,
                "confirmed_absent_objects":outcome.confirmed_absent_objects,
                "registered_objects_before":outcome.registered_objects_before,
                "retained_objects":outcome.retained_objects,
                "retained_catalog_sha256":hex(&fingerprint),
                "retained_roots":root_count,
                "historical_typed_resources":historical_count,
                "retirement":public_status(status),
                "historical_request_outcome_reclassified":false
            }})))
        })();
        if finish.is_err() {
            self.recovery_required = true;
            self.ha_activation = None;
            self.ha_read_cache = None;
        }
        finish
    }
}
