//! Actual Service publication through native Raft, pinned TLS custody and the
//! independent local Shamir owner. Every phase retains the original Actor.
use super::*;
use crate::ha::NativeHaPublicationError;
use crate::ha_state::native_v6::{CodecResult, NativeV6CodecError};
use crate::state_record_root::StateIdentity;
use std::cell::RefCell;

fn rejected() -> Response {
    Response::error(503, "native V6 HA Service publication rejected")
}

impl Service {
    pub(super) fn commit_native_ha_root_plan(
        &mut self,
        state: &State,
        plan: v6_records::NativeRootMigrationPlan,
        migration: bool,
        original_actor: &mut impl FnMut(&AuthState) -> Result<(), Response>,
    ) -> Result<State, Response> {
        let deadline = plan.deadline;
        deadline.check().map_err(|_| rejected())?;
        self.require_native_root_candidate(state)?;
        let ha = self.ha.as_ref().ok_or_else(rejected)?.clone();
        let source_identity = self.current_state_identity()?;
        if migration != matches!(source_identity, StateIdentity::RecordsV5(_))
            || !matches!(
                source_identity,
                StateIdentity::RecordsV5(_) | StateIdentity::RecordsV6(_)
            )
            || migration != self.native_root.is_none()
        {
            return Err(rejected());
        }
        let owner_bytes = plan
            .root
            .owners
            .iter()
            .try_fold(0u64, |sum, owner| sum.checked_add(owner.owner.total_bytes))
            .ok_or_else(|| Response::error(507, "native opaque owner capacity exhausted"))?;
        if owner_bytes > self.opaque_owner_limit() as u64 {
            return Err(Response::error(
                507,
                "native opaque owner capacity exhausted",
            ));
        }
        let source_auth = self.state.as_ref().ok_or_else(rejected)?.auth.clone();
        original_actor(&source_auth)?;
        // Authenticate staged owners and the actual incremental native views
        // before they are offered to the real consensus writer.
        let installed_candidate = self.install_prepared_native_candidate(&plan, original_actor)?;
        self.require_native_root_candidate(&installed_candidate)?;
        let candidate_identity = plan.root.identity().map_err(|_| rejected())?;
        let expected_auth =
            owner_store::serialize_owner(&installed_candidate.auth).map_err(|_| rejected())?;
        let seal = self.seal.clone().ok_or_else(rejected)?;
        let data_dir = self.data_dir.clone();
        let actual_key = self.barrier_key.as_ref().ok_or_else(rejected)?;
        if **actual_key == [0; 32] || seal.is_wrapper() {
            return Err(rejected());
        }
        let source_root = self
            .durable
            .as_ref()
            .ok_or_else(rejected)?
            .get("system", "state")
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        let source_generation = plan.source_generation;
        let source_epoch = self.durable.as_ref().ok_or_else(rejected)?.replay_epoch();
        if source_epoch != plan.root.replay_epoch
            || source_generation == 0
            || self.durable.as_ref().ok_or_else(rejected)?.generation() != source_generation
            || plan.conditions.first().is_none_or(|condition| {
                condition.resource != "state"
                    || condition
                        .expected
                        .as_ref()
                        .is_none_or(|bytes| bytes.expose() != source_root.expose())
            })
        {
            return Err(rejected());
        }
        let denial = RefCell::new(None);
        let publication = {
            // Both callbacks borrow the same actual local owner, sequentially.
            // During preparation NativeSource itself checks its held descriptor
            // and original source session on each payload; the outer local gate
            // runs before and after that borrow, and immediately before root CAS.
            let durable = RefCell::new(self.durable.as_mut().ok_or_else(rejected)?);
            let actor = RefCell::new(&mut *original_actor);
            let actor_only = || -> CodecResult<()> {
                deadline.check().map_err(|_| NativeV6CodecError::Gate)?;
                let result =
                    actor
                        .try_borrow_mut()
                        .map_err(|_| NativeV6CodecError::Gate)?(&source_auth);
                if let Err(error) = result {
                    *denial.borrow_mut() = Some(error);
                    return Err(NativeV6CodecError::Gate);
                }
                deadline.check().map_err(|_| NativeV6CodecError::Gate)
            };
            let mut local_gate = || -> CodecResult<()> {
                actor_only()?;
                if load_seal_metadata(&data_dir)
                    .map_err(|_| NativeV6CodecError::Gate)?
                    .as_ref()
                    != Some(&seal)
                {
                    return Err(NativeV6CodecError::Gate);
                }
                let mut local = durable
                    .try_borrow_mut()
                    .map_err(|_| NativeV6CodecError::Gate)?;
                local
                    .verify_live_ownership()
                    .map_err(|_| NativeV6CodecError::Gate)?;
                if local.recovery_required()
                    || local.generation() != source_generation
                    || local.replay_epoch() != source_epoch
                    || local
                        .get("system", "state")
                        .map_err(|_| NativeV6CodecError::Gate)?
                        .as_ref()
                        .is_none_or(|bytes| bytes.expose() != source_root.expose())
                {
                    return Err(NativeV6CodecError::Gate);
                }
                for condition in &plan.conditions {
                    let current = local
                        .get("system", &condition.resource)
                        .map_err(|_| NativeV6CodecError::Gate)?;
                    if current.as_ref().map(Secret::expose)
                        != condition.expected.as_ref().map(Secret::expose)
                    {
                        return Err(NativeV6CodecError::Gate);
                    }
                }
                actor_only()
            };
            local_gate().map_err(|_| rejected())?;
            let process = ha.lock_for_request().map_err(|_| rejected())?;
            process.publish_native_v6_candidate(
                source_identity,
                source_epoch,
                deadline,
                |codec, enrollment, store, previous, _outer_gate| {
                    actor_only()?;
                    if migration {
                        if previous.is_some() {
                            return Err(NativeV6CodecError::Gate);
                        }
                        return native_v6_ha_objects::prepare_native_v6_ha_objects(
                            &plan,
                            codec,
                            enrollment,
                            store,
                            None,
                            None,
                            &mut || actor_only(),
                        );
                    }
                    let previous = previous.ok_or(NativeV6CodecError::Gate)?;
                    if previous.root_digest() != source_identity.digest() {
                        return Err(NativeV6CodecError::Gate);
                    }
                    let mut local = durable
                        .try_borrow_mut()
                        .map_err(|_| NativeV6CodecError::Gate)?;
                    let source =
                        native_blob_source::NativeSource::new_checked(&mut local, deadline, || {
                            actor_only().map_err(|_| ServiceError::BarrierFailure)
                        })
                        .map_err(|_| NativeV6CodecError::Gate)?;
                    native_v6_ha_objects::prepare_native_v6_ha_objects(
                        &plan,
                        codec,
                        enrollment,
                        store,
                        Some(&source),
                        Some(previous),
                        &mut || actor_only(),
                    )
                },
                &mut local_gate,
            )
        };
        let committed = match publication {
            Ok(committed) => committed,
            Err(NativeHaPublicationError::BeforeRoot { .. }) => {
                self.ha_activation = None;
                if self
                    .durable
                    .as_ref()
                    .is_some_and(|owner| owner.recovery_required())
                {
                    self.recovery_required = true;
                }
                return Err(denial.into_inner().unwrap_or_else(rejected));
            }
            Err(NativeHaPublicationError::RootOutcomeUnknown { recovery, .. }) => {
                return Err(self.fence_native_ha_root_outcome(recovery.reference_id()));
            }
        };
        let recovery_reference = format!(
            "native6-ha-{}",
            hex(&committed.published().intent().operation_digest)
        );
        let result = (|| {
            deadline.check().map_err(|_| rejected())?;
            original_actor(&source_auth)?;
            if committed.published().root_digest() != candidate_identity.digest()
                || committed.deadline().instant() != deadline.instant()
            {
                return Err(rejected());
            }
            // Drop the coordinator's HaProcess lock before the real installer
            // takes that same process and the actual local barrier owner.
            self.sync_native_v6_from_ha_checked(&ha, committed, &mut |_| {
                original_actor(&source_auth)
            })?;
            let installed = self.state.as_mut().ok_or_else(rejected)?;
            if owner_store::serialize_owner(&installed.auth)
                .map_err(|_| rejected())?
                .as_slice()
                != expected_auth.as_slice()
            {
                return Err(rejected());
            }
            installed
                .auth
                .retain_quota_runtime_owner(&plan.candidate.auth)
                .map_err(|_| rejected())?;
            let installed = installed.clone();
            if self.current_state_identity()? != candidate_identity {
                return Err(rejected());
            }
            self.require_native_root_candidate(&installed)?;
            original_actor(&source_auth)?;
            deadline.check().map_err(|_| rejected())?;
            Ok(installed)
        })();
        match result {
            Ok(installed) => Ok(installed),
            Err(_) => Err(self.fence_native_ha_root_outcome(recovery_reference)),
        }
    }

    fn fence_native_ha_root_outcome(&mut self, recovery_reference: String) -> Response {
        self.recovery_required = true;
        self.ha_activation = None;
        self.ha_read_cache = None;
        let error = ServiceError::OutcomeUnknown {
            recovery_reference: recovery_reference.clone(),
        };
        self.capture_native_failure_notice(&error);
        self.capture_ordinary_kv_outcome_unknown(&error, true);
        Response {
            status: 503,
            body: json!({"errors":["native HA root outcome requires cold reconciliation; do not blindly retry"],"recovery_reference": recovery_reference}),
            unwrapped_json: None,
            response_headers: Default::default(),
            consistency_index: None,
        }
    }
}
