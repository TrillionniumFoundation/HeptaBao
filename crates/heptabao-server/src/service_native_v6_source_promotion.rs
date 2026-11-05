//! Affine V4-owner to V5-source promotion for formal standalone native file
//! activation. This publishes no business mount, token or response payload.
//! A real V5 checkpoint must be authenticated from durable bytes before the
//! unchanged V6 migration/cursor protocol may consume it.
use super::super::backup_restore::{StateResource, StateResources};
use super::super::records::RecordPlan;
use super::*;
use crate::configuration::NativeStorageProfile;
use crate::state_record_root::StateIdentity;
use crate::state_records::AddressKey;

const ABSENT_NATIVE_RESOURCES: [&str; 4] = [
    ACTIVE_CURSOR_RESOURCE,
    ACTIVE_SOURCE_ROOT_RESOURCE,
    "state-native-v6/publication-cursor",
    "state-native-v6/root",
];

fn live(deadline: OriginalDeadline) -> Result<(), Response> {
    deadline.check().map_err(|_| rejected())
}

// Every actual source/root/object read retains the one original request budget.
struct CheckedResources<'a> {
    durable: &'a DurableService<AeadBarrier>,
    deadline: OriginalDeadline,
}
impl StateResources for CheckedResources<'_> {
    fn get(&self, resource: &str) -> Result<Option<StateResource<'_>>, ServiceError> {
        self.deadline
            .check()
            .map_err(|_| ServiceError::BarrierFailure)?;
        let value = self.durable.get("system", resource)?;
        self.deadline
            .check()
            .map_err(|_| ServiceError::BarrierFailure)?;
        Ok(value.map(StateResource::Owned))
    }
    fn replay_epoch(&self) -> u64 {
        self.durable.replay_epoch()
    }
}
impl CheckedResources<'_> {
    fn get_owned(&self, resource: &str) -> Result<Option<Secret>, Response> {
        live(self.deadline)?;
        let value = self
            .durable
            .get("system", resource)
            .map_err(|_| rejected())?;
        live(self.deadline)?;
        Ok(value)
    }
}

fn ownership(
    durable: &mut DurableService<AeadBarrier>,
    deadline: OriginalDeadline,
) -> Result<(), Response> {
    live(deadline)?;
    durable.verify_live_ownership().map_err(|_| rejected())?;
    live(deadline)
}

// No Clone, serde, public fields, detached State constructor or caller-selected
// source. The only constructor reopens all five actual V4 owners and binds the
// original manifest, canonical logical identity, generation and request time.
struct LegacySourcePromotion {
    source: Secret,
    source_identity: StateIdentity,
    source_generation: u64,
    source_epoch: u64,
    candidate: State,
    plan: RecordPlan,
    deadline: OriginalDeadline,
}

impl LegacySourcePromotion {
    fn prepare(service: &mut Service, deadline: OriginalDeadline) -> Result<Self, Response> {
        live(deadline)?;
        let state = service.state.as_ref().ok_or_else(rejected)?.clone();
        service.require_native_root_candidate(&state)?;
        if service.native_storage_profile != Some(NativeStorageProfile::File)
            || service.ha.is_some()
            || service.native_root.is_some()
            || service.record_root.is_some()
            || state.engines.record_root().is_some()
            || state.engines.record_address_key().is_some()
        {
            return Err(rejected());
        }
        let source_identity = service.current_state_identity()?;
        let StateIdentity::Legacy(source_digest) = source_identity else {
            return Err(rejected());
        };
        let durable = service.durable.as_mut().ok_or_else(rejected)?;
        ownership(durable, deadline)?;
        let resources = CheckedResources { durable, deadline };
        let source_generation = durable.generation();
        let source_epoch = durable.replay_epoch();
        if source_generation == 0 || state.replay_epoch != source_epoch {
            return Err(rejected());
        }
        let source = resources.get_owned("state")?.ok_or_else(rejected)?;
        // This addition admits precisely the real current V4 owner manifest.
        // Raw legacy, unknown formats, V5 and V6 retain their existing guards.
        if owner_store::decode_manifest(source.expose())
            .map_err(|_| rejected())?
            .is_none()
            || records::decode_root(source.expose())?.is_some()
        {
            return Err(rejected());
        }
        for resource in ABSENT_NATIVE_RESOURCES {
            if resources.get_owned(resource)?.is_some() {
                return Err(rejected());
            }
        }
        let (reopened, logical, rewrite) = Service::load_state_from_resources(&resources)?;
        live(deadline)?;
        let actual = owner_store::serialize_owner(&state).map_err(state_serialization_error)?;
        if rewrite
            || actual.as_slice() != logical.as_slice()
            || crypto::digest(&logical) != source_digest
            || reopened.engines.record_root().is_some()
            || reopened.engines.record_address_key().is_some()
            || reopened.replay_epoch != source_epoch
        {
            return Err(rejected());
        }
        ownership(durable, deadline)?;
        let resources = CheckedResources { durable, deadline };
        if durable.generation() != source_generation
            || resources
                .get_owned("state")?
                .is_none_or(|value| value.expose() != source.expose())
        {
            return Err(rejected());
        }
        // The canonical durable State is the candidate, preserving every Auth
        // field (including finite uses, cubbyhole and durable clocks). Only the
        // storage representation is promoted; no dummy business mutation runs.
        let mut candidate = reopened;
        candidate.engines = candidate
            .engines
            .migrate_kv1_records(AddressKey::from_bytes(
                crypto::random::<32>().map_err(|_| rejected())?,
            ))
            .map_err(Response::from_engine_error)?
            .into();
        candidate.schema = candidate.writer_schema();
        let plan = service.prepare_record_plan(&mut candidate)?;
        service.validate_loaded_capacity(&candidate, Some(&plan.root))?;
        live(deadline)?;
        if plan
            .objects
            .len()
            .checked_add(1)
            .is_none_or(|count| count > heptabao_durable_service::MAX_ATOMIC_MUTATIONS)
        {
            return Err(Response::error(
                507,
                "native source promotion exceeds one atomic publication",
            ));
        }
        Ok(Self {
            source,
            source_identity,
            source_generation,
            source_epoch,
            candidate,
            plan,
            deadline,
        })
    }

    fn publish(
        self,
        service: &mut Service,
        before_publish: &mut impl FnMut(&AuthState) -> Result<(), Response>,
    ) -> Result<(), Response> {
        live(self.deadline)?;
        service.require_native_root_candidate(service.state.as_ref().ok_or_else(rejected)?)?;
        if service.current_state_identity()? != self.source_identity
            || records::legacy_candidate_digest(service.state.as_ref().ok_or_else(rejected)?)?
                != self.source_identity.digest()
            || service.native_storage_profile != Some(NativeStorageProfile::File)
            || service.ha.is_some()
            || service.native_root.is_some()
            || service.record_root.is_some()
        {
            return Err(rejected());
        }
        let actual_auth = service.state.as_ref().ok_or_else(rejected)?.auth.clone();
        before_publish(&actual_auth)?;
        let durable = service.durable.as_mut().ok_or_else(rejected)?;
        ownership(durable, self.deadline)?;
        let resources = CheckedResources {
            durable,
            deadline: self.deadline,
        };
        if durable.generation() != self.source_generation
            || durable.replay_epoch() != self.source_epoch
            || resources
                .get_owned("state")?
                .is_none_or(|value| value.expose() != self.source.expose())
        {
            return Err(rejected());
        }
        let mut conditions = vec![heptabao_durable_service::PublicationCondition {
            resource: "state".into(),
            expected: Some(self.source),
        }];
        for resource in ABSENT_NATIVE_RESOURCES {
            if resources.get_owned(resource)?.is_some() {
                return Err(rejected());
            }
            conditions.push(heptabao_durable_service::PublicationCondition {
                resource: resource.into(),
                expected: None,
            });
        }
        let key = self.plan.root.address_key();
        let mut mutations = Vec::new();
        for object in &self.plan.objects {
            live(self.deadline)?;
            object
                .reference()
                .verify(&key, object.bytes())
                .map_err(|_| rejected())?;
            let resource = object.reference().resource();
            match resources.get_owned(&resource)? {
                Some(value) if value.expose() == object.bytes() => {}
                Some(_) => return Err(rejected()),
                None => mutations.push((
                    resource,
                    Some(Secret::new(object.bytes().to_vec()).map_err(|_| rejected())?),
                )),
            }
        }
        mutations.push((
            "state".into(),
            Some(Secret::new(self.plan.bytes.to_vec()).map_err(|_| rejected())?),
        ));
        let operation = format!(
            "native6-source-promotion-{}-root",
            hex(&crypto::random::<16>().map_err(|_| rejected())?)
        );
        let expected_generation = self.source_generation.checked_add(1).ok_or_else(rejected)?;
        let mut root_committed = false;
        let mut installed = None;
        let result = (|| -> Result<(), ServiceError> {
            let mut gate = || {
                self.deadline
                    .check()
                    .map_err(|_| ServiceError::BarrierFailure)?;
                before_publish(&actual_auth).map_err(|_| ServiceError::BarrierFailure)?;
                self.deadline
                    .check()
                    .map_err(|_| ServiceError::BarrierFailure)
            };
            gate()?;
            durable.apply_batch_conditionally_with_io_gate(
                heptabao_durable_service::BatchPublication {
                    replay_epoch: self.source_epoch,
                    principal: "heptabao-server".into(),
                    namespace: "system".into(),
                    request_id: operation,
                    authorization_digest: self.plan.identity.digest(),
                    mutations,
                },
                conditions,
                &mut gate,
            )?;
            root_committed = true;
            gate()?;
            durable.verify_live_ownership()?;
            gate()?;
            if durable.generation() != expected_generation {
                return Err(ServiceError::CorruptState);
            }
            // Use the real complete cold V5 reader, including every owner
            // chunk and KV1 object; the staged memory is never reader evidence.
            let resources = CheckedResources {
                durable,
                deadline: self.deadline,
            };
            let (state, bytes, rewrite) = Service::load_state_from_resources(&resources)
                .map_err(|_| ServiceError::CorruptState)?;
            gate()?;
            if rewrite
                || bytes.as_slice() != self.plan.bytes.as_slice()
                || state.engines.record_root().as_ref() != Some(&self.plan.root.kv1)
                || owner_store::serialize_owner(&state)
                    .map_err(|_| ServiceError::CorruptState)?
                    .as_slice()
                    != owner_store::serialize_owner(&self.candidate)
                        .map_err(|_| ServiceError::CorruptState)?
                        .as_slice()
            {
                return Err(ServiceError::CorruptState);
            }
            ownership(durable, self.deadline).map_err(|_| ServiceError::BarrierFailure)?;
            gate()?;
            if durable.generation() != expected_generation {
                return Err(ServiceError::CorruptState);
            }
            installed = Some(state);
            Ok(())
        })();
        let unknown = (root_committed && result.is_err())
            || durable.capacity_status().recovery_required
            || matches!(
                &result,
                Err(ServiceError::OutcomeUnknown { .. } | ServiceError::RecoveryRequired)
            );
        if unknown {
            service.recovery_required = true;
            service.ha_activation = None;
            crate::service::openbao_wrapper::fence(&service.openbao_wrapper_owner);
        }
        if let Err(error) = result {
            service.capture_native_failure_notice(&error);
            service.capture_ordinary_kv_outcome_unknown(&error, true);
            let mut response = match error {
                ServiceError::OutcomeUnknown { recovery_reference } => Response {
                    status: 503,
                    body: json!({"errors":["native source promotion durable outcome unknown; reopen and reconcile; do not blindly retry"],"recovery_reference":recovery_reference}),
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                },
                ServiceError::RequestCapacityExhausted | ServiceError::JournalCapacityExhausted => {
                    Response::error(507, "native source promotion capacity exhausted")
                }
                _ => rejected(),
            };
            if unknown {
                response.body["source_promotion_outcome"] = json!(if root_committed {
                    "published_requires_reopen"
                } else {
                    "unknown_requires_reopen"
                });
                response.body["recovery_required"] = json!(true);
                response.body["retry_allowed"] = json!(false);
            }
            return Err(response);
        }
        // Last successful publication cannot acquire a fresh budget or release
        // a late response. Keep old caches fenced until a genuine cold reopen.
        if live(self.deadline).is_err() || before_publish(&actual_auth).is_err() {
            return Err(service.after_native_source_promotion_failure(rejected(), true));
        }
        service.state = Some(installed.ok_or_else(rejected)?);
        service.record_root = Some(self.plan.root);
        service.state_digest = Some(self.plan.identity.digest());
        service.record_writes_since_gc = 0;
        Ok(())
    }
}

#[cfg(test)]
#[path = "service_native_v6_source_promotion_tests.rs"]
mod tests;

impl Service {
    pub(super) fn promote_configured_native_file_source(
        &mut self,
        deadline: OriginalDeadline,
        before_publish: &mut impl FnMut(&AuthState) -> Result<(), Response>,
    ) -> Result<bool, Response> {
        if self.record_root.is_some() {
            return Ok(false);
        }
        // A fixture selector, arbitrary startup capability or HA membership
        // cannot become authority for this formal standalone file transition.
        let promotion = LegacySourcePromotion::prepare(self, deadline)?;
        promotion.publish(self, before_publish)?;
        Ok(true)
    }

    pub(super) fn after_native_source_promotion_failure(
        &mut self,
        mut error: Response,
        promoted: bool,
    ) -> Response {
        if promoted {
            self.recovery_required = true;
            self.ha_activation = None;
            crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
            error.body["source_promotion_completed"] = json!(true);
            error.body["recovery_required"] = json!(true);
            error.body["retry_allowed"] = json!(false);
            error.body["recovery_action"] = json!(
                "cold reopen and reconcile the last verified V5 checkpoint before a separately authorized activation; no automatic replay"
            );
        }
        error
    }
}
