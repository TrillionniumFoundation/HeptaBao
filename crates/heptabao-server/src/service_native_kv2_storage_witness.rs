//! Read-only single-version evidence with the original Service admission.
//! No HA forwarding, plaintext response, restore, retry, or new authentication.
use super::*;
use crate::state_record_root::StateIdentity;
use crate::state_record_root_v6::ObjectDomain;
use crate::state_records::RecordError;
use crate::v6_native_custody::OriginalDeadline;

pub(super) const PATH: &str = "sys/internal/storage/kv2-version-witness";
type Checkpoint = (StateIdentity, plugin::PublicationGeneration);

fn rejected() -> Response {
    Response::error(503, "native KV2 storage witness original custody rejected")
}

// Affine response authority, moved from the real dispatch through mandatory
// audit. An authenticated root or a caller-supplied digest is not this grant.
pub(super) struct WitnessDelivery {
    actor: Principal,
    clock: RequestClock,
    now: u64,
    deadline: OriginalDeadline,
    mount: Zeroizing<String>,
    path: Zeroizing<String>,
    version: u64,
    admitted: State,
    source_auth: Zeroizing<Vec<u8>>,
    checkpoint: Checkpoint,
    data_dir: PathBuf,
    seal: SealMetadata,
    activation: Zeroizing<String>,
    barrier_digest: [u8; 32],
}

impl WitnessDelivery {
    fn authorize_actor(&self, auth: &AuthState) -> Result<(), Response> {
        self.deadline.check().map_err(|_| rejected())?;
        let time = self.clock.with_seconds_floor(self.now)
            .and_then(RequestClock::observed_at)
            .map(AuthorityTime::Precise).map_err(|_| rejected())?;
        let body = json!({"mount":self.mount.as_str(),"path":self.path.as_str(),"version":self.version});
        auth.authorize_request_parameters_observed(
            &self.actor, "", "POST", PATH, &body, time,
        ).map_err(|error| Response::error(error.status, &error.message))?;
        auth.authorize_sudo_request_observed(
            &self.actor, "", PATH, "update", time,
        ).map_err(|error| Response::error(error.status, &error.message))?;
        self.deadline.check().map_err(|_| rejected())
    }

    fn authorize_original(&self) -> Result<(), Response> {
        self.authorize_actor(&self.admitted.auth)?;
        if owner_store::serialize_owner(&self.admitted.auth).map_err(|_| rejected())?.as_slice()
            != self.source_auth.as_slice()
        { return Err(rejected()); }
        self.deadline.check().map_err(|_| rejected())
    }

    fn check_instance(&self, service: &mut Service, checkpoint: Checkpoint) -> Result<(), Response> {
        self.deadline.check().map_err(|_| rejected())?;
        self.authorize_original()?;
        if service.recovery_required || service.audit_failed || service.ha.is_some()
            || service.record_root.is_some() || service.data_dir != self.data_dir
            || service.seal.as_ref() != Some(&self.seal)
            || service.unseal_nonce.as_str() != self.activation.as_str()
            || service.barrier_key.as_ref()
                .is_none_or(|key| crypto::digest(key.as_slice()) != self.barrier_digest)
            || service.native_root.as_ref().is_none_or(|root| root.reader_floor.native_kv2_format != 2)
            || service.native_kv2_witness_checkpoint()? != checkpoint
        { return Err(rejected()); }
        service.native_candidate_profile.as_ref().ok_or_else(rejected)?
            .check_environment(service)?;
        if load_seal_metadata(&self.data_dir).map_err(|_| rejected())?.as_ref() != Some(&self.seal) {
            return Err(rejected());
        }
        service.durable.as_mut().ok_or_else(rejected)?.verify_live_ownership()
            .map_err(|_| rejected())?;
        self.authorize_actor(&service.state.as_ref().ok_or_else(rejected)?.auth)?;
        self.deadline.check().map_err(|_| rejected())
    }

    fn check_source(&self, service: &mut Service) -> Result<(), Response> {
        self.check_instance(service, self.checkpoint)?;
        if owner_store::serialize_owner(&service.state.as_ref().ok_or_else(rejected)?.auth)
            .map_err(|_| rejected())?.as_slice() != self.source_auth.as_slice()
        { return Err(rejected()); }
        self.deadline.check().map_err(|_| rejected())
    }
}

impl Service {
    fn native_kv2_witness_checkpoint(&self) -> Result<Checkpoint, Response> {
        let identity = self.current_state_identity()?;
        if !matches!(identity, StateIdentity::RecordsV6(_)) { return Err(rejected()); }
        Ok((identity, self.external_effect_generation()?))
    }

    pub(super) fn stage_native_kv2_storage_witness(
        &mut self,
        admitted: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let prepared = (|| -> Result<(WitnessDelivery, Response), Response> {
            let actor = principal.ok_or_else(|| Response::error(403, "missing client token"))?;
            if request.method != "POST" || request.path != PATH || !request.namespace.is_empty()
                || request.wrap_ttl_seconds.is_some_and(|ttl| ttl != 0)
            { return Err(Response::error(400, "storage witness requires unwrapped root-namespace POST")); }
            if self.ha.is_some() {
                return Err(Response::error(501, "storage witness requires single-node native custody"));
            }
            let deadline = OriginalDeadline::capture().map_err(|_| rejected())?;
            let clock = request.token_clock.ok_or_else(rejected)?;
            if actor.original_request_clock().is_none() { return Err(rejected()); }
            let fields = request.body.as_object().ok_or_else(|| Response::error(400,
                "storage witness requires mount, path and explicit version"))?;
            if fields.len() != 3 || !fields.contains_key("mount") || !fields.contains_key("path")
                || !fields.contains_key("version")
            { return Err(Response::error(400, "storage witness accepts only mount, path and version")); }
            let mount = fields.get("mount").and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 1024)
                .ok_or_else(|| Response::error(400, "storage witness mount is required"))?;
            let path = fields.get("path").and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 1024 && valid_path(value))
                .ok_or_else(|| Response::error(400, "storage witness path is required"))?;
            let version = fields.get("version").and_then(Value::as_u64).filter(|value| *value > 0)
                .ok_or_else(|| Response::error(400, "storage witness requires a positive explicit version"))?;
            // The ordinary parameter ACL ran in handle_inner. Sudo must pass
            // before inspecting a selected mount, graph, version, or payload.
            admitted.auth.authorize_sudo_request_observed(
                &actor, "", PATH, "update", request.token_time()?,
            ).map_err(|error| Response::error(error.status, &error.message))?;
            self.require_native_root_candidate(&admitted)?;
            if self.native_root.as_ref().is_none_or(|root| root.reader_floor.native_kv2_format != 2) {
                return Err(Response::error(501, "storage witness requires activated native paged storage"));
            }
            let source_auth = owner_store::serialize_owner(&admitted.auth).map_err(|_| rejected())?;
            let plan = WitnessDelivery {
                actor, clock, now: request.now, deadline,
                mount: Zeroizing::new(mount.to_owned()), path: Zeroizing::new(path.to_owned()), version,
                admitted, source_auth, checkpoint: self.native_kv2_witness_checkpoint()?,
                data_dir: self.data_dir.clone(), seal: self.seal.clone().ok_or_else(rejected)?,
                activation: Zeroizing::new(self.unseal_nonce.clone()),
                barrier_digest: crypto::digest(self.barrier_key.as_ref().ok_or_else(rejected)?.as_slice()),
            };
            plan.check_source(self)?;
            let proof = self.capture_native_request_proof(&mut || plan.authorize_original())?
                .ok_or_else(rejected)?;
            if proof.identity() != plan.checkpoint.0 { return Err(rejected()); }
            proof.check_with(self, Self::check_native_installed)?;
            plan.check_source(self)?;
            let observations = Arc::clone(&self.native_payload_observations);
            let durable = self.durable.as_mut().ok_or_else(rejected)?;
            let source = native_blob_source::NativeSource::new_checked(durable, deadline, || {
                plan.authorize_original().map_err(|_| ServiceError::BarrierFailure)
            }).map_err(|_| rejected())?.with_observations(observations);
            let mut witness = plan.admitted.engines.native_kv2_storage_witness(
                plan.mount.as_str(), plan.path.as_str(), plan.version,
                |scope, reference| source.read_paged_payload(&ObjectDomain::Kv2(scope.clone()), reference),
                &|| plan.authorize_original().map_err(|_| RecordError::Invalid),
            ).map_err(Response::from_engine_error)?;
            drop(source);
            proof.check_warm(self)?;
            plan.check_source(self)?;
            witness["source_root_sha256"] = json!(hex(&plan.checkpoint.0.digest()));
            witness["source_publication_generation"] = json!(proof.generation());
            Ok((plan, Response::ok(json!({"data":witness}))))
        })();
        match prepared {
            Ok((plan, response)) => {
                self.pending_native_kv2_witness = Some(plan);
                response
            }
            Err(response) => response,
        }
    }

    pub(super) fn complete_native_kv2_storage_witness(
        &mut self,
        plan: WitnessDelivery,
        mut response: Response,
        fingerprint: &str,
        clock: (u64, Option<RequestClock>),
    ) -> Response {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline.instant());
        if response.status != 200 || plan.check_source(self).is_err() {
            erase_json(&mut response.body);
            response = rejected();
        }
        let selected = response.status == 200;
        let (mut response, receipt) = self.audit_completed_response_with_clock_receipt(
            fingerprint, clock, response, || {}, selected,
        );
        #[cfg(test)]
        if selected && response.status == 200 { run_after_audit_test_hook(self); }
        let delivery = (|| -> Result<(), Response> {
            if !selected || response.status != 200 { return Err(rejected()); }
            let mut checkpoint = Some(plan.checkpoint);
            if let Some(receipt) = receipt {
                let before = checkpoint;
                receipt.advance(&mut checkpoint);
                if checkpoint == before { return Err(rejected()); }
            }
            let checkpoint = checkpoint.ok_or_else(rejected)?;
            // Only this one terminal observation receipt may update the
            // original checkpoint. A different current root is not accepted.
            plan.check_instance(self, checkpoint)?;
            let auth = self.state.as_ref().ok_or_else(rejected)?.auth.clone();
            let proof = self.capture_native_request_proof(&mut || {
                plan.authorize_original()?;
                plan.authorize_actor(&auth)
            })?.ok_or_else(rejected)?;
            if proof.identity() != checkpoint.0 { return Err(rejected()); }
            proof.check_with(self, Self::check_native_installed)?;
            plan.check_instance(self, checkpoint)
        })();
        if delivery.is_err() {
            erase_json(&mut response.body);
            response.consistency_index = None;
            if selected && self.audit_event(
                "native-kv2-witness-delivery-veto", fingerprint, clock.0, Some(503),
            ).is_err() {
                self.recovery_required = true;
                self.ha_activation = None;
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
            }
            response = rejected();
        }
        self.retire_native_external_binding(fingerprint, clock.1);
        response
    }
}

#[cfg(test)]
thread_local! {
    static AFTER_AUDIT_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce(&mut Service)>>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn run_after_audit_test_hook(service: &mut Service) {
    let hook = AFTER_AUDIT_TEST_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook { hook(service); }
}

#[cfg(test)]
#[path = "service_native_kv2_storage_witness_tests.rs"]
mod tests;
