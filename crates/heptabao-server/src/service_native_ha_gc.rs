//! Explicit local shared-ciphertext retirement under the original HTTP Actor,
//! terminal clock, audit chain and deadline. Fresh Raft retention plus actual
//! shared-store quiescence supplies the complete mark. All local barrier
//! objects remain intact; this route is deliberately distinct from File GC.
use super::super::*;
use crate::state_record_root::StateIdentity;
use crate::state_record_root_v6::RecordStateRootV6;
use crate::v6_native_custody::OriginalDeadline;
use heptabao_durable_service::{NativeHaSharedRetirementRequest, PublicationCondition};
use heptabao_raft_runtime::{LocalV6BlobError, NativeV6SharedRetirementSelection};
#[cfg(test)]
use std::cell::RefCell;

#[path = "service_native_ha_gc_intents.rs"]
mod intents;
#[path = "service_native_ha_gc_owner.rs"]
mod physical_owner;

#[path = "service_native_ha_gc_local_mark.rs"]
mod local_mark;
#[path = "service_native_ha_gc_local_retirement.rs"]
mod local_retirement;

pub(in crate::service) const PATH: &str = "sys/storage/native-v6/ha-gc";
pub(in crate::service) const RECONCILE_PATH: &str = "sys/storage/native-v6/ha-gc/reconcile";
pub(in crate::service) const INTENTS_PATH: &str = "sys/storage/native-v6/ha-gc/intents";
pub(in crate::service) const INTENTS_RECONCILE_PATH: &str =
    "sys/storage/native-v6/ha-gc/intents/reconcile";
pub(in crate::service) const LOCAL_PATH: &str = "sys/storage/native-v6/ha-gc/local";
pub(in crate::service) const LOCAL_RECONCILE_PATH: &str =
    "sys/storage/native-v6/ha-gc/local/reconcile";
pub(in crate::service) const LOCAL_MARK_PATH: &str = "sys/storage/native-v6/ha-gc/local-mark";
pub(in crate::service) const ROOTS_ACTIVATE_PATH: &str =
    "sys/storage/native-v6/ha-gc/roots/activate";
type Checkpoint = (StateIdentity, plugin::PublicationGeneration);

#[derive(Clone, Copy)]
enum Operation {
    Status,
    Retire,
    Reconcile([u8; 32]),
    IntentStatus,
    RetireIntents,
    ReconcileIntents([u8; 32]),
    InspectLocalMark,
    LocalStatus,
    RetireLocal,
    ReconcileLocal([u8; 32]),
    ActivateRetainedRoots,
}
impl Operation {
    fn parse(request: &RequestView<'_>) -> Result<Self, Response> {
        if !request.namespace.is_empty() || request.wrap_ttl_seconds.is_some_and(|ttl| ttl != 0) {
            return Err(Response::error(
                400,
                "native HA shared GC requires an unwrapped root-namespace request",
            ));
        }
        let body = request
            .body
            .as_object()
            .ok_or_else(|| Response::error(400, "native HA shared GC requires an object"))?;
        match (request.method, request.path) {
            ("GET", PATH) if body.is_empty() => Ok(Self::Status),
            ("POST", PATH) if body.is_empty() => Ok(Self::Retire),
            ("GET", INTENTS_PATH) if body.is_empty() => Ok(Self::IntentStatus),
            ("POST", INTENTS_PATH) if body.is_empty() => Ok(Self::RetireIntents),
            ("POST", LOCAL_MARK_PATH) if body.is_empty() => Ok(Self::InspectLocalMark),
            ("GET", LOCAL_PATH) if body.is_empty() => Ok(Self::LocalStatus),
            ("POST", LOCAL_PATH) if body.is_empty() => Ok(Self::RetireLocal),
            ("POST", ROOTS_ACTIVATE_PATH) if body.is_empty() => Ok(Self::ActivateRetainedRoots),
            ("POST", RECONCILE_PATH | INTENTS_RECONCILE_PATH | LOCAL_RECONCILE_PATH)
                if body.len() == 1 =>
            {
                let encoded = body
                    .get("expected_pending_sha256")
                    .and_then(Value::as_str)
                    .filter(|value| {
                        value.len() == 64
                            && value
                                .bytes()
                                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                    })
                    .ok_or_else(|| {
                        Response::error(
                            400,
                            "native HA shared GC reconciliation requires one exact pending SHA-256",
                        )
                    })?;
                let bytes: [u8; 32] = decode_hex(encoded)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| Response::error(400, "invalid pending SHA-256"))?;
                Ok(if request.path == LOCAL_RECONCILE_PATH {
                    Self::ReconcileLocal(bytes)
                } else if request.path == INTENTS_RECONCILE_PATH {
                    Self::ReconcileIntents(bytes)
                } else {
                    Self::Reconcile(bytes)
                })
            }
            _ => Err(Response::error(
                400,
                "invalid native HA shared GC operation or body",
            )),
        }
    }
    fn method(self) -> &'static str {
        if matches!(self, Self::Status | Self::IntentStatus | Self::LocalStatus) {
            "GET"
        } else {
            "POST"
        }
    }
    fn path(self) -> &'static str {
        match self {
            Self::Reconcile(_) => RECONCILE_PATH,
            Self::Status | Self::Retire => PATH,
            Self::IntentStatus | Self::RetireIntents => INTENTS_PATH,
            Self::ReconcileIntents(_) => INTENTS_RECONCILE_PATH,
            Self::InspectLocalMark => LOCAL_MARK_PATH,
            Self::LocalStatus | Self::RetireLocal => LOCAL_PATH,
            Self::ReconcileLocal(_) => LOCAL_RECONCILE_PATH,
            Self::ActivateRetainedRoots => ROOTS_ACTIVATE_PATH,
        }
    }
    fn capability(self) -> &'static str {
        if matches!(self, Self::Status | Self::IntentStatus | Self::LocalStatus) {
            "read"
        } else {
            "update"
        }
    }
}

fn public_status(
    status: Option<heptabao_durable_service::NativeHaSharedRetirementStatus>,
) -> Value {
    status.map_or(Value::Null, |status| json!({
        "phase":status.phase, "pending":status.pending,
        "record_sha256":hex(&status.record_sha256),
        "original_pending_sha256":hex(&status.original_pending_sha256),
        "historical_request_outcome_reclassified":status.historical_request_outcome_reclassified,
        "selected_files":status.selected_files,
        "pending_generation":status.pending_generation,
        "replay_epoch":status.replay_epoch, "reconciliation_attempt":status.reconciliation_attempt
    }))
}

fn rejected() -> Response {
    Response::error(
        503,
        "native HA shared retirement or original custody unavailable",
    )
}
fn reply_digest(response: &Response, deadline: OriginalDeadline) -> Result<[u8; 32], Response> {
    deadline.check().map_err(|_| rejected())?;
    let bytes =
        owner_store::serialize_owner(&(response.status, &response.body)).map_err(|_| rejected())?;
    let result = crypto::digest(&bytes);
    deadline.check().map_err(|_| rejected())?;
    Ok(result)
}

// Affine dispatch-to-audit authority. Physical retirement completes before
// this response is staged; only the exact original terminal-clock receipt may
// advance its post-retirement checkpoint. No current-root recapture can do so.
pub(in crate::service) struct GcDelivery {
    operation: Operation,
    request_body: Value,
    actor: Principal,
    clock: RequestClock,
    now: u64,
    deadline: OriginalDeadline,
    admitted: State,
    source_auth: Zeroizing<Vec<u8>>,
    checkpoint: Checkpoint,
    ha: Arc<Mutex<HaProcess>>,
    data_dir: PathBuf,
    seal: SealMetadata,
    activation: Zeroizing<String>,
    barrier_digest: [u8; 32],
    reply_digest: [u8; 32],
    _snapshot_quiescence: Option<Arc<crate::snapshot_file::SnapshotLease>>,
}
impl GcDelivery {
    fn authorize_actor(&self, auth: &AuthState) -> Result<(), Response> {
        self.deadline.check().map_err(|_| rejected())?;
        if !self.actor.is_root() {
            return Err(Response::error(403, "root token required"));
        }
        let time = self
            .clock
            .with_seconds_floor(self.now)
            .and_then(RequestClock::observed_at)
            .map(AuthorityTime::Precise)
            .map_err(|_| rejected())?;
        auth.authorize_request_parameters_observed(
            &self.actor,
            "",
            self.operation.method(),
            self.operation.path(),
            &self.request_body,
            time,
        )
        .map_err(|error| Response::error(error.status, &error.message))?;
        auth.authorize_sudo_request_observed(
            &self.actor,
            "",
            self.operation.path(),
            self.operation.capability(),
            time,
        )
        .map_err(|error| Response::error(error.status, &error.message))?;
        self.deadline.check().map_err(|_| rejected())
    }
    fn authorize_original(&self) -> Result<(), Response> {
        self.authorize_actor(&self.admitted.auth)?;
        if owner_store::serialize_owner(&self.admitted.auth)
            .map_err(|_| rejected())?
            .as_slice()
            != self.source_auth.as_slice()
        {
            return Err(rejected());
        }
        if load_seal_metadata(&self.data_dir)
            .map_err(|_| rejected())?
            .as_ref()
            != Some(&self.seal)
        {
            return Err(rejected());
        }
        self.deadline.check().map_err(|_| rejected())
    }
    fn check_local_instance(
        &self,
        service: &mut Service,
        checkpoint: Checkpoint,
    ) -> Result<(), Response> {
        self.authorize_original()?;
        if service.recovery_required
            || service.audit_failed
            || service
                .ha
                .as_ref()
                .is_none_or(|actual| !Arc::ptr_eq(actual, &self.ha))
            || service.native_candidate_profile.is_some()
            || service.postgres_durable.is_some()
            || service.durable_profile.is_some()
            || service.openbao_wrapper_owner.is_some()
            || service.record_root.is_some()
            || service.data_dir != self.data_dir
            || service.seal.as_ref() != Some(&self.seal)
            || service.unseal_nonce.as_str() != self.activation.as_str()
            || service
                .barrier_key
                .as_ref()
                .is_none_or(|key| crypto::digest(key.as_slice()) != self.barrier_digest)
            || !matches!(
                service.native_storage_profile,
                Some(crate::configuration::NativeStorageProfile::Raft)
            )
            || service
                .native_root
                .as_ref()
                .is_none_or(|root| root.reader_floor.native_kv2_format != 2)
            || service
                .native_kv2_large_flight
                .load(std::sync::atomic::Ordering::Acquire)
            || service.current_state_identity()? != checkpoint.0
        {
            return Err(rejected());
        }
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_live_ownership()
            .map_err(|_| rejected())?;
        self.authorize_actor(&service.state.as_ref().ok_or_else(rejected)?.auth)?;
        self.deadline.check().map_err(|_| rejected())
    }
    fn check_instance(
        &self,
        service: &mut Service,
        checkpoint: Checkpoint,
    ) -> Result<(), Response> {
        self.check_local_instance(service, checkpoint)?;
        if service.native_ha_gc_checkpoint()? != checkpoint {
            return Err(rejected());
        }
        self.authorize_original()
    }
    fn check_source(&self, service: &mut Service) -> Result<(), Response> {
        self.check_instance(service, self.checkpoint)?;
        self.check_source_auth(service)
    }
    // Only while the caller holds the actual HA process/retention writers.
    // No recursive HA lock or invented current Raft frontier is used here.
    // Its sole caller separately checks the exact local source generation
    // and all four current root/cursor conditions under the live backend.
    fn check_local_source_while_retained_ha(&self, service: &mut Service) -> Result<(), Response> {
        self.check_local_instance(service, self.checkpoint)?;
        self.check_source_auth(service)
    }
    fn check_source_auth(&self, service: &Service) -> Result<(), Response> {
        if owner_store::serialize_owner(&service.state.as_ref().ok_or_else(rejected)?.auth)
            .map_err(|_| rejected())?
            .as_slice()
            != self.source_auth.as_slice()
        {
            return Err(rejected());
        }
        Ok(())
    }
}

impl Service {
    fn native_ha_gc_checkpoint(&self) -> Result<Checkpoint, Response> {
        let identity = self.current_state_identity()?;
        if !matches!(identity, StateIdentity::RecordsV6(_)) || self.ha.is_none() {
            return Err(rejected());
        }
        Ok((identity, self.external_effect_generation()?))
    }

    pub(in crate::service) fn stage_native_ha_gc(
        &mut self,
        admitted: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let prepared = (|| -> Result<(GcDelivery, Response), Response> {
            let operation = Operation::parse(request)?;
            if self.ha.is_none()
                || !matches!(
                    self.native_storage_profile,
                    Some(crate::configuration::NativeStorageProfile::Raft)
                )
            {
                return Err(Response::error(
                    501,
                    "native HA shared GC requires its configured Raft owner",
                ));
            }
            let actor = principal
                .filter(Principal::is_root)
                .ok_or_else(|| Response::error(403, "root token required"))?;
            let clock = request.token_clock.ok_or_else(rejected)?;
            if actor.original_request_clock().is_none() {
                return Err(rejected());
            }
            let deadline = OriginalDeadline::capture().map_err(|_| rejected())?;
            self.require_native_root_candidate(&admitted)?;
            if self
                .native_root
                .as_ref()
                .is_none_or(|root| root.reader_floor.native_kv2_format != 2)
            {
                return Err(Response::error(
                    409,
                    "native HA shared GC requires activated paged storage",
                ));
            }
            if self
                .native_kv2_large_flight
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return Err(Response::error(409, "native transfer is active"));
            }
            // A snapshot plan may be outside the Service mutex before it opens
            // its durable source. Hold the actual spool lease as well as the
            // lower physical/session uniqueness gates; no spool is created.
            let snapshot_quiescence = if matches!(
                operation,
                Operation::Status | Operation::IntentStatus | Operation::LocalStatus
            ) {
                None
            } else {
                self.snapshot_spool
                    .as_ref()
                    .map(|spool| spool.lease())
                    .transpose()
                    .map_err(|_| {
                        Response::error(409, "snapshot transfer is active or unavailable")
                    })?
            };
            let source_auth =
                owner_store::serialize_owner(&admitted.auth).map_err(|_| rejected())?;
            let mut plan = GcDelivery {
                operation,
                request_body: request.body.clone(),
                actor,
                clock,
                now: request.now,
                deadline,
                admitted,
                source_auth,
                checkpoint: self.native_ha_gc_checkpoint()?,
                ha: Arc::clone(self.ha.as_ref().ok_or_else(rejected)?),
                data_dir: self.data_dir.clone(),
                seal: self.seal.clone().ok_or_else(rejected)?,
                activation: Zeroizing::new(self.unseal_nonce.clone()),
                barrier_digest: crypto::digest(
                    self.barrier_key.as_ref().ok_or_else(rejected)?.as_slice(),
                ),
                reply_digest: [0; 32],
                _snapshot_quiescence: snapshot_quiescence,
            };
            plan.check_source(self)?;
            let proof = self
                .capture_native_request_proof(&mut || plan.authorize_original())?
                .ok_or_else(rejected)?;
            if proof.identity() != plan.checkpoint.0 {
                return Err(rejected());
            }
            proof.check_with(self, Self::check_native_installed)?;
            plan.check_source(self)?;
            if matches!(operation, Operation::LocalStatus) {
                let status = self
                    .durable
                    .as_mut()
                    .ok_or_else(rejected)?
                    .immutable_retirement_status()
                    .map_err(|_| rejected())?;
                plan.check_source(self)?;
                let response = Response::ok(json!({"data":{
                    "schema":"heptabao-native-ha-local-retirement-status-v1",
                    "scope":"local-barrier-ciphertext",
                    "retirement":local_retirement::public_status(status),
                    "local_barriers_gc_qualified":false,
                    "historical_request_outcome_reclassified":false
                }}));
                plan.reply_digest = reply_digest(&response, deadline)?;
                return Ok((plan, response));
            }
            if matches!(operation, Operation::Status | Operation::IntentStatus) {
                let durable = self.durable.as_mut().ok_or_else(rejected)?;
                let status = if matches!(operation, Operation::IntentStatus) {
                    intents::public_status(
                        durable
                            .native_ha_intent_retirement_status()
                            .map_err(|_| rejected())?,
                    )
                } else {
                    public_status(
                        durable
                            .native_ha_shared_retirement_status()
                            .map_err(|_| rejected())?,
                    )
                };
                plan.check_source(self)?;
                let response = Response::ok(json!({"data":{
                    "schema":if matches!(operation, Operation::IntentStatus) { "heptabao-native-ha-intent-retirement-status-v1" } else { "heptabao-native-ha-shared-retirement-status-v1" }, "retirement":status,
                    "scope":"local-shared-raft-ciphertext", "local_barrier_objects_retained":true, "local_barriers_gc_qualified":false,
                    "historical_request_outcome_reclassified":false
                }}));
                plan.reply_digest = reply_digest(&response, deadline)?;
                return Ok((plan, response));
            }
            let previous = if matches!(operation, Operation::Retire | Operation::Reconcile(_)) {
                self.native_ha_gc_previous_selection(operation)?
            } else {
                None
            };
            plan.check_source(self)?;
            let root = self.native_root.as_ref().ok_or_else(rejected)?.clone();
            let (conditions, root_bytes) = self.native_ha_gc_source_conditions(&plan, &root)?;
            proof.check_warm(self)?;
            plan.check_source(self)?;
            let original_checkpoint = plan.checkpoint;
            let source_generation = proof.generation();
            // The typed proof has done its job. It must not retain a source
            // session or shared-store operation while the original runtime
            // acquires a NEW complete durable Raft retention guard and actual
            // shared quiescence. A serialized root or previous capsule cannot
            // replace that fresh physical authority.
            drop(proof);
            if matches!(plan.operation, Operation::InspectLocalMark) {
                let response = self.execute_native_ha_local_mark(
                    &plan,
                    source_generation,
                    &conditions,
                    root_bytes.expose(),
                )?;
                plan.reply_digest = reply_digest(&response, deadline)?;
                return Ok((plan, response));
            }
            if matches!(
                plan.operation,
                Operation::RetireLocal | Operation::ReconcileLocal(_)
            ) {
                let response = self.execute_native_ha_local_retirement(
                    &mut plan,
                    source_generation,
                    conditions,
                    root_bytes,
                )?;
                plan.reply_digest = reply_digest(&response, deadline)?;
                return Ok((plan, response));
            }
            if matches!(
                plan.operation,
                Operation::RetireIntents
                    | Operation::ReconcileIntents(_)
                    | Operation::ActivateRetainedRoots
            ) {
                let response = self.execute_native_ha_intent_gc(
                    &mut plan,
                    source_generation,
                    conditions,
                    root_bytes,
                )?;
                plan.reply_digest = reply_digest(&response, deadline)?;
                return Ok((plan, response));
            }
            let operation = format!(
                "native6-ha-gc-{}",
                hex(&crypto::random::<16>().map_err(|_| rejected())?)
            );
            let ha = Arc::clone(&plan.ha);
            let process = ha.lock_for_request().map_err(|_| rejected())?;
            let durable = self.durable.as_mut().ok_or_else(rejected)?;
            let session = native_blob_source::session(durable, root_bytes.expose())
                .map_err(|_| rejected())?;
            if session.generation() != source_generation {
                return Err(rejected());
            }
            let mut before = || {
                plan.authorize_original()
                    .map_err(|_| LocalV6BlobError::CorruptOrChanged)
            };
            let expected_pending_sha256 = match plan.operation {
                Operation::Retire => None,
                Operation::Reconcile(expected) => Some(expected),
                Operation::Status
                | Operation::IntentStatus
                | Operation::RetireIntents
                | Operation::ReconcileIntents(_)
                | Operation::LocalStatus
                | Operation::RetireLocal
                | Operation::ReconcileLocal(_)
                | Operation::InspectLocalMark
                | Operation::ActivateRetainedRoots => return Err(rejected()),
            };
            // There is deliberately no fallible post-callback wrapper in the
            // runtime. A precise pending/unknown result must reach this owner
            // without being replaced by a later observation or retried action.
            let result = process
                .with_native_v6_shared_retirement(
                    deadline,
                    original_checkpoint.0,
                    previous.as_ref(),
                    &mut before,
                    |physical, same_original| {
                        let selected_files = physical.selection().selected_files();
                        let request = NativeHaSharedRetirementRequest {
                            session,
                            principal: "native-v6-ha-shared-gc".into(),
                            operation_id: operation,
                            authorization_digest: original_checkpoint.0.digest(),
                            conditions,
                            expected_pending_sha256,
                            physical: physical_owner::Physical::new(physical),
                        };
                        durable
                            .retire_native_ha_shared(request, &mut || {
                                same_original().map_err(|_| ServiceError::BarrierFailure)
                            })
                            .map(|outcome| (selected_files, outcome))
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
            let (selected_files, outcome) = result.map_err(|_| {
                if unresolved {
                    Response::error(503, "native HA shared retirement outcome unknown; reopen the same owner and reconcile its exact pending digest; do not replay")
                } else {
                    rejected()
                }
            })?;
            // The original root is unchanged. Only this exact typed metadata
            // result can advance the local generation, by zero or two. Fresh
            // reconciliation also records its own Pending + Complete pair.
            let finish = (|| -> Result<Response, Response> {
                let delta = if selected_files == 0 { 0 } else { 2 };
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
                    .native_ha_shared_retirement_status()
                    .map_err(|_| rejected())?;
                plan.check_source(self)?;
                Ok(Response::ok(json!({"data":{
                    "schema":if matches!(plan.operation, Operation::Reconcile(_)) { "heptabao-native-ha-shared-reconciliation-v1" } else { "heptabao-native-ha-shared-retirement-v1" },
                    "scope":"local-shared-raft-ciphertext", "local_barrier_objects_retained":true, "local_barriers_gc_qualified":false,
                    "generation":outcome.generation,
                    "selected_files":selected_files,
                    "removed_blobs":outcome.physical.removed_blobs,
                    "removed_manifests":outcome.physical.removed_manifests,
                    "removed_temporary_files":outcome.physical.removed_temporary_files,
                    "removed_ciphertext_bytes":outcome.physical.removed_ciphertext_bytes,
                    "removed_other_bytes":outcome.physical.removed_other_bytes,
                    "confirmed_absent_files":outcome.physical.confirmed_absent_files,
                    "currently_retained_files":outcome.physical.currently_retained_files,
                    "retirement":public_status(status), "historical_request_outcome_reclassified":false
                }})))
            })();
            if finish.is_err() {
                self.recovery_required = true;
            }
            let response = finish?;
            plan.reply_digest = reply_digest(&response, deadline)?;
            Ok((plan, response))
        })();
        match prepared {
            Ok((plan, response)) => {
                self.pending_native_ha_gc = Some(plan);
                response
            }
            Err(response) => response,
        }
    }

    fn native_ha_gc_previous_selection(
        &mut self,
        operation: Operation,
    ) -> Result<Option<NativeV6SharedRetirementSelection>, Response> {
        let durable = self.durable.as_mut().ok_or_else(rejected)?;
        let status = durable
            .native_ha_shared_retirement_status()
            .map_err(|_| rejected())?;
        match operation {
            Operation::Retire => {
                if status.is_some_and(|status| status.pending) {
                    return Err(Response::error(
                        409,
                        "explicit pending retirement reconciliation required",
                    ));
                }
                Ok(None)
            }
            Operation::Reconcile(expected) => {
                if status.is_none_or(|status| !status.pending || status.record_sha256 != expected) {
                    return Err(Response::error(
                        409,
                        "exact pending retirement record required",
                    ));
                }
                let capsule = durable
                    .native_ha_shared_pending_selection(expected)
                    .map_err(|_| rejected())?;
                // Authenticated old DATA selects names only. The runtime must
                // reacquire new retention, quiescence and original FDs; this
                // decode grants no physical deletion or historical success.
                NativeV6SharedRetirementSelection::decode_for_reconciliation(capsule.expose())
                    .map(Some)
                    .map_err(|_| rejected())
            }
            Operation::Status
            | Operation::IntentStatus
            | Operation::RetireIntents
            | Operation::ReconcileIntents(_)
            | Operation::LocalStatus
            | Operation::RetireLocal
            | Operation::ReconcileLocal(_)
            | Operation::InspectLocalMark
            | Operation::ActivateRetainedRoots => Err(rejected()),
        }
    }

    fn native_ha_gc_source_conditions(
        &mut self,
        plan: &GcDelivery,
        root: &RecordStateRootV6,
    ) -> Result<(Vec<PublicationCondition>, Secret), Response> {
        plan.check_source(self)?;
        let durable = self.durable.as_mut().ok_or_else(rejected)?;
        let root_bytes = durable
            .get("system", "state")
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        if root.encode().map_err(|_| rejected())?.as_slice() != root_bytes.expose() {
            return Err(rejected());
        }
        let mut conditions = Vec::new();
        for resource in [
            "state",
            native_v6_reader::ACTIVE_CURSOR_RESOURCE,
            native_v6_reader::ACTIVE_SOURCE_ROOT_RESOURCE,
            native_v6_ha_install::HA_CURSOR_RESOURCE,
        ] {
            plan.authorize_original()?;
            conditions.push(PublicationCondition {
                resource: resource.into(),
                expected: Some(
                    durable
                        .get("system", resource)
                        .map_err(|_| rejected())?
                        .ok_or_else(rejected)?,
                ),
            });
        }
        plan.authorize_original()?;
        Ok((conditions, root_bytes))
    }

    pub(in crate::service) fn complete_native_ha_gc(
        &mut self,
        plan: GcDelivery,
        mut response: Response,
        fingerprint: &str,
        clock: (u64, Option<RequestClock>),
    ) -> Response {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline.instant());
        if response.status != 200
            || plan.check_source(self).is_err()
            || reply_digest(&response, plan.deadline).ok() != Some(plan.reply_digest)
        {
            erase_json(&mut response.body);
            response = rejected();
        }
        let selected = response.status == 200;
        let (mut response, receipt) = self.audit_completed_response_with_clock_receipt(
            fingerprint,
            clock,
            response,
            || {},
            selected,
        );
        #[cfg(test)]
        if selected && response.status == 200 {
            run_after_audit_test_hook(self);
        }
        let delivered = (|| -> Result<(), Response> {
            if !selected
                || response.status != 200
                || reply_digest(&response, plan.deadline)? != plan.reply_digest
            {
                return Err(rejected());
            }
            let mut checkpoint = Some(plan.checkpoint);
            if let Some(receipt) = receipt {
                let before = checkpoint;
                receipt.advance(&mut checkpoint);
                if checkpoint == before {
                    return Err(rejected());
                }
            }
            let checkpoint = checkpoint.ok_or_else(rejected)?;
            plan.check_instance(self, checkpoint)?;
            let actual_auth = self.state.as_ref().ok_or_else(rejected)?.auth.clone();
            let proof = self
                .capture_native_request_proof(&mut || {
                    plan.authorize_original()?;
                    plan.authorize_actor(&actual_auth)
                })?
                .ok_or_else(rejected)?;
            if proof.identity() != checkpoint.0 {
                return Err(rejected());
            }
            proof.check_with(self, Self::check_native_installed)?;
            plan.check_instance(self, checkpoint)
        })();
        if delivered.is_err() {
            erase_json(&mut response.body);
            response.consistency_index = None;
            if selected
                && self
                    .audit_event(
                        "native-ha-shared-gc-delivery-veto",
                        fingerprint,
                        clock.0,
                        Some(503),
                    )
                    .is_err()
            {
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
type AfterAuditHook = Box<dyn FnOnce(&mut Service)>;
#[cfg(test)]
thread_local! {
    static AFTER_AUDIT_HOOK: RefCell<Option<AfterAuditHook>> = const { RefCell::new(None) };
}
#[cfg(test)]
fn run_after_audit_test_hook(service: &mut Service) {
    let hook = AFTER_AUDIT_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(service);
    }
}

#[cfg(test)]
pub(in crate::service) fn fail_after_physical_once() {
    physical_owner::fail_after_physical_once();
}

#[cfg(test)]
pub(in crate::service) fn fail_after_intent_commit_once() {
    intents::fail_after_commit_once();
}

#[cfg(test)]
pub(in crate::service) fn intent_submission_owners_consumed() -> usize {
    intents::submission_owners_consumed()
}

#[cfg(test)]
pub(in crate::service) fn invalidate_activation_after_audit_once() {
    AFTER_AUDIT_HOOK.with(|slot| {
        let previous = slot
            .borrow_mut()
            .replace(Box::new(|service| service.unseal_nonce.push('!')));
        assert!(previous.is_none());
    });
}
