//! Explicit bounded File-only immutable retirement under one original HTTP
//! Actor/deadline and the actual complete typed graph. HA, side roots, active
//! source sessions/pins, snapshots and restore plans are holds, not guesses.
use super::super::*;
use crate::state_record_root::StateIdentity;
use crate::state_record_root_v6::{ObjectDomain, RecordStateRootV6};
use crate::state_records::{ObjectRef, RecordError};
use crate::v6_native_custody::OriginalDeadline;
use crate::v6_read_validation::{ObjectSource, ReadContext, ReadIdentity};
use heptabao_durable_service::{ImmutableRetirementRequest, PublicationCondition};
use std::{cell::RefCell, collections::BTreeSet};

pub(in crate::service) const PATH: &str = "sys/storage/native-v6/gc";
pub(in crate::service) const RECONCILE_PATH: &str = "sys/storage/native-v6/gc/reconcile";
type Checkpoint = (StateIdentity, plugin::PublicationGeneration);

#[derive(Clone, Copy)]
enum Operation {
    Status,
    Retire,
    Reconcile([u8; 32]),
}
impl Operation {
    fn parse(request: &RequestView<'_>) -> Result<Self, Response> {
        if !request.namespace.is_empty() || request.wrap_ttl_seconds.is_some_and(|ttl| ttl != 0) {
            return Err(Response::error(
                400,
                "native File GC requires an unwrapped root-namespace request",
            ));
        }
        let body = request
            .body
            .as_object()
            .ok_or_else(|| Response::error(400, "native File GC requires an object"))?;
        match (request.method, request.path) {
            ("GET", PATH) if body.is_empty() => Ok(Self::Status),
            ("POST", PATH) if body.is_empty() => Ok(Self::Retire),
            ("POST", RECONCILE_PATH) if body.len() == 1 => {
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
                            "native File GC reconciliation requires one exact pending SHA-256",
                        )
                    })?;
                let bytes: [u8; 32] = decode_hex(encoded)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| Response::error(400, "invalid pending SHA-256"))?;
                Ok(Self::Reconcile(bytes))
            }
            _ => Err(Response::error(
                400,
                "invalid native File GC operation or body",
            )),
        }
    }
    fn method(self) -> &'static str {
        if matches!(self, Self::Status) {
            "GET"
        } else {
            "POST"
        }
    }
    fn path(self) -> &'static str {
        if matches!(self, Self::Reconcile(_)) {
            RECONCILE_PATH
        } else {
            PATH
        }
    }
    fn capability(self) -> &'static str {
        if matches!(self, Self::Status) {
            "read"
        } else {
            "update"
        }
    }
}

fn public_status(status: Option<heptabao_durable_service::ImmutableRetirementStatus>) -> Value {
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

fn rejected() -> Response {
    Response::error(
        503,
        "native File retirement or original custody unavailable",
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

/// The actual full materializer determines the closure. A registered marker,
/// directory listing, warm cache, caller-provided set or metadata-only walk
/// cannot substitute for these owner/KV/history/paged-payload reads.
struct MarkingSource<'a> {
    inner: native_blob_source::NativeSource<'a>,
    reached: RefCell<BTreeSet<String>>,
}
impl ObjectSource for MarkingSource<'_> {
    fn read(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        let bytes = self.inner.read(domain, reference)?;
        self.reached
            .try_borrow_mut()
            .map_err(|_| RecordError::Invalid)?
            .insert(v6_records::native_resource(domain, reference));
        Ok(bytes)
    }
    fn object_count(&self) -> Option<usize> {
        None
    }
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
    fn check_instance(
        &self,
        service: &mut Service,
        checkpoint: Checkpoint,
    ) -> Result<(), Response> {
        self.authorize_original()?;
        if service.recovery_required
            || service.audit_failed
            || service.ha.is_some()
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
                Some(crate::configuration::NativeStorageProfile::File)
            )
            || service
                .native_root
                .as_ref()
                .is_none_or(|root| root.reader_floor.native_kv2_format != 2)
            || service
                .native_kv2_large_flight
                .load(std::sync::atomic::Ordering::Acquire)
            || service.native_file_gc_checkpoint()? != checkpoint
        {
            return Err(rejected());
        }
        service
            .native_candidate_profile
            .as_ref()
            .ok_or_else(rejected)?
            .check_environment(service)?;
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_live_ownership()
            .map_err(|_| rejected())?;
        self.authorize_actor(&service.state.as_ref().ok_or_else(rejected)?.auth)?;
        self.deadline.check().map_err(|_| rejected())
    }
    fn check_source(&self, service: &mut Service) -> Result<(), Response> {
        self.check_instance(service, self.checkpoint)?;
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
    fn native_file_gc_checkpoint(&self) -> Result<Checkpoint, Response> {
        let identity = self.current_state_identity()?;
        if !matches!(identity, StateIdentity::RecordsV6(_)) || self.ha.is_some() {
            return Err(rejected());
        }
        Ok((identity, self.external_effect_generation()?))
    }

    pub(in crate::service) fn stage_native_file_gc(
        &mut self,
        admitted: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let prepared = (|| -> Result<(GcDelivery, Response), Response> {
            let operation = Operation::parse(request)?;
            if self.ha.is_some()
                || !matches!(
                    self.native_storage_profile,
                    Some(crate::configuration::NativeStorageProfile::File)
                )
            {
                return Err(Response::error(
                    501,
                    "native File GC requires its configured standalone File owner",
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
                    "native File GC requires activated paged storage",
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
            let snapshot_quiescence = if matches!(operation, Operation::Status) {
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
                checkpoint: self.native_file_gc_checkpoint()?,
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
            if matches!(operation, Operation::Status) {
                let status = self
                    .durable
                    .as_mut()
                    .ok_or_else(rejected)?
                    .immutable_retirement_status()
                    .map_err(|_| rejected())?;
                plan.check_source(self)?;
                let response = Response::ok(json!({"data":{
                    "schema":"heptabao-native-file-retirement-status-v2", "retirement":public_status(status),
                    "historical_request_outcome_reclassified":false
                }}));
                plan.reply_digest = reply_digest(&response, deadline)?;
                return Ok((plan, response));
            }
            if let Operation::Reconcile(expected) = operation {
                let status = self
                    .durable
                    .as_mut()
                    .ok_or_else(rejected)?
                    .immutable_retirement_status()
                    .map_err(|_| rejected())?;
                if status.is_none_or(|status| !status.pending || status.record_sha256 != expected) {
                    return Err(Response::error(
                        409,
                        "exact pending retirement record required",
                    ));
                }
                plan.check_source(self)?;
            }
            let root = self.native_root.as_ref().ok_or_else(rejected)?.clone();
            let (conditions, retained, root_bytes) =
                self.mark_native_file_gc_closure(&plan, &root)?;
            proof.check_warm(self)?;
            plan.check_source(self)?;
            let original_checkpoint = plan.checkpoint;
            let operation = format!(
                "native6-gc-{}",
                hex(&crypto::random::<16>().map_err(|_| rejected())?)
            );
            let durable = self.durable.as_mut().ok_or_else(rejected)?;
            let session = native_blob_source::session(durable, root_bytes.expose())
                .map_err(|_| rejected())?;
            if session.generation() != proof.generation() {
                return Err(rejected());
            }
            let request = ImmutableRetirementRequest {
                session,
                principal: "native-v6-file-gc".into(),
                operation_id: operation,
                authorization_digest: plan.checkpoint.0.digest(),
                conditions,
                retained_resources: retained,
            };
            let mut before = || {
                plan.authorize_original()
                    .map_err(|_| ServiceError::BarrierFailure)
            };
            let result = match plan.operation {
                Operation::Retire => durable.retire_immutable_objects(request, &mut before),
                Operation::Reconcile(expected) => {
                    durable.reconcile_pending_immutable_retirement(request, expected, &mut before)
                }
                Operation::Status => return Err(rejected()),
            };
            if durable.recovery_required() {
                self.recovery_required = true;
            }
            let outcome = result.map_err(|_| rejected())?;
            // The original root is unchanged. Only this exact typed metadata
            // result can advance the local generation, by 0, 1 or 2.
            let finish = (|| -> Result<Response, Response> {
                let delta = if outcome.removed_objects > 0 {
                    2
                } else if outcome.confirmed_absent_objects > 0 {
                    1
                } else {
                    0
                };
                if proof.generation().checked_add(delta) != Some(outcome.generation) {
                    return Err(rejected());
                }
                let checkpoint = self.native_file_gc_checkpoint()?;
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
                    .immutable_retirement_status()
                    .map_err(|_| rejected())?;
                plan.check_source(self)?;
                Ok(Response::ok(json!({"data":{
                    "schema":if matches!(plan.operation, Operation::Reconcile(_)) { "heptabao-native-file-reconciliation-v2" } else { "heptabao-native-file-retirement-v1" },
                    "generation":outcome.generation,
                    "removed_objects":outcome.removed_objects, "removed_ciphertext_bytes":outcome.removed_ciphertext_bytes,
                    "confirmed_absent_objects":outcome.confirmed_absent_objects,
                    "registered_objects_before":outcome.registered_objects_before, "retained_objects":outcome.retained_objects,
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
                self.pending_native_file_gc = Some(plan);
                response
            }
            Err(response) => response,
        }
    }

    fn mark_native_file_gc_closure(
        &mut self,
        plan: &GcDelivery,
        root: &RecordStateRootV6,
    ) -> Result<(Vec<PublicationCondition>, BTreeSet<String>, Secret), Response> {
        plan.check_source(self)?;
        let context = ReadContext {
            expected_identity: ReadIdentity::RecordsV6(
                root.identity().map_err(|_| rejected())?.digest(),
            ),
            cluster_id: &root.cluster_id,
            replay_epoch: root.replay_epoch,
            minimum_state_schema: root.state_schema,
            maximum_state_schema: root.state_schema,
            reader_format: crate::state_record_root_v6::READER_FORMAT,
        };
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
        let source = MarkingSource {
            inner: native_blob_source::NativeSource::new_checked(durable, plan.deadline, || {
                plan.authorize_original()
                    .map_err(|_| ServiceError::BarrierFailure)
            })
            .map_err(|_| rejected())?,
            reached: RefCell::new(BTreeSet::new()),
        };
        let (metadata, native) =
            v6_records::materialize_for_service(root, context, &source).map_err(|_| rejected())?;
        Self::check_native_installed(&plan.admitted, &metadata, &native, root, plan.deadline)?;
        let MarkingSource { inner, reached } = source;
        drop(inner); // release this mark's original Weak/session/profile first
        let reached = reached.into_inner();
        if reached.is_empty() {
            return Err(rejected());
        }
        plan.authorize_original()?;
        Ok((conditions, reached, root_bytes))
    }

    pub(in crate::service) fn complete_native_file_gc(
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
                        "native-file-gc-delivery-veto",
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
#[path = "service_native_file_gc_tests.rs"]
mod tests;
