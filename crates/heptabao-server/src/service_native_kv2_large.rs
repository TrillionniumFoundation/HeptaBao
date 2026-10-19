//! One admitted native-only upload and one existing durable graph publication.
//! The affine plan is created before body I/O and never contains a legacy KV2
//! owner with payloads. Cancellation before finalization publishes nothing.
use super::*;
use crate::engines::kv2_native_large::{NativeLargeBundle, PATH, MAX_BUNDLE_BYTES};
use crate::engines::kv2_native_records::NativeKv2GraphImport;
use crate::state_record_root::StateIdentity;
use crate::state_records::{AddressKey, RecordError};
use crate::v6_native_custody::OriginalDeadline;
use std::time::Instant;
use std::sync::atomic::{AtomicBool, Ordering};

fn rejected() -> Response {
    Response::error(503, "native-large KV2 original custody rejected")
}

type DeliveryCheckpoint = (StateIdentity, plugin::PublicationGeneration);

fn committed_delivery_rejected() -> Response {
    Response {
        status: 503,
        body: json!({"errors":["native-large KV2 import committed but delivery custody rejected; reopen authoritative storage"],
            "recovery_required":true,"retry_allowed":false}),
        unwrapped_json: None, response_headers: Default::default(), consistency_index: None,
    }
}

pub(super) struct TransferPlan {
    actor: Principal,
    clock: RequestClock,
    now: u64,
    mount: Zeroizing<String>,
    activation: Zeroizing<String>,
    base: StateIdentity,
    admitted: State,
    parent: Arc<AddressKey>,
    source_auth: Zeroizing<Vec<u8>>,
    deadline: OriginalDeadline,
    used: bool,
    lease: Option<ImportLease>,
    native_request_binding: Option<native_v6_writer::NativeRequestBinding>,
}

// One independently bounded upload per live Service instance. The lease is
// neither serializable nor cloneable; cancellation frees only its own slot.
struct ImportLease(Arc<AtomicBool>);
impl ImportLease {
    fn acquire(slot: &Arc<AtomicBool>) -> Result<Self, Response> {
        slot.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Response::error(429, "native-large KV2 upload is already admitted"))?;
        Ok(Self(Arc::clone(slot)))
    }
    fn matches(&self, slot: &Arc<AtomicBool>) -> bool {
        Arc::ptr_eq(&self.0, slot) && self.0.load(Ordering::Acquire)
    }
}
impl Drop for ImportLease {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); }
}
impl TransferPlan {
    pub(super) fn original_deadline(&self) -> Instant { self.deadline.instant() }

    fn authorize_actor(&self, auth: &AuthState) -> Result<(), Response> {
        self.deadline.check().map_err(|_| rejected())?;
        let time = self.clock.with_seconds_floor(self.now)
            .and_then(RequestClock::observed_at)
            .map(AuthorityTime::Precise).map_err(|_| rejected())?;
        let body = json!({"mount":self.mount.as_str()});
        auth.authorize_request_parameters_observed(
            &self.actor, "", "POST", PATH, &body, time,
        ).map_err(|error| Response::error(error.status, &error.message))?;
        auth.authorize_sudo_request_observed(
            &self.actor, "", PATH, "update", time,
        ).map_err(|error| Response::error(error.status, &error.message))?;
        self.deadline.check().map_err(|_| rejected())
    }

    fn authorize(&self, auth: &AuthState) -> Result<(), Response> {
        self.authorize_actor(auth)?;
        if owner_store::serialize_owner(auth).map_err(|_| rejected())?.as_slice()
            != self.source_auth.as_slice()
        {
            return Err(Response::error(409, "native-large KV2 authorization owner changed"));
        }
        self.deadline.check().map_err(|_| rejected())
    }
}

impl Service {
    pub(crate) fn begin_native_kv2_large_before(
        &mut self,
        mut request: ServiceRequest<'_>,
        deadline: Instant,
    ) -> RequestExecution {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        if OriginalDeadline::capture().is_err() || request.path != PATH || request.method != "POST" {
            erase_json(&mut request.body);
            return RequestExecution::Complete(rejected());
        }
        // This profile has no HA forwarding contract. Refuse before normal
        // forwarding can turn the admitted query into another request owner.
        if self.ha.is_some() {
            erase_json(&mut request.body);
            return RequestExecution::Complete(Response::error(501,
                "native-large KV2 requires single-node custody"));
        }
        let previous = self.native_kv2_large_transport;
        self.native_kv2_large_transport = true;
        let execution = self.begin_request_before(request, deadline, false);
        self.native_kv2_large_transport = previous;
        execution
    }

    pub(super) fn stage_native_kv2_large(
        &mut self,
        admitted: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let prepared = (|| -> Result<TransferPlan, Response> {
            let actor = principal.ok_or_else(|| Response::error(403, "missing client token"))?;
            if !self.native_kv2_large_transport {
                return Err(Response::error(501, "native-large KV2 requires admitted typed HTTP transport"));
            }
            if request.method != "POST" || request.path != PATH || !request.namespace.is_empty()
                || self.ha.is_some() || request.wrap_ttl_seconds.is_some_and(|ttl| ttl != 0)
            {
                return Err(Response::error(400, "native-large KV2 requires unwrapped root-namespace POST"));
            }
            let deadline = OriginalDeadline::capture().map_err(|_| rejected())?;
            let clock = request.token_clock.ok_or_else(rejected)?;
            if actor.original_request_clock().is_none() { return Err(rejected()); }
            let fields = request.body.as_object().ok_or_else(rejected)?;
            if fields.len() != 1 || !fields.contains_key("mount") {
                return Err(Response::error(400, "native-large KV2 requires only the mount query"));
            }
            let mount = fields.get("mount").and_then(Value::as_str)
                .filter(|mount| !mount.is_empty() && mount.len() <= 1024)
                .ok_or_else(|| Response::error(400, "native-large KV2 mount is required"))?;
            // Refuse an update-only actor before disclosing whether a named
            // mount is pristine/native or touching its durable custody. This is
            // the same original clock/actor later retained by the affine plan.
            let time = clock.with_seconds_floor(request.now)
                .and_then(RequestClock::observed_at).map(AuthorityTime::Precise)
                .map_err(|_| rejected())?;
            admitted.auth.authorize_sudo_request_observed(
                &actor, "", PATH, "update", time,
            ).map_err(|error| Response::error(error.status, &error.message))?;
            deadline.check().map_err(|_| rejected())?;
            self.require_native_root_candidate(&admitted)?;
            let root = self.native_root.as_ref().ok_or_else(|| Response::error(501,
                "native-large KV2 requires activated paged V6 storage"))?;
            if root.reader_floor.native_kv2_format != 2 {
                return Err(Response::error(501, "native-large KV2 requires paged V6 storage"));
            }
            let parent = root.kv2_parent_key().map_err(|_| rejected())?;
            let check = || deadline.check().map_err(|_| RecordError::Invalid);
            admitted.engines.check_native_kv2_import_destination("", mount, &parent, &check)
                .map_err(Response::from_engine_error)?;
            let source_auth = owner_store::serialize_owner(
                &self.state.as_ref().ok_or_else(rejected)?.auth,
            ).map_err(|_| rejected())?;
            if owner_store::serialize_owner(&admitted.auth).map_err(|_| rejected())?.as_slice()
                != source_auth.as_slice()
            { return Err(rejected()); }
            let base = self.current_state_identity()?;
            self.durable.as_mut().ok_or_else(rejected)?.verify_live_ownership()
                .map_err(|_| rejected())?;
            let plan = TransferPlan {
                actor, clock, now: request.now, mount: Zeroizing::new(mount.to_owned()),
                activation: Zeroizing::new(self.unseal_nonce.clone()), base, admitted,
                parent, source_auth, deadline, used: false, lease: None, native_request_binding: None,
            };
            plan.authorize(&plan.admitted.auth)?;
            Ok(plan)
        })();
        match prepared {
            Ok(mut plan) => {
                plan.lease = match ImportLease::acquire(&self.native_kv2_large_flight) {
                    Ok(lease) => Some(lease),
                    Err(response) => return response,
                };
                plan.native_request_binding = self.native_request_binding.take();
                self.pending_native_kv2_large = Some(plan);
                Response::ok(Value::Null)
            }
            Err(response) => response,
        }
    }

    pub(super) fn complete_native_kv2_large(
        &mut self,
        plan: TransferPlan,
        result: Result<NativeKv2GraphImport, Response>,
        fingerprint: &str,
        clock: (u64, Option<RequestClock>),
    ) -> Response {
        self.complete_native_kv2_large_with_receipt(plan, result, fingerprint, clock, || {})
    }

    // Keep the actual existing mandatory audit hook in the implementation;
    // tests can expire the original actor after a successful real audit without
    // replacing the actor, clock, publication, or audit with a synthetic result.
    pub(super) fn complete_native_kv2_large_with_receipt(
        &mut self,
        mut plan: TransferPlan,
        result: Result<NativeKv2GraphImport, Response>,
        fingerprint: &str,
        clock: (u64, Option<RequestClock>),
        after_audit: impl FnOnce(),
    ) -> Response {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline.instant());
        if self.native_request_binding.is_some() || self.native_failure_notice.is_some() {
            self.recovery_required = true;
            return rejected();
        }
        self.native_request_binding = plan.native_request_binding.take();
        let response = self.finalize_native_kv2_large(&mut plan, result);
        let committed = response.status == 204;
        // A terminal observation may legitimately publish one Auth clock floor.
        // Capture the imported root/frontier now, then accept only the affine
        // receipt for that exact self-write. A newer unrelated root is no grant.
        let checkpoint = if committed { self.native_kv2_large_checkpoint().ok() } else { None };
        let (mut response, receipt) = self.audit_completed_response_with_clock_receipt(
            fingerprint, clock, response, after_audit, committed,
        );
        let delivery = if committed && response.status == 204 {
            self.check_native_kv2_large_delivery(&plan, checkpoint, receipt)
        } else if committed {
            Err(rejected())
        } else {
            plan.deadline.check().map_err(|_| rejected())
        };
        if delivery.is_err() {
            if committed {
                self.recovery_required = true;
                self.ha_activation = None;
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                // The already committed import is never mislabeled as a safe
                // retry. Audit this negative delivery decision after withholding
                // all success metadata, even when the ordinary audit succeeded.
                erase_json(&mut response.body);
                let _negative_audit = self.audit_event(
                    "native-large-kv2-delivery-veto", fingerprint, clock.0, Some(503),
                );
                response = committed_delivery_rejected();
            } else {
                response = rejected();
            }
        }
        self.retire_native_external_binding(fingerprint, clock.1);
        response
    }

    fn native_kv2_large_checkpoint(&self) -> Result<DeliveryCheckpoint, Response> {
        let identity = self.current_state_identity()?;
        if !matches!(identity, StateIdentity::RecordsV6(_)) { return Err(rejected()); }
        Ok((identity, self.external_effect_generation()?))
    }

    fn check_native_kv2_large_delivery(
        &mut self,
        plan: &TransferPlan,
        mut checkpoint: Option<DeliveryCheckpoint>,
        receipt: Option<token_precision::TerminalClockReceipt>,
    ) -> Result<(), Response> {
        plan.deadline.check().map_err(|_| rejected())?;
        if checkpoint.is_none() { return Err(rejected()); }
        if let Some(receipt) = receipt {
            let before = checkpoint;
            receipt.advance(&mut checkpoint);
            // advance is an exact-before match; a mismatched receipt remains
            // unchanged. Refuse it rather than accepting the current integer.
            if checkpoint == before { return Err(rejected()); }
        }
        if self.recovery_required || self.audit_failed || self.barrier_key.is_none()
            || self.ha.is_some() || self.unseal_nonce.as_str() != plan.activation.as_str()
            || plan.lease.as_ref().is_none_or(|lease| !lease.matches(&self.native_kv2_large_flight))
            || checkpoint != Some(self.native_kv2_large_checkpoint()?)
        { return Err(rejected()); }
        self.durable.as_mut().ok_or_else(rejected)?.verify_live_ownership()
            .map_err(|_| rejected())?;
        // Neither a terminal floor nor another token owner can renew the
        // original actor. Observe it against the immutable admitted Auth first,
        // then the exact receipt-bound current Auth, without authenticating anew.
        plan.authorize(&plan.admitted.auth)?;
        plan.authorize_actor(&self.state.as_ref().ok_or_else(rejected)?.auth)?;
        plan.deadline.check().map_err(|_| rejected())
    }

    fn finalize_native_kv2_large(
        &mut self,
        plan: &mut TransferPlan,
        result: Result<NativeKv2GraphImport, Response>,
    ) -> Response {
        let result = (|| -> Result<(), Response> {
            plan.deadline.check().map_err(|_| rejected())?;
            if self.recovery_required || self.audit_failed || self.barrier_key.is_none()
                || self.ha.is_some() || self.unseal_nonce.as_str() != plan.activation.as_str()
                || self.current_state_identity()? != plan.base
                || plan.lease.as_ref().is_none_or(|lease| !lease.matches(&self.native_kv2_large_flight))
            {
                return Err(Response::error(409, "native-large KV2 source admission changed"));
            }
            plan.authorize(&self.state.as_ref().ok_or_else(rejected)?.auth)?;
            let objects = result?;
            if !plan.used { return Err(rejected()); }
            plan.admitted.schema = plan.admitted.writer_schema();
            let mut original_gate = |auth: &AuthState| plan.authorize(auth);
            let publication = self.prepare_native_kv2_import_root_checked(
                &plan.admitted, objects, &mut original_gate,
            )?;
            let installed = self.commit_native_root_plan(
                &plan.admitted, publication, false, "kv2-import", &mut original_gate,
            )?;
            self.state = Some(installed);
            Ok(())
        })();
        match result {
            Ok(()) => Response {
                status: 204, body: Value::Null, unwrapped_json: None,
                response_headers: Default::default(), consistency_index: None,
            },
            Err(response) => response,
        }
    }
}

impl PendingExternalRequest {
    /// Only the admitted HTTP lane supplies a bounded, original-deadline
    /// reader. No Service writer is held during upload or graph preparation.
    pub(crate) fn execute_native_kv2_large_transfer(
        &mut self,
        reader: &mut impl Read,
    ) -> ExternalEffectResult {
        let ExternalEffectPlan::NativeKv2Large(plan) = &mut self.effect else {
            return ExternalEffectResult::NativeKv2Large(Err(rejected()));
        };
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline.instant());
        let result = (|| -> Result<NativeKv2GraphImport, Response> {
            if plan.used || plan.lease.is_none() { return Err(rejected()); }
            plan.used = true;
            plan.deadline.check().map_err(|_| rejected())?;
            let mut bytes = Zeroizing::new(Vec::new());
            let mut buffer = Zeroizing::new([0_u8; 64 * 1024]);
            loop {
                plan.deadline.check().map_err(|_| rejected())?;
                let count = reader.read(&mut *buffer).map_err(|cause| {
                    if cause.kind() == io::ErrorKind::TimedOut { rejected() }
                    else { Response::error(400, "native-large KV2 body is incomplete") }
                })?;
                plan.deadline.check().map_err(|_| rejected())?;
                if count == 0 { break; }
                if bytes.len().checked_add(count).is_none_or(|size| size > MAX_BUNDLE_BYTES) {
                    return Err(Response::error(413, "native-large KV2 bundle exceeds bound"));
                }
                bytes.try_reserve(count).map_err(|_| Response::error(507,
                    "native-large KV2 bounded buffer unavailable"))?;
                bytes.extend_from_slice(&buffer[..count]);
            }
            let deadline = plan.deadline;
            let check = || deadline.check().map_err(|_| RecordError::Invalid);
            let bundle = NativeLargeBundle::checked(bytes, &check)
                .map_err(Response::from_engine_error)?;
            let objects = plan.admitted.engines.stage_openbao_kv2_native_large_import(
                "", &plan.mount, &bundle, &plan.parent, &check,
            ).map_err(Response::from_engine_error)?;
            plan.deadline.check().map_err(|_| rejected())?;
            Ok(objects)
        })();
        ExternalEffectResult::NativeKv2Large(result)
    }
}
