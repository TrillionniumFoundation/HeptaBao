//! Root lossless KV2 export under the existing affine snapshot delivery owner.
//! A completed file remains private until original finalization and audit pass.
use super::*;
use crate::engines::kv2_lossless_export::{MAX_BYTES, PATH};
use crate::state_record_root_v6::ObjectDomain;
use crate::state_records::RecordError;
use crate::v6_native_custody::OriginalDeadline;

#[path = "service_snapshot_lossless_parallel_owner.rs"]
mod parallel_owner;

fn unavailable() -> Response {
    Response::error(503, "native KV2 lossless export authority is unavailable")
}

pub(super) fn mount_query<'a>(request: &'a RequestView<'_>) -> Result<&'a str, Response> {
    if request.path != PATH
        || !matches!(request.method, "GET" | "HEAD")
        || !request.namespace.is_empty()
        || request.wrap_ttl_seconds.is_some_and(|ttl| ttl != 0)
    {
        return Err(Response::error(
            400,
            "lossless export requires unwrapped root-namespace GET or HEAD",
        ));
    }
    let fields = request
        .body
        .as_object()
        .filter(|fields| fields.len() == 1 && fields.contains_key("mount"))
        .ok_or_else(|| Response::error(400, "lossless export requires only the mount query"))?;
    fields
        .get("mount")
        .and_then(Value::as_str)
        .filter(|mount| !mount.is_empty() && mount.len() <= 1024)
        .ok_or_else(|| Response::error(400, "lossless export mount is required"))
}

impl Service {
    // An export holds plaintext, so the original owner is checked again after
    // mandatory audit. Only its one terminal clock receipt may advance the
    // captured state/generation; a fresh unrelated root is never a substitute.
    pub(super) fn complete_native_kv2_lossless_delivery(
        &mut self,
        plan: &SnapshotTransferPlan,
        mut response: Response,
        fingerprint: &str,
        clock: (u64, Option<RequestClock>),
    ) -> Response {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline);
        let source = (|| {
            self.check_v6_snapshot_owner(plan)?;
            Ok::<_, Response>((
                (plan.base, self.external_effect_generation()?),
                self.state.as_ref().ok_or_else(unavailable)?.auth.clone(),
            ))
        })();
        if response.status == 200 && source.is_err() {
            erase_json(&mut response.body);
            response = unavailable();
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
        if !selected || response.status != 200 {
            return response;
        }
        let checked = (|| {
            let (original, auth) = source?;
            let mut checkpoint = Some(original);
            if let Some(receipt) = receipt {
                receipt.advance(&mut checkpoint);
                if checkpoint == Some(original) {
                    return Err(unavailable());
                }
            }
            let checkpoint = checkpoint.ok_or_else(unavailable)?;
            self.check_v6_snapshot_owner_at(plan, checkpoint.0)?;
            if self.external_effect_generation()? != checkpoint.1 {
                return Err(unavailable());
            }
            let proof = self
                .capture_native_request_proof(&mut || {
                    if Instant::now() >= plan.deadline {
                        return Err(unavailable());
                    }
                    auth.authorize_request(
                        &plan.actor,
                        &plan.namespace,
                        &plan.path,
                        "read",
                        snapshot_observed_time(plan.now, plan.started.elapsed()),
                    )
                    .map_err(|error| Response::error(error.status, &error.message))
                })?
                .ok_or_else(unavailable)?;
            if proof.identity() != checkpoint.0 {
                return Err(unavailable());
            }
            proof.check_with(self, Self::check_native_installed)?;
            self.check_v6_snapshot_owner_at(plan, checkpoint.0)?;
            if self.external_effect_generation()? != checkpoint.1 {
                return Err(unavailable());
            }
            Ok(())
        })();
        if let Err(error) = checked {
            erase_json(&mut response.body);
            response.consistency_index = None;
            if self
                .audit_event(
                    "native-kv2-lossless-export-delivery-veto",
                    fingerprint,
                    snapshot_observed_time(plan.now, plan.started.elapsed()),
                    Some(error.status),
                )
                .is_err()
            {
                self.recovery_required = true;
                self.ha_activation = None;
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
            }
            return unavailable();
        }
        response
    }

    pub(in crate::service) fn stage_native_kv2_lossless_export(
        &mut self,
        admitted: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let result = (|| {
            let actor = principal
                .filter(Principal::is_root)
                .ok_or_else(|| Response::error(403, "permission denied"))?;
            if !self.native_snapshot_transport {
                return Err(Response::error(
                    501,
                    "lossless export requires admitted typed HTTP transport",
                ));
            }
            mount_query(request)?;
            if actor.original_request_clock().is_none() || request.token_clock.is_none() {
                return Err(unavailable());
            }
            admitted
                .auth
                .authorize_sudo_request_observed(&actor, "", PATH, "read", request.token_time()?)
                .map_err(|error| Response::error(error.status, &error.message))?;
            self.require_native_root_candidate(&admitted)?;
            if self
                .native_root
                .as_ref()
                .is_none_or(|root| root.reader_floor.native_kv2_format != 2)
            {
                return Err(Response::error(
                    501,
                    "lossless export requires activated paged V6 storage",
                ));
            }
            Ok(self.stage_snapshot_transfer(actor, request))
        })();
        match result {
            Ok(response) | Err(response) => response,
        }
    }

    pub(super) fn prepare_native_kv2_lossless_download(
        &mut self,
        plan: &mut SnapshotTransferPlan,
        mount: &str,
    ) -> Result<SnapshotFile, Response> {
        #[cfg(feature = "native-v6-ha")]
        if self.ha.is_some() || plan.ha.is_some() {
            return self.prepare_native_ha_kv2_lossless_download(plan, mount);
        }
        self.check_v6_snapshot_owner(plan)?;
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        let key = Zeroizing::new(**self.barrier_key.as_ref().ok_or_else(unavailable)?);
        let mut durable = self.durable.take().ok_or_else(unavailable)?;
        let result = (|| {
            let profile = self
                .native_candidate_profile
                .as_ref()
                .ok_or_else(unavailable)?;
            let cold =
                native_v6_reader::load_cold_root(self, profile, &mut durable, &key, deadline)?
                    .ok_or_else(unavailable)?;
            if cold.root.reader_floor.native_kv2_format != 2 {
                return Err(unavailable());
            }
            Self::check_native_installed(
                self.state.as_ref().ok_or_else(unavailable)?,
                &cold.metadata,
                &cold.native,
                &cold.root,
                deadline,
            )?;
            self.check_v6_snapshot_owner(plan)?;
            let mut output = plan
                .lease
                .file(MAX_BYTES, plan.deadline)
                .map_err(|_| Response::error(507, "lossless export staging is unavailable"))?;
            if durable.has_file_immutable_reader() {
                let stopped = std::sync::atomic::AtomicBool::new(false);
                let owner = parallel_owner::SnapshotReadOwner::new(self, plan)?;
                let source = native_blob_source::NativeFileSource::new_checked(
                    &mut durable,
                    deadline,
                    || owner.check().map_err(|_| ServiceError::BarrierFailure),
                    &stopped,
                )
                .map_err(|_| unavailable())?;
                let mut writer = output.buffered_writer().map_err(|_| unavailable())?;
                self.state
                    .as_ref()
                    .ok_or_else(unavailable)?
                    .engines
                    .write_native_kv2_lossless_export_parallel(
                        mount,
                        &mut writer,
                        &|scope, reference| {
                            source.read_paged_payload(&ObjectDomain::Kv2(scope.clone()), reference)
                        },
                        &|| source.before_delivery(),
                        &|| deadline.check().map_err(|_| RecordError::Invalid),
                        deadline,
                        &stopped,
                    )
                    .map_err(Response::from_engine_error)?;
                writer.finish().map_err(|_| unavailable())?;
            } else {
                let source =
                    native_blob_source::NativeSource::new_checked(&mut durable, deadline, || {
                        self.check_v6_snapshot_owner(plan)
                            .map_err(|_| ServiceError::BarrierFailure)
                    })
                    .map_err(|_| unavailable())?;
                let mut writer = output.buffered_writer().map_err(|_| unavailable())?;
                self.state
                    .as_ref()
                    .ok_or_else(unavailable)?
                    .engines
                    .write_native_kv2_lossless_export(
                        mount,
                        &mut writer,
                        |scope, reference| {
                            source.read_paged_payload(&ObjectDomain::Kv2(scope.clone()), reference)
                        },
                        &|| deadline.check().map_err(|_| RecordError::Invalid),
                    )
                    .map_err(Response::from_engine_error)?;
                writer.finish().map_err(|_| unavailable())?;
            }
            self.check_v6_snapshot_owner(plan)?;
            output.rewind_checked().map_err(|_| unavailable())?;
            let length = output.len();
            crate::engines::kv2_lossless_export::check_export_syntax(&mut output, length, &|| {
                deadline.check().map_err(|_| RecordError::Invalid)
            })
            .map_err(Response::from_engine_error)?;
            self.check_v6_snapshot_owner(plan)?;
            output.rewind_checked().map_err(|_| unavailable())?;
            Ok(output)
        })();
        self.durable = Some(durable);
        match result {
            Ok(file) => {
                self.check_v6_snapshot_owner(plan)?;
                Ok(file)
            }
            Err(response) => Err(self.check_v6_snapshot_owner(plan).err().unwrap_or(response)),
        }
    }
}

#[cfg(test)]
type AfterAuditTestHook = Box<dyn FnOnce(&mut Service)>;
#[cfg(test)]
thread_local! {
    static AFTER_AUDIT_TEST_HOOK: std::cell::RefCell<Option<AfterAuditTestHook>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn run_after_audit_test_hook(service: &mut Service) {
    let hook = AFTER_AUDIT_TEST_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(service);
    }
}

#[cfg(test)]
#[path = "service_snapshot_lossless_export_tests.rs"]
mod tests;
