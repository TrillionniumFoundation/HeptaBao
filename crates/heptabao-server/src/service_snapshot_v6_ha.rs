//! Native HA snapshot custody at the existing affine Service transfer boundary.
//! Download retains its actual request proof through finalization; an archive
//! cannot supply that proof or authorize a restore publication.
use super::*;

#[path = "service_snapshot_v6_ha_lossless_export.rs"]
mod lossless_export;

#[path = "service_snapshot_v6_ha_repair.rs"]
mod repair;

#[path = "service_snapshot_v6_ha_restore.rs"]
mod restore;
pub(in crate::service::snapshot_transfer) use restore::NativeHaHistoricalReceipt;

// This proof is confined to one historical prepare. Its shared Service and
// plan borrows keep the ordinary root identity fixed. Actor, clock, actual
// seal file, deadline and the original custody checks remain live at every
// gate; the complete identity is authenticated at entry and completion.
struct BorrowedNativeHaSnapshotOwner<'a> {
    service: &'a Service,
    plan: &'a SnapshotTransferPlan,
}

impl<'a> BorrowedNativeHaSnapshotOwner<'a> {
    fn capture(service: &'a Service, plan: &'a SnapshotTransferPlan) -> Result<Self, Response> {
        service.check_native_ha_snapshot_owner(plan)?;
        Ok(Self { service, plan })
    }

    fn check(&self) -> Result<(), Response> {
        self.service
            .check_native_ha_snapshot_owner_before_identity(self.plan)?;
        self.service
            .check_native_ha_snapshot_owner_after_identity(self.plan)
    }

    // This callback surrounds bounded seek/read operations within one object.
    // The shared Service/plan borrow keeps the admitted in-memory identity
    // fixed. Full Actor and physical seal checks still surround the selected
    // object's authenticated read; no plaintext is returned after a late
    // refusal. Reopening seal.json for each I/O chunk adds no authority here.
    fn check_io(&self) -> Result<(), Response> {
        self.service
            .check_native_ha_snapshot_owner_before_identity(self.plan)
    }

    fn check_complete(&self) -> Result<(), Response> {
        self.service.check_native_ha_snapshot_owner(self.plan)
    }
}

impl Service {
    fn check_native_ha_snapshot_owner(&self, plan: &SnapshotTransferPlan) -> Result<(), Response> {
        self.check_native_ha_snapshot_owner_at(plan, plan.base)
    }

    fn check_native_ha_snapshot_owner_at(
        &self,
        plan: &SnapshotTransferPlan,
        expected: StateIdentity,
    ) -> Result<(), Response> {
        self.check_native_ha_snapshot_owner_before_identity(plan)?;
        if self.current_state_identity().ok() != Some(expected) {
            return Err(unavailable());
        }
        self.check_native_ha_snapshot_owner_after_identity(plan)
    }

    fn check_native_ha_snapshot_owner_before_identity(
        &self,
        plan: &SnapshotTransferPlan,
    ) -> Result<(), Response> {
        let same_ha = match (&self.ha, &plan.ha) {
            (Some(current), Some(admitted)) => Arc::ptr_eq(current, admitted),
            _ => false,
        };
        if !same_ha
            || Instant::now() >= plan.deadline
            || self.audit_failed
            || self.recovery_required
            || self.barrier_key.is_none()
            || self.unseal_nonce != plan.activation
        {
            return Err(unavailable());
        }
        Ok(())
    }

    fn check_native_ha_snapshot_owner_after_identity(
        &self,
        plan: &SnapshotTransferPlan,
    ) -> Result<(), Response> {
        if self.native_root.is_none()
            || self.record_root.is_some()
            || self.postgres_durable.is_some()
            || self.durable_profile.is_some()
            || self.openbao_wrapper_owner.is_some()
            || self.native_candidate_profile.is_some()
        {
            return Err(unavailable());
        }
        let public_snapshot = matches!(
            plan.path.as_str(),
            "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force"
        );
        if (!plan.actor.is_root() && !public_snapshot) || !plan.namespace.is_empty() {
            return Err(Response::error(403, "permission denied"));
        }
        let now = snapshot_observed_time(plan.now, plan.started.elapsed());
        self.state
            .as_ref()
            .ok_or_else(unavailable)?
            .auth
            .authorize_request(
                &plan.actor,
                &plan.namespace,
                &plan.path,
                if plan.is_download { "read" } else { "update" },
                now,
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
        if self.current_snapshot_seal_identity_for_plan(plan)? != plan.seal_identity {
            return Err(Response::error(409, "native HA snapshot live seal changed"));
        }
        if Instant::now() >= plan.deadline {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(in crate::service::snapshot_transfer::v6) fn prepare_native_ha_snapshot_download(
        &mut self,
        plan: &mut SnapshotTransferPlan,
    ) -> Result<DownloadSource, Response> {
        self.check_native_ha_snapshot_owner(plan)?;
        if !plan.is_download || plan.native_ha_source.is_some() {
            return Err(unavailable());
        }
        // ReadIndex is obtained by this actual Service request proof. It must
        // remain valid under the admitted root, Actor and original deadline.
        let source_auth = self.state.as_ref().ok_or_else(unavailable)?.auth.clone();
        let proof = self
            .capture_native_ha_request_proof(&mut || {
                if Instant::now() >= plan.deadline {
                    return Err(unavailable());
                }
                source_auth
                    .authorize_request(
                        &plan.actor,
                        &plan.namespace,
                        &plan.path,
                        "read",
                        snapshot_observed_time(plan.now, plan.started.elapsed()),
                    )
                    .map_err(|error| Response::error(error.status, &error.message))
            })?
            .ok_or_else(unavailable)?;
        self.check_native_ha_snapshot_owner(plan)?;
        let local = plan
            .lease
            .file(crate::snapshot_file::MAX_V6_SNAPSHOT_STATE, plan.deadline)
            .map_err(|_| unavailable())?;
        let output = plan
            .lease
            .file(
                crate::snapshot_file::MAX_V6_HA_SNAPSHOT_STATE,
                plan.deadline,
            )
            .map_err(|_| unavailable())?;
        let (state, report) = proof.export_snapshot_archive(
            self,
            local,
            output,
            plan.seal_identity,
            &mut |service| service.check_native_ha_snapshot_owner(plan),
        )?;
        let metadata = serde_json::to_vec(&Metadata::new_v6_ha(
            report.local.generation,
            report.archive_bytes,
            &plan.seal_identity,
        ))
        .map_err(|_| invalid())?;
        let sums = snapshot_archive::sums(&metadata, &report.archive_sha256);
        let barrier = AeadBarrier::new(**self.barrier_key.as_ref().ok_or_else(unavailable)?)
            .map_err(|_| unavailable())?;
        let sealed_sums = barrier
            .seal(snapshot_archive::CHECKSUM_CONTEXT, &sums)
            .map_err(|_| unavailable())?;
        self.check_native_ha_snapshot_owner(plan)?;
        proof.check_warm(self)?;
        plan.native_ha_source = Some(proof);
        Ok(DownloadSource {
            state,
            metadata,
            sums,
            sealed_sums,
        })
    }

    pub(in crate::service::snapshot_transfer) fn finish_native_ha_snapshot_download(
        &mut self,
        plan: &SnapshotTransferPlan,
    ) -> Response {
        let result = (|| {
            self.check_native_ha_snapshot_owner(plan)?;
            let proof = plan.native_ha_source.as_ref().ok_or_else(unavailable)?;
            proof.check_with(self, Service::check_native_installed)?;
            self.check_native_ha_snapshot_owner(plan)
        })();
        match result {
            Ok(()) => Response::ok(Value::Null),
            Err(error) => error,
        }
    }

    pub(in crate::service::snapshot_transfer) fn prepare_native_ha_standby_snapshot_validation(
        &mut self,
        plan: &mut SnapshotTransferPlan,
    ) -> Result<(), Response> {
        self.check_native_ha_snapshot_owner(plan)?;
        if !plan.standby_read
            || plan.is_download
            || plan.native_ha_source.is_some()
            || plan.native_ha_restore_source.is_some()
            || !matches!(
                plan.path.as_str(),
                "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force"
            )
        {
            return Err(unavailable());
        }
        // The real update ACL authorizes parsing this upload, not changing
        // any state. Keep the same source/Actor/ReadIndex through completion;
        // a successfully parsed archive must still go to the actual leader.
        let source_auth = self.state.as_ref().ok_or_else(unavailable)?.auth.clone();
        let proof = self
            .capture_native_ha_request_proof(&mut || {
                if Instant::now() >= plan.deadline {
                    return Err(unavailable());
                }
                source_auth
                    .authorize_request(
                        &plan.actor,
                        &plan.namespace,
                        &plan.path,
                        "update",
                        snapshot_observed_time(plan.now, plan.started.elapsed()),
                    )
                    .map_err(|error| Response::error(error.status, &error.message))
            })?
            .ok_or_else(unavailable)?;
        self.check_native_ha_snapshot_owner(plan)?;
        proof.check_warm(self)?;
        plan.native_ha_source = Some(proof);
        Ok(())
    }

    pub(in crate::service::snapshot_transfer) fn complete_native_ha_snapshot_delivery(
        &mut self,
        plan: &SnapshotTransferPlan,
        mut response: Response,
        fingerprint: &str,
        clock: (u64, Option<RequestClock>),
    ) -> Response {
        if plan.standby_read {
            return self.complete_native_standby_snapshot_delivery(
                plan,
                response,
                fingerprint,
                clock,
            );
        }
        let exported_checkpoint: Result<_, Response> = (|| {
            self.check_native_ha_snapshot_owner(plan)?;
            Ok((plan.base, self.external_effect_generation()?))
        })();
        if response.status < 400
            && let Err(error) = &exported_checkpoint
        {
            response = Response::error(
                error.status,
                "native HA snapshot source changed before terminal audit",
            );
        }
        let (mut response, receipt) = self.audit_completed_response_with_clock_receipt(
            fingerprint,
            clock,
            response,
            || {},
            true,
        );
        if response.status >= 400 {
            return response;
        }
        let checked: Result<(), Response> = (|| {
            let exported_checkpoint = exported_checkpoint?;
            let exported = plan.native_ha_source.as_ref().ok_or_else(unavailable)?;
            if let Some(receipt) = receipt {
                // This is one observation-only successor of archive A, never
                // permission to change A's archived root/generation/provenance.
                let terminal = receipt.bind_native_snapshot(exported_checkpoint)?;
                if self.current_state_identity()? != terminal.0
                    || self.external_effect_generation()? != terminal.1
                {
                    return Err(unavailable());
                }
                self.check_native_ha_snapshot_owner_at(plan, terminal.0)?;
                let source_auth = self.state.as_ref().ok_or_else(unavailable)?.auth.clone();
                let current = self
                    .capture_native_ha_request_proof(&mut || {
                        if Instant::now() >= plan.deadline {
                            return Err(unavailable());
                        }
                        source_auth
                            .authorize_request(
                                &plan.actor,
                                &plan.namespace,
                                &plan.path,
                                if plan.is_download { "read" } else { "update" },
                                snapshot_observed_time(plan.now, plan.started.elapsed()),
                            )
                            .map_err(|error| Response::error(error.status, &error.message))
                    })?
                    .ok_or_else(unavailable)?;
                exported.check_snapshot_terminal_successor(self, &current)?;
                self.check_native_ha_snapshot_owner_at(plan, terminal.0)?;
            } else {
                if self.current_state_identity()? != exported_checkpoint.0
                    || self.external_effect_generation()? != exported_checkpoint.1
                {
                    return Err(unavailable());
                }
                exported.check_with(self, Service::check_native_installed)?;
                self.check_native_ha_snapshot_owner(plan)?;
            }
            Ok(())
        })();
        if let Err(error) = checked {
            erase_json(&mut response.body);
            response.consistency_index = None;
            let now = snapshot_observed_time(plan.now, plan.started.elapsed());
            if self
                .audit_event(
                    "native-ha-snapshot-delivery-veto",
                    fingerprint,
                    now,
                    Some(error.status),
                )
                .is_err()
            {
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(
                    503,
                    "native HA snapshot delivery veto audit failed; recovery required",
                );
            }
            return error;
        }
        response
    }

    pub(in crate::service) fn check_native_standby_snapshot_before_audit(
        &self,
        plan: &SnapshotTransferPlan,
    ) -> Result<(), Response> {
        if !plan.standby_read || !self.native_standby_snapshot_is_read_eligible() {
            return Err(unavailable());
        }
        self.check_native_ha_snapshot_owner(plan)?;
        plan.native_ha_source
            .as_ref()
            .ok_or_else(unavailable)?
            .check_warm(self)?;
        if let Some(request) = &plan.standby_clock {
            if crate::auth::current_ingress().map(|ingress| ingress.attempt_id())
                != Some(request.ingress)
            {
                return Err(unavailable());
            }
        } else if self
            .state
            .as_ref()
            .is_none_or(State::has_token_api_precision_state)
        {
            return Err(unavailable());
        }
        Ok(())
    }

    fn complete_native_standby_snapshot_delivery(
        &mut self,
        plan: &SnapshotTransferPlan,
        response: Response,
        fingerprint: &str,
        clock: (u64, Option<RequestClock>),
    ) -> Response {
        // Retain the complete original response audit. This private affine
        // plan defers only the clock publication; no ordinary request/header
        // can select it. The leader's final observation comes AFTER this audit.
        let (mut response, unexpected_local_receipt) = self
            .audit_completed_response_with_clock_source(
                fingerprint,
                clock,
                response,
                || {},
                false,
                Some(plan),
            );
        if unexpected_local_receipt.is_some() {
            erase_json(&mut response.body);
            return unavailable();
        }
        if self.audit_failed || self.recovery_required {
            return response;
        }
        let checked: Result<(), Response> = (|| {
            self.check_native_ha_snapshot_owner_before_identity(plan)?;
            if self.current_state_identity()? != plan.base
                || self.current_snapshot_seal_identity_for_plan(plan)? != plan.seal_identity
            {
                return Err(unavailable());
            }
            let exported = plan.native_ha_source.as_ref().ok_or_else(unavailable)?;
            exported.check_warm(self)?;
            if let Some(request) = &plan.standby_clock {
                if crate::auth::current_ingress().map(|ingress| ingress.attempt_id())
                    != Some(request.ingress)
                {
                    return Err(unavailable());
                }
                let source = exported.snapshot_clock_shared_state();
                let context = crate::ha::snapshot_clock::SnapshotClockContext {
                    operation: request.operation,
                    method: &request.method,
                    token: &request.token,
                    origin_peer: request.origin_peer,
                    ingress: request.ingress,
                    source,
                    enrollment: exported.snapshot_clock_enrollment(),
                    deadline: plan.deadline,
                };
                let ha = plan.ha.as_ref().ok_or_else(unavailable)?;
                let terminal = {
                    let process = ha.lock_for_request().map_err(|_| unavailable())?;
                    // A failed/unknown single exchange is never resent. Only
                    // this response's authenticated affine receipt can name B.
                    let receipt = process.observe_snapshot_terminal_clock(context)?;
                    receipt.consume(&process, context)?
                };
                self.sync_from_ha_with_anchor(false)?;
                let expected = terminal.successor().unwrap_or(source);
                self.check_native_ha_snapshot_owner_before_identity(plan)?;
                if self.current_state_identity()? != StateIdentity::RecordsV6(expected.root_digest)
                    || self.current_snapshot_seal_identity_for_plan(plan)? != plan.seal_identity
                {
                    return Err(unavailable());
                }
                // A Denied completion still has to prove actual B before a
                // final actor refusal may be delivered. Shared metadata and
                // the status alone cannot stand in for this real ReadIndex.
                let current = self
                    .capture_native_ha_request_proof(&mut || {
                        if Instant::now() >= plan.deadline {
                            Err(unavailable())
                        } else {
                            Ok(())
                        }
                    })?
                    .ok_or_else(unavailable)?;
                if current.snapshot_clock_shared_state() != expected {
                    return Err(unavailable());
                }
                let local_checkpoint = (
                    self.current_state_identity()?,
                    self.external_effect_generation()?,
                );
                if terminal.successor().is_some() {
                    exported.check_snapshot_terminal_successor(self, &current)?;
                } else {
                    exported.check_with(self, Service::check_native_installed)?;
                    current.check_warm(self)?;
                }
                if self.current_state_identity()? != local_checkpoint.0
                    || self.external_effect_generation()? != local_checkpoint.1
                {
                    return Err(unavailable());
                }
                self.check_native_ha_snapshot_owner_before_identity(plan)?;
                // A terminal Actor 403 returns before the ordinary owner's
                // final physical-seal check. Both dispositions must read the
                // retained seal after the actual B ReadIndex and before that
                // refusal can short-circuit the allowed-owner path.
                if self.current_snapshot_seal_identity_for_plan(plan)? != plan.seal_identity {
                    return Err(unavailable());
                }
                let actor = self.check_native_ha_snapshot_owner_after_identity(plan);
                if terminal.is_denied() {
                    match actor {
                        Err(error) if error.status == 403 => {
                            terminal.finish_denied()?;
                            return Err(error);
                        }
                        _ => return Err(unavailable()),
                    }
                }
                // A newly observed expiry after an Allowed floor is not a
                // Denied proof; refuse without releasing A or replaying the
                // clock operation. Pre-writer expiry retains sealed Denied403.
                actor.map_err(|error| {
                    if error.status == 403 {
                        unavailable()
                    } else {
                        error
                    }
                })?;
                terminal.finish_allowed()?;
            } else {
                // The old pure case still checks its original actual proof
                // after mandatory audit. It is not an exemption for a store
                // that now needs a token or resource observation write.
                if self
                    .state
                    .as_ref()
                    .is_none_or(State::has_token_api_precision_state)
                {
                    return Err(unavailable());
                }
                exported.check_with(self, Service::check_native_installed)?;
                self.check_native_ha_snapshot_owner(plan)?;
            }
            Ok(())
        })();
        if let Err(error) = checked {
            erase_json(&mut response.body);
            response.consistency_index = None;
            let now = snapshot_observed_time(plan.now, plan.started.elapsed());
            if self
                .audit_event(
                    "native-ha-snapshot-delivery-veto",
                    fingerprint,
                    now,
                    Some(error.status),
                )
                .is_err()
            {
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(
                    503,
                    "native HA snapshot delivery veto audit failed; recovery required",
                );
            }
            return error;
        }
        crate::ha_forward_completion::audited(clock.1);
        self.stamp_consistency_index(&mut response);
        response
    }
}
