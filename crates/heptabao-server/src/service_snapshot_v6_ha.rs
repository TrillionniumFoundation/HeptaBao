//! Native HA snapshot custody at the existing affine Service transfer boundary.
//! Download retains its actual request proof through finalization; an archive
//! cannot supply that proof or authorize a restore publication.
use super::*;

#[path = "service_snapshot_v6_ha_repair.rs"]
mod repair;

impl Service {
    fn check_native_ha_snapshot_owner(&self, plan: &SnapshotTransferPlan) -> Result<(), Response> {
        self.check_native_ha_snapshot_owner_at(plan, plan.base)
    }

    fn check_native_ha_snapshot_owner_at(
        &self,
        plan: &SnapshotTransferPlan,
        expected: StateIdentity,
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
            || self.current_state_identity().ok() != Some(expected)
            || self.native_root.is_none()
            || self.record_root.is_some()
            || self.postgres_durable.is_some()
            || self.durable_profile.is_some()
            || self.openbao_wrapper_owner.is_some()
            || self.native_candidate_profile.is_some()
        {
            return Err(unavailable());
        }
        if !plan.actor.is_root() || !plan.namespace.is_empty() {
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

    pub(in crate::service::snapshot_transfer) fn complete_native_ha_snapshot_delivery(
        &mut self,
        plan: &SnapshotTransferPlan,
        mut response: Response,
        fingerprint: &str,
        clock: (u64, Option<RequestClock>),
    ) -> Response {
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
}
