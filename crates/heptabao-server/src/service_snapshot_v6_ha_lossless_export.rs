//! A logical export retains the same original HA proof through final delivery.
use super::*;
use crate::engines::kv2_lossless_export::{MAX_BYTES, PATH};

impl Service {
    pub(in crate::service::snapshot_transfer) fn prepare_native_ha_kv2_lossless_download(
        &mut self,
        plan: &mut SnapshotTransferPlan,
        mount: &str,
    ) -> Result<SnapshotFile, Response> {
        self.check_native_ha_snapshot_owner(plan)?;
        if !plan.is_download || plan.path != PATH || plan.native_ha_source.is_some() {
            return Err(unavailable());
        }
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
        let output = plan
            .lease
            .file(MAX_BYTES, plan.deadline)
            .map_err(|_| unavailable())?;
        let output = proof.export_kv2_lossless(self, mount, output, &mut |service| {
            service.check_native_ha_snapshot_owner(plan)
        })?;
        self.check_native_ha_snapshot_owner(plan)?;
        proof.check_warm(self)?;
        plan.native_ha_source = Some(proof);
        Ok(output)
    }
}
