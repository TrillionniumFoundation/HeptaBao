//! The accepted asynchronous task uses the actual native root transaction.
//! No old V5 serializer or unauthenticated payload fallback enters this path.
use super::*;
use crate::state_record_root_v6::ObjectDomain;
use crate::state_records::RecordError;
use crate::v6_native_custody::OriginalDeadline;
use crate::v6_read_validation::ObjectSource;

fn rejected() -> Response {
    Response::error(503, "native remount publication custody rejected")
}

#[cfg(all(test, unix))]
#[path = "service_native_remount_v6_tests.rs"]
mod tests;

impl Task {
    pub(super) fn execute_native(&self, service: &mut Service) -> Result<Owner, Response> {
        self.check_deadline()?;
        let current = service.state.as_ref().ok_or_else(rejected)?.clone();
        self.check_source(service, &current)?;
        self.native_scope
            .as_ref()
            .ok_or_else(rejected)?
            .check(&current)?;
        service.require_native_root_candidate(&current)?;
        let identity = service.current_state_identity()?;
        let actual_auth = current.auth.clone();
        let auth_bytes = owner_store::serialize_owner(&actual_auth).map_err(|_| rejected())?;
        let proof = service
            .capture_native_request_proof(&mut || self.check_deadline())?
            .ok_or_else(rejected)?;
        proof.check_warm(service)?;
        let root = service.native_root.as_ref().ok_or_else(rejected)?.clone();
        #[cfg(test)]
        eprintln!("HBREMOUNT stage=original-native-root");
        let deadline = OriginalDeadline::capture().map_err(|_| rejected())?;
        let mut candidate = current.clone();
        let objects = if let Owner::Engine(owner) = &self.owner
            && current
                .engines
                .is_native_kv2_remount(&self.namespace, &self.from)
        {
            let parent = root.kv2_parent_key().map_err(|_| rejected())?;
            let durable = service.durable.as_mut().ok_or_else(rejected)?;
            let source = native_blob_source::NativeSource::new_checked(durable, deadline, || {
                self.check_deadline()
                    .map_err(|_| ServiceError::BarrierFailure)
            })
            .map_err(|_| rejected())?;
            let receipt = candidate
                .engines
                .stage_native_kv2_remount(
                    &self.namespace,
                    &self.from,
                    &self.to,
                    self.cas,
                    owner,
                    &parent,
                    &root.kv2,
                    |scope, reference| source.read(&ObjectDomain::Kv2(scope.clone()), reference),
                    &|| self.check_deadline().map_err(|_| RecordError::Invalid),
                )
                .map_err(Response::from_engine_error)?;
            drop(source);
            candidate
                .auth
                .relocate_rate_limit_quotas(
                    &self.namespace,
                    &format!("{}/", self.from),
                    &format!("{}/", self.to),
                )
                .map_err(auth_error)?;
            receipt
        } else {
            self.move_current(&mut candidate)?;
            None
        };
        self.check_source(service, service.state.as_ref().ok_or_else(rejected)?)?;
        #[cfg(test)]
        eprintln!("HBREMOUNT stage=detached-move-prepared");
        proof.check_warm(service)?;
        if service.current_state_identity()? != identity {
            return Err(rejected());
        }
        candidate.schema = candidate.writer_schema();
        candidate.validate_publication_schema(Some(&current))?;
        candidate.validate_format()?;
        let terminal = self.resulting_owner(&candidate)?;
        self.check_terminal(service, &candidate, &terminal)?;
        let mut gate = |live_auth: &AuthState| -> Result<(), Response> {
            self.check_deadline()?;
            if owner_store::serialize_owner(live_auth)
                .map_err(|_| rejected())?
                .as_slice()
                != auth_bytes.as_slice()
            {
                return Err(rejected());
            }
            self.native_scope
                .as_ref()
                .ok_or_else(rejected)?
                .check(&current)?;
            self.check_deadline()
        };
        let plan = match objects {
            Some(objects) => {
                service.prepare_native_kv2_import_root_checked(&candidate, objects, &mut gate)?
            }
            None => service.prepare_native_live_root_checked(&candidate, &mut gate)?,
        };
        #[cfg(test)]
        eprintln!("HBREMOUNT stage=native-plan-validated");
        self.check_source(service, service.state.as_ref().ok_or_else(rejected)?)?;
        proof.check_warm(service)?;
        if service.current_state_identity()? != identity {
            return Err(rejected());
        }
        let installed = service.commit_native_root_plan(
            &candidate,
            plan,
            false,
            "native-remount",
            &mut gate,
        )?;
        #[cfg(test)]
        eprintln!("HBREMOUNT stage=native-root-readback");
        // The publisher returns its independently installed/readback candidate.
        // Reusing the detached prepublication state would lose that evidence.
        // Auth's process-local remount marker is newly opened by that readback;
        // capture the actual terminal marker only after the complete candidate
        // owner/root equality has been proved by the native writer.
        let terminal = self.resulting_owner(&installed)?;
        service.state = Some(installed);
        self.check_terminal(
            service,
            service.state.as_ref().ok_or_else(rejected)?,
            &terminal,
        )?;
        Ok(terminal)
    }
}
