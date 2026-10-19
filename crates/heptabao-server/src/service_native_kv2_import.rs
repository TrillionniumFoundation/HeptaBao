//! Root-namespace lossless import through the existing native graph publisher.
//! Ordinary request audit and control-group admission remain in the caller.
use super::*;
use crate::state_records::RecordError;
use crate::v6_native_custody::OriginalDeadline;

fn rejected() -> Response {
    Response::error(503, "native KV2 graph import custody rejected")
}

impl Service {
    pub(super) fn dispatch_native_kv2_import(
        &mut self,
        mut admitted: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        if request.token_clock.is_none() {
            return Response::error(503, "trusted token clock is required");
        }
        let deadline = match OriginalDeadline::capture() {
            Ok(deadline) => deadline,
            Err(_) => return rejected(),
        };
        let mut authority = |auth: &AuthState| -> Result<(), Response> {
            deadline.check().map_err(|_| rejected())?;
            let time = request.token_time()?;
            auth.authorize_request_parameters_observed(
                &principal, request.namespace, request.method,
                request.path, request.body, time,
            ).map_err(|error| Response::error(error.status, &error.message))?;
            auth.authorize_sudo_request_observed(
                &principal, request.namespace, "sys/migration/openbao/kv2", "update", time,
            ).map_err(|error| Response::error(error.status, &error.message))?;
            deadline.check().map_err(|_| rejected())
        };
        if let Err(error) = authority(&admitted.auth) {
            return error;
        }
        if request.method != "POST" {
            return Response::error(405, "KV2 migration requires POST");
        }
        // HA publication carries its own provenance and reply contract. This
        // new single-node import does not silently widen that admission.
        if !request.namespace.is_empty() || self.ha.is_some() {
            return Response::error(501, "native KV2 graph import requires root single-node custody");
        }
        if let Err(error) = self.require_native_root_candidate(&admitted) {
            return error;
        }
        let Some(root) = self.native_root.as_ref() else {
            return rejected();
        };
        if root.reader_floor.native_kv2_format != 2 {
            return Response::error(501, "native KV2 graph import requires paged V6 storage");
        }
        let parent = match root.kv2_parent_key() {
            Ok(parent) => parent,
            Err(_) => return rejected(),
        };
        let Some(fields) = request.body.as_object() else {
            return Response::error(400, "KV2 migration requires a JSON object");
        };
        if fields.len() != 2
            || fields.keys().any(|key| !matches!(key.as_str(), "mount" | "bundle"))
        {
            return Response::error(400, "unsupported KV2 migration parameter");
        }
        let Some(mount) = fields.get("mount").and_then(Value::as_str) else {
            return Response::error(400, "KV2 migration mount is required");
        };
        let Some(bundle) = fields.get("bundle").filter(|value| value.is_object()) else {
            return Response::error(400, "KV2 migration bundle is required");
        };
        // Keep the existing request/bundle limits. This is a graph writer,
        // not an implicit increase of the decoder or HTTP transport budget.
        let bytes = match crate::secret_serde::to_vec(bundle, crate::MAX_APPLICATION_STATE_BYTES) {
            Ok(bytes) => bytes,
            Err(_) => return Response::error(507, "KV2 migration bundle exceeds capacity"),
        };
        let source_auth = match self.state.as_ref()
            .map(|state| owner_store::serialize_owner(&state.auth))
        {
            Some(Ok(bytes)) => bytes,
            _ => return rejected(),
        };
        let admitted_auth = match owner_store::serialize_owner(&admitted.auth) {
            Ok(bytes) => bytes,
            Err(_) => return rejected(),
        };
        if source_auth.as_slice() != admitted_auth.as_slice() {
            return rejected();
        }
        let check = || deadline.check().map_err(|_| RecordError::Invalid);
        let objects = match admitted.engines.stage_openbao_kv2_native_import(
            request.namespace, mount, &bytes, &parent, &check,
        ) {
            Ok(objects) => objects,
            Err(error) => return Response::from_engine_error(error),
        };
        admitted.schema = admitted.writer_schema();
        let mut original_gate = |auth: &AuthState| -> Result<(), Response> {
            authority(auth)?;
            if owner_store::serialize_owner(auth).map_err(|_| rejected())?.as_slice()
                != source_auth.as_slice()
            {
                return Err(rejected());
            }
            deadline.check().map_err(|_| rejected())
        };
        let plan = match self.prepare_native_kv2_import_root_checked(
            &admitted, objects, &mut original_gate,
        ) {
            Ok(plan) => plan,
            Err(error) => return error,
        };
        match self.commit_native_root_plan(
            &admitted, plan, false, "kv2-import", &mut original_gate,
        ) {
            Ok(installed) => {
                self.state = Some(installed);
                Response {
                    status: 204,
                    body: Value::Null,
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                }
            }
            Err(error) => error,
        }
    }
}

#[cfg(test)]
#[path = "service_native_kv2_import_tests.rs"]
mod tests;
