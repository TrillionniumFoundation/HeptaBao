//! Definitions bind query conversion to the actual namespace/version. Data cannot mint authority.
use super::*;
use crate::request_metadata::{DataFrame, QueryProfile};
pub(in crate::service) struct InputBody(pub(in crate::service) Value);
impl Drop for InputBody {
    fn drop(&mut self) {
        erase_json(&mut self.0);
    }
}
pub(in crate::service) struct Prepared {
    pub(in crate::service) body: Option<InputBody>,
    pub(in crate::service) frame: Option<DataFrame>,
}
fn namespace_identity(state: &State, namespace: &str) -> Result<(String, u64), Response> {
    let id = state
        .namespaces
        .identity_namespace(namespace)?
        .id
        .unwrap_or("root")
        .to_owned();
    let incarnation = state
        .namespaces
        .incarnation(namespace)
        .ok_or_else(|| Response::error(404, "workflow namespace owner is absent"))?;
    Ok((id, incarnation))
}
pub(in crate::service) fn prepare(
    state: &State,
    actor: Option<&Principal>,
    request: &RequestView<'_>,
    mut frame: Option<DataFrame>,
) -> Result<Prepared, Response> {
    if let Some(data) = &frame {
        data.validate().map_err(|e| Response::error(400, e))?;
    }
    let route = request.path.starts_with("sys/workflows/execute/");
    if route && !matches!(request.method, "POST" | "PUT") {
        return Err(Response::error(405, "unsupported workflow execution operation"));
    }
    if !route {
        if frame
            .as_ref()
            .is_some_and(|data| !data.query.is_empty() || data.profile.is_some())
        {
            return Err(Response::error(
                400,
                "workflow query data belongs to another route",
            ));
        }
        return Ok(Prepared { body: None, frame });
    }
    let actor = actor.ok_or_else(|| Response::error(403, "missing client token"))?;
    state
        .auth
        .authorize_request_observed(
            actor,
            request.namespace,
            request.path,
            "update",
            request.token_time()?,
        )
        .map_err(|error| Response::error(error.status, &error.message))?;
    let path = route_suffix(request.path, "sys/workflows/execute")
        .ok_or_else(|| Response::error(400, "workflow path is required"))?;
    validate_workflow_path(path).map_err(|e| Response::error(400, e))?;
    let Some(stored) = state.namespaces.workflows.get(request.namespace, path) else {
        // Do not reinterpret missing workflow query as another backend's input.
        return Err(Response::error(404, "workflow not found"));
    };
    let Some(profile) = &stored.definition.profile else {
        if frame.as_ref().is_some_and(|data| !data.query.is_empty()) {
            return Err(Response::error(400, "workflow query requires a profile"));
        }
        return Ok(Prepared { body: None, frame });
    };
    if !profile.has_logical_data() {
        if frame.as_ref().is_some_and(|data| !data.query.is_empty()) {
            return Err(Response::error(
                400,
                "workflow has no declared query fields",
            ));
        }
        return Ok(Prepared { body: None, frame });
    }
    let program = profile
        .dynamic_program()?
        .ok_or_else(|| Response::error(503, "workflow logical data program unavailable"))?;
    let (namespace_id, incarnation) = namespace_identity(state, request.namespace)?;
    let data = frame.get_or_insert_with(DataFrame::default);
    if let Some(previous) = &data.profile {
        if previous.namespace_id != namespace_id
            || previous.incarnation != incarnation
            || previous.path != path
            || previous.version != stored.version
            || previous.document != profile.document()
        {
            return Err(Response::error(
                403,
                "workflow input definition ownership changed",
            ));
        }
    } else {
        data.profile = Some(QueryProfile {
            namespace_id,
            incarnation,
            path: path.to_owned(),
            version: stored.version,
            document: profile.document().to_owned(),
            digest: crypto::digest(profile.document().as_bytes()),
        });
    }
    let raw = program.raw_input(request.body, &data.query)?;
    state
        .auth
        .authorize_request_parameters_observed(
            actor,
            request.namespace,
            request.method,
            request.path,
            &raw.0,
            request.token_time()?,
        )
        .map_err(|error| Response::error(error.status, &error.message))?;
    let value = program.effective_input(request.body, &data.query)?;
    data.validate().map_err(|e| Response::error(400, e))?;
    Ok(Prepared {
        body: Some(InputBody(value)),
        frame,
    })
}
pub(in crate::service) fn reconstruct(
    frame: Option<&DataFrame>,
    method: &str,
    path: &str,
    body: &Value,
) -> Result<Option<InputBody>, Response> {
    let invalid = || Response::error(503, "workflow stored logical data binding rejected");
    let Some(data) = frame else {
        return Ok(None);
    };
    data.validate().map_err(|_| invalid())?;
    let Some(binding) = &data.profile else {
        if !data.query.is_empty() {
            return Err(invalid());
        }
        return Ok(None);
    };
    if !matches!(method, "POST" | "PUT") || path != format!("sys/workflows/execute/{}", binding.path) {
        return Err(invalid());
    }
    validate_workflow_path(&binding.path).map_err(|_| invalid())?;
    let program = profiles::dynamic::Program::compile(&binding.document)
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    if !program.has_logical_data() {
        return Err(invalid());
    }
    let value = program
        .effective_input(body, &data.query)
        .map_err(|_| invalid())?;
    Ok(Some(InputBody(value)))
}
pub(in crate::service) fn live(
    state: &State,
    namespace: &str,
    frame: Option<&DataFrame>,
) -> Result<(), Response> {
    let Some(binding) = frame.and_then(|data| data.profile.as_ref()) else {
        return Ok(());
    };
    let denied = || Response::error(403, "workflow input definition ownership changed");
    let (id, incarnation) = namespace_identity(state, namespace).map_err(|_| denied())?;
    let stored = state
        .namespaces
        .workflows
        .get(namespace, &binding.path)
        .ok_or_else(denied)?;
    let profile = stored.definition.profile.as_ref().ok_or_else(denied)?;
    if binding.namespace_id != id
        || binding.incarnation != incarnation
        || binding.version != stored.version
        || binding.document != profile.document()
        || binding.digest != crypto::digest(profile.document().as_bytes())
    {
        return Err(denied());
    }
    Ok(())
}

/// Run original parameter ACL on actual pre-coercion transport input, before
/// authenticating/claiming the one-use wrapper. No current frame grants authority.
pub(in crate::service) fn authorize_owner_input(
    state: &State,
    actor: &Principal,
    owner: &crate::auth::control_groups::DeferredRequest,
    time: crate::auth::AuthorityTime,
) -> Result<(), Response> {
    let Some(data) = owner.logical_data.as_ref() else {
        return Ok(());
    };
    let Some(binding) = data.profile.as_ref() else {
        return Ok(());
    };
    let program = profiles::dynamic::Program::compile(&binding.document)?
        .ok_or_else(|| Response::error(503, "workflow stored input program unavailable"))?;
    let raw = program.raw_input(&owner.transport_body, &data.query)?;
    state
        .auth
        .authorize_request_parameters_observed(
            actor,
            &owner.namespace,
            &owner.method,
            &owner.path,
            &raw.0,
            time,
        )
        .map_err(|error| Response::error(error.status, &error.message))
}
