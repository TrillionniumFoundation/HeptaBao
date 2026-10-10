//! Service-owned durable deferred approval admission and affine execution.
use super::*;
use crate::auth::control_groups::{
    Approval, DeferredRequest, PolicyControl, ResolvedFactor, ResourceBinding,
};

pub(super) struct ControlGroupResume {
    pub(super) actor: Principal,
    pub(super) echo: Option<Zeroizing<String>>,
}

#[derive(Clone, Copy)]
pub(super) struct TransportRequest<'a> {
    pub(super) method: &'a str,
    pub(super) path: &'a str,
    pub(super) namespace: &'a str,
    pub(super) body: &'a Value,
}

fn auth_error(error: crate::auth::AuthError) -> Response {
    Response::error(error.status, &error.message)
}
fn sudo_requirement(method: &str, path: &str) -> Option<bool> {
    if matches!(path, "sys/auth" | "sys/auth/") {
        return matches!(method, "GET" | "LIST").then_some(false);
    }
    if path.starts_with("sys/auth/") {
        let (_, tune, route) = crate::auth::control_groups::auth_mount_route(path).ok()?;
        if route != path {
            // The ordinary auth route canonicalizes this suffix internally.
            // Controlled noncanonical suffixes need a separately bound route.
            return None;
        }
        return match (tune, method) {
            (true, "GET" | "POST" | "PUT") | (false, "POST" | "PUT" | "DELETE") => Some(true),
            (false, "GET") => Some(false),
            _ => None,
        };
    }
    if path.starts_with("sys/mounts") {
        return Some(!matches!(method, "GET" | "LIST" | "HEAD"));
    }
    if path == "sys/plugins/reload/backend" {
        return matches!(method, "POST" | "PUT").then_some(true);
    }
    if matches!(path, "sys/remount" | "sys/step-down") {
        return matches!(method, "POST" | "PUT").then_some(true);
    }
    if path.starts_with("sys/policies/acl/") || path.starts_with("sys/policy/") {
        return Some(matches!(method, "POST" | "PUT" | "DELETE"));
    }
    if matches!(
        path,
        "auth/token/lookup-self" | "auth/token/renew-self" | "auth/token/revoke-self"
    ) {
        return Some(false);
    }
    if matches!(
        path,
        "auth/token/accessors" | "auth/token/tidy" | "auth/token/revoke-orphan"
    ) {
        return Some(true);
    }
    if !path.starts_with("sys/") && !path.starts_with("auth/") {
        return Some(false);
    }
    // Other auth/system handlers have route-specific or conditional sudo.
    // A controlled action on those routes fails closed until that metadata is
    // shared with its actual handler; grants alone never select a sudo factor.
    None
}
fn capability(state: &State, request: &RequestView<'_>) -> &'static str {
    operation_capability(
        state,
        request.namespace,
        request.method,
        request.path,
        request.body,
    )
}
fn operation_capability(
    state: &State,
    namespace: &str,
    method: &str,
    path: &str,
    body: &Value,
) -> &'static str {
    if matches!(path, "sys/auth" | "sys/auth/") {
        return "read";
    }
    if path.starts_with("sys/auth/") && crate::auth::control_groups::auth_mount_route(path).is_ok()
    {
        return if method == "GET" { "read" } else { "update" };
    }
    state
        .engines
        .required_capability(namespace, kv_authorization_method(method, body), path)
        .unwrap_or(match kv_authorization_method(method, body) {
            "GET" | "HEAD" => "read",
            "LIST" => "list",
            "SCAN" => "scan",
            "DELETE" => "delete",
            "PATCH" => "patch",
            _ => "update",
        })
}
fn selected_policy(
    state: &State,
    actor: &Principal,
    request: &RequestView<'_>,
    time: AuthorityTime,
) -> Result<Option<(PolicyControl, bool)>, Response> {
    let cap = capability(state, request);
    let required = sudo_requirement(request.method, request.path);
    let policy = state
        .auth
        .control_group_policy_with_sudo(
            actor,
            request.namespace,
            request.path,
            cap,
            required.unwrap_or(true),
            time,
        )
        .map_err(auth_error)?;
    let Some(policy) = policy else {
        return Ok(None);
    };
    let required = required.ok_or_else(|| {
        Response::error(
            400,
            "controlled action requires unsupported route-specific sudo classification",
        )
    })?;
    Ok(Some((policy, required)))
}
fn authorize_action(
    state: &State,
    actor: &Principal,
    request: &RequestView<'_>,
    cap: &str,
    requires_sudo: bool,
    time: AuthorityTime,
) -> Result<(), Response> {
    state
        .auth
        .authorize_request_observed(actor, request.namespace, request.path, cap, time)
        .map_err(auth_error)?;
    if requires_sudo {
        state
            .auth
            .authorize_request_observed(actor, request.namespace, request.path, "sudo", time)
            .map_err(auth_error)?;
    }
    state
        .auth
        .authorize_request_parameters_observed(
            actor,
            request.namespace,
            kv_authorization_method(request.method, request.body),
            request.path,
            request.body,
            time,
        )
        .map_err(auth_error)
}
fn validate_transport(state: &State, owner: &DeferredRequest) -> Result<(), Response> {
    let invalid = || Response::error(503, "control group transport ownership mismatch");
    let method = owner.transport_method.as_str();
    let path = owner.transport_path.as_str();
    let body = &owner.transport_body;
    let transport_namespace = owner.transport_namespace.as_str();
    if !valid_namespace(transport_namespace)
        || (!valid_path(path)
            && !crate::http::ocsp::opaque_get_request(method, path, body)
            && !crate::http::ocsp::opaque_header_request(method, path, body))
    {
        return Err(invalid());
    }
    let envelopes = request_normalization::envelopes(method, path, body).map_err(|_| invalid())?;
    let (secret_owner, sdk_auth) = match &owner.resource_binding {
        ResourceBinding::Secret { owner: mount } => {
            if !owner.path.starts_with(mount.path.as_str())
                || !(path.starts_with(mount.path.as_str())
                    || mount
                        .kv_root(kv_authorization_method(method, envelopes.body), path)
                        .is_some())
            {
                return Err(invalid());
            }
            (Some(mount), false)
        }
        ResourceBinding::Auth {
            path: mount,
            query_owner,
            ..
        } => {
            if *query_owner && !path.starts_with(&format!("auth/{mount}/")) {
                return Err(invalid());
            }
            (None, *query_owner)
        }
        ResourceBinding::System => (None, false),
    };
    let kv_root = secret_owner
        .and_then(|owner| owner.kv_root(kv_authorization_method(method, envelopes.body), path));
    let normalized = request_normalization::operation_with_owner(
        secret_owner,
        sdk_auth,
        method,
        kv_root.as_deref().unwrap_or(path),
        path,
        envelopes.body,
    )
    .map_err(|_| invalid())?;
    let logical_body = workflows::input::reconstruct(owner.logical_data.as_ref(),
        &normalized.method,&normalized.path,&normalized.body.0).map_err(|_| invalid())?;
    let canonical_body = logical_body.as_ref().map_or(&normalized.body.0, |value| &value.0);
    let namespace =
        request_normalization::token_namespace(&normalized.path, Some(owner.namespace.as_str()))
            .unwrap_or(transport_namespace);
    if transport_namespace != owner.namespace
        || namespace != owner.namespace
        || normalized.method != owner.method
        || normalized.path != owner.path
        || *canonical_body != owner.body
    {
        return Err(invalid());
    }
    let cap = operation_capability(
        state,
        namespace,
        &normalized.method,
        &normalized.path,
        canonical_body,
    );
    // Concurrent KV existence changes may make an original create/update
    // owner inert. Preserve that record, then require exact current capability
    // before claim. The generic/system fallback is always bound exactly.
    let dynamic_kv_pair = secret_owner
        .is_some_and(|mount| mount.kind == crate::engines::QueryKind::Kv)
        && matches!(
            kv_authorization_method(&normalized.method, canonical_body),
            "POST" | "PUT"
        )
        && matches!(cap, "create" | "update")
        && matches!(owner.capability.as_str(), "create" | "update");
    if (cap != owner.capability && !dynamic_kv_pair)
        || sudo_requirement(&normalized.method, &normalized.path) != Some(owner.requires_sudo)
    {
        return Err(invalid());
    }
    Ok(())
}
impl State {
    pub(super) fn validate_control_group_transports(&self) -> Result<(), Response> {
        for owner in self.auth.control_group_owners() {
            validate_transport(self, owner)?;
        }
        Ok(())
    }
}
fn resource_binding(
    state: &State,
    namespace: &str,
    path: &str,
) -> Result<ResourceBinding, Response> {
    if let Some(binding) = state
        .auth
        .control_group_auth_mount_binding(namespace, path)
        .map_err(auth_error)?
    {
        return Ok(binding);
    }
    if path.starts_with("sys/auth/") {
        let (mount, _, _) =
            crate::auth::control_groups::auth_mount_route(path).map_err(auth_error)?;
        if let Ok(accessor) = state.auth.mount_accessor(namespace, mount) {
            return Ok(ResourceBinding::Auth {
                path: mount.to_owned(),
                accessor,
                query_owner: false,
            });
        }
    }
    Ok(state
        .engines
        .query_owner(namespace, path)
        .map_or(ResourceBinding::System, |owner| ResourceBinding::Secret {
            owner,
        }))
}

fn resolved_factors(
    state: &State,
    namespace: &str,
    policy: &PolicyControl,
) -> Result<Vec<ResolvedFactor>, Response> {
    policy
        .factors
        .iter()
        .map(|f| {
            let group_ids = state
                .engines
                .control_group_ids(namespace, &f.group_ids, &f.group_names)
                .map_err(Response::from_engine_error)?;
            Ok(ResolvedFactor {
                name: f.name.clone(),
                group_ids,
                approvals: f.approvals,
                self_authorization: f.self_authorization,
            })
        })
        .collect()
}
fn namespace_id(state: &State, namespace: &str) -> Result<String, Response> {
    Ok(state
        .namespaces
        .identity_namespace(namespace)?
        .id
        .unwrap_or("root")
        .to_owned())
}
fn entity(state: &State, namespace: &str, id: &str) -> Result<Value, Response> {
    let namespace_id = namespace_id(state, namespace)?;
    state
        .engines
        .control_group_entity(namespace, id, &namespace_id, |accessor| {
            state.auth.control_group_mount_type(namespace, accessor)
        })
        .map_err(Response::from_engine_error)
}
fn eligible(state: &State, owner: &DeferredRequest, factor: &ResolvedFactor, id: &str) -> bool {
    if !factor.self_authorization && id == owner.actor_entity_id {
        return false;
    }
    state
        .engines
        .identity_projection(&owner.namespace, id)
        .is_ok_and(|p| {
            !p.disabled && p.entity_id == id && !p.group_ids.is_disjoint(&factor.group_ids)
        })
}
fn approval_live(
    state: &State,
    owner: &DeferredRequest,
    approval: &Approval,
    time: AuthorityTime,
) -> bool {
    let Ok(mut actor) = state
        .auth
        .control_group_approval_actor(owner, approval, time)
    else {
        return false;
    };
    Service::bind_identity_principal(state, &mut actor, &owner.namespace).is_ok()
        && state
            .auth
            .authorize_request_observed(
                &actor,
                &owner.namespace,
                "sys/control-group/authorize",
                "update",
                time,
            )
            .is_ok()
        && state
            .auth
            .authorize_request_parameters_observed(
                &actor,
                &owner.namespace,
                "POST",
                "sys/control-group/authorize",
                &json!({"accessor":approval.request_accessor}),
                time,
            )
            .is_ok()
}
fn approved(state: &State, owner: &DeferredRequest, time: AuthorityTime) -> bool {
    owner.factors.iter().all(|factor| {
        owner
            .authorizations
            .values()
            .filter(|a| {
                approval_live(state, owner, a, time) && eligible(state, owner, factor, &a.entity_id)
            })
            .count()
            >= factor.approvals
    })
}
fn review(state: &State, owner: &DeferredRequest, time: AuthorityTime) -> Value {
    let authorizations = owner
        .authorizations
        .values()
        .filter(|a| {
            approval_live(state, owner, a, time)
                && owner
                    .factors
                    .iter()
                    .any(|f| eligible(state, owner, f, &a.entity_id))
        })
        .map(|a| json!({"entity_id":a.entity_id,"entity_name":a.entity_name}))
        .collect::<Vec<_>>();
    json!({"approved":approved(state, owner, time),"authorizations":authorizations,
        "request_data":owner.body,"request_entity":owner.actor_entity,
        "request_operation":match owner.capability.as_str() { "create" => "update", other => other },
        "request_path":owner.path})
}
fn wrapping_raw<'a>(request: &'a RequestView<'a>) -> Result<&'a str, Response> {
    let object = request
        .body
        .as_object()
        .ok_or_else(|| Response::error(400, "wrapping request requires an object"))?;
    if object.keys().any(|k| k != "token") {
        return Err(Response::error(400, "unsupported wrapping parameter"));
    }
    match object.get("token") {
        None => Ok(request.token),
        Some(Value::String(token)) if !token.is_empty() => Ok(token),
        _ => Err(Response::error(
            400,
            "wrapping token must be a nonempty string",
        )),
    }
}
impl Service {
    pub(super) fn control_group_preflight(
        state: &State,
        request: &RequestView<'_>,
    ) -> Option<Response> {
        let body_token = request
            .body
            .get("token")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !state.auth.is_control_group_token(request.token)
            && !state.auth.is_control_group_token(body_token)
        {
            return None;
        }
        if state.auth.is_control_group_token(request.token) && request.body.get("token").is_some() {
            return Some(Response::error(
                400,
                "wrapping token cannot also be supplied in the body",
            ));
        }
        let raw = match wrapping_raw(request) {
            Ok(raw) => raw,
            Err(error) => return Some(error),
        };
        let target_time = match request.token_time().and_then(|time| {
            state
                .auth
                .control_group_authority_time(time)
                .map_err(auth_error)
        }) {
            Ok(time) => time,
            Err(error) => return Some(error),
        };
        match state
            .auth
            .control_group_target_observed(raw, request.namespace, target_time)
        {
            Ok(None) => None,
            Err(error) => Some(auth_error(error)),
            Ok(Some(owner)) => {
                let time = match request.token_time().and_then(|time| {
                    state
                        .auth
                        .control_group_authority_time(time)
                        .map_err(auth_error)
                }) {
                    Ok(time) => time,
                    Err(error) => return Some(error),
                };
                if approved(state, owner, time) {
                    // A live quorum cannot renew an expired requester. Reject
                    // before authenticating the one-use wrapping token so a
                    // failed resume keeps the deferred owner reviewable.
                    match state.auth.control_group_actor(owner,time) {
                        Err(error) => Some(auth_error(error)),
                        Ok(actor) => {
                            if owner.logical_data.is_some() {
                                if let Err(error) = Self::validate_control_group_scope(state,owner)
                                    .and_then(|_| workflows::input::live(state,&owner.namespace,owner.logical_data.as_ref()))
                                    .and_then(|_| workflows::input::authorize_owner_input(state,&actor,owner,time)) {
                                    return Some(error);
                                }
                            }
                            None
                        }
                    }
                } else {
                    Some(Response::error(
                        400,
                        "control group authorization is not complete",
                    ))
                }
            }
        }
    }
    pub(super) fn control_group_transactional_step_guard(
        state: &State,
        actor: &Principal,
        outer: &RequestView<'_>,
        transport: TransportRequest<'_>,
    ) -> Result<(), Response> {
        if !state.auth.has_control_group_state() {
            return Ok(());
        }
        let step = RequestView {
            method: transport.method,
            path: transport.path,
            body: transport.body,
            namespace: outer.namespace,
            token: outer.token,
            now: outer.now,
            admission_started: outer.admission_started,
            token_clock: outer.token_clock,
            allow_forward: false,
            enforce_namespace: outer.enforce_namespace,
            wrap_ttl_seconds: None,
            origin_peer: outer.origin_peer,
            client_certificates: outer.client_certificates,
        };
        let time = state
            .auth
            .control_group_authority_time(step.token_time()?)
            .map_err(auth_error)?;
        let cap = capability(state, &step);
        if let Some((_, requires_sudo)) = selected_policy(state, actor, &step, time)? {
            authorize_action(state, actor, &step, cap, requires_sudo, time)?;
            // The workflow's outer approval cannot stand in for a separately
            // controlled inner action. No step-specific durable owner exists yet.
            return Err(Response::error(
                400,
                "controlled workflow steps are not supported",
            ));
        }
        Ok(())
    }
    pub(super) fn control_group_publish(&mut self, admitted: &mut State) -> Result<(), Response> {
        admitted.schema = admitted.writer_schema();
        self.commit_state(admitted)?;
        // Installation follows the same namespace view boundary as other
        // durable authentication admission, without an independent side store.
        let mut committed = admitted.clone();
        committed.namespace_protected = admitted.namespace_protected.clone();
        let installed = self.install_committed_namespace_view(committed);
        self.state = Some(installed);
        Ok(())
    }
    pub(super) fn control_group_route(
        &mut self,
        admitted: &mut State,
        principal: Option<&Principal>,
        request: &RequestView<'_>,
        transport: TransportRequest<'_>,
        resumed: bool,
    ) -> Option<Response> {
        let result =
            self.control_group_route_inner(admitted, principal, request, transport, resumed);
        match result {
            Ok(result) => result,
            Err(error) => Some(error),
        }
    }
    fn control_group_route_inner(
        &mut self,
        admitted: &mut State,
        principal: Option<&Principal>,
        request: &RequestView<'_>,
        transport: TransportRequest<'_>,
        resumed: bool,
    ) -> Result<Option<Response>, Response> {
        let time = admitted
            .auth
            .control_group_authority_time(request.token_time()?)
            .map_err(auth_error)?;
        if admitted
            .auth
            .advance_control_group_observed(time)
            .map_err(auth_error)?
        {
            self.control_group_publish(admitted)?;
        }
        // Persistence does not re-anchor the outer clock. Capture its elapsed
        // observation again before any live approval/request authority checks.
        let time = admitted
            .auth
            .control_group_authority_time(request.token_time()?)
            .map_err(auth_error)?;
        let now = time.seconds();

        let namespace = request.namespace;
        let path = request.path;
        if matches!(
            path,
            "sys/control-group/request" | "sys/control-group/authorize"
        ) {
            if !matches!(request.method, "POST" | "PUT") {
                return Ok(Some(Response::error(405, "method not allowed")));
            }
            let actor = principal.ok_or_else(|| Response::error(403, "missing client token"))?;
            admitted
                .auth
                .authorize_request_observed(actor, namespace, path, "update", time)
                .map_err(auth_error)?;
            let object = request
                .body
                .as_object()
                .ok_or_else(|| Response::error(400, "control group request requires an object"))?;
            if object.keys().any(|k| k != "accessor") {
                return Err(Response::error(400, "unsupported control group parameter"));
            }
            let accessor = object
                .get("accessor")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty() && v.len() <= 256)
                .ok_or_else(|| Response::error(400, "accessor is required"))?;
            let owner = admitted
                .auth
                .control_group_by_accessor(accessor, namespace, time)
                .map_err(auth_error)?
                .clone();
            Self::validate_control_group_scope(admitted, &owner)?;
            if path == "sys/control-group/authorize" {
                let (token_digest, token_accessor, entity_id) = admitted
                    .auth
                    .control_group_actor_binding(actor)
                    .map_err(auth_error)?;
                let identity = entity(admitted, namespace, &entity_id)?;
                if !owner
                    .factors
                    .iter()
                    .any(|f| eligible(admitted, &owner, f, &entity_id))
                {
                    if entity_id == owner.actor_entity_id {
                        return Err(Response::error(
                            500,
                            "self authorization is not allowed for this request",
                        ));
                    }
                    return Ok(Some(Response {
                        unwrapped_json: None,
                        response_headers: Default::default(),
                        consistency_index: None,
                        status: 200,
                        body: json!({"data":{"approved":approved(admitted, &owner, time)}}),
                    }));
                }
                let entity_name = identity["name"]
                    .as_str()
                    .ok_or_else(|| Response::error(503, "control group entity name unavailable"))?
                    .to_owned();
                let approval = admitted
                    .auth
                    .capture_control_group_approval(
                        &owner,
                        Approval {
                            entity_id,
                            entity_name,
                            token_digest,
                            token_accessor,
                            request_accessor: accessor.to_owned(),
                            origin_peer: request.origin_peer,
                            credential: None,
                        },
                        actor,
                        request.token,
                        time,
                    )
                    .map_err(auth_error)?;
                admitted
                    .auth
                    .control_group_authorize(accessor, namespace, time, approval)
                    .map_err(auth_error)?;
                self.control_group_publish(admitted)?;
                let owner = admitted
                    .auth
                    .control_group_by_accessor(accessor, namespace, time)
                    .map_err(auth_error)?;
                return Ok(Some(Response {
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                    status: 200,
                    body: json!({"data":{"approved":approved(admitted, owner, time)}}),
                }));
            }
            return Ok(Some(Response {
                unwrapped_json: None,
                response_headers: Default::default(),
                consistency_index: None,
                status: 200,
                body: json!({"data":review(admitted, &owner, time)}),
            }));
        }
        if path == "sys/wrapping/unwrap" {
            let body_token = request
                .body
                .get("token")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !admitted.auth.is_control_group_token(request.token)
                && !admitted.auth.is_control_group_token(body_token)
            {
                return Ok(None);
            }
            let raw = wrapping_raw(request)?;
            if let Some(owner) = admitted
                .auth
                .control_group_admitted_target(raw, namespace, time)
                .map_err(auth_error)?
                .cloned()
            {
                if !matches!(request.method, "POST" | "PUT") {
                    return Err(Response::error(405, "method not allowed"));
                }
                let caller =
                    principal.ok_or_else(|| Response::error(403, "missing client token"))?;
                admitted
                    .auth
                    .authorize_request_observed(caller, namespace, path, "update", time)
                    .map_err(auth_error)?;
                if admitted.auth.is_control_group_token(request.token)
                    && request.body.get("token").is_some()
                {
                    return Err(Response::error(
                        400,
                        "wrapping token cannot also be supplied in the body",
                    ));
                }
                Self::validate_control_group_scope(admitted, &owner)?;
                if !approved(admitted, &owner, time) {
                    return Err(Response::error(
                        400,
                        "control group authorization is not complete",
                    ));
                }
                let mut actor = admitted
                    .auth
                    .control_group_actor(&owner, time)
                    .map_err(auth_error)?;
                actor.bind_request_wrapping_ttl(owner.wrap_ttl_seconds);
                Self::bind_identity_principal(admitted, &mut actor, namespace)?;
                let action = RequestView {
                    method: &owner.method,
                    path: &owner.path,
                    namespace: &owner.namespace,
                    body: &owner.body,
                    ..*request
                };
                authorize_action(
                    admitted,
                    &actor,
                    &action,
                    &owner.capability,
                    owner.requires_sudo,
                    time,
                )?;
                let (policy, requires_sudo) = selected_policy(admitted, &actor, &action, time)?
                    .ok_or_else(|| Response::error(403, "control group policy has changed"))?;
                if requires_sudo != owner.requires_sudo {
                    return Err(Response::error(
                        403,
                        "control group sudo ownership has changed",
                    ));
                }
                if policy.duration().map_err(auth_error)? != owner.duration().map_err(auth_error)?
                    || resolved_factors(admitted, namespace, &policy)? != owner.factors
                {
                    return Err(Response::error(403, "control group factors have changed"));
                }
                // Check the current logical create/update classification too.
                if capability(admitted, &action) != owner.capability {
                    return Err(Response::error(
                        403,
                        "control group operation ownership has changed",
                    ));
                }
                workflows::input::live(admitted,&owner.namespace,owner.logical_data.as_ref())?;
                workflows::input::authorize_owner_input(admitted,&actor,&owner,time)?;
                let echo = admitted
                    .auth
                    .control_group_echo(&owner)
                    .map_err(auth_error)?;
                let owner = admitted
                    .auth
                    .claim_control_group(raw, namespace, time)
                    .map_err(auth_error)?;
                self.control_group_publish(admitted)?;
                // Only this private affine Principal can resume a claimed owner.
                // Preserve the outer deadline/clock and keep sealed raw custody out of transport.
                let resumed = RequestView {
                    method: &owner.transport_method,
                    path: &owner.transport_path,
                    namespace: &owner.transport_namespace,
                    token: "",
                    body: &owner.transport_body,
                    now,
                    admission_started: request.admission_started,
                    token_clock: request.token_clock,
                    allow_forward: false,
                    enforce_namespace: true,
                    wrap_ttl_seconds: owner.wrap_ttl_seconds,
                    origin_peer: owner.origin_peer,
                    client_certificates: owner.client_certificates.as_deref(),
                };
                let _logical_data = crate::request_metadata::Scope::enter(owner.logical_data.clone(),
                    resumed.method,resumed.path,resumed.namespace,resumed.body)
                    .map_err(|error| Response::error(503,error))?;
                return Ok(Some(self.handle_inner_control_group(
                    resumed,
                    Some(ControlGroupResume { actor, echo }),
                )));
            }
            return Ok(None);
        }
        if resumed || path.starts_with("sys/wrapping/") || path.starts_with("sys/control-group/") {
            return Ok(None);
        }
        let Some(actor) = principal else {
            return Ok(None);
        };
        let cap = capability(admitted, request);
        let Some((policy, requires_sudo)) = selected_policy(admitted, actor, request, time)? else {
            return Ok(None);
        };
        // Ordinary self-token routing may select the authenticated token's
        // namespace. A durable controlled request must also originate in that
        // exact namespace; a root or sibling header cannot acquire its owner.
        if transport.namespace != namespace {
            return Err(Response::error(
                403,
                "control group request namespace mismatch",
            ));
        }
        authorize_action(admitted, actor, request, cap, requires_sudo, time)?;

        // Structural self-route validation precedes durable deferral.
        if path == "auth/token/lookup-self" {
            if !matches!(request.method, "GET" | "POST") {
                return Err(Response::error(405, "method not allowed"));
            }
            crate::auth::control_groups::validate_self_echo_request(actor, path, request.body)
                .map_err(auth_error)?;
        } else if path == "auth/token/renew-self" {
            if !matches!(request.method, "POST" | "PUT") {
                return Err(Response::error(405, "method not allowed"));
            }
            crate::auth::control_groups::validate_self_echo_request(actor, path, request.body)
                .map_err(auth_error)?;
        }
        let (actor_digest, actor_accessor, actor_entity_id) = admitted
            .auth
            .control_group_actor_binding(actor)
            .map_err(auth_error)?;
        let actor_entity = entity(admitted, namespace, &actor_entity_id)?;
        let factors = resolved_factors(admitted, namespace, &policy)?;
        let namespace_id = namespace_id(admitted, namespace)?;
        let namespace_incarnation = admitted
            .namespaces
            .incarnation(namespace)
            .ok_or_else(|| Response::error(404, "namespace not found"))?;
        let precision = policy
            .precise_ttl
            .map(|ttl| crate::auth::control_groups::Precision::capture(time, ttl))
            .transpose()
            .map_err(auth_error)?;
        let expires_at = match precision {
            Some(precision) => precision.expires_at.ceil_seconds().map_err(|_| {
                Response::error(400, "control group TTL overflows precise timestamp")
            })?,
            None => now
                .checked_add(policy.ttl)
                .ok_or_else(|| Response::error(400, "control group TTL overflows timestamp"))?,
        };
        let owner = DeferredRequest {
            cluster_id: admitted.cluster_id.clone(),
            namespace: namespace.to_owned(),
            namespace_id,
            namespace_incarnation,
            resource_binding: resource_binding(admitted, namespace, path)?,
            actor_digest,
            actor_accessor,
            actor_entity_id,
            actor_entity,
            request_accessor: String::new(),
            credential: None,
            method: request.method.to_owned(),
            path: path.to_owned(),
            capability: cap.to_owned(),
            requires_sudo,
            body: request.body.clone(),
            transport_method: transport.method.to_owned(),
            transport_path: transport.path.to_owned(),
            transport_namespace: transport.namespace.to_owned(),
            transport_body: transport.body.clone(),
            logical_data: crate::request_metadata::current(request.method,request.path,namespace,request.body)
                .map_err(|error| Response::error(400,error))?,
            wrap_ttl_seconds: request.wrap_ttl_seconds,
            origin_peer: request.origin_peer,
            client_certificates: request.client_certificates.map(<[Vec<u8>]>::to_vec),
            created_at: now,
            expires_at,
            precision,
            creation_time: precision.map_or_else(
                || crate::engines::timestamp(now),
                |precision| precision.issued_at.rfc3339(),
            ),
            factors,
            authorizations: Default::default(),
        };
        validate_transport(admitted, &owner)?;
        let mut response = admitted
            .auth
            .issue_control_group_admitted(owner, actor, request.token, time)
            .map_err(auth_error)?;
        self.control_group_publish(admitted)?;
        Ok(Some(Response {
            unwrapped_json: None,
            response_headers: Default::default(),
            consistency_index: None,
            status: response.status,
            body: std::mem::take(&mut response.body),
        }))
    }
    fn validate_control_group_scope(
        state: &State,
        owner: &DeferredRequest,
    ) -> Result<(), Response> {
        validate_transport(state, owner)?;
        if state.cluster_id != owner.cluster_id
            || state.namespaces.incarnation(&owner.namespace) != Some(owner.namespace_incarnation)
            || state.namespace_is_sealed(&owner.namespace)
            || resource_binding(state, &owner.namespace, &owner.path)? != owner.resource_binding
        {
            return Err(Response::error(
                403,
                "control group request ownership is unavailable",
            ));
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "service_control_groups_tests.rs"]
mod tests;
