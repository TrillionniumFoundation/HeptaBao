//! Closed namespace-bound KV2 control groups: one affine owner, one native CAS publication.
use super::*;
use crate::auth::control_groups::{DeferredRequest, Precision};
use crate::auth::native_controlgroups_draft::{
    NativeCgAuthBinding, NativeCgAuthDelta, Operation, same_owner,
};
use crate::state_record_root_v6::{OwnerDomain, RecordStateRootV6};
use crate::v6_native_custody::OriginalDeadline;
use control_groups::{
    approved, auth_error, authorize_action, eligible, entity, namespace_id, resolved_factors,
    resource_binding, review, selected_policy, validate_transport, wrapping_raw,
};

#[path = "service_native_controlgroups_read.rs"]
mod read;

fn supported_action(method: &str, capability: &str) -> bool {
    matches!(
        (method, capability),
        ("POST" | "PUT", "create" | "update") | ("GET", "read")
    )
}

// The HTTP parser retains these ordinary transport headers in DataFrame even
// for a direct KV2 request. They do not select a KV2 operation or its input.
// Only this closed route, after exact transport/body equality, may discard
// them. Workflow query/profile data and every other header still require the
// logical-request credential custody that native CG deliberately does not own.
fn only_plain_http_metadata(request: &RequestView<'_>) -> Result<bool, Response> {
    let Some(data) = crate::request_metadata::current(
        request.method,
        request.path,
        request.namespace,
        request.body,
    )
    .map_err(|_| rejected())?
    else {
        return Ok(true);
    };
    data.validate().map_err(|_| rejected())?;
    Ok(data.query.is_empty()
        && data.profile.is_none()
        && data
            .headers
            .keys()
            .all(|name| matches!(name.as_str(), "accept" | "accept-encoding" | "user-agent")))
}

fn rejected() -> Response {
    Response::error(
        503,
        "native control group ownership or delivery unavailable",
    )
}

/// Admission and cold seed both call this. It is the resource half of Auth's
/// closed shape check; unsupported policy/namespace/Auth targets never migrate.
pub(super) fn supported_state(state: &State) -> bool {
    state
        .auth
        .native_v6_control_group_scoped_policy_paths()
        .all(|(namespace, path)| {
            namespaces::native_plain::PlainNamespaceScope::capture(state, namespace).is_ok()
                && state
                    .engines
                    .native_cg_kv2_scoped_data_binding(namespace, path)
                    .is_some()
        })
        && state.auth.control_group_owners().all(|owner| {
            state
                .engines
                .native_cg_kv2_scoped_data_binding(&owner.namespace, &owner.path)
                .is_some()
                && namespaces::native_plain::validate_control_group_scope(state, owner).is_ok()
                && resource_binding(state, &owner.namespace, &owner.path)
                    .is_ok_and(|binding| binding == owner.resource_binding)
                && validate_transport(state, owner).is_ok()
        })
}

fn reply_digest(
    status: u16,
    body: &Value,
    deadline: OriginalDeadline,
) -> Result<[u8; 32], Response> {
    use sha2::{Digest, Sha256};
    struct Sink {
        deadline: OriginalDeadline,
        hash: Sha256,
    }
    impl std::io::Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.deadline
                .check()
                .map_err(|_| std::io::Error::other("original CG deadline expired"))?;
            self.hash.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    deadline.check().map_err(|_| rejected())?;
    let mut sink = Sink {
        deadline,
        hash: Sha256::new(),
    };
    serde_json::to_writer(&mut sink, &(status, body)).map_err(|_| rejected())?;
    deadline.check().map_err(|_| rejected())?;
    Ok(sink.hash.finalize().into())
}

fn action_view<'a>(
    owner: &'a DeferredRequest,
    clock: RequestClock,
    time: AuthorityTime,
) -> RequestView<'a> {
    RequestView {
        method: &owner.method,
        path: &owner.path,
        namespace: &owner.namespace,
        token: "",
        body: &owner.body,
        now: time.seconds(),
        admission_started: clock.started(),
        token_clock: Some(clock),
        allow_forward: false,
        enforce_namespace: true,
        wrap_ttl_seconds: None,
        origin_peer: owner.origin_peer,
        client_certificates: owner.client_certificates.as_deref(),
    }
}

// The same original Principal is refreshed in place. The original capability
// is never reclassified after the candidate has created/updated the KV key.
fn check_action(
    state: &State,
    owner: &DeferredRequest,
    actor: &mut Principal,
    clock: RequestClock,
    quorum: bool,
) -> Result<(), Response> {
    namespaces::native_plain::validate_control_group_scope(state, owner)?;
    let time = state
        .auth
        .control_group_authority_time(
            clock
                .observed_at()
                .map(AuthorityTime::Precise)
                .map_err(|_| rejected())?,
        )
        .map_err(auth_error)?;
    if owner.logical_data.is_some()
        || owner.credential.is_some()
        || owner.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0)
        || owner.requires_sudo
        || !supported_action(&owner.method, &owner.capability)
        || state
            .engines
            .native_cg_kv2_scoped_data_binding(&owner.namespace, &owner.path)
            .is_none()
    {
        return Err(Response::error(501, "unsupported native controlled action"));
    }
    let original = actor.original_request_clock().ok_or_else(rejected)?;
    if original.started() != clock.started() || original.admitted_at() != clock.admitted_at() {
        return Err(rejected());
    }
    let (digest, accessor, id) = state
        .auth
        .control_group_actor_binding(actor)
        .map_err(auth_error)?;
    if digest != owner.actor_digest
        || accessor != owner.actor_accessor
        || id != owner.actor_entity_id
    {
        return Err(rejected());
    }
    Service::bind_identity_principal(state, actor, &owner.namespace)?;
    if entity(state, &owner.namespace, &id)? != owner.actor_entity {
        return Err(Response::error(
            403,
            "control group requester identity changed",
        ));
    }
    let action = action_view(owner, clock, time);
    authorize_action(state, actor, &action, &owner.capability, false, time)?;
    let policy = state
        .auth
        .control_group_policy_with_sudo(
            actor,
            &owner.namespace,
            &owner.path,
            &owner.capability,
            false,
            time,
        )
        .map_err(auth_error)?
        .ok_or_else(|| Response::error(403, "control group policy changed"))?;
    if policy.duration().map_err(auth_error)? != owner.duration().map_err(auth_error)?
        || resolved_factors(state, &owner.namespace, &policy)? != owner.factors
        || quorum && !approved(state, owner, time)
    {
        return Err(Response::error(
            403,
            "control group factors or live quorum changed",
        ));
    }
    Ok(())
}

enum DeliveryKind {
    Defer {
        actor: Principal,
        owner: DeferredRequest,
        raw: Zeroizing<String>,
    },
    Review {
        actor: Principal,
        owner: DeferredRequest,
    },
    Authorize {
        actor: Principal,
        owner: DeferredRequest,
        eligible: bool,
    },
    Execute {
        caller: Principal,
        inner: ordinary_kv_delivery::OrdinaryKvAuthority,
        owner: Box<DeferredRequest>,
    },
    ReadExecute {
        caller: Principal,
        read: Box<read::NativeCgReadOwner>,
        owner: Box<DeferredRequest>,
    },
}

pub(super) struct NativeCgDelivery {
    kind: DeliveryKind,
    clock: RequestClock,
    deadline: OriginalDeadline,
    cluster: String,
    activation: String,
    data_dir: PathBuf,
    ha: Option<Arc<Mutex<HaProcess>>>,
    checkpoint: Option<(
        crate::state_record_root::StateIdentity,
        plugin::PublicationGeneration,
    )>,
    proof: Option<native_v6_reader::NativeProof>,
    reply: [u8; 32],
    audited: Option<String>,
}

impl NativeCgDelivery {
    fn capture(
        service: &Service,
        kind: DeliveryKind,
        clock: RequestClock,
        response: &Response,
    ) -> Result<Self, Response> {
        let deadline = OriginalDeadline::capture().map_err(|_| rejected())?;
        let state = service.state.as_ref().ok_or_else(rejected)?;
        Ok(Self {
            kind,
            clock,
            deadline,
            cluster: state.cluster_id.clone(),
            activation: service.unseal_nonce.clone(),
            data_dir: service.data_dir.clone(),
            ha: service.ha.clone(),
            checkpoint: None,
            proof: None,
            reply: reply_digest(response.status, &response.body, deadline)?,
            audited: None,
        })
    }
    fn current(
        service: &mut Service,
    ) -> Result<
        (
            crate::state_record_root::StateIdentity,
            plugin::PublicationGeneration,
        ),
        Response,
    > {
        Ok((
            service.current_state_identity()?,
            service.external_effect_generation()?,
        ))
    }
    fn environment(&self, service: &mut Service) -> Result<(), Response> {
        self.deadline.check().map_err(|_| rejected())?;
        if service.recovery_required
            || service.audit_failed
            || service.native_root.is_none()
            || service.unseal_nonce != self.activation
            || service.data_dir != self.data_dir
            || service
                .state
                .as_ref()
                .is_none_or(|s| s.cluster_id != self.cluster)
            || self.checkpoint.as_ref() != Some(&Self::current(service)?)
        {
            return Err(rejected());
        }
        match (&self.ha, &service.ha) {
            (None, None) => {}
            #[cfg(feature = "native-v6-ha")]
            (Some(a), Some(b)) if Arc::ptr_eq(a, b) => {}
            _ => return Err(rejected()),
        }
        service
            .durable
            .as_mut()
            .ok_or_else(rejected)?
            .verify_live_ownership()
            .map_err(|_| rejected())?;
        self.check_read_root(service.native_root.as_ref().ok_or_else(rejected)?)?;
        self.deadline.check().map_err(|_| rejected())
    }
    fn check_read_root(&self, root: &RecordStateRootV6) -> Result<(), Response> {
        match &self.kind {
            DeliveryKind::ReadExecute { read, .. } => read.check_root(root),
            _ => Ok(()),
        }
    }
    fn check_live(&mut self, state: &State) -> Result<(), Response> {
        self.deadline.check().map_err(|_| rejected())?;
        let time = state
            .auth
            .control_group_authority_time(
                self.clock
                    .observed_at()
                    .map(AuthorityTime::Precise)
                    .map_err(|_| rejected())?,
            )
            .map_err(auth_error)?;
        match &mut self.kind {
            DeliveryKind::Defer { owner, .. }
            | DeliveryKind::Review { owner, .. }
            | DeliveryKind::Authorize { owner, .. } => {
                namespaces::native_plain::validate_control_group_scope(state, owner)?;
            }
            DeliveryKind::Execute { owner, .. } | DeliveryKind::ReadExecute { owner, .. } => {
                namespaces::native_plain::validate_control_group_scope(state, owner)?;
            }
        }
        match &mut self.kind {
            DeliveryKind::Defer { actor, owner, raw } => {
                check_action(state, owner, actor, self.clock, false)?;
                state
                    .auth
                    .control_group_target_observed(raw, &owner.namespace, time)
                    .map_err(auth_error)?
                    .filter(|actual| actual.request_accessor == owner.request_accessor)
                    .filter(|actual| same_owner(actual, owner).unwrap_or(false))
                    .ok_or_else(rejected)?;
            }
            DeliveryKind::Review { actor, owner } => {
                Service::bind_identity_principal(state, actor, &owner.namespace)?;
                state
                    .auth
                    .authorize_request_observed(
                        actor,
                        &owner.namespace,
                        "sys/control-group/request",
                        "update",
                        time,
                    )
                    .map_err(auth_error)?;
                let actual = state
                    .auth
                    .control_group_by_accessor(&owner.request_accessor, &owner.namespace, time)
                    .map_err(auth_error)?;
                if !same_owner(actual, owner).map_err(auth_error)? {
                    return Err(rejected());
                }
                if reply_digest(
                    200,
                    &json!({"data":review(state,owner,time)}),
                    self.deadline,
                )? != self.reply
                {
                    return Err(rejected());
                }
            }
            DeliveryKind::Authorize {
                actor,
                owner,
                eligible: was_eligible,
            } => {
                Service::bind_identity_principal(state, actor, &owner.namespace)?;
                state
                    .auth
                    .authorize_request_observed(
                        actor,
                        &owner.namespace,
                        "sys/control-group/authorize",
                        "update",
                        time,
                    )
                    .map_err(auth_error)?;
                let (_, _, id) = state
                    .auth
                    .control_group_actor_binding(actor)
                    .map_err(auth_error)?;
                let now_eligible = owner
                    .factors
                    .iter()
                    .any(|f| eligible(state, owner, f, &id, time));
                if now_eligible != *was_eligible {
                    return Err(rejected());
                }
                let actual = state
                    .auth
                    .control_group_by_accessor(&owner.request_accessor, &owner.namespace, time)
                    .map_err(auth_error)?;
                if !same_owner(actual, owner).map_err(auth_error)? {
                    return Err(rejected());
                }
                if reply_digest(
                    200,
                    &json!({"data":{"approved":approved(state,owner,time)}}),
                    self.deadline,
                )? != self.reply
                {
                    return Err(rejected());
                }
            }
            DeliveryKind::Execute {
                caller,
                inner,
                owner,
            } => {
                Service::bind_identity_principal(state, caller, &owner.namespace)?;
                state
                    .auth
                    .authorize_request_observed(
                        caller,
                        &owner.namespace,
                        "sys/wrapping/unwrap",
                        "update",
                        time,
                    )
                    .map_err(auth_error)?;
                inner.check(state, &state.auth, &self.activation)?;
                if !state.auth.native_cg_claim_is_spent(owner) {
                    return Err(rejected());
                }
                // The inner owner keeps the only original requester. Borrow it
                // in place; never mint a second Principal for post-audit checks.
                inner.check_native_control_group(state, owner, self.clock)?;
            }
            DeliveryKind::ReadExecute {
                caller,
                read,
                owner,
            } => {
                Service::bind_identity_principal(state, caller, &owner.namespace)?;
                state
                    .auth
                    .authorize_request_observed(
                        caller,
                        &owner.namespace,
                        "sys/wrapping/unwrap",
                        "update",
                        time,
                    )
                    .map_err(auth_error)?;
                read.check(state, &state.auth, &self.activation)?;
                if !state.auth.native_cg_claim_is_spent(owner) {
                    return Err(rejected());
                }
                read.check_action(state, owner, self.clock)?;
            }
        }
        self.deadline.check().map_err(|_| rejected())
    }
    fn check_before_auth_publication(&mut self, state: &State) -> Result<(), Response> {
        match &mut self.kind {
            DeliveryKind::Defer { actor, owner, .. } => {
                check_action(state, owner, actor, self.clock, false)
            }
            DeliveryKind::Authorize {
                actor,
                owner,
                eligible: was_eligible,
            } => {
                let time = state
                    .auth
                    .control_group_authority_time(
                        self.clock
                            .observed_at()
                            .map(AuthorityTime::Precise)
                            .map_err(|_| rejected())?,
                    )
                    .map_err(auth_error)?;
                Service::bind_identity_principal(state, actor, &owner.namespace)?;
                state
                    .auth
                    .authorize_request_observed(
                        actor,
                        &owner.namespace,
                        "sys/control-group/authorize",
                        "update",
                        time,
                    )
                    .map_err(auth_error)?;
                let (_, _, id) = state
                    .auth
                    .control_group_actor_binding(actor)
                    .map_err(auth_error)?;
                if owner
                    .factors
                    .iter()
                    .any(|f| eligible(state, owner, f, &id, time))
                    != *was_eligible
                {
                    return Err(rejected());
                }
                Ok(())
            }
            _ => self.check_live(state),
        }
    }
    fn stage(&mut self, service: &mut Service) -> Result<(), Response> {
        self.checkpoint = Some(Self::current(service)?);
        self.environment(service)?;
        self.check_live(service.state.as_ref().ok_or_else(rejected)?)
    }
}

struct NativeCgRootTarget<'a> {
    source: &'a State,
    candidate: &'a State,
    owner: &'a DeferredRequest,
    deadline: OriginalDeadline,
}

fn admit_root(
    prior: &RecordStateRootV6,
    next: &RecordStateRootV6,
    target: Option<NativeCgRootTarget<'_>>,
) -> Result<(), Response> {
    if next.state_schema < prior.state_schema
        || next.reader_floor.minimum_state_schema < prior.reader_floor.minimum_state_schema
        || prior.global_lossless_json_format.is_some()
            && next.global_lossless_json_format != prior.global_lossless_json_format
    {
        return Err(rejected());
    }
    let mut normalized = next.clone();
    normalized.state_schema = prior.state_schema;
    normalized.reader_floor.minimum_state_schema = prior.reader_floor.minimum_state_schema;
    normalized.global_lossless_json_format = prior.global_lossless_json_format;
    let engine_format_changed = match target.as_ref() {
        Some(target) => target
            .source
            .engines
            .native_cg_scoped_metadata_transition(
                &target.candidate.engines,
                &target.owner.namespace,
                &target.owner.path,
                &|| target.deadline.check().is_ok(),
            )
            .ok_or_else(rejected)?,
        None => false,
    };
    for (old, new) in prior.owners.iter().zip(normalized.owners.iter_mut()) {
        if old.domain == new.domain
            && (old.domain == OwnerDomain::Auth
                || engine_format_changed && old.domain == OwnerDomain::Engines)
        {
            *new = old.clone();
        }
    }
    if let Some(target) = target.as_ref() {
        let (mount, incarnation, _) = target
            .source
            .engines
            .native_cg_kv2_scoped_data_binding(&target.owner.namespace, &target.owner.path)
            .ok_or_else(rejected)?;
        let index = prior
            .kv2
            .iter()
            .position(|g| {
                g.scope.namespace == target.owner.namespace
                    && g.scope.mount == mount
                    && g.scope.incarnation == incarnation
            })
            .ok_or_else(rejected)?;
        if normalized.kv2.len() != prior.kv2.len()
            || normalized.kv2[index].scope != prior.kv2[index].scope
        {
            return Err(rejected());
        }
        normalized.kv2[index] = prior.kv2[index].clone();
    }
    if normalized.encode().map_err(|_| rejected())?.as_slice()
        != prior.encode().map_err(|_| rejected())?.as_slice()
    {
        return Err(rejected());
    }
    if let Some(target) = target {
        target.deadline.check().map_err(|_| rejected())?;
    }
    Ok(())
}

impl Service {
    pub(super) fn native_cg_unwrap(&self, state: &State, request: &RequestView<'_>) -> bool {
        self.native_root.is_some()
            && request.path == "sys/wrapping/unwrap"
            && (state.auth.is_control_group_token(request.token)
                || request
                    .body
                    .get("token")
                    .and_then(Value::as_str)
                    .is_some_and(|raw| state.auth.is_control_group_token(raw)))
    }

    pub(super) fn observe_native_cg(&mut self, clock: RequestClock) -> Result<(), Response> {
        let source = self.state.as_ref().cloned().ok_or_else(rejected)?;
        let (delta, auth) = NativeCgAuthDelta::observe(&source.auth, clock).map_err(auth_error)?;
        let mut candidate = source.clone();
        candidate.auth = auth.into();
        candidate.schema = candidate.writer_schema();
        candidate.prepare_global_lossless_json_state(Some(&source))?;
        delta
            .check_candidate(&source.auth, &candidate.auth)
            .map_err(auth_error)?;
        let (binding, operation) = delta.into_parts();
        if !matches!(operation, Operation::Observe) {
            return Err(rejected());
        }
        let plan = self.prepare_native_live_root_checked(&candidate, &mut |auth| {
            binding
                .check_candidate(auth, &candidate.auth)
                .map_err(auth_error)
        })?;
        admit_root(
            self.native_root.as_ref().ok_or_else(rejected)?,
            &plan.root,
            None,
        )?;
        if plan.root.identity().map_err(|_| rejected())? != self.current_state_identity()? {
            let installed = self.commit_native_root_plan(
                &candidate,
                plan,
                false,
                "control-group-observe",
                &mut |auth| {
                    binding
                        .check_candidate(auth, &candidate.auth)
                        .map_err(auth_error)
                },
            )?;
            self.state = Some(installed);
        }
        Ok(())
    }

    fn publish_native_cg_auth(
        &mut self,
        source: &State,
        candidate: &State,
        binding: &NativeCgAuthBinding,
        delivery: &mut NativeCgDelivery,
    ) -> Result<(), Response> {
        let mut gate = |auth: &AuthState| {
            binding
                .check_candidate(auth, &candidate.auth)
                .map_err(auth_error)?;
            delivery.check_before_auth_publication(source)
        };
        let plan = self.prepare_native_live_root_checked(candidate, &mut gate)?;
        admit_root(
            self.native_root.as_ref().ok_or_else(rejected)?,
            &plan.root,
            None,
        )?;
        if plan.root.identity().map_err(|_| rejected())? != self.current_state_identity()? {
            let installed = self.commit_native_root_plan(
                candidate,
                plan,
                false,
                "control-group-auth",
                &mut gate,
            )?;
            self.state = Some(installed);
        }
        Ok(())
    }

    pub(super) fn dispatch_native_cg(
        &mut self,
        mut candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
        transport: control_groups::TransportRequest<'_>,
    ) -> Response {
        let run = (|| -> Result<Response, Response> {
            if self.pending_native_cg_delivery.is_some()
                || self.pending_ordinary_kv_authority.is_some()
                || request.token_clock.is_none()
                || request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0)
            {
                return Err(rejected());
            }
            let clock = request.token_clock.ok_or_else(rejected)?;
            let source = self.state.as_ref().cloned().ok_or_else(rejected)?;
            namespaces::native_plain::PlainNamespaceScope::capture(&source, request.namespace)?;
            let actor = principal.ok_or_else(|| Response::error(403, "missing client token"))?;
            let time = source
                .auth
                .control_group_authority_time(request.token_time()?)
                .map_err(auth_error)?;
            if request.path == "sys/wrapping/unwrap" {
                return self.execute_native_cg(source, candidate, actor, request, clock);
            }
            let (response, binding, kind) = if matches!(
                request.path,
                "sys/control-group/request" | "sys/control-group/authorize"
            ) {
                if !matches!(request.method, "POST" | "PUT") {
                    return Err(Response::error(405, "method not allowed"));
                }
                source
                    .auth
                    .authorize_request_observed(
                        &actor,
                        request.namespace,
                        request.path,
                        "update",
                        time,
                    )
                    .map_err(auth_error)?;
                let object = request
                    .body
                    .as_object()
                    .filter(|obj| obj.keys().all(|k| k == "accessor"))
                    .ok_or_else(|| Response::error(400, "unsupported control group parameter"))?;
                let accessor = object
                    .get("accessor")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty() && s.len() <= 256)
                    .ok_or_else(|| Response::error(400, "accessor required"))?;
                let owner = source
                    .auth
                    .control_group_by_accessor(accessor, request.namespace, time)
                    .map_err(auth_error)?
                    .clone();
                namespaces::native_plain::validate_control_group_scope(&source, &owner)?;
                if request.path == "sys/control-group/request" {
                    let response = cg_response(json!({"data":review(&source,&owner,time)}));
                    (response, None, DeliveryKind::Review { actor, owner })
                } else {
                    let (_, _, id) = source
                        .auth
                        .control_group_actor_binding(&actor)
                        .map_err(auth_error)?;
                    let identity = entity(&source, request.namespace, &id)?;
                    let allowed = owner
                        .factors
                        .iter()
                        .any(|f| eligible(&source, &owner, f, &id, time));
                    if !allowed {
                        if id == owner.actor_entity_id {
                            return Err(Response::error(
                                500,
                                "1 error occurred:\n\t* token owner cannot be approver\n\n",
                            ));
                        }
                        (
                            cg_response(json!({"data":{"approved":approved(&source,&owner,time)}})),
                            None,
                            DeliveryKind::Authorize {
                                actor,
                                owner,
                                eligible: false,
                            },
                        )
                    } else {
                        let name = identity["name"].as_str().ok_or_else(rejected)?.to_owned();
                        let (delta, auth) = NativeCgAuthDelta::authorize_scoped(
                            &source.auth,
                            clock,
                            actor,
                            request.namespace,
                            accessor,
                            name,
                            request.token,
                        )
                        .map_err(auth_error)?;
                        delta
                            .check_candidate(&source.auth, &auth)
                            .map_err(auth_error)?;
                        candidate.auth = auth.into();
                        let (binding, operation) = delta.into_parts();
                        let Operation::Authorize { actor, .. } = operation else {
                            return Err(rejected());
                        };
                        let owner = candidate
                            .auth
                            .control_group_by_accessor(accessor, request.namespace, time)
                            .map_err(auth_error)?
                            .clone();
                        let response = cg_response(
                            json!({"data":{"approved":approved(&candidate,&owner,time)}}),
                        );
                        (
                            response,
                            Some(binding),
                            DeliveryKind::Authorize {
                                actor,
                                owner,
                                eligible: true,
                            },
                        )
                    }
                }
            } else {
                let (policy, sudo) =
                    selected_policy(&source, &actor, request, time)?.ok_or_else(rejected)?;
                if sudo
                    || !matches!(request.method, "GET" | "POST" | "PUT")
                    || source
                        .engines
                        .native_cg_kv2_scoped_data_binding(request.namespace, request.path)
                        .is_none()
                    || transport.namespace != request.namespace
                    || transport.method != request.method
                    || transport.path != request.path
                    || transport.body != request.body
                    || !only_plain_http_metadata(request)?
                {
                    return Err(Response::error(501, "unsupported native controlled action"));
                }
                let cap = control_groups::capability(&source, request);
                if !supported_action(request.method, cap) {
                    return Err(Response::error(
                        501,
                        "unsupported native controlled capability",
                    ));
                }
                authorize_action(&source, &actor, request, cap, false, time)?;
                let (digest, accessor, id) = source
                    .auth
                    .control_group_actor_binding(&actor)
                    .map_err(auth_error)?;
                let precision = policy
                    .precise_ttl
                    .map(|ttl| Precision::capture(time, ttl))
                    .transpose()
                    .map_err(auth_error)?;
                let expires = match precision {
                    Some(p) => p.expires_at.ceil_seconds().map_err(|_| rejected())?,
                    None => time
                        .seconds()
                        .checked_add(policy.ttl)
                        .ok_or_else(rejected)?,
                };
                let owner = DeferredRequest {
                    cluster_id: source.cluster_id.clone(),
                    namespace: request.namespace.to_owned(),
                    namespace_id: namespace_id(&source, request.namespace)?,
                    namespace_incarnation: source
                        .namespaces
                        .incarnation(request.namespace)
                        .ok_or_else(rejected)?,
                    resource_binding: resource_binding(&source, request.namespace, request.path)?,
                    actor_digest: digest,
                    actor_accessor: accessor,
                    actor_entity_id: id.clone(),
                    actor_entity: entity(&source, request.namespace, &id)?,
                    request_accessor: String::new(),
                    credential: None,
                    method: request.method.to_owned(),
                    path: request.path.to_owned(),
                    capability: cap.to_owned(),
                    requires_sudo: false,
                    body: request.body.clone(),
                    transport_method: transport.method.to_owned(),
                    transport_path: transport.path.to_owned(),
                    transport_namespace: transport.namespace.to_owned(),
                    transport_body: transport.body.clone(),
                    logical_data: None,
                    wrap_ttl_seconds: None,
                    origin_peer: request.origin_peer,
                    client_certificates: request.client_certificates.map(<[Vec<u8>]>::to_vec),
                    created_at: time.seconds(),
                    expires_at: expires,
                    precision,
                    creation_time: precision.map_or_else(
                        || crate::engines::timestamp(time.seconds()),
                        |p| p.issued_at.rfc3339(),
                    ),
                    factors: resolved_factors(&source, request.namespace, &policy)?,
                    authorizations: Default::default(),
                };
                let (delta, auth, mut auth_response) =
                    NativeCgAuthDelta::defer(&source.auth, clock, actor, owner, request.token)
                        .map_err(auth_error)?;
                delta
                    .check_candidate(&source.auth, &auth)
                    .map_err(auth_error)?;
                candidate.auth = auth.into();
                let raw = Zeroizing::new(
                    auth_response.body["wrap_info"]["token"]
                        .as_str()
                        .ok_or_else(rejected)?
                        .to_owned(),
                );
                let accessor = auth_response.body["wrap_info"]["accessor"]
                    .as_str()
                    .ok_or_else(rejected)?;
                let owner = candidate
                    .auth
                    .control_group_by_accessor(accessor, request.namespace, time)
                    .map_err(auth_error)?
                    .clone();
                let response = cg_response(std::mem::take(&mut auth_response.body));
                let (binding, operation) = delta.into_parts();
                let Operation::Defer(actor) = operation else {
                    return Err(rejected());
                };
                (
                    response,
                    Some(binding),
                    DeliveryKind::Defer { actor, owner, raw },
                )
            };
            candidate.schema = candidate.writer_schema();
            candidate.prepare_global_lossless_json_state(Some(&source))?;
            let mut delivery = NativeCgDelivery::capture(self, kind, clock, &response)?;
            let mut response = response;
            let publication = (|| {
                if let Some(binding) = binding.as_ref() {
                    self.publish_native_cg_auth(&source, &candidate, binding, &mut delivery)?;
                }
                delivery.stage(self)
            })();
            if let Err(error) = publication {
                erase_json(&mut response.body);
                return Err(error);
            }
            self.pending_native_cg_delivery = Some(delivery);
            Ok(response)
        })();
        match run {
            Ok(response) => response,
            Err(error) => error,
        }
    }

    fn execute_native_cg(
        &mut self,
        source: State,
        admitted: State,
        caller: Principal,
        request: &RequestView<'_>,
        clock: RequestClock,
    ) -> Result<Response, Response> {
        if !matches!(request.method, "POST" | "PUT") {
            return Err(Response::error(405, "method not allowed"));
        }
        let raw = wrapping_raw(request)?;
        if source.auth.is_control_group_token(request.token) && request.body.get("token").is_some()
        {
            return Err(Response::error(
                400,
                "wrapping token cannot also be supplied in body",
            ));
        }
        let time = source
            .auth
            .control_group_authority_time(request.token_time()?)
            .map_err(auth_error)?;
        let owner = source
            .auth
            .control_group_target_observed(raw, request.namespace, time)
            .map_err(auth_error)?
            .ok_or_else(rejected)?
            .clone();
        let mut requester = source
            .auth
            .control_group_actor(&owner, time)
            .map_err(auth_error)?;
        requester
            .bind_request_clock(Some(clock))
            .map_err(auth_error)?;
        Self::bind_identity_principal(&source, &mut requester, &owner.namespace)?;
        check_action(&source, &owner, &mut requester, clock, true)?;
        if control_groups::capability(&source, &action_view(&owner, clock, time))
            != owner.capability
        {
            return Err(Response::error(
                403,
                "control group operation ownership changed",
            ));
        }
        let (delta, auth, _claimed) = NativeCgAuthDelta::execute_scoped(
            &source.auth,
            &admitted.auth,
            clock,
            caller,
            requester,
            request.namespace,
            raw,
        )
        .map_err(auth_error)?;
        delta
            .check_candidate(&source.auth, &auth)
            .map_err(auth_error)?;
        let (binding, caller, requester, owner) = delta.into_execute_parts().map_err(auth_error)?;
        let mut candidate = admitted;
        candidate.auth = auth.into();
        if owner.method == "GET" {
            return self.execute_native_cg_read(
                read::ReadExecution {
                    source,
                    candidate,
                    caller,
                    requester,
                    owner,
                    binding,
                    clock,
                },
                request,
            );
        }
        let action = action_view(&owner, clock, time);
        let mut inner = ordinary_kv_delivery::OrdinaryKvAuthority::new(
            requester,
            &candidate,
            &action,
            &self.unseal_nonce,
        )?;
        let mut response =
            match self.dispatch_native_paged_outcome(&mut candidate, &mut inner, &action) {
                native_paged_dispatch::NativePagedOutcome::AdmissionRejected(error) => {
                    return Err(error);
                }
                native_paged_dispatch::NativePagedOutcome::Dispatched(response) => response,
            };
        // A completed domain rejection consumes this one approved claim but
        // publishes no partial target mutation. No native append has happened
        // yet; candidate Engine staging is private and can be discarded exactly.
        // An admission/custody rejection above never claims or executes storage.
        if response.status >= 400 {
            candidate.engines = source.engines.clone();
        }
        candidate.schema = candidate.writer_schema();
        candidate.prepare_global_lossless_json_state(Some(&source))?;
        let mut delivery = NativeCgDelivery::capture(
            self,
            DeliveryKind::Execute {
                caller,
                inner,
                owner: Box::new(owner.clone()),
            },
            clock,
            &response,
        )?;
        let nonce = self.unseal_nonce.clone();
        let deadline = delivery.deadline;
        let mut gate = |auth: &AuthState| {
            binding
                .check_candidate(auth, &candidate.auth)
                .map_err(auth_error)?;
            let DeliveryKind::Execute {
                caller,
                inner,
                owner,
            } = &mut delivery.kind
            else {
                return Err(rejected());
            };
            auth.authorize_request_observed(
                caller,
                &owner.namespace,
                "sys/wrapping/unwrap",
                "update",
                request.token_time()?,
            )
            .map_err(auth_error)?;
            inner.check(&candidate, auth, &nonce)?;
            inner.check_native_control_group(&source, owner, clock)
        };
        let plan = self.prepare_native_live_root_checked(&candidate, &mut gate)?;
        admit_root(
            self.native_root.as_ref().ok_or_else(rejected)?,
            &plan.root,
            Some(NativeCgRootTarget {
                source: &source,
                candidate: &candidate,
                owner: &owner,
                deadline,
            }),
        )?;
        let installed = match self.commit_native_root_plan(
            &candidate,
            plan,
            false,
            "control-group-execute",
            &mut gate,
        ) {
            Ok(installed) => installed,
            Err(error) => {
                erase_json(&mut response.body);
                return Err(error);
            }
        };
        self.state = Some(installed);
        delivery.stage(self)?;
        self.pending_native_cg_delivery = Some(delivery);
        Ok(response)
    }

    pub(super) fn native_cg_terminal_deadline(&self) -> Option<Instant> {
        self.pending_native_cg_delivery
            .as_ref()
            .map(|d| d.deadline.instant())
    }
    pub(super) fn check_pending_native_cg_before_terminal(&mut self) -> Result<(), Response> {
        let Some(mut delivery) = self.pending_native_cg_delivery.take() else {
            return Ok(());
        };
        let result = if delivery.proof.is_some() {
            Err(rejected())
        } else {
            delivery
                .environment(self)
                .and_then(|()| delivery.check_live(self.state.as_ref().ok_or_else(rejected)?))
        };
        self.pending_native_cg_delivery = Some(delivery);
        result
    }
    pub(super) fn bind_pending_native_cg_before_audit(
        &mut self,
        receipt: Option<token_precision::TerminalClockReceipt>,
    ) -> Result<(), Response> {
        let Some(mut delivery) = self.pending_native_cg_delivery.take() else {
            return Err(rejected());
        };
        let result = (|| {
            if delivery.proof.is_some() {
                return Err(rejected());
            }
            if let Some(receipt) = receipt {
                receipt.advance_native_cg(&mut delivery.checkpoint)?;
            }
            delivery.environment(self)?;
            let state = self.state.as_ref().cloned().ok_or_else(rejected)?;
            delivery.check_live(&state)?;
            delivery.proof =
                self.capture_native_request_proof(&mut || delivery.check_live(&state))?;
            let proof = delivery.proof.as_ref().ok_or_else(rejected)?;
            if delivery.checkpoint.as_ref()
                != Some(&(proof.identity(), self.external_effect_generation()?))
            {
                return Err(rejected());
            }
            proof.check_warm(self)?;
            delivery.environment(self)
        })();
        self.pending_native_cg_delivery = Some(delivery);
        result
    }
    pub(super) fn mark_native_cg_audited(&mut self, fingerprint: &str) {
        if let Some(d) = self.pending_native_cg_delivery.as_mut() {
            d.audited = Some(fingerprint.to_owned());
        }
    }
    pub(super) fn complete_native_cg_delivery(
        &mut self,
        expected: bool,
        mut response: Response,
        fingerprint: &str,
    ) -> Response {
        let mut delivery = match (expected, self.pending_native_cg_delivery.take()) {
            (false, None) => return response,
            (true, Some(d)) => d,
            _ => {
                erase_json(&mut response.body);
                self.recovery_required = true;
                return rejected();
            }
        };
        // A prior terminal/audit veto already carries its first outcome. Never
        // replace it by a new success or manufacture a fresh proof here.
        if self.recovery_required
            || delivery.audited.as_deref() != Some(fingerprint)
            || delivery.proof.is_none()
        {
            erase_json(&mut response.body);
            response.consistency_index = None;
            return if response.status >= 400 {
                response
            } else {
                rejected()
            };
        }
        let checked = (|| {
            delivery.environment(self)?;
            if reply_digest(response.status, &response.body, delivery.deadline)? != delivery.reply {
                return Err(rejected());
            }
            let proof = delivery.proof.take().ok_or_else(rejected)?;
            proof.check_with(self, |installed, metadata, native, root, deadline| {
                Self::check_native_installed(installed, metadata, native, root, deadline)?;
                delivery.check_read_root(root)?;
                delivery.check_live(installed)
            })?;
            delivery.environment(self)?;
            delivery.check_live(self.state.as_ref().ok_or_else(rejected)?)
        })();
        if let Err(error) = checked {
            erase_json(&mut response.body);
            response.consistency_index = None;
            if self
                .audit_event(
                    "native-control-group-delivery-veto",
                    fingerprint,
                    delivery.clock.admitted_at().seconds(),
                    Some(error.status),
                )
                .is_err()
            {
                self.recovery_required = true;
                return rejected();
            }
            return error;
        }
        response
    }
}

fn cg_response(body: Value) -> Response {
    Response {
        status: 200,
        body,
        unwrapped_json: None,
        response_headers: Default::default(),
        consistency_index: None,
    }
}

// The borrowing method lives beside OrdinaryKvAuthority's private Principal,
// so that inner KV and control-group validation share one affine requester.
pub(super) fn check_inner_action(
    state: &State,
    owner: &DeferredRequest,
    actor: &mut Principal,
    clock: RequestClock,
) -> Result<(), Response> {
    check_action(state, owner, actor, clock, true)
}
