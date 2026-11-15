//! Closed ordinary namespace metadata and exact empty retirement owners.
//! Independent custody, leases and deleting secret-bearing children remain
//! outside these operations. Flat history keeps schema 140; a complete plain
//! tree retains schema 145 and the actual paired incarnation ledger.
//! Structural profile validation grants no actor or publication authority.
use super::*;
use crate::state_record_root_v6::{OwnerDomain, RecordStateRootV6};
use crate::v6_native_custody::OriginalDeadline;

fn unavailable() -> Response {
    Response::error(503, "native empty namespace owner unavailable")
}

fn absent_catalog_entry() -> Response {
    let mut response = Response::error(404, "");
    response.body = json!({"errors": []});
    response
}

impl NamespaceRegistry {
    fn native_empty_namespace_paths(&self) -> Result<BTreeSet<String>, Response> {
        self.native_flat_catalog_paths()
    }
}

pub(in crate::service) fn empty_profile(state: &State) -> Result<(), Response> {
    if state.namespace_protected.is_some() || !state.namespace_leases.is_empty() {
        return Err(unavailable());
    }
    state.validate_native_flat_retirement_state(None)?;
    state.namespaces.validate(&state.cluster_id)?;
    let paths = state.namespaces.native_empty_namespace_paths()?;
    if let Some(actual) = state.namespaces.batch_lifecycle.as_ref() {
        // Every admitted row and retirement frontier is visible. Derive the
        // sole allowed ledger from the actual cluster and rows; no independent
        // custody or history is normalized away.
        let expected = crate::auth::batch_namespace::Registry::adopt_visible(
            &state.cluster_id,
            state
                .namespaces
                .entries
                .iter()
                .map(|(path, entry)| (path.clone(), entry.incarnation))
                .collect(),
            state.namespaces.next_incarnation.clone(),
        )
        .map_err(|_| unavailable())?;
        if actual != &expected {
            return Err(unavailable());
        }
    }
    state.validate_namespace_batch_state()?;
    let bindings = state.namespace_factory_bindings(&paths)?;
    let normalized = state
        .auth
        .without_namespace_factory_defaults(&bindings)
        .map_err(|error| Response::error(error.status, &error.message))?;
    if !normalized.native_empty_namespace_auth_profile(&paths)
        || !state.engines.native_empty_namespace_engine_profile(&paths)
    {
        return Err(unavailable());
    }
    Ok(())
}

/// The old root-only reader remains unchanged when there is no child catalog
/// or engine metadata. Additional children require the entire closed profile.
pub(in crate::service) fn require_catalog_profile(state: &State) -> Result<(), Response> {
    if state.namespace_protected.is_some() || !state.namespace_leases.is_empty() {
        return Err(unavailable());
    }
    if state.namespaces.is_empty() && state.engines.v6_namespace_paths().all(str::is_empty) {
        return state.validate_format();
    }
    if empty_profile(state).is_err() {
        super::native_plain::profile(state)?;
    }
    state.validate_format()
}

/// Scoped catalog observations use the existing native metadata owner, never
/// the mutation capsule. Custody subroutes keep their own operation owners.
pub(in crate::service) fn is_catalog_read(method: &str, path: &str) -> bool {
    if !matches!(method, "GET" | "HEAD" | "LIST" | "SCAN") || !owns(path) {
        return false;
    }
    let suffix = path
        .strip_prefix("sys/namespaces")
        .unwrap_or_default()
        .trim_start_matches('/');
    suffix != "delete-sealed"
        && !["/seal-status", "/seal", "/unseal", "/delete-sealed"]
            .iter()
            .any(|reserved| suffix.ends_with(reserved))
}

pub(in crate::service) fn authorize_catalog_read(
    auth: &AuthState,
    actor: &Principal,
    namespace: &str,
    method: &str,
    path: &str,
    time: AuthorityTime,
) -> Result<(), Response> {
    if !is_catalog_read(method, path) {
        return Err(unavailable());
    }
    let capability = match method {
        "GET" | "HEAD" => "read",
        "LIST" => "list",
        "SCAN" => "scan",
        _ => return Err(unavailable()),
    };
    // Retain the exact original path and the original operation capability.
    // HTTP list-query normalization has already happened before this route.
    auth.authorize_request_observed(actor, namespace, path, capability, time)
        .map_err(|error| Response::error(error.status, &error.message))
}

/// This is only the original registry projection. NativeAuthDelivery owns the
/// authenticated graph, immutable read plan, reply digest and audit delivery.
pub(in crate::service) fn catalog_read(
    state: &State,
    actor: Option<&Principal>,
    request: &RequestView<'_>,
    time: AuthorityTime,
) -> Response {
    let Some(actor) = actor else {
        return Response::error(403, "missing client token");
    };
    if !is_catalog_read(request.method, request.path) {
        return unavailable();
    }
    if request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
        return Response::error(501, "namespace management responses cannot be wrapped");
    }
    if let Err(error) = authorize_catalog_read(
        &state.auth,
        actor,
        request.namespace,
        request.method,
        request.path,
        time,
    ) {
        return error;
    }
    if let Err(error) = require_catalog_profile(state) {
        return error;
    }
    let suffix = request
        .path
        .strip_prefix("sys/namespaces")
        .unwrap_or_default()
        .trim_start_matches('/');
    if suffix.is_empty() {
        if request.body.as_object().is_none_or(|body| !body.is_empty()) {
            return Response::error(400, "namespace list accepts an empty request body");
        }
        let recursive = match request.method {
            "LIST" => false,
            "SCAN" => true,
            _ => return Response::error(405, "namespace path is required"),
        };
        let response = state
            .namespaces
            .list(&state.cluster_id, request.namespace, recursive);
        if response.body["data"]["keys"]
            .as_array()
            .is_some_and(|keys| keys.is_empty())
        {
            // Official 2.7.1 distinguishes a missing LIST result from a
            // successful empty recursive SCAN. Neither reveals another scope.
            return if recursive {
                Response::ok(json!({"data": {}}))
            } else {
                absent_catalog_entry()
            };
        }
        return response;
    }
    if suffix.contains('/') {
        return Response::error(400, "namespace name cannot contain /");
    }
    let target = match join_path(request.namespace, suffix) {
        Ok(path) => path,
        Err(error) => return error,
    };
    match request.method {
        "GET" | "HEAD" => {
            if request.body.as_object().is_none_or(|body| !body.is_empty()) {
                return Response::error(400, "namespace read accepts an empty request body");
            }
            state
                .namespaces
                .read(&state.cluster_id, request.namespace, &target)
                .unwrap_or_else(|error| {
                    if error.status == 404 {
                        absent_catalog_entry()
                    } else {
                        error
                    }
                })
        }
        _ => Response::error(405, "unsupported namespace method"),
    }
}

// Only native metadata is serialized. No opaque/native payload is flattened.
fn engine_metadata_digest(
    state: &State,
    root: &RecordStateRootV6,
    deadline: OriginalDeadline,
) -> Result<[u8; 32], Response> {
    let check = || {
        deadline
            .check()
            .map_err(|_| crate::state_records::RecordError::Invalid)
    };
    let parent = root.kv2_parent_key().map_err(|_| unavailable())?;
    let kv1_key = root.kv1_key().map_err(|_| unavailable())?;
    let (opaque, graphs) = if root.reader_floor.native_kv2_format == 2 {
        state
            .engines
            .project_v6_native_paged(&parent, &check, |_, _| check())
    } else {
        state
            .engines
            .project_v6_native(&parent, &check, |_, _| check())
    }
    .map_err(|_| unavailable())?;
    if state.engines.record_root().as_ref() != Some(&root.kv1)
        || state
            .engines
            .record_address_key()
            .is_none_or(|key| key.expose() != kv1_key.expose())
        || graphs != root.kv2
    {
        return Err(unavailable());
    }
    let bytes = owner_store::serialize_owner(&(opaque, graphs)).map_err(|_| unavailable())?;
    deadline.check().map_err(|_| unavailable())?;
    Ok(crypto::digest(&bytes))
}

/// The actual Principal has exactly one owner. NativeAuthDelivery retains this
/// capsule through its actual native planner, terminal receipt and audit fence.
/// Constructing this value alone cannot publish or deliver anything.
pub(in crate::service) struct NativeEmptyNamespaceDraft {
    principal: Principal,
    scope: super::native_plain::PlainNamespaceScope,
    method: String,
    creating: bool,
    deleting: bool,
    target_was_present: bool,
    path: String,
    target: String,
    metadata: BTreeMap<String, String>,
    body: Value,
    clock: RequestClock,
    deadline: OriginalDeadline,
    root_digest: [u8; 32],
    catalog_digest: [u8; 32],
    auth_digest: [u8; 32],
    engines_digest: [u8; 32],
    database_digest: [u8; 32],
    raft_digest: [u8; 32],
    installed_catalog: Option<[u8; 32]>,
    installed_engines: Option<[u8; 32]>,
    factory: Option<crate::auth::namespace_factory::PreparedChild>,
}

impl Drop for NativeEmptyNamespaceDraft {
    fn drop(&mut self) {
        erase_json(&mut self.body);
    }
}

impl NativeEmptyNamespaceDraft {
    pub(in crate::service) fn prepare(
        state: &State,
        root: &RecordStateRootV6,
        principal: Principal,
        request: &RequestView<'_>,
    ) -> Result<Self, Response> {
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        let clock = request.token_clock.ok_or_else(unavailable)?;
        let deleting = request.method == "DELETE";
        if deleting && !principal.is_root() {
            return Err(Response::error(
                403,
                "namespace deletion requires the root catalog administrator",
            ));
        }
        if !principal.is_root()
            || !matches!(request.method, "POST" | "PUT" | "PATCH" | "DELETE")
            || request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0)
            || state.schema != root.state_schema
            || state.cluster_id != root.cluster_id
            || state.replay_epoch != root.replay_epoch
        {
            return Err(unavailable());
        }
        let suffix = request
            .path
            .strip_prefix("sys/namespaces/")
            .filter(|target| !target.contains('/') && valid_segment(target))
            .ok_or_else(unavailable)?;
        let target = join_path(request.namespace, suffix)?;
        let target_was_present = state.namespaces.contains(&target);
        let patching = request.method == "PATCH";
        let creating = !deleting && !patching && !target_was_present;
        if matches!(
            suffix,
            "root" | "sys" | "audit" | "auth" | "cubbyhole" | "identity"
        ) || if deleting {
            request.body.as_object().is_none_or(|body| !body.is_empty())
        } else {
            request
                .body
                .as_object()
                .is_none_or(|body| body.keys().any(|key| key != "custom_metadata"))
        } {
            return Err(unavailable());
        }
        super::native_plain::profile(state)?;
        state.validate_format()?;
        let scope = super::native_plain::PlainNamespaceScope::capture(state, request.namespace)?;
        let metadata = if deleting {
            BTreeMap::new()
        } else if patching {
            let mut metadata = state
                .namespaces
                .entries
                .get(&target)
                .ok_or_else(|| Response::error(404, "namespace not found"))?
                .custom_metadata
                .clone();
            patch_metadata(&mut metadata, request.body)?;
            metadata
        } else {
            create_metadata(request.body)?
        };
        let mut draft = Self {
            principal,
            scope,
            method: request.method.to_owned(),
            creating,
            deleting,
            target_was_present,
            path: request.path.to_owned(),
            target,
            metadata,
            body: request.body.clone(),
            clock,
            deadline,
            root_digest: crypto::digest(&root.encode().map_err(|_| unavailable())?),
            catalog_digest: crypto::digest(
                &owner_store::serialize_owner(&state.namespaces).map_err(|_| unavailable())?,
            ),
            auth_digest: crypto::digest(
                &owner_store::serialize_owner(&state.auth).map_err(|_| unavailable())?,
            ),
            engines_digest: engine_metadata_digest(state, root, deadline)?,
            database_digest: crypto::digest(
                &owner_store::serialize_owner(&state.database).map_err(|_| unavailable())?,
            ),
            raft_digest: crypto::digest(
                &owner_store::serialize_owner(&state.raft_admin).map_err(|_| unavailable())?,
            ),
            installed_catalog: None,
            installed_engines: None,
            factory: None,
        };
        // Reuse the first original source authorization's observed time.
        // Later candidate/check calls never reconstruct or retime this seed.
        let time = draft.check_source_observation(state, root)?;
        if creating {
            let mut catalog = state.namespaces.clone();
            catalog.create(
                &state.cluster_id,
                &draft.target,
                draft.metadata.clone(),
                false,
            )?;
            let binding = catalog.custody_binding(&state.cluster_id, &draft.target)?;
            draft.factory = Some(
                crate::auth::namespace_factory::PreparedChild::new(binding, time)
                    .map_err(|error| Response::error(error.status, &error.message))?,
            );
        }
        Ok(draft)
    }

    pub(in crate::service) fn check_source(
        &self,
        state: &State,
        root: &RecordStateRootV6,
    ) -> Result<(), Response> {
        self.check_source_observation(state, root).map(|_| ())
    }

    fn check_source_observation(
        &self,
        state: &State,
        root: &RecordStateRootV6,
    ) -> Result<AuthorityTime, Response> {
        self.deadline.check().map_err(|_| unavailable())?;
        super::native_plain::profile(state)?;
        self.scope.check(state)?;
        if state.schema != root.state_schema
            || state.cluster_id != root.cluster_id
            || state.replay_epoch != root.replay_epoch
            || crypto::digest(&root.encode().map_err(|_| unavailable())?) != self.root_digest
            || crypto::digest(
                &owner_store::serialize_owner(&state.namespaces).map_err(|_| unavailable())?,
            ) != self.catalog_digest
            || crypto::digest(
                &owner_store::serialize_owner(&state.auth).map_err(|_| unavailable())?,
            ) != self.auth_digest
            || engine_metadata_digest(state, root, self.deadline)? != self.engines_digest
            || crypto::digest(
                &owner_store::serialize_owner(&state.database).map_err(|_| unavailable())?,
            ) != self.database_digest
            || crypto::digest(
                &owner_store::serialize_owner(&state.raft_admin).map_err(|_| unavailable())?,
            ) != self.raft_digest
        {
            return Err(unavailable());
        }
        self.check_source_auth_observation(&state.auth)
    }

    pub(in crate::service) fn check_source_auth(&self, auth: &AuthState) -> Result<(), Response> {
        self.check_source_auth_observation(auth).map(|_| ())
    }

    fn check_source_auth_observation(&self, auth: &AuthState) -> Result<AuthorityTime, Response> {
        if crypto::digest(&owner_store::serialize_owner(auth).map_err(|_| unavailable())?)
            != self.auth_digest
        {
            return Err(unavailable());
        }
        self.authorize_current_observation(auth)
    }

    pub(in crate::service) fn authorize_current(&self, auth: &AuthState) -> Result<(), Response> {
        self.authorize_current_observation(auth).map(|_| ())
    }

    fn authorize_current_observation(&self, auth: &AuthState) -> Result<AuthorityTime, Response> {
        self.deadline.check().map_err(|_| unavailable())?;
        let at = self.clock.observed_at().map_err(|_| unavailable())?;
        let time = auth.token_api_observed_time(AuthorityTime::Precise(at));
        auth.authorize_request_parameters_observed(
            &self.principal,
            self.scope.namespace(),
            &self.method,
            &self.path,
            &self.body,
            time,
        )
        .map_err(|error| Response::error(error.status, &error.message))?;
        let observed = auth
            .authorize_request_observation(
                &self.principal,
                self.scope.namespace(),
                &self.path,
                if self.deleting {
                    "delete"
                } else if self.method == "PATCH" {
                    "patch"
                } else {
                    "update"
                },
                time,
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
        self.deadline.check().map_err(|_| unavailable())?;
        Ok(observed)
    }

    pub(in crate::service) fn candidate(
        &self,
        current: &State,
        current_root: &RecordStateRootV6,
    ) -> Result<State, Response> {
        self.check_source(current, current_root)?;
        let mut next = current.clone();
        if self.creating && !self.scope.namespace().is_empty() {
            // Adopt the complete, still-flat source catalog before adding the
            // first nested child. Creation and the new paired ledger publish
            // together; the original source itself is never relabeled.
            next.ensure_namespace_batch_registry()?;
            next.namespaces.native_flat_retirement_format = Some(2);
        }
        if self.deleting {
            if next.namespaces.contains(&self.target) {
                if next.namespaces.entries.keys().any(|path| {
                    path.strip_prefix(&self.target)
                        .is_some_and(|tail| tail.starts_with('/'))
                }) {
                    return Err(Response::error(400, "namespace has child namespaces"));
                }
                // Capture the actual complete ledger before catalog removal.
                // The original remove/record_remove advances the old frontier;
                // all three owners publish in this same native transaction.
                next.ensure_namespace_batch_registry()?;
                let binding = next
                    .namespaces
                    .custody_binding(&next.cluster_id, &self.target)?;
                next.auth
                    .retire_native_flat_namespace_auth(&self.target, &binding)
                    .map_err(|error| Response::error(error.status, &error.message))?;
                if !next.auth.namespace_is_empty(&self.target)
                    || !next.database.namespace_is_empty(&self.target)
                    || !next.namespaces.workflows.namespace_is_empty(&self.target)
                {
                    return Err(Response::error(
                        409,
                        "namespace still contains owned resources",
                    ));
                }
                next.namespaces.remove(&self.target)?;
                if !next.namespaces.has_native_plain_tree_state() {
                    next.namespaces.native_flat_retirement_format = Some(1);
                }
                next.sync_namespace_batch_registry()?;
                // A disabled KV mount retains its mount incarnation frontier.
                // It may leave with this exact namespace incarnation, never
                // through the pristine-owner predicate or an isolated removal.
                if next.namespaces.contains(&self.target)
                    || binding.incarnation().checked_add(1)
                        != next.namespaces.next_incarnation.get(&self.target).copied()
                {
                    return Err(unavailable());
                }
                let lifecycle = next
                    .auth
                    .namespace_batch_registry()
                    .ok_or_else(unavailable)?;
                next.engines
                    .retire_native_flat_namespace_engines(&next.cluster_id, &binding, lifecycle)
                    .map_err(Response::from_engine_error)?;
            }
        } else if self.creating {
            next.namespaces
                .create(&next.cluster_id, &self.target, self.metadata.clone(), false)?;
            let binding = next
                .namespaces
                .custody_binding(&next.cluster_id, &self.target)?;
            self.factory
                .as_ref()
                .ok_or_else(unavailable)?
                .install(&mut next.auth, &binding)
                .map_err(|error| Response::error(error.status, &error.message))?;
            next.engines.ensure_empty_namespace(&self.target);
            if next.has_namespace_batch_state() {
                // Real create records a new incarnation, including following
                // an owned retirement. Its paired Auth ledger moves together.
                next.sync_namespace_batch_registry()?;
            }
        } else {
            // PATCH and replacement change only the selected metadata map.
            // Its factory, incarnation, child resources and sibling rows stay
            // bound to the exact admitted source and deterministic delta.
            next.namespaces
                .entries
                .get_mut(&self.target)
                .ok_or_else(|| Response::error(404, "namespace not found"))?
                .custom_metadata = self.metadata.clone();
        }
        next.schema = next.writer_schema();
        super::native_plain::profile(&next)?;
        next.validate_format()?;
        self.deadline.check().map_err(|_| unavailable())?;
        Ok(next)
    }

    /// Recompute this deterministic transform from the still-authenticated
    /// source, then compare the planner's actually materialized candidate.
    /// A three-domain allow-list alone is never accepted as exact delta proof.
    pub(in crate::service) fn check_candidate(
        &self,
        current: &State,
        current_root: &RecordStateRootV6,
        candidate: &State,
    ) -> Result<(), Response> {
        let expected = self.candidate(current, current_root)?;
        super::native_plain::profile(candidate)?;
        candidate.validate_format()?;
        if candidate.schema != expected.schema
            || candidate.cluster_id != expected.cluster_id
            || candidate.replay_epoch != expected.replay_epoch
            || candidate.global_lossless_json_format != expected.global_lossless_json_format
            || owner_store::serialize_owner(&candidate.namespaces).map_err(|_| unavailable())?
                != owner_store::serialize_owner(&expected.namespaces).map_err(|_| unavailable())?
            || owner_store::serialize_owner(&candidate.auth).map_err(|_| unavailable())?
                != owner_store::serialize_owner(&expected.auth).map_err(|_| unavailable())?
            || owner_store::serialize_owner(&candidate.database).map_err(|_| unavailable())?
                != owner_store::serialize_owner(&expected.database).map_err(|_| unavailable())?
            || owner_store::serialize_owner(&candidate.raft_admin).map_err(|_| unavailable())?
                != owner_store::serialize_owner(&expected.raft_admin).map_err(|_| unavailable())?
            || engine_metadata_digest(candidate, current_root, self.deadline)?
                != engine_metadata_digest(&expected, current_root, self.deadline)?
        {
            return Err(unavailable());
        }
        self.deadline.check().map_err(|_| unavailable())
    }

    /// Necessary root-shape check after the actual native planner. This does
    /// not replace exact candidate materialization or any CAS/NativeProof.
    pub(in crate::service) fn check_root_delta(
        &self,
        prior: &RecordStateRootV6,
        next: &RecordStateRootV6,
    ) -> Result<(), Response> {
        self.deadline.check().map_err(|_| unavailable())?;
        if crypto::digest(&prior.encode().map_err(|_| unavailable())?) != self.root_digest
            || next.state_schema < prior.state_schema
            || next.reader_floor.minimum_state_schema < prior.reader_floor.minimum_state_schema
        {
            return Err(unavailable());
        }
        let mut normalized = next.clone();
        normalized.state_schema = prior.state_schema;
        normalized.reader_floor.minimum_state_schema = prior.reader_floor.minimum_state_schema;
        for (old, new) in prior.owners.iter().zip(normalized.owners.iter_mut()) {
            if old.domain != new.domain {
                return Err(unavailable());
            }
            if matches!(
                old.domain,
                OwnerDomain::Namespaces | OwnerDomain::Auth | OwnerDomain::Engines
            ) {
                *new = old.clone();
            }
        }
        if normalized.encode().map_err(|_| unavailable())?.as_slice()
            != prior.encode().map_err(|_| unavailable())?.as_slice()
        {
            return Err(unavailable());
        }
        self.deadline.check().map_err(|_| unavailable())
    }

    pub(in crate::service) fn admit_candidate(
        &mut self,
        current: &State,
        prior: &RecordStateRootV6,
        candidate: &State,
    ) -> Result<(), Response> {
        if self.installed_catalog.is_some() || self.installed_engines.is_some() {
            return Err(unavailable());
        }
        self.check_candidate(current, prior, candidate)?;
        self.installed_catalog = Some(crypto::digest(
            &owner_store::serialize_owner(&candidate.namespaces).map_err(|_| unavailable())?,
        ));
        self.installed_engines = Some(engine_metadata_digest(candidate, prior, self.deadline)?);
        Ok(())
    }

    pub(in crate::service) fn check_installed(
        &self,
        state: &State,
        root: &RecordStateRootV6,
    ) -> Result<(), Response> {
        super::native_plain::profile(state)?;
        self.scope.check(state)?;
        if self.installed_catalog
            != Some(crypto::digest(
                &owner_store::serialize_owner(&state.namespaces).map_err(|_| unavailable())?,
            ))
            || self.installed_engines != Some(engine_metadata_digest(state, root, self.deadline)?)
        {
            return Err(unavailable());
        }
        self.authorize_current(&state.auth)
    }

    pub(in crate::service) fn response(&self, candidate: &State) -> Result<Response, Response> {
        self.deadline.check().map_err(|_| unavailable())?;
        if self.deleting {
            if candidate.namespaces.contains(&self.target) {
                return Err(unavailable());
            }
            if self.target_was_present && candidate.namespaces.has_native_plain_tree_state() {
                return Ok(Response::ok(json!({"data": {"status": "in-progress"}})));
            }
            return Ok(Response::ok(json!({"data": null})));
        }
        candidate
            .namespaces
            .read(&candidate.cluster_id, self.scope.namespace(), &self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::NativeStorageProfile;
    use crate::service::tests::Root;
    use std::time::Instant;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn call(
        service: &mut Service,
        method: &str,
        path: &str,
        namespace: &str,
        token: &str,
        body: Value,
    ) -> Response {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        service.handle(method, path, namespace, token, body)
    }

    fn formal() -> TestResult<(Root, Service, Zeroizing<String>, Zeroizing<String>)> {
        let files = Root::new();
        let mut service = files.service()?;
        service.configure_native_v6_storage(NativeStorageProfile::File)?;
        let nonce = Zeroizing::new(hex(&crypto::random::<32>()?));
        let mut initialized = call(
            &mut service,
            "POST",
            "sys/init",
            "",
            "",
            json!({
                "secret_shares":1, "secret_threshold":1, "recovery_nonce":nonce.as_str()
            }),
        );
        assert_eq!(initialized.status, 200);
        let key = Zeroizing::new(
            initialized.body["keys"][0]
                .as_str()
                .ok_or("share")?
                .to_owned(),
        );
        let admin = Zeroizing::new(
            initialized.body["root_token"]
                .as_str()
                .ok_or("token")?
                .to_owned(),
        );
        erase_json(&mut initialized.body);
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/unseal",
                "",
                "",
                json!({"key":key.as_str()})
            )
            .status,
            200
        );
        assert_eq!(
            call(&mut service, "POST", "sys/init/ack", "", &admin, json!({})).status,
            204
        );
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/storage/native-v6/activate",
                "",
                &admin,
                json!({})
            )
            .status,
            204
        );
        Ok((files, service, key, admin))
    }

    #[test]
    fn sealed_catalog_entry_never_becomes_a_metadata_only_namespace() -> TestResult {
        let mut registry = NamespaceRegistry::default();
        assert!(
            registry
                .create("cluster", "cg-other", BTreeMap::new(), false)
                .is_ok()
        );
        assert!(registry.native_empty_namespace_paths().is_ok());
        registry.entries.get_mut("cg-other").ok_or("entry")?.sealed = true;
        assert!(registry.native_empty_namespace_paths().is_err());
        Ok(())
    }

    #[test]
    fn incarnation_history_is_retained_and_rejected_by_the_narrow_profile() {
        let mut registry = NamespaceRegistry::default();
        assert!(
            registry
                .create("cluster", "cg-other", BTreeMap::new(), false)
                .is_ok()
        );
        registry.next_incarnation.insert("retired".to_owned(), 2);
        assert!(registry.native_empty_namespace_paths().is_err());
        assert_eq!(registry.next_incarnation.get("retired"), Some(&2));
    }

    #[test]
    fn formal_native_namespace_create_has_real_catalog_and_survives_cold_reopen() -> TestResult {
        let (files, mut service, key, admin) = formal()?;
        let before = service.current_state_identity().map_err(|_| "identity")?;
        let created = call(
            &mut service,
            "POST",
            "sys/namespaces/cg-other",
            "",
            &admin,
            json!({}),
        );
        assert_eq!(created.status, 200, "{}", created.body["errors"]);
        let state = service.state.as_ref().ok_or("state")?;
        assert_eq!(
            created.body["data"]["id"],
            namespace_id(&state.cluster_id, "cg-other", 1)
        );
        assert_eq!(state.namespaces.incarnation("cg-other"), Some(1));
        assert!(!state.auth.namespace_is_empty("cg-other"));
        let binding = state
            .namespaces
            .custody_binding(&state.cluster_id, "cg-other")
            .map_err(|_| "actual namespace factory binding")?;
        let normalized = state
            .auth
            .without_namespace_factory_defaults(&BTreeMap::from([("cg-other".to_owned(), binding)]))
            .map_err(|_| "actual untouched namespace factory")?;
        assert!(normalized.namespace_is_empty("cg-other"));
        assert!(state.engines.namespace_is_empty("cg-other"));
        assert!(empty_profile(state).is_ok());
        assert_ne!(
            before,
            service
                .current_state_identity()
                .map_err(|_| "new identity")?
        );
        drop(service);
        let mut cold = files.service()?;
        cold.configure_native_v6_storage(NativeStorageProfile::File)?;
        assert_eq!(
            call(
                &mut cold,
                "POST",
                "sys/unseal",
                "",
                "",
                json!({"key":key.as_str()})
            )
            .status,
            200
        );
        let state = cold.state.as_ref().ok_or("cold state")?;
        assert_eq!(state.namespaces.incarnation("cg-other"), Some(1));
        assert!(empty_profile(state).is_ok());
        assert!(cold.native_root.is_some() && cold.record_root.is_none());
        assert_eq!(
            call(&mut cold, "GET", "sys/mounts", "", &admin, json!({})).status,
            200
        );
        let catalog =
            owner_store::serialize_owner(&cold.state.as_ref().ok_or("cold state")?.namespaces)?;
        for method in ["GET", "HEAD"] {
            let observed = call(
                &mut cold,
                method,
                "sys/namespaces/cg-other",
                "",
                &admin,
                json!({}),
            );
            assert_eq!(observed.status, 200, "{}", observed.body["errors"]);
            assert_eq!(observed.body["data"], created.body["data"]);
        }
        for method in ["LIST", "SCAN"] {
            for path in ["sys/namespaces", "sys/namespaces/"] {
                let observed = call(&mut cold, method, path, "", &admin, json!({}));
                assert_eq!(observed.status, 200, "{}", observed.body["errors"]);
                assert_eq!(observed.body["data"]["keys"], json!(["cg-other/"]));
                assert_eq!(
                    observed.body["data"]["key_info"]["cg-other/"],
                    created.body["data"],
                );
            }
        }
        assert_eq!(
            catalog,
            owner_store::serialize_owner(&cold.state.as_ref().ok_or("cold state")?.namespaces,)?,
        );
        assert!(cold.native_root.is_some() && cold.record_root.is_none());
        assert!(!cold.recovery_required);
        Ok(())
    }

    #[test]
    fn formal_native_namespace_catalog_preserves_read_list_and_foreign_scope_authority()
    -> TestResult {
        let (_files, mut service, _key, admin) = formal()?;
        for name in ["cg-readable", "cg-private"] {
            let created = call(
                &mut service,
                "POST",
                &format!("sys/namespaces/{name}"),
                "",
                &admin,
                json!({}),
            );
            assert_eq!(created.status, 200, "{}", created.body["errors"]);
        }
        let mut tokens = Vec::new();
        for (name, policy) in [
            (
                "native-catalog-reader",
                r#"path "sys/namespaces/cg-readable" { capabilities = ["read"] }"#,
            ),
            (
                "native-catalog-lister",
                r#"path "sys/namespaces" { capabilities = ["list"] }"#,
            ),
        ] {
            let configured = call(
                &mut service,
                "PUT",
                &format!("sys/policies/acl/{name}"),
                "",
                &admin,
                json!({"policy":policy}),
            );
            assert_eq!(configured.status, 204, "{}", configured.body["errors"]);
            let mut issued = call(
                &mut service,
                "POST",
                "auth/token/create",
                "",
                &admin,
                json!({"policies":[name],"ttl":"10m"}),
            );
            assert_eq!(issued.status, 200, "{}", issued.body["errors"]);
            tokens.push(Zeroizing::new(
                issued.body["auth"]["client_token"]
                    .as_str()
                    .ok_or("catalog token")?
                    .to_owned(),
            ));
            erase_json(&mut issued.body);
        }
        let catalog =
            owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.namespaces)?;
        let reader = tokens.first().ok_or("reader")?;
        let lister = tokens.get(1).ok_or("lister")?;
        for method in ["GET", "HEAD"] {
            let observed = call(
                &mut service,
                method,
                "sys/namespaces/cg-readable",
                "",
                reader,
                json!({}),
            );
            assert_eq!(observed.status, 200, "{}", observed.body["errors"]);
            assert_eq!(observed.body["data"]["path"], "cg-readable/");
        }
        let listed = call(
            &mut service,
            "LIST",
            "sys/namespaces",
            "",
            lister,
            json!({}),
        );
        assert_eq!(listed.status, 200, "{}", listed.body["errors"]);
        assert_eq!(
            listed.body["data"]["keys"],
            json!(["cg-private/", "cg-readable/"])
        );
        for (token, method, path) in [
            (reader, "GET", "sys/namespaces/cg-private"),
            (reader, "LIST", "sys/namespaces"),
            (reader, "SCAN", "sys/namespaces"),
            (lister, "GET", "sys/namespaces/cg-readable"),
            (lister, "SCAN", "sys/namespaces"),
        ] {
            let denied = call(&mut service, method, path, "", token, json!({}));
            assert_eq!(denied.status, 403, "{}", denied.body["errors"]);
            assert!(denied.body.get("data").is_none());
        }
        for (method, path) in [
            ("GET", "sys/namespaces/cg-private"),
            ("LIST", "sys/namespaces"),
        ] {
            let denied = call(&mut service, method, path, "cg-readable", &admin, json!({}));
            assert_eq!(denied.status, 404);
            assert!(denied.body.get("data").is_none());
            assert_eq!(denied.body["errors"], json!([]));
        }
        let empty_scan = call(
            &mut service,
            "SCAN",
            "sys/namespaces",
            "cg-readable",
            &admin,
            json!({}),
        );
        assert_eq!(empty_scan.status, 200);
        assert_eq!(empty_scan.body["data"], json!({}));
        for (method, path, body, status) in [
            ("GET", "sys/namespaces/missing", json!({}), 404),
            (
                "GET",
                "sys/namespaces/cg-readable",
                json!({"extra":true}),
                400,
            ),
            ("LIST", "sys/namespaces", json!({"extra":true}), 400),
            ("GET", "sys/namespaces", json!({}), 405),
            ("LIST", "sys/namespaces/cg-readable", json!({}), 405),
        ] {
            let invalid = call(&mut service, method, path, "", &admin, body);
            assert_eq!(invalid.status, status, "{}", invalid.body["errors"]);
        }
        let custody = call(
            &mut service,
            "GET",
            "sys/namespaces/cg-readable/seal-status",
            "",
            &admin,
            json!({}),
        );
        assert!(custody.status >= 400);
        assert!(custody.body.get("data").is_none());
        assert_eq!(
            catalog,
            owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.namespaces,)?,
        );
        assert!(service.native_root.is_some() && service.record_root.is_none());
        assert!(!service.recovery_required);
        Ok(())
    }

    #[test]
    fn formal_native_empty_namespace_denies_foreign_control_group_routes_without_root_effects()
    -> TestResult {
        let (_files, mut service, _key, admin) = formal()?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/namespaces/cg-other",
                "",
                &admin,
                json!({})
            )
            .status,
            200
        );
        let catalog =
            owner_store::serialize_owner(&service.state.as_ref().ok_or("state")?.namespaces)?;
        for path in [
            "sys/control-group/request",
            "sys/control-group/authorize",
            "sys/wrapping/unwrap",
        ] {
            assert!(
                call(
                    &mut service,
                    "POST",
                    path,
                    "cg-other",
                    &admin,
                    json!({"accessor":"foreign-scope-owned-test"})
                )
                .status
                    >= 400
            );
        }
        assert!(
            catalog.as_slice()
                == owner_store::serialize_owner(
                    &service.state.as_ref().ok_or("state")?.namespaces
                )?
                .as_slice()
        );
        assert!(!service.recovery_required);
        Ok(())
    }

    #[test]
    fn formal_native_namespace_rejects_seal_and_nested_selectors_without_new_catalog_entry()
    -> TestResult {
        let (_files, mut service, _key, admin) = formal()?;
        for (path, body) in [
            (
                "sys/namespaces/closed",
                json!({"secret_shares":1,"secret_threshold":1}),
            ),
            ("sys/namespaces/parent/child", json!({})),
            ("sys/namespaces/root", json!({})),
        ] {
            assert!(call(&mut service, "POST", path, "", &admin, body).status >= 400);
        }
        assert!(service.state.as_ref().ok_or("state")?.namespaces.is_empty());
        assert!(!service.recovery_required);
        Ok(())
    }
}
