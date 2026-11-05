//! Ordinary child namespaces retain the same root-barrier NativeProof as root.
//! This profile never opens independent namespace keys or opaque custody parcels.
//! Each request additionally retains the real catalog identity and incarnation.
use super::*;

fn unavailable() -> Response {
    Response::error(503, "native plain namespace ownership unavailable")
}

impl NamespaceRegistry {
    fn native_plain_paths(&self) -> Result<BTreeSet<String>, Response> {
        self.native_flat_catalog_paths()
    }
}

pub(in crate::service) fn profile(state: &State) -> Result<(), Response> {
    if state.namespace_protected.is_some() || !state.namespace_leases.is_empty() {
        return Err(unavailable());
    }
    state.validate_native_flat_retirement_state(None)?;
    state.namespaces.validate(&state.cluster_id)?;
    state.validate_namespace_factory_state()?;
    let paths = state.namespaces.native_plain_paths()?;
    if let Some(actual) = state.namespaces.batch_lifecycle.as_ref() {
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
    if !state.auth.native_plain_namespace_auth_profile(&paths)
        || !state.engines.native_plain_namespace_engine_profile(&paths)
    {
        return Err(unavailable());
    }
    Ok(())
}

/// Reader capability is sticky only after actual child resources are present.
/// Existing empty-catalog snapshots keep their previously admitted schema.
pub(in crate::service) fn has_child_resources(state: &State) -> bool {
    state.namespaces.entries.keys().any(|namespace| {
        !state.auth.namespace_is_empty(namespace) || !state.engines.namespace_is_empty(namespace)
    })
}

/// A private affine catalog binding. It grants no ACL, actor, engine or write.
pub(in crate::service) struct PlainNamespaceScope {
    cluster: String,
    namespace: String,
    id: String,
    incarnation: u64,
    ancestors: Vec<(String, String, u64)>,
}

impl PlainNamespaceScope {
    pub(in crate::service) fn capture(state: &State, namespace: &str) -> Result<Self, Response> {
        state.validate_native_flat_retirement_state(None)?;
        state.namespaces.validate(&state.cluster_id)?;
        let paths = state.namespaces.native_plain_paths()?;
        let (id, incarnation) = if namespace.is_empty() {
            ("root".to_owned(), 0)
        } else {
            if !paths.contains(namespace) {
                // A complete admitted catalog can report initial absence.
                // A captured owner disappearing later still fails check()
                // with 503; absence never manufactures a usable scope.
                return Err(Response::error(404, "namespace not found"));
            }
            let entry = state
                .namespaces
                .entries
                .get(namespace)
                .ok_or_else(unavailable)?;
            (entry.id.clone(), entry.incarnation)
        };
        let mut ancestors = Vec::new();
        let mut parent = parent_path(namespace);
        while !parent.is_empty() {
            let entry = state
                .namespaces
                .entries
                .get(parent)
                .ok_or_else(unavailable)?;
            ancestors.push((parent.to_owned(), entry.id.clone(), entry.incarnation));
            parent = parent_path(parent);
        }
        let scope = Self {
            cluster: state.cluster_id.clone(),
            namespace: namespace.to_owned(),
            id,
            incarnation,
            ancestors,
        };
        scope.check(state)?;
        Ok(scope)
    }

    pub(in crate::service) fn namespace(&self) -> &str {
        &self.namespace
    }

    pub(in crate::service) fn check(&self, state: &State) -> Result<(), Response> {
        state.validate_native_flat_retirement_state(None)?;
        if self.cluster != state.cluster_id
            || state.namespace_protected.is_some()
            || !state.namespace_leases.is_empty()
            || state.namespace_is_sealed(&self.namespace)
            || state.namespaces.incarnation(&self.namespace) != Some(self.incarnation)
            || state
                .namespaces
                .identity_namespace(&self.namespace)?
                .id
                .unwrap_or("root")
                != self.id
        {
            return Err(unavailable());
        }
        let paths = state.namespaces.native_plain_paths()?;
        if !self.namespace.is_empty() && !paths.contains(&self.namespace) {
            return Err(unavailable());
        }
        for (path, id, incarnation) in &self.ancestors {
            if !paths.contains(path)
                || state.namespace_is_sealed(path)
                || state
                    .namespaces
                    .entries
                    .get(path)
                    .is_none_or(|entry| &entry.id != id || entry.incarnation != *incarnation)
            {
                return Err(unavailable());
            }
        }
        Ok(())
    }
}

pub(in crate::service) fn validate_control_group_scope(
    state: &State,
    owner: &crate::auth::control_groups::DeferredRequest,
) -> Result<(), Response> {
    let scope = PlainNamespaceScope::capture(state, &owner.namespace).map_err(|error| {
        // This is a retained owner, not a new request selecting an absent scope.
        if error.status == 404 {
            unavailable()
        } else {
            error
        }
    })?;
    if scope.id != owner.namespace_id || scope.incarnation != owner.namespace_incarnation {
        return Err(unavailable());
    }
    Service::validate_control_group_scope(state, owner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::tests::{Root, bootstrap_unmounted};
    use std::time::{Duration, Instant};
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn native_plain_scope_retains_real_catalog_identity_incarnation_and_barrier() -> TestResult {
        let files = Root::new();
        let mut service = files.service()?;
        let (key, admin) = bootstrap_unmounted(&mut service)?;
        let _key = Zeroizing::new(key);
        let admin = Zeroizing::new(admin);
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        assert_eq!(
            service
                .handle_at("POST", "sys/namespaces/scoped", "", &admin, json!({}), 100)
                .status,
            200
        );
        let state = service.state.as_ref().ok_or("actual state")?.clone();
        let scope =
            PlainNamespaceScope::capture(&state, "scoped").map_err(|_| "actual catalog binding")?;
        assert_eq!(scope.namespace(), "scoped");
        assert!(scope.check(&state).is_ok());
        let absent = PlainNamespaceScope::capture(&state, "missing")
            .err()
            .ok_or("missing catalog scope unexpectedly admitted")?;
        assert_eq!(absent.status, 404);
        let mut poisoned = state.clone();
        poisoned.cluster_id.push_str("-other");
        assert!(scope.check(&poisoned).is_err());
        let mut poisoned = state.clone();
        poisoned
            .namespaces
            .entries
            .get_mut("scoped")
            .ok_or("entry")?
            .id
            .push('x');
        assert!(scope.check(&poisoned).is_err());
        let mut poisoned = state.clone();
        poisoned
            .namespaces
            .entries
            .get_mut("scoped")
            .ok_or("entry")?
            .incarnation += 1;
        assert!(scope.check(&poisoned).is_err());
        let mut poisoned = state.clone();
        poisoned
            .namespaces
            .entries
            .get_mut("scoped")
            .ok_or("entry")?
            .sealed = true;
        assert!(scope.check(&poisoned).is_err());
        let mut poisoned = state.clone();
        poisoned.namespaces.entries.remove("scoped");
        assert_eq!(
            scope
                .check(&poisoned)
                .err()
                .ok_or("absent namespace admitted")?
                .status,
            503
        );
        // A typed negative fixture binds the previously selected namespace.
        // It is never queued, persisted, or authorized as a control-group grant.
        let retained = crate::auth::control_groups::DeferredRequest {
            cluster_id: state.cluster_id.clone(),
            namespace: scope.namespace().to_owned(),
            namespace_id: scope.id.clone(),
            namespace_incarnation: scope.incarnation,
            resource_binding: crate::auth::control_groups::ResourceBinding::System,
            actor_digest: base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                crypto::digest(b"synthetic-retained-scope-negative"),
            ),
            actor_accessor: "a.synthetic-retained-scope".to_owned(),
            actor_entity_id: "synthetic-entity".to_owned(),
            actor_entity: json!({"ID":"synthetic-entity", "name":"synthetic", "namespace_id":scope.id, "aliases":[]}),
            request_accessor: String::new(),
            credential: None,
            method: "GET".to_owned(),
            path: "sys/mounts".to_owned(),
            capability: "read".to_owned(),
            requires_sudo: false,
            body: json!({}),
            transport_method: "GET".to_owned(),
            transport_path: "sys/mounts".to_owned(),
            transport_namespace: scope.namespace().to_owned(),
            transport_body: json!({}),
            logical_data: None,
            wrap_ttl_seconds: None,
            origin_peer: None,
            client_certificates: None,
            created_at: 100,
            expires_at: 160,
            precision: None,
            creation_time: crate::engines::timestamp(100),
            factors: vec![crate::auth::control_groups::ResolvedFactor {
                name: "scope:review".to_owned(),
                group_ids: BTreeSet::from(["synthetic-group".to_owned()]),
                approvals: 1,
                self_authorization: false,
            }],
            authorizations: BTreeMap::new(),
        };
        retained
            .validate()
            .map_err(|_| "typed negative CG fixture invalid")?;
        let initial = PlainNamespaceScope::capture(&poisoned, &retained.namespace)
            .err()
            .ok_or("absent retained namespace unexpectedly admitted")?;
        assert_eq!(initial.status, 404);
        assert_eq!(
            validate_control_group_scope(&poisoned, &retained)
                .err()
                .ok_or("absent retained namespace admitted")?
                .status,
            503
        );
        // Detached metadata above proves only rejection, never publication.
        assert_eq!(
            service
                .state
                .as_ref()
                .ok_or("live state")?
                .namespaces
                .incarnation("scoped"),
            Some(1)
        );
        assert!(!service.recovery_required);
        Ok(())
    }

    #[test]
    fn native_plain_reader_floor_cannot_be_downgraded_by_publication_or_restore() -> TestResult {
        let files = Root::new();
        let mut service = files.service()?;
        let (key, admin) = crate::service::tests::bootstrap_pre141_unmounted(&mut service)?;
        let _key = Zeroizing::new(key);
        let _admin = Zeroizing::new(admin);
        let mut current = service.state.as_ref().ok_or("actual state")?.clone();
        current.schema = NATIVE_PLAIN_NAMESPACE_STATE_SCHEMA;
        let mut lower = current.clone();
        lower.schema = NATIVE_PLAIN_NAMESPACE_STATE_SCHEMA - 1;
        assert!(lower.validate_publication_schema(Some(&current)).is_err());
        let error = Service::validate_snapshot_protected_floor(&current, &lower)
            .err()
            .ok_or("restore must reject reader downgrade")?;
        assert_eq!(error.status, 400);
        assert_eq!(
            error.body["errors"][0],
            "snapshot would downgrade native child namespace ownership"
        );
        Ok(())
    }
}
