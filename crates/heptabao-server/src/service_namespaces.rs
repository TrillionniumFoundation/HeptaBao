use super::*;
use std::collections::{BTreeMap, BTreeSet};
#[path = "service_namespace_batch.rs"]
mod batch_lifecycle;

const MAX_NAMESPACE_COUNT: usize = 1024;
const MAX_NAMESPACE_METADATA: usize = 64;
const MAX_METADATA_KEY_BYTES: usize = 128;
const MAX_METADATA_VALUE_BYTES: usize = 1024;

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct NamespaceRegistry {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    entries: BTreeMap<String, NamespaceEntry>,
    /// Sticky actual lifecycle, independent of encrypted catalog hydration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    batch_lifecycle: Option<crate::auth::batch_namespace::Registry>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    next_incarnation: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    retired_custody: BTreeMap<String, crate::namespace_custody::Tombstone>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    custody_frontiers: BTreeMap<String, crate::namespace_custody::Frontier>,
    /// Private candidate-owner selection. These verifiers never authenticate
    /// an actor, reveal a catalog entry or grant an unloaded key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    closed_auth_routes: BTreeMap<String, crate::namespace_custody::Binding>,
    #[serde(default, skip_serializing_if = "workflows::WorkflowState::is_empty")]
    pub(super) workflows: workflows::WorkflowState,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespaceEntry {
    id: String,
    incarnation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custody: Option<crate::namespace_custody::Descriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inherited: Option<crate::namespace_custody::InheritedDescriptor>,
    /// Runtime routing projection. An independent custody descriptor is always
    /// persisted sealed; only a process-local authenticated slot opens it.
    #[serde(default, skip_serializing_if = "is_false")]
    sealed: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    custom_metadata: BTreeMap<String, String>,
}

/// Descendant catalog metadata is owned by the longest independent barrier.
/// Its typed parcel is encrypted together with the real descendants' assets;
/// closing a parent removes these entries from the active routing catalog.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CatalogAssets {
    namespace: String,
    entries: BTreeMap<String, NamespaceEntry>,
    next_incarnation: BTreeMap<String, u64>,
    retired_custody: BTreeMap<String, crate::namespace_custody::Tombstone>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

pub(super) fn owns(path: &str) -> bool {
    path == "sys/namespaces" || path.starts_with("sys/namespaces/")
}

fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 128
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
}

fn canonical_path(value: &str) -> Result<String, Response> {
    let value = value.trim_end_matches('/');
    if value.is_empty()
        || value.len() > 512
        || value.starts_with('/')
        || value.contains("//")
        || value.split('/').any(|segment| !valid_segment(segment))
    {
        return Err(Response::error(400, "invalid namespace path"));
    }
    Ok(value.to_owned())
}

fn parent_path(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

fn join_path(base: &str, relative: &str) -> Result<String, Response> {
    let relative = canonical_path(relative)?;
    if base.is_empty() {
        Ok(relative)
    } else {
        canonical_path(&format!("{base}/{relative}"))
    }
}

fn relative_path<'a>(base: &str, absolute: &'a str) -> Option<&'a str> {
    if base.is_empty() {
        Some(absolute)
    } else {
        absolute.strip_prefix(base)?.strip_prefix('/')
    }
}

fn namespace_id(cluster_id: &str, path: &str, incarnation: u64) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let binding = format!("heptabao-namespace-v1\0{cluster_id}\0{path}\0{incarnation}");
    let digest = crypto::digest(binding.as_bytes());
    digest
        .iter()
        .take(5)
        .map(|byte| char::from(ALPHABET[usize::from(*byte) % ALPHABET.len()]))
        .collect()
}

/// Public UUID is a stable projection of the existing durable incarnation.
/// It is not an authority token and never rewrites legacy namespace IDs/state.
fn namespace_metadata(cluster_id: &str, path: &str, entry: &NamespaceEntry) -> Value {
    let binding = format!(
        "heptabao-namespace-uuid-v1\0{cluster_id}\0{path}\0{}",
        entry.incarnation
    );
    let digest = crypto::digest(binding.as_bytes());
    let hex: String = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    );
    json!({
        "id": entry.id, "uuid": uuid, "path": format!("{path}/"),
        "locked": false, "tainted": false, "custom_metadata": entry.custom_metadata,
    })
}

fn validate_metadata_value(key: &str, value: &str) -> Result<(), Response> {
    if key.is_empty()
        || key.len() > MAX_METADATA_KEY_BYTES
        || value.len() > MAX_METADATA_VALUE_BYTES
        || key.chars().any(char::is_control)
        || value.chars().any(char::is_control)
    {
        return Err(Response::error(
            400,
            "namespace custom metadata is outside bounds",
        ));
    }
    Ok(())
}

fn create_metadata(body: &Value) -> Result<BTreeMap<String, String>, Response> {
    let object = body
        .as_object()
        .ok_or_else(|| Response::error(400, "namespace request body must be an object"))?;
    let Some(metadata) = object.get("custom_metadata") else {
        return Ok(BTreeMap::new());
    };
    let metadata = metadata
        .as_object()
        .ok_or_else(|| Response::error(400, "custom_metadata must be a string map"))?;
    if metadata.len() > MAX_NAMESPACE_METADATA {
        return Err(Response::error(400, "too many namespace metadata entries"));
    }
    let mut out = BTreeMap::new();
    for (key, value) in metadata {
        let value = value
            .as_str()
            .ok_or_else(|| Response::error(400, "custom_metadata values must be strings"))?;
        validate_metadata_value(key, value)?;
        out.insert(key.clone(), value.to_owned());
    }
    Ok(out)
}

fn patch_metadata(current: &mut BTreeMap<String, String>, body: &Value) -> Result<(), Response> {
    let object = body
        .as_object()
        .ok_or_else(|| Response::error(400, "namespace request body must be an object"))?;
    if object.keys().any(|key| key != "custom_metadata") {
        return Err(Response::error(
            400,
            "unsupported namespace patch parameter",
        ));
    }
    let metadata = object
        .get("custom_metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| Response::error(400, "custom_metadata merge patch is required"))?;
    if metadata.len() > MAX_NAMESPACE_METADATA {
        return Err(Response::error(400, "too many namespace metadata entries"));
    }
    for (key, value) in metadata {
        if value.is_null() {
            current.remove(key);
            continue;
        }
        let value = value.as_str().ok_or_else(|| {
            Response::error(400, "custom_metadata patch values must be strings or null")
        })?;
        validate_metadata_value(key, value)?;
        current.insert(key.clone(), value.to_owned());
    }
    if current.len() > MAX_NAMESPACE_METADATA {
        return Err(Response::error(400, "too many namespace metadata entries"));
    }
    Ok(())
}

impl NamespaceRegistry {
    pub(super) fn capture_closed_auth_routes(
        &mut self,
        binding: &crate::namespace_custody::Binding,
        verifiers: Vec<String>,
    ) -> Result<(), Response> {
        let mut candidate = self.closed_auth_routes.clone();
        candidate.retain(|_, owner| owner.namespace() != binding.namespace());
        for verifier in verifiers {
            if candidate
                .get(&verifier)
                .is_some_and(|owner| owner != binding)
            {
                return Err(Response::error(
                    503,
                    "conflicting closed auth candidate owner",
                ));
            }
            candidate.insert(verifier, binding.clone());
        }
        if candidate.len() > 4096 {
            return Err(Response::error(
                507,
                "closed auth candidate capacity exhausted",
            ));
        }
        self.closed_auth_routes = candidate;
        Ok(())
    }

    pub(super) fn closed_auth_route(
        &self,
        verifier: &str,
    ) -> Option<&crate::namespace_custody::Binding> {
        self.closed_auth_routes.get(verifier)
    }

    pub(super) fn validate_record_custody_binding(
        &self,
        binding: &crate::namespace_custody::Binding,
    ) -> Result<(), Response> {
        if self
            .custody_frontiers
            .get(binding.namespace())
            .is_none_or(|floor| !floor.matches_binding(binding))
        {
            return Err(Response::error(
                503,
                "namespace opaque record owner has no matching durable floor",
            ));
        }
        Ok(())
    }

    pub(super) fn has_custody_state(&self) -> bool {
        !self.retired_custody.is_empty()
            || !self.custody_frontiers.is_empty()
            || self
                .entries
                .values()
                .any(|entry| entry.custody.is_some() || entry.inherited.is_some())
    }

    pub(super) fn install_custody_owner(
        &mut self,
        cluster_id: &str,
        actual: &str,
        descriptor: crate::namespace_custody::Descriptor,
    ) -> Result<(), Response> {
        let binding = self.custody_binding(cluster_id, actual)?;
        descriptor
            .validate(&binding)
            .map_err(|_| Response::error(503, "namespace ciphertext owner is invalid"))?;
        let frontier = descriptor.frontier();
        if self
            .custody_frontiers
            .get(actual)
            .is_some_and(|old| !old.admits(&frontier))
        {
            return Err(Response::error(
                503,
                "namespace ciphertext durable floor cannot decrease",
            ));
        }
        let entry = self.entries.get_mut(actual).ok_or_else(|| {
            Response::error(503, "namespace ciphertext catalog owner disappeared")
        })?;
        if entry.inherited.is_some() {
            return Err(Response::error(503, "namespace custody kind cannot change"));
        }
        if entry
            .custody
            .as_ref()
            .is_some_and(|old| !old.admits_successor(&descriptor))
        {
            return Err(Response::error(
                503,
                "namespace ciphertext frontier cannot decrease",
            ));
        }
        entry.custody = Some(descriptor);
        self.custody_frontiers.insert(actual.to_owned(), frontier);
        Ok(())
    }

    pub(super) fn custody_owner(
        &self,
        actual: &str,
    ) -> Option<&crate::namespace_custody::Descriptor> {
        self.entries.get(actual)?.custody.as_ref()
    }

    pub(super) fn inherited_owner(
        &self,
        actual: &str,
    ) -> Option<&crate::namespace_custody::InheritedDescriptor> {
        self.entries.get(actual)?.inherited.as_ref()
    }

    pub(super) fn matches_inherited_frontier(
        &self,
        actual: &str,
        owner: &crate::namespace_custody::InheritedDescriptor,
    ) -> bool {
        self.custody_frontiers.get(actual) == Some(&owner.frontier())
    }

    pub(super) fn install_inherited_owner(
        &mut self,
        cluster_id: &str,
        actual: &str,
        descriptor: crate::namespace_custody::InheritedDescriptor,
    ) -> Result<(), Response> {
        let binding = self.custody_binding(cluster_id, actual)?;
        descriptor
            .validate(&binding)
            .map_err(|_| Response::error(503, "invalid inherited owner"))?;
        let frontier = descriptor.frontier();
        if self
            .custody_frontiers
            .get(actual)
            .is_some_and(|old| !old.admits(&frontier))
        {
            return Err(Response::error(
                503,
                "inherited durable floor cannot decrease",
            ));
        }
        let entry = self
            .entries
            .get_mut(actual)
            .ok_or_else(|| Response::error(503, "inherited owner is absent"))?;
        if entry.custody.is_some()
            || entry
                .inherited
                .as_ref()
                .is_some_and(|old| !old.admits_successor(&descriptor))
        {
            return Err(Response::error(
                503,
                "namespace inherited owner cannot change or regress",
            ));
        }
        entry.inherited = Some(descriptor);
        self.custody_frontiers.insert(actual.to_owned(), frontier);
        Ok(())
    }
    pub(super) fn legacy_ordinary_sealed_paths(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(_, entry)| {
                entry.sealed && entry.custody.is_none() && entry.inherited.is_none()
            })
            .map(|(path, _)| path.clone())
            .collect()
    }

    pub(super) fn inherited_paths(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.inherited.is_some())
            .map(|(path, _)| path.clone())
            .collect()
    }

    pub(super) fn closest_independent_ancestor(&self, actual: &str) -> Option<&str> {
        self.entries
            .iter()
            .filter(|(path, entry)| {
                entry.custody.is_some()
                    && actual
                        .strip_prefix(path.as_str())
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
            .map(|(path, _)| path.as_str())
            .max_by_key(|path| path.len())
    }

    pub(super) fn identity_namespace<'a>(
        &'a self,
        actual: &'a str,
    ) -> Result<crate::engines::IdentityNamespace<'a>, Response> {
        let id = if actual.is_empty() {
            None
        } else {
            Some(
                self.entries
                    .get(actual)
                    .ok_or_else(|| Response::error(503, "identity namespace binding is absent"))?
                    .id
                    .as_str(),
            )
        };
        Ok(crate::engines::IdentityNamespace { path: actual, id })
    }

    pub(super) fn custody_binding(
        &self,
        cluster_id: &str,
        actual: &str,
    ) -> Result<crate::namespace_custody::Binding, Response> {
        let entry = self
            .entries
            .get(actual)
            .ok_or_else(|| Response::error(503, "namespace custody owner is absent"))?;
        crate::namespace_custody::Binding::new(
            cluster_id.to_owned(),
            actual.to_owned(),
            entry.id.clone(),
            entry.incarnation,
        )
        .map_err(|_| Response::error(503, "namespace custody binding is invalid"))
    }
    pub(super) fn partition_paths(&self, actual: &str) -> Result<Vec<String>, Response> {
        if actual.is_empty() || !self.entries.contains_key(actual) {
            return Err(Response::error(503, "namespace partition owner is absent"));
        }
        let prefix = format!("{actual}/");
        Ok(self
            .entries
            .keys()
            .filter(|path| path.as_str() == actual || path.starts_with(&prefix))
            .cloned()
            .collect())
    }

    pub(super) fn detach_catalog(&mut self, actual: &str) -> Result<CatalogAssets, Response> {
        let paths = self.partition_paths(actual)?;
        let mut entries = BTreeMap::new();
        for path in paths.into_iter().filter(|path| path != actual) {
            let entry = self
                .entries
                .remove(&path)
                .ok_or_else(|| Response::error(503, "namespace catalog disappeared"))?;
            entries.insert(path, entry);
        }
        let next_incarnation = BTreeMap::new();
        let retired_custody = BTreeMap::new();
        Ok(CatalogAssets {
            namespace: actual.to_owned(),
            entries,
            next_incarnation,
            retired_custody,
        })
    }

    pub(super) fn attach_catalog(
        &mut self,
        actual: &str,
        assets: CatalogAssets,
    ) -> Result<(), Response> {
        let prefix = format!("{actual}/");
        if actual.is_empty()
            || assets.namespace != actual
            || !self.entries.contains_key(actual)
            || assets
                .entries
                .keys()
                .any(|path| !path.starts_with(&prefix) || self.entries.contains_key(path))
            || assets
                .next_incarnation
                .keys()
                .any(|path| !path.starts_with(&prefix) || self.next_incarnation.contains_key(path))
            || assets
                .retired_custody
                .keys()
                .any(|path| !path.starts_with(&prefix) || self.retired_custody.contains_key(path))
        {
            return Err(Response::error(
                503,
                "namespace child catalog binding or collision rejected",
            ));
        }
        self.entries.extend(assets.entries);
        self.next_incarnation.extend(assets.next_incarnation);
        self.retired_custody.extend(assets.retired_custody);
        Ok(())
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
            && self.batch_lifecycle.is_none()
            && self.next_incarnation.is_empty()
            && self.retired_custody.is_empty()
            && self.custody_frontiers.is_empty()
            && self.closed_auth_routes.is_empty()
            && self.workflows.is_empty()
    }

    pub(super) fn contains(&self, path: &str) -> bool {
        path.is_empty() || self.entries.contains_key(path)
    }

    pub(super) fn incarnation(&self, path: &str) -> Option<u64> {
        if path.is_empty() {
            Some(0)
        } else {
            self.entries.get(path).map(|entry| entry.incarnation)
        }
    }

    pub(super) fn retires_namespace_incarnation(&self, previous: &Self, path: &str) -> bool {
        let Some(old) = previous
            .incarnation(path)
            .filter(|incarnation| *incarnation != 0)
        else {
            return false;
        };
        self.next_incarnation
            .get(path)
            .is_some_and(|next| *next > old)
            && self.incarnation(path).is_none_or(|current| current > old)
    }

    pub(super) fn is_sealed(&self, path: &str) -> bool {
        if path.is_empty() {
            return false;
        }
        let mut current = path;
        loop {
            if self.entries.get(current).is_some_and(|entry| entry.sealed) {
                return true;
            }
            let Some(parent) = current.rsplit_once('/').map(|(parent, _)| parent) else {
                return false;
            };
            current = parent;
        }
    }

    pub(super) fn has_sealed_state(&self) -> bool {
        self.entries.values().any(|entry| entry.sealed)
    }

    pub(super) fn validate(&self, cluster_id: &str) -> Result<(), Response> {
        self.validate_batch_lifecycle(cluster_id)?;
        if self.entries.len() > MAX_NAMESPACE_COUNT
            || self.next_incarnation.len() > MAX_NAMESPACE_COUNT.saturating_mul(2)
            || self.retired_custody.len() > MAX_NAMESPACE_COUNT.saturating_mul(2)
            || self.custody_frontiers.len() > MAX_NAMESPACE_COUNT.saturating_mul(2)
            || self.closed_auth_routes.len() > 4096
        {
            return Err(Response::error(503, "namespace catalog exceeds bounds"));
        }
        for (path, entry) in &self.entries {
            canonical_path(path)
                .map_err(|_| Response::error(503, "invalid namespace catalog path"))?;
            let parent = parent_path(path);
            if !parent.is_empty() && !self.entries.contains_key(parent) {
                return Err(Response::error(503, "namespace catalog parent is absent"));
            }
            if entry.incarnation == 0
                || entry.id != namespace_id(cluster_id, path, entry.incarnation)
                || entry.custom_metadata.len() > MAX_NAMESPACE_METADATA
            {
                return Err(Response::error(503, "invalid namespace catalog entry"));
            }
            if let Some(descriptor) = &entry.custody {
                if entry.inherited.is_some() {
                    return Err(Response::error(
                        503,
                        "namespace has conflicting custody kinds",
                    ));
                }
                let binding = self.custody_binding(cluster_id, path)?;
                descriptor
                    .validate(&binding)
                    .map_err(|_| Response::error(503, "invalid namespace ciphertext descriptor"))?;
                if self.custody_frontiers.get(path) != Some(&descriptor.frontier()) {
                    return Err(Response::error(
                        503,
                        "namespace active descriptor differs from durable floor",
                    ));
                }
            }
            if let Some(descriptor) = &entry.inherited {
                if entry.sealed {
                    return Err(Response::error(
                        503,
                        "inherited owner cannot use an independent seal flag",
                    ));
                }
                let binding = self.custody_binding(cluster_id, path)?;
                descriptor
                    .validate(&binding)
                    .map_err(|_| Response::error(503, "invalid inherited ciphertext descriptor"))?;
                if self.custody_frontiers.get(path) != Some(&descriptor.frontier()) {
                    return Err(Response::error(
                        503,
                        "inherited descriptor differs from durable floor",
                    ));
                }
            }
            for (key, value) in &entry.custom_metadata {
                validate_metadata_value(key, value)
                    .map_err(|_| Response::error(503, "invalid namespace catalog metadata"))?;
            }
            if self
                .next_incarnation
                .get(path)
                .is_some_and(|next| *next <= entry.incarnation)
            {
                return Err(Response::error(
                    503,
                    "namespace incarnation frontier is stale",
                ));
            }
        }
        for (path, next) in &self.next_incarnation {
            canonical_path(path)
                .map_err(|_| Response::error(503, "invalid namespace tombstone path"))?;
            if *next == 0 {
                return Err(Response::error(
                    503,
                    "invalid namespace incarnation frontier",
                ));
            }
        }
        for (path, retired) in &self.retired_custody {
            let next = self.next_incarnation.get(path).copied().ok_or_else(|| {
                Response::error(
                    503,
                    "namespace custody retirement has no incarnation frontier",
                )
            })?;
            retired
                .validate(cluster_id, path, next)
                .map_err(|_| Response::error(503, "invalid retired namespace custody frontier"))?;
        }
        for (path, frontier) in &self.custody_frontiers {
            canonical_path(path)
                .map_err(|_| Response::error(503, "invalid namespace custody floor path"))?;
            frontier
                .validate(
                    cluster_id,
                    path,
                    &namespace_id(cluster_id, path, frontier.incarnation()),
                )
                .map_err(|_| Response::error(503, "invalid namespace custody durable floor"))?;
            if let Some(retired) = self.retired_custody.get(path)
                && frontier.is_retired()
                && frontier.incarnation().checked_add(1) == self.next_incarnation.get(path).copied()
                && !frontier.matches_retirement(retired)
            {
                return Err(Response::error(
                    503,
                    "namespace retired descriptor differs from durable floor",
                ));
            }
        }
        for (verifier, binding) in &self.closed_auth_routes {
            let encoding = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let bytes = encoding
                .decode(verifier)
                .map_err(|_| Response::error(503, "invalid closed auth verifier"))?;
            if bytes.len() != 32 || encoding.encode(&bytes) != *verifier {
                return Err(Response::error(503, "noncanonical closed auth verifier"));
            }
            self.validate_record_custody_binding(binding)?;
        }
        self.workflows.validate()?;
        Ok(())
    }

    fn insert_legacy(&mut self, cluster_id: &str, path: &str) -> Result<bool, Response> {
        let path = canonical_path(path)?;
        if self.entries.contains_key(&path) {
            return Ok(false);
        }
        if self.entries.len() >= MAX_NAMESPACE_COUNT {
            return Err(Response::error(507, "namespace catalog capacity exhausted"));
        }
        // A new incarnation never inherits the old credential routing hints.
        self.closed_auth_routes
            .retain(|_, owner| owner.namespace() != path);
        let prior_frontier = self.next_incarnation.get(&path).copied();
        let incarnation = prior_frontier.unwrap_or(1);
        // A tombstone stores the next incarnation to issue. Once it is
        // consumed, advance the frontier again before publishing the entry;
        // otherwise validate() quite correctly rejects the live entry as
        // having a stale incarnation frontier on the same transaction.
        let next_frontier = prior_frontier
            .map(|frontier| {
                frontier
                    .checked_add(1)
                    .ok_or_else(|| Response::error(507, "namespace incarnation exhausted"))
            })
            .transpose()?;
        self.entries.insert(
            path.clone(),
            NamespaceEntry {
                id: namespace_id(cluster_id, &path, incarnation),
                incarnation,
                custody: None,
                inherited: None,
                sealed: false,
                custom_metadata: BTreeMap::new(),
            },
        );
        if let Some(lifecycle) = &mut self.batch_lifecycle {
            lifecycle
                .record_create(&path, incarnation, next_frontier)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        if let Some(next) = next_frontier {
            self.next_incarnation.insert(path, next);
        }
        Ok(true)
    }

    pub(super) fn adopt_legacy(
        &mut self,
        cluster_id: &str,
        paths: BTreeSet<String>,
    ) -> Result<bool, Response> {
        let mut expanded = BTreeSet::new();
        for path in paths {
            let canonical = canonical_path(&path)
                .map_err(|_| Response::error(503, "legacy namespace path is invalid"))?;
            let mut current = String::new();
            for segment in canonical.split('/') {
                if !current.is_empty() {
                    current.push('/');
                }
                current.push_str(segment);
                expanded.insert(current.clone());
            }
        }
        let mut changed = false;
        for path in expanded {
            changed |= self.insert_legacy(cluster_id, &path)?;
        }
        Ok(changed)
    }

    pub(super) fn validate_custody_successor(&self, previous: &Self) -> Result<(), Response> {
        match (&self.batch_lifecycle, &previous.batch_lifecycle) {
            (Some(next), Some(old)) => next
                .validate_successor(old)
                .map_err(|error| Response::error(error.status, &error.message))?,
            (None, Some(_)) => {
                return Err(Response::error(503, "namespace lifecycle cannot retire"));
            }
            _ => {}
        }
        for (path, old) in &previous.custody_frontiers {
            if self
                .custody_frontiers
                .get(path)
                .is_none_or(|next| !old.admits(next))
            {
                return Err(Response::error(
                    503,
                    "namespace custody publication frontier regressed",
                ));
            }
        }
        for (path, old) in &previous.retired_custody {
            if self
                .retired_custody
                .get(path)
                .is_none_or(|next| !old.admits(next))
            {
                return Err(Response::error(
                    503,
                    "namespace custody retirement frontier regressed",
                ));
            }
        }
        Ok(())
    }

    fn create(
        &mut self,
        cluster_id: &str,
        path: &str,
        metadata: BTreeMap<String, String>,
        sealed: bool,
    ) -> Result<(), Response> {
        let path = canonical_path(path)?;
        if self.entries.contains_key(&path) {
            return Err(Response::error(400, "namespace already exists"));
        }
        if self.entries.len() >= MAX_NAMESPACE_COUNT {
            return Err(Response::error(507, "namespace catalog capacity exhausted"));
        }
        // A new incarnation never inherits the old credential routing hints.
        self.closed_auth_routes
            .retain(|_, owner| owner.namespace() != path);
        let prior_frontier = self.next_incarnation.get(&path).copied();
        let incarnation = prior_frontier.unwrap_or(1);
        let next_frontier = prior_frontier
            .map(|frontier| {
                frontier
                    .checked_add(1)
                    .ok_or_else(|| Response::error(507, "namespace incarnation exhausted"))
            })
            .transpose()?;
        self.entries.insert(
            path.clone(),
            NamespaceEntry {
                id: namespace_id(cluster_id, &path, incarnation),
                incarnation,
                custody: None,
                inherited: None,
                sealed,
                custom_metadata: metadata,
            },
        );
        if let Some(lifecycle) = &mut self.batch_lifecycle {
            lifecycle
                .record_create(&path, incarnation, next_frontier)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        if let Some(next) = next_frontier {
            self.next_incarnation.insert(path, next);
        }
        Ok(())
    }

    fn patch(&mut self, path: &str, body: &Value) -> Result<(), Response> {
        let path = canonical_path(path)?;
        let entry = self
            .entries
            .get_mut(&path)
            .ok_or_else(|| Response::error(404, "namespace not found"))?;
        patch_metadata(&mut entry.custom_metadata, body)
    }

    pub(super) fn set_sealed(&mut self, path: &str, sealed: bool) -> Result<(), Response> {
        let path = canonical_path(path)?;
        let entry = self
            .entries
            .get_mut(&path)
            .ok_or_else(|| Response::error(404, "namespace not found"))?;
        entry.sealed = sealed;
        Ok(())
    }

    fn remove(&mut self, path: &str) -> Result<(), Response> {
        let path = canonical_path(path)?;
        let child_prefix = format!("{path}/");
        if self
            .entries
            .keys()
            .any(|candidate| candidate.starts_with(&child_prefix))
        {
            return Err(Response::error(409, "namespace has child namespaces"));
        }
        let entry = self
            .entries
            .remove(&path)
            .ok_or_else(|| Response::error(404, "namespace not found"))?;
        let next = entry
            .incarnation
            .checked_add(1)
            .ok_or_else(|| Response::error(507, "namespace incarnation exhausted"))?;
        if let Some(lifecycle) = &mut self.batch_lifecycle {
            lifecycle
                .record_remove(&path, entry.incarnation, next)
                .map_err(|error| Response::error(error.status, &error.message))?;
        }
        self.next_incarnation.insert(path.clone(), next);
        if let Some(custody) = entry.custody {
            self.custody_frontiers
                .insert(path.clone(), custody.frontier().retirement());
            self.retired_custody
                .insert(path.to_owned(), custody.retirement());
        }
        if let Some(custody) = entry.inherited {
            self.custody_frontiers
                .insert(path.clone(), custody.frontier().retirement());
            self.retired_custody
                .insert(path.to_owned(), custody.retirement());
        }
        Ok(())
    }

    fn read(&self, cluster_id: &str, base: &str, path: &str) -> Result<Response, Response> {
        let entry = self
            .entries
            .get(path)
            .ok_or_else(|| Response::error(404, "namespace not found"))?;
        relative_path(base, path)
            .ok_or_else(|| Response::error(404, "namespace is outside request scope"))?;
        Ok(Response::ok(
            json!({"data": namespace_metadata(cluster_id, path, entry)}),
        ))
    }

    fn list(&self, cluster_id: &str, base: &str, recursive: bool) -> Response {
        let mut keys = BTreeSet::new();
        let mut info = serde_json::Map::new();
        for path in self.entries.keys() {
            let Some(relative) = relative_path(base, path) else {
                continue;
            };
            if relative.is_empty() {
                continue;
            }
            let key = if recursive {
                format!("{relative}/")
            } else {
                format!("{}/", relative.split('/').next().unwrap_or(relative))
            };
            if !keys.insert(key.clone()) {
                continue;
            }
            let absolute = if base.is_empty() {
                key.trim_end_matches('/').to_owned()
            } else {
                format!("{base}/{}", key.trim_end_matches('/'))
            };
            if let Some(entry) = self.entries.get(&absolute) {
                info.insert(
                    key.clone(),
                    namespace_metadata(cluster_id, &absolute, entry),
                );
            }
        }
        Response::ok(json!({"data":{"keys":keys,"key_info":info}}))
    }
}

impl State {
    pub(super) fn namespace_exists(&self, path: &str) -> bool {
        if path.is_empty() || self.namespaces.contains(path) {
            return true;
        }
        self.schema < 9
            && (self.auth.known_namespaces().contains(path)
                || self.engines.known_namespaces().contains(path)
                || self.database.known_namespaces().contains(path))
    }

    pub(super) fn namespace_is_sealed(&self, path: &str) -> bool {
        self.namespaces.is_sealed(path)
    }

    pub(super) fn adopt_legacy_namespaces(&mut self) -> Result<bool, Response> {
        if self.schema >= 9 {
            return Ok(false);
        }
        let mut paths = self.auth.known_namespaces();
        paths.extend(self.engines.known_namespaces());
        paths.extend(self.database.known_namespaces());
        self.namespaces.adopt_legacy(&self.cluster_id, paths)
    }

    fn namespace_has_only_local_cleanup(&self, path: &str) -> bool {
        self.auth.namespace_has_only_local_token_owners(path)
            && self.engines.namespace_has_only_local_kv_owners(path)
            && self.database.namespace_is_empty(path)
            && self.namespaces.workflows.namespace_is_empty(path)
    }

    fn namespace_payload_is_empty(&self, path: &str) -> bool {
        self.auth.namespace_is_empty(path)
            && self.engines.namespace_is_empty(path)
            && self.database.namespace_is_empty(path)
            && self.namespaces.workflows.namespace_is_empty(path)
    }
}

impl Service {
    fn namespace_delete_gate(
        state: &State,
        principal: &Principal,
        request: &RequestView<'_>,
        caller_incarnation: u64,
        binding: &crate::namespace_custody::Binding,
        retired_floor: Option<&crate::namespace_custody::Frontier>,
    ) -> Result<(), Response> {
        namespace_runtime::request_live()?;
        let actual = binding.namespace();
        if state.namespaces.incarnation(request.namespace) != Some(caller_incarnation)
            || state.namespace_is_sealed(request.namespace)
            || state.namespaces.contains(actual)
            || binding.incarnation().checked_add(1)
                != state.namespaces.next_incarnation.get(actual).copied()
            || retired_floor.is_some_and(|floor| {
                !floor.matches_binding(binding)
                    || !floor.is_retired()
                    || state.namespaces.custody_frontiers.get(actual) != Some(floor)
                    || state
                        .namespaces
                        .retired_custody
                        .get(actual)
                        .is_none_or(|tombstone| !floor.matches_retirement(tombstone))
            })
        {
            return Err(Response::error(
                503,
                "namespace retirement owner or caller frontier changed",
            ));
        }
        state
            .auth
            .authorize_request(
                principal,
                request.namespace,
                request.path,
                "delete",
                external_pki::publication_now(request.now),
            )
            .map_err(|error| Response::error(error.status, &error.message))
    }

    fn namespace_custody_gate(
        state: &State,
        principal: &Principal,
        request: &RequestView<'_>,
        caller_incarnation: u64,
        actual: &str,
        binding: &crate::namespace_custody::Binding,
    ) -> Result<(), Response> {
        namespace_runtime::request_live()?;
        if state.namespaces.incarnation(request.namespace) != Some(caller_incarnation)
            || state.namespace_is_sealed(request.namespace)
            || state
                .namespaces
                .custody_binding(&state.cluster_id, actual)?
                != *binding
        {
            return Err(Response::error(
                503,
                "namespace custody owner or caller frontier changed",
            ));
        }
        state
            .auth
            .authorize_request(
                principal,
                request.namespace,
                request.path,
                "update",
                external_pki::publication_now(request.now),
            )
            .map_err(|error| Response::error(error.status, &error.message))
    }

    pub(super) fn namespace_route(
        &mut self,
        mut state: State,
        principal: Option<&Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        if !state.namespace_exists(request.namespace) {
            return Response::error(404, "request namespace not found");
        }
        if request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
            return Response::error(501, "namespace management responses cannot be wrapped");
        }
        let capability = match request.method {
            "GET" | "HEAD" => "read",
            "LIST" => "list",
            "SCAN" => "scan",
            "DELETE" => "delete",
            "PATCH" => "patch",
            "POST" | "PUT" => "update",
            _ => return Response::error(405, "unsupported namespace method"),
        };
        if let Err(error) = state.auth.authorize_request(
            principal,
            request.namespace,
            request.path,
            capability,
            request.now,
        ) {
            return Response::error(error.status, &error.message);
        }
        let Some(caller_incarnation) = state.namespaces.incarnation(request.namespace) else {
            return Response::error(404, "request namespace not found");
        };

        let suffix = request
            .path
            .strip_prefix("sys/namespaces")
            .unwrap_or_default()
            .trim_start_matches('/');
        if suffix.is_empty() {
            if request.body.as_object().is_none_or(|body| !body.is_empty()) {
                return Response::error(400, "namespace list accepts an empty request body");
            }
            return match request.method {
                "LIST" => state
                    .namespaces
                    .list(&state.cluster_id, request.namespace, false),
                "SCAN" => state
                    .namespaces
                    .list(&state.cluster_id, request.namespace, true),
                _ => Response::error(405, "namespace path is required"),
            };
        }
        for operation in ["seal", "unseal", "seal-status"] {
            let Some(target) = suffix.strip_suffix(&format!("/{operation}")) else {
                continue;
            };
            if target.contains('/') {
                return Response::error(400, "namespace name cannot contain /");
            }
            let target = match join_path(request.namespace, target) {
                Ok(path) => path,
                Err(error) => return error,
            };
            if target.is_empty() {
                return Response::error(400, "root namespace cannot be sealed");
            }
            if !state.namespaces.contains(&target) {
                return Response::error(500, "namespace does not exist");
            }
            if operation == "seal-status" {
                if request.method != "GET" && request.method != "HEAD" {
                    return Response::error(405, "namespace seal-status requires GET");
                }
                return self
                    .namespace_runtime
                    .status(&state, &target)
                    .unwrap_or_else(|error| error);
            }
            if !matches!(request.method, "POST" | "PUT") {
                return Response::error(405, "namespace seal operations require POST or PUT");
            }
            if operation == "unseal" {
                let binding = match state.namespaces.custody_binding(&state.cluster_id, &target) {
                    Ok(binding) => binding,
                    Err(error) => return error,
                };
                if let Err(error) = Self::namespace_custody_gate(
                    &state,
                    principal,
                    request,
                    caller_incarnation,
                    &target,
                    &binding,
                ) {
                    self.namespace_runtime.reset_progress(&target);
                    return error;
                }
                let reset = match request.body.get("reset") {
                    None | Some(Value::Null) => false,
                    Some(Value::Bool(value)) => *value,
                    Some(Value::String(value)) => match value.as_str() {
                        "true" | "1" => true,
                        "false" | "0" | "" => false,
                        _ => return Response::error(400, "invalid reset flag"),
                    },
                    Some(Value::Number(value)) => value.as_i64().is_some_and(|value| value != 0),
                    _ => return Response::error(400, "invalid reset flag"),
                };
                if reset {
                    self.namespace_runtime.reset_progress(&target);
                } else {
                    let key = match request.body.get("key") {
                        None => String::new(),
                        Some(value) => match namespace_config::weak_string(value) {
                            Some(value) => value,
                            None => return Response::error(400, "key must be a string"),
                        },
                    };
                    let key = zeroize::Zeroizing::new(key);
                    if key.is_empty() {
                        return Response::error(500, "provided key is empty");
                    }
                    let fragment =
                        match decode_hex(&key).or_else(|| STANDARD.decode(key.as_bytes()).ok()) {
                            Some(value) => zeroize::Zeroizing::new(value),
                            None => return Response::error(400, "invalid key encoding"),
                        };
                    match self
                        .namespace_runtime
                        .submit(&state, &target, &fragment, |candidate| {
                            Self::namespace_custody_gate(
                                candidate,
                                principal,
                                request,
                                caller_incarnation,
                                &target,
                                &binding,
                            )
                        }) {
                        Ok(Some(candidate)) => {
                            state = candidate;
                            let response = self
                                .namespace_runtime
                                .status(&state, &target)
                                .unwrap_or_else(|error| error);
                            self.state = Some(state);
                            return response;
                        }
                        Ok(None) => {}
                        Err(error) => return error,
                    }
                }
                return self
                    .namespace_runtime
                    .status(&state, &target)
                    .unwrap_or_else(|error| error);
            }
            if state.namespaces.custody_owner(&target).is_some() {
                if !state.namespaces.entries[&target].sealed {
                    state = match self.namespace_runtime.closed_candidate(&state, &target) {
                        Ok(candidate) => candidate,
                        Err(error) => return error,
                    };
                    if let Err(error) = self.commit_state(&mut state) {
                        return error;
                    }
                    // Publication precedes revocation. Failed commits keep the
                    // existing loaded owner and deliver no new runtime state.
                    self.namespace_runtime.close(&target);
                    self.state = Some(state);
                } else {
                    self.namespace_runtime.reset_progress(&target);
                }
            } else {
                let binding = match state.namespaces.custody_binding(&state.cluster_id, &target) {
                    Ok(binding) => binding,
                    Err(error) => return error,
                };
                if let Err(error) = Self::namespace_custody_gate(
                    &state,
                    principal,
                    request,
                    caller_incarnation,
                    &target,
                    &binding,
                ) {
                    return error;
                }
                let Some(root_key) = self.barrier_key.as_ref() else {
                    return Response::error(503, "actual barrier key is unavailable");
                };
                state = match self
                    .namespace_runtime
                    .inherited_closed_candidate(&state, &target, root_key)
                {
                    Ok(candidate) => candidate,
                    Err(error) => return error,
                };
                if let Err(error) = self.commit_state(&mut state) {
                    return error;
                }
                // Durable closure is authoritative even if the caller expires
                // after commit. Revoke all old slots and retain the closed state
                // before the final actor/deadline check releases an acknowledgement.
                self.namespace_runtime.close(&target);
                #[cfg(test)]
                external_pki::delay_after_publication_for_test();
                let late = Self::namespace_custody_gate(
                    &state,
                    principal,
                    request,
                    caller_incarnation,
                    &target,
                    &binding,
                );
                self.state = Some(state);
                if let Err(error) = late {
                    return error;
                }
            }
            return Response {
                response_headers: Default::default(),
                consistency_index: None,
                status: 204,
                body: Value::Null,
            };
        }
        if suffix == "delete-sealed" || suffix.ends_with("/delete-sealed") {
            return Response::error(
                501,
                "namespace delete-sealed recovery requires a dedicated key custody profile",
            );
        }
        // CRUD addresses one direct child in the authenticated namespace.
        // A slash in the suffix must not smuggle an ancestor-relative target.
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
                    .unwrap_or_else(|error| error)
            }
            "POST" | "PUT" => {
                if matches!(
                    suffix,
                    "root" | "sys" | "audit" | "auth" | "cubbyhole" | "identity"
                ) {
                    return Response::error(400, "reserved namespace name");
                }
                let parent = parent_path(&target).to_owned();
                if !state.namespace_exists(&parent) {
                    return Response::error(404, "parent namespace not found");
                }
                let metadata = match create_metadata(request.body) {
                    Ok(metadata) => metadata,
                    Err(error) => return error,
                };
                let seal = match namespace_config::parse(request.body) {
                    Ok(seal) => seal,
                    Err(error) => return error,
                };
                // Pure historical catalog creation does not invent a batch
                // ledger. An existing ledger must remain synchronized below.
                if state.namespaces.batch_lifecycle.is_some()
                    && let Err(error) = state.ensure_namespace_batch_registry()
                {
                    return error;
                }
                let exists = state.namespaces.contains(&target);
                if exists {
                    if seal.is_some() {
                        return Response::error(
                            400,
                            "namespace seal configuration cannot be changed",
                        );
                    }
                    let Some(entry) = state.namespaces.entries.get_mut(&target) else {
                        return Response::error(503, "namespace catalog owner disappeared");
                    };
                    entry.custom_metadata = metadata;
                } else {
                    if let Err(error) =
                        state
                            .namespaces
                            .create(&state.cluster_id, &target, metadata, false)
                    {
                        return error;
                    }
                    if let Err(error) = state.auth.initialize_fresh_namespace_auth(&target) {
                        return Response::error(error.status, &error.message);
                    }
                    state.engines.ensure_empty_namespace(&target);
                }
                if state.namespaces.batch_lifecycle.is_some()
                    && let Err(error) = state.sync_namespace_batch_registry()
                {
                    return error;
                }
                let mut shares = None;
                let mut threshold = 0;
                let binding = match state.namespaces.custody_binding(&state.cluster_id, &target) {
                    Ok(binding) => binding,
                    Err(error) => return error,
                };
                if let Err(error) = Self::namespace_custody_gate(
                    &state,
                    principal,
                    request,
                    caller_incarnation,
                    &target,
                    &binding,
                ) {
                    return error;
                }
                if let Some(config) = seal {
                    match namespace_runtime::Runtime::fresh_candidate(
                        &state,
                        &target,
                        config.shares,
                        config.threshold,
                    ) {
                        Ok(fresh) => {
                            state = fresh.candidate;
                            shares = Some(fresh.shares);
                            threshold = config.threshold;
                        }
                        Err(error) => return error,
                    }
                }
                state.schema = state.writer_schema();
                if let Err(error) = state.validate_format() {
                    return error;
                }
                if let Err(error) = Self::namespace_custody_gate(
                    &state,
                    principal,
                    request,
                    caller_incarnation,
                    &target,
                    &binding,
                ) {
                    return error;
                }
                if let Err(error) = self.commit_state(&mut state) {
                    return error;
                }
                #[cfg(test)]
                external_pki::delay_after_publication_for_test();
                if let Err(error) = Self::namespace_custody_gate(
                    &state,
                    principal,
                    request,
                    caller_incarnation,
                    &target,
                    &binding,
                ) {
                    // Publication may have completed while the caller's original
                    // deadline elapsed. Keep the durable closed owner, but drop
                    // private candidate shares and return no new authority.
                    self.state = Some(state);
                    return error;
                }
                let mut response = state
                    .namespaces
                    .read(&state.cluster_id, request.namespace, &target)
                    .unwrap_or_else(|error| error);
                if let Some(shares) = shares {
                    response.body["data"]["key_shares"] =
                        Value::Array(shares.iter().map(|part| Value::String(hex(part))).collect());
                    response.body["data"]["key_threshold"] = json!(threshold);
                }
                self.state = Some(state);
                response
            }
            "PATCH" => {
                if let Err(error) = state.namespaces.patch(&target, request.body) {
                    return error;
                }
                state.schema = state.writer_schema();
                if let Err(error) = state.validate_format() {
                    return error;
                }
                if let Err(error) = self.commit_state(&mut state) {
                    return error;
                }
                let response = state
                    .namespaces
                    .read(&state.cluster_id, request.namespace, &target)
                    .unwrap_or_else(|error| error);
                self.state = Some(state);
                response
            }
            "DELETE" => {
                if state.namespaces.inherited_owner(&target).is_some()
                    && !self.namespace_runtime.is_loaded(&target)
                {
                    return Response::error(
                        503,
                        "unloaded namespace requires owned delete-sealed cleanup",
                    );
                }
                if request.body.as_object().is_none_or(|body| !body.is_empty()) {
                    return Response::error(400, "namespace delete accepts an empty request body");
                }
                if !state.namespaces.contains(&target) {
                    // Terminal observation of an absent namespace is read-only.
                    return Response::ok(json!({"data": null}));
                }
                let populated = !state.namespace_payload_is_empty(&target);
                if populated && !state.namespace_has_only_local_cleanup(&target) {
                    return Response::error(
                        409,
                        "namespace contains runtime state; owned cleanup is required before deletion",
                    );
                }
                if let Err(error) = state.ensure_namespace_batch_registry() {
                    return error;
                }
                if !state.auth.namespace_batch_retirement_safe() {
                    return Response::error(
                        409,
                        "namespace deletion requires stateless batch incarnation retirement",
                    );
                }
                let binding = match state.namespaces.custody_binding(&state.cluster_id, &target) {
                    Ok(binding) => binding,
                    Err(error) => return error,
                };
                let custody = state.namespaces.custody_owner(&target).cloned();
                if custody.is_some() && state.namespaces.entries[&target].sealed {
                    return Response::error(
                        503,
                        "sealed namespace requires owned delete-sealed cleanup",
                    );
                }
                if self.namespace_runtime.has_loaded_within(&target) {
                    state = match self.namespace_runtime.closed_candidate(&state, &target) {
                        Ok(candidate) => candidate,
                        Err(error) => return error,
                    };
                }
                if populated
                    && state.namespaces.custody_owner(&target).is_none()
                    && state.namespaces.inherited_owner(&target).is_none()
                {
                    // An ordinary namespace has no independent runtime slot.
                    // Close its actual assets using the existing longest owner
                    // key before retiring any record or catalog entry.
                    let Some(root_key) = self.barrier_key.as_ref() else {
                        return Response::error(503, "actual barrier key is unavailable");
                    };
                    state = match self
                        .namespace_runtime
                        .inherited_closed_candidate(&state, &target, root_key)
                    {
                        Ok(candidate) => candidate,
                        Err(error) => return error,
                    };
                }
                let custody_binding = state
                    .namespaces
                    .custody_owner(&target)
                    .map(|owner| owner.binding().clone())
                    .or_else(|| {
                        state
                            .namespaces
                            .inherited_owner(&target)
                            .map(|owner| owner.binding().clone())
                    });
                // Pin the exact closed owner produced with its real owner key.
                // This floor is private retirement evidence, never a route grant.
                let retired_floor = custody_binding.as_ref().and_then(|_| {
                    state
                        .namespaces
                        .custody_frontiers
                        .get(&target)
                        .map(crate::namespace_custody::Frontier::retirement)
                });
                if let Some(binding) = custody_binding
                    && let Err(error) = state.engines.retire_namespace_record_cells(&binding)
                {
                    return Response::error(error.status, &error.message);
                }
                if let Err(error) = state.namespaces.remove(&target) {
                    return error;
                }
                if let Err(error) = state.sync_namespace_batch_registry() {
                    return error;
                }
                state.auth.remove_fresh_namespace_auth_defaults(&target);
                if let Err(error) = state.engines.remove_empty_namespace(&target) {
                    return Response::error(error.status, &error.message);
                }
                state.schema = state.writer_schema();
                if let Err(error) = state.validate_format() {
                    return error;
                }
                if let Err(error) = Self::namespace_delete_gate(
                    &state,
                    principal,
                    request,
                    caller_incarnation,
                    &binding,
                    retired_floor.as_ref(),
                ) {
                    return error;
                }
                if let Err(error) = self.commit_state(&mut state) {
                    return error;
                }
                self.namespace_runtime.close(&target);
                #[cfg(test)]
                external_pki::delay_after_publication_for_test();
                if let Err(error) = Self::namespace_delete_gate(
                    &state,
                    principal,
                    request,
                    caller_incarnation,
                    &binding,
                    retired_floor.as_ref(),
                ) {
                    // Successful retirement always destroys old loaded keys,
                    // even when the original caller can no longer receive ACK.
                    self.state = Some(state);
                    return error;
                }
                self.state = Some(state);
                // Native acknowledgement follows the actual loaded-key closure,
                // typed local owner removal and durable retirement. Provider
                // effects remain behind their existing cleanup transactions.
                Response::ok(json!({"data": {"status": "in-progress"}}))
            }
            _ => Response::error(405, "unsupported namespace method"),
        }
    }
}

#[cfg(test)]
#[path = "service_namespace_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "service_namespace_strong_http_tests.rs"]
mod strong_http_tests;
