use super::*;
use std::collections::{BTreeMap, BTreeSet};

const MAX_NAMESPACE_COUNT: usize = 1024;
const MAX_NAMESPACE_METADATA: usize = 64;
const MAX_METADATA_KEY_BYTES: usize = 128;
const MAX_METADATA_VALUE_BYTES: usize = 1024;

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct NamespaceRegistry {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    entries: BTreeMap<String, NamespaceEntry>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    next_incarnation: BTreeMap<String, u64>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespaceEntry {
    id: String,
    incarnation: u64,
    /// Operational namespace seal state. The namespace owner remains encrypted
    /// by the server barrier; this flag fences request routing until an
    /// authorized ancestor explicitly unseals it. A separate per-namespace
    /// custody key hierarchy is intentionally not claimed by this bounded
    /// profile.
    #[serde(default, skip_serializing_if = "is_false")]
    sealed: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    custom_metadata: BTreeMap<String, String>,
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

fn create_metadata(body: &Value) -> Result<(BTreeMap<String, String>, bool), Response> {
    let object = body
        .as_object()
        .ok_or_else(|| Response::error(400, "namespace request body must be an object"))?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "custom_metadata" | "seal"))
    {
        return Err(Response::error(400, "unsupported namespace parameter"));
    }
    if let Some(value) = object.get("seal")
        && !value.is_boolean()
    {
        return Err(Response::error(400, "seal must be boolean"));
    }
    let sealed = object.get("seal").and_then(Value::as_bool).unwrap_or(false);
    let Some(metadata) = object.get("custom_metadata") else {
        return Ok((BTreeMap::new(), sealed));
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
    Ok((out, sealed))
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
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.next_incarnation.is_empty()
    }

    pub(super) fn contains(&self, path: &str) -> bool {
        path.is_empty() || self.entries.contains_key(path)
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
        if self.entries.len() > MAX_NAMESPACE_COUNT
            || self.next_incarnation.len() > MAX_NAMESPACE_COUNT.saturating_mul(2)
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
                sealed: false,
                custom_metadata: BTreeMap::new(),
            },
        );
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
                sealed,
                custom_metadata: metadata,
            },
        );
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

    fn set_sealed(&mut self, path: &str, sealed: bool) -> Result<(), Response> {
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
        self.next_incarnation.insert(path, next);
        Ok(())
    }

    fn read(&self, base: &str, path: &str) -> Result<Response, Response> {
        let entry = self
            .entries
            .get(path)
            .ok_or_else(|| Response::error(404, "namespace not found"))?;
        let relative = relative_path(base, path)
            .ok_or_else(|| Response::error(404, "namespace is outside request scope"))?;
        Ok(Response::ok(json!({
            "id": entry.id,
            "path": format!("{relative}/"),
            "sealed": entry.sealed,
            "custom_metadata": entry.custom_metadata,
        })))
    }

    fn list(&self, base: &str, recursive: bool) -> Response {
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
                    json!({
                        "id": entry.id,
                        "path": key,
                        "sealed": entry.sealed,
                        "custom_metadata": entry.custom_metadata,
                    }),
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

    fn namespace_payload_is_empty(&self, path: &str) -> bool {
        self.auth.namespace_is_empty(path)
            && self.engines.namespace_is_empty(path)
            && self.database.namespace_is_empty(path)
    }
}

impl Service {
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
        if request.wrap_ttl_seconds.is_some() {
            return Response::error(501, "namespace management responses cannot be wrapped");
        }
        let capability = match request.method {
            "GET" | "HEAD" => "read",
            "LIST" | "SCAN" => "list",
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
                "LIST" => state.namespaces.list(request.namespace, false),
                "SCAN" => state.namespaces.list(request.namespace, true),
                _ => Response::error(405, "namespace path is required"),
            };
        }
        for operation in ["seal", "unseal", "seal-status"] {
            let Some(target) = suffix.strip_suffix(&format!("/{operation}")) else {
                continue;
            };
            let target = match join_path(request.namespace, target) {
                Ok(path) => path,
                Err(error) => return error,
            };
            if target.is_empty() {
                return Response::error(400, "root namespace cannot be sealed");
            }
            let Some(current) = state
                .namespaces
                .entries
                .get(&target)
                .map(|entry| entry.sealed)
            else {
                return Response::error(404, "namespace not found");
            };
            if operation == "seal-status" {
                if request.method != "GET" && request.method != "HEAD" {
                    return Response::error(405, "namespace seal-status requires GET");
                }
                if request.body.as_object().is_none_or(|body| !body.is_empty()) {
                    return Response::error(
                        400,
                        "namespace seal-status accepts an empty request body",
                    );
                }
                return Response::ok(json!({
                    "id": state.namespaces.entries[&target].id,
                    "path": format!("{target}/"),
                    "sealed": current,
                    "effective_sealed": state.namespaces.is_sealed(&target),
                }));
            }
            if !matches!(request.method, "POST" | "PUT") {
                return Response::error(405, "namespace seal operations require POST or PUT");
            }
            if request.body.as_object().is_none_or(|body| !body.is_empty()) {
                return Response::error(
                    400,
                    "namespace seal operations accept an empty request body",
                );
            }
            let sealed = operation == "seal";
            if current == sealed {
                return Response::ok(json!({"sealed": current}));
            }
            if let Err(error) = state.namespaces.set_sealed(&target, sealed) {
                return error;
            }
            state.schema = CURRENT_STATE_SCHEMA;
            if let Err(error) = state.validate_format() {
                return error;
            }
            if let Err(error) = self.commit_state(&state) {
                return error;
            }
            self.state = Some(state);
            return Response {
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
                    .read(request.namespace, &target)
                    .unwrap_or_else(|error| error)
            }
            "POST" | "PUT" => {
                let parent = parent_path(&target).to_owned();
                if !state.namespace_exists(&parent) {
                    return Response::error(404, "parent namespace not found");
                }
                let (metadata, sealed) = match create_metadata(request.body) {
                    Ok(metadata) => metadata,
                    Err(error) => return error,
                };
                if let Err(error) =
                    state
                        .namespaces
                        .create(&state.cluster_id, &target, metadata, sealed)
                {
                    return error;
                }
                if let Err(error) = state.auth.initialize_fresh_namespace_auth(&target) {
                    return Response::error(error.status, &error.message);
                }
                state.schema = CURRENT_STATE_SCHEMA;
                if let Err(error) = state.validate_format() {
                    return error;
                }
                if let Err(error) = self.commit_state(&state) {
                    return error;
                }
                self.state = Some(state);
                Response {
                    status: 204,
                    body: Value::Null,
                }
            }
            "PATCH" => {
                if let Err(error) = state.namespaces.patch(&target, request.body) {
                    return error;
                }
                state.schema = CURRENT_STATE_SCHEMA;
                if let Err(error) = state.validate_format() {
                    return error;
                }
                if let Err(error) = self.commit_state(&state) {
                    return error;
                }
                self.state = Some(state);
                Response {
                    status: 204,
                    body: Value::Null,
                }
            }
            "DELETE" => {
                if request.body.as_object().is_none_or(|body| !body.is_empty()) {
                    return Response::error(400, "namespace delete accepts an empty request body");
                }
                if !state.namespace_payload_is_empty(&target) {
                    return Response::error(
                        409,
                        "namespace contains runtime state; owned cleanup is required before deletion",
                    );
                }
                if let Err(error) = state.namespaces.remove(&target) {
                    return error;
                }
                state.auth.remove_fresh_namespace_auth_defaults(&target);
                state.schema = CURRENT_STATE_SCHEMA;
                if let Err(error) = state.validate_format() {
                    return error;
                }
                if let Err(error) = self.commit_state(&state) {
                    return error;
                }
                self.state = Some(state);
                Response {
                    status: 204,
                    body: Value::Null,
                }
            }
            _ => Response::error(405, "unsupported namespace method"),
        }
    }
}

#[cfg(test)]
#[path = "service_namespace_tests.rs"]
mod tests;
