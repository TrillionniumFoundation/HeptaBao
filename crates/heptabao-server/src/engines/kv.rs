use super::*;

const MAX_RETAINED_VERSIONS: u64 = 10_000;

fn metadata_cas_disabled(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub(super) struct Kv2 {
    config: Config,
    entries: BTreeMap<String, Entry>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct Config {
    max_versions: u64,
    cas_required: bool,
    #[serde(default, skip_serializing_if = "metadata_cas_disabled")]
    metadata_cas_required: bool,
    delete_version_after: u64,
}

impl Config {
    fn update(&mut self, body: &Value) -> Result<()> {
        if let Some(max) = optional_u64(body, "max_versions")? {
            if max > MAX_RETAINED_VERSIONS {
                return Err(bad("max_versions exceeds the supported retention bound"));
            }
            self.max_versions = max;
        }
        if let Some(cas_required) = optional_bool(body, "cas_required")? {
            self.cas_required = cas_required;
        }
        if let Some(required) = optional_bool(body, "metadata_cas_required")? {
            self.metadata_cas_required = required;
        }
        if let Some(after) = body.get("delete_version_after") {
            self.delete_version_after = duration_seconds(after)?;
        }
        Ok(())
    }

    fn json(&self) -> Value {
        json!({"max_versions":self.max_versions,"cas_required":self.cas_required,"metadata_cas_required":self.metadata_cas_required,"delete_version_after":format!("{}s",self.delete_version_after)})
    }
}

type Entry = CowValue<EntryState>;

#[derive(Clone, Serialize, Deserialize, Default)]
struct EntryState {
    config: Config,
    current_version: u64,
    #[serde(default, skip_serializing_if = "lease_clock_is_zero")]
    current_metadata_version: u64,
    oldest_version: u64,
    created_at: u64,
    updated_at: u64,
    custom_metadata: Option<BTreeMap<String, String>>,
    versions: BTreeMap<u64, Version>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Version {
    created_at: u64,
    deletion_at: Option<u64>,
    destroyed: bool,
    data: Option<SharedJson>,
}

impl Drop for EntryState {
    fn drop(&mut self) {
        if let Some(metadata) = self.custom_metadata.take() {
            for (mut key, mut value) in metadata {
                key.zeroize();
                value.zeroize();
            }
        }
    }
}

impl Version {
    fn metadata(&self, version: u64, custom_metadata: &Option<BTreeMap<String, String>>) -> Value {
        json!({"version":version,"created_time":timestamp(self.created_at),
            "deletion_time":self.deletion_at.map(timestamp).unwrap_or_default(),
            "destroyed":self.destroyed,"custom_metadata":custom_metadata})
    }

    fn readable(&self, now: u64) -> bool {
        !self.destroyed && self.data.is_some() && self.deletion_at.is_none_or(|at| now < at)
    }
}

impl Entry {
    fn new(now: u64) -> Self {
        Self::from(EntryState {
            config: Config::default(),
            current_version: 0,
            current_metadata_version: 0,
            oldest_version: 0,
            created_at: now,
            updated_at: now,
            custom_metadata: None,
            versions: BTreeMap::new(),
        })
    }
    fn metadata(&self) -> Value {
        let mut metadata = self.config.json();
        metadata["created_time"] = json!(timestamp(self.created_at));
        metadata["updated_time"] = json!(timestamp(self.updated_at));
        metadata["current_version"] = json!(self.current_version);
        metadata["current_metadata_version"] = json!(self.current_metadata_version);
        metadata["oldest_version"] = json!(self.oldest_version);
        metadata["custom_metadata"] = json!(self.custom_metadata);
        metadata["versions"] = Value::Object(self.versions.iter().map(|(version, value)| {
            (version.to_string(), json!({"created_time":timestamp(value.created_at),"deletion_time":value.deletion_at.map(timestamp).unwrap_or_default(),"destroyed":value.destroyed}))
        }).collect());
        metadata
    }
}

pub(super) fn read_v1(
    entries: &BTreeMap<String, SharedJson>,
    method: &str,
    path: &str,
    _body: &Value,
) -> Result<EngineResponse> {
    if matches!(method, "LIST" | "SCAN") {
        if !path.is_empty() {
            valid_path(path.trim_end_matches('/'))?;
        }
        let keys = list_map_keys(entries, path, method == "SCAN", &Value::Null)?;
        return if keys.is_empty() {
            if method == "SCAN" {
                Ok(ok(json!({}), false))
            } else {
                Err(not_found())
            }
        } else {
            Ok(ok(json!({"keys":keys}), false))
        };
    }
    valid_path(path)?;
    if method != "GET" {
        return Err(unsupported());
    }
    entries
        .get(path)
        .map(|data| ok(data.expose().clone(), false))
        .ok_or_else(not_found)
}

pub(super) fn handle_v1(
    entries: &mut BTreeMap<String, SharedJson>,
    method: &str,
    path: &str,
    body: &Value,
) -> Result<EngineResponse> {
    if matches!(method, "GET" | "LIST" | "SCAN") {
        return read_v1(entries, method, path, body);
    }
    valid_path(path)?;
    match method {
        "POST" | "PUT" => {
            if !body.is_object() {
                return Err(bad("secret data must be an object"));
            }
            entries.insert(path.into(), SharedJson::from(SecretJson(body.clone())));
            Ok(empty(true))
        }
        "DELETE" => {
            if entries.remove(path).is_some() {
                Ok(empty(true))
            } else {
                Ok(empty(false))
            }
        }
        _ => Err(unsupported()),
    }
}

/// Seek from the cursor in the ordered record index. A shallow directory is
/// emitted once and then its entire subtree is skipped by advancing '/' to '0'
/// (the next byte in UTF-8 order). No secret values or unrelated keys are read.
fn list_map_keys<T>(
    entries: &BTreeMap<String, T>,
    prefix: &str,
    recursive: bool,
    body: &Value,
) -> Result<Vec<String>> {
    use std::ops::Bound::{Excluded, Included, Unbounded};
    let after = match body.get("after") {
        None | Some(Value::Null) => "",
        Some(value) => value
            .as_str()
            .ok_or_else(|| bad("after must be a string"))?,
    };
    let limit = match body.get("limit") {
        None | Some(Value::Null) => 0,
        Some(Value::String(text)) if text.is_empty() => 0,
        Some(value) => value
            .as_i64()
            .or_else(|| value.as_str().and_then(|text| text.parse::<i64>().ok()))
            .ok_or_else(|| bad("limit must be a signed integer"))?,
    };
    if recursive {
        return scan_map_keys(entries, prefix);
    }
    let prefix = if prefix.is_empty() {
        String::new()
    } else {
        format!("{}/", prefix.trim_end_matches('/'))
    };
    let limit = if limit <= 0 {
        usize::MAX
    } else {
        usize::try_from(limit).unwrap_or(usize::MAX)
    };
    let mut bound = if after.is_empty() {
        Included(prefix.clone())
    } else if let Some(directory) = after.strip_suffix('/') {
        Included(format!("{prefix}{directory}0"))
    } else {
        Excluded(format!("{prefix}{after}"))
    };
    let mut found = Vec::new();
    while found.len() < limit {
        let Some((key, _)) = entries.range((bound, Unbounded)).next() else {
            break;
        };
        let Some(rest) = key.strip_prefix(&prefix) else {
            break;
        };
        bound = Excluded(key.clone());
        if rest.is_empty() {
            continue;
        }
        let value = if let Some((directory, _)) = rest.split_once('/') {
            bound = Included(format!("{prefix}{directory}0"));
            format!("{directory}/")
        } else {
            rest.to_owned()
        };
        if value.as_str() > after {
            found.push(value);
        }
    }
    Ok(found)
}

/// OpenBao ScanView emits each directory's leaves in sorted order, then
/// visits child directories using a LIFO frontier. It does not paginate by the
/// request's after/limit fields. Each shallow list seeks over subtrees so a
/// scan reads key names only, never values or unrelated mount/prefix entries.
fn scan_map_keys<T>(entries: &BTreeMap<String, T>, prefix: &str) -> Result<Vec<String>> {
    let prefix = if prefix.is_empty() {
        String::new()
    } else {
        format!("{}/", prefix.trim_end_matches('/'))
    };
    let mut frontier = vec![String::new()];
    let mut found = Vec::new();
    while let Some(directory) = frontier.pop() {
        let full_prefix = format!("{prefix}{directory}");
        for child in list_map_keys(entries, &full_prefix, false, &Value::Null)? {
            let relative = format!("{directory}{child}");
            if child.ends_with('/') {
                frontier.push(relative);
            } else {
                found.push(relative);
            }
        }
    }
    Ok(found)
}

impl Kv2 {
    pub(super) fn has_metadata_cas_state(&self) -> bool {
        self.config.metadata_cas_required
            || self.entries.values().any(|entry| {
                entry.config.metadata_cas_required || entry.current_metadata_version != 0
            })
    }

    pub(super) fn contains(&self, path: &str) -> bool {
        self.entries
            .get(path)
            .is_some_and(|e| e.current_version > 0)
    }

    pub(super) fn handle_read(
        &self,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        if !matches!(method, "GET" | "LIST" | "SCAN") {
            return Err(unsupported());
        }
        if path == "config" {
            return if method == "GET" {
                Ok(ok(self.config.json(), false))
            } else {
                Err(unsupported())
            };
        }
        let (operation, resource) = path.split_once('/').unwrap_or((path, ""));
        if matches!(operation, "metadata" | "detailed-metadata")
            && matches!(method, "LIST" | "SCAN")
        {
            if !resource.is_empty() {
                valid_path(resource.trim_end_matches('/'))?;
            }
            let keys = list_map_keys(&self.entries, resource, method == "SCAN", body)?;
            if keys.is_empty() {
                return if method == "SCAN" {
                    Ok(ok(json!({}), false))
                } else {
                    Err(not_found())
                };
            }
            let mut data = json!({"keys":keys});
            if operation == "detailed-metadata" {
                let prefix = if resource.is_empty() {
                    String::new()
                } else {
                    format!("{}/", resource.trim_end_matches('/'))
                };
                let info = keys
                    .iter()
                    .map(|key| {
                        // OpenBao joins the relative key before looking up
                        // metadata: "a/" resolves to the same-stem leaf "a"
                        // when present, and pure directories carry an empty map.
                        let path = format!("{prefix}{key}");
                        let metadata = self
                            .entries
                            .get(path.trim_end_matches('/'))
                            .map_or_else(|| json!({}), Entry::metadata);
                        (key.clone(), metadata)
                    })
                    .collect();
                data["key_info"] = Value::Object(info);
            }
            return Ok(ok(data, false));
        }
        if !matches!(
            operation,
            "data" | "subkeys" | "metadata" | "delete" | "undelete" | "destroy"
        ) {
            return Err(error(404, "unknown KV v2 operation"));
        }
        valid_path(resource)?;
        match (operation, method) {
            ("data" | "subkeys", "GET") => self.read(resource, body, now, operation == "subkeys"),
            ("metadata", "GET") => self
                .entries
                .get(resource)
                .map(|entry| ok(entry.metadata(), false))
                .ok_or_else(not_found),
            _ => Err(unsupported()),
        }
    }

    pub(super) fn handle(
        &mut self,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        if matches!(method, "GET" | "LIST" | "SCAN") {
            return self.handle_read(method, path, body, now);
        }
        if path == "config" {
            if !write_method(method) {
                return Err(unsupported());
            }
            reject_unknown(
                body,
                &[
                    "max_versions",
                    "cas_required",
                    "metadata_cas_required",
                    "delete_version_after",
                ],
            )?;
            let mut config = self.config.clone();
            config.update(body)?;
            self.config = config;
            return Ok(empty(true));
        }
        let (operation, resource) = path.split_once('/').unwrap_or((path, ""));
        if !matches!(
            operation,
            "data" | "subkeys" | "metadata" | "delete" | "undelete" | "destroy"
        ) {
            return Err(error(404, "unknown KV v2 operation"));
        }
        valid_path(resource)?;
        match operation {
            "data" if write_method(method) || method == "PATCH" => {
                self.write(resource, body, now, method == "PATCH")
            }
            "data" if method == "DELETE" => {
                let Some(entry) = self.entries.get_mut(resource) else {
                    return Ok(empty(false));
                };
                let current_version = entry.current_version;
                if let Some(version) = entry.versions.get_mut(&current_version)
                    && !version.destroyed
                    && version.deletion_at.is_none_or(|at| at > now)
                {
                    version.deletion_at = Some(now);
                    return Ok(empty(true));
                }
                Ok(empty(false))
            }
            "delete" | "undelete" | "destroy" if write_method(method) => {
                self.change_versions(resource, operation, body, now)
            }
            "metadata" if method == "DELETE" => Ok(empty(self.entries.remove(resource).is_some())),
            "metadata" if write_method(method) || method == "PATCH" => {
                self.write_metadata(resource, body, now, method == "PATCH")
            }
            _ => Err(unsupported()),
        }
    }

    fn read(
        &self,
        resource: &str,
        body: &Value,
        now: u64,
        subkeys: bool,
    ) -> Result<EngineResponse> {
        let entry = self.entries.get(resource).ok_or_else(not_found)?;
        let selected = optional_u64(body, "version")?
            .filter(|v| *v != 0)
            .unwrap_or(entry.current_version);
        let version = entry.versions.get(&selected).ok_or_else(not_found)?;
        let metadata = version.metadata(selected, &entry.custom_metadata);
        if !version.readable(now) {
            return Ok(EngineResponse {
                status: 404,
                body: json!({"data":{"data":null,"metadata":metadata}}),
                mutated: false,
            });
        }
        let data = version.data.as_ref().ok_or_else(not_found)?.expose();
        if subkeys {
            let depth = optional_u64(body, "depth")?.unwrap_or(0);
            Ok(ok(
                json!({"subkeys":strip_values(data, depth, 0),"metadata":metadata}),
                false,
            ))
        } else {
            Ok(ok(json!({"data":data,"metadata":metadata}), false))
        }
    }

    fn write(
        &mut self,
        resource: &str,
        body: &Value,
        now: u64,
        patch: bool,
    ) -> Result<EngineResponse> {
        reject_unknown(body, &["data", "options"])?;
        let new_data = body
            .get("data")
            .filter(|value| value.is_object())
            .ok_or_else(|| bad("data must be a JSON object"))?;
        let cas = if let Some(options) = body.get("options") {
            reject_unknown(options, &["cas"])?;
            optional_u64(options, "cas")?
        } else {
            None
        };
        let current = self.entries.get(resource);
        let current_version = current.map_or(0, |entry| entry.current_version);
        if (self.config.cas_required || current.is_some_and(|entry| entry.config.cas_required))
            && cas.is_none()
        {
            return Err(bad("check-and-set parameter is required for this key"));
        }
        if cas.is_some_and(|expected| expected != current_version) || (patch && cas == Some(0)) {
            return Err(bad(
                "check-and-set parameter did not match the current version",
            ));
        }
        let data = if patch {
            let current_value = current
                .and_then(|entry| entry.versions.get(&current_version))
                .filter(|version| version.readable(now))
                .and_then(|v| v.data.as_ref())
                .map(|data| data.expose().clone())
                .ok_or_else(not_found)?;
            let mut merged = SecretJson(current_value);
            merge_patch(&mut merged, new_data);
            std::mem::take(&mut merged.0)
        } else {
            new_data.clone()
        };
        let next = current_version
            .checked_add(1)
            .ok_or_else(|| bad("version limit reached"))?;
        let entry = self
            .entries
            .entry(resource.into())
            .or_insert_with(|| Entry::new(now));
        let after = match (
            entry.config.delete_version_after,
            self.config.delete_version_after,
        ) {
            (0, engine) => engine,
            (key, 0) => key,
            (key, engine) => key.min(engine),
        };
        let version = Version {
            created_at: now,
            deletion_at: if after == 0 {
                None
            } else {
                Some(
                    now.checked_add(after)
                        .ok_or_else(|| bad("deletion deadline overflow"))?,
                )
            },
            destroyed: false,
            data: Some(SharedJson::from(SecretJson(data))),
        };
        let metadata = version.metadata(next, &entry.custom_metadata);
        entry.versions.insert(next, version);
        entry.current_version = next;
        entry.updated_at = now;
        let retained = match (entry.config.max_versions, self.config.max_versions) {
            (0, 0) => 10,
            (0, engine) => engine,
            (key, _) => key,
        };
        let floor = next.saturating_sub(retained).saturating_add(1);
        entry.versions.retain(|version, _| *version >= floor);
        entry.oldest_version = if floor > 1 { floor } else { 0 };
        Ok(ok(metadata, true))
    }

    fn change_versions(
        &mut self,
        resource: &str,
        operation: &str,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        reject_unknown(body, &["versions"])?;
        let versions = body
            .get("versions")
            .and_then(Value::as_array)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| bad("versions must be a nonempty integer array"))?;
        let versions = versions
            .iter()
            .map(|v| {
                v.as_u64()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| bad("version numbers must be positive integers"))
            })
            .collect::<Result<Vec<_>>>()?;
        let Some(entry) = self.entries.get_mut(resource) else {
            return Ok(empty(false));
        };
        let mut changed = false;
        for number in versions {
            if let Some(version) = entry.versions.get_mut(&number) {
                if version.destroyed {
                    continue;
                }
                match operation {
                    "destroy" => {
                        version.data = None;
                        version.destroyed = true;
                        changed = true;
                    }
                    "delete" if version.deletion_at.is_none_or(|at| at > now) => {
                        version.deletion_at = Some(now);
                        changed = true;
                    }
                    "undelete" if version.deletion_at.is_some() => {
                        version.deletion_at = None;
                        changed = true;
                    }
                    _ => {}
                }
            }
        }
        Ok(empty(changed))
    }

    fn write_metadata(
        &mut self,
        resource: &str,
        body: &Value,
        now: u64,
        patch: bool,
    ) -> Result<EngineResponse> {
        const PATCHABLE_FIELDS: &[&str] = &[
            "max_versions",
            "cas_required",
            "metadata_cas_required",
            "delete_version_after",
            "custom_metadata",
        ];
        reject_unknown(
            body,
            &[
                "max_versions",
                "cas_required",
                "metadata_cas_required",
                "metadata_cas",
                "delete_version_after",
                "custom_metadata",
            ],
        )?;
        let cas = optional_u64(body, "metadata_cas")?;
        if !PATCHABLE_FIELDS
            .iter()
            .any(|field| body.get(*field).is_some())
        {
            return Ok(empty(false));
        }
        let previous = self.entries.get(resource);
        if patch && previous.is_none() {
            return Err(not_found());
        }
        let cas_required = self.config.metadata_cas_required
            || previous.is_some_and(|entry| entry.config.metadata_cas_required);
        if cas_required && cas.is_none() {
            return Err(bad(
                "metadata check-and-set parameter required for this call",
            ));
        }
        if let Some(cas) = cas {
            match previous {
                None if cas != 0 => {
                    return Err(bad("metadata_cas must be 0 when creating new metadata"));
                }
                Some(entry) if cas != entry.current_metadata_version => {
                    return Err(bad(
                        "metadata check-and-set parameter does not match the current version",
                    ));
                }
                _ => {}
            }
        }
        // Validate the entire update before touching durable state. In particular,
        // a rejected CAS or invalid custom metadata must not create an entry or
        // change its configuration, timestamp, or metadata version.
        let next_version = previous
            .map_or(0, |entry| entry.current_metadata_version)
            .checked_add(1)
            .ok_or_else(|| bad("metadata version limit reached"))?;
        let mut config = previous
            .map(|entry| entry.config.clone())
            .unwrap_or_default();
        config.update(body)?;
        let mut custom_metadata = previous.and_then(|entry| entry.custom_metadata.clone());
        if let Some(metadata) = body.get("custom_metadata") {
            if metadata.is_null() {
                custom_metadata = None;
            } else {
                let metadata = metadata
                    .as_object()
                    .ok_or_else(|| bad("custom_metadata must be a string map"))?;
                let mut next = if patch {
                    custom_metadata.take().unwrap_or_default()
                } else {
                    BTreeMap::new()
                };
                for (key, value) in metadata {
                    if key.is_empty() || key.len() > 128 {
                        return Err(bad("custom metadata key exceeds supported limits"));
                    }
                    if patch && value.is_null() {
                        next.remove(key);
                        continue;
                    }
                    let value = value
                        .as_str()
                        .ok_or_else(|| bad("custom_metadata values must be strings"))?;
                    if value.len() > 512 {
                        return Err(bad("custom metadata value exceeds supported limits"));
                    }
                    next.insert(key.clone(), value.into());
                }
                if next.len() > 64 {
                    return Err(bad("too many custom metadata entries"));
                }
                custom_metadata = Some(next);
            }
        }
        let mut warnings = Vec::new();
        for (field, mandated) in [
            ("cas_required", self.config.cas_required),
            ("metadata_cas_required", self.config.metadata_cas_required),
        ] {
            if mandated && body.get(field) == Some(&Value::Bool(false)) {
                warnings.push(format!("\"{field}\" set to false, but is mandated by backend config. This value will be ignored."));
            }
        }
        let entry = self
            .entries
            .entry(resource.into())
            .or_insert_with(|| Entry::new(now));
        entry.config = config;
        entry.current_metadata_version = next_version;
        entry.updated_at = now;
        if let Some(old) = std::mem::replace(&mut entry.custom_metadata, custom_metadata) {
            for (mut name, mut value) in old {
                name.zeroize();
                value.zeroize();
            }
        }
        if warnings.is_empty() {
            Ok(empty(true))
        } else {
            Ok(EngineResponse {
                status: 200,
                body: json!({"warnings": warnings}),
                mutated: true,
            })
        }
    }
}

fn merge_patch(target: &mut Value, patch: &Value) {
    if let Some(patch_map) = patch.as_object() {
        if !target.is_object() {
            wipe_json(target);
            *target = json!({});
        }
        if let Some(target_map) = target.as_object_mut() {
            for (key, value) in patch_map {
                if value.is_null() {
                    if let Some(mut removed) = target_map.remove(key) {
                        wipe_json(&mut removed);
                    }
                } else {
                    merge_patch(target_map.entry(key.clone()).or_insert(Value::Null), value);
                }
            }
        }
    } else {
        wipe_json(target);
        *target = patch.clone();
    }
}

fn strip_values(value: &Value, depth: u64, level: u64) -> Value {
    match value.as_object() {
        Some(map) if !map.is_empty() && (depth == 0 || level < depth) => Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), strip_values(value, depth, level + 1)))
                .collect(),
        ),
        _ => Value::Null,
    }
}

#[cfg(test)]
#[path = "kv_cow_tests.rs"]
mod cow_tests;

#[cfg(test)]
mod ordered_list_tests {
    use super::*;
    #[test]
    fn record_index_paging_matches_reference_for_shallow_and_unicode_keys() -> Result<()> {
        let mut entries = BTreeMap::new();
        for prefix in ["", "nested/", "é/"] {
            for key in [
                "a", "a/one", "a/two", "a0", "b", "b/one", "é", "é/深", "深/a",
            ] {
                entries.insert(format!("{prefix}{key}"), ());
            }
        }
        for prefix in ["", "a", "a/", "nested", "nested/a", "é", "missing"] {
            for after in ["", "a", "a/", "a/one", "a0", "b/", "é", "é/", "深"] {
                for limit in [0, 1, 2, 20] {
                    let body = json!({"after":after,"limit":limit});
                    assert_eq!(
                        list_map_keys(&entries, prefix, false, &body)?,
                        list_keys(entries.keys(), prefix, false, &body)?,
                        "prefix={prefix:?} after={after:?} limit={limit}"
                    );
                }
            }
        }
        Ok(())
    }
}
