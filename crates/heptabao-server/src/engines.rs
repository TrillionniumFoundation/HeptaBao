//! Single-node secret engines. State is secret-bearing and must only be persisted
//! through the server's authenticated encryption boundary; Debug redacts it.
//!
//! Namespace, mount and resource identifiers are separate map dimensions. No
//! delimiter-concatenated value is ever used as a storage identity.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroize;

mod kv;
mod totp;
mod transit;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct EngineState {
    namespaces: BTreeMap<String, NamespaceState>,
}

impl std::fmt::Debug for EngineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineState")
            .field("state", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct NamespaceState {
    mounts: BTreeMap<String, Mount>,
}

impl Default for NamespaceState {
    fn default() -> Self {
        Self {
            mounts: BTreeMap::from([
                (
                    "secret/".into(),
                    Mount::new(Backend::Kv2(kv::Kv2::default()), "Versioned secrets"),
                ),
                (
                    "transit/".into(),
                    Mount::new(
                        Backend::Transit(transit::Transit::default()),
                        "Cryptographic operations",
                    ),
                ),
            ]),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Mount {
    description: String,
    backend: Backend,
}

#[derive(Clone, Serialize, Deserialize)]
enum Backend {
    Kv1(BTreeMap<String, Value>),
    Kv2(kv::Kv2),
    Transit(transit::Transit),
    Totp(totp::Totp),
}

impl Drop for Backend {
    fn drop(&mut self) {
        if let Self::Kv1(entries) = self {
            for (mut path, mut value) in std::mem::take(entries) {
                path.zeroize();
                wipe_json(&mut value);
            }
        }
    }
}

fn wipe_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe_json),
        Value::Object(map) => {
            for (mut name, mut item) in std::mem::take(map) {
                name.zeroize();
                wipe_json(&mut item);
            }
        }
        _ => {}
    }
    *value = Value::Null;
}

struct SecretJson(Value);
impl std::ops::Deref for SecretJson {
    type Target = Value;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for SecretJson {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for SecretJson {
    fn drop(&mut self) {
        wipe_json(&mut self.0);
    }
}

impl Mount {
    fn new(backend: Backend, description: &str) -> Self {
        Self {
            description: description.into(),
            backend,
        }
    }

    fn descriptor(&self) -> Value {
        let (kind, options) = match self.backend {
            Backend::Kv1(_) => ("kv", json!({"version":"1"})),
            Backend::Kv2(_) => ("kv", json!({"version":"2"})),
            Backend::Transit(_) => ("transit", json!({})),
            Backend::Totp(_) => ("totp", json!({})),
        };
        json!({"type":kind,"description":self.description,"options":options,
            "local":false,"seal_wrap":false,"external_entropy_access":false,
            "config":{"default_lease_ttl":0,"max_lease_ttl":0,"force_no_cache":false}})
    }
}

#[derive(Clone)]
pub struct EngineResponse {
    pub status: u16,
    pub body: Value,
    pub mutated: bool,
}

impl Drop for EngineResponse {
    fn drop(&mut self) {
        wipe_json(&mut self.body);
    }
}

impl std::fmt::Debug for EngineResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineResponse")
            .field("status", &self.status)
            .field("mutated", &self.mutated)
            .field("body", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct EngineError {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for EngineError {}

type Result<T> = std::result::Result<T, EngineError>;

fn error(status: u16, message: &str) -> EngineError {
    EngineError {
        status,
        message: message.into(),
    }
}
fn bad(message: &str) -> EngineError {
    error(400, message)
}
fn not_found() -> EngineError {
    error(404, "no value found")
}
fn unsupported() -> EngineError {
    error(405, "operation is not supported by this engine")
}
fn ok(data: Value, mutated: bool) -> EngineResponse {
    EngineResponse {
        status: 200,
        body: json!({"data":data}),
        mutated,
    }
}
fn empty(mutated: bool) -> EngineResponse {
    EngineResponse {
        status: 204,
        body: Value::Null,
        mutated,
    }
}
fn write_method(method: &str) -> bool {
    matches!(method, "POST" | "PUT")
}

fn valid_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 1024
        || path
            .chars()
            .any(|c| c.is_control() || c == '\\' || c == '%' || c == '?' || c == '#')
        || path
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err(bad("path must contain canonical, nonempty path segments"));
    }
    Ok(())
}

fn optional_u64(body: &Value, name: &str) -> Result<Option<u64>> {
    body.get(name)
        .map(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                .ok_or_else(|| bad("expected a nonnegative integer parameter"))
        })
        .transpose()
}
fn optional_bool(body: &Value, name: &str) -> Result<Option<bool>> {
    body.get(name)
        .map(|v| {
            v.as_bool()
                .ok_or_else(|| bad("expected a boolean parameter"))
        })
        .transpose()
}
fn string<'a>(body: &'a Value, name: &str) -> Result<&'a str> {
    body.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| bad("required string parameter is missing or invalid"))
}
fn reject_unknown(body: &Value, allowed: &[&str]) -> Result<()> {
    let map = body
        .as_object()
        .ok_or_else(|| bad("request body must be an object"))?;
    if map.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(bad("unsupported parameter; no state was changed"));
    }
    Ok(())
}

fn list_keys<'a>(
    keys: impl Iterator<Item = &'a String>,
    prefix: &str,
    recursive: bool,
    body: &Value,
) -> Result<Vec<String>> {
    let prefix = if prefix.is_empty() {
        String::new()
    } else {
        format!("{}/", prefix.trim_end_matches('/'))
    };
    let mut found = BTreeSet::new();
    for key in keys {
        if let Some(rest) = key.strip_prefix(&prefix) {
            if rest.is_empty() {
                continue;
            }
            found.insert(if recursive {
                rest.to_owned()
            } else {
                rest.split_once('/')
                    .map_or_else(|| rest.to_owned(), |(first, _)| format!("{first}/"))
            });
        }
    }
    let after = body.get("after").and_then(Value::as_str).unwrap_or("");
    let limit = optional_u64(body, "limit")?.unwrap_or(0);
    Ok(found
        .into_iter()
        .filter(|s| s.as_str() > after)
        .take(if limit == 0 {
            usize::MAX
        } else {
            usize::try_from(limit).unwrap_or(usize::MAX)
        })
        .collect())
}

impl EngineState {
    /// The caller must authorize this capability under the same service lock used
    /// by `handle`. `None` means this module does not own the supplied route.
    pub fn required_capability(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
    ) -> Option<&'static str> {
        let path = path
            .split('?')
            .next()
            .unwrap_or(path)
            .trim_start_matches('/');
        let fallback = NamespaceState::default();
        let state = self.namespaces.get(namespace).unwrap_or(&fallback);
        let (mount_path, mount) = state
            .mounts
            .iter()
            .find(|(mount_path, _)| path.starts_with(mount_path.as_str()))?;
        let relative = &path[mount_path.len()..];
        if write_method(method) {
            let exists = match &mount.backend {
                Backend::Kv1(entries) => Some(entries.contains_key(relative)),
                Backend::Kv2(engine) => relative.strip_prefix("data/").map(|p| engine.contains(p)),
                Backend::Totp(engine) => relative
                    .strip_prefix("keys/")
                    .filter(|name| !name.contains('/'))
                    .map(|name| engine.contains(name)),
                Backend::Transit(engine) => relative
                    .strip_prefix("encrypt/")
                    .or_else(|| relative.strip_prefix("keys/"))
                    .filter(|name| !name.contains('/'))
                    .map(|name| engine.contains(name)),
            };
            if let Some(exists) = exists {
                return Some(if exists { "update" } else { "create" });
            }
        }
        Some(match method {
            "GET" | "HEAD" => "read",
            "LIST" | "SCAN" => "list",
            "DELETE" => "delete",
            "PATCH" => "patch",
            _ => "update",
        })
    }

    /// All successful state changes are atomic even for a direct caller: the
    /// namespace candidate replaces live state only after complete validation.
    pub fn handle(
        &mut self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<EngineResponse>> {
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        let path = path.trim_start_matches('/');
        let mut params = SecretJson(body.clone());
        if params.is_null() {
            *params = json!({});
        }
        let map = params
            .as_object_mut()
            .ok_or_else(|| bad("request body must be an object"))?;
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| bad("invalid query parameter"))?;
            if map.contains_key(key) {
                return Err(bad("duplicate request parameter"));
            }
            map.insert(key.into(), Value::String(value.into()));
        }
        let method =
            if method == "GET" && params.get("list").is_some_and(|v| v == "true" || v == true) {
                "LIST"
            } else {
                method
            };
        let mut candidate = self.namespaces.get(namespace).cloned().unwrap_or_default();
        let response = if path == "sys/mounts" || path == "sys/mounts/" {
            if method != "GET" {
                return Err(unsupported());
            }
            ok(
                Value::Object(
                    candidate
                        .mounts
                        .iter()
                        .map(|(name, mount)| (name.clone(), mount.descriptor()))
                        .collect(),
                ),
                false,
            )
        } else if let Some(mount_path) = path.strip_prefix("sys/mounts/") {
            handle_mounts(&mut candidate, method, mount_path, &params)?
        } else {
            let Some(mount_path) = candidate
                .mounts
                .keys()
                .find(|m| path.starts_with(m.as_str()))
                .cloned()
            else {
                return Ok(None);
            };
            let relative = &path[mount_path.len()..];
            let mount = candidate
                .mounts
                .get_mut(&mount_path)
                .ok_or_else(not_found)?;
            match &mut mount.backend {
                Backend::Kv1(entries) => kv::handle_v1(entries, method, relative, &params)?,
                Backend::Kv2(engine) => engine.handle(method, relative, &params, now)?,
                Backend::Totp(engine) => engine.handle(method, relative, &params, now)?,
                Backend::Transit(engine) => {
                    engine.handle(namespace, &mount_path, method, relative, &params, now)?
                }
            }
        };
        if response.mutated {
            self.namespaces.insert(namespace.into(), candidate);
        }
        Ok(Some(response))
    }
}

fn handle_mounts(
    state: &mut NamespaceState,
    method: &str,
    requested: &str,
    body: &Value,
) -> Result<EngineResponse> {
    let requested = requested.trim_end_matches('/');
    if let Some(mount_path) = requested.strip_suffix("/tune") {
        let mount = state
            .mounts
            .get_mut(&format!("{mount_path}/"))
            .ok_or_else(not_found)?;
        if method == "GET" {
            return Ok(ok(
                json!({"description":mount.description,"options":mount.descriptor()["options"],"default_lease_ttl":0,"max_lease_ttl":0}),
                false,
            ));
        }
        if !write_method(method) {
            return Err(unsupported());
        }
        reject_unknown(body, &["description", "options"])?;
        if let Some(description) = body.get("description") {
            mount.description = description
                .as_str()
                .ok_or_else(|| bad("description must be a string"))?
                .into();
        }
        if let Some(options) = body.get("options") {
            reject_unknown(options, &["version"])?;
            let version = options
                .get("version")
                .and_then(Value::as_str)
                .ok_or_else(|| bad("KV version must be a string"))?;
            match (&mount.backend, version) {
                (Backend::Kv1(_), "1") | (Backend::Kv2(_), "2") => {}
                _ => {
                    return Err(error(
                        501,
                        "online KV format conversion is not implemented; migrate through explicit API export/import",
                    ));
                }
            }
        }
        return Ok(empty(true));
    }
    valid_path(requested)?;
    if matches!(
        requested.split('/').next(),
        Some("sys" | "auth" | "identity" | "cubbyhole")
    ) {
        return Err(bad("reserved mount path"));
    }
    let name = format!("{requested}/");
    if method == "GET" {
        return state
            .mounts
            .get(&name)
            .map(|m| ok(m.descriptor(), false))
            .ok_or_else(not_found);
    }
    if method == "DELETE" {
        return Ok(empty(state.mounts.remove(&name).is_some()));
    }
    if !write_method(method) {
        return Err(unsupported());
    }
    reject_unknown(
        body,
        &[
            "type",
            "description",
            "options",
            "config",
            "local",
            "seal_wrap",
            "external_entropy_access",
        ],
    )?;
    if state
        .mounts
        .keys()
        .any(|existing| existing.starts_with(&name) || name.starts_with(existing))
    {
        return Err(bad("mount path conflicts with an existing mount"));
    }
    for flag in ["local", "seal_wrap", "external_entropy_access"] {
        if optional_bool(body, flag)?.unwrap_or(false) {
            return Err(error(501, "requested mount option is not implemented"));
        }
    }
    if body
        .get("config")
        .is_some_and(|v| v.as_object().is_none_or(|m| !m.is_empty()))
    {
        return Err(error(
            501,
            "nondefault mount lease configuration is not implemented",
        ));
    }
    let kind = string(body, "type")?;
    let backend = match kind {
        "kv" | "kv-v1" | "kv-v2" => {
            let version = if let Some(options) = body.get("options") {
                reject_unknown(options, &["version"])?;
                options
                    .get("version")
                    .map(|v| v.as_str().ok_or_else(|| bad("KV version must be a string")))
                    .transpose()?
            } else {
                None
            }
            .unwrap_or(if kind == "kv-v2" { "2" } else { "1" });
            match version {
                "1" => Backend::Kv1(BTreeMap::new()),
                "2" => Backend::Kv2(kv::Kv2::default()),
                _ => return Err(bad("KV version must be 1 or 2")),
            }
        }
        "transit" => {
            if body
                .get("options")
                .is_some_and(|v| v.as_object().is_none_or(|m| !m.is_empty()))
            {
                return Err(bad("transit mount options are not supported"));
            }
            Backend::Transit(transit::Transit::default())
        }
        "totp" => {
            if body
                .get("options")
                .is_some_and(|v| v.as_object().is_none_or(|m| !m.is_empty()))
            {
                return Err(bad("TOTP mount options are not supported"));
            }
            Backend::Totp(totp::Totp::default())
        }
        _ => return Err(error(501, "secret engine type is not implemented")),
    };
    let description = body
        .get("description")
        .map(|v| {
            v.as_str()
                .ok_or_else(|| bad("description must be a string"))
        })
        .transpose()?
        .unwrap_or("");
    state.mounts.insert(name, Mount::new(backend, description));
    Ok(empty(true))
}

/// RFC 3339 UTC, second resolution, for persisted Unix timestamps.
fn timestamp(seconds: u64) -> String {
    let seconds = seconds.min(253402300799); // last second of year 9999
    let days = (seconds / 86400) as i64;
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let day_seconds = seconds % 86400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        day_seconds / 3600,
        day_seconds / 60 % 60,
        day_seconds % 60
    )
}

/// Durations at one-second resolution. Fractional seconds and sub-second units
/// are explicitly rejected rather than silently rounding a deletion deadline.
fn duration_seconds(value: &Value) -> Result<u64> {
    let text = value
        .as_str()
        .ok_or_else(|| bad("duration must be a string"))?;
    if text == "0" {
        return Ok(0);
    }
    let mut number = String::new();
    let mut total = 0u64;
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            number.push(ch);
            continue;
        }
        let multiplier = match ch {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            _ => return Err(bad("duration supports integer s, m and h units")),
        };
        let count = number.parse::<u64>().map_err(|_| bad("invalid duration"))?;
        total = count
            .checked_mul(multiplier)
            .and_then(|n| total.checked_add(n))
            .ok_or_else(|| bad("duration overflow"))?;
        number.clear();
    }
    if !number.is_empty() || text.is_empty() || total > 315360000 {
        return Err(bad("invalid duration or duration exceeds ten years"));
    }
    Ok(total)
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
