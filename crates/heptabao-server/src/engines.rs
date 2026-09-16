//! Single-node secret engines and core logical surfaces. State is secret-bearing
//! and must only be persisted through the server's authenticated encryption boundary;
//! Debug redacts it.
//!
//! Namespace, mount and resource identifiers are separate map dimensions. No
//! delimiter-concatenated value is ever used as a storage identity.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroize;

mod identity;
#[path = "engine_identity.rs"]
mod identity_projection;
use identity_projection::IdentityProjection;
mod kv;
#[path = "engine_leases.rs"]
mod leases;
mod pki;
mod ssh;
mod totp;
mod transit;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct EngineState {
    #[serde(default, skip_serializing_if = "lease_clock_is_zero")]
    lease_clock: u64,
    namespaces: BTreeMap<String, NamespaceState>,
}

impl std::fmt::Debug for EngineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineState")
            .field("state", &"[REDACTED]")
            .finish()
    }
}

fn lease_clock_is_zero(value: &u64) -> bool {
    *value == 0
}

const fn mount_revision_one() -> u64 {
    1
}

#[derive(Clone, Serialize, Deserialize)]
struct NamespaceState {
    mounts: BTreeMap<String, Mount>,
    /// Next path incarnation after disable/recreate. The active Mount carries
    /// its own incarnation; this tombstone map prevents stale path identity
    /// from being resurrected after deletion.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    mount_epochs: BTreeMap<String, u64>,
    #[serde(default)]
    identity: identity::IdentityState,
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
            mount_epochs: BTreeMap::new(),
            identity: identity::IdentityState::default(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Mount {
    #[serde(default = "mount_revision_one")]
    revision: u64,
    #[serde(default = "mount_revision_one")]
    incarnation: u64,
    description: String,
    backend: Backend,
}

#[derive(Clone, Serialize, Deserialize)]
enum Backend {
    // Runtime provider state and effects belong to the audited Service writer.
    Database,
    Kv1(BTreeMap<String, Value>),
    Kv2(kv::Kv2),
    Transit(transit::Transit),
    Pki(pki::Pki),
    Ssh(ssh::SshOtp),
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
        Self::with_incarnation(backend, description, 1)
    }

    fn with_incarnation(backend: Backend, description: &str, incarnation: u64) -> Self {
        Self {
            revision: 1,
            incarnation: incarnation.max(1),
            description: description.into(),
            backend,
        }
    }

    fn descriptor(&self) -> Value {
        let (kind, options) = match self.backend {
            Backend::Database => ("database", json!({})),
            Backend::Kv1(_) => ("kv", json!({"version":"1"})),
            Backend::Kv2(_) => ("kv", json!({"version":"2"})),
            Backend::Transit(_) => ("transit", json!({})),
            Backend::Pki(_) => ("pki", json!({})),
            Backend::Ssh(_) => ("ssh", json!({})),
            Backend::Totp(_) => ("totp", json!({})),
        };
        let (default_ttl, max_ttl) = match &self.backend {
            Backend::Ssh(engine) => (engine.default_ttl, engine.max_ttl),
            Backend::Pki(engine) => (engine.default_ttl, engine.max_ttl),
            _ => (0, 0),
        };
        json!({"type":kind,"description":self.description,"options":options,
            "revision":self.revision,"incarnation":self.incarnation,
            "local":false,"seal_wrap":false,"external_entropy_access":false,
            "config":{"default_lease_ttl":default_ttl,"max_lease_ttl":max_ttl,"force_no_cache":false}})
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
    pub(crate) fn database_mount(&self, namespace: &str, path: &str) -> Option<&str> {
        self.namespaces
            .get(namespace)?
            .mounts
            .iter()
            .filter(|(mount, _)| path.starts_with(mount.as_str()))
            .max_by_key(|(mount, _)| mount.len())
            .and_then(|(mount, value)| {
                matches!(value.backend, Backend::Database).then_some(mount.as_str())
            })
    }

    /// Atomically relocate one registered secret-engine mount inside the
    /// caller's namespace. The backend moves as one value, so old route lookup
    /// cannot observe it after publication. A revision CAS fences stale
    /// operators and path-incarnation tombstones prevent disable/recreate ABA.
    pub(crate) fn remount(
        &mut self,
        namespace: &str,
        from: &str,
        to: &str,
        cas_revision: Option<u64>,
    ) -> Result<EngineResponse> {
        let from = canonical_secret_mount(from)?;
        let to = canonical_secret_mount(to)?;
        if from == to {
            return Err(bad("remount source and destination must differ"));
        }
        if self.has_live_leases() {
            return Err(error(
                409,
                "secret-engine remount is fenced while dynamic leases are live",
            ));
        }
        let mut candidate = self.namespaces.get(namespace).cloned().unwrap_or_default();
        let from_name = format!("{from}/");
        let to_name = format!("{to}/");
        let current = candidate
            .mounts
            .get(&from_name)
            .cloned()
            .ok_or_else(not_found)?;
        require_mount_revision(cas_revision, current.revision)?;
        if candidate.mounts.keys().any(|existing| {
            existing != &from_name
                && (existing.starts_with(&to_name) || to_name.starts_with(existing))
        }) {
            return Err(bad("remount destination conflicts with an existing mount"));
        }
        let mut moved = candidate.mounts.remove(&from_name).ok_or_else(not_found)?;
        moved.revision = next_mount_revision(moved.revision)?;
        let destination_floor = candidate
            .mount_epochs
            .get(&to_name)
            .copied()
            .unwrap_or(moved.incarnation);
        moved.incarnation = moved.incarnation.max(destination_floor).max(1);
        let old_next = moved
            .incarnation
            .checked_add(1)
            .ok_or_else(|| error(507, "mount incarnation exhausted"))?;
        candidate.mount_epochs.insert(from_name, old_next);
        let revision = moved.revision;
        let incarnation = moved.incarnation;
        candidate.mounts.insert(to_name, moved);
        self.namespaces.insert(namespace.into(), candidate);
        Ok(ok(
            json!({"from":format!("{from}/"),"to":format!("{to}/"),
                "revision":revision,"incarnation":incarnation}),
            true,
        ))
    }

    pub(crate) fn has_database_mount(&self) -> bool {
        self.namespaces.values().any(|ns| {
            ns.mounts
                .values()
                .any(|m| matches!(m.backend, Backend::Database))
        })
    }

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
        if identity::owns(path) {
            return Some(match method {
                "GET" | "HEAD" => "read",
                "LIST" | "SCAN" => "list",
                "DELETE" => "delete",
                "PATCH" => "patch",
                _ => "update",
            });
        }
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
                Backend::Database | Backend::Pki(_) | Backend::Ssh(_) => None,
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
        if identity::owns(path) {
            let response = identity::handle(&mut candidate.identity, method, path, &params, now)?;
            if response.mutated {
                self.namespaces.insert(namespace.into(), candidate);
            }
            return Ok(Some(response));
        }
        let response = if path == "sys/mounts" || path == "sys/mounts/" {
            if method != "GET" {
                return Err(unsupported());
            }
            let mut mounts: serde_json::Map<String, Value> = candidate
                .mounts
                .iter()
                .map(|(name, mount)| (name.clone(), mount.descriptor()))
                .collect();
            mounts.insert("cubbyhole/".into(), cubbyhole_descriptor());
            ok(Value::Object(mounts), false)
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
                Backend::Database => {
                    return Err(error(
                        501,
                        "database operations require the audited external-effect dispatcher",
                    ));
                }
                Backend::Kv1(entries) => kv::handle_v1(entries, method, relative, &params)?,
                Backend::Kv2(engine) => engine.handle(method, relative, &params, now)?,
                Backend::Totp(engine) => engine.handle(method, relative, &params, now)?,
                Backend::Transit(engine) => {
                    engine.handle(namespace, &mount_path, method, relative, &params, now)?
                }
                Backend::Pki(engine) => engine.handle_admin(method, relative, &params, now)?,
                Backend::Ssh(engine) => engine.handle_role(method, relative, &params)?,
            }
        };
        if response.mutated {
            self.namespaces.insert(namespace.into(), candidate);
        }
        Ok(Some(response))
    }
}

fn cubbyhole_descriptor() -> Value {
    json!({"type":"cubbyhole","description":"per-token private secret storage",
        "options":{},"local":true,"seal_wrap":false,"external_entropy_access":false,
        "config":{"default_lease_ttl":0,"max_lease_ttl":0,"force_no_cache":false}})
}

fn canonical_secret_mount(value: &str) -> Result<String> {
    let value = value.trim_end_matches('/');
    valid_path(value)?;
    if matches!(
        value.split('/').next(),
        Some("sys" | "auth" | "identity" | "cubbyhole")
    ) {
        return Err(bad("reserved mount path"));
    }
    Ok(value.to_owned())
}

fn require_mount_revision(expected: Option<u64>, current: u64) -> Result<()> {
    if expected.is_some_and(|value| value != current) {
        return Err(error(409, "stale mount revision; no state was changed"));
    }
    Ok(())
}

fn require_absent_mount_revision(expected: Option<u64>) -> Result<()> {
    if expected.is_some_and(|value| value != 0) {
        return Err(error(
            409,
            "mount is absent; cas_revision must be zero for creation",
        ));
    }
    Ok(())
}

fn next_mount_revision(current: u64) -> Result<u64> {
    current
        .max(1)
        .checked_add(1)
        .ok_or_else(|| error(507, "mount revision exhausted"))
}

fn handle_mounts(
    state: &mut NamespaceState,
    method: &str,
    requested: &str,
    body: &Value,
) -> Result<EngineResponse> {
    let requested = requested.trim_end_matches('/');
    if let Some(mount_path) = requested.strip_suffix("/tune") {
        let name = format!("{mount_path}/");
        let mount = state.mounts.get_mut(&name).ok_or_else(not_found)?;
        if method == "GET" {
            return Ok(ok(
                json!({"description":mount.description,"options":mount.descriptor()["options"],
                    "default_lease_ttl":mount.descriptor()["config"]["default_lease_ttl"],
                    "max_lease_ttl":mount.descriptor()["config"]["max_lease_ttl"],
                    "revision":mount.revision,"incarnation":mount.incarnation}),
                false,
            ));
        }
        if !write_method(method) {
            return Err(unsupported());
        }
        let expected = optional_u64(body, "cas_revision")?;
        require_mount_revision(expected, mount.revision)?;
        let before = serde_json::to_vec(&*mount)
            .map_err(|_| error(500, "mount state serialization failed"))?;
        let mut tune = body.clone();
        tune.as_object_mut()
            .ok_or_else(|| bad("request body must be an object"))?
            .remove("cas_revision");
        if let Backend::Ssh(engine) = &mut mount.backend {
            reject_unknown(
                body,
                &[
                    "description",
                    "default_lease_ttl",
                    "max_lease_ttl",
                    "cas_revision",
                ],
            )?;
            engine.tune(&tune)?;
        } else if let Backend::Pki(engine) = &mut mount.backend {
            reject_unknown(
                body,
                &[
                    "description",
                    "default_lease_ttl",
                    "max_lease_ttl",
                    "cas_revision",
                ],
            )?;
            engine.tune(&tune)?;
        } else {
            reject_unknown(body, &["description", "options", "cas_revision"])?;
        }
        if let Some(description) = tune.get("description") {
            mount.description = description
                .as_str()
                .ok_or_else(|| bad("description must be a string"))?
                .into();
        }
        if let Some(options) = tune.get("options") {
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
        let after = serde_json::to_vec(&*mount)
            .map_err(|_| error(500, "mount state serialization failed"))?;
        if before == after {
            return Ok(empty(false));
        }
        mount.revision = next_mount_revision(mount.revision)?;
        return Ok(empty(true));
    }
    if requested == "cubbyhole" {
        if method == "GET" {
            return Ok(ok(cubbyhole_descriptor(), false));
        }
        return Err(bad("reserved mount path"));
    }
    let requested = canonical_secret_mount(requested)?;
    let name = format!("{requested}/");
    if method == "GET" {
        return state
            .mounts
            .get(&name)
            .map(|m| ok(m.descriptor(), false))
            .ok_or_else(not_found);
    }
    if method == "DELETE" {
        reject_unknown(body, &["cas_revision"])?;
        let Some(current) = state.mounts.get(&name) else {
            return Ok(empty(false));
        };
        require_mount_revision(optional_u64(body, "cas_revision")?, current.revision)?;
        let incarnation = current.incarnation.max(1);
        state.mounts.remove(&name);
        state.mount_epochs.insert(
            name,
            incarnation
                .checked_add(1)
                .ok_or_else(|| error(507, "mount incarnation exhausted"))?,
        );
        return Ok(empty(true));
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
            "cas_revision",
        ],
    )?;
    require_absent_mount_revision(optional_u64(body, "cas_revision")?)?;
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
    if !matches!(
        body.get("type").and_then(Value::as_str),
        Some("ssh" | "pki")
    ) && body
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
        "database" => {
            if body
                .get("options")
                .is_some_and(|v| v.as_object().is_none_or(|m| !m.is_empty()))
            {
                return Err(bad("database mount options are not supported"));
            }
            Backend::Database
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
        "pki" => {
            if body
                .get("options")
                .is_some_and(|v| v.as_object().is_none_or(|m| !m.is_empty()))
            {
                return Err(bad("PKI mount options are not supported"));
            }
            let mut engine = pki::Pki::default();
            if let Some(config) = body.get("config") {
                reject_unknown(config, &["default_lease_ttl", "max_lease_ttl"])?;
                engine.tune(config)?;
            }
            Backend::Pki(engine)
        }
        "ssh" => {
            if body
                .get("options")
                .is_some_and(|v| v.as_object().is_none_or(|m| !m.is_empty()))
            {
                return Err(bad("SSH mount options are not supported"));
            }
            let mut engine = ssh::SshOtp::default();
            if let Some(config) = body.get("config") {
                reject_unknown(config, &["default_lease_ttl", "max_lease_ttl"])?;
                engine.tune(config)?;
            }
            Backend::Ssh(engine)
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
    let incarnation = state.mount_epochs.get(&name).copied().unwrap_or(1).max(1);
    state.mounts.insert(
        name,
        Mount::with_incarnation(backend, description, incarnation),
    );
    Ok(empty(true))
}

/// RFC 3339 UTC, second resolution, for persisted Unix timestamps.
pub(crate) fn timestamp(seconds: u64) -> String {
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

fn listing(keys: Vec<String>) -> Result<EngineResponse> {
    if keys.is_empty() {
        Err(not_found())
    } else {
        Ok(ok(json!({"keys":keys}), false))
    }
}
