#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement, found {count}: {old[:80]!r}")
    write(path, text.replace(old, new, 1))


def regex_once(path: str, pattern: str, replacement: str) -> None:
    text = read(path)
    next_text, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{path}: regex replacement count={count}: {pattern[:80]!r}")
    write(path, next_text)


def append_once(path: str, marker: str, block: str) -> None:
    text = read(path)
    if marker in text:
        return
    if not text.endswith("\n"):
        text += "\n"
    write(path, text + "\n" + block.rstrip() + "\n")


# ---------------------------------------------------------------------------
# Secret-engine mount registry: persistent revision/incarnation + CAS/remount.
# ---------------------------------------------------------------------------
replace_once(
    "crates/heptabao-server/src/engines.rs",
    '''struct NamespaceState {\n    mounts: BTreeMap<String, Mount>,\n    #[serde(default)]\n    identity: identity::IdentityState,\n}\n''',
    '''struct NamespaceState {\n    mounts: BTreeMap<String, Mount>,\n    /// Next path incarnation after disable/recreate. The active Mount carries\n    /// its own incarnation; this tombstone map prevents stale path identity\n    /// from being resurrected after deletion.\n    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]\n    mount_epochs: BTreeMap<String, u64>,\n    #[serde(default)]\n    identity: identity::IdentityState,\n}\n''',
)
replace_once(
    "crates/heptabao-server/src/engines.rs",
    '''            ]),\n            identity: identity::IdentityState::default(),\n        }\n''',
    '''            ]),\n            mount_epochs: BTreeMap::new(),\n            identity: identity::IdentityState::default(),\n        }\n''',
)
replace_once(
    "crates/heptabao-server/src/engines.rs",
    '''struct Mount {\n    description: String,\n    backend: Backend,\n}\n''',
    '''struct Mount {\n    #[serde(default = "mount_revision_one")]\n    revision: u64,\n    #[serde(default = "mount_revision_one")]\n    incarnation: u64,\n    description: String,\n    backend: Backend,\n}\n''',
)
replace_once(
    "crates/heptabao-server/src/engines.rs",
    '''fn lease_clock_is_zero(value: &u64) -> bool {\n    *value == 0\n}\n''',
    '''fn lease_clock_is_zero(value: &u64) -> bool {\n    *value == 0\n}\n\nconst fn mount_revision_one() -> u64 {\n    1\n}\n''',
)
replace_once(
    "crates/heptabao-server/src/engines.rs",
    '''impl Mount {\n    fn new(backend: Backend, description: &str) -> Self {\n        Self {\n            description: description.into(),\n            backend,\n        }\n    }\n''',
    '''impl Mount {\n    fn new(backend: Backend, description: &str) -> Self {\n        Self::with_incarnation(backend, description, 1)\n    }\n\n    fn with_incarnation(backend: Backend, description: &str, incarnation: u64) -> Self {\n        Self {\n            revision: 1,\n            incarnation: incarnation.max(1),\n            description: description.into(),\n            backend,\n        }\n    }\n''',
)
replace_once(
    "crates/heptabao-server/src/engines.rs",
    '''        json!({"type":kind,"description":self.description,"options":options,\n            "local":false,"seal_wrap":false,"external_entropy_access":false,\n            "config":{"default_lease_ttl":default_ttl,"max_lease_ttl":max_ttl,"force_no_cache":false}})\n''',
    '''        json!({"type":kind,"description":self.description,"options":options,\n            "revision":self.revision,"incarnation":self.incarnation,\n            "local":false,"seal_wrap":false,"external_entropy_access":false,\n            "config":{"default_lease_ttl":default_ttl,"max_lease_ttl":max_ttl,"force_no_cache":false}})\n''',
)
replace_once(
    "crates/heptabao-server/src/engines.rs",
    '''    pub(crate) fn has_database_mount(&self) -> bool {\n''',
    '''    /// Atomically relocate one registered secret-engine mount inside the\n    /// caller's namespace. The backend moves as one value, so old route lookup\n    /// cannot observe it after publication. A revision CAS fences stale\n    /// operators and path-incarnation tombstones prevent disable/recreate ABA.\n    pub(crate) fn remount(\n        &mut self,\n        namespace: &str,\n        from: &str,\n        to: &str,\n        cas_revision: Option<u64>,\n    ) -> Result<EngineResponse> {\n        let from = canonical_secret_mount(from)?;\n        let to = canonical_secret_mount(to)?;\n        if from == to {\n            return Err(bad("remount source and destination must differ"));\n        }\n        if self.has_live_leases() {\n            return Err(error(\n                409,\n                "secret-engine remount is fenced while dynamic leases are live",\n            ));\n        }\n        let mut candidate = self.namespaces.get(namespace).cloned().unwrap_or_default();\n        let from_name = format!("{from}/");\n        let to_name = format!("{to}/");\n        let current = candidate\n            .mounts\n            .get(&from_name)\n            .cloned()\n            .ok_or_else(not_found)?;\n        require_mount_revision(cas_revision, current.revision)?;\n        if candidate.mounts.keys().any(|existing| {\n            existing != &from_name\n                && (existing.starts_with(&to_name) || to_name.starts_with(existing))\n        }) {\n            return Err(bad("remount destination conflicts with an existing mount"));\n        }\n        let mut moved = candidate\n            .mounts\n            .remove(&from_name)\n            .ok_or_else(not_found)?;\n        moved.revision = next_mount_revision(moved.revision)?;\n        let destination_floor = candidate\n            .mount_epochs\n            .get(&to_name)\n            .copied()\n            .unwrap_or(moved.incarnation);\n        moved.incarnation = moved.incarnation.max(destination_floor).max(1);\n        let old_next = moved\n            .incarnation\n            .checked_add(1)\n            .ok_or_else(|| error(507, "mount incarnation exhausted"))?;\n        candidate.mount_epochs.insert(from_name, old_next);\n        let revision = moved.revision;\n        let incarnation = moved.incarnation;\n        candidate.mounts.insert(to_name, moved);\n        self.namespaces.insert(namespace.into(), candidate);\n        Ok(ok(\n            json!({"from":format!("{from}/"),"to":format!("{to}/"),\n                "revision":revision,"incarnation":incarnation}),\n            true,\n        ))\n    }\n\n    pub(crate) fn has_database_mount(&self) -> bool {\n''',
)

new_mount_handler = r'''fn canonical_secret_mount(value: &str) -> Result<String> {
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
                &["description", "default_lease_ttl", "max_lease_ttl", "cas_revision"],
            )?;
            engine.tune(&tune)?;
        } else if let Backend::Pki(engine) = &mut mount.backend {
            reject_unknown(
                body,
                &["description", "default_lease_ttl", "max_lease_ttl", "cas_revision"],
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
    let requested = canonical_secret_mount(requested)?;
    if requested == "cubbyhole" && method == "GET" {
        return Ok(ok(cubbyhole_descriptor(), false));
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
'''
regex_once(
    "crates/heptabao-server/src/engines.rs",
    r"fn handle_mounts\(\n.*?\n}\n\n/// RFC 3339 UTC",
    new_mount_handler + "\n/// RFC 3339 UTC",
)

# ---------------------------------------------------------------------------
# Auth mount registry: revision CAS/tune, accessor-preserving remount.
# ---------------------------------------------------------------------------
replace_once(
    "crates/heptabao-server/src/auth.rs",
    '''struct AuthMount {\n    #[serde(default, skip_serializing_if = "Option::is_none")]\n    accessor: Option<String>,\n    kind: String,\n    description: String,\n}\n''',
    '''struct AuthMount {\n    #[serde(default, skip_serializing_if = "Option::is_none")]\n    accessor: Option<String>,\n    #[serde(default = "auth_mount_revision_one")]\n    revision: u64,\n    kind: String,\n    description: String,\n}\n''',
)
replace_once(
    "crates/heptabao-server/src/auth.rs",
    '''impl AuthMount {\n    fn new(kind: &str, description: &str) -> Self {\n        Self {\n            accessor: None,\n            kind: kind.into(),\n            description: description.into(),\n        }\n    }\n''',
    '''const fn auth_mount_revision_one() -> u64 {\n    1\n}\n\nimpl AuthMount {\n    fn new(kind: &str, description: &str) -> Self {\n        Self {\n            accessor: None,\n            revision: 1,\n            kind: kind.into(),\n            description: description.into(),\n        }\n    }\n''',
)
replace_once(
    "crates/heptabao-server/src/auth.rs",
    '''            "type": self.kind,\n            "accessor": self.accessor.as_deref().unwrap_or(""),\n            "description": self.description,\n''',
    '''            "type": self.kind,\n            "accessor": self.accessor.as_deref().unwrap_or(""),\n            "revision": self.revision,\n            "description": self.description,\n''',
)
replace_once(
    "crates/heptabao-server/src/auth.rs",
    '''fn boolean(body: &Value, field: &str, default: bool) -> Result<bool, AuthError> {\n    match body.get(field) {\n        None => Ok(default),\n        Some(value) => value.as_bool().ok_or_else(|| bad("expected boolean")),\n    }\n}\n''',
    '''fn boolean(body: &Value, field: &str, default: bool) -> Result<bool, AuthError> {\n    match body.get(field) {\n        None => Ok(default),\n        Some(value) => value.as_bool().ok_or_else(|| bad("expected boolean")),\n    }\n}\nfn optional_auth_revision(body: &Value) -> Result<Option<u64>, AuthError> {\n    body.get("cas_revision")\n        .map(|value| {\n            value\n                .as_u64()\n                .ok_or_else(|| bad("cas_revision must be a nonnegative integer"))\n        })\n        .transpose()\n}\nfn require_auth_revision(expected: Option<u64>, current: u64) -> Result<(), AuthError> {\n    if expected.is_some_and(|value| value != current) {\n        return Err(err(409, "stale auth mount revision; no state was changed"));\n    }\n    Ok(())\n}\nfn require_absent_auth_revision(expected: Option<u64>) -> Result<(), AuthError> {\n    if expected.is_some_and(|value| value != 0) {\n        return Err(err(\n            409,\n            "auth mount is absent; cas_revision must be zero for creation",\n        ));\n    }\n    Ok(())\n}\nfn next_auth_revision(current: u64) -> Result<u64, AuthError> {\n    current\n        .max(1)\n        .checked_add(1)\n        .ok_or_else(|| err(507, "auth mount revision exhausted"))\n}\n''',
)

new_auth_mount_route = r'''    pub(super) fn remount_mount(
        &mut self,
        namespace: &str,
        from: &str,
        to: &str,
        cas_revision: Option<u64>,
    ) -> Result<AuthResponse, AuthError> {
        if from.is_empty()
            || to.is_empty()
            || from == to
            || from.len() > 256
            || to.len() > 256
            || !from.split('/').all(valid_name)
            || !to.split('/').all(valid_name)
        {
            return Err(bad("auth remount paths must be distinct canonical segments"));
        }
        if from == "token" || to == "token" {
            return Err(bad("the built-in token auth method cannot be remounted"));
        }
        let mut entries = self.effective_auth_mounts(namespace);
        let mut moved = entries
            .get(from)
            .cloned()
            .ok_or_else(|| err(404, "auth mount not found"))?;
        require_auth_revision(cas_revision, moved.revision)?;
        if entries.keys().any(|name| {
            name != from
                && (name == to
                    || name.starts_with(&format!("{to}/"))
                    || to.starts_with(&format!("{name}/")))
        }) {
            return Err(bad("auth remount destination conflicts with an existing mount"));
        }
        entries.remove(from);
        moved.revision = next_auth_revision(moved.revision)?;
        let revision = moved.revision;
        let accessor = moved.accessor.clone().unwrap_or_default();
        entries.insert(to.into(), moved);
        self.auth_mounts.insert(namespace.into(), entries);

        if from == "userpass" {
            if let Some(users) = self.users.remove(namespace) {
                self.mounted_users
                    .entry(namespace.into())
                    .or_default()
                    .insert(to.into(), users);
            }
        } else if let Some(users) = self
            .mounted_users
            .get_mut(namespace)
            .and_then(|mounts| mounts.remove(from))
        {
            self.mounted_users
                .entry(namespace.into())
                .or_default()
                .insert(to.into(), users);
        }
        if from == "approle" {
            if let Some(roles) = self.roles.remove(namespace) {
                self.mounted_roles
                    .entry(namespace.into())
                    .or_default()
                    .insert(to.into(), roles);
            }
        } else if let Some(roles) = self
            .mounted_roles
            .get_mut(namespace)
            .and_then(|mounts| mounts.remove(from))
        {
            self.mounted_roles
                .entry(namespace.into())
                .or_default()
                .insert(to.into(), roles);
        }
        if let Some(value) = self
            .jwt_mounts
            .get_mut(namespace)
            .and_then(|mounts| mounts.remove(from))
        {
            self.jwt_mounts
                .entry(namespace.into())
                .or_default()
                .insert(to.into(), value);
        }
        if let Some(value) = self
            .kubernetes_mounts
            .get_mut(namespace)
            .and_then(|mounts| mounts.remove(from))
        {
            self.kubernetes_mounts
                .entry(namespace.into())
                .or_default()
                .insert(to.into(), value);
        }
        if let Some(value) = self
            .oidc_mounts
            .get_mut(namespace)
            .and_then(|mounts| mounts.remove(from))
        {
            self.oidc_mounts
                .entry(namespace.into())
                .or_default()
                .insert(to.into(), value);
        }
        if let Some(value) = self
            .ldap_mounts
            .get_mut(namespace)
            .and_then(|mounts| mounts.remove(from))
        {
            self.ldap_mounts
                .entry(namespace.into())
                .or_default()
                .insert(to.into(), value);
        }
        for token in self.tokens.values_mut() {
            if token.namespace == namespace && token.auth_mount.as_deref() == Some(from) {
                token.auth_mount = Some(to.into());
            }
        }
        Ok(response(
            json!({"from":format!("auth/{from}/"),"to":format!("auth/{to}/"),
                "revision":revision,"accessor":accessor}),
            true,
        ))
    }

    fn auth_mount_route(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let suffix = path
            .strip_prefix("sys/auth")
            .ok_or_else(|| bad("invalid auth mount path"))?;
        if suffix.is_empty() || suffix == "/" {
            if !matches!(method, "GET" | "LIST") {
                return Err(err(405, "method not allowed"));
            }
            self.permission(principal, namespace, "sys/auth", "read", now)?;
            reject_unknown(body, &[])?;
            let entries = self
                .effective_auth_mounts(namespace)
                .into_iter()
                .map(|(name, mount)| (format!("{name}/"), mount.descriptor()))
                .collect();
            return Ok(response(Value::Object(entries), false));
        }
        let requested = suffix.trim_start_matches('/').trim_end_matches('/');
        let (mount, tune) = requested
            .strip_suffix("/tune")
            .map_or((requested, false), |mount| (mount, true));
        if mount.is_empty() || mount.len() > 256 || !mount.split('/').all(valid_name) {
            return Err(bad("auth mount path must contain canonical segments"));
        }
        let route = if tune {
            format!("sys/auth/{mount}/tune")
        } else {
            format!("sys/auth/{mount}")
        };
        if tune {
            return match method {
                "GET" => {
                    self.permission(principal, namespace, &route, "read", now)?;
                    reject_unknown(body, &[])?;
                    let entry = self
                        .effective_auth_mounts(namespace)
                        .get(mount)
                        .cloned()
                        .ok_or_else(|| err(404, "auth mount not found"))?;
                    Ok(response(
                        json!({"description":entry.description,"revision":entry.revision,
                            "accessor":entry.accessor.as_deref().unwrap_or("")}),
                        false,
                    ))
                }
                "POST" | "PUT" => {
                    let actor = self.permission(principal, namespace, &route, "update", now)?;
                    self.authorize_request(actor, namespace, &route, "sudo", now)?;
                    reject_unknown(body, &["description", "cas_revision"])?;
                    let mut entries = self.effective_auth_mounts(namespace);
                    let mut entry = entries
                        .get(mount)
                        .cloned()
                        .ok_or_else(|| err(404, "auth mount not found"))?;
                    require_auth_revision(optional_auth_revision(body)?, entry.revision)?;
                    let mut changed = false;
                    if let Some(description) = body.get("description") {
                        let description = description
                            .as_str()
                            .ok_or_else(|| bad("description must be a string"))?;
                        if description.len() > 512 || description.chars().any(char::is_control) {
                            return Err(bad("invalid auth mount description"));
                        }
                        if entry.description != description {
                            entry.description = description.into();
                            changed = true;
                        }
                    }
                    if changed {
                        entry.revision = next_auth_revision(entry.revision)?;
                        entries.insert(mount.into(), entry);
                        self.auth_mounts.insert(namespace.into(), entries);
                    }
                    Ok(empty(changed))
                }
                _ => Err(err(405, "method not allowed")),
            };
        }
        match method {
            "GET" => {
                self.permission(principal, namespace, &route, "read", now)?;
                reject_unknown(body, &[])?;
                let entry = self
                    .effective_auth_mounts(namespace)
                    .get(mount)
                    .cloned()
                    .ok_or_else(|| err(404, "auth mount not found"))?;
                Ok(response(entry.descriptor(), false))
            }
            "POST" | "PUT" => {
                let actor = self.permission(principal, namespace, &route, "update", now)?;
                self.authorize_request(actor, namespace, &route, "sudo", now)?;
                reject_unknown(body, &["type", "description", "cas_revision"])?;
                let kind = body
                    .get("type")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("auth mount type is required"))?;
                if !matches!(
                    kind,
                    "userpass" | "approle" | "jwt" | "kubernetes" | "oidc" | "ldap"
                ) {
                    return Err(err(501, "auth method type is not implemented"));
                }
                let description = body
                    .get("description")
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| bad("description must be a string"))
                    })
                    .transpose()?
                    .unwrap_or("");
                if description.len() > 512 || description.chars().any(char::is_control) {
                    return Err(bad("invalid auth mount description"));
                }
                let mut entries = self.effective_auth_mounts(namespace);
                let existing = entries.get(mount).cloned();
                if mount == "token" || existing.as_ref().is_some_and(|old| old.kind != kind) {
                    return Err(bad("auth mount is already in use by another method"));
                }
                if entries.keys().any(|name| {
                    name != mount
                        && (name.starts_with(&format!("{mount}/"))
                            || mount.starts_with(&format!("{name}/")))
                }) {
                    return Err(bad("auth mount paths cannot overlap"));
                }
                match existing.as_ref() {
                    Some(old) => require_auth_revision(optional_auth_revision(body)?, old.revision)?,
                    None => require_absent_auth_revision(optional_auth_revision(body)?)?,
                }
                let mut next = AuthMount::new(kind, description);
                if let Some(old) = existing.as_ref() {
                    next.accessor = old.accessor.clone();
                    next.revision = old.revision;
                    if old.description != description {
                        next.revision = next_auth_revision(old.revision)?;
                    }
                } else {
                    next.accessor = Some(random_id("auth_")?);
                }
                let mutated = existing.as_ref() != Some(&next);
                entries.insert(mount.into(), next);
                self.auth_mounts.insert(namespace.into(), entries);
                Ok(empty(mutated))
            }
            "DELETE" => {
                let actor = self.permission(principal, namespace, &route, "update", now)?;
                self.authorize_request(actor, namespace, &route, "sudo", now)?;
                reject_unknown(body, &["cas_revision"])?;
                if mount == "token" {
                    return Err(bad("the built-in token auth method cannot be disabled"));
                }
                let mut entries = self.effective_auth_mounts(namespace);
                let current = entries
                    .get(mount)
                    .cloned()
                    .ok_or_else(|| err(404, "auth mount not found"))?;
                require_auth_revision(optional_auth_revision(body)?, current.revision)?;
                entries.remove(mount);
                self.auth_mounts.insert(namespace.into(), entries);
                self.disable_auth_mount(AuthScope { namespace, mount });
                Ok(empty(true))
            }
            _ => Err(err(405, "method not allowed")),
        }
    }

    /// Returns None only for routes owned by another service subsystem.'''
regex_once(
    "crates/heptabao-server/src/auth.rs",
    r"    fn auth_mount_route\(\n.*?\n    }\n\n    /// Returns None only for routes owned by another service subsystem\.",
    new_auth_mount_route,
)

# ---------------------------------------------------------------------------
# Service owns sys/remount and audit revision CAS inside the durable transaction.
# ---------------------------------------------------------------------------
replace_once(
    "crates/heptabao-server/src/service.rs",
    '''        let principal = principal.as_ref();\n        if state.engines.is_lease_service_route(namespace, path) || path.starts_with("sys/leases/")\n''',
    '''        let principal = principal.as_ref();\n        if path == "sys/remount" {\n            if !matches!(method, "POST" | "PUT") {\n                return Response::error(405, "remount requires POST or PUT");\n            }\n            let Some(principal) = principal else {\n                return Response::error(403, "missing client token");\n            };\n            if let Err(error) = state\n                .auth\n                .authorize_sudo_request(principal, namespace, path, "update", now)\n            {\n                return Response::error(error.status, &error.message);\n            }\n            let Some(object) = body.as_object() else {\n                return Response::error(400, "remount requires a JSON object");\n            };\n            if object\n                .keys()\n                .any(|key| !matches!(key.as_str(), "from" | "to" | "cas_revision"))\n            {\n                return Response::error(400, "unsupported remount parameter");\n            }\n            let Some(from) = object.get("from").and_then(Value::as_str) else {\n                return Response::error(400, "remount from is required");\n            };\n            let Some(to) = object.get("to").and_then(Value::as_str) else {\n                return Response::error(400, "remount to is required");\n            };\n            if from.starts_with('/') || to.starts_with('/') {\n                return Response::error(400, "remount paths must be relative to the request namespace");\n            }\n            let cas_revision = match object.get("cas_revision") {\n                Some(value) => match value.as_u64() {\n                    Some(value) => Some(value),\n                    None => return Response::error(400, "cas_revision must be a nonnegative integer"),\n                },\n                None => None,\n            };\n            let from = from.trim_end_matches('/');\n            let to = to.trim_end_matches('/');\n            match (from.strip_prefix("auth/"), to.strip_prefix("auth/")) {\n                (Some(from), Some(to)) => {\n                    return match state.auth.remount_mount(namespace, from, to, cas_revision) {\n                        Ok(response) => Response {\n                            status: response.status,\n                            body: response.body,\n                        },\n                        Err(error) => Response::error(error.status, &error.message),\n                    };\n                }\n                (None, None) => {\n                    if from.starts_with("sys/")\n                        || to.starts_with("sys/")\n                        || from.starts_with("identity/")\n                        || to.starts_with("identity/")\n                        || from.starts_with("cubbyhole/")\n                        || to.starts_with("cubbyhole/")\n                    {\n                        return Response::error(400, "remount cannot relocate reserved system paths");\n                    }\n                    return match state.engines.remount(namespace, from, to, cas_revision) {\n                        Ok(mut response) => Response {\n                            status: response.status,\n                            body: std::mem::take(&mut response.body),\n                        },\n                        Err(error) => Response::error(error.status, &error.message),\n                    };\n                }\n                _ => {\n                    return Response::error(\n                        400,\n                        "remount cannot change between auth and secret mount classes",\n                    );\n                }\n            }\n        }\n        if state.engines.is_lease_service_route(namespace, path) || path.starts_with("sys/leases/")\n''',
)
replace_once(
    "crates/heptabao-server/src/service.rs",
    '''                "type": "file",\n                "description": "HeptaBao mandatory authenticated file audit device",\n                "options": {\n''',
    '''                "type": "file",\n                "accessor": "audit_file",\n                "revision": 1,\n                "description": "HeptaBao mandatory authenticated file audit device",\n                "options": {\n''',
)
replace_once(
    "crates/heptabao-server/src/service.rs",
    '''                let Some(object) = body.as_object() else {\n                    return Response::error(400, "audit enable requires a JSON object");\n                };\n                if object\n                    .get("type")\n''',
    '''                let Some(object) = body.as_object() else {\n                    return Response::error(400, "audit enable requires a JSON object");\n                };\n                if object.keys().any(|key| {\n                    !matches!(\n                        key.as_str(),\n                        "type" | "description" | "options" | "local" | "cas_revision"\n                    )\n                }) {\n                    return Response::error(400, "unsupported file audit parameter");\n                }\n                if let Some(revision) = object.get("cas_revision") {\n                    let Some(revision) = revision.as_u64() else {\n                        return Response::error(400, "cas_revision must be a nonnegative integer");\n                    };\n                    if revision != 1 {\n                        return Response::error(409, "stale audit mount revision");\n                    }\n                }\n                if object\n                    .get("type")\n''',
)

# ---------------------------------------------------------------------------
# Executable regression coverage.
# ---------------------------------------------------------------------------
append_once(
    "crates/heptabao-server/src/engine_tests.rs",
    "fn mount_registry_revision_cas_remount_and_incarnation_are_persisted",
    r'''#[test]
fn mount_registry_revision_cas_remount_and_incarnation_are_persisted() -> TestResult {
    let mut state = EngineState::default();
    request(
        &mut state,
        "",
        "POST",
        "sys/mounts/team",
        json!({"type":"kv","options":{"version":"2"},"cas_revision":0}),
        100,
    )?;
    let created = request(&mut state, "", "GET", "sys/mounts/team", json!({}), 100)?;
    assert_eq!(created.body["data"]["revision"], 1);
    assert_eq!(created.body["data"]["incarnation"], 1);
    request(
        &mut state,
        "",
        "POST",
        "team/data/app",
        json!({"data":{"value":"kept"}}),
        101,
    )?;
    request(
        &mut state,
        "",
        "PUT",
        "sys/mounts/team/tune",
        json!({"description":"team-v2","cas_revision":1}),
        102,
    )?;
    let tuned = request(&mut state, "", "GET", "sys/mounts/team", json!({}), 102)?;
    assert_eq!(tuned.body["data"]["revision"], 2);
    let before_stale = serde_json::to_vec(&state)?;
    assert_eq!(
        request(
            &mut state,
            "",
            "PUT",
            "sys/mounts/team/tune",
            json!({"description":"stale","cas_revision":1}),
            103,
        )
        .err()
        .map(|error| error.status),
        Some(409)
    );
    assert_eq!(before_stale, serde_json::to_vec(&state)?);
    let moved = state.remount("", "team", "archive", Some(2))?;
    assert_eq!(moved.body["data"]["revision"], 3);
    assert!(
        state
            .handle("", "GET", "team/data/app", &json!({}), 104)?
            .is_none()
    );
    let read = request(
        &mut state,
        "",
        "GET",
        "archive/data/app",
        json!({}),
        104,
    )?;
    assert_eq!(read.body["data"]["data"]["value"], "kept");
    let mut restored: EngineState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
    let descriptor = request(
        &mut restored,
        "",
        "GET",
        "sys/mounts/archive",
        json!({}),
        105,
    )?;
    assert_eq!(descriptor.body["data"]["revision"], 3);
    assert_eq!(descriptor.body["data"]["incarnation"], 1);
    request(
        &mut restored,
        "",
        "DELETE",
        "sys/mounts/archive",
        json!({"cas_revision":3}),
        106,
    )?;
    request(
        &mut restored,
        "",
        "POST",
        "sys/mounts/archive",
        json!({"type":"kv","options":{"version":"2"},"cas_revision":0}),
        107,
    )?;
    let recreated = request(
        &mut restored,
        "",
        "GET",
        "sys/mounts/archive",
        json!({}),
        107,
    )?;
    assert_eq!(recreated.body["data"]["revision"], 1);
    assert_eq!(recreated.body["data"]["incarnation"], 2);
    assert_eq!(
        request(
            &mut restored,
            "",
            "GET",
            "archive/data/app",
            json!({}),
            108,
        )?
        .status,
        404
    );
    Ok(())
}
''',
)

append_once(
    "crates/heptabao-server/src/auth_tests.rs",
    "fn auth_mount_revision_tune_remount_and_recreate_rotate_identity",
    r'''#[test]
fn auth_mount_revision_tune_remount_and_recreate_rotate_identity() {
    let (mut state, _raw, root) = setup();
    call(
        &mut state,
        &root,
        "",
        "POST",
        "sys/auth/team",
        json!({"type":"userpass","cas_revision":0}),
        100,
    );
    let created = call(
        &mut state,
        &root,
        "",
        "GET",
        "sys/auth/team",
        json!({}),
        100,
    );
    let accessor = created.body["data"]["accessor"].as_str().unwrap().to_owned();
    assert_eq!(created.body["data"]["revision"], 1);
    call(
        &mut state,
        &root,
        "",
        "PUT",
        "sys/auth/team/tune",
        json!({"description":"team-v2","cas_revision":1}),
        100,
    );
    call(
        &mut state,
        &root,
        "",
        "PUT",
        "auth/team/users/alice",
        json!({"password":"correct horse battery staple"}),
        100,
    );
    let issued = call(
        &mut state,
        &root,
        "",
        "POST",
        "auth/team/login/alice",
        json!({"password":"correct horse battery staple"}),
        101,
    )
    .body["auth"]["client_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let moved = state.remount_mount("", "team", "moved", Some(2)).unwrap();
    assert_eq!(moved.body["data"]["revision"], 3);
    assert_eq!(moved.body["data"]["accessor"], accessor);
    assert_eq!(
        state
            .handle(
                None,
                "",
                "POST",
                "auth/team/login/alice",
                &json!({"password":"correct horse battery staple"}),
                102,
            )
            .err()
            .map(|error| error.status),
        Some(404)
    );
    assert_eq!(
        state
            .handle(
                None,
                "",
                "POST",
                "auth/moved/login/alice",
                &json!({"password":"correct horse battery staple"}),
                102,
            )
            .unwrap()
            .unwrap()
            .status,
        200
    );
    assert!(state.authenticate(&issued, 102).is_ok());
    let before_stale = serde_json::to_vec(&state).unwrap();
    assert_eq!(
        state
            .remount_mount("", "moved", "other", Some(1))
            .err()
            .map(|error| error.status),
        Some(409)
    );
    assert_eq!(before_stale, serde_json::to_vec(&state).unwrap());
    call(
        &mut state,
        &root,
        "",
        "DELETE",
        "sys/auth/moved",
        json!({"cas_revision":3}),
        103,
    );
    assert!(state.authenticate(&issued, 103).is_err());
    call(
        &mut state,
        &root,
        "",
        "POST",
        "sys/auth/moved",
        json!({"type":"userpass","cas_revision":0}),
        104,
    );
    let recreated = call(
        &mut state,
        &root,
        "",
        "GET",
        "sys/auth/moved",
        json!({}),
        104,
    );
    assert_eq!(recreated.body["data"]["revision"], 1);
    assert_ne!(recreated.body["data"]["accessor"], accessor);
}
''',
)

append_once(
    "crates/heptabao-server/src/service_tests.rs",
    "fn mount_registry_remount_cas_and_restart_fence_stale_incarnations",
    r'''#[test]
fn mount_registry_remount_cas_and_restart_fence_stale_incarnations()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new();
    let mut service = root.service()?;
    let (key, token) = bootstrap(&mut service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/team",
            &token,
            json!({"type":"kv","options":{"version":"2"},"cas_revision":0})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "team/data/app",
            &token,
            json!({"data":{"value":"persisted"}})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/remount",
            &token,
            json!({"from":"team/","to":"archive/","cas_revision":1})
        )
        .status,
        200
    );
    assert_eq!(
        call(&mut service, "GET", "team/data/app", &token, json!({})).status,
        404
    );
    assert_eq!(
        call(&mut service, "GET", "archive/data/app", &token, json!({})).body["data"]["data"]["value"],
        "persisted"
    );
    let audit = call(&mut service, "GET", "sys/audit/file", &token, json!({}));
    assert_eq!(audit.body["data"]["revision"], 1);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/audit/file",
            &token,
            json!({"type":"file","cas_revision":2})
        )
        .status,
        409
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/audit/file",
            &token,
            json!({"type":"file","cas_revision":1})
        )
        .status,
        204
    );
    drop(service);

    let mut service = root.service()?;
    assert_eq!(
        call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
        200
    );
    let descriptor = call(
        &mut service,
        "GET",
        "sys/mounts/archive",
        &token,
        json!({}),
    );
    assert_eq!(descriptor.body["data"]["revision"], 2);
    assert_eq!(descriptor.body["data"]["incarnation"], 1);
    assert_eq!(
        call(&mut service, "GET", "archive/data/app", &token, json!({})).body["data"]["data"]["value"],
        "persisted"
    );
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "sys/mounts/archive/tune",
            &token,
            json!({"description":"stale","cas_revision":1})
        )
        .status,
        409
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/mounts/archive",
            &token,
            json!({"cas_revision":2})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/mounts/archive",
            &token,
            json!({"type":"kv","options":{"version":"2"},"cas_revision":0})
        )
        .status,
        204
    );
    let recreated = call(
        &mut service,
        "GET",
        "sys/mounts/archive",
        &token,
        json!({}),
    );
    assert_eq!(recreated.body["data"]["revision"], 1);
    assert_eq!(recreated.body["data"]["incarnation"], 2);
    assert_eq!(
        call(&mut service, "GET", "archive/data/app", &token, json!({})).status,
        404
    );

    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/team",
            &token,
            json!({"type":"userpass","cas_revision":0})
        )
        .status,
        204
    );
    let auth_before = call(
        &mut service,
        "GET",
        "sys/auth/team",
        &token,
        json!({}),
    );
    let auth_accessor = auth_before.body["data"]["accessor"]
        .as_str()
        .ok_or("missing auth accessor")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "PUT",
            "auth/team/users/alice",
            &token,
            json!({"password":"correct horse battery staple"})
        )
        .status,
        204
    );
    let issued = call(
        &mut service,
        "POST",
        "auth/team/login/alice",
        "",
        json!({"password":"correct horse battery staple"}),
    );
    let issued_token = issued.body["auth"]["client_token"]
        .as_str()
        .ok_or("missing auth token")?
        .to_owned();
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/remount",
            &token,
            json!({"from":"auth/team/","to":"auth/moved/","cas_revision":1})
        )
        .status,
        200
    );
    let auth_after = call(
        &mut service,
        "GET",
        "sys/auth/moved",
        &token,
        json!({}),
    );
    assert_eq!(auth_after.body["data"]["revision"], 2);
    assert_eq!(auth_after.body["data"]["accessor"], auth_accessor);
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/team/login/alice",
            "",
            json!({"password":"correct horse battery staple"})
        )
        .status,
        404
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "auth/moved/login/alice",
            "",
            json!({"password":"correct horse battery staple"})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &issued_token,
            json!({})
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &mut service,
            "DELETE",
            "sys/auth/moved",
            &token,
            json!({"cas_revision":2})
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut service,
            "GET",
            "auth/token/lookup-self",
            &issued_token,
            json!({})
        )
        .status,
        403
    );
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/auth/moved",
            &token,
            json!({"type":"userpass","cas_revision":0})
        )
        .status,
        204
    );
    let auth_recreated = call(
        &mut service,
        "GET",
        "sys/auth/moved",
        &token,
        json!({}),
    );
    assert_eq!(auth_recreated.body["data"]["revision"], 1);
    assert_ne!(auth_recreated.body["data"]["accessor"], auth_accessor);
    Ok(())
}
''',
)

# ---------------------------------------------------------------------------
# Repository truth guard and current docs/planning projection.
# ---------------------------------------------------------------------------
repo_test = r'''import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class MountRegistryRuntimeTests(unittest.TestCase):
    def test_runtime_revision_cas_remount_and_lifecycle_are_bound(self):
        engines = (ROOT / "crates/heptabao-server/src/engines.rs").read_text()
        auth = (ROOT / "crates/heptabao-server/src/auth.rs").read_text()
        service = (ROOT / "crates/heptabao-server/src/service.rs").read_text()
        tests = "\n".join(
            (ROOT / path).read_text()
            for path in (
                "crates/heptabao-server/src/engine_tests.rs",
                "crates/heptabao-server/src/auth_tests.rs",
                "crates/heptabao-server/src/service_tests.rs",
            )
        )
        for marker in ("cas_revision", "revision", "incarnation", "mount_epochs", "pub(crate) fn remount"):
            self.assertIn(marker, engines)
        for marker in ("cas_revision", "revision", "accessor", "pub(super) fn remount_mount"):
            self.assertIn(marker, auth)
        for marker in ('path == "sys/remount"', '"revision": 1', '"accessor": "audit_file"'):
            self.assertIn(marker, service)
        for name in (
            "mount_registry_revision_cas_remount_and_incarnation_are_persisted",
            "auth_mount_revision_tune_remount_and_recreate_rotate_identity",
            "mount_registry_remount_cas_and_restart_fence_stale_incarnations",
        ):
            self.assertIn(f"fn {name}", tests)

    def test_execution_row_keeps_later_phases_open(self):
        matrix = json.loads((ROOT / "planning/HEPTABAO_REPLACEMENT_EXECUTION_V2.json").read_text())
        row = next(row for row in matrix["surfaces"] if row["surface_id"] == "HB-SURFACE-MOUNT-REGISTRY")
        self.assertEqual(row["implementation"], "RUNTIME_COMPLETE_LOCAL")
        self.assertFalse(row["full_surface_verified"])
        self.assertFalse(row["independently_admitted"])
        self.assertIn("migration", row["remaining_scope"].lower())
        self.assertIn("multi-host", row["remaining_scope"].lower())
        self.assertIn("2.6.2", row["remaining_scope"])
        self.assertEqual(
            set(row["implementation_evidence"]["local_dimensions"]),
            {"protocol_framing", "authorization_before_effect", "effect_readback", "crash_reopen"},
        )


if __name__ == "__main__":
    unittest.main()
'''
write("tests/repository/test_mount_registry_runtime.py", repo_test)

append_once(
    "docs/engines/HEPTABAO_SINGLE_NODE_ENGINES.md",
    "## Mount registry revision and remount boundary",
    '''## Mount registry revision and remount boundary

Secret-engine mounts now persist a monotonically increasing `revision` and a path
`incarnation`. Mutating tune/delete/remount calls may provide `cas_revision`; a stale
value returns conflict before state mutation. Disable records the next path incarnation,
so recreating the same path cannot resurrect the old mount identity or embedded dynamic
state. `sys/remount` moves the complete backend atomically inside the Service transaction,
invalidates the old route immediately, rejects overlapping/reserved destinations, and is
fenced while dynamic leases are live. Repository-local restart tests verify the moved
backend, revision/incarnation and disable/recreate boundary. Later migration, multi-host
fault/upgrade, full OpenBao 2.6.2 differential and independent admission remain open.''',
)
append_once(
    "docs/auth/HEPTABAO_SINGLE_NODE_AUTH.md",
    "## Auth mount revision, tune and remount boundary",
    '''## Auth mount revision, tune and remount boundary

Auth mounts expose a persisted `revision` alongside the existing accessor. Tune, disable
and remount accept `cas_revision` and reject stale operators without mutation. A remount
preserves the accessor while atomically moving mount-local users, roles, JWT/OIDC,
Kubernetes and bounded LDAP state and retagging issued-token mount provenance. Disabling
the moved mount retains the existing credential/token revocation behavior; recreating the
path issues a different accessor and revision 1. `sys/remount` cannot cross auth/secret
classes or namespaces. These are repository-local runtime guarantees, not full external
provider or OpenBao compatibility admission.''',
)

matrix_path = ROOT / "planning/HEPTABAO_REPLACEMENT_EXECUTION_V2.json"
matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
rows = [row for row in matrix["surfaces"] if row["surface_id"] == "HB-SURFACE-MOUNT-REGISTRY"]
if len(rows) != 1:
    raise SystemExit("mount registry execution row missing or duplicated")
row = rows[0]
if row["implementation"] != "PARTIAL_RUNTIME":
    raise SystemExit(f"unexpected mount registry state: {row['implementation']}")
row["implementation"] = "RUNTIME_COMPLETE_LOCAL"
row["runtime_sources"] = [
    "crates/heptabao-server/src/auth.rs",
    "crates/heptabao-server/src/engines.rs",
    "crates/heptabao-server/src/service.rs",
]
row["remaining_scope"] = (
    "Local secret/auth/audit mount registry, revision CAS, atomic remount, overlap and reserved-path rejection, "
    "restart persistence and disable/recreate incarnation or accessor fencing are executable; full asset migration, "
    "real multi-host fault/upgrade, full OpenBao 2.6.2 differential and independent admission remain later ordered phases."
)
row["implementation_evidence"] = {
    "source_paths": [
        "crates/heptabao-server/src/auth.rs",
        "crates/heptabao-server/src/engines.rs",
        "crates/heptabao-server/src/service.rs",
    ],
    "test_anchors": [
        {
            "path": "crates/heptabao-server/src/engine_tests.rs",
            "name": "mount_registry_revision_cas_remount_and_incarnation_are_persisted",
        },
        {
            "path": "crates/heptabao-server/src/auth_tests.rs",
            "name": "auth_mount_revision_tune_remount_and_recreate_rotate_identity",
        },
        {
            "path": "crates/heptabao-server/src/service_tests.rs",
            "name": "mount_registry_remount_cas_and_restart_fence_stale_incarnations",
        },
    ],
    "local_dimensions": [
        "protocol_framing",
        "authorization_before_effect",
        "effect_readback",
        "crash_reopen",
    ],
}
matrix_path.write_text(json.dumps(matrix, indent=2) + "\n", encoding="utf-8")
