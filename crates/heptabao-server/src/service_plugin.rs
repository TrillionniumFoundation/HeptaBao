use super::*;
use heptabao_domain::{CanonicalPath, Id, SecretValue};
use heptabao_plugin_contracts::{PluginDescriptor, PluginKind, PluginRegistry};
use heptabao_plugin_host::{
    CommandSandboxRunner, PluginHost, PluginHostError, PluginHostState, PluginLimits,
    PluginManifest, PluginOperation, SandboxBinding, SecretEnvironment,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

fn req_bytes() -> usize {
    256 * 1024
}
fn resp_bytes() -> usize {
    1024 * 1024
}
fn timeout_ms() -> u64 {
    5_000
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginSecretConfig {
    pub id: String,
    pub command: String,
    pub command_sha256: String,
    pub sandbox_provider_id: String,
    pub sandbox_command: String,
    pub sandbox_command_sha256: String,
    pub sandbox_profile_id: String,
    #[serde(default = "req_bytes")]
    pub maximum_request_bytes: usize,
    #[serde(default = "resp_bytes")]
    pub maximum_response_bytes: usize,
    #[serde(default = "timeout_ms")]
    pub timeout_ms: u64,
}

pub(super) type SharedSecretPlugin = Arc<Mutex<PluginHost<CommandSandboxRunner>>>;

pub(super) struct PluginReadPlan {
    pub namespace: String,
    pub mount: String,
    pub plugin_id: String,
    host: SharedSecretPlugin,
    request: SecretValue,
}

#[derive(Serialize)]
struct PluginReadRequest<'a> {
    method: &'a str,
    namespace: &'a str,
    mount: &'a str,
    path: &'a str,
    data: &'a Value,
}

fn digest(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("plugin checksum must be 64 hexadecimal characters".into());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| "invalid plugin checksum")?;
    }
    Ok(out)
}

pub(super) fn admit_secret_plugins(
    configs: Vec<PluginSecretConfig>,
) -> Result<BTreeMap<String, SharedSecretPlugin>, String> {
    if configs.len() > 32 {
        return Err("plugin runtime count exceeds bound".into());
    }
    let mut out = BTreeMap::new();
    for c in configs {
        let id = Id::parse(c.id.clone()).map_err(|_| "invalid plugin identifier")?;
        if out.contains_key(id.as_str()) {
            return Err("duplicate plugin identifier".into());
        }
        let descriptor = PluginDescriptor::new(
            id.clone(),
            PluginKind::Secrets,
            CanonicalPath::parse(c.command).map_err(|_| "invalid plugin executable path")?,
            digest(&c.command_sha256)?,
            1,
        )
        .map_err(|_| "invalid plugin descriptor")?;
        let mut registry = PluginRegistry::default();
        registry
            .register(descriptor)
            .map_err(|_| "cannot register plugin")?;
        registry.enable(&id).map_err(|_| "cannot enable plugin")?;
        let descriptor = registry.get(&id).map_err(|_| "plugin disappeared")?.clone();
        let sandbox = SandboxBinding::new(
            Id::parse(c.sandbox_provider_id).map_err(|_| "invalid sandbox provider identifier")?,
            CanonicalPath::parse(c.sandbox_command)
                .map_err(|_| "invalid sandbox executable path")?,
            digest(&c.sandbox_command_sha256)?,
            Id::parse(c.sandbox_profile_id).map_err(|_| "invalid sandbox profile identifier")?,
        )
        .map_err(|_| "invalid sandbox binding")?;
        let manifest = PluginManifest::new(
            descriptor,
            sandbox,
            PluginLimits {
                maximum_request_bytes: c.maximum_request_bytes,
                maximum_response_bytes: c.maximum_response_bytes,
                timeout_ms: c.timeout_ms,
            },
            BTreeSet::from([PluginOperation::Read]),
            BTreeSet::new(),
        )
        .map_err(|_| "invalid read-only plugin manifest")?;
        let host = PluginHost::admit(manifest, CommandSandboxRunner)
            .map_err(|_| "plugin or sandbox admission failed")?;
        out.insert(id.to_string(), Arc::new(Mutex::new(host)));
    }
    Ok(out)
}

impl PluginReadPlan {
    pub(super) fn execute(&self) -> Result<Value, Response> {
        let mut host = self
            .host
            .lock()
            .map_err(|_| Response::error(503, "plugin host lock unavailable"))?;
        let response = host
            .invoke(
                PluginOperation::Read,
                &self.request,
                &SecretEnvironment::new(),
            )
            .map_err(failure)?;
        let value = crate::auth::parse_strict_json(response.expose())
            .map_err(|_| Response::error(503, "plugin returned invalid JSON"))?;
        if !value.is_object() {
            return Err(Response::error(
                503,
                "plugin response must be a JSON object",
            ));
        }
        Ok(value)
    }
}

fn failure(error: PluginHostError) -> Response {
    let message = match error {
        PluginHostError::ProcessBeforeEntry | PluginHostError::SandboxUnavailable => {
            "plugin unavailable before entry"
        }
        PluginHostError::ProcessOutcomeUnknown
        | PluginHostError::ReconciliationRequired
        | PluginHostError::ResponseTooLarge
        | PluginHostError::MalformedResponse => "plugin read outcome unavailable; host fenced",
        _ => "plugin read rejected by admitted runtime",
    };
    Response::error(503, message)
}

impl Service {
    pub(super) fn plugin_catalog_handles(path: &str) -> bool {
        path == "sys/plugins/catalog/secret"
            || path.starts_with("sys/plugins/catalog/secret/")
    }

    pub(super) fn validate_plugin_mount_request(
        &self,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<(), Response> {
        if !matches!(method, "POST" | "PUT")
            || !path.starts_with("sys/mounts/")
            || body.get("type").and_then(Value::as_str) != Some("plugin")
        {
            return Ok(());
        }
        let plugin_id = body
            .get("config")
            .and_then(Value::as_object)
            .and_then(|config| config.get("plugin_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| Response::error(400, "plugin mount requires config.plugin_id"))?;
        if !self.plugins.contains_key(plugin_id) {
            return Err(Response::error(
                400,
                "plugin mount references a plugin not admitted by this deployment",
            ));
        }
        Ok(())
    }

    pub(super) fn plugin_catalog_route(
        &self,
        state: &State,
        principal: Option<&Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let RequestView {
            namespace,
            method,
            path,
            body,
            now,
            wrap_ttl_seconds,
            ..
        } = request;
        if !namespace.is_empty() {
            return Response::error(403, "plugin catalog is root-namespace only");
        }
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        let capability = if matches!(*method, "GET" | "HEAD") {
            "read"
        } else if matches!(*method, "LIST" | "SCAN") {
            "list"
        } else {
            "update"
        };
        if let Err(error) = state
            .auth
            .authorize_sudo_request(principal, namespace, path, capability, *now)
        {
            return Response::error(error.status, &error.message);
        }
        if wrap_ttl_seconds.is_some() {
            return Response::error(501, "plugin catalog responses cannot be wrapped");
        }
        if body.as_object().is_none_or(|object| !object.is_empty()) {
            return Response::error(400, "plugin catalog accepts an empty request body");
        }
        let suffix = path
            .strip_prefix("sys/plugins/catalog/secret")
            .unwrap_or_default();
        if suffix.is_empty() {
            if !matches!(*method, "GET" | "HEAD" | "LIST" | "SCAN") {
                return Response::error(
                    501,
                    "runtime plugin catalog mutation is not implemented",
                );
            }
            return Response::ok(json!({
                "data": {
                    "keys": self.plugins.keys().cloned().collect::<Vec<_>>()
                }
            }));
        }
        let Some(plugin_id) = suffix.strip_prefix('/').filter(|value| {
            !value.is_empty() && !value.contains('/')
        }) else {
            return Response::error(404, "plugin catalog entry not found");
        };
        if !matches!(*method, "GET" | "HEAD") {
            return Response::error(
                501,
                "runtime plugin catalog mutation is not implemented",
            );
        }
        let Some(host) = self.plugins.get(plugin_id) else {
            return Response::error(404, "plugin catalog entry not found");
        };
        let host = match host.lock() {
            Ok(host) => host,
            Err(_) => return Response::error(503, "plugin host lock unavailable"),
        };
        let manifest = host.manifest();
        let descriptor = manifest.descriptor();
        let host_state = match host.state() {
            PluginHostState::Active => "active",
            PluginHostState::ReconciliationRequired => "reconciliation_required",
            PluginHostState::Revoked => "revoked",
        };
        let limits = manifest.limits();
        Response::ok(json!({
            "data": {
                "name": plugin_id,
                "type": "secret",
                "sha256": hex(descriptor.checksum()),
                "protocol_version": descriptor.protocol_version(),
                "generation": descriptor.generation(),
                "state": host_state,
                "maximum_request_bytes": limits.maximum_request_bytes,
                "maximum_response_bytes": limits.maximum_response_bytes,
                "timeout_ms": limits.timeout_ms
            }
        }))
    }

    pub(super) fn plugin_secret_handles(&self, state: &State, namespace: &str, path: &str) -> bool {
        state.engines.plugin_secret_mount(namespace, path).is_some()
    }

    pub(super) fn plugin_secret_route(
        &mut self,
        state: State,
        principal: Option<&Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let RequestView {
            namespace,
            method,
            path,
            body,
            now,
            wrap_ttl_seconds,
            ..
        } = request;
        let Some((mount, plugin_id)) = state.engines.plugin_secret_mount(namespace, path) else {
            return Response::error(404, "plugin mount not found");
        };
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        let capability = match *method {
            "GET" | "HEAD" => "read",
            "LIST" | "SCAN" => "list",
            _ => "update",
        };
        if let Err(e) = state
            .auth
            .authorize_request(principal, namespace, path, capability, *now)
        {
            return Response::error(e.status, &e.message);
        }
        if wrap_ttl_seconds.is_some() {
            return Response::error(
                501,
                "response wrapping is not implemented for external plugins",
            );
        }
        if !matches!(*method, "GET" | "HEAD" | "LIST" | "SCAN") {
            return Response::error(
                501,
                "write-capable plugins require durable external-effect reconciliation",
            );
        }
        if self.pending_plugin_read.is_some() {
            return Response::error(503, "another plugin invocation is pending");
        }
        let Some(host) = self.plugins.get(&plugin_id).cloned() else {
            return Response::error(
                503,
                "plugin mount references an unadmitted deployment plugin",
            );
        };
        let relative = path.strip_prefix(&mount).unwrap_or(path);
        let encoded = match serde_json::to_vec(&PluginReadRequest {
            method,
            namespace,
            mount: mount.trim_end_matches('/'),
            path: relative,
            data: body,
        }) {
            Ok(v) => v,
            Err(_) => return Response::error(500, "plugin request encoding failed"),
        };
        let request = match SecretValue::new(encoded) {
            Ok(v) => v,
            Err(_) => return Response::error(413, "plugin request exceeds runtime bound"),
        };
        self.pending_plugin_read = Some(PluginReadPlan {
            namespace: (*namespace).to_owned(),
            mount,
            plugin_id,
            host,
            request,
        });
        Response::error(500, "plugin read was not dispatched")
    }

    pub(super) fn finalize_plugin_read(
        &mut self,
        plan: &PluginReadPlan,
        result: Result<Value, Response>,
    ) -> Response {
        let value = match result {
            Ok(v) => v,
            Err(e) => return e,
        };
        if let Some(ha) = &self.ha {
            let ok = ha
                .lock()
                .ok()
                .and_then(|ha| ha.ensure_linearizable().ok())
                .is_some();
            if !ok {
                return Response::error(
                    503,
                    "plugin response withheld after HA leadership uncertainty",
                );
            }
        }
        let Some(state) = self.state.as_ref() else {
            return Response::error(503, "plugin response withheld because server sealed");
        };
        if state
            .engines
            .plugin_secret_mount(&plan.namespace, &plan.mount)
            .is_none_or(|(m, id)| m != plan.mount || id != plan.plugin_id)
        {
            return Response::error(
                503,
                "plugin response withheld because durable mount binding changed",
            );
        }
        Response::ok(json!({"data": value}))
    }
}

#[cfg(test)]
mod tests {
    use crate::engines::EngineState;
    use serde_json::json;

    #[test]
    fn plugin_mount_persists_only_stable_identity_and_direct_dispatch_is_fenced()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut state = EngineState::default();
        state
            .handle(
                "",
                "POST",
                "sys/mounts/external",
                &json!({"type":"plugin","config":{"plugin_id":"readonly_fixture"}}),
                1,
            )?
            .ok_or("mount response missing")?;
        assert_eq!(
            state.plugin_secret_mount("", "external/item"),
            Some(("external/".into(), "readonly_fixture".into()))
        );
        assert_eq!(
            state
                .handle("", "GET", "external/item", &json!({}), 2)
                .err()
                .map(|e| e.status),
            Some(501)
        );
        let restored: EngineState = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
        assert_eq!(
            restored.plugin_secret_mount("", "external/item"),
            Some(("external/".into(), "readonly_fixture".into()))
        );
        Ok(())
    }
}
