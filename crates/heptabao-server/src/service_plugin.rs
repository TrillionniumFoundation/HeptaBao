use super::*;
use heptabao_domain::{CanonicalPath, Id, SecretValue};
use heptabao_kms_contracts::{KeyCatalog, KeyRegistration, KeyVersion, KmsCapability};
use heptabao_plugin_contracts::{PluginDescriptor, PluginKind, PluginRegistry};
use heptabao_plugin_host::{
    CommandSandboxRunner, PluginHost, PluginHostError, PluginHostState, PluginLimits,
    PluginManifest, PluginOperation, SandboxBinding, SecretEnvironment,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

type KmsPluginMaps = (
    BTreeMap<String, SharedKmsPlugin>,
    BTreeMap<String, KmsKeyBinding>,
);

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

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginAuthConfig {
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

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginDatabaseConfig {
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

fn kms_caps() -> Vec<String> {
    vec!["wrap".into(), "unwrap".into(), "generate_data_key".into()]
}

fn kms_enabled() -> bool {
    true
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginKmsConfig {
    pub id: String,
    pub command: String,
    pub command_sha256: String,
    pub sandbox_provider_id: String,
    pub sandbox_command: String,
    pub sandbox_command_sha256: String,
    pub sandbox_profile_id: String,
    pub key_id: String,
    pub key_version: u64,
    #[serde(default = "kms_caps")]
    pub capabilities: Vec<String>,
    #[serde(default = "kms_enabled")]
    pub enabled: bool,
    #[serde(default = "req_bytes")]
    pub maximum_request_bytes: usize,
    #[serde(default = "resp_bytes")]
    pub maximum_response_bytes: usize,
    #[serde(default = "timeout_ms")]
    pub timeout_ms: u64,
}

pub(super) type SharedSecretPlugin = Arc<Mutex<PluginHost<CommandSandboxRunner>>>;
pub(super) type SharedAuthPlugin = Arc<Mutex<PluginHost<CommandSandboxRunner>>>;
pub(super) type SharedDatabasePlugin = Arc<Mutex<PluginHost<CommandSandboxRunner>>>;

pub(super) type SharedKmsPlugin = Arc<Mutex<PluginHost<CommandSandboxRunner>>>;

#[derive(Clone, Debug)]
pub(super) struct KmsKeyBinding {
    pub key_id: Id,
    pub key_version: KeyVersion,
    pub capabilities: BTreeSet<KmsCapability>,
    pub enabled: bool,
}

/// Own the original affine admission capability through unlocked provider I/O.
/// Rechecking it never authenticates a bearer again or spends another token use.
struct PluginResponseAuthority {
    principal: Principal,
    namespace: String,
    namespace_incarnation: Option<u64>,
    cluster_id: String,
    path: String,
    capability: &'static str,
    sudo: bool,
    admitted_at: u64,
    started: std::time::Instant,
    deadline: Option<std::time::Instant>,
}

impl PluginResponseAuthority {
    fn new(
        principal: Principal,
        state: &State,
        request: &RequestView<'_>,
        capability: &'static str,
        sudo: bool,
    ) -> Self {
        Self {
            principal,
            namespace: request.namespace.to_owned(),
            namespace_incarnation: state.namespaces.incarnation(request.namespace),
            cluster_id: state.cluster_id.clone(),
            path: request.path.to_owned(),
            capability,
            sudo,
            admitted_at: request.now,
            started: request.admission_started,
            deadline: crate::request_deadline::current(),
        }
    }

    fn now(&self) -> u64 {
        std::time::Duration::from_secs(self.admitted_at)
            .saturating_add(self.started.elapsed())
            .as_secs()
    }

    fn deadline_expired(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    }
}

pub(super) struct PluginKmsPlan {
    pub plugin_id: String,
    pub key_binding: KmsKeyBinding,
    host: SharedKmsPlugin,
    request: SecretValue,
    action: &'static str,
    authority: PluginResponseAuthority,
}

pub(crate) struct PluginKmsObservation {
    value: Value,
}

pub(super) struct PluginReadPlan {
    pub namespace: String,
    pub mount: String,
    pub plugin_id: String,
    mount_incarnation: u64,
    host: SharedSecretPlugin,
    request: SecretValue,
    authority: PluginResponseAuthority,
}

pub(super) struct PluginAuthPlan {
    pub(super) auth: crate::auth::PluginAuthLoginPlan,
    host: SharedAuthPlugin,
    request: SecretValue,
}

pub(crate) struct PluginAuthObservation {
    alias: String,
}

#[derive(Serialize)]
struct PluginAuthRequest<'a> {
    method: &'a str,
    namespace: &'a str,
    mount: &'a str,
    data: &'a Value,
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

pub(super) fn admit_auth_plugins(
    configs: Vec<PluginAuthConfig>,
) -> Result<BTreeMap<String, SharedAuthPlugin>, String> {
    if configs.len() > 32 {
        return Err("authentication plugin runtime count exceeds bound".into());
    }
    let mut out = BTreeMap::new();
    for c in configs {
        let id = Id::parse(c.id.clone()).map_err(|_| "invalid plugin identifier")?;
        if out.contains_key(id.as_str()) {
            return Err("duplicate authentication plugin identifier".into());
        }
        let descriptor = PluginDescriptor::new(
            id.clone(),
            PluginKind::Authentication,
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
        .map_err(|_| "invalid authentication plugin manifest")?;
        let host = PluginHost::admit(manifest, CommandSandboxRunner)
            .map_err(|_| "plugin or sandbox admission failed")?;
        out.insert(id.to_string(), Arc::new(Mutex::new(host)));
    }
    Ok(out)
}

pub(super) fn admit_database_plugins(
    configs: Vec<PluginDatabaseConfig>,
) -> Result<BTreeMap<String, SharedDatabasePlugin>, String> {
    if configs.len() > 32 {
        return Err("database plugin runtime count exceeds bound".into());
    }
    let mut out = BTreeMap::new();
    for c in configs {
        let id = Id::parse(c.id.clone()).map_err(|_| "invalid database plugin identifier")?;
        if out.contains_key(id.as_str()) {
            return Err("duplicate database plugin identifier".into());
        }
        let descriptor = PluginDescriptor::new(
            id.clone(),
            PluginKind::Database,
            CanonicalPath::parse(c.command)
                .map_err(|_| "invalid database plugin executable path")?,
            digest(&c.command_sha256)?,
            1,
        )
        .map_err(|_| "invalid database plugin descriptor")?;
        let mut registry = PluginRegistry::default();
        registry
            .register(descriptor)
            .map_err(|_| "cannot register database plugin")?;
        registry
            .enable(&id)
            .map_err(|_| "cannot enable database plugin")?;
        let descriptor = registry
            .get(&id)
            .map_err(|_| "database plugin disappeared")?
            .clone();
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
            BTreeSet::from([
                PluginOperation::Read,
                PluginOperation::Issue,
                PluginOperation::Renew,
                PluginOperation::Revoke,
            ]),
            BTreeSet::new(),
        )
        .map_err(|_| "invalid database plugin manifest")?;
        let host = PluginHost::admit(manifest, CommandSandboxRunner)
            .map_err(|_| "database plugin or sandbox admission failed")?;
        out.insert(id.to_string(), Arc::new(Mutex::new(host)));
    }
    Ok(out)
}

pub(super) fn admit_kms_plugins(configs: Vec<PluginKmsConfig>) -> Result<KmsPluginMaps, String> {
    if configs.len() > 16 {
        return Err("KMS plugin runtime count exceeds bound".into());
    }
    let mut hosts = BTreeMap::new();
    let mut keys = BTreeMap::new();
    for c in configs {
        let id = Id::parse(c.id.clone()).map_err(|_| "invalid KMS plugin identifier")?;
        if hosts.contains_key(id.as_str()) {
            return Err("duplicate KMS plugin identifier".into());
        }
        let key_id = Id::parse(c.key_id.clone()).map_err(|_| "invalid KMS key identifier")?;
        let key_version = KeyVersion::new(c.key_version).map_err(|_| "invalid KMS key version")?;
        let mut capabilities = BTreeSet::new();
        for capability in c.capabilities {
            let capability = match capability.as_str() {
                "wrap" => KmsCapability::Wrap,
                "unwrap" => KmsCapability::Unwrap,
                "generate_data_key" => KmsCapability::GenerateDataKey,
                _ => return Err("unsupported KMS capability".into()),
            };
            capabilities.insert(capability);
        }
        if capabilities.is_empty() {
            return Err("KMS plugin requires at least one capability".into());
        }
        let mut catalog = KeyCatalog::default();
        catalog
            .register(KeyRegistration {
                key_id: key_id.clone(),
                version: key_version,
                capabilities: capabilities.clone(),
            })
            .map_err(|_| "invalid KMS key registration")?;

        let descriptor = PluginDescriptor::new(
            id.clone(),
            PluginKind::Kms,
            CanonicalPath::parse(c.command).map_err(|_| "invalid KMS plugin executable path")?,
            digest(&c.command_sha256)?,
            1,
        )
        .map_err(|_| "invalid KMS plugin descriptor")?;
        let mut registry = PluginRegistry::default();
        registry
            .register(descriptor)
            .map_err(|_| "cannot register KMS plugin")?;
        registry
            .enable(&id)
            .map_err(|_| "cannot enable KMS plugin")?;
        let descriptor = registry
            .get(&id)
            .map_err(|_| "KMS plugin disappeared")?
            .clone();
        let sandbox = SandboxBinding::new(
            Id::parse(c.sandbox_provider_id)
                .map_err(|_| "invalid KMS sandbox provider identifier")?,
            CanonicalPath::parse(c.sandbox_command)
                .map_err(|_| "invalid KMS sandbox executable path")?,
            digest(&c.sandbox_command_sha256)?,
            Id::parse(c.sandbox_profile_id)
                .map_err(|_| "invalid KMS sandbox profile identifier")?,
        )
        .map_err(|_| "invalid KMS sandbox binding")?;
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
        .map_err(|_| "invalid KMS plugin manifest")?;
        let host = PluginHost::admit(manifest, CommandSandboxRunner)
            .map_err(|_| "KMS plugin or sandbox admission failed")?;
        hosts.insert(id.to_string(), Arc::new(Mutex::new(host)));
        keys.insert(
            id.to_string(),
            KmsKeyBinding {
                key_id,
                key_version,
                capabilities,
                enabled: c.enabled,
            },
        );
    }
    Ok((hosts, keys))
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

impl PluginAuthPlan {
    pub(super) fn execute(&self) -> Result<PluginAuthObservation, Response> {
        let mut host = self
            .host
            .lock()
            .map_err(|_| Response::error(503, "authentication plugin host lock unavailable"))?;
        let response = host
            .invoke(
                PluginOperation::Read,
                &self.request,
                &SecretEnvironment::new(),
            )
            .map_err(failure)?;
        let value = crate::auth::parse_strict_json(response.expose())
            .map_err(|_| Response::error(503, "authentication plugin returned invalid JSON"))?;
        let object = value.as_object().ok_or_else(|| {
            Response::error(503, "authentication plugin response must be an object")
        })?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "authenticated" | "alias"))
        {
            return Err(Response::error(
                503,
                "authentication plugin response contains unsupported authority fields",
            ));
        }
        let authenticated = object
            .get("authenticated")
            .and_then(Value::as_bool)
            .ok_or_else(|| Response::error(503, "authentication plugin result is missing"))?;
        if !authenticated {
            return Err(Response::error(403, "plugin authentication denied"));
        }
        let alias = object
            .get("alias")
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
            })
            .ok_or_else(|| Response::error(503, "authentication plugin alias is invalid"))?;
        Ok(PluginAuthObservation {
            alias: alias.to_owned(),
        })
    }
}

impl PluginKmsPlan {
    pub(super) fn execute(&self) -> Result<PluginKmsObservation, Response> {
        let mut host = self
            .host
            .lock()
            .map_err(|_| Response::error(503, "KMS plugin host lock unavailable"))?;
        let response = host
            .invoke(
                PluginOperation::Read,
                &self.request,
                &SecretEnvironment::new(),
            )
            .map_err(kms_failure)?;
        let value = crate::auth::parse_strict_json(response.expose())
            .map_err(|_| Response::error(503, "KMS plugin returned invalid JSON"))?;
        let object = value
            .as_object()
            .ok_or_else(|| Response::error(503, "KMS plugin response must be an object"))?;
        if object.get("action").and_then(Value::as_str) != Some(self.action)
            || object.get("key_id").and_then(Value::as_str)
                != Some(self.key_binding.key_id.as_str())
            || object.get("key_version").and_then(Value::as_u64)
                != Some(self.key_binding.key_version.as_u64())
        {
            return Err(Response::error(
                503,
                "KMS plugin response key binding mismatch",
            ));
        }
        Ok(PluginKmsObservation { value })
    }
}

fn kms_failure(error: PluginHostError) -> Response {
    let (status, message) = match error {
        PluginHostError::ProcessBeforeEntry | PluginHostError::SandboxUnavailable => {
            (503, "KMS provider unavailable before entry")
        }
        PluginHostError::ProcessOutcomeUnknown
        | PluginHostError::ReconciliationRequired
        | PluginHostError::ResponseTooLarge
        | PluginHostError::MalformedResponse => (
            503,
            "KMS provider outcome unknown; host fenced pending reconciliation",
        ),
        _ => (503, "KMS provider invocation rejected"),
    };
    Response::error(status, message)
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
            || path == "sys/plugins/catalog/kms"
            || path.starts_with("sys/plugins/catalog/kms/")
            || path == "sys/plugins/catalog/auth"
            || path.starts_with("sys/plugins/catalog/auth/")
            || path == "sys/plugins/catalog/database"
            || path.starts_with("sys/plugins/catalog/database/")
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
        let (kind, suffix, plugins) =
            if let Some(suffix) = path.strip_prefix("sys/plugins/catalog/secret") {
                ("secret", suffix, &self.plugins)
            } else if let Some(suffix) = path.strip_prefix("sys/plugins/catalog/auth") {
                ("auth", suffix, &self.auth_plugins)
            } else if let Some(suffix) = path.strip_prefix("sys/plugins/catalog/database") {
                ("database", suffix, &self.database_plugins)
            } else if let Some(suffix) = path.strip_prefix("sys/plugins/catalog/kms") {
                ("kms", suffix, &self.kms_plugins)
            } else {
                return Response::error(404, "plugin catalog not found");
            };
        if suffix.is_empty() {
            if !matches!(*method, "GET" | "HEAD" | "LIST" | "SCAN") {
                return Response::error(501, "runtime plugin catalog mutation is not implemented");
            }
            return Response::ok(json!({
                "data": {
                    "keys": plugins.keys().cloned().collect::<Vec<_>>()
                }
            }));
        }
        let Some(plugin_id) = suffix
            .strip_prefix('/')
            .filter(|value| !value.is_empty() && !value.contains('/'))
        else {
            return Response::error(404, "plugin catalog entry not found");
        };
        if !matches!(*method, "GET" | "HEAD") {
            return Response::error(501, "runtime plugin catalog mutation is not implemented");
        }
        let Some(host) = plugins.get(plugin_id) else {
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
                "type": kind,
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

    pub(super) fn plugin_kms_handles(path: &str) -> bool {
        path.starts_with("sys/plugins/kms/")
    }

    pub(super) fn plugin_kms_route(
        &mut self,
        state: &State,
        principal: Option<Principal>,
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
            return Response::error(403, "KMS plugin runtime is root-namespace only");
        }
        if !matches!(*method, "POST" | "PUT") {
            return Response::error(405, "KMS plugin operation requires POST or PUT");
        }
        if wrap_ttl_seconds.is_some() {
            return Response::error(501, "KMS plugin responses cannot be wrapped");
        }
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        if let Err(error) = state
            .auth
            .authorize_sudo_request(&principal, namespace, path, "update", *now)
        {
            return Response::error(error.status, &error.message);
        }
        let Some(rest) = path.strip_prefix("sys/plugins/kms/") else {
            return Response::error(404, "KMS plugin route not found");
        };
        let Some((plugin_id, action_path)) = rest.split_once('/') else {
            return Response::error(404, "KMS plugin route not found");
        };
        if plugin_id.is_empty() || action_path.contains('/') {
            return Response::error(404, "KMS plugin route not found");
        }
        let (action, capability) = match action_path {
            "wrap" => ("wrap", KmsCapability::Wrap),
            "unwrap" => ("unwrap", KmsCapability::Unwrap),
            "generate-data-key" => ("generate_data_key", KmsCapability::GenerateDataKey),
            _ => return Response::error(404, "KMS plugin operation not found"),
        };
        let Some(binding) = self.kms_keys.get(plugin_id).cloned() else {
            return Response::error(404, "KMS plugin key binding not found");
        };
        if !binding.enabled {
            return Response::error(403, "KMS key is disabled");
        }
        if !binding.capabilities.contains(&capability) {
            return Response::error(403, "KMS key capability is denied");
        }
        let Some(object) = body.as_object() else {
            return Response::error(400, "KMS request body must be an object");
        };
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "key_id"
                    | "key_version"
                    | "purpose"
                    | "associated_data_digest"
                    | "plaintext"
                    | "ciphertext"
                    | "bytes"
            )
        }) {
            return Response::error(400, "KMS request contains unsupported fields");
        }
        if object.get("key_id").and_then(Value::as_str) != Some(binding.key_id.as_str())
            || object.get("key_version").and_then(Value::as_u64)
                != Some(binding.key_version.as_u64())
        {
            return Response::error(400, "KMS request key binding mismatch");
        }
        let purpose = object.get("purpose").and_then(Value::as_str).unwrap_or("");
        if Id::parse(purpose.to_owned()).is_err() {
            return Response::error(400, "KMS purpose is invalid");
        }
        let aad = object
            .get("associated_data_digest")
            .and_then(Value::as_str)
            .unwrap_or("");
        if aad.len() != 64
            || !aad.bytes().all(|byte| byte.is_ascii_hexdigit())
            || aad.bytes().all(|byte| byte == b'0')
        {
            return Response::error(400, "KMS associated-data digest is invalid");
        }
        match action {
            "wrap" => {
                let Some(value) = object.get("plaintext").and_then(Value::as_str) else {
                    return Response::error(400, "KMS wrap requires plaintext");
                };
                if value.is_empty() || value.len() > 256 * 1024 || object.contains_key("ciphertext")
                {
                    return Response::error(400, "KMS wrap payload is invalid");
                }
            }
            "unwrap" => {
                let Some(value) = object.get("ciphertext").and_then(Value::as_str) else {
                    return Response::error(400, "KMS unwrap requires ciphertext");
                };
                if value.is_empty() || value.len() > 512 * 1024 || object.contains_key("plaintext")
                {
                    return Response::error(400, "KMS unwrap payload is invalid");
                }
            }
            "generate_data_key" => {
                let Some(bytes) = object.get("bytes").and_then(Value::as_u64) else {
                    return Response::error(400, "KMS data-key request requires bytes");
                };
                if !(1..=65_536).contains(&bytes)
                    || object.contains_key("plaintext")
                    || object.contains_key("ciphertext")
                {
                    return Response::error(400, "KMS data-key request is invalid");
                }
            }
            _ => unreachable!(),
        }
        if self.pending_plugin_kms.is_some() {
            return Response::error(503, "another KMS plugin invocation is pending");
        }
        let Some(host) = self.kms_plugins.get(plugin_id).cloned() else {
            return Response::error(503, "KMS plugin is not admitted by this deployment");
        };
        let mut provider_body = object.clone();
        provider_body.insert("action".into(), Value::String(action.into()));
        provider_body.insert("namespace".into(), Value::String((*namespace).into()));
        let encoded = match serde_json::to_vec(&provider_body) {
            Ok(value) => value,
            Err(_) => return Response::error(500, "KMS plugin request encoding failed"),
        };
        let authority = PluginResponseAuthority::new(principal, state, request, "update", true);
        let request = match SecretValue::new(encoded) {
            Ok(value) => value,
            Err(_) => return Response::error(413, "KMS plugin request exceeds runtime bound"),
        };
        self.pending_plugin_kms = Some(PluginKmsPlan {
            plugin_id: plugin_id.to_owned(),
            key_binding: binding,
            host,
            request,
            action,
            authority,
        });
        Response::error(500, "KMS plugin was not dispatched")
    }

    pub(super) fn finalize_plugin_kms(
        &mut self,
        mut plan: PluginKmsPlan,
        result: Result<PluginKmsObservation, Response>,
    ) -> Response {
        let mut observation = match result {
            Ok(value) => value,
            Err(error) => return error,
        };
        if let Err(error) = self.validate_plugin_response(&mut plan.authority) {
            erase_json(&mut observation.value);
            return error;
        }
        let binding_current = self.kms_keys.get(&plan.plugin_id).is_some_and(|current| {
            current.enabled
                && current.key_id == plan.key_binding.key_id
                && current.key_version == plan.key_binding.key_version
                && current.capabilities == plan.key_binding.capabilities
        });
        let host_current = self
            .kms_plugins
            .get(&plan.plugin_id)
            .is_some_and(|host| Arc::ptr_eq(host, &plan.host));
        if !binding_current || !host_current {
            erase_json(&mut observation.value);
            return Response::error(
                503,
                "KMS result withheld because key or host binding changed",
            );
        }
        Response::ok(json!({"data": observation.value}))
    }

    fn validate_plugin_response(
        &mut self,
        authority: &mut PluginResponseAuthority,
    ) -> Result<(), Response> {
        let _deadline_scope = authority
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        if authority.deadline_expired() || self.recovery_required || self.state.is_none() {
            return Err(Response::error(
                503,
                "plugin response withheld by deadline, seal or recovery fence",
            ));
        }
        // ReadIndex alone is insufficient: install the current application state
        // so revocations committed while the Service writer was unlocked apply.
        if self.ha.is_some() && self.sync_from_ha_with_anchor(false).is_err() {
            return Err(Response::error(
                503,
                "plugin response withheld after HA synchronization failure",
            ));
        }
        let Some(state) = self.state.as_ref() else {
            return Err(Response::error(
                503,
                "plugin response withheld because server sealed",
            ));
        };
        if self.recovery_required
            || state.cluster_id != authority.cluster_id
            || !state.namespace_exists(&authority.namespace)
            || state.namespace_is_sealed(&authority.namespace)
            || state.namespaces.incarnation(&authority.namespace) != authority.namespace_incarnation
        {
            return Err(Response::error(
                503,
                "plugin response withheld because owner binding changed",
            ));
        }
        Self::bind_identity_principal(state, &mut authority.principal, &authority.namespace)?;
        let now = authority.now();
        let authorized = if authority.sudo {
            state.auth.authorize_sudo_request(
                &authority.principal,
                &authority.namespace,
                &authority.path,
                authority.capability,
                now,
            )
        } else {
            state.auth.authorize_request(
                &authority.principal,
                &authority.namespace,
                &authority.path,
                authority.capability,
                now,
            )
        };
        authorized.map_err(|error| Response::error(error.status, &error.message))?;
        if authority.deadline_expired() {
            return Err(Response::error(503, "plugin response deadline exceeded"));
        }
        Ok(())
    }

    pub(super) fn plugin_auth_login(
        &mut self,
        state: &State,
        request: &RequestView<'_>,
    ) -> Option<Response> {
        let auth = match state.auth.prepare_plugin_auth_login(
            request.namespace,
            request.method,
            request.path,
            request.body,
            request.now,
        ) {
            Ok(Some(plan)) => plan,
            Ok(None) => return None,
            Err(error) => return Some(Response::error(error.status, &error.message)),
        };
        if request.wrap_ttl_seconds.is_some() {
            return Some(Response::error(
                501,
                "response wrapping is not implemented for authentication plugins",
            ));
        }
        if self.pending_plugin_auth.is_some() {
            return Some(Response::error(
                503,
                "another authentication plugin invocation is pending",
            ));
        }
        let Some(host) = self.auth_plugins.get(auth.plugin_id()).cloned() else {
            return Some(Response::error(
                503,
                "auth mount references an unadmitted deployment plugin",
            ));
        };
        let encoded = match serde_json::to_vec(&PluginAuthRequest {
            method: request.method,
            namespace: request.namespace,
            mount: auth.mount(),
            data: request.body,
        }) {
            Ok(value) => value,
            Err(_) => {
                return Some(Response::error(
                    500,
                    "authentication plugin request encoding failed",
                ));
            }
        };
        let plugin_request = match SecretValue::new(encoded) {
            Ok(value) => value,
            Err(_) => {
                return Some(Response::error(
                    413,
                    "authentication plugin request exceeds runtime bound",
                ));
            }
        };
        self.pending_plugin_auth = Some(PluginAuthPlan {
            auth,
            host,
            request: plugin_request,
        });
        Some(Response::error(
            500,
            "authentication plugin was not dispatched",
        ))
    }

    pub(super) fn finalize_plugin_auth(
        &mut self,
        plan: PluginAuthPlan,
        result: Result<PluginAuthObservation, Response>,
    ) -> Response {
        let observation = match result {
            Ok(value) => value,
            Err(error) => return error,
        };
        let Some(mut state) = self.state.clone() else {
            return Response::error(
                503,
                "authentication plugin result withheld because server sealed",
            );
        };
        let namespace = plan.auth.namespace().to_owned();
        let now = plan.auth.now();
        let mut issued = match state
            .auth
            .finish_plugin_auth_login(plan.auth, &observation.alias)
        {
            Ok(response) => response,
            Err(error) => return Response::error(error.status, &error.message),
        };
        if let Err(error) = Self::finish_identity_response(
            &mut state.auth,
            &mut state.engines,
            &mut issued,
            &namespace,
            now,
        ) {
            erase_json(&mut issued.body);
            return error;
        }
        state.schema = CURRENT_STATE_SCHEMA;
        if let Err(error) = self.commit_state(&state) {
            erase_json(&mut issued.body);
            return error;
        }
        self.state = Some(state);
        Response {
            status: issued.status,
            body: issued.body,
        }
    }

    pub(super) fn plugin_secret_handles(&self, state: &State, namespace: &str, path: &str) -> bool {
        state.engines.plugin_secret_mount(namespace, path).is_some()
    }

    pub(super) fn plugin_secret_route(
        &mut self,
        state: State,
        principal: Option<Principal>,
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
        let Some((mount, plugin_id, mount_incarnation)) =
            state.engines.plugin_secret_mount_binding(namespace, path)
        else {
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
            .authorize_request(&principal, namespace, path, capability, *now)
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
        let authority = PluginResponseAuthority::new(principal, &state, request, capability, false);
        let request = match SecretValue::new(encoded) {
            Ok(v) => v,
            Err(_) => return Response::error(413, "plugin request exceeds runtime bound"),
        };
        self.pending_plugin_read = Some(PluginReadPlan {
            namespace: (*namespace).to_owned(),
            mount,
            plugin_id,
            mount_incarnation,
            host,
            request,
            authority,
        });
        Response::error(500, "plugin read was not dispatched")
    }

    pub(super) fn finalize_plugin_read(
        &mut self,
        mut plan: PluginReadPlan,
        result: Result<Value, Response>,
    ) -> Response {
        let mut value = match result {
            Ok(v) => v,
            Err(e) => return e,
        };
        if let Err(error) = self.validate_plugin_response(&mut plan.authority) {
            erase_json(&mut value);
            return error;
        }
        let binding_current = self
            .state
            .as_ref()
            .and_then(|state| {
                state
                    .engines
                    .plugin_secret_mount_binding(&plan.namespace, &plan.mount)
            })
            .is_some_and(|(mount, plugin, incarnation)| {
                mount == plan.mount
                    && plugin == plan.plugin_id
                    && incarnation == plan.mount_incarnation
            });
        let host_current = self
            .plugins
            .get(&plan.plugin_id)
            .is_some_and(|host| Arc::ptr_eq(host, &plan.host));
        if !binding_current || !host_current {
            erase_json(&mut value);
            return Response::error(
                503,
                "plugin response withheld because mount or host binding changed",
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

#[cfg(test)]
#[path = "service_plugin_completion_tests.rs"]
mod completion_tests;
