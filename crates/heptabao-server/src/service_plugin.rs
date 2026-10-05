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
pub(super) struct PluginResponseAuthority {
    principal: Principal,
    namespace: String,
    namespace_incarnation: Option<u64>,
    namespace_catalog_required: bool,
    namespace_delivery_binding: namespace_runtime::DeliveryBinding,
    activation_nonce: String,
    cluster_id: String,
    method: String,
    path: String,
    body: Value,
    capability: &'static str,
    sudo: bool,
    admitted_at: u64,
    token_clock: Option<RequestClock>,
    started: std::time::Instant,
    deadline: Option<std::time::Instant>,
}

impl PluginResponseAuthority {
    pub(super) fn principal(&self) -> &Principal {
        &self.principal
    }
    pub(super) fn check_token_api_candidate(
        &self,
        state: &State,
        auth: &AuthState,
        activation: &str,
    ) -> Result<(), Response> {
        state.namespace_leases.validate()?;
        if self.deadline_expired()
            || activation != self.activation_nonce
            || state.cluster_id != self.cluster_id
            || self.namespace_catalog_required && !state.namespace_exists(&self.namespace)
            || state.namespace_is_sealed(&self.namespace)
            || state.namespaces.incarnation(&self.namespace) != self.namespace_incarnation
            || namespace_runtime::DeliveryBinding::capture(state, &self.namespace)
                != self.namespace_delivery_binding
        {
            return Err(Response::error(
                503,
                "token response owner or deadline changed",
            ));
        }
        let time = auth.token_api_observed_time(self.token_time()?);
        auth.authorize_request_parameters_observed(
            &self.principal,
            &self.namespace,
            &self.method,
            &self.path,
            &self.body,
            time,
        )
        .map_err(|error| Response::error(error.status, &error.message))?;
        auth.authorize_request_observed(
            &self.principal,
            &self.namespace,
            &self.path,
            self.capability,
            time,
        )
        .map_err(|error| Response::error(error.status, &error.message))?;
        auth.validate_token_api_delivery_target(
            &self.principal,
            &self.namespace,
            &self.path,
            &self.body,
            time,
        )
        .map_err(|error| Response::error(error.status, &error.message))
    }
    pub(super) fn new(
        principal: Principal,
        state: &State,
        request: &RequestView<'_>,
        capability: &'static str,
        sudo: bool,
        activation_nonce: &str,
    ) -> Self {
        Self {
            principal,
            namespace: request.namespace.to_owned(),
            namespace_incarnation: state.namespaces.incarnation(request.namespace),
            namespace_catalog_required: request.enforce_namespace,
            namespace_delivery_binding: namespace_runtime::DeliveryBinding::capture(
                state,
                request.namespace,
            ),
            activation_nonce: activation_nonce.to_owned(),
            cluster_id: state.cluster_id.clone(),
            method: kv_authorization_method(request.method, request.body).to_owned(),
            path: request.path.to_owned(),
            body: request.body.clone(),
            capability,
            sudo,
            admitted_at: request.now,
            token_clock: request.token_clock,
            started: request.admission_started,
            deadline: crate::request_deadline::current(),
        }
    }

    /// Domain clocks may already be ahead of the request's wall-clock sample.
    pub(super) fn with_time_floor(mut self, floor: u64) -> Self {
        self.admitted_at = self.admitted_at.max(floor);
        self
    }

    pub(super) fn now(&self) -> u64 {
        std::time::Duration::from_secs(self.admitted_at)
            .saturating_add(self.started.elapsed())
            .as_secs()
    }

    pub(super) fn token_time(&self) -> Result<AuthorityTime, Response> {
        match self.token_clock {
            Some(clock) => clock
                .with_seconds_floor(self.admitted_at)
                .and_then(RequestClock::observed_at)
                .map(AuthorityTime::Precise)
                .map_err(|_| Response::error(503, "trusted token clock is unavailable")),
            None => Ok(AuthorityTime::Coarse(self.now())),
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn observe_candidate_time_changed(
        &self,
        state: &mut State,
    ) -> Result<bool, Response> {
        let time = state.auth.token_api_observed_time(self.token_time()?);
        state
            .auth
            .observe_token_api_time(time)
            .map_err(|error| Response::error(error.status, &error.message))
    }

    pub(super) fn observe_candidate_time(
        &self,
        state: &mut State,
    ) -> Result<AuthorityTime, Response> {
        let time = state.auth.token_api_observed_time(self.token_time()?);
        state
            .auth
            .observe_token_api_time(time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        Ok(time)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn validate_live_auth(&self, auth: &AuthState) -> Result<(), Response> {
        if self.deadline_expired() {
            return Err(Response::error(
                503,
                "SDK original deadline expired before publication",
            ));
        }
        let time = self.token_time()?;
        auth.authorize_request_parameters_observed(
            &self.principal,
            &self.namespace,
            &self.method,
            &self.path,
            &self.body,
            time,
        )
        .map_err(|e| Response::error(e.status, &e.message))?;
        let result = if self.sudo {
            auth.authorize_sudo_request_observed(
                &self.principal,
                &self.namespace,
                &self.path,
                self.capability,
                time,
            )
        } else {
            auth.authorize_request_observed(
                &self.principal,
                &self.namespace,
                &self.path,
                self.capability,
                time,
            )
        };
        result.map_err(|e| Response::error(e.status, &e.message))?;
        if self.deadline_expired() {
            return Err(Response::error(503, "SDK publication deadline expired"));
        }
        Ok(())
    }

    pub(super) fn deadline_expired(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    }
}

impl Drop for PluginResponseAuthority {
    fn drop(&mut self) {
        erase_json(&mut self.body);
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

// Content identity alone cannot distinguish deletion followed by restoration.
// Retain the existing durable generation and replica-local frontier as a second,
// monotonic publication fence; this is metadata, not another state owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PublicationGeneration {
    local: u64,
    raft: Option<(u64, u64)>,
}

#[path = "service_external_key_native.rs"]
mod external_key_native;

enum ExternalKeyProvider {
    Kms {
        host: SharedKmsPlugin,
        expected_host_generation: u64,
    },
    NativeTransit(external_key_native::NativeTransitVerification),
}

pub(super) struct ExternalKeyPlan {
    pub(super) plugin_id: String,
    provider: ExternalKeyProvider,
    request: SecretValue,
    action: &'static str,
    config_name: String,
    key_name: Option<String>,
    authority: PluginResponseAuthority,
    expected_identity: crate::state_record_root::StateIdentity,
    expected_generation: PublicationGeneration,
    candidate: State,
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
    response_context: PluginAuthResponseContext,
}

// Binding metadata for an unauthenticated login, not a Principal or a grant.
struct PluginAuthResponseContext {
    namespace: String,
    namespace_incarnation: Option<u64>,
    namespace_delivery_binding: namespace_runtime::DeliveryBinding,
    cluster_id: String,
    activation_nonce: String,
    deadline: Option<std::time::Instant>,
}

impl PluginAuthResponseContext {
    fn new(state: &State, request: &RequestView<'_>, activation_nonce: &str) -> Self {
        Self {
            namespace: request.namespace.to_owned(),
            namespace_incarnation: state.namespaces.incarnation(request.namespace),
            namespace_delivery_binding: namespace_runtime::DeliveryBinding::capture(
                state,
                request.namespace,
            ),
            cluster_id: state.cluster_id.clone(),
            activation_nonce: activation_nonce.to_owned(),
            deadline: crate::request_deadline::current(),
        }
    }

    fn deadline_expired(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    }
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
                "sign" => KmsCapability::Sign,
                "verify" => KmsCapability::Verify,
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

// Even a rejected provider response may contain echoed credential fields.
struct VerificationResponse(Value);
impl Drop for VerificationResponse {
    fn drop(&mut self) {
        erase_json(&mut self.0);
    }
}

impl ExternalKeyPlan {
    pub(super) fn execute(&self) -> Result<(), Response> {
        if self.authority.deadline_expired() {
            return Err(Response::error(
                503,
                "external key request deadline expired before entry",
            ));
        }
        let (host, expected_host_generation) = match &self.provider {
            ExternalKeyProvider::NativeTransit(native) => {
                let _deadline_scope = self
                    .authority
                    .deadline
                    .map(crate::request_deadline::RequestDeadlineScope::enter);
                return native.execute();
            }
            ExternalKeyProvider::Kms {
                host,
                expected_host_generation,
            } => (host, expected_host_generation),
        };
        let mut host = host.try_lock().map_err(|_| {
            Response::error(503, "external key KMS plugin host busy or unavailable")
        })?;
        if host.state() != PluginHostState::Active
            || host.manifest().descriptor().generation() != *expected_host_generation
        {
            return Err(Response::error(
                503,
                "external key KMS host authority changed before entry",
            ));
        }
        let response = host
            .invoke(
                PluginOperation::Read,
                &self.request,
                &SecretEnvironment::new(),
            )
            .map_err(kms_failure)?;
        let value =
            VerificationResponse(crate::auth::parse_strict_json(response.expose()).map_err(
                |_| Response::error(503, "external key KMS plugin returned invalid JSON"),
            )?);
        let object = value.0.as_object().ok_or_else(|| {
            Response::error(503, "external key KMS plugin response must be an object")
        })?;
        let expected_fields = if self.key_name.is_some() { 6 } else { 5 };
        if object.len() != expected_fields
            || object.get("verified").and_then(Value::as_bool) != Some(true)
            || object.get("namespace").and_then(Value::as_str)
                != Some(self.authority.namespace.as_str())
            || object.get("action").and_then(Value::as_str) != Some(self.action)
            || object.get("plugin").and_then(Value::as_str) != Some(self.plugin_id.as_str())
            || object.get("config").and_then(Value::as_str) != Some(self.config_name.as_str())
            || self.key_name.as_deref() != object.get("key").and_then(Value::as_str)
        {
            return Err(Response::error(
                503,
                "external key KMS plugin verification response mismatch",
            ));
        }
        Ok(())
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
        if wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
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
        if wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
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
        let authority = PluginResponseAuthority::new(
            principal,
            state,
            request,
            "update",
            true,
            &self.unseal_nonce,
        );
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

    pub(super) fn external_effect_generation(&self) -> Result<PublicationGeneration, Response> {
        let local = self
            .durable
            .as_ref()
            .ok_or_else(|| Response::error(503, "external effect durable owner is unavailable"))?
            .generation();
        let raft = match self.consistency_observation()? {
            Some(observed) => Some(observed.committed.zip(observed.applied).ok_or_else(|| {
                Response::error(503, "external effect HA frontier is unavailable")
            })?),
            None if self.ha.is_some() => {
                return Err(Response::error(
                    503,
                    "external effect HA observation is unavailable",
                ));
            }
            None => None,
        };
        Ok(PublicationGeneration { local, raft })
    }

    pub(super) fn stage_external_key_verification(
        &mut self,
        state: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
        verification: crate::engines::ExternalKeyVerification,
    ) -> Response {
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        let Some(capability) =
            state
                .engines
                .required_capability(request.namespace, request.method, request.path)
        else {
            return Response::error(404, "external key route not found");
        };
        if let Err(error) = state.auth.authorize_request(
            &principal,
            request.namespace,
            request.path,
            capability,
            request.now,
        ) {
            return Response::error(error.status, &error.message);
        }
        if self.pending_external_key.is_some() {
            return Response::error(503, "another external key verification is pending");
        }
        // Presence of either registry entry selects the original KMS owner.
        // A disabled, revoked or incomplete binding must never fall back to HTTP.
        let provider = match (
            self.kms_plugins.get(&verification.plugin_id).cloned(),
            self.kms_keys.get(&verification.plugin_id),
        ) {
            (Some(host), Some(binding)) => {
                if !binding.enabled {
                    return Response::error(403, "external key KMS provider is disabled");
                }
                let expected_host_generation = {
                    let Ok(guard) = host.try_lock() else {
                        return Response::error(
                            503,
                            "external key KMS plugin host busy or unavailable",
                        );
                    };
                    if guard.state() != PluginHostState::Active {
                        return Response::error(503, "external key KMS plugin host is not active");
                    }
                    guard.manifest().descriptor().generation()
                };
                ExternalKeyProvider::Kms {
                    host,
                    expected_host_generation,
                }
            }
            (None, None) if verification.plugin_id == "transit" => {
                match external_key_native::NativeTransitVerification::prepare(
                    &self.outbound,
                    verification.action,
                    &verification.request,
                ) {
                    Ok(native) => ExternalKeyProvider::NativeTransit(native),
                    Err(error) => return error,
                }
            }
            (None, None) => {
                return Response::error(
                    501,
                    "external key verification requires an admitted KMS provider",
                );
            }
            _ => return Response::error(403, "external key KMS provider is unavailable"),
        };
        if request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
            return Response::error(501, "external key verification responses cannot be wrapped");
        }
        let expected_identity = match self.current_state_identity() {
            Ok(identity) => identity,
            Err(error) => return error,
        };
        let expected_generation = match self.external_effect_generation() {
            Ok(generation) => generation,
            Err(error) => return error,
        };
        let mut candidate = state;
        candidate.schema = candidate.writer_schema();
        candidate.engines = verification.candidate.into();
        if let Err(error) = candidate.validate_format() {
            return error;
        }
        let authority = PluginResponseAuthority::new(
            principal,
            &candidate,
            request,
            capability,
            false,
            &self.unseal_nonce,
        );
        self.pending_external_key = Some(ExternalKeyPlan {
            plugin_id: verification.plugin_id,
            provider,
            request: verification.request,
            action: verification.action,
            config_name: verification.config_name,
            key_name: verification.key_name,
            authority,
            expected_identity,
            expected_generation,
            candidate,
        });
        Response::error(500, "external key verification was not dispatched")
    }

    pub(super) fn finalize_external_key(
        &mut self,
        mut plan: ExternalKeyPlan,
        result: Result<(), Response>,
    ) -> Response {
        if let Err(error) = result {
            return error;
        }
        if let Err(error) = self.validate_plugin_response(&mut plan.authority) {
            return error;
        }
        // Keep the original sandbox host lock through publication. Native
        // HTTP retains the exact enrolled TLS Arc and the absence of a KMS owner.
        let _host_guard = match &plan.provider {
            ExternalKeyProvider::Kms {
                host,
                expected_host_generation,
            } => {
                let host_current = self
                    .kms_plugins
                    .get(&plan.plugin_id)
                    .is_some_and(|current| Arc::ptr_eq(current, host));
                let enabled = self
                    .kms_keys
                    .get(&plan.plugin_id)
                    .is_some_and(|key| key.enabled);
                if !host_current || !enabled {
                    return Response::error(
                        503,
                        "external key KMS host changed before publication",
                    );
                }
                let Ok(guard) = host.try_lock() else {
                    return Response::error(
                        503,
                        "external key KMS plugin host busy or unavailable",
                    );
                };
                if guard.state() != PluginHostState::Active
                    || guard.manifest().descriptor().generation() != *expected_host_generation
                {
                    return Response::error(
                        503,
                        "external key KMS host authority changed before publication",
                    );
                }
                Some(guard)
            }
            ExternalKeyProvider::NativeTransit(native) => {
                if self.kms_plugins.contains_key(&plan.plugin_id)
                    || self.kms_keys.contains_key(&plan.plugin_id)
                    || !native.enrollment_current(&self.outbound)
                {
                    return Response::error(
                        503,
                        "external key native provider changed before publication",
                    );
                }
                None
            }
        };
        let current = match self.current_state_identity() {
            Ok(identity) => identity,
            Err(error) => return error,
        };
        let generation = match self.external_effect_generation() {
            Ok(generation) => generation,
            Err(error) => return error,
        };
        if current != plan.expected_identity || generation != plan.expected_generation {
            return Response::error(
                503,
                "external key verification result withheld after state changed",
            );
        }
        let _deadline_scope = plan
            .authority
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        let mut candidate = plan.candidate;
        if candidate.engines.record_root().is_none() {
            let key = match crypto::random::<32>() {
                Ok(key) => key,
                Err(error) => return Response::error(503, error),
            };
            candidate.engines = match candidate
                .engines
                .migrate_kv1_records(crate::state_records::AddressKey::from_bytes(key))
            {
                Ok(engines) => engines.into(),
                Err(error) => return Response::error(error.status, &error.message),
            };
        }
        let record_plan = match self.prepare_record_plan(&mut candidate) {
            Ok(record_plan) => record_plan,
            Err(error) => return error,
        };
        if let Err(error) = self.commit_record_plan(&candidate, record_plan) {
            return error;
        }
        self.state = Some(candidate);
        Response {
            consistency_index: None,
            status: 204,
            body: Value::Null,
        }
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

    pub(super) fn validate_plugin_response(
        &mut self,
        authority: &mut PluginResponseAuthority,
    ) -> Result<(), Response> {
        let _deadline_scope = authority
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        if authority.deadline_expired()
            || self.recovery_required
            || self.state.is_none()
            || self.unseal_nonce != authority.activation_nonce
        {
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
            || self.unseal_nonce != authority.activation_nonce
            || state.cluster_id != authority.cluster_id
            || authority.namespace_catalog_required && !state.namespace_exists(&authority.namespace)
            || state.namespace_is_sealed(&authority.namespace)
            || (state
                .namespaces
                .inherited_owner(&authority.namespace)
                .is_some()
                && !self.namespace_runtime.is_loaded(&authority.namespace))
            || state.namespaces.incarnation(&authority.namespace) != authority.namespace_incarnation
            || namespace_runtime::DeliveryBinding::capture(state, &authority.namespace)
                != authority.namespace_delivery_binding
        {
            return Err(Response::error(
                503,
                "plugin response withheld because owner binding changed",
            ));
        }
        Self::bind_identity_principal(state, &mut authority.principal, &authority.namespace)?;
        let time = authority.token_time()?;
        state
            .auth
            .authorize_request_parameters_observed(
                &authority.principal,
                &authority.namespace,
                &authority.method,
                &authority.path,
                &authority.body,
                time,
            )
            .map_err(|error| Response::error(error.status, &error.message))?;
        let authorized = if authority.sudo {
            state.auth.authorize_sudo_request_observed(
                &authority.principal,
                &authority.namespace,
                &authority.path,
                authority.capability,
                time,
            )
        } else {
            state.auth.authorize_request_observed(
                &authority.principal,
                &authority.namespace,
                &authority.path,
                authority.capability,
                time,
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
        if request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
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
            auth: auth.with_admission_started(request.admission_started),
            host,
            request: plugin_request,
            response_context: PluginAuthResponseContext::new(state, request, &self.unseal_nonce),
        });
        Some(Response::error(
            500,
            "authentication plugin was not dispatched",
        ))
    }

    fn validate_plugin_auth_response(
        &mut self,
        context: &PluginAuthResponseContext,
        binding: &crate::auth::PluginAuthLoginPlan,
    ) -> Result<(), Response> {
        let _deadline_scope = context
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        if context.deadline_expired() {
            return Err(Response::error(
                503,
                "authentication plugin request deadline expired",
            ));
        }
        // Reuse native online-auth leadership, activation and post-sync checks.
        self.revalidate_online_authority_with_sync(
            &context.namespace,
            &context.activation_nonce,
            Self::sync_from_ha,
        )?;
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "authentication plugin authority unavailable"))?;
        if state.cluster_id != context.cluster_id
            || state.namespaces.incarnation(&context.namespace) != context.namespace_incarnation
            || binding.namespace() != context.namespace
            || (state
                .namespaces
                .inherited_owner(&context.namespace)
                .is_some()
                && !self.namespace_runtime.is_loaded(&context.namespace))
            || namespace_runtime::DeliveryBinding::capture(state, &context.namespace)
                != context.namespace_delivery_binding
        {
            return Err(Response::error(
                503,
                "authentication plugin namespace identity changed",
            ));
        }
        state
            .auth
            .validate_plugin_auth_login_binding(binding)
            .map_err(|error| Response::error(error.status, &error.message))?;
        if context.deadline_expired() {
            return Err(Response::error(
                503,
                "authentication plugin request deadline expired",
            ));
        }
        Ok(())
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
        let PluginAuthPlan {
            auth,
            response_context,
            ..
        } = plan;
        let _deadline_scope = response_context
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        if let Err(error) = self.validate_plugin_auth_response(&response_context, &auth) {
            return error;
        }
        let Some(mut state) = self.state.clone() else {
            return Response::error(503, "authentication plugin authority unavailable");
        };
        // Retain only the immutable validation snapshot for the post-commit
        // check. The external observation is consumed by exactly one finalizer.
        let binding = auth.clone();
        let namespace = auth.namespace().to_owned();
        let now = auth.now();
        let mut issued = match state
            .auth
            .finish_plugin_auth_login(auth, &observation.alias)
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
        state.schema = state.writer_schema();
        if let Err(error) = self.commit_state(&mut state) {
            erase_json(&mut issued.body);
            return error;
        }
        self.state = Some(state);
        if let Err(error) = self.validate_plugin_auth_response(&response_context, &binding) {
            erase_json(&mut issued.body);
            return error;
        }
        Response {
            consistency_index: None,
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
            "LIST" => "list",
            "SCAN" => "scan",
            _ => "update",
        };
        if let Err(e) = state
            .auth
            .authorize_request(&principal, namespace, path, capability, *now)
        {
            return Response::error(e.status, &e.message);
        }
        if wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
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
        let authority = PluginResponseAuthority::new(
            principal,
            &state,
            request,
            capability,
            false,
            &self.unseal_nonce,
        );
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
