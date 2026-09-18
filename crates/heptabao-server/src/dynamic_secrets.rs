//! Runtime composition for durable provider-backed dynamic secret leases.
//!
//! The provider process boundary and durable lease journal live in
//! `heptabao-plugin-host`. This module only wires that already-qualified
//! state machine into the runnable server. It deliberately exposes no ambient
//! plugin fallback and never retries a provider mutation after entry.

use crate::{Response, crypto::AeadBarrier};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use heptabao_domain::{CanonicalPath, Id, SecretValue, Tick};
use heptabao_plugin_contracts::{PluginDescriptor, PluginKind, PluginRegistry};
use heptabao_plugin_host::{
    CommandSandboxRunner, DurableDynamicSecretBroker, DurableReconciliationDecision,
    DynamicLeaseSpec, DynamicLeaseState, DynamicLeaseView, DynamicSecretBroker, PluginHost,
    PluginHostError, PluginLimits, PluginManifest, PluginMutationContext, PluginOperation,
    SecretEnvironment, SandboxBinding,
};
use ring::digest::{SHA256, digest};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const ISSUE_PATH: &str = "sys/dynamic-secrets/issue";
const PENDING_PATH: &str = "sys/dynamic-secrets/pending";
const RECONCILE_PATH: &str = "sys/dynamic-secrets/reconcile";
const LOOKUP_PREFIX: &str = "sys/dynamic-secrets/leases/";
const RENEW_PATH: &str = "sys/leases/renew";
const REVOKE_PATH: &str = "sys/leases/revoke";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicSecretConfig {
    pub state_dir: PathBuf,
    pub plugin_id: String,
    pub plugin_kind: String,
    pub plugin_command: PathBuf,
    pub plugin_sha256: String,
    pub protocol_version: u16,
    pub sandbox_provider_id: String,
    pub sandbox_command: PathBuf,
    pub sandbox_sha256: String,
    pub sandbox_profile_id: String,
    #[serde(default = "default_request_bytes")]
    pub maximum_request_bytes: usize,
    #[serde(default = "default_response_bytes")]
    pub maximum_response_bytes: usize,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_retained_requests")]
    pub max_retained_requests: usize,
}

const fn default_request_bytes() -> usize { 64 * 1024 }
const fn default_response_bytes() -> usize { 64 * 1024 }
const fn default_timeout_ms() -> u64 { 5_000 }
const fn default_retained_requests() -> usize { 100_000 }

impl DynamicSecretConfig {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if !self.state_dir.is_absolute()
            || !self.plugin_command.is_absolute()
            || !self.sandbox_command.is_absolute()
            || self.protocol_version == 0
            || !(1..=1_000_000).contains(&self.max_retained_requests)
        {
            return Err("invalid dynamic-secret runtime configuration");
        }
        if !matches!(self.plugin_kind.as_str(), "database" | "secrets")
            || parse_digest(&self.plugin_sha256).is_err()
            || parse_digest(&self.sandbox_sha256).is_err()
        {
            return Err("invalid dynamic-secret plugin identity");
        }
        Id::parse(self.plugin_id.clone()).map_err(|_| "invalid dynamic-secret plugin id")?;
        Id::parse(self.sandbox_provider_id.clone())
            .map_err(|_| "invalid dynamic-secret sandbox provider id")?;
        Id::parse(self.sandbox_profile_id.clone())
            .map_err(|_| "invalid dynamic-secret sandbox profile id")?;
        canonical_command(&self.plugin_command)?;
        canonical_command(&self.sandbox_command)?;
        PluginLimits {
            maximum_request_bytes: self.maximum_request_bytes,
            maximum_response_bytes: self.maximum_response_bytes,
            timeout_ms: self.timeout_ms,
        }
        .validate()
        .map_err(|_| "invalid dynamic-secret plugin limits")?;
        Ok(())
    }
}

type Broker = DurableDynamicSecretBroker<AeadBarrier, CommandSandboxRunner>;

#[derive(Debug)]
pub(crate) struct DynamicSecretRuntime {
    broker: Broker,
}

impl DynamicSecretRuntime {
    pub(crate) fn open(config: &DynamicSecretConfig, barrier_key: &[u8; 32]) -> Result<Self, String> {
        config.validate().map_err(str::to_owned)?;
        let plugin_id = Id::parse(config.plugin_id.clone()).map_err(|e| e.to_string())?;
        let kind = match config.plugin_kind.as_str() {
            "database" => PluginKind::Database,
            "secrets" => PluginKind::Secrets,
            _ => return Err("unsupported dynamic-secret plugin kind".into()),
        };
        let descriptor = PluginDescriptor::new(
            plugin_id.clone(),
            kind,
            canonical_command(&config.plugin_command).map_err(str::to_owned)?,
            parse_digest(&config.plugin_sha256).map_err(str::to_owned)?,
            config.protocol_version,
        )
        .map_err(|e| e.to_string())?;
        let mut registry = PluginRegistry::default();
        registry.register(descriptor).map_err(|e| e.to_string())?;
        registry.enable(&plugin_id).map_err(|e| e.to_string())?;
        let descriptor = registry.get(&plugin_id).map_err(|e| e.to_string())?.clone();
        let sandbox = SandboxBinding::new(
            Id::parse(config.sandbox_provider_id.clone()).map_err(|e| e.to_string())?,
            canonical_command(&config.sandbox_command).map_err(str::to_owned)?,
            parse_digest(&config.sandbox_sha256).map_err(str::to_owned)?,
            Id::parse(config.sandbox_profile_id.clone()).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let manifest = PluginManifest::new(
            descriptor,
            sandbox,
            PluginLimits {
                maximum_request_bytes: config.maximum_request_bytes,
                maximum_response_bytes: config.maximum_response_bytes,
                timeout_ms: config.timeout_ms,
            },
            BTreeSet::from([
                PluginOperation::Issue,
                PluginOperation::Renew,
                PluginOperation::Revoke,
            ]),
            BTreeSet::new(),
        )
        .map_err(|e| e.to_string())?;
        let host = PluginHost::admit(manifest, CommandSandboxRunner).map_err(|e| e.to_string())?;
        let broker = DynamicSecretBroker::new(host).map_err(|e| e.to_string())?;
        let barrier = AeadBarrier::new(*barrier_key).map_err(|_| "invalid dynamic-secret barrier key")?;

        let create = match fs::read_dir(&config.state_dir) {
            Ok(mut entries) => entries.next().is_none(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => return Err("cannot inspect dynamic-secret state directory".into()),
        };
        let broker = if create {
            DurableDynamicSecretBroker::create_new(
                &config.state_dir,
                barrier,
                broker,
                config.max_retained_requests,
            )
        } else {
            DurableDynamicSecretBroker::reopen(
                &config.state_dir,
                barrier,
                broker,
                config.max_retained_requests,
            )
        }
        .map_err(|e| e.to_string())?;
        Ok(Self { broker })
    }

    pub(crate) fn owns_path(path: &str) -> bool {
        matches!(path, ISSUE_PATH | PENDING_PATH | RECONCILE_PATH | RENEW_PATH | REVOKE_PATH)
            || path.starts_with(LOOKUP_PREFIX)
    }

    pub(crate) fn root_only(path: &str) -> bool {
        path == RECONCILE_PATH
    }

    pub(crate) fn required_capability(method: &str, path: &str) -> &'static str {
        if method == "GET" && (path == PENDING_PATH || path.starts_with(LOOKUP_PREFIX)) {
            "read"
        } else {
            "update"
        }
    }

    pub(crate) fn handle(
        &mut self,
        subject: &str,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Response {
        if path == ISSUE_PATH {
            if !matches!(method, "POST" | "PUT") {
                return Response::error(405, "dynamic secret issuance requires POST or PUT");
            }
            return self.issue(subject, namespace, method, path, body, now);
        }
        if path == RENEW_PATH {
            if !matches!(method, "POST" | "PUT") {
                return Response::error(405, "lease renewal requires POST or PUT");
            }
            return self.renew(subject, namespace, method, path, body, now);
        }
        if path == REVOKE_PATH {
            if !matches!(method, "POST" | "PUT") {
                return Response::error(405, "lease revocation requires POST or PUT");
            }
            return self.revoke(subject, namespace, method, path, body);
        }
        if path == PENDING_PATH {
            if method != "GET" {
                return Response::error(405, "pending lease lookup requires GET");
            }
            return Response::ok(json!({"data":{"pending":self.pending_json()}}));
        }
        if path == RECONCILE_PATH {
            if !matches!(method, "POST" | "PUT") {
                return Response::error(405, "lease reconciliation requires POST or PUT");
            }
            return self.reconcile(subject, namespace, method, path, body);
        }
        if let Some(raw_id) = path.strip_prefix(LOOKUP_PREFIX) {
            if method != "GET" {
                return Response::error(405, "lease lookup requires GET");
            }
            let lease_id = match Id::parse(raw_id.to_owned()) {
                Ok(value) => value,
                Err(_) => return Response::error(400, "invalid lease id"),
            };
            return match self.broker.view(&lease_id, Tick::new(now)) {
                Ok(view) => Response::ok(json!({"data":lease_json(&view)})),
                Err(error) => self.error(error, Some(&lease_id)),
            };
        }
        Response::error(404, "unsupported dynamic-secret path")
    }

    fn issue(
        &mut self,
        subject: &str,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Response {
        if !only_fields(body, &["operation_id", "scope", "ttl", "renewable", "provider_request_base64"]) {
            return Response::error(400, "invalid dynamic secret issuance fields");
        }
        let operation_id = match id_field(body, "operation_id") {
            Ok(value) => value,
            Err(error) => return Response::error(400, error),
        };
        let scope = match body.get("scope").and_then(Value::as_str) {
            Some(value) => match CanonicalPath::parse(value.to_owned()) {
                Ok(value) => value,
                Err(_) => return Response::error(400, "invalid dynamic secret scope"),
            },
            None => return Response::error(400, "scope is required"),
        };
        let ttl = match u64_field(body, "ttl") {
            Ok(value) => value,
            Err(error) => return Response::error(400, error),
        };
        let renewable = match body.get("renewable") {
            Some(Value::Bool(value)) => *value,
            None => true,
            _ => return Response::error(400, "renewable must be a boolean"),
        };
        let request = match provider_request(body) {
            Ok(value) => value,
            Err(error) => return Response::error(400, error),
        };
        let lease_id = derived_lease_id(subject, namespace, &operation_id, &scope);
        if let Ok(view) = self.broker.view(&lease_id, Tick::new(now)) {
            return Response {
                status: 409,
                body: json!({
                    "errors":["lease operation already has a durable projection; do not reissue"],
                    "lease":lease_json(&view),
                }),
            };
        }
        let owner = derived_actor_id(subject);
        let context = match mutation_context(subject, namespace, method, path, &operation_id, body) {
            Ok(value) => value,
            Err(error) => return Response::error(400, error),
        };
        let spec = DynamicLeaseSpec {
            lease_id: lease_id.clone(),
            owner_entity: owner,
            scope,
            issued_at: Tick::new(now),
            ttl,
            renewable,
        };
        match self.broker.issue(&context, spec, &request, &SecretEnvironment::new()) {
            Ok(issue) => {
                let encoded = Zeroizing::new(STANDARD.encode(issue.secret.expose()));
                Response::ok(json!({
                    "data": {
                        "lease": lease_json(&issue.lease),
                        "value_base64": encoded.as_str(),
                    }
                }))
            }
            Err(error) => self.error(error, Some(&lease_id)),
        }
    }

    fn renew(
        &mut self,
        subject: &str,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Response {
        if !only_fields(body, &["operation_id", "lease_id", "ttl", "provider_request_base64"]) {
            return Response::error(400, "invalid lease renewal fields");
        }
        let operation_id = match id_field(body, "operation_id") {
            Ok(value) => value,
            Err(error) => return Response::error(400, error),
        };
        let lease_id = match id_field(body, "lease_id") {
            Ok(value) => value,
            Err(error) => return Response::error(400, error),
        };
        let ttl = match u64_field(body, "ttl") {
            Ok(value) => value,
            Err(error) => return Response::error(400, error),
        };
        let request = match provider_request(body) {
            Ok(value) => value,
            Err(error) => return Response::error(400, error),
        };
        let context = match mutation_context(subject, namespace, method, path, &operation_id, body) {
            Ok(value) => value,
            Err(error) => return Response::error(400, error),
        };
        match self.broker.renew(
            &context,
            &lease_id,
            Tick::new(now),
            ttl,
            &request,
            &SecretEnvironment::new(),
        ) {
            Ok(view) => Response::ok(json!({"data":lease_json(&view)})),
            Err(error) => self.error(error, Some(&lease_id)),
        }
    }

    fn revoke(
        &mut self,
        subject: &str,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Response {
        if !only_fields(body, &["operation_id", "lease_id", "provider_request_base64"]) {
            return Response::error(400, "invalid lease revocation fields");
        }
        let operation_id = match id_field(body, "operation_id") {
            Ok(value) => value,
            Err(error) => return Response::error(400, error),
        };
        let lease_id = match id_field(body, "lease_id") {
            Ok(value) => value,
            Err(error) => return Response::error(400, error),
        };
        let request = match provider_request(body) {
            Ok(value) => value,
            Err(error) => return Response::error(400, error),
        };
        let context = match mutation_context(subject, namespace, method, path, &operation_id, body) {
            Ok(value) => value,
            Err(error) => return Response::error(400, error),
        };
        match self
            .broker
            .revoke(&context, &lease_id, &request, &SecretEnvironment::new())
        {
            Ok(view) => Response::ok(json!({"data":lease_json(&view)})),
            Err(error) => self.error(error, Some(&lease_id)),
        }
    }

    fn reconcile(
        &mut self,
        subject: &str,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Response {
        let Some(object) = body.as_object() else {
            return Response::error(400, "reconciliation request must be an object");
        };
        if object.keys().any(|key| !matches!(key.as_str(), "operation_id" | "decision" | "lease" | "response_sha256")) {
            return Response::error(400, "unsupported reconciliation fields");
        }
        let operation_id = match id_field(body, "operation_id") {
            Ok(value) => value,
            Err(error) => return Response::error(400, error),
        };
        let decision = match body.get("decision").and_then(Value::as_str) {
            Some("no_effect") => DurableReconciliationDecision::ProvenNoEffect,
            Some("completed") => {
                let lease = match body.get("lease").and_then(Value::as_object).and_then(parse_lease) {
                    Some(value) => value,
                    None => return Response::error(400, "completed reconciliation requires a valid lease"),
                };
                let response_digest = match body.get("response_sha256").and_then(Value::as_str) {
                    Some(value) => match parse_digest(value) {
                        Ok(value) => value,
                        Err(_) => return Response::error(400, "invalid response digest"),
                    },
                    None => return Response::error(400, "response_sha256 is required"),
                };
                DurableReconciliationDecision::Completed { lease, response_digest }
            }
            _ => return Response::error(400, "decision must be no_effect or completed"),
        };
        let context = match mutation_context(subject, namespace, method, path, &operation_id, body) {
            Ok(value) => value,
            Err(error) => return Response::error(400, error),
        };
        match self.broker.reconcile(&context, decision) {
            Ok(Some(view)) => Response::ok(json!({"data":{"resolved":true,"lease":lease_json(&view)}})),
            Ok(None) => Response::ok(json!({"data":{"resolved":true,"lease":Value::Null}})),
            Err(error) => self.error(error, None),
        }
    }

    fn pending_json(&self) -> Value {
        self.broker.pending_invocation().map_or(Value::Null, |pending| {
            json!({
                "lease_id": pending.lease_id.as_str(),
                "operation": operation_name(pending.operation),
                "generation": pending.generation,
            })
        })
    }

    fn error(&self, error: PluginHostError, lease_id: Option<&Id>) -> Response {
        let pending = self.pending_json();
        match error {
            PluginHostError::MissingLease => Response::error(404, "dynamic lease does not exist"),
            PluginHostError::DuplicateLease => Response {
                status: 409,
                body: json!({
                    "errors":["dynamic lease already exists; lookup before any retry"],
                    "lease_id":lease_id.map(Id::as_str),
                }),
            },
            PluginHostError::LeaseNotRenewable | PluginHostError::LeaseNotActive => {
                Response::error(409, "dynamic lease state rejects this transition")
            }
            PluginHostError::ProcessOutcomeUnknown
            | PluginHostError::ReconciliationRequired
            | PluginHostError::PendingPluginInvocation
            | PluginHostError::ResponseTooLarge
            | PluginHostError::MalformedResponse => Response {
                status: 503,
                body: json!({
                    "errors":["provider outcome is not safe to retry; authoritative reconciliation required"],
                    "reconciliation_required":true,
                    "pending":pending,
                }),
            },
            PluginHostError::ProcessBeforeEntry => Response {
                status: 503,
                body: json!({
                    "errors":["provider failed before effect entry"],
                    "retryable_before_entry": self.broker.pending_invocation().is_none(),
                    "pending":pending,
                }),
            },
            PluginHostError::Durable(_) | PluginHostError::CorruptDurablePluginState => Response {
                status: 503,
                body: json!({
                    "errors":["dynamic lease durable state unavailable; do not blindly retry"],
                    "reconciliation_required": self.broker.pending_invocation().is_some(),
                    "pending":pending,
                }),
            },
            PluginHostError::SandboxUnavailable | PluginHostError::PluginRevoked => {
                Response::error(503, "dynamic secret provider is unavailable")
            }
            _ => Response::error(400, "dynamic secret request rejected"),
        }
    }
}

fn canonical_command(path: &Path) -> Result<CanonicalPath, &'static str> {
    let value = path.to_str().ok_or("plugin command path must be UTF-8")?;
    CanonicalPath::parse(value.to_owned()).map_err(|_| "invalid canonical plugin command path")
}

fn parse_digest(value: &str) -> Result<[u8; 32], &'static str> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("digest must be 64 hexadecimal characters");
    }
    let mut result = [0_u8; 32];
    for (index, slot) in result.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid hexadecimal digest")?;
    }
    if result == [0; 32] {
        return Err("zero digest is forbidden");
    }
    Ok(result)
}

fn derived_actor_id(subject: &str) -> Id {
    let mut bytes = Vec::with_capacity(32 + subject.len());
    bytes.extend_from_slice(b"heptabao.dynamic-actor.v1\0");
    bytes.extend_from_slice(subject.as_bytes());
    let value = digest(&SHA256, &bytes);
    let suffix = value
        .as_ref()
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Id::parse(format!("actor_{suffix}")).expect("derived actor id is bounded ASCII")
}

fn derived_lease_id(subject: &str, namespace: &str, operation_id: &Id, scope: &CanonicalPath) -> Id {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.extend_from_slice(b"heptabao.dynamic-lease-id.v1\0");
    bytes.extend_from_slice(subject.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(operation_id.as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(scope.as_str().as_bytes());
    let digest = digest(&SHA256, &bytes);
    let suffix = digest
        .as_ref()
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Id::parse(format!("lease_{suffix}")).expect("derived lease id is bounded ASCII")
}

fn mutation_context(
    subject: &str,
    namespace: &str,
    method: &str,
    path: &str,
    operation_id: &Id,
    body: &Value,
) -> Result<PluginMutationContext, &'static str> {
    let principal = derived_actor_id(subject);
    let encoded = serde_json::to_vec(&(
        "heptabao.dynamic-authorized-operation.v1",
        subject,
        namespace,
        method,
        path,
        operation_id.as_str(),
        body,
    ))
    .map_err(|_| "cannot bind dynamic-secret operation")?;
    let value = digest(&SHA256, &encoded);
    let mut authorization_digest = [0_u8; 32];
    authorization_digest.copy_from_slice(value.as_ref());
    PluginMutationContext::new(principal, operation_id.clone(), authorization_digest)
        .map_err(|_| "invalid dynamic-secret operation context")
}

fn provider_request(body: &Value) -> Result<SecretValue, &'static str> {
    let encoded = body
        .get("provider_request_base64")
        .and_then(Value::as_str)
        .ok_or("provider_request_base64 is required")?;
    if encoded.len() > 2 * 1024 * 1024 {
        return Err("provider request encoding exceeds limit");
    }
    let decoded = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .map_err(|_| "provider request is not valid base64")?,
    );
    SecretValue::new(decoded.to_vec()).map_err(|_| "provider request violates secret bounds")
}

fn id_field(body: &Value, field: &str) -> Result<Id, &'static str> {
    let value = body.get(field).and_then(Value::as_str).ok_or("required id is missing")?;
    Id::parse(value.to_owned()).map_err(|_| "invalid bounded id")
}

fn u64_field(body: &Value, field: &str) -> Result<u64, &'static str> {
    body.get(field)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or("required positive integer is missing")
}

fn only_fields(body: &Value, allowed: &[&str]) -> bool {
    body.as_object().is_some_and(|object| {
        object.keys().all(|key| allowed.contains(&key.as_str()))
    })
}

fn lease_json(view: &DynamicLeaseView) -> Value {
    json!({
        "lease_id": view.lease_id.as_str(),
        "scope": view.scope.as_str(),
        "state": state_name(view.state),
        "issued_at": view.issued_at.as_u64(),
        "expires_at": view.expires_at.as_u64(),
        "renewable": view.renewable,
        "generation": view.generation,
    })
}

fn parse_lease(object: &Map<String, Value>) -> Option<DynamicLeaseView> {
    if object.keys().any(|key| !matches!(
        key.as_str(),
        "lease_id" | "owner_entity" | "scope" | "state" | "issued_at" | "expires_at"
            | "renewable" | "generation" | "secret_sha256"
    )) {
        return None;
    }
    let state = match object.get("state")?.as_str()? {
        "active" => DynamicLeaseState::Active,
        "revoked" => DynamicLeaseState::Revoked,
        "expired" => DynamicLeaseState::Expired,
        _ => return None,
    };
    let secret_digest = parse_digest(object.get("secret_sha256")?.as_str()?).ok()?;
    Some(DynamicLeaseView {
        lease_id: Id::parse(object.get("lease_id")?.as_str()?.to_owned()).ok()?,
        owner_entity: Id::parse(object.get("owner_entity")?.as_str()?.to_owned()).ok()?,
        scope: CanonicalPath::parse(object.get("scope")?.as_str()?.to_owned()).ok()?,
        state,
        issued_at: Tick::new(object.get("issued_at")?.as_u64()?),
        expires_at: Tick::new(object.get("expires_at")?.as_u64()?),
        renewable: object.get("renewable")?.as_bool()?,
        generation: object.get("generation")?.as_u64()?,
        secret_digest,
    })
}

const fn state_name(state: DynamicLeaseState) -> &'static str {
    match state {
        DynamicLeaseState::Active => "active",
        DynamicLeaseState::Revoked => "revoked",
        DynamicLeaseState::Expired => "expired",
        DynamicLeaseState::ReconciliationRequired => "reconciliation_required",
    }
}

const fn operation_name(operation: PluginOperation) -> &'static str {
    match operation {
        PluginOperation::Read => "read",
        PluginOperation::Write => "write",
        PluginOperation::Issue => "issue",
        PluginOperation::Renew => "renew",
        PluginOperation::Revoke => "revoke",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_lease_identity_is_stable_and_operation_bound() -> Result<(), Box<dyn std::error::Error>> {
        let operation = Id::parse("request_one")?;
        let scope = CanonicalPath::parse("/database/creds/app")?;
        let first = derived_lease_id(&"a".repeat(64), "", &operation, &scope);
        let second = derived_lease_id(&"a".repeat(64), "", &operation, &scope);
        assert_eq!(first, second);
        assert_ne!(
            first,
            derived_lease_id(&"a".repeat(64), "", &Id::parse("request_two")?, &scope)
        );
        Ok(())
    }

    #[test]
    fn zero_or_malformed_provider_digests_are_rejected() {
        assert!(parse_digest(&"0".repeat(64)).is_err());
        assert!(parse_digest("not-a-digest").is_err());
    }
}
