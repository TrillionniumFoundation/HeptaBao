//! Bounded Kubernetes secrets-engine state.
//!
//! This module owns durable configuration, roles and issued-token lease metadata,
//! but it never performs network I/O. Service persists a PendingToken intent
//! before handing TokenRequestPlan to the unlocked external-effect executor.

use super::*;
use crate::{crypto, outbound::Target};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

const MAX_ROLES: usize = 64;
const MAX_PENDING: usize = 64;
const MAX_LEASES: usize = 1024;
const MIN_TOKEN_TTL: u64 = 600;
const MAX_TOKEN_TTL: u64 = 24 * 60 * 60;
const DEFAULT_TOKEN_TTL: u64 = 600;
const DEFAULT_MAX_TOKEN_TTL: u64 = 3600;

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct SecretString(String);

impl SecretString {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    kubernetes_host: String,
    service_account_token: SecretString,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Role {
    allowed_namespaces: AllowedNamespaces,
    service_account_name: String,
    token_default_ttl: u64,
    token_max_ttl: u64,
    token_default_audiences: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum AllowedNamespaces {
    Any(String),
    Exact(BTreeSet<String>),
}

impl AllowedNamespaces {
    fn permits(&self, namespace: &str) -> bool {
        match self {
            Self::Any(value) => value == "*",
            Self::Exact(values) => values.contains(namespace),
        }
    }

    fn as_json(&self) -> Value {
        match self {
            Self::Any(_) => json!(["*"]),
            Self::Exact(values) => json!(values),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingToken {
    request_digest: String,
    config_digest: String,
    role: String,
    kubernetes_namespace: String,
    service_account_name: String,
    requested_ttl: u64,
    audiences: Vec<String>,
    created_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    role: String,
    kubernetes_namespace: String,
    service_account_name: String,
    expires_at: u64,
    audiences: Vec<String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Kubernetes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    config: Option<Config>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    roles: BTreeMap<String, Role>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pending: BTreeMap<String, PendingToken>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    leases: BTreeMap<String, Lease>,
}

pub(crate) struct TokenRequestPlan {
    pub namespace: String,
    pub mount: String,
    pub lease_id: String,
    pub request_digest: String,
    pub config_digest: String,
    pub provider_url: String,
    pub provider_token: SecretString,
    pub kubernetes_namespace: String,
    pub service_account_name: String,
    pub ttl: u64,
    pub audiences: Vec<String>,
}

pub(crate) enum Dispatch {
    Immediate(EngineResponse),
    External(TokenRequestPlan),
}

pub(crate) struct TokenMetadata {
    pub token: Zeroizing<String>,
    pub expires_at: u64,
    pub audiences: Vec<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn err(status: u16, message: &str) -> EngineError {
    EngineError {
        status,
        message: message.into(),
    }
}

fn empty(mutated: bool) -> EngineResponse {
    EngineResponse {
        status: 204,
        body: Value::Null,
        mutated,
    }
}

fn ok(body: Value, mutated: bool) -> EngineResponse {
    EngineResponse {
        status: 200,
        body,
        mutated,
    }
}

fn valid_component(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn valid_kubernetes_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment.len() <= 63
                && !segment.starts_with('-')
                && !segment.ends_with('-')
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn validate_audiences(values: Vec<String>) -> std::result::Result<Vec<String>, EngineError> {
    if values.len() > 16 {
        return Err(err(400, "too many Kubernetes token audiences"));
    }
    let mut seen = BTreeSet::new();
    for value in &values {
        if value.is_empty()
            || value.len() > 256
            || !value.is_ascii()
            || value.bytes().any(|byte| byte < 32 || byte == 127)
            || !seen.insert(value.clone())
        {
            return Err(err(400, "invalid Kubernetes token audience"));
        }
    }
    Ok(values)
}

fn string_list(value: Option<&Value>, field: &str) -> std::result::Result<Vec<String>, EngineError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if let Some(text) = value.as_str() {
        if text.is_empty() {
            return Ok(Vec::new());
        }
        return Ok(text
            .split(',')
            .map(str::trim)
            .map(str::to_owned)
            .collect());
    }
    let array = value
        .as_array()
        .ok_or_else(|| err(400, &format!("{field} must be a string or string array")))?;
    array
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| err(400, &format!("{field} must contain only strings")))
        })
        .collect()
}

fn duration(value: Option<&Value>, default: u64) -> std::result::Result<u64, EngineError> {
    let Some(value) = value else {
        return Ok(default);
    };
    if let Some(seconds) = value.as_u64() {
        return Ok(seconds);
    }
    let text = value
        .as_str()
        .ok_or_else(|| err(400, "Kubernetes token TTL must be seconds or a bounded duration"))?;
    if text.is_empty() || text.len() > 32 {
        return Err(err(400, "invalid Kubernetes token TTL"));
    }
    let mut total = 0_u64;
    let mut number = 0_u64;
    let mut digits = false;
    for byte in text.bytes() {
        if byte.is_ascii_digit() {
            number = number
                .checked_mul(10)
                .and_then(|current| current.checked_add(u64::from(byte - b'0')))
                .ok_or_else(|| err(400, "Kubernetes token TTL overflow"))?;
            digits = true;
            continue;
        }
        if !digits {
            return Err(err(400, "invalid Kubernetes token TTL"));
        }
        let multiplier = match byte {
            b's' => 1,
            b'm' => 60,
            b'h' => 3600,
            _ => return Err(err(400, "Kubernetes token TTL supports s, m and h")),
        };
        total = total
            .checked_add(
                number
                    .checked_mul(multiplier)
                    .ok_or_else(|| err(400, "Kubernetes token TTL overflow"))?,
            )
            .ok_or_else(|| err(400, "Kubernetes token TTL overflow"))?;
        number = 0;
        digits = false;
    }
    if digits {
        total = total
            .checked_add(number)
            .ok_or_else(|| err(400, "Kubernetes token TTL overflow"))?;
    }
    Ok(total)
}

fn config_digest(config: &Config) -> std::result::Result<String, EngineError> {
    let bytes = serde_json::to_vec(config)
        .map_err(|_| err(500, "Kubernetes provider configuration encoding failed"))?;
    Ok(hex(&crypto::digest(&bytes)))
}

fn request_digest(
    role: &str,
    namespace: &str,
    service_account: &str,
    ttl: u64,
    audiences: &[String],
    config_digest: &str,
) -> std::result::Result<String, EngineError> {
    let bytes = serde_json::to_vec(&json!({
        "role": role,
        "namespace": namespace,
        "service_account": service_account,
        "ttl": ttl,
        "audiences": audiences,
        "config_digest": config_digest,
    }))
    .map_err(|_| err(500, "Kubernetes token request encoding failed"))?;
    Ok(hex(&crypto::digest(&bytes)))
}

impl Kubernetes {
    pub(crate) fn has_unresolved(&self) -> bool {
        !self.pending.is_empty() || !self.leases.is_empty()
    }

    pub(crate) fn validate(&self) -> std::result::Result<(), EngineError> {
        if self.roles.len() > MAX_ROLES
            || self.pending.len() > MAX_PENDING
            || self.leases.len() > MAX_LEASES
        {
            return Err(err(503, "Kubernetes secrets state exceeds bounded capacity"));
        }
        if let Some(config) = &self.config {
            let target = Target::parse(&config.kubernetes_host, "https")
                .map_err(|_| err(503, "invalid Kubernetes provider origin"))?;
            if target.origin != config.kubernetes_host
                || target.path != "/"
                || config.service_account_token.expose().is_empty()
                || config.service_account_token.expose().len() > 32 * 1024
                || !config
                    .service_account_token
                    .expose()
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic())
            {
                return Err(err(503, "invalid Kubernetes provider configuration"));
            }
        }
        for (name, role) in &self.roles {
            if !valid_component(name, 128)
                || !valid_kubernetes_name(&role.service_account_name)
                || !(MIN_TOKEN_TTL..=MAX_TOKEN_TTL).contains(&role.token_default_ttl)
                || !(role.token_default_ttl..=MAX_TOKEN_TTL).contains(&role.token_max_ttl)
                || validate_audiences(role.token_default_audiences.clone()).is_err()
            {
                return Err(err(503, "invalid Kubernetes secrets role state"));
            }
            match &role.allowed_namespaces {
                AllowedNamespaces::Any(value) if value == "*" => {}
                AllowedNamespaces::Exact(values)
                    if !values.is_empty()
                        && values.len() <= 64
                        && values.iter().all(|value| valid_kubernetes_name(value)) => {}
                _ => return Err(err(503, "invalid Kubernetes namespace admission state")),
            }
        }
        for (lease_id, pending) in &self.pending {
            if !valid_component(lease_id.rsplit('/').next().unwrap_or(""), 128)
                || pending.request_digest.len() != 64
                || pending.config_digest.len() != 64
                || !valid_component(&pending.role, 128)
                || !valid_kubernetes_name(&pending.kubernetes_namespace)
                || !valid_kubernetes_name(&pending.service_account_name)
                || !(MIN_TOKEN_TTL..=MAX_TOKEN_TTL).contains(&pending.requested_ttl)
                || validate_audiences(pending.audiences.clone()).is_err()
                || pending.created_at == 0
            {
                return Err(err(503, "invalid pending Kubernetes token state"));
            }
        }
        for (lease_id, lease) in &self.leases {
            if !valid_component(lease_id.rsplit('/').next().unwrap_or(""), 128)
                || !valid_component(&lease.role, 128)
                || !valid_kubernetes_name(&lease.kubernetes_namespace)
                || !valid_kubernetes_name(&lease.service_account_name)
                || lease.expires_at == 0
                || validate_audiences(lease.audiences.clone()).is_err()
            {
                return Err(err(503, "invalid Kubernetes token lease state"));
            }
        }
        Ok(())
    }

    fn reconcile(&mut self, now: u64) -> bool {
        let before = self.leases.len();
        self.leases.retain(|_, lease| lease.expires_at > now);
        before != self.leases.len()
    }

    pub(crate) fn dispatch(
        &mut self,
        service_namespace: &str,
        mount: &str,
        method: &str,
        relative: &str,
        body: &Value,
        now: u64,
    ) -> std::result::Result<Dispatch, EngineError> {
        let mut mutated = self.reconcile(now);
        let body_object = body
            .as_object()
            .ok_or_else(|| err(400, "Kubernetes secrets request body must be an object"))?;
        if relative == "config" {
            return match method {
                "GET" | "HEAD" => {
                    if !body_object.is_empty() {
                        Err(err(400, "Kubernetes config read accepts an empty body"))
                    } else if let Some(config) = &self.config {
                        Ok(Dispatch::Immediate(ok(
                            json!({"data":{
                                "kubernetes_host":config.kubernetes_host,
                                "service_account_token_set":true
                            }}),
                            mutated,
                        )))
                    } else {
                        Err(err(404, "Kubernetes secrets engine is not configured"))
                    }
                }
                "DELETE" => {
                    if !self.pending.is_empty() || !self.leases.is_empty() {
                        return Err(err(
                            409,
                            "Kubernetes configuration is fenced while token intents or leases exist",
                        ));
                    }
                    mutated |= self.config.take().is_some();
                    Ok(Dispatch::Immediate(empty(mutated)))
                }
                "POST" | "PUT" => {
                    if body_object.keys().any(|key| {
                        !matches!(key.as_str(), "kubernetes_host" | "service_account_token")
                    }) {
                        return Err(err(400, "unsupported Kubernetes config field"));
                    }
                    if !self.pending.is_empty() || !self.leases.is_empty() {
                        return Err(err(
                            409,
                            "Kubernetes configuration is frozen while token intents or leases exist",
                        ));
                    }
                    let host = body
                        .get("kubernetes_host")
                        .and_then(Value::as_str)
                        .ok_or_else(|| err(400, "kubernetes_host is required"))?
                        .to_owned();
                    let target = Target::parse(&host, "https")
                        .map_err(|_| err(400, "invalid canonical Kubernetes HTTPS origin"))?;
                    if target.origin != host || target.path != "/" {
                        return Err(err(400, "kubernetes_host must be a canonical HTTPS origin"));
                    }
                    let token = body
                        .get("service_account_token")
                        .and_then(Value::as_str)
                        .ok_or_else(|| err(400, "service_account_token is required"))?;
                    if token.is_empty()
                        || token.len() > 32 * 1024
                        || !token.bytes().all(|byte| byte.is_ascii_graphic())
                    {
                        return Err(err(400, "invalid Kubernetes provider bearer"));
                    }
                    self.config = Some(Config {
                        kubernetes_host: host,
                        service_account_token: SecretString(token.to_owned()),
                    });
                    self.validate()?;
                    Ok(Dispatch::Immediate(empty(true)))
                }
                _ => Err(err(405, "unsupported Kubernetes config method")),
            };
        }

        if relative == "roles" || relative == "roles/" {
            if !body_object.is_empty() {
                return Err(err(400, "Kubernetes role list accepts an empty body"));
            }
            if !matches!(method, "LIST" | "SCAN" | "GET") {
                return Err(err(405, "Kubernetes role list requires LIST"));
            }
            return Ok(Dispatch::Immediate(ok(
                json!({"data":{"keys":self.roles.keys().cloned().collect::<Vec<_>>()}}),
                mutated,
            )));
        }

        if let Some(role_name) = relative.strip_prefix("roles/") {
            if role_name.contains('/') || !valid_component(role_name, 128) {
                return Err(err(400, "invalid Kubernetes role name"));
            }
            return match method {
                "GET" | "HEAD" => {
                    if !body_object.is_empty() {
                        return Err(err(400, "Kubernetes role read accepts an empty body"));
                    }
                    let role = self
                        .roles
                        .get(role_name)
                        .ok_or_else(|| err(404, "Kubernetes role not found"))?;
                    Ok(Dispatch::Immediate(ok(
                        json!({"data":{
                            "allowed_kubernetes_namespaces":role.allowed_namespaces.as_json(),
                            "service_account_name":role.service_account_name,
                            "token_default_ttl":role.token_default_ttl,
                            "token_max_ttl":role.token_max_ttl,
                            "token_default_audiences":role.token_default_audiences,
                        }}),
                        mutated,
                    )))
                }
                "DELETE" => {
                    if self
                        .pending
                        .values()
                        .any(|pending| pending.role == role_name)
                        || self.leases.values().any(|lease| lease.role == role_name)
                    {
                        return Err(err(
                            409,
                            "Kubernetes role is fenced while token intents or leases exist",
                        ));
                    }
                    mutated |= self.roles.remove(role_name).is_some();
                    Ok(Dispatch::Immediate(empty(mutated)))
                }
                "POST" | "PUT" => {
                    if body_object.keys().any(|key| {
                        !matches!(
                            key.as_str(),
                            "allowed_kubernetes_namespaces"
                                | "service_account_name"
                                | "token_default_ttl"
                                | "token_max_ttl"
                                | "token_default_audiences"
                        )
                    }) {
                        return Err(err(400, "unsupported Kubernetes role field"));
                    }
                    if self.roles.len() >= MAX_ROLES && !self.roles.contains_key(role_name) {
                        return Err(err(507, "Kubernetes role capacity exhausted"));
                    }
                    if self
                        .pending
                        .values()
                        .any(|pending| pending.role == role_name)
                        || self.leases.values().any(|lease| lease.role == role_name)
                    {
                        return Err(err(
                            409,
                            "Kubernetes role is frozen while token intents or leases exist",
                        ));
                    }
                    let service_account_name = body
                        .get("service_account_name")
                        .and_then(Value::as_str)
                        .ok_or_else(|| err(400, "service_account_name is required"))?
                        .to_owned();
                    if !valid_kubernetes_name(&service_account_name) {
                        return Err(err(400, "invalid Kubernetes service account name"));
                    }
                    let allowed_values =
                        string_list(body.get("allowed_kubernetes_namespaces"), "allowed_kubernetes_namespaces")?;
                    let allowed_namespaces =
                        if allowed_values.len() == 1 && allowed_values[0] == "*" {
                            AllowedNamespaces::Any("*".into())
                        } else {
                            let values = allowed_values.into_iter().collect::<BTreeSet<_>>();
                            if values.is_empty()
                                || values.len() > 64
                                || !values.iter().all(|value| valid_kubernetes_name(value))
                            {
                                return Err(err(400, "invalid allowed Kubernetes namespaces"));
                            }
                            AllowedNamespaces::Exact(values)
                        };
                    let token_default_ttl =
                        duration(body.get("token_default_ttl"), DEFAULT_TOKEN_TTL)?;
                    let token_max_ttl =
                        duration(body.get("token_max_ttl"), DEFAULT_MAX_TOKEN_TTL)?;
                    if !(MIN_TOKEN_TTL..=MAX_TOKEN_TTL).contains(&token_default_ttl)
                        || token_max_ttl < token_default_ttl
                        || token_max_ttl > MAX_TOKEN_TTL
                    {
                        return Err(err(400, "Kubernetes token TTL is outside bounded profile"));
                    }
                    let token_default_audiences = validate_audiences(string_list(
                        body.get("token_default_audiences"),
                        "token_default_audiences",
                    )?)?;
                    self.roles.insert(
                        role_name.to_owned(),
                        Role {
                            allowed_namespaces,
                            service_account_name,
                            token_default_ttl,
                            token_max_ttl,
                            token_default_audiences,
                        },
                    );
                    self.validate()?;
                    Ok(Dispatch::Immediate(empty(true)))
                }
                _ => Err(err(405, "unsupported Kubernetes role method")),
            };
        }

        if let Some(role_name) = relative.strip_prefix("creds/") {
            if !matches!(method, "POST" | "PUT") {
                return Err(err(405, "Kubernetes credentials require POST or PUT"));
            }
            if role_name.contains('/') || !valid_component(role_name, 128) {
                return Err(err(400, "invalid Kubernetes role name"));
            }
            if body_object
                .keys()
                .any(|key| !matches!(key.as_str(), "kubernetes_namespace" | "ttl" | "audiences"))
            {
                return Err(err(400, "unsupported Kubernetes credentials field"));
            }
            let config = self
                .config
                .as_ref()
                .ok_or_else(|| err(503, "Kubernetes secrets engine is not configured"))?
                .clone();
            let role = self
                .roles
                .get(role_name)
                .ok_or_else(|| err(404, "Kubernetes role not found"))?
                .clone();
            let kubernetes_namespace = body
                .get("kubernetes_namespace")
                .and_then(Value::as_str)
                .ok_or_else(|| err(400, "kubernetes_namespace is required"))?
                .to_owned();
            if !valid_kubernetes_name(&kubernetes_namespace)
                || !role.allowed_namespaces.permits(&kubernetes_namespace)
            {
                return Err(err(403, "Kubernetes namespace is not admitted by this role"));
            }
            let ttl = duration(body.get("ttl"), role.token_default_ttl)?;
            if ttl < MIN_TOKEN_TTL || ttl > role.token_max_ttl {
                return Err(err(400, "requested Kubernetes token TTL exceeds role bounds"));
            }
            let audiences = if body.get("audiences").is_some() {
                validate_audiences(string_list(body.get("audiences"), "audiences")?)?
            } else {
                role.token_default_audiences.clone()
            };
            if self.pending.len() >= MAX_PENDING {
                return Err(err(507, "Kubernetes token intent capacity exhausted"));
            }
            if self.leases.len() >= MAX_LEASES {
                return Err(err(507, "Kubernetes token lease capacity exhausted"));
            }
            let config_digest = config_digest(&config)?;
            let request_digest = request_digest(
                role_name,
                &kubernetes_namespace,
                &role.service_account_name,
                ttl,
                &audiences,
                &config_digest,
            )?;
            let entropy = hex(
                &crypto::random::<16>()
                    .map_err(|_| err(503, "operating system randomness unavailable"))?,
            );
            let lease_id = format!("{mount}creds/{role_name}/{entropy}");
            let provider_url = format!(
                "{}/api/v1/namespaces/{}/serviceaccounts/{}/token",
                config.kubernetes_host, kubernetes_namespace, role.service_account_name
            );
            self.pending.insert(
                lease_id.clone(),
                PendingToken {
                    request_digest: request_digest.clone(),
                    config_digest: config_digest.clone(),
                    role: role_name.to_owned(),
                    kubernetes_namespace: kubernetes_namespace.clone(),
                    service_account_name: role.service_account_name.clone(),
                    requested_ttl: ttl,
                    audiences: audiences.clone(),
                    created_at: now,
                },
            );
            self.validate()?;
            return Ok(Dispatch::External(TokenRequestPlan {
                namespace: service_namespace.to_owned(),
                mount: mount.to_owned(),
                lease_id,
                request_digest,
                config_digest,
                provider_url,
                provider_token: config.service_account_token,
                kubernetes_namespace,
                service_account_name: role.service_account_name,
                ttl,
                audiences,
            }));
        }

        Err(err(404, "unsupported Kubernetes secrets path"))
    }

    pub(crate) fn finalize(
        &mut self,
        plan: &TokenRequestPlan,
        metadata: TokenMetadata,
    ) -> std::result::Result<EngineResponse, EngineError> {
        let pending = self
            .pending
            .get(&plan.lease_id)
            .ok_or_else(|| err(503, "Kubernetes token intent disappeared after provider entry"))?
            .clone();
        if pending.request_digest != plan.request_digest
            || pending.config_digest != plan.config_digest
            || pending.kubernetes_namespace != plan.kubernetes_namespace
            || pending.service_account_name != plan.service_account_name
            || pending.requested_ttl != plan.ttl
            || pending.audiences != plan.audiences
        {
            return Err(err(
                503,
                "Kubernetes token intent changed after provider entry",
            ));
        }
        let current_config = self
            .config
            .as_ref()
            .ok_or_else(|| err(503, "Kubernetes provider configuration disappeared"))?;
        if config_digest(current_config)? != plan.config_digest {
            return Err(err(
                503,
                "Kubernetes provider configuration changed after token issuance",
            ));
        }
        self.pending.remove(&plan.lease_id);
        self.leases.insert(
            plan.lease_id.clone(),
            Lease {
                role: pending.role,
                kubernetes_namespace: plan.kubernetes_namespace.clone(),
                service_account_name: plan.service_account_name.clone(),
                expires_at: metadata.expires_at,
                audiences: metadata.audiences.clone(),
            },
        );
        self.validate()?;
        Ok(ok(
            json!({
                "lease_id":plan.lease_id,
                "lease_duration":metadata.expires_at.saturating_sub(pending.created_at),
                "renewable":false,
                "data":{
                    "service_account_name":plan.service_account_name,
                    "service_account_namespace":plan.kubernetes_namespace,
                    "service_account_token":metadata.token.as_str()
                }
            }),
            true,
        ))
    }
}
