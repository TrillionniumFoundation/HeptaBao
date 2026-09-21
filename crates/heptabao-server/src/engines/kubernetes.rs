//! Bounded Kubernetes secrets-engine state.
//!
//! This module owns durable configuration, roles and issued-token lease metadata,
//! but it never performs network I/O. Service persists a PendingToken intent
//! before handing TokenRequestPlan to the unlocked external-effect executor.

use super::*;
use crate::{
    auth::{LeaseOwner, ResolvedLeaseOwner, ServiceOwnerProfile},
    crypto,
    outbound::Target,
};
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

/// Bao lease authority is separate from the provider JWT expiry. In particular,
/// a short batch token does not change TokenRequest.expirationSeconds.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeaseAuthority {
    pub owner: LeaseOwner,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedAuthority {
    admission: LeaseAuthority,
    provider_expires_at: u64,
    retired: bool,
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
    // Missing is a genuine old intent, not permission to invent an issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority: Option<LeaseAuthority>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    role: String,
    kubernetes_namespace: String,
    service_account_name: String,
    expires_at: u64,
    audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority: Option<ObservedAuthority>,
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
    pub authority: LeaseAuthority,
}

pub(crate) enum Dispatch {
    Immediate(EngineResponse),
    External(Box<TokenRequestPlan>),
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
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
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

fn string_list(
    value: Option<&Value>,
    field: &str,
) -> std::result::Result<Vec<String>, EngineError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if let Some(text) = value.as_str() {
        if text.is_empty() {
            return Ok(Vec::new());
        }
        return Ok(text.split(',').map(str::trim).map(str::to_owned).collect());
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
    let text = value.as_str().ok_or_else(|| {
        err(
            400,
            "Kubernetes token TTL must be seconds or a bounded duration",
        )
    })?;
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
            return Err(err(
                503,
                "Kubernetes secrets state exceeds bounded capacity",
            ));
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
        for pending in self.pending.values() {
            if let Some(authority) = &pending.authority {
                validate_authority(authority)?;
                if authority.issued_at != pending.created_at
                    || authority.expires_at
                        > pending.created_at.saturating_add(pending.requested_ttl)
                {
                    return Err(err(503, "invalid Kubernetes pending lease ceiling"));
                }
            }
        }
        for lease in self.leases.values() {
            if let Some(observed) = &lease.authority {
                validate_authority(&observed.admission)?;
                if observed.provider_expires_at <= observed.admission.issued_at
                    || observed.provider_expires_at
                        > observed
                            .admission
                            .issued_at
                            .saturating_add(MAX_TOKEN_TTL + 120)
                    || lease.expires_at
                        != observed
                            .provider_expires_at
                            .min(observed.admission.expires_at)
                {
                    return Err(err(503, "invalid Kubernetes observed lease lifetime"));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn has_typed_owners(&self) -> bool {
        self.pending.values().any(|p| p.authority.is_some())
            || self.leases.values().any(|p| p.authority.is_some())
    }

    pub(crate) fn has_typed_observations(&self) -> bool {
        self.leases.values().any(|lease| lease.authority.is_some())
    }

    pub(crate) fn all_owners(&self) -> impl Iterator<Item = &LeaseOwner> {
        self.pending
            .values()
            .filter_map(|p| p.authority.as_ref().map(|a| &a.owner))
            .chain(
                self.leases
                    .values()
                    .filter_map(|p| p.authority.as_ref().map(|a| &a.admission.owner)),
            )
    }

    pub(crate) fn validate_scope(&self, namespace: &str) -> std::result::Result<(), EngineError> {
        self.validate()?;
        for owner in self.all_owners() {
            owner
                .validate_scope(namespace, ServiceOwnerProfile::DigestAlphabet)
                .map_err(|_| err(503, "Kubernetes lease owner scope mismatch"))?;
        }
        Ok(())
    }

    pub(crate) fn reconcile_owners(
        &mut self,
        now: u64,
        namespace: &str,
        live: &BTreeSet<(String, LeaseOwner)>,
    ) -> bool {
        let mut changed = self.reconcile(now);
        for lease in self.leases.values_mut() {
            if let Some(observed) = &mut lease.authority
                && !observed.retired
                && !live.contains(&(namespace.to_owned(), observed.admission.owner.clone()))
            {
                // Existing SA: retire only the Bao lease. Its JWT remains an
                // independent provider credential until provider_expires_at.
                observed.retired = true;
                changed = true;
            }
        }
        changed
    }

    pub(crate) fn lease_ids(&self) -> impl Iterator<Item = &str> {
        self.leases
            .iter()
            .filter(|(_, l)| l.authority.as_ref().is_none_or(|a| !a.retired))
            .map(|(id, _)| id.as_str())
    }

    pub(crate) fn contains_lease(&self, id: &str) -> bool {
        self.lease_ids().any(|candidate| candidate == id)
    }

    pub(crate) fn lease_lookup(
        &self,
        id: &str,
        now: u64,
    ) -> std::result::Result<Value, EngineError> {
        let lease = self
            .leases
            .get(id)
            .filter(|l| l.authority.as_ref().is_none_or(|a| !a.retired))
            .ok_or_else(|| err(400, "lease not found"))?;
        Ok(
            json!({"id":id, "path":id.rsplit_once('/').map(|(path,_)| path).unwrap_or(id),
            "issue_time":lease.authority.as_ref().map(|a| timestamp(a.admission.issued_at)),
            "expire_time":timestamp(lease.expires_at), "last_renewal":Value::Null,
            "renewable":false, "ttl":lease.expires_at.saturating_sub(now)}),
        )
    }

    pub(crate) fn retire_lease(&mut self, id: &str) -> bool {
        let Some(lease) = self.leases.get_mut(id) else {
            return false;
        };
        if let Some(observed) = &mut lease.authority {
            let changed = !observed.retired;
            observed.retired = true;
            changed
        } else {
            self.leases.remove(id).is_some()
        }
    }

    pub(crate) fn revoke_prefix(&mut self, prefix: &str) -> bool {
        let boundary = format!("{prefix}/");
        let ids: Vec<_> = self
            .lease_ids()
            .filter(|id| *id == prefix || id.starts_with(&boundary))
            .map(str::to_owned)
            .collect();
        let mut changed = false;
        for id in ids {
            changed |= self.retire_lease(&id);
        }
        // Pending TokenRequest intents are never erased or replayed here.
        changed
    }

    fn reconcile(&mut self, now: u64) -> bool {
        let before = self.leases.len();
        let mut changed = false;
        self.leases.retain(|_, lease| {
            if let Some(observed) = &mut lease.authority {
                if lease.expires_at <= now && !observed.retired {
                    observed.retired = true;
                    changed = true;
                }
                observed.provider_expires_at > now
            } else {
                lease.expires_at > now
            }
        });
        changed || before != self.leases.len()
    }

    // Existing route arguments stay explicit; the added issuer is borrowed authority.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch(
        &mut self,
        service_namespace: &str,
        mount: &str,
        method: &str,
        relative: &str,
        body: &Value,
        now: u64,
        issuer: Option<&ResolvedLeaseOwner>,
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
                    let allowed_values = string_list(
                        body.get("allowed_kubernetes_namespaces"),
                        "allowed_kubernetes_namespaces",
                    )?;
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
                    let token_max_ttl = duration(body.get("token_max_ttl"), DEFAULT_MAX_TOKEN_TTL)?;
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
                return Err(err(
                    403,
                    "Kubernetes namespace is not admitted by this role",
                ));
            }
            let ttl = duration(body.get("ttl"), role.token_default_ttl)?;
            if ttl < MIN_TOKEN_TTL || ttl > role.token_max_ttl {
                return Err(err(
                    400,
                    "requested Kubernetes token TTL exceeds role bounds",
                ));
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
            let issuer =
                issuer.ok_or_else(|| err(403, "Kubernetes credential issuer is required"))?;
            issuer
                .owner
                .validate_scope(service_namespace, ServiceOwnerProfile::DigestAlphabet)
                .map_err(|_| err(403, "Kubernetes credential issuer scope mismatch"))?;
            let mut lease_expiry = now
                .checked_add(ttl)
                .ok_or_else(|| err(400, "lease expiry overflow"))?;
            if let Some(batch) = issuer.owner.batch_claims() {
                lease_expiry = lease_expiry.min(batch.expires_at());
            }
            if lease_expiry <= now {
                return Err(err(403, "Kubernetes credential issuer has expired"));
            }
            let authority = LeaseAuthority {
                owner: issuer.owner.clone(),
                issued_at: now,
                expires_at: lease_expiry,
            };
            let config_digest = config_digest(&config)?;
            let request_digest = request_digest(
                role_name,
                &kubernetes_namespace,
                &role.service_account_name,
                ttl,
                &audiences,
                &config_digest,
            )?;
            let entropy = hex(&crypto::random::<16>()
                .map_err(|_| err(503, "operating system randomness unavailable"))?);
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
                    authority: Some(authority.clone()),
                },
            );
            self.validate()?;
            return Ok(Dispatch::External(Box::new(TokenRequestPlan {
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
                authority,
            })));
        }

        Err(err(404, "unsupported Kubernetes secrets path"))
    }

    pub(crate) fn finalize(
        &mut self,
        plan: &TokenRequestPlan,
        metadata: TokenMetadata,
        now: u64,
        owner_live: bool,
    ) -> std::result::Result<EngineResponse, EngineError> {
        let pending = self
            .pending
            .get(&plan.lease_id)
            .ok_or_else(|| {
                err(
                    503,
                    "Kubernetes token intent disappeared after provider entry",
                )
            })?
            .clone();
        if pending.authority.as_ref() != Some(&plan.authority)
            || pending.request_digest != plan.request_digest
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
        let expires_at = metadata.expires_at.min(plan.authority.expires_at);
        let retired = !owner_live || expires_at <= now;
        self.pending.remove(&plan.lease_id);
        self.leases.insert(
            plan.lease_id.clone(),
            Lease {
                role: pending.role,
                kubernetes_namespace: plan.kubernetes_namespace.clone(),
                service_account_name: plan.service_account_name.clone(),
                expires_at,
                audiences: metadata.audiences.clone(),
                authority: Some(ObservedAuthority {
                    admission: plan.authority.clone(),
                    provider_expires_at: metadata.expires_at,
                    retired,
                }),
            },
        );
        self.validate()?;
        if retired {
            return Ok(EngineResponse {
                status: 503,
                body: json!({
                    "errors":["Kubernetes token observed after lease authority expired or was revoked; credential withheld"],
                    "lease_id":plan.lease_id, "retry_allowed":false,
                    "provider_token_revoked":false, "local_lease_retired":true
                }),
                mutated: true,
            });
        }
        Ok(ok(
            json!({
                "lease_id":plan.lease_id,
                "lease_duration":expires_at.saturating_sub(now),
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

fn validate_authority(authority: &LeaseAuthority) -> std::result::Result<(), EngineError> {
    if authority.issued_at == 0
        || authority.expires_at <= authority.issued_at
        || authority.expires_at.saturating_sub(authority.issued_at) > MAX_TOKEN_TTL
        || authority.owner.batch_claims().is_some_and(|batch| {
            authority.expires_at > batch.expires_at() || authority.issued_at < batch.issued_at()
        })
    {
        return Err(err(503, "invalid Kubernetes lease authority"));
    }
    Ok(())
}

#[cfg(test)]
mod owner_tests {
    use super::*;
    use crate::auth::{BatchClaims, BatchKeyAuthority};
    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn issuer() -> TestResult<ResolvedLeaseOwner> {
        let mut keys = BatchKeyAuthority::new(100)?;
        let token = keys.seal(
            BatchClaims {
                namespace: String::new(),
                policies: BTreeSet::from(["default".into()]),
                metadata: BTreeMap::new(),
                display_name: "test".into(),
                path: "auth/token/create".into(),
                bound_cidrs: Vec::new(),
                issued_at: 100,
                expires_at: 200,
                parent: None,
                entity_id: None,
            },
            100,
        )?;
        Ok(ResolvedLeaseOwner {
            owner: LeaseOwner::from_batch(&keys.open(token.as_str(), "", 100)?),
            expires_at: Some(200),
            entity_id: None,
        })
    }
    fn ready() -> TestResult<(Kubernetes, ResolvedLeaseOwner)> {
        let mut engine = Kubernetes::default();
        engine.dispatch("", "kubernetes/", "POST", "config", &json!({
            "kubernetes_host":"https://localhost:8443", "service_account_token":"synthetic-manager"
        }), 100, None).map_err(|_| "config")?;
        engine
            .dispatch(
                "",
                "kubernetes/",
                "POST",
                "roles/reader",
                &json!({
                    "allowed_kubernetes_namespaces":["default"], "service_account_name":"reader",
                    "token_default_ttl":600, "token_max_ttl":3600
                }),
                100,
                None,
            )
            .map_err(|_| "role")?;
        Ok((engine, issuer()?))
    }
    fn issue(engine: &mut Kubernetes, issuer: &ResolvedLeaseOwner) -> TestResult<TokenRequestPlan> {
        let Dispatch::External(plan) = engine
            .dispatch(
                "",
                "kubernetes/",
                "POST",
                "creds/reader",
                &json!({"kubernetes_namespace":"default"}),
                100,
                Some(issuer),
            )
            .map_err(|_| "issue")?
        else {
            return Err("external expected".into());
        };
        Ok(*plan)
    }
    fn metadata() -> TokenMetadata {
        TokenMetadata {
            token: Zeroizing::new("synthetic-provider-jwt".into()),
            expires_at: 700,
            audiences: Vec::new(),
        }
    }

    #[test]
    fn batch_caps_only_bao_lease_and_retirement_keeps_no_jwt_but_known_expiry() -> TestResult {
        let (mut engine, owner) = ready()?;
        let plan = issue(&mut engine, &owner)?;
        assert_eq!(plan.ttl, 600);
        assert_eq!(plan.authority.expires_at, 200);
        let response = engine
            .finalize(&plan, metadata(), 102, true)
            .map_err(|_| "finalize")?;
        assert_eq!(response.status, 200);
        assert_eq!(response.body["lease_duration"], 98);
        assert_eq!(response.body["renewable"], false);
        let state = serde_json::to_string(&engine)?;
        assert!(!state.contains("synthetic-provider-jwt"));
        let mut reopened: Kubernetes = serde_json::from_str(&state)?;
        assert_eq!(
            reopened
                .lease_lookup(&plan.lease_id, 102)
                .map_err(|_| "lookup")?["ttl"],
            98
        );
        assert!(reopened.reconcile_owners(103, "", &BTreeSet::new()));
        assert!(!reopened.contains_lease(&plan.lease_id));
        assert_eq!(
            reopened
                .leases
                .get(&plan.lease_id)
                .ok_or("observation")?
                .authority
                .as_ref()
                .ok_or("typed")?
                .provider_expires_at,
            700
        );
        assert!(reopened.reconcile_owners(700, "", &BTreeSet::new()));
        assert!(reopened.leases.is_empty());
        Ok(())
    }

    #[test]
    fn late_dead_owner_retires_known_result_unknown_intent_is_not_deleted() -> TestResult {
        let (mut engine, owner) = ready()?;
        let plan = issue(&mut engine, &owner)?;
        assert!(!engine.reconcile_owners(101, "", &BTreeSet::new()));
        assert!(engine.pending.contains_key(&plan.lease_id));
        assert!(!engine.revoke_prefix("kubernetes"));
        assert!(engine.pending.contains_key(&plan.lease_id));
        let response = engine
            .finalize(&plan, metadata(), 101, false)
            .map_err(|_| "finalize")?;
        assert_eq!(response.status, 503);
        assert_eq!(response.body["retry_allowed"], false);
        assert_eq!(response.body["provider_token_revoked"], false);
        assert_eq!(response.body["local_lease_retired"], true);
        assert!(response.body.get("data").is_none());
        assert!(!engine.pending.contains_key(&plan.lease_id));
        assert!(engine.leases.contains_key(&plan.lease_id));
        Ok(())
    }

    #[test]
    fn full_owner_change_with_same_request_digest_is_rejected_without_mutation() -> TestResult {
        let (mut engine, owner) = ready()?;
        let plan = issue(&mut engine, &owner)?;
        engine
            .pending
            .get_mut(&plan.lease_id)
            .ok_or("intent")?
            .authority
            .as_mut()
            .ok_or("authority")?
            .owner = LeaseOwner::service("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")?;
        let before = serde_json::to_vec(&engine)?;
        assert!(engine.finalize(&plan, metadata(), 101, true).is_err());
        assert_eq!(before, serde_json::to_vec(&engine)?);
        Ok(())
    }

    #[test]
    fn old_pending_and_lease_bytes_roundtrip_without_inventing_an_owner() -> TestResult {
        const OLD: &str = r#"{"pending":{"kubernetes/creds/reader/old":{"request_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","config_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","role":"reader","kubernetes_namespace":"default","service_account_name":"reader","requested_ttl":600,"audiences":[],"created_at":100}},"leases":{"kubernetes/creds/reader/issued":{"role":"reader","kubernetes_namespace":"default","service_account_name":"reader","expires_at":700,"audiences":[]}}}"#;
        let mut old: Kubernetes = serde_json::from_str(OLD)?;
        old.validate_scope("").map_err(|_| "legacy validate")?;
        assert!(!old.has_typed_owners());
        assert_eq!(serde_json::to_string(&old)?, OLD);
        assert!(!old.reconcile_owners(101, "", &BTreeSet::new()));
        assert_eq!(serde_json::to_string(&old)?, OLD);
        // Caller loss cannot fabricate a legacy owner or erase an unknown POST.
        assert!(old.pending.values().all(|p| p.authority.is_none()));
        Ok(())
    }
    #[test]
    fn namespace_binding_and_lease_ceiling_tampering_are_rejected() -> TestResult {
        let (mut engine, owner) = ready()?;
        let plan = issue(&mut engine, &owner)?;
        assert!(engine.validate_scope("other").is_err());
        let pending = engine.pending.get_mut(&plan.lease_id).ok_or("pending")?;
        pending.authority.as_mut().ok_or("authority")?.expires_at = 201;
        assert!(engine.validate_scope("").is_err());
        Ok(())
    }
}
