//! Bounded Kubernetes secrets-engine state.
//!
//! This module owns durable configuration, roles and issued-token lease metadata,
//! but it never performs network I/O. Service persists a PendingToken intent
//! before handing TokenRequestPlan to the unlocked external-effect executor.

use super::kubernetes_artifact::{Contract as ArtifactContract, LeaseObservation as ArtifactLease};
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
pub(super) const MAX_TOKEN_TTL: u64 = 24 * 60 * 60;
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    artifact_contract: Option<ArtifactContract>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    role: String,
    kubernetes_namespace: String,
    service_account_name: String,
    expires_at: u64,
    audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority: Option<ObservedAuthority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    opaque_artifact: Option<ArtifactLease>,
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
    // Private producer selection is installed only in the actual admitted intent.
    pub(crate) artifact_contract: Option<ArtifactContract>,
}

pub(crate) enum Dispatch {
    Immediate(EngineResponse),
    External(Box<TokenRequestPlan>),
}

// An affine process-local observation of an actual committed lease. It is
// neither serialized nor constructible from a public credential response.
pub(super) struct LeaseDeliveryReceipt {
    lease_id: String,
    config_digest: String,
    lease: Lease,
}

impl LeaseDeliveryReceipt {
    pub(super) fn expires_at(&self) -> u64 {
        self.lease
            .opaque_artifact
            .as_ref()
            .map_or(self.lease.expires_at, |a| a.admission.expires_at)
    }
    pub(super) fn response_lease_duration(&self, now: u64) -> u64 {
        self.lease.opaque_artifact.as_ref().map_or_else(
            || self.lease.expires_at.saturating_sub(now),
            |a| a.public_ttl,
        )
    }
}

pub(crate) struct TokenMetadata {
    pub token: Zeroizing<String>,
    pub expires_at: u64,
    pub audiences: Vec<String>,
    pub(crate) artifact_lifetime_nanos: Option<i64>,
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
            if let Some(contract) = &pending.artifact_contract {
                contract.validate().map_err(|e| err(503, e))?;
                if pending.authority.is_none() || contract.requested_ttl != pending.requested_ttl {
                    return Err(err(
                        503,
                        "opaque Kubernetes intent is missing its actual admitted owner",
                    ));
                }
            }
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
            if let Some(artifact) = &lease.opaque_artifact {
                if lease.authority.is_some() {
                    return Err(err(
                        503,
                        "Kubernetes observation producers cannot be combined",
                    ));
                }
                validate_authority(&artifact.admission)?;
                artifact
                    .validate(lease.expires_at)
                    .map_err(|e| err(503, e))?;
                if artifact.admission.expires_at
                    > artifact
                        .admission
                        .issued_at
                        .saturating_add(artifact.contract.requested_ttl)
                    || artifact.request_digest
                        != request_digest(
                            &lease.role,
                            &lease.kubernetes_namespace,
                            &lease.service_account_name,
                            artifact.contract.requested_ttl,
                            &lease.audiences,
                            &artifact.config_digest,
                        )?
                    || artifact.config_digest
                        != config_digest(self.config.as_ref().ok_or_else(|| {
                            err(
                                503,
                                "opaque Kubernetes owner lacks actual provider configuration",
                            )
                        })?)?
                {
                    return Err(err(
                        503,
                        "opaque Kubernetes artifact actual request binding changed",
                    ));
                }
            }
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

    pub(super) fn validate_artifact_clock(
        &self,
        floor: Option<crate::auth::Timestamp>,
    ) -> Result<()> {
        for lease in self.leases.values() {
            if let Some(artifact) = &lease.opaque_artifact
                && floor.is_none_or(|at| at < artifact.received_at)
            {
                return Err(err(
                    503,
                    "opaque artifact clock floor does not cover registered owner",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn has_opaque_artifact_state(&self) -> bool {
        self.pending.values().any(|p| p.artifact_contract.is_some())
            || self.leases.values().any(|p| p.opaque_artifact.is_some())
    }

    pub(crate) fn bind_opaque_artifact_intent(
        &mut self,
        plan: &mut TokenRequestPlan,
        system_default: u64,
        system_max: u64,
    ) -> std::result::Result<(), EngineError> {
        let pending = self
            .pending
            .get_mut(&plan.lease_id)
            .ok_or_else(|| err(503, "Kubernetes admitted intent is absent"))?;
        let role = self
            .roles
            .get(&pending.role)
            .ok_or_else(|| err(503, "Kubernetes admitted role is absent"))?;
        if pending.authority.as_ref() != Some(&plan.authority)
            || pending.request_digest != plan.request_digest
            || pending.config_digest != plan.config_digest
            || pending.artifact_contract.is_some()
            || plan.artifact_contract.is_some()
        {
            return Err(err(
                503,
                "Kubernetes admitted opaque producer binding changed",
            ));
        }
        let contract =
            ArtifactContract::admitted(plan.ttl, role.token_max_ttl, system_default, system_max)
                .map_err(|e| err(503, e))?;
        pending.artifact_contract = Some(contract.clone());
        plan.artifact_contract = Some(contract);
        self.validate()
    }

    pub(crate) fn has_typed_owners(&self) -> bool {
        self.pending.values().any(|p| p.authority.is_some())
            || self
                .leases
                .values()
                .any(|p| p.authority.is_some() || p.opaque_artifact.is_some())
    }

    pub(crate) fn has_typed_observations(&self) -> bool {
        self.leases
            .values()
            .any(|lease| lease.authority.is_some() || lease.opaque_artifact.is_some())
    }

    pub(crate) fn all_owners(&self) -> impl Iterator<Item = &LeaseOwner> {
        self.pending
            .values()
            .filter_map(|p| p.authority.as_ref().map(|a| &a.owner))
            .chain(self.leases.values().filter_map(|p| {
                p.authority
                    .as_ref()
                    .map(|a| &a.admission.owner)
                    .or_else(|| p.opaque_artifact.as_ref().map(|a| &a.admission.owner))
            }))
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

    pub(super) fn reconcile_owners_observed(
        &mut self,
        time: crate::auth::AuthorityTime,
        namespace: &str,
        live: &BTreeSet<(String, LeaseOwner)>,
    ) -> Result<bool> {
        let at = if self.has_opaque_artifact_state() {
            Some(
                time.exact()
                    .ok_or_else(|| err(503, "trusted opaque artifact clock is required"))?,
            )
        } else {
            None
        };
        let mut changed = self.reconcile_owners(time.seconds(), namespace, live);
        if let Some(at) = at {
            for lease in self.leases.values_mut() {
                if let Some(artifact) = &mut lease.opaque_artifact
                    && !artifact.retired
                    && (artifact.public_expires_at <= at
                        || !live
                            .contains(&(namespace.to_owned(), artifact.admission.owner.clone())))
                {
                    artifact.retired = true;
                    changed = true;
                }
            }
        }
        Ok(changed)
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
            .filter(|(_, l)| {
                l.authority.as_ref().is_none_or(|a| !a.retired)
                    && l.opaque_artifact.as_ref().is_none_or(|a| !a.retired)
            })
            .map(|(id, _)| id.as_str())
    }

    pub(crate) fn contains_lease(&self, id: &str) -> bool {
        self.lease_ids().any(|candidate| candidate == id)
    }

    pub(super) fn lease_lookup_observed(
        &self,
        id: &str,
        time: crate::auth::AuthorityTime,
    ) -> Result<Value> {
        let lease = self
            .leases
            .get(id)
            .filter(|l| {
                l.authority.as_ref().is_none_or(|a| !a.retired)
                    && l.opaque_artifact.as_ref().is_none_or(|a| !a.retired)
            })
            .ok_or_else(|| err(400, "lease not found"))?;
        if let Some(artifact) = &lease.opaque_artifact {
            let at = time
                .exact()
                .ok_or_else(|| err(503, "trusted opaque artifact clock is required"))?;
            if artifact.public_expires_at <= at {
                return Err(err(400, "lease not found"));
            }
            return Ok(
                json!({"id":id,"path":id.rsplit_once('/').map(|(path,_)|path).unwrap_or(id),
                "issue_time":artifact.received_at.rfc3339(),"expire_time":artifact.public_expires_at.rfc3339(),
                "last_renewal":Value::Null,"renewable":false,"ttl":artifact.lookup_ttl(at).map_err(|e|err(503,e))?}),
            );
        }
        self.lease_lookup(id, time.seconds())
    }

    pub(crate) fn lease_lookup(
        &self,
        id: &str,
        now: u64,
    ) -> std::result::Result<Value, EngineError> {
        let lease = self
            .leases
            .get(id)
            .filter(|l| {
                l.authority.as_ref().is_none_or(|a| !a.retired)
                    && l.opaque_artifact.as_ref().is_none_or(|a| !a.retired)
            })
            .ok_or_else(|| err(400, "lease not found"))?;
        if lease.opaque_artifact.is_some() {
            return Err(err(503, "trusted opaque artifact clock is required"));
        }
        Ok(
            json!({"id":id, "path":id.rsplit_once('/').map(|(path,_)| path).unwrap_or(id),
            "issue_time":lease.opaque_artifact.as_ref().map(|a| a.received_at.rfc3339())
                .or_else(|| lease.authority.as_ref().map(|a| timestamp(a.admission.issued_at))),
            "expire_time":timestamp(lease.expires_at), "last_renewal":Value::Null,
            "renewable":false, "ttl":lease.expires_at.saturating_sub(now)}),
        )
    }

    pub(crate) fn retire_lease(&mut self, id: &str) -> bool {
        let Some(lease) = self.leases.get_mut(id) else {
            return false;
        };
        if let Some(artifact) = &mut lease.opaque_artifact {
            let changed = !artifact.retired;
            artifact.retired = true;
            changed
        } else if let Some(observed) = &mut lease.authority {
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
            if lease.opaque_artifact.is_some() {
                // Retain the complete new owner, including retired observations.
                // Only the explicit precise maintenance path may retire it.
                true
            } else if let Some(observed) = &mut lease.authority {
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

    pub(super) fn dispatch_observed(
        &mut self,
        route: (&str, &str),
        method: &str,
        relative: &str,
        body: &Value,
        admitted_clock: (u64, crate::auth::AuthorityTime),
        issuer: Option<&ResolvedLeaseOwner>,
    ) -> Result<Dispatch> {
        let (service_namespace, mount) = route;
        let (admitted_now, time) = admitted_clock;
        if !self.has_opaque_artifact_state() {
            return self.dispatch(
                service_namespace,
                mount,
                method,
                relative,
                body,
                admitted_now,
                issuer,
            );
        }
        let at = time
            .exact()
            .ok_or_else(|| err(503, "trusted opaque artifact clock is required"))?;
        let mut retired = false;
        for lease in self.leases.values_mut() {
            if let Some(artifact) = &mut lease.opaque_artifact
                && !artifact.retired
                && artifact.public_expires_at <= at
            {
                artifact.retired = true;
                retired = true;
            }
        }
        let mut response = self.dispatch_with_observation(
            (service_namespace, mount),
            method,
            relative,
            body,
            admitted_now,
            issuer,
        )?;
        if let Dispatch::Immediate(value) = &mut response {
            value.mutated |= retired;
        }
        Ok(response)
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
        if self.has_opaque_artifact_state() {
            return Err(err(503, "trusted opaque artifact dispatch is required"));
        }
        self.dispatch_with_observation(
            (service_namespace, mount),
            method,
            relative,
            body,
            now,
            issuer,
        )
    }

    fn dispatch_with_observation(
        &mut self,
        route: (&str, &str),
        method: &str,
        relative: &str,
        body: &Value,
        now: u64,
        issuer: Option<&ResolvedLeaseOwner>,
    ) -> std::result::Result<Dispatch, EngineError> {
        let (service_namespace, mount) = route;
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
                    artifact_contract: None,
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
                artifact_contract: None,
            })));
        }

        Err(err(404, "unsupported Kubernetes secrets path"))
    }

    pub(super) fn capture_delivery_receipt(
        &self,
        plan: &TokenRequestPlan,
    ) -> std::result::Result<Option<LeaseDeliveryReceipt>, EngineError> {
        let lease = self
            .leases
            .get(&plan.lease_id)
            .ok_or_else(|| err(503, "Kubernetes committed lease is unavailable"))?;
        if let Some(artifact) = &lease.opaque_artifact {
            if self.pending.contains_key(&plan.lease_id)
                || artifact.admission != plan.authority
                || plan.artifact_contract.as_ref() != Some(&artifact.contract)
                || artifact.request_digest != plan.request_digest
                || artifact.config_digest != plan.config_digest
                || lease.kubernetes_namespace != plan.kubernetes_namespace
                || lease.service_account_name != plan.service_account_name
                || lease.audiences != plan.audiences
                || config_digest(
                    self.config
                        .as_ref()
                        .ok_or_else(|| err(503, "Kubernetes provider configuration disappeared"))?,
                )? != plan.config_digest
            {
                return Err(err(
                    503,
                    "Kubernetes committed opaque artifact binding changed",
                ));
            }
            if artifact.retired {
                return Ok(None);
            }
            return Ok(Some(LeaseDeliveryReceipt {
                lease_id: plan.lease_id.clone(),
                config_digest: plan.config_digest.clone(),
                lease: lease.clone(),
            }));
        }
        if plan.artifact_contract.is_some() {
            return Err(err(503, "Kubernetes opaque artifact owner disappeared"));
        }
        let observed = lease
            .authority
            .as_ref()
            .ok_or_else(|| err(503, "Kubernetes committed lease owner is unavailable"))?;
        if self.pending.contains_key(&plan.lease_id)
            || observed.admission != plan.authority
            || lease.kubernetes_namespace != plan.kubernetes_namespace
            || lease.service_account_name != plan.service_account_name
            || plan
                .audiences
                .iter()
                .any(|audience| !lease.audiences.contains(audience))
            || lease.expires_at != observed.provider_expires_at.min(plan.authority.expires_at)
            || config_digest(
                self.config
                    .as_ref()
                    .ok_or_else(|| err(503, "Kubernetes provider configuration disappeared"))?,
            )? != plan.config_digest
        {
            return Err(err(503, "Kubernetes committed lease binding changed"));
        }
        if observed.retired {
            return Ok(None);
        }
        Ok(Some(LeaseDeliveryReceipt {
            lease_id: plan.lease_id.clone(),
            config_digest: plan.config_digest.clone(),
            lease: lease.clone(),
        }))
    }

    pub(super) fn validate_delivery_receipt_observed(
        &self,
        plan: &TokenRequestPlan,
        receipt: &LeaseDeliveryReceipt,
        time: crate::auth::AuthorityTime,
    ) -> std::result::Result<(), EngineError> {
        if plan.artifact_contract.is_none() {
            return self.validate_delivery_receipt(plan, receipt, time.seconds());
        }
        let at = time
            .exact()
            .ok_or_else(|| err(503, "trusted opaque artifact clock is required"))?;
        self.validate_delivery_receipt_with_observation(plan, receipt, time.seconds(), Some(at))
    }

    pub(super) fn validate_delivery_receipt(
        &self,
        plan: &TokenRequestPlan,
        receipt: &LeaseDeliveryReceipt,
        now: u64,
    ) -> std::result::Result<(), EngineError> {
        self.validate_delivery_receipt_with_observation(plan, receipt, now, None)
    }

    fn validate_delivery_receipt_with_observation(
        &self,
        plan: &TokenRequestPlan,
        receipt: &LeaseDeliveryReceipt,
        now: u64,
        at: Option<crate::auth::Timestamp>,
    ) -> std::result::Result<(), EngineError> {
        if receipt.lease_id != plan.lease_id
            || receipt.config_digest != plan.config_digest
            || self.pending.contains_key(&plan.lease_id)
            || self.leases.get(&plan.lease_id) != Some(&receipt.lease)
            || receipt.lease.expires_at <= now
            || receipt.expires_at() <= now
            || match (&receipt.lease.opaque_artifact, &receipt.lease.authority) {
                (Some(artifact), None) => {
                    artifact.retired
                        || at.is_none_or(|at| artifact.public_expires_at <= at)
                        || artifact.admission != plan.authority
                        || plan.artifact_contract.as_ref() != Some(&artifact.contract)
                        || artifact.request_digest != plan.request_digest
                        || artifact.config_digest != plan.config_digest
                }
                (None, Some(observed)) => {
                    plan.artifact_contract.is_some()
                        || observed.retired
                        || observed.admission != plan.authority
                }
                _ => true,
            }
            || config_digest(
                self.config
                    .as_ref()
                    .ok_or_else(|| err(503, "Kubernetes provider configuration disappeared"))?,
            )? != receipt.config_digest
        {
            return Err(err(
                503,
                "Kubernetes committed delivery lease changed or expired",
            ));
        }
        Ok(())
    }

    pub(crate) fn finalize_observed(
        &mut self,
        plan: &TokenRequestPlan,
        metadata: TokenMetadata,
        time: crate::auth::AuthorityTime,
        owner_live: bool,
    ) -> std::result::Result<EngineResponse, EngineError> {
        if plan.artifact_contract.is_none() {
            return self.finalize(plan, metadata, time.seconds(), owner_live);
        }
        let at = time
            .exact()
            .ok_or_else(|| err(503, "trusted opaque artifact clock is required"))?;
        self.finalize_with_observation(plan, metadata, time.seconds(), owner_live, Some(at))
    }

    pub(crate) fn finalize(
        &mut self,
        plan: &TokenRequestPlan,
        metadata: TokenMetadata,
        now: u64,
        owner_live: bool,
    ) -> std::result::Result<EngineResponse, EngineError> {
        self.finalize_with_observation(plan, metadata, now, owner_live, None)
    }

    fn finalize_with_observation(
        &mut self,
        plan: &TokenRequestPlan,
        metadata: TokenMetadata,
        now: u64,
        owner_live: bool,
        received_at: Option<crate::auth::Timestamp>,
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
            || pending.artifact_contract != plan.artifact_contract
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
        if let Some(contract) = &plan.artifact_contract {
            let lifetime_nanos = metadata
                .artifact_lifetime_nanos
                .ok_or_else(|| err(503, "opaque Kubernetes artifact producer is absent"))?;
            if metadata.expires_at != 0 || metadata.audiences != plan.audiences {
                return Err(err(
                    503,
                    "opaque Kubernetes artifact carried legacy provider authority",
                ));
            }
            let received_at =
                received_at.ok_or_else(|| err(503, "trusted opaque artifact clock is required"))?;
            if received_at.seconds() != now {
                return Err(err(503, "opaque artifact clock binding changed"));
            }
            let mut artifact = ArtifactLease {
                admission: plan.authority.clone(),
                contract: contract.clone(),
                request_digest: plan.request_digest.clone(),
                config_digest: plan.config_digest.clone(),
                received_at,
                public_expires_at: received_at,
                lifetime_nanos,
                public_ttl: 0,
                retired: false,
            };
            artifact.public_expires_at = artifact.registration_expiry().map_err(|e| err(503, e))?;
            artifact.public_ttl = artifact
                .registered_response_ttl()
                .map_err(|e| err(503, e))?;
            let public_ttl = artifact.public_ttl;
            let expires_at = artifact
                .public_expires_at
                .ceil_seconds()
                .map_err(|_| err(503, "opaque artifact expiry overflow"))?;
            let retired = !owner_live
                || plan.authority.expires_at <= now
                || artifact.public_expires_at <= received_at;
            artifact.retired = retired;
            self.pending.remove(&plan.lease_id);
            self.leases.insert(
                plan.lease_id.clone(),
                Lease {
                    role: pending.role,
                    kubernetes_namespace: plan.kubernetes_namespace.clone(),
                    service_account_name: plan.service_account_name.clone(),
                    expires_at,
                    audiences: plan.audiences.clone(),
                    authority: None,
                    opaque_artifact: Some(artifact),
                },
            );
            self.validate()?;
            if retired {
                return Ok(EngineResponse {
                    status: 503,
                    body: json!({ "errors":["Kubernetes token observed after lease authority expired or was revoked; credential withheld"],
                    "lease_id":plan.lease_id, "retry_allowed":false, "provider_token_revoked":false, "local_lease_retired":true }),
                    mutated: true,
                });
            }
            let mut body = json!({ "lease_id":plan.lease_id, "lease_duration":public_ttl, "renewable":false,
                "data":{ "service_account_name":plan.service_account_name, "service_account_namespace":plan.kubernetes_namespace,
                          "service_account_token":metadata.token.as_str() } });
            let warnings = contract.warnings(lifetime_nanos).map_err(|e| err(503, e))?;
            if !warnings.is_empty() {
                body["warnings"] = json!(warnings);
            }
            return Ok(ok(body, true));
        }
        if metadata.artifact_lifetime_nanos.is_some() {
            return Err(err(
                503,
                "legacy Kubernetes intent rejects opaque artifact metadata",
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
                opaque_artifact: None,
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
                token_role: None,
                token_api_precision: None,
                token_api_policy_names: false,
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
            precise_expires_at: None,
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
            artifact_lifetime_nanos: None,
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

    fn exact(seconds: u64, nanos: u32) -> TestResult<crate::auth::AuthorityTime> {
        Ok(crate::auth::AuthorityTime::Precise(
            crate::auth::Timestamp::checked(seconds, nanos)?,
        ))
    }

    #[test]
    fn kube_opaque_artifact_public_lifetime_never_extends_original_private_batch_cap() -> TestResult
    {
        let (mut engine, issuer) = ready()?;
        let mut plan = issue(&mut engine, &issuer)?;
        engine.bind_opaque_artifact_intent(&mut plan, 32 * 24 * 3600, 32 * 24 * 3600)?;
        assert!(engine.has_opaque_artifact_state());
        assert_eq!(plan.authority.expires_at, 200);
        let before = serde_json::to_vec(&engine)?;
        assert!(
            engine
                .finalize_observed(
                    &plan,
                    metadata(),
                    crate::auth::AuthorityTime::Coarse(103),
                    true
                )
                .is_err()
        );
        assert_eq!(serde_json::to_vec(&engine)?, before);
        let issued = engine.finalize_observed(
            &plan,
            TokenMetadata {
                token: Zeroizing::new("synthetic-opaque-artifact-not-a-grant".into()),
                expires_at: 0,
                audiences: plan.audiences.clone(),
                artifact_lifetime_nanos: Some(0),
            },
            exact(103, 0)?,
            true,
        )?;
        assert_eq!(issued.status, 200);
        assert_eq!(issued.body["lease_duration"], 97);
        assert_eq!(
            issued.body["warnings"][0],
            "the created Kubernetes service accout token TTL 0s is less than the OpenBao lease TTL 10m0s; capping the lease TTL accordingly"
        );
        assert_eq!(
            issued.body["warnings"][1],
            "TTL of \"768h\" exceeded the effective max_ttl of \"1h\"; TTL value is capped accordingly"
        );
        let lookup = engine.lease_lookup_observed(&plan.lease_id, exact(103, 0)?)?;
        assert_eq!(lookup["ttl"], 97);
        let receipt = engine
            .capture_delivery_receipt(&plan)?
            .ok_or("actual receipt")?;
        assert_eq!(receipt.expires_at(), 200);
        assert_eq!(receipt.response_lease_duration(150), 97);
        engine.validate_delivery_receipt_observed(&plan, &receipt, exact(199, 0)?)?;
        assert!(
            engine
                .validate_delivery_receipt_observed(&plan, &receipt, exact(200, 0)?)
                .is_err()
        );
        assert!(
            engine
                .all_owners()
                .any(|owner| owner == &plan.authority.owner)
        );
        let bytes = serde_json::to_vec(&engine)?;
        assert!(!String::from_utf8_lossy(&bytes).contains("synthetic-opaque-artifact-not-a-grant"));
        let reopened: Kubernetes = serde_json::from_slice(&bytes)?;
        reopened.validate_scope("")?;
        assert!(reopened.validate_scope("other").is_err());
        reopened
            .capture_delivery_receipt(&plan)?
            .ok_or("reopened actual owner")?;
        Ok(())
    }

    #[test]
    fn kube_opaque_artifact_actual_request_digest_and_producer_cannot_be_replaced() -> TestResult {
        let (mut engine, issuer) = ready()?;
        let mut plan = issue(&mut engine, &issuer)?;
        engine.bind_opaque_artifact_intent(&mut plan, 32 * 24 * 3600, 32 * 24 * 3600)?;
        assert!(
            engine
                .finalize_observed(&plan, metadata(), exact(101, 0)?, true)
                .is_err()
        );
        assert!(engine.pending.contains_key(&plan.lease_id));
        let new_metadata = TokenMetadata {
            token: Zeroizing::new("synthetic-opaque-result".into()),
            expires_at: 0,
            audiences: plan.audiences.clone(),
            artifact_lifetime_nanos: Some(300_000_000_000),
        };
        assert_eq!(
            engine
                .finalize_observed(&plan, new_metadata, exact(101, 0)?, true)?
                .body["lease_duration"],
            99
        );
        let mut value = serde_json::to_value(&engine)?;
        value["leases"][&plan.lease_id]["opaque_artifact"]["request_digest"] =
            json!("b".repeat(64));
        let changed: Kubernetes = serde_json::from_value(value)?;
        assert!(changed.validate().is_err());
        let mut value = serde_json::to_value(&engine)?;
        value["leases"][&plan.lease_id]["opaque_artifact"]["contract"]["producer"] =
            json!("client-JSON-proof");
        assert!(serde_json::from_value::<Kubernetes>(value).is_err());
        let mut value = serde_json::to_value(&engine)?;
        value["leases"][&plan.lease_id]["opaque_artifact"]["admission"]["expires_at"] = json!(700);
        let widened: Kubernetes = serde_json::from_value(value)?;
        assert!(widened.validate().is_err());
        assert!(engine.retire_lease(&plan.lease_id));
        assert!(engine.has_opaque_artifact_state());
        assert!(engine.capture_delivery_receipt(&plan)?.is_none());
        assert!(
            engine
                .all_owners()
                .any(|owner| owner == &plan.authority.owner)
        );
        Ok(())
    }

    #[test]
    fn kube_opaque_artifact_registration_round_and_lookup_clock_round_are_distinct() -> TestResult {
        let (mut engine, issuer) = ready()?;
        let mut plan = issue(&mut engine, &issuer)?;
        engine.bind_opaque_artifact_intent(&mut plan, 32 * 24 * 3600, 32 * 24 * 3600)?;
        let issued = engine.finalize_observed(
            &plan,
            TokenMetadata {
                token: Zeroizing::new("opaque-rounding-boundary".into()),
                expires_at: 0,
                audiences: plan.audiences.clone(),
                artifact_lifetime_nanos: Some(0),
            },
            exact(103, 600_000_000)?,
            true,
        )?;
        assert_eq!(issued.body["lease_duration"], 96);
        assert_eq!(
            engine.lease_lookup_observed(&plan.lease_id, exact(104, 600_000_000)?)?["ttl"],
            95
        );
        assert_eq!(
            engine.lease_lookup_observed(&plan.lease_id, exact(104, 400_000_000)?)?["ttl"],
            96
        );
        assert!(engine.lease_lookup(&plan.lease_id, 104).is_err());
        let before = serde_json::to_vec(&engine)?;
        assert!(
            engine
                .reconcile_owners_observed(
                    crate::auth::AuthorityTime::Coarse(201),
                    "",
                    &BTreeSet::new()
                )
                .is_err()
        );
        assert_eq!(serde_json::to_vec(&engine)?, before);
        let live = BTreeSet::from([(String::new(), issuer.owner.clone())]);
        assert!(engine.reconcile_owners_observed(exact(200, 0)?, "", &live)?);
        assert!(engine.has_opaque_artifact_state());
        assert!(engine.leases.contains_key(&plan.lease_id));
        assert!(
            engine
                .lease_lookup_observed(&plan.lease_id, exact(199, 0)?)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn kube_opaque_artifact_zero_rounded_public_ttl_does_not_replace_actual_private_expiry()
    -> TestResult {
        let (mut engine, issuer) = ready()?;
        let mut plan = issue(&mut engine, &issuer)?;
        engine.bind_opaque_artifact_intent(&mut plan, 32 * 24 * 3600, 32 * 24 * 3600)?;
        let at = exact(199, 600_000_000)?;
        let response = engine.finalize_observed(
            &plan,
            TokenMetadata {
                token: Zeroizing::new("opaque-less-than-half-second".into()),
                expires_at: 0,
                audiences: plan.audiences.clone(),
                artifact_lifetime_nanos: Some(0),
            },
            at,
            true,
        )?;
        assert_eq!(response.status, 200);
        assert_eq!(response.body["lease_duration"], 0);
        let receipt = engine
            .capture_delivery_receipt(&plan)?
            .ok_or("future precise receipt")?;
        engine.validate_delivery_receipt_observed(&plan, &receipt, at)?;
        assert!(
            engine
                .validate_delivery_receipt_observed(&plan, &receipt, exact(200, 0)?)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn kube_opaque_artifact_service_public_default_is_independent_of_original_private_delivery_cap()
    -> TestResult {
        let (mut engine, _) = ready()?;
        let issuer = ResolvedLeaseOwner {
            owner: LeaseOwner::service("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")?,
            expires_at: Some(104),
            precise_expires_at: None,
            entity_id: None,
        };
        let mut plan = issue(&mut engine, &issuer)?;
        engine.bind_opaque_artifact_intent(&mut plan, 32 * 24 * 3600, 32 * 24 * 3600)?;
        assert_eq!(plan.authority.expires_at, 700);
        let issued = engine.finalize_observed(
            &plan,
            TokenMetadata {
                token: Zeroizing::new("opaque-service-default".into()),
                expires_at: 0,
                audiences: plan.audiences.clone(),
                artifact_lifetime_nanos: Some(0),
            },
            exact(103, 400_000_000)?,
            true,
        )?;
        assert_eq!(issued.body["lease_duration"], 3600);
        let receipt = engine
            .capture_delivery_receipt(&plan)?
            .ok_or("actual service receipt")?;
        assert_eq!(receipt.expires_at(), 700);
        assert!(
            engine
                .validate_delivery_receipt_observed(&plan, &receipt, exact(700, 0)?)
                .is_err()
        );
        // Service caller expiration is resolved by the authenticated live-owner
        // inventory, not a public registration cap or JWT iat/exp projection.
        assert!(engine.reconcile_owners_observed(exact(105, 0)?, "", &BTreeSet::new())?);
        assert!(
            engine
                .lease_lookup_observed(&plan.lease_id, exact(105, 0)?)
                .is_err()
        );
        assert!(engine.has_opaque_artifact_state());
        Ok(())
    }

    #[test]
    fn kube_opaque_artifact_legacy_none_keeps_old_serialization_and_private_expiry_contract()
    -> TestResult {
        let (mut engine, issuer) = ready()?;
        let plan = issue(&mut engine, &issuer)?;
        assert!(!engine.has_opaque_artifact_state());
        let pending = serde_json::to_value(&engine)?;
        assert!(
            pending["pending"][&plan.lease_id]
                .get("artifact_contract")
                .is_none()
        );
        let mut opaque = metadata();
        opaque.expires_at = 0;
        opaque.artifact_lifetime_nanos = Some(600_000_000_000);
        assert!(engine.finalize(&plan, opaque, 101, true).is_err());
        assert!(engine.pending.contains_key(&plan.lease_id));
        engine.finalize(&plan, metadata(), 101, true)?;
        let legacy = serde_json::to_value(&engine)?;
        assert!(
            legacy["leases"][&plan.lease_id]
                .get("opaque_artifact")
                .is_none()
        );
        let reopened: Kubernetes = serde_json::from_value(legacy)?;
        assert!(!reopened.has_opaque_artifact_state());
        assert_eq!(
            reopened
                .capture_delivery_receipt(&plan)?
                .ok_or("legacy receipt")?
                .expires_at(),
            200
        );
        Ok(())
    }
}
