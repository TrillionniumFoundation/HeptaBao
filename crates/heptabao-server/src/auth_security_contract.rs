//! Explicit security options for newly written AppRoles and ACL policies.
//! The immutable OpenBao v2.7.1 contract is recorded in the accompanying
//! research manifest. Unsupported combinations fail before publication.
use super::*;
use std::{borrow::Cow, net::IpAddr};

pub(crate) const STATE_SCHEMA: u32 = 141;

#[derive(Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RoleOptions {
    local_secret_ids: bool,
    token_strictly_bind_ip: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyMetadata {
    allow_slashes_in_identity_templates: bool,
    allow_wildcards_in_identity_templates: bool,
    cas_required: bool,
    version: u64,
    pub(super) modified: Timestamp,
}

pub(super) fn role_local_secret_ids(role: &Role) -> bool {
    role.security
        .is_some_and(|options| options.local_secret_ids)
}

pub(super) fn role_strictly_bind_ip(role: &Role) -> bool {
    role.security
        .is_some_and(|options| options.token_strictly_bind_ip)
}

fn flag(body: &Value, name: &str, old: bool) -> Result<bool, AuthError> {
    let Some(value) = body.get(name) else {
        return Ok(old);
    };
    token_policies::weak_boolean(Some(value), name).map_err(|error| {
        bad(error
            .message
            .strip_prefix("Field validation failed: ")
            .unwrap_or(&error.message))
    })
}

pub(super) fn update_role(role: &mut Role, body: &Value, is_new: bool) -> Result<(), AuthError> {
    let mut options = role.security.unwrap_or_default();
    if body.get("local_secret_ids").is_some() {
        if !is_new {
            return Err(bad(
                "local_secret_ids can only be modified during role creation",
            ));
        }
        options.local_secret_ids = flag(body, "local_secret_ids", false)?;
    }
    options.token_strictly_bind_ip = flag(
        body,
        "token_strictly_bind_ip",
        options.token_strictly_bind_ip,
    )?;
    role.security = Some(options);
    Ok(())
}

pub(super) fn validate_role(role: &Role) -> Result<(), AuthError> {
    approle_local::validate_role_layout(role)?;
    if role_strictly_bind_ip(role)
        && role
            .token_bound_cidrs
            .as_ref()
            .is_some_and(|values| !values.is_empty())
    {
        return Err(bad(
            "'token_strictly_bind_ip' conflicts with 'token_bound_cidrs'; set only one",
        ));
    }
    Ok(())
}

pub(super) fn bind_login_ip(
    role: &Role,
    cidrs: Vec<String>,
    peer: Option<IpAddr>,
) -> Result<Vec<String>, AuthError> {
    validate_role(role)?;
    if !role_strictly_bind_ip(role) {
        return Ok(cidrs);
    }
    let peer = peer.ok_or_else(|| err(500, "failed to get connection information"))?;
    // OpenBao 2.7.1 path_login overwrites PopulateTokenAuth's strict binding.
    // Deliberate hardening: preserve both requested constraints. A SecretID's
    // token CIDRs must contain the login IP, and the issued token is limited
    // to that one address. Never widen the strict binding to the CIDR range.
    token_cidrs::check(&cidrs, Some(peer))?;
    Ok(vec![token_cidrs::canonical(&peer.to_string())?])
}

fn cas_field(body: &Value) -> Result<Option<i64>, AuthError> {
    let value = match body.get("cas") {
        None => return Ok(None),
        // Framework TypeInt keeps a present null as an explicit zero. In a
        // PATCH this must not be mistaken for the omitted-CAS default.
        Some(Value::Null) => 0,
        Some(Value::Number(value)) => value
            .as_i64()
            .ok_or_else(|| bad("cas must be a signed integer"))?,
        Some(Value::String(value)) if value.is_empty() => 0,
        Some(Value::String(value)) => {
            framework_signed_integer(value).map_err(|_| bad("cas must be a signed integer"))?
        }
        Some(Value::Bool(value)) => i64::from(*value),
        _ => return Err(bad("cas must be a signed integer")),
    };
    Ok(Some(value))
}

/// POST/PUT replace omitted options with defaults; PATCH preserves them and
/// internally uses the observed version when the caller omits CAS.
pub(super) fn prepare_policy(
    existing: Option<&Policy>,
    body: &Value,
    patch: bool,
    legacy: bool,
    time: AuthorityTime,
) -> Result<Policy, AuthError> {
    reject_unknown(
        body,
        if legacy {
            &[
                "policy",
                "rules",
                "cas",
                "cas_required",
                "expiration",
                "ttl",
                "allow_slashes_in_identity_templates",
                "allow_wildcards_in_identity_templates",
            ]
        } else {
            &[
                "policy",
                "cas",
                "cas_required",
                "expiration",
                "ttl",
                "allow_slashes_in_identity_templates",
                "allow_wildcards_in_identity_templates",
            ]
        },
    )?;
    if patch && existing.is_none() {
        return Err(err(404, "policy not found"));
    }
    let legacy_source;
    let input = if let Some(value) = body.get("policy") {
        if legacy && (value.is_null() || value.as_str().is_some_and(str::is_empty)) {
            body.get("rules").unwrap_or(value)
        } else {
            value
        }
    } else if legacy && body.get("rules").is_some() {
        body.get("rules").ok_or_else(|| bad("policy is required"))?
    } else if patch {
        legacy_source = Value::String(
            existing
                .ok_or_else(|| err(404, "policy not found"))?
                .source
                .clone(),
        );
        &legacy_source
    } else {
        return Err(bad("'policy' parameter not supplied or empty"));
    };
    if input.as_str().is_some_and(str::is_empty) || input.is_null() {
        return Err(bad("'policy' parameter not supplied or empty"));
    }
    let decoded;
    let input = if let Some(source) = input.as_str() {
        let source = source.replace(['\r', '\n'], "");
        match base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            source.as_bytes(),
        ) {
            Ok(bytes) => {
                decoded = Value::String(
                    String::from_utf8(bytes).map_err(|_| bad("policy must be UTF-8"))?,
                );
                &decoded
            }
            Err(_) => input,
        }
    } else {
        input
    };
    let mut candidate = parse_policy_observed(input, time.exact())?;
    if candidate.has_expiration() && time.exact().is_none() {
        return Err(err(503, "precise policy compilation clock is unavailable"));
    }
    candidate.expiration = policy_expiration::prepare(existing, body, patch, time)?;
    let previous = existing.and_then(|policy| policy.security.as_ref());
    let version = previous.map_or(0, |metadata| metadata.version);
    let old_cas_required = previous.is_some_and(|metadata| metadata.cas_required);
    let old_allow_slashes = existing.is_some_and(|policy| {
        policy
            .security
            .as_ref()
            .is_none_or(|metadata| metadata.allow_slashes_in_identity_templates)
    });
    let old_allow_wildcards =
        previous.is_some_and(|metadata| metadata.allow_wildcards_in_identity_templates);
    let cas_required = flag(body, "cas_required", patch && old_cas_required)?;
    let allow_slashes = flag(
        body,
        "allow_slashes_in_identity_templates",
        patch && old_allow_slashes,
    )?;
    let allow_wildcards = flag(
        body,
        "allow_wildcards_in_identity_templates",
        patch && old_allow_wildcards,
    )?;
    let mut cas = cas_field(body)?;
    if patch && cas.is_none() {
        cas = Some(i64::try_from(version).map_err(|_| bad("policy version is outside CAS range"))?);
    }
    if cas.is_none() && (old_cas_required || cas_required) {
        return Err(bad("check-and-set parameter required for this call"));
    }
    if let Some(cas) = cas {
        if cas == -1 && existing.is_some() {
            return Err(bad("check-and-set parameter set to -1 on existing entry"));
        }
        if cas != -1 && u64::try_from(cas).ok() != Some(version) {
            return Err(bad(
                "check-and-set parameter did not match the current version",
            ));
        }
    }
    let version = version
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| err(507, "policy revision exhausted"))?;
    let modified = match time {
        AuthorityTime::Precise(at) => at,
        AuthorityTime::Coarse(now) => Timestamp::whole(now)
            .map_err(|_| err(503, "policy modification clock is unavailable"))?,
    };
    candidate.security = Some(PolicyMetadata {
        allow_slashes_in_identity_templates: allow_slashes,
        allow_wildcards_in_identity_templates: allow_wildcards,
        cas_required,
        version,
        modified,
    });
    Ok(candidate)
}

impl Policy {
    pub(super) fn read_security_data(&self, name: &str, legacy: bool) -> Result<Value, AuthError> {
        let mut data = json!({"name":name, "version":0, "cas_required":false,
            "allow_slashes_in_identity_templates":true, "allow_wildcards_in_identity_templates":false});
        data[if legacy { "rules" } else { "policy" }] = json!(self.source);
        if let Some(metadata) = &self.security {
            data["version"] = json!(metadata.version);
            data["cas_required"] = json!(metadata.cas_required);
            data["allow_slashes_in_identity_templates"] =
                json!(metadata.allow_slashes_in_identity_templates);
            data["allow_wildcards_in_identity_templates"] =
                json!(metadata.allow_wildcards_in_identity_templates);
            data["modified"] = json!(metadata.modified.rfc3339());
        }
        if let Some(expiration) = self.expiration {
            data["expiration"] = json!(expiration.render()?);
        }
        // An old Hepta record is explicitly unversioned (0) and has no known
        // modification timestamp. Its original slash/wildcard semantics are
        // exposed accurately; no historical timestamp is fabricated.
        Ok(data)
    }

    pub(super) fn render<'a>(
        &self,
        path: &'a str,
        values: &IdentityTemplateValues,
    ) -> Result<Option<Cow<'a, str>>, AuthError> {
        match &self.security {
            Some(metadata) => acl_template::render_with_options(
                path,
                values,
                metadata.allow_slashes_in_identity_templates,
                metadata.allow_wildcards_in_identity_templates,
                true,
            ),
            None => acl_template::render(path, values),
        }
    }
}

impl AuthState {
    /// Construct pre-141 owners only in explicitly historical test inputs.
    /// Callers use an unpublished clone or the bounded pre-141 Service fixture
    /// constructor. This is not a loader or a migration: old policy templates
    /// intentionally retain the predecessor renderer, including slash behavior.
    /// New opt-ins and required CAS cannot be represented and are rejected
    /// before any owner is changed. Credentials, grants and policy source stay.
    #[cfg(test)]
    pub(crate) fn restore_pre141_security_owners_for_format_test(&mut self) {
        for policy in self.policies.values().flat_map(BTreeMap::values) {
            assert!(
                !policy.has_expiration(),
                "legacy fixture cannot erase policy expiration"
            );
            if let Some(metadata) = &policy.security {
                assert!(
                    !metadata.cas_required,
                    "legacy fixture cannot erase required CAS"
                );
                assert!(
                    !metadata.allow_slashes_in_identity_templates,
                    "legacy fixture requires default security options"
                );
                assert!(
                    !metadata.allow_wildcards_in_identity_templates,
                    "legacy fixture cannot erase wildcard opt-in"
                );
            }
        }
        for role in self.roles.values().flat_map(BTreeMap::values).chain(
            self.mounted_roles
                .values()
                .flat_map(BTreeMap::values)
                .flat_map(BTreeMap::values),
        ) {
            assert!(
                !role_local_secret_ids(role),
                "legacy fixture cannot erase local SecretID ownership"
            );
            assert!(
                !role_strictly_bind_ip(role),
                "legacy fixture cannot erase strict IP binding"
            );
        }
        for policy in self.policies.values_mut().flat_map(BTreeMap::values_mut) {
            policy.security = None;
        }
        for role in self
            .roles
            .values_mut()
            .flat_map(BTreeMap::values_mut)
            .chain(
                self.mounted_roles
                    .values_mut()
                    .flat_map(BTreeMap::values_mut)
                    .flat_map(BTreeMap::values_mut),
            )
        {
            role.security = None;
        }
    }

    pub(crate) fn has_security_contract_state(&self) -> bool {
        self.policies
            .values()
            .flat_map(BTreeMap::values)
            .any(|policy| policy.security.is_some())
            || self
                .roles
                .values()
                .flat_map(BTreeMap::values)
                .chain(
                    self.mounted_roles
                        .values()
                        .flat_map(BTreeMap::values)
                        .flat_map(BTreeMap::values),
                )
                .any(|role| role.security.is_some())
    }

    pub(crate) fn validate_security_contract_state(&self) -> Result<(), AuthError> {
        for policy in self.policies.values().flat_map(BTreeMap::values) {
            if policy
                .security
                .as_ref()
                .is_some_and(|metadata| metadata.version == 0 || metadata.version > i64::MAX as u64)
            {
                return Err(bad("invalid persisted ACL policy revision"));
            }
        }
        for (namespace, roles) in &self.roles {
            self.validate_security_role_partition(namespace, "approle", roles)?;
        }
        for (namespace, mounts) in &self.mounted_roles {
            for (mount, roles) in mounts {
                self.validate_security_role_partition(namespace, mount, roles)?;
            }
        }
        Ok(())
    }

    fn validate_security_role_partition(
        &self,
        namespace: &str,
        mount: &str,
        roles: &BTreeMap<String, Role>,
    ) -> Result<(), AuthError> {
        for role in roles.values() {
            if role.security.is_some() && !self.online_mount_enabled(namespace, mount, "approle") {
                return Err(bad("AppRole security options have no AppRole mount"));
            }
            validate_role(role)?;
        }
        Ok(())
    }
}
