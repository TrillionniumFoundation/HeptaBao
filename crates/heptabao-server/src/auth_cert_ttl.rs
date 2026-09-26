//! Certificate TokenParams retain configured zeroes and legacy alias shadows.
//! Issuance captures explicit maximums; renewal reads current ordinary limits.
use super::*;

fn present(body: &Value, key: &str) -> bool {
    body.get(key).is_some_and(|value| !value.is_null())
}
fn upgrade_duration(
    body: &Value,
    old: &str,
    new: &str,
    shadow: &mut u64,
    native: &mut u64,
) -> Result<(), AuthError> {
    if present(body, new) {
        *shadow = if present(body, old) { *native } else { 0 };
    } else if present(body, old) {
        *shadow = duration(body, old, *shadow)?;
        *native = *shadow;
    }
    Ok(())
}

pub(super) fn validate_limits(role: &CertRole) -> Result<(), AuthError> {
    if [
        role.token_ttl,
        role.token_max_ttl,
        role.token_period,
        role.token_explicit_max_ttl,
        role.legacy_ttl,
        role.legacy_max_ttl,
        role.legacy_period,
    ]
    .into_iter()
    .any(|value| value > MAX_TTL)
        || role.token_max_ttl != 0 && role.token_ttl > role.token_max_ttl
    {
        return Err(bad("invalid certificate token TTL limits"));
    }
    Ok(())
}

pub(super) fn apply(role: &mut CertRole, body: &Value) -> Result<(), AuthError> {
    role.token_ttl = approle_renewal::role_duration(body, "token_ttl", role.token_ttl)?;
    role.token_max_ttl = approle_renewal::role_duration(body, "token_max_ttl", role.token_max_ttl)?;
    role.token_period = approle_renewal::role_duration(body, "token_period", role.token_period)?;
    role.token_explicit_max_ttl = approle_renewal::role_duration(
        body,
        "token_explicit_max_ttl",
        role.token_explicit_max_ttl,
    )?;
    // Upstream ParseTokenFields validates the native fields before UpgradeValue.
    validate_limits(role)?;
    cert_batch::validate_role_type(role)?;
    if role.token_type == Some(batch_issuance::UserTokenType::Batch) && role.token_period > 0 {
        return Err(bad(
            "'token_type' cannot be 'batch' when set to generate periodic tokens",
        ));
    }
    upgrade_duration(
        body,
        "ttl",
        "token_ttl",
        &mut role.legacy_ttl,
        &mut role.token_ttl,
    )?;
    if !present(body, "token_ttl") && !present(body, "ttl") && body.get("lease").is_some() {
        // The legacy lease field is TypeInt, so null is a real zero (duration
        // fields instead ignore null). Numeric strings are weakly decoded.
        role.legacy_ttl = match &body["lease"] {
            Value::Null => 0,
            Value::Bool(value) => u64::from(*value),
            Value::String(value) => value.parse().map_err(|_| bad("invalid lease integer"))?,
            value => value.as_u64().ok_or_else(|| bad("invalid lease integer"))?,
        };
        role.token_ttl = role.legacy_ttl;
    }
    upgrade_duration(
        body,
        "max_ttl",
        "token_max_ttl",
        &mut role.legacy_max_ttl,
        &mut role.token_max_ttl,
    )?;
    upgrade_duration(
        body,
        "period",
        "token_period",
        &mut role.legacy_period,
        &mut role.token_period,
    )?;
    validate_limits(role)
}

pub(super) fn write_response(role: &CertRole, mount_default: u64, mount_max: u64) -> AuthResponse {
    let mut response = empty(true);
    let mut warnings = Vec::new();
    if role.token_ttl > mount_default {
        warnings.push(format!(
            "Given ttl of {} seconds is greater than current mount/system default of {} seconds",
            role.token_ttl, mount_default
        ));
    }
    if role.token_max_ttl > mount_max {
        warnings.push(format!("Given max_ttl of {} seconds is greater than current mount/system default of {} seconds", role.token_max_ttl, mount_max));
    }
    if role.token_period > mount_max {
        warnings.push(format!(
            "Given period of {} seconds is greater than the backend's maximum TTL of {} seconds",
            role.token_period, mount_max
        ));
    }
    if !warnings.is_empty() {
        response.status = 200;
        response.body = json!({"warnings":warnings});
    }
    response
}

pub(super) fn extend_read(data: &mut Value, role: &CertRole) {
    data["token_period"] = json!(role.token_period);
    data["token_explicit_max_ttl"] = json!(role.token_explicit_max_ttl);
    for (key, value) in [
        ("ttl", role.legacy_ttl),
        ("max_ttl", role.legacy_max_ttl),
        ("period", role.legacy_period),
    ] {
        if value > 0 {
            data[key] = json!(value);
        }
    }
}

pub(super) fn has_native_shape(role: &CertRole) -> bool {
    role.token_ttl == 0
        || role.token_max_ttl == 0
        || role.token_period > 0
        || role.token_explicit_max_ttl > 0
        || role.legacy_ttl > 0
        || role.legacy_max_ttl > 0
        || role.legacy_period > 0
}

impl AuthState {
    pub(super) fn renew_cert_token(
        &mut self,
        namespace: &str,
        id: &str,
        body: &Value,
        now: u64,
        peer_certificates: Option<&[Vec<u8>]>,
    ) -> Result<Option<AuthResponse>, AuthError> {
        let Some((mount, ttl, max_ttl, period)) =
            self.cert_renewal_limits(id, peer_certificates)?
        else {
            return Ok(None);
        };
        let token = self.tokens.get(id).ok_or_else(denied)?;
        if !token.renewable {
            return Err(bad("token is not renewable"));
        }
        let expires_at = self.native_token_expiry(
            AuthScope {
                namespace,
                mount: &mount,
            },
            native_token::NativeTokenLimits {
                ttl,
                max_ttl,
                period,
            },
            token.created_at,
            token.max_expires_at,
            duration(body, "increment", 0)?,
            now,
        )?;
        let token = self.tokens.get_mut(id).ok_or_else(denied)?;
        token.expires_at = Some(expires_at);
        let mut response = AuthResponse {
            status: 200,
            mutated: true,
            body: json!({"auth": {"accessor":token.accessor,"policies":token.policies,
                "token_policies":token.policies,"entity_id":token.entity_id.as_deref().unwrap_or(""),
                "lease_duration":expires_at-now,"renewable":true,"token_type":"service",
                "orphan":token.parent.is_none(),"num_uses":token.uses_remaining.unwrap_or(0)}}),
            ..empty(false)
        };
        if let Some(metadata) = cert_metadata::snapshot(token) {
            response.body["auth"]["metadata"] = json!(metadata);
        }
        Ok(Some(response))
    }
}
