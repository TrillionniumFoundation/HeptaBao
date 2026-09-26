//! Native bearer login and migration of the former one-use JWT profile.
use super::*;

pub(super) fn native_time_policy(config: &JwtConfig, role: &JwtRole) -> NativeJwtTimePolicy {
    let clock_skew_seconds = match role.clock_skew_leeway {
        Some(value) if value < 0 => 0,
        Some(0) => 60,
        Some(value) => value as u64,
        None => config.clock_skew_seconds.unwrap_or(60),
    };
    NativeJwtTimePolicy {
        clock_skew_seconds,
        legacy_strict_expiry: role.clock_skew_leeway.is_none()
            && config.clock_skew_seconds.is_some(),
        expiration_leeway: role.expiration_leeway.unwrap_or(0),
        not_before_leeway: role.not_before_leeway.unwrap_or(0),
        maximum_token_lifetime_seconds: config.maximum_token_lifetime_seconds,
    }
}

fn seconds_from_float(value: f64) -> Result<i64, AuthError> {
    if !value.is_finite()
        || !(-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&value)
    {
        return Err(bad("JWT leeway is outside signed seconds range"));
    }
    Ok(value as i64)
}

fn signed_duration(value: &str) -> Result<i64, AuthError> {
    if let Ok(seconds) = value.parse::<i64>() {
        return Ok(seconds);
    }
    let (sign, mut rest) = if let Some(rest) = value.strip_prefix('-') {
        (-1.0, rest)
    } else {
        (1.0, value.strip_prefix('+').unwrap_or(value))
    };
    let mut seconds = 0.0;
    if rest.is_empty() {
        return Err(bad("invalid JWT leeway duration"));
    }
    while !rest.is_empty() {
        let count = rest
            .bytes()
            .take_while(|byte| byte.is_ascii_digit() || *byte == b'.')
            .count();
        if count == 0 {
            return Err(bad("invalid JWT leeway duration"));
        }
        let amount = rest[..count]
            .parse::<f64>()
            .map_err(|_| bad("invalid JWT leeway duration"))?;
        rest = &rest[count..];
        let units = [
            ("ns", 0.000_000_001),
            ("us", 0.000_001),
            ("µs", 0.000_001),
            ("μs", 0.000_001),
            ("ms", 0.001),
            ("s", 1.0),
            ("m", 60.0),
            ("h", 3600.0),
        ];
        let (unit, multiplier) = units
            .into_iter()
            .find(|(unit, _)| rest.starts_with(unit))
            .ok_or_else(|| bad("invalid JWT leeway duration unit"))?;
        seconds += amount * multiplier;
        rest = &rest[unit.len()..];
    }
    seconds_from_float(sign * seconds)
}

pub(super) fn role_leeway(
    body: &Value,
    name: &str,
    previous: Option<i64>,
) -> Result<Option<i64>, AuthError> {
    match body.get(name) {
        None | Some(Value::Null) => Ok(previous),
        Some(Value::Number(value)) => value
            .as_i64()
            .map(Ok)
            .unwrap_or_else(|| {
                value
                    .as_f64()
                    .ok_or_else(|| bad("invalid JWT leeway"))
                    .and_then(seconds_from_float)
            })
            .map(Some),
        Some(Value::String(value)) => signed_duration(value).map(Some),
        _ => Err(bad("JWT leeway must be signed seconds or a duration")),
    }
}

impl AuthState {
    pub(crate) fn has_native_jwt_state(&self) -> bool {
        self.jwt_mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .any(|mount| {
                mount.native_claims
                    || mount.config.as_ref().is_some_and(|config| {
                        config.clock_skew_seconds.is_none()
                            || config.maximum_token_lifetime_seconds.is_none()
                    })
                    || mount.roles.values().any(|role| {
                        role.clock_skew_leeway.is_some()
                            || role.expiration_leeway.is_some()
                            || role.not_before_leeway.is_some()
                    })
            })
    }

    pub(crate) fn validate_native_jwt_state(&self) -> Result<(), AuthError> {
        for mount in self.jwt_mounts.values().flat_map(|mounts| mounts.values()) {
            if mount.native_claims && (!mount.replay.is_empty() || mount.last_admission_time != 0) {
                return Err(bad("native JWT state contains retired replay enforcement"));
            }
            if mount.config.as_ref().is_some_and(|config| {
                config.clock_skew_seconds.is_some_and(|value| value > 300)
                    || config
                        .maximum_token_lifetime_seconds
                        .is_some_and(|value| !(1..=86400).contains(&value))
            }) {
                return Err(bad("invalid explicit JWT compatibility limit"));
            }
        }
        Ok(())
    }

    pub(super) fn retire_jwt_login_replay(&mut self, scope: AuthScope<'_>) {
        let mount = self.jwt_at_mut(scope);
        for (mut fingerprint, _) in std::mem::take(&mut mount.replay) {
            fingerprint.zeroize();
        }
        mount.last_admission_time = 0;
        mount.native_claims = true;
    }
}

/// OpenBao applies the matching mode on each role write, while omission of
/// the bound map retains that map. Explicit null clears the map, not the mode.
pub(super) fn bound_claims_update(
    body: &Value,
    previous: Option<&NativeJwtBoundClaims>,
) -> Result<Option<NativeJwtBoundClaims>, AuthError> {
    let kind = match body.get("bound_claims_type") {
        None => NativeJwtBoundClaimsType::String,
        Some(Value::String(value)) if value == "string" => NativeJwtBoundClaimsType::String,
        Some(Value::String(value)) if value == "glob" => NativeJwtBoundClaimsType::Glob,
        _ => return Err(bad("bound_claims_type must be string or glob")),
    };
    let claims = match body.get("bound_claims") {
        None => previous
            .map(|bounds| bounds.claims.clone())
            .unwrap_or_default(),
        Some(Value::Null) => BTreeMap::new(),
        Some(Value::Object(values)) => values.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        _ => return Err(bad("bound_claims must be an object")),
    };
    // A mode-only update is allowed even if an existing map contains values
    // unsuitable for glob matching; those values then fail at authentication.
    if body.get("bound_claims").is_some()
        && kind == NativeJwtBoundClaimsType::Glob
        && claims.values().any(|value| match value {
            Value::String(_) => false,
            Value::Array(values) => values.iter().any(|value| !value.is_string()),
            _ => true,
        })
    {
        return Err(bad("glob bound claims must be strings or lists of strings"));
    }
    if previous.is_none()
        && body.get("bound_claims").is_none()
        && body.get("bound_claims_type").is_none()
    {
        return Ok(None);
    }
    Ok(Some(NativeJwtBoundClaims { kind, claims }))
}

impl AuthState {
    pub(crate) fn has_jwt_bound_claims_state(&self) -> bool {
        self.jwt_mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .any(|mount| mount.roles.values().any(|role| role.bound_claims.is_some()))
    }
}
