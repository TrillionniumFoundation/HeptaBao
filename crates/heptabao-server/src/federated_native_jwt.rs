//! OpenBao native JWT login accepts reusable bearer assertions. Keep its
//! optional NumericDate semantics separate from the public one-use proof API
//! and from OIDC's consumed-session/nonce contract.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeJwtIdentity {
    pub issuer: String,
    pub subject: String,
    pub audiences: BTreeSet<String>,
    pub namespace: Option<String>,
    pub groups: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeJwtTimePolicy {
    /// Effective skew: role 0 means 60, but the legacy config alias 0 means 0.
    pub clock_skew_seconds: u64,
    /// The legacy config skew applies only to future iat/nbf. It never gave
    /// an expired assertion grace; an explicit role skew selects native rules.
    pub legacy_strict_expiry: bool,
    pub expiration_leeway: i64,
    pub not_before_leeway: i64,
    pub maximum_token_lifetime_seconds: Option<u64>,
}

fn missing_claim_leeway(value: i64) -> i128 {
    if value < 0 {
        0
    } else if value == 0 {
        150
    } else {
        i128::from(value)
    }
}

fn numeric_date(
    claims: &mut BTreeMap<String, Value>,
    name: &str,
) -> Result<Option<i64>, AuthError> {
    match claims.remove(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => {
            if let Some(value) = value.as_i64() {
                return Ok(Some(value));
            }
            let value = value.as_f64().ok_or(AuthError::InvalidClaim)?;
            // go-jose NumericDate truncates fractional seconds toward zero.
            // Reject out-of-range dates rather than relying on float-to-int
            // saturation to turn hostile values into unrelated timestamps.
            if !value.is_finite()
                || !(-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&value)
            {
                return Err(AuthError::InvalidClaim);
            }
            Ok(Some(value as i64))
        }
        _ => Err(AuthError::InvalidClaim),
    }
}

impl JwtVerifier {
    pub(crate) fn verify_native(
        &self,
        token: &str,
        now: u64,
        time: NativeJwtTimePolicy,
        bounds: Option<&NativeJwtBoundClaims>,
    ) -> Result<NativeJwtIdentity, AuthError> {
        let (mut claims, _) = self.verified_claims(token)?;
        // Match only the verified, original claims. Registered fields have not
        // been consumed or replaced with inferred time values yet.
        if bounds.is_some_and(|bounds| !bounds.matches(&claims)) {
            return Err(AuthError::ClaimDenied);
        }
        let issuer = take_string(&mut claims, "iss")?;
        let subject = take_string(&mut claims, "sub")?;
        let audiences = take_audiences(&mut claims)?;
        // jti is optional metadata in native JWT authentication, not a nonce.
        // Its registered claim type remains a string if it is supplied.
        match claims.remove("jti") {
            None | Some(Value::Null) | Some(Value::String(_)) => {}
            _ => return Err(AuthError::InvalidClaim),
        }
        let signed_iat = numeric_date(&mut claims, "iat")?;
        let signed_exp = numeric_date(&mut claims, "exp")?;
        let signed_nbf = numeric_date(&mut claims, "nbf")?;
        if let Some(maximum) = time.maximum_token_lifetime_seconds {
            // This explicit HeptaBao compatibility extension retains its
            // original issued-to-expiry bound. Inferred dates cannot prove it.
            let issued = signed_iat.ok_or(AuthError::MissingClaim)?;
            let expiry = signed_exp.ok_or(AuthError::MissingClaim)?;
            let lifetime = i128::from(expiry) - i128::from(issued);
            if expiry == 0 || lifetime <= 0 || lifetime > i128::from(maximum) {
                return Err(AuthError::TokenTimeInvalid);
            }
        }
        let issued = i128::from(signed_iat.unwrap_or(0));
        let mut expiry = i128::from(signed_exp.unwrap_or(0));
        let mut not_before = i128::from(signed_nbf.unwrap_or(0));
        if issued == 0 && expiry == 0 && not_before == 0 {
            return Err(AuthError::MissingClaim);
        }
        if expiry == 0 {
            expiry = issued.max(not_before) + missing_claim_leeway(time.expiration_leeway);
        }
        if not_before == 0 {
            not_before = if issued != 0 {
                issued
            } else {
                expiry - missing_claim_leeway(time.not_before_leeway)
            };
        }
        let now = i128::from(now);
        let skew = i128::from(time.clock_skew_seconds);
        let expired = if time.legacy_strict_expiry {
            now >= expiry
        } else {
            now - skew > expiry
        };
        if now + skew < not_before || expired || now + skew < issued {
            return Err(AuthError::TokenTimeInvalid);
        }
        let namespace = take_optional_string(&mut claims, "heptabao_namespace")?;
        let groups = take_string_set(&mut claims, "groups")?;
        if issuer != self.policy.issuer
            || audiences.is_disjoint(&self.policy.audiences)
            || self
                .policy
                .required_namespace
                .as_ref()
                .is_some_and(|required| namespace.as_ref() != Some(required))
        {
            return Err(AuthError::ClaimDenied);
        }
        Ok(NativeJwtIdentity {
            issuer,
            subject,
            audiences,
            namespace,
            groups,
        })
    }
}

#[cfg(test)]
#[path = "federated_native_jwt_tests.rs"]
mod tests;
