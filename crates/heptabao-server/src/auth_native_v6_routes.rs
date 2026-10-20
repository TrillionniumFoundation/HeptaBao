//! Select only in-process Auth owners for the native V6 writer.
//! Selection is not authentication; the existing domain dispatcher still owns ACLs.
use super::*;

/// Original verified leaf validity only. This is neither certificate login
/// authorization nor a token grant; the real cert handler still owns both.
/// The private bounds are captured once from the request's actual TLS leaf.
pub(crate) struct NativeV6CertLifetime {
    not_before_nanos: i128,
    not_after_nanos: i128,
}

impl NativeV6CertLifetime {
    pub(crate) fn check_at(&self, time: AuthorityTime) -> Result<(), AuthError> {
        const NANOS_PER_SECOND: i128 = 1_000_000_000;
        let observed = match time {
            AuthorityTime::Coarse(seconds) => i128::from(seconds) * NANOS_PER_SECOND,
            AuthorityTime::Precise(at) => {
                i128::from(at.seconds()) * NANOS_PER_SECOND
                    + i128::from(at.duration_since_epoch().subsec_nanos())
            }
        };
        // Match the existing cert_validity validator's inclusive X.509 bounds,
        // including the original subsecond request observation.
        if self.not_before_nanos > self.not_after_nanos
            || observed < self.not_before_nanos
            || observed > self.not_after_nanos
        {
            return Err(denied());
        }
        Ok(())
    }
}

fn presented_leaf_lifetime(
    chain: &[Vec<u8>],
    time: AuthorityTime,
) -> Result<NativeV6CertLifetime, AuthError> {
    // Keep the domain's exact chain bounds and strict leaf parser. This only
    // retains time bounds; the real handler owns TLS/role/token admission.
    parse_presented_certificate(chain, time)?;
    let leaf = chain.first().ok_or_else(denied)?;
    let (remaining, certificate) = parse_x509_certificate(leaf).map_err(|_| denied())?;
    if !remaining.is_empty() {
        return Err(denied());
    }
    let validity = certificate.validity();
    let lifetime = NativeV6CertLifetime {
        not_before_nanos: i128::from(validity.not_before.timestamp()) * 1_000_000_000,
        not_after_nanos: i128::from(validity.not_after.timestamp()) * 1_000_000_000,
    };
    lifetime.check_at(time)?;
    Ok(lifetime)
}

impl AuthState {
    /// Recheck only the original AppRole login credential's lifetime against
    /// the caller's current observation of its original request clock. Call
    /// this on the retained source Auth owner, never the already consumed
    /// candidate. This does not authenticate, decrement uses or issue a token.
    pub(crate) fn validate_native_v6_approle_login_lifetime_observed(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        if !matches!(method, "POST" | "PUT") {
            return Ok(());
        }
        let Some(auth_path) = path.strip_prefix("auth/") else {
            return Ok(());
        };
        let mounts = self.effective_auth_mounts(namespace);
        let Some((mount, _)) = mounts.iter().find(|(mount, entry)| {
            entry.kind == "approle" && auth_path.strip_prefix(&format!("{mount}/")) == Some("login")
        }) else {
            return Ok(());
        };
        let role_id = string_field(body, "role_id")?.trim();
        let secret_id = body.get("secret_id").and_then(Value::as_str).map(str::trim);
        if role_id.len() > 256 || secret_id.is_some_and(|value| value.len() > 256) {
            return Err(bad("invalid role or secret ID"));
        }
        let scope = AuthScope { namespace, mount };
        let role = self
            .roles_at(scope)
            .and_then(|roles| roles.values().find(|role| role.role_id == role_id))
            .ok_or_else(|| bad("invalid role or secret ID"))?;
        if role.bind_secret_id {
            let secret_id = secret_id.ok_or_else(|| bad("invalid role or secret ID"))?;
            let secret = role
                .secret_ids
                .get(&hash(secret_id))
                .ok_or_else(|| bad("invalid role or secret ID"))?;
            let now = self.token_api_observed_time(time).seconds();
            if secret.expires_at.is_some_and(|expiry| now >= expiry)
                || secret.uses_remaining == Some(0)
            {
                return Err(bad("invalid role or secret ID"));
            }
        }
        Ok(())
    }

    /// Capture the presented leaf's original validity for an actual mounted
    /// cert-login route. The caller supplies the existing RequestView's verified
    /// TLS chain; raw HTTP fields are never accepted as a certificate source.
    /// The real cert dispatcher separately verifies role/fingerprint/identity.
    pub(crate) fn capture_native_v6_cert_login_lifetime(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        peer_certificates: Option<&[Vec<u8>]>,
        time: AuthorityTime,
    ) -> Result<Option<NativeV6CertLifetime>, AuthError> {
        if !matches!(method, "POST" | "PUT") {
            return Ok(None);
        }
        let Some(auth_path) = path.strip_prefix("auth/") else {
            return Ok(None);
        };
        if !self
            .effective_auth_mounts(namespace)
            .iter()
            .any(|(mount, entry)| {
                entry.kind == "cert"
                    && auth_path.strip_prefix(&format!("{mount}/")) == Some("login")
            })
        {
            return Ok(None);
        }
        let chain = peer_certificates.ok_or_else(denied)?;
        let time = self.token_api_observed_time(time);
        presented_leaf_lifetime(chain, time).map(Some)
    }

    /// Retain the original verified leaf lifetime only when the actual renewal
    /// target has a direct certificate-login binding. Token-API children keep
    /// their independent renewal authority and require no unrelated TLS leaf.
    /// This must be called on the pre-renewal Auth owner after real dispatch;
    /// it neither renews the target nor consumes another credential use.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture_native_v6_cert_renewal_lifetime(
        &self,
        actor: &Principal,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        peer_certificates: Option<&[Vec<u8>]>,
        time: AuthorityTime,
    ) -> Result<Option<NativeV6CertLifetime>, AuthError> {
        if !matches!(method, "POST" | "PUT") {
            return Ok(None);
        }
        let Some(operation) = path.strip_prefix("auth/token/") else {
            return Ok(None);
        };
        if !matches!(operation, "renew-self" | "renew" | "renew-accessor") {
            return Ok(None);
        }
        let time = self.principal_token_api_time(actor, time)?;
        let id = if operation == "renew-self" {
            actor.require_service("batch tokens cannot be renewed")?;
            actor.digest.clone()
        } else {
            self.target_token_observed(namespace, body, operation == "renew-accessor", time)?
        };
        // Reuse the real renewal contract, including legacy child provenance,
        // live role, exact leaf fingerprint and the no-certificate error class.
        // None is significant: that target has no certificate renewal binding.
        if self
            .cert_renewal_limits(&id, time, peer_certificates)?
            .is_none()
        {
            return Ok(None);
        }
        let chain = peer_certificates.ok_or_else(denied)?;
        presented_leaf_lifetime(chain, time).map(Some)
    }

    pub(crate) fn native_v6_local_auth_route(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> bool {
        if !namespace.is_empty() {
            return false;
        }
        if path == "sys/policy"
            || path.starts_with("sys/policy/")
            || path == "sys/policies/acl"
            || path.starts_with("sys/policies/acl/")
            || path == "sys/quotas/config"
            || path == "sys/quotas/rate-limit"
            || path.starts_with("sys/quotas/rate-limit/")
            || path.starts_with("auth/token/")
        {
            return true;
        }
        let mounts = self.effective_auth_mounts(namespace);
        if let Some(suffix) = path.strip_prefix("sys/auth/") {
            let mount = suffix.strip_suffix("/tune").unwrap_or(suffix);
            return mounts
                .get(mount)
                .is_some_and(|entry| matches!(entry.kind.as_str(), "approle" | "cert"))
                || (matches!(method, "POST" | "PUT")
                    && !suffix.ends_with("/tune")
                    && body
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| matches!(kind, "approle" | "cert")));
        }
        let Some(auth_path) = path.strip_prefix("auth/") else {
            return false;
        };
        mounts.iter().any(|(mount, entry)| {
            let Some(suffix) = auth_path.strip_prefix(&format!("{mount}/")) else {
                return false;
            };
            match entry.kind.as_str() {
                "approle" => suffix == "login" || suffix == "role" || suffix.starts_with("role/"),
                "cert" => {
                    suffix == "login"
                        || suffix == "config"
                        || suffix == "certs"
                        || suffix.starts_with("certs/")
                }
                _ => false,
            }
        })
    }
}
