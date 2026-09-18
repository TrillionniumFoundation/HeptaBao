//! JWT verification through a deployment-enrolled JWKS or OIDC discovery
//! endpoint. This is discovery-backed JWT login, not browser authorization-code
//! flow. Every login refreshes without stale fallback; a key removed remotely
//! cannot be resurrected by a process restart or an old replicated cache.
use super::*;
use crate::outbound::{Outbound, Target};

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct RemoteJwtSource {
    pub jwks_url: Option<String>,
    pub oidc_discovery_url: Option<String>,
}

pub(crate) struct RemoteJwtLoginPlan {
    namespace: String,
    mount: String,
    method: String,
    body: Zeroizing<Vec<u8>>,
    config: JwtConfig,
    now: u64,
}

pub(crate) struct RemoteJwtLoginObservation {
    keys: BTreeMap<String, JwtKeyRecord>,
}

impl RemoteJwtLoginPlan {
    pub(crate) fn execute(
        &self,
        outbound: &Outbound,
    ) -> Result<RemoteJwtLoginObservation, AuthError> {
        let remote = self
            .config
            .remote
            .as_ref()
            .ok_or_else(|| bad("remote JWT source disappeared"))?;
        Ok(RemoteJwtLoginObservation {
            keys: remote.load(outbound, &self.config.issuer)?,
        })
    }
}

fn same_remote_binding(left: &JwtConfig, right: &JwtConfig) -> bool {
    left.remote == right.remote
        && left.jwt_supported_algs == right.jwt_supported_algs
        && left.issuer == right.issuer
        && left.audiences == right.audiences
        && left.required_namespace == right.required_namespace
        && left.clock_skew_seconds == right.clock_skew_seconds
        && left.maximum_token_lifetime_seconds == right.maximum_token_lifetime_seconds
}
impl RemoteJwtSource {
    pub(super) fn parse(body: &Value) -> Result<Option<Self>, AuthError> {
        let jwks_url = optional(body, "jwks_url")?;
        let oidc_discovery_url = optional(body, "oidc_discovery_url")?;
        if jwks_url.is_none() && oidc_discovery_url.is_none() {
            return Ok(None);
        }
        if jwks_url.is_some() == oidc_discovery_url.is_some()
            || body.get("jwks").is_some()
            || body.get("keys").is_some()
        {
            return Err(bad("exactly one JWT key source is required"));
        }
        for url in [jwks_url.as_deref(), oidc_discovery_url.as_deref()]
            .into_iter()
            .flatten()
        {
            Target::parse(url, "https").map_err(bad)?;
        }
        Ok(Some(Self {
            jwks_url,
            oidc_discovery_url,
        }))
    }
    fn load(
        &self,
        outbound: &Outbound,
        issuer: &str,
    ) -> Result<BTreeMap<String, JwtKeyRecord>, AuthError> {
        let url = if let Some(discovery) = &self.oidc_discovery_url {
            let target = Target::parse(discovery, "https").map_err(bad)?;
            if discovery != issuer {
                return Err(bad(
                    "discovery URL must exactly match the configured issuer",
                ));
            }
            let metadata = outbound
                .get_json(&format!(
                    "{}/.well-known/openid-configuration",
                    discovery.trim_end_matches('/')
                ))
                .map_err(|_| err(503, "OIDC discovery is unavailable or untrusted"))?;
            if metadata.get("issuer").and_then(Value::as_str) != Some(issuer) {
                return Err(bad("OIDC discovery issuer mismatch"));
            }
            let uri = metadata
                .get("jwks_uri")
                .and_then(Value::as_str)
                .ok_or_else(|| bad("OIDC discovery has no JWKS URI"))?;
            let keys = Target::parse(uri, "https").map_err(bad)?;
            // Even another enrolled origin is not silently trusted by discovery.
            if keys.origin != target.origin {
                return Err(bad("cross-origin OIDC JWKS URI is forbidden"));
            }
            uri.to_owned()
        } else {
            self.jwks_url
                .clone()
                .ok_or_else(|| bad("missing JWT key source"))?
        };
        let document = outbound.get_json(&url).map_err(|_| {
            err(
                503,
                "JWKS is unavailable or untrusted; stale fallback forbidden",
            )
        })?;
        parse_jwks(&document)
    }
}
fn optional(body: &Value, name: &str) -> Result<Option<String>, AuthError> {
    body.get(name)
        .map(|v| {
            v.as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| bad("remote JWT URL must be nonempty"))
        })
        .transpose()
}
impl AuthState {
    pub(crate) fn prepare_remote_jwt_login(
        &self,
        namespace: &str,
        path: &str,
        method: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<RemoteJwtLoginPlan>, AuthError> {
        if !matches!(method, "POST" | "PUT") {
            return Ok(None);
        }
        let Some(rest) = path.strip_prefix("auth/") else {
            return Ok(None);
        };
        let Some((mount, route)) = rest.split_once('/') else {
            return Ok(None);
        };
        if route != "login" {
            return Ok(None);
        }
        let scope = AuthScope { namespace, mount };
        let Some(config) = self.jwt_at(scope).and_then(|state| state.config.as_ref()).cloned()
        else {
            return Ok(None);
        };
        if config.remote.is_none() {
            return Ok(None);
        }
        let body = Zeroizing::new(
            serde_json::to_vec(body).map_err(|_| bad("JWT login request encoding failed"))?,
        );
        Ok(Some(RemoteJwtLoginPlan {
            namespace: namespace.into(),
            mount: mount.into(),
            method: method.into(),
            body,
            config,
            now,
        }))
    }

    pub(crate) fn finish_remote_jwt_login(
        &mut self,
        plan: RemoteJwtLoginPlan,
        observation: RemoteJwtLoginObservation,
    ) -> Result<AuthResponse, AuthError> {
        let scope = AuthScope {
            namespace: &plan.namespace,
            mount: &plan.mount,
        };
        let current = self
            .jwt_at(scope)
            .and_then(|state| state.config.as_ref())
            .ok_or_else(|| bad("JWT configuration disappeared during refresh"))?;
        if !same_remote_binding(current, &plan.config) {
            return Err(err(409, "JWT configuration changed during remote key refresh"));
        }
        let current = self
            .jwt_at_mut(scope)
            .config
            .as_mut()
            .ok_or_else(|| bad("JWT configuration disappeared during refresh"))?;
        current.keys = observation.keys;
        let mut validation = current.clone();
        if validation.audiences.is_empty() {
            validation
                .audiences
                .insert("configuration-shape-only".into());
        }
        validation.verifier()?;
        let body: Value = serde_json::from_slice(&plan.body)
            .map_err(|_| bad("JWT login request decoding failed"))?;
        let path = format!("auth/{}/login", plan.mount);
        self.handle(
            None,
            &plan.namespace,
            &plan.method,
            &path,
            &body,
            plan.now,
        )?
        .ok_or_else(|| err(404, "JWT login route disappeared during refresh"))
    }

    pub(crate) fn has_remote_jwt_state(&self) -> bool {
        self.jwt_mounts.values().any(|mounts| {
            mounts.values().any(|s| {
                s.config.as_ref().is_some_and(|c| {
                    c.remote.is_some()
                        || c.jwt_supported_algs.is_some()
                        || c.keys.values().any(|k| k.algorithm == "RS256")
                })
            })
        })
    }
    /// Invoked only within Service, after request audit and before authentication
    /// dispatch. Configuration writes have already passed their sudo checks.
    pub(crate) fn refresh_remote_jwt(
        &mut self,
        namespace: &str,
        path: &str,
        method: &str,
        outbound: &Outbound,
        configuration: bool,
    ) -> Result<(), AuthError> {
        if !matches!(method, "POST" | "PUT") {
            return Ok(());
        }
        let Some(rest) = path.strip_prefix("auth/") else {
            return Ok(());
        };
        let Some((mount, route)) = rest.split_once('/') else {
            return Ok(());
        };
        if route != if configuration { "config" } else { "login" } {
            return Ok(());
        }
        let scope = AuthScope { namespace, mount };
        let Some(config) = self.jwt_at(scope).and_then(|s| s.config.as_ref()).cloned() else {
            return Ok(());
        };
        let Some(remote) = &config.remote else {
            return Ok(());
        };
        let keys = remote.load(outbound, &config.issuer)?;
        let current = self
            .jwt_at_mut(scope)
            .config
            .as_mut()
            .ok_or_else(|| bad("JWT configuration changed"))?;
        current.keys = keys;
        // Validate all key encodings independent of whether a role exists yet.
        let mut validation = current.clone();
        if validation.audiences.is_empty() {
            validation
                .audiences
                .insert("configuration-shape-only".into());
        }
        validation.verifier()?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_sources_are_exclusive_and_never_implicitly_activated() {
        for body in [
            json!({"jwks_url":"https://issuer:443/keys","keys":[]}),
            json!({"jwks_url":"https://issuer:443/keys","oidc_discovery_url":"https://issuer:443"}),
            json!({"jwks_url":"http://issuer:443/keys"}),
            json!({"oidc_discovery_url":"https://issuer:443/../x"}),
        ] {
            assert!(RemoteJwtSource::parse(&body).is_err());
        }
        let source = RemoteJwtSource {
            jwks_url: Some("https://issuer:443/keys".into()),
            oidc_discovery_url: None,
        };
        assert!(
            source
                .load(&Outbound::default(), "https://issuer:443")
                .is_err()
        );
    }
}
