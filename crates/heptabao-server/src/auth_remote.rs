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
    mount_revision: AuthMount,
    method: String,
    body: StrictJson,
    config: JwtConfig,
    role_name: String,
    role: JwtRole,
    now: u64,
    started: std::time::Instant,
}

pub(crate) struct RemoteJwtConfigPlan {
    namespace: String,
    mount: String,
    mount_revision: AuthMount,
    previous: Option<JwtConfig>,
    proposed: JwtConfig,
    now: u64,
    started: std::time::Instant,
}

impl RemoteJwtConfigPlan {
    pub(crate) fn execute(
        &self,
        outbound: &Outbound,
    ) -> Result<RemoteJwtLoginObservation, AuthError> {
        let remote = self
            .proposed
            .remote
            .as_ref()
            .ok_or_else(|| bad("remote JWT source disappeared"))?;
        Ok(RemoteJwtLoginObservation {
            keys: remote.load(outbound, &self.proposed.issuer)?,
        })
    }

    pub(crate) fn observed_now(&self) -> u64 {
        elapsed_now(self.now, self.started)
    }
}

fn elapsed_now(now: u64, started: std::time::Instant) -> u64 {
    let elapsed = started.elapsed();
    now.saturating_add(
        elapsed
            .as_secs()
            .saturating_add(u64::from(elapsed.subsec_nanos() > 0)),
    )
}

pub(crate) struct RemoteJwtLoginObservation {
    keys: BTreeMap<String, JwtKeyRecord>,
}

#[cfg(test)]
impl RemoteJwtLoginObservation {
    pub(crate) fn from_test_jwks(document: &Value) -> Result<Self, AuthError> {
        Ok(Self {
            keys: parse_jwks(document)?,
        })
    }
}

impl RemoteJwtLoginPlan {
    pub(crate) fn observed_now(&self) -> u64 {
        elapsed_now(self.now, self.started)
    }

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
        let Some((mount, route)) = rest.rsplit_once('/') else {
            return Ok(None);
        };
        if route != "login" {
            return Ok(None);
        }
        let scope = AuthScope { namespace, mount };
        let Some(config) = self
            .jwt_at(scope)
            .and_then(|state| state.config.as_ref())
            .cloned()
        else {
            return Ok(None);
        };
        if config.remote.is_none() {
            return Ok(None);
        }
        reject_unknown(body, &["role", "jwt"])?;
        let role_name = string_field(body, "role")?;
        if !valid_name(role_name) {
            return Err(bad("invalid JWT role name"));
        }
        let role = self
            .jwt_at(scope)
            .and_then(|state| state.roles.get(role_name))
            .cloned()
            .ok_or_else(|| bad("JWT role not found"))?;
        Ok(Some(RemoteJwtLoginPlan {
            namespace: namespace.into(),
            mount: mount.into(),
            mount_revision: self
                .effective_auth_mounts(namespace)
                .get(mount)
                .cloned()
                .ok_or_else(denied)?,
            method: method.into(),
            body: StrictJson(body.clone()),
            config,
            role_name: role_name.to_owned(),
            role,
            now,
            started: std::time::Instant::now(),
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
        if self.effective_auth_mounts(&plan.namespace).get(&plan.mount)
            != Some(&plan.mount_revision)
            || !same_remote_binding(current, &plan.config)
            || self
                .jwt_at(scope)
                .and_then(|state| state.roles.get(&plan.role_name))
                != Some(&plan.role)
        {
            return Err(err(
                409,
                "JWT configuration or role changed during remote key refresh",
            ));
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
        let now = plan.observed_now();
        let path = format!("auth/{}/login", plan.mount);
        self.handle(
            None,
            &plan.namespace,
            &plan.method,
            &path,
            &plan.body.0,
            now,
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
    pub(crate) fn prepare_remote_jwt_config(
        &self,
        principal: Option<&Principal>,
        namespace: &str,
        path: &str,
        method: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<RemoteJwtConfigPlan>, AuthError> {
        if !matches!(method, "POST" | "PUT") {
            return Ok(None);
        }
        let Some((mount, "config")) = path
            .strip_prefix("auth/")
            .and_then(|rest| rest.rsplit_once('/'))
        else {
            return Ok(None);
        };
        let Some(mount_revision) = self
            .effective_auth_mounts(namespace)
            .get(mount)
            .cloned()
            .filter(|entry| entry.kind == "jwt")
        else {
            return Ok(None);
        };
        // Static keys use the ordinary local route. A remote source is admitted
        // only after the same parser and update+sudo checks as that route.
        if body.get("jwks_url").is_none() && body.get("oidc_discovery_url").is_none() {
            return Ok(None);
        }
        let scope = AuthScope { namespace, mount };
        let proposed = self.parse_jwt_config(principal, scope, body, now)?;
        if proposed.remote.is_none() {
            return Ok(None);
        }
        Ok(Some(RemoteJwtConfigPlan {
            namespace: namespace.to_owned(),
            mount: mount.to_owned(),
            mount_revision,
            previous: self.jwt_at(scope).and_then(|state| state.config.clone()),
            proposed,
            now,
            started: std::time::Instant::now(),
        }))
    }

    pub(crate) fn finish_remote_jwt_config(
        &mut self,
        plan: RemoteJwtConfigPlan,
        actor: &Principal,
        observation: RemoteJwtLoginObservation,
    ) -> Result<AuthResponse, AuthError> {
        let scope = AuthScope {
            namespace: &plan.namespace,
            mount: &plan.mount,
        };
        let path = format!("auth/{}/config", plan.mount);
        // The affine actor was admitted once before dispatch. Reauthorization
        // checks revocation, expiry and current ACL without another use debit.
        self.authorize_sudo_request(actor, &plan.namespace, &path, "update", plan.observed_now())?;
        let current = self.jwt_at(scope).and_then(|state| state.config.as_ref());
        let same = match (current, plan.previous.as_ref()) {
            (None, None) => true,
            (Some(left), Some(right)) => {
                same_remote_binding(left, right)
                    && (left.remote.is_some() || left.keys == right.keys)
            }
            _ => false,
        };
        if self.effective_auth_mounts(&plan.namespace).get(&plan.mount)
            != Some(&plan.mount_revision)
            || !same
        {
            return Err(err(409, "JWT configuration changed during preflight"));
        }
        let mut proposed = plan.proposed;
        proposed.keys = observation.keys;
        let mut validation = proposed.clone();
        if validation.audiences.is_empty() {
            validation
                .audiences
                .insert("configuration-shape-only".into());
        }
        validation.verifier()?;
        let mutated = current != Some(&proposed);
        self.jwt_at_mut(scope).config = Some(proposed);
        Ok(empty(mutated))
    }
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn login_fixture() -> (
        AuthState,
        Principal,
        RemoteJwtLoginPlan,
        RemoteJwtLoginObservation,
    ) {
        let (mut state, raw) = AuthState::bootstrap(1000).unwrap();
        let root = state.authenticate(&raw, 1000).unwrap();
        let pair = Ed25519KeyPair::from_seed_unchecked(&[58; 32]).unwrap();
        for (path, body) in [
            ("sys/auth/nested/jwt", json!({"type":"jwt"})),
            (
                "auth/nested/jwt/config",
                json!({"issuer":"https://issuer.example","audiences":["service"],"clock_skew_seconds":0,"keys":[{"kid":"key","algorithm":"EdDSA","key_base64":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())}]}),
            ),
            (
                "auth/nested/jwt/role/app",
                json!({"bound_audiences":["service"],"token_ttl":60,"token_max_ttl":300}),
            ),
        ] {
            state
                .handle(Some(&root), "", "POST", path, &body, 1000)
                .unwrap()
                .unwrap();
        }
        let config = state
            .jwt_at_mut(AuthScope {
                namespace: "",
                mount: "nested/jwt",
            })
            .config
            .as_mut()
            .unwrap();
        config.remote = Some(RemoteJwtSource {
            jwks_url: Some("https://issuer.example/keys".into()),
            oidc_discovery_url: None,
        });
        let observed = RemoteJwtLoginObservation {
            keys: config.keys.clone(),
        };
        let payload = format!("{}.{}", URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"key"}"#), URL_SAFE_NO_PAD.encode(br#"{"iss":"https://issuer.example","sub":"alice","aud":"service","iat":1000,"exp":1010,"jti":"remote-login"}"#));
        let jwt = format!(
            "{payload}.{}",
            URL_SAFE_NO_PAD.encode(pair.sign(payload.as_bytes()).as_ref())
        );
        let plan = state
            .prepare_remote_jwt_login(
                "",
                "auth/nested/jwt/login",
                "POST",
                &json!({"role":"app","jwt":jwt}),
                1000,
            )
            .unwrap()
            .unwrap();
        (state, root, plan, observed)
    }

    #[test]
    fn remote_login_rechecks_expiration_after_fetch_and_marks_native_role() {
        let (mut state, _, mut plan, observed) = login_fixture();
        plan.started = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(11))
            .unwrap();
        let before = state.tokens.len();
        assert_eq!(
            state
                .finish_remote_jwt_login(plan, observed)
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(state.tokens.len(), before);
        let (mut state, _, plan, observed) = login_fixture();
        let response = state.finish_remote_jwt_login(plan, observed).unwrap();
        assert_eq!(response.body["auth"]["lease_duration"], 60);
        let token = &state.tokens[&hash(response.body["auth"]["client_token"].as_str().unwrap())];
        assert!(
            matches!(&token.auth_provenance, Some(TokenAuthProvenance::Jwt{role_name}) if role_name=="app")
        );
    }

    #[test]
    fn remote_login_rejects_same_path_mount_recreation_even_with_identical_trust() {
        let (mut state, root, plan, observed) = login_fixture();
        let scope = AuthScope {
            namespace: "",
            mount: "nested/jwt",
        };
        let config = state.jwt_at(scope).unwrap().clone();
        state
            .handle(
                Some(&root),
                "",
                "DELETE",
                "sys/auth/nested/jwt",
                &json!({}),
                1001,
            )
            .unwrap();
        state
            .handle(
                Some(&root),
                "",
                "POST",
                "sys/auth/nested/jwt",
                &json!({"type":"jwt"}),
                1001,
            )
            .unwrap();
        *state.jwt_at_mut(scope) = config;
        let before = state.tokens.len();
        assert_eq!(
            state
                .finish_remote_jwt_login(plan, observed)
                .err()
                .unwrap()
                .status,
            409
        );
        assert_eq!(state.tokens.len(), before);
    }

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
    #[test]
    fn remote_login_fences_every_role_field_before_key_cache_or_token_mutation() {
        for change in 0..4 {
            let (mut state, _, plan, observed) = login_fixture();
            let role = state
                .jwt_at_mut(AuthScope {
                    namespace: "",
                    mount: "nested/jwt",
                })
                .roles
                .get_mut("app")
                .unwrap();
            match change {
                0 => {
                    role.token_ttl += 1;
                }
                1 => {
                    role.policies.insert("different".into());
                }
                2 => {
                    role.bound_subject = Some("other".into());
                }
                _ => {
                    role.clock_skew_leeway = Some(-1);
                }
            }
            let before = serde_json::to_vec(&state).unwrap();
            assert_eq!(
                state
                    .finish_remote_jwt_login(plan, observed)
                    .err()
                    .unwrap()
                    .status,
                409
            );
            assert_eq!(serde_json::to_vec(&state).unwrap(), before);
        }
    }

    #[test]
    fn remote_config_is_pure_until_observation_and_merges_latest_roles() {
        let (mut state, root, _, observed) = login_fixture();
        let body = json!({"issuer":"https://new.example:443", "jwks_url":"https://new.example:443/keys", "audiences":["service"]});
        let before = serde_json::to_vec(&state).unwrap();
        let plan = state
            .prepare_remote_jwt_config(
                Some(&root),
                "",
                "auth/nested/jwt/config",
                "POST",
                &body,
                1000,
            )
            .unwrap()
            .unwrap();
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
        state
            .jwt_at_mut(AuthScope {
                namespace: "",
                mount: "nested/jwt",
            })
            .roles
            .get_mut("app")
            .unwrap()
            .token_ttl = 61;
        state
            .finish_remote_jwt_config(plan, &root, observed)
            .unwrap();
        let latest = state
            .jwt_at(AuthScope {
                namespace: "",
                mount: "nested/jwt",
            })
            .unwrap();
        assert_eq!(latest.roles["app"].token_ttl, 61);
        assert_eq!(
            latest.config.as_ref().unwrap().issuer,
            "https://new.example:443"
        );
    }

    #[test]
    fn remote_config_rejects_actor_revocation_or_prior_configuration_change() {
        for revoked in [false, true] {
            let (mut state, root, _, observed) = login_fixture();
            let body = json!({"issuer":"https://new.example:443", "jwks_url":"https://new.example:443/keys", "audiences":["service"]});
            let plan = state
                .prepare_remote_jwt_config(
                    Some(&root),
                    "",
                    "auth/nested/jwt/config",
                    "POST",
                    &body,
                    1000,
                )
                .unwrap()
                .unwrap();
            if revoked {
                state.tokens.remove(&root.digest);
            } else {
                state
                    .jwt_at_mut(AuthScope {
                        namespace: "",
                        mount: "nested/jwt",
                    })
                    .config
                    .as_mut()
                    .unwrap()
                    .issuer = "https://concurrent.example:443".into();
            }
            let before = serde_json::to_vec(&state).unwrap();
            assert_eq!(
                state
                    .finish_remote_jwt_config(plan, &root, observed)
                    .err()
                    .unwrap()
                    .status,
                if revoked { 403 } else { 409 }
            );
            assert_eq!(serde_json::to_vec(&state).unwrap(), before);
        }
    }
}
