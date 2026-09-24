//! Authorization-code OIDC with S256 PKCE and a separate client proof. Sessions
//! are encrypted Service state. Service consumes them durably BEFORE exchanging
//! any code. Replay, restart and leader change never retry an uncertain exchange.
use super::*;
use crate::outbound::{
    AuthHttpsTransport, AuthOidcExchange, Outbound, Target, form_component, parse_auth_https_target,
};
const SESSION_TTL: u64 = 300;
const MAX_SESSIONS: usize = 128;
const MAX_ROLES: usize = 256;
const OIDC_CLIENT_SECRET_BASIC: &str = "client_secret_basic";
const OIDC_CLIENT_NONE: &str = "none";

fn default_oidc_client_auth_method() -> String {
    OIDC_CLIENT_SECRET_BASIC.into()
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct OidcMount {
    config: Option<OidcConfig>,
    roles: BTreeMap<String, OidcRole>,
    sessions: BTreeMap<String, Session>,
    clock: u64,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OidcConfig {
    oidc_discovery_url: String,
    oidc_client_id: String,
    oidc_client_secret: String,
    #[serde(default = "default_oidc_client_auth_method")]
    oidc_client_auth_method: String,
    jwt_supported_algs: BTreeSet<String>,
    pkce_s256_enrolled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transport: Option<AuthHttpsTransport>,
}
pub(crate) struct OidcConfigPlan {
    namespace: String,
    mount: String,
    mount_revision: AuthMount,
    previous: Option<OidcConfig>,
    proposed: OidcConfig,
    now: u64,
    started: std::time::Instant,
}

pub(crate) struct OidcConfigObservation;

impl OidcConfigPlan {
    pub(crate) fn execute(
        &self,
        outbound: &Outbound,
        deadline: std::time::Instant,
    ) -> Result<OidcConfigObservation, AuthError> {
        let result = self.proposed.discovery(outbound, deadline);
        if self.proposed.transport.is_some() {
            result.map_err(|_| bad("OIDC discovery configuration check failed"))?;
        } else {
            result?;
        }
        Ok(OidcConfigObservation)
    }
    pub(crate) fn observed_now(&self) -> u64 {
        let elapsed = self.started.elapsed();
        self.now.saturating_add(
            elapsed
                .as_secs()
                .saturating_add(u64::from(elapsed.subsec_nanos() > 0)),
        )
    }
}

impl Drop for OidcConfig {
    fn drop(&mut self) {
        self.oidc_client_secret.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OidcRole {
    allowed_redirect_uris: BTreeSet<String>,
    bound_subject: Option<String>,
    bound_groups: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    required_acr: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    required_amr: BTreeSet<String>,
    token_policies: BTreeSet<String>,
    token_ttl: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    token_max_ttl: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    token_period: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    token_explicit_max_ttl: u64,
    token_num_uses: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    role: String,
    redirect: String,
    client_proof_hash: String,
    nonce: String,
    verifier: String,
    binding: String,
    created_at: u64,
    expires_at: u64,
    token_endpoint: String,
    jwks_uri: String,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.verifier.zeroize();
        self.nonce.zeroize();
        self.client_proof_hash.zeroize();
    }
}
/// One local, non-serializable exchange permit. It exists only after the caller
/// has removed the exact session in its candidate; Service must commit that
/// candidate before calling exchange. Not an application authorization token.
pub(crate) struct OidcExchange {
    mount_revision: AuthMount,
    config: OidcConfig,
    role: OidcRole,
    session: Session,
    code: Zeroizing<String>,
}

pub(crate) struct OidcBeginPlan {
    namespace: String,
    mount: String,
    mount_revision: AuthMount,
    role_name: String,
    redirect_uri: String,
    client_proof_hash: String,
    config: OidcConfig,
    role: OidcRole,
    now: u64,
}

pub(crate) struct OidcBeginObservation {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

pub(crate) struct OidcLoginObservation {
    subject: String,
    acr: Option<String>,
    amr: BTreeSet<String>,
    now: u64,
}

#[cfg(test)]
impl OidcLoginObservation {
    pub(crate) fn observed(subject: &str, now: u64) -> Self {
        Self {
            subject: subject.into(),
            acr: None,
            amr: BTreeSet::new(),
            now,
        }
    }

    #[cfg(test)]
    pub(crate) fn observed_with_context(
        subject: &str,
        acr: Option<&str>,
        amr: BTreeSet<String>,
        now: u64,
    ) -> Self {
        Self {
            subject: subject.into(),
            acr: acr.map(str::to_owned),
            amr,
            now,
        }
    }
}

impl OidcBeginPlan {
    pub(crate) fn execute(
        &self,
        outbound: &Outbound,
        deadline: std::time::Instant,
    ) -> Result<OidcBeginObservation, AuthError> {
        let (authorization_endpoint, token_endpoint, jwks_uri) =
            self.config.metadata(outbound, deadline)?;
        Ok(OidcBeginObservation {
            authorization_endpoint,
            token_endpoint,
            jwks_uri,
        })
    }
}

impl OidcExchange {
    pub(crate) fn execute(
        &self,
        namespace: &str,
        now: u64,
        started: std::time::Instant,
        outbound: &Outbound,
        deadline: std::time::Instant,
    ) -> Result<OidcLoginObservation, AuthError> {
        let mut token_response = outbound
            .exchange_auth_oidc(
                &self.session.token_endpoint,
                AuthOidcExchange {
                    client_id: &self.config.oidc_client_id,
                    client_secret: &self.config.oidc_client_secret,
                    client_auth_method: &self.config.oidc_client_auth_method,
                    code: &self.code,
                    redirect: &self.session.redirect,
                    verifier: &self.session.verifier,
                },
                self.config.transport.as_ref(),
                deadline,
            )
            .map_err(|_| {
                err(
                    503,
                    "OIDC exchange failed; authorization session consumed; start a new login",
                )
            })?;
        let result = (|| {
            let id_token = token_response
                .get("id_token")
                .and_then(Value::as_str)
                .ok_or_else(denied)?;
            let access = token_response
                .get("access_token")
                .and_then(Value::as_str)
                .filter(|s| bounded_string(s, 32 * 1024))
                .ok_or_else(denied)?;
            if !token_response
                .get("token_type")
                .and_then(Value::as_str)
                .is_some_and(|s| s.eq_ignore_ascii_case("Bearer"))
            {
                return Err(denied());
            }
            let keys = outbound
                .get_auth_json(
                    &self.session.jwks_uri,
                    self.config.transport.as_ref(),
                    deadline,
                )
                .map_err(|_| err(503, "OIDC signing keys unavailable; session consumed"))?;
            let config = JwtConfig {
                remote: None,
                jwt_supported_algs: Some(self.config.jwt_supported_algs.clone()),
                issuer: self.config.oidc_discovery_url.clone(),
                audiences: BTreeSet::from([self.config.oidc_client_id.clone()]),
                required_namespace: None,
                clock_skew_seconds: Some(30),
                maximum_token_lifetime_seconds: Some(86400),
                keys: parse_jwks(&keys)?,
            };
            let elapsed = started.elapsed();
            let now = now.saturating_add(
                elapsed
                    .as_secs()
                    .saturating_add(u64::from(elapsed.subsec_nanos() > 0)),
            );
            if now >= self.session.expires_at {
                return Err(denied());
            }
            let verified = config
                .verifier()?
                .verify_oidc(id_token, now, &self.session.nonce, access, &self.code)
                .map_err(|_| denied())?;
            if self
                .role
                .bound_subject
                .as_ref()
                .is_some_and(|v| v != &verified.subject)
                || !self.role.bound_groups.is_subset(&verified.groups)
                || !self
                    .role
                    .accepts_authentication_context(verified.acr.as_deref(), &verified.amr)
                || verified.namespace.as_ref().is_some_and(|v| v != namespace)
            {
                return Err(denied());
            }
            Ok(OidcLoginObservation {
                subject: verified.subject,
                acr: verified.acr,
                amr: verified.amr,
                now,
            })
        })();
        crate::service::erase_json(&mut token_response);
        result
    }
}
fn bounded_string(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn proof(value: &str) -> bool {
    value.len() == 43 && URL_SAFE_NO_PAD.decode(value).is_ok_and(|v| v.len() == 32)
}
fn redirect(value: &str) -> bool {
    if value.starts_with("https://") {
        Target::parse(value, "https").is_ok()
    } else if value.starts_with("http://127.0.0.1:") {
        Target::parse(value, "http").is_ok_and(|v| v.path == "/oidc/callback")
    } else {
        false
    }
}
fn binding(config: &OidcConfig, role: &OidcRole) -> Result<String, AuthError> {
    // Preserve the exact JSON digest, including old roles with absent zero
    // limits, without allocating a serialized copy of the client secret.
    Ok(URL_SAFE_NO_PAD.encode(provider_renewal::state_revision(&(config, role))?))
}
impl OidcConfig {
    fn validate(&self) -> Result<(), AuthError> {
        parse_auth_https_target(&self.oidc_discovery_url, self.transport.as_ref()).map_err(bad)?;
        if let Some(transport) = &self.transport {
            transport
                .validate_configuration(&self.oidc_discovery_url)
                .map_err(bad)?;
        }
        if self.oidc_discovery_url.ends_with('/')
            || !bounded_string(&self.oidc_client_id, 512)
            || (!self.oidc_client_secret.is_empty()
                && !bounded_string(&self.oidc_client_secret, 4096))
            || self.jwt_supported_algs.is_empty()
            || self
                .jwt_supported_algs
                .iter()
                .any(|v| !matches!(v.as_str(), "RS256" | "ES256"))
        {
            return Err(bad(
                "invalid OIDC configuration; RS256/ES256 code flow required",
            ));
        }
        match self.oidc_client_auth_method.as_str() {
            OIDC_CLIENT_SECRET_BASIC if bounded_string(&self.oidc_client_secret, 4096) => {}
            OIDC_CLIENT_NONE if self.oidc_client_secret.is_empty() && self.pkce_s256_enrolled => {}
            OIDC_CLIENT_SECRET_BASIC => {
                return Err(bad("confidential OIDC clients require a client secret"));
            }
            OIDC_CLIENT_NONE => {
                return Err(bad("public OIDC clients require S256 PKCE enrollment"));
            }
            _ => return Err(bad("unsupported OIDC client authentication method")),
        }
        Ok(())
    }
    fn discovery(
        &self,
        outbound: &Outbound,
        deadline: std::time::Instant,
    ) -> Result<Value, AuthError> {
        let doc = outbound
            .get_auth_json(
                &format!(
                    "{}/.well-known/openid-configuration",
                    self.oidc_discovery_url
                ),
                self.transport.as_ref(),
                deadline,
            )
            .map_err(|_| err(503, "OIDC discovery unavailable or untrusted"))?;
        if doc.get("issuer").and_then(Value::as_str) != Some(&self.oidc_discovery_url) {
            return Err(bad("OIDC discovery issuer mismatch"));
        }
        Ok(doc)
    }

    fn metadata(
        &self,
        outbound: &Outbound,
        deadline: std::time::Instant,
    ) -> Result<(String, String, String), AuthError> {
        let original = parse_auth_https_target(&self.oidc_discovery_url, self.transport.as_ref())
            .map_err(bad)?;
        let doc = self.discovery(outbound, deadline)?;
        if doc.get("issuer").and_then(Value::as_str) != Some(&self.oidc_discovery_url)
            || !array_contains(&doc, "response_types_supported", "code")
            || (doc.get("code_challenge_methods_supported").is_some()
                && !array_contains(&doc, "code_challenge_methods_supported", "S256"))
            || (doc.get("code_challenge_methods_supported").is_none() && !self.pkce_s256_enrolled)
            || !array_contains(
                &doc,
                "token_endpoint_auth_methods_supported",
                &self.oidc_client_auth_method,
            )
        {
            return Err(bad(
                "OIDC issuer or mandatory code-flow capabilities mismatch",
            ));
        }
        let endpoint = |field: &str| -> Result<String, AuthError> {
            let value = doc
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| bad("OIDC metadata endpoint missing"))?;
            let target = parse_auth_https_target(value, self.transport.as_ref()).map_err(bad)?;
            if target.origin != original.origin {
                return Err(bad("cross-origin OIDC endpoint forbidden"));
            }
            if self.transport.is_none() {
                outbound
                    .endpoint(value, "https")
                    .map_err(|_| err(503, "OIDC endpoint not host-enrolled"))?;
            }
            Ok(value.into())
        };
        Ok((
            endpoint("authorization_endpoint")?,
            endpoint("token_endpoint")?,
            endpoint("jwks_uri")?,
        ))
    }
}
fn array_contains(v: &Value, field: &str, expected: &str) -> bool {
    v.get(field).and_then(Value::as_array).is_some_and(|vs| {
        vs.len() <= 64
            && vs.iter().all(Value::is_string)
            && vs.iter().any(|v| v.as_str() == Some(expected))
    })
}
impl OidcRole {
    fn validate(&self) -> Result<(), AuthError> {
        if self.allowed_redirect_uris.is_empty()
            || self.allowed_redirect_uris.len() > 16
            || self.allowed_redirect_uris.iter().any(|v| !redirect(v))
            || self
                .bound_subject
                .as_ref()
                .is_some_and(|v| !bounded_string(v, 1024))
            || self.bound_groups.len() > 128
            || self.bound_groups.iter().any(|v| !bounded_string(v, 1024))
            || self
                .required_acr
                .as_ref()
                .is_some_and(|v| !bounded_string(v, 256))
            || self.required_amr.len() > 32
            || self.required_amr.iter().any(|v| !bounded_string(v, 128))
            || self.token_policies.len() > 128
            || self
                .token_policies
                .iter()
                .any(|v| !valid_name(v) || v == "root")
            || self.token_ttl > MAX_TTL
            || self.token_max_ttl > MAX_TTL
            || self.token_period > MAX_TTL
            || self.token_explicit_max_ttl > MAX_TTL
            || self.token_max_ttl > 0 && self.token_ttl > self.token_max_ttl
        {
            return Err(bad("invalid OIDC role bindings"));
        }
        Ok(())
    }
    fn accepts_authentication_context(&self, acr: Option<&str>, amr: &BTreeSet<String>) -> bool {
        self.required_acr
            .as_ref()
            .is_none_or(|required| acr == Some(required.as_str()))
            && self.required_amr.is_subset(amr)
    }
    fn limits(&self) -> NativeTokenLimits {
        NativeTokenLimits {
            ttl: self.token_ttl,
            max_ttl: self.token_max_ttl,
            period: self.token_period,
        }
    }
}

impl AuthState {
    pub(crate) fn has_oidc_renewal_state(&self) -> bool {
        self.tokens.values().any(|token| {
            matches!(
                token.auth_provenance,
                Some(TokenAuthProvenance::Oidc { .. })
            )
        }) || self
            .oidc_mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .flat_map(|mount| mount.roles.values())
            .any(|role| {
                role.token_policies.is_empty()
                    || role.token_ttl == 0
                    || role.token_ttl > 3600
                    || role.token_max_ttl > 0
                    || role.token_period > 0
                    || role.token_explicit_max_ttl > 0
            })
    }

    pub(crate) fn validate_oidc_renewal_state(&self) -> Result<(), AuthError> {
        for token in self.tokens.values() {
            if let Some(TokenAuthProvenance::Oidc { role_name }) = &token.auth_provenance
                && (token.root
                    || token.parent.is_some()
                    || !token.auth_origin_known
                    || token.wrapping.is_some()
                    || !valid_name(role_name)
                    || token.period > MAX_TTL
                    || token.policies.contains("root")
                    || token.auth_cert_role.is_some()
                    || token.auth_cert_sha256.is_some()
                    || !token.auth_mount.as_ref().is_some_and(|mount| {
                        self.online_mount_enabled(&token.namespace, mount, "oidc")
                    }))
            {
                return Err(bad("invalid OIDC renewal provenance"));
            }
        }
        Ok(())
    }

    pub(super) fn renew_oidc_token(
        &mut self,
        namespace: &str,
        target: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<AuthResponse>, AuthError> {
        let token = self.tokens.get(target).ok_or_else(denied)?;
        let Some(TokenAuthProvenance::Oidc { role_name }) = token.auth_provenance.as_ref() else {
            if token.auth_provenance.is_none()
                && token.parent.is_none()
                && token
                    .auth_mount
                    .as_ref()
                    .is_some_and(|mount| self.online_mount_enabled(&token.namespace, mount, "oidc"))
            {
                return Err(bad(
                    "legacy OIDC token has no issuing role provenance; log in again",
                ));
            }
            return Ok(None);
        };
        if token.namespace != namespace || token.parent.is_some() {
            return Err(denied());
        }
        if !token.renewable {
            return Err(bad("token is not renewable"));
        }
        let mount = token.auth_mount.as_deref().ok_or_else(denied)?;
        let scope = AuthScope { namespace, mount };
        if !self.online_mount_enabled(namespace, mount, "oidc") {
            return Err(denied());
        }
        // The authorization code and ID token authenticate login only. Native
        // OIDC service renewal never refreshes the IdP or rechecks role claims,
        // issuer/client configuration, groups or the issued policy snapshot.
        let role = self
            .oidc_at(scope)
            .and_then(|state| state.roles.get(role_name))
            .ok_or_else(|| err(500, "OIDC role does not exist during renewal"))?;
        let expires_at = self.native_token_expiry(
            scope,
            role.limits(),
            token.created_at,
            token.max_expires_at,
            duration(body, "increment", 0)?,
            now,
        )?;
        let token = self.tokens.get_mut(target).ok_or_else(denied)?;
        token.expires_at = Some(expires_at);
        Ok(Some(AuthResponse {
            approle_secret_consumption: None,
            pending_batch: None,
            login_identity: None,
            external_groups: None,
            status: 200,
            mutated: true,
            body: json!({"auth":{"accessor":token.accessor,"policies":token.policies,"token_policies":token.policies,
                "entity_id":token.entity_id.as_deref().unwrap_or(""),"lease_duration":expires_at-now,
                "renewable":true,"token_type":"service"}}),
        }))
    }

    pub(super) fn has_oidc_state(&self) -> bool {
        self.oidc_mounts.values().any(|m| !m.is_empty())
    }
    pub(super) fn validate_oidc_state(&self) -> Result<(), AuthError> {
        for (namespace, mounts) in &self.oidc_mounts {
            validate_namespace(namespace)?;
            for (mount, state) in mounts {
                if !self.online_mount_enabled(namespace, mount, "oidc")
                    || state.roles.len() > MAX_ROLES
                    || state.sessions.len() > MAX_SESSIONS
                {
                    return Err(denied());
                }
                if let Some(config) = &state.config {
                    config.validate()?;
                }
                for (name, role) in &state.roles {
                    if !valid_name(name) {
                        return Err(denied());
                    }
                    role.validate()?;
                }
                for (id, s) in &state.sessions {
                    if !proof(id)
                        || !proof(&s.client_proof_hash)
                        || !proof(&s.nonce)
                        || !proof(&s.verifier)
                        || s.created_at > state.clock
                        || s.created_at.checked_add(SESSION_TTL) != Some(s.expires_at)
                    {
                        return Err(denied());
                    }
                    let config = state.config.as_ref().ok_or_else(denied)?;
                    let role = state.roles.get(&s.role).ok_or_else(denied)?;
                    let origin = parse_auth_https_target(
                        &config.oidc_discovery_url,
                        config.transport.as_ref(),
                    )
                    .map_err(bad)?
                    .origin;
                    if binding(config, role)? != s.binding
                        || !role.allowed_redirect_uris.contains(&s.redirect)
                        || parse_auth_https_target(&s.token_endpoint, config.transport.as_ref())
                            .map_err(bad)?
                            .origin
                            != origin
                        || parse_auth_https_target(&s.jwks_uri, config.transport.as_ref())
                            .map_err(bad)?
                            .origin
                            != origin
                    {
                        return Err(denied());
                    }
                }
            }
        }
        Ok(())
    }
    fn oidc_at(&self, scope: AuthScope<'_>) -> Option<&OidcMount> {
        self.oidc_mounts.get(scope.namespace)?.get(scope.mount)
    }
    fn oidc_mut(&mut self, scope: AuthScope<'_>) -> &mut OidcMount {
        self.oidc_mounts
            .entry(scope.namespace.into())
            .or_default()
            .entry(scope.mount.into())
            .or_default()
    }
    pub(super) fn oidc_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        suffix: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let path = format!("auth/{}/{suffix}", scope.mount);
        let cap = if matches!(method, "GET" | "LIST") {
            if suffix == "role" { "list" } else { "read" }
        } else {
            "update"
        };
        let actor = self.permission(principal, scope.namespace, &path, cap, now)?;
        if !matches!(method, "GET" | "LIST") {
            self.authorize_request(actor, scope.namespace, &path, "sudo", now)?;
        }
        if suffix == "config" {
            return match method {
                "GET" => {
                    reject_unknown(body, &[])?;
                    let c = self
                        .oidc_at(scope)
                        .and_then(|s| s.config.as_ref())
                        .ok_or_else(|| err(404, "OIDC configuration missing"))?;
                    Ok(response(
                        json!({"oidc_discovery_url":c.oidc_discovery_url,"oidc_client_id":c.oidc_client_id,
                        "oidc_client_secret_set":!c.oidc_client_secret.is_empty(),
                        "oidc_client_auth_method":c.oidc_client_auth_method,
                        "jwt_supported_algs":c.jwt_supported_algs,"pkce_s256_enrolled":c.pkce_s256_enrolled,
                        "oidc_discovery_ca_pem":c.transport.as_ref().map_or("",|transport|transport.certificate.as_str())}),
                        false,
                    ))
                }
                "POST" | "PUT" => {
                    let config = self.parse_oidc_config(scope, body)?;
                    let state = self.oidc_mut(scope);
                    state.config = Some(config);
                    state.sessions.clear();
                    Ok(empty(true))
                }
                _ => Err(err(405, "disable auth mount to remove OIDC binding")),
            };
        }
        if suffix == "role" && matches!(method, "GET" | "LIST") {
            reject_unknown(body, &[])?;
            let keys: Vec<_> = self
                .oidc_at(scope)
                .map(|s| s.roles.keys().cloned().collect())
                .unwrap_or_default();
            return Ok(response(json!({"keys":keys}), false));
        }
        let name = suffix
            .strip_prefix("role/")
            .filter(|s| valid_name(s))
            .ok_or_else(|| err(404, "unsupported OIDC route"))?;
        match method {
            "GET" => {
                reject_unknown(body, &[])?;
                let role = self
                    .oidc_at(scope)
                    .and_then(|s| s.roles.get(name))
                    .ok_or_else(|| err(404, "OIDC role missing"))?;
                let mut data = serde_json::to_value(role).map_err(|_| bad("invalid OIDC role"))?;
                data["role_type"] = json!("oidc");
                data["user_claim"] = json!("sub");
                data["required_acr"] = role
                    .required_acr
                    .as_ref()
                    .map_or(Value::Null, |value| json!(value));
                data["required_amr"] = json!(role.required_amr);
                data["token_max_ttl"] = json!(role.token_max_ttl);
                data["token_period"] = json!(role.token_period);
                data["token_explicit_max_ttl"] = json!(role.token_explicit_max_ttl);
                Ok(response(data, false))
            }
            "POST" | "PUT" => {
                reject_unknown(
                    body,
                    &[
                        "role_type",
                        "user_claim",
                        "allowed_redirect_uris",
                        "bound_subject",
                        "bound_groups",
                        "required_acr",
                        "required_amr",
                        "token_policies",
                        "token_ttl",
                        "token_max_ttl",
                        "token_period",
                        "token_explicit_max_ttl",
                        "token_num_uses",
                    ],
                )?;
                if body
                    .get("role_type")
                    .is_some_and(|v| v.as_str() != Some("oidc"))
                    || body
                        .get("user_claim")
                        .is_some_and(|v| v.as_str() != Some("sub"))
                {
                    return Err(bad("OIDC sub-based code flow required"));
                }
                let mut role = self
                    .oidc_at(scope)
                    .and_then(|state| state.roles.get(name))
                    .cloned()
                    .unwrap_or(OidcRole {
                        allowed_redirect_uris: BTreeSet::new(),
                        bound_subject: None,
                        bound_groups: BTreeSet::new(),
                        required_acr: None,
                        required_amr: BTreeSet::new(),
                        token_policies: BTreeSet::new(),
                        token_ttl: 0,
                        token_max_ttl: 0,
                        token_period: 0,
                        token_explicit_max_ttl: 0,
                        token_num_uses: 0,
                    });
                if let Some(value) = body.get("allowed_redirect_uris").filter(|v| !v.is_null()) {
                    let redirects = value
                        .as_array()
                        .ok_or_else(|| bad("redirect URI array required"))?;
                    if redirects.len() > 16 {
                        return Err(bad("too many redirect URIs"));
                    }
                    let values: BTreeSet<_> = redirects
                        .iter()
                        .map(|v| {
                            v.as_str()
                                .map(str::to_owned)
                                .ok_or_else(|| bad("redirect URI must be string"))
                        })
                        .collect::<Result<_, _>>()?;
                    if values.len() != redirects.len() {
                        return Err(bad("duplicate redirect URI"));
                    }
                    role.allowed_redirect_uris = values;
                }
                if let Some(value) = body.get("bound_subject").filter(|v| !v.is_null()) {
                    let subject = value
                        .as_str()
                        .ok_or_else(|| bad("invalid subject binding"))?;
                    role.bound_subject = if subject.is_empty() {
                        None
                    } else {
                        Some(subject.into())
                    };
                }
                if body.get("bound_groups").is_some_and(|v| !v.is_null()) {
                    role.bound_groups = claim_values(body, "bound_groups")?;
                }
                if let Some(value) = body.get("required_acr") {
                    role.required_acr = if value.is_null() {
                        None
                    } else {
                        Some(
                            value
                                .as_str()
                                .ok_or_else(|| bad("required_acr must be a string"))?
                                .to_owned(),
                        )
                    };
                }
                if body.get("required_amr").is_some_and(|v| !v.is_null()) {
                    role.required_amr = claim_values(body, "required_amr")?;
                } else if body.get("required_amr").is_some() {
                    role.required_amr.clear();
                }
                if body.get("token_policies").is_some_and(|v| !v.is_null()) {
                    role.token_policies =
                        policies(body, "token_policies", &role.token_policies, false)?;
                }
                for (field, target) in [
                    ("token_ttl", &mut role.token_ttl),
                    ("token_max_ttl", &mut role.token_max_ttl),
                    ("token_period", &mut role.token_period),
                    ("token_explicit_max_ttl", &mut role.token_explicit_max_ttl),
                ] {
                    if body.get(field).is_some_and(|v| !v.is_null()) {
                        *target = duration(body, field, *target)?;
                    }
                }
                if body.get("token_num_uses").is_some_and(|v| !v.is_null()) {
                    role.token_num_uses = number(body, "token_num_uses", role.token_num_uses)?;
                }
                role.validate()?;
                self.validate_assignment(actor, &role.token_policies)?;
                let state = self.oidc_mut(scope);
                if state.roles.len() >= MAX_ROLES && !state.roles.contains_key(name) {
                    return Err(err(507, "OIDC role capacity reached"));
                }
                state.sessions.retain(|_, s| s.role != name);
                state.roles.insert(name.into(), role);
                Ok(empty(true))
            }
            "DELETE" => {
                reject_unknown(body, &[])?;
                let state = self.oidc_mut(scope);
                state.sessions.retain(|_, s| s.role != name);
                Ok(empty(state.roles.remove(name).is_some()))
            }
            _ => Err(err(405, "method not allowed")),
        }
    }
    fn parse_oidc_config(
        &self,
        scope: AuthScope<'_>,
        body: &Value,
    ) -> Result<OidcConfig, AuthError> {
        reject_unknown(
            body,
            &[
                "oidc_discovery_url",
                "oidc_discovery_ca_pem",
                "oidc_client_id",
                "oidc_client_secret",
                "oidc_client_auth_method",
                "jwt_supported_algs",
                "pkce_s256_enrolled",
            ],
        )?;
        let previous = self.oidc_at(scope).and_then(|state| state.config.as_ref());
        let client_auth_method = body
            .get("oidc_client_auth_method")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| bad("OIDC client authentication method must be a string"))
            })
            .transpose()?
            .unwrap_or(OIDC_CLIENT_SECRET_BASIC)
            .to_owned();
        let client_secret = body
            .get("oidc_client_secret")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| bad("OIDC client secret must be a string"))
            })
            .transpose()?
            .unwrap_or("");
        let config = OidcConfig {
            transport: remote::parse_https_transport(
                body,
                "oidc_discovery_ca_pem",
                previous.and_then(|config| config.transport.as_ref()),
                previous.is_some(),
            )?,
            pkce_s256_enrolled: body
                .get("pkce_s256_enrolled")
                .map(|v| {
                    v.as_bool()
                        .ok_or_else(|| bad("PKCE enrollment must be boolean"))
                })
                .transpose()?
                .unwrap_or(false),
            oidc_discovery_url: string_field(body, "oidc_discovery_url")?.into(),
            oidc_client_id: string_field(body, "oidc_client_id")?.into(),
            oidc_client_secret: client_secret.into(),
            oidc_client_auth_method: client_auth_method,
            jwt_supported_algs: if body.get("jwt_supported_algs").is_some() {
                claim_values(body, "jwt_supported_algs")?
            } else {
                BTreeSet::from(["RS256".into()])
            },
        };
        config.validate()?;
        // A new issuer/client requires a new accessor, preventing
        // an equal subject in another realm inheriting old policies.
        if self
            .oidc_at(scope)
            .and_then(|s| s.config.as_ref())
            .is_some_and(|old| {
                old.oidc_discovery_url != config.oidc_discovery_url
                    || old.oidc_client_id != config.oidc_client_id
            })
        {
            return Err(err(
                409,
                "changing OIDC issuer or client requires a new auth mount",
            ));
        }
        Ok(config)
    }

    pub(crate) fn prepare_oidc_config(
        &self,
        principal: Option<&Principal>,
        namespace: &str,
        path: &str,
        method: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<OidcConfigPlan>, AuthError> {
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
            .filter(|entry| entry.kind == "oidc")
        else {
            return Ok(None);
        };
        let actor = self.permission(principal, namespace, path, "update", now)?;
        self.authorize_request(actor, namespace, path, "sudo", now)?;
        let scope = AuthScope { namespace, mount };
        let proposed = self.parse_oidc_config(scope, body)?;
        Ok(Some(OidcConfigPlan {
            namespace: namespace.into(),
            mount: mount.into(),
            mount_revision,
            previous: self.oidc_at(scope).and_then(|state| state.config.clone()),
            proposed,
            now,
            started: std::time::Instant::now(),
        }))
    }

    pub(crate) fn finish_oidc_config(
        &mut self,
        plan: OidcConfigPlan,
        actor: &Principal,
        _observation: OidcConfigObservation,
    ) -> Result<AuthResponse, AuthError> {
        let path = format!("auth/{}/config", plan.mount);
        self.authorize_sudo_request(actor, &plan.namespace, &path, "update", plan.observed_now())?;
        let scope = AuthScope {
            namespace: &plan.namespace,
            mount: &plan.mount,
        };
        if self.effective_auth_mounts(&plan.namespace).get(&plan.mount)
            != Some(&plan.mount_revision)
            || self.oidc_at(scope).and_then(|state| state.config.as_ref()) != plan.previous.as_ref()
        {
            return Err(err(409, "OIDC configuration changed during preflight"));
        }
        let state = self.oidc_mut(scope);
        let mutated = state.config.as_ref() != Some(&plan.proposed) || !state.sessions.is_empty();
        state.config = Some(plan.proposed);
        state.sessions.clear();
        Ok(empty(mutated))
    }

    pub(crate) fn has_oidc_api_https_state(&self) -> bool {
        self.oidc_mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .any(|mount| {
                mount
                    .config
                    .as_ref()
                    .is_some_and(|config| config.transport.is_some())
            })
    }

    pub(crate) fn check_oidc_enrollment(
        &self,
        namespace: &str,
        path: &str,
        outbound: &Outbound,
    ) -> Result<(), AuthError> {
        let Some((kind, mount, suffix)) = self.online_mount_route(namespace, path) else {
            return Ok(());
        };
        if kind == "oidc"
            && suffix == "config"
            && let Some(c) = self
                .oidc_at(AuthScope {
                    namespace,
                    mount: &mount,
                })
                .and_then(|s| s.config.as_ref())
        {
            c.validate()?;
            if c.transport.is_none() {
                outbound
                    .endpoint(&c.oidc_discovery_url, "https")
                    .map_err(|_| err(503, "OIDC endpoint not host-enrolled"))?;
            }
        }
        Ok(())
    }
    pub(crate) fn prepare_oidc_begin(
        &self,
        namespace: &str,
        mount: &str,
        body: &Value,
        now: u64,
    ) -> Result<OidcBeginPlan, AuthError> {
        reject_unknown(body, &["role", "redirect_uri", "client_nonce"])?;
        let role_name = string_field(body, "role")?;
        let redirect_uri = string_field(body, "redirect_uri")?;
        let client_nonce = string_field(body, "client_nonce")?;
        if !valid_name(role_name) || !proof(client_nonce) {
            return Err(bad("invalid OIDC role or client proof"));
        }
        if !self.online_mount_enabled(namespace, mount, "oidc") {
            return Err(denied());
        }
        let scope = AuthScope { namespace, mount };
        let state = self.oidc_at(scope).ok_or_else(denied)?;
        if now < state.clock {
            return Err(denied());
        }
        let config = state
            .config
            .as_ref()
            .cloned()
            .ok_or_else(|| err(503, "OIDC not configured"))?;
        let role = state.roles.get(role_name).cloned().ok_or_else(denied)?;
        if !role.allowed_redirect_uris.contains(redirect_uri) {
            return Err(denied());
        }
        if state
            .sessions
            .values()
            .filter(|s| s.expires_at > now)
            .count()
            >= MAX_SESSIONS
        {
            return Err(err(429, "OIDC session capacity reached"));
        }
        Ok(OidcBeginPlan {
            namespace: namespace.into(),
            mount: mount.into(),
            mount_revision: self
                .effective_auth_mounts(namespace)
                .get(mount)
                .cloned()
                .ok_or_else(denied)?,
            role_name: role_name.into(),
            redirect_uri: redirect_uri.into(),
            client_proof_hash: hash(client_nonce),
            config,
            role,
            now,
        })
    }

    pub(crate) fn finish_oidc_begin(
        &mut self,
        plan: OidcBeginPlan,
        observation: OidcBeginObservation,
    ) -> Result<AuthResponse, AuthError> {
        if self.effective_auth_mounts(&plan.namespace).get(&plan.mount)
            != Some(&plan.mount_revision)
        {
            return Err(err(409, "OIDC auth mount changed during discovery"));
        }
        let scope = AuthScope {
            namespace: &plan.namespace,
            mount: &plan.mount,
        };
        let current = self.oidc_at(scope).ok_or_else(denied)?;
        if current.config.as_ref() != Some(&plan.config)
            || current.roles.get(&plan.role_name) != Some(&plan.role)
        {
            return Err(err(409, "OIDC configuration changed during discovery"));
        }
        if plan.now < current.clock
            || current
                .sessions
                .values()
                .filter(|s| s.expires_at > plan.now)
                .count()
                >= MAX_SESSIONS
        {
            return Err(err(409, "OIDC session state changed during discovery"));
        }
        let state_id = random_id("")?;
        let nonce = random_id("")?;
        let verifier = random_id("")?;
        let challenge = hash(&verifier);
        let auth_url = format!(
            "{}?response_type=code&scope=openid&client_id={}&redirect_uri={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            observation.authorization_endpoint,
            form_component(&plan.config.oidc_client_id),
            form_component(&plan.redirect_uri),
            form_component(&state_id),
            form_component(&nonce),
            challenge
        );
        let session = Session {
            role: plan.role_name,
            redirect: plan.redirect_uri,
            client_proof_hash: plan.client_proof_hash,
            nonce,
            verifier,
            binding: binding(&plan.config, &plan.role)?,
            created_at: plan.now,
            expires_at: checked_expiry(plan.now, SESSION_TTL)?,
            token_endpoint: observation.token_endpoint,
            jwks_uri: observation.jwks_uri,
        };
        let state = self.oidc_mut(scope);
        state.clock = plan.now;
        state.sessions.retain(|_, s| s.expires_at > plan.now);
        state.sessions.insert(hash(&state_id), session);
        Ok(response(json!({"auth_url":auth_url}), true))
    }

    pub(crate) fn consume_oidc(
        &mut self,
        namespace: &str,
        mount: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<OidcExchange>, AuthError> {
        reject_unknown(body, &["state", "code", "client_nonce"])?;
        let state_id = string_field(body, "state")?;
        let code = string_field(body, "code")?;
        let client_proof = string_field(body, "client_nonce")?;
        if !proof(state_id) || !proof(client_proof) || !bounded_string(code, 4096) {
            return Err(bad("invalid OIDC callback"));
        }
        if !self.online_mount_enabled(namespace, mount, "oidc") {
            return Err(denied());
        }
        let mount_revision = self
            .effective_auth_mounts(namespace)
            .get(mount)
            .cloned()
            .ok_or_else(denied)?;
        let scope = AuthScope { namespace, mount };
        let state = self.oidc_at(scope).ok_or_else(denied)?;
        let session = state
            .sessions
            .get(&hash(state_id))
            .cloned()
            .ok_or_else(denied)?;
        if now < state.clock
            || now < session.created_at
            || hash(client_proof) != session.client_proof_hash
        {
            return Err(denied());
        }
        if now >= session.expires_at {
            // A valid client proof observing expiry permanently consumes the
            // session. Service commits this denial, so a later wall-clock
            // rollback cannot revive a capability observed to be expired.
            let state = self.oidc_mut(scope);
            state.clock = now;
            state.sessions.remove(&hash(state_id));
            return Ok(None);
        }
        let config = state.config.as_ref().cloned().ok_or_else(denied)?;
        let role = state.roles.get(&session.role).cloned().ok_or_else(denied)?;
        if binding(&config, &role)? != session.binding
            || !role.allowed_redirect_uris.contains(&session.redirect)
        {
            return Err(denied());
        }
        let state = self.oidc_mut(scope);
        state.clock = now;
        state.sessions.remove(&hash(state_id));
        Ok(Some(OidcExchange {
            mount_revision,
            config,
            role,
            session,
            code: Zeroizing::new(code.into()),
        }))
    }
    pub(crate) fn finish_oidc_observation(
        &mut self,
        namespace: &str,
        mount: &str,
        exchange: OidcExchange,
        observation: OidcLoginObservation,
    ) -> Result<AuthResponse, AuthError> {
        if self.effective_auth_mounts(namespace).get(mount) != Some(&exchange.mount_revision) {
            return Err(err(
                409,
                "OIDC auth mount changed after authorization session consumption",
            ));
        }
        let current = self
            .oidc_at(AuthScope { namespace, mount })
            .ok_or_else(denied)?;
        if current.config.as_ref() != Some(&exchange.config)
            || current.roles.get(&exchange.session.role) != Some(&exchange.role)
            || binding(&exchange.config, &exchange.role)? != exchange.session.binding
        {
            return Err(err(
                409,
                "OIDC configuration changed after authorization session consumption",
            ));
        }
        if !exchange
            .role
            .accepts_authentication_context(observation.acr.as_deref(), &observation.amr)
        {
            return Err(denied());
        }
        let limits = exchange.role.limits();
        // Role readback preserves only configured policies. Old stored roles
        // may already contain default; leaving them unchanged also preserves
        // pending-session bindings. Add the implicit policy only at issuance.
        let mut policies = exchange.role.token_policies;
        policies.insert("default".into());
        self.issue_native_online_token(
            AuthScope { namespace, mount },
            &observation.subject,
            NativeOnlineToken {
                bound_cidrs: Vec::new(),
                policies,
                limits,
                explicit_max_ttl: exchange.role.token_explicit_max_ttl,
                uses: exchange.role.token_num_uses,
                provenance: TokenAuthProvenance::Oidc {
                    role_name: exchange.session.role.clone(),
                },
            },
            observation.now,
        )
    }
}

#[cfg(test)]
impl AuthState {
    pub(crate) fn oidc_test_fixture() -> (Self, String, Value) {
        tests::setup()
    }
}

#[cfg(test)]
#[path = "auth_oidc_renewal_tests.rs"]
mod renewal_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn public_oidc_clients_require_pkce_and_do_not_accept_a_secret() {
        let mut config = OidcConfig {
            transport: None,
            oidc_discovery_url: "https://issuer.example:443/realm".into(),
            oidc_client_id: "public-client".into(),
            oidc_client_secret: String::new(),
            oidc_client_auth_method: OIDC_CLIENT_NONE.into(),
            jwt_supported_algs: BTreeSet::from(["RS256".into()]),
            pkce_s256_enrolled: false,
        };
        assert!(config.validate().is_err());
        config.pkce_s256_enrolled = true;
        assert!(config.validate().is_ok());
        config.oidc_client_secret = "unexpected-secret".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn old_oidc_state_defaults_to_confidential_client_authentication() {
        let value = json!({
            "oidc_discovery_url": "https://issuer.example:443/realm",
            "oidc_client_id": "client",
            "oidc_client_secret": "secret",
            "jwt_supported_algs": ["RS256"],
            "pkce_s256_enrolled": false
        });
        let config: OidcConfig = serde_json::from_value(value).unwrap();
        assert_eq!(config.oidc_client_auth_method, OIDC_CLIENT_SECRET_BASIC);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn public_oidc_configuration_is_runtime_persisted_and_secret_redacted() {
        let (mut state, raw, _) = setup();
        let actor = state.authenticate(&raw, 100).unwrap();
        state
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/browser/config",
                &json!({
                    "oidc_discovery_url": "https://issuer.example:443/realm",
                    "oidc_client_id": "client",
                    "oidc_client_auth_method": "none",
                    "pkce_s256_enrolled": true
                }),
                101,
            )
            .unwrap()
            .unwrap();
        let response = state
            .handle(
                Some(&actor),
                "",
                "GET",
                "auth/browser/config",
                &json!({}),
                101,
            )
            .unwrap()
            .unwrap();
        assert_eq!(response.body["data"]["oidc_client_auth_method"], "none");
        assert_eq!(response.body["data"]["oidc_client_secret_set"], false);
        assert!(response.body["data"].get("oidc_client_secret").is_none());
    }

    #[test]
    fn oidc_role_authentication_context_requires_provider_mfa_claims() {
        let mut role = OidcRole {
            allowed_redirect_uris: BTreeSet::from(["http://127.0.0.1:8259/oidc/callback".into()]),
            bound_subject: None,
            bound_groups: BTreeSet::new(),
            required_acr: Some("urn:example:loa:2".into()),
            required_amr: BTreeSet::from(["pwd".into(), "otp".into()]),
            token_policies: BTreeSet::from(["default".into()]),
            token_ttl: 300,
            token_max_ttl: 0,
            token_period: 0,
            token_explicit_max_ttl: 0,
            token_num_uses: 0,
        };
        assert!(role.validate().is_ok());
        let amr = BTreeSet::from(["pwd".into(), "otp".into(), "webauthn".into()]);
        assert!(role.accepts_authentication_context(Some("urn:example:loa:2"), &amr));
        role.required_amr.insert("hwk".into());
        assert!(!role.accepts_authentication_context(Some("urn:example:loa:2"), &amr));
        role.required_amr.remove("hwk");
        role.required_acr = Some("urn:example:loa:3".into());
        assert!(!role.accepts_authentication_context(Some("urn:example:loa:2"), &amr));
    }

    #[test]
    fn oidc_role_authentication_context_is_persisted_and_rejects_bad_shapes() {
        let (mut state, raw, _) = setup();
        let actor = state.authenticate(&raw, 100).unwrap();
        state
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/browser/role/app",
                &json!({
                    "required_acr": "urn:example:loa:2",
                    "required_amr": ["pwd", "otp"]
                }),
                101,
            )
            .unwrap()
            .unwrap();
        let response = state
            .handle(
                Some(&actor),
                "",
                "GET",
                "auth/browser/role/app",
                &json!({}),
                101,
            )
            .unwrap()
            .unwrap();
        assert_eq!(response.body["data"]["required_acr"], "urn:example:loa:2");
        assert_eq!(response.body["data"]["required_amr"], json!(["otp", "pwd"]));
        let before = serde_json::to_vec(&state).unwrap();
        assert!(
            state
                .handle(
                    Some(&actor),
                    "",
                    "POST",
                    "auth/browser/role/app",
                    &json!({"required_amr": ["otp", 7]}),
                    101,
                )
                .is_err()
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    }

    pub(super) fn setup() -> (AuthState, String, Value) {
        let (mut state, root) = AuthState::bootstrap(100).unwrap();
        let actor = state.authenticate(&root, 100).unwrap();
        state
            .handle(
                Some(&actor),
                "",
                "POST",
                "sys/auth/browser",
                &json!({"type":"oidc"}),
                100,
            )
            .unwrap()
            .unwrap();
        let config = OidcConfig {
            transport: None,
            oidc_discovery_url: "https://issuer.example:443/realm".into(),
            oidc_client_id: "client".into(),
            oidc_client_secret: "private-client-secret".into(),
            oidc_client_auth_method: OIDC_CLIENT_SECRET_BASIC.into(),
            jwt_supported_algs: BTreeSet::from(["RS256".into()]),
            pkce_s256_enrolled: false,
        };
        let role = OidcRole {
            allowed_redirect_uris: BTreeSet::from(["http://127.0.0.1:8259/oidc/callback".into()]),
            bound_subject: None,
            bound_groups: BTreeSet::new(),
            required_acr: None,
            required_amr: BTreeSet::new(),
            token_policies: BTreeSet::from(["default".into()]),
            token_ttl: 300,
            token_max_ttl: 0,
            token_period: 0,
            token_explicit_max_ttl: 0,
            token_num_uses: 0,
        };
        let state_id = random_id("").unwrap();
        let client_proof = random_id("").unwrap();
        let session = Session {
            role: "app".into(),
            redirect: role.allowed_redirect_uris.iter().next().unwrap().clone(),
            client_proof_hash: hash(&client_proof),
            nonce: random_id("").unwrap(),
            verifier: random_id("").unwrap(),
            binding: binding(&config, &role).unwrap(),
            created_at: 100,
            expires_at: 400,
            token_endpoint: "https://issuer.example:443/realm/token".into(),
            jwks_uri: "https://issuer.example:443/realm/keys".into(),
        };
        let entry = state.oidc_mut(AuthScope {
            namespace: "",
            mount: "browser",
        });
        entry.config = Some(config);
        entry.roles.insert("app".into(), role);
        entry.clock = 100;
        entry.sessions.insert(hash(&state_id), session);
        (
            state,
            root,
            json!({"state":state_id,"code":"one-use-code","client_nonce":client_proof}),
        )
    }
    #[test]
    fn oidc_client_proof_and_namespace_cannot_consume_another_session() {
        let (mut state, _, body) = setup();
        let before = serde_json::to_vec(&state).unwrap();
        let mut wrong = body.clone();
        wrong["client_nonce"] = json!(random_id("").unwrap());
        assert!(state.consume_oidc("", "browser", &wrong, 110).is_err());
        assert!(state.consume_oidc("other", "browser", &body, 110).is_err());
        assert!(
            state
                .consume_oidc("", "browser-prefix", &body, 110)
                .is_err()
        );
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
        assert!(
            state
                .consume_oidc("", "browser", &body, 110)
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn oidc_session_consumption_survives_serialization_and_never_replays() {
        let (state, _, body) = setup();
        state.validate_online_auth().unwrap();
        let mut reopened: AuthState =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        let exchange = reopened
            .consume_oidc("", "browser", &body, 110)
            .unwrap()
            .unwrap();
        assert!(proof(&exchange.session.verifier));
        let mut reopened: AuthState =
            serde_json::from_slice(&serde_json::to_vec(&reopened).unwrap()).unwrap();
        assert!(reopened.consume_oidc("", "browser", &body, 111).is_err());
        assert!(reopened.consume_oidc("", "browser", &body, 109).is_err());
    }
    #[test]
    fn oidc_observed_expiry_must_be_committed_and_cannot_revive_after_clock_rollback() {
        let (mut state, _, body) = setup();
        assert!(
            state
                .consume_oidc("", "browser", &body, 400)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            state
                .oidc_at(AuthScope {
                    namespace: "",
                    mount: "browser"
                })
                .unwrap()
                .clock,
            400
        );
        let mut reopened: AuthState =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(reopened.consume_oidc("", "browser", &body, 300).is_err());
    }
    #[test]
    fn oidc_role_updates_invalidate_pending_sessions_and_realm_change_requires_remount() {
        let (mut state, root, body) = setup();
        let actor = state.authenticate(&root, 110).unwrap();
        let result = state.handle(
            Some(&actor),
            "",
            "POST",
            "auth/browser/config",
            &json!({
            "oidc_discovery_url":"https://another.example:443/realm","oidc_client_id":"client",
            "oidc_client_secret":"new-secret"}),
            110,
        );
        assert_eq!(result.err().unwrap().status, 409);
        assert!(
            state
                .consume_oidc("", "browser", &body, 110)
                .unwrap()
                .is_some()
        );
        let (mut state, root, body) = setup();
        let actor = state.authenticate(&root, 110).unwrap();
        state.handle(Some(&actor),"","POST","auth/browser/role/app",&json!({
            "allowed_redirect_uris":["http://127.0.0.1:8259/oidc/callback"],"token_policies":["default"]}),110).unwrap().unwrap();
        assert!(state.consume_oidc("", "browser", &body, 111).is_err());
    }
    #[test]
    fn oidc_persisted_binding_tampering_and_unknown_fields_fail_closed() {
        let (state, _, _) = setup();
        let value = serde_json::to_value(&state).unwrap();
        let id = state
            .oidc_at(AuthScope {
                namespace: "",
                mount: "browser",
            })
            .unwrap()
            .sessions
            .keys()
            .next()
            .unwrap();
        for (field, replacement) in [
            ("binding", json!(hash("wrong"))),
            ("expires_at", json!(401)),
            ("verifier", json!("too-short")),
            ("token_endpoint", json!("https://other.example:443/token")),
            ("redirect", json!("http://127.0.0.1:8259/other")),
        ] {
            let mut altered = value.clone();
            altered["oidc_mounts"][""]["browser"]["sessions"][id][field] = replacement;
            let altered: AuthState = serde_json::from_value(altered).unwrap();
            assert!(altered.validate_online_auth().is_err(), "{field}");
        }
        let mut altered = value;
        altered["oidc_mounts"][""]["browser"]["config"]["tls_skip_verify"] = json!(true);
        assert!(serde_json::from_value::<AuthState>(altered).is_err());
    }
    #[test]
    fn oidc_redirects_and_security_parameters_are_closed() {
        assert!(redirect("http://127.0.0.1:8259/oidc/callback"));
        assert!(redirect("https://client.example:443/callback"));
        for bad in [
            "http://localhost:8259/oidc/callback",
            "http://127.0.0.1:8259/other",
            "https://client.example:443/callback?next=elsewhere",
            "https://user@client.example:443/callback",
            "https://client.example:443/a/../callback",
            "https://client.example:443/%2Fcallback",
        ] {
            assert!(!redirect(bad), "{bad}");
        }
        let (mut state, _, mut body) = setup();
        body["redirect_uri"] = json!("https://other.example:443/callback");
        assert!(state.consume_oidc("", "browser", &body, 110).is_err());
    }
    fn config_body() -> Value {
        json!({"oidc_discovery_url":"https://issuer.example:443/realm","oidc_client_id":"client","oidc_client_secret":"private-client-secret","jwt_supported_algs":["RS256"]})
    }

    #[test]
    fn missing_oidc_transport_preserves_pending_session_digest_on_reopen() {
        let (state, _, callback) = setup();
        let encoded = serde_json::to_vec(&state).unwrap();
        let mut reopened: AuthState = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(serde_json::to_vec(&reopened).unwrap(), encoded);
        reopened.validate_oidc_state().unwrap();
        assert!(!reopened.has_oidc_api_https_state());
        assert!(
            reopened
                .consume_oidc("", "browser", &callback, 110)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn oidc_config_prepare_is_pure_and_only_active_ca_promotes_legacy_transport() {
        let (mut state, raw, _) = setup();
        let actor = state.authenticate(&raw, 110).unwrap();
        let before = serde_json::to_vec(&state).unwrap();
        let plan = state
            .prepare_oidc_config(
                Some(&actor),
                "",
                "auth/browser/config",
                "POST",
                &config_body(),
                110,
            )
            .unwrap()
            .unwrap();
        assert!(plan.proposed.transport.is_none());
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
        let mut body = config_body();
        body["oidc_discovery_ca_pem"] = json!("");
        let plan = state
            .prepare_oidc_config(Some(&actor), "", "auth/browser/config", "POST", &body, 110)
            .unwrap()
            .unwrap();
        assert!(plan.proposed.transport.is_some());
        assert_eq!(serde_json::to_vec(&state).unwrap(), before);
        state
            .finish_oidc_config(plan, &actor, OidcConfigObservation)
            .unwrap();
        assert!(state.has_oidc_api_https_state());
        assert!(
            state
                .oidc_at(AuthScope {
                    namespace: "",
                    mount: "browser"
                })
                .unwrap()
                .sessions
                .is_empty()
        );
    }

    #[test]
    fn oidc_configuration_preflight_rechecks_current_actor_and_ca_binding() {
        for revoke in [false, true] {
            let (mut state, raw, _) = setup();
            let actor = state.authenticate(&raw, 110).unwrap();
            let plan = state
                .prepare_oidc_config(
                    Some(&actor),
                    "",
                    "auth/browser/config",
                    "POST",
                    &config_body(),
                    110,
                )
                .unwrap()
                .unwrap();
            if revoke {
                state.tokens.remove(&actor.digest);
            } else {
                state
                    .oidc_mut(AuthScope {
                        namespace: "",
                        mount: "browser",
                    })
                    .config
                    .as_mut()
                    .unwrap()
                    .transport = Some(AuthHttpsTransport::default());
            }
            let before = serde_json::to_vec(&state).unwrap();
            assert_eq!(
                state
                    .finish_oidc_config(plan, &actor, OidcConfigObservation)
                    .err()
                    .unwrap()
                    .status,
                if revoke { 403 } else { 409 }
            );
            assert_eq!(serde_json::to_vec(&state).unwrap(), before);
        }
    }
}

impl AuthState {
    /// An imported code session does not restore the provider's code state.
    pub(crate) fn discard_restored_oidc_sessions(&mut self) {
        for mounts in self.oidc_mounts.values_mut() {
            for mount in mounts.values_mut() {
                mount.sessions.clear();
            }
        }
    }
}

#[cfg(test)]
#[test]
fn restored_oidc_sessions_are_discarded_without_revoking_issued_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut state, root, callback) = tests::setup();
    let scope = AuthScope {
        namespace: "",
        mount: "browser",
    };
    let clock = state.oidc_mut(scope).clock;
    assert_eq!(state.oidc_mut(scope).sessions.len(), 1);
    state.discard_restored_oidc_sessions();
    let restored = state.oidc_mut(scope);
    assert!(restored.sessions.is_empty());
    assert!(restored.config.is_some());
    assert_eq!(restored.roles.len(), 1);
    assert_eq!(restored.clock, clock);
    assert!(state.consume_oidc("", "browser", &callback, 110).is_err());
    assert!(
        state
            .authenticate(&root, 110)
            .map_err(|_| "root")?
            .is_root()
    );
    Ok(())
}
