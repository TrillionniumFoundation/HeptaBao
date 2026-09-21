//! Online, audience-aware Kubernetes TokenReview authentication. The returned
//! ServiceAccount identity is trusted only after verified API-configured TLS,
//! or the unchanged process-enrolled transport of older configurations.
//! Caller-supplied JWT claims are never treated as identity or authorization.
use super::*;
use crate::outbound::{AuthHttpsTransport, Outbound, Target, parse_auth_https_target};

const MAX_KUBERNETES_ROLES: usize = 1024;
const MAX_LOGIN_TTL: u64 = 3600;
const TOKEN_REVIEW_PATH: &str = "/apis/authentication.k8s.io/v1/tokenreviews";

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct KubernetesMount {
    config: Option<KubernetesConfig>,
    roles: BTreeMap<String, KubernetesRole>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct KubernetesConfig {
    kubernetes_host: String,
    token_reviewer_jwt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transport: Option<AuthHttpsTransport>,
}
impl Drop for KubernetesConfig {
    fn drop(&mut self) {
        self.token_reviewer_jwt.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct KubernetesRole {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    token_bound_cidrs: Vec<String>,
    bound_service_account_names: BTreeSet<String>,
    bound_service_account_namespaces: BTreeSet<String>,
    audience: String,
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

pub(crate) struct KubernetesLoginPlan {
    namespace: String,
    mount: String,
    mount_revision: AuthMount,
    role_name: String,
    presented: Zeroizing<String>,
    config: KubernetesConfig,
    role: KubernetesRole,
    origin_peer: Option<std::net::IpAddr>,
    now: u64,
    started: std::time::Instant,
}

pub(crate) struct KubernetesLoginObservation {
    service_account_namespace: String,
    service_account_name: String,
    service_account_uid: String,
}

#[cfg(test)]
impl KubernetesLoginObservation {
    pub(crate) fn observed(namespace: &str, name: &str, uid: &str) -> Self {
        Self {
            service_account_namespace: namespace.into(),
            service_account_name: name.into(),
            service_account_uid: uid.into(),
        }
    }
}

impl KubernetesLoginPlan {
    pub(crate) fn observed_now(&self) -> u64 {
        let elapsed = self.started.elapsed();
        self.now.saturating_add(
            elapsed
                .as_secs()
                .saturating_add(u64::from(elapsed.subsec_nanos() > 0)),
        )
    }

    pub(crate) fn execute(
        &self,
        outbound: &Outbound,
        deadline: std::time::Instant,
    ) -> Result<KubernetesLoginObservation, AuthError> {
        let mut request = json!({
            "apiVersion":"authentication.k8s.io/v1",
            "kind":"TokenReview",
            "spec":{"token":self.presented.as_str(),"audiences":[self.role.audience.clone()]}
        });
        let result = outbound.post_auth_json_bearer(
            &self.config.token_review_url(),
            self.config.reviewer_for(&self.presented),
            &request,
            self.config.transport.as_ref(),
            deadline,
        );
        crate::service::erase_json(&mut request);
        let mut reviewed = result.map_err(|_| {
            // OpenBao maps completed TokenReview transport/provider errors to
            // permission denied. Retained enrolled profiles and caller deadline
            // exhaustion keep their existing availability semantics.
            if self.config.transport.is_some() && std::time::Instant::now() < deadline {
                denied()
            } else {
                err(503, "Kubernetes TokenReview unavailable or untrusted")
            }
        })?;
        let identity = self.role.bind_review(&reviewed);
        crate::service::erase_json(&mut reviewed);
        let (service_account_namespace, service_account_name, service_account_uid) = identity?;
        Ok(KubernetesLoginObservation {
            service_account_namespace,
            service_account_name,
            service_account_uid,
        })
    }
}

fn dns_name(value: &str, namespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= if namespace { 63 } else { 253 }
        && (!namespace || !value.contains('.'))
        && value.split('.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && s.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
                && s.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}
fn credential(value: &str) -> bool {
    (16..=32 * 1024).contains(&value.len()) && value.bytes().all(|c| c.is_ascii_graphic())
}
fn audience(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && value.bytes().all(|b| b.is_ascii_graphic())
}
fn names(body: &Value, field: &str, namespace: bool) -> Result<BTreeSet<String>, AuthError> {
    let value = body
        .get(field)
        .ok_or_else(|| bad("explicit ServiceAccount binding required"))?;
    let values: Vec<&str> = match value {
        Value::String(v) => v.split(',').map(str::trim).collect(),
        Value::Array(v) => v
            .iter()
            .map(|s| s.as_str().ok_or_else(|| bad("binding must be strings")))
            .collect::<Result<_, _>>()?,
        _ => return Err(bad("binding must be array or comma-separated names")),
    };
    if values.is_empty()
        || values.len() > 128
        || values.iter().any(|v| *v != "*" && !dns_name(v, namespace))
    {
        return Err(bad("invalid ServiceAccount binding"));
    }
    let result: BTreeSet<_> = values.iter().map(|v| (*v).to_owned()).collect();
    if result.len() != values.len() || result.contains("*") && result.len() != 1 {
        return Err(bad("duplicate or ambiguous ServiceAccount binding"));
    }
    Ok(result)
}
impl KubernetesConfig {
    fn token_review_url(&self) -> String {
        format!(
            "{}{TOKEN_REVIEW_PATH}",
            self.kubernetes_host
                .strip_suffix('/')
                .unwrap_or(&self.kubernetes_host)
        )
    }

    fn reviewer_for<'a>(&'a self, presented: &'a str) -> &'a str {
        if self.transport.is_some() && self.token_reviewer_jwt.is_empty() {
            presented
        } else {
            &self.token_reviewer_jwt
        }
    }

    fn validate(&self) -> Result<(), AuthError> {
        if let Some(transport) = &self.transport {
            // Kubernetes 2.6.2's explicit no-local-fallback mode requires a CA;
            // empty must never inherit the JWT connector's system-root meaning.
            if transport.certificate.is_empty() || self.kubernetes_host.contains('?') {
                return Err(bad(
                    "explicit Kubernetes CA and a query-free HTTPS base URL required",
                ));
            }
            transport
                .validate_configuration(&self.kubernetes_host)
                .map_err(bad)?;
            parse_auth_https_target(&self.token_review_url(), Some(transport)).map_err(bad)?;
            if !self.token_reviewer_jwt.is_empty() && !credential(&self.token_reviewer_jwt) {
                return Err(bad("invalid Kubernetes reviewer credential"));
            }
        } else {
            let target = Target::parse(&self.kubernetes_host, "https").map_err(bad)?;
            if target.origin != self.kubernetes_host || !credential(&self.token_reviewer_jwt) {
                return Err(bad("invalid Kubernetes host or reviewer credential"));
            }
        }
        Ok(())
    }
}
impl KubernetesRole {
    fn validate(&self) -> Result<(), AuthError> {
        token_cidrs::validate(&self.token_bound_cidrs)?;
        let shape = serde_json::to_value(self).map_err(|_| bad("invalid role"))?;
        names(&shape, "bound_service_account_names", false)?;
        names(&shape, "bound_service_account_namespaces", true)?;
        if !audience(&self.audience)
            || self.token_policies.len() > 128
            || self
                .token_policies
                .iter()
                .any(|p| !valid_name(p) || p == "root")
            || self.token_ttl > MAX_TTL
            || self.token_max_ttl > MAX_TTL
            || self.token_period > MAX_TTL
            || self.token_explicit_max_ttl > MAX_TTL
            || self.token_max_ttl > 0 && self.token_ttl > self.token_max_ttl
        {
            return Err(bad("invalid Kubernetes role policy, TTL or audience"));
        }
        Ok(())
    }
    fn limits(&self) -> NativeTokenLimits {
        NativeTokenLimits {
            ttl: self.token_ttl,
            max_ttl: self.token_max_ttl,
            period: self.token_period,
        }
    }
    fn bind_review(&self, review: &Value) -> Result<(String, String, String), AuthError> {
        if review.get("apiVersion").and_then(Value::as_str) != Some("authentication.k8s.io/v1")
            || review.get("kind").and_then(Value::as_str) != Some("TokenReview")
        {
            return Err(denied());
        }
        let status = review
            .get("status")
            .and_then(Value::as_object)
            .ok_or_else(denied)?;
        if status.get("authenticated").and_then(Value::as_bool) != Some(true)
            || status.get("error").is_some_and(|v| v.as_str() != Some(""))
        {
            return Err(denied());
        }
        let audiences = status
            .get("audiences")
            .and_then(Value::as_array)
            .ok_or_else(denied)?;
        if audiences.is_empty()
            || audiences.len() > 64
            || audiences
                .iter()
                .any(|v| v.as_str().is_none_or(|s| !audience(s)))
            || !audiences.iter().any(|v| v.as_str() == Some(&self.audience))
        {
            return Err(denied());
        }
        let user = status
            .get("user")
            .and_then(Value::as_object)
            .ok_or_else(denied)?;
        let username = user
            .get("username")
            .and_then(Value::as_str)
            .ok_or_else(denied)?;
        let uid = user
            .get("uid")
            .and_then(Value::as_str)
            .filter(|v| {
                !v.is_empty()
                    && v.len() <= 128
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            })
            .ok_or_else(denied)?;
        let rest = username
            .strip_prefix("system:serviceaccount:")
            .ok_or_else(denied)?;
        let (namespace, name) = rest.split_once(':').ok_or_else(denied)?;
        if !dns_name(namespace, true)
            || !dns_name(name, false)
            || !(self.bound_service_account_namespaces.contains("*")
                || self.bound_service_account_namespaces.contains(namespace))
            || !(self.bound_service_account_names.contains("*")
                || self.bound_service_account_names.contains(name))
        {
            return Err(denied());
        }
        Ok((namespace.to_owned(), name.to_owned(), uid.to_owned()))
    }
}

impl AuthState {
    pub(crate) fn has_kubernetes_renewal_state(&self) -> bool {
        self.tokens.values().any(|token| {
            matches!(
                token.auth_provenance,
                Some(TokenAuthProvenance::Kubernetes { .. })
            )
        }) || self
            .kubernetes_mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .flat_map(|mount| mount.roles.values())
            .any(|role| {
                role.token_policies.is_empty()
                    || role.token_ttl == 0
                    || role.token_ttl > MAX_LOGIN_TTL
                    || role.token_max_ttl > 0
                    || role.token_period > 0
                    || role.token_explicit_max_ttl > 0
            })
    }

    pub(crate) fn has_kube_role_bound_cidrs(&self) -> bool {
        self.kubernetes_mounts.values().any(|mounts| {
            mounts.values().any(|mount| {
                mount
                    .roles
                    .values()
                    .any(|role| !role.token_bound_cidrs.is_empty())
            })
        }) || self.tokens.values().any(|token| {
            !token.bound_cidrs.is_empty()
                && matches!(
                    token.auth_provenance,
                    Some(TokenAuthProvenance::Kubernetes { .. })
                )
        })
    }

    pub(crate) fn validate_kubernetes_renewal_state(&self) -> Result<(), AuthError> {
        for token in self.tokens.values() {
            if let Some(TokenAuthProvenance::Kubernetes { role_name }) = &token.auth_provenance
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
                        self.online_mount_enabled(&token.namespace, mount, "kubernetes")
                    }))
            {
                return Err(bad("invalid Kubernetes renewal provenance"));
            }
        }
        Ok(())
    }

    pub(super) fn renew_kubernetes_token(
        &mut self,
        namespace: &str,
        target: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<AuthResponse>, AuthError> {
        let token = self.tokens.get(target).ok_or_else(denied)?;
        let Some(TokenAuthProvenance::Kubernetes { role_name }) = token.auth_provenance.as_ref()
        else {
            if token.auth_provenance.is_none()
                && token.parent.is_none()
                && token.auth_mount.as_ref().is_some_and(|mount| {
                    self.online_mount_enabled(&token.namespace, mount, "kubernetes")
                })
            {
                return Err(bad(
                    "legacy Kubernetes token has no issuing role provenance; log in again",
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
        if !self.online_mount_enabled(namespace, mount, "kubernetes") {
            return Err(denied());
        }
        // TokenReview authenticates login only. Current reviewer credentials,
        // audience, account bounds and assigned policies do not reauthenticate
        // a service token or replace its issued policy snapshot.
        let role = self
            .kubernetes_at(scope)
            .and_then(|state| state.roles.get(role_name))
            .ok_or_else(|| err(500, "Kubernetes role does not exist during renewal"))?;
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
            body: json!({"auth": {
                "accessor":token.accessor,"policies":token.policies,"token_policies":token.policies,
                "entity_id":token.entity_id.as_deref().unwrap_or(""),
                "lease_duration":expires_at-now,"renewable":true,"token_type":"service"
            }}),
        }))
    }

    pub(super) fn online_mount_enabled(&self, namespace: &str, mount: &str, kind: &str) -> bool {
        self.effective_auth_mounts(namespace)
            .get(mount)
            .is_some_and(|v| v.kind == kind)
    }
    pub(crate) fn online_mount_route(
        &self,
        namespace: &str,
        path: &str,
    ) -> Option<(String, String, String)> {
        let rest = path.strip_prefix("auth/")?;
        self.effective_auth_mounts(namespace)
            .into_iter()
            .find_map(|(mount, entry)| {
                if !matches!(
                    entry.kind.as_str(),
                    "kubernetes" | "oidc" | "ldap" | "radius"
                ) {
                    return None;
                }
                rest.strip_prefix(&format!("{mount}/"))
                    .map(|suffix| (entry.kind, mount.clone(), suffix.to_owned()))
            })
    }
    pub(crate) fn has_ldap_group_state(&self) -> bool {
        self.ldap_groups
            .values()
            .any(|mounts| mounts.values().any(|groups| !groups.is_empty()))
            || self
                .ldap_mounts
                .values()
                .any(|mounts| mounts.values().any(|config| !config.group_dn.is_empty()))
    }

    pub(crate) fn has_online_auth_state(&self) -> bool {
        self.has_oidc_state()
            || self.kubernetes_mounts.values().any(|m| !m.is_empty())
            || self.ldap_mounts.values().any(|m| !m.is_empty())
            || self.radius_mounts.values().any(|m| !m.is_empty())
            || self.auth_mounts.values().any(|m| {
                m.values()
                    .any(|v| matches!(v.kind.as_str(), "kubernetes" | "oidc" | "ldap" | "radius"))
            })
    }
    pub(crate) fn validate_online_auth(&self) -> Result<(), AuthError> {
        self.validate_token_bound_cidrs()?;
        self.validate_oidc_state()?;
        self.validate_native_ldap_state()?;
        self.validate_native_radius_state()?;
        for (namespace, mounts) in &self.kubernetes_mounts {
            validate_namespace(namespace)?;
            for (mount, state) in mounts {
                if !self.online_mount_enabled(namespace, mount, "kubernetes")
                    || state.roles.len() > MAX_KUBERNETES_ROLES
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
            }
        }
        for (namespace, mounts) in &self.ldap_mounts {
            validate_namespace(namespace)?;
            for (mount, config) in mounts {
                if !self.online_mount_enabled(namespace, mount, "ldap")
                    || config.url.is_empty()
                    || config.native.is_none()
                        && (config.user_dn_template.is_empty()
                            || !valid_ldap_attribute_name(config.group_attr())
                            || !valid_ldap_attribute_name(config.group_name_attr())
                            || config.group_dn.len() > 1024
                            || config.group_dn.chars().any(char::is_control))
                {
                    return Err(denied());
                }
            }
        }
        for (namespace, mounts) in &self.ldap_groups {
            validate_namespace(namespace)?;
            for (mount, groups) in mounts {
                if !self.online_mount_enabled(namespace, mount, "ldap") || groups.len() > 1024 {
                    return Err(denied());
                }
                for (name, policies) in groups {
                    if !valid_name(name)
                        || policies.len() > 128
                        || policies
                            .iter()
                            .any(|policy| !valid_name(policy) || policy == "root")
                    {
                        return Err(denied());
                    }
                }
            }
        }
        for (namespace, mounts) in &self.radius_mounts {
            validate_namespace(namespace)?;
            for (mount, config) in mounts {
                if !self.online_mount_enabled(namespace, mount, "radius")
                    || config.native.is_none()
                        && crate::outbound::Target::parse(&config.url, "radius")
                            .map_or(true, |target| target.path != "/")
                    || config.policies.len() > 128
                    || config
                        .policies
                        .iter()
                        .any(|policy| !valid_name(policy) || policy == "root")
                    || config.token_ttl > super::MAX_TTL
                    || config.token_max_ttl > super::MAX_TTL
                    || config.token_period > super::MAX_TTL
                    || config.token_explicit_max_ttl > super::MAX_TTL
                    || config.token_ttl > 0
                        && config.token_max_ttl > 0
                        && config.token_ttl > config.token_max_ttl
                {
                    return Err(denied());
                }
            }
        }
        Ok(())
    }
    fn kubernetes_at(&self, scope: AuthScope<'_>) -> Option<&KubernetesMount> {
        self.kubernetes_mounts
            .get(scope.namespace)?
            .get(scope.mount)
    }
    fn kubernetes_mut(&mut self, scope: AuthScope<'_>) -> &mut KubernetesMount {
        self.kubernetes_mounts
            .entry(scope.namespace.into())
            .or_default()
            .entry(scope.mount.into())
            .or_default()
    }
    pub(crate) fn check_online_enrollment(
        &self,
        namespace: &str,
        path: &str,
        outbound: &Outbound,
    ) -> Result<(), AuthError> {
        self.check_oidc_enrollment(namespace, path, outbound)?;
        let Some((kind, mount, suffix)) = self.online_mount_route(namespace, path) else {
            return Ok(());
        };
        if suffix != "config" {
            return Ok(());
        }
        if kind == "ldap" {
            let config = self
                .ldap_mounts
                .get(namespace)
                .and_then(|mounts| mounts.get(&mount))
                .ok_or_else(|| err(503, "LDAP auth is not configured"))?;
            if config.starttls || !config.url.starts_with("ldaps://") {
                return Err(err(
                    503,
                    "LDAP configuration requires a host-enrolled LDAPS endpoint",
                ));
            }
            if let Some(transport) = config
                .native
                .as_ref()
                .and_then(|native| native.transport.as_ref())
            {
                // The authorized native API configuration owns this transport;
                // validation remains pure and cannot contact a provider here.
                return transport
                    .validate_configuration(&config.url)
                    .map_err(|_| bad("invalid native LDAP transport"));
            }
            outbound
                .endpoint(&config.url, "ldaps")
                .map_err(|_| err(503, "LDAP bind target is not host-enrolled"))?;
            return Ok(());
        }
        if kind == "radius" {
            let config = self
                .radius_mounts
                .get(namespace)
                .and_then(|mounts| mounts.get(&mount))
                .ok_or_else(|| err(503, "RADIUS authentication is not configured"))?;
            // Native config is encrypted data, not an egress enrollment. Ports
            // and undeployed origins may be stored; PAP must resolve only an
            // existing fixed process route when the effect actually executes.
            if config.native.is_some() {
                return Ok(());
            }
            outbound
                .radius_endpoint(&config.url)
                .map_err(|_| err(503, "RADIUS target is not host-enrolled"))?;
            return Ok(());
        }
        if let Some(config) = self
            .kubernetes_at(AuthScope {
                namespace,
                mount: &mount,
            })
            .and_then(|s| s.config.as_ref())
        {
            config.validate()?;
            if config.transport.is_none() {
                outbound
                    .endpoint(&config.token_review_url(), "https")
                    .map_err(|_| err(503, "Kubernetes TokenReview target is not host-enrolled"))?;
            }
        }
        Ok(())
    }
    pub(crate) fn has_kubernetes_api_https_state(&self) -> bool {
        self.kubernetes_mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .any(|mount| {
                mount
                    .config
                    .as_ref()
                    .is_some_and(|config| config.transport.is_some())
            })
    }

    fn parse_kubernetes_config(
        &self,
        scope: AuthScope<'_>,
        body: &Value,
    ) -> Result<KubernetesConfig, AuthError> {
        reject_unknown(
            body,
            &[
                "kubernetes_host",
                "token_reviewer_jwt",
                "kubernetes_ca_cert",
                "disable_local_ca_jwt",
            ],
        )?;
        if body
            .get("disable_local_ca_jwt")
            .is_some_and(|value| value.as_bool() != Some(true))
        {
            return Err(bad(
                "implicit in-pod trust or reviewer credentials are forbidden",
            ));
        }
        let previous = self
            .kubernetes_at(scope)
            .and_then(|mount| mount.config.as_ref());
        let transport = match body.get("kubernetes_ca_cert") {
            Some(Value::String(certificate))
                if !certificate.is_empty() && certificate.len() <= 64 * 1024 =>
            {
                Some(AuthHttpsTransport {
                    certificate: certificate.clone(),
                })
            }
            None if previous.is_some_and(|config| config.transport.is_none()) => None,
            _ => return Err(bad("explicit nonempty Kubernetes CA required")),
        };
        let reviewer = match body.get("token_reviewer_jwt") {
            None | Some(Value::Null) => "",
            Some(value) => value
                .as_str()
                .ok_or_else(|| bad("Kubernetes reviewer must be a string"))?,
        };
        let config = KubernetesConfig {
            kubernetes_host: string_field(body, "kubernetes_host")?.into(),
            token_reviewer_jwt: reviewer.into(),
            transport,
        };
        config.validate()?;
        if previous.is_some_and(|old| old.kubernetes_host != config.kubernetes_host) {
            return Err(err(
                409,
                "changing Kubernetes cluster requires a new auth mount",
            ));
        }
        Ok(config)
    }

    pub(super) fn kubernetes_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        suffix: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let path = format!("auth/{}/{suffix}", scope.mount);
        let capability = if matches!(method, "GET" | "LIST") {
            if suffix == "role" { "list" } else { "read" }
        } else {
            "update"
        };
        let actor = self.permission(principal, scope.namespace, &path, capability, now)?;
        if !matches!(method, "GET" | "LIST") {
            self.authorize_request(actor, scope.namespace, &path, "sudo", now)?;
        }
        if suffix == "config" {
            return match method {
                "GET" => {
                    reject_unknown(body, &[])?;
                    let config = self
                        .kubernetes_at(scope)
                        .and_then(|s| s.config.as_ref())
                        .ok_or_else(|| err(404, "Kubernetes configuration missing"))?;
                    Ok(response(
                        json!({"kubernetes_host":config.kubernetes_host,"token_reviewer_jwt_set":!config.token_reviewer_jwt.is_empty(),
                        "kubernetes_ca_cert":config.transport.as_ref().map_or("", |transport| transport.certificate.as_str()),
                        "disable_local_ca_jwt":true}),
                        false,
                    ))
                }
                "POST" | "PUT" => {
                    let config = self.parse_kubernetes_config(scope, body)?;
                    self.kubernetes_mut(scope).config = Some(config);
                    Ok(empty(true))
                }
                "DELETE" => Err(err(
                    405,
                    "disable the auth mount to remove cluster binding and issued tokens",
                )),
                _ => Err(err(405, "method not allowed")),
            };
        }
        if suffix == "role" && matches!(method, "GET" | "LIST") {
            reject_unknown(body, &[])?;
            let keys: Vec<_> = self
                .kubernetes_at(scope)
                .map(|s| s.roles.keys().cloned().collect())
                .unwrap_or_default();
            return Ok(response(json!({"keys":keys}), false));
        }
        let name = suffix
            .strip_prefix("role/")
            .filter(|n| valid_name(n))
            .ok_or_else(|| err(404, "unsupported Kubernetes route"))?;
        match method {
            "GET" => {
                reject_unknown(body, &[])?;
                let role = self
                    .kubernetes_at(scope)
                    .and_then(|s| s.roles.get(name))
                    .ok_or_else(|| err(404, "Kubernetes role missing"))?;
                let mut data = serde_json::to_value(role)
                    .map_err(|_| err(500, "role serialization failed"))?;
                data["alias_name_source"] = json!("serviceaccount_uid");
                data["token_type"] = json!("service");
                data["token_max_ttl"] = json!(role.token_max_ttl);
                data["token_period"] = json!(role.token_period);
                data["token_bound_cidrs"] = json!(role.token_bound_cidrs);
                data["token_explicit_max_ttl"] = json!(role.token_explicit_max_ttl);
                data["token_renewable"] = json!(true);
                Ok(response(data, false))
            }
            "POST" | "PUT" => {
                reject_unknown(
                    body,
                    &[
                        "bound_service_account_names",
                        "bound_service_account_namespaces",
                        "audience",
                        "token_policies",
                        "token_ttl",
                        "token_max_ttl",
                        "token_period",
                        "token_explicit_max_ttl",
                        "token_num_uses",
                        "token_bound_cidrs",
                        "alias_name_source",
                        "token_type",
                    ],
                )?;
                if body
                    .get("alias_name_source")
                    .is_some_and(|v| v.as_str() != Some("serviceaccount_uid"))
                    || body
                        .get("token_type")
                        .is_some_and(|v| v.as_str() != Some("service"))
                {
                    return Err(bad("unsupported Kubernetes token or alias profile"));
                }
                // Native role updates preserve fields not present in this
                // request. New roles still require explicit identity bounds.
                let mut role = self
                    .kubernetes_at(scope)
                    .and_then(|state| state.roles.get(name))
                    .cloned()
                    .unwrap_or(KubernetesRole {
                        token_bound_cidrs: Vec::new(),
                        bound_service_account_names: BTreeSet::new(),
                        bound_service_account_namespaces: BTreeSet::new(),
                        audience: String::new(),
                        token_policies: BTreeSet::new(),
                        token_ttl: 0,
                        token_max_ttl: 0,
                        token_period: 0,
                        token_explicit_max_ttl: 0,
                        token_num_uses: 0,
                    });
                if body
                    .get("bound_service_account_names")
                    .is_some_and(|v| !v.is_null())
                {
                    role.bound_service_account_names =
                        names(body, "bound_service_account_names", false)?;
                }
                if body
                    .get("bound_service_account_namespaces")
                    .is_some_and(|v| !v.is_null())
                {
                    role.bound_service_account_namespaces =
                        names(body, "bound_service_account_namespaces", true)?;
                }
                if body.get("token_bound_cidrs").is_some() {
                    role.token_bound_cidrs = token_cidrs::field(body)?;
                }
                if body.get("audience").is_some_and(|v| !v.is_null()) {
                    role.audience = string_field(body, "audience")?.into();
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
                    if body.get(field).is_some_and(|value| !value.is_null()) {
                        *target = duration(body, field, *target)?;
                    }
                }
                if body
                    .get("token_num_uses")
                    .is_some_and(|value| !value.is_null())
                {
                    role.token_num_uses = number(body, "token_num_uses", role.token_num_uses)?;
                }
                role.validate()?;
                self.validate_assignment(actor, &role.token_policies)?;
                let state = self.kubernetes_mut(scope);
                if state.roles.len() >= MAX_KUBERNETES_ROLES && !state.roles.contains_key(name) {
                    return Err(err(507, "Kubernetes role capacity reached"));
                }
                let changed = state.roles.get(name) != Some(&role);
                state.roles.insert(name.into(), role);
                Ok(empty(changed))
            }
            "DELETE" => {
                reject_unknown(body, &[])?;
                Ok(empty(
                    self.kubernetes_mut(scope).roles.remove(name).is_some(),
                ))
            }
            _ => Err(err(405, "method not allowed")),
        }
    }
    #[cfg(test)]
    pub(crate) fn prepare_kubernetes_login(
        &self,
        namespace: &str,
        mount: &str,
        body: &Value,
        now: u64,
    ) -> Result<KubernetesLoginPlan, AuthError> {
        self.prepare_kubernetes_login_from(namespace, mount, body, now, None)
    }
    pub(crate) fn prepare_kubernetes_login_from(
        &self,
        namespace: &str,
        mount: &str,
        body: &Value,
        now: u64,
        origin_peer: Option<std::net::IpAddr>,
    ) -> Result<KubernetesLoginPlan, AuthError> {
        validate_namespace(namespace)?;
        if !self.online_mount_enabled(namespace, mount, "kubernetes") {
            return Err(denied());
        }
        reject_unknown(body, &["role", "jwt"])?;
        let role_name = string_field(body, "role")?;
        if !valid_name(role_name) {
            return Err(bad("invalid Kubernetes role name"));
        }
        let presented = string_field(body, "jwt")?;
        if !credential(presented) {
            return Err(bad("invalid Kubernetes credential"));
        }
        let state = self
            .kubernetes_at(AuthScope { namespace, mount })
            .ok_or_else(denied)?;
        let role = state.roles.get(role_name).cloned().ok_or_else(denied)?;
        token_cidrs::check(&role.token_bound_cidrs, origin_peer)?;
        let config = state
            .config
            .as_ref()
            .cloned()
            .ok_or_else(|| err(503, "Kubernetes auth is not configured"))?;
        Ok(KubernetesLoginPlan {
            namespace: namespace.into(),
            mount: mount.into(),
            mount_revision: self
                .effective_auth_mounts(namespace)
                .get(mount)
                .cloned()
                .ok_or_else(denied)?,
            role_name: role_name.into(),
            presented: Zeroizing::new(presented.into()),
            config,
            role,
            origin_peer,
            now,
            started: std::time::Instant::now(),
        })
    }

    pub(crate) fn finish_kubernetes_login(
        &mut self,
        plan: KubernetesLoginPlan,
        observation: KubernetesLoginObservation,
    ) -> Result<AuthResponse, AuthError> {
        if self.effective_auth_mounts(&plan.namespace).get(&plan.mount)
            != Some(&plan.mount_revision)
        {
            return Err(err(409, "Kubernetes auth mount changed during TokenReview"));
        }
        let state = self
            .kubernetes_at(AuthScope {
                namespace: &plan.namespace,
                mount: &plan.mount,
            })
            .ok_or_else(denied)?;
        if state.config.as_ref() != Some(&plan.config)
            || state.roles.get(&plan.role_name) != Some(&plan.role)
        {
            return Err(err(
                409,
                "Kubernetes auth configuration changed during TokenReview",
            ));
        }
        token_cidrs::check(&plan.role.token_bound_cidrs, plan.origin_peer)?;
        let now = plan.observed_now();
        let limits = plan.role.limits();
        // The role stores only explicitly assigned policies. The default
        // policy belongs to the issued token, not the role API's readback.
        let mut token_policies = plan.role.token_policies;
        token_policies.insert("default".into());
        let mut issued = self.issue_native_online_token(
            AuthScope {
                namespace: &plan.namespace,
                mount: &plan.mount,
            },
            &observation.service_account_uid,
            NativeOnlineToken {
                bound_cidrs: plan.role.token_bound_cidrs,
                policies: token_policies,
                limits,
                explicit_max_ttl: plan.role.token_explicit_max_ttl,
                uses: plan.role.token_num_uses,
                provenance: TokenAuthProvenance::Kubernetes {
                    role_name: plan.role_name.clone(),
                },
            },
            now,
        )?;
        issued.body["auth"]["metadata"] = json!({
            "service_account_namespace":observation.service_account_namespace,
            "service_account_name":observation.service_account_name,
            "service_account_uid":observation.service_account_uid,
            "role":plan.role_name
        });
        Ok(issued)
    }
}

#[cfg(test)]
#[path = "auth_kubernetes_renewal_tests.rs"]
mod renewal_tests;

#[cfg(test)]
mod tests {
    use super::*;
    fn role() -> KubernetesRole {
        KubernetesRole {
            token_bound_cidrs: Vec::new(),
            bound_service_account_names: BTreeSet::from(["worker".into()]),
            bound_service_account_namespaces: BTreeSet::from(["application".into()]),
            audience: "heptabao".into(),
            token_policies: BTreeSet::from(["default".into()]),
            token_ttl: 300,
            token_max_ttl: 0,
            token_period: 0,
            token_explicit_max_ttl: 0,
            token_num_uses: 0,
        }
    }
    fn review() -> Value {
        json!({"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{
        "authenticated":true,"audiences":["heptabao"],"user":{"username":"system:serviceaccount:application:worker","uid":"abc-123"}}})
    }
    #[test]
    fn tokenreview_requires_authenticated_identity_uid_audience_and_version() {
        let original = review();
        assert!(role().bind_review(&original).is_ok());
        for (pointer, value) in [
            ("/status/authenticated", json!("true")),
            ("/status/audiences", json!([])),
            ("/status/audiences", json!(["other"])),
            ("/status/user/uid", Value::Null),
            (
                "/status/user/username",
                json!("system:serviceaccount:other:worker"),
            ),
            (
                "/status/user/username",
                json!("system:serviceaccount:application:admin"),
            ),
            ("/status/user/username", json!("admin")),
            ("/apiVersion", json!("authentication.k8s.io/v1beta1")),
            ("/kind", json!("Status")),
        ] {
            let mut v = original.clone();
            if let Some(slot) = v.pointer_mut(pointer) {
                *slot = value;
            }
            assert!(role().bind_review(&v).is_err(), "{pointer}");
        }
        let mut v = original;
        v["status"]["error"] = json!("untrusted diagnostic");
        assert!(role().bind_review(&v).is_err());
    }
    #[test]
    fn service_account_name_patterns_are_explicit_and_canonical() {
        for v in [
            json!([]),
            json!(["*", "worker"]),
            json!(["a", "a"]),
            json!(["UPPER"]),
            json!(["../escape"]),
        ] {
            assert!(names(&json!({"names":v}), "names", false).is_err());
        }
        assert!(names(&json!({"names":["*"]}), "names", false).is_ok());
        assert!(dns_name("a.b", false));
        assert!(!dns_name("a.b", true));
    }
    #[test]
    fn credential_and_egress_configuration_have_no_ambient_fallback() {
        for value in ["", "too-short", "1234567890123456\r\nx: y"] {
            assert!(!credential(value));
        }
        for host in [
            "http://localhost:443",
            "https://localhost:443/path",
            "https://user@localhost:443",
        ] {
            assert!(
                KubernetesConfig {
                    kubernetes_host: host.into(),
                    token_reviewer_jwt: "reviewer-for-tests-only".into(),
                    transport: None
                }
                .validate()
                .is_err()
            );
        }
    }
    #[test]
    fn role_cannot_assign_root_or_unbounded_lifetime() {
        let mut r = role();
        r.token_policies.insert("root".into());
        assert!(r.validate().is_err());
        let mut r = role();
        r.token_ttl = MAX_TTL + 1;
        assert!(r.validate().is_err());
    }
}

#[cfg(test)]
#[path = "auth_kubernetes_transport_tests.rs"]
mod transport_tests;
