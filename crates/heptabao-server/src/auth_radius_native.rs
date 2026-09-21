//! Native RADIUS API authority. New administrator-configured targets authorize
//! bounded PAP egress; old records retain their process-enrolled route until an
//! explicit host or port write promotes them.
use super::provider_renewal::{same_policies, state_revision};
use super::*;

const NATIVE_FIELDS: &[&str] = &[
    "host",
    "port",
    "secret",
    "unregistered_user_policies",
    "dial_timeout",
    "read_timeout",
    "nas_port",
    "nas_identifier",
    "token_no_default_policy",
    "token_bound_cidrs",
];
const MAX_NATIVE_TIMEOUT: u64 = 60;

// No Debug implementation: every config and plan snapshot owns a zeroizing
// shared secret which only enters encrypted durable state and PAP generation.
#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct RadiusNativeConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    bound_cidrs: Vec<String>,
    host: String,
    port: i64,
    // Missing on old records: preserve process enrollment until target reconfiguration.
    #[serde(default, skip_serializing_if = "is_false")]
    api_transport: bool,
    secret: ProviderCredential,
    unregistered_user_policies: Vec<String>,
    dial_timeout: u64,
    read_timeout: u64,
    nas_port: i64,
    nas_identifier: String,
    #[serde(default, skip_serializing_if = "is_false")]
    token_no_default_policy: bool,
    // None is the schema-24 normalized policy representation; do not infer nil.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_policies_configured: Option<bool>,
}
impl Default for RadiusNativeConfig {
    fn default() -> Self {
        Self {
            bound_cidrs: Vec::new(),
            host: String::new(),
            port: 1812,
            api_transport: true,
            secret: ProviderCredential::new(""),
            unregistered_user_policies: Vec::new(),
            dial_timeout: 10,
            read_timeout: 10,
            nas_port: 10,
            nas_identifier: String::new(),
            token_no_default_policy: false,
            token_policies_configured: Some(false),
        }
    }
}
impl RadiusNativeConfig {
    pub(super) fn has_bound_cidrs(&self) -> bool {
        !self.bound_cidrs.is_empty()
    }
    fn url(&self) -> String {
        if self.host.contains(':') {
            format!("radius://[{}]:{}", self.host, self.port)
        } else {
            format!("radius://{}:{}", self.host, self.port)
        }
    }
    pub(super) fn api_transport(&self) -> bool {
        self.api_transport
    }
    pub(super) fn options(&self) -> crate::outbound::RadiusNativeOptions<'_> {
        crate::outbound::RadiusNativeOptions {
            secret: &self.secret.0,
            nas_port: self.nas_port,
            nas_identifier: &self.nas_identifier,
            dial_timeout: self.dial_timeout,
            read_timeout: self.read_timeout,
        }
    }
    fn validate(&self) -> Result<(), AuthError> {
        token_cidrs::validate(&self.bound_cidrs)?;
        // Keep signed ports for API readback; the transport rejects unusable ports
        // before DNS or PAP I/O. Legacy records keep their original host grammar.
        if self.api_transport {
            crate::outbound::validate_radius_native_host(&self.host)
                .map_err(|_| bad("invalid native RADIUS host"))?;
        } else {
            let target =
                crate::outbound::Target::parse(&format!("radius://{}:1812", self.host), "radius")
                    .map_err(|_| bad("invalid native RADIUS host"))?;
            if target.path != "/" || target.authority != format!("{}:1812", self.host) {
                return Err(bad("invalid native RADIUS host"));
            }
        }
        if self.secret.0.is_empty()
            || self.secret.0.len() > 256
            || self.secret.0.contains('\0')
            || self.dial_timeout > MAX_NATIVE_TIMEOUT
            || self.read_timeout > MAX_NATIVE_TIMEOUT
            || self.nas_identifier.len() > 253
            || self.nas_identifier.chars().any(char::is_control)
            || self.unregistered_user_policies.len() > 128
            || self
                .unregistered_user_policies
                .iter()
                .any(|p| p.len() > 1024 || p.chars().any(char::is_control))
        {
            return Err(bad("native RADIUS configuration exceeds supported bounds"));
        }
        normalized_policies(self.unregistered_user_policies.iter().map(String::as_str))?;
        self.options()
            .validate_configuration()
            .map_err(|_| bad("invalid native RADIUS wire configuration"))?;
        Ok(())
    }
    fn readback(&self, mount: &RadiusMount) -> Value {
        json!({"token_bound_cidrs":self.bound_cidrs,"host":self.host,"port":self.port,"unregistered_user_policies":self.unregistered_user_policies,
            "dial_timeout":self.dial_timeout,"read_timeout":self.read_timeout,"nas_port":self.nas_port,"nas_identifier":self.nas_identifier,
            "token_policies":mount.policies,"token_ttl":mount.token_ttl,"token_max_ttl":mount.token_max_ttl,
            "token_period":mount.token_period,"token_explicit_max_ttl":mount.token_explicit_max_ttl,"token_num_uses":mount.token_num_uses,"token_no_default_policy":self.token_no_default_policy})
    }
}
fn native_username(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && !value.chars().any(char::is_control)
}
fn native_mapping_name(value: &str) -> bool {
    native_username(value) && !value.contains('/')
}
fn integer(body: &Value, field: &str, default: i64) -> Result<i64, AuthError> {
    match body.get(field) {
        None => Ok(default),
        Some(Value::Null) => Ok(0),
        Some(Value::String(value)) => value
            .parse::<i64>()
            .map_err(|_| bad("expected signed integer")),
        Some(value) => value.as_i64().ok_or_else(|| bad("expected signed integer")),
    }
}
fn normalized_policies<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeSet<String>, AuthError> {
    let result: BTreeSet<String> = values
        .into_iter()
        .map(|p| p.trim().to_lowercase())
        .filter(|p| !p.is_empty())
        .collect();
    if result.len() > 128 || result.iter().any(|p| !valid_name(p) || p == "root") {
        return Err(bad("invalid RADIUS policies"));
    }
    Ok(result)
}
fn policy_field(body: &Value, field: &str) -> Result<BTreeSet<String>, AuthError> {
    match body.get(field) {
        None | Some(Value::Null) => Ok(BTreeSet::new()),
        Some(Value::String(value)) => normalized_policies(value.split(',')),
        Some(Value::Array(values)) => normalized_policies(
            values
                .iter()
                .map(|v| {
                    v.as_str()
                        .ok_or_else(|| bad("policies must contain strings"))
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        _ => Err(bad("policies must be an array or comma-separated string")),
    }
}

impl AuthState {
    pub(super) fn radius_native_at(&self, scope: AuthScope<'_>) -> Option<&RadiusNativeConfig> {
        self.radius_mounts
            .get(scope.namespace)?
            .get(scope.mount)?
            .native
            .as_deref()
    }
    fn radius_user_at(&self, scope: AuthScope<'_>, username: &str) -> Option<&BTreeSet<String>> {
        self.radius_native_users
            .get(scope.namespace)?
            .get(scope.mount)?
            .get(&username.to_lowercase())
    }
    pub(super) fn radius_native_local_revision(
        &self,
        scope: AuthScope<'_>,
        username: &str,
    ) -> Result<[u8; 32], AuthError> {
        state_revision(&self.radius_user_at(scope, username))
    }
    fn radius_native_intent(&self, scope: AuthScope<'_>) -> bool {
        self.radius_native_users
            .get(scope.namespace)
            .is_some_and(|m| m.contains_key(scope.mount))
    }
    fn radius_legacy_issuer_present(&self, scope: AuthScope<'_>) -> bool {
        self.tokens.values().any(|token| {
            token.namespace == scope.namespace
                && token.auth_mount.as_deref() == Some(scope.mount)
                && (matches!(
                    token.auth_provenance,
                    Some(TokenAuthProvenance::Radius { .. })
                ) || token.auth_provenance.is_none() && token.parent.is_none())
        })
    }
    pub(super) fn radius_native_config_request(
        &self,
        scope: AuthScope<'_>,
        body: &Value,
    ) -> Result<bool, AuthError> {
        let current = self
            .radius_mounts
            .get(scope.namespace)
            .and_then(|m| m.get(scope.mount));
        let has_native = NATIVE_FIELDS.iter().any(|f| body.get(f).is_some());
        let has_legacy = body.get("url").is_some();
        if has_native && has_legacy {
            return Err(bad(
                "cannot mix native and legacy RADIUS configuration fields",
            ));
        }
        let native_intent = self.radius_native_intent(scope);
        if has_legacy && (current.is_some_and(|c| c.native.is_some()) || native_intent)
            || has_native
                && (current.is_some_and(|c| c.native.is_none())
                    || self.radius_legacy_issuer_present(scope))
        {
            return Err(err(
                409,
                "RADIUS configuration cannot change profile; use a new mount",
            ));
        }
        Ok(has_native || native_intent || current.is_some_and(|c| c.native.is_some()))
    }
    pub(super) fn radius_native_config_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let path = format!("auth/{}/config", scope.mount);
        let actor = self.permission(
            principal,
            scope.namespace,
            &path,
            route_capability(method, false)?,
            now,
        )?;
        if method == "GET" {
            reject_unknown(body, &[])?;
            let mount = self
                .radius_mounts
                .get(scope.namespace)
                .and_then(|m| m.get(scope.mount))
                .ok_or_else(|| err(404, "RADIUS not configured"))?;
            return Ok(response(
                mount.native.as_ref().ok_or_else(denied)?.readback(mount),
                false,
            ));
        }
        if !matches!(method, "POST" | "PUT") {
            return Err(err(405, "method not allowed"));
        }
        self.authorize_request(actor, scope.namespace, &path, "sudo", now)?;
        let mut allowed = NATIVE_FIELDS.to_vec();
        allowed.extend([
            "token_policies",
            "token_ttl",
            "token_max_ttl",
            "token_period",
            "token_explicit_max_ttl",
            "token_num_uses",
        ]);
        reject_unknown(body, &allowed)?;
        let mut mount = self
            .radius_mounts
            .get(scope.namespace)
            .and_then(|m| m.get(scope.mount))
            .cloned()
            .unwrap_or(RadiusMount {
                url: String::new(),
                policies: BTreeSet::new(),
                token_ttl: 0,
                token_max_ttl: 0,
                token_period: 0,
                token_explicit_max_ttl: 0,
                token_num_uses: 0,
                native: None,
            });
        let mut config = mount.native.take().map(|c| *c).unwrap_or_default();
        if body.get("token_bound_cidrs").is_some() {
            config.bound_cidrs = token_cidrs::field(body)?;
        }
        if body.get("host").is_some() || body.get("port").is_some() {
            config.api_transport = true;
        }
        if body.get("host").is_some() {
            config.host = string_field(body, "host")?.to_lowercase();
        }
        if body.get("secret").is_some() {
            config.secret = ProviderCredential::new(string_field(body, "secret")?);
        }
        config.port = integer(body, "port", config.port)?;
        config.nas_port = integer(body, "nas_port", config.nas_port)?;
        if let Some(value) = body.get("nas_identifier") {
            config.nas_identifier = if value.is_null() {
                String::new()
            } else {
                string_field(body, "nas_identifier")?.into()
            };
        }
        if let Some(value) = body.get("unregistered_user_policies") {
            let raw = if value.is_null() {
                ""
            } else {
                string_field(body, "unregistered_user_policies")?
            };
            config.unregistered_user_policies = if raw.trim().is_empty() {
                Vec::new()
            } else {
                raw.split(',').map(str::to_owned).collect()
            };
        }
        for (field, target) in [
            ("dial_timeout", &mut config.dial_timeout),
            ("read_timeout", &mut config.read_timeout),
        ] {
            if body.get(field).is_some_and(|v| !v.is_null()) {
                *target = duration(body, field, *target)?;
            }
        }
        if let Some(value) = body.get("token_no_default_policy") {
            config.token_no_default_policy = if value.is_null() {
                false
            } else {
                boolean(
                    body,
                    "token_no_default_policy",
                    config.token_no_default_policy,
                )?
            };
        }
        if body.get("token_policies").is_some() {
            config.token_policies_configured = Some(true);
            mount.policies = policy_field(body, "token_policies")?;
        }
        for (field, target) in [
            ("token_ttl", &mut mount.token_ttl),
            ("token_max_ttl", &mut mount.token_max_ttl),
            ("token_period", &mut mount.token_period),
            ("token_explicit_max_ttl", &mut mount.token_explicit_max_ttl),
        ] {
            if body.get(field).is_some_and(|v| !v.is_null()) {
                *target = duration(body, field, *target)?;
            }
        }
        if let Some(value) = body.get("token_num_uses") {
            mount.token_num_uses = if value.is_null() {
                0
            } else {
                number(body, "token_num_uses", mount.token_num_uses)?
            };
        }
        if [
            mount.token_ttl,
            mount.token_max_ttl,
            mount.token_period,
            mount.token_explicit_max_ttl,
        ]
        .into_iter()
        .any(|v| v > MAX_TTL)
            || mount.token_ttl > 0
                && mount.token_max_ttl > 0
                && mount.token_ttl > mount.token_max_ttl
        {
            return Err(bad("invalid RADIUS token TTL limits"));
        }
        config.validate()?;
        self.validate_assignment(actor, &mount.policies)?;
        self.validate_assignment(
            actor,
            &normalized_policies(config.unregistered_user_policies.iter().map(String::as_str))?,
        )?;
        mount.url = config.url();
        mount.native = Some(Box::new(config));
        let changed = self
            .radius_mounts
            .entry(scope.namespace.into())
            .or_default()
            .insert(scope.mount.into(), mount.clone())
            .as_ref()
            != Some(&mount);
        Ok(empty(changed))
    }
    pub(super) fn radius_native_user_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let prefix = format!("auth/{}/users", scope.mount);
        let name = path
            .strip_prefix(&prefix)
            .ok_or_else(|| bad("invalid RADIUS user route"))?
            .trim_start_matches('/');
        let capability = route_capability(method, name.is_empty())?;
        let actor = self.permission(principal, scope.namespace, path, capability, now)?;
        let legacy = self
            .radius_mounts
            .get(scope.namespace)
            .and_then(|m| m.get(scope.mount))
            .is_some_and(|c| c.native.is_none())
            || self.radius_legacy_issuer_present(scope);
        if legacy {
            return Err(err(
                if capability == "update" { 409 } else { 404 },
                "legacy RADIUS profile has no native user mappings",
            ));
        }
        if name.is_empty() {
            if capability != "list" {
                return Err(err(405, "method not allowed"));
            }
            reject_unknown(body, &["after", "limit"])?;
            let after = body
                .get("after")
                .map(|v| v.as_str().ok_or_else(|| bad("invalid list cursor")))
                .transpose()?
                .unwrap_or("");
            let limit = body
                .get("limit")
                .map(|v| v.as_i64().ok_or_else(|| bad("invalid list limit")))
                .transpose()?
                .unwrap_or(0);
            let mut keys: Vec<String> = self
                .radius_native_users
                .get(scope.namespace)
                .and_then(|m| m.get(scope.mount))
                .map(|m| m.keys().filter(|k| k.as_str() > after).cloned().collect())
                .unwrap_or_default();
            if limit > 0 {
                keys.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
            }
            if keys.is_empty() {
                return Err(err(404, "RADIUS users not found"));
            }
            return Ok(response(json!({"keys":keys}), false));
        }
        if !native_mapping_name(name) {
            return Err(bad("invalid RADIUS user mapping name"));
        }
        if capability == "read" {
            reject_unknown(body, &[])?;
            let mapped = self
                .radius_user_at(scope, name)
                .ok_or_else(|| err(404, "RADIUS user mapping not found"))?;
            return Ok(response(json!({"policies":mapped}), false));
        }
        self.authorize_request(actor, scope.namespace, path, "sudo", now)?;
        if capability == "delete" {
            reject_unknown(body, &[])?;
            let removed = self
                .radius_native_users
                .get_mut(scope.namespace)
                .and_then(|m| m.get_mut(scope.mount))
                .and_then(|m| m.remove(name))
                .is_some();
            return Ok(empty(removed));
        }
        if capability != "update" {
            return Err(err(405, "method not allowed"));
        }
        reject_unknown(body, &["policies"])?;
        let policies = policy_field(body, "policies")?;
        self.validate_assignment(actor, &policies)?;
        let users = self
            .radius_native_users
            .entry(scope.namespace.into())
            .or_default()
            .entry(scope.mount.into())
            .or_default();
        if users.len() >= 1024 && !users.contains_key(name) {
            return Err(err(507, "RADIUS user mapping capacity exceeded"));
        }
        let changed = users.insert(name.into(), policies.clone()).as_ref() != Some(&policies);
        Ok(empty(changed))
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_native_radius_login(
        &self,
        scope: AuthScope<'_>,
        mount_revision: AuthMount,
        config: RadiusMount,
        path_username: Option<&str>,
        body: &Value,
        now: u64,
        origin_peer: Option<std::net::IpAddr>,
    ) -> Result<RadiusLoginPlan, AuthError> {
        token_cidrs::check(
            &config.native.as_ref().ok_or_else(denied)?.bound_cidrs,
            origin_peer,
        )?;
        reject_unknown(body, &["username", "password"])?;
        let username = match body.get("username") {
            None | Some(Value::Null) => path_username.unwrap_or("").to_owned(),
            Some(Value::String(value)) if value.is_empty() => {
                path_username.unwrap_or("").to_owned()
            }
            Some(Value::String(value)) => value.clone(),
            Some(Value::Bool(value)) => u8::from(*value).to_string(),
            Some(Value::Number(value)) if value.is_i64() || value.is_u64() => value.to_string(),
            _ => return Err(bad("invalid RADIUS username")),
        };
        let password = string_field(body, "password")?;
        if !native_username(&username)
            || password.is_empty()
            || password.len() > 128
            || password.contains('\0')
        {
            return Err(bad("invalid RADIUS credentials"));
        }
        Ok(RadiusLoginPlan {
            origin_peer,
            namespace: scope.namespace.into(),
            mount: scope.mount.into(),
            mount_revision,
            native_revision: Some(self.radius_native_local_revision(scope, &username)?),
            username,
            password: Zeroizing::new(password.into()),
            config,
            now,
            started: std::time::Instant::now(),
        })
    }
    fn radius_login_policies(
        &self,
        scope: AuthScope<'_>,
        username: &str,
    ) -> Result<Vec<String>, AuthError> {
        let config = self.radius_native_at(scope).ok_or_else(denied)?;
        Ok(self
            .radius_user_at(scope, username)
            .map(|p| p.iter().cloned().collect())
            .unwrap_or_else(|| config.unregistered_user_policies.clone()))
    }
    pub(super) fn finish_native_radius_login(
        &mut self,
        plan: RadiusLoginPlan,
    ) -> Result<AuthResponse, AuthError> {
        let scope = AuthScope {
            namespace: &plan.namespace,
            mount: &plan.mount,
        };
        if Some(self.radius_native_local_revision(scope, &plan.username)?) != plan.native_revision {
            return Err(err(409, "RADIUS mapping changed during provider request"));
        }
        let bound_cidrs = plan
            .config
            .native
            .as_ref()
            .ok_or_else(denied)?
            .bound_cidrs
            .clone();
        token_cidrs::check(&bound_cidrs, plan.origin_peer)?;
        let login_policies = self.radius_login_policies(scope, &plan.username)?;
        let metadata = login_policies.join(",");
        let mut policies = plan.config.policies.clone();
        policies.extend(normalized_policies(
            login_policies.iter().map(String::as_str),
        )?);
        if !plan
            .config
            .native
            .as_ref()
            .ok_or_else(denied)?
            .token_no_default_policy
        {
            policies.insert("default".into());
        }
        let now = plan.observed_now();
        let mut response = self.issue_native_online_token(
            scope,
            &plan.username,
            NativeOnlineToken {
                bound_cidrs,
                policies,
                limits: NativeTokenLimits {
                    ttl: plan.config.token_ttl,
                    max_ttl: plan.config.token_max_ttl,
                    period: plan.config.token_period,
                },
                explicit_max_ttl: plan.config.token_explicit_max_ttl,
                uses: plan.config.token_num_uses,
                provenance: TokenAuthProvenance::RadiusNative {
                    username: plan.username.clone(),
                    credential: ProviderCredential::new(&plan.password),
                    policy_metadata: metadata.clone(),
                },
            },
            now,
        )?;
        if response.body["auth"]["token_policies"]
            .as_array()
            .is_some_and(Vec::is_empty)
        {
            response.body["auth"]
                .as_object_mut()
                .ok_or_else(denied)?
                .remove("token_policies");
        }
        response.body["auth"]["metadata"] = json!({"username":plan.username,"policies":metadata});
        Ok(response)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn finish_native_radius_renewal(
        &mut self,
        scope: AuthScope<'_>,
        target: &str,
        username: &str,
        increment: u64,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let token = self.active_token(target, now, false)?;
        let Some(TokenAuthProvenance::RadiusNative {
            policy_metadata, ..
        }) = &token.auth_provenance
        else {
            return Err(denied());
        };
        let metadata = policy_metadata.clone();
        let config = self
            .radius_mounts
            .get(scope.namespace)
            .and_then(|m| m.get(scope.mount))
            .ok_or_else(denied)?;
        // The upstream plugin compares raw fallback names at renewal; core only
        // normalizes the newly issued service token's policy set during login.
        let mut policies = config.policies.clone();
        let login_policies = self.radius_login_policies(scope, username)?;
        let nil_policies = config
            .native
            .as_ref()
            .is_some_and(|native| native.token_policies_configured == Some(false))
            && policies.is_empty()
            && login_policies.is_empty();
        policies.extend(login_policies);
        // EquivalentPolicies distinguishes nil from an explicit empty list.
        // Legacy schema-24 config had already normalized this distinction away.
        if nil_policies && token.policies.is_empty() || !same_policies(&policies, &token.policies) {
            return Err(err(500, "policies have changed, not renewing"));
        }
        let expiry = self.native_token_expiry(
            scope,
            NativeTokenLimits {
                ttl: config.token_ttl,
                max_ttl: config.token_max_ttl,
                period: config.token_period,
            },
            token.created_at,
            token.max_expires_at,
            increment,
            now,
        )?;
        let token = self.tokens.get_mut(target).ok_or_else(denied)?;
        token.expires_at = Some(expiry);
        let mut response = AuthResponse {
            approle_secret_consumption: None,
            pending_batch: None,
            login_identity: None,
            external_groups: None,
            status: 200,
            mutated: true,
            body: json!({"auth":{
            "accessor":token.accessor,"policies":token.policies,"token_policies":token.policies,"entity_id":token.entity_id.as_deref().unwrap_or(""),
            "metadata":{"username":username,"policies":metadata},"lease_duration":expiry-now,"renewable":true,"token_type":"service"}}),
        };
        if token.policies.is_empty() {
            response.body["auth"]
                .as_object_mut()
                .ok_or_else(denied)?
                .remove("token_policies");
        }
        Ok(response)
    }
    pub(crate) fn has_radius_api_transport(&self) -> bool {
        self.radius_mounts.values().any(|mounts| {
            mounts.values().any(|mount| {
                mount
                    .native
                    .as_ref()
                    .is_some_and(|config| config.api_transport)
            })
        })
    }
    pub(crate) fn has_radius_no_default_policy(&self) -> bool {
        self.radius_mounts.values().any(|mounts| {
            mounts.values().any(|mount| {
                mount.native.as_ref().is_some_and(|config| {
                    config.token_no_default_policy || config.token_policies_configured.is_some()
                })
            })
        }) || self.tokens.values().any(|token| {
            matches!(
                token.auth_provenance,
                Some(TokenAuthProvenance::RadiusNative { .. })
            ) && !token.policies.contains("default")
        })
    }
    pub(crate) fn has_native_radius_state(&self) -> bool {
        self.radius_mounts
            .values()
            .any(|m| m.values().any(|c| c.native.is_some()))
            || self.radius_native_users.values().any(|m| !m.is_empty())
            || self.tokens.values().any(|t| {
                matches!(
                    t.auth_provenance,
                    Some(TokenAuthProvenance::RadiusNative { .. })
                )
            })
    }
    pub(crate) fn validate_native_radius_state(&self) -> Result<(), AuthError> {
        for (ns, mounts) in &self.radius_mounts {
            for (mount, config) in mounts {
                if let Some(native) = &config.native {
                    if !self.online_mount_enabled(ns, mount, "radius") || config.url != native.url()
                    {
                        return Err(bad("invalid native RADIUS mount"));
                    }
                    native.validate()?;
                }
            }
        }
        for (ns, mounts) in &self.radius_native_users {
            for (mount, users) in mounts {
                let scope = AuthScope {
                    namespace: ns,
                    mount,
                };
                if users.len() > 1024
                    || !self.online_mount_enabled(ns, mount, "radius")
                    || self
                        .radius_mounts
                        .get(ns)
                        .and_then(|m| m.get(mount))
                        .is_some_and(|c| c.native.is_none())
                    || self.radius_legacy_issuer_present(scope)
                {
                    return Err(bad("invalid native RADIUS user mappings"));
                }
                for (name, policies) in users {
                    if !native_mapping_name(name)
                        || policies != &normalized_policies(policies.iter().map(String::as_str))?
                    {
                        return Err(bad("invalid native RADIUS mapping"));
                    }
                }
            }
        }
        for token in self.tokens.values() {
            if let Some(TokenAuthProvenance::RadiusNative {
                username,
                credential,
                policy_metadata,
            }) = &token.auth_provenance
                && (token.root
                    || token.parent.is_some()
                    || !token.auth_origin_known
                    || token.wrapping.is_some()
                    || token.period > MAX_TTL
                    || !native_username(username)
                    || credential.0.is_empty()
                    || credential.0.len() > 128
                    || credential.0.contains('\0')
                    || policy_metadata.len() > 128 * 1025
                    || policy_metadata.chars().any(char::is_control)
                    || token.policies.contains("root")
                    || !token.auth_mount.as_ref().is_some_and(|m| {
                        self.radius_native_at(AuthScope {
                            namespace: &token.namespace,
                            mount: m,
                        })
                        .is_some()
                    }))
            {
                return Err(bad("invalid native RADIUS renewal provenance"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "auth_radius_native_tests.rs"]
mod tests;
