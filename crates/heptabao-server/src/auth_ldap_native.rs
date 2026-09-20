//! OpenBao-compatible manager-search-bind profile. Configuration and mappings
//! remain encrypted authority; directory observations never choose token policy.
use super::provider_renewal::{same_policies, state_revision};
use super::*;

const DEFAULT_USER_FILTER: &str = "({{.UserAttr}}={{.Username}})";
const DEFAULT_GROUP_FILTER: &str =
    "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))";
const NATIVE_FIELDS: &[&str] = &[
    "certificate",
    "connection_timeout",
    "request_timeout",
    "binddn",
    "bindpass",
    "userdn",
    "userattr",
    "userfilter",
    "groupdn",
    "groupattr",
    "groupfilter",
    "case_sensitive_names",
    "username_as_alias",
    "token_policies",
    "token_no_default_policy",
    "token_ttl",
    "token_max_ttl",
    "token_period",
    "token_explicit_max_ttl",
    "token_num_uses",
    "token_bound_cidrs",
];
const BOUNDED_FIELDS: &[&str] = &[
    "bind_dn",
    "user_dn_template",
    "group_dn",
    "group_attr",
    "group_name_attr",
];

// Deliberately no Debug: bindpass is a zeroizing secret, including temporary
// config snapshots held across the provider request.
#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct LdapNativeConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    bound_cidrs: Vec<String>,
    // Absence preserves the transport authority of persisted schema 23/24 mounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) transport: Option<crate::outbound::LdapTransportConfig>,
    binddn: String,
    bindpass: ProviderCredential,
    userdn: String,
    userattr: String,
    userfilter: String,
    groupdn: String,
    groupattr: String,
    groupfilter: String,
    case_sensitive_names: bool,
    username_as_alias: bool,
    token_policies: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    token_no_default_policy: bool,
    // None preserves the already-normalized policy lists in older native mounts.
    // New mounts distinguish an omitted list from an explicit empty/null list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_policies_configured: Option<bool>,
    token_ttl: u64,
    token_max_ttl: u64,
    token_period: u64,
    token_explicit_max_ttl: u64,
    token_num_uses: u64,
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct LdapNativeUser {
    groups: BTreeSet<String>,
    policies: BTreeSet<String>,
}

impl Default for LdapNativeConfig {
    fn default() -> Self {
        Self {
            bound_cidrs: Vec::new(),
            transport: None,
            binddn: String::new(),
            bindpass: ProviderCredential::new(""),
            userdn: String::new(),
            userattr: "cn".into(),
            userfilter: DEFAULT_USER_FILTER.into(),
            groupdn: String::new(),
            groupattr: "cn".into(),
            groupfilter: DEFAULT_GROUP_FILTER.into(),
            case_sensitive_names: false,
            username_as_alias: false,
            token_policies: BTreeSet::new(),
            token_no_default_policy: false,
            token_policies_configured: Some(false),
            token_ttl: 0,
            token_max_ttl: 0,
            token_period: 0,
            token_explicit_max_ttl: 0,
            token_num_uses: 0,
        }
    }
}

impl LdapNativeConfig {
    pub(super) fn has_bound_cidrs(&self) -> bool {
        !self.bound_cidrs.is_empty()
    }
    fn validate_target(&self, url: &str) -> Result<(), AuthError> {
        if let Some(transport) = &self.transport {
            transport
                .validate_configuration(url)
                .map_err(|_| bad("invalid native LDAP URL, CA or timeouts"))
        } else {
            let target = crate::outbound::Target::parse(url, "ldaps")
                .map_err(|_| bad("native LDAP requires a host-enrolled LDAPS endpoint"))?;
            if target.path != "/" {
                return Err(bad("LDAP URL must be an origin"));
            }
            Ok(())
        }
    }
    pub(super) fn options(&self) -> crate::outbound::LdapNativeOptions<'_> {
        crate::outbound::LdapNativeOptions {
            bind_dn: &self.binddn,
            bind_password: &self.bindpass.0,
            user_dn: &self.userdn,
            user_attr: &self.userattr,
            user_filter: &self.userfilter,
            group_dn: &self.groupdn,
            group_attr: &self.groupattr,
            group_filter: &self.groupfilter,
            username_as_alias: self.username_as_alias,
        }
    }
    fn canonical(&self, name: &str) -> String {
        if self.case_sensitive_names {
            name.to_owned()
        } else {
            name.to_lowercase()
        }
    }
    fn limits(&self) -> NativeTokenLimits {
        NativeTokenLimits {
            ttl: self.token_ttl,
            max_ttl: self.token_max_ttl,
            period: self.token_period,
        }
    }
    fn validate(&self) -> Result<(), AuthError> {
        token_cidrs::validate(&self.bound_cidrs)?;
        if self.binddn.is_empty()
            || self.userdn.is_empty()
            || self.bindpass.0.is_empty()
            || [&self.binddn, &self.userdn, &self.groupdn]
                .iter()
                .any(|v| v.len() > 1024 || v.chars().any(char::is_control))
            || self.bindpass.0.len() > 1024
            || self.bindpass.0.contains('\0')
            || !valid_ldap_attribute_name(&self.userattr)
            || !valid_ldap_attribute_name(&self.groupattr)
            || [&self.userfilter, &self.groupfilter]
                .iter()
                .any(|v| v.len() > 4096 || v.chars().any(char::is_control))
            || self.token_policies.len() > 128
            || self
                .token_policies
                .iter()
                .any(|p| !valid_name(p) || p == "root")
            || [
                self.token_ttl,
                self.token_max_ttl,
                self.token_period,
                self.token_explicit_max_ttl,
            ]
            .into_iter()
            .any(|v| v > MAX_TTL)
            || self.token_ttl > 0 && self.token_max_ttl > 0 && self.token_ttl > self.token_max_ttl
        {
            return Err(bad("invalid native LDAP configuration"));
        }
        self.options()
            .validate_configuration()
            .map_err(|_| bad("unsupported native LDAP filter or configuration"))?;
        Ok(())
    }
    fn readback(&self, url: &str) -> Value {
        let mut data = json!({"url":url,"binddn":self.binddn,"userdn":self.userdn,"userattr":self.userattr,
            "userfilter":self.userfilter,"groupdn":self.groupdn,"groupattr":self.groupattr,
            "groupfilter":self.groupfilter,"case_sensitive_names":self.case_sensitive_names,
            "username_as_alias":self.username_as_alias,"starttls":false,
            "token_policies":self.token_policies,"token_no_default_policy":self.token_no_default_policy,"token_ttl":self.token_ttl,"token_max_ttl":self.token_max_ttl,
            "token_period":self.token_period,"token_explicit_max_ttl":self.token_explicit_max_ttl,
            "token_num_uses":self.token_num_uses,"token_bound_cidrs":self.bound_cidrs});
        if let Some(transport) = &self.transport {
            data["certificate"] = json!(transport.certificate);
            data["connection_timeout"] = json!(transport.connection_timeout);
            data["request_timeout"] = json!(transport.request_timeout);
        }
        data
    }
}

fn names(body: &Value, field: &str) -> Result<BTreeSet<String>, AuthError> {
    if body.get(field).is_none_or(Value::is_null) {
        return Ok(BTreeSet::new());
    }
    let values = policies(body, field, &BTreeSet::new(), false)?;
    if values.len() > 128 {
        return Err(bad("too many LDAP mapping names"));
    }
    Ok(values)
}

impl AuthState {
    pub(super) fn ldap_native_at(&self, scope: AuthScope<'_>) -> Option<&LdapNativeConfig> {
        self.ldap_mounts
            .get(scope.namespace)?
            .get(scope.mount)?
            .native
            .as_deref()
    }
    fn ldap_native_user_at(&self, scope: AuthScope<'_>, username: &str) -> Option<&LdapNativeUser> {
        self.ldap_native_users
            .get(scope.namespace)?
            .get(scope.mount)?
            .get(username)
    }
    pub(super) fn ldap_native_local_revision(
        &self,
        scope: AuthScope<'_>,
        username: &str,
    ) -> Result<[u8; 32], AuthError> {
        // Option is intentional: adding a previously absent map is an authority
        // change just as replacing or deleting an existing map is.
        let config = self.ldap_native_at(scope).ok_or_else(denied)?;
        state_revision(&(
            self.ldap_native_user_at(scope, &config.canonical(username)),
            self.ldap_groups_at(scope),
        ))
    }
    pub(super) fn ldap_native_config_request(
        &self,
        scope: AuthScope<'_>,
        body: &Value,
    ) -> Result<bool, AuthError> {
        let current = self
            .ldap_mounts
            .get(scope.namespace)
            .and_then(|m| m.get(scope.mount));
        let native_fields = NATIVE_FIELDS.iter().any(|field| body.get(field).is_some());
        let bounded_fields = BOUNDED_FIELDS.iter().any(|field| body.get(field).is_some());
        if bounded_fields && native_fields {
            return Err(bad(
                "cannot mix bounded and native LDAP configuration fields",
            ));
        }
        if bounded_fields && current.is_some_and(|c| c.native.is_some()) {
            return Err(err(
                409,
                "native LDAP configuration cannot change profile; use a new mount",
            ));
        }
        if native_fields
            && (current.is_some_and(|c| c.native.is_none())
                || current.is_none() && self.users_at(scope).is_some_and(|users| !users.is_empty()))
        {
            return Err(err(
                409,
                "bounded LDAP configuration cannot change profile; use a new mount",
            ));
        }
        Ok(native_fields || current.is_some_and(|c| c.native.is_some()))
    }
    pub(super) fn ldap_native_config_route(
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
                .ldap_mounts
                .get(scope.namespace)
                .and_then(|m| m.get(scope.mount))
                .ok_or_else(denied)?;
            return Ok(response(
                mount
                    .native
                    .as_ref()
                    .ok_or_else(denied)?
                    .readback(&mount.url),
                false,
            ));
        }
        if !matches!(method, "POST" | "PUT") {
            return Err(err(405, "method not allowed"));
        }
        self.authorize_request(actor, scope.namespace, &path, "sudo", now)?;
        let mut allowed = NATIVE_FIELDS.to_vec();
        allowed.extend(["url", "starttls"]);
        reject_unknown(body, &allowed)?;
        if body.get("starttls").is_some_and(|v| !v.is_null()) && boolean(body, "starttls", false)? {
            return Err(bad("native LDAP requires LDAPS; StartTLS is not supported"));
        }
        let current = self
            .ldap_mounts
            .get(scope.namespace)
            .and_then(|m| m.get(scope.mount));
        let mut url = current.map(|c| c.url.clone()).unwrap_or_default();
        if body.get("url").is_some() {
            url = string_field(body, "url")?.to_ascii_lowercase();
        }
        let mut next = current
            .and_then(|c| c.native.as_deref().cloned())
            .unwrap_or_default();
        // New native mounts use standard API authority. Old persisted mounts
        // retain process enrollment until an explicit transport configuration.
        let transport_update = ["certificate", "connection_timeout", "request_timeout"]
            .iter()
            .any(|field| body.get(field).is_some());
        if current.is_none() || transport_update {
            let transport = next.transport.get_or_insert_with(Default::default);
            if let Some(value) = body.get("certificate") {
                transport.certificate = if value.is_null() {
                    String::new()
                } else {
                    string_field(body, "certificate")?.to_owned()
                };
            }
            for (field, target, default) in [
                ("connection_timeout", &mut transport.connection_timeout, 30),
                ("request_timeout", &mut transport.request_timeout, 90),
            ] {
                if let Some(value) = body.get(field) {
                    *target = if value.is_null() {
                        default
                    } else {
                        number(body, field, *target)?
                    };
                }
            }
        }
        next.validate_target(&url)?;
        for (field, target) in [
            ("binddn", &mut next.binddn),
            ("userdn", &mut next.userdn),
            ("userattr", &mut next.userattr),
            ("userfilter", &mut next.userfilter),
            ("groupdn", &mut next.groupdn),
            ("groupattr", &mut next.groupattr),
            ("groupfilter", &mut next.groupfilter),
        ] {
            if let Some(value) = body.get(field) {
                *target = if value.is_null() {
                    String::new()
                } else {
                    string_field(body, field)?.to_owned()
                };
                if field == "userattr" {
                    target.make_ascii_lowercase();
                }
            }
        }
        if let Some(value) = body.get("bindpass") {
            next.bindpass = ProviderCredential::new(if value.is_null() {
                ""
            } else {
                string_field(body, "bindpass")?
            });
        }
        for (field, target) in [
            ("case_sensitive_names", &mut next.case_sensitive_names),
            ("username_as_alias", &mut next.username_as_alias),
        ] {
            if let Some(value) = body.get(field) {
                *target = if value.is_null() {
                    false
                } else {
                    boolean(body, field, *target)?
                };
            }
        }
        if body.get("token_bound_cidrs").is_some() {
            next.bound_cidrs = token_cidrs::field(body)?;
        }
        if let Some(value) = body.get("token_no_default_policy") {
            next.token_no_default_policy = if value.is_null() {
                false
            } else {
                boolean(
                    body,
                    "token_no_default_policy",
                    next.token_no_default_policy,
                )?
            };
        }
        if body.get("token_policies").is_some() {
            next.token_policies_configured = Some(true);
            next.token_policies = names(body, "token_policies")?;
        }
        for (field, target) in [
            ("token_ttl", &mut next.token_ttl),
            ("token_max_ttl", &mut next.token_max_ttl),
            ("token_period", &mut next.token_period),
            ("token_explicit_max_ttl", &mut next.token_explicit_max_ttl),
        ] {
            if body.get(field).is_some_and(|v| !v.is_null()) {
                *target = duration(body, field, *target)?;
            }
        }
        if let Some(value) = body.get("token_num_uses") {
            next.token_num_uses = if value.is_null() {
                0
            } else {
                number(body, "token_num_uses", next.token_num_uses)?
            };
        }
        next.validate()?;
        self.validate_assignment(actor, &next.token_policies)?;
        let next = LdapMount {
            url,
            bind_dn: String::new(),
            user_dn_template: String::new(),
            starttls: false,
            group_dn: String::new(),
            group_attr: String::new(),
            group_name_attr: String::new(),
            native: Some(Box::new(next)),
        };
        let changed = self
            .ldap_mounts
            .entry(scope.namespace.into())
            .or_default()
            .insert(scope.mount.into(), next.clone())
            .as_ref()
            != Some(&next);
        Ok(empty(changed))
    }
    pub(super) fn ldap_native_user_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        self.ldap_native_mapping_route(principal, scope, method, path, body, now, true)
    }
    pub(super) fn ldap_native_group_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        self.ldap_native_mapping_route(principal, scope, method, path, body, now, false)
    }
    #[allow(clippy::too_many_arguments)]
    fn ldap_native_mapping_route(
        &mut self,
        principal: Option<&Principal>,
        scope: AuthScope<'_>,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
        user: bool,
    ) -> Result<AuthResponse, AuthError> {
        let prefix = format!(
            "auth/{}/{}",
            scope.mount,
            if user { "users" } else { "groups" }
        );
        let raw = path
            .strip_prefix(&prefix)
            .ok_or_else(|| bad("invalid LDAP mapping route"))?
            .trim_start_matches('/');
        let capability = route_capability(method, raw.is_empty())?;
        let actor = self.permission(principal, scope.namespace, path, capability, now)?;
        let config = self.ldap_native_at(scope).ok_or_else(denied)?;
        if raw.is_empty() {
            if capability != "list" {
                return Err(err(405, "method not allowed"));
            }
            reject_unknown(body, &[])?;
            let keys: Vec<String> = if user {
                self.ldap_native_users
                    .get(scope.namespace)
                    .and_then(|m| m.get(scope.mount))
                    .map(|m| m.keys().cloned().collect())
                    .unwrap_or_default()
            } else {
                self.ldap_groups_at(scope)
                    .map(|m| m.keys().cloned().collect())
                    .unwrap_or_default()
            };
            if keys.is_empty() {
                return Err(err(404, "LDAP mappings not found"));
            }
            return Ok(response(json!({"keys":keys}), false));
        }
        if !valid_name(raw) {
            return Err(bad("invalid LDAP mapping name"));
        }
        // OpenBao's delete path intentionally uses the literal storage key.
        let name = if capability == "delete" {
            raw.to_owned()
        } else {
            config.canonical(raw)
        };
        if capability == "read" {
            reject_unknown(body, &[])?;
            let data = if user {
                let entry = self
                    .ldap_native_user_at(scope, &name)
                    .ok_or_else(|| err(404, "LDAP user mapping not found"))?;
                json!({"groups":entry.groups.iter().cloned().collect::<Vec<_>>().join(","),"policies":entry.policies})
            } else {
                json!({"policies":self.ldap_groups_at(scope).and_then(|m|m.get(&name)).ok_or_else(||err(404,"LDAP group mapping not found"))?})
            };
            return Ok(response(data, false));
        }
        self.authorize_request(actor, scope.namespace, path, "sudo", now)?;
        if capability == "delete" {
            reject_unknown(body, &[])?;
            let removed = if user {
                self.ldap_native_users
                    .get_mut(scope.namespace)
                    .and_then(|m| m.get_mut(scope.mount))
                    .and_then(|m| m.remove(&name))
                    .is_some()
            } else {
                self.ldap_groups_at_mut(scope).remove(&name).is_some()
            };
            return Ok(empty(removed));
        }
        if capability != "update" {
            return Err(err(405, "method not allowed"));
        }
        reject_unknown(
            body,
            if user {
                &["groups", "policies"]
            } else {
                &["policies"]
            },
        )?;
        let mapped = names(body, "policies")?;
        self.validate_assignment(actor, &mapped)?;
        if user {
            let groups = names(body, "groups")?
                .into_iter()
                .map(|g| config.canonical(&g))
                .collect();
            let next = LdapNativeUser {
                groups,
                policies: mapped,
            };
            let entries = self
                .ldap_native_users
                .entry(scope.namespace.into())
                .or_default()
                .entry(scope.mount.into())
                .or_default();
            if entries.len() >= 1024 && !entries.contains_key(&name) {
                return Err(err(507, "LDAP user mapping capacity exceeded"));
            }
            let changed = entries.insert(name, next.clone()).as_ref() != Some(&next);
            Ok(empty(changed))
        } else {
            let entries = self.ldap_groups_at_mut(scope);
            if entries.len() >= 1024 && !entries.contains_key(&name) {
                return Err(err(507, "LDAP group mapping capacity exceeded"));
            }
            let changed = entries.insert(name, mapped.clone()).as_ref() != Some(&mapped);
            Ok(empty(changed))
        }
    }
    pub(super) fn prepare_native_ldap_login(
        &self,
        scope: AuthScope<'_>,
        name: &str,
        body: &Value,
        config: LdapMount,
        now: u64,
        origin_peer: Option<std::net::IpAddr>,
    ) -> Result<LdapLoginPlan, AuthError> {
        reject_unknown(body, &["password"])?;
        let native = config.native.as_ref().ok_or_else(denied)?;
        token_cidrs::check(&native.bound_cidrs, origin_peer)?;
        let username = native.canonical(name.trim());
        if !valid_name(&username) {
            return Err(bad("invalid LDAP username"));
        }
        let password = string_field(body, "password")?;
        if password.is_empty() || password.len() > 1024 || password.contains('\0') {
            return Err(bad("invalid LDAP credential"));
        }
        Ok(LdapLoginPlan {
            origin_peer,
            namespace: scope.namespace.into(),
            mount: scope.mount.into(),
            mount_revision: self
                .effective_auth_mounts(scope.namespace)
                .get(scope.mount)
                .cloned()
                .ok_or_else(denied)?,
            native_revision: Some(self.ldap_native_local_revision(scope, &username)?),
            name: username,
            dn: String::new(),
            config,
            password: Zeroizing::new(password.to_owned()),
            totp_code: None,
            now,
            started: std::time::Instant::now(),
        })
    }
    fn native_ldap_authority(
        &self,
        scope: AuthScope<'_>,
        username: &str,
        directory_groups: BTreeSet<String>,
    ) -> Result<(BTreeSet<String>, BTreeSet<String>), AuthError> {
        let config = self.ldap_native_at(scope).ok_or_else(denied)?;
        let mut groups = directory_groups;
        let mut assigned = config.token_policies.clone();
        if let Some(user) = self.ldap_native_user_at(scope, &config.canonical(username)) {
            groups.extend(user.groups.iter().cloned());
            assigned.extend(user.policies.iter().cloned());
        }
        if let Some(mappings) = self.ldap_groups_at(scope) {
            for group in &groups {
                if let Some(mapped) = mappings.get(&config.canonical(group)) {
                    assigned.extend(mapped.iter().cloned());
                }
            }
        }
        Ok((assigned, groups))
    }
    pub(super) fn finish_native_ldap_login(
        &mut self,
        plan: LdapLoginPlan,
        observation: LdapLoginObservation,
    ) -> Result<AuthResponse, AuthError> {
        let scope = AuthScope {
            namespace: &plan.namespace,
            mount: &plan.mount,
        };
        if Some(self.ldap_native_local_revision(scope, &plan.name)?) != plan.native_revision {
            return Err(err(409, "LDAP mapping changed during provider request"));
        }
        let config = plan.config.native.as_ref().ok_or_else(denied)?;
        token_cidrs::check(&config.bound_cidrs, plan.origin_peer)?;
        let alias = observation
            .alias
            .ok_or_else(|| bad("native LDAP observation missing alias"))?;
        if alias.is_empty() || alias.len() > 1024 || alias.chars().any(char::is_control) {
            return Err(bad("invalid LDAP alias"));
        }
        let (mut policies, groups) =
            self.native_ldap_authority(scope, &plan.name, observation.groups)?;
        if !config.token_no_default_policy {
            policies.insert("default".into());
        }
        let now = plan.observed_now();
        let mut response = self.issue_native_online_token(
            scope,
            &alias,
            NativeOnlineToken {
                bound_cidrs: config.bound_cidrs.clone(),
                policies,
                limits: config.limits(),
                explicit_max_ttl: config.token_explicit_max_ttl,
                uses: config.token_num_uses,
                provenance: TokenAuthProvenance::LdapNative {
                    username: plan.name.clone(),
                    alias: alias.clone(),
                    credential: ProviderCredential::new(&plan.password),
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
        response.body["auth"]["metadata"] = json!({"username":plan.name});
        response.external_groups = Some(identity::ExternalGroups {
            mount: plan.mount,
            alias,
            names: groups,
        });
        Ok(response)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn finish_native_ldap_renewal(
        &mut self,
        scope: AuthScope<'_>,
        target: &str,
        username: &str,
        directory_groups: BTreeSet<String>,
        increment: u64,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let token = self.active_token(target, now, false)?;
        let Some(TokenAuthProvenance::LdapNative { alias, .. }) = &token.auth_provenance else {
            return Err(denied());
        };
        let alias = alias.clone();
        let (policies, groups) = self.native_ldap_authority(scope, username, directory_groups)?;
        let config = self.ldap_native_at(scope).ok_or_else(denied)?;
        // Upstream EquivalentPolicies distinguishes nil from an explicit empty
        // list. Empty local mappings do not turn an omitted config list non-nil.
        let nil_policies = config.token_policies_configured == Some(false) && policies.is_empty();
        if nil_policies && token.policies.is_empty() || !same_policies(&policies, &token.policies) {
            return Err(err(500, "policies have changed, not renewing"));
        }
        let expiry = self.native_token_expiry(
            scope,
            config.limits(),
            token.created_at,
            token.max_expires_at,
            increment,
            now,
        )?;
        let token = self.tokens.get_mut(target).ok_or_else(denied)?;
        token.expires_at = Some(expiry);
        let mut response = AuthResponse {
            login_identity: None,
            external_groups: Some(identity::ExternalGroups {
                mount: scope.mount.into(),
                alias,
                names: groups,
            }),
            status: 200,
            mutated: true,
            body: json!({"auth":{"accessor":token.accessor,"policies":token.policies,"token_policies":token.policies,
                "entity_id":token.entity_id.as_deref().unwrap_or(""),"metadata":{"username":username},
                "lease_duration":expiry-now,"renewable":true,"token_type":"service"}}),
        };
        if token.policies.is_empty() {
            response.body["auth"]
                .as_object_mut()
                .ok_or_else(denied)?
                .remove("token_policies");
        }
        Ok(response)
    }
    pub(crate) fn has_ldap_no_default_policy(&self) -> bool {
        self.ldap_mounts.values().any(|mounts| {
            mounts.values().any(|mount| {
                mount.native.as_ref().is_some_and(|config| {
                    config.token_no_default_policy || config.token_policies_configured.is_some()
                })
            })
        }) || self.tokens.values().any(|token| {
            matches!(
                token.auth_provenance,
                Some(TokenAuthProvenance::LdapNative { .. })
            ) && !token.policies.contains("default")
        })
    }
    pub(crate) fn has_native_ldap_transport(&self) -> bool {
        self.ldap_mounts.values().any(|mounts| {
            mounts.values().any(|mount| {
                mount
                    .native
                    .as_ref()
                    .is_some_and(|native| native.transport.is_some())
            })
        })
    }
    pub(crate) fn has_native_ldap_state(&self) -> bool {
        self.ldap_mounts
            .values()
            .any(|m| m.values().any(|c| c.native.is_some()))
            || self
                .ldap_native_users
                .values()
                .any(|m| m.values().any(|u| !u.is_empty()))
            || self.tokens.values().any(|t| {
                matches!(
                    t.auth_provenance,
                    Some(TokenAuthProvenance::LdapNative { .. })
                )
            })
    }
    pub(crate) fn validate_native_ldap_state(&self) -> Result<(), AuthError> {
        for (ns, mounts) in &self.ldap_mounts {
            for (mount, config) in mounts {
                if let Some(native) = &config.native {
                    if !self.online_mount_enabled(ns, mount, "ldap")
                        || config.starttls
                        || !config.bind_dn.is_empty()
                        || !config.user_dn_template.is_empty()
                        || !config.group_dn.is_empty()
                        || !config.group_attr.is_empty()
                        || !config.group_name_attr.is_empty()
                        || native.validate_target(&config.url).is_err()
                    {
                        return Err(bad("invalid native LDAP mount"));
                    }
                    native.validate()?;
                }
            }
        }
        for (ns, mounts) in &self.ldap_native_users {
            for (mount, users) in mounts {
                if users.len() > 1024
                    || (!users.is_empty()
                        && self
                            .ldap_native_at(AuthScope {
                                namespace: ns,
                                mount,
                            })
                            .is_none())
                {
                    return Err(bad("invalid native LDAP mappings"));
                }
                for (name, user) in users {
                    if !valid_name(name)
                        || user.groups.len() > 128
                        || user.policies.len() > 128
                        || user.groups.iter().any(|g| !valid_name(g))
                        || user.policies.iter().any(|p| !valid_name(p) || p == "root")
                    {
                        return Err(bad("invalid native LDAP user mapping"));
                    }
                }
            }
        }
        for token in self.tokens.values() {
            if let Some(TokenAuthProvenance::LdapNative {
                username,
                alias,
                credential,
            }) = &token.auth_provenance
                && (token.root
                    || token.parent.is_some()
                    || !token.auth_origin_known
                    || token.wrapping.is_some()
                    || token.period > MAX_TTL
                    || !valid_name(username)
                    || alias.is_empty()
                    || alias.len() > 1024
                    || alias.chars().any(char::is_control)
                    || credential.0.is_empty()
                    || credential.0.len() > 1024
                    || credential.0.contains('\0')
                    || token.policies.contains("root")
                    || !token.auth_mount.as_ref().is_some_and(|mount| {
                        self.ldap_native_at(AuthScope {
                            namespace: &token.namespace,
                            mount,
                        })
                        .is_some()
                    }))
            {
                return Err(bad("invalid native LDAP renewal provenance"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "auth_ldap_native_tests.rs"]
mod tests;
