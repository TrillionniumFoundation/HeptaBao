//! OpenBao quota definitions are encrypted Auth owner data. Actual catalog
//! factors are distinct from the public path; per-IP buckets remain node RAM.
use super::*;
#[path = "auth_rate_limit_quota_selectors.rs"]
mod selectors;
pub(crate) use selectors::{Selector, Target};
#[path = "auth_rate_limit_quota_remount.rs"]
mod remount;
#[cfg(feature = "native-v6-storage")]
#[path = "auth_rate_limit_quota_retirement.rs"]
mod retirement;
#[cfg(feature = "native-v6-storage")]
pub(crate) use retirement::MountRetirement;
pub(crate) const STATE_SCHEMA: u32 = 134;
// Keep the original reader contract for existing AppRole-only registries.
// Header-enabled or global quotas irreversibly adopt the extended contract.
pub(crate) const EXTENDED_STATE_SCHEMA: u32 = 137;
pub(crate) const SCOPED_STATE_SCHEMA: u32 = 139;
const MAX_QUOTAS: usize = 256;
const MAX_DURATION: u64 = 86400 * 30;
const MAX_RATE: f64 = 1_000_000.0;
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Definition {
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) role: String,
    pub(crate) rate: f64,
    pub(crate) interval: u64,
    pub(crate) block_interval: u64,
    pub(crate) revision: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(crate) inheritable: bool,
}
impl Definition {
    pub(crate) fn tokens(&self) -> u64 {
        (self.rate.round() as u64).max(1)
    }
    fn data(&self) -> Value {
        json!({"type":"rate-limit","name":self.name,"path":self.path,"role":self.role,
            "rate":self.rate,"interval":self.interval,"block_interval":self.block_interval,"inheritable":self.inheritable})
    }
    fn validate_limits(&self) -> Result<(), AuthError> {
        valid_name(&self.name)?;
        if !self.rate.is_finite()
            || self.rate <= 0.0
            || self.rate > MAX_RATE
            || self.interval == 0
            || self.interval > MAX_DURATION
            || self.block_interval > MAX_DURATION
            || self.revision == 0
            || self.role.len() > 256
            || self.role.contains('/')
        {
            return Err(bad("invalid bounded rate limit definition"));
        }
        Ok(())
    }
    fn validate(&self) -> Result<(), AuthError> {
        self.validate_limits()?;
        if self.path.is_empty() {
            return if self.role.is_empty() {
                Ok(())
            } else {
                Err(bad("global quotas cannot select a login role"))
            };
        }
        if self.inheritable {
            return Err(bad("only namespace quotas can be inheritable"));
        }
        let relative = self
            .path
            .strip_prefix("auth/")
            .ok_or_else(|| bad("quota path must identify a native AppRole mount or login"))?;
        let mount = if let Some(mount) = relative
            .strip_suffix("/login")
            .filter(|_| self.role.is_empty())
        {
            mount
        } else {
            relative
                .strip_suffix('/')
                .ok_or_else(|| bad("invalid canonical quota path"))?
        };
        validate_path(mount, false)?;
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) rate_limit_exempt_paths: Vec<String>,
    pub(crate) enable_rate_limit_audit_logging: bool,
    pub(crate) enable_rate_limit_response_headers: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            rate_limit_exempt_paths: [
                "sys/generate-recovery-token/attempt",
                "sys/generate-recovery-token/update",
                "sys/generate-root/attempt",
                "sys/generate-root/update",
                "sys/health",
                "sys/seal-status",
                "sys/unseal",
            ]
            .iter()
            .map(|p| (*p).into())
            .collect(),
            enable_rate_limit_audit_logging: false,
            enable_rate_limit_response_headers: false,
        }
    }
}
impl Config {
    fn validate(&self) -> Result<(), AuthError> {
        if self.enable_rate_limit_audit_logging {
            return Err(bad(
                "quota audit-device option is outside this bounded profile",
            ));
        }
        if self.rate_limit_exempt_paths.len() > 128 {
            return Err(bad("too many quota exempt paths"));
        }
        for p in &self.rate_limit_exempt_paths {
            if p.len() > 4096 {
                return Err(bad("quota exemption path is outside bounded text limits"));
            }
        }
        Ok(())
    }
    fn needs_path_manager(&self) -> bool {
        self.rate_limit_exempt_paths.iter().any(|path| {
            path.starts_with('!') || path.ends_with('*') || validate_path(path, false).is_err()
        })
    }
    fn exempt(&self, path: &str, path_manager: bool) -> bool {
        if !path_manager {
            // Historical 134/137 accepted literal !/* text. Preserve that
            // admitted encoding and behavior until an explicit config write
            // adopts the new mode; a generic quota alone cannot reinterpret it.
            return self
                .rate_limit_exempt_paths
                .iter()
                .any(|prefix| path.starts_with(prefix));
        }
        // Upstream PathManager ignores empty entries, removes exactly one
        // trailing star, then chooses the longest prefix. The last configured
        // value replaces an identical prefix, including an earlier exception.
        self.rate_limit_exempt_paths
            .iter()
            .enumerate()
            .filter_map(|(index, value)| {
                if value.is_empty() {
                    return None;
                }
                let (value, exception) = value
                    .strip_prefix('!')
                    .map_or((value.as_str(), false), |value| (value, true));
                let prefix = value.strip_suffix('*').unwrap_or(value);
                path.starts_with(prefix)
                    .then_some(((prefix.len(), index), !exception))
            })
            .max_by_key(|(rank, _)| *rank)
            .is_some_and(|(_, exempt)| exempt)
    }
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registry {
    pub(crate) config: Config,
    pub(crate) definitions: BTreeMap<String, Definition>,
    next_revision: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    extended_reader: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    scoped_reader: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    path_manager_exemptions: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    selectors: BTreeMap<String, Selector>,
    #[serde(skip)]
    pub(crate) runtime_owner: std::sync::Arc<()>,
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            config: Config::default(),
            definitions: BTreeMap::new(),
            next_revision: 1,
            extended_reader: false,
            scoped_reader: false,
            path_manager_exemptions: false,
            selectors: BTreeMap::new(),
            runtime_owner: std::sync::Arc::new(()),
        }
    }
}
impl Registry {
    fn validate(&self) -> Result<(), AuthError> {
        self.config.validate()?;
        if self.definitions.len() > MAX_QUOTAS || self.next_revision == 0 {
            return Err(bad("invalid quota registry"));
        }
        if !self.extended_reader
            && (self.config.enable_rate_limit_response_headers
                || self
                    .definitions
                    .values()
                    .any(|definition| definition.path.is_empty()))
        {
            return Err(bad("extended quota reader marker is required"));
        }
        if (!self.scoped_reader && (!self.selectors.is_empty() || self.path_manager_exemptions))
            || self
                .selectors
                .keys()
                .any(|name| !self.definitions.contains_key(name))
        {
            return Err(bad(
                "scoped quota reader marker or selector owner is invalid",
            ));
        }
        if !self.path_manager_exemptions {
            for path in &self.config.rate_limit_exempt_paths {
                validate_path(path, false)?;
            }
        }
        let mut factors = BTreeSet::new();
        for (name, d) in &self.definitions {
            let selector = match self.selectors.get(name) {
                Some(selector) => {
                    selector.validate(d)?;
                    selector.clone()
                }
                None => Selector::legacy(d)?,
            };
            if &d.name != name
                || d.revision >= self.next_revision
                || !factors.insert((selector, &d.role))
            {
                return Err(bad("invalid or conflicting quota definition"));
            }
        }
        Ok(())
    }
    pub(crate) fn exempt(&self, path: &str) -> bool {
        self.config.exempt(path, self.path_manager_exemptions)
    }
}
fn valid_name(name: &str) -> Result<(), AuthError> {
    if name.is_empty()
        || name.len() > 256
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(bad("invalid quota name"));
    }
    Ok(())
}
impl AuthState {
    /// Preserve process-local quota ownership only after native readback has
    /// proved the complete Auth owner equal to the admitted candidate. Cold
    /// readers and snapshot activation do not call this hook.
    #[cfg(feature = "native-v6-storage")]
    pub(crate) fn retain_quota_runtime_owner(&mut self, candidate: &Self) -> Result<(), AuthError> {
        match (&mut self.rate_limit_quotas, &candidate.rate_limit_quotas) {
            (None, None) => Ok(()),
            (Some(installed), Some(admitted)) => {
                let actual =
                    crate::secret_serde::to_vec(installed, crate::MAX_APPLICATION_STATE_BYTES)
                        .map_err(|_| err(503, "native quota owner serialization failed"))?;
                let expected =
                    crate::secret_serde::to_vec(admitted, crate::MAX_APPLICATION_STATE_BYTES)
                        .map_err(|_| err(503, "native quota owner serialization failed"))?;
                if actual.as_slice() != expected.as_slice() {
                    return Err(err(
                        503,
                        "native quota owner does not match admitted definitions",
                    ));
                }
                installed.runtime_owner = std::sync::Arc::clone(&admitted.runtime_owner);
                Ok(())
            }
            _ => Err(err(503, "native quota owner presence changed")),
        }
    }

    pub(crate) fn has_rate_limit_quota_state(&self) -> bool {
        self.rate_limit_quotas.is_some()
    }
    pub(crate) fn has_extended_rate_limit_quota_state(&self) -> bool {
        self.rate_limit_quotas
            .as_ref()
            .is_some_and(|registry| registry.extended_reader)
    }
    pub(crate) fn has_scoped_rate_limit_quota_state(&self) -> bool {
        self.rate_limit_quotas
            .as_ref()
            .is_some_and(|registry| registry.scoped_reader)
    }
    pub(crate) fn validate_rate_limit_quota_state(
        &self,
        previous: Option<&Self>,
    ) -> Result<(), AuthError> {
        if previous.is_some_and(Self::has_rate_limit_quota_state)
            && self.rate_limit_quotas.is_none()
        {
            return Err(bad("quota reader floor cannot be removed"));
        }
        if previous.is_some_and(Self::has_extended_rate_limit_quota_state)
            && !self.has_extended_rate_limit_quota_state()
        {
            return Err(bad("extended quota reader floor cannot be removed"));
        }
        if previous.is_some_and(Self::has_scoped_rate_limit_quota_state)
            && !self.has_scoped_rate_limit_quota_state()
        {
            return Err(bad("scoped quota reader floor cannot be removed"));
        }
        if previous
            .and_then(|state| state.rate_limit_quotas.as_ref())
            .is_some_and(|registry| registry.path_manager_exemptions)
            && self
                .rate_limit_quotas
                .as_ref()
                .is_none_or(|registry| !registry.path_manager_exemptions)
        {
            return Err(bad("quota exemption interpretation cannot be downgraded"));
        }
        if let Some(registry) = &self.rate_limit_quotas {
            registry.validate()?;
        }
        Ok(())
    }
    pub(crate) fn rate_limit_quota_registry(&self) -> Option<&Registry> {
        self.rate_limit_quotas.as_ref()
    }
    pub(super) fn quota_known_namespaces(&self) -> BTreeSet<String> {
        self.rate_limit_quotas
            .as_ref()
            .map(|registry| {
                registry
                    .selectors
                    .values()
                    .map(|selector| selector.namespace().to_owned())
                    .filter(|namespace| !namespace.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }
    pub(super) fn quota_namespace_is_empty(&self, namespace: &str) -> bool {
        self.rate_limit_quotas.as_ref().is_none_or(|registry| {
            registry
                .selectors
                .values()
                .all(|selector| selector.namespace() != namespace)
        })
    }
    /// A detached candidate only. The caller must own the actual catalog
    /// retirement; a quota selector never authorizes namespace deletion.
    #[cfg(feature = "native-v6-storage")]
    pub(crate) fn prune_rate_limit_quotas_namespace(
        &mut self,
        namespace: &str,
    ) -> Result<(), AuthError> {
        validate_namespace(namespace)?;
        if namespace.is_empty() {
            return Err(bad("root quota ownership cannot be retired as a child"));
        }
        let Some(registry) = self.rate_limit_quotas.as_mut() else {
            return Ok(());
        };
        registry.validate()?;
        let names: Vec<String> = registry
            .selectors
            .iter()
            .filter(|(_, selector)| selector.namespace() == namespace)
            .map(|(name, _)| name.clone())
            .collect();
        for name in names {
            registry.definitions.remove(&name);
            registry.selectors.remove(&name);
        }
        // Sticky markers, unrelated definitions, revision allocation and all
        // remaining process-local buckets keep their original ownership.
        registry.validate()
    }
    pub(crate) fn prune_rate_limit_quotas_mount(&mut self, namespace: &str, mount: &str) {
        let Some(registry) = self.rate_limit_quotas.as_mut() else {
            return;
        };
        let names: Vec<String> = registry
            .definitions
            .iter()
            .filter_map(|(name, definition)| {
                let matches = match registry.selectors.get(name) {
                    Some(selector) => {
                        selector.namespace() == namespace && selector.mount() == mount
                    }
                    None => {
                        namespace.is_empty()
                            && (definition.path == mount
                                || definition.path == format!("{mount}login"))
                    }
                };
                matches.then(|| name.clone())
            })
            .collect();
        for name in names {
            registry.definitions.remove(&name);
            registry.selectors.remove(&name);
        }
    }
    /// Resolve only local login-role metadata. Failure is the empty-role
    /// fallback used by 2.7.1; this neither authenticates nor consumes a SID.
    pub(crate) fn rate_limit_quota_login_role(
        &self,
        namespace: &str,
        mount_path: &str,
        body: &Value,
        time: AuthorityTime,
        peer_certificates: Option<&[Vec<u8>]>,
    ) -> String {
        let Some(mount) = mount_path
            .strip_prefix("auth/")
            .and_then(|value| value.strip_suffix('/'))
        else {
            return String::new();
        };
        let mounts = self.effective_auth_mounts(namespace);
        let Some(entry) = mounts.get(mount) else {
            return String::new();
        };
        match entry.kind.as_str() {
            "approle" => body
                .get("role_id")
                .and_then(Value::as_str)
                .and_then(|role_id| {
                    self.roles_at(AuthScope { namespace, mount })
                        .and_then(|roles| roles.iter().find(|(_, r)| r.role_id == role_id.trim()))
                })
                .map(|(name, _)| name.clone())
                .unwrap_or_default(),
            "cert" => {
                let requested = match body.get("name") {
                    None => None,
                    Some(value) => match value.as_str().filter(|value| super::valid_name(value)) {
                        Some(name) => Some(name),
                        None => return String::new(),
                    },
                };
                let Some(chain) = peer_certificates else {
                    return String::new();
                };
                let Ok(presented) = parse_presented_certificate(chain, time) else {
                    return String::new();
                };
                let attributes = chain
                    .first()
                    .and_then(|leaf| parse_certificate_attributes(leaf));
                self.cert_roles
                    .get(namespace)
                    .and_then(|mounts| mounts.get(mount))
                    .and_then(|roles| {
                        roles.iter().find(|(name, role)| {
                            requested.is_none_or(|requested| requested == name.as_str())
                                && matches_cert_role(&presented, attributes.as_ref(), role)
                        })
                    })
                    .map(|(name, _)| name.clone())
                    .unwrap_or_default()
            }
            "jwt" => body
                .get("role")
                .and_then(Value::as_str)
                .and_then(|role| {
                    self.jwt_mounts
                        .get(namespace)
                        .and_then(|mounts| mounts.get(mount))
                        .filter(|state| state.config.is_some() && state.roles.contains_key(role))
                        .map(|_| role.to_owned())
                })
                .unwrap_or_default(),
            "oidc" => self
                .oidc_mounts
                .get(namespace)
                .and_then(|mounts| mounts.get(mount))
                .and_then(|state| state.quota_login_role(body))
                .unwrap_or_default(),
            "kubernetes" => self
                .kubernetes_mounts
                .get(namespace)
                .and_then(|mounts| mounts.get(mount))
                .and_then(|state| state.quota_login_role(body))
                .unwrap_or_default(),
            _ => String::new(),
        }
    }
    pub(super) fn rate_limit_quota_route(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        self.rate_limit_quota_route_inner(principal, namespace, method, path, body, now, None)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rate_limit_quota_catalog_route(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
        target: Result<Target, AuthError>,
    ) -> Result<AuthResponse, AuthError> {
        self.rate_limit_quota_route_inner(
            principal,
            namespace,
            method,
            path,
            body,
            now,
            Some(target),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn rate_limit_quota_route_inner(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
        target: Option<Result<Target, AuthError>>,
    ) -> Result<AuthResponse, AuthError> {
        validate_namespace(namespace)?;
        validate_path(path, false)?;
        // OpenBao 2.7.1 restricts quota administration to the root namespace,
        // before bearer authorization. A root request may still select an
        // existing child namespace through its absolute quota path.
        if !namespace.is_empty() {
            return Err(bad("operation only available in root namespace"));
        }
        let actor = principal.ok_or_else(|| err(403, "missing client token"))?;
        let capability = match method {
            "GET" => "read",
            "LIST" => "list",
            "DELETE" => "delete",
            "POST" | "PUT" => "update",
            _ => return Err(err(405, "unsupported quota operation")),
        };
        self.authorize_request(actor, namespace, path, capability, now)?;
        if path == "sys/quotas/config" {
            return match method {
                "GET" => Ok(response(
                    json!(
                        self.rate_limit_quotas
                            .as_ref()
                            .map(|r| r.config.clone())
                            .unwrap_or_default()
                    ),
                    false,
                )),
                "POST" | "PUT" => {
                    reject_unknown(
                        body,
                        &[
                            "rate_limit_exempt_paths",
                            "enable_rate_limit_audit_logging",
                            "enable_rate_limit_response_headers",
                        ],
                    )?;
                    let config = Config {
                        rate_limit_exempt_paths: match body.get("rate_limit_exempt_paths") {
                            None => Vec::new(),
                            Some(v) => v
                                .as_array()
                                .ok_or_else(|| bad("quota exempt paths must be an array"))?
                                .iter()
                                .map(|v| {
                                    v.as_str()
                                        .map(str::to_owned)
                                        .ok_or_else(|| bad("quota exempt paths must be strings"))
                                })
                                .collect::<Result<Vec<_>, _>>()?,
                        },
                        enable_rate_limit_audit_logging: boolean(
                            body,
                            "enable_rate_limit_audit_logging",
                            false,
                        )?,
                        enable_rate_limit_response_headers: boolean(
                            body,
                            "enable_rate_limit_response_headers",
                            false,
                        )?,
                    };
                    config.validate()?;
                    let registry = self.rate_limit_quotas.get_or_insert_with(Registry::default);
                    registry.extended_reader |= config.enable_rate_limit_response_headers;
                    registry.path_manager_exemptions |= config.needs_path_manager();
                    registry.scoped_reader |= registry.path_manager_exemptions;
                    registry.config = config;
                    Ok(empty(true))
                }
                _ => Err(err(405, "unsupported quota configuration operation")),
            };
        }
        if path == "sys/quotas/rate-limit" {
            if method != "LIST" {
                return Err(err(405, "quota collection supports LIST only"));
            }
            let keys = self
                .rate_limit_quotas
                .as_ref()
                .map(|r| r.definitions.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            return if keys.is_empty() {
                Err(err(404, "no quotas found"))
            } else {
                Ok(response(json!({"keys":keys}), false))
            };
        }
        let name = path
            .strip_prefix("sys/quotas/rate-limit/")
            .ok_or_else(|| err(404, "quota route not found"))?;
        valid_name(name)?;
        match method {
            "GET" => self
                .rate_limit_quotas
                .as_ref()
                .and_then(|r| r.definitions.get(name))
                .map(|d| response(d.data(), false))
                .ok_or_else(|| err(404, "quota not found")),
            "DELETE" => {
                let registry = self.rate_limit_quotas.get_or_insert_with(Registry::default);
                registry.definitions.remove(name);
                registry.selectors.remove(name);
                Ok(empty(true))
            }
            "POST" | "PUT" => {
                reject_unknown(
                    body,
                    &[
                        "name",
                        "path",
                        "rate",
                        "interval",
                        "block_interval",
                        "inheritable",
                        "role",
                    ],
                )?;
                // The framework's route capture overrides a body field named
                // `name`; it cannot rename an existing 2.7.1 quota.
                let supplied = body
                    .get("path")
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| bad("quota path must be string"))
                    })
                    .transpose()?
                    .unwrap_or("")
                    .trim_matches('/');
                let role = body
                    .get("role")
                    .map(|v| v.as_str().ok_or_else(|| bad("quota role must be string")))
                    .transpose()?
                    .unwrap_or("");
                let target = if let Some(target) = target {
                    // Catalog lookup errors are delivered only after the
                    // original bearer and namespace capability check above.
                    target?
                } else if supplied.is_empty() {
                    Target::from_catalog("", "", "", false, false)?
                } else {
                    let relative = supplied.strip_prefix("auth/").ok_or_else(|| {
                        bad("quota path must identify a native AppRole mount or login")
                    })?;
                    let mounts = self.effective_auth_mounts("");
                    let (mount, login_suffix) = if mounts
                        .get(relative)
                        .is_some_and(|m| m.kind == "approle")
                    {
                        (relative, false)
                    } else if let Some(mount) = relative.strip_suffix("/login").filter(|mount| {
                        role.is_empty() && mounts.get(*mount).is_some_and(|m| m.kind == "approle")
                    }) {
                        (mount, true)
                    } else {
                        return Err(bad(
                            "quota path must identify an actual native AppRole mount or login",
                        ));
                    };
                    validate_path(mount, false)?;
                    Target::from_catalog(
                        "",
                        &format!("auth/{mount}/"),
                        if login_suffix { "login" } else { "" },
                        true,
                        true,
                    )?
                };
                target.admit_role(role)?;
                let inheritable = boolean(body, "inheritable", target.default_inheritable())?;
                let path = target.selector().path();
                let rate = body
                    .get("rate")
                    .and_then(Value::as_f64)
                    .ok_or_else(|| bad("rate is invalid"))?;
                let interval = duration(body, "interval", 1)?.max(1);
                let block_interval = duration(body, "block_interval", 0)?;
                let registry = self.rate_limit_quotas.get_or_insert_with(Registry::default);
                for definition in registry.definitions.values() {
                    if definition.name != name
                        && definition.role == role
                        && registry.selector_for(definition)? == *target.selector()
                    {
                        return Err(bad("quota rule with similar properties exists"));
                    }
                }
                if registry.definitions.len() >= MAX_QUOTAS
                    && !registry.definitions.contains_key(name)
                {
                    return Err(bad("quota registry is full"));
                }
                let revision = registry.next_revision;
                let next_revision = revision
                    .checked_add(1)
                    .ok_or_else(|| bad("quota revision exhausted"))?;
                // 2.7.1 checks conflicting factors using the requested role,
                // then clones an existing rule without assigning Role. Preserve
                // that stored role while applying the other requested fields.
                let retained_role = registry
                    .definitions
                    .get(name)
                    .map_or_else(|| role.to_owned(), |definition| definition.role.clone());
                let definition = Definition {
                    name: name.into(),
                    path,
                    role: retained_role,
                    rate,
                    interval,
                    block_interval,
                    revision,
                    inheritable,
                };
                target.selector().validate(&definition)?;
                let needs_scoped_reader = target.requires_scoped_reader(&definition);
                if !needs_scoped_reader {
                    definition.validate()?;
                }
                registry.extended_reader |= definition.path.is_empty();
                registry.scoped_reader |= needs_scoped_reader;
                if needs_scoped_reader {
                    registry
                        .selectors
                        .insert(name.into(), target.into_selector());
                } else {
                    registry.selectors.remove(name);
                }
                registry.next_revision = next_revision;
                registry.definitions.insert(name.into(), definition);
                Ok(empty(true))
            }
            _ => Err(err(405, "unsupported quota operation")),
        }
    }
}
