//! Bounded OpenBao 2.7.1 quota profile: root-owned native AppRole mount/login
//! rules. Definitions are encrypted Auth owner data; per-IP buckets are node RAM.
use super::*;
pub(crate) const STATE_SCHEMA: u32 = 134;
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
}
impl Definition {
    pub(crate) fn tokens(&self) -> u64 {
        (self.rate.round() as u64).max(1)
    }
    fn data(&self) -> Value {
        json!({"type":"rate-limit","name":self.name,"path":self.path,"role":self.role,
            "rate":self.rate,"interval":self.interval,"block_interval":self.block_interval,"inheritable":false})
    }
    fn validate(&self) -> Result<(), AuthError> {
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
        if self.enable_rate_limit_audit_logging || self.enable_rate_limit_response_headers {
            return Err(bad(
                "quota audit-device and response-header options are outside this bounded profile",
            ));
        }
        if self.rate_limit_exempt_paths.len() > 128 {
            return Err(bad("too many quota exempt paths"));
        }
        for p in &self.rate_limit_exempt_paths {
            validate_path(p, false)?;
        }
        Ok(())
    }
    pub(crate) fn exempt(&self, path: &str) -> bool {
        // Upstream PathManager uses prefix exemptions, rather than a bearer or
        // caller-supplied header. Stored paths are canonical and bounded.
        self.rate_limit_exempt_paths
            .iter()
            .any(|p| path.starts_with(p))
    }
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registry {
    pub(crate) config: Config,
    pub(crate) definitions: BTreeMap<String, Definition>,
    next_revision: u64,
    #[serde(skip)]
    pub(crate) runtime_owner: std::sync::Arc<()>,
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            config: Config::default(),
            definitions: BTreeMap::new(),
            next_revision: 1,
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
        let mut factors = BTreeSet::new();
        for (name, d) in &self.definitions {
            d.validate()?;
            if &d.name != name
                || d.revision >= self.next_revision
                || !factors.insert((&d.path, &d.role))
            {
                return Err(bad("invalid or conflicting quota definition"));
            }
        }
        Ok(())
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
    pub(crate) fn ensure_rate_limit_quotas_allow_remount(
        &self,
        namespace: &str,
        mount: &str,
    ) -> Result<(), AuthError> {
        let prefix = format!("auth/{mount}/");
        if namespace.is_empty()
            && self.rate_limit_quotas.as_ref().is_some_and(|r| {
                r.definitions
                    .values()
                    .any(|d| d.path == prefix || d.path == format!("{prefix}login"))
            })
        {
            return Err(bad(
                "remount of a mount with rate limit quotas is outside this bounded profile",
            ));
        }
        Ok(())
    }
    /// Preserve process-local quota ownership only after native readback has
    /// proved the complete Auth owner equal to the admitted candidate. Cold
    /// readers and snapshot activation do not call this hook.
    #[cfg(feature = "fixture-native-v6-service")]
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
    pub(crate) fn validate_rate_limit_quota_state(
        &self,
        previous: Option<&Self>,
    ) -> Result<(), AuthError> {
        if previous.is_some_and(Self::has_rate_limit_quota_state)
            && self.rate_limit_quotas.is_none()
        {
            return Err(bad("quota reader floor cannot be removed"));
        }
        if let Some(registry) = &self.rate_limit_quotas {
            registry.validate()?;
        }
        Ok(())
    }
    pub(crate) fn rate_limit_quota_registry(&self) -> Option<&Registry> {
        self.rate_limit_quotas.as_ref()
    }
    /// Resolves only the live native catalog and role_id, without consuming SID,
    /// authenticating a token, or invoking a plugin/provider.
    pub(crate) fn rate_limit_approle_scope(
        &self,
        namespace: &str,
        _method: &str,
        path: &str,
        body: &Value,
    ) -> Result<Option<(String, String)>, AuthError> {
        if !namespace.is_empty() {
            return Ok(None);
        }
        let Some(relative) = path.strip_prefix("auth/") else {
            return Ok(None);
        };
        let mounts = self.effective_auth_mounts(namespace);
        let Some((mount, entry, _suffix)) = mounts.iter().find_map(|(mount, entry)| {
            relative
                .strip_prefix(&format!("{mount}/"))
                .map(|suffix| (mount, entry, suffix))
        }) else {
            return Ok(None);
        };
        if entry.kind != "approle" {
            return Ok(None);
        }
        let prefix = format!("auth/{mount}/");
        let has_role_quota = self.rate_limit_quotas.as_ref().is_some_and(|r| {
            r.definitions
                .values()
                .any(|d| d.path == prefix && !d.role.is_empty())
        });
        // The 2.7.1 HTTP quota owner resolves the fixed login role for all
        // requests on a mount with role rules. Resolution failure is an empty
        // role, so the exact path and mount fallback counters still apply.
        // Authentication and its stricter body validation happen afterward.
        let role = if has_role_quota {
            body.get("role_id")
                .and_then(Value::as_str)
                .and_then(|role_id| {
                    self.roles_at(AuthScope { namespace, mount })
                        .and_then(|roles| roles.iter().find(|(_, r)| r.role_id == role_id.trim()))
                })
                .map(|(name, _)| name.clone())
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(Some((prefix, role)))
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
        let actor = principal.ok_or_else(|| err(403, "missing client token"))?;
        let capability = match method {
            "GET" => "read",
            "LIST" => "list",
            "DELETE" => "delete",
            "POST" | "PUT" => "update",
            _ => return Err(err(405, "unsupported quota operation")),
        };
        self.authorize_request(actor, namespace, path, capability, now)?;
        if !namespace.is_empty() {
            return Err(bad("quota administration supports the root namespace only"));
        }
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
                    self.rate_limit_quotas
                        .get_or_insert_with(Registry::default)
                        .config = config;
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
                self.rate_limit_quotas
                    .get_or_insert_with(Registry::default)
                    .definitions
                    .remove(name);
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
                if body.get("name").is_some_and(|v| v.as_str() != Some(name)) {
                    return Err(bad("quota name does not match route"));
                }
                if boolean(body, "inheritable", false)? {
                    return Err(bad("inheritable quotas are outside this bounded profile"));
                }
                let supplied = string_field(body, "path")?.trim_matches('/');
                let role = body
                    .get("role")
                    .map(|v| v.as_str().ok_or_else(|| bad("quota role must be string")))
                    .transpose()?
                    .unwrap_or("");
                let relative = supplied.strip_prefix("auth/").ok_or_else(|| {
                    bad("quota path must identify a native AppRole mount or login")
                })?;
                let mounts = self.effective_auth_mounts("");
                let (mount, login_suffix) =
                    if mounts.get(relative).is_some_and(|m| m.kind == "approle") {
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
                let path = if login_suffix {
                    supplied.to_owned()
                } else {
                    format!("{supplied}/")
                };
                let rate = body
                    .get("rate")
                    .and_then(Value::as_f64)
                    .ok_or_else(|| bad("rate is invalid"))?;
                let interval = duration(body, "interval", 1)?.max(1);
                let block_interval = duration(body, "block_interval", 0)?;
                let registry = self.rate_limit_quotas.get_or_insert_with(Registry::default);
                if registry
                    .definitions
                    .get(name)
                    .is_some_and(|d| d.role != role)
                {
                    return Err(bad("changing a quota role is outside this bounded profile"));
                }
                if registry
                    .definitions
                    .values()
                    .any(|d| d.name != name && d.path == path && d.role == role)
                {
                    return Err(bad("quota rule with similar properties exists"));
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
                let definition = Definition {
                    name: name.into(),
                    path,
                    role: role.into(),
                    rate,
                    interval,
                    block_interval,
                    revision,
                };
                definition.validate()?;
                registry.next_revision = next_revision;
                registry.definitions.insert(name.into(), definition);
                Ok(empty(true))
            }
            _ => Err(err(405, "unsupported quota operation")),
        }
    }
}
