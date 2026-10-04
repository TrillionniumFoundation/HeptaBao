//! Namespaced Token API roles and immutable issued-role provenance.
//! Contracts pinned to OpenBao 2.7.0 token_store.go.
//! R07 was observed before external custody loss; fresh qualification is required.
use super::*;
#[path = "auth_token_role_fields.rs"]
mod fields;
#[path = "auth_token_role_lists.rs"]
mod lists;

const MAX_ROLE_TEXT: usize = 1024 * 1024;
const MAX_ISSUED_ROLE_PATH: usize = MAX_ROLE_TEXT + 8192 + 64;
const MAX_ROLE_DURATION: u64 = i64::MAX as u64 / 1_000_000_000;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Role {
    allowed_policies: BTreeSet<String>,
    disallowed_policies: BTreeSet<String>,
    allowed_policies_glob: BTreeSet<String>,
    disallowed_policies_glob: BTreeSet<String>,
    orphan: bool,
    renewable: bool,
    path_suffix: String,
    token_type: String,
    token_no_default_policy: bool,
    token_num_uses: u64,
    token_period: u64,
    token_explicit_max_ttl: u64,
    period: u64,
    explicit_max_ttl: u64,
    token_bound_cidrs: Vec<String>,
    bound_cidrs: Vec<String>,
    allowed_entity_aliases: Option<BTreeSet<String>>,
}

impl Default for Role {
    fn default() -> Self {
        Self {
            allowed_policies: BTreeSet::new(),
            disallowed_policies: BTreeSet::new(),
            allowed_policies_glob: BTreeSet::new(),
            disallowed_policies_glob: BTreeSet::new(),
            orphan: false,
            renewable: true,
            path_suffix: String::new(),
            token_type: "default-service".into(),
            token_no_default_policy: false,
            token_num_uses: 0,
            token_period: 0,
            token_explicit_max_ttl: 0,
            period: 0,
            explicit_max_ttl: 0,
            token_bound_cidrs: Vec::new(),
            bound_cidrs: Vec::new(),
            allowed_entity_aliases: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IssuedRole {
    pub(super) name: String,
    pub(super) path: String,
}

impl IssuedRole {
    pub(super) fn valid_path(&self) -> bool {
        let expected = format!("auth/token/create/{}", self.name);
        valid_role_name(&self.name)
            && self.path.len() <= MAX_ISSUED_ROLE_PATH
            && self.path.strip_prefix(&expected).is_some_and(|suffix| {
                suffix.is_empty()
                    || suffix
                        .strip_prefix('/')
                        .is_some_and(|suffix| !suffix.is_empty() && valid_suffix(suffix))
            })
    }
}
impl Drop for IssuedRole {
    fn drop(&mut self) {
        self.name.zeroize();
        self.path.zeroize();
    }
}

fn word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
fn valid_role_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 8192
        && name.is_ascii()
        && name.as_bytes().first().is_some_and(|b| word(*b))
        && name.as_bytes().last().is_some_and(|b| word(*b))
        && name.bytes().all(|b| word(b) || b == b'-' || b == b'.')
}
fn valid_suffix(suffix: &str) -> bool {
    if suffix.is_empty() {
        return true;
    }
    if suffix.len() > MAX_ROLE_TEXT || suffix.contains("..") {
        return false;
    }
    // The pinned regexp is unanchored: e.g. !abc! is accepted.
    let mut start = None;
    for (index, byte) in suffix.bytes().enumerate() {
        if word(byte) {
            if start.is_some_and(|begin| index >= begin + 2) {
                return true;
            }
            start.get_or_insert(index);
        } else if byte != b'-' && byte != b'.' {
            start = None;
        }
    }
    false
}
fn role_list(
    body: &Value,
    field: &str,
    collapse_root: bool,
) -> Result<BTreeSet<String>, AuthError> {
    let values = lists::comma_strings(body, field)?;
    let mut result: BTreeSet<String> = values
        .iter()
        .map(|s| token_policies::simple_lowercase(s.trim()))
        .filter(|s| !s.is_empty())
        .collect();
    if collapse_root && result.contains("root") {
        result = BTreeSet::from(["root".into()]);
    }
    Ok(result)
}

impl Role {
    fn update(&mut self, body: &Value) -> Result<Vec<String>, AuthError> {
        let mut warnings = Vec::new();
        for (field, slot, collapse) in [
            ("allowed_policies", &mut self.allowed_policies, true),
            ("disallowed_policies", &mut self.disallowed_policies, false),
            (
                "allowed_policies_glob",
                &mut self.allowed_policies_glob,
                true,
            ),
            (
                "disallowed_policies_glob",
                &mut self.disallowed_policies_glob,
                false,
            ),
        ] {
            if body.get(field).is_some() {
                *slot = role_list(body, field, collapse)?;
            }
        }
        if body.get("orphan").is_some() {
            self.orphan = fields::boolean(body, "orphan")?;
        }
        if body.get("renewable").is_some() {
            self.renewable = fields::boolean(body, "renewable")?;
        }
        if body.get("token_no_default_policy").is_some() {
            self.token_no_default_policy = fields::boolean(body, "token_no_default_policy")?;
        }
        if body.get("path_suffix").is_some() {
            let suffix = lists::string(body, "path_suffix")?;
            if suffix.contains("..") {
                return Err(bad(
                    "error registering path suffix: path cannot contain parent references",
                ));
            }
            if !valid_suffix(&suffix) {
                return Err(bad(
                    r"given role path suffix contains invalid characters; must match \w[\w-.]+\w",
                ));
            }
            self.path_suffix = suffix;
        }
        if let Some(value) = body.get("token_type") {
            if value.is_null() {
                return Err(bad("Invalid 'token_type' value: null"));
            }
            // The official handler panics for numeric/bool Raw values after weak
            // framework validation. Retain a bounded rejection rather than
            // introducing a panic; this transport behavior remains a gap.
            if value.is_array() || value.is_object() {
                lists::string(body, "token_type")?;
            }
            let value = value
                .as_str()
                .ok_or_else(|| bad("token type must be a string"))?;
            if !["service", "batch", "default-service", "default-batch"].contains(&value) {
                return Err(bad(&format!(
                    "invalid 'token_type' value {}",
                    token_policies::quote_policy(value)
                )));
            }
            self.token_type = value.into();
        }
        for (native, legacy, value, legacy_value) in [
            (
                "token_period",
                "period",
                &mut self.token_period,
                &mut self.period,
            ),
            (
                "token_explicit_max_ttl",
                "explicit_max_ttl",
                &mut self.token_explicit_max_ttl,
                &mut self.explicit_max_ttl,
            ),
        ] {
            if body.get(native).is_some_and(|v| !v.is_null()) {
                *value = fields::duration(body, native)?;
                *legacy_value = 0;
                if body.get(legacy).is_some_and(|v| !v.is_null()) {
                    warnings.push(format!("Both '{native}' and deprecated '{legacy}' value supplied, ignoring the deprecated value"));
                }
            } else if body.get(legacy).is_some_and(|v| !v.is_null()) {
                *value = fields::duration(body, legacy)?;
                *legacy_value = *value;
            }
        }
        if body.get("token_bound_cidrs").is_some() {
            self.token_bound_cidrs = lists::cidrs(body, "token_bound_cidrs")?;
            self.bound_cidrs.clear();
            if body.get("bound_cidrs").is_some() {
                warnings.insert(usize::from(warnings.first().is_some_and(|w|w.contains("token_period"))),"Both 'token_bound_cidrs' and deprecated 'bound_cidrs' value supplied, ignoring the deprecated value".into());
            }
        } else if body.get("bound_cidrs").is_some() {
            self.bound_cidrs = lists::cidrs(body, "bound_cidrs")?;
            self.token_bound_cidrs.clone_from(&self.bound_cidrs);
        }
        if self.token_explicit_max_ttl > MAX_TTL {
            warnings.push(format!("Given explicit max TTL of {} is greater than system/mount allowed value of {MAX_TTL} seconds; until this is fixed attempting to create tokens against this role will result in an error",self.token_explicit_max_ttl));
        }
        if body.get("token_num_uses").is_some() {
            self.token_num_uses = fields::uses(body)?;
        }
        if body.get("allowed_entity_aliases").is_some() {
            self.allowed_entity_aliases = Some(role_list(body, "allowed_entity_aliases", false)?);
        }
        self.validate()?;
        Ok(warnings)
    }
    fn validate(&self) -> Result<(), AuthError> {
        if !["service", "batch", "default-service", "default-batch"]
            .contains(&self.token_type.as_str())
            || !valid_suffix(&self.path_suffix)
            || [
                self.period,
                self.token_period,
                self.explicit_max_ttl,
                self.token_explicit_max_ttl,
            ]
            .iter()
            .any(|v| *v > MAX_ROLE_DURATION)
            || self.token_num_uses > i64::MAX as u64
        {
            return Err(bad("invalid persisted token role"));
        }
        token_cidrs::validate(&self.token_bound_cidrs)?;
        token_cidrs::validate(&self.bound_cidrs)?;
        for set in [
            &self.allowed_policies,
            &self.disallowed_policies,
            &self.allowed_policies_glob,
            &self.disallowed_policies_glob,
        ] {
            if set.iter().any(|name| {
                name.is_empty()
                    || name.len() > MAX_ROLE_TEXT
                    || token_policies::simple_lowercase(name.trim()) != *name
            }) {
                return Err(bad("invalid persisted token role policy"));
            }
        }
        if self.allowed_entity_aliases.as_ref().is_some_and(|set| {
            set.iter().any(|name| {
                name.is_empty()
                    || name.len() > MAX_ROLE_TEXT
                    || token_policies::simple_lowercase(name.trim()) != *name
            })
        }) {
            return Err(bad("invalid persisted token role aliases"));
        }
        if self.token_type == "batch" {
            let problem = if !self.orphan {
                Some("non-orphan tokens")
            } else if self.token_period > 0 || self.period > 0 {
                Some("periodic tokens")
            } else if self.renewable {
                Some("renewable tokens")
            } else if self.token_explicit_max_ttl > 0 || self.explicit_max_ttl > 0 {
                Some("tokens with an explicit max TTL")
            } else {
                None
            };
            if let Some(problem) = problem {
                return Err(bad(&format!(
                    "'token_type' cannot be 'batch' when role is set to generate {problem}"
                )));
            }
        }
        Ok(())
    }
    fn info(&self, name: &str) -> Value {
        let mut value = json!({"name":name,"allowed_policies":self.allowed_policies,"disallowed_policies":self.disallowed_policies,"allowed_policies_glob":self.allowed_policies_glob,"disallowed_policies_glob":self.disallowed_policies_glob,"orphan":self.orphan,"renewable":self.renewable,"path_suffix":self.path_suffix,"token_type":self.token_type,"token_no_default_policy":self.token_no_default_policy,"token_period":self.token_period,"period":self.period,"token_explicit_max_ttl":self.token_explicit_max_ttl,"explicit_max_ttl":self.explicit_max_ttl,"allowed_entity_aliases":self.allowed_entity_aliases});
        if self.token_num_uses > 0 {
            value["token_num_uses"] = json!(self.token_num_uses);
        }
        if !self.token_bound_cidrs.is_empty() {
            value["token_bound_cidrs"] = json!(self.token_bound_cidrs);
        }
        if !self.bound_cidrs.is_empty() {
            value["bound_cidrs"] = json!(self.bound_cidrs);
        }
        value
    }
    pub(super) fn restricted(&self) -> bool {
        !self.allowed_policies.is_empty()
            || !self.disallowed_policies.is_empty()
            || !self.allowed_policies_glob.is_empty()
            || !self.disallowed_policies_glob.is_empty()
    }
    pub(super) fn resolve_policies(
        &self,
        input: &[String],
        parent: &Token,
        no_default: bool,
    ) -> Result<BTreeSet<String>, AuthError> {
        let add_default = !no_default
            && !self.token_no_default_policy
            && !self.disallowed_policies.contains("default")
            && !glob_contains(&self.disallowed_policies_glob, "default");
        let mut final_policies = if input.is_empty() {
            BTreeSet::new()
        } else {
            normalize(input, add_default)
        };
        if !self.allowed_policies.is_empty() || !self.allowed_policies_glob.is_empty() {
            let allowed = normalize(
                &self.allowed_policies.iter().cloned().collect::<Vec<_>>(),
                add_default,
            );
            if final_policies.is_empty() {
                final_policies = allowed;
            } else {
                for policy in &final_policies {
                    if !allowed.contains(policy)
                        && !glob_contains(&self.allowed_policies_glob, policy)
                    {
                        return Err(bad(&format!(
                            "token policies ({}) must be subset of the role's allowed policies ({}) or glob policies ({})",
                            quote_list(&final_policies),
                            quote_list(&allowed),
                            quote_list(&self.allowed_policies_glob)
                        )));
                    }
                }
            }
        } else if final_policies.is_empty() {
            final_policies = normalize(
                &parent.policies.iter().cloned().collect::<Vec<_>>(),
                add_default,
            );
        }
        for policy in &final_policies {
            if self.disallowed_policies.contains(policy)
                || glob_contains(&self.disallowed_policies_glob, policy)
            {
                return Err(bad(&format!(
                    "token policy {} is disallowed by this role",
                    token_policies::quote_policy(policy)
                )));
            }
        }
        Ok(final_policies)
    }
    pub(super) fn batch(&self, body: &Value) -> Result<bool, AuthError> {
        match self.token_type.as_str() {
            "service" => Ok(false),
            "batch" => Ok(true),
            "default-batch"
                if body
                    .get("type")
                    .is_none_or(|v| v.is_null() || v.as_str() == Some("")) =>
            {
                Ok(true)
            }
            _ => match body.get("type") {
                None | Some(Value::Null) => Ok(false),
                Some(Value::String(v)) if v.is_empty() || v == "service" => Ok(false),
                Some(Value::String(v)) if v == "batch" => Ok(true),
                _ => Err(bad("invalid token type")),
            },
        }
    }
    pub(super) fn orphan(&self) -> bool {
        self.orphan
    }
    pub(super) fn renewable(&self) -> bool {
        self.renewable
    }
    pub(super) fn bound_cidrs(&self) -> Vec<String> {
        self.token_bound_cidrs.clone()
    }
    pub(super) fn uses(&self, requested: u64) -> u64 {
        lesser_nonzero(requested, self.token_num_uses)
    }
    pub(super) fn effective_period(&self) -> u64 {
        self.token_period
    }
    pub(super) fn explicit_max(&self) -> u64 {
        self.token_explicit_max_ttl
    }
    pub(super) fn issued(&self, name: &str, path: &str) -> IssuedRole {
        IssuedRole {
            name: name.into(),
            path: if self.path_suffix.is_empty() {
                path.into()
            } else {
                format!("{path}/{}", self.path_suffix)
            },
        }
    }
    pub(super) fn alias(&self, body: &Value) -> Result<Option<String>, AuthError> {
        let Some(value) = body.get("entity_alias") else {
            return Ok(None);
        };
        let value = value
            .as_str()
            .ok_or_else(|| bad("invalid 'entity_alias' value"))?;
        if value.is_empty() {
            return Ok(None);
        }
        let normalized = token_policies::simple_lowercase(value);
        if !self.allowed_entity_aliases.as_ref().is_some_and(|allowed| {
            allowed.contains(&normalized) || glob_contains(allowed, &normalized)
        }) {
            return Err(bad("invalid 'entity_alias' value"));
        }
        Ok(Some(value.into()))
    }
}
pub(super) fn lesser_nonzero(left: u64, right: u64) -> u64 {
    match (left, right) {
        (0, v) | (v, 0) => v,
        (a, b) => a.min(b),
    }
}
fn normalize(input: &[String], add_default: bool) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = input
        .iter()
        .map(|s| token_policies::simple_lowercase(s.trim()))
        .filter(|s| !s.is_empty())
        .collect();
    if names.contains("root") {
        return BTreeSet::from(["root".into()]);
    }
    if add_default {
        names.insert("default".into());
    }
    names
}
fn quote_list(set: &BTreeSet<String>) -> String {
    format!(
        "[{}]",
        set.iter()
            .map(|s| token_policies::quote_policy(s))
            .collect::<Vec<_>>()
            .join(" ")
    )
}
fn glob_contains(patterns: &BTreeSet<String>, value: &str) -> bool {
    patterns.iter().any(|pattern| glob_matches(pattern, value))
}
fn glob_matches(pattern: &str, value: &str) -> bool {
    // strutil.StrListContainsGlob uses '*' wildcard matching, not ACL '+'.
    let mut rest = value;
    let mut parts = pattern.split('*').peekable();
    let Some(first) = parts.next() else {
        return false;
    };
    if !rest.starts_with(first) {
        return false;
    }
    rest = &rest[first.len()..];
    if parts.peek().is_none() {
        return rest.is_empty();
    }
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            return rest.ends_with(part);
        }
        let Some(index) = rest.find(part) else {
            return false;
        };
        rest = &rest[index + part.len()..];
    }
    true
}
impl AuthState {
    pub(crate) fn has_token_api_schema80_state(&self) -> bool {
        self.token_api_batch_policy_state || self.has_token_role_state()
    }
    pub(crate) fn has_token_role_state(&self) -> bool {
        self.token_roles.values().any(|roles| !roles.is_empty())
            || self.tokens.values().any(|token| token.token_role.is_some())
    }
    pub(crate) fn validate_token_role_state(&self) -> Result<(), AuthError> {
        for (namespace, roles) in &self.token_roles {
            if roles.is_empty() || namespace.len() > 8192 {
                return Err(bad("invalid persisted token role namespace"));
            }
            for (name, role) in roles {
                if !valid_role_name(name) {
                    return Err(bad("invalid persisted token role name"));
                }
                role.validate()?;
            }
        }
        for token in self.tokens.values() {
            if let Some(role) = &token.token_role {
                if !role.valid_path()
                    || !matches!(
                        token.auth_provenance,
                        Some(TokenAuthProvenance::TokenApi { .. })
                    )
                    || token.wrapping.is_some()
                {
                    return Err(bad("invalid persisted issued token role"));
                }
            }
        }
        Ok(())
    }
    pub(super) fn selected_token_role(
        &self,
        namespace: &str,
        path: &str,
    ) -> Result<Option<(String, Role)>, AuthError> {
        let Some(name) = path.strip_prefix("auth/token/create/") else {
            return Ok(None);
        };
        if !valid_role_name(name) {
            return Err(err(404, "unsupported token operation"));
        }
        self.token_roles
            .get(namespace)
            .and_then(|roles| roles.get(name))
            .cloned()
            .map(|role| Some((name.into(), role)))
            .ok_or_else(|| bad(&format!("unknown role {name}")))
    }
    pub(super) fn token_role_route(
        &mut self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        let name = path
            .strip_prefix("auth/token/roles")
            .ok_or_else(|| bad("invalid token role route"))?
            .strip_prefix('/')
            .unwrap_or("");
        let capability = route_capability(method, name.is_empty())?;
        self.permission(principal, namespace, path, capability, now)?;
        if name.is_empty() {
            if capability != "list" {
                return Err(bad("role name cannot be empty"));
            }
            let keys: Vec<&str> = self
                .token_roles
                .get(namespace)
                .map(|roles| roles.keys().map(String::as_str).collect())
                .unwrap_or_default();
            return if keys.is_empty() {
                Ok(AuthResponse {
                    status: 404,
                    body: json!({"errors":[]}),
                    ..empty(false)
                })
            } else {
                Ok(response(json!({"keys":keys}), false))
            };
        }
        if !valid_role_name(name) {
            return Err(err(404, "unsupported token operation"));
        }
        match capability {
            "read" => self
                .token_roles
                .get(namespace)
                .and_then(|roles| roles.get(name))
                .map(|role| response(role.info(name), false))
                .map_or_else(
                    || {
                        Ok(AuthResponse {
                            status: 404,
                            body: json!({"errors":[]}),
                            ..empty(false)
                        })
                    },
                    Ok,
                ),
            "delete" => {
                if let Some(roles) = self.token_roles.get_mut(namespace) {
                    roles.remove(name);
                    if roles.is_empty() {
                        self.token_roles.remove(namespace);
                    }
                }
                Ok(empty(true))
            }
            "update" => {
                let mut role = self
                    .token_roles
                    .get(namespace)
                    .and_then(|roles| roles.get(name))
                    .cloned()
                    .unwrap_or_default();
                let warnings = role.update(body)?;
                self.token_roles
                    .entry(namespace.into())
                    .or_default()
                    .insert(name.into(), role);
                Ok(if warnings.is_empty() {
                    empty(true)
                } else {
                    AuthResponse {
                        status: 200,
                        body: json!({"warnings":warnings}),
                        ..empty(true)
                    }
                })
            }
            _ => Err(err(405, "method not allowed")),
        }
    }
}

#[cfg(test)]
#[path = "auth_token_roles_tests.rs"]
mod tests;
