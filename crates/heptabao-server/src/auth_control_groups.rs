//! Durable pre-execution approval owners, separate from already executed response wrapping.
use super::*;
use std::cmp::Ordering;

const MAX_FACTORS: usize = 32;
const MAX_GROUPS: usize = 64;
const MAX_PENDING: usize = 1024;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub(crate) const STATE_SCHEMA: u32 = 118;
fn valid_digest(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|v| v.len() == 32 && URL_SAFE_NO_PAD.encode(&v) == value)
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Factor {
    pub(crate) name: String,
    pub(crate) group_ids: BTreeSet<String>,
    pub(crate) group_names: BTreeSet<String>,
    pub(crate) approvals: usize,
    pub(crate) self_authorization: bool,
    pub(crate) controlled_capabilities: Option<BTreeSet<String>>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyControl {
    pub(crate) ttl: u64,
    pub(crate) factors: Vec<Factor>,
}
fn names(value: Option<&Value>) -> Result<BTreeSet<String>, AuthError> {
    let Some(value) = value else {
        return Ok(BTreeSet::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| bad("control group names must be an array"))?;
    if values.len() > MAX_GROUPS {
        return Err(bad("control group list exceeds bound"));
    }
    let mut out = BTreeSet::new();
    for v in values {
        let s = v
            .as_str()
            .ok_or_else(|| bad("control group name must be a string"))?;
        if s.is_empty()
            || s.len() > 256
            || s.chars().any(char::is_control)
            || !out.insert(s.to_owned())
        {
            return Err(bad("invalid or duplicate control group name"));
        }
    }
    Ok(out)
}
pub(super) fn auth_mount_route(path: &str) -> Result<(&str, bool, String), AuthError> {
    let suffix = path
        .strip_prefix("sys/auth")
        .ok_or_else(|| bad("invalid auth mount path"))?;
    let requested = suffix.trim_start_matches('/').trim_end_matches('/');
    let (mount, tune) = requested
        .strip_suffix("/tune")
        .map_or((requested, false), |mount| (mount, true));
    if mount.is_empty() || mount.len() > 256 || !mount.split('/').all(valid_name) {
        return Err(bad("auth mount path must contain canonical segments"));
    }
    let route = if tune {
        format!("sys/auth/{mount}/tune")
    } else {
        format!("sys/auth/{mount}")
    };
    Ok((mount, tune, route))
}

impl PolicyControl {
    pub(super) fn parse(value: &Value, capabilities: &BTreeSet<String>) -> Result<Self, AuthError> {
        reject_unknown(value, &["ttl", "factor"])?;
        let explicit_ttl = value
            .get("ttl")
            .map(|v| {
                let raw = v
                    .as_str()
                    .ok_or_else(|| bad("control group TTL must be a duration string"))?;
                token_duration::parse_duration(raw)
                    .map_err(|_| bad("invalid control group TTL duration"))
            })
            .transpose()?;
        let mut ttl = explicit_ttl.unwrap_or(MAX_TTL as i64);
        let factors = value
            .get("factor")
            .and_then(Value::as_object)
            .ok_or_else(|| bad("control group requires named factors"))?;
        if factors.is_empty() || factors.len() > MAX_FACTORS {
            return Err(bad("invalid control group factor count"));
        }
        let mut out = Vec::new();
        for (name, factor) in factors {
            if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
                return Err(bad("invalid control group factor name"));
            }
            reject_unknown(factor, &["identity", "controlled_capabilities"])?;
            let identity = factor
                .get("identity")
                .ok_or_else(|| bad("control group identity factor is required"))?;
            reject_unknown(
                identity,
                &[
                    "group_ids",
                    "group_names",
                    "approvals",
                    "self_authorization",
                    "ttl",
                ],
            )?;
            if let Some(v) = identity.get("ttl") {
                let duration = token_duration::parse_duration(
                    v.as_str()
                        .ok_or_else(|| bad("identity factor TTL must be a duration string"))?,
                )
                .map_err(|_| bad("invalid identity factor TTL duration"))?;
                ttl = ttl.min(duration);
            }
            let group_ids = names(identity.get("group_ids"))?;
            let group_names = names(identity.get("group_names"))?;
            if group_ids.is_empty() && group_names.is_empty() {
                return Err(bad("control group identity needs groups"));
            }
            let approvals = identity
                .get("approvals")
                .and_then(Value::as_u64)
                .filter(|n| *n > 0 && *n <= MAX_GROUPS as u64)
                .ok_or_else(|| bad("control group approvals must be a positive bounded integer"))?
                as usize;
            let self_authorization = match identity.get("self_authorization") {
                None => false,
                Some(Value::Bool(value)) => *value,
                _ => return Err(bad("self_authorization must be boolean")),
            };
            let controlled_capabilities = factor
                .get("controlled_capabilities")
                .map(|v| names(Some(v)))
                .transpose()?;
            if controlled_capabilities.as_ref().is_some_and(|caps| {
                caps.is_empty()
                    || caps
                        .iter()
                        .any(|c| !capabilities.contains(c) || c == "deny")
            }) {
                return Err(bad(
                    "controlled capabilities must be a nonempty subset of path capabilities",
                ));
            }
            out.push(Factor {
                name: name.clone(),
                group_ids,
                group_names,
                approvals,
                self_authorization,
                controlled_capabilities,
            });
        }
        if ttl <= 0 || ttl > MAX_TTL as i64 {
            return Err(bad("control group TTL exceeds bounds"));
        }
        Ok(Self {
            ttl: ttl as u64,
            factors: out,
        })
    }
}
pub(super) fn hcl_value(tokens: &[Lex], cursor: &mut usize) -> Result<Value, AuthError> {
    take(tokens, cursor, Lex::Symbol('{'))?;
    let mut object = serde_json::Map::new();
    let mut factors = serde_json::Map::new();
    while tokens.get(*cursor) != Some(&Lex::Symbol('}')) {
        let field = take_word(tokens, cursor)?;
        if field == "factor" {
            let name = take_string(tokens, cursor)?;
            if factors.contains_key(&name) {
                return Err(bad("duplicate control group factor"));
            }
            take(tokens, cursor, Lex::Symbol('{'))?;
            let mut factor = serde_json::Map::new();
            while tokens.get(*cursor) != Some(&Lex::Symbol('}')) {
                let key = take_word(tokens, cursor)?;
                if factor.contains_key(&key) {
                    return Err(bad("duplicate control group factor field"));
                }
                if key != "identity" || tokens.get(*cursor) == Some(&Lex::Symbol('=')) {
                    take(tokens, cursor, Lex::Symbol('='))?;
                }
                factor.insert(key, parse_hcl_value_at_depth(tokens, cursor, 0)?);
            }
            take(tokens, cursor, Lex::Symbol('}'))?;
            factors.insert(name, Value::Object(factor));
            if factors.len() > MAX_FACTORS {
                return Err(bad("too many control group factors"));
            }
        } else {
            if object.contains_key(&field) {
                return Err(bad("duplicate control group field"));
            }
            take(tokens, cursor, Lex::Symbol('='))?;
            object.insert(field, parse_hcl_value_at_depth(tokens, cursor, 0)?);
        }
        if tokens.get(*cursor) == Some(&Lex::Symbol(',')) {
            *cursor += 1;
        }
    }
    take(tokens, cursor, Lex::Symbol('}'))?;
    if object
        .insert("factor".into(), Value::Object(factors))
        .is_some()
    {
        return Err(bad("ambiguous control group factors"));
    }
    Ok(Value::Object(object))
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct StanzaControl {
    pub(crate) rule_index: usize,
    pub(crate) control: PolicyControl,
}
pub(super) fn collect(
    source: &str,
    rules: &[Rule],
) -> Result<BTreeMap<String, Vec<StanzaControl>>, AuthError> {
    let mut result: BTreeMap<String, Vec<StanzaControl>> = BTreeMap::new();
    let mut rule_index = 0;
    {
        let mut bind = |path: String,
                        capabilities: BTreeSet<String>,
                        control: Option<Value>|
         -> Result<(), AuthError> {
            let rule = rules
                .get(rule_index)
                .ok_or_else(|| bad("control group stanza has no ACL rule"))?;
            if rule.path != path || rule.capabilities != capabilities {
                return Err(bad("control group stanza capability ownership mismatch"));
            }
            if let Some(value) = control {
                let control = PolicyControl::parse(&value, &capabilities)?;
                result.entry(path).or_default().push(StanzaControl {
                    rule_index,
                    control,
                });
            }
            rule_index += 1;
            Ok(())
        };
        if source.trim().starts_with('{') {
            let value = parse_strict_json(source.as_bytes())?;
            let paths = value
                .get("path")
                .and_then(Value::as_object)
                .ok_or_else(|| bad("policy path object is required"))?;
            for (path, config) in paths {
                let capabilities = parse_capability_array(
                    config
                        .get("capabilities")
                        .ok_or_else(|| bad("capabilities array is required"))?,
                )?;
                bind(
                    path.clone(),
                    capabilities,
                    config.get("control_group").cloned(),
                )?;
            }
        } else {
            let tokens = lex_hcl(source)?;
            let mut cursor = 0;
            while cursor < tokens.len() {
                take(&tokens, &mut cursor, Lex::Word("path".into()))?;
                let path = take_string(&tokens, &mut cursor)?;
                take(&tokens, &mut cursor, Lex::Symbol('{'))?;
                let mut capabilities = None;
                let mut control = None;
                let mut seen = BTreeSet::new();
                while tokens.get(cursor) != Some(&Lex::Symbol('}')) {
                    let field = take_word(&tokens, &mut cursor)?;
                    if !seen.insert(field.clone()) {
                        return Err(bad("duplicate ACL rule field"));
                    }
                    take(&tokens, &mut cursor, Lex::Symbol('='))?;
                    match field.as_str() {
                        "capabilities" => {
                            capabilities = Some(parse_hcl_capabilities(&tokens, &mut cursor)?)
                        }
                        "control_group" => control = Some(hcl_value(&tokens, &mut cursor)?),
                        _ => {
                            let _ = parse_hcl_value_at_depth(&tokens, &mut cursor, 0)?;
                        }
                    }
                }
                take(&tokens, &mut cursor, Lex::Symbol('}'))?;
                bind(
                    path,
                    capabilities.ok_or_else(|| bad("capabilities array is required"))?,
                    control,
                )?;
            }
        }
    }
    if rule_index != rules.len() {
        return Err(bad("control group stanza/rule count ownership mismatch"));
    }
    Ok(result)
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedFactor {
    pub(crate) name: String,
    pub(crate) group_ids: BTreeSet<String>,
    pub(crate) approvals: usize,
    pub(crate) self_authorization: bool,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ResourceBinding {
    Secret {
        owner: crate::engines::MountQueryOwner,
    },
    Auth {
        path: String,
        accessor: String,
        query_owner: bool,
    },
    System,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Approval {
    pub(crate) entity_id: String,
    pub(crate) entity_name: String,
    pub(crate) token_digest: String,
    pub(crate) token_accessor: String,
    pub(crate) request_accessor: String,
    pub(crate) origin_peer: Option<std::net::IpAddr>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeferredRequest {
    pub(crate) cluster_id: String,
    pub(crate) namespace: String,
    pub(crate) namespace_id: String,
    pub(crate) namespace_incarnation: u64,
    pub(crate) resource_binding: ResourceBinding,
    pub(crate) actor_digest: String,
    pub(crate) actor_accessor: String,
    pub(crate) actor_entity_id: String,
    pub(crate) actor_entity: Value,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) capability: String,
    pub(crate) requires_sudo: bool,
    pub(crate) body: Value,
    pub(crate) transport_method: String,
    pub(crate) transport_path: String,
    pub(crate) transport_namespace: String,
    pub(crate) transport_body: Value,
    pub(crate) wrap_ttl_seconds: Option<u64>,
    pub(crate) origin_peer: Option<std::net::IpAddr>,
    pub(crate) client_certificates: Option<Vec<Vec<u8>>>,
    pub(crate) created_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) creation_time: String,
    pub(crate) factors: Vec<ResolvedFactor>,
    pub(crate) authorizations: BTreeMap<String, Approval>,
}
impl Drop for DeferredRequest {
    fn drop(&mut self) {
        crate::service::erase_json(&mut self.body);
        crate::service::erase_json(&mut self.transport_body);
        crate::service::erase_json(&mut self.actor_entity);
        self.actor_digest.zeroize();
        if let Some(certificates) = &mut self.client_certificates {
            for certificate in certificates {
                certificate.zeroize();
            }
        }
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registry {
    floor: bool,
    clock: u64,
    requests: BTreeMap<String, DeferredRequest>,
}
impl Registry {
    pub(super) fn is_absent(&self) -> bool {
        !self.floor && self.clock == 0 && self.requests.is_empty()
    }
    pub(crate) fn validate_namespace(&self, actual: &str) -> Result<(), AuthError> {
        if actual.is_empty()
            || !self.floor
            || self.requests.len() > MAX_PENDING
            || self
                .requests
                .values()
                .any(|o| o.namespace != actual || o.created_at > self.clock)
        {
            return Err(bad("control group namespace owner is invalid"));
        }
        for (id, owner) in &self.requests {
            if !valid_digest(id) {
                return Err(bad("control group namespace request identity is invalid"));
            }
            owner.validate()?;
        }
        Ok(())
    }
}
impl AuthState {
    pub(super) fn control_groups_token_permission(
        &self,
        actor: &Principal,
        path: &str,
        capability: &str,
    ) -> bool {
        actor
            .service_token()
            .is_some_and(|t| t.policies == BTreeSet::from(["control-group".into()]))
            && path == "sys/wrapping/unwrap"
            && capability == "update"
    }

    pub(crate) fn control_group_namespace_has_requests(&self, namespace: &str) -> bool {
        self.control_groups
            .requests
            .values()
            .any(|owner| owner.namespace == namespace)
    }
    pub(crate) fn detach_control_group_namespace(&mut self, namespace: &str) -> Option<Registry> {
        let ids = self
            .control_groups
            .requests
            .iter()
            .filter(|(_, o)| o.namespace == namespace)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return None;
        }
        let requests = ids
            .into_iter()
            .filter_map(|id| {
                self.control_groups
                    .requests
                    .remove(&id)
                    .map(|owner| (id, owner))
            })
            .collect();
        Some(Registry {
            floor: true,
            clock: self.control_groups.clock,
            requests,
        })
    }
    pub(crate) fn control_group_namespace_attach_preflight(
        &self,
        namespace: &str,
        incoming: Option<&Registry>,
    ) -> Result<(), AuthError> {
        if self.control_group_namespace_has_requests(namespace) {
            return Err(bad("control group namespace owner is already loaded"));
        }
        if let Some(incoming) = incoming {
            incoming.validate_namespace(namespace)?;
            if incoming
                .requests
                .keys()
                .any(|id| self.control_groups.requests.contains_key(id))
            {
                return Err(bad("control group namespace request identity collision"));
            }
        }
        Ok(())
    }
    pub(crate) fn attach_control_group_namespace(&mut self, incoming: Option<Registry>) {
        if let Some(incoming) = incoming {
            self.control_groups.floor = true;
            self.control_groups.clock = self.control_groups.clock.max(incoming.clock);
            self.control_groups.requests.extend(incoming.requests);
        }
    }
    pub(crate) fn control_group_auth_mount_binding(
        &self,
        namespace: &str,
        path: &str,
    ) -> Result<Option<ResourceBinding>, AuthError> {
        if let Some(binding) = self.sdk_auth_binding(namespace, path)? {
            let accessor = self.mount_accessor(namespace, &binding.mount)?;
            return Ok(Some(ResourceBinding::Auth {
                path: binding.mount,
                accessor,
                query_owner: true,
            }));
        }
        let Some(relative) = path.strip_prefix("auth/") else {
            return Ok(None);
        };
        Ok(self
            .effective_auth_mounts(namespace)
            .iter()
            .find_map(|(mount, entry)| {
                relative.strip_prefix(&format!("{mount}/"))?;
                Some(ResourceBinding::Auth {
                    path: mount.clone(),
                    accessor: entry.accessor.clone()?,
                    query_owner: false,
                })
            }))
    }
    pub(crate) fn control_group_mount_type(
        &self,
        namespace: &str,
        accessor: &str,
    ) -> Option<String> {
        self.effective_auth_mounts(namespace)
            .values()
            .find(|m| m.accessor.as_deref() == Some(accessor))
            .map(|m| m.kind.clone())
    }
    pub(crate) fn control_group_authority_time(
        &self,
        time: AuthorityTime,
    ) -> Result<AuthorityTime, AuthError> {
        time.with_seconds_floor(self.control_groups.clock)
            .map_err(|_| err(503, "control group clock floor is unavailable"))
    }
    pub(crate) fn control_group_owners(&self) -> impl Iterator<Item = &DeferredRequest> {
        self.control_groups.requests.values()
    }
    pub(crate) fn control_group_time(&self, now: u64) -> u64 {
        now.max(self.control_groups.clock)
    }
    #[cfg(test)]
    pub(crate) fn control_group_request_count_for_test(&self) -> usize {
        self.control_groups.requests.len()
    }
    pub(super) fn observe_control_group_policy(&mut self, policy: &Policy) {
        if !policy.control_groups.is_empty() {
            self.control_groups.floor = true;
        }
    }
    pub(crate) fn has_control_group_state(&self) -> bool {
        !self.control_groups.is_absent()
            || self
                .policies
                .values()
                .flat_map(|p| p.values())
                .any(|p| !p.control_groups.is_empty())
    }
    pub(crate) fn control_group_policy(
        &self,
        actor: &Principal,
        namespace: &str,
        path: &str,
        capability: &str,
        time: AuthorityTime,
    ) -> Result<Option<PolicyControl>, AuthError> {
        self.control_group_policy_with_sudo(actor, namespace, path, capability, false, time)
    }
    pub(crate) fn control_group_policy_with_sudo(
        &self,
        actor: &Principal,
        namespace: &str,
        path: &str,
        capability: &str,
        requires_sudo: bool,
        time: AuthorityTime,
    ) -> Result<Option<PolicyControl>, AuthError> {
        let time = self.control_group_authority_time(time)?;
        let token = self.check_principal_observed(actor, namespace, time)?;
        if token.is_root() {
            return Ok(None);
        }
        let mut selected: Option<String> = None;
        let mut controls = Vec::new();
        let policy_names = token
            .policies()
            .iter()
            .chain(&actor.identity_policies)
            .cloned()
            .collect::<BTreeSet<_>>();
        for name in policy_names {
            let Some(policy) = self.policies.get(namespace).and_then(|p| p.get(&name)) else {
                continue;
            };
            for (rule_index, rule) in policy.rules.iter().enumerate() {
                let Some(rendered) = acl_template::render(&rule.path, &actor.identity_templates)?
                else {
                    continue;
                };
                if !path_matches(&rendered, path) {
                    continue;
                }
                match selected.as_deref().map(|old| acl::priority(&rendered, old)) {
                    Some(Ordering::Less) => continue,
                    Some(Ordering::Equal) => {}
                    None | Some(Ordering::Greater) => {
                        selected = Some(rendered.into_owned());
                        controls.clear();
                    }
                }
                if let Some(stanza) = policy.control_groups.get(&rule.path).and_then(|stanzas| {
                    stanzas
                        .iter()
                        .find(|stanza| stanza.rule_index == rule_index)
                }) {
                    let control = &stanza.control;
                    let factors = control
                        .factors
                        .iter()
                        .filter(|f| {
                            f.controlled_capabilities.as_ref().is_none_or(|c| {
                                c.contains(capability) || requires_sudo && c.contains("sudo")
                            })
                        })
                        .cloned()
                        .map(|mut f| {
                            f.name = format!("{name}:{rule_index}:{}", f.name);
                            f
                        })
                        .collect::<Vec<_>>();
                    if !factors.is_empty() {
                        controls.push(PolicyControl {
                            ttl: control.ttl,
                            factors,
                        });
                    }
                }
            }
        }
        if controls.is_empty() {
            return Ok(None);
        }
        let ttl = controls
            .iter()
            .map(|c| c.ttl)
            .min()
            .ok_or_else(|| bad("missing control group TTL"))?;
        let factors = controls
            .into_iter()
            .flat_map(|c| c.factors)
            .collect::<Vec<_>>();
        if factors.len() > MAX_FACTORS {
            return Err(bad("effective control group factors exceed bound"));
        }
        Ok(Some(PolicyControl { ttl, factors }))
    }
    pub(crate) fn control_group_actor_binding(
        &self,
        actor: &Principal,
    ) -> Result<(String, String, String), AuthError> {
        let token = actor.service_token().ok_or_else(|| denied())?;
        let entity = token.entity_id.as_ref().ok_or_else(denied)?;
        Ok((actor.digest.clone(), token.accessor.clone(), entity.clone()))
    }
    pub(crate) fn control_group_actor(
        &self,
        owner: &DeferredRequest,
        time: AuthorityTime,
    ) -> Result<Principal, AuthError> {
        let time = self.control_group_authority_time(time)?;
        let token = self.active_token_observed(&owner.actor_digest, time, false)?;
        if token.accessor != owner.actor_accessor
            || token.entity_id.as_deref() != Some(owner.actor_entity_id.as_str())
            || token.namespace != owner.namespace
        {
            return Err(denied());
        }
        token_cidrs::check(&token.bound_cidrs, owner.origin_peer)?;
        Ok(Self::request_principal(
            owner.actor_digest.clone(),
            token.clone(),
            time.seconds(),
            owner.origin_peer,
            PrincipalAdmission::Operation {
                finite_use_consumed: false,
            },
        ))
    }
    pub(crate) fn control_group_approval_actor(
        &self,
        approval: &Approval,
        namespace: &str,
        time: AuthorityTime,
    ) -> Result<Principal, AuthError> {
        let time = self.control_group_authority_time(time)?;
        let token = self.active_token_observed(&approval.token_digest, time, false)?;
        if token.accessor != approval.token_accessor
            || token.entity_id.as_deref() != Some(approval.entity_id.as_str())
            || token.namespace != namespace
        {
            return Err(denied());
        }
        token_cidrs::check(&token.bound_cidrs, approval.origin_peer)?;
        Ok(Self::request_principal(
            approval.token_digest.clone(),
            token.clone(),
            time.seconds(),
            approval.origin_peer,
            PrincipalAdmission::Operation {
                finite_use_consumed: false,
            },
        ))
    }
    pub(crate) fn is_control_group_token(&self, raw: &str) -> bool {
        raw.len() <= 256
            && self
                .tokens
                .get(&hash(raw))
                .is_some_and(|t| t.policies == BTreeSet::from(["control-group".into()]))
    }
    pub(crate) fn control_group_target(
        &self,
        raw: &str,
        namespace: &str,
        now: u64,
    ) -> Result<Option<&DeferredRequest>, AuthError> {
        if !self.is_control_group_token(raw) {
            return Ok(None);
        }
        let id = hash(raw);
        let token = self
            .active_token(&id, now.max(self.control_groups.clock), true)
            .map_err(|_| bad("wrapping token is not valid or does not exist"))?;
        let owner = self
            .control_groups
            .requests
            .get(&id)
            .ok_or_else(|| bad("wrapping token is not valid or does not exist"))?;
        if token.namespace != namespace
            || owner.namespace != namespace
            || now.max(self.control_groups.clock) >= owner.expires_at
        {
            return Err(bad("wrapping token is not valid or does not exist"));
        }
        Ok(Some(owner))
    }
    pub(crate) fn control_group_admitted_target(
        &self,
        raw: &str,
        namespace: &str,
        now: u64,
    ) -> Result<Option<&DeferredRequest>, AuthError> {
        if !self.is_control_group_token(raw) {
            return Ok(None);
        }
        let id = hash(raw);
        let token = self.active_token(&id, now.max(self.control_groups.clock), false)?;
        let owner = self
            .control_groups
            .requests
            .get(&id)
            .ok_or_else(|| bad("control group request is unavailable"))?;
        if owner.namespace != namespace
            || token.namespace != namespace
            || now.max(self.control_groups.clock) >= owner.expires_at
        {
            return Err(bad("control group request is unavailable"));
        }
        Ok(Some(owner))
    }
    pub(crate) fn control_group_by_accessor(
        &self,
        accessor: &str,
        namespace: &str,
        now: u64,
    ) -> Result<&DeferredRequest, AuthError> {
        self.control_groups
            .requests
            .iter()
            .find_map(|(id, owner)| {
                self.active_token(id, now.max(self.control_groups.clock), true)
                    .ok()
                    .filter(|t| {
                        t.accessor == accessor
                            && t.namespace == namespace
                            && owner.namespace == namespace
                            && now.max(self.control_groups.clock) < owner.expires_at
                    })
                    .map(|_| owner)
            })
            .ok_or_else(|| err(500, "control group request is unavailable"))
    }
    pub(crate) fn control_group_authorize(
        &mut self,
        accessor: &str,
        namespace: &str,
        now: u64,
        approval: Approval,
    ) -> Result<(), AuthError> {
        self.control_group_by_accessor(accessor, namespace, now)?;
        let id = self
            .tokens
            .iter()
            .find(|(_, t)| t.accessor == accessor)
            .map(|(id, _)| id.clone())
            .ok_or_else(|| bad("control group request is unavailable"))?;
        let owner = self
            .control_groups
            .requests
            .get_mut(&id)
            .ok_or_else(|| bad("control group request is unavailable"))?;
        if owner.authorizations.contains_key(&approval.entity_id) {
            return Err(err(500, "entity has already authorized this request"));
        }
        owner
            .authorizations
            .insert(approval.entity_id.clone(), approval);
        Ok(())
    }
    pub(crate) fn issue_control_group(
        &mut self,
        owner: DeferredRequest,
    ) -> Result<AuthResponse, AuthError> {
        if self.control_groups.requests.len() >= MAX_PENDING {
            return Err(err(503, "control group capacity exhausted"));
        }
        owner.validate()?;
        let raw = Zeroizing::new(random_id("hvs.")?);
        let id = hash(&raw);
        if self.tokens.contains_key(&id) {
            return Err(err(503, "control group token collision"));
        }
        let accessor = random_id("a.")?;
        let ttl = owner.expires_at - owner.created_at;
        let token = Token {
            token_api_precision: None,
            public_origin: None,
            issue_stamp: public_origin::CreationStamp::capture(owner.created_at)?,
            token_api_lease_ttl: None,
            token_role: None,
            bound_cidrs: Vec::new(),
            wrapping: None,
            raw_wrapped_reply_custody: None,
            entity_id: None,
            cubbyhole: cubbyhole::TokenCubbyhole::default(),
            accessor: accessor.clone(),
            namespace: owner.namespace.clone(),
            policies: BTreeSet::from(["control-group".into()]),
            root: false,
            parent: None,
            created_at: owner.created_at,
            expires_at: Some(owner.expires_at),
            max_expires_at: Some(owner.expires_at),
            period: 0,
            renewable: false,
            uses_remaining: Some(1),
            display_name: "control-group".into(),
            auth_mount: None,
            auth_origin_known: true,
            auth_cert_role: None,
            auth_cert_sha256: None,
            auth_provenance: None,
        };
        let body = json!({"request_id":"","lease_id":"","lease_duration":0,"renewable":false,"data":null,"auth":null,"warnings":null,
            "wrap_info":{"token":raw.as_str(),"accessor":accessor,"ttl":ttl,"creation_time":owner.creation_time,"creation_path":owner.path}});
        self.control_groups.floor = true;
        self.control_groups.clock = self.control_groups.clock.max(owner.created_at);
        self.control_groups.requests.insert(id.clone(), owner);
        self.store_token(id, token);
        Ok(AuthResponse {
            unwrapped_json: None,
            approle_secret_consumption: None,
            pending_batch: None,
            login_identity: None,
            external_groups: None,
            status: 200,
            mutated: true,
            body,
        })
    }
    pub(crate) fn claim_control_group(
        &mut self,
        raw: &str,
        namespace: &str,
        now: u64,
    ) -> Result<DeferredRequest, AuthError> {
        let id = hash(raw);
        // Self-token admission already consumed its use; the typed owner still
        // must be present and its expiry/scope must be valid before claiming.
        let owner = self
            .control_groups
            .requests
            .get(&id)
            .ok_or_else(|| bad("control group request is unavailable"))?;
        let token = self.active_token(&id, now.max(self.control_groups.clock), false)?;
        if owner.namespace != namespace
            || token.namespace != namespace
            || now.max(self.control_groups.clock) >= owner.expires_at
        {
            return Err(bad("control group request is unavailable"));
        }
        let owner = self
            .control_groups
            .requests
            .remove(&id)
            .ok_or_else(|| bad("control group request is unavailable"))?;
        self.tokens.get_mut(&id).ok_or_else(denied)?.uses_remaining = Some(0);
        Ok(owner)
    }
    pub(crate) fn advance_control_group_clock(&mut self, now: u64) -> bool {
        if self.control_groups.is_absent() || now <= self.control_groups.clock {
            return false;
        }
        self.control_groups.clock = now;
        let expired = self
            .control_groups
            .requests
            .iter()
            .filter(|(_, o)| now >= o.expires_at)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in expired {
            self.control_groups.requests.remove(&id);
            if let Some(t) = self.tokens.get_mut(&id) {
                t.uses_remaining = Some(0);
            }
        }
        true
    }
    pub(crate) fn validate_control_group_clock_floor(
        &self,
        previous: Option<&AuthState>,
    ) -> Result<(), AuthError> {
        if previous.is_some_and(|old| {
            old.control_groups.floor && !self.control_groups.floor
                || self.control_groups.clock < old.control_groups.clock
        }) {
            return Err(err(
                503,
                "control group clock or custody floor cannot decrease",
            ));
        }
        Ok(())
    }
    pub(crate) fn validate_control_group_state(&self) -> Result<(), AuthError> {
        for policy in self.policies.values().flat_map(|p| p.values()) {
            if collect(&policy.source, &policy.rules)? != policy.control_groups {
                return Err(bad("control group policy source ownership mismatch"));
            }
        }
        let registry = &self.control_groups;
        if registry.requests.len() > MAX_PENDING
            || (!registry.floor
                && (!registry.requests.is_empty()
                    || registry.clock != 0
                    || self
                        .policies
                        .values()
                        .flat_map(|p| p.values())
                        .any(|p| !p.control_groups.is_empty())))
        {
            return Err(bad("invalid control group registry"));
        }
        for (id, owner) in &registry.requests {
            owner.validate()?;
            if !valid_digest(id) || owner.created_at > registry.clock {
                return Err(bad("invalid control group owner identity or clock"));
            }
            // Revocation/namespace retirement may leave an inert bounded owner
            // until expiry; absence never resurrects its wrapping credential.
            if let Some(t) = self.tokens.get(id)
                && (t.root
                    || t.parent.is_some()
                    || t.entity_id.is_some()
                    || t.wrapping.is_some()
                    || t.renewable
                    || t.period != 0
                    || !matches!(t.uses_remaining, Some(0 | 1))
                    || t.policies != BTreeSet::from(["control-group".into()])
                    || t.namespace != owner.namespace
                    || t.created_at != owner.created_at
                    || t.expires_at != Some(owner.expires_at)
                    || t.max_expires_at != t.expires_at
                    || owner
                        .authorizations
                        .values()
                        .any(|a| a.request_accessor != t.accessor))
            {
                return Err(bad("invalid control group credential owner"));
            }
        }
        Ok(())
    }
}
impl DeferredRequest {
    pub(crate) fn validate(&self) -> Result<(), AuthError> {
        validate_namespace(&self.namespace)?;
        validate_namespace(&self.transport_namespace)?;
        validate_path(&self.path, false)?;
        if self.cluster_id.is_empty()
            || !valid_digest(&self.actor_digest)
            || self.actor_accessor.is_empty()
            || self.actor_entity_id.is_empty()
            || self.namespace_id.is_empty()
            || self.expires_at <= self.created_at
            || self.expires_at - self.created_at > MAX_TTL
            || !CAPABILITIES.contains(&self.capability.as_str())
            || matches!(self.capability.as_str(), "deny" | "sudo")
            || !matches!(
                self.method.as_str(),
                "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "LIST" | "SCAN"
            )
            || !matches!(
                self.transport_method.as_str(),
                "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "LIST" | "SCAN"
            )
            || self.transport_path.is_empty()
            || self.transport_path.len() > 4096
            || self.transport_path.chars().any(char::is_control)
            || self.path.starts_with("sys/wrapping/")
            || self.path.starts_with("sys/control-group/")
            || self.factors.is_empty()
            || self.factors.len() > MAX_FACTORS
            || self.authorizations.len() > MAX_GROUPS
        {
            return Err(bad("invalid deferred control group request"));
        }

        let entity = self
            .actor_entity
            .as_object()
            .ok_or_else(|| bad("invalid control group request entity"))?;
        if entity.len() != 4
            || entity.get("ID").and_then(Value::as_str) != Some(self.actor_entity_id.as_str())
            || entity.get("namespace_id").and_then(Value::as_str)
                != Some(self.namespace_id.as_str())
            || entity
                .get("name")
                .and_then(Value::as_str)
                .is_none_or(|n| n.is_empty())
            || entity
                .get("aliases")
                .and_then(Value::as_array)
                .is_none_or(|a| a.len() > MAX_GROUPS)
            || (self.namespace.is_empty() != (self.namespace_incarnation == 0))
            || self.wrap_ttl_seconds.is_some_and(|t| t > MAX_TTL)
        {
            return Err(bad("invalid control group entity or namespace incarnation"));
        }
        match &self.resource_binding {
            ResourceBinding::Secret { owner } if !owner.is_valid() => {
                return Err(bad("invalid control group mount binding"));
            }
            ResourceBinding::Auth { path, accessor, .. }
                if path.is_empty()
                    || path.len() > 256
                    || !path.split('/').all(valid_name)
                    || accessor.is_empty() =>
            {
                return Err(bad("invalid control group auth mount binding"));
            }
            _ => {}
        }
        let mut names = BTreeSet::new();
        for f in &self.factors {
            if f.name.is_empty()
                || !names.insert(&f.name)
                || f.group_ids.is_empty()
                || f.group_ids.len() > MAX_GROUPS
                || f.approvals == 0
                || f.approvals > MAX_GROUPS
            {
                return Err(bad("invalid resolved control group factor"));
            }
        }
        for (id, approval) in &self.authorizations {
            if id != &approval.entity_id
                || id.is_empty()
                || approval.entity_name.is_empty()
                || !valid_digest(&approval.token_digest)
                || approval.token_accessor.is_empty()
                || approval.request_accessor.is_empty()
            {
                return Err(bad("invalid control group authorization"));
            }
        }
        for value in [&self.body, &self.transport_body, &self.actor_entity] {
            if Zeroizing::new(
                serde_json::to_vec(value).map_err(|_| bad("invalid control group request JSON"))?,
            )
            .len()
                > MAX_REQUEST_BYTES
            {
                return Err(err(413, "control group request exceeds bound"));
            }
        }
        if self.client_certificates.as_ref().is_some_and(|c| {
            c.len() > 16 || c.iter().map(Vec::len).sum::<usize>() > MAX_REQUEST_BYTES
        }) {
            return Err(bad("control group certificate chain exceeds bound"));
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "auth_control_groups_tests.rs"]
mod tests;
