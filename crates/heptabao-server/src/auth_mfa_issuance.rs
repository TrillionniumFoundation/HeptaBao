//! Private unissued login custody. No raw bearer is persisted in this module.
use super::*;
use ring::hmac;

pub(super) const MAX_CHALLENGES: usize = 1024;
// Inferred from independently compiled observations: becoming eligible does
// not invalidate a request ID. One host-owned janitor may retire one eligible
// head per five-second tick. Tied creation seconds have no vendor order proof.
const CHALLENGE_MINIMUM_AGE_SECONDS: u64 = 300;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeMfaBinding {
    pub(super) cluster_id: String,
    pub(super) namespace: String,
    pub(super) namespace_id: String,
    pub(super) incarnation: u64,
    pub(super) custody: Option<crate::namespace_custody::Binding>,
}
impl NativeMfaBinding {
    pub(crate) fn from_native(
        cluster_id: &str,
        namespace: &str,
        namespace_id: &str,
        incarnation: u64,
        custody: Option<crate::namespace_custody::Binding>,
    ) -> Result<Self, AuthError> {
        if cluster_id.is_empty()
            || namespace_id.is_empty()
            || (!namespace.is_empty() && incarnation == 0)
            || custody.as_ref().is_some_and(|b| b.namespace() != namespace)
        {
            return Err(err(503, "MFA native namespace binding unavailable"));
        }
        if namespace.is_empty() {
            if namespace_id != "root" || incarnation != 0 || custody.is_some() {
                return Err(denied());
            }
        } else {
            let expected = crate::namespace_custody::Binding::new(
                cluster_id.into(),
                namespace.into(),
                namespace_id.into(),
                incarnation,
            )
            .map_err(|_| err(503, "MFA actual namespace binding rejected"))?;
            if custody.as_ref() != Some(&expected) {
                return Err(denied());
            }
        }
        Ok(Self {
            cluster_id: cluster_id.into(),
            namespace: namespace.into(),
            namespace_id: namespace_id.into(),
            incarnation,
            custody,
        })
    }
}

/// One native background observation, never a caller-deserializable authority.
/// No first-factor grant, token, bearer or enrollment secret leaves the owner.
pub(crate) struct MfaJanitorHead {
    pub(super) namespace: String,
    pub(super) id: String,
    pub(super) sequence: u64,
    pub(super) binding: NativeMfaBinding,
    pub(super) created: Timestamp,
    pub(super) eligible_at: Timestamp,
    pub(super) mac: Zeroizing<Vec<u8>>,
    pub(super) mutation_epoch: u64,
    pub(super) closed: Option<super::janitor_custody::Locator>,
}
impl MfaJanitorHead {
    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }
    // This is incapable namespace metadata from the SAME affine signed capture.
    // Service independently verifies its actual enclosing ciphertext before use.
    pub(crate) fn closed_binding(&self, cluster: &str) -> Result<Option<NativeMfaBinding>, AuthError> {
        if self.closed.is_none() { return Ok(None); }
        if self.binding.cluster_id != cluster {
            return Err(err(503, "MFA original closed cluster changed"));
        }
        Ok(Some(self.binding.clone()))
    }
    pub(crate) fn ciphertext_owner(&self) -> Option<&crate::auth::sdk_namespace_custody::CiphertextOwner> {
        self.closed.as_ref().and_then(|locator| locator.enclosures.last().or(locator.capture.ciphertext.as_ref()))
    }
}

/// This request-scoped object is deliberately neither Clone nor Deserialize.
pub(crate) struct PendingServiceGrant {
    token: Token,
    mount_revision: AuthMount,
    user_binding: Zeroizing<Vec<u8>>,
    created: Timestamp,
    origin_peer: Option<std::net::IpAddr>,
    completed: bool,
    native_binding: std::cell::OnceCell<NativeMfaBinding>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Grant {
    Service(Token),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Requirement {
    namespace: String,
    name: String,
    id: String,
    generation: u64,
    methods: BTreeMap<String, u64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Challenge {
    sequence: u64,
    binding: NativeMfaBinding,
    grant: Grant,
    mount: String,
    mount_revision: AuthMount,
    user_binding: Vec<u8>,
    origin_peer: Option<std::net::IpAddr>,
    created: Timestamp,
    expires: Timestamp,
    requirements: Vec<Requirement>,
    mac: Vec<u8>,
}
impl Drop for Challenge {
    fn drop(&mut self) {
        self.user_binding.zeroize();
        self.mac.zeroize();
    }
}
impl PendingServiceGrant {
    pub(crate) fn response(
        token: Token,
        mount_revision: AuthMount,
        user_binding: Vec<u8>,
        time: AuthorityTime,
        origin_peer: Option<std::net::IpAddr>,
    ) -> Result<AuthResponse, AuthError> {
        let at = at(time)?;
        let body = json!({"auth":{"client_token":"","accessor":"",
            "policies":token.policies,"token_policies":token.policies,
            "entity_id":"","metadata":{},"lease_duration":0,"renewable":false,
            "token_type":"service","orphan":false,"num_uses":0}});
        Ok(AuthResponse {
            unwrapped_json: None,
            approle_secret_consumption: None,
            pending_batch: None,
            pending_service: Some(Self {
                token,
                mount_revision,
                user_binding: Zeroizing::new(user_binding),
                created: at,
                origin_peer,
                completed: false,
                native_binding: std::cell::OnceCell::new(),
            }),
            login_identity: None,
            external_groups: None,
            status: 200,
            body,
            mutated: true,
        })
    }
    pub(super) fn bind_entity(
        &mut self,
        namespace: &str,
        mount: &str,
        entity: &str,
    ) -> Result<(), AuthError> {
        if self.token.namespace != namespace
            || self.token.auth_mount.as_deref() != Some(mount)
            || self.token.entity_id.is_some()
            || self.token.root
        {
            return Err(denied());
        }
        self.token.entity_id = Some(entity.to_owned());
        Ok(())
    }
    pub(crate) fn entity_id(&self) -> Option<&str> {
        self.token.entity_id.as_deref()
    }
    pub(crate) fn namespace(&self) -> &str {
        &self.token.namespace
    }
    pub(crate) fn bind_native(&self, binding: NativeMfaBinding) -> Result<(), AuthError> {
        if binding.namespace != self.token.namespace {
            return Err(denied());
        }
        if let Some(current) = self.native_binding.get() {
            if current != &binding {
                return Err(denied());
            }
            return Ok(());
        }
        self.native_binding
            .set(binding)
            .map_err(|_| err(503, "MFA native binding already assigned"))
    }
}
fn at(time: AuthorityTime) -> Result<Timestamp, AuthError> {
    time.exact()
        .map(Ok)
        .unwrap_or_else(|| Timestamp::whole(time.seconds()))
        .map_err(|_| err(503, "MFA captured clock unavailable"))
}
fn plus(at: Timestamp, seconds: u64) -> Result<Timestamp, AuthError> {
    Timestamp::checked(
        at.seconds()
            .checked_add(seconds)
            .ok_or_else(|| err(503, "MFA time overflow"))?,
        at.duration_since_epoch().subsec_nanos(),
    )
    .map_err(|_| err(503, "MFA time overflow"))
}
fn user_binding(user: &User) -> Result<Vec<u8>, AuthError> {
    let mut normal = user.clone();
    normal.failed_login_count = 0;
    normal.failed_login_last_at = 0;
    normal.locked_until = 0;
    if let Some(mfa) = normal.mfa.as_mut() {
        mfa.last_accepted_counter = None;
    }
    let bytes = crate::secret_serde::to_vec(&normal, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| err(503, "MFA native user binding unavailable"))?;
    Ok(crate::crypto::digest(&bytes).to_vec())
}
impl Challenge {
    pub(super) fn queue_entry(&self, key: &[u8]) -> Result<super::janitor_custody::Entry, AuthError> {
        self.verify(key)?;
        Ok(super::janitor_custody::Entry { sequence:self.sequence, binding:self.binding.clone(),
            created:self.created, eligible_at:self.expires, commitment:crate::crypto::digest(&self.mac) })
    }
    pub(super) fn cluster(&self) -> &str {
        &self.binding.cluster_id
    }
    fn entity(&self) -> Option<&str> {
        match &self.grant {
            Grant::Service(t) => t.entity_id.as_deref(),
        }
    }
    fn payload(&self) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        crate::secret_serde::to_vec(
            &(
                self.sequence,
                &self.binding,
                &self.grant,
                &self.mount,
                &self.mount_revision,
                &self.user_binding,
                self.origin_peer,
                self.created,
                self.expires,
                &self.requirements,
            ),
            crate::MAX_APPLICATION_STATE_BYTES,
        )
        .map_err(|_| err(503, "MFA private challenge serialization unavailable"))
    }
    fn sign(&mut self, key: &[u8]) -> Result<(), AuthError> {
        let bytes = self.payload()?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        self.mac = hmac::sign(&key, &bytes).as_ref().to_vec();
        Ok(())
    }
    pub(super) fn verify(&self, key: &[u8]) -> Result<(), AuthError> {
        let bytes = self.payload()?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::verify(&key, &bytes, &self.mac)
            .map_err(|_| err(503, "MFA private challenge custody rejected"))
    }
}
impl NamespaceOwner {
    pub(super) fn retire_matching(&mut self, mut check: impl FnMut(&Challenge) -> bool) {
        let ids = self
            .challenges
            .iter()
            .filter(|(_, c)| check(c))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in ids {
            if let Some(c) = self.challenges.remove(&id) {
                self.terminal.insert(c.sequence);
            }
        }
    }
    pub(super) fn retire_method_challenges(&mut self, id: &str) {
        self.retire_matching(|c| c.requirements.iter().any(|r| r.methods.contains_key(id)));
    }
    pub(super) fn retire_enforcement_challenges(&mut self, name: &str) {
        self.retire_matching(|c| c.requirements.iter().any(|r| r.name == name));
    }
    pub(super) fn retire_enrollment_challenges(&mut self, entity: &str, id: &str) {
        self.retire_matching(|c| {
            c.entity() == Some(entity) && c.requirements.iter().any(|r| r.methods.contains_key(id))
        });
    }
}
impl Registry {
    pub(super) fn validate_challenges(&self, owner: &NamespaceOwner) -> Result<(), AuthError> {
        if owner.challenges.len() > MAX_CHALLENGES
            || owner
                .terminal
                .iter()
                .any(|sequence| *sequence == 0 || *sequence > owner.issued)
        {
            return Err(err(503, "invalid MFA challenge history"));
        }
        let mut sequences = BTreeSet::new();
        for (id, c) in &owner.challenges {
            if !uuid_valid(id)
                || c.sequence == 0
                || c.sequence > owner.issued
                || !sequences.insert(c.sequence)
                || owner.terminal.contains(&c.sequence)
                || c.binding.namespace != owner.namespace
                || c.binding.namespace_id != owner.namespace_id
                || c.binding.incarnation != owner.incarnation
                || c.expires <= c.created
                || c.entity().is_none()
                || c.requirements.is_empty()
                || c.user_binding.len() != 32
                || c.mac.len() != 32
            {
                return Err(err(503, "invalid MFA challenge owner"));
            }
            NativeMfaBinding::from_native(
                &c.binding.cluster_id,
                &c.binding.namespace,
                &c.binding.namespace_id,
                c.binding.incarnation,
                c.binding.custody.clone(),
            )?;
            let Grant::Service(token) = &c.grant;
            if token.root
                || token.policies.contains("root")
                || token.namespace != owner.namespace
                || token.auth_mount.as_deref() != Some(c.mount.as_str())
                || token.created_at != c.created.seconds()
                || token.entity_id.as_deref().is_none_or(str::is_empty)
                || !token.auth_origin_known
                || !matches!(&token.auth_provenance,
                    Some(TokenAuthProvenance::Userpass { username }) if !username.is_empty())
                || token.token_api_precision.is_some()
                || token.public_origin.is_some()
                || token.issue_stamp.is_some()
                || token.token_role.is_some()
                || token.wrapping.is_some()
                || token.raw_wrapped_reply_custody.is_some()
                || token.parent.is_some()
                || c.mount_revision.kind != "userpass"
                || c.mount_revision
                    .accessor
                    .as_deref()
                    .is_none_or(str::is_empty)
            {
                return Err(err(
                    503,
                    "MFA private grant has no native unissued userpass owner",
                ));
            }
            c.verify(&self.key.0)?;
        }
        Ok(())
    }
    pub(super) fn validate_successor(&self, old: &Self) -> Result<(), AuthError> {
        if self.clock < old.clock {
            return Err(err(503, "MFA durable clock regressed"));
        }
        if self.mutation_epoch < old.mutation_epoch
            || self.mutation_epoch == old.mutation_epoch
                && self.semantic_digest()? != old.semantic_digest()?
        {
            return Err(err(
                503,
                "MFA owned mutation epoch or exact private state regressed",
            ));
        }
        for (namespace, previous) in &old.namespaces {
            let Some(next) = self.namespaces.get(namespace) else {
                if let Some(closed) = self.closed_references.get(namespace) {
                    if closed.namespace_id != previous.namespace_id
                        || closed.incarnation != previous.incarnation
                        || closed.method_ids != previous.reference_method_ids()
                        || closed.owner_digest != owner_digest(previous)?
                        || self.format == super::janitor_custody::FORMAT && closed.queue_digest.is_none()
                        || closed.queue_digest.is_some()
                            && closed.queue_digest != super::janitor_custody::Capture::from_owner(previous,
                                owner_digest(previous)?, self.mutation_epoch, &self.key.0)?
                                .as_ref().map(super::janitor_custody::Capture::core_digest).transpose()?
                    {
                        return Err(err(503, "MFA closed namespace reference differs from its owner"));
                    }
                    continue;
                }
                if self
                    .retired
                    .get(namespace)
                    .is_none_or(|inc| *inc < previous.incarnation)
                {
                    return Err(err(503, "MFA native owner removed without retirement"));
                }
                continue;
            };
            if next.incarnation > previous.incarnation
                && self
                    .retired
                    .get(namespace)
                    .is_some_and(|old| *old >= previous.incarnation)
                && next.namespace_id != previous.namespace_id
            {
                continue;
            }
            if next.incarnation != previous.incarnation
                || next.namespace_id != previous.namespace_id
                || next.issued < previous.issued
                || !previous.terminal.is_subset(&next.terminal)
                || next
                    .challenges
                    .values()
                    .any(|c| previous.terminal.contains(&c.sequence))
            {
                return Err(err(503, "MFA history or namespace owner regressed"));
            }
        }
        for (namespace, previous) in &old.closed_references {
            if let Some(next) = self.closed_references.get(namespace) {
                if next.namespace_id != previous.namespace_id
                    || next.incarnation != previous.incarnation
                    || next.method_ids != previous.method_ids
                    || next.owner_digest != previous.owner_digest
                    || next.queue_digest != previous.queue_digest
                {
                    return Err(err(503, "MFA closed namespace reference changed"));
                }
                continue;
            }
            let retired = self
                .retired
                .get(namespace)
                .is_some_and(|inc| *inc >= previous.incarnation);
            if let Some(next) = self.namespaces.get(namespace) {
                if retired
                    && next.incarnation > previous.incarnation
                    && next.namespace_id != previous.namespace_id
                {
                    continue;
                }
                if next.namespace_id != previous.namespace_id
                    || next.incarnation != previous.incarnation
                    || next.reference_method_ids() != previous.method_ids
                    || owner_digest(next)? != previous.owner_digest
                {
                    return Err(err(503, "MFA reopened namespace reference changed"));
                }
            } else if !retired {
                return Err(err(503, "MFA closed namespace reference removed without retirement"));
            }
        }
        self.validate_janitor_successor(old)?;
        for (namespace, incarnation) in &old.retired {
            if self
                .retired
                .get(namespace)
                .is_none_or(|next| next < incarnation)
            {
                return Err(err(503, "MFA retirement floor regressed"));
            }
        }
        Ok(())
    }
}
impl AuthState {
    pub(in crate::auth) fn mfa_userpass_binding(
        &self,
        scope: AuthScope<'_>,
        user: &User,
    ) -> Result<(AuthMount, Vec<u8>), AuthError> {
        let mount = self
            .effective_auth_mounts(scope.namespace)
            .get(scope.mount)
            .cloned()
            .ok_or_else(denied)?;
        if mount.kind != "userpass" || mount.accessor.is_none() {
            return Err(denied());
        }
        Ok((mount, user_binding(user)?))
    }
    pub(crate) fn mfa_might_enforce(&self, namespace: &str, mount: &str, kind: &str) -> bool {
        let accessor = self.mount_accessor(namespace, mount).ok();
        self.identity_mfa.as_ref().is_some_and(|r| {
            r.namespaces.iter().any(|(owner, n)| {
                ancestor(owner, namespace)
                    && n.enforcements.values().any(|e| {
                        !e.identity_entity_ids.is_empty()
                            || !e.identity_group_ids.is_empty()
                            || e.auth_method_types.contains(kind)
                            || accessor
                                .as_ref()
                                .is_some_and(|a| e.auth_method_accessors.contains(a))
                    })
            })
        })
    }
    pub(crate) fn bind_pending_mfa_entity(
        response: &mut AuthResponse,
        namespace: &str,
        mount: &str,
        entity: &str,
    ) -> Result<bool, AuthError> {
        let Some(pending) = response.pending_service.as_mut() else {
            return Ok(false);
        };
        pending.bind_entity(namespace, mount, entity)?;
        response.body["auth"]["entity_id"] = json!(entity);
        Ok(true)
    }
}

fn response_failure(status: u16, message: &str, mutated: bool) -> AuthResponse {
    let mut reply = empty(mutated);
    reply.status = status;
    reply.body = json!({"errors":[message]});
    reply
}
fn same_mount(left: &AuthMount, right: &AuthMount) -> Result<bool, AuthError> {
    let left = crate::secret_serde::to_vec(left, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| err(503, "MFA native mount serialization unavailable"))?;
    let right = crate::secret_serde::to_vec(right, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| err(503, "MFA native mount serialization unavailable"))?;
    Ok(left.as_slice() == right.as_slice())
}
impl Registry {
    fn requirements(
        &self,
        namespace: &str,
        mount_accessor: &str,
        kind: &str,
        entity: &str,
        groups: &BTreeSet<String>,
    ) -> Vec<Requirement> {
        self.namespaces
            .iter()
            .filter(|(owner, _)| ancestor(owner, namespace))
            .flat_map(|(_, owner)| owner.enforcements.values())
            .filter(|rule| {
                rule.auth_method_accessors.contains(mount_accessor)
                    || rule.auth_method_types.contains(kind)
                    || rule.identity_entity_ids.contains(entity)
                    || !rule.identity_group_ids.is_disjoint(groups)
            })
            .map(|rule| Requirement {
                namespace: rule.namespace.clone(),
                name: rule.name.clone(),
                id: rule.id.clone(),
                generation: rule.generation,
                methods: rule
                    .mfa_method_ids
                    .iter()
                    .filter_map(|id| {
                        self.method(namespace, id)
                            .map(|m| (id.clone(), m.generation))
                    })
                    .collect(),
            })
            .collect()
    }
    fn requirements_live(&self, c: &Challenge) -> bool {
        c.requirements.iter().all(|r| {
            self.namespaces
                .get(&r.namespace)
                .and_then(|n| n.enforcements.get(&r.name))
                .is_some_and(|e| {
                    e.id == r.id
                        && e.generation == r.generation
                        && e.mfa_method_ids.len() == r.methods.len()
                        && r.methods.iter().all(|(id, g)| {
                            self.method(&c.binding.namespace, id)
                                .is_some_and(|m| m.generation == *g)
                        })
                })
        })
    }
    // Only methods already bound into the MAC-authenticated native challenge
    // can resolve a public credential key. Name resolution never adds a rule,
    // grants an identity, or permits an unrelated/foreign method owner.
    fn resolve_mfa_payload<'a>(
        &self,
        challenge: &Challenge,
        payload: &'a serde_json::Map<String, Value>,
    ) -> Result<BTreeMap<String, &'a Vec<Value>>, AuthError> {
        let required = challenge.requirements.iter()
            .flat_map(|rule| rule.methods.keys().cloned()).collect::<BTreeSet<_>>();
        let mut resolved = BTreeMap::new();
        for (supplied, value) in payload {
            let id = if required.contains(supplied) {
                supplied.clone()
            } else {
                let matches = required.iter().filter_map(|id| {
                    let method = self.method(&challenge.binding.namespace, id)?;
                    if method.name.is_empty() {
                        return None;
                    }
                    let name = if method.namespace.is_empty() {
                        method.name.clone()
                    } else {
                        format!("{}/{}", method.namespace, method.name)
                    };
                    (name == *supplied).then(|| id.clone())
                }).collect::<BTreeSet<_>>();
                if matches.len() != 1 {
                    return Err(err(403, "unknown or ambiguous MFA method credentials"));
                }
                matches.into_iter().next().ok_or_else(denied)?
            };
            let codes = value.as_array().ok_or_else(|| bad("invalid MFA payload"))?;
            if resolved.insert(id, codes).is_some() {
                return Err(bad("MFA method credentials supplied more than once"));
            }
        }
        Ok(resolved)
    }
    fn challenge_reply(&self, id: &str, c: &Challenge) -> Value {
        let constraints = c
            .requirements
            .iter()
            .map(|r| {
                let any = r
                    .methods
                    .keys()
                    .filter_map(|id| self.method(&c.binding.namespace, id))
                    .map(|m| json!({"id":m.id,"name":m.name,"type":"totp","uses_passcode":true}))
                    .collect::<Vec<_>>();
                (r.name.clone(), json!({"any":any}))
            })
            .collect::<BTreeMap<_, _>>();
        json!({"auth":{"client_token":"","accessor":"","entity_id":"","lease_duration":0,
            "policies":null,"token_policies":null,"metadata":null,"renewable":false,"token_type":"service",
            "mfa_requirement":{"mfa_request_id":id,"mfa_constraints":constraints}}})
    }
}
impl AuthState {
    /// Called only after the Service's real identity projection has completed.
    /// Grant authority comes from the private pending object, never this JSON.
    pub(crate) fn finish_mfa_response(
        &mut self,
        response: &mut AuthResponse,
        entity: &str,
        groups: &BTreeSet<String>,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        let Some(mut pending) = response.pending_service.take() else {
            return Ok(());
        };
        let binding = pending
            .native_binding
            .take()
            .ok_or_else(|| err(503, "MFA native Service binding unavailable"))?;
        let namespace = binding.namespace.clone();
        if self
            .identity_mfa
            .as_ref()
            .is_some_and(|registry| pending.created < registry.clock)
        {
            return Err(err(503, "MFA native challenge clock regressed"));
        }
        if pending.token.namespace != namespace || pending.entity_id() != Some(entity) {
            return Err(err(503, "MFA native identity projection rejected"));
        }
        let mount = pending
            .token
            .auth_mount
            .as_deref()
            .ok_or_else(denied)?
            .to_owned();
        let current = self
            .effective_auth_mounts(&namespace)
            .get(&mount)
            .cloned()
            .ok_or_else(denied)?;
        if !same_mount(&current, &pending.mount_revision)? || current.kind != "userpass" {
            return Err(denied());
        }
        let accessor = current.accessor.as_deref().ok_or_else(denied)?;
        let requirements = self.identity_mfa.as_ref().map_or_else(Vec::new, |r| {
            r.requirements(&namespace, accessor, "userpass", entity, groups)
        });
        if requirements.is_empty() || pending.completed {
            let issued_at = at(time)?;
            if pending.completed {
                self.reanchor_userpass_grant(&mut pending.token, time)?;
            }
            let (id, token, mut issued) = if pending.completed {
                Self::prepare_issue_captured(pending.token, time.seconds(), issued_at)?
            } else {
                Self::prepare_issue(pending.token, time.seconds())?
            };
            let username = match &token.auth_provenance {
                Some(TokenAuthProvenance::Userpass { username }) => username.clone(),
                _ => return Err(denied()),
            };
            issued.body["auth"]["metadata"] = json!({"username":username});
            userpass_no_default::omit_empty_token_policies(&mut issued);
            issued.body["auth"]["mfa_requirement"] = Value::Null;
            self.store_token(id, token);
            issued.body["auth"]["identity_policies"] =
                response.body["auth"]["identity_policies"].clone();
            issued.body["auth"]["policies"] = response.body["auth"]["policies"].clone();
            *response = issued;
            return Ok(());
        }
        let lifetime = CHALLENGE_MINIMUM_AGE_SECONDS;
        let expires = plus(pending.created, lifetime)?;
        let id = uuid()?;
        let registry = self
            .identity_mfa
            .as_mut()
            .ok_or_else(|| err(503, "MFA native owner unavailable"))?;
        let key = Zeroizing::new(registry.key.0.clone());
        registry.clock = registry.clock.max(pending.created);
        let owner = registry.owner_mut(&namespace, &binding.namespace_id, binding.incarnation)?;
        if owner.challenges.len() >= MAX_CHALLENGES {
            return Err(err(507, "MFA challenge capacity exhausted"));
        }
        owner.issued = owner
            .issued
            .checked_add(1)
            .ok_or_else(|| err(503, "MFA challenge sequence exhausted"))?;
        let mut challenge = Challenge {
            sequence: owner.issued,
            binding,
            grant: Grant::Service(pending.token),
            mount,
            mount_revision: current,
            user_binding: std::mem::take(&mut *pending.user_binding),
            origin_peer: pending.origin_peer,
            created: pending.created,
            expires,
            requirements,
            mac: Vec::new(),
        };
        challenge.sign(&key)?;
        owner.challenges.insert(id.clone(), challenge);
        registry.advance_mutation()?;
        let challenge = registry
            .namespaces
            .get(&namespace)
            .and_then(|n| n.challenges.get(&id))
            .ok_or_else(|| err(503, "MFA challenge publication unavailable"))?;
        response.body = registry.challenge_reply(&id, challenge);
        response.mutated = true;
        Ok(())
    }
    // A persisted rule may outlive its auth mount. Validation must never
    // transfer the private first-factor grant to a remounted path.
    pub(super) fn mfa_validation_mount(
        &self,
        scope: AuthScope<'_>,
        expected: &AuthMount,
    ) -> Result<AuthMount, AuthError> {
        self.effective_auth_mounts(scope.namespace)
            .get(scope.mount)
            .filter(|mount| {
                mount.kind == "userpass"
                    && mount.accessor.is_some()
                    && mount.accessor == expected.accessor
            })
            .cloned()
            .ok_or_else(|| err(500, "failed to find MFAEnforcement configuration"))
    }
    fn reanchor_userpass_grant(
        &self,
        token: &mut Token,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        let Some(TokenAuthProvenance::Userpass { username }) = &token.auth_provenance else {
            return Err(denied());
        };
        let mount = token.auth_mount.as_deref().ok_or_else(denied)?;
        let scope = AuthScope {
            namespace: &token.namespace,
            mount,
        };
        let user = self
            .users_at(scope)
            .and_then(|users| users.get(username))
            .ok_or_else(denied)?;
        let now = time.seconds();
        token.created_at = now;
        token.issue_stamp = None;
        token.max_expires_at = (user.token_explicit_max_ttl > 0)
            .then(|| checked_expiry(now, user.token_explicit_max_ttl))
            .transpose()?;
        token.expires_at =
            Some(self.userpass_token_expiry(scope, user, now, token.max_expires_at, 0, now)?);
        Ok(())
    }
    pub(crate) fn mfa_validate(
        &mut self,
        namespace: &str,
        binding: NativeMfaBinding,
        body: &Value,
        time: AuthorityTime,
        origin_peer: Option<std::net::IpAddr>,
    ) -> Result<AuthResponse, AuthError> {
        self.mfa_owned_mutation(|candidate| {
            candidate.mfa_validate_inner(namespace, binding, body, time, origin_peer)
        })
    }
    fn mfa_validate_inner(
        &mut self,
        namespace: &str,
        binding: NativeMfaBinding,
        body: &Value,
        time: AuthorityTime,
        origin_peer: Option<std::net::IpAddr>,
    ) -> Result<AuthResponse, AuthError> {
        reject_unknown(body, &["mfa_request_id", "mfa_payload"])?;
        let id = body
            .get("mfa_request_id")
            .and_then(Value::as_str)
            .filter(|s| uuid_valid(s))
            .ok_or_else(|| bad("invalid request ID"))?;
        if self.mfa_challenge_has_terminal_receipt(namespace, id) { return Err(bad("invalid request ID")); }
        let challenge = self
            .identity_mfa
            .as_ref()
            .and_then(|r| r.namespaces.get(namespace))
            .and_then(|owner| owner.challenges.get(id))
            .cloned()
            .ok_or_else(|| bad("invalid request ID"))?;
        let registry = self
            .identity_mfa
            .as_ref()
            .ok_or_else(|| bad("invalid request ID"))?;
        challenge.verify(&registry.key.0)?;
        if challenge.binding != binding {
            return Err(bad("invalid request ID"));
        }
        let now = at(time)?;
        if now < registry.clock {
            return Err(err(503, "MFA durable clock regressed"));
        }
        if now < challenge.created {
            return Err(err(503, "MFA captured clock regressed"));
        }
        if !registry.requirements_live(&challenge) {
            self.retire_mfa_challenge(namespace, id)?;
            return Ok(response_failure(400, "invalid request ID", true));
        }
        let username = match &challenge.grant {
            Grant::Service(token) => match &token.auth_provenance {
                Some(TokenAuthProvenance::Userpass { username }) => username.clone(),
                _ => return Err(denied()),
            },
        };
        let scope = AuthScope {
            namespace,
            mount: &challenge.mount,
        };
        let current = self.mfa_validation_mount(scope, &challenge.mount_revision)?;
        let user = self
            .users_at(scope)
            .and_then(|users| users.get(&username))
            .ok_or_else(denied)?;
        if user_binding(user)? != challenge.user_binding
            || !same_mount(
                &current,
                &challenge.mount_revision,
            )?
        {
            return Err(denied());
        }
        token_cidrs::check(&user.token_bound_cidrs, origin_peer)?;
        if user.locked_until > time.seconds() {
            return Err(denied());
        }
        let Some(payload) = body.get("mfa_payload").and_then(Value::as_object) else {
            return Ok(response_failure(403, "MFA credentials are required", false));
        };
        let payload = registry.resolve_mfa_payload(&challenge, payload)?;
        let mut selected = Vec::new();
        for requirement in &challenge.requirements {
            let mut candidates = Vec::new();
            for method in requirement.methods.keys() {
                let Some(codes) = payload.get(method) else {
                    continue;
                };
                if codes.len() != 1 {
                    continue;
                }
                let Some(code) = codes[0].as_str() else {
                    continue;
                };
                let code = code.strip_prefix("passcode=").unwrap_or(code);
                let method_config = registry
                    .method(namespace, method)
                    .ok_or_else(denied)?
                    .clone();
                if code.len() != method_config.settings.digits as usize
                    || !code.bytes().all(|c| c.is_ascii_digit())
                {
                    continue;
                }
                candidates.push((
                    method.clone(),
                    method_config,
                    Zeroizing::new(code.to_owned()),
                ));
            }
            selected.push(candidates);
        }
        if selected.iter().all(Vec::is_empty) {
            return Ok(response_failure(403, "invalid MFA credentials", false));
        }
        // Each matching enforcement validates independently. A preceding
        // successful OTP is consumed even if a later rule lacks credentials;
        // the same method in two rules is deliberately not deduplicated.
        self.identity_mfa.as_mut().ok_or_else(denied)?.clock = now;
        let entity = challenge.entity().ok_or_else(denied)?.to_owned();
        let mut attempted = false;
        for candidates in selected {
            let mut requirement_valid = false;
            for (id, method, code) in candidates {
                let owner = self
                    .identity_mfa
                    .as_mut()
                    .and_then(|r| r.namespaces.get_mut(namespace))
                    .ok_or_else(denied)?;
                let Some(enrollment) = owner
                    .enrollments
                    .get_mut(&entity)
                    .and_then(|e| e.get_mut(&id))
                else {
                    // This OR candidate is unavailable, not the entire rule.
                    continue;
                };
                if let Some(last) = enrollment.last_attempt_at {
                    if now < last {
                        return Err(err(503, "MFA attempt clock regressed"));
                    }
                    if now >= plus(last, method.settings.period)? {
                        enrollment.attempts = 0;
                        enrollment.last_attempt_at = None;
                    }
                }
                enrollment.attempts = enrollment
                    .attempts
                    .checked_add(1)
                    .ok_or_else(|| err(503, "MFA attempt counter exhausted"))?;
                enrollment.last_attempt_at.get_or_insert(now);
                attempted = true;
                if enrollment.attempts > method.settings.max_validation_attempts {
                    return Ok(response_failure(
                        403,
                        "maximum MFA validation attempts exceeded",
                        true,
                    ));
                }
                let counter = now.seconds() / method.settings.period;
                let first = counter.saturating_sub(method.settings.skew);
                let last = counter
                    .checked_add(method.settings.skew)
                    .ok_or_else(|| err(503, "MFA counter overflow"))?;
                let mut accepted = None;
                for candidate in first..=last {
                    let actual = Zeroizing::new(
                        crate::engines::rfc6238_code(
                            &enrollment.secret.0,
                            &method.settings.algorithm,
                            method.settings.digits,
                            candidate,
                        )
                        .map_err(|_| err(503, "native TOTP computation unavailable"))?,
                    );
                    let left = crate::crypto::digest(actual.as_bytes());
                    let right = crate::crypto::digest(code.as_bytes());
                    if hmac::verify(
                        &hmac::Key::new(hmac::HMAC_SHA256, &left),
                        b"mfa-code",
                        hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &right), b"mfa-code")
                            .as_ref(),
                    )
                    .is_ok()
                        && enrollment
                            .last_accepted_counter
                            .is_none_or(|old| candidate > old)
                    {
                        accepted = Some(candidate);
                    }
                }
                if let Some(counter) = accepted {
                    enrollment.last_accepted_counter = Some(counter);
                    requirement_valid = true;
                    break;
                }
            }
            if !requirement_valid {
                // Fail at this rule. Prior successful or failed numeric
                // attempts remain durable, but later rules are not evaluated.
                return Ok(response_failure(403, "invalid MFA credentials", attempted));
            }
        }
        self.retire_mfa_challenge(namespace, id)?;
        let Grant::Service(token) = &challenge.grant;
        let mut response = PendingServiceGrant::response(
            token.clone(),
            challenge.mount_revision.clone(),
            challenge.user_binding.clone(),
            time,
            origin_peer,
        )?;
        response
            .pending_service
            .as_mut()
            .ok_or_else(denied)?
            .completed = true;
        response.body["auth"]["entity_id"] = json!(entity);
        Ok(response)
    }
    fn retire_mfa_challenge(&mut self, namespace: &str, id: &str) -> Result<(), AuthError> {
        let owner = self
            .identity_mfa
            .as_mut()
            .and_then(|r| r.namespaces.get_mut(namespace))
            .ok_or_else(|| bad("invalid request ID"))?;
        let challenge = owner
            .challenges
            .remove(id)
            .ok_or_else(|| bad("invalid request ID"))?;
        owner.terminal.insert(challenge.sequence);
        Ok(())
    }
}

impl AuthState {
    pub(super) fn prepare_mfa_open_janitor_observed(
        &self,
        time: AuthorityTime,
    ) -> Result<Option<MfaJanitorHead>, AuthError> {
        let now = time
            .exact()
            .ok_or_else(|| err(503, "MFA janitor requires its captured native clock"))?;
        let Some(registry) = &self.identity_mfa else {
            return Ok(None);
        };
        if now < registry.clock {
            return Err(err(503, "MFA durable clock regressed"));
        }
        // Closed namespaces deliberately remain represented by the exact
        // authenticated index. No plaintext grant is synthesized from it.
        let selected = registry
            .namespaces
            .iter()
            .flat_map(|(namespace, owner)| {
                owner.challenges.iter().map(move |(id, challenge)| {
                    (namespace, id, challenge)
                })
            })
            .min_by(|left, right| {
                (left.2.created.seconds(), left.1)
                    .cmp(&(right.2.created.seconds(), right.1))
            });
        let Some((namespace, id, challenge)) = selected else {
            return Ok(None);
        };
        challenge.verify(&registry.key.0)?;
        Ok(Some(MfaJanitorHead {
            namespace: namespace.clone(),
            id: id.clone(),
            sequence: challenge.sequence,
            binding: challenge.binding.clone(),
            created: challenge.created,
            eligible_at: challenge.expires,
            mac: Zeroizing::new(challenge.mac.clone()),
            mutation_epoch: registry.mutation_epoch,
            closed: None,
        }))
    }
    pub(super) fn finish_mfa_open_janitor_observed(
        &mut self,
        head: MfaJanitorHead,
        binding: NativeMfaBinding,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        let now = time
            .exact()
            .ok_or_else(|| err(503, "MFA janitor requires its original captured clock"))?;
        let registry = self
            .identity_mfa
            .as_mut()
            .ok_or_else(|| err(503, "MFA janitor native owner unavailable"))?;
        let challenge = registry
            .namespaces
            .get(&head.namespace)
            .and_then(|owner| owner.challenges.get(&head.id))
            .ok_or_else(|| err(503, "MFA janitor original head unavailable"))?;
        challenge.verify(&registry.key.0)?;
        if registry.mutation_epoch != head.mutation_epoch
            || head.binding != binding
            || challenge.binding != binding
            || challenge.sequence != head.sequence
            || challenge.created != head.created
            || challenge.expires != head.eligible_at
            || challenge.mac.as_slice() != head.mac.as_slice()
            || now < registry.clock
            || now < challenge.expires
        {
            return Err(err(503, "MFA janitor original owner observation changed"));
        }
        let next_epoch = registry
            .mutation_epoch
            .checked_add(1)
            .ok_or_else(|| err(503, "MFA mutation epoch exhausted"))?;
        let owner = registry
            .namespaces
            .get_mut(&head.namespace)
            .ok_or_else(|| err(503, "MFA janitor namespace owner unavailable"))?;
        // All fallible custody checks precede this one durable transition.
        let challenge = owner
            .challenges
            .remove(&head.id)
            .ok_or_else(|| err(503, "MFA janitor original head unavailable"))?;
        owner.terminal.insert(challenge.sequence);
        registry.clock = now;
        registry.mutation_epoch = next_epoch;
        Ok(())
    }
}
