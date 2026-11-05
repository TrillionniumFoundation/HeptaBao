//! Advanced SDK input is bounded; authority stays with the actual native owner.
use super::*;

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Format {
    #[serde(rename = "sdk_advanced_v1")]
    V1,
}
pub(super) struct Options {
    pub(super) period: token_precision::DurationNanos,
    pub(super) explicit_max: token_precision::DurationNanos,
    pub(super) cidrs: Option<Vec<String>>,
    pub(super) groups: Option<BTreeSet<String>>,
    pub(super) batch: bool,
}
impl Options {
    pub(super) fn parse(
        object: &serde_json::Map<String, Value>,
        mount: &AuthMount,
    ) -> Result<Self, AuthError> {
        for key in ["external_namespace_policies", "mfa_requirement"] {
            if object.get(key).is_some_and(|value| {
                !value.is_null() && !value.as_object().is_some_and(serde_json::Map::is_empty)
            }) {
                return Err(err(
                    501,
                    "SDK external namespace policies and MFA are not implemented",
                ));
            }
        }
        let period = token_precision::DurationNanos::checked(sdk_natural(object, "period")?)
            .map_err(|_| bad("SDK period rejected"))?;
        let explicit_max =
            token_precision::DurationNanos::checked(sdk_natural(object, "explicit_max_ttl")?)
                .map_err(|_| bad("SDK explicit maximum rejected"))?;
        let requested = sdk_natural(object, "token_type")?;
        let user = match requested {
            0 | 3 | 4 => batch_issuance::UserTokenType::Default,
            1 => batch_issuance::UserTokenType::Service,
            2 => batch_issuance::UserTokenType::Batch,
            _ => return Err(bad("SDK token_type rejected")),
        };
        let default = if requested == 4 {
            batch_issuance::MountTokenType::DefaultBatch
        } else {
            batch_issuance::MountTokenType::DefaultService
        };
        let batch = mount.token_type.unwrap_or(default).resolves_batch(user);
        if batch && (!period.is_zero() || sdk_natural(object, "num_uses")? != 0) {
            return Err(bad("batch tokens cannot have a period or limited uses"));
        }
        let cidrs = match object.get("bound_cidrs") {
            None | Some(Value::Null) => None,
            Some(value) => {
                if !value.is_array() {
                    return Err(bad("SDK bound CIDRs require an array of strings"));
                }
                Some(token_cidrs::field(&json!({"token_bound_cidrs":value}))?)
            }
        };
        let groups = match object.get("group_aliases") {
            None | Some(Value::Null) => None,
            Some(value) => {
                let array = value
                    .as_array()
                    .filter(|array| array.len() <= 128)
                    .ok_or_else(|| bad("SDK group aliases exceed the bounded array"))?;
                let mut names = BTreeSet::new();
                for value in array {
                    let alias = value
                        .as_object()
                        .ok_or_else(|| bad("SDK group alias requires an object"))?;
                    let name = alias
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|name| {
                            !name.is_empty()
                                && name.len() <= 1024
                                && !name.chars().any(char::is_control)
                        })
                        .ok_or_else(|| bad("SDK group alias name rejected"))?;
                    // Provider mount/accessor/namespace never selects native ownership.
                    names.insert(name.to_owned());
                }
                Some(names)
            }
        };
        Ok(Self {
            period,
            explicit_max,
            cidrs,
            groups,
            batch,
        })
    }
    pub(super) fn active(&self) -> bool {
        !self.period.is_zero()
            || !self.explicit_max.is_zero()
            || self.batch
            || self.cidrs.as_ref().is_some_and(|values| !values.is_empty())
            || self.groups.is_some()
    }
    pub(super) fn project_groups(
        &self,
        response: &mut AuthResponse,
        binding: &Binding,
        alias: &str,
    ) {
        if let Some(names) = &self.groups {
            response.external_groups = Some(identity::ExternalGroups {
                mount: binding.mount.clone(),
                alias: alias.to_owned(),
                names: names.clone(),
            });
        }
    }
}
impl TokenOrigin {
    pub(super) fn validate_sdk_lifetime(&self, token: &Token) -> Result<(), AuthError> {
        let expiry = self
            .lease
            .expires_at
            .ok_or_else(|| err(503, "SDK Auth saved expiry absent"))?;
        if token.max_expires_at
            != self
                .maximum
                .map(Timestamp::ceil_seconds)
                .transpose()
                .map_err(|_| err(503, "SDK maximum projection rejected"))?
            || self.maximum.is_some_and(|maximum| maximum < expiry)
        {
            return Err(err(503, "SDK Auth saved maximum rejected"));
        }
        if self.advanced.is_none() {
            if self.maximum.is_none()
                || !self.lease.requested_period.is_zero()
                || !self.lease.requested_explicit_max.is_zero()
                || token.period != 0
                || !token.bound_cidrs.is_empty()
                || self.identity_alias.is_some()
            {
                return Err(err(
                    503,
                    "ordinary SDK lifetime cannot carry advanced authority",
                ));
            }
            return Ok(());
        }
        if token.period != self.lease.requested_period.ceil_seconds()
            || (!self.lease.requested_period.is_zero()
                && self.lease.previous_grant > self.lease.requested_period)
            || (self.lease.requested_period.is_zero() && self.maximum.is_none())
        {
            return Err(err(503, "SDK period projection rejected"));
        }
        if !self.lease.requested_explicit_max.is_zero() {
            let limit = self
                .lease
                .issued_at
                .checked_add(self.lease.requested_explicit_max)
                .map_err(|_| err(503, "SDK explicit maximum overflow"))?;
            if self.maximum.is_none_or(|maximum| maximum > limit) {
                return Err(err(503, "SDK explicit maximum rejected"));
            }
        } else if !self.lease.requested_period.is_zero() && self.maximum.is_some() {
            return Err(err(
                503,
                "SDK unbounded period has a false lifetime maximum",
            ));
        }
        if self.identity_alias.as_deref().is_some_and(|alias| {
            alias.is_empty() || alias.len() > 1024 || alias.chars().any(char::is_control)
        }) {
            return Err(err(503, "SDK saved identity alias rejected"));
        }
        token_cidrs::validate(&token.bound_cidrs)
    }
}
impl AuthState {
    pub(crate) fn mark_sdk_advanced_state(&mut self) {
        self.sdk_advanced_format = Some(Format::V1);
    }
    pub(crate) fn has_sdk_advanced_state(&self) -> bool {
        self.sdk_advanced_format.is_some()
    }
    pub(crate) fn validate_sdk_advanced_state(
        &self,
        previous: Option<&Self>,
    ) -> Result<(), AuthError> {
        if previous.is_some_and(Self::has_sdk_advanced_state) && !self.has_sdk_advanced_state() {
            return Err(err(503, "SDK advanced custody cannot be removed"));
        }
        for token in self.tokens.values() {
            if token
                .wrapping
                .as_ref()
                .is_some_and(wrapping::WrappedResponse::has_sdk_origin)
                && !self.has_sdk_advanced_state()
            {
                return Err(err(503, "SDK wrapped response custody marker missing"));
            }
            if let Some(TokenAuthProvenance::Sdk { origin }) = &token.auth_provenance {
                origin.validate_sdk_lifetime(token)?;
                if origin.advanced.is_some() && !self.has_sdk_advanced_state() {
                    return Err(err(503, "SDK advanced custody marker missing"));
                }
            }
        }
        Ok(())
    }
    pub(crate) fn sdk_batch_lease_issuer_live(
        &self,
        owner: &LeaseOwner,
        namespace: &str,
    ) -> Result<bool, AuthError> {
        let Some(claims) = owner.batch_claims() else {
            return Ok(true);
        };
        let Some(issuer) = claims.sdk_issuer() else {
            return Ok(true);
        };
        self.validate_batch_lease_owner(claims, namespace)?;
        Ok(issuer.live(self))
    }
    pub(crate) fn validate_sdk_batch_binding(&self, binding: &Binding) -> Result<(), AuthError> {
        if !self.has_sdk_advanced_state() {
            return Err(denied());
        }
        self.sdk_auth_owner_gate(binding).map_err(|_| denied())
    }
}
/// Authenticated SDK issuer projection carried by a real BatchLeaseClaims owner.
/// It is not a bearer or an admission. Current scope checks still use the native
/// catalog/mount, while history validation accepts a retired known generation.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchIssuer {
    namespace: String,
    mount: String,
    plugin: String,
    version: String,
    generation: u64,
    accessor: String,
    revision: u64,
}
impl BatchIssuer {
    pub(crate) fn from_binding(binding: &Binding) -> Self {
        Self {
            namespace: binding.namespace.clone(),
            mount: binding.mount.clone(),
            plugin: binding.descriptor.name.clone(),
            version: binding.descriptor.version.clone(),
            generation: binding.descriptor.generation,
            accessor: binding.owner.accessor.clone().unwrap_or_default(),
            revision: binding.owner.revision,
        }
    }
    pub(crate) fn validate(&self, namespace: &str) -> Result<(), batch::BatchError> {
        if self.namespace != namespace
            || validate_namespace(namespace).is_err()
            || self.mount.is_empty()
            || self.mount.len() > 512
            || self.mount.split('/').any(|part| !valid_name(part))
            || self.plugin.is_empty()
            || self.version.is_empty()
            || self.generation == 0
            || self.accessor.is_empty()
            || self.accessor.len() > 1024
            || self.revision == 0
        {
            return Err(batch::BatchError::InvalidClaims);
        }
        Ok(())
    }
    pub(crate) fn validate_history(
        &self,
        auth: &AuthState,
        namespace: &str,
    ) -> Result<(), AuthError> {
        self.validate(namespace)
            .map_err(|_| err(503, "SDK batch saved issuer rejected"))?;
        if !auth.has_sdk_advanced_state()
            || auth.sdk_auth_catalog.as_ref().is_none_or(|catalog| {
                !catalog.known_generation(&self.plugin, &self.version, self.generation)
            })
        {
            return Err(err(503, "SDK batch saved issuer generation rejected"));
        }
        Ok(())
    }
    pub(crate) fn live(&self, auth: &AuthState) -> bool {
        self.validate_history(auth, &self.namespace).is_ok()
            && auth
                .sdk_auth_binding(&self.namespace, &format!("auth/{}/", self.mount))
                .ok()
                .flatten()
                .is_some_and(|actual| Self::from_binding(&actual) == *self)
    }
}
impl Token {
    pub(crate) fn issuer_precise_expiry(&self) -> Option<Timestamp> {
        match &self.auth_provenance {
            Some(TokenAuthProvenance::Sdk { origin }) => origin.lease.expires_at,
            _ => self
                .token_api_precision
                .as_ref()
                .and_then(|lease| lease.expires_at),
        }
    }
}
impl TokenOrigin {
    pub(crate) fn project_lookup(
        &self,
        info: &mut Value,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        let at = time.exact().ok_or_else(denied)?;
        info["meta"] = json!(self.metadata);
        info["creation_ttl"] = json!(self.lease.creation_grant.public_seconds());
        info["explicit_max_ttl"] = json!(self.lease.requested_explicit_max.public_seconds());
        info["ttl"] = json!(
            self.lease
                .expires_at
                .ok_or_else(denied)?
                .lookup_remaining_seconds(at)
                .map_err(|_| denied())?
        );
        info["expire_time"] = json!(
            self.lease
                .expires_at
                .map(Timestamp::local_rfc3339)
                .transpose()?
        );
        info["issue_time"] = json!(self.lease.issued_at.local_rfc3339()?);
        if !self.lease.requested_period.is_zero() {
            info["period"] = json!(self.lease.requested_period.public_seconds());
        }
        if let Some(last) = self.lease.last_renewed_at {
            info["last_renewal"] = json!(last.local_rfc3339()?);
            info["last_renewal_time"] = json!(last.seconds());
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "auth_sdk_advanced_tests.rs"]
mod tests;
