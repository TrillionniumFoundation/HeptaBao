//! Provider renewals share request admission and publication; each issuer owns
//! its credential validation and policy decision. Credentials never enter an
//! API response or an intermediate serialized plaintext allocation.
use super::*;

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(transparent)]
pub(super) struct ProviderCredential(pub(super) String);

impl ProviderCredential {
    pub(super) fn new(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl Drop for ProviderCredential {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) enum ProviderRenewalPlan {
    Radius(RadiusRenewalPlan),
    Ldap(LdapRenewalPlan),
}

pub(crate) enum ProviderRenewalObservation {
    Radius(RadiusRenewalObservation),
    Ldap(LdapRenewalObservation),
}

impl ProviderRenewalPlan {
    pub(crate) fn execute(
        &self,
        outbound: &crate::outbound::Outbound,
    ) -> Result<ProviderRenewalObservation, AuthError> {
        match self {
            Self::Radius(plan) => plan
                .execute(outbound)
                .map(ProviderRenewalObservation::Radius),
            Self::Ldap(plan) => plan.execute(outbound).map(ProviderRenewalObservation::Ldap),
        }
    }

    pub(crate) fn observed_now_for(&self, actor: &Principal) -> Result<u64, AuthError> {
        match self {
            Self::Radius(plan) => plan.observed_now_for(actor),
            Self::Ldap(plan) => plan.observed_now_for(actor),
        }
    }

    pub(crate) fn delivery_target(&self) -> &str {
        match self {
            Self::Radius(plan) => plan.delivery_target(),
            Self::Ldap(plan) => plan.delivery_target(),
        }
    }
}

pub(super) fn state_revision<T: Serialize>(value: &T) -> Result<[u8; 32], AuthError> {
    struct DigestWriter(digest::Context);
    impl std::io::Write for DigestWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = DigestWriter(digest::Context::new(&digest::SHA256));
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| err(500, "renewal authority revision unavailable"))?;
    let mut revision = [0; 32];
    revision.copy_from_slice(writer.0.finish().as_ref());
    Ok(revision)
}

pub(super) fn same_policies(left: &BTreeSet<String>, right: &BTreeSet<String>) -> bool {
    left.iter()
        .filter(|name| name.as_str() != "default")
        .eq(right.iter().filter(|name| name.as_str() != "default"))
}

impl AuthState {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_provider_renewal(
        &self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<ProviderRenewalPlan>, AuthError> {
        self.prepare_provider_renewal_observed(
            principal,
            namespace,
            method,
            path,
            body,
            AuthorityTime::Coarse(now),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_provider_renewal_observed(
        &self,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        time: AuthorityTime,
    ) -> Result<Option<ProviderRenewalPlan>, AuthError> {
        if !matches!(method, "POST" | "PUT")
            || !matches!(
                path,
                "auth/token/renew-self" | "auth/token/renew" | "auth/token/renew-accessor"
            )
        {
            return Ok(None);
        }
        let actor = self.permission_observed(principal, namespace, path, "update", time)?;
        let time = self.principal_token_api_time(actor, time)?;
        let target = match path {
            "auth/token/renew-self" => {
                reject_unknown(body, &["increment"])?;
                actor.require_service("batch tokens cannot be renewed")?;
                actor.digest.clone()
            }
            "auth/token/renew" => {
                reject_unknown(body, &["token", "increment"])?;
                self.target_token_observed(namespace, body, false, time)?
            }
            _ => {
                reject_unknown(body, &["accessor", "increment"])?;
                self.target_token_observed(namespace, body, true, time)?
            }
        };
        let target = Zeroizing::new(target);
        // This online-provider probe does not own offline Token API renewal.
        // Retained issuer provenance, after the real actor path ACL and namespace
        // target resolution, lets its handler classify its own expired record.
        // An absent/revoked target is never promoted into an offline handle.
        if self.tokens.get(target.as_str()).is_some_and(|token| {
            token.namespace == namespace
                && matches!(
                    token.auth_provenance,
                    Some(TokenAuthProvenance::TokenApi { .. })
                )
        }) {
            return Ok(None);
        }
        let token = self.active_token_observed(&target, time, false)?;
        let increment = duration(body, "increment", 0)?;
        match token.auth_provenance {
            Some(TokenAuthProvenance::Radius { .. } | TokenAuthProvenance::RadiusNative { .. }) => {
                self.prepare_radius_renewal_target(namespace, path, target, increment, time)
                    .map(ProviderRenewalPlan::Radius)
                    .map(Some)
            }
            Some(TokenAuthProvenance::Ldap { .. } | TokenAuthProvenance::LdapNative { .. }) => self
                .prepare_ldap_renewal_target(namespace, path, target, increment, time)
                .map(ProviderRenewalPlan::Ldap)
                .map(Some),
            _ => {
                self.require_offline_renewal_origin(&target)?;
                Ok(None)
            }
        }
    }

    pub(crate) fn validate_provider_renewal_delivery(
        &self,
        actor: &Principal,
        namespace: &str,
        path: &str,
        target: &str,
        now: u64,
    ) -> Result<(), AuthError> {
        let time = self.principal_token_api_time(actor, AuthorityTime::Coarse(now))?;
        self.authorize_request_observed(actor, namespace, path, "update", time)?;
        let time = self.principal_token_api_time(actor, time)?;
        let token = self.active_token_observed(target, time, false)?;
        if token.namespace != namespace {
            return Err(denied());
        }
        Ok(())
    }

    pub(crate) fn finish_provider_renewal(
        &mut self,
        plan: ProviderRenewalPlan,
        actor: &Principal,
        observation: ProviderRenewalObservation,
        now: u64,
    ) -> Result<AuthResponse, AuthError> {
        match (plan, observation) {
            (
                ProviderRenewalPlan::Radius(plan),
                ProviderRenewalObservation::Radius(observation),
            ) => self.finish_radius_renewal(plan, actor, observation, now),
            (ProviderRenewalPlan::Ldap(plan), ProviderRenewalObservation::Ldap(observation)) => {
                self.finish_ldap_renewal(plan, actor, observation, now)
            }
            _ => Err(err(503, "provider renewal observation type mismatch")),
        }
    }
}
