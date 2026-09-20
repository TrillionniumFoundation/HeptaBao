//! Provider renewals share request admission and publication; each issuer owns
//! its credential validation and policy decision. Credentials never enter an
//! API response or an intermediate serialized plaintext allocation.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
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

    pub(crate) fn observed_now(&self) -> u64 {
        match self {
            Self::Radius(plan) => plan.observed_now(),
            Self::Ldap(plan) => plan.observed_now(),
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
        if !matches!(method, "POST" | "PUT")
            || !matches!(
                path,
                "auth/token/renew-self" | "auth/token/renew" | "auth/token/renew-accessor"
            )
        {
            return Ok(None);
        }
        let actor = self.permission(principal, namespace, path, "update", now)?;
        let target = match path {
            "auth/token/renew-self" => {
                reject_unknown(body, &["increment"])?;
                actor.digest.clone()
            }
            "auth/token/renew" => {
                reject_unknown(body, &["token", "increment"])?;
                self.target_token(namespace, body, false)?
            }
            _ => {
                reject_unknown(body, &["accessor", "increment"])?;
                self.target_token(namespace, body, true)?
            }
        };
        let target = Zeroizing::new(target);
        let token = self.active_token(&target, now, false)?;
        let increment = duration(body, "increment", 0)?;
        match token.auth_provenance {
            Some(TokenAuthProvenance::Radius { .. }) => self
                .prepare_radius_renewal_target(namespace, path, target, increment, now)
                .map(ProviderRenewalPlan::Radius)
                .map(Some),
            Some(TokenAuthProvenance::Ldap { .. }) => self
                .prepare_ldap_renewal_target(namespace, path, target, increment, now)
                .map(ProviderRenewalPlan::Ldap)
                .map(Some),
            _ => {
                self.require_offline_renewal_origin(&target)?;
                Ok(None)
            }
        }
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
