//! Public revocation effects retain the verified account/leaf proof and same
//! original request clock. Public possession never becomes a Vault principal.
use super::*;
use crate::auth::RequestClock;
use pki::acme_revoke::Revocation;
use pki::external::{AcmeCrlTemplate, ExternalPkiPublicKey};
use zeroize::Zeroizing;

pub(crate) enum AcmeExternalEffect {
    Finalize(Box<AcmeExternalFinalize>),
    Revoke(Box<AcmeExternalRevoke>),
}
pub(crate) struct AcmeExternalRevoke {
    owner: AcmeBinding,
    request: SecretValue,
    template: AcmeCrlTemplate,
    revocation: Revocation,
    clock: Option<RequestClock>,
}
impl AcmeExternalEffect {
    pub(crate) fn request(&self) -> &SecretValue {
        match self {
            Self::Finalize(p) => &p.request,
            Self::Revoke(p) => &p.request,
        }
    }
    pub(crate) fn validate_before_effect(
        &self,
        engines: &EngineState,
        at: Timestamp,
    ) -> Result<()> {
        match self {
            Self::Finalize(p) => p.validate_before_effect(engines, at),
            Self::Revoke(p) => p.validate(engines, at),
        }
    }
    pub(crate) fn validate_provider_public(&self, key: &ExternalPkiPublicKey) -> Result<()> {
        match self {
            Self::Finalize(p) => p.template.validate_provider_public(key),
            Self::Revoke(p) => p.template.validate_provider_public(key),
        }
    }
    pub(crate) fn signing_inputs(&self) -> Result<Vec<Vec<u8>>> {
        match self {
            Self::Finalize(p) => Ok(vec![p.template.signing_input()?]),
            Self::Revoke(p) => p.template.signing_inputs(),
        }
    }
    pub(crate) fn hash_algorithm(&self) -> Option<&'static str> {
        match self {
            Self::Finalize(p) => p.template.hash_algorithm(),
            Self::Revoke(p) => p.template.hash_algorithm(),
        }
    }
    pub(crate) fn signature_algorithm(&self) -> &'static str {
        match self {
            Self::Finalize(p) => p.template.signature_algorithm(),
            Self::Revoke(p) => p.template.signature_algorithm(),
        }
    }
    pub(crate) fn signature_size_bound(&self) -> usize {
        match self {
            Self::Finalize(p) => p.template.signature_size_bound(),
            Self::Revoke(p) => p.template.signature_size_bound(),
        }
    }
}
impl AcmeExternalRevoke {
    fn validate(&self, engines: &EngineState, at: Timestamp) -> Result<()> {
        let at = engines.acme_observed_time(at).max(
            Timestamp::whole(engines.lease_clock)
                .map_err(|_| error(503, "ACME original revocation floor unavailable"))?,
        );
        let pki = engines.acme_pki(&self.owner)?;
        pki.validate_live_acme_revocation(&self.revocation, at, false)?;
        self.template.validate_issuer(pki)?;
        let ns = engines
            .namespaces
            .get(&self.owner.namespace)
            .ok_or_else(|| error(503, "ACME external namespace owner unavailable"))?;
        let request = ns.external_keys.transit_consumer_request(
            &self.template.reference,
            &self.owner.mount,
            "sign",
            SecretJson(json!({"input":"","prehashed":false,"signature_algorithm":"pkcs1v15"})),
        )?;
        if request.expose() != self.request.expose() {
            return Err(error(
                503,
                "ACME revocation signing grant or provider binding changed",
            ));
        }
        Ok(())
    }
}
impl EngineState {
    pub(super) fn prepare_acme_external_revoke(
        &self,
        view: &AcmeView,
        proof: &pki::acme_jws::VerifiedJws,
        key: &AcmeJwk,
        kid: Option<&str>,
        at: Timestamp,
        clock: Option<RequestClock>,
    ) -> Result<Option<AcmeExternalEffect>> {
        let mounted = self.acme_pki(&view.owner)?;
        let account = kid.and_then(|value| value.rsplit('/').next());
        let at = self.acme_observed_time(at).max(
            Timestamp::whole(self.lease_clock)
                .map_err(|_| error(503, "ACME original revocation floor unavailable"))?,
        );
        let revoked = mounted.acme_prepare_revocation(key, proof, account, at, clock)?;
        let at = at.max(revoked.at);
        if mounted
            .external_acme_issuer_evidence(&revoked.issuer)?
            .is_none()
        {
            return Ok(None);
        }
        let template = mounted.prepare_acme_external_crl(&revoked, at)?;
        let request = self
            .namespaces
            .get(&view.owner.namespace)
            .ok_or_else(|| error(503, "ACME external namespace owner unavailable"))?
            .external_keys
            .transit_consumer_request(
                &template.reference,
                &view.owner.mount,
                "sign",
                SecretJson(json!({"input":"","prehashed":false,"signature_algorithm":"pkcs1v15"})),
            )?;
        let plan = AcmeExternalRevoke {
            owner: view.owner.clone(),
            request,
            template,
            revocation: revoked,
            clock,
        };
        plan.validate(self, at)?;
        Ok(Some(AcmeExternalEffect::Revoke(Box::new(plan))))
    }
    pub(crate) fn publish_acme_external_effect(
        &mut self,
        plan: AcmeExternalEffect,
        signatures: &[Zeroizing<Vec<u8>>],
        at: Timestamp,
    ) -> Result<(Value, Option<String>, AcmeExternalDelivery)> {
        match plan {
            AcmeExternalEffect::Finalize(p) => {
                if signatures.len() != 1 {
                    return Err(error(503, "ACME certificate signature count changed"));
                }
                let (body, location, delivery) =
                    self.publish_acme_external_finalize(*p, &signatures[0], at)?;
                Ok((
                    body,
                    Some(location),
                    AcmeExternalDelivery::Certificate(Box::new(delivery)),
                ))
            }
            AcmeExternalEffect::Revoke(p) => {
                p.validate(self, at)?;
                let at = self.acme_observed_time(at);
                let end = p
                    .clock
                    .map(|clock| clock.with_timestamp_floor(at).observed_at())
                    .transpose()
                    .map_err(|_| error(503, "ACME original revocation clock unavailable"))?
                    .unwrap_or(at);
                p.validate(self, end)?;
                let at = self.observe_acme(end)?;
                let pki = self.acme_pki_mut(&p.owner)?;
                p.template.publish(pki, signatures, at)?;
                pki.mark_acme_external_global_revocation(&p.revocation)?;
                let body = p.revocation.descriptor();
                let protocol = pki
                    .acme_protocol
                    .as_mut()
                    .ok_or_else(|| error(503, "ACME revocation owner unavailable"))?;
                protocol.observe_time(at);
                protocol
                    .revocations
                    .insert(p.revocation.serial.clone(), p.revocation.clone());
                pki.validate_live_acme_revocation(&p.revocation, at, true)?;
                self.lease_clock = self.lease_clock.max(at.seconds());
                Ok((
                    body,
                    None,
                    AcmeExternalDelivery::Revocation {
                        owner: p.owner,
                        revocation: Box::new(p.revocation),
                    },
                ))
            }
        }
    }
}
pub(crate) enum AcmeExternalDelivery {
    Certificate(Box<AcmeExternalCertificateDelivery>),
    Revocation {
        owner: AcmeBinding,
        revocation: Box<Revocation>,
    },
}
impl AcmeExternalDelivery {
    pub(crate) fn validate(&self, engines: &EngineState, at: Timestamp) -> Result<()> {
        match self {
            Self::Certificate(delivery) => delivery.validate(engines, at),
            Self::Revocation { owner, revocation } => {
                let at = engines.acme_observed_time(at).max(
                    Timestamp::whole(engines.lease_clock)
                        .map_err(|_| error(503, "ACME delivery revocation floor unavailable"))?,
                );
                engines
                    .acme_pki(owner)?
                    .validate_live_acme_revocation(revocation, at, true)
            }
        }
    }
}
