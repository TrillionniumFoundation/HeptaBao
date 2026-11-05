//! Retained revocation metadata owns the original public certificate issuer.
//! A deleted issuer grants no signing capability. Its orphan CRL entry is
//! signed only by current, separately admitted private issuers.
use super::*;
use crate::auth::{AuthorityTime, RequestClock, Timestamp};

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct OrdinaryRevocation {
    pub(super) at: Timestamp,
    original_issuer: String,
    crl_issuers: BTreeSet<String>,
}
impl OrdinaryRevocation {
    pub(super) fn references_issuer(&self, issuer: &str) -> bool {
        self.original_issuer == issuer || self.crl_issuers.contains(issuer)
    }
    pub(super) fn descriptor(&self) -> Value {
        json!({"revocation_time":self.at.seconds(),"revocation_time_rfc3339":self.at.rfc3339(),"state":"revoked"})
    }
}

#[derive(Clone)]
pub(super) struct OrdinaryRevocationPlan {
    pub(super) serial: String,
    pub(super) record: OrdinaryRevocation,
    clock: Option<RequestClock>,
    actor_expires: Option<u64>,
    precise_actor_expires: Option<Timestamp>,
}
impl OrdinaryRevocationPlan {
    pub(super) fn validate_actor(&self, time: AuthorityTime) -> Result<()> {
        let time = precise_time::observe(time, self.clock, self.record.at.seconds())?;
        if self
            .precise_actor_expires
            .is_some_and(|end| time.exact().is_none_or(|at| at > end))
            || self.precise_actor_expires.is_none()
                && self.actor_expires.is_some_and(|end| time.seconds() >= end)
        {
            return Err(error(
                403,
                "administrative PKI original caller expired before signing",
            ));
        }
        Ok(())
    }
    pub(super) fn validate(&self, pki: &Pki, now: u64) -> Result<()> {
        self.validate_actor(AuthorityTime::Coarse(now))?;
        let issued = pki.issued.get(&self.serial).ok_or_else(not_found)?;
        if pki.external_leaf_issuer_reference(&self.serial)? != self.record.original_issuer
            || issued
                .revoked_at
                .is_some_and(|at| at != self.record.at.seconds())
            || pki
                .ordinary_revocations
                .get(&self.serial)
                .is_some_and(|prior| {
                    prior.at != self.record.at
                        || prior.original_issuer != self.record.original_issuer
                })
        {
            return Err(error(503, "ordinary PKI revocation owner changed"));
        }
        Ok(())
    }
}

impl Pki {
    pub(in crate::engines) fn ordinary_revocation_floor(&self) -> Option<Timestamp> {
        self.ordinary_revocations.values().map(|r| r.at).max()
    }
    pub(super) fn ordinary_revocation(&self, serial: &str) -> Option<&OrdinaryRevocation> {
        self.ordinary_revocations.get(serial)
    }
    pub(super) fn ordinary_original_issuer_retired(&self, serial: &str) -> bool {
        self.external_leaf_issuer_reference(serial)
            .is_ok_and(|original| {
                !self
                    .external_signers()
                    .any(|(key, _)| key.issuer_id == original)
            })
    }
    pub(super) fn ordinary_orphan_candidate(&self, serial: &str) -> bool {
        self.ordinary_revocations.get(serial).is_some_and(|record| {
            self.ordinary_original_issuer_retired(serial)
                && self
                    .issued
                    .get(serial)
                    .is_some_and(|issued| issued.revoked_at == Some(record.at.seconds()))
        })
    }
    pub(super) fn ordinary_orphan_for_crl(&self, serial: &str, signer: &str) -> bool {
        self.ordinary_revocations.get(serial).is_some_and(|record| {
            record.crl_issuers.contains(signer)
                && self.ordinary_original_issuer_retired(serial)
                && self
                    .issued
                    .get(serial)
                    .is_some_and(|issued| issued.revoked_at == Some(record.at.seconds()))
        })
    }
    pub(super) fn ordinary_public_issuer_referenced(&self, issuer: &str) -> bool {
        self.ordinary_revocations
            .values()
            .any(|r| r.original_issuer == issuer || r.crl_issuers.contains(issuer))
    }
    pub(super) fn ordinary_crl_signed(&mut self, signer: &str, entries: &BTreeMap<String, u64>) {
        for (serial, at) in entries {
            if self.ordinary_original_issuer_retired(serial)
                && let Some(record) = self.ordinary_revocations.get_mut(serial)
                && record.at.seconds() == *at
            {
                record.crl_issuers.insert(signer.to_owned());
            }
        }
    }
    pub(super) fn prepare_ordinary_revocation(
        &self,
        serial: &str,
        context: &PkiRequestContext<'_>,
    ) -> Result<Option<OrdinaryRevocationPlan>> {
        let Some(issued) = self.issued.get(serial) else {
            return Ok(None);
        };
        if issued.external_issuer_owner.is_none()
            || self.acme_certificate_for_serial(serial)?.is_some()
        {
            return Ok(None);
        }
        let actor = context
            .owner
            .ok_or_else(|| error(403, "administrative PKI caller required"))?;
        let time = context.observed_time(issued.issued)?;
        let at = time
            .exact()
            .or_else(|| Timestamp::whole(time.seconds()).ok())
            .ok_or_else(|| error(503, "ordinary PKI original clock unavailable"))?;
        let original = self.external_leaf_issuer_reference(serial)?.to_owned();
        let record = self
            .ordinary_revocations
            .get(serial)
            .cloned()
            .unwrap_or(OrdinaryRevocation {
                at: issued
                    .revoked_at
                    .map(Timestamp::whole)
                    .transpose()
                    .map_err(|_| bad("ordinary PKI revoked time"))?
                    .unwrap_or(at),
                original_issuer: original,
                crl_issuers: BTreeSet::new(),
            });
        let mut plan = OrdinaryRevocationPlan {
            serial: serial.to_owned(),
            record,
            clock: context.clock,
            actor_expires: actor.expires_at,
            precise_actor_expires: actor.precise_expires_at,
        };
        if !self.ordinary_original_issuer_retired(serial) {
            plan.record
                .crl_issuers
                .insert(plan.record.original_issuer.clone());
        }
        plan.validate_actor(time)?;
        Ok(Some(plan))
    }
    pub(super) fn stage_ordinary_revocation(
        &mut self,
        plan: &OrdinaryRevocationPlan,
    ) -> Result<Value> {
        plan.validate(self, plan.record.at.seconds())?;
        self.issued
            .get_mut(&plan.serial)
            .ok_or_else(not_found)?
            .revoked_at = Some(plan.record.at.seconds());
        let mut record = plan.record.clone();
        if let Some(prior) = self.ordinary_revocations.get(&plan.serial) {
            record.crl_issuers.extend(prior.crl_issuers.iter().cloned());
        }
        self.ordinary_revocations
            .insert(plan.serial.clone(), record);
        Ok(plan.record.descriptor())
    }
    pub(in crate::engines) fn revoke_retired_ordinary_without_signer(
        &mut self,
        body: &Value,
        context: &PkiRequestContext<'_>,
    ) -> Result<Option<EngineResponse>> {
        if self.root.is_some() {
            return Ok(None);
        };
        reject_unknown(body, &["serial_number"])?;
        let serial = self.resolve_certificate_serial(string(body, "serial_number")?)?;
        let Some(plan) = self.prepare_ordinary_revocation(&serial, context)? else {
            return Ok(None);
        };
        if !self.ordinary_original_issuer_retired(&serial) {
            return Err(error(503, "retired ordinary issuer is still active"));
        }
        let changed = self.ordinary_revocation(&serial).is_none();
        let descriptor = self.stage_ordinary_revocation(&plan)?;
        Ok(Some(ok(descriptor, changed)))
    }
    pub(super) fn validate_ordinary_revocations(&self, clock: u64) -> Result<()> {
        if self.ordinary_revocations.len() > MAX_ISSUED {
            return Err(bad("ordinary PKI revocation bounds"));
        }
        for (serial, record) in &self.ordinary_revocations {
            let issued = self
                .issued
                .get(serial)
                .ok_or_else(|| bad("ordinary revocation certificate missing"))?;
            if record.at.seconds() < issued.issued
                || record.at.seconds() > clock
                || issued.revoked_at != Some(record.at.seconds())
                || self.external_leaf_issuer_reference(serial)? != record.original_issuer
                || record
                    .crl_issuers
                    .iter()
                    .any(|id| !self.has_external_public_archive(id))
                || record.crl_issuers.iter().any(|id| {
                    id != &record.original_issuer && !self.ordinary_original_issuer_retired(serial)
                })
            {
                return Err(bad("ordinary PKI revocation public owner differs"));
            }
        }
        Ok(())
    }
    pub(in crate::engines) fn validate_ordinary_revocation_successor(
        &self,
        previous: &Self,
    ) -> Result<()> {
        for (serial, old) in &previous.ordinary_revocations {
            if !self.issued.contains_key(serial) {
                continue;
            }
            let current = self
                .ordinary_revocations
                .get(serial)
                .ok_or_else(|| bad("ordinary revocation owner removed"))?;
            if current.at != old.at
                || current.original_issuer != old.original_issuer
                || !old.crl_issuers.is_subset(&current.crl_issuers)
            {
                return Err(bad("ordinary revocation owner rolled back"));
            }
        }
        Ok(())
    }
}
