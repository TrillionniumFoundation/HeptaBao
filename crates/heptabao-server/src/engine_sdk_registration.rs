//! Historical standard SDK entrance and registration provenance, not a live
//! Principal. Encrypted Lease records own this immutable typed metadata.
use super::*;
use crate::auth::{
    AcceptedSdkLeaseIssuer, AuthState, AuthorityTime, LeaseOwner, ResolvedLeaseOwner, Timestamp,
};
use crate::engines::sdk_lease::{Lease, Phase};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Expiry {
    seconds: Option<u64>,
    precise: Option<Timestamp>,
}
impl Expiry {
    fn from_owner(owner: &ResolvedLeaseOwner) -> Self {
        Self {
            seconds: owner.expires_at,
            precise: owner.precise_expires_at,
        }
    }
    fn ended(&self, at: Timestamp) -> bool {
        match self.precise {
            Some(end) => at > end,
            None => self.seconds.is_some_and(|end| at.seconds() >= end),
        }
    }
    fn validate(&self) -> Result<()> {
        if let Some(end) = self.precise
            && self.seconds
                != Some(
                    end.ceil_seconds().map_err(|_| {
                        error(503, "SDK registration precise parent expiry rejected")
                    })?,
                )
        {
            return Err(error(
                503,
                "SDK registration precise parent expiry rejected",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Parent {
    Linked {
        expiry: Expiry,
    },
    Ended {
        reason: EndReason,
    },
    FinalUse,
    Batch {
        expiry: Expiry,
        parent_instance: Option<String>,
    },
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
enum EndReason {
    OriginalExpiry,
    CurrentOwnerMissing,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registration {
    version: u8,
    accepted: Timestamp,
    registered: Timestamp,
    namespace_incarnation: Option<u64>,
    instance: String,
    original_expiry: Expiry,
    parent: Parent,
}
impl Registration {
    pub(crate) fn from_entry(
        entry: &AcceptedSdkLeaseIssuer,
        accepted: Timestamp,
        registered: Timestamp,
        final_use: bool,
        auth: &AuthState,
        namespace: &str,
        namespace_incarnation: Option<u64>,
    ) -> Result<Self> {
        let owner = &entry.issuer;
        if let Some(claims) = owner.owner.batch_claims() {
            auth.validate_batch_lease_owner(claims, namespace)
                .map_err(|_| error(503, "SDK accepted batch owner structure rejected"))?;
            if final_use || claims.parent().is_some() != entry.parent_instance.is_some() {
                return Err(error(503, "SDK batch entrance parent anchor rejected"));
            }
            return Ok(Self {
                version: 1,
                accepted,
                registered,
                namespace_incarnation,
                instance: instance_hex(&entry.instance),
                original_expiry: Expiry::from_owner(owner),
                parent: Parent::Batch {
                    expiry: Expiry::from_owner(owner),
                    parent_instance: entry.parent_instance.as_ref().map(instance_hex),
                },
            });
        }
        if auth
            .sdk_service_parent_instance(&owner.owner, namespace)
            .map_err(|_| error(503, "SDK registration parent instance observation rejected"))?
            .is_some_and(|current| current != entry.instance)
        {
            return Err(error(503, "SDK registration parent instance changed"));
        }
        let original_expiry = Expiry::from_owner(owner);
        let parent = if final_use {
            Parent::FinalUse
        } else if let Some(current) = auth
            .standard_sdk_service_parent_observed(
                &owner.owner,
                namespace,
                AuthorityTime::Precise(registered),
            )
            .map_err(|_| error(503, "SDK registration parent index observation rejected"))?
        {
            Parent::Linked {
                expiry: Expiry::from_owner(&current),
            }
        } else {
            Parent::Ended {
                reason: if original_expiry.ended(registered) {
                    EndReason::OriginalExpiry
                } else {
                    EndReason::CurrentOwnerMissing
                },
            }
        };
        Ok(Self {
            version: 1,
            accepted,
            registered,
            namespace_incarnation,
            instance: instance_hex(&entry.instance),
            original_expiry,
            parent,
        })
    }
    pub(crate) fn validate_namespace(&self, incarnation: Option<u64>, phase: Phase) -> Result<()> {
        if phase != Phase::Revoked && self.namespace_incarnation != incarnation {
            return Err(error(
                503,
                "SDK registration namespace incarnation rejected",
            ));
        }
        Ok(())
    }
    pub(crate) fn batch_expiry(&self) -> Result<Option<Timestamp>> {
        let Parent::Batch { expiry, .. } = &self.parent else {
            return Ok(None);
        };
        match expiry.precise {
            Some(end) => Ok(Some(end)),
            None => expiry
                .seconds
                .map(Timestamp::whole)
                .transpose()
                .map_err(|_| error(503, "SDK batch expiry rejected")),
        }
    }
    pub(crate) fn final_use(&self) -> bool {
        matches!(self.parent, Parent::FinalUse)
    }
    pub(crate) fn parent_cleanup_required(
        &self,
        issuer: &LeaseOwner,
        namespace: &str,
        auth: &AuthState,
        at: Timestamp,
    ) -> Result<bool> {
        Ok(match &self.parent {
            Parent::Ended { .. } => false,
            Parent::FinalUse => true,
            Parent::Batch {
                parent_instance, ..
            } => {
                let claims = issuer
                    .batch_claims()
                    .ok_or_else(|| error(503, "SDK batch parent owner rejected"))?;
                match (claims.parent(), parent_instance) {
                    (None, None) => false,
                    (Some(parent), Some(expected)) => {
                        let owner = LeaseOwner::service(parent)
                            .map_err(|_| error(503, "SDK batch parent digest rejected"))?;
                        auth.sdk_service_parent_instance(&owner, namespace)
                            .map_err(|_| error(503, "SDK batch parent instance rejected"))?
                            .is_none_or(|current| instance_hex(&current) != *expected)
                            || auth
                                .standard_sdk_service_parent_observed(
                                    &owner,
                                    namespace,
                                    AuthorityTime::Precise(at),
                                )
                                .map_err(|_| error(503, "SDK batch parent index rejected"))?
                                .is_none()
                    }
                    _ => return Err(error(503, "SDK batch parent anchor rejected")),
                }
            }
            Parent::Linked { .. } => {
                auth.sdk_service_parent_instance(issuer, namespace)
                    .map_err(|_| error(503, "SDK parent instance observation rejected"))?
                    .is_none_or(|current| instance_hex(&current) != self.instance)
                    || auth
                        .standard_sdk_service_parent_observed(
                            issuer,
                            namespace,
                            AuthorityTime::Precise(at),
                        )
                        .map_err(|_| error(503, "SDK parent index observation rejected"))?
                        .is_none()
            }
        })
    }
    pub(crate) fn validate<B: crate::engines::sdk_lease::Backend>(
        &self,
        lease: &Lease<B>,
    ) -> Result<()> {
        self.original_expiry.validate()?;
        if self.version != 1
            || self.instance.len() != 64
            || !self
                .instance
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.accepted > self.registered
            || self.registered != lease.issued
            || (lease.issuer.service_digest().is_none()
                != matches!(self.parent, Parent::Batch { .. }))
            || (!lease.namespace.is_empty() && self.namespace_incarnation.is_none())
            || self.original_expiry.ended(self.accepted)
        {
            return Err(error(
                503,
                "SDK accepted Secret registration provenance rejected",
            ));
        }
        match &self.parent {
            Parent::Linked { expiry } => {
                expiry.validate()?;
                if expiry.ended(self.registered) {
                    return Err(error(503, "SDK registration claimed an ended live parent"));
                }
            }
            Parent::Ended {
                reason: EndReason::OriginalExpiry,
            } => {
                if !self.original_expiry.ended(self.registered) {
                    return Err(error(
                        503,
                        "SDK registration original expiry reason rejected",
                    ));
                }
            }
            Parent::Ended {
                reason: EndReason::CurrentOwnerMissing,
            } => {
                if self.original_expiry.ended(self.registered) {
                    return Err(error(
                        503,
                        "SDK registration missing-parent classification rejected",
                    ));
                }
            }
            Parent::Batch {
                expiry,
                parent_instance,
            } => {
                expiry.validate()?;
                let claims = lease
                    .issuer
                    .batch_claims()
                    .ok_or_else(|| error(503, "SDK batch registration issuer rejected"))?;
                let saved = Expiry {
                    seconds: Some(claims.expires_at()),
                    precise: claims.precision().map(|lease| lease.expires_at),
                };
                if *expiry != saved
                    || self.original_expiry != saved
                    || claims.parent().is_some() != parent_instance.is_some()
                    || parent_instance.as_ref().is_some_and(|value| {
                        value.len() != 64
                            || !value
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                    || instance_hex(
                        &AuthState::sdk_batch_owner_instance(&lease.issuer)
                            .map_err(|_| error(503, "SDK batch registration instance rejected"))?,
                    ) != self.instance
                {
                    return Err(error(503, "SDK batch registration provenance rejected"));
                }
                let end = self
                    .batch_expiry()?
                    .ok_or_else(|| error(503, "SDK batch registration expiry absent"))?;
                let anchor = lease.renewed.unwrap_or(lease.issued);
                let grant_end = Timestamp::from_wall(
                    anchor
                        .duration_since_epoch()
                        .checked_add(std::time::Duration::from_nanos(lease.ttl_ns))
                        .ok_or_else(|| error(503, "SDK batch grant overflow"))?,
                )
                .map_err(|_| error(503, "SDK batch grant expiry rejected"))?;
                if lease.expires != end.min(grant_end) {
                    return Err(error(503, "SDK batch effective expiry changed"));
                }
            }
            Parent::FinalUse => {
                if lease.phase == Phase::Active || lease.renewable {
                    return Err(error(
                        503,
                        "SDK final-use registration must remain revoked or pending",
                    ));
                }
            }
        }
        Ok(())
    }
}
impl EngineState {
    pub(crate) fn has_sdk_batch_registration_state(&self) -> bool {
        self.namespaces.values().any(|namespace| {
            namespace.sdk_leases.values().any(|lease| {
                lease.registration.as_ref().is_some_and(|registration| {
                    matches!(&registration.parent, Parent::Batch { .. })
                })
            })
        })
    }
    pub(crate) fn has_sdk_registration_state(&self) -> bool {
        self.namespaces.values().any(|namespace| {
            namespace
                .sdk_leases
                .values()
                .any(|lease| lease.registration.is_some())
        })
    }
    pub(crate) fn validate_sdk_registration_namespace(
        &self,
        incarnation: impl Fn(&str) -> Option<u64>,
    ) -> Result<()> {
        for namespace in self.namespaces.values() {
            for lease in namespace.sdk_leases.values() {
                if let Some(registration) = &lease.registration
                    && lease.phase != Phase::Revoked
                    && incarnation(&lease.namespace) != registration.namespace_incarnation
                {
                    return Err(error(
                        503,
                        "SDK registration namespace incarnation rejected",
                    ));
                }
            }
        }
        Ok(())
    }
    pub(crate) fn validate_sdk_registration_successor(
        &self,
        previous: Option<&Self>,
    ) -> Result<()> {
        for namespace in self.namespaces.values() {
            for lease in namespace.sdk_leases.values() {
                if let Some(registration) = &lease.registration {
                    registration.validate(lease)?;
                }
            }
        }
        if let Some(previous) = previous {
            for (namespace, old_state) in &previous.namespaces {
                for old in old_state.sdk_leases.values() {
                    if old.registration.is_none() {
                        if self
                            .namespaces
                            .get(namespace)
                            .and_then(|state| state.sdk_leases.get(&old.id))
                            .is_some_and(|lease| lease.registration.is_some())
                        {
                            return Err(error(
                                503,
                                "historical SDK lease cannot acquire accepted registration",
                            ));
                        }
                        continue;
                    }
                    let current = self
                        .namespaces
                        .get(namespace)
                        .and_then(|state| state.sdk_leases.get(&old.id))
                        .ok_or_else(|| error(503, "SDK registration provenance was removed"))?;
                    if current.registration != old.registration
                        || current.issuer != old.issuer
                        || current.cluster != old.cluster
                        || current.issued != old.issued
                    {
                        return Err(error(
                            503,
                            "SDK registration provenance changed or was downgraded",
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

fn instance_hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    encoded
}
