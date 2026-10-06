//! Global retained credential-family leases. The backend is the real Auth
//! Binding, never a logical MountOwner, and records are not Principals.
use super::*;
use crate::engines::sdk_lease::{Lease, Phase};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    lease: Lease<sdk::Binding>,
    namespace_owner: Option<batch_namespace::Binding>,
}
impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SDKCredentialLease([REDACTED])")
    }
}
impl Record {
    pub(crate) fn new(
        lease: Lease<sdk::Binding>,
        namespace_owner: Option<batch_namespace::Binding>,
    ) -> Self {
        Self {
            lease,
            namespace_owner,
        }
    }
}
impl std::ops::Deref for Record {
    type Target = Lease<sdk::Binding>;
    fn deref(&self) -> &Self::Target {
        &self.lease
    }
}
impl std::ops::DerefMut for Record {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.lease
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registry {
    records: BTreeMap<String, Record>,
}
impl AuthState {
    pub(crate) fn has_sdk_credential_state(&self) -> bool {
        self.sdk_credential_leases.is_some()
    }
    pub(crate) fn sdk_credential_record(&self, namespace: &str, id: &str) -> Option<Record> {
        self.sdk_credential_leases
            .as_ref()?
            .records
            .get(id)
            .filter(|record| record.namespace == namespace)
            .cloned()
    }
    pub(crate) fn sdk_credential_owners(&self) -> Vec<(String, LeaseOwner)> {
        self.sdk_credential_leases
            .as_ref()
            .map_or_else(Vec::new, |registry| {
                registry
                    .records
                    .values()
                    .map(|record| (record.namespace.clone(), record.issuer.clone()))
                    .collect()
            })
    }
    pub(crate) fn sdk_credential_namespace_pending(&self, namespace: &str) -> bool {
        self.sdk_credential_leases.as_ref().is_some_and(|registry| {
            registry
                .records
                .values()
                .any(|record| record.namespace == namespace && record.phase != Phase::Revoked)
        })
    }
    pub(crate) fn sdk_credential_mount_pending(&self, binding: &sdk::Binding) -> bool {
        self.sdk_credential_leases.as_ref().is_some_and(|registry| {
            registry
                .records
                .values()
                .any(|record| record.backend == *binding && record.phase != Phase::Revoked)
        })
    }
    pub(super) fn sdk_credential_mount_name_pending(&self, namespace: &str, mount: &str) -> bool {
        self.sdk_credential_leases.as_ref().is_some_and(|registry| {
            registry.records.values().any(|record| {
                record.namespace == namespace
                    && record.backend.mount == mount
                    && record.phase != Phase::Revoked
            })
        })
    }
    pub(crate) fn store_sdk_credential(&mut self, record: Record) -> Result<(), AuthError> {
        self.validate_sdk_credential_record(&record)?;
        let registry = self
            .sdk_credential_leases
            .get_or_insert_with(Registry::default);
        if !registry.records.contains_key(&record.id) && registry.records.len() >= 4096 {
            return Err(err(507, "SDK credential lease registry capacity exceeded"));
        }
        if let Some(previous) = registry.records.get(&record.id) {
            Self::sdk_credential_successor_record(&record, previous)?;
        }
        registry.records.insert(record.id.clone(), record);
        Ok(())
    }
    fn sdk_credential_successor_record(
        current: &Record,
        previous: &Record,
    ) -> Result<(), AuthError> {
        if current.namespace_owner != previous.namespace_owner
            || current.namespace != previous.namespace
            || current.cluster != previous.cluster
            || current.mount != previous.mount
            || current.path != previous.path
            || current.backend != previous.backend
            || current.issuer != previous.issuer
            || current.issued != previous.issued
            || current.registration != previous.registration
            || current.max_ttl_ns > previous.max_ttl_ns
            || previous
                .renewed
                .is_some_and(|before| current.renewed.is_none_or(|after| after < before))
            || (previous.phase == Phase::Revoked && current.phase != Phase::Revoked)
            || (previous.phase == Phase::PendingRevoke && current.phase == Phase::Active)
        {
            return Err(err(503, "SDK credential original lease provenance changed"));
        }
        Ok(())
    }
    fn validate_sdk_credential_record(&self, record: &Record) -> Result<(), AuthError> {
        self.validate_batch_namespace_owner_structure(
            record.namespace_owner.as_ref(),
            &record.namespace,
        )?;
        if record.namespace.is_empty() != record.namespace_owner.is_none() {
            return Err(err(503, "SDK credential saved namespace ownership absent"));
        }
        record
            .validate(&record.namespace)
            .map_err(|e| err(e.status, &e.message))?;
        if record.registration.is_none()
            || self.sdk_auth_catalog.as_ref().is_none_or(|catalog| {
                !catalog.known_generation(
                    &record.backend.descriptor().name,
                    &record.backend.descriptor().version,
                    record.backend.descriptor().generation,
                )
            })
            || self.sdk_auth_clock.is_none_or(|floor| {
                record.issued > floor || record.renewed.is_some_and(|time| time > floor)
            })
        {
            return Err(err(
                503,
                "SDK credential retained catalog or clock rejected",
            ));
        }
        Ok(())
    }
    pub(crate) fn validate_sdk_credential_state(
        &self,
        previous: Option<&Self>,
        cluster: &str,
        incarnation: impl Fn(&str) -> Option<u64>,
    ) -> Result<(), AuthError> {
        if previous.is_some_and(|old| old.sdk_credential_leases.is_some())
            && self.sdk_credential_leases.is_none()
        {
            return Err(err(503, "SDK credential registry cannot be removed"));
        }
        if let Some(registry) = &self.sdk_credential_leases {
            if registry.records.len() > 4096 {
                return Err(err(503, "SDK credential registry capacity rejected"));
            }
            for (id, record) in &registry.records {
                self.validate_sdk_credential_record(record)?;
                if id != &record.id || record.cluster != cluster {
                    return Err(err(503, "SDK credential cluster or key rejected"));
                }
                let saved_incarnation = record
                    .namespace_owner
                    .as_ref()
                    .map_or(Some(0), |binding| Some(binding.incarnation()));
                record
                    .registration
                    .as_ref()
                    .ok_or_else(|| err(503, "SDK credential provenance absent"))?
                    .validate_namespace(saved_incarnation, record.phase)
                    .map_err(|e| err(e.status, &e.message))?;
                if let Some(current) = incarnation(&record.namespace)
                    && record.phase != Phase::Revoked
                    && saved_incarnation != Some(current)
                {
                    return Err(err(
                        503,
                        "SDK credential current namespace incarnation differs",
                    ));
                }
                if let Some(claims) = record.issuer.batch_claims() {
                    self.validate_batch_lease_owner(claims, &record.namespace)?;
                }
            }
        }
        if let Some(old) = previous.and_then(|old| old.sdk_credential_leases.as_ref()) {
            for (id, record) in &old.records {
                let current = self
                    .sdk_credential_leases
                    .as_ref()
                    .and_then(|registry| registry.records.get(id))
                    .ok_or_else(|| err(503, "SDK credential retained record removed"))?;
                Self::sdk_credential_successor_record(current, record)?;
            }
        }
        Ok(())
    }
    pub(crate) fn next_sdk_credential_cleanup(
        &self,
        at: Timestamp,
        after: Option<&str>,
    ) -> Result<Option<Record>, AuthError> {
        let Some(registry) = self.sdk_credential_leases.as_ref() else {
            return Ok(None);
        };
        // Rotate discovery before preparation; no owned Plan is prepared and discarded.
        let eligible = |record: &Record| -> Result<bool, AuthError> {
            Ok(record.phase != Phase::Revoked
                && (record.phase == Phase::PendingRevoke
                    || at >= record.expires
                    || record
                        .parent_cleanup_required(self, at)
                        .map_err(|e| err(e.status, &e.message))?))
        };
        for (id, record) in &registry.records {
            if after.is_none_or(|after| id.as_str() > after) && eligible(record)? {
                return Ok(Some(record.clone()));
            }
        }
        if let Some(after) = after {
            for (id, record) in &registry.records {
                if id.as_str() <= after && eligible(record)? {
                    return Ok(Some(record.clone()));
                }
            }
        }
        Ok(None)
    }
}
