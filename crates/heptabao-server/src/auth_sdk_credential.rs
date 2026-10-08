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
        let mut owners = self
            .sdk_credential_leases
            .as_ref()
            .map_or_else(Vec::new, |registry| {
                registry
                    .records
                    .values()
                    .map(|record| (record.namespace.clone(), record.issuer.clone()))
                    .collect()
            });
        owners.extend(
            self.custody_credential_records()
                .into_iter()
                .map(|record| (record.lease.namespace.clone(), record.lease.issuer.clone())),
        );
        owners
    }
    pub(crate) fn sdk_credential_namespace_pending(&self, namespace: &str) -> bool {
        self.sdk_namespace_custody_pending(namespace)
            || self.sdk_credential_leases.as_ref().is_some_and(|registry| {
                registry
                    .records
                    .values()
                    .any(|record| record.namespace == namespace && record.phase != Phase::Revoked)
            })
    }
    pub(crate) fn sdk_credential_mount_records(
        &self,
        binding: &sdk::Binding,
    ) -> Result<Vec<Record>, AuthError> {
        self.sdk_auth_owner_gate(binding)?;
        let Some(registry) = &self.sdk_credential_leases else {
            return Ok(Vec::new());
        };
        let mut records = Vec::new();
        for record in registry.records.values().filter(|record| {
            record.namespace == binding.namespace
                && record.backend.mount == binding.mount
                && record.phase != Phase::Revoked
        }) {
            if record.backend != *binding {
                return Err(err(503, "SDK credential mount owner changed"));
            }
            self.validate_sdk_credential_record(record)?;
            records.push(record.clone());
        }
        Ok(records)
    }
    pub(crate) fn sdk_credential_lease_keys(
        &self,
        binding: &sdk::Binding,
        prefix: &str,
    ) -> Result<BTreeSet<String>, AuthError> {
        let boundary = format!("{}/", prefix.trim_end_matches('/'));
        let mut keys = BTreeSet::new();
        for record in self.sdk_credential_mount_records(binding)? {
            if let Some(tail) = record.id.strip_prefix(&boundary) {
                keys.insert(
                    tail.split_once('/')
                        .map(|(first, _)| format!("{first}/"))
                        .unwrap_or_else(|| tail.into()),
                );
            }
        }
        Ok(keys)
    }
    pub(crate) fn sdk_credential_retired_mount_records(
        &self,
        binding: &sdk::Binding,
    ) -> Result<Vec<Record>, AuthError> {
        self.sdk_auth_owner_gate(binding)?;
        Ok(self
            .sdk_credential_leases
            .as_ref()
            .map_or_else(Vec::new, |registry| {
                registry
                    .records
                    .values()
                    .filter(|record| record.backend == *binding && record.phase == Phase::Revoked)
                    .cloned()
                    .collect()
            }))
    }
    pub(crate) fn sdk_credential_mount_pending(&self, binding: &sdk::Binding) -> bool {
        self.custody_credential_records()
            .iter()
            .any(|record| record.lease.backend == *binding && record.lease.phase != Phase::Revoked)
            || self.sdk_credential_leases.as_ref().is_some_and(|registry| {
                registry
                    .records
                    .values()
                    .any(|record| record.backend == *binding && record.phase != Phase::Revoked)
            })
    }
    pub(super) fn sdk_credential_mount_name_pending(&self, namespace: &str, mount: &str) -> bool {
        self.custody_credential_records().iter().any(|record| {
            record.lease.namespace == namespace
                && record.lease.backend.mount == mount
                && record.lease.phase != Phase::Revoked
        }) || self.sdk_credential_leases.as_ref().is_some_and(|registry| {
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
                if let Some(current) = self
                    .sdk_credential_leases
                    .as_ref()
                    .and_then(|registry| registry.records.get(id))
                {
                    Self::sdk_credential_successor_record(current, record)?;
                } else {
                    let current = self
                        .custody_credential_record(id)
                        .ok_or_else(|| err(503, "SDK credential retained record removed"))?;
                    if current.digest != record.custody_record()?.digest {
                        return Err(err(503, "SDK credential partition changed retained record"));
                    }
                }
            }
        }
        if let Some(old) = previous {
            for record in old.custody_credential_records() {
                let current = self
                    .custody_record_for_validation(&record.lease.namespace, &record.lease.id)?
                    .ok_or_else(|| err(503, "SDK credential closed history removed"))?;
                if current.digest != record.digest {
                    return Err(err(
                        503,
                        "SDK credential closed history changed without logical proof",
                    ));
                }
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
            Ok(
                !self.sdk_auth_retirement_claims_record(&record.namespace, &record.id)
                    && !self.namespace_is_tainted(&record.namespace)
                    && !self.namespace_sdk_cleanup_blocks(
                        namespace_sdk_cleanup::Kind::Credential,
                        &record.namespace,
                        &record.id,
                    )
                    && record.phase != Phase::Revoked
                    && (record.phase == Phase::PendingRevoke
                        || at >= record.expires
                        || record
                            .parent_cleanup_required(self, at)
                            .map_err(|e| err(e.status, &e.message))?),
            )
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

impl AuthState {
    pub(crate) fn namespace_sdk_saved_credential_records(
        &self,
        namespace: &str,
    ) -> Result<Vec<Record>, AuthError> {
        let records = self
            .sdk_credential_leases
            .as_ref()
            .map_or_else(Vec::new, |registry| {
                registry
                    .records
                    .values()
                    .filter(|record| record.namespace == namespace)
                    .cloned()
                    .collect::<Vec<_>>()
            });
        for record in &records {
            self.validate_sdk_credential_record(record)?;
        }
        Ok(records)
    }
    pub(crate) fn namespace_sdk_deletion_records(
        &self,
        namespace: &str,
    ) -> Result<Vec<Record>, AuthError> {
        if namespace.is_empty() {
            return Err(err(503, "root credential deletion scope rejected"));
        }
        let records: Vec<_> =
            self.sdk_credential_leases
                .as_ref()
                .map_or_else(Vec::new, |registry| {
                    registry
                        .records
                        .values()
                        .filter(|record| record.namespace == namespace)
                        .cloned()
                        .collect()
                });
        for record in &records {
            self.validate_sdk_credential_record(record)?;
            if record.phase != Phase::Revoked {
                self.sdk_auth_owner_gate(&record.backend)?;
            }
        }
        Ok(records)
    }
    /// Never published: retain the global real Registry in every actual state.
    pub(crate) fn namespace_sdk_native_deletion_projection(
        &self,
        namespace: &str,
    ) -> Result<Self, AuthError> {
        self.namespace_sdk_deletion_records(namespace)?;
        let mut candidate = self.clone();
        if let Some(mounts) = self.plugin_auth_mounts.get(namespace) {
            for (mount, config) in mounts {
                if config.sdk.is_none() {
                    return Err(err(409, "namespace contains a non-SDK callback Auth mount"));
                }
                self.sdk_auth_binding(namespace, &format!("auth/{mount}/"))?
                    .filter(|binding| binding.mount == *mount)
                    .ok_or_else(|| err(503, "namespace SDK Auth actual binding unavailable"))?;
                if let Some(auth) = candidate.auth_mounts.get_mut(namespace) {
                    auth.remove(mount);
                }
            }
            candidate.plugin_auth_mounts.remove(namespace);
        }
        if let Some(registry) = &mut candidate.sdk_credential_leases {
            registry
                .records
                .retain(|_, record| record.namespace != namespace);
        }
        Ok(candidate)
    }
}

impl AuthState {
    pub(crate) fn namespace_sdk_auth_bindings(
        &self,
        namespace: &str,
    ) -> Result<Vec<sdk::Binding>, AuthError> {
        let mut result = Vec::new();
        if let Some(mounts) = self.plugin_auth_mounts.get(namespace) {
            for (mount, config) in mounts {
                if config.sdk.is_none() {
                    return Err(err(409, "namespace contains a non-SDK callback Auth mount"));
                }
                let binding = self
                    .sdk_auth_binding(namespace, &format!("auth/{mount}/"))?
                    .filter(|binding| binding.mount == *mount)
                    .ok_or_else(|| err(503, "namespace SDK Auth actual binding unavailable"))?;
                result.push(binding);
            }
        }
        Ok(result)
    }
}

/// Non-executable exact projection. The complete Record remains solely in its
/// actual global owner or authenticated namespace parcel.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyRecord {
    pub(super) namespace_owner: Option<batch_namespace::Binding>,
    pub(super) lease: crate::engines::sdk_lease::Metadata<sdk::Binding>,
    pub(super) digest: [u8; 32],
}
impl Record {
    pub(super) fn custody_record(&self) -> Result<CustodyRecord, AuthError> {
        let bytes = Zeroizing::new(
            crate::secret_serde::to_vec(self, 4 * 1024 * 1024)
                .map_err(|_| err(503, "SDK namespace credential custody encoding unavailable"))?,
        );
        Ok(CustodyRecord {
            namespace_owner: self.namespace_owner.clone(),
            lease: self.lease.public_metadata(),
            digest: crate::crypto::digest(&bytes),
        })
    }
}
impl Registry {
    pub(super) fn namespace_slice(
        &mut self,
        namespace: &str,
        owner: &batch_namespace::Binding,
    ) -> Self {
        let keys = self
            .records
            .iter()
            .filter(|(_, record)| {
                record.namespace == namespace && record.namespace_owner.as_ref() == Some(owner)
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        Self {
            records: keys
                .into_iter()
                .filter_map(|id| self.records.remove_entry(&id))
                .collect(),
        }
    }
    pub(super) fn namespace_index(
        &self,
        namespace: &str,
    ) -> Result<BTreeMap<String, CustodyRecord>, AuthError> {
        self.records
            .iter()
            .map(|(id, record)| {
                if id != &record.id || record.namespace != namespace {
                    return Err(err(503, "SDK namespace credential parcel binding rejected"));
                }
                Ok((id.clone(), record.custody_record()?))
            })
            .collect()
    }
    pub(super) fn contains_any(&self, incoming: &Self) -> bool {
        incoming
            .records
            .keys()
            .any(|id| self.records.contains_key(id))
    }
    pub(super) fn append_exact(&mut self, incoming: Self) -> Result<(), AuthError> {
        if self.contains_any(&incoming) || self.records.len() + incoming.records.len() > 4096 {
            return Err(err(
                503,
                "SDK namespace credential parcel collision or capacity rejected",
            ));
        }
        self.records.extend(incoming.records);
        Ok(())
    }
    pub(super) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub(super) fn custody_global_record_count(&self) -> usize {
        self.records.len()
    }
}

impl AuthState {
    pub(super) fn validate_sdk_custody_credential_metadata(
        &self,
        record: &CustodyRecord,
        cluster: &str,
    ) -> Result<(), AuthError> {
        let lease = &record.lease;
        self.validate_batch_namespace_owner_structure(
            record.namespace_owner.as_ref(),
            &lease.namespace,
        )?;
        if lease.namespace.is_empty() != record.namespace_owner.is_none()
            || lease.cluster != cluster
            || record.digest == [0; 32]
        {
            return Err(err(503, "SDK credential custody saved owner rejected"));
        }
        lease
            .validate_metadata(&lease.namespace)
            .map_err(|e| err(e.status, &e.message))?;
        let registration = lease
            .registration
            .as_ref()
            .ok_or_else(|| err(503, "SDK credential custody registration absent"))?;
        registration
            .validate_namespace(
                record
                    .namespace_owner
                    .as_ref()
                    .map_or(Some(0), |owner| Some(owner.incarnation())),
                lease.phase,
            )
            .map_err(|e| err(e.status, &e.message))?;
        if self.sdk_auth_catalog.as_ref().is_none_or(|catalog| {
            !catalog.known_generation(
                &lease.backend.descriptor().name,
                &lease.backend.descriptor().version,
                lease.backend.descriptor().generation,
            )
        }) || self.sdk_auth_clock.is_none_or(|floor| {
            lease.issued > floor || lease.renewed.is_some_and(|time| time > floor)
        }) {
            return Err(err(503, "SDK credential custody catalog or clock rejected"));
        }
        if let Some(claims) = lease.issuer.batch_claims() {
            self.validate_batch_lease_owner(claims, &lease.namespace)?;
        }
        Ok(())
    }
    pub(super) fn custody_record_for_validation(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<CustodyRecord>, AuthError> {
        if let Some(record) = self
            .sdk_credential_leases
            .as_ref()
            .and_then(|registry| registry.records.get(id))
            .filter(|record| record.namespace == namespace)
        {
            return record.custody_record().map(Some);
        }
        Ok(self
            .custody_credential_record(id)
            .filter(|record| record.lease.namespace == namespace)
            .cloned())
    }
}

impl Registry {
    pub(super) fn namespace_present(&self, actual: &str) -> bool {
        self.records
            .values()
            .any(|record| record.namespace == actual)
    }
}

impl Registry {
    pub(super) fn custody_contains_id(&self, id: &str) -> bool {
        self.records.contains_key(id)
    }
}
