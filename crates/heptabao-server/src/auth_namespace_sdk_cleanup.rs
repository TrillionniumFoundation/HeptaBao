//! Durable subtractive SDK work. A saved attempt is neither a Principal nor a
//! retry grant. The registered resource remains in its actual SDK lease owner.
use super::*;
use crate::crypto;
use crate::engines::{
    sdk::MountOwner,
    sdk_lease::{Backend, Lease, Phase},
    sdk_registration::{LeaseMetadata, Registration},
};
use crate::namespace_custody::Binding;

pub(crate) const STATE_SCHEMA: u32 = 109;
const MAX_WORK: usize = 10_000;
const MAX_NAMESPACE_WORK: usize = 1024;

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Kind {
    Logical,
    Credential,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "family", deny_unknown_fields)]
enum Resource {
    Logical { backend: MountOwner },
    Credential { backend: Box<sdk::Binding> },
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    id: String,
    mount: String,
    path: String,
    issuer: LeaseOwner,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    registration: Option<Registration>,
    issued: Timestamp,
    expires: Timestamp,
    renewed: Option<Timestamp>,
    ttl_ns: u64,
    max_ttl_ns: u64,
    renewable: bool,
}
impl Metadata {
    fn capture<B: Backend>(lease: &Lease<B>) -> Self {
        Self {
            id: lease.id.clone(),
            mount: lease.mount.clone(),
            path: lease.path.clone(),
            issuer: lease.issuer.clone(),
            registration: lease.registration.clone(),
            issued: lease.issued,
            expires: lease.expires,
            renewed: lease.renewed,
            ttl_ns: lease.ttl_ns,
            max_ttl_ns: lease.max_ttl_ns,
            renewable: lease.renewable,
        }
    }
    fn validate(&self, namespace: &str, incarnation: u64) -> Result<(), AuthError> {
        validate_path(&self.id, false)?;
        validate_path(self.mount.trim_end_matches('/'), false)?;
        validate_path(&self.path, false)?;
        self.issuer
            .validate_scope(namespace, ServiceOwnerProfile::CanonicalDigest)
            .map_err(|_| err(503, "namespace SDK cleanup saved issuer rejected"))?;
        if self.id.len() > 4096
            || self.path.len() > 4096
            || self.mount.len() > 4096
            || !self
                .id
                .starts_with(&format!("{}/", self.path.trim_end_matches('/')))
            || !self.path.starts_with(&self.mount)
            || !self.mount.ends_with('/')
            || self.ttl_ns == 0
            || self.ttl_ns > self.max_ttl_ns
            || self.max_ttl_ns > i64::MAX as u64
            || self
                .renewed
                .is_some_and(|at| at < self.issued || at > self.expires)
        {
            return Err(err(503, "namespace SDK cleanup saved metadata rejected"));
        }
        let max_end = Timestamp::from_wall(
            self.issued
                .duration_since_epoch()
                .checked_add(std::time::Duration::from_nanos(self.max_ttl_ns))
                .ok_or_else(|| err(503, "namespace SDK cleanup expiry overflow"))?,
        )
        .map_err(|_| err(503, "namespace SDK cleanup expiry rejected"))?;
        let batch_end = self
            .registration
            .as_ref()
            .map(Registration::batch_expiry)
            .transpose()
            .map_err(|e| err(e.status, &e.message))?
            .flatten();
        if self.expires > max_end || (self.expires < self.issued && batch_end.is_none()) {
            return Err(err(503, "namespace SDK cleanup saved expiry rejected"));
        }
        if let Some(registration) = &self.registration {
            registration
                .validate_namespace(Some(incarnation), Phase::PendingRevoke)
                .map_err(|e| err(e.status, &e.message))?;
            registration
                .validate_metadata(LeaseMetadata {
                    issuer: &self.issuer,
                    namespace,
                    issued: self.issued,
                    expires: self.expires,
                    renewed: self.renewed,
                    ttl_ns: self.ttl_ns,
                    renewable: self.renewable,
                    phase: Phase::PendingRevoke,
                })
                .map_err(|e| err(e.status, &e.message))?;
        }
        Ok(())
    }
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "stage", deny_unknown_fields)]
pub(crate) enum Stage {
    Queued,
    Attempted,
    Terminal { revoked_digest: [u8; 32] },
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    deletion_owner: Binding,
    resource: Resource,
    metadata: Metadata,
    pending_digest: [u8; 32],
    stage: Stage,
}
impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NamespaceSdkCleanup([REDACTED])")
    }
}
fn digest<T: Serialize>(value: &T) -> Result<[u8; 32], AuthError> {
    let bytes = zeroize::Zeroizing::new(
        crate::secret_serde::to_vec(value, 512 * 1024)
            .map_err(|_| err(503, "namespace SDK cleanup owner encoding rejected"))?,
    );
    Ok(crypto::digest(&bytes))
}
impl Record {
    pub(crate) fn logical(binding: Binding, lease: &Lease) -> Result<Self, AuthError> {
        lease
            .validate(&lease.namespace)
            .map_err(|e| err(e.status, &e.message))?;
        Self::capture(
            binding,
            Resource::Logical {
                backend: lease.backend.clone(),
            },
            lease,
            digest(lease)?,
        )
    }
    pub(crate) fn credential(
        binding: Binding,
        record: &sdk_credential::Record,
    ) -> Result<Self, AuthError> {
        record
            .validate(&record.namespace)
            .map_err(|e| err(e.status, &e.message))?;
        Self::capture(
            binding,
            Resource::Credential {
                backend: Box::new(record.backend.clone()),
            },
            record,
            digest(record)?,
        )
    }
    fn capture<B: Backend>(
        binding: Binding,
        resource: Resource,
        lease: &Lease<B>,
        pending_digest: [u8; 32],
    ) -> Result<Self, AuthError> {
        binding
            .validate_cluster_namespace(&lease.cluster, &lease.namespace)
            .map_err(|_| {
                err(
                    503,
                    "namespace SDK cleanup actual cluster or namespace rejected",
                )
            })?;
        if lease.phase != Phase::PendingRevoke {
            return Err(err(
                503,
                "namespace SDK cleanup requires actual pending resource",
            ));
        }
        let value = Self {
            deletion_owner: binding,
            resource,
            metadata: Metadata::capture(lease),
            pending_digest,
            stage: Stage::Queued,
        };
        value.validate(&lease.cluster)?;
        Ok(value)
    }
    pub(crate) fn binding(&self) -> &Binding {
        &self.deletion_owner
    }
    pub(crate) fn kind(&self) -> Kind {
        match &self.resource {
            Resource::Logical { .. } => Kind::Logical,
            Resource::Credential { .. } => Kind::Credential,
        }
    }
    pub(crate) fn lease_id(&self) -> &str {
        &self.metadata.id
    }
    pub(crate) fn stage(&self) -> &Stage {
        &self.stage
    }
    pub(crate) fn work_id(&self) -> Result<String, AuthError> {
        Ok(crypto::digest(
            &crate::secret_serde::to_vec(
                &(&self.deletion_owner, self.kind(), &self.metadata.id),
                16 * 1024,
            )
            .map_err(|_| err(503, "namespace SDK cleanup work identity rejected"))?,
        )
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
    }
    fn validate(&self, cluster: &str) -> Result<(), AuthError> {
        self.deletion_owner
            .validate_cluster_namespace(cluster, self.deletion_owner.namespace())
            .map_err(|_| err(503, "namespace SDK cleanup binding rejected"))?;
        self.metadata.validate(
            self.deletion_owner.namespace(),
            self.deletion_owner.incarnation(),
        )?;
        if self.pending_digest == [0; 32]
            || matches!(
            self.stage, Stage::Terminal { revoked_digest } if revoked_digest == [0;32])
        {
            return Err(err(503, "namespace SDK cleanup resource digest rejected"));
        }
        match &self.resource {
            Resource::Logical { backend } => {
                backend
                    .validate_lease_binding(self.deletion_owner.namespace(), &self.metadata.mount)
                    .map_err(|e| err(e.status, &e.message))?;
                if backend.plugin.len() > 128
                    || backend.version.len() > 128
                    || heptabao_domain::Id::parse(backend.plugin.clone()).is_err()
                    || backend
                        .version
                        .bytes()
                        .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')))
                {
                    return Err(err(503, "namespace SDK cleanup logical backend rejected"));
                }
            }
            Resource::Credential { backend } => backend
                .validate_lease_binding(self.deletion_owner.namespace(), &self.metadata.mount)
                .map_err(|e| err(e.status, &e.message))?,
        }
        Ok(())
    }
    pub(crate) fn is_terminal_successor(&self, old: &Self) -> bool {
        self.same_selected(old)
            && old.stage == Stage::Attempted
            && matches!(self.stage, Stage::Terminal { .. })
    }
    fn selection_digest(&self) -> Result<[u8; 32], AuthError> {
        let mut immutable = self.clone();
        immutable.stage = Stage::Queued;
        digest(&immutable)
    }
    fn same_selected(&self, old: &Self) -> bool {
        self.deletion_owner == old.deletion_owner
            && self.resource == old.resource
            && self.metadata == old.metadata
            && self.pending_digest == old.pending_digest
    }
    fn successor(&self, old: &Self) -> Result<(), AuthError> {
        if !self.same_selected(old)
            || !matches!((&old.stage, &self.stage),
            (Stage::Queued, Stage::Queued | Stage::Attempted)
                | (Stage::Attempted, Stage::Attempted | Stage::Terminal { .. })
                | (Stage::Terminal { .. }, Stage::Terminal { .. }) if
                    !matches!(&old.stage, Stage::Terminal { .. }) || self.stage == old.stage)
        {
            return Err(err(
                503,
                "namespace SDK cleanup attempt cannot roll back or replace owner",
            ));
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn check_unboxed_credential_wire(&self) -> Result<(), AuthError> {
        // Preserve the original unboxed persisted shape, including field order
        // and the bytes used by the immutable record digest.
        #[derive(Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct OriginalCredentialResource {
            family: String,
            backend: sdk::Binding,
        }
        #[derive(Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct OriginalCredentialRecord {
            deletion_owner: Binding,
            resource: OriginalCredentialResource,
            metadata: Metadata,
            pending_digest: [u8; 32],
            stage: Stage,
        }
        let Resource::Credential { backend } = &self.resource else {
            return Err(err(
                503,
                "namespace SDK cleanup wire fixture family rejected",
            ));
        };
        let original = OriginalCredentialRecord {
            deletion_owner: self.deletion_owner.clone(),
            resource: OriginalCredentialResource {
                family: "Credential".into(),
                backend: backend.as_ref().clone(),
            },
            metadata: self.metadata.clone(),
            pending_digest: self.pending_digest,
            stage: self.stage.clone(),
        };
        let original_bytes = zeroize::Zeroizing::new(
            crate::secret_serde::to_vec(&original, 512 * 1024)
                .map_err(|_| err(503, "namespace SDK cleanup wire fixture encoding rejected"))?,
        );
        let boxed_bytes = zeroize::Zeroizing::new(
            crate::secret_serde::to_vec(self, 512 * 1024)
                .map_err(|_| err(503, "namespace SDK cleanup wire fixture encoding rejected"))?,
        );
        assert!(original_bytes.as_slice() == boxed_bytes.as_slice());
        assert!(crypto::digest(&original_bytes) == digest(self)?);
        let old_decoded: OriginalCredentialRecord = serde_json::from_slice(&boxed_bytes)
            .map_err(|_| err(503, "namespace SDK cleanup original wire decoder rejected"))?;
        assert!(old_decoded.resource.family == "Credential");
        assert!(old_decoded.resource.backend == *backend.as_ref());
        let old_reencoded = zeroize::Zeroizing::new(
            crate::secret_serde::to_vec(&old_decoded, 512 * 1024).map_err(|_| {
                err(
                    503,
                    "namespace SDK cleanup original wire reencoding rejected",
                )
            })?,
        );
        assert!(old_reencoded.as_slice() == original_bytes.as_slice());
        let new_decoded: Self = serde_json::from_slice(&original_bytes)
            .map_err(|_| err(503, "namespace SDK cleanup boxed wire decoder rejected"))?;
        assert!(new_decoded == *self);
        assert!(new_decoded.selection_digest()? == self.selection_digest()?);
        Ok(())
    }
    pub(crate) fn check_logical(&self, lease: &Lease, terminal: bool) -> Result<(), AuthError> {
        let Resource::Logical { backend } = &self.resource else {
            return Err(err(503, "namespace SDK cleanup family changed"));
        };
        if backend != &lease.backend {
            return Err(err(503, "namespace SDK cleanup backend changed"));
        }
        self.check_metadata(lease, digest(lease)?, terminal)
    }
    pub(crate) fn check_credential(
        &self,
        lease: &sdk_credential::Record,
        terminal: bool,
    ) -> Result<(), AuthError> {
        let Resource::Credential { backend } = &self.resource else {
            return Err(err(503, "namespace SDK cleanup family changed"));
        };
        if backend.as_ref() != &lease.backend {
            return Err(err(503, "namespace SDK cleanup backend changed"));
        }
        self.check_metadata(lease, digest(lease)?, terminal)
    }
    fn check_metadata<B: Backend>(
        &self,
        lease: &Lease<B>,
        fingerprint: [u8; 32],
        terminal: bool,
    ) -> Result<(), AuthError> {
        lease
            .validate(&lease.namespace)
            .map_err(|e| err(e.status, &e.message))?;
        let mut expected = self.metadata.clone();
        if terminal {
            expected.renewable = false;
        }
        self.deletion_owner
            .validate_cluster_namespace(&lease.cluster, &lease.namespace)
            .map_err(|_| {
                err(
                    503,
                    "namespace SDK cleanup actual cluster or namespace changed",
                )
            })?;
        if lease.namespace != self.deletion_owner.namespace()
            || Metadata::capture(lease) != expected
            || lease.phase
                != if terminal {
                    Phase::Revoked
                } else {
                    Phase::PendingRevoke
                }
            || (!terminal && fingerprint != self.pending_digest)
            || (terminal
                && matches!(self.stage, Stage::Terminal { revoked_digest }
                if revoked_digest != fingerprint))
        {
            return Err(err(
                503,
                "namespace SDK cleanup actual registered resource changed",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    binding: Binding,
    members: BTreeMap<String, [u8; 32]>,
}
#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registry {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    records: BTreeMap<String, Record>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    logical_history: Option<crate::engines::sdk_history::Mirror>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_selections: Option<BTreeMap<String, Selection>>,
}
impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NamespaceSdkCleanupRegistry([REDACTED])")
    }
}
impl Registry {
    pub(crate) fn logical_history(&self) -> Option<&crate::engines::sdk_history::Mirror> {
        self.logical_history.as_ref()
    }
    pub(crate) fn enable_refinement(
        &mut self,
        history: crate::engines::sdk_history::Mirror,
    ) -> Result<(), AuthError> {
        if let Some(old) = &self.logical_history {
            history
                .validate_successor(old)
                .map_err(|e| err(e.status, &e.message))?;
        }
        self.logical_history = Some(history);
        self.source_selections.get_or_insert_with(Default::default);
        Ok(())
    }
    pub(crate) fn seal_selection(&mut self, binding: &Binding) -> Result<(), AuthError> {
        let members = self
            .records
            .iter()
            .filter(|(_, record)| record.binding() == binding)
            .map(|(key, record)| Ok((key.clone(), record.selection_digest()?)))
            .collect::<Result<BTreeMap<_, _>, AuthError>>()?;
        let value = Selection {
            binding: binding.clone(),
            members,
        };
        let selections = self
            .source_selections
            .as_mut()
            .ok_or_else(|| err(503, "namespace SDK source selection marker missing"))?;
        if let Some(old) = selections.get(binding.namespace()) {
            if old != &value {
                return Err(err(
                    503,
                    "namespace SDK original selection cannot be replaced",
                ));
            }
        } else {
            selections.insert(binding.namespace().to_owned(), value);
        }
        Ok(())
    }
    pub(crate) fn records(&self) -> &BTreeMap<String, Record> {
        &self.records
    }
    pub(crate) fn blocks_dispatch(&self, kind: Kind, namespace: &str, id: &str) -> bool {
        self.records.values().any(|record| {
            record.kind() == kind
                && record.binding().namespace() == namespace
                && record.lease_id() == id
        })
    }
    pub(crate) fn queue(&mut self, record: Record) -> Result<String, AuthError> {
        let key = record.work_id()?;
        if self.records.len() >= MAX_WORK
            || self
                .records
                .values()
                .filter(|old| old.binding() == record.binding())
                .count()
                >= MAX_NAMESPACE_WORK
            || self.records.values().any(|old| {
                old.kind() == record.kind()
                    && old.binding() == record.binding()
                    && old.lease_id() == record.lease_id()
            })
        {
            return Err(err(
                503,
                "namespace SDK cleanup selection conflicts or exceeds bounds",
            ));
        }
        self.records.insert(key.clone(), record);
        Ok(key)
    }
    pub(crate) fn attempted(&mut self, key: &str) -> Result<(), AuthError> {
        let record = self
            .records
            .get_mut(key)
            .ok_or_else(|| err(503, "namespace SDK cleanup selected work missing"))?;
        if record.stage != Stage::Queued {
            return Err(err(
                503,
                "namespace SDK cleanup cannot resend attempted callback",
            ));
        }
        record.stage = Stage::Attempted;
        Ok(())
    }
    pub(crate) fn terminal_logical(&mut self, key: &str, lease: &Lease) -> Result<(), AuthError> {
        let record = self
            .records
            .get_mut(key)
            .ok_or_else(|| err(503, "namespace SDK cleanup selected work missing"))?;
        if record.stage != Stage::Attempted {
            return Err(err(503, "namespace SDK cleanup terminal lacks attempt"));
        }
        record.check_logical(lease, true)?;
        record.stage = Stage::Terminal {
            revoked_digest: digest(lease)?,
        };
        Ok(())
    }
    pub(crate) fn terminal_credential(
        &mut self,
        key: &str,
        lease: &sdk_credential::Record,
    ) -> Result<(), AuthError> {
        let record = self
            .records
            .get_mut(key)
            .ok_or_else(|| err(503, "namespace SDK cleanup selected work missing"))?;
        if record.stage != Stage::Attempted {
            return Err(err(503, "namespace SDK cleanup terminal lacks attempt"));
        }
        record.check_credential(lease, true)?;
        record.stage = Stage::Terminal {
            revoked_digest: digest(lease)?,
        };
        Ok(())
    }
    pub(crate) fn validate(
        &self,
        cluster: &str,
        pending: &BTreeMap<String, Binding>,
        retired: &BTreeMap<String, u64>,
    ) -> Result<(), AuthError> {
        if self.records.len() > MAX_WORK {
            return Err(err(503, "namespace SDK cleanup registry exceeds bounds"));
        }
        match (&self.logical_history, &self.source_selections) {
            (None, None) => {}
            (Some(history), Some(selections)) => {
                history
                    .validate(cluster, pending, retired)
                    .map_err(|e| err(e.status, &e.message))?;
                if selections.len() > 4096 || selections.len() != pending.len() {
                    return Err(err(
                        503,
                        "namespace SDK source selection lacks exact pending set",
                    ));
                }
                for (path, binding) in pending {
                    let selection = selections.get(path).ok_or_else(|| {
                        err(503, "namespace SDK original source selection absent")
                    })?;
                    let actual = self
                        .records
                        .iter()
                        .filter(|(_, record)| record.binding() == binding)
                        .map(|(key, record)| Ok((key.clone(), record.selection_digest()?)))
                        .collect::<Result<BTreeMap<_, _>, AuthError>>()?;
                    if &selection.binding != binding || selection.members != actual {
                        return Err(err(503, "namespace SDK original source membership changed"));
                    }
                }
            }
            _ => {
                return Err(err(
                    503,
                    "namespace SDK refined history and selection markers disagree",
                ));
            }
        }
        let mut count = BTreeMap::<&str, usize>::new();
        for (key, record) in &self.records {
            record.validate(cluster)?;
            let path = record.binding().namespace();
            *count.entry(path).or_default() += 1;
            if key != &record.work_id()?
                || count[path] > MAX_NAMESPACE_WORK
                || (pending.get(path) != Some(record.binding())
                    && (!matches!(record.stage, Stage::Terminal { .. })
                        || retired
                            .get(path)
                            .is_none_or(|inc| *inc < record.binding().incarnation())))
            {
                return Err(err(
                    503,
                    "namespace SDK cleanup lacks original namespace intent",
                ));
            }
        }
        Ok(())
    }
    pub(crate) fn validate_successor(
        &self,
        old: &Self,
        retired: &BTreeMap<String, u64>,
    ) -> Result<(), AuthError> {
        match (&self.logical_history, &old.logical_history) {
            (None, Some(_)) => {
                return Err(err(503, "namespace SDK logical history marker disappeared"));
            }
            (Some(next), Some(previous)) => next
                .validate_successor(previous)
                .map_err(|e| err(e.status, &e.message))?,
            _ => {}
        }
        match (&self.source_selections, &old.source_selections) {
            (None, Some(_)) => {
                return Err(err(
                    503,
                    "namespace SDK source selection marker disappeared",
                ));
            }
            (Some(next), Some(previous)) => {
                for (path, selection) in previous {
                    match next.get(path) {
                        Some(current) if current == selection => {}
                        None if retired
                            .get(path)
                            .is_some_and(|inc| *inc >= selection.binding.incarnation()) => {}
                        _ => {
                            return Err(err(
                                503,
                                "namespace SDK original source selection disappeared",
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
        for (key, previous) in &old.records {
            match self.records.get(key) {
                Some(next) => next.successor(previous)?,
                None if matches!(previous.stage, Stage::Terminal { .. })
                    && retired
                        .get(previous.binding().namespace())
                        .is_some_and(|inc| *inc >= previous.binding().incarnation()) => {}
                None => {
                    return Err(err(
                        503,
                        "namespace SDK cleanup unresolved work disappeared",
                    ));
                }
            }
        }
        Ok(())
    }
    pub(crate) fn retire(&mut self, binding: &Binding) -> Result<(), AuthError> {
        if self.records.values().any(|record| {
            record.binding() == binding && !matches!(record.stage, Stage::Terminal { .. })
        }) {
            return Err(err(503, "namespace SDK cleanup has unresolved attempts"));
        }
        self.records.retain(|_, record| record.binding() != binding);
        if let Some(selections) = &mut self.source_selections {
            if selections
                .get(binding.namespace())
                .is_some_and(|selection| selection.binding != *binding)
            {
                return Err(err(
                    503,
                    "namespace SDK source selection retirement owner changed",
                ));
            }
            selections.remove(binding.namespace());
        }
        Ok(())
    }
    pub(crate) fn owners(&self) -> Vec<(String, LeaseOwner)> {
        self.records
            .values()
            .map(|record| {
                (
                    record.binding().namespace().to_owned(),
                    record.metadata.issuer.clone(),
                )
            })
            .collect()
    }
}
