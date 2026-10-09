//! Exact SDK Auth namespace custody. Serialized locators are validation and
//! discovery metadata only; they never return a mount, Record or retirement
//! execution authority. Complete values stay in the MAC-authenticated parcel.
use super::*;
use crate::namespace_custody::Binding as CustodyBinding;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Parcel {
    namespace: String,
    namespace_owner: batch_namespace::Binding,
    credentials: Option<sdk_credential::Registry>,
    retirements: Option<sdk_retirement::Registry>,
    // Original subtractive 109 control records, not a Lease or execution grant.
    // The complete logical resource still has to pass authenticated hydration.
    logical_cleanup: BTreeMap<String, namespace_sdk_cleanup::Record>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Locator {
    boundary: CustodyBinding,
    namespace_owner: batch_namespace::Binding,
    parcel: [u8; 32],
    ciphertext_owner: Option<CiphertextOwner>,
    // Inner to outer. A hidden child's actual descriptor remains committed;
    // opening the enclosing MAC catalog must reveal that exact descriptor.
    enclosures: Vec<CiphertextOwner>,
    credentials: BTreeMap<String, sdk_credential::CustodyRecord>,
    // Job contains only original control metadata/digests, no Secret/data.
    // This non-executable index is never read by sdk_auth_retirement_job.
    retirements: BTreeMap<String, sdk_retirement::Job>,
    logical_cleanup: BTreeMap<String, namespace_sdk_cleanup::Record>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CiphertextOwner {
    pub(crate) binding: CustodyBinding,
    pub(crate) key_epoch: u64,
    pub(crate) seal_frontier: u64,
    pub(crate) parent: Option<crate::namespace_custody::InheritedParent>,
    pub(crate) descriptor: [u8; 32],
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registry {
    namespaces: BTreeMap<String, Locator>,
}
fn digest<T: Serialize>(value: &T) -> Result<[u8; 32], AuthError> {
    let bytes = Zeroizing::new(
        crate::secret_serde::to_vec(value, 4 * 1024 * 1024)
            .map_err(|_| err(503, "SDK namespace custody encoding unavailable"))?,
    );
    Ok(crate::crypto::digest(&bytes))
}
impl Parcel {
    fn index(&self, actual: &str, boundary: &CustodyBinding) -> Result<Locator, AuthError> {
        if actual.is_empty()
            || actual != self.namespace
            || !(actual == boundary.namespace()
                || actual
                    .strip_prefix(boundary.namespace())
                    .is_some_and(|tail| tail.starts_with('/')))
        {
            return Err(err(503, "SDK namespace custody parcel ownership rejected"));
        }
        self.namespace_owner.validate(actual)?;
        let credentials = self
            .credentials
            .as_ref()
            .map(|records| records.namespace_index(actual))
            .transpose()?
            .unwrap_or_default();
        let retirements = self
            .retirements
            .as_ref()
            .map(|jobs| jobs.namespace_index(actual))
            .transpose()?
            .unwrap_or_default();
        if credentials
            .values()
            .any(|r| r.namespace_owner.as_ref() != Some(&self.namespace_owner))
            || retirements
                .values()
                .any(|j| j.saved_namespace_owner() != Some(&self.namespace_owner))
        {
            return Err(err(
                503,
                "SDK namespace custody actual saved incarnation differs",
            ));
        }
        Ok(Locator {
            boundary: boundary.clone(),
            namespace_owner: self.namespace_owner.clone(),
            enclosures: Vec::new(),
            parcel: digest(&(b"heptabao-sdk-auth-namespace-parcel-114".as_slice(), self))?,
            ciphertext_owner: None,
            credentials,
            retirements,
            logical_cleanup: self.logical_cleanup.clone(),
        })
    }
}
impl AuthState {
    pub(crate) fn has_sdk_namespace_custody(&self) -> bool {
        self.sdk_namespace_custody.is_some()
    }
    pub(super) fn detach_sdk_namespace(
        &mut self,
        actual: &str,
    ) -> Result<Option<Parcel>, AuthError> {
        let owner = self
            .namespace_batch_registry
            .as_ref()
            .map(|registry| registry.binding(actual))
            .transpose()?;
        let Some(owner) = owner else {
            if self
                .sdk_credential_leases
                .as_ref()
                .is_some_and(|r| r.namespace_present(actual))
                || self
                    .sdk_auth_retirements
                    .as_ref()
                    .is_some_and(|r| r.namespace_present(actual))
            {
                return Err(err(
                    503,
                    "SDK namespace parcel requires actual saved lifecycle owner",
                ));
            }
            return Ok(None);
        };
        let logical_cleanup = self.namespace_sdk_logical_custody_records(actual, &owner)?;
        let credentials = self
            .sdk_credential_leases
            .as_mut()
            .map(|r| r.namespace_slice(actual, &owner));
        let retirements = self
            .sdk_auth_retirements
            .as_mut()
            .map(|r| r.namespace_slice(actual, &owner));
        if credentials
            .as_ref()
            .is_none_or(sdk_credential::Registry::is_empty)
            && retirements
                .as_ref()
                .is_none_or(sdk_retirement::Registry::is_empty)
            && logical_cleanup.is_empty()
        {
            return Ok(None);
        }
        Ok(Some(Parcel {
            namespace: actual.into(),
            namespace_owner: owner,
            credentials,
            retirements,
            logical_cleanup,
        }))
    }
    pub(crate) fn install_sdk_namespace_custody(
        &mut self,
        actual: &str,
        boundary: &CustodyBinding,
        parcel: &namespace_assets::NamespaceAssets,
    ) -> Result<(), AuthError> {
        let Some(value) = parcel.sdk_namespace_parcel() else {
            return Ok(());
        };
        let locator = value.index(actual, boundary)?;
        let registry = self
            .sdk_namespace_custody
            .get_or_insert_with(Registry::default);
        if registry.namespaces.contains_key(actual) || registry.namespaces.len() >= 1024 {
            return Err(err(
                503,
                "SDK namespace custody locator collision or capacity rejected",
            ));
        }
        registry.namespaces.insert(actual.into(), locator);
        self.update_sdk_auth_retirement_mirror()
    }
    pub(crate) fn bind_sdk_namespace_ciphertext(
        &mut self,
        boundary: &CustodyBinding,
        owner: CiphertextOwner,
    ) -> Result<(), AuthError> {
        if let Some(registry) = &mut self.sdk_namespace_custody {
            if &owner.binding != boundary {
                return Err(err(503, "SDK namespace actual ciphertext binding differs"));
            }
            for entry in registry.namespaces.values_mut() {
                if &entry.boundary == boundary {
                    entry.ciphertext_owner = Some(owner.clone());
                } else {
                    let visible = entry
                        .enclosures
                        .last()
                        .or(entry.ciphertext_owner.as_ref())
                        .ok_or_else(|| err(503, "SDK namespace prior ciphertext owner absent"))?;
                    if visible
                        .binding
                        .namespace()
                        .strip_prefix(boundary.namespace())
                        .is_some_and(|tail| tail.starts_with('/'))
                    {
                        if entry.enclosures.len() >= 256 {
                            return Err(err(503, "SDK namespace enclosing owner bound exceeded"));
                        }
                        entry.enclosures.push(owner.clone());
                    }
                }
            }
            self.update_sdk_auth_retirement_mirror()?;
        }
        Ok(())
    }
    pub(super) fn sdk_namespace_attach_preflight(
        &self,
        actual: &str,
        parcel: &Option<Parcel>,
    ) -> Result<(), AuthError> {
        match (
            parcel,
            self.sdk_namespace_custody
                .as_ref()
                .and_then(|r| r.namespaces.get(actual)),
        ) {
            (None, None) => Ok(()),
            (Some(parcel), Some(locator)) => {
                let mut expected = parcel.index(actual, &locator.boundary)?;
                expected.ciphertext_owner = locator.ciphertext_owner.clone();
                expected.enclosures = locator.enclosures.clone();
                if digest(&expected)? != digest(locator)?
                    || locator.ciphertext_owner.is_none()
                    || !locator.enclosures.is_empty()
                    || parcel.credentials.as_ref().is_some_and(|incoming| {
                        self.sdk_credential_leases
                            .as_ref()
                            .is_none_or(|current| current.contains_any(incoming))
                    })
                    || parcel.retirements.as_ref().is_some_and(|incoming| {
                        self.sdk_auth_retirements
                            .as_ref()
                            .is_none_or(|current| current.contains_any(incoming))
                    })
                {
                    return Err(err(
                        503,
                        "SDK namespace custody restore provenance or collision rejected",
                    ));
                }
                Ok(())
            }
            _ => Err(err(503, "SDK namespace custody parcel and locator differ")),
        }
    }
    pub(super) fn attach_sdk_namespace(
        &mut self,
        actual: &str,
        parcel: Option<Parcel>,
    ) -> Result<(), AuthError> {
        self.sdk_namespace_attach_preflight(actual, &parcel)?;
        let Some(parcel) = parcel else {
            return Ok(());
        };
        if self.namespace_sdk_logical_custody_records(actual, &parcel.namespace_owner)?
            != parcel.logical_cleanup
        {
            return Err(err(
                503,
                "namespace SDK logical custody original selection differs",
            ));
        }
        if let Some(records) = parcel.credentials {
            self.sdk_credential_leases
                .as_mut()
                .ok_or_else(|| err(503, "SDK namespace credential registry presence changed"))?
                .append_exact(records)?;
        }
        if let Some(jobs) = parcel.retirements {
            self.sdk_auth_retirements
                .as_mut()
                .ok_or_else(|| err(503, "SDK namespace retirement registry presence changed"))?
                .append_exact(jobs)?;
        }
        self.sdk_namespace_custody
            .as_mut()
            .ok_or_else(|| err(503, "SDK namespace custody registry absent"))?
            .namespaces
            .remove(actual)
            .ok_or_else(|| err(503, "SDK namespace custody locator absent"))?;
        self.update_sdk_auth_retirement_mirror()
    }
    /// Restore history only from complete, authenticated logical Records.
    /// The original locator digest/collision/enclosure checks still govern the
    /// full Parcel transfer. No index can manufacture a Record or execution grant.
    pub(crate) fn restore_terminal_sdk_namespace_history(
        &mut self,
        binding: &CustodyBinding,
        authenticated: &AuthState,
    ) -> Result<(), AuthError> {
        let actual = binding.namespace();
        let mut owned = authenticated.clone();
        if owned
            .namespace_sdk_saved_credential_records(actual)?
            .iter()
            .any(|record| record.phase != crate::engines::sdk_lease::Phase::Revoked)
        {
            return Err(err(503, "namespace terminal credential history is not revoked"));
        }
        let parcel = owned.detach_sdk_namespace(actual)?;
        if let Some(parcel) = &parcel {
            if parcel.namespace_owner.incarnation() != binding.incarnation()
                || parcel
                    .retirements
                    .as_ref()
                    .map(|jobs| jobs.namespace_index(actual))
                    .transpose()?
                    .is_some_and(|jobs| jobs.values().any(|job| !job.completed()))
                || parcel.logical_cleanup.values().any(|record| {
                    !matches!(record.stage(), namespace_sdk_cleanup::Stage::Terminal { .. })
                })
            {
                return Err(err(503, "namespace terminal SDK history lacks actual completion"));
            }
        }
        self.attach_sdk_namespace(actual, parcel)
    }
    pub(super) fn custody_credential_records(&self) -> Vec<&sdk_credential::CustodyRecord> {
        self.sdk_namespace_custody
            .as_ref()
            .into_iter()
            .flat_map(|r| r.namespaces.values())
            .flat_map(|entry| entry.credentials.values())
            .collect()
    }
    pub(super) fn custody_credential_record(
        &self,
        id: &str,
    ) -> Option<&sdk_credential::CustodyRecord> {
        self.sdk_namespace_custody
            .as_ref()?
            .namespaces
            .values()
            .find_map(|entry| entry.credentials.get(id))
    }
    pub(super) fn custody_retirement_jobs(&self) -> Vec<&sdk_retirement::Job> {
        self.sdk_namespace_custody
            .as_ref()
            .into_iter()
            .flat_map(|r| r.namespaces.values())
            .flat_map(|entry| entry.retirements.values())
            .collect()
    }
    pub(super) fn custody_retirement_job_for_validation(
        &self,
        id: &str,
    ) -> Option<&sdk_retirement::Job> {
        self.sdk_namespace_custody
            .as_ref()?
            .namespaces
            .values()
            .find_map(|entry| entry.retirements.get(id))
    }
    pub(crate) fn sdk_namespace_custody_visible_owners(&self) -> Vec<&CiphertextOwner> {
        self.sdk_namespace_custody
            .as_ref()
            .into_iter()
            .flat_map(|r| r.namespaces.values())
            .filter_map(|entry| entry.enclosures.last().or(entry.ciphertext_owner.as_ref()))
            .collect()
    }
    pub(crate) fn sdk_namespace_custody_opening_owners(
        &self,
        actual: &str,
        owner: &CiphertextOwner,
    ) -> Result<Vec<CiphertextOwner>, AuthError> {
        let mut inner = Vec::new();
        if let Some(registry) = &self.sdk_namespace_custody {
            for entry in registry.namespaces.values() {
                if let Some(last) = entry.enclosures.last()
                    && last.binding.namespace() == actual
                {
                    if last != owner {
                        return Err(err(503, "SDK namespace enclosing ciphertext differs"));
                    }
                    inner.push(
                        entry
                            .enclosures
                            .iter()
                            .rev()
                            .nth(1)
                            .or(entry.ciphertext_owner.as_ref())
                            .ok_or_else(|| err(503, "SDK namespace hidden ciphertext absent"))?
                            .clone(),
                    );
                }
            }
        }
        Ok(inner)
    }
    pub(crate) fn remove_sdk_namespace_enclosure(
        &mut self,
        actual: &str,
        owner: &CiphertextOwner,
    ) -> Result<(), AuthError> {
        self.sdk_namespace_custody_opening_owners(actual, owner)?;
        if let Some(registry) = &mut self.sdk_namespace_custody {
            for entry in registry.namespaces.values_mut() {
                if entry
                    .enclosures
                    .last()
                    .is_some_and(|last| last.binding.namespace() == actual)
                {
                    entry.enclosures.pop();
                }
            }
            self.update_sdk_auth_retirement_mirror()?;
        }
        Ok(())
    }
    pub(crate) fn sdk_namespace_custody_unchanged(
        &self,
        previous: &Self,
    ) -> Result<bool, AuthError> {
        Ok(digest(&self.sdk_namespace_custody)? == digest(&previous.sdk_namespace_custody)?)
    }
    pub(super) fn sdk_namespace_custody_pending(&self, actual: &str) -> bool {
        self.sdk_namespace_custody.as_ref().is_some_and(|registry| {
            registry.namespaces.get(actual).is_some_and(|entry| {
                entry
                    .credentials
                    .values()
                    .any(|record| record.lease.phase != crate::engines::sdk_lease::Phase::Revoked)
                    || entry.retirements.values().any(|job| !job.completed())
            })
        })
    }
    pub(crate) fn validate_sdk_namespace_custody_structure(
        &self,
        cluster: &str,
    ) -> Result<(), AuthError> {
        let Some(registry) = &self.sdk_namespace_custody else {
            return Ok(());
        };
        if registry.namespaces.len() > 1024 {
            return Err(err(
                503,
                "SDK namespace custody catalogue or capacity rejected",
            ));
        }
        let mut records = BTreeSet::new();
        let mut jobs = BTreeSet::new();
        let mut record_count = self
            .sdk_credential_leases
            .as_ref()
            .map_or(0, |r| r.custody_global_record_count());
        let mut job_count = self
            .sdk_auth_retirements
            .as_ref()
            .map_or(0, |r| r.custody_global_job_count());
        let mut resource_count = self
            .sdk_auth_retirements
            .as_ref()
            .map_or(Some(0usize), |r| r.custody_global_resource_count())
            .ok_or_else(|| err(503, "SDK namespace retirement resource count overflow"))?;
        for (actual, entry) in &registry.namespaces {
            entry
                .boundary
                .validate_cluster_namespace(cluster, entry.boundary.namespace())
                .map_err(|_| err(503, "SDK namespace custody boundary rejected"))?;
            self.validate_batch_namespace_owner_structure(Some(&entry.namespace_owner), actual)?;
            if self
                .namespace_batch_registry
                .as_ref()
                .ok_or_else(|| err(503, "SDK namespace custody lifecycle absent"))?
                .binding(actual)?
                != entry.namespace_owner
            {
                return Err(err(
                    503,
                    "SDK namespace custody current saved incarnation differs",
                ));
            }
            if entry.logical_cleanup
                != self.namespace_sdk_logical_custody_records(actual, &entry.namespace_owner)?
                || ((!entry.credentials.is_empty() || !entry.retirements.is_empty())
                    && self.sdk_auth_catalog.is_none())
            {
                return Err(err(
                    503,
                    "SDK namespace custody original logical selection or catalog differs",
                ));
            }
            if entry.credentials.is_empty()
                && entry.retirements.is_empty()
                && entry.logical_cleanup.is_empty()
            {
                return Err(err(
                    503,
                    "SDK namespace custody empty locator has no original resource",
                ));
            }
            if actual.is_empty()
                || entry.ciphertext_owner.is_none()
                || entry.parcel == [0; 32]
                || !(actual == entry.boundary.namespace()
                    || actual
                        .strip_prefix(entry.boundary.namespace())
                        .is_some_and(|tail| tail.starts_with('/')))
                || (!entry.credentials.is_empty() && self.sdk_credential_leases.is_none())
                || (!entry.retirements.is_empty() && self.sdk_auth_retirements.is_none())
            {
                return Err(err(503, "SDK namespace custody locator structure rejected"));
            }
            let direct = entry
                .ciphertext_owner
                .as_ref()
                .ok_or_else(|| err(503, "SDK namespace custody ciphertext owner absent"))?;
            if direct.binding != entry.boundary || entry.enclosures.len() > 256 {
                return Err(err(503, "SDK namespace custody direct owner differs"));
            }
            let mut previous_path = direct.binding.namespace();
            for (position, stamp) in std::iter::once(direct).chain(&entry.enclosures).enumerate() {
                stamp
                    .binding
                    .validate_cluster_namespace(cluster, stamp.binding.namespace())
                    .map_err(|_| err(503, "SDK namespace ciphertext owner binding rejected"))?;
                if stamp.descriptor == [0; 32]
                    || stamp.key_epoch == 0
                    || stamp.seal_frontier == 0
                    || (position > 0
                        && !previous_path
                            .strip_prefix(stamp.binding.namespace())
                            .is_some_and(|tail| tail.starts_with('/')))
                {
                    return Err(err(503, "SDK namespace enclosing owner chain rejected"));
                }
                previous_path = stamp.binding.namespace();
            }
            for (id, record) in &entry.credentials {
                if !records.insert(id)
                    || record.lease.id != *id
                    || record.lease.namespace != *actual
                    || self
                        .sdk_credential_leases
                        .as_ref()
                        .is_some_and(|r| r.custody_contains_id(id))
                {
                    return Err(err(
                        503,
                        "SDK namespace custody credential duplicate or owner rejected",
                    ));
                }
                if record.namespace_owner.as_ref() != Some(&entry.namespace_owner) {
                    return Err(err(
                        503,
                        "SDK namespace custody credential incarnation differs",
                    ));
                }
                self.validate_sdk_custody_credential_metadata(record, cluster)?;
            }
            for (id, job) in &entry.retirements {
                if !jobs.insert(id)
                    || job.binding().namespace != *actual
                    || self.sdk_auth_retirement_job(id).is_some()
                {
                    return Err(err(
                        503,
                        "SDK namespace custody retirement duplicate or owner rejected",
                    ));
                }
                if job.saved_namespace_owner() != Some(&entry.namespace_owner) {
                    return Err(err(503, "SDK namespace custody job incarnation differs"));
                }
                job.validate_custody_index(id, cluster, self)?;
                resource_count = resource_count
                    .checked_add(job.custody_resource_count())
                    .ok_or_else(|| err(503, "SDK namespace retirement resource count overflow"))?;
            }
            record_count += entry.credentials.len();
            job_count += entry.retirements.len();
        }
        if record_count > 4096 || job_count > 256 || resource_count > 4096 {
            return Err(err(
                503,
                "SDK namespace custody aggregate capacity rejected",
            ));
        }
        Ok(())
    }
}

impl AuthState {
    pub(crate) fn validate_sdk_namespace_custody_successor(
        &self,
        previous: &Self,
    ) -> Result<(), AuthError> {
        if previous.sdk_namespace_custody.is_some() && self.sdk_namespace_custody.is_none()
            || previous.sdk_credential_leases.is_some() && self.sdk_credential_leases.is_none()
            || previous.sdk_auth_retirements.is_some() && self.sdk_auth_retirements.is_none()
        {
            return Err(err(
                503,
                "SDK namespace custody sticky registry presence regressed",
            ));
        }
        for before in previous.custody_retirement_jobs() {
            let after = self
                .sdk_auth_retirement_job(before.custody_id())
                .or_else(|| self.custody_retirement_job_for_validation(before.custody_id()))
                .ok_or_else(|| err(503, "SDK namespace closed retirement history removed"))?;
            if after != before {
                return Err(err(
                    503,
                    "SDK namespace closed retirement changed without logical proof",
                ));
            }
        }
        Ok(())
    }
    pub(crate) fn sdk_namespace_custody_raw_publication_unchanged(
        &self,
        previous: &Self,
    ) -> Result<bool, AuthError> {
        if previous.sdk_namespace_custody.is_none()
            && self
                .sdk_namespace_custody
                .as_ref()
                .is_some_and(|r| r.namespaces.is_empty())
        {
            // Sticky empty presence carries no owner, record or execution grant.
            return Ok(true);
        }
        self.sdk_namespace_custody_unchanged(previous)
    }
}

impl AuthState {
    #[cfg(test)]
    pub(crate) fn sdk_namespace_credential_index_for_test(
        &self,
        namespace: &str,
        id: &str,
    ) -> Option<(crate::engines::sdk_lease::Metadata<sdk::Binding>, [u8; 32])> {
        let record = self.custody_credential_record(id)?;
        (record.lease.namespace == namespace).then(|| (record.lease.clone(), record.digest))
    }
    #[cfg(test)]
    pub(crate) fn sdk_namespace_job_index_for_test(
        &self,
        namespace: &str,
        id: &str,
    ) -> Option<sdk_retirement::Job> {
        let job = self.custody_retirement_job_for_validation(id)?;
        (job.binding().namespace == namespace).then(|| job.clone())
    }
}

impl AuthState {
    pub(crate) fn validate_namespace_sdk_credential_index(
        &self,
        namespace: &str,
        job: &namespace_sdk_cleanup::Record,
    ) -> Result<(), AuthError> {
        let registry = self
            .sdk_namespace_custody
            .as_ref()
            .ok_or_else(|| err(503, "namespace SDK credential custody index absent"))?;
        let entry = registry
            .namespaces
            .get(namespace)
            .ok_or_else(|| err(503, "namespace SDK credential custody namespace absent"))?;
        if entry.namespace_owner.incarnation() != job.binding().incarnation()
            || namespace != job.binding().namespace()
        {
            return Err(err(
                503,
                "namespace SDK credential custody saved incarnation differs",
            ));
        }
        let value = entry
            .credentials
            .get(job.lease_id())
            .ok_or_else(|| err(503, "namespace SDK credential custody resource absent"))?;
        job.check_credential_index(&value.lease, value.digest)
    }
}

// These functions validate a deferred physical obligation only. They do not
// return a logical Lease, a selected Authority, or permission to dispatch.
impl AuthState {
    fn namespace_sdk_logical_custody_records(
        &self,
        namespace: &str,
        owner: &batch_namespace::Binding,
    ) -> Result<BTreeMap<String, namespace_sdk_cleanup::Record>, AuthError> {
        owner.validate(namespace)?;
        let Some(ledger) = self.namespace_deletion_ledger() else {
            return Ok(BTreeMap::new());
        };
        let Some(work) = ledger.sdk_cleanup() else {
            return Ok(BTreeMap::new());
        };
        let mut selected = BTreeMap::new();
        for (key, record) in work.records() {
            if record.kind() == namespace_sdk_cleanup::Kind::Logical
                && record.binding().namespace() == namespace
                && record.binding().incarnation() == owner.incarnation()
            {
                if !ledger.is_tainted(namespace) || record.work_id()? != *key {
                    return Err(err(
                        503,
                        "namespace SDK logical custody original task rejected",
                    ));
                }
                selected.insert(key.clone(), record.clone());
            }
        }
        Ok(selected)
    }
    pub(crate) fn validate_namespace_sdk_logical_custody_obligation(
        &self,
        namespace: &str,
        binding: &CustodyBinding,
    ) -> Result<bool, AuthError> {
        let Some(entry) = self
            .sdk_namespace_custody
            .as_ref()
            .and_then(|r| r.namespaces.get(namespace))
        else {
            return Ok(false);
        };
        if entry.logical_cleanup.is_empty() {
            return Ok(false);
        }
        if binding.namespace() != namespace
            || binding.incarnation() != entry.namespace_owner.incarnation()
            || entry.logical_cleanup
                != self.namespace_sdk_logical_custody_records(namespace, &entry.namespace_owner)?
        {
            return Err(err(
                503,
                "namespace SDK logical custody actual owner or selection differs",
            ));
        }
        Ok(true)
    }
    pub(crate) fn validate_namespace_sdk_logical_custody_index(
        &self,
        namespace: &str,
        record: &namespace_sdk_cleanup::Record,
    ) -> Result<(), AuthError> {
        if !self.validate_namespace_sdk_logical_custody_obligation(namespace, record.binding())? {
            return Err(err(503, "namespace SDK logical custody obligation absent"));
        }
        let entry = self
            .sdk_namespace_custody
            .as_ref()
            .and_then(|r| r.namespaces.get(namespace))
            .ok_or_else(|| err(503, "namespace SDK logical custody index absent"))?;
        if entry.logical_cleanup.get(&record.work_id()?) != Some(record) {
            return Err(err(
                503,
                "namespace SDK logical custody full original task differs",
            ));
        }
        Ok(())
    }
}
