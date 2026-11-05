//! Complete historical logical leases. These entries are structural provenance,
//! never a lookup, renewal, expiry candidate, callback payload or live grant.
use super::*;
use crate::namespace_custody::Binding;

const MAX_HISTORY: usize = 10_000;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    binding: Binding,
    lease: sdk_lease::Lease,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registry {
    entries: BTreeMap<String, Entry>,
}
#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Mirror {
    entries: BTreeMap<String, Summary>,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Summary {
    binding: Binding,
    lease_digest: [u8; 32],
}
impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RetiredLogicalSdkHistory([REDACTED])")
    }
}
fn digest<T: Serialize>(value: &T) -> Result<[u8; 32]> {
    let bytes = zeroize::Zeroizing::new(
        crate::secret_serde::to_vec(value, 512 * 1024)
            .map_err(|_| error(503, "SDK logical history encoding rejected"))?,
    );
    Ok(crate::crypto::digest(&bytes))
}
fn history_key(binding: &Binding, id: &str) -> Result<String> {
    Ok(digest(&("retired-logical-sdk-v1", binding, id))?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
impl Entry {
    fn validate(&self, cluster: &str) -> Result<()> {
        self.binding
            .validate_cluster_namespace(cluster, &self.lease.namespace)
            .map_err(|_| error(503, "SDK logical history namespace binding rejected"))?;
        self.lease.validate(&self.lease.namespace)?;
        if self.binding.namespace().is_empty()
            || self.lease.cluster != cluster
            || self.lease.phase != sdk_lease::Phase::Revoked
        {
            return Err(error(
                503,
                "SDK logical history requires actual revoked record",
            ));
        }
        if let Some(registration) = &self.lease.registration {
            registration.validate_retired_namespace(self.binding.incarnation())?;
        }
        Ok(())
    }
    fn same_original(&self, old: &sdk_lease::Lease) -> bool {
        self.lease.id == old.id
            && self.lease.namespace == old.namespace
            && self.lease.cluster == old.cluster
            && self.lease.mount == old.mount
            && self.lease.path == old.path
            && self.lease.backend == old.backend
            && self.lease.registration == old.registration
            && self.lease.issuer == old.issuer
            && self.lease.issued == old.issued
    }
}
impl Mirror {
    pub(crate) fn bindings(&self) -> impl Iterator<Item = &Binding> {
        self.entries.values().map(|entry| &entry.binding)
    }
    pub(crate) fn validate(
        &self,
        cluster: &str,
        pending: &BTreeMap<String, Binding>,
        retired: &BTreeMap<String, u64>,
    ) -> Result<()> {
        if self.entries.len() > MAX_HISTORY {
            return Err(error(503, "SDK logical history mirror exceeds bound"));
        }
        for summary in self.entries.values() {
            summary
                .binding
                .validate_cluster_namespace(cluster, summary.binding.namespace())
                .map_err(|_| error(503, "SDK logical history mirror binding rejected"))?;
            if summary.lease_digest == [0; 32]
                || (pending.get(summary.binding.namespace()) != Some(&summary.binding)
                    && retired
                        .get(summary.binding.namespace())
                        .is_none_or(|inc| *inc < summary.binding.incarnation()))
            {
                return Err(error(
                    503,
                    "SDK logical history lacks actual namespace retirement",
                ));
            }
        }
        Ok(())
    }
    pub(crate) fn validate_successor(&self, old: &Self) -> Result<()> {
        if old
            .entries
            .iter()
            .any(|(key, entry)| self.entries.get(key) != Some(entry))
        {
            return Err(error(
                503,
                "SDK logical history mirror cannot be removed or changed",
            ));
        }
        Ok(())
    }
}
impl Registry {
    fn records(&self) -> impl Iterator<Item = &sdk_lease::Lease> {
        self.entries.values().map(|entry| &entry.lease)
    }
    fn projection(&self) -> Result<Mirror> {
        let entries = self
            .entries
            .iter()
            .map(|(key, entry)| {
                Ok((
                    key.clone(),
                    Summary {
                        binding: entry.binding.clone(),
                        lease_digest: digest(&entry.lease)?,
                    },
                ))
            })
            .collect::<Result<_>>()?;
        Ok(Mirror { entries })
    }
    fn validate(&self, engines: &EngineState, cluster: &str) -> Result<()> {
        if self.entries.len() > MAX_HISTORY {
            return Err(error(503, "SDK logical history exceeds bound"));
        }
        for (key, entry) in &self.entries {
            entry.validate(cluster)?;
            if key != &history_key(&entry.binding, &entry.lease.id)?
                || !engines.sdk_catalog.known_generation(
                    &entry.lease.backend.plugin,
                    &entry.lease.backend.version,
                    entry.lease.backend.catalog_generation,
                )
                || engines
                    .namespaces
                    .get(&entry.lease.namespace)
                    .and_then(|ns| ns.sdk_leases.get(&entry.lease.id))
                    .is_some_and(|lease| entry.same_original(lease))
            {
                return Err(error(
                    503,
                    "SDK logical history owner or current-record conflict",
                ));
            }
        }
        Ok(())
    }
    fn validate_successor(&self, old: &Self) -> Result<()> {
        for (key, previous) in &old.entries {
            let next = self
                .entries
                .get(key)
                .ok_or_else(|| error(503, "SDK logical registration history disappeared"))?;
            if digest(next)? != digest(previous)? {
                return Err(error(503, "SDK logical registration history changed"));
            }
        }
        Ok(())
    }
}
impl EngineState {
    pub(crate) fn ensure_sdk_logical_history(&mut self) {
        self.sdk_retired_logical
            .get_or_insert_with(|| Registry::default().into());
    }
    pub(crate) fn sdk_logical_history_projection(&self) -> Result<Option<Mirror>> {
        self.sdk_retired_logical
            .as_ref()
            .map(|registry| registry.projection())
            .transpose()
    }
    /// Mount-owner metadata survives protected record views. Only actual lease
    /// records or an authenticated, attached namespace graph prove materialization.
    pub(crate) fn sdk_namespace_records_materialized(&self, namespace: &str) -> bool {
        self.namespaces
            .get(namespace)
            .is_some_and(|state| !state.sdk_leases.is_empty())
            || self
                .records
                .as_ref()
                .is_some_and(|records| records.loaded_namespaces.contains(namespace))
    }
    pub(crate) fn sdk_materialized_namespace_records(
        &self,
        namespace: &str,
    ) -> Result<Vec<sdk_lease::Lease>> {
        self.validate_sdk_leases()?;
        Ok(self
            .namespaces
            .get(namespace)
            .map_or_else(Vec::new, |state| {
                state.sdk_leases.values().cloned().collect()
            }))
    }
    pub(crate) fn sdk_logical_history_records(&self) -> impl Iterator<Item = &sdk_lease::Lease> {
        self.sdk_retired_logical
            .iter()
            .flat_map(|registry| registry.records())
    }
    #[cfg(any(test, target_os = "linux", target_os = "macos"))]
    pub(crate) fn sdk_logical_history_source(
        &self,
        binding: &Binding,
    ) -> Result<Vec<sdk_lease::Lease>> {
        let records = self.namespace_sdk_deletion_records(binding.namespace())?;
        for lease in &records {
            Entry {
                binding: binding.clone(),
                lease: lease.clone(),
            }
            .validate(&lease.cluster)?;
        }
        Ok(records)
    }
    pub(crate) fn install_sdk_logical_history(
        &mut self,
        binding: &Binding,
        records: Vec<sdk_lease::Lease>,
    ) -> Result<()> {
        if self
            .namespaces
            .get(binding.namespace())
            .is_some_and(|ns| !ns.sdk_leases.is_empty())
        {
            return Err(error(
                503,
                "SDK logical history cannot retain a callable namespace record",
            ));
        }
        let registry = self
            .sdk_retired_logical
            .as_mut()
            .ok_or_else(|| error(503, "SDK logical history marker missing"))?;
        for lease in records {
            let entry = Entry {
                binding: binding.clone(),
                lease,
            };
            entry.validate(&entry.lease.cluster)?;
            let key = history_key(binding, &entry.lease.id)?;
            if registry.entries.len() >= MAX_HISTORY && !registry.entries.contains_key(&key) {
                return Err(error(507, "SDK logical history capacity exhausted"));
            }
            if let Some(old) = registry.entries.get(&key) {
                if digest(old)? != digest(&entry)? {
                    return Err(error(
                        503,
                        "SDK logical history cannot overwrite an original owner",
                    ));
                }
            } else {
                registry.entries.insert(key, entry);
            }
        }
        Ok(())
    }
    pub(crate) fn validate_sdk_logical_history(
        &self,
        cluster: &str,
        previous: Option<&Self>,
    ) -> Result<()> {
        if let Some(registry) = &self.sdk_retired_logical {
            registry.validate(self, cluster)?;
        }
        if let Some(old) = previous.and_then(|state| state.sdk_retired_logical.as_ref()) {
            self.sdk_retired_logical
                .as_ref()
                .ok_or_else(|| error(503, "SDK logical history sticky registry disappeared"))?
                .validate_successor(old)?;
        }
        Ok(())
    }
    pub(crate) fn validate_sdk_logical_history_successor(&self, previous: &Self) -> Result<()> {
        match (&self.sdk_retired_logical, &previous.sdk_retired_logical) {
            (Some(next), Some(old)) => next.validate_successor(old),
            (None, Some(_)) => Err(error(
                503,
                "SDK logical history sticky registry disappeared",
            )),
            _ => Ok(()),
        }
    }
    #[cfg(test)]
    pub(crate) fn sdk_history_fixture_damage(&mut self) {
        if let Some(registry) = self.sdk_retired_logical.as_mut()
            && let Some(entry) = registry.entries.values_mut().next()
        {
            entry.lease.registration = None;
        }
    }
    #[cfg(test)]
    pub(crate) fn sdk_history_fixture_clear_materialized_leases(&mut self, namespace: &str) {
        if let Some(state) = self.namespaces.get_mut(namespace) {
            state.sdk_leases.clear();
        }
    }
    pub(crate) fn sdk_history_contains_id(&self, namespace: &str, id: &str) -> bool {
        self.sdk_logical_history_records()
            .any(|lease| lease.namespace == namespace && lease.id == id)
    }
    pub(crate) fn sdk_registered_history_successor(
        &self,
        original: &sdk_lease::Lease,
    ) -> Option<&sdk_lease::Lease> {
        self.sdk_retired_logical
            .as_ref()?
            .entries
            .values()
            .find(|entry| entry.same_original(original))
            .map(|entry| &entry.lease)
    }
    pub(crate) fn sdk_logical_history_shared_with(&self, previous: &Self) -> bool {
        match (&self.sdk_retired_logical, &previous.sdk_retired_logical) {
            (None, None) => true,
            (Some(current), Some(old)) => Arc::ptr_eq(&current.0, &old.0),
            _ => false,
        }
    }
}

impl Registry {
    pub(super) fn has_lossless_json_state(&self) -> bool {
        self.entries
            .values()
            .any(|entry| entry.lease.has_lossless_json_state())
    }
}
