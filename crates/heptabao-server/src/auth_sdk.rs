//! SDK Auth owns a distinct catalog and encrypted namespace auth cells. None
//! retains historical bytes; retained catalog epochs make retirement sticky.
//! No value in this module is a Principal or an authentication admission.
use super::*;
use crate::engines::sdk::{Catalog, Descriptor};
#[path = "auth_sdk_renew.rs"]
mod renewal;
pub(crate) use renewal::RenewalTarget;
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cell {
    value: Vec<u8>,
    seal_wrap: bool,
}
impl std::fmt::Debug for Cell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SDK Auth cell([REDACTED])")
    }
}
impl Drop for Cell {
    fn drop(&mut self) {
        self.value.zeroize()
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Paths {
    root: Vec<String>,
    unauthenticated: Vec<String>,
}
impl Paths {
    pub(crate) fn from_actual(value: &Value) -> Result<Self, AuthError> {
        let root: Vec<String> = serde_json::from_value(
            value
                .get("Root")
                .cloned()
                .ok_or_else(|| bad("SDK Root metadata missing"))?,
        )
        .map_err(|_| bad("SDK Root metadata malformed"))?;
        let unauthenticated: Vec<String> = serde_json::from_value(
            value
                .get("Unauthenticated")
                .cloned()
                .ok_or_else(|| bad("SDK public metadata missing"))?,
        )
        .map_err(|_| bad("SDK public metadata malformed"))?;
        let paths = Self {
            root,
            unauthenticated,
        };
        paths.validate()?;
        Ok(paths)
    }
    fn validate(&self) -> Result<(), AuthError> {
        if !heptabao_plugin_contracts::sdk_paths::valid_root(&self.root)
            || !heptabao_plugin_contracts::sdk_paths::valid(&self.unauthenticated)
        {
            return Err(bad("SDK path policy rejected"));
        }
        Ok(())
    }
    pub(crate) fn wire(&self) -> Value {
        json!({"Root":self.root,"Unauthenticated":self.unauthenticated,"LocalStorage":[],"SealWrapStorage":[],"WriteForwardedStorage":[]})
    }
    pub(crate) fn is_root(&self, path: &str) -> bool {
        heptabao_plugin_contracts::sdk_paths::root_matches(&self.root, path)
    }
    pub(crate) fn is_public(&self, path: &str) -> bool {
        heptabao_plugin_contracts::sdk_paths::matches(&self.unauthenticated, path)
    }
    pub(crate) fn legacy() -> Self {
        Self {
            root: Vec::new(),
            unauthenticated: vec!["login".into()],
        }
    }
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Mount {
    descriptor: Descriptor,
    mount: AuthMount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    special_paths: Option<Paths>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    storage: BTreeMap<String, Cell>,
}
impl std::fmt::Debug for Mount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SDK Auth mount([REDACTED])")
    }
}
impl Mount {
    pub(super) fn same_binding(&self, other: &Self) -> bool {
        self.descriptor == other.descriptor
            && self.mount == other.mount
            && self.special_paths == other.special_paths
    }
    pub(super) fn validate_local(&self, current: Option<&AuthMount>) -> Result<(), AuthError> {
        self.descriptor
            .validate()
            .map_err(|_| err(503, "SDK Auth descriptor rejected"))?;
        if current != Some(&self.mount)
            || self.mount.kind != "plugin"
            || self.mount.accessor.as_ref().is_none_or(|a| a.is_empty())
            || self.mount.revision == 0
        {
            return Err(err(503, "SDK Auth exact mount identity rejected"));
        }
        if let Some(paths) = &self.special_paths {
            paths.validate()?;
        }
        if self.storage.len() > 4096 {
            return Err(err(503, "SDK Auth storage cell bound exceeded"));
        }
        let mut total = 0usize;
        for (key, value) in &self.storage {
            if key.is_empty()
                || key.len() > 4096
                || key.contains('\0')
                || value.value.len() > 256 * 1024
            {
                return Err(err(503, "SDK Auth storage cell rejected"));
            }
            total = total
                .checked_add(key.len())
                .and_then(|n| n.checked_add(value.value.len()))
                .ok_or_else(|| err(503, "SDK Auth storage size overflow"))?;
            if total > 8 * 1024 * 1024 {
                return Err(err(507, "SDK Auth storage owner capacity exceeded"));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub namespace: String,
    pub mount: String,
    descriptor: Descriptor,
    owner: AuthMount,
}
impl Binding {
    pub(crate) fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
}
impl crate::engines::sdk_lease::Backend for Binding {
    fn validate_lease_binding(
        &self,
        namespace: &str,
        mount: &str,
    ) -> Result<(), crate::engines::EngineError> {
        self.descriptor.validate()?;
        if self.namespace != namespace
            || mount != format!("auth/{}/", self.mount)
            || self.mount.is_empty()
            || self.owner.kind != "plugin"
            || self.owner.revision == 0
            || self
                .owner
                .accessor
                .as_ref()
                .is_none_or(|accessor| accessor.is_empty())
        {
            return Err(crate::engines::EngineError {
                status: 503,
                message: "SDK credential actual Auth mount binding rejected".into(),
            });
        }
        Ok(())
    }
}
/// An in-memory owned Storage observation. It is neither cloneable nor a
/// persisted grant; the exact mount includes every observed cell and metadata.
pub(crate) struct StorageWitness {
    mount: Mount,
}
impl StorageWitness {
    pub(crate) fn check(&self, auth: &AuthState, binding: &Binding) -> Result<(), AuthError> {
        auth.sdk_auth_owner_gate(binding)?;
        if auth.plugin_auth_mounts[&binding.namespace][&binding.mount]
            .sdk
            .as_ref()
            != Some(&self.mount)
        {
            return Err(err(503, "SDK Auth admitted Storage owner changed"));
        }
        Ok(())
    }
}
pub(crate) struct Entry {
    pub key: String,
    pub value: Zeroizing<Vec<u8>>,
    pub seal_wrap: bool,
}
impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SDK Auth storage entry([REDACTED])")
    }
}
impl AuthState {
    pub(crate) fn has_sdk_auth_state(&self) -> bool {
        self.sdk_auth_catalog.is_some()
            || self.sdk_auth_clock.is_some()
            || self
                .plugin_auth_mounts
                .values()
                .any(|mounts| mounts.values().any(|mount| mount.sdk.is_some()))
    }
    pub(crate) fn sdk_auth_paths(&self, binding: &Binding) -> Result<Option<Paths>, AuthError> {
        self.sdk_auth_owner_gate(binding)?;
        Ok(self
            .plugin_auth_mounts
            .get(&binding.namespace)
            .and_then(|mounts| mounts.get(&binding.mount))
            .and_then(|config| config.sdk.as_ref())
            .and_then(|sdk| sdk.special_paths.clone()))
    }
    pub(crate) fn capture_sdk_auth_paths(
        &mut self,
        binding: &Binding,
        paths: Paths,
    ) -> Result<(), AuthError> {
        self.sdk_auth_owner_gate(binding)?;
        paths.validate()?;
        let sdk = self
            .plugin_auth_mounts
            .get_mut(&binding.namespace)
            .and_then(|mounts| mounts.get_mut(&binding.mount))
            .and_then(|config| config.sdk.as_mut())
            .ok_or_else(|| err(503, "SDK metadata owner absent"))?;
        if sdk.special_paths.is_some() {
            return Err(err(409, "SDK metadata already captured"));
        }
        sdk.special_paths = Some(paths);
        Ok(())
    }
    pub(super) fn sdk_public_path(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
    ) -> Option<bool> {
        let binding = self.sdk_auth_binding(namespace, path).ok().flatten()?;
        let relative = path.strip_prefix(&format!("auth/{}/", binding.mount))?;
        let paths = match self.sdk_auth_paths(&binding) {
            Ok(Some(paths)) => paths,
            Ok(None) => Paths::legacy(),
            Err(_) => return Some(false),
        };
        Some(
            paths.is_public(&heptabao_plugin_contracts::sdk_paths::request_path(
                relative, method,
            )),
        )
    }
    pub(crate) fn sdk_auth_clock_floor(&self) -> Option<Timestamp> {
        self.sdk_auth_clock
    }
    pub(crate) fn observe_sdk_auth_clock(&mut self, at: Timestamp) -> bool {
        let next = self.sdk_auth_clock.map_or(at, |floor| floor.max(at));
        let changed = self.sdk_auth_clock != Some(next);
        self.sdk_auth_clock = Some(next);
        changed
    }
    pub(crate) fn validate_sdk_auth_clock(&self, previous: Option<&Self>) -> Result<(), AuthError> {
        if let Some(previous) = previous {
            for (namespace, mounts) in &previous.plugin_auth_mounts {
                for (mount, config) in mounts {
                    let Some(old) = config
                        .sdk
                        .as_ref()
                        .filter(|sdk| sdk.special_paths.is_some())
                    else {
                        continue;
                    };
                    let current = self
                        .plugin_auth_mounts
                        .get(namespace)
                        .and_then(|mounts| mounts.get(mount))
                        .and_then(|config| config.sdk.as_ref());
                    if let Some(current) = current
                        && current.descriptor == old.descriptor
                        && current.mount.accessor == old.mount.accessor
                        && current.special_paths != old.special_paths
                    {
                        return Err(err(503, "SDK original mounted path policy cannot change"));
                    }
                }
            }
        }
        if previous
            .and_then(|state| state.sdk_auth_clock)
            .is_some_and(|floor| self.sdk_auth_clock.is_none_or(|time| time < floor))
        {
            return Err(err(
                503,
                "SDK Auth original observation floor cannot decrease",
            ));
        }
        if self.sdk_auth_catalog.is_some() != self.sdk_auth_clock.is_some() {
            return Err(err(503, "SDK Auth original observation floor absent"));
        }
        Ok(())
    }
    pub(crate) fn sdk_auth_epoch_floor(&self) -> Option<BTreeMap<String, u64>> {
        self.sdk_auth_catalog.as_ref().map(Catalog::epoch_floor)
    }
    pub(crate) fn validate_sdk_auth_epoch_floor(
        &self,
        floor: Option<&BTreeMap<String, u64>>,
    ) -> Result<(), AuthError> {
        if floor.is_some_and(|floor| {
            self.sdk_auth_catalog
                .as_ref()
                .is_none_or(|catalog| !catalog.protects_epoch_floor(floor))
        }) {
            return Err(err(503, "SDK Auth catalog epoch floor cannot decrease"));
        }
        Ok(())
    }
    pub(crate) fn validate_sdk_auth_state(&self) -> Result<(), AuthError> {
        self.validate_sdk_auth_clock(None)?;
        if let Some(catalog) = &self.sdk_auth_catalog {
            catalog
                .validate()
                .map_err(|_| err(503, "SDK Auth catalog rejected"))?
        }
        for (namespace, mounts) in &self.plugin_auth_mounts {
            let actual = self.effective_auth_mounts(namespace);
            for (mount, config) in mounts {
                if let Some(sdk) = &config.sdk {
                    sdk.validate_local(actual.get(mount))?;
                    if config.plugin_id != sdk.descriptor.name
                        || self.sdk_auth_catalog.as_ref().and_then(|catalog| {
                            catalog.get(&sdk.descriptor.name, &sdk.descriptor.version)
                        }) != Some(&sdk.descriptor)
                    {
                        return Err(err(503, "SDK Auth catalog owner changed"));
                    }
                }
            }
        }
        for token in self.tokens.values() {
            if let Some(TokenAuthProvenance::Sdk { origin }) = &token.auth_provenance {
                origin
                    .binding
                    .descriptor
                    .validate()
                    .map_err(|_| err(503, "SDK Auth saved issuer rejected"))?;
                validate_namespace(&origin.binding.namespace)?;
                if origin.binding.mount.is_empty()
                    || origin.binding.mount.len() > 512
                    || origin
                        .binding
                        .mount
                        .split('/')
                        .any(|part| !valid_name(part))
                    || origin.binding.owner.kind != "plugin"
                    || origin.binding.owner.revision == 0
                    || origin
                        .binding
                        .owner
                        .accessor
                        .as_ref()
                        .is_none_or(|accessor| accessor.is_empty())
                    || serde_json::to_vec(&origin.internal_data)
                        .map_err(|_| bad("SDK Auth internal data rejected"))?
                        .len()
                        > 256 * 1024
                {
                    return Err(err(503, "SDK Auth saved native mount owner rejected"));
                }
                if token.namespace != origin.binding.namespace
                    || token.auth_mount.as_ref() != Some(&origin.binding.mount)
                    || token.renewable && origin.renewal.is_none()
                    || origin.renewal.as_ref().is_some_and(|r| !r.valid())
                    || token.root
                    || token.policies.contains("root")
                    || self.sdk_auth_catalog.as_ref().is_none_or(|c| {
                        !c.known_generation(
                            &origin.binding.descriptor.name,
                            &origin.binding.descriptor.version,
                            origin.binding.descriptor.generation,
                        )
                    })
                    || self.sdk_auth_clock.is_none_or(|at| {
                        origin.lease.issued_at > at || origin.lease.grant_started_at > at
                    })
                    || origin
                        .lease
                        .validate(
                            token.created_at,
                            token.expires_at,
                            Some(origin.lease.previous_grant.ceil_seconds()),
                        )
                        .is_err()
                    || token.max_expires_at != origin.maximum.ceil_seconds().ok()
                    || origin.maximum
                        < origin
                            .lease
                            .expires_at
                            .ok_or_else(|| err(503, "SDK Auth saved expiry absent"))?
                    || !crate::login_metadata::within_limit(&origin.metadata)
                {
                    return Err(err(503, "SDK Auth saved token owner rejected"));
                }
            }
        }
        Ok(())
    }
    pub(crate) fn sdk_auth_descriptor(&self, name: &str, version: &str) -> Option<Descriptor> {
        self.sdk_auth_catalog.as_ref()?.get(name, version).cloned()
    }
    pub(crate) fn sdk_auth_descriptors(&self) -> Vec<Descriptor> {
        self.sdk_auth_catalog
            .as_ref()
            .map_or_else(Vec::new, |catalog| catalog.entries().cloned().collect())
    }
    pub(crate) fn register_sdk_auth_descriptor(
        &mut self,
        descriptor: Descriptor,
    ) -> Result<Descriptor, AuthError> {
        if self.plugin_auth_mounts.values().any(|mounts| {
            mounts.values().any(|config| {
                config.sdk.as_ref().is_some_and(|owner| {
                    owner.descriptor.name == descriptor.name
                        && owner.descriptor.version == descriptor.version
                })
            })
        }) {
            return Err(err(409, "mounted SDK Auth descriptor cannot be replaced"));
        }
        self.sdk_auth_catalog
            .get_or_insert_with(Catalog::default)
            .register(descriptor)
            .map_err(|e| err(e.status, &e.message))
    }
    pub(crate) fn deregister_sdk_auth_descriptor(
        &mut self,
        name: &str,
        version: &str,
    ) -> Result<bool, AuthError> {
        if self.plugin_auth_mounts.values().any(|mounts| {
            mounts.values().any(|config| {
                config.sdk.as_ref().is_some_and(|owner| {
                    owner.descriptor.name == name && owner.descriptor.version == version
                })
            })
        }) {
            return Err(err(409, "mounted SDK Auth descriptor cannot be removed"));
        }
        match self.sdk_auth_catalog.as_mut() {
            None => Ok(false),
            Some(catalog) => catalog
                .retire_auth_generation(name, version)
                .map_err(|error| err(error.status, &error.message)),
        }
    }
    pub(crate) fn sdk_auth_owned_mount(&self, namespace: &str, mount: &str) -> bool {
        self.plugin_auth_mounts
            .get(namespace)
            .and_then(|mounts| mounts.get(mount))
            .is_some_and(|config| config.sdk.is_some())
    }
    pub(crate) fn sdk_auth_binding(
        &self,
        namespace: &str,
        path: &str,
    ) -> Result<Option<Binding>, AuthError> {
        let Some(path) = path.strip_prefix("auth/") else {
            return Ok(None);
        };
        let Some(mounts) = self.plugin_auth_mounts.get(namespace) else {
            return Ok(None);
        };
        let Some((name, config)) = mounts
            .iter()
            .filter(|(mount, _)| path.starts_with(&format!("{mount}/")))
            .max_by_key(|(mount, _)| mount.len())
        else {
            return Ok(None);
        };
        let Some(sdk) = config.sdk.as_ref() else {
            return Ok(None);
        };
        let binding = Binding {
            namespace: namespace.into(),
            mount: name.clone(),
            descriptor: sdk.descriptor.clone(),
            owner: sdk.mount.clone(),
        };
        self.sdk_auth_owner_gate(&binding)?;
        Ok(Some(binding))
    }
    pub(crate) fn bind_sdk_auth_mount(
        &mut self,
        namespace: &str,
        mount: &str,
        descriptor: &Descriptor,
    ) -> Result<Binding, AuthError> {
        if self
            .sdk_auth_descriptor(&descriptor.name, &descriptor.version)
            .as_ref()
            != Some(descriptor)
        {
            return Err(err(503, "SDK Auth descriptor changed before mount"));
        }
        let owner = self
            .effective_auth_mounts(namespace)
            .get(mount)
            .cloned()
            .filter(|m| m.kind == "plugin" && m.accessor.is_some())
            .ok_or_else(|| err(503, "SDK Auth original mount unavailable"))?;
        let config = PluginAuthMount {
            sdk: Some(Mount {
                descriptor: descriptor.clone(),
                mount: owner.clone(),
                special_paths: None,
                storage: BTreeMap::new(),
            }),
            plugin_id: descriptor.name.clone(),
            policies: BTreeSet::new(),
            token_ttl: 0,
            token_max_ttl: 0,
            token_num_uses: 0,
        };
        if self
            .plugin_auth_mounts
            .get(namespace)
            .is_some_and(|mounts| mounts.contains_key(mount))
        {
            return Err(err(409, "SDK Auth mount configuration already exists"));
        }
        self.plugin_auth_mounts
            .entry(namespace.into())
            .or_default()
            .insert(mount.into(), config);
        Ok(Binding {
            namespace: namespace.into(),
            mount: mount.into(),
            descriptor: descriptor.clone(),
            owner,
        })
    }
    pub(crate) fn sdk_auth_owner_gate(&self, binding: &Binding) -> Result<(), AuthError> {
        let config = self
            .plugin_auth_mounts
            .get(&binding.namespace)
            .and_then(|mounts| mounts.get(&binding.mount))
            .ok_or_else(|| err(503, "SDK Auth owner absent"))?;
        let sdk = config
            .sdk
            .as_ref()
            .ok_or_else(|| err(503, "SDK Auth typed owner absent"))?;
        sdk.validate_local(
            self.effective_auth_mounts(&binding.namespace)
                .get(&binding.mount),
        )?;
        if sdk.descriptor != binding.descriptor
            || sdk.mount != binding.owner
            || self
                .sdk_auth_descriptor(&binding.descriptor.name, &binding.descriptor.version)
                .as_ref()
                != Some(&binding.descriptor)
        {
            return Err(err(503, "SDK Auth actual owner differs from admission"));
        }
        Ok(())
    }
    pub(crate) fn sdk_auth_storage_witness(
        &self,
        binding: &Binding,
    ) -> Result<StorageWitness, AuthError> {
        self.sdk_auth_owner_gate(binding)?;
        Ok(StorageWitness {
            mount: self.plugin_auth_mounts[&binding.namespace][&binding.mount]
                .sdk
                .as_ref()
                .ok_or_else(|| err(503, "SDK Auth Storage owner absent"))?
                .clone(),
        })
    }

    /// Merge only the plugin's owned cells into current Auth. The original
    /// transaction's tokens, ACLs, clocks and other mounts never become current.
    pub(crate) fn merge_sdk_auth_storage(
        &mut self,
        binding: &Binding,
        original: &StorageWitness,
        working: &AuthState,
    ) -> Result<(), AuthError> {
        original.check(self, binding)?;
        working.sdk_auth_owner_gate(binding)?;
        let changed = working.plugin_auth_mounts[&binding.namespace][&binding.mount]
            .sdk
            .as_ref()
            .ok_or_else(|| err(503, "SDK Auth working Storage absent"))?;
        if !original.mount.same_binding(changed) {
            return Err(err(503, "SDK Auth working mount changed"));
        }
        let mut candidate = original.mount.clone();
        candidate.storage = changed.storage.clone();
        candidate.validate_local(Some(&binding.owner))?;
        self.plugin_auth_mounts
            .get_mut(&binding.namespace)
            .and_then(|mounts| mounts.get_mut(&binding.mount))
            .ok_or_else(|| err(503, "SDK Auth current Storage absent"))?
            .sdk = Some(candidate);
        Ok(())
    }

    pub(crate) fn sdk_auth_storage_get(
        &self,
        binding: &Binding,
        key: &str,
    ) -> Result<Option<Entry>, AuthError> {
        self.sdk_auth_owner_gate(binding)?;
        if key.is_empty() || key.len() > 4096 || key.contains('\0') {
            return Err(bad("SDK Auth storage key rejected"));
        }
        let sdk = self.plugin_auth_mounts[&binding.namespace][&binding.mount]
            .sdk
            .as_ref()
            .ok_or_else(|| err(503, "SDK Auth owner absent"))?;
        Ok(sdk.storage.get(key).map(|entry| Entry {
            key: key.into(),
            value: Zeroizing::new(entry.value.clone()),
            seal_wrap: entry.seal_wrap,
        }))
    }
    pub(crate) fn sdk_auth_storage_put(
        &mut self,
        binding: &Binding,
        entry: Entry,
    ) -> Result<(), AuthError> {
        self.sdk_auth_owner_gate(binding)?;
        if entry.key.is_empty()
            || entry.key.len() > 4096
            || entry.key.contains('\0')
            || entry.value.len() > 256 * 1024
        {
            return Err(bad("SDK Auth storage entry rejected"));
        }
        let current = self.plugin_auth_mounts[&binding.namespace][&binding.mount]
            .sdk
            .as_ref()
            .ok_or_else(|| err(503, "SDK Auth owner absent"))?;
        let mut candidate = current.clone();
        candidate.storage.insert(
            entry.key,
            Cell {
                value: entry.value.to_vec(),
                seal_wrap: entry.seal_wrap,
            },
        );
        candidate.validate_local(Some(&binding.owner))?;
        self.plugin_auth_mounts
            .get_mut(&binding.namespace)
            .and_then(|mounts| mounts.get_mut(&binding.mount))
            .ok_or_else(|| err(503, "SDK Auth owner absent"))?
            .sdk = Some(candidate);
        Ok(())
    }
    pub(crate) fn sdk_auth_storage_delete(
        &mut self,
        binding: &Binding,
        key: &str,
    ) -> Result<(), AuthError> {
        self.sdk_auth_owner_gate(binding)?;
        if key.is_empty() || key.len() > 4096 || key.contains('\0') {
            return Err(bad("SDK Auth storage key rejected"));
        }
        self.plugin_auth_mounts
            .get_mut(&binding.namespace)
            .and_then(|mounts| mounts.get_mut(&binding.mount))
            .and_then(|config| config.sdk.as_mut())
            .ok_or_else(|| err(503, "SDK Auth owner absent"))?
            .storage
            .remove(key);
        Ok(())
    }
    pub(crate) fn sdk_auth_storage_list(
        &self,
        binding: &Binding,
        prefix: &str,
        after: &str,
        limit: i64,
    ) -> Result<Vec<String>, AuthError> {
        self.sdk_auth_owner_gate(binding)?;
        if prefix.len() > 4096
            || prefix.contains('\0')
            || after.len() > 4096
            || after.contains('\0')
        {
            return Err(bad("SDK Auth storage list rejected"));
        }
        let sdk = self.plugin_auth_mounts[&binding.namespace][&binding.mount]
            .sdk
            .as_ref()
            .ok_or_else(|| err(503, "SDK Auth owner absent"))?;
        let keys = sdk
            .storage
            .keys()
            .filter_map(|key| {
                let suffix = key.strip_prefix(prefix)?;
                Some(
                    suffix
                        .find('/')
                        .map_or_else(|| suffix.to_owned(), |i| suffix[..=i].into()),
                )
            })
            .filter(|key| after.is_empty() || key.as_str() > after)
            .collect::<BTreeSet<_>>();
        Ok(keys
            .into_iter()
            .take(if limit <= 0 {
                usize::MAX
            } else {
                usize::try_from(limit).map_err(|_| bad("SDK Auth list limit rejected"))?
            })
            .collect())
    }
}

/// An authenticated issuer owner retained with the native service token. It
/// carries no bearer/Principal and cannot admit a request or authorize Storage.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TokenOrigin {
    binding: Binding,
    lease: token_precision::ServicePrecision,
    maximum: Timestamp,
    metadata: BTreeMap<String, String>,
    internal_data: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    renewal: Option<renewal::RenewalOwner>,
}
impl Drop for TokenOrigin {
    fn drop(&mut self) {
        approle_metadata::erase(&mut self.metadata);
        erase_value(&mut self.internal_data)
    }
}
fn erase_value(value: &mut Value) {
    match value {
        Value::String(v) => v.zeroize(),
        Value::Array(v) => v.iter_mut().for_each(erase_value),
        Value::Object(v) => v.values_mut().for_each(erase_value),
        _ => {}
    }
    *value = Value::Null;
}
impl AuthState {
    pub(super) fn validate_sdk_auth_token_live(
        &self,
        token: &Token,
        time: AuthorityTime,
    ) -> Result<(), AuthError> {
        if let Some(TokenAuthProvenance::Sdk { origin }) = &token.auth_provenance {
            self.sdk_auth_owner_gate(&origin.binding)
                .map_err(|_| denied())?;
            let at = time.exact().ok_or_else(denied)?;
            let at = self.sdk_auth_clock.map_or(at, |floor| floor.max(at));
            if origin.lease.expires_at.is_none_or(|expires| at >= expires) {
                return Err(denied());
            }
        }
        Ok(())
    }
    pub(crate) fn sdk_auth_issued_live(
        &self,
        raw: &str,
        clock: RequestClock,
    ) -> Result<(), AuthError> {
        let at = clock
            .observed_at()
            .map_err(|_| err(503, "SDK Auth original clock unavailable"))?;
        let token = self.active_token_observed(&hash(raw), AuthorityTime::Precise(at), false)?;
        if !matches!(token.auth_provenance, Some(TokenAuthProvenance::Sdk { .. })) {
            return Err(denied());
        }
        Ok(())
    }
    pub(crate) fn finish_sdk_auth_login(
        &mut self,
        binding: &Binding,
        path: &str,
        value: &Value,
        clock: RequestClock,
    ) -> Result<AuthResponse, AuthError> {
        self.sdk_auth_owner_gate(binding)?;
        let object = value
            .as_object()
            .ok_or_else(|| bad("SDK Auth response requires object"))?;
        let renewable = object.get("renewable").map_or(Ok(false), |v| {
            v.as_bool()
                .ok_or_else(|| bad("SDK renewable requires bool"))
        })?;
        let unsupported = object
            .get("period")
            .is_some_and(|v| v.as_i64().unwrap_or(-1) != 0)
            || object
                .get("explicit_max_ttl")
                .is_some_and(|v| v.as_i64().unwrap_or(-1) != 0)
            || object
                .get("token_type")
                .is_some_and(|v| !matches!(v.as_u64(), Some(0 | 1)))
            || object
                .get("group_aliases")
                .is_some_and(|v| !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty()))
            || object
                .get("bound_cidrs")
                .is_some_and(|v| !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty()));
        if unsupported {
            return Err(err(
                501,
                "SDK Auth period, batch, group and CIDR responses are not implemented",
            ));
        }
        let alias = object
            .get("alias")
            .and_then(|v| v.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| bad("SDK Auth alias required"))?;
        if alias.is_empty() || alias.len() > 1024 || alias.chars().any(char::is_control) {
            return Err(denied());
        }
        let mut policies = BTreeSet::new();
        for key in ["policies", "token_policies"] {
            if let Some(value) = object.get(key).filter(|v| !v.is_null()) {
                let values = value
                    .as_array()
                    .ok_or_else(|| bad("SDK Auth policies require strings"))?;
                if values.len() > 128 {
                    return Err(bad("SDK Auth policy bound exceeded"));
                }
                for name in values {
                    let name = name
                        .as_str()
                        .filter(|v| valid_name(v))
                        .ok_or_else(|| bad("SDK Auth policy rejected"))?;
                    policies.insert(name.to_owned());
                }
            }
        }
        if !object
            .get("no_default_policy")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            policies.insert("default".into());
        }
        if policies.contains("root") {
            return Err(denied());
        }
        let ttl = sdk_natural(object, "lease")?;
        let max = sdk_natural(object, "max_ttl")?;
        let (default, mount_max) = self.auth_mount_lease_defaults(AuthScope {
            namespace: &binding.namespace,
            mount: &binding.mount,
        })?;
        let ttl = if ttl == 0 {
            token_precision::DurationNanos::from_seconds(default)
        } else {
            token_precision::DurationNanos::checked(ttl)
        }
        .map_err(|_| bad("SDK Auth TTL rejected"))?;
        let mount_max = token_precision::DurationNanos::from_seconds(mount_max)
            .map_err(|_| bad("SDK Auth maximum rejected"))?;
        let max = if max == 0 {
            mount_max
        } else {
            token_precision::DurationNanos::checked(max)
                .map_err(|_| bad("SDK Auth maximum rejected"))?
                .min(mount_max)
        };
        let ttl = ttl.min(max);
        if ttl.is_zero() {
            return Err(bad("SDK Auth positive lease required"));
        }
        let uses = sdk_natural(object, "num_uses")?;
        let metadata = match object.get("metadata").filter(|v| !v.is_null()) {
            None => BTreeMap::new(),
            Some(v) => serde_json::from_value::<BTreeMap<String, String>>(v.clone())
                .map_err(|_| bad("SDK Auth metadata rejected"))?,
        };
        if !crate::login_metadata::within_limit(&metadata) {
            return Err(err(413, "SDK Auth metadata exceeds bound"));
        }
        let internal_data = object.get("internal_data").cloned().unwrap_or(Value::Null);
        if serde_json::to_vec(&internal_data)
            .map_err(|_| bad("SDK Auth internal data rejected"))?
            .len()
            > 256 * 1024
        {
            return Err(err(413, "SDK Auth internal data exceeds bound"));
        }
        let at = clock
            .observed_at()
            .map_err(|_| err(503, "SDK Auth original clock unavailable"))?;
        let at = self.sdk_auth_clock.map_or(at, |floor| at.max(floor));
        let at = self
            .token_api_observed_time(AuthorityTime::Precise(at))
            .exact()
            .ok_or_else(|| err(503, "SDK Auth precise observation absent"))?;
        let end = at
            .checked_add(ttl)
            .map_err(|_| bad("SDK Auth expiry overflow"))?;
        let maximum = at
            .checked_add(max)
            .map_err(|_| bad("SDK Auth maximum overflow"))?;
        let now = at.seconds();
        let mut token = login_token(
            &binding.namespace,
            policies,
            ttl.ceil_seconds(),
            max.ceil_seconds(),
            uses,
            format!("plugin-{}", binding.descriptor.name),
            now,
        )?;
        token.auth_mount = Some(binding.mount.clone());
        token.renewable = renewable;
        token.expires_at = Some(
            end.ceil_seconds()
                .map_err(|_| bad("SDK Auth expiry projection"))?,
        );
        token.max_expires_at = Some(
            maximum
                .ceil_seconds()
                .map_err(|_| bad("SDK Auth maximum projection"))?,
        );
        let lease = token_precision::ServicePrecision {
            issued_at: at,
            grant_started_at: at,
            expires_at: Some(end),
            last_renewed_at: None,
            previous_grant: ttl,
            creation_grant: ttl,
            requested_period: token_precision::DurationNanos::checked(0)
                .map_err(|_| bad("SDK Auth period"))?,
            requested_explicit_max: token_precision::DurationNanos::checked(0)
                .map_err(|_| bad("SDK Auth maximum"))?,
        };
        token.auth_provenance = Some(TokenAuthProvenance::Sdk {
            origin: Box::new(TokenOrigin {
                binding: binding.clone(),
                lease,
                maximum,
                metadata: metadata.clone(),
                internal_data,
                renewal: if renewable {
                    Some(renewal::RenewalOwner::new(path)?)
                } else {
                    None
                },
            }),
        });
        let (id, token, mut response) = Self::prepare_issue(token, now)?;
        response.body["auth"]["lease_duration"] = json!(ttl.public_seconds());
        response.body["auth"]["metadata"] = json!(metadata);
        response.login_identity = Some(LoginIdentity {
            token_api_alias: false,
            metadata: None,
            mount: binding.mount.clone(),
            alias: alias.into(),
        });
        self.observe_sdk_auth_clock(at);
        self.store_token(id, token);
        Ok(response)
    }
}

fn sdk_natural(object: &serde_json::Map<String, Value>, name: &str) -> Result<u64, AuthError> {
    match object.get(name) {
        None => Ok(0),
        Some(value) => value
            .as_u64()
            .ok_or_else(|| bad("SDK Auth nonnegative integer field required")),
    }
}
#[cfg(test)]
mod sdk_auth100_tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn setup() -> Result<(AuthState, Binding, RequestClock), Box<dyn std::error::Error>> {
        let (mut auth, root) = AuthState::bootstrap(100)?;
        let principal = auth.authenticate(&root, 100)?;
        let mounted = auth
            .handle(
                Some(&principal),
                "",
                "POST",
                "sys/auth/sdk",
                &json!({"type":"plugin"}),
                100,
            )?
            .ok_or("native mount")?;
        assert_eq!(mounted.status, 204);
        auth.register_sdk_auth_descriptor(Descriptor {
            name: "auth_probe".into(),
            version: "v0.0.1".into(),
            command: "probe".into(),
            args: vec!["--serve".into()],
            sha256: "a".repeat(64),
            generation: 1,
        })?;
        let descriptor = auth
            .sdk_auth_descriptor("auth_probe", "v0.0.1")
            .ok_or("actual descriptor")?;
        let binding = auth.bind_sdk_auth_mount("", "sdk", &descriptor)?;
        let clock = RequestClock::anchored(
            std::time::Duration::new(100, 100_000_000),
            std::time::Instant::now(),
        )?;
        auth.observe_sdk_auth_clock(clock.observed_at()?);
        auth.validate_sdk_auth_state()?;
        Ok((auth, binding, clock))
    }
    fn issue(
        auth: &mut AuthState,
        binding: &Binding,
        clock: RequestClock,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let response=auth.finish_sdk_auth_login(binding,"login",&json!({"alias":{"name":"alice"},"lease":1_000_000_000u64,"max_ttl":2_000_000_000u64,"num_uses":2,"client_token":"plugin-forged-token","accessor":"plugin-forged-accessor","metadata":{"provider":"actual-SDK270"}}),clock)?;
        let raw = response.body["auth"]["client_token"]
            .as_str()
            .ok_or("native token")?
            .to_owned();
        assert!(raw.starts_with("hvs."));
        assert_ne!(raw, "plugin-forged-token");
        assert_ne!(
            response.body["auth"]["accessor"],
            json!("plugin-forged-accessor")
        );
        auth.validate_sdk_auth_state()?;
        Ok(raw)
    }
    #[test]
    fn sdk_auth100_precise_issued_token_expires_on_original_running_clock_without_new_admission()
    -> TestResult {
        let (mut auth, binding, clock) = setup()?;
        let raw = issue(&mut auth, &binding, clock)?;
        auth.sdk_auth_issued_live(&raw, clock)?;
        let remaining = auth.tokens.get(&hash(&raw)).ok_or("token")?.uses_remaining;
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(auth.sdk_auth_issued_live(&raw, clock).is_err());
        assert_eq!(
            auth.tokens
                .get(&hash(&raw))
                .ok_or("retained token")?
                .uses_remaining,
            remaining
        );
        Ok(())
    }
    #[test]
    fn sdk_auth100_saved_owner_clock_and_catalog_epoch_tampering_fail_closed() -> TestResult {
        let (mut auth, binding, clock) = setup()?;
        let raw = issue(&mut auth, &binding, clock)?;
        let original = auth.clone();
        let floor = original.sdk_auth_epoch_floor().ok_or("epoch")?;
        for field in ["floor", "catalog", "native_mount", "generation"] {
            let mut altered = original.clone();
            match field {
                "floor" => altered.sdk_auth_clock = Some(Timestamp::checked(99, 0)?),
                "catalog" => altered.sdk_auth_catalog = None,
                "native_mount" => {
                    if let Some(TokenAuthProvenance::Sdk { origin }) = &mut altered
                        .tokens
                        .get_mut(&hash(&raw))
                        .ok_or("token")?
                        .auth_provenance
                    {
                        origin.binding.owner.revision = 0
                    }
                }
                _ => {
                    if let Some(TokenAuthProvenance::Sdk { origin }) = &mut altered
                        .tokens
                        .get_mut(&hash(&raw))
                        .ok_or("token")?
                        .auth_provenance
                    {
                        origin.binding.descriptor.generation += 1
                    }
                }
            }
            assert!(altered.validate_sdk_auth_state().is_err());
        }
        let mut retired = original.clone();
        retired.plugin_auth_mounts.clear();
        retired.tokens.retain(|_, token| {
            !matches!(token.auth_provenance, Some(TokenAuthProvenance::Sdk { .. }))
        });
        retired.deregister_sdk_auth_descriptor("auth_probe", "v0.0.1")?;
        retired.validate_sdk_auth_epoch_floor(Some(&floor))?;
        retired.validate_sdk_auth_state()?;
        assert!(retired.has_sdk_auth_state());
        assert!(retired.sdk_auth_catalog.is_some());
        assert!(retired.sdk_auth_owner_gate(&binding).is_err());
        Ok(())
    }
    #[test]
    fn sdk_auth100_storage_exact_native_owner_list_and_replacement_are_bound() -> TestResult {
        let (mut auth, binding, _) = setup()?;
        auth.sdk_auth_storage_put(
            &binding,
            Entry {
                key: "nested/item".into(),
                value: Zeroizing::new(b"actual-owner-cell".to_vec()),
                seal_wrap: true,
            },
        )?;
        let reopened: AuthState = serde_json::from_slice(&serde_json::to_vec(&auth)?)?;
        reopened.validate_sdk_auth_state()?;
        assert_eq!(
            reopened
                .sdk_auth_storage_get(&binding, "nested/item")?
                .ok_or("cell")?
                .value
                .as_slice(),
            b"actual-owner-cell"
        );
        let mut foreign = binding.clone();
        foreign.owner.revision += 1;
        assert!(
            reopened
                .sdk_auth_storage_get(&foreign, "nested/item")
                .is_err()
        );
        assert!(
            reopened
                .sdk_auth_storage_list(&foreign, "", "", 10)
                .is_err()
        );
        let mut backwards = reopened.clone();
        backwards.sdk_auth_clock = Some(Timestamp::checked(99, 0)?);
        assert!(backwards.validate_sdk_auth_clock(Some(&reopened)).is_err());
        assert_eq!(
            auth.sdk_auth_storage_get(&binding, "nested/item")?
                .ok_or("retained cell")?
                .value
                .as_slice(),
            b"actual-owner-cell"
        );
        Ok(())
    }
    #[test]
    fn sdk_auth100_absent_legacy_fields_remain_absent_and_invalid_duration_never_mints_token()
    -> TestResult {
        let (legacy, _) = AuthState::bootstrap(100)?;
        let bytes = serde_json::to_vec(&legacy)?;
        let value: Value = serde_json::from_slice(&bytes)?;
        assert!(value.get("sdk_auth_catalog").is_none());
        assert!(value.get("sdk_auth_clock").is_none());
        let (mut auth, binding, clock) = setup()?;
        let before = auth.tokens.len();
        for field in ["lease", "max_ttl", "num_uses"] {
            let mut value = json!({"alias":{"name":"alice"},"lease":1_000_000_000u64,"max_ttl":2_000_000_000u64,"num_uses":2});
            value[field] = json!(-1);
            assert!(
                auth.finish_sdk_auth_login(&binding, "login", &value, clock)
                    .is_err()
            );
            assert_eq!(auth.tokens.len(), before);
        }
        Ok(())
    }
    fn renewable_issue(
        auth: &mut AuthState,
        binding: &Binding,
        clock: RequestClock,
        ttl: u64,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let response=auth.finish_sdk_auth_login(binding,"login",&json!({"alias":{"name":"alice"},"lease":ttl,"max_ttl":120_000_000_000u64,"renewable":true,"num_uses":2,"internal_data":{"count":0},"metadata":{"provider":"actual-sdk-renewal270"}}),clock)?;
        Ok(response.body["auth"]["client_token"]
            .as_str()
            .ok_or("native bearer")?
            .to_owned())
    }
    #[test]
    fn sdk_auth100_renewal_preserves_native_identity_finite_uses_and_reopens_typed_origin()
    -> TestResult {
        let (mut auth, binding, clock) = setup()?;
        let raw = renewable_issue(&mut auth, &binding, clock, 30_000_000_000)?;
        let actor = auth.authenticate_from_observed(
            &raw,
            AuthorityTime::Precise(clock.observed_at()?),
            None,
        )?;
        let mut target = auth.prepare_sdk_renewal(
            &actor,
            "",
            "auth/token/renew-self",
            &json!({"increment":40}),
            &raw,
            clock,
        )?;
        let (mut input, issue, increment) = target.input(&auth, clock)?;
        assert_eq!(input["client_token"], json!(""));
        assert!(issue > 0);
        assert_eq!(increment, 40_000_000_000);
        let original = auth.tokens[&hash(&raw)].clone();
        input["internal_data"]["count"] = json!(1);
        input["client_token"] = json!("plugin-forged");
        input["accessor"] = json!("plugin-forged");
        input["num_uses"] = json!(999);
        let renewed = auth.finish_sdk_renewal(&target, &input, clock)?;
        assert_eq!(renewed.body["auth"]["client_token"], json!(raw));
        assert_eq!(renewed.body["auth"]["lease_duration"], json!(40));
        let current = &auth.tokens[&hash(&raw)];
        assert_eq!(current.accessor, original.accessor);
        assert_eq!(current.created_at, original.created_at);
        assert_eq!(current.uses_remaining, original.uses_remaining);
        assert_eq!(current.policies, original.policies);
        assert!(auth.sdk_renewal_gate(&target, clock).is_err());
        auth.sdk_renewal_published(&mut target)?;
        auth.sdk_renewal_gate(&target, clock)?;
        auth.validate_sdk_auth_state()?;
        let reopened: AuthState = serde_json::from_slice(&serde_json::to_vec(&auth)?)?;
        reopened.validate_sdk_auth_state()?;
        let (again, _, _) = target.input(&reopened, clock)?;
        assert_eq!(again["internal_data"]["count"], json!(1));
        Ok(())
    }
    #[test]
    fn sdk_auth100_renewal_original_expiry_is_not_extended_by_candidate_grant() -> TestResult {
        let (mut auth, binding, clock) = setup()?;
        let raw = renewable_issue(&mut auth, &binding, clock, 1_000_000_000)?;
        let actor = auth.authenticate_from_observed(
            &raw,
            AuthorityTime::Precise(clock.observed_at()?),
            None,
        )?;
        let mut target = auth.prepare_sdk_renewal(
            &actor,
            "",
            "auth/token/renew-self",
            &json!({"increment":60}),
            &raw,
            clock,
        )?;
        let (input, _, _) = target.input(&auth, clock)?;
        auth.finish_sdk_renewal(&target, &input, clock)?;
        auth.sdk_renewal_published(&mut target)?;
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(auth.sdk_auth_issued_live(&raw, clock).is_ok());
        assert!(auth.sdk_renewal_gate(&target, clock).is_err());
        Ok(())
    }
    #[test]
    fn sdk_auth100_renewal_target_revoke_or_mount_retirement_withholds_callback() -> TestResult {
        let (mut auth, binding, clock) = setup()?;
        let raw = renewable_issue(&mut auth, &binding, clock, 30_000_000_000)?;
        let actor = auth.authenticate_from_observed(
            &raw,
            AuthorityTime::Precise(clock.observed_at()?),
            None,
        )?;
        let target =
            auth.prepare_sdk_renewal(&actor, "", "auth/token/renew-self", &json!({}), &raw, clock)?;
        let mut retired = auth.clone();
        retired.plugin_auth_mounts.clear();
        assert!(target.input(&retired, clock).is_err());
        let mut revoked = auth.clone();
        revoked.revoke(&hash(&raw));
        assert!(target.input(&revoked, clock).is_err());
        let mut altered = auth.clone();
        altered
            .tokens
            .get_mut(&hash(&raw))
            .ok_or("token")?
            .policies
            .insert("root".into());
        assert!(target.input(&altered, clock).is_err());
        Ok(())
    }
}
