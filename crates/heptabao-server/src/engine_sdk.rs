//! SDK catalog metadata and opaque Storage entries share the existing record
//! owner. No callback writes a separate DurableService namespace.
use super::*;
use crate::state_records::{Kv1Key, Kv1Scope, RecordError};
#[derive(Clone)]
pub(crate) struct StorageEntry {
    pub key: String,
    pub value: zeroize::Zeroizing<Vec<u8>>,
    pub seal_wrap: bool,
}
impl std::fmt::Debug for StorageEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SDK StorageEntry([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Descriptor {
    pub name: String,
    pub version: String,
    pub command: String,
    pub args: Vec<String>,
    pub sha256: String,
    pub generation: u64,
}
impl Descriptor {
    pub(crate) fn validate(&self) -> Result<()> {
        heptabao_domain::Id::parse(self.name.clone())
            .map_err(|_| bad("invalid SDK plugin name"))?;
        if self.command.is_empty()
            || self.command.len() > 255
            || self.command.contains('/')
            || self.command == "."
            || self.command == ".."
            || self.command.contains('\0')
        {
            return Err(bad("SDK plugin command requires a bounded file name"));
        }
        if self.version.len() > 128
            || self
                .version
                .bytes()
                .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')))
        {
            return Err(bad("invalid SDK plugin version"));
        }
        if self.sha256.len() != 64
            || self
                .sha256
                .bytes()
                .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
            || self.generation == 0
            || self.args.len() > 64
            || self.args.iter().any(|s| s.len() > 4096 || s.contains('\0'))
        {
            return Err(bad("invalid SDK plugin descriptor"));
        }
        Ok(())
    }
    fn key(&self) -> String {
        catalog_key(&self.name, &self.version)
    }
}
fn catalog_key(name: &str, version: &str) -> String {
    format!("{name}@{version}")
}

#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Catalog {
    entries: BTreeMap<String, Descriptor>,
    /// Registration incarnation survives deregistration of its descriptor.
    epochs: BTreeMap<String, u64>,
}
impl Catalog {
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.epochs.is_empty()
    }
    pub(crate) fn get(&self, name: &str, version: &str) -> Option<&Descriptor> {
        self.entries.get(&catalog_key(name, version))
    }
    pub(crate) fn entries(&self) -> impl Iterator<Item = &Descriptor> {
        self.entries.values()
    }
    pub(crate) fn register(&mut self, mut descriptor: Descriptor) -> Result<Descriptor> {
        if self.epochs.len() >= 128 && !self.epochs.contains_key(&descriptor.key()) {
            return Err(error(507, "SDK catalog capacity exhausted"));
        }
        let generation = self
            .epochs
            .get(&descriptor.key())
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| error(507, "SDK catalog generation exhausted"))?;
        descriptor.generation = generation;
        descriptor.validate()?;
        self.epochs.insert(descriptor.key(), generation);
        self.entries.insert(descriptor.key(), descriptor.clone());
        Ok(descriptor)
    }
    pub(crate) fn remove(&mut self, name: &str, version: &str) -> bool {
        self.entries.remove(&catalog_key(name, version)).is_some()
    }
    fn validate(&self) -> Result<()> {
        if self.entries.len() > 128 || self.epochs.len() > 128 {
            return Err(error(503, "SDK catalog exceeds bound"));
        }
        for (key, descriptor) in &self.entries {
            descriptor.validate()?;
            if descriptor.key() != *key
                || self.epochs.get(key).copied() != Some(descriptor.generation)
            {
                return Err(error(503, "SDK catalog incarnation rejected"));
            }
        }
        for (key, epoch) in &self.epochs {
            let Some((name, version)) = key.split_once('@') else {
                return Err(error(503, "SDK catalog key rejected"));
            };
            if *epoch == 0
                || heptabao_domain::Id::parse(name.to_owned()).is_err()
                || version.len() > 128
                || version
                    .bytes()
                    .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')))
                || catalog_key(name, version) != *key
            {
                return Err(error(503, "SDK catalog retirement rejected"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MountOwner {
    pub plugin: String,
    pub version: String,
    pub catalog_generation: u64,
    pub mount_incarnation: u64,
}

impl EngineState {
    pub(crate) fn has_sdk_state(&self) -> bool {
        !self.sdk_catalog.is_empty() || self.namespaces.values().any(|ns| !ns.sdk_owners.is_empty())
    }
    pub(crate) fn sdk_descriptor(&self, name: &str, version: &str) -> Option<Descriptor> {
        self.sdk_catalog.get(name, version).cloned()
    }
    pub(crate) fn sdk_descriptors(&self) -> Vec<Descriptor> {
        self.sdk_catalog.entries().cloned().collect()
    }
    pub(crate) fn register_sdk_descriptor(&mut self, descriptor: Descriptor) -> Result<Descriptor> {
        if self.sdk_descriptor_is_mounted(&descriptor.name, &descriptor.version) {
            return Err(error(
                409,
                "mounted SDK descriptor must be unmounted before replacement",
            ));
        }
        self.sdk_catalog.register(descriptor)
    }
    pub(crate) fn deregister_sdk_descriptor(&mut self, name: &str, version: &str) -> Result<bool> {
        if self.sdk_descriptor_is_mounted(name, version) {
            return Err(error(409, "mounted SDK descriptor cannot be removed"));
        }
        Ok(self.sdk_catalog.remove(name, version))
    }
    fn sdk_descriptor_is_mounted(&self, name: &str, version: &str) -> bool {
        self.namespaces.values().any(|ns| {
            ns.sdk_owners
                .values()
                .any(|o| o.plugin == name && o.version == version)
        })
    }
    pub(crate) fn sdk_mount_binding(
        &self,
        namespace: &str,
        path: &str,
    ) -> Option<(String, MountOwner)> {
        let ns = self.namespaces.get(namespace)?;
        ns.sdk_owners
            .iter()
            .filter(|(mount, _)| path.starts_with(mount.as_str()))
            .filter(|(mount, owner)| {
                ns.mounts.get(*mount).is_some_and(|m| {
                    m.incarnation == owner.mount_incarnation
                        && matches!(&m.backend,Backend::PluginSecret(id) if id==&owner.plugin)
                })
            })
            .max_by_key(|(mount, _)| mount.len())
            .map(|(mount, owner)| (mount.clone(), owner.clone()))
    }
    pub(crate) fn bind_sdk_mount(
        &mut self,
        namespace: &str,
        mount: &str,
        descriptor: &Descriptor,
    ) -> Result<MountOwner> {
        if self.sdk_catalog.get(&descriptor.name, &descriptor.version) != Some(descriptor) {
            return Err(error(503, "SDK descriptor changed before mount"));
        }
        let ns = self.namespaces.get_mut(namespace).ok_or_else(not_found)?;
        let current = ns.mounts.get(mount).ok_or_else(not_found)?;
        if !matches!(&current.backend,Backend::PluginSecret(id) if id==&descriptor.name)
            || ns.sdk_owners.contains_key(mount)
        {
            return Err(error(503, "SDK mount binding rejected"));
        }
        let owner = MountOwner {
            plugin: descriptor.name.clone(),
            version: descriptor.version.clone(),
            catalog_generation: descriptor.generation,
            mount_incarnation: current.incarnation,
        };
        ns.sdk_owners.insert(mount.to_owned(), owner.clone());
        Ok(owner)
    }
    pub(crate) fn validate_sdk_state(&self) -> Result<()> {
        self.sdk_catalog.validate()?;
        for ns in self.namespaces.values() {
            for (mount, owner) in &ns.sdk_owners {
                let valid = ns.mounts.get(mount).is_some_and(|m| {
                    m.incarnation == owner.mount_incarnation
                        && matches!(&m.backend,Backend::PluginSecret(id) if id==&owner.plugin)
                });
                let descriptor = self.sdk_catalog.get(&owner.plugin, &owner.version);
                if !valid || descriptor.is_none_or(|d| d.generation != owner.catalog_generation) {
                    return Err(error(503, "SDK mount owner rejected"));
                }
            }
        }
        Ok(())
    }
    pub(crate) fn sdk_storage_get(
        &self,
        namespace: &str,
        mount: &str,
        owner: &MountOwner,
        key: &str,
    ) -> Result<Option<StorageEntry>> {
        self.sdk_owner_gate(namespace, mount, owner)?;
        let key = record_key(namespace, mount, owner, key)?;
        self.records
            .as_ref()
            .ok_or_else(|| error(503, "SDK record root absent"))?
            .index
            .get(&key)
            .map(|bytes| decode_record(owner, key.path(), bytes))
            .transpose()
            .map_err(kv1_records::record_error)
    }
    pub(crate) fn sdk_storage_put(
        &mut self,
        namespace: &str,
        mount: &str,
        owner: &MountOwner,
        entry: StorageEntry,
    ) -> Result<bool> {
        self.sdk_owner_gate(namespace, mount, owner)?;
        if entry.value.len() > 256 * 1024 {
            return Err(bad("SDK storage value exceeds bound"));
        }
        let key = record_key(namespace, mount, owner, &entry.key)?;
        let base64 = base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let value = SecretJson(
            json!({"sdk_storage_v1":{"key":entry.key,"value":base64.encode(entry.value.as_slice()),"seal_wrap":entry.seal_wrap,"catalog_generation":owner.catalog_generation}}),
        );
        let bytes = crate::secret_serde::to_vec(&*value, crate::state_records::MAX_VALUE_BYTES)
            .map_err(|_| error(507, "SDK storage serialization exceeds bound"))?;
        self.records
            .as_mut()
            .ok_or_else(|| error(503, "SDK record root absent"))?
            .apply(key, Some(&bytes))
    }
    pub(crate) fn sdk_storage_delete(
        &mut self,
        namespace: &str,
        mount: &str,
        owner: &MountOwner,
        key: &str,
    ) -> Result<bool> {
        self.sdk_owner_gate(namespace, mount, owner)?;
        let key = record_key(namespace, mount, owner, key)?;
        self.records
            .as_mut()
            .ok_or_else(|| error(503, "SDK record root absent"))?
            .apply(key, None)
    }
    pub(crate) fn sdk_storage_list(
        &self,
        namespace: &str,
        mount: &str,
        owner: &MountOwner,
        prefix: &str,
        after: &str,
        limit: i64,
    ) -> Result<Vec<String>> {
        self.sdk_owner_gate(namespace, mount, owner)?;
        if prefix.len() > 4096
            || prefix.contains('\0')
            || after.len() > 4096
            || after.contains('\0')
        {
            return Err(bad("SDK storage prefix exceeds bound"));
        }
        let runtime = self
            .records
            .as_ref()
            .ok_or_else(|| error(503, "SDK record root absent"))?;
        let scope = Kv1Scope::new(namespace, mount, owner.mount_incarnation)
            .map_err(kv1_records::record_error)?;
        let mut cursor = None;
        let mut names = BTreeSet::new();
        let mut count = 0usize;
        loop {
            crate::engines::kv_versioning::deadline()?;
            let page = runtime
                .index
                .scan(&scope, "sdk92/", cursor.as_deref(), 256, true)
                .map_err(kv1_records::record_error)?;
            if page.next_after.is_some() && (page.keys.is_empty() || page.next_after == cursor) {
                return Err(error(503, "SDK storage cursor did not advance"));
            }
            for path in &page.keys {
                count += 1;
                if count > 10000 {
                    return Err(error(507, "SDK storage listing exceeds bound"));
                }
                let full_path = format!("sdk92/{path}");
                let key = Kv1Key::new(namespace, mount, owner.mount_incarnation, &full_path)
                    .map_err(kv1_records::record_error)?;
                let bytes = runtime
                    .index
                    .get(&key)
                    .ok_or_else(|| error(503, "SDK record missing"))?;
                let entry =
                    decode_record(owner, &full_path, bytes).map_err(kv1_records::record_error)?;
                if let Some(suffix) = entry.key.strip_prefix(prefix) {
                    let name = suffix
                        .find('/')
                        .map_or_else(|| suffix.to_owned(), |i| suffix[..=i].to_owned());
                    if after.is_empty() || name.as_str() > after {
                        names.insert(name);
                    }
                }
            }
            cursor = page.next_after;
            if cursor.is_none() {
                break;
            }
        }
        let n = if limit <= 0 {
            usize::MAX
        } else {
            usize::try_from(limit).map_err(|_| bad("SDK storage page limit"))?
        };
        Ok(names.into_iter().take(n).collect())
    }
    fn sdk_owner_gate(&self, namespace: &str, mount: &str, owner: &MountOwner) -> Result<()> {
        if self
            .sdk_mount_binding(namespace, mount)
            .is_none_or(|(actual, current)| actual != mount || &current != owner)
        {
            return Err(error(503, "SDK storage owner changed"));
        }
        Ok(())
    }
    pub(super) fn validate_sdk_record(
        &self,
        key: &Kv1Key,
        bytes: &[u8],
    ) -> std::result::Result<(), RecordError> {
        let owner = self
            .namespaces
            .get(key.namespace())
            .and_then(|ns| ns.sdk_owners.get(key.mount()))
            .ok_or(RecordError::Corrupt)?;
        if key.incarnation() != owner.mount_incarnation {
            return Err(RecordError::Corrupt);
        }
        decode_record(owner, key.path(), bytes)?;
        Ok(())
    }
}
fn storage_path(key: &str) -> String {
    format!(
        "sdk92/{}",
        crate::crypto::digest(key.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}
fn record_key(namespace: &str, mount: &str, owner: &MountOwner, key: &str) -> Result<Kv1Key> {
    if key.is_empty() || key.len() > 4096 || key.contains('\0') {
        return Err(bad("invalid SDK storage key"));
    }
    Kv1Key::new(
        namespace,
        mount,
        owner.mount_incarnation,
        &storage_path(key),
    )
    .map_err(kv1_records::record_error)
}
fn decode_record(
    owner: &MountOwner,
    path: &str,
    bytes: &[u8],
) -> std::result::Result<StorageEntry, RecordError> {
    use base64::Engine;
    let value: SecretJson = serde_json::from_slice(bytes).map_err(|_| RecordError::Corrupt)?;
    let canonical = crate::secret_serde::to_vec(&*value, crate::state_records::MAX_VALUE_BYTES)
        .map_err(|_| RecordError::Corrupt)?;
    if canonical.as_slice() != bytes {
        return Err(RecordError::Corrupt);
    }
    let outer = value.as_object().ok_or(RecordError::Corrupt)?;
    let object = outer
        .get("sdk_storage_v1")
        .and_then(Value::as_object)
        .ok_or(RecordError::Corrupt)?;
    let key = object
        .get("key")
        .and_then(Value::as_str)
        .ok_or(RecordError::Corrupt)?;
    if outer.len() != 1
        || object.len() != 4
        || key.is_empty()
        || key.len() > 4096
        || key.contains('\0')
        || storage_path(key) != path
        || object.get("catalog_generation").and_then(Value::as_u64)
            != Some(owner.catalog_generation)
    {
        return Err(RecordError::Corrupt);
    }
    let raw = object
        .get("value")
        .and_then(Value::as_str)
        .ok_or(RecordError::Corrupt)?;
    if raw.len() > 350000 {
        return Err(RecordError::Corrupt);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|_| RecordError::Corrupt)?;
    if bytes.len() > 256 * 1024 {
        return Err(RecordError::Corrupt);
    }
    Ok(StorageEntry {
        key: key.to_owned(),
        value: zeroize::Zeroizing::new(bytes),
        seal_wrap: object
            .get("seal_wrap")
            .and_then(Value::as_bool)
            .ok_or(RecordError::Corrupt)?,
    })
}
