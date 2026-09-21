//! KV1's runtime graph belongs to the candidate EngineState. Its serialized
//! owner contains mount metadata only; Service publishes the separate V5 root.
use super::*;
use crate::state_records::{
    AddressKey, Kv1Index, Kv1Key, Kv1Root, Kv1Scope, RecordError, StagedObject,
};
use std::sync::Mutex;

const KEY_PAGE: usize = 256;

enum Pending {
    Ready(Vec<Arc<StagedObject>>),
    Unavailable,
}

pub(super) struct Runtime {
    key: Arc<AddressKey>,
    index: Kv1Index,
    // Bookkeeping only, not logical state. Publication clears exactly this
    // root's objects; readers still own their complete immutable graph.
    pending: Mutex<Pending>,
}

impl Clone for Runtime {
    fn clone(&self) -> Self {
        let pending = match self.pending.lock() {
            Ok(pending) => match &*pending {
                Pending::Ready(objects) => Pending::Ready(objects.clone()),
                Pending::Unavailable => Pending::Unavailable,
            },
            Err(_) => Pending::Unavailable,
        };
        Self {
            key: Arc::clone(&self.key),
            index: self.index.clone(),
            pending: Mutex::new(pending),
        }
    }
}

fn record_error(error_value: RecordError) -> EngineError {
    match error_value {
        RecordError::TooLarge => error(507, "KV1 record capacity exhausted"),
        RecordError::Invalid => bad("invalid KV1 record operation"),
        RecordError::Corrupt | RecordError::Missing => {
            error(503, "KV1 record graph is unavailable")
        }
    }
}

impl Runtime {
    fn new(key: Arc<AddressKey>, index: Kv1Index) -> Self {
        Self {
            key,
            index,
            pending: Mutex::new(Pending::Ready(Vec::new())),
        }
    }

    fn apply(&mut self, key: Kv1Key, value: Option<&[u8]>) -> Result<bool> {
        let edit = self.index.edit(key, value).map_err(record_error)?;
        if !edit.changed {
            return Ok(false);
        }
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| error(503, "KV1 staging metadata is unavailable"))?;
        let Pending::Ready(objects) = &mut *pending else {
            return Err(error(503, "KV1 staging metadata is unavailable"));
        };
        objects.extend(edit.objects);
        self.index = edit.next;
        Ok(true)
    }

    fn shallow(&self, scope: &Kv1Scope, prefix: &str) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .index
                .scan(scope, prefix, after.as_deref(), KEY_PAGE, false)
                .map_err(record_error)?;
            if page.next_after.is_some() && (page.keys.is_empty() || page.next_after == after) {
                return Err(error(503, "KV1 record cursor did not advance"));
            }
            keys.extend(page.keys);
            after = page.next_after;
            if after.is_none() {
                return Ok(keys);
            }
        }
    }

    fn remove_or_move_scope(
        &mut self,
        namespace: &str,
        mount: &str,
        incarnation: u64,
        destination: Option<(&str, u64)>,
    ) -> Result<()> {
        let scope = Kv1Scope::new(namespace, mount, incarnation).map_err(record_error)?;
        let mut after = None;
        loop {
            let page = self
                .index
                .scan(&scope, "", after.as_deref(), KEY_PAGE, true)
                .map_err(record_error)?;
            if page.next_after.is_some() && (page.keys.is_empty() || page.next_after == after) {
                return Err(error(503, "KV1 record cursor did not advance"));
            }
            for path in &page.keys {
                let source =
                    Kv1Key::new(namespace, mount, incarnation, path).map_err(record_error)?;
                if let Some((new_mount, new_incarnation)) = destination {
                    let prior = self.index.clone();
                    let value = prior
                        .get(&source)
                        .ok_or_else(|| error(503, "KV1 move source disappeared"))?;
                    let target = Kv1Key::new(namespace, new_mount, new_incarnation, path)
                        .map_err(record_error)?;
                    if self.index.get(&target).is_some() {
                        return Err(error(503, "KV1 move destination is not empty"));
                    }
                    self.apply(target, Some(value))?;
                }
                self.apply(source, None)?;
            }
            after = page.next_after;
            if after.is_none() {
                return Ok(());
            }
        }
    }
}

impl EngineState {
    pub(crate) fn record_root(&self) -> Option<Kv1Root> {
        self.records.as_ref().map(|runtime| runtime.index.root())
    }
    pub(crate) fn record_address_key(&self) -> Option<Arc<AddressKey>> {
        self.records
            .as_ref()
            .map(|runtime| Arc::clone(&runtime.key))
    }
    pub(crate) fn has_record_kv1(&self) -> bool {
        self.namespaces.values().any(|namespace| {
            namespace
                .mounts
                .values()
                .any(|mount| matches!(mount.backend, Backend::Kv1Records))
        })
    }

    pub(crate) fn visit_record_objects(
        &self,
        mut visitor: impl FnMut(&Arc<StagedObject>) -> std::result::Result<(), RecordError>,
    ) -> Result<()> {
        let runtime = self
            .records
            .as_ref()
            .ok_or_else(|| error(503, "KV1 record root is unavailable"))?;
        runtime
            .index
            .visit_objects(|object| visitor(object))
            .map_err(record_error)
    }

    pub(crate) fn record_objects(&self) -> Result<Vec<Arc<StagedObject>>> {
        let runtime = self
            .records
            .as_ref()
            .ok_or_else(|| error(503, "KV1 record root is unavailable"))?;
        let pending = runtime
            .pending
            .lock()
            .map_err(|_| error(503, "KV1 staging metadata is unavailable"))?;
        match &*pending {
            Pending::Ready(objects) => Ok(objects.clone()),
            Pending::Unavailable => Err(error(503, "KV1 staging metadata is unavailable")),
        }
    }

    pub(crate) fn clear_published_record_objects(&self, expected: &Kv1Root) -> Result<()> {
        let runtime = self
            .records
            .as_ref()
            .ok_or_else(|| error(503, "KV1 record root is unavailable"))?;
        if &runtime.index.root() != expected {
            return Err(error(503, "KV1 publication root changed"));
        }
        let mut pending = runtime
            .pending
            .lock()
            .map_err(|_| error(503, "KV1 staging metadata is unavailable"))?;
        let Pending::Ready(objects) = &mut *pending else {
            return Err(error(503, "KV1 staging metadata is unavailable"));
        };
        objects.clear();
        Ok(())
    }

    pub(crate) fn owner_metadata_shared_with(&self, previous: &Self) -> bool {
        self.lease_clock == previous.lease_clock
            && self.namespaces.len() == previous.namespaces.len()
            && self.namespaces.iter().all(|(name, state)| {
                previous
                    .namespaces
                    .get(name)
                    .is_some_and(|old| Arc::ptr_eq(&state.0, &old.0))
            })
    }

    /// Explicit write-side transition. Reopening legacy bytes never calls this.
    pub(crate) fn migrate_kv1_records(&self, key: Arc<AddressKey>) -> Result<Self> {
        if self.records.is_some() {
            return Err(error(503, "KV1 record root already exists"));
        }
        let mut index = Kv1Index::empty(Arc::clone(&key));
        for (namespace, state) in &self.namespaces {
            for (mount, entry) in &state.mounts {
                match &entry.backend {
                    Backend::Kv1(entries) => {
                        for (path, value) in entries {
                            let bytes = crate::secret_serde::to_vec(
                                value,
                                crate::state_records::MAX_VALUE_BYTES,
                            )
                            .map_err(|_| error(507, "KV1 value exceeds record capacity"))?;
                            let record_key = Kv1Key::new(namespace, mount, entry.incarnation, path)
                                .map_err(record_error)?;
                            index = index
                                .edit(record_key, Some(&bytes))
                                .map_err(record_error)?
                                .next;
                        }
                    }
                    Backend::Kv1Records => {
                        return Err(error(503, "KV1 metadata has no record root"));
                    }
                    _ => {}
                }
            }
        }
        let mut objects = Vec::new();
        index
            .visit_objects(|object| {
                objects.push(Arc::clone(object));
                Ok(())
            })
            .map_err(record_error)?;
        let mut candidate = self.clone();
        for state in candidate.namespaces.values_mut() {
            for mount in state.mounts.values_mut() {
                if matches!(mount.backend, Backend::Kv1(_)) {
                    mount.backend = Backend::Kv1Records;
                }
            }
        }
        candidate.records = Some(Runtime {
            key,
            index,
            pending: Mutex::new(Pending::Ready(objects)),
        });
        candidate.validate_record_registry()?;
        Ok(candidate)
    }

    pub(crate) fn install_record_index(
        &mut self,
        key: Arc<AddressKey>,
        index: Kv1Index,
    ) -> Result<()> {
        if self.records.is_some()
            || self.namespaces.values().any(|namespace| {
                namespace
                    .mounts
                    .values()
                    .any(|mount| matches!(mount.backend, Backend::Kv1(_)))
            })
        {
            return Err(error(503, "mixed legacy and record KV1 state"));
        }
        self.records = Some(Runtime::new(key, index));
        if let Err(error) = self.validate_record_registry() {
            self.records = None;
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn validate_record_mode(&self) -> Result<()> {
        let legacy = self.namespaces.values().any(|namespace| {
            namespace
                .mounts
                .values()
                .any(|mount| matches!(mount.backend, Backend::Kv1(_)))
        });
        if (self.records.is_some() && legacy) || (self.records.is_none() && self.has_record_kv1()) {
            return Err(error(
                503,
                "KV1 record metadata has no matching authenticated root",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_record_registry(&self) -> Result<()> {
        let Some(runtime) = &self.records else {
            return if self.has_record_kv1() {
                Err(error(503, "KV1 record root is absent"))
            } else {
                Ok(())
            };
        };
        if self.namespaces.values().any(|namespace| {
            namespace
                .mounts
                .values()
                .any(|mount| matches!(mount.backend, Backend::Kv1(_)))
        }) {
            return Err(error(503, "mixed legacy and record KV1 state"));
        }
        runtime
            .index
            .visit_keys(|key| {
                let registered = self
                    .namespaces
                    .get(key.namespace())
                    .and_then(|state| state.mounts.get(key.mount()));
                if !registered.is_some_and(|mount| {
                    matches!(mount.backend, Backend::Kv1Records)
                        && mount.incarnation == key.incarnation()
                }) {
                    return Err(RecordError::Corrupt);
                }
                let bytes = runtime.index.get(key).ok_or(RecordError::Corrupt)?;
                let value: SecretJson =
                    serde_json::from_slice(bytes).map_err(|_| RecordError::Corrupt)?;
                if !value.is_object() {
                    return Err(RecordError::Corrupt);
                }
                let canonical =
                    crate::secret_serde::to_vec(&*value, crate::state_records::MAX_VALUE_BYTES)
                        .map_err(|_| RecordError::Corrupt)?;
                if canonical.as_slice() != bytes {
                    return Err(RecordError::Corrupt);
                }
                Ok(())
            })
            .map_err(record_error)
    }

    pub(super) fn read_record_kv1(
        &self,
        namespace: &str,
        mount: &str,
        incarnation: u64,
        method: &str,
        path: &str,
    ) -> Result<EngineResponse> {
        let runtime = self
            .records
            .as_ref()
            .ok_or_else(|| error(503, "KV1 record root is unavailable"))?;
        if matches!(method, "LIST" | "SCAN") {
            if !path.is_empty() {
                valid_path(path.trim_end_matches('/'))?;
            }
            let scope = Kv1Scope::new(namespace, mount, incarnation).map_err(record_error)?;
            let keys = if method == "LIST" {
                runtime.shallow(&scope, path)?
            } else {
                // Match OpenBao ScanView: leaves first, child directories LIFO.
                let prefix = if path.is_empty() {
                    String::new()
                } else {
                    format!("{}/", path.trim_end_matches('/'))
                };
                let mut frontier = vec![String::new()];
                let mut keys = Vec::new();
                while let Some(directory) = frontier.pop() {
                    for child in runtime.shallow(&scope, &format!("{prefix}{directory}"))? {
                        let relative = format!("{directory}{child}");
                        if child.ends_with('/') {
                            frontier.push(relative);
                        } else {
                            keys.push(relative);
                        }
                    }
                }
                keys
            };
            return if keys.is_empty() {
                if method == "SCAN" {
                    Ok(ok(json!({}), false))
                } else {
                    Err(not_found())
                }
            } else {
                Ok(ok(json!({"keys":keys}), false))
            };
        }
        valid_path(path)?;
        if method != "GET" {
            return Err(unsupported());
        }
        let key = Kv1Key::new(namespace, mount, incarnation, path).map_err(record_error)?;
        let bytes = runtime.index.get(&key).ok_or_else(not_found)?;
        let value: SecretJson =
            serde_json::from_slice(bytes).map_err(|_| error(503, "KV1 record JSON is invalid"))?;
        if !value.is_object() {
            return Err(error(503, "KV1 record JSON is not an object"));
        }
        Ok(ok(value.0.clone(), false))
    }

    pub(super) fn record_kv1_exists(
        &self,
        namespace: &str,
        mount: &str,
        incarnation: u64,
        path: &str,
    ) -> Option<bool> {
        let key = Kv1Key::new(namespace, mount, incarnation, path).ok()?;
        Some(self.records.as_ref()?.index.get(&key).is_some())
    }

    pub(super) fn handle_record_kv1(
        &mut self,
        namespace: &str,
        mount: &str,
        incarnation: u64,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<EngineResponse> {
        if matches!(method, "GET" | "LIST" | "SCAN") {
            return self.read_record_kv1(namespace, mount, incarnation, method, path);
        }
        valid_path(path)?;
        let key = Kv1Key::new(namespace, mount, incarnation, path).map_err(record_error)?;
        let runtime = self
            .records
            .as_mut()
            .ok_or_else(|| error(503, "KV1 record root is unavailable"))?;
        let changed = match method {
            "POST" | "PUT" => {
                if !body.is_object() {
                    return Err(bad("secret data must be an object"));
                }
                let bytes =
                    crate::secret_serde::to_vec(body, crate::state_records::MAX_VALUE_BYTES)
                        .map_err(|_| error(507, "KV1 value exceeds record capacity"))?;
                runtime.apply(key, Some(&bytes))?
            }
            "DELETE" => runtime.apply(key, None)?,
            _ => return Err(unsupported()),
        };
        Ok(empty(changed))
    }

    pub(super) fn update_record_registry(
        &mut self,
        namespace: &str,
        candidate: &mut CowNamespace,
    ) -> Result<()> {
        let Some(current) = &self.records else {
            return Ok(());
        };
        let mut next = current.clone();
        if let Some(previous) = self.namespaces.get(namespace) {
            for (name, mount) in &previous.mounts {
                if matches!(mount.backend, Backend::Kv1Records)
                    && !candidate.mounts.get(name).is_some_and(|next| {
                        matches!(next.backend, Backend::Kv1Records)
                            && next.incarnation == mount.incarnation
                    })
                {
                    next.remove_or_move_scope(namespace, name, mount.incarnation, None)?;
                }
            }
        }
        for mount in candidate.mounts.values_mut() {
            if let Backend::Kv1(entries) = &mount.backend {
                if !entries.is_empty() {
                    return Err(error(503, "new record mount has legacy values"));
                }
                mount.backend = Backend::Kv1Records;
            }
        }
        self.records = Some(next);
        Ok(())
    }

    pub(super) fn remount_record_kv1(
        &mut self,
        namespace: &str,
        from: &str,
        old_incarnation: u64,
        to: &str,
        new_incarnation: u64,
    ) -> Result<()> {
        let mut next = self
            .records
            .as_ref()
            .ok_or_else(|| error(503, "KV1 record root is unavailable"))?
            .clone();
        next.remove_or_move_scope(
            namespace,
            from,
            old_incarnation,
            Some((to, new_incarnation)),
        )?;
        self.records = Some(next);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    fn call(state: &mut EngineState, method: &str, path: &str, body: Value) -> EngineResponse {
        state
            .handle("", method, path, &body, 100)
            .expect("engine request")
            .expect("owned route")
    }
    fn populated() -> EngineState {
        let mut state = EngineState::default();
        call(
            &mut state,
            "POST",
            "sys/mounts/raw",
            json!({"type":"kv","options":{"version":"1"}}),
        );
        for path in [
            "a",
            "a/b",
            "a/c/d",
            "false",
            "m/x",
            "m/y/z",
            "pure/leaf",
            "true",
            "z",
        ] {
            call(
                &mut state,
                "PUT",
                &format!("raw/{path}"),
                json!({"value":path}),
            );
        }
        state
    }
    #[test]
    fn migration_preserves_reads_scan_order_and_candidate_isolation() {
        let mut legacy = populated();
        let legacy_bytes = serde_json::to_vec(&legacy).unwrap();
        let mut records = legacy
            .migrate_kv1_records(AddressKey::from_bytes([7; 32]))
            .unwrap();
        for method in ["LIST", "SCAN"] {
            for path in ["raw/", "raw/a", "raw/a/", "raw/pure/"] {
                assert_eq!(
                    call(&mut records, method, path, json!({})).body,
                    call(&mut legacy, method, path, json!({})).body
                );
            }
        }
        let metadata = serde_json::to_vec(&records).unwrap();
        let root = records.record_root().unwrap();
        records.clear_published_record_objects(&root).unwrap();
        let mut candidate = records.clone();
        call(&mut candidate, "PUT", "raw/a", json!({"value":"changed"}));
        assert_eq!(
            call(&mut records, "GET", "raw/a", json!({})).body["data"]["value"],
            "a"
        );
        assert_eq!(
            call(&mut candidate, "GET", "raw/a", json!({})).body["data"]["value"],
            "changed"
        );
        assert_eq!(serde_json::to_vec(&candidate).unwrap(), metadata);
        assert!(candidate.owner_metadata_shared_with(&records));
        assert!(records.record_objects().unwrap().is_empty());
        assert!(!candidate.record_objects().unwrap().is_empty());
        assert!(candidate.clear_published_record_objects(&root).is_err());
        assert_eq!(serde_json::to_vec(&legacy).unwrap(), legacy_bytes);
        let objects = candidate.record_objects().unwrap().len();
        assert!(!call(&mut candidate, "PUT", "raw/a", json!({"value":"changed"})).mutated);
        assert_eq!(candidate.record_objects().unwrap().len(), objects);
    }
    #[test]
    fn metadata_without_authenticated_graph_is_not_readable_and_disable_drops_scope() {
        let legacy = populated();
        let mut records = legacy
            .migrate_kv1_records(AddressKey::from_bytes([9; 32]))
            .unwrap();
        let bytes = serde_json::to_vec(&records).unwrap();
        let mut missing: EngineState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            missing
                .handle("", "GET", "raw/a", &json!({}), 100)
                .unwrap_err()
                .status,
            503
        );
        call(&mut records, "DELETE", "sys/mounts/raw", json!({}));
        call(
            &mut records,
            "POST",
            "sys/mounts/raw",
            json!({"type":"kv","options":{"version":"1"}}),
        );
        assert_eq!(
            records
                .handle("", "GET", "raw/a", &json!({}), 100)
                .unwrap_err()
                .status,
            404
        );
        records.validate_record_registry().unwrap();
        assert_eq!(records.record_root().unwrap().reference, None);
    }
    #[test]
    fn object_reopen_validates_scope_and_rejects_missing_graph() {
        struct Reader(BTreeMap<crate::state_records::ObjectId, Arc<StagedObject>>);
        impl crate::state_records::RecordReader for Reader {
            fn read_object(
                &self,
                reference: &crate::state_records::ObjectRef,
            ) -> std::result::Result<zeroize::Zeroizing<Vec<u8>>, RecordError> {
                let object = self.0.get(&reference.id).ok_or(RecordError::Missing)?;
                Ok(zeroize::Zeroizing::new(object.bytes().to_vec()))
            }
        }
        let records = populated()
            .migrate_kv1_records(AddressKey::from_bytes([3; 32]))
            .unwrap();
        let key = records.record_address_key().unwrap();
        let root = records.record_root().unwrap();
        let objects = records.record_objects().unwrap();
        let reader = Reader(
            objects
                .iter()
                .map(|o| (o.reference().id, Arc::clone(o)))
                .collect(),
        );
        let reopened = Kv1Index::open(Arc::clone(&key), root.clone(), &reader).unwrap();
        let mut metadata: EngineState =
            serde_json::from_slice(&serde_json::to_vec(&records).unwrap()).unwrap();
        metadata
            .install_record_index(Arc::clone(&key), reopened)
            .unwrap();
        assert_eq!(
            call(&mut metadata, "GET", "raw/a", json!({})).body["data"]["value"],
            "a"
        );
        assert!(Kv1Index::open(key, root, &Reader(BTreeMap::new())).is_err());
    }
}
