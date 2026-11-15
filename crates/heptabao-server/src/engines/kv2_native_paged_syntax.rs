//! Request-owned syntax data only. No reader, fd, callback, validation memo,
//! Actor, seal observation or completed gate can be retained by this type.
use super::*;
use subtle::ConstantTimeEq;

pub(crate) struct PagedSyntaxHint {
    scope: Scope,
    key: Arc<AddressKey>,
    index: Kv1Index,
    paths: BTreeMap<Kv1Key, PathCell<Entry>>,
    descriptors: SharedDescriptors,
    syntax_bytes: usize,
}

pub(super) enum PagedPath<'a> {
    Decoded(Box<PathCell>),
    SameBytes(&'a PathCell<Entry>),
}
impl PagedPath<'_> {
    pub(super) fn fields(&self) -> (&str, &Scope, &str, &EntryState, &BTreeSet<u64>) {
        match self {
            Self::Decoded(cell) => {
                let PathCell {
                    format,
                    scope,
                    path,
                    metadata,
                    payload_versions,
                } = cell.as_ref();
                (format, scope, path, metadata, payload_versions)
            }
            Self::SameBytes(PathCell {
                format,
                scope,
                path,
                metadata,
                payload_versions,
            }) => (format, scope, path, metadata, payload_versions),
        }
    }
    pub(super) fn into_entry(self) -> (String, Entry) {
        match self {
            Self::Decoded(mut cell) => (
                std::mem::take(&mut cell.path),
                Entry::from(std::mem::take(&mut cell.metadata)),
            ),
            Self::SameBytes(cell) => (cell.path.clone(), cell.metadata.clone()),
        }
    }
}

impl PagedSyntaxHint {
    pub(crate) fn budget(&self) -> (usize, usize) {
        (
            self.syntax_bytes,
            1 + self.paths.len() + self.descriptors.values().map(BTreeMap::len).sum::<usize>(),
        )
    }
    pub(super) fn same_graph(&self, scope: &Scope, key: &AddressKey) -> bool {
        self.scope.matches(scope) && bool::from(self.key.expose().ct_eq(key.expose()))
    }
    pub(super) fn path(&self, record: &Kv1Key, bytes: &[u8]) -> Option<&PathCell<Entry>> {
        (self.index.get(record)? == bytes)
            .then(|| self.paths.get(record))
            .flatten()
    }
    pub(super) fn descriptor(
        &self,
        record: &Kv1Key,
        bytes: &[u8],
        path: &str,
        version: u64,
    ) -> Option<&PayloadDescriptor> {
        (self.index.get(record)? == bytes)
            .then(|| self.descriptors.get(path)?.get(&version))
            .flatten()
    }
}

// Exhaustive projections fail compilation if a logical or derived field is
// added. There are no serde(skip) fields: conditional omissions are precisely
// false/zero/None/empty; Timestamp serializes both actual parts. CowValue is
// only Arc<EntryState>; allocation identity is not logical state.
#[cfg(any(test, feature = "native-v6-storage"))]
fn project_entry(entry: &EntryState) {
    let EntryState {
        config,
        current_version: _,
        current_metadata_version: _,
        oldest_version: _,
        created_at: _,
        updated_at: _,
        custom_metadata: _,
        versions,
        precision,
    } = entry;
    let Config {
        max_versions: _,
        cas_required: _,
        metadata_cas_required: _,
        delete_version_after: _,
        delete_version_after_nanos: _,
    } = config;
    let EntryPrecision {
        created_at: _,
        updated_at: _,
        versions: precise,
    } = precision;
    for version in versions.values() {
        let Version {
            created_at: _,
            deletion_at: _,
            destroyed: _,
            data: _,
        } = version;
    }
    for version in precise.values() {
        let VersionPrecision {
            created_at: _,
            deletion_at: _,
            source_deletion_at: _,
        } = version;
    }
}

#[cfg(test)]
#[path = "kv2_native_paged_syntax_tests.rs"]
mod tests;

#[cfg(any(test, feature = "native-v6-storage"))]
impl NativeReadView {
    pub(crate) fn capture_paged_syntax_hint(
        &self,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<Option<PagedSyntaxHint>> {
        check()?;
        let NativeReadView {
            owner,
            graph,
            pending,
        } = self;
        if pending.paths().next().is_some() {
            return Ok(None);
        }
        let Some(NativeGraph {
            scope,
            key,
            index,
            format,
            paged,
        }) = graph
        else {
            return Ok(None);
        };
        let Some(PagedPayloads {
            descriptors,
            new_blocks,
        }) = paged
        else {
            return Ok(None);
        };
        let DetachedOwner(Kv2 {
            config,
            entries,
            lossless_format,
        }) = &**owner;
        if format != PAGED_NATIVE_FORMAT
            || !new_blocks.is_empty()
            || entries.len() > MAX_PATHS
            || validate_owner_structure(owner, true).is_err()
        {
            return Ok(None);
        }
        let mount = MountCell {
            format: PAGED_NATIVE_FORMAT.into(),
            scope: scope.clone(),
            config: config.clone(),
            lossless_format: *lossless_format,
        };
        let config_record = scope.key("config")?;
        let Some(config_bytes) = index.get(&config_record) else {
            return Ok(None);
        };
        if !crate::secret_serde::matches_bytes(&mount, config_bytes, MAX_CONFIG_BYTES)
            .unwrap_or(false)
            || descriptors
                .iter()
                .any(|(path, values)| !entries.contains_key(path) || values.is_empty())
        {
            return Ok(None);
        }
        let mut paths = BTreeMap::new();
        let mut total = config_bytes.len();
        let mut records = 1_usize;
        for (path, entry) in entries {
            check()?;
            project_entry(entry);
            let old_descriptors = descriptors.get(path);
            let cell = PathCell {
                format: PAGED_NATIVE_FORMAT.into(),
                scope: scope.clone(),
                path: path.clone(),
                metadata: entry.clone(),
                payload_versions: old_descriptors
                    .map(|d| d.keys().copied().collect())
                    .unwrap_or_default(),
            };
            let record = metadata_key(scope, key, path)?;
            let Some(bytes) = index.get(&record) else {
                return Ok(None);
            };
            total = total
                .checked_add(bytes.len())
                .ok_or(RecordError::TooLarge)?;
            records = records.checked_add(1).ok_or(RecordError::TooLarge)?;
            if total > MAX_GRAPH_BYTES
                || records > MAX_RECORDS
                || !crate::secret_serde::matches_bytes(&cell, bytes, MAX_METADATA_BYTES)
                    .unwrap_or(false)
            {
                return Ok(None);
            }
            if let Some(old_descriptors) = old_descriptors {
                for (number, descriptor) in old_descriptors {
                    check()?;
                    let PayloadDescriptor {
                        format: _,
                        path_token: _,
                        version: _,
                        logical_bytes: _,
                        digest: _,
                        blocks: _,
                    } = descriptor;
                    let payload = payload_key(scope, key, path, *number)?;
                    let Some(bytes) = index.get(&payload) else {
                        return Ok(None);
                    };
                    total = total
                        .checked_add(bytes.len())
                        .ok_or(RecordError::TooLarge)?;
                    records = records.checked_add(1).ok_or(RecordError::TooLarge)?;
                    if total > MAX_GRAPH_BYTES
                        || records > MAX_RECORDS
                        || !crate::secret_serde::matches_bytes(
                            descriptor,
                            bytes,
                            MAX_DESCRIPTOR_BYTES,
                        )
                        .unwrap_or(false)
                    {
                        return Ok(None);
                    }
                }
            }
            paths.insert(record, cell);
            check()?;
        }
        check()?;
        let mut expected_records = 0_usize;
        index.visit_keys(|_| {
            check()?;
            expected_records = expected_records
                .checked_add(1)
                .ok_or(RecordError::TooLarge)?;
            Ok(())
        })?;
        if expected_records != records {
            return Ok(None);
        }
        Ok(Some(PagedSyntaxHint {
            scope: scope.clone(),
            key: Arc::clone(key),
            index: index.clone(),
            paths,
            descriptors: descriptors.clone(),
            syntax_bytes: total,
        }))
    }
}
