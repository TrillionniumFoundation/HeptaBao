//! Selected-cell edits on an already authenticated native graph.
//!
//! This is detached graph construction only. Keeping old object identities
//! grants no authority to publish, install a Service owner, or reuse custody.
use super::*;

#[derive(Clone, Default)]
pub(super) struct PendingPaths(Vec<PathBaseline>);

#[derive(Clone)]
struct PathBaseline {
    path: Zeroizing<String>,
    entry: Option<Entry>,
}

impl PendingPaths {
    pub(super) fn capture(&mut self, owner: &Kv2, request: &str) -> Result<Option<usize>> {
        let Some((operation, path)) = request.split_once('/') else {
            return Ok(None);
        };
        if !matches!(
            operation,
            "data" | "metadata" | "delete" | "undelete" | "destroy"
        ) || valid_path(path).is_err()
            || self.0.iter().any(|baseline| baseline.path.as_str() == path)
        {
            return Ok(None);
        }
        if self.0.len() >= MAX_PATHS {
            return Err(error(413, "native KV2 pending path capacity exceeded"));
        }
        let position = self.0.len();
        self.0.push(PathBaseline {
            path: Zeroizing::new(path.to_owned()),
            entry: owner.entries.get(path).cloned(),
        });
        Ok(Some(position))
    }
    pub(super) fn discard(&mut self, captured: Option<usize>) {
        if let Some(position) = captured {
            self.0.remove(position);
        }
    }
}

fn edit(
    index: &mut Kv1Index,
    record: Kv1Key,
    bytes: Option<&[u8]>,
    check: &impl Fn() -> CodecResult<()>,
) -> CodecResult<()> {
    check()?;
    *index = index.edit(record, bytes)?.next;
    check()
}

impl NativeGraph {
    pub(super) fn with_updates(
        &self,
        owner: &Kv2,
        parent: &AddressKey,
        input: NativeScope<'_>,
        pending: &PendingPaths,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<Self> {
        check()?;
        let scope = Scope::new(input)?;
        if !self.scope.matches(&scope) {
            return Err(RecordError::Invalid);
        }
        let expected_key = graph_key(parent, &scope)?;
        // No early-exit comparison of secret address keys. Re-addressing under
        // a new key requires a distinct, explicitly authorized full projection.
        let difference = self
            .key
            .expose()
            .iter()
            .zip(expected_key.expose())
            .fold(0_u8, |difference, (old, new)| difference | (old ^ new));
        if difference != 0 {
            return Err(RecordError::Invalid);
        }
        validate_owner(owner)?;
        check()?;
        let mut next = self.clone();
        let mount = MountCell {
            format: FORMAT.into(),
            scope: self.scope.clone(),
            config: owner.config.clone(),
            lossless_format: owner.lossless_format,
        };
        let bytes = serialize(&mount, MAX_CONFIG_BYTES)?;
        let record = self.scope.key("config")?;
        if next.index.get(&record) != Some(bytes.as_slice()) {
            edit(&mut next.index, record, Some(&bytes), check)?;
        }
        check()?;
        for baseline in &pending.0 {
            check()?;
            let path = baseline.path.as_str();
            let current = owner.entries.get(path);
            if let Some(previous) = &baseline.entry {
                for (number, version) in &previous.versions {
                    check()?;
                    if version.data.is_some()
                        && !current
                            .and_then(|entry| entry.versions.get(number))
                            .is_some_and(|version| version.data.is_some())
                    {
                        let record = payload_key(&self.scope, &self.key, path, *number)?;
                        edit(&mut next.index, record, None, check)?;
                    }
                }
            }
            let record = metadata_key(&self.scope, &self.key, path)?;
            let Some(entry) = current else {
                edit(&mut next.index, record, None, check)?;
                continue;
            };
            let mut cell = PathCell {
                format: FORMAT.into(),
                scope: self.scope.clone(),
                path: path.to_owned(),
                metadata: (**entry).clone(),
                payload_versions: BTreeSet::new(),
            };
            for (number, version) in &mut cell.metadata.versions {
                check()?;
                if let Some(data) = version.data.take() {
                    let previous = baseline
                        .entry
                        .as_ref()
                        .and_then(|entry| entry.versions.get(number))
                        .and_then(|version| version.data.as_ref());
                    let record = payload_key(&self.scope, &self.key, path, *number)?;
                    if previous.is_some_and(|previous| Arc::ptr_eq(&previous.0, &data.0)) {
                        // The baseline belongs to the authenticated cached
                        // graph. Shared JSON proves unchanged payload identity.
                        if next.index.get(&record).is_none() {
                            return Err(RecordError::Corrupt);
                        }
                    } else {
                        let bytes = serialize(&data, MAX_VALUE_BYTES)?;
                        edit(&mut next.index, record, Some(&bytes), check)?;
                    }
                    cell.payload_versions.insert(*number);
                }
                check()?;
            }
            let bytes = serialize(&cell, MAX_METADATA_BYTES)?;
            if next.index.get(&record) != Some(bytes.as_slice()) {
                edit(&mut next.index, record, Some(&bytes), check)?;
            }
            check()?;
        }
        check()?;
        Ok(next)
    }
}
