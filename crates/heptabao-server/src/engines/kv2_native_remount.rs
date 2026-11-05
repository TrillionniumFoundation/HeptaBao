//! Readdress a complete authenticated KV2 graph without modifying its source.
//! This codec creates no Actor, source lease, task, or publication authority.
use super::super::import::NativeKv2GraphImport;
use super::*;

struct CheckedReader<'a, R, C> {
    reader: &'a R,
    check: &'a C,
}
impl<R: RecordReader, C: Fn() -> CodecResult<()>> RecordReader for CheckedReader<'_, R, C> {
    fn read_object(&self, reference: &ObjectRef) -> CodecResult<Zeroizing<Vec<u8>>> {
        (self.check)()?;
        let bytes = self.reader.read_object(reference)?;
        (self.check)()?;
        Ok(bytes)
    }
}

impl NativeReadView {
    /// Only a fully committed old cache is eligible. Reopen its complete typed
    /// metadata from the caller's actual source, then authenticate every live
    /// payload while encoding it under the destination scope. At most one
    /// decoded payload is held at a time; the immutable staged objects remain
    /// owned by the affine receipt until the native publication planner takes
    /// them. The old graph and all of its physical objects remain unchanged.
    pub(in crate::engines) fn prepare_graph_readdress(
        &self,
        parent: &AddressKey,
        from: NativeScope<'_>,
        expected: &Kv1Root,
        to: NativeScope<'_>,
        source: &impl RecordReader,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<(Self, Option<NativeKv2GraphImport>)> {
        check()?;
        let old_scope = Scope::new(from)?;
        let next_scope = Scope::new(to)?;
        let cached = self.graph.as_ref().ok_or(RecordError::Missing)?;
        if old_scope.matches(&next_scope)
            || !cached.scope.matches(&old_scope)
            || cached.index.root() != *expected
            || self.pending.paths().next().is_some()
            || cached
                .paged
                .as_ref()
                .is_some_and(|paged| !paged.new_blocks.is_empty())
            || cached.key.expose() != graph_key(parent, &old_scope)?.expose()
        {
            return Err(RecordError::Corrupt);
        }
        let source = CheckedReader {
            reader: source,
            check,
        };
        let fresh = if self.is_paged() {
            Self::open_paged_checked(parent, from, expected.clone(), &source, check)?
        } else {
            if cached.format != FORMAT || cached.paged.is_some() {
                return Err(RecordError::Corrupt);
            }
            let key = graph_key(parent, &old_scope)?;
            let graph = NativeGraph {
                scope: old_scope,
                index: Kv1Index::open(Arc::clone(&key), expected.clone(), &source)?,
                key,
                format: FORMAT.into(),
                paged: None,
            };
            let owner = graph.decode_checked(check)?;
            Self {
                owner: owner.into(),
                graph: Some(graph),
                pending: mutation::PendingPaths::default(),
            }
        };
        // Cached metadata cannot be substituted for the authenticated owner,
        // including config-only edits, destroyed history or an old descriptor.
        // Compare one bounded entry at a time rather than serializing a 34 MiB
        // paged owner through the smaller legacy aggregate decoder.
        if serialize(&self.owner.config, MAX_CONFIG_BYTES)?.as_slice()
            != serialize(&fresh.owner.config, MAX_CONFIG_BYTES)?.as_slice()
            || self.owner.lossless_format != fresh.owner.lossless_format
            || self.owner.entries.len() != fresh.owner.entries.len()
        {
            return Err(RecordError::Corrupt);
        }
        for (path, original) in &self.owner.entries {
            check()?;
            let actual = fresh.owner.entries.get(path).ok_or(RecordError::Corrupt)?;
            let limit = if self.is_paged() {
                MAX_METADATA_BYTES
            } else {
                MAX_GRAPH_BYTES
            };
            if serialize(&**original, limit)?.as_slice() != serialize(&**actual, limit)?.as_slice()
            {
                return Err(RecordError::Corrupt);
            }
        }
        if !self.is_paged() {
            let graph = NativeGraph::encode_checked(&fresh.owner, parent, to, check)?;
            check()?;
            return Ok((
                Self {
                    owner: fresh.owner,
                    graph: Some(graph),
                    pending: mutation::PendingPaths::default(),
                },
                None,
            ));
        }
        let original = fresh.graph.as_ref().ok_or(RecordError::Missing)?;
        let old_payloads = original.paged.as_ref().ok_or(RecordError::Missing)?;
        let cached_payloads = cached.paged.as_ref().ok_or(RecordError::Missing)?;
        if cached_payloads.descriptors != old_payloads.descriptors {
            return Err(RecordError::Corrupt);
        }
        fresh.validate_paged_metadata()?;
        let key = graph_key(parent, &next_scope)?;
        let mut next = NativeGraph {
            scope: next_scope,
            index: Kv1Index::empty(Arc::clone(&key)),
            key,
            format: PAGED_NATIVE_FORMAT.into(),
            paged: Some(PagedPayloads::default()),
        };
        next.update_paged_config(&fresh.owner, check, None)?;
        for (path, entry) in &fresh.owner.entries {
            check()?;
            let metadata = (**entry).clone();
            let mut descriptors = BTreeMap::new();
            for (number, version) in &metadata.versions {
                check()?;
                if version.data.is_some() {
                    return Err(RecordError::Corrupt);
                }
                if version.destroyed {
                    continue;
                }
                let old = old_payloads
                    .descriptors
                    .get(path)
                    .and_then(|versions| versions.get(number))
                    .ok_or(RecordError::Missing)?;
                let data = old.read(&original.key, path, *number, &source, check)?;
                if lossless::needs_lossless_number_format(data.expose())
                    && fresh.owner.lossless_format != Some(1)
                {
                    return Err(RecordError::Corrupt);
                }
                let descriptor = PayloadDescriptor::encode(
                    &next.key,
                    path,
                    *number,
                    &data,
                    &mut next.paged.as_mut().ok_or(RecordError::Missing)?.new_blocks,
                    check,
                )?;
                drop(data);
                let bytes = serialize(&descriptor, MAX_DESCRIPTOR_BYTES)?;
                next.index = next
                    .index
                    .edit(
                        payload_key(&next.scope, &next.key, path, *number)?,
                        Some(&bytes),
                    )?
                    .next;
                descriptors.insert(*number, descriptor);
                check()?;
            }
            let cell = PathCell {
                format: PAGED_NATIVE_FORMAT.into(),
                scope: next.scope.clone(),
                path: path.clone(),
                metadata,
                payload_versions: descriptors.keys().copied().collect(),
            };
            let bytes = serialize(&cell, MAX_METADATA_BYTES)?;
            next.index = next
                .index
                .edit(metadata_key(&next.scope, &next.key, path)?, Some(&bytes))?
                .next;
            if !descriptors.is_empty() {
                next.paged
                    .as_mut()
                    .ok_or(RecordError::Missing)?
                    .descriptors
                    .insert(path.clone(), descriptors);
            }
        }
        let payloads = next.paged.as_ref().ok_or(RecordError::Missing)?;
        payloads.validate(&fresh.owner, &next.key)?;
        if payloads.payload_count() != old_payloads.payload_count()
            || payloads.logical_bytes()? != old_payloads.logical_bytes()?
        {
            return Err(RecordError::Corrupt);
        }
        let graph = NativeCellGraph(next);
        let receipt = NativeKv2GraphImport::from_readdressed_graph(parent, to, &graph, check)?;
        let mut candidate = Self {
            owner: fresh.owner,
            graph: Some(graph.0),
            pending: mutation::PendingPaths::default(),
        };
        candidate
            .graph
            .as_mut()
            .and_then(|graph| graph.paged.as_mut())
            .ok_or(RecordError::Missing)?
            .clear_new_blocks();
        candidate.validate_paged_metadata()?;
        check()?;
        Ok((candidate, Some(receipt)))
    }
}

#[cfg(test)]
#[path = "kv2_native_remount_tests.rs"]
mod tests;
