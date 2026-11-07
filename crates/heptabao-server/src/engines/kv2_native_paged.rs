//! Versioned metadata-only KV2 graph with bounded, independently read payloads.
//! This codec grants no Actor, physical source session, publication or admission.
use super::*;
use crate::state_records::{BLOCK_BYTES, ObjectKind};
use std::cell::RefCell;

#[path = "kv2_native_paged_syntax.rs"]
pub(super) mod syntax;

#[cfg(any(test, feature = "native-v6-storage"))]
#[path = "kv2_native_storage_witness.rs"]
mod storage_witness;

#[cfg(any(test, feature = "native-v6-storage"))]
#[path = "kv2_native_remount.rs"]
mod remount;

#[cfg(feature = "native-v6-storage")]
#[path = "kv2_native_lossless_export.rs"]
pub(crate) mod lossless_export;

#[cfg(feature = "native-v6-storage")]
#[path = "kv2_native_retained_read.rs"]
mod retained_read;
#[cfg(feature = "native-v6-storage")]
pub(crate) use retained_read::{NativeDataReadWitness, NativeRetainedReadVersion};

pub(crate) const PAGED_NATIVE_FORMAT: &str = "heptabao-kv2-native-paged-v2";
pub(crate) const MAX_PAGED_LOGICAL_BYTES: u64 = 1024 * 1024 * 1024;
const PAYLOAD_FORMAT: &str = "heptabao-kv2-native-payload-v2";
const PAYLOAD_DOMAIN: &[u8] = b"kv2-native-v6-paged-v2/payload";
const MAX_DESCRIPTOR_BYTES: usize = 32 * 1024;
const OBJECT_HEADER_BYTES: usize = 25;

// This is a memo of deterministic JSON semantics, never a source or custody
// receipt. Every hit still follows fresh block reads, keyed ObjectRef checks
// and the complete payload digest under the caller's original live gates.
// Its type/domain fixes paged-v2, canonical SharedJson and the lossless-number
// check. The scoped key, path token, version, digest and length fix the input.
const PAYLOAD_VALIDATION_DOMAIN: &[u8] =
    b"heptabao-kv2-native-paged-v2/canonical-shared-json-v1/lossless-number-check-v1";
type PayloadValidationKey = ([u8; 32], u64, [u8; 32], u64);

#[derive(Default)]
pub(crate) struct PagedPayloadValidationMemo {
    needs_lossless: BTreeMap<PayloadValidationKey, bool>,
    #[cfg(test)]
    hits: usize,
}

#[cfg(test)]
impl PagedPayloadValidationMemo {
    pub(crate) fn test_observations(&self) -> (usize, usize) {
        (self.needs_lossless.len(), self.hits)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadDescriptor {
    format: String,
    path_token: String,
    version: u64,
    logical_bytes: u64,
    digest: [u8; 32],
    #[serde(deserialize_with = "bounded_blocks")]
    blocks: Vec<ObjectRef>,
}
fn bounded_blocks<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<Vec<ObjectRef>, D::Error> {
    struct Blocks;
    impl<'de> serde::de::Visitor<'de> for Blocks {
        type Value = Vec<ObjectRef>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded payload block list")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut blocks = Vec::new();
            while let Some(block) = sequence.next_element()? {
                if blocks.len() >= MAX_VALUE_BYTES.div_ceil(BLOCK_BYTES) {
                    return Err(serde::de::Error::custom(
                        "payload block list bound exceeded",
                    ));
                }
                blocks.push(block);
            }
            Ok(blocks)
        }
    }
    decoder.deserialize_seq(Blocks)
}

fn preflight_paged_path(bytes: &[u8]) -> CodecResult<()> {
    #[derive(Deserialize)]
    struct Bounds<'a> {
        #[serde(borrow)]
        metadata: &'a serde_json::value::RawValue,
        #[serde(borrow)]
        payload_versions: &'a serde_json::value::RawValue,
    }
    struct Versions;
    impl<'de> serde::de::Visitor<'de> for Versions {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded payload version list")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<(), A::Error> {
            let mut count = 0;
            while sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                if count >= MAX_RETAINED_VERSIONS as usize {
                    return Err(serde::de::Error::custom(
                        "payload version list bound exceeded",
                    ));
                }
                count += 1;
            }
            Ok(())
        }
    }
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(RecordError::TooLarge);
    }
    let bounds: Bounds<'_> = serde_json::from_slice(bytes).map_err(|_| RecordError::Corrupt)?;
    preflight_entry(bounds.metadata)?;
    let mut decoder = serde_json::Deserializer::from_str(bounds.payload_versions.get());
    serde::de::Deserializer::deserialize_seq(&mut decoder, Versions)
        .map_err(|_| RecordError::Corrupt)?;
    Ok(())
}

// Pure canonical metadata bounds only. The hint contains no validation
// receipt: each matching fresh authenticated input is bounded again from
// the complete typed fields whose canonical bytes were captured together.
fn preflight_paged_typed_path(bytes: &[u8], cell: &PathCell<Entry>) -> CodecResult<()> {
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(RecordError::TooLarge);
    }
    if cell.metadata.versions.len() > MAX_RETAINED_VERSIONS as usize
        || cell.metadata.precision.versions.len() > MAX_RETAINED_VERSIONS as usize
        || cell
            .metadata
            .custom_metadata
            .as_ref()
            .is_some_and(|metadata| metadata.len() > 64)
        || cell.payload_versions.len() > MAX_RETAINED_VERSIONS as usize
    {
        return Err(RecordError::Corrupt);
    }
    Ok(())
}

impl Drop for PayloadDescriptor {
    fn drop(&mut self) {
        self.path_token.zeroize();
    }
}
impl PayloadDescriptor {
    fn validate(&self, key: &AddressKey, path: &str, version: u64) -> CodecResult<()> {
        if self.format != PAYLOAD_FORMAT
            || self.path_token != token(key, path)?
            || self.version != version
            || version == 0
            || self.logical_bytes == 0
            || self.logical_bytes > MAX_VALUE_BYTES as u64
            || self.blocks.len() != (self.logical_bytes as usize).div_ceil(BLOCK_BYTES)
        {
            return Err(RecordError::Corrupt);
        }
        for (number, block) in self.blocks.iter().enumerate() {
            let expected = (self.logical_bytes as usize - number * BLOCK_BYTES).min(BLOCK_BYTES);
            if block.kind != ObjectKind::Block
                || block.record_count != 0
                || block.payload_bytes != expected as u64
                || block.encoded_bytes as usize != expected + OBJECT_HEADER_BYTES
            {
                return Err(RecordError::Corrupt);
            }
        }
        Ok(())
    }
    #[cfg(any(test, feature = "native-v6-storage"))]
    fn encode(
        key: &AddressKey,
        path: &str,
        version: u64,
        data: &SharedJson,
        blocks: &mut BTreeMap<ObjectId, Arc<StagedObject>>,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<Self> {
        check()?;
        if !data.expose().is_object() {
            return Err(RecordError::Corrupt);
        }
        let bytes = serialize(data, MAX_VALUE_BYTES)?;
        let digest = key.digest(PAYLOAD_DOMAIN, &bytes)?;
        let mut references = Vec::new();
        for chunk in bytes.chunks(BLOCK_BYTES) {
            check()?;
            let object = StagedObject::payload_block(key, chunk)?;
            if let Some(prior) = blocks.insert(object.reference().id, Arc::clone(&object))
                && (prior.reference() != object.reference() || prior.bytes() != object.bytes())
            {
                return Err(RecordError::Corrupt);
            }
            references.push(object.reference().clone());
            check()?;
        }
        let descriptor = Self {
            format: PAYLOAD_FORMAT.into(),
            path_token: token(key, path)?,
            version,
            logical_bytes: bytes.len() as u64,
            digest,
            blocks: references,
        };
        descriptor.validate(key, path, version)?;
        check()?;
        Ok(descriptor)
    }
    fn matches_data(&self, key: &AddressKey, data: &SharedJson) -> CodecResult<bool> {
        let bytes = serialize(data, MAX_VALUE_BYTES)?;
        let digest = key.digest(PAYLOAD_DOMAIN, &bytes)?;
        let difference = digest
            .iter()
            .zip(self.digest)
            .fold(0_u8, |x, (a, b)| x | (a ^ b));
        Ok(bytes.len() as u64 == self.logical_bytes && difference == 0)
    }
    fn authenticate_payload(
        &self,
        key: &AddressKey,
        path: &str,
        version: u64,
        reader: &impl RecordReader,
        check: &impl Fn() -> CodecResult<()>,
        retain_bytes: bool,
    ) -> CodecResult<Option<Zeroizing<Vec<u8>>>> {
        check()?;
        self.validate(key, path, version)?;
        let mut value =
            retain_bytes.then(|| Zeroizing::new(Vec::with_capacity(self.logical_bytes as usize)));
        let digest = key.digest_value_stream(PAYLOAD_DOMAIN, self.logical_bytes, |update| {
            for reference in &self.blocks {
                check()?;
                // Reader must retain actual source/owner/Actor/Clock custody.
                // Neither this codec nor a memo can manufacture that custody.
                let encoded = reader.read_object(reference)?;
                reference.verify(key, &encoded)?;
                if encoded.len() != reference.encoded_bytes as usize {
                    return Err(RecordError::Corrupt);
                }
                let chunk = encoded
                    .get(OBJECT_HEADER_BYTES..)
                    .ok_or(RecordError::Corrupt)?;
                if chunk.len() as u64 != reference.payload_bytes {
                    return Err(RecordError::Corrupt);
                }
                // The stream bounds the accumulated length before hashing
                // or copying, and requires the exact declared length at EOF.
                update(chunk)?;
                if let Some(value) = &mut value {
                    value.extend_from_slice(chunk);
                }
                check()?;
            }
            Ok(())
        })?;
        if digest
            .iter()
            .zip(self.digest)
            .fold(0_u8, |x, (a, b)| x | (a ^ b))
            != 0
        {
            return Err(RecordError::Corrupt);
        }
        Ok(value)
    }

    fn read(
        &self,
        key: &AddressKey,
        path: &str,
        version: u64,
        reader: &impl RecordReader,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<SharedJson> {
        let value = self
            .authenticate_payload(key, path, version, reader, check, true)?
            .ok_or(RecordError::Invalid)?;
        let data: SharedJson = canonical(&value, MAX_VALUE_BYTES)?;
        if !data.expose().is_object() {
            return Err(RecordError::Corrupt);
        }
        check()?;
        Ok(data)
    }

    fn verify_semantics(
        &self,
        key: &AddressKey,
        path: &str,
        version: u64,
        reader: &impl RecordReader,
        check: &impl Fn() -> CodecResult<()>,
        memo: &RefCell<PagedPayloadValidationMemo>,
    ) -> CodecResult<bool> {
        check()?;
        let memo_key = (
            key.digest(PAYLOAD_VALIDATION_DOMAIN, self.path_token.as_bytes())?,
            self.version,
            self.digest,
            self.logical_bytes,
        );
        // This lookup only decides whether to retain a contiguous JSON copy.
        // It grants no hit: every current block and the complete payload MAC
        // are freshly authenticated below under the original live gates.
        let hint = memo
            .try_borrow()
            .map_err(|_| RecordError::Invalid)?
            .needs_lossless
            .get(&memo_key)
            .copied();
        let value = self.authenticate_payload(key, path, version, reader, check, hint.is_none())?;
        check()?;
        let known = memo
            .try_borrow()
            .map_err(|_| RecordError::Invalid)?
            .needs_lossless
            .get(&memo_key)
            .copied();
        // Do not reuse an entry replaced during a source callback. The hint
        // was only an allocation decision, not a retained semantic receipt.
        if known != hint {
            return Err(RecordError::Invalid);
        }
        let needs_lossless = if let Some(known) = known {
            #[cfg(test)]
            {
                memo.try_borrow_mut()
                    .map_err(|_| RecordError::Invalid)?
                    .hits += 1;
            }
            known
        } else {
            let value = value.ok_or(RecordError::Invalid)?;
            let data: SharedJson = canonical(&value, MAX_VALUE_BYTES)?;
            if !data.expose().is_object() {
                return Err(RecordError::Corrupt);
            }
            let needs_lossless = lossless::needs_lossless_number_format(data.expose());
            drop(data);
            check()?;
            let mut memo = memo.try_borrow_mut().map_err(|_| RecordError::Invalid)?;
            // Bound retained metadata independently of the source. Reaching
            // the bound only disables memoization; it never grants admission.
            if memo.needs_lossless.len() < MAX_RECORDS {
                memo.needs_lossless.insert(memo_key, needs_lossless);
            }
            needs_lossless
        };
        check()?;
        Ok(needs_lossless)
    }
}

#[derive(Clone, Default, Eq, PartialEq)]
struct DescriptorMap(BTreeMap<String, BTreeMap<u64, PayloadDescriptor>>);
impl Drop for DescriptorMap {
    fn drop(&mut self) {
        for (mut path, _) in std::mem::take(&mut self.0) {
            path.zeroize();
        }
    }
}

// These are pure decoded descriptors and ObjectRefs, never fd/source pins or
// completed validation. Every physical read and keyed validation is unchanged.
#[derive(Clone, Default, Eq, PartialEq)]
struct SharedDescriptors(Arc<DescriptorMap>);
impl Deref for SharedDescriptors {
    type Target = BTreeMap<String, BTreeMap<u64, PayloadDescriptor>>;
    fn deref(&self) -> &Self::Target {
        &self.0.0
    }
}
impl DerefMut for SharedDescriptors {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut Arc::make_mut(&mut self.0).0
    }
}
impl<'a> IntoIterator for &'a SharedDescriptors {
    type Item = (&'a String, &'a BTreeMap<u64, PayloadDescriptor>);
    type IntoIter = std::collections::btree_map::Iter<'a, String, BTreeMap<u64, PayloadDescriptor>>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Clone, Default)]
pub(super) struct PagedPayloads {
    descriptors: SharedDescriptors,
    #[cfg(any(test, feature = "native-v6-storage"))]
    new_blocks: BTreeMap<ObjectId, Arc<StagedObject>>,
}
impl PagedPayloads {
    #[cfg(any(test, feature = "native-v6-storage"))]
    pub(super) fn clear_new_blocks(&mut self) {
        self.new_blocks.clear();
    }
    pub(super) fn payload_count(&self) -> usize {
        self.descriptors.values().map(BTreeMap::len).sum()
    }
    fn logical_bytes(&self) -> CodecResult<u64> {
        self.descriptors
            .values()
            .flat_map(BTreeMap::values)
            .try_fold(0_u64, |total, d| {
                total
                    .checked_add(d.logical_bytes)
                    .filter(|n| *n <= MAX_PAGED_LOGICAL_BYTES)
                    .ok_or(RecordError::TooLarge)
            })
    }
    #[cfg(any(test, feature = "native-v6-storage"))]
    pub(super) fn visit_new_blocks(
        &self,
        visitor: &mut impl FnMut(&Arc<StagedObject>) -> CodecResult<()>,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<()> {
        for object in self.new_blocks.values() {
            check()?;
            visitor(object)?;
            check()?;
        }
        Ok(())
    }
    fn validate(&self, owner: &Kv2, key: &AddressKey) -> CodecResult<()> {
        validate_owner_structure(owner, true)?;
        let mut count = 0;
        for (path, entry) in &owner.entries {
            let descriptors = self.descriptors.get(path);
            for (number, version) in &entry.versions {
                let descriptor = descriptors.and_then(|d| d.get(number));
                if version.destroyed {
                    if descriptor.is_some() || version.data.is_some() {
                        return Err(RecordError::Corrupt);
                    }
                } else {
                    let descriptor = descriptor.ok_or(RecordError::Missing)?;
                    descriptor.validate(key, path, *number)?;
                    if let Some(data) = &version.data
                        && !descriptor.matches_data(key, data)?
                    {
                        return Err(RecordError::Corrupt);
                    }
                    count += 1;
                }
            }
        }
        if count != self.payload_count() {
            return Err(RecordError::Corrupt);
        }
        self.logical_bytes()?;
        Ok(())
    }
}

type InitialPagedRecords = BTreeMap<Kv1Key, Zeroizing<Vec<u8>>>;

// Initial import gathers unique records for one bottom-up build. Ordinary
// edits keep the persistent path-copy behavior and existing reader pins.
fn write_paged_record(
    index: &mut Kv1Index,
    key: Kv1Key,
    bytes: Zeroizing<Vec<u8>>,
    initial: &mut Option<&mut InitialPagedRecords>,
) -> CodecResult<()> {
    if let Some(records) = initial.as_deref_mut() {
        match records.entry(key) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(bytes);
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(RecordError::Corrupt);
            }
        }
    } else {
        *index = index.edit(key, Some(&bytes))?.next;
    }
    Ok(())
}

impl NativeGraph {
    #[cfg(any(test, feature = "native-v6-storage"))]
    fn encode_paged(
        owner: &Kv2,
        base: &AddressKey,
        input: NativeScope<'_>,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<Self> {
        check()?;
        validate_owner(owner)?;
        let scope = Scope::new(input)?;
        let key = graph_key(base, &scope)?;
        let mut next = Self {
            scope,
            key: Arc::clone(&key),
            index: Kv1Index::empty(key),
            format: PAGED_NATIVE_FORMAT.into(),
            paged: Some(PagedPayloads::default()),
        };
        let mut records = InitialPagedRecords::new();
        next.update_paged_config(owner, check, Some(&mut records))?;
        for (path, entry) in &owner.entries {
            next.update_paged_path(path, Some(entry), check, Some(&mut records))?;
            #[cfg(feature = "private-ha-forward-diagnostic")]
            crate::engines::kv2_native_large::diagnostic::graph_path_completed();
        }
        check()?;
        #[cfg(feature = "private-ha-forward-diagnostic")]
        let _diagnostic_bulk =
            crate::engines::kv2_native_large::diagnostic::Span::new("bulk_index_build");
        next.index = Kv1Index::from_records_checked(Arc::clone(&next.key), records, check)?;
        next.paged
            .as_ref()
            .ok_or(RecordError::Corrupt)?
            .logical_bytes()?;
        Ok(next)
    }
    #[cfg(any(test, feature = "native-v6-storage"))]
    fn update_paged_config(
        &mut self,
        owner: &Kv2,
        check: &impl Fn() -> CodecResult<()>,
        mut records: Option<&mut InitialPagedRecords>,
    ) -> CodecResult<()> {
        let mount = MountCell {
            format: PAGED_NATIVE_FORMAT.into(),
            scope: self.scope.clone(),
            config: owner.config.clone(),
            lossless_format: owner.lossless_format,
        };
        let bytes = serialize(&mount, MAX_CONFIG_BYTES)?;
        let record = self.scope.key("config")?;
        if self.index.get(&record) != Some(bytes.as_slice()) {
            check()?;
            #[cfg(feature = "private-ha-forward-diagnostic")]
            let diagnostic_edit = std::time::Instant::now();
            write_paged_record(&mut self.index, record, bytes, &mut records)?;
            #[cfg(feature = "private-ha-forward-diagnostic")]
            if records.is_none() {
                crate::engines::kv2_native_large::diagnostic::index_edit_elapsed(
                    diagnostic_edit.elapsed(),
                );
            }
            check()?;
        }
        Ok(())
    }
    #[cfg(any(test, feature = "native-v6-storage"))]
    fn update_paged_path(
        &mut self,
        path: &str,
        entry: Option<&Entry>,
        check: &impl Fn() -> CodecResult<()>,
        mut records: Option<&mut InitialPagedRecords>,
    ) -> CodecResult<()> {
        check()?;
        let paged = self.paged.as_mut().ok_or(RecordError::Corrupt)?;
        let old = paged.descriptors.get(path).cloned().unwrap_or_default();
        let mut descriptors = BTreeMap::new();
        let record = metadata_key(&self.scope, &self.key, path)?;
        if let Some(entry) = entry {
            let mut metadata = (**entry).clone();
            for (number, version) in &mut metadata.versions {
                check()?;
                let data = version.data.take();
                if version.destroyed {
                    if data.is_some() {
                        return Err(RecordError::Corrupt);
                    }
                    continue;
                }
                let descriptor = if let Some(previous) = old.get(number) {
                    if let Some(data) = data
                        && !previous.matches_data(&self.key, &data)?
                    {
                        return Err(RecordError::Corrupt);
                    }
                    previous.clone()
                } else {
                    PayloadDescriptor::encode(
                        &self.key,
                        path,
                        *number,
                        data.as_ref().ok_or(RecordError::Missing)?,
                        &mut paged.new_blocks,
                        check,
                    )?
                };
                descriptor.validate(&self.key, path, *number)?;
                let bytes = serialize(&descriptor, MAX_DESCRIPTOR_BYTES)?;
                let payload = payload_key(&self.scope, &self.key, path, *number)?;
                if self.index.get(&payload) != Some(bytes.as_slice()) {
                    #[cfg(feature = "private-ha-forward-diagnostic")]
                    let diagnostic_edit = std::time::Instant::now();
                    write_paged_record(&mut self.index, payload, bytes, &mut records)?;
                    #[cfg(feature = "private-ha-forward-diagnostic")]
                    if records.is_none() {
                        crate::engines::kv2_native_large::diagnostic::index_edit_elapsed(
                            diagnostic_edit.elapsed(),
                        );
                    }
                }
                descriptors.insert(*number, descriptor);
                check()?;
            }
            let cell = PathCell {
                format: PAGED_NATIVE_FORMAT.into(),
                scope: self.scope.clone(),
                path: path.into(),
                metadata,
                payload_versions: descriptors.keys().copied().collect(),
            };
            let bytes = serialize(&cell, MAX_METADATA_BYTES)?;
            if self.index.get(&record) != Some(bytes.as_slice()) {
                #[cfg(feature = "private-ha-forward-diagnostic")]
                let diagnostic_edit = std::time::Instant::now();
                write_paged_record(&mut self.index, record, bytes, &mut records)?;
                #[cfg(feature = "private-ha-forward-diagnostic")]
                if records.is_none() {
                    crate::engines::kv2_native_large::diagnostic::index_edit_elapsed(
                        diagnostic_edit.elapsed(),
                    );
                }
            }
        } else if self.index.get(&record).is_some() {
            self.index = self.index.edit(record, None)?.next;
        }
        for number in old.keys().filter(|n| !descriptors.contains_key(n)) {
            let payload = payload_key(&self.scope, &self.key, path, *number)?;
            if self.index.get(&payload).is_none() {
                return Err(RecordError::Corrupt);
            }
            self.index = self.index.edit(payload, None)?.next;
        }
        if descriptors.is_empty() {
            paged.descriptors.remove(path);
        } else {
            paged.descriptors.insert(path.into(), descriptors);
        }
        check()
    }
    #[cfg(any(test, feature = "native-v6-storage"))]
    fn with_paged_updates(
        &self,
        owner: &Kv2,
        base: &AddressKey,
        input: NativeScope<'_>,
        pending: &mutation::PendingPaths,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<Self> {
        check()?;
        let scope = Scope::new(input)?;
        if self.format != PAGED_NATIVE_FORMAT || !self.scope.matches(&scope) {
            return Err(RecordError::Invalid);
        }
        let expected = graph_key(base, &scope)?;
        if self
            .key
            .expose()
            .iter()
            .zip(expected.expose())
            .fold(0_u8, |a, (b, c)| a | (b ^ c))
            != 0
        {
            return Err(RecordError::Invalid);
        }
        validate_owner_structure(owner, true)?;
        let mut next = self.clone();
        next.paged
            .as_mut()
            .ok_or(RecordError::Corrupt)?
            .clear_new_blocks();
        next.update_paged_config(owner, check, None)?;
        for path in pending.paths() {
            next.update_paged_path(path, owner.entries.get(path), check, None)?;
        }
        next.paged
            .as_ref()
            .ok_or(RecordError::Corrupt)?
            .validate(owner, &next.key)?;
        check()?;
        Ok(next)
    }
    fn decode_paged_with_syntax(
        &mut self,
        check: &impl Fn() -> CodecResult<()>,
        syntax: Option<&syntax::PagedSyntaxHint>,
    ) -> CodecResult<DetachedOwner> {
        check()?;
        let syntax = syntax.filter(|hint| hint.same_graph(&self.scope, &self.key));
        let mut keys = BTreeSet::new();
        self.index.visit_keys(|key| {
            check()?;
            if !self.scope.matches_key(key) || keys.len() >= MAX_RECORDS {
                return Err(RecordError::Corrupt);
            }
            keys.insert(key.clone());
            Ok(())
        })?;
        let config = self.scope.key("config")?;
        let mount: MountCell = canonical(
            self.index.get(&config).ok_or(RecordError::Missing)?,
            MAX_CONFIG_BYTES,
        )?;
        if mount.format != PAGED_NATIVE_FORMAT || !self.scope.matches(&mount.scope) {
            return Err(RecordError::Corrupt);
        }
        keys.remove(&config);
        let mut owner = DetachedOwner(Kv2 {
            config: mount.config,
            entries: BTreeMap::new(),
            lossless_format: mount.lossless_format,
        });
        let metadata: Vec<_> = keys
            .iter()
            .filter(|key| key.path().starts_with("metadata/"))
            .cloned()
            .collect();
        if metadata.len() > MAX_PATHS {
            return Err(RecordError::TooLarge);
        }
        let mut paged = PagedPayloads::default();
        for record in metadata {
            check()?;
            let cell_bytes = self.index.get(&record).ok_or(RecordError::Missing)?;
            let cell = match syntax.and_then(|hint| hint.path(&record, cell_bytes)) {
                Some(value) => {
                    preflight_paged_typed_path(cell_bytes, value)?;
                    syntax::PagedPath::SameBytes(value)
                }
                None => {
                    preflight_paged_path(cell_bytes)?;
                    syntax::PagedPath::Decoded(Box::new(canonical(cell_bytes, MAX_METADATA_BYTES)?))
                }
            };
            let (format, scope, path, metadata, payload_versions) = cell.fields();
            if format != PAGED_NATIVE_FORMAT
                || !self.scope.matches(scope)
                || metadata_key(&self.scope, &self.key, path)? != record
                || metadata.versions.len() > MAX_RETAINED_VERSIONS as usize
                || payload_versions.len() > MAX_RETAINED_VERSIONS as usize
                || metadata
                    .versions
                    .values()
                    .any(|version| version.data.is_some())
            {
                return Err(RecordError::Corrupt);
            }
            keys.remove(&record);
            let mut descriptors = BTreeMap::new();
            for number in payload_versions {
                check()?;
                let version = metadata.versions.get(number).ok_or(RecordError::Corrupt)?;
                if version.destroyed {
                    return Err(RecordError::Corrupt);
                }
                let payload = payload_key(&self.scope, &self.key, path, *number)?;
                let descriptor_bytes = self.index.get(&payload).ok_or(RecordError::Missing)?;
                let descriptor = match syntax
                    .and_then(|hint| hint.descriptor(&payload, descriptor_bytes, path, *number))
                {
                    Some(value) => value.clone(),
                    None => canonical(descriptor_bytes, MAX_DESCRIPTOR_BYTES)?,
                };
                descriptor.validate(&self.key, path, *number)?;
                if !keys.remove(&payload) {
                    return Err(RecordError::Corrupt);
                }
                descriptors.insert(*number, descriptor);
            }
            if !descriptors.is_empty() {
                paged.descriptors.insert(path.to_owned(), descriptors);
            }
            let (path, entry) = cell.into_entry();
            if owner.entries.insert(path, entry).is_some() {
                return Err(RecordError::Corrupt);
            }
            check()?;
        }
        if !keys.is_empty() {
            return Err(RecordError::Corrupt);
        }
        paged.validate(&owner, &self.key)?;
        self.paged = Some(paged);
        check()?;
        Ok(owner)
    }
}

#[cfg(any(test, feature = "native-v6-storage"))]
impl NativeCellGraph {
    #[cfg(test)]
    pub(crate) fn graph_format(&self) -> &str {
        &self.0.format
    }
    pub(crate) fn logical_payload_bytes(&self) -> CodecResult<u64> {
        self.0
            .paged
            .as_ref()
            .map_or(Ok(0), PagedPayloads::logical_bytes)
    }
    #[cfg(any(test, feature = "native-v6-storage"))]
    fn encode_paged(
        owner: &Kv2,
        parent: &AddressKey,
        scope: NativeScope<'_>,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<Self> {
        Ok(Self(NativeGraph::encode_paged(
            owner, parent, scope, check,
        )?))
    }
}

impl NativeReadView {
    /// A data-only proof about this unchanged, fully opened config-only graph.
    /// Zero payload bytes/counts alone are insufficient: deleted or destroyed
    /// histories, pending deletion and an old cached index must all be absent.
    #[cfg(any(test, feature = "native-v6-storage"))]
    pub(crate) fn is_authenticated_empty_for_marker(
        &self,
        parent: &AddressKey,
        scope: NativeScope<'_>,
        expected: &Kv1Root,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<bool> {
        check()?;
        let Some(graph) = &self.graph else {
            return Ok(false);
        };
        let Some(paged) = &graph.paged else {
            return Ok(false);
        };
        let actual_scope = Scope::new(scope)?;
        if graph.format != PAGED_NATIVE_FORMAT
            || !self.owner.entries.is_empty()
            || self.pending.paths().next().is_some()
            || !paged.descriptors.is_empty()
            || !paged.new_blocks.is_empty()
            || !graph.scope.matches(&actual_scope)
            || graph.index.root() != *expected
        {
            return Ok(false);
        }
        self.validate_paged_candidate()?;
        let config = graph.scope.key("config")?;
        let mut found = false;
        graph.index.visit_keys(|key| {
            check()?;
            if key != &config || found {
                return Err(RecordError::Corrupt);
            }
            found = true;
            Ok(())
        })?;
        if !found {
            return Ok(false);
        }
        let actual = graph.index.get(&config).ok_or(RecordError::Missing)?;
        let expected_cell = MountCell {
            format: PAGED_NATIVE_FORMAT.into(),
            scope: actual_scope,
            config: self.owner.config.clone(),
            lossless_format: self.owner.lossless_format,
        };
        if serialize(&expected_cell, MAX_CONFIG_BYTES)?.as_slice() != actual {
            return Ok(false);
        }
        // This additionally binds the caller's independently derived address
        // key and the decoded owner. It cannot replace the no-pending/index
        // checks above with a newly encoded prospective empty graph.
        let matches = self.matches_authenticated_root(parent, scope, expected, check)?;
        check()?;
        Ok(matches)
    }

    pub(crate) fn is_paged(&self) -> bool {
        self.graph
            .as_ref()
            .is_some_and(|graph| graph.format == PAGED_NATIVE_FORMAT && graph.paged.is_some())
    }
    pub(crate) fn logical_payload_bytes(&self) -> CodecResult<u64> {
        self.graph
            .as_ref()
            .and_then(|graph| graph.paged.as_ref())
            .map_or(Ok(0), PagedPayloads::logical_bytes)
    }
    fn validate_paged_metadata(&self) -> CodecResult<()> {
        let graph = self.graph.as_ref().ok_or(RecordError::Corrupt)?;
        graph
            .paged
            .as_ref()
            .ok_or(RecordError::Corrupt)?
            .validate(&self.owner, &graph.key)
    }
    pub(super) fn validate_paged_candidate(&self) -> CodecResult<()> {
        validate_owner_structure(&self.owner, true)?;
        let graph = self.graph.as_ref().ok_or(RecordError::Corrupt)?;
        let paged = graph.paged.as_ref().ok_or(RecordError::Corrupt)?;
        for (path, entry) in &self.owner.entries {
            for (number, version) in &entry.versions {
                if version.destroyed {
                    continue;
                }
                let descriptor = paged
                    .descriptors
                    .get(path)
                    .and_then(|values| values.get(number));
                match (&version.data, descriptor) {
                    (Some(data), Some(descriptor)) => {
                        descriptor.validate(&graph.key, path, *number)?;
                        if !descriptor.matches_data(&graph.key, data)? {
                            return Err(RecordError::Corrupt);
                        }
                    }
                    (Some(data), None) if data.expose().is_object() => {}
                    (None, Some(descriptor)) => descriptor.validate(&graph.key, path, *number)?,
                    _ => return Err(RecordError::Missing),
                }
            }
        }
        Ok(())
    }
    /// Erase payloads opened from already authenticated old descriptors. Fresh
    /// versions remain present until the candidate's own graph is constructed.
    #[cfg(any(test, feature = "native-v6-storage"))]
    pub(crate) fn clear_hydrated_payloads(&mut self) -> Result<()> {
        if !self.is_paged() {
            return Ok(());
        }
        let graph = self
            .graph
            .as_ref()
            .ok_or_else(|| error(503, "native paged graph missing"))?;
        let paged = graph
            .paged
            .as_ref()
            .ok_or_else(|| error(503, "native paged descriptors missing"))?;
        for (path, entry) in &mut self.owner.entries {
            for (number, version) in &mut entry.versions {
                if let Some(descriptor) = paged
                    .descriptors
                    .get(path)
                    .and_then(|values| values.get(number))
                {
                    if let Some(data) = &version.data
                        && !descriptor
                            .matches_data(&graph.key, data)
                            .map_err(|_| error(503, "native hydrated payload check failed"))?
                    {
                        return Err(error(
                            503,
                            "native hydrated payload changed its old descriptor",
                        ));
                    }
                    version.data = None;
                }
            }
        }
        self.pending.erase_payloads();
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn erase_hydrated_payloads(&mut self) {
        for entry in self.owner.entries.values_mut() {
            for version in entry.versions.values_mut() {
                version.data = None;
            }
        }
    }
    pub(crate) fn open_paged(
        parent: &AddressKey,
        input: NativeScope<'_>,
        root: Kv1Root,
        reader: &impl RecordReader,
    ) -> CodecResult<Self> {
        Self::open_paged_checked(parent, input, root, reader, &|| Ok(()))
    }
    pub(crate) fn open_paged_checked(
        parent: &AddressKey,
        input: NativeScope<'_>,
        root: Kv1Root,
        reader: &impl RecordReader,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<Self> {
        Self::open_paged_with_syntax(parent, input, root, reader, check, None)
    }
    pub(crate) fn open_paged_with_syntax(
        parent: &AddressKey,
        input: NativeScope<'_>,
        root: Kv1Root,
        reader: &impl RecordReader,
        check: &impl Fn() -> CodecResult<()>,
        syntax: Option<&syntax::PagedSyntaxHint>,
    ) -> CodecResult<Self> {
        check()?;
        let scope = Scope::new(input)?;
        let key = graph_key(parent, &scope)?;
        let index = Kv1Index::open(Arc::clone(&key), root, reader)?;
        let mut graph = NativeGraph {
            scope,
            key,
            index,
            format: PAGED_NATIVE_FORMAT.into(),
            paged: None,
        };
        let owner = graph.decode_paged_with_syntax(check, syntax)?;
        check()?;
        Ok(Self {
            owner: owner.into(),
            graph: Some(graph),
            pending: mutation::PendingPaths::default(),
        })
    }
    #[cfg(any(test, feature = "native-v6-storage"))]
    pub(crate) fn encode_paged(
        &self,
        parent: &AddressKey,
        scope: NativeScope<'_>,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<NativeCellGraph> {
        match &self.graph {
            Some(graph) if graph.paged.is_some() => Ok(NativeCellGraph(graph.with_paged_updates(
                &self.owner,
                parent,
                scope,
                &self.pending,
                check,
            )?)),
            _ => NativeCellGraph::encode_paged(&self.owner, parent, scope, check),
        }
    }
    #[cfg(feature = "native-v6-storage")]
    pub(crate) fn visit_paged_payload_references(
        &self,
        mut visit: impl FnMut(&ObjectRef) -> CodecResult<()>,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<()> {
        check()?;
        self.validate_paged_metadata()?;
        let graph = self.graph.as_ref().ok_or(RecordError::Corrupt)?;
        for descriptors in graph
            .paged
            .as_ref()
            .ok_or(RecordError::Corrupt)?
            .descriptors
            .values()
        {
            for descriptor in descriptors.values() {
                for reference in &descriptor.blocks {
                    check()?;
                    visit(reference)?;
                    check()?;
                }
            }
        }
        check()
    }

    #[cfg(test)]
    pub(crate) fn verify_paged_payloads(
        &self,
        reader: &impl RecordReader,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<()> {
        self.verify_paged_payloads_with_memo(reader, check, None)
    }

    pub(crate) fn verify_paged_payloads_with_memo(
        &self,
        reader: &impl RecordReader,
        check: &impl Fn() -> CodecResult<()>,
        memo: Option<&RefCell<PagedPayloadValidationMemo>>,
    ) -> CodecResult<()> {
        check()?;
        self.validate_paged_metadata()?;
        let graph = self.graph.as_ref().ok_or(RecordError::Corrupt)?;
        if graph.format != PAGED_NATIVE_FORMAT {
            return Err(RecordError::Invalid);
        }
        for (path, descriptors) in &graph
            .paged
            .as_ref()
            .ok_or(RecordError::Corrupt)?
            .descriptors
        {
            for (number, descriptor) in descriptors {
                check()?;
                let needs_lossless = match memo {
                    Some(memo) => descriptor
                        .verify_semantics(&graph.key, path, *number, reader, check, memo)?,
                    None => {
                        let value = descriptor.read(&graph.key, path, *number, reader, check)?;
                        lossless::needs_lossless_number_format(value.expose())
                    }
                };
                // A memo records the bytes' semantics, never the current
                // owner's permission to contain lossless numbers.
                if needs_lossless && self.owner.lossless_format != Some(1) {
                    return Err(RecordError::Corrupt);
                }
                check()?;
            }
        }
        check()
    }

    /// Verify a detached candidate against the actual admitted prior view.
    /// The Service must bind `prior` to its current authenticated root and live
    /// source instance; metadata-only reopening cannot create that authority.
    /// `staged` MUST read only this candidate's staged objects, without fallback
    /// to the prior durable source. A changed descriptor is never inherited.
    /// This codec does not grant Actor, physical-source or publication custody.
    #[cfg(test)]
    pub(crate) fn verify_paged_transition(
        &self,
        prior: Option<&NativeReadView>,
        staged: &impl RecordReader,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<()> {
        self.verify_paged_transition_with_memo(prior, staged, check, None)
    }

    #[cfg(any(test, feature = "native-v6-storage"))]
    pub(crate) fn verify_paged_transition_with_memo(
        &self,
        prior: Option<&NativeReadView>,
        staged: &impl RecordReader,
        check: &impl Fn() -> CodecResult<()>,
        memo: Option<&RefCell<PagedPayloadValidationMemo>>,
    ) -> CodecResult<()> {
        check()?;
        self.validate_paged_metadata()?;
        let graph = self.graph.as_ref().ok_or(RecordError::Corrupt)?;
        if graph.format != PAGED_NATIVE_FORMAT {
            return Err(RecordError::Invalid);
        }
        let previous = if let Some(prior) = prior {
            check()?;
            prior.validate_paged_metadata()?;
            let previous = prior.graph.as_ref().ok_or(RecordError::Corrupt)?;
            let key_difference = graph
                .key
                .expose()
                .iter()
                .zip(previous.key.expose())
                .fold(0_u8, |difference, (new, old)| difference | (new ^ old));
            if previous.format != PAGED_NATIVE_FORMAT
                || !graph.scope.matches(&previous.scope)
                || key_difference != 0
            {
                return Err(RecordError::Invalid);
            }
            Some(previous.paged.as_ref().ok_or(RecordError::Corrupt)?)
        } else {
            None
        };
        let paged = graph.paged.as_ref().ok_or(RecordError::Corrupt)?;
        for (path, descriptors) in &paged.descriptors {
            for (number, descriptor) in descriptors {
                check()?;
                if previous
                    .and_then(|old| old.descriptors.get(path))
                    .and_then(|versions| versions.get(number))
                    .is_some_and(|old| old == descriptor)
                {
                    if prior.is_some_and(|old| old.owner.lossless_format == Some(1))
                        && self.owner.lossless_format != Some(1)
                    {
                        return Err(RecordError::Corrupt);
                    }
                    // Exact same-path/version descriptor and key/scope prove
                    // inherited typed closure, never a fresh plaintext read.
                    check()?;
                    continue;
                }
                // A semantic hit never supplies this changed staged closure.
                // Read and authenticate every current block before consulting it.
                let needs_lossless = match memo {
                    Some(memo) => descriptor
                        .verify_semantics(&graph.key, path, *number, staged, check, memo)?,
                    None => {
                        let value = descriptor.read(&graph.key, path, *number, staged, check)?;
                        lossless::needs_lossless_number_format(value.expose())
                    }
                };
                if needs_lossless && self.owner.lossless_format != Some(1) {
                    return Err(RecordError::Corrupt);
                }
                check()?;
            }
        }
        check()
    }
    #[cfg(any(test, feature = "native-v6-storage"))]
    pub(crate) fn read_with_source(
        &self,
        method: &str,
        path: &str,
        body: &Value,
        now: Timestamp,
        reader: &impl RecordReader,
    ) -> Result<EngineResponse> {
        if !self.is_paged() {
            return self.read(method, path, body, now);
        }
        let Some((operation, resource)) = path.split_once('/') else {
            return self.read(method, path, body, now);
        };
        if !matches!(operation, "data" | "subkeys") {
            return self.read(method, path, body, now);
        }
        valid_path(resource)?;
        let mut owner = self.owner.clone();
        if let Some(entry) = owner.entries.get_mut(resource) {
            let selected = body
                .get("version")
                .map(wire_version)
                .transpose()?
                .flatten()
                .unwrap_or(entry.current_version);
            let precise = entry.version_precision(selected);
            if let Some(version) = entry.versions.get_mut(&selected)
                && !version.destroyed
                && version
                    .deletion_at
                    .is_none_or(|at| lossless::time_before(now, at, precise.deletion_at))
            {
                let graph = self
                    .graph
                    .as_ref()
                    .ok_or_else(|| error(503, "native paged graph missing"))?;
                let descriptor = graph
                    .paged
                    .as_ref()
                    .and_then(|p| p.descriptors.get(resource))
                    .and_then(|p| p.get(&selected))
                    .ok_or_else(|| error(503, "native paged descriptor missing"))?;
                version.data = Some(
                    descriptor
                        .read(&graph.key, resource, selected, reader, &|| Ok(()))
                        .map_err(|_| error(503, "native paged point read rejected"))?,
                );
            }
        }
        owner.handle_read_precise(method, path, body, now)
    }
    #[cfg(any(test, feature = "native-v6-storage"))]
    pub(crate) fn hydrate_current_for_patch(
        &mut self,
        path: &str,
        reader: &impl RecordReader,
    ) -> Result<()> {
        if !self.is_paged() {
            return Ok(());
        }
        let Some(resource) = path.strip_prefix("data/") else {
            return Ok(());
        };
        valid_path(resource)?;
        let Some(entry) = self.owner.entries.get_mut(resource) else {
            return Ok(());
        };
        let number = entry.current_version;
        let Some(version) = entry.versions.get_mut(&number) else {
            return Ok(());
        };
        if version.destroyed {
            return Ok(());
        }
        let graph = self
            .graph
            .as_ref()
            .ok_or_else(|| error(503, "native paged graph missing"))?;
        let descriptor = graph
            .paged
            .as_ref()
            .and_then(|p| p.descriptors.get(resource))
            .and_then(|p| p.get(&number))
            .ok_or_else(|| error(503, "native paged descriptor missing"))?;
        version.data = Some(
            descriptor
                .read(&graph.key, resource, number, reader, &|| Ok(()))
                .map_err(|_| error(503, "native paged PATCH source rejected"))?,
        );
        Ok(())
    }
}

#[cfg(any(test, feature = "native-v6-storage"))]
impl EngineState {
    pub(crate) fn project_v6_native_paged(
        &self,
        parent: &AddressKey,
        check: &impl Fn() -> CodecResult<()>,
        mut visit: impl FnMut(
            &crate::state_record_root_v6::MountScope,
            &Arc<StagedObject>,
        ) -> CodecResult<()>,
    ) -> CodecResult<(EngineState, Vec<crate::state_record_root_v6::Kv2GraphRef>)> {
        check()?;
        let mut opaque = self.clone();
        let mut pending = Vec::new();
        let mut metadata_bytes = 0_u64;
        let mut logical_bytes = 0_u64;
        let mut records = 0_u64;
        for (namespace, owner) in &mut opaque.namespaces {
            for (mount, descriptor) in &mut owner.mounts {
                check()?;
                if !matches!(descriptor.backend, Backend::Kv2(_) | Backend::Kv2Native(_)) {
                    continue;
                }
                if pending.len() >= crate::state_record_root_v6::MAX_KV2_MOUNTS {
                    return Err(RecordError::TooLarge);
                }
                let scope = crate::state_record_root_v6::MountScope {
                    namespace: namespace.clone(),
                    mount: mount.clone(),
                    incarnation: descriptor.incarnation,
                };
                let graph = match &descriptor.backend {
                    Backend::Kv2(engine) => {
                        NativeCellGraph::encode_paged(engine, parent, scope.borrowed(), check)?
                    }
                    Backend::Kv2Native(view) => {
                        view.encode_paged(parent, scope.borrowed(), check)?
                    }
                    _ => return Err(RecordError::Corrupt),
                };
                let root = graph.root();
                let reference = root.reference.as_ref().ok_or(RecordError::Corrupt)?;
                metadata_bytes = metadata_bytes
                    .checked_add(reference.payload_bytes)
                    .filter(|n| *n <= MAX_GRAPH_BYTES as u64)
                    .ok_or(RecordError::TooLarge)?;
                logical_bytes = logical_bytes
                    .checked_add(graph.logical_payload_bytes()?)
                    .filter(|n| *n <= MAX_PAGED_LOGICAL_BYTES)
                    .ok_or(RecordError::TooLarge)?;
                records = records
                    .checked_add(reference.record_count)
                    .filter(|n| *n <= crate::state_record_root_v6::MAX_KV2_RECORDS)
                    .ok_or(RecordError::TooLarge)?;
                pending.push((scope, graph, root));
                descriptor.backend = Backend::Kv2(Kv2::default());
                check()?;
            }
        }
        let mut roots = pending
            .iter()
            .map(|(scope, graph, root)| {
                Ok(crate::state_record_root_v6::Kv2GraphRef {
                    scope: scope.clone(),
                    graph_format: PAGED_NATIVE_FORMAT.into(),
                    root: root.clone(),
                    logical_payload_bytes: graph.logical_payload_bytes()?,
                })
            })
            .collect::<CodecResult<Vec<_>>>()?;
        roots.sort_by(|a, b| a.scope.cmp(&b.scope));
        opaque
            .validate_v6_kv2_placeholders(
                &roots.iter().map(|g| g.scope.clone()).collect::<Vec<_>>(),
            )
            .map_err(|_| RecordError::Corrupt)?;
        check()?;
        for (scope, graph, _) in &pending {
            graph.visit_objects(|object| visit(scope, object), check)?;
        }
        check()?;
        Ok((opaque, roots))
    }
}

#[cfg(test)]
#[path = "kv2_native_paged_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "kv2_native_empty_snapshot_floor_tests.rs"]
mod empty_snapshot_floor_tests;

#[cfg(test)]
#[path = "kv2_native_payload_validation_tests.rs"]
mod payload_validation_tests;
