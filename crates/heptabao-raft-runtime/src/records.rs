//! Bounded immutable encrypted objects and one CAS-published application root.
use crate::{RaftRuntimeError, ReplicatedEnvelope};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

pub type RecordObjectId = [u8; 32];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordUsage {
    /// Conservative charged JSON bytes: actual entry encodings plus bounded
    /// map/field punctuation reserve, including coexisting legacy statuses.
    pub encoded_bytes: usize,
    pub object_count: usize,
    pub encoded_limit: usize,
}

pub(crate) const MAX_RECORD_COMMAND_BYTES: usize = 1024 * 1024;
const MAX_OBJECTS: usize = 131_072;
const MAX_CHILDREN: usize = 256;
const MAX_DEPTH: u8 = 18;
// Includes JSON/base64/key overhead and coexisting legacy chunk statuses. The
// remaining MiB bounds Raft metadata; duplicated compact snapshots stay <128MiB.
const MAX_APPLICATION_JSON_BYTES: usize = 47 * 1024 * 1024;
pub(crate) const PRODUCTION_CLIENT: &str = "heptabao-production-ha";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecordObjectKind {
    Block,
    Value,
    Leaf,
    Branch,
    OwnerChunk,
    PackedLeaf,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordObjectRef {
    pub id: RecordObjectId,
    pub kind: RecordObjectKind,
    pub encoded_bytes: u32,
    pub record_count: u64,
    pub payload_bytes: u64,
}
impl fmt::Debug for RecordObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordObjectRef")
            .field("kind", &self.kind)
            .field("encoded_bytes", &self.encoded_bytes)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedRecordObject {
    reference: RecordObjectRef,
    children: Vec<RecordObjectRef>,
    #[serde(with = "sealed_bytes")]
    sealed: Vec<u8>,
}
impl fmt::Debug for SealedRecordObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedRecordObject")
            .field("kind", &self.reference.kind)
            .field("children", &self.children.len())
            .field("sealed_bytes", &self.sealed.len())
            .finish_non_exhaustive()
    }
}
impl SealedRecordObject {
    pub fn new(
        reference: RecordObjectRef,
        children: Vec<RecordObjectRef>,
        sealed: Vec<u8>,
    ) -> Result<Self, RaftRuntimeError> {
        let value = Self {
            reference,
            children,
            sealed,
        };
        value.validate().map_err(RaftRuntimeError::RecordRejected)?;
        Ok(value)
    }
    pub fn reference(&self) -> &RecordObjectRef {
        &self.reference
    }
    pub fn children(&self) -> &[RecordObjectRef] {
        &self.children
    }
    pub fn sealed(&self) -> &[u8] {
        &self.sealed
    }
    fn validate(&self) -> Result<(), RecordRejection> {
        if self.sealed.is_empty()
            || self.sealed.len() > self.reference.encoded_bytes as usize + 256
            || self.sealed.len() > MAX_RECORD_COMMAND_BYTES
            || self.children.len() > MAX_CHILDREN
            || self.reference.encoded_bytes < 25
            || self.reference.encoded_bytes as usize > MAX_RECORD_COMMAND_BYTES
        {
            return Err(RecordRejection::Invalid);
        }
        let mut records = 0_u64;
        let mut payload = 0_u64;
        for child in &self.children {
            if child.encoded_bytes < 25 || child.encoded_bytes as usize > MAX_RECORD_COMMAND_BYTES {
                return Err(RecordRejection::Invalid);
            }
            records = records
                .checked_add(child.record_count)
                .ok_or(RecordRejection::Budget)?;
            payload = payload
                .checked_add(child.payload_bytes)
                .ok_or(RecordRejection::Budget)?;
        }
        use RecordObjectKind::*;
        let valid = match self.reference.kind {
            Block | OwnerChunk => {
                self.children.is_empty()
                    && self.reference.record_count == 0
                    && self.reference.payload_bytes <= 256 * 1024
                    && u64::from(self.reference.encoded_bytes) == 25 + self.reference.payload_bytes
            }
            Value => {
                self.children.len() <= 64
                    && self.reference.record_count == 1
                    && self.reference.payload_bytes <= 16 * 1024 * 1024
                    && self.children.iter().all(|c| c.kind == Block)
                    && payload == self.reference.payload_bytes
                    && self.reference.encoded_bytes as usize == 27 + 53 * self.children.len()
            }
            Leaf => {
                !self.children.is_empty()
                    && self.reference.encoded_bytes <= 32 * 1024
                    && self.children.iter().all(|c| c.kind == Value)
                    && records == self.reference.record_count
                    && payload == self.reference.payload_bytes
            }
            PackedLeaf => {
                // This validates visible aggregate bounds only. The application
                // authenticates/decrypts the page and verifies its actual entries.
                // Repeated Value refs are repeated edges, not deduplicated here.
                let inline_count = self.reference.record_count.checked_sub(records);
                let inline_payload = self.reference.payload_bytes.checked_sub(payload);
                (27..=32 * 1024).contains(&self.reference.encoded_bytes)
                    && (1..=256).contains(&self.reference.record_count)
                    && self
                        .children
                        .iter()
                        .all(|c| c.kind == Value && c.record_count == 1)
                    && inline_count.is_some_and(|count| count > 0 && count <= 256)
                    && inline_count
                        .zip(inline_payload)
                        .is_some_and(|(count, bytes)| {
                            bytes <= count * 1024
                                && bytes
                                    <= u64::from(self.reference.encoded_bytes.saturating_sub(27))
                        })
            }
            Branch => {
                !self.children.is_empty()
                    && self.reference.encoded_bytes <= 32 * 1024
                    && self
                        .children
                        .iter()
                        .all(|c| matches!(c.kind, Leaf | PackedLeaf | Branch))
                    && (self.children.iter().all(|c| c.kind == Branch)
                        || self
                            .children
                            .iter()
                            .all(|c| matches!(c.kind, Leaf | PackedLeaf)))
                    && records == self.reference.record_count
                    && payload == self.reference.payload_bytes
            }
        };
        if !valid
            || json_size(self)?
                .checked_add(128)
                .is_none_or(|n| n > MAX_RECORD_COMMAND_BYTES)
        {
            return Err(RecordRejection::Invalid);
        }
        Ok(())
    }
}
mod sealed_bytes {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD_NO_PAD.encode(value))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() > MAX_RECORD_COMMAND_BYTES * 4 / 3 + 4 {
            return Err(serde::de::Error::custom("sealed object exceeds bound"));
        }
        let bytes = STANDARD_NO_PAD
            .decode(&encoded)
            .map_err(|_| serde::de::Error::custom("invalid sealed object encoding"))?;
        if STANDARD_NO_PAD.encode(&bytes) != encoded {
            return Err(serde::de::Error::custom(
                "noncanonical sealed object encoding",
            ));
        }
        Ok(bytes)
    }
}
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecordRootBase {
    Empty,
    Legacy([u8; 32]),
    RecordsV5([u8; 32]),
}
impl fmt::Debug for RecordRootBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "Empty",
            Self::Legacy(_) => "Legacy([REDACTED])",
            Self::RecordsV5(_) => "RecordsV5([REDACTED])",
        })
    }
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedRecordRoot {
    base: RecordRootBase,
    #[serde(with = "root_envelope")]
    envelope: ReplicatedEnvelope,
    direct_refs: Vec<RecordObjectRef>,
}
impl fmt::Debug for PublishedRecordRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishedRecordRoot")
            .field("base", &self.base)
            .field("direct_refs", &self.direct_refs.len())
            .finish_non_exhaustive()
    }
}
impl PublishedRecordRoot {
    pub fn new(
        base: RecordRootBase,
        envelope: ReplicatedEnvelope,
        direct_refs: Vec<RecordObjectRef>,
    ) -> Result<Self, RaftRuntimeError> {
        let value = Self {
            base,
            envelope,
            direct_refs,
        };
        value.validate().map_err(RaftRuntimeError::RecordRejected)?;
        Ok(value)
    }
    pub fn base(&self) -> RecordRootBase {
        self.base
    }
    pub fn envelope(&self) -> &ReplicatedEnvelope {
        &self.envelope
    }
    pub fn direct_refs(&self) -> &[RecordObjectRef] {
        &self.direct_refs
    }
    fn validate(&self) -> Result<(), RecordRejection> {
        if self.direct_refs.len() > MAX_CHILDREN
            || self.direct_refs.iter().any(|r| {
                !matches!(
                    r.kind,
                    RecordObjectKind::OwnerChunk
                        | RecordObjectKind::Leaf
                        | RecordObjectKind::PackedLeaf
                        | RecordObjectKind::Branch
                )
            })
            || json_size(self)?
                .checked_add(128)
                .is_none_or(|n| n > MAX_RECORD_COMMAND_BYTES)
        {
            return Err(RecordRejection::Invalid);
        }
        Ok(())
    }
}
mod root_envelope {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &ReplicatedEnvelope,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.encoded_status())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ReplicatedEnvelope, D::Error> {
        ReplicatedEnvelope::decode_status(&String::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid record publication envelope"))
    }
}
pub type LegacyEnvelopeObservation = (ReplicatedEnvelope, LegacyStatusIdentity);

/// Identity of the exact persisted legacy status representation, not a
/// decode/re-encode approximation. This is not an AEAD authentication proof.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyStatusIdentity {
    pub digest: [u8; 32],
    pub status_sha256: [u8; 32],
}
impl fmt::Debug for LegacyStatusIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyStatusIdentity([REDACTED])")
    }
}
impl LegacyStatusIdentity {
    pub(crate) fn inspect(status: &str) -> Result<(ReplicatedEnvelope, Self), RecordRejection> {
        use sha2::{Digest, Sha256};
        let envelope =
            ReplicatedEnvelope::decode_status(status).map_err(|_| RecordRejection::Invalid)?;
        let identity = Self {
            digest: envelope.digest(),
            status_sha256: Sha256::digest(status.as_bytes()).into(),
        };
        Ok((envelope, identity))
    }
    pub(crate) fn validate(&self) -> Result<(), RecordRejection> {
        if self.digest == [0; 32] || self.status_sha256 == [0; 32] {
            return Err(RecordRejection::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyChunkRef {
    pub index: u16,
    pub slot: u8,
    pub identity: LegacyStatusIdentity,
}
impl fmt::Debug for LegacyChunkRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyChunkRef([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecordRejection {
    Invalid,
    MissingDependency,
    ImmutableConflict,
    StaleRoot,
    Reachable,
    ReferencedByStaged,
    Budget,
    LegacyFenced,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum RecordCommand {
    RetainLegacyChunks {
        expected_manifest: LegacyStatusIdentity,
        active: Vec<LegacyChunkRef>,
    },
    Stage {
        object: SealedRecordObject,
    },
    Publish {
        root: PublishedRecordRoot,
    },
    Prune {
        expected_root: [u8; 32],
        ids: Vec<RecordObjectId>,
    },
}
impl fmt::Debug for RecordCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RetainLegacyChunks { .. } => "RetainLegacyChunks([REDACTED])",
            Self::Stage { .. } => "Stage([REDACTED])",
            Self::Publish { .. } => "Publish([REDACTED])",
            Self::Prune { .. } => "Prune([REDACTED])",
        })
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordState {
    objects: BTreeMap<String, SealedRecordObject>,
    published: Option<PublishedRecordRoot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legacy_migration_prepared: Option<LegacyStatusIdentity>,
    #[serde(skip)]
    cache: Option<RecordCache>,
}
#[derive(Clone, Default)]
struct RecordCache {
    encoded_bytes: usize,
    depths: HashMap<String, u8>,
}
impl fmt::Debug for RecordState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordState")
            .field("objects", &self.objects.len())
            .field("published", &self.published.is_some())
            .field(
                "legacy_migration_prepared",
                &self.legacy_migration_prepared.is_some(),
            )
            .finish()
    }
}
pub(crate) fn json_size(value: &impl Serialize) -> Result<usize, RecordRejection> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("encoded size overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value).map_err(|_| RecordRejection::Invalid)?;
    Ok(counter.0)
}
pub(crate) fn status_entry_size(client: &str, status: &str) -> Result<usize, RecordRejection> {
    json_size(&client)?
        .checked_add(json_size(&status)?)
        .and_then(|n| n.checked_add(2))
        .ok_or(RecordRejection::Budget)
}
fn object_entry_size(id: &str, object: &SealedRecordObject) -> Result<usize, RecordRejection> {
    json_size(&id)?
        .checked_add(json_size(object)?)
        .and_then(|n| n.checked_add(2))
        .ok_or(RecordRejection::Budget)
}
fn hex(id: &RecordObjectId) -> String {
    let mut result = String::with_capacity(64);
    crate::append_hex(&mut result, id);
    result
}
fn reject_budget(record_bytes: usize, legacy_bytes: usize) -> Result<(), RecordRejection> {
    if record_bytes
        .checked_add(legacy_bytes)
        .is_none_or(|n| n > MAX_APPLICATION_JSON_BYTES)
    {
        Err(RecordRejection::Budget)
    } else {
        Ok(())
    }
}
impl RecordState {
    pub(crate) fn usage(&mut self, legacy_bytes: usize) -> Result<RecordUsage, RecordRejection> {
        if self.cache.is_none() {
            self.cache = Some(self.build_cache(legacy_bytes)?);
        }
        Ok(RecordUsage {
            encoded_bytes: self
                .cache
                .as_ref()
                .ok_or(RecordRejection::Invalid)?
                .encoded_bytes
                .checked_add(legacy_bytes)
                .ok_or(RecordRejection::Budget)?,
            object_count: self.objects.len(),
            encoded_limit: MAX_APPLICATION_JSON_BYTES,
        })
    }
    /// Read-only complete publication admission; no object bytes are cloned.
    /// Existing unreachable objects are charged again because maintenance may
    /// remove them before staging. Current reachable reuse is byte-identical.
    pub(crate) fn preflight_publication(
        &self,
        objects: &[SealedRecordObject],
        root: &PublishedRecordRoot,
        usage: RecordUsage,
    ) -> Result<usize, RecordRejection> {
        root.validate()?;
        let expected = self.published_digest().ok_or(RecordRejection::StaleRoot)?;
        if root.base != RecordRootBase::RecordsV5(expected) {
            return Err(RecordRejection::StaleRoot);
        }
        let reachable = self.reachable()?;
        let cache = self.cache.as_ref().ok_or(RecordRejection::Invalid)?;
        let mut incoming = BTreeMap::<String, (&SealedRecordObject, u8)>::new();
        let mut growth = json_size(&Some(root))?;
        let mut count = usage.object_count;
        for object in objects {
            object.validate()?;
            // Serialize the actual command shape with the largest serial. The
            // borrowing variant avoids cloning sealed buffers just to count.
            #[derive(Serialize)]
            struct Request<'a> {
                serial: u64,
                records_v5: Command<'a>,
            }
            #[derive(Serialize)]
            enum Command<'a> {
                Stage { object: &'a SealedRecordObject },
            }
            if json_size(&Request {
                serial: u64::MAX,
                records_v5: Command::Stage { object },
            })? > MAX_RECORD_COMMAND_BYTES
            {
                return Err(RecordRejection::Budget);
            }
            let id = hex(&object.reference.id);
            if let Some((prior, _)) = incoming.get(&id) {
                if *prior != object {
                    return Err(RecordRejection::ImmutableConflict);
                }
                continue;
            }
            if self.objects.get(&id).is_some_and(|prior| prior != object) {
                return Err(RecordRejection::ImmutableConflict);
            }
            let mut depth = 1_u8;
            for child in &object.children {
                let child_id = hex(&child.id);
                let (found, child_depth) = if let Some((found, depth)) = incoming.get(&child_id) {
                    (*found, *depth)
                } else {
                    (
                        self.objects
                            .get(&child_id)
                            .ok_or(RecordRejection::MissingDependency)?,
                        *cache
                            .depths
                            .get(&child_id)
                            .ok_or(RecordRejection::MissingDependency)?,
                    )
                };
                if &found.reference != child {
                    return Err(RecordRejection::ImmutableConflict);
                }
                depth = depth.max(child_depth.checked_add(1).ok_or(RecordRejection::Budget)?);
            }
            if depth > MAX_DEPTH {
                return Err(RecordRejection::Budget);
            }
            if !reachable.contains(&id) {
                growth = growth
                    .checked_add(object_entry_size(&id, object)?)
                    .ok_or(RecordRejection::Budget)?;
                count = count.checked_add(1).ok_or(RecordRejection::Budget)?;
            }
            incoming.insert(id, (object, depth));
        }
        for reference in &root.direct_refs {
            let id = hex(&reference.id);
            let object = incoming
                .get(&id)
                .map(|(o, _)| *o)
                .or_else(|| self.objects.get(&id))
                .ok_or(RecordRejection::MissingDependency)?;
            if &object.reference != reference {
                return Err(RecordRejection::ImmutableConflict);
            }
        }
        #[derive(Serialize)]
        struct Request<'a> {
            serial: u64,
            records_v5: Command<'a>,
        }
        #[derive(Serialize)]
        enum Command<'a> {
            Publish { root: &'a PublishedRecordRoot },
        }
        if count > MAX_OBJECTS
            || json_size(&Request {
                serial: u64::MAX,
                records_v5: Command::Publish { root },
            })? > MAX_RECORD_COMMAND_BYTES
        {
            return Err(RecordRejection::Budget);
        }
        reject_budget(usage.encoded_bytes, growth)?;
        Ok(growth)
    }

    pub(crate) fn prunable(&self, limit: usize) -> Result<Vec<RecordObjectId>, RecordRejection> {
        if limit == 0 || limit > 256 {
            return Err(RecordRejection::Invalid);
        }
        let reachable = self.reachable()?;
        let referenced: BTreeSet<_> = self
            .objects
            .values()
            .flat_map(|o| o.children.iter().map(|r| hex(&r.id)))
            .collect();
        Ok(self
            .objects
            .iter()
            .filter(|(id, _)| !reachable.contains(*id) && !referenced.contains(*id))
            .take(limit)
            .map(|(_, o)| o.reference.id)
            .collect())
    }
    pub(crate) fn published_digest(&self) -> Option<[u8; 32]> {
        self.published.as_ref().map(|root| root.envelope.digest())
    }
    pub(crate) fn published(&self) -> Option<PublishedRecordRoot> {
        self.published.clone()
    }
    pub(crate) fn object(
        &self,
        reference: &RecordObjectRef,
    ) -> Result<Option<SealedRecordObject>, RecordRejection> {
        let object = self.objects.get(&hex(&reference.id));
        if object.is_some_and(|o| &o.reference != reference) {
            return Err(RecordRejection::ImmutableConflict);
        }
        Ok(object.cloned())
    }
    pub(crate) fn inventory(
        &self,
        after: Option<RecordObjectId>,
        limit: usize,
    ) -> Result<Vec<RecordObjectRef>, RecordRejection> {
        use std::ops::Bound::{Excluded, Unbounded};
        if limit == 0 || limit > 256 {
            return Err(RecordRejection::Invalid);
        }
        let bound = after.map(|id| Excluded(hex(&id))).unwrap_or(Unbounded);
        Ok(self
            .objects
            .range((bound, Unbounded))
            .take(limit)
            .map(|(_, object)| object.reference.clone())
            .collect())
    }
    fn depth(
        &self,
        id: &str,
        memo: &mut HashMap<String, u8>,
        visiting: &mut BTreeSet<String>,
    ) -> Result<u8, RecordRejection> {
        if let Some(depth) = memo.get(id) {
            return Ok(*depth);
        }
        if visiting.len() >= MAX_DEPTH as usize || !visiting.insert(id.to_owned()) {
            return Err(RecordRejection::Invalid);
        }
        let object = self
            .objects
            .get(id)
            .ok_or(RecordRejection::MissingDependency)?;
        let mut depth = 1;
        for child in &object.children {
            let child_id = hex(&child.id);
            let found = self
                .objects
                .get(&child_id)
                .ok_or(RecordRejection::MissingDependency)?;
            if &found.reference != child {
                return Err(RecordRejection::ImmutableConflict);
            }
            depth = depth.max(
                self.depth(&child_id, memo, visiting)?
                    .checked_add(1)
                    .ok_or(RecordRejection::Budget)?,
            );
        }
        if depth > MAX_DEPTH {
            return Err(RecordRejection::Budget);
        }
        visiting.remove(id);
        memo.insert(id.into(), depth);
        Ok(depth)
    }
    fn build_cache(&self, legacy_bytes: usize) -> Result<RecordCache, RecordRejection> {
        self.build_cache_with_preparation(legacy_bytes, self.legacy_migration_prepared.as_ref())
    }
    fn build_cache_with_preparation(
        &self,
        legacy_bytes: usize,
        prepared: Option<&LegacyStatusIdentity>,
    ) -> Result<RecordCache, RecordRejection> {
        if let Some(identity) = prepared {
            identity.validate()?;
            if self.published.is_some() {
                return Err(RecordRejection::Invalid);
            }
        }
        if self.objects.len() > MAX_OBJECTS {
            return Err(RecordRejection::Budget);
        }
        let mut cache = RecordCache {
            encoded_bytes: 128 + json_size(&self.published)? + json_size(&prepared)?,
            depths: HashMap::new(),
        };
        for (id, object) in &self.objects {
            object.validate()?;
            if *id != hex(&object.reference.id) {
                return Err(RecordRejection::Invalid);
            }
            cache.encoded_bytes = cache
                .encoded_bytes
                .checked_add(object_entry_size(id, object)?)
                .ok_or(RecordRejection::Budget)?;
            reject_budget(cache.encoded_bytes, legacy_bytes)?;
            self.depth(id, &mut cache.depths, &mut BTreeSet::new())?;
        }
        if let Some(root) = &self.published {
            root.validate()?;
            self.check_refs(&root.direct_refs)?;
        }
        // Cleanup may start from an oversized legacy map. Only its empty
        // migration fence is exempt; every Stage and published graph keeps the
        // unchanged typed budget. Full durable artifact bounds still apply.
        if prepared.is_none() || !self.objects.is_empty() {
            reject_budget(cache.encoded_bytes, legacy_bytes)?;
        }
        Ok(cache)
    }
    pub(crate) fn prepared_identity(&self) -> Option<LegacyStatusIdentity> {
        self.legacy_migration_prepared
    }
    pub(crate) fn prepare_legacy_migration(
        &mut self,
        identity: LegacyStatusIdentity,
        legacy_bytes: usize,
    ) -> Result<(), RecordRejection> {
        if self.published.is_some() {
            return Err(RecordRejection::LegacyFenced);
        }
        let cache = self.build_cache_with_preparation(legacy_bytes, Some(&identity))?;
        self.legacy_migration_prepared = Some(identity);
        self.cache = Some(cache);
        Ok(())
    }
    pub(crate) fn validate(&self, legacy_bytes: usize) -> Result<(), RecordRejection> {
        self.build_cache(legacy_bytes).map(|_| ())
    }
    pub(crate) fn permits_legacy(&mut self, legacy_bytes: usize) -> Result<(), RecordRejection> {
        if self.published.is_some() {
            return Err(RecordRejection::LegacyFenced);
        }
        if self.cache.is_none() {
            self.cache = Some(self.build_cache(legacy_bytes)?);
        }
        reject_budget(
            self.cache
                .as_ref()
                .ok_or(RecordRejection::Invalid)?
                .encoded_bytes,
            legacy_bytes,
        )
    }
    fn check_refs(&self, refs: &[RecordObjectRef]) -> Result<(), RecordRejection> {
        for reference in refs {
            let object = self
                .objects
                .get(&hex(&reference.id))
                .ok_or(RecordRejection::MissingDependency)?;
            if &object.reference != reference {
                return Err(RecordRejection::ImmutableConflict);
            }
        }
        Ok(())
    }
    fn reachable(&self) -> Result<BTreeSet<String>, RecordRejection> {
        let mut seen = BTreeSet::new();
        let mut pending = self
            .published
            .as_ref()
            .map(|p| p.direct_refs.clone())
            .unwrap_or_default();
        while let Some(reference) = pending.pop() {
            let id = hex(&reference.id);
            if !seen.insert(id.clone()) {
                continue;
            }
            let object = self
                .objects
                .get(&id)
                .ok_or(RecordRejection::MissingDependency)?;
            if object.reference != reference {
                return Err(RecordRejection::ImmutableConflict);
            }
            pending.extend(object.children.iter().cloned());
        }
        Ok(seen)
    }
    pub(crate) fn apply(
        &mut self,
        command: &RecordCommand,
        current_base: RecordRootBase,
        legacy_bytes: usize,
    ) -> Result<(), RecordRejection> {
        if self.cache.is_none() {
            self.cache = Some(self.build_cache(legacy_bytes)?);
        }
        match command {
            // This maintenance command is validated against the legacy map by
            // StateMachine, before attempting any typed cache admission.
            RecordCommand::RetainLegacyChunks { .. } => Err(RecordRejection::Invalid),
            RecordCommand::Stage { object } => {
                object.validate()?;
                let id = hex(&object.reference.id);
                if let Some(existing) = self.objects.get(&id) {
                    return if existing == object {
                        Ok(())
                    } else {
                        Err(RecordRejection::ImmutableConflict)
                    };
                }
                self.check_refs(&object.children)?;
                if self.objects.len() >= MAX_OBJECTS {
                    return Err(RecordRejection::Budget);
                }
                let cache = self.cache.as_mut().ok_or(RecordRejection::Invalid)?;
                let mut depth = 1;
                for child in &object.children {
                    depth = depth.max(
                        cache
                            .depths
                            .get(&hex(&child.id))
                            .ok_or(RecordRejection::MissingDependency)?
                            .checked_add(1)
                            .ok_or(RecordRejection::Budget)?,
                    );
                }
                if depth > MAX_DEPTH {
                    return Err(RecordRejection::Budget);
                }
                let next = cache
                    .encoded_bytes
                    .checked_add(object_entry_size(&id, object)?)
                    .ok_or(RecordRejection::Budget)?;
                reject_budget(next, legacy_bytes)?;
                cache.encoded_bytes = next;
                cache.depths.insert(id.clone(), depth);
                self.objects.insert(id, object.clone());
                Ok(())
            }
            RecordCommand::Publish { root } => {
                root.validate()?;
                if self.published.as_ref() == Some(root) {
                    return Ok(());
                }
                if root.base != current_base {
                    return Err(RecordRejection::StaleRoot);
                }
                self.check_refs(&root.direct_refs)?;
                let cache = self.cache.as_mut().ok_or(RecordRejection::Invalid)?;
                let next = cache
                    .encoded_bytes
                    .checked_sub(json_size(&self.published)?)
                    .and_then(|n| n.checked_sub(json_size(&self.legacy_migration_prepared).ok()?))
                    .and_then(|n| {
                        n.checked_add(json_size(&Option::<LegacyStatusIdentity>::None).ok()?)
                    })
                    .and_then(|n| n.checked_add(json_size(&Some(root)).ok()?))
                    .ok_or(RecordRejection::Budget)?;
                reject_budget(next, legacy_bytes)?;
                cache.encoded_bytes = next;
                self.published = Some(root.clone());
                self.legacy_migration_prepared = None;
                Ok(())
            }
            RecordCommand::Prune { expected_root, ids } => {
                let current = self
                    .published
                    .as_ref()
                    .map(|root| root.envelope.digest())
                    .unwrap_or([0; 32]);
                if *expected_root != current {
                    return Err(RecordRejection::StaleRoot);
                }
                if ids.is_empty() || ids.len() > 256 {
                    return Err(RecordRejection::Invalid);
                }
                let ids: BTreeSet<_> = ids.iter().map(hex).collect();
                let reachable = self.reachable()?;
                if ids.iter().any(|id| reachable.contains(id)) {
                    return Err(RecordRejection::Reachable);
                }
                if self.objects.iter().any(|(id, o)| {
                    !ids.contains(id) && o.children.iter().any(|c| ids.contains(&hex(&c.id)))
                }) {
                    return Err(RecordRejection::ReferencedByStaged);
                }
                let mut removed = 0_usize;
                for id in &ids {
                    if let Some(object) = self.objects.get(id) {
                        removed = removed
                            .checked_add(object_entry_size(id, object)?)
                            .ok_or(RecordRejection::Budget)?;
                    }
                }
                let cache = self.cache.as_mut().ok_or(RecordRejection::Invalid)?;
                let next = cache
                    .encoded_bytes
                    .checked_sub(removed)
                    .ok_or(RecordRejection::Invalid)?;
                for id in &ids {
                    self.objects.remove(id);
                    cache.depths.remove(id);
                }
                cache.encoded_bytes = next;
                Ok(())
            }
        }
    }
}
