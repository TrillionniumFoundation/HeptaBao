//! Detached native KV2 record foundation, stage A only.
//!
//! These records encode the actual KV2 runtime owner, without the experimental
//! shard codec's string payload or contiguous 32-version restrictions. Neither
//! this codec nor its read-only verifier publishes a Service root, writes
//! storage, grants reader admission, or authorizes migration. Reader fencing,
//! namespace custody, HA and atomic publication remain separate prerequisites.
use super::*;
use crate::state_records::{
    AddressKey, Kv1Index, Kv1Key, Kv1Root, MAX_GRAPH_BYTES, MAX_VALUE_BYTES, ObjectId, ObjectRef,
    RecordError, RecordReader, StagedObject,
};
use zeroize::Zeroizing;

const FORMAT: &str = "heptabao-kv2-native-records-v6-stage-a";
pub(crate) const NATIVE_FORMAT: &str = FORMAT;
const KEY_DOMAIN: &[u8] = b"kv2-native-v6-stage-a/scoped-address-key";
const PATH_DOMAIN: &[u8] = b"kv2-native-v6-stage-a/path-token";
const MAX_METADATA_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 16 * 1024;
const MAX_PATHS: usize = 10_000;
const MAX_RECORDS: usize = 100_000;

type CodecResult<T> = std::result::Result<T, RecordError>;

// Own decoded runtime state even while typed closure is still being checked.
// Actual EntryState/SecretJson destructors wipe metadata and payloads; this
// detached owner additionally erases the owning path map on every exit.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct DetachedOwner(Kv2);
impl Deref for DetachedOwner {
    type Target = Kv2;
    fn deref(&self) -> &Kv2 {
        &self.0
    }
}
impl DerefMut for DetachedOwner {
    fn deref_mut(&mut self) -> &mut Kv2 {
        &mut self.0
    }
}
impl Drop for DetachedOwner {
    fn drop(&mut self) {
        for (mut path, entry) in std::mem::take(&mut self.0.entries) {
            path.zeroize();
            drop(entry);
        }
    }
}

/// Independent authority scope to which the detached record graph is bound.
#[derive(Clone, Copy)]
pub struct NativeScope<'a> {
    pub namespace: &'a str,
    pub mount: &'a str,
    pub incarnation: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    namespace: String,
    mount: String,
    incarnation: u64,
}
impl Drop for Scope {
    fn drop(&mut self) {
        self.namespace.zeroize();
        self.mount.zeroize();
    }
}
impl Scope {
    fn new(input: NativeScope<'_>) -> CodecResult<Self> {
        // Validate borrowed fields before making any owning copies.
        Kv1Key::new(input.namespace, input.mount, input.incarnation, "config")?;
        Ok(Self {
            namespace: input.namespace.into(),
            mount: input.mount.into(),
            incarnation: input.incarnation,
        })
    }
    fn key(&self, path: &str) -> CodecResult<Kv1Key> {
        Kv1Key::new(&self.namespace, &self.mount, self.incarnation, path)
    }
    fn matches(&self, other: &Self) -> bool {
        self.namespace == other.namespace
            && self.mount == other.mount
            && self.incarnation == other.incarnation
    }
    fn matches_key(&self, key: &Kv1Key) -> bool {
        self.namespace == key.namespace()
            && self.mount == key.mount()
            && self.incarnation == key.incarnation()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MountCell {
    format: String,
    scope: Scope,
    config: Config,
    lossless_format: Option<u32>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathCell {
    format: String,
    scope: Scope,
    path: String,
    // EntryState's serde representation is the real runtime metadata schema.
    // Its version data fields must be absent here; headers bind payload presence.
    metadata: EntryState,
    payload_versions: BTreeSet<u64>,
}
impl Drop for PathCell {
    fn drop(&mut self) {
        self.path.zeroize();
    }
}

fn serialize(value: &impl Serialize, limit: usize) -> CodecResult<Zeroizing<Vec<u8>>> {
    crate::secret_serde::to_vec(value, limit).map_err(|error| match error {
        crate::secret_serde::Error::TooLarge => RecordError::TooLarge,
        crate::secret_serde::Error::Serialization => RecordError::Corrupt,
    })
}

fn canonical<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
    limit: usize,
) -> CodecResult<T> {
    if bytes.len() > limit {
        return Err(RecordError::TooLarge);
    }
    let value: T = serde_json::from_slice(bytes).map_err(|_| RecordError::Corrupt)?;
    if serialize(&value, limit)?.as_slice() != bytes {
        return Err(RecordError::Corrupt);
    }
    Ok(value)
}

// Count containers before the real runtime deserializer allocates histories.
// RawValue borrows payloads; this does not project or normalize secret JSON.
fn bounded_raw_values<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
    limit: usize,
) -> std::result::Result<Vec<&'de serde_json::value::RawValue>, D::Error> {
    struct Values(usize);
    impl<'de> serde::de::Visitor<'de> for Values {
        type Value = Vec<&'de serde_json::value::RawValue>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded KV2 runtime map")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut values = Vec::new();
            while map.next_key::<serde::de::IgnoredAny>()?.is_some() {
                if values.len() >= self.0 {
                    return Err(serde::de::Error::custom("KV2 runtime map bound exceeded"));
                }
                values.push(map.next_value()?);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(Values(limit))
}
fn bounded_paths<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<&'de serde_json::value::RawValue>, D::Error> {
    bounded_raw_values(deserializer, MAX_PATHS)
}
fn bounded_versions<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<&'de serde_json::value::RawValue>, D::Error> {
    bounded_raw_values(deserializer, MAX_RETAINED_VERSIONS as usize)
}
#[derive(Deserialize)]
struct OwnerBounds<'a> {
    #[serde(borrow, deserialize_with = "bounded_paths")]
    entries: Vec<&'a serde_json::value::RawValue>,
}
#[derive(Deserialize, Default)]
struct PrecisionBounds<'a> {
    #[serde(default, borrow, deserialize_with = "bounded_versions")]
    versions: Vec<&'a serde_json::value::RawValue>,
}
#[derive(Deserialize)]
struct EntryBounds<'a> {
    #[serde(borrow, deserialize_with = "bounded_versions")]
    versions: Vec<&'a serde_json::value::RawValue>,
    #[serde(default, borrow)]
    precision: PrecisionBounds<'a>,
    #[serde(default, borrow)]
    custom_metadata: Option<&'a serde_json::value::RawValue>,
}
fn preflight_entry(entry: &serde_json::value::RawValue) -> CodecResult<usize> {
    let bound: EntryBounds<'_> =
        serde_json::from_str(entry.get()).map_err(|_| RecordError::Corrupt)?;
    // Precision is bounded independently even if every entry is malformed.
    if bound.precision.versions.len() > MAX_RETAINED_VERSIONS as usize {
        return Err(RecordError::TooLarge);
    }
    if let Some(metadata) = bound.custom_metadata {
        let mut decoder = serde_json::Deserializer::from_str(metadata.get());
        bounded_raw_values(&mut decoder, 64).map_err(|_| RecordError::Corrupt)?;
    }
    Ok(bound.versions.len())
}
fn preflight_owner(bytes: &[u8]) -> CodecResult<()> {
    if bytes.len() > MAX_GRAPH_BYTES {
        return Err(RecordError::TooLarge);
    }
    let bounds: OwnerBounds<'_> =
        serde_json::from_slice(bytes).map_err(|_| RecordError::Corrupt)?;
    let mut records = 1_usize;
    for entry in bounds.entries {
        let versions = preflight_entry(entry)?;
        records = records
            .checked_add(1 + versions)
            .filter(|count| *count <= MAX_RECORDS)
            .ok_or(RecordError::TooLarge)?;
    }
    Ok(())
}

fn graph_key(base: &AddressKey, scope: &Scope) -> CodecResult<Arc<AddressKey>> {
    let scope_bytes = serialize(scope, MAX_CONFIG_BYTES)?;
    let mut derived = base.digest(KEY_DOMAIN, &scope_bytes)?;
    let key = AddressKey::from_bytes(derived);
    derived.zeroize();
    Ok(key)
}

fn token(key: &AddressKey, path: &str) -> CodecResult<String> {
    valid_path(path).map_err(|_| RecordError::Invalid)?;
    let digest = key.digest(PATH_DOMAIN, path.as_bytes())?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 15)]));
    }
    Ok(encoded)
}

fn metadata_key(scope: &Scope, key: &AddressKey, path: &str) -> CodecResult<Kv1Key> {
    scope.key(&format!("metadata/{}", token(key, path)?))
}
fn payload_key(scope: &Scope, key: &AddressKey, path: &str, version: u64) -> CodecResult<Kv1Key> {
    scope.key(&format!("payload/{}/{version:020}", token(key, path)?))
}

fn valid_config(config: &Config) -> bool {
    config.max_versions <= MAX_RETAINED_VERSIONS
        && config.delete_version_after <= 315_360_000
        && config.delete_version_after_nanos < 1_000_000_000
}
fn consistent_time(seconds: u64, precise: Option<Timestamp>) -> bool {
    Timestamp::whole(seconds).is_ok()
        && precise.is_none_or(|at| at.seconds() == seconds && lossless::subsecond(at).is_some())
}

// Native records preserve sparse runtime histories. This deliberately does not
// impose the aggregate lossless importer's contiguous-history input contract.
fn validate_owner(owner: &Kv2) -> CodecResult<()> {
    validate_owner_structure(owner, false)
}

fn validate_owner_structure(owner: &Kv2, metadata_only: bool) -> CodecResult<()> {
    if owner.entries.len() > MAX_PATHS {
        return Err(RecordError::TooLarge);
    }
    if !valid_config(&owner.config)
        || owner.lossless_format.is_some_and(|v| v != 1)
        || (owner.has_lossless_import_state() && owner.lossless_format != Some(1))
    {
        return Err(RecordError::Corrupt);
    }
    let mut records = 1_usize;
    for (path, entry) in &owner.entries {
        valid_path(path).map_err(|_| RecordError::Corrupt)?;
        if entry.versions.len() > MAX_RETAINED_VERSIONS as usize {
            return Err(RecordError::TooLarge);
        }
        records = records
            .checked_add(1 + entry.versions.len())
            .filter(|count| *count <= MAX_RECORDS)
            .ok_or(RecordError::TooLarge)?;
        if !valid_config(&entry.config)
            || entry.current_version > i64::MAX as u64
            || entry.oldest_version > entry.current_version
            || (entry.current_version > 0 && !entry.versions.contains_key(&entry.current_version))
            || !consistent_time(entry.created_at, entry.precision.created_at)
            || !consistent_time(entry.updated_at, entry.precision.updated_at)
            || entry.custom_metadata.as_ref().is_some_and(|metadata| {
                metadata.len() > 64
                    || metadata
                        .iter()
                        .any(|(key, value)| key.is_empty() || key.len() > 128 || value.len() > 512)
            })
        {
            return Err(RecordError::Corrupt);
        }
        for (number, version) in &entry.versions {
            let precise = entry.version_precision(*number);
            if *number == 0
                || *number < entry.oldest_version
                || *number > entry.current_version
                || !consistent_time(version.created_at, precise.created_at)
                || version
                    .deletion_at
                    .is_some_and(|seconds| !consistent_time(seconds, precise.deletion_at))
                || (version.destroyed && version.data.is_some())
                || (!version.destroyed
                    && !(metadata_only && version.data.is_none())
                    && !version
                        .data
                        .as_ref()
                        .is_some_and(|v| v.expose().is_object()))
            {
                return Err(RecordError::Corrupt);
            }
        }
        for (number, precise) in &entry.precision.versions {
            let version = entry.versions.get(number).ok_or(RecordError::Corrupt)?;
            if (precise.created_at.is_none()
                && precise.deletion_at.is_none()
                && precise.source_deletion_at.is_none())
                || !consistent_time(version.created_at, precise.created_at)
                || match version.deletion_at {
                    Some(seconds) => !consistent_time(seconds, precise.deletion_at),
                    None => precise.deletion_at.is_some(),
                }
                || precise.source_deletion_at.is_some_and(|source| {
                    (
                        source.seconds(),
                        source.duration_since_epoch().subsec_nanos(),
                    ) < (
                        version.created_at,
                        precise
                            .created_at
                            .map_or(0, |at| at.duration_since_epoch().subsec_nanos()),
                    )
                })
            {
                return Err(RecordError::Corrupt);
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
struct NativeGraph {
    scope: Scope,
    key: Arc<AddressKey>,
    index: Kv1Index,
    format: String,
    paged: Option<paged::PagedPayloads>,
}

#[cfg(any(test, feature = "fixture-native-v6-service"))]
#[path = "kv2_native_install.rs"]
mod install;
#[path = "kv2_native_mutation.rs"]
mod mutation;
#[path = "kv2_native_paged.rs"]
mod paged;
pub(crate) use paged::{MAX_PAGED_LOGICAL_BYTES, PAGED_NATIVE_FORMAT};

/// A private decoded graph view and its authenticated graph cache. This type
/// grants no storage writes or authority to install a writable Service owner.
#[derive(Clone)]
pub(crate) struct NativeReadView {
    owner: DetachedOwner,
    graph: Option<NativeGraph>,
    pending: mutation::PendingPaths,
}
// A live native view cannot be saved or reconstructed as inline KV2 JSON.
// The independent graph and actual custody reader are mandatory.
impl Serialize for NativeReadView {
    fn serialize<S: serde::Serializer>(
        &self,
        _serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(
            "native KV2 owner requires separate authenticated records",
        ))
    }
}
impl<'de> Deserialize<'de> for NativeReadView {
    fn deserialize<D: serde::Deserializer<'de>>(
        _decoder: D,
    ) -> std::result::Result<Self, D::Error> {
        Err(serde::de::Error::custom(
            "native KV2 owner requires an authenticated graph reader",
        ))
    }
}

impl NativeReadView {
    pub(crate) fn contains(&self, path: &str) -> bool {
        self.owner.contains(path)
    }

    pub(crate) fn has_metadata_cas_state(&self) -> bool {
        self.owner.has_metadata_cas_state()
    }
    pub(crate) fn validate_lossless_state(&self) -> Result<()> {
        if self.is_paged() {
            self.validate_paged_candidate()
                .map_err(|_| error(503, "native paged metadata rejected"))
        } else {
            self.owner.validate_lossless_state()
        }
    }
    #[cfg(test)]
    pub(crate) fn has_lossless_json_state(&self) -> bool {
        self.owner.has_lossless_json_state()
    }
    #[cfg(any(test, feature = "fixture-native-v6-service"))]
    pub(crate) fn matches_authenticated_root(
        &self,
        parent: &AddressKey,
        scope: NativeScope<'_>,
        root: &Kv1Root,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<bool> {
        check()?;
        let candidate = self.encode(parent, scope, check)?;
        let matches = candidate.root() == *root;
        check()?;
        Ok(matches)
    }
    #[cfg(test)]
    fn advance_authenticated_cache(
        &mut self,
        parent: &AddressKey,
        scope: NativeScope<'_>,
        expected: &Kv1Root,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<()> {
        let graph = self.encode(parent, scope, check)?;
        if graph.root() != *expected {
            return Err(RecordError::Corrupt);
        }
        check()?;
        self.graph = Some(graph.0);
        if self.is_paged() {
            self.erase_hydrated_payloads();
            if let Some(paged) = self.graph.as_mut().and_then(|graph| graph.paged.as_mut()) {
                paged.clear_new_blocks();
            }
        }
        self.pending = mutation::PendingPaths::default();
        check()
    }
    #[cfg(any(test, feature = "fixture-native-v6-service"))]
    fn cached_scope_matches(&self, input: NativeScope<'_>) -> CodecResult<bool> {
        let scope = Scope::new(input)?;
        Ok(self
            .graph
            .as_ref()
            .is_some_and(|graph| graph.scope.matches(&scope)))
    }
    pub(crate) fn open(
        base: &AddressKey,
        scope: NativeScope<'_>,
        root: Kv1Root,
        reader: &impl RecordReader,
    ) -> CodecResult<Self> {
        let graph = NativeGraph::open(base, scope, root, reader)?;
        let owner = graph.decode()?;
        Ok(Self {
            owner,
            graph: Some(graph),
            pending: mutation::PendingPaths::default(),
        })
    }
    pub(crate) fn read(
        &self,
        method: &str,
        path: &str,
        body: &Value,
        now: Timestamp,
    ) -> Result<EngineResponse> {
        if self.is_paged() && matches!(path.split_once('/').map(|v| v.0), Some("data" | "subkeys"))
        {
            return Err(error(
                503,
                "native paged payload requires its original checked source",
            ));
        }
        self.owner.handle_read_precise(method, path, body, now)
    }
    pub(crate) fn counts(&self) -> (usize, usize, usize) {
        (
            self.owner.entries.len(),
            self.owner
                .entries
                .values()
                .map(|entry| entry.versions.len())
                .sum(),
            if let Some(paged) = self.graph.as_ref().and_then(|graph| graph.paged.as_ref()) {
                paged.payload_count()
            } else {
                self.owner
                    .entries
                    .values()
                    .flat_map(|entry| entry.versions.values())
                    .filter(|version| version.data.is_some())
                    .count()
            },
        )
    }
    pub(crate) fn has_lossless_state(&self) -> bool {
        self.owner.has_lossless_import_state()
            || (self.is_paged() && self.owner.lossless_format == Some(1))
    }
    /// Mutate only a detached owner. This grants no Service or storage authority.
    pub(crate) fn mutate(
        &mut self,
        method: &str,
        path: &str,
        body: &Value,
        now: Timestamp,
    ) -> Result<EngineResponse> {
        // Keep only a shared baseline for the selected path. Existing payloads
        // remain shared and are never serialized merely to detect a change.
        let captured = self.pending.capture(&self.owner, path)?;
        let response = self.owner.handle_precise(method, path, body, now);
        if !response.as_ref().is_ok_and(|response| response.mutated) {
            self.pending.discard(captured);
        }
        response
    }
    #[cfg(any(test, feature = "fixture-native-v6-service"))]
    pub(crate) fn encode(
        &self,
        parent: &AddressKey,
        scope: NativeScope<'_>,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<NativeCellGraph> {
        if self.is_paged() {
            return self.encode_paged(parent, scope, check);
        }
        match &self.graph {
            Some(graph) => Ok(NativeCellGraph(graph.with_updates(
                &self.owner,
                parent,
                scope,
                &self.pending,
                check,
            )?)),
            None => NativeCellGraph::encode(&self.owner, parent, scope, check),
        }
    }
    #[cfg(test)]
    pub(crate) fn fixture_lossless_import(bytes: &[u8]) -> CodecResult<Self> {
        let owner = Kv2::from_lossless_import_json(bytes).map_err(|_| RecordError::Corrupt)?;
        validate_owner(&owner)?;
        Ok(Self {
            owner: DetachedOwner(owner),
            graph: None,
            pending: mutation::PendingPaths::default(),
        })
    }
    #[cfg(test)]
    pub(crate) fn fixture_owner(bytes: &[u8]) -> CodecResult<Self> {
        preflight_owner(bytes)?;
        let owner: DetachedOwner = canonical(bytes, MAX_GRAPH_BYTES)?;
        validate_owner(&owner)?;
        Ok(Self {
            owner,
            graph: None,
            pending: mutation::PendingPaths::default(),
        })
    }
}

/// Actual native codec graph for custody projection. The caller must keep the
/// graph inside its original key/deadline callback and encrypt every object
/// before allowing a retained pin to leave that callback.
#[cfg(any(test, feature = "fixture-native-v6-service"))]
pub(crate) struct NativeCellGraph(NativeGraph);
#[cfg(any(test, feature = "fixture-native-v6-service"))]
impl NativeCellGraph {
    fn encode(
        owner: &Kv2,
        parent: &AddressKey,
        scope: NativeScope<'_>,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<Self> {
        Ok(Self(NativeGraph::encode_checked(
            owner, parent, scope, check,
        )?))
    }
    pub(crate) fn root(&self) -> Kv1Root {
        self.0.index.root()
    }
    pub(crate) fn visit_objects(
        &self,
        mut visit: impl FnMut(&Arc<StagedObject>) -> CodecResult<()>,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<()> {
        self.0.index.visit_objects(|object| {
            check()?;
            visit(object)?;
            check()
        })?;
        if let Some(paged) = &self.0.paged {
            paged.visit_new_blocks(&mut visit, check)?;
        }
        check()
    }
    #[cfg(test)]
    pub(crate) fn open_view(
        parent: &AddressKey,
        scope: NativeScope<'_>,
        root: Kv1Root,
        reader: &impl RecordReader,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<NativeReadView> {
        check()?;
        let scope = Scope::new(scope)?;
        let key = graph_key(parent, &scope)?;
        let index = Kv1Index::open(Arc::clone(&key), root, reader)?;
        check()?;
        let graph = NativeGraph {
            scope,
            key,
            index,
            format: FORMAT.into(),
            paged: None,
        };
        let owner = graph.decode_checked(check)?;
        Ok(NativeReadView {
            owner,
            graph: Some(graph),
            pending: mutation::PendingPaths::default(),
        })
    }
}

impl EngineState {
    pub(crate) fn v6_namespace_paths(&self) -> impl Iterator<Item = &str> {
        self.namespaces.keys().map(String::as_str)
    }
    /// The metadata-only V6 engines owner has exactly one pristine placeholder
    /// for every declared native graph. Legacy values are never fallback data.
    pub(crate) fn validate_v6_kv2_placeholders(
        &self,
        scopes: &[crate::state_record_root_v6::MountScope],
    ) -> Result<()> {
        if !self.namespaces.contains_key("") {
            return Err(error(
                503,
                "V6 engines metadata requires an explicit root namespace",
            ));
        }
        let mut actual = BTreeSet::new();
        for (namespace, owner) in &self.namespaces {
            for (mount, descriptor) in &owner.mounts {
                if matches!(descriptor.backend, Backend::Kv2Native(_)) {
                    return Err(error(
                        503,
                        "V6 engines metadata contains a live native owner",
                    ));
                }
                if let Backend::Kv2(engine) = &descriptor.backend {
                    if !engine.is_pristine_for_import() {
                        return Err(error(
                            503,
                            "V6 KV2 metadata contains opaque payload or configuration",
                        ));
                    }
                    actual.insert(crate::state_record_root_v6::MountScope {
                        namespace: namespace.clone(),
                        mount: mount.clone(),
                        incarnation: descriptor.incarnation,
                    });
                }
            }
        }
        if actual != scopes.iter().cloned().collect() {
            return Err(error(503, "V6 KV2 graph and mount ownership differ"));
        }
        Ok(())
    }
}

/// Borrowed preflight rejects opaque KV2 payloads before the real engines
/// deserializer can allocate them. Other owners keep their existing decoder.
pub(crate) fn preflight_v6_kv2_metadata(bytes: &[u8]) -> CodecResult<()> {
    fn values<'de, D: serde::Deserializer<'de>>(
        decoder: D,
    ) -> std::result::Result<Vec<&'de serde_json::value::RawValue>, D::Error> {
        bounded_raw_values(decoder, MAX_RECORDS)
    }
    #[derive(Deserialize)]
    struct Engine<'a> {
        #[serde(borrow, deserialize_with = "values")]
        namespaces: Vec<&'a serde_json::value::RawValue>,
    }
    #[derive(Deserialize)]
    struct Namespace<'a> {
        #[serde(borrow, deserialize_with = "values")]
        mounts: Vec<&'a serde_json::value::RawValue>,
    }
    #[derive(Deserialize)]
    struct Mount<'a> {
        #[serde(borrow)]
        backend: &'a serde_json::value::RawValue,
    }
    #[derive(Deserialize)]
    struct BackendCell<'a> {
        #[serde(default, borrow, rename = "Kv2")]
        kv2: Option<&'a serde_json::value::RawValue>,
    }
    let engine: Engine<'_> = serde_json::from_slice(bytes).map_err(|_| RecordError::Corrupt)?;
    let pristine = serialize(&Kv2::default(), MAX_CONFIG_BYTES)?;
    let mut count = 0_usize;
    let mut native = 0_usize;
    for owner in engine.namespaces {
        let namespace: Namespace<'_> =
            serde_json::from_str(owner.get()).map_err(|_| RecordError::Corrupt)?;
        count = count
            .checked_add(namespace.mounts.len())
            .filter(|sum| *sum <= MAX_RECORDS)
            .ok_or(RecordError::TooLarge)?;
        for mount in namespace.mounts {
            let mount: Mount<'_> =
                serde_json::from_str(mount.get()).map_err(|_| RecordError::Corrupt)?;
            if mount.backend.get().starts_with('{') {
                let backend: BackendCell<'_> =
                    serde_json::from_str(mount.backend.get()).map_err(|_| RecordError::Corrupt)?;
                if let Some(kv2) = backend.kv2 {
                    native += 1;
                    if native > crate::state_record_root_v6::MAX_KV2_MOUNTS {
                        return Err(RecordError::TooLarge);
                    }
                    if kv2.get().as_bytes() != pristine.as_slice() {
                        return Err(RecordError::Corrupt);
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) struct ReaderFixture {
    pub opaque: EngineState,
    pub roots: Vec<crate::state_record_root_v6::Kv2GraphRef>,
    pub objects: Vec<(crate::state_record_root_v6::MountScope, Arc<StagedObject>)>,
}
/// Project actual runtime KV2 owners into independent native graphs. Objects
/// leave only through the caller's checked visitor; no publication is granted.
/// The caller must encrypt each object before retaining it outside custody.
impl EngineState {
    #[cfg(any(test, feature = "fixture-native-v6-service"))]
    pub(crate) fn project_v6_native(
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
        // The V6 root enforces aggregate size and record limits. Enforce the
        // identical bounds BEFORE any object is handed to a caller-owned
        // encryption/staging visitor. Per-mount limits alone are insufficient:
        // otherwise earlier mounts can escape before a later root is denied.
        let mut pending = Vec::new();
        let mut total_bytes = 0_u64;
        let mut total_records = 0_u64;
        for (namespace, owner) in &mut opaque.namespaces {
            for (mount, descriptor) in &mut owner.mounts {
                check()?;
                if matches!(descriptor.backend, Backend::Kv2(_) | Backend::Kv2Native(_)) {
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
                            NativeCellGraph::encode(engine, parent, scope.borrowed(), check)?
                        }
                        Backend::Kv2Native(view) => view.encode(parent, scope.borrowed(), check)?,
                        _ => return Err(RecordError::Corrupt),
                    };
                    let root = graph.root();
                    let reference = root.reference.as_ref().ok_or(RecordError::Corrupt)?;
                    total_bytes = total_bytes
                        .checked_add(reference.payload_bytes)
                        .filter(|bytes| *bytes <= MAX_GRAPH_BYTES as u64)
                        .ok_or(RecordError::TooLarge)?;
                    total_records = total_records
                        .checked_add(reference.record_count)
                        .filter(|count| *count <= crate::state_record_root_v6::MAX_KV2_RECORDS)
                        .ok_or(RecordError::TooLarge)?;
                    pending.push((scope, graph, root));
                    descriptor.backend = Backend::Kv2(Kv2::default());
                    check()?;
                }
            }
        }
        let mut roots: Vec<_> = pending
            .iter()
            .map(
                |(scope, _, root)| crate::state_record_root_v6::Kv2GraphRef {
                    scope: scope.clone(),
                    graph_format: FORMAT.into(),
                    root: root.clone(),
                    logical_payload_bytes: 0,
                },
            )
            .collect();
        roots.sort_by(|a, b| a.scope.cmp(&b.scope));
        opaque
            .validate_v6_kv2_placeholders(
                &roots
                    .iter()
                    .map(|graph| graph.scope.clone())
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| RecordError::Corrupt)?;
        check()?;
        // All scopes and aggregate V6 root budgets are now proven. Custody is
        // independently checked before and after every encrypted-object visit.
        for (scope, graph, _) in &pending {
            graph.visit_objects(|object| visit(scope, object), check)?;
        }
        check()?;
        Ok((opaque, roots))
    }
}
#[cfg(test)]
pub(crate) fn reader_fixture(
    engines: &EngineState,
    parent: &AddressKey,
) -> CodecResult<ReaderFixture> {
    let mut objects = Vec::new();
    let (opaque, roots) = engines.project_v6_native(parent, &|| Ok(()), |scope, object| {
        objects.push((scope.clone(), Arc::clone(object)));
        Ok(())
    })?;
    Ok(ReaderFixture {
        opaque,
        roots,
        objects,
    })
}

impl NativeGraph {
    fn encode(owner: &Kv2, base: &AddressKey, input: NativeScope<'_>) -> CodecResult<Self> {
        Self::encode_checked(owner, base, input, &|| Ok(()))
    }

    fn encode_checked(
        owner: &Kv2,
        base: &AddressKey,
        input: NativeScope<'_>,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<Self> {
        check()?;
        let scope = Scope::new(input)?;
        validate_owner(owner)?;
        check()?;
        let key = graph_key(base, &scope)?;
        let mut index = Kv1Index::empty(Arc::clone(&key));
        let mount = MountCell {
            format: FORMAT.into(),
            scope: scope.clone(),
            config: owner.config.clone(),
            lossless_format: owner.lossless_format,
        };
        let bytes = serialize(&mount, MAX_CONFIG_BYTES)?;
        index = index.edit(scope.key("config")?, Some(&bytes))?.next;
        for (path, entry) in &owner.entries {
            check()?;
            let mut cell = PathCell {
                format: FORMAT.into(),
                scope: scope.clone(),
                path: path.clone(),
                metadata: (**entry).clone(),
                payload_versions: BTreeSet::new(),
            };
            for (number, version) in &mut cell.metadata.versions {
                check()?;
                if let Some(data) = version.data.take() {
                    let bytes = serialize(&data, MAX_VALUE_BYTES)?;
                    let record = payload_key(&scope, &key, path, *number)?;
                    index = index.edit(record, Some(&bytes))?.next;
                    cell.payload_versions.insert(*number);
                }
                check()?;
            }
            let bytes = serialize(&cell, MAX_METADATA_BYTES)?;
            let record = metadata_key(&scope, &key, path)?;
            if index.get(&record).is_some() {
                return Err(RecordError::Corrupt);
            }
            index = index.edit(record, Some(&bytes))?.next;
            check()?;
        }
        Ok(Self {
            scope,
            key,
            index,
            format: FORMAT.into(),
            paged: None,
        })
    }

    fn open(
        base: &AddressKey,
        input: NativeScope<'_>,
        root: Kv1Root,
        reader: &impl RecordReader,
    ) -> CodecResult<Self> {
        let scope = Scope::new(input)?;
        let key = graph_key(base, &scope)?;
        let index = Kv1Index::open(Arc::clone(&key), root, reader)?;
        let graph = Self {
            scope,
            key,
            index,
            format: FORMAT.into(),
            paged: None,
        };
        // Keyed object authentication alone cannot establish typed closure.
        graph.decode()?;
        Ok(graph)
    }

    fn decode(&self) -> CodecResult<DetachedOwner> {
        self.decode_checked(&|| Ok(()))
    }
    fn decode_checked(&self, check: &impl Fn() -> CodecResult<()>) -> CodecResult<DetachedOwner> {
        check()?;
        let mut keys = BTreeSet::new();
        self.index.visit_keys(|key| {
            check()?;
            if !self.scope.matches_key(key) {
                return Err(RecordError::Corrupt);
            }
            if keys.len() >= MAX_RECORDS {
                return Err(RecordError::TooLarge);
            }
            keys.insert(key.clone());
            Ok(())
        })?;
        let config_key = self.scope.key("config")?;
        let bytes = self.index.get(&config_key).ok_or(RecordError::Missing)?;
        let mount: MountCell = canonical(bytes, MAX_CONFIG_BYTES)?;
        if mount.format != FORMAT || !self.scope.matches(&mount.scope) {
            return Err(RecordError::Corrupt);
        }
        keys.remove(&config_key);
        let mut owner = DetachedOwner(Kv2 {
            config: mount.config,
            entries: BTreeMap::new(),
            lossless_format: mount.lossless_format,
        });
        let metadata_keys: Vec<_> = keys
            .iter()
            .filter(|key| key.path().starts_with("metadata/"))
            .cloned()
            .collect();
        if metadata_keys.len() > MAX_PATHS {
            return Err(RecordError::TooLarge);
        }
        for record in metadata_keys {
            check()?;
            let bytes = self.index.get(&record).ok_or(RecordError::Missing)?;
            let mut cell: PathCell = canonical(bytes, MAX_METADATA_BYTES)?;
            if cell.format != FORMAT
                || !self.scope.matches(&cell.scope)
                || metadata_key(&self.scope, &self.key, &cell.path)? != record
                || cell.metadata.versions.len() > MAX_RETAINED_VERSIONS as usize
                || cell.payload_versions.len() > MAX_RETAINED_VERSIONS as usize
                || cell.metadata.versions.values().any(|v| v.data.is_some())
            {
                return Err(RecordError::Corrupt);
            }
            keys.remove(&record);
            for number in &cell.payload_versions {
                check()?;
                let version = cell
                    .metadata
                    .versions
                    .get_mut(number)
                    .ok_or(RecordError::Corrupt)?;
                if version.destroyed {
                    return Err(RecordError::Corrupt);
                }
                let payload = payload_key(&self.scope, &self.key, &cell.path, *number)?;
                let bytes = self.index.get(&payload).ok_or(RecordError::Missing)?;
                version.data = Some(canonical::<SharedJson>(bytes, MAX_VALUE_BYTES)?);
                if !keys.remove(&payload) {
                    return Err(RecordError::Corrupt);
                }
                check()?;
            }
            let path = std::mem::take(&mut cell.path);
            let metadata = std::mem::take(&mut cell.metadata);
            if owner.entries.insert(path, Entry::from(metadata)).is_some() {
                return Err(RecordError::Corrupt);
            }
        }
        if !keys.is_empty() {
            return Err(RecordError::Corrupt);
        }
        validate_owner(&owner)?;
        check()?;
        Ok(owner)
    }
}

#[derive(Default)]
struct GraphObjects(BTreeMap<ObjectId, Arc<StagedObject>>);
impl RecordReader for GraphObjects {
    fn read_object(&self, reference: &ObjectRef) -> CodecResult<Zeroizing<Vec<u8>>> {
        self.0
            .get(&reference.id)
            .map(|object| Zeroizing::new(object.bytes().to_vec()))
            .ok_or(RecordError::Missing)
    }
}
impl GraphObjects {
    fn from_index(index: &Kv1Index) -> CodecResult<Self> {
        let mut objects = Self::default();
        index.visit_objects(|object| {
            objects.0.insert(object.reference().id, Arc::clone(object));
            Ok(())
        })?;
        Ok(objects)
    }
}

/// Counts describe only this detached codec roundtrip. All admission flags are
/// false: successful stage A validation cannot qualify a production root.
#[derive(Debug, Serialize)]
pub struct FoundationReceipt {
    pub format: &'static str,
    pub paths: usize,
    pub retained_versions: usize,
    pub payload_records: usize,
    pub graph_objects: usize,
    pub encoded_graph_bytes: usize,
    pub production_writer_admitted: bool,
    pub migration_admitted: bool,
    pub replacement_authority: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FoundationError {
    Invalid,
    Corrupt,
    Missing,
    TooLarge,
}
impl std::fmt::Display for FoundationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid native KV2 foundation scope",
            Self::Corrupt => "invalid native KV2 foundation records",
            Self::Missing => "native KV2 foundation graph is incomplete",
            Self::TooLarge => "native KV2 foundation capacity exceeded",
        })
    }
}
impl std::error::Error for FoundationError {}
impl From<RecordError> for FoundationError {
    fn from(error: RecordError) -> Self {
        match error {
            RecordError::Invalid => Self::Invalid,
            RecordError::Corrupt => Self::Corrupt,
            RecordError::Missing => Self::Missing,
            RecordError::TooLarge => Self::TooLarge,
        }
    }
}

/// Verify an actual serialized KV2 owner through the detached keyed native
/// codec, authenticated object reopening and exact logical reconstruction.
/// Owner input and graph are independently bounded at 64 MiB. Payload records
/// are bounded at 16 MiB, path metadata at 4 MiB, retained history at 10,000 per
/// path, paths at 10,000 and total logical records at 100,000. No storage opens.
pub fn verify_native_owner_records(
    owner_json: &[u8],
    address_key: &[u8; 32],
    scope: NativeScope<'_>,
) -> std::result::Result<FoundationReceipt, FoundationError> {
    // Scope validation must precede parsing attacker-controlled owner input.
    Scope::new(scope)?;
    preflight_owner(owner_json)?;
    let owner: DetachedOwner = canonical(owner_json, MAX_GRAPH_BYTES)?;
    let base = AddressKey::from_bytes(*address_key);
    let graph = NativeGraph::encode(&owner, &base, scope)?;
    let objects = GraphObjects::from_index(&graph.index)?;
    let reopened = NativeGraph::open(&base, scope, graph.index.root(), &objects)?;
    let restored = reopened.decode()?;
    if serialize(&restored, MAX_GRAPH_BYTES)?.as_slice() != owner_json {
        return Err(FoundationError::Corrupt);
    }
    Ok(FoundationReceipt {
        format: FORMAT,
        paths: restored.entries.len(),
        retained_versions: restored.entries.values().map(|v| v.versions.len()).sum(),
        payload_records: restored
            .entries
            .values()
            .flat_map(|v| v.versions.values())
            .filter(|v| v.data.is_some())
            .count(),
        graph_objects: objects.0.len(),
        encoded_graph_bytes: objects.0.values().map(|v| v.bytes().len()).sum(),
        production_writer_admitted: false,
        migration_admitted: false,
        replacement_authority: false,
    })
}

#[cfg(test)]
#[path = "kv2_native_records_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "kv2_native_mutation_tests.rs"]
mod mutation_tests;
