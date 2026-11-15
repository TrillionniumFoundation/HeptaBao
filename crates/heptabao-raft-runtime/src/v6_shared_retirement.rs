//! Shared replica ciphertext retirement under a complete durable Raft mark.
//! This never grants local barrier-object, Actor or ledger-commit authority.
//! The Service caller must durably commit and continuously verify the exact
//! selected capsule before entering the affine physical operation.
use super::*;
use crate::NativeV6RetentionGuard;
use heptabao_filesystem_guard::{FileRetirementError, PreparedFileRetirement};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const FORMAT: u8 = 1;
const MAX_SHARED_OBJECTS: usize = 1_000_000;
const MAX_SHARED_FILES: usize = 1_016_384;
const MAX_SELECTED: usize = heptabao_filesystem_guard::MAX_IMMUTABLE_RETIREMENT_FILES;
const MAX_CAPSULE_BYTES: usize = 64 * 1024;
const MAX_MANIFEST_BYTES: usize = 16 + 131_072 * 40;

fn rejected() -> LocalV6BlobError {
    LocalV6BlobError::CorruptOrChanged
}
fn io_rejected() -> io::Error {
    io::Error::other("native shared retirement source or ownership changed")
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Descriptor {
    device: u64,
    inode: u64,
    length: u64,
    uid: u32,
    mode: u32,
    modified: i64,
    modified_ns: i64,
    changed: i64,
    changed_ns: i64,
}
impl Descriptor {
    pub(super) fn read(file: &File) -> Result<Self, LocalV6BlobError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = file.metadata()?;
            if !meta.is_file() || meta.nlink() != 1 || meta.mode() & 0o077 != 0 {
                return Err(rejected());
            }
            Ok(Self {
                device: meta.dev(),
                inode: meta.ino(),
                length: meta.len(),
                uid: meta.uid(),
                mode: meta.mode(),
                modified: meta.mtime(),
                modified_ns: meta.mtime_nsec(),
                changed: meta.ctime(),
                changed_ns: meta.ctime_nsec(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = file;
            Err(rejected())
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
enum EntryKind {
    Blob,
    Manifest,
    BlobTemporary,
    ManifestTemporary,
}
impl EntryKind {
    fn maximum(self) -> usize {
        match self {
            Self::Blob | Self::BlobTemporary => 256 * 1024,
            Self::Manifest | Self::ManifestTemporary => MAX_MANIFEST_BYTES,
        }
    }
}
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
enum Action {
    Remove,
    AlreadyAbsent,
    CurrentlyRetained,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    leaf: String,
    kind: EntryKind,
    action: Action,
    descriptor: Option<Descriptor>,
    bytes_sha256: [u8; 32],
}

/// Authenticated-ledger DATA only. Decoding this capsule cannot reconstruct an
/// original file descriptor, writer guard, exclusive lease or deletion plan.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeV6SharedRetirementSelection {
    format: u8,
    directory_device: u64,
    directory_inode: u64,
    retained_source_digest: [u8; 32],
    predecessor_selection_digest: Option<[u8; 32]>,
    marked_blobs: usize,
    marked_manifests: usize,
    observed_files: usize,
    entries: Vec<Entry>,
}
impl fmt::Debug for NativeV6SharedRetirementSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeV6SharedRetirementSelection")
            .field("selected_files", &self.entries.len())
            .finish_non_exhaustive()
    }
}

fn parse_hex(raw: &str) -> Option<[u8; 32]> {
    if raw.len() != 64 {
        return None;
    }
    let mut result = [0; 32];
    fn nibble(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            _ => None,
        }
    }
    for (index, pair) in raw.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        result[index] = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    (result != [0; 32]).then_some(result)
}
fn temporary_suffix(value: &str) -> bool {
    let Some((pid, serial)) = value.split_once('-') else {
        return false;
    };
    [pid, serial].into_iter().all(|part| {
        !part.is_empty()
            && part.len() <= 20
            && part.bytes().all(|byte| byte.is_ascii_digit())
            && part
                .parse::<u64>()
                .ok()
                .is_some_and(|number| number != 0 && number.to_string() == part)
    })
}
fn classify(leaf: &str) -> Option<(EntryKind, Option<[u8; 32]>)> {
    if let Some(raw) = leaf
        .strip_prefix("v6-closure-")
        .and_then(|value| value.strip_suffix(".manifest"))
    {
        return parse_hex(raw).map(|digest| (EntryKind::Manifest, Some(digest)));
    }
    if let Some(raw) = leaf
        .strip_prefix("v6-")
        .and_then(|value| value.strip_suffix(".blob"))
    {
        return parse_hex(raw).map(|digest| (EntryKind::Blob, Some(digest)));
    }
    if leaf.strip_prefix(".v6-tmp-").is_some_and(temporary_suffix) {
        return Some((EntryKind::BlobTemporary, None));
    }
    if leaf
        .strip_prefix(".v6-manifest-tmp-")
        .is_some_and(temporary_suffix)
    {
        return Some((EntryKind::ManifestTemporary, None));
    }
    None
}

impl NativeV6SharedRetirementSelection {
    fn validate(&self) -> Result<(), LocalV6BlobError> {
        if self.format != FORMAT
            || self.directory_inode == 0
            || self.retained_source_digest == [0; 32]
            || self.entries.len() > MAX_SELECTED
            || self.marked_blobs > MAX_SHARED_OBJECTS
            || self.marked_manifests > 16_384
            || self.observed_files > MAX_SHARED_FILES
            || self.predecessor_selection_digest == Some([0; 32])
        {
            return Err(rejected());
        }
        let mut previous: Option<&str> = None;
        for entry in &self.entries {
            if classify(&entry.leaf).map(|(kind, _)| kind) != Some(entry.kind)
                || previous.is_some_and(|prior| prior >= entry.leaf.as_str())
                || entry.bytes_sha256 == [0; 32]
            {
                return Err(rejected());
            }
            match (&entry.descriptor, entry.action) {
                (None, Action::AlreadyAbsent) if self.predecessor_selection_digest.is_some() => {}
                (Some(meta), Action::Remove | Action::CurrentlyRetained)
                    if meta.inode != 0
                        && meta.length <= entry.kind.maximum() as u64
                        && meta.mode & 0o077 == 0 => {}
                _ => return Err(rejected()),
            }
            if self.predecessor_selection_digest.is_none() && entry.action != Action::Remove {
                return Err(rejected());
            }
            previous = Some(&entry.leaf);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, LocalV6BlobError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| rejected())?;
        if bytes.len() > MAX_CAPSULE_BYTES {
            return Err(rejected());
        }
        Ok(bytes)
    }
    pub fn decode_for_reconciliation(bytes: &[u8]) -> Result<Self, LocalV6BlobError> {
        if bytes.len() > MAX_CAPSULE_BYTES {
            return Err(rejected());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| rejected())?;
        if value.encode()? != bytes {
            return Err(rejected());
        }
        Ok(value)
    }
    pub fn digest(&self) -> Result<[u8; 32], LocalV6BlobError> {
        Ok(Sha256::digest(self.encode()?).into())
    }
    pub fn selected_files(&self) -> usize {
        self.entries.len()
    }
    pub fn is_reconciliation(&self) -> bool {
        self.predecessor_selection_digest.is_some()
    }
    pub fn predecessor_selection_digest(&self) -> Option<[u8; 32]> {
        self.predecessor_selection_digest
    }
}

struct Marked {
    blobs: BTreeMap<[u8; 32], RecordObjectRef>,
    manifests: BTreeSet<[u8; 32]>,
    leaves: BTreeSet<String>,
}
impl Marked {
    fn retained(&self, leaf: &str) -> bool {
        self.leaves.contains(leaf)
    }
}

/// Original held descriptors plus actual durable writers and exclusive shared
/// operation ownership. Its private fields have no serialized constructor.
pub struct NativeV6SharedRetirementPlan<'a> {
    store: &'a LocalV6BlobStage,
    retained: NativeV6RetentionGuard,
    exclusive: NativeV6BlobQuiescence,
    selection: NativeV6SharedRetirementSelection,
    descriptors: Vec<Option<PreparedFileRetirement>>,
}
impl fmt::Debug for NativeV6SharedRetirementPlan<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeV6SharedRetirementPlan")
            .field("selected_files", &self.selection.entries.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeV6SharedRetirementOutcome {
    pub removed_blobs: usize,
    pub removed_manifests: usize,
    pub removed_temporary_files: usize,
    pub removed_ciphertext_bytes: u64,
    pub removed_other_bytes: u64,
    pub confirmed_absent_files: usize,
    pub currently_retained_files: usize,
}

/// Keeps the same actual retained writers and shared exclusive owner after
/// physical completion until the caller's authenticated terminal Apply is
/// known. This cannot be decoded from a prior result or reacquired by path.
pub struct NativeV6SharedRetirementReceipt<'a> {
    store: &'a LocalV6BlobStage,
    retained: NativeV6RetentionGuard,
    exclusive: NativeV6BlobQuiescence,
    selection: NativeV6SharedRetirementSelection,
    held: Vec<(Entry, PreparedFileRetirement)>,
    outcome: NativeV6SharedRetirementOutcome,
}
impl fmt::Debug for NativeV6SharedRetirementReceipt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeV6SharedRetirementReceipt")
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}
impl NativeV6SharedRetirementReceipt<'_> {
    pub fn outcome(&self) -> NativeV6SharedRetirementOutcome {
        self.outcome
    }
    pub fn verify_completed(&self) -> Result<(), LocalV6BlobError> {
        ownership(self.store, &self.retained, &self.exclusive)?;
        for entry in &self.selection.entries {
            if entry.action != Action::CurrentlyRetained
                && self.store.directory.entry_exists(&entry.leaf)?
            {
                return Err(rejected());
            }
        }
        for (entry, descriptor) in &self.held {
            self.store.directory.verify_file_retirement(descriptor)?;
            if entry.descriptor.as_ref() != Some(&Descriptor::read(descriptor.file())?) {
                return Err(rejected());
            }
        }
        ownership(self.store, &self.retained, &self.exclusive)
    }
}

#[derive(Debug)]
pub enum NativeV6SharedRetirementError {
    BeforePhysical(LocalV6BlobError),
    OutcomeUnknown(LocalV6BlobError),
}
impl fmt::Display for NativeV6SharedRetirementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BeforePhysical(_) => "shared retirement rejected before physical invocation",
            Self::OutcomeUnknown(_) => "shared retirement physical outcome is unknown",
        })
    }
}
impl std::error::Error for NativeV6SharedRetirementError {}

fn bounded_read(
    file: &File,
    length: usize,
    gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
) -> Result<Vec<u8>, LocalV6BlobError> {
    gate()?;
    let mut file = file;
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(length);
    let mut block = [0; 64 * 1024];
    loop {
        gate()?;
        let maximum = block.len().min(length - bytes.len() + 1);
        let count = file.read(&mut block[..maximum])?;
        #[cfg(test)]
        if count != 0 {
            SHARED_READ_PROGRESS.with(|slot| {
                if let Some((revoked, calls)) = slot.borrow().as_ref() {
                    calls.set(calls.get() + 1);
                    revoked.set(true);
                }
            });
        }
        gate()?;
        if count == 0 {
            break;
        }
        if count > length - bytes.len() {
            return Err(rejected());
        }
        bytes.extend_from_slice(&block[..count]);
    }
    if bytes.len() != length {
        return Err(rejected());
    }
    gate()?;
    Ok(bytes)
}

fn authenticate_named(kind: EntryKind, leaf: &str, bytes: &[u8]) -> Result<(), LocalV6BlobError> {
    let (_, named) = classify(leaf).ok_or_else(rejected)?;
    match kind {
        EntryKind::Blob => {
            let object = SealedRecordObject::new_native_v6_ciphertext_chunk(bytes.to_vec())
                .map_err(|_| rejected())?;
            if Some(object.reference().id) != named {
                return Err(rejected());
            }
        }
        EntryKind::Manifest => {
            if Some(super::closure_manifest::canonical_unreferenced_manifest_digest(bytes)?)
                != named
            {
                return Err(rejected());
            }
        }
        // Temporary names are never root references. Complete quiescence and
        // private singly-linked exact descriptors, not a PID-age guess, allow
        // a new explicit operation to retire these abandoned bounded bytes.
        EntryKind::BlobTemporary | EntryKind::ManifestTemporary => {}
    }
    Ok(())
}

pub(super) fn ownership(
    store: &LocalV6BlobStage,
    retained: &NativeV6RetentionGuard,
    exclusive: &NativeV6BlobQuiescence,
) -> Result<(), LocalV6BlobError> {
    store.verify_retention_ownership(retained, exclusive)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let named = heptabao_filesystem_guard::open_absolute_directory_no_symlinks(
            store.directory.original_path(),
        )?
        .metadata()?;
        if named.dev() != store.directory.identity().device()
            || named.ino() != store.directory.identity().inode()
            || named.mode() & 0o077 != 0
        {
            return Err(rejected());
        }
    }
    #[cfg(not(unix))]
    return Err(rejected());
    Ok(())
}

pub(super) fn read_descriptor(
    store: &LocalV6BlobStage,
    leaf: &str,
    maximum: usize,
    gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
) -> Result<(PreparedFileRetirement, Descriptor, Vec<u8>), LocalV6BlobError> {
    gate()?;
    let initial = store.directory.open_file(leaf, FileAccess::Read)?;
    let length = usize::try_from(initial.metadata()?.len()).map_err(|_| rejected())?;
    if length > maximum {
        return Err(rejected());
    }
    drop(initial);
    let prepared = store.directory.prepare_file_retirement(leaf, length)?;
    let descriptor = Descriptor::read(prepared.file())?;
    let bytes = bounded_read(prepared.file(), length, gate)?;
    store.directory.verify_file_retirement(&prepared)?;
    if Descriptor::read(prepared.file())? != descriptor {
        return Err(rejected());
    }
    gate()?;
    Ok((prepared, descriptor, bytes))
}

fn full_mark(
    store: &LocalV6BlobStage,
    retained: &NativeV6RetentionGuard,
    gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
) -> Result<Marked, LocalV6BlobError> {
    let mut result = Marked {
        blobs: BTreeMap::new(),
        manifests: BTreeSet::new(),
        leaves: BTreeSet::new(),
    };
    let mut manifest_facts = BTreeMap::<[u8; 32], (u64, u64)>::new();
    for intent in retained.retained_intents() {
        gate()?;
        let digest = intent.closure_manifest_sha256;
        let facts = (intent.object_count, intent.ciphertext_bytes);
        if let Some(previous) = manifest_facts.get(&digest) {
            if *previous != facts {
                return Err(rejected());
            }
            continue;
        }
        if manifest_facts.len() >= 16_384 {
            return Err(rejected());
        }
        manifest_facts.insert(digest, facts);
        let leaf = super::closure_manifest::manifest_leaf(&digest)?;
        let (descriptor, _, bytes) = read_descriptor(store, &leaf, MAX_MANIFEST_BYTES, gate)?;
        let refs = LocalV6BlobStage::validate_archived_closure_manifest(&bytes, intent)?;
        store.directory.verify_file_retirement(&descriptor)?;
        result.manifests.insert(digest);
        result.leaves.insert(leaf);
        // Authentication comes from the ACTUAL retained Raft intent's exact
        // canonical closure digest/count/length, never merely this filename.
        for reference in refs {
            gate()?;
            if let Some(existing) = result.blobs.get(&reference.id) {
                if *existing != reference {
                    return Err(rejected());
                }
            } else {
                if result.blobs.len() >= MAX_SHARED_OBJECTS {
                    return Err(rejected());
                }
                result.leaves.insert(LocalV6BlobStage::leaf(&reference)?);
                result.blobs.insert(reference.id, reference);
            }
        }
        // Captured canonical bytes cannot gain new references while retaining
        // their authenticated digest. An unbounded set of open FDs is not
        // needed; shared producers and Raft writers remain separately held.
        drop(descriptor);
    }
    if result.manifests.is_empty() || result.blobs.is_empty() {
        return Err(rejected());
    }
    for reference in result.blobs.values() {
        gate()?;
        let leaf = LocalV6BlobStage::leaf(reference)?;
        let (descriptor, meta, bytes) = read_descriptor(store, &leaf, 256 * 1024, gate)?;
        if meta.length != reference.payload_bytes {
            return Err(rejected());
        }
        let object = SealedRecordObject::new(reference.clone(), Vec::new(), bytes)
            .map_err(|_| rejected())?;
        if object.reference() != reference {
            return Err(rejected());
        }
        store.directory.verify_file_retirement(&descriptor)?;
    }
    gate()?;
    Ok(result)
}

impl LocalV6BlobStage {
    /// Prepare one bounded fresh selection. Every physically retained source
    /// and complete in-flight operation is protected, including uncommitted
    /// intents still present in a retained log or journal. No files are written
    /// or removed, and no ledger or original Actor is manufactured.
    pub fn prepare_shared_retirement<'a>(
        &'a self,
        retained: NativeV6RetentionGuard,
        exclusive: NativeV6BlobQuiescence,
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<NativeV6SharedRetirementPlan<'a>, LocalV6BlobError> {
        self.prepare_shared_retirement_inner(retained, exclusive, None, gate)
    }

    /// An explicit NEW selection under a fresh complete mark and new original
    /// descriptors. A former pending capsule selects names only. It supplies
    /// no physical or retained-root authority and cannot replay its old plan.
    pub fn prepare_shared_retirement_reconciliation<'a>(
        &'a self,
        retained: NativeV6RetentionGuard,
        exclusive: NativeV6BlobQuiescence,
        previous: &NativeV6SharedRetirementSelection,
        gate: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<NativeV6SharedRetirementPlan<'a>, LocalV6BlobError> {
        self.prepare_shared_retirement_inner(retained, exclusive, Some(previous), gate)
    }

    fn prepare_shared_retirement_inner<'a>(
        &'a self,
        retained: NativeV6RetentionGuard,
        exclusive: NativeV6BlobQuiescence,
        previous: Option<&NativeV6SharedRetirementSelection>,
        outer: &mut impl FnMut() -> Result<(), LocalV6BlobError>,
    ) -> Result<NativeV6SharedRetirementPlan<'a>, LocalV6BlobError> {
        let mut gate = || {
            outer()?;
            ownership(self, &retained, &exclusive)
        };
        gate()?;
        if let Some(previous) = previous {
            previous.validate()?;
            if previous.entries.is_empty()
                || previous.directory_device != self.directory.identity().device()
                || previous.directory_inode != self.directory.identity().inode()
            {
                return Err(rejected());
            }
        }
        let marked = full_mark(self, &retained, &mut gate)?;
        let mut observed = BTreeSet::new();
        for entry in self.directory.entries()? {
            gate()?;
            let leaf = entry?.into_string().map_err(|_| rejected())?;
            // Unknown names, symlink/alias candidates and foreign layouts are
            // holds. A valid orphan in the bounded native namespace is not
            // held forever just because no current registry records it.
            if classify(&leaf).is_none()
                || observed.len() >= MAX_SHARED_FILES
                || !observed.insert(leaf)
            {
                return Err(rejected());
            }
        }
        if !marked.leaves.is_subset(&observed) {
            return Err(rejected());
        }
        let selected: Vec<String> = previous.map_or_else(
            || {
                observed
                    .difference(&marked.leaves)
                    .take(MAX_SELECTED)
                    .cloned()
                    .collect()
            },
            |previous| {
                previous
                    .entries
                    .iter()
                    .map(|entry| entry.leaf.clone())
                    .collect()
            },
        );
        let mut entries = Vec::with_capacity(selected.len());
        let mut descriptors = Vec::with_capacity(selected.len());
        let mut inodes = BTreeSet::new();
        for leaf in selected {
            gate()?;
            let (kind, _) = classify(&leaf).ok_or_else(rejected)?;
            if !observed.contains(&leaf) {
                let old = previous
                    .and_then(|p| p.entries.iter().find(|entry| entry.leaf == leaf))
                    .ok_or_else(rejected)?;
                if self.directory.entry_exists(&leaf)? {
                    return Err(rejected());
                }
                entries.push(Entry {
                    leaf,
                    kind,
                    action: Action::AlreadyAbsent,
                    descriptor: None,
                    bytes_sha256: old.bytes_sha256,
                });
                descriptors.push(None);
                continue;
            }
            let action = if marked.retained(&leaf) {
                Action::CurrentlyRetained
            } else {
                Action::Remove
            };
            let (descriptor, meta, bytes) =
                read_descriptor(self, &leaf, kind.maximum(), &mut gate)?;
            authenticate_named(kind, &leaf, &bytes)?;
            if !inodes.insert((meta.device, meta.inode)) {
                return Err(rejected());
            }
            entries.push(Entry {
                leaf,
                kind,
                action,
                descriptor: Some(meta),
                bytes_sha256: Sha256::digest(&bytes).into(),
            });
            descriptors.push(Some(descriptor));
        }
        gate()?;
        let selection = NativeV6SharedRetirementSelection {
            format: FORMAT,
            directory_device: self.directory.identity().device(),
            directory_inode: self.directory.identity().inode(),
            retained_source_digest: retained.retention_fingerprint().map_err(|_| rejected())?,
            predecessor_selection_digest: previous
                .map(NativeV6SharedRetirementSelection::digest)
                .transpose()?,
            marked_blobs: marked.blobs.len(),
            marked_manifests: marked.manifests.len(),
            observed_files: observed.len(),
            entries,
        };
        selection.validate()?;
        gate()?;
        Ok(NativeV6SharedRetirementPlan {
            store: self,
            retained,
            exclusive,
            selection,
            descriptors,
        })
    }
}

impl<'a> NativeV6SharedRetirementPlan<'a> {
    pub fn selection(&self) -> &NativeV6SharedRetirementSelection {
        &self.selection
    }
    pub fn verify_prepared(&self) -> Result<(), LocalV6BlobError> {
        ownership(self.store, &self.retained, &self.exclusive)?;
        self.selection.validate()?;
        if self.selection.entries.len() != self.descriptors.len()
            || self.selection.retained_source_digest
                != self
                    .retained
                    .retention_fingerprint()
                    .map_err(|_| rejected())?
        {
            return Err(rejected());
        }
        for (entry, descriptor) in self.selection.entries.iter().zip(&self.descriptors) {
            match descriptor {
                Some(descriptor) => {
                    self.store.directory.verify_file_retirement(descriptor)?;
                    if entry.descriptor.as_ref() != Some(&Descriptor::read(descriptor.file())?) {
                        return Err(rejected());
                    }
                }
                None if entry.action == Action::AlreadyAbsent
                    && !self.store.directory.entry_exists(&entry.leaf)? => {}
                _ => return Err(rejected()),
            }
        }
        Ok(())
    }

    /// Consume the exact affine plan only AFTER the caller has received a
    /// known local authenticated pending Apply for selection().encode(). The
    /// callback must recheck that exact committed capsule/root/Actor/deadline
    /// at each boundary. It is a trusted Service integration contract, not a
    /// user-controlled callback or a substitute for the durable ledger.
    /// Every error leaves that pending record unresolved for explicit fresh
    /// reconciliation. This method never retries an unlink or treats ENOENT
    /// from an attempted unlink as success.
    pub fn retire_after_known_ledger(
        self,
        verify_committed: &mut impl FnMut(&[u8]) -> Result<(), LocalV6BlobError>,
    ) -> Result<NativeV6SharedRetirementReceipt<'a>, NativeV6SharedRetirementError> {
        use NativeV6SharedRetirementError::{BeforePhysical, OutcomeUnknown};
        self.verify_prepared().map_err(BeforePhysical)?;
        let encoded = self.selection.encode().map_err(BeforePhysical)?;
        verify_committed(&encoded).map_err(BeforePhysical)?;
        let NativeV6SharedRetirementPlan {
            store,
            retained,
            exclusive,
            selection,
            descriptors,
        } = self;
        let mut remove = Vec::new();
        let mut remove_entries = Vec::new();
        let mut held = Vec::new();
        let mut absent = Vec::new();
        let mut outcome = NativeV6SharedRetirementOutcome {
            removed_blobs: 0,
            removed_manifests: 0,
            removed_temporary_files: 0,
            removed_ciphertext_bytes: 0,
            removed_other_bytes: 0,
            confirmed_absent_files: 0,
            currently_retained_files: 0,
        };
        for (entry, descriptor) in selection.entries.iter().zip(descriptors) {
            match (entry.action, descriptor) {
                (Action::Remove, Some(descriptor)) => {
                    remove.push(descriptor);
                    remove_entries.push(entry);
                }
                (Action::CurrentlyRetained, Some(descriptor)) => {
                    held.push((entry, descriptor));
                    outcome.currently_retained_files += 1;
                }
                (Action::AlreadyAbsent, None) => {
                    absent.push(entry);
                    outcome.confirmed_absent_files += 1;
                }
                _ => return Err(BeforePhysical(rejected())),
            }
        }
        // Keep the shared original gate in one lexical scope so its borrows
        // end before the affine owners move into the terminal receipt.
        {
            let mut check = || -> Result<(), LocalV6BlobError> {
                verify_committed(&encoded)?;
                ownership(store, &retained, &exclusive)?;
                for (entry, descriptor) in &held {
                    store.directory.verify_file_retirement(descriptor)?;
                    if entry.descriptor.as_ref() != Some(&Descriptor::read(descriptor.file())?) {
                        return Err(rejected());
                    }
                }
                for entry in &absent {
                    if store.directory.entry_exists(&entry.leaf)? {
                        return Err(rejected());
                    }
                }
                Ok(())
            };
            check().map_err(BeforePhysical)?;
            // Both callbacks run serially in retire_files_checked. Share the SAME
            // full original Actor/known-pending/retained-owner gate through a
            // checked interior borrow, including every bounded ciphertext read.
            // No copied callback or later authorization replaces this one.
            let check = std::cell::RefCell::new(check);
            if !remove.is_empty() {
                let mut auth = |index: usize, file: &File| -> io::Result<()> {
                    let entry = remove_entries.get(index).ok_or_else(io_rejected)?;
                    let descriptor = entry.descriptor.as_ref().ok_or_else(io_rejected)?;
                    // The FS primitive checks the same FD and event witness on
                    // both sides. Re-read/authenticate exact bytes just before its
                    // sole unlink. No call here manufactures an AEAD/domain claim.
                    let bytes = bounded_read(file, descriptor.length as usize, &mut || {
                        let mut original = check.try_borrow_mut().map_err(|_| rejected())?;
                        original()
                    })
                    .map_err(|_| io_rejected())?;
                    if <[u8; 32]>::from(Sha256::digest(&bytes)) != entry.bytes_sha256 {
                        return Err(io_rejected());
                    }
                    authenticate_named(entry.kind, &entry.leaf, &bytes).map_err(|_| io_rejected())
                };
                let mut gate = || {
                    let mut original = check.try_borrow_mut().map_err(|_| io_rejected())?;
                    original().map_err(|_| io_rejected())
                };
                store
                    .directory
                    .retire_files_checked(remove, &mut auth, &mut gate)
                    .map_err(|error| match error {
                        FileRetirementError::BeforeUnlink(error) => {
                            BeforePhysical(LocalV6BlobError::Io(error))
                        }
                        FileRetirementError::OutcomeUnknown(error) => {
                            OutcomeUnknown(LocalV6BlobError::Io(error))
                        }
                    })?;
            } else if !absent.is_empty() {
                // A new absence observation includes an explicit current directory
                // barrier. It neither replays old unlink nor claims which old call
                // caused absence. Sync uncertainty keeps the new outcome unknown.
                store
                    .directory
                    .sync_all()
                    .map_err(|error| OutcomeUnknown(LocalV6BlobError::Guard(error)))?;
            }
            {
                let mut original = check
                    .try_borrow_mut()
                    .map_err(|_| OutcomeUnknown(rejected()))?;
                original().map_err(OutcomeUnknown)?;
            }
        }
        for entry in remove_entries {
            let bytes = entry
                .descriptor
                .as_ref()
                .ok_or_else(|| OutcomeUnknown(rejected()))?
                .length;
            match entry.kind {
                EntryKind::Blob => {
                    outcome.removed_blobs += 1;
                    outcome.removed_ciphertext_bytes += bytes;
                }
                EntryKind::Manifest => {
                    outcome.removed_manifests += 1;
                    outcome.removed_other_bytes += bytes;
                }
                EntryKind::BlobTemporary | EntryKind::ManifestTemporary => {
                    outcome.removed_temporary_files += 1;
                    outcome.removed_other_bytes += bytes;
                }
            }
        }
        let held = held
            .into_iter()
            .map(|(entry, descriptor)| (entry.clone(), descriptor))
            .collect();
        let receipt = NativeV6SharedRetirementReceipt {
            store,
            retained,
            exclusive,
            selection,
            held,
            outcome,
        };
        receipt.verify_completed().map_err(OutcomeUnknown)?;
        Ok(receipt)
    }
}

// Test-only observation of real nonempty descriptor reads. It cannot grant
// authority, alter data, relax a gate or survive its same-thread RAII scope.
#[cfg(test)]
type SharedReadProgress = (
    std::rc::Rc<std::cell::Cell<bool>>,
    std::rc::Rc<std::cell::Cell<usize>>,
);
#[cfg(test)]
thread_local! {
    static SHARED_READ_PROGRESS: std::cell::RefCell<Option<SharedReadProgress>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(crate) struct SharedRetirementReadObserver {
    _same_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
#[cfg(test)]
impl Drop for SharedRetirementReadObserver {
    fn drop(&mut self) {
        SHARED_READ_PROGRESS.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
#[cfg(test)]
pub(crate) fn observe_shared_retirement_reads(
    revoked: std::rc::Rc<std::cell::Cell<bool>>,
    calls: std::rc::Rc<std::cell::Cell<usize>>,
) -> Result<SharedRetirementReadObserver, LocalV6BlobError> {
    SHARED_READ_PROGRESS.with(|slot| {
        let mut slot = slot.try_borrow_mut().map_err(|_| rejected())?;
        if slot.is_some() {
            return Err(rejected());
        }
        *slot = Some((revoked, calls));
        Ok(SharedRetirementReadObserver {
            _same_thread: std::marker::PhantomData,
        })
    })
}
