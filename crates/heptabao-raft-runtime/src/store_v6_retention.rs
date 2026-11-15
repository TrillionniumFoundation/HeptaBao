//! A closed, descriptor-bound retention inventory under BOTH actual writers.
//! No recovery, truncation, checkpoint, purge or directory mutation occurs here.
use super::*;
use crate::v6_retention::{Log, NativeV6IntentRetirementCommand, NativeV6RetentionSource};
use crate::{NativeV6CommitIntent, RecordObjectId, SealedRecordObject};
use heptabao_filesystem_guard::{ExclusiveDirectory, FileAccess, FileMutationWitness};
use std::collections::BTreeSet;
use std::time::Instant;
use tokio::sync::OwnedMutexGuard;

const MAX_RETAINED_INTENTS: usize = 16_384;
const MAX_RETAINED_ROOT_BYTES: usize = 32 * 1024 * 1024;
const MAX_JOURNAL_BYTES: usize = 256 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;

fn refused() -> io::Error {
    invalid("native retained storage is unresolved or changed")
}
fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(refused())
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    uid: u32,
    modified: i64,
    modified_ns: i64,
    changed: i64,
    changed_ns: i64,
}
impl FileIdentity {
    fn read(file: &File) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = file.metadata()?;
            if !meta.is_file() || meta.nlink() != 1 {
                return Err(refused());
            }
            Ok(Self {
                device: meta.dev(),
                inode: meta.ino(),
                length: meta.len(),
                mode: meta.mode(),
                uid: meta.uid(),
                modified: meta.mtime(),
                modified_ns: meta.mtime_nsec(),
                changed: meta.ctime(),
                changed_ns: meta.ctime_nsec(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = file;
            Err(refused())
        }
    }
}
struct RetainedFile {
    leaf: &'static str,
    file: File,
    identity: FileIdentity,
    mutations: FileMutationWitness,
}
impl RetainedFile {
    fn read(
        directory: &ExclusiveDirectory,
        leaf: &'static str,
        maximum: usize,
        deadline: Instant,
    ) -> io::Result<(Self, Vec<u8>)> {
        check_deadline(deadline)?;
        let mut file = directory.open_file(leaf, FileAccess::Read)?;
        let identity = FileIdentity::read(&file)?;
        if identity.length > maximum as u64 {
            return Err(refused());
        }
        let mutations = directory.watch_file_mutations(&file)?;
        let mut bytes = Vec::with_capacity(identity.length as usize);
        let mut block = [0_u8; 64 * 1024];
        loop {
            check_deadline(deadline)?;
            let n = file.read(&mut block)?;
            if n == 0 {
                break;
            }
            if bytes.len().checked_add(n).is_none_or(|size| size > maximum) {
                return Err(refused());
            }
            bytes.extend_from_slice(&block[..n]);
        }
        let owned = Self {
            leaf,
            file,
            identity,
            mutations,
        };
        owned.verify(directory, deadline)?;
        if bytes.len() as u64 != identity.length {
            return Err(refused());
        }
        Ok((owned, bytes))
    }
    fn verify(&self, directory: &ExclusiveDirectory, deadline: Instant) -> io::Result<()> {
        check_deadline(deadline)?;
        self.mutations.verify_file(&self.file)?;
        if FileIdentity::read(&self.file)? != self.identity
            || FileIdentity::read(&directory.open_file(self.leaf, FileAccess::Read)?)?
                != self.identity
        {
            return Err(refused());
        }
        self.mutations.verify_file(&self.file)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct HistoricalSource {
    root: [u8; 32],
    generation: u64,
    cluster: [u8; 32],
    epoch: u64,
}
#[derive(Default)]
struct RetainedIntents {
    intents: BTreeMap<RecordObjectId, NativeV6CommitIntent>,
    origins: BTreeMap<Log, NativeV6CommitIntent>,
    required_origins: BTreeMap<Log, HistoricalSource>,
    roots: BTreeMap<Log, crate::v6_root_publication::NativeV6RootCommand>,
    roots_bytes: usize,
    roots_overflowed: bool,
}
impl RetainedIntents {
    // A command in retained history is DATA, including uncommitted/truncated
    // log history. Never construct NativeV6PublishedRoot from this catalog.
    fn root(
        &mut self,
        root: &crate::v6_root_publication::NativeV6RootCommand,
        publication: Log,
    ) -> io::Result<()> {
        root.validate().map_err(|_| refused())?;
        if !crate::v6_root_publication::valid_log(publication)
            || publication.index <= root.intent_log.index
        {
            return Err(refused());
        }
        self.insert(root.intent, root.intent_log)?;
        if let Some(previous) = self.roots.get(&publication) {
            return if previous == root {
                Ok(())
            } else {
                Err(refused())
            };
        }
        if self.roots_overflowed {
            return Ok(());
        }
        let next = self
            .roots_bytes
            .checked_add(root.envelope.sealed().len())
            .and_then(|n| n.checked_add(512));
        if self.roots.len() >= MAX_RETAINED_INTENTS
            || next.is_none_or(|n| n > MAX_RETAINED_ROOT_BYTES)
        {
            // Shared-ciphertext retention stays complete. Only the stronger
            // local locator union is unavailable; do not truncate it into a
            // falsely complete catalog or inflate the original time budget.
            self.roots.clear();
            self.roots_bytes = 0;
            self.roots_overflowed = true;
            return Ok(());
        }
        self.roots_bytes = next.ok_or_else(refused)?;
        self.roots.insert(publication, root.clone());
        Ok(())
    }
    fn insert(&mut self, intent: NativeV6CommitIntent, origin: Log) -> io::Result<()> {
        let object =
            SealedRecordObject::new_native_v6_commit_intent(intent).map_err(|_| refused())?;
        if !crate::v6_root_publication::valid_log(origin) {
            return Err(refused());
        }
        if let Some(existing) = self.intents.get(&object.reference().id) {
            if *existing != intent {
                return Err(refused());
            }
        } else {
            if self.intents.len() >= MAX_RETAINED_INTENTS {
                return Err(refused());
            }
            self.intents.insert(object.reference().id, intent);
        }
        if self
            .origins
            .get(&origin)
            .is_some_and(|actual| *actual != intent)
        {
            return Err(refused());
        }
        if !self.origins.contains_key(&origin) && self.origins.len() >= MAX_RETAINED_INTENTS {
            return Err(refused());
        }
        self.origins.insert(origin, intent);
        Ok(())
    }
    fn source(
        &mut self,
        source: &crate::v6_epoch_restore::NativeV6EpochRestoreSource,
    ) -> io::Result<()> {
        let expected = HistoricalSource {
            root: source.root_digest,
            generation: source.generation,
            cluster: source.enrollment.command.cluster_digest,
            epoch: source.enrollment.command.epoch,
        };
        if self
            .required_origins
            .get(&source.intent_log)
            .is_some_and(|actual| *actual != expected)
        {
            return Err(refused());
        }
        if !self.required_origins.contains_key(&source.intent_log)
            && self.required_origins.len() >= MAX_RETAINED_INTENTS
        {
            return Err(refused());
        }
        self.required_origins.insert(source.intent_log, expected);
        Ok(())
    }
    fn pending(
        &mut self,
        pending: &crate::v6_epoch_restore::NativeV6PendingEpochRestore,
    ) -> io::Result<()> {
        pending.validate().map_err(|_| refused())?;
        self.source(&pending.command.source)?;
        if let Some(intent) = &pending.intent {
            self.insert(intent.intent, intent.log)?;
        }
        Ok(())
    }
    fn state(&mut self, state: &MemStoreStateMachine) -> io::Result<()> {
        state.validate().map_err(|_| refused())?;
        for (_, (intent, origin)) in state.native_v6_retained_intents().map_err(|_| refused())? {
            self.insert(intent, origin)?;
        }
        if let Some(root) = &state.v6_root {
            state
                .native_v6_protected_intent_logs()
                .map_err(|_| refused())?;
            self.root(&root.command, root.publication_log)?;
            for step in &root.restore_lineage {
                self.pending(&step.pending)?;
                if let Some(roots) = &step.retained_roots {
                    self.root(&roots.source, step.pending.command.source.publication_log)?;
                    self.root(&roots.target, step.publication_log)?;
                }
            }
        }
        if let Some(pending) = &state.v6_pending_epoch_restore {
            self.pending(pending)?;
        }
        Ok(())
    }
    fn bundle(&mut self, bundle: &PersistentStateBundle) -> io::Result<()> {
        bundle.validate()?;
        self.state(&bundle.state)?;
        if let Some(snapshot) = &bundle.current_snapshot {
            self.state(&MemStoreStateMachine::from_snapshot(&snapshot.data)?)?;
        }
        Ok(())
    }
    fn entry(&mut self, index: u64, serialized: &str) -> io::Result<()> {
        let entry: EntryOf<TypeConfig> = serde_json::from_str(serialized).map_err(|_| refused())?;
        if entry.log_id.index != index {
            return Err(refused());
        }
        let EntryPayload::Normal(request) = &entry.payload else {
            return Ok(());
        };
        request.validate_size().map_err(|_| refused())?;
        let crate::ApplicationRequest::RecordsV5(data) = request else {
            return Ok(());
        };
        use crate::records::RecordCommand;
        match &data.records_v5 {
            RecordCommand::Stage { object }
                if object.reference().kind == crate::RecordObjectKind::NativeV6CommitIntent =>
            {
                // Rebuild through the strict object validator, not just a
                // filename/id or a deserialized byte vector.
                let intent =
                    NativeV6CommitIntent::decode(object.sealed()).map_err(|_| refused())?;
                if SealedRecordObject::new_native_v6_commit_intent(intent).map_err(|_| refused())?
                    != *object
                {
                    return Err(refused());
                }
                self.insert(intent, entry.log_id)?;
            }
            RecordCommand::PublishNativeV6 { root } => {
                self.root(root, entry.log_id)?;
            }
            RecordCommand::BeginNativeV6EpochRestore { pending } => {
                pending.validate().map_err(|_| refused())?;
                self.source(&pending.source)?;
            }
            RecordCommand::CancelNativeV6EpochRestore { pending } => self.pending(pending)?,
            RecordCommand::PublishNativeV6EpochRestore { publication } => {
                self.pending(&publication.pending)?;
                self.root(&publication.root, entry.log_id)?;
            }
            RecordCommand::RetireNativeV6Intents { retirement } => {
                retirement.validate().map_err(|_| refused())?
            }
            RecordCommand::ActivateNativeV6RetainedRoots { activation } => {
                activation.validate().map_err(|_| refused())?
            }
            _ => {}
        }
        Ok(())
    }
    fn log(&mut self, log: &PersistentLogState) -> io::Result<()> {
        log.validate()?;
        for (&index, entry) in &log.log {
            self.entry(index, entry)?;
        }
        Ok(())
    }
    fn finish(self) -> io::Result<BTreeMap<RecordObjectId, NativeV6CommitIntent>> {
        for (origin, expected) in self.required_origins {
            let actual = self.origins.get(&origin).ok_or_else(refused)?;
            if actual.proposed_root_digest != expected.root
                || actual.proposed_generation != expected.generation
                || actual.cluster_digest != expected.cluster
                || actual.epoch != expected.epoch
            {
                return Err(refused());
            }
        }
        Ok(self.intents)
    }
}

fn directory_identity(path: &Path) -> io::Result<(u64, u64, u32, u32)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = heptabao_filesystem_guard::open_absolute_directory_no_symlinks(path)
            .map_err(io::Error::other)?
            .metadata()?;
        if meta.mode() & 0o077 != 0 {
            return Err(refused());
        }
        Ok((meta.dev(), meta.ino(), meta.uid(), meta.mode()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(refused())
    }
}

fn exact_directory(directory: &ExclusiveDirectory, expected: &[&str]) -> io::Result<()> {
    directory.verify().map_err(io::Error::other)?;
    // Store I/O still uses its original path. Do not let a descriptor for a
    // renamed directory justify deletion while the live writer targets a new
    // directory at that path.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = heptabao_filesystem_guard::open_absolute_directory_no_symlinks(
            directory.original_path(),
        )
        .map_err(io::Error::other)?
        .metadata()?;
        if opened.dev() != directory.identity().device()
            || opened.ino() != directory.identity().inode()
        {
            return Err(refused());
        }
    }
    #[cfg(not(unix))]
    return Err(refused());
    let mut observed = BTreeSet::new();
    for entry in directory.entries()? {
        let leaf = entry?.into_string().map_err(|_| refused())?;
        if !expected.contains(&leaf.as_str()) || !observed.insert(leaf) {
            return Err(refused());
        }
    }
    if observed.len() != expected.len() {
        return Err(refused());
    }
    // In particular a .previous, .tmp, foreign snapshot or unknown sidecar is
    // unresolved retained history. It is never silently skipped or cleaned.
    Ok(())
}

fn frames<'a>(
    bytes: &'a [u8],
    header_len: usize,
    magic: [u8; 8],
    deadline: Instant,
    mut each: impl FnMut(&'a [u8]) -> io::Result<()>,
) -> io::Result<()> {
    check_deadline(deadline)?;
    let mut offset = header_len;
    if offset > bytes.len() {
        return Err(refused());
    }
    while offset < bytes.len() {
        check_deadline(deadline)?;
        if bytes.len() - offset < 20 || bytes[offset..offset + 8] != magic {
            return Err(refused());
        }
        let length = usize::try_from(u64::from_le_bytes(
            bytes[offset + 8..offset + 16]
                .try_into()
                .map_err(|_| refused())?,
        ))
        .map_err(|_| refused())?;
        if length > MAX_EVENT_BYTES {
            return Err(refused());
        }
        let end = offset
            .checked_add(20)
            .and_then(|n| n.checked_add(length))
            .ok_or_else(refused)?;
        if end > bytes.len() {
            return Err(refused());
        }
        let payload = &bytes[offset + 16..end - 4];
        if u32::from_le_bytes(bytes[end - 4..end].try_into().map_err(|_| refused())?)
            != crc32(payload)
        {
            return Err(refused());
        }
        each(payload)?;
        offset = end;
    }
    Ok(())
}

fn replay_log_readonly(
    bytes: &[u8],
    state: &mut PersistentLogState,
    retained: &mut RetainedIntents,
    deadline: Instant,
) -> io::Result<()> {
    if bytes.len() < 16 || bytes[..8] != LOG_JOURNAL_MAGIC {
        return Err(refused());
    }
    let epoch = u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| refused())?);
    if epoch == 0 || epoch > state.journal_epoch {
        return Err(refused());
    }
    let apply = epoch == state.journal_epoch;
    frames(bytes, 16, LOG_EVENT_MAGIC, deadline, |payload| {
        let event: LogJournalEvent = serde_json::from_slice(payload).map_err(|_| refused())?;
        if let LogJournalEvent::Append(entries) = &event {
            for (index, entry) in entries {
                retained.entry(*index, entry)?;
            }
        }
        // A durably newer checkpoint may cover an older journal, but the
        // latter's ciphertext references are still retained until it is gone.
        if apply {
            apply_log_journal_event(state, event)?;
        }
        Ok(())
    })?;
    state.validate()
}
fn replay_state_readonly(
    bytes: &[u8],
    bundle: &mut PersistentStateBundle,
    retained: &mut RetainedIntents,
    deadline: Instant,
) -> io::Result<()> {
    if bytes.len() < 8 || bytes[..8] != STATE_JOURNAL_MAGIC {
        return Err(refused());
    }
    frames(bytes, 8, STATE_EVENT_MAGIC, deadline, |payload| {
        let event: StateJournalEvent = serde_json::from_slice(payload).map_err(|_| refused())?;
        let StateJournalEvent::Apply { entry, .. } = &event;
        let decoded: EntryOf<TypeConfig> = serde_json::from_str(entry).map_err(|_| refused())?;
        retained.entry(decoded.log_id.index, entry)?;
        let _ = apply_state_journal_event(bundle, event)?;
        Ok(())
    })?;
    bundle.validate()
}

/// This handle keeps the actual log and state-machine writers quiescent.
/// There is no constructor, Clone or Serde. A caller-provided current root,
/// frontier, source directory or list of live names cannot manufacture it.
pub struct NativeV6RetentionGuard {
    _log: OwnedMutexGuard<PersistentLogState>,
    _bundle: OwnedMutexGuard<PersistentStateBundle>,
    log_directory: ExclusiveDirectory,
    state_directory: ExclusiveDirectory,
    log_files: Vec<RetainedFile>,
    state_files: Vec<RetainedFile>,
    intents: BTreeMap<RecordObjectId, NativeV6CommitIntent>,
    roots: BTreeMap<Log, crate::v6_root_publication::NativeV6RootCommand>,
    roots_overflowed: bool,
    source: NativeV6RetentionSource,
    deadline: Instant,
    raft_root: PathBuf,
    raft_identity: (u64, u64, u32, u32),
}
/// A complete DATA catalog borrowed from this exact opaque guard. It is
/// neither a fresh quorum/business read nor a physical-deletion capability.
pub struct NativeV6RetainedRootCatalog<'a> {
    guard: &'a NativeV6RetentionGuard,
}
/// One historical sealed root command under the catalog's actual held owner.
/// Uncommitted history is conservatively retained and never called published.
pub struct NativeV6RetainedRoot<'a> {
    guard: &'a NativeV6RetentionGuard,
    publication: Log,
    root: &'a crate::v6_root_publication::NativeV6RootCommand,
}
impl<'a> NativeV6RetainedRootCatalog<'a> {
    pub fn roots(&self) -> impl ExactSizeIterator<Item = NativeV6RetainedRoot<'a>> + '_ {
        let guard: &'a NativeV6RetentionGuard = self.guard;
        guard
            .roots
            .iter()
            .map(move |(publication, root)| NativeV6RetainedRoot {
                guard,
                publication: *publication,
                root,
            })
    }
    pub fn verify(&self) -> io::Result<()> {
        self.guard.verify()
    }
    pub fn fingerprint(&self) -> io::Result<[u8; 32]> {
        use sha2::{Digest, Sha256};
        self.verify()?;
        let mut hash = Sha256::new();
        hash.update(b"HeptaBao/native-v6/retained-root-catalog/v1\0");
        hash.update(self.guard.retention_fingerprint()?);
        hash.update((self.guard.roots.len() as u64).to_be_bytes());
        for (publication, root) in &self.guard.roots {
            check_deadline(self.guard.deadline)?;
            hash.update(serde_json::to_vec(publication).map_err(|_| refused())?);
            hash.update(serde_json::to_vec(root).map_err(|_| refused())?);
        }
        self.verify()?;
        Ok(hash.finalize().into())
    }
}
impl NativeV6RetainedRoot<'_> {
    pub fn verify(&self) -> io::Result<()> {
        self.guard.verify()
    }
    pub fn verify_shared_ownership(
        &self,
        store: &crate::LocalV6BlobStage,
        exclusive: &crate::NativeV6BlobQuiescence,
    ) -> io::Result<()> {
        self.verify()?;
        store
            .verify_retention_ownership(self.guard, exclusive)
            .map_err(|_| refused())?;
        self.verify()
    }
    pub(crate) fn retention_guard(&self) -> &NativeV6RetentionGuard {
        self.guard
    }
    pub fn intent(&self) -> NativeV6CommitIntent {
        self.root.intent
    }
    pub fn intent_log_id(&self) -> Log {
        self.root.intent_log
    }
    pub fn publication_log_id(&self) -> Log {
        self.publication
    }
    pub fn enrollment_digest(&self) -> [u8; 32] {
        self.root.enrollment_digest
    }
    pub fn sealed_root(&self) -> &[u8] {
        self.root.envelope.sealed()
    }
}

impl std::fmt::Debug for NativeV6RetentionGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeV6RetentionGuard")
            .field("retained_intents", &self.intents.len())
            .field("generation", &self.source.generation)
            .finish_non_exhaustive()
    }
}
impl NativeV6RetentionGuard {
    pub fn retained_intents(&self) -> impl ExactSizeIterator<Item = &NativeV6CommitIntent> {
        self.intents.values()
    }
    pub fn operation_deadline(&self) -> Instant {
        self.deadline
    }
    /// Complete retained-root DATA under the same held log/state writers.
    /// Missing historical sealed roots or unbounded history holds all local
    /// barrier deletion; ordinary shared-only retirement remains available.
    pub fn retained_root_catalog(&self) -> io::Result<NativeV6RetainedRootCatalog<'_>> {
        self.verify()?;
        if self._bundle.state.v6_retained_root_protocol
            != Some(crate::v6_retained_roots::RETAINED_ROOT_PROTOCOL)
        {
            return Err(refused());
        }
        if self.roots_overflowed || self.roots.is_empty() {
            return Err(refused());
        }
        let mut covered = BTreeSet::new();
        for root in self.roots.values() {
            check_deadline(self.deadline)?;
            let id = SealedRecordObject::new_native_v6_commit_intent(root.intent)
                .map_err(|_| refused())?
                .reference()
                .id;
            if self.intents.get(&id) != Some(&root.intent) {
                return Err(refused());
            }
            covered.insert(id);
        }
        if covered.len() != self.intents.len()
            || self.intents.keys().any(|id| !covered.contains(id))
        {
            return Err(refused());
        }
        self.verify()?;
        Ok(NativeV6RetainedRootCatalog { guard: self })
    }

    /// Public DATA digest only. Actual permission remains with this non-Clone
    /// handle, both held writers, source file descriptors and original bound.
    pub fn retention_fingerprint(&self) -> io::Result<[u8; 32]> {
        use sha2::{Digest, Sha256};
        self.verify()?;
        let mut hash = Sha256::new();
        hash.update(b"HeptaBao/native-v6/retained-source/v1\0");
        hash.update(serde_json::to_vec(&self.source).map_err(|_| refused())?);
        hash.update((self.intents.len() as u64).to_be_bytes());
        for (id, intent) in &self.intents {
            check_deadline(self.deadline)?;
            hash.update(id);
            hash.update(intent.encode().map_err(|_| refused())?);
        }
        self.verify()?;
        Ok(hash.finalize().into())
    }
    pub(crate) fn verify_blob_directory(&self, directory: &ExclusiveDirectory) -> io::Result<()> {
        self.verify()?;
        if directory.original_path() != self.raft_root.join("native-v6-ciphertext") {
            return Err(refused());
        }
        directory.verify().map_err(io::Error::other)
    }
    pub(crate) fn verify(&self) -> io::Result<()> {
        check_deadline(self.deadline)?;
        if directory_identity(&self.raft_root)? != self.raft_identity {
            return Err(refused());
        }
        exact_directory(
            &self.log_directory,
            &["initialized.bin", "raft-log.bin", "raft-log.journal"],
        )?;
        exact_directory(
            &self.state_directory,
            &[
                "initialized.bin",
                "state-bundle.bin",
                "state-machine.journal",
            ],
        )?;
        for file in &self.log_files {
            if file.identity.uid != self.raft_identity.2 {
                return Err(refused());
            }
            file.verify(&self.log_directory, self.deadline)?;
        }
        for file in &self.state_files {
            if file.identity.uid != self.raft_identity.2 {
                return Err(refused());
            }
            file.verify(&self.state_directory, self.deadline)?;
        }
        check_deadline(self.deadline)
    }
}

impl DurableStateMachine {
    pub(crate) async fn native_v6_retained_root_activation(
        &self,
        generation: u64,
        source: &NativeV6RetentionSource,
    ) -> io::Result<crate::v6_retained_roots::NativeV6RetainedRootActivation> {
        let owner = self.bundle.lock().await;
        if owner.generation != generation
            || NativeV6RetentionSource::from_state(&owner.state).map_err(|_| refused())? != *source
        {
            return Err(refused());
        }
        owner
            .state
            .prepare_native_v6_retained_root_activation()
            .map_err(|_| refused())
    }

    pub(crate) async fn native_v6_intent_retirement_observation(
        &self,
        generation: u64,
        source: &NativeV6RetentionSource,
        previous: &crate::v6_retention::NativeV6IntentRetirementRecovery,
    ) -> io::Result<crate::v6_retention::NativeV6IntentRetirementResolution> {
        let owner = self.bundle.lock().await;
        if owner.generation != generation
            || NativeV6RetentionSource::from_state(&owner.state).map_err(|_| refused())? != *source
        {
            return Err(refused());
        }
        owner
            .state
            .observe_native_v6_intent_retirement(previous)
            .map_err(|_| refused())
    }

    pub(crate) async fn native_v6_retirement_command(
        &self,
        generation: u64,
        source: &NativeV6RetentionSource,
        limit: usize,
    ) -> io::Result<NativeV6IntentRetirementCommand> {
        let owner = self.bundle.lock().await;
        if owner.generation != generation
            || NativeV6RetentionSource::from_state(&owner.state).map_err(|_| refused())? != *source
        {
            return Err(refused());
        }
        owner
            .state
            .prepare_native_v6_intent_retirement(limit)
            .map_err(|_| refused())
    }

    pub(crate) async fn native_v6_retention_guard(
        &self,
        log: &DurableLogStore,
        generation: u64,
        source: NativeV6RetentionSource,
        deadline: Instant,
    ) -> io::Result<NativeV6RetentionGuard> {
        check_deadline(deadline)?;
        // One fixed order, held through all physical retirement. Normal store
        // writers acquire only their own lock, so there is no reverse pair.
        let log_owner = log.state.clone().lock_owned().await;
        let bundle_owner = self.bundle.clone().lock_owned().await;
        let log_path = log.state_path.clone();
        let state_path = self.bundle_path.clone();
        tokio::task::spawn_blocking(move || {
            check_deadline(deadline)?;
            if bundle_owner.generation != generation
                || bundle_owner.state.v6_retention_protocol
                    != Some(crate::v6_retention::RETENTION_PROTOCOL)
                || NativeV6RetentionSource::from_state(&bundle_owner.state)
                    .map_err(|_| refused())?
                    != source
            {
                return Err(refused());
            }
            let raft_root = log_path
                .parent()
                .and_then(Path::parent)
                .ok_or_else(refused)?
                .to_path_buf();
            if state_path.parent().and_then(Path::parent) != Some(raft_root.as_path()) {
                return Err(refused());
            }
            let raft_identity = directory_identity(&raft_root)?;
            let log_directory = ExclusiveDirectory::open(log_path.parent().ok_or_else(refused)?)
                .map_err(io::Error::other)?;
            let state_directory =
                ExclusiveDirectory::open(state_path.parent().ok_or_else(refused)?)
                    .map_err(io::Error::other)?;
            exact_directory(
                &log_directory,
                &["initialized.bin", "raft-log.bin", "raft-log.journal"],
            )?;
            exact_directory(
                &state_directory,
                &[
                    "initialized.bin",
                    "state-bundle.bin",
                    "state-machine.journal",
                ],
            )?;
            let mut retained = RetainedIntents::default();
            let mut log_files = Vec::new();
            let mut state_files = Vec::new();
            for (directory, domain, file, output) in [
                (&log_directory, LOG_DOMAIN, "raft-log.bin", &mut log_files),
                (
                    &state_directory,
                    STATE_MACHINE_DOMAIN,
                    "state-bundle.bin",
                    &mut state_files,
                ),
            ] {
                let (owned, bytes) =
                    RetainedFile::read(directory, "initialized.bin", 4096, deadline)?;
                let marker: PersistentInitializationMarker =
                    serde_json::from_slice(&decode_envelope(INITIALIZATION_MAGIC, &bytes)?)
                        .map_err(|_| refused())?;
                marker.validate(domain, file)?;
                output.push(owned);
            }
            let (owned, bytes) = RetainedFile::read(
                &log_directory,
                "raft-log.bin",
                MAX_DURABLE_ARTIFACT_BYTES,
                deadline,
            )?;
            let mut disk_log: PersistentLogState =
                serde_json::from_slice(&decode_envelope(LOG_MAGIC, &bytes)?)
                    .map_err(|_| refused())?;
            log_files.push(owned);
            if disk_log.journal_format != 1 {
                return Err(refused());
            }
            retained.log(&disk_log)?;
            let (owned, bytes) = RetainedFile::read(
                &log_directory,
                "raft-log.journal",
                MAX_JOURNAL_BYTES,
                deadline,
            )?;
            replay_log_readonly(&bytes, &mut disk_log, &mut retained, deadline)?;
            log_files.push(owned);
            if serde_json::to_value(&disk_log).map_err(|_| refused())?
                != serde_json::to_value(&*log_owner).map_err(|_| refused())?
            {
                return Err(refused());
            }
            retained.log(&log_owner)?;
            let (owned, bytes) = RetainedFile::read(
                &state_directory,
                "state-bundle.bin",
                MAX_DURABLE_ARTIFACT_BYTES,
                deadline,
            )?;
            let mut disk_bundle: PersistentStateBundle =
                serde_json::from_slice(&decode_envelope(STATE_BUNDLE_MAGIC, &bytes)?)
                    .map_err(|_| refused())?;
            state_files.push(owned);
            if disk_bundle.journal_format != 1 {
                return Err(refused());
            }
            retained.bundle(&disk_bundle)?;
            let (owned, bytes) = RetainedFile::read(
                &state_directory,
                "state-machine.journal",
                MAX_JOURNAL_BYTES,
                deadline,
            )?;
            replay_state_readonly(&bytes, &mut disk_bundle, &mut retained, deadline)?;
            state_files.push(owned);
            if serde_json::to_value(&disk_bundle).map_err(|_| refused())?
                != serde_json::to_value(&*bundle_owner).map_err(|_| refused())?
            {
                return Err(refused());
            }
            retained.bundle(&bundle_owner)?;
            let roots = std::mem::take(&mut retained.roots);
            let roots_overflowed = retained.roots_overflowed;
            let guard = NativeV6RetentionGuard {
                _log: log_owner,
                _bundle: bundle_owner,
                log_directory,
                state_directory,
                log_files,
                state_files,
                intents: retained.finish()?,
                roots,
                roots_overflowed,
                source,
                deadline,
                raft_root,
                raft_identity,
            };
            guard.verify()?;
            Ok(guard)
        })
        .await
        .map_err(|_| refused())?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn intent() -> NativeV6CommitIntent {
        NativeV6CommitIntent {
            cluster_digest: [1; 32],
            epoch: 3,
            operation_digest: [2; 32],
            closure_manifest_sha256: [3; 32],
            object_count: 1,
            ciphertext_bytes: 64,
            prior_root_digest: [4; 32],
            proposed_root_digest: [5; 32],
            prior_generation: 1,
            proposed_generation: 2,
            expected_previous_commit_index: 2,
        }
    }
    fn log(index: u64) -> Log {
        openraft::LogId {
            leader_id: openraft::impls::leader_id_adv::LeaderId {
                term: 1,
                node_id: 1,
            },
            index,
        }
    }
    #[test]
    fn native_retention_journal_reader_rejects_every_incomplete_tail_and_bad_checksum()
    -> io::Result<()> {
        let until = Instant::now() + std::time::Duration::from_secs(5);
        let payload = br#"{"only":"public-fixture"}"#;
        let mut complete = STATE_JOURNAL_MAGIC.to_vec();
        complete.extend_from_slice(&encode_envelope(STATE_EVENT_MAGIC, payload)?);
        let mut seen = 0;
        frames(&complete, 8, STATE_EVENT_MAGIC, until, |actual| {
            assert_eq!(actual, payload);
            seen += 1;
            Ok(())
        })?;
        assert_eq!(seen, 1);
        for length in 9..complete.len() {
            assert!(frames(&complete[..length], 8, STATE_EVENT_MAGIC, until, |_| Ok(())).is_err());
        }
        let last = complete.len() - 1;
        complete[last] ^= 1;
        assert!(frames(&complete, 8, STATE_EVENT_MAGIC, until, |_| Ok(())).is_err());
        assert!(
            frames(
                &STATE_JOURNAL_MAGIC,
                8,
                STATE_EVENT_MAGIC,
                Instant::now(),
                |_| Ok(())
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn native_retention_catalog_requires_exact_historical_root_and_unique_full_origin()
    -> io::Result<()> {
        let current = intent();
        for changed in 0..5 {
            let mut retained = RetainedIntents::default();
            retained.insert(current, log(3))?;
            let mut source = HistoricalSource {
                root: current.proposed_root_digest,
                generation: current.proposed_generation,
                cluster: current.cluster_digest,
                epoch: current.epoch,
            };
            let mut origin = log(3);
            match changed {
                0 => source.root[0] ^= 1,
                1 => source.generation += 1,
                2 => source.cluster[0] ^= 1,
                3 => source.epoch += 1,
                _ => origin.leader_id.node_id = 2,
            }
            retained.required_origins.insert(origin, source);
            assert!(retained.finish().is_err());
        }
        let mut retained = RetainedIntents::default();
        retained.insert(current, log(3))?;
        let different = NativeV6CommitIntent {
            operation_digest: [9; 32],
            ..current
        };
        assert!(retained.insert(different, log(3)).is_err());
        Ok(())
    }
    #[test]
    fn native_retention_local_catalog_bound_never_truncates_shared_retention() -> io::Result<()> {
        let intent = intent();
        let root = crate::v6_root_publication::NativeV6RootCommand {
            intent,
            intent_log: log(3),
            enrollment_digest: [9; 32],
            envelope: crate::ReplicatedEnvelope::new(
                crate::v6_root_publication::NativeV6RootCommand::operation_id(&intent),
                intent.proposed_root_digest,
                vec![0x55; 64],
            )
            .map_err(io::Error::other)?,
        };
        let mut retained = RetainedIntents {
            roots_bytes: MAX_RETAINED_ROOT_BYTES,
            ..Default::default()
        };
        retained.root(&root, log(4))?;
        assert!(retained.roots_overflowed);
        assert!(retained.roots.is_empty());
        retained.root(&root, log(5))?;
        assert!(
            retained.roots.is_empty(),
            "an overflowed local union cannot become a truncated complete mark"
        );
        assert_eq!(
            retained.finish()?.into_values().collect::<Vec<_>>(),
            vec![intent],
            "the original shared intent catalog remains complete and usable"
        );
        Ok(())
    }
    #[test]
    fn native_retention_covered_old_log_journal_still_marks_its_external_intents() -> io::Result<()>
    {
        let current = intent();
        let object =
            SealedRecordObject::new_native_v6_commit_intent(current).map_err(io::Error::other)?;
        let request =
            crate::ApplicationRequest::records(3, crate::records::RecordCommand::Stage { object })
                .map_err(|_| refused())?;
        let entry = EntryOf::<TypeConfig> {
            log_id: log(3),
            payload: EntryPayload::Normal(request),
        };
        let event = LogJournalEvent::Append(vec![(
            3,
            serde_json::to_string(&entry).map_err(io::Error::other)?,
        )]);
        let mut bytes = LOG_JOURNAL_MAGIC.to_vec();
        bytes.extend_from_slice(&1_u64.to_le_bytes());
        bytes.extend_from_slice(&encode_envelope(
            LOG_EVENT_MAGIC,
            &serde_json::to_vec(&event).map_err(io::Error::other)?,
        )?);
        let mut state = PersistentLogState {
            journal_format: 1,
            journal_epoch: 2,
            last_purged_log_id: Some(log(9)),
            ..PersistentLogState::default()
        };
        let mut retained = RetainedIntents::default();
        replay_log_readonly(
            &bytes,
            &mut state,
            &mut retained,
            Instant::now() + std::time::Duration::from_secs(5),
        )?;
        assert!(state.log.is_empty());
        assert_eq!(
            retained.finish()?.into_values().collect::<Vec<_>>(),
            vec![current]
        );
        Ok(())
    }
}
