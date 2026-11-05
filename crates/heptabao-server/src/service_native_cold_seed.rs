//! Offline recovery of the authenticated migration seed from a complete HA
//! snapshot and its matching Shamir seal envelope. The current native graph is
//! fully checked before publication, but this output is ONLY a bootstrap seed:
//! the new cohort must still restore that complete graph through real quorum.
//! No old shared key, donor, Raft database or serialized capability is used.
use super::*;
use crate::crypto::AeadBarrier;
use crate::ha::native_v6_backup::{NativeV6ArchiveError, validate_cold_native_v6_archive};
use crate::service::{
    MAX_OPERATIONS, Service, State, collect_seal_key, native_blob_source, native_v6_ha_install,
    native_v6_reader, records, snapshot_transfer, v6_records,
};
use crate::snapshot_file::{
    MAX_NATIVE_ARCHIVE, MAX_V6_SNAPSHOT_STATE, SnapshotFile, SnapshotSpool,
};
use crate::state_record_root::RecordStateRoot;
use crate::state_record_root_v6::{ObjectDomain, RecordStateRootV6};
use crate::state_records::{ObjectRef, RecordError, RecordReader};
use crate::v6_native_custody::OriginalDeadline;
use crate::v6_read_validation::{ObjectSource, ReadContext, ReadIdentity};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use heptabao_durable_service::{
    Barrier, BatchPublication, DurableService, PreparedRestore, PreparedV6Restore,
    PublicationCondition, Secret, ServiceError,
};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const MAX_SHARES_BYTES: u64 = 16 * 1024;
const COLD_SEED_BUDGET: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ColdSeedError {
    InvalidInput,
    UnsafeOwner,
    InputChanged,
    SealRejected,
    ArchiveRejected,
    GraphRejected,
    Deadline,
    DestinationExists,
    Storage,
    OutcomeUnknown,
}

impl std::fmt::Display for ColdSeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid cold seed input",
            Self::UnsafeOwner => "cold seed requires private descriptor custody",
            Self::InputChanged => "cold seed input bytes or ownership changed",
            Self::SealRejected => "cold seed Shamir seal authentication failed",
            Self::ArchiveRejected => "cold seed complete archive authentication failed",
            Self::GraphRejected => "cold seed complete typed graph authentication failed",
            Self::Deadline => "cold seed original operation deadline expired",
            Self::DestinationExists => "cold seed destination already exists",
            Self::Storage => "cold seed private staging failed; retain staging for reconciliation",
            Self::OutcomeUnknown => {
                "cold seed publication outcome is unknown; reconcile without retry"
            }
        })
    }
}
impl std::error::Error for ColdSeedError {}
impl From<SeedError> for ColdSeedError {
    fn from(error: SeedError) -> Self {
        match error {
            SeedError::InvalidInput | SeedError::UnsupportedPlatform => Self::InvalidInput,
            SeedError::UnsafeOwner | SeedError::WriterActive => Self::UnsafeOwner,
            SeedError::SourceRejected | SeedError::SourceChanged | SeedError::ReceiptRejected => {
                Self::InputChanged
            }
            SeedError::DestinationExists => Self::DestinationExists,
            SeedError::Io => Self::Storage,
            SeedError::OutcomeUnknown => Self::OutcomeUnknown,
        }
    }
}

/// No credential, payload, path or Raft handle is serialized. A seed receipt
/// explicitly cannot claim that the latest data was installed or HA recovered.
#[derive(Serialize)]
pub struct ColdSeedReceipt {
    schema: u32,
    operation: &'static str,
    archive_sha256: String,
    seal_metadata_sha256: String,
    native_root_sha256: String,
    native_replay_epoch: u64,
    native_local_generation: u64,
    native_local_object_count: usize,
    retained_source_root_sha256: String,
    retained_source_replay_epoch: u64,
    bootstrap_root_sha256: String,
    bootstrap_replay_epoch: u64,
    bootstrap_object_count: usize,
    seed: SeedManifest,
    seed_manifest_sha256: String,
    complete_archive_and_graph_authenticated: bool,
    every_file_synced_and_read_back: bool,
    atomic_directory_publication_synced: bool,
    source_inputs_unchanged: bool,
    current_native_data_installed: bool,
    ha_qualified: bool,
}

fn live(deadline: OriginalDeadline) -> Result<(), ColdSeedError> {
    deadline.check().map_err(|_| ColdSeedError::Deadline)
}
fn io_failure(_: impl std::fmt::Debug) -> std::io::Error {
    std::io::Error::other("cold seed input custody is unavailable")
}

// Each held descriptor has a fixed private inode and length. Reads never use
// an archive-supplied pathname, follow a link or accept an ambient replacement.
struct PinnedInput {
    parent: File,
    parent_path: PathBuf,
    parent_identity: (u64, u64),
    leaf: String,
    file: File,
    witness: FileWitness,
    bound: u64,
    deadline: OriginalDeadline,
}

impl PinnedInput {
    fn open(path: &Path, bound: u64, deadline: OriginalDeadline) -> Result<Self, ColdSeedError> {
        use rustix::fs::{Mode, OFlags, openat};
        live(deadline)?;
        let (parent_path, leaf) = target_parts(path)?;
        let parent = open_absolute_directory_no_symlinks(parent_path)
            .map_err(|_| ColdSeedError::UnsafeOwner)?;
        let metadata = parent.metadata().map_err(|_| ColdSeedError::UnsafeOwner)?;
        if !private_directory(&metadata) {
            return Err(ColdSeedError::UnsafeOwner);
        }
        let file = File::from(
            openat(
                &parent,
                leaf,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| ColdSeedError::UnsafeOwner)?,
        );
        let witness = FileWitness::capture(&file, bound)?;
        if witness.bytes == 0 {
            return Err(ColdSeedError::InvalidInput);
        }
        let input = Self {
            parent,
            parent_path: parent_path.to_owned(),
            parent_identity: (metadata.dev(), metadata.ino()),
            leaf: leaf.to_owned(),
            file,
            witness,
            bound,
            deadline,
        };
        input.check()?;
        Ok(input)
    }

    fn check(&self) -> Result<(), ColdSeedError> {
        use rustix::fs::{Mode, OFlags, openat};
        live(self.deadline)?;
        self.witness.check(&self.file, self.bound)?;
        for metadata in [
            self.parent
                .metadata()
                .map_err(|_| ColdSeedError::InputChanged)?,
            open_absolute_directory_no_symlinks(&self.parent_path)
                .map_err(|_| ColdSeedError::InputChanged)?
                .metadata()
                .map_err(|_| ColdSeedError::InputChanged)?,
        ] {
            if !private_directory(&metadata)
                || (metadata.dev(), metadata.ino()) != self.parent_identity
            {
                return Err(ColdSeedError::InputChanged);
            }
        }
        let current = File::from(
            openat(
                &self.parent,
                self.leaf.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| ColdSeedError::InputChanged)?,
        );
        self.witness.check(&current, self.bound)?;
        live(self.deadline)
    }

    fn small(&mut self) -> Result<Zeroizing<Vec<u8>>, ColdSeedError> {
        self.check()?;
        self.seek(SeekFrom::Start(0))
            .map_err(|_| ColdSeedError::InputChanged)?;
        let length =
            usize::try_from(self.witness.bytes).map_err(|_| ColdSeedError::InvalidInput)?;
        let mut bytes = Zeroizing::new(vec![0; length]);
        self.read_exact(&mut bytes)
            .map_err(|_| ColdSeedError::InputChanged)?;
        self.check()?;
        Ok(bytes)
    }

    fn digest(&mut self) -> Result<String, ColdSeedError> {
        self.check()?;
        self.seek(SeekFrom::Start(0))
            .map_err(|_| ColdSeedError::InputChanged)?;
        let mut remaining = self.witness.bytes;
        let mut buffer = Zeroizing::new([0_u8; BUFFER_BYTES]);
        let mut hash = Sha256::new();
        while remaining != 0 {
            let amount = remaining.min(BUFFER_BYTES as u64) as usize;
            self.read_exact(&mut buffer[..amount])
                .map_err(|_| ColdSeedError::InputChanged)?;
            hash.update(&buffer[..amount]);
            remaining -= amount as u64;
        }
        self.check()?;
        Ok(hex(hash.finalize().as_ref()))
    }
}

impl Read for PinnedInput {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        live(self.deadline).map_err(io_failure)?;
        self.witness
            .check(&self.file, self.bound)
            .map_err(io_failure)?;
        let count = self.file.read(output)?;
        self.witness
            .check(&self.file, self.bound)
            .map_err(io_failure)?;
        live(self.deadline).map_err(io_failure)?;
        Ok(count)
    }
}
impl Seek for PinnedInput {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        live(self.deadline).map_err(io_failure)?;
        self.witness
            .check(&self.file, self.bound)
            .map_err(io_failure)?;
        let result = self.file.seek(position)?;
        live(self.deadline).map_err(io_failure)?;
        Ok(result)
    }
}

struct WorkDirectory {
    fence: DirectoryFence,
    path: PathBuf,
}
impl WorkDirectory {
    fn create(parent: &DirectoryFence) -> Result<Self, ColdSeedError> {
        parent.verify_at(parent.guard.original_path())?;
        let leaf = format!(
            ".heptabao-cold-stage-{}",
            hex(&crypto::random::<16>().map_err(|_| ColdSeedError::Storage)?)
        );
        rustix::fs::mkdirat(&parent.handle, leaf.as_str(), rustix::fs::Mode::RWXU)
            .map_err(|_| ColdSeedError::Storage)?;
        let path = parent.guard.original_path().join(leaf);
        let fence = DirectoryFence::acquire(&path)?;
        parent.verify_at(parent.guard.original_path())?;
        Ok(Self { fence, path })
    }

    fn create_child(&self, leaf: &str) -> Result<PathBuf, ColdSeedError> {
        self.fence.verify_at(&self.path)?;
        rustix::fs::mkdirat(&self.fence.handle, leaf, rustix::fs::Mode::RWXU)
            .map_err(|_| ColdSeedError::Storage)?;
        self.fence.verify_at(&self.path)?;
        Ok(self.path.join(leaf))
    }
}

fn old_barrier_key(
    seal: &SealMetadata,
    encoded: &[u8],
) -> Result<Zeroizing<[u8; 32]>, ColdSeedError> {
    seal.validate().map_err(|_| ColdSeedError::SealRejected)?;
    if seal.is_wrapper() || seal.share_format != "shamir-v1" {
        return Err(ColdSeedError::SealRejected);
    }
    let shares: Vec<String> =
        serde_json::from_slice(encoded).map_err(|_| ColdSeedError::SealRejected)?;
    let shares = Zeroizing::new(shares);
    if shares.len() != usize::from(seal.secret_threshold) {
        return Err(ColdSeedError::SealRejected);
    }
    let mut provided = BTreeMap::new();
    let mut recovered = None;
    for share in shares.iter() {
        recovered = collect_seal_key(seal, share, &mut provided)
            .map_err(|_| ColdSeedError::SealRejected)?
            .map(Zeroizing::new);
    }
    if provided.len() != usize::from(seal.secret_threshold) {
        return Err(ColdSeedError::SealRejected);
    }
    let seal_key = recovered.ok_or(ColdSeedError::SealRejected)?;
    let wrapped = Zeroizing::new(
        STANDARD
            .decode(&seal.wrapped_barrier_key)
            .map_err(|_| ColdSeedError::SealRejected)?,
    );
    crypto::unwrap_barrier_key(&seal_key, &seal.associated_data(), &wrapped)
        .map(Zeroizing::new)
        .map_err(|_| ColdSeedError::SealRejected)
}

struct ArchiveObjects<'a> {
    durable: &'a DurableService<AeadBarrier>,
    archive: RefCell<&'a mut PreparedV6Restore<SnapshotFile>>,
    root_bytes: &'a [u8],
    gate: &'a dyn Fn() -> Result<(), ColdSeedError>,
}
impl ObjectSource for ArchiveObjects<'_> {
    fn read(
        &self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        (self.gate)().map_err(|_| RecordError::Invalid)?;
        let mut archive = self
            .archive
            .try_borrow_mut()
            .map_err(|_| RecordError::Invalid)?;
        let resource = v6_records::native_resource(domain, reference);
        let slot = archive
            .state()
            .get("system", &resource)
            .map_err(|_| RecordError::Corrupt)?
            .ok_or(RecordError::Missing)?;
        native_blob_source::validate_archive_slot(self.root_bytes, slot, reference)?;
        let bytes = self
            .durable
            .read_v6_restore_object(&mut archive, &resource, &mut || {
                (self.gate)().map_err(|_| ServiceError::BarrierFailure)
            })
            .map_err(|_| RecordError::Corrupt)?;
        (self.gate)().map_err(|_| RecordError::Invalid)?;
        if bytes.len() != reference.encoded_bytes as usize {
            return Err(RecordError::Corrupt);
        }
        Ok(bytes)
    }
}

struct MigrationObjects<'a> {
    state: &'a PreparedRestore,
    root: &'a RecordStateRoot,
    objects: RefCell<BTreeMap<String, Zeroizing<Vec<u8>>>>,
    gate: &'a dyn Fn() -> Result<(), ColdSeedError>,
}
impl RecordReader for MigrationObjects<'_> {
    fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        (self.gate)().map_err(|_| RecordError::Invalid)?;
        let resource = reference.resource();
        let bytes = self
            .state
            .get("system", &resource)
            .map_err(|_| RecordError::Corrupt)?
            .ok_or(RecordError::Missing)?;
        reference.verify(&self.root.address_key(), bytes)?;
        let mut objects = self
            .objects
            .try_borrow_mut()
            .map_err(|_| RecordError::Invalid)?;
        match objects.get(&resource) {
            Some(previous) if previous.as_slice() != bytes => return Err(RecordError::Corrupt),
            Some(_) => {}
            None => {
                objects.insert(resource, Zeroizing::new(bytes.to_vec()));
            }
        }
        (self.gate)().map_err(|_| RecordError::Invalid)?;
        Ok(Zeroizing::new(bytes.to_vec()))
    }
}

fn root_scope(state: &State) -> Result<(), ColdSeedError> {
    if crate::service::namespaces::native_empty::require_catalog_profile(state).is_err()
        || state.auth.has_recovery_state()
        || !state.database.is_empty()
        || crate::service::namespaces::native_plain::profile(state).is_err()
        || !crate::service::native_controlgroups::supported_state(state)
        || !state.raft_admin.is_default()
    {
        return Err(ColdSeedError::GraphRejected);
    }
    state
        .validate_format()
        .map_err(|_| ColdSeedError::GraphRejected)
}

/// Build ONLY the retained, authenticated migration seed in a new destination.
/// Inputs are the actual gzip/tar snapshot, matching encrypted seal.json and a
/// private JSON array containing exactly the old Shamir threshold. Neither a
/// share nor a barrier key may be supplied through command-line arguments.
/// After this returns, operators must create the new actual cohort and restore
/// the complete snapshot before directing any production traffic to it.
pub fn recover_ha_seed(
    archive_path: &Path,
    seal_path: &Path,
    shares_path: &Path,
    destination: &Path,
    expected_archive_sha256: &str,
    expected_seal_sha256: &str,
) -> Result<ColdSeedReceipt, ColdSeedError> {
    if !cfg!(any(target_os = "linux", target_os = "macos"))
        || !valid_hash(expected_archive_sha256)
        || !valid_hash(expected_seal_sha256)
        || archive_path == seal_path
        || archive_path == shares_path
        || seal_path == shares_path
        || crate::request_deadline::current().is_some()
    {
        return Err(ColdSeedError::InvalidInput);
    }
    // One original offline operation budget; nested work never resets it.
    let _scope =
        crate::request_deadline::RequestDeadlineScope::enter(Instant::now() + COLD_SEED_BUDGET);
    let deadline = OriginalDeadline::capture().map_err(|_| ColdSeedError::Deadline)?;
    let mut archive_input = PinnedInput::open(archive_path, MAX_NATIVE_ARCHIVE, deadline)?;
    let mut seal_input = PinnedInput::open(seal_path, SEAL_METADATA_LIMIT, deadline)?;
    let mut shares_input = PinnedInput::open(shares_path, MAX_SHARES_BYTES, deadline)?;
    let seal_bytes = seal_input.small()?;
    if hex(&crypto::digest(&seal_bytes)) != expected_seal_sha256 {
        return Err(ColdSeedError::InputChanged);
    }
    let seal: SealMetadata =
        serde_json::from_slice(&seal_bytes).map_err(|_| ColdSeedError::SealRejected)?;
    let shares_bytes = shares_input.small()?;
    let key = old_barrier_key(&seal, &shares_bytes)?;
    drop(shares_bytes);
    let seal_identity = snapshot_transfer::canonical_seal_identity(&seal)
        .map_err(|_| ColdSeedError::SealRejected)?;
    let barrier = AeadBarrier::new(*key).map_err(|_| ColdSeedError::SealRejected)?;
    let (parent_path, target_leaf) = target_parts(destination)?;
    let parent = DirectoryFence::acquire(parent_path)?;
    if parent
        .guard
        .entry_exists(target_leaf)
        .map_err(|_| ColdSeedError::UnsafeOwner)?
    {
        return Err(ColdSeedError::DestinationExists);
    }
    let work = WorkDirectory::create(&parent)?;
    let spool = SnapshotSpool::open(&work.path).map_err(|_| ColdSeedError::Storage)?;
    let lease = spool.lease().map_err(|_| ColdSeedError::Storage)?;
    let mut transported = lease
        .file(MAX_NATIVE_ARCHIVE, deadline.instant())
        .map_err(|_| ColdSeedError::Storage)?;
    let mut digest = Sha256::new();
    let mut buffer = Zeroizing::new([0_u8; BUFFER_BYTES]);
    let mut remaining = archive_input.witness.bytes;
    while remaining != 0 {
        let amount = remaining.min(BUFFER_BYTES as u64) as usize;
        archive_input
            .read_exact(&mut buffer[..amount])
            .map_err(|_| ColdSeedError::InputChanged)?;
        transported
            .write_all(&buffer[..amount])
            .map_err(|_| ColdSeedError::Storage)?;
        digest.update(&buffer[..amount]);
        remaining -= amount as u64;
    }
    archive_input.check()?;
    if hex(digest.finalize().as_ref()) != expected_archive_sha256 {
        return Err(ColdSeedError::InputChanged);
    }
    let gate = || -> Result<(), ColdSeedError> {
        live(deadline)?;
        archive_input.check()?;
        seal_input.check()?;
        shares_input.check()?;
        parent.verify_at(parent_path)?;
        work.fence.verify_at(&work.path)?;
        live(deadline)
    };
    gate()?;
    let imported = crate::snapshot_archive::import(transported, &lease, deadline.instant())
        .map_err(|_| ColdSeedError::ArchiveRejected)?;
    if !imported.metadata.is_v6_ha()
        || !imported
            .metadata
            .seal_identity()
            .is_some_and(|identity| identity.matches(&seal_identity))
    {
        return Err(ColdSeedError::ArchiveRejected);
    }
    let sums = Zeroizing::new(
        barrier
            .open(
                crate::snapshot_archive::CHECKSUM_CONTEXT,
                &imported.sealed_sums,
            )
            .map_err(|_| ColdSeedError::ArchiveRejected)?,
    );
    if sums.as_slice() != imported.sums.as_slice() {
        return Err(ColdSeedError::ArchiveRejected);
    }
    let generation = imported.metadata.generation();
    let (mut checked, facts) = validate_cold_native_v6_archive(
        imported.state,
        seal_identity,
        &barrier,
        deadline,
        &mut || gate().map_err(|_| NativeV6ArchiveError::Gate),
    )
    .map_err(|_| ColdSeedError::ArchiveRejected)?;
    let report = checked.report();
    if report.local.generation != generation {
        return Err(ColdSeedError::ArchiveRejected);
    }
    let mut local = lease
        .file(MAX_V6_SNAPSHOT_STATE, deadline.instant())
        .map_err(|_| ColdSeedError::Storage)?;
    checked
        .copy_local_pack_to(&mut local, &mut || {
            gate().map_err(|_| NativeV6ArchiveError::Gate)
        })
        .map_err(|_| ColdSeedError::ArchiveRejected)?;
    drop(checked);
    gate()?;
    let decoder_path = work.create_child("decode")?;
    let decoder = DurableService::create_new(
        &decoder_path,
        AeadBarrier::new(*key).map_err(|_| ColdSeedError::SealRejected)?,
        MAX_OPERATIONS,
    )
    .map_err(|_| ColdSeedError::Storage)?;
    let mut prepared = decoder
        .prepare_v6_restore_from_reader(
            local,
            report.local.archive_bytes,
            &mut || gate().map_err(|_| ServiceError::BarrierFailure),
            &mut |_, _, _| Ok(()),
        )
        .map_err(|_| ColdSeedError::ArchiveRejected)?;
    if prepared.size() != report.local
        || prepared.state().metadata().replay_epoch != facts.replay_epoch()
    {
        return Err(ColdSeedError::ArchiveRejected);
    }
    let root_bytes = Zeroizing::new(
        prepared
            .state()
            .get("system", "state")
            .map_err(|_| ColdSeedError::GraphRejected)?
            .ok_or(ColdSeedError::GraphRejected)?
            .to_vec(),
    );
    let root = RecordStateRootV6::decode(&root_bytes).map_err(|_| ColdSeedError::GraphRejected)?;
    if root
        .identity()
        .map_err(|_| ColdSeedError::GraphRejected)?
        .digest()
        != facts.root_digest()
        || root.replay_epoch != facts.replay_epoch()
        || root.reader_floor.native_kv2_format != 2
        || (root.state_schema < crate::service::NATIVE_PLAIN_NAMESPACE_STATE_SCHEMA
            && root
                .kv2
                .iter()
                .any(|graph| !graph.scope.namespace.is_empty()))
    {
        return Err(ColdSeedError::GraphRejected);
    }
    let retained_bytes = Zeroizing::new(
        prepared
            .state()
            .get("system", native_v6_reader::ACTIVE_SOURCE_ROOT_RESOURCE)
            .map_err(|_| ColdSeedError::GraphRejected)?
            .ok_or(ColdSeedError::GraphRejected)?
            .to_vec(),
    );
    let retained =
        RecordStateRoot::decode(&retained_bytes).map_err(|_| ColdSeedError::GraphRejected)?;
    native_v6_ha_install::validate_cold_archive_cursor(
        &root,
        &retained,
        prepared
            .state()
            .get("system", native_v6_reader::ACTIVE_CURSOR_RESOURCE)
            .map_err(|_| ColdSeedError::GraphRejected)?
            .ok_or(ColdSeedError::GraphRejected)?,
        prepared
            .state()
            .get("system", native_v6_ha_install::HA_CURSOR_RESOURCE)
            .map_err(|_| ColdSeedError::GraphRejected)?
            .ok_or(ColdSeedError::GraphRejected)?,
        generation,
        &facts,
    )
    .map_err(|_| ColdSeedError::GraphRejected)?;
    {
        let objects = ArchiveObjects {
            durable: &decoder,
            archive: RefCell::new(&mut prepared),
            root_bytes: &root_bytes,
            gate: &gate,
        };
        let (mut state, native) = v6_records::materialize_for_service(
            &root,
            ReadContext {
                expected_identity: ReadIdentity::RecordsV6(facts.root_digest()),
                cluster_id: &root.cluster_id,
                replay_epoch: root.replay_epoch,
                minimum_state_schema: root.state_schema,
                maximum_state_schema: root.state_schema,
                reader_format: crate::state_record_root_v6::READER_FORMAT,
            },
            &objects,
        )
        .map_err(|_| ColdSeedError::GraphRejected)?;
        state
            .engines
            .install_native_views(native)
            .map_err(|_| ColdSeedError::GraphRejected)?;
        root_scope(&state)?;
    }
    gate()?;
    let migration = MigrationObjects {
        state: prepared.state(),
        root: &retained,
        objects: RefCell::new(BTreeMap::new()),
        gate: &gate,
    };
    let mut old = Service::materialize_record_state(&retained, &migration)
        .map_err(|_| ColdSeedError::GraphRejected)?;
    root_scope(&old)?;
    records::verify_received_record_graph(&retained, &migration, &old)
        .map_err(|_| ColdSeedError::GraphRejected)?;
    // The retained migration graph may predate several historical restores.
    // Lift ONLY its data replay epoch to the authenticated current archive
    // epoch, so a fresh real cohort can perform its ordinary next-epoch CAS.
    // Do not relax the historical projection's archived_epoch < next_epoch
    // guard, synthesize an enrollment, or replay one retirement per old epoch.
    facts
        .replay_epoch()
        .checked_add(1)
        .ok_or(ColdSeedError::GraphRejected)?;
    let retained_digest = retained
        .identity()
        .map_err(|_| ColdSeedError::GraphRejected)?
        .digest();
    let mut bootstrap = retained.clone();
    bootstrap.replay_epoch = facts.replay_epoch();
    bootstrap
        .validate()
        .map_err(|_| ColdSeedError::GraphRejected)?;
    old.replay_epoch = bootstrap.replay_epoch;
    root_scope(&old)?;
    records::verify_received_record_graph(&bootstrap, &migration, &old)
        .map_err(|_| ColdSeedError::GraphRejected)?;
    let bootstrap_bytes = bootstrap
        .encode()
        .map_err(|_| ColdSeedError::GraphRejected)?;
    let objects = migration.objects.into_inner();
    let object_count = objects.len();
    let bootstrap_digest = bootstrap
        .identity()
        .map_err(|_| ColdSeedError::GraphRejected)?
        .digest();
    gate()?;
    let seed_path = work.create_child("seed")?;
    let seed_handle =
        open_absolute_directory_no_symlinks(&seed_path).map_err(|_| ColdSeedError::UnsafeOwner)?;
    let seed_gate = || -> Result<(), ColdSeedError> {
        gate()?;
        check_child_identity(&seed_path, &seed_handle)?;
        live(deadline)
    };
    seed_gate()?;
    let mut target = DurableService::create_new_at_replay_epoch(
        &seed_path,
        AeadBarrier::new(*key).map_err(|_| ColdSeedError::SealRejected)?,
        MAX_OPERATIONS,
        bootstrap.replay_epoch,
    )
    .map_err(|_| ColdSeedError::Storage)?;
    let nonce = hex(&crypto::random::<16>().map_err(|_| ColdSeedError::Storage)?);
    let mutations = objects
        .into_iter()
        .map(|(name, bytes)| Secret::new(bytes.to_vec()).map(|secret| (name, Some(secret))))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ColdSeedError::GraphRejected)?;
    for (index, batch) in mutations
        .chunks(heptabao_durable_service::MAX_ATOMIC_MUTATIONS)
        .enumerate()
    {
        seed_gate()?;
        target
            .apply_batch_conditionally_before_publish(
                BatchPublication {
                    replay_epoch: bootstrap.replay_epoch,
                    principal: "heptabao-offline-cold-seed".into(),
                    namespace: "system".into(),
                    request_id: format!("cold-seed-{nonce}-objects-{index}"),
                    authorization_digest: facts.root_digest(),
                    mutations: batch.to_vec(),
                },
                vec![PublicationCondition {
                    resource: "state".into(),
                    expected: None,
                }],
                &mut || seed_gate().map_err(|_| ServiceError::BarrierFailure),
            )
            .map_err(|_| ColdSeedError::Storage)?;
    }
    seed_gate()?;
    target
        .apply_batch_conditionally_before_publish(
            BatchPublication {
                replay_epoch: bootstrap.replay_epoch,
                principal: "heptabao-offline-cold-seed".into(),
                namespace: "system".into(),
                request_id: format!("cold-seed-{nonce}-root"),
                authorization_digest: facts.root_digest(),
                mutations: vec![(
                    "state".into(),
                    Some(
                        Secret::new(bootstrap_bytes.to_vec())
                            .map_err(|_| ColdSeedError::GraphRejected)?,
                    ),
                )],
            },
            vec![PublicationCondition {
                resource: "state".into(),
                expected: None,
            }],
            &mut || seed_gate().map_err(|_| ServiceError::BarrierFailure),
        )
        .map_err(|_| ColdSeedError::Storage)?;
    seed_gate()?;
    records::verify_received_record_graph(
        &bootstrap,
        &CheckedBootstrapObjects {
            durable: &target,
            gate: &seed_gate,
        },
        &old,
    )
    .map_err(|_| ColdSeedError::GraphRejected)?;
    if target
        .get("system", "state")
        .map_err(|_| ColdSeedError::Storage)?
        .as_ref()
        .map(Secret::expose)
        != Some(bootstrap_bytes.as_slice())
        || target.replay_epoch() != bootstrap.replay_epoch
    {
        return Err(ColdSeedError::GraphRejected);
    }
    target.compact().map_err(|_| ColdSeedError::Storage)?;
    seed_gate()?;
    write_seal(&seed_handle, &seal_bytes)?;
    // Pin the completed four files while the actual backend writer is still
    // held, then require exact same inodes/bytes after taking the transfer fence.
    let mut final_files = Vec::new();
    let mut final_commitments = Vec::new();
    for leaf in LEAVES {
        let mut input = PinnedInput::open(&seed_path.join(leaf), leaf_bound(leaf), deadline)?;
        let commitment = input.digest()?;
        input.check()?;
        final_commitments.push((leaf.to_owned(), input.witness.clone(), commitment));
        final_files.push(input);
    }
    seed_gate()?;
    target.close().map_err(|_| ColdSeedError::Storage)?;
    let mut captured = CapturedSeed::capture(&seed_path)?;
    for ((leaf, witness, digest), artifact) in final_commitments.iter().zip(&captured.artifacts) {
        if artifact.commitment.leaf != *leaf
            || artifact.witness != *witness
            || artifact.commitment.sha256 != *digest
        {
            return Err(ColdSeedError::InputChanged);
        }
    }
    captured.recheck()?;
    seed_gate()?;
    let seed = captured.manifest.clone();
    let seed_manifest_sha256 = manifest_hash(&seed)?;
    let staged = StagedSeed {
        fence: captured.fence,
        path: seed_path,
        leaf: "seed".into(),
        artifacts: Vec::from(captured.artifacts),
    };
    staged.verify(&staged.path)?;
    gate()?;
    use rustix::fs::{RenameFlags, renameat_with};
    match renameat_with(
        &work.fence.handle,
        "seed",
        &parent.handle,
        target_leaf,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => return Err(ColdSeedError::DestinationExists),
        Err(_) => return Err(ColdSeedError::OutcomeUnknown),
    }
    // Every post-publication refusal is explicitly uncertain, never a retry.
    work.fence
        .guard
        .sync_all()
        .map_err(|_| ColdSeedError::OutcomeUnknown)?;
    parent
        .guard
        .sync_all()
        .map_err(|_| ColdSeedError::OutcomeUnknown)?;
    staged
        .verify(destination)
        .map_err(|_| ColdSeedError::OutcomeUnknown)?;
    gate().map_err(|_| ColdSeedError::OutcomeUnknown)?;
    drop(final_files);
    decoder.close().map_err(|_| ColdSeedError::OutcomeUnknown)?;
    Ok(ColdSeedReceipt {
        schema: 1,
        operation: "recover-ha-migration-seed",
        archive_sha256: expected_archive_sha256.to_owned(),
        seal_metadata_sha256: expected_seal_sha256.to_owned(),
        native_root_sha256: hex(&facts.root_digest()),
        native_replay_epoch: facts.replay_epoch(),
        native_local_generation: generation,
        native_local_object_count: report.local.object_count,
        retained_source_root_sha256: hex(&retained_digest),
        retained_source_replay_epoch: retained.replay_epoch,
        bootstrap_root_sha256: hex(&bootstrap_digest),
        bootstrap_replay_epoch: bootstrap.replay_epoch,
        bootstrap_object_count: object_count,
        seed,
        seed_manifest_sha256,
        complete_archive_and_graph_authenticated: true,
        every_file_synced_and_read_back: true,
        atomic_directory_publication_synced: true,
        source_inputs_unchanged: true,
        current_native_data_installed: false,
        ha_qualified: false,
    })
}

struct CheckedBootstrapObjects<'a> {
    durable: &'a DurableService<AeadBarrier>,
    gate: &'a dyn Fn() -> Result<(), ColdSeedError>,
}
impl RecordReader for CheckedBootstrapObjects<'_> {
    fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        (self.gate)().map_err(|_| RecordError::Invalid)?;
        let value = records::DurableReader(self.durable).read_object(reference)?;
        (self.gate)().map_err(|_| RecordError::Invalid)?;
        Ok(value)
    }
}

fn check_child_identity(path: &Path, held: &File) -> Result<(), ColdSeedError> {
    let held = held.metadata().map_err(|_| ColdSeedError::UnsafeOwner)?;
    let current = open_absolute_directory_no_symlinks(path)
        .map_err(|_| ColdSeedError::UnsafeOwner)?
        .metadata()
        .map_err(|_| ColdSeedError::UnsafeOwner)?;
    if !private_directory(&held)
        || !private_directory(&current)
        || held.dev() != current.dev()
        || held.ino() != current.ino()
    {
        return Err(ColdSeedError::UnsafeOwner);
    }
    Ok(())
}

fn write_seal(parent: &File, bytes: &[u8]) -> Result<(), ColdSeedError> {
    use rustix::fs::{Mode, OFlags, openat};
    let mut file = File::from(
        openat(
            parent,
            "seal.json",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| ColdSeedError::Storage)?,
    );
    file.write_all(bytes).map_err(|_| ColdSeedError::Storage)?;
    file.sync_all().map_err(|_| ColdSeedError::Storage)?;
    parent.sync_all().map_err(|_| ColdSeedError::Storage)
}
