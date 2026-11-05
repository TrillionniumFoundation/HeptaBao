//! Offline transport of one stopped, four-file Shamir seed.
//!
//! This is a physical copy boundary, not initialization, restore, unseal or HA
//! admission. The caller must first stop its owned ordinary-file server and
//! retain the actual init/unseal/ack and cluster-identity evidence. This module
//! takes the same exclusive directory fence as that server and refuses every
//! non-core leaf. The export/stage operations never accept a Shamir share or
//! barrier key. The separate native-HA cold recovery operation authenticates a
//! complete archive with explicitly supplied private old-seal/share files.
use super::{SEAL_METADATA_LIMIT, SealMetadata, crypto, hex};
use heptabao_durable_service::MAX_BACKEND_ARTIFACT_BYTES;
use heptabao_filesystem_guard::{
    DirectoryGuardError, DirectoryIdentity, ExclusiveDirectory, FileAccess,
    open_absolute_directory_no_symlinks,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const SCHEMA: u32 = 1;
const LEAVES: [&str; 4] = ["state.hbs", "journal.hbj", "ledger.hbl", "seal.json"];
const MAX_RECEIPT_BYTES: u64 = 16 * 1024;
const BUFFER_BYTES: usize = 64 * 1024;

#[cfg(feature = "native-v6-ha")]
#[path = "service_native_cold_seed.rs"]
mod cold;
#[cfg(feature = "native-v6-ha")]
pub use cold::{ColdSeedError, ColdSeedReceipt, recover_ha_seed};

#[cfg(feature = "native-v6-storage")]
#[path = "service_native_seed_import.rs"]
mod offline_import;
#[cfg(feature = "native-v6-storage")]
pub use offline_import::{
    DEFAULT_OFFLINE_IMPORT_SECONDS, MAX_OFFLINE_IMPORT_SECONDS, OfflineImportError,
    OfflineImportReceipt, OfflineKv2Import, import_kv2,
};

#[cfg(feature = "native-v6-ha")]
pub use offline_import::{HaImportError, HaImportReceipt, HaKv2Import, import_kv2_ha};

/// Errors contain no path, ciphertext, credential or operating-system message.
/// A failed copy can leave its private staging directory for reconciliation.
/// OutcomeUnknown must never cause an automatic retry of the publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeedError {
    InvalidInput,
    UnsupportedPlatform,
    UnsafeOwner,
    WriterActive,
    SourceRejected,
    SourceChanged,
    ReceiptRejected,
    DestinationExists,
    Io,
    OutcomeUnknown,
}

impl std::fmt::Display for SeedError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid offline seed input",
            Self::UnsupportedPlatform => "atomic offline seed publication is unsupported",
            Self::UnsafeOwner => "offline seed requires unchanged private descriptor custody",
            Self::WriterActive => "the original directory writer fence is already held",
            Self::SourceRejected => "offline seed is not exactly the four admitted Shamir files",
            Self::SourceChanged => "offline seed bytes or ownership changed",
            Self::ReceiptRejected => "offline seed does not match the pinned export receipt",
            Self::DestinationExists => "offline seed destination already exists",
            Self::Io => "offline seed I/O failed; retain any staging directory",
            Self::OutcomeUnknown => {
                "offline seed publication outcome is unknown; reconcile without retry"
            }
        })
    }
}

impl std::error::Error for SeedError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Export,
    Stage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    leaf: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SealShape {
    generation: u64,
    shares: u8,
    threshold: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SeedManifest {
    profile: String,
    artifacts: [Artifact; 4],
    shamir: SealShape,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DirectoryEvidence {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
}

/// Only physical, non-secret evidence. Successful serialization does not prove
/// that the encrypted state can be opened or admitted by a particular cohort.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeedReceipt {
    schema: u32,
    operation: Operation,
    source_directory: DirectoryEvidence,
    destination_directory: DirectoryEvidence,
    seed: SeedManifest,
    seed_manifest_sha256: String,
    original_writer_fence_held: bool,
    every_file_synced_and_read_back: bool,
    directory_publication_synced: bool,
    cryptographic_state_admission_performed: bool,
    ha_qualified: bool,
}

impl SeedReceipt {
    fn validate_export(&self) -> Result<(), SeedError> {
        if self.schema != SCHEMA
            || self.operation != Operation::Export
            || !self.original_writer_fence_held
            || !self.every_file_synced_and_read_back
            || !self.directory_publication_synced
            || self.cryptographic_state_admission_performed
            || self.ha_qualified
            || self.seed.profile != "four-file-shamir-cipher-seed"
            || self.seed_manifest_sha256 != manifest_hash(&self.seed)?
        {
            return Err(SeedError::ReceiptRejected);
        }
        for (artifact, leaf) in self.seed.artifacts.iter().zip(LEAVES) {
            if artifact.leaf != leaf
                || artifact.bytes > leaf_bound(leaf)
                || (leaf != "journal.hbj" && artifact.bytes == 0)
                || !valid_hash(&artifact.sha256)
            {
                return Err(SeedError::ReceiptRejected);
            }
        }
        if self.seed.shamir.generation == 0
            || self.seed.shamir.shares == 0
            || self.seed.shamir.shares > super::MAX_SEAL_SHARES
            || self.seed.shamir.threshold == 0
            || self.seed.shamir.threshold > self.seed.shamir.shares
        {
            return Err(SeedError::ReceiptRejected);
        }
        Ok(())
    }
}

/// Export a stopped ordinary-file seed to a new private directory.
/// The caller retains the returned JSON and pins its exact SHA-256 for staging.
pub fn export(source: &Path, destination: &Path) -> Result<SeedReceipt, SeedError> {
    copy_seed(source, destination, None)
}

/// Stage the exact encrypted seed committed by a separately pinned export
/// receipt. The receipt path must itself be a bounded private regular file.
/// The transferred source directory must still contain only the four leaves.
pub fn stage(
    source: &Path,
    destination: &Path,
    export_receipt: &Path,
    expected_receipt_sha256: &str,
) -> Result<SeedReceipt, SeedError> {
    if !valid_hash(expected_receipt_sha256) {
        return Err(SeedError::ReceiptRejected);
    }
    let bytes = read_receipt(export_receipt)?;
    if hex(&crypto::digest(&bytes)) != expected_receipt_sha256 {
        return Err(SeedError::ReceiptRejected);
    }
    let receipt: SeedReceipt =
        serde_json::from_slice(&bytes).map_err(|_| SeedError::ReceiptRejected)?;
    receipt.validate_export()?;
    copy_seed(source, destination, Some(&receipt.seed))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn leaf_bound(leaf: &str) -> u64 {
    if leaf == "seal.json" {
        SEAL_METADATA_LIMIT
    } else {
        MAX_BACKEND_ARTIFACT_BYTES as u64
    }
}

fn manifest_hash(manifest: &SeedManifest) -> Result<String, SeedError> {
    let encoded = serde_json::to_vec(manifest).map_err(|_| SeedError::ReceiptRejected)?;
    Ok(hex(&crypto::digest(&encoded)))
}

fn guard_error(error: DirectoryGuardError) -> SeedError {
    if matches!(error, DirectoryGuardError::WriterBusy) {
        SeedError::WriterActive
    } else {
        SeedError::UnsafeOwner
    }
}

fn identity_matches(metadata: &Metadata, identity: DirectoryIdentity) -> bool {
    metadata.dev() == identity.device() && metadata.ino() == identity.inode()
}

fn private_directory(metadata: &Metadata) -> bool {
    metadata.is_dir()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.mode() & 0o7777 == 0o700
}

struct DirectoryFence {
    guard: ExclusiveDirectory,
    handle: File,
    evidence: DirectoryEvidence,
}

impl DirectoryFence {
    fn acquire(path: &Path) -> Result<Self, SeedError> {
        let guard = ExclusiveDirectory::open(path).map_err(guard_error)?;
        let handle = open_absolute_directory_no_symlinks(path).map_err(guard_error)?;
        let metadata = handle.metadata().map_err(|_| SeedError::UnsafeOwner)?;
        if !private_directory(&metadata) || !identity_matches(&metadata, guard.identity()) {
            return Err(SeedError::UnsafeOwner);
        }
        let fence = Self {
            evidence: DirectoryEvidence {
                device: metadata.dev(),
                inode: metadata.ino(),
                owner: metadata.uid(),
                mode: metadata.mode() & 0o7777,
            },
            guard,
            handle,
        };
        fence.verify_at(path)?;
        Ok(fence)
    }

    fn verify_at(&self, path: &Path) -> Result<(), SeedError> {
        self.guard.verify().map_err(guard_error)?;
        let held = self.handle.metadata().map_err(|_| SeedError::UnsafeOwner)?;
        let current = open_absolute_directory_no_symlinks(path)
            .map_err(guard_error)?
            .metadata()
            .map_err(|_| SeedError::UnsafeOwner)?;
        for metadata in [&held, &current] {
            if !private_directory(metadata)
                || !identity_matches(metadata, self.guard.identity())
                || metadata.uid() != self.evidence.owner
                || metadata.mode() & 0o7777 != self.evidence.mode
            {
                return Err(SeedError::UnsafeOwner);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileWitness {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
    links: u64,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileWitness {
    fn capture(file: &File, bound: u64) -> Result<Self, SeedError> {
        let metadata = file.metadata().map_err(|_| SeedError::SourceChanged)?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() > bound
        {
            return Err(SeedError::SourceRejected);
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            group: metadata.gid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            bytes: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    fn check(&self, file: &File, bound: u64) -> Result<(), SeedError> {
        if &Self::capture(file, bound)? != self {
            return Err(SeedError::SourceChanged);
        }
        Ok(())
    }
}

struct PinnedArtifact {
    file: File,
    witness: FileWitness,
    commitment: Artifact,
}

impl PinnedArtifact {
    fn open(directory: &ExclusiveDirectory, leaf: &str) -> Result<Self, SeedError> {
        let mut file = directory
            .open_file(leaf, FileAccess::Read)
            .map_err(|_| SeedError::SourceRejected)?;
        let witness = FileWitness::capture(&file, leaf_bound(leaf))?;
        if leaf != "journal.hbj" && witness.bytes == 0 {
            return Err(SeedError::SourceRejected);
        }
        let sha256 = stream_exact(&mut file, witness.bytes, None)?;
        let pinned = Self {
            commitment: Artifact {
                leaf: leaf.into(),
                bytes: witness.bytes,
                sha256,
            },
            file,
            witness,
        };
        pinned.check_name(directory)?;
        Ok(pinned)
    }

    fn check_name(&self, directory: &ExclusiveDirectory) -> Result<(), SeedError> {
        self.witness
            .check(&self.file, leaf_bound(&self.commitment.leaf))?;
        let current = directory
            .open_file(&self.commitment.leaf, FileAccess::Read)
            .map_err(|_| SeedError::SourceChanged)?;
        self.witness
            .check(&current, leaf_bound(&self.commitment.leaf))
    }

    fn observe(
        &mut self,
        directory: &ExclusiveDirectory,
        output: Option<&mut File>,
    ) -> Result<(), SeedError> {
        self.check_name(directory)?;
        let observed = stream_exact(&mut self.file, self.witness.bytes, output)?;
        self.check_name(directory)?;
        if observed != self.commitment.sha256 {
            return Err(SeedError::SourceChanged);
        }
        Ok(())
    }
}

fn stream_exact(
    input: &mut File,
    expected_bytes: u64,
    mut output: Option<&mut File>,
) -> Result<String, SeedError> {
    input.seek(SeekFrom::Start(0)).map_err(|_| SeedError::Io)?;
    let mut buffer = Zeroizing::new([0_u8; BUFFER_BYTES]);
    let mut hash = Sha256::new();
    let mut remaining = expected_bytes;
    while remaining > 0 {
        let amount = usize::try_from(remaining.min(BUFFER_BYTES as u64))
            .map_err(|_| SeedError::SourceRejected)?;
        input
            .read_exact(&mut buffer[..amount])
            .map_err(|_| SeedError::SourceChanged)?;
        hash.update(&buffer[..amount]);
        if let Some(destination) = output.as_mut() {
            destination
                .write_all(&buffer[..amount])
                .map_err(|_| SeedError::Io)?;
        }
        remaining -= amount as u64;
    }
    if input.read(&mut buffer[..1]).map_err(|_| SeedError::Io)? != 0 {
        return Err(SeedError::SourceChanged);
    }
    Ok(hex(hash.finalize().as_ref()))
}

#[derive(Eq, PartialEq)]
struct DirectoryStamp {
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl DirectoryStamp {
    fn read(file: &File) -> Result<Self, SeedError> {
        let metadata = file.metadata().map_err(|_| SeedError::UnsafeOwner)?;
        Ok(Self {
            links: metadata.nlink(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

struct CapturedSeed {
    fence: DirectoryFence,
    stamp: DirectoryStamp,
    artifacts: [PinnedArtifact; 4],
    manifest: SeedManifest,
}

impl CapturedSeed {
    fn capture(source: &Path) -> Result<Self, SeedError> {
        let fence = DirectoryFence::acquire(source)?;
        exact_leaves(&fence.guard)?;
        let stamp = DirectoryStamp::read(&fence.handle)?;
        let mut artifacts = Vec::with_capacity(LEAVES.len());
        for leaf in LEAVES {
            artifacts.push(PinnedArtifact::open(&fence.guard, leaf)?);
        }
        let mut artifacts: [PinnedArtifact; 4] = artifacts
            .try_into()
            .map_err(|_| SeedError::SourceRejected)?;
        let seal_artifact = artifacts.last_mut().ok_or(SeedError::SourceRejected)?;
        seal_artifact
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|_| SeedError::Io)?;
        let mut encoded = Zeroizing::new(Vec::new());
        (&mut seal_artifact.file)
            .take(SEAL_METADATA_LIMIT + 1)
            .read_to_end(&mut encoded)
            .map_err(|_| SeedError::Io)?;
        if encoded.len() as u64 != seal_artifact.witness.bytes
            || hex(&crypto::digest(&encoded)) != seal_artifact.commitment.sha256
        {
            return Err(SeedError::SourceChanged);
        }
        let seal: SealMetadata =
            serde_json::from_slice(&encoded).map_err(|_| SeedError::SourceRejected)?;
        if seal.is_wrapper() || seal.share_format != "shamir-v1" {
            return Err(SeedError::SourceRejected);
        }
        seal.validate().map_err(|_| SeedError::SourceRejected)?;
        let manifest = SeedManifest {
            profile: "four-file-shamir-cipher-seed".into(),
            artifacts: artifacts
                .each_ref()
                .map(|artifact| artifact.commitment.clone()),
            shamir: SealShape {
                generation: seal.generation,
                shares: seal.secret_shares,
                threshold: seal.secret_threshold,
            },
        };
        let mut captured = Self {
            fence,
            stamp,
            artifacts,
            manifest,
        };
        captured.recheck()?;
        Ok(captured)
    }

    fn recheck(&mut self) -> Result<(), SeedError> {
        self.fence.verify_at(self.fence.guard.original_path())?;
        exact_leaves(&self.fence.guard)?;
        if DirectoryStamp::read(&self.fence.handle)? != self.stamp {
            return Err(SeedError::SourceChanged);
        }
        for artifact in &mut self.artifacts {
            artifact.observe(&self.fence.guard, None)?;
        }
        self.fence.verify_at(self.fence.guard.original_path())?;
        if DirectoryStamp::read(&self.fence.handle)? != self.stamp {
            return Err(SeedError::SourceChanged);
        }
        Ok(())
    }
}

fn exact_leaves(directory: &ExclusiveDirectory) -> Result<(), SeedError> {
    let mut seen = [false; 4];
    for entry in directory.entries().map_err(|_| SeedError::SourceRejected)? {
        let entry = entry.map_err(|_| SeedError::SourceRejected)?;
        let name = entry.to_str().ok_or(SeedError::SourceRejected)?;
        let index = LEAVES
            .iter()
            .position(|leaf| *leaf == name)
            .ok_or(SeedError::SourceRejected)?;
        if seen[index] {
            return Err(SeedError::SourceRejected);
        }
        seen[index] = true;
    }
    if seen.contains(&false) {
        return Err(SeedError::SourceRejected);
    }
    Ok(())
}

fn target_parts(destination: &Path) -> Result<(&Path, &str), SeedError> {
    if !destination.is_absolute() {
        return Err(SeedError::InvalidInput);
    }
    let parent = destination.parent().ok_or(SeedError::InvalidInput)?;
    let leaf = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(SeedError::InvalidInput)?;
    if leaf.is_empty()
        || leaf.len() > heptabao_filesystem_guard::MAX_GUARDED_LEAF_BYTES
        || matches!(leaf, "." | "..")
        || !leaf
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(SeedError::InvalidInput);
    }
    Ok((parent, leaf))
}

struct StagedSeed {
    fence: DirectoryFence,
    path: PathBuf,
    leaf: String,
    artifacts: Vec<PinnedArtifact>,
}

impl StagedSeed {
    fn create(parent: &DirectoryFence) -> Result<Self, SeedError> {
        parent.verify_at(parent.guard.original_path())?;
        let random = crypto::random::<16>().map_err(|_| SeedError::Io)?;
        let leaf = format!(".heptabao-seed-stage-{}", hex(&random));
        rustix::fs::mkdirat(
            &parent.handle,
            leaf.as_str(),
            rustix::fs::Mode::from_bits_truncate(0o700),
        )
        .map_err(|_| SeedError::Io)?;
        let path = parent.guard.original_path().join(&leaf);
        let fence = DirectoryFence::acquire(&path)?;
        parent.verify_at(parent.guard.original_path())?;
        Ok(Self {
            fence,
            path,
            leaf,
            artifacts: Vec::with_capacity(4),
        })
    }

    fn write(&mut self, source: &mut CapturedSeed) -> Result<(), SeedError> {
        for artifact in &mut source.artifacts {
            self.fence.verify_at(&self.path)?;
            let mut output = self
                .fence
                .guard
                .open_file(&artifact.commitment.leaf, FileAccess::CreateNewReadWrite)
                .map_err(|_| SeedError::Io)?;
            artifact.observe(&source.fence.guard, Some(&mut output))?;
            output.sync_all().map_err(|_| SeedError::Io)?;
            let witness = FileWitness::capture(&output, leaf_bound(&artifact.commitment.leaf))?;
            if witness.bytes != artifact.commitment.bytes {
                return Err(SeedError::SourceChanged);
            }
            // Read through a separately opened descriptor after the actual
            // writer FD's sync, retaining both descriptors and exact metadata.
            let mut readback = PinnedArtifact::open(&self.fence.guard, &artifact.commitment.leaf)?;
            if readback.witness != witness || readback.commitment != artifact.commitment {
                return Err(SeedError::SourceChanged);
            }
            readback.observe(&self.fence.guard, None)?;
            self.artifacts.push(PinnedArtifact {
                file: output,
                witness,
                commitment: artifact.commitment.clone(),
            });
        }
        self.verify(&self.path)?;
        self.fence.guard.sync_all().map_err(|_| SeedError::Io)?;
        self.verify(&self.path)
    }

    fn verify(&self, path: &Path) -> Result<(), SeedError> {
        self.fence.verify_at(path)?;
        exact_leaves(&self.fence.guard)?;
        if self.artifacts.len() != LEAVES.len() {
            return Err(SeedError::SourceRejected);
        }
        for written in &self.artifacts {
            written.check_name(&self.fence.guard)?;
            let mut readback = PinnedArtifact::open(&self.fence.guard, &written.commitment.leaf)?;
            if readback.witness != written.witness || readback.commitment != written.commitment {
                return Err(SeedError::SourceChanged);
            }
            readback.observe(&self.fence.guard, None)?;
        }
        self.fence.verify_at(path)
    }
}

fn copy_seed(
    source: &Path,
    destination: &Path,
    expected: Option<&SeedManifest>,
) -> Result<SeedReceipt, SeedError> {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return Err(SeedError::UnsupportedPlatform);
    }
    let (parent_path, target_leaf) = target_parts(destination)?;
    let mut captured = CapturedSeed::capture(source)?;
    if expected.is_some_and(|expected| expected != &captured.manifest) {
        return Err(SeedError::ReceiptRejected);
    }
    let parent = DirectoryFence::acquire(parent_path)?;
    if parent
        .guard
        .entry_exists(target_leaf)
        .map_err(|_| SeedError::UnsafeOwner)?
    {
        return Err(SeedError::DestinationExists);
    }
    let mut staged = StagedSeed::create(&parent)?;
    staged.write(&mut captured)?;
    captured.recheck()?;
    parent.verify_at(parent_path)?;
    staged.verify(&staged.path)?;
    // Never substitute a preflight exists check plus overwriting rename here.
    // The final syscall must refuse even a concurrently appearing empty target.
    publish_noreplace(&parent.handle, &staged.leaf, target_leaf)?;
    // Publication has happened. Every later failure is an unknown outcome and
    // must retain the target and source for explicit reconciliation.
    parent
        .guard
        .sync_all()
        .map_err(|_| SeedError::OutcomeUnknown)?;
    parent
        .verify_at(parent_path)
        .map_err(|_| SeedError::OutcomeUnknown)?;
    staged
        .verify(destination)
        .map_err(|_| SeedError::OutcomeUnknown)?;
    captured.recheck().map_err(|_| SeedError::OutcomeUnknown)?;
    let seed_manifest_sha256 =
        manifest_hash(&captured.manifest).map_err(|_| SeedError::OutcomeUnknown)?;
    Ok(SeedReceipt {
        schema: SCHEMA,
        operation: if expected.is_some() {
            Operation::Stage
        } else {
            Operation::Export
        },
        source_directory: captured.fence.evidence.clone(),
        destination_directory: staged.fence.evidence.clone(),
        seed: captured.manifest,
        seed_manifest_sha256,
        original_writer_fence_held: true,
        every_file_synced_and_read_back: true,
        directory_publication_synced: true,
        cryptographic_state_admission_performed: false,
        ha_qualified: false,
    })
}

fn publish_noreplace(parent: &File, staging: &str, target: &str) -> Result<(), SeedError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // Locked rustix 1.1.4 maps this to Linux RENAME_NOREPLACE and Apple
        // RENAME_EXCL. Both refuse a target created after the preflight.
        let flags = rustix::fs::RenameFlags::NOREPLACE;
        match rustix::fs::renameat_with(parent, staging, parent, target, flags) {
            Ok(()) => Ok(()),
            Err(rustix::io::Errno::EXIST) => Err(SeedError::DestinationExists),
            Err(_) => Err(SeedError::OutcomeUnknown),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (parent, staging, target);
        Err(SeedError::UnsupportedPlatform)
    }
}

fn read_receipt(path: &Path) -> Result<Zeroizing<Vec<u8>>, SeedError> {
    use rustix::fs::{Mode, OFlags, openat};
    let (parent_path, leaf) = target_parts(path)?;
    let parent = open_absolute_directory_no_symlinks(parent_path).map_err(guard_error)?;
    let before = parent.metadata().map_err(|_| SeedError::ReceiptRejected)?;
    if !private_directory(&before) {
        return Err(SeedError::ReceiptRejected);
    }
    let mut file = File::from(
        openat(
            &parent,
            leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| SeedError::ReceiptRejected)?,
    );
    let witness =
        FileWitness::capture(&file, MAX_RECEIPT_BYTES).map_err(|_| SeedError::ReceiptRejected)?;
    let mut encoded = Zeroizing::new(Vec::new());
    (&mut file)
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|_| SeedError::ReceiptRejected)?;
    if encoded.len() as u64 != witness.bytes {
        return Err(SeedError::ReceiptRejected);
    }
    witness
        .check(&file, MAX_RECEIPT_BYTES)
        .map_err(|_| SeedError::ReceiptRejected)?;
    let current = File::from(
        openat(
            &parent,
            leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| SeedError::ReceiptRejected)?,
    );
    witness
        .check(&current, MAX_RECEIPT_BYTES)
        .map_err(|_| SeedError::ReceiptRejected)?;
    let current_parent = open_absolute_directory_no_symlinks(parent_path)
        .map_err(guard_error)?
        .metadata()
        .map_err(|_| SeedError::ReceiptRejected)?;
    if !private_directory(&current_parent)
        || current_parent.dev() != before.dev()
        || current_parent.ino() != before.ino()
    {
        return Err(SeedError::ReceiptRejected);
    }
    Ok(encoded)
}

#[cfg(test)]
#[path = "service_native_seed_tests.rs"]
mod tests;
