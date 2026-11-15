//! Isolated, synthetic, disk-backed V6 design trial: never a production writer.
//! Proves durable immutable objects, authenticated trial-root publication,
//! crash-before-root invisibility, pins, and corruption rejection.
use super::*;
use crate::kv2_v6_shard_validator::{
    SHARD_INDEX_SCHEMA, sharded_version_scope, validate_sharded_trial_index,
};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(not(unix))]
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const TRIAL_FORMAT: &str = "heptabao-kv2-v6-disk-staging-experiment";
const ROOT_DOMAIN: &[u8] = b"heptabao/kv2-v6/trial-commit-root";
const ADDRESS_DOMAIN: &[u8] = b"heptabao/kv2-v6/trial-address-key";
static NEXT_TRIAL: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrialPayload {
    format: String,
    cluster: String,
    epoch: u64,
    generation: u64,
    root: crate::state_records::Kv1Root,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrialRootEnvelope {
    payload: TrialPayload,
    mac: [u8; 32],
}

struct TrialDisk {
    dir: PathBuf,
    #[cfg(unix)]
    root_identity: (u64, u64),
    #[cfg(unix)]
    objects_identity: (u64, u64),
}
impl TrialDisk {
    fn fresh() -> Result<Self, Box<dyn std::error::Error>> {
        let id = NEXT_TRIAL.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "heptabao-kv2-v6-private-staging-{}-{id}",
            std::process::id()
        ));
        // No initial 0755 window before chmod: make both private directories
        // restrictive in the creation syscall, even in a shared tmp parent.
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir)?;
        builder.create(dir.join("objects"))?;
        #[cfg(unix)]
        let root_identity = {
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::symlink_metadata(&dir)?;
            (metadata.dev(), metadata.ino())
        };
        #[cfg(unix)]
        let objects_identity = {
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::symlink_metadata(dir.join("objects"))?;
            (metadata.dev(), metadata.ino())
        };
        Ok(Self {
            dir,
            #[cfg(unix)]
            root_identity,
            #[cfg(unix)]
            objects_identity,
        })
    }
    fn object_path(&self, id: &ObjectId) -> PathBuf {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = String::with_capacity(64);
        for byte in id.bytes() {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 15)]));
        }
        self.dir.join("objects").join(name)
    }
    fn manifest_path(&self) -> PathBuf {
        self.dir.join("root.json")
    }
    // Reused immutable files must be opened directly and without following
    // a symlink. A correct MAC over bytes does not admit an arbitrary source
    // path outside the authenticated private object or manifest directory.
    #[cfg(not(unix))]
    fn open_private_regular(path: &Path) -> Result<File, RecordError> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(path).map_err(|_| RecordError::Corrupt)?;
        if !file.metadata().map_err(|_| RecordError::Corrupt)?.is_file() {
            return Err(RecordError::Corrupt);
        }
        Ok(file)
    }
    // Authenticate the same root inode captured at construction, rather than
    // following a symlinked (or replaced regular-directory) ancestor.
    #[cfg(unix)]
    fn open_root_dir(&self) -> Result<File, RecordError> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let directory = options.open(&self.dir).map_err(|_| RecordError::Corrupt)?;
        let metadata = directory.metadata().map_err(|_| RecordError::Corrupt)?;
        if !metadata.is_dir() || (metadata.dev(), metadata.ino()) != self.root_identity {
            return Err(RecordError::Corrupt);
        }
        Ok(directory)
    }

    #[cfg(unix)]
    fn open_objects_dir(&self) -> Result<File, RecordError> {
        use rustix::fs::{Mode, OFlags, openat};
        let root = self.open_root_dir()?;
        let descriptor = openat(
            &root,
            "objects",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| RecordError::Corrupt)?;
        let directory = File::from(descriptor);
        use std::os::unix::fs::MetadataExt;
        let metadata = directory.metadata().map_err(|_| RecordError::Corrupt)?;
        if !metadata.is_dir() || (metadata.dev(), metadata.ino()) != self.objects_identity {
            return Err(RecordError::Corrupt);
        }
        Ok(directory)
    }

    // Safe descriptor-relative operations are mandatory: this workspace
    // forbids unsafe code and a no-follow pathname check has a race.
    #[cfg(unix)]
    fn open_object_at(
        &self,
        directory: &File,
        id: &ObjectId,
        create_new: bool,
    ) -> Result<File, RecordError> {
        use rustix::fs::{Mode, OFlags, openat};
        let path = self.object_path(id);
        let component = path.file_name().ok_or(RecordError::Corrupt)?;
        let flags = OFlags::NOFOLLOW
            | OFlags::CLOEXEC
            | OFlags::NONBLOCK
            | if create_new {
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL
            } else {
                OFlags::RDONLY
            };
        let descriptor =
            openat(directory, component, flags, Mode::RUSR | Mode::WUSR).map_err(|error| {
                if !create_new && error == rustix::io::Errno::NOENT {
                    RecordError::Missing
                } else {
                    RecordError::Corrupt
                }
            })?;
        let file = File::from(descriptor);
        // A regular hard link can redirect the exact authenticated bytes to
        // an inode that is also writable from outside our private object
        // directory. Refuse such aliases even if the digest still matches.
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata().map_err(|_| RecordError::Corrupt)?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(RecordError::Corrupt);
        }
        Ok(file)
    }

    #[cfg(unix)]
    fn verify_existing_object_at(
        &self,
        directory: &File,
        id: &ObjectId,
        expected: &[u8],
    ) -> Result<(), RecordError> {
        let source = self.open_object_at(directory, id, false)?;
        let length = source.metadata().map_err(|_| RecordError::Corrupt)?.len();
        if length != expected.len() as u64 {
            return Err(RecordError::Corrupt);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        source
            .take(length + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| RecordError::Corrupt)?;
        if bytes.as_slice() != expected {
            return Err(RecordError::Corrupt);
        }
        Ok(())
    }

    /// A power loss during an object write must never leave the final identity
    /// containing a truncated object. fsync the private temporary inode first,
    /// atomically link its verified bytes into the immutable final name, then
    /// fsync the objects directory before publishing any authenticated root.
    /// The injection flag is used only by this isolated durability trial.
    #[cfg(unix)]
    fn install_new_object_at(
        &self,
        directory: &File,
        id: &ObjectId,
        contents: &[u8],
        interrupt_partial_write: bool,
    ) -> Result<(), RecordError> {
        use rustix::fs::{AtFlags, Mode, OFlags, linkat, openat, unlinkat};
        let entropy = crate::crypto::random::<16>().map_err(|_| RecordError::Corrupt)?;
        let mut staged = String::from(".staged-");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in entropy {
            staged.push(char::from(HEX[usize::from(byte >> 4)]));
            staged.push(char::from(HEX[usize::from(byte & 15)]));
        }
        let handle = openat(
            directory,
            staged.as_str(),
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| RecordError::Corrupt)?;
        let mut writer = File::from(handle);
        if interrupt_partial_write {
            // Model a process killed after its first partial disk write.
            // This file deliberately remains an untrusted orphan on disk.
            writer
                .write_all(&contents[..contents.len().div_ceil(2)])
                .map_err(|_| RecordError::Corrupt)?;
            return Err(RecordError::Corrupt);
        }
        writer
            .write_all(contents)
            .and_then(|()| writer.sync_all())
            .map_err(|_| RecordError::Corrupt)?;
        drop(writer);
        let name = self.object_path(id);
        let destination = name.file_name().ok_or(RecordError::Corrupt)?;
        // Hard-link creation is no-replace, including with a concurrent writer.
        // A prior immutable identity is accepted only if byte-for-byte equal.
        let linked = linkat(
            directory,
            staged.as_str(),
            directory,
            destination,
            AtFlags::empty(),
        );
        unlinkat(directory, staged.as_str(), AtFlags::empty()).map_err(|_| RecordError::Corrupt)?;
        match linked {
            Ok(()) => Ok(()),
            Err(rustix::io::Errno::EXIST) => {
                self.verify_existing_object_at(directory, id, contents)
            }
            Err(_) => Err(RecordError::Corrupt),
        }
    }

    #[cfg(unix)]
    fn persist_objects(&self, graph: &Kv1Index) -> Result<(), RecordError> {
        let directory = self.open_objects_dir()?;
        graph.visit_objects(|object| {
            let identity = &object.reference().id;
            match self.verify_existing_object_at(&directory, identity, object.bytes()) {
                Ok(()) => {}
                Err(RecordError::Missing) => {
                    self.install_new_object_at(&directory, identity, object.bytes(), false)?
                }
                Err(failure) => return Err(failure),
            }
            Ok(())
        })?;
        directory.sync_all().map_err(|_| RecordError::Corrupt)
    }

    #[cfg(not(unix))]
    fn persist_objects(&self, graph: &Kv1Index) -> Result<(), RecordError> {
        graph.visit_objects(|object| {
            let path = self.object_path(&object.reference().id);
            if path.exists() {
                let source = Self::open_private_regular(&path)?;
                let length = source.metadata().map_err(|_| RecordError::Corrupt)?.len();
                if length != object.bytes().len() as u64 {
                    return Err(RecordError::Corrupt);
                }
                let mut bytes = Zeroizing::new(Vec::new());
                source
                    .take(length + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| RecordError::Corrupt)?;
                if bytes.as_slice() != object.bytes() {
                    return Err(RecordError::Corrupt);
                }
            } else {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .map_err(|_| RecordError::Corrupt)?;
                file.write_all(object.bytes())
                    .and_then(|()| file.sync_all())
                    .map_err(|_| RecordError::Corrupt)?;
            }
            Ok(())
        })?;
        File::open(self.dir.join("objects"))
            .and_then(|dir| dir.sync_all())
            .map_err(|_| RecordError::Corrupt)
    }
    // Validate the *previous* signed root before accepting any next-generation
    // objects. This remains an isolated single-writer trial, not cross-process
    // fencing or an authorization path for production KV2.
    fn authenticated_root(&self, key: &AddressKey) -> Result<TrialRootEnvelope, RecordError> {
        #[cfg(unix)]
        let source = {
            use rustix::fs::{Mode, OFlags, openat};
            let root = self.open_root_dir()?;
            let descriptor = openat(
                &root,
                "root.json",
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| RecordError::Corrupt)?;
            let file = File::from(descriptor);
            // O_NOFOLLOW rejects symlinks but not a regular inode exported by
            // hard link to another path. Object reads already reject nlink>1;
            // the authenticated root must obey the same custody boundary.
            use std::os::unix::fs::MetadataExt;
            let metadata = file.metadata().map_err(|_| RecordError::Corrupt)?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(RecordError::Corrupt);
            }
            file
        };
        #[cfg(not(unix))]
        let source = Self::open_private_regular(&self.manifest_path())?;
        if source.metadata().map_err(|_| RecordError::Corrupt)?.len()
            > crate::state_record_root::MAX_ROOT_BYTES as u64
        {
            return Err(RecordError::Corrupt);
        }
        let mut raw = Vec::new();
        source
            .take(crate::state_record_root::MAX_ROOT_BYTES as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(|_| RecordError::Corrupt)?;
        let envelope: TrialRootEnvelope =
            serde_json::from_slice(&raw).map_err(|_| RecordError::Corrupt)?;
        if envelope.payload.format != TRIAL_FORMAT
            || envelope.payload.cluster != "synthetic-r310"
            || envelope.payload.epoch != 7
            || envelope.payload.generation == 0
            || serde_json::to_vec(&envelope).map_err(|_| RecordError::Corrupt)? != raw
        {
            return Err(RecordError::Corrupt);
        }
        let bytes = serde_json::to_vec(&envelope.payload).map_err(|_| RecordError::Corrupt)?;
        if key.digest(ROOT_DOMAIN, &bytes)? != envelope.mac {
            return Err(RecordError::Corrupt);
        }
        Ok(envelope)
    }

    fn published_generation(
        &self,
        key: &Arc<AddressKey>,
    ) -> Result<Option<(u64, Kv1Index)>, RecordError> {
        match fs::symlink_metadata(self.manifest_path()) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    return Err(RecordError::Corrupt);
                }
                let previous = self.authenticated_root(key)?;
                // Retain the authenticated predecessor *under the same
                // publication lock*. The next generation number alone does
                // not prove that an independently staged graph preserves
                // acknowledged KV2 cells.
                let prior = Kv1Index::open(Arc::clone(key), previous.payload.root, self)?;
                Ok(Some((previous.payload.generation, prior)))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(RecordError::Corrupt),
        }
    }

    fn publish(
        &self,
        graph: &Kv1Index,
        key: &Arc<AddressKey>,
        generation: u64,
        stop_before_root: bool,
    ) -> Result<(), RecordError> {
        // The single-writer trial must actually fence independent descriptors:
        // generation validation, immutable object staging, and signed-root
        // publication are one exclusive, nonblocking critical section.
        // Kernel locks are released on process death, including hard SIGKILL.
        // This protects a trial directory; it is NOT Raft or production CAS.
        #[cfg(unix)]
        let _publication_guard = {
            use rustix::fs::{FlockOperation, flock};
            let directory = self.open_root_dir()?;
            flock(&directory, FlockOperation::NonBlockingLockExclusive)
                .map_err(|_| RecordError::Invalid)?;
            directory
        };
        // Fail closed *before* persisting any immutable candidate object.
        // A stale, duplicate, skipped or wrapped generation may not overwrite
        // an acknowledged root, even with otherwise valid signed bytes.
        let predecessor = match self.published_generation(key)? {
            None if generation == 1 => None,
            Some((previous, index)) if previous.checked_add(1) == Some(generation) => Some(index),
            _ => return Err(RecordError::Invalid),
        };
        // This deliberately conservative V6 trial has no authenticated
        // physical-retirement capability. KV2 soft delete and destroy must
        // remain represented by retained, versioned cells; the data plane
        // cannot silently disappear just because a caller knows the next
        // root generation. A production retirement protocol is still
        // unimplemented and MUST NOT inherit this test-only permission.
        // Validate before persisting any candidate object (no orphan
        // staging side effect from a refused predecessor).
        if let Some(previous) = predecessor.as_ref() {
            // One authenticated root is not automatically valid KV2 state.
            // Reopen alone verifies the object tree, not complete physical
            // shard custody. Validate BOTH root closures and immutable
            // predecessor continuity while this exact publication lock is held,
            // before staging any candidate object or publishing a signed root.
            // This remains strictly an isolated V6 trial, not production CAS.
            crate::kv2_v6_shard_validator::validate_immutable_transition(previous, graph)?;
        }
        // Reject malformed or self-contradictory typed entries in memory,
        // before durable staging. Even if a caller signs the correct graph
        // address, this negative path may not create ghost object files.
        graph.visit_keys(|record_key| {
            let value = graph.get(record_key).ok_or(RecordError::Corrupt)?;
            decode(record_key, value).map(|_| ())
        })?;
        validate_sharded_trial_index(graph)?;
        self.persist_objects(graph)?;
        // A signed manifest must never point at an unreopenable graph.
        // Reopen *all* persisted pages using the key that will sign the root,
        // then authenticate every typed KV2 cell against its indexed scope.
        // Merely visiting staged objects proves neither property. A failure
        // here leaves only inert, unpublished immutable objects on disk.
        let authenticated = Kv1Index::open(Arc::clone(key), graph.root(), self)
            .map_err(|_| RecordError::Corrupt)?;
        authenticated.visit_keys(|record_key| {
            let cell = authenticated.get(record_key).ok_or(RecordError::Corrupt)?;
            decode(record_key, cell).map_err(|_| RecordError::Corrupt)?;
            Ok(())
        })?;
        // A crashed/aborted writer may leave reachable-looking object bytes:
        // without the authenticated published root they confer no read rights.
        if stop_before_root {
            return Ok(());
        }
        let payload = TrialPayload {
            format: TRIAL_FORMAT.into(),
            cluster: "synthetic-r310".into(),
            epoch: 7,
            generation,
            root: graph.root(),
        };
        let bytes = serde_json::to_vec(&payload).map_err(|_| RecordError::Corrupt)?;
        let envelope = TrialRootEnvelope {
            mac: key.digest(ROOT_DOMAIN, &bytes)?,
            payload,
        };
        let manifest = serde_json::to_vec(&envelope).map_err(|_| RecordError::Corrupt)?;
        // Every attempted publication gets a fresh private staged name. An
        // interrupted manifest write can leave this file behind, but may not
        // wedge the next admitted generation by monopolizing a fixed pathname.
        // This remains a single-writer V6 experiment, not a cross-process CAS.
        let entropy = crate::crypto::random::<16>().map_err(|_| RecordError::Corrupt)?;
        let mut staged_name = String::from("root.json.staged-");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in entropy {
            staged_name.push(char::from(HEX[usize::from(byte >> 4)]));
            staged_name.push(char::from(HEX[usize::from(byte & 15)]));
        }
        #[cfg(unix)]
        let mut writer = {
            use rustix::fs::{Mode, OFlags, openat};
            let descriptor = openat(
                &_publication_guard,
                staged_name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| RecordError::Corrupt)?;
            File::from(descriptor)
        };
        #[cfg(not(unix))]
        let mut writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.dir.join(&staged_name))
            .map_err(|_| RecordError::Corrupt)?;
        writer
            .write_all(&manifest)
            .and_then(|()| writer.sync_all())
            .map_err(|_| RecordError::Corrupt)?;
        drop(writer);
        #[cfg(unix)]
        {
            use rustix::fs::renameat;
            renameat(
                &_publication_guard,
                staged_name.as_str(),
                &_publication_guard,
                "root.json",
            )
            .map_err(|_| RecordError::Corrupt)?;
            _publication_guard
                .sync_all()
                .map_err(|_| RecordError::Corrupt)
        }
        #[cfg(not(unix))]
        {
            fs::rename(self.dir.join(&staged_name), self.manifest_path())
                .map_err(|_| RecordError::Corrupt)?;
            File::open(&self.dir)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| RecordError::Corrupt)
        }
    }
    fn reopen(
        &self,
        key: Arc<AddressKey>,
        expected_generation: u64,
    ) -> Result<Kv1Index, RecordError> {
        let envelope = self.authenticated_root(&key)?;
        if envelope.payload.generation != expected_generation {
            return Err(RecordError::Corrupt);
        }
        let index = Kv1Index::open(key, envelope.payload.root, self)?;
        // Authentication of the root and every object page is necessary but
        // not sufficient: a historical data image may contain valid MACs
        // yet violate the typed KV2 envelope/retained-version grammar.
        // Reopen must validate *all* cells before exposing even one record.
        index.visit_keys(|record_key| {
            let cell = index.get(record_key).ok_or(RecordError::Corrupt)?;
            decode(record_key, cell).map_err(|_| RecordError::Corrupt)?;
            Ok(())
        })?;
        validate_sharded_trial_index(&index)?;
        Ok(index)
    }
}
impl RecordReader for TrialDisk {
    fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        #[cfg(unix)]
        let source = {
            let directory = self.open_objects_dir()?;
            self.open_object_at(&directory, &reference.id, false)?
        };
        #[cfg(not(unix))]
        let source = TrialDisk::open_private_regular(&self.object_path(&reference.id))?;
        let metadata = source.metadata().map_err(|_| RecordError::Corrupt)?;
        if !metadata.is_file() || metadata.len() != u64::from(reference.encoded_bytes) {
            return Err(RecordError::Corrupt);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
        source
            .take(metadata.len() + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| RecordError::Corrupt)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(RecordError::Corrupt);
        }
        Ok(bytes)
    }
}
impl TrialDisk {
    // Cleanup belongs only to the exact original private directory inodes.
    // Never recursively traverse a pathname after validating its identity:
    // it can be exchanged between the check and the removal. Descriptor-
    // relative unlink removes only leaves in the pinned directories; a final
    // rmdir cannot recursively erase a substituted directory's contents.
    #[cfg(unix)]
    fn cleanup_pinned_trial(&self) -> Result<(), RecordError> {
        use rustix::fs::{AtFlags, Dir, unlinkat};
        use std::os::unix::fs::MetadataExt;

        fn unlink_leaves(directory: &File, skip_objects: bool) -> Result<(), RecordError> {
            let mut entries = Dir::read_from(directory).map_err(|_| RecordError::Corrupt)?;
            while let Some(entry) = entries.read() {
                let entry = entry.map_err(|_| RecordError::Corrupt)?;
                let name = entry.file_name();
                if matches!(name.to_bytes(), b"." | b"..")
                    || (skip_objects && name.to_bytes() == b"objects")
                {
                    continue;
                }
                // Neither a leaf symlink nor a regular-file hard link can
                // redirect unlinkat outside this pinned directory. Unexpected
                // nested directories are not traversed (unlinkat rejects).
                unlinkat(directory, name, AtFlags::empty()).map_err(|_| RecordError::Corrupt)?;
            }
            Ok(())
        }
        // Both provenance checks precede the first mutation.
        let root = self.open_root_dir()?;
        let objects = self.open_objects_dir()?;
        unlink_leaves(&objects, false)?;
        unlink_leaves(&root, true)?;
        // An exchanged "objects" entry may not be removed under a
        // different inode, even if its current contents are empty.
        self.open_objects_dir()?;
        unlinkat(&root, "objects", AtFlags::REMOVEDIR).map_err(|_| RecordError::Corrupt)?;
        let current = fs::symlink_metadata(&self.dir).map_err(|_| RecordError::Corrupt)?;
        if !current.is_dir() || (current.dev(), current.ino()) != self.root_identity {
            return Err(RecordError::Corrupt);
        }
        // Unlike remove_dir_all, rmdir cannot delete any substituted data.
        fs::remove_dir(&self.dir).map_err(|_| RecordError::Corrupt)
    }
}
impl Drop for TrialDisk {
    fn drop(&mut self) {
        #[cfg(unix)]
        let _ = self.cleanup_pinned_trial();
        #[cfg(not(unix))]
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn private_trial_key(base: &AddressKey) -> Result<Arc<AddressKey>, RecordError> {
    let bytes = base.digest(ADDRESS_DOMAIN, b"synthetic-r310/epoch-7")?;
    Ok(AddressKey::from_bytes(bytes))
}

fn v1_cell(
    number: u64,
    path: &str,
    text: String,
) -> Result<(Kv1Key, Zeroizing<Vec<u8>>), RecordError> {
    let scope = Scope {
        namespace: "tenant-r310".into(),
        mount: "secret/".into(),
        incarnation: 7,
        path: path.into(),
    };
    let address = key(&scope)?;
    let mut versions = serde_json::Map::new();
    versions.insert(
        number.to_string(),
        json!({"data":{"payload":text},"destroyed":false}),
    );
    let record = encode(
        scope,
        number,
        json!({"current_version":number,"versions":Value::Object(versions)}),
    )?;
    Ok((address, record))
}

#[test]
fn kv2_v6_disk_trial_34m_durable_root_failure_invisibility_and_tamper()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let parent = AddressKey::from_bytes([0x71; 32]);
    let key_material = private_trial_key(&parent)?;
    assert_ne!(
        key_material.expose(),
        parent.expose(),
        "v6 trial key domain separation"
    );
    let mut graph = Kv1Index::empty(Arc::clone(&key_material));
    let mut objects = LocalObjects(BTreeMap::new());

    let (first, initial) = v1_cell(1, "entry-000", "A".repeat(192 * 1024))?;
    stage(&mut graph, &mut objects, first.clone(), Some(&initial))?;
    disk.publish(&graph, &key_material, 1, false)?;
    let older = graph.clone();
    let pinned_old = disk.reopen(Arc::clone(&key_material), 1)?;
    assert_eq!(pinned_old.get(&first), Some(initial.as_slice()));
    let old_root_bytes = fs::read(disk.manifest_path())?;

    let mut payload_bytes = initial.len();
    let mut last = None;
    // Actual record graph has an independent 64 MiB bound; 181 additional
    // records exceed the V5 opaque owner 16 MiB limit without inflating V5.
    for index in 1..182_u64 {
        let name = format!("entry-{index:03}");
        let (item, bytes) = v1_cell(1, &name, format!("{index:03}").repeat(64 * 1024))?;
        payload_bytes += bytes.len();
        stage(&mut graph, &mut objects, item.clone(), Some(&bytes))?;
        if index == 181 {
            last = Some((item, bytes));
        }
    }
    assert!(payload_bytes > 32 * 1024 * 1024);
    assert!(payload_bytes < 48 * 1024 * 1024);
    let (last_key, last_bytes) = last.ok_or("missing last record")?;

    // Persist all immutable objects, then inject an interrupted writer before
    // root publication. The previous authenticated root stays visible.
    disk.publish(&graph, &key_material, 2, true)?;
    let abandoned = disk.reopen(Arc::clone(&key_material), 1)?;
    assert_eq!(abandoned.get(&first), Some(initial.as_slice()));
    assert!(abandoned.get(&last_key).is_none());
    assert_eq!(fs::read(disk.manifest_path())?, old_root_bytes);

    disk.publish(&graph, &key_material, 2, false)?;
    let reopened = disk.reopen(Arc::clone(&key_material), 2)?;
    assert_eq!(reopened.get(&first), Some(initial.as_slice()));
    assert_eq!(reopened.get(&last_key), Some(last_bytes.as_slice()));
    assert_eq!(decode(&last_key, last_bytes.as_slice())?.version, 1);
    assert_eq!(older.get(&first), Some(initial.as_slice()));
    assert!(older.get(&last_key).is_none());
    assert!(disk.reopen(Arc::clone(&key_material), 1).is_err());

    // Swapped, stale and corrupted root bytes must not be adopted.
    assert!(
        disk.reopen(private_trial_key(&AddressKey::from_bytes([0x72; 32]))?, 2)
            .is_err()
    );
    let current = fs::read(disk.manifest_path())?;
    fs::write(disk.manifest_path(), &old_root_bytes)?;
    assert!(disk.reopen(Arc::clone(&key_material), 2).is_err());
    fs::write(disk.manifest_path(), &current)?;
    let root_object = graph.root().reference.ok_or("missing graph root")?;
    let root_path = disk.object_path(&root_object.id);
    let original = fs::read(&root_path)?;
    let mut corrupted = original.clone();
    corrupted[0] ^= 0x80;
    fs::write(&root_path, &corrupted)?;
    assert!(disk.reopen(Arc::clone(&key_material), 2).is_err());
    fs::remove_file(&root_path)?;
    assert!(disk.reopen(key_material, 2).is_err());
    Ok(())
}

// A short write followed by process death must leave only a private orphan,
// never a corrupt file under the final immutable ID that blocks all restarts.
#[cfg(unix)]
#[test]
fn kv2_v6_disk_trial_partial_write_never_poison_final_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let key_material = private_trial_key(&AddressKey::from_bytes([0x91; 32]))?;
    let mut graph = Kv1Index::empty(Arc::clone(&key_material));
    let mut objects = LocalObjects(BTreeMap::new());
    let (name, payload) = v1_cell(1, "partial-write-reopen", "validated".repeat(2048))?;
    stage(&mut graph, &mut objects, name.clone(), Some(&payload))?;

    let root = graph.root().reference.ok_or("missing root")?;
    let mut root_bytes: Option<Zeroizing<Vec<u8>>> = None;
    graph.visit_objects(|object| {
        if object.reference().id == root.id {
            root_bytes = Some(Zeroizing::new(object.bytes().to_vec()));
        }
        Ok(())
    })?;
    let root_bytes = root_bytes.ok_or("missing root payload")?;
    let directory = disk.open_objects_dir()?;
    assert!(matches!(
        disk.install_new_object_at(&directory, &root.id, &root_bytes, true),
        Err(RecordError::Corrupt)
    ));
    assert!(!disk.object_path(&root.id).exists());
    assert!(!disk.manifest_path().exists());
    assert_eq!(
        fs::read_dir(disk.dir.join("objects"))?
            .filter_map(Result::ok)
            .filter(|item| item.file_name().to_string_lossy().starts_with(".staged-"))
            .count(),
        1,
        "injected interrupted write must leave a private partial temp"
    );

    // A retry must publish the full authenticated graph without reusing the
    // interrupted temp, or silently repairing an already-final corrupt file.
    disk.publish(&graph, &key_material, 1, false)?;
    assert_eq!(
        disk.reopen(Arc::clone(&key_material), 1)?.get(&name),
        Some(payload.as_slice())
    );
    let final_bytes = fs::read(disk.object_path(&root.id))?;
    assert_eq!(final_bytes, root_bytes.as_slice());
    let original_root = fs::read(disk.manifest_path())?;

    // A truncated *final* identity is tampering, not a crash retry; never
    // auto-overwrite a previously advertised immutable object.
    fs::write(
        disk.object_path(&root.id),
        &root_bytes[..root_bytes.len() / 2],
    )?;
    assert!(disk.persist_objects(&graph).is_err());
    assert_eq!(fs::read(disk.manifest_path())?, original_root);
    assert!(disk.reopen(key_material, 1).is_err());
    Ok(())
}

// An interrupted manifest write must not make the next authenticated
// generation impossible to publish. The previous complete root remains
// visible until an atomically installed successor is durably synchronized.
#[test]
fn kv2_v6_disk_trial_stale_root_staging_does_not_wedge_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let key_material = private_trial_key(&AddressKey::from_bytes([0x92; 32]))?;
    let mut graph = Kv1Index::empty(Arc::clone(&key_material));
    let mut objects = LocalObjects(BTreeMap::new());
    let (first_key, first_bytes) = v1_cell(1, "manifest-first", "first".repeat(256))?;
    stage(
        &mut graph,
        &mut objects,
        first_key.clone(),
        Some(&first_bytes),
    )?;
    disk.publish(&graph, &key_material, 1, false)?;
    let root_1 = fs::read(disk.manifest_path())?;

    // Model the legacy fixed-name temporary file stranded by an OS crash.
    let old_staged = disk.dir.join("root.json.staged");
    fs::write(&old_staged, b"incomplete-root-write")?;
    let (new_key, new_bytes) = v1_cell(1, "manifest-next", "second".repeat(512))?;
    stage(&mut graph, &mut objects, new_key.clone(), Some(&new_bytes))?;
    assert!(
        disk.reopen(Arc::clone(&key_material), 1)?
            .get(&new_key)
            .is_none()
    );
    assert_eq!(fs::read(disk.manifest_path())?, root_1);

    // A fresh, generation-bound staged name must let the next single-writer
    // publication finish, without trusting or erasing the stale file.
    disk.publish(&graph, &key_material, 2, false)?;
    assert_eq!(fs::read(old_staged)?, b"incomplete-root-write");
    let reopened = disk.reopen(Arc::clone(&key_material), 2)?;
    assert_eq!(reopened.get(&first_key), Some(first_bytes.as_slice()));
    assert_eq!(reopened.get(&new_key), Some(new_bytes.as_slice()));
    assert!(disk.reopen(key_material, 1).is_err());
    Ok(())
}

// A published MAC alone is insufficient if a path traversal can redirect disk
// I/O outside the private immutable object and manifest storage roots.
#[cfg(unix)]
#[test]
fn kv2_v6_disk_trial_rejects_symlink_object_and_root_paths()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;
    let disk = TrialDisk::fresh()?;
    let key_material = private_trial_key(&AddressKey::from_bytes([0x79; 32]))?;
    let mut graph = Kv1Index::empty(Arc::clone(&key_material));
    let mut objects = LocalObjects(BTreeMap::new());
    let (entry, bytes) = v1_cell(1, "link-attack", "trusted".repeat(1024))?;
    stage(&mut graph, &mut objects, entry.clone(), Some(&bytes))?;
    disk.publish(&graph, &key_material, 1, false)?;
    assert_eq!(
        disk.reopen(Arc::clone(&key_material), 1)?.get(&entry),
        Some(bytes.as_slice())
    );

    let object = graph.root().reference.ok_or("root object")?;
    let path = disk.object_path(&object.id);
    let original = fs::read(&path)?;
    let outside = disk.dir.join("untrusted-redirect-with-valid-bytes");
    fs::write(&outside, &original)?;
    fs::remove_file(&path)?;
    symlink(&outside, &path)?;
    assert!(
        disk.persist_objects(&graph).is_err(),
        "immutable object path may not follow a symbolic link"
    );
    assert!(
        disk.reopen(Arc::clone(&key_material), 1).is_err(),
        "published object root may not follow a symbolic link"
    );

    fs::remove_file(&path)?;
    fs::write(&path, &original)?;
    assert!(disk.reopen(Arc::clone(&key_material), 1).is_ok());
    let manifest = disk.manifest_path();
    let root_bytes = fs::read(&manifest)?;
    let outside_root = disk.dir.join("untrusted-root-redirect-with-valid-bytes");
    fs::write(&outside_root, root_bytes)?;
    fs::remove_file(&manifest)?;
    symlink(&outside_root, &manifest)?;
    assert!(
        disk.reopen(key_material, 1).is_err(),
        "authenticated manifest must not follow a symbolic link"
    );
    Ok(())
}

// An O_NOFOLLOW on the leaf does not protect the parent "objects" directory.
// A pinned root must not accept identical bytes redirected through a symlinked
// ancestor, including when the attacker leaves all MACs valid.
#[cfg(unix)]
#[test]
fn kv2_v6_disk_trial_rejects_ancestor_object_directory_symlink()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;
    let disk = TrialDisk::fresh()?;
    let address = private_trial_key(&AddressKey::from_bytes([0x7a; 32]))?;
    let mut graph = Kv1Index::empty(Arc::clone(&address));
    let mut objects = LocalObjects(BTreeMap::new());
    let (name, bytes) = v1_cell(1, "ancestor-link-attack", "intact".repeat(1024))?;
    stage(&mut graph, &mut objects, name.clone(), Some(&bytes))?;
    disk.publish(&graph, &address, 1, false)?;
    assert_eq!(
        disk.reopen(Arc::clone(&address), 1)?.get(&name),
        Some(bytes.as_slice())
    );

    let official = disk.dir.join("objects");
    let redirect = disk.dir.join("untrusted-objects-outside-the-owned-subdir");
    fs::rename(&official, &redirect)?;
    symlink(&redirect, &official)?;
    let redirected_write = disk.persist_objects(&graph);
    let redirected_read = disk.reopen(Arc::clone(&address), 1);
    // Restore the exact pinned directory before Drop: the guarded destructor
    // must refuse redirected trees, so test fixtures must not strand orphans.
    fs::remove_file(&official)?;
    fs::rename(&redirect, &official)?;
    assert!(
        redirected_write.is_err(),
        "valid bytes behind a symlinked parent must never be reused"
    );
    assert!(
        redirected_read.is_err(),
        "published graph must not read ordinary leaves through a symlinked parent"
    );
    assert_eq!(disk.reopen(address, 1)?.get(&name), Some(bytes.as_slice()));
    Ok(())
}

// A hard link is not blocked by O_NOFOLLOW and can point at identical
// authenticated bytes outside the private objects directory. No write or
// reopen may accept a multi-linked immutable inode.
#[cfg(unix)]
#[test]
fn kv2_v6_disk_trial_rejects_hardlinked_object_with_identical_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::MetadataExt;
    let disk = TrialDisk::fresh()?;
    let key = private_trial_key(&AddressKey::from_bytes([0x8d; 32]))?;
    let mut graph = Kv1Index::empty(Arc::clone(&key));
    let mut objects = LocalObjects(BTreeMap::new());
    let (name, bytes) = v1_cell(1, "hardlink-alias", "unchanged".repeat(1024))?;
    stage(&mut graph, &mut objects, name.clone(), Some(&bytes))?;
    disk.publish(&graph, &key, 1, false)?;
    assert_eq!(
        disk.reopen(Arc::clone(&key), 1)?.get(&name),
        Some(bytes.as_slice())
    );

    let object = graph.root().reference.ok_or("root object")?;
    let original = disk.object_path(&object.id);
    let outside_alias = disk.dir.join("outside-objects-hardlink-alias");
    fs::hard_link(&original, &outside_alias)?;
    assert_eq!(fs::metadata(&original)?.nlink(), 2);
    assert!(
        disk.persist_objects(&graph).is_err(),
        "linked object cannot be reused"
    );
    assert!(
        disk.reopen(Arc::clone(&key), 1).is_err(),
        "published graph cannot read a multi-linked object"
    );
    fs::remove_file(&outside_alias)?;
    assert_eq!(fs::metadata(&original)?.nlink(), 1);
    assert_eq!(disk.reopen(key, 1)?.get(&name), Some(bytes.as_slice()));
    Ok(())
}

// A manifest hard link bypasses O_NOFOLLOW just like an object hard link.
// A valid MAC over copied bytes cannot authorize a multiply-linked root inode.
#[cfg(unix)]
#[test]
fn kv2_v6_disk_trial_rejects_hardlinked_manifest_with_valid_mac()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::MetadataExt;
    let disk = TrialDisk::fresh()?;
    let key = private_trial_key(&AddressKey::from_bytes([0xa7; 32]))?;
    let mut graph = Kv1Index::empty(Arc::clone(&key));
    let mut objects = LocalObjects(BTreeMap::new());
    let (entry, bytes) = v1_cell(1, "root-hardlink", "trusted".repeat(1024))?;
    stage(&mut graph, &mut objects, entry.clone(), Some(&bytes))?;
    disk.publish(&graph, &key, 1, false)?;
    let manifest = disk.manifest_path();
    let original = fs::read(&manifest)?;
    let alias = disk.dir.join("outside-manifest-hardlink");
    fs::hard_link(&manifest, &alias)?;
    assert_eq!(fs::symlink_metadata(&manifest)?.nlink(), 2);

    let redirected_read = disk.reopen(Arc::clone(&key), 1);
    let redirected_publication = disk.publish(&graph, &key, 2, false);
    assert!(
        redirected_read.is_err(),
        "linked signed root must not authorize reads"
    );
    assert!(
        redirected_publication.is_err(),
        "linked signed root must not authorize a new generation"
    );
    assert_eq!(
        fs::read(&manifest)?,
        original,
        "denial cannot mutate the prior root"
    );
    fs::remove_file(alias)?;
    let recovered = disk.reopen(key, 1)?;
    assert_eq!(recovered.get(&entry), Some(bytes.as_slice()));
    Ok(())
}

// The object directory itself has provenance, independent of its signed leaf
// bytes. Replacing it with a different *regular directory*, filled with
// byte-identical authenticated objects, must be rejected even without symlinks.
#[cfg(unix)]
#[test]
fn kv2_v6_disk_trial_rejects_replaced_regular_objects_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let address = private_trial_key(&AddressKey::from_bytes([0x9d; 32]))?;
    let mut graph = Kv1Index::empty(Arc::clone(&address));
    let mut staged = LocalObjects(BTreeMap::new());
    let (item, bytes) = v1_cell(
        1,
        "same-object-bytes-different-directory",
        "owned".repeat(512),
    )?;
    stage(&mut graph, &mut staged, item.clone(), Some(&bytes))?;
    disk.publish(&graph, &address, 1, false)?;
    assert_eq!(
        disk.reopen(Arc::clone(&address), 1)?.get(&item),
        Some(bytes.as_slice())
    );

    let original = disk.dir.join("objects");
    let relocated = disk.dir.join("objects-original-pinned");
    assert!(!relocated.exists());
    fs::rename(&original, &relocated)?;
    fs::create_dir(&original)?;
    for entry in fs::read_dir(&relocated)? {
        let entry = entry?;
        fs::copy(entry.path(), original.join(entry.file_name()))?;
    }
    let redirected_read = disk.reopen(Arc::clone(&address), 1);
    let redirected_reuse = disk.persist_objects(&graph);
    // Restore before asserting, including during the intentionally red test.
    fs::remove_dir_all(&original)?;
    fs::rename(&relocated, &original)?;
    assert!(
        redirected_read.is_err(),
        "a substituted regular object directory cannot be read"
    );
    assert!(
        redirected_reuse.is_err(),
        "a substituted regular object directory cannot be reused"
    );
    assert_eq!(disk.reopen(address, 1)?.get(&item), Some(bytes.as_slice()));
    Ok(())
}

// V6 is still a single-writer *trial*, not production authority. Even in that
// limited scope, a stale or skipped generation must never replace an already
// authenticated root, nor stage objects before the rejection is established.
#[test]
fn kv2_v6_disk_trial_rejects_generation_replay_gap_and_corrupt_predecessor()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let key_material = private_trial_key(&AddressKey::from_bytes([0x87; 32]))?;
    let mut graph = Kv1Index::empty(Arc::clone(&key_material));
    let mut staged = LocalObjects(BTreeMap::new());
    let (old_key, old_bytes) = v1_cell(1, "generation-000", "first".repeat(512))?;
    stage(&mut graph, &mut staged, old_key.clone(), Some(&old_bytes))?;
    let count_objects =
        || -> Result<usize, std::io::Error> { Ok(fs::read_dir(disk.dir.join("objects"))?.count()) };

    // Only generation 1 can initialize a fresh root.
    assert!(disk.publish(&graph, &key_material, 2, false).is_err());
    assert!(!disk.manifest_path().exists());
    assert_eq!(count_objects()?, 0);
    disk.publish(&graph, &key_material, 1, false)?;
    let root_v1 = fs::read(disk.manifest_path())?;
    assert_eq!(
        disk.reopen(Arc::clone(&key_material), 1)?.get(&old_key),
        Some(old_bytes.as_slice())
    );

    let (new_key, new_bytes) = v1_cell(1, "generation-001", "second".repeat(512))?;
    stage(&mut graph, &mut staged, new_key.clone(), Some(&new_bytes))?;
    let before_rejection = count_objects()?;
    for invalid_generation in [0, 1, 3, u64::MAX] {
        assert!(
            disk.publish(&graph, &key_material, invalid_generation, false)
                .is_err(),
            "a stale, skipped or wrapping generation must not publish"
        );
        assert_eq!(fs::read(disk.manifest_path())?, root_v1);
        assert_eq!(count_objects()?, before_rejection);
    }
    assert!(
        disk.reopen(Arc::clone(&key_material), 1)?
            .get(&new_key)
            .is_none()
    );

    // The exact next generation may stage durable objects without publishing
    // a new root. Only the later completed root grants read visibility.
    disk.publish(&graph, &key_material, 2, true)?;
    assert_eq!(fs::read(disk.manifest_path())?, root_v1);
    disk.publish(&graph, &key_material, 2, false)?;
    let root_v2 = fs::read(disk.manifest_path())?;
    assert_ne!(root_v1, root_v2);
    assert_eq!(
        disk.reopen(Arc::clone(&key_material), 2)?.get(&new_key),
        Some(new_bytes.as_slice())
    );
    assert!(disk.reopen(Arc::clone(&key_material), 1).is_err());

    // A conflicting same-generation root must not overwrite acknowledged B.
    let (third_key, third_bytes) = v1_cell(1, "generation-002", "third".repeat(512))?;
    stage(
        &mut graph,
        &mut staged,
        third_key.clone(),
        Some(&third_bytes),
    )?;
    let v2_objects = count_objects()?;
    assert!(disk.publish(&graph, &key_material, 2, false).is_err());
    assert_eq!(fs::read(disk.manifest_path())?, root_v2);
    assert_eq!(count_objects()?, v2_objects);

    // No new generation may be committed through a corrupt previous root,
    // even when the candidate graph itself is otherwise well-formed.
    fs::write(disk.manifest_path(), b"corrupt-predecessor")?;
    assert!(disk.publish(&graph, &key_material, 3, false).is_err());
    assert_eq!(fs::read(disk.manifest_path())?, b"corrupt-predecessor");
    fs::write(disk.manifest_path(), &root_v2)?;
    disk.publish(&graph, &key_material, 3, false)?;
    assert_eq!(
        disk.reopen(key_material, 3)?.get(&third_key),
        Some(third_bytes.as_slice())
    );
    Ok(())
}

// An independent file description holding the exclusive publication lock
// must prevent even the first generation from staging or publishing bytes.
#[cfg(unix)]
#[test]
fn kv2_v6_disk_trial_exclusive_generation_lock_denies_concurrent_writer()
-> Result<(), Box<dyn std::error::Error>> {
    use rustix::fs::{FlockOperation, flock};
    let disk = TrialDisk::fresh()?;
    let key = private_trial_key(&AddressKey::from_bytes([0x9a; 32]))?;
    let mut graph = Kv1Index::empty(Arc::clone(&key));
    let mut staged = LocalObjects(BTreeMap::new());
    let (item, bytes) = v1_cell(1, "competing-publication", "locked".repeat(512))?;
    stage(&mut graph, &mut staged, item.clone(), Some(&bytes))?;
    let competing_writer = File::open(&disk.dir)?;
    flock(&competing_writer, FlockOperation::NonBlockingLockExclusive)?;
    assert!(
        matches!(
            disk.publish(&graph, &key, 1, false),
            Err(RecordError::Invalid)
        ),
        "concurrent generation must be rejected"
    );
    assert!(!disk.manifest_path().exists());
    assert_eq!(fs::read_dir(disk.dir.join("objects"))?.count(), 0);
    drop(competing_writer);
    disk.publish(&graph, &key, 1, false)?;
    assert_eq!(disk.reopen(key, 1)?.get(&item), Some(bytes.as_slice()));
    Ok(())
}

#[cfg(unix)]
#[test]
fn kv2_v6_disk_trial_rejects_redirected_trial_root_even_with_valid_mac()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;
    let disk = TrialDisk::fresh()?;
    let key_material = private_trial_key(&AddressKey::from_bytes([0x9b; 32]))?;
    let mut graph = Kv1Index::empty(Arc::clone(&key_material));
    let mut staged = LocalObjects(BTreeMap::new());
    let (record_key, record) = v1_cell(1, "relocated-root", "trusted".repeat(512))?;
    stage(&mut graph, &mut staged, record_key.clone(), Some(&record))?;
    disk.publish(&graph, &key_material, 1, false)?;
    assert_eq!(
        disk.reopen(Arc::clone(&key_material), 1)?.get(&record_key),
        Some(record.as_slice())
    );
    // Redirect the entire root path, not just the leaf root.json or objects.
    // All files and MACs remain valid; their *origin* has changed.
    let relocated = disk.dir.with_extension("relocated-untrusted");
    assert!(!relocated.exists());
    fs::rename(&disk.dir, &relocated)?;
    symlink(&relocated, &disk.dir)?;
    let redirected = disk.reopen(Arc::clone(&key_material), 1);
    // Restore and clean up before the assertion, including during the red run.
    fs::remove_file(&disk.dir)?;
    fs::rename(&relocated, &disk.dir)?;
    assert!(
        redirected.is_err(),
        "a signed root redirected through a symlinked trial root must fail closed"
    );
    assert_eq!(
        disk.reopen(key_material, 1)?.get(&record_key),
        Some(record.as_slice())
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn kv2_v6_disk_trial_rejects_replaced_regular_root_with_copied_signed_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let key_material = private_trial_key(&AddressKey::from_bytes([0x9c; 32]))?;
    let mut graph = Kv1Index::empty(Arc::clone(&key_material));
    let mut staged = LocalObjects(BTreeMap::new());
    let (record_key, record) = v1_cell(1, "copied-directory-root", "trusted".repeat(256))?;
    stage(&mut graph, &mut staged, record_key.clone(), Some(&record))?;
    disk.publish(&graph, &key_material, 1, false)?;
    let old_dir = disk.dir.with_extension("original-pinned");
    assert!(!old_dir.exists());
    fs::rename(&disk.dir, &old_dir)?;
    fs::create_dir(&disk.dir)?;
    fs::create_dir(disk.dir.join("objects"))?;
    fs::copy(old_dir.join("root.json"), disk.manifest_path())?;
    for object in fs::read_dir(old_dir.join("objects"))? {
        let object = object?;
        fs::copy(
            object.path(),
            disk.dir.join("objects").join(object.file_name()),
        )?;
    }
    // This is a different directory inode, despite byte-identical signed data.
    let replacement = disk.reopen(Arc::clone(&key_material), 1);
    fs::remove_dir_all(&disk.dir)?;
    fs::rename(&old_dir, &disk.dir)?;
    assert!(
        replacement.is_err(),
        "a copied signed tree must not replace the pinned private root"
    );
    assert_eq!(
        disk.reopen(key_material, 1)?.get(&record_key),
        Some(record.as_slice())
    );
    Ok(())
}

// A path-based recursive Drop can erase a different owner's unrelated
// regular directory if the pinned private root was moved between test phases.
// This is a synthetic fixture regression; no new storage authority is granted.
#[cfg(unix)]
#[test]
fn kv2_v6_trial_drop_must_not_remove_replaced_root() -> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let untrusted = disk.dir.clone();
    let original = disk.dir.with_extension("r510-original-root");
    assert!(!original.exists());
    fs::rename(&untrusted, &original)?;
    fs::create_dir(&untrusted)?;
    let sentinel = untrusted.join("independent-owner-keeps-this");
    fs::write(&sentinel, b"untrusted synthetic data")?;
    drop(disk);
    let untouched = fs::read(&sentinel).ok().as_deref() == Some(b"untrusted synthetic data");
    if untrusted.exists() {
        fs::remove_dir_all(&untrusted)?;
    }
    fs::remove_dir_all(original)?;
    assert!(
        untouched,
        "drop must never recursively erase an untrusted replacement root"
    );
    Ok(())
}

// The root inode alone is insufficient: a different objects directory inside
// the same root must also deny recursive cleanup.
#[cfg(unix)]
#[test]
fn kv2_v6_trial_drop_must_not_remove_replaced_objects_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let original = disk.dir.join("objects");
    let relocated = disk.dir.join("objects-original-r510");
    fs::rename(&original, &relocated)?;
    fs::create_dir(&original)?;
    let sentinel = original.join("independent-owner-keeps-this");
    fs::write(&sentinel, b"untrusted synthetic object")?;
    let root = disk.dir.clone();
    drop(disk);
    let untouched = fs::read(&sentinel).ok().as_deref() == Some(b"untrusted synthetic object");
    if root.exists() {
        fs::remove_dir_all(&root)?;
    }
    assert!(
        untouched,
        "drop must never erase substituted object directories"
    );
    Ok(())
}

// Before a V6 record has a real tombstone authority, its acknowledged
// version history is immutable. A future signed *root* alone cannot authorize
// rewriting the same KV2 version or deleting/replacing past version entries.
fn history_attack_must_not_publish(case: &str) -> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let signer = private_trial_key(&AddressKey::from_bytes([0xbb; 32]))?;
    let (address, original) = v1_cell(1, "r612-history", "original".into())?;
    let mut base = Kv1Index::empty(Arc::clone(&signer));
    let mut objects = LocalObjects(BTreeMap::new());
    stage(&mut base, &mut objects, address.clone(), Some(&original))?;
    disk.publish(&base, &signer, 1, false)?;
    let frozen_root = fs::read(disk.manifest_path())?;
    let frozen_count = fs::read_dir(disk.dir.join("objects"))?.count();
    let scope = Scope {
        namespace: "tenant-r310".into(),
        mount: "secret/".into(),
        incarnation: 7,
        path: "r612-history".into(),
    };
    let forged = match case {
        "same_version_rewrite" => v1_cell(1, "r612-history", "mutated".into())?.1,
        "missing_prior" => v1_cell(2, "r612-history", "later".into())?.1,
        "modified_prior" => encode(
            scope,
            2,
            json!({
                "current_version":2,
                "versions":{
                    "1":{"data":{"payload":"forged"},"destroyed":false},
                    "2":{"data":{"payload":"later"},"destroyed":false}
                }
            }),
        )?,
        _ => return Err("unrecognized history attack".into()),
    };
    let mut proposed = base;
    let mut next_objects = LocalObjects(BTreeMap::new());
    stage(
        &mut proposed,
        &mut next_objects,
        address.clone(),
        Some(&forged),
    )?;
    assert!(
        disk.publish(&proposed, &signer, 2, false).is_err(),
        "{case} must be rejected before the signed root and object staging"
    );
    assert_eq!(fs::read(disk.manifest_path())?, frozen_root);
    assert_eq!(
        fs::read_dir(disk.dir.join("objects"))?.count(),
        frozen_count
    );
    let visible = disk.reopen(signer, 1)?;
    assert_eq!(visible.get(&address), Some(original.as_slice()));
    Ok(())
}
#[test]
fn kv2_v6_disk_trial_rejects_same_version_payload_rewrite() -> Result<(), Box<dyn std::error::Error>>
{
    history_attack_must_not_publish("same_version_rewrite")
}
#[test]
fn kv2_v6_disk_trial_rejects_disappeared_prior_version() -> Result<(), Box<dyn std::error::Error>> {
    history_attack_must_not_publish("missing_prior")
}
#[test]
fn kv2_v6_disk_trial_rejects_changed_prior_version() -> Result<(), Box<dyn std::error::Error>> {
    history_attack_must_not_publish("modified_prior")
}

// A new signed root must retain previously acknowledged typed KV2 record
// addresses and never lower the visible version without retirement authority.
#[test]
fn kv2_v6_disk_trial_generation_cannot_erase_or_regress_committed_records()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let key_material = private_trial_key(&AddressKey::from_bytes([0xa4; 32]))?;
    let mut committed = Kv1Index::empty(Arc::clone(&key_material));
    let mut original_objects = LocalObjects(BTreeMap::new());
    let (protected, first) = v1_cell(3, "r610-protected", "original".repeat(150))?;
    let (retained, second) = v1_cell(1, "r610-retained", "retained".repeat(150))?;
    stage(
        &mut committed,
        &mut original_objects,
        protected.clone(),
        Some(&first),
    )?;
    stage(
        &mut committed,
        &mut original_objects,
        retained.clone(),
        Some(&second),
    )?;
    disk.publish(&committed, &key_material, 1, false)?;
    let signed_original = fs::read(disk.manifest_path())?;
    let objects_count = || fs::read_dir(disk.dir.join("objects")).map(|entries| entries.count());
    let before = objects_count()?;

    // A stale candidate was not edited from the committed graph. A caller
    // with the exact next number must not erase the acknowledged record.
    let mut lost = Kv1Index::empty(Arc::clone(&key_material));
    let mut new_objects = LocalObjects(BTreeMap::new());
    stage(&mut lost, &mut new_objects, retained.clone(), Some(&second))?;
    let (new_key, new_bytes) = v1_cell(1, "r610-unrelated", "new".repeat(150))?;
    stage(
        &mut lost,
        &mut new_objects,
        new_key.clone(),
        Some(&new_bytes),
    )?;
    assert!(
        disk.publish(&lost, &key_material, 2, false).is_err(),
        "a next-generation number cannot authorize losing an existing record"
    );
    assert_eq!(fs::read(disk.manifest_path())?, signed_original);
    assert_eq!(objects_count()?, before);
    assert_eq!(
        disk.reopen(Arc::clone(&key_material), 1)?.get(&protected),
        Some(first.as_slice())
    );
    assert!(
        disk.reopen(Arc::clone(&key_material), 1)?
            .get(&new_key)
            .is_none()
    );

    // Replacing a record with an older signed cell is likewise inadmissible,
    // even if every graph key remains present.
    let mut regressed = committed.clone();
    let mut regression_objects = LocalObjects(BTreeMap::new());
    let (_, older) = v1_cell(2, "r610-protected", "rolled-back".repeat(150))?;
    stage(
        &mut regressed,
        &mut regression_objects,
        protected.clone(),
        Some(&older),
    )?;
    assert!(
        disk.publish(&regressed, &key_material, 2, false).is_err(),
        "a signed generation must not lower an existing cell version"
    );
    assert_eq!(fs::read(disk.manifest_path())?, signed_original);
    assert_eq!(objects_count()?, before);

    // A correctly retained graph with an increasing cell version still
    // publishes exactly once after the negative cases.
    let mut next = committed;
    let mut next_objects = LocalObjects(BTreeMap::new());
    let prior = decode(&protected, &first)?;
    // Preserve the zeroizing Drop contract of the signed V6 Cell: use the
    // audited consuming API instead of moving secret-bearing fields directly.
    let (prior_scope, _prior_version, mut updated_entry) = prior.into_parts();
    updated_entry["current_version"] = json!(4);
    updated_entry["versions"]["4"] =
        json!({"data":{"payload":"updated".repeat(150)},"destroyed":false});
    let updated = encode(prior_scope, 4, updated_entry)?;
    stage(
        &mut next,
        &mut next_objects,
        protected.clone(),
        Some(&updated),
    )?;
    disk.publish(&next, &key_material, 2, false)?;
    let reopened = disk.reopen(key_material, 2)?;
    assert_eq!(reopened.get(&protected), Some(updated.as_slice()));
    assert_eq!(reopened.get(&retained), Some(second.as_slice()));
    assert!(reopened.get(&new_key).is_none());
    Ok(())
}

// Canonical JSON and a valid MAC are insufficient when the envelope version
// disagrees with the embedded KV2 current_version / retained-version map.
#[test]
fn kv2_v6_disk_trial_refuses_inconsistent_entry_version_and_history()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let signer = private_trial_key(&AddressKey::from_bytes([0xa5; 32]))?;
    let scope = Scope {
        namespace: "tenant-r310".into(),
        mount: "secret/".into(),
        incarnation: 7,
        path: "r610-inconsistent".into(),
    };
    let record_key = key(&scope)?;
    let malformed = encode(
        scope.clone(),
        2,
        json!({"current_version":1,"versions":{"1":{"data":{"payload":"old"}},"2":{"data":{"payload":"claimed"}}}}),
    )?;
    let mut bad_graph = Kv1Index::empty(Arc::clone(&signer));
    let mut bad_objects = LocalObjects(BTreeMap::new());
    stage(
        &mut bad_graph,
        &mut bad_objects,
        record_key.clone(),
        Some(&malformed),
    )?;
    assert!(
        disk.publish(&bad_graph, &signer, 1, false).is_err(),
        "inner current_version must match the signed cell version"
    );
    assert!(!disk.manifest_path().exists());
    assert_eq!(fs::read_dir(disk.dir.join("objects"))?.count(), 0);

    let (first_key, first) = v1_cell(2, "r610-inconsistent", "accepted".into())?;
    assert!(first_key == record_key);
    let mut original = Kv1Index::empty(Arc::clone(&signer));
    let mut objects = LocalObjects(BTreeMap::new());
    stage(&mut original, &mut objects, first_key.clone(), Some(&first))?;
    disk.publish(&original, &signer, 1, false)?;
    let signed = fs::read(disk.manifest_path())?;
    let count = fs::read_dir(disk.dir.join("objects"))?.count();

    // Even a higher envelope version cannot hide that its claimed current
    // value has no matching entry in the versioned history.
    let mut new_graph = original;
    let missing_current = encode(
        scope,
        3,
        json!({"current_version":3,"versions":{"2":{"data":{"payload":"retained"}}}}),
    )?;
    stage(
        &mut new_graph,
        &mut objects,
        record_key.clone(),
        Some(&missing_current),
    )?;
    assert!(
        disk.publish(&new_graph, &signer, 2, false).is_err(),
        "the claimed current KV2 version must exist in its history"
    );
    assert_eq!(fs::read(disk.manifest_path())?, signed);
    assert_eq!(fs::read_dir(disk.dir.join("objects"))?.count(), count);
    let reopened = disk.reopen(signer, 1)?;
    assert_eq!(reopened.get(&record_key), Some(first.as_slice()));
    Ok(())
}

// A correct signed manifest is useless when its B-tree pages were addressed
// using a different authenticated key. Reject before publishing a root that
// any admitted reader will be unable to reopen.
#[test]
fn kv2_v6_disk_trial_never_publishes_foreign_address_key_graph()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let signer = private_trial_key(&AddressKey::from_bytes([0xa6; 32]))?;
    let foreign = private_trial_key(&AddressKey::from_bytes([0xa7; 32]))?;
    assert_ne!(signer.expose(), foreign.expose());

    let mut wrong = Kv1Index::empty(Arc::clone(&foreign));
    let mut objects = LocalObjects(BTreeMap::new());
    let (foreign_key, foreign_record) =
        v1_cell(1, "foreign-key", "should-not-be-visible".repeat(32))?;
    stage(&mut wrong, &mut objects, foreign_key, Some(&foreign_record))?;
    assert!(
        disk.publish(&wrong, &signer, 1, false).is_err(),
        "foreign-address graph must not obtain a signed generation"
    );
    assert!(
        !disk.manifest_path().exists(),
        "rejected initial graph must leave no authenticated root"
    );

    let mut valid = Kv1Index::empty(Arc::clone(&signer));
    let (accepted_key, accepted_record) = v1_cell(1, "original-owner", "original".repeat(64))?;
    stage(
        &mut valid,
        &mut objects,
        accepted_key.clone(),
        Some(&accepted_record),
    )?;
    disk.publish(&valid, &signer, 1, false)?;
    let signed_generation_one = fs::read(disk.manifest_path())?;
    assert_eq!(
        disk.reopen(Arc::clone(&signer), 1)?.get(&accepted_key),
        Some(accepted_record.as_slice())
    );

    assert!(
        disk.publish(&wrong, &signer, 2, false).is_err(),
        "foreign-address graph must not replace an acknowledged root"
    );
    assert_eq!(fs::read(disk.manifest_path())?, signed_generation_one);
    assert_eq!(
        disk.reopen(signer, 1)?.get(&accepted_key),
        Some(accepted_record.as_slice())
    );
    Ok(())
}

// Correctly addressed B-tree pages are not sufficient when a KV2 cell is
// noncanonical or claims another scope. Both initial and successor roots must
// reject these bytes before making a new authenticated publication visible.
#[test]
fn kv2_v6_disk_trial_rejects_noncanonical_or_wrong_scope_cell_before_signed_root()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let signer = private_trial_key(&AddressKey::from_bytes([0xa8; 32]))?;
    let mut objects = LocalObjects(BTreeMap::new());
    let mut invalid = Kv1Index::empty(Arc::clone(&signer));
    let (record_key, correct) = v1_cell(1, "scope-pinned", "canonical".repeat(40))?;
    let mut other_scope: Value = serde_json::from_slice(&correct)?;
    other_scope["scope"]["path"] = json!("impostor");
    let wrong_scope = serde_json::to_vec(&other_scope)?;
    stage(
        &mut invalid,
        &mut objects,
        record_key.clone(),
        Some(&wrong_scope),
    )?;
    assert!(
        disk.publish(&invalid, &signer, 1, false).is_err(),
        "valid B-tree pages cannot authenticate a cell claiming another key"
    );
    assert!(!disk.manifest_path().exists());

    let mut valid = Kv1Index::empty(Arc::clone(&signer));
    stage(&mut valid, &mut objects, record_key.clone(), Some(&correct))?;
    disk.publish(&valid, &signer, 1, false)?;
    let signed_generation_one = fs::read(disk.manifest_path())?;

    let (second_key, second) = v1_cell(1, "format-pinned", "canonical".repeat(40))?;
    let mut noncanonical: Value = serde_json::from_slice(&second)?;
    noncanonical["format"] = json!("foreign-format");
    stage(
        &mut valid,
        &mut objects,
        second_key,
        Some(&serde_json::to_vec(&noncanonical)?),
    )?;
    assert!(
        disk.publish(&valid, &signer, 2, false).is_err(),
        "noncanonical typed cell must not replace acknowledged generation"
    );
    assert_eq!(fs::read(disk.manifest_path())?, signed_generation_one);
    assert_eq!(
        disk.reopen(signer, 1)?.get(&record_key),
        Some(correct.as_slice())
    );
    Ok(())
}

// A signed record must not smuggle historical versions newer than the
// advertised current version, alternate decimal spellings or a non-record.
// Generation/history consistency is checked before writing any page to disk.
#[test]
fn kv2_v6_disk_trial_rejects_invalid_history_version_names_and_values()
-> Result<(), Box<dyn std::error::Error>> {
    let rejected = [
        ("future", json!({"3":{"data":{"payload":"ok"}},"4":{}})),
        ("zero", json!({"0":{},"3":{"data":{"payload":"ok"}}})),
        (
            "leading_zero",
            json!({"03":{},"3":{"data":{"payload":"ok"}}}),
        ),
        (
            "non_numeric",
            json!({"legacy":{},"3":{"data":{"payload":"ok"}}}),
        ),
        (
            "overflow",
            json!({"18446744073709551616":{},"3":{"data":{"payload":"ok"}}}),
        ),
        (
            "non_object",
            json!({"2":null,"3":{"data":{"payload":"ok"}}}),
        ),
        ("wrong_type", json!({"1":[],"3":{"data":{"payload":"ok"}}})),
    ];
    for (case, versions) in rejected {
        let disk = TrialDisk::fresh()?;
        let signer = private_trial_key(&AddressKey::from_bytes([0x8e; 32]))?;
        let scope = Scope {
            namespace: "r650-history".into(),
            mount: "secret/".into(),
            incarnation: 5,
            path: format!("record-{case}"),
        };
        let address = key(&scope)?;
        let malformed = encode(
            scope.clone(),
            3,
            json!({
                "current_version": 3, "versions":versions,
            }),
        )?;
        let mut malicious = Kv1Index::empty(Arc::clone(&signer));
        let mut objects = LocalObjects(BTreeMap::new());
        stage(
            &mut malicious,
            &mut objects,
            address.clone(),
            Some(&malformed),
        )?;
        assert!(
            disk.publish(&malicious, &signer, 1, false).is_err(),
            "{case}"
        );
        assert!(!disk.manifest_path().exists(), "{case}: root published");
        assert_eq!(
            fs::read_dir(disk.dir.join("objects"))?.count(),
            0,
            "{case}: invalid history left a staged object",
        );
        // Each negative test must prove that the fixture itself can publish
        // an accepted sparse-but-canonical historical record after rejection.
        let valid = encode(
            scope,
            3,
            json!({
                "current_version":3,"versions":{"3":{"data":{"payload":"ok"}}}
            }),
        )?;
        let mut good = Kv1Index::empty(Arc::clone(&signer));
        stage(&mut good, &mut objects, address.clone(), Some(&valid))?;
        disk.publish(&good, &signer, 1, false)?;
        assert_eq!(
            disk.reopen(signer, 1)?.get(&address),
            Some(valid.as_slice())
        );
    }
    Ok(())
}

// Reopen is also an admission boundary. A valid manifest MAC plus correctly
// addressed object pages cannot make a malformed KV2 history authoritative.
#[test]
fn kv2_v6_disk_trial_reopen_rejects_valid_mac_with_invalid_kv2_history()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let signer = private_trial_key(&AddressKey::from_bytes([0xc3; 32]))?;
    let scope = Scope {
        namespace: "r660-reopen".into(),
        mount: "secret/".into(),
        incarnation: 7,
        path: "history".into(),
    };
    let address = key(&scope)?;
    let invalid = encode(
        scope.clone(),
        3,
        json!({
            "current_version":3, "versions":{"3":{"data":{"payload":"ok"}},"4":{}}
        }),
    )?;
    let mut graph = Kv1Index::empty(Arc::clone(&signer));
    let mut staging = LocalObjects(BTreeMap::new());
    stage(&mut graph, &mut staging, address.clone(), Some(&invalid))?;
    // A disk image can contain valid object MACs and a valid signed root,
    // yet still be internally inconsistent. Construct it without calling
    // publish(), whose strict preflight intentionally rejects this image.
    disk.persist_objects(&graph)?;
    let raw_index = Kv1Index::open(Arc::clone(&signer), graph.root(), &disk)?;
    assert_eq!(raw_index.get(&address), Some(invalid.as_slice()));
    let payload = TrialPayload {
        format: TRIAL_FORMAT.into(),
        cluster: "synthetic-r310".into(),
        epoch: 7,
        generation: 1,
        root: graph.root(),
    };
    let data = serde_json::to_vec(&payload)?;
    let authenticated = TrialRootEnvelope {
        mac: signer.digest(ROOT_DOMAIN, &data)?,
        payload,
    };
    let root_bytes = serde_json::to_vec(&authenticated)?;
    fs::write(disk.manifest_path(), &root_bytes)?;
    assert!(
        disk.authenticated_root(&signer).is_ok(),
        "test requires a valid MAC"
    );
    assert!(
        disk.reopen(Arc::clone(&signer), 1).is_err(),
        "reopen must reject an authenticated but incoherent KV2 history"
    );
    assert_eq!(
        fs::read(disk.manifest_path())?,
        root_bytes,
        "a negative reopen must not modify root bytes"
    );
    // Positive control: a canonical sparse history is still admissible.
    let healthy = TrialDisk::fresh()?;
    let valid = encode(
        scope,
        3,
        json!({
            "current_version":3,"versions":{"3":{"data":{"payload":"ok"}}}
        }),
    )?;
    let mut good = Kv1Index::empty(Arc::clone(&signer));
    stage(&mut good, &mut staging, address.clone(), Some(&valid))?;
    healthy.publish(&good, &signer, 1, false)?;
    assert_eq!(
        healthy.reopen(signer, 1)?.get(&address),
        Some(valid.as_slice())
    );
    Ok(())
}

#[test]
fn kv2_v6_disk_trial_refuses_malformed_version_payload_before_object_staging()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let signer = private_trial_key(&AddressKey::from_bytes([0xd3; 32]))?;
    let scope = Scope {
        namespace: "r670-version-fields".into(),
        mount: "secret/".into(),
        incarnation: 7,
        path: "inconsistent-legacy-payload".into(),
    };
    let address = key(&scope)?;
    let malformed = encode(
        scope.clone(),
        1,
        json!({"current_version":1, "versions":{"1":{
            "destroyed":false, "data":["invalid", "not_object"]
        }}}),
    )?;
    let mut graph = Kv1Index::empty(Arc::clone(&signer));
    let mut staging = LocalObjects(BTreeMap::new());
    stage(&mut graph, &mut staging, address.clone(), Some(&malformed))?;
    assert!(disk.publish(&graph, &signer, 1, false).is_err());
    assert!(
        !disk.manifest_path().exists(),
        "rejected root was published"
    );
    assert_eq!(
        fs::read_dir(disk.dir.join("objects"))?.count(),
        0,
        "rejected candidate staged durable objects"
    );
    let healthy = encode(
        scope,
        1,
        json!({"current_version":1, "versions":{"1":{
            "destroyed":false, "data":{"payload":"valid"}
        }}}),
    )?;
    stage(&mut graph, &mut staging, address.clone(), Some(&healthy))?;
    disk.publish(&graph, &signer, 1, false)?;
    assert_eq!(
        disk.reopen(signer, 1)?.get(&address),
        Some(healthy.as_slice())
    );
    Ok(())
}

// Metadata times participate in KV2 deletion/retention decisions. A valid
// address and signed root must not legitimize arrays, numbers or maps as
// creation/deletion timestamps for a later production migration reader.
#[test]
fn kv2_v6_disk_trial_refuses_untyped_temporal_fields_before_signed_root()
-> Result<(), Box<dyn std::error::Error>> {
    let attacks = [
        ("created_bool", "created_time", json!(true)),
        ("created_array", "created_time", json!([])),
        ("created_empty", "created_time", json!("")),
        (
            "created_invalid_calendar",
            "created_time",
            json!("2026-13-52T00:00:00Z"),
        ),
        ("deleted_object", "deletion_time", json!({"when":"now"})),
        ("deleted_number", "deletion_time", json!(42)),
        ("deleted_invalid", "deletion_time", json!("tomorrow")),
        // Valid RFC3339 syntax is not enough: a deletion cannot predate
        // creation, including when the two clock offsets differ.
        (
            "deleted_before_created",
            "deletion_time",
            json!("2026-10-11T23:59:59Z"),
        ),
        (
            "deleted_before_created_offset",
            "deletion_time",
            json!("2026-10-12T08:59:59+09:00"),
        ),
    ];
    for (name, field, wrong_type) in attacks {
        let disk = TrialDisk::fresh()?;
        let signer = private_trial_key(&AddressKey::from_bytes([0xe8; 32]))?;
        let scope = Scope {
            namespace: "r680-temporal-type".into(),
            mount: "secret/".into(),
            incarnation: 9,
            path: name.into(),
        };
        let address = key(&scope)?;
        let mut malformed = json!({
            "current_version":1, "versions":{"1":{
                "data":{"payload":"present"}, "destroyed":false,
                "created_time":"2026-10-12T00:00:00Z", "deletion_time":""
            }}
        });
        malformed["versions"]["1"][field] = wrong_type;
        let bad = encode(scope.clone(), 1, malformed)?;
        let mut graph = Kv1Index::empty(Arc::clone(&signer));
        let mut pending = LocalObjects(BTreeMap::new());
        stage(&mut graph, &mut pending, address.clone(), Some(&bad))?;
        assert!(
            disk.publish(&graph, &signer, 1, false).is_err(),
            "{name}: invalid time field signed into an acknowledged root"
        );
        assert!(!disk.manifest_path().exists(), "{name}: root published");
        assert_eq!(
            fs::read_dir(disk.dir.join("objects"))?.count(),
            0,
            "{name}: refused candidate left durable objects"
        );
        let good = encode(
            scope,
            1,
            json!({
                "current_version":1, "versions":{"1":{
                    "data":{"payload":"present"}, "destroyed":false,
                    "created_time":"2026-10-12T00:00:00Z", "deletion_time":""
                }}
            }),
        )?;
        stage(&mut graph, &mut pending, address.clone(), Some(&good))?;
        disk.publish(&graph, &signer, 1, false)?;
        assert_eq!(disk.reopen(signer, 1)?.get(&address), Some(good.as_slice()));
    }
    Ok(())
}

// Red gate for compatibility between the admitted 2560KiB KV2 HTTP ingress
// and the independent V6 typed-record storage experiment. The latter must not
// claim admission if a correctly typed large value cannot be published/reopened.
#[test]
fn kv2_v6_disk_trial_actual_2560k_value_signed_root_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let key_material = private_trial_key(&AddressKey::from_bytes([0xda; 32]))?;
    let mut graph = Kv1Index::empty(Arc::clone(&key_material));
    let mut objects = LocalObjects(BTreeMap::new());
    let (address, cell) = v1_cell(1, "official-kv2-2560k", "P".repeat(2560 * 1024))?;
    assert!(cell.len() > crate::http::MAX_BODY);
    assert!(cell.len() < crate::state_records::MAX_VALUE_BYTES);
    stage(&mut graph, &mut objects, address.clone(), Some(&cell))?;
    disk.publish(&graph, &key_material, 1, false)?;
    let reopened = disk.reopen(Arc::clone(&key_material), 1)?;
    assert_eq!(reopened.get(&address), Some(cell.as_slice()));
    let verified = decode(&address, reopened.get(&address).ok_or("cell missing")?)?;
    assert_eq!(verified.version, 1);
    assert_eq!(
        verified.entry["versions"]["1"]["data"]["payload"]
            .as_str()
            .map(str::len),
        Some(2560 * 1024),
    );
    Ok(())
}

// All helpers below belong solely to the private R740 V6 experiment.
// Production still uses the opaque V5 engine owner. This is NOT a migration
// adapter, record retirement authority, or alternative service dispatcher.
fn sharded_index_cell(
    logical: Scope,
    current_version: u64,
) -> Result<Zeroizing<Vec<u8>>, RecordError> {
    if current_version == 0 || current_version > 32 {
        return Err(RecordError::Invalid);
    }
    let mut pointers = serde_json::Map::new();
    for version in 1..=current_version {
        let shard = sharded_version_scope(&logical, version)?;
        pointers.insert(
            version.to_string(),
            json!({"data":{"shard_path":shard.path},"destroyed":false}),
        );
    }
    encode(
        logical,
        current_version,
        json!({"shard_schema":SHARD_INDEX_SCHEMA, "current_version":current_version,
               "versions":Value::Object(pointers)}),
    )
}

fn stage_sharded_version(
    index: &mut Kv1Index,
    objects: &mut LocalObjects,
    logical: &Scope,
    version: u64,
    payload: String,
) -> Result<(), RecordError> {
    let scope = sharded_version_scope(logical, version)?;
    let mut retained = serde_json::Map::new();
    retained.insert(
        version.to_string(),
        json!({"data":{"payload":payload},"destroyed":false}),
    );
    let version_cell = encode(
        scope.clone(),
        version,
        json!({"current_version":version, "versions":Value::Object(retained)}),
    )?;
    stage(index, objects, key(&scope)?, Some(&version_cell))?;
    let indexed = sharded_index_cell(logical.clone(), version)?;
    stage(index, objects, key(logical)?, Some(&indexed))
}

fn sharded_payload(
    graph: &Kv1Index,
    logical: &Scope,
    version: u64,
) -> Result<Zeroizing<String>, RecordError> {
    validate_sharded_trial_index(graph)?;
    let header_key = key(logical)?;
    let header = decode(
        &header_key,
        graph.get(&header_key).ok_or(RecordError::Missing)?,
    )?;
    if header.entry.get("shard_schema").and_then(Value::as_str) != Some(SHARD_INDEX_SCHEMA)
        || version == 0
        || version > header.version
    {
        return Err(RecordError::Invalid);
    }
    let physical_key = key(&sharded_version_scope(logical, version)?)?;
    let version_cell = decode(
        &physical_key,
        graph.get(&physical_key).ok_or(RecordError::Missing)?,
    )?;
    let payload = version_cell
        .entry
        .get("versions")
        .and_then(Value::as_object)
        .and_then(|versions| versions.get(&version.to_string()))
        .and_then(|entry| entry.get("data"))
        .and_then(|data| data.get("payload"))
        .and_then(Value::as_str)
        .ok_or(RecordError::Corrupt)?;
    Ok(Zeroizing::new(payload.to_owned()))
}

#[test]
fn kv2_v6_disk_trial_two_2560k_retained_versions_survive_signed_root()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let signing = private_trial_key(&AddressKey::from_bytes([0xbb; 32]))?;
    let logical = Scope {
        namespace: "tenant-sharded".into(),
        mount: "secret/".into(),
        incarnation: 17,
        path: "two-retained-large-versions".into(),
    };
    let first = "A".repeat(2560 * 1024);
    let second = "B".repeat(2560 * 1024);
    // Old per-path layout cannot hold both acknowledged large versions.
    assert!(matches!(
        encode(
            logical.clone(),
            2,
            json!({"current_version":2,"versions":{
                "1":{"data":{"payload":first},"destroyed":false},
                "2":{"data":{"payload":second},"destroyed":false}
            }})
        ),
        Err(RecordError::TooLarge)
    ));
    let mut graph = Kv1Index::empty(Arc::clone(&signing));
    let mut objects = LocalObjects(BTreeMap::new());
    stage_sharded_version(&mut graph, &mut objects, &logical, 1, first.clone())?;
    disk.publish(&graph, &signing, 1, false)?;
    let first_manifest = fs::read(disk.manifest_path())?;
    let first_graph = disk.reopen(Arc::clone(&signing), 1)?;
    assert_eq!(sharded_payload(&first_graph, &logical, 1)?.as_str(), first);

    stage_sharded_version(&mut graph, &mut objects, &logical, 2, second.clone())?;
    disk.publish(&graph, &signing, 2, true)?;
    assert_eq!(fs::read(disk.manifest_path())?, first_manifest);
    let pending = disk.reopen(Arc::clone(&signing), 1)?;
    assert!(sharded_payload(&pending, &logical, 2).is_err());

    disk.publish(&graph, &signing, 2, false)?;
    let committed = disk.reopen(Arc::clone(&signing), 2)?;
    assert_eq!(sharded_payload(&committed, &logical, 1)?.as_str(), first);
    assert_eq!(sharded_payload(&committed, &logical, 2)?.as_str(), second);
    assert!(disk.reopen(Arc::clone(&signing), 1).is_err());

    // A next signed root may not point a version at a different shard or
    // reference a missing shard. The refusal precedes object staging.
    let mut invalid = graph.clone();
    let mut more = LocalObjects(BTreeMap::new());
    let mut bad_index: Cell = serde_json::from_slice(&sharded_index_cell(logical.clone(), 3)?)?;
    bad_index.entry["versions"]["3"]["data"]["shard_path"] =
        json!(sharded_version_scope(&logical, 1)?.path);
    let bad_bytes = serde_json::to_vec(&bad_index)?;
    assert!(
        decode(&key(&logical)?, &bad_bytes).is_ok(),
        "wrong shard pointer must remain a canonically encoded Cell"
    );
    stage(&mut invalid, &mut more, key(&logical)?, Some(&bad_bytes))?;
    let second_manifest = fs::read(disk.manifest_path())?;
    assert!(disk.publish(&invalid, &signing, 3, false).is_err());
    assert_eq!(fs::read(disk.manifest_path())?, second_manifest);
    let still_committed = disk.reopen(Arc::clone(&signing), 2)?;
    assert_eq!(
        sharded_payload(&still_committed, &logical, 2)?.as_str(),
        second
    );

    // A header pointing to a missing shard has no publication authority.
    let mut missing = graph.clone();
    let future_header = sharded_index_cell(logical.clone(), 3)?;
    stage(
        &mut missing,
        &mut LocalObjects(BTreeMap::new()),
        key(&logical)?,
        Some(&future_header),
    )?;
    assert!(disk.publish(&missing, &signing, 3, false).is_err());

    // An unreferenced version object cannot be admitted into an
    // authenticated graph merely because its own envelope is valid.
    let mut orphan = graph.clone();
    let third_scope = sharded_version_scope(&logical, 3)?;
    let mut retained_third = serde_json::Map::new();
    retained_third.insert(
        "3".into(),
        json!({"data":{"payload":"unreferenced"},"destroyed":false}),
    );
    let third_bytes = encode(
        third_scope.clone(),
        3,
        json!({"current_version":3,"versions":Value::Object(retained_third)}),
    )?;
    stage(
        &mut orphan,
        &mut LocalObjects(BTreeMap::new()),
        key(&third_scope)?,
        Some(&third_bytes),
    )?;
    assert!(disk.publish(&orphan, &signing, 3, false).is_err());

    // The old acknowledged version is immutable across a later generation.
    let mut altered = graph.clone();
    let original_scope = sharded_version_scope(&logical, 1)?;
    let forged = encode(
        original_scope.clone(),
        1,
        json!({"current_version":1,"versions":{
            "1":{"data":{"payload":"forged-old-version"},"destroyed":false}
        }}),
    )?;
    stage(
        &mut altered,
        &mut LocalObjects(BTreeMap::new()),
        key(&original_scope)?,
        Some(&forged),
    )?;
    assert!(disk.publish(&altered, &signing, 3, false).is_err());
    assert_eq!(fs::read(disk.manifest_path())?, second_manifest);
    assert_eq!(
        sharded_payload(&disk.reopen(signing, 2)?, &logical, 1)?.as_str(),
        first
    );
    Ok(())
}

// The signed logical pointer must not contradict its referenced physical
// version record. This rejects a metadata-only disguise on a newly
// committed version, where prior-cell byte identity cannot yet fence it.
#[test]
fn kv2_v6_disk_trial_sharded_new_pointer_must_not_claim_destroyed()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let signing = private_trial_key(&AddressKey::from_bytes([0xc3; 32]))?;
    let logical = Scope {
        namespace: "tenant-r760-pointer".into(),
        mount: "secret/".into(),
        incarnation: 31,
        path: "ledger".into(),
    };
    let mut graph = Kv1Index::empty(Arc::clone(&signing));
    let mut objects = LocalObjects(BTreeMap::new());
    stage_sharded_version(&mut graph, &mut objects, &logical, 1, "original".into())?;
    disk.publish(&graph, &signing, 1, false)?;
    let known_root = fs::read(disk.manifest_path())?;

    stage_sharded_version(&mut graph, &mut objects, &logical, 2, "next".into())?;
    let index_key = key(&logical)?;
    let mut forged: Cell = serde_json::from_slice(graph.get(&index_key).ok_or("missing index")?)?;
    // The indexed version 2 says destroyed; the actual version-2
    // shard remains live. A canonical Cell is still rejected at decoding.
    forged.entry["versions"]["2"]["destroyed"] = json!(true);
    let bytes = serde_json::to_vec(&forged)?;
    assert!(
        decode(&index_key, &bytes).is_err(),
        "destroyed pointer retaining data must fail typed Cell decoding"
    );
    stage(&mut graph, &mut objects, index_key, Some(&bytes))?;
    assert!(
        disk.publish(&graph, &signing, 2, false).is_err(),
        "contradictory pointer must be denied before signed root"
    );
    assert_eq!(fs::read(disk.manifest_path())?, known_root);
    assert_eq!(
        sharded_payload(&disk.reopen(signing, 1)?, &logical, 1)?.as_str(),
        "original"
    );
    Ok(())
}

// An unrelated control-character reserved mount must not be accepted as an
// ordinary, unreferenced KV2 record just because it is not the exact
// private version-shard mount suffix.
#[test]
fn kv2_v6_disk_trial_sharded_unreferenced_reserved_mount_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let signing = private_trial_key(&AddressKey::from_bytes([0xc4; 32]))?;
    let shadow = Scope {
        namespace: "tenant-r760-orphan".into(),
        mount: format!("secret/{}shadow/", char::from(0x1f)),
        incarnation: 11,
        path: "forged".into(),
    };
    let raw = encode(
        shadow.clone(),
        1,
        json!({
           "current_version":1,
           "versions":{"1":{"data":{"payload":"unauthorized"},
                            "destroyed":false}}
        }),
    )?;
    let mut graph = Kv1Index::empty(Arc::clone(&signing));
    stage(
        &mut graph,
        &mut LocalObjects(BTreeMap::new()),
        key(&shadow)?,
        Some(&raw),
    )?;
    assert!(
        disk.publish(&graph, &signing, 1, false).is_err(),
        "unreferenced reserved mount must not be publishable"
    );
    assert!(!disk.manifest_path().exists());
    Ok(())
}

// An extra authenticated pointer field cannot confer a new interpretation
// of a version that physically lives in one immutable shard.
#[test]
fn kv2_v6_disk_trial_sharded_pointer_extra_data_must_be_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let signing = private_trial_key(&AddressKey::from_bytes([0xc5; 32]))?;
    let logical = Scope {
        namespace: "tenant-r760-pointer-alias".into(),
        mount: "secret/".into(),
        incarnation: 31,
        path: "ledger".into(),
    };
    let mut graph = Kv1Index::empty(Arc::clone(&signing));
    let mut objects = LocalObjects(BTreeMap::new());
    stage_sharded_version(&mut graph, &mut objects, &logical, 1, "original".into())?;
    disk.publish(&graph, &signing, 1, false)?;
    let previous_root = fs::read(disk.manifest_path())?;

    stage_sharded_version(&mut graph, &mut objects, &logical, 2, "new".into())?;
    let index_key = key(&logical)?;
    let mut forged: Cell = serde_json::from_slice(graph.get(&index_key).ok_or("missing header")?)?;
    forged.entry["versions"]["2"]["data"]["alias"] = json!("privileged-alternative-shard");
    let bytes = serde_json::to_vec(&forged)?;
    assert!(
        decode(&index_key, &bytes).is_ok(),
        "the test must reach shard closure with canonical Cell encoding"
    );
    stage(&mut graph, &mut objects, index_key, Some(&bytes))?;
    assert!(
        disk.publish(&graph, &signing, 2, false).is_err(),
        "unauthorized pointer data extension must fail"
    );
    assert_eq!(fs::read(disk.manifest_path())?, previous_root);
    assert_eq!(
        sharded_payload(&disk.reopen(signing, 1)?, &logical, 1)?.as_str(),
        "original"
    );
    Ok(())
}

// Canonical typed encoding is required here: converting the entire Cell
// through a generic JSON Value changes its outer field order and can make a
// rejection test pass before the shard-closure predicate is even reached.
#[test]
fn kv2_v6_disk_trial_canonical_shard_extra_data_rejected_by_closure()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = private_trial_key(&AddressKey::from_bytes([0xcf; 32]))?;
    let logical = Scope {
        namespace: "tenant-r780-canonical".into(),
        mount: "secret/".into(),
        incarnation: 52,
        path: "ledger".into(),
    };
    let mut graph = Kv1Index::empty(Arc::clone(&signer));
    let mut cache = LocalObjects(BTreeMap::new());
    stage_sharded_version(&mut graph, &mut cache, &logical, 1, "record".into())?;
    assert!(validate_sharded_trial_index(&graph).is_ok());
    let physical = key(&sharded_version_scope(&logical, 1)?)?;
    let mut cell: Cell =
        serde_json::from_slice(graph.get(&physical).ok_or("missing physical cell")?)?;
    cell.entry["versions"]["1"]["unauthorized_alias"] = json!(true);
    let raw = serde_json::to_vec(&cell)?;
    assert!(
        decode(&physical, &raw).is_ok(),
        "test must preserve canonical Cell encoding"
    );
    let mut changed = graph.clone();
    stage(
        &mut changed,
        &mut LocalObjects(BTreeMap::new()),
        physical,
        Some(&raw),
    )?;
    assert!(
        validate_sharded_trial_index(&changed).is_err(),
        "canonical physical shard gained an unauthorized version metadata field"
    );
    let index_key = key(&logical)?;
    for (kind, header) in [
        ("pointer-extra", {
            let mut cell: Cell =
                serde_json::from_slice(graph.get(&index_key).ok_or("missing logical index")?)?;
            cell.entry["versions"]["1"]["data"]["extra_acl_grant"] = json!(true);
            cell
        }),
        ("header-extra", {
            let mut cell: Cell =
                serde_json::from_slice(graph.get(&index_key).ok_or("missing logical index")?)?;
            cell.entry["alternate_index_authority"] = json!(true);
            cell
        }),
    ] {
        let raw = serde_json::to_vec(&header)?;
        assert!(
            decode(&index_key, &raw).is_ok(),
            "canonical {kind} test must reach the shard closure"
        );
        let mut candidate = graph.clone();
        stage(
            &mut candidate,
            &mut LocalObjects(BTreeMap::new()),
            index_key.clone(),
            Some(&raw),
        )?;
        assert!(
            validate_sharded_trial_index(&candidate).is_err(),
            "canonical {kind} field bypassed the closed V6 shard grammar"
        );
    }
    Ok(())
}

// A signed V6 graph may contain legacy sparse KV2 cells without a private
// shard_schema marker. Validation must not interpret an invalid *logical*
// namespace or path as an ordinary cell merely because no shard is referenced.
#[test]
fn kv2_v6_signed_trial_root_rejects_control_scope_without_shard_discriminator()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let signing = private_trial_key(&AddressKey::from_bytes([0xda; 32]))?;
    let valid = Scope {
        namespace: "tenant".into(),
        mount: "secret/".into(),
        incarnation: 91,
        path: "invoice".into(),
    };
    for (field, scope) in [
        (
            "namespace",
            Scope {
                namespace: "tenant\u{0002}".into(),
                ..valid.clone()
            },
        ),
        (
            "path",
            Scope {
                path: "invoice\u{0003}".into(),
                ..valid.clone()
            },
        ),
    ] {
        let mut graph = Kv1Index::empty(Arc::clone(&signing));
        let mut objects = LocalObjects(BTreeMap::new());
        let record_key = key(&scope)?;
        let cell = encode(
            scope,
            1,
            json!({"current_version":1,"versions":{
                "1":{"data":{"payload":"synthetic"},"destroyed":false}
            }}),
        )?;
        assert!(
            decode(&record_key, &cell).is_ok(),
            "the test must reach the graph validator, not fail JSON decoding"
        );
        stage(&mut graph, &mut objects, record_key, Some(&cell))?;
        assert!(
            validate_sharded_trial_index(&graph).is_err(),
            "unsigned logical control character in {field} bypassed V6 graph admission"
        );
        assert!(
            disk.publish(&graph, &signing, 1, false).is_err(),
            "invalid logical {field} must never publish a signed trial root"
        );
        assert!(
            !disk.manifest_path().exists(),
            "failed publication must leave no durable V6 root"
        );
    }
    Ok(())
}

// R1040: the next graph may itself be completely closed and authenticated,
// yet rewrite the previously acknowledged version-1 payload. Validate
// monotonicity against the *original* signed root, not just each graph alone.
#[test]
fn kv2_v6_signed_transition_refuses_rewrite_of_acknowledged_shard()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::kv2_v6_shard_validator::validate_immutable_transition;
    let disk = TrialDisk::fresh()?;
    let signing = private_trial_key(&AddressKey::from_bytes([0xdb; 32]))?;
    let logical = Scope {
        namespace: "tenant-r1040".into(),
        mount: "secret/".into(),
        incarnation: 1040,
        path: "retained-two-versions".into(),
    };
    let mut graph = Kv1Index::empty(Arc::clone(&signing));
    let mut objects = LocalObjects(BTreeMap::new());
    let first = "A".repeat(2560 * 1024);
    let second = "B".repeat(2560 * 1024);
    stage_sharded_version(&mut graph, &mut objects, &logical, 1, first.clone())?;
    disk.publish(&graph, &signing, 1, false)?;
    let previous = disk.reopen(Arc::clone(&signing), 1)?;
    stage_sharded_version(&mut graph, &mut objects, &logical, 2, second.clone())?;
    disk.publish(&graph, &signing, 2, false)?;
    let current = disk.reopen(Arc::clone(&signing), 2)?;
    assert!(validate_immutable_transition(&previous, &current).is_ok());

    let old_scope = sharded_version_scope(&logical, 1)?;
    let forged = encode(
        old_scope.clone(),
        1,
        json!({"current_version":1, "versions":{
            "1":{"data":{"payload":"changed-after-ack"},"destroyed":false}
        }}),
    )?;
    let mut changed = current.clone();
    stage(
        &mut changed,
        &mut LocalObjects(BTreeMap::new()),
        key(&old_scope)?,
        Some(&forged),
    )?;
    assert!(
        validate_sharded_trial_index(&changed).is_ok(),
        "red test must reach monotonic predecessor comparison"
    );
    assert!(
        validate_immutable_transition(&previous, &changed).is_err(),
        "valid-looking changed shard must not rewrite an acknowledged version"
    );
    assert_eq!(sharded_payload(&current, &logical, 1)?.as_str(), first);
    assert_eq!(sharded_payload(&current, &logical, 2)?.as_str(), second);
    Ok(())
}

// A MAC-valid predecessor root is insufficient to authorize publication
// if its logical shard pointer never resolved to a physical version. A new
// candidate must not launder this invalid predecessor by silently adding
// missing shards. The rejection must precede ALL candidate object staging.
#[test]
fn kv2_v6_disk_trial_rejects_signed_but_unclosed_predecessor_before_staging()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let signing = private_trial_key(&AddressKey::from_bytes([0xe5; 32]))?;
    let logical = Scope {
        namespace: "tenant-r1050".into(),
        mount: "secret/".into(),
        incarnation: 1050,
        path: "predecessor-incomplete".into(),
    };
    let logical_key = key(&logical)?;
    let logical_cell = sharded_index_cell(logical.clone(), 1)?;
    let mut incomplete = Kv1Index::empty(Arc::clone(&signing));
    let mut pending = LocalObjects(BTreeMap::new());
    stage(
        &mut incomplete,
        &mut pending,
        logical_key.clone(),
        Some(&logical_cell),
    )?;
    assert!(validate_sharded_trial_index(&incomplete).is_err());
    disk.persist_objects(&incomplete)?;

    // A synthetic privileged signer commits a correctly MAC-bound generation
    // with a missing shard. This root authenticates, but never passed the
    // independent V6 closure reader and must not become predecessor authority.
    let payload = TrialPayload {
        format: TRIAL_FORMAT.into(),
        cluster: "synthetic-r310".into(),
        epoch: 7,
        generation: 1,
        root: incomplete.root(),
    };
    let mac = signing.digest(ROOT_DOMAIN, &serde_json::to_vec(&payload)?)?;
    let envelope = TrialRootEnvelope { payload, mac };
    fs::write(disk.manifest_path(), serde_json::to_vec(&envelope)?)?;
    assert!(disk.authenticated_root(&signing).is_ok());
    assert!(disk.reopen(Arc::clone(&signing), 1).is_err());

    // The new graph itself is fully closed, with the exact same logical
    // pointer plus the previously absent physical version.
    let mut next = incomplete.clone();
    let mut objects = LocalObjects(BTreeMap::new());
    stage_sharded_version(&mut next, &mut objects, &logical, 1, "new-version".into())?;
    assert_eq!(next.get(&logical_key), incomplete.get(&logical_key));
    assert!(validate_sharded_trial_index(&next).is_ok());
    let frozen_manifest = fs::read(disk.manifest_path())?;
    let frozen_objects = fs::read_dir(disk.dir.join("objects"))?.count();

    assert!(
        disk.publish(&next, &signing, 2, false).is_err(),
        "the next signed root must not repair an unclosed prior authority"
    );
    assert_eq!(fs::read(disk.manifest_path())?, frozen_manifest);
    assert_eq!(
        fs::read_dir(disk.dir.join("objects"))?.count(),
        frozen_objects,
        "refused predecessor must not even stage new physical shards"
    );
    Ok(())
}

// R1090: the real lossless KV2 bridge preserves destroyed versions and
// per-version timestamps. A V6 indexed graph must prove their safe read
// representation; an all-live-payload-only validator cannot migrate it.
#[test]
fn r1090_signed_v6_shards_accept_real_tombstone_and_timestamp()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let signing = private_trial_key(&AddressKey::from_bytes([0xf1; 32]))?;
    let logical = Scope {
        namespace: "tenant-r1090".into(),
        mount: "secret/".into(),
        incarnation: 1090,
        path: "retained-deleted-and-live".into(),
    };
    let mut graph = Kv1Index::empty(Arc::clone(&signing));
    let mut objects = LocalObjects(BTreeMap::new());

    let gone = sharded_version_scope(&logical, 1)?;
    let gone_cell = encode(
        gone.clone(),
        1,
        json!({"current_version":1,"versions":{"1":{
            "data":null,"destroyed":true,
            "created_time":"2026-10-12T09:00:00.123456789Z",
            "deletion_time":""
        }}}),
    )?;
    assert!(decode(&key(&gone)?, &gone_cell).is_ok());
    stage(&mut graph, &mut objects, key(&gone)?, Some(&gone_cell))?;

    let retained = sharded_version_scope(&logical, 2)?;
    let retained_cell = encode(
        retained.clone(),
        2,
        json!({"current_version":2,"versions":{"2":{
            "data":{"payload":"retained-after-soft-deletion"},
            "destroyed":false,
            "created_time":"2026-10-12T09:00:01.000000001Z",
            "deletion_time":"2026-10-13T10:00:00+09:00",
            "source_deletion_time":"2026-10-14T10:00:00+09:00"
        }}}),
    )?;
    assert!(decode(&key(&retained)?, &retained_cell).is_ok());
    stage(
        &mut graph,
        &mut objects,
        key(&retained)?,
        Some(&retained_cell),
    )?;
    let index = sharded_index_cell(logical.clone(), 2)?;
    stage(&mut graph, &mut objects, key(&logical)?, Some(&index))?;

    assert!(
        validate_sharded_trial_index(&graph).is_ok(),
        "the closed version-shard validator must admit typed KV2 tombstones and timestamps"
    );
    disk.publish(&graph, &signing, 1, false)?;
    let reopened = disk.reopen(signing, 1)?;
    assert!(sharded_payload(&reopened, &logical, 1).is_err());
    assert_eq!(
        sharded_payload(&reopened, &logical, 2)?.as_str(),
        "retained-after-soft-deletion"
    );
    Ok(())
}

// Source deletion times are historical replay data, not an arbitrary
// authorization channel. Reject malformed times before a signed root, and
// refuse extra fields despite their valid canonical JSON representation.
#[test]
fn r1090_source_deletion_time_type_and_unknown_authority_are_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let scope = sharded_version_scope(
        &Scope {
            namespace: "tenant-r1090-negative".into(),
            mount: "secret/".into(),
            incarnation: 1090,
            path: "strict-history".into(),
        },
        1,
    )?;
    let record_key = key(&scope)?;
    for invalid in [
        json!(42),
        json!("yesterday"),
        json!({"timestamp":"2026-10-12T09:00:00Z"}),
    ] {
        let version_cell = encode(
            scope.clone(),
            1,
            json!({"current_version":1,"versions":{"1":{
                "data":{"payload":"known"},"destroyed":false,
                "source_deletion_time":invalid
            }}}),
        )?;
        assert!(
            decode(&record_key, &version_cell).is_err(),
            "malformed historical source deletion time reached an authenticated record"
        );
    }
    let valid = encode(
        scope.clone(),
        1,
        json!({"current_version":1,"versions":{"1":{
            "data":{"payload":"known"},"destroyed":false,
            "source_deletion_time":"2026-10-14T10:00:00+09:00",
            "permission_override":"owner"
        }}}),
    )?;
    assert!(decode(&record_key, &valid).is_ok());
    // The outer codec accepts historical extensions, but the private shard
    // signed-graph grammar must not authorize arbitrary extension metadata.
    let logical = Scope {
        namespace: "tenant-r1090-negative".into(),
        mount: "secret/".into(),
        incarnation: 1090,
        path: "strict-history".into(),
    };
    let mut graph = Kv1Index::empty(private_trial_key(&AddressKey::from_bytes([0xf2; 32]))?);
    let mut objects = LocalObjects(BTreeMap::new());
    stage(&mut graph, &mut objects, record_key, Some(&valid))?;
    let indexed = sharded_index_cell(logical.clone(), 1)?;
    stage(&mut graph, &mut objects, key(&logical)?, Some(&indexed))?;
    assert!(
        validate_sharded_trial_index(&graph).is_err(),
        "unknown shard metadata acquired signed-root authority"
    );
    Ok(())
}

// A valid lossless OpenBao KV2 owner may have oldest_version > 1 after
// authorized historical retirement. The *initial* private shard graph must
// permit a closed retained suffix while rejecting a hole in that suffix.
#[test]
fn r1090_signed_v6_shards_accept_contiguous_retained_suffix()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let signing = private_trial_key(&AddressKey::from_bytes([0xf3; 32]))?;
    let logical = Scope {
        namespace: "tenant-r1090-suffix".into(),
        mount: "secret/".into(),
        incarnation: 1090,
        path: "oldest-version-2".into(),
    };
    let mut graph = Kv1Index::empty(Arc::clone(&signing));
    let mut objects = LocalObjects(BTreeMap::new());
    for (version, payload) in [(2_u64, "retained-two"), (3, "retained-three")] {
        let physical = sharded_version_scope(&logical, version)?;
        let mut single = serde_json::Map::new();
        single.insert(
            version.to_string(),
            json!({"data":{"payload":payload},"destroyed":false}),
        );
        let cell = encode(
            physical.clone(),
            version,
            json!({"current_version":version,"versions":Value::Object(single)}),
        )?;
        stage(&mut graph, &mut objects, key(&physical)?, Some(&cell))?;
    }
    let index_key = key(&logical)?;
    let mut index: Cell = serde_json::from_slice(&sharded_index_cell(logical.clone(), 3)?)?;
    index.entry["versions"]
        .as_object_mut()
        .ok_or("index versions")?
        .remove("1");
    let index_bytes = serde_json::to_vec(&index)?;
    assert!(decode(&index_key, &index_bytes).is_ok());
    stage(
        &mut graph,
        &mut objects,
        index_key.clone(),
        Some(&index_bytes),
    )?;

    assert!(
        validate_sharded_trial_index(&graph).is_ok(),
        "lossless KV2 history oldest_version=2/current_version=3 is valid"
    );
    disk.publish(&graph, &signing, 1, false)?;
    let original = disk.reopen(Arc::clone(&signing), 1)?;
    assert_eq!(
        sharded_payload(&original, &logical, 3)?.as_str(),
        "retained-three"
    );
    assert!(sharded_payload(&original, &logical, 1).is_err());

    let mut hole: Cell = serde_json::from_slice(&index_bytes)?;
    let entries = hole.entry["versions"]
        .as_object_mut()
        .ok_or("hole versions")?;
    entries.remove("2");
    entries.insert(
        "1".into(),
        json!({"data":{"shard_path":sharded_version_scope(&logical, 1)?.path},
               "destroyed":false}),
    );
    let damaged = serde_json::to_vec(&hole)?;
    assert!(decode(&index_key, &damaged).is_ok());
    let mut rejected = graph.clone();
    stage(
        &mut rejected,
        &mut LocalObjects(BTreeMap::new()),
        index_key,
        Some(&damaged),
    )?;
    assert!(
        validate_sharded_trial_index(&rejected).is_err(),
        "a hole between retained version pointers must never look like retirement"
    );
    Ok(())
}

// R1100: migrate genuine KV2 JSON objects, not merely the synthetic
// one-string payload shape. Signed historical versions must retain data
// exactly, while the typed codec still refuses array/scalar data roots.
#[test]
fn r1100_signed_shards_preserve_arbitrary_kv2_json_object_versions()
-> Result<(), Box<dyn std::error::Error>> {
    let disk = TrialDisk::fresh()?;
    let signing = private_trial_key(&AddressKey::from_bytes([0xa1; 32]))?;
    let logical = Scope {
        namespace: "tenant-r1100".into(),
        mount: "secret/".into(),
        incarnation: 1100,
        path: "user-defined-complex-json".into(),
    };
    let first = json!({
        "enabled": true,
        "retry_count": 0,
        "unauthorized_alias": true,
        "large_integer": 9_007_199_254_740_993_u64,
        "tags": ["🚀", false, null, 7],
        "nested": {"array": [1, {"name": "HeptaBao"}, []], "empty": {}}
    });
    let second = json!({
        "enabled": false,
        "ratio": 1.25,
        "numbers": [-4, 0, 9_007_199_254_740_993_u64],
        "records": [{"id": 1, "ok": true}, {"id": 2, "ok": false}],
        "nullable": null
    });
    let mut graph = Kv1Index::empty(Arc::clone(&signing));
    let mut objects = LocalObjects(BTreeMap::new());
    for (version, payload) in [(1_u64, first.clone()), (2_u64, second.clone())] {
        let scope = sharded_version_scope(&logical, version)?;
        let mut versions = serde_json::Map::new();
        versions.insert(
            version.to_string(),
            json!({
                "data": payload,
                "destroyed": false,
                "created_time": "2026-10-13T00:00:00.000000001Z",
                "deletion_time": ""
            }),
        );
        let bytes = encode(
            scope.clone(),
            version,
            json!({"current_version":version,"versions":Value::Object(versions)}),
        )?;
        assert!(decode(&key(&scope)?, &bytes).is_ok());
        stage(&mut graph, &mut objects, key(&scope)?, Some(&bytes))?;
    }
    let index = sharded_index_cell(logical.clone(), 2)?;
    stage(&mut graph, &mut objects, key(&logical)?, Some(&index))?;
    assert!(
        validate_sharded_trial_index(&graph).is_ok(),
        "genuine KV2 objects must be accepted, not only synthetic payload strings"
    );
    disk.publish(&graph, &signing, 1, false)?;
    let reopened = disk.reopen(signing, 1)?;
    for (version, expected) in [(1_u64, first), (2_u64, second)] {
        let physical = sharded_version_scope(&logical, version)?;
        let address = key(&physical)?;
        let decoded = decode(&address, reopened.get(&address).ok_or("missing V6 shard")?)?;
        assert_eq!(
            decoded.entry["versions"][version.to_string()]["data"],
            expected,
            "historical user KV2 JSON changed after signed-root reopen"
        );
    }
    let invalid_scope = sharded_version_scope(&logical, 1)?;
    let array = encode(
        invalid_scope.clone(),
        1,
        json!({"current_version":1,"versions":{"1":{
            "data":["not","a","kv2","object"],"destroyed":false
        }}}),
    )?;
    assert!(decode(&key(&invalid_scope)?, &array).is_err());
    Ok(())
}

// R1120 isolated pre-admission test. V1 must keep its historical <=32
// version grammar; a distinct V2 signed discriminator can describe a high
// *absolute* version with only one retained physical shard.
#[test]
fn r1120_v2_high_absolute_version_shards_have_separate_signed_authority()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::kv2_v6_shard_validator::{SHARD_INDEX_SCHEMA_V2, sharded_version_scope_v2};
    for version in [33_u64, 10_001, i64::MAX as u64] {
        let disk = TrialDisk::fresh()?;
        let signing = private_trial_key(&AddressKey::from_bytes([0xb6; 32]))?;
        let logical = Scope {
            namespace: "r1120".into(),
            mount: "secret/".into(),
            incarnation: 1120,
            path: format!("v{version}"),
        };
        assert!(sharded_version_scope(&logical, 33).is_err());
        assert!(sharded_version_scope_v2(&logical, i64::MAX as u64 + 1).is_err());
        let physical = sharded_version_scope_v2(&logical, version)?;
        let mut graph = Kv1Index::empty(Arc::clone(&signing));
        let mut objects = LocalObjects(BTreeMap::new());
        let mut history = serde_json::Map::new();
        history.insert(
            version.to_string(),
            json!({"data":{"value":version},"destroyed":false}),
        );
        let version_bytes = encode(
            physical.clone(),
            version,
            json!({"current_version":version,"versions":Value::Object(history)}),
        )?;
        stage(
            &mut graph,
            &mut objects,
            key(&physical)?,
            Some(&version_bytes),
        )?;
        let mut pointers = serde_json::Map::new();
        pointers.insert(
            version.to_string(),
            json!({
                "data":{"shard_path":physical.path},"destroyed":false
            }),
        );
        let index_bytes = encode(
            logical.clone(),
            version,
            json!({
                "shard_schema":SHARD_INDEX_SCHEMA_V2,
                "current_version":version,
                "versions":Value::Object(pointers)
            }),
        )?;
        let index_key = key(&logical)?;
        stage(
            &mut graph,
            &mut objects,
            index_key.clone(),
            Some(&index_bytes),
        )?;
        assert!(validate_sharded_trial_index(&graph).is_ok());
        disk.publish(&graph, &signing, 1, false)?;
        let reopened = disk.reopen(Arc::clone(&signing), 1)?;
        assert_eq!(
            reopened.get(&key(&physical)?),
            Some(version_bytes.as_slice())
        );
        let cell = decode(
            &key(&physical)?,
            reopened.get(&key(&physical)?).ok_or("missing V2 shard")?,
        )?;
        assert_eq!(
            cell.entry["versions"][version.to_string()]["data"]["value"].as_u64(),
            Some(version)
        );
        // Alter only the discriminator, not the underlying authenticated
        // graph. The historical V1 parser must still reject version >32.
        let mut forged: Cell = serde_json::from_slice(&index_bytes)?;
        forged.entry["shard_schema"] = json!(SHARD_INDEX_SCHEMA);
        let forged_bytes = serde_json::to_vec(&forged)?;
        let mut invalid = graph.clone();
        stage(
            &mut invalid,
            &mut LocalObjects(BTreeMap::new()),
            index_key,
            Some(&forged_bytes),
        )?;
        assert!(validate_sharded_trial_index(&invalid).is_err());
    }
    Ok(())
}

// Independent negative V2 closure: a digest-valid physical version has no
// authority by itself, a retargeted pointer cannot authorize it, and signed
// metadata cannot acquire an unrecognized policy/retirement flag.
#[test]
fn r1120_v2_dangling_or_retargeted_shard_remains_unpublishable()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::kv2_v6_shard_validator::{SHARD_INDEX_SCHEMA_V2, sharded_version_scope_v2};
    let disk = TrialDisk::fresh()?;
    let signing = private_trial_key(&AddressKey::from_bytes([0xb7; 32]))?;
    let logical = Scope {
        namespace: "tenant-r1120-closed".into(),
        mount: "secret/".into(),
        incarnation: 33,
        path: "ledger".into(),
    };
    let version = 33_u64;
    let physical = sharded_version_scope_v2(&logical, version)?;
    let mut entries = serde_json::Map::new();
    entries.insert(
        version.to_string(),
        json!({"data":{"payload":"unchanged"},"destroyed":false}),
    );
    let cell = encode(
        physical.clone(),
        version,
        json!({"current_version":version,"versions":Value::Object(entries)}),
    )?;
    let mut graph = Kv1Index::empty(Arc::clone(&signing));
    let mut objects = LocalObjects(BTreeMap::new());
    stage(&mut graph, &mut objects, key(&physical)?, Some(&cell))?;
    assert!(validate_sharded_trial_index(&graph).is_err());
    assert!(disk.publish(&graph, &signing, 1, false).is_err());
    assert!(!disk.manifest_path().exists());
    let index_key = key(&logical)?;
    let mut pointers = serde_json::Map::new();
    pointers.insert(
        "33".into(),
        json!({"data":{"shard_path":"invalid/00000000000000000033"},
                "destroyed":false}),
    );
    let wrong = encode(
        logical.clone(),
        version,
        json!({
            "shard_schema":SHARD_INDEX_SCHEMA_V2,
            "current_version":version, "versions":Value::Object(pointers)
        }),
    )?;
    stage(&mut graph, &mut objects, index_key.clone(), Some(&wrong))?;
    assert!(validate_sharded_trial_index(&graph).is_err());
    assert!(disk.publish(&graph, &signing, 1, false).is_err());
    assert!(!disk.manifest_path().exists());
    let mut fixed: Cell = serde_json::from_slice(&wrong)?;
    fixed.entry["versions"]["33"]["data"]["shard_path"] = json!(physical.path);
    let valid = serde_json::to_vec(&fixed)?;
    stage(&mut graph, &mut objects, index_key.clone(), Some(&valid))?;
    assert!(validate_sharded_trial_index(&graph).is_ok());
    disk.publish(&graph, &signing, 1, false)?;
    let frozen = fs::read(disk.manifest_path())?;
    fixed.entry["authority_extension"] = json!({"allow_retirement":true});
    let unauthorized = serde_json::to_vec(&fixed)?;
    let mut altered = graph.clone();
    stage(
        &mut altered,
        &mut LocalObjects(BTreeMap::new()),
        index_key,
        Some(&unauthorized),
    )?;
    assert!(validate_sharded_trial_index(&altered).is_err());
    assert!(disk.publish(&altered, &signing, 2, false).is_err());
    assert_eq!(fs::read(disk.manifest_path())?, frozen);
    let reopened = disk.reopen(signing, 1)?;
    assert_eq!(reopened.get(&key(&physical)?), Some(cell.as_slice()));
    Ok(())
}
