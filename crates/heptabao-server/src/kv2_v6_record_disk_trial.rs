//! Isolated, synthetic, disk-backed V6 design trial: never a production writer.
//! Proves durable immutable objects, authenticated trial-root publication,
//! crash-before-root invisibility, pins, and corruption rejection.
use super::*;
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
        let mut source = {
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
        let mut source = Self::open_private_regular(&self.manifest_path())?;
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

    fn published_generation(&self, key: &Arc<AddressKey>) -> Result<Option<u64>, RecordError> {
        match fs::symlink_metadata(self.manifest_path()) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    return Err(RecordError::Corrupt);
                }
                let previous = self.authenticated_root(key)?;
                // The signed manifest alone is not enough: a corrupted
                // referenced object must never be silently superseded.
                Kv1Index::open(Arc::clone(key), previous.payload.root, self)?;
                Ok(Some(previous.payload.generation))
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
        let valid_next = match self.published_generation(key)? {
            None => generation == 1,
            Some(previous) => previous.checked_add(1) == Some(generation),
        };
        if !valid_next {
            return Err(RecordError::Invalid);
        }
        self.persist_objects(graph)?;
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
        Kv1Index::open(key, envelope.payload.root, self)
    }
}
impl RecordReader for TrialDisk {
    fn read_object(&self, reference: &ObjectRef) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        #[cfg(unix)]
        let mut source = {
            let directory = self.open_objects_dir()?;
            self.open_object_at(&directory, &reference.id, false)?
        };
        #[cfg(not(unix))]
        let mut source = TrialDisk::open_private_regular(&self.object_path(&reference.id))?;
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
impl Drop for TrialDisk {
    fn drop(&mut self) {
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
    assert!(
        disk.persist_objects(&graph).is_err(),
        "valid bytes behind a symlinked parent must never be reused"
    );
    assert!(
        disk.reopen(address, 1).is_err(),
        "published graph must not read ordinary leaves through a symlinked parent"
    );
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
