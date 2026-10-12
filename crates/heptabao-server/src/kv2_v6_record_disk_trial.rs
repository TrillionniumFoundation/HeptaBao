//! Isolated, synthetic, disk-backed V6 design trial: never a production writer.
//! Proves durable immutable objects, authenticated trial-root publication,
//! crash-before-root invisibility, pins, and corruption rejection.
use super::*;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
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
}
impl TrialDisk {
    fn fresh() -> Result<Self, Box<dyn std::error::Error>> {
        let id = NEXT_TRIAL.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "heptabao-kv2-v6-private-staging-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        fs::create_dir(dir.join("objects"))?;
        Ok(Self { dir })
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
    // Pin the actual private objects-directory descriptor. A no-follow leaf
    // by itself cannot prevent an ancestor-directory symlink redirection.
    #[cfg(unix)]
    fn open_objects_dir(&self) -> Result<File, RecordError> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let directory = options
            .open(self.dir.join("objects"))
            .map_err(|_| RecordError::Corrupt)?;
        if !directory
            .metadata()
            .map_err(|_| RecordError::Corrupt)?
            .is_dir()
        {
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
        if !file.metadata().map_err(|_| RecordError::Corrupt)?.is_file() {
            return Err(RecordError::Corrupt);
        }
        Ok(file)
    }

    #[cfg(unix)]
    fn persist_objects(&self, graph: &Kv1Index) -> Result<(), RecordError> {
        let directory = self.open_objects_dir()?;
        graph.visit_objects(|object| {
            let identity = &object.reference().id;
            match self.open_object_at(&directory, identity, false) {
                Ok(source) => {
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
                }
                Err(RecordError::Missing) => {
                    let mut file = self.open_object_at(&directory, identity, true)?;
                    file.write_all(object.bytes())
                        .and_then(|()| file.sync_all())
                        .map_err(|_| RecordError::Corrupt)?;
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
        let staged = self.dir.join("root.json.staged");
        let mut writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)
            .map_err(|_| RecordError::Corrupt)?;
        writer
            .write_all(&manifest)
            .and_then(|()| writer.sync_all())
            .map_err(|_| RecordError::Corrupt)?;
        drop(writer);
        fs::rename(staged, self.manifest_path()).map_err(|_| RecordError::Corrupt)?;
        File::open(&self.dir)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| RecordError::Corrupt)
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
