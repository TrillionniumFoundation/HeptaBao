//! Crash-recoverable rotation of the authenticated JSONL audit stream.
//! The active inode/legacy writer lock remain stable. Sidecars are accessed
//! through an opened directory and obsolete segments require authenticated receipts.
use super::{check_private_file, verify_audit_from};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::{digest, hmac};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};
const MAX_SEGMENT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 128 * 1024;
const STAGING_MAGIC: &[u8] = b"heptabao-audit-manifest-staging-v1\n";
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    pub segment_bytes: u64,
    pub retained_segments: usize,
}
impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            segment_bytes: MAX_SEGMENT_BYTES,
            retained_segments: 8,
        }
    }
}
impl AuditConfig {
    fn validate(self) -> io::Result<Self> {
        if !(4096..=MAX_SEGMENT_BYTES).contains(&self.segment_bytes)
            || !(1..=64).contains(&self.retained_segments)
        {
            return Err(invalid("invalid audit rotation/retention bounds"));
        }
        Ok(self)
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frontier {
    sequence: u64,
    mac: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Segment {
    id: u64,
    length: u64,
    digest: [u8; 32],
    start: Frontier,
    end: Frontier,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    generation: u64,
    base: Frontier,
    segments: Vec<Segment>,
    pending: Option<Segment>,
    garbage: Vec<Segment>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedManifest {
    manifest: Manifest,
    mac: String,
}
pub(super) struct AuditRotation {
    directory: File,
    access: PathBuf,
    name: String,
    _writer: File,
    config: AuditConfig,
    manifest: Manifest,
    manifest_exists: bool,
    #[cfg(test)]
    fault: Option<&'static str>,
}
impl AuditRotation {
    pub(super) fn open(path: &Path, config: AuditConfig) -> io::Result<(Self, File)> {
        let config = config.validate()?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| {
                !n.is_empty()
                    && n.len() <= 128
                    && n.is_ascii()
                    && n.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
            .ok_or_else(|| invalid("invalid audit filename"))?
            .to_owned();
        let directory = open_directory(
            path.parent()
                .ok_or_else(|| invalid("invalid audit parent"))?,
        )?;
        let access = descriptor_path(&directory)?;
        let writer = private_options(true)
            .create(true)
            .read(true)
            .write(true)
            .open(access.join(format!("{name}.rotation-lock")))?;
        check_private_file(&writer)?;
        lock_writer(&writer)?;
        let active_path = access.join(&name);
        let audit = match private_options(false)
            .append(true)
            .read(true)
            .open(&active_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // The active inode is never removed by rotation. Its absence
                // beside an established key/checkpoint is data loss, not a new log.
                if fs::symlink_metadata(access.join(format!("{name}.hmac-key"))).is_ok()
                    || fs::symlink_metadata(access.join(format!("{name}.rotation.json"))).is_ok()
                {
                    return Err(invalid("established audit activity file is missing"));
                }
                private_options(true)
                    .create_new(true)
                    .append(true)
                    .read(true)
                    .open(&active_path)?
            }
            Err(error) => return Err(error),
        };
        check_private_file(&audit)?;
        if fs::symlink_metadata(access.join(format!("{name}.rotation.json"))).is_ok()
            && fs::symlink_metadata(access.join(format!("{name}.hmac-key"))).is_err()
        {
            return Err(invalid("audit checkpoint has no authentication key"));
        }
        lock_writer(&audit)?;
        directory.sync_all()?;
        Ok((
            Self {
                directory,
                access,
                name,
                _writer: writer,
                config,
                manifest: Manifest {
                    schema: 1,
                    ..Manifest::default()
                },
                manifest_exists: false,
                #[cfg(test)]
                fault: None,
            },
            audit,
        ))
    }
    pub(super) fn active_path(&self) -> PathBuf {
        self.access.join(&self.name)
    }
    fn sidecar(&self, suffix: &str) -> PathBuf {
        self.access.join(format!("{}.{suffix}", self.name))
    }
    fn segment_path(&self, id: u64) -> PathBuf {
        self.sidecar(&format!("segment-{id:020}.jsonl"))
    }
    fn active_start(&self) -> Frontier {
        self.manifest
            .segments
            .last()
            .map_or(self.manifest.base, |s| s.end)
    }
    pub(super) fn recover(
        &mut self,
        audit: &mut File,
        key: &hmac::Key,
    ) -> io::Result<(u64, [u8; 32])> {
        self.verify_active_identity(audit)?;
        match open_read(&self.sidecar("rotation.json")) {
            Ok(mut file) => {
                self.manifest = decode_manifest(&mut file, key)?;
                self.manifest_exists = true;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        self.verify_manifest(key)?;
        self.discard_staging()?;
        if let Some(segment) = self.manifest.pending.clone() {
            let bytes = read_bounded(audit, MAX_SEGMENT_BYTES)?;
            if !bytes.is_empty() {
                if bytes.len() as u64 != segment.length || sha256(&bytes) != segment.digest {
                    return Err(invalid("pending audit rotation does not match active file"));
                }
                audit.set_len(0)?;
                audit.sync_all()?;
            }
            let mut complete = self.manifest.clone();
            complete.pending = None;
            self.publish(complete, key)?;
        }
        self.collect_garbage(key)?;
        let start = self.active_start();
        let frontier = verify_audit_from(audit, key, start.sequence, start.mac).map_err(invalid)?;
        self.verify_archive_inventory(audit)?;
        Ok(frontier)
    }
    pub(super) fn before_append(
        &mut self,
        audit: &mut File,
        key: &hmac::Key,
        added: usize,
        sequence: u64,
        previous: [u8; 32],
    ) -> io::Result<()> {
        self.verify_active_identity(audit)?;
        let length = audit.metadata()?.len();
        if added as u64 > self.config.segment_bytes {
            return Err(invalid("single audit record exceeds segment capacity"));
        }
        if length
            .checked_add(added as u64)
            .is_some_and(|n| n <= self.config.segment_bytes)
        {
            return Ok(());
        }
        self.rotate(
            audit,
            key,
            Frontier {
                sequence,
                mac: previous,
            },
        )
    }
    fn rotate(&mut self, audit: &mut File, key: &hmac::Key, end: Frontier) -> io::Result<()> {
        self.verify_active_identity(audit)?;
        self.collect_garbage(key)?;
        let start = self.active_start();
        let observed = verify_audit_from(audit, key, start.sequence, start.mac).map_err(invalid)?;
        if observed != (end.sequence, end.mac) || end.sequence <= start.sequence {
            return Err(invalid(
                "audit rotation frontier disagrees with active chain",
            ));
        }
        let bytes = read_bounded(audit, MAX_SEGMENT_BYTES)?;
        let id = self
            .manifest
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("audit generation exhausted"))?;
        let segment = Segment {
            id,
            length: bytes.len() as u64,
            digest: sha256(&bytes),
            start,
            end,
        };
        let path = self.segment_path(id);
        match private_options(true)
            .create_new(true)
            .write(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(&bytes)?;
                file.sync_all()?;
                self.directory.sync_all()?;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // Resume only an exact prefix of the independently authenticated
                // active stream. Arbitrary occupants are never deleted/overwritten.
                let mut file = private_options(false).read(true).append(true).open(&path)?;
                check_private_file(&file)?;
                let prefix = read_bounded(&mut file, MAX_SEGMENT_BYTES)?;
                if !bytes.starts_with(&prefix) {
                    return Err(invalid("unrecognized audit archive occupant"));
                }
                file.write_all(&bytes[prefix.len()..])?;
                file.sync_all()?;
                self.directory.sync_all()?;
            }
            Err(e) => return Err(e),
        }
        self.crash_point("archive")?;
        let mut pending = self.manifest.clone();
        pending.generation = id;
        pending.segments.push(segment.clone());
        pending.pending = Some(segment);
        while pending.segments.len() > self.config.retained_segments {
            let old = pending.segments.remove(0);
            pending.base = old.end;
            pending.garbage.push(old);
        }
        self.publish(pending, key)?;
        self.crash_point("pending")?;
        audit.set_len(0)?;
        audit.sync_all()?;
        self.crash_point("truncated")?;
        let mut complete = self.manifest.clone();
        complete.pending = None;
        self.publish(complete, key)?;
        self.crash_point("complete")?;
        self.collect_garbage(key)
    }
    fn verify_archive_inventory(&self, audit: &mut File) -> io::Result<()> {
        let prefix = format!("{}.segment-", self.name);
        let next = self
            .manifest
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("audit generation exhausted"))?;
        for entry in fs::read_dir(&self.access)? {
            let entry = entry?;
            if !entry.file_name().to_string_lossy().starts_with(&prefix) {
                continue;
            }
            let path = entry.path();
            if self
                .manifest
                .segments
                .iter()
                .any(|segment| path == self.segment_path(segment.id))
            {
                continue;
            }
            // Only an interrupted archive of the next generation can legitimately
            // exist outside the signed checkpoint. It must be an exact prefix of
            // the current, already authenticated active stream, including empty
            // create-new files left by interruption before the first copy write.
            if path != self.segment_path(next) {
                return Err(invalid("unexplained audit archive generation"));
            }
            let bytes = read_bounded(audit, MAX_SEGMENT_BYTES)?;
            let mut orphan = open_read(&path)?;
            let copied = read_bounded(&mut orphan, MAX_SEGMENT_BYTES)?;
            if bytes.is_empty() || !bytes.starts_with(&copied) {
                return Err(invalid("unexplained audit archive content"));
            }
        }
        Ok(())
    }
    fn verify_manifest(&self, key: &hmac::Key) -> io::Result<()> {
        let m = &self.manifest;
        if m.schema != 1
            || m.segments.len() > 64
            || m.garbage.len() > 64
            || m.segments.is_empty() != (m.generation == 0)
            || m.pending
                .as_ref()
                .is_some_and(|p| m.segments.last() != Some(p))
        {
            return Err(invalid("invalid audit manifest structure"));
        }
        let mut frontier = m.base;
        let mut id = 0;
        for segment in &m.segments {
            if segment.id <= id
                || segment.id > m.generation
                || segment.start != frontier
                || segment.end.sequence <= segment.start.sequence
                || segment.length == 0
                || segment.length > MAX_SEGMENT_BYTES
            {
                return Err(invalid("inconsistent audit segment chain"));
            }
            self.verify_segment(segment, key)?;
            frontier = segment.end;
            id = segment.id;
        }
        if !m.segments.is_empty() && id != m.generation {
            return Err(invalid("missing latest audit segment"));
        }
        for segment in &m.garbage {
            if segment.id >= m.segments.first().map_or(0, |s| s.id)
                || segment.end.sequence > m.base.sequence
            {
                return Err(invalid("invalid obsolete audit segment"));
            }
        }
        Ok(())
    }
    fn verify_segment(&self, segment: &Segment, key: &hmac::Key) -> io::Result<()> {
        let mut file = open_read(&self.segment_path(segment.id))?;
        let bytes = read_bounded(&mut file, MAX_SEGMENT_BYTES)?;
        if bytes.len() as u64 != segment.length || sha256(&bytes) != segment.digest {
            return Err(invalid(
                "audit archive content does not match authenticated manifest",
            ));
        }
        let end = verify_audit_from(&mut file, key, segment.start.sequence, segment.start.mac)
            .map_err(invalid)?;
        if end != (segment.end.sequence, segment.end.mac) {
            return Err(invalid("audit archive frontier mismatch"));
        }
        Ok(())
    }
    fn collect_garbage(&mut self, key: &hmac::Key) -> io::Result<()> {
        if self.manifest.pending.is_some() || self.manifest.garbage.is_empty() {
            return Ok(());
        }
        for segment in &self.manifest.garbage {
            let path = self.segment_path(segment.id);
            match open_read(&path) {
                Ok(file) => {
                    self.verify_segment(segment, key)?;
                    verify_identity(&file, &path)?;
                    fs::remove_file(&path)?;
                    self.directory.sync_all()?;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        self.crash_point("garbage")?;
        let mut complete = self.manifest.clone();
        complete.garbage.clear();
        self.publish(complete, key)
    }
    fn publish(&mut self, manifest: Manifest, key: &hmac::Key) -> io::Result<()> {
        let target = self.sidecar("rotation.json");
        match open_read(&target) {
            Ok(mut file) => {
                if !self.manifest_exists || decode_manifest(&mut file, key)? != self.manifest {
                    return Err(invalid("audit manifest changed outside its writer"));
                }
                verify_identity(&file, &target)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && !self.manifest_exists => {}
            Err(e) => return Err(e),
        }
        self.discard_staging()?;
        let payload = serde_json::to_vec(&manifest)?;
        let bytes = serde_json::to_vec(&SignedManifest {
            manifest: manifest.clone(),
            mac: STANDARD.encode(manifest_tag(key, &payload)),
        })?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(invalid("audit manifest exceeds bound"));
        }
        let stage = self.sidecar("rotation.tmp");
        let mut file = private_options(true)
            .write(true)
            .create_new(true)
            .open(&stage)?;
        file.write_all(STAGING_MAGIC)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        verify_identity(&file, &stage)?;
        fs::rename(&stage, &target)?;
        self.directory.sync_all()?;
        self.manifest = manifest;
        self.manifest_exists = true;
        Ok(())
    }
    fn discard_staging(&self) -> io::Result<()> {
        let path = self.sidecar("rotation.tmp");
        let mut file = match open_read(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let bytes = read_bounded(&mut file, MAX_MANIFEST_BYTES + STAGING_MAGIC.len() as u64)?;
        let prefix_length = bytes.len().min(STAGING_MAGIC.len());
        if bytes[..prefix_length] != STAGING_MAGIC[..prefix_length] {
            return Err(invalid("unrecognized file occupies audit staging path"));
        }
        verify_identity(&file, &path)?;
        fs::remove_file(path)?;
        self.directory.sync_all()
    }
    fn verify_active_identity(&self, audit: &File) -> io::Result<()> {
        verify_identity(audit, &self.active_path())
    }
    fn crash_point(&self, _point: &str) -> io::Result<()> {
        #[cfg(test)]
        if self.fault == Some(_point) {
            if std::env::var_os("HEPTABAO_TEST_AUDIT_EXIT").is_some() {
                // Test subprocess termination deliberately skips Rust destructors.
                std::process::exit(73);
            }
            return Err(invalid("injected audit rotation interruption"));
        }
        Ok(())
    }
}
fn decode_manifest(file: &mut File, key: &hmac::Key) -> io::Result<Manifest> {
    let bytes = read_bounded(file, MAX_MANIFEST_BYTES + STAGING_MAGIC.len() as u64)?;
    let json = bytes
        .strip_prefix(STAGING_MAGIC)
        .ok_or_else(|| invalid("invalid audit manifest framing"))?;
    let signed: SignedManifest = serde_json::from_slice(json)?;
    let payload = serde_json::to_vec(&signed.manifest)?;
    let tag = STANDARD
        .decode(signed.mac)
        .map_err(|_| invalid("invalid audit manifest tag"))?;
    let mut message = b"heptabao.audit.rotation.manifest.v1\0".to_vec();
    message.extend_from_slice(&payload);
    hmac::verify(key, &message, &tag)
        .map_err(|_| invalid("audit manifest authentication failed"))?;
    Ok(signed.manifest)
}
fn manifest_tag(key: &hmac::Key, bytes: &[u8]) -> Vec<u8> {
    let mut message = b"heptabao.audit.rotation.manifest.v1\0".to_vec();
    message.extend_from_slice(bytes);
    hmac::sign(key, &message).as_ref().to_vec()
}
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0; 32];
    output.copy_from_slice(digest::digest(&digest::SHA256, bytes).as_ref());
    output
}
fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}
fn read_bounded(file: &mut File, maximum: u64) -> io::Result<Vec<u8>> {
    if file.metadata()?.len() > maximum {
        return Err(invalid("audit file exceeds bound"));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(invalid("audit file exceeds bound"));
    }
    Ok(bytes)
}
fn open_read(path: &Path) -> io::Result<File> {
    let file = private_options(false).read(true).open(path)?;
    check_private_file(&file)?;
    Ok(file)
}
fn private_options(create: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0o400000 | 0o2000000 | 0o4000);
        if create {
            options.mode(0o600);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = create;
    options
}
fn descriptor_path(file: &File) -> io::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        Ok(PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        Err(invalid(
            "audit rotation requires Linux descriptor anchoring",
        ))
    }
}
fn open_directory(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(invalid("audit directory must be absolute"));
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(0o200000 | 0o400000 | 0o2000000);
        let mut current = options.open("/")?;
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    current = options.open(descriptor_path(&current)?.join(name))?
                }
                _ => return Err(invalid("noncanonical audit directory")),
            }
        }
        if current.metadata()?.permissions().mode() & 0o022 != 0 {
            return Err(invalid(
                "audit directory must not be writable by group or others",
            ));
        }
        Ok(current)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(invalid(
            "audit rotation requires Linux descriptor anchoring",
        ))
    }
}
fn lock_writer(file: &File) -> io::Result<()> {
    // O_CLOEXEC closes at exec, not fork: tolerate the same bounded inheritance
    // window as ExclusiveDirectory while still refusing an actual live writer.
    let mut retries = 32;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(fs::TryLockError::WouldBlock) if retries > 0 => {
                retries -= 1;
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            Err(fs::TryLockError::WouldBlock) => {
                return Err(invalid("audit writer is already active"));
            }
            Err(fs::TryLockError::Error(error)) => return Err(error),
        }
    }
}
fn verify_identity(file: &File, path: &Path) -> io::Result<()> {
    check_private_file(file)?;
    let named = fs::symlink_metadata(path)?;
    if !named.is_file() || named.file_type().is_symlink() {
        return Err(invalid("audit pathname is unsafe"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        if opened.dev() != named.dev() || opened.ino() != named.ino() {
            return Err(invalid("audit file identity changed"));
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::super::{Service, private_directory};
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    type ResultTest = Result<(), Box<dyn std::error::Error>>;
    struct Root(PathBuf);
    impl Root {
        fn new() -> io::Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "heptabao-audit-rotation-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            private_directory(&path)?;
            Ok(Self(path))
        }
        fn path(&self) -> PathBuf {
            self.0.join("audit.jsonl")
        }
        fn service(&self, retained: usize) -> Result<Service, &'static str> {
            Service::new_with_audit_config(
                self.0.join("data"),
                &self.path(),
                AuditConfig {
                    segment_bytes: 4096,
                    retained_segments: retained,
                },
            )
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn requests(service: &mut Service, count: usize) {
        for _ in 0..count {
            assert_eq!(
                service
                    .handle_at("GET", "sys/init", "", "", json!({}), 100)
                    .status,
                200
            );
        }
    }
    fn rotate(service: &mut Service) -> io::Result<()> {
        service.audit_rotation.rotate(
            &mut service.audit,
            &service.audit_key,
            Frontier {
                sequence: service.audit_sequence,
                mac: service.audit_previous,
            },
        )
    }
    #[test]
    fn audit_rotation_retains_bounded_segments_and_continuous_authenticated_sequence() -> ResultTest
    {
        let root = Root::new()?;
        let mut service = root.service(2)?;
        requests(&mut service, 150);
        assert_eq!(service.audit_sequence, 300);
        assert_eq!(service.audit_rotation.manifest.segments.len(), 2);
        assert!(service.audit_rotation.manifest.base.sequence > 0);
        assert!(service.audit.metadata()?.len() <= 4096);
        let archives: Vec<_> = fs::read_dir(&root.0)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|e| e.file_name().to_string_lossy().contains(".segment-"))
            .collect();
        assert_eq!(archives.len(), 2);
        for file in &archives {
            assert!(file.metadata()?.len() <= 4096);
        }
        let expected = service.audit_previous;
        drop(service);
        let mut reopened = root.service(2)?;
        assert_eq!(
            (reopened.audit_sequence, reopened.audit_previous),
            (300, expected)
        );
        requests(&mut reopened, 1);
        assert_eq!(reopened.audit_sequence, 302);
        Ok(())
    }
    #[test]
    fn audit_rotation_reopens_existing_single_file_without_rewriting_old_records() -> ResultTest {
        let root = Root::new()?;
        let mut old = Service::new(root.0.join("data"), &root.path())?;
        requests(&mut old, 10);
        let original = fs::read(root.path())?;
        drop(old);
        let mut service = root.service(2)?;
        assert_eq!(fs::read(root.path())?, original);
        requests(&mut service, 1);
        let first = service.audit_rotation.segment_path(1);
        assert_eq!(fs::read(first)?, original);
        drop(service);
        assert_eq!(root.service(2)?.audit_sequence, 22);
        Ok(())
    }
    #[test]
    fn audit_rotation_recovers_each_durable_boundary_without_loss_or_duplicate() -> ResultTest {
        for fault in ["archive", "pending", "truncated", "complete", "garbage"] {
            let root = Root::new()?;
            let mut service = root.service(1)?;
            requests(&mut service, 2);
            rotate(&mut service)?;
            requests(&mut service, 2);
            let before = (service.audit_sequence, service.audit_previous);
            service.audit_rotation.fault = Some(fault);
            assert!(rotate(&mut service).is_err(), "{fault}");
            drop(service);
            let mut reopened = root.service(1)?;
            assert_eq!(
                (reopened.audit_sequence, reopened.audit_previous),
                before,
                "{fault}"
            );
            requests(&mut reopened, 1);
            rotate(&mut reopened)?;
            assert_eq!(reopened.audit_sequence, before.0 + 2);
            assert_eq!(reopened.audit_rotation.manifest.segments.len(), 1);
        }
        Ok(())
    }
    #[test]
    fn audit_rotation_resumes_partial_archive_and_discards_only_reserved_staging() -> ResultTest {
        let root = Root::new()?;
        let mut service = root.service(2)?;
        requests(&mut service, 2);
        let bytes = fs::read(root.path())?;
        let archive = service.audit_rotation.segment_path(1);
        let stage = service.audit_rotation.sidecar("rotation.tmp");
        let mut file = private_options(true)
            .write(true)
            .create_new(true)
            .open(&archive)?;
        file.write_all(&bytes[..bytes.len() / 2])?;
        file.sync_all()?;
        let mut file = private_options(true)
            .write(true)
            .create_new(true)
            .open(&stage)?;
        file.write_all(&STAGING_MAGIC[..7])?;
        file.sync_all()?;
        let archive = root
            .0
            .join(archive.file_name().ok_or("missing archive leaf")?);
        let stage = root.0.join(stage.file_name().ok_or("missing stage leaf")?);
        drop(service);
        let mut reopened = root.service(2)?;
        rotate(&mut reopened)?;
        assert_eq!(fs::read(archive)?, bytes);
        assert!(!stage.exists());
        Ok(())
    }
    #[test]
    fn audit_rotation_rejects_archive_tampering_and_missing_checkpoint() -> ResultTest {
        let root = Root::new()?;
        let mut service = root.service(2)?;
        requests(&mut service, 2);
        rotate(&mut service)?;
        let archive = service.audit_rotation.segment_path(1);
        let checkpoint = service.audit_rotation.sidecar("rotation.json");
        let archive_bytes = fs::read(&archive)?;
        let checkpoint_bytes = fs::read(&checkpoint)?;
        drop(service);
        let archive = root
            .0
            .join(archive.file_name().ok_or("no archive filename")?);
        let checkpoint = root
            .0
            .join(checkpoint.file_name().ok_or("no checkpoint filename")?);
        let mut altered = archive_bytes.clone();
        altered[10] ^= 1;
        fs::write(&archive, altered)?;
        assert!(root.service(2).is_err());
        fs::write(&archive, archive_bytes)?;
        let mut altered = checkpoint_bytes.clone();
        let last = altered.len() - 2;
        altered[last] ^= 1;
        fs::write(&checkpoint, altered)?;
        assert!(root.service(2).is_err());
        fs::write(&checkpoint, checkpoint_bytes)?;
        fs::remove_file(&checkpoint)?;
        assert!(root.service(2).is_err());
        Ok(())
    }
    #[test]
    fn audit_rotation_rejects_symlink_and_foreign_archive_without_modifying_target() -> ResultTest {
        use std::os::unix::fs::symlink;
        let root = Root::new()?;
        let mut service = root.service(2)?;
        requests(&mut service, 2);
        let destination = root.0.join("unrelated");
        fs::write(&destination, b"do not change")?;
        let archive = service.audit_rotation.segment_path(1);
        symlink(&destination, &archive)?;
        assert!(rotate(&mut service).is_err());
        assert_eq!(fs::read(&destination)?, b"do not change");
        fs::remove_file(&archive)?;
        let mut file = private_options(true)
            .create_new(true)
            .write(true)
            .open(&archive)?;
        file.write_all(b"foreign file")?;
        file.sync_all()?;
        assert!(rotate(&mut service).is_err());
        assert_eq!(fs::read(&archive)?, b"foreign file");
        Ok(())
    }
    #[test]
    fn audit_rotation_fences_concurrent_writers_and_survives_parent_rename() -> ResultTest {
        let root = Root::new()?;
        let mut service = root.service(2)?;
        assert!(root.service(2).is_err());
        requests(&mut service, 2);
        let moved = root.0.with_extension("moved");
        fs::rename(&root.0, &moved)?;
        private_directory(&root.0)?;
        fs::write(root.path(), b"unrelated replacement directory")?;
        rotate(&mut service)?;
        assert_eq!(fs::read(root.path())?, b"unrelated replacement directory");
        assert!(
            moved
                .join("audit.jsonl.segment-00000000000000000001.jsonl")
                .exists()
        );
        drop(service);
        fs::remove_dir_all(moved)?;
        Ok(())
    }
    #[test]
    fn audit_rotation_configuration_bounds_are_validated_before_file_creation() -> ResultTest {
        let root = Root::new()?;
        for config in [
            AuditConfig {
                segment_bytes: 0,
                retained_segments: 8,
            },
            AuditConfig {
                segment_bytes: 4096,
                retained_segments: 0,
            },
            AuditConfig {
                segment_bytes: MAX_SEGMENT_BYTES + 1,
                retained_segments: 8,
            },
        ] {
            assert!(AuditRotation::open(&root.path(), config).is_err());
        }
        assert!(!root.path().exists());
        Ok(())
    }
    #[test]
    fn audit_rotation_abrupt_subprocess_exit_recovers_all_durable_boundaries() -> ResultTest {
        const PHASES: [&str; 5] = ["archive", "pending", "truncated", "complete", "garbage"];
        if let Some(path) = std::env::var_os("HEPTABAO_TEST_AUDIT_CHILD_ROOT") {
            let phase = std::env::var("HEPTABAO_TEST_AUDIT_CHILD_PHASE")?;
            let point = PHASES
                .into_iter()
                .find(|point| *point == phase)
                .ok_or("invalid child phase")?;
            let root = Root(PathBuf::from(path));
            let mut service = root.service(1)?;
            requests(&mut service, 2);
            rotate(&mut service)?;
            requests(&mut service, 2);
            service.audit_rotation.fault = Some(point);
            rotate(&mut service)?;
            return Err("subprocess did not terminate at the injected boundary".into());
        }
        for phase in PHASES {
            let root = Root::new()?;
            let output = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", "service::audit_rotation::tests::audit_rotation_abrupt_subprocess_exit_recovers_all_durable_boundaries", "--nocapture"])
                .env("HEPTABAO_TEST_AUDIT_CHILD_ROOT", &root.0)
                .env("HEPTABAO_TEST_AUDIT_CHILD_PHASE", phase)
                .env("HEPTABAO_TEST_AUDIT_EXIT", "1")
                .output()?;
            assert_eq!(
                output.status.code(),
                Some(73),
                "phase={phase}, stderr={}",
                String::from_utf8_lossy(&output.stderr)
            );
            let mut service = root.service(1)?;
            assert_eq!(service.audit_sequence, 8, "{phase}");
            requests(&mut service, 1);
            assert_eq!(service.audit_sequence, 10, "{phase}");
            rotate(&mut service)?;
        }
        Ok(())
    }
    #[test]
    fn audit_rotation_rejects_missing_active_file_without_reinitializing_it() -> ResultTest {
        for leaf in ["audit.jsonl", "audit.jsonl.hmac-key"] {
            let root = Root::new()?;
            let mut service = root.service(2)?;
            requests(&mut service, 2);
            rotate(&mut service)?;
            drop(service);
            let missing = root.0.join(leaf);
            fs::remove_file(&missing)?;
            assert!(root.service(2).is_err());
            assert!(!missing.exists());
        }
        Ok(())
    }
    #[test]
    fn audit_rotation_hot_path_rejects_renamed_replaced_symlinked_or_unlinked_active_file()
    -> ResultTest {
        use std::os::unix::fs::symlink;
        for action in ["rename", "replace", "symlink", "unlink"] {
            let root = Root::new()?;
            let mut service = root.service(2)?;
            requests(&mut service, 1);
            assert!(service.audit.metadata()?.len() < 2048);
            let before = service.audit_sequence;
            let saved = root.0.join("saved.jsonl");
            if action == "unlink" {
                fs::remove_file(root.path())?;
            } else {
                fs::rename(root.path(), &saved)?;
            }
            if action == "replace" {
                let mut file = private_options(true)
                    .create_new(true)
                    .write(true)
                    .open(root.path())?;
                file.write_all(b"unrelated occupant")?;
            }
            if action == "symlink" {
                symlink(&saved, root.path())?;
            }
            let response = service.handle_at("GET", "sys/init", "", "", json!({}), 100);
            assert_eq!(response.status, 503, "{action}");
            assert!(service.audit_failed, "{action}");
            assert_eq!(service.audit_sequence, before, "{action}");
            if action == "replace" {
                assert_eq!(fs::read(root.path())?, b"unrelated occupant");
            }
        }
        Ok(())
    }
    #[test]
    fn audit_rotation_reopen_rejects_unlisted_archives_even_with_valid_checkpoint() -> ResultTest {
        for (id, content) in [
            (7, b"foreign bytes".as_slice()),
            (2, b"foreign bytes".as_slice()),
        ] {
            let root = Root::new()?;
            let mut service = root.service(2)?;
            requests(&mut service, 1);
            rotate(&mut service)?;
            requests(&mut service, 1);
            let path = root.0.join(format!("audit.jsonl.segment-{id:020}.jsonl"));
            let mut file = private_options(true)
                .write(true)
                .create_new(true)
                .open(&path)?;
            file.write_all(content)?;
            file.sync_all()?;
            drop(service);
            assert!(root.service(2).is_err());
            assert_eq!(fs::read(path)?, content);
        }
        Ok(())
    }
}
