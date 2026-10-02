//! Linux /proc identity collector with held executable/config descriptors.
//!
//! Capture uses the fixed `/proc` mount; tests alone may substitute a fake tree.
//! No cmdline, environ, process signaling or executable spawning is performed.
//! The authoritative lifecycle hook brackets every actual OS observation.

use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

use ring::digest::{Context, SHA256};
use rustix::fs::{Mode, OFlags};
use zeroize::Zeroizing;

use crate::{BridgeError, HostLifecycle, IdentityProbe, OwnedPluginIdentity};

const MAX_PROC_FILE: usize = 64 * 1024;
const MAX_EXECUTABLE: u64 = 512 * 1024 * 1024;
const MAX_CONFIG: u64 = 1024 * 1024;

/// Implemented by the product's authoritative sealed/configuration owner.
/// The adapter deliberately does not infer host authority from process metadata.
/// The owner must advance its generation for every configuration replacement;
/// an OS identity cannot authenticate this application-level authority.
pub trait AuthoritativeLifecycleHook: fmt::Debug {
    fn snapshot(&self) -> Result<HostLifecycle, BridgeError>;
}

/// Immutable executable and private configuration captured by the product's
/// own launch. A PID supplied by an untrusted caller is not launch authority.
pub struct StartedChildBinding {
    pub uid: u32,
    pub pid: u32,
    pub executable_device: u64,
    pub executable_inode: u64,
    pub executable_sha256: [u8; 32],
    pub config_device: u64,
    pub config_inode: u64,
    pub config_sha256: [u8; 32],
}

impl fmt::Debug for StartedChildBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StartedChildBinding([REDACTED])")
    }
}

impl<H: AuthoritativeLifecycleHook> LinuxIdentityProbe<H> {
    /// Collect the actual start/SID and bind the known sealed image/private file
    /// before admitting a fresh session. The trusted caller must own this Child
    /// and a held pidfd; this adapter never obtains process ownership from a PID.
    pub fn capture_started_child(
        binding: StartedChildBinding,
        config_path: &Path,
        hook: H,
    ) -> Result<Self, BridgeError> {
        if !cfg!(target_os = "linux") {
            return Err(BridgeError::ProcessObservationUnavailable);
        }
        let root = Path::new("/proc");
        let lifecycle = hook.snapshot()?;
        if !lifecycle.sealed || lifecycle.configuration_generation == 0 {
            return Err(BridgeError::LifecycleDenied);
        }
        let before = process_frame(root, binding.pid, binding.uid)?;
        let expected = OwnedPluginIdentity {
            uid: binding.uid,
            pid: binding.pid,
            session_id: before.session_id,
            start_ticks: before.start_ticks,
            executable_device: binding.executable_device,
            executable_inode: binding.executable_inode,
            executable_sha256: binding.executable_sha256,
            config_device: binding.config_device,
            config_inode: binding.config_inode,
            config_sha256: binding.config_sha256,
            config_mode: 0o600,
        };
        let probe = Self::capture(expected, config_path, hook)?;
        let (_, after_lifecycle) = probe.observe()?;
        if process_frame(root, binding.pid, binding.uid)? != before || after_lifecycle != lifecycle
        {
            return Err(BridgeError::IdentityChanged);
        }
        Ok(probe)
    }
}

pub struct LinuxIdentityProbe<H> {
    expected: OwnedPluginIdentity,
    held_executable: File,
    held_config: File,
    config_path: PathBuf,
    hook: H,
    #[cfg(test)]
    proc_root: PathBuf,
}
impl<H> fmt::Debug for LinuxIdentityProbe<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LinuxIdentityProbe([REDACTED])")
    }
}

impl<H: AuthoritativeLifecycleHook> LinuxIdentityProbe<H> {
    /// The expected digest/inode/start identity comes from immutable launch
    /// admission. This method independently collects OS metadata before binding.
    pub fn capture(
        expected: OwnedPluginIdentity,
        config_path: &Path,
        hook: H,
    ) -> Result<Self, BridgeError> {
        if !cfg!(target_os = "linux") {
            return Err(BridgeError::ProcessObservationUnavailable);
        }
        Self::capture_at(Path::new("/proc"), expected, config_path, hook)
    }
    fn capture_at(
        root: &Path,
        expected: OwnedPluginIdentity,
        config_path: &Path,
        hook: H,
    ) -> Result<Self, BridgeError> {
        expected.validate()?;
        if !config_path.is_absolute() {
            return Err(BridgeError::InvalidBinding);
        }
        let lifecycle = hook.snapshot()?;
        if !lifecycle.sealed || lifecycle.configuration_generation == 0 {
            return Err(BridgeError::LifecycleDenied);
        }
        let before = process_frame(root, expected.pid, expected.uid)?;
        verify_frame(&before, &expected)?;
        let held_executable = open_executable(root, expected.pid)?;
        let held_config = open_config(config_path)?;
        let probe = Self {
            expected,
            held_executable,
            held_config,
            config_path: config_path.to_path_buf(),
            hook,
            #[cfg(test)]
            proc_root: root.to_path_buf(),
        };
        let (actual, after) = probe.observe_at(root)?;
        if actual != probe.expected {
            return Err(BridgeError::IdentityChanged);
        }
        if after != lifecycle {
            return Err(BridgeError::LifecycleDenied);
        }
        Ok(probe)
    }
    fn observe_at(&self, root: &Path) -> Result<(OwnedPluginIdentity, HostLifecycle), BridgeError> {
        let lifecycle_before = self.hook.snapshot()?;
        if lifecycle_before.configuration_generation == 0 {
            return Err(BridgeError::LifecycleDenied);
        }
        let before = process_frame(root, self.expected.pid, self.expected.uid)?;
        verify_frame(&before, &self.expected)?;
        let executable = open_executable(root, self.expected.pid)?;
        let config = open_config(&self.config_path)?;
        let held_executable_meta = stable_metadata(&self.held_executable)?;
        let held_config_meta = stable_metadata(&self.held_config)?;
        let executable_meta = stable_metadata(&executable)?;
        let config_meta = stable_metadata(&config)?;
        if executable_meta != held_executable_meta || config_meta != held_config_meta {
            return Err(BridgeError::IdentityChanged);
        }
        if executable_meta.uid != self.expected.uid {
            return Err(BridgeError::IdentityChanged);
        }
        if config_meta.uid != self.expected.uid
            || config_meta.mode & 0o7777 != 0o600
            || config_meta.links != 1
        {
            return Err(BridgeError::IdentityChanged);
        }
        let executable_sha = stable_hash(&executable, MAX_EXECUTABLE)?;
        let config_sha = stable_hash(&config, MAX_CONFIG)?;
        if stable_metadata(&self.held_executable)? != executable_meta
            || stable_metadata(&self.held_config)? != config_meta
        {
            return Err(BridgeError::IdentityChanged);
        }
        // Reopen the original config path to reject rename/symlink replacement,
        // even though its original held descriptor remains valid.
        if stable_metadata(&open_config(&self.config_path)?)? != config_meta {
            return Err(BridgeError::IdentityChanged);
        }
        if stable_metadata(&open_executable(root, self.expected.pid)?)? != executable_meta {
            return Err(BridgeError::IdentityChanged);
        }
        let after = process_frame(root, self.expected.pid, self.expected.uid)?;
        if after != before {
            return Err(BridgeError::IdentityChanged);
        }
        let lifecycle_after = self.hook.snapshot()?;
        if lifecycle_after != lifecycle_before {
            return Err(BridgeError::LifecycleDenied);
        }
        let actual = OwnedPluginIdentity {
            uid: before.uid,
            pid: before.pid,
            session_id: before.session_id,
            start_ticks: before.start_ticks,
            executable_device: executable_meta.device,
            executable_inode: executable_meta.inode,
            executable_sha256: executable_sha,
            config_device: config_meta.device,
            config_inode: config_meta.inode,
            config_sha256: config_sha,
            config_mode: config_meta.mode & 0o7777,
        };
        if actual != self.expected {
            return Err(BridgeError::IdentityChanged);
        }
        Ok((actual, lifecycle_after))
    }
}
impl<H: AuthoritativeLifecycleHook> IdentityProbe for LinuxIdentityProbe<H> {
    fn observe(&self) -> Result<(OwnedPluginIdentity, HostLifecycle), BridgeError> {
        #[cfg(test)]
        {
            self.observe_at(&self.proc_root)
        }
        #[cfg(not(test))]
        {
            if !cfg!(target_os = "linux") {
                return Err(BridgeError::ProcessObservationUnavailable);
            }
            self.observe_at(Path::new("/proc"))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StableMetadata {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    length: u64,
    links: u64,
    modified_seconds: i64,
    modified_nanos: i64,
    changed_seconds: i64,
    changed_nanos: i64,
}
fn metadata_value(metadata: Metadata) -> Result<StableMetadata, BridgeError> {
    if !metadata.is_file() {
        return Err(BridgeError::ProcessObservationUnavailable);
    }
    Ok(StableMetadata {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
        length: metadata.len(),
        links: metadata.nlink(),
        modified_seconds: metadata.mtime(),
        modified_nanos: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanos: metadata.ctime_nsec(),
    })
}
fn stable_metadata(file: &File) -> Result<StableMetadata, BridgeError> {
    metadata_value(
        file.metadata()
            .map_err(|_| BridgeError::ProcessObservationUnavailable)?,
    )
}
fn open_executable(root: &Path, pid: u32) -> Result<File, BridgeError> {
    // /proc/PID/exe is a kernel-owned symlink. It is the only intentional follow.
    let fd = rustix::fs::open(
        root.join(pid.to_string()).join("exe"),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BridgeError::ProcessObservationUnavailable)?;
    Ok(File::from(fd))
}
fn open_config(path: &Path) -> Result<File, BridgeError> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| BridgeError::ProcessObservationUnavailable)?;
    Ok(File::from(fd))
}
fn hash_pass(file: &File, length: u64) -> Result<[u8; 32], BridgeError> {
    let mut context = Context::new(&SHA256);
    let mut buffer = Zeroizing::new(vec![0; 16 * 1024]);
    let mut offset = 0;
    while offset < length {
        let size = (length - offset).min(buffer.len() as u64) as usize;
        let count = file
            .read_at(&mut buffer[..size], offset)
            .map_err(|_| BridgeError::ProcessObservationUnavailable)?;
        if count == 0 {
            return Err(BridgeError::IdentityChanged);
        }
        context.update(&buffer[..count]);
        offset += count as u64;
    }
    let mut extra = Zeroizing::new([0u8; 1]);
    if file
        .read_at(extra.as_mut_slice(), length)
        .map_err(|_| BridgeError::ProcessObservationUnavailable)?
        != 0
    {
        return Err(BridgeError::IdentityChanged);
    }
    let digest = context.finish();
    digest
        .as_ref()
        .try_into()
        .map_err(|_| BridgeError::ProcessObservationUnavailable)
}
fn stable_hash(file: &File, maximum: u64) -> Result<[u8; 32], BridgeError> {
    let before = stable_metadata(file)?;
    if before.length == 0 || before.length > maximum {
        return Err(BridgeError::InvalidBinding);
    }
    let first = hash_pass(file, before.length)?;
    if stable_metadata(file)? != before {
        return Err(BridgeError::IdentityChanged);
    }
    let second = hash_pass(file, before.length)?;
    if stable_metadata(file)? != before || first != second {
        return Err(BridgeError::IdentityChanged);
    }
    Ok(first)
}
fn read_proc_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| BridgeError::ProcessObservationUnavailable)?;
    let mut file = File::from(fd);
    let mut bytes = Zeroizing::new(Vec::new());
    file.by_ref()
        .take(MAX_PROC_FILE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BridgeError::ProcessObservationUnavailable)?;
    if bytes.is_empty() || bytes.len() > MAX_PROC_FILE {
        return Err(BridgeError::ProcessObservationUnavailable);
    }
    Ok(bytes)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessFrame {
    pid: u32,
    uid: u32,
    session_id: u32,
    start_ticks: u64,
}
fn unsigned<T: std::str::FromStr>(bytes: &[u8]) -> Result<T, BridgeError> {
    if bytes.is_empty()
        || (bytes.len() > 1 && bytes[0] == b'0')
        || bytes.iter().any(|b| !b.is_ascii_digit())
    {
        return Err(BridgeError::ProcessObservationUnavailable);
    }
    std::str::from_utf8(bytes)
        .map_err(|_| BridgeError::ProcessObservationUnavailable)?
        .parse()
        .map_err(|_| BridgeError::ProcessObservationUnavailable)
}
fn parse_stat(bytes: &[u8]) -> Result<(u32, u32, u64), BridgeError> {
    let split = bytes
        .iter()
        .position(|b| *b == b' ')
        .ok_or(BridgeError::ProcessObservationUnavailable)?;
    let pid: u32 = unsigned(&bytes[..split])?;
    if bytes.get(split + 1) != Some(&b'(') {
        return Err(BridgeError::ProcessObservationUnavailable);
    }
    let close = bytes
        .iter()
        .rposition(|b| *b == b')')
        .ok_or(BridgeError::ProcessObservationUnavailable)?;
    if close <= split + 1 || bytes.get(close + 1) != Some(&b' ') {
        return Err(BridgeError::ProcessObservationUnavailable);
    }
    let fields: Vec<_> = bytes[close + 2..]
        .split(|b| b.is_ascii_whitespace())
        .filter(|p| !p.is_empty())
        .collect();
    // Linux proc_pid_stat(5) fields 3..52. New/unknown grammar is denied.
    if fields.len() != 50 || fields[0].len() != 1 || !b"RSDZTtXxKWPI".contains(&fields[0][0]) {
        return Err(BridgeError::ProcessObservationUnavailable);
    }
    for field in &fields[1..] {
        let field = field.strip_prefix(b"-").unwrap_or(field);
        let _: u64 = unsigned(field)?;
    }
    let session_id: u32 = unsigned(fields[3])?;
    let start_ticks: u64 = unsigned(fields[19])?;
    if pid == 0 || session_id == 0 || start_ticks == 0 {
        return Err(BridgeError::ProcessObservationUnavailable);
    }
    Ok((pid, session_id, start_ticks))
}
fn parse_uids(bytes: &[u8]) -> Result<u32, BridgeError> {
    let mut found = None;
    for line in bytes.split(|b| *b == b'\n') {
        if let Some(value) = line.strip_prefix(b"Uid:") {
            if found.is_some() {
                return Err(BridgeError::ProcessObservationUnavailable);
            }
            let values: Vec<_> = value
                .split(|b| b.is_ascii_whitespace())
                .filter(|v| !v.is_empty())
                .collect();
            if values.len() != 4 {
                return Err(BridgeError::ProcessObservationUnavailable);
            }
            let parsed: Vec<u32> = values
                .iter()
                .map(|v| unsigned(v))
                .collect::<Result<_, _>>()?;
            if parsed.iter().any(|v| *v != parsed[0]) {
                return Err(BridgeError::IdentityChanged);
            }
            found = Some(parsed[0]);
        }
    }
    found.ok_or(BridgeError::ProcessObservationUnavailable)
}
fn process_frame(root: &Path, pid: u32, uid: u32) -> Result<ProcessFrame, BridgeError> {
    let directory = root.join(pid.to_string());
    let before =
        fs::symlink_metadata(&directory).map_err(|_| BridgeError::ProcessObservationUnavailable)?;
    if !before.is_dir() || before.uid() != uid {
        return Err(BridgeError::IdentityChanged);
    }
    let (actual_pid, session_id, start_ticks) =
        parse_stat(&read_proc_file(&directory.join("stat"))?)?;
    let actual_uid = parse_uids(&read_proc_file(&directory.join("status"))?)?;
    let after =
        fs::symlink_metadata(&directory).map_err(|_| BridgeError::ProcessObservationUnavailable)?;
    if actual_pid != pid
        || actual_uid != uid
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
    {
        return Err(BridgeError::IdentityChanged);
    }
    Ok(ProcessFrame {
        pid: actual_pid,
        uid: actual_uid,
        session_id,
        start_ticks,
    })
}
fn verify_frame(frame: &ProcessFrame, expected: &OwnedPluginIdentity) -> Result<(), BridgeError> {
    if frame.pid != expected.pid
        || frame.uid != expected.uid
        || frame.session_id != expected.session_id
        || frame.start_ticks != expected.start_ticks
    {
        return Err(BridgeError::IdentityChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
