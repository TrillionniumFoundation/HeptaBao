#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Linux directory-handle anchoring and exclusive writer fencing.
//!
//! The guard opens one existing absolute directory without following its final
//! component, verifies the same device/inode before and after open, binds all
//! later access through `/proc/self/fd/<fd>`, and holds an exclusive
//! process-scoped file lock on the directory handle. Consumers must use
//! `access_path()` for every filesystem operation and keep the guard alive for
//! the complete store or journal lifetime.
//!
//! This is a Linux-only implementation profile. It intentionally returns
//! `UnsupportedPlatform` elsewhere rather than silently falling back to
//! path-relative operations.

use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::{Component, Path, PathBuf};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

pub const MAX_GUARDED_LEAF_BYTES: usize = 240;

// Linux values from asm-generic/fcntl.h. They are used only on the Linux
// implementation selected by this crate's explicit runtime profile.
#[cfg(target_os = "linux")]
const O_DIRECTORY: i32 = 0o200000;
#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(target_os = "linux")]
const O_CLOEXEC: i32 = 0o2000000;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    pub const fn device(self) -> u64 {
        self.device
    }

    pub const fn inode(self) -> u64 {
        self.inode
    }
}

/// Owns the directory descriptor and its exclusive inter-process writer lock.
///
/// Dropping the value closes the descriptor and therefore releases the lock.
/// It is intentionally not `Clone`: one owner must control the lifetime.
pub struct ExclusiveDirectory {
    original_path: PathBuf,
    access_path: PathBuf,
    handle: File,
    identity: DirectoryIdentity,
}

impl fmt::Debug for ExclusiveDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExclusiveDirectory")
            .field("original_path", &"[REDACTED_ABSOLUTE_PATH]")
            .field("access_path", &"[DESCRIPTOR_BOUND]")
            .field("identity", &self.identity)
            .field("writer_lock", &"EXCLUSIVE_HELD")
            .finish()
    }
}

impl ExclusiveDirectory {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, DirectoryGuardError> {
        let original_path = root.as_ref().to_path_buf();
        if !original_path.is_absolute() {
            return Err(DirectoryGuardError::RootMustBeAbsolute);
        }

        #[cfg(target_os = "linux")]
        {
            Self::open_linux(original_path)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = original_path;
            Err(DirectoryGuardError::UnsupportedPlatform)
        }
    }

    pub fn original_path(&self) -> &Path {
        &self.original_path
    }

    pub fn access_path(&self) -> &Path {
        &self.access_path
    }

    pub const fn identity(&self) -> DirectoryIdentity {
        self.identity
    }

    pub fn leaf_path(&self, name: &str) -> Result<PathBuf, DirectoryGuardError> {
        validate_leaf(name)?;
        Ok(self.access_path.join(name))
    }

    pub fn verify(&self) -> Result<(), DirectoryGuardError> {
        #[cfg(target_os = "linux")]
        {
            let handle_metadata = self.handle.metadata().map_err(DirectoryGuardError::Io)?;
            let access_metadata = fs::metadata(&self.access_path).map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    DirectoryGuardError::DescriptorPathUnavailable
                } else {
                    DirectoryGuardError::Io(error)
                }
            })?;
            if !handle_metadata.is_dir()
                || !access_metadata.is_dir()
                || identity(&handle_metadata) != self.identity
                || identity(&access_metadata) != self.identity
            {
                return Err(DirectoryGuardError::RootIdentityChanged);
            }
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(DirectoryGuardError::UnsupportedPlatform)
        }
    }

    pub fn sync_all(&self) -> Result<(), DirectoryGuardError> {
        self.verify()?;
        self.handle.sync_all().map_err(DirectoryGuardError::Io)?;
        self.verify()
    }

    #[cfg(target_os = "linux")]
    fn open_linux(original_path: PathBuf) -> Result<Self, DirectoryGuardError> {
        let before = fs::symlink_metadata(&original_path).map_err(DirectoryGuardError::Io)?;
        if before.file_type().is_symlink() || !before.is_dir() {
            return Err(DirectoryGuardError::UnsafeRoot);
        }
        let before_identity = identity(&before);

        let handle = open_absolute_directory_no_symlinks(&original_path)?;
        let opened = handle.metadata().map_err(DirectoryGuardError::Io)?;
        let after = fs::symlink_metadata(&original_path).map_err(DirectoryGuardError::Io)?;
        if !opened.is_dir()
            || after.file_type().is_symlink()
            || !after.is_dir()
            || identity(&opened) != before_identity
            || identity(&after) != before_identity
        {
            return Err(DirectoryGuardError::RootIdentityChanged);
        }

        let access_path = PathBuf::from(format!("/proc/self/fd/{}", handle.as_raw_fd()));
        let access_metadata = fs::metadata(&access_path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                DirectoryGuardError::DescriptorPathUnavailable
            } else {
                DirectoryGuardError::Io(error)
            }
        })?;
        if !access_metadata.is_dir() || identity(&access_metadata) != before_identity {
            return Err(DirectoryGuardError::DescriptorPathUnavailable);
        }

        match handle.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(DirectoryGuardError::WriterBusy),
            Err(TryLockError::Error(error)) => return Err(DirectoryGuardError::Io(error)),
        }

        let guard = Self {
            original_path,
            access_path,
            handle,
            identity: before_identity,
        };
        guard.verify()?;
        Ok(guard)
    }
}

#[derive(Debug)]
pub enum DirectoryGuardError {
    RootMustBeAbsolute,
    UnsupportedPlatform,
    UnsafeRoot,
    RootIdentityChanged,
    DescriptorPathUnavailable,
    WriterBusy,
    InvalidLeafName,
    Io(io::Error),
}

impl fmt::Display for DirectoryGuardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootMustBeAbsolute => formatter.write_str("guarded root must be absolute"),
            Self::UnsupportedPlatform => formatter
                .write_str("descriptor-anchored writer guard is unsupported on this platform"),
            Self::UnsafeRoot => formatter
                .write_str("guarded root or one of its ancestors is a symlink or not a directory"),
            Self::RootIdentityChanged => formatter
                .write_str("guarded directory identity changed during or after acquisition"),
            Self::DescriptorPathUnavailable => formatter
                .write_str("descriptor-bound /proc access path is unavailable or mismatched"),
            Self::WriterBusy => {
                formatter.write_str("another process holds the directory writer fence")
            }
            Self::InvalidLeafName => formatter.write_str("guarded leaf name is invalid"),
            Self::Io(error) => write!(formatter, "directory guard I/O failure: {error}"),
        }
    }
}

impl Error for DirectoryGuardError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for DirectoryGuardError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn validate_leaf(name: &str) -> Result<(), DirectoryGuardError> {
    if name.is_empty()
        || name.len() > MAX_GUARDED_LEAF_BYTES
        || !name.is_ascii()
        || name == "."
        || name == ".."
        || name.bytes().any(|byte| {
            !matches!(
                byte,
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-'
            )
        })
    {
        return Err(DirectoryGuardError::InvalidLeafName);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_absolute_directory_no_symlinks(path: &Path) -> Result<File, DirectoryGuardError> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(DirectoryGuardError::RootMustBeAbsolute);
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    let mut current = options.open("/").map_err(DirectoryGuardError::Io)?;

    for component in components {
        let Component::Normal(name) = component else {
            return Err(DirectoryGuardError::UnsafeRoot);
        };
        let current_identity = identity(&current.metadata().map_err(DirectoryGuardError::Io)?);
        let current_access = PathBuf::from(format!("/proc/self/fd/{}", current.as_raw_fd()));
        let access_metadata = fs::metadata(&current_access).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                DirectoryGuardError::DescriptorPathUnavailable
            } else {
                DirectoryGuardError::Io(error)
            }
        })?;
        if !access_metadata.is_dir() || identity(&access_metadata) != current_identity {
            return Err(DirectoryGuardError::DescriptorPathUnavailable);
        }

        let candidate = current_access.join(name);
        let before = fs::symlink_metadata(&candidate).map_err(DirectoryGuardError::Io)?;
        if before.file_type().is_symlink() || !before.is_dir() {
            return Err(DirectoryGuardError::UnsafeRoot);
        }
        let before_identity = identity(&before);
        let next = options.open(&candidate).map_err(|error| {
            if error.raw_os_error() == Some(40) {
                DirectoryGuardError::UnsafeRoot
            } else {
                DirectoryGuardError::Io(error)
            }
        })?;
        let opened = next.metadata().map_err(DirectoryGuardError::Io)?;
        let after = fs::symlink_metadata(&candidate).map_err(DirectoryGuardError::Io)?;
        if !opened.is_dir()
            || after.file_type().is_symlink()
            || !after.is_dir()
            || identity(&opened) != before_identity
            || identity(&after) != before_identity
        {
            return Err(DirectoryGuardError::RootIdentityChanged);
        }
        current = next;
    }
    Ok(current)
}

#[cfg(target_os = "linux")]
fn identity(metadata: &fs::Metadata) -> DirectoryIdentity {
    DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::symlink;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    // `Command::spawn` may fork while another test owns a directory descriptor.
    // `O_CLOEXEC` closes that descriptor only at exec, so serialize these tests
    // to prevent transient inheritance from extending an unrelated writer lock.
    static TEST_SERIAL: Mutex<()> = Mutex::new(());

    fn serial_test() -> MutexGuard<'static, ()> {
        match TEST_SERIAL.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[derive(Debug)]
    struct TemporaryDirectory {
        path: PathBuf,
    }

    impl TemporaryDirectory {
        fn new(label: &str) -> io::Result<Self> {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "heptabao-filesystem-guard-{label}-{}-{sequence:016x}",
                std::process::id()
            ));
            fs::create_dir(&path)?;
            Ok(Self { path })
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
            if let Some(parent) = self.path.parent() {
                let moved_prefix = self
                    .path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .map(|value| format!("{value}-moved"));
                if let Some(prefix) = moved_prefix
                    && let Ok(entries) = fs::read_dir(parent)
                {
                    for entry in entries.flatten() {
                        if entry.file_name().to_string_lossy().starts_with(&prefix) {
                            let _ = fs::remove_dir_all(entry.path());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn root_is_descriptor_bound_and_leaf_names_are_closed() -> Result<(), Box<dyn Error>> {
        let _serial = serial_test();
        let temporary = TemporaryDirectory::new("basic")?;
        let guard = ExclusiveDirectory::open(&temporary.path)?;
        guard.verify()?;
        let leaf = guard.leaf_path("CURRENT")?;
        let mut file = File::create(&leaf)?;
        file.write_all(b"bound")?;
        file.sync_all()?;
        guard.sync_all()?;
        assert_eq!(fs::read(temporary.path.join("CURRENT"))?, b"bound");
        assert!(matches!(
            guard.leaf_path("../escape"),
            Err(DirectoryGuardError::InvalidLeafName)
        ));
        assert!(matches!(
            guard.leaf_path("nested/path"),
            Err(DirectoryGuardError::InvalidLeafName)
        ));
        Ok(())
    }

    #[test]
    fn second_open_is_fenced_until_drop() -> Result<(), Box<dyn Error>> {
        let _serial = serial_test();
        let temporary = TemporaryDirectory::new("lock")?;
        let first = ExclusiveDirectory::open(&temporary.path)?;
        let second = ExclusiveDirectory::open(&temporary.path);
        assert!(matches!(second, Err(DirectoryGuardError::WriterBusy)));
        drop(first);
        let reacquired = ExclusiveDirectory::open(&temporary.path)?;
        reacquired.verify()?;
        Ok(())
    }

    #[test]
    fn cooperating_processes_observe_writer_fence() -> Result<(), Box<dyn Error>> {
        let _serial = serial_test();
        const ROOT_ENV: &str = "HEPTABAO_FILESYSTEM_GUARD_TEST_ROOT";
        const MODE_ENV: &str = "HEPTABAO_FILESYSTEM_GUARD_TEST_MODE";
        const TEST_NAME: &str = "tests::cooperating_processes_observe_writer_fence";

        if let (Some(root), Some(mode)) = (std::env::var_os(ROOT_ENV), std::env::var_os(MODE_ENV)) {
            let result = ExclusiveDirectory::open(PathBuf::from(root));
            match mode.to_str() {
                Some("busy") => {
                    assert!(matches!(result, Err(DirectoryGuardError::WriterBusy)));
                }
                Some("available") => {
                    let guard = result?;
                    guard.verify()?;
                }
                _ => return Err(io::Error::other("invalid subprocess lock-test mode").into()),
            }
            return Ok(());
        }

        let temporary = TemporaryDirectory::new("process-lock")?;
        let guard = ExclusiveDirectory::open(&temporary.path)?;
        let executable = std::env::current_exe()?;

        let busy = Command::new(&executable)
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env(ROOT_ENV, &temporary.path)
            .env(MODE_ENV, "busy")
            .status()?;
        assert!(busy.success());

        drop(guard);

        let available = Command::new(executable)
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env(ROOT_ENV, &temporary.path)
            .env(MODE_ENV, "available")
            .status()?;
        assert!(available.success());
        Ok(())
    }

    #[test]
    fn descriptor_survives_root_path_replacement() -> Result<(), Box<dyn Error>> {
        let _serial = serial_test();
        let temporary = TemporaryDirectory::new("rename")?;
        let guard = ExclusiveDirectory::open(&temporary.path)?;
        let moved = temporary.path.with_file_name(format!(
            "{}-moved",
            temporary
                .path
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| io::Error::other("temporary path is not UTF-8"))?
        ));
        fs::rename(&temporary.path, &moved)?;
        fs::create_dir(&temporary.path)?;

        let anchored = guard.leaf_path("anchored.hb")?;
        fs::write(&anchored, b"old-root")?;
        guard.sync_all()?;
        assert_eq!(fs::read(moved.join("anchored.hb"))?, b"old-root");
        assert!(!temporary.path.join("anchored.hb").exists());
        Ok(())
    }

    #[test]
    fn symlink_root_is_rejected() -> Result<(), Box<dyn Error>> {
        let _serial = serial_test();
        let target = TemporaryDirectory::new("target")?;
        let link_parent = TemporaryDirectory::new("link-parent")?;
        let link = link_parent.path.join("root-link");
        symlink(&target.path, &link)?;
        let result = ExclusiveDirectory::open(&link);
        assert!(matches!(result, Err(DirectoryGuardError::UnsafeRoot)));
        Ok(())
    }

    #[test]
    fn relative_root_is_rejected() {
        let _serial = serial_test();
        let result = ExclusiveDirectory::open("relative-root");
        assert!(matches!(
            result,
            Err(DirectoryGuardError::RootMustBeAbsolute)
        ));
    }

    #[test]
    fn intermediate_symlink_is_rejected() -> Result<(), Box<dyn Error>> {
        let _serial = serial_test();
        let target = TemporaryDirectory::new("ancestor-target")?;
        let link_parent = TemporaryDirectory::new("ancestor-link-parent")?;
        let ancestor_link = link_parent.path.join("redirected");
        symlink(&target.path, &ancestor_link)?;
        let nested = target.path.join("nested");
        fs::create_dir(&nested)?;

        let result = ExclusiveDirectory::open(ancestor_link.join("nested"));
        assert!(matches!(result, Err(DirectoryGuardError::UnsafeRoot)));
        Ok(())
    }
}
