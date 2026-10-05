//! Darwin SDK image snapshots. This is installed trusted plugin execution,
//! not OS containment and not a claim of Linux memfd equivalence.
use crate::SandboxFailure;
use ring::digest::{Context, SHA256};
use rustix::fs::OFlags;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(1);
const MAX_IMAGE: u64 = 256 * 1024 * 1024;
/// Owned private immutable copy retained by inode, read-only fd and full SHA256.
pub struct OwnedExecutableImage {
    image: File,
    path: PathBuf,
    expected: [u8; 32],
    identity: (u64, u64, u64),
}
impl std::fmt::Debug for OwnedExecutableImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OwnedExecutableImage([REDACTED])")
    }
}
fn fingerprint(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64, u32, u32, u64) {
    (
        m.dev(),
        m.ino(),
        m.size(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.mode(),
        m.uid(),
        m.nlink(),
    )
}
impl OwnedExecutableImage {
    pub fn open_in(
        path: &Path,
        expected: [u8; 32],
        directory: &Path,
    ) -> Result<Self, SandboxFailure> {
        Self::snapshot(path, expected, directory).map_err(|_| SandboxFailure::BeforeEntry)
    }
    fn snapshot(source: &Path, expected: [u8; 32], directory: &Path) -> io::Result<Self> {
        if !source.is_absolute() || !directory.is_absolute() {
            return Err(io::Error::other("absolute SDK paths required"));
        }
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(
            OFlags::NOFOLLOW
                .bits()
                .try_into()
                .map_err(|_| io::Error::other("Darwin flags"))?,
        );
        let mut source = options.open(source)?;
        let before = source.metadata()?;
        if !before.is_file()
            || before.size() == 0
            || before.size() > MAX_IMAGE
            || before.mode() & 0o111 == 0
        {
            return Err(io::Error::other("SDK executable image rejected"));
        }
        let path = directory.join(format!(
            "image-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&path)?;
        let result = (|| {
            let mut digest = Context::new(&SHA256);
            let mut total = 0u64;
            let mut block = [0u8; 65536];
            loop {
                let n = source.read(&mut block)?;
                if n == 0 {
                    break;
                }
                total = total
                    .checked_add(n as u64)
                    .ok_or_else(|| io::Error::other("image length"))?;
                if total > MAX_IMAGE {
                    return Err(io::Error::other("image grew"));
                }
                writer.write_all(&block[..n])?;
                digest.update(&block[..n]);
            }
            if total != before.size()
                || digest.finish().as_ref() != expected
                || fingerprint(&before) != fingerprint(&source.metadata()?)
            {
                return Err(io::Error::other("original SDK image changed"));
            }
            writer.sync_all()?;
            drop(writer);
            let image = options.open(&path)?;
            let m = image.metadata()?;
            let owned = Self {
                image,
                path: path.clone(),
                expected,
                identity: (m.dev(), m.ino(), m.size()),
            };
            heptabao_linux_parent_death::set_owned_file_immutable(&owned.image, true)?;
            Ok(owned)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&path);
        }
        let image = result?;
        image.verify()?;
        Ok(image)
    }
    pub fn verify(&self) -> io::Result<()> {
        let m = fs::symlink_metadata(&self.path)?;
        let fd = self.image.metadata()?;
        if !m.is_file()
            || m.mode() & 0o077 != 0
            || m.nlink() != 1
            || m.uid() != rustix::process::getuid().as_raw()
            || (m.dev(), m.ino(), m.size()) != self.identity
            || fingerprint(&m) != fingerprint(&fd)
        {
            return Err(io::Error::other("SDK owned image identity changed"));
        }
        let mut file = File::open(&self.path)?;
        if (
            file.metadata()?.dev(),
            file.metadata()?.ino(),
            file.metadata()?.size(),
        ) != self.identity
        {
            return Err(io::Error::other("SDK owned image open changed"));
        }
        let mut digest = Context::new(&SHA256);
        let mut block = [0u8; 65536];
        loop {
            let n = file.read(&mut block)?;
            if n == 0 {
                break;
            }
            digest.update(&block[..n]);
        }
        if digest.finish().as_ref() != self.expected
            || fingerprint(&m) != fingerprint(&file.metadata()?)
        {
            return Err(io::Error::other("SDK owned image digest changed"));
        }
        Ok(())
    }
    pub fn command(&self) -> Command {
        Command::new(&self.path)
    }
    pub fn descriptor_path(&self) -> &Path {
        &self.path
    }
    pub fn original_file(&self) -> &File {
        &self.image
    }
    pub fn cleanup_identity(&self) -> (u64, u64, u64) {
        self.identity
    }
    pub fn identity(&self) -> io::Result<(u64, u64)> {
        let m = self.image.metadata()?;
        Ok((m.dev(), m.ino()))
    }
}
impl Drop for OwnedExecutableImage {
    fn drop(&mut self) {
        let _ = heptabao_linux_parent_death::set_owned_file_immutable(&self.image, false);
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|m| (m.dev(), m.ino(), m.size()) == self.identity)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}
