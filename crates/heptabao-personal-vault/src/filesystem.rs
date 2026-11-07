use crate::crypto::{digest, random};
use crate::{MAX_FILE_BYTES, Result, VaultError};
use heptabao_filesystem_guard::{
    DirectoryGuardError, ExclusiveDirectory, FileAccess, ImmutablePublication,
    ImmutablePublicationError,
};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

pub(crate) fn open_directory(root: &Path) -> Result<ExclusiveDirectory> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let guard = ExclusiveDirectory::open(root).map_err(|e| match e {
            DirectoryGuardError::WriterBusy => VaultError::Busy,
            DirectoryGuardError::UnsupportedPlatform => VaultError::UnsupportedPlatform,
            _ => VaultError::UnsafePath,
        })?;
        let m = std::fs::symlink_metadata(root).map_err(|_| VaultError::UnsafePath)?;
        if !m.is_dir()
            || m.mode() & 0o777 != 0o700
            || m.uid() != rustix::process::geteuid().as_raw()
            || m.dev() != guard.identity().device()
            || m.ino() != guard.identity().inode()
        {
            return Err(VaultError::UnsafePath);
        }
        Ok(guard)
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(VaultError::UnsupportedPlatform)
    }
}
fn checked_file(file: File) -> Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata().map_err(|_| VaultError::Io)?;
        if !m.is_file()
            || m.nlink() != 1
            || m.mode() & 0o777 != 0o600
            || m.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(VaultError::UnsafePath);
        }
        if m.len() > MAX_FILE_BYTES as u64 {
            return Err(VaultError::TooLarge);
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Err(VaultError::UnsupportedPlatform)
    }
}
fn read_leaf(dir: &ExclusiveDirectory, name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let file = dir.open_file(name, FileAccess::Read).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            VaultError::Missing
        } else {
            VaultError::UnsafePath
        }
    })?;
    let file = checked_file(file)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| VaultError::Io)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(VaultError::TooLarge);
    }
    Ok(bytes)
}
pub(crate) fn read_vault(dir: &ExclusiveDirectory) -> Result<Vec<u8>> {
    Ok(read_leaf(dir, "vault.hbv")?.to_vec())
}
fn temp_name() -> Result<String> {
    let token = random::<16>()?;
    let mut s = String::from("pending-");
    for b in token {
        use std::fmt::Write;
        write!(&mut s, "{b:02x}").map_err(|_| VaultError::Io)?;
    }
    Ok(s)
}
pub(crate) fn publish_vault(
    dir: &ExclusiveDirectory,
    bytes: &[u8],
    expected: Option<[u8; 32]>,
) -> Result<()> {
    publish(dir, "vault.hbv", bytes, expected)
}
fn publish(
    dir: &ExclusiveDirectory,
    name: &str,
    bytes: &[u8],
    expected: Option<[u8; 32]>,
) -> Result<()> {
    publish_with_readback(dir, name, bytes, expected, || read_leaf(dir, name))
}
fn publish_with_readback(
    dir: &ExclusiveDirectory,
    name: &str,
    bytes: &[u8],
    expected: Option<[u8; 32]>,
    readback: impl FnOnce() -> Result<Zeroizing<Vec<u8>>>,
) -> Result<()> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(VaultError::TooLarge);
    }
    if let Some(hash) = expected {
        if digest(&read_leaf(dir, name)?) != hash {
            return Err(VaultError::Conflict);
        }
    } else if dir.entry_exists(name).map_err(|_| VaultError::UnsafePath)? {
        return Err(VaultError::Exists);
    }
    let temp = temp_name()?;
    let mut file = dir
        .open_file(&temp, FileAccess::CreateNewReadWrite)
        .map_err(|_| VaultError::Io)?;
    if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
        let _ = dir.remove_file(&temp);
        return Err(VaultError::Io);
    }
    if let Some(hash) = expected {
        match read_leaf(dir, name) {
            Ok(current) if digest(&current) == hash => {}
            _ => {
                let _ = dir.remove_file(&temp);
                return Err(VaultError::Conflict);
            }
        }
        if dir.rename(&temp, name).is_err() {
            let _ = dir.remove_file(&temp);
            return Err(VaultError::OutcomeUnknown);
        }
        dir.sync_all().map_err(|_| VaultError::OutcomeUnknown)?;
    } else {
        match dir.publish_file_noreplace(&temp, &file, name, bytes.len() as u64) {
            Ok(ImmutablePublication::Published(_)) => {}
            Ok(ImmutablePublication::AlreadyExists(_)) => {
                let _ = dir.remove_file(&temp);
                return Err(VaultError::Exists);
            }
            Err(ImmutablePublicationError::BeforePublication(_)) => {
                let _ = dir.remove_file(&temp);
                return Err(VaultError::Io);
            }
            Err(ImmutablePublicationError::OutcomeUnknown(_)) => {
                return Err(VaultError::OutcomeUnknown);
            }
        }
    }
    // Publication has already happened: a failed readback cannot report a
    // pre-publication error or imply that retrying this write is safe.
    let published = readback().map_err(|_| VaultError::OutcomeUnknown)?;
    if digest(&published) != digest(bytes) {
        return Err(VaultError::OutcomeUnknown);
    }
    Ok(())
}
/// Read only a private regular file through a no-symlink, private parent descriptor.
pub fn read_private_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let parent = path.parent().ok_or(VaultError::UnsafePath)?;
    let name = path
        .file_name()
        .and_then(|x| x.to_str())
        .ok_or(VaultError::UnsafePath)?;
    let guard = open_directory(parent)?;
    read_leaf(&guard, name)
}
/// Secret export is explicit, create-only and fsynced. It never overwrites a destination.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(VaultError::UnsafePath)?;
    let name = path
        .file_name()
        .and_then(|x| x.to_str())
        .ok_or(VaultError::UnsafePath)?;
    let guard = open_directory(parent)?;
    publish(&guard, name, bytes, None)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::error::Error;
    use std::os::unix::fs::DirBuilderExt;

    #[test]
    fn readback_fault_after_publication_is_unknown_and_not_replayed()
    -> std::result::Result<(), Box<dyn Error>> {
        let token = temp_name()?;
        let root =
            std::env::temp_dir().join(format!("hb-vault-publish-{}-{token}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        let dir = open_directory(&root)?;
        let first = b"synthetic ciphertext version one";
        assert_eq!(
            publish_with_readback(&dir, "vault.hbv", first, None, || Err(VaultError::Io)),
            Err(VaultError::OutcomeUnknown)
        );
        assert_eq!(&*read_leaf(&dir, "vault.hbv")?, first);
        assert_eq!(
            publish(&dir, "vault.hbv", first, None),
            Err(VaultError::Exists)
        );
        let second = b"synthetic ciphertext version two";
        assert_eq!(
            publish_with_readback(&dir, "vault.hbv", second, Some(digest(first)), || Err(
                VaultError::UnsafePath
            )),
            Err(VaultError::OutcomeUnknown)
        );
        assert_eq!(&*read_leaf(&dir, "vault.hbv")?, second);
        assert_eq!(
            publish(&dir, "vault.hbv", first, Some(digest(first))),
            Err(VaultError::Conflict)
        );
        drop(dir);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
