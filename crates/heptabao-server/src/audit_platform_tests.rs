//! These tests execute on both Linux x86_64 and aarch64 in the workspace gate.
use super::{open_directory, open_read, private_options};
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "heptabao-audit-abi-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn target_abi_opens_private_regular_files_and_real_directories() -> TestResult {
    let root = Root::new()?;
    assert!(open_directory(&root.0)?.metadata()?.is_dir());
    let path = root.0.join("audit.jsonl");
    let mut file = private_options(true)
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(b"synthetic audit fixture\n")?;
    file.sync_all()?;
    assert_eq!(file.metadata()?.permissions().mode() & 0o777, 0o600);
    assert_eq!(open_read(&path)?.metadata()?.len(), 24);
    assert!(open_directory(&path).is_err());
    Ok(())
}

#[test]
fn target_abi_rejects_leaf_and_intermediate_symlinks() -> TestResult {
    let root = Root::new()?;
    let path = root.0.join("audit.jsonl");
    private_options(true)
        .write(true)
        .create_new(true)
        .open(&path)?;
    let alias = root.0.join("alias");
    symlink(&path, &alias)?;
    assert!(open_read(&alias).is_err());
    let directory = root.0.join("directory");
    fs::create_dir(&directory)?;
    let linked_directory = root.0.join("linked-directory");
    symlink(&directory, &linked_directory)?;
    assert!(open_directory(&linked_directory).is_err());
    fs::create_dir(directory.join("child"))?;
    assert!(open_directory(&linked_directory.join("child")).is_err());
    Ok(())
}

#[test]
fn target_abi_rejects_group_or_world_writable_audit_directories() -> TestResult {
    let root = Root::new()?;
    for mode in [0o770, 0o707] {
        fs::set_permissions(&root.0, fs::Permissions::from_mode(mode))?;
        assert!(open_directory(&root.0).is_err());
    }
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700))?;
    assert!(open_directory(&root.0).is_ok());
    Ok(())
}
