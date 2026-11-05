//! Real descriptor tests. No metadata publication or typed graph authority is
//! inferred here; the durable/server tests own those separate assertions.
use super::*;
use std::{
    cell::Cell,
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().canonicalize()?.join(format!(
            "heptabao-retirement-fs-{}-{}",
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
fn add(owner: &ExclusiveDirectory, name: &str, bytes: &[u8]) -> io::Result<()> {
    let mut file = owner.open_file(name, FileAccess::CreateNew)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    owner.sync_all().map_err(io::Error::other)
}
fn gate() -> io::Result<()> {
    Ok(())
}
fn authenticate(_: usize, file: &File) -> io::Result<()> {
    let mut fd = file;
    let mut bytes = Vec::new();
    fd.read_to_end(&mut bytes)?;
    if bytes != b"original-A" {
        return Err(io::Error::other("unexpected fixture bytes"));
    }
    Ok(())
}

#[test]
fn immutable_retirement_real_fd_sync_and_exact_absence() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    add(&owner, "one", b"original-A")?;
    add(&owner, "keep", b"retained")?;
    let prepared = owner.prepare_file_retirement("one", 10)?;
    assert!(prepared.file().try_clone()?.write_all(b"invalid").is_err());
    let original = prepared.file().try_clone()?;
    owner.retire_files_checked(vec![prepared], &mut authenticate, &mut gate)?;
    assert_eq!(original.metadata()?.nlink(), 0);
    assert!(!owner.entry_exists("one")?);
    assert_eq!(fs::read(root.0.join("keep"))?, b"retained");
    Ok(())
}

#[test]
fn immutable_retirement_pre_unlink_gate_has_zero_effects() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    add(&owner, "one", b"original-A")?;
    let prepared = owner.prepare_file_retirement("one", 10)?;
    let calls = Cell::new(0);
    let mut auth = |_: usize, _: &File| {
        calls.set(calls.get() + 1);
        Ok(())
    };
    let result = owner.retire_files_checked(vec![prepared], &mut auth, &mut || {
        Err(io::Error::other("original deadline expired"))
    });
    assert!(matches!(result, Err(FileRetirementError::BeforeUnlink(_))));
    assert_eq!(calls.get(), 0);
    assert_eq!(fs::read(root.0.join("one"))?, b"original-A");
    Ok(())
}

#[test]
fn immutable_retirement_same_inode_rewrite_aba_is_not_reaccepted() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    add(&owner, "one", b"original-A")?;
    let prepared = owner.prepare_file_retirement("one", 10)?;
    let inode = prepared.file().metadata()?.ino();
    let modified = prepared.file().metadata()?.modified()?;
    for bytes in [b"differentB", b"original-A"] {
        let mut writer = owner.open_file("one", FileAccess::Write)?;
        writer.write_all(bytes)?;
        writer.set_modified(modified)?;
        writer.sync_all()?;
    }
    assert_eq!(fs::metadata(root.0.join("one"))?.ino(), inode);
    assert_eq!(fs::metadata(root.0.join("one"))?.modified()?, modified);
    let result = owner.retire_files_checked(vec![prepared], &mut authenticate, &mut gate);
    assert!(matches!(result, Err(FileRetirementError::BeforeUnlink(_))));
    assert_eq!(fs::read(root.0.join("one"))?, b"original-A");
    Ok(())
}

#[test]
fn immutable_retirement_replaced_leaf_is_not_unlinked() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    add(&owner, "one", b"original-A")?;
    let prepared = owner.prepare_file_retirement("one", 10)?;
    fs::rename(root.0.join("one"), root.0.join("original"))?;
    add(&owner, "one", b"replacement")?;
    let result = owner.retire_files_checked(vec![prepared], &mut authenticate, &mut gate);
    assert!(matches!(result, Err(FileRetirementError::BeforeUnlink(_))));
    assert_eq!(fs::read(root.0.join("one"))?, b"replacement");
    assert_eq!(fs::read(root.0.join("original"))?, b"original-A");
    Ok(())
}

#[test]
fn immutable_retirement_directory_sync_loss_is_unknown_not_retry() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    add(&owner, "one", b"original-A")?;
    let prepared = owner.prepare_file_retirement("one", 10)?;
    let original = prepared.file().try_clone()?;
    let result =
        owner.retire_files_with_sync(vec![prepared], &mut authenticate, &mut gate, &mut || {
            Err(io::Error::other(
                "injected directory barrier acknowledgement loss",
            ))
        });
    assert!(matches!(
        result,
        Err(FileRetirementError::OutcomeUnknown(_))
    ));
    assert_eq!(original.metadata()?.nlink(), 0);
    assert!(!owner.entry_exists("one")?);
    assert!(owner.prepare_file_retirement("one", 10).is_err());
    Ok(())
}

#[test]
fn immutable_retirement_after_first_unlink_holds_remaining_members() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    add(&owner, "one", b"original-A")?;
    add(&owner, "two", b"original-A")?;
    let first = owner.prepare_file_retirement("one", 10)?;
    let second = owner.prepare_file_retirement("two", 10)?;
    let mut auth = |index: usize, file: &File| {
        if index == 1 {
            return Err(io::Error::other("second object gate refused"));
        }
        authenticate(index, file)
    };
    let result = owner.retire_files_checked(vec![first, second], &mut auth, &mut gate);
    assert!(matches!(
        result,
        Err(FileRetirementError::OutcomeUnknown(_))
    ));
    assert!(!owner.entry_exists("one")?);
    assert_eq!(fs::read(root.0.join("two"))?, b"original-A");
    Ok(())
}

#[test]
fn immutable_retirement_is_anchored_to_original_directory_after_path_swap() -> TestResult {
    let root = Root::new()?;
    let original = root.0.join("original");
    fs::create_dir(&original)?;
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700))?;
    let owner = ExclusiveDirectory::open(&original)?;
    add(&owner, "one", b"original-A")?;
    let prepared = owner.prepare_file_retirement("one", 10)?;
    let moved = root.0.join("moved");
    fs::rename(&original, &moved)?;
    fs::create_dir(&original)?;
    fs::write(original.join("one"), b"replacement-owner")?;
    owner.retire_files_checked(vec![prepared], &mut authenticate, &mut gate)?;
    assert!(!moved.join("one").exists());
    assert_eq!(fs::read(original.join("one"))?, b"replacement-owner");
    Ok(())
}
