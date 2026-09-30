use super::{DirectoryGuardError, ExclusiveDirectory, FileAccess};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::symlink,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().canonicalize()?.join(format!(
            "heptabao-relative-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn read(root: &ExclusiveDirectory, name: &str) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    root.open_file(name, FileAccess::Read)?
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[test]
fn unix_relative_io_and_independent_inventory_stay_on_held_directory() -> TestResult {
    let root = Root::new()?;
    let original = root.0.join("original");
    fs::create_dir(&original)?;
    let owner = ExclusiveDirectory::open(&original)?;
    let mut first = owner.open_file("old", FileAccess::CreateNew)?;
    first.write_all(b"original")?;
    first.sync_all()?;
    let moved = root.0.join("moved");
    fs::rename(&original, &moved)?;
    fs::create_dir(&original)?;
    fs::write(original.join("old"), b"unrelated")?;
    fs::write(original.join("new"), b"replacement")?;
    for _ in 0..3 {
        assert_eq!(
            owner.entries()?.collect::<io::Result<Vec<_>>>()?,
            vec![std::ffi::OsString::from("old")]
        );
    }
    owner.rename("old", "new")?;
    owner.sync_all()?;
    owner
        .open_file("new", FileAccess::Append)?
        .write_all(b"-append")?;
    assert_eq!(read(&owner, "new")?, b"original-append");
    assert!(owner.entry_exists("new")?);
    assert!(!owner.entry_exists("old")?);
    let file = owner.open_file("new", FileAccess::Write)?;
    file.set_len(8)?;
    file.sync_all()?;
    assert_eq!(read(&owner, "new")?, b"original");
    owner.remove_file("new")?;
    owner.sync_all()?;
    assert!(owner.entries()?.next().is_none());
    assert_eq!(fs::read(original.join("old"))?, b"unrelated");
    assert_eq!(fs::read(original.join("new"))?, b"replacement");
    assert!(!moved.join("new").exists());
    Ok(())
}

#[test]
fn unix_relative_owner_preserves_exclusive_fence_across_path_rename() -> TestResult {
    let root = Root::new()?;
    let path = root.0.join("owned");
    fs::create_dir(&path)?;
    let first = ExclusiveDirectory::open(&path)?;
    let moved = root.0.join("moved");
    fs::rename(&path, &moved)?;
    assert!(matches!(
        ExclusiveDirectory::open(&moved),
        Err(DirectoryGuardError::WriterBusy)
    ));
    drop(first);
    ExclusiveDirectory::open(&moved)?.verify()?;
    Ok(())
}

#[test]
fn unix_relative_invalid_names_cannot_escape_or_create_files() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    for name in [
        "",
        ".",
        "..",
        "../outside",
        "/absolute",
        "nested/file",
        "./a",
        "a/",
        "a\0b",
    ] {
        assert!(owner.open_file(name, FileAccess::CreateNew).is_err());
        assert!(owner.entry_exists(name).is_err());
        assert!(owner.remove_file(name).is_err());
        assert!(owner.rename(name, "safe").is_err());
        assert!(owner.rename("safe", name).is_err());
    }
    assert!(owner.entries()?.next().is_none());
    Ok(())
}

#[test]
fn unix_relative_symlinks_hardlinks_and_fifo_are_rejected_without_target_changes() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    fs::write(root.0.join("sentinel"), b"unchanged")?;
    symlink(root.0.join("sentinel"), root.0.join("link"))?;
    fs::hard_link(root.0.join("sentinel"), root.0.join("hard"))?;
    fs::create_dir(root.0.join("directory"))?;
    assert!(
        std::process::Command::new("mkfifo")
            .arg(root.0.join("fifo"))
            .status()?
            .success()
    );
    for leaf in ["link", "hard", "directory", "fifo"] {
        for mode in [
            FileAccess::Read,
            FileAccess::Write,
            FileAccess::Append,
            FileAccess::CreateNew,
        ] {
            assert!(owner.open_file(leaf, mode).is_err(), "{leaf}");
        }
    }
    owner.remove_file("link")?;
    owner.remove_file("hard")?;
    assert_eq!(fs::read(root.0.join("sentinel"))?, b"unchanged");
    Ok(())
}

#[test]
fn unix_relative_intermediate_symlink_is_not_authority() -> TestResult {
    let root = Root::new()?;
    let original = root.0.join("original");
    fs::create_dir(&original)?;
    fs::create_dir(original.join("nested"))?;
    symlink(&original, root.0.join("alias"))?;
    assert!(matches!(
        ExclusiveDirectory::open(root.0.join("alias/nested")),
        Err(DirectoryGuardError::UnsafeRoot)
    ));
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unix_legacy_proc_path_api_has_no_original_path_fallback() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    assert!(matches!(
        owner.access_path(),
        Err(DirectoryGuardError::UnsupportedPlatform)
    ));
    assert!(matches!(
        owner.leaf_path("valid"),
        Err(DirectoryGuardError::UnsupportedPlatform)
    ));
    owner
        .open_file("valid", FileAccess::CreateNew)?
        .write_all(b"relative")?;
    assert_eq!(read(&owner, "valid")?, b"relative");
    Ok(())
}
