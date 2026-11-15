//! Descriptor-relative audit filesystem regressions for Linux and macOS.
use super::{open_directory, open_read, private_options};
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().canonicalize()?.join(format!(
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
    let directory = open_directory(&root.0)?;
    assert_eq!(
        open_read(&directory, Path::new("audit.jsonl"))?
            .metadata()?
            .len(),
        24
    );
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
    let opened = open_directory(&root.0)?;
    assert!(open_read(&opened, Path::new("alias")).is_err());
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

#[test]
fn target_abi_rejects_non_leaf_names_before_filesystem_effects() -> TestResult {
    use super::{ChildMode, open_child, remove_child, rename_child};
    let root = Root::new()?;
    let directory = open_directory(&root.0)?;
    for name in [
        "",
        ".",
        "..",
        "../outside",
        "/absolute",
        "a/b",
        "a/",
        "a/.",
        "./a",
        "a//",
        "a\0b",
    ] {
        let path = Path::new(name);
        assert!(
            open_child(&directory, path, ChildMode::CreateNew).is_err(),
            "{name:?}"
        );
        assert!(remove_child(&directory, path).is_err(), "{name:?}");
        assert!(
            rename_child(&directory, path, Path::new("new")).is_err(),
            "{name:?}"
        );
        assert!(
            rename_child(&directory, Path::new("old"), path).is_err(),
            "{name:?}"
        );
    }
    assert_eq!(fs::read_dir(&root.0)?.count(), 0);
    Ok(())
}

#[test]
fn target_abi_relative_operations_stay_in_the_opened_directory() -> TestResult {
    use super::{
        ChildMode, directory_entries, open_child, remove_child, rename_child, verify_identity,
    };
    let root = Root::new()?;
    let original = root.0.join("owned");
    fs::create_dir(&original)?;
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700))?;
    let directory = open_directory(&original)?;
    let mut file = open_child(&directory, Path::new("first"), ChildMode::CreateNew)?;
    file.write_all(b"anchored")?;
    file.sync_all()?;
    verify_identity(&file, &directory, Path::new("first"))?;
    let moved = root.0.join("moved");
    fs::rename(&original, &moved)?;
    fs::create_dir(&original)?;
    fs::write(original.join("first"), b"replacement first")?;
    fs::write(original.join("second"), b"replacement second")?;
    for _ in 0..3 {
        assert_eq!(
            directory_entries(&directory)?.collect::<io::Result<Vec<_>>>()?,
            vec![PathBuf::from("first")]
        );
    }
    rename_child(&directory, Path::new("first"), Path::new("second"))?;
    verify_identity(&file, &directory, Path::new("second"))?;
    assert!(verify_identity(&file, &directory, Path::new("first")).is_err());
    assert_eq!(fs::read(moved.join("second"))?, b"anchored");
    remove_child(&directory, Path::new("second"))?;
    assert!(directory_entries(&directory)?.next().is_none());
    assert_eq!(fs::read(original.join("first"))?, b"replacement first");
    assert_eq!(fs::read(original.join("second"))?, b"replacement second");
    Ok(())
}

#[test]
fn target_abi_rejects_hardlinks_fifos_and_directories_without_touching_occupants() -> TestResult {
    use super::{ChildMode, open_child};
    let root = Root::new()?;
    let directory = open_directory(&root.0)?;
    let mut sentinel = private_options(true)
        .write(true)
        .create_new(true)
        .open(root.0.join("sentinel"))?;
    sentinel.write_all(b"untouched")?;
    sentinel.sync_all()?;
    fs::hard_link(root.0.join("sentinel"), root.0.join("hardlink"))?;
    fs::create_dir(root.0.join("directory"))?;
    // Fixture creation only: Darwin has no mknodat. Exercise the identical
    // production openat refusal against an actual FIFO on both target systems.
    let created = std::process::Command::new("mkfifo")
        .args(["-m", "600"])
        .arg(root.0.join("fifo"))
        .status()?;
    assert!(created.success(), "FIFO fixture creation failed");
    for name in ["hardlink", "directory", "fifo"] {
        for mode in [
            ChildMode::Read,
            ChildMode::Append,
            ChildMode::WriterLock,
            ChildMode::CreateNew,
        ] {
            assert!(
                open_child(&directory, Path::new(name), mode).is_err(),
                "{name}"
            );
        }
    }
    assert_eq!(fs::read(root.0.join("sentinel"))?, b"untouched");
    Ok(())
}

#[test]
fn target_abi_key_creation_and_reopen_use_the_held_directory_after_rename() -> TestResult {
    use super::super::load_audit_key;
    use super::{AuditConfig, AuditRotation};
    let root = Root::new()?;
    let original = root.0.join("owned");
    fs::create_dir(&original)?;
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700))?;
    let (rotation, audit) =
        AuditRotation::open(&original.join("audit.jsonl"), AuditConfig::default())?;
    let moved = root.0.join("moved");
    fs::rename(&original, &moved)?;
    fs::create_dir(&original)?;
    fs::write(
        original.join("audit.jsonl.hmac-key"),
        b"unrelated replacement",
    )?;
    let first = load_audit_key(&rotation, &audit)?;
    let reopened = load_audit_key(&rotation, &audit)?;
    assert_eq!(
        ring::hmac::sign(&first, b"synthetic anchored key").as_ref(),
        ring::hmac::sign(&reopened, b"synthetic anchored key").as_ref(),
    );
    assert_eq!(fs::metadata(moved.join("audit.jsonl.hmac-key"))?.len(), 32);
    assert_eq!(
        fs::read(original.join("audit.jsonl.hmac-key"))?,
        b"unrelated replacement"
    );
    Ok(())
}

#[test]
fn target_abi_missing_active_symlink_key_is_never_reinitialized() -> TestResult {
    use super::{AuditConfig, AuditRotation};
    let root = Root::new()?;
    // A dangling key symlink is still evidence of an established/unsafe store.
    let key = root.0.join("audit.jsonl.hmac-key");
    symlink(root.0.join("not-created"), &key)?;
    assert!(AuditRotation::open(&root.0.join("audit.jsonl"), AuditConfig::default()).is_err());
    assert!(!root.0.join("audit.jsonl").exists());
    assert!(!root.0.join("not-created").exists());
    assert!(fs::symlink_metadata(&key)?.file_type().is_symlink());
    Ok(())
}
