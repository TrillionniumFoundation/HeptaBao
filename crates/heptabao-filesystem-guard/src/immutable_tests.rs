use super::*;
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const TEMP: &str = "native-v6-object.tmp";
const FINAL: &str = "nv6.0011223344556677.8899aabbccddeeff.hbo";
struct Root(PathBuf);
impl Root {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().canonicalize()?.join(format!(
            "heptabao-immutable-fs-{}-{}",
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
fn temporary(owner: &ExclusiveDirectory, bytes: &[u8]) -> io::Result<File> {
    let mut file = owner.open_file(TEMP, FileAccess::CreateNewReadWrite)?;
    file.write_all(bytes)?;
    Ok(file)
}
fn read_file(mut file: File) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[test]
fn immutable_publish_returns_actual_read_only_single_link_fd() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let temp = temporary(&owner, b"sealed-object")?;
    let ImmutablePublication::Published(mut published) =
        owner.publish_file_noreplace(TEMP, &temp, FINAL, 13)?
    else {
        return Err("first publication was not new".into());
    };
    assert_eq!(published.metadata()?.dev(), temp.metadata()?.dev());
    assert_eq!(published.metadata()?.ino(), temp.metadata()?.ino());
    assert_eq!(published.metadata()?.nlink(), 1);
    assert!(published.write_all(b"overwrite").is_err());
    assert!(!owner.entry_exists(TEMP)?);
    assert_eq!(read_file(published)?, b"sealed-object");
    assert_eq!(fs::read(root.0.join(FINAL))?, b"sealed-object");
    Ok(())
}

#[test]
fn immutable_existing_destination_is_preserved_and_returned_without_content_claim() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    fs::write(root.0.join(FINAL), b"old-cipher")?;
    let existing_identity = fs::metadata(root.0.join(FINAL))?.ino();
    let temp = temporary(&owner, b"new-cipher")?;
    let ImmutablePublication::AlreadyExists(existing) =
        owner.publish_file_noreplace(TEMP, &temp, FINAL, 10)?
    else {
        return Err("existing destination was replaced".into());
    };
    assert_eq!(existing.metadata()?.ino(), existing_identity);
    assert_eq!(read_file(existing)?, b"old-cipher");
    assert_eq!(fs::read(root.0.join(FINAL))?, b"old-cipher");
    assert_eq!(temp.metadata()?.nlink(), 0);
    assert!(!owner.entry_exists(TEMP)?);
    Ok(())
}

#[test]
fn immutable_existing_unsafe_or_wrong_length_destination_is_never_replaced() -> TestResult {
    for kind in ["symlink", "hardlink", "directory", "wrong-length", "fifo"] {
        let root = Root::new()?;
        let owner = ExclusiveDirectory::open(&root.0)?;
        fs::write(root.0.join("sentinel"), b"unchanged")?;
        match kind {
            "symlink" => symlink(root.0.join("sentinel"), root.0.join(FINAL))?,
            "hardlink" => fs::hard_link(root.0.join("sentinel"), root.0.join(FINAL))?,
            "directory" => fs::create_dir(root.0.join(FINAL))?,
            "wrong-length" => fs::write(root.0.join(FINAL), b"short")?,
            "fifo" => assert!(
                std::process::Command::new("mkfifo")
                    .arg(root.0.join(FINAL))
                    .status()?
                    .success()
            ),
            _ => unreachable!(),
        }
        let temp = temporary(&owner, b"candidate")?;
        assert!(
            matches!(
                owner.publish_file_noreplace(TEMP, &temp, FINAL, 9),
                Err(ImmutablePublicationError::BeforePublication(_))
            ),
            "{kind}"
        );
        assert_eq!(fs::read(root.0.join("sentinel"))?, b"unchanged");
        assert!(owner.entry_exists(TEMP)?);
    }
    Ok(())
}

#[test]
fn immutable_publication_remains_on_original_directory_after_path_replacement() -> TestResult {
    let root = Root::new()?;
    let original = root.0.join("original");
    fs::create_dir(&original)?;
    let owner = ExclusiveDirectory::open(&original)?;
    let temp = temporary(&owner, b"old-owner")?;
    let moved = root.0.join("moved");
    fs::rename(&original, &moved)?;
    fs::create_dir(&original)?;
    fs::write(original.join(FINAL), b"unrelated")?;
    fs::write(original.join(TEMP), b"unrelated")?;
    assert!(matches!(
        owner.publish_file_noreplace(TEMP, &temp, FINAL, 9)?,
        ImmutablePublication::Published(_)
    ));
    assert_eq!(fs::read(moved.join(FINAL))?, b"old-owner");
    assert!(!moved.join(TEMP).exists());
    assert_eq!(fs::read(original.join(FINAL))?, b"unrelated");
    assert_eq!(fs::read(original.join(TEMP))?, b"unrelated");
    Ok(())
}

#[test]
fn immutable_lost_ack_after_actual_link_has_typed_unknown_and_reopen_cleanup() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let temp = temporary(&owner, b"stable-object")?;
    assert!(matches!(
        owner.publish_file_noreplace_checked(
            TEMP,
            &temp,
            FINAL,
            13,
            || Ok(()),
            || {
                Err(io::Error::other(
                    "injected acknowledgement loss after actual linkat",
                ))
            }
        ),
        Err(ImmutablePublicationError::OutcomeUnknown(_))
    ));
    assert_eq!(temp.metadata()?.nlink(), 2);
    assert_eq!(fs::metadata(root.0.join(FINAL))?.nlink(), 2);
    assert!(owner.open_file(FINAL, FileAccess::Read).is_err());
    drop(temp);
    drop(owner);
    let reopened = ExclusiveDirectory::open(&root.0)?;
    assert!(reopened.cleanup_immutable_temporary(TEMP)?);
    assert!(!reopened.cleanup_immutable_temporary(TEMP)?);
    let final_file = reopened.open_file(FINAL, FileAccess::Read)?;
    assert_eq!(final_file.metadata()?.nlink(), 1);
    assert_eq!(read_file(final_file)?, b"stable-object");
    Ok(())
}

#[test]
fn immutable_source_name_swap_cannot_return_a_false_published_descriptor() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let temp = temporary(&owner, b"original")?;
    assert!(matches!(
        owner.publish_file_noreplace_checked(
            TEMP,
            &temp,
            FINAL,
            8,
            || {
                fs::rename(root.0.join(TEMP), root.0.join("original-fd"))?;
                fs::write(root.0.join(TEMP), b"impostor")
            },
            || Ok(())
        ),
        Err(ImmutablePublicationError::OutcomeUnknown(_))
    ));
    assert_eq!(fs::read(root.0.join("original-fd"))?, b"original");
    assert_eq!(fs::read(root.0.join(FINAL))?, b"impostor");
    assert_ne!(
        temp.metadata()?.ino(),
        fs::metadata(root.0.join(FINAL))?.ino()
    );
    Ok(())
}

#[test]
fn immutable_destination_swap_or_length_change_after_link_is_unknown() -> TestResult {
    for replace in [false, true] {
        let root = Root::new()?;
        let owner = ExclusiveDirectory::open(&root.0)?;
        let temp = temporary(&owner, b"original")?;
        assert!(matches!(
            owner.publish_file_noreplace_checked(
                TEMP,
                &temp,
                FINAL,
                8,
                || Ok(()),
                || {
                    if replace {
                        fs::remove_file(root.0.join(FINAL))?;
                        fs::write(root.0.join(FINAL), b"impostor")
                    } else {
                        temp.set_len(9)
                    }
                }
            ),
            Err(ImmutablePublicationError::OutcomeUnknown(_))
        ));
        assert!(owner.entry_exists(TEMP)?);
    }
    Ok(())
}

#[test]
fn immutable_wrong_descriptor_and_invalid_names_fail_before_link() -> TestResult {
    let root = Root::new()?;
    let other_root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let other = ExclusiveDirectory::open(&other_root.0)?;
    let temp = temporary(&owner, b"original")?;
    let foreign = temporary(&other, b"original")?;
    assert!(matches!(
        owner.publish_file_noreplace(TEMP, &foreign, FINAL, 8),
        Err(ImmutablePublicationError::BeforePublication(_))
    ));
    for invalid in [
        "",
        ".",
        "..",
        "../outside",
        "/absolute",
        "nested/file",
        "a\0b",
        "non-ascii-秘密",
    ] {
        assert!(matches!(
            owner.publish_file_noreplace(invalid, &temp, FINAL, 8),
            Err(ImmutablePublicationError::BeforePublication(_))
        ));
        assert!(matches!(
            owner.publish_file_noreplace(TEMP, &temp, invalid, 8),
            Err(ImmutablePublicationError::BeforePublication(_))
        ));
        assert!(matches!(
            owner.cleanup_immutable_temporary(invalid),
            Err(ImmutablePublicationError::BeforePublication(_))
        ));
    }
    assert!(matches!(
        owner.publish_file_noreplace(TEMP, &temp, TEMP, 8),
        Err(ImmutablePublicationError::BeforePublication(_))
    ));
    assert!(!owner.entry_exists(FINAL)?);
    assert_eq!(temp.metadata()?.nlink(), 1);
    assert_eq!(fs::read(root.0.join(TEMP))?, b"original");
    Ok(())
}

#[test]
fn immutable_temp_cleanup_never_follows_symlink_or_replacement_root_path() -> TestResult {
    let root = Root::new()?;
    let original = root.0.join("original");
    fs::create_dir(&original)?;
    let owner = ExclusiveDirectory::open(&original)?;
    fs::write(root.0.join("sentinel"), b"unchanged")?;
    symlink(root.0.join("sentinel"), original.join(TEMP))?;
    let moved = root.0.join("moved");
    fs::rename(&original, &moved)?;
    fs::create_dir(&original)?;
    fs::write(original.join(TEMP), b"unrelated")?;
    assert!(owner.cleanup_immutable_temporary(TEMP)?);
    assert!(!moved.join(TEMP).exists());
    assert_eq!(fs::read(root.0.join("sentinel"))?, b"unchanged");
    assert_eq!(fs::read(original.join(TEMP))?, b"unrelated");
    Ok(())
}
