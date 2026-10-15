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
        owner.publish_file_noreplace_with_hooks(
            TEMP,
            &temp,
            FINAL,
            13,
            &mut || Ok::<(), std::convert::Infallible>(()),
            (
                || Ok(()),
                || Err(io::Error::other("lost acknowledgement after actual linkat"))
            )
        ),
        Err(ImmutablePublicationCheckedError::Publication(
            ImmutablePublicationError::OutcomeUnknown(_)
        ))
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
        owner.publish_file_noreplace_with_hooks(
            TEMP,
            &temp,
            FINAL,
            8,
            &mut || Ok::<(), std::convert::Infallible>(()),
            (
                || {
                    fs::rename(root.0.join(TEMP), root.0.join("original-fd"))?;
                    fs::write(root.0.join(TEMP), b"impostor")
                },
                || Ok(())
            )
        ),
        Err(ImmutablePublicationCheckedError::Publication(
            ImmutablePublicationError::OutcomeUnknown(_)
        ))
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
            owner.publish_file_noreplace_with_hooks(
                TEMP,
                &temp,
                FINAL,
                8,
                &mut || Ok::<(), std::convert::Infallible>(()),
                (
                    || Ok(()),
                    || {
                        if replace {
                            fs::remove_file(root.0.join(FINAL))?;
                            fs::write(root.0.join(FINAL), b"impostor")
                        } else {
                            temp.set_len(9)
                        }
                    }
                )
            ),
            Err(ImmutablePublicationCheckedError::Publication(
                ImmutablePublicationError::OutcomeUnknown(_)
            ))
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

#[test]
fn immutable_original_deadline_expired_after_real_temp_sync_blocks_final_link() -> TestResult {
    use std::time::{Duration, Instant};
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let temp = temporary(&owner, b"original")?;
    let original_deadline = Instant::now() + Duration::from_millis(500);
    let mut gate = || {
        if Instant::now() >= original_deadline {
            Err(io::Error::other("original deadline expired"))
        } else {
            Ok(())
        }
    };
    let mut synced_boundary_observed = false;
    let result = owner.publish_file_noreplace_with_hooks(
        TEMP,
        &temp,
        FINAL,
        8,
        &mut gate,
        (
            || {
                // The hook is after the actual temporary descriptor sync_all.
                synced_boundary_observed = true;
                std::thread::sleep(Duration::from_millis(550));
                Ok(())
            },
            || Ok(()),
        ),
    );
    assert!(synced_boundary_observed);
    assert!(matches!(
        result,
        Err(ImmutablePublicationCheckedError::GateBeforeLink(_))
    ));
    assert!(!owner.entry_exists(FINAL)?);
    assert_eq!(temp.metadata()?.nlink(), 1);
    assert_eq!(fs::read(root.0.join(TEMP))?, b"original");
    Ok(())
}

#[test]
fn immutable_gate_after_actual_link_is_an_orphan_not_an_io_unknown() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let temp = temporary(&owner, b"original")?;
    let mut gate = || {
        if owner.entry_exists(FINAL)? {
            Err(io::Error::other("custody ended after link"))
        } else {
            Ok(())
        }
    };
    assert!(matches!(
        owner.publish_file_noreplace_checked(TEMP, &temp, FINAL, 8, &mut gate),
        Err(ImmutablePublicationCheckedError::GateAfterLink(_))
    ));
    assert_eq!(temp.metadata()?.nlink(), 2);
    assert_eq!(fs::read(root.0.join(FINAL))?, b"original");
    assert!(owner.cleanup_immutable_temporary(TEMP)?);
    assert_eq!(
        owner
            .open_file(FINAL, FileAccess::Read)?
            .metadata()?
            .nlink(),
        1
    );
    Ok(())
}

#[test]
fn bounded_batch_returns_all_exact_readonly_files_after_final_gate() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let mut first = owner.open_file("batch-a.tmp", FileAccess::CreateNewReadWrite)?;
    first.write_all(b"first")?;
    let mut second = owner.open_file("batch-b.tmp", FileAccess::CreateNewReadWrite)?;
    second.write_all(b"second")?;
    let entries = [
        ImmutableBatchEntry {
            temporary: "batch-a.tmp",
            file: &first,
            destination: "batch-a.final",
            exact_len: 5,
        },
        ImmutableBatchEntry {
            temporary: "batch-b.tmp",
            file: &second,
            destination: "batch-b.final",
            exact_len: 6,
        },
    ];
    let mut gates = 0;
    let result = owner.publish_files_noreplace_checked(&entries, &mut || {
        gates += 1;
        Ok::<_, io::Error>(())
    })?;
    assert_eq!(result.len(), 2);
    assert!(gates > 10);
    for (result, expected) in result
        .into_iter()
        .zip([b"first".as_slice(), b"second".as_slice()])
    {
        let ImmutablePublication::Published(mut file) = result else {
            return Err("unexpected existing member".into());
        };
        assert_eq!(file.metadata()?.nlink(), 1);
        assert!(file.write_all(b"x").is_err());
        assert_eq!(read_file(file)?, expected);
    }
    Ok(())
}

#[test]
fn bounded_batch_rejects_alias_before_any_publication() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let first = temporary(&owner, b"first")?;
    let entries = [
        ImmutableBatchEntry {
            temporary: TEMP,
            file: &first,
            destination: FINAL,
            exact_len: 5,
        },
        ImmutableBatchEntry {
            temporary: TEMP,
            file: &first,
            destination: "other",
            exact_len: 5,
        },
    ];
    assert!(
        owner
            .publish_files_noreplace_checked(&entries, &mut || Ok::<_, io::Error>(()))
            .is_err()
    );
    assert!(!owner.entry_exists(FINAL)?);
    assert!(owner.entry_exists(TEMP)?);
    Ok(())
}

#[test]
fn bounded_batch_every_gate_rejection_withholds_all_completion() -> TestResult {
    // First observe the actual number of gates, then reject every boundary.
    let mut count = 0;
    {
        let root = Root::new()?;
        let owner = ExclusiveDirectory::open(&root.0)?;
        let temp = temporary(&owner, b"fixture")?;
        owner.publish_files_noreplace_checked(
            &[ImmutableBatchEntry {
                temporary: TEMP,
                file: &temp,
                destination: FINAL,
                exact_len: 7,
            }],
            &mut || {
                count += 1;
                Ok::<_, io::Error>(())
            },
        )?;
    }
    for reject in 1..=count {
        let root = Root::new()?;
        let owner = ExclusiveDirectory::open(&root.0)?;
        let temp = temporary(&owner, b"fixture")?;
        let mut calls = 0;
        let result = owner.publish_files_noreplace_checked(
            &[ImmutableBatchEntry {
                temporary: TEMP,
                file: &temp,
                destination: FINAL,
                exact_len: 7,
            }],
            &mut || {
                calls += 1;
                if calls == reject {
                    Err(io::Error::other("owned negative gate"))
                } else {
                    Ok(())
                }
            },
        );
        assert!(result.is_err(), "gate {reject} produced a completion");
        assert_eq!(calls, reject);
    }
    Ok(())
}

#[test]
fn bounded_batch_final_strong_sync_failure_returns_no_receipt() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let temp = temporary(&owner, b"fixture")?;
    let mut flushes = 0;
    let result = owner.publish_files_noreplace_with_final_sync(
        &[ImmutableBatchEntry {
            temporary: TEMP,
            file: &temp,
            destination: FINAL,
            exact_len: 7,
        }],
        &mut || Ok::<_, io::Error>(()),
        &mut |_file| {
            flushes += 1;
            assert!(root.0.join(FINAL).is_file());
            assert!(!root.0.join(TEMP).exists());
            Err(io::Error::other("synthetic strong flush failure"))
        },
    );
    assert!(matches!(
        result,
        Err(ImmutablePublicationCheckedError::Publication(
            ImmutablePublicationError::OutcomeUnknown(_)
        ))
    ));
    assert_eq!(flushes, 1);
    Ok(())
}

#[test]
fn bounded_batch_destination_replacement_at_final_barrier_is_rejected() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let temp = temporary(&owner, b"fixture")?;
    let result = owner.publish_files_noreplace_with_final_sync(
        &[ImmutableBatchEntry {
            temporary: TEMP,
            file: &temp,
            destination: FINAL,
            exact_len: 7,
        }],
        &mut || Ok::<_, io::Error>(()),
        &mut |file| {
            file.sync_all()?;
            fs::rename(root.0.join(FINAL), root.0.join("retired-original"))?;
            fs::write(root.0.join(FINAL), b"fixture")?;
            Ok(())
        },
    );
    assert!(result.is_err());
    Ok(())
}

#[test]
fn bounded_batch_one_final_strong_flush_covers_all_members() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let names = [
        ("a.tmp", "a.final"),
        ("b.tmp", "b.final"),
        ("c.tmp", "c.final"),
        ("d.tmp", "d.final"),
    ];
    let mut files = Vec::new();
    for (temp, _) in names {
        let mut f = owner.open_file(temp, FileAccess::CreateNewReadWrite)?;
        f.write_all(b"fixture")?;
        files.push(f);
    }
    let entries: Vec<_> = files
        .iter()
        .zip(names)
        .map(|(f, (t, d))| ImmutableBatchEntry {
            temporary: t,
            file: f,
            destination: d,
            exact_len: 7,
        })
        .collect();
    let mut flushes = 0;
    let result = owner.publish_files_noreplace_with_final_sync(
        &entries,
        &mut || Ok::<_, io::Error>(()),
        &mut |f| {
            for (temp, destination) in names {
                assert!(!root.0.join(temp).exists());
                assert!(root.0.join(destination).is_file());
            }
            flushes += 1;
            f.sync_all()
        },
    )?;
    assert_eq!(result.len(), 4);
    assert_eq!(flushes, 1);
    Ok(())
}

#[test]
fn bounded_batch_limit_and_empty_are_readonly_rejections() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let temp = temporary(&owner, b"fixture")?;
    assert!(
        owner
            .publish_files_noreplace_checked(&[], &mut || Ok::<_, io::Error>(()))
            .is_err()
    );
    let entries: Vec<_> = (0..5)
        .map(|_| ImmutableBatchEntry {
            temporary: TEMP,
            file: &temp,
            destination: FINAL,
            exact_len: 7,
        })
        .collect();
    assert!(
        owner
            .publish_files_noreplace_checked(&entries, &mut || Ok::<_, io::Error>(()))
            .is_err()
    );
    assert!(!owner.entry_exists(FINAL)?);
    assert!(owner.entry_exists(TEMP)?);
    Ok(())
}

#[test]
fn thirty_two_member_batch_keeps_one_final_strong_flush_and_thirty_third_is_refused() -> TestResult
{
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    assert_eq!(MAX_IMMUTABLE_BATCH_OBJECTS, 32);
    let names: Vec<(String, String)> = (0..=MAX_IMMUTABLE_BATCH_OBJECTS)
        .map(|index| {
            (
                format!("batch32-{index}.tmp"),
                format!("batch32-{index}.final"),
            )
        })
        .collect();
    let mut files = Vec::new();
    for (temporary, _) in &names {
        let mut file = owner.open_file(temporary, FileAccess::CreateNewReadWrite)?;
        file.write_all(b"fixture")?;
        files.push(file);
    }
    let entries: Vec<_> = files
        .iter()
        .zip(&names)
        .map(|(file, (temporary, destination))| ImmutableBatchEntry {
            temporary,
            file,
            destination,
            exact_len: 7,
        })
        .collect();
    assert!(
        owner
            .publish_files_noreplace_checked(&entries, &mut || Ok::<_, io::Error>(()))
            .is_err()
    );
    for (temporary, destination) in &names {
        assert!(root.0.join(temporary).is_file());
        assert!(!root.0.join(destination).exists());
    }
    let mut flushes = 0;
    let published = owner.publish_files_noreplace_with_final_sync(
        &entries[..MAX_IMMUTABLE_BATCH_OBJECTS],
        &mut || Ok::<_, io::Error>(()),
        &mut |file| {
            for (temporary, destination) in names.iter().take(MAX_IMMUTABLE_BATCH_OBJECTS) {
                assert!(!root.0.join(temporary).exists());
                assert_eq!(fs::read(root.0.join(destination))?, b"fixture");
            }
            flushes += 1;
            file.sync_all()
        },
    )?;
    assert_eq!(published.len(), MAX_IMMUTABLE_BATCH_OBJECTS);
    assert_eq!(flushes, 1);
    assert!(root.0.join(&names[MAX_IMMUTABLE_BATCH_OBJECTS].0).is_file());
    assert!(!root.0.join(&names[MAX_IMMUTABLE_BATCH_OBJECTS].1).exists());
    Ok(())
}

#[test]
fn eight_member_failed_final_strong_flush_is_unknown_not_completed() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let names = [
        ("failure0.tmp", "failure0.final"),
        ("failure1.tmp", "failure1.final"),
        ("failure2.tmp", "failure2.final"),
        ("failure3.tmp", "failure3.final"),
        ("failure4.tmp", "failure4.final"),
        ("failure5.tmp", "failure5.final"),
        ("failure6.tmp", "failure6.final"),
        ("failure7.tmp", "failure7.final"),
    ];
    let mut files = Vec::new();
    for (temp, _) in names {
        let mut file = owner.open_file(temp, FileAccess::CreateNewReadWrite)?;
        file.write_all(b"fixture")?;
        files.push(file);
    }
    let entries: Vec<_> = files
        .iter()
        .zip(names)
        .map(|(file, (temporary, destination))| ImmutableBatchEntry {
            temporary,
            file,
            destination,
            exact_len: 7,
        })
        .collect();
    let mut flushes = 0;
    let result = owner.publish_files_noreplace_with_final_sync(
        &entries,
        &mut || Ok::<_, io::Error>(()),
        &mut |_| {
            flushes += 1;
            Err(io::Error::other("injected final strong sync failure"))
        },
    );
    assert_eq!(flushes, 1);
    assert!(matches!(
        result,
        Err(ImmutablePublicationCheckedError::Publication(
            ImmutablePublicationError::OutcomeUnknown(_)
        ))
    ));
    for (temp, dest) in names {
        assert!(!root.0.join(temp).exists());
        assert_eq!(fs::read(root.0.join(dest))?, b"fixture");
    }
    Ok(())
}
