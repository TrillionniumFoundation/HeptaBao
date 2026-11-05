//! macOS strict-new batch regressions using the real held-directory path.
//! These tests prove checked IO/identity/error behavior, not sudden power loss.
use super::*;
use std::io::{Seek, SeekFrom};

fn pair(owner: &ExclusiveDirectory) -> io::Result<Vec<File>> {
    [
        ("first.tmp", b"stable-one".as_slice()),
        ("second.tmp", b"stable-two".as_slice()),
    ]
    .into_iter()
    .map(|(name, bytes)| {
        let mut file = owner.open_file(name, FileAccess::CreateNewReadWrite)?;
        file.write_all(bytes)?;
        Ok(file)
    })
    .collect()
}

fn entries(files: &[File]) -> Vec<ImmutableBatchEntry<'_>> {
    files
        .iter()
        .zip([("first.tmp", "first.final"), ("second.tmp", "second.final")])
        .map(|(file, (temporary, destination))| ImmutableBatchEntry {
            temporary,
            file,
            destination,
            exact_len: 10,
        })
        .collect()
}

#[test]
fn macos_strict_new_batch_keeps_actual_witnesses_and_cold_exact_files() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let files = pair(&owner)?;
    let mut witnesses = Vec::new();
    let mut flushes = 0;
    let published = owner.publish_files_noreplace_with_sync_mode(
        &entries(&files),
        &mut || Ok::<_, io::Error>(()),
        &mut |file| {
            flushes += 1;
            file.sync_all()
        },
        true,
        Some(&mut witnesses),
    )?;
    assert_eq!(flushes, 1);
    assert_eq!(witnesses.len(), 2);
    verify_strict_new_batch_device(owner.identity(), &witnesses, 2)?;
    for ((publication, witness), bytes) in published
        .into_iter()
        .zip(witnesses)
        .zip([b"stable-one".as_slice(), b"stable-two".as_slice()])
    {
        let ImmutablePublication::Published(mut file) = publication else {
            return Err("strict new publication accepted an existing destination".into());
        };
        witness.verify_file(&file)?;
        assert_eq!(file.metadata()?.nlink(), 1);
        assert!(file.write_all(b"x").is_err());
        assert_eq!(read_file(file)?, bytes);
    }
    drop(files);
    drop(owner);
    let cold = ExclusiveDirectory::open(&root.0)?;
    for (name, bytes) in [
        ("first.final", b"stable-one".as_slice()),
        ("second.final", b"stable-two".as_slice()),
    ] {
        let file = cold.open_file(name, FileAccess::Read)?;
        assert_eq!(file.metadata()?.nlink(), 1);
        assert_eq!(read_file(file)?, bytes);
    }
    Ok(())
}

#[test]
fn macos_strict_new_batch_every_original_gate_withholds_all_receipts() -> TestResult {
    let mut total = 0;
    {
        let root = Root::new()?;
        let owner = ExclusiveDirectory::open(&root.0)?;
        let files = pair(&owner)?;
        owner.publish_files_noreplace_with_sync_mode(
            &entries(&files),
            &mut || {
                total += 1;
                Ok::<_, io::Error>(())
            },
            &mut |file| file.sync_all(),
            true,
            None,
        )?;
    }
    assert!(total > 10);
    for reject in 1..=total {
        let root = Root::new()?;
        let owner = ExclusiveDirectory::open(&root.0)?;
        let files = pair(&owner)?;
        let mut calls = 0;
        let mut witnesses = Vec::new();
        let result = owner.publish_files_noreplace_with_sync_mode(
            &entries(&files),
            &mut || {
                calls += 1;
                if calls == reject {
                    Err(io::Error::other("owned original gate refusal"))
                } else {
                    Ok(())
                }
            },
            &mut |file| file.sync_all(),
            true,
            Some(&mut witnesses),
        );
        assert!(result.is_err(), "gate {reject} returned a receipt");
        assert_eq!(calls, reject);
        assert!(witnesses.is_empty());
    }
    Ok(())
}

#[test]
fn macos_strict_new_batch_device_flush_failure_has_no_retry_or_receipt() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let files = pair(&owner)?;
    let mut flushes = 0;
    let mut witnesses = Vec::new();
    let result = owner.publish_files_noreplace_with_sync_mode(
        &entries(&files),
        &mut || Ok::<_, io::Error>(()),
        &mut |_file| {
            flushes += 1;
            Err(io::Error::other("injected final device flush failure"))
        },
        true,
        Some(&mut witnesses),
    );
    assert!(matches!(
        result,
        Err(ImmutablePublicationCheckedError::Publication(
            ImmutablePublicationError::OutcomeUnknown(_)
        ))
    ));
    assert_eq!(flushes, 1);
    assert!(witnesses.is_empty());
    assert_eq!(fs::read(root.0.join("first.final"))?, b"stable-one");
    assert_eq!(fs::read(root.0.join("second.final"))?, b"stable-two");
    Ok(())
}

#[test]
fn macos_strict_new_batch_nonfirst_aba_after_device_flush_is_unknown() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let files = pair(&owner)?;
    let mut witnesses = Vec::new();
    let result = owner.publish_files_noreplace_with_sync_mode(
        &entries(&files),
        &mut || Ok::<_, io::Error>(()),
        &mut |file| {
            file.sync_all()?;
            let target = root.0.join("second.final");
            let before = fs::metadata(&target)?;
            let mut changed = fs::OpenOptions::new().write(true).open(&target)?;
            changed.write_all(b"temporary!")?;
            changed.seek(SeekFrom::Start(0))?;
            changed.write_all(b"stable-two")?;
            changed.set_times(
                fs::FileTimes::new()
                    .set_accessed(before.accessed()?)
                    .set_modified(before.modified()?),
            )?;
            assert_eq!(changed.metadata()?.ino(), before.ino());
            assert_eq!(changed.metadata()?.len(), before.len());
            assert_eq!(fs::read(&target)?, b"stable-two");
            Ok(())
        },
        true,
        Some(&mut witnesses),
    );
    assert!(matches!(
        result,
        Err(ImmutablePublicationCheckedError::Publication(
            ImmutablePublicationError::OutcomeUnknown(_)
        ))
    ));
    assert!(witnesses.is_empty());
    Ok(())
}

#[test]
fn macos_strict_new_batch_replaced_name_after_device_flush_is_unknown() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let files = pair(&owner)?;
    let mut witnesses = Vec::new();
    let result = owner.publish_files_noreplace_with_sync_mode(
        &entries(&files),
        &mut || Ok::<_, io::Error>(()),
        &mut |file| {
            file.sync_all()?;
            fs::rename(root.0.join("second.final"), root.0.join("retained-second"))?;
            fs::write(root.0.join("second.final"), b"stable-two")?;
            Ok(())
        },
        true,
        Some(&mut witnesses),
    );
    assert!(matches!(
        result,
        Err(ImmutablePublicationCheckedError::Publication(
            ImmutablePublicationError::OutcomeUnknown(_)
        ))
    ));
    assert!(witnesses.is_empty());
    Ok(())
}

#[test]
fn macos_strict_new_batch_device_guard_rejects_altered_original_witness() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let files = pair(&owner)?;
    let mut witnesses = Vec::new();
    let published = owner.publish_files_noreplace_with_sync_mode(
        &entries(&files),
        &mut || Ok::<_, io::Error>(()),
        &mut |file| file.sync_all(),
        true,
        Some(&mut witnesses),
    )?;
    verify_strict_new_batch_device(owner.identity(), &witnesses, 2)?;
    assert!(verify_strict_new_batch_device(owner.identity(), &witnesses, 1).is_err());
    assert!(verify_strict_new_batch_device(owner.identity(), &[], 0).is_err());
    // This is an injected predicate unit test. Production cannot construct or
    // alter the private original fd witness, and no foreign filesystem is faked.
    witnesses[1].identity.identity.device ^= 1;
    assert!(verify_strict_new_batch_device(owner.identity(), &witnesses, 2).is_err());
    drop(published);
    Ok(())
}
