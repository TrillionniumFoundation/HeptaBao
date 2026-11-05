use super::*;
use crate::FileAccess;
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().canonicalize()?.join(format!(
            "heptabao-mutation-witness-{}-{}",
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

fn existing(owner: &ExclusiveDirectory, name: &str) -> io::Result<File> {
    let mut writer = owner.open_file(name, FileAccess::CreateNew)?;
    writer.write_all(b"original-A")?;
    drop(writer);
    owner.open_file(name, FileAccess::Read)
}

#[test]
fn mutation_witness_real_same_inode_aba_survives_mtime_restore() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let mut held = existing(&owner, "leaf")?;
    let identity = FileIdentity::read(&held)?;
    let modified = held.metadata()?.modified()?;
    let witness = owner.watch_file_mutations(&held)?;
    held.sync_all()?;
    owner.sync_all()?;
    let mut bytes = Vec::new();
    held.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"original-A");
    witness.verify_file(&held)?; // legitimate reads and barriers are not mutations
    for bytes in [b"differentB", b"original-A"] {
        let mut writer = owner.open_file("leaf", FileAccess::Write)?;
        writer.write_all(bytes)?;
        writer.set_modified(modified)?;
        writer.sync_all()?;
    }
    assert_eq!(FileIdentity::read(&held)?, identity);
    assert_eq!(held.metadata()?.modified()?, modified);
    assert_eq!(fs::read(root.0.join("leaf"))?, b"original-A");
    // No assumption about ctime precision. Actual A->B->A is latched by the
    // ORIGINAL registration, independent of the final bytes and mtime.
    assert!(witness.verify_file(&held).is_err());
    assert!(witness.clone().verify_file(&held).is_err());
    assert!(owner.watch_file_mutations(&held).is_err());
    Ok(())
}

#[test]
fn mutation_witness_many_inodes_share_one_owner_queue_and_release() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let mut held = Vec::new();
    let mut witnesses = Vec::new();
    // The >128 inotify INSTANCE limit is Linux-specific. Darwin retains a
    // duplicate fd per active inode; 64 still proves shared-queue ownership
    // under its actual soft fd limit of 256 without changing that limit.
    let inode_count = if cfg!(target_os = "linux") { 256 } else { 64 };
    for index in 0..inode_count {
        let file = existing(&owner, &format!("leaf-{index}"))?;
        let witness = owner.watch_file_mutations(&file)?;
        if let Some(first) = witnesses.first() {
            let first: &FileMutationWitness = first;
            assert!(Arc::ptr_eq(&first.0.broker, &witness.0.broker));
        }
        held.push(file);
        witnesses.push(witness);
    }
    for (file, witness) in held.iter().zip(&witnesses) {
        witness.verify_file(file)?;
    }
    let broker = witnesses
        .first()
        .ok_or("missing actual watch")?
        .0
        .broker
        .clone();
    drop(witnesses);
    let state = broker.lock().map_err(|_| "poisoned test broker")?;
    assert!(state.by_inode.is_empty());
    assert!(state.entries.values().all(|entry| entry.leases == 0));
    assert!(!state.poisoned);
    Ok(())
}

#[test]
fn mutation_witness_shared_inode_lifetime_never_rebases_a_remaining_clone() -> TestResult {
    let root = Root::new()?;
    let owner = ExclusiveDirectory::open(&root.0)?;
    let file = existing(&owner, "leaf")?;
    let first = owner.watch_file_mutations(&file)?;
    let retained = first.clone();
    let separate = owner.watch_file_mutations(&file)?;
    assert_eq!(first.0.watch, separate.0.watch);
    drop(first);
    drop(separate);
    retained.verify_file(&file)?;
    let identity = FileIdentity::read(&file)?;
    fs::rename(root.0.join("leaf"), root.0.join("moved"))?;
    fs::rename(root.0.join("moved"), root.0.join("leaf"))?;
    assert_eq!(FileIdentity::read(&file)?, identity);
    assert_eq!(fs::read(root.0.join("leaf"))?, b"original-A");
    assert!(retained.verify_file(&file).is_err());
    assert!(owner.watch_file_mutations(&file).is_err());
    drop(retained);
    // With no surviving original pin, a genuinely NEW registration may begin.
    // It is not evidence for any old read or sync; those tokens are gone.
    owner.watch_file_mutations(&file)?.verify_file(&file)?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn mutation_inotify_overflow_unknown_flags_and_truncated_frames_refuse() -> TestResult {
    fn frame(watch: i32, mask: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&watch.to_ne_bytes());
        out.extend_from_slice(&mask.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out
    }
    let mut count = 0;
    for malformed in [
        frame(-1, libc::IN_Q_OVERFLOW),
        frame(1, libc::IN_OPEN),
        vec![0; 15],
    ] {
        assert!(
            platform::decode(&malformed, &mut |_| {
                count += 1;
                Ok(())
            })
            .is_err()
        );
    }
    assert_eq!(count, 0);
    let mut removed = false;
    platform::decode(&frame(7, libc::IN_IGNORED), &mut |event| {
        assert_eq!(event.watch, 7);
        removed = event.removed;
        Ok(())
    })?;
    assert!(removed);
    Ok(())
}
