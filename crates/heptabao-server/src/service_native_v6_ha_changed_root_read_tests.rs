//! Real Service publication, production pinned TLS, and actual three-node Raft.
//! A stale Service root hint must not force fresh durability publication for an
//! already complete selected ciphertext closure. No mocked receipts or clocks.
use super::*;
use heptabao_raft_runtime::NativeV6PublishedRoot;
use std::os::unix::fs::MetadataExt as _;

#[derive(Debug, Eq, PartialEq)]
struct CiphertextObservation {
    directory: (u64, u64, i64, i64, i64, i64),
    files: BTreeMap<std::ffi::OsString, (u64, [u8; 32])>,
}

fn observe_ciphertext(path: &Path) -> TestResult<CiphertextObservation> {
    let info = fs::symlink_metadata(path)?;
    assert!(info.is_dir() && !info.file_type().is_symlink());
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        assert!(entry.file_type()?.is_file());
        let bytes = fs::read(entry.path())?;
        files.insert(
            entry.file_name(),
            (bytes.len() as u64, crypto::digest(&bytes)),
        );
    }
    Ok(CiphertextObservation {
        directory: (
            info.dev(),
            info.ino(),
            info.mtime(),
            info.mtime_nsec(),
            info.ctime(),
            info.ctime_nsec(),
        ),
        files,
    })
}

fn changed_root_pipeline() -> TestResult<(Pipeline, usize, [u8; 32], NativeV6PublishedRoot)> {
    let pipeline = Pipeline::start()?;
    let leader = pipeline.ready_leader()?;
    expect(
        pipeline.call(
            leader,
            "POST",
            "sys/internal/native-v6/activate",
            pipeline.admin(),
            json!({}),
        )?,
        204,
        "changed-root-activation",
    )?;
    let previous = pipeline.native_selection(leader)?;
    expect(
        pipeline.call(
            leader,
            "POST",
            "secret/data/pipeline/history",
            pipeline.admin(),
            json!({"options":{"cas":1},"data":{"value":"changed-root-real-quorum".repeat(1024)}}),
        )?,
        200,
        "changed-root-real-Service-publication",
    )?;
    let published = {
        let _scope = scope();
        let process = pipeline.processes[leader]
            .as_ref()
            .ok_or("process absent")?
            .lock_for_request()
            .map_err(|_| "publication process lock")?;
        let read = process
            .native_v6_committed_read(OriginalDeadline::capture()?)?
            .ok_or("changed committed root absent")?;
        process.verify_native_v6_committed_read(&read)?;
        read.published().clone()
    };
    assert_ne!(published.root_digest(), previous.1);
    assert!(published.generation() > previous.0);
    Ok((pipeline, leader, previous.1, published))
}

#[test]
fn native_ha_changed_selected_root_reopens_complete_leader_and_follower_without_republication()
-> TestResult {
    let (pipeline, leader, old_hint, published) = changed_root_pipeline()?;
    // Find an actual quorum recipient with a complete physical closure. No
    // ciphertext is copied and no absent follower is silently repaired here.
    let follower = (0..3)
        .filter(|index| *index != leader)
        .find(|&index| {
            let observed = (|| -> TestResult<bool> {
                let _scope = scope();
                let process = pipeline.processes[index]
                    .as_ref()
                    .ok_or("follower absent")?
                    .lock_for_request()
                    .map_err(|_| "follower process lock")?;
                let store = process.native_install_test_store()?;
                Ok(store
                    .reopen_root_closure(&published, &mut || Ok(()))
                    .is_ok())
            })();
            observed.unwrap_or(false)
        })
        .ok_or("actual quorum follower closure absent")?;
    for (index, hint) in [
        (leader, Some(old_hint)),
        (leader, None),
        (follower, Some(old_hint)),
    ] {
        let path = pipeline.configs[index]
            .raft_dir
            .join("native-v6-ciphertext");
        let before = observe_ciphertext(&path)?;
        {
            let _scope = scope();
            let original = OriginalDeadline::capture()?;
            let process = pipeline.processes[index]
                .as_ref()
                .ok_or("read process absent")?
                .lock_for_request()
                .map_err(|_| "read process lock")?;
            let read = match hint {
                Some(hint) => process.native_v6_committed_read_for_local_root(original, hint)?,
                None => process.native_v6_committed_read(original)?,
            }
            .ok_or("actual selected root absent")?;
            assert_eq!(read.published(), &published);
            assert_eq!(read.deadline().instant(), original.instant());
            process.verify_native_v6_committed_read(&read)?;
        }
        assert_eq!(
            observe_ciphertext(&path)?,
            before,
            "changed/absent Service hint must not republish an already complete physical closure"
        );
    }
    Ok(())
}

#[test]
fn native_ha_changed_selected_root_keeps_checked_missing_repair_and_corrupt_leaf_refusal()
-> TestResult {
    let (pipeline, leader, old_hint, published) = changed_root_pipeline()?;
    let (store, references) = {
        let _scope = scope();
        let process = pipeline.processes[leader]
            .as_ref()
            .ok_or("repair process absent")?
            .lock_for_request()
            .map_err(|_| "repair store lock")?;
        let store = process.native_install_test_store()?;
        let references = store.reopen_root_closure(&published, &mut || Ok(()))?;
        (store, references)
    };
    let reference = references.first().ok_or("ciphertext reference absent")?;
    let leaf = pipeline.configs[leader]
        .raft_dir
        .join("native-v6-ciphertext")
        .join(format!("v6-{}.blob", hex(&reference.id)));
    let original_bytes = fs::read(&leaf)?;
    fs::remove_file(&leaf)?;
    {
        let _scope = scope();
        let original = OriginalDeadline::capture()?;
        let process = pipeline.processes[leader]
            .as_ref()
            .ok_or("repair process absent")?
            .lock_for_request()
            .map_err(|_| "repair process lock")?;
        let read = process
            .native_v6_committed_read_for_local_root(original, old_hint)?
            .ok_or("repaired changed root absent")?;
        assert_eq!(read.published(), &published);
        assert_eq!(read.deadline().instant(), original.instant());
        process.verify_native_v6_committed_read(&read)?;
    }
    assert_eq!(fs::read(&leaf)?, original_bytes);
    assert_eq!(
        store.reopen_root_closure(&published, &mut || Ok(()))?,
        references
    );
    let damaged = b"existing owned damaged leaf must remain unchanged";
    fs::write(&leaf, damaged)?;
    {
        let _scope = scope();
        let process = pipeline.processes[leader]
            .as_ref()
            .ok_or("corrupt process absent")?
            .lock_for_request()
            .map_err(|_| "corrupt process lock")?;
        assert!(
            process
                .native_v6_committed_read_for_local_root(OriginalDeadline::capture()?, old_hint)
                .is_err()
        );
    }
    assert_eq!(fs::read(&leaf)?.as_slice(), damaged);
    // The ordinary fixture owner performs final cleanup after all processes
    // stop. Neither the product reader nor this test repairs the damaged leaf.
    Ok(())
}
