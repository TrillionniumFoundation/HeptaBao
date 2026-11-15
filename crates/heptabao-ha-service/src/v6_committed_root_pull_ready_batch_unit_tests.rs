//! Local ownership/receipt controls complement the unchanged real TLS tests.
//! These controls do not supply an authenticated peer or a Raft witness.
use super::*;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct RemovedOnDrop(std::path::PathBuf);
impl RemovedOnDrop {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut nonce = [0u8; 8];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| "cannot create disposable test name")?;
        let path = std::env::temp_dir().join(format!(
            "hb-ready-pull-receipts-{}-{:016x}",
            std::process::id(),
            u64::from_be_bytes(nonce),
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for RemovedOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct CompletionWitness(Arc<AtomicBool>);
impl Drop for CompletionWitness {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[test]
fn ready_pull_poll_does_not_wait_for_a_silent_donor_or_release_payload_capacity() -> TestResult {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let capacity = Arc::new(Semaphore::new(NATIVE_V6_ROOT_PULL_GLOBAL_FRAMES));
    let silent_permit = capacity.clone().try_acquire_owned()?;
    let completed = Arc::new(AtomicBool::new(false));
    let witness = CompletionWitness(completed.clone());
    let silent = runtime.spawn(async move {
        let _witness = witness;
        let _permit = silent_permit;
        std::future::pending::<Result<VerifiedPullReply, HaError>>().await
    });
    let abort = silent.abort_handle();
    let ready_permit = capacity.clone().try_acquire_owned()?;
    let ready = runtime.spawn(async move {
        Ok(VerifiedPullReply {
            payload: vec![0x91; 32],
            _permit: ready_permit,
            _observation: None,
        })
    });
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !ready.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
    })?;
    let mut pulls = OwnedPulls {
        runtime: runtime.handle(),
        pending: vec![
            PendingPull {
                target: 1,
                step: PullStep::Object(0),
                operation: silent,
            },
            PendingPull {
                target: 2,
                step: PullStep::Object(1),
                operation: ready,
            },
        ],
        observation: None,
    };
    // A deliberately broken implementation which awaits the silent task is
    // released by the watchdog and fails the completion-witness assertion.
    // Normal polling neither waits for this watchdog nor manufactures a reply.
    let (release, released) = std::sync::mpsc::channel();
    thread::scope(|scope| -> TestResult {
        let watchdog = scope.spawn(move || {
            if released.recv_timeout(Duration::from_secs(1)).is_err() {
                abort.abort();
            }
        });
        let result = (|| -> TestResult {
            let (target, index, response) = pulls.take_ready_object().ok_or("ready task absent")?;
            assert_eq!((target, index), (2, 1));
            let response = response?;
            assert_eq!(response.payload, vec![0x91; 32]);
            assert!(!completed.load(Ordering::Acquire));
            assert_eq!(
                capacity.available_permits(),
                NATIVE_V6_ROOT_PULL_GLOBAL_FRAMES - 2
            );
            assert!(pulls.take_ready_object().is_none());
            assert!(!completed.load(Ordering::Acquire));
            drop(response);
            assert_eq!(
                capacity.available_permits(),
                NATIVE_V6_ROOT_PULL_GLOBAL_FRAMES - 1
            );
            pulls.cancel_and_join();
            assert!(completed.load(Ordering::Acquire));
            assert_eq!(
                capacity.available_permits(),
                NATIVE_V6_ROOT_PULL_GLOBAL_FRAMES
            );
            Ok(())
        })();
        let _ = release.send(());
        watchdog
            .join()
            .map_err(|_| "ready-only watchdog panicked")?;
        result
    })
}

#[test]
fn ready_pull_missing_or_misordered_real_receipts_never_mark_partial_completion() -> TestResult {
    let root = RemovedOnDrop::new()?;
    let storage = LocalV6BlobStage::open_existing(&root.0)?;
    let first = vec![0xa1; 32 * 1024];
    let second = vec![0xa2; 32 * 1024];
    let mut receipts = storage
        .stage_local_batch_checked(&[first.as_slice(), second.as_slice()], &mut || Ok(()))?;
    assert_eq!(receipts.len(), 2);
    let references: Vec<_> = receipts
        .iter()
        .map(|receipt| receipt.reference().clone())
        .collect();
    let mut fsynced = vec![false; references.len()];
    let missing = receipts.pop().ok_or("second real receipt absent")?;
    assert!(accept_ready_pull_receipts(&references, &[0, 1], &receipts, &mut fsynced).is_err());
    assert_eq!(fsynced, vec![false, false]);
    assert_eq!(storage.read_local(&references[0])?, first);
    assert_eq!(storage.read_local(&references[1])?, second);
    receipts.push(missing);
    receipts.swap(0, 1);
    assert!(accept_ready_pull_receipts(&references, &[0, 1], &receipts, &mut fsynced).is_err());
    assert_eq!(fsynced, vec![false, false]);
    receipts.swap(0, 1);
    assert!(accept_ready_pull_receipts(&references, &[0, 0], &receipts, &mut fsynced).is_err());
    assert_eq!(fsynced, vec![false, false]);
    accept_ready_pull_receipts(&references, &[0, 1], &receipts, &mut fsynced)?;
    assert_eq!(fsynced, vec![true, true]);
    Ok(())
}
