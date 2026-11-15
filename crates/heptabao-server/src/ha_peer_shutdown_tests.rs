use super::*;
use std::sync::mpsc;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self(std::env::temp_dir().join(format!(
            "heptabao-ha-self-shutdown-{}-{}",
            std::process::id(),
            u64::from_le_bytes(crate::crypto::random::<8>()?),
        ))))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn wait_terminal(
    receipt: &PeerNodeShutdownReceipt,
) -> Result<PeerNodeShutdownSummary, Box<dyn std::error::Error>> {
    let until = Instant::now() + Duration::from_secs(5);
    let mut value = receipt
        .terminal
        .lock()
        .map_err(|_| "shutdown receipt poisoned")?;
    loop {
        if let Some(summary) = *value {
            return Ok(summary);
        }
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("owned shutdown did not complete".into());
        }
        let (next, _) = receipt
            .changed
            .wait_timeout(value, remaining)
            .map_err(|_| "shutdown wait poisoned")?;
        value = next;
    }
}

#[test]
fn last_ha_owner_on_peer_keeps_runtime_until_all_original_workers_join() -> TestResult {
    let directory = Directory::new()?;
    let mut process = super::super::request_deadline_tests::process(&directory.0)?;
    let runtime = Arc::downgrade(&process.runtime);
    let node = Arc::downgrade(process.node.as_ref().ok_or("actual node absent")?);
    let receipt = Arc::new(PeerNodeShutdownReceipt::default());
    let stop = Arc::new(AtomicBool::new(false));
    let (owned_sender, owned_receiver) = mpsc::channel::<HaProcess>();
    let (dropped_sender, dropped_receiver) = mpsc::channel();
    let (release_self, held_self) = mpsc::channel();
    let (other_stopped, other_stopped_receiver) = mpsc::channel();
    let (release_other, held_other) = mpsc::channel();
    let self_exit = Arc::new(AtomicBool::new(false));
    let other_exit = Arc::new(AtomicBool::new(false));
    let self_done = Arc::clone(&self_exit);
    let self_worker = thread::Builder::new()
        .name("owned-ha-self-drop-test".into())
        .spawn(move || {
            let result = (|| -> Result<(), &'static str> {
                let owned = owned_receiver.recv().map_err(|_| "actual owner missing")?;
                let handle = owned.runtime.handle().clone();
                drop(owned);
                // This runs after the actual HaProcess destructor on its own peer,
                // while the supervisor must still retain the original Runtime.
                handle.block_on(async { tokio::task::yield_now().await });
                dropped_sender
                    .send(Ok(()))
                    .map_err(|_| "drop observation receiver closed")?;
                let _ = held_self.recv();
                self_done.store(true, Ordering::Release);
                Ok(())
            })();
            if let Err(error) = result {
                let _ = dropped_sender.send(Err(error));
            }
        })?;
    let other_stop = Arc::clone(&stop);
    let other_done = Arc::clone(&other_exit);
    let other_worker = thread::Builder::new()
        .name("owned-ha-other-peer-test".into())
        .spawn(move || {
            while !other_stop.load(Ordering::Acquire) {
                thread::yield_now();
            }
            let _ = other_stopped.send(());
            let _ = held_other.recv();
            other_done.store(true, Ordering::Release);
        })?;
    process.listener = Some(PeerListener {
        shutdown_supervisor: PeerShutdownSupervisor::global()?,
        shutdown_receipt: Arc::clone(&receipt),
        stop: Arc::clone(&stop),
        workers: vec![self_worker, other_worker],
        #[cfg(all(
            feature = "native-v6-ha",
            any(test, feature = "experimental-native-v6-ha")
        ))]
        native_capacity_installed: false,
    });
    owned_sender
        .send(process)
        .map_err(|_| "owner handoff failed")?;
    dropped_receiver.recv_timeout(Duration::from_secs(5))??;
    other_stopped_receiver.recv_timeout(Duration::from_secs(5))?;
    assert!(stop.load(Ordering::Acquire));
    assert!(receipt.terminal.lock().map_err(|_| "receipt")?.is_none());
    assert!(runtime.upgrade().is_some());
    assert!(node.upgrade().is_some());
    release_self.send(())?;
    // The other original worker remains live. No terminal receipt may be issued
    // merely because the self-dropping worker can now return.
    assert!(receipt.terminal.lock().map_err(|_| "receipt")?.is_none());
    release_other.send(())?;
    let completed = wait_terminal(&receipt)?;
    assert_eq!(
        completed.workers,
        WorkerJoinSummary {
            joined: 2,
            panicked: 0
        }
    );
    assert_eq!(completed.node, NodeShutdown::Completed);
    assert!(self_exit.load(Ordering::Acquire));
    assert!(other_exit.load(Ordering::Acquire));
    assert!(runtime.upgrade().is_none());
    assert!(node.upgrade().is_none());
    Ok(())
}

#[test]
fn external_ha_owner_waits_for_original_worker_and_runtime_shutdown() -> TestResult {
    let directory = Directory::new()?;
    let mut process = super::super::request_deadline_tests::process(&directory.0)?;
    let runtime = Arc::downgrade(&process.runtime);
    let node = Arc::downgrade(process.node.as_ref().ok_or("actual node absent")?);
    let receipt = Arc::new(PeerNodeShutdownReceipt::default());
    let stop = Arc::new(AtomicBool::new(false));
    let (stopped_sender, stopped_receiver) = mpsc::channel();
    let (release, held) = mpsc::channel();
    let peer_stop = Arc::clone(&stop);
    let worker = thread::spawn(move || {
        while !peer_stop.load(Ordering::Acquire) {
            thread::yield_now();
        }
        let _ = stopped_sender.send(());
        let _ = held.recv();
    });
    process.listener = Some(PeerListener {
        shutdown_supervisor: PeerShutdownSupervisor::global()?,
        shutdown_receipt: Arc::clone(&receipt),
        stop,
        workers: vec![worker],
        #[cfg(all(
            feature = "native-v6-ha",
            any(test, feature = "experimental-native-v6-ha")
        ))]
        native_capacity_installed: false,
    });
    let (returned_sender, returned_receiver) = mpsc::channel();
    let owner = thread::spawn(move || {
        drop(process);
        let _ = returned_sender.send(());
    });
    stopped_receiver.recv_timeout(Duration::from_secs(5))?;
    assert!(matches!(
        returned_receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert!(receipt.terminal.lock().map_err(|_| "receipt")?.is_none());
    assert!(runtime.upgrade().is_some());
    assert!(node.upgrade().is_some());
    release.send(())?;
    // The signal is sent after the actual HaProcess drop, including automatic
    // field destruction. Only this boundary proves its last Runtime Arc ended.
    returned_receiver.recv_timeout(Duration::from_secs(5))?;
    owner.join().map_err(|_| "external owner panicked")?;
    let completed = wait_terminal(&receipt)?;
    assert_eq!(
        completed.workers,
        WorkerJoinSummary {
            joined: 1,
            panicked: 0
        }
    );
    assert_eq!(completed.node, NodeShutdown::Completed);
    assert!(runtime.upgrade().is_none());
    assert!(node.upgrade().is_none());
    Ok(())
}
