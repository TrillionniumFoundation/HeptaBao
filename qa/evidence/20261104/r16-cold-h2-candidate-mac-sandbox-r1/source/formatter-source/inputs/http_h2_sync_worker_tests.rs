use super::run_unentered_service_worker;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

struct DropCount(Arc<AtomicUsize>);

impl Drop for DropCount {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn h2_sync_worker_is_unentered_and_retains_outer_context() -> Result<(), &'static str> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "owned test runtime")?;
    runtime.block_on(async {
        tokio::task::spawn_blocking(|| {
            assert!(tokio::runtime::Handle::try_current().is_ok());
            let parent = std::thread::current().id();
            let result = run_unentered_service_worker(
                Instant::now() + Duration::from_secs(2),
                move || {
                    assert_ne!(std::thread::current().id(), parent);
                    assert!(tokio::runtime::Handle::try_current().is_err());
                    17_u8
                },
            );
            assert_eq!(result, Ok(17));
            assert!(tokio::runtime::Handle::try_current().is_ok());
        })
        .await
        .map_err(|_| "owned blocking parent")
    })?;
    assert!(tokio::runtime::Handle::try_current().is_err());
    Ok(())
}

#[test]
fn h2_sync_worker_expired_deadline_never_calls_work() {
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let captured_calls = Arc::clone(&calls);
    let capture = DropCount(Arc::clone(&drops));
    let result = run_unentered_service_worker(Instant::now(), move || {
        captured_calls.fetch_add(1, Ordering::SeqCst);
        drop(capture);
    });
    assert_eq!(result, Err(()));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn h2_sync_worker_preserves_inner_result() {
    let result = run_unentered_service_worker(
        Instant::now() + Duration::from_secs(2),
        || Err::<(), u8>(19),
    );
    assert_eq!(result, Ok(Err(19)));
}

#[test]
fn h2_sync_worker_joins_panicked_work_and_drops_capture() {
    let drops = Arc::new(AtomicUsize::new(0));
    let capture = DropCount(Arc::clone(&drops));
    let result: Result<(), ()> = run_unentered_service_worker(
        Instant::now() + Duration::from_secs(2),
        move || {
            let _capture = capture;
            std::panic::resume_unwind(Box::new("fixed owned worker component"));
        },
    );
    assert_eq!(result, Err(()));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(tokio::runtime::Handle::try_current().is_err());
}

#[test]
fn h2_sync_worker_does_not_authorize_nested_runtime_context() {
    let result = run_unentered_service_worker(
        Instant::now() + Duration::from_secs(2),
        || -> Result<(), &'static str> {
            assert!(tokio::runtime::Handle::try_current().is_err());
            let nested = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| "owned nested runtime")?;
            nested.block_on(async {
                // This is precisely the unchanged guard's refusal predicate.
                assert!(tokio::runtime::Handle::try_current().is_ok());
            });
            assert!(tokio::runtime::Handle::try_current().is_err());
            Ok(())
        },
    );
    assert_eq!(result, Ok(Ok(())));
}

#[test]
fn h2_sync_worker_cancelled_waiter_retains_blocking_capacity() -> Result<(), &'static str> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .map_err(|_| "owned single-slot runtime")?;
    let parent_drops = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    let probe_completed = Arc::new(AtomicUsize::new(0));
    let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let held_drops = Arc::clone(&parent_drops);
    let held_completed = Arc::clone(&completed);
    runtime.block_on(async {
        let waiter = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                let _parent = DropCount(held_drops);
                run_unentered_service_worker(
                    Instant::now() + Duration::from_secs(2),
                    move || -> Result<(), &'static str> {
                        started_sender.send(()).map_err(|_| "owned start observer")?;
                        release_receiver
                            .recv_timeout(Duration::from_secs(1))
                            .map_err(|_| "bounded component release")?;
                        held_completed.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                )
            })
            .await
        });
        started_receiver.await.map_err(|_| "actual child started")?;
        waiter.abort();
        match waiter.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(_) => return Err("waiter was not cancelled"),
        }
        assert_eq!(parent_drops.load(Ordering::SeqCst), 0);
        assert_eq!(completed.load(Ordering::SeqCst), 0);
        let observed_completed = Arc::clone(&completed);
        let observed_probe = Arc::clone(&probe_completed);
        let probe = tokio::task::spawn_blocking(move || {
            assert_eq!(observed_completed.load(Ordering::SeqCst), 1);
            observed_probe.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(probe_completed.load(Ordering::SeqCst), 0);
        release_sender.send(()).map_err(|_| "release actual worker")?;
        probe.await.map_err(|_| "single capacity slot resumed")?;
        Ok::<(), &'static str>(())
    })?;
    drop(runtime);
    assert_eq!(completed.load(Ordering::SeqCst), 1);
    assert_eq!(parent_drops.load(Ordering::SeqCst), 1);
    assert_eq!(probe_completed.load(Ordering::SeqCst), 1);
    Ok(())
}
