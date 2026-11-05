//! Blocking persistence retains the existing sole store owner.
//!
//! Acquire the owned mutex before admission to the blocking pool. At most one
//! job per store owner can be queued or executing. Dropping the async waiter
//! cannot release that lock, cancel a started filesystem effect, or permit a
//! concurrent writer. Completion callbacks belong inside the operation, after
//! durable publication; a worker failure is an I/O failure, never an ack.
//! This does not claim that an unresponsive filesystem can be interrupted.
use std::io;
use tokio::sync::OwnedMutexGuard;

pub(super) async fn with_owned_store<T, R, F>(
    mut owner: OwnedMutexGuard<T>,
    operation: F,
) -> io::Result<R>
where
    T: Send + 'static,
    R: Send + 'static,
    F: FnOnce(&mut T) -> io::Result<R> + Send + 'static,
{
    tokio::task::spawn_blocking(move || operation(&mut owner))
        .await
        .map_err(|_| io::Error::other("raft store blocking worker failed"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, mpsc};
    use std::time::Duration;
    use tokio::sync::{Mutex, oneshot};

    #[tokio::test(flavor = "current_thread")]
    async fn store_io_blocked_writer_does_not_block_consensus_runtime_progress() -> io::Result<()> {
        let store = Arc::new(Mutex::new(0_u64));
        let owner = store.clone().lock_owned().await;
        let (entered, started) = oneshot::channel();
        let (pulse, received) = mpsc::channel();
        let write = with_owned_store(owner, move |value| {
            let _ = entered.send(());
            let runtime_progressed = received.recv_timeout(Duration::from_secs(2)).is_ok();
            *value += 1;
            Ok(runtime_progressed)
        });
        let heartbeat = async move {
            let _ = started.await;
            let _ = pulse.send(());
        };
        let (progressed, ()) = tokio::join!(write, heartbeat);
        assert!(
            progressed?,
            "blocking store work occupied the consensus executor"
        );
        assert_eq!(*store.lock().await, 1);
        Ok(())
    }

    #[tokio::test]
    async fn store_io_preserves_failure_and_never_invents_success() -> io::Result<()> {
        let store = Arc::new(Mutex::new(0_u64));
        let owner = store.clone().lock_owned().await;
        let result: io::Result<()> = with_owned_store(owner, |_| {
            Err(io::Error::new(io::ErrorKind::StorageFull, "synthetic-full"))
        })
        .await;
        assert!(result.is_err_and(|error| error.kind() == io::ErrorKind::StorageFull));
        assert_eq!(*store.lock().await, 0);
        Ok(())
    }
    #[tokio::test(flavor = "current_thread")]
    async fn store_io_aborted_waiter_keeps_owner_until_write_and_publication_finish()
    -> io::Result<()> {
        let store = Arc::new(Mutex::new(0_u64));
        let owner = store.clone().lock_owned().await;
        let (entered, started) = oneshot::channel();
        let (release, released) = mpsc::channel();
        let (published, publication) = oneshot::channel();
        let waiter = tokio::spawn(with_owned_store(owner, move |value| {
            let _ = entered.send(());
            released
                .recv_timeout(Duration::from_secs(5))
                .map_err(io::Error::other)?;
            *value += 1;
            let _ = published.send(*value);
            Ok(())
        }));
        tokio::time::timeout(Duration::from_secs(5), started)
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        waiter.abort();
        assert!(waiter.await.is_err_and(|error| error.is_cancelled()));
        assert!(
            store.try_lock().is_err(),
            "cancelled waiter released an in-flight writer"
        );
        release.send(()).map_err(io::Error::other)?;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), publication)
                .await
                .map_err(io::Error::other)?
                .map_err(io::Error::other)?,
            1
        );
        let observed = tokio::time::timeout(Duration::from_secs(5), store.lock())
            .await
            .map_err(io::Error::other)?;
        assert_eq!(*observed, 1);
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic,
        reason = "fault injection verifies a panicking worker never acknowledges persistence"
    )]
    async fn store_io_worker_panic_is_reported_as_io_failure_without_panic_contents() {
        let store = Arc::new(Mutex::new(0_u64));
        let owner = store.lock_owned().await;
        let result: io::Result<()> = with_owned_store(owner, |_| {
            panic!("synthetic private worker diagnostic");
        })
        .await;
        let error = result.expect_err("panic must not become a successful completion");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.to_string(), "raft store blocking worker failed");
    }
}
