//! An explicitly propagated, absolute ReadIndex deadline. This only bounds
//! read authority checks; it does not cancel/retry Raft writes or maintenance.
use std::future::Future;
use std::time::Instant;

tokio::task_local! {
    static READ_INDEX_DEADLINE: Instant;
}

pub(super) fn current() -> Option<Instant> {
    READ_INDEX_DEADLINE.try_with(|deadline| *deadline).ok()
}

/// Scope all nested ReadIndex calls, including administration's internal
/// checks, to one absolute deadline. The scope follows this future while it
/// is polled, restores on cancellation/unwind, and is not inherited by spawned
/// background tasks. Nested callers can shorten but cannot extend the budget.
/// Other Raft operations retain their existing completion/unknown-outcome rules.
pub async fn with_read_index_deadline<F: Future>(deadline: Instant, operation: F) -> F::Output {
    let deadline = current().map_or(deadline, |outer| deadline.min(outer));
    READ_INDEX_DEADLINE.scope(deadline, operation).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn nested_and_concurrent_operations_do_not_extend_or_leak_deadlines()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = Instant::now() + Duration::from_secs(1);
        let later = first + Duration::from_secs(5);
        assert!(current().is_none());
        with_read_index_deadline(first, async {
            assert_eq!(current(), Some(first));
            with_read_index_deadline(later, async {
                tokio::task::yield_now().await;
                assert_eq!(current(), Some(first));
            })
            .await;
            let earlier = first - Duration::from_millis(100);
            with_read_index_deadline(earlier, async {
                assert_eq!(current(), Some(earlier));
            })
            .await;
            assert_eq!(current(), Some(first));
            assert!(tokio::spawn(async { current() }).await?.is_none());
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await?;
        assert!(current().is_none());
        // Dropping a pending request restores the task's prior scope.
        let expired = tokio::time::timeout(
            Duration::from_millis(1),
            with_read_index_deadline(first, std::future::pending::<()>()),
        )
        .await;
        assert!(expired.is_err());
        assert!(current().is_none());
        Ok(())
    }
}
