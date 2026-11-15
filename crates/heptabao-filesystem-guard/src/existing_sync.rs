//! Scoped synchronization of already owned read-only descriptors.
use std::fs::File;
use std::io;

/// Maximum concurrently joined descriptor synchronizations in one existing-file unit.
pub const MAX_PARALLEL_EXISTING_FSYNC: usize = 4;

/// Synchronize one bounded group and join every started worker before returning.
/// No admission callback, mutable backend or new file owner enters these workers.
pub fn parallel_existing_sync(
    files: &[&File],
    sync_one: &(impl Fn(&File) -> io::Result<()> + Sync),
) -> io::Result<Vec<io::Result<()>>> {
    if files.is_empty() || files.len() > MAX_PARALLEL_EXISTING_FSYNC {
        return Err(io::Error::other("invalid existing fsync worker count"));
    }
    std::thread::scope(|scope| {
        let mut jobs = Vec::with_capacity(files.len());
        let mut spawn_error = None;
        for file in files {
            match std::thread::Builder::new().spawn_scoped(scope, move || sync_one(file)) {
                Ok(job) => jobs.push(job),
                Err(error) => {
                    spawn_error = Some(error);
                    break;
                }
            }
        }
        // Join ALL started workers even after a failed spawn, failed fsync or
        // panic. No unfinished I/O may coexist with a returned pin, directory
        // barrier, cleanup, next chunk or caller return.
        let results = jobs
            .into_iter()
            .map(|job| {
                job.join()
                    .unwrap_or_else(|_| Err(io::Error::other("existing fsync worker panicked")))
            })
            .collect();
        match spawn_error {
            Some(error) => Err(error),
            None => Ok(results),
        }
    })
}
