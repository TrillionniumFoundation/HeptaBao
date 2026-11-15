//! Durable writes through an already held exclusive directory descriptor.
use crate::{ExclusiveDirectory, FileAccess};
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};

/// Failure while replacing a control file through its owning directory.
/// A published result is indeterminate durability, never permission to retry.
#[derive(Debug)]
pub struct AtomicReplaceError {
    /// Original filesystem failure, retained without changing its category.
    pub source: io::Error,
    /// True only after rename succeeded and synchronizing the directory failed.
    pub published: bool,
}

/// Create an absent file, flush and synchronize it, then synchronize its parent.
/// The caller retains control over cleanup and any publication-unknown mapping.
pub fn write_new_file_and_sync_parent(
    root: &ExclusiveDirectory,
    leaf_name: &str,
    bytes: &[u8],
) -> io::Result<()> {
    root.verify().map_err(io::Error::other)?;
    let mut file = root.open_file(leaf_name, FileAccess::CreateNew)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    root.sync_all().map_err(io::Error::other)
}

/// Replace one file only after its temporary contents have been synchronized.
/// The supplied counter remains the caller's sequence owner. Directory verification
/// precedes incrementing it; temporary names and failure cleanup stay deterministic.
/// A successful rename followed by a directory-sync failure sets `published` true.
pub fn atomic_replace(
    root: &ExclusiveDirectory,
    target_name: &str,
    bytes: &[u8],
    temporary_sequence: &AtomicU64,
) -> Result<(), AtomicReplaceError> {
    if let Err(error) = root.verify() {
        return Err(AtomicReplaceError {
            source: io::Error::other(error),
            published: false,
        });
    }
    let sequence = temporary_sequence.fetch_add(1, Ordering::Relaxed);
    let temporary_name = format!(".{target_name}.tmp-{}-{sequence:016x}", std::process::id());
    let write_result = (|| -> io::Result<()> {
        let mut file = root.open_file(&temporary_name, FileAccess::CreateNew)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()
    })();
    if let Err(source) = write_result {
        let _ = root.remove_file(&temporary_name);
        return Err(AtomicReplaceError {
            source,
            published: false,
        });
    }
    if let Err(source) = root.rename(&temporary_name, target_name) {
        let _ = root.remove_file(&temporary_name);
        return Err(AtomicReplaceError {
            source,
            published: false,
        });
    }
    if let Err(error) = root.sync_all() {
        return Err(AtomicReplaceError {
            source: io::Error::other(error),
            published: true,
        });
    }
    Ok(())
}
