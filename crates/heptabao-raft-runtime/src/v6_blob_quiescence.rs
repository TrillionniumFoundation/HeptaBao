//! Nonblocking shared-operation ownership and one exclusive retirement owner.
//! The outer producer/read/archive keeps a lease for its COMPLETE operation;
//! short nested I/O leases alone cannot protect not-yet-staged ciphertext.
use super::*;
use std::sync::Arc;

const EXCLUSIVE: u64 = 1 << 63;
const MAX_OPERATIONS: u64 = 1 << 32;

#[derive(Debug, Default)]
pub(super) struct OperationState(AtomicU64);

#[derive(Debug)]
struct ActiveOperation {
    state: Arc<OperationState>,
}
impl Drop for ActiveOperation {
    fn drop(&mut self) {
        self.state.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Clones extend the SAME operation's lifetime. No constructor or wire fields
/// can manufacture a lease, and an upgradeable Weak handle is never exposed.
#[derive(Clone, Debug)]
pub struct NativeV6BlobOperation {
    _operation: Arc<ActiveOperation>,
}

/// Exclusive local blob ownership only. It is neither a retained-root mark,
/// Raft quorum, original Actor, deadline nor authority over local barrier files.
#[derive(Debug)]
pub struct NativeV6BlobQuiescence {
    state: Arc<OperationState>,
}
impl Drop for NativeV6BlobQuiescence {
    fn drop(&mut self) {
        self.state.0.store(0, Ordering::Release);
    }
}
impl NativeV6BlobQuiescence {
    pub(super) fn verify(&self, store: &LocalV6BlobStage) -> Result<(), LocalV6BlobError> {
        if !Arc::ptr_eq(&self.state, &store.operations)
            || self.state.0.load(Ordering::Acquire) != EXCLUSIVE
        {
            return Err(LocalV6BlobError::RetentionBusy);
        }
        store.directory.verify()?;
        Ok(())
    }
}

impl LocalV6BlobStage {
    pub fn begin_native_operation(&self) -> Result<NativeV6BlobOperation, LocalV6BlobError> {
        self.directory.verify()?;
        self.operations
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                if value & EXCLUSIVE == 0 && value < MAX_OPERATIONS {
                    Some(value + 1)
                } else {
                    None
                }
            })
            .map_err(|_| LocalV6BlobError::RetentionBusy)?;
        Ok(NativeV6BlobOperation {
            _operation: Arc::new(ActiveOperation {
                state: Arc::clone(&self.operations),
            }),
        })
    }

    /// No waiting or budget renewal. Every in-flight producer, read/backup and
    /// replica operation must already have released its original lease.
    pub fn try_native_quiescence(&self) -> Result<NativeV6BlobQuiescence, LocalV6BlobError> {
        self.directory.verify()?;
        self.operations
            .0
            .compare_exchange(0, EXCLUSIVE, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| LocalV6BlobError::RetentionBusy)?;
        Ok(NativeV6BlobQuiescence {
            state: Arc::clone(&self.operations),
        })
    }

    /// Read-only composition check. This is still NOT an unlink permission:
    /// the caller must mark every retained manifest, retain original Actor and
    /// exact local metadata ownership, and durably close the physical intent.
    pub fn verify_retention_ownership(
        &self,
        retained: &crate::NativeV6RetentionGuard,
        exclusive: &NativeV6BlobQuiescence,
    ) -> Result<(), LocalV6BlobError> {
        exclusive.verify(self)?;
        retained
            .verify_blob_directory(&self.directory)
            .map_err(|_| LocalV6BlobError::CorruptOrChanged)?;
        exclusive.verify(self)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn store() -> Result<(std::path::PathBuf, LocalV6BlobStage), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "hb-v6-retention-lease-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        let store = LocalV6BlobStage::open_existing(&root)?;
        Ok((root, store))
    }
    #[test]
    fn native_retention_operations_and_cloned_archive_pins_block_exclusive_gc()
    -> Result<(), Box<dyn std::error::Error>> {
        let (path, store) = store()?;
        let lease = store.begin_native_operation()?;
        let archive = lease.clone();
        assert!(store.try_native_quiescence().is_err());
        // Nested I/O is permitted without a recursive RwLock or writer wait.
        let leaf = store.stage_local(&[0x55; 64])?;
        assert_eq!(store.read_local(leaf.reference())?, vec![0x55; 64]);
        drop(lease);
        assert!(store.try_native_quiescence().is_err());
        drop(archive);
        let exclusive = store.try_native_quiescence()?;
        exclusive.verify(&store)?;
        assert!(store.begin_native_operation().is_err());
        assert!(store.read_local(leaf.reference()).is_err());
        assert!(store.stage_local(&[0x66; 64]).is_err());
        drop(exclusive);
        assert_eq!(store.read_local(leaf.reference())?, vec![0x55; 64]);
        drop(store);
        std::fs::remove_dir_all(path)?;
        Ok(())
    }
    #[test]
    fn native_retention_exclusive_owner_cannot_cross_store_or_cold_instance()
    -> Result<(), Box<dyn std::error::Error>> {
        let (path, store) = store()?;
        let (other_path, other) = self::store()?;
        let exclusive = store.try_native_quiescence()?;
        assert!(exclusive.verify(&other).is_err());
        drop(store);
        let cold = LocalV6BlobStage::open_existing(&path)?;
        assert!(exclusive.verify(&cold).is_err());
        drop(exclusive);
        let current = cold.try_native_quiescence()?;
        current.verify(&cold)?;
        drop(current);
        drop(cold);
        drop(other);
        std::fs::remove_dir_all(path)?;
        std::fs::remove_dir_all(other_path)?;
        Ok(())
    }
}
