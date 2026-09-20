//! Prove the protocol and capacity APIs need no filesystem-specific backend.
use super::tests::{TestBarrier, put_request};
use super::*;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Default)]
struct Stored {
    bundle: Option<BackendBundle>,
    owned: bool,
    appends: usize,
    checkpoints: usize,
    closes: usize,
    lose_append_ack: Option<usize>,
}

#[derive(Clone, Default)]
struct MemoryStore(Arc<Mutex<Stored>>);

impl MemoryStore {
    fn lock(&self) -> Result<MutexGuard<'_, Stored>, BackendError> {
        self.0.lock().map_err(|_| BackendError::Corrupt)
    }

    fn open(&self) -> Result<MemoryBackend, BackendError> {
        let mut stored = self.lock()?;
        if stored.owned {
            return Err(BackendError::WriterLocked);
        }
        stored.owned = true;
        Ok(MemoryBackend(self.clone()))
    }
}

struct MemoryBackend(MemoryStore);

impl Drop for MemoryBackend {
    fn drop(&mut self) {
        if let Ok(mut stored) = self.0.lock() {
            stored.owned = false;
        }
    }
}

impl DurableBackend for MemoryBackend {
    fn verify(&self) -> Result<(), BackendError> {
        if self.0.lock()?.owned {
            Ok(())
        } else {
            Err(BackendError::StaleWriter)
        }
    }

    fn load(&mut self) -> Result<BackendBundle, BackendError> {
        self.0
            .lock()?
            .bundle
            .clone()
            .ok_or(BackendError::MissingArtifact)
    }

    fn initialize_empty(&mut self, initial: &BackendBundle) -> Result<(), BackendError> {
        let mut stored = self.0.lock()?;
        if stored.bundle.is_some() {
            return Err(BackendError::RootNotEmpty);
        }
        stored.bundle = Some(initial.clone());
        Ok(())
    }

    fn append_journal(&mut self, expected_len: usize, frame: &[u8]) -> Result<usize, BackendError> {
        let mut stored = self.0.lock()?;
        let bundle = stored
            .bundle
            .as_mut()
            .ok_or(BackendError::MissingArtifact)?;
        if bundle.journal.len() != expected_len {
            return Err(BackendError::StaleWriter);
        }
        bundle.journal.extend_from_slice(frame);
        let new_len = bundle.journal.len();
        stored.appends += 1;
        if stored.lose_append_ack == Some(stored.appends) {
            stored.lose_append_ack = None;
            return Err(BackendError::OutcomeUnknown);
        }
        Ok(new_len)
    }

    fn truncate_journal(
        &mut self,
        expected_len: usize,
        new_len: usize,
    ) -> Result<(), BackendError> {
        let mut stored = self.0.lock()?;
        let bundle = stored
            .bundle
            .as_mut()
            .ok_or(BackendError::MissingArtifact)?;
        if bundle.journal.len() != expected_len || new_len > expected_len {
            return Err(BackendError::StaleWriter);
        }
        bundle.journal.truncate(new_len);
        Ok(())
    }

    fn publish_checkpoint(
        &mut self,
        expected: &BackendBundle,
        replacement: &BackendBundle,
    ) -> Result<(), BackendError> {
        let mut stored = self.0.lock()?;
        if stored.bundle.as_ref() != Some(expected) {
            return Err(BackendError::StaleWriter);
        }
        stored.bundle = Some(replacement.clone());
        stored.checkpoints += 1;
        Ok(())
    }

    fn close(self) -> Result<(), BackendError> {
        self.0.lock()?.closes += 1;
        Ok(())
    }
}

#[test]
fn injected_backend_runs_batch_checkpoint_restore_and_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::default();
    let mut service =
        DurableService::create_new_with_backend(store.open()?, TestBarrier::new(), 8)?;
    assert!(matches!(store.open(), Err(BackendError::WriterLocked)));
    service.apply_batch(
        "principal-a",
        "root/team-a",
        "batch-1",
        [7; 32],
        vec![
            (
                "secret/application".into(),
                Some(Secret::new(b"first".to_vec())?),
            ),
            (
                "secret/other".into(),
                Some(Secret::new(b"second".to_vec())?),
            ),
        ],
    )?;
    assert_eq!(service.capacity_status().generation, 1);
    service.compact()?;
    let backup = service.export_backup()?;
    service.put(put_request("after-backup", b"third")?)?;
    service.restore_backup(&backup, true)?;
    assert_eq!(service.generation(), 1);
    service.close()?;
    assert_eq!(store.lock()?.closes, 1);
    let service = DurableService::reopen_with_backend(store.open()?, TestBarrier::new(), 8)?;
    assert_eq!(service.generation(), 1);
    assert_eq!(
        service.list("root/team-a", "secret")?,
        vec!["application", "other"]
    );
    assert_eq!(
        service
            .get("root/team-a", "secret/application")?
            .as_ref()
            .map(Secret::expose),
        Some(b"first".as_slice())
    );
    assert!(store.lock()?.checkpoints >= 3);
    drop(service);
    assert!(store.open().is_ok());
    Ok(())
}

#[test]
fn injected_backend_lost_apply_ack_fences_and_recovers_once()
-> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::default();
    let mut service =
        DurableService::create_new_with_backend(store.open()?, TestBarrier::new(), 8)?;
    // Intent is acknowledged; Apply persists but its acknowledgement is lost.
    store.lock()?.lose_append_ack = Some(2);
    let result = service.put(put_request("lost-ack", b"durable")?);
    assert!(matches!(result, Err(ServiceError::OutcomeUnknown { .. })));
    assert!(service.recovery_required());
    assert!(matches!(
        service.put(put_request("next", b"blocked")?),
        Err(ServiceError::RecoveryRequired)
    ));
    drop(service);
    let mut service = DurableService::reopen_with_backend(store.open()?, TestBarrier::new(), 8)?;
    assert_eq!(service.generation(), 1);
    assert!(matches!(
        service.put(put_request("lost-ack", b"durable")?)?,
        MutationOutcome::Duplicate { generation: 1, .. }
    ));
    assert_eq!(service.generation(), 1);
    assert_eq!(
        service
            .get("root/team-a", "secret/application")?
            .as_ref()
            .map(Secret::expose),
        Some(b"durable".as_slice())
    );
    Ok(())
}
