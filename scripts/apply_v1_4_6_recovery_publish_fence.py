#!/usr/bin/env python3
from pathlib import Path


def replace(path: str, old: str, new: str, expected: int = 1) -> None:
    file = Path(path)
    value = file.read_text(encoding="utf-8")
    actual = value.count(old)
    if actual != expected:
        raise SystemExit(f"{path}: expected {expected} matches, found {actual}: {old[:160]!r}")
    file.write_text(value.replace(old, new, expected), encoding="utf-8")


path = "crates/heptabao-recovery-core/src/lib.rs"
replace(
    path,
    """        let anchor_revision = anchored_checkpoint.revision();
        let expected = RestoreReceipt {
""",
    """        let anchor_revision = anchored_checkpoint.revision();
        let publish_checkpoint = verified.checkpoint().clone();
        let expected = RestoreReceipt {
""",
)
replace(
    path,
    """        let staged = target
            .stage(authorized)
            .map_err(RecoveryRestoreError::Target)?;
        let receipt = target.publish(staged).map_err(|error| match error {
""",
    """        let staged = target
            .stage(authorized)
            .map_err(RecoveryRestoreError::Target)?;
        anchor.verify_current(&publish_checkpoint).map_err(|_| {
            RecoveryRestoreError::Contract(RecoveryContractError::CheckpointNotAnchored)
        })?;
        let receipt = target.publish(staged).map_err(|error| match error {
""",
)
replace(
    path,
    """mod tests {
    use super::*;
    use heptabao_journal_api::{AppendReceipt, JournalContractError, JournalOpenMode};
""",
    """mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use heptabao_journal_api::{AppendReceipt, JournalContractError, JournalOpenMode};
""",
)
replace(
    path,
    """    #[test]
    fn capture_encode_decode_verify_and_restore_round_trip() -> Result<(), Box<dyn Error>> {
""",
    """    #[derive(Debug)]
    struct SharedAnchor {
        current: Arc<Mutex<RecoveryCheckpoint>>,
    }

    impl RollbackAnchor for SharedAnchor {
        type Error = TestError;

        fn current(&self) -> Result<Option<RecoveryCheckpoint>, Self::Error> {
            self.current
                .lock()
                .map(|current| Some(current.clone()))
                .map_err(|_| TestError::Target)
        }

        fn compare_and_swap(
            &mut self,
            _expected_revision: Option<AnchorRevision>,
            _next: RecoveryCheckpoint,
        ) -> Result<AnchorAdvanceReceipt, Self::Error> {
            Err(TestError::Contract)
        }
    }

    #[derive(Debug)]
    struct StageAdvancesAnchorTarget {
        current: Arc<Mutex<RecoveryCheckpoint>>,
        advanced: RecoveryCheckpoint,
        publish_called: bool,
    }

    impl RecoveryTarget for StageAdvancesAnchorTarget {
        type Error = TestError;
        type Staged = AuthorizedRecoveryImage;

        fn is_empty(&self) -> Result<bool, Self::Error> {
            Ok(true)
        }

        fn stage(&mut self, image: AuthorizedRecoveryImage) -> Result<Self::Staged, Self::Error> {
            let mut current = self.current.lock().map_err(|_| TestError::Target)?;
            *current = self.advanced.clone();
            Ok(image)
        }

        fn publish(
            &mut self,
            _staged: Self::Staged,
        ) -> Result<RestoreReceipt, PublishFailure<Self::Error>> {
            self.publish_called = true;
            Err(PublishFailure::NotPublished(TestError::Target))
        }
    }

    #[test]
    fn anchor_advance_during_stage_prevents_publish() -> Result<(), Box<dyn Error>> {
        let store = MemoryStore::new()?;
        let journal = MemoryJournal::new()?;
        let checkpoint = checkpoint(&store, &journal)?;
        let advanced = RecoveryCheckpoint::from_parts(
            AnchorRevision::new(2)?,
            Some(checkpoint.digest()),
            checkpoint.authenticator_id().clone(),
            checkpoint.observation().clone(),
            CheckpointDigest::new([7; 32])?,
        )?;
        let shared = Arc::new(Mutex::new(checkpoint.clone()));
        let anchor = AnchorCoordinator::new(
            SharedAnchor {
                current: Arc::clone(&shared),
            },
            TestCheckpointAuthenticator::new()?,
        );
        let authenticator = TestAuthenticator::new()?;
        let archive = RecoveryArchive::capture(
            RecoveryArchiveId::new("recovery-stage-anchor-race".to_owned())?,
            &store,
            &journal,
            KeyEpoch::INITIAL,
            checkpoint,
            &authenticator,
        )?;
        let mut target = StageAdvancesAnchorTarget {
            current: shared,
            advanced,
            publish_called: false,
        };
        assert!(matches!(
            RecoveryRestorer::restore(&mut target, archive, &authenticator, &anchor),
            Err(RecoveryRestoreError::Contract(
                RecoveryContractError::CheckpointNotAnchored
            ))
        ));
        assert!(!target.publish_called);
        Ok(())
    }

    #[test]
    fn capture_encode_decode_verify_and_restore_round_trip() -> Result<(), Box<dyn Error>> {
""",
)
print("V1.4.6 recovery publish-fence patch applied")
