//! File publication mechanics only. Barrier authentication belongs to the service.
use super::*;
use sha2::{Digest, Sha256};

pub(crate) const RESTORE_MAGIC: &[u8; 4] = b"HBR1";
pub(crate) const MAX_RESTORE_INTENT_BYTES: usize = 8192;
const HASH_DOMAIN: &[u8] = b"heptabao.durable-service.restore-component.v1";
// Different stems prevent write_temp's extension replacement from aliasing.
const OLD: [&str; 3] = [
    "restore-old-state.hbs",
    "restore-old-ledger.hbl",
    "restore-old-journal.hbj",
];
const NEW: [&str; 3] = [
    "restore-new-state.hbs",
    "restore-new-ledger.hbl",
    "restore-new-journal.hbj",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreProfile {
    Atomic,
    FileIntent { target_identity: [u8; 16] },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactCommitment {
    pub length: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundleCommitment {
    /// Snapshot, ledger, journal, in that order.
    pub artifacts: [ArtifactCommitment; 3],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagedRestoreCommitments {
    pub old: BundleCommitment,
    pub new: BundleCommitment,
}

impl ArtifactCommitment {
    pub(crate) fn of(bytes: &[u8]) -> Self {
        Self {
            length: bytes.len() as u64,
            digest: crate::digest32(HASH_DOMAIN, bytes),
        }
    }
}
impl BundleCommitment {
    pub(crate) fn of(bundle: &BackendBundle) -> Self {
        Self {
            artifacts: [
                ArtifactCommitment::of(&bundle.snapshot),
                ArtifactCommitment::of(&bundle.ledger),
                ArtifactCommitment::of(&bundle.journal),
            ],
        }
    }
}

impl FileBackend {
    fn commit_restore_leaf(&mut self, leaf: &str, bytes: &[u8]) -> Result<(), BackendError> {
        self.verify()?;
        let temporary = self.write_temp(leaf, bytes)?;
        self.verify()?;
        fs::rename(temporary, self.path(leaf)?).map_err(|_| BackendError::OutcomeUnknown)?;
        self.directory
            .sync_all()
            .map_err(|_| BackendError::OutcomeUnknown)?;
        #[cfg(test)]
        {
            self.restore_step += 1;
            if self.restore_fail_after == Some(self.restore_step) {
                return Err(BackendError::OutcomeUnknown);
            }
        }
        Ok(())
    }

    pub(super) fn publish_file_restore(
        &mut self,
        expected: &BackendBundle,
        replacement: &BackendBundle,
        intent: &[u8],
    ) -> Result<(), BackendError> {
        expected.validate()?;
        replacement.validate()?;
        if !intent.starts_with(RESTORE_MAGIC) || intent.len() > MAX_RESTORE_INTENT_BYTES {
            return Err(BackendError::Corrupt);
        }
        if self.read_bundle()? != *expected || expected.snapshot.starts_with(RESTORE_MAGIC) {
            return Err(BackendError::StaleWriter);
        }
        // These stages are not authority. A crash here leaves the complete old
        // active state. Only an authenticated HBR1 at state.hbs commits intent.
        for (leaves, bundle) in [(OLD, expected), (NEW, replacement)] {
            for (leaf, bytes) in
                leaves
                    .into_iter()
                    .zip([&bundle.snapshot, &bundle.ledger, &bundle.journal])
            {
                self.commit_restore_leaf(leaf, bytes)?;
            }
        }
        if self.read_bundle()? != *expected {
            return Err(BackendError::StaleWriter);
        }
        self.commit_restore_leaf(SNAPSHOT_LEAF, intent)?;
        self.finish_file_restore(intent, replacement)
    }

    pub(super) fn finish_file_restore(
        &mut self,
        intent: &[u8],
        replacement: &BackendBundle,
    ) -> Result<(), BackendError> {
        replacement.validate()?;
        self.verify()?;
        if !intent.starts_with(RESTORE_MAGIC)
            || intent.len() > MAX_RESTORE_INTENT_BYTES
            || self.read_artifact(SNAPSHOT_LEAF)? != intent
        {
            return Err(BackendError::StaleWriter);
        }
        // The marker remains the active snapshot throughout both replacements.
        // An old reader cannot see a normal snapshot with a mixed epoch bundle.
        self.commit_restore_leaf(LEDGER_LEAF, &replacement.ledger)?;
        self.commit_restore_leaf(JOURNAL_LEAF, &replacement.journal)?;
        self.commit_restore_leaf(SNAPSHOT_LEAF, &replacement.snapshot)?;
        // Publication is already durable. Cleanup cannot invalidate it. Orphan
        // stages are sealed, ignored without HBR1, and replaced by the next txn.
        for leaf in OLD.into_iter().chain(NEW) {
            if let Ok(path) = self.path(leaf) {
                let _ = fs::remove_file(path);
            }
        }
        let _ = self.directory.sync_all();
        Ok(())
    }

    fn commitment(&self, leaf: &str) -> Result<ArtifactCommitment, BackendError> {
        let (mut file, length) = self.open_artifact(leaf, nofollow_options().read(true))?;
        let mut hasher = Sha256::new();
        hasher.update((HASH_DOMAIN.len() as u64).to_le_bytes());
        hasher.update(HASH_DOMAIN);
        hasher.update((length as u64).to_le_bytes());
        let mut buffer = [0; 64 * 1024];
        let mut read = 0_usize;
        loop {
            let n = file.read(&mut buffer).map_err(|_| BackendError::Io)?;
            if n == 0 {
                break;
            }
            read = read.checked_add(n).ok_or(BackendError::Capacity)?;
            if read > length {
                return Err(BackendError::Corrupt);
            }
            hasher.update(&buffer[..n]);
        }
        if read != length {
            return Err(BackendError::Corrupt);
        }
        self.verify()?;
        Ok(ArtifactCommitment {
            length: length as u64,
            digest: hasher.finalize().into(),
        })
    }

    pub(super) fn file_restore_commitments(
        &self,
    ) -> Result<StagedRestoreCommitments, BackendError> {
        let bundle = |leaves: [&str; 3]| -> Result<BundleCommitment, BackendError> {
            Ok(BundleCommitment {
                artifacts: [
                    self.commitment(leaves[0])?,
                    self.commitment(leaves[1])?,
                    self.commitment(leaves[2])?,
                ],
            })
        };
        Ok(StagedRestoreCommitments {
            old: bundle(OLD)?,
            new: bundle(NEW)?,
        })
    }

    pub(super) fn file_restore_replacement(&self) -> Result<BackendBundle, BackendError> {
        BackendBundle::new(
            self.read_artifact(NEW[0])?,
            self.read_artifact(NEW[1])?,
            self.read_artifact(NEW[2])?,
        )
    }

    #[cfg(test)]
    pub(crate) fn fail_restore_after(&mut self, step: usize) {
        self.restore_step = 0;
        self.restore_fail_after = Some(step);
    }
}
