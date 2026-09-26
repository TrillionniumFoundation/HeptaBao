//! Authenticated restore authority. File presence alone never authorizes replay.
use super::*;
use backend::{MAX_RESTORE_INTENT_BYTES, RESTORE_MAGIC};
use zeroize::Zeroizing;

const CONTEXT: &[u8] = b"heptabao.durable-service.restore-intent.v1";

// No Debug/Serialize: even physical identity and replay frontier stay private.
struct Intent {
    target: [u8; 16],
    old_authority: [u64; 5],
    new_authority: [u64; 3],
    commitments: StagedRestoreCommitments,
}

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    pub(super) fn restore_authority(&self) -> [u64; 5] {
        [
            self.snapshot.generation,
            self.replay_epoch,
            self.retired_through_generation,
            self.journal_sequence,
            self.journal_bytes as u64,
        ]
    }
}

fn write_commitment(bytes: &mut Vec<u8>, commitment: BundleCommitment) {
    for artifact in commitment.artifacts {
        write_u64(bytes, artifact.length);
        bytes.extend_from_slice(&artifact.digest);
    }
}

fn read_commitment(cursor: &mut Cursor<'_>) -> Result<BundleCommitment, ServiceError> {
    let mut artifacts = [ArtifactCommitment {
        length: 0,
        digest: [0; 32],
    }; 3];
    for artifact in &mut artifacts {
        artifact.length = cursor.read_u64()?;
        artifact.digest = cursor.read_array_32()?;
        if artifact.length > MAX_FILE_BYTES as u64 {
            return Err(ServiceError::CorruptState);
        }
    }
    Ok(BundleCommitment { artifacts })
}

pub(super) fn seal_intent<B: Barrier>(
    barrier: &B,
    target: [u8; 16],
    old_authority: [u64; 5],
    new_authority: [u64; 3],
    old: &BackendBundle,
    new: &BackendBundle,
) -> Result<Vec<u8>, ServiceError> {
    // Fixed-size authenticated metadata, not an extra plaintext backup copy.
    let mut plain = Zeroizing::new(Vec::with_capacity(322));
    write_u16(&mut plain, 1);
    plain.extend_from_slice(&target);
    for value in old_authority {
        write_u64(&mut plain, value);
    }
    for value in new_authority {
        write_u64(&mut plain, value);
    }
    write_commitment(&mut plain, BundleCommitment::of(old));
    write_commitment(&mut plain, BundleCommitment::of(new));
    let sealed = barrier
        .seal(CONTEXT, &plain)
        .map_err(|_| ServiceError::BarrierFailure)?;
    if sealed
        .len()
        .checked_add(8)
        .is_none_or(|length| length > MAX_RESTORE_INTENT_BYTES)
    {
        return Err(ServiceError::CorruptState);
    }
    let mut output = Vec::with_capacity(8 + sealed.len());
    output.extend_from_slice(RESTORE_MAGIC);
    write_bytes(&mut output, &sealed)?;
    Ok(output)
}

fn open_intent<B: Barrier>(barrier: &B, encoded: &[u8]) -> Result<Intent, ServiceError> {
    if encoded.len() > MAX_RESTORE_INTENT_BYTES {
        return Err(ServiceError::CorruptState);
    }
    let mut cursor = Cursor::new(encoded);
    if cursor.read_exact(4)? != RESTORE_MAGIC {
        return Err(ServiceError::CorruptState);
    }
    let sealed = cursor.read_bytes(MAX_RESTORE_INTENT_BYTES)?;
    cursor.finish()?;
    let plain = Zeroizing::new(
        barrier
            .open(CONTEXT, sealed)
            .map_err(|_| ServiceError::BarrierFailure)?,
    );
    let mut cursor = Cursor::new(&plain);
    if cursor.read_u16()? != 1 {
        return Err(ServiceError::CorruptState);
    }
    let target = cursor
        .read_exact(16)?
        .try_into()
        .map_err(|_| ServiceError::CorruptState)?;
    let mut old_authority = [0; 5];
    for value in &mut old_authority {
        *value = cursor.read_u64()?;
    }
    let mut new_authority = [0; 3];
    for value in &mut new_authority {
        *value = cursor.read_u64()?;
    }
    let commitments = StagedRestoreCommitments {
        old: read_commitment(&mut cursor)?,
        new: read_commitment(&mut cursor)?,
    };
    cursor.finish()?;
    if old_authority[2] > old_authority[0]
        || new_authority[2] > new_authority[0]
        || old_authority[4] != commitments.old.artifacts[2].length
        || commitments
            .new
            .artifacts
            .iter()
            .try_fold(60_u64, |total, artifact| total.checked_add(artifact.length))
            .is_none_or(|total| total > MAX_BACKUP_BYTES as u64)
    {
        return Err(ServiceError::CorruptState);
    }
    Ok(Intent {
        target,
        old_authority,
        new_authority,
        commitments,
    })
}

pub(super) fn reopen_pending<B: Barrier, P: DurableBackend>(
    mut backend: P,
    barrier: B,
    active: BackendBundle,
    max_retained_requests: usize,
) -> Result<DurableService<B, P>, ServiceError> {
    let intent = open_intent(&barrier, &active.snapshot)?;
    match backend.restore_profile().map_err(map_backend_error)? {
        RestoreProfile::FileIntent { target_identity } if target_identity == intent.target => {}
        _ => return Err(ServiceError::RequestBindingConflict),
    }
    let observed = backend
        .staged_restore_commitments()
        .map_err(map_backend_error)?;
    if observed != intent.commitments {
        return Err(ServiceError::CorruptState);
    }
    // Only the exact committed old->new prefix is recoverable. Neither file
    // existence nor independently valid but unrelated components are enough.
    let ledger = ArtifactCommitment::of(&active.ledger);
    let journal = ArtifactCommitment::of(&active.journal);
    let old = intent.commitments.old.artifacts;
    let new = intent.commitments.new.artifacts;
    if !((ledger == old[1] && journal == old[2])
        || (ledger == new[1] && journal == old[2])
        || (ledger == new[1] && journal == new[2]))
    {
        return Err(ServiceError::CorruptState);
    }
    // Drop old active encrypted buffers before materializing the incoming
    // backup. The retained old bundle was hashed using a 64KiB scratch buffer.
    let marker = active.snapshot;
    drop(active.ledger);
    drop(active.journal);
    let replacement = backend
        .staged_restore_replacement()
        .map_err(map_backend_error)?;
    if BundleCommitment::of(&replacement) != intent.commitments.new {
        return Err(ServiceError::CorruptState);
    }
    let mut restored = decode_backup_components(
        &barrier,
        intent.new_authority[0],
        replacement.snapshot,
        replacement.journal,
        replacement.ledger,
        max_retained_requests,
    )?;
    if [
        restored.snapshot.generation,
        restored.replay_epoch,
        restored.retired_through_generation,
    ] != intent.new_authority
    {
        return Err(ServiceError::CorruptState);
    }
    // Old frontier is authenticated alongside all old bytes, including journal
    // sequence. It is not substituted for the new epoch on rollback.
    let _old_authority = intent.old_authority;
    let snapshot_plaintext_bytes = snapshot_plaintext_len(&restored.snapshot)?;
    let ledger_plaintext_bytes = ledger_plaintext_len(&restored.ledger)?;
    let replacement = BackendBundle {
        snapshot: std::mem::take(&mut restored.snapshot_bytes),
        ledger: std::mem::take(&mut restored.ledger_bytes),
        journal: std::mem::take(&mut restored.journal_bytes),
    };
    backend.verify().map_err(map_backend_error)?;
    backend
        .finish_restore(&marker, &replacement)
        .map_err(map_backend_error)?;
    let snapshot = std::mem::replace(
        &mut restored.snapshot,
        Snapshot {
            generation: 0,
            entries: BTreeMap::new(),
            last_commit: None,
        },
    );
    let mut service = DurableService {
        backend,
        barrier,
        snapshot,
        snapshot_plaintext_bytes,
        ledger_plaintext_bytes,
        ledger: std::mem::take(&mut restored.ledger),
        replay_epoch: restored.replay_epoch,
        retired_through_generation: restored.retired_through_generation,
        reconciliation: BTreeMap::new(),
        journal_sequence: restored.journal_sequence,
        journal_bytes: replacement.journal.len(),
        journal_limit: MAX_FILE_BYTES,
        max_retained_requests,
        unresolved: false,
        restore_instance: std::sync::Arc::new(()),
    };
    service.rebuild_reconciliation()?;
    Ok(service)
}

#[cfg(test)]
mod tests;
