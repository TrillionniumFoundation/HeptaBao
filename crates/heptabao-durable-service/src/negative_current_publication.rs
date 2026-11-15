//! Read-only physical authentication for a negative no-write terminal gate.
//! This does not admit a request or return a restore/publication authority.
use super::*;

struct Materialized {
    snapshot: Snapshot,
    ledger: BTreeMap<RequestKey, LedgerRecord>,
    replay_epoch: u64,
    retired_through_generation: u64,
    journal_sequence: u64,
    journal_bytes: usize,
}

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    /// Read and authenticate the actual bounded backend bundle using its held
    /// writer session and this barrier. A terminal, exactly current publication
    /// is required. Pending/partial/repair-required artifacts are rejected.
    ///
    /// The only server consumer is a negative no-write integrity gate. This
    /// method performs no backend write, compaction, repair, reseal or clock
    /// observation, and cannot establish quorum or response authority. Two
    /// actual byte views and the lease are checked; this is not inode CAS
    /// protection against a non-cooperating external writer.
    pub fn verify_negative_current_publication(&mut self) -> Result<(), ServiceError> {
        self.verify_live_ownership()?;
        let bundle = self.backend.load().map_err(map_backend_error)?;
        let current = materialize(&self.barrier, &bundle, self.max_retained_requests)?;
        if current.snapshot != self.snapshot
            || current.ledger != self.ledger
            || current.replay_epoch != self.replay_epoch
            || current.retired_through_generation != self.retired_through_generation
            || current.journal_sequence != self.journal_sequence
            || current.journal_bytes != self.journal_bytes
        {
            return Err(ServiceError::CorruptState);
        }
        self.verify_live_ownership()?;
        let after = self.backend.load().map_err(map_backend_error)?;
        if after != bundle {
            return Err(ServiceError::CorruptState);
        }
        self.verify_live_ownership()
    }
}

fn materialize<B: Barrier>(
    barrier: &B,
    bundle: &BackendBundle,
    max_retained_requests: usize,
) -> Result<Materialized, ServiceError> {
    if bundle.snapshot.starts_with(backend::RESTORE_MAGIC) {
        return Err(ServiceError::RecoveryRequired);
    }
    let mut snapshot = decode_snapshot_frame(&bundle.snapshot, barrier)?;
    let (journal_sequence, events, journal_bytes, incomplete_tail) =
        decode_journal_frames(&bundle.journal, barrier)?;
    if incomplete_tail || journal_bytes != bundle.journal.len() {
        return Err(ServiceError::RecoveryRequired);
    }
    let (ledger_generation, replay_epoch, retired_through_generation, ledger) =
        decode_ledger_frame(&bundle.ledger, barrier)?;
    validate_ledger_generation(&ledger, ledger_generation, retired_through_generation)?;
    let mut pending: Option<CommitMarker> = None;
    let mut pending_applied = false;
    let mut committed: BTreeMap<RequestKey, CommitMarker> = BTreeMap::new();
    let mut last_commit: Option<CommitMarker> = None;
    let mut committed_generation = 0_u64;
    let mut references = std::collections::BTreeSet::new();
    let mut saw_checkpoint = false;

    for (offset, event) in events.into_iter().enumerate() {
        match event {
            JournalEvent::Checkpoint(checkpoint) => {
                if offset != 0
                    || saw_checkpoint
                    || pending.is_some()
                    || pending_applied
                    || !committed.is_empty()
                {
                    return Err(ServiceError::CorruptState);
                }
                saw_checkpoint = true;
                let prefix =
                    ledger_prefix(&ledger, checkpoint.generation, retired_through_generation)?;
                validate_checkpoint(&checkpoint, &prefix, retired_through_generation)?;
                committed_generation = checkpoint.generation;
                last_commit = checkpoint.last_commit.clone();
                for (key, record) in prefix {
                    let marker = marker_from_ledger(&key, &record)?;
                    if !references.insert(marker.recovery_reference.clone()) {
                        return Err(ServiceError::CorruptState);
                    }
                    committed.insert(key, marker);
                }
            }
            JournalEvent::Intent(marker) => {
                validate_marker(&marker)?;
                let sequence = u64::try_from(offset)
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .ok_or(ServiceError::GenerationOverflow)?;
                if pending.is_some()
                    || pending_applied
                    || committed.contains_key(&marker.key)
                    || marker.generation
                        != committed_generation
                            .checked_add(1)
                            .ok_or(ServiceError::GenerationOverflow)?
                    || marker.recovery_reference
                        != recovery_reference(&marker.binding_digest, marker.generation, sequence)
                    || !references.insert(marker.recovery_reference.clone())
                {
                    return Err(ServiceError::CorruptState);
                }
                pending = Some(marker);
            }
            JournalEvent::Apply { marker, mutations } => {
                if pending.as_ref() != Some(&marker) || pending_applied {
                    return Err(ServiceError::CorruptState);
                }
                apply_journal_mutations(&mut snapshot, &marker, &mutations)?;
                pending_applied = true;
            }
            JournalEvent::Commit(marker) => {
                if pending.as_ref() != Some(&marker) {
                    return Err(ServiceError::CorruptState);
                }
                // Legacy journals have Intent -> full snapshot publication ->
                // Commit and therefore no Apply frame. Such a commit is valid
                // only when the authenticated checkpoint snapshot already
                // contains that generation. New journals use Apply as the
                // durable application-state publication.
                if !pending_applied && marker.generation > snapshot.generation {
                    return Err(ServiceError::CorruptState);
                }
                pending = None;
                pending_applied = false;
                committed_generation = marker.generation;
                last_commit = Some(marker.clone());
                committed.insert(marker.key.clone(), marker);
            }
            JournalEvent::Abort(marker) => {
                if pending.as_ref() != Some(&marker) || pending_applied {
                    return Err(ServiceError::CorruptState);
                }
                pending = None;
            }
        }
    }
    let expected_active = committed_generation
        .checked_sub(retired_through_generation)
        .ok_or(ServiceError::CorruptState)?;
    if committed.len() as u64 != expected_active {
        return Err(ServiceError::CorruptState);
    }
    // Snapshot files are authenticated checkpoints and may lag the journal.
    // apply_journal_mutations advances the in-memory snapshot for every
    // committed delta after that checkpoint. A sole pending Apply is already
    // a durable commit even when its trailing bookkeeping frame was lost.
    let published_pending = pending.as_ref().is_some_and(|marker| {
        snapshot.generation == marker.generation && snapshot.last_commit.as_ref() == Some(marker)
    });
    if !published_pending
        && (snapshot.generation != committed_generation || snapshot.last_commit != last_commit)
    {
        return Err(ServiceError::CorruptState);
    }
    if snapshot.generation == 0 && (!snapshot.entries.is_empty() || snapshot.last_commit.is_some())
    {
        return Err(ServiceError::CorruptState);
    }
    // The persisted ledger is a checkpoint prefix. Ordinary committed
    // requests after that checkpoint live in the authenticated journal and
    // are rebuilt below, so the ledger may legitimately lag by many
    // generations. It may never lead the journal's committed frontier.
    if ledger_generation > committed_generation {
        return Err(ServiceError::CorruptState);
    }
    for (key, marker) in &committed {
        if marker.generation <= ledger_generation {
            let record = ledger.get(key).ok_or(ServiceError::CorruptState)?;
            if marker.binding_digest != record.binding_digest
                || marker.generation != record.generation
                || marker.recovery_reference != record.recovery_reference
            {
                return Err(ServiceError::CorruptState);
            }
        } else if ledger.contains_key(key) {
            return Err(ServiceError::CorruptState);
        }
    }
    for key in ledger.keys() {
        if !committed.contains_key(key) {
            return Err(ServiceError::CorruptState);
        }
    }
    if committed.len() + usize::from(published_pending) > max_retained_requests {
        return Err(ServiceError::RequestCapacityExhausted);
    }

    if pending.is_some() || pending_applied || published_pending {
        return Err(ServiceError::RecoveryRequired);
    }
    let ledger = committed
        .into_iter()
        .map(|(key, marker)| {
            (
                key,
                LedgerRecord {
                    binding_digest: marker.binding_digest,
                    recovery_reference: marker.recovery_reference,
                    generation: marker.generation,
                },
            )
        })
        .collect();
    validate_committed_state(
        &snapshot,
        snapshot.generation,
        retired_through_generation,
        &ledger,
    )?;
    Ok(Materialized {
        snapshot,
        ledger,
        replay_epoch,
        retired_through_generation,
        journal_sequence,
        journal_bytes,
    })
}

#[cfg(test)]
#[path = "negative_current_publication_tests.rs"]
mod tests;
