//! Re-seal one authenticated incoming state at a fresh, source-bound frontier.
//! Application owner/clock validation remains mandatory at the V6 caller.
use super::*;

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    pub(crate) fn v6_projection_target(
        &self,
        source: &PreparedRestore,
    ) -> Result<(u64, u64), ServiceError> {
        self.verify_prepared_restore(source)?;
        Ok((
            self.generation()
                .max(source.metadata().generation)
                .checked_add(1)
                .ok_or(ServiceError::GenerationOverflow)?,
            self.replay_epoch
                .max(source.metadata().replay_epoch)
                .checked_add(1)
                .ok_or(ServiceError::ReplayEpochMismatch)?,
        ))
    }

    // The original affine instance/frontier survives this derivation. Only the
    // incoming application's selected resources change; neither an archived
    // request identity nor an old generation can name the new root.
    pub(crate) fn project_prepared_v6_state(
        &self,
        source: &PreparedRestore,
        target: (u64, u64),
        changes: Vec<(String, Secret)>,
        original: &mut impl FnMut() -> Result<(), ServiceError>,
    ) -> Result<PreparedRestore, ServiceError> {
        original()?;
        if self.v6_projection_target(source)? != target || changes.is_empty() {
            return Err(ServiceError::RequestBindingConflict);
        }
        let mut binding = Vec::new();
        for value in [
            self.generation(),
            self.replay_epoch,
            source.metadata().generation,
            source.metadata().replay_epoch,
            target.0,
            target.1,
        ] {
            binding.extend_from_slice(&value.to_be_bytes());
        }
        let current_root = self.get("system", "state")?;
        for root in [
            current_root.as_ref().map(Secret::expose),
            source.get("system", "state")?,
        ] {
            let root = root.ok_or(ServiceError::CorruptState)?;
            binding.extend_from_slice(&digest32(b"heptabao.v6-restore.source-root.v1", root));
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut snapshot = source.components.snapshot.clone();
        for (resource, value) in changes {
            original()?;
            validate_resource(&resource)?;
            if !seen.insert(resource.clone()) {
                return Err(ServiceError::InvalidResource);
            }
            encode_string(&mut binding, &resource);
            binding.extend_from_slice(&digest32(
                b"heptabao.v6-restore.projected-value.v1",
                value.expose(),
            ));
            snapshot.entries.insert(("system".into(), resource), value);
        }
        let binding_digest = digest32(b"heptabao.v6-restore.projection.v1", &binding);
        binding.zeroize();
        let id = binding_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let key = RequestKey {
            principal: "heptabao-server".into(),
            namespace: "system".into(),
            request_id: scope_request_id(target.1, &format!("v6-snapshot-projection-{id}"))?,
        };
        let recovery_reference = recovery_reference(&binding_digest, target.0, 1);
        snapshot.generation = target.0;
        snapshot.last_commit = Some(CommitMarker {
            key: key.clone(),
            binding_digest,
            recovery_reference: recovery_reference.clone(),
            generation: target.0,
        });
        if snapshot_plaintext_len(&snapshot)? > MAX_FILE_BYTES {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        let snapshot_bytes = sealed_snapshot(&self.barrier, &snapshot)?;
        if snapshot_bytes.len() > MAX_FILE_BYTES {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        // A fresh epoch retires both old live and archived replay frontiers.
        // The replacement ledger contains only this actual derivation, never
        // resurrected archived acknowledgements under a changed root.
        let retired = target
            .0
            .checked_sub(1)
            .ok_or(ServiceError::GenerationOverflow)?;
        let ledger = BTreeMap::from([(
            key,
            LedgerRecord {
                binding_digest,
                recovery_reference,
                generation: target.0,
            },
        )]);
        if ledger.len() > self.max_retained_requests {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        let ledger_bytes = sealed_ledger(&self.barrier, target.0, target.1, retired, &ledger)?;
        if ledger_bytes.len() > MAX_FILE_BYTES {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        let checkpoint = checkpoint_marker(&snapshot, &ledger, retired)?;
        let frame = sealed_journal_record(&self.barrier, 1, &JournalEvent::Checkpoint(checkpoint))?;
        let mut journal_bytes = Vec::with_capacity(JOURNAL_MAGIC.len() + frame.len());
        journal_bytes.extend_from_slice(JOURNAL_MAGIC);
        journal_bytes.extend_from_slice(&frame);
        if journal_bytes.len() > self.journal_limit || journal_bytes.len() > MAX_FILE_BYTES {
            return Err(ServiceError::JournalCapacityExhausted);
        }
        original()?;
        if self.v6_projection_target(source)? != target {
            return Err(ServiceError::RequestBindingConflict);
        }
        Ok(PreparedRestore {
            instance: Arc::clone(&source.instance),
            frontier: source.frontier,
            components: BackupComponents {
                snapshot_bytes,
                ledger_bytes,
                journal_bytes,
                snapshot,
                ledger,
                replay_epoch: target.1,
                retired_through_generation: retired,
                journal_sequence: 1,
            },
        })
    }
}
