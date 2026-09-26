//! Read-only admission for immutable staging followed by one authoritative root.
//! The caller retains its writer/HA authority fence from admission to execution.
use super::*;

pub struct ImmutablePublication<'a> {
    pub replay_epoch: u64,
    pub principal: &'a str,
    pub namespace: &'a str,
    pub operation_id: &'a str,
    pub authorization_digest: [u8; 32],
    pub objects: &'a [(String, &'a [u8])],
    pub root_resource: &'a str,
    pub root_bytes: &'a [u8],
}
impl fmt::Debug for ImmutablePublication<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImmutablePublication")
            .field("object_count", &self.objects.len())
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImmutablePublicationCapacity {
    pub new_objects: usize,
    pub batches: usize,
    pub snapshot_peak_bound: usize,
    pub final_snapshot_bound: usize,
    pub journal_peak_bound: usize,
    pub retained_requests_after: usize,
    pub replay_epoch_transitions: u64,
}
fn add(a: usize, b: usize) -> Result<usize, ServiceError> {
    a.checked_add(b)
        .ok_or(ServiceError::RequestCapacityExhausted)
}
fn protected_frame_bound<B: Barrier>(barrier: &B, plaintext: usize) -> Result<usize, ServiceError> {
    // Snapshot/ledger and journal frames each carry 48 outer bytes. The latter
    // includes the record-length prefix; JOURNAL_MAGIC belongs to the file.
    add(
        barrier
            .sealed_len_bound(plaintext)
            .ok_or(ServiceError::UnsupportedProfile)?,
        48,
    )
}
fn artifact_bound<B: Barrier>(barrier: &B, plaintext: usize) -> Result<usize, ServiceError> {
    let size = protected_frame_bound(barrier, plaintext)?;
    if size > MAX_FILE_BYTES {
        return Err(ServiceError::RequestCapacityExhausted);
    }
    Ok(size)
}
fn checkpoint_bound<B: Barrier>(barrier: &B, marker_len: usize) -> Result<usize, ServiceError> {
    add(
        JOURNAL_MAGIC.len(),
        protected_frame_bound(barrier, add(50, marker_len)?)?,
    )
}
fn batch_binding(key: &RequestKey, auth: &[u8; 32], batch: &[(&str, &[u8])]) -> [u8; 32] {
    let mut bytes = Vec::new();
    encode_string(&mut bytes, &key.principal);
    encode_string(&mut bytes, &key.namespace);
    encode_string(&mut bytes, &key.request_id);
    bytes.extend_from_slice(auth);
    for (resource, value) in batch {
        encode_string(&mut bytes, resource);
        bytes.push(1);
        bytes.extend_from_slice(&digest32(b"heptabao.durable-service.value.v1", value));
    }
    digest32(b"heptabao.durable-service.batch-binding.v1", &bytes)
}

impl<B: Barrier, P: DurableBackend> DurableService<B, P> {
    /// Admit the complete immutable publication before **any** remote or local
    /// staging. This neither retires epochs nor compacts/seals/writes artifacts.
    /// Existing resources are looked up only for this delta and must match bytes.
    /// Batches use `{operation}-objects-{0..}` for each 96 new objects, then
    /// `{operation}-root` for the remaining 0..95 objects and root replacement.
    /// The caller must execute this exact packing with compaction enabled and
    /// perform the indicated epoch transitions first. Admission is not a lease:
    /// it must be repeated after any intervening local durable mutation.
    pub fn preflight_immutable_publication(
        &self,
        publication: ImmutablePublication<'_>,
    ) -> Result<ImmutablePublicationCapacity, ServiceError> {
        if self.unresolved {
            return Err(ServiceError::RecoveryRequired);
        }
        self.backend.verify().map_err(map_backend_error)?;
        validate_identifier(publication.principal)?;
        validate_namespace(publication.namespace)?;
        validate_identifier(publication.operation_id)?;
        validate_resource(publication.root_resource)?;
        if publication.authorization_digest == [0; 32] {
            return Err(ServiceError::InvalidAuthorizationDigest);
        }
        let transitions = publication
            .replay_epoch
            .checked_sub(self.replay_epoch)
            .ok_or(ServiceError::ReplayEpochMismatch)?;
        if publication.root_bytes.is_empty() || publication.root_bytes.len() > MAX_SECRET_BYTES {
            return Err(ServiceError::InvalidSecret);
        }
        let old_marker_len = self
            .snapshot
            .last_commit
            .as_ref()
            .map(encoded_marker_len)
            .transpose()?
            .unwrap_or(0);
        let mut entries_bytes = self
            .snapshot_plaintext_bytes
            .checked_sub(old_marker_len)
            .ok_or(ServiceError::CorruptState)?;
        let mut marker_len = old_marker_len;
        let mut snapshot_peak = artifact_bound(&self.barrier, self.snapshot_plaintext_bytes)?;
        // The first retirement itself compacts the old full ledger; it cannot
        // assume the smaller empty ledger has already been published.
        artifact_bound(&self.barrier, self.ledger_plaintext_bytes)?;
        let mut ledger_bytes = if transitions > 0 {
            24
        } else {
            self.ledger_plaintext_bytes
        };
        let mut retained = if transitions > 0 {
            0
        } else {
            self.ledger.len()
        };
        let mut generation = self.snapshot.generation;
        let mut sequence = if transitions > 0 {
            1
        } else {
            self.journal_sequence
        };
        let mut journal = if transitions > 0 {
            checkpoint_bound(&self.barrier, marker_len)?
        } else {
            self.journal_bytes
        };
        if journal > self.journal_limit || journal > MAX_FILE_BYTES {
            return Err(ServiceError::JournalCapacityExhausted);
        }
        let mut journal_peak = journal;
        let mut seen = std::collections::BTreeMap::<&str, &[u8]>::new();
        let mut missing = Vec::new();
        for (resource, value) in publication.objects {
            validate_resource(resource)?;
            if resource == publication.root_resource {
                return Err(ServiceError::InvalidResource);
            }
            if value.is_empty() || value.len() > MAX_SECRET_BYTES {
                return Err(ServiceError::InvalidSecret);
            }
            if let Some(previous) = seen.insert(resource.as_str(), value) {
                if previous != *value {
                    return Err(ServiceError::RequestBindingConflict);
                }
                continue;
            }
            let key = (publication.namespace.to_owned(), resource.clone());
            match self.snapshot.entries.get(&key) {
                Some(old) if old.expose() != *value => {
                    return Err(ServiceError::RequestBindingConflict);
                }
                Some(_) => {}
                None => missing.push((resource.as_str(), *value)),
            }
        }
        let root_key = (
            publication.namespace.to_owned(),
            publication.root_resource.to_owned(),
        );
        let old_root = self.snapshot.entries.get(&root_key);
        let total_entries = self
            .snapshot
            .entries
            .len()
            .checked_add(missing.len())
            .and_then(|n| n.checked_add(usize::from(old_root.is_none())))
            .ok_or(ServiceError::RequestCapacityExhausted)?;
        if total_entries > MAX_RECORDS {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        let new_objects = missing.len();
        let batches = new_objects / MAX_ATOMIC_MUTATIONS + 1;
        let mut final_snapshot = snapshot_peak;
        for batch_index in 0..batches {
            let is_root = batch_index + 1 == batches;
            let start = batch_index * MAX_ATOMIC_MUTATIONS;
            let end = (start + MAX_ATOMIC_MUTATIONS).min(new_objects);
            let mut batch = missing[start..end].to_vec();
            let request_id = if is_root {
                batch.push((publication.root_resource, publication.root_bytes));
                format!("{}-root", publication.operation_id)
            } else {
                format!("{}-objects-{batch_index}", publication.operation_id)
            };
            let key = RequestKey {
                principal: publication.principal.to_owned(),
                namespace: publication.namespace.to_owned(),
                request_id: scope_request_id(publication.replay_epoch, &request_id)?,
            };
            let binding = batch_binding(&key, &publication.authorization_digest, &batch);
            if transitions == 0
                && let Some(prior) = self.ledger.get(&key)
            {
                if prior.binding_digest != binding
                    || batch.iter().any(|(resource, value)| {
                        self.snapshot
                            .entries
                            .get(&(publication.namespace.to_owned(), (*resource).to_owned()))
                            .is_none_or(|current| current.expose() != *value)
                    })
                {
                    return Err(ServiceError::RequestBindingConflict);
                }
                // An already materialized exact retry reserves no second slot.
                continue;
            }
            retained = retained
                .checked_add(1)
                .ok_or(ServiceError::RequestCapacityExhausted)?;
            if retained > self.max_retained_requests {
                return Err(ServiceError::RequestCapacityExhausted);
            }
            generation = generation
                .checked_add(1)
                .ok_or(ServiceError::GenerationOverflow)?;
            let marker = CommitMarker {
                key,
                binding_digest: binding,
                recovery_reference: "0".repeat(32),
                generation,
            };
            let next_marker_len = encoded_marker_len(&marker)?;
            ledger_bytes = add(ledger_bytes, next_marker_len)?;
            artifact_bound(&self.barrier, ledger_bytes)?;
            for (resource, value) in &missing[start..end] {
                entries_bytes = add(
                    entries_bytes,
                    snapshot_entry_len(publication.namespace, resource, value.len())?,
                )?;
            }
            // Do not discount the old root or any legacy objects in the staging
            // peak. Only the root replacement itself can remove old root bytes.
            snapshot_peak = snapshot_peak.max(artifact_bound(
                &self.barrier,
                add(entries_bytes, next_marker_len)?,
            )?);
            if is_root {
                if let Some(old) = old_root {
                    entries_bytes = entries_bytes
                        .checked_sub(snapshot_entry_len(
                            publication.namespace,
                            publication.root_resource,
                            old.expose().len(),
                        )?)
                        .ok_or(ServiceError::CorruptState)?;
                }
                entries_bytes = add(
                    entries_bytes,
                    snapshot_entry_len(
                        publication.namespace,
                        publication.root_resource,
                        publication.root_bytes.len(),
                    )?,
                )?;
            }
            final_snapshot = artifact_bound(&self.barrier, add(entries_bytes, next_marker_len)?)?;
            snapshot_peak = snapshot_peak.max(final_snapshot);
            let mutation_bytes = batch.iter().try_fold(0_usize, |total, (resource, value)| {
                add(total, add(9 + resource.len(), value.len())?)
            })?;
            let intent = protected_frame_bound(&self.barrier, add(1, next_marker_len)?)?;
            let apply = protected_frame_bound(
                &self.barrier,
                add(add(5, next_marker_len)?, mutation_bytes)?,
            )?;
            if apply > MAX_FILE_BYTES {
                return Err(ServiceError::RequestCapacityExhausted);
            }
            let frames = add(add(intent, apply)?, intent)?;
            let terminal = sequence
                .checked_add(3)
                .ok_or(ServiceError::GenerationOverflow)?;
            let next_journal = add(journal, frames)?;
            if terminal > MAX_RECORDS as u64
                || next_journal > self.journal_limit
                || next_journal > MAX_FILE_BYTES
            {
                // apply_batch_with_compaction checkpoints the *previous* state
                // before retrying. Previous snapshot/ledger bounds were already
                // validated; terminal remains reserved, including crash recovery.
                journal = checkpoint_bound(&self.barrier, marker_len)?;
                sequence = 1;
                // The barrier may conservatively overestimate. Actual writes
                // might fit without this simulated compaction, so the honest
                // upper bound in this branch is the configured journal limit.
                journal_peak = journal_peak.max(self.journal_limit.min(MAX_FILE_BYTES));
            }
            journal = add(journal, frames)?;
            sequence = sequence
                .checked_add(3)
                .ok_or(ServiceError::GenerationOverflow)?;
            if journal > self.journal_limit
                || journal > MAX_FILE_BYTES
                || sequence > MAX_RECORDS as u64
            {
                return Err(ServiceError::JournalCapacityExhausted);
            }
            journal_peak = journal_peak.max(journal);
            marker_len = next_marker_len;
        }
        Ok(ImmutablePublicationCapacity {
            new_objects,
            batches,
            snapshot_peak_bound: snapshot_peak,
            final_snapshot_bound: final_snapshot,
            journal_peak_bound: journal_peak,
            retained_requests_after: retained,
            replay_epoch_transitions: transitions,
        })
    }
}

#[cfg(test)]
mod tests;
