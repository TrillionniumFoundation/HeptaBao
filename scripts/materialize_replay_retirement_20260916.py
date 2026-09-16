from pathlib import Path

LIB = Path('crates/heptabao-durable-service/src/lib.rs')
CAP = Path('crates/heptabao-durable-service/src/capacity.rs')


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected one match, found {count}')
    return text.replace(old, new, 1)


s = LIB.read_text()
s = replace_once(s,
    'const LEDGER_PLAINTEXT_MAGIC: &[u8; 4] = b"HBC2";',
    'const LEGACY_LEDGER_PLAINTEXT_MAGIC: &[u8; 4] = b"HBC2";\nconst LEDGER_PLAINTEXT_MAGIC: &[u8; 4] = b"HBC3";',
    'ledger plaintext magic')

s = replace_once(s,
'''#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreOutcome {
    pub previous_generation: u64,
    pub restored_generation: u64,
    pub retained_requests: usize,
}
''',
'''#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreOutcome {
    pub previous_generation: u64,
    pub restored_generation: u64,
    pub retained_requests: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayRetirementOutcome {
    pub previous_epoch: u64,
    pub current_epoch: u64,
    pub retired_through_generation: u64,
    pub retired_requests: usize,
}
''', 'retirement outcome')

s = replace_once(s,
'''    RequestBindingConflict,
    RequestCapacityExhausted,
    BackupRollbackRejected,
''',
'''    RequestBindingConflict,
    ReplayEpochMismatch,
    RequestCapacityExhausted,
    BackupRollbackRejected,
''', 'error variant')

s = replace_once(s,
'''            Self::RequestBindingConflict => {
                formatter.write_str("request identity is bound to a different operation")
            }
            Self::RequestCapacityExhausted => {
''',
'''            Self::RequestBindingConflict => {
                formatter.write_str("request identity is bound to a different operation")
            }
            Self::ReplayEpochMismatch => {
                formatter.write_str("request replay epoch is not current")
            }
            Self::RequestCapacityExhausted => {
''', 'error display')

s = replace_once(s,
'''    snapshot: Snapshot,
    ledger: BTreeMap<RequestKey, LedgerRecord>,
    reconciliation: BTreeMap<String, ReconciliationStatus>,
''',
'''    snapshot: Snapshot,
    ledger: BTreeMap<RequestKey, LedgerRecord>,
    replay_epoch: u64,
    retired_through_generation: u64,
    reconciliation: BTreeMap<String, ReconciliationStatus>,
''', 'service replay fields')

s = replace_once(s,
'''    snapshot: Snapshot,
    ledger: BTreeMap<RequestKey, LedgerRecord>,
    journal_sequence: u64,
''',
'''    snapshot: Snapshot,
    ledger: BTreeMap<RequestKey, LedgerRecord>,
    replay_epoch: u64,
    retired_through_generation: u64,
    journal_sequence: u64,
''', 'backup replay fields')

s = replace_once(s,
'''        persist_ledger(&root, &barrier, 0, &ledger)?;
        Ok(Self {
            root,
            directory,
            barrier,
            snapshot,
            ledger,
            reconciliation: BTreeMap::new(),
''',
'''        persist_ledger(&root, &barrier, 0, 0, 0, &ledger)?;
        Ok(Self {
            root,
            directory,
            barrier,
            snapshot,
            ledger,
            replay_epoch: 0,
            retired_through_generation: 0,
            reconciliation: BTreeMap::new(),
''', 'create replay state')

s = replace_once(s,
'''        let (ledger_generation, ledger) = load_ledger(&root, &barrier)?;
        let mut service = Self {
            root,
            directory,
            barrier,
            snapshot,
            ledger,
            reconciliation: BTreeMap::new(),
''',
'''        let (ledger_generation, replay_epoch, retired_through_generation, ledger) =
            load_ledger(&root, &barrier)?;
        let mut service = Self {
            root,
            directory,
            barrier,
            snapshot,
            ledger,
            replay_epoch,
            retired_through_generation,
            reconciliation: BTreeMap::new(),
''', 'reopen replay state')

s = replace_once(s,
'''    pub fn put(&mut self, request: PutRequest) -> Result<MutationOutcome, ServiceError> {
        self.put_with_failpoint(request, Failpoint::None)
    }
''',
'''    pub fn put(&mut self, request: PutRequest) -> Result<MutationOutcome, ServiceError> {
        self.put_in_replay_epoch(0, request)
    }

    pub fn put_in_replay_epoch(
        &mut self,
        replay_epoch: u64,
        request: PutRequest,
    ) -> Result<MutationOutcome, ServiceError> {
        self.put_with_epoch_policy(request, Failpoint::None, false, replay_epoch)
    }
''', 'epoch put entrypoint')

s = replace_once(s,
'''    pub fn put_with_failpoint(
        &mut self,
        request: PutRequest,
        failpoint: Failpoint,
    ) -> Result<MutationOutcome, ServiceError> {
        self.put_with_policy(request, failpoint, false)
    }

    fn put_with_policy(
        &mut self,
        mut request: PutRequest,
        failpoint: Failpoint,
        compact_before_entry: bool,
    ) -> Result<MutationOutcome, ServiceError> {
        request.validate()?;
''',
'''    pub fn put_with_failpoint(
        &mut self,
        request: PutRequest,
        failpoint: Failpoint,
    ) -> Result<MutationOutcome, ServiceError> {
        self.put_with_policy(request, failpoint, false)
    }

    fn put_with_policy(
        &mut self,
        request: PutRequest,
        failpoint: Failpoint,
        compact_before_entry: bool,
    ) -> Result<MutationOutcome, ServiceError> {
        self.put_with_epoch_policy(request, failpoint, compact_before_entry, 0)
    }

    fn put_with_epoch_policy(
        &mut self,
        mut request: PutRequest,
        failpoint: Failpoint,
        compact_before_entry: bool,
        replay_epoch: u64,
    ) -> Result<MutationOutcome, ServiceError> {
        request.validate()?;
        if replay_epoch != self.replay_epoch {
            return Err(ServiceError::ReplayEpochMismatch);
        }
''', 'put epoch policy')

s = replace_once(s,
'''                request_id: request.request_id,
            },
            resource: request.resource,
            kind: MutationKind::Put,
''',
'''                request_id: scope_request_id(replay_epoch, &request.request_id)?,
            },
            resource: request.resource,
            kind: MutationKind::Put,
''', 'put scoped request id')

s = replace_once(s,
'''    pub fn delete(&mut self, request: DeleteRequest) -> Result<MutationOutcome, ServiceError> {
        self.delete_with_failpoint(request, Failpoint::None)
    }
''',
'''    pub fn delete(&mut self, request: DeleteRequest) -> Result<MutationOutcome, ServiceError> {
        self.delete_in_replay_epoch(0, request)
    }

    pub fn delete_in_replay_epoch(
        &mut self,
        replay_epoch: u64,
        request: DeleteRequest,
    ) -> Result<MutationOutcome, ServiceError> {
        self.delete_with_epoch_failpoint(request, Failpoint::None, replay_epoch)
    }
''', 'epoch delete entrypoint')

s = replace_once(s,
'''    pub fn delete_with_failpoint(
        &mut self,
        request: DeleteRequest,
        failpoint: Failpoint,
    ) -> Result<MutationOutcome, ServiceError> {
        request.validate()?;
        let binding = Binding {
            key: RequestKey {
                principal: request.principal,
                namespace: request.namespace,
                request_id: request.request_id,
            },
''',
'''    pub fn delete_with_failpoint(
        &mut self,
        request: DeleteRequest,
        failpoint: Failpoint,
    ) -> Result<MutationOutcome, ServiceError> {
        self.delete_with_epoch_failpoint(request, failpoint, 0)
    }

    fn delete_with_epoch_failpoint(
        &mut self,
        request: DeleteRequest,
        failpoint: Failpoint,
        replay_epoch: u64,
    ) -> Result<MutationOutcome, ServiceError> {
        request.validate()?;
        if replay_epoch != self.replay_epoch {
            return Err(ServiceError::ReplayEpochMismatch);
        }
        let binding = Binding {
            key: RequestKey {
                principal: request.principal,
                namespace: request.namespace,
                request_id: scope_request_id(replay_epoch, &request.request_id)?,
            },
''', 'delete epoch policy')

s = replace_once(s,
'''    #[must_use]
    pub fn retained_request_count(&self) -> usize {
        self.ledger.len()
    }

    /// Report committed local capacity only.''',
'''    #[must_use]
    pub fn retained_request_count(&self) -> usize {
        self.ledger.len()
    }

    #[must_use]
    pub const fn replay_epoch(&self) -> u64 {
        self.replay_epoch
    }

    #[must_use]
    pub const fn retired_through_generation(&self) -> u64 {
        self.retired_through_generation
    }

    /// Retire every resolved request identity in the current replay epoch.
    ///
    /// The operation first checkpoints the complete active ledger, then publishes
    /// an authenticated HBC3 ledger carrying the next epoch and the exact retired
    /// generation frontier, and finally rewrites the journal checkpoint against
    /// the empty active ledger. A crash between those two replacements is
    /// recoverable because the authenticated frontier makes the old checkpoint
    /// historical rather than replay authority. Unknown outcomes must be
    /// reconciled before this maintenance operation is allowed.
    pub fn retire_replay_epoch(&mut self) -> Result<ReplayRetirementOutcome, ServiceError> {
        if self.unresolved {
            return Err(ServiceError::RecoveryRequired);
        }
        self.directory.verify().map_err(map_guard_error)?;
        self.compact()?;
        let previous_epoch = self.replay_epoch;
        let current_epoch = previous_epoch
            .checked_add(1)
            .ok_or(ServiceError::GenerationOverflow)?;
        let retired_through_generation = self.snapshot.generation;
        let retired_requests = self.ledger.len();
        let empty = BTreeMap::new();
        let ledger_bytes = sealed_ledger(
            &self.barrier,
            self.snapshot.generation,
            current_epoch,
            retired_through_generation,
            &empty,
        )?;
        let checkpoint = checkpoint_marker(
            &self.snapshot,
            &empty,
            retired_through_generation,
        )?;
        let frame = sealed_journal_record(
            &self.barrier,
            1,
            &JournalEvent::Checkpoint(checkpoint),
        )?;
        let mut journal = Vec::with_capacity(JOURNAL_MAGIC.len() + frame.len());
        journal.extend_from_slice(JOURNAL_MAGIC);
        journal.extend_from_slice(&frame);
        if journal.len() > self.journal_limit {
            return Err(ServiceError::JournalCapacityExhausted);
        }
        self.unresolved = true;
        atomic_write(&self.root, &ledger_path(&self.root), &ledger_bytes)?;
        self.ledger.clear();
        self.replay_epoch = current_epoch;
        self.retired_through_generation = retired_through_generation;
        atomic_write(&self.root, &journal_path(&self.root), &journal)?;
        self.journal_sequence = 1;
        self.journal_bytes = journal.len();
        self.reconciliation.clear();
        self.unresolved = false;
        Ok(ReplayRetirementOutcome {
            previous_epoch,
            current_epoch,
            retired_through_generation,
            retired_requests,
        })
    }

    /// Report committed local capacity only.''', 'retirement API')

s = s.replace(
    'validate_committed_state(&self.snapshot, self.snapshot.generation, &self.ledger)?;',
    'validate_committed_state(\n            &self.snapshot,\n            self.snapshot.generation,\n            self.retired_through_generation,\n            &self.ledger,\n        )?;')
s = s.replace(
    'checkpoint_marker(&self.snapshot, &self.ledger)?',
    'checkpoint_marker(&self.snapshot, &self.ledger, self.retired_through_generation)?')
s = s.replace(
    'sealed_ledger(&self.barrier, self.snapshot.generation, &self.ledger)?',
    'sealed_ledger(\n            &self.barrier,\n            self.snapshot.generation,\n            self.replay_epoch,\n            self.retired_through_generation,\n            &self.ledger,\n        )?')
s = s.replace(
    'sealed_ledger(&self.barrier, generation, &candidate_ledger)?',
    'sealed_ledger(\n            &self.barrier,\n            generation,\n            self.replay_epoch,\n            self.retired_through_generation,\n            &candidate_ledger,\n        )?')

s = replace_once(s,
'''        self.snapshot = restored.snapshot;
        self.ledger = restored.ledger;
        self.journal_sequence = restored.journal_sequence;
''',
'''        self.snapshot = restored.snapshot;
        self.ledger = restored.ledger;
        self.replay_epoch = restored.replay_epoch;
        self.retired_through_generation = restored.retired_through_generation;
        self.journal_sequence = restored.journal_sequence;
''', 'restore replay state')

s = replace_once(s,
'''        validate_ledger_generation(&self.ledger, ledger_generation)?;
''',
'''        validate_ledger_generation(
            &self.ledger,
            ledger_generation,
            self.retired_through_generation,
        )?;
''', 'recover ledger validation')

s = replace_once(s,
'''                    let prefix = ledger_prefix(&self.ledger, checkpoint.generation)?;
                    validate_checkpoint(&checkpoint, &prefix)?;
''',
'''                    let prefix = ledger_prefix(
                        &self.ledger,
                        checkpoint.generation,
                        self.retired_through_generation,
                    )?;
                    validate_checkpoint(
                        &checkpoint,
                        &prefix,
                        self.retired_through_generation,
                    )?;
''', 'recover checkpoint validation')

s = replace_once(s,
'''        if committed.len() as u64 != committed_generation {
            return Err(ServiceError::CorruptState);
        }
''',
'''        let expected_active = committed_generation
            .checked_sub(self.retired_through_generation)
            .ok_or(ServiceError::CorruptState)?;
        if committed.len() as u64 != expected_active {
            return Err(ServiceError::CorruptState);
        }
''', 'active committed count')

s = replace_once(s,
'''        persist_ledger(
            &self.root,
            &self.barrier,
            self.snapshot.generation,
            &self.ledger,
        )?;
''',
'''        persist_ledger(
            &self.root,
            &self.barrier,
            self.snapshot.generation,
            self.replay_epoch,
            self.retired_through_generation,
            &self.ledger,
        )?;
''', 'recover ledger persist')

start = s.index('fn validate_ledger_generation(')
end = s.index('\nfn validate_capacity(', start)
new_validation = r'''fn validate_ledger_generation(
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
    generation: u64,
    retired_through_generation: u64,
) -> Result<(), ServiceError> {
    if retired_through_generation > generation
        || ledger.len() as u64 != generation - retired_through_generation
    {
        return Err(ServiceError::CorruptState);
    }
    let mut generations = std::collections::BTreeSet::new();
    let mut references = std::collections::BTreeSet::new();
    for (key, record) in ledger {
        validate_identifier(&key.principal)?;
        validate_namespace(&key.namespace)?;
        validate_identifier(&key.request_id)?;
        validate_ledger_record(record)?;
        if record.generation <= retired_through_generation
            || record.generation > generation
            || !generations.insert(record.generation)
            || !references.insert(record.recovery_reference.clone())
        {
            return Err(ServiceError::CorruptState);
        }
    }
    if generations
        .iter()
        .copied()
        .ne(retired_through_generation.saturating_add(1)..=generation)
    {
        return Err(ServiceError::CorruptState);
    }
    Ok(())
}

fn validate_committed_state(
    snapshot: &Snapshot,
    ledger_generation: u64,
    retired_through_generation: u64,
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
) -> Result<(), ServiceError> {
    if snapshot.generation != ledger_generation {
        return Err(ServiceError::CorruptState);
    }
    validate_ledger_generation(ledger, ledger_generation, retired_through_generation)?;
    if ledger_generation == 0 {
        if snapshot.last_commit.is_some() || !ledger.is_empty() || retired_through_generation != 0 {
            return Err(ServiceError::CorruptState);
        }
        return Ok(());
    }
    if ledger_generation == retired_through_generation {
        let marker = snapshot.last_commit.as_ref().ok_or(ServiceError::CorruptState)?;
        validate_marker(marker)?;
        if marker.generation != ledger_generation || !ledger.is_empty() {
            return Err(ServiceError::CorruptState);
        }
        return Ok(());
    }
    let (key, record) = ledger
        .iter()
        .find(|(_, record)| record.generation == ledger_generation)
        .ok_or(ServiceError::CorruptState)?;
    if snapshot.last_commit.as_ref() != Some(&marker_from_ledger(key, record)?) {
        return Err(ServiceError::CorruptState);
    }
    Ok(())
}

fn marker_from_ledger(
    key: &RequestKey,
    record: &LedgerRecord,
) -> Result<CommitMarker, ServiceError> {
    validate_ledger_record(record)?;
    let marker = CommitMarker {
        key: key.clone(),
        binding_digest: record.binding_digest,
        recovery_reference: record.recovery_reference.clone(),
        generation: record.generation,
    };
    validate_marker(&marker)?;
    Ok(marker)
}

fn ledger_prefix(
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
    generation: u64,
    retired_through_generation: u64,
) -> Result<BTreeMap<RequestKey, LedgerRecord>, ServiceError> {
    if generation < retired_through_generation {
        return Err(ServiceError::CorruptState);
    }
    let prefix = ledger
        .iter()
        .filter(|(_, record)| {
            record.generation > retired_through_generation && record.generation <= generation
        })
        .map(|(key, record)| (key.clone(), record.clone()))
        .collect::<BTreeMap<_, _>>();
    validate_ledger_generation(&prefix, generation, retired_through_generation)?;
    Ok(prefix)
}

fn checkpoint_marker(
    snapshot: &Snapshot,
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
    retired_through_generation: u64,
) -> Result<CheckpointMarker, ServiceError> {
    validate_committed_state(
        snapshot,
        snapshot.generation,
        retired_through_generation,
        ledger,
    )?;
    let encoded = Zeroizing::new(encode_ledger(ledger)?);
    Ok(CheckpointMarker {
        generation: snapshot.generation,
        retained_requests: ledger.len() as u64,
        last_commit: snapshot.last_commit.clone(),
        ledger_digest: digest32(b"heptabao.durable-service.checkpoint-ledger.v1", &encoded),
    })
}

fn validate_checkpoint(
    checkpoint: &CheckpointMarker,
    prefix: &BTreeMap<RequestKey, LedgerRecord>,
    retired_through_generation: u64,
) -> Result<(), ServiceError> {
    if checkpoint.generation < retired_through_generation {
        return Err(ServiceError::CorruptState);
    }
    if checkpoint.generation == retired_through_generation {
        if !prefix.is_empty() {
            return Err(ServiceError::CorruptState);
        }
        if checkpoint.generation == 0 {
            if checkpoint.last_commit.is_some() {
                return Err(ServiceError::CorruptState);
            }
        } else {
            let marker = checkpoint
                .last_commit
                .as_ref()
                .ok_or(ServiceError::CorruptState)?;
            validate_marker(marker)?;
            if marker.generation != checkpoint.generation {
                return Err(ServiceError::CorruptState);
            }
        }
        // During retirement the authenticated HBC3 ledger can be published
        // immediately after a complete pre-retirement checkpoint and before the
        // replacement empty-ledger checkpoint. The old checkpoint's ledger
        // digest is historical once the HBC3 frontier equals its generation.
        return Ok(());
    }
    if checkpoint.retained_requests != prefix.len() as u64
        || checkpoint.retained_requests != checkpoint.generation - retired_through_generation
    {
        return Err(ServiceError::CorruptState);
    }
    validate_ledger_generation(prefix, checkpoint.generation, retired_through_generation)?;
    let encoded = Zeroizing::new(encode_ledger(prefix)?);
    let expected = digest32(b"heptabao.durable-service.checkpoint-ledger.v1", &encoded);
    if !constant_time_eq(&checkpoint.ledger_digest, &expected) {
        return Err(ServiceError::CorruptState);
    }
    let (key, record) = prefix
        .iter()
        .find(|(_, record)| record.generation == checkpoint.generation)
        .ok_or(ServiceError::CorruptState)?;
    if checkpoint.last_commit.as_ref() != Some(&marker_from_ledger(key, record)?) {
        return Err(ServiceError::CorruptState);
    }
    Ok(())
}
'''
s = s[:start] + new_validation + s[end:]

s = replace_once(s,
'''fn persist_ledger<B: Barrier>(
    root: &Path,
    barrier: &B,
    generation: u64,
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
) -> Result<(), ServiceError> {
    let encoded = sealed_ledger(barrier, generation, ledger)?;
    atomic_write(root, &ledger_path(root), &encoded)
}

fn sealed_ledger<B: Barrier>(
    barrier: &B,
    generation: u64,
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
) -> Result<Vec<u8>, ServiceError> {
    let plaintext = Zeroizing::new(encode_ledger(ledger)?);
''',
'''fn persist_ledger<B: Barrier>(
    root: &Path,
    barrier: &B,
    generation: u64,
    replay_epoch: u64,
    retired_through_generation: u64,
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
) -> Result<(), ServiceError> {
    let encoded = sealed_ledger(
        barrier,
        generation,
        replay_epoch,
        retired_through_generation,
        ledger,
    )?;
    atomic_write(root, &ledger_path(root), &encoded)
}

fn sealed_ledger<B: Barrier>(
    barrier: &B,
    generation: u64,
    replay_epoch: u64,
    retired_through_generation: u64,
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
) -> Result<Vec<u8>, ServiceError> {
    validate_ledger_generation(ledger, generation, retired_through_generation)?;
    let plaintext = Zeroizing::new(encode_ledger_state(
        replay_epoch,
        retired_through_generation,
        ledger,
    )?);
''', 'ledger persistence signature')

s = replace_once(s,
'''fn load_ledger<B: Barrier>(
    root: &Path,
    barrier: &B,
) -> Result<(u64, BTreeMap<RequestKey, LedgerRecord>), ServiceError> {
    let encoded = read_bounded(&ledger_path(root))?;
    decode_ledger_frame(&encoded, barrier)
}

fn decode_ledger_frame<B: Barrier>(
    encoded: &[u8],
    barrier: &B,
) -> Result<(u64, BTreeMap<RequestKey, LedgerRecord>), ServiceError> {
''',
'''fn load_ledger<B: Barrier>(
    root: &Path,
    barrier: &B,
) -> Result<(u64, u64, u64, BTreeMap<RequestKey, LedgerRecord>), ServiceError> {
    let encoded = read_bounded(&ledger_path(root))?;
    decode_ledger_frame(&encoded, barrier)
}

fn decode_ledger_frame<B: Barrier>(
    encoded: &[u8],
    barrier: &B,
) -> Result<(u64, u64, u64, BTreeMap<RequestKey, LedgerRecord>), ServiceError> {
''', 'ledger load signature')

s = replace_once(s,
'''    let plaintext = Zeroizing::new(plaintext);
    Ok((generation, decode_ledger(&plaintext)?))
}
''',
'''    let plaintext = Zeroizing::new(plaintext);
    let (replay_epoch, retired_through_generation, ledger) = decode_ledger_state(&plaintext)?;
    validate_ledger_generation(&ledger, generation, retired_through_generation)?;
    Ok((
        generation,
        replay_epoch,
        retired_through_generation,
        ledger,
    ))
}
''', 'ledger decode return')

s = replace_once(s,
'''    let snapshot = decode_snapshot_frame(&snapshot_bytes, barrier)?;
    let (ledger_generation, ledger) = decode_ledger_frame(&ledger_bytes, barrier)?;
''',
'''    let snapshot = decode_snapshot_frame(&snapshot_bytes, barrier)?;
    let (ledger_generation, replay_epoch, retired_through_generation, ledger) =
        decode_ledger_frame(&ledger_bytes, barrier)?;
''', 'backup ledger decode')

s = replace_once(s,
'''    validate_committed_state(&snapshot, ledger_generation, &ledger)?;
    match &events[0] {
        JournalEvent::Checkpoint(checkpoint) => {
            validate_checkpoint(checkpoint, &ledger)?;
''',
'''    validate_committed_state(
        &snapshot,
        ledger_generation,
        retired_through_generation,
        &ledger,
    )?;
    match &events[0] {
        JournalEvent::Checkpoint(checkpoint) => {
            validate_checkpoint(checkpoint, &ledger, retired_through_generation)?;
''', 'backup validation')

s = replace_once(s,
'''        snapshot,
        ledger,
        journal_sequence,
''',
'''        snapshot,
        ledger,
        replay_epoch,
        retired_through_generation,
        journal_sequence,
''', 'backup components return')

# Replace the ledger codec with a versioned plaintext codec while retaining HBC2
# as the canonical active-ledger digest encoding used by journal checkpoints.
marker = 'fn encode_ledger(ledger: &BTreeMap<RequestKey, LedgerRecord>) -> Result<Vec<u8>, ServiceError> {'
start = s.index(marker)
end = s.index('\nfn encode_marker(', start)
codec = r'''fn encode_ledger(ledger: &BTreeMap<RequestKey, LedgerRecord>) -> Result<Vec<u8>, ServiceError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(LEGACY_LEDGER_PLAINTEXT_MAGIC);
    encode_ledger_records(&mut bytes, ledger)?;
    Ok(bytes)
}

fn encode_ledger_state(
    replay_epoch: u64,
    retired_through_generation: u64,
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
) -> Result<Vec<u8>, ServiceError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(LEDGER_PLAINTEXT_MAGIC);
    write_u64(&mut bytes, replay_epoch);
    write_u64(&mut bytes, retired_through_generation);
    encode_ledger_records(&mut bytes, ledger)?;
    Ok(bytes)
}

fn encode_ledger_records(
    bytes: &mut Vec<u8>,
    ledger: &BTreeMap<RequestKey, LedgerRecord>,
) -> Result<(), ServiceError> {
    write_u32(
        bytes,
        u32::try_from(ledger.len()).map_err(|_| ServiceError::CorruptState)?,
    );
    for (key, record) in ledger {
        encode_request_key(bytes, key)?;
        bytes.extend_from_slice(&record.binding_digest);
        encode_string_checked(bytes, &record.recovery_reference)?;
        write_u64(bytes, record.generation);
    }
    Ok(())
}

fn decode_ledger(bytes: &[u8]) -> Result<BTreeMap<RequestKey, LedgerRecord>, ServiceError> {
    if bytes.len() < 4 || &bytes[..4] != LEGACY_LEDGER_PLAINTEXT_MAGIC {
        return Err(ServiceError::CorruptState);
    }
    let mut cursor = Cursor::new(&bytes[4..]);
    let ledger = decode_ledger_records(&mut cursor)?;
    cursor.finish()?;
    Ok(ledger)
}

fn decode_ledger_state(
    bytes: &[u8],
) -> Result<(u64, u64, BTreeMap<RequestKey, LedgerRecord>), ServiceError> {
    if bytes.len() < 4 {
        return Err(ServiceError::CorruptState);
    }
    if &bytes[..4] == LEGACY_LEDGER_PLAINTEXT_MAGIC {
        return Ok((0, 0, decode_ledger(bytes)?));
    }
    if &bytes[..4] != LEDGER_PLAINTEXT_MAGIC {
        return Err(ServiceError::CorruptState);
    }
    let mut cursor = Cursor::new(&bytes[4..]);
    let replay_epoch = cursor.read_u64()?;
    let retired_through_generation = cursor.read_u64()?;
    if replay_epoch == 0 && retired_through_generation != 0 {
        return Err(ServiceError::CorruptState);
    }
    if replay_epoch > 0 && retired_through_generation == 0 {
        return Err(ServiceError::CorruptState);
    }
    let ledger = decode_ledger_records(&mut cursor)?;
    cursor.finish()?;
    Ok((replay_epoch, retired_through_generation, ledger))
}

fn decode_ledger_records(
    cursor: &mut Cursor<'_>,
) -> Result<BTreeMap<RequestKey, LedgerRecord>, ServiceError> {
    let count = usize::try_from(cursor.read_u32()?).map_err(|_| ServiceError::CorruptState)?;
    if count > MAX_RECORDS {
        return Err(ServiceError::CorruptState);
    }
    let mut ledger = BTreeMap::new();
    for _ in 0..count {
        let key = decode_request_key(cursor)?;
        let binding_digest = cursor.read_array_32()?;
        let recovery_reference = cursor.read_string(128)?;
        let generation = cursor.read_u64()?;
        let record = LedgerRecord {
            binding_digest,
            recovery_reference,
            generation,
        };
        if ledger.insert(key, record).is_some() {
            return Err(ServiceError::CorruptState);
        }
    }
    Ok(ledger)
}
'''
s = s[:start] + codec + s[end:]

# Public/raw request IDs remain unchanged for epoch zero. Later epochs are
# durably namespaced without widening the persisted marker format.
insert_at = s.index('\nfn validate_identifier(')
helper = r'''
fn scope_request_id(replay_epoch: u64, request_id: &str) -> Result<String, ServiceError> {
    validate_identifier(request_id)?;
    if replay_epoch == 0 {
        return Ok(request_id.to_owned());
    }
    let scoped = format!("epoch{replay_epoch}:{request_id}");
    validate_identifier(&scoped)?;
    Ok(scoped)
}
'''
s = s[:insert_at] + helper + s[insert_at:]

LIB.write_text(s)

c = CAP.read_text()
c = replace_once(c,
'''struct AtomicBatchRequest {
    principal: String,
''',
'''struct AtomicBatchRequest {
    replay_epoch: u64,
    principal: String,
''', 'batch epoch field')

c = replace_once(c,
'''    pub fn apply_batch(
        &mut self,
        principal: impl Into<String>,
        namespace: impl Into<String>,
        request_id: impl Into<String>,
        authorization_digest: [u8; 32],
        mutations: Vec<(String, Option<Secret>)>,
    ) -> Result<MutationOutcome, ServiceError> {
        self.apply_batch_with_policy(
            AtomicBatchRequest {
                principal: principal.into(),
''',
'''    pub fn apply_batch(
        &mut self,
        principal: impl Into<String>,
        namespace: impl Into<String>,
        request_id: impl Into<String>,
        authorization_digest: [u8; 32],
        mutations: Vec<(String, Option<Secret>)>,
    ) -> Result<MutationOutcome, ServiceError> {
        self.apply_batch_in_replay_epoch(
            0,
            principal,
            namespace,
            request_id,
            authorization_digest,
            mutations,
        )
    }

    pub fn apply_batch_in_replay_epoch(
        &mut self,
        replay_epoch: u64,
        principal: impl Into<String>,
        namespace: impl Into<String>,
        request_id: impl Into<String>,
        authorization_digest: [u8; 32],
        mutations: Vec<(String, Option<Secret>)>,
    ) -> Result<MutationOutcome, ServiceError> {
        self.apply_batch_with_policy(
            AtomicBatchRequest {
                replay_epoch,
                principal: principal.into(),
''', 'batch epoch entrypoint')

# Existing compaction API remains epoch-zero compatible; new callers can use the
# explicit epoch form once a retirement has occurred.
c = replace_once(c,
'''    pub fn apply_batch_with_compaction(
        &mut self,
        principal: impl Into<String>,
        namespace: impl Into<String>,
        request_id: impl Into<String>,
        authorization_digest: [u8; 32],
        mutations: Vec<(String, Option<Secret>)>,
    ) -> Result<MutationOutcome, ServiceError> {
        self.apply_batch_with_policy(
            AtomicBatchRequest {
                principal: principal.into(),
''',
'''    pub fn apply_batch_with_compaction(
        &mut self,
        principal: impl Into<String>,
        namespace: impl Into<String>,
        request_id: impl Into<String>,
        authorization_digest: [u8; 32],
        mutations: Vec<(String, Option<Secret>)>,
    ) -> Result<MutationOutcome, ServiceError> {
        self.apply_batch_with_compaction_in_replay_epoch(
            0,
            principal,
            namespace,
            request_id,
            authorization_digest,
            mutations,
        )
    }

    pub fn apply_batch_with_compaction_in_replay_epoch(
        &mut self,
        replay_epoch: u64,
        principal: impl Into<String>,
        namespace: impl Into<String>,
        request_id: impl Into<String>,
        authorization_digest: [u8; 32],
        mutations: Vec<(String, Option<Secret>)>,
    ) -> Result<MutationOutcome, ServiceError> {
        self.apply_batch_with_policy(
            AtomicBatchRequest {
                replay_epoch,
                principal: principal.into(),
''', 'batch compact epoch entrypoint')

# Test-only batch failpoint is legacy epoch zero.
c = c.replace(
'''            AtomicBatchRequest {
                principal,
                namespace,
                request_id,
''',
'''            AtomicBatchRequest {
                replay_epoch: 0,
                principal,
                namespace,
                request_id,
''', 1)

c = replace_once(c,
'''        validate_identifier(&request.principal)?;
        validate_namespace(&request.namespace)?;
        validate_identifier(&request.request_id)?;
''',
'''        validate_identifier(&request.principal)?;
        validate_namespace(&request.namespace)?;
        validate_identifier(&request.request_id)?;
        if request.replay_epoch != self.replay_epoch {
            return Err(ServiceError::ReplayEpochMismatch);
        }
''', 'batch epoch validation')

c = replace_once(c,
'''            request_id: request.request_id.clone(),
        };
''',
'''            request_id: scope_request_id(request.replay_epoch, &request.request_id)?,
        };
''', 'batch scoped key')

c = replace_once(c,
'''        let ledger_bytes = sealed_ledger(&self.barrier, generation, &candidate_ledger)?;
''',
'''        let ledger_bytes = sealed_ledger(
            &self.barrier,
            generation,
            self.replay_epoch,
            self.retired_through_generation,
            &candidate_ledger,
        )?;
''', 'batch ledger state')

# Add focused retirement regressions before the test module closes.
needle = '\n}\n'
# Find final module close, not an earlier function close.
pos = c.rfind(needle)
if pos < 0:
    raise SystemExit('capacity test module close not found')
tests = r'''

    #[test]
    fn replay_retirement_rejects_old_epoch_and_survives_restart() -> Result<(), ServiceError> {
        let _serial = serial_test();
        let root = TestRoot::new("replay-retirement-restart")?;
        let mut service = DurableService::create_new(&root.0, TestBarrier::new(), 2)?;
        service.put_in_replay_epoch(0, put_request("old-a", b"a")?)?;
        service.put_in_replay_epoch(0, put_request("old-b", b"b")?)?;
        assert_eq!(service.retained_request_count(), 2);
        let retired = service.retire_replay_epoch()?;
        assert_eq!(retired.previous_epoch, 0);
        assert_eq!(retired.current_epoch, 1);
        assert_eq!(retired.retired_through_generation, 2);
        assert_eq!(retired.retired_requests, 2);
        assert_eq!(service.retained_request_count(), 0);
        assert!(matches!(
            service.put_in_replay_epoch(0, put_request("old-a", b"a")?),
            Err(ServiceError::ReplayEpochMismatch)
        ));
        let committed = service.put_in_replay_epoch(1, put_request("new-a", b"c")?)?;
        assert!(matches!(committed, MutationOutcome::Committed { generation: 3, .. }));
        drop(service);

        let mut service = DurableService::reopen(&root.0, TestBarrier::new(), 2)?;
        assert_eq!(service.replay_epoch(), 1);
        assert_eq!(service.retired_through_generation(), 2);
        assert_eq!(service.retained_request_count(), 1);
        assert!(matches!(
            service.put_in_replay_epoch(0, put_request("old-a", b"a")?),
            Err(ServiceError::ReplayEpochMismatch)
        ));
        assert!(matches!(
            service.put_in_replay_epoch(1, put_request("new-a", b"c")?)?,
            MutationOutcome::Duplicate { generation: 3, .. }
        ));
        Ok(())
    }

    #[test]
    fn hbc3_frontier_admits_generation_beyond_legacy_identity_ceiling() -> Result<(), ServiceError> {
        let mut ledger = BTreeMap::new();
        let retired_through_generation = 32_000_u64;
        for offset in 1..=64_u64 {
            let generation = retired_through_generation + offset;
            ledger.insert(
                RequestKey {
                    principal: "principal-a".to_owned(),
                    namespace: "tenant-a".to_owned(),
                    request_id: format!("epoch7:request-{offset}"),
                },
                LedgerRecord {
                    binding_digest: digest32(
                        b"heptabao.test.replay-retirement.binding",
                        &generation.to_le_bytes(),
                    ),
                    recovery_reference: format!("{generation:032x}"),
                    generation,
                },
            );
        }
        validate_ledger_generation(
            &ledger,
            retired_through_generation + 64,
            retired_through_generation,
        )?;
        let encoded = encode_ledger_state(7, retired_through_generation, &ledger)?;
        let (epoch, frontier, decoded) = decode_ledger_state(&encoded)?;
        assert_eq!(epoch, 7);
        assert_eq!(frontier, 32_000);
        assert_eq!(decoded, ledger);
        assert_eq!(decoded.len(), 64);
        Ok(())
    }
'''
c = c[:pos] + tests + c[pos:]
CAP.write_text(c)
