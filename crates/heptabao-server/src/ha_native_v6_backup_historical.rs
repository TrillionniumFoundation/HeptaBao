//! Authenticated historical provenance as DATA, never a decoded Raft handle.
//! The same barrier transcript and complete dual-pack validation used by exact
//! repair remain mandatory. Current facts are taken only from a real selection.
use super::*;

/// No Clone/Serde/constructor outside this validator. Still no restore rights:
/// the Service must authenticate the local pack and its complete typed graph,
/// enforce live protected floors, retain original Actor and publish through
/// actual next-epoch consensus. This holds no enrollment/root/read capability.
pub(crate) struct HistoricalNativeV6ArchiveFacts {
    intent: NativeV6CommitIntent,
    migration_digest: [u8; 32],
    migration_log: [u64; 3],
    publication_log: [u64; 3],
    intent_log: [u64; 3],
    enrollment_digest: [u8; 32],
}
impl HistoricalNativeV6ArchiveFacts {
    pub(crate) fn cluster_digest(&self) -> [u8; 32] { self.intent.cluster_digest }
    pub(crate) fn replay_epoch(&self) -> u64 { self.intent.epoch }
    pub(crate) fn root_digest(&self) -> [u8; 32] { self.intent.proposed_root_digest }
    pub(crate) fn raft_generation(&self) -> u64 { self.intent.proposed_generation }
    pub(crate) fn migration_digest(&self) -> [u8; 32] { self.migration_digest }
    pub(crate) fn migration_log(&self) -> [u64; 3] { self.migration_log }
    pub(crate) fn publication_log(&self) -> [u64; 3] { self.publication_log }
    pub(crate) fn intent_log(&self) -> [u64; 3] { self.intent_log }
    pub(crate) fn enrollment_digest(&self) -> [u8; 32] { self.enrollment_digest }
}

struct Decoder<'a> { bytes: &'a [u8], at: usize }
impl Decoder<'_> {
    fn bytes(&mut self, len: usize) -> ArchiveResult<&[u8]> {
        let end = self.at.checked_add(len).ok_or(NativeV6ArchiveError::Invalid)?;
        let bytes = self.bytes.get(self.at..end).ok_or(NativeV6ArchiveError::Invalid)?;
        self.at = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> ArchiveResult<[u8; N]> {
        self.bytes(N)?.try_into().map_err(|_| NativeV6ArchiveError::Invalid)
    }
    fn u64(&mut self) -> ArchiveResult<u64> { Ok(u64::from_be_bytes(self.array()?)) }
    fn u32(&mut self) -> ArchiveResult<u32> { Ok(u32::from_be_bytes(self.array()?)) }
    fn log(&mut self) -> ArchiveResult<[u64; 3]> {
        let log = [self.u64()?, self.u64()?, self.u64()?];
        if log.contains(&0) { return Err(NativeV6ArchiveError::Invalid); }
        Ok(log)
    }
}
fn ordered(before: [u64; 3], after: [u64; 3]) -> bool {
    before[2] < after[2] && before[0] <= after[0]
        && (before[0] != after[0] || before[1] == after[1])
}

fn decode_facts(
    bytes: &[u8], current: &NativeV6ArchiveSelection,
) -> ArchiveResult<HistoricalNativeV6ArchiveFacts> {
    if bytes.len() > MAX_PROVENANCE_BYTES { return Err(NativeV6ArchiveError::TooLarge); }
    let mut decoded = Decoder { bytes, at: 0 };
    if decoded.bytes(8)? != b"HBV6HAP1" { return Err(NativeV6ArchiveError::Invalid); }
    let cluster: [u8; 32] = decoded.array()?;
    let epoch = decoded.u64()?;
    let enrollment_digest = decoded.array()?;
    let membership = decoded.log()?;
    let enrollment = decoded.log()?;
    let intent_log = decoded.log()?;
    let publication_log = decoded.log()?;
    let migration_log = decoded.log()?;
    let migration_digest = decoded.array()?;
    let count = decoded.u64()?;
    if !(3..=256).contains(&count) { return Err(NativeV6ArchiveError::Invalid); }
    let pins_start = decoded.at;
    let mut previous = 0;
    for _ in 0..count {
        let id = decoded.u64()?;
        let pin: [u8; 32] = decoded.array()?;
        if id <= previous || pin == [0; 32] { return Err(NativeV6ArchiveError::Invalid); }
        previous = id;
    }
    let pins_end = decoded.at;
    let length = decoded.u32()? as usize;
    if length != 213 { return Err(NativeV6ArchiveError::Invalid); }
    let intent = NativeV6CommitIntent::decode(decoded.bytes(length)?)
        .map_err(|_| NativeV6ArchiveError::Invalid)?;
    let length = decoded.u32()? as usize;
    if !(25..=crate::state_record_root::MAX_ROOT_BYTES + 256).contains(&length) {
        return Err(NativeV6ArchiveError::Invalid);
    }
    let _sealed_root_data = decoded.bytes(length)?;
    if decoded.at != bytes.len() || cluster != intent.cluster_digest || epoch != intent.epoch
        || enrollment_digest == [0; 32] || migration_digest == [0; 32]
        || !ordered(membership, enrollment) || !ordered(enrollment, intent_log)
        || !ordered(intent_log, publication_log) || !ordered(migration_log, intent_log)
        || intent.expected_previous_commit_index >= intent_log[2]
    {
        return Err(NativeV6ArchiveError::Invalid);
    }
    // Parse the independently actual selection only for comparison, never to
    // construct opaque runtime values from the historical archive's bytes.
    let actual = &current.provenance;
    let mut current_decoder = Decoder { bytes: actual, at: 8 };
    let actual_cluster: [u8; 32] = current_decoder.array()?;
    let actual_epoch = current_decoder.u64()?;
    let _actual_enrollment_digest: [u8; 32] = current_decoder.array()?;
    let actual_membership = current_decoder.log()?;
    let _ = current_decoder.log()?;
    let _ = current_decoder.log()?;
    let actual_publication = current_decoder.log()?;
    let actual_migration = current_decoder.log()?;
    let actual_migration_digest: [u8; 32] = current_decoder.array()?;
    let actual_count = current_decoder.u64()?;
    let actual_pins = current_decoder.bytes(actual_count as usize * 40)?;
    if cluster != actual_cluster || epoch > actual_epoch
        || epoch < current.published.native_origin_epoch()
        || membership != actual_membership || count != actual_count
        || bytes[pins_start..pins_end] != *actual_pins
        || migration_log != actual_migration || migration_digest != actual_migration_digest
        || intent.proposed_generation > current.published.generation()
        || publication_log[2] > actual_publication[2]
        || publication_log[0] > actual_publication[0]
        || (publication_log[0] == actual_publication[0] && publication_log[1] != actual_publication[1])
    {
        return Err(NativeV6ArchiveError::WrongSelection);
    }
    // Equality of Raft generation is exact equality of the entire published
    // selection. A historical archive may never relabel the current root.
    if intent.proposed_generation == current.published.generation()
        && bytes != current.provenance
    {
        return Err(NativeV6ArchiveError::WrongSelection);
    }
    Ok(HistoricalNativeV6ArchiveFacts { intent, migration_digest, migration_log,
        publication_log, intent_log, enrollment_digest })
}

pub(crate) fn validate_historical_native_v6_archive<R: Read + Seek>(
    reader: R,
    current: &NativeV6ArchiveSelection,
    expected_seal_identity: [u8; 32],
    barrier: &AeadBarrier,
    deadline: OriginalDeadline,
    gate: &mut impl FnMut() -> ArchiveResult<()>,
) -> ArchiveResult<(VerifiedNativeV6Archive<R>, HistoricalNativeV6ArchiveFacts)> {
    let mut selected = None;
    let archive = validate_archive_inner(reader, expected_seal_identity, barrier, deadline, gate,
        |bytes| {
            let facts = decode_facts(bytes, current)?;
            let intent = facts.intent;
            selected = Some(facts);
            Ok(intent)
        })?;
    // `selected` cannot escape any failed transcript, checksum, framing, count,
    // EOF or original-owner gate. It describes authenticated data only.
    Ok((archive, selected.ok_or(NativeV6ArchiveError::Invalid)?))
}
