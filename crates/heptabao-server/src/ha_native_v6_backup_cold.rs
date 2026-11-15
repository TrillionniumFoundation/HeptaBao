//! Authentication of a complete old HA archive without a surviving cohort.
//!
//! The old Shamir barrier and matching seal identity authenticate DATA only.
//! Old membership, enrollment, LogIds and generations never become current
//! Raft capabilities. A recovery coordinator must independently validate the
//! complete local typed graph and publish it through the new actual quorum.
use super::*;

/// Authenticated source facts, with no constructor, Clone, Serde or conversion
/// to an enrollment, published root, Actor, witness or restore authorization.
pub(crate) struct ColdNativeV6ArchiveFacts {
    intent: NativeV6CommitIntent,
    migration_digest: [u8; 32],
    migration_log: [u64; 3],
    publication_log: [u64; 3],
    intent_log: [u64; 3],
    enrollment_digest: [u8; 32],
}

impl ColdNativeV6ArchiveFacts {
    // Exact public cluster-domain transcript used by
    // ClusterStateCodec::native_v6_cluster_digest. This computes data binding
    // only; it does not construct a codec with an invented replication key.
    pub(crate) fn matches_cluster_id(&self, cluster_id: &str) -> bool {
        let Ok(length) = u32::try_from(cluster_id.len()) else {
            return false;
        };
        if cluster_id.is_empty() {
            return false;
        }
        let mut hash = Sha256::new();
        hash.update(b"heptabao.native-v6.replication.cluster.v1\0");
        hash.update(length.to_be_bytes());
        hash.update(cluster_id.as_bytes());
        let digest: [u8; 32] = hash.finalize().into();
        digest == self.cluster_digest()
    }
    pub(crate) fn cluster_digest(&self) -> [u8; 32] {
        self.intent.cluster_digest
    }
    pub(crate) fn replay_epoch(&self) -> u64 {
        self.intent.epoch
    }
    pub(crate) fn root_digest(&self) -> [u8; 32] {
        self.intent.proposed_root_digest
    }
    pub(crate) fn raft_generation(&self) -> u64 {
        self.intent.proposed_generation
    }
    pub(crate) fn migration_digest(&self) -> [u8; 32] {
        self.migration_digest
    }
    pub(crate) fn migration_log(&self) -> [u64; 3] {
        self.migration_log
    }
    pub(crate) fn publication_log(&self) -> [u64; 3] {
        self.publication_log
    }
    pub(crate) fn intent_log(&self) -> [u64; 3] {
        self.intent_log
    }
    pub(crate) fn enrollment_digest(&self) -> [u8; 32] {
        self.enrollment_digest
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Decoder<'_> {
    fn bytes(&mut self, len: usize) -> ArchiveResult<&[u8]> {
        let end = self
            .at
            .checked_add(len)
            .ok_or(NativeV6ArchiveError::Invalid)?;
        let bytes = self
            .bytes
            .get(self.at..end)
            .ok_or(NativeV6ArchiveError::Invalid)?;
        self.at = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> ArchiveResult<[u8; N]> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| NativeV6ArchiveError::Invalid)
    }
    fn u64(&mut self) -> ArchiveResult<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> ArchiveResult<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn log(&mut self) -> ArchiveResult<[u64; 3]> {
        let log = [self.u64()?, self.u64()?, self.u64()?];
        if log.contains(&0) {
            return Err(NativeV6ArchiveError::Invalid);
        }
        Ok(log)
    }
}

fn ordered(before: [u64; 3], after: [u64; 3]) -> bool {
    before[2] < after[2]
        && before[0] <= after[0]
        && (before[0] != after[0] || before[1] == after[1])
}

// Preserve every intrinsic HBV6HAP1 check from the historical validator. Cold
// recovery has no actual old selection to compare with; it must not invent one.
// These facts remain private until validate_archive_inner authenticates the
// complete dual pack, all hashes, the original barrier footer and exact EOF.
fn decode_facts(bytes: &[u8]) -> ArchiveResult<ColdNativeV6ArchiveFacts> {
    if bytes.len() > MAX_PROVENANCE_BYTES {
        return Err(NativeV6ArchiveError::TooLarge);
    }
    let mut decoded = Decoder { bytes, at: 0 };
    if decoded.bytes(8)? != b"HBV6HAP1" {
        return Err(NativeV6ArchiveError::Invalid);
    }
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
    if !(3..=256).contains(&count) {
        return Err(NativeV6ArchiveError::Invalid);
    }
    let mut previous = 0;
    for _ in 0..count {
        let id = decoded.u64()?;
        let pin: [u8; 32] = decoded.array()?;
        if id <= previous || pin == [0; 32] {
            return Err(NativeV6ArchiveError::Invalid);
        }
        previous = id;
    }
    let length = decoded.u32()? as usize;
    if length != 213 {
        return Err(NativeV6ArchiveError::Invalid);
    }
    let intent = NativeV6CommitIntent::decode(decoded.bytes(length)?)
        .map_err(|_| NativeV6ArchiveError::Invalid)?;
    let length = decoded.u32()? as usize;
    if !(25..=crate::state_record_root::MAX_ROOT_BYTES + 256).contains(&length) {
        return Err(NativeV6ArchiveError::Invalid);
    }
    let _sealed_root_data = decoded.bytes(length)?;
    if decoded.at != bytes.len()
        || cluster != intent.cluster_digest
        || epoch != intent.epoch
        || enrollment_digest == [0; 32]
        || migration_digest == [0; 32]
        || !ordered(membership, enrollment)
        || !ordered(enrollment, intent_log)
        || !ordered(intent_log, publication_log)
        || !ordered(migration_log, intent_log)
        || intent.expected_previous_commit_index >= intent_log[2]
    {
        return Err(NativeV6ArchiveError::Invalid);
    }
    Ok(ColdNativeV6ArchiveFacts {
        intent,
        migration_digest,
        migration_log,
        publication_log,
        intent_log,
        enrollment_digest,
    })
}

/// Read-only old-data authentication. No old shared replication key or live
/// donor is needed: the local pack remains under the supplied old barrier.
/// This does not decrypt or install that pack, authorize a restore, re-enroll a
/// peer, replace any destination root, or change the ordinary restore guards.
pub(crate) fn validate_cold_native_v6_archive<R: Read + Seek>(
    reader: R,
    expected_seal_identity: [u8; 32],
    old_barrier: &AeadBarrier,
    deadline: OriginalDeadline,
    gate: &mut impl FnMut() -> ArchiveResult<()>,
) -> ArchiveResult<(VerifiedNativeV6Archive<R>, ColdNativeV6ArchiveFacts)> {
    let mut selected = None;
    let archive = validate_archive_inner(
        reader,
        expected_seal_identity,
        old_barrier,
        deadline,
        gate,
        |bytes| {
            let facts = decode_facts(bytes)?;
            let intent = facts.intent;
            selected = Some(facts);
            Ok(intent)
        },
    )?;
    Ok((archive, selected.ok_or(NativeV6ArchiveError::Invalid)?))
}
