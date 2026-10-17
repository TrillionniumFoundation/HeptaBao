//! Private bounded wire codec. Parsed fields are untrusted; only the parent
//! module's real Raft and pinned-mTLS paths may turn a final reply into custody.
use super::*;
use heptabao_raft_runtime::{NativeV6ClosureAdmission, NativeV6CommitIntent, RecordObjectKind};
use ring::digest::{Context, SHA256};
use ring::rand::{SecureRandom, SystemRandom};

const REQUEST_MAGIC: &[u8; 5] = b"HBVC2";
const REPLY_MAGIC: &[u8; 5] = b"HBCA2";
const INTENT_BYTES: usize = 213;
pub(super) const HEADER_BYTES: usize = 5 + 1 + INTENT_BYTES + 32 + 3 * 24 + 8 + 8 + 8 + 32;
pub(super) const MAX_OBJECTS: usize = 131_072;
pub(super) const PAGE_OBJECTS: usize = 4_096;
pub(super) const MAX_CIPHERTEXT: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
    Manifest = 1,
    Stage = 2,
    FsyncExisting = 3,
    Finalize = 4,
    StageBatch = 5,
    FsyncExistingBatch = 6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Binding {
    pub(super) intent: NativeV6CommitIntent,
    pub(super) enrollment_digest: [u8; 32],
    pub(super) membership_log: [u64; 3],
    pub(super) enrollment_log: [u64; 3],
    pub(super) intent_log: [u64; 3],
    pub(super) leader: u64,
    pub(super) term: u64,
}

impl Binding {
    pub(super) fn observed(admission: &NativeV6ClosureAdmission) -> Self {
        let enrollment = admission.enrollment();
        let membership = enrollment.membership_log_id();
        let enrolled = enrollment.enrollment_log_id();
        let intent_log = admission.intent_log_id();
        Self {
            intent: *admission.intent(),
            enrollment_digest: enrollment.digest(),
            membership_log: [
                membership.committed_leader_id().term,
                membership.committed_leader_id().node_id,
                membership.index,
            ],
            enrollment_log: [
                enrolled.committed_leader_id().term,
                enrolled.committed_leader_id().node_id,
                enrolled.index,
            ],
            intent_log: [
                intent_log.committed_leader_id().term,
                intent_log.committed_leader_id().node_id,
                intent_log.index,
            ],
            leader: admission.leader_id(),
            term: admission.term(),
        }
    }
}

pub(super) struct Request<'a> {
    pub(super) kind: Kind,
    pub(super) binding: Binding,
    pub(super) target: u64,
    pub(super) payload: &'a [u8],
    bytes: &'a [u8],
}

fn take<const N: usize>(bytes: &[u8], at: &mut usize) -> Result<[u8; N], HaError> {
    let end = at.checked_add(N).ok_or(HaError::InvalidFrame)?;
    let value = bytes
        .get(*at..end)
        .ok_or(HaError::InvalidFrame)?
        .try_into()
        .map_err(|_| HaError::InvalidFrame)?;
    *at = end;
    Ok(value)
}

pub(super) fn encode(
    binding: &Binding,
    target: u64,
    kind: Kind,
    payload: &[u8],
) -> Result<Vec<u8>, HaError> {
    if target == 0
        || binding.leader == 0
        || binding.term == 0
        || HEADER_BYTES
            .checked_add(payload.len())
            .is_none_or(|len| len > batch::MAX_PAYLOAD + HEADER_BYTES)
    {
        return Err(HaError::InvalidFrame);
    }
    let intent = binding.intent.encode().map_err(|_| HaError::InvalidFrame)?;
    if intent.len() != INTENT_BYTES {
        return Err(HaError::InvalidFrame);
    }
    let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len());
    bytes.extend_from_slice(REQUEST_MAGIC);
    bytes.push(kind as u8);
    bytes.extend_from_slice(&intent);
    bytes.extend_from_slice(&binding.enrollment_digest);
    for log in [
        binding.membership_log,
        binding.enrollment_log,
        binding.intent_log,
    ] {
        for number in log {
            bytes.extend_from_slice(&number.to_be_bytes());
        }
    }
    bytes.extend_from_slice(&binding.leader.to_be_bytes());
    bytes.extend_from_slice(&binding.term.to_be_bytes());
    bytes.extend_from_slice(&target.to_be_bytes());
    let mut nonce = [0u8; 32];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| HaError::Transport)?;
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

pub(super) fn parse(bytes: &[u8]) -> Result<Request<'_>, HaError> {
    if bytes.len() < HEADER_BYTES || bytes.len() > batch::MAX_PAYLOAD + HEADER_BYTES {
        return Err(HaError::InvalidFrame);
    }
    let mut at = 0;
    if &take::<5>(bytes, &mut at)? != REQUEST_MAGIC {
        return Err(HaError::InvalidFrame);
    }
    let kind = match take::<1>(bytes, &mut at)?[0] {
        1 => Kind::Manifest,
        2 => Kind::Stage,
        3 => Kind::FsyncExisting,
        4 => Kind::Finalize,
        5 => Kind::StageBatch,
        6 => Kind::FsyncExistingBatch,
        _ => return Err(HaError::InvalidFrame),
    };
    let intent = NativeV6CommitIntent::decode(&take::<INTENT_BYTES>(bytes, &mut at)?)
        .map_err(|_| HaError::InvalidFrame)?;
    let enrollment_digest = take::<32>(bytes, &mut at)?;
    let mut logs = [[0u64; 3]; 3];
    for log in &mut logs {
        for number in log {
            *number = u64::from_be_bytes(take::<8>(bytes, &mut at)?);
        }
    }
    let leader = u64::from_be_bytes(take::<8>(bytes, &mut at)?);
    let term = u64::from_be_bytes(take::<8>(bytes, &mut at)?);
    let target = u64::from_be_bytes(take::<8>(bytes, &mut at)?);
    let _nonce = take::<32>(bytes, &mut at)?;
    if at != HEADER_BYTES || leader == 0 || term == 0 || target == 0 || enrollment_digest == [0; 32]
    {
        return Err(HaError::InvalidFrame);
    }
    Ok(Request {
        kind,
        binding: Binding {
            intent,
            enrollment_digest,
            membership_log: logs[0],
            enrollment_log: logs[1],
            intent_log: logs[2],
            leader,
            term,
        },
        target,
        payload: &bytes[at..],
        bytes,
    })
}

pub(super) fn reply(request: &Request<'_>, payload: &[u8]) -> Result<Vec<u8>, HaError> {
    if payload.len() > batch::MAX_ACK {
        return Err(HaError::InvalidFrame);
    }
    let mut bytes = request.bytes[..HEADER_BYTES].to_vec();
    bytes[..5].copy_from_slice(REPLY_MAGIC);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

pub(super) fn verify_reply(
    request: &[u8],
    received: &[u8],
    expected_payload: &[u8],
) -> Result<(), HaError> {
    if request.len() < HEADER_BYTES
        || received.len() != HEADER_BYTES + expected_payload.len()
        || received.get(..5) != Some(REPLY_MAGIC.as_slice())
        || received.get(5..HEADER_BYTES) != request.get(5..HEADER_BYTES)
        || received.get(HEADER_BYTES..) != Some(expected_payload)
    {
        return Err(HaError::OutcomeUnknown);
    }
    Ok(())
}

pub(super) fn reference_payload(reference: &RecordObjectRef) -> Result<Vec<u8>, HaError> {
    validate_reference(reference)?;
    let mut bytes = Vec::with_capacity(36);
    bytes.extend_from_slice(&reference.id);
    bytes.extend_from_slice(&reference.encoded_bytes.to_be_bytes());
    Ok(bytes)
}

pub(super) fn parse_reference(bytes: &[u8]) -> Result<RecordObjectRef, HaError> {
    if bytes.len() != 36 {
        return Err(HaError::InvalidFrame);
    }
    let length = u32::from_be_bytes(
        bytes[32..36]
            .try_into()
            .map_err(|_| HaError::InvalidFrame)?,
    );
    let reference = RecordObjectRef {
        id: bytes[..32].try_into().map_err(|_| HaError::InvalidFrame)?,
        kind: RecordObjectKind::NativeV6CiphertextChunk,
        encoded_bytes: length,
        record_count: 0,
        payload_bytes: u64::from(length),
    };
    validate_reference(&reference)?;
    Ok(reference)
}

pub(super) fn validate_reference(reference: &RecordObjectRef) -> Result<(), HaError> {
    if reference.id == [0; 32]
        || reference.kind != RecordObjectKind::NativeV6CiphertextChunk
        || reference.record_count != 0
        || reference.payload_bytes != u64::from(reference.encoded_bytes)
        || !(25..=MAX_CIPHERTEXT as u32).contains(&reference.encoded_bytes)
    {
        return Err(HaError::InvalidFrame);
    }
    Ok(())
}

pub(super) fn manifest_page(
    offset: usize,
    references: &[RecordObjectRef],
) -> Result<Vec<u8>, HaError> {
    if references.is_empty() || references.len() > PAGE_OBJECTS || offset > MAX_OBJECTS {
        return Err(HaError::InvalidFrame);
    }
    let mut bytes = Vec::with_capacity(8 + references.len() * 40);
    bytes.extend_from_slice(&(offset as u32).to_be_bytes());
    bytes.extend_from_slice(&(references.len() as u32).to_be_bytes());
    for reference in references {
        validate_reference(reference)?;
        bytes.extend_from_slice(&reference.id);
        bytes.extend_from_slice(&reference.payload_bytes.to_be_bytes());
    }
    Ok(bytes)
}

pub(super) fn parse_manifest_page(bytes: &[u8]) -> Result<(usize, Vec<RecordObjectRef>), HaError> {
    if bytes.len() < 8 {
        return Err(HaError::InvalidFrame);
    }
    let offset =
        u32::from_be_bytes(bytes[..4].try_into().map_err(|_| HaError::InvalidFrame)?) as usize;
    let count =
        u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| HaError::InvalidFrame)?) as usize;
    if count == 0
        || count > PAGE_OBJECTS
        || bytes.len() != 8 + count * 40
        || offset
            .checked_add(count)
            .is_none_or(|end| end > MAX_OBJECTS)
    {
        return Err(HaError::InvalidFrame);
    }
    let mut references = Vec::with_capacity(count);
    for entry in bytes[8..].chunks_exact(40) {
        let length = u64::from_be_bytes(
            entry[32..40]
                .try_into()
                .map_err(|_| HaError::InvalidFrame)?,
        );
        let reference = RecordObjectRef {
            id: entry[..32].try_into().map_err(|_| HaError::InvalidFrame)?,
            kind: RecordObjectKind::NativeV6CiphertextChunk,
            encoded_bytes: u32::try_from(length).map_err(|_| HaError::InvalidFrame)?,
            record_count: 0,
            payload_bytes: length,
        };
        validate_reference(&reference)?;
        if references
            .last()
            .is_some_and(|last: &RecordObjectRef| last.id >= reference.id)
        {
            return Err(HaError::InvalidFrame);
        }
        references.push(reference);
    }
    Ok((offset, references))
}

pub(super) fn exact_manifest(
    references: &[RecordObjectRef],
    intent: &NativeV6CommitIntent,
) -> Result<(), HaError> {
    if references.is_empty()
        || references.len() > MAX_OBJECTS
        || references.len() as u64 != intent.object_count
    {
        return Err(HaError::InvalidFrame);
    }
    let mut hash = Context::new(&SHA256);
    hash.update(b"heptabao.v6.local-ciphertext-closure.v1\0");
    hash.update(&(references.len() as u64).to_be_bytes());
    let mut previous = None;
    let mut total = 0u64;
    for reference in references {
        validate_reference(reference)?;
        if previous.is_some_and(|id| id >= reference.id) {
            return Err(HaError::InvalidFrame);
        }
        previous = Some(reference.id);
        total = total
            .checked_add(reference.payload_bytes)
            .ok_or(HaError::InvalidFrame)?;
        hash.update(&reference.id);
        hash.update(&reference.payload_bytes.to_be_bytes());
    }
    if hash.finish().as_ref() != intent.closure_manifest_sha256.as_slice()
        || total != intent.ciphertext_bytes
    {
        return Err(HaError::InvalidFrame);
    }
    Ok(())
}

pub(super) fn final_payload(intent: &NativeV6CommitIntent) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(48);
    bytes.extend_from_slice(&intent.closure_manifest_sha256);
    bytes.extend_from_slice(&intent.object_count.to_be_bytes());
    bytes.extend_from_slice(&intent.ciphertext_bytes.to_be_bytes());
    bytes
}
