//! Private repair wire. Neither request fields nor a decoded reply construct
//! read, fsync-quorum, Actor, or installation authority.
use super::*;
use heptabao_raft_runtime::NativeV6CommitIntent;

const REQUEST_MAGIC: &[u8; 5] = b"HBVP2";
const REPLY_MAGIC: &[u8; 5] = b"HBVD2";
const INTENT_BYTES: usize = 213;
const HEADER_BYTES: usize = 5 + 1 + INTENT_BYTES + 32 + 4 * 24 + 4 * 8 + 2 * 32;
const MAX_REPLY_PAYLOAD: usize = super::super::wire::MAX_CIPHERTEXT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
    Manifest = 1,
    Object = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RootBinding {
    pub(super) intent: NativeV6CommitIntent,
    pub(super) enrollment: [u8; 32],
    logs: [[u64; 3]; 4],
    pub(super) leader: u64,
    pub(super) term: u64,
}

impl RootBinding {
    pub(super) fn observed(read: &NativeV6CommittedRootRead) -> Self {
        let enrollment = read.enrollment();
        let root = read.root();
        let logs = [
            enrollment.membership_log_id(),
            enrollment.enrollment_log_id(),
            root.intent_log_id(),
            root.publication_log_id(),
        ]
        .map(|log| {
            [
                log.committed_leader_id().term,
                log.committed_leader_id().node_id,
                log.index,
            ]
        });
        Self {
            intent: root.intent(),
            enrollment: enrollment.digest(),
            logs,
            leader: read.leader_id(),
            term: read.term(),
        }
    }
}

pub(super) struct Request<'a> {
    pub(super) binding: RootBinding,
    pub(super) requester: u64,
    pub(super) target: u64,
    pub(super) kind: Kind,
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
    binding: &RootBinding,
    requester: u64,
    target: u64,
    round: [u8; 32],
    kind: Kind,
    payload: &[u8],
) -> Result<Vec<u8>, HaError> {
    if requester == 0 || target == 0 || requester == target || payload.len() > 36 {
        return Err(HaError::InvalidFrame);
    }
    let encoded = binding.intent.encode().map_err(|_| HaError::InvalidFrame)?;
    if encoded.len() != INTENT_BYTES || round == [0; 32] {
        return Err(HaError::InvalidFrame);
    }
    let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len());
    bytes.extend_from_slice(REQUEST_MAGIC);
    bytes.push(kind as u8);
    bytes.extend_from_slice(&encoded);
    bytes.extend_from_slice(&binding.enrollment);
    for log in binding.logs {
        for value in log {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    }
    for value in [binding.leader, binding.term, requester, target] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&round);
    let mut nonce = [0u8; 32];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| HaError::Transport)?;
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

pub(super) fn parse(bytes: &[u8]) -> Result<Request<'_>, HaError> {
    if bytes.len() < HEADER_BYTES || bytes.len() > HEADER_BYTES + 36 {
        return Err(HaError::InvalidFrame);
    }
    let mut at = 0;
    if &take::<5>(bytes, &mut at)? != REQUEST_MAGIC {
        return Err(HaError::InvalidFrame);
    }
    let kind = match take::<1>(bytes, &mut at)?[0] {
        1 => Kind::Manifest,
        2 => Kind::Object,
        _ => return Err(HaError::InvalidFrame),
    };
    let intent = NativeV6CommitIntent::decode(&take::<INTENT_BYTES>(bytes, &mut at)?)
        .map_err(|_| HaError::InvalidFrame)?;
    let enrollment = take::<32>(bytes, &mut at)?;
    let mut logs = [[0u64; 3]; 4];
    for log in &mut logs {
        for value in log {
            *value = u64::from_be_bytes(take::<8>(bytes, &mut at)?);
        }
    }
    let leader = u64::from_be_bytes(take::<8>(bytes, &mut at)?);
    let term = u64::from_be_bytes(take::<8>(bytes, &mut at)?);
    let requester = u64::from_be_bytes(take::<8>(bytes, &mut at)?);
    let target = u64::from_be_bytes(take::<8>(bytes, &mut at)?);
    let round = take::<32>(bytes, &mut at)?;
    let nonce = take::<32>(bytes, &mut at)?;
    if at != HEADER_BYTES
        || leader == 0
        || term == 0
        || requester == 0
        || target == 0
        || requester == target
        || enrollment == [0; 32]
        || round == [0; 32]
        || nonce == [0; 32]
    {
        return Err(HaError::InvalidFrame);
    }
    Ok(Request {
        binding: RootBinding {
            intent,
            enrollment,
            logs,
            leader,
            term,
        },
        requester,
        target,
        kind,
        payload: &bytes[at..],
        bytes,
    })
}

pub(super) fn reply(request: &Request<'_>, payload: &[u8]) -> Result<Vec<u8>, HaError> {
    if payload.is_empty() || payload.len() > MAX_REPLY_PAYLOAD {
        return Err(HaError::InvalidFrame);
    }
    let mut bytes = request.bytes[..HEADER_BYTES].to_vec();
    bytes[..5].copy_from_slice(REPLY_MAGIC);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// Only the private actual pinned socket worker invokes this decoder.
pub(super) fn verified_payload(request: &[u8], mut reply: Vec<u8>) -> Result<Vec<u8>, HaError> {
    if request.len() < HEADER_BYTES
        || reply.len() <= HEADER_BYTES
        || reply.len() > HEADER_BYTES + MAX_REPLY_PAYLOAD
        || reply.get(..5) != Some(REPLY_MAGIC.as_slice())
        || reply.get(5..HEADER_BYTES) != request.get(5..HEADER_BYTES)
    {
        return Err(HaError::OutcomeUnknown);
    }
    drop(reply.drain(..HEADER_BYTES));
    Ok(reply)
}
