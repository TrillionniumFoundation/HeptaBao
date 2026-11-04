//! Closed, small terminal-clock exchange for one original snapshot operation.
//! Wire metadata is data only. The leader Service alone can mint the sealed
//! observation after its actual clock writer; the follower must still consume
//! this affine exchange and obtain a real local ReadIndex proof before delivery.
use super::*;
use heptabao_ha_service::{
    AuthenticatedPeerFrame, HaError, MAX_SNAPSHOT_CLOCK_FRAME_BYTES, SNAPSHOT_CLOCK_REQUEST_MAGIC,
    SNAPSHOT_CLOCK_RESPONSE_MAGIC,
};
use heptabao_raft_runtime::NativeV6PeerEnrollment;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

const REQUEST_HEADER_BYTES: usize = 13;
const MAX_TOKEN_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotClockLogId {
    pub(crate) term: u64,
    pub(crate) node_id: u64,
    pub(crate) index: u64,
}

/// Shared logical publication metadata, never a node-local durable generation
/// or an Actor/ReadIndex/clock capability. Only the Service proves its meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SharedSnapshotClockState {
    pub(crate) epoch: u64,
    pub(crate) enrollment_digest: [u8; 32],
    pub(crate) root_digest: [u8; 32],
    pub(crate) logical_generation: u64,
    pub(crate) publication_log: SnapshotClockLogId,
    pub(crate) auth_sha256: [u8; 32],
}

impl SharedSnapshotClockState {
    fn validate(&self) -> bool {
        self.enrollment_digest != [0; 32]
            && self.root_digest != [0; 32]
            && self.auth_sha256 != [0; 32]
            && self.publication_log.term > 0
            && self.publication_log.node_id > 0
            && self.publication_log.index > 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SnapshotClockOperation {
    Download,
    ValidateUpload,
    ValidateForceUpload,
}

impl SnapshotClockOperation {
    pub(crate) fn path(self) -> &'static str {
        match self {
            Self::Download | Self::ValidateUpload => "sys/storage/raft/snapshot",
            Self::ValidateForceUpload => "sys/storage/raft/snapshot-force",
        }
    }

    fn accepts(self, method: ClockMethod) -> bool {
        match self {
            Self::Download => matches!(method, ClockMethod::Get | ClockMethod::Head),
            Self::ValidateUpload | Self::ValidateForceUpload => {
                matches!(method, ClockMethod::Post | ClockMethod::Put)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum ClockMethod {
    Get,
    Head,
    Post,
    Put,
}

impl ClockMethod {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "GET" => Some(Self::Get),
            "HEAD" => Some(Self::Head),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }
}

/// References to the caller's already retained original request and actual
/// enrollment. Constructing this data does not grant any observation authority.
#[derive(Clone, Copy)]
pub(crate) struct SnapshotClockContext<'a> {
    pub(crate) operation: SnapshotClockOperation,
    pub(crate) method: &'a str,
    pub(crate) token: &'a str,
    pub(crate) origin_peer: Option<IpAddr>,
    pub(crate) ingress: [u8; 16],
    pub(crate) source: SharedSnapshotClockState,
    pub(crate) enrollment: &'a NativeV6PeerEnrollment,
    pub(crate) deadline: Instant,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestWire {
    cluster: String,
    source_node: u64,
    target_node: u64,
    leader_term: u64,
    nonce: [u8; 32],
    ingress: [u8; 16],
    operation: SnapshotClockOperation,
    method: ClockMethod,
    #[serde(with = "token_wire")]
    token: Zeroizing<String>,
    origin_peer: Option<IpAddr>,
    source: SharedSnapshotClockState,
}

// An arbitrary valid token must not expand six-fold through JSON escaping.
// Canonical base64 keeps the existing 16 KiB token limit inside this separate
// 32 KiB frame, and both encoded and decoded temporary owners erase on error.
mod token_wire {
    use super::*;

    pub(super) fn serialize<S: serde::Serializer>(
        token: &Zeroizing<String>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let encoded = Zeroizing::new(STANDARD.encode(token.as_bytes()));
        serializer.serialize_str(&encoded)
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<String>, D::Error> {
        use serde::de::Error as _;
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        if encoded.len() > MAX_TOKEN_BYTES.div_ceil(3) * 4 {
            return Err(D::Error::custom("snapshot clock token bound exceeded"));
        }
        let decoded = Zeroizing::new(
            STANDARD
                .decode(encoded.as_bytes())
                .map_err(|_| D::Error::custom("snapshot clock token encoding invalid"))?,
        );
        let canonical = Zeroizing::new(STANDARD.encode(decoded.as_slice()));
        if decoded.len() > MAX_TOKEN_BYTES || canonical.as_bytes() != encoded.as_bytes() {
            return Err(D::Error::custom(
                "snapshot clock token encoding is not canonical",
            ));
        }
        let token = std::str::from_utf8(&decoded)
            .map_err(|_| D::Error::custom("snapshot clock token text invalid"))?;
        Ok(Zeroizing::new(token.to_owned()))
    }
}

/// This type has no constructor, Clone or Deserialize outside this actual TLS
/// dispatcher. The Service independently authenticates the original token and
/// compares source A against its own real proof before observing its own clock.
pub(crate) struct AuthenticatedSnapshotClockRequest {
    wire: RequestWire,
    actual_peer_leaf: [u8; 32],
    cluster_digest: [u8; 32],
    deadline: Instant,
}

impl AuthenticatedSnapshotClockRequest {
    pub(crate) fn source(&self) -> &SharedSnapshotClockState {
        &self.wire.source
    }
    pub(crate) fn operation(&self) -> SnapshotClockOperation {
        self.wire.operation
    }
    pub(crate) fn method(&self) -> &'static str {
        self.wire.method.as_str()
    }
    pub(crate) fn path(&self) -> &'static str {
        self.wire.operation.path()
    }
    pub(crate) fn namespace(&self) -> &'static str {
        ""
    }
    pub(crate) fn token(&self) -> &str {
        &self.wire.token
    }
    pub(crate) fn origin_peer(&self) -> Option<IpAddr> {
        self.wire.origin_peer
    }
    pub(crate) fn ingress(&self) -> [u8; 16] {
        self.wire.ingress
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn leader_node(&self) -> u64 {
        self.wire.target_node
    }
    pub(crate) fn leader_term(&self) -> u64 {
        self.wire.leader_term
    }
    pub(crate) fn check_enrollment(&self, actual: &NativeV6PeerEnrollment) -> Result<(), Response> {
        if actual.digest() != self.wire.source.enrollment_digest
            || actual.epoch() != self.wire.source.epoch
            || actual.cluster_digest() != self.cluster_digest
            || actual.pins().get(&self.wire.source_node) != Some(&self.actual_peer_leaf)
            || !actual.pins().contains_key(&self.wire.target_node)
            || Instant::now() >= self.deadline
        {
            return Err(unavailable());
        }
        Ok(())
    }
}

pub(crate) type SnapshotClockHandler = Arc<
    dyn Fn(
            AuthenticatedSnapshotClockRequest,
        ) -> Result<crate::service::SnapshotClockObservation, Response>
        + Send
        + Sync,
>;

/// The decision attached to a sealed Service clock observation. This enum is
/// data only: constructing it cannot mint an observation or remote completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SnapshotClockDisposition {
    Allowed,
    Denied,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum OutcomeWire {
    Completed {
        source: SharedSnapshotClockState,
        successor: Box<Option<SharedSnapshotClockState>>,
    },
    Denied {
        source: SharedSnapshotClockState,
        successor: Box<Option<SharedSnapshotClockState>>,
        status: u16,
    },
    Rejected {
        status: u16,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseWire {
    cluster: String,
    source_node: u64,
    target_node: u64,
    leader_term: u64,
    nonce: [u8; 32],
    ingress: [u8; 16],
    request_sha256: [u8; 32],
    operation: SnapshotClockOperation,
    method: ClockMethod,
    outcome: OutcomeWire,
}

fn unavailable() -> Response {
    Response::error(503, "snapshot terminal observation is unavailable")
}

fn rejected(status: u16) -> Response {
    match status {
        400 => Response::error(400, "snapshot terminal observation request is invalid"),
        403 => Response::error(403, "permission denied"),
        409 => Response::error(409, "snapshot terminal observation source changed"),
        500 => Response::error(500, "snapshot terminal observation failed"),
        _ => unavailable(),
    }
}

fn error_status(status: u16) -> u16 {
    match status {
        400 | 403 | 409 | 500 | 503 => status,
        _ => 503,
    }
}

fn valid_successor(
    source: SharedSnapshotClockState,
    successor: Option<SharedSnapshotClockState>,
    leader: u64,
    term: u64,
) -> bool {
    successor.is_none_or(|next| {
        next.validate()
            && next.epoch == source.epoch
            && next.enrollment_digest == source.enrollment_digest
            && next.root_digest != source.root_digest
            && source.logical_generation.checked_add(1) == Some(next.logical_generation)
            && next.publication_log.term == term
            && next.publication_log.node_id == leader
            && next.publication_log.index > source.publication_log.index
    })
}

pub(super) struct ListenerContext<'a> {
    pub(super) cluster: &'a str,
    pub(super) cluster_digest: [u8; 32],
    pub(super) local: u64,
    pub(super) ids: &'a BTreeMap<NodeId, u64>,
    pub(super) native_candidate: bool,
    pub(super) node: &'a Arc<ProcessRaftNode>,
    pub(super) handler: &'a Arc<Mutex<Option<SnapshotClockHandler>>>,
    pub(super) slots: &'a Arc<Semaphore>,
}

fn check_leader(
    node: &ProcessRaftNode,
    leader: u64,
    term: u64,
    local: bool,
) -> Result<(), HaError> {
    let current = node
        .local_leader_observation()
        .map_err(|_| HaError::OutcomeUnknown)?;
    if current.term != term
        || term == 0
        || current.leader != Some(leader)
        || local && (!current.local_is_leader || current.local_id != leader)
    {
        return Err(HaError::NotLeader);
    }
    Ok(())
}

pub(super) fn handle_authenticated(
    authenticated: AuthenticatedPeerFrame,
    context: ListenerContext<'_>,
) -> Result<Vec<u8>, HaError> {
    let strict_raft_alpn = authenticated.has_strict_raft_alpn();
    let source_node = context.ids.get(authenticated.peer()).copied();
    let actual_peer_leaf = authenticated.actual_leaf_sha256();
    let deadline = authenticated.deadline();
    let (_, frame, _) = authenticated.into_legacy_parts();
    let frame = Zeroizing::new(frame);
    if !context.native_candidate || !strict_raft_alpn {
        return Err(HaError::PeerAuthenticationFailed);
    }
    let source_node = source_node.ok_or(HaError::UnknownPeer)?;
    if source_node == context.local
        || frame.len() <= REQUEST_HEADER_BYTES
        || frame.len() > MAX_SNAPSHOT_CLOCK_FRAME_BYTES
        || !frame.starts_with(SNAPSHOT_CLOCK_REQUEST_MAGIC)
        || Instant::now() >= deadline
    {
        return Err(HaError::InvalidFrame);
    }
    let wire: RequestWire = serde_json::from_slice(&frame[REQUEST_HEADER_BYTES..])
        .map_err(|_| HaError::InvalidFrame)?;
    if wire.cluster != context.cluster
        || wire.cluster.is_empty()
        || wire.cluster.len() > MAX_CLUSTER_ID_BYTES
        || wire.source_node != source_node
        || wire.target_node != context.local
        || wire.nonce == [0; 32]
        || wire.ingress == [0; 16]
        || wire.token.is_empty()
        || wire.token.len() > MAX_TOKEN_BYTES
        || !wire.operation.accepts(wire.method)
        || !wire.source.validate()
    {
        return Err(HaError::InvalidFrame);
    }
    check_leader(context.node, context.local, wire.leader_term, true)?;
    let _slot = context
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| HaError::WriterBusy)?;
    let handler = context
        .handler
        .lock()
        .map_err(|_| HaError::Transport)?
        .clone()
        .ok_or(HaError::NotLeader)?;
    let source = wire.source;
    let mut reply = ResponseWire {
        cluster: wire.cluster.clone(),
        source_node: context.local,
        target_node: source_node,
        leader_term: wire.leader_term,
        nonce: wire.nonce,
        ingress: wire.ingress,
        request_sha256: crate::crypto::digest(&frame),
        operation: wire.operation,
        method: wire.method,
        outcome: OutcomeWire::Rejected { status: 503 },
    };
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    let _ingress = crate::auth::IngressReplyScope::authenticated_forward(Some(wire.ingress), None);
    let observation = handler(AuthenticatedSnapshotClockRequest {
        wire,
        actual_peer_leaf,
        cluster_digest: context.cluster_digest,
        deadline,
    });
    // A locally committed but no-longer-owned result is unknown, not a reason
    // to repeat the observation on a newly elected leader or to mint a proof.
    if Instant::now() >= deadline {
        return Err(HaError::OutcomeUnknown);
    }
    check_leader(context.node, context.local, reply.leader_term, true)?;
    reply.outcome = match observation {
        Ok(observation) => {
            let (before, after, disposition) = observation.into_parts();
            if before != source || !valid_successor(before, after, context.local, reply.leader_term)
            {
                return Err(HaError::OutcomeUnknown);
            }
            match disposition {
                SnapshotClockDisposition::Allowed => OutcomeWire::Completed {
                    source: before,
                    successor: Box::new(after),
                },
                SnapshotClockDisposition::Denied => OutcomeWire::Denied {
                    source: before,
                    successor: Box::new(after),
                    status: 403,
                },
            }
        }
        Err(response) => OutcomeWire::Rejected {
            status: error_status(response.status),
        },
    };
    let mut encoded = SNAPSHOT_CLOCK_RESPONSE_MAGIC.to_vec();
    serde_json::to_writer(&mut encoded, &reply).map_err(|_| HaError::InvalidFrame)?;
    if encoded.len() > MAX_SNAPSHOT_CLOCK_FRAME_BYTES || Instant::now() >= deadline {
        return Err(HaError::OutcomeUnknown);
    }
    Ok(encoded)
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct OriginalBinding {
    operation: SnapshotClockOperation,
    method: ClockMethod,
    token_sha256: [u8; 32],
    origin_peer: Option<IpAddr>,
    ingress: [u8; 16],
    source: SharedSnapshotClockState,
    deadline: Instant,
}

impl OriginalBinding {
    fn capture(context: SnapshotClockContext<'_>) -> Result<Self, Response> {
        let method = ClockMethod::parse(context.method).ok_or_else(unavailable)?;
        if !context.operation.accepts(method)
            || context.token.is_empty()
            || context.token.len() > MAX_TOKEN_BYTES
            || context.ingress == [0; 16]
            || !context.source.validate()
            || context.enrollment.digest() != context.source.enrollment_digest
            || context.enrollment.epoch() != context.source.epoch
            || Instant::now() >= context.deadline
        {
            return Err(unavailable());
        }
        Ok(Self {
            operation: context.operation,
            method,
            token_sha256: crate::crypto::digest(context.token.as_bytes()),
            origin_peer: context.origin_peer,
            ingress: context.ingress,
            source: context.source,
            deadline: context.deadline,
        })
    }
}

struct ExpectedResponse<'a> {
    cluster: &'a str,
    caller: u64,
    leader: u64,
    term: u64,
    nonce: [u8; 32],
    request_sha256: [u8; 32],
    original: &'a OriginalBinding,
}

// Data from the pure metadata check, not an authenticated remote capability.
// Only the actual TLS caller can retain it in a RemoteSnapshotClockReceipt.
struct CheckedClockReply {
    successor: Option<SharedSnapshotClockState>,
    disposition: SnapshotClockDisposition,
}

// This pure metadata check cannot construct a RemoteSnapshotClockReceipt or a
// RemoteSnapshotClockCompletion. Production must complete the pinned exchange.
fn check_response_binding(
    reply: ResponseWire,
    expected: ExpectedResponse<'_>,
) -> Result<CheckedClockReply, Response> {
    if reply.cluster != expected.cluster
        || reply.source_node != expected.leader
        || reply.target_node != expected.caller
        || reply.leader_term != expected.term
        || reply.nonce != expected.nonce
        || reply.ingress != expected.original.ingress
        || reply.request_sha256 != expected.request_sha256
        || reply.operation != expected.original.operation
        || reply.method != expected.original.method
    {
        return Err(unavailable());
    }
    match reply.outcome {
        OutcomeWire::Completed { source, successor }
            if source == expected.original.source
                && valid_successor(source, *successor, expected.leader, expected.term) =>
        {
            Ok(CheckedClockReply {
                successor: *successor,
                disposition: SnapshotClockDisposition::Allowed,
            })
        }
        OutcomeWire::Denied {
            source,
            successor,
            status: 403,
        } if source == expected.original.source
            && valid_successor(source, *successor, expected.leader, expected.term) =>
        {
            Ok(CheckedClockReply {
                successor: *successor,
                disposition: SnapshotClockDisposition::Denied,
            })
        }
        OutcomeWire::Rejected { status } => Err(rejected(status)),
        _ => Err(unavailable()),
    }
}

/// One authenticated reply, retained only by its original local operation.
/// Consuming it yields one affine completion, never a local ReadIndex proof.
pub(crate) struct RemoteSnapshotClockReceipt {
    process: Arc<ProcessRaftNode>,
    binding: OriginalBinding,
    leader: u64,
    term: u64,
    effective_deadline: Instant,
    checked: CheckedClockReply,
}

/// Sealed by the original authenticated receipt's one-time consume. Metadata
/// getters do not authorize any bytes: the Service must still sync, obtain its
/// real ReadIndex proof, verify A/B and the original actor/seal/deadline, then
/// consume the matching disposition. No public constructor, Clone or serde.
pub(crate) struct RemoteSnapshotClockCompletion {
    checked: CheckedClockReply,
}

impl RemoteSnapshotClockCompletion {
    pub(crate) fn successor(&self) -> Option<SharedSnapshotClockState> {
        self.checked.successor
    }

    pub(crate) fn is_denied(&self) -> bool {
        self.checked.disposition == SnapshotClockDisposition::Denied
    }

    pub(crate) fn finish_allowed(self) -> Result<(), Response> {
        self.finish(SnapshotClockDisposition::Allowed)
    }

    pub(crate) fn finish_denied(self) -> Result<(), Response> {
        self.finish(SnapshotClockDisposition::Denied)
    }

    fn finish(self, expected: SnapshotClockDisposition) -> Result<(), Response> {
        if self.checked.disposition != expected {
            return Err(unavailable());
        }
        Ok(())
    }
}

impl RemoteSnapshotClockReceipt {
    pub(crate) fn consume(
        self,
        process: &HaProcess,
        expected: SnapshotClockContext<'_>,
    ) -> Result<RemoteSnapshotClockCompletion, Response> {
        let node = process.node.as_ref().ok_or_else(unavailable)?;
        if !Arc::ptr_eq(node, &self.process)
            || OriginalBinding::capture(expected)? != self.binding
            || expected.enrollment.cluster_digest() != process.codec.native_v6_cluster_digest()
            || Instant::now() >= self.effective_deadline
        {
            return Err(unavailable());
        }
        check_leader(node, self.leader, self.term, false).map_err(|_| unavailable())?;
        Ok(RemoteSnapshotClockCompletion {
            checked: self.checked,
        })
    }
}

impl HaProcess {
    pub(crate) fn register_snapshot_clock_handler(
        &mut self,
        handler: SnapshotClockHandler,
    ) -> Result<(), String> {
        let mut slot = self
            .snapshot_clock_handler
            .lock()
            .map_err(|_| "snapshot clock handler registry is unavailable")?;
        if slot.is_some() {
            return Err("snapshot clock handler is already registered".into());
        }
        *slot = Some(handler);
        Ok(())
    }

    pub(crate) fn observe_snapshot_terminal_clock(
        &self,
        context: SnapshotClockContext<'_>,
    ) -> Result<RemoteSnapshotClockReceipt, Response> {
        let binding = OriginalBinding::capture(context)?;
        if !self.native_v6_enabled()
            || self.emit_legacy_peer_v1
            || context.enrollment.cluster_digest() != self.codec.native_v6_cluster_digest()
            || crate::request_deadline::current() != Some(context.deadline)
        {
            return Err(unavailable());
        }
        let node = self.node.as_ref().ok_or_else(unavailable)?;
        let selected = node.local_leader_observation().map_err(|_| unavailable())?;
        let leader = selected.leader.ok_or_else(unavailable)?;
        if leader == selected.local_id || selected.term == 0 || selected.local_is_leader {
            return Err(unavailable());
        }
        let peer = self.peers.get(&leader).ok_or_else(unavailable)?;
        let pin = *context
            .enrollment
            .pins()
            .get(&leader)
            .ok_or_else(unavailable)?;
        if !context.enrollment.pins().contains_key(&selected.local_id) {
            return Err(unavailable());
        }
        let deadline = context.deadline.min(Instant::now() + self.forward_timeout);
        let nonce = crate::crypto::random::<32>().map_err(|_| unavailable())?;
        let mut request_sha256 = None;
        let response = self
            .forward_transport
            .exchange_snapshot_clock_before_pinned_server(peer, deadline, pin, |remaining| {
                check_leader(node, leader, selected.term, false)?;
                let wire = RequestWire {
                    cluster: self.cluster_id.clone(),
                    source_node: selected.local_id,
                    target_node: leader,
                    leader_term: selected.term,
                    nonce,
                    ingress: context.ingress,
                    operation: context.operation,
                    method: binding.method,
                    token: Zeroizing::new(context.token.to_owned()),
                    origin_peer: context.origin_peer,
                    source: context.source,
                };
                let mut frame = Zeroizing::new(SNAPSHOT_CLOCK_REQUEST_MAGIC.to_vec());
                frame.extend_from_slice(
                    &u64::try_from(remaining.as_nanos())
                        .map_err(|_| HaError::InvalidFrame)?
                        .to_be_bytes(),
                );
                serde_json::to_writer(&mut *frame, &wire).map_err(|_| HaError::InvalidFrame)?;
                if frame.len() > MAX_SNAPSHOT_CLOCK_FRAME_BYTES {
                    return Err(HaError::InvalidFrame);
                }
                request_sha256 = Some(crate::crypto::digest(&frame));
                Ok(std::mem::take(&mut *frame))
            })
            .map_err(|_| unavailable())?;
        let response = Zeroizing::new(response);
        if !response.starts_with(SNAPSHOT_CLOCK_RESPONSE_MAGIC)
            || response.len() > MAX_SNAPSHOT_CLOCK_FRAME_BYTES
            || Instant::now() >= deadline
        {
            return Err(unavailable());
        }
        check_leader(node, leader, selected.term, false).map_err(|_| unavailable())?;
        let reply: ResponseWire =
            serde_json::from_slice(&response[SNAPSHOT_CLOCK_RESPONSE_MAGIC.len()..])
                .map_err(|_| unavailable())?;
        let checked = check_response_binding(
            reply,
            ExpectedResponse {
                cluster: &self.cluster_id,
                caller: selected.local_id,
                leader,
                term: selected.term,
                nonce,
                request_sha256: request_sha256.ok_or_else(unavailable)?,
                original: &binding,
            },
        )?;
        if Instant::now() >= deadline {
            return Err(unavailable());
        }
        Ok(RemoteSnapshotClockReceipt {
            process: node.clone(),
            binding,
            leader,
            term: selected.term,
            effective_deadline: deadline,
            checked,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> SharedSnapshotClockState {
        SharedSnapshotClockState {
            epoch: 0,
            enrollment_digest: [7; 32],
            root_digest: [8; 32],
            logical_generation: 9,
            publication_log: SnapshotClockLogId {
                term: 3,
                node_id: 1,
                index: 50,
            },
            auth_sha256: [10; 32],
        }
    }

    fn original() -> OriginalBinding {
        OriginalBinding {
            operation: SnapshotClockOperation::Download,
            method: ClockMethod::Get,
            token_sha256: [11; 32],
            origin_peer: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            ingress: [12; 16],
            source: source(),
            deadline: Instant::now() + Duration::from_secs(1),
        }
    }

    fn response() -> ResponseWire {
        ResponseWire {
            cluster: "bound-clock-cluster".into(),
            source_node: 2,
            target_node: 3,
            leader_term: 5,
            nonce: [13; 32],
            ingress: [12; 16],
            request_sha256: [14; 32],
            operation: SnapshotClockOperation::Download,
            method: ClockMethod::Get,
            outcome: OutcomeWire::Completed {
                source: source(),
                successor: Box::new(None),
            },
        }
    }

    fn expected(original: &OriginalBinding) -> ExpectedResponse<'_> {
        ExpectedResponse {
            cluster: "bound-clock-cluster",
            caller: 3,
            leader: 2,
            term: 5,
            nonce: [13; 32],
            request_sha256: [14; 32],
            original,
        }
    }

    #[test]
    fn snapshot_clock_wire_refuses_cross_request_actor_ingress_direction_and_operation() {
        let original = original();
        assert!(matches!(
            check_response_binding(response(), expected(&original)),
            Ok(checked) if checked.successor.is_none()
                && checked.disposition == SnapshotClockDisposition::Allowed
        ));
        let mutations: [fn(&mut ResponseWire); 8] = [
            |reply| reply.nonce[0] ^= 1,
            |reply| reply.request_sha256[0] ^= 1,
            |reply| reply.ingress[0] ^= 1,
            |reply| reply.source_node = 1,
            |reply| reply.target_node = 1,
            |reply| reply.leader_term += 1,
            |reply| reply.operation = SnapshotClockOperation::ValidateUpload,
            |reply| reply.method = ClockMethod::Post,
        ];
        for mutate in mutations {
            let mut reply = response();
            mutate(&mut reply);
            assert!(matches!(
                check_response_binding(reply, expected(&original)),
                Err(response) if response.status == 503
            ));
        }
        let mut changed_source = source();
        changed_source.auth_sha256[0] ^= 1;
        let mut reply = response();
        reply.outcome = OutcomeWire::Completed {
            source: changed_source,
            successor: Box::new(None),
        };
        assert!(matches!(
            check_response_binding(reply, expected(&original)),
            Err(response) if response.status == 503
        ));
    }

    #[test]
    fn snapshot_clock_wire_requires_exact_single_successor_and_preserves_failed_auth_status() {
        let original = original();
        let successor = SharedSnapshotClockState {
            root_digest: [20; 32],
            logical_generation: 10,
            publication_log: SnapshotClockLogId {
                term: 5,
                node_id: 2,
                index: 55,
            },
            auth_sha256: [21; 32],
            ..source()
        };
        let mut reply = response();
        reply.outcome = OutcomeWire::Completed {
            source: source(),
            successor: Box::new(Some(successor)),
        };
        assert!(matches!(
            check_response_binding(reply, expected(&original)),
            Ok(checked) if checked.successor == Some(successor)
                && checked.disposition == SnapshotClockDisposition::Allowed
        ));
        for changed in [
            SharedSnapshotClockState {
                logical_generation: 11,
                ..successor
            },
            SharedSnapshotClockState {
                epoch: 1,
                ..successor
            },
            SharedSnapshotClockState {
                enrollment_digest: [22; 32],
                ..successor
            },
            SharedSnapshotClockState {
                publication_log: SnapshotClockLogId {
                    term: 4,
                    node_id: 2,
                    index: 55,
                },
                ..successor
            },
        ] {
            let mut reply = response();
            reply.outcome = OutcomeWire::Completed {
                source: source(),
                successor: Box::new(Some(changed)),
            };
            assert!(matches!(
                check_response_binding(reply, expected(&original)),
                Err(response) if response.status == 503
            ));
        }
        let mut reply = response();
        reply.outcome = OutcomeWire::Rejected { status: 403 };
        assert!(matches!(
            check_response_binding(reply, expected(&original)),
            Err(response) if response.status == 403
        ));
        assert!(!SnapshotClockOperation::Download.accepts(ClockMethod::Post));
        assert!(!SnapshotClockOperation::ValidateForceUpload.accepts(ClockMethod::Get));
    }


    #[test]
    fn snapshot_clock_denied_requires_original_binding_exact_successor_and_only_status_403() {
        let original = original();
        let successor = SharedSnapshotClockState {
            root_digest: [20; 32],
            logical_generation: 10,
            publication_log: SnapshotClockLogId {
                term: 5,
                node_id: 2,
                index: 55,
            },
            auth_sha256: [21; 32],
            ..source()
        };
        // These are pure metadata checks, never a constructed remote receipt
        // or completion. The actual three-voter Service tests own that proof.
        for successor in [None, Some(successor)] {
            let mut reply = response();
            reply.outcome = OutcomeWire::Denied {
                source: source(),
                successor: Box::new(successor),
                status: 403,
            };
            assert!(matches!(
                check_response_binding(reply, expected(&original)),
                Ok(checked) if checked.successor == successor
                    && checked.disposition == SnapshotClockDisposition::Denied
            ));
        }
        let mutations: [fn(&mut ResponseWire); 8] = [
            |reply| reply.nonce[0] ^= 1,
            |reply| reply.request_sha256[0] ^= 1,
            |reply| reply.ingress[0] ^= 1,
            |reply| reply.source_node = 1,
            |reply| reply.target_node = 1,
            |reply| reply.leader_term += 1,
            |reply| reply.operation = SnapshotClockOperation::ValidateUpload,
            |reply| reply.method = ClockMethod::Post,
        ];
        for mutate in mutations {
            let mut reply = response();
            reply.outcome = OutcomeWire::Denied {
                source: source(),
                successor: Box::new(None),
                status: 403,
            };
            mutate(&mut reply);
            assert!(matches!(
                check_response_binding(reply, expected(&original)),
                Err(error) if error.status == 503
            ));
        }
        for status in [0, 200, 400, 401, 409, 500, 503, u16::MAX] {
            let mut reply = response();
            reply.outcome = OutcomeWire::Denied {
                source: source(),
                successor: Box::new(None),
                status,
            };
            assert!(matches!(
                check_response_binding(reply, expected(&original)),
                Err(error) if error.status == 503
            ));
        }
        let mut wrong_source = source();
        wrong_source.auth_sha256[0] ^= 1;
        for (before, after) in [
            (wrong_source, None),
            (source(), Some(SharedSnapshotClockState {
                logical_generation: 11,
                ..successor
            })),
        ] {
            let mut reply = response();
            reply.outcome = OutcomeWire::Denied {
                source: before,
                successor: Box::new(after),
                status: 403,
            };
            assert!(matches!(
                check_response_binding(reply, expected(&original)),
                Err(error) if error.status == 503
            ));
        }
        let mut reply = response();
        reply.outcome = OutcomeWire::Rejected { status: 403 };
        assert!(matches!(
            check_response_binding(reply, expected(&original)),
            Err(error) if error.status == 403
        ));
    }

    #[test]
    fn snapshot_clock_token_wire_keeps_maximum_escaped_token_within_small_frame()
    -> Result<(), serde_json::Error> {
        let token = "\u{1}".repeat(MAX_TOKEN_BYTES);
        let wire = RequestWire {
            cluster: "bound-clock-cluster".into(),
            source_node: 3,
            target_node: 2,
            leader_term: 5,
            nonce: [13; 32],
            ingress: [12; 16],
            operation: SnapshotClockOperation::Download,
            method: ClockMethod::Get,
            token: Zeroizing::new(token.clone()),
            origin_peer: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            source: source(),
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&wire)?);
        assert!(encoded.len() + REQUEST_HEADER_BYTES <= MAX_SNAPSHOT_CLOCK_FRAME_BYTES);
        let decoded: RequestWire = serde_json::from_slice(&encoded)?;
        assert!(decoded.token.as_bytes() == token.as_bytes());
        let mut invalid: serde_json::Value = serde_json::from_slice(&encoded)?;
        invalid["token"] = serde_json::Value::String("not canonical base64".into());
        assert!(serde_json::from_value::<RequestWire>(invalid).is_err());
        Ok(())
    }
    #[test]
    fn snapshot_clock_outcome_box_preserves_frozen_named_field_wire_shape()
    -> Result<(), serde_json::Error> {
        // Fixed public payloads from frozen 06a2's original enum contract.
        // This pure codec fixture conveys no Service observation authority.
        const ORIGINAL_NONE: &[u8] = br#"{"kind":"completed","source":{"epoch":0,"enrollment_digest":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"root_digest":[8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8],"logical_generation":9,"publication_log":{"term":3,"node_id":1,"index":50},"auth_sha256":[10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10]},"successor":null}"#;
        const ORIGINAL_SOME: &[u8] = br#"{"kind":"completed","source":{"epoch":0,"enrollment_digest":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"root_digest":[8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8],"logical_generation":9,"publication_log":{"term":3,"node_id":1,"index":50},"auth_sha256":[10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10]},"successor":{"epoch":0,"enrollment_digest":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"root_digest":[8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8],"logical_generation":9,"publication_log":{"term":3,"node_id":1,"index":50},"auth_sha256":[10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10]}}"#;
        for (successor, original_bytes) in [(None, ORIGINAL_NONE), (Some(source()), ORIGINAL_SOME)]
        {
            let outcome = OutcomeWire::Completed {
                source: source(),
                successor: Box::new(successor),
            };
            assert_eq!(serde_json::to_vec(&outcome)?, original_bytes);
            let decoded: OutcomeWire = serde_json::from_slice(original_bytes)?;
            assert!(matches!(
                decoded,
                OutcomeWire::Completed {
                    source: actual,
                    successor: actual_successor,
                } if actual == source() && *actual_successor == successor
            ));
            assert!(
                original_bytes.len() + SNAPSHOT_CLOCK_RESPONSE_MAGIC.len()
                    <= MAX_SNAPSHOT_CLOCK_FRAME_BYTES
            );
        }
        let rejected = OutcomeWire::Rejected { status: 403 };
        assert_eq!(
            serde_json::to_vec(&rejected)?,
            br#"{"kind":"rejected","status":403}"#
        );
        Ok(())
    }
}
