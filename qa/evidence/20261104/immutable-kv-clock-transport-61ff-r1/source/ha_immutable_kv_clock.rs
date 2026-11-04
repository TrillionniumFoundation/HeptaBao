//! Closed, metadata-only terminal-clock exchange for one original immutable KV read.
//! Wire metadata is data only. The leader Service alone can mint the sealed
//! observation after its actual clock writer; the follower must still consume
//! this affine exchange and obtain a real local ReadIndex proof before delivery.
use super::*;
use super::snapshot_clock::SharedSnapshotClockState;
use heptabao_ha_service::{
    AuthenticatedPeerFrame, HaError, MAX_IMMUTABLE_KV_CLOCK_FRAME_BYTES, IMMUTABLE_KV_CLOCK_REQUEST_MAGIC,
    IMMUTABLE_KV_CLOCK_RESPONSE_MAGIC,
};
use heptabao_raft_runtime::NativeV6PeerEnrollment;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

const REQUEST_HEADER_BYTES: usize = 13;
const MAX_HTTP_METADATA_BYTES: usize = 16 * 1024 + 4;
const MAX_RAW_TARGET_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum ClockMethod {
    Get,
    List,
    Scan,
}

impl ClockMethod {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "GET" => Some(Self::Get),
            "LIST" => Some(Self::List),
            "SCAN" => Some(Self::Scan),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::List => "LIST",
            Self::Scan => "SCAN",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum WireMethod {
    Get,
    Head,
    List,
    Scan,
}

impl WireMethod {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "GET" => Some(Self::Get),
            "HEAD" => Some(Self::Head),
            "LIST" => Some(Self::List),
            "SCAN" => Some(Self::Scan),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::List => "LIST",
            Self::Scan => "SCAN",
        }
    }

    // Only a structural precondition. The leader must run the actual original
    // HTTP parser and actual immutable-owner/parameter ACL checks itself.
    fn accepts(self, method: ClockMethod) -> bool {
        match self {
            Self::Get => matches!(method, ClockMethod::Get | ClockMethod::List | ClockMethod::Scan),
            Self::Head => method == ClockMethod::Get,
            Self::List => method == ClockMethod::List,
            Self::Scan => method == ClockMethod::Scan,
        }
    }
}

fn valid_shared_state(state: &SharedSnapshotClockState) -> bool {
    state.enrollment_digest != [0; 32]
        && state.root_digest != [0; 32]
        && state.auth_sha256 != [0; 32]
        && state.publication_log.term > 0
        && state.publication_log.node_id > 0
        && state.publication_log.index > 0
}

fn valid_http_metadata(raw_target: &str, namespace: &str, token: &str) -> bool {
    !raw_target.is_empty()
        && raw_target.len() <= MAX_RAW_TARGET_BYTES
        && !token.is_empty()
        && raw_target.len().checked_add(namespace.len())
            .and_then(|count| count.checked_add(token.len()))
            .is_some_and(|count| count <= MAX_HTTP_METADATA_BYTES)
}

/// References to the caller's already retained original request and actual
/// enrollment. Constructing this data does not grant any observation authority.
#[derive(Clone, Copy)]
pub(crate) struct ImmutableKvClockContext<'a> {
    pub(crate) wire_method: &'a str,
    pub(crate) method: &'a str,
    pub(crate) raw_target: &'a str,
    pub(crate) namespace: &'a str,
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
    cluster_digest: [u8; 32],
    source_node: u64,
    target_node: u64,
    leader_term: u64,
    nonce: [u8; 32],
    ingress: [u8; 16],
    wire_method: WireMethod,
    method: ClockMethod,
    #[serde(with = "text_wire")]
    raw_target: Zeroizing<String>,
    #[serde(with = "text_wire")]
    namespace: Zeroizing<String>,
    #[serde(with = "text_wire")]
    token: Zeroizing<String>,
    origin_peer: Option<IpAddr>,
    source: SharedSnapshotClockState,
}

// HTTP bounds the request line and all headers jointly. Encode the original
// target, namespace and token once each, using canonical base64. Their joint
// decoded size is checked before sending and after parsing; parsed query JSON
// and business payloads never enter this independent 32 KiB protocol.
mod text_wire {
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
        if encoded.len() > MAX_HTTP_METADATA_BYTES.div_ceil(3) * 4 {
            return Err(D::Error::custom("immutable KV clock metadata bound exceeded"));
        }
        let decoded = Zeroizing::new(
            STANDARD
                .decode(encoded.as_bytes())
                .map_err(|_| D::Error::custom("immutable KV clock metadata encoding invalid"))?,
        );
        let canonical = Zeroizing::new(STANDARD.encode(decoded.as_slice()));
        if decoded.len() > MAX_HTTP_METADATA_BYTES || canonical.as_bytes() != encoded.as_bytes() {
            return Err(D::Error::custom(
                "immutable KV clock metadata encoding is not canonical",
            ));
        }
        let token = std::str::from_utf8(&decoded)
            .map_err(|_| D::Error::custom("immutable KV clock metadata text invalid"))?;
        Ok(Zeroizing::new(token.to_owned()))
    }
}

/// This type has no constructor, Clone or Deserialize outside this actual TLS
/// dispatcher. The Service independently authenticates the original token and
/// compares source A against its own real proof before observing its own clock.
pub(crate) struct AuthenticatedImmutableKvClockRequest {
    wire: RequestWire,
    actual_peer_leaf: [u8; 32],
    cluster_digest: [u8; 32],
    deadline: Instant,
}

impl AuthenticatedImmutableKvClockRequest {
    pub(crate) fn source(&self) -> &SharedSnapshotClockState {
        &self.wire.source
    }
    pub(crate) fn wire_method(&self) -> &'static str {
        self.wire.wire_method.as_str()
    }
    pub(crate) fn method(&self) -> &'static str {
        self.wire.method.as_str()
    }
    pub(crate) fn raw_target(&self) -> &str {
        &self.wire.raw_target
    }
    pub(crate) fn namespace(&self) -> &str {
        &self.wire.namespace
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

pub(crate) type ImmutableKvClockHandler = Arc<
    dyn Fn(
            AuthenticatedImmutableKvClockRequest,
        ) -> Result<crate::service::ImmutableKvClockObservation, Response>
        + Send
        + Sync,
>;

/// The decision attached to a sealed Service clock observation. This enum is
/// data only: constructing it cannot mint an observation or remote completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ImmutableKvClockDisposition {
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
    cluster_digest: [u8; 32],
    source_node: u64,
    target_node: u64,
    leader_term: u64,
    nonce: [u8; 32],
    ingress: [u8; 16],
    request_sha256: [u8; 32],
    wire_method: WireMethod,
    method: ClockMethod,
    outcome: OutcomeWire,
}

fn unavailable() -> Response {
    Response::error(503, "immutable KV terminal observation is unavailable")
}

fn rejected(status: u16) -> Response {
    match status {
        400 => Response::error(400, "immutable KV terminal observation request is invalid"),
        403 => Response::error(403, "permission denied"),
        409 => Response::error(409, "immutable KV terminal observation source changed"),
        500 => Response::error(500, "immutable KV terminal observation failed"),
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
        valid_shared_state(&next)
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
    pub(super) cluster_digest: [u8; 32],
    pub(super) local: u64,
    pub(super) ids: &'a BTreeMap<NodeId, u64>,
    pub(super) native_candidate: bool,
    pub(super) node: &'a Arc<ProcessRaftNode>,
    pub(super) handler: &'a Arc<Mutex<Option<ImmutableKvClockHandler>>>,
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
        || frame.len() > MAX_IMMUTABLE_KV_CLOCK_FRAME_BYTES
        || !frame.starts_with(IMMUTABLE_KV_CLOCK_REQUEST_MAGIC)
        || Instant::now() >= deadline
    {
        return Err(HaError::InvalidFrame);
    }
    let wire: RequestWire = serde_json::from_slice(&frame[REQUEST_HEADER_BYTES..])
        .map_err(|_| HaError::InvalidFrame)?;
    if wire.cluster_digest != context.cluster_digest
        || wire.cluster_digest == [0; 32]
        || wire.source_node != source_node
        || wire.target_node != context.local
        || wire.nonce == [0; 32]
        || wire.ingress == [0; 16]
        || !valid_http_metadata(&wire.raw_target, &wire.namespace, &wire.token)
        || !wire.wire_method.accepts(wire.method)
        || !valid_shared_state(&wire.source)
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
        cluster_digest: wire.cluster_digest,
        source_node: context.local,
        target_node: source_node,
        leader_term: wire.leader_term,
        nonce: wire.nonce,
        ingress: wire.ingress,
        request_sha256: crate::crypto::digest(&frame),
        wire_method: wire.wire_method,
        method: wire.method,
        outcome: OutcomeWire::Rejected { status: 503 },
    };
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(deadline);
    let _ingress = crate::auth::IngressReplyScope::authenticated_forward(Some(wire.ingress), None);
    let observation = handler(AuthenticatedImmutableKvClockRequest {
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
                ImmutableKvClockDisposition::Allowed => OutcomeWire::Completed {
                    source: before,
                    successor: Box::new(after),
                },
                ImmutableKvClockDisposition::Denied => OutcomeWire::Denied {
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
    let mut encoded = IMMUTABLE_KV_CLOCK_RESPONSE_MAGIC.to_vec();
    serde_json::to_writer(&mut encoded, &reply).map_err(|_| HaError::InvalidFrame)?;
    if encoded.len() > MAX_IMMUTABLE_KV_CLOCK_FRAME_BYTES || Instant::now() >= deadline {
        return Err(HaError::OutcomeUnknown);
    }
    Ok(encoded)
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct OriginalBinding {
    wire_method: WireMethod,
    method: ClockMethod,
    raw_target_sha256: [u8; 32],
    namespace_sha256: [u8; 32],
    token_sha256: [u8; 32],
    origin_peer: Option<IpAddr>,
    ingress: [u8; 16],
    source: SharedSnapshotClockState,
    deadline: Instant,
}

impl OriginalBinding {
    fn capture(context: ImmutableKvClockContext<'_>) -> Result<Self, Response> {
        let method = ClockMethod::parse(context.method).ok_or_else(unavailable)?;
        let wire_method = WireMethod::parse(context.wire_method).ok_or_else(unavailable)?;
        if !wire_method.accepts(method)
            || !valid_http_metadata(context.raw_target, context.namespace, context.token)
            || context.ingress == [0; 16]
            || !valid_shared_state(&context.source)
            || context.enrollment.digest() != context.source.enrollment_digest
            || context.enrollment.epoch() != context.source.epoch
            || Instant::now() >= context.deadline
        {
            return Err(unavailable());
        }
        Ok(Self {
            wire_method,
            method,
            raw_target_sha256: crate::crypto::digest(context.raw_target.as_bytes()),
            namespace_sha256: crate::crypto::digest(context.namespace.as_bytes()),
            token_sha256: crate::crypto::digest(context.token.as_bytes()),
            origin_peer: context.origin_peer,
            ingress: context.ingress,
            source: context.source,
            deadline: context.deadline,
        })
    }
}

struct ExpectedResponse<'a> {
    cluster_digest: [u8; 32],
    caller: u64,
    leader: u64,
    term: u64,
    nonce: [u8; 32],
    request_sha256: [u8; 32],
    original: &'a OriginalBinding,
}

// Data from the pure metadata check, not an authenticated remote capability.
// Only the actual TLS caller can retain it in a RemoteImmutableKvClockReceipt.
struct CheckedClockReply {
    successor: Option<SharedSnapshotClockState>,
    disposition: ImmutableKvClockDisposition,
}

// This pure metadata check cannot construct a RemoteImmutableKvClockReceipt or a
// RemoteImmutableKvClockCompletion. Production must complete the pinned exchange.
fn check_response_binding(
    reply: ResponseWire,
    expected: ExpectedResponse<'_>,
) -> Result<CheckedClockReply, Response> {
    if reply.cluster_digest != expected.cluster_digest
        || reply.source_node != expected.leader
        || reply.target_node != expected.caller
        || reply.leader_term != expected.term
        || reply.nonce != expected.nonce
        || reply.ingress != expected.original.ingress
        || reply.request_sha256 != expected.request_sha256
        || reply.wire_method != expected.original.wire_method
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
                disposition: ImmutableKvClockDisposition::Allowed,
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
                disposition: ImmutableKvClockDisposition::Denied,
            })
        }
        OutcomeWire::Rejected { status } => Err(rejected(status)),
        _ => Err(unavailable()),
    }
}

/// One authenticated reply, retained only by its original local operation.
/// Consuming it yields one affine completion, never a local ReadIndex proof.
pub(crate) struct RemoteImmutableKvClockReceipt {
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
pub(crate) struct RemoteImmutableKvClockCompletion {
    checked: CheckedClockReply,
}

impl RemoteImmutableKvClockCompletion {
    pub(crate) fn successor(&self) -> Option<SharedSnapshotClockState> {
        self.checked.successor
    }

    pub(crate) fn is_denied(&self) -> bool {
        self.checked.disposition == ImmutableKvClockDisposition::Denied
    }

    pub(crate) fn finish_allowed(self) -> Result<(), Response> {
        self.finish(ImmutableKvClockDisposition::Allowed)
    }

    pub(crate) fn finish_denied(self) -> Result<(), Response> {
        self.finish(ImmutableKvClockDisposition::Denied)
    }

    fn finish(self, expected: ImmutableKvClockDisposition) -> Result<(), Response> {
        if self.checked.disposition != expected {
            return Err(unavailable());
        }
        Ok(())
    }
}

impl RemoteImmutableKvClockReceipt {
    pub(crate) fn consume(
        self,
        process: &HaProcess,
        expected: ImmutableKvClockContext<'_>,
    ) -> Result<RemoteImmutableKvClockCompletion, Response> {
        let node = process.node.as_ref().ok_or_else(unavailable)?;
        if !Arc::ptr_eq(node, &self.process)
            || OriginalBinding::capture(expected)? != self.binding
            || expected.enrollment.cluster_digest() != process.codec.native_v6_cluster_digest()
            || Instant::now() >= self.effective_deadline
        {
            return Err(unavailable());
        }
        check_leader(node, self.leader, self.term, false).map_err(|_| unavailable())?;
        Ok(RemoteImmutableKvClockCompletion {
            checked: self.checked,
        })
    }
}

impl HaProcess {
    pub(crate) fn register_immutable_kv_clock_handler(
        &mut self,
        handler: ImmutableKvClockHandler,
    ) -> Result<(), String> {
        let mut slot = self
            .immutable_kv_clock_handler
            .lock()
            .map_err(|_| "immutable KV clock handler registry is unavailable")?;
        if slot.is_some() {
            return Err("immutable KV clock handler is already registered".into());
        }
        *slot = Some(handler);
        Ok(())
    }

    pub(crate) fn observe_immutable_kv_terminal_clock(
        &self,
        context: ImmutableKvClockContext<'_>,
    ) -> Result<RemoteImmutableKvClockReceipt, Response> {
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
            .exchange_immutable_kv_clock_before_pinned_server(peer, deadline, pin, |remaining| {
                check_leader(node, leader, selected.term, false)?;
                let wire = RequestWire {
                    cluster_digest: context.enrollment.cluster_digest(),
                    source_node: selected.local_id,
                    target_node: leader,
                    leader_term: selected.term,
                    nonce,
                    ingress: context.ingress,
                    wire_method: binding.wire_method,
                    method: binding.method,
                    raw_target: Zeroizing::new(context.raw_target.to_owned()),
                    namespace: Zeroizing::new(context.namespace.to_owned()),
                    token: Zeroizing::new(context.token.to_owned()),
                    origin_peer: context.origin_peer,
                    source: context.source,
                };
                let mut frame = Zeroizing::new(IMMUTABLE_KV_CLOCK_REQUEST_MAGIC.to_vec());
                frame.extend_from_slice(
                    &u64::try_from(remaining.as_nanos())
                        .map_err(|_| HaError::InvalidFrame)?
                        .to_be_bytes(),
                );
                serde_json::to_writer(&mut *frame, &wire).map_err(|_| HaError::InvalidFrame)?;
                if frame.len() > MAX_IMMUTABLE_KV_CLOCK_FRAME_BYTES {
                    return Err(HaError::InvalidFrame);
                }
                request_sha256 = Some(crate::crypto::digest(&frame));
                Ok(std::mem::take(&mut *frame))
            })
            .map_err(|_| unavailable())?;
        let response = Zeroizing::new(response);
        if !response.starts_with(IMMUTABLE_KV_CLOCK_RESPONSE_MAGIC)
            || response.len() > MAX_IMMUTABLE_KV_CLOCK_FRAME_BYTES
            || Instant::now() >= deadline
        {
            return Err(unavailable());
        }
        check_leader(node, leader, selected.term, false).map_err(|_| unavailable())?;
        let reply: ResponseWire =
            serde_json::from_slice(&response[IMMUTABLE_KV_CLOCK_RESPONSE_MAGIC.len()..])
                .map_err(|_| unavailable())?;
        let checked = check_response_binding(
            reply,
            ExpectedResponse {
                cluster_digest: context.enrollment.cluster_digest(),
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
        Ok(RemoteImmutableKvClockReceipt {
            process: node.clone(),
            binding,
            leader,
            term: selected.term,
            effective_deadline: deadline,
            checked,
        })
    }
}
