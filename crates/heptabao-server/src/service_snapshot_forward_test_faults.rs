//! Test-only, per-Service fault injection at actual snapshot delivery boundaries.
//! No global state, fabricated completion, synthetic root or restored Auth authority.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Point {
    SourceAfterFinalizer,
    IngressFirstDelivery,
    IngressSecondDelivery,
}

#[derive(Clone, Debug)]
pub(crate) struct Observation {
    pub(crate) point: Point,
    pub(crate) nonce: [u8; 32],
    pub(crate) deadline: Instant,
    pub(crate) original_identity: StateIdentity,
    pub(crate) original_epoch: u64,
    pub(crate) original_auth: [u8; 32],
    pub(crate) installed_identity: Option<StateIdentity>,
    pub(crate) installed_epoch: Option<u64>,
    pub(crate) installed_auth: Option<[u8; 32]>,
    pub(crate) audit_sequence: u64,
    pub(crate) audit_bytes: Option<u64>,
    pub(crate) injected: bool,
}

#[derive(Default)]
pub(crate) struct State {
    armed: Option<(Point, [u8; 32])>,
    observation: Option<Observation>,
    hits: usize,
}

impl State {
    pub(crate) fn arm(&mut self, point: Point, nonce: [u8; 32]) -> Result<(), &'static str> {
        if self.armed.is_some() || self.observation.is_some() || self.hits != 0 {
            return Err("snapshot forward fault already used by this Service");
        }
        self.armed = Some((point, nonce));
        Ok(())
    }

    pub(crate) fn observed(&self) -> Option<&Observation> {
        self.observation.as_ref()
    }

    pub(crate) fn hits(&self) -> usize {
        self.hits
    }

    pub(crate) fn pending(&self) -> bool {
        self.armed.is_some()
    }
}

impl Service {
    pub(in crate::service::snapshot_transfer::forward) fn fixture_snapshot_forward_fault(
        &mut self, point: Point, nonce: [u8; 32], deadline: Instant,
        original: &wire::AdmissionData,
    ) {
        if self.snapshot_forward_test.armed != Some((point, nonce)) {
            return;
        }
        // Consume before any observation or injection. An I/O failure below
        // leaves injected=false and fails the test; it never retries a boundary.
        self.snapshot_forward_test.armed.take();
        self.snapshot_forward_test.hits += 1;
        let audit_bytes = self.audit.metadata().ok().map(|info| info.len());
        let observation = Observation {
            point, nonce, deadline,
            original_identity: original.original_identity,
            original_epoch: original.original_epoch,
            original_auth: original.original_auth,
            installed_identity: self.current_state_identity().ok(),
            installed_epoch: self.state.as_ref().map(|state| state.replay_epoch),
            installed_auth: self.state.as_ref()
                .and_then(|state| state.auth.forward_owner_projection_digest().ok()),
            audit_sequence: self.audit_sequence,
            audit_bytes,
            injected: audit_bytes.is_some(),
        };
        self.snapshot_forward_test.observation = Some(observation);
        if let Some(bytes) = audit_bytes {
            // These are two explicit test-only faults: invalidate the actual
            // activation nonce, then deny the next real audit append through
            // its existing test I/O capacity. No receipt, root, epoch, Actor,
            // completion data, deadline or recovery flag is supplied here.
            self.audit_capacity = bytes;
            self.unseal_nonce.push_str(":snapshot-forward-audit-fixture");
        }
    }
}

/// A negative wire fixture only: use the real enrolled mTLS peer but supply
/// untrusted JSON in a nonce-bound denial. It never sends READY, parses an
/// archive, admits an Actor, constructs CompletionWire or invokes a restore.
pub(crate) fn reject_unverified_root_fields(
    ingress: crate::ha::SnapshotIngress<'_>,
) -> Result<(), heptabao_ha_service::HaError> {
    let cluster = ingress.cluster().to_owned();
    let source = ingress.source();
    let target = ingress.target();
    let peer = ingress.into_peer();
    let metadata = Zeroizing::new(peer.metadata().to_vec());
    let request: wire::RequestWire = wire::decode(&metadata)
        .map_err(|_| heptabao_ha_service::HaError::InvalidFrame)?;
    if request.cluster != cluster || request.ingress != source || request.leader != target
        || request.operation().map_err(|_| heptabao_ha_service::HaError::InvalidFrame)?
            != wire::Operation::HistoricalRestore
    {
        return Err(heptabao_ha_service::HaError::PeerAuthenticationFailed);
    }
    let response = forged_root_response();
    let reply = wire::ReplyData::from_response(response, &cluster)
        .map_err(|_| heptabao_ha_service::HaError::InvalidFrame)?;
    let bytes = wire::encode(&wire::RejectionWire {
        nonce: request.nonce,
        metadata_sha256: wire::digest(&metadata),
        reply,
    }).map_err(|_| heptabao_ha_service::HaError::InvalidFrame)?;
    peer.reject(503, &bytes)
}

pub(crate) fn forged_root_response() -> Response {
    Response {
        status: 503,
        body: json!({"errors":["untrusted fixture denial"],"outcome_unknown":true,
            "retry_allowed":false,"root_attempted":true,
            "recovery_reference":"native-v6-restore-forged-untrusted-fixture"}),
        unwrapped_json: None,
        response_headers: Default::default(),
        consistency_index: None,
    }
}
