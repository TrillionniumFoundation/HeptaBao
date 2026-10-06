//! A peer completion is minted only inside an authenticated inbound forward
//! scope, after the original Service floor, mandatory audit and delivery gates.
//! Deserializing wire metadata never constructs the affine delivery receipt.
use crate::{
    auth::{RequestClock, Timestamp},
    state_record_root::StateIdentity,
};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, time::Instant};

pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut result = [0; 32];
    result.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
    result
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompletionWire {
    pub nonce: [u8; 32],
    pub request_digest: [u8; 32],
    pub response_digest: [u8; 32],
    pub identity: StateIdentity,
    pub floor: Option<Timestamp>,
    pub precise: bool,
    pub audit_sequence: u64,
    pub audit_mac: [u8; 32],
    pub applied_index: u64,
    pub prefix: heptabao_raft_runtime::CommittedApplicationPrefix,
    pub owner_projection: [u8; 32],
    pub publication_mac: [u8; 32],
    pub actor: Option<crate::auth::ForwardActorWitness>,
    pub acknowledgement_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_missing_session_denial: Option<OidcDenialPublication>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OidcDenialPublication {
    pub denial: crate::auth::OidcMissingSessionDenial,
    pub non_auth_owner_projection: [u8; 32],
}

pub(crate) struct CompletedExchange<'a> {
    pub cluster: String,
    pub source: u64,
    pub target: u64,
    pub deadline: Instant,
    pub nonce: [u8; 32],
    pub request: &'a [u8],
    pub response_digest: [u8; 32],
}

// Only HaProcess's authenticated exchange can construct this type. No Clone:
// the exact completion travels once to the follower's terminal audit gate.
pub(crate) struct CompletedForwardReceipt {
    wire: CompletionWire,
    pub cluster: String,
    pub source: u64,
    pub target: u64,
    pub deadline: Instant,
}
impl CompletedForwardReceipt {
    pub(super) fn verified(
        wire: CompletionWire,
        exchange: CompletedExchange<'_>,
    ) -> Result<Self, String> {
        let CompletedExchange {
            cluster,
            source,
            target,
            deadline,
            nonce,
            request,
            response_digest,
        } = exchange;
        if Instant::now() >= deadline
            || wire.nonce != nonce
            || wire.request_digest != digest(request)
            || wire.response_digest != response_digest
            || wire.audit_sequence == 0
            || wire.audit_mac == [0; 32]
            || wire.identity.digest() == [0; 32]
            || wire.applied_index == 0
            || !wire.prefix.valid()
            || wire.applied_index != wire.prefix.index()
            || wire.owner_projection == [0; 32]
            || wire.publication_mac == [0; 32]
            || (wire.precise && wire.floor.is_none())
            || (wire.oidc_missing_session_denial.is_some() && wire.actor.is_some())
            || wire
                .oidc_missing_session_denial
                .as_ref()
                .is_some_and(|denial| denial.non_auth_owner_projection == [0; 32])
        {
            return Err("HA completed-forward proof is invalid".into());
        }
        Ok(Self {
            wire,
            cluster,
            source,
            target,
            deadline,
        })
    }
    // Verify the original source's actual publication and audit fields before
    // interpreting its log prefix against a later local quorum witness.
    pub(crate) fn verify_publication(&self, key: &[u8]) -> Result<(), String> {
        let bytes = publication_bytes(&self.wire, &self.cluster, self.source)?;
        ring::hmac::verify(&publication_key(key), &bytes, &self.wire.publication_mac)
            .map_err(|_| "HA completed-forward publication is unauthenticated".into())
    }
    pub(crate) fn prefix(&self) -> &heptabao_raft_runtime::CommittedApplicationPrefix {
        &self.wire.prefix
    }
    pub(crate) fn owner_projection(&self) -> [u8; 32] {
        self.wire.owner_projection
    }
    pub(crate) fn identity(&self) -> StateIdentity {
        self.wire.identity
    }
    pub(crate) fn floor(&self) -> Option<Timestamp> {
        self.wire.floor
    }
    pub(crate) fn actor(&self) -> Option<&crate::auth::ForwardActorWitness> {
        self.wire.actor.as_ref()
    }
    pub(crate) fn oidc_missing_session_denial(&self) -> Option<&OidcDenialPublication> {
        self.wire.oidc_missing_session_denial.as_ref()
    }
    pub(crate) fn acknowledgement_only(&self) -> bool {
        self.wire.acknowledgement_only
    }
    pub(crate) fn applied_index(&self) -> u64 {
        self.wire.applied_index
    }
    pub(crate) fn precise(&self) -> bool {
        self.wire.precise
    }
    pub(crate) fn response_matches(&self, response: &crate::Response) -> bool {
        response_digest(response).is_ok_and(|digest| digest == self.wire.response_digest)
    }
}

pub(crate) fn response_digest(response: &crate::Response) -> Result<[u8; 32], String> {
    let encoded = zeroize::Zeroizing::new(
        serde_json::to_vec(&(response.status, &response.body, &response.response_headers))
            .map_err(|_| "HA response digest is unavailable")?,
    );
    Ok(digest(&encoded))
}
pub(crate) fn wire_response_digest(
    response: &crate::ha_forward::ForwardResponse,
) -> Result<[u8; 32], String> {
    let encoded = zeroize::Zeroizing::new(
        serde_json::to_vec(&(response.status, &response.body, &response.response_headers))
            .map_err(|_| "HA response digest is unavailable")?,
    );
    Ok(digest(&encoded))
}

struct Capture {
    cluster: String,
    target: u64,
    nonce: [u8; 32],
    request_digest: [u8; 32],
    deadline: Instant,
    clock: Option<RequestClock>,
    audited: bool,
    actor: Option<crate::auth::ForwardActorWitness>,
    acknowledgement_only: bool,
    diagnostic_step_down: bool,
    oidc_missing_session_denial: Option<(crate::auth::OidcMissingSessionDenial, [u8; 32])>,
    complete: Option<CompletionWire>,
}
thread_local! { static CAPTURE: RefCell<Option<Capture>> = const {RefCell::new(None)}; }
pub(crate) struct CompletionScope {
    previous: Option<Capture>,
}
impl CompletionScope {
    pub(crate) fn enter(
        nonce: Option<[u8; 32]>,
        request: &[u8],
        deadline: Instant,
        cluster: &str,
        target: u64,
        acknowledgement_route: bool,
    ) -> Self {
        let previous = CAPTURE.with(|slot| {
            slot.replace(nonce.map(|nonce| Capture {
                cluster: cluster.to_owned(),
                target,
                nonce,
                request_digest: digest(request),
                deadline,
                clock: None,
                audited: false,
                actor: None,
                acknowledgement_only: acknowledgement_route,
                diagnostic_step_down: false,
                oidc_missing_session_denial: None,
                complete: None,
            }))
        });
        Self { previous }
    }
    pub(crate) fn has_oidc_missing_session_denial() -> bool {
        CAPTURE.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|c| c.oidc_missing_session_denial.is_some())
        })
    }
    pub(crate) fn active() -> bool {
        CAPTURE.with(|slot| slot.borrow().is_some())
    }
    pub(crate) fn deadline() -> Option<Instant> {
        CAPTURE.with(|slot| slot.borrow().as_ref().map(|c| c.deadline))
    }
    pub(crate) fn matches_owner(cluster: &str, local: u64) -> bool {
        CAPTURE.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|c| c.cluster == cluster && c.target == local)
        })
    }
    pub(crate) fn finish(&self) -> Option<CompletionWire> {
        CAPTURE.with(|slot| slot.borrow_mut().as_mut().and_then(|c| c.complete.take()))
    }
}
impl Drop for CompletionScope {
    fn drop(&mut self) {
        CAPTURE.with(|slot| {
            slot.replace(self.previous.take());
        });
    }
}
// Private diagnostic flag derives only from the authenticated decoded route.
// It is never serialized, included in a proof, or consulted by an authority gate.
pub(crate) fn diagnostic_step_down(enabled: bool) {
    CAPTURE.with(|slot| {
        if let Some(c) = slot.borrow_mut().as_mut() {
            c.diagnostic_step_down = enabled;
        }
    });
}
pub(crate) fn diagnostic_record_guard(guard: &'static str) {
    let enabled = CAPTURE.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|capture| capture.diagnostic_step_down)
    });
    if enabled {
        eprintln!("heptabao-forward-diagnostic: phase=record_validation guard={guard}");
    }
}
pub(crate) fn diagnostic_delivery_state(
    phase: &'static str,
    deadline_expired: bool,
    recovery_required: bool,
    sealed: bool,
    activation_matches: bool,
) {
    let captured = CAPTURE.with(|slot| {
        slot.borrow()
            .as_ref()
            .filter(|capture| capture.diagnostic_step_down)
            .map(|capture| capture.deadline)
    });
    if let Some(original_deadline) = captured {
        let now = std::time::Instant::now();
        eprintln!(
            "heptabao-forward-diagnostic: phase={phase} deadline_expired={deadline_expired} recovery_required={recovery_required} sealed={sealed} activation_matches={activation_matches} original_remaining_ns={} scoped_remaining_ns={:?}",
            original_deadline.saturating_duration_since(now).as_nanos(),
            crate::request_deadline::current()
                .map(|deadline| deadline.saturating_duration_since(now).as_nanos())
        );
    }
}
pub(crate) fn diagnostic_response(phase: &'static str, response: &crate::Response) {
    let enabled = CAPTURE.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|c| c.diagnostic_step_down)
    });
    if !enabled {
        return;
    }
    let error = response
        .body
        .get("errors")
        .and_then(|value| value.get(0))
        .and_then(serde_json::Value::as_str);
    let category = match error {
        None => "none",
        Some("Token API observation floor was not committed") => "terminal_floor_uncommitted",
        Some("HA linearizable state is unavailable") => "linearizable_state",
        Some("HA leadership transfer failed") => "transfer_failed",
        Some("HA step-down admission capsule was lost") => "step_down_capsule",
        Some("response audit failed; outcome unknown; authoritative recovery required") => {
            "response_audit"
        }
        Some("trusted token clock is unavailable") => "trusted_clock",
        Some("permission denied") => "permission_denied",
        Some("service request deadline exceeded") => "request_deadline",
        Some(_) => "other",
    };
    eprintln!(
        "heptabao-forward-diagnostic: phase={phase} status={} error_category={category} error_digest={:02x?}",
        response.status,
        error.map_or([0; 32], |value| digest(value.as_bytes()))
    );
}
// Only the real no-effect OIDC branch can supply this private affine value.
// A response status or error string never creates it.
pub(crate) fn oidc_missing_session_denied(
    denial: crate::auth::OidcMissingSessionDenial,
    response: &crate::Response,
) {
    let Ok(expected_response) = response_digest(response) else {
        return;
    };
    CAPTURE.with(|slot| {
        if let Some(c) = slot.borrow_mut().as_mut()
            && c.actor.is_none()
            && !c.acknowledgement_only
            && Instant::now() < c.deadline
        {
            c.oidc_missing_session_denial = Some((denial, expected_response));
        }
    });
}
pub(crate) fn actor(actor: crate::auth::ForwardActorWitness) {
    CAPTURE.with(|slot| {
        if let Some(c) = slot.borrow_mut().as_mut() {
            c.oidc_missing_session_denial = None;
            c.actor = Some(actor);
        }
    });
}
pub(crate) fn audited(clock: Option<RequestClock>) {
    CAPTURE.with(|slot| {
        if let Some(c) = slot.borrow_mut().as_mut() {
            c.clock = clock;
            c.audited = clock.is_some();
            c.complete = None;
        }
    });
}
pub(crate) struct CompletedPublication<'a> {
    pub proof_key: &'a [u8],
    pub identity: StateIdentity,
    pub prefix: heptabao_raft_runtime::CommittedApplicationPrefix,
    pub owner_projection: [u8; 32],
    pub floor: Option<Timestamp>,
    pub precise: bool,
    pub audit_sequence: u64,
    pub audit_mac: [u8; 32],
    pub non_auth_owner_projection: [u8; 32],
}
pub(crate) fn original_actor_live(
    response: &crate::Response,
    check: impl FnOnce(&crate::auth::ForwardActorWitness, RequestClock) -> bool,
) -> bool {
    CAPTURE.with(|slot| {
        let borrowed = slot.borrow();
        let Some(c) = borrowed.as_ref() else {
            return false;
        };
        if c.acknowledgement_only
            && response.status == 204
            && response.body.is_null()
            && response.response_headers.is_empty()
        {
            return true;
        }
        match (&c.actor, c.clock) {
            (Some(actor), Some(clock)) => check(actor, clock),
            (None, _) => true,
            _ => false,
        }
    })
}
pub(crate) fn seal(response: &crate::Response, publication: CompletedPublication<'_>) {
    let CompletedPublication {
        proof_key,
        identity,
        prefix,
        owner_projection,
        floor,
        precise,
        audit_sequence,
        audit_mac,
        non_auth_owner_projection,
    } = publication;
    let applied_index = prefix.index();
    CAPTURE.with(|slot| {
        if let Some(c) = slot.borrow_mut().as_mut() {
            let live_clock = c.clock.is_some_and(|clock| {
                clock.observed_at().is_ok()
                    && (!precise || floor.is_some_and(|at| at >= clock.admitted_at()))
            });
            if !c.audited || !live_clock || Instant::now() >= c.deadline {
                return;
            }
            let Ok(response_digest) = response_digest(response) else {
                return;
            };
            let no_actor = c.actor.is_none();
            let mut wire = CompletionWire {
                nonce: c.nonce,
                request_digest: c.request_digest,
                response_digest,
                identity,
                floor,
                precise,
                audit_sequence,
                audit_mac,
                applied_index,
                prefix,
                owner_projection,
                publication_mac: [0; 32],
                actor: c.actor.take(),
                oidc_missing_session_denial: c.oidc_missing_session_denial.take().and_then(
                    |(denial, expected)| {
                        (expected == response_digest
                            && no_actor
                            && non_auth_owner_projection != [0; 32]
                            && response.response_headers.is_empty()
                            && response.consistency_index.is_none())
                        .then_some(OidcDenialPublication {
                            denial,
                            non_auth_owner_projection,
                        })
                    },
                ),
                acknowledgement_only: c.acknowledgement_only
                    && response.status == 204
                    && response.body.is_null()
                    && response.response_headers.is_empty(),
            };
            let Ok(bytes) = publication_bytes(&wire, &c.cluster, c.target) else {
                return;
            };
            wire.publication_mac
                .copy_from_slice(ring::hmac::sign(&publication_key(proof_key), &bytes).as_ref());
            if Instant::now() < c.deadline {
                c.complete = Some(wire);
            }
        }
    });
}

// Domain-separated key derives only from the held current barrier key.
// Public transport metadata and caller body cannot select or supply it.
fn publication_key(barrier: &[u8]) -> ring::hmac::Key {
    let owner = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, barrier);
    let derived = ring::hmac::sign(&owner, b"HeptaBao/completed-forward/publication/v1");
    ring::hmac::Key::new(ring::hmac::HMAC_SHA256, derived.as_ref())
}
fn publication_bytes(
    wire: &CompletionWire,
    cluster: &str,
    source: u64,
) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let original = serde_json::to_vec(&(
        cluster,
        source,
        (
            wire.nonce,
            wire.request_digest,
            wire.response_digest,
            wire.identity,
            wire.floor,
            wire.precise,
            wire.audit_sequence,
            wire.audit_mac,
            wire.applied_index,
            wire.prefix,
            wire.owner_projection,
        ),
        (&wire.actor, wire.acknowledgement_only),
    ))
    .map(zeroize::Zeroizing::new)
    .map_err(|_| "HA completed-forward publication is unavailable")?;
    match &wire.oidc_missing_session_denial {
        None => Ok(original),
        Some(denial) => serde_json::to_vec(&(
            "HeptaBao/completed-forward/OIDC-missing-session-no-effect/v1",
            original.as_slice(),
            denial,
        ))
        .map(zeroize::Zeroizing::new)
        .map_err(|_| "HA completed-forward publication is unavailable".into()),
    }
}
