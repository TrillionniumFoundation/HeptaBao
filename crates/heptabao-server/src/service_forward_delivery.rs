//! Follower delivery consumes a verified completed peer result, never a new
//! local Actor admission or Raft publication. Local mandatory audit is retained.
use super::*;
use crate::ha_forward_completion::{CompletedForwardReceipt, CompletionScope};
use std::time::Instant;

pub(super) enum PendingForwardDelivery {
    Rejected,
    Completed(Box<ForwardDelivery>),
}

pub(super) struct ForwardDelivery {
    receipt: CompletedForwardReceipt,
    ha: Arc<Mutex<crate::ha::HaProcess>>,
    unseal_nonce: Zeroizing<String>,
    barrier_digest: [u8; 32],
    namespace: Zeroizing<String>,
    namespace_binding: namespace_runtime::DeliveryBinding,
    clock: Option<RequestClock>,
    now: u64,
}
impl Service {
    // Exact current authority graph, with only the independently proven
    // monotonic Token API observation excluded. Other owners stay exact.
    fn forward_owner_projection(&self) -> Result<[u8; 32], Response> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(unavailable)?
            .protected_state()?;
        let auth = state
            .auth
            .forward_owner_projection_digest()
            .map_err(|_| unavailable())?;
        let root = self.record_root.as_ref().ok_or_else(unavailable)?;
        let other: Vec<_> = root
            .owners
            .iter()
            .filter(|owner| owner.name != "auth")
            .map(|owner| (&owner.name, owner.digest))
            .collect();
        let bytes = Zeroizing::new(
            serde_json::to_vec(&(
                root.state_schema,
                &root.cluster_id,
                root.replay_epoch,
                other,
                &root.kv1,
                auth,
            ))
            .map_err(|_| unavailable())?,
        );
        Ok(crate::ha_forward_completion::digest(&bytes))
    }
    pub(super) fn expects_local_ha_step_down(&self, path: &str, response: &Response) -> bool {
        path == "sys/step-down"
            && response.status == 204
            && !matches!(
                self.pending_forward_delivery.as_ref(),
                Some(PendingForwardDelivery::Completed(_))
            )
    }
    pub(super) fn stage_forward_delivery(
        &mut self,
        receipt: CompletedForwardReceipt,
        ha: Arc<Mutex<crate::ha::HaProcess>>,
        namespace: &str,
        clock: Option<RequestClock>,
        now: u64,
    ) -> Result<ForwardDelivery, Response> {
        let state = self.state.as_ref().ok_or_else(unavailable)?;
        let key = self.barrier_key.as_ref().ok_or_else(unavailable)?;
        let result = ForwardDelivery {
            receipt,
            ha,
            unseal_nonce: Zeroizing::new(self.unseal_nonce.clone()),
            barrier_digest: crate::ha_forward_completion::digest(key.as_slice()),
            namespace: Zeroizing::new(namespace.to_owned()),
            namespace_binding: namespace_runtime::DeliveryBinding::capture(state, namespace),
            clock,
            now,
        };
        self.check_forward_delivery(&result, "stage")?;
        Ok(result)
    }
    fn check_forward_delivery(
        &mut self,
        authority: &ForwardDelivery,
        phase: &'static str,
    ) -> Result<(), Response> {
        let _original_deadline =
            crate::request_deadline::RequestDeadlineScope::enter(authority.receipt.deadline);
        let original_key = self.barrier_key.as_ref().ok_or_else(unavailable)?;
        authority
            .receipt
            .verify_publication(original_key.as_slice())
            .map_err(|_| diagnostic_unavailable(phase, "publication_mac"))?;
        // Wait and synchronize before the final original Actor observation.
        // A blocking applied-index wait must never follow that observation.
        authority
            .ha
            .lock_for_request()
            .map_err(|_| diagnostic_unavailable(phase, "ha_lock"))?
            .wait_forward_applied(&authority.receipt)
            .map_err(|_| diagnostic_unavailable(phase, "wait_applied"))?;
        // No deadline or Actor is renewed when an unrelated completion raced
        // the first materialization. The final witness must authenticate this
        // same actual Service graph before any owner or Actor check follows.
        let (actual_identity, witness) = loop {
            self.sync_from_ha_with_anchor(false).inspect_err(|error| {
                eprintln!(
                    "heptabao-forward-diagnostic: phase={phase} guard=sync status={}",
                    error.status
                );
            })?;
            let (identity, witness) = authority
                .ha
                .lock_for_request()
                .map_err(|_| unavailable())?
                .application_identity_witness()
                .map_err(|_| diagnostic_unavailable(phase, "fresh_witness"))?;
            if self.current_state_identity()? == identity {
                break (identity, witness);
            }
            if Instant::now() >= authority.receipt.deadline {
                return Err(unavailable());
            }
        };
        if !witness.covers_completed_prefix(authority.receipt.prefix())
            || self
                .forward_owner_projection()
                .map_err(|_| diagnostic_unavailable(phase, "current_projection"))?
                != authority.receipt.owner_projection()
        {
            eprintln!(
                "heptabao-forward-diagnostic: phase={phase} guard=prefix_or_owner actual_digest={:02x?} receipt_digest={:02x?}",
                actual_identity.digest(),
                authority.receipt.identity().digest()
            );
            return Err(unavailable());
        }
        let state = self.state.as_ref().ok_or_else(unavailable)?;
        let key = self.barrier_key.as_ref().ok_or_else(unavailable)?;
        macro_rules! veto_if {
            ($condition:expr, $label:literal) => {
                if $condition {
                    return Err(diagnostic_unavailable(phase, $label));
                }
            };
        }
        veto_if!(self.recovery_required, "recovery");
        veto_if!(self.audit_failed, "audit_failed");
        veto_if!(
            self.durable
                .as_ref()
                .is_none_or(|store| store.recovery_required()),
            "durable_recovery"
        );
        veto_if!(self.unseal_nonce != *authority.unseal_nonce, "unseal_nonce");
        veto_if!(
            crate::ha_forward_completion::digest(key.as_slice()) != authority.barrier_digest,
            "barrier_digest"
        );
        veto_if!(state.cluster_id != authority.receipt.cluster, "cluster");
        if !matches!((state.auth.terminal_token_clock_floor(), authority.receipt.floor()),
            (Some(current), Some(original)) if current >= original)
            && !(state.auth.terminal_token_clock_floor().is_none()
                && authority.receipt.floor().is_none())
        {
            eprintln!(
                "heptabao-forward-diagnostic: phase={phase} guard=floor actual={:?} receipt={:?} receipt_index={}",
                state.auth.terminal_token_clock_floor(),
                authority.receipt.floor(),
                authority.receipt.applied_index()
            );
            return Err(unavailable());
        }
        veto_if!(
            self.ha
                .as_ref()
                .is_none_or(|ha| !Arc::ptr_eq(ha, &authority.ha)),
            "ha_owner"
        );
        veto_if!(
            namespace_runtime::DeliveryBinding::capture(state, &authority.namespace)
                != authority.namespace_binding,
            "namespace_binding"
        );
        veto_if!(Instant::now() >= authority.receipt.deadline, "deadline");
        veto_if!(
            authority.receipt.precise() && authority.clock.is_none(),
            "clock_missing"
        );
        veto_if!(
            authority
                .clock
                .is_some_and(|clock| clock.observed_at().is_err()),
            "clock_observation"
        );
        if !authority.receipt.acknowledgement_only()
            && let Some(actor) = authority.receipt.actor()
        {
            let time = match authority.clock {
                Some(clock) => {
                    AuthorityTime::Precise(clock.observed_at().map_err(|_| unavailable())?)
                }
                None => AuthorityTime::Coarse(authority.now),
            };
            state
                .auth
                .validate_forward_actor(actor, time)
                .map_err(|e| {
                    eprintln!("heptabao-forward-diagnostic: phase={phase} guard=actor status={} receipt_index={}", e.status, authority.receipt.applied_index());
                    Response::error(e.status, &e.message)
                })?;
        }
        if Instant::now() >= authority.receipt.deadline {
            return Err(diagnostic_unavailable(phase, "final_deadline"));
        }
        Ok(())
    }
    pub(super) fn check_pending_forward_delivery(
        &mut self,
        response: &Response,
    ) -> Result<(), Response> {
        let Some(pending) = self.pending_forward_delivery.take() else {
            return Err(unavailable());
        };
        let result = match &pending {
            PendingForwardDelivery::Rejected => Err(unavailable()),
            PendingForwardDelivery::Completed(authority) => {
                if authority.receipt.response_matches(response) {
                    self.check_forward_delivery(authority, "pre_audit")
                } else {
                    Err(diagnostic_unavailable("pre_audit", "response_digest"))
                }
            }
        };
        self.pending_forward_delivery = Some(pending);
        result
    }
    pub(super) fn complete_forward_delivery(
        &mut self,
        mut response: Response,
        fingerprint: &str,
    ) -> Response {
        let Some(pending) = self.pending_forward_delivery.take() else {
            return response;
        };
        let PendingForwardDelivery::Completed(authority) = pending else {
            erase_json(&mut response.body);
            response.response_headers.clear();
            return unavailable();
        };
        let rejection = if authority.receipt.response_matches(&response) {
            self.check_forward_delivery(&authority, "post_audit").err()
        } else {
            Some(diagnostic_unavailable("post_audit", "response_digest"))
        };
        if let Some(rejection) = rejection {
            erase_json(&mut response.body);
            response.response_headers.clear();
            response.consistency_index = None;
            if self
                .audit_event(
                    "forward_delivery_veto",
                    fingerprint,
                    authority.now,
                    Some(rejection.status),
                )
                .is_err()
            {
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(
                    503,
                    "forward delivery veto audit failed; outcome unknown; authoritative recovery required",
                );
            }
            return rejection;
        }
        response
    }
    // Called with the original Service writer still held, after every route's
    // existing audit and final delivery capsules have finished. No reacquire.
    pub(crate) fn seal_forward_completion(&self, response: &Response) {
        if crate::request_deadline::current().is_some_and(|deadline| Instant::now() >= deadline)
            || CompletionScope::deadline().is_none()
            || self.recovery_required
            || self.audit_failed
            || !self.ha_activation_permitted()
        {
            seal_diagnostic("entry");
            return;
        }
        let Some(state) = &self.state else {
            seal_diagnostic("state_missing");
            return;
        };
        let Some(ha) = &self.ha else {
            seal_diagnostic("ha_missing");
            return;
        };
        let Ok(ha) = ha.lock_for_request() else {
            seal_diagnostic("ha_lock");
            return;
        };
        let Ok(local) = ha.local_id() else {
            seal_diagnostic("local_id");
            return;
        };
        drop(ha);
        if !CompletionScope::matches_owner(&state.cluster_id, local) {
            seal_diagnostic("scope_owner");
            return;
        }
        let Ok(identity) = self.current_state_identity() else {
            seal_diagnostic("state_identity");
            return;
        };
        let Ok((observed_identity, witness)) = self
            .ha
            .as_ref()
            .ok_or(())
            .and_then(|ha| ha.lock_for_request().map_err(|_| ()))
            .and_then(|ha| ha.application_identity_witness().map_err(|_| ()))
        else {
            seal_diagnostic("fresh_witness");
            return;
        };
        if observed_identity != identity {
            seal_diagnostic("witness_identity");
            return;
        }
        let Ok(owner_projection) = self.forward_owner_projection() else {
            seal_diagnostic("projection");
            return;
        };
        if state.namespace_leases.validate().is_err()
            || !crate::ha_forward_completion::original_actor_live(response, |actor, clock| {
                clock.observed_at().is_ok_and(|now| {
                    state
                        .auth
                        .validate_forward_actor(actor, AuthorityTime::Precise(now))
                        .is_ok()
                })
            })
        {
            seal_diagnostic("terminal_actor_slots");
            return;
        }
        crate::ha_forward_completion::seal(
            response,
            crate::ha_forward_completion::CompletedPublication {
                proof_key: match self.barrier_key.as_ref() {
                    Some(key) => key.as_slice(),
                    None => return,
                },
                identity,
                prefix: witness.completed_prefix(),
                owner_projection,
                floor: state.auth.terminal_token_clock_floor(),
                precise: state.has_token_api_precision_state(),
                audit_sequence: self.audit_sequence,
                audit_mac: self.audit_previous,
            },
        );
    }
}
fn diagnostic_label(phase: &'static str, guard: &'static str) {
    eprintln!("heptabao-forward-diagnostic: phase={phase} guard={guard}");
}
fn diagnostic_unavailable(phase: &'static str, guard: &'static str) -> Response {
    diagnostic_label(phase, guard);
    unavailable()
}
fn unavailable() -> Response {
    Response::error(503, "HA leader forwarding failed")
}

#[cfg(test)]
#[path = "service_forward_delivery_tests.rs"]
mod tests;

fn seal_diagnostic(guard: &'static str) {
    if CompletionScope::active() {
        diagnostic_label("source_seal", guard);
    }
}
