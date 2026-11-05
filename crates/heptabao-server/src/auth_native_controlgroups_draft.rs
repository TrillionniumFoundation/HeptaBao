//! Closed Auth-delta portion of a native CG transaction; not publication authority.
//!
//! Constructors run the existing domain operation once on a private candidate.
//! They never accept an arbitrary post-operation AuthState, recreate Principal,
//! publish, advance a budget, select a KV owner, or authenticate a bearer again.
//! Service integration must independently bind policy/group/resource/quorum and
//! join Execute's Auth delta to its real KV2 graph in the same native CAS plan.
//! Service retains the affine actors and joins this delta to its exact native writer.
use super::*;
use crate::v6_native_custody::OriginalDeadline;
use control_groups::{Approval, DeferredRequest};

pub(crate) enum Operation {
    Observe,
    Defer(Principal),
    Authorize {
        actor: Principal,
        accessor: String,
    },
    Execute {
        caller: Principal,
        requester: Principal,
        owner: Box<DeferredRequest>,
    },
}

// No Clone/serde/public fields. An expected digest can prove an exact Auth
// transition, but cannot by itself grant engine mutation or reply delivery.
pub(crate) struct NativeCgAuthDelta {
    source: AuthState,
    source_digest: [u8; 32],
    candidate_digest: [u8; 32],
    clock: RequestClock,
    deadline: OriginalDeadline,
    operation: Operation,
    namespace: Option<String>,
}

// A consumed Execute may transfer both original Principals into Service's
// operation/delivery owners. This capsule retains only its closed Auth delta;
// it cannot grant ACLs or be repurposed as an ordinary token-API authority.
pub(crate) struct NativeCgAuthBinding {
    source: AuthState,
    source_digest: [u8; 32],
    candidate_digest: [u8; 32],
    clock: RequestClock,
    deadline: OriginalDeadline,
}

impl NativeCgAuthBinding {
    pub(crate) fn check_candidate(
        &self,
        source: &AuthState,
        candidate: &AuthState,
    ) -> Result<(), AuthError> {
        self.deadline
            .check()
            .map_err(|_| err(503, "original control group deadline expired"))?;
        self.source
            .control_group_authority_time(NativeCgAuthDelta::original_time(self.clock)?)?;
        if digest(source)? != self.source_digest || digest(candidate)? != self.candidate_digest {
            return Err(err(503, "native control group Auth binding changed"));
        }
        candidate.validate_control_group_state()?;
        candidate.validate_control_group_clock_floor(Some(source))?;
        self.deadline
            .check()
            .map_err(|_| err(503, "original control group deadline expired"))
    }
}

pub(crate) fn same_owner(
    left: &DeferredRequest,
    right: &DeferredRequest,
) -> Result<bool, AuthError> {
    let left = crate::secret_serde::to_vec(left, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| err(503, "native CG owner encoding unavailable"))?;
    let right = crate::secret_serde::to_vec(right, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| err(503, "native CG owner encoding unavailable"))?;
    Ok(left.as_slice() == right.as_slice())
}

impl AuthState {
    pub(crate) fn native_cg_claim_is_spent(&self, owner: &DeferredRequest) -> bool {
        self.tokens
            .iter()
            .find(|(_, token)| token.accessor == owner.request_accessor)
            .is_some_and(|(id, token)| {
                !self.control_groups.requests.contains_key(id)
                    && token.namespace == owner.namespace
                    && token.uses_remaining == Some(0)
                    && token.policies == BTreeSet::from(["control-group".into()])
                    && token.expires_at == Some(owner.expires_at)
            })
    }
}

fn encoded(auth: &AuthState) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    crate::secret_serde::to_vec(auth, crate::MAX_APPLICATION_STATE_BYTES)
        .map_err(|_| err(503, "native control group Auth encoding unavailable"))
}
fn digest(auth: &AuthState) -> Result<[u8; 32], AuthError> {
    use sha2::{Digest, Sha256};
    Ok(Sha256::digest(encoded(auth)?.as_slice()).into())
}

impl NativeCgAuthDelta {
    pub(crate) fn into_parts(self) -> (NativeCgAuthBinding, Operation) {
        let Self {
            source,
            source_digest,
            candidate_digest,
            clock,
            deadline,
            operation,
            namespace: _,
        } = self;
        (
            NativeCgAuthBinding {
                source,
                source_digest,
                candidate_digest,
                clock,
                deadline,
            },
            operation,
        )
    }
    pub(crate) fn into_execute_parts(
        self,
    ) -> Result<(NativeCgAuthBinding, Principal, Principal, DeferredRequest), AuthError> {
        let Self {
            source,
            source_digest,
            candidate_digest,
            clock,
            deadline,
            operation,
            namespace: _,
        } = self;
        let Operation::Execute {
            caller,
            requester,
            owner,
        } = operation
        else {
            return Err(denied());
        };
        Ok((
            NativeCgAuthBinding {
                source,
                source_digest,
                candidate_digest,
                clock,
                deadline,
            },
            caller,
            requester,
            *owner,
        ))
    }

    pub(crate) fn original_time(clock: RequestClock) -> Result<AuthorityTime, AuthError> {
        OriginalDeadline::capture()
            .map_err(|_| err(503, "original control group deadline unavailable"))?;
        clock
            .observed_at()
            .map(AuthorityTime::Precise)
            .map_err(|_| err(503, "original control group clock unavailable"))
    }

    fn bound_actor(actor: &Principal, clock: RequestClock) -> Result<(), AuthError> {
        let original = actor.original_request_clock().ok_or_else(denied)?;
        if original.started() != clock.started() || original.admitted_at() != clock.admitted_at() {
            return Err(denied());
        }
        Ok(())
    }

    fn capture(
        source: &AuthState,
        candidate: &AuthState,
        clock: RequestClock,
        operation: Operation,
        namespace: Option<&str>,
    ) -> Result<Self, AuthError> {
        let deadline = OriginalDeadline::capture()
            .map_err(|_| err(503, "original control group deadline unavailable"))?;
        source.validate_control_group_state()?;
        candidate.validate_control_group_state()?;
        candidate.validate_control_group_clock_floor(Some(source))?;
        let delta = Self {
            source: source.clone(),
            source_digest: digest(source)?,
            candidate_digest: digest(candidate)?,
            clock,
            deadline,
            operation,
            namespace: namespace.map(str::to_owned),
        };
        delta.check_source(source)?;
        Ok(delta)
    }

    pub(crate) fn observe(
        source: &AuthState,
        clock: RequestClock,
    ) -> Result<(Self, AuthState), AuthError> {
        // Constructor may not cause even private work after the original scope
        // expires. Capture again below verifies the identical ambient deadline.
        OriginalDeadline::capture()
            .map_err(|_| err(503, "original control group deadline unavailable"))?;
        let mut candidate = source.clone();
        candidate.advance_control_group_observed(Self::original_time(clock)?)?;
        let delta = Self::capture(source, &candidate, clock, Operation::Observe, None)?;
        Ok((delta, candidate))
    }

    pub(crate) fn defer(
        source: &AuthState,
        clock: RequestClock,
        actor: Principal,
        owner: DeferredRequest,
        raw: &str,
    ) -> Result<(Self, AuthState, AuthResponse), AuthError> {
        Self::bound_actor(&actor, clock)?;
        let time = Self::original_time(clock)?;
        // Auth-delta construction is downstream of Service's exact selected
        // policy/group/mount owner, never a substitute for that capability.
        let namespace = owner.namespace.clone();
        source.check_principal_observed(&actor, &namespace, time)?;
        let mut candidate = source.clone();
        let response = candidate.issue_control_group_admitted(owner, &actor, raw, time)?;
        let delta = Self::capture(
            source,
            &candidate,
            clock,
            Operation::Defer(actor),
            Some(&namespace),
        )?;
        Ok((delta, candidate, response))
    }

    #[cfg(test)]
    pub(crate) fn authorize(
        source: &AuthState,
        clock: RequestClock,
        actor: Principal,
        accessor: &str,
        entity_name: String,
        raw: &str,
    ) -> Result<(Self, AuthState), AuthError> {
        Self::authorize_scoped(source, clock, actor, "", accessor, entity_name, raw)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authorize_scoped(
        source: &AuthState,
        clock: RequestClock,
        actor: Principal,
        namespace: &str,
        accessor: &str,
        entity_name: String,
        raw: &str,
    ) -> Result<(Self, AuthState), AuthError> {
        Self::bound_actor(&actor, clock)?;
        let time = Self::original_time(clock)?;
        source.authorize_request_observed(
            &actor,
            namespace,
            "sys/control-group/authorize",
            "update",
            time,
        )?;
        let owner = source.control_group_by_accessor(accessor, namespace, time)?;
        let (token_digest, token_accessor, entity_id) =
            source.control_group_actor_binding(&actor)?;
        let mut candidate = source.clone();
        let approval = candidate.capture_control_group_approval(
            owner,
            Approval {
                entity_id,
                entity_name,
                token_digest,
                token_accessor,
                request_accessor: accessor.to_owned(),
                origin_peer: actor.origin_peer,
                credential: None,
            },
            &actor,
            raw,
            time,
        )?;
        candidate.control_group_authorize(accessor, namespace, time, approval)?;
        let delta = Self::capture(
            source,
            &candidate,
            clock,
            Operation::Authorize {
                actor,
                accessor: accessor.to_owned(),
            },
            Some(namespace),
        )?;
        Ok((delta, candidate))
    }

    #[cfg(test)]
    pub(crate) fn execute(
        source: &AuthState,
        admitted: &AuthState,
        clock: RequestClock,
        caller: Principal,
        requester: Principal,
        raw: &str,
    ) -> Result<(Self, AuthState, DeferredRequest), AuthError> {
        Self::execute_scoped(source, admitted, clock, caller, requester, "", raw)
    }

    pub(crate) fn execute_scoped(
        source: &AuthState,
        admitted: &AuthState,
        clock: RequestClock,
        caller: Principal,
        requester: Principal,
        namespace: &str,
        raw: &str,
    ) -> Result<(Self, AuthState, DeferredRequest), AuthError> {
        Self::bound_actor(&caller, clock)?;
        Self::bound_actor(&requester, clock)?;
        let time = Self::original_time(clock)?;
        // Only real admission's exact consumed-use delta may be transferred
        // into this transaction; a detached modified AuthState is rejected.
        if caller.consumed_use() {
            source.validate_native_consumed_auth_candidate(&caller, admitted, time)?;
        } else if digest(source)? != digest(admitted)? {
            return Err(denied());
        }
        source.authorize_request_observed(
            &caller,
            namespace,
            "sys/wrapping/unwrap",
            "update",
            time,
        )?;
        if caller
            .service_token()
            .is_some_and(|token| token.policies == BTreeSet::from(["control-group".into()]))
            && caller.digest != hash(raw)
        {
            return Err(denied());
        }
        let mut candidate = admitted.clone();
        let owner = candidate.claim_control_group(raw, namespace, time)?;
        let (requester_digest, accessor, entity) =
            source.control_group_actor_binding(&requester)?;
        if requester_digest != owner.actor_digest
            || accessor != owner.actor_accessor
            || entity != owner.actor_entity_id
        {
            return Err(denied());
        }
        let delta = Self::capture(
            source,
            &candidate,
            clock,
            Operation::Execute {
                caller,
                requester,
                owner: Box::new(owner.clone()),
            },
            Some(namespace),
        )?;
        Ok((delta, candidate, owner))
    }

    pub(crate) fn check_source(&self, current: &AuthState) -> Result<(), AuthError> {
        self.deadline
            .check()
            .map_err(|_| err(503, "original control group deadline expired"))?;
        if digest(current)? != self.source_digest {
            return Err(err(503, "native control group Auth source changed"));
        }
        let time = self
            .source
            .control_group_authority_time(Self::original_time(self.clock)?)?;
        let namespace = self.namespace.as_deref().unwrap_or("");
        if matches!(&self.operation, Operation::Observe) != self.namespace.is_none() {
            return Err(denied());
        }
        match &self.operation {
            Operation::Observe => {}
            Operation::Defer(actor) => {
                Self::bound_actor(actor, self.clock)?;
                current.check_principal_observed(actor, namespace, time)?;
            }
            Operation::Authorize { actor, accessor } => {
                Self::bound_actor(actor, self.clock)?;
                current.authorize_request_observed(
                    actor,
                    namespace,
                    "sys/control-group/authorize",
                    "update",
                    time,
                )?;
                current.control_group_by_accessor(accessor, namespace, time)?;
            }
            Operation::Execute {
                caller,
                requester,
                owner,
            } => {
                if owner.namespace != namespace {
                    return Err(denied());
                }
                Self::bound_actor(caller, self.clock)?;
                Self::bound_actor(requester, self.clock)?;
                current.authorize_request_observed(
                    caller,
                    namespace,
                    "sys/wrapping/unwrap",
                    "update",
                    time,
                )?;
                current.authorize_request_parameters_observed(
                    requester,
                    &owner.namespace,
                    &owner.method,
                    &owner.path,
                    &owner.body,
                    time,
                )?;
                current.authorize_request_observed(
                    requester,
                    &owner.namespace,
                    &owner.path,
                    &owner.capability,
                    time,
                )?;
                if owner.requires_sudo {
                    current.authorize_request_observed(
                        requester,
                        &owner.namespace,
                        &owner.path,
                        "sudo",
                        time,
                    )?;
                }
            }
        }
        self.deadline
            .check()
            .map_err(|_| err(503, "original control group deadline expired"))
    }

    pub(crate) fn check_candidate(
        &self,
        source: &AuthState,
        candidate: &AuthState,
    ) -> Result<(), AuthError> {
        self.check_source(source)?;
        candidate.validate_control_group_state()?;
        candidate.validate_control_group_clock_floor(Some(source))?;
        if digest(candidate)? != self.candidate_digest {
            return Err(err(503, "native control group Auth delta changed"));
        }
        self.deadline
            .check()
            .map_err(|_| err(503, "original control group deadline expired"))
    }
}

#[cfg(test)]
#[path = "auth_native_controlgroups_draft_tests.rs"]
mod tests;
