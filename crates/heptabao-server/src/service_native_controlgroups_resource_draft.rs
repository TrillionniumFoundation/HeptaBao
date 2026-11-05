//! Live resource/quorum gate for the native CG draft.
//!
//! The actual old Service dispatcher supplies synthetic setup and approvals in
//! these component tests. They prove the preserved policy/Identity/resource
//! contract, not native publication, HTTP compatibility or cold V6 ownership.
use super::*;
use crate::v6_native_custody::OriginalDeadline;
use std::time::{Duration, Instant};

// Retain the existing domain-recovered requester exactly once. No Clone,
// public fields, serde, detached policy grant, or reconstructed Principal.
struct NativeCgResourceGate {
    owner: DeferredRequest,
    requester: Principal,
    clock: RequestClock,
    deadline: OriginalDeadline,
}

impl NativeCgResourceGate {
    fn capture(
        state: &State,
        owner: DeferredRequest,
        requester: Principal,
        clock: RequestClock,
    ) -> Result<Self, Response> {
        let deadline = OriginalDeadline::capture()
            .map_err(|_| Response::error(503, "original control group deadline absent"))?;
        if !owner.namespace.is_empty()
            || owner.namespace_id != "root"
            || owner.namespace_incarnation != 0
            || owner.logical_data.is_some()
            || owner.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0)
            || owner.transport_namespace != owner.namespace
            || owner.transport_method != owner.method
            || owner.transport_path != owner.path
            || owner.transport_body != owner.body
        {
            return Err(Response::error(
                501,
                "native controlled action profile unsupported",
            ));
        }
        let ResourceBinding::Secret { owner: mount } = &owner.resource_binding else {
            return Err(Response::error(
                501,
                "native controlled target is not an ordinary KV mount",
            ));
        };
        if !mount.is_kv(&owner.path) || !owner.path.starts_with(&format!("{}data/", mount.path)) {
            return Err(Response::error(
                501,
                "native controlled action requires a KV data operation",
            ));
        }
        let original = requester
            .original_request_clock()
            .ok_or_else(|| Response::error(503, "original requester clock absent"))?;
        if original.started() != clock.started() || original.admitted_at() != clock.admitted_at() {
            return Err(Response::error(503, "original requester clock changed"));
        }
        let mut gate = Self {
            owner,
            requester,
            clock,
            deadline,
        };
        gate.check(state)?;
        Ok(gate)
    }

    fn check(&mut self, state: &State) -> Result<(), Response> {
        self.deadline
            .check()
            .map_err(|_| Response::error(503, "original control group deadline expired"))?;
        Service::validate_control_group_scope(state, &self.owner)?;
        let time = state
            .auth
            .control_group_authority_time(
                self.clock
                    .observed_at()
                    .map(AuthorityTime::Precise)
                    .map_err(|_| {
                        Response::error(503, "original control group clock unavailable")
                    })?,
            )
            .map_err(auth_error)?;
        let (digest, accessor, entity_id) = state
            .auth
            .control_group_actor_binding(&self.requester)
            .map_err(auth_error)?;
        if digest != self.owner.actor_digest
            || accessor != self.owner.actor_accessor
            || entity_id != self.owner.actor_entity_id
        {
            return Err(Response::error(403, "original requester ownership changed"));
        }
        // A stale Principal's Identity projection cannot supply a newer grant.
        // Check live request entity and live policy/factors/quorum separately.
        Service::bind_identity_principal(state, &mut self.requester, "")?;
        let identity = entity(state, "", &entity_id)?;
        if identity != self.owner.actor_entity {
            return Err(Response::error(403, "original requester identity changed"));
        }
        let action = RequestView {
            method: &self.owner.method,
            path: &self.owner.path,
            namespace: "",
            token: "",
            body: &self.owner.body,
            now: time.seconds(),
            admission_started: self.clock.started(),
            token_clock: Some(self.clock),
            allow_forward: false,
            enforce_namespace: true,
            wrap_ttl_seconds: None,
            origin_peer: self.owner.origin_peer,
            client_certificates: self.owner.client_certificates.as_deref(),
        };
        authorize_action(
            state,
            &self.requester,
            &action,
            &self.owner.capability,
            self.owner.requires_sudo,
            time,
        )?;
        let (policy, sudo) = selected_policy(state, &self.requester, &action, time)?
            .ok_or_else(|| Response::error(403, "controlled policy no longer selected"))?;
        if sudo != self.owner.requires_sudo
            || policy.duration().map_err(auth_error)?
                != self.owner.duration().map_err(auth_error)?
            || resolved_factors(state, "", &policy)? != self.owner.factors
            || capability(state, &action) != self.owner.capability
            || !approved(state, &self.owner, time)
        {
            return Err(Response::error(
                403,
                "controlled policy or live quorum changed",
            ));
        }
        self.deadline
            .check()
            .map_err(|_| Response::error(503, "original control group deadline expired"))
    }
}

fn capture(
    f: &Fixture,
    accessor: &str,
) -> Result<NativeCgResourceGate, Box<dyn std::error::Error>> {
    let state = f.service.state.as_ref().ok_or("state")?;
    let clock = RequestClock::anchored(Duration::from_secs(100), Instant::now())?;
    let time = AuthorityTime::Precise(clock.observed_at()?);
    let owner = state
        .auth
        .control_group_by_accessor(accessor, "", time)?
        .clone();
    // This is the original existing authenticated deferred-credential recovery
    // operation, not Principal construction in the new Service owner.
    let mut requester = state.auth.control_group_actor(&owner, time)?;
    requester.bind_request_clock(Some(clock))?;
    Service::bind_identity_principal(state, &mut requester, "").map_err(|_| "identity")?;
    NativeCgResourceGate::capture(state, owner, requester, clock)
        .map_err(|_| "resource gate".into())
}

fn approved_fixture() -> TestResult<(Fixture, String)> {
    let mut f = setup()?;
    create(&mut f);
    let (_, accessor) = pending(&mut f)?;
    approve_two(&mut f, &accessor);
    Ok((f, accessor))
}

#[test]
fn native_cg_resource_gate_requires_actual_quorum_and_preserves_target_until_execution()
-> TestResult {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let mut f = setup()?;
    create(&mut f);
    let (_, accessor) = pending(&mut f)?;
    assert!(capture(&f, &accessor).is_err());
    approve_two(&mut f, &accessor);
    let mut gate = capture(&f, &accessor)?;
    gate.check(f.service.state.as_ref().ok_or("state")?)
        .map_err(|_| "gate")?;
    read(&mut f, 1, "before", 100);
    Ok(())
}

#[test]
fn native_cg_resource_gate_rechecks_live_identity_membership_and_policy() -> TestResult {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let (mut f, accessor) = approved_fixture()?;
    let mut gate = capture(&f, &accessor)?;
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "POST",
            &format!("identity/group/id/{}", f.group),
            json!({"member_entity_ids":[f.requester.entity,f.first.entity]}),
            100
        )
        .status,
        204
    );
    assert!(
        gate.check(f.service.state.as_ref().ok_or("state")?)
            .is_err()
    );
    let (mut f, accessor) = approved_fixture()?;
    let mut gate = capture(&f, &accessor)?;
    policy_write(
        &mut f.service,
        &f.admin,
        "cg-requester",
        &requester_policy("30s", ""),
    );
    assert!(
        gate.check(f.service.state.as_ref().ok_or("state")?)
            .is_err()
    );
    Ok(())
}

#[test]
fn native_cg_resource_gate_rechecks_original_requester_revocation_and_mount_incarnation()
-> TestResult {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let (mut f, accessor) = approved_fixture()?;
    let mut gate = capture(&f, &accessor)?;
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "POST",
            "auth/token/revoke",
            json!({"token":f.requester.token.as_str()}),
            100
        )
        .status,
        204
    );
    assert!(
        gate.check(f.service.state.as_ref().ok_or("state")?)
            .is_err()
    );
    let (mut f, accessor) = approved_fixture()?;
    let mut gate = capture(&f, &accessor)?;
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "DELETE",
            "sys/mounts/secret",
            json!({}),
            100
        )
        .status,
        204
    );
    assert_eq!(
        call(
            &mut f.service,
            &f.admin,
            "POST",
            "sys/mounts/secret",
            json!({"type":"kv","options":{"version":"2"}}),
            100
        )
        .status,
        204
    );
    assert!(
        gate.check(f.service.state.as_ref().ok_or("state")?)
            .is_err()
    );
    Ok(())
}

#[test]
fn native_cg_resource_gate_rejects_shorter_deadline_and_altered_transport() -> TestResult {
    let _deadline = crate::request_deadline::RequestDeadlineScope::enter(
        Instant::now() + Duration::from_secs(15),
    );
    let (f, accessor) = approved_fixture()?;
    let mut gate = capture(&f, &accessor)?;
    {
        let _shorter = crate::request_deadline::RequestDeadlineScope::enter(Instant::now());
        assert!(
            gate.check(f.service.state.as_ref().ok_or("state")?)
                .is_err()
        );
    }
    let state = f.service.state.as_ref().ok_or("state")?;
    let clock = RequestClock::anchored(Duration::from_secs(100), Instant::now())?;
    let time = AuthorityTime::Precise(clock.observed_at()?);
    let mut owner = state
        .auth
        .control_group_by_accessor(&accessor, "", time)?
        .clone();
    let mut requester = state.auth.control_group_actor(&owner, time)?;
    requester.bind_request_clock(Some(clock))?;
    Service::bind_identity_principal(state, &mut requester, "").map_err(|_| "identity")?;
    owner.transport_namespace = "foreign".into();
    assert!(NativeCgResourceGate::capture(state, owner, requester, clock).is_err());
    Ok(())
}
