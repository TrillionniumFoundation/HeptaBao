//! Read-only Raft observations retain the actual native request owner.
//!
//! The route selector and JSON projection grant no consensus or Actor authority.
//! The shared native delivery path authenticates the source graph before this
//! owner calls the actual HA process, then retains the original deadline and
//! Actor through terminal clock publication and mandatory response audit.
use super::*;
use crate::state_record_root_v6::RecordStateRootV6;
use crate::v6_native_custody::OriginalDeadline;

pub(super) fn is_read(method: &str, path: &str) -> bool {
    method == "GET"
        && matches!(
            path,
            "sys/storage/raft/configuration"
                | "sys/storage/raft/snapshot-status"
                | "sys/storage/raft/linearizable-read"
                | "sys/storage/raft/autopilot/state"
                | "sys/storage/raft/autopilot/configuration"
        )
}

fn unavailable() -> Response {
    Response::error(503, "native Raft observation or delivery unavailable")
}

pub(super) struct NativeRaftObservationOwner {
    path: String,
    ha: Arc<Mutex<HaProcess>>,
    source_root: RecordStateRootV6,
    policy: raft_admin::RaftAdminState,
    deadline: OriginalDeadline,
    executed: bool,
}

impl NativeRaftObservationOwner {
    pub(super) fn prepare(
        service: &Service,
        actor: &Principal,
        request: &RequestView<'_>,
    ) -> Result<Self, Response> {
        if !request.namespace.is_empty() || !is_read(request.method, request.path) {
            return Err(unavailable());
        }
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        let source = service.state.as_ref().ok_or_else(unavailable)?;
        // Check both read and sudo before exposing HA configuration, policy,
        // request-shape diagnostics or private native metadata.
        source
            .auth
            .authorize_sudo_request_observed(actor, "", request.path, "read", request.token_time()?)
            .map_err(|error| Response::error(error.status, &error.message))?;
        if request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
            return Err(Response::error(
                501,
                "consensus administration cannot be response-wrapped",
            ));
        }
        let ha = service
            .ha
            .as_ref()
            .ok_or_else(|| Response::error(400, "HA is not enabled"))?
            .clone();
        if !cfg!(feature = "native-v6-ha") {
            return Err(unavailable());
        }
        let object = request
            .body
            .as_object()
            .ok_or_else(|| Response::error(400, "object required"))?;
        if !object.is_empty() {
            return Err(Response::error(400, "read operation has no body fields"));
        }
        let source_root = service
            .native_root
            .as_ref()
            .ok_or_else(unavailable)?
            .clone();
        if !source.raft_admin.is_default() {
            return Err(unavailable());
        }
        deadline.check().map_err(|_| unavailable())?;
        Ok(Self {
            path: request.path.to_owned(),
            ha,
            source_root,
            policy: (*source.raft_admin).clone(),
            deadline,
            executed: false,
        })
    }

    pub(super) fn authorize(
        &self,
        auth: &AuthState,
        actor: &Principal,
        time: AuthorityTime,
    ) -> Result<(), Response> {
        self.deadline.check().map_err(|_| unavailable())?;
        auth.authorize_sudo_request_observed(actor, "", &self.path, "read", time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        self.deadline.check().map_err(|_| unavailable())
    }

    pub(super) fn check_installed(&self, service: &Service) -> Result<(), Response> {
        self.deadline.check().map_err(|_| unavailable())?;
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        let root = service.native_root.as_ref().ok_or_else(unavailable)?;
        if !service
            .ha
            .as_ref()
            .is_some_and(|ha| Arc::ptr_eq(ha, &self.ha))
            || !state.raft_admin.is_default()
            || *state.raft_admin != self.policy
        {
            return Err(unavailable());
        }
        // This operation never changes any business owner. An Auth successor
        // is admitted only by the enclosing delivery's affine terminal-clock
        // receipt and exact checkpoint, never by this data comparison alone.
        native_auth::auth_only_root_change(&self.source_root, root, false)?;
        self.deadline.check().map_err(|_| unavailable())
    }

    #[cfg(feature = "native-v6-ha")]
    pub(super) fn execute(
        &mut self,
        service: &Service,
        candidate: &State,
        source_proof: &native_v6_reader::NativeProof,
    ) -> Result<Response, Response> {
        if std::mem::replace(&mut self.executed, true) {
            return Err(unavailable());
        }
        let _original_deadline =
            crate::request_deadline::RequestDeadlineScope::enter(self.deadline.instant());
        self.check_installed(service)?;
        // A standalone selection or a reconstructed membership index cannot
        // authorize this path. The caller must retain the actual HA proof.
        match source_proof {
            native_v6_reader::NativeProof::Ha(proof) => proof.check_warm(service)?,
            _ => return Err(unavailable()),
        }
        if *candidate.raft_admin != self.policy {
            return Err(unavailable());
        }
        let process = self
            .ha
            .lock_for_request()
            .map_err(|_| Response::error(503, "HA lock unavailable"))?;
        if !process.native_v6_enabled() {
            return Err(unavailable());
        }
        // membership() performs the existing genuine ReadIndex with the
        // original request budget before observing the runtime membership.
        let observation = process
            .membership()
            .map_err(|_| Response::error(503, "current consensus observation unavailable"))?;
        self.deadline.check().map_err(|_| unavailable())?;
        let mut response = service.raft_admin_read_observation_response(
            candidate,
            &observation,
            &self.path,
            |id| process.enrolled(id),
        )?;
        drop(process);
        let checked = self
            .check_installed(service)
            .and_then(|()| source_proof.check_warm(service));
        if let Err(error) = checked {
            erase_json(&mut response.body);
            return Err(error);
        }
        Ok(response)
    }

    #[cfg(not(feature = "native-v6-ha"))]
    pub(super) fn execute(
        &mut self,
        _service: &Service,
        _candidate: &State,
        _source_proof: &native_v6_reader::NativeProof,
    ) -> Result<Response, Response> {
        self.executed = true;
        Err(unavailable())
    }
}

#[cfg(test)]
#[path = "service_native_raft_observation_tests.rs"]
pub(super) mod tests;
