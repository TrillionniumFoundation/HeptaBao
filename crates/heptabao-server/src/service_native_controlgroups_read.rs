//! Controlled GET owns an immutable point read and an Auth-only claim CAS.
//! It never enters the mutable native KV dispatcher or borrows a write target.
use super::*;
use crate::state_record_root_v6::ObjectDomain;

// Only the parent CG executor can move these already admitted actors and the
// exact Auth claim delta here. No bearer reauthentication or cloned Principal.
pub(super) struct ReadExecution {
    pub(super) source: State,
    pub(super) candidate: State,
    pub(super) caller: Principal,
    pub(super) requester: Principal,
    pub(super) owner: DeferredRequest,
    pub(super) binding: NativeCgAuthBinding,
    pub(super) clock: RequestClock,
}

// The root is bounded authenticated graph/owner metadata, never hydrated KV
// values. It pins every non-Auth owner through claim publication and delivery.
pub(super) struct NativeCgReadOwner {
    inner: ordinary_kv_delivery::OrdinaryKvAuthority,
    original_root: RecordStateRootV6,
    deadline: OriginalDeadline,
}

impl NativeCgReadOwner {
    fn capture(
        service: &Service,
        requester: Principal,
        source: &State,
        owner: &DeferredRequest,
        clock: RequestClock,
    ) -> Result<Self, Response> {
        if owner.method != "GET" || owner.capability != "read" {
            return Err(rejected());
        }
        let deadline = OriginalDeadline::capture().map_err(|_| rejected())?;
        let time = source
            .auth
            .control_group_authority_time(
                clock
                    .observed_at()
                    .map(AuthorityTime::Precise)
                    .map_err(|_| rejected())?,
            )
            .map_err(auth_error)?;
        let action = action_view(owner, clock, time);
        let mut read = Self {
            inner: ordinary_kv_delivery::OrdinaryKvAuthority::new(
                requester,
                source,
                &action,
                &service.unseal_nonce,
            )?,
            original_root: service.native_root.as_ref().ok_or_else(rejected)?.clone(),
            deadline,
        };
        read.check_action(source, owner, clock)?;
        Ok(read)
    }

    pub(super) fn check_root(&self, root: &RecordStateRootV6) -> Result<(), Response> {
        self.deadline.check().map_err(|_| rejected())?;
        // None permits the existing bounded Auth/clock projection only. It
        // grants no KV2 graph replacement or Engine metadata normalization.
        admit_root(&self.original_root, root, None)?;
        self.deadline.check().map_err(|_| rejected())
    }

    pub(super) fn check(
        &mut self,
        state: &State,
        auth: &AuthState,
        nonce: &str,
    ) -> Result<(), Response> {
        self.deadline.check().map_err(|_| rejected())?;
        self.inner.check(state, auth, nonce)
    }

    pub(super) fn check_action(
        &mut self,
        state: &State,
        owner: &DeferredRequest,
        clock: RequestClock,
    ) -> Result<(), Response> {
        if owner.method != "GET" || owner.capability != "read" {
            return Err(rejected());
        }
        self.inner.check_native_control_group(state, owner, clock)
    }

    fn dispatch(
        &mut self,
        service: &mut Service,
        source_state: &State,
        owner: &DeferredRequest,
        clock: RequestClock,
    ) -> native_paged_dispatch::NativePagedOutcome {
        use native_paged_dispatch::NativePagedOutcome;
        let run = (|| -> Result<Response, Response> {
            self.check_action(source_state, owner, clock)?;
            let actual_auth = service.state.as_ref().ok_or_else(rejected)?.auth.clone();
            let nonce = service.unseal_nonce.clone();
            self.check(source_state, &actual_auth, &nonce)?;
            let proof = service
                .capture_native_request_proof(&mut || {
                    self.check(source_state, &actual_auth, &nonce)?;
                    self.check_action(source_state, owner, clock)
                })?
                .ok_or_else(rejected)?;
            if proof.identity() != self.original_root.identity().map_err(|_| rejected())? {
                return Err(rejected());
            }
            proof.check_warm(service)?;
            self.check_root(service.native_root.as_ref().ok_or_else(rejected)?)?;
            let time = source_state
                .auth
                .control_group_authority_time(
                    clock
                        .observed_at()
                        .map(AuthorityTime::Precise)
                        .map_err(|_| rejected())?,
                )
                .map_err(auth_error)?;
            let at = Service::kv2_request_timestamp(time)?;
            let observations = Arc::clone(&service.native_payload_observations);
            let source_failed = std::cell::Cell::new(false);
            let durable = service.durable.as_mut().ok_or_else(rejected)?;
            let storage_source =
                native_blob_source::NativeSource::new_checked(durable, self.deadline, || {
                    self.check(source_state, &actual_auth, &nonce)
                        .and_then(|()| self.check_action(source_state, owner, clock))
                        .map_err(|_| ServiceError::BarrierFailure)
                })
                .map_err(|_| rejected())?
                .with_observations(observations);
            // Read the actual admitted immutable source graph. The private
            // claim candidate cannot supply a different value or graph here.
            let result = source_state.engines.read_native_paged(
                &owner.namespace,
                "GET",
                &owner.path,
                &owner.body,
                at,
                |scope, reference| {
                    let payload = storage_source
                        .read_paged_payload(&ObjectDomain::Kv2(scope.clone()), reference);
                    if payload.is_err() {
                        source_failed.set(true);
                    }
                    payload
                },
            );
            drop(storage_source);
            // Preserve the actual typed point-source rejection as admission
            // failure. An Engine HTTP status cannot recast failed custody as a
            // completed domain read and spend the still-unexecuted claim.
            if source_failed.get() {
                return Err(rejected());
            }
            self.check(source_state, &actual_auth, &nonce)?;
            self.check_action(source_state, owner, clock)?;
            proof.check_warm(service)?;
            self.check_root(service.native_root.as_ref().ok_or_else(rejected)?)?;
            Ok(match result {
                Ok(mut response) => Response {
                    status: response.status,
                    body: std::mem::take(&mut response.body),
                    unwrapped_json: None,
                    response_headers: Default::default(),
                    consistency_index: None,
                },
                Err(error) => Response::from_engine_error(error),
            })
        })();
        match run {
            Ok(response) => NativePagedOutcome::Dispatched(response),
            Err(error) => NativePagedOutcome::AdmissionRejected(error),
        }
    }
}

impl Service {
    pub(super) fn execute_native_cg_read(
        &mut self,
        execution: ReadExecution,
        request: &RequestView<'_>,
    ) -> Result<Response, Response> {
        let ReadExecution {
            source,
            mut candidate,
            caller,
            requester,
            owner,
            binding,
            clock,
        } = execution;
        let mut read = NativeCgReadOwner::capture(self, requester, &source, &owner, clock)?;
        let mut response = match read.dispatch(self, &source, &owner, clock) {
            native_paged_dispatch::NativePagedOutcome::AdmissionRejected(error) => {
                return Err(error);
            }
            native_paged_dispatch::NativePagedOutcome::Dispatched(response) => response,
        };
        // A completed read, including a domain 404, spends the approved claim.
        // There is no mutable Engine operation to undo or bless. Both success
        // and domain failure must publish exactly the unchanged original graph.
        candidate.schema = candidate.writer_schema();
        candidate.prepare_global_lossless_json_state(Some(&source))?;
        let original_root = read.original_root.clone();
        let mut delivery = NativeCgDelivery::capture(
            self,
            DeliveryKind::ReadExecute {
                caller,
                read: Box::new(read),
                owner: Box::new(owner),
            },
            clock,
            &response,
        )?;
        let nonce = self.unseal_nonce.clone();
        let mut gate = |auth: &AuthState| {
            binding
                .check_candidate(auth, &candidate.auth)
                .map_err(auth_error)?;
            let DeliveryKind::ReadExecute {
                caller,
                read,
                owner,
            } = &mut delivery.kind
            else {
                return Err(rejected());
            };
            auth.authorize_request_observed(
                caller,
                &owner.namespace,
                "sys/wrapping/unwrap",
                "update",
                request.token_time()?,
            )
            .map_err(auth_error)?;
            read.check(&candidate, auth, &nonce)?;
            read.check_action(&source, owner, clock)
        };
        let plan = self.prepare_native_live_root_checked(&candidate, &mut gate)?;
        admit_root(&original_root, &plan.root, None)?;
        let installed = match self.commit_native_root_plan(
            &candidate,
            plan,
            false,
            "control-group-read-execute",
            &mut gate,
        ) {
            Ok(installed) => installed,
            Err(error) => {
                erase_json(&mut response.body);
                return Err(error);
            }
        };
        self.state = Some(installed);
        delivery.stage(self)?;
        self.pending_native_cg_delivery = Some(delivery);
        Ok(response)
    }
}
