//! Native output composition keeps the original ordinary KV authority. This
//! companion owns only actual source/output/checkpoint proof; it cannot mint an
//! Actor, select a resource route, reexecute a dispatcher or publish a root.
use super::*;
use crate::v6_native_custody::OriginalDeadline;

type Checkpoint = (
    crate::state_record_root::StateIdentity,
    plugin::PublicationGeneration,
);

fn rejected() -> Response {
    Response::error(503, "native KV response wrapping custody unavailable")
}

pub(super) struct NativeWrappedKvDelivery {
    output: crate::auth::NativeResponseWrappingOwner,
    source: State,
    deadline: OriginalDeadline,
    activation: String,
    data_dir: PathBuf,
    ha: Option<Arc<Mutex<HaProcess>>>,
    source_proof: Option<native_v6_reader::NativeProof>,
    checkpoint: Option<Checkpoint>,
    generation: Option<u64>,
    proof: Option<native_v6_reader::NativeProof>,
}

impl NativeWrappedKvDelivery {
    pub(super) fn prepare(
        service: &mut Service,
        authority: &mut ordinary_kv_delivery::OrdinaryKvAuthority,
        source: &State,
        request: &RequestView<'_>,
    ) -> Result<Self, Response> {
        let ttl = request
            .wrap_ttl_seconds
            .filter(|ttl| *ttl > 0)
            .ok_or_else(rejected)?;
        let clock = request.token_clock.ok_or_else(rejected)?;
        let deadline = OriginalDeadline::capture().map_err(|_| rejected())?;
        if service.native_root.is_none()
            || !request.namespace.is_empty()
            || source
                .engines
                .ordinary_kv_mount_binding(request.namespace, request.path)
                .is_none()
            || service.pending_native_auth_delivery.is_some()
            || service.pending_native_cg_delivery.is_some()
        {
            return Err(rejected());
        }
        let output = crate::auth::NativeResponseWrappingOwner::prepare(
            &source.auth,
            request.namespace,
            request.path,
            ttl,
            clock,
        )
        .map_err(|error| Response::error(error.status, &error.message))?;
        let mut owner = Self {
            output,
            source: source.clone(),
            deadline,
            activation: service.unseal_nonce.clone(),
            data_dir: service.data_dir.clone(),
            ha: service.ha.clone(),
            source_proof: None,
            checkpoint: None,
            generation: None,
            proof: None,
        };
        owner.check_environment(service)?;
        owner.check_source(authority)?;
        let proof = service
            .capture_native_request_proof(&mut || owner.check_source(authority))?
            .ok_or_else(rejected)?;
        proof.check_warm(service)?;
        owner.source_proof = Some(proof);
        Ok(owner)
    }

    fn check_environment(&self, service: &mut Service) -> Result<(), Response> {
        self.deadline.check().map_err(|_| rejected())?;
        if service.recovery_required
            || service.audit_failed
            || service.unseal_nonce != self.activation
            || service.data_dir != self.data_dir
            || service.native_root.is_none()
            || service
                .state
                .as_ref()
                .is_none_or(|state| state.cluster_id != self.source.cluster_id)
        {
            return Err(rejected());
        }
        match (&self.ha, &service.ha) {
            (None, None) => {}
            #[cfg(feature = "native-v6-ha")]
            (Some(original), Some(current)) if Arc::ptr_eq(original, current) => {}
            _ => return Err(rejected()),
        }
        let durable = service.durable.as_mut().ok_or_else(rejected)?;
        durable.verify_live_ownership().map_err(|_| rejected())?;
        if self
            .generation
            .is_some_and(|generation| durable.generation() != generation)
        {
            return Err(rejected());
        }
        self.deadline.check().map_err(|_| rejected())
    }

    fn check_source(
        &self,
        authority: &mut ordinary_kv_delivery::OrdinaryKvAuthority,
    ) -> Result<(), Response> {
        self.output
            .check_source(&self.source.auth)
            .map_err(|error| Response::error(error.status, &error.message))?;
        authority.check(&self.source, &self.source.auth, &self.activation)
    }

    pub(super) fn admit_candidate(&self, candidate: &State) -> Result<(), Response> {
        self.output
            .admit_candidate(&candidate.auth)
            .map_err(|error| Response::error(error.status, &error.message))
    }

    pub(super) fn check_publish_source(
        &self,
        candidate: &State,
        actual_auth: &AuthState,
    ) -> Result<(), Response> {
        if self.checkpoint.is_some()
            || self.generation.is_some()
            || self.proof.is_some()
            || self.source_proof.is_none()
        {
            return Err(rejected());
        }
        self.output
            .check_source(actual_auth)
            .map_err(|error| Response::error(error.status, &error.message))?;
        self.admit_candidate(candidate)
    }

    fn compose(
        &mut self,
        service: &mut Service,
        authority: &mut ordinary_kv_delivery::OrdinaryKvAuthority,
        mut candidate: State,
        rollback: State,
        response: Response,
    ) -> Result<(State, Response), Response> {
        self.check_environment(service)?;
        self.source_proof
            .as_ref()
            .ok_or_else(rejected)?
            .check_warm(service)?;
        self.check_source(authority)?;
        authority.check(&candidate, &self.source.auth, &self.activation)?;
        // This is the original KV observation, before the output Auth capsule
        // binds its exact candidate. The terminal writer retains later time.
        authority.observe_candidate(&mut candidate)?;
        let response = self
            .output
            .compose(&mut candidate.auth, response)
            .map_err(|error| Response::error(error.status, &error.message))?;
        if self.output.construction_failed() {
            candidate = rollback;
            self.output
                .bind_failure_rollback(&self.source.auth, &mut candidate.auth, None)
                .map_err(|error| Response::error(error.status, &error.message))?;
            // KV has no authenticated SecretID transition. Earlier actual
            // finite-token admission is already part of this rollback source.
        }
        self.admit_candidate(&candidate)?;
        self.check_source(authority)?;
        Ok((candidate, response))
    }

    fn checkpoint(service: &Service) -> Result<Checkpoint, Response> {
        let identity = service.current_state_identity()?;
        if !matches!(
            identity,
            crate::state_record_root::StateIdentity::RecordsV6(_)
        ) {
            return Err(rejected());
        }
        Ok((identity, service.external_effect_generation()?))
    }

    fn stage_publication(
        &mut self,
        service: &mut Service,
        authority: &mut ordinary_kv_delivery::OrdinaryKvAuthority,
    ) -> Result<(), Response> {
        if self.checkpoint.is_some()
            || self.generation.is_some()
            || self.proof.is_some()
            || self.source_proof.take().is_none()
        {
            return Err(rejected());
        }
        self.check_source(authority)?;
        self.check_environment(service)?;
        self.output
            .check_current_auth(&service.state.as_ref().ok_or_else(rejected)?.auth)
            .map_err(|error| Response::error(error.status, &error.message))?;
        self.generation = Some(service.durable.as_ref().ok_or_else(rejected)?.generation());
        self.checkpoint = Some(Self::checkpoint(service)?);
        self.check_checkpoint(service, authority)
    }

    fn check_checkpoint(
        &self,
        service: &mut Service,
        authority: &mut ordinary_kv_delivery::OrdinaryKvAuthority,
    ) -> Result<(), Response> {
        self.check_environment(service)?;
        self.check_source(authority)?;
        if self.source_proof.is_some()
            || self.generation.is_none()
            || self.checkpoint.as_ref() != Some(&Self::checkpoint(service)?)
        {
            return Err(rejected());
        }
        Ok(())
    }

    fn bind_after_terminal(
        &mut self,
        service: &mut Service,
        authority: &mut ordinary_kv_delivery::OrdinaryKvAuthority,
        receipt: Option<token_precision::TerminalClockReceipt>,
    ) -> Result<(), Response> {
        if self.proof.is_some() || self.checkpoint.is_none() || self.source_proof.is_some() {
            return Err(rejected());
        }
        self.check_source(authority)?;
        if let Some(receipt) = receipt {
            receipt.advance_native_response_wrapping(&mut self.checkpoint)?;
            if self.checkpoint.as_ref() != Some(&Self::checkpoint(service)?) {
                return Err(rejected());
            }
            self.generation = Some(service.durable.as_ref().ok_or_else(rejected)?.generation());
        }
        self.check_checkpoint(service, authority)?;
        let proof = service
            .capture_native_request_proof(&mut || self.check_source(authority))?
            .ok_or_else(rejected)?;
        let valid_kind = match (&self.ha, &proof) {
            (None, native_v6_reader::NativeProof::Single(_)) => true,
            #[cfg(feature = "native-v6-ha")]
            (Some(_), native_v6_reader::NativeProof::Ha(_)) => true,
            _ => false,
        };
        if !valid_kind || Some(proof.generation()) != self.generation {
            return Err(rejected());
        }
        self.proof = Some(proof);
        self.check_checkpoint(service, authority)
    }

    pub(super) fn check_delivery(
        &self,
        service: &mut Service,
        authority: &mut ordinary_kv_delivery::OrdinaryKvAuthority,
        response: &Response,
    ) -> Result<(), Response> {
        self.output
            .check_reply(response)
            .map_err(|error| Response::error(error.status, &error.message))?;
        self.check_checkpoint(service, authority)?;
        let proof = self.proof.as_ref().ok_or_else(rejected)?;
        proof.check_warm(service)?;
        proof.check_with(service, |installed, metadata, native, root, deadline| {
            Service::check_native_installed(installed, metadata, native, root, deadline)?;
            self.check_source(authority)?;
            authority.check(installed, &metadata.auth, &self.activation)?;
            self.output
                .check_current_auth(&metadata.auth)
                .map_err(|error| Response::error(error.status, &error.message))
        })?;
        self.check_checkpoint(service, authority)?;
        let current = service.state.as_ref().ok_or_else(rejected)?;
        authority.check(current, &current.auth, &self.activation)?;
        self.output
            .check_current_auth(&current.auth)
            .map_err(|error| Response::error(error.status, &error.message))?;
        self.deadline.check().map_err(|_| rejected())
    }
}

impl Service {
    pub(super) fn compose_native_wrapped_kv_output(
        &mut self,
        mut owner: NativeWrappedKvDelivery,
        candidate: State,
        rollback: State,
        response: Response,
    ) -> Result<(State, Response), Response> {
        let mut authority = self
            .pending_ordinary_kv_authority
            .take()
            .ok_or_else(rejected)?;
        let result = if authority.native_response_wrapping.is_some() {
            Err(rejected())
        } else {
            owner.compose(self, &mut authority, candidate, rollback, response)
        };
        if result.is_ok() {
            authority.native_response_wrapping = Some(Box::new(owner));
        }
        self.pending_ordinary_kv_authority = Some(authority);
        result
    }

    pub(super) fn stage_pending_native_wrapped_kv(&mut self) -> Result<(), Response> {
        let Some(mut authority) = self.pending_ordinary_kv_authority.take() else {
            return Ok(());
        };
        let result = if let Some(mut owner) = authority.native_response_wrapping.take() {
            let result = owner.stage_publication(self, &mut authority);
            authority.native_response_wrapping = Some(owner);
            result
        } else {
            Ok(())
        };
        self.pending_ordinary_kv_authority = Some(authority);
        result
    }

    pub(super) fn native_wrapped_kv_terminal_deadline(&self) -> Option<Instant> {
        self.pending_ordinary_kv_authority
            .as_ref()
            .and_then(|authority| authority.native_response_wrapping.as_ref())
            .map(|owner| owner.deadline.instant())
    }

    pub(super) fn check_pending_native_wrapped_kv_before_terminal(
        &mut self,
    ) -> Result<(), Response> {
        let Some(mut authority) = self.pending_ordinary_kv_authority.take() else {
            return Ok(());
        };
        let result = if let Some(owner) = authority.native_response_wrapping.take() {
            let result = if owner.proof.is_some()
                || self.pending_forward_delivery.is_some()
                || self.pending_native_auth_delivery.is_some()
                || self.pending_native_cg_delivery.is_some()
            {
                Err(rejected())
            } else {
                owner.check_checkpoint(self, &mut authority)
            };
            authority.native_response_wrapping = Some(owner);
            result
        } else {
            Ok(())
        };
        self.pending_ordinary_kv_authority = Some(authority);
        result
    }

    pub(super) fn bind_pending_native_wrapped_kv_before_audit(
        &mut self,
        receipt: Option<token_precision::TerminalClockReceipt>,
    ) -> Result<(), Response> {
        let mut authority = self
            .pending_ordinary_kv_authority
            .take()
            .ok_or_else(rejected)?;
        let result = if let Some(mut owner) = authority.native_response_wrapping.take() {
            let result = owner.bind_after_terminal(self, &mut authority, receipt);
            authority.native_response_wrapping = Some(owner);
            result
        } else {
            Err(rejected())
        };
        self.pending_ordinary_kv_authority = Some(authority);
        result
    }
}
