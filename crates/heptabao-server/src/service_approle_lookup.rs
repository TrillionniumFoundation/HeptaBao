//! Borrowed AppRole projections use the existing immutable request/audit/delivery
//! capsule. This module contributes only the actual record and mount read owner.
use super::*;
use crate::auth::approle_lookup::AppRoleSecretLookupOwner;
use std::time::Instant;

fn unavailable() -> Response {
    Response::error(503, "AppRole immutable lookup owner changed")
}
pub(super) struct AppRoleReadOwner {
    record: ha_read::RecordReadIdentity,
    mount: AppRoleSecretLookupOwner,
    leases: namespace_runtime::Leases,
    delivery: namespace_runtime::DeliveryBinding,
    namespace: String,
    ha: Option<Arc<Mutex<HaProcess>>>,
    role: Option<(u64, u64)>,
    barrier: [u8; 32],
    deadline: Option<Instant>,
}
impl AppRoleReadOwner {
    fn capture(service: &Service, request: &RequestView<'_>) -> Result<Self, Response> {
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        let mount = state
            .auth
            .approle_secret_lookup_owner(request.namespace, request.method, request.path)
            .ok_or_else(unavailable)?;
        let role = if let Some(ha) = &service.ha {
            let node = ha.lock_for_request().map_err(|_| unavailable())?;
            let status = node.leader_status().map_err(|_| unavailable())?;
            if !status.local_is_leader || status.leader != Some(status.local_id) {
                return Err(unavailable());
            }
            Some((status.local_id, status.term))
        } else {
            None
        };
        let owner = Self {
            record: ha_read::RecordReadIdentity::capture(service)?,
            mount,
            leases: state.namespace_leases.clone(),
            delivery: namespace_runtime::DeliveryBinding::capture(state, request.namespace),
            namespace: request.namespace.to_owned(),
            ha: service.ha.clone(),
            role,
            barrier: crypto::digest(
                service
                    .barrier_key
                    .as_ref()
                    .ok_or_else(unavailable)?
                    .as_ref(),
            ),
            deadline: crate::request_deadline::current(),
        };
        owner.check(service)?;
        Ok(owner)
    }
    pub(super) fn check_mount(&self, auth: &AuthState) -> Result<(), Response> {
        self.mount
            .check(auth)
            .map_err(|error| Response::error(error.status, &error.message))
    }
    fn check_deadline(&self) -> Result<(), Response> {
        if self.deadline.is_some_and(|value| Instant::now() >= value) {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(super) fn check(&self, service: &Service) -> Result<(), Response> {
        self.check_deadline()?;
        match (&self.ha, &service.ha, self.role) {
            (None, None, None) => (),
            (Some(original), Some(current), Some(expected)) if Arc::ptr_eq(original, current) => {
                let _scope = self
                    .deadline
                    .map(crate::request_deadline::RequestDeadlineScope::enter);
                let node = current.lock_for_request().map_err(|_| unavailable())?;
                let before = node.leader_status().map_err(|_| unavailable())?;
                if !before.local_is_leader
                    || before.leader != Some(before.local_id)
                    || (before.local_id, before.term) != expected
                {
                    return Err(unavailable());
                }
                node.ensure_application_identity(service.current_state_identity()?)
                    .map_err(|_| unavailable())?;
                let after = node.leader_status().map_err(|_| unavailable())?;
                if !after.local_is_leader
                    || after.leader != Some(after.local_id)
                    || (after.local_id, after.term) != expected
                {
                    return Err(unavailable());
                }
            }
            _ => return Err(unavailable()),
        }
        self.record.check(service)?;
        self.leases.validate()?;
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        state.namespace_leases.validate()?;
        if service.recovery_required
            || service.audit_failed
            || service
                .barrier_key
                .as_ref()
                .map(|value| crypto::digest(value.as_ref()))
                != Some(self.barrier)
            || namespace_runtime::DeliveryBinding::capture(state, &self.namespace) != self.delivery
            || state.namespaces.inherited_owner(&self.namespace).is_some()
                && !service.namespace_runtime.is_loaded(&self.namespace)
        {
            return Err(unavailable());
        }
        self.check_mount(&state.auth)?;
        self.check_deadline()
    }
}
impl Service {
    pub(super) fn immutable_approle_lookup_response(
        &mut self,
        request: &RequestView<'_>,
    ) -> Option<Response> {
        let state = self.state.as_ref()?;
        if request.wrap_ttl_seconds.is_some()
            || state.has_token_api_precision_state()
            || state.engines.has_kubernetes_opaque_artifact_state()
            || state.engines.has_lease_state()
            || state.engines.has_local_pki_crl_state()
            || !state.auth.approle_lookup_can_skip_maintenance()
            || !state
                .auth
                .legacy_immutable_token_is_non_consuming(request.token)
            || self.record_root.is_none()
            || state
                .namespaces
                .inherited_owner(request.namespace)
                .is_some()
                && !self.namespace_runtime.is_loaded(request.namespace)
            || state
                .auth
                .approle_secret_lookup_mount(request.namespace, request.method, request.path)
                .is_none()
        {
            return None;
        }
        let time = match request.token_time() {
            Ok(time) => time,
            Err(error) => return Some(error),
        };
        let mut principal = match state.auth.authenticate_read_only_from_observed(
            request.token,
            time,
            request.origin_peer,
        ) {
            Ok(Some(principal)) => principal,
            Ok(None) => return None,
            Err(error) => return Some(Response::error(error.status, &error.message)),
        };
        if let Err(error) = principal.bind_request_clock(request.token_clock) {
            return Some(Response::error(error.status, &error.message));
        }
        if let Err(error) = Self::bind_identity_principal(state, &mut principal, request.namespace)
        {
            return Some(error);
        }
        let owner = match AppRoleReadOwner::capture(self, request) {
            Ok(owner) => owner,
            Err(error) => return Some(error),
        };
        let authority = match ordinary_kv_delivery::OrdinaryKvAuthority::new_approle_lookup(
            principal,
            state,
            request,
            &self.unseal_nonce,
            owner,
        ) {
            Ok(authority) => authority,
            Err(error) => return Some(error),
        };
        let response = match state.auth.handle_approle_secret_lookup_immutable(
            authority.principal(),
            request.namespace,
            request.method,
            request.path,
            request.body,
            time,
        ) {
            Ok(Some(mut result)) => Response {
                response_headers: Default::default(),
                consistency_index: None,
                status: result.status,
                body: std::mem::take(&mut result.body),
            },
            Ok(None) => return Some(unavailable()),
            Err(error) => Response::error(error.status, &error.message),
        };
        self.pending_ordinary_kv_authority = Some(authority);
        Some(response)
    }
    pub(super) fn check_pending_approle_lookup_before_audit(&mut self) -> Result<(), Response> {
        let Some(mut authority) = self.pending_ordinary_kv_authority.take() else {
            return Ok(());
        };
        let result = if authority.is_approle_lookup() {
            authority.check_private_read_owner(self).and_then(|()| {
                let state = self.state.as_ref().ok_or_else(unavailable)?;
                authority.check(state, &state.auth, &self.unseal_nonce)
            })
        } else {
            Ok(())
        };
        self.pending_ordinary_kv_authority = Some(authority);
        result
    }
}
#[cfg(test)]
#[path = "service_approle_lookup_tests.rs"]
mod tests;
