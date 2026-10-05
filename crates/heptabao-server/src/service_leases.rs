//! Service-owned admission for online SSH OTP, internal PKI issuance and their lease projections.
//! Expiry/issuer revocation are reconciled under the same post-ReadIndex state
//! lock, never by an independent authoritative writer.
use super::*;
use std::collections::BTreeSet;

impl Service {
    #[cfg(test)]
    pub(super) fn reconcile_lease_owners(state: &mut State, now: u64) -> Result<bool, Response> {
        Self::reconcile_lease_owners_observed(state, AuthorityTime::Coarse(now))
    }
    pub(super) fn reconcile_lease_owners_observed(
        state: &mut State,
        time: AuthorityTime,
    ) -> Result<bool, Response> {
        // Missing precise authority is not proof of expiry. Reject before any
        // engine clock, owner retirement or CRL mutation on the candidate.
        if time.exact().is_none()
            && (state.has_token_api_precision_state()
                || state.engines.has_kubernetes_opaque_artifact_state())
        {
            return Err(Response::error(503, "trusted token clock is required"));
        }
        let time = state
            .engines
            .kubernetes_artifact_time(time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        let time = time
            .with_seconds_floor(state.engines.lease_clock())
            .map_err(|_| Response::error(503, "trusted token clock is unavailable"))?;
        let clock_changed = state
            .auth
            .observe_token_api_time(time)
            .map_err(|error| Response::error(error.status, &error.message))?;
        let time = state.auth.token_api_observed_time(time);
        let now = time.seconds();
        let owners = state.engines.lease_owners();
        let mut live = BTreeSet::new();
        for (namespace, stored_owner) in owners {
            if let Some(owner) =
                state
                    .auth
                    .resolve_lease_owner_observed(&stored_owner, &namespace, time)
            {
                let active = match owner.entity_id.as_deref() {
                    None => true,
                    Some(id) => state
                        .engines
                        .identity_projection(&namespace, id)
                        .is_ok_and(|projection| !projection.disabled),
                };
                if active {
                    live.insert((namespace, stored_owner));
                }
            }
        }
        let reconciled = state
            .engines
            .reconcile_lease_state_observed(time, &live)
            .map_err(|error| Response::error(error.status, &error.message))?;
        let rebuilt = state
            .engines
            .maintain_local_pki_crl(now)
            .map_err(|error| Response::error(error.status, &error.message))?;
        Ok(clock_changed | reconciled | rebuilt)
    }
    pub(super) fn lease_route(
        state: &mut State,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        time: AuthorityTime,
    ) -> Response {
        let now = time.seconds();
        let run = (|| {
            let public = state.engines.is_ssh_verification(namespace, method, path);
            let mut owner = None;
            if !public {
                let principal =
                    principal.ok_or_else(|| Response::error(403, "missing client token"))?;
                let capability = if method == "LIST" { "list" } else { "update" };
                state
                    .auth
                    .authorize_request_observed(principal, namespace, path, capability, time)
                    .map_err(|e| Response::error(e.status, &e.message))?;
                if path.starts_with("sys/leases/lookup/")
                    || path.starts_with("sys/leases/revoke-prefix/")
                {
                    state
                        .auth
                        .authorize_request_observed(principal, namespace, path, "sudo", time)
                        .map_err(|e| Response::error(e.status, &e.message))?;
                }
                if state.engines.is_lease_service_route(namespace, path) {
                    owner = Some(
                        state
                            .auth
                            .typed_lease_issuer_observed(principal, namespace, time)
                            .map_err(|e| Response::error(e.status, &e.message))?,
                    );
                }
            }
            let mut engines = state.engines.clone();
            let mut response = if path.starts_with("sys/leases/") {
                engines.handle_lease_admin_observed(namespace, method, path, body, time)
            } else if engines.is_pki_issue_route(namespace, path) {
                let owner = owner
                    .as_ref()
                    .ok_or_else(|| Response::error(403, "credential issuer is required"))?;
                engines.handle_service_pki(namespace, method, path, body, owner, now)
            } else {
                engines.handle_service_ssh(namespace, method, path, body, owner.as_ref(), now)
            }
            .map_err(|e| Response::error(e.status, &e.message))?;
            if response.mutated {
                state.engines = engines;
            }
            Ok(Response {
                consistency_index: None,
                status: response.status,
                body: std::mem::take(&mut response.body),
            })
        })();
        run.unwrap_or_else(|error| error)
    }
}
