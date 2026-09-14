//! Service-owned admission for online SSH OTP and its local lease projection.
//! Expiry/issuer revocation are reconciled under the same post-ReadIndex state
//! lock, never by an independent authoritative writer.
use super::*;
use std::collections::BTreeSet;

impl Service {
    pub(super) fn reconcile_lease_owners(state: &mut State, now: u64) -> bool {
        let owners = state.engines.lease_owners();
        let mut live = BTreeSet::new();
        for (namespace, digest) in owners {
            if let Some(owner) = state.auth.lease_issuer_by_digest(&digest, &namespace, now) {
                let active = match owner.entity_id.as_deref() {
                    None => true,
                    Some(id) => state
                        .engines
                        .identity_projection(&namespace, id)
                        .is_ok_and(|projection| !projection.disabled),
                };
                if active {
                    live.insert((namespace, digest));
                }
            }
        }
        state.engines.reconcile_lease_state(now, &live)
    }
    pub(super) fn lease_route(
        state: &mut State,
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Response {
        let run = (|| {
            let public = state.engines.is_ssh_verification(namespace, method, path);
            let mut owner = None;
            if !public {
                let principal =
                    principal.ok_or_else(|| Response::error(403, "missing client token"))?;
                let capability = if method == "LIST" { "list" } else { "update" };
                state
                    .auth
                    .authorize_request(principal, namespace, path, capability, now)
                    .map_err(|e| Response::error(e.status, &e.message))?;
                if path.starts_with("sys/leases/lookup/")
                    || path.starts_with("sys/leases/revoke-prefix/")
                {
                    state
                        .auth
                        .authorize_request(principal, namespace, path, "sudo", now)
                        .map_err(|e| Response::error(e.status, &e.message))?;
                }
                if state.engines.is_ssh_service_route(namespace, path) {
                    owner = Some(
                        state
                            .auth
                            .lease_issuer(principal, namespace, now)
                            .map_err(|e| Response::error(e.status, &e.message))?,
                    );
                }
            }
            let mut engines = state.engines.clone();
            let mut response = if path.starts_with("sys/leases/") {
                engines.handle_lease_admin(namespace, method, path, body, now)
            } else {
                engines.handle_service_ssh(namespace, method, path, body, owner.as_ref(), now)
            }
            .map_err(|e| Response::error(e.status, &e.message))?;
            if response.mutated {
                state.engines = engines;
            }
            Ok(Response {
                status: response.status,
                body: std::mem::take(&mut response.body),
            })
        })();
        run.unwrap_or_else(|error| error)
    }
}
