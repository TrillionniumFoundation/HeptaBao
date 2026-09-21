//! Service-owned OpenLDAP dynamic credential effects.
//!
//! The engine state is committed before LDAPS I/O.  The provider operation runs
//! without the Service writer and the finalizer revalidates the durable intent
//! before publishing credentials or removing a lease.  The bounded profile uses
//! a persistent LDAP tombstone on revoke so a delayed old Add cannot recreate a
//! credential at the same DN.

use super::*;
use crate::{engines::openldap, outbound::Outbound};
use std::{collections::BTreeSet, sync::Weak};

pub(super) struct OpenLdapEffectPlan {
    pub(super) inner: openldap::EffectPlan,
    outbound: Outbound,
    ha: Option<Arc<Mutex<HaProcess>>>,
    _in_flight: Arc<()>,
}

#[derive(Default)]
pub(super) struct OpenLdapFlights {
    leases: BTreeMap<(String, String, String), Weak<()>>,
}
impl OpenLdapFlights {
    fn contains(&self, namespace: &str, mount: &str, id: &str) -> bool {
        self.leases
            .get(&(namespace.into(), mount.into(), id.into()))
            .is_some_and(|flight| flight.strong_count() != 0)
    }
    fn track(&mut self, plan: &openldap::EffectPlan) -> Arc<()> {
        self.leases.retain(|_, flight| flight.strong_count() != 0);
        let key = (
            plan.namespace.clone(),
            plan.mount.clone(),
            plan.lease_id.clone(),
        );
        let flight = Arc::new(());
        self.leases.insert(key, Arc::downgrade(&flight));
        flight
    }
}

pub(super) struct OpenLdapMaintenance {
    pub(super) fingerprint: String,
    pub(super) now: u64,
    pub(super) plan: OpenLdapEffectPlan,
}

impl OpenLdapEffectPlan {
    pub(super) fn new(
        inner: openldap::EffectPlan,
        outbound: Outbound,
        ha: Option<Arc<Mutex<HaProcess>>>,
        in_flight: Arc<()>,
    ) -> Self {
        Self {
            inner,
            outbound,
            ha,
            _in_flight: in_flight,
        }
    }

    pub(super) fn execute(&self) -> Result<(), Response> {
        let result = match self.inner.action {
            openldap::EffectAction::Issue => {
                let entry = self
                    .inner
                    .entry
                    .as_ref()
                    .ok_or_else(|| openldap_outcome_unknown(&self.inner.lease_id))?;
                self.outbound
                    .ldap_dynamic_add(
                        &self.inner.provider_url,
                        &self.inner.bind_dn,
                        self.inner.bind_password.expose(),
                        &entry.dn,
                        &entry.attributes,
                        self.inner.password.expose(),
                    )
                    .map_err(|_| openldap_outcome_unknown(&self.inner.lease_id))
            }
            openldap::EffectAction::Revoke => self
                .outbound
                .ldap_dynamic_tombstone(
                    &self.inner.provider_url,
                    &self.inner.bind_dn,
                    self.inner.bind_password.expose(),
                    &self.inner.dn,
                    self.inner.password.expose(),
                    &self.inner.request_digest,
                    &self.inner.original_attributes,
                )
                .map_err(|_| openldap_outcome_unknown(&self.inner.lease_id)),
        };
        result?;
        if let Some(ha) = &self.ha
            && ha
                .lock_for_request()
                .map_err(|_| openldap_outcome_unknown(&self.inner.lease_id))
                .and_then(|ha| {
                    ha.ensure_linearizable()
                        .map_err(|_| openldap_outcome_unknown(&self.inner.lease_id))
                })
                .is_err()
        {
            return Err(openldap_outcome_unknown(&self.inner.lease_id));
        }
        Ok(())
    }
}

fn openldap_outcome_unknown(lease_id: &str) -> Response {
    Response {
        status: 503,
        body: json!({
            "errors":["OpenLDAP provider outcome is unknown; durable intent retained"],
            "lease_id":lease_id,
            "reconcile_required":true,
            "retry_allowed":false
        }),
    }
}

impl Service {
    pub(super) fn prepare_openldap_maintenance(
        &mut self,
        now: u64,
    ) -> Result<Option<OpenLdapMaintenance>, &'static str> {
        if self.state.is_none() || self.recovery_required || self.audit_failed {
            return Ok(None);
        }
        if self.pending_openldap_effect.is_some() {
            return Ok(None);
        }
        if let Some(ha) = &self.ha {
            let ha = ha
                .lock_for_request()
                .map_err(|_| "OpenLDAP HA lock unavailable")?;
            if !ha.is_leader().map_err(|_| "OpenLDAP leader unavailable")? {
                return Ok(None);
            }
            drop(ha);
            self.sync_from_ha()
                .map_err(|_| "OpenLDAP ReadIndex unavailable")?;
        }
        let current = self.state.as_ref().ok_or("sealed")?;
        let now = now.max(current.engines.lease_clock());
        let mut live = BTreeSet::new();
        for (namespace, digest) in current.engines.lease_owners() {
            if current
                .auth
                .lease_issuer_by_digest(&digest, &namespace, now)
                .is_some_and(|owner| {
                    owner.entity_id.as_deref().is_none_or(|id| {
                        current
                            .engines
                            .identity_projection(&namespace, id)
                            .is_ok_and(|projection| !projection.disabled)
                    })
                })
            {
                live.insert((namespace, digest));
            }
        }
        let candidates = current.engines.openldap_reconcile_candidates(now, &live);
        let candidates: Vec<_> = candidates
            .into_iter()
            .filter(|(ns, mount, id, _)| !self.openldap_in_flight.contains(ns, mount, id))
            .collect();
        let selected = candidates
            .iter()
            .find(|(ns, mount, id, _)| {
                self.openldap_cursor
                    .as_ref()
                    .is_none_or(|last| &(ns.clone(), mount.clone(), id.clone()) > last)
            })
            .or_else(|| candidates.first())
            .cloned();
        let Some((namespace, mount, lease_id, force_revoke)) = selected else {
            return Ok(None);
        };
        self.openldap_cursor = Some((namespace.clone(), mount.clone(), lease_id.clone()));
        let mut next = current.clone();
        let plan = next
            .engines
            .openldap_prepare_effect(&namespace, &mount, &lease_id, now, force_revoke)
            .map_err(|_| "cannot reconstruct OpenLDAP provider intent")?;
        next.schema = CURRENT_STATE_SCHEMA;
        next.validate_format()
            .map_err(|_| "OpenLDAP maintenance state validation failed")?;
        let fingerprint =
            self.request_fingerprint("INTERNAL", "openldap/reconcile", &namespace, "");
        self.audit_event("provider-request", &fingerprint, now, None)
            .map_err(|_| "OpenLDAP provider audit unavailable")?;
        self.commit_state(&next)
            .map_err(|_| "OpenLDAP provider intent commit failed")?;
        self.state = Some(next);
        let in_flight = self.openldap_in_flight.track(&plan);
        self.pending_openldap_effect = Some(OpenLdapEffectPlan::new(
            plan,
            self.outbound.clone(),
            self.ha.clone(),
            in_flight,
        ));
        let plan = self
            .pending_openldap_effect
            .take()
            .ok_or("OpenLDAP provider plan unavailable")?;
        Ok(Some(OpenLdapMaintenance {
            fingerprint,
            now,
            plan,
        }))
    }

    pub(super) fn finish_openldap_maintenance(
        &mut self,
        pending: OpenLdapMaintenance,
        provider_result: Result<(), Response>,
    ) -> Result<bool, &'static str> {
        let response = self.finalize_openldap_effect(&pending.plan, provider_result);
        let completed = response.status < 300;
        self.audit_event(
            "provider-response",
            &pending.fingerprint,
            pending.now,
            Some(response.status),
        )
        .map_err(|_| "OpenLDAP provider response audit unavailable")?;
        if !completed {
            return Err("OpenLDAP provider remains indeterminate");
        }
        Ok(true)
    }

    pub(super) fn openldap_handles(
        state: &State,
        namespace: &str,
        path: &str,
        body: &Value,
    ) -> bool {
        if state.engines.openldap_mount(namespace, path).is_some()
            || state
                .engines
                .openldap_lease_mount(namespace, path)
                .is_some()
        {
            return true;
        }
        if path.starts_with("sys/leases/") {
            let id = body
                .get("lease_id")
                .and_then(Value::as_str)
                .or_else(|| path.strip_prefix("sys/leases/revoke/"))
                .or_else(|| path.strip_prefix("sys/leases/renew/"));
            return id
                .is_some_and(|id| state.engines.openldap_lease_mount(namespace, id).is_some());
        }
        false
    }

    pub(super) fn openldap_route(
        &mut self,
        mut state: State,
        principal: Option<&Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        let capability = match request.method {
            "GET" | "HEAD" => "read",
            "LIST" => "list",
            "DELETE" => "delete",
            _ => "update",
        };
        let sudo = request.path.starts_with("sys/")
            || request.path.contains("/config")
            || request.path.contains("/role");
        let authorization = if sudo {
            state.auth.authorize_sudo_request(
                principal,
                request.namespace,
                request.path,
                capability,
                request.now,
            )
        } else {
            state.auth.authorize_request(
                principal,
                request.namespace,
                request.path,
                capability,
                request.now,
            )
        };
        if let Err(error) = authorization {
            return Response::error(error.status, &error.message);
        }
        let issuer = if request.path.contains("/creds/") || request.path.starts_with("sys/leases/")
        {
            match state
                .auth
                .lease_issuer(principal, request.namespace, request.now)
            {
                Ok(value) => Some(value),
                Err(error) => return Response::error(error.status, &error.message),
            }
        } else {
            None
        };
        if request.path.starts_with("sys/leases/") {
            let (action, path_id) =
                if let Some(id) = request.path.strip_prefix("sys/leases/revoke/") {
                    ("revoke", Some(id))
                } else if let Some(id) = request.path.strip_prefix("sys/leases/renew/") {
                    ("renew", Some(id))
                } else if request.path == "sys/leases/revoke" {
                    ("revoke", None)
                } else if request.path == "sys/leases/renew" {
                    ("renew", None)
                } else {
                    return Response::error(501, "OpenLDAP lease operation is not implemented");
                };
            if path_id.is_some_and(|id| id.is_empty() || id.contains('/')) {
                return Response::error(400, "invalid OpenLDAP lease id");
            }
            let body_id = request.body.get("lease_id").and_then(Value::as_str);
            if path_id.is_some() && body_id.is_some() && path_id != body_id {
                return Response::error(400, "lease_id conflicts with the lease path");
            }
            let lease_id = path_id
                .or(body_id)
                .ok_or_else(|| Response::error(400, "lease_id is required"));
            let lease_id = match lease_id {
                Ok(value) => value,
                Err(error) => return error,
            };
            let Some(mount) = state
                .engines
                .openldap_lease_mount(request.namespace, lease_id)
            else {
                return Response::error(404, "OpenLDAP lease not found");
            };
            if self
                .openldap_in_flight
                .contains(request.namespace, &mount, lease_id)
            {
                return openldap_outcome_unknown(lease_id);
            }
            if !matches!(request.method, "POST" | "PUT") {
                return Response::error(405, "OpenLDAP lease operations require POST or PUT");
            }
            if action == "renew" {
                let increment = request
                    .body
                    .get("increment")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let response = match state.engines.openldap_renew(
                    request.namespace,
                    &mount,
                    lease_id,
                    (!principal.is_root())
                        .then(|| issuer.as_ref().map(|issuer| issuer.digest.as_str()))
                        .flatten(),
                    increment,
                    request.now,
                ) {
                    Ok(response) => response,
                    Err(error) => return Response::error(error.status, &error.message),
                };
                state.schema = CURRENT_STATE_SCHEMA;
                if let Err(error) = self.commit_state(&state) {
                    return error;
                }
                self.state = Some(state);
                let mut response = response;
                return Response {
                    status: response.status,
                    body: std::mem::take(&mut response.body),
                };
            }
            if action == "revoke" {
                let plan =
                    match state
                        .engines
                        .openldap_stage_revoke(request.namespace, &mount, lease_id)
                    {
                        Ok(plan) => plan,
                        Err(error) => return Response::error(error.status, &error.message),
                    };
                state.schema = CURRENT_STATE_SCHEMA;
                if let Err(error) = self.commit_state(&state) {
                    return error;
                }
                self.state = Some(state);
                let in_flight = self.openldap_in_flight.track(&plan);
                self.pending_openldap_effect = Some(OpenLdapEffectPlan::new(
                    plan,
                    self.outbound.clone(),
                    self.ha.clone(),
                    in_flight,
                ));
                return Response::error(500, "OpenLDAP revoke was not dispatched");
            }
            return Response::error(501, "OpenLDAP lease operation is not implemented");
        }
        let dispatch = match state.engines.openldap_dispatch(
            request.namespace,
            request.path,
            request.method,
            request.body,
            request.now,
            issuer.as_ref(),
        ) {
            Ok(Some(value)) => value,
            Ok(None) => return Response::error(404, "OpenLDAP mount not found"),
            Err(error) => return Response::error(error.status, &error.message),
        };
        match dispatch {
            openldap::Dispatch::Immediate(mut response) => {
                if response.mutated {
                    state.schema = CURRENT_STATE_SCHEMA;
                    if let Err(error) = state.validate_format() {
                        return error;
                    }
                    if let Err(error) = self.commit_state(&state) {
                        return error;
                    }
                    self.state = Some(state);
                }
                Response {
                    status: response.status,
                    body: std::mem::take(&mut response.body),
                }
            }
            openldap::Dispatch::External(plan) => {
                let plan = *plan;
                state.schema = CURRENT_STATE_SCHEMA;
                if let Err(error) = state.validate_format() {
                    return error;
                }
                if let Err(error) = self.commit_state(&state) {
                    return error;
                }
                self.state = Some(state);
                let in_flight = self.openldap_in_flight.track(&plan);
                self.pending_openldap_effect = Some(OpenLdapEffectPlan::new(
                    plan,
                    self.outbound.clone(),
                    self.ha.clone(),
                    in_flight,
                ));
                Response::error(500, "OpenLDAP provider effect was not dispatched")
            }
        }
    }

    pub(super) fn finalize_openldap_effect(
        &mut self,
        plan: &OpenLdapEffectPlan,
        result: Result<(), Response>,
    ) -> Response {
        if let Err(error) = result {
            return error;
        }
        if let Some(ha) = &self.ha {
            let Ok(ha) = ha.lock_for_request() else {
                return openldap_outcome_unknown(&plan.inner.lease_id);
            };
            if ha.ensure_linearizable().is_err() {
                return openldap_outcome_unknown(&plan.inner.lease_id);
            }
        }
        let Some(mut state) = self.state.clone() else {
            return openldap_outcome_unknown(&plan.inner.lease_id);
        };
        let response = match state.engines.openldap_finalize(
            &plan.inner.namespace,
            &plan.inner.mount,
            &plan.inner,
        ) {
            Ok(response) => response,
            Err(_) => return openldap_outcome_unknown(&plan.inner.lease_id),
        };
        state.schema = CURRENT_STATE_SCHEMA;
        if state.validate_format().is_err() || self.commit_state(&state).is_err() {
            return openldap_outcome_unknown(&plan.inner.lease_id);
        }
        self.state = Some(state);
        let mut response = response;
        Response {
            status: response.status,
            body: std::mem::take(&mut response.body),
        }
    }
}
