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
    now: u64,
    started: std::time::Instant,
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
        now: u64,
        started: std::time::Instant,
    ) -> Self {
        Self {
            inner,
            now,
            started,
            outbound,
            ha,
            _in_flight: in_flight,
        }
    }

    fn completed_now(&self) -> u64 {
        std::time::Duration::from_secs(self.now)
            .saturating_add(self.started.elapsed())
            .as_secs()
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
        let started = std::time::Instant::now();
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
        for (namespace, stored_owner) in current.engines.lease_owners() {
            if current
                .auth
                .resolve_lease_owner(&stored_owner, &namespace, now)
                .is_some_and(|owner| {
                    owner.entity_id.as_deref().is_none_or(|id| {
                        current
                            .engines
                            .identity_projection(&namespace, id)
                            .is_ok_and(|projection| !projection.disabled)
                    })
                })
            {
                live.insert((namespace, stored_owner));
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
            now,
            started,
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
        let started = std::time::Instant::now();
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
                .typed_lease_issuer(principal, request.namespace, request.now)
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
                let Some((stored_owner, _)) =
                    state
                        .engines
                        .openldap_lease_authority(request.namespace, &mount, lease_id)
                else {
                    return Response::error(404, "OpenLDAP lease not found");
                };
                if !principal.is_root()
                    && issuer
                        .as_ref()
                        .is_none_or(|actor| !actor.owner.same_credential(stored_owner))
                {
                    return Response::error(409, "OpenLDAP lease is not active");
                }
                let Some(target_owner) =
                    state
                        .auth
                        .resolve_lease_owner(stored_owner, request.namespace, request.now)
                else {
                    return Response::error(403, "OpenLDAP lease owner expired or revoked");
                };
                if target_owner.entity_id.as_deref().is_some_and(|entity| {
                    !state
                        .engines
                        .identity_projection(request.namespace, entity)
                        .is_ok_and(|projection| !projection.disabled)
                }) {
                    return Response::error(403, "OpenLDAP lease owner identity is unavailable");
                }
                let response = match state.engines.openldap_renew(
                    request.namespace,
                    &mount,
                    lease_id,
                    &target_owner,
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
                    request.now,
                    started,
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
                    request.now,
                    started,
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
        self.finalize_openldap_effect_with_clock(plan, result, || plan.completed_now())
    }

    fn finalize_openldap_effect_with_clock(
        &mut self,
        plan: &OpenLdapEffectPlan,
        result: Result<(), Response>,
        mut completed_now: impl FnMut() -> u64,
    ) -> Response {
        if let Err(error) = result {
            return error;
        }
        if self.ha.is_some() && self.sync_from_ha_with_anchor(false).is_err() {
            return openldap_outcome_unknown(&plan.inner.lease_id);
        }
        let Some(mut state) = self.state.clone() else {
            return openldap_outcome_unknown(&plan.inner.lease_id);
        };
        let now = completed_now().max(state.engines.lease_clock());
        if state
            .engines
            .openldap_effect_authority(&plan.inner.namespace, &plan.inner.mount, &plan.inner)
            .is_err()
        {
            return openldap_outcome_unknown(&plan.inner.lease_id);
        }
        if matches!(plan.inner.action, openldap::EffectAction::Issue)
            && !Self::openldap_completion_owner_live(&state, plan, now)
        {
            return self.reject_openldap_completion(state, plan, now);
        }
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
        let now = completed_now().max(now);
        if matches!(plan.inner.action, openldap::EffectAction::Issue) {
            let Some(current) = self.state.as_ref() else {
                return openldap_outcome_unknown(&plan.inner.lease_id);
            };
            if !Self::openldap_completion_owner_live(current, plan, now) {
                return self.reject_openldap_completion(current.clone(), plan, now);
            }
        }
        let mut response = response;
        if matches!(plan.inner.action, openldap::EffectAction::Issue) {
            response.body["lease_duration"] = json!(plan.inner.expires_at.saturating_sub(now));
        }
        Response {
            status: response.status,
            body: std::mem::take(&mut response.body),
        }
    }

    fn openldap_completion_owner_live(state: &State, plan: &OpenLdapEffectPlan, now: u64) -> bool {
        plan.inner.expires_at > now
            && state
                .auth
                .resolve_lease_owner(&plan.inner.owner, &plan.inner.namespace, now)
                .is_some_and(|owner| {
                    owner.entity_id.as_deref().is_none_or(|id| {
                        state
                            .engines
                            .identity_projection(&plan.inner.namespace, id)
                            .is_ok_and(|projection| !projection.disabled)
                    })
                })
    }

    fn reject_openldap_completion(
        &mut self,
        mut state: State,
        plan: &OpenLdapEffectPlan,
        now: u64,
    ) -> Response {
        // Called only after checking the complete admitted intent (or after our
        // own terminal publication). Never revoke a concurrently newer intent.
        if state
            .engines
            .openldap_prepare_effect(
                &plan.inner.namespace,
                &plan.inner.mount,
                &plan.inner.lease_id,
                now,
                true,
            )
            .is_ok()
        {
            state.schema = CURRENT_STATE_SCHEMA;
            if state.validate_format().is_ok() && self.commit_state(&state).is_ok() {
                self.state = Some(state);
            }
        }
        openldap_outcome_unknown(&plan.inner.lease_id)
    }
}

#[cfg(test)]
mod completion_tests {
    use super::super::tests::{Root, bootstrap, call};
    use super::*;
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    type Fixture = (Root, Service, String, String, OpenLdapEffectPlan);
    fn fixture() -> TestResult<Fixture> {
        fixture_with_batch(None)
    }
    fn fixture_with_batch(parented: Option<bool>) -> TestResult<Fixture> {
        fixture_with_batch_identity(parented, false)
    }
    fn fixture_with_batch_identity(parented: Option<bool>, identity: bool) -> TestResult<Fixture> {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, token) = bootstrap(&mut service)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/mounts/ldap",
                &token,
                json!({"type":"ldap"})
            )
            .status,
            204
        );
        let issued = call(
            &mut service,
            "POST",
            "auth/token/create",
            &token,
            json!({"policies":["default"], "ttl":120}),
        );
        assert_eq!(issued.status, 200);
        let raw = issued.body["auth"]["client_token"]
            .as_str()
            .ok_or("token")?;
        let mut state = service.state.clone().ok_or("state")?;
        let actor = state.auth.authenticate(raw, 100).map_err(|_| "actor")?;
        let owner = state
            .auth
            .typed_lease_issuer(&actor, "", 100)
            .map_err(|_| "owner")?;
        let entity_id = if identity {
            let entity = state
                .engines
                .handle(
                    "",
                    "POST",
                    "identity/entity",
                    &json!({"name":"completion-owner"}),
                    100,
                )
                .map_err(|_| "entity")?
                .ok_or("entity route")?;
            Some(
                entity.body["data"]["id"]
                    .as_str()
                    .ok_or("entity id")?
                    .to_owned(),
            )
        } else {
            None
        };
        let owner = if let Some(parented) = parented {
            use crate::auth::{BatchClaims, BatchKeyAuthority, LeaseOwner};
            let mut authority = BatchKeyAuthority::new(100)?;
            let parent = if parented {
                owner.owner.service_digest().map(str::to_owned)
            } else {
                None
            };
            let raw = authority.seal(
                BatchClaims {
                    namespace: String::new(),
                    policies: BTreeSet::from(["default".into()]),
                    metadata: BTreeMap::new(),
                    display_name: "batch-test".into(),
                    path: "auth/userpass/login/test".into(),
                    bound_cidrs: Vec::new(),
                    issued_at: 100,
                    expires_at: 220,
                    parent,
                    entity_id,
                },
                100,
            )?;
            let batch_owner = LeaseOwner::from_batch(&authority.open(raw.as_str(), "", 100)?);
            let mut serialized = serde_json::to_value(&state.auth)?;
            let service_count = serialized["tokens"].as_object().ok_or("tokens")?.len();
            serialized["batch_authority"] = serde_json::to_value(&authority)?;
            state.auth = serde_json::from_value(serialized)?;
            assert_eq!(
                serde_json::to_value(&state.auth)?["tokens"]
                    .as_object()
                    .ok_or("tokens")?
                    .len(),
                service_count
            );
            state
                .auth
                .resolve_lease_owner(&batch_owner, "", 100)
                .ok_or("batch owner")?
        } else {
            owner
        };
        state
            .engines
            .openldap_dispatch(
                "",
                "ldap/config",
                "POST",
                &json!({
                    "url":"ldaps://localhost:636", "binddn":"cn=manager,dc=example,dc=test",
                    "bindpass":"synthetic-bind-password", "userdn":"ou=people,dc=example,dc=test"
                }),
                100,
                None,
            )
            .map_err(|_| "config")?;
        let creation = "dn: uid={{.Username}},ou=people,dc=example,dc=test\nchangetype: add\nobjectClass: top\nobjectClass: person\nobjectClass: organizationalPerson\nobjectClass: inetOrgPerson\ncn: {{.Username}}\nsn: Synthetic\nuid: {{.Username}}\nuserPassword: {{.Password}}\n";
        let deletion = "dn: uid={{.Username}},ou=people,dc=example,dc=test\nchangetype: delete\n";
        state
            .engines
            .openldap_dispatch(
                "",
                "ldap/role/reader",
                "POST",
                &json!({
                    "creation_ldif":creation, "deletion_ldif":deletion, "rollback_ldif":deletion,
                    "default_ttl":120, "max_ttl":120
                }),
                100,
                None,
            )
            .map_err(|_| "role")?;
        let dispatch = state
            .engines
            .openldap_dispatch(
                "",
                "ldap/creds/reader",
                "GET",
                &json!({}),
                100,
                Some(&owner),
            )
            .map_err(|_| "issue")?
            .ok_or("dispatch")?;
        let openldap::Dispatch::External(inner) = dispatch else {
            return Err("external plan".into());
        };
        state.schema = CURRENT_STATE_SCHEMA;
        state.validate_format().map_err(|_| "validate")?;
        service.commit_state(&state).map_err(|_| "commit")?;
        service.state = Some(state);
        let flight = service.openldap_in_flight.track(&inner);
        let plan = OpenLdapEffectPlan::new(
            *inner,
            service.outbound.clone(),
            None,
            flight,
            100,
            std::time::Instant::now(),
        );
        Ok((root, service, key, token, plan))
    }

    #[test]
    fn completion_openldap_expired_owner_preserves_revoke_intent_across_reopen() -> TestResult {
        let (root, mut service, key, _, mut plan) = fixture()?;
        plan.started = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(121))
            .ok_or("clock")?;
        let response = service.finalize_openldap_effect(&plan, Ok(()));
        assert_eq!(response.status, 503);
        assert_eq!(response.body["retry_allowed"], false);
        assert!(response.body.get("data").is_none());
        let id = plan.inner.lease_id.clone();
        drop(plan);
        drop(service);
        let mut service = root.service()?;
        assert_eq!(
            call(&mut service, "PUT", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        let pending = service
            .prepare_openldap_maintenance(222)?
            .ok_or("cleanup")?;
        assert!(pending.plan.inner.action == openldap::EffectAction::Revoke);
        assert_eq!(pending.plan.inner.lease_id, id);
        assert_eq!(
            service
                .finalize_openldap_effect(&pending.plan, Ok(()))
                .status,
            204
        );
        assert!(
            service
                .state
                .as_ref()
                .ok_or("state")?
                .engines
                .openldap_lease_authority("", "ldap/", &id)
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn completion_openldap_full_owner_drift_is_rejected_without_touching_current_intent()
    -> TestResult {
        let (_root, mut service, _, _, mut plan) = fixture()?;
        plan.inner.owner = crate::auth::LeaseOwner::service(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
        )
        .map_err(|_| "owner")?;
        let durable = service.durable.as_ref().ok_or("durable")?;
        let generation = durable.generation();
        let saved = durable.get("system", "state")?;
        assert_eq!(service.finalize_openldap_effect(&plan, Ok(())).status, 503);
        let durable = service.durable.as_ref().ok_or("durable")?;
        assert_eq!(durable.generation(), generation);
        assert_eq!(durable.get("system", "state")?, saved);
        Ok(())
    }

    #[test]
    fn completion_openldap_live_owner_gets_secret_and_only_remaining_ttl() -> TestResult {
        let (_root, mut service, _, _, mut plan) = fixture()?;
        plan.started = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(2))
            .ok_or("clock")?;
        let response = service.finalize_openldap_effect(&plan, Ok(()));
        assert_eq!(response.status, 200);
        assert!(response.body["data"]["password"].is_string());
        assert!(
            response.body["lease_duration"]
                .as_u64()
                .is_some_and(|ttl| ttl <= 118 && ttl > 0)
        );
        Ok(())
    }

    #[test]
    fn completion_openldap_parent_revocation_during_add_retains_cleanup() -> TestResult {
        let (_root, mut service, _, root_token, plan) = fixture()?;
        let mut state = service.state.clone().ok_or("state")?;
        let actor = state
            .auth
            .authenticate(&root_token, 100)
            .map_err(|_| "actor")?;
        state
            .auth
            .handle(
                Some(&actor),
                "",
                "POST",
                "auth/token/revoke-self",
                &json!({}),
                100,
            )
            .map_err(|_| "revoke parent")?
            .ok_or("route")?;
        service
            .commit_state(&state)
            .map_err(|_| "publish revocation")?;
        service.state = Some(state);
        let response = service.finalize_openldap_effect(&plan, Ok(()));
        assert_eq!(response.status, 503);
        assert_eq!(response.body["retry_allowed"], false);
        assert!(response.body.get("data").is_none());
        let cleanup = service
            .state
            .as_mut()
            .ok_or("state")?
            .engines
            .openldap_prepare_effect("", "ldap/", &plan.inner.lease_id, 100, false)
            .map_err(|_| "cleanup")?;
        assert!(cleanup.action == openldap::EffectAction::Revoke);
        Ok(())
    }

    #[test]
    fn completion_openldap_owner_expires_during_terminal_commit_no_secret_is_released() -> TestResult
    {
        let (_root, mut service, _, _, plan) = fixture()?;
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let mut reads = 0;
        let response = service.finalize_openldap_effect_with_clock(&plan, Ok(()), || {
            reads += 1;
            if reads == 1 { 100 } else { 221 }
        });
        assert_eq!(reads, 2);
        assert_eq!(response.status, 503);
        assert_eq!(response.body["retry_allowed"], false);
        assert!(response.body.get("data").is_none());
        assert!(service.durable.as_ref().ok_or("durable")?.generation() > generation);
        let cleanup = service
            .state
            .as_mut()
            .ok_or("state")?
            .engines
            .openldap_prepare_effect("", "ldap/", &plan.inner.lease_id, 222, false)
            .map_err(|_| "cleanup")?;
        assert!(cleanup.action == openldap::EffectAction::Revoke);
        Ok(())
    }

    #[test]
    fn completion_openldap_verified_batch_expiry_and_parent_revoke_never_publish_secret()
    -> TestResult {
        for parent_revoked in [false, true] {
            let (_root, mut service, _, root_token, mut plan) =
                fixture_with_batch(Some(parent_revoked))?;
            if parent_revoked {
                let mut state = service.state.clone().ok_or("state")?;
                let actor = state
                    .auth
                    .authenticate(&root_token, 100)
                    .map_err(|_| "actor")?;
                state
                    .auth
                    .handle(
                        Some(&actor),
                        "",
                        "POST",
                        "auth/token/revoke-self",
                        &json!({}),
                        100,
                    )
                    .map_err(|_| "revoke")?
                    .ok_or("route")?;
                service
                    .commit_state(&state)
                    .map_err(|_| "commit revocation")?;
                service.state = Some(state);
            } else {
                plan.started = std::time::Instant::now()
                    .checked_sub(std::time::Duration::from_secs(121))
                    .ok_or("clock")?;
            }
            let response = service.finalize_openldap_effect(&plan, Ok(()));
            assert_eq!(response.status, 503);
            assert_eq!(response.body["retry_allowed"], false);
            assert!(response.body.get("data").is_none());
            let cleanup = service
                .state
                .as_mut()
                .ok_or("state")?
                .engines
                .openldap_prepare_effect("", "ldap/", &plan.inner.lease_id, 222, false)
                .map_err(|_| "cleanup")?;
            assert!(cleanup.action == openldap::EffectAction::Revoke);
        }
        Ok(())
    }
    #[test]
    fn completion_openldap_batch_parent_shortened_but_live_is_not_a_ttl_cap() -> TestResult {
        for completed_now in [100, 106] {
            let (_root, mut service, _, root_token, plan) = fixture_with_batch(Some(true))?;
            let parent = plan
                .inner
                .owner
                .batch_claims()
                .and_then(|claims| claims.parent())
                .ok_or("parent")?;
            let serialized = serde_json::to_value(&service.state.as_ref().ok_or("state")?.auth)?;
            let accessor = serialized["tokens"][parent]["accessor"]
                .as_str()
                .ok_or("accessor")?
                .to_owned();
            let renewed = call(
                &mut service,
                "POST",
                "auth/token/renew-accessor",
                &root_token,
                json!({"accessor":accessor,"increment":5}),
            );
            assert_eq!(renewed.status, 200);
            let resolved = service
                .state
                .as_ref()
                .ok_or("state")?
                .auth
                .resolve_lease_owner(&plan.inner.owner, "", 100)
                .ok_or("live parent")?;
            assert_eq!(resolved.expires_at, Some(220));
            let response =
                service.finalize_openldap_effect_with_clock(&plan, Ok(()), || completed_now);
            assert_eq!(
                response.status,
                if completed_now == 100 { 200 } else { 503 }
            );
            if completed_now == 100 {
                assert_eq!(response.body["lease_duration"], 120);
                assert!(response.body["data"]["password"].is_string());
            } else {
                assert_eq!(response.body["retry_allowed"], false);
                assert!(response.body.get("data").is_none());
                let cleanup = service
                    .state
                    .as_mut()
                    .ok_or("state")?
                    .engines
                    .openldap_prepare_effect("", "ldap/", &plan.inner.lease_id, 106, false)
                    .map_err(|_| "cleanup")?;
                assert!(cleanup.action == openldap::EffectAction::Revoke);
            }
        }
        Ok(())
    }
    #[test]
    fn completion_openldap_uses_live_identity_in_lease_namespace() -> TestResult {
        for same_namespace in [false, true] {
            let (_root, mut service, _, _, plan) = fixture_with_batch_identity(Some(false), true)?;
            let mut state = service.state.clone().ok_or("state")?;
            let owner = state
                .auth
                .resolve_lease_owner(&plan.inner.owner, "", 100)
                .ok_or("owner")?;
            let entity_id = owner.entity_id.ok_or("entity id")?;
            // The same generated entity ID exists in a different namespace.
            // Disabling it must not disable the root namespace's batch owner.
            let other = state
                .engines
                .handle(
                    "other",
                    "POST",
                    "identity/entity",
                    &json!({"name":"completion-owner"}),
                    100,
                )
                .map_err(|_| "other entity")?
                .ok_or("other entity route")?;
            assert_eq!(other.body["data"]["id"], entity_id);
            let ns = if same_namespace { "" } else { "other" };
            state
                .engines
                .handle(
                    ns,
                    "POST",
                    &format!("identity/entity/id/{entity_id}"),
                    &json!({"disabled":true}),
                    100,
                )
                .map_err(|_| "disable entity")?
                .ok_or("disable route")?;
            assert_eq!(
                state
                    .engines
                    .identity_projection("", &entity_id)
                    .map_err(|_| "projection")?
                    .disabled,
                same_namespace
            );
            service
                .commit_state(&state)
                .map_err(|_| "commit identity")?;
            service.state = Some(state);
            // Real admitted intent/typed batch, simulated successful provider result.
            let response = service.finalize_openldap_effect_with_clock(&plan, Ok(()), || 100);
            if same_namespace {
                assert_eq!(response.status, 503);
                assert_eq!(response.body["retry_allowed"], false);
                assert!(response.body.get("data").is_none());
                let cleanup = service
                    .state
                    .as_mut()
                    .ok_or("state")?
                    .engines
                    .openldap_prepare_effect("", "ldap/", &plan.inner.lease_id, 100, false)
                    .map_err(|_| "cleanup")?;
                assert!(cleanup.action == openldap::EffectAction::Revoke);
            } else {
                assert_eq!(response.status, 200);
                assert!(response.body["data"]["password"].is_string());
            }
        }
        Ok(())
    }
}
