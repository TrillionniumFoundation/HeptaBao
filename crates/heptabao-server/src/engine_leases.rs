//! Online dynamic-secret lifetime and administration for local SSH OTP and PKI
//! issuance. External-provider renewal callbacks remain outside this module.
use super::*;
use crate::auth::{LeaseOwner, ResolvedLeaseOwner, ServiceOwnerProfile};

pub(crate) struct PkiRequestContext<'a> {
    pub(crate) owner: Option<&'a ResolvedLeaseOwner>,
    pub(crate) time: crate::auth::AuthorityTime,
    pub(crate) clock: Option<crate::auth::RequestClock>,
    pub(crate) identity_templates: Option<&'a crate::auth::IdentityTemplateValues>,
}
impl PkiRequestContext<'_> {
    pub(crate) fn observed_time(&self, floor: u64) -> Result<crate::auth::AuthorityTime> {
        pki::precise_time::observe(self.time, self.clock, floor)
    }
}

/// A response-only receipt for an unchanged, actual PKI mount. It grants no
/// provider or local signing operation and contains no private key material.
#[derive(PartialEq, Eq)]
pub(crate) struct PkiNoEffectBinding {
    mount: String,
    incarnation: u64,
    revision: u64,
    fingerprint: [u8; 32],
}

impl EngineState {
    fn pki_no_effect_binding(
        &self,
        namespace: &str,
        mount_path: &str,
    ) -> Result<PkiNoEffectBinding> {
        let mount = self
            .namespaces
            .get(namespace)
            .and_then(|state| state.mounts.get(mount_path))
            .ok_or_else(not_found)?;
        let Backend::Pki(engine) = &mount.backend else {
            return Err(not_found());
        };
        let encoded = zeroize::Zeroizing::new(
            crate::secret_serde::to_vec(engine.as_ref(), crate::MAX_APPLICATION_STATE_BYTES)
                .map_err(|_| error(503, "PKI no-effect owner exceeds bounds"))?,
        );
        Ok(PkiNoEffectBinding {
            mount: mount_path.to_owned(),
            incarnation: mount.incarnation,
            revision: mount.revision,
            fingerprint: crate::crypto::digest(&encoded),
        })
    }

    pub(crate) fn external_pki_no_effect_current(
        &self,
        namespace: &str,
        expected: &PkiNoEffectBinding,
    ) -> bool {
        self.pki_no_effect_binding(namespace, &expected.mount)
            .is_ok_and(|current| current == *expected)
    }

    pub(crate) fn prepare_external_pki_no_effect(
        &self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        context: PkiRequestContext<'_>,
    ) -> Result<Option<(PkiNoEffectBinding, EngineResponse)>> {
        let Some(mount_path) = self.pki_mount(namespace, path) else {
            return Ok(None);
        };
        if !write_method(method) || &path[mount_path.len()..] != "revoke" {
            return Ok(None);
        }
        let mount = self
            .namespaces
            .get(namespace)
            .and_then(|state| state.mounts.get(mount_path))
            .ok_or_else(not_found)?;
        let Backend::Pki(engine) = &mount.backend else {
            return Ok(None);
        };
        let Some(response) = engine.external_no_effect_revocation(body, &context)? else {
            return Ok(None);
        };
        if response.mutated {
            return Err(error(503, "PKI no-effect result changed its owner"));
        }
        Ok(Some((
            self.pki_no_effect_binding(namespace, mount_path)?,
            response,
        )))
    }

    fn ssh_mount(&self, namespace: &str, path: &str) -> Option<&str> {
        let state = self.namespaces.get(namespace)?;
        let mount = state
            .mounts
            .keys()
            .filter(|name| path.starts_with(name.as_str()))
            .max_by_key(|name| name.len())?;
        matches!(state.mounts.get(mount)?.backend, Backend::Ssh(_)).then_some(mount.as_str())
    }
    fn pki_mount(&self, namespace: &str, path: &str) -> Option<&str> {
        let state = self.namespaces.get(namespace)?;
        let mount = state
            .mounts
            .keys()
            .filter(|name| path.starts_with(name.as_str()))
            .max_by_key(|name| name.len())?;
        matches!(state.mounts.get(mount)?.backend, Backend::Pki(_)).then_some(mount.as_str())
    }
    pub(crate) fn is_ssh_service_route(&self, namespace: &str, path: &str) -> bool {
        self.ssh_mount(namespace, path).is_some_and(|mount| {
            let relative = &path[mount.len()..];
            relative == "verify" || relative.starts_with("creds/")
        })
    }
    pub(crate) fn is_pki_issue_route(&self, namespace: &str, path: &str) -> bool {
        self.pki_mount(namespace, path).is_some_and(|mount| {
            let relative = &path[mount.len()..];
            relative.starts_with("issue/")
                || relative.starts_with("sign/")
                || pki::Pki::issuer_issue_route(relative).is_some()
                || pki::Pki::issuer_sign_route(relative).is_some()
        })
    }
    pub(crate) fn is_pki_acme_operator_revoke_route(&self, namespace: &str, path: &str) -> bool {
        self.pki_mount(namespace, path).is_some_and(|mount| {
            &path[mount.len()..] == "revoke" && self.namespaces.get(namespace)
                .and_then(|state|state.mounts.get(mount))
                .is_some_and(|mount| matches!(&mount.backend, Backend::Pki(pki) if pki.acme_protocol.is_some()))
        })
    }
    pub(crate) fn is_lease_service_route(&self, namespace: &str, path: &str) -> bool {
        self.is_ssh_service_route(namespace, path)
            || self.is_pki_issue_route(namespace, path)
            || self.is_pki_acme_operator_revoke_route(namespace, path)
    }
    pub(crate) fn is_ssh_verification(&self, namespace: &str, method: &str, path: &str) -> bool {
        write_method(method)
            && self
                .ssh_mount(namespace, path)
                .is_some_and(|mount| &path[mount.len()..] == "verify")
    }
    pub(crate) fn has_live_leases(&self) -> bool {
        self.namespaces.values().any(|state| {
            state.mounts.values().any(|mount| match &mount.backend {
                Backend::Ssh(engine) => !engine.leases.is_empty(),
                Backend::Pki(engine) => engine.has_live_leases(self.lease_clock),
                Backend::Kubernetes(engine) => engine.has_unresolved(),
                Backend::OpenLdap(engine) => engine.has_unresolved(),
                _ => false,
            })
        })
    }
    pub(crate) fn has_lease_state(&self) -> bool {
        self.lease_clock != 0
            || self.namespaces.values().any(|state| {
                state.mounts.values().any(|mount| {
                    matches!(
                        mount.backend,
                        Backend::Ssh(_)
                            | Backend::Pki(_)
                            | Backend::Kubernetes(_)
                            | Backend::OpenLdap(_)
                    )
                })
            })
    }
    pub(crate) fn validate_lease_state(&self) -> Result<()> {
        for (namespace, state) in &self.namespaces {
            for (name, mount) in &state.mounts {
                match &mount.backend {
                    Backend::Ssh(engine) => engine.validate(namespace, name, self.lease_clock)?,
                    Backend::Pki(engine) => engine.validate(namespace, name, self.lease_clock)?,
                    Backend::Kubernetes(engine) => engine.validate_scope(namespace)?,
                    Backend::OpenLdap(engine) => engine.validate_scope(namespace)?,
                    _ => {}
                }
            }
        }
        Ok(())
    }
    pub(crate) fn lease_owners(&self) -> BTreeSet<(String, LeaseOwner)> {
        self.namespaces
            .iter()
            .flat_map(|(namespace, state)| {
                state.mounts.values().flat_map(move |mount| {
                    let mut owners = Vec::new();
                    match &mount.backend {
                        Backend::Ssh(engine) => owners.extend(
                            engine
                                .leases
                                .values()
                                .map(|lease| (namespace.clone(), lease.owner.clone())),
                        ),
                        Backend::Pki(engine) => owners.extend(
                            engine
                                .active_owners(self.lease_clock)
                                .map(|owner| (namespace.clone(), owner.clone())),
                        ),
                        Backend::Kubernetes(engine) => owners.extend(
                            engine
                                .all_owners()
                                .map(|owner| (namespace.clone(), owner.clone())),
                        ),
                        Backend::OpenLdap(engine) => owners.extend(
                            engine
                                .lease_owners()
                                .map(|owner| (namespace.clone(), owner.to_owned())),
                        ),
                        _ => {}
                    }
                    owners
                })
            })
            .collect()
    }
    /// Every retained owner, including revoked/non-leased certificates and
    /// pending external intents. Format validation must not depend on liveness.
    pub(crate) fn all_lease_owners(&self) -> BTreeSet<(String, LeaseOwner)> {
        let mut owners = self.sdk_lease_owners();
        for (namespace, state) in &self.namespaces {
            for mount in state.mounts.values() {
                match &mount.backend {
                    Backend::Ssh(engine) => owners.extend(
                        engine
                            .leases
                            .values()
                            .map(|lease| (namespace.clone(), lease.owner.clone())),
                    ),
                    Backend::Pki(engine) => owners.extend(
                        engine
                            .all_owners()
                            .map(|owner| (namespace.clone(), owner.clone())),
                    ),
                    Backend::Kubernetes(engine) => owners.extend(
                        engine
                            .all_owners()
                            .map(|owner| (namespace.clone(), owner.clone())),
                    ),
                    Backend::OpenLdap(engine) => owners.extend(
                        engine
                            .lease_owners()
                            .map(|owner| (namespace.clone(), owner.clone())),
                    ),
                    _ => {}
                }
            }
        }
        owners
    }

    pub(crate) fn reconcile_lease_state_observed(
        &mut self,
        time: crate::auth::AuthorityTime,
        live: &BTreeSet<(String, LeaseOwner)>,
    ) -> Result<bool> {
        if !self.has_kubernetes_opaque_artifact_state() {
            return Ok(self.reconcile_lease_state(time.seconds(), live));
        }
        // Obtain a precise observation before any clock or retirement mutation.
        let time = self.kubernetes_artifact_time(time)?;
        let mut changed = self.observe_kubernetes_artifact_time(time)?;
        changed |= self.reconcile_lease_state(time.seconds(), live);
        for (namespace, state) in &mut self.namespaces {
            for mount in state.mounts.values_mut() {
                if let Backend::Kubernetes(engine) = &mut mount.backend {
                    changed |= engine.reconcile_owners_observed(time, namespace, live)?;
                }
            }
        }
        Ok(changed)
    }

    pub(crate) fn reconcile_lease_state(
        &mut self,
        now: u64,
        live: &BTreeSet<(String, LeaseOwner)>,
    ) -> bool {
        let any = self.namespaces.values().any(|state| {
            state.mounts.values().any(|mount| match &mount.backend {
                Backend::Ssh(engine) => !engine.leases.is_empty(),
                // External signed caches also consume this monotonic floor:
                // a root-only issuer can have no currently leased leaf while
                // an observed CRL expiry still requires durable fencing.
                Backend::Pki(engine) => {
                    engine.has_live_leases(self.lease_clock) || engine.has_external_state()
                }
                Backend::Kubernetes(engine) => engine.has_typed_observations(),
                _ => false,
            })
        });
        if !any {
            return false;
        }
        let mut changed = now > self.lease_clock;
        self.lease_clock = self.lease_clock.max(now);
        for (namespace, state) in &mut self.namespaces {
            for mount in state.mounts.values_mut() {
                match &mut mount.backend {
                    Backend::Ssh(engine) => {
                        let before = engine.leases.len();
                        engine.leases.retain(|_, lease| {
                            lease.expires > self.lease_clock
                                && live.contains(&(namespace.clone(), lease.owner.clone()))
                        });
                        changed |= before != engine.leases.len();
                    }
                    Backend::Pki(engine) => {
                        changed |= engine.reconcile(self.lease_clock, namespace, live);
                    }
                    Backend::Kubernetes(engine) => {
                        changed |= engine.reconcile_owners(self.lease_clock, namespace, live);
                    }
                    _ => {}
                }
            }
        }
        changed
    }
    pub(crate) fn handle_service_ssh(
        &mut self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        owner: Option<&ResolvedLeaseOwner>,
        now: u64,
    ) -> Result<EngineResponse> {
        if !write_method(method) {
            return Err(unsupported());
        }
        let mount = self
            .ssh_mount(namespace, path)
            .ok_or_else(not_found)?
            .to_owned();
        let mut candidate = self
            .namespaces
            .get(namespace)
            .ok_or_else(not_found)?
            .clone();
        let Backend::Ssh(engine) = &mut candidate
            .mounts
            .get_mut(&mount)
            .ok_or_else(not_found)?
            .backend
        else {
            return Err(not_found());
        };
        let relative = &path[mount.len()..];
        let now = now.max(self.lease_clock);
        let response = if relative == "verify" {
            engine.verify(body, now)?
        } else {
            let name = relative.strip_prefix("creds/").ok_or_else(not_found)?;
            let owner = owner.ok_or_else(|| error(403, "credential issuer is required"))?;
            owner
                .owner
                .validate_scope(namespace, ServiceOwnerProfile::DigestAlphabet)
                .map_err(|_| error(403, "credential owner scope mismatch"))?;
            engine.issue(&mount, name, body, &owner.owner, owner.expires_at, now)?
        };
        if response.mutated {
            self.namespaces.insert(namespace.into(), candidate);
            self.lease_clock = now;
        }
        Ok(response)
    }
    #[cfg(test)]
    pub(crate) fn handle_service_pki(
        &mut self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        owner: &ResolvedLeaseOwner,
        now: u64,
    ) -> Result<EngineResponse> {
        self.handle_service_pki_context(
            namespace,
            method,
            path,
            body,
            PkiRequestContext {
                owner: Some(owner),
                time: crate::auth::AuthorityTime::Coarse(now),
                clock: None,
                identity_templates: None,
            },
        )
    }

    pub(crate) fn pki_identity_selectors(&self, namespace: &str, path: &str) -> BTreeSet<String> {
        let Some(mount) = self.pki_mount(namespace, path) else {
            return BTreeSet::new();
        };
        let Some(Backend::Pki(engine)) = self
            .namespaces
            .get(namespace)
            .and_then(|state| state.mounts.get(mount))
            .map(|mount| &mount.backend)
        else {
            return BTreeSet::new();
        };
        engine.identity_selectors(&path[mount.len()..])
    }

    pub(crate) fn handle_service_pki_operator_revoke(
        &mut self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        context: PkiRequestContext<'_>,
        mut before_effect: impl FnMut() -> Result<()>,
    ) -> Result<EngineResponse> {
        if !write_method(method) {
            return Err(unsupported());
        }
        let actor = context
            .owner
            .ok_or_else(|| error(403, "administrative PKI caller required"))?;
        actor
            .owner
            .validate_scope(namespace, ServiceOwnerProfile::DigestAlphabet)
            .map_err(|_| error(403, "administrative PKI caller namespace rejected"))?;
        let mount = self
            .pki_mount(namespace, path)
            .ok_or_else(not_found)?
            .to_owned();
        if &path[mount.len()..] != "revoke" {
            return Err(not_found());
        }
        let time = context.observed_time(self.lease_clock)?;
        let mut candidate = self
            .namespaces
            .get(namespace)
            .ok_or_else(not_found)?
            .clone();
        let Backend::Pki(engine) = &mut candidate
            .mounts
            .get_mut(&mount)
            .ok_or_else(not_found)?
            .backend
        else {
            return Err(not_found());
        };
        let response = match engine.revoke_acme_by_operator(
            body,
            PkiRequestContext { time, ..context },
            &mut before_effect,
        )? {
            Some(response) => response,
            None => {
                before_effect()?;
                engine.handle_admin(method, "revoke", body, time.seconds())?
            }
        };
        let delivered = context.observed_time(
            time.seconds().max(
                engine
                    .acme_protocol
                    .as_ref()
                    .map_or(0, |p| p.clock.seconds()),
            ),
        )?;
        if actor
            .precise_expires_at
            .is_some_and(|end| delivered.exact().is_none_or(|at| at > end))
            || actor.precise_expires_at.is_none()
                && actor
                    .expires_at
                    .is_some_and(|end| delivered.seconds() >= end)
        {
            return Err(error(403, "administrative PKI caller no longer live"));
        }
        if response.mutated {
            self.namespaces.insert(namespace.into(), candidate);
            self.lease_clock = self.lease_clock.max(delivered.seconds());
        }
        Ok(response)
    }

    pub(crate) fn handle_service_pki_context(
        &mut self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        context: PkiRequestContext<'_>,
    ) -> Result<EngineResponse> {
        let owner = context
            .owner
            .ok_or_else(|| error(403, "credential issuer is required"))?;
        let time = context.observed_time(self.lease_clock)?;
        let now = time.seconds();
        if !write_method(method) {
            return Err(unsupported());
        }
        let mount = self
            .pki_mount(namespace, path)
            .ok_or_else(not_found)?
            .to_owned();
        let relative = &path[mount.len()..];
        let mut candidate = self
            .namespaces
            .get(namespace)
            .ok_or_else(not_found)?
            .clone();
        let Backend::Pki(engine) = &mut candidate
            .mounts
            .get_mut(&mount)
            .ok_or_else(not_found)?
            .backend
        else {
            return Err(not_found());
        };
        let now = now.max(self.lease_clock);
        owner
            .owner
            .validate_scope(namespace, ServiceOwnerProfile::DigestAlphabet)
            .map_err(|_| error(403, "credential owner scope mismatch"))?;
        let response = engine.issue_route(
            &mount,
            relative,
            body,
            pki::LeafAuthority {
                owner: &owner.owner,
                owner_expires: owner.expires_at,
                precise_owner_expires: owner.precise_expires_at,
                time,
                clock: context.clock,
                identity_templates: context.identity_templates,
            },
        )?;
        let delivered = context.observed_time(now)?;
        if owner
            .precise_expires_at
            .is_some_and(|end| delivered.exact().is_none_or(|at| at > end))
            || owner.precise_expires_at.is_none()
                && owner
                    .expires_at
                    .is_some_and(|end| delivered.seconds() >= end)
        {
            return Err(error(403, "issuer no longer has a live PKI lease window"));
        }
        if response.mutated {
            self.namespaces.insert(namespace.into(), candidate);
            self.lease_clock = delivered.seconds();
        }
        Ok(response)
    }

    pub(crate) fn handle_lease_admin_observed(
        &mut self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        time: crate::auth::AuthorityTime,
    ) -> Result<EngineResponse> {
        if !self.has_kubernetes_opaque_artifact_state() {
            return self.handle_lease_admin(namespace, method, path, body, time.seconds());
        }
        let time = self.kubernetes_artifact_time(time)?;
        self.handle_lease_admin_with_observation(
            namespace,
            method,
            path,
            body,
            time.seconds(),
            Some(time),
        )
    }

    pub(crate) fn handle_lease_admin(
        &mut self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        if self.has_kubernetes_opaque_artifact_state() {
            return Err(error(503, "trusted opaque artifact clock is required"));
        }
        self.handle_lease_admin_with_observation(namespace, method, path, body, now, None)
    }

    fn handle_lease_admin_with_observation(
        &mut self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
        observed: Option<crate::auth::AuthorityTime>,
    ) -> Result<EngineResponse> {
        let mut candidate = self.namespaces.get(namespace).cloned().unwrap_or_default();
        if let Some(prefix) = path.strip_prefix("sys/leases/lookup/") {
            if method != "LIST" {
                return Err(unsupported());
            }
            reject_unknown(body, &[])?;
            let prefix = if prefix.is_empty() {
                String::new()
            } else {
                format!("{}/", prefix.trim_end_matches('/'))
            };
            let mut keys = BTreeSet::new();
            for mount in candidate.mounts.values() {
                let ids: Vec<&str> = match &mount.backend {
                    Backend::Ssh(engine) => engine
                        .leases
                        .values()
                        .map(|lease| lease.id.as_str())
                        .collect(),
                    Backend::Pki(engine) => engine.lease_ids().collect(),
                    Backend::Kubernetes(engine) => engine.lease_ids().collect(),
                    _ => Vec::new(),
                };
                for id in ids {
                    if let Some(tail) = id.strip_prefix(&prefix) {
                        if let Some((first, _)) = tail.split_once('/') {
                            keys.insert(format!("{first}/"));
                        } else {
                            keys.insert(tail.to_owned());
                        }
                    }
                }
            }
            return listing(keys.into_iter().collect());
        }
        if !write_method(method) {
            return Err(unsupported());
        }
        if let Some(prefix) = path.strip_prefix("sys/leases/revoke-prefix/") {
            reject_unknown(body, &["sync"])?;
            if body.get("sync").is_some_and(|v| !v.is_boolean()) {
                return Err(bad("sync must be boolean"));
            }
            let prefix = prefix.trim_end_matches('/');
            if prefix.is_empty()
                || !candidate
                    .mounts
                    .iter()
                    .any(|(name, mount)| match &mount.backend {
                        Backend::Ssh(_) | Backend::Kubernetes(_) => {
                            prefix == name.trim_end_matches('/')
                                || prefix == format!("{name}creds")
                                || prefix.starts_with(&format!("{name}creds/"))
                        }
                        Backend::Pki(_) => {
                            prefix == name.trim_end_matches('/')
                                || prefix == format!("{name}issue")
                                || prefix.starts_with(&format!("{name}issue/"))
                                || prefix == format!("{name}sign")
                                || prefix.starts_with(&format!("{name}sign/"))
                                || prefix.starts_with(&format!("{name}issuer/"))
                                    && (prefix.contains("/issue/") || prefix.contains("/sign/"))
                        }
                        _ => false,
                    })
            {
                return Err(error(
                    501,
                    "requested lease prefix is outside registered dynamic credential engines",
                ));
            }
            let boundary = format!("{prefix}/");
            let clock = now.max(self.lease_clock);
            let mut changed = false;
            for mount in candidate.mounts.values_mut() {
                match &mut mount.backend {
                    Backend::Ssh(engine) => {
                        let old = engine.leases.len();
                        engine.leases.retain(|_, lease| {
                            lease.id != prefix && !lease.id.starts_with(&boundary)
                        });
                        changed |= old != engine.leases.len();
                    }
                    Backend::Pki(engine) => changed |= engine.revoke_prefix(prefix, clock),
                    Backend::Kubernetes(engine) => changed |= engine.revoke_prefix(prefix),
                    _ => {}
                }
            }
            if changed {
                self.namespaces.insert(namespace.into(), candidate);
                self.lease_clock = clock;
            }
            return Ok(empty(changed));
        }
        let (action, path_id) = if path == "sys/leases/lookup" {
            ("lookup", None)
        } else if path == "sys/leases/revoke" {
            ("revoke", None)
        } else if path == "sys/leases/renew" {
            ("renew", None)
        } else if let Some(id) = path.strip_prefix("sys/leases/revoke/") {
            ("revoke", Some(id))
        } else if let Some(id) = path.strip_prefix("sys/leases/renew/") {
            ("renew", Some(id))
        } else {
            return Err(error(
                501,
                "lease administration surface is not implemented",
            ));
        };
        let fields = match action {
            "lookup" => &["lease_id"][..],
            "renew" => &["lease_id", "increment"][..],
            _ => &["lease_id", "sync"][..],
        };
        reject_unknown(body, fields)?;
        if body.get("sync").is_some_and(|v| !v.is_boolean()) {
            return Err(bad("sync must be boolean"));
        }
        if let Some(increment) = body.get("increment")
            && increment.as_u64().is_none()
        {
            return Err(bad("increment must be a nonnegative integer"));
        }
        let id = body
            .get("lease_id")
            .map(|v| v.as_str().ok_or_else(|| bad("lease_id must be a string")))
            .transpose()?;
        if let (Some(body_id), Some(path_id)) = (id, path_id)
            && body_id != path_id
        {
            return Err(bad("lease_id conflicts with the authorized request path"));
        }
        let id = id.or(path_id).ok_or_else(|| bad("lease_id is required"))?;
        valid_path(id)?;
        enum LeaseLocation {
            Ssh { mount: String, digest: String },
            Pki { mount: String, serial: String },
            Kubernetes { mount: String },
        }
        let location =
            candidate
                .mounts
                .iter()
                .find_map(|(name, mount)| match &mount.backend {
                    Backend::Ssh(engine) => engine
                        .leases
                        .iter()
                        .find(|(_, lease)| lease.id == id)
                        .map(|(digest, _)| LeaseLocation::Ssh {
                            mount: name.clone(),
                            digest: digest.clone(),
                        }),
                    Backend::Kubernetes(engine) if engine.contains_lease(id) => {
                        Some(LeaseLocation::Kubernetes {
                            mount: name.clone(),
                        })
                    }
                    Backend::Pki(engine) => {
                        engine.lease_location(id).map(|serial| LeaseLocation::Pki {
                            mount: name.clone(),
                            serial,
                        })
                    }
                    _ => None,
                });
        let Some(location) = location else {
            return if action == "revoke" {
                Ok(empty(false))
            } else {
                Err(bad("lease not found"))
            };
        };
        let clock = now.max(self.lease_clock);
        match location {
            LeaseLocation::Kubernetes { mount } => {
                let Backend::Kubernetes(engine) = &mut candidate
                    .mounts
                    .get_mut(&mount)
                    .ok_or_else(not_found)?
                    .backend
                else {
                    return Err(not_found());
                };
                match action {
                    "lookup" => Ok(ok(
                        match observed {
                            Some(time) => engine.lease_lookup_observed(id, time)?,
                            None => engine.lease_lookup(id, clock)?,
                        },
                        false,
                    )),
                    "renew" => Err(bad("Kubernetes token leases are not renewable")),
                    _ => {
                        let changed = engine.retire_lease(id);
                        if changed {
                            self.namespaces.insert(namespace.into(), candidate);
                            self.lease_clock = clock;
                        }
                        Ok(empty(changed))
                    }
                }
            }
            LeaseLocation::Ssh { mount, digest } => {
                let Backend::Ssh(engine) = &mut candidate
                    .mounts
                    .get_mut(&mount)
                    .ok_or_else(not_found)?
                    .backend
                else {
                    return Err(not_found());
                };
                let lease = engine.leases.get(&digest).ok_or_else(not_found)?;
                match action {
                    "lookup" => Ok(ok(
                        json!({"id":lease.id,"path":lease.path,"issue_time":timestamp(lease.issued),
                        "expire_time":timestamp(lease.expires),"last_renewal":Value::Null,"renewable":false,"ttl":lease.expires.saturating_sub(clock)}),
                        false,
                    )),
                    "renew" => Err(bad("SSH OTP leases are not renewable")),
                    _ => {
                        engine.leases.remove(&digest);
                        self.namespaces.insert(namespace.into(), candidate);
                        self.lease_clock = clock;
                        Ok(empty(true))
                    }
                }
            }
            LeaseLocation::Pki { mount, serial } => {
                let Backend::Pki(engine) = &mut candidate
                    .mounts
                    .get_mut(&mount)
                    .ok_or_else(not_found)?
                    .backend
                else {
                    return Err(not_found());
                };
                match action {
                    "lookup" => Ok(ok(engine.lease_lookup(&serial, clock)?, false)),
                    "renew" => Err(bad("PKI certificate leases are not renewable")),
                    _ => {
                        let changed = engine.revoke_lease(&serial, clock)?;
                        if changed {
                            self.namespaces.insert(namespace.into(), candidate);
                            self.lease_clock = clock;
                        }
                        Ok(empty(changed))
                    }
                }
            }
        }
    }
}
