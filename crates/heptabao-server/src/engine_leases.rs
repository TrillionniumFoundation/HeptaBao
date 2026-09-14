//! Online dynamic-secret lifetime and administration for local SSH OTP and PKI
//! issuance. External-provider renewal callbacks remain outside this module.
use super::*;
use crate::auth::LeaseIssuer;

impl EngineState {
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
        self.pki_mount(namespace, path)
            .is_some_and(|mount| path[mount.len()..].starts_with("issue/"))
    }
    pub(crate) fn is_lease_service_route(&self, namespace: &str, path: &str) -> bool {
        self.is_ssh_service_route(namespace, path) || self.is_pki_issue_route(namespace, path)
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
                _ => false,
            })
        })
    }
    pub(crate) fn has_lease_state(&self) -> bool {
        self.lease_clock != 0
            || self.namespaces.values().any(|state| {
                state
                    .mounts
                    .values()
                    .any(|mount| matches!(mount.backend, Backend::Ssh(_) | Backend::Pki(_)))
            })
    }
    pub(crate) fn validate_lease_state(&self) -> Result<()> {
        for state in self.namespaces.values() {
            for (name, mount) in &state.mounts {
                match &mount.backend {
                    Backend::Ssh(engine) => engine.validate(name, self.lease_clock)?,
                    Backend::Pki(engine) => engine.validate(name, self.lease_clock)?,
                    _ => {}
                }
            }
        }
        Ok(())
    }
    pub(crate) fn lease_owners(&self) -> BTreeSet<(String, String)> {
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
                        _ => {}
                    }
                    owners
                })
            })
            .collect()
    }
    pub(crate) fn reconcile_lease_state(
        &mut self,
        now: u64,
        live: &BTreeSet<(String, String)>,
    ) -> bool {
        let any = self.namespaces.values().any(|state| {
            state.mounts.values().any(|mount| match &mount.backend {
                Backend::Ssh(engine) => !engine.leases.is_empty(),
                Backend::Pki(engine) => engine.has_live_leases(self.lease_clock),
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
        owner: Option<&LeaseIssuer>,
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
            engine.issue(&mount, name, body, &owner.digest, owner.expires_at, now)?
        };
        if response.mutated {
            self.namespaces.insert(namespace.into(), candidate);
            self.lease_clock = now;
        }
        Ok(response)
    }
    pub(crate) fn handle_service_pki(
        &mut self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        owner: &LeaseIssuer,
        now: u64,
    ) -> Result<EngineResponse> {
        if !write_method(method) {
            return Err(unsupported());
        }
        let mount = self
            .pki_mount(namespace, path)
            .ok_or_else(not_found)?
            .to_owned();
        let relative = &path[mount.len()..];
        let role = relative.strip_prefix("issue/").ok_or_else(not_found)?;
        if role.is_empty() || role.contains('/') {
            return Err(not_found());
        }
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
        let response = engine.issue(&mount, role, body, &owner.digest, owner.expires_at, now)?;
        if response.mutated {
            self.namespaces.insert(namespace.into(), candidate);
            self.lease_clock = now;
        }
        Ok(response)
    }

    pub(crate) fn handle_lease_admin(
        &mut self,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
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
                        Backend::Ssh(_) => {
                            prefix == name.trim_end_matches('/')
                                || prefix == format!("{name}creds")
                                || prefix.starts_with(&format!("{name}creds/"))
                        }
                        Backend::Pki(_) => {
                            prefix == name.trim_end_matches('/')
                                || prefix == format!("{name}issue")
                                || prefix.starts_with(&format!("{name}issue/"))
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
