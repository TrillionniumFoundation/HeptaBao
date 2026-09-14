//! Online dynamic-secret lifetime and administration for the SSH OTP profile.
//! No external provider, database account, CA or general lease worker is implied.
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
    pub(crate) fn is_ssh_service_route(&self, namespace: &str, path: &str) -> bool {
        self.ssh_mount(namespace, path).is_some_and(|mount| {
            let relative = &path[mount.len()..];
            relative == "verify" || relative.starts_with("creds/")
        })
    }
    pub(crate) fn is_ssh_verification(&self, namespace: &str, method: &str, path: &str) -> bool {
        write_method(method)
            && self
                .ssh_mount(namespace, path)
                .is_some_and(|mount| &path[mount.len()..] == "verify")
    }
    pub(crate) fn has_live_leases(&self) -> bool {
        self.namespaces.values().any(|state| {
            state.mounts.values().any(
                |mount| matches!(&mount.backend, Backend::Ssh(engine) if !engine.leases.is_empty()),
            )
        })
    }
    pub(crate) fn has_lease_state(&self) -> bool {
        self.lease_clock != 0
            || self.namespaces.values().any(|state| {
                state
                    .mounts
                    .values()
                    .any(|mount| matches!(mount.backend, Backend::Ssh(_)))
            })
    }
    pub(crate) fn validate_lease_state(&self) -> Result<()> {
        for state in self.namespaces.values() {
            for (name, mount) in &state.mounts {
                if let Backend::Ssh(engine) = &mount.backend {
                    engine.validate(name, self.lease_clock)?;
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
                    if let Backend::Ssh(engine) = &mount.backend {
                        owners.extend(
                            engine
                                .leases
                                .values()
                                .map(|lease| (namespace.clone(), lease.owner.clone())),
                        );
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
            state.mounts.values().any(
                |mount| matches!(&mount.backend,Backend::Ssh(engine) if !engine.leases.is_empty()),
            )
        });
        if !any {
            return false;
        }
        let mut changed = now > self.lease_clock;
        self.lease_clock = self.lease_clock.max(now);
        for (namespace, state) in &mut self.namespaces {
            for mount in state.mounts.values_mut() {
                if let Backend::Ssh(engine) = &mut mount.backend {
                    let before = engine.leases.len();
                    engine.leases.retain(|_, lease| {
                        lease.expires > self.lease_clock
                            && live.contains(&(namespace.clone(), lease.owner.clone()))
                    });
                    changed |= before != engine.leases.len();
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
                if let Backend::Ssh(engine) = &mount.backend {
                    for lease in engine.leases.values() {
                        if let Some(tail) = lease.id.strip_prefix(&prefix) {
                            if let Some((first, _)) = tail.split_once('/') {
                                keys.insert(format!("{first}/"));
                            } else {
                                keys.insert(tail.to_owned());
                            }
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
                || !candidate.mounts.iter().any(|(name, mount)| {
                    matches!(mount.backend, Backend::Ssh(_))
                        && (prefix == name.trim_end_matches('/')
                            || prefix == format!("{name}creds")
                            || prefix.starts_with(&format!("{name}creds/")))
                })
            {
                return Err(error(
                    501,
                    "this profile revokes only a registered SSH credential prefix, not token or external-provider leases",
                ));
            }
            let boundary = format!("{prefix}/");
            let mut changed = false;
            for mount in candidate.mounts.values_mut() {
                if let Backend::Ssh(engine) = &mut mount.backend {
                    let old = engine.leases.len();
                    engine
                        .leases
                        .retain(|_, lease| lease.id != prefix && !lease.id.starts_with(&boundary));
                    changed |= old != engine.leases.len();
                }
            }
            if changed {
                self.namespaces.insert(namespace.into(), candidate);
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
        let location = candidate.mounts.iter().find_map(|(name, mount)| {
            if let Backend::Ssh(engine) = &mount.backend {
                engine
                    .leases
                    .iter()
                    .find(|(_, lease)| lease.id == id)
                    .map(|(digest, _)| (name.clone(), digest.clone()))
            } else {
                None
            }
        });
        let Some((name, digest)) = location else {
            return if action == "revoke" {
                Ok(empty(false))
            } else {
                Err(bad("lease not found"))
            };
        };
        let Backend::Ssh(engine) = &mut candidate
            .mounts
            .get_mut(&name)
            .ok_or_else(not_found)?
            .backend
        else {
            return Err(not_found());
        };
        let lease = engine.leases.get(&digest).ok_or_else(not_found)?;
        match action {
            "lookup" => Ok(ok(
                json!({"id":lease.id,"path":lease.path,"issue_time":timestamp(lease.issued),
                "expire_time":timestamp(lease.expires),"last_renewal":Value::Null,"renewable":false,"ttl":lease.expires.saturating_sub(now.max(self.lease_clock))}),
                false,
            )),
            "renew" => Err(bad("SSH OTP leases are not renewable")),
            _ => {
                engine.leases.remove(&digest);
                self.namespaces.insert(namespace.into(), candidate);
                Ok(empty(true))
            }
        }
    }
}
