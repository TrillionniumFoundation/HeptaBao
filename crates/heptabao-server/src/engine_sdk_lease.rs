//! Typed encrypted SDK lease metadata. Only Service creates an issuer from its
//! admitted Principal; plugin JSON never creates a credential or owner.
use super::*;
use crate::auth::{LeaseOwner, ServiceOwnerProfile, Timestamp};

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Phase {
    Active,
    PendingRevoke,
    Revoked,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Lease {
    pub(crate) id: String,
    pub(crate) namespace: String,
    pub(crate) cluster: String,
    pub(crate) mount: String,
    pub(crate) path: String,
    pub(crate) backend: sdk::MountOwner,
    pub(crate) issuer: LeaseOwner,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) registration: Option<sdk_registration::Registration>,
    pub(crate) issued: Timestamp,
    pub(crate) expires: Timestamp,
    pub(crate) renewed: Option<Timestamp>,
    pub(crate) max_ttl_ns: u64,
    pub(crate) ttl_ns: u64,
    pub(crate) renewable: bool,
    pub(crate) phase: Phase,
    secret: SecretJson,
    data: SecretJson,
}
impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SDKLease([REDACTED])")
    }
}
impl Lease {
    pub(crate) fn new(binding: Binding, mut grant: Grant) -> Result<Self> {
        let Binding {
            id,
            namespace,
            cluster,
            mount,
            path,
            backend,
            issuer,
        } = binding;
        let issued = grant.issued;
        let ttl_ns = grant.ttl_ns;
        let max_ttl_ns = grant.max_ttl_ns;
        let renewable = grant.renewable;
        let expires = add_ns(issued, ttl_ns)?;
        let secret = std::mem::take(&mut grant.secret);
        let data = std::mem::take(&mut grant.data);
        let value = Self {
            id,
            namespace,
            cluster,
            mount,
            path,
            backend,
            issuer,
            registration: None,
            issued,
            expires,
            renewed: None,
            max_ttl_ns,
            ttl_ns,
            renewable,
            phase: Phase::Active,
            secret: SecretJson(secret),
            data: SecretJson(data),
        };
        value.validate(&value.namespace)?;
        Ok(value)
    }
    pub(crate) fn register(&mut self, registration: sdk_registration::Registration) -> Result<()> {
        if self.registration.is_some() {
            return Err(error(503, "SDK registration already exists"));
        }
        if registration.final_use() {
            self.phase = Phase::PendingRevoke;
            self.renewable = false;
        }
        self.registration = Some(registration);
        self.validate(&self.namespace)
    }
    pub(crate) fn parent_cleanup_required(
        &self,
        auth: &crate::auth::AuthState,
        at: Timestamp,
    ) -> Result<bool> {
        self.registration.as_ref().map_or_else(
            || {
                Ok(auth
                    .resolve_lease_owner_observed(
                        &self.issuer,
                        &self.namespace,
                        crate::auth::AuthorityTime::Precise(at),
                    )
                    .is_none())
            },
            |registration| {
                registration.parent_cleanup_required(&self.issuer, &self.namespace, auth, at)
            },
        )
    }
    pub(crate) fn callback(&self) -> Value {
        self.secret.0.clone()
    }
    pub(crate) fn issue_ns(&self) -> Result<u64> {
        epoch_ns(self.issued)
    }
    pub(crate) fn response_data(&self) -> Value {
        self.data.0.clone()
    }
    pub(crate) fn renew(&mut self, mut grant: Grant) -> Result<()> {
        if self.phase != Phase::Active || !self.renewable {
            return Err(bad("SDK lease is not renewable"));
        }
        let end = add_ns(self.issued, self.max_ttl_ns)?;
        if grant.issued >= end {
            return Err(bad("SDK lease reached maximum lifetime"));
        }
        self.max_ttl_ns = self.max_ttl_ns.min(grant.max_ttl_ns);
        self.ttl_ns = grant.ttl_ns.min(
            epoch_ns(add_ns(self.issued, self.max_ttl_ns)?)?
                .saturating_sub(epoch_ns(grant.issued)?),
        );
        if self.ttl_ns == 0 {
            return Err(bad("SDK lease reached maximum lifetime"));
        }
        self.expires = add_ns(grant.issued, self.ttl_ns)?;
        self.renewed = Some(grant.issued);
        self.renewable = grant.renewable;
        self.secret = SecretJson(std::mem::take(&mut grant.secret));
        self.data = SecretJson(std::mem::take(&mut grant.data));
        self.validate(&self.namespace)
    }
    pub(crate) fn revoke(&mut self) {
        self.phase = Phase::Revoked;
        self.renewable = false;
        self.secret = SecretJson(Value::Null);
        self.data = SecretJson(Value::Null);
    }
    pub(crate) fn validate(&self, namespace: &str) -> Result<()> {
        if let Some(registration) = &self.registration {
            registration.validate(self)?;
        }
        valid_path(&self.id)?;
        valid_path(self.mount.trim_end_matches('/'))?;
        valid_path(&self.path)?;
        self.issuer
            .validate_scope(namespace, ServiceOwnerProfile::CanonicalDigest)
            .map_err(|_| error(503, "SDK lease issuer scope rejected"))?;
        if self.namespace != namespace
            || self.cluster.is_empty()
            || self.id.len() > 4096
            || !self
                .id
                .starts_with(&format!("{}/", self.path.trim_end_matches('/')))
            || !self.path.starts_with(&self.mount)
            || self.backend.mount_incarnation == 0
            || self.backend.catalog_generation == 0
            || self.ttl_ns == 0
            || self.ttl_ns > self.max_ttl_ns
            || self.max_ttl_ns > i64::MAX as u64
            || self.expires < self.issued
            || self.expires > add_ns(self.issued, self.max_ttl_ns)?
            || self
                .renewed
                .is_some_and(|at| at < self.issued || at > self.expires)
            || (self.phase == Phase::Revoked
                && (!self.secret.is_null() || !self.data.is_null() || self.renewable))
            || (self.phase != Phase::Revoked
                && (!self.secret.is_object()
                    || self
                        .secret
                        .get("internal_data")
                        .is_none_or(|v| !v.is_object())
                    || !self.data.is_object()))
        {
            return Err(error(503, "SDK lease metadata rejected"));
        }
        if self.phase != Phase::Revoked {
            let object = self
                .secret
                .as_object()
                .ok_or_else(|| error(503, "SDK Secret object rejected"))?;
            if object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "internal_data" | "LeaseID" | "lease" | "max_ttl" | "renewable"
                )
            }) || object.get("LeaseID").and_then(Value::as_str) != Some("")
                || object.get("renewable").and_then(Value::as_bool).is_none()
                || ["lease", "max_ttl"].iter().any(|key| {
                    object
                        .get(*key)
                        .is_none_or(|v| v.as_u64().is_none_or(|n| n > i64::MAX as u64))
                })
            {
                return Err(error(503, "SDK Secret wire metadata rejected"));
            }
        }
        if crate::secret_serde::to_vec(&self.secret.0, 256 * 1024).is_err()
            || crate::secret_serde::to_vec(&self.data.0, 256 * 1024).is_err()
        {
            return Err(error(503, "SDK lease payload exceeds bound"));
        }
        Ok(())
    }
    pub(crate) fn same_backend(&self, owner: &sdk::MountOwner) -> bool {
        self.backend.plugin == owner.plugin
            && self.backend.version == owner.version
            && self.backend.catalog_generation == owner.catalog_generation
            && self.backend.mount_incarnation == owner.mount_incarnation
    }
    pub(crate) fn lookup(&self, at: Timestamp) -> Result<Value> {
        if self.phase != Phase::Active || at >= self.expires {
            return Err(bad("invalid lease"));
        }
        Ok(
            json!({"id":self.id,"path":self.path,"issue_time":self.issued.local_rfc3339().map_err(|_|error(503,"SDK public timestamp rejected"))?,"expire_time":self.expires.local_rfc3339().map_err(|_|error(503,"SDK public timestamp rejected"))?,"last_renewal":self.renewed.map(Timestamp::local_rfc3339).transpose().map_err(|_|error(503,"SDK public timestamp rejected"))?,"renewable":self.renewable,"ttl":self.expires.lookup_remaining_seconds(at).map_err(|_|error(503,"SDK lease clock rejected"))?}),
        )
    }
}
pub(crate) struct Binding {
    pub(crate) id: String,
    pub(crate) namespace: String,
    pub(crate) cluster: String,
    pub(crate) mount: String,
    pub(crate) path: String,
    pub(crate) backend: sdk::MountOwner,
    pub(crate) issuer: LeaseOwner,
}
pub(crate) struct Grant {
    pub(crate) issued: Timestamp,
    pub(crate) ttl_ns: u64,
    pub(crate) max_ttl_ns: u64,
    pub(crate) renewable: bool,
    pub(crate) secret: Value,
    pub(crate) data: Value,
}
impl Drop for Grant {
    fn drop(&mut self) {
        wipe_json(&mut self.secret);
        wipe_json(&mut self.data);
    }
}
pub(crate) fn epoch_ns(at: Timestamp) -> Result<u64> {
    u64::try_from(at.duration_since_epoch().as_nanos())
        .ok()
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or_else(|| error(503, "SDK timestamp exceeds supported range"))
}
fn add_ns(at: Timestamp, ns: u64) -> Result<Timestamp> {
    let end = at
        .duration_since_epoch()
        .checked_add(std::time::Duration::from_nanos(ns))
        .ok_or_else(|| bad("SDK lease duration overflow"))?;
    Timestamp::from_wall(end).map_err(|_| bad("SDK lease duration overflow"))
}
impl EngineState {
    pub(crate) fn sdk_mount_leases(
        &self,
        namespace: &str,
        mount: &str,
        owner: &sdk::MountOwner,
    ) -> Result<Vec<Lease>> {
        let rows = self
            .namespaces
            .get(namespace)
            .ok_or_else(not_found)?
            .sdk_leases
            .values()
            .filter(|lease| lease.mount == mount && lease.phase != Phase::Revoked)
            .cloned()
            .collect::<Vec<_>>();
        if rows.iter().any(|lease| !lease.same_backend(owner)) {
            return Err(error(503, "SDK retirement lease mount owner mismatch"));
        }
        Ok(rows)
    }
    pub(crate) fn sdk_retired_mount_leases(
        &self,
        namespace: &str,
        mount: &str,
        owner: &sdk::MountOwner,
    ) -> Result<Vec<Lease>> {
        Ok(self
            .namespaces
            .get(namespace)
            .ok_or_else(not_found)?
            .sdk_leases
            .values()
            .filter(|lease| {
                lease.mount == mount && lease.phase == Phase::Revoked && lease.same_backend(owner)
            })
            .cloned()
            .collect())
    }
    pub(crate) fn sdk_cleanup_candidate(
        &self,
        auth: &crate::auth::AuthState,
        at: Timestamp,
        after: Option<(&str, &str)>,
    ) -> Result<Option<Lease>> {
        let mut first = None;
        for lease in self
            .namespaces
            .values()
            .flat_map(|namespace| namespace.sdk_leases.values())
        {
            let eligible = lease.phase == Phase::PendingRevoke
                || (lease.phase == Phase::Active
                    && (at >= lease.expires || lease.parent_cleanup_required(auth, at)?));
            if !eligible {
                continue;
            }
            if first.is_none() {
                first = Some(lease.clone());
            }
            if after.is_none_or(|key| (lease.namespace.as_str(), lease.id.as_str()) > key) {
                return Ok(Some(lease.clone()));
            }
        }
        Ok(first)
    }
    pub(crate) fn has_live_sdk_leases(&self) -> bool {
        self.namespaces.values().any(|ns| {
            ns.sdk_leases
                .values()
                .any(|lease| lease.phase != Phase::Revoked)
        })
    }
    pub(crate) fn sdk_lease_clock_floor(&self) -> Option<Timestamp> {
        self.sdk_lease_clock
    }
    pub(crate) fn observe_sdk_lease_clock(&mut self, at: Timestamp) -> bool {
        let next = self.sdk_lease_clock.map_or(at, |floor| at.max(floor));
        let changed = self.sdk_lease_clock != Some(next);
        self.sdk_lease_clock = Some(next);
        changed
    }
    pub(crate) fn validate_sdk_lease_clock(&self, previous: Option<&Self>) -> Result<()> {
        self.validate_sdk_registration_successor(previous)?;
        if previous
            .and_then(|old| old.sdk_lease_clock)
            .is_some_and(|floor| self.sdk_lease_clock.is_none_or(|at| at < floor))
        {
            return Err(error(503, "SDK lease clock was removed or rolled back"));
        }
        if self
            .namespaces
            .values()
            .flat_map(|ns| ns.sdk_leases.values())
            .any(|lease| {
                self.sdk_lease_clock.is_none_or(|floor| {
                    floor < lease.issued || lease.renewed.is_some_and(|at| floor < at)
                })
            })
        {
            return Err(error(
                503,
                "SDK lease clock does not cover registered leases",
            ));
        }
        Ok(())
    }
    pub(crate) fn has_sdk_lease_state(&self) -> bool {
        self.sdk_lease_clock.is_some()
            || self.namespaces.values().any(|ns| !ns.sdk_leases.is_empty())
    }
    pub(crate) fn sdk_lease(&self, namespace: &str, id: &str) -> Option<Lease> {
        self.namespaces.get(namespace)?.sdk_leases.get(id).cloned()
    }
    pub(crate) fn store_sdk_lease(&mut self, lease: Lease) -> Result<()> {
        lease.validate(&lease.namespace)?;
        let ns = self
            .namespaces
            .get_mut(&lease.namespace)
            .ok_or_else(not_found)?;
        if ns.sdk_leases.len() >= 10_000 && !ns.sdk_leases.contains_key(&lease.id) {
            return Err(error(507, "SDK lease registry capacity exhausted"));
        }
        ns.sdk_leases.insert(lease.id.clone(), lease);
        Ok(())
    }
    pub(crate) fn sdk_lease_owners(&self) -> BTreeSet<(String, LeaseOwner)> {
        self.namespaces
            .iter()
            .flat_map(|(n, s)| {
                s.sdk_leases
                    .values()
                    .map(move |l| (n.clone(), l.issuer.clone()))
            })
            .collect()
    }
    pub(crate) fn validate_sdk_lease_cluster(&self, cluster: &str) -> Result<()> {
        if self
            .namespaces
            .values()
            .any(|ns| ns.sdk_leases.values().any(|l| l.cluster != cluster))
        {
            return Err(error(503, "SDK lease cluster rejected"));
        }
        Ok(())
    }
    pub(crate) fn validate_sdk_leases(&self) -> Result<()> {
        self.validate_sdk_lease_clock(None)?;
        for (namespace, ns) in &self.namespaces {
            if ns.sdk_leases.len() > 10_000 {
                return Err(error(503, "SDK lease registry exceeds bound"));
            }
            for (id, lease) in &ns.sdk_leases {
                lease.validate(namespace)?;
                if id != &lease.id
                    || !self.sdk_catalog.known_generation(
                        &lease.backend.plugin,
                        &lease.backend.version,
                        lease.backend.catalog_generation,
                    )
                {
                    return Err(error(503, "SDK lease catalog owner rejected"));
                }
                if lease.phase != Phase::Revoked
                    && self.sdk_mount_binding(namespace, &lease.mount).is_none_or(
                        |(mount, owner)| mount != lease.mount || !lease.same_backend(&owner),
                    )
                {
                    return Err(error(503, "SDK lease mount owner rejected"));
                }
            }
        }
        Ok(())
    }
}
