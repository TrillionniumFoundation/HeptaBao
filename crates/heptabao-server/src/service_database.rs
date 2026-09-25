//! Database effects have a durable intent BEFORE provider entry and a source-
//! bound readback BEFORE completion. A remote error never erases an intent.
//! Provider-side monotonically sequenced tombstones fence delayed old leaders.
use super::*;
use crate::{
    auth::{LeaseOwner, ResolvedLeaseOwner, ServiceOwnerProfile},
    outbound::Target,
    postgres_wire::PgSession,
    valkey_wire::{RespValue, ValkeySession},
};
use heptabao_domain::SecretValue;
use heptabao_plugin_host::{PluginHostError, PluginOperation, SecretEnvironment};
use std::collections::BTreeSet;
use std::sync::Weak;

/// The provider has already been entered and its effect observed. No local
/// persistence failure can now mean that issuance/renewal/revocation was absent.
/// Keep the durable pending intent and expose only reconciliation metadata.
fn post_provider_publication_failure(error: Response, id: &str) -> Response {
    let mut body = json!({
        "errors": ["provider effect observed but local completion not established; durable intent retained; do not blindly retry"],
        "lease_id": id,
        "reconcile_required": true,
        "retry_allowed": false
    });
    if let Some(reference) = error.body.get("recovery_reference").and_then(Value::as_str) {
        body["recovery_reference"] = json!(reference);
    }
    Response { status: 503, body }
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct DatabaseState {
    mounts: BTreeMap<String, BTreeMap<String, DatabaseMount>>,
    clock: u64,
    #[serde(default, skip_serializing_if = "provider_fence_is_zero")]
    provider_fence: u64,
}

fn provider_fence_is_zero(value: &u64) -> bool {
    *value == 0
}
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct DatabaseMount {
    connections: BTreeMap<String, Connection>,
    roles: BTreeMap<String, DatabaseRole>,
    leases: BTreeMap<String, DatabaseLease>,
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
enum DatabaseProvider {
    #[default]
    Postgresql,
    Valkey,
    Plugin,
}
fn is_postgresql_provider(provider: &DatabaseProvider) -> bool {
    *provider == DatabaseProvider::Postgresql
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Connection {
    #[serde(default, skip_serializing_if = "is_postgresql_provider")]
    provider: DatabaseProvider,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    plugin_id: Option<String>,
    connection_url: String,
    username: String,
    password: PrivateString,
    allowed_roles: BTreeSet<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct PrivateString(String);
impl Drop for PrivateString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DatabaseRole {
    db_name: String,
    provider_role: String,
    default_ttl: u64,
    max_ttl: u64,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
enum Phase {
    PendingIssue,
    Active,
    PendingRenew,
    PendingRevoke,
    Revoked,
    Quarantined,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DatabaseLease {
    id: String,
    provider_id: String,
    username: String,
    db_name: String,
    provider_role: String,
    owner: LeaseOwner,
    issued: u64,
    expires: u64,
    max_expires: u64,
    last_renewal: Option<u64>,
    seq: u64,
    phase: Phase,
    password: Option<PrivateString>,
    request_digest: String,
}

pub(super) struct DatabaseEffectPlan {
    namespace: String,
    mount: String,
    now: u64,
    started: std::time::Instant,
    outbound: crate::outbound::Outbound,
    ha: Option<Arc<Mutex<HaProcess>>>,
    plugin: Option<plugin::SharedDatabasePlugin>,
    connection: Connection,
    fence_id: String,
    lease: DatabaseLease,
    // Kept through provider execution and local finalization. Dropping an
    // abandoned plan makes its durable intent eligible for maintenance again.
    _in_flight: Arc<()>,
}

/// Advisory process-local ownership only; never persisted as lease authority.
/// Weak entries cannot retain abandoned work or survive a Service reopen.
#[derive(Default)]
pub(super) struct DatabaseFlights {
    leases: BTreeMap<(String, String, String), Weak<()>>,
}

impl DatabaseFlights {
    fn prune(&mut self) {
        self.leases.retain(|_, flight| flight.strong_count() != 0);
    }

    fn track(&mut self, namespace: &str, mount: &str, id: &str) -> Arc<()> {
        self.prune();
        let key = (namespace.to_owned(), mount.to_owned(), id.to_owned());
        if let Some(flight) = self.leases.get(&key).and_then(Weak::upgrade) {
            return flight;
        }
        let flight = Arc::new(());
        self.leases.insert(key, Arc::downgrade(&flight));
        flight
    }

    fn contains(&self, namespace: &str, mount: &str, id: &str) -> bool {
        self.leases
            .get(&(namespace.to_owned(), mount.to_owned(), id.to_owned()))
            .is_some_and(|flight| flight.strong_count() != 0)
    }
}

fn database_maintenance_candidate(
    phase: &Phase,
    expires: u64,
    now: u64,
    live_owner: bool,
    in_flight: bool,
) -> bool {
    !in_flight
        && (phase == &Phase::Revoked
            || (phase != &Phase::Quarantined
                && (phase != &Phase::Active || expires <= now || !live_owner)))
}

pub(super) struct DatabaseMaintenance {
    fingerprint: String,
    now: u64,
    plan: DatabaseEffectPlan,
}

pub(super) struct DatabaseBatchEffectPlan {
    plans: Vec<DatabaseEffectPlan>,
}

pub(super) type DatabaseBatchEffectResult = Vec<Result<(), Response>>;

pub(super) struct DatabaseConfigPlan {
    namespace: String,
    mount: String,
    mount_incarnation: u64,
    authority: plugin::PluginResponseAuthority,
    key: String,
    connection: Connection,
    plugin: Option<plugin::SharedDatabasePlugin>,
    expected_mount_digest: [u8; 32],
    outbound: crate::outbound::Outbound,
    now: u64,
}

#[derive(Serialize)]
struct PluginDatabaseRequest<'a> {
    action: &'a str,
    namespace: &'a str,
    mount: &'a str,
    connection: &'a str,
    connection_url: &'a str,
    manager_username: &'a str,
    manager_password: &'a str,
    lease_id: Option<&'a str>,
    provider_id: Option<&'a str>,
    username: Option<&'a str>,
    password: Option<&'a str>,
    provider_role: Option<&'a str>,
    seq: Option<u64>,
    request_digest: Option<&'a str>,
    expires: Option<u64>,
}

impl DatabaseConfigPlan {
    pub(super) fn execute(&self) -> Result<(), Response> {
        match self.connection.provider {
            DatabaseProvider::Postgresql => {
                let mut pg = self.connection.session(&self.outbound).map_err(failure)?;
                let response = pg
                    .scalar("SELECT current_user::text", &[])
                    .map_err(failure)?;
                if response != self.connection.username {
                    return Err(failure("PostgreSQL manager identity mismatch"));
                }
                if pg
                    .scalar("SELECT heptabao_provider.protocol()", &[])
                    .map_err(failure)?
                    != "heptabao-postgresql-provider-v2"
                {
                    return Err(failure(
                        "PostgreSQL provider contract is not installed or mismatched",
                    ));
                }
            }
            DatabaseProvider::Valkey => {
                let mut valkey = self
                    .connection
                    .valkey_session(&self.outbound)
                    .map_err(failure)?;
                if !resp_text_equals(&valkey.command(&["PING"]).map_err(failure)?, "PONG") {
                    return Err(failure("Valkey provider did not acknowledge PING"));
                }
                let whoami = valkey.command(&["ACL", "WHOAMI"]).map_err(failure)?;
                if !resp_text_equals(&whoami, &self.connection.username) {
                    return Err(failure("Valkey manager identity mismatch"));
                }
            }
            DatabaseProvider::Plugin => {
                let host = self
                    .plugin
                    .as_ref()
                    .ok_or_else(|| failure("database plugin is not admitted by this deployment"))?;
                let request = PluginDatabaseRequest {
                    action: "configure",
                    namespace: &self.namespace,
                    mount: self.mount.trim_end_matches('/'),
                    connection: &self.key,
                    connection_url: &self.connection.connection_url,
                    manager_username: &self.connection.username,
                    manager_password: &self.connection.password.0,
                    lease_id: None,
                    provider_id: None,
                    username: None,
                    password: None,
                    provider_role: None,
                    seq: None,
                    request_digest: None,
                    expires: None,
                };
                let encoded = serde_json::to_vec(&request)
                    .map_err(|_| failure("database plugin request encoding failed"))?;
                let request = SecretValue::new(encoded)
                    .map_err(|_| failure("database plugin request exceeds runtime bound"))?;
                let response = host
                    .lock()
                    .map_err(|_| failure("database plugin host lock unavailable"))?
                    .invoke(PluginOperation::Read, &request, &SecretEnvironment::new())
                    .map_err(database_plugin_config_failure)?;
                let observed = crate::auth::parse_strict_json(response.expose())
                    .map_err(|_| failure("database plugin returned invalid JSON"))?;
                let object = observed
                    .as_object()
                    .ok_or_else(|| failure("database plugin response must be an object"))?;
                if object.len() == 2
                    && object.get("configured") == Some(&json!(false))
                    && object
                        .get("error")
                        .and_then(Value::as_str)
                        .is_some_and(|value| {
                            !value.is_empty()
                                && value.len() <= 64
                                && value
                                    .bytes()
                                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                        })
                {
                    return Err(invalid("database plugin rejected configuration"));
                }
                if object.len() != 2
                    || object.get("configured") != Some(&json!(true))
                    || object.get("manager_identity") != Some(&json!(self.connection.username))
                {
                    return Err(failure("database plugin configuration readback mismatch"));
                }
            }
        }
        Ok(())
    }
}

fn database_mount_digest(mount: Option<&DatabaseMount>) -> Result<[u8; 32], Response> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(&mount).map_err(|_| failure("database mount fence encoding failed"))?,
    );
    Ok(crypto::digest(&bytes))
}

impl DatabaseMaintenance {
    pub(super) fn execute(&self) -> Result<(), Response> {
        self.plan.execute()
    }
}

impl DatabaseBatchEffectPlan {
    pub(super) fn execute(&self) -> DatabaseBatchEffectResult {
        let mut results = Vec::with_capacity(self.plans.len());
        for plan in &self.plans {
            let result = plan.execute();
            let stop = result.is_err();
            results.push(result);
            if stop {
                break;
            }
        }
        results
    }
}

impl DatabaseEffectPlan {
    fn completed_now(&self) -> u64 {
        std::time::Duration::from_secs(self.now)
            .saturating_add(self.started.elapsed())
            .as_secs()
    }

    /// Execute only the remote provider side effect and readback. This value is
    /// fully owned so callers may drop the global Service writer while the
    /// bounded network operation is in flight.
    pub(super) fn execute(&self) -> Result<(), Response> {
        let indeterminate = || Response {
            status: 503,
            body: json!({
                "errors":["provider outcome indeterminate; durable intent retained"],
                "lease_id":self.lease.id,
                "reconcile_required":true
            }),
        };
        if let Some(ha) = &self.ha {
            ha.lock_for_request()
                .map_err(|_| failure("HA provider fence unavailable"))?
                .ensure_linearizable()
                .map_err(|_| failure("HA provider fence unavailable"))?;
        }
        if self.connection.provider == DatabaseProvider::Plugin {
            return self.execute_plugin();
        }
        if self.connection.provider == DatabaseProvider::Valkey {
            return self.execute_valkey();
        }
        let mut pg = self
            .connection
            .session(&self.outbound)
            .map_err(|_| indeterminate())?;
        let seq = self.lease.seq.to_string();
        let expires = self.lease.expires.to_string();

        // A revoke may already have reached the terminal retirement boundary
        // before the caller lost its response or local publication. Exact
        // provider readback makes that state safely resumable without recreating
        // either the ledger row or the generated PostgreSQL role.
        if self.lease.phase == Phase::PendingRevoke {
            let retired = pg
                .scalar(
                    "SELECT heptabao_provider.retired($1,$2,$3,$4::bigint)::text",
                    &[
                        &self.fence_id,
                        &self.lease.provider_id,
                        &self.lease.username,
                        &seq,
                    ],
                )
                .map_err(|_| indeterminate())?;
            if retired == "true" {
                return Ok(());
            }
        }

        pg.scalar(
            "SELECT heptabao_provider.apply($1,$2,$3,$4::bigint,$5,$6::bigint,$7,$8,$9)::text",
            &[
                &self.fence_id,
                &self.lease.provider_id,
                &self.lease.username,
                &seq,
                action(&self.lease),
                &expires,
                &self.lease.provider_role,
                self.lease
                    .password
                    .as_ref()
                    .map(|p| p.0.as_str())
                    .unwrap_or(""),
                &self.lease.request_digest,
            ],
        )
        .map_err(|_| indeterminate())?;

        // A separate readback proves the committed provider state rather than
        // treating a function return value as transaction completion.
        let observed = pg
            .scalar(
                "SELECT heptabao_provider.observe($1)::text",
                &[&self.lease.provider_id],
            )
            .map_err(|_| indeterminate())?;
        let observed =
            crate::auth::parse_strict_json(observed.as_bytes()).map_err(|_| indeterminate())?;
        let matched = observed.get("found") == Some(&json!(true))
            && observed["fence_id"] == self.fence_id
            && observed["lease_id"] == self.lease.provider_id
            && observed["username"] == self.lease.username
            && observed["seq"].as_u64() == Some(self.lease.seq)
            && observed["request_digest"] == self.lease.request_digest
            && observed["action"] == action(&self.lease)
            && observed["expires"].as_u64() == Some(self.lease.expires);
        let valid = if self.lease.phase == Phase::PendingRevoke {
            observed.get("login") == Some(&json!(false))
                && observed["active_sessions"].as_u64() == Some(0)
        } else {
            observed.get("controlled") == Some(&json!(true))
                && observed.get("login") == Some(&json!(true))
                && self.lease.expires > self.now
        };
        if !matched || !valid {
            return Err(Response {
                status: 503,
                body: json!({
                    "errors":["provider completion not established; pending intent retained"],
                    "lease_id":self.lease.id,
                    "reconcile_required":true
                }),
            });
        }

        if self.lease.phase == Phase::PendingRevoke {
            let retired = pg
                .scalar(
                    "SELECT heptabao_provider.retire($1,$2,$3,$4::bigint)::text",
                    &[
                        &self.fence_id,
                        &self.lease.provider_id,
                        &self.lease.username,
                        &seq,
                    ],
                )
                .map_err(|_| indeterminate())?;
            if retired != "true" {
                return Err(indeterminate());
            }
            let readback = pg
                .scalar(
                    "SELECT heptabao_provider.retired($1,$2,$3,$4::bigint)::text",
                    &[
                        &self.fence_id,
                        &self.lease.provider_id,
                        &self.lease.username,
                        &seq,
                    ],
                )
                .map_err(|_| indeterminate())?;
            if readback != "true" {
                return Err(indeterminate());
            }
        }
        Ok(())
    }

    fn execute_plugin(&self) -> Result<(), Response> {
        let host = self
            .plugin
            .as_ref()
            .ok_or_else(|| failure("database plugin is not admitted by this deployment"))?;
        let (operation, action, expected_active) = match self.lease.phase {
            Phase::PendingIssue => (PluginOperation::Issue, "issue", true),
            Phase::PendingRenew => (PluginOperation::Renew, "renew", true),
            Phase::PendingRevoke => (PluginOperation::Revoke, "revoke", false),
            _ => return Err(failure("database plugin effect is not pending")),
        };
        let request = PluginDatabaseRequest {
            action,
            namespace: &self.namespace,
            mount: self.mount.trim_end_matches('/'),
            connection: &self.lease.db_name,
            connection_url: &self.connection.connection_url,
            manager_username: &self.connection.username,
            manager_password: &self.connection.password.0,
            lease_id: Some(&self.lease.id),
            provider_id: Some(&self.lease.provider_id),
            username: Some(&self.lease.username),
            password: self.lease.password.as_ref().map(|value| value.0.as_str()),
            provider_role: Some(&self.lease.provider_role),
            seq: Some(self.lease.seq),
            request_digest: Some(&self.lease.request_digest),
            expires: Some(self.lease.expires),
        };
        let encoded = serde_json::to_vec(&request)
            .map_err(|_| failure("database plugin request encoding failed"))?;
        let request = SecretValue::new(encoded)
            .map_err(|_| failure("database plugin request exceeds runtime bound"))?;
        let response = host
            .lock()
            .map_err(|_| failure("database plugin host lock unavailable"))?
            .invoke(operation, &request, &SecretEnvironment::new())
            .map_err(|error| database_plugin_effect_failure(error, &self.lease.id))?;
        let observed = crate::auth::parse_strict_json(response.expose())
            .map_err(|_| database_plugin_indeterminate(&self.lease.id))?;
        let object = observed
            .as_object()
            .ok_or_else(|| database_plugin_indeterminate(&self.lease.id))?;
        if object.len() != 7
            || object.get("applied") != Some(&json!(true))
            || object.get("provider_id") != Some(&json!(self.lease.provider_id))
            || object.get("seq").and_then(Value::as_u64) != Some(self.lease.seq)
            || object.get("request_digest") != Some(&json!(self.lease.request_digest))
            || object.get("username") != Some(&json!(self.lease.username))
            || object.get("active").and_then(Value::as_bool) != Some(expected_active)
            || object.get("expires").and_then(Value::as_u64) != Some(self.lease.expires)
        {
            return Err(database_plugin_indeterminate(&self.lease.id));
        }
        Ok(())
    }

    fn execute_valkey(&self) -> Result<(), Response> {
        let indeterminate = || Response {
            status: 503,
            body: json!({
                "errors":["Valkey provider outcome indeterminate; durable intent retained"],
                "lease_id":self.lease.id,
                "reconcile_required":true
            }),
        };
        let mut valkey = self
            .connection
            .valkey_session(&self.outbound)
            .map_err(|_| indeterminate())?;
        let permissions = valkey_permissions(&self.lease.provider_role)
            .ok_or_else(|| failure("unsupported Valkey ACL role profile"))?;
        let pattern = format!("~hb:{}:*", self.lease.provider_id);
        // The off/no-password ACL marker and managed user share one atomic ACL
        // SAVE file. The transient WATCH key only serializes live connections:
        // a provider restart kills all watchers and restores the durable marker.
        // Never expire/delete either fence: old leaders may still hold plans.
        let marker = format!("hbf_{}", &self.lease.provider_id[4..]);
        let watch_key = format!("__heptabao_fence:{}", self.lease.provider_id);
        if !valkey
            .command(&["WATCH", &watch_key])
            .map_err(|_| indeterminate())?
            .is_ok()
        {
            return Err(indeterminate());
        }
        let previous = valkey
            .command(&["ACL", "GETUSER", &marker])
            .map_err(|_| indeterminate())?;
        let fence = valkey_fence_readback(&previous).ok_or_else(indeterminate)?;
        if !valkey_fence_admits(fence, self.lease.seq, &self.lease.request_digest) {
            return Err(indeterminate());
        }
        let current = valkey
            .command(&["ACL", "GETUSER", &self.lease.username])
            .map_err(|_| indeterminate())?;
        let expected_password = self
            .lease
            .password
            .as_ref()
            .map(|password| hex(&crypto::digest(password.0.as_bytes())));
        match self.lease.phase {
            Phase::PendingIssue => {
                if expected_password.is_none() || (fence.is_none() && !current.is_null()) {
                    return Err(indeterminate());
                }
            }
            Phase::PendingRenew => {
                // Renewal must not recreate a disappeared user, turn on a
                // disabled account, or preserve an expanded ACL/selector.
                if fence.is_none()
                    || !valkey_acl_readback_matches(&current, &pattern, permissions, None)
                {
                    return Err(indeterminate());
                }
            }
            Phase::PendingRevoke => {
                if fence.is_none() && !current.is_null() {
                    return Err(indeterminate());
                }
            }
            _ => return Err(indeterminate()),
        }
        if !valkey
            .command(&["MULTI"])
            .map_err(|_| indeterminate())?
            .is_ok()
        {
            return Err(indeterminate());
        }
        let mut queue = |args: &[&str]| -> Result<(), Response> {
            if resp_text_equals(
                &valkey.command(args).map_err(|_| indeterminate())?,
                "QUEUED",
            ) {
                Ok(())
            } else {
                Err(indeterminate())
            }
        };
        match self.lease.phase {
            Phase::PendingIssue => {
                let hash = format!(
                    "#{}",
                    expected_password.as_deref().ok_or_else(indeterminate)?
                );
                let mut args = vec![
                    "ACL",
                    "SETUSER",
                    &self.lease.username,
                    "reset",
                    "on",
                    "resetchannels",
                    &pattern,
                    &hash,
                ];
                args.extend_from_slice(permissions);
                queue(&args)?;
            }
            Phase::PendingRenew => queue(&["PING"])?,
            Phase::PendingRevoke => queue(&["ACL", "DELUSER", &self.lease.username])?,
            _ => return Err(indeterminate()),
        }
        let binding = format!("{}:{}", self.lease.seq, self.lease.request_digest);
        let marker_pattern = format!("~{binding}");
        queue(&[
            "ACL",
            "SETUSER",
            &marker,
            "reset",
            "off",
            "resetchannels",
            &marker_pattern,
        ])?;
        queue(&["SET", &watch_key, &binding])?;
        let executed = valkey.command(&["EXEC"]).map_err(|_| indeterminate())?;
        let RespValue::Array(results) = executed else {
            return Err(indeterminate());
        };
        if results.len() != 3
            || !results[1].is_ok()
            || !results[2].is_ok()
            || match self.lease.phase {
                Phase::PendingIssue => !results[0].is_ok(),
                Phase::PendingRenew => !resp_text_equals(&results[0], "PONG"),
                Phase::PendingRevoke => !matches!(results[0], RespValue::Integer(0 | 1)),
                _ => true,
            }
        {
            return Err(indeterminate());
        }
        if !valkey
            .command(&["ACL", "SAVE"])
            .map_err(|_| indeterminate())?
            .is_ok()
        {
            return Err(indeterminate());
        }
        let observed_marker = valkey
            .command(&["ACL", "GETUSER", &marker])
            .map_err(|_| indeterminate())?;
        if valkey_fence_readback(&observed_marker)
            != Some(Some((self.lease.seq, self.lease.request_digest.as_str())))
        {
            return Err(indeterminate());
        }
        let observed = valkey
            .command(&["ACL", "GETUSER", &self.lease.username])
            .map_err(|_| indeterminate())?;
        let matched = if self.lease.phase == Phase::PendingRevoke {
            observed.is_null()
        } else {
            valkey_acl_readback_matches(
                &observed,
                &pattern,
                permissions,
                expected_password.as_deref(),
            )
        };
        if !matched {
            return Err(indeterminate());
        }
        Ok(())
    }

    fn success_response(&self, now: u64) -> Result<Response, Response> {
        match self.lease.phase {
            Phase::PendingIssue => {
                let password = self
                    .lease
                    .password
                    .as_ref()
                    .ok_or_else(|| failure("pending database issue lost secret material"))?;
                let mut data = json!({
                    "username":self.lease.username,
                    "password":password.0
                });
                if self.connection.provider == DatabaseProvider::Valkey {
                    data["key_pattern"] = json!(format!("hb:{}:*", self.lease.provider_id));
                }
                Ok(Response::ok(json!({
                    "lease_id":self.lease.id,
                    "lease_duration":self.lease.expires.saturating_sub(now),
                    "renewable":true,
                    "data":data
                })))
            }
            Phase::PendingRenew => Ok(Response::ok(json!({
                "lease_id":self.lease.id,
                "lease_duration":self.lease.expires.saturating_sub(now),
                "renewable":true
            }))),
            Phase::PendingRevoke => Ok(Response {
                status: 204,
                body: Value::Null,
            }),
            _ => Err(failure("database effect plan is not pending")),
        }
    }
}
impl DatabaseState {
    pub(super) fn known_namespaces(&self) -> BTreeSet<String> {
        self.mounts
            .keys()
            .filter(|namespace| !namespace.is_empty())
            .cloned()
            .collect()
    }

    pub(super) fn namespace_is_empty(&self, namespace: &str) -> bool {
        self.mounts
            .get(namespace)
            .is_none_or(|mounts| mounts.is_empty())
    }

    pub(super) fn is_empty(&self) -> bool {
        self.mounts.is_empty() && self.provider_fence == 0
    }
    pub(super) fn has_provider_fence(&self) -> bool {
        self.provider_fence != 0
    }
    fn current_provider_fence(&self) -> u64 {
        let retained_max = self
            .mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .flat_map(|mount| mount.leases.values())
            .map(|lease| lease.seq)
            .max()
            .unwrap_or(0);
        self.provider_fence.max(retained_max)
    }

    fn next_provider_fence(&mut self) -> Result<u64, Response> {
        let next = self
            .current_provider_fence()
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or_else(|| failure("database provider fence exhausted"))?;
        self.provider_fence = next;
        Ok(next)
    }
    pub(super) fn validate(&self) -> Result<(), Response> {
        if self.mounts.len() > 64 || self.provider_fence > i64::MAX as u64 {
            return Err(failure(
                "database namespace or provider-fence capacity exceeded",
            ));
        }
        let retained_max = self
            .mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .flat_map(|mount| mount.leases.values())
            .map(|lease| lease.seq)
            .max()
            .unwrap_or(0);
        if self.provider_fence != 0 && self.provider_fence < retained_max {
            return Err(failure(
                "database provider fence regressed behind retained lease state",
            ));
        }
        for (ns, mounts) in &self.mounts {
            if !valid_namespace(ns) || mounts.len() > 64 {
                return Err(failure("invalid database namespace state"));
            }
            for (mount, state) in mounts {
                if !valid_path(mount.trim_end_matches('/'))
                    || !mount.ends_with('/')
                    || state.leases.len() > 128
                    || state.connections.len() > 16
                    || state.roles.len() > 64
                {
                    return Err(failure("invalid database state bounds"));
                }
                for (connection_name, connection) in &state.connections {
                    if !name(connection_name)
                        || !name(&connection.username)
                        || connection.password.0.is_empty()
                        || connection.password.0.len() > 512
                        || !connection.password.0.is_ascii()
                        || connection.password.0.bytes().any(|b| b < 32 || b == 127)
                        || connection.allowed_roles.is_empty()
                        || connection.allowed_roles.len() > 64
                        || connection.allowed_roles.iter().any(|s| !name(s))
                        || match connection.provider {
                            DatabaseProvider::Postgresql => {
                                connection.plugin_id.is_some()
                                    || Target::parse(&connection.connection_url, "postgresql")
                                        .is_err()
                            }
                            DatabaseProvider::Valkey => {
                                connection.plugin_id.is_some()
                                    || Target::parse(&connection.connection_url, "valkeys").is_err()
                                    || connection
                                        .connection_url
                                        .rsplit_once('/')
                                        .and_then(|(_, value)| value.parse::<u8>().ok())
                                        .is_none_or(|db| db != 0)
                            }
                            DatabaseProvider::Plugin => {
                                connection
                                    .plugin_id
                                    .as_deref()
                                    .is_none_or(|value| !name(value))
                                    || connection.connection_url.is_empty()
                                    || connection.connection_url.len() > 2048
                                    || connection.connection_url.chars().any(char::is_control)
                            }
                        }
                    {
                        return Err(failure("invalid persisted provider configuration"));
                    }
                }
                for (role_name, role) in &state.roles {
                    if !name(role_name)
                        || !name(&role.provider_role)
                        || !state.connections.contains_key(&role.db_name)
                        || state
                            .connections
                            .get(&role.db_name)
                            .is_some_and(|connection| {
                                connection.provider == DatabaseProvider::Valkey
                                    && valkey_permissions(&role.provider_role).is_none()
                            })
                        || role.default_ttl == 0
                        || role.default_ttl > role.max_ttl
                        || role.max_ttl > 86400
                    {
                        return Err(failure("invalid persisted database role"));
                    }
                }
                for (id, l) in &state.leases {
                    if id != &l.id
                        || id.len() > 512
                        || l.provider_id.len() != 68
                        || !l.provider_id.starts_with("hb1:")
                        || !l.provider_id[4..].bytes().all(|b| b.is_ascii_hexdigit())
                        || !name(&l.provider_role)
                        || l.owner
                            .validate_scope(ns, ServiceOwnerProfile::CanonicalDigest)
                            .is_err()
                        || l.owner.batch_claims().is_some_and(|claims| {
                            l.issued < claims.issued_at() || l.expires > claims.expires_at()
                        })
                        || l.max_expires > i64::MAX as u64
                        || l.max_expires.saturating_sub(l.issued) > 86400
                        || !l.request_digest.bytes().all(|b| b.is_ascii_hexdigit())
                        || l.password.as_ref().is_some_and(|p| {
                            p.0.len() != 64 || !p.0.bytes().all(|b| b.is_ascii_hexdigit())
                        })
                        || matches!(l.phase, Phase::PendingRevoke | Phase::Revoked)
                            && l.expires != 0
                        || !matches!(l.phase, Phase::PendingIssue | Phase::Quarantined)
                            && l.password.is_some()
                        || !id.starts_with(&format!("{mount}creds/"))
                        || l.seq == 0
                        || l.seq > i64::MAX as u64
                        || l.max_expires <= l.issued
                        || l.expires > l.max_expires
                        || !valid_database_username(&l.username)
                        || !state.connections.contains_key(&l.db_name)
                        || l.request_digest.len() != 64
                        || l.phase == Phase::Active && l.password.is_some()
                        || l.phase == Phase::PendingIssue && l.password.is_none()
                    {
                        return Err(failure("invalid database lease identity or lifecycle"));
                    }
                    if matches!(
                        l.phase,
                        Phase::PendingIssue | Phase::PendingRenew | Phase::PendingRevoke
                    ) && digest_lease(l)? != l.request_digest
                    {
                        return Err(failure("database intent digest mismatch"));
                    }
                }
            }
        }
        Ok(())
    }
    pub(super) fn validate_scope(&self, cluster: &str) -> Result<(), Response> {
        self.validate()?;
        for (namespace, mounts) in &self.mounts {
            for mount in mounts.values() {
                for lease in mount.leases.values() {
                    if provider_identity(cluster, namespace, &lease.id)? != lease.provider_id {
                        return Err(failure(
                            "persisted provider identity belongs to another scope",
                        ));
                    }
                }
            }
        }
        Ok(())
    }
    /// Complete retained ownership, not just Active leases; Pending/Revoke and
    /// quarantined records must participate in format/key validation.
    pub(super) fn all_lease_owners(&self) -> BTreeSet<(String, LeaseOwner)> {
        self.mounts
            .iter()
            .flat_map(|(namespace, mounts)| {
                mounts.values().flat_map(move |mount| {
                    mount
                        .leases
                        .values()
                        .map(move |lease| (namespace.clone(), lease.owner.clone()))
                })
            })
            .collect()
    }

    fn mount_mut(&mut self, ns: &str, mount: &str) -> &mut DatabaseMount {
        self.mounts
            .entry(ns.into())
            .or_default()
            .entry(mount.into())
            .or_default()
    }
    fn mount(&self, ns: &str, mount: &str) -> Option<&DatabaseMount> {
        self.mounts.get(ns)?.get(mount)
    }
    fn locate(&self, ns: &str, id: &str) -> Option<String> {
        self.mounts
            .get(ns)?
            .iter()
            .find_map(|(name, m)| m.leases.contains_key(id).then(|| name.clone()))
    }
    fn mount_for_lease_prefix(&self, ns: &str, id: &str) -> Option<String> {
        self.mounts.get(ns)?.keys().find_map(|mount| {
            id.starts_with(&format!("{mount}creds/"))
                .then(|| mount.clone())
        })
    }
}
impl Connection {
    fn plugin_name(&self) -> &str {
        match self.provider {
            DatabaseProvider::Postgresql => "postgresql-database-plugin",
            DatabaseProvider::Valkey => "valkey-database-plugin",
            DatabaseProvider::Plugin => self.plugin_id.as_deref().unwrap_or(""),
        }
    }

    fn session(&self, outbound: &crate::outbound::Outbound) -> Result<PgSession, &'static str> {
        let (endpoint, target) = outbound.endpoint(&self.connection_url, "postgresql")?;
        let database = target
            .path
            .strip_prefix('/')
            .ok_or("invalid database URL")?;
        if !name(database) {
            return Err("invalid PostgreSQL database name");
        }
        PgSession::connect(&endpoint, database, &self.username, &self.password.0)
    }

    fn valkey_session(
        &self,
        outbound: &crate::outbound::Outbound,
    ) -> Result<ValkeySession, &'static str> {
        let (endpoint, target) = outbound.endpoint(&self.connection_url, "valkeys")?;
        ValkeySession::connect(&endpoint, &target, &self.username, &self.password.0)
    }
}
fn database_plugin_config_failure(error: PluginHostError) -> Response {
    match error {
        PluginHostError::ProcessBeforeEntry | PluginHostError::SandboxUnavailable => {
            failure("database plugin unavailable before entry")
        }
        PluginHostError::ProcessOutcomeUnknown => {
            failure("database plugin configuration outcome unknown after entry")
        }
        PluginHostError::ReconciliationRequired => {
            failure("database plugin host requires reconciliation")
        }
        PluginHostError::ResponseTooLarge => {
            failure("database plugin configuration response exceeds bound")
        }
        PluginHostError::MalformedResponse => {
            failure("database plugin configuration response malformed")
        }
        _ => failure("database plugin configuration readback unavailable"),
    }
}

fn database_plugin_indeterminate(lease_id: &str) -> Response {
    Response {
        status: 503,
        body: json!({
            "errors":["database plugin outcome indeterminate; durable intent retained"],
            "lease_id":lease_id,
            "reconcile_required":true
        }),
    }
}

fn database_plugin_effect_failure(error: PluginHostError, lease_id: &str) -> Response {
    match error {
        PluginHostError::ProcessBeforeEntry | PluginHostError::SandboxUnavailable => Response {
            status: 503,
            body: json!({
                "errors":["database plugin unavailable before entry; durable intent retained"],
                "lease_id":lease_id,
                "reconcile_required":true
            }),
        },
        _ => database_plugin_indeterminate(lease_id),
    }
}

fn failure(message: &str) -> Response {
    Response::error(503, message)
}
fn invalid(message: &str) -> Response {
    Response::error(400, message)
}
fn fields(body: &Value, allowed: &[&str]) -> Result<(), Response> {
    let map = body.as_object().ok_or_else(|| invalid("object required"))?;
    if map.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(invalid("unsupported database field"));
    }
    Ok(())
}
fn text<'a>(body: &'a Value, key: &str) -> Result<&'a str, Response> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 2048 && !s.chars().any(char::is_control))
        .ok_or_else(|| invalid("missing or invalid database string"))
}
fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

// Native PostgreSQL v2 operators already deployed the exact hbp_ + 32-hex
// contract. Do not change that protocol while accommodating MySQL's 32-byte
// account-name limit in the generic plugin adapter. Existing persisted names
// (both lengths) remain unchanged, including pending reconciliation identities.
fn generated_database_username(provider: DatabaseProvider, entropy: &[u8; 16]) -> String {
    let encoded = hex(entropy);
    let digits = match provider {
        DatabaseProvider::Postgresql | DatabaseProvider::Valkey => 32,
        DatabaseProvider::Plugin => 28,
    };
    format!("hbp_{}", &encoded[..digits])
}

fn valid_database_username(s: &str) -> bool {
    s.starts_with("hbp_")
        && matches!(s.len(), 32 | 36)
        && s[4..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn ttl(body: &Value, key: &str, default: u64) -> Result<u64, Response> {
    let v = match body.get(key) {
        None => default,
        Some(Value::Number(n)) => n.as_u64().ok_or_else(|| invalid("invalid TTL"))?,
        Some(Value::String(s)) => {
            let (n, m) = if let Some(s) = s.strip_suffix('s') {
                (s, 1)
            } else if let Some(s) = s.strip_suffix('m') {
                (s, 60)
            } else if let Some(s) = s.strip_suffix('h') {
                (s, 3600)
            } else {
                (s.as_str(), 1)
            };
            n.parse::<u64>()
                .ok()
                .and_then(|n| n.checked_mul(m))
                .ok_or_else(|| invalid("invalid TTL"))?
        }
        _ => return Err(invalid("invalid TTL")),
    };
    if v == 0 || v > 86400 {
        return Err(invalid("TTL must be 1..86400 seconds"));
    }
    Ok(v)
}
fn action(l: &DatabaseLease) -> &'static str {
    match l.phase {
        Phase::PendingIssue => "issue",
        Phase::PendingRenew => "renew",
        _ => "revoke",
    }
}
fn provider_identity(cluster: &str, namespace: &str, id: &str) -> Result<String, Response> {
    let binding = serde_json::to_vec(&(cluster, namespace, id))
        .map_err(|_| failure("provider scope binding failed"))?;
    Ok(format!("hb1:{}", hex(&crypto::digest(&binding))))
}

fn provider_fence_identity(cluster: &str) -> Result<String, Response> {
    let binding = serde_json::to_vec(&("heptabao.postgresql.fence.v2", cluster))
        .map_err(|_| failure("provider fence binding failed"))?;
    Ok(format!("hbf1:{}", hex(&crypto::digest(&binding))))
}

// Explicit key-bearing command lists avoid category expansion and keyless
// operations such as FLUSHALL, KEYS, SCAN and module-added commands.
fn valkey_permissions(role: &str) -> Option<&'static [&'static str]> {
    match role {
        "readonly" => Some(&[
            "+ping", "+get", "+mget", "+exists", "+ttl", "+pttl", "+type",
        ]),
        "readwrite" => Some(&[
            "+ping", "+get", "+mget", "+exists", "+ttl", "+pttl", "+type", "+set", "+del",
            "+unlink", "+expire", "+pexpire", "+persist",
        ]),
        _ => None,
    }
}

fn resp_text_equals(value: &RespValue, expected: &str) -> bool {
    resp_text(value) == Some(expected)
}

fn resp_text(value: &RespValue) -> Option<&str> {
    match value {
        RespValue::Simple(value) => Some(value.as_str()),
        RespValue::Bulk(value) => std::str::from_utf8(value).ok(),
        _ => None,
    }
}

fn resp_text_list(value: &RespValue) -> Option<Vec<&str>> {
    let RespValue::Array(values) = value else {
        return None;
    };
    values.iter().map(resp_text).collect()
}

fn valkey_acl_fields(value: &RespValue) -> Option<BTreeMap<&str, &RespValue>> {
    let RespValue::Array(fields) = value else {
        return None;
    };
    if fields.len() != 12 {
        return None;
    }
    let mut map = BTreeMap::new();
    for pair in fields.as_chunks::<2>().0 {
        let key = resp_text(&pair[0])?;
        if ![
            "flags",
            "passwords",
            "commands",
            "keys",
            "channels",
            "selectors",
        ]
        .contains(&key)
            || map.insert(key, &pair[1]).is_some()
        {
            return None;
        }
    }
    Some(map)
}

fn valkey_acl_readback_matches(
    value: &RespValue,
    key_pattern: &str,
    permissions: &[&str],
    password_hash: Option<&str>,
) -> bool {
    let Some(fields) = valkey_acl_fields(value) else {
        return false;
    };
    let Some(flags) = resp_text_list(fields["flags"]) else {
        return false;
    };
    let Some(passwords) = resp_text_list(fields["passwords"]) else {
        return false;
    };
    let Some(commands) = resp_text(fields["commands"]) else {
        return false;
    };
    let actual: BTreeSet<_> = commands.split_ascii_whitespace().collect();
    let expected: BTreeSet<_> = std::iter::once("-@all")
        .chain(permissions.iter().copied())
        .collect();
    valkey_flags_match(&flags, "on")
        && passwords.len() == 1
        && passwords[0].len() == 64
        && passwords[0].bytes().all(|b| b.is_ascii_hexdigit())
        && password_hash.is_none_or(|hash| passwords[0] == hash)
        && actual == expected
        && commands.split_ascii_whitespace().count() == expected.len()
        && resp_text_equals(fields["keys"], key_pattern)
        && resp_text_equals(fields["channels"], "")
        && matches!(fields["selectors"], RespValue::Array(values) if values.is_empty())
}

fn valkey_flags_match(flags: &[&str], state: &str) -> bool {
    let unique: BTreeSet<_> = flags.iter().copied().collect();
    unique.len() == flags.len()
        && unique.contains(state)
        && unique
            .iter()
            .all(|flag| *flag == state || *flag == "sanitize-payload")
}

fn valkey_fence_readback(value: &RespValue) -> Option<Option<(u64, &str)>> {
    if value.is_null() {
        return Some(None);
    }
    let fields = valkey_acl_fields(value)?;
    if !valkey_flags_match(&resp_text_list(fields["flags"])?, "off")
        || !resp_text_list(fields["passwords"])?.is_empty()
        || !resp_text_equals(fields["commands"], "-@all")
        || !resp_text_equals(fields["channels"], "")
        || !matches!(fields["selectors"], RespValue::Array(values) if values.is_empty())
    {
        return None;
    }
    let (sequence, digest) = resp_text(fields["keys"])?
        .strip_prefix('~')?
        .split_once(':')?;
    let sequence = sequence
        .parse::<u64>()
        .ok()
        .filter(|s| *s > 0 && *s <= i64::MAX as u64)?;
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(Some((sequence, digest)))
}

fn valkey_fence_admits(previous: Option<(u64, &str)>, sequence: u64, digest: &str) -> bool {
    previous.is_none_or(|(old, binding)| sequence > old || (sequence == old && digest == binding))
}
fn digest_lease(l: &DatabaseLease) -> Result<String, Response> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(&(
            l.id.as_str(),
            l.provider_id.as_str(),
            l.username.as_str(),
            l.seq,
            action(l),
            l.expires,
            l.provider_role.as_str(),
            l.password.as_ref().map(|p| p.0.as_str()).unwrap_or(""),
        ))
        .map_err(|_| failure("lease serialization failed"))?,
    );
    Ok(hex(&crypto::digest(&bytes)))
}
impl Service {
    pub(super) fn database_handles(
        &self,
        state: &State,
        ns: &str,
        path: &str,
        body: &Value,
    ) -> bool {
        if state.engines.database_mount(ns, path).is_some() {
            return true;
        }
        if let Some(mount) = path.strip_prefix("sys/mounts/")
            && state
                .database
                .mount(ns, &format!("{}/", mount.trim_end_matches('/')))
                .is_some()
        {
            return true;
        }
        if path.starts_with("sys/leases/") {
            let id = body
                .get("lease_id")
                .and_then(Value::as_str)
                .or_else(|| path.strip_prefix("sys/leases/revoke/"))
                .or_else(|| path.strip_prefix("sys/leases/renew/"))
                .or_else(|| path.strip_prefix("sys/leases/reconcile/"));
            if id.is_some_and(|id| {
                state.database.locate(ns, id).is_some()
                    || state.database.mount_for_lease_prefix(ns, id).is_some()
            }) {
                return true;
            }
            // Prefix/list operations may cover multiple engine classes: handled
            // in this service boundary only for an exactly registered DB prefix.
            if let Some(prefix) = path
                .strip_prefix("sys/leases/lookup/")
                .or_else(|| path.strip_prefix("sys/leases/revoke-prefix/"))
            {
                return state.database.mounts.get(ns).is_some_and(|m| {
                    m.keys()
                        .any(|p| prefix == p.trim_end_matches('/') || prefix.starts_with(p))
                });
            }
        }
        false
    }
    pub(super) fn database_route(
        &mut self,
        mut state: State,
        mut principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let started = std::time::Instant::now();
        let RequestView {
            namespace: ns,
            method,
            path,
            body,
            now,
            wrap_ttl_seconds,
            ..
        } = request;
        let now = (*now).max(state.database.clock);
        let execute = (|| -> Result<Response, Response> {
            let p = principal
                .as_ref()
                .ok_or_else(|| Response::error(403, "missing client token"))?;
            let capability = match *method {
                "GET" => "read",
                "LIST" => "list",
                "DELETE" => "delete",
                _ => "update",
            };
            let sudo =
                path.starts_with("sys/") || path.contains("/config/") || path.contains("/roles/");
            if sudo {
                state
                    .auth
                    .authorize_sudo_request(p, ns, path, capability, now)
            } else {
                state.auth.authorize_request(p, ns, path, capability, now)
            }
            .map_err(|e| Response::error(e.status, &e.message))?;
            if path.starts_with("sys/mounts/") {
                return Err(Response::error(
                    409,
                    "database mounts retain provider identities; automatic unmount is not supported",
                ));
            }
            if wrap_ttl_seconds.is_some() {
                return Err(Response::error(
                    501,
                    "database response wrapping requires an external-effect publication envelope",
                ));
            }
            state.database.clock = now;
            let cluster_identity = state.cluster_id.clone();
            if let Some(mount) = state.engines.database_mount(ns, path).map(str::to_owned) {
                let relative = &path[mount.len()..];
                let (kind, key) = relative.split_once('/').unwrap_or((relative, ""));
                let collection_list =
                    *method == "LIST" && key.is_empty() && matches!(kind, "roles" | "config");
                if !collection_list && !name(key) {
                    return Err(invalid("invalid database resource name"));
                }
                match (kind, *method) {
                    ("config", "POST" | "PUT") => {
                        fields(
                            body,
                            &[
                                "plugin_name",
                                "connection_url",
                                "username",
                                "password",
                                "allowed_roles",
                                "verify_connection",
                            ],
                        )?;
                        let plugin_name = text(body, "plugin_name")?;
                        let (provider, plugin_id) = match plugin_name {
                            "postgresql-database-plugin" => (DatabaseProvider::Postgresql, None),
                            "valkey-database-plugin" => (DatabaseProvider::Valkey, None),
                            value if name(value) && self.database_plugins.contains_key(value) => {
                                (DatabaseProvider::Plugin, Some(value.to_owned()))
                            }
                            _ => {
                                return Err(invalid(
                                    "database provider is not admitted by this deployment",
                                ));
                            }
                        };
                        if body
                            .get("verify_connection")
                            .is_some_and(|v| v != &Value::Bool(true))
                        {
                            return Err(invalid("provider configuration verification is required"));
                        }
                        let url = text(body, "connection_url")?.to_owned();
                        if provider != DatabaseProvider::Plugin {
                            let target = Target::parse(
                                &url,
                                match provider {
                                    DatabaseProvider::Postgresql => "postgresql",
                                    DatabaseProvider::Valkey => "valkeys",
                                    DatabaseProvider::Plugin => unreachable!(),
                                },
                            )
                            .map_err(invalid)?;
                            if !name(target.path.trim_start_matches('/'))
                                || (provider == DatabaseProvider::Valkey
                                    && target.path.trim_start_matches('/').parse::<u8>() != Ok(0))
                            {
                                return Err(invalid(
                                    "single explicit bounded provider database required",
                                ));
                            }
                        }
                        let username = text(body, "username")?.to_owned();
                        if !name(&username) {
                            return Err(invalid("invalid database manager name"));
                        }
                        let password = text(body, "password")?.to_owned();
                        if password.len() > 512 || !password.is_ascii() {
                            return Err(invalid(
                                "bounded ASCII database manager password required",
                            ));
                        }
                        let roles = body
                            .get("allowed_roles")
                            .and_then(Value::as_array)
                            .ok_or_else(|| invalid("allowed_roles array is required"))?;
                        if roles.is_empty() || roles.len() > 64 {
                            return Err(invalid("allowed_roles count outside bounds"));
                        }
                        let allowed_roles: BTreeSet<String> = roles
                            .iter()
                            .map(|v| {
                                v.as_str()
                                    .filter(|s| name(s))
                                    .map(str::to_owned)
                                    .ok_or_else(|| invalid("invalid allowed role"))
                            })
                            .collect::<Result<_, _>>()?;
                        if state
                            .database
                            .mount(ns, &mount)
                            .is_some_and(|m| m.leases.values().any(|l| l.db_name == key))
                        {
                            return Err(Response::error(
                                409,
                                "provider identity is frozen while lease/tombstone records exist",
                            ));
                        }
                        let connection = Connection {
                            provider,
                            plugin_id: plugin_id.clone(),
                            connection_url: url,
                            username,
                            password: PrivateString(password),
                            allowed_roles,
                        };
                        let expected_mount_digest =
                            database_mount_digest(state.database.mount(ns, &mount))?;
                        if self.pending_database_config_effect.is_some() {
                            return Err(failure(
                                "database configuration validation is already pending",
                            ));
                        }
                        let plugin = plugin_id
                            .as_ref()
                            .and_then(|id| self.database_plugins.get(id))
                            .cloned();
                        let mount_incarnation = state
                            .engines
                            .database_mount_binding(ns, path)
                            .map(|(_, incarnation)| incarnation)
                            .ok_or_else(|| {
                                failure("database mount disappeared before validation")
                            })?;
                        // Keep the consumed admission capability, not a replayable
                        // bearer or a second authentication/use at completion.
                        let authority = plugin::PluginResponseAuthority::new(
                            principal
                                .take()
                                .ok_or_else(|| failure("database admission disappeared"))?,
                            &state,
                            request,
                            capability,
                            sudo,
                        )
                        .with_time_floor(now);
                        self.pending_database_config_effect = Some(DatabaseConfigPlan {
                            namespace: (*ns).into(),
                            mount,
                            mount_incarnation,
                            authority,
                            key: key.into(),
                            connection,
                            plugin,
                            expected_mount_digest,
                            outbound: self.outbound.clone(),
                            now,
                        });
                        Ok(Response::error(
                            500,
                            "database configuration validation was not dispatched",
                        ))
                    }
                    ("config", "GET") => {
                        fields(body, &[])?;
                        let c = state
                            .database
                            .mount(ns, &mount)
                            .and_then(|m| m.connections.get(key))
                            .ok_or_else(|| {
                                Response::error(404, "database configuration not found")
                            })?;
                        Ok(Response::ok(
                            json!({"data":{"plugin_name":c.plugin_name(),"connection_url":c.connection_url,"username":c.username,"allowed_roles":c.allowed_roles,"verify_connection":true}}),
                        ))
                    }
                    ("config", "LIST") => {
                        fields(body, &[])?;
                        let keys = state
                            .database
                            .mount(ns, &mount)
                            .map(|m| m.connections.keys().cloned().collect::<Vec<_>>())
                            .unwrap_or_default();
                        Ok(Response::ok(json!({"data":{"keys":keys}})))
                    }
                    ("config", "DELETE") => {
                        fields(body, &[])?;
                        let database_mount = state
                            .database
                            .mount(ns, &mount)
                            .ok_or_else(|| Response::error(404, "database mount not found"))?;
                        if !database_mount.connections.contains_key(key) {
                            return Err(Response::error(404, "database configuration not found"));
                        }
                        if database_mount
                            .roles
                            .values()
                            .any(|role| role.db_name == key)
                            || database_mount
                                .leases
                                .values()
                                .any(|lease| lease.db_name == key)
                        {
                            return Err(Response::error(
                                409,
                                "database configuration is still referenced by a role or lease",
                            ));
                        }
                        state.database.mount_mut(ns, &mount).connections.remove(key);
                        self.publish_database(state)?;
                        Ok(Response {
                            status: 204,
                            body: Value::Null,
                        })
                    }
                    ("roles", "POST" | "PUT") => {
                        fields(
                            body,
                            &["db_name", "provider_role", "default_ttl", "max_ttl"],
                        )?;
                        let db_name = text(body, "db_name")?.to_owned();
                        let provider_role = text(body, "provider_role")?.to_owned();
                        if !name(&db_name) || !name(&provider_role) {
                            return Err(invalid("invalid database role reference"));
                        }
                        let default_ttl = ttl(body, "default_ttl", 3600)?;
                        let max_ttl = ttl(body, "max_ttl", 86400)?;
                        if default_ttl > max_ttl {
                            return Err(invalid("default TTL exceeds maximum"));
                        }
                        let m = state.database.mount_mut(ns, &mount);
                        let c = m
                            .connections
                            .get(&db_name)
                            .ok_or_else(|| invalid("unknown database configuration"))?;
                        if c.provider == DatabaseProvider::Valkey
                            && valkey_permissions(&provider_role).is_none()
                        {
                            return Err(invalid(
                                "Valkey provider_role must be readonly or readwrite",
                            ));
                        }
                        if !c.allowed_roles.contains(key) {
                            return Err(Response::error(
                                403,
                                "database role is not allowed by connection",
                            ));
                        }
                        if m.roles.len() >= 64 && !m.roles.contains_key(key) {
                            return Err(Response::error(507, "database role capacity exhausted"));
                        }
                        m.roles.insert(
                            key.into(),
                            DatabaseRole {
                                db_name,
                                provider_role,
                                default_ttl,
                                max_ttl,
                            },
                        );
                        self.publish_database(state)?;
                        Ok(Response {
                            status: 204,
                            body: Value::Null,
                        })
                    }
                    ("roles", "GET") => {
                        fields(body, &[])?;
                        let role = state
                            .database
                            .mount(ns, &mount)
                            .and_then(|m| m.roles.get(key))
                            .ok_or_else(|| Response::error(404, "database role not found"))?;
                        Ok(Response::ok(json!({"data":role})))
                    }
                    ("roles", "LIST") => {
                        fields(body, &[])?;
                        let keys = state
                            .database
                            .mount(ns, &mount)
                            .map(|m| m.roles.keys().cloned().collect::<Vec<_>>())
                            .unwrap_or_default();
                        Ok(Response::ok(json!({"data":{"keys":keys}})))
                    }
                    ("roles", "DELETE") => {
                        fields(body, &[])?;
                        let removed = state.database.mount_mut(ns, &mount).roles.remove(key);
                        if removed.is_none() {
                            return Err(Response::error(404, "database role not found"));
                        }
                        self.publish_database(state)?;
                        Ok(Response {
                            status: 204,
                            body: Value::Null,
                        })
                    }
                    ("creds", "GET") => {
                        fields(body, &[])?;
                        let owner = state
                            .auth
                            .typed_lease_issuer(p, ns, now)
                            .map_err(|e| Response::error(e.status, &e.message))?;
                        let role = state
                            .database
                            .mount(ns, &mount)
                            .and_then(|m| m.roles.get(key))
                            .cloned()
                            .ok_or_else(|| Response::error(404, "database role not found"))?;
                        let database_mount = state
                            .database
                            .mount(ns, &mount)
                            .ok_or_else(|| Response::error(404, "database mount not found"))?;
                        if database_mount.leases.len() >= 128 {
                            return Err(Response::error(
                                507,
                                "database active or unresolved lease capacity exhausted",
                            ));
                        }
                        let connection = database_mount
                            .connections
                            .get(&role.db_name)
                            .filter(|c| c.allowed_roles.contains(key))
                            .ok_or_else(|| {
                                Response::error(403, "database role is no longer allowed")
                            })?;
                        let entropy = crypto::random::<16>().map_err(failure)?;
                        let username = generated_database_username(connection.provider, &entropy);
                        // The durable identity always retains all 128 random bits,
                        // including for plugins with a shorter username contract.
                        let entropy = hex(&entropy);
                        let id = format!("{mount}creds/{key}/{entropy}");
                        if id.len() > 512 {
                            return Err(invalid("database lease identity exceeds bound"));
                        }
                        let provider_id = provider_identity(&cluster_identity, ns, &id)?;
                        let password = hex(&crypto::random::<32>().map_err(failure)?);
                        let max_expires = now
                            .checked_add(role.max_ttl)
                            .ok_or_else(|| invalid("lease time exhausted"))?;
                        let expires = now
                            .checked_add(role.default_ttl)
                            .ok_or_else(|| invalid("lease time exhausted"))?
                            .min(owner.expires_at.unwrap_or(u64::MAX));
                        if max_expires > i64::MAX as u64 {
                            return Err(invalid("PostgreSQL expiry exceeds timestamp profile"));
                        }
                        if expires <= now {
                            return Err(Response::error(403, "issuer expired"));
                        }
                        let provider_fence = state.database.next_provider_fence()?;
                        let mut lease = DatabaseLease {
                            id: id.clone(),
                            provider_id,
                            username: username.clone(),
                            db_name: role.db_name,
                            provider_role: role.provider_role,
                            owner: owner.owner.clone(),
                            issued: now,
                            expires,
                            max_expires,
                            last_renewal: None,
                            seq: provider_fence,
                            phase: Phase::PendingIssue,
                            password: Some(PrivateString(password)),
                            request_digest: String::new(),
                        };
                        lease.request_digest = digest_lease(&lease)?;
                        state
                            .database
                            .mount_mut(ns, &mount)
                            .leases
                            .insert(id.clone(), lease);
                        self.publish_database(state)?;
                        self.defer_database_effect(ns, &mount, &id, now)
                    }
                    _ => Err(Response::error(
                        501,
                        "database operation is outside the implemented provider profile",
                    )),
                }
            } else {
                self.database_admin(state, p, request, now)
            }
        })();
        // Include intent publication time as well as unlocked provider I/O.
        if let Some(plan) = &mut self.pending_database_effect {
            plan.started = started;
        }
        if let Some(batch) = &mut self.pending_database_batch_effect {
            for plan in &mut batch.plans {
                plan.started = started;
            }
        }
        execute.unwrap_or_else(|e| e)
    }
    fn publish_database(&mut self, mut state: State) -> Result<(), Response> {
        state.schema = CURRENT_STATE_SCHEMA;
        state.validate_format()?;
        self.commit_state(&state)?;
        self.state = Some(state);
        Ok(())
    }
    pub(super) fn finalize_database_config(
        &mut self,
        mut plan: DatabaseConfigPlan,
        validation: Result<(), Response>,
    ) -> Response {
        if let Err(error) = validation {
            return error;
        }
        // Provider validation executes outside the Service writer. Synchronize
        // HA and recheck live ACL, identity, expiry, deadline and namespace owner
        // before installing credentials. Failure preserves the previous config.
        if let Err(error) = self.validate_plugin_response(&mut plan.authority) {
            return error;
        }
        let Some(mut state) = self.state.clone() else {
            return failure("server sealed after database configuration validation");
        };
        if state
            .engines
            .database_mount_binding(&plan.namespace, &plan.mount)
            != Some((plan.mount.as_str(), plan.mount_incarnation))
        {
            return Response::error(409, "database mount incarnation changed during validation");
        }
        if let Some(host) = &plan.plugin {
            let current = plan
                .connection
                .plugin_id
                .as_ref()
                .and_then(|id| self.database_plugins.get(id));
            if current.is_none_or(|current| !std::sync::Arc::ptr_eq(current, host)) {
                return failure("database plugin host changed during validation");
            }
        }
        let current_digest =
            match database_mount_digest(state.database.mount(&plan.namespace, &plan.mount)) {
                Ok(digest) => digest,
                Err(error) => return error,
            };
        if current_digest != plan.expected_mount_digest {
            return Response::error(
                409,
                "database mount changed during provider configuration validation",
            );
        }
        if state
            .database
            .mount(&plan.namespace, &plan.mount)
            .is_some_and(|mount| mount.leases.values().any(|lease| lease.db_name == plan.key))
        {
            return Response::error(
                409,
                "provider identity is frozen while lease/tombstone records exist",
            );
        }
        state.database.clock = state.database.clock.max(plan.now).max(plan.authority.now());
        let mount = state.database.mount_mut(&plan.namespace, &plan.mount);
        if mount.connections.len() >= 16 && !mount.connections.contains_key(&plan.key) {
            return Response::error(507, "database connection capacity exhausted");
        }
        mount.connections.insert(plan.key, plan.connection);
        match self.publish_database(state) {
            Ok(()) => Response {
                status: 204,
                body: Value::Null,
            },
            Err(error) => error,
        }
    }

    fn database_effect_plan(
        &mut self,
        ns: &str,
        mount: &str,
        id: &str,
        now: u64,
    ) -> Result<DatabaseEffectPlan, Response> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| failure("server sealed"))?;
        let database_mount = state
            .database
            .mount(ns, mount)
            .ok_or_else(|| failure("database mount disappeared"))?;
        let lease = database_mount
            .leases
            .get(id)
            .cloned()
            .ok_or_else(|| failure("database lease disappeared"))?;
        if !matches!(
            lease.phase,
            Phase::PendingIssue | Phase::PendingRenew | Phase::PendingRevoke
        ) {
            return Err(invalid("database effect is not pending"));
        }
        let connection = database_mount
            .connections
            .get(&lease.db_name)
            .cloned()
            .ok_or_else(|| failure("provider configuration disappeared"))?;
        let plugin = connection
            .plugin_id
            .as_ref()
            .and_then(|id| self.database_plugins.get(id))
            .cloned();
        if connection.provider == DatabaseProvider::Plugin && plugin.is_none() {
            return Err(failure(
                "database plugin is not admitted by this deployment",
            ));
        }
        Ok(DatabaseEffectPlan {
            namespace: ns.to_owned(),
            mount: mount.to_owned(),
            now,
            started: std::time::Instant::now(),
            outbound: self.outbound.clone(),
            ha: self.ha.clone(),
            plugin,
            connection,
            fence_id: provider_fence_identity(&state.cluster_id)?,
            lease,
            _in_flight: self.database_in_flight.track(ns, mount, id),
        })
    }

    fn defer_database_effect(
        &mut self,
        ns: &str,
        mount: &str,
        id: &str,
        now: u64,
    ) -> Result<Response, Response> {
        self.database_in_flight.prune();
        if self.database_in_flight.contains(ns, mount, id) {
            return Err(Self::database_effect_in_flight(id));
        }
        if self.pending_database_effect.is_some() {
            return Err(failure(
                "another database provider effect is already pending dispatch",
            ));
        }
        self.pending_database_effect = Some(self.database_effect_plan(ns, mount, id, now)?);
        // This response never leaves the Service request wrapper: the wrapper
        // either executes the plan synchronously or hands it to the HTTP layer.
        Ok(Response::error(
            500,
            "database provider effect was not dispatched",
        ))
    }

    pub(super) fn finalize_database_effect(
        &mut self,
        plan: &DatabaseEffectPlan,
        provider_result: Result<(), Response>,
    ) -> Response {
        self.finalize_database_effect_with_clock(plan, provider_result, || plan.completed_now())
    }

    fn finalize_database_effect_with_clock(
        &mut self,
        plan: &DatabaseEffectPlan,
        provider_result: Result<(), Response>,
        mut completed_now: impl FnMut() -> u64,
    ) -> Response {
        if let Err(error) = provider_result {
            return error;
        }
        // A ReadIndex alone does not install revocations made while I/O was
        // unlocked. Install the latest application state before resolving owner.
        if self.ha.is_some() && self.sync_from_ha_with_anchor(false).is_err() {
            return post_provider_publication_failure(
                failure("HA provider finalize fence unavailable"),
                &plan.lease.id,
            );
        }
        let Some(mut next) = self.state.clone() else {
            return post_provider_publication_failure(
                failure("server sealed after provider entry"),
                &plan.lease.id,
            );
        };
        let Some(current) = next
            .database
            .mount(&plan.namespace, &plan.mount)
            .and_then(|mount| mount.leases.get(&plan.lease.id))
            .cloned()
        else {
            return post_provider_publication_failure(
                failure("lease disappeared after provider entry"),
                &plan.lease.id,
            );
        };
        if current.seq != plan.lease.seq
            || current.request_digest != plan.lease.request_digest
            || current.phase != plan.lease.phase
            || current.owner != plan.lease.owner
            || current.expires != plan.lease.expires
        {
            return post_provider_publication_failure(
                failure("lease fence changed after provider entry"),
                &plan.lease.id,
            );
        }
        let now = completed_now().max(next.database.clock);
        if current.phase != Phase::PendingRevoke
            && !Self::database_completion_owner_live(&next, plan, now)
        {
            return self.reject_database_completion(next, plan, now);
        }
        next.database.clock = now;
        if plan.lease.phase == Phase::PendingRevoke {
            let removed = next
                .database
                .mount_mut(&plan.namespace, &plan.mount)
                .leases
                .remove(&plan.lease.id);
            if removed.is_none() {
                return post_provider_publication_failure(
                    failure("lease retirement disappeared before publication"),
                    &plan.lease.id,
                );
            }
        } else {
            let Some(current) = next
                .database
                .mount_mut(&plan.namespace, &plan.mount)
                .leases
                .get_mut(&plan.lease.id)
            else {
                return post_provider_publication_failure(
                    failure("lease disappeared before terminal publication"),
                    &plan.lease.id,
                );
            };
            current.password = None;
            current.phase = Phase::Active;
            if plan.lease.phase == Phase::PendingRenew {
                current.last_renewal = Some(now);
            }
        }
        if let Err(error) = self.publish_database(next) {
            return post_provider_publication_failure(error, &plan.lease.id);
        }
        // Publication itself may take time. Never release a secret after its
        // authority expired while persisting the terminal state.
        let now = completed_now().max(now);
        if plan.lease.phase != Phase::PendingRevoke {
            let Some(current) = self.state.as_ref() else {
                return post_provider_publication_failure(
                    failure("server sealed after publication"),
                    &plan.lease.id,
                );
            };
            if !Self::database_completion_owner_live(current, plan, now) {
                return self.reject_database_completion(current.clone(), plan, now);
            }
        }
        plan.success_response(now).unwrap_or_else(|error| error)
    }

    fn database_completion_owner_live(state: &State, plan: &DatabaseEffectPlan, now: u64) -> bool {
        plan.lease.expires > now
            && state
                .auth
                .resolve_lease_owner(&plan.lease.owner, &plan.namespace, now)
                .is_some_and(|owner| Self::database_owner_active(state, &owner, &plan.namespace))
    }

    fn reject_database_completion(
        &mut self,
        mut state: State,
        plan: &DatabaseEffectPlan,
        now: u64,
    ) -> Response {
        // The remote effect succeeded. Keep cleanup durable instead of returning
        // its secret or erasing the provider-side obligation. On commit failure
        // the original pending/active record remains available to maintenance.
        state.database.clock = now;
        let staged = Self::stage_revoke(&mut state, &plan.namespace, &plan.mount, &plan.lease.id)
            .and_then(|()| self.publish_database(state));
        post_provider_publication_failure(
            staged.err().unwrap_or_else(|| {
                failure("database lease owner expired or was revoked during provider entry")
            }),
            &plan.lease.id,
        )
    }

    pub(super) fn finalize_database_batch_effect(
        &mut self,
        plan: &DatabaseBatchEffectPlan,
        results: DatabaseBatchEffectResult,
    ) -> Response {
        if results.len() > plan.plans.len() {
            self.recovery_required = true;
            return Response::error(
                503,
                "database prefix revocation result count exceeds the staged batch",
            );
        }
        let attempted = results.len();
        let mut first_error = None;
        for (effect, result) in plan.plans.iter().zip(results) {
            let response = self.finalize_database_effect(effect, result);
            if response.status >= 300 && first_error.is_none() {
                first_error = Some(response);
            }
        }
        if attempted < plan.plans.len() && first_error.is_none() {
            first_error = Some(Response {
                status: 503,
                body: json!({
                    "errors":["database prefix revocation stopped after an indeterminate provider result"],
                    "reconcile_required":true,
                    "retry_allowed":false,
                    "pending_count":plan.plans.len().saturating_sub(attempted)
                }),
            });
        }
        first_error.unwrap_or(Response {
            status: 204,
            body: Value::Null,
        })
    }

    fn stage_revoke(state: &mut State, ns: &str, mount: &str, id: &str) -> Result<(), Response> {
        let (phase, seq) = state
            .database
            .mount(ns, mount)
            .and_then(|database_mount| database_mount.leases.get(id))
            .map(|lease| (lease.phase.clone(), lease.seq))
            .ok_or_else(|| invalid("lease not found"))?;
        if phase == Phase::PendingRevoke && seq == state.database.current_provider_fence() {
            return Ok(());
        }
        // A failed cleanup can be overtaken by another admitted lease operation.
        // Its old sequence must remain rejected by the provider. Re-admit only
        // this subtractive effect under the current Service writer, with a fresh
        // durable sequence/digest before external entry. A current pending revoke
        // keeps its identity unchanged; no remote counter or old backup can grant
        // this process a newer local frontier.

        let provider_fence = state.database.next_provider_fence()?;
        let l = state
            .database
            .mount_mut(ns, mount)
            .leases
            .get_mut(id)
            .ok_or_else(|| invalid("lease not found"))?;
        l.seq = provider_fence;
        l.phase = Phase::PendingRevoke;
        l.password = None;
        l.expires = 0;
        l.request_digest = digest_lease(l)?;
        Ok(())
    }
    fn database_admin(
        &mut self,
        mut state: State,
        _principal: &Principal,
        request: &RequestView<'_>,
        now: u64,
    ) -> Result<Response, Response> {
        let RequestView {
            namespace: ns,
            path,
            method,
            body,
            ..
        } = request;
        if let Some(prefix) = path.strip_prefix("sys/leases/lookup/") {
            if *method != "LIST" {
                return Err(invalid("lease enumeration requires LIST"));
            }
            fields(body, &[])?;
            let boundary = format!("{}/", prefix.trim_end_matches('/'));
            let mut keys = BTreeSet::new();
            if let Some(mounts) = state.database.mounts.get(*ns) {
                for mount in mounts.values() {
                    for l in mount.leases.values().filter(|l| l.phase != Phase::Revoked) {
                        if let Some(tail) = l.id.strip_prefix(&boundary) {
                            keys.insert(
                                tail.split_once('/')
                                    .map(|(first, _)| format!("{first}/"))
                                    .unwrap_or_else(|| tail.into()),
                            );
                        }
                    }
                }
            }
            return Ok(Response::ok(json!({"data":{"keys":keys}})));
        }
        if let Some(prefix) = path.strip_prefix("sys/leases/revoke-prefix/") {
            if !matches!(*method, "POST" | "PUT") {
                return Err(invalid("lease prefix revocation requires POST or PUT"));
            }
            fields(body, &["sync"])?;
            if body.get("sync").is_some_and(|value| value != &json!(true)) {
                return Err(invalid(
                    "database prefix revocation is synchronous or remains explicitly pending",
                ));
            }
            let boundary = format!("{}/", prefix.trim_end_matches('/'));
            let mut matches = Vec::new();
            if let Some(mounts) = state.database.mounts.get(*ns) {
                for (mount_name, database_mount) in mounts {
                    for lease in database_mount.leases.values() {
                        if lease.id.starts_with(&boundary) {
                            matches.push((mount_name.clone(), lease.id.clone()));
                        }
                    }
                }
            }
            if matches.is_empty() {
                return Ok(Response {
                    status: 204,
                    body: Value::Null,
                });
            }
            const MAX_PREFIX_REVOKE_LEASES: usize = 64;
            if matches.len() > MAX_PREFIX_REVOKE_LEASES {
                return Err(Response::error(
                    413,
                    "database revoke-prefix selection exceeds the bounded synchronous batch",
                ));
            }
            if self.pending_database_batch_effect.is_some() {
                return Err(failure(
                    "another database provider batch is already pending dispatch",
                ));
            }
            if let Some((_, id)) = matches
                .iter()
                .find(|(mount, id)| self.database_in_flight.contains(ns, mount, id))
            {
                return Err(Self::database_effect_in_flight(id));
            }
            for (mount_name, id) in &matches {
                Self::stage_revoke(&mut state, ns, mount_name, id)?;
            }
            self.publish_database(state)?;
            let mut plans = Vec::with_capacity(matches.len());
            for (mount_name, id) in matches {
                plans.push(self.database_effect_plan(ns, &mount_name, &id, now)?);
            }
            self.pending_database_batch_effect = Some(DatabaseBatchEffectPlan { plans });
            return Ok(Response::error(
                500,
                "database provider batch was not dispatched",
            ));
        }
        if !matches!(*method, "POST" | "PUT") {
            return Err(invalid("lease operation requires POST or PUT"));
        }
        let (operation, path_id) = if *path == "sys/leases/lookup" {
            ("lookup", None)
        } else if *path == "sys/leases/renew" {
            ("renew", None)
        } else if *path == "sys/leases/revoke" {
            ("revoke", None)
        } else if let Some(id) = path.strip_prefix("sys/leases/revoke/") {
            ("revoke", Some(id))
        } else if let Some(id) = path.strip_prefix("sys/leases/renew/") {
            ("renew", Some(id))
        } else if let Some(id) = path.strip_prefix("sys/leases/reconcile/") {
            ("reconcile", Some(id))
        } else {
            return Err(invalid("unknown database lease operation"));
        };
        fields(
            body,
            match operation {
                "renew" => &["lease_id", "increment"],
                "revoke" => &["lease_id", "sync"],
                _ => &["lease_id"],
            },
        )?;
        if body.get("sync").is_some_and(|v| v != &json!(true)) {
            return Err(invalid(
                "database revocation is synchronous or remains explicitly pending",
            ));
        }
        let body_id = body
            .get("lease_id")
            .map(|_| text(body, "lease_id"))
            .transpose()?;
        if let (Some(a), Some(b)) = (path_id, body_id)
            && a != b
        {
            return Err(invalid("lease_id conflicts with authorized path"));
        }
        let id = path_id
            .or(body_id)
            .ok_or_else(|| invalid("lease_id required"))?;
        let mount = match state.database.locate(ns, id) {
            Some(mount) => mount,
            None if operation == "revoke"
                && state.database.mount_for_lease_prefix(ns, id).is_some() =>
            {
                return Ok(Response {
                    status: 204,
                    body: Value::Null,
                });
            }
            None => return Err(invalid("lease not found")),
        };
        let l = state
            .database
            .mount(ns, &mount)
            .and_then(|m| m.leases.get(id))
            .cloned()
            .ok_or_else(|| invalid("lease not found"))?;
        if operation == "lookup" {
            let renewable = l.phase == Phase::Active
                && l.expires > now
                && l.expires < l.max_expires
                && state
                    .auth
                    .resolve_lease_owner(&l.owner, ns, now)
                    .is_some_and(|owner| Self::database_owner_active(&state, &owner, ns));
            return Ok(Response::ok(
                json!({"data":{"id":l.id,"ttl":l.expires.saturating_sub(now),"renewable":renewable,"issue_time":l.issued,"expire_time":l.expires,"last_renewal":l.last_renewal,"phase":l.phase}}),
            ));
        }
        if self.database_in_flight.contains(ns, &mount, id) {
            return Err(Self::database_effect_in_flight(id));
        }
        if operation == "renew" {
            let owner = state
                .auth
                .resolve_lease_owner(&l.owner, ns, now)
                .ok_or_else(|| Response::error(403, "lease owner expired or revoked"))?;
            if !Self::database_owner_active(&state, &owner, ns)
                || l.phase != Phase::Active
                || l.expires <= now
            {
                return Err(invalid("database lease cannot be renewed"));
            }
            let increment = ttl(body, "increment", 3600)?;
            let expiry = now
                .checked_add(increment)
                .ok_or_else(|| invalid("lease time exhausted"))?
                .min(l.max_expires)
                .min(owner.expires_at.unwrap_or(u64::MAX));
            if expiry <= l.expires {
                return Err(invalid("renewal must advance expiry within maximum TTL"));
            }
            let provider_fence = state.database.next_provider_fence()?;
            let current = state
                .database
                .mount_mut(ns, &mount)
                .leases
                .get_mut(id)
                .ok_or_else(|| invalid("lease not found"))?;
            current.seq = provider_fence;
            current.expires = expiry;
            current.phase = Phase::PendingRenew;
            current.request_digest = digest_lease(current)?;
            self.publish_database(state)?;
            return self.defer_database_effect(ns, &mount, id, now);
        }
        if l.phase == Phase::Revoked {
            return Ok(Response {
                status: 204,
                body: Value::Null,
            });
        }
        Self::stage_revoke(&mut state, ns, &mount, id)?;
        self.publish_database(state)?;
        self.defer_database_effect(ns, &mount, id, now)
    }
    fn database_owner_active(state: &State, owner: &ResolvedLeaseOwner, ns: &str) -> bool {
        owner.entity_id.as_deref().is_none_or(|id| {
            state
                .engines
                .identity_projection(ns, id)
                .is_ok_and(|p| !p.disabled)
        })
    }

    fn database_effect_in_flight(id: &str) -> Response {
        Response {
            status: 503,
            body: json!({
                "errors":["database provider effect is already in flight; durable intent retained"],
                "lease_id":id,
                "reconcile_required":true
            }),
        }
    }
    /// Stage at most one provider reconciliation while holding the Service
    /// writer. The returned plan owns everything required for remote I/O so the
    /// lifecycle worker can release the writer before provider entry.
    pub(super) fn prepare_database_maintenance(
        &mut self,
        now: u64,
    ) -> Result<Option<DatabaseMaintenance>, &'static str> {
        let started = std::time::Instant::now();
        if self.state.is_none() || self.recovery_required || self.audit_failed {
            return Ok(None);
        }
        if let Some(ha) = &self.ha {
            let ha = ha
                .lock_for_request()
                .map_err(|_| "provider HA lock unavailable")?;
            if !ha.is_leader().map_err(|_| "provider leader unavailable")? {
                return Ok(None);
            }
            drop(ha);
            self.sync_from_ha()
                .map_err(|_| "provider ReadIndex unavailable")?;
        }
        self.database_in_flight.prune();
        let state = self.state.as_ref().ok_or("sealed")?;
        let now = now.max(state.database.clock);
        let mut candidates = Vec::new();
        for (ns, mounts) in &state.database.mounts {
            for (mount, m) in mounts {
                for (id, l) in &m.leases {
                    let owner = state.auth.resolve_lease_owner(&l.owner, ns, now);
                    let live = owner
                        .as_ref()
                        .is_some_and(|o| Self::database_owner_active(state, o, ns));
                    // Do not race a live plan's provider I/O or finalization.
                    // Once it is dropped (including failed/abandoned requests)
                    // or the process reopens, recover the durable pending intent.
                    if database_maintenance_candidate(
                        &l.phase,
                        l.expires,
                        now,
                        live,
                        self.database_in_flight.contains(ns, mount, id),
                    ) {
                        candidates.push((ns.clone(), mount.clone(), id.clone()));
                    }
                }
            }
        }
        // Advisory cursor only; pending/terminal truth remains in durable state.
        // A permanently unavailable provider must not starve later leases.
        let selected = candidates
            .iter()
            .find(|key| self.database_cursor.as_ref().is_none_or(|last| *key > last))
            .or_else(|| candidates.first())
            .cloned();
        if selected.is_some() {
            self.database_cursor = selected.clone();
        }
        let Some((ns, mount, id)) = selected else {
            return Ok(None);
        };
        let mut state = state.clone();
        let fingerprint = self.request_fingerprint("INTERNAL", "database/reconcile", &ns, "");
        self.audit_event("provider-request", &fingerprint, now, None)
            .map_err(|_| "provider audit unavailable")?;
        state.database.clock = now;
        Self::stage_revoke(&mut state, &ns, &mount, &id)
            .map_err(|_| "cannot stage provider revoke")?;
        self.publish_database(state)
            .map_err(|_| "provider intent not committed")?;
        self.defer_database_effect(&ns, &mount, &id, now)
            .map_err(|_| "provider plan unavailable")?;
        let mut plan = self
            .pending_database_effect
            .take()
            .ok_or("provider plan unavailable")?;
        plan.started = started;
        Ok(Some(DatabaseMaintenance {
            fingerprint,
            now,
            plan,
        }))
    }

    pub(super) fn finish_database_maintenance(
        &mut self,
        pending: DatabaseMaintenance,
        provider_result: Result<(), Response>,
    ) -> Result<bool, &'static str> {
        let response = self.finalize_database_effect(&pending.plan, provider_result);
        let completed = response.status < 300;
        if self
            .audit_event(
                "provider-response",
                &pending.fingerprint,
                pending.now,
                Some(if completed { 204 } else { 503 }),
            )
            .is_err()
        {
            self.recovery_required = true;
            return Err("provider result audit unavailable");
        }
        if !completed {
            return Err("provider remains indeterminate");
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug)]
    struct TestFailure;
    impl From<Response> for TestFailure {
        fn from(_: Response) -> Self {
            Self
        }
    }

    #[test]
    fn database_username_accepts_mysql_bound_and_historical_shape() {
        assert!(valid_database_username(&format!("hbp_{}", "ab".repeat(14))));
        assert!(valid_database_username(&format!("hbp_{}", "ab".repeat(16))));
        assert!(!valid_database_username(&format!(
            "hbp_{}",
            "ab".repeat(13)
        )));
        assert!(!valid_database_username(&format!(
            "hbp_{}",
            "ab".repeat(15)
        )));
        assert!(!valid_database_username(&format!(
            "hbp_{}",
            "zz".repeat(14)
        )));
    }

    #[test]
    fn native_database_names_preserve_deployed_provider_contracts() {
        let entropy = [0xab; 16];
        for provider in [DatabaseProvider::Postgresql, DatabaseProvider::Valkey] {
            let username = generated_database_username(provider, &entropy);
            assert_eq!(username, format!("hbp_{}", "ab".repeat(16)));
            assert!(valid_database_username(&username));
        }
    }

    #[test]
    fn plugin_database_names_keep_mysql_limit_without_changing_native_names() {
        let entropy = [0xcd; 16];
        let username = generated_database_username(DatabaseProvider::Plugin, &entropy);
        assert_eq!(username.len(), 32);
        assert_eq!(username, format!("hbp_{}", "cd".repeat(14)));
        assert!(valid_database_username(&username));
        assert_ne!(
            username,
            generated_database_username(DatabaseProvider::Postgresql, &entropy)
        );
    }

    #[test]
    fn provider_completion_publication_failure_is_never_before_entry_rejection() {
        for status in [400, 503, 507] {
            let error = Response {
                status,
                body: json!({"recovery_reference":"synthetic-local-reference", "password":"must-not-escape"}),
            };
            let result =
                post_provider_publication_failure(error, "database/creds/reader/synthetic");
            assert_eq!(result.status, 503);
            assert_eq!(result.body["lease_id"], "database/creds/reader/synthetic");
            assert_eq!(result.body["reconcile_required"], true);
            assert_eq!(result.body["retry_allowed"], false);
            assert_eq!(
                result.body["recovery_reference"],
                "synthetic-local-reference"
            );
            assert!(result.body.get("password").is_none());
        }
    }

    #[test]
    fn database_flights_are_process_local_and_reopen_pending_work_after_drop() {
        let mut flights = DatabaseFlights::default();
        assert!(!flights.contains("", "database/", "database/creds/reader/1"));
        let first = flights.track("", "database/", "database/creds/reader/1");
        assert!(flights.contains("", "database/", "database/creds/reader/1"));
        let response = Service::database_effect_in_flight("database/creds/reader/1");
        assert_eq!(response.status, 503);
        assert_eq!(response.body["reconcile_required"], true);
        let second = flights.track("", "database/", "database/creds/reader/1");
        drop(second);
        assert!(flights.contains("", "database/", "database/creds/reader/1"));
        drop(first);
        flights.prune();
        assert!(!flights.contains("", "database/", "database/creds/reader/1"));

        // A fresh Service process has a fresh empty registry and can recover a
        // persisted pending intent without inheriting process-local ownership.
        let fresh = DatabaseFlights::default();
        assert!(!fresh.contains("", "database/", "database/creds/reader/1"));
    }

    #[test]
    fn database_maintenance_skips_live_pending_effects_but_reclaims_after_drop() {
        let mut flights = DatabaseFlights::default();
        let flight = flights.track("", "database/", "database/creds/reader/1");
        assert!(!database_maintenance_candidate(
            &Phase::PendingIssue,
            100,
            100,
            true,
            flights.contains("", "database/", "database/creds/reader/1"),
        ));
        assert!(!database_maintenance_candidate(
            &Phase::PendingRenew,
            200,
            100,
            true,
            flights.contains("", "database/", "database/creds/reader/1"),
        ));
        assert!(!database_maintenance_candidate(
            &Phase::PendingRevoke,
            0,
            100,
            false,
            flights.contains("", "database/", "database/creds/reader/1"),
        ));
        drop(flight);
        flights.prune();
        assert!(database_maintenance_candidate(
            &Phase::PendingIssue,
            100,
            100,
            true,
            flights.contains("", "database/", "database/creds/reader/1"),
        ));
        assert!(database_maintenance_candidate(
            &Phase::PendingRenew,
            200,
            100,
            true,
            flights.contains("", "database/", "database/creds/reader/1"),
        ));
        assert!(!database_maintenance_candidate(
            &Phase::Quarantined,
            0,
            100,
            false,
            false
        ));
    }

    fn sample() -> Result<(DatabaseState, String), Response> {
        let id = "database/creds/reader/001122".to_owned();
        let mut state = DatabaseState::default();
        let m = state.mount_mut("", "database/");
        m.connections.insert(
            "local".into(),
            Connection {
                provider: DatabaseProvider::Postgresql,
                plugin_id: None,
                connection_url: "postgresql://localhost:5432/app".into(),
                username: "hb_manager".into(),
                password: PrivateString("synthetic-password".into()),
                allowed_roles: BTreeSet::from(["reader".into()]),
            },
        );
        let mut l = DatabaseLease {
            id: id.clone(),
            provider_id: provider_identity("cluster", "", &id)?,
            username: format!("hbp_{}", "ab".repeat(16)),
            db_name: "local".into(),
            provider_role: "app_reader".into(),
            owner: LeaseOwner::service(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]),
            )
            .map_err(|_| failure("fixture lease owner"))?,
            issued: 1000,
            expires: 1100,
            max_expires: 1200,
            last_renewal: None,
            seq: 1,
            phase: Phase::PendingIssue,
            password: Some(PrivateString("ab".repeat(32))),
            request_digest: String::new(),
        };
        l.request_digest = digest_lease(&l)?;
        m.leases.insert(id.clone(), l);
        Ok((state, id))
    }
    #[test]
    fn pending_database_state_survives_serde_with_real_owner_digest_shape()
    -> Result<(), TestFailure> {
        let (s, _) = sample()?;
        s.validate_scope("cluster")?;
        let raw = serde_json::to_vec(&s).map_err(|_| failure("serialize"))?;
        let restored: DatabaseState =
            serde_json::from_slice(&raw).map_err(|_| failure("deserialize"))?;
        restored.validate_scope("cluster")?;
        Ok(())
    }
    #[test]
    fn provider_identity_binds_cluster_namespace_and_lease() -> Result<(), TestFailure> {
        let (mut s, id) = sample()?;
        assert!(s.validate_scope("another").is_err());
        let l = s
            .mount_mut("", "database/")
            .leases
            .get_mut(&id)
            .ok_or_else(|| failure("missing"))?;
        l.provider_id = provider_identity("cluster", "other", &id)?;
        l.request_digest = digest_lease(l)?;
        assert!(s.validate_scope("cluster").is_err());
        Ok(())
    }
    #[test]
    fn persisted_pending_intent_rejects_payload_drift() -> Result<(), TestFailure> {
        let (mut s, id) = sample()?;
        s.mount_mut("", "database/")
            .leases
            .get_mut(&id)
            .ok_or_else(|| failure("missing"))?
            .expires += 1;
        assert!(s.validate_scope("cluster").is_err());
        Ok(())
    }
    #[test]
    fn active_database_state_cannot_retain_plaintext_password() -> Result<(), TestFailure> {
        let (mut s, id) = sample()?;
        let l = s
            .mount_mut("", "database/")
            .leases
            .get_mut(&id)
            .ok_or_else(|| failure("missing"))?;
        l.phase = Phase::Active;
        assert!(s.validate_scope("cluster").is_err());
        Ok(())
    }
    #[test]
    fn pending_revoke_has_no_secret_and_a_new_fence() -> Result<(), TestFailure> {
        let (mut s, id) = sample()?;
        let l = s
            .mount_mut("", "database/")
            .leases
            .get_mut(&id)
            .ok_or_else(|| failure("missing"))?;
        l.phase = Phase::PendingRevoke;
        l.seq += 1;
        l.password = None;
        l.expires = 0;
        l.request_digest = digest_lease(l)?;
        s.validate_scope("cluster")?;
        Ok(())
    }
    #[test]
    fn provider_fence_is_global_monotonic_and_survives_legacy_lease_sequences()
    -> Result<(), TestFailure> {
        let (mut state, id) = sample()?;
        assert_eq!(state.provider_fence, 0);
        assert_eq!(state.next_provider_fence()?, 2);
        assert_eq!(state.next_provider_fence()?, 3);
        let lease = state
            .mount_mut("", "database/")
            .leases
            .get_mut(&id)
            .ok_or_else(|| failure("missing"))?;
        lease.seq = 9;
        lease.request_digest = digest_lease(lease)?;
        assert_eq!(state.next_provider_fence()?, 10);
        state.validate_scope("cluster")?;
        Ok(())
    }

    #[test]
    fn retired_database_leases_do_not_create_a_lifetime_128_issue_ceiling()
    -> Result<(), TestFailure> {
        let (mut state, seed_id) = sample()?;
        state
            .mount_mut("", "database/")
            .leases
            .remove(&seed_id)
            .ok_or_else(|| failure("seed lease missing"))?;

        // The 128-entry bound is a simultaneous retained-lease bound, not a
        // lifetime issuance bound. Provider retirement removes terminal rows
        // while the monotonic provider fence survives and continues fencing any
        // delayed effect from an older lease incarnation.
        for index in 0..512_u64 {
            let id = format!("database/creds/reader/{index:016x}");
            let seq = state.next_provider_fence()?;
            let mut lease = DatabaseLease {
                id: id.clone(),
                provider_id: provider_identity("cluster", "", &id)?,
                username: format!("hbp_{:032x}", index + 1),
                db_name: "local".into(),
                provider_role: "app_reader".into(),
                owner: LeaseOwner::service(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]),
                )
                .map_err(|_| failure("fixture lease owner"))?,
                issued: 1000 + index,
                expires: 1100 + index,
                max_expires: 1200 + index,
                last_renewal: None,
                seq,
                phase: Phase::PendingIssue,
                password: Some(PrivateString("ab".repeat(32))),
                request_digest: String::new(),
            };
            lease.request_digest = digest_lease(&lease)?;
            state
                .mount_mut("", "database/")
                .leases
                .insert(id.clone(), lease);
            state.validate_scope("cluster")?;
            state
                .mount_mut("", "database/")
                .leases
                .remove(&id)
                .ok_or_else(|| failure("retired lease missing"))?;
        }

        assert!(
            state
                .mount("", "database/")
                .is_some_and(|mount| mount.leases.is_empty())
        );
        assert!(state.provider_fence >= 512);
        state.validate_scope("cluster")?;

        let raw = serde_json::to_vec(&state).map_err(|_| failure("serialize"))?;
        let restored: DatabaseState =
            serde_json::from_slice(&raw).map_err(|_| failure("deserialize"))?;
        assert_eq!(restored.provider_fence, state.provider_fence);
        restored.validate_scope("cluster")?;
        Ok(())
    }

    #[test]
    fn provider_wire_and_ttl_bounds_do_not_accept_silent_fallbacks() {
        assert!(ttl(&json!({"ttl":"18446744073709551615h"}), "ttl", 1).is_err());
        assert!(ttl(&json!({"ttl":false}), "ttl", 1).is_err());
        assert!(!name("bad; DROP ROLE manager"));
        assert!(fields(&json!({"creation_statements":[]}), &["provider_role"]).is_err());
        assert!(
            valkey_permissions("readonly")
                .is_some_and(|p| p.contains(&"+get") && !p.contains(&"+set"))
        );
        assert!(valkey_permissions("+@all").is_none());
    }

    fn acl_value(flags: &[&str], commands: &str, keys: &str, passwords: &[&str]) -> RespValue {
        let text = |s: &str| RespValue::Bulk(Zeroizing::new(s.as_bytes().to_vec()));
        RespValue::Array(vec![
            text("flags"),
            RespValue::Array(flags.iter().map(|s| text(s)).collect()),
            text("passwords"),
            RespValue::Array(passwords.iter().map(|s| text(s)).collect()),
            text("commands"),
            text(commands),
            text("keys"),
            text(keys),
            text("channels"),
            text(""),
            text("selectors"),
            RespValue::Array(Vec::new()),
        ])
    }

    #[test]
    fn valkey_readback_rejects_privilege_password_selector_and_shape_drift() {
        let pattern = "~hb:hb1:abcd:*";
        let password = "ab".repeat(32);
        let permissions = &["+ping", "+get"][..];
        let valid = || acl_value(&["on"], "-@all +get +ping", pattern, &[&password]);
        assert!(valkey_acl_readback_matches(
            &valid(),
            pattern,
            permissions,
            Some(&password)
        ));
        for value in [
            acl_value(&["on", "nopass"], "-@all +get +ping", pattern, &[&password]),
            acl_value(&["on"], "-@all +get +ping +flushall", pattern, &[&password]),
            acl_value(&["on"], "-@all +get +ping", "~*", &[&password]),
            acl_value(&["on"], "-@all +get +ping", pattern, &[]),
            acl_value(
                &["on"],
                "-@all +get +ping",
                pattern,
                &[&password, &password],
            ),
        ] {
            assert!(!valkey_acl_readback_matches(
                &value,
                pattern,
                permissions,
                None
            ));
        }
        assert!(!valkey_acl_readback_matches(
            &valid(),
            pattern,
            permissions,
            Some(&"cd".repeat(32))
        ));
        let RespValue::Array(mut fields) = valid() else {
            unreachable!()
        };
        fields[11] = RespValue::Array(vec![RespValue::Array(Vec::new())]);
        assert!(!valkey_acl_readback_matches(
            &RespValue::Array(fields),
            pattern,
            permissions,
            None
        ));
        let RespValue::Array(mut fields) = valid() else {
            unreachable!()
        };
        fields.push(RespValue::Null);
        assert!(!valkey_acl_readback_matches(
            &RespValue::Array(fields),
            pattern,
            permissions,
            None
        ));
    }

    #[test]
    fn valkey_durable_fence_rejects_stale_and_conflicting_envelopes() -> Result<(), TestFailure> {
        let digest = "ab".repeat(32);
        let marker = acl_value(&["off"], "-@all", &format!("~10:{digest}"), &[]);
        let fence = valkey_fence_readback(&marker).ok_or(TestFailure)?;
        assert_eq!(fence, Some((10, digest.as_str())));
        assert!(!valkey_fence_admits(fence, 9, &digest));
        assert!(!valkey_fence_admits(fence, 10, &"cd".repeat(32)));
        assert!(valkey_fence_admits(fence, 10, &digest));
        assert!(valkey_fence_admits(fence, 11, &"cd".repeat(32)));
        assert!(
            valkey_fence_readback(&acl_value(&["on"], "-@all", &format!("~10:{digest}"), &[]))
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn legacy_database_owner_and_intent_match_fixed_pre_typed_bytes() -> Result<(), TestFailure> {
        const OLD_LEASE: &str = r#"{"id":"database/creds/reader/001122","provider_id":"hb1:a46dc356b4f33603e447e6367d32851521a6a6754ac4aa1895a03046716a47f4","username":"hbp_abababababababababababababababab","db_name":"local","provider_role":"app_reader","owner":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","issued":1000,"expires":1100,"max_expires":1200,"last_renewal":null,"seq":1,"phase":"PendingIssue","password":"abababababababababababababababababababababababababababababababab","request_digest":"dd686f4f2c376995c54e836972574036fd8d0762177c49d94358ed27c0f6c879"}"#;
        const OLD_INTENT_DIGEST: &str =
            "dd686f4f2c376995c54e836972574036fd8d0762177c49d94358ed27c0f6c879";
        let legacy: DatabaseLease =
            serde_json::from_str(OLD_LEASE).map_err(|_| failure("legacy fixture decode"))?;
        assert_eq!(
            serde_json::to_string(&legacy).map_err(|_| failure("legacy fixture encode"))?,
            OLD_LEASE
        );
        assert_eq!(digest_lease(&legacy)?, OLD_INTENT_DIGEST);
        let (state, id) = sample()?;
        let actual = state
            .mount("", "database/")
            .and_then(|mount| mount.leases.get(&id))
            .ok_or(TestFailure)?;
        assert_eq!(
            serde_json::to_string(actual).map_err(|_| failure("sample encode"))?,
            OLD_LEASE
        );
        Ok(())
    }

    #[test]
    fn pending_and_revoked_database_batch_owners_remain_scoped_and_enumerated()
    -> Result<(), TestFailure> {
        use crate::auth::{BatchClaims, BatchKeyAuthority};
        let mut authority = BatchKeyAuthority::new(1000).map_err(|_| failure("authority"))?;
        let token = authority
            .seal(
                BatchClaims {
                    namespace: String::new(),
                    policies: BTreeSet::new(),
                    metadata: BTreeMap::new(),
                    display_name: "fixture".into(),
                    path: "auth/userpass/login/fixture".into(),
                    bound_cidrs: Vec::new(),
                    issued_at: 1000,
                    expires_at: 1200,
                    parent: None,
                    entity_id: None,
                },
                1000,
            )
            .map_err(|_| failure("seal"))?;
        let verified = authority
            .open(token.as_str(), "", 1000)
            .map_err(|_| failure("open"))?;
        let owner = LeaseOwner::from_batch(&verified);
        let (mut state, id) = sample()?;
        state
            .mount_mut("", "database/")
            .leases
            .get_mut(&id)
            .ok_or(TestFailure)?
            .owner = owner.clone();
        state.validate_scope("cluster")?;
        assert!(
            state
                .all_lease_owners()
                .contains(&(String::new(), owner.clone()))
        );
        let pending = serde_json::to_vec(&state).map_err(|_| failure("encode"))?;
        for phase in [Phase::PendingRevoke, Phase::Revoked] {
            let lease = state
                .mount_mut("", "database/")
                .leases
                .get_mut(&id)
                .ok_or(TestFailure)?;
            lease.phase = phase;
            lease.expires = 0;
            lease.password = None;
            lease.request_digest = digest_lease(lease)?;
            state.validate_scope("cluster")?;
            assert!(
                state
                    .all_lease_owners()
                    .contains(&(String::new(), owner.clone()))
            );
        }
        let restored: DatabaseState =
            serde_json::from_slice(&serde_json::to_vec(&state).map_err(|_| failure("encode"))?)
                .map_err(|_| failure("decode"))?;
        restored.validate_scope("cluster")?;
        assert_eq!(
            restored
                .mount("", "database/")
                .and_then(|mount| mount.leases.get(&id))
                .map(|lease| lease.expires),
            Some(0)
        );
        let mut inflated: DatabaseState =
            serde_json::from_slice(&pending).map_err(|_| failure("decode"))?;
        let lease = inflated
            .mount_mut("", "database/")
            .leases
            .get_mut(&id)
            .ok_or(TestFailure)?;
        lease.max_expires = 1600;
        lease.expires = 1300;
        lease.request_digest = digest_lease(lease)?;
        assert!(inflated.validate_scope("cluster").is_err());
        let mut crossed: DatabaseState =
            serde_json::from_slice(&pending).map_err(|_| failure("decode"))?;
        let mounts = crossed.mounts.remove("").ok_or(TestFailure)?;
        crossed.mounts.insert("other".into(), mounts);
        let lease = crossed
            .mount_mut("other", "database/")
            .leases
            .get_mut(&id)
            .ok_or(TestFailure)?;
        lease.provider_id = provider_identity("cluster", "other", &id)?;
        lease.request_digest = digest_lease(lease)?;
        assert!(crossed.validate_scope("cluster").is_err());
        Ok(())
    }

    type CompletionResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    type CompletionFixture = (
        super::super::tests::Root,
        Service,
        String,
        String,
        DatabaseEffectPlan,
    );

    fn completion_fixture(phase: Phase) -> CompletionResult<CompletionFixture> {
        completion_fixture_with_ttl(phase, 120)
    }

    fn completion_fixture_with_ttl(phase: Phase, ttl: u64) -> CompletionResult<CompletionFixture> {
        use super::super::tests::{Root, bootstrap, call};
        let root = Root::new();
        let mut service = root.service()?;
        let (key, root_token) = bootstrap(&mut service)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/mounts/database",
                &root_token,
                json!({"type":"database"})
            )
            .status,
            204
        );
        let token = call(
            &mut service,
            "POST",
            "auth/token/create",
            &root_token,
            json!({"policies":["default"], "ttl":ttl}),
        );
        assert_eq!(token.status, 200);
        let token = token.body["auth"]["client_token"]
            .as_str()
            .ok_or("token")?
            .to_owned();
        let mut state = service.state.clone().ok_or("state")?;
        let actor = state.auth.authenticate(&token, 100).map_err(|_| "actor")?;
        let owner = state
            .auth
            .typed_lease_issuer(&actor, "", 100)
            .map_err(|_| "owner")?;
        let (mut database, id) = sample().map_err(|_| "sample")?;
        database.clock = 100;
        let lease = database
            .mount_mut("", "database/")
            .leases
            .get_mut(&id)
            .ok_or("lease")?;
        lease.provider_id = provider_identity(&state.cluster_id, "", &id).map_err(|_| "id")?;
        lease.owner = owner.owner;
        lease.issued = 100;
        lease.expires = if phase == Phase::PendingRevoke {
            0
        } else {
            100 + ttl.min(100)
        };
        lease.max_expires = 220;
        lease.phase = phase;
        if lease.phase != Phase::PendingIssue {
            lease.password = None;
        }
        lease.request_digest = digest_lease(lease).map_err(|_| "digest")?;
        state.database = database.into();
        service.publish_database(state).map_err(|_| "publish")?;
        let plan = service
            .database_effect_plan("", "database/", &id, 100)
            .map_err(|_| "plan")?;
        Ok((root, service, key, root_token, plan))
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pending_revoke_overtaken_by_other_work_is_readmitted_without_identity_change()
    -> CompletionResult {
        let (root, mut service, key, _, plan) = completion_fixture(Phase::PendingRevoke)?;
        let mut state = service.state.clone().ok_or("state")?;
        let original = (
            plan.lease.id.clone(),
            plan.lease.provider_id.clone(),
            plan.lease.username.clone(),
            plan.lease.seq,
        );
        let newer = state.database.next_provider_fence().map_err(|_| "newer")?;
        assert!(newer > original.3);
        Service::stage_revoke(&mut state, "", "database/", &original.0).map_err(|_| "readmit")?;
        let lease = state
            .database
            .mount("", "database/")
            .and_then(|mount| mount.leases.get(&original.0))
            .ok_or("lease")?;
        assert_eq!(
            (&lease.id, &lease.provider_id, &lease.username),
            (&original.0, &original.1, &original.2)
        );
        assert!(lease.seq > newer);
        assert!(lease.phase == Phase::PendingRevoke);
        assert_eq!(lease.expires, 0);
        assert!(lease.password.is_none());
        let seq = lease.seq;
        let digest = lease.request_digest.clone();
        Service::stage_revoke(&mut state, "", "database/", &original.0).map_err(|_| "retry")?;
        service.publish_database(state).map_err(|_| "publish")?;
        // A delayed success for the older attempt must not overwrite the
        // replacement intent or claim this freshly admitted cleanup completed.
        let response = service.finalize_database_effect(&plan, Ok(()));
        assert_eq!(response.status, 503);
        let lease = service
            .state
            .as_ref()
            .ok_or("state")?
            .database
            .mount("", "database/")
            .and_then(|m| m.leases.get(&original.0))
            .ok_or("lease")?;
        assert_eq!(lease.seq, seq);
        assert_eq!(lease.request_digest, digest);
        assert!(lease.phase == Phase::PendingRevoke);
        drop(plan);
        drop(service);

        // Reopen the actual encrypted owner, not only a serialized lease. The
        // freshly committed cleanup is current and must not be readmitted again.
        let mut service = root.service()?;
        assert_eq!(
            super::super::tests::call(&mut service, "PUT", "sys/unseal", "", json!({"key":key}))
                .status,
            200
        );
        let pending = service
            .prepare_database_maintenance(101)?
            .ok_or("cleanup")?;
        let lease = &pending.plan.lease;
        assert_eq!(
            (&lease.id, &lease.provider_id, &lease.username),
            (&original.0, &original.1, &original.2)
        );
        assert_eq!(lease.seq, seq);
        assert_eq!(lease.request_digest, digest);
        assert!(lease.phase == Phase::PendingRevoke);
        assert!(lease.password.is_none());
        assert_eq!(lease.expires, 0);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn overtaken_pending_revoke_waits_for_its_live_plan_before_readmission() -> CompletionResult {
        let (_root, mut service, _, token, plan) = completion_fixture(Phase::PendingRevoke)?;
        let mut state = service.state.clone().ok_or("state")?;
        let newer = state.database.next_provider_fence().map_err(|_| "newer")?;
        service.publish_database(state).map_err(|_| "publish")?;
        let before = serde_json::to_vec(&*service.state.as_ref().ok_or("state")?.database)?;
        assert!(service.prepare_database_maintenance(100)?.is_none());
        let response = super::super::tests::call(
            &mut service,
            "POST",
            "sys/leases/revoke",
            &token,
            json!({"lease_id":plan.lease.id}),
        );
        assert_eq!(response.status, 503);
        assert_eq!(response.body["reconcile_required"], true);
        assert_eq!(
            serde_json::to_vec(&*service.state.as_ref().ok_or("state")?.database)?,
            before
        );
        let id = plan.lease.id.clone();
        drop(plan);
        let pending = service
            .prepare_database_maintenance(100)?
            .ok_or("cleanup")?;
        assert_eq!(pending.plan.lease.id, id);
        assert!(pending.plan.lease.seq > newer);
        assert!(pending.plan.lease.phase == Phase::PendingRevoke);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn overtaken_revoke_fence_exhaustion_is_atomic() -> CompletionResult {
        let (_root, service, _, _, plan) = completion_fixture(Phase::PendingRevoke)?;
        let mut state = service.state.clone().ok_or("state")?;
        state.database.provider_fence = i64::MAX as u64;
        let before = serde_json::to_vec(&*state.database)?;
        assert!(Service::stage_revoke(&mut state, "", "database/", &plan.lease.id).is_err());
        assert_eq!(serde_json::to_vec(&*state.database)?, before);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn historical_short_native_intent_reopens_as_same_identity_cleanup() -> CompletionResult {
        let (root, mut service, key, _, plan) = completion_fixture(Phase::PendingIssue)?;
        let mut state = service.state.clone().ok_or("state")?;
        let lease = state
            .database
            .mount_mut("", "database/")
            .leases
            .get_mut(&plan.lease.id)
            .ok_or("lease")?;
        // Reproduce the committed short-name shape from the MySQL spillover,
        // not a newly issued credential under the corrected native contract.
        lease.username = format!("hbp_{}", "ab".repeat(14));
        lease.request_digest = digest_lease(lease).map_err(|_| "digest")?;
        let original = (
            lease.id.clone(),
            lease.provider_id.clone(),
            lease.username.clone(),
            lease.seq,
            lease.request_digest.clone(),
        );
        service.publish_database(state).map_err(|_| "publish")?;
        drop(plan);
        drop(service);

        let mut service = root.service()?;
        assert_eq!(
            super::super::tests::call(&mut service, "PUT", "sys/unseal", "", json!({"key":key}))
                .status,
            200
        );
        let pending = service
            .prepare_database_maintenance(100)?
            .ok_or("cleanup")?;
        let lease = &pending.plan.lease;
        assert_eq!(
            (&lease.id, &lease.provider_id, &lease.username),
            (&original.0, &original.1, &original.2)
        );
        assert!(lease.phase == Phase::PendingRevoke);
        assert!(lease.password.is_none());
        assert_eq!(lease.expires, 0);
        assert!(lease.seq > original.3);
        assert_ne!(lease.request_digest, original.4);
        let seq = lease.seq;
        let digest = lease.request_digest.clone();
        drop(pending);
        drop(service);

        // A second restart must resume that same cleanup, not re-issue or
        // silently rename the obligation and not allocate a fresh sequence.
        let mut service = root.service()?;
        assert_eq!(
            super::super::tests::call(&mut service, "PUT", "sys/unseal", "", json!({"key":key}))
                .status,
            200
        );
        let pending = service
            .prepare_database_maintenance(101)?
            .ok_or("cleanup")?;
        let lease = &pending.plan.lease;
        assert_eq!(
            (&lease.id, &lease.provider_id, &lease.username),
            (&original.0, &original.1, &original.2)
        );
        assert!(lease.phase == Phase::PendingRevoke);
        assert!(lease.password.is_none());
        assert_eq!(lease.seq, seq);
        assert_eq!(lease.request_digest, digest);
        Ok(())
    }

    #[test]
    fn completion_database_expired_issue_and_renew_keep_durable_cleanup_without_secret()
    -> CompletionResult {
        for phase in [Phase::PendingIssue, Phase::PendingRenew] {
            let (root, mut service, key, _, mut plan) = completion_fixture(phase)?;
            plan.started = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(121))
                .ok_or("clock")?;
            let response = service.finalize_database_effect(&plan, Ok(()));
            assert_eq!(response.status, 503);
            assert_eq!(response.body["retry_allowed"], false);
            assert_eq!(response.body["reconcile_required"], true);
            assert!(response.body.get("data").is_none());
            let lease = service
                .state
                .as_ref()
                .ok_or("state")?
                .database
                .mount("", "database/")
                .ok_or("mount")?
                .leases
                .get(&plan.lease.id)
                .ok_or("lease")?;
            assert!(lease.phase == Phase::PendingRevoke);
            assert!(lease.password.is_none());
            assert!(lease.seq > plan.lease.seq);
            drop(plan);
            drop(service);
            let mut service = root.service()?;
            assert_eq!(
                super::super::tests::call(
                    &mut service,
                    "PUT",
                    "sys/unseal",
                    "",
                    json!({"key":key})
                )
                .status,
                200
            );
            let pending = service
                .prepare_database_maintenance(222)?
                .ok_or("cleanup")?;
            assert!(pending.plan.lease.phase == Phase::PendingRevoke);
            // Revocation completion must work even though its original owner is dead.
            assert_eq!(
                service
                    .finalize_database_effect(&pending.plan, Ok(()))
                    .status,
                204
            );
        }
        Ok(())
    }

    #[test]
    fn completion_database_owner_change_with_identical_digest_is_rejected_without_mutation()
    -> CompletionResult {
        let (_root, mut service, _, _, mut plan) = completion_fixture(Phase::PendingIssue)?;
        plan.lease.owner = LeaseOwner::service(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
        )
        .map_err(|_| "owner")?;
        let durable = service.durable.as_ref().ok_or("durable")?;
        let generation = durable.generation();
        let saved = durable.get("system", "state")?;
        assert_eq!(service.finalize_database_effect(&plan, Ok(())).status, 503);
        let durable = service.durable.as_ref().ok_or("durable")?;
        assert_eq!(durable.generation(), generation);
        assert_eq!(durable.get("system", "state")?, saved);
        Ok(())
    }

    #[test]
    fn completion_database_live_owner_is_published_and_remaining_ttl_uses_completion_clock()
    -> CompletionResult {
        let (_root, mut service, _, _, mut plan) = completion_fixture(Phase::PendingIssue)?;
        plan.started = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(2))
            .ok_or("clock")?;
        let response = service.finalize_database_effect(&plan, Ok(()));
        assert_eq!(response.status, 200);
        assert!(response.body["data"]["password"].is_string());
        assert!(
            response.body["lease_duration"]
                .as_u64()
                .is_some_and(|ttl| ttl <= 98 && ttl > 0)
        );
        let lease = service
            .state
            .as_ref()
            .ok_or("state")?
            .database
            .mount("", "database/")
            .ok_or("mount")?
            .leases
            .get(&plan.lease.id)
            .ok_or("lease")?;
        assert!(lease.phase == Phase::Active);
        assert!(lease.password.is_none());
        Ok(())
    }

    #[test]
    fn completion_database_revoke_succeeds_after_owner_expires() -> CompletionResult {
        let (_root, mut service, _, _, mut plan) = completion_fixture(Phase::PendingRevoke)?;
        plan.started = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(121))
            .ok_or("clock")?;
        assert_eq!(service.finalize_database_effect(&plan, Ok(())).status, 204);
        assert!(
            service
                .state
                .as_ref()
                .ok_or("state")?
                .database
                .mount("", "database/")
                .ok_or("mount")?
                .leases
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn completion_database_one_second_owner_uses_integer_second_domain() -> CompletionResult {
        for delayed in [false, true] {
            let (_root, mut service, _, _, mut plan) =
                completion_fixture_with_ttl(Phase::PendingIssue, 1)?;
            if delayed {
                plan.started = std::time::Instant::now()
                    .checked_sub(std::time::Duration::from_secs(1))
                    .ok_or("clock")?;
            }
            let response = service.finalize_database_effect(&plan, Ok(()));
            assert_eq!(response.status, if delayed { 503 } else { 200 });
            if delayed {
                assert!(response.body.get("data").is_none());
            } else {
                assert_eq!(response.body["lease_duration"], 1);
            }
        }
        Ok(())
    }

    #[test]
    fn completion_database_parent_revocation_during_provider_io_stages_cleanup() -> CompletionResult
    {
        let (_root, mut service, _, root_token, plan) = completion_fixture(Phase::PendingIssue)?;
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
            .publish_database(state)
            .map_err(|_| "publish revocation")?;
        let response = service.finalize_database_effect(&plan, Ok(()));
        assert_eq!(response.status, 503);
        assert!(response.body.get("data").is_none());
        let lease = service
            .state
            .as_ref()
            .ok_or("state")?
            .database
            .mount("", "database/")
            .ok_or("mount")?
            .leases
            .get(&plan.lease.id)
            .ok_or("lease")?;
        assert!(lease.phase == Phase::PendingRevoke);
        Ok(())
    }

    #[test]
    fn completion_database_owner_expires_during_terminal_commit_no_secret_is_released()
    -> CompletionResult {
        let (_root, mut service, _, _, plan) = completion_fixture(Phase::PendingIssue)?;
        let generation = service.durable.as_ref().ok_or("durable")?.generation();
        let mut reads = 0;
        let response = service.finalize_database_effect_with_clock(&plan, Ok(()), || {
            reads += 1;
            if reads == 1 { 100 } else { 221 }
        });
        assert_eq!(reads, 2);
        assert_eq!(response.status, 503);
        assert_eq!(response.body["retry_allowed"], false);
        assert!(response.body.get("data").is_none());
        assert!(service.durable.as_ref().ok_or("durable")?.generation() > generation);
        let lease = service
            .state
            .as_ref()
            .ok_or("state")?
            .database
            .mount("", "database/")
            .ok_or("mount")?
            .leases
            .get(&plan.lease.id)
            .ok_or("lease")?;
        assert!(lease.phase == Phase::PendingRevoke);
        Ok(())
    }

    #[test]
    fn completion_database_verified_batch_expiry_and_parent_revoke_never_publish_secret()
    -> CompletionResult {
        use crate::auth::{BatchClaims, BatchKeyAuthority};
        for parent_revoked in [false, true] {
            let (_root, mut service, _, root_token, mut plan) =
                completion_fixture(Phase::PendingIssue)?;
            let mut state = service.state.clone().ok_or("state")?;
            let mut authority = BatchKeyAuthority::new(100)?;
            let parent = parent_revoked.then(|| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(crate::crypto::digest(root_token.as_bytes()))
            });
            let raw = authority.seal(
                BatchClaims {
                    namespace: String::new(),
                    policies: BTreeSet::from(["default".into()]),
                    metadata: BTreeMap::new(),
                    display_name: "batch-test".into(),
                    path: "auth/userpass/login/test".into(),
                    bound_cidrs: Vec::new(),
                    issued_at: 100,
                    expires_at: 200,
                    parent,
                    entity_id: None,
                },
                100,
            )?;
            let owner = LeaseOwner::from_batch(&authority.open(raw.as_str(), "", 100)?);
            let mut serialized = serde_json::to_value(&state.auth)?;
            let service_count = serialized["tokens"].as_object().ok_or("tokens")?.len();
            serialized["batch_authority"] = serde_json::to_value(&authority)?;
            state.auth = serde_json::from_value(serialized)?;
            assert!(state.auth.resolve_lease_owner(&owner, "", 100).is_some());
            assert_eq!(
                serde_json::to_value(&state.auth)?["tokens"]
                    .as_object()
                    .ok_or("tokens")?
                    .len(),
                service_count
            );
            state
                .database
                .mount_mut("", "database/")
                .leases
                .get_mut(&plan.lease.id)
                .ok_or("lease")?
                .owner = owner.clone();
            plan.lease.owner = owner;
            if parent_revoked {
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
            } else {
                plan.started = std::time::Instant::now()
                    .checked_sub(std::time::Duration::from_secs(101))
                    .ok_or("clock")?;
            }
            service.publish_database(state).map_err(|_| "publish")?;
            let response = service.finalize_database_effect(&plan, Ok(()));
            assert_eq!(response.status, 503);
            assert_eq!(response.body["retry_allowed"], false);
            assert!(response.body.get("data").is_none());
            assert!(
                service
                    .state
                    .as_ref()
                    .ok_or("state")?
                    .database
                    .mount("", "database/")
                    .ok_or("mount")?
                    .leases
                    .get(&plan.lease.id)
                    .ok_or("lease")?
                    .phase
                    == Phase::PendingRevoke
            );
        }
        Ok(())
    }
    #[test]
    fn completion_database_batch_parent_shortened_but_live_is_not_a_ttl_cap() -> CompletionResult {
        use crate::auth::{BatchClaims, BatchKeyAuthority};
        for completed_now in [100, 106] {
            let (_root, mut service, _, root_token, mut plan) =
                completion_fixture(Phase::PendingIssue)?;
            let parent = plan
                .lease
                .owner
                .service_digest()
                .ok_or("parent")?
                .to_owned();
            let mut state = service.state.clone().ok_or("state")?;
            let mut serialized = serde_json::to_value(&state.auth)?;
            let accessor = serialized["tokens"][&parent]["accessor"]
                .as_str()
                .ok_or("accessor")?
                .to_owned();
            let mut authority = BatchKeyAuthority::new(100)?;
            let raw = authority.seal(
                BatchClaims {
                    namespace: String::new(),
                    policies: BTreeSet::from(["default".into()]),
                    metadata: BTreeMap::new(),
                    display_name: "batch-test".into(),
                    path: "auth/userpass/login/test".into(),
                    bound_cidrs: Vec::new(),
                    issued_at: 100,
                    expires_at: 200,
                    parent: Some(parent),
                    entity_id: None,
                },
                100,
            )?;
            let owner = LeaseOwner::from_batch(&authority.open(raw.as_str(), "", 100)?);
            serialized["batch_authority"] = serde_json::to_value(&authority)?;
            state.auth = serde_json::from_value(serialized)?;
            state
                .database
                .mount_mut("", "database/")
                .leases
                .get_mut(&plan.lease.id)
                .ok_or("lease")?
                .owner = owner.clone();
            plan.lease.owner = owner;
            service.publish_database(state).map_err(|_| "publish")?;
            // The original parent stays live; only its remaining lifetime changes.
            let renewed = super::super::tests::call(
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
                .resolve_lease_owner(&plan.lease.owner, "", 100)
                .ok_or("live parent")?;
            assert_eq!(resolved.expires_at, Some(200));
            let response =
                service.finalize_database_effect_with_clock(&plan, Ok(()), || completed_now);
            assert_eq!(
                response.status,
                if completed_now == 100 { 200 } else { 503 }
            );
            let lease = service
                .state
                .as_ref()
                .ok_or("state")?
                .database
                .mount("", "database/")
                .ok_or("mount")?
                .leases
                .get(&plan.lease.id)
                .ok_or("lease")?;
            if completed_now == 100 {
                assert!(lease.phase == Phase::Active);
                assert_eq!(response.body["lease_duration"], 100);
                assert!(response.body["data"]["password"].is_string());
            } else {
                assert!(lease.phase == Phase::PendingRevoke);
                assert_eq!(response.body["retry_allowed"], false);
                assert!(response.body.get("data").is_none());
            }
        }
        Ok(())
    }
    #[test]
    fn completion_database_uses_live_identity_in_lease_namespace() -> CompletionResult {
        use crate::auth::{BatchClaims, BatchKeyAuthority};
        for same_namespace in [false, true] {
            let (_root, mut service, _, _, mut plan) = completion_fixture(Phase::PendingIssue)?;
            let mut state = service.state.clone().ok_or("state")?;
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
            let entity_id = entity.body["data"]["id"]
                .as_str()
                .ok_or("entity id")?
                .to_owned();
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
            let mut authority = BatchKeyAuthority::new(100)?;
            let raw = authority.seal(
                BatchClaims {
                    namespace: String::new(),
                    policies: BTreeSet::from(["default".into()]),
                    metadata: BTreeMap::new(),
                    display_name: "batch-test".into(),
                    path: "auth/userpass/login/test".into(),
                    bound_cidrs: Vec::new(),
                    issued_at: 100,
                    expires_at: 200,
                    parent: None,
                    entity_id: Some(entity_id.clone()),
                },
                100,
            )?;
            let owner = LeaseOwner::from_batch(&authority.open(raw.as_str(), "", 100)?);
            let mut serialized = serde_json::to_value(&state.auth)?;
            serialized["batch_authority"] = serde_json::to_value(&authority)?;
            state.auth = serde_json::from_value(serialized)?;
            state
                .database
                .mount_mut("", "database/")
                .leases
                .get_mut(&plan.lease.id)
                .ok_or("lease")?
                .owner = owner.clone();
            plan.lease.owner = owner;
            service
                .publish_database(state)
                .map_err(|_| "publish admitted batch")?;
            let mut state = service.state.clone().ok_or("state")?;
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
                .publish_database(state)
                .map_err(|_| "publish identity")?;
            // Real durable pending intent and typed batch; provider success is simulated.
            let response = service.finalize_database_effect_with_clock(&plan, Ok(()), || 100);
            if same_namespace {
                assert_eq!(response.status, 503);
                assert_eq!(response.body["retry_allowed"], false);
                assert!(response.body.get("data").is_none());
                assert!(
                    service
                        .state
                        .as_ref()
                        .ok_or("state")?
                        .database
                        .mount("", "database/")
                        .ok_or("mount")?
                        .leases
                        .get(&plan.lease.id)
                        .ok_or("lease")?
                        .phase
                        == Phase::PendingRevoke
                );
            } else {
                assert_eq!(response.status, 200);
                assert!(response.body["data"]["password"].is_string());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "service_database_config_tests.rs"]
mod configuration_completion_tests;
