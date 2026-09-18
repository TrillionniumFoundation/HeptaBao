//! Database effects have a durable intent BEFORE provider entry and a source-
//! bound readback BEFORE completion. A remote error never erases an intent.
//! Provider-side monotonically sequenced tombstones fence delayed old leaders.
use super::*;
use crate::{auth::LeaseIssuer, outbound::Target, postgres_wire::PgSession};
use std::collections::BTreeSet;

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
}
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct DatabaseMount {
    connections: BTreeMap<String, Connection>,
    roles: BTreeMap<String, DatabaseRole>,
    leases: BTreeMap<String, DatabaseLease>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Connection {
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
    owner: String,
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
    outbound: crate::outbound::Outbound,
    ha: Option<Arc<Mutex<HaProcess>>>,
    connection: Connection,
    lease: DatabaseLease,
}

impl DatabaseEffectPlan {
    /// Execute only the remote provider side effect and readback. This value is
    /// fully owned so callers may drop the global Service writer while the
    /// bounded network operation is in flight.
    pub(super) fn execute(&self) -> Result<(), Response> {
        if let Some(ha) = &self.ha {
            ha.lock()
                .map_err(|_| failure("HA provider fence unavailable"))?
                .ensure_linearizable()
                .map_err(|_| failure("HA provider fence unavailable"))?;
        }
        let mut pg = self.connection.session(&self.outbound).map_err(failure)?;
        let seq = self.lease.seq.to_string();
        let expires = self.lease.expires.to_string();
        pg.scalar(
            "SELECT heptabao_provider.apply($1,$2,$3::bigint,$4,$5::bigint,$6,$7,$8)::text",
            &[
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
        .map_err(|_| Response {
            status: 503,
            body: json!({
                "errors":["provider outcome indeterminate; durable intent retained"],
                "lease_id":self.lease.id,
                "reconcile_required":true
            }),
        })?;
        // A separate readback proves the committed provider state rather than
        // treating a function return value as transaction completion.
        let observed = pg
            .scalar(
                "SELECT heptabao_provider.observe($1)::text",
                &[&self.lease.provider_id],
            )
            .map_err(|_| Response {
                status: 503,
                body: json!({
                    "errors":["provider outcome indeterminate; durable intent retained"],
                    "lease_id":self.lease.id,
                    "reconcile_required":true
                }),
            })?;
        let observed = crate::auth::parse_strict_json(observed.as_bytes()).map_err(|_| {
            Response {
                status: 503,
                body: json!({
                    "errors":["provider outcome indeterminate; durable intent retained"],
                    "lease_id":self.lease.id,
                    "reconcile_required":true
                }),
            }
        })?;
        let matched = observed.get("found") == Some(&json!(true))
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
        Ok(())
    }

    fn success_response(&self) -> Result<Response, Response> {
        match self.lease.phase {
            Phase::PendingIssue => {
                let password = self
                    .lease
                    .password
                    .as_ref()
                    .ok_or_else(|| failure("pending database issue lost secret material"))?;
                Ok(Response::ok(json!({
                    "lease_id":self.lease.id,
                    "lease_duration":self.lease.expires.saturating_sub(self.now),
                    "renewable":true,
                    "data":{
                        "username":self.lease.username,
                        "password":password.0
                    }
                })))
            }
            Phase::PendingRenew => Ok(Response::ok(json!({
                "lease_id":self.lease.id,
                "lease_duration":self.lease.expires.saturating_sub(self.now),
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
    pub(super) fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }
    pub(super) fn validate(&self) -> Result<(), Response> {
        if self.mounts.len() > 64 {
            return Err(failure("database namespace capacity exceeded"));
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
                        || Target::parse(&connection.connection_url, "postgresql").is_err()
                    {
                        return Err(failure("invalid persisted provider configuration"));
                    }
                }
                for (role_name, role) in &state.roles {
                    if !name(role_name)
                        || !name(&role.provider_role)
                        || !state.connections.contains_key(&role.db_name)
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
                        || base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(&l.owner)
                            .map_or(true, |v| v.len() != 32)
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
                        || l.username.len() != 36
                        || !l.username.starts_with("hbp_")
                        || !l.username[4..].bytes().all(|b| b.is_ascii_hexdigit())
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
}
impl Connection {
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
            if id.is_some_and(|id| state.database.locate(ns, id).is_some()) {
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
        principal: Option<&Principal>,
        request: &RequestView<'_>,
    ) -> Response {
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
            let p = principal.ok_or_else(|| Response::error(403, "missing client token"))?;
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
                let (kind, key) = relative
                    .split_once('/')
                    .ok_or_else(|| invalid("database resource path required"))?;
                if !name(key) {
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
                        if text(body, "plugin_name")? != "postgresql-database-plugin"
                            || body
                                .get("verify_connection")
                                .is_some_and(|v| v != &Value::Bool(true))
                        {
                            return Err(invalid(
                                "only verified PostgreSQL provider configuration is supported",
                            ));
                        }
                        let url = text(body, "connection_url")?.to_owned();
                        let target = Target::parse(&url, "postgresql").map_err(invalid)?;
                        if !name(target.path.trim_start_matches('/')) {
                            return Err(invalid("single explicit PostgreSQL database required"));
                        }
                        let username = text(body, "username")?.to_owned();
                        if !name(&username) {
                            return Err(invalid("invalid database manager name"));
                        }
                        let password = text(body, "password")?.to_owned();
                        if password.len() > 512 || !password.is_ascii() {
                            return Err(invalid(
                                "bounded ASCII PostgreSQL manager password required",
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
                            connection_url: url,
                            username,
                            password: PrivateString(password),
                            allowed_roles,
                        };
                        let mut pg = connection.session(&self.outbound).map_err(failure)?;
                        let response = pg
                            .scalar("SELECT current_user::text", &[])
                            .map_err(failure)?;
                        if response != connection.username {
                            return Err(failure("PostgreSQL manager identity mismatch"));
                        }
                        if pg
                            .scalar("SELECT heptabao_provider.protocol()", &[])
                            .map_err(failure)?
                            != "heptabao-postgresql-provider-v1"
                        {
                            return Err(failure(
                                "PostgreSQL provider contract is not installed or mismatched",
                            ));
                        }
                        let m = state.database.mount_mut(ns, &mount);
                        if m.connections.len() >= 16 && !m.connections.contains_key(key) {
                            return Err(Response::error(
                                507,
                                "database connection capacity exhausted",
                            ));
                        }
                        m.connections.insert(key.into(), connection);
                        self.publish_database(state)?;
                        Ok(Response {
                            status: 204,
                            body: Value::Null,
                        })
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
                            json!({"data":{"plugin_name":"postgresql-database-plugin","connection_url":c.connection_url,"username":c.username,"allowed_roles":c.allowed_roles,"verify_connection":true}}),
                        ))
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
                    ("creds", "GET") => {
                        fields(body, &[])?;
                        let owner = state
                            .auth
                            .lease_issuer(p, ns, now)
                            .map_err(|e| Response::error(e.status, &e.message))?;
                        let m = state.database.mount_mut(ns, &mount);
                        let role = m
                            .roles
                            .get(key)
                            .cloned()
                            .ok_or_else(|| Response::error(404, "database role not found"))?;
                        if m.leases.len() >= 128 {
                            return Err(Response::error(
                                507,
                                "database lease ledger capacity exhausted; no tombstone eviction",
                            ));
                        }
                        if !m
                            .connections
                            .get(&role.db_name)
                            .is_some_and(|c| c.allowed_roles.contains(key))
                        {
                            return Err(Response::error(403, "database role is no longer allowed"));
                        }
                        let entropy = hex(&crypto::random::<16>().map_err(failure)?);
                        let username = format!("hbp_{entropy}");
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
                        let mut lease = DatabaseLease {
                            id: id.clone(),
                            provider_id,
                            username: username.clone(),
                            db_name: role.db_name,
                            provider_role: role.provider_role,
                            owner: owner.digest,
                            issued: now,
                            expires,
                            max_expires,
                            last_renewal: None,
                            seq: 1,
                            phase: Phase::PendingIssue,
                            password: Some(PrivateString(password.clone())),
                            request_digest: String::new(),
                        };
                        lease.request_digest = digest_lease(&lease)?;
                        m.leases.insert(id.clone(), lease);
                        let secret = PrivateString(password);
                        self.publish_database(state)?;
                        self.execute_database_effect(ns, &mount, &id, now)?;
                        Ok(Response::ok(
                            json!({"lease_id":id,"lease_duration":expires-now,"renewable":true,"data":{"username":username,"password":secret.0}}),
                        ))
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
        execute.unwrap_or_else(|e| e)
    }
    fn publish_database(&mut self, mut state: State) -> Result<(), Response> {
        state.schema = CURRENT_STATE_SCHEMA;
        state.validate_format()?;
        self.commit_state(&state)?;
        self.state = Some(state);
        Ok(())
    }
    fn execute_database_effect(
        &mut self,
        ns: &str,
        mount: &str,
        id: &str,
        now: u64,
    ) -> Result<(), Response> {
        // Final current-fence check immediately before adapter entry. PostgreSQL
        // also enforces the persisted per-lease sequence against delayed peers.
        if let Some(ha) = &self.ha {
            ha.lock()
                .map_err(|_| failure("HA provider fence unavailable"))?
                .ensure_linearizable()
                .map_err(|_| failure("HA provider fence unavailable"))?;
        }
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| failure("server sealed"))?;
        let m = state
            .database
            .mount(ns, mount)
            .ok_or_else(|| failure("database mount disappeared"))?;
        let lease = m
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
        let connection = m
            .connections
            .get(&lease.db_name)
            .cloned()
            .ok_or_else(|| failure("provider configuration disappeared"))?;
        let result = (|| -> Result<Value, &'static str> {
            let mut pg = connection.session(&self.outbound)?;
            let seq = lease.seq.to_string();
            let expires = lease.expires.to_string();
            pg.scalar(
                "SELECT heptabao_provider.apply($1,$2,$3::bigint,$4,$5::bigint,$6,$7,$8)::text",
                &[
                    &lease.provider_id,
                    &lease.username,
                    &seq,
                    action(&lease),
                    &expires,
                    &lease.provider_role,
                    lease.password.as_ref().map(|p| p.0.as_str()).unwrap_or(""),
                    &lease.request_digest,
                ],
            )?;
            // Separate post-commit readback; returning a function row alone does
            // not prove transaction commit or that sessions have terminated.
            let observed = pg.scalar(
                "SELECT heptabao_provider.observe($1)::text",
                &[&lease.provider_id],
            )?;
            crate::auth::parse_strict_json(observed.as_bytes())
                .map_err(|_| "invalid provider observation")
        })();
        let observed=result.map_err(|_|Response{status:503,body:json!({"errors":["provider outcome indeterminate; durable intent retained"],"lease_id":id,"reconcile_required":true})})?;
        let matched = observed.get("found") == Some(&json!(true))
            && observed["lease_id"] == lease.provider_id
            && observed["username"] == lease.username
            && observed["seq"].as_u64() == Some(lease.seq)
            && observed["request_digest"] == lease.request_digest
            && observed["action"] == action(&lease)
            && observed["expires"].as_u64() == Some(lease.expires);
        let valid = if lease.phase == Phase::PendingRevoke {
            observed.get("login") == Some(&json!(false))
                && observed["active_sessions"].as_u64() == Some(0)
        } else {
            observed.get("controlled") == Some(&json!(true))
                && observed.get("login") == Some(&json!(true))
                && lease.expires > now
        };
        if !matched || !valid {
            return Err(Response {
                status: 503,
                body: json!({"errors":["provider completion not established; pending intent retained"],"lease_id":id,"reconcile_required":true}),
            });
        }
        let mut next = self.state.clone().ok_or_else(|| failure("server sealed"))?;
        let current = next
            .database
            .mount_mut(ns, mount)
            .leases
            .get_mut(id)
            .ok_or_else(|| failure("lease disappeared"))?;
        if current.seq != lease.seq || current.request_digest != lease.request_digest {
            return Err(failure("lease fence changed"));
        }
        current.password = None;
        current.phase = if lease.phase == Phase::PendingRevoke {
            Phase::Revoked
        } else {
            Phase::Active
        };
        if lease.phase == Phase::PendingRenew {
            current.last_renewal = Some(now);
        }
        self.publish_database(next)
            .map_err(|error| post_provider_publication_failure(error, id))
    }
    fn stage_revoke(state: &mut State, ns: &str, mount: &str, id: &str) -> Result<(), Response> {
        let l = state
            .database
            .mount_mut(ns, mount)
            .leases
            .get_mut(id)
            .ok_or_else(|| invalid("lease not found"))?;
        if matches!(l.phase, Phase::PendingRevoke | Phase::Revoked) {
            return Ok(());
        }
        l.seq = l
            .seq
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or_else(|| failure("provider fence exhausted"))?;
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
        if path.starts_with("sys/leases/revoke-prefix/") {
            return Err(Response::error(
                501,
                "database prefix revocation requires bounded batch receipts; no local-only acknowledgement",
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
        let mount = state
            .database
            .locate(ns, id)
            .ok_or_else(|| invalid("lease not found"))?;
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
                    .lease_issuer_by_digest(&l.owner, ns, now)
                    .is_some_and(|owner| Self::database_owner_active(&state, &owner, ns));
            return Ok(Response::ok(
                json!({"data":{"id":l.id,"ttl":l.expires.saturating_sub(now),"renewable":renewable,"issue_time":l.issued,"expire_time":l.expires,"last_renewal":l.last_renewal,"phase":l.phase}}),
            ));
        }
        if operation == "renew" {
            let owner = state
                .auth
                .lease_issuer_by_digest(&l.owner, ns, now)
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
            let current = state
                .database
                .mount_mut(ns, &mount)
                .leases
                .get_mut(id)
                .ok_or_else(|| invalid("lease not found"))?;
            current.seq = current
                .seq
                .checked_add(1)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or_else(|| failure("lease sequence exhausted"))?;
            current.expires = expiry;
            current.phase = Phase::PendingRenew;
            current.request_digest = digest_lease(current)?;
            self.publish_database(state)?;
            self.execute_database_effect(ns, &mount, id, now)?;
            return Ok(Response::ok(
                json!({"lease_id":id,"lease_duration":expiry-now,"renewable":true}),
            ));
        }
        if l.phase == Phase::Revoked {
            return Ok(Response {
                status: 204,
                body: Value::Null,
            });
        }
        Self::stage_revoke(&mut state, ns, &mount, id)?;
        self.publish_database(state)?;
        self.execute_database_effect(ns, &mount, id, now)?;
        Ok(Response {
            status: 204,
            body: Value::Null,
        })
    }
    fn database_owner_active(state: &State, owner: &LeaseIssuer, ns: &str) -> bool {
        owner.entity_id.as_deref().is_none_or(|id| {
            state
                .engines
                .identity_projection(ns, id)
                .is_ok_and(|p| !p.disabled)
        })
    }
    /// A tick attempts at most one provider operation; it never drops a pending
    /// record, retries issuance, or labels a failed revoke as completed.
    pub(super) fn maintain_database(&mut self, now: u64) -> Result<bool, &'static str> {
        if self.state.is_none() || self.recovery_required || self.audit_failed {
            return Ok(false);
        }
        if let Some(ha) = &self.ha {
            let ha = ha.lock().map_err(|_| "provider HA lock unavailable")?;
            if !ha.is_leader().map_err(|_| "provider leader unavailable")? {
                return Ok(false);
            }
            drop(ha);
            self.sync_from_ha()
                .map_err(|_| "provider ReadIndex unavailable")?;
        }
        let mut state = self.state.clone().ok_or("sealed")?;
        let now = now.max(state.database.clock);
        let mut candidates = Vec::new();
        for (ns, mounts) in &state.database.mounts {
            for (mount, m) in mounts {
                for (id, l) in &m.leases {
                    let owner = state.auth.lease_issuer_by_digest(&l.owner, ns, now);
                    let live = owner
                        .as_ref()
                        .is_some_and(|o| Self::database_owner_active(&state, o, ns));
                    if !matches!(l.phase, Phase::Revoked | Phase::Quarantined)
                        && (l.phase != Phase::Active || l.expires <= now || !live)
                    {
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
            return Ok(false);
        };
        let fingerprint = self.request_fingerprint("INTERNAL", "database/reconcile", &ns, "");
        self.audit_event("provider-request", &fingerprint, now, None)
            .map_err(|_| "provider audit unavailable")?;
        state.database.clock = now;
        Self::stage_revoke(&mut state, &ns, &mount, &id)
            .map_err(|_| "cannot stage provider revoke")?;
        self.publish_database(state)
            .map_err(|_| "provider intent not committed")?;
        let result = self.execute_database_effect(&ns, &mount, &id, now);
        if self
            .audit_event(
                "provider-response",
                &fingerprint,
                now,
                Some(if result.is_ok() { 204 } else { 503 }),
            )
            .is_err()
        {
            self.recovery_required = true;
            return Err("provider result audit unavailable");
        }
        result.map_err(|_| "provider remains indeterminate")?;
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

    fn sample() -> Result<(DatabaseState, String), Response> {
        let id = "database/creds/reader/001122".to_owned();
        let mut state = DatabaseState::default();
        let m = state.mount_mut("", "database/");
        m.connections.insert(
            "local".into(),
            Connection {
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
            owner: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]),
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
    fn provider_wire_and_ttl_bounds_do_not_accept_silent_fallbacks() {
        assert!(ttl(&json!({"ttl":"18446744073709551615h"}), "ttl", 1).is_err());
        assert!(ttl(&json!({"ttl":false}), "ttl", 1).is_err());
        assert!(!name("bad; DROP ROLE manager"));
        assert!(fields(&json!({"creation_statements":[]}), &["provider_role"]).is_err());
    }
}
