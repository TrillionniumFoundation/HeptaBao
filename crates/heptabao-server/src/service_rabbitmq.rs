//! RabbitMQ secret-engine state and external effects.
//!
//! RabbitMQ is intentionally not a database provider.  The engine owns its
//! own encrypted connection/role/lease owner, while the Service remains the
//! sole durable writer.  The provider boundary is the pinned RabbitMQ
//! management API: every mutating request is fenced by the lease digest and
//! followed by provider readback.
use super::*;
use crate::auth::{LeaseOwner, ServiceOwnerProfile};
use crate::outbound::{Outbound, Target};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Weak;
use zeroize::Zeroize;

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct RabbitmqState {
    mounts: BTreeMap<String, BTreeMap<String, RabbitmqMount>>,
    clock: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    provider_fence: u64,
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RabbitmqMount {
    connection: Option<RabbitmqConnection>,
    roles: BTreeMap<String, RabbitmqRole>,
    leases: BTreeMap<String, RabbitmqLease>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RabbitmqConnection {
    connection_url: String,
    username: String,
    password: RabbitmqSecret,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RabbitmqRole {
    vhosts: BTreeMap<String, RabbitmqPermissions>,
    tags: String,
    default_ttl: u64,
    max_ttl: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RabbitmqPermissions {
    configure: String,
    write: String,
    read: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
enum RabbitmqPhase {
    PendingIssue,
    Active,
    PendingRevoke,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RabbitmqLease {
    id: String,
    provider_id: String,
    username: String,
    role: String,
    vhosts: BTreeMap<String, RabbitmqPermissions>,
    issued: u64,
    expires: u64,
    max_expires: u64,
    last_renewal: Option<u64>,
    owner: LeaseOwner,
    seq: u64,
    phase: RabbitmqPhase,
    password: Option<RabbitmqSecret>,
    request_digest: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct RabbitmqSecret(String);
impl Drop for RabbitmqSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(super) struct RabbitmqEffectPlan {
    namespace: String,
    mount: String,
    now: u64,
    started: std::time::Instant,
    outbound: Outbound,
    ha: Option<Arc<Mutex<HaProcess>>>,
    connection: RabbitmqConnection,
    lease: RabbitmqLease,
    _in_flight: Arc<()>,
}

#[derive(Default)]
pub(super) struct RabbitmqFlights {
    leases: BTreeMap<(String, String, String), Weak<()>>,
}
impl RabbitmqFlights {
    fn prune(&mut self) {
        self.leases.retain(|_, value| value.strong_count() != 0);
    }
    fn track(&mut self, ns: &str, mount: &str, id: &str) -> Arc<()> {
        self.prune();
        let key = (ns.to_owned(), mount.to_owned(), id.to_owned());
        if let Some(existing) = self.leases.get(&key).and_then(Weak::upgrade) {
            return existing;
        }
        let value = Arc::new(());
        self.leases.insert(key, Arc::downgrade(&value));
        value
    }
    fn contains(&self, ns: &str, mount: &str, id: &str) -> bool {
        self.leases
            .get(&(ns.to_owned(), mount.to_owned(), id.to_owned()))
            .is_some_and(|value| value.strong_count() != 0)
    }
}

pub(super) struct RabbitmqMaintenance {
    fingerprint: String,
    now: u64,
    pub(super) plan: RabbitmqEffectPlan,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}
fn invalid(message: &str) -> Response {
    Response::error(400, message)
}
fn failure(message: &str) -> Response {
    Response::error(503, message)
}
fn fields(body: &Value, allowed: &[&str]) -> Result<(), Response> {
    let object = body.as_object().ok_or_else(|| invalid("object required"))?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid("unsupported RabbitMQ field"));
    }
    Ok(())
}
fn bounded_text<'a>(body: &'a Value, key: &str, max: usize) -> Result<&'a str, Response> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= max
                && value.bytes().all(|byte| byte >= 0x20 && byte != 0x7f)
        })
        .ok_or_else(|| invalid("missing or invalid RabbitMQ string"))
}
fn object_text<'a>(
    body: &'a serde_json::Map<String, Value>,
    key: &str,
    max: usize,
) -> Result<&'a str, Response> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= max
                && value.bytes().all(|byte| byte >= 0x20 && byte != 0x7f)
        })
        .ok_or_else(|| invalid("missing or invalid RabbitMQ permission"))
}
fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}
fn ttl(body: &Value, key: &str, default: u64) -> Result<u64, Response> {
    let value = match body.get(key) {
        None => default,
        Some(Value::Number(value)) => value.as_u64().ok_or_else(|| invalid("invalid TTL"))?,
        Some(Value::String(value)) => value
            .strip_suffix('s')
            .unwrap_or(value)
            .parse::<u64>()
            .map_err(|_| invalid("invalid TTL"))?,
        _ => return Err(invalid("invalid TTL")),
    };
    if !(1..=86400).contains(&value) {
        return Err(invalid("TTL must be 1..86400 seconds"));
    }
    Ok(value)
}
fn rabbitmq_username(value: &str) -> bool {
    value.starts_with("hbr_")
        && value.len() == 32
        && value[4..].bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn valid_vhost(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| byte >= 0x20 && byte != 0x7f)
}
fn valid_pattern(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.bytes().all(|byte| byte >= 0x20 && byte != 0x7f)
}
fn valid_tags(value: &str) -> bool {
    value.len() <= 256 && value.bytes().all(|byte| byte >= 0x20 && byte != 0x7f)
}
fn percent_component(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            result.push(byte as char);
        } else {
            result.push('%');
            result.push_str(&format!("{byte:02X}"));
        }
    }
    result
}
fn provider_identity(cluster: &str, ns: &str, id: &str) -> Result<String, Response> {
    let bytes = serde_json::to_vec(&("heptabao.rabbitmq.lease.v1", cluster, ns, id))
        .map_err(|_| failure("RabbitMQ provider identity failed"))?;
    Ok(format!("hbr1:{}", hex(&crypto::digest(&bytes))))
}
fn digest_lease(lease: &RabbitmqLease) -> Result<String, Response> {
    let bytes = serde_json::to_vec(&(
        lease.id.as_str(),
        lease.provider_id.as_str(),
        lease.username.as_str(),
        lease.role.as_str(),
        &lease.vhosts,
        lease.seq,
        lease.expires,
        lease
            .password
            .as_ref()
            .map(|value| value.0.as_str())
            .unwrap_or(""),
    ))
    .map_err(|_| failure("RabbitMQ lease serialization failed"))?;
    Ok(hex(&crypto::digest(&bytes)))
}
impl RabbitmqState {
    pub(super) fn is_empty(&self) -> bool {
        self.mounts.is_empty() && self.provider_fence == 0
    }
    pub(super) fn all_lease_owners(&self) -> BTreeSet<(String, LeaseOwner)> {
        self.mounts
            .iter()
            .flat_map(|(ns, mounts)| {
                mounts.values().flat_map(move |mount| {
                    mount
                        .leases
                        .values()
                        .map(move |lease| (ns.clone(), lease.owner.clone()))
                })
            })
            .collect()
    }
    fn mount(&self, ns: &str, mount: &str) -> Option<&RabbitmqMount> {
        self.mounts.get(ns)?.get(mount)
    }
    fn mount_mut(&mut self, ns: &str, mount: &str) -> &mut RabbitmqMount {
        self.mounts
            .entry(ns.into())
            .or_default()
            .entry(mount.into())
            .or_default()
    }
    fn locate(&self, ns: &str, id: &str) -> Option<String> {
        self.mounts
            .get(ns)?
            .iter()
            .find_map(|(mount, state)| state.leases.contains_key(id).then(|| mount.clone()))
    }
    fn next_fence(&mut self) -> Result<u64, Response> {
        let max_lease = self
            .mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .flat_map(|mount| mount.leases.values())
            .map(|lease| lease.seq)
            .max()
            .unwrap_or(0);
        let next = self
            .provider_fence
            .max(max_lease)
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or_else(|| failure("RabbitMQ provider fence exhausted"))?;
        self.provider_fence = next;
        Ok(next)
    }
    pub(super) fn validate_scope(&self, cluster: &str) -> Result<(), Response> {
        if self.mounts.len() > 64 || self.provider_fence > i64::MAX as u64 {
            return Err(failure("invalid RabbitMQ state capacity"));
        }
        for (ns, mounts) in &self.mounts {
            if !valid_namespace(ns) || mounts.len() > 64 {
                return Err(failure("invalid RabbitMQ namespace state"));
            }
            for (mount, state) in mounts {
                if !valid_path(mount.trim_end_matches('/'))
                    || !mount.ends_with('/')
                    || state.roles.len() > 64
                    || state.leases.len() > 128
                {
                    return Err(failure("invalid RabbitMQ mount state"));
                }
                if let Some(connection) = &state.connection
                    && (Target::parse(&connection.connection_url, "rabbitmq").is_err()
                        || !name(&connection.username)
                        || connection.password.0.is_empty()
                        || connection.password.0.len() > 512)
                {
                    return Err(failure("invalid RabbitMQ connection state"));
                }
                for (role_name, role) in &state.roles {
                    if !name(role_name)
                        || role.vhosts.is_empty()
                        || role.vhosts.len() > 32
                        || !valid_tags(&role.tags)
                        || role.default_ttl == 0
                        || role.default_ttl > role.max_ttl
                        || role.max_ttl > 86400
                    {
                        return Err(failure("invalid RabbitMQ role state"));
                    }
                    for (vhost, permissions) in &role.vhosts {
                        if !valid_vhost(vhost)
                            || !valid_pattern(&permissions.configure)
                            || !valid_pattern(&permissions.write)
                            || !valid_pattern(&permissions.read)
                        {
                            return Err(failure("invalid RabbitMQ permission state"));
                        }
                    }
                }
                for (id, lease) in &state.leases {
                    if id != &lease.id
                        || !id.starts_with(&format!("{mount}creds/"))
                        || id.len() > 512
                        || lease.provider_id.len() != 69
                        || !lease.provider_id.starts_with("hbr1:")
                        || !lease.provider_id[5..]
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit())
                        || !rabbitmq_username(&lease.username)
                        || !name(&lease.role)
                        || lease.vhosts.is_empty()
                        || lease
                            .owner
                            .validate_scope(ns, ServiceOwnerProfile::CanonicalDigest)
                            .is_err()
                        || lease.seq == 0
                        || lease.seq > i64::MAX as u64
                        || lease.max_expires <= lease.issued
                        || lease.max_expires.saturating_sub(lease.issued) > 86400
                        || lease.expires > lease.max_expires
                        || lease.request_digest.len() != 64
                        || !lease
                            .request_digest
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit())
                        || lease.password.as_ref().is_some_and(|secret| {
                            secret.0.len() != 64
                                || !secret.0.bytes().all(|byte| byte.is_ascii_hexdigit())
                        })
                        || matches!(lease.phase, RabbitmqPhase::PendingRevoke) && lease.expires != 0
                        || !matches!(lease.phase, RabbitmqPhase::PendingIssue)
                            && lease.password.is_some()
                        || lease.phase == RabbitmqPhase::PendingIssue && lease.password.is_none()
                        || provider_identity(cluster, ns, id)? != lease.provider_id
                    {
                        return Err(failure("invalid RabbitMQ lease state"));
                    }
                    if !matches!(lease.phase, RabbitmqPhase::Active)
                        && digest_lease(lease)? != lease.request_digest
                    {
                        return Err(failure("RabbitMQ intent digest mismatch"));
                    }
                }
            }
        }
        Ok(())
    }
}

impl RabbitmqEffectPlan {
    fn completed_now(&self) -> u64 {
        self.now.saturating_add(self.started.elapsed().as_secs())
    }
    pub(super) fn execute(&self) -> Result<(), Response> {
        if let Some(ha) = &self.ha {
            ha.lock_for_request()
                .map_err(|_| failure("RabbitMQ provider fence unavailable"))?
                .ensure_linearizable()
                .map_err(|_| failure("RabbitMQ provider fence unavailable"))?;
        }
        let error = || Response {
            status: 503,
            body: json!({"errors":["RabbitMQ provider outcome indeterminate; durable intent retained"],"lease_id":self.lease.id,"reconcile_required":true}),
        };
        match self.lease.phase {
            RabbitmqPhase::PendingIssue => {
                let password = self.lease.password.as_ref().ok_or_else(error)?;
                let (status, _) = self.request(
                    "PUT",
                    &format!("/api/users/{}", percent_component(&self.lease.username)),
                    Some(&json!({"password":password.0,"tags":""})),
                )?;
                if !matches!(status, 201 | 204) {
                    return Err(error());
                }
                for (vhost, permissions) in &self.lease.vhosts {
                    let path = format!(
                        "/api/permissions/{}/{}",
                        percent_component(vhost),
                        percent_component(&self.lease.username)
                    );
                    let (status, _) = self.request("PUT", &path, Some(&json!({"configure":permissions.configure,"write":permissions.write,"read":permissions.read})))?;
                    if !matches!(status, 201 | 204) {
                        return Err(error());
                    }
                }
                let (status, observed) = self.request(
                    "GET",
                    &format!("/api/users/{}", percent_component(&self.lease.username)),
                    None,
                )?;
                if status != 200 || observed.get("name") != Some(&json!(self.lease.username)) {
                    return Err(error());
                }
                for (vhost, permissions) in &self.lease.vhosts {
                    let path = format!(
                        "/api/permissions/{}/{}",
                        percent_component(vhost),
                        percent_component(&self.lease.username)
                    );
                    let (status, observed) = self.request("GET", &path, None)?;
                    if status != 200
                        || observed.get("configure") != Some(&json!(permissions.configure))
                        || observed.get("write") != Some(&json!(permissions.write))
                        || observed.get("read") != Some(&json!(permissions.read))
                    {
                        return Err(error());
                    }
                }
                Ok(())
            }
            RabbitmqPhase::PendingRevoke => {
                // RabbitMQ normally closes a user's sessions when the user is
                // deleted, but make the existing-connection boundary explicit
                // when the management API exposes a connection name.
                let (connections_status, connections) =
                    self.request("GET", "/api/connections", None)?;
                if connections_status == 200 {
                    let Some(connections) = connections.as_array() else {
                        return Err(error());
                    };
                    if connections.len() > 256 {
                        return Err(error());
                    }
                    for connection in connections {
                        if connection.get("user") == Some(&json!(self.lease.username)) {
                            let Some(name) = connection.get("name").and_then(Value::as_str) else {
                                return Err(error());
                            };
                            let (status, _) = self.request(
                                "DELETE",
                                &format!("/api/connections/{}", percent_component(name)),
                                None,
                            )?;
                            if !matches!(status, 204 | 404) {
                                return Err(error());
                            }
                        }
                    }
                } else if connections_status != 404 {
                    return Err(error());
                }
                let (status, _) = self.request(
                    "DELETE",
                    &format!("/api/users/{}", percent_component(&self.lease.username)),
                    None,
                )?;
                if !matches!(status, 204 | 404) {
                    return Err(error());
                }
                let (status, _) = self.request(
                    "GET",
                    &format!("/api/users/{}", percent_component(&self.lease.username)),
                    None,
                )?;
                if status != 404 {
                    return Err(error());
                }
                Ok(())
            }
            RabbitmqPhase::Active => Err(failure("RabbitMQ effect is not pending")),
        }
    }
    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(u16, Value), Response> {
        self.outbound
            .rabbitmq_json(path_url(&self.connection.connection_url, path).as_str(), method, path, &self.connection.username, &self.connection.password.0, body)
            .map_err(|_| Response { status: 503, body: json!({"errors":["RabbitMQ provider unavailable; durable intent retained"],"lease_id":self.lease.id,"reconcile_required":true}) })
    }
}

fn path_url(url: &str, _path: &str) -> String {
    url.to_owned()
}

impl Service {
    pub(super) fn rabbitmq_handles(
        &self,
        state: &State,
        ns: &str,
        path: &str,
        body: &Value,
    ) -> bool {
        if state.engines.rabbitmq_mount(ns, path).is_some() {
            return true;
        }
        if path.starts_with("sys/leases/") {
            let id = body
                .get("lease_id")
                .and_then(Value::as_str)
                .or_else(|| path.strip_prefix("sys/leases/revoke/"))
                .or_else(|| path.strip_prefix("sys/leases/reconcile/"));
            if id.is_some_and(|id| state.rabbitmq.locate(ns, id).is_some()) {
                return true;
            }
        }
        false
    }

    pub(super) fn rabbitmq_route(
        &mut self,
        state: State,
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
        let now = (*now).max(state.rabbitmq.clock);
        let result = (|| -> Result<Response, Response> {
            let principal =
                principal.ok_or_else(|| Response::error(403, "missing client token"))?;
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
                    .authorize_sudo_request(principal, ns, path, capability, now)
            } else {
                state
                    .auth
                    .authorize_request(principal, ns, path, capability, now)
            }
            .map_err(|e| Response::error(e.status, &e.message))?;
            if wrap_ttl_seconds.is_some() {
                return Err(Response::error(
                    501,
                    "RabbitMQ response wrapping is not supported for an external effect",
                ));
            }
            let mount = state.engines.rabbitmq_mount(ns, path).map(str::to_owned);
            if let Some(mount) = mount {
                let relative = &path[mount.len()..];
                match relative {
                    "config/connection" => {
                        return self.rabbitmq_config(state, ns, &mount, method, body, now);
                    }
                    "roles" => {
                        return self.rabbitmq_role(state, ns, &mount, "", method, body, now);
                    }
                    value if let Some(role_name) = value.strip_prefix("roles/") => {
                        return self.rabbitmq_role(state, ns, &mount, role_name, method, body, now);
                    }
                    value if let Some(role_name) = value.strip_prefix("creds/") => {
                        if body.as_object().is_some_and(|object| !object.is_empty()) {
                            return Err(invalid("credential issuance accepts no fields"));
                        }
                        return self
                            .rabbitmq_issue(state, ns, &mount, role_name, method, principal, now);
                    }
                    _ => return Err(Response::error(404, "unsupported RabbitMQ path")),
                }
            }
            self.rabbitmq_admin(state, principal, request, now)
        })();
        if let Some(plan) = &mut self.pending_rabbitmq_effect {
            plan.started = std::time::Instant::now();
        }
        result.unwrap_or_else(|error| error)
    }

    fn rabbitmq_config(
        &mut self,
        mut state: State,
        ns: &str,
        mount: &str,
        method: &str,
        body: &Value,
        _now: u64,
    ) -> Result<Response, Response> {
        fields(
            body,
            &[
                "connection_uri",
                "username",
                "password",
                "verify_connection",
            ],
        )?;
        let mount_state = state
            .rabbitmq
            .mount(ns, mount)
            .ok_or_else(|| invalid("RabbitMQ mount not found"))?;
        match method {
            "GET" => {
                if body.as_object().is_some_and(|object| !object.is_empty()) {
                    return Err(invalid("GET accepts no fields"));
                }
                let connection = mount_state
                    .connection
                    .as_ref()
                    .ok_or_else(|| Response::error(404, "RabbitMQ connection is not configured"))?;
                Ok(Response::ok(
                    json!({"data":{"connection_uri":connection.connection_url,"username":connection.username,"verify_connection":true}}),
                ))
            }
            "DELETE" => {
                if mount_state.connection.is_none() {
                    return Err(Response::error(
                        404,
                        "RabbitMQ connection is not configured",
                    ));
                }
                if !mount_state.leases.is_empty() || !mount_state.roles.is_empty() {
                    return Err(Response::error(
                        409,
                        "RabbitMQ connection is still referenced",
                    ));
                }
                state.rabbitmq.mount_mut(ns, mount).connection = None;
                self.publish_rabbitmq(state)?;
                Ok(Response {
                    status: 204,
                    body: Value::Null,
                })
            }
            "POST" | "PUT" => {
                if body.get("verify_connection") != Some(&Value::Bool(true)) {
                    return Err(invalid("provider configuration verification is required"));
                }
                let url = bounded_text(body, "connection_uri", 2048)?.to_owned();
                if Target::parse(&url, "rabbitmq").is_err() {
                    return Err(invalid(
                        "connection_uri must be a private enrolled RabbitMQ endpoint",
                    ));
                }
                let username = bounded_text(body, "username", 128)?.to_owned();
                let password = bounded_text(body, "password", 512)?.to_owned();
                if !name(&username) || password.is_empty() {
                    return Err(invalid("invalid RabbitMQ manager credentials"));
                }
                if !mount_state.leases.is_empty() {
                    return Err(Response::error(
                        409,
                        "RabbitMQ connection identity is frozen while leases exist",
                    ));
                }
                self.pending_rabbitmq_config_effect = Some(RabbitmqConfigPlan {
                    namespace: ns.to_owned(),
                    mount: mount.to_owned(),
                    connection: RabbitmqConnection {
                        connection_url: url,
                        username,
                        password: RabbitmqSecret(password),
                    },
                    expected_empty: mount_state.connection.is_none(),
                    outbound: self.outbound.clone(),
                });
                Ok(Response::error(
                    500,
                    "RabbitMQ configuration validation was not dispatched",
                ))
            }
            _ => Err(invalid(
                "RabbitMQ connection requires GET, POST, PUT or DELETE",
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn rabbitmq_role(
        &mut self,
        mut state: State,
        ns: &str,
        mount: &str,
        role_name: &str,
        method: &str,
        body: &Value,
        _now: u64,
    ) -> Result<Response, Response> {
        if !name(role_name) {
            return Err(invalid("invalid RabbitMQ role name"));
        }
        let mount_state = state
            .rabbitmq
            .mount(ns, mount)
            .ok_or_else(|| invalid("RabbitMQ mount not found"))?;
        match method {
            "GET" => {
                if role_name.is_empty() {
                    return Err(invalid("role list path requires LIST"));
                }
                if body.as_object().is_some_and(|object| !object.is_empty()) {
                    return Err(invalid("GET accepts no fields"));
                }
                let role = mount_state
                    .roles
                    .get(role_name)
                    .ok_or_else(|| Response::error(404, "RabbitMQ role not found"))?;
                Ok(Response::ok(json!({"data":role})))
            }
            "LIST" => {
                if !role_name.is_empty() {
                    return Err(invalid("role list path is invalid"));
                }
                let keys = mount_state.roles.keys().cloned().collect::<Vec<_>>();
                Ok(Response::ok(json!({"data":{"keys":keys}})))
            }
            "DELETE" => {
                if body.as_object().is_some_and(|object| !object.is_empty()) {
                    return Err(invalid("DELETE accepts no fields"));
                }
                if mount_state
                    .leases
                    .values()
                    .any(|lease| lease.role == role_name)
                {
                    return Err(Response::error(
                        409,
                        "RabbitMQ role is still referenced by a lease",
                    ));
                }
                if state
                    .rabbitmq
                    .mount_mut(ns, mount)
                    .roles
                    .remove(role_name)
                    .is_none()
                {
                    return Err(Response::error(404, "RabbitMQ role not found"));
                }
                self.publish_rabbitmq(state)?;
                Ok(Response {
                    status: 204,
                    body: Value::Null,
                })
            }
            "POST" | "PUT" => {
                fields(body, &["vhosts", "tags", "default_ttl", "max_ttl"])?;
                let vhosts = body
                    .get("vhosts")
                    .and_then(Value::as_object)
                    .ok_or_else(|| invalid("vhosts object is required"))?;
                if vhosts.is_empty() || vhosts.len() > 32 {
                    return Err(invalid("bounded vhosts object is required"));
                }
                let mut parsed = BTreeMap::new();
                for (vhost, value) in vhosts {
                    if !valid_vhost(vhost) {
                        return Err(invalid("invalid RabbitMQ vhost"));
                    }
                    let value = value
                        .as_object()
                        .ok_or_else(|| invalid("vhost permissions must be objects"))?;
                    if value
                        .keys()
                        .any(|key| !matches!(key.as_str(), "configure" | "write" | "read"))
                    {
                        return Err(invalid("unsupported RabbitMQ permission field"));
                    }
                    let permissions = RabbitmqPermissions {
                        configure: object_text(value, "configure", 512)?.to_owned(),
                        write: object_text(value, "write", 512)?.to_owned(),
                        read: object_text(value, "read", 512)?.to_owned(),
                    };
                    parsed.insert(vhost.clone(), permissions);
                }
                let tags = body
                    .get("tags")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                if !valid_tags(&tags) {
                    return Err(invalid("invalid RabbitMQ tags"));
                }
                if !tags.is_empty() {
                    return Err(invalid(
                        "RabbitMQ role tags are disabled in the scoped runtime",
                    ));
                }
                let default_ttl = ttl(body, "default_ttl", 3600)?;
                let max_ttl = ttl(body, "max_ttl", 86400)?;
                if default_ttl > max_ttl || mount_state.connection.is_none() {
                    return Err(invalid(
                        "RabbitMQ connection must be configured before a role",
                    ));
                }
                state.rabbitmq.mount_mut(ns, mount).roles.insert(
                    role_name.to_owned(),
                    RabbitmqRole {
                        vhosts: parsed,
                        tags,
                        default_ttl,
                        max_ttl,
                    },
                );
                self.publish_rabbitmq(state)?;
                Ok(Response {
                    status: 204,
                    body: Value::Null,
                })
            }
            _ => Err(invalid("unsupported RabbitMQ role method")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn rabbitmq_issue(
        &mut self,
        mut state: State,
        ns: &str,
        mount: &str,
        role_name: &str,
        method: &str,
        principal: &Principal,
        now: u64,
    ) -> Result<Response, Response> {
        if method != "GET" {
            return Err(invalid("RabbitMQ credential issuance requires GET"));
        }
        let owner = state
            .auth
            .typed_lease_issuer(principal, ns, now)
            .map_err(|e| Response::error(e.status, &e.message))?;
        let role = state
            .rabbitmq
            .mount(ns, mount)
            .and_then(|mount| mount.roles.get(role_name))
            .cloned()
            .ok_or_else(|| Response::error(404, "RabbitMQ role not found"))?;
        state
            .rabbitmq
            .mount(ns, mount)
            .and_then(|mount| mount.connection.as_ref())
            .ok_or_else(|| invalid("RabbitMQ connection is not configured"))?;
        let entropy = hex(&crypto::random::<16>().map_err(failure)?);
        let username = format!("hbr_{}", &entropy[..28]);
        let id = format!("{mount}creds/{role_name}/{entropy}");
        let expires = now
            .checked_add(role.default_ttl)
            .ok_or_else(|| invalid("lease time exhausted"))?
            .min(owner.expires_at.unwrap_or(u64::MAX));
        let max_expires = now
            .checked_add(role.max_ttl)
            .ok_or_else(|| invalid("lease time exhausted"))?;
        if expires <= now {
            return Err(Response::error(403, "issuer expired"));
        }
        let mut lease = RabbitmqLease {
            id: id.clone(),
            provider_id: provider_identity(&state.cluster_id, ns, &id)?,
            username,
            role: role_name.to_owned(),
            vhosts: role.vhosts,
            issued: now,
            expires,
            max_expires,
            last_renewal: None,
            owner: owner.owner,
            seq: state.rabbitmq.next_fence()?,
            phase: RabbitmqPhase::PendingIssue,
            password: Some(RabbitmqSecret(hex(
                &crypto::random::<32>().map_err(failure)?
            ))),
            request_digest: String::new(),
        };
        lease.request_digest = digest_lease(&lease)?;
        state
            .rabbitmq
            .mount_mut(ns, mount)
            .leases
            .insert(id.clone(), lease);
        state.rabbitmq.clock = now;
        self.publish_rabbitmq(state)?;
        self.defer_rabbitmq_effect(ns, mount, &id, now)
    }

    fn rabbitmq_admin(
        &mut self,
        mut state: State,
        _principal: &Principal,
        request: &RequestView<'_>,
        now: u64,
    ) -> Result<Response, Response> {
        let RequestView {
            path,
            method,
            body,
            namespace: ns,
            ..
        } = request;
        if !matches!(*method, "POST" | "PUT" | "GET") {
            return Err(invalid("unsupported RabbitMQ lease method"));
        }
        let operation = if *path == "sys/leases/lookup" {
            "lookup"
        } else if *path == "sys/leases/renew" || path.starts_with("sys/leases/renew/") {
            "renew"
        } else if *path == "sys/leases/reconcile" || path.starts_with("sys/leases/reconcile/") {
            "reconcile"
        } else if *path == "sys/leases/revoke" || path.starts_with("sys/leases/revoke/") {
            "revoke"
        } else {
            return Err(Response::error(404, "unsupported lease path"));
        };
        let path_id = path
            .strip_prefix("sys/leases/reconcile/")
            .or_else(|| path.strip_prefix("sys/leases/revoke/"))
            .or_else(|| path.strip_prefix("sys/leases/renew/"));
        let body_id = body.get("lease_id").and_then(Value::as_str);
        if path_id.is_some() && body_id.is_some() && path_id != body_id {
            return Err(invalid("lease_id conflicts with path"));
        }
        let id = path_id
            .or(body_id)
            .ok_or_else(|| invalid("lease_id required"))?;
        let mount = state
            .rabbitmq
            .locate(ns, id)
            .ok_or_else(|| invalid("lease not found"))?;
        let lease = state
            .rabbitmq
            .mount(ns, &mount)
            .and_then(|mount| mount.leases.get(id))
            .cloned()
            .ok_or_else(|| invalid("lease not found"))?;
        if operation == "lookup" {
            return Ok(Response::ok(
                json!({"data":{"id":lease.id,"ttl":lease.expires.saturating_sub(now),"renewable":false,"issue_time":lease.issued,"expire_time":lease.expires,"phase":lease.phase}}),
            ));
        }
        if operation == "renew" {
            return Err(invalid(
                "RabbitMQ user credentials do not support provider renewal",
            ));
        }
        if self.rabbitmq_in_flight.contains(ns, &mount, id) {
            return Err(Response {
                status: 503,
                body: json!({"errors":["RabbitMQ provider effect is already in flight; durable intent retained"],"lease_id":id,"reconcile_required":true}),
            });
        }
        if operation == "revoke" && lease.phase != RabbitmqPhase::PendingRevoke {
            self.stage_rabbitmq_revoke(&mut state, ns, &mount, id)?;
            self.publish_rabbitmq(state)?;
        }
        self.defer_rabbitmq_effect(ns, &mount, id, now)
    }

    fn publish_rabbitmq(&mut self, mut state: State) -> Result<(), Response> {
        state.schema = CURRENT_STATE_SCHEMA;
        state.validate_format()?;
        self.commit_state(&state)?;
        self.state = Some(state);
        Ok(())
    }
    fn rabbitmq_effect_plan(
        &mut self,
        ns: &str,
        mount: &str,
        id: &str,
        now: u64,
    ) -> Result<RabbitmqEffectPlan, Response> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| failure("server sealed"))?;
        let lease = state
            .rabbitmq
            .mount(ns, mount)
            .and_then(|mount| mount.leases.get(id))
            .cloned()
            .ok_or_else(|| failure("RabbitMQ lease disappeared"))?;
        let connection = state
            .rabbitmq
            .mount(ns, mount)
            .and_then(|mount| mount.connection.clone())
            .ok_or_else(|| failure("RabbitMQ connection disappeared"))?;
        if !matches!(
            lease.phase,
            RabbitmqPhase::PendingIssue | RabbitmqPhase::PendingRevoke
        ) {
            return Err(invalid("RabbitMQ effect is not pending"));
        }
        Ok(RabbitmqEffectPlan {
            namespace: ns.to_owned(),
            mount: mount.to_owned(),
            now,
            started: std::time::Instant::now(),
            outbound: self.outbound.clone(),
            ha: self.ha.clone(),
            connection,
            lease,
            _in_flight: self.rabbitmq_in_flight.track(ns, mount, id),
        })
    }
    fn defer_rabbitmq_effect(
        &mut self,
        ns: &str,
        mount: &str,
        id: &str,
        now: u64,
    ) -> Result<Response, Response> {
        self.rabbitmq_in_flight.prune();
        if self.rabbitmq_in_flight.contains(ns, mount, id) {
            return Err(invalid("RabbitMQ provider effect is already in flight"));
        }
        if self.pending_rabbitmq_effect.is_some() {
            return Err(failure(
                "another RabbitMQ provider effect is pending dispatch",
            ));
        }
        self.pending_rabbitmq_effect = Some(self.rabbitmq_effect_plan(ns, mount, id, now)?);
        Ok(Response::error(
            500,
            "RabbitMQ provider effect was not dispatched",
        ))
    }
    fn stage_rabbitmq_revoke(
        &mut self,
        state: &mut State,
        ns: &str,
        mount: &str,
        id: &str,
    ) -> Result<(), Response> {
        let seq = state.rabbitmq.next_fence()?;
        let lease = state
            .rabbitmq
            .mount_mut(ns, mount)
            .leases
            .get_mut(id)
            .ok_or_else(|| invalid("lease not found"))?;
        lease.seq = seq;
        lease.phase = RabbitmqPhase::PendingRevoke;
        lease.expires = 0;
        lease.password = None;
        lease.request_digest = digest_lease(lease)?;
        Ok(())
    }
    pub(super) fn finalize_rabbitmq_effect(
        &mut self,
        plan: &RabbitmqEffectPlan,
        result: Result<(), Response>,
    ) -> Response {
        if let Err(error) = result {
            return error;
        }
        let Some(mut next) = self.state.clone() else {
            return failure("server sealed after RabbitMQ provider entry");
        };
        let Some(current) = next
            .rabbitmq
            .mount(&plan.namespace, &plan.mount)
            .and_then(|mount| mount.leases.get(&plan.lease.id))
            .cloned()
        else {
            return failure("RabbitMQ lease disappeared after provider entry");
        };
        if current.seq != plan.lease.seq
            || current.request_digest != plan.lease.request_digest
            || current.phase != plan.lease.phase
        {
            return failure("RabbitMQ lease fence changed after provider entry");
        }
        let now = plan.completed_now().max(next.rabbitmq.clock);
        next.rabbitmq.clock = now;
        if plan.lease.phase == RabbitmqPhase::PendingIssue
            && !next
                .auth
                .resolve_lease_owner(&plan.lease.owner, &plan.namespace, now)
                .is_some()
        {
            let seq = match next.rabbitmq.next_fence() {
                Ok(value) => value,
                Err(error) => return error,
            };
            let lease = next
                .rabbitmq
                .mount_mut(&plan.namespace, &plan.mount)
                .leases
                .get_mut(&plan.lease.id)
                .ok_or_else(|| failure("RabbitMQ lease disappeared before cleanup"));
            let Ok(lease) = lease else {
                return failure("RabbitMQ lease disappeared before cleanup");
            };
            lease.seq = seq;
            lease.phase = RabbitmqPhase::PendingRevoke;
            lease.expires = 0;
            lease.password = None;
            lease.request_digest = match digest_lease(lease) {
                Ok(value) => value,
                Err(error) => return error,
            };
            if let Err(error) = self.publish_rabbitmq(next) {
                return error;
            }
            return failure(
                "RabbitMQ lease owner expired before secret release; durable revoke retained",
            );
        }
        if plan.lease.phase == RabbitmqPhase::PendingRevoke {
            next.rabbitmq
                .mount_mut(&plan.namespace, &plan.mount)
                .leases
                .remove(&plan.lease.id);
        } else {
            let lease = next
                .rabbitmq
                .mount_mut(&plan.namespace, &plan.mount)
                .leases
                .get_mut(&plan.lease.id)
                .ok_or_else(|| failure("RabbitMQ lease disappeared before publication"));
            let Ok(lease) = lease else {
                return failure("RabbitMQ lease disappeared before publication");
            };
            lease.password = None;
            lease.phase = RabbitmqPhase::Active;
        }
        if let Err(error) = self.publish_rabbitmq(next) {
            return Response {
                status: 503,
                body: json!({"errors":["RabbitMQ provider effect observed but local completion not established; durable intent retained"],"lease_id":plan.lease.id,"reconcile_required":true,"retry_allowed":false,"cause":error.body.get("errors").and_then(Value::as_array).and_then(|v| v.first()).and_then(Value::as_str).unwrap_or("publication failed")}),
            };
        }
        if plan.lease.phase == RabbitmqPhase::PendingIssue && !self.rabbitmq_owner_live(plan, now) {
            return failure(
                "RabbitMQ lease owner expired before secret release; reconciliation required",
            );
        }
        plan.success_response(now)
    }
    fn rabbitmq_owner_live(&self, plan: &RabbitmqEffectPlan, now: u64) -> bool {
        plan.lease.expires > now
            && self
                .state
                .as_ref()
                .and_then(|state| {
                    state
                        .auth
                        .resolve_lease_owner(&plan.lease.owner, &plan.namespace, now)
                })
                .is_some()
    }
    pub(super) fn prepare_rabbitmq_maintenance(
        &mut self,
        now: u64,
    ) -> Result<Option<RabbitmqMaintenance>, &'static str> {
        if self.state.is_none() || self.recovery_required || self.audit_failed {
            return Ok(None);
        }
        self.rabbitmq_in_flight.prune();
        let state = self.state.as_ref().ok_or("sealed")?;
        let mut selected = None;
        for (ns, mounts) in &state.rabbitmq.mounts {
            for (mount, value) in mounts {
                for (id, lease) in &value.leases {
                    let dead = lease.phase == RabbitmqPhase::PendingRevoke
                        || (lease.phase == RabbitmqPhase::Active && lease.expires <= now)
                        || (lease.phase == RabbitmqPhase::PendingIssue && lease.expires <= now);
                    if dead && !self.rabbitmq_in_flight.contains(ns, mount, id) {
                        selected = Some((ns.clone(), mount.clone(), id.clone()));
                        break;
                    }
                }
                if selected.is_some() {
                    break;
                }
            }
            if selected.is_some() {
                break;
            }
        }
        let Some((ns, mount, id)) = selected else {
            return Ok(None);
        };
        let mut next = state.clone();
        if next
            .rabbitmq
            .mount(&ns, &mount)
            .and_then(|mount| mount.leases.get(&id))
            .is_some_and(|lease| lease.phase != RabbitmqPhase::PendingRevoke)
        {
            self.stage_rabbitmq_revoke(&mut next, &ns, &mount, &id)
                .map_err(|_| "cannot stage RabbitMQ revoke")?;
            self.publish_rabbitmq(next)
                .map_err(|_| "RabbitMQ intent not committed")?;
        }
        self.defer_rabbitmq_effect(&ns, &mount, &id, now)
            .map_err(|_| "RabbitMQ plan unavailable")?;
        let plan = self
            .pending_rabbitmq_effect
            .take()
            .ok_or("RabbitMQ plan unavailable")?;
        let fingerprint = self.request_fingerprint("INTERNAL", "rabbitmq/reconcile", &ns, "");
        Ok(Some(RabbitmqMaintenance {
            fingerprint,
            now,
            plan,
        }))
    }
    pub(super) fn finish_rabbitmq_maintenance(
        &mut self,
        pending: RabbitmqMaintenance,
        result: Result<(), Response>,
    ) -> Result<bool, &'static str> {
        let response = self.finalize_rabbitmq_effect(&pending.plan, result);
        let ok = response.status < 300;
        if self
            .audit_event(
                "rabbitmq-provider-response",
                &pending.fingerprint,
                pending.now,
                Some(response.status),
            )
            .is_err()
        {
            self.recovery_required = true;
            return Err("RabbitMQ provider result audit unavailable");
        }
        Ok(ok)
    }
}

pub(super) struct RabbitmqConfigPlan {
    namespace: String,
    mount: String,
    connection: RabbitmqConnection,
    expected_empty: bool,
    outbound: Outbound,
}
impl RabbitmqConfigPlan {
    pub(super) fn execute(&self) -> Result<(), Response> {
        self.outbound
            .rabbitmq_json(
                &self.connection.connection_url,
                "GET",
                "/api/whoami",
                &self.connection.username,
                &self.connection.password.0,
                None,
            )
            .map_err(|_| failure("RabbitMQ configuration provider unavailable"))
            .and_then(|(status, value)| {
                if status == 200 && value.get("name") == Some(&json!(self.connection.username)) {
                    Ok(())
                } else {
                    Err(failure("RabbitMQ manager identity readback mismatch"))
                }
            })
    }
}
impl Service {
    pub(super) fn finalize_rabbitmq_config(
        &mut self,
        plan: RabbitmqConfigPlan,
        result: Result<(), Response>,
    ) -> Response {
        if let Err(error) = result {
            return error;
        }
        let Some(mut state) = self.state.clone() else {
            return failure("server sealed after RabbitMQ configuration validation");
        };
        let mount = state.rabbitmq.mount_mut(&plan.namespace, &plan.mount);
        if mount.connection.is_some() == plan.expected_empty {
            return Response::error(
                409,
                "RabbitMQ mount changed during configuration validation",
            );
        }
        mount.connection = Some(plan.connection);
        match self.publish_rabbitmq(state) {
            Ok(()) => Response {
                status: 204,
                body: Value::Null,
            },
            Err(error) => error,
        }
    }
}

impl RabbitmqEffectPlan {
    fn success_response(&self, now: u64) -> Response {
        match self.lease.phase {
            RabbitmqPhase::PendingIssue => {
                let Some(password) = self.lease.password.as_ref() else {
                    return failure("RabbitMQ pending issue lost secret material");
                };
                Response::ok(
                    json!({"lease_id":self.lease.id,"lease_duration":self.lease.expires.saturating_sub(now),"renewable":false,"data":{"username":self.lease.username,"password":password.0,"vhosts":self.lease.vhosts}}),
                )
            }
            RabbitmqPhase::PendingRevoke => Response {
                status: 204,
                body: Value::Null,
            },
            RabbitmqPhase::Active => failure("RabbitMQ effect is not pending"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_identity_and_management_components_are_canonical() {
        let result = provider_identity("cluster", "", "rabbitmq/creds/app/id");
        assert!(result.is_ok());
        let first = match result {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(first.len(), 69);
        let result = provider_identity("cluster", "team", "rabbitmq/creds/app/id");
        assert!(result.is_ok());
        let second = match result {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_ne!(first, second);
        assert_eq!(percent_component("/guest user"), "%2Fguest%20user");
        assert_eq!(percent_component("hbr_a"), "hbr_a");
    }
}
