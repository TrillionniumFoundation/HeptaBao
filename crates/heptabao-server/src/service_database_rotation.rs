//! PostgreSQL static-role and manager credential rotation.
//!
//! Every remote password mutation has a durable local intent and a provider-side
//! global fence before entry. HTTP authority is process-local and never rebuilt
//! during recovery. The lifecycle owner may only reconcile the original intent.
use super::*;

const MIN_STATIC_ROTATION_SECONDS: u64 = 5;
const MAX_STATIC_ROTATION_SECONDS: u64 = 86_400;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) enum DatabaseStaticPhase {
    PendingRotate,
    PendingDelete,
    Active,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DatabaseStaticRole {
    pub(super) db_name: String,
    pub(super) username: String,
    pub(super) rotation_period: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) current_password: Option<PrivateString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) pending_password: Option<PrivateString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) pending_provider_password: Option<PrivateString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) last_rotation: Option<u64>,
    pub(super) next_rotation: u64,
    pub(super) seq: u64,
    pub(super) phase: DatabaseStaticPhase,
    pub(super) request_digest: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DatabaseRootRotation {
    pub(super) seq: u64,
    pub(super) pending_password: PrivateString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) provider_password: Option<PrivateString>,
    pub(super) request_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DatabaseRotationObservation {
    Applied,
    ReadmitRequired,
}

#[derive(Clone)]
enum DatabaseRotationKind {
    Static {
        role_name: String,
        expected: DatabaseStaticRole,
    },
    Root {
        connection_name: String,
        expected: DatabaseRootRotation,
    },
}

pub(crate) struct DatabaseRotationPlan {
    namespace: String,
    mount: String,
    now: u64,
    started: std::time::Instant,
    outbound: crate::outbound::Outbound,
    ha: Option<Arc<Mutex<HaProcess>>>,
    connection: Connection,
    fence_id: String,
    operation_id: String,
    kind: DatabaseRotationKind,
    response_authority: Option<Box<plugin::PluginResponseAuthority>>,
    _in_flight: Arc<()>,
}

pub(crate) struct DatabaseRotationMaintenance {
    fingerprint: String,
    now: u64,
    pub(super) plan: DatabaseRotationPlan,
}

impl DatabaseRotationMaintenance {
    pub(crate) fn execute(&self) -> Result<DatabaseRotationObservation, Response> {
        self.plan.execute()
    }
}

fn rotation_failure(message: &str, operation_id: &str) -> Response {
    Response {
        status: 503,
        body: json!({
            "errors":[message],
            "operation_id":operation_id,
            "reconcile_required":true,
            "retry_allowed":false
        }),
    }
}

fn rotation_digest(parts: &impl Serialize) -> Result<String, Response> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(parts)
            .map_err(|_| failure("database rotation intent encoding failed"))?,
    );
    Ok(hex(&crypto::digest(&bytes)))
}

fn static_operation_id(
    cluster: &str,
    namespace: &str,
    mount: &str,
    role_name: &str,
) -> Result<String, Response> {
    let bytes = serde_json::to_vec(&(
        "heptabao.database.static.v1",
        cluster,
        namespace,
        mount,
        role_name,
    ))
    .map_err(|_| failure("database static-role identity encoding failed"))?;
    Ok(format!("hbs1:{}", hex(&crypto::digest(&bytes))))
}

fn root_operation_id(
    cluster: &str,
    namespace: &str,
    mount: &str,
    connection: &str,
) -> Result<String, Response> {
    let bytes = serde_json::to_vec(&(
        "heptabao.database.root.v1",
        cluster,
        namespace,
        mount,
        connection,
    ))
    .map_err(|_| failure("database root-rotation identity encoding failed"))?;
    Ok(format!("hbr1:{}", hex(&crypto::digest(&bytes))))
}

fn static_digest(role_name: &str, role: &DatabaseStaticRole) -> Result<String, Response> {
    if let Some(provider_password) = &role.pending_provider_password {
        rotation_digest(&(
            "heptabao.database.static.scram-sha-256.v1",
            role_name,
            role.db_name.as_str(),
            role.username.as_str(),
            role.rotation_period,
            role.seq,
            role.pending_password
                .as_ref()
                .map(|value| value.0.as_str())
                .unwrap_or(""),
            provider_password.0.as_str(),
        ))
    } else {
        // Exact published tuple for password-mode and historical intents.
        rotation_digest(&(
            "rotate-static",
            role_name,
            role.db_name.as_str(),
            role.username.as_str(),
            role.rotation_period,
            role.seq,
            role.pending_password
                .as_ref()
                .map(|value| value.0.as_str())
                .unwrap_or(""),
        ))
    }
}

fn static_retire_digest(role_name: &str, role: &DatabaseStaticRole) -> Result<String, Response> {
    rotation_digest(&(
        "retire-static",
        role_name,
        role.db_name.as_str(),
        role.username.as_str(),
        role.seq,
    ))
}

fn root_digest(connection_name: &str, rotation: &DatabaseRootRotation) -> Result<String, Response> {
    if let Some(provider_password) = &rotation.provider_password {
        rotation_digest(&(
            "heptabao.database.root.scram-sha-256.v1",
            connection_name,
            rotation.seq,
            rotation.pending_password.0.as_str(),
            provider_password.0.as_str(),
        ))
    } else {
        // Exact published tuple for password-mode and historical intents.
        rotation_digest(&(
            "rotate-root",
            connection_name,
            rotation.seq,
            rotation.pending_password.0.as_str(),
        ))
    }
}

fn parse_provider_object(value: &str) -> Result<serde_json::Map<String, Value>, Response> {
    crate::auth::parse_strict_json(value.as_bytes())
        .map_err(|_| failure("PostgreSQL rotation provider returned invalid JSON"))?
        .as_object()
        .cloned()
        .ok_or_else(|| failure("PostgreSQL rotation provider returned a non-object"))
}

fn static_observation_matches(
    value: &str,
    operation_id: &str,
    username: &str,
    seq: u64,
    digest: &str,
) -> bool {
    let Ok(object) = parse_provider_object(value) else {
        return false;
    };
    object.len() == 8
        && object.get("found") == Some(&json!(true))
        && object.get("static_id") == Some(&json!(operation_id))
        && object.get("username") == Some(&json!(username))
        && object.get("seq") == Some(&json!(seq))
        && object.get("request_digest") == Some(&json!(digest))
        && object.get("rotated_at").is_some_and(Value::is_u64)
        && object.get("controlled") == Some(&json!(true))
        && object.get("login") == Some(&json!(true))
}

impl DatabaseRotationPlan {
    fn completed_now(&self) -> u64 {
        std::time::Duration::from_secs(self.now)
            .saturating_add(self.started.elapsed())
            .as_secs()
    }

    pub(crate) fn execute(&self) -> Result<DatabaseRotationObservation, Response> {
        if let Some(ha) = &self.ha {
            ha.lock_for_request()
                .map_err(|_| {
                    rotation_failure("database rotation HA fence unavailable", &self.operation_id)
                })?
                .ensure_linearizable()
                .map_err(|_| {
                    rotation_failure("database rotation HA fence unavailable", &self.operation_id)
                })?;
        }
        if self.connection.provider != DatabaseProvider::Postgresql {
            return Err(Response::error(
                501,
                "bounded static/root rotation currently requires PostgreSQL",
            ));
        }
        match &self.kind {
            DatabaseRotationKind::Static { expected, .. } => match expected.phase {
                DatabaseStaticPhase::PendingRotate => self
                    .execute_static(expected)
                    .map(|()| DatabaseRotationObservation::Applied),
                DatabaseStaticPhase::PendingDelete => self
                    .execute_static_delete(expected)
                    .map(|()| DatabaseRotationObservation::Applied),
                DatabaseStaticPhase::Active => Err(rotation_failure(
                    "database static-role plan is not pending",
                    &self.operation_id,
                )),
            },
            DatabaseRotationKind::Root { expected, .. } => self.execute_root(expected),
        }
    }

    fn execute_static(&self, expected: &DatabaseStaticRole) -> Result<(), Response> {
        let password = expected.pending_password.as_ref().ok_or_else(|| {
            rotation_failure(
                "static-role pending password disappeared",
                &self.operation_id,
            )
        })?;
        let mut pg = self.connection.session(&self.outbound).map_err(|_| {
            rotation_failure(
                "PostgreSQL static-role provider unavailable",
                &self.operation_id,
            )
        })?;
        if pg
            .scalar("SELECT heptabao_provider.static_protocol()", &[])
            .map_err(|_| {
                rotation_failure(
                    "PostgreSQL static-role extension unavailable",
                    &self.operation_id,
                )
            })?
            != "heptabao-postgresql-static-v1"
        {
            return Err(rotation_failure(
                "PostgreSQL static-role extension mismatched",
                &self.operation_id,
            ));
        }
        let provider_password = self
            .connection
            .password_authentication
            .provider_password(&password.0, expected.pending_provider_password.as_ref())?;
        let seq = expected.seq.to_string();
        // This timestamp and provider credential are part of the durable intent.
        // Retries after a lost response send byte-identical semantics.
        let rotated_at = expected.next_rotation.to_string();
        pg.scalar(
            self.connection.static_rotation_function(),
            &[
                &self.fence_id,
                &self.operation_id,
                &expected.username,
                &seq,
                provider_password,
                &expected.request_digest,
                &rotated_at,
            ],
        )
        .map_err(|_| {
            rotation_failure(
                "PostgreSQL static-role outcome indeterminate",
                &self.operation_id,
            )
        })?;
        let observed = pg
            .scalar(
                "SELECT heptabao_provider.observe_static($1)::text",
                &[&self.operation_id],
            )
            .map_err(|_| {
                rotation_failure(
                    "PostgreSQL static-role readback unavailable",
                    &self.operation_id,
                )
            })?;
        if !static_observation_matches(
            &observed,
            &self.operation_id,
            &expected.username,
            expected.seq,
            &expected.request_digest,
        ) {
            return Err(rotation_failure(
                "PostgreSQL static-role readback mismatch",
                &self.operation_id,
            ));
        }
        Ok(())
    }

    fn execute_static_delete(&self, expected: &DatabaseStaticRole) -> Result<(), Response> {
        let mut pg = self.connection.session(&self.outbound).map_err(|_| {
            rotation_failure(
                "PostgreSQL static-role retirement provider unavailable",
                &self.operation_id,
            )
        })?;
        if pg
            .scalar("SELECT heptabao_provider.static_protocol()", &[])
            .map_err(|_| {
                rotation_failure(
                    "PostgreSQL static-role extension unavailable",
                    &self.operation_id,
                )
            })?
            != "heptabao-postgresql-static-v1"
        {
            return Err(rotation_failure(
                "PostgreSQL static-role extension mismatched",
                &self.operation_id,
            ));
        }
        let seq = expected.seq.to_string();
        let retired = pg
            .scalar(
                "SELECT heptabao_provider.retire_static($1,$2,$3,$4::bigint,$5)::text",
                &[
                    &self.fence_id,
                    &self.operation_id,
                    &expected.username,
                    &seq,
                    &expected.request_digest,
                ],
            )
            .map_err(|_| {
                rotation_failure(
                    "PostgreSQL static-role retirement is indeterminate",
                    &self.operation_id,
                )
            })?;
        if retired != "true" {
            return Err(rotation_failure(
                "PostgreSQL static-role retirement was not confirmed",
                &self.operation_id,
            ));
        }
        let observed = pg
            .scalar(
                "SELECT heptabao_provider.static_retired($1,$2,$3,$4::bigint,$5)::text",
                &[
                    &self.fence_id,
                    &self.operation_id,
                    &expected.username,
                    &seq,
                    &expected.request_digest,
                ],
            )
            .map_err(|_| {
                rotation_failure(
                    "PostgreSQL static-role retirement readback unavailable",
                    &self.operation_id,
                )
            })?;
        if observed != "true" {
            return Err(rotation_failure(
                "PostgreSQL static-role retirement readback mismatch",
                &self.operation_id,
            ));
        }
        Ok(())
    }

    fn execute_root(
        &self,
        expected: &DatabaseRootRotation,
    ) -> Result<DatabaseRotationObservation, Response> {
        let seq = expected.seq.to_string();
        // A lost response may leave PostgreSQL already using the pending secret.
        // Readback with that secret first; never blindly replay an old-password mutation.
        if let Ok(mut observed) = self
            .connection
            .session_with_password(&self.outbound, &expected.pending_password.0)
            && observed
                .scalar(
                    "SELECT heptabao_provider.root_rotation_observed($1,$2,$3::bigint,$4)::text",
                    &[
                        &self.fence_id,
                        &self.operation_id,
                        &seq,
                        &expected.request_digest,
                    ],
                )
                .is_ok_and(|value| value == "true")
        {
            return Ok(DatabaseRotationObservation::Applied);
        }
        let mut old = self.connection.session(&self.outbound).map_err(|_| {
            rotation_failure(
                "PostgreSQL root rotation is indeterminate",
                &self.operation_id,
            )
        })?;
        if old
            .scalar("SELECT heptabao_provider.static_protocol()", &[])
            .map_err(|_| {
                rotation_failure(
                    "PostgreSQL root-rotation extension unavailable",
                    &self.operation_id,
                )
            })?
            != "heptabao-postgresql-static-v1"
        {
            return Err(rotation_failure(
                "PostgreSQL root-rotation extension mismatched",
                &self.operation_id,
            ));
        }
        let retriable = old
            .scalar(
                "SELECT heptabao_provider.root_rotation_retriable($1,$2,$3::bigint)::text",
                &[&self.fence_id, &self.operation_id, &seq],
            )
            .map_err(|_| {
                rotation_failure(
                    "PostgreSQL root-rotation retry proof unavailable",
                    &self.operation_id,
                )
            })?;
        if retriable == "true" {
            return Ok(DatabaseRotationObservation::ReadmitRequired);
        }
        let provider_password = self.connection.password_authentication.provider_password(
            &expected.pending_password.0,
            expected.provider_password.as_ref(),
        )?;
        old.scalar(
            self.connection.root_rotation_function(),
            &[
                &self.fence_id,
                &self.operation_id,
                &seq,
                provider_password,
                &expected.request_digest,
            ],
        )
        .map_err(|_| {
            rotation_failure(
                "PostgreSQL root rotation is indeterminate",
                &self.operation_id,
            )
        })?;
        drop(old);
        let mut current = self
            .connection
            .session_with_password(&self.outbound, &expected.pending_password.0)
            .map_err(|_| {
                rotation_failure(
                    "PostgreSQL root rotation readback login failed",
                    &self.operation_id,
                )
            })?;
        let manager = current
            .scalar("SELECT current_user::text", &[])
            .map_err(|_| {
                rotation_failure(
                    "PostgreSQL root identity readback failed",
                    &self.operation_id,
                )
            })?;
        let observed = current
            .scalar(
                "SELECT heptabao_provider.root_rotation_observed($1,$2,$3::bigint,$4)::text",
                &[
                    &self.fence_id,
                    &self.operation_id,
                    &seq,
                    &expected.request_digest,
                ],
            )
            .map_err(|_| {
                rotation_failure(
                    "PostgreSQL root rotation readback unavailable",
                    &self.operation_id,
                )
            })?;
        if manager != self.connection.username || observed != "true" {
            return Err(rotation_failure(
                "PostgreSQL root rotation readback mismatch",
                &self.operation_id,
            ));
        }
        Ok(DatabaseRotationObservation::Applied)
    }
}

impl Connection {
    fn session_with_password(
        &self,
        outbound: &crate::outbound::Outbound,
        password: &str,
    ) -> Result<PgSession, &'static str> {
        let (endpoint, target) = outbound.endpoint(&self.connection_url, "postgresql")?;
        let database = target
            .path
            .strip_prefix('/')
            .ok_or("invalid database URL")?;
        if !name(database) {
            return Err("invalid PostgreSQL database name");
        }
        PgSession::connect(&endpoint, database, &self.username, password)
    }
}

impl DatabaseMount {
    pub(super) fn max_rotation_sequence(&self) -> u64 {
        self.static_roles
            .values()
            .map(|role| role.seq)
            .chain(
                self.connections
                    .values()
                    .filter_map(|connection| connection.root_rotation.as_ref())
                    .map(|rotation| rotation.seq),
            )
            .max()
            .unwrap_or(0)
    }

    pub(super) fn validate_rotation_state(&self) -> Result<(), Response> {
        for connection in self.connections.values() {
            if let Some(rotation) = &connection.root_rotation
                && (connection.provider != DatabaseProvider::Postgresql
                    || !connection
                        .password_authentication
                        .persisted_provider_password_is_valid(
                            Some(&rotation.pending_password),
                            rotation.provider_password.as_ref(),
                        )
                    || rotation.seq == 0
                    || rotation.seq > i64::MAX as u64
                    || rotation.pending_password.0.len() != 64
                    || !rotation
                        .pending_password
                        .0
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                    || rotation.request_digest.len() != 64
                    || !rotation
                        .request_digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit()))
            {
                return Err(failure("invalid persisted database root rotation"));
            }
        }
        for (name, role) in &self.static_roles {
            let Some(connection) = self.connections.get(&role.db_name) else {
                return Err(failure(
                    "static role references a missing database connection",
                ));
            };
            let pending = role.pending_password.as_ref();
            let current = role.current_password.as_ref();
            let digest_is_valid = || {
                role.request_digest.len() == 64
                    && role
                        .request_digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
            };
            let common_invalid = !super::name(name)
                || !super::name(&role.username)
                || role.username == connection.username
                || connection.provider != DatabaseProvider::Postgresql
                || !connection.allowed_roles.contains(name)
                || !(MIN_STATIC_ROTATION_SECONDS..=MAX_STATIC_ROTATION_SECONDS)
                    .contains(&role.rotation_period)
                || role.seq == 0
                || role.seq > i64::MAX as u64
                || role.next_rotation < role.last_rotation.unwrap_or(0)
                || current.is_some_and(|value| {
                    value.0.len() != 64 || !value.0.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                || pending.is_some_and(|value| {
                    value.0.len() != 64 || !value.0.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                || !connection
                    .password_authentication
                    .persisted_provider_password_is_valid(
                        pending,
                        role.pending_provider_password.as_ref(),
                    );
            let phase_invalid = match role.phase {
                DatabaseStaticPhase::PendingRotate => {
                    pending.is_none()
                        || !digest_is_valid()
                        || static_digest(name, role)? != role.request_digest
                }
                DatabaseStaticPhase::PendingDelete => {
                    pending.is_some()
                        || current.is_none()
                        || role.last_rotation.is_none()
                        || !digest_is_valid()
                        || static_retire_digest(name, role)? != role.request_digest
                }
                DatabaseStaticPhase::Active => {
                    pending.is_some()
                        || current.is_none()
                        || role.last_rotation.is_none()
                        || role.next_rotation
                            != role
                                .last_rotation
                                .unwrap_or(0)
                                .saturating_add(role.rotation_period)
                        || !role.request_digest.is_empty()
                }
            };
            if common_invalid || phase_invalid {
                return Err(failure("invalid persisted database static role"));
            }
        }
        Ok(())
    }
}

impl DatabaseState {
    pub(crate) fn has_credential_rotation_state(&self) -> bool {
        self.mounts
            .values()
            .flat_map(|mounts| mounts.values())
            .any(|mount| {
                !mount.static_roles.is_empty()
                    || mount
                        .connections
                        .values()
                        .any(|connection| connection.root_rotation.is_some())
            })
    }
}

fn unix_rfc3339(seconds: u64) -> Result<String, Response> {
    let seconds =
        i64::try_from(seconds).map_err(|_| failure("rotation timestamp exceeds range"))?;
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;
    if !(1970..=9999).contains(&year) {
        return Err(failure("rotation timestamp exceeds RFC3339 range"));
    }
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

impl Service {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn database_rotation_route(
        &mut self,
        mut state: State,
        principal: &mut Option<Principal>,
        request: &RequestView<'_>,
        mount: &str,
        kind: &str,
        key: &str,
        now: u64,
        capability: &'static str,
        sudo: bool,
    ) -> Result<Response, Response> {
        if !name(key) && !(kind == "static-roles" && request.method == "LIST" && key.is_empty()) {
            return Err(invalid("invalid database rotation resource name"));
        }
        match (kind, request.method) {
            ("static-roles", "LIST") if key.is_empty() => {
                fields(request.body, &[])?;
                let keys = state
                    .database
                    .mount(request.namespace, mount)
                    .map(|value| value.static_roles.keys().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();
                Ok(Response::ok(json!({"data":{"keys":keys}})))
            }
            ("static-roles", "GET") => {
                fields(request.body, &[])?;
                let role = state
                    .database
                    .mount(request.namespace, mount)
                    .and_then(|value| value.static_roles.get(key))
                    .ok_or_else(|| Response::error(404, "database static role not found"))?;
                Ok(Response::ok(json!({"data":{
                    "db_name":role.db_name,
                    "username":role.username,
                    "rotation_period":role.rotation_period,
                    "credential_type":"password"
                }})))
            }
            ("static-roles", "POST" | "PUT") => {
                fields(request.body, &["db_name", "username", "rotation_period"])?;
                let db_name = text(request.body, "db_name")?.to_owned();
                let username = text(request.body, "username")?.to_owned();
                if !name(&db_name) || !name(&username) {
                    return Err(invalid("invalid static-role database or username"));
                }
                let rotation_period = ttl(request.body, "rotation_period", 0)?;
                if rotation_period < MIN_STATIC_ROTATION_SECONDS {
                    return Err(invalid(
                        "static-role rotation period must be at least 5 seconds",
                    ));
                }
                let database_mount = state
                    .database
                    .mount(request.namespace, mount)
                    .ok_or_else(|| Response::error(404, "database mount not found"))?;
                let connection = database_mount
                    .connections
                    .get(&db_name)
                    .ok_or_else(|| invalid("unknown static-role database configuration"))?;
                if connection.provider != DatabaseProvider::Postgresql {
                    return Err(Response::error(
                        501,
                        "bounded static roles currently require PostgreSQL",
                    ));
                }
                if username == connection.username {
                    return Err(invalid("root database credentials cannot be a static role"));
                }
                if !connection.allowed_roles.contains(key) {
                    return Err(Response::error(
                        403,
                        "database static role is not allowed by connection",
                    ));
                }
                if let Some(existing) = database_mount.static_roles.get(key) {
                    if existing.phase != DatabaseStaticPhase::Active {
                        return Err(rotation_failure(
                            "database static-role rotation is already pending",
                            &static_operation_id(&state.cluster_id, request.namespace, mount, key)?,
                        ));
                    }
                    if existing.db_name != db_name || existing.username != username {
                        return Err(Response::error(
                            409,
                            "static-role database identity cannot be rebound",
                        ));
                    }
                } else if database_mount.static_roles.len() >= 64 {
                    return Err(Response::error(
                        507,
                        "database static-role capacity exhausted",
                    ));
                }
                let authority = plugin::PluginResponseAuthority::new(
                    principal
                        .take()
                        .ok_or_else(|| failure("database static-role admission disappeared"))?,
                    &state,
                    request,
                    capability,
                    sudo,
                    &self.unseal_nonce,
                )
                .with_time_floor(now);
                let password_authentication = connection.password_authentication;
                let seq = state.database.next_provider_fence()?;
                let pending_password =
                    PrivateString(hex(&crypto::random::<32>().map_err(failure)?));
                let pending_provider_password =
                    password_authentication.generate_provider_password(&pending_password.0)?;
                let prior = state
                    .database
                    .mount(request.namespace, mount)
                    .and_then(|value| value.static_roles.get(key))
                    .cloned();
                let mut role = DatabaseStaticRole {
                    db_name,
                    username,
                    rotation_period,
                    current_password: prior
                        .as_ref()
                        .and_then(|value| value.current_password.clone()),
                    pending_password: Some(pending_password),
                    pending_provider_password,
                    last_rotation: prior.as_ref().and_then(|value| value.last_rotation),
                    next_rotation: now,
                    seq,
                    phase: DatabaseStaticPhase::PendingRotate,
                    request_digest: String::new(),
                };
                role.request_digest = static_digest(key, &role)?;
                state
                    .database
                    .mount_mut(request.namespace, mount)
                    .static_roles
                    .insert(key.to_owned(), role);
                self.publish_database(state)?;
                self.defer_database_rotation(
                    request.namespace,
                    mount,
                    RotationTarget::Static(key.to_owned()),
                    now,
                    Some(authority),
                )
            }
            ("static-roles", "DELETE") => {
                fields(request.body, &[])?;
                let role = state
                    .database
                    .mount(request.namespace, mount)
                    .and_then(|value| value.static_roles.get(key))
                    .cloned()
                    .ok_or_else(|| Response::error(404, "database static role not found"))?;
                if role.phase != DatabaseStaticPhase::Active {
                    return Err(Response::error(
                        409,
                        "database static role has an unresolved provider operation",
                    ));
                }
                let authority = plugin::PluginResponseAuthority::new(
                    principal.take().ok_or_else(|| {
                        failure("database static-role deletion admission disappeared")
                    })?,
                    &state,
                    request,
                    capability,
                    sudo,
                    &self.unseal_nonce,
                )
                .with_time_floor(now);
                let seq = state.database.next_provider_fence()?;
                let role = state
                    .database
                    .mount_mut(request.namespace, mount)
                    .static_roles
                    .get_mut(key)
                    .ok_or_else(|| Response::error(404, "database static role not found"))?;
                role.seq = seq;
                role.pending_password = None;
                role.pending_provider_password = None;
                role.phase = DatabaseStaticPhase::PendingDelete;
                role.request_digest = static_retire_digest(key, role)?;
                self.publish_database(state)?;
                self.defer_database_rotation(
                    request.namespace,
                    mount,
                    RotationTarget::Static(key.to_owned()),
                    now,
                    Some(authority),
                )
            }
            ("static-creds", "GET") => {
                fields(request.body, &[])?;
                let role = state
                    .database
                    .mount(request.namespace, mount)
                    .and_then(|value| value.static_roles.get(key))
                    .ok_or_else(|| Response::error(404, "database static role not found"))?;
                if role.phase != DatabaseStaticPhase::Active {
                    return Err(rotation_failure(
                        "database static-role password is being reconciled",
                        &static_operation_id(&state.cluster_id, request.namespace, mount, key)?,
                    ));
                }
                let password = role
                    .current_password
                    .as_ref()
                    .ok_or_else(|| failure("database static-role password unavailable"))?;
                let last = role
                    .last_rotation
                    .ok_or_else(|| failure("database static-role rotation time unavailable"))?;
                Ok(Response::ok(json!({"data":{
                    "username":role.username,
                    "password":password.0,
                    "rotation_period":role.rotation_period,
                    "ttl":role.next_rotation.saturating_sub(now),
                    "last_vault_rotation":unix_rfc3339(last)?
                }})))
            }
            ("rotate-role", "POST" | "PUT") => {
                fields(request.body, &[])?;
                let role = state
                    .database
                    .mount(request.namespace, mount)
                    .and_then(|value| value.static_roles.get(key))
                    .cloned()
                    .ok_or_else(|| Response::error(404, "database static role not found"))?;
                if role.phase != DatabaseStaticPhase::Active {
                    return Err(rotation_failure(
                        "database static-role rotation is already pending",
                        &static_operation_id(&state.cluster_id, request.namespace, mount, key)?,
                    ));
                }
                let authority = plugin::PluginResponseAuthority::new(
                    principal
                        .take()
                        .ok_or_else(|| failure("database static-role admission disappeared"))?,
                    &state,
                    request,
                    capability,
                    sudo,
                    &self.unseal_nonce,
                )
                .with_time_floor(now);
                self.stage_static_rotation(&mut state, request.namespace, mount, key, now)?;
                self.publish_database(state)?;
                self.defer_database_rotation(
                    request.namespace,
                    mount,
                    RotationTarget::Static(key.to_owned()),
                    now,
                    Some(authority),
                )
            }
            ("rotate-root", "POST" | "PUT") => {
                fields(request.body, &[])?;
                let connection = state
                    .database
                    .mount(request.namespace, mount)
                    .and_then(|value| value.connections.get(key))
                    .ok_or_else(|| Response::error(404, "database configuration not found"))?;
                if connection.provider != DatabaseProvider::Postgresql {
                    return Err(Response::error(
                        501,
                        "bounded root rotation currently requires PostgreSQL",
                    ));
                }
                if connection.root_rotation.is_some() {
                    return Err(rotation_failure(
                        "database root rotation is already pending",
                        &root_operation_id(&state.cluster_id, request.namespace, mount, key)?,
                    ));
                }
                let authority = plugin::PluginResponseAuthority::new(
                    principal
                        .take()
                        .ok_or_else(|| failure("database root-rotation admission disappeared"))?,
                    &state,
                    request,
                    capability,
                    sudo,
                    &self.unseal_nonce,
                )
                .with_time_floor(now);
                self.stage_root_rotation(&mut state, request.namespace, mount, key)?;
                self.publish_database(state)?;
                self.defer_database_rotation(
                    request.namespace,
                    mount,
                    RotationTarget::Root(key.to_owned()),
                    now,
                    Some(authority),
                )
            }
            _ => Err(Response::error(
                405,
                "method not allowed for database rotation endpoint",
            )),
        }
    }
}

#[derive(Clone)]
enum RotationTarget {
    Static(String),
    Root(String),
}

impl Service {
    fn stage_static_rotation(
        &self,
        state: &mut State,
        namespace: &str,
        mount: &str,
        role_name: &str,
        now: u64,
    ) -> Result<(), Response> {
        let password_authentication = {
            let database_mount = state
                .database
                .mount(namespace, mount)
                .ok_or_else(|| Response::error(404, "database mount not found"))?;
            let role = database_mount
                .static_roles
                .get(role_name)
                .ok_or_else(|| Response::error(404, "database static role not found"))?;
            if role.phase != DatabaseStaticPhase::Active {
                return Err(failure("database static-role rotation is already pending"));
            }
            database_mount
                .connections
                .get(&role.db_name)
                .ok_or_else(|| failure("database static-role connection disappeared"))?
                .password_authentication
        };
        let pending_password = PrivateString(hex(&crypto::random::<32>().map_err(failure)?));
        let pending_provider_password =
            password_authentication.generate_provider_password(&pending_password.0)?;
        let seq = state.database.next_provider_fence()?;
        let role = state
            .database
            .mount_mut(namespace, mount)
            .static_roles
            .get_mut(role_name)
            .ok_or_else(|| Response::error(404, "database static role not found"))?;
        role.seq = seq;
        role.pending_password = Some(pending_password);
        role.pending_provider_password = pending_provider_password;
        role.phase = DatabaseStaticPhase::PendingRotate;
        role.next_rotation = now;
        role.request_digest = static_digest(role_name, role)?;
        Ok(())
    }

    fn readmit_overtaken_static_rotation(
        &self,
        state: &mut State,
        namespace: &str,
        mount: &str,
        role_name: &str,
    ) -> Result<bool, Response> {
        let frontier = state.database.current_provider_fence();
        let (phase, previous_seq) = state
            .database
            .mount(namespace, mount)
            .and_then(|database_mount| database_mount.static_roles.get(role_name))
            .map(|role| (role.phase.clone(), role.seq))
            .ok_or_else(|| Response::error(404, "database static role not found"))?;
        if phase == DatabaseStaticPhase::Active || previous_seq >= frontier {
            return Ok(false);
        }
        let seq = state.database.next_provider_fence()?;
        let role = state
            .database
            .mount_mut(namespace, mount)
            .static_roles
            .get_mut(role_name)
            .ok_or_else(|| Response::error(404, "database static role not found"))?;
        if role.phase != phase || role.seq != previous_seq {
            return Err(failure(
                "database static-role intent changed during readmission",
            ));
        }
        role.seq = seq;
        role.request_digest = match role.phase {
            DatabaseStaticPhase::PendingRotate => static_digest(role_name, role)?,
            DatabaseStaticPhase::PendingDelete => static_retire_digest(role_name, role)?,
            DatabaseStaticPhase::Active => {
                return Err(failure("active database static role cannot be readmitted"));
            }
        };
        Ok(true)
    }

    fn stage_root_rotation(
        &self,
        state: &mut State,
        namespace: &str,
        mount: &str,
        connection_name: &str,
    ) -> Result<(), Response> {
        let password_authentication = state
            .database
            .mount(namespace, mount)
            .and_then(|database_mount| database_mount.connections.get(connection_name))
            .ok_or_else(|| Response::error(404, "database configuration not found"))?
            .password_authentication;
        let pending_password = PrivateString(hex(&crypto::random::<32>().map_err(failure)?));
        let provider_password =
            password_authentication.generate_provider_password(&pending_password.0)?;
        let seq = state.database.next_provider_fence()?;
        let mut rotation = DatabaseRootRotation {
            seq,
            pending_password,
            provider_password,
            request_digest: String::new(),
        };
        rotation.request_digest = root_digest(connection_name, &rotation)?;
        let connection = state
            .database
            .mount_mut(namespace, mount)
            .connections
            .get_mut(connection_name)
            .ok_or_else(|| Response::error(404, "database configuration not found"))?;
        if connection.root_rotation.is_some() {
            return Err(failure("database root rotation is already pending"));
        }
        connection.root_rotation = Some(rotation);
        Ok(())
    }

    fn database_rotation_plan(
        &mut self,
        namespace: &str,
        mount: &str,
        target: RotationTarget,
        now: u64,
        response_authority: Option<plugin::PluginResponseAuthority>,
    ) -> Result<DatabaseRotationPlan, Response> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| failure("server sealed"))?;
        let database_mount = state
            .database
            .mount(namespace, mount)
            .ok_or_else(|| failure("database mount disappeared"))?;
        let (connection_name, operation_id, kind) = match target {
            RotationTarget::Static(role_name) => {
                let expected = database_mount
                    .static_roles
                    .get(&role_name)
                    .filter(|role| role.phase != DatabaseStaticPhase::Active)
                    .cloned()
                    .ok_or_else(|| failure("database static-role intent disappeared"))?;
                let operation_id =
                    static_operation_id(&state.cluster_id, namespace, mount, &role_name)?;
                (
                    expected.db_name.clone(),
                    operation_id,
                    DatabaseRotationKind::Static {
                        role_name,
                        expected,
                    },
                )
            }
            RotationTarget::Root(connection_name) => {
                let expected = database_mount
                    .connections
                    .get(&connection_name)
                    .and_then(|connection| connection.root_rotation.as_ref())
                    .cloned()
                    .ok_or_else(|| failure("database root-rotation intent disappeared"))?;
                let operation_id =
                    root_operation_id(&state.cluster_id, namespace, mount, &connection_name)?;
                (
                    connection_name.clone(),
                    operation_id,
                    DatabaseRotationKind::Root {
                        connection_name,
                        expected,
                    },
                )
            }
        };
        let connection = database_mount
            .connections
            .get(&connection_name)
            .cloned()
            .ok_or_else(|| failure("database rotation connection disappeared"))?;
        if connection.provider != DatabaseProvider::Postgresql {
            return Err(Response::error(
                501,
                "bounded credential rotation currently requires PostgreSQL",
            ));
        }
        if self
            .database_in_flight
            .contains(namespace, mount, &operation_id)
        {
            return Err(rotation_failure(
                "database credential rotation is already in flight",
                &operation_id,
            ));
        }
        let in_flight = self
            .database_in_flight
            .track(namespace, mount, &operation_id);
        Ok(DatabaseRotationPlan {
            namespace: namespace.to_owned(),
            mount: mount.to_owned(),
            now,
            started: std::time::Instant::now(),
            outbound: self.outbound.clone(),
            ha: self.ha.clone(),
            connection,
            fence_id: provider_fence_identity(&state.cluster_id)?,
            operation_id,
            kind,
            response_authority: response_authority.map(Box::new),
            _in_flight: in_flight,
        })
    }

    fn defer_database_rotation(
        &mut self,
        namespace: &str,
        mount: &str,
        target: RotationTarget,
        now: u64,
        authority: Option<plugin::PluginResponseAuthority>,
    ) -> Result<Response, Response> {
        if self.pending_database_rotation_effect.is_some() {
            return Err(failure(
                "another database credential rotation is already pending dispatch",
            ));
        }
        self.pending_database_rotation_effect =
            Some(self.database_rotation_plan(namespace, mount, target, now, authority)?);
        Ok(Response::error(
            500,
            "database credential rotation was not dispatched",
        ))
    }

    fn readmit_overtaken_root_rotation(
        &mut self,
        plan: &DatabaseRotationPlan,
        now: u64,
    ) -> Response {
        let DatabaseRotationKind::Root {
            connection_name,
            expected,
        } = &plan.kind
        else {
            return rotation_failure(
                "provider requested root readmission for a non-root operation",
                &plan.operation_id,
            );
        };
        let Some(mut state) = self.state.clone() else {
            return rotation_failure("server sealed during root readmission", &plan.operation_id);
        };
        let frontier = state.database.current_provider_fence();
        let Some(current) = state
            .database
            .mount(&plan.namespace, &plan.mount)
            .and_then(|mount| mount.connections.get(connection_name))
            .and_then(|connection| connection.root_rotation.as_ref())
        else {
            return rotation_failure(
                "database root-rotation intent disappeared before readmission",
                &plan.operation_id,
            );
        };
        if current.seq != expected.seq
            || current.request_digest != expected.request_digest
            || current.pending_password.0 != expected.pending_password.0
            || current.seq >= frontier
        {
            return rotation_failure(
                "database root-rotation intent cannot be safely readmitted",
                &plan.operation_id,
            );
        }
        let seq = match state.database.next_provider_fence() {
            Ok(value) => value,
            Err(error) => return error,
        };
        let Some(rotation) = state
            .database
            .mount_mut(&plan.namespace, &plan.mount)
            .connections
            .get_mut(connection_name)
            .and_then(|connection| connection.root_rotation.as_mut())
        else {
            return rotation_failure(
                "database root-rotation intent disappeared during readmission",
                &plan.operation_id,
            );
        };
        if rotation.seq != expected.seq
            || rotation.request_digest != expected.request_digest
            || rotation.pending_password.0 != expected.pending_password.0
        {
            return rotation_failure(
                "database root-rotation intent changed during readmission",
                &plan.operation_id,
            );
        }
        rotation.seq = seq;
        rotation.request_digest = match root_digest(connection_name, rotation) {
            Ok(value) => value,
            Err(error) => return error,
        };
        state.database.clock = state.database.clock.max(now);
        if let Err(error) = self.publish_database(state) {
            return error;
        }
        rotation_failure(
            "database root rotation was safely readmitted under a fresh provider fence",
            &plan.operation_id,
        )
    }

    pub(crate) fn finalize_database_rotation_request(
        &mut self,
        mut plan: DatabaseRotationPlan,
        provider_result: Result<DatabaseRotationObservation, Response>,
    ) -> Response {
        let mut authority = plan.response_authority.take();
        self.finalize_database_rotation_checked(
            &plan,
            provider_result,
            || plan.completed_now(),
            |service| {
                let authority = authority.as_mut().ok_or_else(|| {
                    rotation_failure(
                        "database rotation delivery authority is unavailable",
                        &plan.operation_id,
                    )
                })?;
                service.validate_plugin_response(authority)
            },
        )
    }

    fn finalize_database_rotation_checked(
        &mut self,
        plan: &DatabaseRotationPlan,
        provider_result: Result<DatabaseRotationObservation, Response>,
        mut completed_now: impl FnMut() -> u64,
        mut authorize: impl FnMut(&mut Self) -> Result<(), Response>,
    ) -> Response {
        let observation = match provider_result {
            Ok(value) => value,
            Err(error) => return error,
        };
        if self.ha.is_some() && self.sync_from_ha_with_anchor(false).is_err() {
            return rotation_failure(
                "database rotation HA completion fence unavailable",
                &plan.operation_id,
            );
        }
        if observation == DatabaseRotationObservation::ReadmitRequired {
            return self.readmit_overtaken_root_rotation(plan, completed_now());
        }
        if let Err(error) = authorize(self) {
            return rotation_failure(
                error.body["errors"][0]
                    .as_str()
                    .unwrap_or("database rotation authority changed"),
                &plan.operation_id,
            );
        }
        let Some(mut state) = self.state.clone() else {
            return rotation_failure("server sealed after database rotation", &plan.operation_id);
        };
        let now = completed_now().max(state.database.clock);
        let result = match &plan.kind {
            DatabaseRotationKind::Static {
                role_name,
                expected,
            } => {
                let Some(current) = state
                    .database
                    .mount(&plan.namespace, &plan.mount)
                    .and_then(|mount| mount.static_roles.get(role_name))
                else {
                    return rotation_failure(
                        "database static-role intent disappeared after provider entry",
                        &plan.operation_id,
                    );
                };
                if current.seq != expected.seq
                    || current.request_digest != expected.request_digest
                    || current.phase != expected.phase
                    || current.username != expected.username
                    || current.db_name != expected.db_name
                    || current
                        .pending_password
                        .as_ref()
                        .map(|value| value.0.as_str())
                        != expected
                            .pending_password
                            .as_ref()
                            .map(|value| value.0.as_str())
                    || current
                        .current_password
                        .as_ref()
                        .map(|value| value.0.as_str())
                        != expected
                            .current_password
                            .as_ref()
                            .map(|value| value.0.as_str())
                {
                    return rotation_failure(
                        "database static-role intent changed after provider entry",
                        &plan.operation_id,
                    );
                }
                match expected.phase {
                    DatabaseStaticPhase::PendingRotate => {
                        if let Some(role) = state
                            .database
                            .mount_mut(&plan.namespace, &plan.mount)
                            .static_roles
                            .get_mut(role_name)
                        {
                            role.current_password = role.pending_password.take();
                            role.pending_provider_password = None;
                            role.last_rotation = Some(expected.next_rotation);
                            role.next_rotation =
                                expected.next_rotation.saturating_add(role.rotation_period);
                            role.phase = DatabaseStaticPhase::Active;
                            role.request_digest.clear();
                            Ok(())
                        } else {
                            Err(failure("database static role disappeared"))
                        }
                    }
                    DatabaseStaticPhase::PendingDelete => {
                        if state
                            .database
                            .mount_mut(&plan.namespace, &plan.mount)
                            .static_roles
                            .remove(role_name)
                            .is_some()
                        {
                            Ok(())
                        } else {
                            Err(failure("database static role disappeared"))
                        }
                    }
                    DatabaseStaticPhase::Active => {
                        Err(failure("database static-role effect was not pending"))
                    }
                }
            }
            DatabaseRotationKind::Root {
                connection_name,
                expected,
            } => {
                let Some(current) = state
                    .database
                    .mount(&plan.namespace, &plan.mount)
                    .and_then(|mount| mount.connections.get(connection_name))
                    .and_then(|connection| connection.root_rotation.as_ref())
                else {
                    return rotation_failure(
                        "database root-rotation intent disappeared after provider entry",
                        &plan.operation_id,
                    );
                };
                if current.seq != expected.seq
                    || current.request_digest != expected.request_digest
                    || current.pending_password.0 != expected.pending_password.0
                {
                    return rotation_failure(
                        "database root-rotation intent changed after provider entry",
                        &plan.operation_id,
                    );
                }
                let connection = state
                    .database
                    .mount_mut(&plan.namespace, &plan.mount)
                    .connections
                    .get_mut(connection_name)
                    .ok_or_else(|| failure("database connection disappeared"));
                match connection {
                    Ok(connection) => {
                        connection.password = expected.pending_password.clone();
                        connection.root_rotation = None;
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
        };
        if let Err(error) = result {
            return rotation_failure(
                error.body["errors"][0]
                    .as_str()
                    .unwrap_or("database rotation publication failed"),
                &plan.operation_id,
            );
        }
        state.database.clock = now;
        if let Err(error) = self.publish_database(state) {
            return rotation_failure(
                error.body["errors"][0]
                    .as_str()
                    .unwrap_or("database rotation publication failed"),
                &plan.operation_id,
            );
        }
        if let Err(error) = authorize(self) {
            return rotation_failure(
                error.body["errors"][0]
                    .as_str()
                    .unwrap_or("database rotation authority changed after publication"),
                &plan.operation_id,
            );
        }
        Response {
            status: 204,
            body: Value::Null,
        }
    }

    fn finalize_database_rotation_maintenance(
        &mut self,
        plan: &DatabaseRotationPlan,
        provider_result: Result<DatabaseRotationObservation, Response>,
    ) -> Response {
        self.finalize_database_rotation_checked(
            plan,
            provider_result,
            || plan.completed_now(),
            |_| Ok(()),
        )
    }

    pub(crate) fn prepare_database_rotation_maintenance(
        &mut self,
        now: u64,
    ) -> Result<Option<DatabaseRotationMaintenance>, &'static str> {
        if self.state.is_none() || self.recovery_required || self.audit_failed {
            return Ok(None);
        }
        if let Some(ha) = &self.ha {
            let ha = ha
                .lock_for_request()
                .map_err(|_| "database rotation HA lock unavailable")?;
            if !ha
                .is_leader()
                .map_err(|_| "database rotation leader unavailable")?
            {
                return Ok(None);
            }
            drop(ha);
            self.sync_from_ha()
                .map_err(|_| "database rotation ReadIndex unavailable")?;
        }
        self.database_in_flight.prune();
        let current = self.state.as_ref().ok_or("sealed")?.clone();
        let now = now.max(current.database.clock);
        let mut candidates = Vec::new();
        for (namespace, mounts) in &current.database.mounts {
            for (mount, database_mount) in mounts {
                for (connection_name, connection) in &database_mount.connections {
                    if connection.root_rotation.is_some() {
                        let id = root_operation_id(
                            &current.cluster_id,
                            namespace,
                            mount,
                            connection_name,
                        )
                        .map_err(|_| "database root-rotation identity unavailable")?;
                        if !self.database_in_flight.contains(namespace, mount, &id) {
                            candidates.push((
                                namespace.clone(),
                                mount.clone(),
                                format!("root:{connection_name}"),
                                RotationTarget::Root(connection_name.clone()),
                                false,
                            ));
                        }
                    }
                }
                for (role_name, role) in &database_mount.static_roles {
                    let id = static_operation_id(&current.cluster_id, namespace, mount, role_name)
                        .map_err(|_| "database static-role identity unavailable")?;
                    if self.database_in_flight.contains(namespace, mount, &id) {
                        continue;
                    }
                    if matches!(
                        role.phase,
                        DatabaseStaticPhase::PendingRotate | DatabaseStaticPhase::PendingDelete
                    ) || role.next_rotation <= now
                    {
                        candidates.push((
                            namespace.clone(),
                            mount.clone(),
                            format!("static:{role_name}"),
                            RotationTarget::Static(role_name.clone()),
                            role.phase == DatabaseStaticPhase::Active,
                        ));
                    }
                }
            }
        }
        candidates.sort_by(|left, right| {
            (&left.0, &left.1, &left.2).cmp(&(&right.0, &right.1, &right.2))
        });
        let selected = candidates
            .iter()
            .find(|(namespace, mount, key, _, _)| {
                self.database_rotation_cursor
                    .as_ref()
                    .is_none_or(|last| &(namespace.clone(), mount.clone(), key.clone()) > last)
            })
            .or_else(|| candidates.first())
            .cloned();
        let Some((namespace, mount, cursor_key, target, due)) = selected else {
            return Ok(None);
        };
        self.database_rotation_cursor = Some((namespace.clone(), mount.clone(), cursor_key));
        let fingerprint =
            self.request_fingerprint("INTERNAL", "database/rotate/reconcile", &namespace, "");
        self.audit_event("provider-request", &fingerprint, now, None)
            .map_err(|_| "database rotation audit unavailable")?;
        let readmit = match &target {
            RotationTarget::Static(role_name) => current
                .database
                .mount(&namespace, &mount)
                .and_then(|database_mount| database_mount.static_roles.get(role_name))
                .is_some_and(|role| {
                    role.phase != DatabaseStaticPhase::Active
                        && role.seq < current.database.current_provider_fence()
                }),
            RotationTarget::Root(_) => false,
        };
        if due || readmit {
            let RotationTarget::Static(role_name) = &target else {
                return Err("automatic root rotation is not scheduled");
            };
            let mut state = current.clone();
            if due {
                self.stage_static_rotation(&mut state, &namespace, &mount, role_name, now)
                    .map_err(|_| "cannot stage automatic static-role rotation")?;
            } else if !self
                .readmit_overtaken_static_rotation(&mut state, &namespace, &mount, role_name)
                .map_err(|_| "cannot readmit overtaken static-role rotation")?
            {
                return Err("database static-role intent no longer needs readmission");
            }
            self.publish_database(state)
                .map_err(|_| "database static-role intent not committed")?;
        }
        let plan = self
            .database_rotation_plan(&namespace, &mount, target, now, None)
            .map_err(|_| "database rotation plan unavailable")?;
        Ok(Some(DatabaseRotationMaintenance {
            fingerprint,
            now,
            plan,
        }))
    }

    pub(crate) fn finish_database_rotation_maintenance(
        &mut self,
        pending: DatabaseRotationMaintenance,
        provider_result: Result<DatabaseRotationObservation, Response>,
    ) -> Result<bool, &'static str> {
        let response = self.finalize_database_rotation_maintenance(&pending.plan, provider_result);
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
            return Err("database rotation result audit unavailable");
        }
        if !completed {
            return Err("database credential rotation remains indeterminate");
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::tests::{Root, bootstrap, call};
    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn response<T>(result: Result<T, Response>) -> TestResult<T> {
        result.map_err(|error| format!("HTTP {}: {}", error.status, error.body).into())
    }

    fn fixture() -> TestResult<(Root, Service, String)> {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, root_token) = bootstrap(&mut service)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "sys/mounts/database",
                &root_token,
                json!({"type":"database"}),
            )
            .status,
            204
        );
        let mut state = service.state.clone().ok_or("state")?;
        state
            .database
            .mount_mut("", "database/")
            .connections
            .insert(
                "local".into(),
                Connection {
                    provider: DatabaseProvider::Postgresql,
                    plugin_id: None,
                    connection_url: "postgresql://localhost:5432/app".into(),
                    username: "hb_manager".into(),
                    password: PrivateString("old-manager-password".into()),
                    allowed_roles: BTreeSet::from(["static-a".into(), "static-b".into()]),
                    password_authentication: PostgresqlPasswordAuthentication::Password,
                    root_rotation: None,
                },
            );
        state.schema = CURRENT_STATE_SCHEMA;
        response(state.validate_format())?;
        response(service.commit_state(&state))?;
        service.state = Some(state);
        Ok((root, service, root_token))
    }

    fn insert_pending_static(
        state: &mut State,
        name: &str,
        username: &str,
        now: u64,
    ) -> Result<DatabaseStaticRole, Response> {
        let seq = state.database.next_provider_fence()?;
        let pending_password = PrivateString("ab".repeat(32));
        let password_authentication = state
            .database
            .mount("", "database/")
            .and_then(|mount| mount.connections.get("local"))
            .ok_or_else(|| failure("static fixture connection missing"))?
            .password_authentication;
        let pending_provider_password =
            password_authentication.generate_provider_password(&pending_password.0)?;
        let mut role = DatabaseStaticRole {
            db_name: "local".into(),
            username: username.into(),
            rotation_period: 60,
            current_password: None,
            pending_password: Some(pending_password),
            pending_provider_password,
            last_rotation: None,
            next_rotation: now,
            seq,
            phase: DatabaseStaticPhase::PendingRotate,
            request_digest: String::new(),
        };
        role.request_digest = static_digest(name, &role)?;
        state
            .database
            .mount_mut("", "database/")
            .static_roles
            .insert(name.into(), role.clone());
        Ok(role)
    }

    fn publish(service: &mut Service, mut state: State) -> TestResult {
        state.schema = CURRENT_STATE_SCHEMA;
        response(state.validate_format())?;
        response(service.commit_state(&state))?;
        service.state = Some(state);
        Ok(())
    }

    #[test]
    fn rotation_state_requires_schema_53_and_rejects_digest_tamper() -> TestResult {
        let (_root, service, _) = fixture()?;
        let mut state = service.state.clone().ok_or("state")?;
        response(insert_pending_static(
            &mut state,
            "static-a",
            "app_static_a",
            100,
        ))?;
        state.schema = 52;
        let error = state.validate_format().err().ok_or("schema 52 admitted")?;
        assert_eq!(error.status, 503);
        state.schema = CURRENT_STATE_SCHEMA;
        response(state.validate_format())?;
        state
            .database
            .mount_mut("", "database/")
            .static_roles
            .get_mut("static-a")
            .ok_or("role")?
            .pending_password = Some(PrivateString("cd".repeat(32)));
        assert!(state.validate_format().is_err());
        assert_eq!(
            service.state.as_ref().ok_or("state")?.schema,
            CURRENT_STATE_SCHEMA
        );
        Ok(())
    }

    #[test]
    fn scram_rotation_state_requires_provider_verifier_pairing() -> TestResult {
        let (_root, service, _) = fixture()?;
        let mut state = service.state.clone().ok_or("state")?;
        state
            .database
            .mount_mut("", "database/")
            .connections
            .get_mut("local")
            .ok_or("connection")?
            .password_authentication = PostgresqlPasswordAuthentication::ScramSha256;
        let pending = response(insert_pending_static(
            &mut state,
            "static-a",
            "app_static_a",
            100,
        ))?;
        assert!(
            pending
                .pending_provider_password
                .as_ref()
                .is_some_and(|value| valid_postgresql_scram_verifier(&value.0))
        );
        response(state.validate_format())?;
        let saved = state
            .database
            .mount_mut("", "database/")
            .static_roles
            .get_mut("static-a")
            .ok_or("role")?
            .pending_provider_password
            .take();
        assert!(state.validate_format().is_err());
        state
            .database
            .mount_mut("", "database/")
            .static_roles
            .get_mut("static-a")
            .ok_or("role")?
            .pending_provider_password = saved;
        response(state.validate_format())?;

        let mut root_state = service.state.clone().ok_or("root state")?;
        root_state
            .database
            .mount_mut("", "database/")
            .connections
            .get_mut("local")
            .ok_or("connection")?
            .password_authentication = PostgresqlPasswordAuthentication::ScramSha256;
        response(service.stage_root_rotation(&mut root_state, "", "database/", "local"))?;
        response(root_state.validate_format())?;
        let root_provider = root_state
            .database
            .mount_mut("", "database/")
            .connections
            .get_mut("local")
            .ok_or("connection")?
            .root_rotation
            .as_mut()
            .ok_or("root rotation")?
            .provider_password
            .take();
        assert!(root_state.validate_format().is_err());
        root_state
            .database
            .mount_mut("", "database/")
            .connections
            .get_mut("local")
            .ok_or("connection")?
            .root_rotation
            .as_mut()
            .ok_or("root rotation")?
            .provider_password = root_provider;
        response(root_state.validate_format())?;
        Ok(())
    }

    #[test]
    fn rotation_state_rejects_provider_fence_behind_static_intent() -> TestResult {
        let (_root, service, _) = fixture()?;
        let mut state = service.state.clone().ok_or("state")?;
        let pending = response(insert_pending_static(
            &mut state,
            "static-a",
            "app_static_a",
            100,
        ))?;
        assert!(pending.seq > 0);
        state.database.provider_fence = pending.seq - 1;
        let error = state
            .validate_format()
            .err()
            .ok_or("rotation state admitted a regressed provider fence")?;
        assert_eq!(error.status, 503);
        Ok(())
    }

    #[test]
    fn provider_success_is_required_before_static_password_publication() -> TestResult {
        let (_root, mut service, _) = fixture()?;
        let mut state = service.state.clone().ok_or("state")?;
        let expected = response(insert_pending_static(
            &mut state,
            "static-a",
            "app_static_a",
            100,
        ))?;
        publish(&mut service, state)?;
        let plan = response(service.database_rotation_plan(
            "",
            "database/",
            RotationTarget::Static("static-a".into()),
            100,
            None,
        ))?;
        let rejected = service.finalize_database_rotation_maintenance(
            &plan,
            Err(rotation_failure(
                "synthetic provider failure",
                &plan.operation_id,
            )),
        );
        assert_eq!(rejected.status, 503);
        let pending = service
            .state
            .as_ref()
            .and_then(|state| state.database.mount("", "database/"))
            .and_then(|mount| mount.static_roles.get("static-a"))
            .ok_or("pending role")?;
        assert_eq!(pending.phase, DatabaseStaticPhase::PendingRotate);
        assert!(pending.current_password.is_none());
        assert_eq!(
            service
                .finalize_database_rotation_maintenance(
                    &plan,
                    Ok(DatabaseRotationObservation::Applied),
                )
                .status,
            204
        );
        let active = service
            .state
            .as_ref()
            .and_then(|state| state.database.mount("", "database/"))
            .and_then(|mount| mount.static_roles.get("static-a"))
            .ok_or("active role")?;
        assert_eq!(active.phase, DatabaseStaticPhase::Active);
        assert_eq!(
            active
                .current_password
                .as_ref()
                .map(|value| value.0.as_str()),
            expected
                .pending_password
                .as_ref()
                .map(|value| value.0.as_str())
        );
        assert!(active.pending_password.is_none());
        assert_eq!(active.last_rotation, Some(100));
        assert_eq!(active.next_rotation, 160);
        Ok(())
    }

    #[test]
    fn provider_success_is_required_before_root_password_replaces_local_config() -> TestResult {
        let (_root, mut service, _) = fixture()?;
        let mut state = service.state.clone().ok_or("state")?;
        response(service.stage_root_rotation(&mut state, "", "database/", "local"))?;
        let expected = state
            .database
            .mount("", "database/")
            .and_then(|mount| mount.connections.get("local"))
            .and_then(|connection| connection.root_rotation.as_ref())
            .cloned()
            .ok_or("rotation")?;
        publish(&mut service, state)?;
        let plan = response(service.database_rotation_plan(
            "",
            "database/",
            RotationTarget::Root("local".into()),
            100,
            None,
        ))?;
        assert_eq!(
            service
                .finalize_database_rotation_maintenance(
                    &plan,
                    Ok(DatabaseRotationObservation::Applied),
                )
                .status,
            204
        );
        let connection = service
            .state
            .as_ref()
            .and_then(|state| state.database.mount("", "database/"))
            .and_then(|mount| mount.connections.get("local"))
            .ok_or("connection")?;
        assert_eq!(connection.password.0, expected.pending_password.0);
        assert!(connection.root_rotation.is_none());
        Ok(())
    }

    #[test]
    fn provider_proven_overtaken_root_rotation_is_readmitted_durably() -> TestResult {
        let (_root, mut service, _) = fixture()?;
        let mut state = service.state.clone().ok_or("state")?;
        response(service.stage_root_rotation(&mut state, "", "database/", "local"))?;
        let original = state
            .database
            .mount("", "database/")
            .and_then(|mount| mount.connections.get("local"))
            .and_then(|connection| connection.root_rotation.as_ref())
            .cloned()
            .ok_or("root rotation")?;
        let overtaking = response(state.database.next_provider_fence())?;
        publish(&mut service, state)?;
        let plan = response(service.database_rotation_plan(
            "",
            "database/",
            RotationTarget::Root("local".into()),
            100,
            None,
        ))?;
        let result = service.finalize_database_rotation_maintenance(
            &plan,
            Ok(DatabaseRotationObservation::ReadmitRequired),
        );
        assert_eq!(result.status, 503);
        let current = service
            .state
            .as_ref()
            .and_then(|state| state.database.mount("", "database/"))
            .and_then(|mount| mount.connections.get("local"))
            .and_then(|connection| connection.root_rotation.as_ref())
            .ok_or("readmitted rotation")?;
        assert!(current.seq > overtaking);
        assert_ne!(current.request_digest, original.request_digest);
        assert_eq!(current.pending_password.0, original.pending_password.0);
        Ok(())
    }

    #[test]
    fn rotation_maintenance_cursor_does_not_starve_an_independent_intent() -> TestResult {
        let (_root, mut service, _) = fixture()?;
        let mut state = service.state.clone().ok_or("state")?;
        response(insert_pending_static(
            &mut state,
            "static-a",
            "app_static_a",
            100,
        ))?;
        response(insert_pending_static(
            &mut state,
            "static-b",
            "app_static_b",
            100,
        ))?;
        publish(&mut service, state)?;
        let first = service
            .prepare_database_rotation_maintenance(100)?
            .ok_or("first rotation")?;
        let first_name = match &first.plan.kind {
            DatabaseRotationKind::Static { role_name, .. } => role_name.clone(),
            DatabaseRotationKind::Root { .. } => return Err("unexpected root".into()),
        };
        drop(first);
        service.database_in_flight.prune();
        let second = service
            .prepare_database_rotation_maintenance(100)?
            .ok_or("second rotation")?;
        let second_name = match &second.plan.kind {
            DatabaseRotationKind::Static { role_name, .. } => role_name.clone(),
            DatabaseRotationKind::Root { .. } => return Err("unexpected root".into()),
        };
        assert_ne!(first_name, second_name);
        Ok(())
    }

    #[test]
    fn overtaken_pending_static_rotation_is_readmitted_with_same_secret() -> TestResult {
        let (_root, mut service, _) = fixture()?;
        let mut state = service.state.clone().ok_or("state")?;
        let original = response(insert_pending_static(
            &mut state,
            "static-a",
            "app_static_a",
            100,
        ))?;
        let original_password = original
            .pending_password
            .as_ref()
            .ok_or("pending password")?
            .0
            .clone();
        let overtaking = response(state.database.next_provider_fence())?;
        assert!(overtaking > original.seq);
        publish(&mut service, state)?;
        let pending = service
            .prepare_database_rotation_maintenance(101)?
            .ok_or("overtaken static rotation was not recovered")?;
        let DatabaseRotationKind::Static { expected, .. } = &pending.plan.kind else {
            return Err("unexpected root rotation".into());
        };
        assert!(expected.seq > overtaking);
        assert_ne!(expected.request_digest, original.request_digest);
        assert_eq!(
            expected
                .pending_password
                .as_ref()
                .map(|value| value.0.as_str()),
            Some(original_password.as_str())
        );
        let current = service
            .state
            .as_ref()
            .and_then(|state| state.database.mount("", "database/"))
            .and_then(|mount| mount.static_roles.get("static-a"))
            .ok_or("readmitted role")?;
        assert_eq!(current.seq, expected.seq);
        assert_eq!(current.request_digest, expected.request_digest);
        Ok(())
    }

    #[test]
    fn pending_static_delete_is_recovered_by_lifecycle_maintenance() -> TestResult {
        let (_root, mut service, _) = fixture()?;
        let mut state = service.state.clone().ok_or("state")?;
        let seq = response(state.database.next_provider_fence())?;
        let mut role = DatabaseStaticRole {
            db_name: "local".into(),
            username: "app_static_a".into(),
            rotation_period: 60,
            current_password: Some(PrivateString("ab".repeat(32))),
            pending_password: None,
            pending_provider_password: None,
            last_rotation: Some(100),
            next_rotation: 160,
            seq,
            phase: DatabaseStaticPhase::PendingDelete,
            request_digest: String::new(),
        };
        role.request_digest = response(static_retire_digest("static-a", &role))?;
        state
            .database
            .mount_mut("", "database/")
            .static_roles
            .insert("static-a".into(), role.clone());
        publish(&mut service, state)?;
        let pending = service
            .prepare_database_rotation_maintenance(101)?
            .ok_or("pending static delete was not recovered")?;
        match &pending.plan.kind {
            DatabaseRotationKind::Static {
                role_name,
                expected,
            } => {
                assert_eq!(role_name, "static-a");
                assert_eq!(expected.phase, DatabaseStaticPhase::PendingDelete);
                assert_eq!(expected.seq, role.seq);
                assert_eq!(expected.request_digest, role.request_digest);
            }
            DatabaseRotationKind::Root { .. } => return Err("unexpected root rotation".into()),
        }
        Ok(())
    }

    #[test]
    fn static_provider_readback_requires_exact_eight_fields() -> TestResult {
        let valid = json!({
            "found":true,
            "static_id":"hbs1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "username":"app_static",
            "seq":7,
            "request_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "rotated_at":100,
            "controlled":true,
            "login":true
        });
        let encoded = valid.to_string();
        assert!(static_observation_matches(
            &encoded,
            "hbs1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "app_static",
            7,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ));
        let mut extra = valid.as_object().ok_or("object")?.clone();
        extra.insert("untrusted".into(), json!(true));
        assert!(!static_observation_matches(
            &Value::Object(extra).to_string(),
            "hbs1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "app_static",
            7,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ));
        Ok(())
    }

    #[test]
    fn rfc3339_projection_is_bounded_and_stable() -> TestResult {
        assert_eq!(response(unix_rfc3339(0))?, "1970-01-01T00:00:00Z");
        assert_eq!(
            response(unix_rfc3339(1_700_000_000))?,
            "2023-11-14T22:13:20Z"
        );
        Ok(())
    }
}
