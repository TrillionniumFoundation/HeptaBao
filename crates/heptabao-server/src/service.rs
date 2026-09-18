use crate::{
    auth::{AuthState, Principal},
    crypto::{self, AeadBarrier, SecretShare},
    engines::EngineState,
    ha::HaProcess,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
#[cfg(test)]
use heptabao_durable_service::PutRequest;
use heptabao_durable_service::{
    Barrier, DurableService, MutationOutcome, ReconciliationStatus, Secret, ServiceError,
};
use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

const CURRENT_STATE_SCHEMA: u32 = 10;
const MAX_STATE_BYTES: usize = state_store::MAX_SERIALIZED_STATE_BYTES;
const MAX_OPERATIONS: usize = 32_000;
const MAX_AUDIT_BYTES: u64 = 32 * 1024 * 1024;
#[path = "audit_rotation.rs"]
mod audit_rotation;
#[path = "service_capabilities.rs"]
mod capabilities;
#[path = "service_database.rs"]
mod database;
#[path = "service_identity.rs"]
mod identity;
#[path = "service_kubernetes_secrets.rs"]
mod kubernetes_secret;
#[path = "service_lifecycle.rs"]
mod lifecycle;
#[path = "service_namespaces.rs"]
mod namespaces;
#[path = "service_online_auth.rs"]
mod online_auth;
#[path = "service_plugin.rs"]
mod plugin;
pub use plugin::{PluginAuthConfig, PluginSecretConfig};
#[path = "service_openapi.rs"]
mod openapi;
#[path = "service_owner_store.rs"]
mod owner_store;
#[path = "service_raft_admin.rs"]
mod raft_admin;
#[path = "service_state_store.rs"]
mod state_store;
pub(crate) use lifecycle::start_lifecycle_worker;

#[path = "service_leases.rs"]
mod leases;
pub use audit_rotation::AuditConfig;
use audit_rotation::AuditRotation;
const MAX_SEAL_SHARES: u8 = 16;
const SEAL_METADATA_FILE: &str = "seal.json";
const PENDING_REKEY_FILE: &str = "seal-rekey.json";
const SEAL_METADATA_LIMIT: u64 = 64 * 1024;
const REKEY_METADATA_LIMIT: u64 = 96 * 1024;
const INIT_RECOVERY_FILE: &str = "init-recovery.hbe";
const INIT_RECOVERY_LIMIT: u64 = 16 * 1024;
const MAX_BACKUP_TRANSFER_BYTES: usize = 20 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SealMetadata {
    schema: u32,
    generation: u64,
    share_format: String,
    secret_shares: u8,
    secret_threshold: u8,
    wrapped_barrier_key: String,
}

impl SealMetadata {
    fn validate(&self) -> Result<(), &'static str> {
        if self.schema != 1
            || self.generation == 0
            || !matches!(self.share_format.as_str(), "shamir-v1" | "raw-v1")
            || self.secret_shares == 0
            || self.secret_shares > MAX_SEAL_SHARES
            || self.secret_threshold == 0
            || self.secret_threshold > self.secret_shares
            || self.share_format == "raw-v1"
                && (self.secret_shares != 1 || self.secret_threshold != 1)
        {
            return Err("unsupported or invalid seal metadata");
        }
        let wrapped = STANDARD
            .decode(&self.wrapped_barrier_key)
            .map_err(|_| "invalid wrapped barrier key encoding")?;
        if wrapped.len() != 64 {
            return Err("invalid wrapped barrier key size");
        }
        Ok(())
    }

    fn associated_data(&self) -> Vec<u8> {
        seal_associated_data(
            self.schema,
            self.generation,
            &self.share_format,
            self.secret_shares,
            self.secret_threshold,
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRekeyMetadata {
    schema: u32,
    active_generation: u64,
    nonce: String,
    verification_nonce: String,
    candidate: SealMetadata,
}

impl PendingRekeyMetadata {
    fn validate_shape(&self) -> Result<(), &'static str> {
        if self.schema != 1
            || !valid_nonce(&self.nonce)
            || !valid_nonce(&self.verification_nonce)
            || self.active_generation == 0
            || self.candidate.generation
                != self
                    .active_generation
                    .checked_add(1)
                    .ok_or("pending rekey generation exhausted")?
            || self.candidate.share_format != "shamir-v1"
        {
            return Err("unsupported or invalid pending rekey metadata");
        }
        self.candidate.validate()
    }
}

struct RekeyState {
    nonce: String,
    new_shares: u8,
    new_threshold: u8,
    require_verification: bool,
    provided: BTreeMap<u8, SecretShare>,
    verification: Option<PendingRekeyMetadata>,
    verification_provided: BTreeMap<u8, SecretShare>,
}

#[derive(Debug)]
struct CowOwner<T>(Arc<T>);

impl<T> Clone for CowOwner<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> From<T> for CowOwner<T> {
    fn from(value: T) -> Self {
        Self(Arc::new(value))
    }
}

impl<T> Default for CowOwner<T>
where
    T: Default,
{
    fn default() -> Self {
        Self::from(T::default())
    }
}

impl<T> CowOwner<T> {
    fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl<T> std::ops::Deref for CowOwner<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<T> std::ops::DerefMut for CowOwner<T>
where
    T: Clone,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.0)
    }
}

impl<T> Serialize for CowOwner<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_ref().serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for CowOwner<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::from)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: u32,
    cluster_id: String,
    /// Cluster-visible replay generation. Epoch changes are ordinary replicated
    /// application-state transitions; each node retires its local detailed
    /// replay ledger before publishing state for the new epoch.
    #[serde(default, skip_serializing_if = "replay_epoch_is_zero")]
    replay_epoch: u64,
    #[serde(
        default,
        skip_serializing_if = "namespaces::NamespaceRegistry::is_empty"
    )]
    namespaces: CowOwner<namespaces::NamespaceRegistry>,
    auth: CowOwner<AuthState>,
    engines: CowOwner<EngineState>,
    #[serde(default, skip_serializing_if = "database::DatabaseState::is_empty")]
    database: CowOwner<database::DatabaseState>,
    #[serde(
        default,
        skip_serializing_if = "raft_admin::RaftAdminState::is_default"
    )]
    raft_admin: CowOwner<raft_admin::RaftAdminState>,
}

#[derive(Clone, Copy, Default)]
struct OwnerReuseHint {
    namespaces: bool,
    auth: bool,
    engines: bool,
    database: bool,
    raft_admin: bool,
}

impl OwnerReuseHint {
    fn between(previous: Option<&State>, next: &State) -> Self {
        let Some(previous) = previous else {
            return Self::default();
        };
        Self {
            namespaces: next.namespaces.ptr_eq(&previous.namespaces),
            auth: next.auth.ptr_eq(&previous.auth),
            engines: next.engines.ptr_eq(&previous.engines),
            database: next.database.ptr_eq(&previous.database),
            raft_admin: next.raft_admin.ptr_eq(&previous.raft_admin),
        }
    }
}

fn replay_epoch_is_zero(value: &u64) -> bool {
    *value == 0
}

pub struct Response {
    pub status: u16,
    pub body: Value,
}
impl Drop for Response {
    fn drop(&mut self) {
        erase_json(&mut self.body);
    }
}

impl Response {
    pub fn error(status: u16, message: &str) -> Self {
        Self {
            status,
            body: json!({"errors":[message]}),
        }
    }
    fn ok(body: Value) -> Self {
        Self { status: 200, body }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum WireRejection {
    RateLimited,
    ParseRejected,
}

fn default_audit_socket_timeout_ms() -> u64 {
    2_000
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSocketConfig {
    pub address: SocketAddr,
    #[serde(default = "default_audit_socket_timeout_ms")]
    pub write_timeout_ms: u64,
}

impl AuditSocketConfig {
    fn validate(self) -> Result<Self, String> {
        if !(1..=10_000).contains(&self.write_timeout_ms) || self.address.ip().is_unspecified() {
            return Err("invalid bounded audit socket configuration".into());
        }
        Ok(self)
    }
}

fn default_audit_syslog_facility() -> String {
    "AUTH".into()
}

fn default_audit_syslog_tag() -> String {
    "heptabao".into()
}

fn default_audit_syslog_socket_path() -> PathBuf {
    PathBuf::from("/dev/log")
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSyslogConfig {
    #[serde(default = "default_audit_syslog_facility")]
    pub facility: String,
    #[serde(default = "default_audit_syslog_tag")]
    pub tag: String,
    #[serde(default = "default_audit_syslog_socket_path")]
    pub socket_path: PathBuf,
}

impl AuditSyslogConfig {
    fn validate(mut self) -> Result<Self, String> {
        self.facility.make_ascii_uppercase();
        if syslog_facility_code(&self.facility).is_none()
            || self.tag.is_empty()
            || self.tag.len() > 64
            || !self
                .tag
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || !self.socket_path.is_absolute()
        {
            return Err("invalid bounded syslog audit configuration".into());
        }
        Ok(self)
    }
}

fn syslog_facility_code(facility: &str) -> Option<u8> {
    match facility {
        "KERN" => Some(0),
        "USER" => Some(1),
        "MAIL" => Some(2),
        "DAEMON" => Some(3),
        "AUTH" => Some(4),
        "SYSLOG" => Some(5),
        "LPR" => Some(6),
        "NEWS" => Some(7),
        "UUCP" => Some(8),
        "CRON" => Some(9),
        "AUTHPRIV" => Some(10),
        "FTP" => Some(11),
        "LOCAL0" => Some(16),
        "LOCAL1" => Some(17),
        "LOCAL2" => Some(18),
        "LOCAL3" => Some(19),
        "LOCAL4" => Some(20),
        "LOCAL5" => Some(21),
        "LOCAL6" => Some(22),
        "LOCAL7" => Some(23),
        _ => None,
    }
}

impl WireRejection {
    fn code(self) -> &'static [u8] {
        match self {
            Self::RateLimited => b"rate-limited",
            Self::ParseRejected => b"parse-rejected",
        }
    }
}

struct InitializationStage {
    path: PathBuf,
    published: bool,
}

impl InitializationStage {
    fn create(final_path: &Path) -> Result<Self, io::Error> {
        if final_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "initialization target already exists",
            ));
        }
        let parent = final_path
            .parent()
            .ok_or_else(|| io::Error::other("initialization target has no parent"))?;
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(io::Error::other("initialization parent is unsafe"));
        }
        let suffix = hex(&crypto::random::<16>().map_err(io::Error::other)?);
        let path = parent.join(format!(".heptabao-init-{suffix}"));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path)?;
        Ok(Self {
            path,
            published: false,
        })
    }

    fn publish(&mut self, final_path: &Path) -> Result<bool, io::Error> {
        if final_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "initialization target appeared before publication",
            ));
        }
        fs::rename(&self.path, final_path)?;
        self.published = true;
        let parent = final_path
            .parent()
            .ok_or_else(|| io::Error::other("initialization target has no parent"))?;
        Ok(File::open(parent)
            .and_then(|directory| directory.sync_all())
            .is_ok())
    }
}

impl Drop for InitializationStage {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// One bounded request. The token and body are secret-bearing; deliberately no
/// Debug/Clone/Serialize implementation. HTTP and authenticated HA use this same entry.
pub struct ServiceRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub namespace: &'a str,
    pub token: &'a str,
    pub body: Value,
    pub wrap_ttl_seconds: Option<u64>,
}

struct RequestDispatch<'a> {
    method: &'a str,
    path: &'a str,
    namespace: &'a str,
    token: &'a str,
    body: Value,
    now: u64,
    allow_forward: bool,
    wrap_ttl_seconds: Option<u64>,
}

struct RequestView<'a> {
    method: &'a str,
    path: &'a str,
    namespace: &'a str,
    token: &'a str,
    body: &'a Value,
    now: u64,
    allow_forward: bool,
    wrap_ttl_seconds: Option<u64>,
}

pub(crate) enum RequestExecution {
    Complete(Response),
    External(Box<PendingExternalRequest>),
}

enum ExternalEffectPlan {
    Database(database::DatabaseEffectPlan),
    DatabaseConfig(database::DatabaseConfigPlan),
    DatabaseBatch(database::DatabaseBatchEffectPlan),
    OnlineAuth(online_auth::OnlineAuthEffectPlan),
    PluginAuth(plugin::PluginAuthPlan),
    PluginRead(plugin::PluginReadPlan),
    KubernetesToken(kubernetes_secret::KubernetesTokenEffectPlan),
}

pub(crate) enum ExternalEffectResult {
    Database(Result<(), Response>),
    DatabaseConfig(Result<(), Response>),
    DatabaseBatch(database::DatabaseBatchEffectResult),
    OnlineAuth(Result<online_auth::OnlineAuthObservation, Response>),
    PluginAuth(Result<plugin::PluginAuthObservation, Response>),
    PluginRead(Result<Value, Response>),
    KubernetesToken(Result<crate::engines::kubernetes::TokenMetadata, Response>),
}

pub(crate) struct PendingExternalRequest {
    fingerprint: String,
    now: u64,
    effect: ExternalEffectPlan,
}

impl PendingExternalRequest {
    /// Run only the bounded external side effect. The caller must not hold the
    /// global Service writer while this method is executing.
    pub(crate) fn execute(&self) -> ExternalEffectResult {
        match &self.effect {
            ExternalEffectPlan::Database(plan) => ExternalEffectResult::Database(plan.execute()),
            ExternalEffectPlan::DatabaseConfig(plan) => {
                ExternalEffectResult::DatabaseConfig(plan.execute())
            }
            ExternalEffectPlan::DatabaseBatch(plan) => {
                ExternalEffectResult::DatabaseBatch(plan.execute())
            }
            ExternalEffectPlan::OnlineAuth(plan) => {
                ExternalEffectResult::OnlineAuth(plan.execute())
            }
            ExternalEffectPlan::PluginAuth(plan) => {
                ExternalEffectResult::PluginAuth(plan.execute())
            }
            ExternalEffectPlan::PluginRead(plan) => {
                ExternalEffectResult::PluginRead(plan.execute())
            }
            ExternalEffectPlan::KubernetesToken(plan) => {
                ExternalEffectResult::KubernetesToken(plan.execute())
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestEffectClass {
    PureRead,
    DurableMutation,
    SideEffectingRead,
}

fn kv_authorization_method<'a>(method: &'a str, body: &Value) -> &'a str {
    if method == "GET"
        && body
            .get("list")
            .is_some_and(|value| value == true || value == "true")
    {
        "LIST"
    } else {
        method
    }
}

fn classify_request_effect(
    method: &str,
    before_digest: [u8; 32],
    after_digest: [u8; 32],
) -> RequestEffectClass {
    if before_digest == after_digest {
        RequestEffectClass::PureRead
    } else if matches!(method, "GET" | "HEAD" | "LIST" | "SCAN") {
        RequestEffectClass::SideEffectingRead
    } else {
        RequestEffectClass::DurableMutation
    }
}

pub struct Service {
    outbound: crate::outbound::Outbound,
    database_cursor: Option<(String, String, String)>,
    pending_database_effect: Option<database::DatabaseEffectPlan>,
    pending_database_config_effect: Option<database::DatabaseConfigPlan>,
    pending_database_batch_effect: Option<database::DatabaseBatchEffectPlan>,
    pending_online_auth_effect: Option<online_auth::OnlineAuthEffectPlan>,
    pending_plugin_auth: Option<plugin::PluginAuthPlan>,
    pending_plugin_read: Option<plugin::PluginReadPlan>,
    pending_kubernetes_token: Option<kubernetes_secret::KubernetesTokenEffectPlan>,
    auth_plugins: BTreeMap<String, plugin::SharedAuthPlugin>,
    plugins: BTreeMap<String, plugin::SharedSecretPlugin>,
    raft_stabilization: raft_admin::Stabilization,
    data_dir: PathBuf,
    audit: File,
    audit_rotation: AuditRotation,
    audit_key: hmac::Key,
    audit_sequence: u64,
    audit_previous: [u8; 32],
    audit_failed: bool,
    audit_http_url: Option<String>,
    audit_socket: Option<AuditSocketConfig>,
    audit_socket_failures: u64,
    audit_syslog: Option<AuditSyslogConfig>,
    audit_syslog_failures: u64,
    durable: Option<DurableService<AeadBarrier>>,
    state: Option<State>,
    state_digest: Option<[u8; 32]>,
    kv_read_only_dispatches: u64,
    seal: Option<SealMetadata>,
    unseal_shares: BTreeMap<u8, SecretShare>,
    unseal_nonce: String,
    barrier_key: Option<Zeroizing<[u8; 32]>>,
    rekey: Option<RekeyState>,
    recovery_required: bool,
    ha: Option<Arc<Mutex<HaProcess>>>,
    #[cfg(test)]
    state_capacity: usize,
    #[cfg(test)]
    audit_capacity: u64,
}

impl Service {
    /// Install the trusted process configuration before unseal, never via HTTP.
    pub fn install_outbound_endpoints(
        &mut self,
        endpoints: Vec<crate::outbound::EndpointConfig>,
    ) -> Result<(), String> {
        if self.state.is_some() {
            return Err("outbound policy is immutable while unsealed".into());
        }
        self.outbound = crate::outbound::Outbound::new(endpoints).map_err(str::to_owned)?;
        Ok(())
    }

    pub fn install_auth_plugins(&mut self, configs: Vec<PluginAuthConfig>) -> Result<(), String> {
        if self.state.is_some() {
            return Err("plugin runtime configuration is immutable while unsealed".into());
        }
        self.auth_plugins = plugin::admit_auth_plugins(configs)?;
        Ok(())
    }

    pub fn install_secret_plugins(
        &mut self,
        configs: Vec<PluginSecretConfig>,
    ) -> Result<(), String> {
        if self.state.is_some() {
            return Err("plugin runtime configuration is immutable while unsealed".into());
        }
        self.plugins = plugin::admit_secret_plugins(configs)?;
        Ok(())
    }

    /// Install an optional mandatory HTTPS audit collector before unseal.
    /// The URL must already be inside the deployment-owned outbound allowlist.
    /// Runtime API input can observe this device but cannot widen or replace it.
    pub fn install_audit_http_endpoint(&mut self, url: Option<String>) -> Result<(), String> {
        if self.state.is_some() {
            return Err("audit HTTP policy is immutable while unsealed".into());
        }
        if let Some(value) = url.as_deref() {
            let (_, target) = self
                .outbound
                .endpoint(value, "https")
                .map_err(str::to_owned)?;
            if target.path == "/" {
                return Err("audit HTTP endpoint requires an enrolled non-root path".into());
            }
        }
        self.audit_http_url = url;
        Ok(())
    }

    /// Install an optional deployment-owned TCP audit device before unseal.
    /// The mandatory local file device remains authoritative, so bounded socket
    /// delivery failure is observable but cannot erase or block the local record.
    pub fn install_audit_socket(
        &mut self,
        config: Option<AuditSocketConfig>,
    ) -> Result<(), String> {
        if self.state.is_some() {
            return Err("audit socket policy is immutable while unsealed".into());
        }
        self.audit_socket = config.map(AuditSocketConfig::validate).transpose()?;
        self.audit_socket_failures = 0;
        Ok(())
    }

    /// Install an optional local Unix syslog audit device before unseal.
    /// The destination defaults to the host's local /dev/log agent and is never
    /// mutable through the HTTP API. The mandatory authenticated file sink stays
    /// authoritative if the local syslog agent is unavailable.
    pub fn install_audit_syslog(
        &mut self,
        config: Option<AuditSyslogConfig>,
    ) -> Result<(), String> {
        if self.state.is_some() {
            return Err("audit syslog policy is immutable while unsealed".into());
        }
        self.audit_syslog = config.map(AuditSyslogConfig::validate).transpose()?;
        self.audit_syslog_failures = 0;
        Ok(())
    }

    /// The TLS private key and audit file belong outside the exclusively owned
    /// data directory. The directory is never initialized implicitly on serve.
    pub fn new(data_dir: PathBuf, audit_path: &Path) -> Result<Self, &'static str> {
        Self::new_inner(data_dir, audit_path, None, AuditConfig::default())
    }

    pub fn new_with_ha(
        data_dir: PathBuf,
        audit_path: &Path,
        ha: Arc<Mutex<HaProcess>>,
    ) -> Result<Self, &'static str> {
        Self::new_inner(data_dir, audit_path, Some(ha), AuditConfig::default())
    }

    pub fn new_with_audit_config(
        data_dir: PathBuf,
        audit_path: &Path,
        audit_config: AuditConfig,
    ) -> Result<Self, &'static str> {
        Self::new_inner(data_dir, audit_path, None, audit_config)
    }

    pub fn new_with_ha_audit_config(
        data_dir: PathBuf,
        audit_path: &Path,
        ha: Arc<Mutex<HaProcess>>,
        audit_config: AuditConfig,
    ) -> Result<Self, &'static str> {
        Self::new_inner(data_dir, audit_path, Some(ha), audit_config)
    }

    fn new_inner(
        data_dir: PathBuf,
        audit_path: &Path,
        ha: Option<Arc<Mutex<HaProcess>>>,
        audit_config: AuditConfig,
    ) -> Result<Self, &'static str> {
        if !data_dir.is_absolute() || !audit_path.is_absolute() || audit_path.starts_with(&data_dir)
        {
            return Err("data and audit paths must be absolute and separate");
        }
        // Historical audit-key escrow could expose the single-key seal to an
        // audit-directory reader. Never silently treat it as the new protocol.
        for suffix in [".init-escrow", ".init-escrow.next"] {
            let mut legacy = audit_path.as_os_str().to_os_string();
            legacy.push(suffix);
            if path_present(Path::new(&legacy))? {
                return Err("legacy initialization escrow requires explicit offline migration");
            }
        }
        if ha.is_some() && initialization_recovery_pending(&data_dir)? {
            return Err("acknowledge initialization recovery before enabling HA");
        }
        let (mut audit_rotation, mut audit) = AuditRotation::open(audit_path, audit_config)
            .map_err(|_| "cannot safely open audit rotation files")?;
        let audit_key = load_audit_key(&audit_rotation.active_path(), &audit)?;
        let (audit_sequence, audit_previous) = audit_rotation
            .recover(&mut audit, &audit_key)
            .map_err(|_| "audit verification or rotation recovery failed")?;
        let seal = load_seal_metadata(&data_dir)?;
        let pending_rekey = load_pending_rekey(&data_dir, seal.as_ref())?;
        let rekey = pending_rekey.map(|pending| RekeyState {
            nonce: pending.nonce.clone(),
            new_shares: pending.candidate.secret_shares,
            new_threshold: pending.candidate.secret_threshold,
            require_verification: true,
            provided: BTreeMap::new(),
            verification: Some(pending),
            verification_provided: BTreeMap::new(),
        });
        let unseal_nonce = hex(&crypto::random::<16>()?);
        Ok(Self {
            outbound: crate::outbound::Outbound::default(),
            database_cursor: None,
            pending_database_effect: None,
            pending_database_config_effect: None,
            pending_database_batch_effect: None,
            pending_online_auth_effect: None,
            pending_plugin_auth: None,
            pending_plugin_read: None,
            pending_kubernetes_token: None,
            auth_plugins: BTreeMap::new(),
            plugins: BTreeMap::new(),
            raft_stabilization: raft_admin::Stabilization::default(),
            data_dir,
            audit,
            audit_rotation,
            audit_key,
            audit_sequence,
            audit_previous,
            audit_failed: false,
            audit_http_url: None,
            audit_socket: None,
            audit_socket_failures: 0,
            audit_syslog: None,
            audit_syslog_failures: 0,
            durable: None,
            state: None,
            state_digest: None,
            kv_read_only_dispatches: 0,
            seal,
            unseal_shares: BTreeMap::new(),
            unseal_nonce,
            barrier_key: None,
            rekey,
            recovery_required: false,
            ha,
            #[cfg(test)]
            state_capacity: MAX_STATE_BYTES,
            #[cfg(test)]
            audit_capacity: MAX_AUDIT_BYTES,
        })
    }

    pub fn handle(
        &mut self,
        method: &str,
        path: &str,
        namespace: &str,
        token: &str,
        body: Value,
    ) -> Response {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.handle_at(method, path, namespace, token, body, now)
    }

    pub(crate) fn handle_wire_rejection(
        &mut self,
        attempt_id: &[u8; 16],
        rejection: WireRejection,
        status: u16,
        message: &'static str,
    ) -> Response {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let fingerprint = self.wire_rejection_fingerprint(attempt_id, rejection, status);
        if self
            .audit_event("wire-rejection", &fingerprint, now, None)
            .is_err()
        {
            return Response::error(503, "wire rejection audit unavailable");
        }
        let response = Response::error(status, message);
        if self
            .audit_event("wire-response", &fingerprint, now, Some(status))
            .is_err()
        {
            self.recovery_required = true;
            return Response::error(503, "wire rejection response audit unavailable");
        }
        response
    }

    pub fn handle_at(
        &mut self,
        method: &str,
        path: &str,
        namespace: &str,
        token: &str,
        body: Value,
        now: u64,
    ) -> Response {
        self.handle_request_at(
            ServiceRequest {
                method,
                path,
                namespace,
                token,
                body,
                wrap_ttl_seconds: None,
            },
            now,
        )
    }

    pub fn handle_request(&mut self, request: ServiceRequest<'_>) -> Response {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.handle_request_at(request, now)
    }

    pub fn handle_request_at(&mut self, request: ServiceRequest<'_>, now: u64) -> Response {
        let ServiceRequest {
            method,
            path,
            namespace,
            token,
            body,
            wrap_ttl_seconds,
        } = request;
        self.handle_at_mode(RequestDispatch {
            method,
            path,
            namespace,
            token,
            body,
            now,
            allow_forward: true,
            wrap_ttl_seconds,
        })
    }

    /// Start a network request while holding the Service writer. A database
    /// provider effect may be returned as an owned external plan after its
    /// intent has been durably committed.
    pub(crate) fn begin_request(&mut self, request: ServiceRequest<'_>) -> RequestExecution {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let ServiceRequest {
            method,
            path,
            namespace,
            token,
            body,
            wrap_ttl_seconds,
        } = request;
        self.begin_at_mode(RequestDispatch {
            method,
            path,
            namespace,
            token,
            body,
            now,
            allow_forward: true,
            wrap_ttl_seconds,
        })
    }

    pub(crate) fn begin_forwarded(&mut self, request: ServiceRequest<'_>) -> RequestExecution {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let ServiceRequest {
            method,
            path,
            namespace,
            token,
            body,
            wrap_ttl_seconds,
        } = request;
        self.begin_at_mode(RequestDispatch {
            method,
            path,
            namespace,
            token,
            body,
            now,
            allow_forward: false,
            wrap_ttl_seconds,
        })
    }

    fn handle_at_mode(&mut self, request: RequestDispatch<'_>) -> Response {
        match self.begin_at_mode(request) {
            RequestExecution::Complete(response) => response,
            RequestExecution::External(pending) => {
                let provider_result = pending.execute();
                self.finish_external_request(*pending, provider_result)
            }
        }
    }

    pub(crate) fn finish_external_request(
        &mut self,
        pending: PendingExternalRequest,
        result: ExternalEffectResult,
    ) -> Response {
        let response = match (pending.effect, result) {
            (ExternalEffectPlan::Database(plan), ExternalEffectResult::Database(result)) => {
                self.finalize_database_effect(&plan, result)
            }
            (
                ExternalEffectPlan::DatabaseConfig(plan),
                ExternalEffectResult::DatabaseConfig(result),
            ) => self.finalize_database_config(plan, result),
            (
                ExternalEffectPlan::DatabaseBatch(plan),
                ExternalEffectResult::DatabaseBatch(result),
            ) => self.finalize_database_batch_effect(&plan, result),
            (ExternalEffectPlan::OnlineAuth(plan), ExternalEffectResult::OnlineAuth(result)) => {
                self.finalize_online_auth_effect(plan, result)
            }
            (ExternalEffectPlan::PluginAuth(plan), ExternalEffectResult::PluginAuth(result)) => {
                self.finalize_plugin_auth(plan, result)
            }
            (ExternalEffectPlan::PluginRead(plan), ExternalEffectResult::PluginRead(result)) => {
                self.finalize_plugin_read(&plan, result)
            }
            (
                ExternalEffectPlan::KubernetesToken(plan),
                ExternalEffectResult::KubernetesToken(result),
            ) => self.finalize_kubernetes_token(&plan, result),
            _ => {
                self.recovery_required = true;
                Response::error(503, "external request observation type mismatch")
            }
        };
        self.audit_completed_response(&pending.fingerprint, pending.now, response)
    }

    fn audit_completed_response(
        &mut self,
        fingerprint: &str,
        now: u64,
        response: Response,
    ) -> Response {
        if self
            .audit_event("response", fingerprint, now, Some(response.status))
            .is_err()
        {
            self.recovery_required = true;
            return Response::error(
                503,
                "response audit failed; outcome unknown; authoritative recovery required",
            );
        }
        response
    }

    fn begin_at_mode(&mut self, request: RequestDispatch<'_>) -> RequestExecution {
        let RequestDispatch {
            method,
            path,
            namespace,
            token,
            mut body,
            now,
            allow_forward,
            wrap_ttl_seconds,
        } = request;
        if self.pending_database_effect.is_some()
            || self.pending_database_config_effect.is_some()
            || self.pending_database_batch_effect.is_some()
            || self.pending_online_auth_effect.is_some()
            || self.pending_plugin_auth.is_some()
            || self.pending_plugin_read.is_some()
            || self.pending_kubernetes_token.is_some()
        {
            erase_json(&mut body);
            return RequestExecution::Complete(Response::error(
                503,
                "external request dispatch state is unavailable",
            ));
        }
        let mut fingerprint = self.request_fingerprint(method, path, namespace, token);
        if let Some(ttl) = wrap_ttl_seconds {
            let mut context = hmac::Context::with_key(&self.audit_key);
            context.update(b"heptabao.audit.wrapping-request.v1");
            context.update(fingerprint.as_bytes());
            context.update(&ttl.to_le_bytes());
            fingerprint = STANDARD.encode(context.sign().as_ref());
        }
        if self
            .audit_event("request", &fingerprint, now, None)
            .is_err()
        {
            erase_json(&mut body);
            return RequestExecution::Complete(Response::error(
                503,
                "audit unavailable before entry",
            ));
        }
        if let Some(ttl) = wrap_ttl_seconds {
            let validation = if ttl == 0 || ttl > 32 * 24 * 3600 {
                Some((400, "wrapping TTL is outside the bounded service profile"))
            } else if matches!(
                path,
                "sys/health"
                    | "sys/leader"
                    | "sys/init"
                    | "sys/unseal"
                    | "sys/seal"
                    | "sys/seal-status"
                    | "sys/init/ack"
            ) || path.starts_with("sys/rekey/")
                || path.starts_with("sys/storage/")
                || path.starts_with("sys/internal/recovery/")
                || path == "sys/internal/capacity"
                || matches!(method, "HEAD" | "DELETE")
            {
                Some((
                    501,
                    "response wrapping is not implemented on this service boundary",
                ))
            } else {
                None
            };
            if let Some((status, message)) = validation {
                erase_json(&mut body);
                let response = Response::error(status, message);
                if self
                    .audit_event("response", &fingerprint, now, Some(status))
                    .is_err()
                {
                    self.recovery_required = true;
                    return RequestExecution::Complete(Response::error(
                        503,
                        "wrapping rejection audit unavailable",
                    ));
                }
                return RequestExecution::Complete(response);
            }
        }
        if path == "sys/init" && matches!(method, "PUT" | "POST") {
            let (response, response_audited) =
                if !valid_path(path) || !valid_namespace(namespace) || !namespace.is_empty() {
                    (
                        Response::error(400, "initialization requires the root namespace"),
                        false,
                    )
                } else {
                    self.initialize(&body, now, &fingerprint)
                };
            erase_json(&mut body);
            if !response_audited
                && self
                    .audit_event("response", &fingerprint, now, Some(response.status))
                    .is_err()
            {
                self.recovery_required = self.initialized();
                return RequestExecution::Complete(Response::error(
                    503,
                    "initialization response audit unavailable",
                ));
            }
            return RequestExecution::Complete(response);
        }
        let response = self.handle_inner(RequestView {
            method,
            path,
            namespace,
            token,
            body: &body,
            now,
            allow_forward,
            wrap_ttl_seconds,
        });
        erase_json(&mut body);
        let database = self.pending_database_effect.take();
        let database_config = self.pending_database_config_effect.take();
        let database_batch = self.pending_database_batch_effect.take();
        let online_auth = self.pending_online_auth_effect.take();
        let plugin_auth = self.pending_plugin_auth.take();
        let plugin_read = self.pending_plugin_read.take();
        let kubernetes_token = self.pending_kubernetes_token.take();
        let staged = usize::from(database.is_some())
            + usize::from(database_config.is_some())
            + usize::from(database_batch.is_some())
            + usize::from(online_auth.is_some())
            + usize::from(plugin_auth.is_some())
            + usize::from(plugin_read.is_some())
            + usize::from(kubernetes_token.is_some());
        if staged > 1 {
            self.recovery_required = true;
            return RequestExecution::Complete(self.audit_completed_response(
                &fingerprint,
                now,
                Response::error(503, "multiple external effects staged for one request"),
            ));
        }
        let effect = database
            .map(ExternalEffectPlan::Database)
            .or_else(|| database_config.map(ExternalEffectPlan::DatabaseConfig))
            .or_else(|| database_batch.map(ExternalEffectPlan::DatabaseBatch))
            .or_else(|| online_auth.map(ExternalEffectPlan::OnlineAuth))
            .or_else(|| plugin_auth.map(ExternalEffectPlan::PluginAuth))
            .or_else(|| plugin_read.map(ExternalEffectPlan::PluginRead))
            .or_else(|| kubernetes_token.map(ExternalEffectPlan::KubernetesToken));
        if let Some(effect) = effect {
            return RequestExecution::External(Box::new(PendingExternalRequest {
                fingerprint,
                now,
                effect,
            }));
        }
        RequestExecution::Complete(self.audit_completed_response(&fingerprint, now, response))
    }

    fn handle_inner(&mut self, request: RequestView<'_>) -> Response {
        let RequestView {
            method,
            path,
            namespace,
            token,
            body,
            now,
            allow_forward,
            wrap_ttl_seconds,
        } = request;
        if !valid_namespace(namespace) || !valid_path(path) {
            return Response::error(400, "invalid canonical namespace or path");
        }
        if path == "sys/health" && matches!(method, "GET" | "HEAD") {
            let initialized = self.initialized();
            let sealed = self.state.is_none();
            let (ha_enabled, standby, ha_active, _, _) = self.ha_observation();
            let status = health_status(
                initialized,
                sealed,
                self.recovery_required,
                ha_enabled,
                standby,
                ha_active,
            );
            return Response {
                status,
                body: json!({"initialized":initialized,"sealed":sealed,"standby":standby,"performance_standby":false,"replication_performance_mode":if ha_enabled {"enabled"} else {"disabled"},"replication_dr_mode":"disabled","server_time_utc":now,"version":"HeptaBao-0.2.0","cluster_name":if ha_enabled {"heptabao-ha"} else {"heptabao-single-node"},"cluster_id":self.state.as_ref().map(|s|s.cluster_id.as_str()),"ha_enabled":ha_enabled,"ha_active":ha_active,"recovery_required":self.recovery_required}),
            };
        }
        if path == "sys/init" && method == "GET" {
            return Response::ok(json!({"initialized":self.initialized()}));
        }
        if path == "sys/seal-status" && method == "GET" {
            return self.seal_status();
        }
        if path == "sys/unseal" && matches!(method, "PUT" | "POST") {
            return self.unseal(body);
        }
        if self.state.is_none() {
            return Response::error(503, "server is sealed");
        }
        if let Some(ha) = self.ha.as_ref().cloned() {
            let (leader, local) = match ha.lock() {
                Ok(ha) => {
                    let leader = match ha.leader() {
                        Ok(value) => value,
                        Err(_) => return Response::error(503, "HA leader state is unavailable"),
                    };
                    let local = match ha.local_id() {
                        Ok(value) => value,
                        Err(_) => return Response::error(503, "HA local identity is unavailable"),
                    };
                    (leader, local)
                }
                Err(_) => return Response::error(503, "HA process lock is unavailable"),
            };
            if leader != Some(local) {
                let Some(_) = leader else {
                    return Response::error(503, "HA cluster has no elected leader");
                };
                if !allow_forward {
                    return Response::error(503, "forwarded request reached a standby node");
                }
                return match ha.lock() {
                    Ok(ha) => ha
                        .forward_request(method, path, namespace, token, body, wrap_ttl_seconds)
                        .unwrap_or_else(|_| Response::error(503, "HA leader forwarding failed")),
                    Err(_) => Response::error(503, "HA process lock is unavailable"),
                };
            }
            if let Err(error) = self.sync_from_ha() {
                return error;
            }
        }
        if self.recovery_required {
            return Response::error(
                503,
                "authoritative recovery required; unseal with the stored key before retry",
            );
        }

        if let Some(response) = self.immutable_kv_response(&request) {
            self.kv_read_only_dispatches = self.kv_read_only_dispatches.saturating_add(1);
            return response;
        }

        let Some(mut admitted) = self.state.clone() else {
            return Response::error(503, "server is sealed");
        };
        // A trusted wall-clock observation is persisted before a wrapping
        // token can be rejected/consumed. Observed expiry cannot be undone by
        // a later clock rollback, process restart, or HA leader change.
        if Self::reconcile_lease_owners(&mut admitted, now) {
            admitted.schema = CURRENT_STATE_SCHEMA;
            if let Err(error) = self.commit_state(&admitted) {
                return error;
            }
            self.state = Some(admitted.clone());
        }
        let public_otp_verify = admitted
            .engines
            .is_ssh_verification(namespace, method, path);
        if (wrap_ttl_seconds.is_some()
            || path.starts_with("sys/wrapping/")
            || admitted.auth.is_wrapping_token(token))
            && admitted.auth.advance_wrapping_clock(now)
        {
            admitted.schema = CURRENT_STATE_SCHEMA;
            if let Err(error) = self.commit_state(&admitted) {
                return error;
            }
            self.state = Some(admitted.clone());
        }
        // OpenBao reports an invalid self-unwrapping capability as a wrapping
        // request error, not a generic login failure. Validate its type/scope
        // without consuming it; actual admission below still consumes exactly once.
        if path == "sys/wrapping/unwrap"
            && body.get("token").is_none()
            && let Err(error) =
                admitted
                    .auth
                    .lookup_wrapping_request(token, namespace, "POST", &json!({}), now)
        {
            return Response::error(error.status, &error.message);
        }
        let public_login = admitted.auth.is_public_login(namespace, method, path);
        let mut principal = if token.is_empty()
            || path == "sys/wrapping/lookup"
            || public_otp_verify
            || public_login
        {
            None
        } else {
            match admitted.auth.authenticate(token, now) {
                Ok(principal) => Some(principal),
                Err(error) => return Response::error(error.status, &error.message),
            }
        };
        if principal.as_ref().is_some_and(Principal::consumed_use) {
            admitted.schema = CURRENT_STATE_SCHEMA;
            if let Err(error) = self.commit_state(&admitted) {
                return error;
            }
            self.state = Some(admitted.clone());
        }
        if let Some(principal) = principal.as_mut()
            && let Err(error) = Self::bind_identity_principal(&admitted, principal, namespace)
        {
            return error;
        }
        if namespaces::owns(path) {
            return self.namespace_route(admitted, principal.as_ref(), &request);
        }
        if path == "sys/audit"
            || path.starts_with("sys/audit/")
            || path == "sys/internal/audit/file"
        {
            let Some(principal) = principal.as_ref() else {
                return Response::error(403, "missing client token");
            };
            return self.audit_route(principal, namespace, method, path, body);
        }
        if Self::is_raft_admin_path(path) {
            return self.raft_admin_route(admitted, principal.as_ref(), &request);
        }
        if Self::plugin_catalog_handles(path) {
            return self.plugin_catalog_route(&admitted, principal.as_ref(), &request);
        }
        if matches!(method, "POST" | "PUT")
            && path.starts_with("sys/mounts/")
            && body.get("type").and_then(Value::as_str) == Some("plugin")
        {
            let Some(plugin_principal) = principal.as_ref() else {
                return Response::error(403, "missing client token");
            };
            if let Err(error) =
                admitted
                    .auth
                    .authorize_request(plugin_principal, namespace, path, "sudo", now)
            {
                return Response::error(error.status, &error.message);
            }
            if let Err(error) =
                admitted
                    .auth
                    .authorize_request(plugin_principal, namespace, path, "update", now)
            {
                return Response::error(error.status, &error.message);
            }
            if let Err(error) = self.validate_plugin_mount_request(method, path, body) {
                return error;
            }
        }
        if self.database_handles(&admitted, namespace, path, body) {
            return self.database_route(admitted, principal.as_ref(), &request);
        }
        if Self::kubernetes_secret_handles(&admitted, namespace, path) {
            return self.kubernetes_secret_route(admitted, principal.as_ref(), &request);
        }
        if self.plugin_secret_handles(&admitted, namespace, path) {
            return self.plugin_secret_route(admitted, principal.as_ref(), &request);
        }
        if path == "sys/leader" && method == "GET" {
            let Some(principal) = principal.as_ref() else {
                return Response::error(403, "missing client token");
            };
            if let Err(error) = admitted
                .auth
                .authorize_request(principal, namespace, path, "read", now)
            {
                return Response::error(error.status, &error.message);
            }
            return self.leader_response();
        }
        if path == "sys/step-down" {
            if !matches!(method, "POST" | "PUT") {
                return Response::error(405, "step-down requires POST or PUT");
            }
            if body.as_object().is_none_or(|object| !object.is_empty()) {
                return Response::error(400, "step-down accepts an empty JSON object");
            }
            let Some(principal) = principal.as_ref() else {
                return Response::error(403, "missing client token");
            };
            if let Err(error) = admitted
                .auth
                .authorize_sudo_request(principal, namespace, path, "update", now)
            {
                return Response::error(error.status, &error.message);
            }
            let Some(ha) = self.ha.as_ref() else {
                return Response::error(400, "HA is not enabled");
            };
            return match ha.lock() {
                Ok(ha) => match ha.step_down() {
                    Ok(_) => Response {
                        status: 204,
                        body: Value::Null,
                    },
                    Err(_) => Response::error(503, "HA leadership transfer failed"),
                },
                Err(_) => Response::error(503, "HA process lock is unavailable"),
            };
        }
        if path == "sys/init/ack" {
            if !namespace.is_empty() || !principal.as_ref().is_some_and(Principal::is_root) {
                return Response::error(403, "permission denied");
            }
            return self.ack_initialization(method, body);
        }
        if matches!(path, "sys/rekey/init" | "sys/rekey/update") {
            if !principal.as_ref().is_some_and(Principal::is_root) {
                return Response::error(403, "permission denied");
            }
            return self.rekey_route(method, path, body);
        }
        if path == "sys/internal/storage/capacity" {
            if !namespace.is_empty() || !principal.as_ref().is_some_and(Principal::is_root) {
                return Response::error(403, "permission denied");
            }
            return self.capacity_route(method, body);
        }
        if path == "sys/internal/capacity" {
            if !namespace.is_empty() || !principal.as_ref().is_some_and(Principal::is_root) {
                return Response::error(403, "permission denied");
            }
            return self.capacity_response(method, body);
        }
        if path.starts_with("sys/internal/recovery/")
            || matches!(
                path,
                "sys/storage/raft/compact"
                    | "sys/storage/raft/replay-retire"
                    | "sys/storage/raft/snapshot"
                    | "sys/storage/raft/snapshot-force"
            )
        {
            if !principal.as_ref().is_some_and(Principal::is_root) {
                return Response::error(403, "permission denied");
            }
            return self.maintenance_route(method, path, body);
        }
        if path == "sys/seal" && matches!(method, "PUT" | "POST") {
            if !principal.as_ref().is_some_and(Principal::is_root) {
                return Response::error(403, "permission denied");
            }
            self.state = None;
            self.durable = None;
            self.barrier_key = None;
            self.unseal_shares.clear();
            let discard_rekey = self
                .rekey
                .as_ref()
                .is_some_and(|rekey| rekey.verification.is_none());
            if let Some(rekey) = self.rekey.as_mut() {
                rekey.provided.clear();
                rekey.verification_provided.clear();
            }
            if discard_rekey {
                self.rekey = None;
            }
            if self.rotate_unseal_nonce().is_err() {
                return Response::error(503, "operating system randomness unavailable");
            }
            return Response {
                status: 204,
                body: Value::Null,
            };
        }
        if let Some(response) = self.plugin_auth_login(&admitted, &request) {
            return response;
        }
        if let Some(response) = self.online_login(&admitted, &request) {
            return response;
        }
        let before_digest = match self.current_state_digest() {
            Ok(value) => value,
            Err(error) => return error,
        };
        // Response wrapping is the only normal dispatch path that needs an
        // in-memory rollback snapshot after the domain handler succeeds. Avoid
        // cloning the complete State for every ordinary request: move the
        // admitted candidate into dispatch and retain a rollback copy only when
        // wrapping was explicitly requested.
        let wrapping_rollback = wrap_ttl_seconds.map(|_| admitted.clone());
        let mut transaction = admitted;
        if let Err(error) =
            transaction
                .auth
                .refresh_remote_jwt(namespace, path, method, &self.outbound, false)
        {
            return Response::error(error.status, &error.message);
        }
        let mut response = if path == "sys/wrapping/lookup" {
            match transaction
                .auth
                .lookup_wrapping_request(token, namespace, method, body, now)
            {
                Ok(value) => Response {
                    status: value.status,
                    body: value.body,
                },
                Err(error) => Response::error(error.status, &error.message),
            }
        } else if path == "sys/wrapping/wrap" && wrap_ttl_seconds.is_none() {
            Response::error(400, "endpoint requires response wrapping to be used")
        } else {
            Self::dispatch(
                &mut transaction,
                principal,
                namespace,
                method,
                path,
                body,
                now,
            )
        };
        if response.status < 300
            && let Err(error) =
                transaction
                    .auth
                    .refresh_remote_jwt(namespace, path, method, &self.outbound, true)
        {
            return Response::error(error.status, &error.message);
        }
        if response.status < 300
            && matches!(method, "POST" | "PUT")
            && let Err(error) =
                transaction
                    .auth
                    .check_online_enrollment(namespace, path, &self.outbound)
        {
            return Response::error(error.status, &error.message);
        }
        // The durable AuthState stores only token digests. After successful
        // token renewal, echo only the exact credential already supplied on
        // this authorized request. Do this before optional response wrapping;
        // no bearer is reconstructed from an accessor or stored in plaintext.
        if response.status == 200 && matches!(path, "auth/token/renew-self" | "auth/token/renew") {
            let renewed = if path == "auth/token/renew-self" {
                Some(token)
            } else {
                body.get("token").and_then(Value::as_str)
            };
            if let (Some(renewed), Some(auth)) = (
                renewed,
                response.body.get_mut("auth").and_then(Value::as_object_mut),
            ) {
                auth.insert("client_token".into(), json!(renewed));
            }
        }
        if let Some(ttl) = wrap_ttl_seconds
            && (200..300).contains(&response.status)
            && response.status != 204
            && !response.body.is_null()
            && response.body.get("wrap_info").is_none_or(Value::is_null)
        {
            match transaction
                .auth
                .wrap_response(namespace, path, ttl, &response.body, now)
            {
                Ok(wrapped) => {
                    response = Response {
                        status: wrapped.status,
                        body: wrapped.body,
                    };
                    admitted = transaction;
                }
                // Wrapping publication failure rolls back the domain operation;
                // the earlier finite-use token admission deliberately stays consumed.
                Err(error) => {
                    response = Response::error(error.status, &error.message);
                    let Some(rollback) = wrapping_rollback else {
                        return Response::error(500, "wrapping rollback state is unavailable");
                    };
                    admitted = rollback;
                }
            }
        } else {
            admitted = transaction;
        }
        let mut serialized = match serde_json::to_vec(&admitted) {
            Ok(v) => Zeroizing::new(v),
            Err(_) => return Response::error(500, "state serialization failed"),
        };
        let mut serialized_digest = crypto::digest(&serialized);
        match classify_request_effect(method, before_digest, serialized_digest) {
            RequestEffectClass::PureRead => {}
            RequestEffectClass::DurableMutation | RequestEffectClass::SideEffectingRead => {
                if admitted.schema != CURRENT_STATE_SCHEMA {
                    admitted.schema = CURRENT_STATE_SCHEMA;
                    serialized = match serde_json::to_vec(&admitted) {
                        Ok(value) => Zeroizing::new(value),
                        Err(_) => return Response::error(500, "state serialization failed"),
                    };
                    serialized_digest = crypto::digest(&serialized);
                }
                if let Err(error) = admitted.validate_format() {
                    return error;
                }
                if let Err(error) = self.commit_state_bytes(
                    &admitted,
                    &serialized,
                    admitted.schema,
                    admitted.replay_epoch,
                    serialized_digest,
                ) {
                    return error;
                }
                self.state = Some(admitted);
            }
        }
        response
    }

    fn immutable_kv_response(&self, request: &RequestView<'_>) -> Option<Response> {
        let state = self.state.as_ref()?;
        if request.wrap_ttl_seconds.is_some()
            || state.engines.has_live_leases()
            || state.auth.is_wrapping_token(request.token)
            || !state
                .engines
                .is_immutable_kv_read(request.namespace, request.method, request.path)
        {
            return None;
        }
        if request.token.is_empty() {
            return Some(Response::error(403, "missing client token"));
        }
        let mut principal = match state
            .auth
            .authenticate_read_only(request.token, request.now)
        {
            Ok(Some(principal)) => principal,
            Ok(None) => return None,
            Err(error) => return Some(Response::error(error.status, &error.message)),
        };
        if let Err(error) = Self::bind_identity_principal(state, &mut principal, request.namespace)
        {
            return Some(error);
        }
        // Direct Service callers must authorize the same operation as the HTTP
        // parser: GET+list is a LIST, never a read-only-policy enumeration bypass.
        let method = kv_authorization_method(request.method, request.body);
        let capability =
            state
                .engines
                .required_capability(request.namespace, method, request.path)?;
        if let Err(error) = state.auth.authorize_request(
            &principal,
            request.namespace,
            request.path,
            capability,
            request.now,
        ) {
            return Some(Response::error(error.status, &error.message));
        }
        Some(
            match state.engines.handle_immutable_kv_read(
                request.namespace,
                request.method,
                request.path,
                request.body,
                request.now,
            ) {
                Ok(mut response) => Response {
                    status: response.status,
                    body: std::mem::take(&mut response.body),
                },
                Err(error) => Response::error(error.status, &error.message),
            },
        )
    }

    fn dispatch(
        state: &mut State,
        principal: Option<Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Response {
        let principal = principal.as_ref();
        if path == "sys/remount" {
            if !matches!(method, "POST" | "PUT") {
                return Response::error(405, "remount requires POST or PUT");
            }
            let Some(principal) = principal else {
                return Response::error(403, "missing client token");
            };
            if let Err(error) = state
                .auth
                .authorize_sudo_request(principal, namespace, path, "update", now)
            {
                return Response::error(error.status, &error.message);
            }
            let Some(object) = body.as_object() else {
                return Response::error(400, "remount requires a JSON object");
            };
            if object
                .keys()
                .any(|key| !matches!(key.as_str(), "from" | "to" | "cas_revision"))
            {
                return Response::error(400, "unsupported remount parameter");
            }
            let Some(from) = object.get("from").and_then(Value::as_str) else {
                return Response::error(400, "remount from is required");
            };
            let Some(to) = object.get("to").and_then(Value::as_str) else {
                return Response::error(400, "remount to is required");
            };
            if from.starts_with('/') || to.starts_with('/') {
                return Response::error(
                    400,
                    "remount paths must be relative to the request namespace",
                );
            }
            let cas_revision = match object.get("cas_revision") {
                Some(value) => match value.as_u64() {
                    Some(value) => Some(value),
                    None => {
                        return Response::error(400, "cas_revision must be a nonnegative integer");
                    }
                },
                None => None,
            };
            let from = from.trim_end_matches('/');
            let to = to.trim_end_matches('/');
            match (from.strip_prefix("auth/"), to.strip_prefix("auth/")) {
                (Some(from), Some(to)) => {
                    return match state.auth.remount_mount(namespace, from, to, cas_revision) {
                        Ok(response) => Response {
                            status: response.status,
                            body: response.body,
                        },
                        Err(error) => Response::error(error.status, &error.message),
                    };
                }
                (None, None) => {
                    if from.starts_with("sys/")
                        || to.starts_with("sys/")
                        || from.starts_with("identity/")
                        || to.starts_with("identity/")
                        || from.starts_with("cubbyhole/")
                        || to.starts_with("cubbyhole/")
                    {
                        return Response::error(
                            400,
                            "remount cannot relocate reserved system paths",
                        );
                    }
                    return match state.engines.remount(namespace, from, to, cas_revision) {
                        Ok(mut response) => Response {
                            status: response.status,
                            body: std::mem::take(&mut response.body),
                        },
                        Err(error) => Response::error(error.status, &error.message),
                    };
                }
                _ => {
                    return Response::error(
                        400,
                        "remount cannot change between auth and secret mount classes",
                    );
                }
            }
        }
        if state.engines.is_lease_service_route(namespace, path) || path.starts_with("sys/leases/")
        {
            return Self::lease_route(state, principal, namespace, method, path, body, now);
        }
        if matches!(
            path,
            "sys/capabilities" | "sys/capabilities-self" | "sys/capabilities-accessor"
        ) {
            return Self::capabilities_route(state, principal, namespace, method, path, body, now);
        }
        let mut auth = state.auth.clone();
        match auth.handle(principal, namespace, method, path, body, now) {
            Ok(Some(mut response)) => {
                let mut engines = state.engines.clone();
                if !path.starts_with("sys/wrapping/")
                    && let Err(error) = Self::finish_identity_response(
                        &mut auth,
                        &mut engines,
                        &mut response,
                        namespace,
                        now,
                    )
                {
                    erase_json(&mut response.body);
                    return error;
                }
                if response.mutated {
                    state.auth = auth;
                    state.engines = engines;
                }
                return Response {
                    status: response.status,
                    body: response.body,
                };
            }
            Err(error) => return Response::error(error.status, &error.message),
            Ok(None) => {}
        }
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        if path == "sys/internal/specs/openapi" {
            if let Err(error) = state
                .auth
                .authorize_request(principal, namespace, path, "read", now)
            {
                return Response::error(error.status, &error.message);
            }
            return openapi::handle(method, body, principal.is_root());
        }
        if path == "sys/leader" && method == "GET" {
            return Response::error(500, "leader route escaped service HA boundary");
        }
        if path == "sys/step-down" || path.starts_with("sys/storage/raft") {
            return Response::error(
                501,
                "Raft administrative route is not implemented by this request profile",
            );
        }
        let fallback = match method {
            "GET" | "HEAD" => "read",
            "LIST" => "list",
            "DELETE" => "delete",
            "PATCH" => "patch",
            _ => "update",
        };
        let capability = state
            .engines
            .required_capability(namespace, kv_authorization_method(method, body), path)
            .unwrap_or(fallback);
        if path.starts_with("sys/mounts")
            && !matches!(method, "GET" | "LIST" | "HEAD")
            && let Err(error) = state
                .auth
                .authorize_request(principal, namespace, path, "sudo", now)
        {
            return Response::error(error.status, &error.message);
        }
        if let Err(error) = state
            .auth
            .authorize_request(principal, namespace, path, capability, now)
        {
            return Response::error(error.status, &error.message);
        }
        if matches!(method, "POST" | "PUT" | "PATCH")
            && let Err(error) =
                Self::validate_identity_alias_mount(&state.auth, namespace, path, body)
        {
            return error;
        }
        let mut engines = state.engines.clone();
        match engines.handle(namespace, method, path, body, now) {
            Ok(Some(mut response)) => {
                if response.mutated {
                    state.engines = engines;
                }
                Response {
                    status: response.status,
                    body: std::mem::take(&mut response.body),
                }
            }
            Ok(None) => Response::error(404, "unsupported path"),
            Err(error) => Response::error(error.status, &error.message),
        }
    }

    fn load_owner_bytes(
        durable: &DurableService<AeadBarrier>,
        manifest: &owner_store::OwnerStateManifest,
        owner: &str,
    ) -> Result<Zeroizing<Vec<u8>>, Response> {
        let count = manifest
            .chunk_count(owner)
            .map_err(|_| Response::error(503, "owner-state manifest is invalid"))?;
        let mut values = Vec::with_capacity(count);
        for index in 0..count {
            let resource = manifest
                .chunk_resource(owner, index)
                .map_err(|_| Response::error(503, "owner-state manifest is invalid"))?;
            let chunk = durable
                .get("system", &resource)
                .map_err(|_| Response::error(503, "owner-state chunk is unavailable"))?
                .ok_or_else(|| Response::error(503, "owner-state chunk is absent"))?;
            values.push(chunk);
        }
        let refs = values.iter().map(Secret::expose).collect::<Vec<_>>();
        let bytes = manifest
            .assemble_owner(owner, &refs)
            .map_err(|_| Response::error(503, "owner-state chunk set is invalid"))?;
        Ok(Zeroizing::new(bytes))
    }

    fn load_state_from_durable(
        durable: &DurableService<AeadBarrier>,
    ) -> Result<(State, Zeroizing<Vec<u8>>, bool), Response> {
        let record = durable
            .get("system", "state")
            .map_err(|_| Response::error(503, "server state is unavailable"))?
            .ok_or_else(|| Response::error(503, "server state is absent; recovery required"))?;

        let owner_manifest = owner_store::decode_manifest(record.expose())
            .map_err(|_| Response::error(503, "owner-state manifest is invalid"))?;
        let (mut state, mut bytes, mut needs_rewrite) = if let Some(manifest) = owner_manifest {
            let namespaces = Self::load_owner_bytes(durable, &manifest, "namespaces")?;
            let auth = Self::load_owner_bytes(durable, &manifest, "auth")?;
            let engines = Self::load_owner_bytes(durable, &manifest, "engines")?;
            let database = Self::load_owner_bytes(durable, &manifest, "database")?;
            let raft_admin = Self::load_owner_bytes(durable, &manifest, "raft_admin")?;
            let state = State {
                schema: manifest.state_schema(),
                cluster_id: manifest.cluster_id().to_owned(),
                replay_epoch: manifest.replay_epoch(),
                namespaces: serde_json::from_slice::<namespaces::NamespaceRegistry>(&namespaces)
                    .map(CowOwner::from)
                    .map_err(|_| Response::error(503, "namespace owner state is invalid"))?,
                auth: serde_json::from_slice(&auth)
                    .map_err(|_| Response::error(503, "auth owner state is invalid"))?,
                engines: serde_json::from_slice(&engines)
                    .map_err(|_| Response::error(503, "engine owner state is invalid"))?,
                database: serde_json::from_slice(&database)
                    .map_err(|_| Response::error(503, "database owner state is invalid"))?,
                raft_admin: serde_json::from_slice(&raft_admin)
                    .map_err(|_| Response::error(503, "raft-admin owner state is invalid"))?,
            };
            state.validate_format()?;
            let bytes = Zeroizing::new(
                serde_json::to_vec(&state)
                    .map_err(|_| Response::error(500, "state serialization failed"))?,
            );
            manifest
                .verify_logical(&bytes)
                .map_err(|_| Response::error(503, "owner-state logical digest is invalid"))?;
            (state, bytes, false)
        } else {
            let manifest = state_store::decode_manifest(record.expose())
                .map_err(|_| Response::error(503, "server state manifest is invalid"))?;
            let (bytes, needs_rewrite) = if let Some(manifest) = manifest.as_ref() {
                let mut chunk_values = Vec::with_capacity(manifest.chunk_count());
                for index in 0..manifest.chunk_count() {
                    let resource = manifest
                        .chunk_resource(index)
                        .map_err(|_| Response::error(503, "server state manifest is invalid"))?;
                    let chunk = durable
                        .get("system", &resource)
                        .map_err(|_| Response::error(503, "server state chunk is unavailable"))?
                        .ok_or_else(|| Response::error(503, "server state chunk is absent"))?;
                    chunk_values.push(chunk);
                }
                let chunk_refs = chunk_values.iter().map(Secret::expose).collect::<Vec<_>>();
                let assembled = state_store::assemble_state(manifest, &chunk_refs)
                    .map_err(|_| Response::error(503, "server state chunk set is invalid"))?;
                (Zeroizing::new(assembled), false)
            } else {
                if record.expose().len() > MAX_STATE_BYTES {
                    return Err(Response::error(
                        507,
                        "legacy server state exceeds migration bound",
                    ));
                }
                (Zeroizing::new(record.expose().to_vec()), true)
            };
            let state: State = serde_json::from_slice(&bytes)
                .map_err(|_| Response::error(503, "server state schema is invalid"))?;
            state.validate_format()?;
            if let Some(manifest) = manifest
                && manifest.state_schema() != state.schema
            {
                return Err(Response::error(
                    503,
                    "server state manifest schema binding is inconsistent",
                ));
            }
            (state, bytes, needs_rewrite)
        };

        let durable_epoch = durable.replay_epoch();
        if state.replay_epoch > durable_epoch {
            return Err(Response::error(
                503,
                "server state replay epoch is ahead of durable replay authority",
            ));
        }
        let mut logical_rewrite = false;
        if state.replay_epoch < durable_epoch {
            state.replay_epoch = durable_epoch;
            logical_rewrite = true;
        }
        if state.adopt_legacy_namespaces()? {
            logical_rewrite = true;
        }
        if logical_rewrite {
            state.schema = CURRENT_STATE_SCHEMA;
            state.validate_format()?;
            bytes = Zeroizing::new(
                serde_json::to_vec(&state)
                    .map_err(|_| Response::error(500, "state serialization failed"))?,
            );
            needs_rewrite = true;
        }
        Ok((state, bytes, needs_rewrite))
    }

    fn persist_owner_state_batch(
        durable: &mut DurableService<AeadBarrier>,
        state: &State,
        bytes: &[u8],
        operation_id: &str,
        state_schema: u32,
        target_replay_epoch: u64,
        compact_before_entry: bool,
        allow_epoch_catchup: bool,
        reuse: OwnerReuseHint,
    ) -> Result<MutationOutcome, ServiceError> {
        if bytes.len() > MAX_STATE_BYTES {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        let current_replay_epoch = durable.replay_epoch();
        if target_replay_epoch < current_replay_epoch {
            return Err(ServiceError::ReplayEpochMismatch);
        }
        if target_replay_epoch > current_replay_epoch {
            if !allow_epoch_catchup
                && current_replay_epoch.checked_add(1) != Some(target_replay_epoch)
            {
                return Err(ServiceError::ReplayEpochMismatch);
            }
            while durable.replay_epoch() < target_replay_epoch {
                durable.retire_replay_epoch()?;
            }
        }

        let current = durable.get("system", "state")?;
        let previous_owner = current
            .as_ref()
            .map(|record| owner_store::decode_manifest(record.expose()))
            .transpose()
            .map_err(|_| ServiceError::CorruptState)?
            .flatten();
        let legacy_deletes = if previous_owner.is_none() {
            current
                .as_ref()
                .map(|record| state_store::decode_manifest(record.expose()))
                .transpose()
                .map_err(|_| ServiceError::CorruptState)?
                .flatten()
                .map(|manifest| manifest.unique_chunk_resources())
                .transpose()
                .map_err(|_| ServiceError::CorruptState)?
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        // V4 copy-on-write owners carry their authenticated descriptor/chunks
        // forward directly when the request did not mutate them. This removes a
        // second full-owner serialization/hash/chunk pass after the logical State
        // has already been serialized for the cluster digest.
        let may_reuse = previous_owner.is_some();
        let owners = vec![
            (
                "namespaces",
                if may_reuse && reuse.namespaces {
                    None
                } else {
                    Some(
                        serde_json::to_vec(&state.namespaces)
                            .map_err(|_| ServiceError::CorruptState)?,
                    )
                },
            ),
            (
                "auth",
                if may_reuse && reuse.auth {
                    None
                } else {
                    Some(serde_json::to_vec(&state.auth).map_err(|_| ServiceError::CorruptState)?)
                },
            ),
            (
                "engines",
                if may_reuse && reuse.engines {
                    None
                } else {
                    Some(serde_json::to_vec(&state.engines).map_err(|_| ServiceError::CorruptState)?)
                },
            ),
            (
                "database",
                if may_reuse && reuse.database {
                    None
                } else {
                    Some(serde_json::to_vec(&state.database).map_err(|_| ServiceError::CorruptState)?)
                },
            ),
            (
                "raft_admin",
                if may_reuse && reuse.raft_admin {
                    None
                } else {
                    Some(serde_json::to_vec(&state.raft_admin).map_err(|_| ServiceError::CorruptState)?)
                },
            ),
        ];
        let plan = owner_store::OwnerWritePlan::new_with_reuse(
            bytes,
            operation_id,
            state_schema,
            &state.cluster_id,
            target_replay_epoch,
            owners,
            previous_owner.as_ref(),
            legacy_deletes,
        )
        .map_err(|error| match error {
            owner_store::OwnerStoreError::StateTooLarge => ServiceError::RequestCapacityExhausted,
            _ => ServiceError::CorruptState,
        })?;
        if plan.required_mutations() > heptabao_durable_service::MAX_ATOMIC_MUTATIONS {
            return Err(ServiceError::RequestCapacityExhausted);
        }
        for resource in &plan.required_existing {
            let existing = durable
                .get("system", resource)?
                .ok_or(ServiceError::CorruptState)?;
            owner_store::validate_content_addressed_chunk(resource, existing.expose())
                .map_err(|_| ServiceError::CorruptState)?;
        }

        let mut mutations = Vec::with_capacity(plan.required_mutations());
        for chunk in plan.chunks {
            owner_store::validate_content_addressed_chunk(&chunk.resource, &chunk.bytes)
                .map_err(|_| ServiceError::CorruptState)?;
            mutations.push((chunk.resource, Some(Secret::new(chunk.bytes)?)));
        }
        for resource in plan.deletes {
            mutations.push((resource, None));
        }
        mutations.push(("state".to_owned(), Some(Secret::new(plan.manifest_bytes)?)));

        let replay_epoch = durable.replay_epoch();
        if replay_epoch != target_replay_epoch {
            return Err(ServiceError::ReplayEpochMismatch);
        }
        if compact_before_entry {
            durable.apply_batch_with_compaction_in_replay_epoch(
                replay_epoch,
                "heptabao-server",
                "system",
                operation_id,
                crypto::digest(bytes),
                mutations,
            )
        } else {
            durable.apply_batch_in_replay_epoch(
                replay_epoch,
                "heptabao-server",
                "system",
                operation_id,
                crypto::digest(bytes),
                mutations,
            )
        }
    }

    fn commit_state(&mut self, state: &State) -> Result<(), Response> {
        state.validate_format()?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(state)
                .map_err(|_| Response::error(500, "state serialization failed"))?,
        );
        let next_digest = crypto::digest(&bytes);
        self.commit_state_bytes(state, &bytes, state.schema, state.replay_epoch, next_digest)
    }

    fn commit_state_bytes(
        &mut self,
        state: &State,
        bytes: &[u8],
        state_schema: u32,
        target_replay_epoch: u64,
        next_digest: [u8; 32],
    ) -> Result<(), Response> {
        #[cfg(not(test))]
        let capacity = MAX_STATE_BYTES;
        #[cfg(test)]
        let capacity = self.state_capacity;
        if bytes.len() > capacity {
            return Err(Response::error(507, "state capacity exhausted"));
        }
        let base_digest = self.current_state_digest()?;
        self.persist(state, bytes, base_digest, state_schema, target_replay_epoch)?;
        self.state_digest = Some(next_digest);
        Ok(())
    }

    fn current_state_digest(&self) -> Result<[u8; 32], Response> {
        if self.state.is_none() {
            return Err(Response::error(503, "server is sealed"));
        }
        self.state_digest
            .ok_or_else(|| Response::error(503, "server state digest is unavailable"))
    }

    fn initialized(&self) -> bool {
        self.data_dir.join("state.hbs").exists()
    }

    fn seal_status(&self) -> Response {
        let (seal_type, shares, threshold) = self
            .seal
            .as_ref()
            .map(|seal| {
                (
                    if seal.share_format == "raw-v1" {
                        "shamir-legacy"
                    } else {
                        "shamir"
                    },
                    seal.secret_shares,
                    seal.secret_threshold,
                )
            })
            .unwrap_or(("shamir-legacy", 1, 1));
        let progress = if self.state.is_some() {
            0
        } else {
            u8::try_from(self.unseal_shares.len()).unwrap_or(u8::MAX)
        };
        Response::ok(json!({
            "type": seal_type,
            "initialized": self.initialized(),
            "sealed": self.state.is_none(),
            "t": threshold,
            "n": shares,
            "progress": progress,
            "nonce": if progress == 0 { "" } else { self.unseal_nonce.as_str() },
            "version": "HeptaBao-0.2.0",
            "migration": false,
            "recovery_seal": false,
            "storage_type": if self.ha.is_some() { "heptabao-raft-v1" } else { "heptabao-durable-v2" },
            "seal_generation": self.seal.as_ref().map_or(0, |seal| seal.generation),
        }))
    }

    fn initialize(
        &mut self,
        body: &Value,
        now: u64,
        response_fingerprint: &str,
    ) -> (Response, bool) {
        if self.ha.is_some() {
            return (
                Response::error(
                    409,
                    "initialize and unseal a node before enabling HA; HA initialization requires an existing durable state",
                ),
                false,
            );
        }
        if body.as_object().is_none_or(|object| {
            object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "secret_shares" | "secret_threshold" | "recovery_nonce"
                )
            })
        }) {
            return (
                Response::error(400, "unsupported initialization options"),
                false,
            );
        }
        let shares = match bounded_u8_field(body, "secret_shares", 5) {
            Ok(value) => value,
            Err(message) => return (Response::error(400, message), false),
        };
        let threshold = match bounded_u8_field(body, "secret_threshold", 3) {
            Ok(value) => value,
            Err(message) => return (Response::error(400, message), false),
        };
        if shares == 0 || shares > MAX_SEAL_SHARES || threshold == 0 || threshold > shares {
            return (
                Response::error(
                    400,
                    "secret shares must be 1..=16 and threshold must be within that set",
                ),
                false,
            );
        }
        let recovery_secret = match body.get("recovery_nonce") {
            None => None,
            Some(value) => match decode_initialization_secret(value) {
                Ok(secret) => Some(secret),
                Err(error) => return (Response::error(400, error), false),
            },
        };
        if self.initialized() {
            return (
                match recovery_secret.as_ref() {
                    Some(secret) => self.recover_initialization(secret, shares, threshold),
                    None => Response::error(400, "already initialized"),
                },
                false,
            );
        }

        let seal_key = match crypto::random::<32>() {
            Ok(value) => Zeroizing::new(value),
            Err(error) => return (Response::error(503, error), false),
        };
        let barrier_key = match crypto::random::<32>() {
            Ok(value) => Zeroizing::new(value),
            Err(error) => return (Response::error(503, error), false),
        };
        let generated_shares = match crypto::split_secret(&seal_key, shares, threshold) {
            Ok(value) => value,
            Err(error) => return (Response::error(503, error), false),
        };
        let mut seal = SealMetadata {
            schema: 1,
            generation: 1,
            share_format: "shamir-v1".into(),
            secret_shares: shares,
            secret_threshold: threshold,
            wrapped_barrier_key: String::new(),
        };
        let wrapped =
            match crypto::wrap_barrier_key(&seal_key, &seal.associated_data(), &barrier_key) {
                Ok(value) => Zeroizing::new(value),
                Err(error) => return (Response::error(503, error), false),
            };
        seal.wrapped_barrier_key = STANDARD.encode(wrapped.as_slice());
        if let Err(error) = seal.validate() {
            return (Response::error(500, error), false);
        }
        let barrier = match AeadBarrier::new(*barrier_key) {
            Ok(value) => value,
            Err(_) => {
                return (
                    Response::error(503, "cannot construct storage provider"),
                    false,
                );
            }
        };
        let (auth, root_token) = match AuthState::bootstrap(now) {
            Ok((auth, token)) => (auth, Zeroizing::new(token)),
            Err(error) => return (Response::error(error.status, &error.message), false),
        };
        let cluster_id = match crypto::random::<16>() {
            Ok(value) => STANDARD.encode(value),
            Err(error) => return (Response::error(503, error), false),
        };
        let state = State {
            schema: CURRENT_STATE_SCHEMA,
            cluster_id,
            replay_epoch: 0,
            namespaces: namespaces::NamespaceRegistry::default().into(),
            auth: auth.into(),
            engines: EngineState::default().into(),
            database: database::DatabaseState::default().into(),
            raft_admin: raft_admin::RaftAdminState::default().into(),
        };
        let mut stage = match InitializationStage::create(&self.data_dir) {
            Ok(value) => value,
            Err(_) => {
                return (
                    Response::error(503, "cannot create private initialization stage"),
                    false,
                );
            }
        };
        let mut durable = match DurableService::create_new(&stage.path, barrier, MAX_OPERATIONS) {
            Ok(value) => value,
            Err(_) => {
                return (
                    Response::error(503, "cannot prepare durable initialization state"),
                    false,
                );
            }
        };
        let bytes = match serde_json::to_vec(&state) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => return (Response::error(500, "state serialization failed"), false),
        };
        if bytes.len() > MAX_STATE_BYTES {
            return (
                Response::error(507, "single-node state capacity exhausted"),
                false,
            );
        }
        let operation_id = match crypto::random::<16>() {
            Ok(value) => value,
            Err(error) => return (Response::error(503, error), false),
        };
        let operation_id = hex(&operation_id);
        if let Err(error) = Self::persist_owner_state_batch(
            &mut durable,
            &state,
            &bytes,
            &operation_id,
            state.schema,
            state.replay_epoch,
            false,
            false,
            OwnerReuseHint::default(),
        ) {
            return (
                Response::error(
                    if matches!(
                        error,
                        ServiceError::RequestCapacityExhausted
                            | ServiceError::JournalCapacityExhausted
                    ) {
                        507
                    } else {
                        503
                    },
                    "staged initialization state was rejected",
                ),
                false,
            );
        }
        if persist_seal_metadata(&stage.path, &seal).is_err() {
            return (Response::error(503, "cannot prepare seal metadata"), false);
        }
        drop(durable);

        let mut keys = Vec::with_capacity(generated_shares.len());
        let mut keys_base64 = Vec::with_capacity(generated_shares.len());
        for share in generated_shares {
            let encoded = Zeroizing::new(share.encode());
            keys.push(hex(&encoded));
            keys_base64.push(STANDARD.encode(encoded.as_slice()));
        }
        let mut response = Response::ok(json!({
            "keys": keys,
            "keys_base64": keys_base64,
            "root_token": root_token.as_str(),
            "recovery_keys": [],
            "recovery_keys_base64": [],
        }));
        if let Some(secret) = recovery_secret.as_ref() {
            response.body["init_ack_required"] = json!(true);
            if write_initialization_recovery(&stage.path, &seal, secret, &response.body).is_err() {
                return (
                    Response::error(503, "cannot prepare initialization recovery"),
                    false,
                );
            }
        }
        if self
            .audit_event(
                "initialization-response-prepared",
                response_fingerprint,
                now,
                Some(200),
            )
            .is_err()
        {
            return (
                Response::error(
                    503,
                    "initialization response audit unavailable; no active state published",
                ),
                true,
            );
        }
        let parent_synced = match stage.publish(&self.data_dir) {
            Ok(value) => value,
            Err(_) => {
                return (
                    Response::error(503, "initialization publication failed before activation"),
                    false,
                );
            }
        };
        self.seal = Some(seal);
        self.state = None;
        self.durable = None;
        self.barrier_key = None;
        self.unseal_shares.clear();
        self.rekey = None;
        if !parent_synced {
            self.recovery_required = true;
            if recovery_secret.is_some() {
                return (
                    Response::error(
                        503,
                        "initialization publication outcome unknown; retry with the same recovery nonce",
                    ),
                    true,
                );
            }
            if let Some(object) = response.body.as_object_mut() {
                object.insert(
                    "warnings".into(),
                    json!(["initialization published but parent directory sync requires recovery review"]),
                );
            }
        }
        (response, true)
    }

    fn recover_initialization(&self, secret: &[u8; 32], shares: u8, threshold: u8) -> Response {
        let seal = match self.seal.as_ref() {
            Some(seal) if seal.secret_shares == shares && seal.secret_threshold == threshold => {
                seal
            }
            _ => return Response::error(400, "initialization recovery parameters do not match"),
        };
        if load_seal_metadata(&self.data_dir).ok().flatten().as_ref() != Some(seal) {
            return Response::error(503, "initialization recovery seal binding changed");
        }
        let protected = match read_initialization_recovery(&self.data_dir) {
            Ok(Some(value)) => value,
            Ok(None) => return Response::error(409, "initialization recovery is not pending"),
            Err(_) => return Response::error(503, "initialization recovery file is unavailable"),
        };
        let (barrier, context) = match initialization_recovery_barrier(secret, seal) {
            Ok(value) => value,
            Err(_) => return Response::error(503, "initialization recovery provider unavailable"),
        };
        let plaintext = match barrier.open(&context, &protected) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => return Response::error(403, "initialization recovery authentication failed"),
        };
        let Some(parent) = self.data_dir.parent() else {
            return Response::error(503, "initialization recovery parent is unavailable");
        };
        if File::open(parent)
            .and_then(|directory| directory.sync_all())
            .is_err()
        {
            return Response::error(503, "initialization publication durability is unknown");
        }
        match serde_json::from_slice::<Value>(&plaintext) {
            Ok(body) => Response::ok(body),
            Err(_) => Response::error(503, "initialization recovery response is corrupt"),
        }
    }

    fn ack_initialization(&mut self, method: &str, body: &Value) -> Response {
        self.ack_initialization_with_sync(method, body, |path| File::open(path)?.sync_all())
    }

    fn ack_initialization_with_sync(
        &mut self,
        method: &str,
        body: &Value,
        sync: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Response {
        if !matches!(method, "POST" | "PUT") {
            return Response::error(405, "initialization acknowledgement requires POST or PUT");
        }
        if body.as_object().is_none_or(|fields| !fields.is_empty()) {
            return Response::error(
                400,
                "initialization acknowledgement accepts an empty object",
            );
        }
        let removed = fs::remove_file(self.data_dir.join(INIT_RECOVERY_FILE));
        if let Err(error) = removed
            && error.kind() != io::ErrorKind::NotFound
        {
            return Response::error(503, "cannot remove initialization recovery file");
        }
        // Also sync an already absent file: a previous delete may have succeeded
        // while its directory sync failed, so absence alone is not an acknowledgement.
        if sync(&self.data_dir).is_err() {
            self.recovery_required = true;
            return Response::error(
                503,
                "initialization acknowledgement outcome unknown; directory sync failed",
            );
        }
        Response {
            status: 204,
            body: Value::Null,
        }
    }

    fn unseal(&mut self, body: &Value) -> Response {
        if self.state.is_some() && !self.recovery_required {
            return self.seal_status();
        }
        if !self.initialized() {
            return Response::error(400, "not initialized");
        }
        let Some(object) = body.as_object() else {
            return Response::error(400, "invalid unseal request");
        };
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "key" | "reset" | "migrate"))
        {
            return Response::error(400, "unsupported unseal options");
        }
        match body.get("migrate") {
            None | Some(Value::Bool(false)) => {}
            Some(Value::Bool(true)) => {
                return Response::error(501, "seal migration is not implemented by this endpoint");
            }
            Some(_) => return Response::error(400, "migrate must be a boolean"),
        }
        let reset = match body.get("reset") {
            None => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => return Response::error(400, "reset must be a boolean"),
        };
        if reset {
            if body.get("key").is_some() {
                return Response::error(400, "reset and key cannot be supplied together");
            }
            self.unseal_shares.clear();
            if self.rotate_unseal_nonce().is_err() {
                return Response::error(503, "operating system randomness unavailable");
            }
            return self.seal_status();
        }
        if private_directory(&self.data_dir).is_err() {
            return Response::error(400, "unsafe data directory");
        }
        let Some(encoded) = body.get("key").and_then(Value::as_str) else {
            return Response::error(400, "key is required");
        };

        if self.seal.is_none() {
            let decoded = match decode_key_material(encoded) {
                Ok(value) => Zeroizing::new(value),
                Err(error) => return Response::error(400, error),
            };
            let key: Zeroizing<[u8; 32]> = match decoded.as_slice().try_into() {
                Ok(value) => Zeroizing::new(value),
                Err(_) => return Response::error(400, "invalid legacy unseal key length"),
            };
            if let Err(error) = self.activate_barrier(&key) {
                return error;
            }
            let mut seal = SealMetadata {
                schema: 1,
                generation: 1,
                share_format: "raw-v1".into(),
                secret_shares: 1,
                secret_threshold: 1,
                wrapped_barrier_key: String::new(),
            };
            let wrapped = match crypto::wrap_barrier_key(&key, &seal.associated_data(), &key) {
                Ok(value) => Zeroizing::new(value),
                Err(_) => {
                    self.state = None;
                    self.durable = None;
                    self.barrier_key = None;
                    return Response::error(503, "legacy seal metadata migration failed");
                }
            };
            seal.wrapped_barrier_key = STANDARD.encode(wrapped.as_slice());
            if persist_seal_metadata(&self.data_dir, &seal).is_err() {
                self.state = None;
                self.durable = None;
                self.barrier_key = None;
                return Response::error(503, "legacy seal metadata migration failed");
            }
            self.seal = Some(seal);
            return self.seal_status();
        }

        let seal = match self.seal.clone() {
            Some(value) => value,
            None => return Response::error(503, "seal metadata unavailable"),
        };
        let seal_key = match collect_seal_key(&seal, encoded, &mut self.unseal_shares) {
            Ok(Some(value)) => Zeroizing::new(value),
            Ok(None) => return self.seal_status(),
            Err(error) => return Response::error(400, error),
        };
        let wrapped = match STANDARD.decode(&seal.wrapped_barrier_key) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => {
                self.unseal_shares.clear();
                return Response::error(503, "seal metadata is corrupt");
            }
        };
        let barrier_key =
            match crypto::unwrap_barrier_key(&seal_key, &seal.associated_data(), &wrapped) {
                Ok(value) => Zeroizing::new(value),
                Err(_) => {
                    self.unseal_shares.clear();
                    let _ = self.rotate_unseal_nonce();
                    return Response::error(400, "unseal failed");
                }
            };
        if let Err(error) = self.activate_barrier(&barrier_key) {
            self.unseal_shares.clear();
            let _ = self.rotate_unseal_nonce();
            return error;
        }
        self.unseal_shares.clear();
        if self.rotate_unseal_nonce().is_err() {
            self.state = None;
            self.durable = None;
            self.barrier_key = None;
            return Response::error(503, "operating system randomness unavailable");
        }
        self.seal_status()
    }

    fn activate_barrier(&mut self, key: &[u8; 32]) -> Result<(), Response> {
        self.durable = None;
        self.state = None;
        let barrier =
            AeadBarrier::new(*key).map_err(|_| Response::error(400, "invalid unseal key"))?;
        let mut durable = DurableService::reopen(&self.data_dir, barrier, MAX_OPERATIONS)
            .map_err(|_| Response::error(400, "unseal or recovery failed"))?;
        let (state, bytes, state_rewrite_required) = Self::load_state_from_durable(&durable)?;
        // Bind durable identity before any local state is admitted into an HA epoch.
        if let Some(ha) = self.ha.as_ref() {
            let ha = ha
                .lock()
                .map_err(|_| Response::error(503, "HA identity is unavailable during unseal"))?;
            if state.cluster_id != ha.cluster_id() {
                return Err(Response::error(
                    503,
                    "HA configuration belongs to a different cluster",
                ));
            }
        }
        if state_rewrite_required {
            let operation_id = format!(
                "state-format-{}",
                hex(&crypto::random::<16>().map_err(|error| Response::error(503, error))?)
            );
            match Self::persist_owner_state_batch(
                &mut durable,
                &state,
                &bytes,
                &operation_id,
                state.schema,
                state.replay_epoch,
                true,
                false,
                OwnerReuseHint::default(),
            ) {
                Ok(_) => {}
                Err(ServiceError::OutcomeUnknown { recovery_reference }) => {
                    return Err(Response {
                        status: 503,
                        body: json!({
                            "errors":["state-format metadata migration outcome unknown; retry unseal after durable reconciliation"],
                            "recovery_reference": recovery_reference,
                        }),
                    });
                }
                Err(
                    ServiceError::RequestCapacityExhausted | ServiceError::JournalCapacityExhausted,
                ) => {
                    return Err(Response::error(
                        507,
                        "state-format metadata migration capacity exhausted",
                    ));
                }
                Err(_) => {
                    return Err(Response::error(
                        503,
                        "state-format metadata migration failed closed",
                    ));
                }
            }
        }
        self.durable = Some(durable);
        self.state = Some(state);
        self.state_digest = Some(crypto::digest(&bytes));
        self.barrier_key = Some(Zeroizing::new(*key));
        self.recovery_required = false;
        let sync_as_leader = if let Some(ha) = self.ha.as_ref() {
            match ha.lock() {
                Ok(ha) => match ha.is_leader() {
                    Ok(value) => value,
                    Err(_) => {
                        self.recovery_required = true;
                        return Err(Response::error(503, "HA role is unavailable during unseal"));
                    }
                },
                Err(_) => {
                    self.recovery_required = true;
                    return Err(Response::error(503, "HA role is unavailable during unseal"));
                }
            }
        } else {
            false
        };
        if sync_as_leader && let Err(error) = self.sync_from_ha() {
            self.recovery_required = true;
            return Err(error);
        }
        Ok(())
    }

    fn rotate_unseal_nonce(&mut self) -> Result<(), &'static str> {
        self.unseal_nonce = hex(&crypto::random::<16>()?);
        Ok(())
    }

    fn rekey_status(&self) -> Response {
        if let Some(rekey) = &self.rekey {
            let (
                progress,
                required,
                verification_required,
                verification_nonce,
                verification_progress,
            ) = if let Some(pending) = &rekey.verification {
                (
                    0,
                    0,
                    true,
                    pending.verification_nonce.as_str(),
                    rekey.verification_provided.len(),
                )
            } else {
                (
                    rekey.provided.len(),
                    usize::from(self.seal.as_ref().map_or(1, |seal| seal.secret_threshold)),
                    false,
                    "",
                    0,
                )
            };
            Response::ok(json!({
                "started": rekey.verification.is_none(),
                "nonce": rekey.nonce,
                "t": rekey.new_threshold,
                "n": rekey.new_shares,
                "progress": progress,
                "required": required,
                "verification_required": verification_required,
                "verification_nonce": verification_nonce,
                "verification_progress": verification_progress,
                "verification_required_shares": if verification_required { rekey.new_threshold } else { 0 },
            }))
        } else {
            Response::ok(json!({
                "started": false,
                "nonce": "",
                "t": 0,
                "n": 0,
                "progress": 0,
                "required": self.seal.as_ref().map_or(1, |seal| seal.secret_threshold),
                "verification_required": false,
                "verification_nonce": "",
                "verification_progress": 0,
                "verification_required_shares": 0,
            }))
        }
    }

    fn rekey_route(&mut self, method: &str, path: &str, body: &Value) -> Response {
        match initialization_recovery_pending(&self.data_dir) {
            Ok(false) => {}
            Ok(true) => {
                return Response::error(409, "acknowledge initialization recovery before rekey");
            }
            Err(_) => return Response::error(503, "initialization recovery state is unavailable"),
        }
        if path == "sys/rekey/init" {
            if method == "GET" {
                return self.rekey_status();
            }
            if method == "DELETE" {
                if self
                    .rekey
                    .as_ref()
                    .is_some_and(|rekey| rekey.verification.is_some())
                    && delete_pending_rekey(&self.data_dir).is_err()
                {
                    return Response::error(503, "cannot durably cancel pending rekey");
                }
                self.rekey = None;
                return Response {
                    status: 204,
                    body: Value::Null,
                };
            }
            if !matches!(method, "POST" | "PUT") {
                return Response::error(405, "method not allowed");
            }
            if self.rekey.is_some() {
                return Response::error(400, "rekey is already in progress");
            }
            let Some(object) = body.as_object() else {
                return Response::error(400, "invalid rekey request");
            };
            if object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "secret_shares" | "secret_threshold" | "backup" | "require_verification"
                )
            }) {
                return Response::error(400, "unsupported rekey options");
            }
            match body.get("backup") {
                None | Some(Value::Bool(false)) => {}
                Some(Value::Bool(true)) => {
                    return Response::error(501, "PGP-encrypted rekey backup is not implemented");
                }
                Some(_) => return Response::error(400, "backup must be a boolean"),
            }
            let require_verification = match body.get("require_verification") {
                None => true,
                Some(Value::Bool(value)) => *value,
                Some(_) => return Response::error(400, "require_verification must be a boolean"),
            };
            let shares = match bounded_u8_field(body, "secret_shares", 5) {
                Ok(value) => value,
                Err(error) => return Response::error(400, error),
            };
            let threshold = match bounded_u8_field(body, "secret_threshold", 3) {
                Ok(value) => value,
                Err(error) => return Response::error(400, error),
            };
            if shares == 0 || shares > MAX_SEAL_SHARES || threshold == 0 || threshold > shares {
                return Response::error(400, "invalid rekey share configuration");
            }
            let nonce = match crypto::random::<16>() {
                Ok(value) => hex(&value),
                Err(error) => return Response::error(503, error),
            };
            self.rekey = Some(RekeyState {
                nonce,
                new_shares: shares,
                new_threshold: threshold,
                require_verification,
                provided: BTreeMap::new(),
                verification: None,
                verification_provided: BTreeMap::new(),
            });
            return self.rekey_status();
        }

        if path != "sys/rekey/update" {
            return Response::error(404, "unsupported rekey path");
        }
        if !matches!(method, "POST" | "PUT") {
            return Response::error(405, "method not allowed");
        }
        let Some(object) = body.as_object() else {
            return Response::error(400, "invalid rekey request");
        };
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "key" | "nonce"))
        {
            return Response::error(400, "unsupported rekey update fields");
        }
        let supplied_nonce = match body.get("nonce").and_then(Value::as_str) {
            Some(value) => value,
            None => return Response::error(400, "rekey nonce is required"),
        };
        let supplied_key = match body.get("key").and_then(Value::as_str) {
            Some(value) => value,
            None => return Response::error(400, "unseal share is required"),
        };
        let mut rekey = match self.rekey.take() {
            Some(value) => value,
            None => return Response::error(400, "rekey is not in progress"),
        };
        if rekey.verification.is_some() {
            return self.verify_rekey_share(rekey, supplied_nonce, supplied_key);
        }
        if supplied_nonce != rekey.nonce {
            self.rekey = Some(rekey);
            return Response::error(400, "rekey nonce mismatch");
        }
        let seal = match self.seal.clone() {
            Some(value) => value,
            None => {
                self.rekey = Some(rekey);
                return Response::error(503, "seal metadata unavailable");
            }
        };
        let seal_key = match collect_seal_key(&seal, supplied_key, &mut rekey.provided) {
            Ok(Some(value)) => Zeroizing::new(value),
            Ok(None) => {
                let progress = rekey.provided.len();
                let response = Response::ok(json!({
                    "started": true,
                    "nonce": rekey.nonce,
                    "t": rekey.new_threshold,
                    "n": rekey.new_shares,
                    "progress": progress,
                    "required": seal.secret_threshold,
                    "complete": false,
                    "verification_required": false,
                }));
                self.rekey = Some(rekey);
                return response;
            }
            Err(error) => {
                self.rekey = Some(rekey);
                return Response::error(400, error);
            }
        };
        let wrapped = match STANDARD.decode(&seal.wrapped_barrier_key) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => {
                self.rekey = Some(rekey);
                return Response::error(503, "seal metadata is corrupt");
            }
        };
        let current_barrier_key =
            match crypto::unwrap_barrier_key(&seal_key, &seal.associated_data(), &wrapped) {
                Ok(value) => Zeroizing::new(value),
                Err(_) => {
                    self.rekey = Some(rekey);
                    return Response::error(400, "unseal shares do not authorize rekey");
                }
            };
        if let Err(error) = self.verify_active_barrier(&current_barrier_key) {
            self.rekey = Some(rekey);
            return error;
        }

        let next_seal_key = match crypto::random::<32>() {
            Ok(value) => Zeroizing::new(value),
            Err(error) => {
                self.rekey = Some(rekey);
                return Response::error(503, error);
            }
        };
        let next_shares =
            match crypto::split_secret(&next_seal_key, rekey.new_shares, rekey.new_threshold) {
                Ok(value) => value,
                Err(error) => {
                    self.rekey = Some(rekey);
                    return Response::error(503, error);
                }
            };
        let generation = match seal.generation.checked_add(1) {
            Some(value) => value,
            None => {
                self.rekey = Some(rekey);
                return Response::error(507, "seal generation exhausted");
            }
        };
        let mut next = SealMetadata {
            schema: 1,
            generation,
            share_format: "shamir-v1".into(),
            secret_shares: rekey.new_shares,
            secret_threshold: rekey.new_threshold,
            wrapped_barrier_key: String::new(),
        };
        let next_wrapped = match crypto::wrap_barrier_key(
            &next_seal_key,
            &next.associated_data(),
            &current_barrier_key,
        ) {
            Ok(value) => Zeroizing::new(value),
            Err(error) => {
                self.rekey = Some(rekey);
                return Response::error(503, error);
            }
        };
        next.wrapped_barrier_key = STANDARD.encode(next_wrapped.as_slice());

        let mut keys = Vec::with_capacity(next_shares.len());
        let mut keys_base64 = Vec::with_capacity(next_shares.len());
        for share in next_shares {
            let encoded = Zeroizing::new(share.encode());
            keys.push(hex(&encoded));
            keys_base64.push(STANDARD.encode(encoded.as_slice()));
        }

        if rekey.require_verification {
            let verification_nonce = match crypto::random::<16>() {
                Ok(value) => hex(&value),
                Err(error) => {
                    self.rekey = Some(rekey);
                    return Response::error(503, error);
                }
            };
            let pending = PendingRekeyMetadata {
                schema: 1,
                active_generation: seal.generation,
                nonce: rekey.nonce.clone(),
                verification_nonce,
                candidate: next,
            };
            if persist_pending_rekey(&self.data_dir, &pending).is_err() {
                self.rekey = Some(rekey);
                return Response::error(503, "cannot durably stage rekey verification");
            }
            let response = Response::ok(json!({
                "started": false,
                "complete": true,
                "nonce": rekey.nonce,
                "keys": keys,
                "keys_base64": keys_base64,
                "verification_required": true,
                "verification_nonce": pending.verification_nonce,
            }));
            rekey.provided.clear();
            rekey.verification = Some(pending);
            rekey.verification_provided.clear();
            self.rekey = Some(rekey);
            return response;
        }

        if persist_seal_metadata(&self.data_dir, &next).is_err() {
            self.rekey = Some(rekey);
            return Response::error(503, "cannot durably publish new seal generation");
        }
        self.seal = Some(next);
        self.rekey = None;
        self.unseal_shares.clear();
        Response::ok(json!({
            "started": false,
            "complete": true,
            "nonce": rekey.nonce,
            "keys": keys,
            "keys_base64": keys_base64,
            "verification_required": false,
            "verification_nonce": "",
        }))
    }

    fn verify_rekey_share(
        &mut self,
        mut rekey: RekeyState,
        supplied_nonce: &str,
        supplied_key: &str,
    ) -> Response {
        let pending = match rekey.verification.clone() {
            Some(value) => value,
            None => {
                self.rekey = Some(rekey);
                return Response::error(500, "missing pending rekey metadata");
            }
        };
        if supplied_nonce != pending.verification_nonce {
            self.rekey = Some(rekey);
            return Response::error(400, "rekey verification nonce mismatch");
        }
        let next_seal_key = match collect_seal_key(
            &pending.candidate,
            supplied_key,
            &mut rekey.verification_provided,
        ) {
            Ok(Some(value)) => Zeroizing::new(value),
            Ok(None) => {
                let progress = rekey.verification_provided.len();
                let response = Response::ok(json!({
                    "started": false,
                    "complete": false,
                    "verification_required": true,
                    "verification_nonce": pending.verification_nonce,
                    "verification_progress": progress,
                    "verification_required_shares": pending.candidate.secret_threshold,
                }));
                self.rekey = Some(rekey);
                return response;
            }
            Err(error) => {
                self.rekey = Some(rekey);
                return Response::error(400, error);
            }
        };
        let wrapped = match STANDARD.decode(&pending.candidate.wrapped_barrier_key) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => {
                self.rekey = Some(rekey);
                return Response::error(503, "pending rekey metadata is corrupt");
            }
        };
        let candidate_barrier = match crypto::unwrap_barrier_key(
            &next_seal_key,
            &pending.candidate.associated_data(),
            &wrapped,
        ) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => {
                rekey.verification_provided.clear();
                self.rekey = Some(rekey);
                return Response::error(400, "rekey verification failed");
            }
        };
        if let Err(error) = self.verify_active_barrier(&candidate_barrier) {
            rekey.verification_provided.clear();
            self.rekey = Some(rekey);
            return error;
        }
        if persist_seal_metadata(&self.data_dir, &pending.candidate).is_err() {
            self.rekey = Some(rekey);
            return Response::error(503, "cannot durably promote verified seal generation");
        }
        self.seal = Some(pending.candidate.clone());
        self.unseal_shares.clear();
        self.rekey = None;
        if delete_pending_rekey(&self.data_dir).is_err() {
            self.recovery_required = true;
            return Response::error(
                503,
                "verified seal promoted but pending marker cleanup failed; restart required",
            );
        }
        Response::ok(json!({
            "started": false,
            "complete": true,
            "verification_required": false,
            "verification_nonce": pending.verification_nonce,
        }))
    }

    fn capacity_route(&self, method: &str, body: &Value) -> Response {
        if method != "GET" {
            return Response::error(405, "capacity observation requires GET");
        }
        if !body.is_null() && body.as_object().is_none_or(|v| !v.is_empty()) {
            return Response::error(400, "capacity observation accepts no fields");
        }
        let Some(durable) = self.durable.as_ref() else {
            return Response::error(503, "server is sealed");
        };
        let capacity = match durable.capacity() {
            Ok(value) => value,
            Err(_) => return Response::error(503, "durable capacity unavailable"),
        };
        Response::ok(json!({"data": {
            "scope": "local_node_bounded_runtime",
            "state_limit_bytes": MAX_STATE_BYTES,
            "stored_value_bytes": capacity.logical_payload_bytes,
            "generation": capacity.generation,
            "journal_bytes": capacity.journal_bytes,
            "journal_limit_bytes": capacity.journal_limit_bytes,
            "retained_requests": capacity.retained_requests,
            "retained_request_limit": capacity.max_retained_requests,
            "remaining_request_slots": capacity.max_retained_requests.saturating_sub(capacity.retained_requests),
            "recovery_required": false,
            "automatic_journal_checkpoint": true,
            "replay_id_eviction": false,
            "replay_epoch": durable.replay_epoch(),
            "retired_through_generation": durable.retired_through_generation(),
            "replay_retirement": if self.ha.is_some() { "raft-coordinated" } else { "local-epoch" }
        }}))
    }

    fn maintenance_route(&mut self, method: &str, path: &str, body: &Value) -> Response {
        if let Some(reference) = path.strip_prefix("sys/internal/recovery/") {
            if method != "GET" {
                return Response::error(405, "recovery lookup requires GET");
            }
            if !valid_recovery_reference(reference) {
                return Response::error(400, "invalid recovery reference");
            }
            let Some(durable) = self.durable.as_ref() else {
                return Response::error(503, "server is sealed");
            };
            return match durable.reconcile(reference) {
                ReconciliationStatus::Committed { generation } => Response::ok(json!({
                    "data": {
                        "recovery_reference": reference,
                        "status": "committed",
                        "generation": generation,
                    }
                })),
                ReconciliationStatus::Aborted => Response::ok(json!({
                    "data": {
                        "recovery_reference": reference,
                        "status": "aborted",
                    }
                })),
                ReconciliationStatus::Unknown => Response {
                    status: 404,
                    body: json!({"errors":["recovery reference is unknown"]}),
                },
            };
        }

        if path == "sys/storage/raft/replay-retire" {
            if !matches!(method, "POST" | "PUT") {
                return Response::error(405, "replay retirement requires POST or PUT");
            }
            if body.as_object().is_none_or(|object| !object.is_empty()) {
                return Response::error(400, "replay retirement accepts an empty JSON object");
            }
            let Some(mut next_state) = self.state.clone() else {
                return Response::error(503, "server is sealed");
            };
            let Some(durable) = self.durable.as_ref() else {
                return Response::error(503, "server is sealed");
            };
            let previous_epoch = durable.replay_epoch();
            if next_state.replay_epoch != previous_epoch {
                self.recovery_required = true;
                return Response::error(503, "replay epoch metadata requires recovery");
            }
            let Some(current_epoch) = previous_epoch.checked_add(1) else {
                return Response::error(507, "replay epoch exhausted");
            };
            let retired_requests = durable.retained_request_count();
            let retired_through_generation = durable.generation();
            next_state.schema = CURRENT_STATE_SCHEMA;
            next_state.replay_epoch = current_epoch;

            // The epoch marker is part of the authoritative application state.
            // In HA mode it is committed by Raft before any node discards its
            // detailed replay ledger. Each node then retires locally immediately
            // before publishing the state batch under the new epoch.
            if let Err(error) = self.commit_state(&next_state) {
                return error;
            }
            self.state = Some(next_state);
            let Some(durable) = self.durable.as_ref() else {
                self.recovery_required = true;
                return Response::error(503, "replay retirement lost durable owner");
            };
            if durable.replay_epoch() != current_epoch
                || durable.retired_through_generation() != retired_through_generation
            {
                self.recovery_required = true;
                return Response::error(503, "replay retirement did not converge locally");
            }
            return Response::ok(json!({
                "data": {
                    "previous_epoch": previous_epoch,
                    "replay_epoch": current_epoch,
                    "retired_through_generation": retired_through_generation,
                    "retired_requests": retired_requests,
                    "cluster_coordinated": self.ha.is_some(),
                }
            }));
        }

        if path == "sys/storage/raft/compact" {
            if !matches!(method, "POST" | "PUT") {
                return Response::error(405, "storage compaction requires POST or PUT");
            }
            if body.as_object().is_none_or(|object| !object.is_empty()) {
                return Response::error(400, "storage compaction accepts an empty JSON object");
            }
            if let Some(ha) = self.ha.as_ref() {
                let result = ha
                    .lock()
                    .map_err(|_| ())
                    .and_then(|ha| ha.trigger_snapshot().map_err(|_| ()));
                if result.is_err() {
                    return Response::error(503, "HA snapshot trigger failed");
                }
            }
            let (result, fenced) = {
                let Some(durable) = self.durable.as_mut() else {
                    return Response::error(503, "server is sealed");
                };
                let result = durable.compact();
                (result, durable.recovery_required())
            };
            if fenced {
                self.recovery_required = true;
            }
            return match result {
                Ok(outcome) => Response::ok(json!({
                    "data": {
                        "generation": outcome.generation,
                        "retained_requests": outcome.retained_requests,
                        "journal_bytes_before": outcome.journal_bytes_before,
                        "journal_bytes_after": outcome.journal_bytes_after,
                    }
                })),
                Err(_) => Response::error(503, "storage compaction failed; inspect durable state"),
            };
        }

        if path == "sys/storage/raft/snapshot" && method == "GET" {
            if let Some(ha) = self.ha.as_ref() {
                let result = ha
                    .lock()
                    .map_err(|_| ())
                    .and_then(|ha| ha.trigger_snapshot().map_err(|_| ()));
                if result.is_err() {
                    return Response::error(503, "HA snapshot trigger failed");
                }
            }
            let Some(durable) = self.durable.as_ref() else {
                return Response::error(503, "server is sealed");
            };
            let backup = match durable.export_backup() {
                Ok(value) => Zeroizing::new(value),
                Err(_) => return Response::error(503, "cannot export durable snapshot"),
            };
            if backup.len() > MAX_BACKUP_TRANSFER_BYTES {
                return Response::error(507, "durable snapshot exceeds transfer limit");
            }
            let digest = hex(&crypto::digest(&backup));
            return Response::ok(json!({
                "data": {
                    "snapshot": STANDARD.encode(backup.as_slice()),
                    "sha256": digest,
                    "generation": durable.generation(),
                    "retained_requests": durable.retained_request_count(),
                    "format": "heptabao-encrypted-backup-v1",
                }
            }));
        }

        if matches!(
            path,
            "sys/storage/raft/snapshot" | "sys/storage/raft/snapshot-force"
        ) {
            if self.ha.is_some() {
                return Response::error(
                    409,
                    "direct local snapshot restore is forbidden while HA is enabled",
                );
            }
            if self
                .state
                .as_ref()
                .is_some_and(|state| !state.database.is_empty())
            {
                return Response::error(
                    409,
                    "database provider epochs cannot be rolled back with a local snapshot",
                );
            }
            if !matches!(method, "POST" | "PUT") {
                return Response::error(405, "snapshot restore requires POST or PUT");
            }
            let Some(object) = body.as_object() else {
                return Response::error(400, "snapshot restore requires a JSON object");
            };
            if object.keys().any(|key| key != "snapshot") {
                return Response::error(400, "unsupported snapshot restore field");
            }
            let Some(encoded) = object.get("snapshot").and_then(Value::as_str) else {
                return Response::error(400, "snapshot is required");
            };
            if encoded.len() > MAX_BACKUP_TRANSFER_BYTES * 2 {
                return Response::error(413, "encoded snapshot exceeds transfer limit");
            }
            let backup = match STANDARD.decode(encoded) {
                Ok(value) if value.len() <= MAX_BACKUP_TRANSFER_BYTES => Zeroizing::new(value),
                Ok(_) => return Response::error(413, "snapshot exceeds transfer limit"),
                Err(_) => return Response::error(400, "invalid snapshot encoding"),
            };
            let allow_rollback = path == "sys/storage/raft/snapshot-force";
            let outcome = {
                let Some(durable) = self.durable.as_mut() else {
                    return Response::error(503, "server is sealed");
                };
                match durable.restore_backup(&backup, allow_rollback) {
                    Ok(value) => value,
                    Err(ServiceError::BackupRollbackRejected) => {
                        return Response::error(
                            400,
                            "snapshot is older than live state; use snapshot-force only after review",
                        );
                    }
                    Err(ServiceError::CorruptState | ServiceError::BarrierFailure) => {
                        return Response::error(400, "snapshot authentication or structure failed");
                    }
                    Err(_) => {
                        if durable.recovery_required() {
                            self.recovery_required = true;
                        }
                        return Response::error(
                            503,
                            "snapshot restore failed; authoritative recovery required",
                        );
                    }
                }
            };
            if let Err(response) = self.refresh_state_from_durable() {
                self.recovery_required = true;
                return response;
            }
            return Response::ok(json!({
                "data": {
                    "previous_generation": outcome.previous_generation,
                    "restored_generation": outcome.restored_generation,
                    "retained_requests": outcome.retained_requests,
                    "rollback": outcome.restored_generation < outcome.previous_generation,
                }
            }));
        }

        Response::error(404, "unsupported maintenance path")
    }

    fn refresh_state_from_durable(&mut self) -> Result<(), Response> {
        let durable = self
            .durable
            .as_ref()
            .ok_or_else(|| Response::error(503, "server is sealed"))?;
        let (state, bytes, _) = Self::load_state_from_durable(durable)?;
        self.state = Some(state);
        self.state_digest = Some(crypto::digest(&bytes));
        self.recovery_required = false;
        Ok(())
    }

    fn verify_active_barrier(&self, candidate: &[u8; 32]) -> Result<(), Response> {
        let Some(active_key) = self.barrier_key.as_ref() else {
            return Err(Response::error(503, "server must be unsealed for rekey"));
        };
        let candidate_key = hmac::Key::new(hmac::HMAC_SHA256, candidate);
        let candidate_tag = hmac::sign(&candidate_key, b"heptabao.barrier-key-proof.v1");
        let active_key = hmac::Key::new(hmac::HMAC_SHA256, active_key.as_ref());
        hmac::verify(
            &active_key,
            b"heptabao.barrier-key-proof.v1",
            candidate_tag.as_ref(),
        )
        .map_err(|_| Response::error(400, "seal shares do not match the active barrier"))
    }

    fn persist(
        &mut self,
        state: &State,
        bytes: &[u8],
        base_digest: [u8; 32],
        state_schema: u32,
        target_replay_epoch: u64,
    ) -> Result<(), Response> {
        let durable = self
            .durable
            .as_ref()
            .ok_or_else(|| Response::error(503, "server is sealed"))?;
        let current_epoch = durable.replay_epoch();
        let next_epoch = current_epoch.checked_add(1);
        let epoch_transition = next_epoch == Some(target_replay_epoch);
        if target_replay_epoch < current_epoch
            || (target_replay_epoch != current_epoch && !epoch_transition)
        {
            return Err(Response::error(503, "invalid replay epoch transition"));
        }
        // Ordinary requests allocate a new local replay identity and must prove
        // capacity before a Raft effect. An epoch transition is itself the
        // authenticated escape from a full detailed ledger, so it is allowed to
        // replicate before local retirement and then publishes under the new epoch.
        if !epoch_transition {
            durable
                .preflight_new_identity()
                .map_err(|error| match error {
                    ServiceError::RequestCapacityExhausted => {
                        Response::error(507, "retained operation capacity exhausted")
                    }
                    _ => Response::error(503, "durable capacity preflight unavailable"),
                })?;
        }
        let id = crypto::random::<16>().map_err(|e| Response::error(503, e))?;
        let operation_id = hex(&id);
        if let Some(ha) = self.ha.as_ref() {
            let commit = ha
                .lock()
                .map_err(|_| Response::error(503, "HA control state is unavailable"))?
                .commit_state(&operation_id, base_digest, bytes);
            if let Err(error) = commit {
                return Err(Response::error(503, &error));
            }
        }
        match self.persist_local(
            state,
            bytes,
            &operation_id,
            state_schema,
            target_replay_epoch,
        ) {
            Ok(()) => Ok(()),
            Err(error) => {
                if self.ha.is_some() {
                    self.recovery_required = true;
                    return Err(Self::ha_committed_local_failure(error));
                }
                Err(error)
            }
        }
    }

    fn persist_local(
        &mut self,
        state: &State,
        bytes: &[u8],
        operation_id: &str,
        state_schema: u32,
        target_replay_epoch: u64,
    ) -> Result<(), Response> {
        self.persist_local_with_epoch_policy(
            state,
            bytes,
            operation_id,
            state_schema,
            target_replay_epoch,
            false,
        )
    }

    fn persist_local_with_epoch_policy(
        &mut self,
        state: &State,
        bytes: &[u8],
        operation_id: &str,
        state_schema: u32,
        target_replay_epoch: u64,
        allow_epoch_catchup: bool,
    ) -> Result<(), Response> {
        let reuse = OwnerReuseHint::between(self.state.as_ref(), state);
        let durable = self
            .durable
            .as_mut()
            .ok_or_else(|| Response::error(503, "server is sealed"))?;
        let prior_replay_epoch = durable.replay_epoch();
        let result = Self::persist_owner_state_batch(
            durable,
            state,
            bytes,
            operation_id,
            state_schema,
            target_replay_epoch,
            true,
            allow_epoch_catchup,
            reuse,
        );
        // If retirement itself published but the following state batch failed,
        // application state and replay authority no longer have the same epoch.
        // Fence the process even when the durable primitive is otherwise healthy;
        // restart normalization or HA catch-up is then the only admissible path.
        let epoch_advanced_without_state = result.is_err()
            && target_replay_epoch > prior_replay_epoch
            && durable.replay_epoch() == target_replay_epoch;
        if durable.recovery_required() || epoch_advanced_without_state {
            self.recovery_required = true;
        }
        match result {
            Ok(_) => Ok(()),
            Err(ServiceError::OutcomeUnknown { recovery_reference }) => {
                self.recovery_required = true;
                Err(Response {
                    status: 503,
                    body: json!({"errors":["durable outcome unknown; do not blindly retry"],"recovery_reference":recovery_reference}),
                })
            }
            Err(
                ServiceError::RequestCapacityExhausted | ServiceError::JournalCapacityExhausted,
            ) => Err(Response::error(
                507,
                "durable capacity exhausted; no response released",
            )),
            Err(_) => {
                self.recovery_required |= durable.recovery_required();
                Err(Response::error(
                    503,
                    "durable state rejected; no response released",
                ))
            }
        }
    }

    fn sync_from_ha(&mut self) -> Result<(), Response> {
        let Some(ha) = self.ha.as_ref().cloned() else {
            return Ok(());
        };
        let committed = ha
            .lock()
            .map_err(|_| Response::error(503, "HA control state is unavailable"))?
            .latest_committed_state()
            .map_err(|_| Response::error(503, "HA linearizable state is unavailable"))?;
        let Some(committed) = committed else {
            return Ok(());
        };
        if self.current_state_digest()? == committed.digest {
            return Ok(());
        }
        let state: State = serde_json::from_slice(&committed.bytes)
            .map_err(|_| Response::error(503, "HA committed state schema is invalid"))?;
        state.validate_format()?;
        let expected_cluster = ha
            .lock()
            .map_err(|_| Response::error(503, "HA control state is unavailable"))?
            .cluster_id()
            .to_owned();
        if state.cluster_id != expected_cluster {
            return Err(Response::error(
                503,
                "HA committed state belongs to a different cluster",
            ));
        }
        let operation_id = format!("hasync-{}", hex(&committed.digest));
        if let Err(error) = self.persist_local_with_epoch_policy(
            &state,
            &committed.bytes,
            &operation_id,
            state.schema,
            state.replay_epoch,
            true,
        ) {
            self.recovery_required = true;
            return Err(Self::ha_committed_local_failure(error));
        }
        self.state = Some(state);
        self.state_digest = Some(committed.digest);
        self.recovery_required = false;
        Ok(())
    }

    fn ha_observation(&self) -> (bool, bool, bool, Option<u64>, Option<u64>) {
        let Some(ha) = self.ha.as_ref() else {
            return (false, false, true, None, None);
        };
        let Ok(ha) = ha.lock() else {
            return (true, false, false, None, None);
        };
        let local = match ha.local_id() {
            Ok(local) => Some(local),
            Err(_) => return (true, false, false, None, None),
        };
        let leader = match ha.leader() {
            Ok(leader) => leader,
            Err(_) => return (true, false, false, None, local),
        };
        let standby = leader.is_some() && leader != local;
        let active = leader.is_some() && leader == local && ha.ensure_linearizable().is_ok();
        (true, standby, active, leader, local)
    }

    fn leader_response(&self) -> Response {
        let (ha_enabled, _, ha_active, leader, local) = self.ha_observation();
        if !ha_enabled {
            return Response::ok(json!({
                "ha_enabled": false,
                "is_self": true,
                "leader_address": "",
                "leader_cluster_address": "",
                "performance_standby": false,
                "performance_standby_last_remote_wal": 0
            }));
        }
        Response::ok(json!({
            "ha_enabled": true,
            "is_self": ha_active && leader.is_some() && leader == local,
            "leader_address": "",
            "leader_cluster_address": "",
            "performance_standby": false,
            "performance_standby_last_remote_wal": 0
        }))
    }

    /// Inspect deployment-owned audit devices. The standard file-device route
    /// follows the pinned OpenBao declarative-device profile: list the device,
    /// reject duplicate enable and disable, and refuse a per-device GET. The
    /// explicit internal file route retains HeptaBao's read/idempotent binding
    /// extension without claiming that extension is an upstream endpoint.
    fn audit_route(
        &self,
        principal: &Principal,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Response {
        if !namespace.is_empty() || !principal.is_root() {
            return Response::error(403, "permission denied");
        }
        let config = self.audit_rotation.config();
        let file_path = self.audit_rotation.active_path();
        let file_path = file_path.to_string_lossy().into_owned();
        let device = || {
            json!({
                "type": "file",
                "accessor": "audit_file",
                "revision": 1,
                "description": "HeptaBao mandatory authenticated file audit device",
                "options": {
                    "file_path": file_path.as_str(),
                    "segment_bytes": config.segment_bytes,
                    "retained_segments": config.retained_segments,
                },
                "local": true,
                "log_raw": false,
                "seal_wrap": false,
            })
        };
        let http_device = || {
            self.audit_http_url.as_ref().map(|url| {
                json!({
                    "type": "http",
                    "accessor": "audit_http",
                    "revision": 1,
                    "description": "HeptaBao mandatory host-enrolled HTTPS audit collector",
                    "options": {
                        "address": url,
                    },
                    "local": true,
                    "log_raw": false,
                    "seal_wrap": false,
                })
            })
        };
        let socket_device = || {
            self.audit_socket.map(|config| {
                json!({
                    "type": "socket",
                    "accessor": "audit_socket",
                    "revision": 1,
                    "description": "HeptaBao deployment-owned bounded TCP audit collector",
                    "options": {
                        "address": config.address.to_string(),
                        "socket_type": "tcp",
                        "write_timeout_ms": config.write_timeout_ms,
                    },
                    "local": true,
                    "log_raw": false,
                    "seal_wrap": false,
                    "failed_writes": self.audit_socket_failures,
                })
            })
        };
        let syslog_device = || {
            self.audit_syslog.as_ref().map(|config| {
                json!({
                    "type": "syslog",
                    "accessor": "audit_syslog",
                    "revision": 1,
                    "description": "HeptaBao deployment-owned local Unix syslog audit device",
                    "options": {
                        "facility": config.facility.as_str(),
                        "tag": config.tag.as_str(),
                    },
                    "local": true,
                    "log_raw": false,
                    "seal_wrap": false,
                    "failed_writes": self.audit_syslog_failures,
                })
            })
        };
        let path = path.trim_end_matches('/');
        match (path, method) {
            ("sys/audit", "GET" | "LIST") => {
                let mut devices = serde_json::Map::new();
                devices.insert("file/".into(), device());
                if let Some(http) = http_device() {
                    devices.insert("http/".into(), http);
                }
                if let Some(socket) = socket_device() {
                    devices.insert("socket/".into(), socket);
                }
                if let Some(syslog) = syslog_device() {
                    devices.insert("syslog/".into(), syslog);
                }
                Response::ok(json!({"data":devices}))
            }
            ("sys/internal/audit/file", "GET") => Response::ok(json!({"data":device()})),
            ("sys/audit/file", "POST" | "PUT") => {
                Response::error(400, "audit device is already configured by the deployment")
            }
            ("sys/audit/http", "GET") => match http_device() {
                Some(http) => Response::ok(json!({"data":http})),
                None => Response::error(404, "audit device not found"),
            },
            ("sys/audit/socket", "GET") => match socket_device() {
                Some(socket) => Response::ok(json!({"data":socket})),
                None => Response::error(404, "audit device not found"),
            },
            ("sys/audit/syslog", "GET") => match syslog_device() {
                Some(syslog) => Response::ok(json!({"data":syslog})),
                None => Response::error(404, "audit device not found"),
            },
            ("sys/internal/audit/file", "POST" | "PUT") => {
                let Some(object) = body.as_object() else {
                    return Response::error(400, "audit enable requires a JSON object");
                };
                if object.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "type" | "description" | "options" | "local" | "cas_revision"
                    )
                }) {
                    return Response::error(400, "unsupported file audit parameter");
                }
                if let Some(revision) = object.get("cas_revision") {
                    let Some(revision) = revision.as_u64() else {
                        return Response::error(400, "cas_revision must be a nonnegative integer");
                    };
                    if revision != 1 {
                        return Response::error(409, "stale audit mount revision");
                    }
                }
                if object
                    .get("type")
                    .and_then(Value::as_str)
                    .is_none_or(|kind| kind != "file")
                {
                    return Response::error(
                        501,
                        "only the mandatory file audit device is supported",
                    );
                }
                if let Some(options) = object.get("options") {
                    let Some(options) = options.as_object() else {
                        return Response::error(400, "audit options must be a JSON object");
                    };
                    if let Some(requested) = options.get("file_path") {
                        let Some(requested) = requested.as_str() else {
                            return Response::error(400, "audit file_path must be a string");
                        };
                        if requested != file_path.as_str() {
                            return Response::error(
                                409,
                                "the mandatory audit file path is fixed at process startup",
                            );
                        }
                    }
                    if let Some(requested) = options.get("segment_bytes")
                        && requested.as_u64() != Some(config.segment_bytes)
                    {
                        return Response::error(
                            409,
                            "the audit segment bound is fixed at process startup",
                        );
                    }
                    if let Some(requested) = options.get("retained_segments")
                        && requested.as_u64() != Some(config.retained_segments as u64)
                    {
                        return Response::error(
                            409,
                            "the audit retention bound is fixed at process startup",
                        );
                    }
                    for key in options.keys() {
                        if !matches!(
                            key.as_str(),
                            "file_path" | "segment_bytes" | "retained_segments"
                        ) {
                            return Response::error(400, "unsupported file audit option");
                        }
                    }
                }
                Response {
                    status: 204,
                    body: Value::Null,
                }
            }
            ("sys/audit/file" | "sys/internal/audit/file", "DELETE") => Response::error(
                400,
                "the mandatory file audit device cannot be disabled while the service is running",
            ),
            ("sys/audit/http", "POST" | "PUT" | "DELETE") => Response::error(
                409,
                "HTTP audit collector is fixed by trusted process configuration",
            ),
            ("sys/audit/socket", "POST" | "PUT" | "DELETE") => Response::error(
                409,
                "socket audit collector is fixed by trusted process configuration",
            ),
            ("sys/audit/syslog", "POST" | "PUT" | "DELETE") => Response::error(
                409,
                "syslog audit device is fixed by trusted process configuration",
            ),
            ("sys/audit", _)
            | ("sys/audit/file", _)
            | ("sys/internal/audit/file", _)
            | ("sys/audit/http", _)
            | ("sys/audit/socket", _)
            | ("sys/audit/syslog", _) => Response::error(405, "unsupported sys/audit method"),
            _ => Response::error(404, "audit device not found"),
        }
    }

    fn wire_rejection_fingerprint(
        &self,
        attempt_id: &[u8; 16],
        rejection: WireRejection,
        status: u16,
    ) -> String {
        let mut context = hmac::Context::with_key(&self.audit_key);
        context.update(b"heptabao.audit.wire-rejection.v1");
        context.update(&(rejection.code().len() as u64).to_le_bytes());
        context.update(rejection.code());
        context.update(&status.to_le_bytes());
        context.update(attempt_id);
        STANDARD.encode(context.sign().as_ref())
    }

    fn request_fingerprint(
        &self,
        method: &str,
        path: &str,
        namespace: &str,
        token: &str,
    ) -> String {
        let mut context = hmac::Context::with_key(&self.audit_key);
        context.update(b"heptabao.audit.request-fingerprint.v2");
        for field in [method, namespace, path, token] {
            context.update(&(field.len() as u64).to_le_bytes());
            context.update(field.as_bytes());
        }
        STANDARD.encode(context.sign().as_ref())
    }

    fn audit_event(
        &mut self,
        kind: &str,
        fingerprint: &str,
        now: u64,
        status: Option<u16>,
    ) -> Result<(), std::io::Error> {
        if self.audit_failed {
            return Err(std::io::Error::other("audit requires offline recovery"));
        }
        let sequence = self
            .audit_sequence
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("audit sequence exhausted"))?;
        let unsigned = AuditUnsigned {
            schema: 2,
            sequence,
            previous: STANDARD.encode(self.audit_previous),
            time: now,
            kind: kind.to_owned(),
            path_digest: fingerprint.to_owned(),
            status,
        };
        let payload = serde_json::to_vec(&unsigned)?;
        let tag = hmac::sign(&self.audit_key, &payload);
        let record = AuditRecord {
            event: unsigned,
            mac: STANDARD.encode(tag.as_ref()),
        };
        let mut bytes = serde_json::to_vec(&record)?;
        bytes.push(b'\n');
        // Preserve the existing test-only I/O budget injection. Production
        // capacity is per segment and rotates without skipping either audit event.
        #[cfg(test)]
        if self
            .audit
            .metadata()?
            .len()
            .checked_add(bytes.len() as u64)
            .is_none_or(|n| n > self.audit_capacity)
        {
            return Err(std::io::Error::other("injected audit capacity exhausted"));
        }
        if let Err(error) = self.audit_rotation.before_append(
            &mut self.audit,
            &self.audit_key,
            bytes.len(),
            self.audit_sequence,
            self.audit_previous,
        ) {
            self.audit_failed = true;
            return Err(error);
        }
        if let Err(error) = self
            .audit
            .write_all(&bytes)
            .and_then(|()| self.audit.sync_all())
        {
            self.audit_failed = true;
            return Err(error);
        }
        if let Some(url) = self.audit_http_url.as_deref() {
            let value = serde_json::to_value(&record)?;
            if self.outbound.post_audit_json(url, &value).is_err() {
                self.audit_failed = true;
                return Err(std::io::Error::other(
                    "mandatory HTTP audit collector unavailable",
                ));
            }
        }
        if let Some(config) = self.audit_socket
            && write_audit_socket(config, &bytes).is_err()
        {
            self.audit_socket_failures = self.audit_socket_failures.saturating_add(1);
        }
        if let Some(config) = self.audit_syslog.as_ref()
            && write_audit_syslog(config, &bytes).is_err()
        {
            self.audit_syslog_failures = self.audit_syslog_failures.saturating_add(1);
        }
        self.audit_sequence = sequence;
        self.audit_previous.copy_from_slice(tag.as_ref());
        Ok(())
    }
}
fn write_audit_socket(config: AuditSocketConfig, bytes: &[u8]) -> io::Result<()> {
    let timeout = Duration::from_millis(config.write_timeout_ms);
    let mut stream = TcpStream::connect_timeout(&config.address, timeout)?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(bytes)?;
    stream.flush()
}

#[cfg(unix)]
fn write_audit_syslog(config: &AuditSyslogConfig, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::net::UnixDatagram;

    let facility = syslog_facility_code(&config.facility)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid syslog facility"))?;
    let priority = facility
        .checked_mul(8)
        .and_then(|value| value.checked_add(6))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid syslog priority"))?;
    let mut frame = Vec::with_capacity(bytes.len().saturating_add(config.tag.len() + 16));
    write!(&mut frame, "<{priority}>{}: ", config.tag)?;
    frame.extend_from_slice(bytes);
    if frame.len() > 64 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bounded syslog datagram exceeds 64 KiB",
        ));
    }
    let socket = UnixDatagram::unbound()?;
    socket.connect(&config.socket_path)?;
    if socket.send(&frame)? != frame.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short syslog datagram write",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_audit_syslog(_config: &AuditSyslogConfig, _bytes: &[u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "syslog audit is supported only on Unix",
    ))
}

fn health_status(
    initialized: bool,
    sealed: bool,
    recovery_required: bool,
    ha_enabled: bool,
    standby: bool,
    ha_active: bool,
) -> u16 {
    if !initialized {
        501
    } else if sealed || recovery_required {
        503
    } else if ha_enabled && standby {
        429
    } else if ha_enabled && !ha_active {
        503
    } else {
        200
    }
}

fn path_present(path: &Path) -> Result<bool, &'static str> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("cannot inspect initialization recovery path"),
    }
}

fn initialization_recovery_pending(data_dir: &Path) -> Result<bool, &'static str> {
    path_present(&data_dir.join(INIT_RECOVERY_FILE))
}

fn decode_initialization_secret(value: &Value) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let encoded = value.as_str().ok_or("recovery_nonce must be a string")?;
    if encoded.len() != 44 && encoded.len() != 64 {
        return Err("recovery_nonce must contain 32 random bytes");
    }
    let decoded = if encoded.len() == 64
        && encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Zeroizing::new(decode_hex(encoded).ok_or("invalid recovery_nonce encoding")?)
    } else {
        let decoded = Zeroizing::new(
            STANDARD
                .decode(encoded)
                .map_err(|_| "invalid recovery_nonce encoding")?,
        );
        let canonical = Zeroizing::new(STANDARD.encode(decoded.as_slice()));
        if canonical.as_str() != encoded {
            return Err("recovery_nonce must use canonical base64 or lowercase hex");
        }
        decoded
    };
    let secret = Zeroizing::new(
        decoded
            .as_slice()
            .try_into()
            .map_err(|_| "recovery_nonce must contain 32 random bytes")?,
    );
    if *secret == [0; 32] {
        return Err("recovery_nonce must be generated with cryptographic randomness");
    }
    Ok(secret)
}

fn initialization_recovery_barrier(
    secret: &[u8; 32],
    seal: &SealMetadata,
) -> Result<(AeadBarrier, Vec<u8>), io::Error> {
    let encoded = serde_json::to_vec(seal).map_err(io::Error::other)?;
    let mut context = b"heptabao.initialization-recovery.v2\0".to_vec();
    context.extend_from_slice(&crypto::digest(&encoded));
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, &context);
    let mut derived = Zeroizing::new([0_u8; 32]);
    derived.copy_from_slice(tag.as_ref());
    let barrier = AeadBarrier::new(*derived)
        .map_err(|_| io::Error::other("cannot derive initialization recovery key"))?;
    Ok((barrier, context))
}

fn write_initialization_recovery(
    stage: &Path,
    seal: &SealMetadata,
    secret: &[u8; 32],
    response: &Value,
) -> Result<(), io::Error> {
    let plaintext = Zeroizing::new(serde_json::to_vec(response).map_err(io::Error::other)?);
    let (barrier, context) = initialization_recovery_barrier(secret, seal)?;
    let protected = Zeroizing::new(
        barrier
            .seal(&context, &plaintext)
            .map_err(|_| io::Error::other("cannot encrypt initialization recovery"))?,
    );
    if protected.len() as u64 > INIT_RECOVERY_LIMIT {
        return Err(io::Error::other("initialization recovery exceeds bound"));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let mut file = options.open(stage.join(INIT_RECOVERY_FILE))?;
    check_private_file(&file)?;
    file.write_all(&protected)?;
    file.sync_all()?;
    File::open(stage)?.sync_all()
}

fn read_initialization_recovery(data_dir: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, io::Error> {
    let path = data_dir.join(INIT_RECOVERY_FILE);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(io::Error::other(
                "initialization recovery symlink is forbidden",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    check_private_file(&file)?;
    if file.metadata()?.len() > INIT_RECOVERY_LIMIT {
        return Err(io::Error::other("initialization recovery exceeds bound"));
    }
    let mut protected = Zeroizing::new(Vec::new());
    file.take(INIT_RECOVERY_LIMIT + 1)
        .read_to_end(&mut protected)?;
    if protected.len() as u64 > INIT_RECOVERY_LIMIT {
        return Err(io::Error::other("initialization recovery exceeds bound"));
    }
    Ok(Some(protected))
}

fn seal_associated_data(
    schema: u32,
    generation: u64,
    share_format: &str,
    shares: u8,
    threshold: u8,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(64 + share_format.len());
    output.extend_from_slice(b"heptabao.seal-metadata.v1\0");
    output.extend_from_slice(&schema.to_le_bytes());
    output.extend_from_slice(&generation.to_le_bytes());
    output.extend_from_slice(&(share_format.len() as u64).to_le_bytes());
    output.extend_from_slice(share_format.as_bytes());
    output.extend_from_slice(&[shares, threshold]);
    output
}

fn bounded_u8_field(body: &Value, field: &str, default: u8) -> Result<u8, &'static str> {
    let Some(value) = body.get(field) else {
        return Ok(default);
    };
    let Some(value) = value.as_u64() else {
        return Err("share configuration fields must be unsigned integers");
    };
    u8::try_from(value).map_err(|_| "share configuration field exceeds supported range")
}

fn decode_key_material(encoded: &str) -> Result<Vec<u8>, &'static str> {
    if encoded.is_empty() || encoded.len() > 1024 {
        return Err("invalid bounded key encoding");
    }
    if encoded.len().is_multiple_of(2) && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return decode_hex(encoded).ok_or("invalid hexadecimal key encoding");
    }
    STANDARD
        .decode(encoded)
        .map_err(|_| "key must be hexadecimal or standard base64")
}

fn collect_seal_key(
    seal: &SealMetadata,
    encoded: &str,
    provided: &mut BTreeMap<u8, SecretShare>,
) -> Result<Option<[u8; 32]>, &'static str> {
    let decoded = Zeroizing::new(decode_key_material(encoded)?);
    if seal.share_format == "raw-v1" {
        let key: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| "invalid legacy unseal key length")?;
        return Ok(Some(key));
    }
    let share = SecretShare::decode(decoded.as_slice())?;
    if share.total() != seal.secret_shares || share.threshold() != seal.secret_threshold {
        return Err("Shamir share does not match this seal generation");
    }
    if let Some(existing) = provided.get(&share.index()) {
        if existing != &share {
            return Err("conflicting Shamir share index");
        }
    } else {
        provided.insert(share.index(), share);
    }
    if provided.len() < usize::from(seal.secret_threshold) {
        return Ok(None);
    }
    let selected = provided
        .values()
        .take(usize::from(seal.secret_threshold))
        .cloned()
        .collect::<Vec<_>>();
    crypto::combine_shares(&selected).map(Some)
}

fn load_seal_metadata(data_dir: &Path) -> Result<Option<SealMetadata>, &'static str> {
    let path = data_dir.join(SEAL_METADATA_FILE);
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cannot safely open seal metadata"),
    };
    check_private_file(&file).map_err(|_| "seal metadata must be a private regular file")?;
    if file
        .metadata()
        .map_err(|_| "cannot inspect seal metadata")?
        .len()
        > SEAL_METADATA_LIMIT
    {
        return Err("seal metadata exceeds the supported bound");
    }
    let mut encoded = Zeroizing::new(Vec::new());
    file.take(SEAL_METADATA_LIMIT + 1)
        .read_to_end(&mut encoded)
        .map_err(|_| "cannot read seal metadata")?;
    if encoded.len() as u64 > SEAL_METADATA_LIMIT {
        return Err("seal metadata exceeds the supported bound");
    }
    let metadata: SealMetadata =
        serde_json::from_slice(&encoded).map_err(|_| "invalid seal metadata")?;
    metadata.validate()?;
    Ok(Some(metadata))
}

fn load_pending_rekey(
    data_dir: &Path,
    active: Option<&SealMetadata>,
) -> Result<Option<PendingRekeyMetadata>, &'static str> {
    let path = data_dir.join(PENDING_REKEY_FILE);
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cannot safely open pending rekey metadata"),
    };
    check_private_file(&file)
        .map_err(|_| "pending rekey metadata must be a private regular file")?;
    if file
        .metadata()
        .map_err(|_| "cannot inspect pending rekey metadata")?
        .len()
        > REKEY_METADATA_LIMIT
    {
        return Err("pending rekey metadata exceeds the supported bound");
    }
    let mut encoded = Zeroizing::new(Vec::new());
    file.take(REKEY_METADATA_LIMIT + 1)
        .read_to_end(&mut encoded)
        .map_err(|_| "cannot read pending rekey metadata")?;
    if encoded.len() as u64 > REKEY_METADATA_LIMIT {
        return Err("pending rekey metadata exceeds the supported bound");
    }
    let pending: PendingRekeyMetadata =
        serde_json::from_slice(&encoded).map_err(|_| "invalid pending rekey metadata")?;
    pending.validate_shape()?;
    let active = active.ok_or("pending rekey exists without active seal metadata")?;
    if &pending.candidate == active {
        delete_pending_rekey(data_dir)
            .map_err(|_| "cannot reconcile completed pending rekey marker")?;
        return Ok(None);
    }
    if pending.active_generation != active.generation {
        return Err("pending rekey does not match the active seal generation");
    }
    Ok(Some(pending))
}

fn persist_pending_rekey(
    data_dir: &Path,
    pending: &PendingRekeyMetadata,
) -> Result<(), std::io::Error> {
    pending.validate_shape().map_err(std::io::Error::other)?;
    private_directory(data_dir)?;
    let encoded = Zeroizing::new(
        serde_json::to_vec(pending)
            .map_err(|_| std::io::Error::other("cannot encode pending rekey metadata"))?,
    );
    if encoded.len() as u64 > REKEY_METADATA_LIMIT {
        return Err(std::io::Error::other(
            "pending rekey metadata exceeds supported bound",
        ));
    }
    let suffix = hex(&crypto::random::<8>().map_err(std::io::Error::other)?);
    let temporary = data_dir.join(format!(".seal-rekey.{suffix}.next"));
    let final_path = data_dir.join(PENDING_REKEY_FILE);
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        let mut file = options.open(&temporary)?;
        check_private_file(&file)?;
        file.write_all(encoded.as_slice())?;
        file.sync_all()?;
        fs::rename(&temporary, &final_path)?;
        File::open(data_dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn delete_pending_rekey(data_dir: &Path) -> Result<(), std::io::Error> {
    match fs::remove_file(data_dir.join(PENDING_REKEY_FILE)) {
        Ok(()) => File::open(data_dir)?.sync_all(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn valid_nonce(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_recovery_reference(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn persist_seal_metadata(data_dir: &Path, seal: &SealMetadata) -> Result<(), std::io::Error> {
    seal.validate().map_err(std::io::Error::other)?;
    private_directory(data_dir)?;
    let encoded = Zeroizing::new(
        serde_json::to_vec(seal)
            .map_err(|_| std::io::Error::other("cannot encode seal metadata"))?,
    );
    if encoded.len() as u64 > SEAL_METADATA_LIMIT {
        return Err(std::io::Error::other(
            "seal metadata exceeds supported bound",
        ));
    }
    let suffix = hex(&crypto::random::<8>().map_err(std::io::Error::other)?);
    let temporary = data_dir.join(format!(".seal.{}.{}.next", seal.generation, suffix));
    let final_path = data_dir.join(SEAL_METADATA_FILE);
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        let mut file = options.open(&temporary)?;
        check_private_file(&file)?;
        file.write_all(encoded.as_slice())?;
        file.sync_all()?;
        fs::rename(&temporary, &final_path)?;
        File::open(data_dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn private_directory(path: &Path) -> Result<(), std::io::Error> {
    if path.exists() {
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(std::io::Error::other("unsafe directory"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(std::io::Error::other("directory is not private"));
            }
        }
    } else {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path)?;
    }
    Ok(())
}
fn valid_namespace(value: &str) -> bool {
    value.is_empty()
        || (value.len() <= 1024
            && value.split('/').all(|s| {
                !s.is_empty()
                    && !matches!(s, "." | "..")
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            }))
}
fn valid_path(value: &str) -> bool {
    value.len() <= 4096
        && !value.contains("//")
        && !value.starts_with('/')
        && value.trim_end_matches('/').split('/').all(|s| {
            !s.is_empty()
                && !matches!(s, "." | "..")
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        })
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            std::str::from_utf8(p)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditUnsigned {
    schema: u32,
    sequence: u64,
    previous: String,
    time: u64,
    kind: String,
    path_digest: String,
    status: Option<u16>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditRecord {
    event: AuditUnsigned,
    mac: String,
}

fn check_private_file(file: &File) -> Result<(), std::io::Error> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(std::io::Error::other("file is not private"));
        }
    }
    Ok(())
}

fn load_audit_key(audit_path: &Path, audit: &File) -> Result<hmac::Key, &'static str> {
    use std::io::Read;
    let name = audit_path
        .file_name()
        .ok_or("invalid audit path")?
        .to_string_lossy();
    let key_path = audit_path.with_file_name(format!("{name}.hmac-key"));
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let material = match options.open(&key_path) {
        Ok(mut file) => {
            check_private_file(&file).map_err(|_| "audit key must be a private regular file")?;
            if file
                .metadata()
                .map_err(|_| "cannot inspect audit key")?
                .len()
                != 32
            {
                return Err("invalid audit key size");
            }
            let mut material = Zeroizing::new([0_u8; 32]);
            file.read_exact(material.as_mut())
                .map_err(|_| "cannot read audit key")?;
            material
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if audit.metadata().map_err(|_| "cannot inspect audit")?.len() != 0 {
                return Err(
                    "existing audit has no authentication key; explicit migration required",
                );
            }
            let material = Zeroizing::new(crypto::random::<32>()?);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
            }
            let mut file = options
                .open(&key_path)
                .map_err(|_| "cannot exclusively create audit key")?;
            file.write_all(material.as_ref())
                .and_then(|()| file.sync_all())
                .map_err(|_| "cannot persist audit key")?;
            File::open(audit_path.parent().ok_or("invalid audit parent")?)
                .and_then(|file| file.sync_all())
                .map_err(|_| "cannot sync audit directory")?;
            material
        }
        Err(_) => return Err("cannot safely open audit key"),
    };
    Ok(hmac::Key::new(hmac::HMAC_SHA256, material.as_ref()))
}

fn verify_audit_from(
    audit: &mut File,
    key: &hmac::Key,
    mut sequence: u64,
    mut previous: [u8; 32],
) -> Result<(u64, [u8; 32]), &'static str> {
    use std::io::{Read, Seek, SeekFrom};
    if audit.metadata().map_err(|_| "cannot inspect audit")?.len() > MAX_AUDIT_BYTES {
        return Err("audit capacity exceeded");
    }
    audit
        .seek(SeekFrom::Start(0))
        .map_err(|_| "cannot seek audit")?;
    let mut bytes = Vec::new();
    audit
        .take(MAX_AUDIT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read audit")?;
    if bytes.len() as u64 > MAX_AUDIT_BYTES || !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err("audit is truncated or oversized; preserve evidence for recovery");
    }
    if bytes.windows(2).any(|pair| pair == b"\n\n") || bytes.starts_with(b"\n") {
        return Err("audit contains empty records");
    }
    for line in bytes
        .split(|b| *b == b'\n')
        .take_while(|line| !line.is_empty())
    {
        let record: AuditRecord = serde_json::from_slice(line)
            .map_err(|_| "unsupported or corrupt authenticated audit format")?;
        if record.event.schema != 2
            || Some(record.event.sequence) != sequence.checked_add(1)
            || record.event.previous != STANDARD.encode(previous)
        {
            return Err("audit chain is inconsistent");
        }
        let tag = STANDARD
            .decode(&record.mac)
            .map_err(|_| "invalid audit authenticator")?;
        if tag.len() != 32 {
            return Err("invalid audit authenticator length");
        }
        let payload = serde_json::to_vec(&record.event).map_err(|_| "invalid audit payload")?;
        hmac::verify(key, &payload, &tag).map_err(|_| "audit authentication failed")?;
        previous.copy_from_slice(&tag);
        sequence = record.event.sequence;
    }
    Ok((sequence, previous))
}

pub(crate) fn erase_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => {
            for value in values {
                erase_json(value);
            }
        }
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                erase_json(&mut value);
            }
        }
        _ => {}
    }
    *value = Value::Null;
}

#[cfg(test)]
mod cow_owner_tests {
    use super::CowOwner;
    use std::collections::BTreeMap;

    #[test]
    fn serialization_is_transparent_and_mutation_detaches() -> Result<(), Box<dyn std::error::Error>>
    {
        let plain = BTreeMap::from([("alpha".to_owned(), "one".to_owned())]);
        let owner = CowOwner::from(plain.clone());
        let encoded_owner = serde_json::to_vec(&owner)?;
        let encoded_plain = serde_json::to_vec(&plain)?;
        assert_eq!(encoded_owner, encoded_plain);

        let mut fork = owner.clone();
        fork.insert("beta".to_owned(), "two".to_owned());
        assert_eq!(owner.len(), 1);
        assert_eq!(fork.len(), 2);

        let decoded: CowOwner<BTreeMap<String, String>> = serde_json::from_slice(&encoded_owner)?;
        assert_eq!(&*decoded, &plain);
        Ok(())
    }
}

#[cfg(test)]
mod ha_health_status_tests {
    use super::health_status;

    #[test]
    fn health_never_reports_active_without_current_linearizable_authority() {
        assert_eq!(health_status(true, false, false, false, false, true), 200);
        assert_eq!(health_status(true, false, false, true, false, true), 200);
        assert_eq!(health_status(true, false, false, true, true, false), 429);
        assert_eq!(health_status(true, false, false, true, false, false), 503);
        assert_eq!(health_status(true, true, false, true, false, true), 503);
        assert_eq!(health_status(true, false, true, true, false, true), 503);
        assert_eq!(health_status(false, false, false, true, false, false), 501);
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "wrapping_service_tests.rs"]
mod wrapping_service_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "capabilities_service_tests.rs"]
mod capabilities_service_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "ssh_service_tests.rs"]
mod ssh_service_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "pki_service_tests.rs"]
mod pki_service_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "openapi_service_tests.rs"]
mod openapi_service_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "auth_mount_ttl_tests.rs"]
mod auth_mount_ttl_tests;

#[cfg(test)]
#[path = "service_state_store_integration_tests.rs"]
mod state_store_integration_tests;

#[path = "service_capacity.rs"]
mod capacity;
#[cfg(test)]
#[path = "service_capacity_tests.rs"]
mod capacity_tests;

#[cfg(test)]
#[path = "service_immutable_read_tests.rs"]
mod immutable_read_tests;
