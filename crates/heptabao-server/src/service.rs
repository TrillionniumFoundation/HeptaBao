use crate::{
    auth::{AuthState, Principal},
    crypto::{self, AeadBarrier, SecretShare},
    engines::EngineState,
    ha::HaProcess,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use heptabao_durable_service::{
    DurableService, PutRequest, ReconciliationStatus, Secret, ServiceError,
};
use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_STATE_BYTES: usize = 768 * 1024;
const MAX_OPERATIONS: usize = 32_000;
const MAX_AUDIT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_SEAL_SHARES: u8 = 16;
const SEAL_METADATA_FILE: &str = "seal.json";
const PENDING_REKEY_FILE: &str = "seal-rekey.json";
const SEAL_METADATA_LIMIT: u64 = 64 * 1024;
const REKEY_METADATA_LIMIT: u64 = 96 * 1024;
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: u32,
    cluster_id: String,
    auth: AuthState,
    engines: EngineState,
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

struct RequestDispatch<'a> {
    method: &'a str,
    path: &'a str,
    namespace: &'a str,
    token: &'a str,
    body: Value,
    now: u64,
    allow_forward: bool,
}

struct RequestView<'a> {
    method: &'a str,
    path: &'a str,
    namespace: &'a str,
    token: &'a str,
    body: &'a Value,
    now: u64,
    allow_forward: bool,
}

pub struct Service {
    data_dir: PathBuf,
    audit: File,
    audit_key: hmac::Key,
    audit_sequence: u64,
    audit_previous: [u8; 32],
    audit_failed: bool,
    durable: Option<DurableService<AeadBarrier>>,
    state: Option<State>,
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
    /// The TLS private key and audit file belong outside the exclusively owned
    /// data directory. The directory is never initialized implicitly on serve.
    pub fn new(data_dir: PathBuf, audit_path: &Path) -> Result<Self, &'static str> {
        Self::new_inner(data_dir, audit_path, None)
    }

    pub fn new_with_ha(
        data_dir: PathBuf,
        audit_path: &Path,
        ha: Arc<Mutex<HaProcess>>,
    ) -> Result<Self, &'static str> {
        Self::new_inner(data_dir, audit_path, Some(ha))
    }

    fn new_inner(
        data_dir: PathBuf,
        audit_path: &Path,
        ha: Option<Arc<Mutex<HaProcess>>>,
    ) -> Result<Self, &'static str> {
        if !data_dir.is_absolute() || !audit_path.is_absolute() || audit_path.starts_with(&data_dir)
        {
            return Err("data and audit paths must be absolute and separate");
        }
        if fs::symlink_metadata(audit_path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("audit symlinks are forbidden");
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true).read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(0o400000 | 0o2000000 | 0o4000);
        }
        let mut audit = options
            .open(audit_path)
            .map_err(|_| "cannot open private audit file")?;
        check_private_file(&audit).map_err(|_| "audit file must be a private regular file")?;
        audit
            .try_lock()
            .map_err(|_| "audit writer is already active or locking is unavailable")?;
        let audit_key = load_audit_key(audit_path, &audit)?;
        let (audit_sequence, audit_previous) = verify_audit(&mut audit, &audit_key)?;
        File::open(audit_path.parent().ok_or("invalid audit parent")?)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "cannot sync audit directory")?;
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
            data_dir,
            audit,
            audit_key,
            audit_sequence,
            audit_previous,
            audit_failed: false,
            durable: None,
            state: None,
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
        self.handle_at_mode(RequestDispatch {
            method,
            path,
            namespace,
            token,
            body,
            now,
            allow_forward: true,
        })
    }

    pub(crate) fn handle_forwarded(
        &mut self,
        method: &str,
        path: &str,
        namespace: &str,
        token: &str,
        body: Value,
    ) -> Response {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        self.handle_at_mode(RequestDispatch {
            method,
            path,
            namespace,
            token,
            body,
            now,
            allow_forward: false,
        })
    }

    fn handle_at_mode(&mut self, request: RequestDispatch<'_>) -> Response {
        let RequestDispatch {
            method,
            path,
            namespace,
            token,
            mut body,
            now,
            allow_forward,
        } = request;
        let fingerprint = self.request_fingerprint(method, path, namespace, token);
        if self
            .audit_event("request", &fingerprint, now, None)
            .is_err()
        {
            erase_json(&mut body);
            return Response::error(503, "audit unavailable before entry");
        }
        if path == "sys/init" && matches!(method, "PUT" | "POST") {
            let (response, response_audited) = self.initialize(&body, now, &fingerprint);
            erase_json(&mut body);
            if !response_audited
                && self
                    .audit_event("response", &fingerprint, now, Some(response.status))
                    .is_err()
            {
                self.recovery_required = self.initialized();
                return Response::error(503, "initialization response audit unavailable");
            }
            return response;
        }
        let response = self.handle_inner(RequestView {
            method,
            path,
            namespace,
            token,
            body: &body,
            now,
            allow_forward,
        });
        erase_json(&mut body);
        if self
            .audit_event("response", &fingerprint, now, Some(response.status))
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

    fn handle_inner(&mut self, request: RequestView<'_>) -> Response {
        let RequestView {
            method,
            path,
            namespace,
            token,
            body,
            now,
            allow_forward,
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
                        .forward_request(method, path, namespace, token, body)
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

        let Some(mut admitted) = self.state.clone() else {
            return Response::error(503, "server is sealed");
        };
        let principal = if token.is_empty() {
            None
        } else {
            match admitted.auth.authenticate(token, now) {
                Ok(principal) => Some(principal),
                Err(error) => return Response::error(error.status, &error.message),
            }
        };
        if principal.as_ref().is_some_and(Principal::consumed_use) {
            if let Err(error) = self.commit_state(&admitted) {
                return error;
            }
            self.state = Some(admitted.clone());
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
        if matches!(path, "sys/rekey/init" | "sys/rekey/update") {
            if !principal.as_ref().is_some_and(Principal::is_root) {
                return Response::error(403, "permission denied");
            }
            return self.rekey_route(method, path, body);
        }
        if path.starts_with("sys/internal/recovery/")
            || matches!(
                path,
                "sys/storage/raft/compact"
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
        let before = match serde_json::to_vec(&admitted) {
            Ok(v) => Zeroizing::new(v),
            Err(_) => return Response::error(500, "state serialization failed"),
        };
        let response = Self::dispatch(&mut admitted, principal, namespace, method, path, body, now);
        let serialized = match serde_json::to_vec(&admitted) {
            Ok(v) => Zeroizing::new(v),
            Err(_) => return Response::error(500, "state serialization failed"),
        };
        if *serialized != *before {
            if let Err(error) = self.commit_state_bytes(&serialized) {
                return error;
            }
            self.state = Some(admitted);
        }
        response
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
        let mut auth = state.auth.clone();
        match auth.handle(principal, namespace, method, path, body, now) {
            Ok(Some(response)) => {
                if response.mutated {
                    state.auth = auth;
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
            .required_capability(namespace, method, path)
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

    fn commit_state(&mut self, state: &State) -> Result<(), Response> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(state)
                .map_err(|_| Response::error(500, "state serialization failed"))?,
        );
        self.commit_state_bytes(&bytes)
    }

    fn commit_state_bytes(&mut self, bytes: &[u8]) -> Result<(), Response> {
        #[cfg(not(test))]
        let capacity = MAX_STATE_BYTES;
        #[cfg(test)]
        let capacity = self.state_capacity;
        if bytes.len() > capacity {
            return Err(Response::error(507, "state capacity exhausted"));
        }
        let base_digest = self.current_state_digest()?;
        self.persist(bytes, base_digest)
    }

    fn current_state_digest(&self) -> Result<[u8; 32], Response> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "server is sealed"))?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(state)
                .map_err(|_| Response::error(500, "state serialization failed"))?,
        );
        Ok(crypto::digest(&bytes))
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
        if self.initialized() {
            return (Response::error(400, "already initialized"), false);
        }
        if body.as_object().is_none_or(|object| {
            object
                .keys()
                .any(|key| !matches!(key.as_str(), "secret_shares" | "secret_threshold"))
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
            schema: 1,
            cluster_id,
            auth,
            engines: EngineState::default(),
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
        let value = match Secret::new(bytes.to_vec()) {
            Ok(value) => value,
            Err(_) => return (Response::error(507, "state capacity exhausted"), false),
        };
        let request = match PutRequest::new(
            "heptabao-server",
            "system",
            hex(&operation_id),
            "state",
            crypto::digest(&bytes),
            value,
        ) {
            Ok(value) => value,
            Err(_) => {
                return (
                    Response::error(500, "invalid server commit envelope"),
                    false,
                );
            }
        };
        if durable.put(request).is_err() {
            return (
                Response::error(503, "staged initialization state was rejected"),
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
            if let Some(object) = response.body.as_object_mut() {
                object.insert(
                    "warnings".into(),
                    json!(["initialization published but parent directory sync requires recovery review"]),
                );
            }
        }
        (response, true)
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
        let durable = DurableService::reopen(&self.data_dir, barrier, MAX_OPERATIONS)
            .map_err(|_| Response::error(400, "unseal or recovery failed"))?;
        let bytes = durable
            .get("system", "state")
            .map_err(|_| Response::error(503, "server state is unavailable"))?
            .ok_or_else(|| Response::error(503, "server state is absent; recovery required"))?;
        let state: State = serde_json::from_slice(bytes.expose())
            .map_err(|_| Response::error(503, "server state schema is invalid"))?;
        if state.schema != 1 {
            return Err(Response::error(503, "unsupported server state schema"));
        }
        self.durable = Some(durable);
        self.state = Some(state);
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
        let bytes = self
            .durable
            .as_ref()
            .ok_or_else(|| Response::error(503, "server is sealed"))?
            .get("system", "state")
            .map_err(|_| Response::error(503, "server state is unavailable"))?
            .ok_or_else(|| Response::error(503, "server state is absent; recovery required"))?;
        let state: State = serde_json::from_slice(bytes.expose())
            .map_err(|_| Response::error(503, "server state schema is invalid"))?;
        if state.schema != 1 {
            return Err(Response::error(503, "unsupported server state schema"));
        }
        self.state = Some(state);
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

    fn persist(&mut self, bytes: &[u8], base_digest: [u8; 32]) -> Result<(), Response> {
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
        match self.persist_local(bytes, &operation_id) {
            Ok(()) => Ok(()),
            Err(error) => {
                if self.ha.is_some() {
                    self.recovery_required = true;
                }
                Err(error)
            }
        }
    }

    fn persist_local(&mut self, bytes: &[u8], operation_id: &str) -> Result<(), Response> {
        let value = Secret::new(bytes.to_vec())
            .map_err(|_| Response::error(507, "state capacity exhausted"))?;
        let request = PutRequest::new(
            "heptabao-server",
            "system",
            operation_id,
            "state",
            crypto::digest(bytes),
            value,
        )
        .map_err(|_| Response::error(500, "invalid server commit envelope"))?;
        let durable = self
            .durable
            .as_mut()
            .ok_or_else(|| Response::error(503, "server is sealed"))?;
        match durable.put(request) {
            Ok(_) => Ok(()),
            Err(ServiceError::OutcomeUnknown { recovery_reference }) => {
                self.recovery_required = true;
                Err(Response {
                    status: 503,
                    body: json!({"errors":["durable outcome unknown; do not blindly retry"],"recovery_reference":recovery_reference}),
                })
            }
            Err(_) => Err(Response::error(
                503,
                "durable state rejected; no response released",
            )),
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
        if state.schema != 1 {
            return Err(Response::error(
                503,
                "unsupported HA committed state schema",
            ));
        }
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
        self.persist_local(&committed.bytes, &operation_id)?;
        self.state = Some(state);
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
        let mut bytes = serde_json::to_vec(&AuditRecord {
            event: unsigned,
            mac: STANDARD.encode(tag.as_ref()),
        })?;
        bytes.push(b'\n');
        let length = self.audit.metadata()?.len();
        #[cfg(not(test))]
        let capacity = MAX_AUDIT_BYTES;
        #[cfg(test)]
        let capacity = self.audit_capacity;
        if length
            .checked_add(bytes.len() as u64)
            .is_none_or(|n| n > capacity)
        {
            return Err(std::io::Error::other("audit capacity exhausted"));
        }
        if let Err(error) = self
            .audit
            .write_all(&bytes)
            .and_then(|()| self.audit.sync_all())
        {
            self.audit_failed = true;
            return Err(error);
        }
        self.audit_sequence = sequence;
        self.audit_previous.copy_from_slice(tag.as_ref());
        Ok(())
    }
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
        options.custom_flags(0o400000 | 0o2000000 | 0o4000);
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
        options.custom_flags(0o400000 | 0o2000000 | 0o4000);
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
                .custom_flags(0o400000 | 0o2000000 | 0o4000);
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
                .custom_flags(0o400000 | 0o2000000 | 0o4000);
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
        options.custom_flags(0o400000 | 0o2000000 | 0o4000);
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
                    .custom_flags(0o400000 | 0o2000000 | 0o4000);
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

fn verify_audit(audit: &mut File, key: &hmac::Key) -> Result<(u64, [u8; 32]), &'static str> {
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
    let mut sequence = 0_u64;
    let mut previous = [0_u8; 32];
    for line in bytes
        .split(|b| *b == b'\n')
        .take_while(|line| !line.is_empty())
    {
        let record: AuditRecord = serde_json::from_slice(line)
            .map_err(|_| "unsupported or corrupt authenticated audit format")?;
        if record.event.schema != 2
            || record.event.sequence != sequence + 1
            || record.event.previous != STANDARD.encode(previous)
        {
            return Err("audit chain is inconsistent");
        }
        let tag = STANDARD
            .decode(&record.mac)
            .map_err(|_| "invalid audit authenticator")?;
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
