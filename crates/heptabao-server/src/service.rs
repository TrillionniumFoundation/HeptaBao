use crate::{
    auth::{AuthState, Principal},
    crypto::{self, AeadBarrier, SecretShare},
    engines::EngineState,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use heptabao_durable_service::{DurableService, PutRequest, Secret, ServiceError};
use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_STATE_BYTES: usize = 768 * 1024;
const MAX_OPERATIONS: usize = 32_000;
const MAX_AUDIT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_SEAL_SHARES: u8 = 16;
const SEAL_METADATA_FILE: &str = "seal.json";
const SEAL_METADATA_LIMIT: u64 = 64 * 1024;

#[derive(Clone, Serialize, Deserialize)]
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

struct RekeyState {
    nonce: String,
    new_shares: u8,
    new_threshold: u8,
    provided: BTreeMap<u8, SecretShare>,
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
    #[cfg(test)]
    state_capacity: usize,
    #[cfg(test)]
    audit_capacity: u64,
}

impl Service {
    /// The TLS private key and audit file belong outside the exclusively owned
    /// data directory. The directory is never initialized implicitly on serve.
    pub fn new(data_dir: PathBuf, audit_path: &Path) -> Result<Self, &'static str> {
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
            rekey: None,
            recovery_required: false,
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

    pub fn handle_at(
        &mut self,
        method: &str,
        path: &str,
        namespace: &str,
        token: &str,
        mut body: Value,
        now: u64,
    ) -> Response {
        let fingerprint = self.request_fingerprint(method, path, namespace, token);
        // Audit every attempted route, including malformed requests, health,
        // failed authentication, initialization and wrong unseal keys. A failed
        // audit append cannot itself be audited and blocks further dispatch.
        if self
            .audit_event("request", &fingerprint, now, None)
            .is_err()
        {
            erase_json(&mut body);
            return Response::error(503, "audit unavailable before entry");
        }
        let response = self.handle_inner(method, path, namespace, token, &body, now);
        erase_json(&mut body);
        if self
            .audit_event("response", &fingerprint, now, Some(response.status))
            .is_err()
        {
            self.recovery_required = true;
            // Drop erases an initialized root token, plaintext read, login token
            // or batch ciphertext before replacing it with the uncertainty error.
            return Response::error(
                503,
                "response audit failed; outcome unknown; authoritative recovery required",
            );
        }
        response
    }

    fn handle_inner(
        &mut self,
        method: &str,
        path: &str,
        namespace: &str,
        token: &str,
        body: &Value,
        now: u64,
    ) -> Response {
        if !valid_namespace(namespace) || !valid_path(path) {
            return Response::error(400, "invalid canonical namespace or path");
        }
        if path == "sys/health" && matches!(method, "GET" | "HEAD") {
            let initialized = self.initialized();
            let sealed = self.state.is_none();
            let status = if !initialized {
                501
            } else if sealed || self.recovery_required {
                503
            } else {
                200
            };
            return Response {
                status,
                body: json!({"initialized":initialized,"sealed":sealed,"standby":false,"performance_standby":false,"replication_performance_mode":"disabled","replication_dr_mode":"disabled","server_time_utc":now,"version":"HeptaBao-0.2.0","cluster_name":"heptabao-single-node","cluster_id":self.state.as_ref().map(|s|s.cluster_id.as_str()),"ha_enabled":false,"recovery_required":self.recovery_required}),
            };
        }
        if path == "sys/init" && method == "GET" {
            return Response::ok(json!({"initialized":self.initialized()}));
        }
        if path == "sys/seal-status" && method == "GET" {
            return self.seal_status();
        }
        if path == "sys/init" && matches!(method, "PUT" | "POST") {
            return self.initialize(body, now);
        }
        if path == "sys/unseal" && matches!(method, "PUT" | "POST") {
            return self.unseal(body);
        }
        if self.state.is_none() {
            return Response::error(503, "server is sealed");
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
        // Consumption is its own durable admission transaction. In particular,
        // oversized writes, malformed engine/auth operations, ACL denial and
        // subsequent storage failures cannot restore an authenticated token use.
        if principal.as_ref().is_some_and(Principal::consumed_use) {
            if let Err(error) = self.commit_state(&admitted) {
                return error;
            }
            self.state = Some(admitted.clone());
        }
        if matches!(path, "sys/rekey/init" | "sys/rekey/update") {
            if !principal.as_ref().is_some_and(Principal::is_root) {
                return Response::error(403, "permission denied");
            }
            return self.rekey_route(method, path, body);
        }
        if path == "sys/seal" && matches!(method, "PUT" | "POST") {
            if !principal.as_ref().is_some_and(Principal::is_root) {
                return Response::error(403, "permission denied");
            }
            self.state = None;
            self.durable = None;
            self.barrier_key = None;
            self.unseal_shares.clear();
            self.rekey = None;
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
        let response = Self::dispatch(
            &mut admitted,
            principal.as_ref(),
            namespace,
            method,
            path,
            body,
            now,
        );
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
        principal: Option<&Principal>,
        namespace: &str,
        method: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Response {
        // Each subsystem operates on its own candidate. A returned Err or an
        // unsupported path discards all tentative changes, while admission
        // consumption has already been persisted independently.
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
            if let Err(error) = state.auth.authorize(principal, namespace, path, "read") {
                return Response::error(error.status, &error.message);
            }
            return Response::ok(
                json!({"ha_enabled":false,"is_self":true,"leader_address":"","leader_cluster_address":""}),
            );
        }
        if path == "sys/step-down" || path.starts_with("sys/storage/raft") {
            return Response::error(
                501,
                "Raft and failover are not implemented by the single-node profile",
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
            && let Err(error) = state.auth.authorize(principal, namespace, path, "sudo")
        {
            return Response::error(error.status, &error.message);
        }
        if let Err(error) = state.auth.authorize(principal, namespace, path, capability) {
            return Response::error(error.status, &error.message);
        }
        let mut engines = state.engines.clone();
        match engines.handle(namespace, method, path, body, now) {
            // A batch may return HTTP 400 with individually successful encrypted
            // outputs. The engine's explicit mutation flag owns that transaction.
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
            return Err(Response::error(507, "single-node state capacity exhausted"));
        }
        self.persist(bytes)
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
            "storage_type": "heptabao-durable-v2",
            "seal_generation": self.seal.as_ref().map_or(0, |seal| seal.generation),
        }))
    }

    fn initialize(&mut self, body: &Value, now: u64) -> Response {
        if self.initialized() {
            return Response::error(400, "already initialized");
        }
        if body.as_object().is_none_or(|object| {
            object
                .keys()
                .any(|key| !matches!(key.as_str(), "secret_shares" | "secret_threshold"))
        }) {
            return Response::error(400, "unsupported initialization options");
        }
        let shares = match bounded_u8_field(body, "secret_shares", 5) {
            Ok(value) => value,
            Err(message) => return Response::error(400, message),
        };
        let threshold = match bounded_u8_field(body, "secret_threshold", 3) {
            Ok(value) => value,
            Err(message) => return Response::error(400, message),
        };
        if shares == 0 || shares > MAX_SEAL_SHARES || threshold == 0 || threshold > shares {
            return Response::error(
                400,
                "secret shares must be 1..=16 and threshold must be within that set",
            );
        }

        let seal_key = match crypto::random::<32>() {
            Ok(value) => Zeroizing::new(value),
            Err(error) => return Response::error(503, error),
        };
        let barrier_key = match crypto::random::<32>() {
            Ok(value) => Zeroizing::new(value),
            Err(error) => return Response::error(503, error),
        };
        let generated_shares = match crypto::split_secret(&seal_key, shares, threshold) {
            Ok(value) => value,
            Err(error) => return Response::error(503, error),
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
                Err(error) => return Response::error(503, error),
            };
        seal.wrapped_barrier_key = STANDARD.encode(wrapped.as_slice());
        if let Err(error) = seal.validate() {
            return Response::error(500, error);
        }
        let barrier = match AeadBarrier::new(*barrier_key) {
            Ok(value) => value,
            Err(_) => return Response::error(503, "cannot construct storage provider"),
        };
        let (auth, root_token) = match AuthState::bootstrap(now) {
            Ok((auth, token)) => (auth, Zeroizing::new(token)),
            Err(error) => return Response::error(error.status, &error.message),
        };
        let cluster_id = match crypto::random::<16>() {
            Ok(value) => STANDARD.encode(value),
            Err(error) => return Response::error(503, error),
        };
        let state = State {
            schema: 1,
            cluster_id,
            auth,
            engines: EngineState::default(),
        };
        if private_directory(&self.data_dir).is_err() {
            return Response::error(503, "cannot create private data directory");
        }
        let durable = match DurableService::create_new(&self.data_dir, barrier, MAX_OPERATIONS) {
            Ok(value) => value,
            Err(_) => {
                return Response::error(
                    503,
                    "cannot initialize durable state; inspect data directory",
                );
            }
        };
        self.durable = Some(durable);
        let bytes = match serde_json::to_vec(&state) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => return Response::error(500, "state serialization failed"),
        };
        if let Err(error) = self.commit_state_bytes(&bytes) {
            return error;
        }
        if persist_seal_metadata(&self.data_dir, &seal).is_err() {
            self.recovery_required = true;
            self.state = None;
            self.durable = None;
            return Response::error(
                503,
                "seal metadata persistence failed after initialization; preserve data for recovery",
            );
        }
        self.seal = Some(seal);
        self.state = Some(state);

        let mut keys = Vec::with_capacity(generated_shares.len());
        let mut keys_base64 = Vec::with_capacity(generated_shares.len());
        for share in generated_shares {
            let encoded = Zeroizing::new(share.encode());
            keys.push(hex(&encoded));
            keys_base64.push(STANDARD.encode(encoded.as_slice()));
        }
        let response = Response::ok(json!({
            "keys": keys,
            "keys_base64": keys_base64,
            "root_token": root_token.as_str(),
            "recovery_keys": [],
            "recovery_keys_base64": [],
        }));
        self.state = None;
        self.durable = None;
        self.barrier_key = None;
        self.unseal_shares.clear();
        self.rekey = None;
        response
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
        Ok(())
    }

    fn rotate_unseal_nonce(&mut self) -> Result<(), &'static str> {
        self.unseal_nonce = hex(&crypto::random::<16>()?);
        Ok(())
    }

    fn rekey_status(&self) -> Response {
        if let Some(rekey) = &self.rekey {
            Response::ok(json!({
                "started": true,
                "nonce": rekey.nonce,
                "t": rekey.new_threshold,
                "n": rekey.new_shares,
                "progress": rekey.provided.len(),
                "required": self.seal.as_ref().map_or(1, |seal| seal.secret_threshold),
                "verification_required": false,
                "verification_nonce": "",
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
            }))
        }
    }

    fn rekey_route(&mut self, method: &str, path: &str, body: &Value) -> Response {
        if path == "sys/rekey/init" {
            if method == "GET" {
                return self.rekey_status();
            }
            if method == "DELETE" {
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
            match body.get("require_verification") {
                None | Some(Value::Bool(false)) => {}
                Some(Value::Bool(true)) => {
                    return Response::error(501, "rekey verification is not implemented");
                }
                Some(_) => return Response::error(400, "require_verification must be a boolean"),
            }
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
                provided: BTreeMap::new(),
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
        let seal = match self.seal.clone() {
            Some(value) => value,
            None => return Response::error(503, "seal metadata unavailable"),
        };
        let mut rekey = match self.rekey.take() {
            Some(value) => value,
            None => return Response::error(400, "rekey is not in progress"),
        };
        if supplied_nonce != rekey.nonce {
            self.rekey = Some(rekey);
            return Response::error(400, "rekey nonce mismatch");
        }
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
        let Some(active_key) = self.barrier_key.as_ref() else {
            self.rekey = Some(rekey);
            return Response::error(503, "server must be unsealed for rekey");
        };
        let candidate_key = hmac::Key::new(hmac::HMAC_SHA256, current_barrier_key.as_ref());
        let candidate_tag = hmac::sign(&candidate_key, b"heptabao.barrier-key-proof.v1");
        let active_key = hmac::Key::new(hmac::HMAC_SHA256, active_key.as_ref());
        if hmac::verify(
            &active_key,
            b"heptabao.barrier-key-proof.v1",
            candidate_tag.as_ref(),
        )
        .is_err()
        {
            self.rekey = Some(rekey);
            return Response::error(400, "unseal shares do not match the active barrier");
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
        if persist_seal_metadata(&self.data_dir, &next).is_err() {
            self.rekey = Some(rekey);
            return Response::error(503, "cannot durably publish new seal generation");
        }
        self.seal = Some(next);
        self.rekey = None;
        self.unseal_shares.clear();

        let mut keys = Vec::with_capacity(next_shares.len());
        let mut keys_base64 = Vec::with_capacity(next_shares.len());
        for share in next_shares {
            let encoded = Zeroizing::new(share.encode());
            keys.push(hex(&encoded));
            keys_base64.push(STANDARD.encode(encoded.as_slice()));
        }
        Response::ok(json!({
            "started": false,
            "complete": true,
            "nonce": rekey.nonce,
            "keys": keys,
            "keys_base64": keys_base64,
            "verification_required": false,
        }))
    }

    fn persist(&mut self, bytes: &[u8]) -> Result<(), Response> {
        let id = crypto::random::<16>().map_err(|e| Response::error(503, e))?;
        let value = Secret::new(bytes.to_vec())
            .map_err(|_| Response::error(507, "state capacity exhausted"))?;
        let request = PutRequest::new(
            "heptabao-server",
            "system",
            hex(&id),
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
    let temporary = data_dir.join(format!("seal.{}.next", seal.generation));
    let final_path = data_dir.join(SEAL_METADATA_FILE);
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
    File::open(data_dir)?.sync_all()?;
    Ok(())
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
#[path = "service_tests.rs"]
mod tests;
