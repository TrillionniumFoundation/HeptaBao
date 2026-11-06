#![forbid(unsafe_code)]
//! A bounded, synthetic-only local credential broker.
//!
//! The owner issues MAC-authenticated grants for one exact request. The agent
//! interface never returns API credentials or upstream response bytes. An
//! external request is journaled before dispatch; any unresolved dispatch stays
//! unknown across restart and is never repeated. The operating-system account
//! is the trust boundary: this is not isolation from other processes of that
//! same account, nor a HeptaRuntime workload-identity attestation.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use heptabao_filesystem_guard::{
    ExclusiveDirectory, FileAccess, open_absolute_directory_no_symlinks,
};
use ring::{
    digest, hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::os::unix::{
    fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    net::{UnixListener, UnixStream},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File},
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_MESSAGE: usize = 128 * 1024;
const MAX_BODY: usize = 32 * 1024;
const MAX_STATE: usize = 4 * 1024 * 1024;
const MAX_OPERATIONS: usize = 4096;
const MAX_TTL: u64 = 3600;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const SOCKET_NAME: &str = "broker.sock";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub &'static str);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
fn io<T>(r: std::io::Result<T>) -> Result<T> {
    r.map_err(|_| Error("io_failure"))
}
fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error("invalid_json"))
}
fn parse<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| Error("invalid_json"))
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error("clock_invalid"))
}
fn random_id() -> Result<String> {
    let mut b = [0u8; 32];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| Error("random_failure"))?;
    Ok(URL_SAFE_NO_PAD.encode(b))
}
fn hash(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, bytes).as_ref())
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn private_metadata(m: &fs::Metadata, directory: bool) -> Result<()> {
    if m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o077 != 0
        || if directory {
            !m.is_dir()
        } else {
            !m.is_file() || m.nlink() != 1
        }
    {
        return Err(Error("private_owner_required"));
    }
    Ok(())
}
fn private_dir(path: &Path) -> Result<File> {
    let f = open_absolute_directory_no_symlinks(path).map_err(|_| Error("unsafe_directory"))?;
    private_metadata(&io(f.metadata())?, true)?;
    Ok(f)
}
fn private_read_at(dir: &File, name: &str, cap: usize) -> Result<Zeroizing<Vec<u8>>> {
    let fd = rustix::fs::openat(
        dir,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| Error("private_read_failed"))?;
    let f = File::from(fd);
    let m = io(f.metadata())?;
    private_metadata(&m, false)?;
    if m.len() > cap as u64 {
        return Err(Error("input_too_large"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    io(f.take(cap as u64 + 1).read_to_end(&mut bytes))?;
    if bytes.len() > cap {
        return Err(Error("input_too_large"));
    }
    Ok(bytes)
}
fn create_at(dir: &ExclusiveDirectory, name: &str, bytes: &[u8]) -> Result<()> {
    let mut f = dir
        .open_file(name, FileAccess::CreateNew)
        .map_err(|_| Error("create_failed"))?;
    io(f.write_all(bytes))?;
    io(f.sync_all())?;
    dir.sync_all().map_err(|_| Error("sync_failed"))
}
fn atomic_save(dir: &ExclusiveDirectory, name: &str, bytes: &[u8]) -> Result<()> {
    let temp = format!("tmp-{}", random_id()?);
    create_at(dir, &temp, bytes)?;
    dir.rename(&temp, name)
        .map_err(|_| Error("publication_unknown"))?;
    dir.sync_all().map_err(|_| Error("publication_unknown"))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub id: String,
    /// Exactly `loopback_http` or `git_sshsig`; no implicit real-network mode.
    pub kind: String,
    /// HTTP: http://127.0.0.1:port or http://[::1]:port. Git: git:repository-id.
    pub target: String,
    pub method: String,
    pub path: String,
    /// Synthetic bearer token or an unencrypted synthetic OpenSSH private key.
    pub secret: String,
}
impl Drop for Credential {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("secret", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub synthetic_only: bool,
    pub credentials: Vec<Credential>,
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: u32,
    broker_id: String,
    synthetic_only: bool,
    credentials: Vec<Credential>,
}

fn endpoint(target: &str) -> Result<SocketAddr> {
    let value = target
        .strip_prefix("http://")
        .ok_or(Error("unsupported_target"))?;
    let address: SocketAddr = value.parse().map_err(|_| Error("unsupported_target"))?;
    if !address.ip().is_loopback() || address.port() == 0 || format!("http://{address}") != target {
        return Err(Error("unsupported_target"));
    }
    Ok(address)
}
fn validate_credential(c: &Credential) -> Result<()> {
    if !identifier(&c.id) {
        return Err(Error("invalid_credential"));
    }
    match c.kind.as_str() {
        "loopback_http" => {
            endpoint(&c.target)?;
            if !matches!(c.method.as_str(), "GET" | "POST" | "PUT" | "DELETE")
                || !c.path.starts_with('/')
                || c.path.len() > 1024
                || c.path.contains("//")
                || c.path.contains("..")
                || c.path
                    .bytes()
                    .any(|b| !(b.is_ascii_alphanumeric() || b"/-_.".contains(&b)))
                || c.secret.is_empty()
                || c.secret.len() > 4096
                || c.secret.bytes().any(|b| !(33..=126).contains(&b))
            {
                return Err(Error("invalid_http_policy"));
            }
        }
        "git_sshsig" => {
            if c.target.strip_prefix("git:").is_none_or(|s| !identifier(s))
                || c.method != "SIGN"
                || c.path != "git"
                || c.secret.len() > 16 * 1024
            {
                return Err(Error("invalid_git_policy"));
            }
            let key = ssh_key::PrivateKey::from_openssh(&c.secret)
                .map_err(|_| Error("invalid_signing_key"))?;
            if key.is_encrypted() || key.algorithm() != ssh_key::Algorithm::Ed25519 {
                return Err(Error("unsupported_signing_key"));
            }
        }
        _ => return Err(Error("unsupported_credential_kind")),
    }
    Ok(())
}

pub fn initialize(root: &Path, bootstrap: Bootstrap) -> Result<()> {
    if !root.is_absolute()
        || !bootstrap.synthetic_only
        || bootstrap.credentials.is_empty()
        || bootstrap.credentials.len() > 64
    {
        return Err(Error("synthetic_scope_required"));
    }
    let mut ids = BTreeSet::new();
    for c in &bootstrap.credentials {
        validate_credential(c)?;
        if !ids.insert(c.id.clone()) {
            return Err(Error("duplicate_credential"));
        }
    }
    io(fs::DirBuilder::new().mode(0o700).create(root))?;
    let _check = private_dir(root)?;
    let dir = ExclusiveDirectory::open(root).map_err(|_| Error("writer_busy"))?;
    let key = Zeroizing::new(random_id()?.into_bytes());
    let config = Config {
        schema: 1,
        broker_id: random_id()?,
        synthetic_only: true,
        credentials: bootstrap.credentials,
    };
    create_at(&dir, "owner.key", &key)?;
    create_at(&dir, "config.json", &Zeroizing::new(json(&config)?))?;
    let state = State {
        schema: 1,
        broker_id: config.broker_id,
        observed_wall: now()?,
        revoked: BTreeSet::new(),
        operations: BTreeMap::new(),
    };
    create_at(&dir, "state.json", &json(&state)?)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub operation_id: String,
    pub task_id: String,
    pub run_id: String,
    pub credential_id: String,
    pub target: String,
    pub method: String,
    pub path: String,
    pub body_base64: String,
}
impl Operation {
    fn checked_body(&self) -> Result<Zeroizing<Vec<u8>>> {
        if [
            &self.operation_id,
            &self.task_id,
            &self.run_id,
            &self.credential_id,
        ]
        .iter()
        .any(|s| !identifier(s))
            || self.body_base64.len() > MAX_BODY * 2
        {
            return Err(Error("invalid_operation"));
        }
        let body = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(&self.body_base64)
                .map_err(|_| Error("invalid_body"))?,
        );
        if body.len() > MAX_BODY || URL_SAFE_NO_PAD.encode(body.as_slice()) != self.body_base64 {
            return Err(Error("invalid_body"));
        }
        Ok(body)
    }
    fn binding(&self) -> Result<String> {
        self.checked_body()?;
        Ok(hash(&json(self)?))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    schema: u32,
    pub grant_id: String,
    broker_id: String,
    policy_mac: String,
    pub task_id: String,
    pub run_id: String,
    pub operation_id: String,
    request_digest: String,
    issued_at: u64,
    pub expires_at: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGrant {
    pub grant: Grant,
    signature: String,
}
fn mac(key: &[u8], domain: &[u8], bytes: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut c = hmac::Context::with_key(&key);
    c.update(domain);
    c.update(bytes);
    URL_SAFE_NO_PAD.encode(c.sign().as_ref())
}
fn verify_mac(key: &[u8], domain: &[u8], bytes: &[u8], signature: &str) -> Result<()> {
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| Error("authorization_denied"))?;
    let mut message = Vec::with_capacity(domain.len() + bytes.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(bytes);
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, key),
        &message,
        &signature,
    )
    .map_err(|_| Error("authorization_denied"))
}
const GRANT_DOMAIN: &[u8] = b"heptabao-broker-grant-v1\0";
const REVOKE_DOMAIN: &[u8] = b"heptabao-broker-revoke-v1\0";

struct Owner {
    config: Config,
    key: Zeroizing<Vec<u8>>,
    policy_mac: String,
}
impl Owner {
    fn open(root: &Path) -> Result<Self> {
        let dir = private_dir(root)?;
        let key = private_read_at(&dir, "owner.key", 128)?;
        if key.len() != 43 || URL_SAFE_NO_PAD.decode(&key).is_err() {
            return Err(Error("invalid_owner_key"));
        }
        let bytes = private_read_at(&dir, "config.json", MAX_MESSAGE)?;
        let config: Config = parse(&bytes)?;
        if config.schema != 1
            || !config.synthetic_only
            || config.credentials.is_empty()
            || config.credentials.len() > 64
            || !identifier(&config.broker_id)
        {
            return Err(Error("synthetic_scope_required"));
        }
        let mut ids = BTreeSet::new();
        for c in &config.credentials {
            validate_credential(c)?;
            if !ids.insert(&c.id) {
                return Err(Error("duplicate_credential"));
            }
        }
        let policy_mac = mac(&key, b"heptabao-broker-policy-v1\0", &bytes);
        Ok(Self {
            config,
            key,
            policy_mac,
        })
    }
    fn credential<'a>(&'a self, op: &Operation) -> Result<&'a Credential> {
        let c = self
            .config
            .credentials
            .iter()
            .find(|c| c.id == op.credential_id)
            .ok_or(Error("policy_denied"))?;
        if c.target != op.target || c.method != op.method || c.path != op.path {
            return Err(Error("policy_denied"));
        }
        Ok(c)
    }
}
/// Owner-only issuer. The subject labels are bound to a real owner-issued MAC;
/// they are not independently attested HeptaRuntime task identities.
pub fn issue(root: &Path, operation: &Operation, ttl: u64) -> Result<SignedGrant> {
    if ttl == 0 || ttl > MAX_TTL {
        return Err(Error("invalid_ttl"));
    }
    let owner = Owner::open(root)?;
    owner.credential(operation)?;
    let issued_at = now()?;
    let grant = Grant {
        schema: 1,
        grant_id: random_id()?,
        broker_id: owner.config.broker_id.clone(),
        policy_mac: owner.policy_mac.clone(),
        task_id: operation.task_id.clone(),
        run_id: operation.run_id.clone(),
        operation_id: operation.operation_id.clone(),
        request_digest: operation.binding()?,
        issued_at,
        expires_at: issued_at.checked_add(ttl).ok_or(Error("clock_invalid"))?,
    };
    let signature = mac(&owner.key, GRANT_DOMAIN, &json(&grant)?);
    Ok(SignedGrant { grant, signature })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    broker_id: String,
    pub grant_id: String,
    expires_at: u64,
    signature: String,
}
pub fn authorize_revocation(root: &Path, grant: &SignedGrant) -> Result<Revocation> {
    let owner = Owner::open(root)?;
    verify_mac(
        &owner.key,
        GRANT_DOMAIN,
        &json(&grant.grant)?,
        &grant.signature,
    )?;
    if grant.grant.broker_id != owner.config.broker_id {
        return Err(Error("authorization_denied"));
    }
    let mut r = Revocation {
        broker_id: owner.config.broker_id,
        grant_id: grant.grant.grant_id.clone(),
        expires_at: now()?.checked_add(300).ok_or(Error("clock_invalid"))?,
        signature: String::new(),
    };
    r.signature = mac(
        &owner.key,
        REVOKE_DOMAIN,
        &json(&(&r.broker_id, &r.grant_id, r.expires_at))?,
    );
    Ok(r)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Execute {
        grant: SignedGrant,
        operation: Operation,
    },
    Status {
        grant: SignedGrant,
        operation: Operation,
    },
    Revoke {
        revocation: Revocation,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: String,
    pub outcome: String,
    pub http_status: Option<u16>,
    /// HTTP response classification only; application success is not inferred.
    pub http_success: Option<bool>,
    pub signature_pem: Option<String>,
    pub public_key: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    request_digest: String,
    grant_id: String,
    receipt: Receipt,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: u32,
    broker_id: String,
    observed_wall: u64,
    revoked: BTreeSet<String>,
    operations: BTreeMap<String, Entry>,
}

pub struct Broker {
    root: PathBuf,
    dir: ExclusiveDirectory,
    owner: Owner,
    state: State,
    started: Instant,
    started_wall: u64,
    failed: bool,
}
impl fmt::Debug for Broker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Broker")
            .field("secrets", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
impl Broker {
    pub fn open(root: &Path) -> Result<Self> {
        let checked = private_dir(root)?;
        let dir = ExclusiveDirectory::open(root).map_err(|_| Error("writer_busy"))?;
        let owner = Owner::open(root)?;
        let state: State = parse(&private_read_at(&checked, "state.json", MAX_STATE)?)?;
        if state.schema != 1
            || state.broker_id != owner.config.broker_id
            || state.operations.len() > MAX_OPERATIONS
            || state.revoked.len() > MAX_OPERATIONS
        {
            return Err(Error("invalid_state"));
        }
        let current = now()?;
        if current < state.observed_wall {
            return Err(Error("clock_regression"));
        }
        Ok(Self {
            root: root.to_path_buf(),
            dir,
            owner,
            state,
            started: Instant::now(),
            started_wall: current,
            failed: false,
        })
    }
    fn current(&mut self) -> Result<u64> {
        if self.failed {
            return Err(Error("recovery_required"));
        }
        // A backward wall jump cannot extend a lease while this process lives.
        let wall = now()?;
        let monotonic = self
            .started_wall
            .saturating_add(self.started.elapsed().as_secs());
        if wall < self.state.observed_wall || wall.saturating_add(1) < monotonic {
            self.failed = true;
            return Err(Error("clock_regression"));
        }
        self.state.observed_wall = wall.max(monotonic);
        Ok(self.state.observed_wall)
    }
    fn save(&mut self) -> Result<()> {
        let bytes = json(&self.state)?;
        if bytes.len() > MAX_STATE {
            self.failed = true;
            return Err(Error("ledger_full"));
        }
        if let Err(e) = atomic_save(&self.dir, "state.json", &bytes) {
            self.failed = true;
            return Err(e);
        }
        Ok(())
    }
    fn admit(&mut self, g: &SignedGrant, op: &Operation) -> Result<String> {
        let current = self.current()?;
        let grant = &g.grant;
        verify_mac(&self.owner.key, GRANT_DOMAIN, &json(grant)?, &g.signature)?;
        let binding = op.binding()?;
        if grant.schema != 1
            || grant.broker_id != self.owner.config.broker_id
            || grant.policy_mac != self.owner.policy_mac
            || grant.task_id != op.task_id
            || grant.run_id != op.run_id
            || grant.operation_id != op.operation_id
            || grant.request_digest != binding
            || grant.issued_at > current
            || grant.expires_at <= current
            || grant.expires_at.saturating_sub(grant.issued_at) > MAX_TTL
            || self.state.revoked.contains(&grant.grant_id)
        {
            return Err(Error("authorization_denied"));
        }
        self.owner.credential(op)?;
        Ok(binding)
    }
    pub fn handle(&mut self, request: Request) -> Result<Receipt> {
        match request {
            Request::Revoke { revocation: r } => {
                let current = self.current()?;
                verify_mac(
                    &self.owner.key,
                    REVOKE_DOMAIN,
                    &json(&(&r.broker_id, &r.grant_id, r.expires_at))?,
                    &r.signature,
                )?;
                if r.broker_id != self.owner.config.broker_id
                    || r.expires_at <= current
                    || self.state.revoked.len() >= MAX_OPERATIONS
                {
                    return Err(Error("authorization_denied"));
                }
                self.state.revoked.insert(r.grant_id);
                self.save()?;
                Ok(Receipt {
                    operation_id: String::new(),
                    outcome: "revoked".into(),
                    http_status: None,
                    http_success: None,
                    signature_pem: None,
                    public_key: None,
                })
            }
            Request::Status { grant, operation } => {
                let binding = self.admit(&grant, &operation)?;
                self.lookup(&operation.operation_id, &binding, &grant.grant.grant_id)?
                    .ok_or(Error("operation_not_found"))
            }
            Request::Execute { grant, operation } => {
                let binding = self.admit(&grant, &operation)?;
                if let Some(result) =
                    self.lookup(&operation.operation_id, &binding, &grant.grant.grant_id)?
                {
                    return Ok(result);
                }
                if self.state.operations.len() >= MAX_OPERATIONS {
                    return Err(Error("ledger_full"));
                }
                let pending = Receipt {
                    operation_id: operation.operation_id.clone(),
                    outcome: "outcome_unknown".into(),
                    http_status: None,
                    http_success: None,
                    signature_pem: None,
                    public_key: None,
                };
                self.state.operations.insert(
                    operation.operation_id.clone(),
                    Entry {
                        request_digest: binding,
                        grant_id: grant.grant.grant_id.clone(),
                        receipt: pending.clone(),
                    },
                );
                // Persistence is mandatory BEFORE any target contact or signature.
                self.save()?;
                // Revalidate after durable admission immediately before use.
                self.admit(&grant, &operation)?;
                let credential = self.owner.credential(&operation)?;
                let result = execute(credential, &operation).unwrap_or(pending);
                if let Some(entry) = self.state.operations.get_mut(&operation.operation_id) {
                    entry.receipt = result.clone();
                } else {
                    self.failed = true;
                    return Err(Error("recovery_required"));
                }
                self.save()?;
                Ok(result)
            }
        }
    }
    fn lookup(&self, id: &str, binding: &str, grant_id: &str) -> Result<Option<Receipt>> {
        match self.state.operations.get(id) {
            Some(entry) if entry.request_digest == binding && entry.grant_id == grant_id => {
                Ok(Some(entry.receipt.clone()))
            }
            Some(_) => Err(Error("operation_identity_conflict")),
            None => Ok(None),
        }
    }
    /// One serial writer; no request can race revocation through another worker.
    /// `max_requests` is useful for bounded qualification and supervised runs.
    pub fn serve(mut self, max_requests: usize) -> Result<()> {
        if max_requests == 0 || max_requests > MAX_OPERATIONS {
            return Err(Error("invalid_request_limit"));
        }
        let path = self.root.join(SOCKET_NAME);
        if let Ok(meta) = fs::symlink_metadata(&path) {
            use std::os::unix::fs::FileTypeExt;
            if !meta.file_type().is_socket() || meta.uid() != rustix::process::geteuid().as_raw() {
                return Err(Error("unsafe_socket"));
            }
            self.dir
                .remove_file(SOCKET_NAME)
                .map_err(|_| Error("socket_cleanup_failed"))?;
        }
        let listener = io(UnixListener::bind(&path))?;
        io(fs::set_permissions(
            &path,
            fs::Permissions::from_mode(0o600),
        ))?;
        self.dir.sync_all().map_err(|_| Error("sync_failed"))?;
        for _ in 0..max_requests {
            let (mut stream, _) = io(listener.accept())?;
            io(stream.set_read_timeout(Some(IO_TIMEOUT)))?;
            io(stream.set_write_timeout(Some(IO_TIMEOUT)))?;
            let response = match read_frame(&mut stream, IO_TIMEOUT)
                .and_then(|bytes| parse::<Request>(&bytes))
                .and_then(|request| self.handle(request))
            {
                Ok(receipt) => serde_json::json!({"ok":true,"receipt":receipt}),
                Err(error) => serde_json::json!({"ok":false,"error":error.0}),
            };
            // A lost client ACK cannot undo the already durable result.
            let _write_result = write_frame(&mut stream, &json(&response)?);
            if self.failed {
                break;
            }
        }
        drop(listener);
        self.dir
            .remove_file(SOCKET_NAME)
            .map_err(|_| Error("socket_cleanup_failed"))?;
        self.dir.sync_all().map_err(|_| Error("sync_failed"))
    }
}

fn execute(c: &Credential, op: &Operation) -> Result<Receipt> {
    let body = op.checked_body()?;
    let mut result = Receipt {
        operation_id: op.operation_id.clone(),
        outcome: "completed".into(),
        http_status: None,
        http_success: None,
        signature_pem: None,
        public_key: None,
    };
    if c.kind == "git_sshsig" {
        let key =
            ssh_key::PrivateKey::from_openssh(&c.secret).map_err(|_| Error("signing_failed"))?;
        let sig = key
            .sign("git", ssh_key::HashAlg::Sha512, &body)
            .map_err(|_| Error("signing_failed"))?;
        result.signature_pem = Some(
            sig.to_pem(ssh_key::LineEnding::LF)
                .map_err(|_| Error("signing_failed"))?,
        );
        result.public_key = Some(
            key.public_key()
                .to_openssh()
                .map_err(|_| Error("signing_failed"))?,
        );
        return Ok(result);
    }
    let address = endpoint(&c.target)?;
    let mut stream = io(TcpStream::connect_timeout(&address, IO_TIMEOUT))?;
    io(stream.set_read_timeout(Some(IO_TIMEOUT)))?;
    io(stream.set_write_timeout(Some(IO_TIMEOUT)))?;
    let host = match address.ip() {
        IpAddr::V4(ip) => format!("{ip}:{}", address.port()),
        IpAddr::V6(ip) => format!("[{ip}]:{}", address.port()),
    };
    let header = Zeroizing::new(format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        c.method,
        c.path,
        host,
        c.secret,
        body.len()
    ));
    io(stream.write_all(header.as_bytes()))?;
    io(stream.write_all(&body))?;
    // No upstream response, headers or error strings are exposed or persisted.
    // Read only the bounded status line, so an echo cannot disclose the token.
    let started = Instant::now();
    let mut line = Zeroizing::new(Vec::new());
    while line.len() < 128 {
        if started.elapsed() >= IO_TIMEOUT {
            return Err(Error("upstream_timeout"));
        }
        let mut b = [0u8; 1];
        let remaining = IO_TIMEOUT.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(Error("upstream_timeout"));
        }
        io(stream.set_read_timeout(Some(remaining)))?;
        io(stream.read_exact(&mut b))?;
        line.push(b[0]);
        if line.ends_with(b"\r\n") {
            break;
        }
    }
    if !line.ends_with(b"\r\n") {
        return Err(Error("upstream_invalid"));
    }
    let text = std::str::from_utf8(&line).map_err(|_| Error("upstream_invalid"))?;
    let parts: Vec<&str> = text.trim_end_matches("\r\n").splitn(3, ' ').collect();
    if parts.len() < 2 || !matches!(parts[0], "HTTP/1.0" | "HTTP/1.1") || parts[1].len() != 3 {
        return Err(Error("upstream_invalid"));
    }
    let status: u16 = parts[1].parse().map_err(|_| Error("upstream_invalid"))?;
    if !(200..=599).contains(&status) {
        return Err(Error("upstream_invalid"));
    }
    // 3xx is observed but never followed; no credential is sent to its Location.
    result.http_status = Some(status);
    result.http_success = Some((200..=299).contains(&status));
    Ok(result)
}
fn read_bounded(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    started: Instant,
    timeout: Duration,
) -> Result<()> {
    while !bytes.is_empty() {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(Error("request_timeout"));
        }
        io(stream.set_read_timeout(Some(remaining)))?;
        let count = io(stream.read(bytes))?;
        if count == 0 {
            return Err(Error("incomplete_frame"));
        }
        bytes = &mut bytes[count..];
    }
    Ok(())
}
fn read_frame(stream: &mut UnixStream, timeout: Duration) -> Result<Zeroizing<Vec<u8>>> {
    let started = Instant::now();
    let mut size = [0u8; 4];
    read_bounded(stream, &mut size, started, timeout)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_MESSAGE {
        return Err(Error("invalid_frame"));
    }
    let mut bytes = Zeroizing::new(vec![0; size]);
    read_bounded(stream, &mut bytes, started, timeout)?;
    Ok(bytes)
}
fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_MESSAGE {
        return Err(Error("invalid_frame"));
    }
    io(stream.write_all(&(bytes.len() as u32).to_be_bytes()))?;
    io(stream.write_all(bytes))
}
/// SDK entry. A caller supplies an owner-issued grant, not an upstream secret.
pub fn call(root: &Path, request: &Request) -> Result<serde_json::Value> {
    let _root = private_dir(root)?;
    let path = root.join(SOCKET_NAME);
    let meta = io(fs::symlink_metadata(&path))?;
    use std::os::unix::fs::FileTypeExt;
    if !meta.file_type().is_socket()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
    {
        return Err(Error("unsafe_socket"));
    }
    let mut stream = io(UnixStream::connect(path))?;
    io(stream.set_read_timeout(Some(Duration::from_secs(15))))?;
    io(stream.set_write_timeout(Some(IO_TIMEOUT)))?;
    write_frame(&mut stream, &Zeroizing::new(json(request)?))?;
    parse(&read_frame(&mut stream, Duration::from_secs(20))?)
}

/// Read a caller-selected private JSON file. No path or parser content appears
/// in failures; symlink components and shared or hard-linked files are refused.
pub fn read_private(path: &Path, cap: usize) -> Result<Zeroizing<Vec<u8>>> {
    let parent = path.parent().ok_or(Error("invalid_path"))?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or(Error("invalid_path"))?;
    private_read_at(&private_dir(parent)?, name, cap)
}
/// Create-only private output, anchored to a private owner directory.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(Error("invalid_path"))?;
    let _check = private_dir(parent)?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or(Error("invalid_path"))?;
    let dir = ExclusiveDirectory::open(parent).map_err(|_| Error("writer_busy"))?;
    create_at(&dir, name, bytes)
}
