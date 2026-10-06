//! Official SDK logical backends through an owned Go AutoMTLS companion.
//!
//! The companion's stdio is internal IPC. The plugin receives the unchanged
//! OpenBao SDK v5 Backend and Storage gRPC protocol. This first adapter supports
//! secret backend CRUD; catalog, HTTP mounting, leases and auth are separate.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustix::fs::OFlags;
use rustix::process::{Pid, Signal};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use crate::OwnedExecutableImage;

const MAX_FRAME: usize = 1024 * 1024;
const MAX_VALUE: usize = 256 * 1024;
const MAX_STORAGE_CALLS: usize = 4096;

/// Registered lease metadata supplied by the owning Service writer. These
/// values carry SDK callback input only and never create caller authority.
pub struct SdkLeaseCallback {
    pub secret: Value,
    pub issue_time_ns: u64,
    pub increment_ns: u64,
}
impl std::fmt::Debug for SdkLeaseCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SdkLeaseCallback([REDACTED])")
    }
}
impl Drop for SdkLeaseCallback {
    fn drop(&mut self) {
        wipe_json(&mut self.secret);
    }
}
pub struct SdkLogicalRequest<'a> {
    pub operation: &'a str,
    pub path: &'a str,
    pub data: Value,
    pub lease: Option<SdkLeaseCallback>,
}
impl std::fmt::Debug for SdkLogicalRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SdkLogicalRequest([REDACTED])")
    }
}
impl Drop for SdkLogicalRequest<'_> {
    fn drop(&mut self) {
        wipe_json(&mut self.data);
    }
}
struct SensitiveJson(Value);
impl std::ops::Deref for SensitiveJson {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}
impl std::ops::DerefMut for SensitiveJson {
    fn deref_mut(&mut self) -> &mut Value {
        &mut self.0
    }
}
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        wipe_json(&mut self.0);
    }
}
fn wipe_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => {
            for value in values {
                wipe_json(value)
            }
        }
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                wipe_json(&mut value)
            }
        }
        _ => {}
    }
    *value = Value::Null;
}

#[derive(Clone, Eq, PartialEq)]
pub struct SdkStorageEntry {
    pub key: String,
    pub value: Zeroizing<Vec<u8>>,
    pub seal_wrap: bool,
}
impl std::fmt::Debug for SdkStorageEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SdkStorageEntry([REDACTED])")
    }
}

/// The caller supplies a mount-scoped view with its own durable commit policy.
/// Implementations must observe this same deadline; it is never renewed by IPC.
pub trait SdkStorage {
    fn get(
        &mut self,
        key: &str,
        deadline: Instant,
    ) -> Result<Option<SdkStorageEntry>, SdkBridgeError>;
    fn put(&mut self, entry: SdkStorageEntry, deadline: Instant) -> Result<(), SdkBridgeError>;
    fn delete(&mut self, key: &str, deadline: Instant) -> Result<(), SdkBridgeError>;
    fn list_page(
        &mut self,
        prefix: &str,
        after: &str,
        limit: i64,
        deadline: Instant,
    ) -> Result<Vec<String>, SdkBridgeError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdkBridgeError {
    BeforeEntry,
    OutcomeUnknown,
    Storage,
    Backend,
    Fenced,
}
impl std::fmt::Display for SdkBridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SDK bridge {:?}", self)
    }
}
impl std::error::Error for SdkBridgeError {}

/// Backend family admitted by the owning Service catalog. A plugin's reported
/// family can only confirm this value and never grants token authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdkBackendType {
    Secret,
    Auth,
}
impl SdkBackendType {
    fn label(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Auth => "auth",
        }
    }
}

#[derive(Clone)]
pub struct SdkLaunch {
    pub companion: PathBuf,
    pub companion_sha256: [u8; 32],
    pub plugin: PathBuf,
    pub plugin_sha256: [u8; 32],
    pub plugin_args: Vec<String>,
    pub socket_directory: PathBuf,
    pub private_log: PathBuf,
    pub timeout: Duration,
    pub default_ttl_seconds: u32,
    pub max_ttl_seconds: u32,
}
impl std::fmt::Debug for SdkLaunch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SdkLaunch([REDACTED])")
    }
}

/// Serial ownership keeps call IDs, storage callbacks and process fate bound.
pub struct SdkBackendHost {
    child: Option<Child>,
    pid: Pid,
    input: ChildStdin,
    output: ChildStdout,
    buffered: Zeroizing<Vec<u8>>,
    _companion: OwnedExecutableImage,
    _plugin: OwnedExecutableImage,
    _socket: File,
    _thread_owner: PhantomData<Rc<()>>,
    timeout: Duration,
    backend_type: SdkBackendType,
    auth_paths: Option<Value>,
    call: u64,
    storage_rpc: u64,
    fenced: bool,
}
impl std::fmt::Debug for SdkBackendHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SdkBackendHost")
            .field("fenced", &self.fenced)
            .finish_non_exhaustive()
    }
}

impl SdkBackendHost {
    /// Launch from a persistent ownership thread. Linux binds owner death to
    /// the spawning thread; that thread must outlive the host's terminal wait.
    pub fn launch(
        config: &SdkLaunch,
        storage: &mut dyn SdkStorage,
    ) -> Result<Self, SdkBridgeError> {
        Self::launch_before(config, storage, Instant::now() + config.timeout)
    }

    pub fn launch_before(
        config: &SdkLaunch,
        storage: &mut dyn SdkStorage,
        original_deadline: Instant,
    ) -> Result<Self, SdkBridgeError> {
        Self::launch_typed_before(config, storage, SdkBackendType::Secret, original_deadline)
    }

    pub fn launch_typed_before(
        config: &SdkLaunch,
        storage: &mut dyn SdkStorage,
        backend_type: SdkBackendType,
        original_deadline: Instant,
    ) -> Result<Self, SdkBridgeError> {
        if Instant::now() >= original_deadline {
            return Err(SdkBridgeError::BeforeEntry);
        }
        if config.timeout.is_zero()
            || config.timeout > Duration::from_secs(30)
            || config.default_ttl_seconds > config.max_ttl_seconds
            || config.plugin_args.len() > 64
            || config
                .plugin_args
                .iter()
                .any(|s| s.len() > 4096 || s.contains('\0'))
        {
            return Err(SdkBridgeError::BeforeEntry);
        }
        let socket = std::fs::symlink_metadata(&config.socket_directory)
            .map_err(|_| SdkBridgeError::BeforeEntry)?;
        if !socket.is_dir() || socket.mode() & 0o077 != 0 || !config.socket_directory.is_absolute()
        {
            return Err(SdkBridgeError::BeforeEntry);
        }
        // A descriptor alias keeps long caller paths inside Linux's Unix
        // socket address limit and binds the actual admitted private directory.
        let mut socket_options = OpenOptions::new();
        socket_options.read(true).custom_flags(
            (OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK)
                .bits()
                .try_into()
                .map_err(|_| SdkBridgeError::BeforeEntry)?,
        );
        let socket_directory = socket_options
            .open(&config.socket_directory)
            .map_err(|_| SdkBridgeError::BeforeEntry)?;
        let bound_socket = socket_directory
            .metadata()
            .map_err(|_| SdkBridgeError::BeforeEntry)?;
        if bound_socket.dev() != socket.dev()
            || bound_socket.ino() != socket.ino()
            || bound_socket.mode() & 0o077 != 0
            || !bound_socket.is_dir()
            || bound_socket.uid() != rustix::process::getuid().as_raw()
        {
            return Err(SdkBridgeError::BeforeEntry);
        }
        #[cfg(target_os = "linux")]
        let socket_alias = {
            let proc_self =
                std::fs::read_link("/proc/self").map_err(|_| SdkBridgeError::BeforeEntry)?;
            if proc_self.components().count() != 1
                || proc_self
                    .to_str()
                    .is_none_or(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()))
            {
                return Err(SdkBridgeError::BeforeEntry);
            }
            format!(
                "/proc/{}/fd/{}",
                proc_self.display(),
                socket_directory.as_raw_fd()
            )
        };
        #[cfg(target_os = "macos")]
        let socket_alias = ".".to_owned();
        #[cfg(target_os = "linux")]
        let companion = OwnedExecutableImage::open(&config.companion, config.companion_sha256)
            .map_err(|_| SdkBridgeError::BeforeEntry)?;
        #[cfg(target_os = "linux")]
        let plugin = OwnedExecutableImage::open(&config.plugin, config.plugin_sha256)
            .map_err(|_| SdkBridgeError::BeforeEntry)?;
        #[cfg(target_os = "macos")]
        let companion = OwnedExecutableImage::open_in(
            &config.companion,
            config.companion_sha256,
            &config.socket_directory,
        )
        .map_err(|_| SdkBridgeError::BeforeEntry)?;
        #[cfg(target_os = "macos")]
        let plugin = OwnedExecutableImage::open_in(
            &config.plugin,
            config.plugin_sha256,
            &config.socket_directory,
        )
        .map_err(|_| SdkBridgeError::BeforeEntry)?;
        #[cfg(target_os = "macos")]
        {
            companion
                .verify()
                .map_err(|_| SdkBridgeError::BeforeEntry)?;
            plugin.verify().map_err(|_| SdkBridgeError::BeforeEntry)?;
        }
        let log = private_log(&config.private_log)?;
        let deadline = original_deadline.min(Instant::now() + config.timeout);
        let mut command = companion.command();
        command
            .env_clear()
            .env("TMPDIR", &socket_alias)
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log));
        #[cfg(target_os = "linux")]
        heptabao_linux_parent_death::bind_owner_death(&mut command);
        #[cfg(target_os = "macos")]
        heptabao_linux_parent_death::bind_private_directory(&mut command, &socket_directory)
            .map_err(|_| SdkBridgeError::BeforeEntry)?;
        #[cfg(target_os = "macos")]
        let owned_images = {
            let cfd = heptabao_linux_parent_death::inherit_owned_file(
                &mut command,
                companion.original_file(),
            )
            .map_err(|_| SdkBridgeError::BeforeEntry)?;
            let pfd = heptabao_linux_parent_death::inherit_owned_file(
                &mut command,
                plugin.original_file(),
            )
            .map_err(|_| SdkBridgeError::BeforeEntry)?;
            let (cdev, cino, csize) = companion.cleanup_identity();
            let (pdev, pino, psize) = plugin.cleanup_identity();
            let images = json!([
                {"role":"companion","path":companion.descriptor_path(),"fd":cfd,
                 "device":cdev,"inode":cino,"bytes":csize,"sha256":hex_encode(&config.companion_sha256)},
                {"role":"plugin","path":plugin.descriptor_path(),"fd":pfd,
                 "device":pdev,"inode":pino,"bytes":psize,"sha256":hex_encode(&config.plugin_sha256)}
            ]);
            command.env("HBP_SDK_OWNED_IMAGES", images.to_string());
            images
        };
        let child = command.spawn().map_err(|_| SdkBridgeError::BeforeEntry)?;
        let mut pending = PendingChild(Some(child));
        let child = pending.0.as_mut().ok_or(SdkBridgeError::OutcomeUnknown)?;
        let pid =
            Pid::from_raw(i32::try_from(child.id()).map_err(|_| SdkBridgeError::OutcomeUnknown)?)
                .ok_or(SdkBridgeError::OutcomeUnknown)?;
        let input = child.stdin.take().ok_or(SdkBridgeError::OutcomeUnknown)?;
        let output = child.stdout.take().ok_or(SdkBridgeError::OutcomeUnknown)?;
        let mut host = Self {
            child: pending.0.take(),
            pid,
            input,
            output,
            buffered: Zeroizing::new(Vec::new()),
            _companion: companion,
            _plugin: plugin,
            _socket: socket_directory,
            _thread_owner: PhantomData,
            timeout: config.timeout,
            backend_type,
            auth_paths: None,
            call: 1,
            storage_rpc: 0,
            fenced: false,
        };
        nonblocking(&host.input)?;
        nonblocking(&host.output)?;
        let setup = json!({"version":1,"kind":"setup","call":1,"backend_type":backend_type.label(),
            "plugin":host._plugin.descriptor_path(),"args":config.plugin_args,
            "socket_dir":socket_alias,"timeout_ms":config.timeout.as_millis(),
            "default_ttl_seconds":config.default_ttl_seconds,"max_ttl_seconds":config.max_ttl_seconds});
        #[cfg(target_os = "macos")]
        let setup = {
            let mut setup = setup;
            setup["owned_images"] = owned_images;
            setup
        };
        host.send(&setup, deadline)?;
        let ready = host.exchange(storage, "ready", deadline)?;
        if ready.get("backend_type").and_then(Value::as_str) != Some(backend_type.label()) {
            return Err(SdkBridgeError::OutcomeUnknown);
        }
        if backend_type == SdkBackendType::Auth {
            host.auth_paths = Some(
                normalized_auth_paths(ready.get("auth_paths"))
                    .ok_or(SdkBridgeError::OutcomeUnknown)?,
            );
        }
        Ok(host)
    }

    /// Actual SDK SpecialPaths captured at owned Setup, without a caller grant.
    pub fn auth_special_paths(&self) -> Option<&Value> {
        self.auth_paths.as_ref()
    }

    pub fn handle_request(
        &mut self,
        operation: &str,
        path: &str,
        data: Value,
        storage: &mut dyn SdkStorage,
    ) -> Result<Option<Value>, SdkBridgeError> {
        self.handle_request_before(
            operation,
            path,
            data,
            storage,
            Instant::now() + self.timeout,
        )
    }

    pub fn handle_request_before(
        &mut self,
        operation: &str,
        path: &str,
        data: Value,
        storage: &mut dyn SdkStorage,
        original_deadline: Instant,
    ) -> Result<Option<Value>, SdkBridgeError> {
        self.handle_logical_request_before(
            SdkLogicalRequest {
                operation,
                path,
                data,
                lease: None,
            },
            storage,
            original_deadline,
        )
    }

    pub fn handle_logical_request_before(
        &mut self,
        mut logical: SdkLogicalRequest<'_>,
        storage: &mut dyn SdkStorage,
        original_deadline: Instant,
    ) -> Result<Option<Value>, SdkBridgeError> {
        let operation = logical.operation;
        let path = logical.path;
        if Instant::now() >= original_deadline {
            return Err(SdkBridgeError::BeforeEntry);
        }
        if self.fenced {
            return Err(SdkBridgeError::Fenced);
        }
        let operation_valid = match &logical.lease {
            None => matches!(
                operation,
                "read" | "create" | "update" | "patch" | "delete" | "list" | "scan"
            ),
            Some(lease) => {
                matches!(operation, "renew" | "revoke")
                    && lease.secret.is_object()
                    && lease.issue_time_ns > 0
                    && lease.issue_time_ns <= i64::MAX as u64
                    && lease.increment_ns <= i64::MAX as u64
            }
        };
        if !operation_valid
            || path.is_empty()
            || path.len() > 4096
            || path.contains('\0')
            || !logical.data.is_object()
        {
            return Err(SdkBridgeError::BeforeEntry);
        }
        self.call = self.call.checked_add(1).ok_or(SdkBridgeError::Fenced)?;
        let deadline = original_deadline.min(Instant::now() + self.timeout);
        let mut request = SensitiveJson(json!({"version":1,"kind":"request","call":self.call,
            "operation":operation,"path":path}));
        request["data"] = std::mem::take(&mut logical.data);
        if let Some(mut lease) = logical.lease.take() {
            request["secret"] = std::mem::take(&mut lease.secret);
            request["issue_time_ns"] = json!(lease.issue_time_ns);
            request["increment_ns"] = json!(lease.increment_ns);
        }
        let result = (|| {
            self.send(&request, deadline)?;
            self.exchange(storage, "result", deadline)
        })();
        let result = match result {
            Ok(v) => SensitiveJson(v),
            Err(e) => {
                self.fenced = true;
                return Err(e);
            }
        };
        if result
            .get("error")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
        {
            return Err(SdkBridgeError::Backend);
        }
        let response = result.get("response").ok_or_else(|| {
            self.fenced = true;
            SdkBridgeError::OutcomeUnknown
        })?;
        if response.is_null() {
            Ok(None)
        } else {
            let auth_valid = response.get("auth").is_some_and(|value| {
                value.is_null() || self.backend_type == SdkBackendType::Auth && value.is_object()
            });
            let secret_valid = response.get("secret").is_some_and(|value| {
                value.is_null() || self.backend_type == SdkBackendType::Secret && value.is_object()
            });
            if !response.is_object() || !auth_valid || !secret_valid {
                self.fenced = true;
                return Err(SdkBridgeError::OutcomeUnknown);
            }
            Ok(Some(response.clone()))
        }
    }

    /// Cleanup completes the same owned process, without starting another one.
    pub fn close(&mut self, storage: &mut dyn SdkStorage) -> Result<(), SdkBridgeError> {
        if self.fenced {
            return Err(SdkBridgeError::Fenced);
        }
        self.call = self.call.checked_add(1).ok_or(SdkBridgeError::Fenced)?;
        let deadline = Instant::now() + self.timeout;
        let result = (|| {
            self.send(
                &json!({"version":1,"kind":"close","call":self.call}),
                deadline,
            )?;
            self.exchange(storage, "closed", deadline)?;
            loop {
                if Instant::now() >= deadline {
                    return Err(SdkBridgeError::OutcomeUnknown);
                }
                let child = self.child.as_mut().ok_or(SdkBridgeError::OutcomeUnknown)?;
                match child
                    .try_wait()
                    .map_err(|_| SdkBridgeError::OutcomeUnknown)?
                {
                    Some(status) if status.success() => {
                        self.child = None;
                        return Ok(());
                    }
                    Some(_) => {
                        self.child = None;
                        return Err(SdkBridgeError::OutcomeUnknown);
                    }
                    None => pause(deadline),
                }
            }
        })();
        self.fenced = true;
        result
    }

    fn exchange(
        &mut self,
        storage: &mut dyn SdkStorage,
        expected: &str,
        deadline: Instant,
    ) -> Result<Value, SdkBridgeError> {
        for _ in 0..=MAX_STORAGE_CALLS {
            let message = self.receive(deadline)?;
            if message.get("version").and_then(Value::as_u64) != Some(1)
                || message.get("call").and_then(Value::as_u64) != Some(self.call)
            {
                return Err(SdkBridgeError::OutcomeUnknown);
            }
            let kind = message
                .get("kind")
                .and_then(Value::as_str)
                .ok_or(SdkBridgeError::OutcomeUnknown)?;
            if kind == expected {
                return Ok(message);
            }
            if kind != "storage" {
                return Err(SdkBridgeError::OutcomeUnknown);
            }
            let rpc = message
                .get("rpc")
                .and_then(Value::as_u64)
                .ok_or(SdkBridgeError::OutcomeUnknown)?;
            if self.storage_rpc.checked_add(1) != Some(rpc) {
                return Err(SdkBridgeError::OutcomeUnknown);
            }
            self.storage_rpc = rpc;
            let mut reply = json!({"version":1,"kind":"storage_reply","call":self.call,"rpc":rpc});
            match storage_callback(storage, &message, deadline) {
                Ok(value) => {
                    reply
                        .as_object_mut()
                        .ok_or(SdkBridgeError::OutcomeUnknown)?
                        .extend(
                            value
                                .as_object()
                                .ok_or(SdkBridgeError::OutcomeUnknown)?
                                .clone(),
                        );
                }
                Err(error @ (SdkBridgeError::OutcomeUnknown | SdkBridgeError::Fenced)) => {
                    // A plugin may swallow a Storage RPC error. An uncertain
                    // host mutation must therefore terminate this exchange
                    // and fence the host, regardless of the plugin's result.
                    self.fenced = true;
                    return Err(error);
                }
                Err(_) => {
                    reply["error"] = json!("host storage rejected operation");
                }
            }
            if Instant::now() >= deadline {
                return Err(SdkBridgeError::OutcomeUnknown);
            }
            self.send(&reply, deadline)?;
        }
        Err(SdkBridgeError::OutcomeUnknown)
    }

    fn send(&mut self, value: &Value, deadline: Instant) -> Result<(), SdkBridgeError> {
        let mut frame =
            Zeroizing::new(serde_json::to_vec(value).map_err(|_| SdkBridgeError::BeforeEntry)?);
        if frame.len() > MAX_FRAME {
            return Err(SdkBridgeError::BeforeEntry);
        }
        frame.push(b'\n');
        let mut offset = 0;
        while offset < frame.len() {
            if Instant::now() >= deadline {
                return Err(SdkBridgeError::OutcomeUnknown);
            }
            match self.input.write(&frame[offset..]) {
                Ok(0) => return Err(SdkBridgeError::OutcomeUnknown),
                Ok(n) => offset += n,
                Err(e) if retryable(&e) => pause(deadline),
                Err(_) => return Err(SdkBridgeError::OutcomeUnknown),
            }
        }
        Ok(())
    }
    fn receive(&mut self, deadline: Instant) -> Result<Value, SdkBridgeError> {
        let mut buffer = Zeroizing::new([0u8; 8192]);
        loop {
            if Instant::now() >= deadline {
                return Err(SdkBridgeError::OutcomeUnknown);
            }
            if let Some(end) = self.buffered.iter().position(|b| *b == b'\n') {
                let message = serde_json::from_slice(&self.buffered[..end])
                    .map_err(|_| SdkBridgeError::OutcomeUnknown)?;
                self.buffered.drain(..=end);
                return Ok(message);
            }
            match self.output.read(&mut buffer[..]) {
                Ok(0) => return Err(SdkBridgeError::OutcomeUnknown),
                Ok(n) => {
                    if self.buffered.len() + n > MAX_FRAME + 1 {
                        return Err(SdkBridgeError::OutcomeUnknown);
                    }
                    self.buffered.extend_from_slice(&buffer[..n]);
                }
                Err(e) if retryable(&e) => pause(deadline),
                Err(_) => return Err(SdkBridgeError::OutcomeUnknown),
            }
        }
    }
}

struct PendingChild(Option<Child>);
impl Drop for PendingChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            if let Some(pid) = i32::try_from(child.id()).ok().and_then(Pid::from_raw) {
                let _ = rustix::process::kill_process_group(pid, Signal::KILL);
            }
            let _ = child.kill();
            reap_owned(child);
        }
    }
}

impl Drop for SdkBackendHost {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = rustix::process::kill_process_group(self.pid, Signal::KILL);
            let _ = child.kill();
            reap_owned(child);
        }
    }
}
fn reap_owned(mut child: Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    // A failed thread spawn drops its closure. Keep another owner outside that
    // closure so the exact Child remains recoverable and can still be reaped.
    let held = Arc::new(Mutex::new(Some(child)));
    let background = Arc::clone(&held);
    let result = std::thread::Builder::new()
        .name("heptabao-sdk-reaper".into())
        .spawn(move || {
            let child = background.lock().unwrap_or_else(|p| p.into_inner()).take();
            if let Some(mut child) = child {
                let _ = child.wait();
            }
        });
    if result.is_err() {
        let child = held.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(mut child) = child {
            let _ = child.wait();
        }
    }
}
fn private_log(path: &Path) -> Result<File, SdkBridgeError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| SdkBridgeError::BeforeEntry)
}
fn nonblocking(fd: &impl AsFd) -> Result<(), SdkBridgeError> {
    let flags = rustix::fs::fcntl_getfl(fd).map_err(|_| SdkBridgeError::OutcomeUnknown)?;
    rustix::fs::fcntl_setfl(fd, flags | OFlags::NONBLOCK)
        .map_err(|_| SdkBridgeError::OutcomeUnknown)
}
fn retryable(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    )
}
fn pause(deadline: Instant) {
    std::thread::sleep(
        Duration::from_millis(1).min(deadline.saturating_duration_since(Instant::now())),
    )
}
fn text<'a>(m: &'a Value, key: &str) -> Result<&'a str, SdkBridgeError> {
    m.get(key)
        .and_then(Value::as_str)
        .ok_or(SdkBridgeError::Storage)
}
fn hex_encode(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}
fn hex_decode(value: &str) -> Result<Zeroizing<Vec<u8>>, SdkBridgeError> {
    if value.len() > MAX_VALUE * 2 || !value.len().is_multiple_of(2) {
        return Err(SdkBridgeError::Storage);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| {
            std::str::from_utf8(c)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .ok_or(SdkBridgeError::Storage)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Zeroizing::new)
}
fn storage_callback(
    storage: &mut dyn SdkStorage,
    m: &Value,
    deadline: Instant,
) -> Result<Value, SdkBridgeError> {
    let method = text(m, "method")?;
    let key = m.get("key").and_then(Value::as_str).unwrap_or("");
    if key.len() > 4096
        || key.contains('\0')
        || (key.is_empty() && !matches!(method, "list" | "list_page"))
    {
        return Err(SdkBridgeError::Storage);
    }
    if Instant::now() >= deadline {
        return Err(SdkBridgeError::Storage);
    }
    match method {
        "get" => match storage.get(key, deadline)? {
            None => Ok(json!({"entry":null})),
            Some(entry) if entry.key == key && entry.value.len() <= MAX_VALUE => Ok(
                json!({"entry":{"key":entry.key,"value_hex":hex_encode(&entry.value),"seal_wrap":entry.seal_wrap}}),
            ),
            Some(_) => Err(SdkBridgeError::Storage),
        },
        "put" => {
            let e = m.get("entry").ok_or(SdkBridgeError::Storage)?;
            if text(e, "key")? != key {
                return Err(SdkBridgeError::Storage);
            }
            let entry = SdkStorageEntry {
                key: key.to_owned(),
                value: hex_decode(text(e, "value_hex")?)?,
                seal_wrap: e
                    .get("seal_wrap")
                    .and_then(Value::as_bool)
                    .ok_or(SdkBridgeError::Storage)?,
            };
            storage.put(entry, deadline)?;
            Ok(json!({}))
        }
        "delete" => {
            storage.delete(key, deadline)?;
            Ok(json!({}))
        }
        "list" | "list_page" => {
            let after = m.get("after").and_then(Value::as_str).unwrap_or("");
            let limit = m.get("limit").and_then(Value::as_i64).unwrap_or(0);
            let keys = storage.list_page(key, after, limit, deadline)?;
            if keys.len() > 10000 || keys.iter().any(|s| s.len() > 4096 || s.contains('\0')) {
                return Err(SdkBridgeError::Storage);
            }
            Ok(json!({"keys":keys}))
        }
        _ => Err(SdkBridgeError::Storage),
    }
}

// Auth100 currently implements one exact public login route and ordinary
// authenticated paths. SDK special root/local/seal-wrap/forwarded semantics
// must never be silently dropped during admission of an arbitrary backend.
fn normalized_auth_paths(value: Option<&Value>) -> Option<Value> {
    let value = value?;
    if value.is_null() {
        return Some(
            json!({"Root":[],"Unauthenticated":[],"LocalStorage":[],"SealWrapStorage":[],"WriteForwardedStorage":[]}),
        );
    }
    let paths = value.as_object()?;
    if paths.len() != 5
        || paths.keys().any(|key| {
            !matches!(
                key.as_str(),
                "Root"
                    | "Unauthenticated"
                    | "LocalStorage"
                    | "SealWrapStorage"
                    | "WriteForwardedStorage"
            )
        })
    {
        return None;
    }
    let mut normalized = serde_json::Map::new();
    for key in [
        "Root",
        "Unauthenticated",
        "LocalStorage",
        "SealWrapStorage",
        "WriteForwardedStorage",
    ] {
        let raw = paths.get(key)?;
        let values: Vec<String> = if raw.is_null() {
            Vec::new()
        } else {
            serde_json::from_value(raw.clone()).ok()?
        };
        if !heptabao_plugin_contracts::sdk_paths::valid(&values)
            || (!matches!(key, "Root" | "Unauthenticated") && !values.is_empty())
        {
            return None;
        }
        normalized.insert(key.into(), json!(values));
    }
    Some(Value::Object(normalized))
}
#[cfg(test)]
mod auth_paths_tests {
    use super::*;
    #[test]
    fn actual_sdk_auth_special_paths_cannot_mint_public_or_drop_root_scope() {
        let admitted = json!({"Root":["config"],"Unauthenticated":["login","public/+/*"],"LocalStorage":null,"SealWrapStorage":null,"WriteForwardedStorage":null});
        let Some(actual) = normalized_auth_paths(Some(&admitted)) else {
            panic!("literal valid policy")
        };
        assert_eq!(actual["Root"], json!(["config"]));
        assert_eq!(actual["Unauthenticated"], json!(["login", "public/+/*"]));
        let Some(private) = normalized_auth_paths(Some(&Value::Null)) else {
            panic!("private policy")
        };
        assert_eq!(private["Unauthenticated"], json!([]));
        for field in ["LocalStorage", "SealWrapStorage", "WriteForwardedStorage"] {
            let mut rejected = admitted.clone();
            rejected[field] = json!(["config"]);
            assert!(normalized_auth_paths(Some(&rejected)).is_none());
        }
        let mut malformed = admitted.clone();
        malformed["Unauthenticated"] = json!(["foo+bar"]);
        assert!(normalized_auth_paths(Some(&malformed)).is_none());
        assert!(normalized_auth_paths(None).is_none());
    }
}
