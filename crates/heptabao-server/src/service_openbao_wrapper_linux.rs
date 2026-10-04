//! A bounded persistent runtime for one exact server-owned Wrapper launch.
//! Child wait results, rather than successful signal requests, determine cleanup.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use heptabao_openbao_grpc::automatic_tls::{
    AutomaticHandshake, AutomaticWrapperTransport, PerLaunchClientIdentity,
};
use heptabao_openbao_grpc::handshake::{KMS_MAGIC_COOKIE_KEY, KMS_MAGIC_COOKIE_VALUE};
use heptabao_openbao_grpc::linux_identity::{LinuxIdentityProbe, StartedChildBinding};
use heptabao_openbao_grpc::protocol::wrapping::RpcOptions;
use heptabao_openbao_grpc::{
    BridgeError, IdentityProbe, OpaqueBlobInfo, OpenBaoGrpcSession, RpcLimits, WrapperRpcTransport,
};
use heptabao_plugin_host::OwnedExecutableImage;
use ring::digest::{Context, SHA256};
use rustix::fs::{MemfdFlags, Mode, OFlags, SealFlags};
use rustix::process::{Pid, PidfdFlags, Signal};
use serde::Deserialize;
use serde::de::{MapAccess, Visitor};
use zeroize::{Zeroize, Zeroizing};

use super::{OpenBaoWrapperConfig, ServiceLifecycle, digest};

const POLL: Duration = Duration::from_millis(2);
const MAX_HANDSHAKE: usize = 4096;

#[cfg(test)]
#[path = "service_openbao_wrapper_linux/deadline_tests.rs"]
mod deadline_tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WrapperCleanupState {
    NotStarted,
    Starting,
    Live,
    StopRequested,
    TerminalReaped,
    CleanupUnknown,
}

pub enum WrapperOperation {
    Encrypt {
        plaintext: Zeroizing<Vec<u8>>,
        options: RpcOptions,
    },
    Decrypt {
        blob: OpaqueBlobInfo,
        options: RpcOptions,
    },
}
impl fmt::Debug for WrapperOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WrapperOperation([REDACTED])")
    }
}

pub enum WrapperReply {
    Encrypted(OpaqueBlobInfo),
    Decrypted(Zeroizing<Vec<u8>>),
}
impl fmt::Debug for WrapperReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WrapperReply([REDACTED])")
    }
}

struct Request {
    operation: WrapperOperation,
    deadline: Instant,
    reply: mpsc::SyncSender<Result<WrapperReply, BridgeError>>,
}

struct Control {
    sender: mpsc::SyncSender<Request>,
    stop: Arc<AtomicBool>,
    cleanup: Arc<Mutex<WrapperCleanupState>>,
    generation: u64,
    timeout: Duration,
}
impl Drop for Control {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

#[derive(Clone)]
pub(super) struct WrapperRuntime(Arc<Control>);
impl fmt::Debug for WrapperRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WrapperRuntime([REDACTED])")
    }
}
impl WrapperRuntime {
    pub(super) fn generation(&self) -> u64 {
        self.0.generation
    }
    pub(super) fn timeout(&self) -> Duration {
        self.0.timeout
    }
    pub(super) fn revoke(&self) {
        self.0.stop.store(true, Ordering::Release);
    }
    pub(super) fn cleanup_state(&self) -> WrapperCleanupState {
        self.0
            .cleanup
            .lock()
            .map(|state| *state)
            .unwrap_or(WrapperCleanupState::CleanupUnknown)
    }
    pub(super) fn is_live(&self) -> bool {
        !self.0.stop.load(Ordering::Acquire) && self.cleanup_state() == WrapperCleanupState::Live
    }
    pub(super) fn execute(
        &self,
        operation: WrapperOperation,
        deadline: Instant,
    ) -> Result<WrapperReply, BridgeError> {
        if self.0.stop.load(Ordering::Acquire) || self.cleanup_state() != WrapperCleanupState::Live
        {
            return Err(BridgeError::LifecycleDenied);
        }
        let (reply, receiver) = mpsc::sync_channel(1);
        if Instant::now() >= deadline {
            return Err(BridgeError::BeforeDispatch);
        }
        let request = Request {
            operation,
            deadline,
            reply,
        };
        match self.0.sender.try_send(request) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => return Err(BridgeError::BeforeDispatch),
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.revoke();
                return Err(BridgeError::BeforeDispatch);
            }
        }
        let result = receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| BridgeError::OutcomeUnknown);
        // Once queue admission succeeds, a missing/failed reply may hide a
        // completed provider effect. Revoke, retain the unknown, never replay.
        match result {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(error)) => {
                self.revoke();
                Err(error)
            }
            Err(error) => {
                self.revoke();
                Err(error)
            }
        }
    }
}

struct WorkerFinalizer {
    lifecycle: ServiceLifecycle,
    cleanup: Arc<Mutex<WrapperCleanupState>>,
}
impl Drop for WorkerFinalizer {
    fn drop(&mut self) {
        self.lifecycle.revoke();
        let mut state = self
            .cleanup
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(
            *state,
            WrapperCleanupState::Starting
                | WrapperCleanupState::Live
                | WrapperCleanupState::StopRequested
        ) {
            *state = WrapperCleanupState::CleanupUnknown;
        }
    }
}

fn set_cleanup(state: &Arc<Mutex<WrapperCleanupState>>, value: WrapperCleanupState) {
    *state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
}

struct OwnedChild {
    child: Child,
    pidfd: OwnedFd,
    cleanup: Arc<Mutex<WrapperCleanupState>>,
}
impl OwnedChild {
    fn capture(child: Child, cleanup: Arc<Mutex<WrapperCleanupState>>) -> Result<Self, Child> {
        let Some(pid) = i32::try_from(child.id()).ok().and_then(Pid::from_raw) else {
            return Err(child);
        };
        let Ok(pidfd) = rustix::process::pidfd_open(pid, PidfdFlags::empty()) else {
            return Err(child);
        };
        set_cleanup(&cleanup, WrapperCleanupState::Live);
        Ok(Self {
            child,
            pidfd,
            cleanup,
        })
    }
    fn request_stop(&mut self) {
        set_cleanup(&self.cleanup, WrapperCleanupState::StopRequested);
        if rustix::process::pidfd_send_signal(&self.pidfd, Signal::KILL).is_err() {
            set_cleanup(&self.cleanup, WrapperCleanupState::CleanupUnknown);
        }
    }
    fn await_terminal(&mut self) {
        // This ownership worker can remain pending for a kernel-delayed exit;
        // the Service writer lock never waits on it. No detached reaper is
        // counted as completed cleanup and no other child/group is signalled.
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    set_cleanup(&self.cleanup, WrapperCleanupState::TerminalReaped);
                    return;
                }
                Ok(None) => thread::sleep(POLL),
                Err(_) => {
                    set_cleanup(&self.cleanup, WrapperCleanupState::CleanupUnknown);
                    thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self
            .cleanup
            .lock()
            .map_or(true, |state| *state != WrapperCleanupState::TerminalReaped)
        {
            let _ = rustix::process::pidfd_send_signal(&self.pidfd, Signal::KILL);
            // Panic/drop cannot claim a terminal wait observation.
            set_cleanup(&self.cleanup, WrapperCleanupState::CleanupUnknown);
        }
    }
}

struct ConfigMap(BTreeMap<String, String>);
impl Drop for ConfigMap {
    fn drop(&mut self) {
        for (mut key, mut value) in std::mem::take(&mut self.0) {
            key.zeroize();
            value.zeroize();
        }
    }
}
struct PrivateText(String);
impl Drop for PrivateText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl<'de> Deserialize<'de> for PrivateText {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}
impl<'de> Deserialize<'de> for ConfigMap {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapVisitor;
        impl<'de> Visitor<'de> for MapVisitor {
            type Value = ConfigMap;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded private configuration map")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
                let mut map = ConfigMap(BTreeMap::new());
                while let Some((mut key, mut value)) =
                    input.next_entry::<PrivateText, PrivateText>()?
                {
                    if map.0.len() >= 64
                        || key.0.is_empty()
                        || key.0.len() > 128
                        || key.0.chars().any(char::is_control)
                        || value.0.len() > 16 * 1024
                        || map.0.contains_key(&key.0)
                    {
                        return Err(serde::de::Error::custom(
                            "invalid private configuration map",
                        ));
                    }
                    map.0
                        .insert(std::mem::take(&mut key.0), std::mem::take(&mut value.0));
                }
                Ok(map)
            }
        }
        deserializer.deserialize_map(MapVisitor)
    }
}

fn private_file(
    path: &std::path::Path,
    expected_sha256: &str,
) -> Result<(File, Zeroizing<Vec<u8>>), BridgeError> {
    let parent = path.parent().ok_or(BridgeError::InvalidBinding)?;
    let name = path.file_name().ok_or(BridgeError::InvalidBinding)?;
    let directory = heptabao_filesystem_guard::open_absolute_directory_no_symlinks(parent)
        .map_err(|_| BridgeError::InvalidBinding)?;
    let file = File::from(
        rustix::fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| BridgeError::InvalidBinding)?,
    );
    let metadata = file.metadata().map_err(|_| BridgeError::InvalidBinding)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > 1024 * 1024
    {
        return Err(BridgeError::InvalidBinding);
    }
    let stamp = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.uid(),
            m.mode(),
            m.len(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    let before = stamp(&metadata);
    let expected = digest(expected_sha256)?;
    let mut bytes = Zeroizing::new(vec![0; metadata.len() as usize]);
    for _ in 0..2 {
        let mut offset = 0;
        while offset < bytes.len() {
            let count = file
                .read_at(&mut bytes[offset..], offset as u64)
                .map_err(|_| BridgeError::InvalidBinding)?;
            if count == 0 {
                return Err(BridgeError::IdentityChanged);
            }
            offset += count;
        }
        let mut hash = Context::new(&SHA256);
        hash.update(&bytes);
        if hash.finish().as_ref() != expected
            || stamp(&file.metadata().map_err(|_| BridgeError::InvalidBinding)?) != before
        {
            return Err(BridgeError::IdentityChanged);
        }
    }
    Ok((file, bytes))
}

fn private_config(config: &OpenBaoWrapperConfig) -> Result<(File, RpcOptions), BridgeError> {
    let (file, bytes) = private_file(&config.configuration_file, &config.configuration_sha256)?;
    let mut map: ConfigMap =
        serde_json::from_slice(&bytes).map_err(|_| BridgeError::InvalidOptions)?;
    let mut options = RpcOptions::default();
    options.with_config_map = std::mem::take(&mut map.0);
    options.with_disallow_env_vars = true;
    Ok((file, options))
}

fn create_socket_directory(path: &PathBuf) -> Result<File, BridgeError> {
    let directory = heptabao_filesystem_guard::open_absolute_directory_no_symlinks(
        path.parent().ok_or(BridgeError::InvalidBinding)?,
    )
    .map_err(|_| BridgeError::InvalidBinding)?;
    let parent = directory
        .metadata()
        .map_err(|_| BridgeError::InvalidBinding)?;
    let uid = rustix::process::geteuid().as_raw();
    // A shared temporary parent must be sticky and owned by root or this
    // service. mkdirat is exclusive, with an unpredictable 128-bit name;
    // there is no environment-selected directory or reused socket path.
    if !parent.is_dir()
        || (parent.uid() != 0 && parent.uid() != uid)
        || (parent.mode() & 0o022 != 0 && parent.mode() & 0o1000 == 0)
    {
        return Err(BridgeError::InvalidBinding);
    }
    let name = path.file_name().ok_or(BridgeError::InvalidBinding)?;
    rustix::fs::mkdirat(&directory, name, Mode::from_bits_truncate(0o700))
        .map_err(|_| BridgeError::InvalidBinding)?;
    let owned = File::from(
        rustix::fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| BridgeError::InvalidBinding)?,
    );
    let metadata = owned.metadata().map_err(|_| BridgeError::InvalidBinding)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(BridgeError::InvalidBinding);
    }
    Ok(owned)
}

fn read_handshake(
    child: &mut Child,
    probe: &impl IdentityProbe,
    directory: &PathBuf,
    deadline: Instant,
    stop: &AtomicBool,
) -> Result<AutomaticHandshake, BridgeError> {
    let output = child.stdout.as_mut().ok_or(BridgeError::OutcomeUnknown)?;
    let flags = rustix::fs::fcntl_getfl(output.as_fd()).map_err(|_| BridgeError::OutcomeUnknown)?;
    rustix::fs::fcntl_setfl(output.as_fd(), flags | OFlags::NONBLOCK)
        .map_err(|_| BridgeError::OutcomeUnknown)?;
    let mut line = Zeroizing::new(Vec::new());
    let mut bytes = Zeroizing::new([0; 256]);
    loop {
        if stop.load(Ordering::Acquire) {
            return Err(BridgeError::LifecycleDenied);
        }
        if Instant::now() >= deadline {
            return Err(BridgeError::OutcomeUnknown);
        }
        probe.observe()?;
        match output.read(bytes.as_mut_slice()) {
            Ok(0) => return Err(BridgeError::InvalidHandshake),
            Ok(count) => {
                let chunk = &bytes[..count];
                let length = chunk
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(count, |i| i + 1);
                if line.len() + length > MAX_HANDSHAKE {
                    return Err(BridgeError::InvalidHandshake);
                }
                line.extend_from_slice(&chunk[..length]);
                if chunk.get(length.saturating_sub(1)) == Some(&b'\n') {
                    let result = AutomaticHandshake::parse(&line, directory)?;
                    probe.observe()?;
                    return Ok(result);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err(BridgeError::OutcomeUnknown),
        }
        thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

async fn execute_operation<T: WrapperRpcTransport, P: IdentityProbe>(
    session: &mut OpenBaoGrpcSession<T, P>,
    operation: WrapperOperation,
    deadline: Instant,
    stop: &AtomicBool,
) -> Result<WrapperReply, BridgeError> {
    // Queue admission is not provider dispatch. An expired queued request must
    // stop here before Tokio can poll an Encrypt/Decrypt future.
    if Instant::now() >= deadline {
        return Err(BridgeError::BeforeDispatch);
    }
    tokio::select! {
        _ = cancelled(stop) => Err(BridgeError::OutcomeUnknown),
        result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            match operation {
                WrapperOperation::Encrypt { plaintext, options } => session.encrypt_before(plaintext, options, deadline).await.map(WrapperReply::Encrypted),
                WrapperOperation::Decrypt { blob, options } => session.decrypt_before(&blob, options, deadline).await.map(WrapperReply::Decrypted),
            }
        }) => result.map_err(|_| BridgeError::OutcomeUnknown)?,
    }
}

async fn cancelled(stop: &AtomicBool) {
    while !stop.load(Ordering::Acquire) {
        tokio::time::sleep(POLL).await;
    }
}

pub(super) fn launch_automatic_runtime(
    config: &OpenBaoWrapperConfig,
    lifecycle: ServiceLifecycle,
    directory: PathBuf,
) -> Result<WrapperRuntime, BridgeError> {
    let generation = lifecycle.snapshot()?.configuration_generation;
    let timeout = Duration::from_millis(config.startup_timeout_ms);
    let deadline = Instant::now() + timeout;
    let (sender, receiver) = mpsc::sync_channel::<Request>(1);
    let (ready, admission) = mpsc::sync_channel(1);
    let stop = Arc::new(AtomicBool::new(false));
    let cleanup = Arc::new(Mutex::new(WrapperCleanupState::NotStarted));
    lifecycle.track_cleanup(cleanup.clone())?;
    let diagnostic = Arc::new(Mutex::new(Some(
        serde_json::json!({"provider":null,"owned_pid":null,
        "generation":generation,"authenticated_h2":false,"health_authenticated":false}),
    )));
    lifecycle.track_diagnostic(diagnostic.clone())?;
    let control = Arc::new(Control {
        sender,
        stop: stop.clone(),
        cleanup: cleanup.clone(),
        generation,
        timeout,
    });
    let config = config.clone();
    // The ownership thread exists before any Child is created. Thread creation
    // failure therefore cannot be reported as successful cleanup of a launch.
    thread::Builder::new().name("heptabao-wrapper-owner".into()).spawn(move || {
        let _finalizer = WorkerFinalizer { lifecycle: lifecycle.clone(), cleanup: cleanup.clone() };
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(_) => { let _ = ready.send(Err(BridgeError::BeforeDispatch)); lifecycle.revoke(); return; }
        };
        let mut child: Option<OwnedChild> = None;
        // This FD lives through session drop and the actual child terminal wait.
        let mut soft_hsm: Option<(File, File)> = None;
        let mut socket_directory: Option<File> = None;
        let startup = (|| {
            let before = lifecycle.snapshot()?;
            let image = OwnedExecutableImage::open(&config.command, digest(&config.command_sha256)?).map_err(|_| BridgeError::InvalidBinding)?;
            let executable = image.identity().map_err(|_| BridgeError::InvalidBinding)?;
            let (configuration, options) = private_config(&config)?;
            let meta = configuration.metadata().map_err(|_| BridgeError::InvalidBinding)?;
            if let (Some(path), Some(hash)) = (&config.soft_hsm_configuration_file, &config.soft_hsm_configuration_sha256) {
                let (original, bytes) = private_file(path, hash)?;
                let mut sealed = File::from(rustix::fs::memfd_create("heptabao-soft-hsm-configuration",
                    MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING).map_err(|_| BridgeError::BeforeDispatch)?);
                sealed.write_all(&bytes).map_err(|_| BridgeError::BeforeDispatch)?;
                rustix::fs::fchmod(&sealed, Mode::RUSR | Mode::WUSR).map_err(|_| BridgeError::BeforeDispatch)?;
                rustix::fs::fcntl_add_seals(&sealed, SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL)
                    .map_err(|_| BridgeError::BeforeDispatch)?;
                soft_hsm = Some((original, sealed));
            }
            let client = PerLaunchClientIdentity::generate()?;
            socket_directory = Some(create_socket_directory(&directory)?);
            if lifecycle.snapshot()? != before || stop.load(Ordering::Acquire) { return Err(BridgeError::LifecycleDenied); }
            let mut command = image.command();
            command.env_clear().env(KMS_MAGIC_COOKIE_KEY, KMS_MAGIC_COOKIE_VALUE)
                .env("PLUGIN_PROTOCOL_VERSIONS", "1")
                .env("PLUGIN_CLIENT_CERT", client.public_certificate_pem())
                .env("PLUGIN_UNIX_SOCKET_DIR", &directory)
                .process_group(0).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
            if let Some((_, file)) = soft_hsm.as_ref() {
                command.env("SOFTHSM2_CONF", format!("/proc/{}/fd/{}", std::process::id(), file.as_raw_fd()));
            }
            // This persistent owner thread retains the Child through its actual
            // terminal wait. Request-thread exit cannot trigger the binding.
            // The sealed mode-0500 image has no set-ID/capability transition.
            heptabao_linux_parent_death::bind_owner_death(&mut command);
            lifecycle.authorize_start(generation)?;
            let started = command.spawn().map_err(|_| {
                set_cleanup(&cleanup, WrapperCleanupState::NotStarted);
                BridgeError::BeforeDispatch
            })?;
            let owned = match OwnedChild::capture(started, cleanup.clone()) {
                Ok(child) => child,
                Err(mut uncaptured) => {
                    if let Ok(mut observed) = diagnostic.lock() {
                        if let Some(value) = observed.as_mut() { value["owned_pid"] = serde_json::json!(uncaptured.id()); }
                    }
                    // The owned Child has not been waited or reaped, so its PID
                    // cannot be reused. This is only the pidfd-capture failure.
                    let _ = uncaptured.kill();
                    set_cleanup(&cleanup, WrapperCleanupState::CleanupUnknown);
                    let _ = ready.send(Err(BridgeError::ProcessObservationUnavailable));
                    lifecycle.revoke();
                    // Keep the Child in this existing worker until actual wait.
                    loop {
                        match uncaptured.try_wait() {
                            Ok(Some(_)) => { set_cleanup(&cleanup, WrapperCleanupState::TerminalReaped); break; }
                            Ok(None) => thread::sleep(POLL),
                            Err(_) => thread::sleep(Duration::from_millis(20)),
                        }
                    }
                    return Err(BridgeError::ProcessObservationUnavailable);
                }
            };
            child = Some(owned);
            if let Ok(mut observed) = diagnostic.lock() {
                if let Some(value) = observed.as_mut() { value["owned_pid"] = serde_json::json!(child.as_ref().ok_or(BridgeError::OutcomeUnknown)?.child.id()); }
            }
            let owned = child.as_mut().ok_or(BridgeError::OutcomeUnknown)?;
            let probe = LinuxIdentityProbe::capture_started_child(StartedChildBinding {
                pid: owned.child.id(), uid: rustix::process::geteuid().as_raw(), executable_device: executable.0,
                executable_inode: executable.1, executable_sha256: digest(&config.command_sha256)?,
                config_device: meta.dev(), config_inode: meta.ino(), config_sha256: digest(&config.configuration_sha256)?,
            }, &config.configuration_file, lifecycle.clone())?;
            let identity = probe.observe()?.0;
            let actual_pid = Pid::from_raw(identity.pid as i32).ok_or(BridgeError::InvalidBinding)?;
            let actual_pgid = rustix::process::getpgid(Some(actual_pid)).map_err(|_| BridgeError::ProcessObservationUnavailable)?.as_raw_pid();
            if probe.observe()?.0 != identity { return Err(BridgeError::IdentityChanged); }
            let observation = serde_json::json!({
                "provider": {"pid":identity.pid,"pgid":actual_pgid,"sid":identity.session_id,
                    "uid":identity.uid,"start_ticks":identity.start_ticks,
                    "executable_sha256":super::super::hex(&identity.executable_sha256)},
                "owned_pid":identity.pid,"generation":generation,"authenticated_h2":false,"health_authenticated":false
            });
            *diagnostic.lock().map_err(|_| BridgeError::ProcessObservationUnavailable)? = Some(observation.clone());
            let handshake = read_handshake(&mut owned.child, &probe, &directory, deadline, &stop)?;
            let limits = RpcLimits { maximum_request_bytes: 1024 * 1024, maximum_response_bytes: 1024 * 1024, timeout };
            let session = rt.block_on(async {
                tokio::select! {
                    _ = cancelled(&stop) => Err(BridgeError::LifecycleDenied),
                    result = tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), async {
                        let mut transport = AutomaticWrapperTransport::connect_after_owned_launch(&identity, &probe, handshake, client, limits, deadline).await?;
                        transport.authenticated_health_check(deadline).await?;
                        let mut session = OpenBaoGrpcSession::admit(transport, probe, identity, limits)?;
                        let _metadata = session.set_config_before(options, deadline).await?;
                        let _type = session.wrapper_type_before(deadline).await?;
                        let _key_id = session.key_id_before(deadline).await?;
                        let mut options = RpcOptions::default(); options.with_disallow_env_vars = true;
                        session.init_before(options, deadline).await?;
                        Ok(session)
                    }) => result.map_err(|_| BridgeError::OutcomeUnknown)?,
                }
            })?;
            let mut authenticated = observation;
            authenticated["authenticated_h2"] = serde_json::json!(true);
            authenticated["health_authenticated"] = serde_json::json!(true);
            *diagnostic.lock().map_err(|_| BridgeError::ProcessObservationUnavailable)? = Some(authenticated);
            Ok(session)
        })();
        match startup {
            Ok(mut session) => {
                if ready.send(Ok(())).is_ok() {
                    while !stop.load(Ordering::Acquire) {
                        if let Some(owned) = child.as_mut() {
                            match owned.child.try_wait() {
                                Ok(Some(_)) => { set_cleanup(&cleanup, WrapperCleanupState::TerminalReaped); break; }
                                Ok(None) => {}
                                Err(_) => { set_cleanup(&cleanup, WrapperCleanupState::CleanupUnknown); break; }
                            }
                        }
                        let request = match receiver.recv_timeout(POLL) {
                            Ok(request) => request,
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        };
                        let result = rt.block_on(execute_operation(
                            &mut session, request.operation, request.deadline, &stop,
                        ));
                        let failed = result.is_err();
                        if request.reply.send(result).is_err() || failed { stop.store(true, Ordering::Release); break; }
                    }
                }
                drop(session);
            }
            Err(error) => { let _ = ready.send(Err(error)); }
        }
        lifecycle.revoke();
        if let Some(mut owned) = child {
            if owned.cleanup.lock().map_or(true, |state| *state != WrapperCleanupState::TerminalReaped) {
                owned.request_stop();
                owned.await_terminal();
            }
        }
        // Keep the private directory descriptor through the owned provider's
        // actual terminal wait, then retain its path for metadata audit.
        drop(socket_directory);
        // No recursive deletion, path-based signal, or descendant claim is made.
    }).map_err(|_| BridgeError::BeforeDispatch)?;
    match admission.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Ok(())) => Ok(WrapperRuntime(control)),
        Ok(Err(error)) => {
            control.stop.store(true, Ordering::Release);
            Err(error)
        }
        Err(_) => {
            control.stop.store(true, Ordering::Release);
            Err(BridgeError::OutcomeUnknown)
        }
    }
}
