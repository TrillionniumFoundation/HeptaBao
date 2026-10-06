//! Linux SDK secret backends. Worker threads own processes; each Storage RPC
//! returns to the existing Service writer before an acknowledgement is emitted.
use super::*;
use crate::engines::sdk::{Descriptor, MountOwner, StorageEntry};
use heptabao_plugin_host::sdk_backend::{
    SdkAuthCallback, SdkBackendHost, SdkBridgeError, SdkLaunch, SdkLeaseCallback,
    SdkLogicalRequest, SdkStorage, SdkStorageEntry,
};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::time::{Duration, Instant};

pub(in crate::service) fn writer_before(
    service: &Arc<Mutex<Service>>,
    deadline: Instant,
) -> Result<std::sync::MutexGuard<'_, Service>, Response> {
    loop {
        if Instant::now() >= deadline {
            return Err(Response::error(503, "SDK original writer deadline expired"));
        }
        match service.try_lock() {
            Ok(writer) => return Ok(writer),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(Response::error(503, "SDK writer poisoned"));
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                std::thread::park_timeout(Duration::from_millis(1))
            }
        }
    }
}

fn timeout_ms() -> u64 {
    5_000
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkBackendConfig {
    pub plugin_directory: PathBuf,
    pub companion: PathBuf,
    pub companion_sha256: String,
    pub runtime_directory: PathBuf,
    #[serde(default = "timeout_ms")]
    pub timeout_ms: u64,
}
impl SdkBackendConfig {
    fn validate(&self) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        if !(1..=30_000).contains(&self.timeout_ms) || !self.companion.is_absolute() {
            return Err("SDK runtime requires a bounded timeout and absolute companion".into());
        }
        checksum(&self.companion_sha256).map_err(|_| "invalid SDK companion checksum")?;
        for path in [&self.plugin_directory, &self.runtime_directory] {
            let meta = fs::symlink_metadata(path).map_err(|_| "SDK directory is unavailable")?;
            if !path.is_absolute() || !meta.is_dir() || meta.mode() & 0o077 != 0 {
                return Err("SDK directories must be absolute and private".into());
            }
        }
        Ok(())
    }
}
fn checksum(text: &str) -> Result<[u8; 32], Response> {
    if text.len() != 64
        || text
            .bytes()
            .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
    {
        return Err(Response::error(400, "invalid SDK checksum"));
    }
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| Response::error(400, "invalid SDK checksum"))?;
    }
    Ok(out)
}

/// Status is bounded process-local metadata. It carries no mutation authority.
/// Namespace incarnation and the original typed custody chain prevent ABA.
pub(super) struct MigrationStatus {
    namespace: String,
    namespace_incarnation: Option<u64>,
    namespace_binding: namespace_runtime::DeliveryBinding,
    cluster: String,
    from: String,
    to: String,
}
fn parse_header_allowlist(value: Option<&Value>) -> Result<Vec<String>, Response> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| Response::error(400, "allowed_response_headers requires strings"))?;
    let names = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| Response::error(400, "allowed_response_headers requires strings"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !validate_sdk_header_allowlist(&names) {
        return Err(Response::error(
            501,
            "SDK response transport header policy is not implemented or exceeds bounds",
        ));
    }
    Ok(names)
}
fn migration_id() -> Result<String, Response> {
    let mut bytes = crypto::random::<16>()
        .map_err(|_| Response::error(503, "remount identity entropy unavailable"))?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let text = hex(&bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &text[..8],
        &text[8..12],
        &text[12..16],
        &text[16..20],
        &text[20..]
    ))
}

#[path = "service_sdk_auth.rs"]
pub(in crate::service) mod auth100;
#[path = "service_sdk_expiry.rs"]
mod expiry;
#[path = "service_sdk_retirement.rs"]
mod retirement;
#[path = "service_sdk_lease.rs"]
mod secret_lease;

struct StageTarget<'a> {
    mount: String,
    owner: MountOwner,
    operation: &'a str,
    path: &'a str,
    lease: Option<secret_lease::LeaseCall>,
}

enum StorageOp {
    Get(String),
    Put(StorageEntry),
    Delete(String),
    List(String, String, i64),
}
enum StorageReply {
    Entry(Option<SdkStorageEntry>),
    Empty,
    Keys(Vec<String>),
}
enum Event {
    Storage(StorageOp, Sender<Result<StorageReply, SdkBridgeError>>),
    Complete(Result<Option<Value>, SdkBridgeError>),
}
struct WorkerJob {
    operation: String,
    path: String,
    data: Value,
    lease: Option<SdkLeaseCallback>,
    auth: Option<Box<SdkAuthCallback>>,
    expected_auth_paths: Option<Value>,
    deadline: Instant,
    events: Sender<Event>,
}
impl Drop for WorkerJob {
    fn drop(&mut self) {
        erase_json(&mut self.data);
    }
}
enum WorkerCommand {
    Invoke(WorkerJob),
    Stop,
}
pub(super) struct Control {
    sender: SyncSender<WorkerCommand>,
    busy: Arc<AtomicBool>,
    fenced: Arc<AtomicBool>,
    retiring: AtomicBool,
}
impl Control {
    fn retire(&self) {
        self.fenced.store(true, Ordering::Release);
        let _ = self.sender.try_send(WorkerCommand::Stop);
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        self.retire();
    }
}

struct CallbackView {
    events: Sender<Event>,
    deadline: Instant,
}
impl CallbackView {
    fn exchange(&self, op: StorageOp, deadline: Instant) -> Result<StorageReply, SdkBridgeError> {
        let deadline = deadline.min(self.deadline);
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(SdkBridgeError::Fenced)?;
        let (reply, received) = mpsc::channel();
        self.events
            .send(Event::Storage(op, reply))
            .map_err(|_| SdkBridgeError::Fenced)?;
        received
            .recv_timeout(remaining)
            .map_err(|_| SdkBridgeError::Fenced)?
    }
}
impl SdkStorage for CallbackView {
    fn get(
        &mut self,
        key: &str,
        deadline: Instant,
    ) -> Result<Option<SdkStorageEntry>, SdkBridgeError> {
        match self.exchange(StorageOp::Get(key.into()), deadline)? {
            StorageReply::Entry(e) => Ok(e),
            _ => Err(SdkBridgeError::Fenced),
        }
    }
    fn put(&mut self, entry: SdkStorageEntry, deadline: Instant) -> Result<(), SdkBridgeError> {
        match self.exchange(
            StorageOp::Put(StorageEntry {
                key: entry.key,
                value: entry.value,
                seal_wrap: entry.seal_wrap,
            }),
            deadline,
        )? {
            StorageReply::Empty => Ok(()),
            _ => Err(SdkBridgeError::Fenced),
        }
    }
    fn delete(&mut self, key: &str, deadline: Instant) -> Result<(), SdkBridgeError> {
        match self.exchange(StorageOp::Delete(key.into()), deadline)? {
            StorageReply::Empty => Ok(()),
            _ => Err(SdkBridgeError::Fenced),
        }
    }
    fn list_page(
        &mut self,
        prefix: &str,
        after: &str,
        limit: i64,
        deadline: Instant,
    ) -> Result<Vec<String>, SdkBridgeError> {
        match self.exchange(
            StorageOp::List(prefix.into(), after.into(), limit),
            deadline,
        )? {
            StorageReply::Keys(k) => Ok(k),
            _ => Err(SdkBridgeError::Fenced),
        }
    }
}

fn start_worker(config: SdkLaunch) -> Result<Arc<Control>, Response> {
    start_worker_typed(
        config,
        heptabao_plugin_host::sdk_backend::SdkBackendType::Secret,
    )
}
fn start_worker_typed(
    config: SdkLaunch,
    family: heptabao_plugin_host::sdk_backend::SdkBackendType,
) -> Result<Arc<Control>, Response> {
    let (sender, commands) = mpsc::sync_channel(1);
    let busy = Arc::new(AtomicBool::new(false));
    let fenced = Arc::new(AtomicBool::new(false));
    let worker_busy = Arc::clone(&busy);
    let worker_fenced = Arc::clone(&fenced);
    std::thread::Builder::new()
        .name("sdk-mount-owner".into())
        .spawn(move || {
            let mut host: Option<SdkBackendHost> = None;
            while let Ok(command) = commands.recv() {
                let WorkerCommand::Invoke(mut job) = command else {
                    break;
                };
                let mut view = CallbackView {
                    events: job.events.clone(),
                    deadline: job.deadline,
                };
                let result = (|| {
                    if worker_fenced.load(Ordering::Acquire) || Instant::now() >= job.deadline {
                        return Err(SdkBridgeError::Fenced);
                    }
                    if host.is_none() {
                        host = Some(SdkBackendHost::launch_typed_before(
                            &config,
                            &mut view,
                            family,
                            job.deadline,
                        )?);
                    }
                    if job.operation == "_mount" {
                        return if family==heptabao_plugin_host::sdk_backend::SdkBackendType::Auth {
                            Ok(Some(json!({"auth_paths":host.as_ref().ok_or(SdkBridgeError::Fenced)?.auth_special_paths().ok_or(SdkBridgeError::Fenced)?})))
                        } else {Ok(None)};
                    }
                    if let Some(expected)=job.expected_auth_paths.as_ref()
                        && host.as_ref().and_then(SdkBackendHost::auth_special_paths)!=Some(expected) {
                        return Err(SdkBridgeError::Fenced);
                    }
                    host.as_mut()
                        .ok_or(SdkBridgeError::Fenced)?
                        .handle_logical_request_before(
                            SdkLogicalRequest {
                                operation: &job.operation,
                                path: &job.path,
                                data: std::mem::take(&mut job.data),
                                lease: job.lease.take(),
                                auth: job.auth.take().map(|auth| *auth),
                            },
                            &mut view,
                            job.deadline,
                        )
                })();
                if matches!(
                    result,
                    Err(SdkBridgeError::OutcomeUnknown | SdkBridgeError::Fenced)
                ) {
                    worker_fenced.store(true, Ordering::Release);
                }
                let _ = job.events.send(Event::Complete(result));
                worker_busy.store(false, Ordering::Release);
                if worker_fenced.load(Ordering::Acquire) {
                    break;
                }
            }
            drop(host); // Same persistent owner thread retains the owned process until cleanup.
        })
        .map_err(|_| Response::error(503, "SDK owner thread unavailable before entry"))?;
    Ok(Arc::new(Control {
        sender,
        busy,
        fenced,
        retiring: AtomicBool::new(false),
    }))
}

struct StorageTransaction {
    engines: CowOwner<EngineState>,
    identity: crate::state_record_root::StateIdentity,
    changed: bool,
}

pub(super) struct Plan {
    namespace: String,
    mount: String,
    owner: MountOwner,
    descriptor: Descriptor,
    control: Arc<Control>,
    authority: Mutex<expiry::Authority>,
    operation: String,
    path: String,
    data: Value,
    lease: Mutex<Option<Box<secret_lease::LeaseCall>>>,
    retirement: Option<Mutex<retirement::Retirement>>,
    transaction: Mutex<StorageTransaction>,
    pub(in crate::service) deadline: Instant,
}
impl Drop for Plan {
    fn drop(&mut self) {
        erase_json(&mut self.data);
        if self.retirement.is_some() {
            self.control.retiring.store(false, Ordering::Release);
        }
    }
}

impl Plan {
    pub(super) fn execute(
        &self,
        service: &Arc<Mutex<Service>>,
        deadline: Instant,
    ) -> Result<Option<Value>, Response> {
        let deadline = deadline.min(self.deadline);
        if self.retirement.is_some() {
            return self.execute_retirement(service, deadline);
        }
        self.execute_once(service, deadline)
    }
    fn execute_once(
        &self,
        service: &Arc<Mutex<Service>>,
        deadline: Instant,
    ) -> Result<Option<Value>, Response> {
        let deadline = deadline.min(self.deadline);
        if self.control.fenced.load(Ordering::Acquire)
            || Instant::now() >= deadline
            || (self.control.retiring.load(Ordering::Acquire) && self.retirement.is_none())
        {
            return Err(Response::error(
                503,
                "SDK owner or original deadline unavailable before entry",
            ));
        }
        let call = self
            .lease
            .lock()
            .map_err(|_| Response::error(503, "SDK callback owner unavailable"))?
            .clone();
        let lease_callback = call.as_ref().map(|call| call.callback()).transpose()?;
        if self
            .control
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Response::error(503, "SDK mount is busy before entry"));
        }
        if self.control.retiring.load(Ordering::Acquire) && self.retirement.is_none() {
            self.control.busy.store(false, Ordering::Release);
            return Err(Response::error(
                503,
                "SDK mount retirement admitted before effect",
            ));
        }

        let (events, received) = mpsc::channel();
        let job = WorkerJob {
            operation: self.operation.clone(),
            path: call.as_ref().map_or_else(
                || self.path.clone(),
                |call| {
                    call.record
                        .path
                        .strip_prefix(&self.mount)
                        .unwrap_or("")
                        .to_owned()
                },
            ),
            data: call
                .as_ref()
                .map_or_else(|| self.data.clone(), |call| call.request_data()),
            lease: lease_callback,
            auth: None,
            expected_auth_paths: None,
            deadline,
            events,
        };
        if self
            .control
            .sender
            .try_send(WorkerCommand::Invoke(job))
            .is_err()
        {
            self.control.busy.store(false, Ordering::Release);
            return Err(Response::error(
                503,
                "SDK owner queue unavailable before entry",
            ));
        }
        self.pump(service, received, deadline)
    }
    fn pump(
        &self,
        service: &Arc<Mutex<Service>>,
        events: Receiver<Event>,
        deadline: Instant,
    ) -> Result<Option<Value>, Response> {
        loop {
            let remaining = match deadline.checked_duration_since(Instant::now()) {
                Some(t) => t,
                None => {
                    self.control.retire();
                    return Err(Response::error(
                        503,
                        "SDK original deadline expired; owner fenced",
                    ));
                }
            };
            match events.recv_timeout(remaining) {
                Ok(Event::Complete(result)) => return result.map_err(bridge_failure),
                Ok(Event::Storage(op, reply)) => {
                    let result = loop {
                        match service.try_lock() {
                            Ok(mut writer) => {
                                break writer.sdk_storage_callback(self, op, deadline);
                            }
                            Err(std::sync::TryLockError::Poisoned(_)) => {
                                break Err(SdkBridgeError::Fenced);
                            }
                            Err(std::sync::TryLockError::WouldBlock) => {
                                if Instant::now() >= deadline {
                                    break Err(SdkBridgeError::Fenced);
                                }
                                std::thread::park_timeout(Duration::from_millis(1));
                            }
                        }
                    };
                    if matches!(
                        result,
                        Err(SdkBridgeError::OutcomeUnknown | SdkBridgeError::Fenced)
                    ) {
                        self.control.retire();
                    }
                    if reply.send(result).is_err() {
                        self.control.retire();
                        return Err(Response::error(
                            503,
                            "SDK Storage acknowledgement outcome unknown; owner fenced",
                        ));
                    }
                }
                Err(_) => {
                    self.control.retire();
                    return Err(Response::error(
                        503,
                        "SDK execution outcome unavailable; owner fenced",
                    ));
                }
            }
        }
    }
}
fn bridge_failure(e: SdkBridgeError) -> Response {
    match e {
        SdkBridgeError::Backend => Response::error(400, "SDK backend rejected request"),
        SdkBridgeError::BeforeEntry => Response::error(503, "SDK plugin unavailable before entry"),
        SdkBridgeError::OutcomeUnknown => {
            Response::error(503, "SDK execution outcome unknown; mount owner fenced")
        }
        _ => Response::error(503, "SDK execution fenced or Storage unavailable"),
    }
}

impl Service {
    pub(super) fn sdk_control_handles(&self, state: &State, request: &RequestView<'_>) -> bool {
        if let Some(mount) = request
            .path
            .strip_prefix("sys/mounts/")
            .and_then(|p| p.strip_suffix("/tune"))
        {
            let mount = format!("{}/", mount.trim_end_matches('/'));
            if state
                .engines
                .sdk_mount_binding(request.namespace, &mount)
                .is_some_and(|(actual, _)| actual == mount)
            {
                return true;
            }
        }
        if request.path.starts_with("sys/remount/status/") {
            return self.sdk_configuration.is_some() || state.engines.has_sdk_state();
        }
        if request.path == "sys/remount" {
            let from = request
                .body
                .get("from")
                .and_then(Value::as_str)
                .unwrap_or("");
            let from = format!("{}/", from.trim_end_matches('/'));
            if state
                .engines
                .sdk_mount_binding(request.namespace, &from)
                .is_some_and(|(actual, _)| actual == from)
            {
                return true;
            }
        }
        if request.method == "DELETE" && request.path.starts_with("sys/mounts/") {
            let mount = format!(
                "{}/",
                request
                    .path
                    .trim_start_matches("sys/mounts/")
                    .trim_end_matches('/')
            );
            if state
                .engines
                .sdk_mount_binding(request.namespace, &mount)
                .is_some()
            {
                return true;
            }
        }
        if request.path == "sys/plugins/catalog" {
            return true;
        }
        if request.path == "sys/plugins/catalog/secret"
            || request.path.starts_with("sys/plugins/catalog/secret/")
        {
            return self.sdk_configuration.is_some() || state.engines.has_sdk_state();
        }
        if matches!(request.method, "POST" | "PUT")
            && request.path.starts_with("sys/mounts/")
            && !request.path.ends_with("/tune")
        {
            let name = request
                .body
                .get("plugin_name")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .or_else(|| request.body.get("type").and_then(Value::as_str));
            let version = request
                .body
                .get("config")
                .and_then(|v| v.get("plugin_version"))
                .and_then(Value::as_str)
                .unwrap_or("");
            return name.is_some_and(|name| state.engines.sdk_descriptor(name, version).is_some());
        }
        false
    }
    pub(super) fn sdk_control_route(
        &mut self,
        mut state: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        let capability = if matches!(request.method, "GET" | "HEAD") {
            "read"
        } else if matches!(request.method, "LIST" | "SCAN") {
            "list"
        } else if request.method == "DELETE" {
            "delete"
        } else {
            "update"
        };
        let expected = match self.current_state_identity() {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut authority = plugin::PluginResponseAuthority::new(
            principal,
            &state,
            request,
            capability,
            !request.path.starts_with("sys/remount/status/"),
            &self.unseal_nonce,
        )
        .with_sdk_clock();
        if let Err(error) = self.validate_plugin_response(&mut authority) {
            return error;
        }
        if self.current_state_identity().as_ref().ok() != Some(&expected) {
            return Response::error(503, "SDK control snapshot changed before admission");
        }
        if request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
            return Response::error(501, "SDK catalog and mount wrapping is not implemented");
        }
        if let Some(mount) = request
            .path
            .strip_prefix("sys/mounts/")
            .and_then(|p| p.strip_suffix("/tune"))
        {
            let mount = format!("{}/", mount.trim_end_matches('/'));
            let Some((actual, owner)) = state
                .engines
                .sdk_mount_binding(request.namespace, &mount)
                .filter(|(actual, _)| actual == &mount)
            else {
                return Response::error(404, "SDK mount not found");
            };
            if matches!(request.method, "GET" | "HEAD") {
                self.pending_sdk_control_authority = Some(authority);
                return Response::ok(
                    json!({"data":{"default_lease_ttl":0,"max_lease_ttl":0,"force_no_cache":false,"allowed_response_headers":owner.allowed_response_headers}}),
                );
            }
            if !matches!(request.method, "POST" | "PUT") {
                return Response::error(405, "SDK tune requires GET, POST or PUT");
            }
            let Some(mut object) = request.body.as_object().cloned() else {
                return Response::error(400, "SDK tune requires object");
            };
            for field in [
                "options",
                "default_lease_ttl",
                "max_lease_ttl",
                "force_no_cache",
            ] {
                let Some(value) = object.get(field) else {
                    continue;
                };
                let neutral = match field {
                    "options" => value.is_null(),
                    "force_no_cache" => value.as_bool() == Some(false),
                    _ => value.as_str() == Some(""),
                };
                if !neutral {
                    return Response::error(
                        501,
                        "SDK nondefault lease configuration is not implemented",
                    );
                }
                object.remove(field);
            }
            if object.len() != 1 || !object.contains_key("allowed_response_headers") {
                return Response::error(501, "SDK tune parameter not implemented");
            }
            let headers = match parse_header_allowlist(object.get("allowed_response_headers")) {
                Ok(headers) => headers,
                Err(error) => return error,
            };
            let host_key = self.sdk_host_key(request.namespace, &actual, &owner);
            if let Err(error) =
                state
                    .engines
                    .set_sdk_response_headers(request.namespace, &actual, &owner, headers)
            {
                return Response::error(error.status, &error.message);
            }
            state.schema = state.writer_schema();
            if let Err(error) = self.commit_sdk_control(&mut state, &mut authority, &expected) {
                return error;
            }
            self.state = Some(state);
            self.pending_sdk_control_authority = Some(authority);
            if let Some(control) = self.sdk_hosts.remove(&host_key) {
                control.retire()
            }
            return Response {
                status: 204,
                body: json!({}),
                response_headers: Default::default(),
                consistency_index: None,
            };
        }
        if let Some(id) = request.path.strip_prefix("sys/remount/status/") {
            if !matches!(request.method, "GET" | "HEAD") {
                return Response::error(405, "remount status requires GET");
            }
            let Some(info) = self.sdk_migrations.get(id).filter(|info| {
                info.namespace == request.namespace
                    && info.cluster == state.cluster_id
                    && info.namespace_incarnation == state.namespaces.incarnation(request.namespace)
                    && info.namespace_binding
                        == namespace_runtime::DeliveryBinding::capture(&state, request.namespace)
            }) else {
                return Response::error(404, "remount migration not found");
            };
            let response = Response::ok(json!({"data":{"migration_id":id,
                "migration_info":{"source_mount":info.from,"target_mount":info.to,"status":"success"}}}));
            self.pending_sdk_control_authority = Some(authority);
            return response;
        }
        if request.path == "sys/remount" {
            if !matches!(request.method, "POST" | "PUT") {
                return Response::error(405, "remount requires POST or PUT");
            }
            let Some(object) = request.body.as_object() else {
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
            if from.starts_with('/')
                || to.starts_with('/')
                || from.starts_with("auth/")
                || to.starts_with("auth/")
            {
                return Response::error(400, "SDK remount requires relative secret mount paths");
            }
            for reserved in ["sys/", "identity/", "cubbyhole/"] {
                if from.starts_with(reserved) || to.starts_with(reserved) {
                    return Response::error(400, "remount cannot relocate reserved system paths");
                }
            }
            let cas = match object.get("cas_revision") {
                Some(value) => match value.as_u64() {
                    Some(value) => Some(value),
                    None => {
                        return Response::error(400, "cas_revision must be a nonnegative integer");
                    }
                },
                None => None,
            };
            let from = format!("{}/", from.trim_end_matches('/'));
            let to = format!("{}/", to.trim_end_matches('/'));
            let Some((actual, owner)) = state
                .engines
                .sdk_mount_binding(request.namespace, &from)
                .filter(|(actual, _)| actual == &from)
            else {
                return Response::error(404, "SDK source mount not found");
            };
            if self.sdk_migrations.len() >= 128 {
                return Response::error(507, "remount migration status capacity exhausted");
            }
            let id = match migration_id() {
                Ok(id) => id,
                Err(error) => return error,
            };
            if self.sdk_migrations.contains_key(&id) {
                return Response::error(503, "remount migration identity collision");
            }
            let registered_leases =
                match state
                    .engines
                    .sdk_mount_leases(request.namespace, &actual, &owner)
                {
                    Ok(rows) => rows,
                    Err(error) => return Response::from_engine_error(error),
                };
            if !registered_leases.is_empty() {
                return self.stage_sdk_retirement(
                    state,
                    authority,
                    request,
                    actual,
                    owner,
                    retirement::Action::Remount { to, cas, id },
                );
            }
            let host_key = self.sdk_host_key(request.namespace, &actual, &owner);
            if let Err(error) = state.engines.remount(request.namespace, &from, &to, cas) {
                return Response::error(error.status, &error.message);
            }
            state.schema = state.writer_schema();
            if let Err(error) = self.commit_sdk_control(&mut state, &mut authority, &expected) {
                return error;
            }
            let info = MigrationStatus {
                namespace: request.namespace.into(),
                namespace_incarnation: state.namespaces.incarnation(request.namespace),
                namespace_binding: namespace_runtime::DeliveryBinding::capture(
                    &state,
                    request.namespace,
                ),
                cluster: state.cluster_id.clone(),
                from,
                to,
            };
            self.sdk_migrations.insert(id.clone(), info);
            self.state = Some(state);
            self.pending_sdk_control_authority = Some(authority);
            if let Some(control) = self.sdk_hosts.remove(&host_key) {
                control.retire();
            }
            return Response::ok(json!({"migration_id":id,"data":{"migration_id":id}}));
        }
        if request.method == "DELETE" && request.path.starts_with("sys/mounts/") {
            let mount = format!(
                "{}/",
                request
                    .path
                    .trim_start_matches("sys/mounts/")
                    .trim_end_matches('/')
            );
            let Some((actual, owner)) = state
                .engines
                .sdk_mount_binding(request.namespace, &mount)
                .filter(|(actual, _)| actual == &mount)
            else {
                return Response::error(404, "SDK mount not found");
            };
            let registered_leases =
                match state
                    .engines
                    .sdk_mount_leases(request.namespace, &actual, &owner)
                {
                    Ok(rows) => rows,
                    Err(error) => return Response::from_engine_error(error),
                };
            if !registered_leases.is_empty() {
                return self.stage_sdk_retirement(
                    state,
                    authority,
                    request,
                    actual,
                    owner,
                    retirement::Action::Unmount,
                );
            }
            let host_key = self.sdk_host_key(request.namespace, &actual, &owner);
            if let Err(e) = state.engines.handle(
                request.namespace,
                "DELETE",
                request.path,
                request.body,
                request.now,
            ) {
                return Response::error(e.status, &e.message);
            }
            state.schema = state.writer_schema();
            if let Err(e) = self.commit_sdk_control(&mut state, &mut authority, &expected) {
                return e;
            }
            self.state = Some(state);
            self.pending_sdk_control_authority = Some(authority);
            if let Some(control) = self.sdk_hosts.remove(&host_key) {
                control.retire();
            }
            return Response {
                status: 204,
                body: json!({}),
                response_headers: Default::default(),
                consistency_index: None,
            };
        }
        if request.path.starts_with("sys/mounts/") {
            let Some(config) = self.sdk_configuration.as_ref() else {
                return Response::error(503, "SDK runtime is not configured");
            };
            if config.validate().is_err() {
                return Response::error(503, "SDK deployment directories changed");
            }
            let name = request
                .body
                .get("plugin_name")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .or_else(|| request.body.get("type").and_then(Value::as_str))
                .unwrap_or("");
            let version = request
                .body
                .get("config")
                .and_then(|v| v.get("plugin_version"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let Some(descriptor) = state.engines.sdk_descriptor(name, version) else {
                return Response::error(400, "SDK catalog descriptor not found");
            };
            let mut body = request.body.clone();
            let Some(object) = body.as_object_mut() else {
                return Response::error(400, "mount body must be an object");
            };
            object.remove("plugin_name");
            object.insert("type".into(), json!("plugin"));
            if object.get("options").is_some_and(Value::is_null) {
                object.remove("options");
            }
            let configuration = object.entry("config").or_insert_with(|| json!({}));
            let Some(configuration) = configuration.as_object_mut() else {
                return Response::error(400, "mount config must be an object");
            };
            let allowed_headers = match parse_header_allowlist(
                configuration.remove("allowed_response_headers").as_ref(),
            ) {
                Ok(headers) => headers,
                Err(error) => return error,
            };
            configuration.remove("plugin_version");
            configuration.remove("plugin_name");
            for field in [
                "options",
                "default_lease_ttl",
                "max_lease_ttl",
                "force_no_cache",
            ] {
                let Some(value) = configuration.get(field) else {
                    continue;
                };
                let neutral = match field {
                    "options" => value.is_null(),
                    "force_no_cache" => value.as_bool() == Some(false),
                    _ => value.as_str() == Some(""),
                };
                if !neutral {
                    return Response::error(
                        501,
                        "SDK nondefault mount configuration is not implemented",
                    );
                }
                configuration.remove(field);
            }
            configuration.insert("plugin_id".into(), json!(descriptor.name));
            let response = match state.engines.handle(
                request.namespace,
                request.method,
                request.path,
                &body,
                request.now,
            ) {
                Ok(Some(r)) if r.status == 204 => r,
                Ok(_) => return Response::error(503, "SDK mount admission returned no ownership"),
                Err(e) => return Response::error(e.status, &e.message),
            };
            let _ = response;
            let mount = format!(
                "{}/",
                request
                    .path
                    .trim_start_matches("sys/mounts/")
                    .trim_end_matches('/')
            );
            let owner = match state
                .engines
                .bind_sdk_mount(request.namespace, &mount, &descriptor)
            {
                Ok(o) => o,
                Err(e) => return Response::error(e.status, &e.message),
            };
            let owner = match state.engines.set_sdk_response_headers(
                request.namespace,
                &mount,
                &owner,
                allowed_headers,
            ) {
                Ok(owner) => owner,
                Err(error) => return Response::error(error.status, &error.message),
            };
            if let Err(error) = self.prepare_sdk_mount_record_root(&mut state) {
                return error;
            }
            state.schema = state.writer_schema();
            if let Err(e) = self.commit_sdk_control(&mut state, &mut authority, &expected) {
                return e;
            }
            self.state = Some(state.clone());
            // Setup callbacks see the already admitted exact durable mount.
            // A failed external Setup preserves that mount for explicit cleanup.
            return self.stage_sdk_plan(
                &state,
                authority.into(),
                request,
                StageTarget {
                    mount,
                    owner,
                    operation: "_mount",
                    path: "",
                    lease: None,
                },
            );
        }
        if !request.namespace.is_empty() {
            return Response::error(403, "SDK catalog is root-namespace only");
        }
        if request.path == "sys/plugins/catalog" {
            if !matches!(request.method, "GET" | "HEAD") {
                return Response::error(405, "catalog listing requires GET");
            }
            let descriptors = state.engines.sdk_descriptors();
            let mut names = self.plugins.keys().cloned().collect::<BTreeSet<_>>();
            names.extend(descriptors.iter().map(|d| d.name.clone()));
            let mut detailed = descriptors
                .iter()
                .map(|d| json!({"type":"secret","name":d.name,"version":d.version,"builtin":false}))
                .collect::<Vec<_>>();
            let auth_descriptors = state.auth.sdk_auth_descriptors();
            let mut auth_names = self.auth_plugins.keys().cloned().collect::<BTreeSet<_>>();
            auth_names.extend(auth_descriptors.iter().map(|d| d.name.clone()));
            detailed.extend(
                auth_descriptors.iter().map(
                    |d| json!({"type":"auth","name":d.name,"version":d.version,"builtin":false}),
                ),
            );
            self.pending_sdk_control_authority = Some(authority);
            return Response::ok(
                json!({"data":{"secret":names,"auth":auth_names,"database":self.database_plugins.keys().collect::<Vec<_>>(),"detailed":detailed}}),
            );
        }
        let suffix = request
            .path
            .strip_prefix("sys/plugins/catalog/secret")
            .unwrap_or("");
        if suffix.is_empty() {
            if !matches!(request.method, "GET" | "HEAD" | "LIST" | "SCAN") {
                return Response::error(405, "catalog listing requires GET or LIST");
            }
            self.pending_sdk_control_authority = Some(authority);
            return Response::ok(
                json!({"data":{"keys":state.engines.sdk_descriptors().into_iter().map(|d|d.name).collect::<BTreeSet<_>>()}}),
            );
        }
        let Some(name) = suffix
            .strip_prefix('/')
            .filter(|s| !s.is_empty() && !s.contains('/'))
        else {
            return Response::error(404, "catalog entry not found");
        };
        let version = request
            .body
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("");
        let response = match request.method {
            "GET" | "HEAD" => {
                let Some(d) = state.engines.sdk_descriptor(name, version) else {
                    return Response::error(404, "SDK catalog entry not found");
                };
                Response::ok(
                    json!({"data":{"name":d.name,"command":d.command,"args":d.args,"sha256":d.sha256,"version":d.version,"builtin":false}}),
                )
            }
            "POST" | "PUT" => {
                if self.sdk_configuration.is_none() {
                    return Response::error(503, "SDK runtime is not configured");
                }
                let Some(object) = request.body.as_object() else {
                    return Response::error(400, "SDK descriptor must be an object");
                };
                if object.keys().any(|k| {
                    !matches!(
                        k.as_str(),
                        "type" | "args" | "command" | "sha256" | "version"
                    )
                }) || object
                    .get("type")
                    .is_some_and(|t| t.as_str() != Some("secret") && t.as_u64() != Some(3))
                {
                    return Response::error(400, "SDK secret descriptor fields rejected");
                }
                let args = match object.get("args") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(v) => match serde_json::from_value::<Vec<String>>(v.clone()) {
                        Ok(a) => a,
                        Err(_) => return Response::error(400, "invalid SDK arguments"),
                    },
                };
                let d = Descriptor {
                    name: name.into(),
                    version: version.into(),
                    command: object
                        .get("command")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .into(),
                    args,
                    sha256: object
                        .get("sha256")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .into(),
                    generation: 1,
                };
                if state.namespaces.has_custody_state()
                    && state.engines.sdk_descriptor(name, version).is_some()
                {
                    return Response::error(
                        409,
                        "SDK descriptor replacement requires complete independent namespace ownership",
                    );
                }
                if let Err(e) = state.engines.register_sdk_descriptor(d) {
                    return Response::error(e.status, &e.message);
                }
                state.schema = state.writer_schema();
                if let Err(e) = self.commit_sdk_control(&mut state, &mut authority, &expected) {
                    return e;
                }
                self.state = Some(state);
                Response {
                    status: 204,
                    body: json!({}),
                    response_headers: Default::default(),
                    consistency_index: None,
                }
            }
            "DELETE" => {
                if state.namespaces.has_custody_state() {
                    return Response::error(
                        409,
                        "SDK descriptor removal requires complete independent namespace ownership",
                    );
                }
                if let Err(e) = state.engines.deregister_sdk_descriptor(name, version) {
                    return Response::error(e.status, &e.message);
                }
                state.schema = state.writer_schema();
                if let Err(e) = self.commit_sdk_control(&mut state, &mut authority, &expected) {
                    return e;
                }
                self.state = Some(state);
                Response {
                    status: 204,
                    body: json!({}),
                    response_headers: Default::default(),
                    consistency_index: None,
                }
            }
            _ => Response::error(405, "SDK catalog method unsupported"),
        };
        self.pending_sdk_control_authority = Some(authority);
        response
    }
    fn commit_sdk_control(
        &mut self,
        state: &mut State,
        authority: &mut plugin::PluginResponseAuthority,
        expected: &crate::state_record_root::StateIdentity,
    ) -> Result<(), Response> {
        self.validate_plugin_response(authority)?;
        if &self.current_state_identity()? != expected {
            return Err(Response::error(
                503,
                "SDK control snapshot changed before candidate",
            ));
        }
        authority.observe_candidate_time(state)?;
        self.prepare_sdk_mount_record_root(state)?;
        state.schema = state.writer_schema();
        let publication = self.prepare_record_plan(state)?;
        self.validate_plugin_response(authority)?;
        if &self.current_state_identity()? != expected {
            return Err(Response::error(
                503,
                "SDK control snapshot changed before publication",
            ));
        }
        self.commit_record_plan_with_before_publish(
            state,
            publication,
            |auth| authority.validate_live_auth(auth),
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            None,
        )?;
        self.state = Some(state.clone());
        Ok(())
    }

    pub fn install_sdk_backend(&mut self, config: Option<SdkBackendConfig>) -> Result<(), String> {
        if self.state.is_some() {
            return Err("SDK runtime configuration is immutable while unsealed".into());
        }
        if let Some(c) = &config {
            c.validate()?;
        }
        self.retire_sdk_hosts();
        self.sdk_configuration = config;
        Ok(())
    }
    pub(super) fn retire_sdk_hosts(&mut self) {
        for host in self.sdk_hosts.values() {
            host.retire();
        }
        self.sdk_hosts.clear();
    }
    fn sdk_binding_gate(&self, plan: &Plan) -> Result<(), SdkBridgeError> {
        if Instant::now() >= plan.deadline
            || plan.control.fenced.load(Ordering::Acquire)
            || self.recovery_required
            || (plan.control.retiring.load(Ordering::Acquire) && plan.retirement.is_none())
        {
            return Err(SdkBridgeError::Fenced);
        }
        let state = self.state.as_ref().ok_or(SdkBridgeError::Fenced)?;
        if state
            .engines
            .sdk_mount_binding(&plan.namespace, &plan.mount)
            != Some((plan.mount.clone(), plan.owner.clone()))
            || state
                .engines
                .sdk_descriptor(&plan.owner.plugin, &plan.owner.version)
                != Some(plan.descriptor.clone())
            || self
                .sdk_hosts
                .get(&self.sdk_host_key(&plan.namespace, &plan.mount, &plan.owner))
                .is_none_or(|current| !Arc::ptr_eq(current, &plan.control))
        {
            return Err(SdkBridgeError::Fenced);
        }
        Ok(())
    }
    fn sdk_host_key(&self, namespace: &str, mount: &str, owner: &MountOwner) -> String {
        hex(&crypto::digest(
            format!(
                "{}\0{namespace}\0{mount}\0{}\0{}\0{}",
                self.unseal_nonce, owner.mount_incarnation, owner.catalog_generation, owner.version
            )
            .as_bytes(),
        ))
    }
    fn sdk_storage_callback(
        &mut self,
        plan: &Plan,
        op: StorageOp,
        deadline: Instant,
    ) -> Result<StorageReply, SdkBridgeError> {
        let _scope =
            crate::request_deadline::RequestDeadlineScope::enter(deadline.min(plan.deadline));
        let mut authority = plan.authority.lock().map_err(|_| SdkBridgeError::Fenced)?;
        self.validate_sdk_authority(&mut authority)
            .map_err(|_| SdkBridgeError::Fenced)?;
        self.sdk_binding_gate(plan)?;
        let mut state = self.state.clone().ok_or(SdkBridgeError::Fenced)?;
        let auth_clock_changed = authority
            .observe_candidate_time_changed(&mut state)
            .map_err(|_| SdkBridgeError::Fenced)?;
        let observed = expiry::precise(&authority, &state).map_err(|_| SdkBridgeError::Fenced)?;
        let sdk_clock_changed = state.engines.observe_sdk_lease_clock(observed);
        let clock_changed = auth_clock_changed || sdk_clock_changed;
        let mut transaction = plan
            .transaction
            .lock()
            .map_err(|_| SdkBridgeError::Fenced)?;
        if self
            .current_state_identity()
            .map_err(|_| SdkBridgeError::Fenced)?
            != transaction.identity
        {
            return Err(SdkBridgeError::Fenced);
        }
        transaction.engines.observe_sdk_lease_clock(observed);
        let (reply, storage_changed) = match op {
            StorageOp::Get(key) => {
                let entry = transaction
                    .engines
                    .sdk_storage_get(&plan.namespace, &plan.mount, &plan.owner, &key)
                    .map_err(|_| SdkBridgeError::Storage)?;
                (
                    StorageReply::Entry(entry.map(|e| SdkStorageEntry {
                        key: e.key,
                        value: e.value,
                        seal_wrap: e.seal_wrap,
                    })),
                    false,
                )
            }
            StorageOp::List(prefix, after, limit) => {
                let keys = transaction
                    .engines
                    .sdk_storage_list(
                        &plan.namespace,
                        &plan.mount,
                        &plan.owner,
                        &prefix,
                        &after,
                        limit,
                    )
                    .map_err(|_| SdkBridgeError::Storage)?;
                (StorageReply::Keys(keys), false)
            }
            StorageOp::Put(entry) => (
                StorageReply::Empty,
                transaction
                    .engines
                    .sdk_storage_put(&plan.namespace, &plan.mount, &plan.owner, entry)
                    .map_err(|_| SdkBridgeError::Storage)?,
            ),
            StorageOp::Delete(key) => (
                StorageReply::Empty,
                transaction
                    .engines
                    .sdk_storage_delete(&plan.namespace, &plan.mount, &plan.owner, &key)
                    .map_err(|_| SdkBridgeError::Storage)?,
            ),
        };
        transaction.changed |= storage_changed;
        let changed = clock_changed;
        if changed {
            state.schema = state.writer_schema();
            let publication = self
                .prepare_record_plan(&mut state)
                .map_err(|_| SdkBridgeError::Storage)?;
            self.validate_sdk_authority(&mut authority)
                .map_err(|_| SdkBridgeError::Fenced)?;
            self.sdk_binding_gate(plan)?;
            if self
                .commit_record_plan_with_before_publish(
                    &state,
                    publication,
                    |auth| authority.validate_live_auth(auth),
                    #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                    None,
                )
                .is_err()
            {
                return Err(if self.recovery_required {
                    SdkBridgeError::OutcomeUnknown
                } else {
                    SdkBridgeError::Fenced
                });
            }
            // Publish the actual committed owner even when the following gate fails.
            self.state = Some(state);
            transaction.identity = self
                .current_state_identity()
                .map_err(|_| SdkBridgeError::OutcomeUnknown)?;
        }
        self.validate_sdk_authority(&mut authority).map_err(|_| {
            if changed {
                SdkBridgeError::OutcomeUnknown
            } else {
                SdkBridgeError::Fenced
            }
        })?;
        self.sdk_binding_gate(plan)?;
        Ok(reply)
    }
    pub(super) fn stage_sdk_request(
        &mut self,
        state: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some((mount, owner)) = state
            .engines
            .sdk_mount_binding(request.namespace, request.path)
        else {
            return Response::error(404, "SDK mount not found");
        };
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        let operation = match kv_authorization_method(request.method, request.body) {
            "GET" | "HEAD" => "read",
            "PUT" | "POST" => "update",
            "PATCH" => "patch",
            "DELETE" => "delete",
            "LIST" => "list",
            "SCAN" => "scan",
            _ => return Response::error(405, "SDK operation unsupported"),
        };
        let capability = match operation {
            "read" => "read",
            "list" => "list",
            "scan" => "scan",
            "delete" => "delete",
            _ => "update",
        };
        if request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
            return Response::error(501, "SDK response wrapping is not implemented");
        }
        let mut authority = plugin::PluginResponseAuthority::new(
            principal,
            &state,
            request,
            capability,
            false,
            &self.unseal_nonce,
        )
        .with_sdk_clock();
        if let Err(error) = self.validate_plugin_response(&mut authority) {
            return error;
        }
        let path = request.path.strip_prefix(&mount).unwrap_or("").to_owned();
        self.stage_sdk_plan(
            &state,
            authority.into(),
            request,
            StageTarget {
                mount,
                owner,
                operation,
                path: &path,
                lease: None,
            },
        )
    }
    fn stage_sdk_plan(
        &mut self,
        state: &State,
        mut authority: expiry::Authority,
        request: &RequestView<'_>,
        target: StageTarget<'_>,
    ) -> Response {
        let StageTarget {
            mount,
            owner,
            operation,
            path,
            lease,
        } = target;
        let Some(config) = self.sdk_configuration.clone() else {
            return Response::error(503, "SDK runtime is not configured");
        };
        let Some(descriptor) = state.engines.sdk_descriptor(&owner.plugin, &owner.version) else {
            return Response::error(503, "SDK descriptor absent");
        };
        if let Err(error) = self.validate_sdk_authority(&mut authority) {
            return error;
        }
        let key = self.sdk_host_key(request.namespace, &mount, &owner);
        if self
            .sdk_hosts
            .get(&key)
            .is_some_and(|control| control.fenced.load(Ordering::Acquire))
        {
            if self
                .sdk_hosts
                .get(&key)
                .is_some_and(|control| control.busy.load(Ordering::Acquire))
            {
                return Response::error(
                    503,
                    "SDK retired owner still completing its original invocation",
                );
            }
            // A new independently admitted request retains its own original
            // capsule. It does not revive the fenced call or retry its effect.
            if let Some(retired) = self.sdk_hosts.remove(&key) {
                retired.retire();
            }
        }
        let control = if let Some(c) = self.sdk_hosts.get(&key) {
            Arc::clone(c)
        } else {
            let suffix = match crypto::random::<16>() {
                Ok(bytes) => hex(&bytes),
                Err(_) => return Response::error(503, "SDK runtime randomness unavailable"),
            };
            let socket = config.runtime_directory.join(suffix);
            if private_directory(&socket).is_err() {
                return Response::error(503, "SDK runtime directory unavailable");
            }
            let launch = SdkLaunch {
                companion: config.companion,
                companion_sha256: match checksum(&config.companion_sha256) {
                    Ok(v) => v,
                    Err(e) => return e,
                },
                plugin: config.plugin_directory.join(&descriptor.command),
                plugin_sha256: match checksum(&descriptor.sha256) {
                    Ok(v) => v,
                    Err(e) => return e,
                },
                plugin_args: descriptor.args.clone(),
                socket_directory: socket.clone(),
                private_log: socket.join("companion.private"),
                timeout: Duration::from_millis(config.timeout_ms),
                default_ttl_seconds: 2_764_800,
                max_ttl_seconds: 2_764_800,
            };
            let control = match start_worker(launch) {
                Ok(c) => c,
                Err(e) => return e,
            };
            self.sdk_hosts.insert(key, Arc::clone(&control));
            control
        };

        let data = if let Some(call) = &lease {
            call.request_data()
        } else if request.body.is_null() {
            json!({})
        } else {
            request.body.clone()
        };
        let path = path.to_owned();
        let deadline = crate::request_deadline::current()
            .unwrap_or(request.admission_started + Duration::from_millis(config.timeout_ms));
        let identity = match self.current_state_identity() {
            Ok(identity) => identity,
            Err(error) => return error,
        };
        self.pending_sdk_request = Some(Plan {
            namespace: request.namespace.into(),
            mount,
            owner,
            descriptor,
            control,
            authority: Mutex::new(authority),
            operation: operation.into(),
            path,
            data,
            lease: Mutex::new(lease.map(Box::new)),
            retirement: None,
            transaction: Mutex::new(StorageTransaction {
                engines: state.engines.clone(),
                identity,
                changed: false,
            }),
            deadline,
        });
        Response::error(500, "SDK request was not dispatched")
    }
    fn sdk_delivery_veto(
        &mut self,
        mut response: Response,
        error: Response,
        fingerprint: &str,
        original_now: u64,
    ) -> Response {
        erase_json(&mut response.body);
        response.response_headers.clear();
        response.consistency_index = None;
        if self
            .audit_event(
                "sdk-delivery-veto",
                fingerprint,
                original_now,
                Some(error.status),
            )
            .is_err()
        {
            crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
            self.recovery_required = true;
            self.ha_activation = None;
            self.retire_sdk_hosts();
            return Response::error(503, "SDK delivery veto audit failed; recovery required");
        }
        error
    }
    fn sdk_delivery_capsule_lost(&mut self, mut response: Response) -> Response {
        erase_json(&mut response.body);
        response.response_headers.clear();
        response.consistency_index = None;
        crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
        self.recovery_required = true;
        self.ha_activation = None;
        self.retire_sdk_hosts();
        Response::error(503, "SDK delivery capsule was lost")
    }
    pub(super) fn complete_pending_sdk_control_delivery(
        &mut self,
        expected: bool,
        response: Response,
        fingerprint: &str,
    ) -> Response {
        match (expected, self.pending_sdk_control_authority.take()) {
            (true, Some(mut authority)) => {
                if let Err(error) = self.validate_plugin_response(&mut authority) {
                    return self.sdk_delivery_veto(response, error, fingerprint, authority.now());
                }
                response
            }
            (false, None) => response,
            _ => self.sdk_delivery_capsule_lost(response),
        }
    }
    pub(super) fn complete_sdk_delivery(
        &mut self,
        plan: &mut Plan,
        response: Response,
        fingerprint: &str,
    ) -> Response {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline);
        let gate = match plan.authority.lock() {
            Ok(mut authority) => {
                let original_now = authority.now();
                self.validate_sdk_authority(&mut authority)
                    .and_then(|()| {
                        if plan.retirement.is_some() {
                            self.sdk_retirement_delivery_gate(plan)
                        } else {
                            self.sdk_binding_gate(plan).map_err(bridge_failure)
                        }
                    })
                    .map_err(|error| (error, original_now))
            }
            Err(_) => {
                plan.control.retire();
                return self.sdk_delivery_capsule_lost(response);
            }
        };
        if let Err((error, original_now)) = gate {
            plan.control.retire();
            return self.sdk_delivery_veto(response, error, fingerprint, original_now);
        }
        response
    }
    pub(super) fn finalize_sdk_request(
        &mut self,
        plan: &mut Plan,
        result: Result<Option<Value>, Response>,
    ) -> Response {
        let mut value = match result {
            Ok(v) => v,
            Err(e) => return e,
        };
        let gate = (|| {
            let mut authority = plan
                .authority
                .lock()
                .map_err(|_| Response::error(503, "SDK affine authority unavailable"))?;
            self.validate_sdk_authority(&mut authority)?;
            self.sdk_binding_gate(plan).map_err(bridge_failure)
        })();
        if let Err(e) = gate {
            if let Some(v) = &mut value {
                erase_json(v);
            }
            plan.control.retire();
            return e;
        }
        if plan.retirement.is_some() {
            return self.finalize_sdk_retirement(plan);
        }
        self.finalize_sdk_transaction(plan, value.take())
    }
}

#[cfg(test)]
#[path = "service_sdk_authority_tests.rs"]
mod authority_tests;
