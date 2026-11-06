// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Ten native read operations with encrypted original results and durable no-replay bindings.
//! Cancellation controls an owned Rust future, never a caller-selected process.
use super::{
	config::runtime_config,
	operation_crypto::{
		NativePayloadKind, ResultCryptoScope, TrustedResultBinding, MAX_PACKET_BYTES,
		MAX_PAYLOAD_BYTES,
	},
	request_audit::{self, AuditCompletion, RequestIdentity},
};
use anyhow::{anyhow, bail, Result};
use rmcp::{
	handler::server::tool::IntoCallToolResult,
	model::{CallToolResponse, CallToolResult},
	schemars,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
	collections::{HashMap, VecDeque},
	fs::File,
	io::{Read, Write},
	path::{Path, PathBuf},
	sync::{
		atomic::{AtomicBool, AtomicU8, Ordering},
		Arc, Mutex, OnceLock,
	},
	time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;

const STORE_NAME: &str = "request-operations-v10";
const ANCHOR_NAME: &str = ".request-operations-v10-anchor.json";
const MAX_RECORD_BYTES: usize = 4096;
const QUEUED: u8 = 0;
const RUNNING: u8 = 1;
const SETTLING: u8 = 2;
static STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static ROOT_PINS: OnceLock<Mutex<HashMap<PathBuf, (u64, u64)>>> = OnceLock::new();
static ADMISSION: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
static STOPPING: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(
	tag = "tool",
	content = "arguments",
	rename_all = "snake_case",
	deny_unknown_fields
)]
pub enum ReadOperation {
	ReadMultipleFiles(super::multi_read::MultiReadParams),
	FileInfo(super::binary::FileInfoParams),
	BinaryRead(super::binary::BinaryReadParams),
	ProcessStatus(super::jobs::ProcessRefParams),
	ProcessRead(super::jobs::ProcessReadParams),
	ProcessWait(super::jobs::ProcessWaitParams),
	ProcessList(super::jobs::ProcessListParams),
	HardwareSnapshot(super::inspect::HostParams),
	ServiceStatus(super::inspect::ServiceStatusParams),
	NetworkInspect(super::inspect::HostParams),
}
pub(super) fn eligible(tool: &str) -> bool {
	matches!(
		tool,
		"read_multiple_files"
			| "file_info"
			| "binary_read"
			| "process_status"
			| "process_read"
			| "process_wait"
			| "process_list"
			| "hardware_snapshot"
			| "service_status"
			| "network_inspect"
	)
}
impl ReadOperation {
	fn tool(&self) -> &'static str {
		match self {
			Self::ReadMultipleFiles(_) => "read_multiple_files",
			Self::FileInfo(_) => "file_info",
			Self::BinaryRead(_) => "binary_read",
			Self::ProcessStatus(_) => "process_status",
			Self::ProcessRead(_) => "process_read",
			Self::ProcessWait(_) => "process_wait",
			Self::ProcessList(_) => "process_list",
			Self::HardwareSnapshot(_) => "hardware_snapshot",
			Self::ServiceStatus(_) => "service_status",
			Self::NetworkInspect(_) => "network_inspect",
		}
	}
	fn validate(&self) -> Result<()> {
		let host = match self {
			Self::ReadMultipleFiles(p) => Some(p.host.as_str()),
			Self::FileInfo(p) => Some(p.host.as_str()),
			Self::BinaryRead(p) => Some(p.host.as_str()),
			Self::ProcessStatus(p) => Some(p.host.as_str()),
			Self::ProcessRead(p) => Some(p.host.as_str()),
			Self::ProcessWait(p) => Some(p.host.as_str()),
			Self::ProcessList(p) => p.host.as_deref(),
			Self::HardwareSnapshot(p) => Some(p.host.as_str()),
			Self::ServiceStatus(p) => Some(p.host.as_str()),
			Self::NetworkInspect(p) => Some(p.host.as_str()),
		};
		if let Some(host) = host {
			runtime_config()?.host(host)?;
		}
		// Every actual read delegates to the original native policy checks; no synthetic
		// SSH target, shell, privilege, filesystem write or recursive tool dispatch.
		Ok(())
	}
	async fn dispatch(self) -> Result<CallToolResponse, rmcp::ErrorData> {
		let result = match self {
			Self::ReadMultipleFiles(p) => super::multi_read::read(p).await,
			Self::FileInfo(p) => super::binary::info(p).await,
			Self::BinaryRead(p) => super::binary::read(p).await,
			Self::ProcessStatus(p) => super::jobs::status_job(p).await,
			Self::ProcessRead(p) => super::jobs::read_job(p).await,
			Self::ProcessWait(p) => super::jobs::wait_job(p).await,
			Self::ProcessList(p) => super::jobs::list_jobs(p),
			Self::HardwareSnapshot(p) => super::inspect::hardware_snapshot(p).await,
			Self::ServiceStatus(p) => super::inspect::service_status(p).await,
			Self::NetworkInspect(p) => super::inspect::network_inspect(p).await,
		};
		result
			.map_err(|error| error.to_string())
			.into_call_tool_result()
	}
}
#[derive(Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationStartParams {
	pub operation: ReadOperation,
	/// Required private 1..128-byte key, unchanged typed arguments must reuse the same key.
	pub idempotency_key: String,
}
#[derive(Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationStatusParams {
	pub operation_id: String,
}
#[derive(Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationCancelParams {
	pub operation_id: String,
}
#[derive(Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationResultParams {
	pub operation_id: String,
	#[serde(default)]
	pub offset: Option<u32>,
	/// Independent original-byte page; at most 16384 bytes. Default 16384.
	#[serde(default)]
	pub limit: Option<u16>,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Binding {
	request_id: String,
	owner: String,
	tool_name: String,
	accepted_unix_ms: u128,
	key_hash: String,
	request_hash: String,
	policy_binding: String,
	ledger_identity: String,
}
impl Binding {
	fn identity(&self) -> RequestIdentity {
		RequestIdentity {
			request_id: self.request_id.clone(),
			owner: self.owner.clone(),
			tool_name: self.tool_name.clone(),
			accepted_unix_ms: self.accepted_unix_ms,
		}
	}
}
enum Reservation {
	New(Binding),
	Existing(Binding),
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
	namespace_id: String,
	payloads_device: u64,
	payloads_inode: u64,
	device: u64,
	inode: u64,
	occupancy_device: u64,
	occupancy_inode: u64,
	intents_device: u64,
	intents_inode: u64,
	metadata_lock_device: u64,
	metadata_lock_inode: u64,
	controller_lock_device: u64,
	controller_lock_inode: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Outcome {
	request_id: String,
	owner: String,
	key_hash: String,
	policy_binding: String,
	tool_name: String,
	accepted_unix_ms: u128,
	request_hash: String,
	ledger_identity: String,
	state: String,
}
fn check_outcome(b: &Binding, o: &Outcome) -> Result<()> {
	if o.request_id != b.request_id
		|| o.owner != b.owner
		|| o.key_hash != b.key_hash
		|| o.policy_binding != b.policy_binding
		|| o.tool_name != b.tool_name
		|| o.accepted_unix_ms != b.accepted_unix_ms
		|| o.request_hash != b.request_hash
		|| o.ledger_identity != b.ledger_identity
		|| !matches!(
			o.state.as_str(),
			"completed" | "failed" | "cancelled_before_dispatch" | "cancelled_future" | "unknown"
		) {
		bail!("async outcome unavailable");
	}
	Ok(())
}
struct Active {
	binding: Binding,
	cancel: CancellationToken,
	phase: AtomicU8,
}
#[derive(Default)]
struct Registry {
	reserved: HashMap<String, usize>,
	active: HashMap<String, Arc<Active>>,
	lease: Option<(PathBuf, File)>,
}
fn registry() -> Result<std::sync::MutexGuard<'static, Registry>> {
	REGISTRY
		.get_or_init(|| Mutex::new(Registry::default()))
		.lock()
		.map_err(|_| anyhow!("async request state unavailable"))
}
struct Slot {
	owner: String,
	_shared: super::request_async::Slot,
}
impl Slot {
	fn take(owner: &str) -> Result<Self> {
		let shared = super::request_async::Slot::take(owner)?;
		let mut r = registry()?;
		*r.reserved.entry(owner.into()).or_default() += 1;
		Ok(Self {
			owner: owner.into(),
			_shared: shared,
		})
	}
}
impl Drop for Slot {
	fn drop(&mut self) {
		if let Ok(mut r) = registry() {
			if let Some(count) = r.reserved.get_mut(&self.owner) {
				*count = count.saturating_sub(1);
				if *count == 0 {
					r.reserved.remove(&self.owner);
				}
			}
		}
	}
}
struct ActiveGuard {
	id: String,
	_slot: Slot,
}
impl Drop for ActiveGuard {
	fn drop(&mut self) {
		if let Ok(mut r) = registry() {
			r.active.remove(&self.id);
		}
	}
}
fn valid_id(s: &str) -> bool {
	s.len() == 64
		&& s.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_key(s: &str) -> bool {
	!s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control)
}
fn digest(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.iter()
		.map(|b| format!("{b:02x}"))
		.collect()
}
fn next_id() -> Result<String> {
	let mut bytes = [0u8; 32];
	File::open("/dev/urandom")?.read_exact(&mut bytes)?;
	Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn valid_binding(r: &Binding) -> bool {
	[
		&r.request_id,
		&r.owner,
		&r.key_hash,
		&r.request_hash,
		&r.policy_binding,
		&r.ledger_identity,
	]
	.iter()
	.all(|v| valid_id(v))
		&& eligible(&r.tool_name)
}
#[cfg(unix)]
fn open_at(parent: &File, name: &str, flags: i32, mode: u32) -> Result<File> {
	use std::os::fd::{AsRawFd, FromRawFd};
	let name = std::ffi::CString::new(name)?;
	let fd = unsafe {
		libc::openat(
			parent.as_raw_fd(),
			name.as_ptr(),
			flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			mode,
		)
	};
	if fd < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	Ok(unsafe { File::from_raw_fd(fd) })
}
#[cfg(unix)]
fn private_dir(file: &File) -> Result<()> {
	use std::os::unix::fs::MetadataExt;
	let m = file.metadata()?;
	if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7777 != 0o700 {
		bail!("private async directory unavailable");
	}
	Ok(())
}
#[cfg(unix)]
fn private_file(file: &File) -> Result<()> {
	use std::os::unix::fs::MetadataExt;
	let m = file.metadata()?;
	if !m.is_file()
		|| m.uid() != unsafe { libc::geteuid() }
		|| m.mode() & 0o7777 != 0o600
		|| m.nlink() != 1
		|| m.len() > MAX_RECORD_BYTES as u64
	{
		bail!("private async metadata unavailable");
	}
	Ok(())
}
#[cfg(unix)]
fn root_handle(root: &Path) -> Result<File> {
	let raw = root
		.to_str()
		.ok_or_else(|| anyhow!("private async root unavailable"))?;
	if !root.is_absolute() || raw.split('/').any(|p| p == "." || p == "..") {
		bail!("private async root unavailable");
	}
	let mut base = File::open("/")?;
	for component in raw.split('/').filter(|p| !p.is_empty()) {
		base = open_at(&base, component, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	}
	Ok(base)
}
#[cfg(unix)]
fn root_at(root: &Path) -> Result<File> {
	let base = root_handle(root)?;
	private_dir(&base)?;
	Ok(base)
}
#[cfg(unix)]
fn make_dir(parent: &File, name: &str) -> Result<File> {
	use std::os::fd::AsRawFd;
	let n = std::ffi::CString::new(name)?;
	if unsafe { libc::mkdirat(parent.as_raw_fd(), n.as_ptr(), 0o700) } < 0 {
		let error = std::io::Error::last_os_error();
		if error.kind() != std::io::ErrorKind::AlreadyExists {
			return Err(error.into());
		}
	} else {
		parent.sync_all()?;
	}
	let dir = open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_dir(&dir)?;
	Ok(dir)
}
#[cfg(unix)]
fn read_json<T: serde::de::DeserializeOwned>(dir: &File, name: &str) -> Result<T> {
	read_json_observed(dir, name, |_| Ok(()))
}
#[cfg(unix)]
fn read_json_observed<T: serde::de::DeserializeOwned>(
	dir: &File,
	name: &str,
	after_read: impl FnOnce(&File) -> Result<()>,
) -> Result<T> {
	use std::os::unix::fs::MetadataExt;
	let mut f = open_at(dir, name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
	private_file(&f)?;
	let before = f.metadata()?;
	if before.len() > MAX_RECORD_BYTES as u64 {
		bail!("private async metadata unavailable");
	}
	let mut bytes = Vec::new();
	Read::by_ref(&mut f)
		.take((MAX_RECORD_BYTES + 1) as u64)
		.read_to_end(&mut bytes)?;
	after_read(&f)?;
	let after = f.metadata()?;
	private_file(&f)?;
	if bytes.len() > MAX_RECORD_BYTES
		|| bytes.len() as u64 != before.len()
		|| before.dev() != after.dev()
		|| before.ino() != after.ino()
		|| before.uid() != after.uid()
		|| before.mode() != after.mode()
		|| before.nlink() != after.nlink()
		|| before.len() != after.len()
		|| before.mtime() != after.mtime()
		|| before.mtime_nsec() != after.mtime_nsec()
		|| before.ctime() != after.ctime()
		|| before.ctime_nsec() != after.ctime_nsec()
	{
		bail!("private async metadata changed while reading");
	}
	Ok(serde_json::from_slice(&bytes)?)
}
#[cfg(unix)]
fn publish<T: Serialize>(dir: &File, name: &str, value: &T) -> Result<()> {
	use std::os::fd::AsRawFd;
	let bytes = serde_json::to_vec(value)?;
	if bytes.len() > MAX_RECORD_BYTES {
		bail!("async metadata bound exceeded");
	}
	let temporary = format!(".publish-{}", next_id()?);
	let mut f = open_at(
		dir,
		&temporary,
		libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
		0o600,
	)?;
	let result = (|| {
		f.write_all(&bytes)?;
		f.sync_all()?;
		let from = std::ffi::CString::new(temporary.as_str())?;
		let to = std::ffi::CString::new(name)?;
		if unsafe {
			libc::linkat(
				dir.as_raw_fd(),
				from.as_ptr(),
				dir.as_raw_fd(),
				to.as_ptr(),
				0,
			)
		} < 0
		{
			return Err(std::io::Error::last_os_error().into());
		}
		if unsafe { libc::unlinkat(dir.as_raw_fd(), from.as_ptr(), 0) } < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		dir.sync_all()?;
		Ok(())
	})();
	// Only staging may be removed on failure. A published key is never erased.
	if result.is_err() {
		if let Ok(n) = std::ffi::CString::new(temporary.as_str()) {
			unsafe {
				libc::unlinkat(dir.as_raw_fd(), n.as_ptr(), 0);
			}
		}
	}
	result
}
#[cfg(unix)]
fn create_lock(dir: &File, name: &str) -> Result<File> {
	let file = open_at(
		dir,
		name,
		libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
		0o600,
	)?;
	private_file(&file)?;
	file.sync_all()?;
	dir.sync_all()?;
	Ok(file)
}
#[cfg(unix)]
fn pinned_lock(dir: &File, name: &str, device: u64, inode: u64) -> Result<File> {
	use std::os::unix::fs::MetadataExt;
	let file = open_at(dir, name, libc::O_RDWR | libc::O_NONBLOCK, 0)?;
	private_file(&file)?;
	let metadata = file.metadata()?;
	if metadata.dev() != device || metadata.ino() != inode || metadata.len() != 0 {
		bail!("async lock identity changed; never create a replacement lock");
	}
	Ok(file)
}
#[cfg(unix)]
fn anchored_lock(root: &Path, dir: &File, name: &str) -> Result<File> {
	use std::os::unix::fs::MetadataExt;
	let base = root_at(root)?;
	let anchor: Anchor =
		read_json(&base, ANCHOR_NAME).map_err(|_| anyhow!("async lock anchor unavailable"))?;
	let metadata = dir.metadata()?;
	if metadata.dev() != anchor.device || metadata.ino() != anchor.inode {
		bail!("async lock namespace changed");
	}
	match name {
		".lock" => pinned_lock(
			dir,
			name,
			anchor.metadata_lock_device,
			anchor.metadata_lock_inode,
		),
		".controller.lock" => pinned_lock(
			dir,
			name,
			anchor.controller_lock_device,
			anchor.controller_lock_inode,
		),
		_ => bail!("async lock identity unavailable"),
	}
}
#[cfg(unix)]
fn store(root: &Path) -> Result<File> {
	use std::os::unix::fs::MetadataExt;
	let base = root_at(root)?;
	let metadata = base.metadata()?;
	let mut pins = ROOT_PINS
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.map_err(|_| anyhow!("async root binding unavailable"))?;
	match pins.get(root) {
		Some(old) if *old != (metadata.dev(), metadata.ino()) => {
			bail!("async root binding changed; keys unavailable")
		}
		Some(_) => {}
		None => {
			pins.insert(root.into(), (metadata.dev(), metadata.ino()));
		}
	}
	drop(pins);
	let existing = read_json::<Anchor>(&base, ANCHOR_NAME);
	let dir = match existing {
		Ok(anchor) => {
			let dir = open_at(&base, STORE_NAME, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
			if !valid_id(&anchor.namespace_id) {
				bail!("operation ledger identity unavailable");
			}
			let identity: String = read_json(&dir, ".identity.json")?;
			if identity != anchor.namespace_id {
				bail!("operation namespace identity changed");
			}
			let payloads = open_at(&dir, ".payloads", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
			private_dir(&payloads)?;
			let pm = payloads.metadata()?;
			if pm.dev() != anchor.payloads_device || pm.ino() != anchor.payloads_inode {
				bail!("operation payload namespace changed; never replay");
			}

			private_dir(&dir)?;
			let m = dir.metadata()?;
			if m.dev() != anchor.device || m.ino() != anchor.inode {
				bail!("async journal binding changed; keys unavailable");
			}
			let occupancy = open_at(&dir, ".occupied", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
			private_dir(&occupancy)?;
			let occupied = occupancy.metadata()?;
			if occupied.dev() != anchor.occupancy_device || occupied.ino() != anchor.occupancy_inode
			{
				bail!("async occupancy binding changed; never replay");
			}
			let intents = open_at(&dir, ".intents", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
			private_dir(&intents)?;
			let intent_metadata = intents.metadata()?;
			if intent_metadata.dev() != anchor.intents_device
				|| intent_metadata.ino() != anchor.intents_inode
			{
				bail!("async intent history binding changed; never replay");
			}
			pinned_lock(
				&dir,
				".lock",
				anchor.metadata_lock_device,
				anchor.metadata_lock_inode,
			)?;
			pinned_lock(
				&dir,
				".controller.lock",
				anchor.controller_lock_device,
				anchor.controller_lock_inode,
			)?;
			dir
		}
		Err(error) if missing(&error) => {
			// An unanchored existing directory is uncertain, never an empty namespace.
			match open_at(&base, STORE_NAME, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
				Ok(_) => bail!("unanchored async journal unavailable"),
				Err(error) if missing(&error) => {}
				Err(error) => return Err(error),
			}
			let dir = make_dir(&base, STORE_NAME)?;
			let occupancy = make_dir(&dir, ".occupied")?;
			let payloads = make_dir(&dir, ".payloads")?.metadata()?;
			let namespace_id = next_id()?;
			publish(&dir, ".identity.json", &namespace_id)?;
			let occupied = occupancy.metadata()?;
			let intents = make_dir(&dir, ".intents")?;
			let intent_metadata = intents.metadata()?;
			let metadata_lock = create_lock(&dir, ".lock")?.metadata()?;
			let controller_lock = create_lock(&dir, ".controller.lock")?.metadata()?;
			let m = dir.metadata()?;
			publish(
				&base,
				ANCHOR_NAME,
				&Anchor {
					namespace_id,
					payloads_device: payloads.dev(),
					payloads_inode: payloads.ino(),
					device: m.dev(),
					inode: m.ino(),
					occupancy_device: occupied.dev(),
					occupancy_inode: occupied.ino(),
					intents_device: intent_metadata.dev(),
					intents_inode: intent_metadata.ino(),
					metadata_lock_device: metadata_lock.dev(),
					metadata_lock_inode: metadata_lock.ino(),
					controller_lock_device: controller_lock.dev(),
					controller_lock_inode: controller_lock.ino(),
				},
			)?;
			dir
		}
		Err(_) => bail!("async journal anchor unavailable"),
	};
	make_dir(&dir, ".outcomes")?;
	Ok(dir)
}
fn missing(error: &anyhow::Error) -> bool {
	error
		.downcast_ref::<std::io::Error>()
		.is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}
#[cfg(unix)]
struct MetadataLock(File);
#[cfg(unix)]
impl Drop for MetadataLock {
	fn drop(&mut self) {
		use std::os::fd::AsRawFd;
		// A forked child shares this open-file description until exec or exit.
		// Closing only the parent's fd would leave its short metadata lock held.
		// The controller's long-lived ownership lease deliberately stays separate.
		unsafe {
			libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
		}
	}
}
#[cfg(unix)]
fn locked_store(root: &Path) -> Result<(File, MetadataLock)> {
	use std::os::fd::AsRawFd;
	let dir = store(root)?;
	let lock = anchored_lock(root, &dir, ".lock")?;
	if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	Ok((dir, MetadataLock(lock)))
}
#[cfg(all(test, unix))]
fn names(dir: &File) -> Result<Vec<String>> {
	names_impl(dir, true)
}
#[cfg(all(test, unix))]
fn record_names(dir: &File) -> Result<Vec<String>> {
	names_impl(dir, false)
}
#[cfg(all(test, unix))]
fn names_impl(dir: &File, root: bool) -> Result<Vec<String>> {
	let mut names = Vec::new();
	for_each_name(dir, root, |name| {
		names.push(name.to_owned());
		Ok(())
	})?;
	Ok(names)
}
#[cfg(unix)]
fn for_each_name(dir: &File, root: bool, mut visit: impl FnMut(&str) -> Result<()>) -> Result<()> {
	use std::os::fd::AsRawFd;
	let scan = open_at(dir, ".", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	let fd = unsafe { libc::dup(scan.as_raw_fd()) };
	if fd < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	let stream = unsafe { libc::fdopendir(fd) };
	if stream.is_null() {
		unsafe {
			libc::close(fd);
		}
		return Err(std::io::Error::last_os_error().into());
	}
	struct Stream(*mut libc::DIR);
	impl Drop for Stream {
		fn drop(&mut self) {
			unsafe {
				libc::closedir(self.0);
			}
		}
	}
	let guard = Stream(stream);
	loop {
		#[cfg(target_os = "linux")]
		let errno = unsafe { libc::__errno_location() };
		#[cfg(target_os = "macos")]
		let errno = unsafe { libc::__error() };
		#[cfg(not(any(target_os = "linux", target_os = "macos")))]
		{
			let _ = &guard;
			bail!("async directory scan unsupported");
		}
		#[cfg(any(target_os = "linux", target_os = "macos"))]
		{
			unsafe {
				*errno = 0;
			}
			let entry = unsafe { libc::readdir(guard.0) };
			if entry.is_null() {
				if unsafe { *errno } != 0 {
					bail!("async directory scan unavailable");
				}
				break;
			}
			let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
				.to_str()?
				.to_owned();
			if matches!(name.as_str(), "." | "..")
				|| (root
					&& matches!(
						name.as_str(),
						".lock"
							| ".outcomes" | ".occupied"
							| ".intents" | ".controller.lock"
							| ".payloads" | ".identity.json"
					)) {
				continue;
			}
			// Incomplete publication is an explicit refusal, never silently treated absent.
			if !name.ends_with(".json") || !valid_id(&name[..name.len().saturating_sub(5)]) {
				bail!("async key registry unavailable; administrator review required");
			}
			visit(&name)?;
		}
	}
	Ok(())
}
#[cfg(all(test, unix))]
fn bindings(dir: &File) -> Result<Vec<Binding>> {
	let occupancy = open_at(dir, ".occupied", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	let intents = open_at(dir, ".intents", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	let outcomes = open_at(dir, ".outcomes", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_dir(&occupancy)?;
	private_dir(&intents)?;
	private_dir(&outcomes)?;
	let mut occupied_names = record_names(&occupancy)?;
	let mut primary_names = names(dir)?;
	occupied_names.sort_unstable();
	primary_names.sort_unstable();
	let mut by_key = HashMap::new();
	let mut by_id = HashMap::new();
	for name in record_names(&intents)? {
		let b: Binding =
			read_json(&intents, &name).map_err(|_| anyhow!("async intent history unavailable"))?;
		if !valid_binding(&b)
			|| !valid_id(&b.ledger_identity)
			|| name != format!("{}.json", b.request_id)
			|| by_key.insert(b.key_hash.clone(), b.clone()).is_some()
			|| by_id.insert(b.request_id.clone(), b).is_some()
		{
			bail!("async intent history unavailable");
		}
	}
	if occupied_names != primary_names || occupied_names.len() != by_key.len() {
		bail!("async key history incomplete; never replay or repair automatically");
	}
	let mut result = Vec::new();
	for name in occupied_names {
		let b = binding_pair(dir, &name[..name.len() - 5])?
			.ok_or_else(|| anyhow!("async key registry changed"))?;
		if by_key.get(&b.key_hash) != Some(&b) {
			bail!("async key history identity changed");
		}
		result.push(b);
	}
	for name in record_names(&outcomes)? {
		let outcome: Outcome = read_json(&outcomes, &name)
			.map_err(|_| anyhow!("async outcome history unavailable"))?;
		let b = by_id.get(&outcome.request_id).ok_or_else(|| {
			anyhow!("async outcome has no complete historical binding; never replay")
		})?;
		if name != format!("{}.json", outcome.request_id) {
			bail!("async outcome identity changed");
		}
		check_outcome(b, &outcome)?;
	}
	Ok(result)
}
#[cfg(unix)]
#[derive(Clone, PartialEq, Eq)]
struct DirectoryStamp {
	device: u64,
	inode: u64,
	modified: (i64, i64),
	changed: (i64, i64),
	namespace: super::namespace_version::Version,
}
#[cfg(unix)]
#[derive(Clone, PartialEq, Eq)]
struct NamespaceStamp([DirectoryStamp; 4]);
#[cfg(unix)]
static NAMESPACE_CACHE: OnceLock<Mutex<VecDeque<NamespaceStamp>>> = OnceLock::new();

#[cfg(unix)]
fn namespace_stamp(directory: &File) -> Result<NamespaceStamp> {
	use std::os::unix::fs::MetadataExt;
	fn stamp(directory: &File) -> Result<DirectoryStamp> {
		private_dir(directory)?;
		let metadata = directory.metadata()?;
		Ok(DirectoryStamp {
			device: metadata.dev(),
			inode: metadata.ino(),
			modified: (metadata.mtime(), metadata.mtime_nsec()),
			changed: (metadata.ctime(), metadata.ctime_nsec()),
			namespace: super::namespace_version::version(directory)?,
		})
	}
	let occupied = open_at(
		directory,
		".occupied",
		libc::O_RDONLY | libc::O_DIRECTORY,
		0,
	)?;
	let intents = open_at(directory, ".intents", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	let outcomes = open_at(
		directory,
		".outcomes",
		libc::O_RDONLY | libc::O_DIRECTORY,
		0,
	)?;
	Ok(NamespaceStamp([
		stamp(directory)?,
		stamp(&occupied)?,
		stamp(&intents)?,
		stamp(&outcomes)?,
	]))
}
#[cfg(unix)]
fn cache_namespace(directory: &File) -> Result<()> {
	let stamp = namespace_stamp(directory)?;
	let mut cache = NAMESPACE_CACHE
		.get_or_init(|| Mutex::new(VecDeque::new()))
		.lock()
		.map_err(|_| anyhow!("async namespace cache unavailable"))?;
	cache.retain(|old| (old.0[0].device, old.0[0].inode) != (stamp.0[0].device, stamp.0[0].inode));
	// This only bounds disposable validation-cache memory. Durable keys, active
	// futures, and newly eligible requests are never counted against this budget.
	if cache.len() >= 16 {
		cache.pop_front();
	}
	cache.push_back(stamp);
	Ok(())
}
#[cfg(unix)]
fn validate_namespace(directory: &File) -> Result<()> {
	let before = namespace_stamp(directory)?;
	if NAMESPACE_CACHE
		.get_or_init(|| Mutex::new(VecDeque::new()))
		.lock()
		.map_err(|_| anyhow!("async namespace cache unavailable"))?
		.iter()
		.any(|stamp| *stamp == before)
	{
		return Ok(());
	}
	// Only a cold/external namespace change needs a complete inventory. Validate
	// both directions by exact filenames, without collecting lifetime history.
	let intents = open_at(directory, ".intents", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	let occupied = open_at(
		directory,
		".occupied",
		libc::O_RDONLY | libc::O_DIRECTORY,
		0,
	)?;
	let outcomes = open_at(
		directory,
		".outcomes",
		libc::O_RDONLY | libc::O_DIRECTORY,
		0,
	)?;
	for_each_name(directory, true, |name| {
		binding_pair(directory, &name[..name.len() - 5])?
			.ok_or_else(|| anyhow!("async key history incomplete; never replay"))?;
		Ok(())
	})?;
	for_each_name(&occupied, false, |name| {
		binding_pair(directory, &name[..name.len() - 5])?
			.ok_or_else(|| anyhow!("async occupancy history incomplete; never replay"))?;
		Ok(())
	})?;
	for_each_name(&intents, false, |name| {
		let binding: Binding = read_json(&intents, name)?;
		if !valid_binding(&binding)
			|| name != format!("{}.json", binding.request_id)
			|| binding_pair(directory, &binding.key_hash)?.as_ref() != Some(&binding)
		{
			bail!("async intent history incomplete; never replay");
		}
		Ok(())
	})?;
	for_each_name(&outcomes, false, |name| {
		let outcome: Outcome = read_json(&outcomes, name)?;
		if !valid_id(&outcome.request_id) || name != format!("{}.json", outcome.request_id) {
			bail!("async outcome history identity unavailable");
		}
		let binding: Binding = read_json(&intents, &format!("{}.json", outcome.request_id))?;
		if !valid_binding(&binding)
			|| binding.request_id != outcome.request_id
			|| binding_pair(directory, &binding.key_hash)?.as_ref() != Some(&binding)
		{
			bail!("async outcome has no complete historical binding; never replay");
		}
		check_outcome(&binding, &outcome)
	})?;
	if namespace_stamp(directory)? != before {
		bail!("async namespace changed during validation; never replay");
	}
	cache_namespace(directory)
}

#[cfg(unix)]
fn binding_pair(dir: &File, hash: &str) -> Result<Option<Binding>> {
	let occupancy = open_at(dir, ".occupied", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_dir(&occupancy)?;
	let name = format!("{hash}.json");
	let primary = read_json::<Binding>(dir, &name);
	let occupied = read_json::<Binding>(&occupancy, &name);
	match (primary, occupied) {
		(Ok(primary), Ok(occupied))
			if primary == occupied && valid_binding(&primary) && primary.key_hash == hash =>
		{
			let identity: String = read_json(dir, ".identity.json")?;
			if primary.ledger_identity != identity {
				bail!("operation key belongs to another ledger");
			}
			let intents = open_at(dir, ".intents", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
			private_dir(&intents)?;
			let intent: Binding = read_json(&intents, &format!("{}.json", primary.request_id))
				.map_err(|_| anyhow!("async historical intent unavailable; never replay"))?;
			if intent != primary {
				bail!("async historical intent identity changed");
			}
			Ok(Some(primary))
		}
		(Err(primary), Err(occupied)) if missing(&primary) && missing(&occupied) => Ok(None),
		_ => bail!(
			"async key binding or occupancy unavailable; never replay or repair automatically"
		),
	}
}
fn check_binding(b: &Binding, owner: &str, hash: &str, request: &str, policy: &str) -> Result<()> {
	if b.owner != owner
		|| b.key_hash != hash
		|| b.request_hash != request
		|| b.policy_binding != policy
	{
		bail!("async key unavailable to this scope, arguments or current policy");
	}
	Ok(())
}
#[cfg(unix)]
fn lookup_key_at(
	root: &Path,
	owner: &str,
	hash: &str,
	request: &str,
	policy: &str,
) -> Result<Option<Binding>> {
	let _lock = STORE_LOCK
		.get_or_init(|| Mutex::new(()))
		.lock()
		.map_err(|_| anyhow!("async metadata unavailable"))?;
	let (dir, _lease) = locked_store(root)?;
	validate_namespace(&dir)?;
	let Some(b) = binding_pair(&dir, hash)? else {
		// Absence of both key markers is not a fresh permit while any independent
		// historical intent/outcome remains inconsistent with this namespace.
		return Ok(None);
	};
	if !valid_binding(&b) {
		bail!("async key unavailable");
	}
	check_binding(&b, owner, hash, request, policy)?;
	Ok(Some(b))
}
#[cfg(unix)]
fn lookup_id_at(root: &Path, owner: &str, id: &str, policy: &str) -> Result<Option<Binding>> {
	if !valid_id(owner) || !valid_id(id) || !valid_id(policy) {
		bail!("async request unavailable to this scope");
	}
	let _lock = STORE_LOCK
		.get_or_init(|| Mutex::new(()))
		.lock()
		.map_err(|_| anyhow!("async metadata unavailable"))?;
	// A legacy V8 lookup never creates an async namespace or adds a new
	// state-root permission requirement when no async journal exists.
	let base = root_handle(root)?;
	match read_json::<Anchor>(&base, ANCHOR_NAME) {
		Ok(_) => {}
		Err(error) if missing(&error) => {
			match open_at(&base, STORE_NAME, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
				Err(error) if missing(&error) => return Ok(None),
				_ => bail!("unanchored async journal unavailable"),
			}
		}
		Err(_) => bail!("async journal unavailable"),
	}
	let (dir, _lease) = locked_store(root)?;
	validate_namespace(&dir)?;
	let intents = open_at(&dir, ".intents", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	let binding: Binding = match read_json(&intents, &format!("{id}.json")) {
		Ok(binding) => binding,
		Err(error) if missing(&error) => return Ok(None),
		Err(_) => bail!("async intent unavailable to this scope"),
	};
	if !valid_binding(&binding)
		|| binding.request_id != id
		|| binding.owner != owner
		|| binding.policy_binding != policy
		|| binding_pair(&dir, &binding.key_hash)?.as_ref() != Some(&binding)
	{
		bail!("async request unavailable to this scope or current policy");
	}
	Ok(Some(binding))
}
#[cfg(unix)]
fn reserve_at(root: &Path, candidate: Binding) -> Result<Reservation> {
	if !valid_binding(&candidate) {
		bail!("async admission unavailable");
	}
	let _lock = STORE_LOCK
		.get_or_init(|| Mutex::new(()))
		.lock()
		.map_err(|_| anyhow!("async metadata unavailable"))?;
	let (dir, _lease) = locked_store(root)?;
	validate_namespace(&dir)?;
	let name = format!("{}.json", candidate.key_hash);
	let base = root_at(root)?;
	let anchor: Anchor = read_json(&base, ANCHOR_NAME)?;
	if candidate.ledger_identity != anchor.namespace_id {
		bail!("operation ledger binding changed");
	}

	if let Some(old) = binding_pair(&dir, &candidate.key_hash)? {
		if old.tool_name != candidate.tool_name {
			bail!("async key unavailable to this operation");
		}
		if !valid_binding(&old) {
			bail!("async key unavailable");
		}
		check_binding(
			&old,
			&candidate.owner,
			&candidate.key_hash,
			&candidate.request_hash,
			&candidate.policy_binding,
		)?;
		return Ok(Reservation::Existing(old));
	}
	let historical = open_at(&dir, ".intents", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	match read_json::<Binding>(&historical, &format!("{}.json", candidate.request_id)) {
		Ok(_) => bail!("generated request identity already bound"),
		Err(error) if missing(&error) => {}
		Err(_) => bail!("generated request identity unavailable"),
	}
	let occupancy = open_at(&dir, ".occupied", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_dir(&occupancy)?;
	// Burn the identity-indexed historical intent before either key marker.
	// Every incomplete graph refuses: no reconstruction or reissued permit.
	let intents = open_at(&dir, ".intents", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_dir(&intents)?;
	publish(
		&intents,
		&format!("{}.json", candidate.request_id),
		&candidate,
	)?;
	publish(&occupancy, &name, &candidate)?;
	publish(&dir, &name, &candidate)?;
	cache_namespace(&dir)?;
	Ok(Reservation::New(candidate))
}
#[cfg(unix)]
fn acquire_controller(root: &Path) -> Result<()> {
	use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
	let dir = store(root)?;
	let lock = anchored_lock(root, &dir, ".controller.lock")?;
	let mut r = registry()?;
	if let Some((old, held)) = &r.lease {
		private_file(held)?;
		let saved = held.metadata()?;
		let current = lock.metadata()?;
		if old != root
			|| saved.dev() != current.dev()
			|| saved.ino() != current.ino()
			|| saved.len() != 0
		{
			bail!("async controller binding changed");
		}
		return Ok(());
	}
	if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
		bail!("another controller owns async execution; existing receipts remain readable");
	}
	r.lease = Some((root.into(), lock));
	Ok(())
}
#[cfg(unix)]
fn outcome_at(root: &Path, b: &Binding, state: Option<&str>) -> Result<Option<String>> {
	let _lock = STORE_LOCK
		.get_or_init(|| Mutex::new(()))
		.lock()
		.map_err(|_| anyhow!("async metadata unavailable"))?;
	let (dir, _lease) = locked_store(root)?;
	validate_namespace(&dir)?;
	let saved =
		binding_pair(&dir, &b.key_hash)?.ok_or_else(|| anyhow!("async occupancy missing"))?;
	if saved != *b {
		bail!("async outcome binding changed");
	}
	let outcomes = open_at(&dir, ".outcomes", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_dir(&outcomes)?;
	let name = format!("{}.json", b.request_id);
	// A duplicate metadata settlement can only observe the original immutable
	// outcome. Never rewrite it, grant execution, or interpret corruption absent.
	match read_json::<Outcome>(&outcomes, &name) {
		Ok(original) => {
			check_outcome(b, &original)?;
			return Ok(Some(original.state));
		}
		Err(error) if missing(&error) => {}
		Err(_) => bail!("operation outcome unavailable"),
	}
	if let Some(state) = state {
		if !matches!(
			state,
			"completed" | "failed" | "cancelled_before_dispatch" | "cancelled_future" | "unknown"
		) {
			bail!("async outcome unavailable");
		}
		publish(
			&outcomes,
			&name,
			&Outcome {
				request_id: b.request_id.clone(),
				owner: b.owner.clone(),
				key_hash: b.key_hash.clone(),
				policy_binding: b.policy_binding.clone(),
				tool_name: b.tool_name.clone(),
				accepted_unix_ms: b.accepted_unix_ms,
				request_hash: b.request_hash.clone(),
				ledger_identity: b.ledger_identity.clone(),
				state: state.into(),
			},
		)?;
		cache_namespace(&dir)?;
	}
	let o: Outcome = match read_json(&outcomes, &name) {
		Ok(o) => o,
		Err(error) if missing(&error) => return Ok(None),
		Err(_) => bail!("async outcome unavailable"),
	};
	check_outcome(b, &o)?;
	Ok(Some(o.state))
}
#[cfg(not(unix))]
fn lookup_key_at(
	_root: &Path,
	_owner: &str,
	_hash: &str,
	_request: &str,
	_policy: &str,
) -> Result<Option<Binding>> {
	bail!("async private state requires Unix");
}
#[cfg(not(unix))]
fn lookup_id_at(_root: &Path, _owner: &str, _id: &str, _policy: &str) -> Result<Option<Binding>> {
	bail!("async private state requires Unix");
}
#[cfg(not(unix))]
fn reserve_at(_root: &Path, _candidate: Binding) -> Result<Reservation> {
	bail!("async private state requires Unix");
}
#[cfg(not(unix))]
fn acquire_controller(_root: &Path) -> Result<()> {
	bail!("async private state requires Unix");
}
#[cfg(not(unix))]
fn outcome_at(_root: &Path, _b: &Binding, _state: Option<&str>) -> Result<Option<String>> {
	bail!("async private state requires Unix");
}

#[cfg(unix)]
fn ledger_identity_at(root: &Path) -> Result<String> {
	let _lock = STORE_LOCK
		.get_or_init(|| Mutex::new(()))
		.lock()
		.map_err(|_| anyhow!("operation metadata unavailable"))?;
	let _dir = store(root)?;
	let anchor: Anchor = read_json(&root_at(root)?, ANCHOR_NAME)?;
	if !valid_id(&anchor.namespace_id) {
		bail!("operation ledger identity unavailable");
	}
	Ok(anchor.namespace_id)
}
#[cfg(not(unix))]
fn ledger_identity_at(_root: &Path) -> Result<String> {
	bail!("operation ledger requires Unix");
}
fn crypto_binding(b: &Binding, kind: NativePayloadKind) -> Result<TrustedResultBinding> {
	Ok(TrustedResultBinding::new(
		&b.request_id,
		&b.owner,
		&b.tool_name,
		b.accepted_unix_ms,
		&b.policy_binding,
		&b.request_hash,
		&b.ledger_identity,
		kind,
	)?)
}
struct BoundedWriter {
	bytes: zeroize::Zeroizing<Vec<u8>>,
}
impl Write for BoundedWriter {
	fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
		if self.bytes.len().saturating_add(data.len()) > MAX_PAYLOAD_BYTES {
			return Err(std::io::Error::other(
				"native payload exceeds encrypted retention bound",
			));
		}
		self.bytes.extend_from_slice(data);
		Ok(data.len())
	}
	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}
fn original_payload(
	result: &Result<CallToolResponse, rmcp::ErrorData>,
) -> Result<(NativePayloadKind, zeroize::Zeroizing<Vec<u8>>)> {
	let mut writer = BoundedWriter {
		bytes: zeroize::Zeroizing::new(Vec::new()),
	};
	let kind = match result {
		Ok(CallToolResponse::Complete(value)) => {
			serde_json::to_writer(&mut writer, value)?;
			NativePayloadKind::NativeResult
		}
		Err(error) => {
			serde_json::to_writer(&mut writer, error)?;
			NativePayloadKind::NativeError
		}
		_ => bail!("native payload kind unavailable"),
	};
	Ok((kind, writer.bytes))
}
#[cfg(unix)]
fn validate_packet(file: &File) -> Result<()> {
	use std::os::unix::fs::MetadataExt;
	let m = file.metadata()?;
	if !m.is_file()
		|| m.uid() != unsafe { libc::geteuid() }
		|| m.mode() & 0o7777 != 0o600
		|| m.nlink() != 1
		|| m.len() > MAX_PACKET_BYTES as u64
	{
		bail!("private encrypted packet unavailable");
	}
	Ok(())
}
#[cfg(unix)]
fn save_payload_at(root: &Path, b: &Binding, packet: &[u8]) -> Result<()> {
	use std::os::fd::AsRawFd;
	if packet.len() > MAX_PACKET_BYTES {
		bail!("encrypted packet bound exceeded");
	}
	let _lock = STORE_LOCK
		.get_or_init(|| Mutex::new(()))
		.lock()
		.map_err(|_| anyhow!("operation metadata unavailable"))?;
	let (dir, _lease) = locked_store(root)?;
	validate_namespace(&dir)?;
	let saved = binding_pair(&dir, &b.key_hash)?
		.ok_or_else(|| anyhow!("operation occupancy unavailable"))?;
	if saved != *b {
		bail!("operation payload binding changed");
	}
	let payloads = open_at(&dir, ".payloads", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_dir(&payloads)?;
	let temporary = format!(".publish-{}", next_id()?);
	let mut file = open_at(
		&payloads,
		&temporary,
		libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
		0o600,
	)?;
	let result = (|| {
		file.write_all(packet)?;
		file.sync_all()?;
		let from = std::ffi::CString::new(temporary.as_str())?;
		// Build the publication filename from the validated trusted result identity,
		// never a caller-selected path or a raw unchecked journal component.
		let validated = crypto_binding(b, NativePayloadKind::NativeResult)?;
		let to = std::ffi::CString::new(format!("{}.bin", validated.operation_id()))?;
		if unsafe {
			libc::linkat(
				payloads.as_raw_fd(),
				from.as_ptr(),
				payloads.as_raw_fd(),
				to.as_ptr(),
				0,
			)
		} < 0
		{
			return Err(std::io::Error::last_os_error().into());
		}
		if unsafe { libc::unlinkat(payloads.as_raw_fd(), from.as_ptr(), 0) } < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		payloads.sync_all()?;
		Ok(())
	})();
	if result.is_err() {
		if let Ok(name) = std::ffi::CString::new(temporary) {
			unsafe {
				libc::unlinkat(payloads.as_raw_fd(), name.as_ptr(), 0);
			}
		}
	}
	result
}
#[cfg(not(unix))]
fn save_payload_at(_root: &Path, _b: &Binding, _packet: &[u8]) -> Result<()> {
	bail!("operation ledger requires Unix");
}
#[cfg(unix)]
fn read_payload_at(root: &Path, b: &Binding) -> Result<Option<Vec<u8>>> {
	use std::os::unix::fs::MetadataExt;
	let _lock = STORE_LOCK
		.get_or_init(|| Mutex::new(()))
		.lock()
		.map_err(|_| anyhow!("operation metadata unavailable"))?;
	let (dir, _lease) = locked_store(root)?;
	validate_namespace(&dir)?;
	let saved = binding_pair(&dir, &b.key_hash)?
		.ok_or_else(|| anyhow!("operation occupancy unavailable"))?;
	if saved != *b {
		bail!("operation payload binding changed");
	}
	let payloads = open_at(&dir, ".payloads", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_dir(&payloads)?;
	let mut file = match open_at(
		&payloads,
		&format!("{}.bin", b.request_id),
		libc::O_RDONLY | libc::O_NONBLOCK,
		0,
	) {
		Ok(file) => file,
		Err(error) if missing(&error) => return Ok(None),
		Err(_) => bail!("encrypted packet unavailable"),
	};
	validate_packet(&file)?;
	let before = file.metadata()?;
	let mut bytes = Vec::new();
	Read::by_ref(&mut file)
		.take((MAX_PACKET_BYTES + 1) as u64)
		.read_to_end(&mut bytes)?;
	let after = file.metadata()?;
	if bytes.len() > MAX_PACKET_BYTES
		|| before.dev() != after.dev()
		|| before.ino() != after.ino()
		|| before.len() != after.len()
		|| before.mtime() != after.mtime()
		|| before.mtime_nsec() != after.mtime_nsec()
		|| before.ctime() != after.ctime()
		|| before.ctime_nsec() != after.ctime_nsec()
	{
		bail!("encrypted packet changed while reading");
	}
	validate_packet(&file)?;
	Ok(Some(bytes))
}
#[cfg(not(unix))]
fn read_payload_at(_root: &Path, _b: &Binding) -> Result<Option<Vec<u8>>> {
	bail!("operation ledger requires Unix");
}
fn base64(data: &[u8]) -> String {
	const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
	for r in data.chunks(3) {
		let n = ((r[0] as u32) << 16)
			| ((r.get(1).copied().unwrap_or(0) as u32) << 8)
			| (r.get(2).copied().unwrap_or(0) as u32);
		out.push(A[((n >> 18) & 63) as usize] as char);
		out.push(A[((n >> 12) & 63) as usize] as char);
		out.push(if r.len() > 1 {
			A[((n >> 6) & 63) as usize] as char
		} else {
			'='
		});
		out.push(if r.len() > 2 {
			A[(n & 63) as usize] as char
		} else {
			'='
		});
	}
	out
}
fn page(value: Value) -> Result<String> {
	let text = serde_json::to_string(&value)?;
	let wire = CallToolResult::success(vec![rmcp::model::ContentBlock::text(&text)]);
	if serde_json::to_vec(&wire)?.len() > 64 * 1024 {
		bail!("operation wire budget exceeded");
	}
	Ok(text)
}
fn phase(b: &Binding) -> Result<&'static str> {
	let r = registry()?;
	match r.active.get(&b.request_id) {
		Some(a) if a.binding == *b => Ok(match a.phase.load(Ordering::Acquire) {
			QUEUED => "queued",
			RUNNING => "running",
			_ => "settling",
		}),
		Some(_) => bail!("async live identity changed"),
		None => Ok("unknown"),
	}
}
fn admission_receipt(b: &Binding, reused: bool) -> Result<String> {
	Ok(serde_json::to_string(
		&json!({"operation_id":b.request_id,"tool_name":b.tool_name,"reused":reused,
        "async_state":phase(b)?,"idempotency_binding_retained":true,"automatic_retry":false,
        "delivery_proven":false,"execution_resume_after_restart":false,
        "admission_is_not_dispatch_completion":true,"authenticated_chatgpt_caller_isolation":false}),
	)?)
}

fn private_policy_binding_for<T: Serialize>(
	crypto: &ResultCryptoScope,
	config: &T,
) -> Result<String> {
	let mut canonical = BoundedWriter {
		bytes: zeroize::Zeroizing::new(Vec::new()),
	};
	serde_json::to_writer(&mut canonical, config)
		.map_err(|_| anyhow!("operation policy exceeds admission budget"))?;
	Ok(crypto.policy_binding(&canonical.bytes)?)
}
fn private_policy_binding(crypto: &ResultCryptoScope) -> Result<String> {
	private_policy_binding_for(crypto, runtime_config()?)
}
async fn await_read_completion<F, T, E>(
	operation: F,
	cancel: &CancellationToken,
) -> (Option<T>, &'static str)
where
	F: std::future::Future<Output = std::result::Result<T, E>>,
{
	tokio::pin!(operation);
	tokio::select! {
		biased;
		value = &mut operation => match value {
			Ok(value) => (Some(value), "completed"),
			Err(_) => (None, "unknown"),
		},
		_ = cancel.cancelled() => (None, "cancelled_future"),
	}
}
pub(crate) async fn start(
	owner: &str,
	crypto: Arc<ResultCryptoScope>,
	p: OperationStartParams,
) -> Result<String> {
	if !valid_id(owner) || !valid_key(&p.idempotency_key) {
		bail!("operation parameters unavailable");
	}
	p.operation.validate()?;
	let policy = private_policy_binding(&crypto)?;
	// Raw key and potentially secret args never appear in disk metadata or history.
	let hash = crypto.idempotency_binding(p.idempotency_key.as_bytes())?;
	let mut canonical = BoundedWriter {
		bytes: zeroize::Zeroizing::new(Vec::new()),
	};
	serde_json::to_writer(&mut canonical, &p.operation)
		.map_err(|_| anyhow!("operation arguments exceed admission budget"))?;
	let request = crypto.request_binding(&canonical.bytes)?;
	let root = runtime_config()?.state_dir.clone();
	let (rr, ro, rh, rq, rp) = (
		root.clone(),
		owner.to_owned(),
		hash.clone(),
		request.clone(),
		policy.clone(),
	);
	if let Some(old) =
		tokio::task::spawn_blocking(move || lookup_key_at(&rr, &ro, &rh, &rq, &rp)).await??
	{
		return checked_receipt(&old, true).await;
	}
	let _admission = ADMISSION
		.get_or_init(|| tokio::sync::Mutex::new(()))
		.lock()
		.await;
	let (rr, ro, rh, rq, rp) = (
		root.clone(),
		owner.to_owned(),
		hash.clone(),
		request.clone(),
		policy.clone(),
	);
	if let Some(old) =
		tokio::task::spawn_blocking(move || lookup_key_at(&rr, &ro, &rh, &rq, &rp)).await??
	{
		return checked_receipt(&old, true).await;
	}
	if STOPPING.load(Ordering::Acquire) {
		bail!("operation controller is shutting down");
	}
	let slot = Slot::take(owner)?;
	let lease_root = root.clone();
	tokio::task::spawn_blocking(move || acquire_controller(&lease_root)).await??;
	let identity_root = root.clone();
	let ledger_identity =
		tokio::task::spawn_blocking(move || ledger_identity_at(&identity_root)).await??;
	let candidate = Binding {
		request_id: next_id()?,
		owner: owner.into(),
		tool_name: p.operation.tool().into(),
		accepted_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
		key_hash: hash,
		request_hash: request,
		policy_binding: policy,
		ledger_identity,
	};
	let write_root = root.clone();
	let binding =
		match tokio::task::spawn_blocking(move || reserve_at(&write_root, candidate)).await?? {
			Reservation::Existing(old) => return checked_receipt(&old, true).await,
			Reservation::New(new) => new,
		};
	let ticket = match request_audit::begin_operation_reserved(binding.identity()).await {
		Ok(ticket) => ticket,
		Err(_) => return checked_receipt(&binding, false).await,
	};
	let active = Arc::new(Active {
		binding: binding.clone(),
		cancel: CancellationToken::new(),
		phase: AtomicU8::new(QUEUED),
	});
	registry()?
		.active
		.insert(binding.request_id.clone(), active.clone());
	let guard = ActiveGuard {
		id: binding.request_id.clone(),
		_slot: slot,
	};
	let receipt = checked_receipt(&binding, false).await?;
	let owned = binding.clone();
	tokio::spawn(async move {
		let _guard = guard;
		tokio::task::yield_now().await;
		let (result, state) = if active.cancel.is_cancelled() {
			(None, "cancelled_before_dispatch")
		} else {
			active.phase.store(RUNNING, Ordering::Release);
			let operation = tokio::time::timeout(Duration::from_secs(40), p.operation.dispatch());
			// An already-completed native payload wins a simultaneous late cancel.
			// A still-pending read future remains cancellable; settlement never is.
			await_read_completion(operation, &active.cancel).await
		};
		active.phase.store(SETTLING, Ordering::Release);
		let completion = match &result {
			Some(Ok(CallToolResponse::Complete(value))) if !value.is_error.unwrap_or(false) => {
				AuditCompletion::Completed
			}
			Some(_) => AuditCompletion::Failed,
			None => AuditCompletion::Unknown,
		};
		// Settlement is not selectable/cancellable. Store the unmodified native payload;
		// neither old handlers nor their exact wire limits receive operation metadata.
		let retained = if let Some(ref result) = result {
			match original_payload(result) {
				Ok((kind, bytes)) => {
					match crypto_binding(&owned, kind)
						.and_then(|aad| Ok(crypto.seal(&aad, &bytes)?))
					{
						Ok(packet) => {
							let (write_root, write_binding) = (root.clone(), owned.clone());
							tokio::task::spawn_blocking(move || {
								save_payload_at(&write_root, &write_binding, &packet)
							})
							.await
							.is_ok_and(|v| v.is_ok())
						}
						Err(_) => false,
					}
				}
				Err(_) => false,
			}
		} else {
			true
		};
		let audited = request_audit::finish(ticket, completion).await.is_ok();
		let terminal = if !retained || !audited {
			"unknown"
		} else if matches!(completion, AuditCompletion::Failed) {
			"failed"
		} else {
			state
		};
		let _ =
			tokio::task::spawn_blocking(move || outcome_at(&root, &owned, Some(terminal))).await;
	});
	Ok(receipt)
}
fn check_audit_identity(b: &Binding, identity: &RequestIdentity) -> Result<()> {
	if identity.request_id != b.request_id
		|| identity.owner != b.owner
		|| identity.tool_name != b.tool_name
		|| identity.accepted_unix_ms != b.accepted_unix_ms
	{
		bail!("async request audit identity unavailable");
	}
	Ok(())
}
async fn audit_present(b: &Binding) -> Result<bool> {
	match request_audit::optional_observation(&b.owner, &b.request_id).await? {
		Some(observation) => {
			check_audit_identity(b, &observation.identity)?;
			Ok(true)
		}
		None => Ok(false),
	}
}
async fn checked_receipt(b: &Binding, reused: bool) -> Result<String> {
	audit_present(b).await?;
	admission_receipt(b, reused)
}
async fn observation(owner: &str, crypto: &ResultCryptoScope, id: &str) -> Result<Option<Value>> {
	let root = runtime_config()?.state_dir.clone();
	let binding = private_policy_binding(crypto)?;
	let (read_owner, read_id) = (owner.to_owned(), id.to_owned());
	let b =
		tokio::task::spawn_blocking(move || lookup_id_at(&root, &read_owner, &read_id, &binding))
			.await??;
	let Some(b) = b else {
		return Ok(None);
	};
	let audit_metadata_available = audit_present(&b).await?;
	let live = phase(&b)?;
	let root = runtime_config()?.state_dir.clone();
	let copy = b.clone();
	let durable = tokio::task::spawn_blocking(move || outcome_at(&root, &copy, None)).await??;
	let state = if live != "unknown" {
		live.to_owned()
	} else {
		durable.unwrap_or_else(|| "unknown".into())
	};
	Ok(Some(
		json!({"async_state":state,"audit_metadata_available":audit_metadata_available,
        "early_return_async_start_supported":true,
        "owned_future_active":live!="unknown","automatic_retry":false,"execution_resume_after_restart":false,
        "cancellation_does_not_prove_remote_effect_stopped":true,"remote_termination_confirmed":false}),
	))
}
pub(crate) async fn cancel(
	owner: &str,
	crypto: Arc<ResultCryptoScope>,
	p: OperationCancelParams,
) -> Result<String> {
	let root = runtime_config()?.state_dir.clone();
	let policy = private_policy_binding(&crypto)?;
	let (read_owner, id, binding) = (owner.to_owned(), p.operation_id.clone(), policy.clone());
	let b = tokio::task::spawn_blocking(move || lookup_id_at(&root, &read_owner, &id, &binding))
		.await??
		.ok_or_else(|| anyhow!("async request unavailable to this scope"))?;
	audit_present(&b).await?;
	let (requested, observed) = {
		let r = registry()?;
		match r.active.get(&b.request_id) {
			Some(a) if a.binding == b && a.phase.load(Ordering::Acquire) != SETTLING => {
				a.cancel.cancel();
				(true, "owned_future_cancellation_requested")
			}
			Some(a) if a.binding == b => (false, "settlement_is_not_cancellable"),
			Some(_) => bail!("async live identity changed"),
			None => (false, "no_owned_future_present_no_replay"),
		}
	};
	Ok(serde_json::to_string(
		&json!({"operation_id":b.request_id,"cancel_requested":requested,"observation":observed,
        "automatic_retry":false,"effect_may_continue":true,"remote_termination_confirmed":false,
        "cancellation_scope":"this_controller_owned_rust_future_only"}),
	)?)
}

async fn owned_binding(owner: &str, crypto: &ResultCryptoScope, id: &str) -> Result<Binding> {
	let root = runtime_config()?.state_dir.clone();
	let policy = private_policy_binding(crypto)?;
	let (owner, id) = (owner.to_owned(), id.to_owned());
	let binding =
		tokio::task::spawn_blocking(move || lookup_id_at(&root, &owner, &id, &policy)).await??;
	binding.ok_or_else(|| anyhow!("operation unavailable to this scope or current policy"))
}
pub(crate) async fn status(
	owner: &str,
	crypto: Arc<ResultCryptoScope>,
	p: OperationStatusParams,
) -> Result<String> {
	let b = owned_binding(owner, &crypto, &p.operation_id).await?;
	let observed = observation(owner, &crypto, &p.operation_id)
		.await?
		.ok_or_else(|| anyhow!("operation unavailable"))?;
	let (root, copy) = (runtime_config()?.state_dir.clone(), b.clone());
	let payload = tokio::task::spawn_blocking(move || read_payload_at(&root, &copy)).await??;
	if let Some(ref packet) = payload {
		if crypto
			.open(
				&crypto_binding(&b, NativePayloadKind::NativeResult)?,
				packet,
			)
			.is_err()
		{
			crypto
				.open(&crypto_binding(&b, NativePayloadKind::NativeError)?, packet)
				.map_err(|_| anyhow!("operation original result unavailable"))?;
		}
	}
	let mut object = observed
		.as_object()
		.cloned()
		.ok_or_else(|| anyhow!("operation status unavailable"))?;
	object.insert("operation_id".into(), b.request_id.into());
	object.insert("delivery_proven".into(), false.into());
	object.insert("tool_name".into(), b.tool_name.into());
	object.insert("payload_available".into(), payload.is_some().into());
	object.insert(
		"result_state".into(),
		if payload.is_some() {
			"stored_observed"
		} else {
			"unavailable"
		}
		.into(),
	);
	object.insert(
		"retention_max_original_bytes".into(),
		json!(MAX_PAYLOAD_BYTES),
	);
	object.insert(
		"original_payload_is_not_transport_delivery_proof".into(),
		true.into(),
	);
	page(Value::Object(object))
}
pub(crate) async fn result(
	owner: &str,
	crypto: Arc<ResultCryptoScope>,
	p: OperationResultParams,
) -> Result<String> {
	let limit = p.limit.unwrap_or(16384) as usize;
	if !(1..=16384).contains(&limit) {
		bail!("operation result limit must be 1..16384");
	}
	let b = owned_binding(owner, &crypto, &p.operation_id).await?;
	audit_present(&b).await?;
	let (root, copy) = (runtime_config()?.state_dir.clone(), b.clone());
	let packet = tokio::task::spawn_blocking(move || read_payload_at(&root, &copy))
		.await??
		.ok_or_else(|| {
			anyhow!("operation original result unavailable; never replay automatically")
		})?;
	// The payload kind is authenticated in AAD. A failed first kind attempt emits
	// no plaintext; only one exact authenticated kind can be accepted.
	let (opened, kind) = match crypto.open(
		&crypto_binding(&b, NativePayloadKind::NativeResult)?,
		&packet,
	) {
		Ok(value) => (value, "native_result"),
		Err(_) => (
			crypto
				.open(
					&crypto_binding(&b, NativePayloadKind::NativeError)?,
					&packet,
				)
				.map_err(|_| anyhow!("operation original result unavailable"))?,
			"native_error",
		),
	};
	let bytes = opened.as_bytes();
	let offset = p.offset.unwrap_or(0) as usize;
	if offset > bytes.len() {
		bail!("operation result offset exceeds retained length");
	}
	let end = offset.saturating_add(limit).min(bytes.len());
	page(
		json!({"operation_id":b.request_id,"offset":offset,"next_offset":end,"total_bytes":bytes.len(),
        "eof":end==bytes.len(),"data_base64":base64(&bytes[offset..end]),"result_sha256":digest(bytes),
        "payload_kind":kind,"format":"serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization",
        "immutable_snapshot":true,"automatic_retry":false,"delivery_proven":false}),
	)
}
pub(crate) fn freeze_admission() {
	STOPPING.store(true, Ordering::Release);
}
pub(crate) async fn shutdown() {
	freeze_admission();
	let _admission = ADMISSION
		.get_or_init(|| tokio::sync::Mutex::new(()))
		.lock()
		.await;
	if let Ok(r) = registry() {
		for a in r.active.values() {
			a.cancel.cancel();
		}
	}
	for _ in 0..100 {
		if registry().is_ok_and(|r| r.active.is_empty()) {
			return;
		}
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}
#[cfg(all(test, unix))]
#[path = "operation_async_tests.rs"]
mod tests;
