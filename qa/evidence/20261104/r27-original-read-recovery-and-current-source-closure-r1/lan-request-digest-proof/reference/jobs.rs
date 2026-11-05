// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Durable host-bound job identities, recovery and log pagination.
use anyhow::{bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock, TryLockError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};

use super::config::{check_environment, check_execution, runtime_config, valid_name};
use super::config::{ExecutionMode, Platform};
use super::ssh::{run_jobctl, run_python_json};
use super::ssh::{run_jobctl_with_entry, run_python_json_with_entry};

static JOB_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const START_LANE_COUNT: usize = 64;
type StartLanes = [Arc<AsyncMutex<()>>; START_LANE_COUNT];
static START_LOCKS: OnceLock<Mutex<HashMap<String, StartLanes>>> = OnceLock::new();
type OwnedStartGuard = Arc<OwnedMutexGuard<()>>;
const MAX_START_IO_WORKERS: usize = 4;
static START_IO_WORKERS: OnceLock<Arc<Semaphore>> = OnceLock::new();
// Reserve before remote submission so a received ACK always owns bounded
// publication capacity, including when its original request is cancelled.
const MAX_START_OUTCOME_PUBLICATIONS: usize = 8;
static START_OUTCOME_PUBLICATIONS: OnceLock<Arc<Semaphore>> = OnceLock::new();
const MAX_CANCEL_PUBLICATIONS: usize = 8;
static CANCEL_PUBLICATIONS: OnceLock<Arc<Semaphore>> = OnceLock::new();
static AUDIT_LOCK: OnceLock<Mutex<Option<AuditReadiness>>> = OnceLock::new();
const MAX_OBSERVATION_AUDITS: usize = 8;
static OBSERVATION_AUDITS: OnceLock<Arc<Semaphore>> = OnceLock::new();
static REUSE_HITS: OnceLock<Mutex<ReuseHitCache>> = OnceLock::new();
const MAX_REGISTRY_LOOKUPS: usize = 4;
static REGISTRY_LOOKUPS: OnceLock<Arc<Semaphore>> = OnceLock::new();
const MAX_COLD_DEMAND_BYTES: usize = 1024;
const MAX_COLD_HINT_BYTES: usize = 16 * 1024;
const MAX_COLD_COHORT_IDENTITIES: usize = 8;
const MAX_RECENT_COLD_KEY_BYTES: usize = 2 * 1024;
const MAX_COLD_TARGET_KEY_BYTES: usize = 3 * MAX_COLD_DEMAND_BYTES;
// Coordinate only this owner process's local metadata reads/publications.
// Guards remain inside synchronous functions, never across remote awaits.
static REGISTRY_ACCESS: RwLock<()> = RwLock::new(());
const MAX_REUSE_HITS: usize = 4096;
const MAX_IDEMPOTENCY_SCAN_ATTEMPTS: usize = 3;
const MAX_CACHED_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_JOB_RECORD_BYTES: u64 = 4 * 1024 * 1024;
const MAX_STDIN_BYTES: usize = 1024 * 1024;
const MAX_LOG_READ_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessStartParams {
	/// Configured host name, never a raw SSH destination.
	pub host: String,
	/// Executable path or command name. Shell syntax is not accepted.
	pub executable: String,
	#[serde(default)]
	pub args: Vec<String>,
	#[serde(default)]
	pub cwd: Option<String>,
	#[serde(default)]
	pub env: BTreeMap<String, String>,
	/// Optional standard input written once at process start (max 1 MiB).
	#[serde(default)]
	pub stdin: Option<String>,
	/// Optional process timeout. The remote supervisor terminates the process group.
	#[serde(default)]
	pub timeout_seconds: Option<u64>,
	/// Mandatory stable operation key; exact retries reconcile the original durable job.
	#[schemars(required)]
	pub idempotency_key: Option<String>,
	/// Non-negative Unix nice adjustment, 0..19.
	#[serde(default)]
	pub nice: Option<u8>,
	/// Optional transient systemd CPUQuota percentage, 1..1000.
	#[serde(default)]
	pub cpu_quota_percent: Option<u16>,
	/// Optional transient systemd MemoryMax in bytes.
	#[serde(default)]
	pub memory_max_bytes: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessRefParams {
	pub host: String,
	pub job_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessReadParams {
	pub host: String,
	pub job_id: String,
	#[serde(default)]
	pub stdout_offset: Option<u64>,
	#[serde(default)]
	pub stderr_offset: Option<u64>,
	/// Maximum bytes returned per stream, capped at 16 KiB with lossless byte cursors.
	#[serde(default)]
	pub limit: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessWaitParams {
	pub host: String,
	pub job_id: String,
	/// Maximum wait for this call, capped at 30 seconds.
	#[serde(default)]
	pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessCancelParams {
	pub host: String,
	pub job_id: String,
	/// Grace period before the fallback backend sends SIGKILL, capped at 30 seconds.
	#[serde(default)]
	pub grace_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessListParams {
	#[serde(default)]
	pub host: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessListPageParams {
	#[serde(default)]
	pub host: Option<String>,
	/// Opaque continuation from this exact registry snapshot. Changes require a fresh first page.
	#[serde(default)]
	pub cursor: Option<String>,
	/// At most 128 identities per page, additionally bounded to a 64 KiB wire response.
	#[serde(default)]
	pub limit: Option<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
struct JobRecord {
	#[serde(default)]
	execution_mode: ExecutionMode,
	#[serde(default)]
	system_jobctl: bool,
	id: String,
	host: String,
	ssh_target: String,
	unit: String,
	remote_job_dir: String,
	executable: String,
	args: Vec<String>,
	cwd: Option<String>,
	env_keys: Vec<String>,
	created_unix_ms: u128,
	idempotency_key: Option<String>,
	request_fingerprint: u64,
	#[serde(default)]
	request_digest: Option<String>,
	#[serde(default = "default_launch_state")]
	launch_state: String,
	#[serde(default)]
	launch_error: Option<String>,
}

fn default_launch_state() -> String {
	"launched".to_string()
}

fn start_lane(key: Option<&str>) -> usize {
	// Hash only the original key. A changed payload with the same key must
	// still wait for the original lookup, durable intent and remote outcome.
	key.map_or(0, |key| {
		usize::from(Sha256::digest(key.as_bytes())[0]) % START_LANE_COUNT
	})
}

fn start_lock_in(
	registry: &Mutex<HashMap<String, StartLanes>>,
	host: &str,
	key: Option<&str>,
) -> Result<Arc<AsyncMutex<()>>> {
	// Only configured hosts reach this map in production. Fixed lanes bound
	// retained locks regardless of caller key cardinality. Collisions merely
	// serialize independent starts, and missing keys keep their original lane.
	let mut locks = registry
		.lock()
		.map_err(|_| anyhow::anyhow!("job launch lock registry unavailable"))?;
	Ok(locks
		.entry(host.to_owned())
		.or_insert_with(|| std::array::from_fn(|_| Arc::new(AsyncMutex::new(()))))[start_lane(key)]
	.clone())
}

fn start_lock(host: &str, key: Option<&str>) -> Result<Arc<AsyncMutex<()>>> {
	start_lock_in(
		START_LOCKS.get_or_init(|| Mutex::new(HashMap::new())),
		host,
		key,
	)
}

fn now_ms() -> u128 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_millis()
}

fn next_job_id() -> String {
	let seq = JOB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
	format!("{:x}-{:x}-{:x}", now_ms(), std::process::id(), seq)
}

fn jobs_dir() -> Result<PathBuf> {
	let path = runtime_config()?.state_dir.join("jobs");
	std::fs::create_dir_all(&path)?;
	Ok(path)
}

fn record_path(id: &str) -> Result<PathBuf> {
	if !valid_name(id) {
		bail!("invalid job id `{id}`");
	}
	Ok(jobs_dir()?.join(format!("{id}.json")))
}

fn with_registry_read<T>(gate: &RwLock<()>, read: impl FnOnce() -> Result<T>) -> Result<T> {
	let _read = gate
		.read()
		.map_err(|_| anyhow::anyhow!("job registry read lock unavailable"))?;
	read()
}

fn save_record(record: &JobRecord) -> Result<()> {
	save_record_with_registry_gate(record, &REGISTRY_ACCESS, || record_path(&record.id))
}

fn save_record_with_registry_gate(
	record: &JobRecord,
	gate: &RwLock<()>,
	record_path: impl FnOnce() -> Result<PathBuf>,
) -> Result<()> {
	// Include path/directory creation and both fsyncs. Every local publication,
	// including a launch outcome replacing pending metadata, uses this writer.
	let _write = gate
		.write()
		.map_err(|_| anyhow::anyhow!("job registry write lock unavailable"))?;
	let path = record_path()?;
	save_record_at(&path, record)
}

fn save_record_at(path: &Path, record: &JobRecord) -> Result<()> {
	let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
	let bytes = serde_json::to_vec_pretty(record)?;
	// The durable identity must remain readable by the bounded recovery path.
	// Reject an oversized request before creating a receipt or remote effect.
	if bytes.len() as u64 > MAX_JOB_RECORD_BYTES {
		bail!("durable job record exceeds {} bytes", MAX_JOB_RECORD_BYTES);
	}
	#[cfg(unix)]
	let mut file = {
		use std::os::unix::fs::OpenOptionsExt;
		OpenOptions::new()
			.create_new(true)
			.write(true)
			.mode(0o600)
			.open(&tmp)?
	};
	#[cfg(not(unix))]
	let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
	file.write_all(&bytes)?;
	// The identity must be durable before an external process can be launched.
	file.sync_all()?;
	drop(file);
	std::fs::rename(&tmp, path)?;
	#[cfg(unix)]
	if let Some(parent) = path.parent() {
		File::open(parent)?.sync_all()?;
	}
	Ok(())
}

fn read_record_at(path: &Path, expected_id: &str) -> Result<JobRecord> {
	read_record_at_with_buffer(path, expected_id, &mut Vec::new())
}

fn read_record_at_with_buffer(
	path: &Path,
	expected_id: &str,
	bytes: &mut Vec<u8>,
) -> Result<JobRecord> {
	// A scan owns this scratch buffer; returned records own their decoded data.
	// Clear even an early failure so later reads cannot observe earlier bytes.
	bytes.clear();
	let result = read_record_at_into(path, expected_id, bytes);
	bytes.clear();
	// A concurrent growth/read error can make read_to_end overallocate. Do not
	// retain that capacity across receipts, even though the scan will refuse it.
	if bytes.capacity() > (MAX_JOB_RECORD_BYTES + 1) as usize {
		*bytes = Vec::new();
	}
	result
}

fn read_record_at_into(path: &Path, expected_id: &str, bytes: &mut Vec<u8>) -> Result<JobRecord> {
	// A symlink or a mismatched identity is not a usable effect-owner receipt.
	let metadata = std::fs::symlink_metadata(path)
		.with_context(|| format!("cannot stat durable job record {}", path.display()))?;
	if !metadata.file_type().is_file() {
		bail!("unsafe durable job record type: {}", path.display());
	}
	let mut options = OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
	}
	// Recheck the opened file, not only the pathname inspected above:
	// a concurrent symlink swap must never redirect a credentialed read.
	let file = options
		.open(path)
		.with_context(|| format!("cannot open durable job record {}", path.display()))?;
	let opened = file.metadata()?;
	if !opened.is_file() || opened.len() > MAX_JOB_RECORD_BYTES {
		bail!(
			"invalid or oversized durable job record: {}",
			path.display()
		);
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		if opened.nlink() != 1
			|| opened.uid() != unsafe { libc::geteuid() }
			|| metadata.dev() != opened.dev()
			|| metadata.ino() != opened.ino()
		{
			bail!("unsafe durable job receipt ownership or inode");
		}
	}
	// The descriptor length is already bounded. One spare byte lets the same
	// buffer observe EOF without growing for every unchanged regular receipt.
	bytes
		.try_reserve_exact(opened.len() as usize + 1)
		.context("cannot allocate bounded durable job read buffer")?;
	let mut bounded = (&file).take(MAX_JOB_RECORD_BYTES + 1);
	bounded.read_to_end(bytes)?;
	if bytes.len() as u64 > MAX_JOB_RECORD_BYTES {
		bail!("oversized durable job record: {}", path.display());
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		let after = file.metadata()?;
		let current = std::fs::symlink_metadata(path)?;
		let stamp = |m: &std::fs::Metadata| {
			(
				m.dev(),
				m.ino(),
				m.mode(),
				m.uid(),
				m.nlink(),
				m.len(),
				m.mtime(),
				m.mtime_nsec(),
				m.ctime(),
				m.ctime_nsec(),
			)
		};
		if stamp(&opened) != stamp(&after) || stamp(&after) != stamp(&current) {
			bail!("durable job receipt changed during read");
		}
	}
	let record: JobRecord = serde_json::from_slice(bytes)
		.with_context(|| format!("corrupt job record; durable job receipt {}", path.display()))?;
	if record.id != expected_id {
		bail!("durable job filename/identity mismatch: {}", path.display());
	}
	Ok(record)
}

fn load_record(id: &str) -> Result<JobRecord> {
	read_record_at(&record_path(id)?, id)
		.with_context(|| format!("unknown or invalid durable job `{id}`"))
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegistryEpoch {
	device: u64,
	inode: u64,
	owner: u32,
	mode: u32,
	modified_seconds: i64,
	modified_nanos: i64,
	changed_seconds: i64,
	changed_nanos: i64,
	content: Option<super::namespace_version::Version>,
}
#[cfg(not(unix))]
type RegistryEpoch = ();

#[cfg(unix)]
fn registry_epoch(dir: &Path) -> Result<RegistryEpoch> {
	use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
	let directory = OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
		.open(dir)?;
	let m = directory.metadata()?;
	if !m.is_dir() {
		bail!("job registry directory identity is not a directory");
	}
	Ok(RegistryEpoch {
		device: m.dev(),
		inode: m.ino(),
		owner: m.uid(),
		mode: m.mode(),
		modified_seconds: m.mtime(),
		modified_nanos: m.mtime_nsec(),
		changed_seconds: m.ctime(),
		changed_nanos: m.ctime_nsec(),
		content: super::namespace_version::content_version(&directory)?,
	})
}
#[cfg(not(unix))]
fn registry_epoch(_dir: &Path) -> Result<RegistryEpoch> {
	bail!("positive reuse caching requires a Unix registry identity")
}

fn registry_has_content_watch(epoch: &RegistryEpoch) -> bool {
	#[cfg(target_os = "linux")]
	{
		matches!(
			epoch.content,
			Some(super::namespace_version::Version::Watch(_, _))
		)
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = epoch;
		false
	}
}

#[cfg(unix)]
fn same_registry_root(one: &RegistryEpoch, other: &RegistryEpoch) -> bool {
	one.device == other.device
		&& one.inode == other.inode
		&& one.owner == other.owner
		&& one.mode == other.mode
}
#[cfg(not(unix))]
fn same_registry_root(_one: &RegistryEpoch, _other: &RegistryEpoch) -> bool {
	false
}

#[derive(Debug)]
struct RegistryScanChanged;

impl std::fmt::Display for RegistryScanChanged {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str("idempotency registry changed during scan; no new job may launch")
	}
}

impl std::error::Error for RegistryScanChanged {}

#[derive(Default)]
struct ReuseHitCache {
	root: Option<PathBuf>,
	epoch: Option<RegistryEpoch>,
	// Preserve known host/key bindings across ordinary directory updates.
	// These are refusal evidence, not a negative cache or effect authority.
	known: HashMap<(String, String), KnownReuseBinding>,
	hits: HashMap<(String, String), String>,
	// Scheduling predictions only: no result, record ID, digest or generation.
	// Unlike hints, these bounded keys may outlive the last admitted demand.
	recent_cold: VecDeque<(String, String)>,
	cold: Arc<RegistryColdScans>,
}

impl ReuseHitCache {
	fn remember_cold_identity(&mut self, identity: &(String, String)) {
		let incoming = identity.0.len().saturating_add(identity.1.len());
		if incoming > MAX_COLD_DEMAND_BYTES {
			return;
		}
		self.recent_cold.retain(|previous| previous != identity);
		let mut bytes: usize = self
			.recent_cold
			.iter()
			.map(|(host, key)| host.len() + key.len())
			.sum();
		while self.recent_cold.len() >= MAX_COLD_COHORT_IDENTITIES
			|| bytes.saturating_add(incoming) > MAX_RECENT_COLD_KEY_BYTES
		{
			let Some(oldest) = self.recent_cold.pop_front() else {
				break;
			};
			bytes -= oldest.0.len() + oldest.1.len();
		}
		self.recent_cold.push_back(identity.clone());
	}

	fn recent_strict_candidates(&self, dir: &Path) -> Vec<(String, String)> {
		if self.root.as_deref() != Some(dir) {
			return Vec::new();
		}
		// At most eight known lookups, independent of the full ownership map.
		self.recent_cold
			.iter()
			.rev()
			.take(MAX_COLD_COHORT_IDENTITIES)
			.filter(|identity| {
				self.known
					.get(*identity)
					.is_some_and(|binding| binding.strict)
			})
			.cloned()
			.collect()
	}
}

#[derive(Clone)]
struct KnownReuseBinding {
	id: String,
	// Invalidating a fast hit must not downgrade an originally strict receipt
	// to the compatibility reader after a content/permission change.
	strict: bool,
}

#[derive(Default)]
struct RegistryColdScans {
	gate: Mutex<()>,
	state: Mutex<RegistryColdState>,
}

#[derive(Default)]
struct RegistryColdState {
	demands: HashMap<(String, String), usize>,
	hints: HashMap<(String, String), RegistryColdHint>,
	active: Option<Vec<(String, String)>>,
}

struct RegistryColdLeader<'a> {
	scans: &'a RegistryColdScans,
	_gate: MutexGuard<'a, ()>,
}

impl Drop for RegistryColdLeader<'_> {
	fn drop(&mut self) {
		// Clear membership before the original gate unlocks, including on panic.
		// A later leader must never inherit authority to queue unscanned keys.
		self.scans
			.state
			.lock()
			.unwrap_or_else(|error| error.into_inner())
			.active = None;
	}
}

#[derive(Clone)]
struct RegistryColdHint {
	epoch: RegistryEpoch,
	id: String,
	digest: [u8; 32],
}

// Only admitted workers register demand. No complete receipt, absent result,
// error or speculative ownership survives the last worker for its key.
struct RegistryColdDemand {
	scans: Arc<RegistryColdScans>,
	identity: (String, String),
}

impl RegistryColdDemand {
	fn register(scans: Arc<RegistryColdScans>, host: &str, key: &str) -> Result<Option<Self>> {
		if host.len().saturating_add(key.len()) > MAX_COLD_DEMAND_BYTES {
			return Ok(None);
		}
		let identity = (host.to_owned(), key.to_owned());
		{
			let mut state = scans
				.state
				.lock()
				.map_err(|_| anyhow::anyhow!("job registry cold demand unavailable"))?;
			if state.demands.values().sum::<usize>() >= MAX_REGISTRY_LOOKUPS {
				return Ok(None);
			}
			*state.demands.entry(identity.clone()).or_default() += 1;
		}
		Ok(Some(Self { scans, identity }))
	}

	fn targets(&self, state: &RegistryColdState) -> Vec<RegistryColdTarget> {
		state
			.demands
			.keys()
			.filter(|identity| *identity != &self.identity)
			.map(|identity| RegistryColdTarget {
				identity: identity.clone(),
				seen: false,
				candidate: None,
			})
			.collect()
	}

	#[cfg(all(test, unix))]
	fn cohort(&self) -> Result<Vec<RegistryColdTarget>> {
		let state = self
			.scans
			.state
			.lock()
			.map_err(|_| anyhow::anyhow!("job registry cold demand unavailable"))?;
		Ok(self.targets(&state))
	}

	fn start_cohort<'a>(
		&'a self,
		gate: MutexGuard<'a, ()>,
		recent: Vec<(String, String)>,
	) -> Result<(RegistryColdLeader<'a>, Vec<RegistryColdTarget>)> {
		let leader = RegistryColdLeader {
			scans: &self.scans,
			_gate: gate,
		};
		let mut state = self
			.scans
			.state
			.lock()
			.map_err(|_| anyhow::anyhow!("job registry cold demand unavailable"))?;
		// All actual other demands fit: at most three distinct keys, each at
		// most 1 KiB. Predictions never displace them or reject the lookup.
		let mut cohort = self.targets(&state);
		let mut bytes: usize = cohort
			.iter()
			.map(|target| target.identity.0.len() + target.identity.1.len())
			.sum();
		for identity in recent {
			if cohort.len() >= MAX_COLD_COHORT_IDENTITIES - 1 {
				break;
			}
			let incoming = identity.0.len().saturating_add(identity.1.len());
			if identity == self.identity
				|| cohort.iter().any(|target| target.identity == identity)
				|| incoming > MAX_COLD_DEMAND_BYTES
				|| bytes.saturating_add(incoming) > MAX_COLD_TARGET_KEY_BYTES
			{
				continue;
			}
			bytes += incoming;
			cohort.push(RegistryColdTarget {
				identity,
				seen: false,
				candidate: None,
			});
		}
		// The consumed prediction iterator (including unused keys) is dropped
		// before cloning this separate, at-most-3-KiB active-membership payload.
		// Membership and the actual scan targets are one frozen snapshot. Late
		// keys cannot wait for a scan that may already have passed their owner.
		state.active = Some(
			cohort
				.iter()
				.map(|target| target.identity.clone())
				.collect(),
		);
		Ok((leader, cohort))
	}

	fn read_hint(
		&self,
		dir: &Path,
		epoch_probe: &impl Fn(&Path) -> Result<RegistryEpoch>,
	) -> Result<Option<JobRecord>> {
		let hint = self
			.scans
			.state
			.lock()
			.map_err(|_| anyhow::anyhow!("job registry cold demand unavailable"))?
			.hints
			.get(&self.identity)
			.cloned();
		let Some(hint) = hint else { return Ok(None) };
		if !registry_has_content_watch(&hint.epoch) || epoch_probe(dir)? != hint.epoch {
			return Ok(None);
		}
		// A hint is not strict ownership. Legacy receipts that cannot pass this
		// reader must retain their complete compatibility scan, not a new error.
		let Ok(record) = read_verified_cached_record(dir, &hint.id) else {
			return Ok(None);
		};
		if record.id != hint.id
			|| record.host != self.identity.0
			|| record.idempotency_key.as_deref() != Some(self.identity.1.as_str())
			|| record.launch_state != "launched"
			|| job_record_binding_digest(&record)? != hint.digest
			|| epoch_probe(dir)? != hint.epoch
		{
			return Ok(None);
		}
		Ok(Some(record))
	}

	fn publish(&self, cohort: Vec<RegistryColdTarget>, epoch: RegistryEpoch) -> Result<()> {
		if !registry_has_content_watch(&epoch) {
			return Ok(());
		}
		let mut state = self
			.scans
			.state
			.lock()
			.map_err(|_| anyhow::anyhow!("job registry cold demand unavailable"))?;
		// Close admission atomically with publication. A predicted key that
		// registers after this point must not wait for an already finished scan.
		state.active = None;
		let mut retained = state
			.hints
			.iter()
			.map(|((host, key), hint)| host.len() + key.len() + hint.id.len() + hint.digest.len())
			.sum::<usize>();
		for target in cohort {
			let Some((id, digest)) = target.candidate else {
				continue;
			};
			let bytes = target.identity.0.len() + target.identity.1.len() + id.len() + digest.len();
			if !state.demands.contains_key(&target.identity)
				|| retained.saturating_add(bytes) > MAX_COLD_HINT_BYTES
			{
				continue;
			}
			retained += bytes;
			state
				.hints
				.insert(target.identity, RegistryColdHint { epoch, id, digest });
		}
		Ok(())
	}
}

impl Drop for RegistryColdDemand {
	fn drop(&mut self) {
		// Cleanup is required even after a worker panic poisoned the registry.
		let mut state = self
			.scans
			.state
			.lock()
			.unwrap_or_else(|error| error.into_inner());
		if let Some(count) = state.demands.get_mut(&self.identity) {
			*count -= 1;
			if *count == 0 {
				state.demands.remove(&self.identity);
				state.hints.remove(&self.identity);
			}
		}
	}
}

struct RegistryColdTarget {
	identity: (String, String),
	seen: bool,
	candidate: Option<(String, [u8; 32])>,
}

impl RegistryColdTarget {
	fn observe(&mut self, record: &JobRecord) -> Result<()> {
		if record.host == self.identity.0
			&& record.idempotency_key.as_deref() == Some(self.identity.1.as_str())
		{
			if self.seen {
				// A duplicate affects that target only. Keep the tombstone so a
				// third record cannot resurrect it as an apparently unique hint.
				self.candidate = None;
			} else if record.launch_state == "launched" && valid_name(&record.id) {
				// The strict hint reader already requires this at-most-128-byte ID.
				// Other IDs still count as seen and retain their full scan path.
				self.candidate = Some((record.id.clone(), job_record_binding_digest(record)?));
			}
			self.seen = true;
		}
		Ok(())
	}
}

struct RegistryScanObserver<'a, F> {
	cohort: &'a mut [RegistryColdTarget],
	after_scan: F,
}

#[cfg(test)]
fn scan_records_dir(dir: &Path) -> Result<Vec<JobRecord>> {
	let mut records = Vec::new();
	let mut bytes = Vec::new();
	for entry in std::fs::read_dir(dir)? {
		let entry = entry?;
		let path = entry.path();
		if path.extension().and_then(|s| s.to_str()) != Some("json") {
			continue;
		}
		// A corrupt/unreadable record might be the owner of an idempotency key.
		// Skipping it would allow a second physical launch after a restart.
		let expected_id = path
			.file_stem()
			.and_then(|stem| stem.to_str())
			.ok_or_else(|| {
				anyhow::anyhow!("invalid durable job record name: {}", path.display())
			})?;
		records.push(read_record_at_with_buffer(&path, expected_id, &mut bytes)?);
	}
	records.sort_by_key(|record| record.created_unix_ms);
	Ok(records)
}

#[cfg(test)]
fn all_records_in(dir: &Path) -> Result<Vec<JobRecord>> {
	scan_records_dir(dir)
}

// Cached reads must be stricter than ordinary compatibility scans: no
// symlink/hardlink, foreign ownership, mode widening, oversized payload or
// path/inode replacement may be silently promoted to a known-good job.
#[cfg(unix)]
fn read_verified_cached_record(dir: &Path, id: &str) -> Result<JobRecord> {
	use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
	if !valid_name(id) {
		bail!("cached job identity invalid");
	}
	let path = dir.join(format!("{id}.json"));
	let before = std::fs::symlink_metadata(&path)
		.context("cached job record unavailable; reconcile original identity")?;
	let safe_file = |m: &std::fs::Metadata| {
		m.file_type().is_file()
			&& m.nlink() == 1
			&& m.uid() == unsafe { libc::geteuid() }
			&& (m.mode() & 0o7777) == 0o600
			&& m.len() > 0
			&& m.len() <= MAX_CACHED_RECORD_BYTES
	};
	let identity = |m: &std::fs::Metadata| {
		(
			m.dev(),
			m.ino(),
			m.uid(),
			m.mode(),
			m.nlink(),
			m.len(),
			m.mtime(),
			m.mtime_nsec(),
			m.ctime(),
			m.ctime_nsec(),
		)
	};
	if !safe_file(&before) {
		bail!("cached job record inode or permissions unsafe; no relaunch");
	}
	#[cfg(all(test, unix))]
	registry_content_tests::after_cached_stat();
	let mut file = OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
		.open(&path)
		.context("cached job record path changed; no relaunch")?;
	let opened = file.metadata()?;
	if !safe_file(&opened) || identity(&before) != identity(&opened) {
		bail!("cached job record identity changed before read; no relaunch");
	}
	// Leave room to observe EOF without growing an otherwise exact-sized read.
	// The same extra byte still detects growth beyond the strict receipt limit.
	let mut bytes = Vec::with_capacity(before.len() as usize + 1);
	(&mut file)
		.take(MAX_CACHED_RECORD_BYTES + 1)
		.read_to_end(&mut bytes)?;
	if bytes.len() as u64 > MAX_CACHED_RECORD_BYTES {
		bail!("cached job record exceeds bounded byte budget");
	}
	let read_done = file.metadata()?;
	let path_done = std::fs::symlink_metadata(&path)?;
	if !safe_file(&path_done)
		|| identity(&opened) != identity(&read_done)
		|| identity(&opened) != identity(&path_done)
	{
		bail!("cached job record changed during read; no relaunch");
	}
	serde_json::from_slice(&bytes)
		.context("cached job record corrupted; never relaunch automatically")
}
#[cfg(not(unix))]
fn read_verified_cached_record(_dir: &Path, _id: &str) -> Result<JobRecord> {
	bail!("cached job record reads require Unix inode identity")
}

// Unlike the full inventory view, an exact-key lookup does not need a sorted
// Vec of all job records. It must still parse EVERY existing JSON record so
// malformed history and duplicate original bindings refuse a new effect.
#[cfg(test)]
fn scan_idempotent_binding_in(dir: &Path, host: &str, key: &str) -> Result<Option<JobRecord>> {
	scan_idempotent_binding_in_with_retries(dir, host, key, |_| {})
}

// Independent host launches can atomically add/replace records while another
// host scans. Retry only that same-directory epoch change, before any job ID,
// durable intent or remote effect is allocated. Never retry invalid history or
// a different registry root; sustained churn still fails within a fixed budget.
#[cfg(test)]
fn scan_idempotent_binding_in_with_retries(
	dir: &Path,
	host: &str,
	key: &str,
	after_scan: impl FnMut(usize),
) -> Result<Option<JobRecord>> {
	scan_idempotent_binding_with_probe(dir, host, key, None, &registry_epoch, after_scan)
}

#[cfg(test)]
fn scan_idempotent_binding_with_probe(
	dir: &Path,
	host: &str,
	key: &str,
	strict_id: Option<&str>,
	epoch_probe: &impl Fn(&Path) -> Result<RegistryEpoch>,
	after_scan: impl FnMut(usize),
) -> Result<Option<JobRecord>> {
	scan_idempotent_binding_cohort(
		dir,
		host,
		key,
		strict_id,
		epoch_probe,
		RegistryScanObserver {
			cohort: &mut [],
			after_scan,
		},
	)
	.map(|(found, _)| found)
}

fn scan_idempotent_binding_cohort(
	dir: &Path,
	host: &str,
	key: &str,
	strict_id: Option<&str>,
	epoch_probe: &impl Fn(&Path) -> Result<RegistryEpoch>,
	mut observer: RegistryScanObserver<'_, impl FnMut(usize)>,
) -> Result<(Option<JobRecord>, RegistryEpoch)> {
	let root = epoch_probe(dir)?;
	for attempt in 0..MAX_IDEMPOTENCY_SCAN_ATTEMPTS {
		match scan_idempotent_binding_once(
			dir,
			host,
			key,
			&root,
			strict_id,
			epoch_probe,
			RegistryScanObserver {
				cohort: &mut *observer.cohort,
				after_scan: || (observer.after_scan)(attempt),
			},
		) {
			Err(error)
				if error.downcast_ref::<RegistryScanChanged>().is_some()
					&& attempt + 1 < MAX_IDEMPOTENCY_SCAN_ATTEMPTS => {}
			result => return result,
		}
	}
	unreachable!("bounded registry scan returns its final attempt")
}

// Preserve the upstream deterministic post-enumeration race fixture for one
// scan. Production uses the bounded wrapper above with the same scan body.
#[cfg(test)]
fn scan_idempotent_binding_in_with_observer(
	dir: &Path,
	host: &str,
	key: &str,
	after_scan: impl FnOnce(),
) -> Result<Option<JobRecord>> {
	scan_idempotent_binding_once(
		dir,
		host,
		key,
		&registry_epoch(dir)?,
		None,
		&registry_epoch,
		RegistryScanObserver {
			cohort: &mut [],
			after_scan,
		},
	)
	.map(|(found, _)| found)
}

fn select_idempotent_record(
	records: impl IntoIterator<Item = JobRecord>,
	host: &str,
	key: &str,
) -> Result<Option<JobRecord>> {
	let mut selected = None;
	for record in records {
		if record.host == host && record.idempotency_key.as_deref() == Some(key) {
			// Historical duplicate owners cannot be resolved by selecting the oldest
			// record. The external effect may already have run from either record.
			if selected.is_some() {
				bail!("duplicate original idempotency binding; multiple durable owners for one key; reconcile before reuse");
			}
			selected = Some(record);
		}
	}
	Ok(selected)
}

fn job_record_binding_digest(record: &JobRecord) -> Result<[u8; 32]> {
	let mut digest = RequestHashWriter(Sha256::new());
	serde_json::to_writer(&mut digest, record)?;
	Ok(digest.0.finalize().into())
}

fn scan_registry_records(
	dir: &Path,
	host: &str,
	key: &str,
	fingerprint: bool,
) -> Result<(Option<JobRecord>, Option<[u8; 32]>)> {
	scan_registry_records_observed(dir, host, key, fingerprint, &mut [])
}

fn scan_registry_records_observed(
	dir: &Path,
	host: &str,
	key: &str,
	fingerprint: bool,
	cohort: &mut [RegistryColdTarget],
) -> Result<(Option<JobRecord>, Option<[u8; 32]>)> {
	#[cfg(all(test, unix))]
	registry_coalescing_tests::scan_started();
	let mut found: Option<JobRecord> = None;
	let mut bytes = Vec::new();
	let mut digest = fingerprint.then(|| RequestHashWriter(Sha256::new()));
	if let Some(digest) = &mut digest {
		digest.write_all(b"hepta-job-registry-stream-v1\0")?;
	}
	for entry in std::fs::read_dir(dir)? {
		let entry = entry?;
		let path = entry.path();
		if path.extension().and_then(|s| s.to_str()) != Some("json") {
			continue;
		}
		let expected_id = path
			.file_stem()
			.and_then(|name| name.to_str())
			.context("invalid durable job record name")?;
		let record = read_record_at_with_buffer(&path, expected_id, &mut bytes)?;
		for target in &mut *cohort {
			target.observe(&record)?;
		}
		if let Some(digest) = &mut digest {
			digest.write_all(&(expected_id.len() as u64).to_le_bytes())?;
			digest.write_all(expected_id.as_bytes())?;
			serde_json::to_writer(digest, &record)?;
		}
		found =
			select_idempotent_record(found.into_iter().chain(std::iter::once(record)), host, key)?;
	}
	Ok((found, digest.map(|digest| digest.0.finalize().into())))
}

fn scan_idempotent_binding_once(
	dir: &Path,
	host: &str,
	key: &str,
	root: &RegistryEpoch,
	strict_id: Option<&str>,
	epoch_probe: &impl Fn(&Path) -> Result<RegistryEpoch>,
	observer: RegistryScanObserver<'_, impl FnOnce()>,
) -> Result<(Option<JobRecord>, RegistryEpoch)> {
	// Never infer an absent binding from a scan that overlaps a directory
	// mutation. The original root identity is pinned across all retry attempts.
	let before = epoch_probe(dir)?;
	if !same_registry_root(root, &before) {
		bail!("idempotency registry root identity changed; reconcile before execution");
	}
	let RegistryScanObserver { cohort, after_scan } = observer;
	// A retry observes a different complete generation. No hint from an earlier
	// failed attempt may acquire the final successful attempt's epoch.
	for target in &mut *cohort {
		target.seen = false;
		target.candidate = None;
	}
	let (mut found, fingerprint) = scan_registry_records_observed(
		dir,
		host,
		key,
		!registry_has_content_watch(&before),
		cohort,
	)?;
	#[cfg(all(test, unix))]
	registry_coalescing_tests::scan_finished();
	after_scan();
	if let Some(fingerprint) = fingerprint {
		// Without a content watch no positive cache is authoritative. Two complete
		// scans validate every receipt and compare decoded bindings, with memory
		// bounded by the selected record and one input record. Directory order is
		// intentionally retained: reordering conservatively retries, never sorts
		// an unbounded pathname collection or uses a commutative digest.
		drop(found);
		let (verified, second) = scan_registry_records(dir, host, key, true)?;
		if second != Some(fingerprint) {
			return Err(RegistryScanChanged.into());
		}
		found = verified;
	}
	if let Some(id) = strict_id {
		// The first strict read can precede a changed epoch and compatibility
		// rescan. Validate the final original again inside this scan's fence.
		let record = read_verified_cached_record(dir, id).map_err(|error| {
			anyhow::anyhow!(
				"previous idempotency binding could not be verified: {error}; no new launch"
			)
		})?;
		if found.as_ref().map(|record| record.id.as_str()) != Some(id)
			|| record.id != id
			|| record.host != host
			|| record.idempotency_key.as_deref() != Some(key)
		{
			bail!("previous idempotency binding missing or changed; no new launch");
		}
		// Both values are already fully decoded. Compare every field directly;
		// digesting serialized copies adds work without adding a trust boundary.
		if found.as_ref() != Some(&record) {
			return Err(RegistryScanChanged.into());
		}
		found = Some(record);
	}
	let after = epoch_probe(dir)?;
	if !same_registry_root(root, &after) {
		bail!("idempotency registry root identity changed; reconcile before execution");
	}
	if after != before {
		return Err(RegistryScanChanged.into());
	}
	Ok((found, after))
}

fn prefill_scanned_strict_peers(
	dir: &Path,
	cache: &Mutex<ReuseHitCache>,
	initial_epoch: RegistryEpoch,
	scanned_epoch: RegistryEpoch,
	cohort: &[RegistryColdTarget],
	epoch_probe: &impl Fn(&Path) -> Result<RegistryEpoch>,
) -> Result<()> {
	// A complete scan can cover callers still outside the four-worker admission
	// bound. Predictions earn only ordinary ID hits after independent strict
	// verification; they never create ownership or extend a demand's hint life.
	if initial_epoch != scanned_epoch
		|| !registry_has_content_watch(&scanned_epoch)
		|| cohort.len() >= MAX_COLD_COHORT_IDENTITIES
		|| cohort.iter().fold(0usize, |bytes, target| {
			bytes
				.saturating_add(target.identity.0.len())
				.saturating_add(target.identity.1.len())
		}) > MAX_COLD_TARGET_KEY_BYTES
	{
		return Ok(());
	}
	let eligible: Vec<_> = {
		let guard = cache
			.lock()
			.map_err(|_| anyhow::anyhow!("reuse cache unavailable"))?;
		if guard.root.as_deref() != Some(dir)
			|| guard.epoch != Some(scanned_epoch)
			|| guard.hits.len() >= MAX_REUSE_HITS
		{
			return Ok(());
		}
		cohort
			.iter()
			.filter(|target| {
				target.seen
					&& target
						.identity
						.0
						.len()
						.saturating_add(target.identity.1.len())
						<= MAX_COLD_DEMAND_BYTES
					&& !guard.hits.contains_key(&target.identity)
					&& target.candidate.as_ref().is_some_and(|(id, _)| {
						guard
							.known
							.get(&target.identity)
							.is_some_and(|binding| binding.strict && binding.id == *id)
					})
			})
			.collect()
	};
	if eligible.is_empty() || !matches!(epoch_probe(dir), Ok(current) if current == scanned_epoch) {
		return Ok(());
	}
	// Stage only borrowed, bounded identities. No file I/O or hashing holds a
	// cache/state mutex, and a later verification panic cannot publish a prefix.
	let mut verified = Vec::with_capacity(eligible.len());
	for target in eligible {
		let Some((id, digest)) = &target.candidate else {
			continue;
		};
		let Ok(record) = read_verified_cached_record(dir, id) else {
			// A failed prediction does not reject an unrelated healthy leader.
			// Its retained strict binding still forbids a compatibility downgrade.
			continue;
		};
		if record.id == *id
			&& record.host == target.identity.0
			&& record.idempotency_key.as_deref() == Some(target.identity.1.as_str())
			&& record.launch_state == "launched"
			&& job_record_binding_digest(&record).ok().as_ref() == Some(digest)
		{
			verified.push(target);
		}
	}
	if verified.is_empty() || !matches!(epoch_probe(dir), Ok(current) if current == scanned_epoch) {
		return Ok(());
	}
	let mut guard = cache
		.lock()
		.map_err(|_| anyhow::anyhow!("reuse cache unavailable"))?;
	if guard.root.as_deref() != Some(dir) || guard.epoch != Some(scanned_epoch) {
		return Ok(());
	}
	for target in verified {
		if guard.hits.len() >= MAX_REUSE_HITS {
			break;
		}
		let Some((id, _)) = &target.candidate else {
			continue;
		};
		if guard
			.known
			.get(&target.identity)
			.is_some_and(|binding| binding.strict && binding.id == *id)
		{
			guard
				.hits
				.entry(target.identity.clone())
				.or_insert_with(|| id.clone());
		}
	}
	Ok(())
}

// Only cache a VERIFIED EXISTING, already launched identity. Unknown keys,
// pending/uncertain launches, changed registry identity and errors always
// retain the full historical scan. Never use this cache to authorize a new job.
fn find_idempotent_in(
	dir: &Path,
	host: &str,
	key: &str,
	cache: &Mutex<ReuseHitCache>,
) -> Result<Option<JobRecord>> {
	find_idempotent_in_with_probe(dir, host, key, cache, registry_epoch, || {})
}

fn find_idempotent_in_with_probe(
	dir: &Path,
	host: &str,
	key: &str,
	cache: &Mutex<ReuseHitCache>,
	epoch_probe: impl Fn(&Path) -> Result<RegistryEpoch>,
	after_strict_read: impl FnOnce(),
) -> Result<Option<JobRecord>> {
	let epoch = epoch_probe(dir)?;
	let identity = (host.to_owned(), key.to_owned());
	let (cached_id, known) = {
		let mut guard = cache
			.lock()
			.map_err(|_| anyhow::anyhow!("reuse cache unavailable"))?;
		if guard.root.is_some() && guard.root.as_deref() != Some(dir) {
			bail!("job registry root changed; reconcile existing identities first");
		}
		if guard
			.epoch
			.is_some_and(|previous| !same_registry_root(&previous, &epoch))
		{
			bail!("job registry root identity changed; reconcile existing identities first");
		}
		if guard.epoch != Some(epoch) {
			// A changed registry invalidates fast reads, not prior ownership.
			guard.hits.clear();
			guard.epoch = Some(epoch);
		}
		if !registry_has_content_watch(&epoch) {
			guard.hits.clear();
		}
		guard.root = Some(dir.to_path_buf());
		(
			guard.hits.get(&identity).cloned(),
			guard.known.get(&identity).cloned(),
		)
	};
	// Only refreshes of known strict ownership share a complete generation.
	// Register before this worker's strict read so other admitted refreshes can
	// join during that required I/O; there is no batching delay or extra queue.
	// Hot hits, first observations and new keys retain their independent paths.
	let demand = if cached_id.is_none()
		&& registry_has_content_watch(&epoch)
		&& known.as_ref().is_some_and(|binding| binding.strict)
	{
		let scans = cache
			.lock()
			.map_err(|_| anyhow::anyhow!("reuse cache unavailable"))?
			.cold
			.clone();
		RegistryColdDemand::register(scans, host, key)?
	} else {
		None
	};
	#[cfg(all(test, unix))]
	registry_coalescing_tests::after_registration();
	let strict_id = cached_id.as_deref().or_else(|| {
		known
			.as_ref()
			.filter(|binding| binding.strict)
			.map(|binding| binding.id.as_str())
	});
	if let Some(id) = strict_id {
		if known.as_ref().map(|binding| binding.id.as_str()) != Some(id) {
			bail!("cached idempotency binding lost original ownership; no new launch");
		}
		if !valid_name(id) {
			bail!("cached job identity invalid; never allocate a replacement job");
		}
		let record = read_verified_cached_record(dir, id).map_err(|error| {
			anyhow::anyhow!(
				"previous idempotency binding could not be verified: {error}; no new launch"
			)
		})?;
		if record.id != id || record.host != host || record.idempotency_key.as_deref() != Some(key)
		{
			bail!("cached job binding changed; never allocate a replacement job");
		}
		after_strict_read();
		// A pending/unknown record can cause launch reconciliation; that path
		// must continue scanning every original job before any new effect.
		if cached_id.is_some() && record.launch_state == "launched" && epoch_probe(dir)? == epoch {
			return Ok(Some(record));
		}
	}

	// Only members of an already frozen scan wait for its hints. An admitted
	// late key retains the original parallel full scan instead of queuing for
	// work that never covered it. The original worker still owns its permit.
	let mut cold_leader = None;
	let mut shared = None;
	let mut cohort = Vec::new();
	if let Some(demand) = &demand {
		if demand.scans.gate.is_poisoned() {
			bail!("job registry cold scan unavailable");
		}
		shared = demand.read_hint(dir, &epoch_probe)?;
		if demand.scans.gate.is_poisoned() {
			bail!("job registry cold scan unavailable");
		}
		if shared.is_none() {
			match demand.scans.gate.try_lock() {
				Ok(gate) => {
					// A completed leader may have published after our first read.
					shared = demand.read_hint(dir, &epoch_probe)?;
					if shared.is_none() {
						let recent = {
							let guard = cache
								.lock()
								.map_err(|_| anyhow::anyhow!("reuse cache unavailable"))?;
							guard.recent_strict_candidates(dir)
						};
						let (leader, targets) = demand.start_cohort(gate, recent)?;
						cold_leader = Some(leader);
						cohort = targets;
					}
				}
				Err(TryLockError::WouldBlock) => {
					let included = {
						let state =
							demand.scans.state.lock().map_err(|_| {
								anyhow::anyhow!("job registry cold demand unavailable")
							})?;
						state
							.active
							.as_ref()
							.is_some_and(|targets| targets.contains(&demand.identity))
					};
					if included {
						#[cfg(all(test, unix))]
						registry_coalescing_tests::cohort_wait_started();
						let gate =
							demand.scans.gate.lock().map_err(|_| {
								anyhow::anyhow!("job registry cold scan unavailable")
							})?;
						shared = demand.read_hint(dir, &epoch_probe)?;
						// Missing/changed hints must not turn a follower into another
						// serial full scan. Fall back only after releasing the gate.
						drop(gate);
					}
				}
				Err(TryLockError::Poisoned(_)) => {
					bail!("job registry cold scan unavailable");
				}
			}
		}
	}
	let (found, scanned_epoch) = if let Some(record) = shared {
		(Some(record), None)
	} else {
		let (found, scanned_epoch) = scan_idempotent_binding_cohort(
			dir,
			host,
			key,
			known
				.as_ref()
				.filter(|binding| binding.strict)
				.map(|binding| binding.id.as_str()),
			&epoch_probe,
			RegistryScanObserver {
				cohort: &mut cohort,
				after_scan: |_| {},
			},
		)?;
		(found, Some(scanned_epoch))
	};
	if !same_registry_root(&epoch, &epoch_probe(dir)?) {
		bail!("job registry root identity changed during lookup; no new launch");
	}
	if let Some(expected) = &known {
		if found.as_ref().map(|r| r.id.as_str()) != Some(expected.id.as_str()) {
			bail!("previous idempotency binding missing or changed; no new launch");
		}
	}
	if found.is_none() {
		// A cancelled predecessor can finish its read-only lookup after the next
		// same-key caller started. Newly retained ownership still forbids absence.
		let guard = cache
			.lock()
			.map_err(|_| anyhow::anyhow!("reuse cache unavailable"))?;
		if guard.known.contains_key(&identity) {
			bail!("previous idempotency binding missing or changed; no new launch");
		}
	}
	if let Some(record) = &found {
		// Compatibility scans may legitimately return old 0644 or 1–4 MiB
		// receipts. Retain their ownership without falsely making them strict.
		// Hash/read outside the cache mutex; only verified bytes can earn a hit.
		let verify_strict = (registry_has_content_watch(&epoch)
			&& record.launch_state == "launched")
			|| known.as_ref().is_some_and(|binding| binding.strict);
		let strict_verification = verify_strict.then(|| -> Result<()> {
			let verified = read_verified_cached_record(dir, &record.id)?;
			if &verified != record {
				bail!("cached job binding changed during strict verification");
			}
			Ok(())
		});
		let strictly_verified = matches!(&strict_verification, Some(Ok(())));
		let after = epoch_probe(dir)?;
		let mut guard = cache
			.lock()
			.map_err(|_| anyhow::anyhow!("reuse cache unavailable"))?;
		if let Some(latest) = guard.known.get(&identity) {
			if latest.id != record.id {
				bail!("previous idempotency binding missing or changed; no new launch");
			}
			if latest.strict && !strictly_verified {
				if let Some(Err(error)) = strict_verification {
					bail!("previous idempotency binding could not be verified: {error}; no new launch");
				}
				bail!("previous idempotency binding became strict during lookup; no new launch");
			}
		}
		if guard.root.as_deref() == Some(dir) && guard.epoch == Some(epoch) {
			if guard.known.len() < MAX_REUSE_HITS {
				guard
					.known
					.entry(identity.clone())
					.or_insert_with(|| KnownReuseBinding {
						id: record.id.clone(),
						strict: false,
					});
			}
			if record.launch_state == "launched"
				&& registry_has_content_watch(&epoch)
				&& strictly_verified
				&& after == epoch
				&& guard.hits.len() < MAX_REUSE_HITS
				// Epoch changes clear hits, while known can already be full.
				// Never cache an identity whose refusal evidence was not retained.
				&& guard.known.get(&identity).map(|binding| &binding.id) == Some(&record.id)
			{
				if let Some(binding) = guard.known.get_mut(&identity) {
					binding.strict = true;
				}
				// Update only inside the complete original positive-hit gate.
				// Warm fast returns never mutate this prediction queue.
				guard.remember_cold_identity(&identity);
				guard
					.hits
					.entry(identity)
					.or_insert_with(|| record.id.clone());
			}
		}
	}
	if let (Some(_), Some(demand), Some(scanned_epoch)) = (&cold_leader, &demand, scanned_epoch) {
		// Publish only after all original refusal checks succeed. Each waiter
		// verifies the complete digest and this exact epoch before using a hint.
		prefill_scanned_strict_peers(dir, cache, epoch, scanned_epoch, &cohort, &epoch_probe)?;
		demand.publish(cohort, scanned_epoch)?;
	}
	Ok(found)
}

fn find_idempotent(host: &str, key: &str) -> Result<Option<JobRecord>> {
	// Readers may scan concurrently. A local pending/result publication waits
	// until every lookup, including verified cache reads, has checked its epoch.
	// External writers still require the bounded epoch checks inside the scan.
	with_registry_read(&REGISTRY_ACCESS, || {
		find_idempotent_in(
			&jobs_dir()?,
			host,
			key,
			REUSE_HITS.get_or_init(|| Mutex::new(ReuseHitCache::default())),
		)
	})
}

async fn run_registry_lookup(
	slots: Arc<Semaphore>,
	lookup: impl FnOnce() -> Result<Option<JobRecord>> + Send + 'static,
) -> Result<Option<JobRecord>> {
	let permit = slots
		.acquire_owned()
		.await
		.map_err(|_| anyhow::anyhow!("job registry lookup capacity unavailable"))?;
	let result = tokio::task::spawn_blocking(move || {
		// A cancelled caller cannot release capacity while its original scan
		// still holds the registry read lock or accesses historical receipts.
		let _permit = permit;
		lookup()
	})
	.await;
	match result {
		Ok(result) => result,
		Err(_) => bail!("job registry lookup worker unavailable"),
	}
}

async fn find_idempotent_async(host: &str, key: &str) -> Result<Option<JobRecord>> {
	let host = host.to_owned();
	let key = key.to_owned();
	let slots = REGISTRY_LOOKUPS
		.get_or_init(|| Arc::new(Semaphore::new(MAX_REGISTRY_LOOKUPS)))
		.clone();
	// This lookup worker is read-only. The caller retains its
	// original key lane and effect admission fence around later publication.
	run_registry_lookup(slots, move || find_idempotent(&host, &key)).await
}

fn start_io_slots() -> Arc<Semaphore> {
	START_IO_WORKERS
		.get_or_init(|| Arc::new(Semaphore::new(MAX_START_IO_WORKERS)))
		.clone()
}

fn start_outcome_slots() -> Arc<Semaphore> {
	START_OUTCOME_PUBLICATIONS
		.get_or_init(|| Arc::new(Semaphore::new(MAX_START_OUTCOME_PUBLICATIONS)))
		.clone()
}

async fn run_start_io<T: Send + 'static>(
	slots: Arc<Semaphore>,
	ownership: impl Send + 'static,
	operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
	let permit = slots
		.acquire_owned()
		.await
		.map_err(|_| anyhow::anyhow!("job start I/O capacity unavailable"))?;
	run_admitted_start_io(permit, ownership, operation).await
}

async fn run_admitted_start_io<T: Send + 'static>(
	permit: OwnedSemaphorePermit,
	ownership: impl Send + 'static,
	operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
	let result = tokio::task::spawn_blocking(move || {
		// Cancellation cannot release the original key lane, owner fence or
		// worker slot while a durable publication can still change the registry.
		let _permit = permit;
		let _ownership = ownership;
		operation()
	})
	.await;
	match result {
		Ok(result) => result,
		Err(_) => bail!("job start I/O worker unavailable"),
	}
}

async fn start_io<T: Send + 'static>(
	guard: &Option<OwnedStartGuard>,
	owner: &Arc<super::effect_owner_fence::AdmissionPermit>,
	operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
	run_start_io(start_io_slots(), (guard.clone(), owner.clone()), operation).await
}

async fn start_audit(
	action: &str,
	host: &str,
	subject: &str,
	outcome: &Value,
	guard: &Option<OwnedStartGuard>,
	owner: &Arc<super::effect_owner_fence::AdmissionPermit>,
) -> Result<()> {
	// Freeze the original event before capacity backpressure can suspend it.
	let prepared = prepare_audit(action, host, subject, outcome)?;
	start_io(guard, owner, move || append_audit(prepared)).await
}

fn persist_pending_with(
	prepared: PreparedAudit,
	record: &JobRecord,
	append: impl FnOnce(PreparedAudit) -> Result<()>,
	persist: impl FnOnce(&JobRecord) -> Result<()>,
) -> Result<()> {
	require_operation_intent(append(prepared))?;
	persist(record).map_err(|_| {
		anyhow::anyhow!("Durable job identity could not be saved; no remote launch submitted")
	})
}

async fn publish_pending_record(
	record: &JobRecord,
	guard: &Option<OwnedStartGuard>,
	owner: &Arc<super::effect_owner_fence::AdmissionPermit>,
) -> Result<()> {
	let prepared = prepare_audit(
		"process_start_intent",
		&record.host,
		&record.id,
		&json!({"phase":"intent","remote_operation_submitted":false}),
	)
	.map_err(|_| operation_intent_unavailable())?;
	let record = record.clone();
	start_io(guard, owner, move || {
		persist_pending_with(prepared, &record, append_audit, save_record)
	})
	.await
}

// Keep the alphabetical key order of the original serde_json::Value map.
// Borrow potentially large input while retaining exactly its original JSON bytes.
#[derive(Serialize)]
struct RequestBinding<'a> {
	args: &'a [String],
	cpu_quota_percent: Option<u16>,
	cwd: Option<&'a str>,
	env: &'a BTreeMap<String, String>,
	executable: &'a str,
	host: &'a str,
	memory_max_bytes: Option<u64>,
	nice: Option<u8>,
	stdin: Option<&'a str>,
	timeout_seconds: Option<u64>,
}
fn request_binding(params: &ProcessStartParams) -> RequestBinding<'_> {
	RequestBinding {
		args: &params.args,
		cpu_quota_percent: params.cpu_quota_percent,
		cwd: params.cwd.as_deref(),
		env: &params.env,
		executable: &params.executable,
		host: &params.host,
		memory_max_bytes: params.memory_max_bytes,
		nice: params.nice,
		stdin: params.stdin.as_deref(),
		timeout_seconds: params.timeout_seconds,
	}
}
struct RequestHashWriter(Sha256);
impl Write for RequestHashWriter {
	fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
		self.0.update(bytes);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}
pub(crate) fn request_digest(params: &ProcessStartParams) -> Result<String> {
	let mut writer = RequestHashWriter(Sha256::new());
	serde_json::to_writer(&mut writer, &request_binding(params))?;
	let digest = writer.0.finalize();
	let mut hex = String::with_capacity(64);
	const HEX: &[u8; 16] = b"0123456789abcdef";
	for byte in digest {
		hex.push(HEX[(byte >> 4) as usize] as char);
		hex.push(HEX[(byte & 15) as usize] as char);
	}
	Ok(hex)
}

// Retain the old prefix only for readable legacy metadata. New idempotent
// requests compare all 256 bits, and legacy bindings never silently relaunch.
fn fingerprint(digest: &str) -> u64 {
	digest
		.get(..16)
		.and_then(|prefix| u64::from_str_radix(prefix, 16).ok())
		.unwrap_or(0)
}
fn verify_reuse_binding(
	existing: &JobRecord,
	key: &str,
	legacy_fingerprint: u64,
	full_digest: &str,
) -> Result<()> {
	// Old 64-bit-only records remain inspectable, but do not establish a
	// collision-resistant authorization to restart a physical process.
	if existing.request_digest.is_none() {
		bail!("legacy idempotency record lacks full request binding; reconcile without replay");
	}
	if existing.request_fingerprint != legacy_fingerprint
		|| existing.request_digest.as_deref() != Some(full_digest)
	{
		bail!("idempotency key `{key}` is already bound to a different request");
	}
	Ok(())
}

fn admit_observation_only_reuse(record: &JobRecord) -> Result<()> {
	match record.launch_state.as_str() {
		"launched" => Ok(()),
		"pending" | "launch_failed" => bail!(
			"durable launch outcome indeterminate: reconcile original remote effect without replay"
		),
		_ => bail!("unknown durable job launch state; no replay permitted"),
	}
}

fn matches_request(record: &JobRecord, digest: &str) -> Result<bool> {
	let expected = record.request_digest.as_ref().context(
		"legacy idempotency binding lacks a full digest; inspect existing job_id instead of relaunching",
	)?;
	Ok(expected.as_str() == digest
		&& verify_reuse_binding(
			record,
			record.idempotency_key.as_deref().unwrap_or(""),
			fingerprint(digest),
			digest,
		)
		.is_ok())
}

fn check_ref(params: &ProcessRefParams) -> Result<JobRecord> {
	let record = load_record(&params.job_id)?;
	check_binding(&record)?;
	if record.host != params.host {
		bail!(
			"job `{}` belongs to host `{}`, not `{}`",
			params.job_id,
			record.host,
			params.host
		);
	}
	Ok(record)
}

struct PreparedAudit {
	path: PathBuf,
	line: Vec<u8>,
}

// One positive publication proof, never an event/history or absence cache.
// Held descriptors prevent inode reuse from manufacturing an identity match.
struct AuditReadiness {
	#[cfg(unix)]
	binding: AuditBinding,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AuditDirectoryStamp {
	device: u64,
	inode: u64,
	modified: (i64, i64),
	changed: (i64, i64),
	namespace: super::namespace_version::Version,
}

#[cfg(unix)]
fn audit_directory_stamp(directory: &std::fs::File) -> Result<AuditDirectoryStamp> {
	use std::os::unix::fs::MetadataExt;
	let metadata = directory.metadata()?;
	if !metadata.is_dir() {
		bail!("audit publication parent is not a directory");
	}
	Ok(AuditDirectoryStamp {
		device: metadata.dev(),
		inode: metadata.ino(),
		modified: (metadata.mtime(), metadata.mtime_nsec()),
		changed: (metadata.ctime(), metadata.ctime_nsec()),
		namespace: super::namespace_version::version(directory)?,
	})
}

#[cfg(unix)]
fn audit_inode(metadata: &std::fs::Metadata) -> (u64, u64) {
	use std::os::unix::fs::MetadataExt;
	(metadata.dev(), metadata.ino())
}

#[cfg(unix)]
fn open_audit_directory(path: &Path) -> Result<std::fs::File> {
	use std::os::unix::fs::OpenOptionsExt;
	// Follow the same configured symlinks as before, while refusing a FIFO or
	// regular-file substitution before a newly added read open could block.
	Ok(OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
		.open(path)?)
}

#[cfg(unix)]
fn audit_reliable_generation(stamps: &[AuditDirectoryStamp; 3]) -> bool {
	#[cfg(target_os = "linux")]
	{
		stamps.iter().all(|stamp| {
			matches!(
				stamp.namespace,
				super::namespace_version::Version::Watch(_, _)
			)
		})
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = stamps;
		false
	}
}

#[cfg(unix)]
struct AuditBinding {
	path: PathBuf,
	audit_path: PathBuf,
	state_path: PathBuf,
	target_path: PathBuf,
	file: std::fs::File,
	audit_directory: std::fs::File,
	state_directory: std::fs::File,
	target_directory: std::fs::File,
	stamps: [AuditDirectoryStamp; 3],
}

#[cfg(unix)]
impl AuditBinding {
	fn open(path: PathBuf, file: std::fs::File) -> Result<Self> {
		let path = if path.is_absolute() {
			path
		} else {
			std::env::current_dir()?.join(path)
		};
		let audit_path = path
			.parent()
			.context("audit path has no parent")?
			.to_path_buf();
		let state_path = audit_path.parent().unwrap_or(Path::new("/")).to_path_buf();
		// The file was opened no-follow and owner-private. Keep the complete
		// path and parent publication fences in addition to that inode check.
		let target_path = std::fs::canonicalize(&path)?;
		let target_parent = target_path.parent().context("audit target has no parent")?;
		let audit_directory = open_audit_directory(&audit_path)?;
		let state_directory = open_audit_directory(&state_path)?;
		let target_directory = open_audit_directory(target_parent)?;
		let stamps = [
			audit_directory_stamp(&audit_directory)?,
			audit_directory_stamp(&state_directory)?,
			audit_directory_stamp(&target_directory)?,
		];
		let binding = Self {
			path,
			audit_path,
			state_path,
			target_path,
			file,
			audit_directory,
			state_directory,
			target_directory,
			stamps,
		};
		binding.validate()?;
		Ok(binding)
	}

	fn validate(&self) -> Result<()> {
		let file_identity = audit_inode(&self.file.metadata()?);
		if audit_inode(&std::fs::metadata(&self.path)?) != file_identity
			|| std::fs::canonicalize(&self.path)? != self.target_path
			|| audit_inode(&std::fs::metadata(&self.target_path)?) != file_identity
		{
			bail!("audit file binding changed");
		}
		let paths: [&Path; 3] = [
			self.audit_path.as_path(),
			self.state_path.as_path(),
			self.target_path.parent().expect("target parent"),
		];
		let directories = [
			&self.audit_directory,
			&self.state_directory,
			&self.target_directory,
		];
		for ((path, directory), expected) in paths.into_iter().zip(directories).zip(&self.stamps) {
			if audit_inode(&std::fs::metadata(path)?) != (expected.device, expected.inode)
				|| audit_directory_stamp(directory)? != *expected
			{
				bail!("audit directory publication binding changed");
			}
		}
		Ok(())
	}

	fn can_reuse_parents(&self, path: &Path, file: &std::fs::File) -> Result<bool> {
		// A names/inodes fingerprint can return to the same value after an
		// unlink/relink ABA, especially on a filesystem with coarse timestamps.
		// It remains a final fence, but never authorizes omitting a later barrier.
		if !path.is_absolute()
			|| path.as_os_str() != self.path.as_os_str()
			|| !audit_reliable_generation(&self.stamps)
			|| audit_inode(&file.metadata()?) != audit_inode(&self.file.metadata()?)
		{
			return Ok(false);
		}
		// Resolve all original names and symlink targets again, and validate all
		// held directory descriptors and reliable namespace generations.
		self.validate()?;
		Ok(true)
	}

	fn synchronize_directories(
		&self,
		synchronize: &mut impl FnMut(&std::fs::File) -> Result<()>,
	) -> Result<()> {
		// Normal layout performs exactly audit → state. A symlink target outside
		// that pair adds one bounded target-parent barrier before alias parents.
		let target = (self.stamps[2].device, self.stamps[2].inode);
		let audit = (self.stamps[0].device, self.stamps[0].inode);
		let state = (self.stamps[1].device, self.stamps[1].inode);
		if target != audit && target != state {
			synchronize(&self.target_directory)?;
		}
		synchronize(&self.audit_directory)?;
		if state != audit {
			synchronize(&self.state_directory)?;
		}
		Ok(())
	}
}

fn prepare_audit_at(
	path: PathBuf,
	action: &str,
	host: &str,
	subject: &str,
	outcome: &Value,
) -> Result<PreparedAudit> {
	let event = json!({
		"at_unix_ms": now_ms(),
		"action": action,
		"host": host,
		"subject": subject,
		"outcome": outcome,
	});
	let mut line = serde_json::to_vec(&event)?;
	line.push(b'\n');
	Ok(PreparedAudit { path, line })
}

fn prepare_audit(
	action: &str,
	host: &str,
	subject: &str,
	outcome: &Value,
) -> Result<PreparedAudit> {
	prepare_audit_at(
		runtime_config()?.state_dir.join("audit/events.jsonl"),
		action,
		host,
		subject,
		outcome,
	)
}

fn append_audit_with(
	prepared: PreparedAudit,
	synchronize: impl FnOnce(&std::fs::File) -> Result<()>,
) -> Result<()> {
	let preparation = prepared.path.parent().map_or(Ok(()), |parent| {
		std::fs::create_dir_all(parent).map_err(anyhow::Error::from)
	});
	let mut readiness = AUDIT_LOCK
		.get_or_init(|| Mutex::new(None))
		.lock()
		.map_err(|_| anyhow::anyhow!("audit lock poisoned"))?;
	append_audit_prepared_with(
		prepared,
		&mut readiness,
		preparation,
		synchronize,
		|directory| Ok(directory.sync_all()?),
	)
}

fn append_audit_prepared_with(
	prepared: PreparedAudit,
	readiness: &mut Option<AuditReadiness>,
	preparation: Result<()>,
	synchronize_file: impl FnOnce(&std::fs::File) -> Result<()>,
	synchronize_directory: impl FnMut(&std::fs::File) -> Result<()>,
) -> Result<()> {
	if let Err(error) = preparation {
		*readiness = None;
		return Err(error);
	}
	append_audit_at_with(prepared, readiness, synchronize_file, synchronize_directory)
}

fn open_audit_append(path: &Path) -> Result<File> {
	let mut options = OpenOptions::new();
	options.create(true).append(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options
			.mode(0o600)
			.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
	}
	let file = options.open(path)?;
	let metadata = file.metadata()?;
	if !metadata.is_file() {
		bail!("audit sink is not a regular file: {}", path.display());
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::{MetadataExt, PermissionsExt};
		if metadata.nlink() != 1 || metadata.uid() != unsafe { libc::geteuid() } {
			bail!("audit sink must not be hard-linked: {}", path.display());
		}
		// The prior release created audit files using the caller's umask.
		// Tighten a regular, independently opened file descriptor during upgrade
		// rather than breaking every audit operation on legacy mode 0644.
		if metadata.permissions().mode() & 0o077 != 0 {
			file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
			if file.metadata()?.permissions().mode() & 0o077 != 0 {
				bail!("audit sink must be owner-private: {}", path.display());
			}
		}
	}
	Ok(file)
}

#[cfg(unix)]
fn append_audit_at_with(
	prepared: PreparedAudit,
	readiness: &mut Option<AuditReadiness>,
	synchronize_file: impl FnOnce(&std::fs::File) -> Result<()>,
	mut synchronize_directory: impl FnMut(&std::fs::File) -> Result<()>,
) -> Result<()> {
	let previous = readiness.take();
	let file = open_audit_append(&prepared.path)?;
	let warm = previous.as_ref().is_some_and(|previous| {
		previous
			.binding
			.can_reuse_parents(&prepared.path, &file)
			.unwrap_or(false)
	});
	let mut binding = if warm {
		let mut binding = previous.expect("qualified audit readiness").binding;
		binding.file = file;
		binding
	} else {
		// Any missing/mismatched/failed prior proof is irreversibly cold. A
		// freshly opened matching binding cannot restore warm authorization.
		AuditBinding::open(prepared.path, file)?
	};
	binding.file.write_all(&prepared.line)?;
	// The existing per-event fdatasync remains mandatory on both paths.
	synchronize_file(&binding.file)?;
	if !warm {
		binding.synchronize_directories(&mut synchronize_directory)?;
	}
	binding.validate()?;
	*readiness = Some(AuditReadiness { binding });
	Ok(())
}

#[cfg(not(unix))]
fn append_audit_at_with(
	prepared: PreparedAudit,
	readiness: &mut Option<AuditReadiness>,
	synchronize_file: impl FnOnce(&std::fs::File) -> Result<()>,
	_synchronize_directory: impl FnMut(&std::fs::File) -> Result<()>,
) -> Result<()> {
	// Keep the previous platform guarantee and path behavior. This candidate's
	// directory publication proof applies only to the Unix implementation.
	*readiness = None;
	let mut file = open_audit_append(&prepared.path)?;
	file.write_all(&prepared.line)?;
	synchronize_file(&file)
}

fn append_audit(prepared: PreparedAudit) -> Result<()> {
	append_audit_with(prepared, |file| {
		file.sync_data()?;
		Ok(())
	})
}

pub(crate) fn audit(action: &str, host: &str, subject: &str, outcome: &Value) -> Result<()> {
	append_audit(prepare_audit(action, host, subject, outcome)?)
}

fn observation_audit_unavailable() -> anyhow::Error {
	anyhow::anyhow!("Existing job observation completion audit unavailable")
}

async fn run_observation_audit(
	prepared: PreparedAudit,
	slots: Arc<Semaphore>,
	append: impl FnOnce(PreparedAudit) -> Result<()> + Send + 'static,
) -> Result<()> {
	let permit = slots
		.acquire_owned()
		.await
		.map_err(|_| observation_audit_unavailable())?;
	let result = tokio::task::spawn_blocking(move || {
		// A cancelled waiter cannot release capacity while its blocking append
		// still owns a file or waits for the shared audit synchronization lock.
		let _permit = permit;
		append(prepared)
	})
	.await;
	match result {
		Ok(Ok(())) => Ok(()),
		_ => Err(observation_audit_unavailable()),
	}
}

async fn observation_completion_audit(
	action: &str,
	host: &str,
	subject: &str,
	outcome: &Value,
) -> Result<()> {
	// Freeze the original observation time, destination and identity before
	// either capacity backpressure or the blocking-pool handoff can suspend.
	let prepared = prepare_audit(action, host, subject, outcome)
		.map_err(|_| observation_audit_unavailable())?;
	let slots = OBSERVATION_AUDITS
		.get_or_init(|| Arc::new(Semaphore::new(MAX_OBSERVATION_AUDITS)))
		.clone();
	run_observation_audit(prepared, slots, append_audit).await
}

// Shared by start and reconciliation: existing unsafe directories never become a new launch.
const PRIVATE_DIRECTORY_CODE: &str = r#"
import os, pathlib, stat, sys
_hepta_directory_pins = []
def private_job_directory(raw, create=False):
    if not isinstance(raw, str) or not raw.startswith("/") or any(p in (".", "..") for p in raw.split("/")):
        raise SystemExit("unsafe remote job path")
    parts = [p for p in raw.split("/") if p]
    if len(parts) < 3 or parts[-2] != "jobs":
        raise SystemExit("remote job path must name a dedicated state/jobs/job directory")
    shared_access = getattr(os, "O_PATH", os.O_RDONLY) if sys.platform == "linux" else os.O_RDONLY
    path_only_shared = shared_access != os.O_RDONLY
    directory_flags = os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", shared_access | directory_flags)
    _hepta_directory_pins.append(fd)
    for offset, part in enumerate(parts):
        private = offset >= len(parts) - 3
        if create and private and not path_only_shared:
            try:
                os.mkdir(part, mode=0o700, dir_fd=fd)
                os.fsync(fd)
            except FileExistsError:
                pass
        access = os.O_RDONLY if private else shared_access
        try:
            child = os.open(part, access | directory_flags, dir_fd=fd)
        except FileNotFoundError:
            if not (create and private and path_only_shared):
                raise
            # O_PATH traverses an existing searchable ancestor without reading it.
            # A new child still needs its parent's original durability barrier:
            # acquire a readable handle before mkdir, or refuse without creating.
            sync_parent = os.open(".", os.O_RDONLY | directory_flags, dir_fd=fd)
            _hepta_directory_pins.append(sync_parent)
            pinned = os.fstat(fd)
            readable = os.fstat(sync_parent)
            if (pinned.st_dev, pinned.st_ino) != (readable.st_dev, readable.st_ino):
                raise SystemExit("remote parent directory identity changed; no directory created")
            try:
                os.mkdir(part, mode=0o700, dir_fd=sync_parent)
            except FileExistsError:
                pass
            else:
                os.fsync(sync_parent)
            child = os.open(part, os.O_RDONLY | directory_flags, dir_fd=sync_parent)
        _hepta_directory_pins.append(child)
        info = os.fstat(child)
        if private and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise SystemExit("unsafe remote state/jobs/job directory; existing permissions are never repaired")
        fd = child
    os.fchdir(fd)
    return pathlib.Path(".")

def private_bound_job_directory(raw, expected):
    job = private_job_directory(raw)
    info = os.fstat(_hepta_directory_pins[-1])
    if (info.st_dev, info.st_ino) != (expected["device"], expected["inode"]):
        raise SystemExit("remote job directory identity changed; no workload submitted")
    return job

def private_open_job_file(name):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=_hepta_directory_pins[-1])
    except FileNotFoundError:
        return None
    except OSError as error:
        raise SystemExit("unsafe remote job file " + name) from error
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022):
        os.close(fd)
        raise SystemExit("unsafe remote job file " + name + ": non-regular or linked inode")
    return fd

def private_read_json(name):
    import json
    fd = private_open_job_file(name)
    if fd is None: return None
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if before.st_size > 4 * 1024 * 1024:
            raise SystemExit("unsafe remote job file " + name + ": linked or oversized inode")
        encoded = stream.read(4 * 1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
        current = os.stat(name, dir_fd=_hepta_directory_pins[-1], follow_symlinks=False)
    def stamp(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if len(encoded) > 4 * 1024 * 1024 or stamp(before) != stamp(after) or stamp(after) != stamp(current):
        raise SystemExit("unsafe remote job file " + name + ": changed while reading")
    try:
        value = json.loads(encoded)
        if not isinstance(value, dict): raise ValueError("not an object")
        return value
    except (ValueError, UnicodeError) as error:
        raise SystemExit("corrupt remote job file " + name) from error

"#;

fn private_remote_code(code: &str) -> Result<String> {
	Ok(format!(
		"REMOTE_DIRECTORY_SOURCE = {}\nexec(REMOTE_DIRECTORY_SOURCE)\n{}",
		serde_json::to_string(PRIVATE_DIRECTORY_CODE)?,
		code
	))
}

const BOUND_OBSERVATION_CODE: &str = r#"
import io, json
_original_query = json.load(sys.stdin)
_bound_job = private_job_directory(_original_query["job_dir"])
_bound_request = private_read_json("request.json")
_digest = _original_query.get("request_digest")
if (not isinstance(_bound_request, dict) or not isinstance(_digest, str) or len(_digest) != 64 or
        any(c not in "0123456789abcdef" for c in _digest) or
        _bound_request.get("job_id") != _original_query.get("job_id") or
        _bound_request.get("job_dir") != _original_query.get("job_dir") or
        _bound_request.get("unit") != _original_query.get("unit") or
        _bound_request.get("request_digest", _bound_request.get("request_fingerprint")) != _digest):
    raise SystemExit("remote job request binding missing or mismatched")
# Metadata is validated before a status can claim success or cancellation can
# acknowledge a terminal receipt. The status owner interprets a torn private
# started.json as unknown, and a confirmed terminal receipt takes precedence.
# Cancellation still validates its owner record before sending any signal.
for _name in ("launch.json", "exit.json"):
    private_read_json(_name)
sys.stdin = io.StringIO(json.dumps(_original_query))
"#;

fn bound_remote_code(code: &str) -> Result<String> {
	private_remote_code(&format!("{BOUND_OBSERVATION_CODE}\n{code}"))
}

pub(super) fn observation_script(kind: super::ssh::ObservationScript) -> Result<String> {
	bound_remote_code(match kind {
		super::ssh::ObservationScript::Status => STATUS_CODE,
		super::ssh::ObservationScript::Read => READ_CODE,
	})
}

#[cfg(test)]
#[path = "private_job_directory_tests.rs"]
mod private_directory_tests;

const START_CODE: &str = r#"
import fcntl, json, os, pathlib, shutil, subprocess, sys, time
req = json.load(sys.stdin)
req["default_cwd"] = os.getcwd()
os.umask(0o077)
job = private_job_directory(req["job_dir"], create=True)
lock_fd = os.open(job / "launch.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
lock_info = os.fstat(lock_fd)
if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.geteuid() or lock_info.st_nlink != 1 or stat.S_IMODE(lock_info.st_mode) != 0o600:
    raise SystemExit("unsafe remote launch lock")
launch_lock = os.fdopen(lock_fd, "a")
fcntl.flock(launch_lock.fileno(), fcntl.LOCK_EX)


def read_json(name):
    return private_read_json(name)

def atomic(name, value):
    target = job / name
    tmp = job / (name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")
        stream.flush(); os.fsync(stream.fileno())
    os.replace(tmp, target)
    fd = os.open(job, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)

def stage_file(name, data, mode):
    # A durable request/launch must never refer to an unsynchronized input or
    # supervisor archive. Partial creates remain tombstones, never replacements.
    fd = os.open(job / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        os.fchmod(stream.fileno(), mode)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(_hepta_directory_pins[-1])

stdin_text = req.pop("stdin", None)
existing = read_json("request.json")
if existing is not None:
    if (existing.get("job_id") != req.get("job_id") or existing.get("request_fingerprint") != req.get("request_fingerprint") or
            existing.get("job_dir") != req.get("job_dir") or existing.get("unit") != req.get("unit") or
            existing.get("request_digest", existing.get("request_fingerprint")) != req.get("request_digest", req.get("request_fingerprint"))):
        raise SystemExit("remote job directory is bound to a different request")
    launch = read_json("launch.json")
    exit_data = read_json("exit.json")
    # An existing request never launches again. Owner tombstones need not be
    # parsed here; status owns their conservative interpretation.
    if launch and launch.get("backend") == "launch_failed":
        raise SystemExit("prior remote launch failed; reconcile original identity without replay")
    if launch or exit_data:
        print(json.dumps({"ok": True, "reused_remote": True, **(launch or {"backend": "completed"})}, sort_keys=True))
        raise SystemExit(0)
    raise SystemExit("ambiguous prior launch: inspect this job; do not relaunch under another key")
else:
    if any(os.path.lexists(job / name) for name in ("stdin.bin","runner.py","owner-intent.json","started.json","child.json","launch.json","exit.json","exit.witness.json","exit.witness.json.tmp","stdout.log","stderr.log")):
        raise SystemExit("prior or uncertain job artifacts exist without request binding; no launch submitted")
    req["launch_nonce"] = os.urandom(16).hex()
    req["terminal_publication_protocol"] = 1
    if stdin_text is not None:
        stage_file("stdin.bin", stdin_text.encode("utf-8"), 0o600)
        req["stdin_path"] = str(pathlib.Path(req["job_dir"]) / "stdin.bin")
    fd = os.open(job / "request.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(req, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(job, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)
runner = r'''#!/usr/bin/env python3
import errno, fcntl, hashlib, json, os, pathlib, select, shutil, signal, stat, subprocess, sys, threading, time
# Only the trusted launcher chooses this argv marker, never request metadata.
# A legacy unmarked runner retains the original detached nice adjustment.
if len(sys.argv) not in (3, 4):
    raise SystemExit("invalid supervisor launch backend; no workload submitted")
launch_backend = sys.argv[3] if len(sys.argv) == 4 else "detached"
if launch_backend not in ("systemd", "detached"):
    raise SystemExit("invalid supervisor launch backend; no workload submitted")
binding = json.loads(sys.argv[2])
job = private_bound_job_directory(sys.argv[1], binding)
req = private_read_json("request.json")
if (req.get("job_id"), req.get("launch_nonce"), req.get("request_fingerprint")) != (binding["job_id"], binding["launch_nonce"], binding["request_fingerprint"]):
    raise SystemExit("remote launch identity changed; no workload submitted")

def atomic(name, value):
    target = job / name
    tmp = job / (name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    encoded = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
        stream.flush(); os.fsync(stream.fileno())
    os.replace(tmp, target)
    os.fsync(_hepta_directory_pins[-1])
    return encoded

def publish_terminal(value):
    value = {**value, "terminal_publication_protocol": 1,
             "job_id": req["job_id"], "launch_nonce": req["launch_nonce"]}
    encoded = atomic("exit.json", value)
    # A visible witness proves that the preceding exit file and directory
    # barriers returned. Losing the witness only makes status unconfirmed;
    # its presence does not claim its own final directory fsync survived loss.
    atomic("exit.witness.json", {
        "terminal_publication_protocol": 1,
        "job_id": req["job_id"],
        "launch_nonce": req["launch_nonce"],
        "exit_sha256": hashlib.sha256(encoded).hexdigest(),
    })

def reap_original_child(child, timeout):
    # Finish every original-group signal before entering this bounded wait.
    # Popen.wait maps ECHILD to a successful-looking zero; only an actual
    # waitpid return for this original child can prove a reap and exit code.
    wait_deadline = time.monotonic() + timeout
    while True:
        waited_pid, status = os.waitpid(child.pid, os.WNOHANG)
        if waited_pid == child.pid:
            child.returncode = os.waitstatus_to_exitcode(status)
            return child.returncode
        if waited_pid != 0:
            raise RuntimeError("wait returned an unexpected child identity")
        remaining = wait_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("original child wait deadline exceeded")
        time.sleep(min(0.01, remaining))

def process_identity(pid):
    if sys.platform == "linux":
        try:
            ticks = int(pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19])
            boot = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            return {"kind": "proc_start_ticks", "value": boot + ":" + str(ticks)} if boot else None
        except Exception:
            return None
    try:
        value = subprocess.check_output(["ps", "-p", str(pid), "-o", "lstart="], text=True, timeout=3).strip()
        return {"kind": "ps_lstart", "value": value} if value else None
    except Exception:
        return None

os.umask(0o077)
owner_fd = os.open(job / "owner.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
owner_stat = os.fstat(owner_fd)
if not stat.S_ISREG(owner_stat.st_mode) or owner_stat.st_uid != os.geteuid() or owner_stat.st_nlink != 1 or owner_stat.st_mode & 0o077:
    raise SystemExit("unsafe supervisor lifetime lock")
fcntl.flock(owner_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
if any(os.path.lexists(job / name) for name in ("owner-intent.json","started.json","exit.json","exit.witness.json","exit.witness.json.tmp")):
    raise SystemExit("prior supervisor intent or binding exists; workload must not be replayed")
if sys.platform == "linux":
    if not hasattr(os, "waitid") or not hasattr(os, "WNOWAIT"):
        raise SystemExit("non-reaping child identity observation unavailable; no workload submitted")
elif not all(hasattr(select, name) for name in ("kqueue","kevent","KQ_FILTER_PROC","KQ_NOTE_EXIT")):
    raise SystemExit("non-reaping child exit observation unavailable; no workload submitted")
owner_identity = process_identity(os.getpid())
if not owner_identity:
    raise SystemExit("supervisor start identity unavailable; no workload submitted")
owner_binding = {"at_unix_ms":int(time.time()*1000),"job_id":req["job_id"],
    "launch_nonce":req["launch_nonce"],"supervisor_pid":os.getpid(),
    "supervisor_uid":os.geteuid(),"supervisor_identity":owner_identity,
    "invocation_id":os.environ.get("INVOCATION_ID")}
def stage_owner(name):
    fd = os.open(job / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(owner_binding, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
# Both files must be synced and closed before one barrier publishes their names.
# Surviving partial creates remain tombstones; no workload precedes this barrier.
stage_owner("owner-intent.json")
stage_owner("started.json")
os.fsync(_hepta_directory_pins[-1])
child = None
cancel_requested = False

def stop_handler(signum, _frame):
    global cancel_requested
    cancel_requested = True

signal.signal(signal.SIGTERM, stop_handler)
signal.signal(signal.SIGINT, stop_handler)
# systemd has already applied Nice=; only the detached path needs an adjustment.
if launch_backend == "detached" and req.get("nice"):
    try:
        os.nice(int(req["nice"]))
    except OSError:
        pass
out = open(job / "stdout.log", "ab", buffering=0)
err = open(job / "stderr.log", "ab", buffering=0)
stdin_handle = subprocess.DEVNULL
if req.get("stdin_path"):
    stdin_handle = open(job / "stdin.bin", "rb", buffering=0)
env = os.environ.copy()
env.update(req.get("env", {}))
env["HEPTA_RUNTIME_JOB_ID"] = req["job_id"]
try:
    child = subprocess.Popen(
        [req["executable"], *req.get("args", [])],
        cwd=req.get("cwd") or req.get("default_cwd"),
        env=env,
        stdin=stdin_handle,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    atomic("child.json", {
        "pid": child.pid,
        "identity": process_identity(child.pid),
    })
except Exception as exc:
    if child is not None:
        # Popen crossed the effect boundary. Keep the original child unreaped
        # until every group signal is sent, and never report a prelaunch error.
        group_signal = "submitted"
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            group_signal = "already_absent"
        except OSError:
            group_signal = "failed"
        child_reaped = False
        try:
            reap_original_child(child, 2)
            child_reaped = True
        except Exception:
            pass
        publish_terminal({
            "at_unix_ms": int(time.time() * 1000),
            "exit_code": 125,
            "supervisor_error": "child receipt publication failed after spawn",
            "effect_outcome": "unknown",
            "status_authoritative": False,
            "automatic_retry": False,
            "child_spawned": True,
            "child_pid": child.pid,
            "child_group_signal": group_signal,
            "child_reaped": child_reaped,
            "child_exit_code": child.returncode if child_reaped else None,
            "output_complete": False,
            "output_durable": False,
            "cancelled": False,
            "timed_out": False,
        })
        raise SystemExit(125)
    publish_terminal({
        "at_unix_ms": int(time.time() * 1000),
        "exit_code": 127,
        "launch_error": str(exc),
        "cancelled": False,
        "timed_out": False,
    })
    print(str(exc), file=err, flush=True)
    raise SystemExit(127)

# Operator archives retain every byte; isolated compatibility remains bounded.
# Disk failures are explicit capture errors, never silent tail eviction.
log_truncated = {"stdout": False, "stderr": False}
log_errors = {"stdout": None, "stderr": None}
log_eof = {"stdout": False, "stderr": False}
log_drain_finished = {"stdout": None, "stderr": None}
log_bytes = {"stdout": {"seen": 0, "stored": 0}, "stderr": {"seen": 0, "stored": 0}}
def drain(stream, sink, label):
    stored = 0
    try:
        while True:
            chunk = stream.read1(65536)
            if not chunk:
                log_eof[label] = True
                break
            log_bytes[label]["seen"] += len(chunk)
            keep = chunk if req.get("execution_mode") == "operator" else chunk[:max(0, 16 * 1024 * 1024 - stored)]
            if len(keep) != len(chunk):
                log_truncated[label] = True
            if log_errors[label] is None:
                try:
                    pending = memoryview(keep)
                    while pending:
                        written = sink.write(pending)
                        if written is None or written <= 0 or written > len(pending):
                            raise OSError("log write made invalid progress")
                        stored += written
                        log_bytes[label]["stored"] = stored
                        pending = pending[written:]
                except Exception as exc:
                    # Continue draining after storage failure; never deadlock the
                    # producer or publish silent success for lost output.
                    log_errors[label] = "write: " + str(exc)
    except Exception as exc:
        log_errors[label] = "read: " + str(exc)
    finally:
        try:
            stream.close()
        except Exception as exc:
            if log_errors[label] is None:
                log_errors[label] = "close: " + str(exc)
        log_drain_finished[label] = time.monotonic()

readers = None
try:
    readers = [threading.Thread(target=drain, args=(child.stdout, out, "stdout"), daemon=True),
               threading.Thread(target=drain, args=(child.stderr, err, "stderr"), daemon=True)]
    for reader in readers:
        reader.start()
except Exception as exc:
    # Reader startup is after Popen and the durable child receipt. Keep the
    # original child unreaped until the last group signal, just as for a
    # post-spawn receipt failure; this must never become a prelaunch error.
    primary_error = type(exc).__name__ + ": " + str(exc)
    cleanup_errors = []
    group_signal = "submitted"
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        group_signal = "already_absent"
    except Exception as cleanup:
        group_signal = "failed"
        cleanup_errors.append("signal: " + str(cleanup))
    child_reaped = False
    try:
        reap_original_child(child, 2)
        child_reaped = True
    except Exception as cleanup:
        cleanup_errors.append("wait: " + str(cleanup))
    for index, (label, stream) in enumerate((("stdout", child.stdout), ("stderr", child.stderr))):
        reader = readers[index] if readers is not None else None
        # ident remains set after a thread exits. Join every reader whose
        # startup is observable; do not join one without an observed ident.
        try:
            if reader is not None and reader.ident is not None:
                reader.join(timeout=2)
                if reader.is_alive():
                    cleanup_errors.append(label + ": output reader did not stop")
            else:
                stream.close()
        except Exception as cleanup:
            cleanup_errors.append(label + ": " + str(cleanup))
    try:
        publish_terminal({
            "at_unix_ms": int(time.time() * 1000),
            "exit_code": 125,
            "supervisor_error": "output reader startup failed after spawn: " + primary_error,
            "supervisor_cleanup_errors": cleanup_errors,
            "effect_outcome": "unknown",
            "status_authoritative": False,
            "automatic_retry": False,
            "child_spawned": True,
            "child_pid": child.pid,
            "child_group_signal": group_signal,
            "child_reaped": child_reaped,
            "child_exit_code": child.returncode if child_reaped else None,
            "output_complete": False,
            "output_durable": False,
            "cancelled": False,
            "timed_out": False,
        })
    except Exception as publication_error:
        # A failed error receipt must not replace the original startup error.
        raise exc from publication_error
    raise SystemExit(125)
timed_out = False
timeout = req.get("timeout_seconds")
deadline = time.monotonic() + float(timeout) if timeout else None
stop_deadline, kill_submitted = None, False
# Preserve both original join budgets while the leader remains unreaped:
# stdout gets two seconds, then stderr gets two seconds after stdout finishes.
# The absolute four-second cap also bounds any cleanup after a failed join.
leader_drain_until, leader_reader_deadline = None, None
leader_reader_index, leader_reader_expired = 0, False
leader_drain_error, leader_group_signal = None, "not_submitted"
leader_group_signal_number = None
leader_kill_submitted, leader_cancel_signalled = False, False
leader_cleanup_errors = []
exit_queue, exit_seen = None, False
def exit_observation_failed(exc):
    # A failed observer does not establish that the submitted child stopped.
    # Except for ECHILD, this owner has never reaped its original child: finish
    # every group signal before its bounded wait. ECHILD expressly removes
    # that custody; neither a saved PID nor Popen's ECHILD compatibility result
    # may then authorize signalling or be presented as a known child exit.
    primary_error = type(exc).__name__ + ": " + str(exc)
    cleanup_errors = []
    custody_retained = not isinstance(exc, ChildProcessError) and getattr(exc, "errno", None) != errno.ECHILD
    group_signal, group_signal_number, child_reaped = "not_submitted", None, False
    if custody_retained:
        group_signal, group_signal_number = "submitted", int(signal.SIGKILL)
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            group_signal = "already_absent"
        except Exception as cleanup:
            group_signal = "failed"
            cleanup_errors.append("signal: " + str(cleanup))
        try:
            reap_original_child(child, 2)
            child_reaped = True
        except Exception as cleanup:
            if isinstance(cleanup, ChildProcessError) or getattr(cleanup, "errno", None) == errno.ECHILD:
                custody_retained = False
            cleanup_errors.append("wait: " + str(cleanup))
    else:
        cleanup_errors.append("wait: original child custody unavailable; no signal or wait submitted")
    # This is a separate failure cleanup budget, never a new workload timeout
    # or a retry. One absolute join budget covers both already-started readers.
    join_deadline = time.monotonic() + 2
    for label, reader in zip(("stdout", "stderr"), readers):
        try:
            reader.join(timeout=max(0, join_deadline - time.monotonic()))
            if reader.is_alive():
                cleanup_errors.append(label + ": output reader did not stop")
        except Exception as cleanup:
            cleanup_errors.append(label + ": " + str(cleanup))
    if exit_queue is not None:
        try:
            exit_queue.close()
        except Exception as cleanup:
            cleanup_errors.append("observer close: " + str(cleanup))
    try:
        publish_terminal({
            "at_unix_ms": int(time.time() * 1000),
            "exit_code": 125,
            "supervisor_error": "child exit observation failed after spawn: " + primary_error,
            "supervisor_cleanup_errors": cleanup_errors,
            "effect_outcome": "unknown",
            "status_authoritative": False,
            "automatic_retry": False,
            "child_spawned": True,
            "child_pid": child.pid,
            "child_custody_retained": custody_retained,
            "child_group_signal": group_signal,
            "child_group_signal_number": group_signal_number,
            "child_reaped": child_reaped,
            "child_exit_code": child.returncode if child_reaped else None,
            "output_complete": False,
            "output_durable": False,
            "cancelled": bool(cancel_requested),
            "timed_out": bool(timed_out),
        })
    except Exception as publication_error:
        raise exc from publication_error
    raise SystemExit(125)

if sys.platform != "linux":
    try:
        exit_queue = select.kqueue()
        try:
            exit_queue.control([select.kevent(child.pid, filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE, fflags=select.KQ_NOTE_EXIT)], 0, 0)
        except ProcessLookupError:
            exit_seen = True
    except Exception as exc:
        exit_observation_failed(exc)
while True:
    # waitid(WNOWAIT) / kqueue observes exit without reaping. The original
    # leader holds its PID/PGID until this one path completes all group signals.
    try:
        if sys.platform == "linux":
            exited = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        else:
            exit_seen = exit_seen or bool(exit_queue.control([], 1, 0))
            exited = True if exit_seen else None
    except Exception as exc:
        exit_observation_failed(exc)
    now = time.monotonic()
    if exited is None and deadline is not None and now >= deadline:
        timed_out = True
    stopping = timed_out or cancel_requested
    if exited is not None and not stopping and leader_drain_until is None:
        leader_reader_deadline, leader_drain_until = now + 2, now + 4
    if leader_drain_until is not None:
        if not leader_kill_submitted:
            while leader_reader_index < len(readers):
                label = ("stdout", "stderr")[leader_reader_index]
                finished = log_drain_finished[label]
                # Natural completion requires EOF and an ended thread: a read
                # failure also ends drain without releasing inherited writers.
                # A completion timestamp later than this reader's deadline
                # cannot turn an expired join into success.
                if (log_eof[label] and not readers[leader_reader_index].is_alive() and finished is not None
                        and finished <= leader_reader_deadline):
                    leader_reader_index += 1
                    if leader_reader_index < len(readers):
                        leader_reader_deadline = min(leader_drain_until, now + 2)
                    continue
                if now >= leader_reader_deadline:
                    leader_reader_expired = True
                break
            if leader_reader_index == len(readers):
                break
        elif not any(reader.is_alive() for reader in readers):
            break
        # Cancellation during this existing drain window must not renew it
        # with a fresh eight-second cancellation grace period.
        if cancel_requested and not leader_cancel_signalled and not leader_kill_submitted:
            leader_cancel_signalled = True
            # SIGTERM can close the inherited pipes immediately. Record the
            # interrupted capture before signalling, not only on escalation.
            leader_drain_error = "output drain cancelled after leader exit"
            for label in log_errors:
                if not log_eof[label]:
                    log_errors[label] = log_errors[label] or leader_drain_error
            leader_group_signal, leader_group_signal_number = "submitted", int(signal.SIGTERM)
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                leader_group_signal = "already_absent"
            except Exception as cleanup:
                leader_group_signal = "failed"
                leader_cleanup_errors.append("signal: " + str(cleanup))
        if leader_reader_expired and not leader_kill_submitted:
            leader_kill_submitted = True
            leader_drain_error = leader_drain_error or "output drain deadline exceeded after leader exit"
            expired_label = ("stdout", "stderr")[leader_reader_index]
            log_errors[expired_label] = log_errors[expired_label] or leader_drain_error
            for label in log_errors:
                if not log_eof[label]:
                    log_errors[label] = log_errors[label] or leader_drain_error
            leader_group_signal, leader_group_signal_number = "submitted", int(signal.SIGKILL)
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                leader_group_signal = "already_absent"
            except Exception as cleanup:
                leader_group_signal = "failed"
                leader_cleanup_errors.append("signal: " + str(cleanup))
        if now >= leader_drain_until:
            # A late stderr timeout may leave no join time. Signal while the
            # original leader is still held, then report any undrained reader;
            # never grant another interval or claim cleanup completed.
            break
    elif stopping:
        if stop_deadline is None:
            stop_deadline = now + 8
            try: os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError: pass
        elif now >= stop_deadline and not kill_submitted:
            kill_submitted = True
            try: os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        if exited is not None and (all(log_eof.values()) or now >= stop_deadline):
            break
    time.sleep(.05)
try:
    # Every loop exit already observed the original leader's exit. Consume its
    # actual status once, without creating another child-wait interval.
    reap_original_child(child, 0)
except Exception as exc:
    # This is after the final reap boundary, unlike observer failures above.
    # A failed final wait grants no further signal or wait authority: ECHILD
    # may mean the original identity is already gone. Never rescue by old PGID.
    cleanup_errors = list(leader_cleanup_errors)
    # An existing leader drain deadline also bounds this error path, including
    # the zero remaining time after expiry; do not grant another two seconds.
    join_deadline = leader_drain_until if leader_drain_until is not None else time.monotonic() + 2
    for label, reader in zip(("stdout", "stderr"), readers):
        try:
            reader.join(timeout=max(0, join_deadline - time.monotonic()))
            if reader.is_alive():
                cleanup_errors.append(label + ": output reader did not stop")
        except Exception as cleanup:
            cleanup_errors.append(label + ": " + str(cleanup))
    if exit_queue is not None:
        try:
            exit_queue.close()
        except Exception as cleanup:
            cleanup_errors.append("observer close: " + str(cleanup))
    terminal = {
        "at_unix_ms": int(time.time() * 1000),
        "exit_code": 125,
        "supervisor_error": "final child wait failed after exit observation: " + type(exc).__name__ + ": " + str(exc),
        "supervisor_cleanup_errors": cleanup_errors,
        "effect_outcome": "unknown",
        "status_authoritative": False,
        "automatic_retry": False,
        "child_spawned": True,
        "child_pid": child.pid,
        "child_reaped": False,
        "child_exit_code": None,
        "output_complete": False,
        "output_durable": False,
        "log_truncated": log_truncated,
        "log_errors": log_errors,
        "log_bytes": log_bytes,
        "log_synced": {"stdout": False, "stderr": False},
        "cancelled": bool(cancel_requested),
        "timed_out": bool(timed_out),
    }
    if leader_drain_error is not None:
        terminal.update({
            "prior_output_drain_error": leader_drain_error,
            "child_group_signal": leader_group_signal,
            "child_group_signal_number": leader_group_signal_number,
        })
    try:
        publish_terminal(terminal)
    except Exception as publication_error:
        raise exc from publication_error
    raise SystemExit(125)
if exit_queue is not None: exit_queue.close()
rc = 124 if timed_out else child.returncode
log_synced = {"stdout": False, "stderr": False}
for label, reader, sink in zip(("stdout", "stderr"), readers, (out, err)):
    remaining = max(0, leader_drain_until - time.monotonic()) if leader_drain_until is not None else 2
    reader.join(timeout=remaining)
    if reader.is_alive():
        log_errors[label] = log_errors[label] or "output drain deadline exceeded"
        if leader_drain_error is not None:
            leader_cleanup_errors.append(label + ": output reader did not stop")
        continue
    try:
        # One barrier per completed stream, never per chunk. A durable exit
        # receipt must not precede the output bytes whose completion it claims.
        sink.flush()
        os.fsync(sink.fileno())
        log_synced[label] = True
    except Exception as exc:
        log_errors[label] = log_errors[label] or "sync: " + str(exc)
output_complete = leader_drain_error is None and all(log_eof.values()) and not any(log_errors.values()) and not any(log_truncated.values())
output_durable = output_complete and all(log_synced.values())
terminal = {
    "at_unix_ms": int(time.time() * 1000),
    "exit_code": int(rc),
    "cancelled": bool(cancel_requested),
    "timed_out": bool(timed_out),
    "log_truncated": log_truncated,
    "log_errors": log_errors,
    "log_bytes": log_bytes,
    "output_complete": output_complete,
    "output_durable": output_durable,
    "log_synced": log_synced,
}
if leader_drain_error is not None:
    # EOF after terminating an inherited writer cannot restore successful
    # capture or establish which external effects that writer performed.
    terminal.update({
        "exit_code": 125,
        "supervisor_error": leader_drain_error,
        "supervisor_cleanup_errors": leader_cleanup_errors,
        "effect_outcome": "unknown",
        "status_authoritative": False,
        "automatic_retry": False,
        "child_spawned": True,
        "child_pid": child.pid,
        "child_group_signal": leader_group_signal,
        "child_group_signal_number": leader_group_signal_number,
        "child_reaped": True,
        "child_exit_code": child.returncode,
    })
publish_terminal(terminal)
supervisor_rc = 125 if leader_drain_error is not None else rc if output_durable or rc != 0 else 74
raise SystemExit(int(supervisor_rc) if 0 <= int(supervisor_rc) <= 255 else 1)
'''
runner_path = job / "runner.py"
runner = REMOTE_DIRECTORY_SOURCE + "\n" + runner
stage_file("runner.py", runner.encode("utf-8"), 0o700)
info = os.fstat(_hepta_directory_pins[-1])
binding = json.dumps({"device":info.st_dev,"inode":info.st_ino,"job_id":req["job_id"],"launch_nonce":req["launch_nonce"],"request_fingerprint":req["request_fingerprint"]}, sort_keys=True)
uid = os.getuid()
env = os.environ.copy()
env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{uid}")
env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path=/run/user/{uid}/bus")
cmd = [
    "systemd-run", "--user", "--quiet", "--collect",
    "--unit", req["unit"],
    "--property", "KillMode=control-group",
    "--property", "TimeoutStopSec=10s",
    "--property", f"Description=Hepta Runtime job {req['job_id']} {req['launch_nonce']}",
]
if req.get("cpu_quota_percent"):
    cmd += ["--property", f"CPUQuota={int(req['cpu_quota_percent'])}%"]
if req.get("memory_max_bytes"):
    cmd += ["--property", f"MemoryMax={int(req['memory_max_bytes'])}"]
if req.get("nice"):
    cmd += ["--property", f"Nice={int(req['nice'])}"]
if req.get("execution_mode", "isolated") != "operator":
    cmd += ["--property", "NoNewPrivileges=yes", "--property", "RestrictSUIDSGID=yes"]
if not req.get("allow_job_network", False):
    cmd += ["--property", "PrivateNetwork=yes", "--property", "RestrictAddressFamilies=AF_UNIX AF_NETLINK"]
# Execute the trusted source inline. A renamed shared ancestor must never
# redirect the interpreter into an unverified replacement runner.py.
cmd += ["--", sys.executable, "-I", "-S", "-c", runner, req["job_dir"], binding, "systemd"]
if req.get("platform", "linux") == "linux" and shutil.which("systemd-run"):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
else:
    result = subprocess.CompletedProcess(cmd, 127, "", "systemd user units unavailable on this platform")
if result.returncode == 0:
    launch = {"backend": "systemd", "unit": req["unit"], "launcher_pid": None}
else:
    if not req.get("allow_detached_fallback", False):
        atomic("launch.json", {
            "backend": "launch_failed",
            "unit": req["unit"],
            "systemd_error": result.stderr.strip(),
        })
        print(result.stderr.strip(), file=sys.stderr)
        raise SystemExit(result.returncode or 1)
    if req.get("cpu_quota_percent") or req.get("memory_max_bytes"):
        raise SystemExit("detached backend cannot enforce requested CPU/memory limits")
    process = subprocess.Popen(
        [sys.executable, "-I", "-S", "-c", runner, req["job_dir"], binding, "detached"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
        env=env,
    )
    launch = {
        "backend": "detached",
        "unit": req["unit"],
        "launcher_pid": process.pid,
        "systemd_error": result.stderr.strip(),
    }
atomic("launch.json", launch)
print(json.dumps({"ok": True, **launch}, sort_keys=True))
"#;

const STATUS_CODE: &str = r#"
import json, os, pathlib, stat, subprocess, sys, time
q = json.load(sys.stdin)
job = private_job_directory(q["job_dir"])

def read_json(name):
    return private_read_json(name)

def process_identity(pid):
    if sys.platform == "linux":
        try:
            ticks = int(pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19])
            boot = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            return {"kind": "proc_start_ticks", "value": boot + ":" + str(ticks)} if boot else None
        except Exception:
            return None
    try:
        value = subprocess.check_output(["ps", "-p", str(pid), "-o", "lstart="], text=True, timeout=3).strip()
        return {"kind": "ps_lstart", "value": value} if value else None
    except Exception:
        return None

def valid_owner(request, started, systemd=False):
    nonce = request.get("launch_nonce")
    identity = started.get("supervisor_identity")
    return (isinstance(nonce, str) and len(nonce) == 32 and all(c in "0123456789abcdef" for c in nonce) and
        started.get("job_id") == request.get("job_id") and started.get("launch_nonce") == nonce and
        type(started.get("supervisor_uid")) is int and started["supervisor_uid"] == os.geteuid() and
        type(started.get("supervisor_pid")) is int and 1 < started["supervisor_pid"] <= 2147483647 and
        isinstance(identity, dict) and identity.get("kind") == ("proc_start_ticks" if sys.platform == "linux" else "ps_lstart") and
        isinstance(identity.get("value"), str) and bool(identity["value"]) and
        (not systemd or (isinstance(started.get("invocation_id"), str) and len(started["invocation_id"]) == 32 and
            all(c in "0123456789abcdef" for c in started["invocation_id"]))))

def process_uid(pid):
    if sys.platform == "linux": return pathlib.Path(f"/proc/{pid}").stat().st_uid
    return int(subprocess.check_output(["ps", "-p", str(pid), "-o", "uid="], text=True, timeout=3).strip())

def publication_pending(reason):
    return {"state": "finalizing", "outcome": "unknown", "reason": reason,
            "terminal_publication_confirmed": False,
            "status_authoritative": False, "automatic_retry": False}

def read_terminal_file(name, limit, missing_ok=False):
    # Relative to the already pinned job directory; never follow a receipt
    # symlink or wait on a substituted FIFO. Hash and parse this one snapshot.
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=_hepta_directory_pins[-1])
    except FileNotFoundError:
        if missing_ok:
            return None
        raise
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > limit):
            raise ValueError("unsafe terminal publication file")
        encoded = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        current = os.stat(name, dir_fd=_hepta_directory_pins[-1], follow_symlinks=False)
    def stamp(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if (len(encoded) > limit or len(encoded) != before.st_size or
            stamp(before) != stamp(after) or stamp(after) != stamp(current)):
        raise ValueError("terminal publication file changed")
    return encoded

def read_owner_binding():
    # An interrupted O_EXCL owner write is a permanent no-replay tombstone.
    # Only malformed bytes in a verified private regular file become Unknown;
    # unsafe paths, ownership/mode changes and read failures still propagate.
    encoded = read_terminal_file("started.json", 16 * 1024, missing_ok=True)
    if encoded is None:
        return {}
    try:
        value = json.loads(encoded)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}

def read_terminal_status(request):
    field = "terminal_publication_protocol"
    if field in request and (type(request[field]) is not int or request[field] != 1):
        return publication_pending("terminal publication protocol is unsupported")
    try:
        encoded = read_terminal_file("exit.json", 1024 * 1024)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return publication_pending("terminal receipt is unavailable or unsafe")
    try:
        exit_data = json.loads(encoded)
        if not isinstance(exit_data, dict):
            raise ValueError("terminal receipt must be an object")
        if field not in request and field not in exit_data:
            return final_status(exit_data)
        if type(exit_data.get(field)) is not int or exit_data[field] != 1:
            return publication_pending("terminal publication protocol is missing or unsupported")
        nonce = request.get("launch_nonce")
        if (not isinstance(nonce, str) or len(nonce) != 32 or
                not all(c in "0123456789abcdef" for c in nonce) or
                exit_data.get("job_id") != request["job_id"] or exit_data.get("launch_nonce") != nonce):
            return publication_pending("terminal receipt identity does not match the original request")
        import hashlib
        witness = json.loads(read_terminal_file("exit.witness.json", 4096))
        if (not isinstance(witness, dict) or type(witness.get(field)) is not int or witness[field] != 1 or
                witness.get("job_id") != request["job_id"] or witness.get("launch_nonce") != nonce or
                witness.get("exit_sha256") != hashlib.sha256(encoded).hexdigest()):
            return publication_pending("terminal publication witness does not match the original receipt")
        result = final_status(exit_data)
        result["terminal_publication_confirmed"] = True
        result["automatic_retry"] = False
        return result
    except (OSError, ValueError, TypeError, KeyError):
        return publication_pending("terminal publication witness or receipt is unavailable or invalid")

def final_status(exit_data):
    if exit_data.get("effect_outcome") == "unknown":
        state = "effect_unknown"
    elif exit_data.get("timed_out"):
        state = "timed_out"
    elif exit_data.get("cancelled"):
        state = "cancelled"
    elif int(exit_data.get("exit_code", -1)) == 0:
        # Legacy receipts without these additive fields remain readable.
        output_failed = any(name in exit_data and exit_data[name] is not True
                            for name in ("output_complete", "output_durable"))
        state = "failed" if output_failed else "succeeded"
    else:
        state = "failed"
    return {**exit_data, "state": state}

def one_status():
    request = read_json("request.json")
    if not request or request.get("job_id") != q["job_id"]:
        return {"state": "unknown", "reason": "remote job metadata missing or mismatched"}
    terminal = read_terminal_status(request)
    if terminal is not None:
        return terminal
    requires_witness = "terminal_publication_protocol" in request
    launch = read_json("launch.json") or {}
    if launch.get("backend") == "systemd":
        uid = os.getuid()
        env = os.environ.copy()
        env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{uid}")
        env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path=/run/user/{uid}/bus")
        p = subprocess.run(
            ["systemctl", "--user", "show", q["unit"], "--no-pager",
             "--property=LoadState,ActiveState,SubState,Result,ExecMainPID,ExecMainCode,ExecMainStatus,InvocationID,Description"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        props = {}
        for line in p.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1); props[k] = v
        # A --collect unit can disappear immediately after the runner exits.
        # Re-read the atomic exit record after querying systemd to close that race.
        terminal = read_terminal_status(request)
        if terminal is not None:
            return terminal
        started = read_owner_binding()
        nonce = request.get("launch_nonce")
        invocation = started.get("invocation_id")
        if not valid_owner(request, started, systemd=True):
            return {"state":"owner_unknown","reason":"frozen supervisor binding unavailable",
                    "status_authoritative":False,"automatic_retry":False}
        if props.get("LoadState") != "not-found" and (props.get("InvocationID") != invocation or
                props.get("Description") != f"Hepta Runtime job {q['job_id']} {nonce}"):
            return {"state":"owner_unknown","reason":"unit incarnation differs from frozen supervisor",
                    "status_authoritative":False,"automatic_retry":False}
        active = props.get("ActiveState")
        sub = props.get("SubState")
        if active in ("active", "activating") and sub not in ("exited", "dead"):
            try: matching = process_identity(started["supervisor_pid"]) == started["supervisor_identity"] and process_uid(started["supervisor_pid"]) == started["supervisor_uid"]
            except (OSError, ValueError, subprocess.SubprocessError): matching = False
            if not matching:
                return {"state":"owner_unknown","reason":"frozen supervisor PID/start/UID unavailable or changed",
                        "status_authoritative":False,"automatic_retry":False}
            state = "running"
        elif active == "failed":
            if requires_witness:
                return publication_pending("supervisor exited without a confirmed terminal receipt")
            state = "failed"
        elif active == "active" and sub == "exited":
            if requires_witness:
                return publication_pending("supervisor exited without a confirmed terminal receipt")
            # RemainAfterExit can become visible a few microseconds before the
            # supervisor's atomic exit.json rename. systemd already has the
            # authoritative process result, so use it rather than returning a
            # false completed_unknown race.
            try:
                exit_code = int(props.get("ExecMainStatus", "-1"))
            except ValueError:
                exit_code = -1
            if props.get("ExecMainCode") == "1":
                state = "succeeded" if exit_code == 0 else "failed"
                return {"state": state, "backend": "systemd", "exit_code": exit_code, "systemd": props}
            state = "completed_unknown"
        elif props.get("LoadState") == "not-found":
            if requires_witness:
                return publication_pending("supervisor disappeared without a confirmed terminal receipt")
            state = "finalizing"
        else:
            if requires_witness:
                return publication_pending("supervisor has no confirmed terminal receipt")
            state = active or "unknown"
        return {"state": state, "backend": "systemd", "systemd": props}
    started = read_owner_binding()
    if not valid_owner(request, started):
        return {"state":"owner_unknown","reason":"frozen supervisor binding unavailable",
                "status_authoritative":False,"automatic_retry":False}
    pid = started["supervisor_pid"]
    expected = started["supervisor_identity"]
    actual = process_identity(pid)
    running = bool(pid and actual is not None and (expected is not None and expected == actual))
    if not running and requires_witness:
        return publication_pending("supervisor disappeared without a confirmed terminal receipt")
    return {"state": "running" if running else "lost", "backend": launch.get("backend", "detached"), "pid": pid, "identity": actual}

deadline = time.monotonic() + min(float(q.get("wait_seconds", 0)), 30.0)
while True:
    status = one_status()
    state = status.get("state")
    transient = state in ("running", "activating", "finalizing", "completed_unknown")
    now = time.monotonic()
    if not transient or now >= deadline:
        if (now >= deadline and state in ("finalizing", "completed_unknown") and
                status.get("terminal_publication_confirmed") is not False):
            status["state"] = "lost"
            status["reason"] = "no exit record appeared before the wait deadline"
        status["job_id"] = q["job_id"]
        print(json.dumps(status, sort_keys=True))
        break
    time.sleep(0.1)
"#;

const READ_CODE: &str = r#"
import json, pathlib, sys
q = json.load(sys.stdin)
job = private_job_directory(q["job_dir"])
try:
    request = private_read_json("request.json")
except Exception:
    raise SystemExit("remote job metadata missing")
if request.get("job_id") != q["job_id"]:
    raise SystemExit("remote job metadata mismatch")
limit = max(1, min(int(q.get("limit", 16384)), 16384))

def read_part(name, offset):
    fd = private_open_job_file(name)
    offset = max(0, int(offset or 0))
    data = b""
    size = 0
    if fd is not None:
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            size = before.st_size
            if offset > size: raise SystemExit("cursor exceeds log length; refusing silent rewind")
            stream.seek(offset)
            data = stream.read(min(limit, size - offset))
            current = os.stat(name, dir_fd=_hepta_directory_pins[-1], follow_symlinks=False)
            after = os.fstat(stream.fileno())
            if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino) or after.st_nlink != 1 or after.st_size < size:
                raise SystemExit("remote log identity changed while reading")
    elif offset:
        raise SystemExit("cursor exceeds log length; refusing silent rewind")
    return {"offset": offset, "next_offset": offset + len(data), "size": size,
            "eof": offset + len(data) >= size, "text": data.decode("utf-8", errors="replace"),
            "bytes_hex": data.hex()}

print(json.dumps({
    "job_id": q["job_id"],
    "stdout": read_part("stdout.log", q.get("stdout_offset", 0)),
    "stderr": read_part("stderr.log", q.get("stderr_offset", 0)),
}, sort_keys=True))
"#;

const CANCEL_CODE: &str = r#"
import json, os, pathlib, signal, subprocess, sys, time
q = json.load(sys.stdin)
job = private_job_directory(q["job_dir"])

def read_json(name):
    return private_read_json(name)

def atomic(name, value):
    target = job / name
    tmp = job / (name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")
        stream.flush(); os.fsync(stream.fileno())
    os.replace(tmp, target)
    fd = os.open(job, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)

def process_identity(pid):
    if sys.platform == "linux":
        try:
            ticks = int(pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19])
            boot = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            return {"kind": "proc_start_ticks", "value": boot + ":" + str(ticks)} if boot else None
        except Exception:
            return None
    try:
        value = subprocess.check_output(["ps", "-p", str(pid), "-o", "lstart="], text=True, timeout=3).strip()
        return {"kind": "ps_lstart", "value": value} if value else None
    except Exception:
        return None

def valid_owner(request, started, systemd=False):
    nonce = request.get("launch_nonce")
    identity = started.get("supervisor_identity")
    return (isinstance(nonce, str) and len(nonce) == 32 and all(c in "0123456789abcdef" for c in nonce) and
        started.get("job_id") == request.get("job_id") and started.get("launch_nonce") == nonce and
        type(started.get("supervisor_uid")) is int and started["supervisor_uid"] == os.geteuid() and
        type(started.get("supervisor_pid")) is int and 1 < started["supervisor_pid"] <= 2147483647 and
        isinstance(identity, dict) and identity.get("kind") == ("proc_start_ticks" if sys.platform == "linux" else "ps_lstart") and
        isinstance(identity.get("value"), str) and bool(identity["value"]) and
        (not systemd or (isinstance(started.get("invocation_id"), str) and len(started["invocation_id"]) == 32 and
            all(c in "0123456789abcdef" for c in started["invocation_id"]))))

def process_uid(pid):
    if sys.platform == "linux": return pathlib.Path(f"/proc/{pid}").stat().st_uid
    return int(subprocess.check_output(["ps", "-p", str(pid), "-o", "uid="], text=True, timeout=3).strip())

request = read_json("request.json")
if not request or request.get("job_id") != q["job_id"]:
    raise SystemExit("remote job metadata missing or mismatched")
if read_json("exit.json"):
    print(json.dumps({"job_id": q["job_id"], "result": "already_exited"}))
    raise SystemExit(0)
launch = read_json("launch.json") or {}
started = read_json("started.json") or {}
nonce = request.get("launch_nonce")
pid = int(started.get("supervisor_pid") or 0)
expected = started.get("supervisor_identity")
expected_uid = started.get("supervisor_uid")
if not valid_owner(request, started, systemd=launch.get("backend") == "systemd"):
    raise SystemExit("frozen supervisor binding unavailable; no cancellation submitted")
# Never stop by a reusable unit name. This descriptor stays bound to the
# original supervisor even if its PID or systemd unit name is later recycled.
atomic_identity = sys.platform == "linux"
fd = None
try:
    if atomic_identity:
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise SystemExit("atomic supervisor signalling unavailable; no cancellation submitted")
        fd = os.pidfd_open(pid, 0)
    if process_identity(pid) != expected or process_uid(pid) != expected_uid:
        raise SystemExit("frozen supervisor identity or UID changed; no cancellation submitted")
    atomic("cancel-request.json", {"at_unix_ms": int(time.time() * 1000),
           "job_id": q["job_id"], "launch_nonce": nonce})
    if atomic_identity:
        signal.pidfd_send_signal(fd, signal.SIGTERM, None, 0)
    else:
        # macOS has no pidfd. Retain its explicitly non-atomic account scope.
        if process_identity(pid) != expected or process_uid(pid) != expected_uid:
            raise SystemExit("supervisor changed before best-effort signal")
        os.kill(pid, signal.SIGTERM)
    grace = max(0.0, min(float(q.get("grace_seconds", 10)), 30.0))
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if read_json("exit.json") or process_identity(pid) != expected:
            break
        time.sleep(.1)
    # The original runner owns workload termination, escalation and output
    # drain. Never force-kill a potentially recycled child group from here.
    result = "stop_requested" if launch.get("backend") == "systemd" else "term_sent"
    print(json.dumps({"job_id":q["job_id"],"result":result,
          "atomic_identity":atomic_identity,"supervisor_pid":pid,
          "termination_confirmed":False,"reconcile_via":"process_status"}, sort_keys=True))
finally:
    if fd is not None: os.close(fd)
"#;

fn validate_start(params: &ProcessStartParams) -> Result<()> {
	match params.idempotency_key.as_deref() {
		Some(key) if !key.trim().is_empty() && key.len() <= 256 => {}
		_ => bail!("idempotency_key is mandatory and must contain 1..256 nonblank bytes"),
	}
	check_execution(
		&params.host,
		&params.executable,
		&params.args,
		params.cwd.as_deref(),
		false,
	)?;
	check_environment(&params.host, &params.env)?;
	if params.args.len() > 256 {
		bail!("at most 256 arguments are allowed");
	}
	if params.env.len() > 128 {
		bail!("at most 128 environment variables are allowed");
	}
	for key in params.env.keys() {
		let valid = !key.is_empty()
			&& !key.as_bytes()[0].is_ascii_digit()
			&& key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
		if !valid {
			bail!("invalid environment variable name `{key}`");
		}
	}
	if params
		.stdin
		.as_ref()
		.is_some_and(|value| value.len() > MAX_STDIN_BYTES)
	{
		bail!("stdin exceeds the 1 MiB limit");
	}
	if params
		.timeout_seconds
		.is_some_and(|value| value == 0 || value > 604_800)
	{
		bail!("timeout_seconds must be between 1 and 604800");
	}
	if params.nice.is_some_and(|value| value > 19) {
		bail!("nice must be between 0 and 19");
	}
	if params
		.cpu_quota_percent
		.is_some_and(|value| value == 0 || value > 1000)
	{
		bail!("cpu_quota_percent must be between 1 and 1000");
	}
	if params
		.memory_max_bytes
		.is_some_and(|value| value < 16 * 1024 * 1024)
	{
		bail!("memory_max_bytes must be at least 16 MiB");
	}
	if params
		.idempotency_key
		.as_ref()
		.is_some_and(|value| value.is_empty() || value.len() > 256)
	{
		bail!("idempotency_key must contain 1..256 bytes");
	}
	Ok(())
}

fn verify_host_binding(
	record: &JobRecord,
	configured_target: &str,
	configured_state_dir: &str,
) -> Result<()> {
	let expected_job_dir = format!(
		"{}/jobs/{}",
		configured_state_dir.trim_end_matches('/'),
		record.id
	);
	if record.ssh_target != configured_target || record.remote_job_dir != expected_job_dir {
		bail!("durable job host binding changed; remote operation requires independent reconciliation");
	}
	Ok(())
}

fn check_binding(record: &JobRecord) -> Result<()> {
	let host = runtime_config()?.host(&record.host)?;
	verify_host_binding(record, &host.ssh_target, &host.remote_state_dir)?;
	if host.ssh_target != record.ssh_target || host.execution_mode != record.execution_mode {
		bail!("host binding changed; refusing to operate an old job");
	}
	Ok(())
}

async fn status_record(record: &JobRecord, wait_seconds: u64) -> Result<Value> {
	let config = runtime_config()?;
	let host = config.host(&record.host)?;
	check_binding(record)?;
	if record.system_jobctl {
		let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_seconds.min(30));
		loop {
			let value = run_jobctl(host, &json!({"op":"status","job_id":record.id})).await?;
			if value.get("state").and_then(Value::as_str) != Some("running")
				|| tokio::time::Instant::now() >= deadline
			{
				return Ok(value);
			}
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}
	let request = json!({
		"job_id": record.id,
		"job_dir": record.remote_job_dir,
		"request_digest": record.request_digest,
		"unit": record.unit,
		"wait_seconds": wait_seconds.min(30),
	});
	run_python_json(
		host,
		&bound_remote_code(STATUS_CODE)?,
		&request,
		Duration::from_secs(wait_seconds.min(30) + 10),
	)
	.await
}

/// Public observation routes opt in explicitly. Start/reuse reconciliation
/// continues to call the unchanged status_record above.
async fn status_observation(record: &JobRecord, wait_seconds: u64) -> Result<Value> {
	if !super::ssh::observation_pool_requested() {
		return status_record(record, wait_seconds).await;
	}
	check_binding(record)?;
	use super::ssh::{run_job_observation, JobObservation};
	if record.system_jobctl {
		let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_seconds.min(30));
		loop {
			let value = run_job_observation(
				&record.host,
				JobObservation::SystemStatus { job_id: &record.id },
			)
			.await?;
			if value.get("state").and_then(Value::as_str) != Some("running")
				|| tokio::time::Instant::now() >= deadline
			{
				return Ok(value);
			}
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}
	run_job_observation(
		&record.host,
		JobObservation::PythonStatus {
			job_id: &record.id,
			job_dir: &record.remote_job_dir,
			unit: &record.unit,
			request_digest: record
				.request_digest
				.as_deref()
				.context("legacy job has no full observation binding")?,
			wait_seconds,
		},
	)
	.await
}

fn operation_intent_unavailable() -> anyhow::Error {
	anyhow::anyhow!("Operation intent audit unavailable; no remote operation submitted")
}

fn require_operation_intent(outcome: Result<()>) -> Result<()> {
	outcome.map_err(|_| operation_intent_unavailable())
}

fn cancel_publication_slots() -> Arc<Semaphore> {
	CANCEL_PUBLICATIONS
		.get_or_init(|| Arc::new(Semaphore::new(MAX_CANCEL_PUBLICATIONS)))
		.clone()
}

async fn run_cancel_intent<O: Send + 'static>(
	prepared: PreparedAudit,
	slots: Arc<Semaphore>,
	ownership: O,
	append: impl FnOnce(PreparedAudit) -> Result<()> + Send + 'static,
) -> Result<(OwnedSemaphorePermit, O)> {
	let permit = slots
		.acquire_owned()
		.await
		.map_err(|_| operation_intent_unavailable())?;
	let result = tokio::task::spawn_blocking(move || {
		// The same reservation follows this already-owned cancellation from
		// durable intent through the remote response and completion audit.
		// Cancelling a waiter never admits another worker before this one ends.
		require_operation_intent(append(prepared))?;
		Ok((permit, ownership))
	})
	.await;
	match result {
		Ok(result) => result,
		Err(_) => Err(operation_intent_unavailable()),
	}
}

async fn complete_cancel_audit(
	output: Value,
	prepared: Result<PreparedAudit>,
	permit: OwnedSemaphorePermit,
	ownership: impl Send + 'static,
	append: impl FnOnce(PreparedAudit) -> Result<()> + Send + 'static,
) -> Value {
	let completion = match prepared {
		// Capacity was reserved before the remote cancellation. A received ACK
		// reaches the actual writer before the first cancellable suspension.
		Ok(prepared) => run_admitted_start_io(permit, ownership, move || append(prepared)).await,
		Err(error) => Err(error),
	};
	retain_result_after_audit(output, completion)
}

fn retain_result_after_audit(mut result: Value, outcome: Result<()>) -> Value {
	result["audit_recorded"] = json!(outcome.is_ok());
	if outcome.is_err() {
		result["audit_warning"] = json!(
			"Operation result retained; completion audit unavailable. Reconcile using the existing job_id."
		);
	}
	result
}

#[derive(Debug)]
struct LaunchOutcome {
	value: Value,
	local_record_pending: bool,
}

fn trusted_launch_ack(record: &JobRecord, value: &Value) -> bool {
	if value["ok"] != true {
		return false;
	}
	if record.system_jobctl && record.execution_mode == ExecutionMode::Isolated {
		return value["backend"] == "systemd_system"
			&& value
				.pointer("/status/job_id")
				.is_none_or(|id| id.as_str() == Some(&record.id));
	}
	match value["backend"].as_str() {
		Some("systemd") => value["unit"].as_str() == Some(&record.unit),
		Some("detached") => value["launcher_pid"]
			.as_u64()
			.is_some_and(|pid| pid > 0 && pid <= i32::MAX as u64),
		Some("completed" | "launch_failed") => value["reused_remote"] == true,
		_ => false,
	}
}

fn preserve_launch_outcome<F>(
	record: &mut JobRecord,
	outcome: Result<Value>,
	persist: F,
) -> LaunchOutcome
where
	F: FnOnce(&JobRecord) -> Result<()>,
{
	let value = match outcome {
		Ok(value) if trusted_launch_ack(record, &value) => {
			let remote_state = if record.system_jobctl
				&& record.execution_mode == ExecutionMode::Isolated
				&& value.get("reused_remote").and_then(Value::as_bool) == Some(true)
			{
				value
					.pointer("/status/launch_state")
					.and_then(Value::as_str)
					.filter(|state| {
						matches!(
							*state,
							"pending" | "launch_failed" | "launched" | "cancelled"
						)
					})
					.unwrap_or("launch_unknown")
			} else if value["backend"] == "launch_failed" {
				"launch_failed"
			} else {
				"launched"
			};
			record.launch_state = remote_state.to_string();
			record.launch_error = (remote_state == "launch_unknown")
				.then(|| "Remote launch state unavailable".to_string());
			value
		}
		Ok(_) | Err(_) => {
			// Invalid ACKs and transport failures cannot prove the supervisor did not launch.
			record.launch_state = "launch_unknown".to_string();
			record.launch_error = Some("Remote launch outcome unavailable".to_string());
			json!({
				"job_id":record.id,
				"state":"launch_unknown",
				"outcome":"unknown",
				"status_authoritative":false,
				"automatic_retry":false,
				"reconcile_via":"process_status"
			})
		}
	};
	LaunchOutcome {
		value,
		local_record_pending: persist(record).is_err(),
	}
}

async fn preserve_launch_outcome_async(
	record: &mut JobRecord,
	outcome: Result<Value>,
	permit: OwnedSemaphorePermit,
	ownership: impl Send + 'static,
	persist: impl FnOnce(&JobRecord) -> Result<()> + Send + 'static,
) -> LaunchOutcome {
	// The launch reserved capacity before submitting any remote effect. From
	// receiving its ACK to handing the original outcome and ownership to the
	// blocking worker there is no cancellable await, even when writers are busy.
	let mut retained = preserve_launch_outcome(record, outcome, |_| Ok(()));
	let publication = record.clone();
	retained.local_record_pending =
		run_admitted_start_io(permit, ownership, move || persist(&publication))
			.await
			.is_err();
	retained
}

fn attach_launch_record_warning(result: &mut Value, outcome: &LaunchOutcome) {
	result["local_record_pending"] = json!(outcome.local_record_pending);
	if outcome.local_record_pending {
		result["reconcile_warning"] = json!(
			"Remote launch outcome retained; local launch record update is pending. Use process_status with the existing job_id; do not create a new key."
		);
	}
}

fn reconcile_retry_allowed(record: &JobRecord) -> bool {
	if admit_observation_only_reuse(record).is_ok() {
		return false;
	}
	// The administrator-pinned jobctl first checks the same job ID and full
	// request digest. Operator helpers never relaunch an uncertain old record.
	record.system_jobctl
		&& record.execution_mode == ExecutionMode::Isolated
		&& matches!(record.launch_state.as_str(), "pending" | "launch_failed")
}

fn unavailable_status(job_id: &str) -> Value {
	json!({"job_id":job_id,"state":"status_unavailable","outcome":"unknown",
        "status_authoritative":false,"automatic_retry":false})
}

async fn read_reuse_status<G>(
	record: &JobRecord,
	retry: bool,
	start_guard: &mut Option<G>,
	read_status: impl Future<Output = Result<Value>>,
) -> Value {
	// A confirmed original launch needs only an observation. Keep uncertain
	// identities and launch reconciliation serialized, but do not make another
	// same-host start wait for this read-only SSH status roundtrip.
	if !retry && record.launch_state == "launched" {
		drop(start_guard.take());
	}
	read_status
		.await
		.unwrap_or_else(|_| unavailable_status(&record.id))
}

fn retain_cancel_outcome(job_id: &str, outcome: Result<Value>) -> Value {
	if let Ok(value) = outcome {
		if value["job_id"].as_str() == Some(job_id)
			&& value["result"].as_str().is_some_and(|result| {
				matches!(
					result,
					"already_exited" | "stop_requested" | "term_sent" | "kill_sent" | "not_running"
				)
			}) {
			// An acknowledgement requests or sends a signal; it is not terminal proof.
			let mut retained = json!({"job_id":job_id,"result":value["result"],"automatic_retry":false,
				"termination_confirmed":false,"reconcile_via":"process_status"});
			if value["atomic_identity"].is_boolean() {
				retained["atomic_identity"] = value["atomic_identity"].clone();
			}
			if value["supervisor_pid"]
				.as_u64()
				.is_some_and(|pid| pid > 1 && pid <= i32::MAX as u64)
			{
				retained["supervisor_pid"] = value["supervisor_pid"].clone();
			}
			return retained;
		}
	}
	json!({"job_id":job_id,"result":"cancel_unknown","outcome":"unknown",
		"status_authoritative":false,"automatic_retry":false,"termination_confirmed":false,
		"reconcile_via":"process_status"})
}

async fn launch_record(
	record: &mut JobRecord,
	params: &ProcessStartParams,
	guard: &Option<OwnedStartGuard>,
	owner: &Arc<super::effect_owner_fence::AdmissionPermit>,
) -> Result<LaunchOutcome> {
	launch_record_with_entry(record, params, guard, owner, || Ok(())).await
}

async fn launch_record_with_entry<F, G>(
	record: &mut JobRecord,
	params: &ProcessStartParams,
	guard: &Option<OwnedStartGuard>,
	owner: &Arc<super::effect_owner_fence::AdmissionPermit>,
	enter: F,
) -> Result<LaunchOutcome>
where
	F: FnOnce() -> Result<G> + Send + 'static,
	G: Send + 'static,
{
	let config = runtime_config()?;
	let host = config.host(&record.host)?;
	// These eight permits bound remote launches through outcome publication,
	// not observation RPCs or the independent pending/audit writer workers.
	// Waiting for SSH never consumes a blocking-pool thread.
	let publication_permit = start_outcome_slots()
		.acquire_owned()
		.await
		.map_err(|_| anyhow::anyhow!("job launch publication capacity unavailable"))?;
	let request = json!({
		"job_id": record.id,
		"job_dir": record.remote_job_dir,
		"request_digest": record.request_digest,
		"unit": record.unit,
		"request_fingerprint": record.request_digest.clone().unwrap_or_else(|| format!("{:016x}", record.request_fingerprint)),
		"platform": host.platform,
		"execution_mode": record.execution_mode,
		"executable": params.executable,
		"args": params.args,
		"cwd": params.cwd,
		"env": params.env,
		"stdin": params.stdin,
		"timeout_seconds": params.timeout_seconds,
		"nice": params.nice.unwrap_or(0),
		"cpu_quota_percent": params.cpu_quota_percent,
		"memory_max_bytes": params.memory_max_bytes,
		"allow_job_network": host.allow_job_network,
		"allow_detached_fallback": host.allow_detached_fallback,
	});
	let launch_result = if record.system_jobctl {
		run_jobctl_with_entry(
			host,
			&json!({
				"op":"start", "job_id":record.id, "executable":params.executable,
				"args":params.args, "cwd":params.cwd, "env":params.env, "stdin":params.stdin,
				"timeout_seconds":params.timeout_seconds, "nice":params.nice,
				"cpu_quota_percent":params.cpu_quota_percent, "memory_max_bytes":params.memory_max_bytes
			}),
			enter,
		)
		.await
	} else {
		run_python_json_with_entry(
			host,
			&private_remote_code(START_CODE)?,
			&request,
			Duration::from_secs(20),
			enter,
		)
		.await
	};
	Ok(preserve_launch_outcome_async(
		record,
		launch_result,
		publication_permit,
		(guard.clone(), owner.clone()),
		save_record,
	)
	.await)
}

/// The macOS operator helper uses a detached process backend. It cannot
/// enforce systemd CPUQuota/MemoryMax. Refuse a *new* unsupported request
/// before allocating a durable job identity, persisting launch intent or
/// contacting SSH; never silently drop the requested resource bounds.
fn validate_new_host_resource_limits(
	platform: Platform,
	params: &ProcessStartParams,
) -> Result<()> {
	if platform == Platform::Macos
		&& (params.cpu_quota_percent.is_some() || params.memory_max_bytes.is_some())
	{
		bail!(
            "macOS detached job backend cannot enforce requested CPU/memory limits;              no new job identity allocated or remote launch submitted"
        );
	}
	Ok(())
}

/// Observe an original request when its start acknowledgement (and job ID) was lost.
/// Absence is only a local-registry observation, never permission to replay an effect.
pub async fn observe_request(params: ProcessStartParams) -> Result<Option<String>> {
	// Revoking new execution must not prevent observing a previously admitted
	// request. Preserve its original identity, digest and physical binding.
	match params.idempotency_key.as_deref() {
		Some(key) if !key.trim().is_empty() && key.len() <= 256 => {}
		_ => bail!("request observation requires its original nonempty idempotency key"),
	}
	runtime_config()?.host(&params.host)?;
	let lane = start_lock(&params.host, params.idempotency_key.as_deref())?;
	let mut guard = Some(lane.lock().await);
	let key = params
		.idempotency_key
		.as_deref()
		.context("request observation requires its original idempotency key")?;
	let Some(existing) = find_idempotent_async(&params.host, key).await? else {
		return Ok(None);
	};
	let digest = request_digest(&params)?;
	if !matches_request(&existing, &digest)? {
		bail!("idempotency key `{key}` is already bound to a different request");
	}
	check_binding(&existing)?;
	// Even pending isolated/jobctl records are observation-only here. In
	// particular, do not use start_job's optional launch reconciliation path.
	let status = read_reuse_status(&existing, false, &mut guard, status_record(&existing, 0)).await;
	Ok(Some(serde_json::to_string_pretty(&json!({
		"observation_only": true,
		"reused": true,
		"retried_launch": false,
		"launch": null,
		"job": existing,
		"status": status,
	}))?))
}

pub async fn start_job(params: ProcessStartParams) -> Result<String> {
	start_job_with_policy(params, true, |_| Ok(())).await
}

/// Checked native entry never relaunches an existing uncertain binding. Only
/// a new job can consume this one-shot callback at the actual SSH spawn.
pub(crate) async fn start_job_with_entry<F, G>(
	params: ProcessStartParams,
	enter: F,
) -> Result<String>
where
	F: FnOnce(&ProcessStartParams) -> Result<G> + Send + 'static,
	G: Send + 'static,
{
	start_job_with_policy(params, false, enter).await
}

async fn start_job_with_policy<F, G>(
	params: ProcessStartParams,
	allow_reconcile_launch: bool,
	enter: F,
) -> Result<String>
where
	F: FnOnce(&ProcessStartParams) -> Result<G> + Send + 'static,
	G: Send + 'static,
{
	validate_start(&params)?;
	let lane = start_lock(&params.host, params.idempotency_key.as_deref())?;
	let mut start_guard = Some(Arc::new(lane.lock_owned().await));
	// Cross-process owner fence: retain the shared admission lock from
	// idempotency lookup through durable intent, launch and response.
	let _owner_admission = super::effect_owner_fence::admit_new_effect().await?;
	let owner_admission = Arc::new(_owner_admission);
	// The freshly promoted controller must not relaunch a process_start key
	// previously accepted by V4. Perform the private predecessor lookup while
	// the shared epoch-bound admission lock is held, BEFORE any new job ID or
	// launch intent is allocated. Unknown/corrupt old history fails closed.
	if owner_admission.has_predecessor_state() {
		let replay_owner = owner_admission.clone();
		let replay_host = params.host.clone();
		let replay_key = params.idempotency_key.clone();
		start_io(&start_guard, &owner_admission, move || {
			replay_owner.require_new_process_identity(&replay_host, replay_key.as_deref())
		})
		.await?;
	}
	// Serialize and hash the full binding once, including potentially large stdin.
	// Both reuse checks and new metadata retain this same complete SHA256 value.
	let digest = request_digest(&params)?;
	let request_fingerprint = fingerprint(&digest);
	if let Some(key) = params.idempotency_key.as_deref() {
		if let Some(mut existing) = find_idempotent_async(&params.host, key).await? {
			if !matches_request(&existing, &digest)? {
				bail!("idempotency key `{key}` is already bound to a different request");
			}
			check_binding(&existing)?;
			let retry = allow_reconcile_launch && reconcile_retry_allowed(&existing);
			let launch = if retry {
				require_operation_intent(
					start_audit(
						"process_start_reconcile_intent",
						&params.host,
						&existing.id,
						&json!({"phase":"intent","remote_operation_submitted":false}),
						&start_guard,
						&owner_admission,
					)
					.await,
				)?;
				Some(launch_record(&mut existing, &params, &start_guard, &owner_admission).await?)
			} else {
				None
			};
			let status = read_reuse_status(
				&existing,
				retry,
				&mut start_guard,
				status_record(&existing, 0),
			)
			.await;
			let mut result = json!({
				"reused": true,
				"retried_launch": retry,
				"job": existing,
				"launch": launch.as_ref().map(|outcome| &outcome.value),
				"status": status,
			});
			if let Some(outcome) = &launch {
				attach_launch_record_warning(&mut result, outcome);
			}
			let completion = start_audit(
				"process_start_reused",
				&params.host,
				&existing.id,
				&json!({"phase":"result","reused":true,"retried_launch":retry}),
				&start_guard,
				&owner_admission,
			)
			.await;
			let result = retain_result_after_audit(result, completion);
			return Ok(serde_json::to_string_pretty(&result)?);
		}
	}

	let config = runtime_config()?;
	let host = config.host(&params.host)?;
	validate_new_host_resource_limits(host.platform, &params)?;
	let id = next_job_id();
	let unit = format!("hepta-runtime-job-{id}");
	let remote_job_dir = format!("{}/jobs/{id}", host.remote_state_dir.trim_end_matches('/'));
	let mut record = JobRecord {
		system_jobctl: host.platform == Platform::Linux
			&& host.execution_mode == ExecutionMode::Isolated,
		execution_mode: host.execution_mode,
		id: id.clone(),
		host: params.host.clone(),
		ssh_target: host.ssh_target.clone(),
		unit,
		remote_job_dir,
		executable: params.executable.clone(),
		args: params.args.clone(),
		cwd: params.cwd.clone(),
		env_keys: params.env.keys().cloned().collect(),
		created_unix_ms: now_ms(),
		idempotency_key: params.idempotency_key.clone(),
		request_fingerprint,
		request_digest: Some(digest),
		launch_state: "pending".to_string(),
		launch_error: None,
	};
	// Persist identity before remote launch. Later calls reconcile this same
	// host, job ID and request binding; never invent a second remote job.
	publish_pending_record(&record, &start_guard, &owner_admission).await?;
	// The independent SSH owner can outlive this request future. Carry the
	// exact binding into its final entry; do not consume the grant while queued.
	// Share the owned binding rather than copying up to 1 MiB of admitted stdin.
	let params = Arc::new(params);
	let entry_params = params.clone();
	let launch = launch_record_with_entry(
		&mut record,
		&params,
		&start_guard,
		&owner_admission,
		move || enter(&entry_params),
	)
	.await?;
	let mut result = json!({"reused": false, "job": record, "launch": launch.value});
	attach_launch_record_warning(&mut result, &launch);
	let completion = start_audit(
		"process_start",
		&params.host,
		&id,
		&json!({"phase":"result","launch_state":record.launch_state}),
		&start_guard,
		&owner_admission,
	)
	.await;
	let result = retain_result_after_audit(result, completion);
	Ok(serde_json::to_string_pretty(&result)?)
}

pub async fn status_job(params: ProcessRefParams) -> Result<String> {
	let record = check_ref(&params)?;
	let status = status_observation(&record, 0).await?;
	let completion = observation_completion_audit(
		"process_status",
		&params.host,
		&params.job_id,
		&json!({"phase":"observation","ok":true}),
	)
	.await;
	Ok(serde_json::to_string_pretty(
		&retain_observation_after_audit(status, completion, &record.host, &record.id),
	)?)
}

pub async fn wait_job(params: ProcessWaitParams) -> Result<String> {
	let reference = ProcessRefParams {
		host: params.host.clone(),
		job_id: params.job_id.clone(),
	};
	let record = check_ref(&reference)?;
	let wait = params.timeout_seconds.unwrap_or(10).min(30);
	let status = status_observation(&record, wait).await?;
	let completion = observation_completion_audit(
		"process_wait",
		&params.host,
		&params.job_id,
		&json!({"phase":"observation","ok":true}),
	)
	.await;
	Ok(serde_json::to_string_pretty(
		&retain_observation_after_audit(status, completion, &record.host, &record.id),
	)?)
}

pub async fn read_job(params: ProcessReadParams) -> Result<String> {
	let reference = ProcessRefParams {
		host: params.host.clone(),
		job_id: params.job_id.clone(),
	};
	let record = check_ref(&reference)?;
	let host = runtime_config()?.host(&record.host)?;
	let request = json!({
		"job_id": record.id,
		"job_dir": record.remote_job_dir,
		"request_digest": record.request_digest,
		"unit": record.unit,
		"stdout_offset": params.stdout_offset.unwrap_or(0),
		"stderr_offset": params.stderr_offset.unwrap_or(0),
		"limit": params.limit.unwrap_or(65_536).min(MAX_LOG_READ_BYTES),
	});
	let output: Value = if super::ssh::observation_pool_requested() {
		use super::ssh::{run_job_observation, JobObservation};
		let observation = if record.system_jobctl {
			JobObservation::SystemRead {
				job_id: &record.id,
				stdout_offset: params.stdout_offset.unwrap_or(0),
				stderr_offset: params.stderr_offset.unwrap_or(0),
				limit: params.limit.unwrap_or(16384),
			}
		} else {
			JobObservation::PythonRead {
				job_id: &record.id,
				job_dir: &record.remote_job_dir,
				unit: &record.unit,
				request_digest: record
					.request_digest
					.as_deref()
					.context("legacy job has no full observation binding")?,
				stdout_offset: params.stdout_offset.unwrap_or(0),
				stderr_offset: params.stderr_offset.unwrap_or(0),
				limit: params.limit.unwrap_or(65_536).min(MAX_LOG_READ_BYTES),
			}
		};
		run_job_observation(&record.host, observation).await?
	} else if record.system_jobctl {
		run_jobctl(host, &json!({"op":"read","job_id":record.id,
            "stdout_offset":params.stdout_offset.unwrap_or(0),"stderr_offset":params.stderr_offset.unwrap_or(0),"limit":params.limit.unwrap_or(16384)})).await?
	} else {
		run_python_json(
			host,
			&bound_remote_code(READ_CODE)?,
			&request,
			Duration::from_secs(15),
		)
		.await?
	};
	let completion = observation_completion_audit(
		"process_read",
		&params.host,
		&params.job_id,
		&json!({"phase":"observation","ok": true}),
	)
	.await;
	Ok(serde_json::to_string_pretty(
		&retain_observation_after_audit(output, completion, &record.host, &record.id),
	)?)
}

fn retain_observation_after_audit(
	mut result: Value,
	outcome: Result<()>,
	host: &str,
	job_id: &str,
) -> Value {
	if !result.is_object() {
		return json!({"host":host,"job_id":job_id,"result":"invalid_remote_observation","outcome":"unknown","automatic_retry":false,"audit_recorded":outcome.is_ok(),"reconcile_warning":"Existing job observation was not a trusted object. No new job was launched."});
	}
	result["audit_recorded"] = json!(outcome.is_ok());
	if outcome.is_err() {
		result["audit_warning"] =
			json!("Existing job observation retained; audit unavailable. No new job was launched.");
	}
	result
}

pub async fn cancel_job(params: ProcessCancelParams) -> Result<String> {
	let reference = ProcessRefParams {
		host: params.host.clone(),
		job_id: params.job_id.clone(),
	};
	// Cancellation continues an existing identity even when new effects are
	// fenced off. Carry that verified binding, without acquiring a new owner.
	let record = Arc::new(check_ref(&reference)?);
	let host = runtime_config()?.host(&record.host)?;
	let request = json!({
		"job_id": record.id,
		"job_dir": record.remote_job_dir,
		"request_digest": record.request_digest,
		"unit": record.unit,
		"grace_seconds": params.grace_seconds.unwrap_or(10).min(30),
	});
	let intent = prepare_audit(
		"process_cancel_intent",
		&params.host,
		&params.job_id,
		&json!({"phase":"intent","remote_operation_submitted":false}),
	)
	.map_err(|_| operation_intent_unavailable())?;
	let (publication_permit, record) =
		run_cancel_intent(intent, cancel_publication_slots(), record, append_audit).await?;
	let remote = if record.system_jobctl {
		run_jobctl(host, &json!({"op":"cancel","job_id":record.id})).await
	} else {
		run_python_json(
			host,
			&bound_remote_code(CANCEL_CODE)?,
			&request,
			Duration::from_secs(45),
		)
		.await
	};
	let output = retain_cancel_outcome(&params.job_id, remote);
	let completion = prepare_audit(
		"process_cancel",
		&params.host,
		&params.job_id,
		&json!({"phase":"result","outcome_unknown":output["outcome"]=="unknown"}),
	);
	let output =
		complete_cancel_audit(output, completion, publication_permit, record, append_audit).await;
	Ok(serde_json::to_string_pretty(&output)?)
}

pub fn list_jobs(params: ProcessListParams) -> Result<String> {
	if let Some(host) = params.host.as_deref() {
		runtime_config()?.host(host)?;
	}
	let rows = list_job_rows_in(&jobs_dir()?, params.host.as_deref())?;
	job_inventory_rows_response(&rows)
}

/// The old unpaginated API remains unchanged; this API never silently truncates it.
pub fn list_jobs_page(params: ProcessListPageParams) -> Result<String> {
	if let Some(host) = params.host.as_deref() {
		runtime_config()?.host(host)?;
	}
	let rows = inventory_page_rows_at(
		&runtime_config()?.state_dir,
		params.host.as_deref(),
		InventoryLimits::default(),
	)?;
	let root = runtime_config()?.state_dir.to_string_lossy();
	page_job_rows(&rows, &params, &root)
}

// Retain the original public field types until the complete source scan has
// passed every final fence. This drops private args/paths per record without
// serializing unselected records or changing whole-source error ordering.
struct InventoryRow {
	id: String,
	host: String,
	created_unix_ms: u128,
	execution_mode: ExecutionMode,
	launch_state: String,
}

fn list_job_rows_in(dir: &Path, host: Option<&str>) -> Result<Vec<InventoryRow>> {
	let mut rows = Vec::new();
	let mut bytes = Vec::new();
	for entry in std::fs::read_dir(dir)? {
		let entry = entry?;
		let path = entry.path();
		if path.extension().and_then(|value| value.to_str()) != Some("json") {
			continue;
		}
		let expected_id = path
			.file_stem()
			.and_then(|stem| stem.to_str())
			.ok_or_else(|| {
				anyhow::anyhow!("invalid durable job record name: {}", path.display())
			})?;
		// Keep the complete compatibility read before filtering. A corrupt or
		// unsafe neighbor must still refuse the inventory, even after an earlier
		// row would exceed the wire budget. Only public fields survive this step.
		let record = read_record_at_with_buffer(&path, expected_id, &mut bytes)?;
		if host.is_none_or(|host| record.host == host) {
			rows.push(InventoryRow {
				id: record.id,
				host: record.host,
				created_unix_ms: record.created_unix_ms,
				execution_mode: record.execution_mode,
				launch_state: record.launch_state,
			});
		}
	}
	// Stable sorting preserves encounter order for tied timestamps, as with
	// the previous full-record sort followed by filtering. Defer JSON conversion
	// until every source has passed so unselected wide timestamps stay inert.
	rows.sort_by_key(|record| record.created_unix_ms);
	Ok(rows)
}

fn inventory_page_rows_at(
	root: &Path,
	host: Option<&str>,
	limits: InventoryLimits,
) -> Result<Vec<Value>> {
	let records = inventory_projected_at(root, limits, |record| InventoryRow {
		id: record.id,
		host: record.host,
		created_unix_ms: record.created_unix_ms,
		execution_mode: record.execution_mode,
		launch_state: record.launch_state,
	})?;
	let mut rows: Vec<Value> = records
		.into_iter()
		.filter(|record| host.is_none_or(|host| record.host == host))
		.map(|record| {
			json!({"id":record.id,"host":record.host,"created_unix_ms":record.created_unix_ms,
			"execution_mode":record.execution_mode,"launch_state":record.launch_state})
		})
		.collect();
	rows.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
	Ok(rows)
}

#[derive(Clone, Copy)]
struct InventoryLimits {
	records: usize,
	bytes: u64,
	record_bytes: u64,
	time: Duration,
}

impl Default for InventoryLimits {
	fn default() -> Self {
		Self {
			records: 65_536,
			bytes: 128 * 1024 * 1024,
			record_bytes: 4 * 1024 * 1024 + 64 * 1024,
			time: Duration::from_secs(5),
		}
	}
}

#[cfg(all(test, unix))]
fn inventory_records_at(root: &Path, limits: InventoryLimits) -> Result<Vec<JobRecord>> {
	inventory_projected_at(root, limits, |record| record)
}

#[cfg(unix)]
fn inventory_projected_at<T>(
	root: &Path,
	limits: InventoryLimits,
	mut project: impl FnMut(JobRecord) -> T,
) -> Result<Vec<T>> {
	use std::fs::{File, Metadata};
	use std::io::Read;
	use std::os::fd::{AsRawFd, FromRawFd};
	use std::os::unix::fs::MetadataExt;
	use std::time::Instant;
	let started = Instant::now();
	let deadline = || -> Result<()> {
		if started.elapsed() >= limits.time {
			bail!("durable inventory source time budget exceeded; no partial inventory returned");
		}
		Ok(())
	};
	fn open_at(base: Option<&File>, component: &str, flags: i32) -> Result<File> {
		let name = std::ffi::CString::new(component)?;
		let fd = unsafe {
			libc::openat(
				base.map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd),
				name.as_ptr(),
				flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
			)
		};
		if fd < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		Ok(unsafe { File::from_raw_fd(fd) })
	}
	fn open_root(root: &std::path::Path) -> Result<File> {
		let raw = root
			.to_str()
			.ok_or_else(|| anyhow::anyhow!("inventory root must be UTF-8"))?;
		if !root.is_absolute() || raw.split('/').any(|part| matches!(part, "." | "..")) {
			bail!("inventory root must be an explicit absolute path");
		}
		let mut base = open_at(None, "/", libc::O_RDONLY | libc::O_DIRECTORY)?;
		for part in raw.split('/').filter(|part| !part.is_empty()) {
			base = open_at(Some(&base), part, libc::O_RDONLY | libc::O_DIRECTORY)?;
		}
		let info = base.metadata()?;
		if info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o077 != 0 {
			bail!("durable inventory root must be private and account-owned");
		}
		Ok(base)
	}
	fn stamp(info: &Metadata) -> (u64, u64, u32, u32, u64, u64, i64, i64, i64, i64) {
		(
			info.dev(),
			info.ino(),
			info.uid(),
			info.mode(),
			info.nlink(),
			info.len(),
			info.mtime(),
			info.mtime_nsec(),
			info.ctime(),
			info.ctime_nsec(),
		)
	}
	fn directory_identity(info: &Metadata) -> (u64, u64, u32, u32) {
		(info.dev(), info.ino(), info.uid(), info.mode())
	}
	fn entries(
		base: &File,
		maximum: usize,
		check: &impl Fn() -> Result<()>,
	) -> Result<Vec<String>> {
		// A new file description keeps repeated membership scans independent.
		let scan = open_at(Some(base), ".", libc::O_RDONLY | libc::O_DIRECTORY)?;
		let fd = unsafe { libc::dup(scan.as_raw_fd()) };
		if fd < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		let pointer = unsafe { libc::fdopendir(fd) };
		if pointer.is_null() {
			unsafe { libc::close(fd) };
			return Err(std::io::Error::last_os_error().into());
		}
		struct Stream(*mut libc::DIR);
		impl Drop for Stream {
			fn drop(&mut self) {
				unsafe { libc::closedir(self.0) };
			}
		}
		let stream = Stream(pointer);
		let mut names = Vec::new();
		loop {
			check()?;
			#[cfg(target_os = "linux")]
			let error = unsafe { libc::__errno_location() };
			#[cfg(target_os = "macos")]
			let error = unsafe { libc::__error() };
			#[cfg(not(any(target_os = "linux", target_os = "macos")))]
			{
				bail!("bounded inventory directory scans require Linux or macOS");
			}
			#[cfg(any(target_os = "linux", target_os = "macos"))]
			{
				unsafe { *error = 0 };
				let item = unsafe { libc::readdir(stream.0) };
				if item.is_null() {
					if unsafe { *error } != 0 {
						return Err(std::io::Error::last_os_error().into());
					}
					break;
				}
				let value =
					unsafe { std::ffi::CStr::from_ptr((*item).d_name.as_ptr()) }.to_str()?;
				if matches!(value, "." | "..") {
					continue;
				}
				if names.len() >= maximum.saturating_add(32) {
					bail!("durable inventory source entry bound exceeded");
				}
				names.push(value.to_owned());
			}
		}
		names.sort();
		Ok(names
			.into_iter()
			.filter(|name| name.ends_with(".json"))
			.collect())
	}
	let rootfd = open_root(root)?;
	let root_identity = directory_identity(&rootfd.metadata()?);
	let base = open_at(Some(&rootfd), "jobs", libc::O_RDONLY | libc::O_DIRECTORY)?;
	let base_metadata = base.metadata()?;
	if base_metadata.uid() != unsafe { libc::geteuid() } || base_metadata.mode() & 0o022 != 0 {
		bail!("durable inventory directory must be account-owned and non-writable by others");
	}
	let base_identity = directory_identity(&base_metadata);
	let names = entries(&base, limits.records, &deadline)?;
	if names.len() > limits.records {
		bail!("durable inventory source row bound exceeded");
	}
	let mut records = Vec::with_capacity(names.len());
	let mut stamps = Vec::with_capacity(names.len());
	let mut bytes = 0u64;
	for name in &names {
		deadline()?;
		let id = name
			.strip_suffix(".json")
			.ok_or_else(|| anyhow::anyhow!("invalid inventory identity"))?;
		if !valid_name(id) {
			bail!("invalid durable inventory identity");
		}
		let mut file = open_at(Some(&base), name, libc::O_RDONLY)?;
		let before = file.metadata()?;
		if !before.is_file()
			|| before.uid() != unsafe { libc::geteuid() }
			|| before.mode() & 0o7777 != 0o600
			|| before.nlink() != 1
			|| before.len() == 0
			|| before.len() > limits.record_bytes
		{
			bail!("durable inventory metadata inode or byte bound refused");
		}
		bytes = bytes
			.checked_add(before.len())
			.ok_or_else(|| anyhow::anyhow!("durable inventory byte overflow"))?;
		if bytes > limits.bytes {
			bail!("durable inventory total source byte bound exceeded");
		}
		let mut raw = Vec::with_capacity(before.len() as usize);
		Read::by_ref(&mut file)
			.take(before.len() + 1)
			.read_to_end(&mut raw)?;
		deadline()?;
		if raw.len() as u64 != before.len() || stamp(&before) != stamp(&file.metadata()?) {
			bail!("durable inventory metadata changed during observation");
		}
		let record: JobRecord =
			serde_json::from_slice(&raw).context("corrupt durable inventory metadata")?;
		if record.id != id || !valid_name(&record.host) {
			bail!("durable inventory record identity mismatch");
		}
		stamps.push(stamp(&before));
		records.push(project(record));
	}
	if entries(&base, limits.records, &deadline)? != names {
		bail!("durable inventory membership changed");
	}
	for (name, before) in names.iter().zip(stamps) {
		deadline()?;
		let current = open_at(Some(&base), name, libc::O_RDONLY)?;
		if stamp(&current.metadata()?) != before {
			bail!("durable inventory metadata changed");
		}
	}
	let held_base = open_at(Some(&rootfd), "jobs", libc::O_RDONLY | libc::O_DIRECTORY)?;
	if directory_identity(&held_base.metadata()?) != base_identity
		|| directory_identity(&base.metadata()?) != base_identity
		|| directory_identity(&rootfd.metadata()?) != root_identity
		|| directory_identity(&open_root(root)?.metadata()?) != root_identity
	{
		bail!("durable inventory root or directory changed");
	}
	deadline()?;
	Ok(records)
}

#[cfg(not(unix))]
fn inventory_projected_at<T>(
	_root: &Path,
	_limits: InventoryLimits,
	_project: impl FnMut(JobRecord) -> T,
) -> Result<Vec<T>> {
	bail!("bounded durable inventory requires Unix descriptor support")
}

fn page_job_rows(
	rows: &[Value],
	params: &ProcessListPageParams,
	namespace: &str,
) -> Result<String> {
	let limit = params.limit.unwrap_or(128) as usize;
	if !(1..=128).contains(&limit)
		|| params
			.cursor
			.as_ref()
			.is_some_and(|cursor| cursor.len() > 256)
	{
		bail!("invalid durable job inventory page");
	}
	let binding =
		serde_json::to_vec(&json!({"namespace":namespace,"host":params.host,"rows":rows}))?;
	let fingerprint = Sha256::digest(&binding)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect::<String>();
	let start = match params.cursor.as_deref() {
		None => 0,
		Some(cursor) => {
			let (digest, id) = cursor
				.split_once(':')
				.ok_or_else(|| anyhow::anyhow!("invalid inventory cursor"))?;
			if digest != fingerprint {
				bail!("durable job inventory changed; restart from the first page");
			}
			rows.iter()
				.position(|row| row["id"].as_str() == Some(id))
				.ok_or_else(|| anyhow::anyhow!("inventory cursor unavailable"))?
				+ 1
		}
	};
	let mut end = (start + limit).min(rows.len());
	loop {
		let more = end < rows.len();
		let next = if more {
			Some(format!(
				"{}:{}",
				fingerprint,
				rows[end - 1]["id"].as_str().unwrap_or_default()
			))
		} else {
			None
		};
		let value = json!({"jobs":&rows[start..end],"total":rows.len(),"next_cursor":next,
			"has_more":more,"inventory_complete":!more,"snapshot_sha256":fingerprint,
			"status_authoritative":false,"snapshot_semantics":"registry_metadata_at_observation"});
		let text = serde_json::to_string(&value)?;
		let wire = rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(
			text.clone(),
		)]);
		if serde_json::to_vec(&wire)?.len() <= 64 * 1024 {
			return Ok(text);
		}
		if end <= start + 1 {
			bail!("one durable job identity exceeds the inventory page budget");
		}
		end -= 1;
	}
}

fn job_inventory_rows_response(records: &[InventoryRow]) -> Result<String> {
	const MAX_INVENTORY_WIRE_BYTES: usize = 1024 * 1024;
	let jobs: Vec<Value> = records
		.iter()
		.map(|record| {
			json!({
				"id":record.id,"host":record.host,"created_unix_ms":record.created_unix_ms,
				"execution_mode":record.execution_mode,"launch_state":record.launch_state,
			})
		})
		.collect();
	let text = serde_json::to_string(&json!({"jobs":jobs,"total":records.len(),
		"inventory_complete":true,"status_authoritative":false}))?;
	let wire = serde_json::to_vec(&rmcp::model::CallToolResult::success(vec![
		rmcp::model::ContentBlock::text(text.clone()),
	]))?;
	if wire.len() > MAX_INVENTORY_WIRE_BYTES {
		bail!(
			"Durable job inventory exceeds the 1 MiB response budget; narrow using the configured host filter. No partial inventory returned."
		);
	}
	Ok(text)
}

#[cfg(test)]
fn job_inventory_response(records: &[JobRecord]) -> Result<String> {
	const MAX_INVENTORY_WIRE_BYTES: usize = 1024 * 1024;
	let jobs: Vec<Value> = records
		.iter()
		.map(|record| {
			json!({
				"id":record.id,"host":record.host,"created_unix_ms":record.created_unix_ms,
				"execution_mode":record.execution_mode,"launch_state":record.launch_state,
			})
		})
		.collect();
	let text = serde_json::to_string(&json!({"jobs":jobs,"total":records.len(),
		"inventory_complete":true,"status_authoritative":false}))?;
	let wire = serde_json::to_vec(&rmcp::model::CallToolResult::success(vec![
		rmcp::model::ContentBlock::text(text.clone()),
	]))?;
	if wire.len() > MAX_INVENTORY_WIRE_BYTES {
		bail!(
			"Durable job inventory exceeds the 1 MiB response budget; narrow using the configured host filter. No partial inventory returned."
		);
	}
	Ok(text)
}

#[cfg(test)]
#[path = "jobs_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "jobs_inventory_streaming_tests.rs"]
mod inventory_streaming_tests;

#[cfg(test)]
#[path = "jobs_pagination_tests.rs"]
mod pagination_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "jobs_output_durability_tests.rs"]
mod output_durability_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "jobs_staging_durability_tests.rs"]
mod staging_durability_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "jobs_terminal_publication_tests.rs"]
mod terminal_publication_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "jobs_owner_metadata_tests.rs"]
mod owner_metadata_tests;

#[cfg(test)]
#[path = "jobs_security_tests.rs"]
mod security_tests;

#[cfg(all(test, unix))]
#[path = "jobs_registry_content_tests.rs"]
mod registry_content_tests;

#[cfg(test)]
#[path = "jobs_registry_async_tests.rs"]
mod registry_async_tests;

#[cfg(test)]
#[path = "jobs_start_io_tests.rs"]
mod start_io_tests;

#[cfg(test)]
#[path = "jobs_cancel_io_tests.rs"]
mod cancel_io_tests;

#[cfg(all(test, unix))]
#[path = "jobs_registry_coalescing_tests.rs"]
mod registry_coalescing_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "jobs_registry_prefill_tests.rs"]
mod registry_prefill_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "jobs_observe_request_tests.rs"]
mod observe_request_tests;

#[cfg(all(test, unix))]
#[path = "jobs_registry_concurrency_bench.rs"]
mod registry_concurrency_bench;

#[cfg(all(test, target_os = "linux"))]
#[path = "jobs_record_comparison_tests.rs"]
mod record_comparison_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "jobs_record_read_bench.rs"]
mod record_read_bench;
