//! Local, authenticated KV2 import into an existing stopped native-file owner.
//! This command has its own single bounded offline lifetime. It changes neither
//! an HTTP deadline nor a token's lifetime, and never creates a mount or actor.
use super::{FileWitness, SeedError, hex, private_directory, target_parts, valid_hash};
use crate::configuration::NativeStorageProfile;
use crate::engines::kv2_native_large::{MAX_BUNDLE_BYTES, PATH};
use crate::service::{
    ExternalEffectResult, RequestExecution, Response, Service, ServiceRequest, erase_json,
    token_precision, v6_records,
};
use crate::v6_native_custody::OriginalDeadline;
use heptabao_filesystem_guard::open_absolute_directory_no_symlinks;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const DEFAULT_OFFLINE_IMPORT_SECONDS: u64 = 300;
pub const MAX_OFFLINE_IMPORT_SECONDS: u64 = 360;
const MAX_CREDENTIAL_BYTES: u64 = 16 * 1024;
const BUFFER_BYTES: usize = 64 * 1024;

/// Credentials are private files, never command-line secret values. The shares
/// file is a JSON array containing exactly the existing Shamir threshold; the
/// token file contains one existing root token with an optional final newline.
pub struct OfflineKv2Import<'a> {
    pub data_dir: &'a Path,
    pub audit_path: &'a Path,
    pub shares_path: &'a Path,
    pub token_path: &'a Path,
    pub bundle_path: &'a Path,
    pub mount: &'a str,
    pub bundle_sha256: &'a str,
    pub budget_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineImportError {
    InvalidInput,
    UnsafeOwner,
    InputChanged,
    DigestMismatch,
    CredentialRejected,
    TargetRejected,
    Deadline,
    RequestRejected(u16),
    OutcomeUnknown,
}
impl std::fmt::Display for OfflineImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput => f.write_str("invalid offline native KV2 import input"),
            Self::UnsafeOwner => f.write_str("offline native KV2 requires private descriptor custody"),
            Self::InputChanged => f.write_str("offline native KV2 input bytes or ownership changed"),
            Self::DigestMismatch => f.write_str("offline native KV2 bundle digest mismatch"),
            Self::CredentialRejected => f.write_str("offline native KV2 credential rejected"),
            Self::TargetRejected => f.write_str("offline native KV2 requires an existing stopped native-file target"),
            Self::Deadline => f.write_str("offline native KV2 original operation deadline expired"),
            Self::RequestRejected(status) => write!(f, "offline native KV2 request rejected with status {status}"),
            Self::OutcomeUnknown => f.write_str("offline native KV2 may have committed; reopen authoritative storage and reconcile; do not blindly retry"),
        }
    }
}
impl std::error::Error for OfflineImportError {}
impl From<SeedError> for OfflineImportError {
    fn from(error: SeedError) -> Self {
        match error {
            SeedError::InvalidInput | SeedError::UnsupportedPlatform => Self::InvalidInput,
            SeedError::SourceChanged => Self::InputChanged,
            SeedError::OutcomeUnknown => Self::OutcomeUnknown,
            _ => Self::UnsafeOwner,
        }
    }
}

/// No token, share, plaintext, mount path or filesystem path is serialized.
/// Offline completion is not a claim about HTTP latency or an HA cohort.
#[derive(Serialize)]
pub struct OfflineImportReceipt {
    schema: u32,
    operation: &'static str,
    bundle_sha256: String,
    bundle_bytes: u64,
    budget_seconds: u64,
    elapsed_millis: u128,
    committed_root_identity: String,
    committed_root_sha256: String,
    committed_generation: u64,
    replay_epoch: u64,
    cold_root_identity: String,
    cold_root_sha256: String,
    cold_generation: u64,
    original_inputs_unchanged: bool,
    complete_cold_graph_verified: bool,
    cold_auth_clock_advance_verified: bool,
    http_latency_qualified: bool,
    ha_qualified: bool,
}

fn live(deadline: OriginalDeadline) -> Result<(), OfflineImportError> {
    deadline.check().map_err(|_| OfflineImportError::Deadline)
}

struct TargetDirectory {
    path: PathBuf,
    handle: File,
    identity: (u64, u64),
}
impl TargetDirectory {
    fn open(path: &Path) -> Result<Self, OfflineImportError> {
        let handle = open_absolute_directory_no_symlinks(path)
            .map_err(|_| OfflineImportError::UnsafeOwner)?;
        let metadata = handle
            .metadata()
            .map_err(|_| OfflineImportError::UnsafeOwner)?;
        if !private_directory(&metadata) {
            return Err(OfflineImportError::UnsafeOwner);
        }
        Ok(Self {
            path: path.to_owned(),
            handle,
            identity: (metadata.dev(), metadata.ino()),
        })
    }
    fn check(&self, deadline: OriginalDeadline) -> Result<(), OfflineImportError> {
        live(deadline)?;
        let named = open_absolute_directory_no_symlinks(&self.path)
            .map_err(|_| OfflineImportError::UnsafeOwner)?;
        for file in [&self.handle, &named] {
            let metadata = file
                .metadata()
                .map_err(|_| OfflineImportError::UnsafeOwner)?;
            if !private_directory(&metadata) || (metadata.dev(), metadata.ino()) != self.identity {
                return Err(OfflineImportError::UnsafeOwner);
            }
        }
        live(deadline)
    }
}

// All bytes are read through the original fd. A separately opened fd is used
// only to verify that the original name still denotes that same private inode.
struct PinnedInput {
    parent: TargetDirectory,
    leaf: String,
    file: File,
    witness: FileWitness,
    bound: u64,
    deadline: OriginalDeadline,
    consumed: Option<(Sha256, u64)>,
}
impl PinnedInput {
    fn open(
        path: &Path,
        bound: u64,
        deadline: OriginalDeadline,
    ) -> Result<Self, OfflineImportError> {
        use rustix::fs::{Mode, OFlags, openat};
        live(deadline)?;
        let (parent_path, leaf) = target_parts(path)?;
        let parent = TargetDirectory::open(parent_path)?;
        let file = File::from(
            openat(
                &parent.handle,
                leaf,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| OfflineImportError::UnsafeOwner)?,
        );
        let witness = FileWitness::capture(&file, bound)?;
        if witness.bytes == 0 {
            return Err(OfflineImportError::InvalidInput);
        }
        let input = Self {
            parent,
            leaf: leaf.to_owned(),
            file,
            witness,
            bound,
            deadline,
            consumed: None,
        };
        input.check()?;
        Ok(input)
    }
    fn check(&self) -> Result<(), OfflineImportError> {
        use rustix::fs::{Mode, OFlags, openat};
        live(self.deadline)?;
        self.parent.check(self.deadline)?;
        self.witness
            .check(&self.file, self.bound)
            .map_err(|_| OfflineImportError::InputChanged)?;
        let named = File::from(
            openat(
                &self.parent.handle,
                self.leaf.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| OfflineImportError::InputChanged)?,
        );
        self.witness
            .check(&named, self.bound)
            .map_err(|_| OfflineImportError::InputChanged)?;
        live(self.deadline)
    }
    fn rewind(&mut self) -> Result<(), OfflineImportError> {
        self.check()?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| OfflineImportError::InputChanged)?;
        self.check()
    }
    fn small(&mut self) -> Result<Zeroizing<Vec<u8>>, OfflineImportError> {
        self.rewind()?;
        let length =
            usize::try_from(self.witness.bytes).map_err(|_| OfflineImportError::InvalidInput)?;
        let mut bytes = Zeroizing::new(vec![0; length]);
        self.read_exact(&mut bytes)
            .map_err(|_| self.read_failure())?;
        self.check()?;
        Ok(bytes)
    }
    fn digest(&mut self) -> Result<String, OfflineImportError> {
        self.rewind()?;
        let mut left = self.witness.bytes;
        let mut buffer = Zeroizing::new([0u8; BUFFER_BYTES]);
        let mut digest = Sha256::new();
        while left != 0 {
            let count = left.min(BUFFER_BYTES as u64) as usize;
            self.read_exact(&mut buffer[..count])
                .map_err(|_| self.read_failure())?;
            digest.update(&buffer[..count]);
            left -= count as u64;
        }
        self.check()?;
        Ok(hex(digest.finalize().as_ref()))
    }
    fn start_consuming(&mut self) -> Result<(), OfflineImportError> {
        self.rewind()?;
        self.consumed = Some((Sha256::new(), 0));
        Ok(())
    }
    fn consumed_exactly(&self, expected: &str) -> Result<(), OfflineImportError> {
        self.check()?;
        let (hash, bytes) = self
            .consumed
            .as_ref()
            .ok_or(OfflineImportError::InputChanged)?;
        if *bytes != self.witness.bytes || hex(hash.clone().finalize().as_ref()) != expected {
            return Err(OfflineImportError::DigestMismatch);
        }
        Ok(())
    }
    fn read_failure(&self) -> OfflineImportError {
        if live(self.deadline).is_err() {
            OfflineImportError::Deadline
        } else {
            OfflineImportError::InputChanged
        }
    }
}
impl Read for PinnedInput {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let failure = |error: OfflineImportError| {
            io::Error::new(
                if error == OfflineImportError::Deadline {
                    io::ErrorKind::TimedOut
                } else {
                    io::ErrorKind::Other
                },
                "offline native input custody rejected",
            )
        };
        self.check().map_err(failure)?;
        let count = self.file.read(output)?;
        if let Some((digest, bytes)) = self.consumed.as_mut() {
            digest.update(&output[..count]);
            *bytes = bytes
                .checked_add(count as u64)
                .ok_or_else(|| failure(OfflineImportError::InputChanged))?;
            if *bytes > self.witness.bytes {
                return Err(failure(OfflineImportError::InputChanged));
            }
        }
        self.check().map_err(failure)?;
        Ok(count)
    }
}

fn budget(options: &OfflineKv2Import<'_>) -> Result<u64, OfflineImportError> {
    let seconds = options
        .budget_seconds
        .unwrap_or(DEFAULT_OFFLINE_IMPORT_SECONDS);
    if seconds == 0
        || seconds > MAX_OFFLINE_IMPORT_SECONDS
        || !valid_hash(options.bundle_sha256)
        || options.mount.is_empty()
        || options.mount.len() > 1024
        || options.mount.contains('\0')
        || !options.data_dir.is_absolute()
        || !options.audit_path.is_absolute()
        || options.audit_path.starts_with(options.data_dir)
        || options.shares_path == options.token_path
        || options.shares_path == options.bundle_path
        || options.token_path == options.bundle_path
        || [options.shares_path, options.token_path, options.bundle_path]
            .iter()
            .any(|path| *path == options.audit_path || path.starts_with(options.data_dir))
    {
        return Err(OfflineImportError::InvalidInput);
    }
    Ok(seconds)
}

fn reject_response(service: &Service, response: &mut Response) -> OfflineImportError {
    let unknown = service.recovery_required
        || response
            .body
            .get("recovery_required")
            .and_then(serde_json::Value::as_bool)
            == Some(true);
    let status = response.status;
    erase_json(&mut response.body);
    if unknown {
        OfflineImportError::OutcomeUnknown
    } else {
        OfflineImportError::RequestRejected(status)
    }
}

fn open_unsealed(
    options: &OfflineKv2Import<'_>,
    shares: &[String],
    target: &TargetDirectory,
    deadline: OriginalDeadline,
    expected_cold: Option<token_precision::offline::Checkpoint>,
) -> Result<(Service, bool), OfflineImportError> {
    target.check(deadline)?;
    let mut service = Service::new(options.data_dir.to_owned(), options.audit_path)
        .map_err(|_| OfflineImportError::TargetRejected)?;
    let seal = service
        .seal
        .as_ref()
        .ok_or(OfflineImportError::TargetRejected)?;
    if shares.len() != usize::from(seal.secret_threshold) || shares.is_empty() || seal.is_wrapper()
    {
        return Err(OfflineImportError::CredentialRejected);
    }
    service
        .configure_native_v6_storage(NativeStorageProfile::File)
        .map_err(|_| OfflineImportError::TargetRejected)?;
    let clock_observation = expected_cold
        .map(|checkpoint| token_precision::offline::Scope::enter(&service, checkpoint))
        .transpose()
        .map_err(|_| OfflineImportError::TargetRejected)?;
    for share in shares {
        target.check(deadline)?;
        let mut response = service.handle("POST", "sys/unseal", "", "", json!({"key":share}));
        if response.status != 200 {
            return Err(reject_response(&service, &mut response));
        }
        erase_json(&mut response.body);
        target.check(deadline)?;
    }
    if service.ha.is_some()
        || service.recovery_required
        || service.audit_failed
        || service
            .native_root
            .as_ref()
            .is_none_or(|root| root.reader_floor.native_kv2_format != 2)
        || service.state.is_none()
        || service.barrier_key.is_none()
    {
        return Err(OfflineImportError::TargetRejected);
    }
    // Unseal has acquired FileBackend's actual exclusive writer fence. This is
    // the original backend owner; a path or JSON receipt cannot grant that lock.
    service
        .durable
        .as_mut()
        .ok_or(OfflineImportError::TargetRejected)?
        .verify_live_ownership()
        .map_err(|_| OfflineImportError::TargetRejected)?;
    target.check(deadline)?;
    let clock_advanced = if let Some(observation) = clock_observation {
        observation
            .finish(&service)
            .map_err(|_| OfflineImportError::TargetRejected)?
    } else {
        false
    };
    Ok((service, clock_advanced))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    BundleVerified,
    GraphPrepared,
    Committed,
    RawColdVerified,
}

/// A distinct finite offline operation. There is no HTTP flag, replacement
/// actor, synthetic clock, new mount, reset or retry path in this interface.
pub fn import_kv2(
    options: OfflineKv2Import<'_>,
) -> Result<OfflineImportReceipt, OfflineImportError> {
    let seconds = budget(&options)?;
    if crate::request_deadline::current().is_some() {
        return Err(OfflineImportError::InvalidInput);
    }
    let started = Instant::now();
    let until = started
        .checked_add(Duration::from_secs(seconds))
        .ok_or(OfflineImportError::InvalidInput)?;
    import_before(options, started, until, |_| {})
}

// The private observer only exercises real before/after boundaries in unit
// tests. Production supplies an empty closure; it cannot supply results,
// authority, a deadline, an actor, a graph, a receipt or a durable backend.
fn import_before(
    options: OfflineKv2Import<'_>,
    started: Instant,
    until: Instant,
    mut observe: impl FnMut(Phase),
) -> Result<OfflineImportReceipt, OfflineImportError> {
    let seconds = budget(&options)?;
    if crate::request_deadline::current().is_some() {
        return Err(OfflineImportError::InvalidInput);
    }
    let _scope = crate::request_deadline::RequestDeadlineScope::enter(until);
    let deadline = OriginalDeadline::capture().map_err(|_| OfflineImportError::Deadline)?;
    let target = TargetDirectory::open(options.data_dir)?;
    let mut bundle = PinnedInput::open(options.bundle_path, MAX_BUNDLE_BYTES as u64, deadline)?;
    let mut shares_input = PinnedInput::open(options.shares_path, MAX_CREDENTIAL_BYTES, deadline)?;
    let mut token_input = PinnedInput::open(options.token_path, MAX_CREDENTIAL_BYTES, deadline)?;
    if bundle.digest()? != options.bundle_sha256 {
        return Err(OfflineImportError::DigestMismatch);
    }
    let shares_bytes = shares_input.small()?;
    let shares: Vec<String> = serde_json::from_slice(&shares_bytes)
        .map_err(|_| OfflineImportError::CredentialRejected)?;
    let shares = Zeroizing::new(shares);
    if shares.is_empty()
        || shares.len() > 255
        || shares.iter().any(|key| key.is_empty() || key.len() > 1024)
    {
        return Err(OfflineImportError::CredentialRejected);
    }
    drop(shares_bytes);
    let token_bytes = token_input.small()?;
    let token =
        std::str::from_utf8(&token_bytes).map_err(|_| OfflineImportError::CredentialRejected)?;
    let token = Zeroizing::new(token.trim_end_matches(['\r', '\n']).to_owned());
    if token.is_empty()
        || token.len() > 4096
        || token.chars().any(char::is_whitespace)
        || token.contains('\0')
    {
        return Err(OfflineImportError::CredentialRejected);
    }
    drop(token_bytes);
    observe(Phase::BundleVerified);
    let inputs_live = |bundle: &PinnedInput| {
        target.check(deadline)?;
        bundle.check()?;
        shares_input.check()?;
        token_input.check()?;
        live(deadline)
    };
    inputs_live(&bundle)?;
    let (mut service, _) = open_unsealed(&options, &shares, &target, deadline, None)?;
    inputs_live(&bundle)?;
    let mut lookup = service.handle("GET", "auth/token/lookup-self", "", &token, json!({}));
    if lookup.status != 200 {
        return Err(reject_response(&service, &mut lookup));
    }
    let is_root = lookup
        .body
        .get("data")
        .and_then(|data| data.get("policies"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|policies| {
            policies
                .iter()
                .any(|policy| policy.as_str() == Some("root"))
        });
    erase_json(&mut lookup.body);
    if !is_root {
        return Err(OfflineImportError::CredentialRejected);
    }
    inputs_live(&bundle)?;
    bundle.start_consuming()?;
    let mut pending = match service.begin_native_kv2_large_before(
        ServiceRequest::new("POST", PATH, "", &token, json!({"mount":options.mount})),
        until,
    ) {
        RequestExecution::External(pending) => pending,
        RequestExecution::Complete(mut response) => {
            return Err(reject_response(&service, &mut response));
        }
    };
    let mut result = pending.execute_native_kv2_large_transfer(&mut bundle);
    observe(Phase::GraphPrepared);
    let input_result =
        inputs_live(&bundle).and_then(|()| bundle.consumed_exactly(options.bundle_sha256));
    if input_result.is_err() {
        // Still finish the admitted request's original audit/negative outcome;
        // no prepared object is admitted when the actual input binding failed.
        result = ExternalEffectResult::NativeKv2Large(Err(Response::error(
            400,
            "offline input custody rejected",
        )));
    }
    let mut response = service.finish_external_request(*pending, result);
    if response.status != 204 {
        let rejection = reject_response(&service, &mut response);
        return Err(if rejection == OfflineImportError::OutcomeUnknown {
            rejection
        } else {
            input_result.err().unwrap_or(rejection)
        });
    }
    erase_json(&mut response.body);
    // Publication succeeded. Any subsequent failure is an uncertain delivery,
    // never permission to retry the pristine-target import automatically.
    let completed = (|| -> Result<OfflineImportReceipt, OfflineImportError> {
        input_result?;
        observe(Phase::Committed);
        inputs_live(&bundle)?;
        let identity = service
            .current_state_identity()
            .map_err(|_| OfflineImportError::TargetRejected)?;
        let expected_checkpoint = (
            identity,
            service
                .external_effect_generation()
                .map_err(|_| OfflineImportError::TargetRejected)?,
        );
        let root = service
            .native_root
            .as_ref()
            .ok_or(OfflineImportError::TargetRejected)?
            .clone();
        let root_bytes = root
            .encode()
            .map_err(|_| OfflineImportError::TargetRejected)?;
        let key = Zeroizing::new(
            **service
                .barrier_key
                .as_ref()
                .ok_or(OfflineImportError::TargetRejected)?,
        );
        let durable = service
            .durable
            .as_ref()
            .ok_or(OfflineImportError::TargetRejected)?;
        let generation = durable.generation();
        let replay_epoch = durable.replay_epoch();
        drop(service);
        // Coldly authenticate exact persisted bytes before ordinary unseal can
        // legitimately append its terminal Auth observation. No raw state write
        // is issued here and the key never leaves zeroizing process memory.
        target.check(deadline)?;
        let mut raw = heptabao_durable_service::DurableService::reopen(
            options.data_dir,
            crate::crypto::AeadBarrier::new(*key)
                .map_err(|_| OfflineImportError::TargetRejected)?,
            crate::service::MAX_OPERATIONS,
        )
        .map_err(|_| OfflineImportError::TargetRejected)?;
        drop(key);
        if raw.generation() != generation
            || raw.replay_epoch() != replay_epoch
            || raw
                .get("system", "state")
                .map_err(|_| OfflineImportError::TargetRejected)?
                .is_none_or(|bytes| bytes.expose() != root_bytes.as_slice())
        {
            return Err(OfflineImportError::TargetRejected);
        }
        v6_records::verify_durable_native_candidate(&root, &mut raw, deadline, &mut || {
            inputs_live(&bundle).map_err(|_| heptabao_durable_service::ServiceError::BarrierFailure)
        })
        .map_err(|_| OfflineImportError::TargetRejected)?;
        raw.verify_live_ownership()
            .map_err(|_| OfflineImportError::TargetRejected)?;
        raw.close()
            .map_err(|_| OfflineImportError::TargetRejected)?;
        observe(Phase::RawColdVerified);
        inputs_live(&bundle)?;
        // These are real lock release/reacquire boundaries. The private,
        // affine receipt admits only this actual Service owner's one clock
        // self-write from the exact cold checkpoint; any intervening writer,
        // multiple transition or unexplained Auth change refuses delivery.
        let (mut cold, clock_advanced) = open_unsealed(
            &options,
            &shares,
            &target,
            deadline,
            Some(expected_checkpoint),
        )?;
        let cold_root = cold
            .native_root
            .as_ref()
            .ok_or(OfflineImportError::TargetRejected)?
            .clone();
        let mut non_auth = cold_root.clone();
        for owner in &mut non_auth.owners {
            if owner.domain == crate::state_record_root_v6::OwnerDomain::Auth {
                *owner = root
                    .owners
                    .iter()
                    .find(|prior| prior.domain == owner.domain)
                    .ok_or(OfflineImportError::TargetRejected)?
                    .clone();
            }
        }
        if non_auth
            .encode()
            .map_err(|_| OfflineImportError::TargetRejected)?
            .as_slice()
            != root_bytes.as_slice()
        {
            return Err(OfflineImportError::TargetRejected);
        }
        let durable = cold
            .durable
            .as_mut()
            .ok_or(OfflineImportError::TargetRejected)?;
        v6_records::verify_durable_native_candidate(&cold_root, durable, deadline, &mut || {
            inputs_live(&bundle).map_err(|_| heptabao_durable_service::ServiceError::BarrierFailure)
        })
        .map_err(|_| OfflineImportError::TargetRejected)?;
        inputs_live(&bundle)?;
        durable
            .verify_live_ownership()
            .map_err(|_| OfflineImportError::TargetRejected)?;
        live(deadline)?;
        let cold_identity = cold_root
            .identity()
            .map_err(|_| OfflineImportError::TargetRejected)?;
        let cold_bytes = cold_root
            .encode()
            .map_err(|_| OfflineImportError::TargetRejected)?;
        Ok(OfflineImportReceipt {
            schema: 1,
            operation: "offline-native-import",
            bundle_sha256: options.bundle_sha256.to_owned(),
            bundle_bytes: bundle.witness.bytes,
            budget_seconds: seconds,
            elapsed_millis: started.elapsed().as_millis(),
            committed_root_identity: hex(&identity.digest()),
            committed_root_sha256: hex(Sha256::digest(root_bytes.as_slice()).as_ref()),
            committed_generation: generation,
            replay_epoch,
            cold_root_identity: hex(&cold_identity.digest()),
            cold_root_sha256: hex(Sha256::digest(cold_bytes.as_slice()).as_ref()),
            cold_generation: durable.generation(),
            original_inputs_unchanged: true,
            complete_cold_graph_verified: true,
            cold_auth_clock_advance_verified: clock_advanced,
            http_latency_qualified: false,
            ha_qualified: false,
        })
    })();
    completed.map_err(|_| OfflineImportError::OutcomeUnknown)
}

#[cfg(test)]
#[path = "service_native_seed_import_tests.rs"]
mod tests;

#[cfg(feature = "native-v6-ha")]
#[path = "service_native_seed_ha_import.rs"]
mod ha_import;
#[cfg(feature = "native-v6-ha")]
pub use ha_import::{HaImportError, HaImportReceipt, HaKv2Import, import_kv2_ha};
