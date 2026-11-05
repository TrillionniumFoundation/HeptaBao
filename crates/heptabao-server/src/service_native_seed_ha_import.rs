//! A finite maintenance import through the real enrolled native Raft owner.
//!
//! The other voters must already be running in the isolated cohort. This
//! operation starts only this node's ordinary mTLS peer listener, acquires its
//! real Raft/file fences, authenticates supplied Shamir shares and the existing
//! root token, and invokes the unchanged native-large writer once. It creates
//! neither an HTTP listener nor a caller-authored cursor, root or quorum proof.
//! The operation's separate maintenance budget never changes an HTTP budget.
use super::{
    DEFAULT_OFFLINE_IMPORT_SECONDS, MAX_CREDENTIAL_BYTES, MAX_OFFLINE_IMPORT_SECONDS,
    OfflineImportError, OfflineKv2Import, PinnedInput, TargetDirectory, budget as file_budget, hex,
    live, reject_response, valid_hash,
};
use crate::configuration::{self, NativeStorageProfile, StorageConfig};
use crate::engines::kv2_native_large::{MAX_BUNDLE_BYTES, PATH};
use crate::ha::{HaProcess, HaProcessConfig};
use crate::request_deadline::{HaLock, RequestDeadlineScope};
use crate::service::{
    ExternalEffectResult, RequestExecution, Response, Service, ServiceRequest, erase_json,
    v6_records,
};
use crate::v6_native_custody::OriginalDeadline;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const CONFIG_BYTES: u64 = 65_536;
const PEER_CREDENTIAL_BYTES: u64 = 512 * 1024;
const READINESS_SECONDS: u64 = 8;

/// All inputs are existing absolute private files. The server and HA configs
/// are the ordinary deployment schemas, with formal `native_v6_raft` storage.
/// This operation does not create a seed, mount, membership or root principal.
pub struct HaKv2Import<'a> {
    pub server_config_path: &'a Path,
    pub ha_config_path: &'a Path,
    pub shares_path: &'a Path,
    pub token_path: &'a Path,
    pub bundle_path: &'a Path,
    pub mount: &'a str,
    pub bundle_sha256: &'a str,
    pub budget_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HaImportError {
    InvalidInput,
    UnsafeOwner,
    InputChanged,
    DigestMismatch,
    CredentialRejected,
    ConfigurationRejected,
    TargetRejected,
    QuorumUnavailable,
    Deadline,
    RequestRejected(u16),
    OwnerShutdown,
    OutcomeUnknown,
}
impl From<OfflineImportError> for HaImportError {
    fn from(error: OfflineImportError) -> Self {
        match error {
            OfflineImportError::InvalidInput => Self::InvalidInput,
            OfflineImportError::UnsafeOwner => Self::UnsafeOwner,
            OfflineImportError::InputChanged => Self::InputChanged,
            OfflineImportError::DigestMismatch => Self::DigestMismatch,
            OfflineImportError::CredentialRejected => Self::CredentialRejected,
            OfflineImportError::TargetRejected => Self::TargetRejected,
            OfflineImportError::Deadline => Self::Deadline,
            OfflineImportError::RequestRejected(status) => Self::RequestRejected(status),
            OfflineImportError::OutcomeUnknown => Self::OutcomeUnknown,
        }
    }
}
impl std::fmt::Display for HaImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput => f.write_str("invalid native HA maintenance import input"),
            Self::UnsafeOwner => f.write_str("native HA maintenance import requires private descriptor custody"),
            Self::InputChanged => f.write_str("native HA maintenance import input or owner changed"),
            Self::DigestMismatch => f.write_str("native HA maintenance import bundle digest mismatch"),
            Self::CredentialRejected => f.write_str("native HA maintenance import credential rejected"),
            Self::ConfigurationRejected => f.write_str("native HA maintenance import requires matching formal enrolled Raft configuration"),
            Self::TargetRejected => f.write_str("native HA maintenance import target or authenticated graph rejected"),
            Self::QuorumUnavailable => f.write_str("native HA maintenance import could not obtain its original bounded quorum observation"),
            Self::Deadline => f.write_str("native HA maintenance import original operation deadline expired"),
            Self::RequestRejected(status) => write!(f, "native HA maintenance import request rejected with status {status}; earlier authenticated activation may have completed"),
            Self::OwnerShutdown => f.write_str("native HA maintenance import did not observe complete original owner shutdown"),
            Self::OutcomeUnknown => f.write_str("native HA maintenance import may have committed; reconcile the actual quorum and cold storage without blind replay"),
        }
    }
}
impl std::error::Error for HaImportError {}

/// This is observed maintenance evidence, not authority or general HA/HTTP
/// qualification. It contains no token, share, path, plaintext or cluster ID.
#[derive(Serialize)]
pub struct HaImportReceipt {
    schema: u32,
    operation: &'static str,
    server_config_sha256: String,
    ha_config_sha256: String,
    bundle_sha256: String,
    bundle_bytes: u64,
    budget_seconds: u64,
    elapsed_millis: u128,
    local_node_id: u64,
    voters: BTreeSet<u64>,
    activation_performed: bool,
    committed_root_identity: String,
    committed_root_sha256: String,
    local_generation: u64,
    replay_epoch: u64,
    native_generation: u64,
    publication_log_index: u64,
    first_owner_peer_workers_joined: usize,
    cold_owner_peer_workers_joined: usize,
    original_inputs_unchanged: bool,
    complete_cold_graph_verified: bool,
    cold_root_and_local_generation_exact: bool,
    cold_quorum_readindex_verified: bool,
    cold_selection_exact: bool,
    real_native_writer_used: bool,
    imported_once: bool,
    http_listener_started: bool,
    http_latency_qualified: bool,
    physical_failover_qualified: bool,
    full_replacement_qualified: bool,
}

fn seconds(options: &HaKv2Import<'_>) -> Result<u64, HaImportError> {
    let seconds = options
        .budget_seconds
        .unwrap_or(DEFAULT_OFFLINE_IMPORT_SECONDS);
    let paths = [
        options.server_config_path,
        options.ha_config_path,
        options.shares_path,
        options.token_path,
        options.bundle_path,
    ];
    if seconds == 0
        || seconds > MAX_OFFLINE_IMPORT_SECONDS
        || !valid_hash(options.bundle_sha256)
        || options.mount.is_empty()
        || options.mount.len() > 1024
        || options.mount.contains('\0')
        || paths.iter().any(|path| !path.is_absolute())
        || paths
            .iter()
            .enumerate()
            .any(|(i, path)| paths[..i].contains(path))
    {
        return Err(HaImportError::InvalidInput);
    }
    Ok(seconds)
}

fn validate_configuration(
    options: &HaKv2Import<'_>,
    config: &crate::http::Config,
    ha: &HaProcessConfig,
) -> Result<(), HaImportError> {
    configuration::validate_storage(config, Some(ha))
        .map_err(|_| HaImportError::ConfigurationRejected)?;
    if !matches!(
        config.storage.as_ref(),
        Some(StorageConfig::NativeV6Raft { .. })
    ) || config.audit_http_url.is_some()
        || config.audit_socket.is_some()
        || config.audit_syslog.is_some()
        || !config.outbound_endpoints.is_empty()
    {
        // No configured mandatory collector is silently dropped by a local
        // maintenance command. Provider exclusions remain the formal profile's.
        return Err(HaImportError::ConfigurationRejected);
    }
    file_budget(&OfflineKv2Import {
        data_dir: &config.data_dir,
        audit_path: &config.audit_file,
        shares_path: options.shares_path,
        token_path: options.token_path,
        bundle_path: options.bundle_path,
        mount: options.mount,
        bundle_sha256: options.bundle_sha256,
        budget_seconds: options.budget_seconds,
    })?;
    let inputs = [
        options.server_config_path,
        options.ha_config_path,
        options.shares_path,
        options.token_path,
        options.bundle_path,
        ha.ca_file.as_path(),
        ha.cert_file.as_path(),
        ha.key_file.as_path(),
        ha.replication_key_file.as_path(),
    ];
    if inputs.iter().any(|path| {
        *path == config.audit_file
            || path.starts_with(&config.data_dir)
            || path.starts_with(&ha.raft_dir)
    }) || config.audit_file.starts_with(&ha.raft_dir)
        || ha.raft_dir.starts_with(&config.data_dir)
        || config.data_dir.starts_with(&ha.raft_dir)
    {
        return Err(HaImportError::ConfigurationRejected);
    }
    Ok(())
}

// Own the exact Service and process references. No forward handler retaining
// Service is registered; all release paths close the local durable owner before
// joining the original peer workers and waiting for the actual Raft shutdown.
struct Owner {
    service: Option<Service>,
    process: Option<Arc<Mutex<HaProcess>>>,
}
impl Owner {
    fn start(config: &crate::http::Config, ha: &HaProcessConfig) -> Result<Self, HaImportError> {
        let process = HaProcess::start_with_storage(ha.clone(), config)
            .map_err(|_| HaImportError::TargetRejected)?;
        configuration::validate_storage_running(config, &process)
            .map_err(|_| HaImportError::ConfigurationRejected)?;
        let process = Arc::new(Mutex::new(process));
        let mut owner = Self {
            service: None,
            process: Some(Arc::clone(&process)),
        };
        let mut service = Service::new_with_ha_audit_config(
            config.data_dir.clone(),
            &config.audit_file,
            process,
            config.audit,
        )
        .map_err(|_| HaImportError::TargetRejected)?;
        service
            .configure_native_v6_storage(NativeStorageProfile::Raft)
            .map_err(|_| HaImportError::ConfigurationRejected)?;
        owner.service = Some(service);
        Ok(owner)
    }
    fn service(&mut self) -> Result<&mut Service, HaImportError> {
        self.service.as_mut().ok_or(HaImportError::TargetRejected)
    }
    fn process(&self) -> Result<&Arc<Mutex<HaProcess>>, HaImportError> {
        self.process.as_ref().ok_or(HaImportError::TargetRejected)
    }
    fn close(&mut self) -> Result<usize, HaImportError> {
        let mut service = self.service.take();
        let durable_closed = service
            .as_mut()
            .and_then(|service| service.durable.take())
            .map(|durable| durable.close())
            .transpose()
            .is_ok();
        drop(service);
        let Some(process) = self.process.take() else {
            return Ok(0);
        };
        let process = Arc::try_unwrap(process).map_err(|_| HaImportError::OwnerShutdown)?;
        let process = process
            .into_inner()
            .map_err(|_| HaImportError::OwnerShutdown)?;
        let joined = process
            .close_owned_native()
            .map_err(|_| HaImportError::OwnerShutdown)?;
        if !durable_closed {
            return Err(HaImportError::OwnerShutdown);
        }
        Ok(joined)
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn wait_leader(
    owner: &Owner,
    voters: &BTreeSet<u64>,
    deadline: OriginalDeadline,
) -> Result<(), HaImportError> {
    let until = deadline
        .instant()
        .min(Instant::now() + Duration::from_secs(READINESS_SECONDS));
    let _scope = RequestDeadlineScope::enter(until);
    let mut ready_since = None;
    while Instant::now() < until {
        let ready = {
            let process = owner
                .process()?
                .lock_for_request()
                .map_err(|_| HaImportError::QuorumUnavailable)?;
            if !process.bootstrap_ready() || !process.is_leader().unwrap_or(false) {
                false
            } else if let (Ok(role), Ok(membership)) =
                (process.leader_status(), process.membership())
            {
                let fresh_peers = membership
                    .voters
                    .iter()
                    .filter(|id| **id != role.local_id)
                    .filter(|id| {
                        membership
                            .peer_contact_ms
                            .get(id)
                            .is_some_and(|age| age.is_some_and(|age| age <= 400))
                            && membership.peer_matched.get(id).is_some_and(|matched| {
                                matched.is_some_and(|matched| {
                                    role.committed_index
                                        .is_some_and(|committed| matched >= committed)
                                })
                            })
                    })
                    .count();
                role.local_is_leader
                    && role.leader == Some(role.local_id)
                    && membership.committed
                    && !membership.joint
                    && membership.term == role.term
                    && membership.voters == *voters
                    && fresh_peers >= voters.len() / 2
                    && role.committed_index.is_some_and(|committed| {
                        role.applied_index
                            .is_some_and(|applied| applied >= committed)
                    })
            } else {
                false
            }
        };
        if ready {
            let since = ready_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= Duration::from_millis(250) && Instant::now() < until {
                return Ok(());
            }
        } else {
            ready_since = None;
        }
        let pause = until
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(20));
        std::thread::sleep(pause);
    }
    Err(HaImportError::QuorumUnavailable)
}

// Pure comparison data, never an HA capability. Each construction below first
// obtains and verifies a fresh opaque read from the actual current HaProcess.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Selection {
    root: [u8; 32],
    generation: u64,
    publication: u64,
}
fn selection(owner: &Owner, deadline: OriginalDeadline) -> Result<Selection, HaImportError> {
    live(deadline)?;
    let process = owner
        .process()?
        .lock_for_request()
        .map_err(|_| HaImportError::QuorumUnavailable)?;
    let read = process
        .native_v6_committed_read(deadline)
        .map_err(|_| HaImportError::QuorumUnavailable)?
        .ok_or(HaImportError::TargetRejected)?;
    process
        .verify_native_v6_committed_read(&read)
        .map_err(|_| HaImportError::QuorumUnavailable)?;
    let result = Selection {
        root: read.published().root_digest(),
        generation: read.published().generation(),
        publication: read.published().publication_log_id().index,
    };
    live(deadline)?;
    Ok(result)
}
fn wait_cold_selection(
    owner: &Owner,
    expected: Selection,
    deadline: OriginalDeadline,
) -> Result<(), HaImportError> {
    let until = deadline
        .instant()
        .min(Instant::now() + Duration::from_secs(READINESS_SECONDS));
    let _scope = RequestDeadlineScope::enter(until);
    let original = OriginalDeadline::capture().map_err(|_| HaImportError::Deadline)?;
    while Instant::now() < until {
        match selection(owner, original) {
            Ok(actual) if actual == expected => return Ok(()),
            Ok(_) => return Err(HaImportError::TargetRejected),
            Err(HaImportError::QuorumUnavailable) | Err(HaImportError::TargetRejected) => {}
            Err(error) => return Err(error),
        }
        std::thread::sleep(
            until
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(20)),
        );
    }
    Err(HaImportError::QuorumUnavailable)
}

fn unseal(
    owner: &mut Owner,
    shares: &[String],
    gate: &impl Fn() -> Result<(), HaImportError>,
) -> Result<(), HaImportError> {
    let service = owner.service()?;
    let seal = service.seal.as_ref().ok_or(HaImportError::TargetRejected)?;
    if shares.is_empty() || shares.len() != usize::from(seal.secret_threshold) || seal.is_wrapper()
    {
        return Err(HaImportError::CredentialRejected);
    }
    for share in shares {
        gate()?;
        let mut response = service.handle("POST", "sys/unseal", "", "", json!({"key":share}));
        if response.status != 200 {
            return Err(reject_response(service, &mut response).into());
        }
        erase_json(&mut response.body);
        gate()?;
    }
    if service.ha.is_none()
        || service.recovery_required
        || service.audit_failed
        || service.state.is_none()
        || service.barrier_key.is_none()
    {
        return Err(HaImportError::TargetRejected);
    }
    service
        .durable
        .as_mut()
        .ok_or(HaImportError::TargetRejected)?
        .verify_live_ownership()
        .map_err(|_| HaImportError::TargetRejected)?;
    gate()
}

fn verify_graph(
    owner: &mut Owner,
    expected: Selection,
    deadline: OriginalDeadline,
    gate: &impl Fn() -> Result<(), HaImportError>,
) -> Result<(), HaImportError> {
    if selection(owner, deadline)? != expected {
        return Err(HaImportError::TargetRejected);
    }
    let service = owner.service()?;
    let root = service
        .native_root
        .as_ref()
        .ok_or(HaImportError::TargetRejected)?
        .clone();
    if root.reader_floor.native_kv2_format != 2
        || root
            .identity()
            .map_err(|_| HaImportError::TargetRejected)?
            .digest()
            != expected.root
    {
        return Err(HaImportError::TargetRejected);
    }
    let durable = service
        .durable
        .as_mut()
        .ok_or(HaImportError::TargetRejected)?;
    v6_records::verify_durable_native_candidate(&root, durable, deadline, &mut || {
        gate().map_err(|_| heptabao_durable_service::ServiceError::BarrierFailure)
    })
    .map_err(|_| HaImportError::TargetRejected)?;
    durable
        .verify_live_ownership()
        .map_err(|_| HaImportError::TargetRejected)?;
    gate()?;
    // A fresh terminal quorum observation must still select the same unique
    // publication. The earlier read's bounded witness is never refreshed.
    if selection(owner, deadline)? != expected {
        return Err(HaImportError::TargetRejected);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    BundleVerified,
    OwnerStarted,
    LeaderReady,
    Prepared,
    Committed,
    FirstOwnerClosed,
    RawColdVerified,
    ColdReadIndex,
    ColdOwnerClosed,
}

pub fn import_kv2_ha(options: HaKv2Import<'_>) -> Result<HaImportReceipt, HaImportError> {
    let seconds = seconds(&options)?;
    if crate::request_deadline::current().is_some() {
        return Err(HaImportError::InvalidInput);
    }
    let started = Instant::now();
    let until = started
        .checked_add(Duration::from_secs(seconds))
        .ok_or(HaImportError::InvalidInput)?;
    import_before(options, started, until, |_| {})
}

// Tests may observe or interrupt real boundaries; they cannot provide an
// actor, graph, owner, response, consensus result or replacement deadline.
fn import_before(
    options: HaKv2Import<'_>,
    started: Instant,
    until: Instant,
    mut observe: impl FnMut(Phase),
) -> Result<HaImportReceipt, HaImportError> {
    let budget_seconds = seconds(&options)?;
    if crate::request_deadline::current().is_some() {
        return Err(HaImportError::InvalidInput);
    }
    let _scope = RequestDeadlineScope::enter(until);
    let deadline = OriginalDeadline::capture().map_err(|_| HaImportError::Deadline)?;
    let mut server_input = PinnedInput::open(options.server_config_path, CONFIG_BYTES, deadline)?;
    let mut ha_input = PinnedInput::open(options.ha_config_path, CONFIG_BYTES, deadline)?;
    let server_bytes = server_input.small()?;
    let ha_bytes = ha_input.small()?;
    let config = configuration::parse_server(&server_bytes)
        .map_err(|_| HaImportError::ConfigurationRejected)?;
    let ha_config =
        configuration::parse_ha(&ha_bytes).map_err(|_| HaImportError::ConfigurationRejected)?;
    validate_configuration(&options, &config, &ha_config)?;
    let target = TargetDirectory::open(&config.data_dir)?;
    let raft = TargetDirectory::open(&ha_config.raft_dir)?;
    let mut peer_inputs = Vec::new();
    for path in [
        &ha_config.ca_file,
        &ha_config.cert_file,
        &ha_config.key_file,
        &ha_config.replication_key_file,
    ] {
        peer_inputs.push(PinnedInput::open(path, PEER_CREDENTIAL_BYTES, deadline)?);
    }
    let mut bundle = PinnedInput::open(options.bundle_path, MAX_BUNDLE_BYTES as u64, deadline)?;
    let mut shares_input = PinnedInput::open(options.shares_path, MAX_CREDENTIAL_BYTES, deadline)?;
    let mut token_input = PinnedInput::open(options.token_path, MAX_CREDENTIAL_BYTES, deadline)?;
    if bundle.digest()? != options.bundle_sha256 {
        return Err(HaImportError::DigestMismatch);
    }
    let shares = Zeroizing::new(
        serde_json::from_slice::<Vec<String>>(&shares_input.small()?)
            .map_err(|_| HaImportError::CredentialRejected)?,
    );
    if shares.is_empty()
        || shares.len() > 255
        || shares
            .iter()
            .any(|share| share.is_empty() || share.len() > 1024)
    {
        return Err(HaImportError::CredentialRejected);
    }
    let token_bytes = token_input.small()?;
    let token = Zeroizing::new(
        std::str::from_utf8(&token_bytes)
            .map_err(|_| HaImportError::CredentialRejected)?
            .trim_end_matches(['\r', '\n'])
            .to_owned(),
    );
    if token.is_empty()
        || token.len() > 4096
        || token.contains('\0')
        || token.chars().any(char::is_whitespace)
    {
        return Err(HaImportError::CredentialRejected);
    }
    drop(token_bytes);
    let common_gate = || -> Result<(), HaImportError> {
        target.check(deadline)?;
        raft.check(deadline)?;
        server_input.check()?;
        ha_input.check()?;
        for input in &peer_inputs {
            input.check()?;
        }
        shares_input.check()?;
        token_input.check()?;
        live(deadline)?;
        Ok(())
    };
    observe(Phase::BundleVerified);
    common_gate()?;
    bundle.check()?;
    let voters = ha_config
        .initial_voters
        .clone()
        .unwrap_or_else(|| ha_config.peers.keys().copied().collect());
    let mut owner = Owner::start(&config, &ha_config)?;
    observe(Phase::OwnerStarted);
    common_gate()?;
    bundle.check()?;
    wait_leader(&owner, &voters, deadline)?;
    observe(Phase::LeaderReady);
    unseal(&mut owner, &shares, &common_gate)?;
    let service = owner.service()?;
    let mut lookup = service.handle("GET", "auth/token/lookup-self", "", &token, json!({}));
    if lookup.status != 200 {
        return Err(reject_response(service, &mut lookup).into());
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
        return Err(HaImportError::CredentialRejected);
    }
    let activation_performed = service.native_root.is_none();
    if activation_performed {
        common_gate()?;
        bundle.check()?;
        let mut response = service.handle(
            "POST",
            "sys/storage/native-v6/activate",
            "",
            &token,
            json!({}),
        );
        if response.status != 204 {
            return Err(reject_response(service, &mut response).into());
        }
        erase_json(&mut response.body);
    }
    common_gate()?;
    bundle.check()?;
    bundle.start_consuming()?;
    let mut pending = match service.begin_native_kv2_large_before(
        ServiceRequest::new("POST", PATH, "", &token, json!({"mount":options.mount})),
        until,
    ) {
        RequestExecution::External(pending) => pending,
        RequestExecution::Complete(mut response) => {
            return Err(reject_response(service, &mut response).into());
        }
    };
    let mut result = pending.execute_native_kv2_large_transfer(&mut bundle);
    observe(Phase::Prepared);
    let input_result = common_gate().and_then(|()| {
        bundle
            .consumed_exactly(options.bundle_sha256)
            .map_err(Into::into)
    });
    if input_result.is_err() {
        result = ExternalEffectResult::NativeKv2Large(Err(Response::error(
            400,
            "maintenance input custody rejected",
        )));
    }
    let mut response = service.finish_external_request(*pending, result);
    if response.status != 204 {
        let rejection = HaImportError::from(reject_response(service, &mut response));
        return Err(if rejection == HaImportError::OutcomeUnknown {
            rejection
        } else {
            input_result.err().unwrap_or(rejection)
        });
    }
    erase_json(&mut response.body);
    // Every failure after the actual writer acknowledges publication is an
    // unknown delivery. No branch replays import or restores an old checkpoint.
    let completed = (|| -> Result<HaImportReceipt, HaImportError> {
        input_result?;
        observe(Phase::Committed);
        let gate = || {
            common_gate()?;
            bundle.check()?;
            Ok(())
        };
        gate()?;
        let selected = selection(&owner, deadline)?;
        verify_graph(&mut owner, selected, deadline, &gate)?;
        let service = owner.service()?;
        let root = service
            .native_root
            .as_ref()
            .ok_or(HaImportError::TargetRejected)?
            .clone();
        let root_bytes = root.encode().map_err(|_| HaImportError::TargetRejected)?;
        let identity = root.identity().map_err(|_| HaImportError::TargetRejected)?;
        let key = Zeroizing::new(
            **service
                .barrier_key
                .as_ref()
                .ok_or(HaImportError::TargetRejected)?,
        );
        let durable = service
            .durable
            .as_ref()
            .ok_or(HaImportError::TargetRejected)?;
        let generation = durable.generation();
        let replay_epoch = durable.replay_epoch();
        let first_joined = owner.close()?;
        observe(Phase::FirstOwnerClosed);
        gate()?;
        let mut raw = heptabao_durable_service::DurableService::reopen(
            &config.data_dir,
            crate::crypto::AeadBarrier::new(*key).map_err(|_| HaImportError::TargetRejected)?,
            crate::service::MAX_OPERATIONS,
        )
        .map_err(|_| HaImportError::TargetRejected)?;
        drop(key);
        if raw.generation() != generation
            || raw.replay_epoch() != replay_epoch
            || raw
                .get("system", "state")
                .map_err(|_| HaImportError::TargetRejected)?
                .is_none_or(|bytes| bytes.expose() != root_bytes.as_slice())
        {
            return Err(HaImportError::TargetRejected);
        }
        v6_records::verify_durable_native_candidate(&root, &mut raw, deadline, &mut || {
            gate().map_err(|_| heptabao_durable_service::ServiceError::BarrierFailure)
        })
        .map_err(|_| HaImportError::TargetRejected)?;
        raw.verify_live_ownership()
            .map_err(|_| HaImportError::TargetRejected)?;
        raw.close().map_err(|_| HaImportError::OwnerShutdown)?;
        observe(Phase::RawColdVerified);
        gate()?;
        let mut cold = Owner::start(&config, &ha_config)?;
        wait_cold_selection(&cold, selected, deadline)?;
        observe(Phase::ColdReadIndex);
        gate()?;
        unseal(&mut cold, &shares, &gate)?;
        let service = cold.service()?;
        let cold_root = service
            .native_root
            .as_ref()
            .ok_or(HaImportError::TargetRejected)?;
        let durable = service
            .durable
            .as_ref()
            .ok_or(HaImportError::TargetRejected)?;
        // Ordinary native Shamir unseal uses LocalUnsealCompletion and is
        // read-only in state. No clock self-write is invented to make this pass.
        if cold_root
            .encode()
            .map_err(|_| HaImportError::TargetRejected)?
            .as_slice()
            != root_bytes.as_slice()
            || durable.generation() != generation
            || durable.replay_epoch() != replay_epoch
        {
            return Err(HaImportError::TargetRejected);
        }
        verify_graph(&mut cold, selected, deadline, &gate)?;
        let cold_joined = cold.close()?;
        observe(Phase::ColdOwnerClosed);
        gate()?;
        Ok(HaImportReceipt {
            schema: 1,
            operation: "native-raft-maintenance-import",
            server_config_sha256: hex(Sha256::digest(server_bytes.as_slice()).as_ref()),
            ha_config_sha256: hex(Sha256::digest(ha_bytes.as_slice()).as_ref()),
            bundle_sha256: options.bundle_sha256.to_owned(),
            bundle_bytes: bundle.witness.bytes,
            budget_seconds,
            elapsed_millis: started.elapsed().as_millis(),
            local_node_id: ha_config.node_id,
            voters,
            activation_performed,
            committed_root_identity: hex(&identity.digest()),
            committed_root_sha256: hex(Sha256::digest(root_bytes.as_slice()).as_ref()),
            local_generation: generation,
            replay_epoch,
            native_generation: selected.generation,
            publication_log_index: selected.publication,
            first_owner_peer_workers_joined: first_joined,
            cold_owner_peer_workers_joined: cold_joined,
            original_inputs_unchanged: true,
            complete_cold_graph_verified: true,
            cold_root_and_local_generation_exact: true,
            cold_quorum_readindex_verified: true,
            cold_selection_exact: true,
            real_native_writer_used: true,
            imported_once: true,
            http_listener_started: false,
            http_latency_qualified: false,
            physical_failover_qualified: false,
            full_replacement_qualified: false,
        })
    })();
    completed.map_err(|_| HaImportError::OutcomeUnknown)
}

#[cfg(test)]
#[path = "service_native_seed_ha_import_tests.rs"]
mod tests;
